package main

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// natDevice wraps the tunnel interface and rewrites addresses on the way
// through. It exists because of how the macOS split tunnel works:
//
// The firewall (pf) diverts the tunneled app's packets into the utun interface
// with a "route-to" rule, after the kernel has already picked the source
// address for the interface it originally routed to (Wi-Fi/Ethernet). pf cannot
// translate a packet it diverts this way, so packets reach the tunnel carrying
// the LAN address, and VPN servers that enforce the assigned tunnel address
// silently drop them. So:
//
//   - outbound (kernel -> tunnel): the source becomes the tunnel address and the
//     original source is remembered per flow;
//   - inbound (tunnel -> kernel): the destination is restored to that original
//     source, so the reply reaches the socket that sent the request. Inbound
//     traffic that belongs to no known flow is dropped.
//
// Ports are never changed. TCP SYN/SYN-ACK packets also get their MSS clamped
// to the tunnel MTU, because the app sized its segments for the LAN link.
type natDevice struct {
	tun.Device
	tunAddr [4]byte
	maxMSS  uint16

	mu      sync.Mutex
	flows   map[flowKey]*flowEntry
	frags   map[fragKey]*flowEntry
	inserts int
	now     func() int64

	statOut     atomic.Uint64
	statIn      atomic.Uint64
	statDropped atomic.Uint64
	statClamped atomic.Uint64
}

type flowKey struct {
	proto      uint8
	localPort  uint16 // or ICMP echo identifier
	remoteIP   [4]byte
	remotePort uint16
}

type fragKey struct {
	remoteIP [4]byte
	id       uint16
	proto    uint8
}

type flowEntry struct {
	orig [4]byte
	seen int64
}

const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17

	flowIdleSeconds = 600
	fragIdleSeconds = 30
	flowLimit       = 65536
	fragLimit       = 4096
	sweepEvery      = 2048

	icmpEchoReply   = 0
	icmpUnreachable = 3
	icmpEchoRequest = 8
	icmpTimeExceed  = 11
	icmpParamProb   = 12
)

func newNATDevice(dev tun.Device, tunAddr [4]byte, mtu int) *natDevice {
	mss := mtu - 40
	if mss < 536 || mss > 65495 {
		mss = 1240
	}
	return &natDevice{
		Device:  dev,
		tunAddr: tunAddr,
		maxMSS:  uint16(mss),
		flows:   make(map[flowKey]*flowEntry),
		frags:   make(map[fragKey]*flowEntry),
		now:     func() int64 { return time.Now().Unix() },
	}
}

func (d *natDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	for i := 0; i < n; i++ {
		d.egress(bufs[i][offset : offset+sizes[i]])
	}
	return n, err
}

func (d *natDevice) Write(bufs [][]byte, offset int) (int, error) {
	// Drops are rare, so the filtered list is only built once one happens.
	var keep [][]byte
	dropped := false
	for i, buf := range bufs {
		if offset <= len(buf) && d.ingress(buf[offset:]) {
			if dropped {
				keep = append(keep, buf)
			}
			continue
		}
		if !dropped {
			dropped = true
			keep = append(make([][]byte, 0, len(bufs)), bufs[:i]...)
		}
	}
	if !dropped {
		return d.Device.Write(bufs, offset)
	}
	if len(keep) > 0 {
		if _, err := d.Device.Write(keep, offset); err != nil {
			return 0, err
		}
	}
	return len(bufs), nil
}

type natStats struct {
	Out     uint64 `json:"rewritten_out"`
	In      uint64 `json:"restored_in"`
	Dropped uint64 `json:"dropped_in"`
	Clamped uint64 `json:"mss_clamped"`
	Flows   int    `json:"flows"`
}

func (d *natDevice) stats() natStats {
	d.mu.Lock()
	flows := len(d.flows)
	d.mu.Unlock()
	return natStats{
		Out:     d.statOut.Load(),
		In:      d.statIn.Load(),
		Dropped: d.statDropped.Load(),
		Clamped: d.statClamped.Load(),
		Flows:   flows,
	}
}

// ipv4Header validates the fixed part of an IPv4 packet and returns the header
// length. ok is false for anything that is not a well-formed IPv4 packet.
func ipv4Header(pkt []byte) (ihl int, ok bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return 0, false
	}
	ihl = int(pkt[0]&0x0f) * 4
	if ihl < 20 || ihl > len(pkt) {
		return 0, false
	}
	return ihl, true
}

// egress handles a packet read from the kernel on its way into the tunnel.
func (d *natDevice) egress(pkt []byte) {
	ihl, ok := ipv4Header(pkt)
	if !ok {
		return
	}
	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])

	proto := pkt[9]
	fragField := binary.BigEndian.Uint16(pkt[6:8])
	first := fragField&0x1fff == 0
	l4 := pkt[ihl:]

	if first {
		if key, ok := flowKeyOut(proto, l4, dst); ok {
			d.remember(key, src)
		}
		if proto == protoTCP {
			d.clampSYN(l4)
		}
	}

	if src == d.tunAddr {
		return
	}
	rewriteAddr(pkt, ihl, 12, d.tunAddr[:], first)
	d.statOut.Add(1)
}

// ingress handles a packet decrypted from the tunnel on its way to the kernel.
// It returns false when the packet must be dropped.
func (d *natDevice) ingress(pkt []byte) bool {
	ihl, ok := ipv4Header(pkt)
	if !ok {
		return true
	}
	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	if dst != d.tunAddr {
		return true
	}

	proto := pkt[9]
	fragField := binary.BigEndian.Uint16(pkt[6:8])
	first := fragField&0x1fff == 0
	more := fragField&0x2000 != 0
	l4 := pkt[ihl:]
	fkey := fragKey{remoteIP: src, id: binary.BigEndian.Uint16(pkt[4:6]), proto: proto}

	if !first {
		orig, ok := d.lookupFrag(fkey)
		if !ok {
			d.statDropped.Add(1)
			return false
		}
		rewriteAddr(pkt, ihl, 16, orig[:], false)
		d.statIn.Add(1)
		return true
	}

	if proto == protoICMP && len(l4) >= 8 && isICMPError(l4[0]) {
		if d.ingressICMPError(pkt, ihl) {
			d.statIn.Add(1)
			return true
		}
		d.statDropped.Add(1)
		return false
	}

	key, ok := flowKeyIn(proto, l4, src)
	if !ok {
		// Not TCP, UDP or an echo reply: nothing here can be matched to a
		// socket, so the packet is delivered as it came.
		return true
	}
	orig, ok := d.lookup(key)
	if !ok {
		d.statDropped.Add(1)
		return false
	}
	if more {
		d.rememberFrag(fkey, orig)
	}
	if proto == protoTCP {
		d.clampSYN(l4)
	}
	if orig != d.tunAddr {
		rewriteAddr(pkt, ihl, 16, orig[:], true)
	}
	d.statIn.Add(1)
	return true
}

// ingressICMPError translates an ICMP error about one of our outbound packets:
// the quoted packet carries the tunnel address as source, and both it and the
// outer destination go back to the original source so the kernel can match the
// error to the socket (this is what keeps path-MTU discovery working).
func (d *natDevice) ingressICMPError(pkt []byte, ihl int) bool {
	icmp := pkt[ihl:]
	inner := icmp[8:]
	innerIHL, ok := ipv4Header(inner)
	if !ok {
		return false
	}
	var innerSrc, innerDst [4]byte
	copy(innerSrc[:], inner[12:16])
	copy(innerDst[:], inner[16:20])
	if innerSrc != d.tunAddr {
		return false
	}
	key, ok := flowKeyOut(inner[9], inner[innerIHL:], innerDst)
	if !ok {
		return false
	}
	orig, ok := d.lookup(key)
	if !ok {
		return false
	}
	if orig == d.tunAddr {
		return true
	}

	innerFirst := binary.BigEndian.Uint16(inner[6:8])&0x1fff == 0
	rewriteAddr(inner, innerIHL, 12, orig[:], innerFirst)
	rewriteAddr(pkt, ihl, 16, orig[:], false)

	icmp[2], icmp[3] = 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], ^checksumFold(checksumAdd(0, icmp)))
	return true
}

func isICMPError(icmpType byte) bool {
	return icmpType == icmpUnreachable || icmpType == icmpTimeExceed || icmpType == icmpParamProb
}

// flowKeyOut builds the key of an outbound packet from its transport header.
func flowKeyOut(proto uint8, l4 []byte, remote [4]byte) (flowKey, bool) {
	switch proto {
	case protoTCP, protoUDP:
		if len(l4) < 4 {
			return flowKey{}, false
		}
		return flowKey{
			proto:      proto,
			localPort:  binary.BigEndian.Uint16(l4[0:2]),
			remoteIP:   remote,
			remotePort: binary.BigEndian.Uint16(l4[2:4]),
		}, true
	case protoICMP:
		if len(l4) < 8 || l4[0] != icmpEchoRequest {
			return flowKey{}, false
		}
		return flowKey{proto: proto, localPort: binary.BigEndian.Uint16(l4[4:6]), remoteIP: remote}, true
	}
	return flowKey{}, false
}

// flowKeyIn builds the same key from the matching inbound packet.
func flowKeyIn(proto uint8, l4 []byte, remote [4]byte) (flowKey, bool) {
	switch proto {
	case protoTCP, protoUDP:
		if len(l4) < 4 {
			return flowKey{}, false
		}
		return flowKey{
			proto:      proto,
			localPort:  binary.BigEndian.Uint16(l4[2:4]),
			remoteIP:   remote,
			remotePort: binary.BigEndian.Uint16(l4[0:2]),
		}, true
	case protoICMP:
		if len(l4) < 8 || l4[0] != icmpEchoReply {
			return flowKey{}, false
		}
		return flowKey{proto: proto, localPort: binary.BigEndian.Uint16(l4[4:6]), remoteIP: remote}, true
	}
	return flowKey{}, false
}

func (d *natDevice) remember(key flowKey, orig [4]byte) {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if entry, ok := d.flows[key]; ok {
		entry.orig = orig
		entry.seen = now
		return
	}
	d.inserts++
	if d.inserts%sweepEvery == 0 || len(d.flows) >= flowLimit {
		d.sweepLocked(now)
	}
	if len(d.flows) >= flowLimit {
		return
	}
	d.flows[key] = &flowEntry{orig: orig, seen: now}
}

func (d *natDevice) lookup(key flowKey) ([4]byte, bool) {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.flows[key]
	if !ok {
		return [4]byte{}, false
	}
	entry.seen = now
	return entry.orig, true
}

func (d *natDevice) rememberFrag(key fragKey, orig [4]byte) {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.frags) >= fragLimit {
		for k, entry := range d.frags {
			if now-entry.seen > fragIdleSeconds {
				delete(d.frags, k)
			}
		}
		if len(d.frags) >= fragLimit {
			return
		}
	}
	d.frags[key] = &flowEntry{orig: orig, seen: now}
}

func (d *natDevice) lookupFrag(key fragKey) ([4]byte, bool) {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	entry, ok := d.frags[key]
	if !ok || now-entry.seen > fragIdleSeconds {
		return [4]byte{}, false
	}
	return entry.orig, true
}

// sweepLocked drops idle flows. When the table is full it shortens the idle
// limit until something is freed, so active flows are the last to go.
func (d *natDevice) sweepLocked(now int64) {
	for idle := int64(flowIdleSeconds); idle >= 1; idle /= 2 {
		for key, entry := range d.flows {
			if now-entry.seen > idle {
				delete(d.flows, key)
			}
		}
		if len(d.flows) < flowLimit {
			break
		}
	}
	for key, entry := range d.frags {
		if now-entry.seen > fragIdleSeconds {
			delete(d.frags, key)
		}
	}
}

// rewriteAddr replaces the 4-byte address at addrOff (12 = source, 16 =
// destination) and fixes the IPv4 header checksum. With transport set it also
// fixes the TCP or UDP checksum, whose pseudo-header covers the addresses; that
// is only valid for packets that start a datagram (not later fragments).
func rewriteAddr(pkt []byte, ihl, addrOff int, newAddr []byte, transport bool) {
	var old [4]byte
	copy(old[:], pkt[addrOff:addrOff+4])
	copy(pkt[addrOff:addrOff+4], newAddr)
	checksumReplace(pkt[10:12], old[:], newAddr)

	if !transport {
		return
	}
	l4 := pkt[ihl:]
	switch pkt[9] {
	case protoTCP:
		if len(l4) >= 18 {
			checksumReplace(l4[16:18], old[:], newAddr)
		}
	case protoUDP:
		if len(l4) >= 8 && (l4[6] != 0 || l4[7] != 0) {
			checksumReplace(l4[6:8], old[:], newAddr)
			if l4[6] == 0 && l4[7] == 0 {
				l4[6], l4[7] = 0xff, 0xff
			}
		}
	}
}

// clampSYN lowers the MSS announced by a TCP SYN or SYN-ACK to what fits the
// tunnel. Only packets with the SYN flag carry the option.
func (d *natDevice) clampSYN(tcp []byte) {
	if len(tcp) < 20 || tcp[13]&0x02 == 0 {
		return
	}
	headerLen := int(tcp[12]>>4) * 4
	if headerLen < 20 || headerLen > len(tcp) {
		return
	}
	for i := 20; i < headerLen; {
		kind := tcp[i]
		if kind == 0 {
			return
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= headerLen {
			return
		}
		optLen := int(tcp[i+1])
		if optLen < 2 || i+optLen > headerLen {
			return
		}
		if kind == 2 && optLen == 4 {
			if binary.BigEndian.Uint16(tcp[i+2:i+4]) > d.maxMSS {
				var newMSS [2]byte
				binary.BigEndian.PutUint16(newMSS[:], d.maxMSS)
				replaceChecksummed(tcp, i+2, newMSS[:], tcp[16:18])
				d.statClamped.Add(1)
			}
			return
		}
		i += optLen
	}
}

// replaceChecksummed overwrites data[off:off+len(value)] and updates sum, a
// checksum computed over data from its start. The field may sit at an odd
// offset (TCP options are byte aligned), so the update is done over the 16-bit
// words that contain it.
func replaceChecksummed(data []byte, off int, value []byte, sum []byte) {
	start := off &^ 1
	end := (off + len(value) + 1) &^ 1
	if end > len(data) {
		end = len(data) &^ 1
		if end <= start {
			copy(data[off:], value)
			return
		}
	}
	old := make([]byte, end-start)
	copy(old, data[start:end])
	copy(data[off:], value)
	checksumReplace(sum, old, data[start:end])
}

// checksumReplace updates an Internet checksum in place after the 16-bit words
// in old were replaced by the ones in new (RFC 1624, equation 3).
func checksumReplace(sum, old, new []byte) {
	acc := uint32(^binary.BigEndian.Uint16(sum))
	for i := 0; i+1 < len(old); i += 2 {
		acc += uint32(^binary.BigEndian.Uint16(old[i:]))
		acc += uint32(binary.BigEndian.Uint16(new[i:]))
	}
	binary.BigEndian.PutUint16(sum, ^checksumFold(acc))
}

func checksumAdd(acc uint32, data []byte) uint32 {
	for len(data) >= 2 {
		acc += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		acc += uint32(data[0]) << 8
	}
	return acc
}

func checksumFold(acc uint32) uint16 {
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return uint16(acc)
}
