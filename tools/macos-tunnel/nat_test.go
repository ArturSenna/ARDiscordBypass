package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

var (
	lanAddr    = [4]byte{192, 168, 1, 50}
	otherLAN   = [4]byte{192, 168, 64, 1}
	tunnelAddr = [4]byte{10, 5, 0, 2}
	remoteAddr = [4]byte{162, 159, 130, 234}
)

func fullChecksum(parts ...[]byte) uint16 {
	var acc uint32
	for _, p := range parts {
		// Every part but the last has an even length in these tests.
		acc = checksumAdd(acc, p)
	}
	return ^checksumFold(acc)
}

func pseudoHeader(src, dst [4]byte, proto uint8, length int) []byte {
	p := make([]byte, 12)
	copy(p[0:4], src[:])
	copy(p[4:8], dst[:])
	p[9] = proto
	binary.BigEndian.PutUint16(p[10:12], uint16(length))
	return p
}

// ipv4 builds a packet with a valid header checksum around the given payload.
func ipv4(src, dst [4]byte, proto uint8, id, fragField uint16, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], fragField)
	pkt[8] = 64
	pkt[9] = proto
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], payload)
	binary.BigEndian.PutUint16(pkt[10:12], fullChecksum(pkt[:20]))
	return pkt
}

func tcpSegment(src, dst [4]byte, sport, dport uint16, flags byte, options, data []byte) []byte {
	for len(options)%4 != 0 {
		options = append(options, 1)
	}
	seg := make([]byte, 20+len(options)+len(data))
	binary.BigEndian.PutUint16(seg[0:2], sport)
	binary.BigEndian.PutUint16(seg[2:4], dport)
	binary.BigEndian.PutUint32(seg[4:8], 1000)
	seg[12] = byte((20 + len(options)) / 4 << 4)
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	copy(seg[20:], options)
	copy(seg[20+len(options):], data)
	binary.BigEndian.PutUint16(seg[16:18], fullChecksum(pseudoHeader(src, dst, protoTCP, len(seg)), seg))
	return seg
}

func udpDatagram(src, dst [4]byte, sport, dport uint16, data []byte, withChecksum bool) []byte {
	dgram := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(dgram[0:2], sport)
	binary.BigEndian.PutUint16(dgram[2:4], dport)
	binary.BigEndian.PutUint16(dgram[4:6], uint16(len(dgram)))
	copy(dgram[8:], data)
	if withChecksum {
		binary.BigEndian.PutUint16(dgram[6:8], fullChecksum(pseudoHeader(src, dst, protoUDP, len(dgram)), dgram))
	}
	return dgram
}

func icmpMessage(icmpType, code byte, rest uint32, data []byte) []byte {
	msg := make([]byte, 8+len(data))
	msg[0], msg[1] = icmpType, code
	binary.BigEndian.PutUint32(msg[4:8], rest)
	copy(msg[8:], data)
	binary.BigEndian.PutUint16(msg[2:4], fullChecksum(msg))
	return msg
}

// checkPacket verifies every checksum of a whole (unfragmented) packet.
func checkPacket(t *testing.T, name string, pkt []byte) {
	t.Helper()
	if got := fullChecksum(pkt[:20]); got != 0 {
		t.Errorf("%s: bad IPv4 header checksum (residue %#04x)", name, got)
	}
	var src, dst [4]byte
	copy(src[:], pkt[12:16])
	copy(dst[:], pkt[16:20])
	l4 := pkt[20:]
	switch pkt[9] {
	case protoTCP:
		if got := fullChecksum(pseudoHeader(src, dst, protoTCP, len(l4)), l4); got != 0 {
			t.Errorf("%s: bad TCP checksum (residue %#04x)", name, got)
		}
	case protoUDP:
		if l4[6] == 0 && l4[7] == 0 {
			return
		}
		if got := fullChecksum(pseudoHeader(src, dst, protoUDP, len(l4)), l4); got != 0 {
			t.Errorf("%s: bad UDP checksum (residue %#04x)", name, got)
		}
	case protoICMP:
		if got := fullChecksum(l4); got != 0 {
			t.Errorf("%s: bad ICMP checksum (residue %#04x)", name, got)
		}
	}
}

func addrOf(pkt []byte, off int) [4]byte {
	var a [4]byte
	copy(a[:], pkt[off:off+4])
	return a
}

func newTestNAT() *natDevice {
	return newNATDevice(nil, tunnelAddr, 1280)
}

func TestTCPRoundTrip(t *testing.T) {
	nat := newTestNAT()

	out := ipv4(lanAddr, remoteAddr, protoTCP, 1, 0x4000,
		tcpSegment(lanAddr, remoteAddr, 51000, 443, 0x18, nil, []byte("hello")))
	nat.egress(out)
	if addrOf(out, 12) != tunnelAddr {
		t.Fatalf("source not rewritten: %v", addrOf(out, 12))
	}
	if addrOf(out, 16) != remoteAddr {
		t.Fatalf("destination changed: %v", addrOf(out, 16))
	}
	checkPacket(t, "egress", out)

	in := ipv4(remoteAddr, tunnelAddr, protoTCP, 2, 0x4000,
		tcpSegment(remoteAddr, tunnelAddr, 443, 51000, 0x18, nil, []byte("world!")))
	if !nat.ingress(in) {
		t.Fatal("reply was dropped")
	}
	if addrOf(in, 16) != lanAddr {
		t.Fatalf("destination not restored: %v", addrOf(in, 16))
	}
	checkPacket(t, "ingress", in)

	if s := nat.stats(); s.Out != 1 || s.In != 1 || s.Dropped != 0 || s.Flows != 1 {
		t.Errorf("unexpected stats: %+v", s)
	}
}

func TestUDPChecksumVariants(t *testing.T) {
	for _, withChecksum := range []bool{true, false} {
		nat := newTestNAT()
		out := ipv4(lanAddr, remoteAddr, protoUDP, 1, 0,
			udpDatagram(lanAddr, remoteAddr, 50000, 50001, []byte("voice-frame"), withChecksum))
		nat.egress(out)
		checkPacket(t, "egress", out)
		if !withChecksum && (out[26] != 0 || out[27] != 0) {
			t.Error("a UDP packet without checksum gained one")
		}

		in := ipv4(remoteAddr, tunnelAddr, protoUDP, 2, 0,
			udpDatagram(remoteAddr, tunnelAddr, 50001, 50000, []byte("reply"), withChecksum))
		if !nat.ingress(in) || addrOf(in, 16) != lanAddr {
			t.Fatalf("checksum=%v: reply not restored", withChecksum)
		}
		checkPacket(t, "ingress", in)
	}
}

// Two sockets bound to different local addresses (WebRTC binds one per
// interface) must each get their own replies back.
func TestFlowsKeepTheirOwnSource(t *testing.T) {
	nat := newTestNAT()
	nat.egress(ipv4(lanAddr, remoteAddr, protoUDP, 1, 0, udpDatagram(lanAddr, remoteAddr, 40001, 3478, nil, true)))
	nat.egress(ipv4(otherLAN, remoteAddr, protoUDP, 2, 0, udpDatagram(otherLAN, remoteAddr, 40002, 3478, nil, true)))

	first := ipv4(remoteAddr, tunnelAddr, protoUDP, 3, 0, udpDatagram(remoteAddr, tunnelAddr, 3478, 40001, nil, true))
	second := ipv4(remoteAddr, tunnelAddr, protoUDP, 4, 0, udpDatagram(remoteAddr, tunnelAddr, 3478, 40002, nil, true))
	if !nat.ingress(first) || !nat.ingress(second) {
		t.Fatal("reply dropped")
	}
	if addrOf(first, 16) != lanAddr || addrOf(second, 16) != otherLAN {
		t.Errorf("replies crossed: %v %v", addrOf(first, 16), addrOf(second, 16))
	}
}

func TestUnknownInboundIsDropped(t *testing.T) {
	nat := newTestNAT()
	for name, pkt := range map[string][]byte{
		"tcp":   ipv4(remoteAddr, tunnelAddr, protoTCP, 1, 0, tcpSegment(remoteAddr, tunnelAddr, 443, 51000, 0x02, nil, nil)),
		"udp":   ipv4(remoteAddr, tunnelAddr, protoUDP, 1, 0, udpDatagram(remoteAddr, tunnelAddr, 53, 5353, nil, true)),
		"frag2": ipv4(remoteAddr, tunnelAddr, protoUDP, 9, 185, []byte("tail of some datagram....")),
	} {
		if nat.ingress(pkt) {
			t.Errorf("%s: unsolicited packet was let in", name)
		}
	}
	if s := nat.stats(); s.Dropped != 3 {
		t.Errorf("dropped = %d, want 3", s.Dropped)
	}

	// Not addressed to the tunnel, or not IPv4: left alone.
	foreign := ipv4(remoteAddr, lanAddr, protoUDP, 1, 0, udpDatagram(remoteAddr, lanAddr, 1, 2, nil, true))
	before := append([]byte(nil), foreign...)
	if !nat.ingress(foreign) || !bytes.Equal(before, foreign) {
		t.Error("packet for another address was touched")
	}
	v6 := []byte{0x60, 0, 0, 0, 0, 0, 59, 64}
	if !nat.ingress(v6) {
		t.Error("IPv6 packet dropped")
	}
	nat.egress(v6)
	nat.egress([]byte{0x45})
}

func TestMSSClamp(t *testing.T) {
	mssOption := func(v uint16) []byte { return []byte{2, 4, byte(v >> 8), byte(v)} }
	mssOf := func(pkt []byte, off int) uint16 { return binary.BigEndian.Uint16(pkt[20+off:]) }

	nat := newTestNAT() // MTU 1280 -> MSS 1240

	syn := ipv4(lanAddr, remoteAddr, protoTCP, 1, 0x4000,
		tcpSegment(lanAddr, remoteAddr, 51000, 443, 0x02, mssOption(1460), nil))
	nat.egress(syn)
	if got := mssOf(syn, 22); got != 1240 {
		t.Errorf("SYN MSS = %d, want 1240", got)
	}
	checkPacket(t, "syn", syn)

	synAck := ipv4(remoteAddr, tunnelAddr, protoTCP, 2, 0x4000,
		tcpSegment(remoteAddr, tunnelAddr, 443, 51000, 0x12, mssOption(1380), nil))
	if !nat.ingress(synAck) {
		t.Fatal("SYN-ACK dropped")
	}
	if got := mssOf(synAck, 22); got != 1240 {
		t.Errorf("SYN-ACK MSS = %d, want 1240", got)
	}
	checkPacket(t, "syn-ack", synAck)

	// Option at an odd offset (after a NOP) and a value that already fits.
	odd := ipv4(lanAddr, remoteAddr, protoTCP, 3, 0x4000,
		tcpSegment(lanAddr, remoteAddr, 51001, 443, 0x02, append([]byte{1}, mssOption(1460)...), nil))
	nat.egress(odd)
	if got := mssOf(odd, 23); got != 1240 {
		t.Errorf("odd-offset MSS = %d, want 1240", got)
	}
	checkPacket(t, "odd offset", odd)

	small := ipv4(lanAddr, remoteAddr, protoTCP, 4, 0x4000,
		tcpSegment(lanAddr, remoteAddr, 51002, 443, 0x02, mssOption(1200), nil))
	nat.egress(small)
	if got := mssOf(small, 22); got != 1200 {
		t.Errorf("small MSS changed to %d", got)
	}

	// A data segment that merely looks like it has the option is not touched.
	data := ipv4(lanAddr, remoteAddr, protoTCP, 5, 0x4000,
		tcpSegment(lanAddr, remoteAddr, 51000, 443, 0x10, mssOption(1460), nil))
	nat.egress(data)
	if got := mssOf(data, 22); got != 1460 {
		t.Errorf("non-SYN segment was clamped to %d", got)
	}
	if s := nat.stats(); s.Clamped != 3 {
		t.Errorf("clamped = %d, want 3", s.Clamped)
	}
}

func TestICMPErrorIsTranslated(t *testing.T) {
	nat := newTestNAT()
	out := ipv4(lanAddr, remoteAddr, protoUDP, 7, 0x4000,
		udpDatagram(lanAddr, remoteAddr, 40001, 50001, bytes.Repeat([]byte{0xab}, 64), true))
	nat.egress(out)

	// A router on the path quotes our packet (as it saw it: tunnel source) in
	// a "fragmentation needed" error.
	router := [4]byte{100, 64, 0, 1}
	quoted := out[:28]
	in := ipv4(router, tunnelAddr, protoICMP, 8, 0, icmpMessage(icmpUnreachable, 4, 1200, quoted))
	if !nat.ingress(in) {
		t.Fatal("ICMP error dropped")
	}
	if addrOf(in, 16) != lanAddr {
		t.Errorf("outer destination = %v", addrOf(in, 16))
	}
	inner := in[28:]
	if addrOf(inner, 12) != lanAddr {
		t.Errorf("quoted source = %v", addrOf(inner, 12))
	}
	if got := fullChecksum(inner[:20]); got != 0 {
		t.Errorf("bad quoted header checksum (residue %#04x)", got)
	}
	checkPacket(t, "icmp error", in)

	unrelated := ipv4(router, tunnelAddr, protoICMP, 9, 0, icmpMessage(icmpUnreachable, 4, 1200,
		ipv4(tunnelAddr, remoteAddr, protoUDP, 1, 0, udpDatagram(tunnelAddr, remoteAddr, 1, 2, nil, true))[:28]))
	if nat.ingress(unrelated) {
		t.Error("ICMP error for an unknown flow was let in")
	}
}

func TestICMPEcho(t *testing.T) {
	nat := newTestNAT()
	out := ipv4(lanAddr, remoteAddr, protoICMP, 1, 0, icmpMessage(icmpEchoRequest, 0, 0x1234_0001, []byte("ping")))
	nat.egress(out)
	checkPacket(t, "echo", out)

	in := ipv4(remoteAddr, tunnelAddr, protoICMP, 2, 0, icmpMessage(icmpEchoReply, 0, 0x1234_0001, []byte("ping")))
	if !nat.ingress(in) || addrOf(in, 16) != lanAddr {
		t.Fatal("echo reply not restored")
	}
	checkPacket(t, "echo reply", in)
}

func TestFragments(t *testing.T) {
	nat := newTestNAT()
	nat.egress(ipv4(lanAddr, remoteAddr, protoUDP, 1, 0, udpDatagram(lanAddr, remoteAddr, 40001, 50001, nil, true)))

	// Outbound later fragment: only the address and the header checksum change.
	tail := ipv4(lanAddr, remoteAddr, protoUDP, 5, 185, []byte("rest of an outbound datagram"))
	payload := append([]byte(nil), tail[20:]...)
	nat.egress(tail)
	if addrOf(tail, 12) != tunnelAddr || !bytes.Equal(tail[20:], payload) {
		t.Error("outbound fragment not handled as address-only")
	}
	if got := fullChecksum(tail[:20]); got != 0 {
		t.Errorf("bad header checksum on outbound fragment (residue %#04x)", got)
	}

	// Inbound: the first fragment names the flow, the rest follow by IP id.
	head := ipv4(remoteAddr, tunnelAddr, protoUDP, 77, 0x2000, udpDatagram(remoteAddr, tunnelAddr, 50001, 40001, []byte("first part"), true))
	rest := ipv4(remoteAddr, tunnelAddr, protoUDP, 77, 3, []byte("second part"))
	if !nat.ingress(head) || !nat.ingress(rest) {
		t.Fatal("fragmented reply dropped")
	}
	if addrOf(head, 16) != lanAddr || addrOf(rest, 16) != lanAddr {
		t.Error("fragments not restored to the original source")
	}
	if got := fullChecksum(rest[:20]); got != 0 {
		t.Errorf("bad header checksum on inbound fragment (residue %#04x)", got)
	}
}

func TestIdleFlowsExpire(t *testing.T) {
	nat := newTestNAT()
	clock := int64(1000)
	nat.now = func() int64 { return clock }

	nat.egress(ipv4(lanAddr, remoteAddr, protoUDP, 1, 0, udpDatagram(lanAddr, remoteAddr, 40001, 50001, nil, true)))
	clock += flowIdleSeconds + 1
	nat.mu.Lock()
	nat.sweepLocked(clock)
	nat.mu.Unlock()

	reply := ipv4(remoteAddr, tunnelAddr, protoUDP, 2, 0, udpDatagram(remoteAddr, tunnelAddr, 50001, 40001, nil, true))
	if nat.ingress(reply) {
		t.Error("reply for an expired flow was let in")
	}
}

// fakeTun feeds one packet to Read and records what Write receives.
type fakeTun struct {
	tun.Device
	next    []byte
	written [][]byte
}

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	sizes[0] = copy(bufs[0][offset:], f.next)
	return 1, nil
}

func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func (f *fakeTun) File() *os.File { return nil }

func TestDeviceWrapper(t *testing.T) {
	const offset = 4
	fake := &fakeTun{next: ipv4(lanAddr, remoteAddr, protoUDP, 1, 0, udpDatagram(lanAddr, remoteAddr, 40001, 50001, []byte("x"), true))}
	nat := newNATDevice(fake, tunnelAddr, 1280)

	bufs := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	if n, err := nat.Read(bufs, sizes, offset); n != 1 || err != nil {
		t.Fatalf("Read = %d, %v", n, err)
	}
	if addrOf(bufs[0][offset:], 12) != tunnelAddr {
		t.Error("Read did not rewrite the source")
	}

	withOffset := func(pkt []byte) []byte { return append(make([]byte, offset), pkt...) }
	good := withOffset(ipv4(remoteAddr, tunnelAddr, protoUDP, 2, 0, udpDatagram(remoteAddr, tunnelAddr, 50001, 40001, []byte("a"), true)))
	bad := withOffset(ipv4(remoteAddr, tunnelAddr, protoUDP, 3, 0, udpDatagram(remoteAddr, tunnelAddr, 9, 9, []byte("b"), true)))
	good2 := withOffset(ipv4(remoteAddr, tunnelAddr, protoUDP, 4, 0, udpDatagram(remoteAddr, tunnelAddr, 50001, 40001, []byte("c"), true)))

	if n, err := nat.Write([][]byte{good, bad, good2}, offset); n != 3 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if len(fake.written) != 2 {
		t.Fatalf("%d packets reached the device, want 2", len(fake.written))
	}
	for _, pkt := range fake.written {
		if addrOf(pkt, 16) != lanAddr {
			t.Errorf("delivered packet has destination %v", addrOf(pkt, 16))
		}
	}
}
