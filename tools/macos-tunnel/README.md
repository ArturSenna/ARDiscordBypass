# macos-tunnel (`ardc-tunnel`)

Metade privilegiada do ARDiscordBypass no macOS. O macOS não tem namespaces de rede, então o túnel por aplicativo é montado com três peças que este utilitário controla:

1. **WireGuard em userspace** ([wireguard-go](https://git.zx2c4.com/wireguard-go), como biblioteca) numa interface `utunN` que **nunca vira rota padrão**.
2. **Regras do firewall `pf`** que desviam (`route-to`) para essa interface apenas o tráfego de sockets cujo dono é um **grupo unix dedicado**. O `pf` não enxerga aplicativos, mas enxerga o grupo do socket.
3. **Reescrita do endereço de origem**: o pacote desviado chega ao túnel com o endereço da rede local (o kernel escolheu a origem antes do desvio, e o `pf` não traduz o que desvia). O utilitário troca a origem pelo endereço do túnel e desfaz a troca nas respostas, por fluxo.

Quem abre o navegador sob o grupo é o próprio executável `ARDiscordBypass_macos` (`--internal-launch`); este utilitário só informa e encerra os processos que carregam o grupo.

> **Estado**: prévia. O código foi compilado para macOS e exercitado em Linux (túnel real, reescrita de endereços e fluxo do daemon); as partes exclusivas do macOS (`pf`, `ifconfig`, `sysctl`, `utun`) ainda não foram validadas num Mac.

## Comandos

| Comando | Root | O que faz |
| :--- | :---: | :--- |
| `up --conf ARQ [--mtu N] [--gid N] [--keep-tso]` | sim | Sobe o túnel em segundo plano e só retorna depois do handshake. Imprime `READY ifname=… gid=… address=… endpoint=…` |
| `down` | sim | Fecha os processos tunelados, encerra o daemon e desfaz todas as alterações (inclusive restos de uma execução interrompida) |
| `status` | não | Estado em linhas `chave=valor`; código de saída 0 só com o túnel ativo |
| `pids` / `kill` | não | Lista / encerra os processos que rodam sob o grupo do túnel |
| `gid` | não | Grupo usado para os processos tunelados |
| `diag` | sim | Estado do `pf`, da interface e do daemon, para relatos de erro |

Em caso de erro a saída tem uma linha `Error: …` e o código de saída é 1 (mesmo contrato dos geradores de perfil).

## O que é alterado no sistema (e desfeito no `down`)

- **Âncora do `pf` `com.apple/ardiscordbypass`**: o `/etc/pf.conf` não é editado; o conjunto de regras padrão do macOS já avalia tudo o que fica abaixo de `com.apple/`. O `pf` é ligado por referência (`pfctl -E`) e a referência é devolvida (`pfctl -X`), sem desligar o firewall de quem mais o usa.
  ```
  pass out quick on ! lo0 inet proto { tcp, udp } from any to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } group <gid> keep state
  pass out quick on ! lo0 route-to (utunN <endereço do túnel>) inet proto { tcp, udp } from any to any group <gid> keep state
  block return out quick on ! lo0 proto { tcp, udp } from any to any group <gid>
  ```
  A rede local continua direta; todo o resto do grupo entra no túnel; o que sobrar (IPv6 incluído, o túnel é só IPv4) é recusado na hora.
- **`net.inet.tcp.tso=0`** enquanto o túnel está ativo (o valor anterior é restaurado). Com TSO o kernel entrega à placa um segmento TCP gigante para ela dividir; o `route-to` não divide, e um segmento desviado maior que o MTU do túnel é descartado (`pf_route` no xnu). Sem isso, qualquer envio tunelado maior que um segmento travaria. A configuração é global; `--keep-tso` a mantém como está.
- **Interface `utunN`** com o endereço do perfil e MTU 1280, sem rota.
- **`/var/run/ardiscordbypass/`**: estado (`state.json`, `stats.json`), regras carregadas e `tunnel.log`. Nenhum segredo é gravado.

### Kill switch

Se o daemon parar com processos do grupo ainda abertos, ele deixa carregada apenas a regra `block` (com o `pf` ligado): esses processos ficam sem rede em vez de cair em silêncio para a conexão normal. O próximo `up` assume esse estado sem liberar nada no meio; o `down` limpa tudo.

### Grupo

O grupo não precisa existir no diretório de contas: o `pf` compara o número, e nada mais o consulta. É usado o primeiro id livre a partir de 47823.

## Limites conhecidos

- **DNS fica fora do túnel**: as consultas passam pelo resolvedor do sistema, que não pertence ao grupo.
- **Sem IPv6** para os processos tunelados (bloqueado, não roteado).
- **Safari e navegadores WebKit não podem ser tunelados**: a rede deles roda em processos do sistema que não herdam o grupo.
- Um aplicativo que **se reabre sozinho** (por exemplo após se atualizar) volta fora do grupo, portanto fora do túnel.
- A Apple trata `pf`/`utun` manipulados diretamente como técnica legada; uma versão futura do macOS pode exigir Network Extension.

## Compilar e testar

Requer Go 1.23+. Dependências: `golang.zx2c4.com/wireguard` e `golang.org/x/sys`.

```bash
go test ./...

# macOS Apple Silicon e Intel
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o ../../PC/bin/macos-arm64/ardc-tunnel .
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ../../PC/bin/macos-amd64/ardc-tunnel .
```

O linker do Go já assina o binário arm64 de forma ad hoc (exigência do Apple Silicon), também na compilação cruzada a partir do Linux.

`sys_linux.go` existe apenas para desenvolvimento: permite compilar e exercitar o túnel, a reescrita e o daemon em Linux, onde não há `pf` e quem testa configura a interface.
