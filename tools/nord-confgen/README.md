# nord-confgen

Gerador de perfil WireGuard (NordLynx) para a NordVPN usado pelo ARDiscordBypass como segundo provedor, ao lado do `proton-confgen`. Go puro, só biblioteca padrão.

## O que faz

1. Recebe um **token de acesso** do Nord Account e consulta `GET /v1/users/services/credentials` para obter a chave privada NordLynx da conta.
2. Consulta `GET /v1/servers/recommendations` e escolhe o servidor recomendado no primeiro país de `--countries` que tiver um servidor WireGuard online.
3. Grava o perfil em `--output` (permissão `0600`, troca atômica).
4. Salva **apenas a chave NordLynx** em `~/.nordvpn-session.json`. Nas próximas execuções, sem token, o perfil é renovado a partir dessa chave. O token nunca é gravado em disco.

A NordVPN não tem plano gratuito: a conta precisa de assinatura ativa. O endpoint de credenciais não faz parte de uma API pública documentada pela NordVPN e pode mudar; se isso acontecer, o `.conf` WireGuard oficial baixado no Nord Account continua funcionando pelo modo de perfil customizado do aplicativo.

## Uso

```bash
# Login com token lido da entrada padrão (forma usada pelo aplicativo)
echo "$TOKEN" | nord-confgen --token-stdin --countries US,NL,JP --output ardc_vpn.conf

# Renovação com a chave já salva (sem token)
nord-confgen --countries US,NL,JP --output ardc_vpn.conf
```

| Flag | Padrão | Descrição |
| :--- | :--- | :--- |
| `--token-stdin` | — | Lê o token da primeira linha da entrada padrão. |
| `--token <t>` | — | Token direto na linha de comando (fica visível na lista de processos; prefira `--token-stdin`). |
| `--countries` | `US,NL,JP` | Códigos de país em ordem de preferência. Vazio = servidor mais próximo. |
| `--output` | `ardc_vpn.conf` | Caminho do perfil gerado. |
| `--session-file` | `~/.nordvpn-session.json` | Onde a chave NordLynx fica salva. |
| `--api-base` | `https://api.nordvpn.com` | Base da API (usado nos testes). |

A saída segue o mesmo contrato do `proton-confgen` (`Authentication successful`, `Selected server:`, `WireGuard configuration written`, `Successfully generated config`, e `Error: ...` em caso de falha), para que os orquestradores em C++ e Kotlin usem o mesmo parser de progresso. A primeira linha do perfil (`# NordVPN WireGuard Configuration`) identifica o provedor para a renovação automática.

## Compilar e testar

Requer Go 1.22+.

```bash
go test ./...

# Linux x86_64
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ../../PC/bin/nord-confgen .

# Windows x64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ../../PC/bin/nord-confgen.exe .

# Android ARM64
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build -trimpath -ldflags "-s -w" \
  -o ../../Mobile/Android/app/src/main/jniLibs/arm64-v8a/libnordconfgen.so .
```

Os binários de `PC/bin/` são embutidos nos executáveis Desktop na compilação (`objcopy`), da mesma forma que o `proton-confgen`.
