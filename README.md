# wg-mkauthd

Daemon Go para gerenciamento de interface WireGuard via MK-AUTH.

## O que faz

- Escuta comandos via Unix socket (`/run/wgmkauth.sock`)
- Gerencia `wg0.conf` (criar, remover, ativar/desativar peers)
- Gera chaves WireGuard (PrivateKey, PublicKey, PresharedKey)
- Executa `wg-quick up/down` de forma segura
- Integrado ao addon WireGuard do MK-AUTH

## Compilação

```bash
make build
