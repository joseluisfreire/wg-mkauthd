# wg-mkauthd

Daemon Go para provisionamento WireGuard via MK-AUTH.

## Por que existe

O **wg-mkauthd** surge da necessidade de um provisionamento **rápido, estável e seguro** de ramais MikroTik no sistema MK-AUTH — principalmente quando o sistema é executado em **VPS na nuvem**, onde o protocolo PPTP (GRE) é da idade da pedra lascada.

Funciona como um **gateway de comunicação** entre o addon PHP do MK-AUTH e as ferramentas `wg` / `wg-quick`, traduzindo requisições JSON em comandos shell de forma segura e controlada.


> **Fala JSON. Executa shell.**

```text
  PHP (addon)                wg-mkauthd                 Kernel
 ┌───────────┐  JSON/sock  ┌────────────┐   shell   ┌─────────────┐
 │  MK-AUTH  │────────────►│   daemon   │──────────►│ wg          │
 │ (Apache2) │◄────────────│   (Go)     │◄──────────│ wg-quick    │
 └───────────┘  JSON/sock  └────────────┘           └─────────────┘
                           /run/wgmkauth.sock
```

## O que faz

- Escuta comandos via Unix socket (`/run/wgmkauth.sock`)
- Gerencia `wg0.conf` (criar, remover, ativar/desativar peers)
- Gera chaves WireGuard (PrivateKey, PublicKey, PresharedKey)
- Executa `wg-quick up/down` de forma segura
- Retorna sempre JSON estruturado para o addon PHP
- Integrado ao addon WireGuard do MK-AUTH



## O que faz

- Escuta comandos via Unix socket (`/run/wgmkauth.sock`)
- Gerencia `wg0.conf` (criar, remover, ativar/desativar peers)
- Gera chaves WireGuard (PrivateKey, PublicKey, PresharedKey)
- Executa `wg-quick up/down` de forma segura
- Retorna sempre JSON estruturado para o addon PHP
- Auto bring-up/down da interface via flags `--auto-bring-up` / `--auto-bring-down`

## Constantes

| Constante | Valor |
|---|---|
| `socketPath` | `/run/wgmkauth.sock` |
| `wgInterface` | `wg0` |
| `wgConfPath` | `/etc/wireguard/wg0.conf` |
| `logFilePath` | `/var/log/wg-mkauthd.log` |
| `groupName` | `wgmkauth` |
| `defaultKeepalive` | `25` segundos |

## Flags de linha de comando

| Flag | Default | Descrição |
|---|---|---|
| `--config` | `/etc/wg-mkauthd.cfg` | Caminho do arquivo de configuração |
| `--auto-bring-up` | `false` | Executa `wg-quick up wg0` ao iniciar o daemon |
| `--auto-bring-down` | `false` | Executa `wg-quick down wg0` ao encerrar o daemon |
| `--version` | — | Exibe a versão e sai |

## Protocolo de Comunicação

Todas as requisições são enviadas via Unix socket como **uma linha JSON** terminada em `\n`.

**Testar manualmente:**

```bash
echo '{"action":"ping"}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```

**Resposta de sucesso:**

```json
{
  "ok": true,
  "message": "...",
  "data": { ... }
}
```

**Resposta de erro:**

```json
{
  "ok": false,
  "error": "error_code",
  "message": "Descrição legível do erro"
}
```
## Request — Campos aceitos

```json
{
  "action":              "nome-da-acao",
  "publicKey":           "chave pública do peer",
  "allowedIPs":          "10.0.0.2/32",
  "name":                "nome do cliente",
  "address":             "endereço IP do cliente",
  "presharedKey":        "PSK (opcional em enable-client)",
  "persistentKeepalive": 25,
  "applyRuntime":        true,
  "wgPort":              51820,
  "wgIPv4":              "10.66.66.1/24",
  "conf":                "conteúdo completo do wg0.conf (restore)"
}
```

> Nem todos os campos são usados em todas as actions. Veja a tabela abaixo.

## Handlers — Referência Completa

### Geral

| Action | Descrição | Campos obrigatórios | Campos opcionais |
|---|---|---|---|
| `ping` | Health check do daemon | — | — |
| `version` | Versão do daemon, do `wg` e status do kernel | — | — |
| `status` | Estado da interface WireGuard (IP, porta, up/down) | — | — |

### Servidor

| Action | Descrição | Campos obrigatórios | Campos opcionais |
|---|---|---|---|
| `server-create` | Cria `wg0.conf` + gera keypair + sobe interface | — | `wgPort`, `wgIPv4` |
| `server-reset` | Derruba, recria `wg0.conf` com nova keypair, sobe | — | `wgPort`, `wgIPv4`, `address` |
| `server-up` | `wg-quick up wg0` | — | — |
| `server-down` | `wg-quick down wg0` | — | — |
| `server-get-config` | Retorna conteúdo parseado do `wg0.conf` | — | — |
| `restore-wg-conf` | Substitui `wg0.conf` inteiro e reinicia interface | `conf` | — |

### Clientes (Peers)

| Action | Descrição | Campos obrigatórios | Campos opcionais |
|---|---|---|---|
| `list-clients` | Lista todos os peers com stats (rx/tx/handshake) | — | — |
| `create-client` | Gera keypair+PSK, adiciona peer ao runtime e conf | `name`, `address` | — |
| `delete-client` | Remove peer do runtime e do `wg0.conf` | `publicKey` | — |
| `enable-client` | Reativa peer (restaura AllowedIPs) | `publicKey`, `allowedIPs` | `presharedKey` |
| `disable-client` | Desabilita peer (zera AllowedIPs) | `publicKey` | — |
| `update-client-address` | Atualiza o IP/AllowedIPs de um peer | `publicKey`, `allowedIPs` | — |

## Exemplos de Uso

### ping

```bash
echo '{"action":"ping"}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{"ok":true,"data":{"pong":true}}
```

---

### version

```bash
echo '{"action":"version"}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{
  "ok": true,
  "data": {
    "daemonVersion": "v1.0.0",
    "wgVersion": "wireguard-tools v1.0.20210914",
    "socketPath": "/run/wgmkauth.sock",
    "daemonStartedAt": "2026-02-22T21:00:00-03:00",
    "kernelHasWireguard": true
  }
}
```

---

### status

```bash
echo '{"action":"status"}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{
  "ok": true,
  "data": {
    "interface": "wg0",
    "public_ip": "203.0.113.10",
    "port": 51820,
    "if_up": true,
    "wg_show": "interface: wg0 public key: ... listening port: 51820",
    "wg_address": "10.66.66.1/24"
  }
}
```

---

### server-create

```bash
echo '{
  "action": "server-create",
  "wgPort": 51820,
  "wgIPv4": "10.66.66.1/24"
}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{
  "ok": true,
  "message": "Server created and interface up",
  "data": {
    "interface": "wg0",
    "address": "10.66.66.1/24",
    "listenPort": 51820,
    "publicKey": "ServerPubKey..."
  }
}
```

> ⚠️ Retorna erro `already_initialized` se `wg0.conf` já existir. Use `server-reset` para recriar.

---

### server-reset

```bash
echo '{
  "action": "server-reset",
  "wgPort": 51820,
  "wgIPv4": "10.66.66.1/24"
}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{
  "ok": true,
  "message": "Server reset with new keypair and fresh config",
  "data": {
    "interface": "wg0",
    "address": "10.66.66.1/24",
    "listenPort": 51820,
    "publicKey": "NewServerPubKey...",
    "lostPeers": true
  }
}
```

> ⚠️ **Todos os peers serão perdidos!** O campo `lostPeers: true` indica isso.

---

### server-up

```bash
echo '{"action":"server-up"}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{"ok":true,"message":"interface brought up"}
```

---

### server-down

```bash
echo '{"action":"server-down"}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{"ok":true,"message":"interface brought down"}
```

---

### server-get-config

```bash
echo '{"action":"server-get-config"}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{
  "ok": true,
  "data": {
    "interface": "wg0",
    "address": "10.66.66.1/24",
    "listenPort": 51820,
    "hasIPv6": false,
    "hasPostUp": true,
    "hasPostDown": true,
    "rawText": "[Interface]\nAddress = 10.66.66.1/24\n..."
  }
}
```

---

### restore-wg-conf

```bash
echo '{
  "action": "restore-wg-conf",
  "conf": "[Interface]\nAddress = 10.66.66.1/24\nListenPort = 51820\nPrivateKey = ...\n"
}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{"ok":true,"message":"wg0.conf restored successfully, interface is up"}
```

---

### list-clients

```bash
echo '{"action":"list-clients"}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{
  "ok": true,
  "data": {
    "clients": [
      {
        "publicKey": "aBcDeF...",
        "allowedIPs": "10.66.66.2/32",
        "endpoint": "198.51.100.5:43210",
        "latestHandshakeAt": "2026-02-22T23:45:00.000Z",
        "transferRx": 1048576,
        "transferTx": 2097152,
        "persistentKeepalive": "25"
      }
    ]
  }
}
```

---

### create-client

```bash
echo '{
  "action": "create-client",
  "name": "router-cliente-001",
  "address": "10.66.66.2/32"
}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{
  "ok": true,
  "data": {
    "id": "ClientPubKey...",
    "name": "router-cliente-001",
    "address": "10.66.66.2/32",
    "publicKey": "ClientPubKey...",
    "presharedKey": "PskKey...",
    "allowedIPs": "10.66.66.1/32,10.66.66.2/32",
    "persistentKeepalive": 25,
    "config": "[Interface]\\nPrivateKey = ...\\nAddress = 10.66.66.2/32\\n\\n[Peer]\\n..."
  }
}
```

> O campo `config` contém a configuração pronta para importar no MikroTik/cliente.
> O `allowedIPs` retornado inclui `serverIP/32,clientIP/32` para uso no PHP.

---

### delete-client

```bash
echo '{
  "action": "delete-client",
  "publicKey": "ClientPubKey..."
}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{"ok":true,"data":{"publicKey":"ClientPubKey..."}}
```

---

### disable-client

```bash
echo '{
  "action": "disable-client",
  "publicKey": "ClientPubKey..."
}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{"ok":true,"data":{"publicKey":"ClientPubKey..."}}
```

> Zera `AllowedIPs` no runtime e no `wg0.conf`. O peer continua existindo mas sem tráfego.

---

### enable-client

```bash
echo '{
  "action": "enable-client",
  "publicKey": "ClientPubKey...",
  "allowedIPs": "10.66.66.2/32",
  "presharedKey": "PskKey..."
}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{"ok":true,"data":{"publicKey":"ClientPubKey..."}}
```

> O campo `presharedKey` é opcional. Se enviado, atualiza a PSK no conf.

---

### update-client-address

```bash
echo '{
  "action": "update-client-address",
  "publicKey": "ClientPubKey...",
  "allowedIPs": "10.66.66.50/32"
}' | socat - UNIX-CONNECT:/run/wgmkauth.sock
```
```json
{
  "ok": true,
  "data": {
    "publicKey": "ClientPubKey...",
    "allowedIPs": "10.66.66.1/32,10.66.66.50/32"
  }
}
```

> No runtime/conf grava só o `/32` do cliente. No JSON de retorno inclui `serverIP/32,clientIP/32` pro PHP.

## Códigos de Erro

| Código | Handler(s) | Descrição |
|---|---|---|
| `empty_input` | — | Nenhum JSON recebido |
| `bad_json` | — | JSON inválido |
| `invalid_action` | — | Action desconhecida |
| `wg_down` | `status` | Interface `wg0` não está UP |
| `wg_show_failed` | `status` | Falha ao executar `wg show` |
| `conf_not_found` | `server-get-config` | `wg0.conf` não encontrado |
| `conf_read_failed` | `server-get-config` | Falha ao ler `wg0.conf` |
| `conf_write_failed` | `server-create`, `server-reset`, `restore-wg-conf` | Falha ao gravar `wg0.conf` |
| `already_initialized` | `server-create` | `wg0.conf` já existe |
| `keygen_failed` | `server-create`, `server-reset`, `create-client` | Falha ao gerar keypair |
| `psk_failed` | `create-client` | Falha ao gerar PresharedKey |
| `wg_quick_up_failed` | `server-up`, `server-create`, `server-reset`, `restore-wg-conf` | `wg-quick up` falhou |
| `wg_quick_down_failed` | `server-down`, `server-reset`, `restore-wg-conf` | `wg-quick down` falhou |
| `wg_set_failed` | `create-client`, `update-client-address` | `wg set` falhou |
| `wg_remove_failed` | `delete-client` | `wg set peer remove` falhou |
| `wg_disable_failed` | `disable-client` | `wg set` (zerar AllowedIPs) falhou |
| `wg_enable_failed` | `enable-client` | `wg set` (restaurar AllowedIPs) falhou |
| `wg_dump_failed` | `list-clients` | `wg show dump` falhou |
| `server_pub_failed` | `create-client` | Falha ao obter PublicKey do servidor |
| `missing_name` | `create-client` | Campo `name` ausente |
| `missing_address` | `create-client` | Campo `address` ausente |
| `missing_publicKey` | `delete-client`, `disable-client` | Campo `publicKey` ausente |
| `missing_fields` | `enable-client`, `update-client-address` | Campos obrigatórios ausentes |
| `missing_conf` | `restore-wg-conf` | Campo `conf` ausente |
| `invalid_publicKey` | `delete-client`, `disable-client`, `enable-client`, `update-client-address` | PublicKey com formato inválido |

## Compilação

```bash
make build
```

O binário é compilado estaticamente (`CGO_ENABLED=0`) — **zero dependências externas**.

## Segurança

| Aspecto | Implementação |
|---|---|
| **Socket** | Permissão `0660`, owner `root:wgmkauth` |
| **Binário** | Compilado estaticamente — sem dependências |
| **Rede** | Zero portas abertas — comunicação local via Unix socket |
| **Validação** | JSON parseado e validado em todas as requisições |
| **PublicKey** | Validação de formato base64 antes de qualquer operação |
| **Comandos** | Apenas `wg` e `wg-quick` são executados (whitelist) |
| **Conf** | `wg0.conf` com permissão `0600` (somente root) |
| **Logs** | `/var/log/wg-mkauthd.log` com timestamp RFC3339 |

## Licença

[MIT](LICENSE)


