// wg-mkauthd/main.go
package main

import (
	"flag"
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	daemonVersion = "v1.0.3"
	socketPath   = "/run/wgmkauth.sock"
	wgInterface  = "wg0"
	wgConfPath   = "/etc/wireguard/" + wgInterface + ".conf"
	logFilePath  = "/var/log/wg-mkauthd.log"
	groupName    = "wgmkauth"
)

var daemonStartedAt time.Time
var (
    cfgPath       = flag.String("config", "/etc/wg-mkauthd.cfg", "config file")
    autoBringUp   = flag.Bool("auto-bring-up", false, "run wg-quick up on start")
    autoBringDown = flag.Bool("auto-bring-down", false, "run wg-quick down on shutdown")
)

type Request struct {
	Action              string `json:"action"`
	PublicKey           string `json:"publicKey,omitempty"`
	AllowedIPs          string `json:"allowedIPs,omitempty"`
	Name                string `json:"name,omitempty"`
	Address             string `json:"address,omitempty"`
	PresharedKey        string `json:"presharedKey,omitempty"`
	PersistentKeepalive int    `json:"persistentKeepalive,omitempty"`
	ApplyRuntime        *bool  `json:"applyRuntime,omitempty"`
	WGPort 				int    `json:"wgPort,omitempty"`
	WGIPv4 				string `json:"wgIPv4,omitempty"`
	Conf   				string `json:"conf,omitempty"`
	Endpoint            string `json:"endpoint,omitempty"`
}

type Response struct {
	OK      bool        `json:"ok"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type StatusData struct {
	Interface string `json:"interface"`
	PublicIP  string `json:"public_ip"`
	Port      int    `json:"port"`
	IfUp      bool   `json:"if_up"`
	WgShow    string `json:"wg_show"`
	WgAddress string `json:"wg_address"`
}

type ServerConfigData struct {
	Interface   string `json:"interface"`
	Address     string `json:"address"`
	ListenPort  int    `json:"listenPort"`
	HasIPv6     bool   `json:"hasIPv6"`
	HasPostUp   bool   `json:"hasPostUp"`
	HasPostDown bool   `json:"hasPostDown"`
	RawText     string `json:"rawText"`
}

type Client struct {
	PublicKey          string  `json:"publicKey"`
	AllowedIPs         string  `json:"allowedIPs"`
	Endpoint           string  `json:"endpoint"`
	LatestHandshakeISO *string `json:"latestHandshakeAt,omitempty"`
	TransferRx         uint64  `json:"transferRx"`
	TransferTx         uint64  `json:"transferTx"`
	Keepalive          string  `json:"persistentKeepalive"`
}

type VersionData struct {
    DaemonVersion     string `json:"daemonVersion"`
    WgVersion         string `json:"wgVersion"`
    SocketPath        string `json:"socketPath"`
    DaemonStartedAt   string `json:"daemonStartedAt,omitempty"`
    KernelHasWireguard bool   `json:"kernelHasWireguard"`
}

type ListClientsData struct {
	Clients []Client `json:"clients"`
}

var showVersion = flag.Bool("version", false, "show daemon version and exit")

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("wg-mkauthd %s\n", daemonVersion)
		os.Exit(0)
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
    _ = os.Remove(socketPath)

    l, err := net.Listen("unix", socketPath)
    if err != nil {
        return fmt.Errorf("listen unix: %w", err)
    }
    
    if err := fixSocketPerms(socketPath); err != nil {
        return fmt.Errorf("fix perms: %w", err)
    }

    logInfo("wg-mkauthd started, listening on " + socketPath)
    daemonStartedAt = time.Now()

    // autoBringUp: tentar subir interface no start
    if *autoBringUp {
        if !wgIsUp() {
            cmd := exec.Command("wg-quick", "up", wgInterface)
            out, err := cmd.CombinedOutput()
            if err != nil {
                logError(fmt.Sprintf("autoBringUp failed: %v out=%s", err, string(out)))
            } else {
                logInfo("autoBringUp: interface " + wgInterface + " is up")
            }
        } else {
            logInfo("autoBringUp: interface " + wgInterface + " already up")
        }
    }

	// graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				// se o listener foi fechado durante o shutdown, sai do loop
				if ne, ok := err.(*net.OpError); ok && ne.Err != nil &&
					ne.Err.Error() == "use of closed network connection" {
					logInfo("listener closed, stopping accept loop")
					return
				}
				logError(fmt.Sprintf("accept: %v", err))
				continue
			}
			go handleConn(conn)
		}
	}()

	s := <-sigCh
	logInfo("received signal: " + s.String())

	// força o Accept a acordar com erro
	_ = l.Close()

	// autoBringDown: tentar derrubar interface no stop
	if *autoBringDown {
		cmd := exec.Command("wg-quick", "down", wgInterface)
		out, err := cmd.CombinedOutput()
		if err != nil {
			logError(fmt.Sprintf("autoBringDown failed: %v out=%s", err, string(out)))
		} else {
			logInfo("autoBringDown: interface " + wgInterface + " is down")
		}
	}

	return nil
}

// ----------------------------------------------------------------------------
// Socket / perms
// ----------------------------------------------------------------------------

func fixSocketPerms(path string) error {
	if err := os.Chmod(path, 0660); err != nil {
		return err
	}
	gid, err := lookupGID(groupName)
	if err != nil {
		// se não achar grupo, deixa root:root
		logError("lookup group failed: " + err.Error())
		return nil
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return err
	}
	return nil
}

func lookupGID(name string) (int, error) {
	// jeito simples: ler /etc/group
	f, err := os.Open("/etc/group")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, name+":") {
			parts := strings.Split(line, ":")
			if len(parts) >= 3 {
				return strconv.Atoi(parts[2])
			}
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, errors.New("group not found")
}

// ----------------------------------------------------------------------------
// Conn handler
// ----------------------------------------------------------------------------

func handleConn(conn net.Conn) {
	defer conn.Close()

	r := bufio.NewReader(conn)
	line, err := r.ReadBytes('\n')
	if err != nil {
		// cliente fechou ou erro de leitura
		return
	}
	raw := strings.TrimSpace(string(line))
	if raw == "" {
		writeJSON(conn, Response{OK: false, Error: "empty_input", Message: "No JSON input"})
		return
	}
	logInfo("line: " + raw)

	var req Request
	if err := json.Unmarshal([]byte(raw), &req); err != nil {
		logError("json_unmarshal: " + err.Error())
		writeJSON(conn, Response{OK: false, Error: "bad_json", Message: "Invalid JSON"})
		return
	}

	logInfo("action: '" + req.Action + "'")

	resp := dispatch(req)
	writeJSON(conn, resp)
}

func writeJSON(conn net.Conn, resp Response) {
	enc := json.NewEncoder(conn)
	_ = enc.Encode(resp)
}

// ----------------------------------------------------------------------------
// Dispatch
// ----------------------------------------------------------------------------

func dispatch(req Request) Response {
	switch req.Action {
	case "ping":
		return handlePing()
	case "status":
		return handleStatus()
	case "list-clients":
		return handleListClients()
	case "create-client":
		return handleCreateClient(req)
	case "delete-client":
		return handleDeleteClient(req)
	case "enable-client":
		return handleEnableClient(req)
	case "disable-client":
		return handleDisableClient(req)
	case "update-client-address":
		return handleUpdateClientAddress(req)
	case "version":
		return handleVersion()
	case "server-up":
		return handleServerUp()
	case "server-down":
		return handleServerDown()
	case "server-get-config":
		return handleServerGetConfig()
	case "server-create":
		return handleServerCreate(req)
	case "server-reset":
		return handleServerReset(req)
	case "restore-wg-conf":
		return handleRestoreWgConf(req)	
	default:
		return Response{OK: false, Error: "invalid_action", Message: "Unknown action: " + req.Action}
	}
}

// ----------------------------------------------------------------------------
// Handlers básicos
// ----------------------------------------------------------------------------

func handlePing() Response {
	return Response{
		OK:   true,
		Data: map[string]any{"pong": true},
	}
}

func handleStatus() Response {
	ifUp := wgIsUp()
	if !ifUp {
		return Response{
			OK:      false,
			Error:   "wg_down",
			Message: "WireGuard interface " + wgInterface + " is down",
		}
	}

	wgTxt, err := wgShowText()
	if err != nil {
		logError("wg_show_text: " + err.Error())
		return Response{OK: false, Error: "wg_show_failed", Message: "Failed to run wg show"}
	}

	port := extractListeningPort(wgTxt)
	pubIP := firstHostIP()
	wgAddr := readWgAddressFromConf()
	
	data := StatusData{
		Interface: wgInterface,
		PublicIP:  pubIP,
		Port:      port,
		IfUp:      true,
		WgShow:    strings.ReplaceAll(wgTxt, "\n", " "),
		WgAddress: wgAddr,
	}
	return Response{OK: true, Data: data}
}
// ----------------------------------------------------------------------------
// Server Interface control: wg-quick up/down
// ----------------------------------------------------------------------------

func handleServerUp() Response {
	if wgIsUp() {
		return Response{
			OK:      true,
			Message: "interface " + wgInterface + " already up",
		}
	}

	cmd := exec.Command("wg-quick", "up", wgInterface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logError(fmt.Sprintf("server-up: wg-quick up %s failed: %v out=%s", wgInterface, err, string(out)))
		return Response{
			OK:      false,
			Error:   "wg_quick_up_failed",
			Message: "wg-quick up failed",
		}
	}

	logInfo("server-up: wg-quick up " + wgInterface + " ok")
	return Response{
		OK:      true,
		Message: "interface brought up",
	}
}

func handleServerDown() Response {
	if !wgIsUp() {
		return Response{
			OK:      true,
			Message: "interface " + wgInterface + " already down",
		}
	}

	cmd := exec.Command("wg-quick", "down", wgInterface)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logError(fmt.Sprintf("server-down: wg-quick down %s failed: %v out=%s", wgInterface, err, string(out)))
		return Response{
			OK:      false,
			Error:   "wg_quick_down_failed",
			Message: "wg-quick down failed",
		}
	}

	logInfo("server-down: wg-quick down " + wgInterface + " ok")
	return Response{
		OK:      true,
		Message: "interface brought down",
	}
}

func handleServerGetConfig() Response {
	b, err := os.ReadFile(wgConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Response{
				OK:    false,
				Error: "conf_not_found",
				Message: "WireGuard config file not found at " + wgConfPath +
					" (maybe not initialized yet)",
			}
		}
		logError("server-get-config read: " + err.Error())
		return Response{OK: false, Error: "conf_read_failed", Message: "Failed to read wg config"}
	}

	lines := strings.Split(string(b), "\n")

	var address string
	var listenPort int
	var hasIPv6 bool
	var hasPostUp bool
	var hasPostDown bool

	inInterface := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.HasPrefix(t, "[") {
			// novo bloco
			if strings.EqualFold(t, "[Interface]") {
				inInterface = true
				continue
			}
			// saiu da interface
			if inInterface {
				break
			}
			continue
		}
		if !inInterface {
			continue
		}

		if strings.HasPrefix(t, "Address") {
			parts := strings.SplitN(t, "=", 2)
			if len(parts) == 2 {
				address = strings.TrimSpace(parts[1])
				if strings.Contains(address, ":") {
					hasIPv6 = true
				}
			}
			continue
		}
		if strings.HasPrefix(t, "ListenPort") {
			parts := strings.SplitN(t, "=", 2)
			if len(parts) == 2 {
				lp := strings.TrimSpace(parts[1])
				listenPort, _ = strconv.Atoi(lp)
			}
			continue
		}
		if strings.HasPrefix(t, "PostUp") {
			hasPostUp = true
			continue
		}
		if strings.HasPrefix(t, "PostDown") {
			hasPostDown = true
			continue
		}
	}

	data := ServerConfigData{
		Interface:   wgInterface,
		Address:     address,
		ListenPort:  listenPort,
		HasIPv6:     hasIPv6,
		HasPostUp:   hasPostUp,
		HasPostDown: hasPostDown,
		RawText:     string(b),
	}
	return Response{OK: true, Data: data}
}

func handleServerReset(req Request) Response {
	// derruba interface antes de mexer no conf
	if wgIsUp() {
		cmd := exec.Command("wg-quick", "down", wgInterface)
		if out, err := cmd.CombinedOutput(); err != nil {
			logError(fmt.Sprintf("server-reset wg-quick down failed: %v out=%s", err, string(out)))
			return Response{
				OK:      false,
				Error:   "wg_quick_down_failed",
				Message: "Failed to bring interface down before reset",
			}
		}
	}

	// tenta reaproveitar porta atual, se possível
	currentPort := 0
	if txt, err := wgShowText(); err == nil {
		currentPort = extractListeningPort(txt)
	}

	port := req.WGPort
	if port <= 0 {
		if currentPort > 0 {
			port = currentPort
		} else {
			port = 51820
		}
	}

	// defaults de address (poderíamos receber por req.Address depois)
	wgIPv4 := strings.TrimSpace(req.WGIPv4)
	if wgIPv4 == "" {
		wgIPv4 = strings.TrimSpace(req.Address) // compat com chamadas antigas
	}
	if wgIPv4 == "" {
		wgIPv4 = "10.66.66.1/24" // default final
	}

	// gera nova key do servidor
	priv, pub, err := genKeypair()
	if err != nil {
		logError("server-reset genKeypair: " + err.Error())
		return Response{
			OK:      false,
			Error:   "keygen_failed",
			Message: "Failed to generate new server keypair",
		}
	}

	// interface pública do host (para PostUp/PostDown)
	pubNIC := firstHostNic()

	conf := buildServerConfFromDefaults(priv, wgIPv4, "", port, pubNIC)
	// escreve wg0.conf novo
	if err := os.WriteFile(wgConfPath, []byte(conf), 0o600); err != nil {
		logError("server-reset write wgConfPath: " + err.Error())
		return Response{
			OK:      false,
			Error:   "conf_write_failed",
			Message: "Failed to write new wg config",
		}
	}

	// sobe interface com novo conf
	cmdUp := exec.Command("wg-quick", "up", wgInterface)
	if out, err := cmdUp.CombinedOutput(); err != nil {
		logError(fmt.Sprintf("server-reset wg-quick up failed: %v out=%s", err, string(out)))
		return Response{
			OK:      false,
			Error:   "wg_quick_up_failed",
			Message: "Failed to bring interface up after reset",
		}
	}

	logInfo("server-reset completed with new keypair, conf recreated")

	data := map[string]any{
		"interface":  wgInterface,
		"address":    wgIPv4,
		"listenPort": port,
		"publicKey":  pub,
		"lostPeers":  true,
	}

	return Response{
		OK:      true,
		Message: "Server reset with new keypair and fresh config",
		Data:    data,
	}
}

// ============================================================================
// Handler: restore-wg-conf (substitui o antigo backup)
// ============================================================================

func handleRestoreWgConf(req Request) Response {
    conf := strings.TrimSpace(req.Conf)
    if conf == "" {
        return Response{
            OK:      false,
            Error:   "missing_conf",
            Message: "Field 'conf' is required for restore-wg-conf",
        }
    }

    // 1. Derruba a interface (se estiver up)
    if wgIsUp() {
        cmd := exec.Command("wg-quick", "down", wgInterface)
        if out, err := cmd.CombinedOutput(); err != nil {
            logError(fmt.Sprintf("restore-wg-conf: wg-quick down failed: %v out=%s", err, string(out)))
            return Response{
                OK:      false,
                Error:   "wg_quick_down_failed",
                Message: "Failed to bring interface down before restore",
            }
        }
    }

    // 2. Escreve o conf
    if err := os.WriteFile(wgConfPath, []byte(conf), 0o600); err != nil {
        logError("restore-wg-conf: write failed: " + err.Error())
        return Response{
            OK:      false,
            Error:   "conf_write_failed",
            Message: "Failed to write wg0.conf: " + err.Error(),
        }
    }

    // 3. Sobe a interface
    cmdUp := exec.Command("wg-quick", "up", wgInterface)
    if out, err := cmdUp.CombinedOutput(); err != nil {
        logError(fmt.Sprintf("restore-wg-conf: wg-quick up failed: %v out=%s", err, string(out)))
        return Response{
            OK:      false,
            Error:   "wg_quick_up_failed",
            Message: "Failed to bring interface up after restore: " + string(out),
        }
    }

    logInfo("restore-wg-conf: wg0.conf restored and interface up")
    return Response{
        OK:      true,
        Message: "wg0.conf restored successfully, interface is up",
    }
}

func handleServerCreate(req Request) Response {
    // se conf já existe, não cria de novo (evita destruir peers)
    if _, err := os.Stat(wgConfPath); err == nil {
        return Response{
            OK:      false,
            Error:   "already_initialized",
            Message: "wg0.conf already exists; use server-reset to recreate",
        }
    }

    // porta
    port := req.WGPort
    if port <= 0 {
        port = 51820
    }

    // ipv4
    wgIPv4 := strings.TrimSpace(req.WGIPv4)
    if wgIPv4 == "" {
        wgIPv4 = "10.66.66.1/24"
    }
    
    priv, pub, err := genKeypair()
    if err != nil {
        return Response{OK: false, Error: "keygen_failed", Message: "Failed to generate server keypair"}
    }

    pubNIC := firstHostNic()
	conf := buildServerConfFromDefaults(priv, wgIPv4, "", port, pubNIC)
    if err := os.WriteFile(wgConfPath, []byte(conf), 0o600); err != nil {
        return Response{OK: false, Error: "conf_write_failed", Message: "Failed to write new wg config"}
    }

    // sobe
    cmdUp := exec.Command("wg-quick", "up", wgInterface)
    if out, err := cmdUp.CombinedOutput(); err != nil {
        logError(fmt.Sprintf("server-create wg-quick up failed: %v out=%s", err, string(out)))
        return Response{OK: false, Error: "wg_quick_up_failed", Message: "Failed to bring interface up"}
    }

	return Response{
		OK:      true,
		Message: "Server created and interface up",
		Data: map[string]any{
			"interface":  wgInterface,
			"address":    wgIPv4,
			"listenPort": port,
			"publicKey":  pub,
		},
	}
}

// ----------------------------------------------------------------------------
// Versão / about
// ----------------------------------------------------------------------------

func handleVersion() Response {
    wgVer := strings.TrimSpace(runCmdVersion("wg", "--version"))

    // testa se o módulo wireguard está carregado (simples lsmod)
    lsmodOut := runCmdVersion("sh", "-c", "lsmod | grep -w wireguard || true")
    hasKernel := strings.TrimSpace(lsmodOut) != ""

    data := VersionData{
        DaemonVersion:      daemonVersion,
        WgVersion:          wgVer,
        SocketPath:         socketPath,
        DaemonStartedAt:    daemonStartedAt.Format(time.RFC3339),
        KernelHasWireguard: hasKernel,
    }
    return Response{OK: true, Data: data}
}

func runCmdVersion(bin string, args ...string) string {
    cmd := exec.Command(bin, args...)
    out, err := cmd.CombinedOutput()
    if err != nil {
        logError(fmt.Sprintf("version: %s %v failed: %v out=%s", bin, args, err, string(out)))
        return ""
    }
    return string(out)
}

func handleListClients() Response {
	clients, err := buildClientsFromWg()
	if err != nil {
		logError("build_clients: " + err.Error())
		return Response{OK: false, Error: "wg_dump_failed", Message: "Failed to get clients from wg"}
	}
	return Response{OK: true, Data: ListClientsData{Clients: clients}}
}

//create Client
type CreateClientData struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	Address             string `json:"address"`
	PublicKey           string `json:"publicKey"`
	PresharedKey        string `json:"presharedKey"`
	AllowedIPs          string `json:"allowedIPs"`
	PersistentKeepalive int    `json:"persistentKeepalive"`
	Config              string `json:"config"`
}

const (
	defaultKeepalive = 25
)

func handleCreateClient(req Request) Response {
    name := strings.TrimSpace(req.Name)
    addr := strings.TrimSpace(req.Address)

    if name == "" {
        return Response{
            OK:      false,
            Error:   "missing_name",
            Message: `Field "name" is required for create-client`,
        }
    }
    if addr == "" {
        return Response{
            OK:      false,
            Error:   "missing_address",
            Message: `Field "address" is required for create-client`,
        }
    }

    priv, pub, err := genKeypair()
    if err != nil {
        logError("create-client genKeypair: " + err.Error())
        return Response{
            OK:      false,
            Error:   "keygen_failed",
            Message: "Failed to generate WireGuard keypair",
        }
    }

    psk, err := genPresharedKey()
    if err != nil {
        logError("create-client genPresharedKey: " + err.Error())
        return Response{
            OK:      false,
            Error:   "psk_failed",
            Message: "Failed to generate preshared key",
        }
    }

    // pega IP v4 do servidor a partir do wg0.conf
    serverIP := getServerIPv4FromConf()
    
    // --- INÍCIO DA BLINDAGEM ---
    // Limpa qualquer lixo que o PHP tenha mandado junto com o IP do cliente
    cleanAddr := sanitizeAllowedIPs(addr, serverIP)
    
	// 1) Allowed usado no runtime/conf: SÓ O IP LIMPO DO CLIENTE
    allowedRuntime := cleanAddr
    
	// AllowedIPs: o JSON que volta pro PHP pode levar o duplo (como ele espera) ou o limpo.
    // Vamos manter a sua lógica original de devolver duplo pro JSON, mas o runtime/conf usa o limpo.
    allowed := cleanAddr
    if serverIP != "" {
        allowed = fmt.Sprintf("%s/32,%s", serverIP, cleanAddr)
    }
    // --- FIM DA BLINDAGEM ---
    // wg set wg0 peer <pub> preshared-key <psk> allowed-ips <allowed>
    cmd := exec.Command(
        "wg", "set", wgInterface,
        "peer", pub,
        "preshared-key", "/dev/stdin",
        "allowed-ips", allowedRuntime,
    )
    cmd.Stdin = strings.NewReader(psk + "\n")
    if out, err := cmd.CombinedOutput(); err != nil {
        logError("create-client wg set failed: " + err.Error() + " out=" + string(out))
        return Response{
            OK:      false,
            Error:   "wg_set_failed",
            Message: "Failed to add peer to interface " + wgInterface,
        }
    }

    logInfo(fmt.Sprintf("create-client name='%s' addr='%s' pub='%s' allowed='%s'", name, addr, pub, allowed))

    if err := appendClientToConf(name, pub, psk, allowedRuntime); err != nil {
        logError("create-client appendClientToConf: " + err.Error())
    }

    // monta config do client
    serverPub, err := cmdGetServerPublicKey()
    if err != nil {
        logError("create-client get server pubkey: " + err.Error())
        return Response{
            OK:      false,
            Error:   "server_pub_failed",
            Message: "Failed to get server public key",
        }
    }

    // --- INÍCIO DA LÓGICA DE ENDPOINT (MANUAL VS AUTO) ---
    var endpoint string
    reqEndpoint := strings.TrimSpace(req.Endpoint)
    
    if reqEndpoint != "" {
        // Se o PHP mandou um IP/Domínio manual do banco (ex: "200.20.20.5" ou "vpn.provedor.com")
        // Vamos anexar a porta do servidor, caso o PHP não tenha mandado a porta junto.
        if strings.Contains(reqEndpoint, ":") {
            endpoint = reqEndpoint // Já veio com porta (ex: ip:51820)
        } else {
            // Descobre a porta que o wg0 está usando agora
            port := 51820
            if txt, err := wgShowText(); err == nil {
                if p := extractListeningPort(txt); p > 0 {
                    port = p
                }
            }
            endpoint = fmt.Sprintf("%s:%d", reqEndpoint, port)
        }
    } else {
        // Se o PHP mandou vazio, usa a redundância automática (curl)
        endpoint = getCurrentEndpoint()
    }
    // --- FIM DA LÓGICA DE ENDPOINT ---

    cfg := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = %d
`, priv, addr, serverPub, psk, endpoint, allowed, defaultKeepalive)

    cfgJson := strings.ReplaceAll(cfg, "\r", "")
    cfgJson = strings.ReplaceAll(cfgJson, "\n", "\\n")

    data := CreateClientData{
        ID:                  pub,
        Name:                name,
        Address:             addr,
        PublicKey:           pub,
        PresharedKey:        psk,
        AllowedIPs:          allowed,
        PersistentKeepalive: defaultKeepalive,
        Config:              cfgJson,
    }

    return Response{
        OK:   true,
        Data: data,
    }
}

func cmdGetServerPublicKey() (string, error) {
	out, err := exec.Command("wg", "show", wgInterface, "public-key").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
//delete client
func handleDeleteClient(req Request) Response {
	pub := strings.TrimSpace(req.PublicKey)
	if pub == "" {
		logError(fmt.Sprintf("delete-client missing_publicKey req=%+v", req))
		return Response{
			OK:      false,
			Error:   "missing_publicKey",
			Message: `Field "publicKey" is required for delete-client`,
		}
	}

	// valida formato básico, igual shell (base64)
	if !isValidPublicKey(pub) {
		logError(fmt.Sprintf("delete-client invalid_publicKey pub=%q", pub))
		return Response{
			OK:      false,
			Error:   "invalid_publicKey",
			Message: `Field "publicKey" has invalid format`,
		}
	}

	// 1) Remove do runtime se existir (wg show wg0 dump ...)
	peers, err := wgShowPeers()
	if err != nil {
		logError("delete-client wg_show_failed: " + err.Error())
		// segue adiante pra tentar mexer no conf mesmo assim, igual shell
	}

	if peers[pub] {
		if err := wgSetPeerRemove(pub); err != nil {
			logError("delete-client runtime-remove-failed pub='" + pub + "' err=" + err.Error())
			return Response{
				OK:      false,
				Error:   "wg_remove_failed",
				Message: "Failed to remove peer from interface " + wgInterface,
			}
		}
		logInfo("delete-client runtime-removed pub='" + pub + "'")
	} else {
		logInfo("delete-client runtime-peer-not-found pub='" + pub + "'")
	}

	// 2) Remove do arquivo de configuração, espelhando o sed/awk do shell
	if err := deletePeerFromConf(pub); err != nil {
		logError("delete-client conf-remove-error pub='" + pub + "' err=" + err.Error())
		// shell loga erro mas ainda responde ok; vamos seguir igual
	}

	return Response{
		OK: true,
		Data: map[string]string{
			"publicKey": pub,
		},
	}
}

//disable Client
func handleDisableClient(req Request) Response {
	pub := strings.TrimSpace(req.PublicKey)
	if pub == "" {
		logError(fmt.Sprintf("disable-client missing_publicKey req=%+v", req))
		return Response{
			OK:      false,
			Error:   "missing_publicKey",
			Message: `Field "publicKey" is required for disable-client`,
		}
	}
	if !isValidPublicKey(pub) {
		logError(fmt.Sprintf("disable-client invalid_publicKey pub=%q", pub))
		return Response{
			OK:      false,
			Error:   "invalid_publicKey",
			Message: `Field "publicKey" has invalid format`,
		}
	}

	// 1) runtime: zerar AllowedIPs -> (none)
	cmd := exec.Command("wg", "set", wgInterface, "peer", pub, "allowed-ips", "")
	if out, err := cmd.CombinedOutput(); err != nil {
		logError("disable-client wg set failed: " + err.Error() + " out=" + string(out))
		return Response{
			OK:      false,
			Error:   "wg_disable_failed",
			Message: "Failed to disable peer on " + wgInterface,
		}
	}
	logInfo("disable-client runtime-updated pub='" + pub + "' allowed-ips=\"\"")

	// 2) conf: usar a mesma janela do awk para trocar AllowedIPs
	if err := setAllowedIPsWindow(pub, ""); err != nil {
		logError("disable-client conf-setAllowedIPsWindow pub='" + pub + "' err=" + err.Error())
	}

	return Response{
		OK: true,
		Data: map[string]string{
			"publicKey": pub,
		},
	}
}

//enable Client
func handleEnableClient(req Request) Response {
	pub := strings.TrimSpace(req.PublicKey)
	allowed := strings.TrimSpace(req.AllowedIPs)

	if pub == "" || allowed == "" {
		logError(fmt.Sprintf("enable-client missing_fields pub=%q allowed=%q", pub, allowed))
		return Response{
			OK:    false,
			Error: "missing_fields",
			Message: `Fields "publicKey" and "allowedIPs" are required for ` +
				"enable-client",
		}
	}
	if !isValidPublicKey(pub) {
		logError(fmt.Sprintf("enable-client invalid_publicKey pub=%q", pub))
		return Response{
			OK:      false,
			Error:   "invalid_publicKey",
			Message: `Field "publicKey" has invalid format`,
		}
	}
    // --- INÍCIO DA BLINDAGEM ---
    serverIP := getServerIPv4FromConf()
    allowed = sanitizeAllowedIPs(allowed, serverIP)
    // --- FIM DA BLINDAGEM ---
	// 1) runtime: reaplicar allowed-ips (+ psk se vier)
	args := []string{"set", wgInterface, "peer", pub, "allowed-ips", allowed}
	var stdinStr string
	if strings.TrimSpace(req.PresharedKey) != "" {
		args = append(args, "preshared-key", "/dev/stdin")
		stdinStr = strings.TrimSpace(req.PresharedKey) + "\n"
	}

	cmd := exec.Command("wg", args...)
	if stdinStr != "" {
		cmd.Stdin = strings.NewReader(stdinStr)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		logError("enable-client wg set failed: " + err.Error() + " out=" + string(out))
		return Response{
			OK:      false,
			Error:   "wg_enable_failed",
			Message: "Failed to enable peer on " + wgInterface,
		}
	}
	logInfo(fmt.Sprintf("enable-client runtime-updated pub='%s' allowed='%s'", pub, allowed))

	// 2) conf: mesma janela do awk para AllowedIPs
	if err := setAllowedIPsWindow(pub, allowed); err != nil {
		logError("enable-client conf-setAllowedIPsWindow pub='" + pub + "' err=" + err.Error())
	}

	// 3) conf: se vier psk, atualiza PresharedKey dentro da mesma janela
	if strings.TrimSpace(req.PresharedKey) != "" {
		if err := setPresharedKeyWindow(pub, strings.TrimSpace(req.PresharedKey)); err != nil {
			logError("enable-client conf-setPresharedKeyWindow pub='" + pub + "' err=" + err.Error())
		}
	}

	return Response{
		OK: true,
		Data: map[string]string{
			"publicKey": pub,
		},
	}
}

// update-client-address
func handleUpdateClientAddress(req Request) Response {
    pub := strings.TrimSpace(req.PublicKey)
    clientAddr := strings.TrimSpace(req.AllowedIPs) // ex: 10.66.66.84/32

    if pub == "" || clientAddr == "" {
        logError(fmt.Sprintf("update-client-address: missing_fields pub=%q addr=%q", pub, clientAddr))
        return Response{
            OK:      false,
            Error:   "missing_fields",
            Message: "Fields publicKey and allowedIPs (client address) are required for update-client-address",
        }
    }
    if !isValidPublicKey(pub) {
        logError(fmt.Sprintf("update-client-address: invalid_publicKey %q", pub))
        return Response{
            OK:      false,
            Error:   "invalid_publicKey",
            Message: "Field publicKey has invalid format",
        }
    }
    // --- INÍCIO DA BLINDAGEM ---
    serverIP := getServerIPv4FromConf()
    clientAddr = sanitizeAllowedIPs(clientAddr, serverIP)
    // --- FIM DA BLINDAGEM ---
    // 1) runtime/conf: só o /32 do cliente
    allowedRuntime := clientAddr

    cmd := exec.Command("wg", "set", wgInterface, "peer", pub, "allowed-ips", allowedRuntime)
    if out, err := cmd.CombinedOutput(); err != nil {
        logError(fmt.Sprintf("update-client-address: wg set failed: %v out=%s", err, string(out)))
        return Response{
            OK:      false,
            Error:   "wg_set_failed",
            Message: "Failed to update allowed-ips for peer on interface " + wgInterface,
        }
    }
    logInfo(fmt.Sprintf("update-client-address: runtime-updated %s allowed-ips=%s", pub, allowedRuntime))

    // 2) conf: também só o /32 do cliente
    if err := setAllowedIPsWindow(pub, allowedRuntime); err != nil {
        logError(fmt.Sprintf("update-client-address: conf-setAllowedIPsWindow %s err=%v", pub, err))
        // segue ok, runtime já está certo
    }

    // 3) JSON de retorno pro PHP/Mikrotik (opcionalmente com o duplo)
    serverIPv4 := getServerIPv4FromConf()
    allowedJson := clientAddr
    if serverIPv4 != "" {
        allowedJson = serverIPv4 + "/32," + clientAddr
    }

    return Response{
        OK: true,
        Data: map[string]string{
            "publicKey":  pub,
            "allowedIPs": allowedJson, // aqui vai o duplo pro PHP gravar
        },
    }
}
// ----------------------------------------------------------------------------
// WireGuard helpers (exec wg / ip / hostname)
// ----------------------------------------------------------------------------
// BLINDAGEM NÍVEL 2: Sanitiza o IP do servidor da lista de AllowedIPs
// ----------------------------------------------------------------------------
func sanitizeAllowedIPs(rawIPs string, serverIPv4 string) string {
	if serverIPv4 == "" || rawIPs == "" {
		return rawIPs // Nada para limpar
	}

	// Cria o padrão que queremos arrancar (ex: "10.66.66.1/32")
	serverCIDR := serverIPv4 + "/32"
	
	parts := strings.Split(rawIPs, ",")
	var cleanIPs []string

	for _, p := range parts {
		ip := strings.TrimSpace(p)
		if ip == "" {
			continue
		}
		// Se o IP da lista for igual ao IP do servidor/32, NÓS IGNORAMOS (arranca fora)
		if ip == serverCIDR || ip == serverIPv4 {
			logInfo(fmt.Sprintf("Blindagem: Removendo IP do servidor (%s) dos AllowedIPs", ip))
			continue
		}
		// Se não for o servidor, é o cliente, então guarda
		cleanIPs = append(cleanIPs, ip)
	}

	return strings.Join(cleanIPs, ",")
}

func readWgAddressFromConf() string {
    b, err := os.ReadFile(wgConfPath)
    if err != nil {
        return ""
    }
    lines := strings.Split(string(b), "\n")
    for _, line := range lines {
        t := strings.TrimSpace(line)
        if strings.HasPrefix(t, "Address") {
            parts := strings.SplitN(t, "=", 2)
            if len(parts) == 2 {
                return strings.TrimSpace(parts[1])
            }
        }
    }
    return ""
}

func getServerIPv4FromConf() string {
    addr := readWgAddressFromConf()
    if addr == "" {
        return ""
    }

    // exemplo: "10.66.66.1/24,fd42:42:42::1/64"
    parts := strings.Split(addr, ",")
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p == "" {
            continue
        }
        if strings.Contains(p, ":") {
            continue // pula IPv6
        }
        hp := strings.SplitN(p, "/", 2)
        return hp[0] // "10.66.66.1"
    }
    return ""
}

func wgIsUp() bool {
	cmd := exec.Command("ip", "link", "show", "dev", wgInterface)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func wgShowText() (string, error) {
	out, err := exec.Command("wg", "show", wgInterface).CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// parse wg show wg0 dump
func buildClientsFromWg() ([]Client, error) {
	out, err := exec.Command("wg", "show", wgInterface, "dump").CombinedOutput()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) <= 1 {
		return []Client{}, nil
	}

	var res []Client
	for i, line := range lines {
		if i == 0 {
			continue // interface line
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		pub := fields[0]
		allowed := fields[3]
		hsStr := fields[4]
		rxStr := fields[5]
		txStr := fields[6]
		ka := fields[7]

		var iso *string
		if hsStr != "" && hsStr != "0" {
			sec, err := strconv.ParseInt(hsStr, 10, 64)
			if err == nil && sec > 0 {
				t := time.Unix(sec, 0).UTC()
				s := t.Format("2006-01-02T15:04:05.000Z")
				iso = &s
			}
		}

		rx, _ := strconv.ParseUint(rxStr, 10, 64)
		tx, _ := strconv.ParseUint(txStr, 10, 64)

		res = append(res, Client{
			PublicKey:          pub,
			AllowedIPs:         allowed,
			Endpoint:           fields[2],
			LatestHandshakeISO: iso,
			TransferRx:         rx,
			TransferTx:         tx,
			Keepalive:          ka,
		})
	}
	return res, nil
}

func isValidPublicKey(pub string) bool {
	for _, r := range pub {
		if (r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '+' || r == '/' || r == '=' {
			continue
		}
		return false
	}
	return pub != ""
}

// Descobre IP+porta atuais do servidor para usar no Endpoint dos clients.
func getCurrentEndpoint() string {
    // 1) tenta pegar porta real via wg show
    txt, err := wgShowText()
    if err == nil {
        if port := extractListeningPort(txt); port > 0 {
            if host := firstHostIP(); host != "" {
                return fmt.Sprintf("%s:%d", host, port)
            }
        }
    }

    // 2) fallback: tenta ler ListenPort direto do wg0.conf
    b, err := os.ReadFile(wgConfPath)
    if err == nil {
        lines := strings.Split(string(b), "\n")
        var port int
        for _, line := range lines {
            t := strings.TrimSpace(line)
            if strings.HasPrefix(t, "ListenPort") {
                parts := strings.SplitN(t, "=", 2)
                if len(parts) == 2 {
                    lp := strings.TrimSpace(parts[1])
                    if p, err := strconv.Atoi(lp); err == nil && p > 0 {
                        port = p
                        break
                    }
                }
            }
        }
        if port > 0 {
            if host := firstHostIP(); host != "" {
                return fmt.Sprintf("%s:%d", host, port)
            }
        }
    }

    // 3) último recurso: porta 51820 no primeiro IP encontrado
    host := firstHostIP()
    if host == "" {
        host = "127.0.0.1"
    }
    return fmt.Sprintf("%s:%d", host, 51820)
}

// peers do runtime (equivalente a wg show wg0 dump | awk '{print $1}')
func wgShowPeers() (map[string]bool, error) {
	out, err := exec.Command("wg", "show", wgInterface, "dump").Output()
	if err != nil {
		return nil, err
	}
	peers := make(map[string]bool)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, line := range lines {
		if i == 0 {
			// primeira linha é interface
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		peers[fields[0]] = true
	}
	return peers, nil
}

// wg set wg0 peer <pub> remove
func wgSetPeerRemove(pub string) error {
	cmd := exec.Command("wg", "set", wgInterface, "peer", pub, "remove")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run()
}

func extractListeningPort(wgTxt string) int {
	for _, line := range strings.Split(wgTxt, "\n") {
		if strings.Contains(line, "listening port:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				p, _ := strconv.Atoi(parts[2])
				return p
			}
		}
	}
	return 0
}

func firstHostIP() string {
	// 1) Tenta IP público com redundância (curl nativo do sistema)
	urls := []string{"ifconfig.me", "api.ipify.org", "icanhazip.com"}
	for _, url := range urls {
		out, err := exec.Command("curl", "-s", "-4", "-m", "3", url).CombinedOutput()
		if err == nil {
			ip := strings.TrimSpace(string(out))
			if net.ParseIP(ip) != nil {
				return ip // Achou um IP válido, retorna e sai do loop
			}
		}
	}

	// 2) Fallback: IP da placa principal (evita docker/wg0)
	nic := firstHostNic()
	if nic != "" {
		cmd := fmt.Sprintf("ip -4 addr show %s | awk '/inet / {print $2}' | cut -d/ -f1 | head -n 1", nic)
		outNic, errNic := exec.Command("sh", "-c", cmd).CombinedOutput()
		if errNic == nil {
			ipNic := strings.TrimSpace(string(outNic))
			if ipNic != "" {
				return ipNic
			}
		}
	}

	// 3) Último recurso: hostname -I antigo
	outHost, errHost := exec.Command("hostname", "-I").CombinedOutput()
	if errHost == nil {
		parts := strings.Fields(string(outHost))
		if len(parts) > 0 {
			return parts[0]
		}
	}

	return "127.0.0.1"
}

// tentativa simples de descobrir NIC pública (igual script do Gutierrez)
func firstHostNic() string {
	out, err := exec.Command("sh", "-c", "ip -4 route ls | awk '/default/ {for (i=1;i<=NF;i++) if ($i==\"dev\") print $(i+1)}' | head -1").CombinedOutput()
	if err != nil {
		logError("firstHostNic: " + err.Error())
		return "eth0"
	}
	n := strings.TrimSpace(string(out))
	if n == "" {
		return "eth0"
	}
	return n
}

func buildServerConfFromDefaults(privKey, ipv4Cidr, ipv6Cidr string, port int, pubNIC string) string {
	// monta Address: se tiver IPv6, usa; senão, só IPv4
	addr := ipv4Cidr
	if ipv6Cidr != "" {
		addr = ipv4Cidr + "," + ipv6Cidr
	}

	return fmt.Sprintf(`[Interface]
Address = %s
ListenPort = %d
PrivateKey = %s
PostUp = iptables -A INPUT -p udp --dport %d -j ACCEPT
PostDown = iptables -D INPUT -p udp --dport %d -j ACCEPT
PostUp = iptables -A INPUT -i %s -j ACCEPT
PostDown = iptables -D INPUT -i %s -j ACCEPT
PostUp = iptables -A OUTPUT -o %s -j ACCEPT
PostDown = iptables -D OUTPUT -o %s -j ACCEPT
`, addr, port, privKey,
		port, port,
		wgInterface, wgInterface,
		wgInterface, wgInterface,
	)
}

// ----------------------------------------------------------------------------
// Helpers extras: keypair, psk, backup, conf
// ----------------------------------------------------------------------------

func genKeypair() (priv, pub string, err error) {
	outPriv, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("genkey: %w", err)
	}
	priv = strings.TrimSpace(string(outPriv))

	cmdPub := exec.Command("wg", "pubkey")
	cmdPub.Stdin = strings.NewReader(priv)
	outPub, err := cmdPub.Output()
	if err != nil {
		return "", "", fmt.Errorf("pubkey: %w", err)
	}
	pub = strings.TrimSpace(string(outPub))
	return priv, pub, nil
}

func genPresharedKey() (string, error) {
	out, err := exec.Command("wg", "genpsk").Output()
	if err != nil {
		return "", fmt.Errorf("genpsk: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func appendClientToConf(name, pub, psk, allowed string) error {
	if _, err := os.Stat(wgConfPath); err != nil {
		// se não existir, não falha; só loga
		logError("wg_conf_missing: " + wgConfPath)
		return nil
	}

	f, err := os.OpenFile(wgConfPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	block := fmt.Sprintf(`
### Client %s
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
`, name, pub, psk, allowed)

	_, err = f.WriteString(block)
	return err
}

func deletePeerFromConf(pub string) error {
	if _, err := os.Stat(wgConfPath); err != nil {
		if os.IsNotExist(err) {
			logInfo("delete-client no-conf-file pub='" + pub + "'")
			return nil
		}
		return err
	}

	logInfo("delete-client conf-remove-start pub='" + pub + "'")

	f, err := os.Open(wgConfPath)
	if err != nil {
		return err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return err
	}

	// achar linha "PublicKey = <pub>"
	pkLine := -1
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "PublicKey") && strings.Contains(trim, pub) {
			pkLine = i
			break
		}
	}
	if pkLine == -1 {
		logInfo("delete-client conf-publicKey-not-found pub='" + pub + "'")
		return nil
	}

	// start = pkLine - 2 (### Client + [Peer]), mínimo 0
	start := pkLine - 2
	if start < 0 {
		start = 0
	}

	// end = linha anterior ao próximo "### Client" ou fim do arquivo
	end := len(lines) - 1
	for i := pkLine + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "### Client ") {
			end = i - 1
			break
		}
	}

	newLines := append([]string{}, lines[:start]...)
	if end+1 < len(lines) {
		newLines = append(newLines, lines[end+1:]...)
	}

	tmp := wgConfPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(newLines, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, wgConfPath); err != nil {
		return err
	}

	logInfo(fmt.Sprintf("delete-client conf-removed pub='%s' lines=%d-%d", pub, start+1, end+1))
	return nil
}

// setAllowedIPsWindow replica a lógica do awk com janela em torno do [Peer]:
// - detecta [Peer] (inicia janela)
// - se PublicKey dentro da janela == pub, marca match_peer
// - dentro da janela do peer alvo, troca AllowedIPs = newIPs
func setAllowedIPsWindow(pub, newIPs string) error {
	if _, err := os.Stat(wgConfPath); err != nil {
		if os.IsNotExist(err) {
			logInfo("setAllowedIPsWindow no-conf-file pub='" + pub + "'")
			return nil
		}
		return err
	}

	b, err := os.ReadFile(wgConfPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")

	inPeer := false
	matchPeer := false
	windowStart := -1
	windowEnd := -1
	const windowSize = 5 // mesmo NR+5 do awk

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		trim := strings.TrimSpace(line)

		// início de [Peer]
		if strings.HasPrefix(trim, "[Peer]") {
			inPeer = true
			matchPeer = false
			windowStart = i
			windowEnd = i + windowSize
			continue
		}

		// PublicKey dentro da janela
		if inPeer && strings.HasPrefix(trim, "PublicKey") {
			// extrai valor
			val := trim
			val = strings.TrimPrefix(val, "PublicKey")
			val = strings.TrimLeft(val, " \t=")
			val = strings.ReplaceAll(val, " ", "")
			val = strings.ReplaceAll(val, "\t", "")
			if val == pub {
				matchPeer = true
			}
			continue
		}

		// Dentro da janela do peer alvo, troca AllowedIPs (Buscando também os comentados)
		if inPeer && matchPeer && i >= windowStart && i <= windowEnd && (strings.HasPrefix(trim, "AllowedIPs") || strings.HasPrefix(trim, "#AllowedIPs")) {
			if newIPs == "" {
				// Se for desabilitar, comenta a linha pro wg-quick não dar Syntax Error!
				lines[i] = "#AllowedIPs = disabled" 
			} else {
				// Se for habilitar, escreve o IP normalmente e tira o comentário
				lines[i] = fmt.Sprintf("AllowedIPs = %s", newIPs)
			}
			continue
		}

		// Saiu da janela, limpa flags
		if windowEnd >= 0 && i > windowEnd {
			inPeer = false
			matchPeer = false
		}
	}

	tmp := wgConfPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, wgConfPath); err != nil {
		return err
	}

	logInfo(fmt.Sprintf("setAllowedIPsWindow updated pub='%s' to '%s'", pub, newIPs))
	return nil
}

// setPresharedKeyWindow: mesma janela, mas trocando PresharedKey
func setPresharedKeyWindow(pub, newPSK string) error {
	if _, err := os.Stat(wgConfPath); err != nil {
		if os.IsNotExist(err) {
			logInfo("setPresharedKeyWindow no-conf-file pub='" + pub + "'")
			return nil
		}
		return err
	}

	b, err := os.ReadFile(wgConfPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")

	inPeer := false
	matchPeer := false
	windowStart := -1
	windowEnd := -1
	const windowSize = 5

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trim := strings.TrimSpace(line)

		// início de [Peer]
		if strings.HasPrefix(trim, "[Peer]") {
			inPeer = true
			matchPeer = false
			windowStart = i
			windowEnd = i + windowSize
			continue
		}

		// PublicKey dentro da janela
		if inPeer && strings.HasPrefix(trim, "PublicKey") {
			val := trim
			val = strings.TrimPrefix(val, "PublicKey")
			val = strings.TrimLeft(val, " \t=")
			val = strings.ReplaceAll(val, " ", "")
			val = strings.ReplaceAll(val, "\t", "")
			if val == pub {
				matchPeer = true
			}
			continue
		}

		// Dentro da janela do peer alvo, troca PresharedKey
		if inPeer && matchPeer && i >= windowStart && i <= windowEnd && strings.HasPrefix(trim, "PresharedKey") {
			lines[i] = fmt.Sprintf("PresharedKey = %s", newPSK)
			continue
		}

		if windowEnd >= 0 && i > windowEnd {
			inPeer = false
			matchPeer = false
		}
	}

	tmp := wgConfPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, wgConfPath); err != nil {
		return err
	}

	logInfo(fmt.Sprintf("setPresharedKeyWindow updated pub='%s'", pub))
	return nil
}

// ----------------------------------------------------------------------------
// Logging
// ----------------------------------------------------------------------------

func logInfo(msg string) {
	logLine("INFO", msg)
}

func logError(msg string) {
	logLine("ERROR", msg)
}

func logLine(level, msg string) {
	ts := time.Now().Format(time.RFC3339)
	line := fmt.Sprintf("[%s] %s: %s\n", ts, level, msg)

	f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		// last resort
		fmt.Fprintf(os.Stderr, "log open: %v\n", err)
		return
	}
	defer f.Close()
	_, _ = f.WriteString(line)
}
