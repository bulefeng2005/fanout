package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel 是一条运行中的隧道：一个netns + 一个openvpn 进程+ 一个本地SOCKS5 端口。
type Tunnel struct {
	Slot   int       `json:"slot"`
	Port   int       `json:"port"`
	Node   Node      `json:"node"`
	Status string    `json:"status"` // starting | up | failed | stopped
	ExitIP string    `json:"exit_ip"`
	Err    string    `json:"err,omitempty"`
	Since  time.Time `json:"since"`

	ns       string
	listener net.Listener
	ovpn     *exec.Cmd
	mu       sync.Mutex
}

func (t *Tunnel) nsName() string { return fmt.Sprintf("fo%d", t.Slot) }
func (t *Tunnel) subnet() string { return fmt.Sprintf("10.99.%d", t.Slot) }

// run 在母机命名空间内执行命令并返回详细错误。
func run(name string, args ...string) error {
	out, err := cmdCombined(exec.Command(name, args...))
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runQuiet 在母机命名空间内执行清理类命令，忽略"本来就不存在"这类错误。
func runQuiet(name string, args ...string) {
	_ = cmdRun(exec.Command(name, args...))
}

// socksListenHost 返回SOCKS5 监听地址。
// 默认仅绑定127.0.0.1 供本机Xray/3x-ui 调用，防止公网扫描；
// 如需暴露到公网，可设置环境变量 FANOUT_LISTEN_PUBLIC=1。
func socksListenHost() string {
	if os.Getenv("FANOUT_LISTEN_PUBLIC") == "1" {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

// netnsDNSList 返回隧道内使用的安全DNS 服务器IP 列表，支持通过环境变量 FANOUT_NETNS_DNS 自定义。
func netnsDNSList() []string {
	if custom := strings.TrimSpace(os.Getenv("FANOUT_NETNS_DNS")); custom != "" {
		var ips []string
		for _, ip := range strings.FieldsFunc(custom, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			return ips
		}
	}
	return []string{"1.1.1.1", "8.8.8.8"}
}

// netnsDNSResolvConf 生成写入 /etc/netns/<ns>/resolv.conf 的配置文本。
func netnsDNSResolvConf() string {
	var lines []string
	for _, ip := range netnsDNSList() {
		lines = append(lines, "nameserver "+ip)
	}
	return strings.Join(lines, "\n") + "\n"
}

// extractRemoteIPs 从.ovpn 配置文本中提取remote 指令的服务器IP，用于配置Kill-Switch 白名单。
func extractRemoteIPs(ovpnConfig string) []string {
	seen := make(map[string]bool)
	var ips []string
	for _, rawLine := range strings.Split(ovpnConfig, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "remote") {
			host := fields[1]
			if ip := net.ParseIP(host); ip != nil && !seen[host] {
				seen[host] = true
				ips = append(ips, host)
			}
		}
	}
	return ips
}

// sanitizeOvpnConfig 过滤匿名志愿者节点.ovpn 配置中的危险外部脚本指令，防范RCE 命令注入。
func sanitizeOvpnConfig(raw string) string {
	blockedDirectives := map[string]bool{
		"script-security":       true,
		"up":                    true,
		"down":                  true,
		"up-restart":            true,
		"ipchange":              true,
		"route-up":              true,
		"route-pre-down":        true,
		"client-connect":        true,
		"client-disconnect":     true,
		"learn-address":         true,
		"tls-verify":            true,
		"auth-user-pass-verify": true,
		"plugin":                true,
		"management":            true,
		"log":                   true,
		"log-append":            true,
		"syslog":                true,
		"chroot":                true,
		"cd":                    true,
	}

	var cleaned []string
	for _, rawLine := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			fields := strings.Fields(trimmed)
			if len(fields) > 0 {
				directive := strings.ToLower(fields[0])
				if blockedDirectives[directive] {
					continue
				}
			}
		}
		cleaned = append(cleaned, rawLine)
	}
	return strings.Join(cleaned, "\n")
}

// setupNetns 建立netns 与veth 链路，并配好NAT、转发放行与防泄漏Kill-Switch。
func (t *Tunnel) setupNetns() error {
	ns, sub := t.nsName(), t.subnet()
	veth, peer := fmt.Sprintf("fov%d", t.Slot), fmt.Sprintf("fop%d", t.Slot)

	t.teardownNetns()

	if err := run("ip", "netns", "add", ns); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"); err != nil {
		return err
	}
	if err := run("ip", "link", "add", veth, "type", "veth", "peer", "name", peer); err != nil {
		return err
	}
	if err := run("ip", "link", "set", peer, "netns", ns); err != nil {
		return err
	}
	if err := run("ip", "addr", "add", sub+".1/30", "dev", veth); err != nil {
		return err
	}
	if err := run("ip", "link", "set", veth, "up"); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", ns, "ip", "addr", "add", sub+".2/30", "dev", peer); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", ns, "ip", "link", "set", peer, "up"); err != nil {
		return err
	}
	if err := run("ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", sub+".1"); err != nil {
		return err
	}

	// 配置netns 内部Kill-Switch 防火墙：禁止业务流量在tun0 断开时直接从veth 裸奔出网
	t.setupNetnsKillSwitch(ns, peer)

	// netns 内的DNS 配置
	nsDir := filepath.Join("/etc/netns", ns)
	if err := os.MkdirAll(nsDir, 0755); err != nil {
		return fmt.Errorf("创建%s 失败: %w", nsDir, err)
	}
	if err := os.WriteFile(filepath.Join(nsDir, "resolv.conf"), []byte(netnsDNSResolvConf()), 0644); err != nil {
		return fmt.Errorf("写resolv.conf 失败: %w", err)
	}

	cidr := sub + ".0/30"
	ensureRule("nat", "POSTROUTING", "-s", cidr, "-j", "MASQUERADE")
	ensureRuleInsert("filter", "FORWARD", "-s", cidr, "-j", "ACCEPT")
	ensureRuleInsert("filter", "FORWARD", "-d", cidr, "-j", "ACCEPT")
	return nil
}

// setupNetnsKillSwitch 在隧道命名空间内部设置iptables OUTPUT 规则，防止OpenVPN 掉线期间真实IP 泄漏。
func (t *Tunnel) setupNetnsKillSwitch(ns, peerDev string) {
	remoteIPs := extractRemoteIPs(t.Node.Config)
	// 如果.ovpn 中没有直接写出远端IP（例如使用纯域名），跳过IP 锁死以保证能先解析远端主机名
	if len(remoteIPs) == 0 {
		return
	}

	runQuiet("ip", "netns", "exec", ns, "iptables", "-F", "OUTPUT")
	runQuiet("ip", "netns", "exec", ns, "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
	runQuiet("ip", "netns", "exec", ns, "iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	// 放行所有经过tun0 加密隧道的流量
	runQuiet("ip", "netns", "exec", ns, "iptables", "-A", "OUTPUT", "-o", "tun+", "-j", "ACCEPT")
	// 仅允许发往VPN Gate 节点服务器IP 的OpenVPN 握手与加密包走veth 接口
	for _, rip := range remoteIPs {
		runQuiet("ip", "netns", "exec", ns, "iptables", "-A", "OUTPUT", "-o", peerDev, "-d", rip, "-j", "ACCEPT")
	}
	// 拦截一切其他企图绕过tun0 直接从veth 裸奔出网的流量
	runQuiet("ip", "netns", "exec", ns, "iptables", "-A", "OUTPUT", "-o", peerDev, "-j", "REJECT")
}

// ensureRule 幂等追加一条iptables 规则。
func ensureRule(table, chain string, spec ...string) {
	check := append([]string{"-t", table, "-C", chain}, spec...)
	if cmdRun(exec.Command("iptables", check...)) == nil {
		return
	}
	add := append([]string{"-t", table, "-A", chain}, spec...)
	runQuiet("iptables", add...)
}

// ensureRuleInsert 幂等插入规则到链首。
// FORWARD 链末尾常有兜底REJECT，必须插到最前面才生效。
func ensureRuleInsert(table, chain string, spec ...string) {
	check := append([]string{"-t", table, "-C", chain}, spec...)
	if cmdRun(exec.Command("iptables", check...)) == nil {
		return
	}
	ins := append([]string{"-t", table, "-I", chain, "1"}, spec...)
	runQuiet("iptables", ins...)
}

func (t *Tunnel) teardownNetns() {
	ns, sub := t.nsName(), t.subnet()
	cidr := sub + ".0/30"
	runQuiet("ip", "netns", "del", ns)
	runQuiet("ip", "link", "del", fmt.Sprintf("fov%d", t.Slot))
	runQuiet("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", cidr, "-j", "MASQUERADE")
	runQuiet("iptables", "-D", "FORWARD", "-s", cidr, "-j", "ACCEPT")
	runQuiet("iptables", "-D", "FORWARD", "-d", cidr, "-j", "ACCEPT")
}

// startOpenVPN 在netns 内拉起openvpn，并等待tun0 拿到地址。
func (t *Tunnel) startOpenVPN(dir string) error {
	ns := t.nsName()
	cfgPath := filepath.Join(dir, ns+".ovpn")
	safeConfig := sanitizeOvpnConfig(t.Node.Config)
	if err := os.WriteFile(cfgPath, []byte(safeConfig), 0600); err != nil {
		return fmt.Errorf("写配置失败: %w", err)
	}
	authPath := filepath.Join(dir, "auth.txt")
	if err := os.WriteFile(authPath, []byte("vpn\nvpn\n"), 0600); err != nil {
		return fmt.Errorf("写凭据失败: %w", err)
	}
	logPath := filepath.Join(dir, ns+".log")

	cmd := exec.Command("ip", "netns", "exec", ns, "openvpn",
		"--config", cfgPath,
		"--auth-user-pass", authPath,
		"--auth-nocache",
		"--script-security", "0",
		"--dev", "tun0",
		"--connect-retry-max", "2",
		"--connect-timeout", "15",
		"--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
		"--verb", "3",
		"--log", logPath,
	)
	if err := cmdStart(cmd); err != nil {
		return fmt.Errorf("启动openvpn 失败: %w", err)
	}
	t.ovpn = cmd
	go cmd.Wait() // 回收子进程，避免僵尸

	// 250ms 快速轮询等待tun0 就绪，加快隧道建立响应速度
	deadline := time.Now().Add(35 * time.Second)
	for time.Now().Before(deadline) {
		if out, err := cmdOutput(exec.Command("ip", "netns", "exec", ns, "ip", "-4", "addr", "show", "tun0")); err == nil {
			if strings.Contains(string(out), "inet ") {
				return nil
			}
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return fmt.Errorf("openvpn 提前退出，详见%s", logPath)
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("等待tun0 就绪超时，详见%s", logPath)
}

// serve 在母机上监听SOCKS5 端口，出站连接则在netns 内建立。
func (t *Tunnel) serve() error {
	listenHost := socksListenHost()
	var ln net.Listener
	var err error
	for i := 0; i < 6; i++ {
		ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", listenHost, t.Port))
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		port, perr := freeRandomPort(map[int]bool{t.Port: true})
		if perr != nil {
			return fmt.Errorf("监听%d 失败且无备用端口: %w", t.Port, err)
		}
		ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", listenHost, port))
		if err != nil {
			return fmt.Errorf("监听%d 失败: %w", port, err)
		}
		t.Port = port
	}
	t.listener = ln

	dial := dialerInNetns(t.nsName())
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSocks(conn, dial)
		}
	}()
	return nil
}

// 多个HTTPS 加密出口IP 探测源，轮询分流防止单点限流与明文HTTP 劫持。
var exitIPProbeEndpoints = []string{
	"https://api.ipify.org",
	"https://icanhazip.com",
	"https://checkip.amazonaws.com",
	"https://api.ip.sb/ip",
}

var probeRoundRobin uint64

// probeExitIP 使用Go 原生网络栈与HTTPS 多源探测隧道出口IP，彻底告别外部curl 进程开销。
func (t *Tunnel) probeExitIP() (string, error) {
	client := httpClientInNetns(t.nsName(), 10*time.Second)
	startIdx := int(atomic.AddUint64(&probeRoundRobin, 1) % uint64(len(exitIPProbeEndpoints)))

	var lastErr error
	for i := 0; i < len(exitIPProbeEndpoints); i++ {
		endpoint := exitIPProbeEndpoints[(startIdx+i)%len(exitIPProbeEndpoints)]
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "curl/8.5.0")

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		cancel()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
		lastErr = fmt.Errorf("探测源%s 返回异常IP: %q", endpoint, ip)
	}
	return "", fmt.Errorf("查询出口IP 失败: %w", lastErr)
}

// stop 停止这条隧道并清理它占用的所有资源。
func (t *Tunnel) stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener != nil {
		t.listener.Close()
		t.listener = nil
	}
	if t.ovpn != nil && t.ovpn.Process != nil {
		_ = t.ovpn.Process.Kill()
		t.ovpn = nil
	}
	t.teardownNetns()
	t.Status = "stopped"
}
