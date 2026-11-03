package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// mainNetns 是fanout 启动时所在的网络命名空间，全程持有不关闭。
var mainNetns *os.File

// initMainNetns 记下母机的网络命名空间。必须在建任何隧道之前调用。
func initMainNetns() error {
	f, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("记录母机网络命名空间失败: %w", err)
	}
	mainNetns = f
	return nil
}

// inMainNetns 把fn 放到母机网络命名空间里执行。
func inMainNetns(fn func() error) error {
	if mainNetns == nil {
		return fn()
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Setns(int(mainNetns.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("切回母机网络命名空间失败: %w", err)
			return
		}
		err := fn()
		runtime.UnlockOSThread()
		errc <- err
	}()
	return <-errc
}

// cmdRun 在母机命名空间里执行命令，只关心成败。
func cmdRun(cmd *exec.Cmd) error {
	return inMainNetns(cmd.Run)
}

// cmdStart 在母机命名空间里拉起一个常驻子进程。
func cmdStart(cmd *exec.Cmd) error {
	return inMainNetns(cmd.Start)
}

// cmdOutput 在母机命名空间里执行命令并取标准输出。
func cmdOutput(cmd *exec.Cmd) ([]byte, error) {
	var out []byte
	err := inMainNetns(func() error {
		var e error
		out, e = cmd.Output()
		return e
	})
	return out, err
}

// cmdCombined 在母机命名空间里执行命令并取合并输出。
func cmdCombined(cmd *exec.Cmd) ([]byte, error) {
	var out []byte
	err := inMainNetns(func() error {
		var e error
		out, e = cmd.CombinedOutput()
		return e
	})
	return out, err
}

// openNetnsFile 打开指定名称的netns 文件描述符，兼容 /run/netns 与 /var/run/netns。
func openNetnsFile(nsName string) (*os.File, error) {
	p1 := filepath.Join("/run/netns", nsName)
	if f, err := os.Open(p1); err == nil {
		return f, nil
	}
	p2 := filepath.Join("/var/run/netns", nsName)
	return os.Open(p2)
}

// dialSocketInNetns 在目标netns 中创建socket fd，并在发起慢速网络connect() 握手前
// 立即通过Control 钩子将OS 线程切回母机命名空间，使线程停留在隧道netns 的时间缩短至微秒级。
func dialSocketInNetns(ctx context.Context, nsFd int, network, ipAddr string) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Setns(nsFd, unix.CLONE_NEWNET); err != nil {
			ch <- res{nil, fmt.Errorf("切入隧道netns 失败: %w", err)}
			return
		}
		switchedBack := false
		d := net.Dialer{
			Timeout: 10 * time.Second,
			Control: func(ctrlNet, ctrlAddr string, c syscall.RawConn) error {
				// 此时内核已完成sysSocket 创建，fd 已永久绑定在隧道netns 上；
				// 在发起耗时TCP/UDP connect 之前立即切回母机命名空间！
				if mainNetns != nil {
					if err := unix.Setns(int(mainNetns.Fd()), unix.CLONE_NEWNET); err == nil {
						switchedBack = true
					}
				}
				return nil
			},
		}
		conn, derr := d.DialContext(ctx, network, ipAddr)
		if !switchedBack && mainNetns != nil {
			if err := unix.Setns(int(mainNetns.Fd()), unix.CLONE_NEWNET); err != nil {
				// 切回失败则不调用UnlockOSThread，让该线程随goroutine 退出销毁
				ch <- res{conn, derr}
				return
			}
		}
		runtime.UnlockOSThread()
		ch <- res{conn, derr}
	}()

	select {
	case r := <-ch:
		return r.c, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// fastDialContextInNetns 极速、防DNS 泄漏、零命名空间传染的netns 拨号器：
// 1. 若目标地址为域名，先在目标netns 内部通过安全DNS 解析成IP（防止母机DNS 泄漏）；
// 2. 针对目标IP:Port 调用dialSocketInNetns，仅在创建socket fd 的微秒级瞬间切入netns。
func fastDialContextInNetns(nsName string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		nsFile, err := openNetnsFile(nsName)
		if err != nil {
			return nil, fmt.Errorf("打开netns %s 失败: %w", nsName, err)
		}
		defer nsFile.Close()
		nsFd := int(nsFile.Fd())

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// 如果已经是纯IP，直接拨号
		if net.ParseIP(host) != nil {
			return dialSocketInNetns(ctx, nsFd, network, addr)
		}

		// 如果是域名，在目标netns 内部向安全DNS 发起解析，杜绝母机DNS 泄漏
		dnsServers := netnsDNSList()
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(rctx context.Context, rnet, raddr string) (net.Conn, error) {
				dnsIP := "1.1.1.1"
				if len(dnsServers) > 0 {
					dnsIP = dnsServers[0]
				}
				return dialSocketInNetns(rctx, nsFd, "udp", net.JoinHostPort(dnsIP, "53"))
			},
		}
		ips, rerr := resolver.LookupIPAddr(ctx, host)
		if rerr != nil || len(ips) == 0 {
			return nil, fmt.Errorf("隧道内解析域名 %s 失败: %w", host, rerr)
		}
		targetAddr := net.JoinHostPort(ips[0].IP.String(), port)
		return dialSocketInNetns(ctx, nsFd, network, targetAddr)
	}
}

// httpClientInNetns 返回绑定在指定netns 上的原生http.Client，零外部进程开销。
func httpClientInNetns(nsName string, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DialContext:           fastDialContextInNetns(nsName),
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
}
