// 移动端 VPN 承载：基于 sing-box libbox（官方 SFA/SFI 同款路径）。
//
// 移动操作系统不允许普通 App 自设系统代理，只有系统 VPN（Android
// VpnService / iOS NEPacketTunnelProvider）创建 TUN 才能接管流量。
// libbox 的 BoxService 启动时会回调 PlatformInterface.OpenTun 索要 TUN
// 文件描述符：fd 由宿主原生层（Kotlin / Swift）建立 VPN 后返回。
//
// 宿主通过 PrismVPNSetCallbacks 注册 C 回调：
//   open_tun(options_json)  —— 建立 VPN，返回 TUN fd（<0 = 错误）
//   protect_socket(fd)      —— Android 保护底层 socket 绕过 VPN（0 = 成功）
//   under_extension()       —— 是否运行于网络扩展（iOS = 1）
package main

/*
#include <stdlib.h>

typedef struct prism_vpn_cbs {
    int (*open_tun)(const char* options_json);
    int (*protect_socket)(int fd);
    int (*under_extension)(void);
} prism_vpn_cbs;

static int prism_call_open_tun(prism_vpn_cbs cbs, const char* json) {
    if (cbs.open_tun == NULL) {
        return -1;
    }
    return cbs.open_tun(json);
}

static int prism_call_protect(prism_vpn_cbs cbs, int fd) {
    if (cbs.protect_socket == NULL) {
        return 0;
    }
    return cbs.protect_socket(fd);
}

static int prism_call_under_extension(prism_vpn_cbs cbs) {
    if (cbs.under_extension == NULL) {
        return 0;
    }
    return cbs.under_extension();
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/experimental/libbox"
)

var (
	vpnMu      sync.Mutex
	vpnService *libbox.BoxService
	vpnCbs     C.prism_vpn_cbs
	vpnCbsSet  bool
)

//export PrismVPNSetCallbacks
func PrismVPNSetCallbacks(cbs C.prism_vpn_cbs) {
	vpnCbs = cbs
	vpnCbsSet = true
}

//export PrismVPNStart
// configContent：完整配置 JSON 文本（libbox 自行解析）
func PrismVPNStart(configContent *C.char, workDir *C.char) *C.char {
	// iOS 网络扩展的 Jetsam 物理内存红线极低（iOS 16 通常 15~50MB，
	// build 144 实证：解析 2.47MB 配置时内存冲顶被 SIGKILL → code=12
	// 且扩展来不及写任何错误文件）。当前配置已瘦身至 30KB 以内，
	// 恢复 GC 默认触发比例（100 = 堆增长 100% 才回收），消除高速转发时
	// 每增长 10% 堆就触发一次全局 STW 造成的限速与发热；仅保留 38MB
	// 软上限（离 50MB 硬红线留足安全裕度），逼近上限时才提前回收。
	// 仅 iOS 生效，Android 保持默认。
	if runtime.GOOS == "ios" {
		debug.SetGCPercent(100)
		debug.SetMemoryLimit(38 << 20) // 38MB < iOS 50MB Jetsam 硬红线
	}

	vpnMu.Lock()
	defer vpnMu.Unlock()
	if vpnService != nil {
		return nil // 已在运行
	}
	if !vpnCbsSet {
		return C.CString("vpn: platform callbacks not registered")
	}

	wd := C.GoString(workDir)
	if err := vpnSetupPaths(wd); err != nil {
		return C.CString("vpn setup: " + err.Error())
	}

	service, err := libbox.NewService(C.GoString(configContent), &prismPlatform{})
	if err != nil {
		return C.CString("create vpn service: " + err.Error())
	}
	if err := service.Start(); err != nil {
		_ = service.Close()
		return C.CString("start vpn service: " + err.Error())
	}
	vpnService = service
	return nil
}

//export PrismVPNStop
func PrismVPNStop() {
	vpnMu.Lock()
	defer vpnMu.Unlock()
	if vpnService != nil {
		_ = vpnService.Close()
		vpnService = nil
	}
}

// ---------------- 内部辅助 ----------------

type vpnError struct{ msg string }

func (e *vpnError) Error() string { return e.msg }

func errVpn(msg string) error { return &vpnError{msg: msg} }

var (
	vpnLogMu sync.Mutex
	vpnLogF  *os.File
)

func vpnSetupPaths(workDir string) error {
	// 与 PrismKernelStart 保持一致
	_ = os.Setenv("ENABLE_DEPRECATED_GEOIP", "true")
	_ = os.Setenv("ENABLE_DEPRECATED_GEOSITE", "true")

	if workDir == "" {
		return errVpn("missing working directory")
	}
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("create working directory: %w", err)
	}
	if err := os.Chdir(workDir); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}

	// libbox 内部文件管理器（profile/cache 等）的路径基准
	libbox.Setup(&libbox.SetupOptions{
		BasePath:    workDir,
		WorkingPath: workDir,
		TempPath:    workDir,
	})

	f, err := os.Create(filepath.Join(workDir, "kernel.log"))
	if err != nil {
		return fmt.Errorf("open kernel log: %w", err)
	}
	vpnLogF = f
	return nil
}

func vpnWriteLog(message string) {
	vpnLogMu.Lock()
	defer vpnLogMu.Unlock()
	if vpnLogF != nil {
		_, _ = vpnLogF.WriteString(time.Now().Format("15:04:05") + " " + message + "\n")
	}
}

// vpnLogf：与 vpnWriteLog 同源，支持 Printf 风格格式化。
// 必须保持轻量无阻塞：内核热路径（protect_socket / Control 回调）也会调用，
// 写日志绝不允许 panic 或长时间持锁；写入失败仅静默丢弃。
func vpnLogf(format string, args ...interface{}) {
	vpnWriteLog(fmt.Sprintf(format, args...))
}

// ---------------- PlatformInterface ----------------

type prismPlatform struct{}

func (p *prismPlatform) UsePlatformAutoDetectInterfaceControl() bool {
	// Android: 底层拨号 socket 经 VpnService.protect 绕过 VPN，避免回环
	return true
}

func (p *prismPlatform) AutoDetectInterfaceControl(fd int32) error {
	// 【APP-12 任务1.1】protect_socket 永不返回 error：
	// sing-box 的 wireguard 出站底层 wireguard-go 的 StdNetBind.Open() 会
	// 同时尝试打开 udp4(AF_INET) 与 udp6(AF_INET6) 两个 Socket。在 iOS
	// 纯 IPv4 网络下，对 udp6 setsockopt(IP_BOUND_IF) 会返回 EPERM。
	// 若此处返回 error，wireguard-go 会把已成功的 udp4 一并关闭退出，
	// 导致 WireGuard 握手包 100% 发不出、家里服务端无任何连接记录！
	// 必须只记录日志、永远返回 nil——绑定失败最多影响该 socket 自身，
	// 不会连坐其他 socket。
	//
	// 【APP14 任务2】iOS 侧已彻底移除自定义网卡绑定：
	// - 扩展配置不再写 route.default_interface / outbound.bind_interface，
	//   auto_detect_interface 保持 false，因此 sing-box 根本不会调用本回调；
	// - Swift 的 prism_protect_socket 已改为完全空操作（不再 setsockopt
	//   IP_BOUND_IF / IPV6_BOUND_IF），扩展进程 Socket 由 iOS NECP 按当前
	//   活跃物理网卡自动路由，与 155 个常规代理节点 100% 同一条路径；
	// - 本回调仍保留 UsePlatformAutoDetectInterfaceControl()=true，
	//   是为了 Android 端 VpnService.protect 不被破坏（本文件双端共用）。
	rc := C.prism_call_protect(vpnCbs, C.int(fd))
	if rc != 0 {
		vpnLogf("protect_socket fd=%d returned %d (ignored)", fd, rc)
	}
	return nil
}

func (p *prismPlatform) OpenTun(options libbox.TunOptions) (int32, error) {
	payload, err := buildTunOptionsJSON(options)
	if err != nil {
		return 0, err
	}
	cPayload := C.CString(payload)
	defer C.free(unsafe.Pointer(cPayload))
	fd := C.prism_call_open_tun(vpnCbs, cPayload)
	if fd < 0 {
		return 0, errVpn("platform open_tun failed")
	}
	return int32(fd), nil
}

func (p *prismPlatform) WriteLog(message string) {
	vpnWriteLog(message)
}

func (p *prismPlatform) UseProcFS() bool { return false }

func (p *prismPlatform) FindConnectionOwner(_ int32, _ string, _ int32, _ string, _ int32) (int32, error) {
	// 进程匹配规则（PROCESS-NAME 等）在移动端不支持
	return 0, errVpn("connection owner lookup not implemented")
}

func (p *prismPlatform) PackageNameByUid(_ int32) (string, error) {
	return "", nil
}

func (p *prismPlatform) UIDByPackageName(_ string) (int32, error) {
	return 0, errVpn("uid lookup not implemented")
}

func (p *prismPlatform) StartDefaultInterfaceMonitor(_ libbox.InterfaceUpdateListener) error {
	// 与 SFI 一致：no-op
	return nil
}

func (p *prismPlatform) CloseDefaultInterfaceMonitor(_ libbox.InterfaceUpdateListener) error {
	return nil
}

func (p *prismPlatform) GetInterfaces() (libbox.NetworkInterfaceIterator, error) {
	return nil, errVpn("interface enumeration not implemented")
}

func (p *prismPlatform) UnderNetworkExtension() bool {
	return C.prism_call_under_extension(vpnCbs) != 0
}

func (p *prismPlatform) IncludeAllNetworks() bool { return false }

func (p *prismPlatform) ReadWIFIState() *libbox.WIFIState { return nil }

func (p *prismPlatform) ClearDNSCache() {}

func (p *prismPlatform) SendNotification(_ *libbox.Notification) error { return nil }

// ---------------- TUN options → JSON ----------------

type tunPrefixJSON struct {
	Address string `json:"address"`
	Prefix  int32  `json:"prefix"`
}

type tunHTTPProxyJSON struct {
	Server       string   `json:"server"`
	Port         int32    `json:"port"`
	BypassDomain []string `json:"bypass_domain"`
	MatchDomain  []string `json:"match_domain"`
}

type tunOptionsJSON struct {
	MTU                       int32            `json:"mtu"`
	AutoRoute                 bool             `json:"auto_route"`
	StrictRoute               bool             `json:"strict_route"`
	DNSServer                 string           `json:"dns_server,omitempty"`
	Inet4Address              []tunPrefixJSON  `json:"inet4_address"`
	Inet6Address              []tunPrefixJSON  `json:"inet6_address"`
	Inet4RouteAddress          []tunPrefixJSON  `json:"inet4_route_address"`
	Inet6RouteAddress          []tunPrefixJSON  `json:"inet6_route_address"`
	Inet4RouteExcludeAddress   []tunPrefixJSON  `json:"inet4_route_exclude_address"`
	Inet6RouteExcludeAddress   []tunPrefixJSON  `json:"inet6_route_exclude_address"`
	IncludePackage             []string         `json:"include_package"`
	ExcludePackage             []string         `json:"exclude_package"`
	HTTPProxy                  *tunHTTPProxyJSON `json:"http_proxy,omitempty"`
}

func collectPrefixes(it libbox.RoutePrefixIterator) []tunPrefixJSON {
	out := make([]tunPrefixJSON, 0)
	for it != nil && it.HasNext() {
		p := it.Next()
		out = append(out, tunPrefixJSON{Address: p.Address(), Prefix: p.Prefix()})
	}
	return out
}

func collectStrings(it libbox.StringIterator) []string {
	out := make([]string, 0)
	for it != nil && it.HasNext() {
		out = append(out, it.Next())
	}
	return out
}

func buildTunOptionsJSON(options libbox.TunOptions) (string, error) {
	dnsServer := ""
	if box, err := options.GetDNSServerAddress(); err == nil && box != nil {
		dnsServer = box.Value
	}

	out := tunOptionsJSON{
		MTU:             options.GetMTU(),
		AutoRoute:       options.GetAutoRoute(),
		StrictRoute:     options.GetStrictRoute(),
		DNSServer:       dnsServer,
		Inet4Address:    collectPrefixes(options.GetInet4Address()),
		Inet6Address:    collectPrefixes(options.GetInet6Address()),
		Inet4RouteAddress: collectPrefixes(options.GetInet4RouteAddress()),
		Inet6RouteAddress: collectPrefixes(options.GetInet6RouteAddress()),
		Inet4RouteExcludeAddress: collectPrefixes(options.GetInet4RouteExcludeAddress()),
		Inet6RouteExcludeAddress: collectPrefixes(options.GetInet6RouteExcludeAddress()),
		IncludePackage: collectStrings(options.GetIncludePackage()),
		ExcludePackage: collectStrings(options.GetExcludePackage()),
	}

	if options.IsHTTPProxyEnabled() {
		out.HTTPProxy = &tunHTTPProxyJSON{
			Server:       options.GetHTTPProxyServer(),
			Port:         options.GetHTTPProxyServerPort(),
			BypassDomain: collectStrings(options.GetHTTPProxyBypassDomain()),
			MatchDomain:  collectStrings(options.GetHTTPProxyMatchDomain()),
		}
	}

	raw, err := json.Marshal(out)
	return string(raw), err
}
