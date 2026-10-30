import Foundation
import NetworkExtension
import Network
import Darwin

private let prismAppGroupID = "group.com.prism.proxy"
private var prismProviderRef: PacketTunnelProvider?

/// 缓存当前活跃的物理网卡索引与名称（en0 / pdp_ip0）
private var cachedPhysicalIfIndex: UInt32 = 0
private var cachedPhysicalIfName: String = "en0"

/// 【APP-2】常驻 NWPathMonitor 观测的系统默认路由信息：
/// 弱 Wi-Fi 被系统自动切走时 currentPath 的首选接口精确变为 pdp_ip* 而非
/// 断网 en0；双卡/VoLTE 多 pdp_ip* 场景据此识别真正的数据网卡
private var systemDefaultInterfaceName: String = ""
private var systemDefaultIsCellular: Bool = false
private var prismPathMonitor: NWPathMonitor?

/// 启动常驻 NWPathMonitor（幂等），实时记录系统默认路由使用的物理网卡
private func startSystemPathMonitor() {
    guard prismPathMonitor == nil else { return }
    let monitor = NWPathMonitor()
    prismPathMonitor = monitor
    monitor.pathUpdateHandler = { path in
        let cellular = path.usesInterfaceType(.cellular)
        systemDefaultIsCellular = cellular
        if cellular {
            systemDefaultInterfaceName =
                path.availableInterfaces.first { $0.type == .cellular }?.name ?? ""
        } else if path.usesInterfaceType(.wifi) {
            systemDefaultInterfaceName =
                path.availableInterfaces.first { $0.type == .wifi }?.name ?? ""
        } else {
            // 排除虚拟网卡后的首个物理接口
            systemDefaultInterfaceName = path.availableInterfaces.first {
                !$0.name.hasPrefix("utun") && !$0.name.hasPrefix("ipsec")
                    && !$0.name.hasPrefix("ppp") && !$0.name.hasPrefix("llw")
                    && !$0.name.hasPrefix("awdl") && !$0.name.hasPrefix("lo")
            }?.name ?? ""
        }
    }
    monitor.start(queue: DispatchQueue(label: "com.prism.proxy.pathMonitor", qos: .utility))
}

private struct PhysicalInterface {
    let name: String
    let index: UInt32
    /// 该网卡是否具备真实可路由 IP（ipa-8 隐患 C）：电梯/地下室等
    /// 短暂无网场景下兜底候选（pdp_ip0/en0 盲猜）标记为 false，
    /// 热重载检测据此保持待机，不切到死网卡
    let hasRoutableIP: Bool
    /// 【IPA9 任务4.3】该网卡当前的真实 IPv4 地址（无则空串）。
    /// 记录日志 / 热重载判定用，不再注入出站 inet4_bind_address
    /// （5G 蜂窝下会引发 i/o timeout）。
    var ipv4: String = ""
}

/// 【APP22 任务2.2】跨线程传递 DNS 预解析结果的引用容器
///（DispatchSemaphore 提供 happens-before，无需加锁）
private final class ResolveResultBox {
    var value: String? = nil
}

// MARK: - 【APP19 任务2】IPv4 前缀解析（零元组、零强制转型）

/// IPv4 网段的标准化表示。全部字段为明确的基础类型，
/// 严禁任何命名元组 / 强制类型转换，确保 swiftc 类型推导 100% 通过。
private struct PrismIPv4Prefix {
    let net: UInt32
    let prefix: Int
    let networkAddress: String
    let subnetMask: String
}

/// UInt32 数值 → 点分十进制字符串（零元组、零强制转型）
private func ipv4String(_ v: UInt32) -> String {
    let octets: [UInt32] = [(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]
    return octets.map { String($0) }.joined(separator: ".")
}

/// 解析 "a.b.c.d[/prefix]" → PrismIPv4Prefix。解析失败返回 nil。
private func parseIPv4Prefix(_ raw: String) -> PrismIPv4Prefix? {
    let allowed = Set("0123456789./")
    let cleaned = String(raw.unicodeScalars.filter { allowed.contains(Character($0)) })
    guard !cleaned.isEmpty else { return nil }
    let parts = cleaned.split(separator: "/", omittingEmptySubsequences: false)
    let ipPart = String(parts[0])
    guard !ipPart.isEmpty else { return nil }
    let prefixVal: Int
    if parts.count > 1, let p = Int(parts[1]), p >= 0 && p <= 32 {
        prefixVal = p
    } else {
        prefixVal = 24
    }
    var addr = in_addr()
    guard inet_pton(AF_INET, ipPart, &addr) == 1 else { return nil }
    let ipU32 = UInt32(bigEndian: addr.s_addr)
    let maskU32: UInt32 = prefixVal == 0 ? 0 : (0xFFFF_FFFF << (32 - prefixVal))
    let netU32 = ipU32 & maskU32
    return PrismIPv4Prefix(
        net: netU32,
        prefix: prefixVal,
        networkAddress: ipv4String(netU32),
        subnetMask: ipv4String(maskU32)
    )
}

/// 严格校验 IPv4 字面量（a.b.c.d 且每段 0-255）。
private func isValidIPv4Literal(_ s: String) -> Bool {
    let parts = s.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return false }
    for p in parts {
        guard !p.isEmpty, p.count <= 3, p.allSatisfy({ $0.isNumber }),
              let v = Int(p), v >= 0, v <= 255
        else { return false }
    }
    return true
}

/// 严格判断网卡上的地址是否为真正可路由的 IP（排除 127.0.0.1、169.254.x.x 以及 iOS Wi-Fi 断开后残留的 fe80:: 链路本地地址）
private func isRoutableAddress(_ addrPtr: UnsafePointer<sockaddr>) -> Bool {
    let family = Int32(addrPtr.pointee.sa_family)
    if family == AF_INET {
        return addrPtr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sinPtr in
            let ip = UInt32(bigEndian: sinPtr.pointee.sin_addr.s_addr)
            let b0 = (ip >> 24) & 0xff
            let b1 = (ip >> 16) & 0xff
            if b0 == 0 || b0 == 127 { return false }
            if b0 == 169 && b1 == 254 { return false } // 排除 169.254.0.0/16 链路本地地址
            return true
        }
    } else if family == AF_INET6 {
        return addrPtr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { sin6Ptr in
            var addr = sin6Ptr.pointee.sin6_addr
            return withUnsafeBytes(of: &addr) { rawBuf -> Bool in
                guard rawBuf.count >= 16 else { return false }
                let b0 = rawBuf[0]
                let b1 = rawBuf[1]
                // 排除 fe80::/10 链路本地地址（Wi-Fi 未连接路由器时 en0 依然保有 fe80:: 地址！）
                if b0 == 0xfe && (b1 & 0xc0) == 0x80 { return false }
                // 排除 :: 和 ::1 回环地址
                var allZero = true
                for i in 0..<15 where rawBuf[i] != 0 { allZero = false; break }
                if allZero && (rawBuf[15] == 0 || rawBuf[15] == 1) { return false }
                // 仅认可 2000::/3 全球单播 IPv6 地址（如三大运营商 4G/5G 的 2408/2409/240e 开头地址）
                return (b0 & 0xe0) == 0x20
            }
        }
    }
    return false
}

/// 【APP11 任务1.1】内核路由实测：向公网 DNS 223.5.5.5:53 发一个 UDP connect
/// （仅 connect 不发数据），让内核按「当前真实默认路由」选出源 IP，再
/// getsockname 读出。这是"此刻真正在用的物理网卡"最权威的判据——弱 Wi-Fi
/// 无外网时内核会选蜂窝 IP，彻底避免把出站 Socket 绑到断网的 en0。
/// 隧道已建立时源 IP 可能是 utun 地址（ipv4ByName 不匹配）→ 返回空串，
/// 调用方自动回退到既有 NWPathMonitor 逻辑。
private func probeRoutedSourceIPv4() -> String {
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    guard fd >= 0 else { return "" }
    defer { close(fd) }
    var addr = sockaddr_in()
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = UInt16(53).bigEndian
    addr.sin_addr.s_addr = inet_addr("223.5.5.5")
    let connected = withUnsafePointer(to: &addr) { p -> Int32 in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard connected == 0 else { return "" }
    var local = sockaddr_in()
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    let got = withUnsafeMutablePointer(to: &local) { p -> Int32 in
        p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            getsockname(fd, $0, &len)
        }
    }
    guard got == 0 else { return "" }
    var raw = local.sin_addr
    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    guard inet_ntop(AF_INET, &raw, &buf, socklen_t(INET_ADDRSTRLEN)) != nil else { return "" }
    let ip = String(cString: buf)
    return isValidIPv4Literal(ip) ? ip : ""
}

/// 获取当前真正联网的物理网卡（Wi-Fi 在家选 en0，出门断 Wi-Fi 自动选蜂窝流量 pdp_ip0）
///
/// 【APP-2】双卡/VoLTE 与弱 Wi-Fi 增强：
/// - 多 pdp_ip* 候选中，与 NWPathMonitor 观测的系统默认路由同名者最优先；
///   其次拥有可路由 IPv4(AF_INET) 的数据网卡，仅 IPv6 的 IMS 语音专网垫底
///   （IMS 专网只有运营商内网 IPv6，不能上公网）
/// - NWPathMonitor 指示默认路由已是蜂窝（弱 Wi-Fi 信号区 iOS 已自动切流量）
///   时，直接选用最优 pdp_ip*，忽略有局域网 IP 但无外网连通性的弱 en0
private func findActivePhysicalInterface() -> PhysicalInterface {
    var ifaddrPtr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddrPtr) == 0, let firstAddr = ifaddrPtr else {
        let idx = if_nametoindex("en0")
        return PhysicalInterface(name: "en0", index: idx, hasRoutableIP: false)
    }
    defer { freeifaddrs(ifaddrPtr) }

    var wifiCandidate: PhysicalInterface?
    // 蜂窝候选细分：系统默认路由同名 > 有可路由 IPv4 > 仅 IPv6（IMS 专网）
    var cellNamedCandidate: PhysicalInterface?
    var cellV4Candidate: PhysicalInterface?
    var cellV6Candidate: PhysicalInterface?
    var otherCandidate: PhysicalInterface?

    var ptr: UnsafeMutablePointer<ifaddrs>? = firstAddr
    // 网卡名 → 真实 IPv4 地址（同一网卡可能同时挂 IPv4/IPv6 两条记录，
    // 只取 AF_INET 那条，IPv6 记录不参与）
    var ipv4ByName: [String: String] = [:]
    while let current = ptr {
        let flags = Int32(current.pointee.ifa_flags)
        let isUp = (flags & IFF_UP) != 0 && (flags & IFF_RUNNING) != 0
        let isLoopback = (flags & IFF_LOOPBACK) != 0

        if let addr = current.pointee.ifa_addr, Int32(addr.pointee.sa_family) == AF_INET {
            let name = String(cString: current.pointee.ifa_name)
            if ipv4ByName[name] == nil, isRoutableAddress(addr) {
                ipv4ByName[name] = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sinPtr in
                    var raw = sinPtr.pointee.sin_addr
                    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                    if inet_ntop(AF_INET, &raw, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                        return String(cString: buf)
                    }
                    return ""
                }
            }
        }

        if isUp && !isLoopback, let addr = current.pointee.ifa_addr, isRoutableAddress(addr) {
            let name = String(cString: current.pointee.ifa_name)
            if !name.hasPrefix("utun") && !name.hasPrefix("ipsec") && !name.hasPrefix("ppp") && !name.hasPrefix("llw") && !name.hasPrefix("awdl") && !name.hasPrefix("lo") {
                let idx = if_nametoindex(name)
                if idx > 0 {
                    if name == "en0" {
                        wifiCandidate = PhysicalInterface(name: name, index: idx, hasRoutableIP: true)
                    } else if name.hasPrefix("pdp_ip") {
                        let iface = PhysicalInterface(name: name, index: idx, hasRoutableIP: true)
                        let isV4 = Int32(addr.pointee.sa_family) == AF_INET
                        if name == systemDefaultInterfaceName && cellNamedCandidate == nil {
                            cellNamedCandidate = iface
                        }
                        if isV4 {
                            if cellV4Candidate == nil { cellV4Candidate = iface }
                        } else if cellV6Candidate == nil {
                            cellV6Candidate = iface
                        }
                    } else if otherCandidate == nil {
                        otherCandidate = PhysicalInterface(name: name, index: idx, hasRoutableIP: true)
                    }
                }
            }
        }
        ptr = current.pointee.ifa_next
    }

    // 把已采集的 IPv4 附加到最终选中的网卡上
    func attached(_ iface: PhysicalInterface) -> PhysicalInterface {
        var out = iface
        out.ipv4 = ipv4ByName[iface.name] ?? ""
        return out
    }

    // 最优蜂窝候选：系统默认路由同名 > 有可路由 IPv4 > 仅 IPv6（IMS 专网）
    let bestCell = cellNamedCandidate ?? cellV4Candidate ?? cellV6Candidate

    // 【APP11 任务1.1】内核路由实测最优先：谁能真正连公网就用谁。
    // 直接向 223.5.5.5:53 connect 后 getsockname 得到内核选定的源 IP，
    // 再反查承载该 IP 的物理网卡。弱 Wi-Fi（有局域网 IP 但无外网）时
    // 内核会选蜂窝 IP，从而避免把出站 Socket 绑到断网的 en0。
    let routedIP = probeRoutedSourceIPv4()
    if !routedIP.isEmpty,
       let routedName = ipv4ByName.first(where: { $0.value == routedIP })?.key,
       !routedName.isEmpty
    {
        // 【APP13 任务1修复】if_nametoindex 返回非可选 UInt32，
        // 严禁在 if 条件链里用 `let routedIdx = ...` 绑定（会触发
        // "initializer for conditional binding must have Optional type"
        // 编译错误）。拆成独立局部变量后再做 `> 0` 判断。
        let routedIdx = if_nametoindex(routedName)
        if routedIdx > 0 {
            let iface = PhysicalInterface(name: routedName, index: routedIdx, hasRoutableIP: true)
            cachedPhysicalIfIndex = routedIdx
            cachedPhysicalIfName = routedName
            return attached(iface)
        }
    }

    // NWPathMonitor 指示系统默认路由已是蜂窝（弱 Wi-Fi 已被 iOS 自动切走）
    // → 忽略有局域网 IP 但无外网连通性的弱 en0，直接选用最优 pdp_ip*
    if systemDefaultIsCellular, let cell = bestCell {
        cachedPhysicalIfIndex = cell.index
        cachedPhysicalIfName = cell.name
        return attached(cell)
    }
    if let wifi = wifiCandidate {
        cachedPhysicalIfIndex = wifi.index
        cachedPhysicalIfName = wifi.name
        return attached(wifi)
    }
    if let cell = bestCell {
        cachedPhysicalIfIndex = cell.index
        cachedPhysicalIfName = cell.name
        return attached(cell)
    }
    if let other = otherCandidate {
        cachedPhysicalIfIndex = other.index
        cachedPhysicalIfName = other.name
        return attached(other)
    }
    // 兜底：若 getifaddrs 均未匹配，优先尝试 pdp_ip0 再尝试 en0
    let pdpIdx = if_nametoindex("pdp_ip0")
    if pdpIdx > 0 {
        cachedPhysicalIfIndex = pdpIdx
        cachedPhysicalIfName = "pdp_ip0"
        return attached(PhysicalInterface(name: "pdp_ip0", index: pdpIdx, hasRoutableIP: false))
    }
    let enIdx = if_nametoindex("en0")
    cachedPhysicalIfIndex = enIdx
    cachedPhysicalIfName = "en0"
    return attached(PhysicalInterface(name: "en0", index: enIdx, hasRoutableIP: false))
}

final class PacketTunnelProvider: NEPacketTunnelProvider {

    private enum TunnelState {
        case stopped
        case starting
        case running
        case stopping
    }

    private let vpnQueue = DispatchQueue(label: "com.prism.proxy.vpnQueue", qos: .userInitiated)
    private var currentState: TunnelState = .stopped
    private let stateLock = NSLock()
    private var heartbeatTimer: Timer?
    /// 【APP-3】事件驱动网络切换监听：系统网络路径变化时才回调，
    /// 取代原先每 3 秒轮询 getifaddrs 的心跳定时器
    private var pathMonitor: NWPathMonitor?

    private var resolvedSharedDirURL: URL?
    private var lastOpenTunError: String?
    private var lastHeartbeatStage: String = "init"

    /// 保存当前运行时的工作目录与绑定网卡名，用于在 Wi-Fi <-> 蜂窝流量切换时自动热重载内核
    private var activeWorkDir: URL?
    private var activeBoundInterface: String = ""
    private var isReloadingForNetworkChange: Bool = false

    /// 【APP25 任务2.2】本次内核实际监听的 mixed-in 端口（默认 2080）。
    /// openTun 构造 NEProxySettings 时把系统 HTTP/HTTPS 代理指向
    /// 127.0.0.1:<该端口>，Safari 等 App 的内网请求由此 100% 进入
    /// sing-box 路由（IP 规则 / 域名规则均可命中 go-lan-home）。
    private var effectiveMixedPort: Int = 2080

    // MARK: - 生命周期

    /// 【build 169 方案】init() 级最早心跳：系统 pkd 实例化扩展进程的
    /// 瞬间（早于 startTunnel）即写入 "init" 心跳，诊断可精准区分
    /// 「进程未被拉起（hb=无）」与「拉起了但未进 startTunnel」
    override init() {
        super.init()
        prismProviderRef = self
        writeHeartbeat("init")
    }

    // MARK: - 共享目录与诊断写入

    private func sharedDirURLs() -> [URL] {
        var urls: [URL] = []
        if let resolved = resolvedSharedDirURL {
            urls.append(resolved)
        }
        if let groupURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: prismAppGroupID) {
            if !urls.contains(groupURL) {
                urls.append(groupURL)
            }
        }
        let prefURL = URL(fileURLWithPath: "/private/var/mobile/Library/Preferences")
        if !urls.contains(prefURL) {
            urls.append(prefURL)
        }
        return urls
    }

    private func writeSharedError(_ message: String) {
        // 内核报错脱敏：写入共享错误文件前抹除内核商标字样（不区分大小写）
        let cleanMsg = message
            .replacingOccurrences(of: "sing-box", with: "内核", options: .caseInsensitive)
            .replacingOccurrences(of: "singbox", with: "内核", options: .caseInsensitive)
            .replacingOccurrences(of: "libbox", with: "内核", options: .caseInsensitive)
        NSLog("[PrismVPN] ERROR: \(cleanMsg)")
        for dir in sharedDirURLs() {
            let url = dir.appendingPathComponent("prism_error.txt")
            try? cleanMsg.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    private func clearSharedError() {
        lastOpenTunError = nil
        for dir in sharedDirURLs() {
            try? FileManager.default.removeItem(at: dir.appendingPathComponent("prism_error.txt"))
        }
    }

    private func writeHeartbeat(_ stage: String) {
        lastHeartbeatStage = stage
        let ts = Int(Date().timeIntervalSince1970)
        let text = "\(ts) \(stage)"
        for dir in sharedDirURLs() {
            let url = dir.appendingPathComponent("prism_status.txt")
            try? text.write(to: url, atomically: true, encoding: .utf8)
        }
    }

    /// 【APP10 任务2.2】向 App Group vpn_trace.log 追加一行 GoLan-Ext 实况
    /// 日志：扩展进程内真实生效的 go-lan-home 顶层字段与回家路由网段。
    /// 主 App 运行日志（logger.rs collect_kernel_and_extension_logs）会
    /// 读取该文件并按 go-lan-home 关键字归类到 GoLan 模块。
    private func writeGoLanExtLog(_ sanitizedConfig: String) {
        guard let data = sanitizedConfig.data(using: .utf8),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let outbounds = root["outbounds"] as? [[String: Any]],
              let golan = outbounds.first(where: {
                  ($0["tag"] as? String) == "go-lan-home"
              })
        else { return }
        let server = golan["server"] as? String ?? "?"
        let port = (golan["server_port"] as? NSNumber)?.intValue
            ?? (golan["server_port"] as? Int) ?? 0
        let local = (golan["local_address"] as? [String])?.joined(separator: ",")
            ?? (golan["local_address"] as? String) ?? "?"
        var cidrs: [String] = []
        if let rules = (root["route"] as? [String: Any])?["rules"] as? [[String: Any]] {
            for rule in rules where (rule["outbound"] as? String) == "go-lan-home" {
                for c in (rule["ip_cidr"] as? [String]) ?? [] where !cidrs.contains(c) {
                    cidrs.append(c)
                }
            }
        }
        let ts = Int(Date().timeIntervalSince1970)
        let line = "\(ts) INFO [GoLan-Ext] 扩展已加载 go-lan-home -> server=\(server):\(port), local=\(local), 路由网段=[\(cidrs.joined(separator: ", "))]\n"
        for dir in sharedDirURLs() {
            let url = dir.appendingPathComponent("vpn_trace.log")
            if let h = try? FileHandle(forWritingTo: url) {
                h.seekToEndOfFile()
                h.write(line.data(using: .utf8) ?? Data())
                try? h.close()
            } else {
                try? line.write(to: url, atomically: true, encoding: .utf8)
            }
        }
    }

    private func loadRawConfigText() throws -> String {
        if let configPath = (protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["config_path"] as? String,
           !configPath.isEmpty
        {
            resolvedSharedDirURL = URL(fileURLWithPath: configPath).deletingLastPathComponent()
            return try String(contentsOfFile: configPath, encoding: .utf8)
        } else if let inlineConfig = (protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["config"] as? String
        {
            return inlineConfig
        } else {
            throw NSError(domain: "PrismVPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "缺少配置（providerConfiguration.config_path）"])
        }
    }

    // MARK: - 启动隧道

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        prismProviderRef = self
        // 【APP-2】启动常驻 NWPathMonitor（幂等），供 findActivePhysicalInterface
        // 精准识别系统默认路由网卡（弱 Wi-Fi 自动切走 / 双卡 VoLTE 场景）
        startSystemPathMonitor()
        // 【APP-3】事件驱动切网检测（替代 3 秒轮询定时器）
        startNetworkPathMonitor()
        let phy = findActivePhysicalInterface()
        activeBoundInterface = phy.name

        if let configPath = (protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["config_path"] as? String,
           !configPath.isEmpty
        {
            resolvedSharedDirURL = URL(fileURLWithPath: configPath).deletingLastPathComponent()
        }

        clearSharedError()
        writeHeartbeat("start(\(phy.name))")

        stateLock.lock()
        if currentState != .stopped {
            stateLock.unlock()
            let err = NSError(domain: "PrismVPN", code: -1, userInfo: [NSLocalizedDescriptionKey: "内核正在运行或状态切换中"])
            completionHandler(err)
            return
        }
        currentState = .starting
        stateLock.unlock()

        let configText: String
        do {
            configText = try loadRawConfigText()
        } catch {
            failStart(code: 3, message: "无法读取共享配置文件: \(error.localizedDescription)", completionHandler: completionHandler)
            return
        }

        let baseDir = resolvedSharedDirURL
            ?? FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: prismAppGroupID)
            ?? FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        let workDir = baseDir.appendingPathComponent("prism_work", isDirectory: true)
        activeWorkDir = workDir

        vpnQueue.async { [weak self] in
            guard let self = self else { return }

            do {
                try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
                try? self.copyGeoDatabases(to: workDir)

                // 【APP11 任务5.1】启动前清空 box.log / vpn_trace.log：
                // 内核以 append 模式写 box.log，跨会话累积会让运行日志里
                // 堆满历史内核报错（8.8.8.8:853 i/o timeout 等）；vpn_trace.log
                // 是本扩展自写的实况日志，同样逐会话累积。启动前截断，
                // 保证日志只反映本次会话。
                for logName in ["box.log", "vpn_trace.log"] {
                    let u = workDir.appendingPathComponent(logName)
                    try? FileManager.default.removeItem(at: u)
                    FileManager.default.createFile(atPath: u.path, contents: nil)
                }

                let currentPhy = findActivePhysicalInterface()
                self.activeBoundInterface = currentPhy.name
                let sanitizedConfig = self.sanitizeConfigForExtension(
                    configText,
                    workDir: workDir,
                    phyName: currentPhy.name,
                    phyIPv4: currentPhy.ipv4
                )
                // 预解析与网卡取值都在 PrismVPNStart（内部才 setTunnelNetworkSettings）
                // 之前完成，保证 WireGuard 服务器 IP 落地时 UDP 会话仍绑定物理网卡

                // 【APP10 任务2.2】GoLan-Ext 实况日志：把扩展进程内真实生效的
                // go-lan-home 参数（server/local/路由网段）写入 App Group
                // vpn_trace.log，用户可在运行日志界面直接确认扩展侧配置。
                self.writeGoLanExtLog(sanitizedConfig)

                let callbacks = prism_vpn_cbs(
                    open_tun: prismOpenTun,
                    protect_socket: prismProtectSocket,
                    under_extension: prismUnderExtension
                )
                PrismVPNSetCallbacks(callbacks)
                self.writeHeartbeat("calling-PrismVPNStart(\(currentPhy.name))")

                let errorPtr = sanitizedConfig.withCString { configPtr in
                    workDir.path.withCString { dirPtr in
                        PrismVPNStart(
                            UnsafeMutablePointer(mutating: configPtr),
                            UnsafeMutablePointer(mutating: dirPtr)
                        )
                    }
                }

                if let errorPtr = errorPtr {
                    let message = String(cString: errorPtr)
                    PrismKernelFree(errorPtr)
                    // 【APP-11 任务1.1】移除 go-lan-home 静默剥离降级：
                    // 过去配置有误时自动剥掉回家出站并"启动成功"，用户以为
                    // Go Lan 已生效，实际家里根本连不上，问题被长期掩盖。
                    // 现在错误必须原样上抛到前端，让用户明确看到失败原因。
                    self.writeHeartbeat("start-failed:\(message)")
                    throw NSError(domain: "PrismVPN", code: 2, userInfo: [NSLocalizedDescriptionKey: message])
                }

                self.stateLock.lock()
                self.currentState = .running
                self.stateLock.unlock()

                self.writeHeartbeat("running(\(currentPhy.name))")
                // 【APP-4 任务5】隧道启动 1 秒后向内网网关发轻量探测，
                // 触发 WireGuard 首次握手（wg-easy 面板即时在线/流量）
                self.scheduleGoLanWarmup(sanitizedConfig: sanitizedConfig)
                DispatchQueue.main.async {
                    self.startHeartbeatTimer()
                    completionHandler(nil)
                }
            } catch {
                self.failStart(code: 2, message: error.localizedDescription, completionHandler: completionHandler)
            }
        }
    }

    /// 当检测到物理网络切换（如出门从 Wi-Fi en0 切换到蜂窝流量 pdp_ip0，或回家从 pdp_ip0 切回 en0）时，
    /// 自动热重载 sing-box 内核并绑定到新网卡，彻底解决切流量断网问题
    private func checkAndReloadIfNetworkChanged() {
        stateLock.lock()
        let isRunning = (currentState == .running)
        stateLock.unlock()
        guard isRunning, !isReloadingForNetworkChange else { return }

        let latestPhy = findActivePhysicalInterface()
        // ipa-8 隐患 C：仅当新候选网卡具备真实可路由 IP 时才热重载。
        // 飞行模式/电梯等短暂完全无网时 findActivePhysicalInterface 走
        // 盲猜兜底（hasRoutableIP=false），此时保持现有隧道待机，等
        // 信号恢复（真实网卡出现）后再平滑切网，绝不报错停止
        guard !latestPhy.name.isEmpty,
              latestPhy.hasRoutableIP,
              latestPhy.name != activeBoundInterface
        else {
            return
        }

        let oldIf = activeBoundInterface
        let newIf = latestPhy.name
        NSLog("[PrismVPN] 检测到物理网卡切换: \(oldIf) -> \(newIf)，正在热重载内核...")
        isReloadingForNetworkChange = true
        activeBoundInterface = newIf
        writeHeartbeat("netSwitch:\(oldIf)->\(newIf)")

        vpnQueue.async { [weak self] in
            guard let self = self, let workDir = self.activeWorkDir else {
                self?.isReloadingForNetworkChange = false
                return
            }
            if let rawConfig = try? self.loadRawConfigText() {
                let updatedConfig = self.sanitizeConfigForExtension(
                    rawConfig,
                    workDir: workDir,
                    phyName: newIf,
                    phyIPv4: latestPhy.ipv4
                )
                PrismVPNStop()
                let errPtr = updatedConfig.withCString { configPtr in
                    workDir.path.withCString { dirPtr in
                        PrismVPNStart(
                            UnsafeMutablePointer(mutating: configPtr),
                            UnsafeMutablePointer(mutating: dirPtr)
                        )
                    }
                }
                if let errPtr = errPtr {
                    let msg = String(cString: errPtr)
                    PrismKernelFree(errPtr)
                    self.writeSharedError("网络切换(\(oldIf)->\(newIf))重载失败: \(msg)")
                } else {
                    self.writeHeartbeat("running(\(newIf))")
                }
            }
            self.isReloadingForNetworkChange = false
        }
    }

    private func failStart(code: Int, message: String, completionHandler: @escaping (Error?) -> Void) {
        stateLock.lock()
        currentState = .stopped
        stateLock.unlock()

        let fullMessage: String
        if let tunErr = lastOpenTunError, !tunErr.isEmpty {
            fullMessage = "\(message) [openTun原因: \(tunErr)]"
        } else {
            fullMessage = message
        }

        writeSharedError(fullMessage)
        writeHeartbeat("startFailed(\(lastHeartbeatStage))")
        let err = NSError(domain: "PrismVPN", code: code, userInfo: [NSLocalizedDescriptionKey: fullMessage])
        DispatchQueue.main.async {
            completionHandler(err)
        }
    }

    /// 【APP-3】事件驱动切网：NWPathMonitor 在系统网络路径真正变化
    ///（Wi-Fi ⇄ 蜂窝、断网恢复、默认路由切换）时才回调，网络稳定时
    /// CPU / 磁盘开销为 0；替代原先每 3 秒调用一次 getifaddrs 的定时器。
    /// NWPathMonitor 的回调在 vpnQueue 上执行，稍作延迟等待
    /// startSystemPathMonitor 更新默认网卡名，再执行热重载判定。
    private func startNetworkPathMonitor() {
        pathMonitor?.cancel()
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] _ in
            self?.vpnQueue.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.checkAndReloadIfNetworkChanged()
            }
        }
        monitor.start(queue: vpnQueue)
        pathMonitor = monitor
    }

    /// 低频心跳（60s）：仅用于主 App 看门狗判定扩展存活与故障阶段，
    /// 不再承担网卡检测职责（切网由 NWPathMonitor 事件驱动）
    private func startHeartbeatTimer() {
        heartbeatTimer?.invalidate()
        let t = Timer.scheduledTimer(withTimeInterval: 60.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            self.writeHeartbeat("alive(\(self.activeBoundInterface))")
        }
        RunLoop.main.add(t, forMode: .common)
        heartbeatTimer = t
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        stateLock.lock()
        currentState = .stopping
        stateLock.unlock()

        DispatchQueue.main.async {
            self.heartbeatTimer?.invalidate()
            self.heartbeatTimer = nil
        }
        pathMonitor?.cancel()
        pathMonitor = nil

        writeHeartbeat("stopped:\(reason.rawValue)")

        // 【APP22 任务2.2】PrismVPNStop 已改为非阻塞超时关闭（内部 1500ms
        // 上限，先摘指针再异步关闭），此处调用后立即回调 completionHandler()，
        // 绝不等待 wireguard[go-lan-home] 关闭完成，杜绝系统判定 stop 超时；
        // 进程在 Go 侧关闭窗口（1.8s）结束后退出，完成最终清理。
        DispatchQueue.global(qos: .userInitiated).async {
            PrismVPNStop()
        }
        DispatchQueue.main.async {
            completionHandler()
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.8) {
                exit(0)
            }
        }
    }

    // MARK: - OpenTun

    fileprivate func openTun(optionsJSON: String) -> Int32 {
        NSLog("[PrismVPN] openTun options: \(optionsJSON)")
        writeHeartbeat("openTun")

        guard let data = optionsJSON.data(using: .utf8),
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            lastOpenTunError = "optionsJSON 解析失败: \(optionsJSON.prefix(200))"
            writeHeartbeat("tunJsonErr")
            return -1
        }

        // 【APP22 任务4.2】外层 utun MTU 与 tun-in 统一 1280。
        // 1280 会自动向对端宣告 MSS = 1240，飞牛 NAS 回送的网页 TLS
        // 证书 / JS 大包 / SMB 文件块最大 1280 字节，加 60 字节 WireGuard
        // 头部仅 1340 字节，可 100% 无损穿过 MTU 1420 的 go-lan-home 与
        // 5G 蜂窝网络；历史 1500 倒挂会把满载分段静默丢弃。
        let mtu: Int32 = 1280

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: mtu)

        let dnsServer = (json["dns_server"] as? String)
            ?? ((json["dns_servers"] as? [String])?.first)
            ?? "1.1.1.1"
        let cleanDNS = dnsServer.isEmpty ? "1.1.1.1" : dnsServer
        let dnsSettings = NEDNSSettings(servers: [cleanDNS, "8.8.8.8"])
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings

        var v4Addresses = prefixes(json["inet4_address"])
        if v4Addresses.isEmpty {
            v4Addresses = prefixes(json["address"])
        }
        if v4Addresses.isEmpty {
            v4Addresses = [Prefix(address: "172.19.0.1", prefix: 30)]
        }

        let ipv4 = NEIPv4Settings(
            addresses: v4Addresses.map(\.address),
            subnetMasks: v4Addresses.map { subnetMask(prefix: $0.prefix) }
        )
        // 【APP22 任务4.1】includedRoutes 必须包含系统默认路由，让全部
        // 流量进入 utun，再由内核 route.rules 的 ip_cidr → go-lan-home 分流。
        var includedRoutes: [NEIPv4Route] = [NEIPv4Route.default()]

        // 【APP25 任务2.2】再把回家网段显式下发给系统（gatewayAddress 指向
        // 隧道自身地址 172.19.0.1）。系统守护进程（「文件」App SMB、
        // 打印 cupsd）不走 App 的 HTTP 代理，只能依赖这条系统级路由；
        // 同时 iPhone 自身 Wi-Fi 与回家网段重叠时，显式路由优先接管。
        // 10.196.0.0/24 是 go-lan-home 的 WireGuard 管理网段，必须排除，
        // 否则会把隧道自身的握手流量再喂回隧道形成环路。
        let gatewayIp = v4Addresses.first?.address ?? "172.19.0.1"
        let sidecarDir = activeWorkDir ?? resolvedSharedDirURL
        var lanRouteCount = 0
        if let dir = sidecarDir {
            let sidecarURL = dir.appendingPathComponent("golan_routes.json")
            if let rawData = try? Data(contentsOf: sidecarURL),
               let cidrList = (try? JSONSerialization.jsonObject(with: rawData)) as? [String] {
                for cidr in cidrList {
                    if cidr == "10.196.0.0/24" { continue }
                    let parts = cidr.split(separator: "/")
                    guard parts.count == 2,
                          let prefixLen = Int(parts[1]),
                          prefixLen > 0, prefixLen < 32
                    else { continue }
                    let route = NEIPv4Route(
                        destinationAddress: String(parts[0]),
                        networkPrefixLength: NSNumber(value: prefixLen)
                    )
                    route.gatewayAddress = gatewayIp
                    includedRoutes.append(route)
                    lanRouteCount += 1
                }
            }
        }
        ipv4.includedRoutes = includedRoutes
        ipv4.excludedRoutes = []
        settings.ipv4Settings = ipv4

        // 【APP25 任务2.2】NEProxySettings 把系统 HTTP/HTTPS 代理指向
        // 127.0.0.1:<mixed-in 端口>：Safari / 飞牛 App 等内网 Web 请求
        // 100% 进入 sing-box 的 mixed-in，再按 route.rules 命中
        // go-lan-home，避免「只有 http 协议能过、https 直连被内网设备重置」。
        // exceptionList 仅保留回环地址，严禁放行内网网段（否则请求绕过代理）。
        let proxySettings = NEProxySettings()
        let proxyServer = NEProxyServer(address: "127.0.0.1", port: effectiveMixedPort)
        proxySettings.httpEnabled = true
        proxySettings.httpServer = proxyServer
        proxySettings.httpsEnabled = true
        proxySettings.httpsServer = proxyServer
        proxySettings.exceptionList = ["127.0.0.1", "localhost"]
        settings.proxySettings = proxySettings
        NSLog("[PrismVPN] proxy 127.0.0.1:\(effectiveMixedPort) lanRoutes=\(lanRouteCount)")

        let v6Addresses = prefixes(json["inet6_address"]).filter { !$0.address.isEmpty && $0.prefix > 0 }
        if !v6Addresses.isEmpty {
            let ipv6 = NEIPv6Settings(
                addresses: v6Addresses.map(\.address),
                networkPrefixLengths: v6Addresses.map { NSNumber(value: $0.prefix) }
            )
            let v6Routes = prefixes(json["inet6_route_address"])
            if v6Routes.isEmpty {
                ipv6.includedRoutes = [NEIPv6Route.default()]
            } else {
                ipv6.includedRoutes = v6Routes.map {
                    if $0.prefix <= 0 || $0.address == "::" {
                        return NEIPv6Route.default()
                    }
                    return NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.prefix))
                }
            }
            settings.ipv6Settings = ipv6
        } else {
            // 【APP12 任务3】空壳 ipv6Settings：即使不接管任何 IPv6 流量，
            // 也要挂一个 includedRoutes=[]、excludedRoutes=[default] 的占位。
            // 原理：iOS 内核 NECP 只有在隧道配置了 ipv6Settings 时才允许扩展
            // 进程创建 AF_INET6 双栈 UDP Socket（wireguard-go 会同时尝试
            // udp4 和 udp6），否则直接 EPERM → WireGuard 握手包发不出。
            let ipv6 = NEIPv6Settings(addresses: [], networkPrefixLengths: [])
            ipv6.includedRoutes = []
            ipv6.excludedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
        }

        if let err = applyNetworkSettingsSync(settings) {
            settings.ipv6Settings = nil
            if let retryErr = applyNetworkSettingsSync(settings) {
                lastOpenTunError = "setTunnelNetworkSettings失败: \(retryErr) (原始错误: \(err))"
                writeHeartbeat("tunSetErr")
                return -1
            }
        }

        writeHeartbeat("tun-ok")

        guard let fd = findTunnelFileDescriptor(), fd >= 0 else {
            lastOpenTunError = "无法获取 utun 文件描述符"
            writeHeartbeat("tunFdFail")
            return -1
        }

        NSLog("[PrismVPN] openTun succeeded, fd=\(fd)")
        writeHeartbeat("tun-fd:\(fd)")
        return fd
    }

    private func applyNetworkSettingsSync(_ settings: NEPacketTunnelNetworkSettings) -> String? {
        let semaphore = DispatchSemaphore(value: 0)
        var settingsError: Error?
        setTunnelNetworkSettings(settings) { error in
            settingsError = error
            semaphore.signal()
        }
        let waitResult = semaphore.wait(timeout: .now() + 10)
        if waitResult == .timedOut {
            return "10s超时"
        }
        if let settingsError = settingsError {
            return settingsError.localizedDescription
        }
        return nil
    }

    private func findTunnelFileDescriptor() -> Int32? {
        if let fd = (packetFlow.value(forKeyPath: "socket.fileDescriptor") as? Int32)
            ?? (packetFlow.value(forKeyPath: "socket.socketDescriptor") as? Int32),
           fd >= 0
        {
            return fd
        }

        let sysprotoControl: Int32 = 2
        let utunOptIfname: Int32 = 2
        var matchedFd: Int32? = nil

        for fd: Int32 in 0...1024 {
            var buf = [CChar](repeating: 0, count: 64)
            var len = socklen_t(buf.count)
            let ret = getsockopt(fd, sysprotoControl, utunOptIfname, &buf, &len)
            if ret == 0 && len > 0 {
                let name = String(cString: buf)
                if name.hasPrefix("utun") {
                    matchedFd = fd
                }
            }
        }
        return matchedFd
    }

    // MARK: - 配置清洗与物理网卡绑定

    // MARK: - WireGuard 密钥兜底自愈（APP-6 任务3）

    /// WireGuard 密钥规范化：URL 解码 → 去引号/空白 → URL-safe 转标准 →
    /// 补齐 padding → Base64 解码；32 字节（且不全为 0）校验通过返回
    /// 苹果原生标准 44 位 Base64，否则返回 nil。
    /// 修复 `decode pre shared key ... illegal base64 data at input byte 43`：
    /// 末尾 `=` 被编码成 `%3D`（byte 43 为 `%`）等历史脏数据在此自愈。
    private func sanitizeWireGuardKey(_ raw: Any?) -> String? {
        guard let s = raw as? String else { return nil }
        var str = s
        if let decoded = str.removingPercentEncoding {
            str = decoded
        }
        str = str.trimmingCharacters(in: .whitespacesAndNewlines)
            .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
        if let idx = str.firstIndex(of: "#") {
            str = String(str[..<idx])
        }
        str = str.trimmingCharacters(in: .whitespacesAndNewlines)
        if str.isEmpty { return nil }
        // 64 位纯 Hex → 32 字节原始密钥
        if str.count == 64, str.allSatisfy({ $0.isHexDigit }) {
            var bytes = [UInt8]()
            var it = str.startIndex
            while let next = str.index(it, offsetBy: 2, limitedBy: str.endIndex) {
                guard let b = UInt8(str[it..<next], radix: 16) else { break }
                bytes.append(b)
                it = next
            }
            guard bytes.count == 32, !bytes.allSatisfy({ $0 == 0 }) else { return nil }
            return Data(bytes).base64EncodedString()
        }
        // URL-safe（-/ _）→ 标准 Base64 字符；只保留合法数据字符
        let replaced = str.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let cleaned = String(replaced.filter {
            ("a"..."z").contains($0) || ("A"..."Z").contains($0) ||
            ("0"..."9").contains($0) || $0 == "+" || $0 == "/"
        })
        // 32 字节密钥 = 43 个数据字符 + 1 个 `=` 填充
        guard cleaned.count == 43 else { return nil }
        guard let data = Data(base64Encoded: cleaned + "="), data.count == 32,
              !data.allSatisfy({ $0 == 0 }) else { return nil }
        return data.base64EncodedString()
    }

    // MARK: - WireGuard 域名预解析（APP-8 任务3）

    /// 基于 iOS 系统原生 getaddrinfo 的域名预解析。
    /// 内核 post-start 阶段对 wireguard 出站必须同步解析 server 域名，
    /// 若 dns-direct(-bak) 解析被 RST 会中断整个 VPN 启动。提前在扩展侧
    /// 把 server 域名替换为 IP，post-start 零 DNS 请求、瞬时启动。
    /// 优先返回 IPv4，无 IPv4 时返回第一个 IPv6；解析失败返回 nil。
    /// 【APP22 任务2.2】限时 1.5 秒：getaddrinfo 在弱网/无网下可能阻塞
    /// 数秒，拖垮 startTunnel 触发 code=12。超时按解析失败处理（保留
    /// 原域名交给内核解析），绝不卡住启动流程；已是 IP 字面量时调用方
    /// 经 isIPLiteral 守卫直接跳过本函数，0ms 通过。
    private func resolveHostToIP(_ host: String) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return nil }
        let sem = DispatchSemaphore(value: 0)
        let box = ResolveResultBox()
        DispatchQueue.global(qos: .userInitiated).async {
            box.value = self.resolveHostToIPInner(trimmed)
            sem.signal()
        }
        let waitRet = sem.wait(timeout: .now() + 1.5)
        if waitRet == .timedOut { return nil }
        return box.value
    }

    private func resolveHostToIPInner(_ host: String) -> String? {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return nil }
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var res: UnsafeMutablePointer<addrinfo>? = nil
        let status = getaddrinfo(trimmed, nil, &hints, &res)
        guard status == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }

        var ipv6Fallback: String? = nil
        var ptr: UnsafeMutablePointer<addrinfo>? = first
        while let info = ptr {
            if info.pointee.ai_family == AF_INET, let addr = info.pointee.ai_addr {
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                let sin = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var inAddr = sin.sin_addr
                if inet_ntop(AF_INET, &inAddr, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    return String(cString: buffer)
                }
            } else if info.pointee.ai_family == AF_INET6, ipv6Fallback == nil, let addr = info.pointee.ai_addr {
                var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                let sin6 = addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var in6Addr = sin6.sin6_addr
                if inet_ntop(AF_INET6, &in6Addr, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                    ipv6Fallback = String(cString: buffer)
                }
            }
            ptr = info.pointee.ai_next
        }
        return ipv6Fallback
    }

    /// 判断字符串是否已是 IP 字面量（IPv4 或 IPv6）
    private func isIPLiteral(_ s: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, s, &v4) == 1 { return true }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, s, &v6) == 1 { return true }
        return false
    }

    // MARK: - Go Lan 主动握手探测（APP-4 任务5）

    /// 隧道启动成功 1 秒后，经 Clash API 对 go-lan-home 出站向内网网关发起
    /// 轻量延迟探测：网关取 local_address 末段改 .1（如 10.1.8.2/24 → 10.1.8.1）
    /// 以及 route.rules 中各回家网段的 .1。探测包穿过隧道即触发 WireGuard
    /// Handshake——配合 peers[0].persistent_keepalive_interval=15 的启动即
    /// 握手，wg-easy 面板立即显示在线与实时流量（与桌面端
    /// spawn_go_lan_warmup 对齐；结果不重要，发包即可）。
    private func scheduleGoLanWarmup(sanitizedConfig: String) {
        guard let data = sanitizedConfig.data(using: .utf8),
              let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return }

        // 仅当配置里确实存在 go-lan-home WireGuard 出站时才需要探测
        let outbounds = (root["outbounds"] as? [[String: Any]]) ?? []
        guard let wg = outbounds.first(where: {
            ($0["tag"] as? String) == "go-lan-home" && ($0["type"] as? String) == "wireguard"
        }) else { return }

        var gateways: [String] = []
        func pushGateway(_ ip: String) {
            let parts = ip.split(separator: ".")
            guard parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) else { return }
            let gw = "\(parts[0]).\(parts[1]).\(parts[2]).1"
            if !gateways.contains(gw) { gateways.append(gw) }
        }
        let localAddrs = (wg["local_address"] as? [String])
            ?? (wg["local_address"] as? String).map { [$0] }
            ?? []
        for la in localAddrs {
            pushGateway(la.split(separator: "/").first.map(String.init) ?? "")
        }
        let rules = ((root["route"] as? [String: Any])?["rules"] as? [[String: Any]]) ?? []
        for rule in rules where (rule["outbound"] as? String) == "go-lan-home" {
            for cidr in (rule["ip_cidr"] as? [String]) ?? [] {
                pushGateway(cidr.split(separator: "/").first.map(String.init) ?? "")
            }
        }
        guard !gateways.isEmpty else { return }

        // Clash API 地址与密钥（与桌面端 KernelApi.test_delay 一致）
        guard let clashAPI = (root["experimental"] as? [String: Any])?["clash_api"] as? [String: Any],
              let controller = clashAPI["external_controller"] as? String,
              !controller.isEmpty else { return }
        let secret = clashAPI["secret"] as? String
        let base = controller.hasPrefix("http") ? controller : "http://\(controller)"

        vpnQueue.asyncAfter(deadline: .now() + 1.0) {
            for gw in gateways {
                var comps = URLComponents(string: "\(base)/proxies/go-lan-home/delay")
                comps?.queryItems = [
                    URLQueryItem(name: "url", value: "http://\(gw)"),
                    URLQueryItem(name: "timeout", value: "1500"),
                ]
                guard let url = comps?.url else { continue }
                var req = URLRequest(url: url, timeoutInterval: 3.5)
                if let secret = secret, !secret.isEmpty {
                    req.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
                }
                // 探测结果不重要（家庭网关多半不开 HTTP），只要发包即可触发握手
                URLSession.shared.dataTask(with: req).resume()
            }
            NSLog("[PrismVPN] [go-lan] 主动握手探测已触发 \(gateways)")
        }
    }

    // MARK: - go-lan-home 剥离兜底（APP-8 任务4）

    /// 从配置 JSON 中剥离 go-lan-home WireGuard 出站及其关联引用，
    /// 用于家庭 DDNS 域名彻底无法解析时的降级启动。
    /// 剥离范围：
    ///   - outbounds[] 中 tag == "go-lan-home"
    ///   - route.rules[] 中 outbound == "go-lan-home"
    ///   - route.final / dns.rules[].server / dns.servers[] 中引用
    ///     go-lan-home 的项（dns-home 服务器 detour 指向 go-lan-home 时移除）
    /// 返回剥离后的 JSON 字符串；若无可剥离内容返回原串。
    private func stripGoLanHome(from configJSON: String) -> String {
        guard let data = configJSON.data(using: .utf8),
              var root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return configJSON }

        let tag = "go-lan-home"
        var changed = false

        // 1. outbounds 中移除
        if var outbounds = root["outbounds"] as? [[String: Any]] {
            let before = outbounds.count
            outbounds.removeAll { ($0["tag"] as? String) == tag }
            if outbounds.count != before {
                root["outbounds"] = outbounds
                changed = true
            }
        }

        // 2. route.rules 中移除 outbound == go-lan-home 的规则
        if var route = root["route"] as? [String: Any] {
            if var rules = route["rules"] as? [[String: Any]] {
                let before = rules.count
                rules.removeAll { ($0["outbound"] as? String) == tag }
                if rules.count != before {
                    route["rules"] = rules
                    changed = true
                }
            }
            // route.final 若指向 go-lan-home 则回退为 proxy
            if (route["final"] as? String) == tag {
                route["final"] = "proxy"
                changed = true
            }
            root["route"] = route
        }

        // 3. dns：移除 detour 指向 go-lan-home 的 dns-home 服务器，及其规则
        if var dns = root["dns"] as? [String: Any] {
            if var servers = dns["servers"] as? [[String: Any]] {
                let before = servers.count
                servers.removeAll { ($0["detour"] as? String) == tag }
                if servers.count != before {
                    dns["servers"] = servers
                    changed = true
                }
            }
            if var rules = dns["rules"] as? [[String: Any]] {
                let before = rules.count
                rules.removeAll { ($0["server"] as? String) == "dns-home" }
                if rules.count != before {
                    dns["rules"] = rules
                    changed = true
                }
            }
            root["dns"] = dns
        }

        guard changed,
              let out = try? JSONSerialization.data(withJSONObject: root),
              let str = String(data: out, encoding: .utf8)
        else { return configJSON }
        return str
    }

    /// - Parameters:
    ///   - phyName: 当前活跃物理网卡名（en0 / pdp_ip0），仅记录日志
    ///   - phyIPv4: 该网卡的真实 IPv4，仅记录日志，不再用于 excludedRoutes 或
    ///     出站 inet4_bind_address（iOS 路由完全由 NEPacketTunnelNetworkSettings
    ///     下发，APP18 起 excludedRoutes 保持空）
    private func sanitizeConfigForExtension(
        _ rawJSON: String,
        workDir: URL,
        phyName: String,
        phyIPv4: String = ""
    ) -> String {
        guard let data = rawJSON.data(using: .utf8),
              var root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            return rawJSON
        }

        let cacheDBURL = workDir.appendingPathComponent("cache.db")
        try? FileManager.default.removeItem(at: cacheDBURL)

        // 1. 修正 inbounds 中的 tun 配置
        if var inbounds = root["inbounds"] as? [[String: Any]] {
            for i in inbounds.indices {
                if (inbounds[i]["type"] as? String) == "tun" {
                    inbounds[i].removeValue(forKey: "interface_name")
                    inbounds[i]["strict_route"] = false
                    // 【APP18 任务2】iOS 路由完全由 NEPacketTunnelNetworkSettings
                    // 下发，tun-in 不再自行改路由（auto_route=false）。
                    inbounds[i]["auto_route"] = false
                    // 【APP22 任务4.2】tun-in MTU 与 NEPacketTunnelNetworkSettings
                    // 的 settings.mtu 严格一致，统一 1280：向对端宣告
                    // MSS=1240，飞牛 NAS 回包 +60 字节 WG 头仅 1340 字节，
                    // 100% 穿透 5G 蜂窝网络。
                    inbounds[i]["mtu"] = 1280
                    // 【APP22 任务2.1】tun-in 栈固定 gvisor：上一轮改用的
                    // "system" 在 iOS 网络扩展沙盒中引发启动/关闭挂起
                    //（ERR7 code=12），严禁在 iOS 上使用 system 栈。
                    inbounds[i]["stack"] = "gvisor"
                    // 【APP10 任务2.1】tun-in 严禁 sniff=true：
                    // sniff 开启时 sing-box 会在 tun-in 收到发往
                    // 192.168.10.253:80 的包时先在本地伪造 TCP 握手
                    // （SYN-ACK 代答）并等待客户端发 HTTP 头，造成
                    // "TUN直连:80 延迟 2502 ms" 假阳性检测，还会干扰
                    // SMB/SSH/WebSocket 等非 HTTP 内网协议。本 App DNS
                    // 采用 dns-remote/dns-local 标准解析（非 FakeIP），
                    // IP 与域名规则直接匹配，关闭 sniff 后访问
                    // 10.1.8.0/24、192.168.10.0/24 的包零延迟直入
                    // go-lan-home WireGuard 隧道。
                    inbounds[i]["sniff"] = false
                    inbounds[i]["sniff_override_destination"] = false
                    inbounds[i]["udp_timeout"] = "5m"
                }
            }
            root["inbounds"] = inbounds
        }

        // 【APP25 任务2.2】记录 mixed-in 实际监听端口，供 openTun 的
        // NEProxySettings 使用（Rust 端默认 2080，此处按实际配置读取）
        if let ins = root["inbounds"] as? [[String: Any]] {
            for item in ins where (item["type"] as? String) == "mixed" {
                if let p = (item["listen_port"] as? NSNumber)?.intValue, p > 0, p < 65536 {
                    effectiveMixedPort = p
                    break
                }
            }
        }

        // 2. 检查 outbounds：绑定当前活跃物理网卡 (en0 或 pdp_ip0)，收集全部真实代理节点 tag
        var dnsOutboundTag: String? = nil
        var blockOutboundTag: String? = nil
        var hasDirectOutbound = false
        var firstSelectorTag: String? = nil
        var allRealProxyTags: [String] = []

        let proxyOutboundTypes: Set<String> = [
            "vless", "vmess", "trojan", "shadowsocks",
            "hysteria", "hysteria2", "tuic", "wireguard", "http", "socks", "ssh", "anytls"
        ]
        var outbounds = (root["outbounds"] as? [[String: Any]]) ?? []
        // 【APP14 任务2】不再给出站注入 bind_interface：
        // 实证（文本(1).txt）——155 个常规代理节点在 5G 下全部正常，而
        // go-lan-home 握手失败。扩展进程自身 Socket 由 iOS NECP 天然走
        // 当前活跃物理网卡（pdp_ip0 / en0），额外的 IP_BOUND_IF 强绑反而
        // 把发往 WireGuard 对端的 UDP 握手包堵死。让 go-lan-home 与常规
        // 代理节点使用 100% 相同的底层 Socket 创建方式。
        _ = phyIPv4
        for i in outbounds.indices {
            let t = (outbounds[i]["type"] as? String) ?? ""
            let tag = (outbounds[i]["tag"] as? String) ?? ""
            // 【APP21 任务2】彻底移除全部出站的网卡强绑字段：扩展进程自身
            // Socket 由 iOS NECP 按当前活跃物理网卡（5G pdp_ip0 / Wi-Fi en0）
            // 原生路由，Wi-Fi ↔ 5G 随时无缝切换；强绑 bind_interface /
            // inet4_bind_address / routing_mark 只会在切换瞬间把 WireGuard
            // UDP 握手包堵死（log4 第 10 行 sendmsg: network is unreachable）。
            outbounds[i].removeValue(forKey: "bind_interface")
            outbounds[i].removeValue(forKey: "inet4_bind_address")
            outbounds[i].removeValue(forKey: "routing_mark")
            if t == "dns" {
                dnsOutboundTag = tag.isEmpty ? "dns-out" : tag
            } else if t == "block" {
                blockOutboundTag = tag.isEmpty ? "block" : tag
            } else if t == "direct" {
                hasDirectOutbound = true
                // 【APP-11B 任务2】direct 出站强制 ipv4_only：iOS 16.5 NECP 沙盒下
                // Go 默认创建 AF_INET6 双栈 UDP Socket 会被拒绝（EPERM），
                // 锁定 ipv4_only 强制使用纯 IPv4 udp4 Socket，根治
                // `listen outbound packet connection: operation not permitted`
                outbounds[i]["domain_strategy"] = "ipv4_only"
            } else if t == "selector" && !tag.isEmpty {
                if firstSelectorTag == nil {
                    firstSelectorTag = tag
                }
            } else if t == "urltest" {
                // 【APP-11B 任务3】清洗订阅自带 urltest 的畸形测速地址
                // （APP.txt 中 http://gateway.icloud.com 带空格导致后台
                // 疯狂报错刷屏耗电）：统一强制为 Cloudflare 204，间隔 10m。
                // Cloudflare 的 cp.cloudflare.com 在国内可达性与稳定性优于
                // gstatic，且响应体极小、无 TLS 指纹风险。
                var u = ((outbounds[i]["url"] as? String) ?? "")
                    .replacingOccurrences(of: " ", with: "")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if !u.lowercased().hasPrefix("http") {
                    u = "http://cp.cloudflare.com/generate_204"
                }
                outbounds[i]["url"] = u
                outbounds[i]["interval"] = "10m"
            } else if t == "wireguard" {
                // 【APP6 任务2】统一为 sing-box v1.11.3 **顶层单节点模式**
                // （connect=true，DialContext("udp4") 连接型 Socket）：
                // - peers 数组模式走 ListenPacket("udp","") 双栈非连接 Socket，
                //   在 iOS 扩展沙盒被 NECP 拦截报
                //   listen outbound packet connection: operation not permitted；
                // - allowed_ips / persistent_keepalive_interval 是顶层与 peers
                //   元素均不支持的非法字段（APP4/APP5 历史残留），
                //   写入触发 "decode config: ... json: unknown field" 直接
                //   拒绝启动，必须无条件剥离；
                // - domain_strategy: ipv4_only 强制纯 IPv4 Socket，根治
                //   NECP 对双栈 Socket 的 EPERM 拦截（IPA9 任务4.2）。
                // 【APP6 任务2】peers 数组模式在 sing-box v1.11.3 走
                // ListenPacket("udp","") 双栈非连接 Socket，iOS NECP 沙盒
                // 直接拦截报 listen outbound packet connection: operation
                // not permitted。把 peers[0] 提升为顶层单节点（connect=true，
                // DialContext("udp4") 连接型 Socket）后 100% 穿透出去。
                // 历史磁盘缓存 / 旧版本配置里若有 peers 数组，统一在此兜底。
                if var peers = outbounds[i]["peers"] as? [[String: Any]], let p0 = peers.first {
                    if (outbounds[i]["server"] as? String ?? "").isEmpty,
                       let s = p0["server"] as? String {
                        outbounds[i]["server"] = s
                    }
                    if outbounds[i]["server_port"] == nil,
                       let sp = p0["server_port"] {
                        outbounds[i]["server_port"] = sp
                    }
                    if (outbounds[i]["peer_public_key"] as? String ?? "").isEmpty,
                       let pk = p0["public_key"] as? String {
                        outbounds[i]["peer_public_key"] = pk
                    }
                    if outbounds[i]["pre_shared_key"] == nil,
                       let psk = p0["pre_shared_key"] as? String {
                        outbounds[i]["pre_shared_key"] = psk
                    }
                    peers.removeAll()
                    outbounds[i].removeValue(forKey: "peers")
                }
                // allowed_ips / persistent_keepalive_interval：顶层与 peers 元素
                // 均不支持（v1.11.3 LegacyWireGuard 结构），写入触发
                // "decode config: ... json: unknown field" 直接拒绝启动。
                // 必须无条件剥离。
                outbounds[i].removeValue(forKey: "allowed_ips")
                outbounds[i].removeValue(forKey: "persistent_keepalive_interval")
                // 【APP10 任务1】不注入 inet4_bind_address（5G 蜂窝下引发
                // i/o timeout）；domain_strategy: ipv4_only 保证纯 IPv4
                // Socket，物理网卡路由由系统 NECP + excludedRoutes 兜底。
                // local_address 必须带子网前缀，否则内核 netip.Prefix 解析失败
                if let la = outbounds[i]["local_address"] as? [String], !la.isEmpty {
                    outbounds[i]["local_address"] = la.map { normalizePrefixString($0) }
                } else if let la = outbounds[i]["local_address"] as? String, !la.isEmpty {
                    outbounds[i]["local_address"] = [normalizePrefixString(la)]
                }
                // 【APP21 任务3.1 / 任务3.2】go-lan-home 双重加固：
                // 1) local_address 完整保留全部合法 IPv4 CIDR（严禁再用 .first
                //    截断）：服务端专门分配的第 2 个地址（如 192.168.10.222/24）
                //    是访问同网段内网（飞牛 NAS 192.168.10.253）时必须使用的
                //    同网段源 IP，丢弃会导致跨网段源 IP 回包受阻；
                // 2) 隧道 MTU 保留用户配置（通常 1420），严禁压到 1280。
                if tag == "go-lan-home" {
                    // 【APP21 任务3.1】保留 local_address 数组中的所有合法
                    // IPv4 CIDR 地址（与官方 WireGuard 客户端 100% 一致：
                    // 访问 192.168.10.x 时内核按最长前缀匹配自动选用同网段
                    // 源 IP 192.168.10.222；访问 10.196.0.x 时选 10.196.0.2）。
                    // 掩码缺失补 /24；输入框截断的 /2 等非法小掩码（<8）自动
                    // 还原为 /24。
                    let rawLocal = outbounds[i]["local_address"]
                    var rawItems: [String] = []
                    if let arr = rawLocal as? [String] {
                        rawItems = arr
                    } else if let s = rawLocal as? String {
                        rawItems = [s]
                    }
                    var validAddrs: [String] = []
                    let allowedChars = Set("0123456789./")
                    for item in rawItems {
                        let parts = item.components(separatedBy: CharacterSet(charactersIn: ",; \r\n\t"))
                        for part in parts {
                            let clean = String(part.unicodeScalars.filter { allowedChars.contains(Character($0)) })
                            guard !clean.isEmpty else { continue }
                            let slashParts = clean.split(separator: "/", omittingEmptySubsequences: false)
                            let ipStr = String(slashParts[0])
                            var addr = in_addr()
                            let ptonRet = inet_pton(AF_INET, ipStr, &addr)
                            guard ptonRet == 1 else { continue }
                            var prefixBits = 24
                            if slashParts.count > 1, let p = Int(slashParts[1]), p >= 8 && p <= 32 {
                                prefixBits = p
                            }
                            let cidr = "\(ipStr)/\(prefixBits)"
                            if !validAddrs.contains(cidr) {
                                validAddrs.append(cidr)
                            }
                        }
                    }
                    if !validAddrs.isEmpty {
                        outbounds[i]["local_address"] = validAddrs
                    }
                    // 【APP25 任务2.1】go-lan-home 出站 MTU 强制锁定 1280：
                    // log6.txt 实证 1420 会向内网 Web 服务器宣告 MSS=1380，
                    // 满载 1420 字节回包 + 60 字节 WG 头 = 1480 字节，在
                    // 5G / PPPoE 链路上整包丢弃（RDP 小包 92ms 能通、Web
                    // 端口全部 3000ms 超时）。1280 → MSS=1240，全部回包
                    // ≤1280 字节，套 WG 头仅 1340 字节，100% 穿透。
                    outbounds[i]["mtu"] = 1280
                    // 【APP21 任务2】严禁再给 go-lan-home 注入 bind_interface：
                    // WireGuard UDP 握手/数据包由 iOS NECP 按当前活跃物理网卡
                    // 原生发出，5G 下或 Wi-Fi→5G 切换时绝不再报
                    // sendmsg: network is unreachable（本循环顶部已统一
                    // removeValue bind_interface / inet4_bind_address /
                    // routing_mark，此处仅作说明性兜底）。
                    outbounds[i].removeValue(forKey: "bind_interface")
                    outbounds[i].removeValue(forKey: "inet4_bind_address")
                    outbounds[i].removeValue(forKey: "routing_mark")
                }
                // iOS 关闭 IPv6 时双栈 UDP Socket 绑定 IPv4 网卡会被 EPERM 拒绝，
                // 强制 ipv4_only 保证 WireGuard 握手包可正常发出
                outbounds[i]["domain_strategy"] = "ipv4_only"
                // APP-6 任务3：WireGuard 密钥兜底自愈——历史脏数据（%3D /
                // 引号 / URL-safe / 损坏 PSK）自动修复为标准 44 位 Base64，
                // 无法通过 32 字节校验的 pre_shared_key 直接剔除，
                // 100% 永不再报 decode pre shared key ... illegal base64 data
                if let fixed = sanitizeWireGuardKey(outbounds[i]["private_key"]) {
                    outbounds[i]["private_key"] = fixed
                }
                if let fixed = sanitizeWireGuardKey(outbounds[i]["peer_public_key"]) {
                    outbounds[i]["peer_public_key"] = fixed
                }
                if outbounds[i]["pre_shared_key"] != nil {
                    if let fixed = sanitizeWireGuardKey(outbounds[i]["pre_shared_key"]) {
                        outbounds[i]["pre_shared_key"] = fixed
                    } else {
                        outbounds[i].removeValue(forKey: "pre_shared_key")
                    }
                }
                // 【APP6 任务2】peers 数组已在上方整体提升为顶层单节点并删除，
                // 此处不再有 peers 元素需要清洗。
                // APP-8 任务3：wireguard 出站在内核 post-start 阶段必须同步
                // 解析 server 域名，dns-direct 被 RST 会中断整个启动。
                // 预解析顶层 server 为 IP，零 DNS 瞬时启动。
                // 【APP-11B】先剔除 server 中的 \u2060 等隐形字符再判定/解析
                // （server 可能是域名，必须用 cleanVisibleASCII 而非 cleanCIDR）
                if let srv = outbounds[i]["server"] as? String {
                    let cleanedSrv = cleanVisibleASCII(srv)
                    if cleanedSrv != srv { outbounds[i]["server"] = cleanedSrv }
                    if !cleanedSrv.isEmpty, !isIPLiteral(cleanedSrv) {
                        if let ip = resolveHostToIP(cleanedSrv) {
                            outbounds[i]["server"] = ip
                        }
                    }
                }
            } else if proxyOutboundTypes.contains(t) {
                if !tag.isEmpty {
                    allRealProxyTags.append(tag)
                }
            }
        }

        let routeFinal = (root["route"] as? [String: Any])?["final"] as? String
        let mainProxyTag: String = {
            if let rf = routeFinal, !rf.isEmpty, rf != "direct", rf != "block" {
                return rf
            }
            return firstSelectorTag ?? "proxy"
        }()

        // 确保主 selector 包含全部真实代理节点（防止主 selector 节点列表只剩 10 个子分组节点）
        if !allRealProxyTags.isEmpty {
            var foundMainSelector = false
            for i in outbounds.indices {
                let t = (outbounds[i]["type"] as? String) ?? ""
                let tag = (outbounds[i]["tag"] as? String) ?? ""
                if t == "selector" && tag == mainProxyTag {
                    foundMainSelector = true
                    var existing = (outbounds[i]["outbounds"] as? [String]) ?? []
                    for pTag in allRealProxyTags where !existing.contains(pTag) {
                        existing.append(pTag)
                    }
                    outbounds[i]["outbounds"] = existing
                    if let def = outbounds[i]["default"] as? String,
                       (def == "direct" || !existing.contains(def)),
                       let firstReal = allRealProxyTags.first
                    {
                        outbounds[i]["default"] = firstReal
                    }
                }
            }
            if !foundMainSelector && !allRealProxyTags.contains(mainProxyTag) {
                var selObj: [String: Any] = [
                    "type": "selector",
                    "tag": mainProxyTag,
                    "outbounds": allRealProxyTags
                ]
                if let firstReal = allRealProxyTags.first {
                    selObj["default"] = firstReal
                }
                outbounds.insert(selObj, at: 0)
            }
        }

        if !hasDirectOutbound {
            // 【APP12 任务1.2】var→let：Swift 编译器警告"变量从未被修改"
            let directObj: [String: Any] = ["type": "direct", "tag": "direct", "domain_strategy": "ipv4_only"]
            outbounds.append(directObj)
        }
        if dnsOutboundTag == nil {
            outbounds.append(["type": "dns", "tag": "dns-out"])
            dnsOutboundTag = "dns-out"
        }
        if blockOutboundTag == nil {
            outbounds.append(["type": "block", "tag": "block"])
            blockOutboundTag = "block"
        }
        root["outbounds"] = outbounds

        // 【APP15 任务2】mixed-in 入站必须始终存在（Rust 端已始终注入，
        // 此处兜底历史版本生成的旧配置）：否则内网检测在 1ms 内就因
        // 127.0.0.1:2080 Connection refused 而报「本地代理端口未就绪」。
        var mixedInbounds = (root["inbounds"] as? [[String: Any]]) ?? []
        if !mixedInbounds.contains(where: { ($0["tag"] as? String) == "mixed-in" }) {
            mixedInbounds.append([
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 2080,
                "sniff": false
            ])
            root["inbounds"] = mixedInbounds
        }

        // 2.5 GO-AIM 4 路隔离探针兜底（APP-4 任务3.1）
        // Rust 端 config_builder 已注入探针入站（127.0.0.1:2083-2086）与
        // 选择组 GO-AIM-PROBE-0..3；此处确保扩展收到的配置即便由旧版后端
        // 生成也具备探针设施——Go AIM 真实探测引擎启动即依赖它们存在。
        // 仅存在真实代理节点时注入（空配置注入无意义）。
        if !allRealProxyTags.isEmpty {
            var probeInbounds = (root["inbounds"] as? [[String: Any]]) ?? []
            var inboundsChanged = false
            for slot in 0..<4 {
                let tag = "aim-probe-in-\(slot)"
                let port = 2083 + slot
                if !probeInbounds.contains(where: { ($0["tag"] as? String) == tag }) {
                    probeInbounds.append([
                        "type": "mixed",
                        "tag": tag,
                        "listen": "127.0.0.1",
                        "listen_port": port,
                        "sniff": false
                    ])
                    inboundsChanged = true
                }
            }
            if inboundsChanged {
                root["inbounds"] = probeInbounds
            }

            var probeOutbounds = (root["outbounds"] as? [[String: Any]]) ?? []
            for slot in 0..<4 {
                let tag = "GO-AIM-PROBE-\(slot)"
                if !probeOutbounds.contains(where: { ($0["tag"] as? String) == tag }) {
                    probeOutbounds.append([
                        "type": "selector",
                        "tag": tag,
                        "outbounds": allRealProxyTags
                    ])
                }
            }
            root["outbounds"] = probeOutbounds
        }

        // 3. 重构 DNS：
        //    - dns-remote 使用 ipv4_only（确保返回给 Safari 的全为 IPv4，100% 流量进入 utun）
        //    - dns-direct 使用 prefer_ipv4（确保蜂窝流量下解析 VLESS 节点域名时同时支持 IPv4 与 IPv6）
        //    - dns-remote 用 tcp://8.8.8.8：Cloudflare 官方安全策略禁止
        //      Worker 节点出站连接 1.1.1.1，代理 DNS 请求 100% 被边缘拒绝
        //    - rules 补齐直连/全局模式与国内域名分流：直连模式下 DNS
        //      也必须走 dns-direct（223.5.5.5），否则连百度都打不开
        //
        //    Go Lan（回家网络）：先从原配置中提取 dns-home 服务器与其解析规则，
        //    重建时原样保留——回家域名必须经隧道内家庭 DNS 解析
        // 【APP-9 任务3.1】同时保留 Go Cus 注入的自定义 DNS 规则
        // （domain_suffix → dns-local，如 [Host] 非阻断映射），防止
        // 去广告/改写模块的域名级 DNS 规则在扩展清洗时丢失。
        var preservedDnsServers: [[String: Any]] = []
        var preservedDnsRules: [[String: Any]] = []
        if let oldDns = root["dns"] as? [String: Any] {
            if let servers = oldDns["servers"] as? [[String: Any]] {
                for s in servers {
                    let tag = (s["tag"] as? String) ?? ""
                    let detour = (s["detour"] as? String) ?? ""
                    if tag == "dns-home" || detour == "go-lan-home" {
                        preservedDnsServers.append(s)
                    } else if tag == "dns-local" {
                        // 【APP19 任务3】内网反向 DNS 等规则引用 dns-local，
                        // 必须同步保留该服务器，否则 iOS 侧重建 DNS 后
                        // 规则指向不存在的 tag 会导致内核启动失败。
                        preservedDnsServers.append(s)
                    }
                }
            }
            if let oldRules = oldDns["rules"] as? [[String: Any]] {
                for r in oldRules {
                    let server = (r["server"] as? String) ?? ""
                    // 保留 Go Lan 家庭 DNS 规则
                    if server == "dns-home" {
                        preservedDnsRules.append(r)
                        continue
                    }
                    // 保留 Go Cus 自定义域名 DNS 规则（domain_suffix → dns-local），
                    // 但排除内置的 .cn 兜底与 geosite cn 规则（下方重建覆盖）
                    if server == "dns-local",
                       r["domain_suffix"] != nil,
                       r["geosite"] == nil {
                        let suffixes = (r["domain_suffix"] as? [String]) ?? []
                        let isDefaultCn = suffixes.count == 1 && suffixes[0] == ".cn"
                        if !isDefaultCn {
                            preservedDnsRules.append(r)
                        }
                    }
                }
            }
        }
        var dnsServers: [[String: Any]] = [
            [
                "tag": "dns-remote",
                "address": "tcp://8.8.8.8",
                "detour": mainProxyTag,
                "strategy": "ipv4_only"
            ],
            // 【APP-11B 任务3】dns-direct 锁定纯 UDP/TCP 53：
            // APP-11 的 DoT（tls://223.5.5.5:853）在部分运营商网络仍会被
            // SNI 嗅探拦截；且 erro-2.txt 显示 https://223.5.5.5/dns-query
            // 仍被阿里云 WAF 拦返回 403。dns-direct 直接用最经典的
            // `223.5.5.5`（UDP/TCP 53 + ipv4_only），彻底告别 403 与 EPERM。
            // direct 出站已强制 ipv4_only（见 sanitize 循环），UDP Socket
            // 走纯 AF_INET，不存在双栈被 NECP 拒绝的问题。
            [
                "tag": "dns-direct",
                "address": "223.5.5.5",
                "detour": "direct",
                "strategy": "ipv4_only"
            ],
            [
                "tag": "dns-direct-bak",
                "address": "223.5.5.5",
                "detour": "direct",
                "strategy": "ipv4_only"
            ]
        ]
        dnsServers.append(contentsOf: preservedDnsServers)
        // dns-home 规则必须排在最前（位于 outbound:any 兜底规则之前）
        var dnsRules: [[String: Any]] = preservedDnsRules
        dnsRules.append(contentsOf: [
            [
                // 【APP14 任务4】节点域名解析（内核出站侧发起）直接走 dns-direct
                // （223.5.5.5，UDP/TCP 53 + direct 出站）。dns-remote 是
                // tcp://8.8.8.8 且 detour=主代理，一旦主代理抖动/未锁定，
                // 就会出现文本(1) 里 `->8.8.8.8:53 read: connection reset by peer`
                // 的刷屏；改走国内直连 DNS 后与「解析节点域名」这一用途完全匹配。
                "outbound": "any",
                "server": "dns-direct"
            ],
            [
                // 【APP19 任务3】内网反向 / 局域网后缀 DNS 直连解析：
                // 「文件」App 挂载 SMB、AirPrint 打印机发现、WebDAV 等系统
                // 组件会频繁查询 *.in-addr.arpa / *.ip6.arpa / .lan / .local，
                // 若被送往 dns-remote（tcp://8.8.8.8）会等待数秒超时，
                // 表现为共享文件夹打开极慢或直接报错。
                "domain_suffix": [
                    ".in-addr.arpa", ".ip6.arpa", ".lan", ".local",
                    ".home", ".internal", ".localdomain"
                ],
                "server": "dns-direct"
            ],
            [
                "clash_mode": "direct",
                "server": "dns-direct"
            ],
            [
                "clash_mode": "global",
                "server": "dns-remote"
            ],
            [
                "geosite": ["cn", "private"],
                "server": "dns-direct"
            ]
        ])
        root["dns"] = [
            "servers": dnsServers,
            "rules": dnsRules,
            "final": "dns-remote",
            "strategy": "ipv4_only"
        ]

        // 4. 修正 route
        // 【APP14 任务2】彻底移除 route.default_interface 与 auto_detect_interface
        // 的手工干预：
        // - 不再写 default_interface = 物理网卡（手工指定网卡名在蜂窝/Wi-Fi
        //   切换瞬间极易指向已消失的接口，导致 network is unreachable）；
        // - auto_detect_interface 保持 false（关闭），让 sing-box 完全不做
        //   接口探测/绑定，与常规代理节点走同一条系统 NECP 默认路由。
        var route = (root["route"] as? [String: Any]) ?? [:]
        route["auto_detect_interface"] = false
        route.removeValue(forKey: "default_interface")
        route["final"] = mainProxyTag

        var rules = (route["rules"] as? [[String: Any]]) ?? []
        rules.removeAll { rule in
            let p = rule["protocol"]
            return (p as? String) == "dns" || ((p as? [String])?.contains("dns") == true) || (rule["action"] as? String) == "hijack-dns"
        }

        let finalDnsTag = dnsOutboundTag ?? "dns-out"
        let finalBlockTag = blockOutboundTag ?? "block"

        // Go Lan（回家网络）智能同网段防环回：
        // 本机 Wi-Fi IP（en*）落在回家网段内时，对应 ip_cidr 规则改走直连，
        // 避免设备在家时把家庭局域网流量再绕回家庭隧道形成回环。
        // 豁免：蜂窝（pdp_ip*）出口的 CGNAT 10.x 与常见局域网网段重叠，不参与判定。
        // 【APP-11B】先对 go-lan-home 规则的 ip_cidr 执行 cleanCIDR，物理剔除
        // 历史脏缓存中的 \u2060 等隐形字符，避免内核 ParsePrefix 崩溃。
        for i in rules.indices
        where (rules[i]["outbound"] as? String) == "go-lan-home" {
            if let cidrs = rules[i]["ip_cidr"] as? [String] {
                rules[i]["ip_cidr"] = cidrs.map { cleanCIDR($0) }.filter { !$0.isEmpty }
            }
        }
        if phyName.hasPrefix("en"), let localIP = localInterfaceIPv4(phyName) {
            for i in rules.indices {
                guard (rules[i]["outbound"] as? String) == "go-lan-home",
                      let cidrs = rules[i]["ip_cidr"] as? [String]
                else { continue }
                if cidrs.contains(where: { ipv4InCidr(localIP, $0) }) {
                    rules[i]["outbound"] = "direct"
                }
            }
        }

        // 【APP-9 任务2.1a 黄金优先级】提取 Go Lan 回家规则并提升到
        // headRules 之后、clash_mode / ip_is_private 之前——无论用户处于
        // 「规则」「全局」还是「直连」模式，回家流量永远 100% 走 go-lan-home
        // 隧道，绝不被 clash_mode: global 或 ip_is_private 抢先命中。
        var goLanRules: [[String: Any]] = []
        rules.removeAll { rule in
            if (rule["outbound"] as? String) == "go-lan-home" {
                goLanRules.append(rule)
                return true
            }
            return false
        }

        // 【APP19 任务2】把最终生效的回家网段落盘为 sidecar，
        // 供 openTun 构造带 gatewayAddress="172.19.0.1" 的 includedRoutes
        // （打通「文件」App SMB 挂载、打印机 cupsd 等系统守护进程）。
        // 注意：已因「本机 Wi-Fi 就在该网段」被改判直连的规则不会进入
        // goLanRules，因此不会注入多余的系统路由。
        var goLanCidrs: [String] = []
        for rule in goLanRules {
            guard let cidrs = rule["ip_cidr"] as? [String] else { continue }
            for cidr in cidrs where !goLanCidrs.contains(cidr) {
                goLanCidrs.append(cidr)
            }
        }
        let goLanSidecarURL = workDir.appendingPathComponent("golan_routes.json")
        if let sidecarData = try? JSONSerialization.data(withJSONObject: goLanCidrs) {
            try? sidecarData.write(to: goLanSidecarURL)
        }

        let headRules: [[String: Any]] = [
            ["protocol": ["dns"], "outbound": finalDnsTag],
            ["port": [53], "outbound": finalDnsTag],
            // 【APP11 任务4.1】DNS-over-TLS(853) 顶部拦截：系统在隧道就绪前
            // 尝试 DoT 直连 8.8.8.8:853 / 8.8.4.4:853 会反复 i/o timeout
            // 刷屏耗电；直接 block 853，逼使回退到标准 53 端口 DNS。
            ["port": [853], "outbound": finalBlockTag],
            // 【APP15 任务3.2】公共 DNS 的 DoH/DoT 端点拦截：紧跟 853 之后，
            // iOS 系统与部分 App 直连 8.8.8.8/8.8.4.4/1.1.1.1/1.0.0.1 的
            // 443/853 会绕过本地 DNS 劫持并反复超时刷屏。
            [
                "ip_cidr": ["8.8.8.8/32", "8.8.4.4/32", "1.1.1.1/32", "1.0.0.1/32"],
                "port": [443, 853],
                "outbound": finalBlockTag
            ],
            ["protocol": ["quic"], "outbound": finalBlockTag],
            ["network": ["udp"], "port": [443], "outbound": finalBlockTag]
        ]

        // GO-AIM 探针路由兜底（APP-4 任务3.1 + APP-9 任务4.1）：
        // inbound -> GO-AIM-PROBE-N 必须紧随 DNS 劫持头规则之后、
        // Go Lan 与 clash_mode 规则之前（inbound 匹配优先于模式规则，
        // 否则全局模式下探针流量被 GLOBAL 组吞掉）。
        // Rust 配置已携带这 4 条规则，此处仅防缺失。
        var aimProbeRules: [[String: Any]] = []
        if !allRealProxyTags.isEmpty {
            for slot in 0..<4 {
                let tag = "GO-AIM-PROBE-\(slot)"
                let exists = rules.contains { ($0["outbound"] as? String) == tag }
                if !exists {
                    aimProbeRules.append(["inbound": ["aim-probe-in-\(slot)"], "outbound": tag])
                }
            }
        }

        // 【APP19 任务3】黄金优先级顺序（自上而下）：
        // 1. GO-AIM 探针专用通道（inbound → GO-AIM-PROBE-N，仅匹配本地
        //    127.0.0.1:2083..2086 探针入站）
        // 2. Go Lan 回家内网无条件全通（ip_cidr → go-lan-home，无 port /
        //    network 限制）：必须排在 protocol dns、port 53、853、DoH、
        //    block_quic 与 clash_mode 全部之前，否则发往家里的
        //    HTTP/3(QUIC)、UDP 443、SMB 137/138/139/445、飞牛 8000/8001、
        //    打印机 515/631/9100 以及内网 DNS(53) 都会被提前拦截或劫持。
        // 3. DNS 劫持 / 853 与 DoH 拦截 / QUIC 拦截
        // 4. 私有地址直连（排除已被第 2 优先级命中的家庭网段）
        // 5. 运行模式（clash_mode direct/global）与自定义/订阅分流规则
        var finalHead = aimProbeRules
        finalHead.append(contentsOf: goLanRules)
        finalHead.append(contentsOf: headRules)
        finalHead.append(["ip_is_private": true, "outbound": "direct"])
        rules.insert(contentsOf: finalHead, at: 0)
        route["rules"] = rules

        if var geoip = route["geoip"] as? [String: Any], geoip["path"] != nil {
            geoip["path"] = workDir.appendingPathComponent("geoip.db").path
            route["geoip"] = geoip
        }
        if var geosite = route["geosite"] as? [String: Any], geosite["path"] != nil {
            geosite["path"] = workDir.appendingPathComponent("geosite.db").path
            route["geosite"] = geosite
        }
        if var ruleSets = route["rule_set"] as? [[String: Any]] {
            for i in ruleSets.indices {
                if (ruleSets[i]["type"] as? String) == "local",
                   let oldPath = ruleSets[i]["path"] as? String,
                   oldPath.contains("/Containers/Data/Application/")
                {
                    let fileName = (oldPath as NSString).lastPathComponent
                    let newPath = workDir.appendingPathComponent("rulesets").appendingPathComponent(fileName).path
                    ruleSets[i]["path"] = newPath
                }
            }
            route["rule_set"] = ruleSets
        }
        root["route"] = route

        // 5. 修正 experimental.cache_file / clash_api
        // 【APP15 任务2】clash_api 必须始终存在：内网检测的通道2（
        // `/proxies/go-lan-home/delay`）与前端实时数据都依赖它。
        var experimental = (root["experimental"] as? [String: Any]) ?? [:]
        var cacheFile = (experimental["cache_file"] as? [String: Any]) ?? [:]
        cacheFile.removeValue(forKey: "store_selected")
        cacheFile["enabled"] = false
        cacheFile["path"] = cacheDBURL.path
        experimental["cache_file"] = cacheFile

        var clashAPI = (experimental["clash_api"] as? [String: Any]) ?? [:]
        clashAPI.removeValue(forKey: "external_ui")
        clashAPI.removeValue(forKey: "external_ui_download_url")
        if (clashAPI["external_controller"] as? String ?? "").isEmpty {
            clashAPI["external_controller"] = "127.0.0.1:9090"
        }
        if (clashAPI["default_mode"] as? String ?? "").isEmpty {
            clashAPI["default_mode"] = "rule"
        }
        experimental["clash_api"] = clashAPI
        root["experimental"] = experimental

        // 6. 开启 box.log（warn 级别）：正常上网的每条连接不再同步写盘，
        // 消除高频磁盘 I/O 阻塞（info 级别会为每次路由匹配写一行）
        var logObj = (root["log"] as? [String: Any]) ?? [:]
        logObj["disabled"] = false
        logObj["level"] = "warn"
        logObj["output"] = workDir.appendingPathComponent("box.log").path
        root["log"] = logObj

        guard let newData = try? JSONSerialization.data(withJSONObject: root),
              let newText = String(data: newData, encoding: .utf8)
        else {
            return rawJSON
        }
        return newText
    }

    // MARK: - Go Lan 辅助：本机地址与网段判定

    /// 读取指定网卡（en0 / pdp_ip0）的 IPv4 地址
    private func localInterfaceIPv4(_ name: String) -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let p = ptr {
            let ifa = p.pointee
            ptr = ifa.ifa_next
            guard let addr = ifa.ifa_addr,
                  String(cString: ifa.ifa_name) == name,
                  addr.pointee.sa_family == UInt8(AF_INET)
            else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(addr, socklen_t(addr.pointee.sa_len), &host,
                                     socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            if result == 0 {
                let ip = String(cString: host)
                // 去掉可能的 zone 后缀（fe80::1%en0 形式仅 IPv6，稳妥起见仍做切分）
                return ip.split(separator: "%").first.map(String.init)
            }
        }
        return nil
    }

    /// 判断 IPv4 是否位于 CIDR 网段内
    private func ipv4InCidr(_ ip: String, _ cidr: String) -> Bool {
        let parts = cidr.split(separator: "/")
        guard parts.count == 2, let mask = Int(parts[1]) else { return false }
        func toU32(_ s: String) -> UInt32? {
            var result: UInt32 = 0
            var count = 0
            for octet in s.split(separator: ".") {
                guard let v = UInt32(octet), v <= 255, count < 4 else { return nil }
                result = (result << 8) | v
                count += 1
            }
            return count == 4 ? result : nil
        }
        guard let ipU = toU32(ip), let cidrU = toU32(String(parts[0])) else { return false }
        if mask <= 0 { return true }
        if mask >= 32 { return ipU == cidrU }
        let maskBits: UInt32 = ~UInt32(0) << (32 - UInt32(mask))
        return (ipU & maskBits) == (cidrU & maskBits)
    }

    private func copyGeoDatabases(to workDir: URL) throws {
        let mainAppBundleURL = Bundle.main.bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        for name in ["geoip.db", "geosite.db"] {
            let dst = workDir.appendingPathComponent(name)
            if FileManager.default.fileExists(atPath: dst.path) {
                continue
            }
            if let src = Bundle.main.url(forResource: name, withExtension: nil) {
                try? FileManager.default.copyItem(at: src, to: dst)
            } else {
                let fallbackSrc = mainAppBundleURL.appendingPathComponent(name)
                if FileManager.default.fileExists(atPath: fallbackSrc.path) {
                    try? FileManager.default.copyItem(at: fallbackSrc, to: dst)
                }
            }
        }
    }
}

// MARK: - 地址前缀解析

private struct Prefix {
    let address: String
    let prefix: Int
}

/// 【APP-11B 任务1.2】剔除 \u2060 等隐形零宽字符：仅保留 IP/CIDR 合法字符
/// （数字、hex 字母、`.`、`:`、`/`）。iOS 剪贴板从微信/网页复制时会在末尾
/// 塞入 U+2060 Word Joiner，trim 无法去除，会导致内核
/// `netip.ParsePrefix("10.195.0.2/32\u{2060}")` 报 bad bits after slash。
private func cleanCIDR(_ raw: String) -> String {
    let allowed = Set("0123456789abcdefABCDEF.:/")
    return String(raw.unicodeScalars.filter { allowed.contains(Character($0)) })
}

/// 【APP-11B】通用可见 ASCII 提纯：仅保留 0x21...0x7E，剔除空格、
/// \u2060、\u200B-\u200F、\uFEFF、换行等一切不可见/非 ASCII 字符。
/// 用于 server 域名等字段（cleanCIDR 仅适用 IP/CIDR，会误伤域名字母）。
private func cleanVisibleASCII(_ raw: String) -> String {
    String(raw.unicodeScalars.filter { $0.value >= 0x21 && $0.value <= 0x7E })
}

/// 【APP-11 任务1.1】给无前缀的地址补默认子网前缀（IPv4 → /24，IPv6 → /64），
/// 内核按 netip.Prefix 解析 local_address，缺前缀会直接失败。
/// 【APP-11B】先经 cleanCIDR 剔除隐形字符再补前缀。
private func normalizePrefixString(_ raw: String) -> String {
    let s = cleanCIDR(raw)
    if s.isEmpty { return "10.0.0.2/24" }
    if s.contains("/") { return s }
    return s.contains(":") ? "\(s)/64" : "\(s)/24"
}

private func parseCIDR(_ cidr: String) -> Prefix? {
    let parts = cidr.split(separator: "/")
    guard parts.count == 2,
          let prefix = Int(parts[1])
    else { return nil }
    return Prefix(address: String(parts[0]), prefix: prefix)
}

private func prefixes(_ raw: Any?) -> [Prefix] {
    if let dictArray = raw as? [[String: Any]] {
        return dictArray.compactMap { item in
            if let address = item["address"] as? String {
                if let prefix = (item["prefix"] as? NSNumber)?.intValue ?? (item["prefix"] as? Int) {
                    return Prefix(address: address, prefix: prefix)
                }
                if let parsed = parseCIDR(address) {
                    return parsed
                }
            }
            return nil
        }
    }
    if let strArray = raw as? [String] {
        return strArray.compactMap { parseCIDR($0) }
    }
    if let singleStr = raw as? String {
        if let parsed = parseCIDR(singleStr) {
            return [parsed]
        }
    }
    return []
}

private func subnetMask(prefix: Int) -> String {
    var mask = [UInt8](repeating: 0, count: 4)
    let bits = min(max(prefix, 0), 32)
    for i in 0..<bits {
        mask[i / 8] |= 0x80 >> (i % 8)
    }
    return mask.map { String($0) }.joined(separator: ".")
}

/// 【APP-12 任务1.3】IPv4 字符串转 UInt32（网络字节序），用于 /24 → 两个 /25
/// 最长前缀匹配路由拆分。解析失败返回 nil。
private func ipv4ToUInt32(_ s: String) -> UInt32? {
    let parts = s.split(separator: ".")
    guard parts.count == 4 else { return nil }
    var v: UInt32 = 0
    for p in parts {
        guard let b = UInt32(p), b <= 255 else { return nil }
        v = (v << 8) | b
    }
    return v
}

/// 【APP-12 任务1.3】UInt32（网络字节序）转 IPv4 字符串
private func uint32ToIPv4(_ v: UInt32) -> String? {
    let b0 = (v >> 24) & 0xFF
    let b1 = (v >> 16) & 0xFF
    let b2 = (v >> 8) & 0xFF
    let b3 = v & 0xFF
    return "\(b0).\(b1).\(b2).\(b3)"
}

// MARK: - Go C 回调（@_cdecl）

@_cdecl("prism_open_tun")
private func prismOpenTun(_ json: UnsafePointer<CChar>?) -> Int32 {
    guard let json = json, let provider = prismProviderRef else { return -1 }
    return provider.openTun(optionsJSON: String(cString: json))
}

@_cdecl("prism_protect_socket")
private func prismProtectSocket(_ fd: Int32) -> Int32 {
    // 【APP14 任务2】完全空操作：不再对任何 Socket 做 IP_BOUND_IF / IPV6_BOUND_IF
    // 强绑物理网卡。
    //
    // 实证（文本(1).txt）：5G 蜂窝下，wireguard-go 的 UDP Socket 被
    // setsockopt(IP_BOUND_IF, 索引=蜂窝网卡) 后，握手包以
    // `operation not permitted` / `network is unreachable` 收场；而 155 个
    // 常规代理节点（TCP）在同样代码路径下却全部正常，说明问题出在
    // 对 UDP 的强制网卡绑定本身，而非路由策略。
    //
    // 扩展进程自身发出的 Socket 天然由 iOS NECP 按当前活跃物理网卡
    // （pdp_ip0 / en0）路由，本函数保持空操作即可让 go-lan-home 的
    // WireGuard 与常规代理节点使用 100% 相同的底层 Socket 创建方式。
    // 函数签名保持 `-> Int32` 是因为 C 侧 prism_vpn_cbs 声明为
    // `int (*protect_socket)(int)`，改为 Void 会造成未定义行为。
    _ = fd
    return 0
}

@_cdecl("prism_under_extension")
private func prismUnderExtension() -> Int32 {
    return 1
}
