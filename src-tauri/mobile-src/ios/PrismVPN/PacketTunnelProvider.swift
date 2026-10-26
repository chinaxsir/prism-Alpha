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
    /// 仅供 excludedRoutes（如「允许局域网连接」回包路由）使用，
    /// 不再注入出站 inet4_bind_address（5G 蜂窝下引发 i/o timeout）。
    var ipv4: String = ""
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

        DispatchQueue.global(qos: .userInitiated).async {
            PrismVPNStop()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            completionHandler()
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) {
                exit(0)
            }
        }
    }

    // MARK: - OpenTun

    fileprivate func openTun(optionsJSON: String) -> Int32 {
        NSLog("[PrismVPN] openTun options: \(optionsJSON)")
        writeHeartbeat("openTun")
        // 【APP-13 任务6】物理网卡 IPv4 在 openTun 顶层解析并固定，
        // 供下方「允许局域网连接」回包路由使用。严禁在使用点再定义，
        // 避免出现 cannot find 'bindIPv4' in scope 的作用域错误。
        let activePhy = findActivePhysicalInterface()
        let bindIPv4: String = isValidIPv4Literal(activePhy.ipv4) ? activePhy.ipv4 : ""

        guard let data = optionsJSON.data(using: .utf8),
              let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else {
            lastOpenTunError = "optionsJSON 解析失败: \(optionsJSON.prefix(200))"
            writeHeartbeat("tunJsonErr")
            return -1
        }

        let rawMtu = (json["mtu"] as? NSNumber)?.int32Value ?? 1400
        let mtu: Int32 = (rawMtu >= 1280 && rawMtu <= 9000) ? rawMtu : 1400

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
        let v4Routes = prefixes(json["inet4_route_address"])
        if v4Routes.isEmpty {
            ipv4.includedRoutes = [NEIPv4Route.default()]
        } else {
            ipv4.includedRoutes = v4Routes.map {
                if $0.prefix <= 0 || $0.address == "0.0.0.0" {
                    return NEIPv4Route.default()
                }
                return NEIPv4Route(destinationAddress: $0.address, subnetMask: subnetMask(prefix: $0.prefix))
            }
        }
        // 【APP-11 任务1.2】Go Lan 路由与 Socket 加固：
        // 1) WireGuard 对端公网 IP 加入 excludedRoutes → 加密 UDP 由系统内核
        //    直接走物理网卡直出，绝不回环进 utun，彻底消除
        //    "listen outbound packet connection: operation not permitted"；
        // 2) 回家内网网段（go-lan-home 规则的 ip_cidr）显式加入 includedRoutes，
        //    强制系统把访问家庭内网 IP 的流量送入 utun 交给回家隧道，
        //    而不是走当前 Wi-Fi 本地局域网丢包。
        var excludedV4: [NEIPv4Route] = []
        var includedV4: [NEIPv4Route] = ipv4.includedRoutes ?? []
        if let outs = json["outbounds"] as? [[String: Any]] {
            for ob in outs
            where (ob["tag"] as? String) == "go-lan-home" && (ob["type"] as? String) == "wireguard" {
                if let srv = ob["server"] as? String, isIPLiteral(srv) {
                    excludedV4.append(
                        NEIPv4Route(destinationAddress: srv, subnetMask: "255.255.255.255")
                    )
                }
                if let peers = ob["peers"] as? [[String: Any]] {
                    for peer in peers {
                        if let srv = peer["server"] as? String, isIPLiteral(srv) {
                            excludedV4.append(
                                NEIPv4Route(destinationAddress: srv, subnetMask: "255.255.255.255")
                            )
                        }
                    }
                }
            }
        }
        if let rules = (json["route"] as? [String: Any])?["rules"] as? [[String: Any]] {
            for rule in rules where (rule["outbound"] as? String) == "go-lan-home" {
                for cidr in (rule["ip_cidr"] as? [String]) ?? [] {
                    guard let p = parseCIDR(cidr), !p.address.isEmpty else { continue }
                    let route = p.prefix <= 0
                        ? NEIPv4Route.default()
                        : NEIPv4Route(
                            destinationAddress: p.address,
                            subnetMask: subnetMask(prefix: p.prefix)
                        )
                    if !includedV4.contains(where: {
                        $0.destinationAddress == route.destinationAddress
                            && $0.destinationSubnetMask == route.destinationSubnetMask
                    }) {
                        includedV4.append(route)
                    }
                    // 【APP-12 任务1.3】最长前缀匹配：iOS 路由表中外网 Wi-Fi 的
                    // 本地 /24 路由优先级高于 TUN 的默认 0.0.0.0/0。把每个
                    // /24 回家网段拆为两个 /25（.0/25 与 .128/25，掩码
                    // 255.255.255.128），最长前缀匹配确保任何 Wi-Fi/蜂窝下
                    // 访问家里内网 IP 100% 进入 PrismVPN 隧道。
                    // 对 /24 及更宽前缀（/8 /16 等）做 +1 拆分。
                    if p.prefix > 0 && p.prefix < 32,
                       let base = ipv4ToUInt32(p.address) {
                        let halfBits: UInt32 = 1 << (31 - UInt32(p.prefix)) // 半个网段地址数
                        let firstAddr = base & ~(halfBits * 2 - 1) // 对齐到本网段起点
                        let secondAddr = firstAddr + halfBits
                        let halfMask = subnetMask(prefix: p.prefix + 1)
                        for halfAddr in [firstAddr, secondAddr] {
                            if let halfStr = uint32ToIPv4(halfAddr) {
                                let halfRoute = NEIPv4Route(
                                    destinationAddress: halfStr,
                                    subnetMask: halfMask
                                )
                                if !includedV4.contains(where: {
                                    $0.destinationAddress == halfRoute.destinationAddress
                                        && $0.destinationSubnetMask == halfRoute.destinationSubnetMask
                                }) {
                                    includedV4.append(halfRoute)
                                }
                            }
                        }
                    }
                }
            }
        }
        // 【APP-13 任务6】「允许局域网连接」回包闭环：
        // mixed 入站监听 0.0.0.0 后，局域网设备（192.168.x.x）连本机代理端口，
        // 其回包若被 utun 默认路由接管会发出不去，表现为「连上了但一直转圈」。
        // 把本机物理网卡所在 /24 加入 excludedRoutes，回包固定走物理网卡。
        let lanEnabled = ((json["inbounds"] as? [[String: Any]]) ?? []).contains {
            ($0["type"] as? String) == "mixed" && ($0["listen"] as? String) == "0.0.0.0"
        }
        if lanEnabled, !bindIPv4.isEmpty, let selfIp = ipv4ToUInt32(bindIPv4) {
            let lanMask: UInt32 = 0xFFFF_FF00
            if let net = uint32ToIPv4(selfIp & lanMask) {
                excludedV4.append(
                    NEIPv4Route(destinationAddress: net, subnetMask: "255.255.255.0")
                )
            }
        }

        // 直连 DNS 223.5.5.5 / 114.114.114.114 直出物理网卡（零 403 / 零 EPERM）
        excludedV4.append(
            NEIPv4Route(destinationAddress: "223.5.5.5", subnetMask: "255.255.255.255")
        )
        excludedV4.append(
            NEIPv4Route(destinationAddress: "114.114.114.114", subnetMask: "255.255.255.255")
        )
        if !excludedV4.isEmpty {
            ipv4.excludedRoutes = excludedV4
        }
        ipv4.includedRoutes = includedV4
        settings.ipv4Settings = ipv4

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
    private func resolveHostToIP(_ host: String) -> String? {
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
    ///   - phyName: 当前活跃物理网卡名（en0 / pdp_ip0），供
    ///     prism_protect_socket 动态设置 IP_BOUND_IF 使用
    ///   - phyIPv4: 该网卡的真实 IPv4，仅用于 excludedRoutes 回包路由，
    ///     不再注入出站 inet4_bind_address（IPA9 任务4.3）
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
                    inbounds[i]["auto_route"] = true
                    inbounds[i]["mtu"] = 1400
                    // mixed 栈：TCP 走系统原生栈、UDP 走 gvisor（sing-box 默认），
                    // 大幅提升大流量下载吞吐并降低单核 CPU 占用
                    inbounds[i]["stack"] = "mixed"
                    inbounds[i]["sniff"] = true
                    // 【APP-12 任务1.2】严禁 sniff_override_destination=true：
                    // 置 true 时访问家里内网 IP 会被嗅探把目标改写成 Host/SNI
                    // 域名，导致 ip_cidr → go-lan-home 规则匹配失败，流量
                    // 被错误发往海外代理节点。保留 sniff 仅用于协议识别。
                    inbounds[i]["sniff_override_destination"] = false
                    inbounds[i]["sniff_timeout"] = "100ms"
                    inbounds[i]["udp_timeout"] = "5m"
                }
            }
            root["inbounds"] = inbounds
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
        // 【IPA9 任务4.3】移除 bind_interface 与 inet4_bind_address：
        // 5G 蜂窝下写死物理网卡 IP（如 10.66.92.229）会导致
        // dial tcp 10.66.92.229:0->8.8.4.4:853: i/o timeout。
        // 物理网卡绑定统一由 prism_protect_socket(fd) 在 Socket 创建时
        // 动态设置 IP_BOUND_IF 完成，无需在配置 JSON 中写死。
        let bindIPv4 = isValidIPv4Literal(phyIPv4) ? phyIPv4 : ""
        func applyPhysicalBind(_ obj: inout [String: Any]) {
            // 仅保留 domain_strategy: ipv4_only 强制纯 IPv4 Socket，
            // 不再注入 bind_interface / inet4_bind_address
            _ = bindIPv4
            _ = phyName
        }
        for i in outbounds.indices {
            let t = (outbounds[i]["type"] as? String) ?? ""
            let tag = (outbounds[i]["tag"] as? String) ?? ""
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
                applyPhysicalBind(&outbounds[i])
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
                // 【IPA9 任务4.3】不再注入 inet4_bind_address（5G 蜂窝下引发
                // i/o timeout）；domain_strategy: ipv4_only 已保证纯 IPv4
                // Socket，物理网卡绑定由 prism_protect_socket 动态完成。
                // local_address 必须带子网前缀，否则内核 netip.Prefix 解析失败
                if let la = outbounds[i]["local_address"] as? [String], !la.isEmpty {
                    outbounds[i]["local_address"] = la.map { normalizePrefixString($0) }
                } else if let la = outbounds[i]["local_address"] as? String, !la.isEmpty {
                    outbounds[i]["local_address"] = [normalizePrefixString(la)]
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
                applyPhysicalBind(&outbounds[i])
            } else if proxyOutboundTypes.contains(t) {
                if !tag.isEmpty {
                    allRealProxyTags.append(tag)
                }
                applyPhysicalBind(&outbounds[i])
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
            var directObj: [String: Any] = ["type": "direct", "tag": "direct"]
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
                // 节点域名解析（内核出站侧发起）走备用 DNSPod，
                // 与国内域名解析的 AliDNS 主用互为主备
                "outbound": "any",
                "server": "dns-direct-bak"
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
        var route = (root["route"] as? [String: Any]) ?? [:]
        route["auto_detect_interface"] = false
        if !phyName.isEmpty {
            route["default_interface"] = phyName
        }
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

        let headRules: [[String: Any]] = [
            ["protocol": ["dns"], "outbound": finalDnsTag],
            ["port": [53], "outbound": finalDnsTag],
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

        // 黄金优先级顺序（自上而下）：
        // 1. DNS 劫持 + QUIC 拦截（headRules）
        // 2. GO-AIM 探针专用通道（inbound → GO-AIM-PROBE-N）
        // 3. Go Lan 回家内网直通（ip_cidr → go-lan-home，必须在 clash_mode 之前！）
        // 4. 私有地址直连（排除已被第 3 优先级命中的家庭网段）
        // 5. 运行模式（clash_mode direct/global）与自定义/订阅分流规则
        var finalHead = headRules
        finalHead.append(contentsOf: aimProbeRules)
        finalHead.append(contentsOf: goLanRules)
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

        // 5. 修正 experimental.cache_file
        if var experimental = root["experimental"] as? [String: Any] {
            if var cacheFile = experimental["cache_file"] as? [String: Any] {
                cacheFile.removeValue(forKey: "store_selected")
                cacheFile["enabled"] = false
                cacheFile["path"] = cacheDBURL.path
                experimental["cache_file"] = cacheFile
            }
            if var clashAPI = experimental["clash_api"] as? [String: Any] {
                clashAPI.removeValue(forKey: "external_ui")
                clashAPI.removeValue(forKey: "external_ui_download_url")
                experimental["clash_api"] = clashAPI
            }
            root["experimental"] = experimental
        }

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
    guard fd >= 0 else { return 0 }
    var idx = cachedPhysicalIfIndex
    if idx == 0 {
        idx = findActivePhysicalInterface().index
    }
    guard idx > 0 else { return 0 }

    let ipBoundIf: Int32 = 25    // IP_BOUND_IF
    let ipv6BoundIf: Int32 = 125 // IPV6_BOUND_IF

    // 【IPA9 任务4.2】区分 Socket 类型：
    // - TCP（SOCK_STREAM）走 connect()，IP_BOUND_IF 在 connect 前设置
    //   不会触发 EPERM，正常绑定物理网卡，防止代理流量回环进 VPN。
    // - UDP（SOCK_DGRAM）可能走 ListenPacket("udp", ":0") → bind(0.0.0.0:0)。
    //   iOS XNU 下对已设置 IP_BOUND_IF 的未绑定 Socket 调用 bind 会返回
    //   EPERM（listen outbound packet connection: operation not permitted），
    //   导致 WireGuard 握手包与 UDP DNS 全灭。因此 UDP Socket 一律跳过
    //   IP_BOUND_IF，改由 excludedRoutes 把 WireGuard 对端 / DNS 服务器
    //   路由到物理网卡直出。
    var sockType: Int32 = 0
    var typeLen = socklen_t(MemoryLayout<Int32>.size)
    guard getsockopt(fd, SOL_SOCKET, SO_TYPE, &sockType, &typeLen) == 0 else {
        return 0
    }
    let isUDP = sockType == SOCK_DGRAM

    var addr = sockaddr()
    var len = socklen_t(MemoryLayout<sockaddr>.size)
    if getsockname(fd, &addr, &len) == 0 {
        switch Int32(addr.sa_family) {
        case AF_INET:
            if !isUDP {
                _ = setsockopt(fd, IPPROTO_IP, ipBoundIf, &idx, socklen_t(MemoryLayout<UInt32>.size))
            }
        case AF_INET6:
            if !isUDP {
                _ = setsockopt(fd, IPPROTO_IPV6, ipv6BoundIf, &idx, socklen_t(MemoryLayout<UInt32>.size))
            }
        default:
            break
        }
        return 0
    }
    // getsockname 失败：仅 TCP 兜底绑定
    if !isUDP {
        if setsockopt(fd, IPPROTO_IP, ipBoundIf, &idx, socklen_t(MemoryLayout<UInt32>.size)) != 0 {
            _ = setsockopt(fd, IPPROTO_IPV6, ipv6BoundIf, &idx, socklen_t(MemoryLayout<UInt32>.size))
        }
    }
    return 0
}

@_cdecl("prism_under_extension")
private func prismUnderExtension() -> Int32 {
    return 1
}
