// Prism 主 App 侧隧道控制：Rust 经 C ABI（@_cdecl）调用，
// 通过 NETunnelProviderManager 启动/停止 PrismVPN 网络扩展。
// 内核（Go libbox）与 TUN 全部运行在扩展进程内。

import Foundation
import UIKit
import NetworkExtension
import Security
import Darwin

/// 扩展 Bundle ID：优先取 App 包 PlugIns 内【实际存在】的
/// packet-tunnel-provider appex 的真实 CFBundleIdentifier（防构建侧
/// ID 漂移导致 providerBundleIdentifier 与实际 appex 不一致）；
/// 取不到时回落 主 App Bundle ID + ".PrismVPN"
private let extensionBundleIdentifier: String = {
    let main = Bundle.main.bundleIdentifier ?? "com.prism.proxy"
    let derived = "\(main).PrismVPN"
    guard let actual = PrismTunnelController.discoverExtensionBundleID() else {
        NSLog("[PrismVPN] PlugIns 内未找到 appex, 回落推导 ID=\(derived)")
        return derived
    }
    if actual != derived {
        NSLog("[PrismVPN] appex 实际 ID=\(actual) 与推导 ID=\(derived) 不同, 采用实际 ID")
    }
    return actual
}()

/// App Group 共享容器 ID（与扩展端一致）
/// TrollStore 可签任意 entitlement，App Group 不需要 Apple 注册
private let prismAppGroupID = "group.com.prism.proxy"

private let managerServerTag = "Prism"

// MARK: - C ABI 入口（供 Rust 调用）

/// 【APP35 任务1】彻底禁用 iOS 摇晃撤销（Undo Typing / Undo Paste）系统弹窗。
/// UIApplication 状态必须在主线程修改，异步派发避免阻塞 Rust 调用线程。
private func disableShakeToEdit() {
    DispatchQueue.main.async {
        UIApplication.shared.applicationSupportsShakeToEdit = false
    }
}

@_cdecl("prism_ios_vpn_start")
func prismIosVpnStart(_ config: UnsafePointer<CChar>) -> Int32 {
    disableShakeToEdit()
    let configText = String(cString: config)

    // APP-5 任务2：启动前强制做一次覆盖升级检查（Rust setup 已调用过，
    // 此处兜底——指纹一致时是 O(1) 直接返回，不会重复杀进程）
    PrismTunnelController.handleUpgradeIfNeededOnLaunch()

    // 写到 App Group 共享容器，避开 NETunnelProviderManager
    // providerConfiguration 512KB 限制（用户配置 2.47MB）
    let configPath: String
    if let groupURL = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: prismAppGroupID
    ) {
        configPath = groupURL.appendingPathComponent("prism_config.json").path
        NSLog("[PrismVPN] App Group 可用: \(configPath)")
    } else {
        // 回落到主 App tmp（与扩展进程不共享，仅小配置场景可用）
        configPath = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("prism_config.json")
        NSLog("[PrismVPN] App Group 不可用, 回落 tmp: \(configPath) (扩展可能读不到)")
    }
    do {
        try configText.write(toFile: configPath, atomically: true, encoding: .utf8)
    } catch {
        NSLog("[PrismVPN] 写共享配置失败: \(error.localizedDescription)")
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("prism_vpn_start_error.txt")
        try? "写共享配置失败: \(error.localizedDescription)"
            .write(toFile: path, atomically: true, encoding: .utf8)
        return -1
    }

    // build 146 方案第 2 步：本地 .srs 规则集存放在主 App 私有沙盒
    //（Application Support/com.prism.proxy/rulesets/），扩展进程无
    // no-sandbox 读不到主 App 私有容器。启动前整目录拷入 App Group 的
    // prism_work/rulesets/，扩展侧清洗函数会把 local rule_set 路径
    // 重定向到该位置。无 rulesets 目录时跳过（防御性，正常订阅不涉及）
    if let appSupport = FileManager.default.urls(
        for: .applicationSupportDirectory, in: .userDomainMask
    ).first {
        let rulesetsSrc = appSupport.appendingPathComponent(
            "com.prism.proxy/rulesets", isDirectory: true)
        if FileManager.default.fileExists(atPath: rulesetsSrc.path),
           let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: prismAppGroupID)
        {
            let rulesetsDst = groupURL.appendingPathComponent(
                "prism_work/rulesets", isDirectory: true)
            try? FileManager.default.createDirectory(
                at: rulesetsDst, withIntermediateDirectories: true)
            if let files = try? FileManager.default.contentsOfDirectory(
                atPath: rulesetsSrc.path)
            {
                for file in files where file.hasSuffix(".srs") {
                    let dst = rulesetsDst.appendingPathComponent(file)
                    try? FileManager.default.removeItem(at: dst)
                    try? FileManager.default.copyItem(
                        at: rulesetsSrc.appendingPathComponent(file), to: dst)
                }
                NSLog("[PrismVPN] 已拷贝 \(files.count) 个本地规则集到共享目录")
            }
        }
    }

    let semaphore = DispatchSemaphore(value: 0)
    var result: Int32 = 0
    var errorDesc: String = ""

    PrismTunnelController.shared.start(configPath: configPath) { error in
        if let error = error {
            result = -1
            errorDesc = PrismTunnelController.describe(error: error)
        }
        semaphore.signal()
    }
    semaphore.wait()

    if result != 0 {
        // 把详细错误写入沙盒 tmp（与 Rust std::env::temp_dir() 同一路径，
        // iOS 沙盒内 /tmp 并不存在，必须用 NSTemporaryDirectory()）
        let buildId = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        let groupOk = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.prism.proxy") != nil
        let diag = PrismTunnelController.diagnosePackaging()
        let sig = PrismTunnelController.diagnoseAppexEntitlements()
        let preflight = PrismTunnelController.diagnoseAppexPreflight()
        // 检查 appex bundle seal 是否存在
        var sealOk = "未检查"
        if let pluginsURL = Bundle.main.builtInPlugInsURL,
           let entries = try? FileManager.default.contentsOfDirectory(atPath: pluginsURL.path),
           let appexName = entries.first(where: { $0.hasSuffix(".appex") })
        {
            let sealPath = pluginsURL.appendingPathComponent(appexName)
                .appendingPathComponent("_CodeSignature/CodeResources").path
            sealOk = FileManager.default.fileExists(atPath: sealPath) ? "有" : "无"
        }
        let staticCheck = PrismTunnelController.diagnoseAppexStaticCode()
        let devMode = PrismTunnelController.diagnoseDeveloperMode()
        let provisioning = PrismTunnelController.diagnoseProvisioning()
        let rtEnt = PrismTunnelController.runtimeEntitlementsSummary()
        let pkdReg = PrismTunnelController.diagnosePkdRegistration()
        let full = "\(errorDesc)\n[诊断] build=\(buildId) app=\(Bundle.main.bundleIdentifier ?? "?") ext=\(extensionBundleIdentifier) group=\(groupOk ? "OK" : "nil") managers=\(PrismTunnelController.lastManagerCount) seal=\(sealOk) rtEnt=\(rtEnt) pkd=\(pkdReg) rootHelper=\(PrismTunnelController.rootHelperResult) selfHelper=\(PrismTunnelController.selfHelperResult) hb=\(PrismTunnelController.diagnoseExtensionHeartbeat()) extErr=\(PrismTunnelController.diagnoseExtensionError()) crash=\(PrismTunnelController.latestExtensionCrashSummary()) box=\(PrismTunnelController.diagnoseBoxLog()) static=\(staticCheck) devMode=\(devMode) provisioning=\(provisioning) lsReg=\(PrismTunnelController.lsRegisterResult) lsAppWS=\(PrismTunnelController.lsAppWorkspaceResult) PlugIns: \(diag) ; appex签名: \(sig) ; appex预检: \(preflight)\n[提示] hb= 扩展心跳最后阶段（无=没进 startTunnel，start-gotPath/openTun/tun-ok=对应阶段）；extErr= 扩展写出的精确错误；crash= 最新 PrismVPN/Jetsam 崩溃报告头部。selfHelper= 随包 PrismHelper 以 root 执行的结果；rootHelper= TrollStore 官方 uicache（u0=成功）"
        let path = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("prism_vpn_start_error.txt")
        NSLog("[PrismVPN] 写错误详情到 \(path): \(full)")
        try? full.write(
            toFile: path,
            atomically: true,
            encoding: .utf8
        )
    }
    return result
}

@_cdecl("prism_ios_vpn_stop")
func prismIosVpnStop() {
    let semaphore = DispatchSemaphore(value: 0)
    PrismTunnelController.shared.stop { _ in
        semaphore.signal()
    }
    semaphore.wait()
}

/// Rust 状态轮询用（platform/ios.rs vpn_is_connected，build 157 用户方案）：
/// VPN 会话是否存活。系统可在任意时刻杀掉扩展/注销会话（系统设置关闭、
/// 其他 VPN 抢占、NESM 会话失效），Rust 侧据此把状态同步为 Stopped，
/// 避免 UI 永远显示"运行中"。连接中/已连接/重设中返回 1，其余 0
@_cdecl("prism_ios_vpn_is_connected")
func prismIosVpnIsConnected() -> Int32 {
    switch PrismTunnelController.shared.currentConnectionStatus {
    case .connected, .connecting, .reasserting:
        return 1
    default:
        return 0
    }
}

/// APP6 任务1：返回 App Group（group.com.prism.proxy）共享容器路径，
/// 供 Rust 侧运行日志系统读取扩展诊断日志（prism_error.txt /
/// prism_work/box.log / vpn_trace.log）。拿不到时返回 NULL。
/// 注意：Darwin.strdup 返回 UnsafeMutablePointer<CChar>!，与 C ABI 声明的
/// UnsafePointer<CChar>? 不是同一类型，Swift 不允许在 return 处隐式转换，
/// 必须显式构造（否则报 cannot convert return expression）。
@_cdecl("prism_ios_app_group_dir")
func prismIosAppGroupDir() -> UnsafePointer<CChar>? {
    guard let groupURL = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: prismAppGroupID
    ) else { return nil }
    guard let path = strdup(groupURL.path) else { return nil }
    return UnsafePointer(path)
}

/// Rust 启动内核时读取系统级真实连接起始时间戳（IPA-12）：
/// connectedDate 由系统守护进程 nesessionmanagerd 维护，不受 App 挂起、
/// 锁屏甚至主 App 重启影响。Rust 在内核进入 Running 时优先采用该值作为
/// startedAtMs，前端亮屏第一帧即可用 Date.now() 差值 0ms 瞬时同步时长。
/// 未连接/无法获取时返回 0（Rust 侧回退本地时钟）
@_cdecl("prism_ios_vpn_connected_timestamp")
func prismIosVpnConnectedTimestamp() -> Int64 {
    let status = PrismTunnelController.shared.currentConnectionStatus
    guard status == .connected || status == .reasserting,
          let connectedDate = PrismTunnelController.shared.vpnConnectedDate else {
        return 0
    }
    return Int64(connectedDate.timeIntervalSince1970 * 1000.0)
}

// MARK: - APP-5 任务2：覆盖升级启动自愈（C ABI 入口）

/// App 启动时由 Rust 调用：比对安装指纹，升级后首次启动时清理驻留的旧版
/// 扩展进程（否则系统里跑的仍是旧 appex，UI 会一直显示未连接而实际已在
/// 代理）。返回 1 = 本次为升级后首次启动且已执行清理。
@_cdecl("prism_ios_upgrade_selfheal")
func prismIosUpgradeSelfheal() -> Int32 {
    PrismTunnelController.handleUpgradeIfNeededOnLaunch() ? 1 : 0
}

/// 取走并清除「升级后待自动重启」标记（一次性）：Rust 在启动流程末尾据此
/// 自动重建隧道，用户升级后无需手动点连接。
@_cdecl("prism_ios_take_pending_restart")
func prismIosTakePendingRestart() -> Int32 {
    let defaults = UserDefaults.standard
    guard defaults.bool(forKey: PrismTunnelController.kPendingRestartKey) else {
        return 0
    }
    defaults.set(false, forKey: PrismTunnelController.kPendingRestartKey)
    return 1
}

// MARK: - Device ID（Keychain 持久化，绝不同步）

/// 返回堆分配的 UTF-8 C 字符串（Rust 侧负责 free）。
/// 内容为 64 字符小写 hex SHA-256 硬件指纹。
/// 铁律：Keychain 已存在则直接返回（向后兼容）；仅首次生成。
/// 必须设 kSecAttrSynchronizable = false（绝不能 iCloud 同步，
/// 否则用户换 Apple ID 设备会共享 device_id → 一解绑全解绑）。
@_cdecl("prism_ios_get_device_id")
func prismIosGetDeviceId() -> UnsafeMutablePointer<CChar>? {
    let account = "prism.device_id" as CFString

    // 1. 先查 Keychain
    if let existing = PrismKeychain.get(account: account) {
        return strdup(existing)
    }

    // 2. 首次生成：identifierForVendor + hostname → SHA-256 hex
    let vendor = UIDevice.current.identifierForVendor?.uuidString ?? "unknown-vendor"
    let hostname = ProcessInfo.processInfo.hostName
    let raw = "\(vendor)|\(hostname)"
    let hex = raw.sha256Hex()

    // 3. 写入 Keychain（kSecAttrSynchronizable = false 是核心）
    if PrismKeychain.set(account: account, value: hex) {
        return strdup(hex)
    }

    // 4. Keychain 写入失败（极罕见）：直接返回生成值，下次启动重试
    return strdup(hex)
}

// MARK: - 控制器

/// 【APP58 任务2.2】原生打开外链：WKWebView 内 `window.open(url, "_blank")`
/// 与 `<a target="_blank">` 会被系统静默丢弃，必须由 UIKit 在系统浏览器
/// （Safari / 默认浏览器）中打开，确保「关于帮助」链接点击 100% 生效。
@_cdecl("prism_ios_open_url")
func prismIosOpenUrl(_ urlCStr: UnsafePointer<CChar>?) -> Bool {
    guard let urlCStr = urlCStr else { return false }
    let urlString = String(cString: urlCStr).trimmingCharacters(in: .whitespacesAndNewlines)
    guard let url = URL(string: urlString) else { return false }
    DispatchQueue.main.async {
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
    return true
}

/// 【APP63 任务2.2】零闪退文本文件导出 / 分享：
/// 1. 先无条件写入系统剪贴板（100% 可靠保底）；
/// 2. 再写入 tmp 目录并**在主线程**安全唤起 UIActivityViewController，
///    且必须设置 popoverPresentationController.sourceView / sourceRect，
///    否则 iPad / 折叠屏会抛 NSGenericException 导致 APP 闪退。
/// 全程仅做字符串写入与主线程派发，绝不触碰 WebView 视图树。
@_cdecl("prism_ios_share_text_file")
func prismIosShareTextFile(
    _ filenameCStr: UnsafePointer<CChar>?,
    _ contentCStr: UnsafePointer<CChar>?
) -> Bool {
    guard let filenameCStr = filenameCStr, let contentCStr = contentCStr else { return false }
    let filename = String(cString: filenameCStr)
        .trimmingCharacters(in: .whitespacesAndNewlines)
    let content = String(cString: contentCStr)
    if filename.isEmpty || content.isEmpty { return false }

    DispatchQueue.main.async {
        // 1. 剪贴板兜底
        UIPasteboard.general.string = content

        // 2. 写临时文件
        let tempDir = FileManager.default.temporaryDirectory
        let fileURL = tempDir.appendingPathComponent(filename)
        do {
            try content.write(to: fileURL, atomically: true, encoding: .utf8)
        } catch {
            NSLog("[PrismVPN] 写导出日志失败: \(error.localizedDescription)")
            return
        }

        // 3. 定位最顶层控制器
        guard let scene = UIApplication.shared.connectedScenes
            .first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene
            ?? UIApplication.shared.connectedScenes.first as? UIWindowScene,
            let rootVC = scene.windows.first(where: { $0.isKeyWindow })?.rootViewController
                ?? scene.windows.first?.rootViewController else {
            return
        }
        var topVC = rootVC
        while let presented = topVC.presentedViewController {
            topVC = presented
        }
        // 已有分享面板时绝不重复弹出
        if topVC is UIActivityViewController { return }

        let activityVC = UIActivityViewController(
            activityItems: [fileURL], applicationActivities: nil)
        if let popover = activityVC.popoverPresentationController {
            popover.sourceView = topVC.view
            popover.sourceRect = CGRect(
                x: topVC.view.bounds.midX,
                y: topVC.view.bounds.maxY - 60,
                width: 1, height: 1)
            popover.permittedArrowDirections = []
        }
        topVC.present(activityVC, animated: true, completion: nil)
    }
    return true
}

final class PrismTunnelController {
    static let shared = PrismTunnelController()

    // 【APP24 / APP28 任务1】本控制器 100% 只负责 NETunnelProviderManager VPN
    // 隧道控制，严禁触碰任何 UIWindow / UIView / UIScrollView / WKWebView 属性：
    // 递归遍历视图树给 WKCompositingView / WKContentView 刷底色会导致
    // 切换 App 时整屏黑屏且无法触摸（APP26 曾加回，APP28 已彻底移除）。
    private init() {}

    /// 最近一次 loadAllFromPreferences 可见的配置数。诊断用：
    /// 若系统设置里存在旧 Prism 条目而此处为 0，说明该条目属于
    /// 旧签名身份，App 内 API 不可见/不可删，必须去系统设置手动删除
    static var lastManagerCount = -1

    /// 连接成功后的长期断开监听（installDisconnectWatcher 安装/拆除）
    private var disconnectWatcher: NSObjectProtocol?

    /// 最近一次成功发起连接的 manager：看门狗判死后经它强制
    /// stopVPNTunnel 重置系统 VPN 状态（IPA.txt 主 App 端方案）
    private var activeManager: NETunnelProviderManager?

    /// 本次 start() 的真实配置路径：Code=12 自愈重试可能从 reload/
    /// 连接超时等拿不到 configPath（空串）的失败点发起，重建
    /// providerConfiguration 时必须用它
    private var lastStartConfigPath: String = ""

    /// 当前 VPN 连接状态（Rust 经 C ABI prism_ios_vpn_is_connected 轮询，
    /// build 157）：activeManager 未启动时视为 invalid
    /// 【APP43 任务2.1】主 APP 被划掉后重开，系统隧道可能仍在运行而
    /// activeManager 还是 nil（只有 start() 才会赋值）。这里先同步补拉
    /// 一次系统配置，保证 Rust 第一次轮询就能拿到真实状态。
    var currentConnectionStatus: NEVPNStatus {
        if activeManager == nil {
            syncExistingManagerIfNeeded()
        }
        return activeManager?.connection.status ?? .invalid
    }

    /// 【APP43 任务2.1】同步补拉系统里已存在的 Prism VPN 配置（最多等 400ms）。
    /// - 找到已连接/连接中的 manager 立即缓存为 activeManager，供状态轮询
    ///   与 connectedDate 读取；
    /// - 主线程禁止阻塞等待（loadAllFromPreferences 回调可能与主线程互锁），
    ///   直接返回，稍后的轮询会再次尝试；
    /// - recovering 标志防止并发重入导致连续多次 load。
    private var recoveringManager = false
    /// 回调跨线程写入的持有盒（避免 Swift 并发检查报「捕获变量被并发修改」）
    private final class ManagerBox {
        var manager: NETunnelProviderManager?
    }
    private func syncExistingManagerIfNeeded() {
        if activeManager != nil || recoveringManager || Thread.isMainThread {
            return
        }
        recoveringManager = true
        let semaphore = DispatchSemaphore(value: 0)
        let box = ManagerBox()
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                NSLog("[PrismVPN] 冷启动 loadAllFromPreferences 失败: \(PrismTunnelController.describe(error: error))")
            }
            let expectedExtID = "com.prism.proxy.PrismVPN"
            box.manager = (managers ?? []).first { manager in
                (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == expectedExtID
            }
            semaphore.signal()
        }
        _ = semaphore.wait(timeout: .now() + .milliseconds(400))
        recoveringManager = false
        guard let manager = box.manager else { return }
        activeManager = manager
        NSLog("[PrismVPN] 冷启动检测到系统 VPN 配置，状态=\(manager.connection.status.rawValue)，已缓存 manager")
    }

    /// 系统级连接起始时间（IPA-12）：NEVPNConnection.connectedDate 由
    /// nesessionmanagerd 维护，供 prism_ios_vpn_connected_timestamp 导出
    var vpnConnectedDate: Date? {
        activeManager?.connection.connectedDate
    }

    /// 巨魔看门狗定时器：连接成功后每 4s 轮询扩展心跳，
    /// 扩展被 Jetsam 静默强杀且系统丢弃断开通知时兜底判死
    private var vpnWatchdogTimer: Timer?

    /// 非预期断开回调（看门狗判死时触发；Swift→Rust 暂无回调通道，
    /// 断开原因同时写入 App Group prism_error.txt 供诊断与下次启动回显）
    var onVpnUnexpectedDisconnect: ((String) -> Void)?

    /// 内核报错脱敏：用户可见错误文本统一抹除内核商标字样（不区分大小写）
    static func sanitizeKernelError(_ message: String) -> String {
        message
            .replacingOccurrences(of: "sing-box", with: "内核", options: .caseInsensitive)
            .replacingOccurrences(of: "singbox", with: "内核", options: .caseInsensitive)
            .replacingOccurrences(of: "libbox", with: "内核", options: .caseInsensitive)
    }

    /// 把 NSError 完整描述（domain/code/userInfo）输出，便于真机定位
    static func describe(error: Error) -> String {
        let ns = error as NSError
        let userInfo = ns.userInfo.map { (k, v) -> String in
            "\(k)=\(v)"
        }.joined(separator: "; ")
        return sanitizeKernelError(
            "domain=\(ns.domain) code=\(ns.code) desc=\(ns.localizedDescription) userInfo={\(userInfo)}"
        )
    }

    // MARK: - 扩展心跳/错误/崩溃诊断（build 145 方案）

    /// 扩展共享文件读取目录（与扩展多路写入对应）：App Group 容器、
    /// 主 App configPath 所在目录（同一位置，二者取其一即可）、
    /// 用户 Preferences（扩展无沙盒时的最后兜底）
    private static func extensionSharedDirs() -> [URL] {
        var urls: [URL] = []
        if let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: "group.com.prism.proxy"
        ) {
            urls.append(groupURL)
        }
        urls.append(URL(fileURLWithPath: "/private/var/mobile/Library/Preferences"))
        return urls
    }

    /// 【APP16 任务3】最新文本文件候选：用结构体替代命名元组，
    /// 严禁命名元组类型声明与强制类型转换。
    private struct LatestTextFile {
        let text: String
        let mtime: Date
    }

    /// 【APP16 任务3】最新崩溃日志候选：用结构体替代命名元组。
    private struct LatestLogFile {
        let path: String
        let mtime: Date
    }

    /// 读取扩展心跳 prism_status.txt 的最后阶段（多目录取最新）。
    /// hb=无 → 扩展没进入 startTunnel()（main() 前崩溃/Jetsam）；
    /// hb=start-gotPath/openTun/tun-ok → 精确定位卡死阶段
    static func diagnoseExtensionHeartbeat() -> String {
        let fm = FileManager.default
        var best: LatestTextFile?
        for dir in extensionSharedDirs() {
            let path = dir.appendingPathComponent("prism_status.txt").path
            guard let text = try? String(contentsOfFile: path, encoding: .utf8),
                  let attrs = try? fm.attributesOfItem(atPath: path),
                  let mtime = attrs[.modificationDate] as? Date
            else { continue }
            if best == nil || mtime > (best?.mtime ?? Date.distantPast) {
                best = LatestTextFile(text: text, mtime: mtime)
            }
        }
        guard let best = best else { return "无" }
        let age = Int(Date().timeIntervalSince(best.mtime))
        return "\(best.text) (距今\(age)s)".replacingOccurrences(of: "\n", with: " ")
    }

    /// 读取扩展写出的精确错误 prism_error.txt（多目录取最新）
    static func diagnoseExtensionError() -> String {
        let fm = FileManager.default
        var best: LatestTextFile?
        for dir in extensionSharedDirs() {
            let path = dir.appendingPathComponent("prism_error.txt").path
            guard let text = try? String(contentsOfFile: path, encoding: .utf8), !text.isEmpty,
                  let attrs = try? fm.attributesOfItem(atPath: path),
                  let mtime = attrs[.modificationDate] as? Date
            else { continue }
            if best == nil || mtime > (best?.mtime ?? Date.distantPast) {
                best = LatestTextFile(text: text, mtime: mtime)
            }
        }
        guard let best = best else { return "无" }
        return best.text.prefix(200).replacingOccurrences(of: "\n", with: " ")
    }

    /// 读取系统 CrashReporter 下最新的 PrismVPN 崩溃报告或 Jetsam 报告
    /// （主 App 持 no-sandbox 可直接读；扩展被 SIGKILL 时唯一的一手证据）
    static func latestExtensionCrashSummary() -> String {
        let dirs = [
            "/private/var/mobile/Library/Logs/CrashReporter",
            "/private/var/mobile/Library/Logs/CrashReporter/Retired"
        ]
        let fm = FileManager.default
        var latestFile: LatestLogFile?
        for dir in dirs {
            guard let items = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for item in items where item.contains("PrismVPN") || item.contains("JetsamEvent") {
                let full = "\(dir)/\(item)"
                guard let attrs = try? fm.attributesOfItem(atPath: full),
                      let mtime = attrs[.modificationDate] as? Date
                else { continue }
                if latestFile == nil || mtime > (latestFile?.mtime ?? Date.distantPast) {
                    latestFile = LatestLogFile(path: full, mtime: mtime)
                }
            }
        }
        guard let file = latestFile else { return "无crash日志" }
        guard let content = try? String(contentsOfFile: file.path, encoding: .utf8) else {
            return "不可读:\((file.path as NSString).lastPathComponent)"
        }
        let name = (file.path as NSString).lastPathComponent
        // 截取前 400 字符（含 bug_type / exception / termination / dyld 错误详情）
        let head = String(content.prefix(400)).replacingOccurrences(of: "\n", with: " ")
        return "\(name):\(head)"
    }

    /// 读取扩展 prism_work/box.log 的末尾（sing-box 一手日志：出站绑定、
    /// DNS、握手失败都会写这里；主 App 持 no-sandbox 直接读共享目录）
    static func diagnoseBoxLog() -> String {
        let fm = FileManager.default
        var best: LatestTextFile?
        for dir in extensionSharedDirs() {
            let path = dir.appendingPathComponent("prism_work/box.log").path
            guard let text = try? String(contentsOfFile: path, encoding: .utf8),
                  let attrs = try? fm.attributesOfItem(atPath: path),
                  let mtime = attrs[.modificationDate] as? Date
            else { continue }
            if best == nil || mtime > (best?.mtime ?? Date.distantPast) {
                best = LatestTextFile(text: text, mtime: mtime)
            }
        }
        guard let best = best else { return "无" }
        // build 157 用户方案：拼入启动后的前 50 行（启动期错误都在开头，
        // 后 8 行通常是 traffic 心跳刷屏）
        let lines = best.text.split(separator: "\n").prefix(50)
        guard !lines.isEmpty else { return "空" }
        return lines.joined(separator: " | ")
    }

    /// 遍历 App 包 PlugIns 下的 .appex，返回声明了 packet-tunnel
    /// 扩展点的那个的真实 CFBundleIdentifier；找不到返回 nil。
    /// 注意扩展点标识是 packet-tunnel（无 -provider 后缀，WireGuard
    /// 官方同款）；-provider 是 entitlements 数组值，两者易混淆。
    static func discoverExtensionBundleID() -> String? {
        guard let pluginsURL = Bundle.main.builtInPlugInsURL,
              let entries = try? FileManager.default.contentsOfDirectory(
                atPath: pluginsURL.path)
        else { return nil }
        for entry in entries.sorted() where entry.hasSuffix(".appex") {
            guard let bundle = Bundle(url: pluginsURL.appendingPathComponent(entry)),
                  let info = bundle.infoDictionary
            else { continue }
            let point = (info["NSExtension"] as? [String: Any])?["NSExtensionPointIdentifier"] as? String
            if point == "com.apple.networkextension.packet-tunnel",
               let bid = info["CFBundleIdentifier"] as? String, !bid.isEmpty {
                return bid
            }
        }
        return nil
    }

    /// 对 appex 做不加载、不启动扩展的完整性预检。
    /// 两条系统级路径在 iOS 上都不可用：
    /// - Bundle 没有 preflightCheck 方法（编译错误）
    /// - SecStaticCode/SecCode 系列是 macOS-only SPI，iOS 上即便
    ///   import Security 也「cannot find type SecStaticCode in scope」
    /// 因此这里只做文件级预检：bundle 可定位、Info.plist 扩展点正确、
    /// 可执行文件存在且 Mach-O 魔数合法。签名与 entitlements 的深度
    /// 诊断（手动解析 CS Superblob）见 diagnoseAppexEntitlements。
    static func diagnoseAppexPreflight() -> String {
        guard let pluginsURL = Bundle.main.builtInPlugInsURL,
              let entries = try? FileManager.default.contentsOfDirectory(
                atPath: pluginsURL.path),
              let appexName = entries.first(where: { $0.hasSuffix(".appex") }),
              let bundle = Bundle(url: pluginsURL.appendingPathComponent(appexName))
        else { return "appex bundle 不可定位" }

        guard let info = bundle.infoDictionary,
              let ext = info["NSExtension"] as? [String: Any],
              let point = ext["NSExtensionPointIdentifier"] as? String,
              point == "com.apple.networkextension.packet-tunnel"
        else { return "Info.plist 扩展点声明缺失或错误" }

        guard let execURL = bundle.executableURL,
              let data = try? Data(contentsOf: execURL),
              data.count >= 4
        else { return "可执行文件缺失或不可读" }

        // Mach-O 魔数（arm64 thin 为小端 0xFEEDFACF；同时兼容大端变体
        // 与 FAT/通用二进制 0xCAFEBABE）
        let magic = data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }
        let valid: Set<UInt32> = [
            0xfeedfacf, 0xcffaedfe, // MH_MAGIC_64
            0xfeedface, 0xcefaedfe, // MH_MAGIC
            0xbebafeca, 0xcafebabe, // FAT 32
            0xbfbafeca, 0xcafebabf, // FAT 64
        ]
        guard valid.contains(magic) else {
            return String(format: "可执行文件 Mach-O 魔数非法: 0x%08x", magic)
        }
        return "ok"
    }

    /// 解析 appex 可执行文件内嵌代码签名（CS Superblob），报告
    /// legacy entitlements（槽位5）与 DER entitlements（槽位7）是否存在
    /// 及关键键值。用于确认 TrollStore 重签后扩展权限是否真实存活：
    /// nesessionmanager 解析 provider 时校验这些，缺失即报 code=14。
    ///
    /// 字节序注意（曾因此误报）：Mach-O 头与 Load Command 是小端序；
    /// 代码签名 Superblob 内部是大端（网络）序；FAT 头是大端序。
    static func diagnoseAppexEntitlements() -> String {
        guard let pluginsURL = Bundle.main.builtInPlugInsURL,
              let entries = try? FileManager.default.contentsOfDirectory(
                atPath: pluginsURL.path),
              let appexName = entries.first(where: { $0.hasSuffix(".appex") }),
              let bundle = Bundle(url: pluginsURL.appendingPathComponent(appexName)),
              let execURL = bundle.executableURL,
              let data = try? Data(contentsOf: execURL)
        else { return "无法读取 appex 可执行文件" }

        func u8(_ off: Int) -> Int {
            guard off >= 0, off < data.count else { return 0 }
            return Int(data[data.index(data.startIndex, offsetBy: off)])
        }
        func le32(_ off: Int) -> Int {
            u8(off) | (u8(off + 1) << 8) | (u8(off + 2) << 16) | (u8(off + 3) << 24)
        }
        func be32(_ off: Int) -> Int {
            (u8(off) << 24) | (u8(off + 1) << 16) | (u8(off + 2) << 8) | u8(off + 3)
        }

        // 定位 Mach-O slice：FAT(大端 ca fe ba be/bf) 或 thin(小端 cf fa ed fe)
        var base = 0
        if u8(0) == 0xcf, u8(1) == 0xfa, u8(2) == 0xed, u8(3) == 0xfe {
            base = 0  // MH_MAGIC_64 thin
        } else if u8(0) == 0xca, u8(1) == 0xfe,
                  (u8(2) == 0xba && (u8(3) == 0xbe || u8(3) == 0xbf)) {
            // FAT_MAGIC / FAT_MAGIC_64：找 arm64(0x0100000c) slice
            let nfat = be32(4)
            var found = -1
            for i in 0..<min(nfat, 16) {
                let aoff = 8 + i * 20
                if be32(aoff) == 0x0100000c { found = be32(aoff + 8) }  // arch.offset
            }
            guard found > 0 else { return "FAT 内无 arm64 slice" }
            base = found
        } else {
            return "非 arm64 Mach-O (magic=\(String(format: "%02x%02x%02x%02x", u8(0), u8(1), u8(2), u8(3)))"
        }

        guard u8(base) == 0xcf, u8(base + 1) == 0xfa,
              u8(base + 2) == 0xed, u8(base + 3) == 0xfe else {
            return "slice magic 异常"
        }
        let ncmds = le32(base + 16)
        var off = base + 32
        var sigFileOff = -1
        for _ in 0..<min(ncmds, 256) {
            let cmd = le32(off)
            let size = le32(off + 4)
            if cmd == 0x1d { sigFileOff = le32(off + 8) }  // LC_CODE_SIGNATURE.dataoff
            if size <= 0 { break }
            off += size
        }
        guard sigFileOff > 0, sigFileOff < data.count,
              be32(sigFileOff) == 0xfade0cc0 else {
            return "无内嵌代码签名(LC_CODE_SIGNATURE 不可用)"
        }

        let count = min(be32(sigFileOff + 8), 32)
        var entPlist = ""
        var derFound = false
        for i in 0..<count {
            let slot = be32(sigFileOff + 12 + i * 8)
            let blobOff = sigFileOff + be32(sigFileOff + 12 + i * 8 + 4)
            if slot == 5, be32(blobOff) == 0xfade7171 {  // CSMAGIC_EMBEDDED_ENTITLEMENTS
                let len = be32(blobOff + 4)
                if len > 8, blobOff + len <= data.count {
                    let lo = data.index(data.startIndex, offsetBy: blobOff + 8)
                    let hi = data.index(data.startIndex, offsetBy: blobOff + len)
                    entPlist = String(decoding: data[lo..<hi], as: UTF8.self)
                }
            } else if slot == 7 {
                derFound = true
            }
        }

        if entPlist.isEmpty {
            return "legacy entitlements 槽位缺失! der=\(derFound ? "有" : "无")"
        }
        let appID = entPlist.contains("TROLLTROLL.com.prism.proxy.PrismVPN") ? "ok" : "异常"
        let ne = entPlist.contains("packet-tunnel-provider") ? "ok" : "缺"
        let group = entPlist.contains("group.com.prism.proxy") ? "ok" : "缺"
        return "appID=\(appID) ne=\(ne) group=\(group) der=\(derFound ? "有" : "无")"
    }

    /// 用系统 Security 框架的【私有但在 iOS 真实导出】的 SecStaticCode API，
    /// 对 appex【整个 bundle 目录】做不启动扩展的静态校验。这与 pkd /
    /// pluginkit 注册扩展时所做的校验是同一套代码，因此能给出真机上的
    /// 权威结论：
    /// 输出四段区分根因：
    ///   bnd=整包校验（pkd 注册同款）；bin=直接校验二进制文件；
    ///   exe=安装后 CFBundleExecutable 实际值/文件是否存在；
    ///   app=阳性对照：主 App 二进制同款校验。
    ///   bin=valid 而 bnd=invalid → bundle 结构问题（exe 键/seal）；
    ///   两者都 invalid 且 app=valid → appex 二进制签名被安装管线破坏；
    ///   app 与 appex 同错 → 该校验根本不认 ChOma bypass 签名，
    ///   static= 整段是噪声，Code 14 根因在注册层（开发者模式 /
    ///   pkd 未注册）而非签名，应立即转向注册层排查。
    /// 这些符号不在公开 SDK 头里（Swift 直接写会"cannot find"），但
    /// TrollStore 自己（Shared/TSUtil.m）就在设备上直接链接使用它们，
    /// 故运行时 dlsym 一定能取到。
    static func diagnoseAppexStaticCode() -> String {
        guard let pluginsURL = Bundle.main.builtInPlugInsURL,
              let entries = try? FileManager.default.contentsOfDirectory(
                atPath: pluginsURL.path),
              let appexName = entries.first(where: { $0.hasSuffix(".appex") })
        else { return "appex未定位" }
        let appexURL = pluginsURL.appendingPathComponent(appexName)

        // 读取安装后 Info.plist 的 CFBundleExecutable 实际值并核对文件存在。
        // 若该键与实际二进制名不匹配，SecStaticCode 对 bundle 会解析不到
        // 主二进制而误报"未签名"（-67061），这是必须排除的结构问题。
        // 【109 实测教训】NSDictionary(contentsOf:) 传【目录】URL 恒返回 nil
        //（设备上 exe 恒报"plist读取失败"、bin 校验从未执行）。改用
        // Bundle(url:) 解析 —— 该路径已在真机上被预检/签名诊断验证可用。
        var exeInfo = "exe=appex bundle解析失败"
        var execURL: URL?
        if let bundle = Bundle(url: appexURL),
           let exeName = bundle.infoDictionary?["CFBundleExecutable"] as? String,
           let url = bundle.executableURL {
            let exists = FileManager.default.fileExists(atPath: url.path)
            exeInfo = "exe=\(exeName)/\(exists ? "ok" : "缺失")"
            if exists { execURL = url }
        }

        guard let sec = dlopen(
            "/System/Library/Frameworks/Security.framework/Security", 1
        ) else { return "Security dlopen失败" }

        guard let createP = dlsym(sec, "SecStaticCodeCreateWithPathAndAttributes"),
              let checkErrP = dlsym(sec, "SecStaticCodeCheckValidityWithErrors"),
              let infoP = dlsym(sec, "SecCodeCopySigningInformation")
        else { return "SecStaticCode符号未找到" }

        // 精确 ABI：OSStatus 即 Int32。CF 对象参数统一 CFTypeRef?/OpaquePointer。
        // 只用 CheckValidityWithErrors（带 CFError 输出），它已验证能给出
        // 真实结论（如 -67061 unsigned），不再用 ABI 敏感的 CheckValidity。
        typealias CreateFn = @convention(c) (
            CFURL, UInt32, CFTypeRef?,
            UnsafeMutablePointer<CFTypeRef?>
        ) -> OSStatus
        typealias CheckErrFn = @convention(c) (
            OpaquePointer, UInt32, OpaquePointer?,
            UnsafeMutablePointer<CFError?>
        ) -> OSStatus
        typealias InfoFn = @convention(c) (
            OpaquePointer, UInt32,
            UnsafeMutablePointer<CFTypeRef?>
        ) -> OSStatus
        let create = unsafeBitCast(createP, to: CreateFn.self)
        let checkErr = unsafeBitCast(checkErrP, to: CheckErrFn.self)
        let info = unsafeBitCast(infoP, to: InfoFn.self)

        // 对单个 URL（bundle 目录或二进制文件）做静态校验并返回可读结论
        func checkOne(_ url: URL) -> String {
            var ref: CFTypeRef?
            let cs = create(url as CFURL, 0, nil, &ref)
            guard cs == 0, let code = ref else { return "createErr(\(cs))" }
            let ptr = unsafeBitCast(code, to: OpaquePointer.self)
            var cfErr: CFError?
            let vs = checkErr(ptr, 0, nil, &cfErr)
            if vs == 0 { return "valid" }
            var s = "invalid(\(vs))"
            if let e = cfErr {
                let domain = CFErrorGetDomain(e) as String
                let ecode = CFErrorGetCode(e)
                let reason = CFErrorCopyFailureReason(e) as String? ?? ""
                s += " \(domain)/\(ecode) \(reason)"
            }
            return s
        }

        // bnd=整包校验（pkd 注册时同款）；bin=直接校验二进制文件。
        // bin=valid 而 bnd=invalid → bundle 结构问题（exe 键/seal）；
        // 两者都 invalid → 二进制签名本身被安装管线破坏。
        let bnd = checkOne(appexURL)
        let bin = execURL.map { checkOne($0) } ?? "无二进制"

        // 阳性对照：主 App 与 appex 走同一 TrollStore 安装管线
        //（CI codesign → ldid 重签 → ChOma bypass）。若 app 与 appex
        // 返回相同错误码，说明此校验不认 ChOma bypass 签名，
        // static= 整段无诊断价值；只有 app=valid 时 bnd/bin 才可作判据。
        let app = Bundle.main.executableURL.map { checkOne($0) } ?? "无路径"

        // ---- requirement 对照（IPA.txt 消噪）----
        // 三目标同报 paramErr(-50) 有两种可能：
        //   a) API 层必现错误（isStaticCode 失败之类）→ static 段整体噪声
        //   b) BasicValidator 解析 TrollStore 签名时抛 paramErr →
        //      nesessionmanager 若走同款校验，同样 -50 → 直接解释 code 14
        // 区分方法：对同一对象用显式 requirement（"anchor apple generic"）
        // 再校验一次。requirement 解析发生在类型检查之后——若返回
        // -67050（designated 不满足）说明校验器正常工作且签名被正式
        // 拒绝；若仍 -50 则确认 API 层错误。
        var req = "req符号未找到"
        if let reqCreateP = dlsym(sec, "SecRequirementCreateWithString") {
            typealias ReqCreateFn = @convention(c) (
                CFString, UInt32, UnsafeMutablePointer<CFTypeRef?>
            ) -> OSStatus
            let reqCreate = unsafeBitCast(reqCreateP, to: ReqCreateFn.self)
            var reqRef: CFTypeRef?
            let rc = reqCreate("anchor apple generic" as CFString, 0, &reqRef)
            if rc == 0, let reqPtr = reqRef {
                var ref2: CFTypeRef?
                let cs2 = create(appexURL as CFURL, 0, nil, &ref2)
                if cs2 == 0, let code2 = ref2 {
                    let ptr2 = unsafeBitCast(code2, to: OpaquePointer.self)
                    var cfErr2: CFError?
                    let vs2 = checkErr(
                        ptr2, 0,
                        unsafeBitCast(reqPtr, to: OpaquePointer.self),
                        &cfErr2)
                    req = vs2 == 0
                        ? "reqValid(不应发生)" : "req=\(vs2)"
                } else {
                    req = "reqCreateCodeErr(\(cs2))"
                }
            } else {
                req = "reqCreateErr(\(rc))"
            }
        }

        // identifier/team/flags（经 bundle）
        var extra = ""
        var infoCodeRef: CFTypeRef?
        if create(appexURL as CFURL, 0, nil, &infoCodeRef) == 0,
           let infoCode = infoCodeRef {
            let ptr = unsafeBitCast(infoCode, to: OpaquePointer.self)
            var infoDictRef: CFTypeRef?
            if info(ptr, 0, &infoDictRef) == 0, let d = infoDictRef,
               CFGetTypeID(d) == CFDictionaryGetTypeID(),
               let nd = d as? NSDictionary {
                if let ident = nd["identifier"] { extra += " id=\(ident)" }
                if let team = nd["teamidentifier"] { extra += " team=\(team)" }
                if let flags = nd["flags"] { extra += " flags=\(flags)" }
            }
        }
        // 注意：Swift ARC 自动管理 CF 对象，不能也无需手动 CFRelease。

        return "bnd=\(bnd) bin=\(bin) app=\(app) req=\(req) \(exeInfo)\(extra)"
    }

    /// 检查开发者模式状态与扩展注册情况。
    ///
    /// 【根因收敛】build=111 阳性对照已证实：app=invalid(-50) 与 appex
    /// 同错，SecStaticCode 校验整段是 ChOma 噪声。签名方向彻底排除。
    /// Code 14 根因锁定在 pkd 未注册扩展。iOS 16+ 要求开发者模式开启，
    /// pkd 才会注册 NetworkExtension；若关闭，App 本身可正常运行
    /// （CoreTrust bypass 不受开发者模式影响），但扩展不会被注册。
    static func diagnoseDeveloperMode() -> String {
        var parts: [String] = []

        // 1. iOS 版本（16+ 需要开发者模式才能加载 NE 扩展）
        let v = ProcessInfo.processInfo.operatingSystemVersion
        parts.append("iOS\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)")

        // 2. 尝试 csops 读取自身代码签名标志
        // CS_GET_TASK_ALLOW (0x4) 若设置，表明开发者模式允许调试；
        // 我们的 TrollStore 包没有 get-task-allow entitlement，
        // 但开发者模式开启时内核行为不同，csflags 可能反映差异。
        if let lib = dlopen("/usr/lib/system/libsystem_kernel.dylib", 1),
           let sym = dlsym(lib, "csops") {
            typealias Fn = @convention(c) (Int32, UInt32, UnsafeMutableRawPointer?, Int) -> Int32
            let fn = unsafeBitCast(sym, to: Fn.self)
            var flags: UInt32 = 0
            let r = fn(getpid(), 0, &flags, MemoryLayout<UInt32>.size)
            if r == 0 {
                let getTask = (flags & 0x4) != 0
                let valid = (flags & 0x1) != 0
                parts.append("csflags=0x\(String(format: "%x", flags)) valid=\(valid ? "1" : "0") getTaskAllow=\(getTask ? "1" : "0")")
            } else {
                parts.append("csops=err(\(r))")
            }
        } else {
            parts.append("csops=符号未找到")
        }

        // 3. 开发者模式相关路径检查
        for p in ["/Developer", "/var/db/developermode"] {
            if FileManager.default.fileExists(atPath: p) {
                parts.append("\(p)=有")
            }
        }

        // 4. iOS build 版本（帮助精确识别 iOS 版本）
        var osversion = [CChar](repeating: 0, count: 32)
        var size: Int = 32
        if sysctlbyname("kern.osversion", &osversion, &size, nil, 0) == 0 {
            parts.append("build=\(String(cString: osversion))")
        }

        // 5. 尝试查询扩展是否已注册到系统
        // LSApplicationWorkspace applicationIsRegistered: 返回 BOOL，
        // 必须用 objc_msgSend 直接调用（perform 无法可靠取回 BOOL）
        let appexBid = extensionBundleIdentifier
        if let wsClass = NSClassFromString("LSApplicationWorkspace") {
            let wsObj = wsClass as AnyObject
            let defaultSel = NSSelectorFromString("defaultWorkspace")
            if wsObj.responds(to: defaultSel),
               let workspace = wsObj.perform(defaultSel)?.takeUnretainedValue() {
                let regSel = NSSelectorFromString("applicationIsRegistered:")
                if workspace.responds(to: regSel),
                   let msgSym = dlsym(dlopen(nil, 1), "objc_msgSend") {
                    typealias MsgFn = @convention(c) (AnyObject, Selector, NSString) -> Bool
                    let fn = unsafeBitCast(msgSym, to: MsgFn.self)
                    let isReg = fn(workspace, regSel, appexBid as NSString)
                    parts.append("extRegistered=\(isReg ? "是" : "否")")
                }
            }
        }

        return parts.joined(separator: " ")
    }

    /// 检查 provisioning profile 与 PKPlugInKit 注册状态。
    /// Apple 文档 TN3134 明确要求：NE entitlement「must be authorised by
    /// a provisioning profile」。TrollStore 可能不创建 embedded.mobileprovision，
    /// 而 pkd 可能要求它存在才注册扩展。
    static func diagnoseProvisioning() -> String {
        var parts: [String] = []

        // 1. 主 App 的 provisioning profile
        let appProfile = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision")
        parts.append("appProfile=\(appProfile != nil ? "有" : "无")")

        // 2. appex 的 provisioning profile
        if let pluginsURL = Bundle.main.builtInPlugInsURL,
           let entries = try? FileManager.default.contentsOfDirectory(atPath: pluginsURL.path),
           let appexName = entries.first(where: { $0.hasSuffix(".appex") }) {
            let profilePath = pluginsURL.appendingPathComponent(appexName)
                .appendingPathComponent("embedded.mobileprovision").path
            parts.append("appexProfile=\(FileManager.default.fileExists(atPath: profilePath) ? "有" : "无")")
        }

        // 3. PKPlugInKit 查询已注册扩展
        if dlopen("/System/Library/PrivateFrameworks/PlugKit.framework/PlugKit", 1) != nil,
           let pkClass = NSClassFromString("PKPlugInKit") {
            let pkObj = pkClass as AnyObject
            let sharedSel = NSSelectorFromString("plugInKit")
            if pkObj.responds(to: sharedSel),
               let kit = pkObj.perform(sharedSel)?.takeUnretainedValue() {
                let plugsSel = NSSelectorFromString("plugIns")
                if kit.responds(to: plugsSel),
                   let plugs = kit.perform(plugsSel)?.takeUnretainedValue() as? [AnyObject] {
                    parts.append("pkTotal=\(plugs.count)")
                    var found = false
                    for plug in plugs {
                        let idSel = NSSelectorFromString("pluginIdentifier")
                        if plug.responds(to: idSel),
                           let id = plug.perform(idSel)?.takeUnretainedValue() as? String,
                           id == extensionBundleIdentifier {
                            found = true
                            break
                        }
                    }
                    parts.append("pkOurExt=\(found ? "已注册" : "未注册")")
                }
            }
        } else {
            parts.append("PKKit=未找到")
        }

        return parts.joined(separator: " ")
    }

    /// 直读 pkd（pluginkit 守护进程）注册数据库与 LS plugin 视图，
    /// 一锤定音"扩展到底进没进系统"：
    /// - lsPlug: 主 App LSApplicationProxy.plugins 里能否找到 appex
    ///   （nesessionmanager 查 provider 的路径之一）
    /// - pkdDB: 直接在 PlugInKit 数据库文件的原始字节里搜 appex
    ///   bundleID（binary plist/sqlite 的字符串均明文存储，原始搜索可靠）
    static func diagnosePkdRegistration() -> String {
        var parts: [String] = []
        let appexBid = extensionBundleIdentifier
        let mainBid = Bundle.main.bundleIdentifier ?? "com.prism.proxy"

        // 1. LS 层：直接对 appex bundleID 取 proxy——若 LS 认识该 plugin，
        //    proxy 非 nil 且 pluginIdentity 存在（等价于主 App plugins 数组
        //    里有它，但绕开 plugins 属性的桥接问题）
        var lsPlug = "类未找到"
        if let wsClass = NSClassFromString("LSApplicationProxy") {
            let cls = wsClass as AnyObject
            let proxySel = NSSelectorFromString("applicationProxyForIdentifier:")
            if cls.responds(to: proxySel) {
                let appexProxy = cls.perform(proxySel, with: appexBid)?
                    .takeUnretainedValue()
                let mainProxy = cls.perform(proxySel, with: mainBid)?
                    .takeUnretainedValue()
                // 主 App plugins 数组（NSArray 桥接可能失败，仅报数量）
                var plugCount = -1
                if let mp = mainProxy {
                    let pluginsSel = NSSelectorFromString("plugins")
                    if mp.responds(to: pluginsSel),
                       let arr = mp.perform(pluginsSel)?.takeUnretainedValue() {
                        plugCount = (arr as? NSArray)?.count ?? -1
                    }
                }
                if appexProxy == nil {
                    lsPlug = "appex无proxy"
                } else {
                    let piSel = NSSelectorFromString("pluginIdentity")
                    let hasPI = appexProxy!.responds(to: piSel)
                        && appexProxy!.perform(piSel)?.takeUnretainedValue() != nil
                    lsPlug = "\(hasPI ? "pluginIdentity有" : "pluginIdentity无")(count=\(plugCount))"
                }
            } else {
                lsPlug = "proxy选择器不可用"
            }
        }
        parts.append("lsPlug=\(lsPlug)")

        // 2. pkd 层：PlugInKit 数据库目录原始搜索。
        //    iOS 16 的 pkd 数据库在 /var/mobile/Library/PlugInKit/（历史路径）
        //    或 system group container；先枚举候选目录再看能不能命中。
        let needle = Data(appexBid.utf8)
        var pkdDB = "目录不存在"
        var probeDirs: [String] = []
        // 2a. /var/mobile/Library/ 枚举（no-sandbox 后应可读）——找
        //     PlugIn 相关目录，同时报目录是否存在（决定性信息）
        let mobLib = "/var/mobile/Library"
        if let entries = try? FileManager.default.contentsOfDirectory(
            atPath: mobLib) {
            let hitNames = entries.filter {
                $0.lowercased().contains("pluginkit")
                    || $0.lowercased().contains("plugin")
            }
            probeDirs = hitNames.map { (mobLib as NSString).appendingPathComponent($0) }
            pkdDB = "mobLib可枚举(\(entries.count)项, plug=\(hitNames.joined(separator: ",")))"
        } else {
            pkdDB = "mobLib不可枚举"
        }
        // 2b. system group container 扫描
        let sgRoot = "/var/containers/Shared/SystemGroup"
        if let subs = try? FileManager.default.contentsOfDirectory(atPath: sgRoot) {
            let pkSubs = subs.filter { $0.lowercased().contains("pluginkit") }
            for s in pkSubs {
                probeDirs.append((sgRoot as NSString).appendingPathComponent(s))
            }
            pkdDB += " sg=\(pkSubs.isEmpty ? "无pluginkit组" : pkSubs.joined(separator: ","))"
        } else {
            pkdDB += " sg不可枚举"
        }
        // 2c. 对候选目录做原始字节搜索
        if !probeDirs.isEmpty {
            var hit = false
            var scanned = 0
            for dir in probeDirs {
                let files = (try? FileManager.default.contentsOfDirectory(
                    atPath: dir)) ?? []
                for f in files {
                    let p = (dir as NSString).appendingPathComponent(f)
                    guard let data = FileManager.default.contents(atPath: p),
                          !data.isEmpty else { continue }
                    scanned += 1
                    if data.range(of: needle) != nil { hit = true }
                }
                if hit { break }
            }
            pkdDB += hit
                ? " 搜索=命中" : " 搜索=未命中(扫\(scanned)文件)"
        }
        parts.append("pkdDB=\(pkdDB)")

        return parts.joined(separator: " ")
    }

    /// 打包诊断：列出 PlugIns 下每个 appex 的 bundle ID 与扩展点。
    /// 随启动失败错误一起输出，用户截图即可远程定位是 IPA 缺扩展
    /// 还是系统/配置层问题
    static func diagnosePackaging() -> String {
        guard let pluginsURL = Bundle.main.builtInPlugInsURL else {
            return "PlugIns 目录不存在(builtInPlugInsURL=nil)"
        }
        let entries = (try? FileManager.default.contentsOfDirectory(
            atPath: pluginsURL.path)) ?? []
        let appexes = entries.filter { $0.hasSuffix(".appex") }
        if appexes.isEmpty {
            return "PlugIns 下无 .appex(扩展未打包!)"
        }
        return appexes.map { name in
            let bundle = Bundle(url: pluginsURL.appendingPathComponent(name))
            let bid = bundle?.infoDictionary?["CFBundleIdentifier"] as? String ?? "?"
            let point = ((bundle?.infoDictionary?["NSExtension"] as? [String: Any])?["NSExtensionPointIdentifier"] as? String) ?? "?"
            let ver = bundle?.infoDictionary?["CFBundleVersion"] as? String ?? "?"
            return "\(name): id=\(bid) point=\(point) extbuild=\(ver)"
        }.joined(separator: " | ")
    }

    // MARK: - 强制注册扩展

    /// 运行时读取主进程实际生效的关键 entitlements（TrollStore 重签后的
    /// 真值）。与 knownMainEntitlements() 期望值比对：若设备上读不到
    /// 或值不符，说明 TrollStore 安装时丢弃/改写了 entitlements——
    /// 这是"签名/预检全 ok 但行为异常"的终极判据。
    static func runtimeEntitlementsSummary() -> String {
        guard let sec = dlopen(
            "/System/Library/Frameworks/Security.framework/Security", 1),
            let createSelfP = dlsym(sec, "SecTaskCreateFromSelf"),
            let copyValueP = dlsym(sec, "SecTaskCopyValueForEntitlement")
        else { return "SecTask符号未找到" }

        typealias CreateSelfFn = @convention(c) (CFAllocator?) -> CFTypeRef?
        typealias CopyValueFn = @convention(c) (
            OpaquePointer, CFString, UnsafeMutablePointer<CFError?>?
        ) -> CFTypeRef?
        let createSelf = unsafeBitCast(createSelfP, to: CreateSelfFn.self)
        let copyValue = unsafeBitCast(copyValueP, to: CopyValueFn.self)

        guard let taskRef = createSelf(kCFAllocatorDefault) else {
            return "task创建失败"
        }
        let task = unsafeBitCast(taskRef, to: OpaquePointer.self)

        func valueFor(_ key: String) -> String {
            let v = copyValue(task, key as CFString, nil)
            if v == nil { return "-" }
            if let b = v as? Bool { return b ? "1" : "0" }
            if let s = v as? String { return s }
            if let a = v as? [Any] { return "[\(a.count)]" }
            return "?"
        }

        let parts = [
            "platform=\(valueFor("platform-application"))",
            "noSbx=\(valueFor("com.apple.private.security.no-sandbox"))",
            "noCnt=\(valueFor("com.apple.private.security.no-container"))",
            "adc=\(valueFor("com.apple.private.security.storage.AppDataContainers"))",
            "persona=\(valueFor("com.apple.private.persona-mgmt"))",
            "netext=\(valueFor("com.apple.developer.networking.networkextension"))",
            "groups=\(valueFor("com.apple.security.application-groups"))",
            "appID=\(valueFor("application-identifier"))",
        ]
        return parts.joined(separator: " ")
    }

    /// 保存注册尝试的结果，供诊断输出
    static var lsRegisterResult: String = "未调用"
    static var lsAppWorkspaceResult: String = "未调用"

    /// 强制向 Launch Services 注册 appex bundle。
    /// TrollStore 安装不走 installd，pkd 不会自动登记 PlugIns 下的扩展
    ///（CoreTrust 绕过只影响 amfid/FrontBoard 的代码签名校验，
    /// pluginkit 有独立的注册数据库），导致系统找不到扩展
    /// → NEVPNConnectionErrorDomain code=14。
    /// 方案1: posix_spawn pluginkit -a/-e（主 App 携带 no-sandbox 后可行，
    ///        失败再用 persona-mgmt 以 root 重试）——pkd 注册的正道
    /// 方案2: LSApplicationWorkspace.registerApplicationDictionary 私有 API
    /// 方案3: dlsym 多路径加载 LSRegisterURL（iOS 16 上符号未导出，兜底）
    static func registerAppexWithLaunchServices() {
        guard let pluginsURL = Bundle.main.builtInPlugInsURL,
              let entries = try? FileManager.default.contentsOfDirectory(
                atPath: pluginsURL.path)
        else {
            NSLog("[PrismVPN] registerAppex: PlugIns 目录不存在")
            lsRegisterResult = "PlugIns不存在"
            return
        }
        for entry in entries where entry.hasSuffix(".appex") {
            let appexURL = pluginsURL.appendingPathComponent(entry)
            let csPath = appexURL.appendingPathComponent("_CodeSignature/CodeResources").path
            let hasSeal = FileManager.default.fileExists(atPath: csPath)
            NSLog("[PrismVPN] appex=\(entry) CodeResources=\(hasSeal ? "有" : "无")")

            // 方案1: posix_spawn pluginkit -a/-e —— 已废弃：iOS 无
            //        pluginkit CLI（/usr/bin/pluginkit 不存在，spawn 恒
            //        ENOENT）。注册交给：
            //        a) 随包 PrismHelper（root 级 fixperm + LSApplicationWorkspace
            //           注册，写完整 _LSBundlePlugins 字典）
            //        b) 注册失败时回退 TrollStore 官方 trollstorehelper uicache。
            //           顺序绝不能反：uicache 以官方字典重建 _LSBundlePlugins，
            //           在 PrismHelper 注册成功后再跑会覆盖刚写入的注册信息
            //           （build 141 方案第 3 条）
            // 注册统一由 TrollStore 安装时的官方 trollstorehelper uicache
            // 完成。App 运行期严禁再调 rootHelper/selfHelper：uicache 第一步
            // 会 unregisterApplication 注销运行中的 App → nehelper/
            // nesessionmanagerd 立刻将 VPN 会话标记失效 → Code=12 且 hb=无
            // （build 133/138/140/153 实证；TrollStore 安装 IPA 时已执行过
            // uicache，App 内绝不能二次调用）

            // 方案2（原 tryLSApplicationWorkspace，mobile 身份
            // registerApplicationDictionary）已移除：以 mobile 身份传入的
            // 字典不如 TrollStore 安装时完整，会在 LaunchServices 里
            // 覆盖掉安装时生成的 _LSBundlePlugins 注册记录，反而清空
            // 主 App 的 plugInKitPlugins（lsPlug=plugins不可读 的来源）。
            // LaunchServices 层注册统一由 root 级 uicache/PrismRegister.sh 负责。

            // 方案3: dlsym 多框架/多符号名尝试（兜底）
            // Apple 平台 C 符号在符号表中带下划线前缀：_LSRegisterURL
            let frameworks = [
                "/System/Library/Frameworks/CoreServices.framework/CoreServices",
                "/System/Library/PrivateFrameworks/MobileCoreServices.framework/MobileCoreServices",
                "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/LaunchServices"
            ]
            let symbolNames = ["_LSRegisterURL", "LSRegisterURL"]
            var lsDone = false
            for fwPath in frameworks {
                guard !lsDone,
                      let handle = dlopen(fwPath, 1)  // RTLD_LAZY
                else { continue }
                for symName in symbolNames {
                    guard !lsDone,
                          let sym = dlsym(handle, symName)
                    else { continue }
                    typealias Fn = @convention(c) (CFURL, Bool) -> Int32
                    let fn = unsafeBitCast(sym, to: Fn.self)
                    let status = fn(appexURL as CFURL, true)
                    lsRegisterResult = "\(symName)@\((fwPath as NSString).lastPathComponent)=\(status)"
                    NSLog("[PrismVPN] \(symName) status=\(status)")
                    lsDone = true
                }
                dlclose(handle)
            }
            if !lsDone {
                lsRegisterResult = "所有路径/符号均未找到"
                NSLog("[PrismVPN] LSRegisterURL not found in any framework")
            }
        }
    }

    /// 【APP16 任务3】runSpawnTool 返回值：用结构体替代命名元组，
    /// 严禁命名元组声明与强制类型转换。
    private struct SpawnToolResult {
        let spawn: Int32
        let exit: Int32
        let termsig: Int32
        let output: String
    }

    /// 通过 posix_spawn 运行 pluginkit 子命令。
    /// asRoot 依赖 com.apple.private.persona-mgmt entitlement，用
    /// posix_spawn 运行外部工具（TrollStore TSUtil.m spawnRoot 同款机制）；
    /// captureOutput 时把 stdout 重定向到临时文件并在结束后读回。
    /// 返回 SpawnToolResult(spawnErrno, 子进程exitCode, 终止信号(0=正常退出), stdout)
    private static func runSpawnTool(
        path: String,
        args: [String],
        asRoot: Bool,
        captureOutput: Bool
    ) -> SpawnToolResult {
        var argv: [UnsafeMutablePointer<CChar>?] = [strdup(path)]
        for a in args { argv.append(strdup(a)) }
        argv.append(nil)
        defer { argv.prefix(while: { $0 != nil }).forEach { free($0) } }

        // 注意：iOS SDK 中 posix_spawnattr_t / posix_spawn_file_actions_t
        // 是指针 typedef（Swift 导入为 OpaquePointer），不能值初始化，
        // 必须经 *_init 分配、*_destroy 释放。
        var attr: posix_spawnattr_t? = nil
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }

        if asRoot {
            // persona-mgmt entitlement 允许以任意 persona spawn：
            // 99 = persona id（任意非零），1 = POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE
            typealias PersonaNP = @convention(c) (
                UnsafeMutablePointer<posix_spawnattr_t?>, uid_t, UInt32
            ) -> Int32
            typealias PersonaID = @convention(c) (
                UnsafeMutablePointer<posix_spawnattr_t?>, uid_t
            ) -> Int32
            let h = dlopen(nil, 1) // RTLD_LAZY，全局作用域含 libSystem
            if let p = dlsym(h, "posix_spawnattr_set_persona_np"),
               let u = dlsym(h, "posix_spawnattr_set_persona_uid_np"),
               let g = dlsym(h, "posix_spawnattr_set_persona_gid_np") {
                let setNP = unsafeBitCast(p, to: PersonaNP.self)
                let setUID = unsafeBitCast(u, to: PersonaID.self)
                let setGID = unsafeBitCast(g, to: PersonaID.self)
                _ = setNP(&attr, 99, 1)
                _ = setUID(&attr, 0)
                _ = setGID(&attr, 0)
            }
        }

        var fa: posix_spawn_file_actions_t? = nil
        var outPath: String? = nil
        if captureOutput {
            posix_spawn_file_actions_init(&fa)
            outPath = (NSTemporaryDirectory() as NSString)
                .appendingPathComponent("prism_pluginkit_out.txt")
            unlink(outPath!)
            posix_spawn_file_actions_addopen(
                &fa, 1, outPath!, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
        }
        // 销毁须发生在 posix_spawn 之后，故 defer 不能放在 if 块内
        defer {
            if captureOutput { posix_spawn_file_actions_destroy(&fa) }
        }

        var pid: pid_t = 0
        let spawnResult: Int32
        if captureOutput {
            spawnResult = posix_spawn(&pid, path, &fa, &attr, &argv, nil)
        } else {
            spawnResult = posix_spawn(&pid, path, nil, &attr, &argv, nil)
        }
        guard spawnResult == 0 else {
            return SpawnToolResult(spawn: spawnResult, exit: -1, termsig: 0, output: "")
        }
        var status: Int32 = 0
        waitpid(pid, &status, 0)
        let exitCode = (status >> 8) & 0xFF // WEXITSTATUS
        // 信号死亡（SIGSEGV/SIGABRT…）时 WEXITSTATUS 恒为 0，会被误判为
        // 成功退出（build 138 实证 register:u0[] 的成因之一）——单独提取
        // WTERMSIG（status 低 7 位，非 0 = 被信号杀死）
        let termsig = status & 0x7F

        var output = ""
        if captureOutput, let outPath {
            output = (try? String(contentsOfFile: outPath, encoding: .utf8)) ?? ""
            unlink(outPath)
        }
        return SpawnToolResult(spawn: 0, exit: exitCode, termsig: termsig, output: output)
    }

    // MARK: - root helper 注册

    static var rootHelperResult: String = "未调用"

    /// 定位 TrollStore.app 目录（LS 查询，失败则扫描 Bundle/Application）
    private static func trollStoreAppPath() -> String? {
        if let cls = NSClassFromString("LSApplicationProxy") {
            let c = cls as AnyObject
            let sel = NSSelectorFromString("applicationProxyForIdentifier:")
            if c.responds(to: sel),
               let proxy = c.perform(sel, with: "com.opa334.TrollStore")?
                   .takeUnretainedValue() {
                let urlSel = NSSelectorFromString("bundleURL")
                if let url = proxy.perform(urlSel)?
                    .takeUnretainedValue() as? URL {
                    return url.path
                }
            }
        }
        let root = "/var/containers/Bundle/Application"
        if let ids = try? FileManager.default.contentsOfDirectory(atPath: root) {
            for id in ids {
                let p = (root as NSString).appendingPathComponent(id)
                if let apps = try? FileManager.default.contentsOfDirectory(atPath: p),
                   apps.contains("TrollStore.app") {
                    return (p as NSString).appendingPathComponent("TrollStore.app")
                }
            }
        }
        return nil
    }

    /// 用 TrollStore 自带的 setuid root helper（trollstorehelper）以 root
    /// 身份执行官方 uicache 注册。
    ///
    /// 背景：iOS 没有 pluginkit CLI（/usr/bin/pluginkit 不存在，spawn 恒
    /// ENOENT），App 内 registerApplicationDictionary 只是同字典的 mobile
    /// 身份重复劳动。TrollStore 安装 IPA 时正是以 root 跑 trollstorehelper
    /// uicache（RootHelper/uicache.m registerPath，含 PlugIns 的完整
    /// _LSBundlePlugins 字典）——这是生态内唯一的 root 级注册正道。
    /// uicache CLI 语义：给 app 路径 = 注册该 app（含 PlugIns）。
    @discardableResult
    static func tryRootHelperUICache() -> Bool {
        guard let tsPath = trollStoreAppPath() else {
            rootHelperResult = "helper=TrollStore未定位"
            return false
        }
        let helperPath = (tsPath as NSString)
            .appendingPathComponent("trollstorehelper")
        guard FileManager.default.isExecutableFile(atPath: helperPath) else {
            rootHelperResult = "helper=\(helperPath)不可执行"
            return false
        }
        let appPath = Bundle.main.bundlePath
        let spawnTool = runSpawnTool(
            path: helperPath, args: ["uicache", appPath],
            asRoot: true, captureOutput: true)
        if spawnTool.spawn != 0 {
            rootHelperResult = "helper=spawn=\(spawnTool.spawn)"
            return false
        }
        let tail = spawnTool.output.trimmingCharacters(in: .whitespacesAndNewlines)
        let sigNote = spawnTool.termsig != 0 ? " sig=\(spawnTool.termsig)" : ""
        rootHelperResult = "helper=u\(spawnTool.exit)\(sigNote)\(tail.isEmpty ? "" : " out=\(tail.prefix(100))")"
        NSLog("[PrismVPN] rootHelper: \(rootHelperResult)")
        return spawnTool.exit == 0 && spawnTool.termsig == 0
    }

    // MARK: 旧版扩展进程清理（build 150 方案第 2 步）

    /// Code=12+hb无 自愈只执行一次（防反复重启死循环）
    static var code12SelfHealed = false

    /// Code=12 且扩展无心跳：旧版 PrismVPN 进程驻留占住 nesessionmanager
    /// 的典型指纹（TrollStore 覆盖安装只杀主 App 不杀后台扩展，磁盘二进制
    /// 已被新版覆盖 → 旧进程 XPC 失败，新版 startTunnel 根本不被拉起）
    static func isCode12WithNoHeartbeat(_ error: Error) -> Bool {
        guard diagnoseExtensionHeartbeat() == "无" else { return false }
        var current = error as NSError
        while true {
            if current.domain == "NEVPNConnectionErrorDomain" || current.domain == "NEVPNErrorDomain" {
                if current.code == 12 || current.code == 1 { return true }
            }
            guard let next = current.userInfo[NSUnderlyingErrorKey] as? NSError else { return false }
            current = next
        }
    }

    /// 覆盖安装检测：CFBundleVersion 变化说明磁盘二进制已更新，后台可能
    /// 仍驻留旧版扩展进程。启动前先杀旧进程 + uicache 刷新（每次新版本
    /// 仅执行一次，靠 UserDefaults 记录已处理的版本）
    static func checkAndKillStaleExtension() {
        let current = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        let last = UserDefaults.standard.string(forKey: "prism_last_build_version")
        guard last != current else { return }
        UserDefaults.standard.set(current, forKey: "prism_last_build_version")
        NSLog("[PrismVPN] 检测到覆盖安装 \(last ?? "无") -> \(current)，清理驻留旧版扩展进程")
        killStaleExtensionProcess()
        tryRootHelperUICache()
    }

    // MARK: - APP-5 任务2：升级指纹 + 启动自愈

    /// 已处理的安装指纹（版本号|build|二进制 mtime）
    private static let kUpgradeFingerprintKey = "prism_upgrade_fingerprint"
    /// 升级后待自动重启标记（Rust 读取后清除）
    static let kPendingRestartKey = "prism_pending_restart_after_upgrade"
    /// 上一次进入连接状态记录（用于判断升级前隧道是否在使用中）
    private static let kWasConnectedKey = "prism_tunnel_was_connected"

    /// 计算当前安装指纹。
    /// 仅比较版本号/build 无法感知「同 build 重签覆盖」或 TrollStore 覆盖重装，
    /// 因此引入主程序与扩展二进制的磁盘修改时间：二进制一旦被替换，
    /// mtime 必然变化，指纹 100% 改变。
    static func computeInstallFingerprint() -> String {
        let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        return "\(version)|\(build)|\(mainBinaryStamp())|\(extensionBinaryStamp())"
    }

    /// 单个文件/目录的 mtime（Unix 秒），不可得时返回 0
    private static func modificationStamp(ofPath path: String) -> Int {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
              let date = attrs[.modificationDate] as? Date
        else {
            return 0
        }
        return Int(date.timeIntervalSince1970)
    }

    /// 主 App 可执行文件 mtime（回落到 bundle 目录属性）
    private static func mainBinaryStamp() -> Int {
        let stamp = Bundle.main.executablePath.map { modificationStamp(ofPath: $0) } ?? 0
        return stamp != 0 ? stamp : modificationStamp(ofPath: Bundle.main.bundlePath)
    }

    /// 隧道扩展二进制 mtime（PlugIns/PrismVPN.appex/PrismVPN）。
    /// 扩展才是真正执行代理的进程——只换主 App 不换扩展时，必须靠它感知。
    private static func extensionBinaryStamp() -> Int {
        let appex = "\(Bundle.main.bundlePath)/PlugIns/PrismVPN.appex"
        let binary = "\(appex)/PrismVPN"
        let stamp = modificationStamp(ofPath: binary)
        return stamp != 0 ? stamp : modificationStamp(ofPath: appex)
    }

    /// 覆盖升级自愈统一入口（APP-5 任务2）：App 启动时（Rust setup）与
    /// prismIosVpnStart 开头都会调用，指纹比对保证只在升级后首次启动执行一次。
    /// 返回 true 表示本次是升级后首次启动且已执行清理。
    @discardableResult
    static func handleUpgradeIfNeededOnLaunch() -> Bool {
        // 【APP35 任务1】App 每次启动都关闭摇晃撤销（与指纹无关，必须在 guard 之前）
        disableShakeToEdit()
        let fingerprint = computeInstallFingerprint()
        let defaults = UserDefaults.standard
        let last = defaults.string(forKey: kUpgradeFingerprintKey)
        guard last != fingerprint else { return false }

        defaults.set(fingerprint, forKey: kUpgradeFingerprintKey)
        // 同步旧键，保持既有清理路径（preCleanAndSyncVersion）行为一致
        let build = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        defaults.set(build, forKey: "prism_last_build_version")
        NSLog("[PrismVPN] 升级指纹变化 \(last ?? "无") -> \(fingerprint)，执行启动自愈")

        // 1. 杀掉驻留的旧版 PrismVPN 扩展进程：不做这步，系统里运行的
        //    仍是旧 appex，新版主 App 无法与它共享配置版本
        killStaleExtensionProcess()

        // 2. 升级前隧道处于连接状态 → 标记待自动重启，由 Rust 在启动
        //    流程末尾重建隧道（用户无需手动点「连接」）
        if defaults.bool(forKey: kWasConnectedKey) {
            defaults.set(true, forKey: kPendingRestartKey)
            NSLog("[PrismVPN] 升级前隧道在使用中，已标记升级后自动重建")
        }
        return true
    }

    /// 调用随包 PrismHelper killext（killall -9 PrismVPN）
    static func killStaleExtensionProcess() {
        let helperPath = Bundle.main.bundleURL
            .appendingPathComponent("PrismHelper").path
        guard FileManager.default.isExecutableFile(atPath: helperPath) else {
            NSLog("[PrismVPN] killext 失败：PrismHelper 不存在")
            return
        }
        let spawnTool = runSpawnTool(
            path: helperPath, args: ["killext"],
            asRoot: true, captureOutput: false)
        NSLog("[PrismVPN] killext spawn=\(spawnTool.spawn) exit=\(spawnTool.exit) sig=\(spawnTool.termsig)")
    }

    // MARK: - 随包 root helper（PrismHelper）强扭注册

    static var selfHelperResult: String = "未调用"

    /// 以 root persona spawn 随包的 PrismHelper（Mach-O CLI）：
    /// 1. fixperm  — Bundle 目录/文件属主修回 _installd:_installd (33:33)
    ///    （目录/可执行 0755、其余 0644），数据容器 mobile(501:501)。
    ///    绝不能是 mobile(501)——普通用户属主的系统插件二进制会被
    ///    pkd/launchd 拒绝执行。必须先于 register 执行（build 141 方案）
    /// 2. register — root 身份 LSApplicationWorkspace.registerApplication
    ///    Dictionary:（完整官方字典）+ registerPlugin: 强扭注册扩展
    /// helper 的 stdout 全部捕获进诊断（selfHelper= 字段）。
    ///
    /// 注意路径必须用 bundleURL 直接构造：path(forResource:ofType:) 对
    /// bundle 根目录无扩展名文件的查找有怪癖（build 136 真机 helper
    /// 缺失的成因之一）。spawn 前先尝试恢复 +x（TrollStore 安装器可能
    /// 统一重置 bundle 内文件权限；helper 由 CI 签名带主 App 同款
    /// entitlements——裸签的 helper 以 root 启动会被系统拦截）。
    /// 另：shell 脚本方案不可行——AMFI 严禁 posix_spawn 执行非 Mach-O
    /// 的 .sh（build 137 实证 spawn=1 EPERM）。
    @discardableResult
    static func trySelfHelperRegister() -> Bool {
        let helperPath = Bundle.main.bundleURL
            .appendingPathComponent("PrismHelper").path
        if !FileManager.default.fileExists(atPath: helperPath) {
            selfHelperResult = "helper缺失"
            return false
        }
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: helperPath)
        guard FileManager.default.isExecutableFile(atPath: helperPath) else {
            selfHelperResult = "helper不可执行"
            return false
        }
        let mainPath = Bundle.main.bundlePath
        let appexPath = mainPath + "/PlugIns/PrismVPN.appex"
        guard FileManager.default.fileExists(atPath: appexPath) else {
            selfHelperResult = "appex缺失"
            return false
        }

        var all = [String]()
        var spawnedOK = true
        var registerText = ""
        // fixperm 必须先于 register：Bundle 属主修成 _installd(33:33) 后
        // 再注册，pkd/LaunchServices 读到的就是正确属主（build 141 方案）
        for cmd in ["fixperm", "register"] {
            let spawnTool = runSpawnTool(
                path: helperPath, args: [cmd, mainPath, appexPath],
                asRoot: true, captureOutput: true)
            if spawnTool.spawn != 0 {
                all.append("\(cmd):spawn=\(spawnTool.spawn)")
                spawnedOK = false
                continue
            }
            let lines = spawnTool.output.split(separator: "\n")
                .map { String($0).trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            // sig=N 非零说明 helper 被信号杀死（此时 WEXITSTATUS 恒为 0，
            // 不能只看 exitCode 判定成功——build 138 实证空括号误判）
            let sigNote = spawnTool.termsig != 0 ? " sig=\(spawnTool.termsig)" : ""
            all.append("\(cmd):u\(spawnTool.exit)\(sigNote)[\(lines.joined(separator: " | ").prefix(220))]")
            if cmd == "register" { registerText = spawnTool.output }
            if spawnTool.exit != 0 || spawnTool.termsig != 0 { spawnedOK = false }
        }
        selfHelperResult = all.joined(separator: " ")
        NSLog("[PrismVPN] selfHelper: \(selfHelperResult)")
        // 注册成功判定：两步进程均正常退出，且 register 末行
        // result=reg ls=1 plugin=1（LS 双注册均返回 YES）。
        // 返回 false 时调用方才回退 TrollStore 官方 uicache
        guard spawnedOK else { return false }
        return registerText.contains("ls=1") && registerText.contains("plugin=1")
    }

    // MARK: 失效配置识别

    /// 判断错误是否表示「系统保存的 VPN 配置已找不到对应扩展」。
    ///
    /// App 覆盖安装（尤其是 TrollStore 重签/升级安装）后，系统 Network
    /// Extension 偏好里的旧配置与新装 appex 的内部映射可能失效——即使
    /// bundle ID 表面一致，继续在旧 manager 上 save/start 只会反复报：
    ///   NEVPNConnectionErrorDomain code=14
    ///   "The VPN app used by the VPN configuration is not installed"
    /// （build 169 方案：该错误仅记录诊断交回上层，交由用户重装/
    /// TrollStore 处理，运行期绝不自动清理配置或调用 uicache）
    ///
    /// 是否为 Code=14「VPN 插件未安装/未注册」错误（build 144 方案：
    /// 该错误码是 rootHelper uicache 修复的唯一触发条件）
    static func isVPNAppNotInstalled(_ error: Error) -> Bool {
        let ns = error as NSError
        if ns.domain == "NEVPNConnectionErrorDomain" && ns.code == 14 {
            return true
        }
        if ns.domain == "NEVPNErrorDomain" && ns.code == 14 {
            return true
        }
        let text = error.localizedDescription
        return text.contains("not installed") || text.contains("未安装")
    }

    /// 失效/无效配置判定（曾用于自动重建重试的依据）。
    ///
    /// 注意（build 169 方案）：失败路径绝不允许 removeFromPreferences
    /// （误删合法配置 → managers=0 → 反复授权弹窗），resetAllManagers
    /// 重建重试分支已随 Code=12 自愈方案一并移除；本函数保留作
    /// 错误分类备用。
    static func isStaleOrInvalid(_ error: Error) -> Bool {
        var current: NSError? = error as NSError
        while let ns = current {
            // NEVPNConnectionErrorDomain 14：配置指向的扩展未安装
            if ns.domain == "NEVPNConnectionErrorDomain" && ns.code == 14 {
                return true
            }
            // NEVPNErrorDomain 1 = configurationInvalid（配置失效）
            if ns.domain == "NEVPNErrorDomain" && ns.code == 1 {
                return true
            }
            // 本控制器 code=-3：status=invalid，系统中无有效持久化配置，
            // 重建 manager 即可恢复
            if ns.domain == "PrismVPN" && ns.code == -3 {
                return true
            }
            // 「无任何错误痕迹的立即断开」：既没有扩展写入的 prism_error.txt，
            // 系统也没有断开错误记录（iOS14/15 无 fetchLastDisconnectError，
            // 或 iOS16+ 返回 nil）。扩展 startTunnel 只要真正跑起来，任何
            // 失败都会写共享错误文件——所以这种情形等价于扩展根本没被
            // 系统拉起（旧系统上的 code=14），同样需要清除重建
            if ns.domain == "PrismVPN", ns.code == -2,
               ns.localizedDescription.hasPrefix("扩展启动后立即断开")
            {
                return true
            }
            // 文案兜底（不同 iOS 版本 domain 偶有差异）
            if ns.localizedDescription.lowercased().contains("not installed") {
                return true
            }
            current = ns.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        return false
    }

    // MARK: 启动（带失效配置自愈，最多重试 1 次）

    func start(configPath: String, completion: @escaping (Error?) -> Void) {
        // 【build 150 方案第 2 步】错误文件只在最外层入口清一次：
        // startAttempt 重试/自愈路径不再清，保留第一轮 hb=/extErr= 现场
        // 供失败诊断（此前每次尝试开头都清，错误证据全被抹掉）
        clearSharedErrorFile()
        PrismTunnelController.code12SelfHealed = false
        // 记录真实配置路径：Code=12 自愈重试从任意失败点发起时，
        // 部分 recoverOrFinish 调用点（reload/连接超时）拿不到
        // configPath（传空串），重试必须用真实路径
        lastStartConfigPath = configPath
        // 【build 169 方案】覆盖安装检测移交 preCleanAndSyncVersion：
        // 版本变化仅调一次 PrismHelper killext 清理驻留旧扩展进程，
        // App 运行期严禁调用 rootHelper(uicache)/selfHelper（uicache 会
        // 注销运行中的 App → nesessionmanager 会话失效 → Code=12 且 hb=无，
        // build 153 实证；凡 rootHelper=helper=u0 的版本 133/138/140/153 全部 Code=12）

        // attemptsRemaining=0：失败后严禁自动删配置重建——重建会触发
        // 第二次"添加 VPN 配置"授权弹窗，且刚授权的配置被删光后
        // managers=0（build 137 实证）。code=14/失效配置的恢复交给
        // 用户手动重置（设置页的 reset 入口），或修好注册链路后自然消失
        startAttempt(configPath: configPath, attemptsRemaining: 0, completion: completion)
    }

    private func startAttempt(
        configPath: String,
        attemptsRemaining: Int,
        completion: @escaping (Error?) -> Void
    ) {
        // 【APP-2】启动前清场：非已连接状态下先 killext 清理残留/僵死的旧
        // PrismVPN 扩展进程（可能仍绑定旧基站 Socket），达到"先开一下其他
        // 代理软件"的同效清场，根治跨基站移动/弱 Wi-Fi 切换后全超时
        if activeManager?.connection.status != .connected {
            PrismTunnelController.killStaleExtensionProcess()
        }

        // 【build 150】clearSharedErrorFile 已上移到 start() 入口只清一次；
        // 重试/自愈路径保留上一轮心跳与错误现场，诊断串才能看到真实卡点

        // 【build 144 方案·关键】启动路径对注册零干预：
        // TrollStore 安装 IPA 时已经由官方 trollstorehelper 完成了最标准的
        // 插件容器分配与 _LSBundlePlugins 注册（appex entitlements 纯净后
        // 连 container-required 都会被 TrollStore 自动补齐）。此前在这里
        // 无条件跑 selfHelper（PrismHelper register），用从零新建的字典
        // 覆盖了官方注册——缺 NSExtension/CFBundleExecutable/TeamIdentifier，
        // LaunchServices 里扩展点标识被抹掉 → nesessionmanager 立刻报
        // Code=14 "VPN 插件未安装"（build 143 实证）。
        // 现在失败出口（recoverOrFinish）对 Code=14 仅记录诊断交回上层：
        // App 运行期严禁 uicache/rootHelper（会注销运行中的 App 造成
        // Code=12 且 hb=无，build 153/169 实证），注册问题交由用户
        // 重装/TrollStore 处理。

        // 主动 pre-clean + 版本同步（同时解决三个问题）：
        //
        // 1) 解决"Prism - 需要更新"红色提示：iOS 在 VPN 配置里记录了
        //    App 安装时的版本号/签名时间戳；每次 TrollStore 重装会更新
        //    签名但 VPN 配置里的版本号不自动同步，iOS 因此认为配置
        //    指向"过时"的 App。loadOrCreateManager 找到已存配置后，
        //    主动 saveToPreferences 一次即可让 iOS 把当前 App 的真实
        //    版本号/时间戳写进 VPN 配置，消除系统设置里的红色提示
        //
        // 2) 清理旧 TrollStore 重装留下的残留条目：providerBundleIdentifier
        //    是老签名/老版本的 .PrismVPN，新 App loadAllFromPreferences
        //    返回空数组（配置指向的扩展 App ID 与签名不匹配），但系统
        //    设置里残留为只读条目，用户看起来就是"需要 2 次添加"
        //
        // 3) 确保第一次 saveToPreferences 时 providerBundleIdentifier
        //    与当前真实 appex 完全一致——万一 discoverExtensionBundleID
        //    失败回落硬编码 fallback，这里也能二次校验
        preCleanAndSyncVersion {
            self.loadOrCreateManager { result in
                switch result {
                case .failure(let error):
                    self.recoverOrFinish(
                        error, configPath: configPath,
                        attemptsRemaining: attemptsRemaining, completion: completion
                    )
                case .success(let manager):
                    self.configureSaveAndStart(
                        manager: manager, configPath: configPath,
                        attemptsRemaining: attemptsRemaining, completion: completion
                    )
                }
            }
        }
    }

    /// 启动前一次性预处理：遍历全部 VPN 配置，
    /// - 找到与当前 extensionBundleIdentifier 匹配的条目 → 直接结束清理，
    ///   仅主动 saveToPreferences 让 iOS 把当前 App 版本号/签名时间戳
    ///   同步进 VPN 配置（消除"需要更新"提示）——绝不删除任何配置
    ///   （build 143 方案第 2 步：误删合法配置 → managers=0 → 反复授权弹窗）
    /// - 仅在无任何匹配条目时，才清理旧签名/旧 bundle 的 Prism 残留
    private func preCleanAndSyncVersion(completion: @escaping () -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            guard let managers = managers else {
                if let error = error {
                    NSLog("[PrismVPN] preClean loadAllFromPreferences 失败: \(error.localizedDescription)")
                }
                completion()
                return
            }
            let group = DispatchGroup()
            var matched: NETunnelProviderManager?
            var stale = [NETunnelProviderManager]()
            // 匹配判断用硬编码期望值而非运行时发现的 extensionBundleID：
            // discoverExtensionBundleID 失败回落时会误把本来匹配的配置
            // 当"旧残留"删掉 → 用户被迫二次授权弹窗（managers=0 的来源）
            let expectedExtID = "com.prism.proxy.PrismVPN"
            for manager in managers {
                guard let proto = manager.protocolConfiguration
                    as? NETunnelProviderProtocol else { continue }
                let isOurs = proto.providerBundleIdentifier?.hasSuffix(".PrismVPN") == true
                guard isOurs else { continue }
                if proto.providerBundleIdentifier == expectedExtID {
                    // 匹配即结束清理（build 143 方案）：找到合法配置后
                    // 不得再删除任何条目（包括其他 .PrismVPN 残留——
                    // 宁可留旧条目也不能动合法配置）
                    matched = manager
                    break
                }
                stale.append(manager)
            }
            if let matched = matched {
                // 【build 169 方案】版本变化（TrollStore 覆盖安装）：只调用
                // 一次 PrismHelper killext 清理驻留的旧版扩展进程。严禁
                // stopVPNTunnel → isEnabled=false → save → enable → save
                // 连续双写——旧扩展进程仍驻留内存时极易卡死
                // nesessionmanagerd（build 168 真机实证：首启必报 Code=12
                // 且 hb=无），也绝不调用 rootHelper uicache
                let current = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
                let last = UserDefaults.standard.string(forKey: "prism_last_build_version")
                if last != current {
                    UserDefaults.standard.set(current, forKey: "prism_last_build_version")
                    NSLog("[PrismVPN] 检测到覆盖安装 \(last ?? "无") -> \(current)：killext 清理驻留旧版扩展进程")
                    PrismTunnelController.killStaleExtensionProcess()
                }
                // 保持 isEnabled=true，单次 save 同步当前 App 版本号/签名
                // 时间戳（消除"需要更新"红色提示）
                NSLog("[PrismVPN] 匹配配置已存在，跳过清理，直接 save 同步版本号")
                group.enter()
                matched.saveToPreferences { _ in group.leave() }
            } else {
                for manager in stale {
                    NSLog("[PrismVPN] 无匹配配置，仅清理旧签名残留: \(String(describing: (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier))")
                    group.enter()
                    manager.removeFromPreferences { _ in group.leave() }
                }
            }
            group.notify(queue: .main) { completion() }
        }
    }

    /// 失败出口：Code=12 且扩展无心跳时执行一次性自愈——killext 杀掉
    /// 卡死的旧驻留扩展进程，reload 会话句柄后 1.0s 重试一次启动；
    /// 其余错误直接交回上层。
    /// 【build 169 方案】任何路径都绝不删除已保存的 VPN 配置（误删 →
    /// managers=0 → 反复授权弹窗；且新建配置首启必报 Code=12，删配置
    /// 即形成「新建→报错→被删」死循环，build 168 真机实证）
    private func recoverOrFinish(
        _ error: Error,
        configPath: String,
        attemptsRemaining: Int,
        completion: @escaping (Error?) -> Void
    ) {
        if PrismTunnelController.isVPNAppNotInstalled(error) {
            // App 运行期严禁调用 rootHelper（uicache 会注销运行中的 App
            // → 会话失效）。Code=14 仅记录诊断交回上层
            NSLog("[PrismVPN] Code=14 插件未注册（App 运行期不调 uicache，交由用户重装/TrollStore 处理）")
        }
        // Code=12 且 hb=无：旧版 PrismVPN 进程驻留占住 nesessionmanager
        // 会话的典型指纹，配置本身是好的——严禁删除；只杀卡死的旧扩展
        // 进程，reload 后自动重试一次（code12SelfHealed 置位，仅一次，
        // 再次失败直接交回上层，绝不循环）
        if !PrismTunnelController.code12SelfHealed,
           PrismTunnelController.isCode12WithNoHeartbeat(error)
        {
            PrismTunnelController.code12SelfHealed = true
            NSLog("[PrismVPN] Code=12 且 hb=无：保留 VPN 配置，killext 清理旧扩展进程后自愈重试一次")
            // 只调 PrismHelper killext（杀旧 PrismVPN 进程）；
            // 绝不调用 uicache / rootHelper
            PrismTunnelController.killStaleExtensionProcess()
            // reload 刷新系统会话句柄（nesessionmanagerd 重新绑定），
            // 1.0s 后重试启动
            NETunnelProviderManager.loadAllFromPreferences { managers, _ in
                PrismTunnelController.lastManagerCount = managers?.count ?? 0
                NSLog("[PrismVPN] 自愈 reload 完成（\(managers?.count ?? 0) 个配置全部保留），1.0s 后重试启动")
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
                    self.startAttempt(
                        configPath: self.lastStartConfigPath.isEmpty ? configPath : self.lastStartConfigPath,
                        attemptsRemaining: attemptsRemaining,
                        completion: completion
                    )
                }
            }
            return
        }
        completion(error)
    }

    private func configureSaveAndStart(
        manager: NETunnelProviderManager,
        configPath: String,
        attemptsRemaining: Int,
        completion: @escaping (Error?) -> Void
    ) {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = extensionBundleIdentifier
        proto.serverAddress = managerServerTag
        proto.disconnectOnSleep = false
        // 只传路径（短），避开 NETunnelProviderManager
        // providerConfiguration 512KB 限制
        proto.providerConfiguration = ["config_path": configPath]

        manager.protocolConfiguration = proto
        manager.isEnabled = true

        manager.saveToPreferences { saveError in
            if let saveError = saveError {
                NSLog("[PrismVPN] saveToPreferences 失败: \(PrismTunnelController.describe(error: saveError))")
                self.recoverOrFinish(
                    saveError, configPath: configPath,
                    attemptsRemaining: attemptsRemaining, completion: completion
                )
                return
            }
            NSLog("[PrismVPN] saveToPreferences 成功, extBundleId=\(extensionBundleIdentifier)")

            // 【build 169 方案·关键】新建或修改配置 saveToPreferences 成功
            // 后，必须重新 loadFromPreferences 从系统刷新会话句柄——
            // nesessionmanagerd 完成会话绑定前直接 startVPNTunnel 必报
            // Code=12 且扩展进程根本不被拉起（hb=无）。loadFromPreferences
            // 完成后再等 0.8s 确保绑定落定，随后直接在已绑定的 manager
            // 上启动隧道（取代旧的「通知等待 + loadAllFromPreferences 重查」
            // 链路——0.5s 兜底过短，build 168 真机实证首启必失败）
            manager.loadFromPreferences { loadError in
                if let loadError = loadError {
                    NSLog("[PrismVPN] loadFromPreferences 失败: \(PrismTunnelController.describe(error: loadError))")
                    self.recoverOrFinish(
                        loadError, configPath: configPath,
                        attemptsRemaining: attemptsRemaining, completion: completion
                    )
                    return
                }
                self.activeManager = manager
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                    self.launchTunnelSession(
                        manager: manager,
                        attemptsRemaining: attemptsRemaining,
                        completion: completion
                    )
                }
            }
        }
    }

    /// 在已完成 saveToPreferences + loadFromPreferences 的 manager 上
    /// 发起 startVPNTunnel 并等待连接结果（build 169 方案）
    private func launchTunnelSession(
        manager: NETunnelProviderManager,
        attemptsRemaining: Int,
        completion: @escaping (Error?) -> Void
    ) {
        do {
            try manager.connection.startVPNTunnel()
            NSLog("[PrismVPN] startVPNTunnel 调用成功")

            waitForConnected(connection: manager.connection, timeout: 20) { err in
                if let err = err {
                    self.recoverOrFinish(
                        err, configPath: "",
                        attemptsRemaining: attemptsRemaining, completion: completion
                    )
                } else {
                    completion(nil)
                }
            }
        } catch {
            NSLog("[PrismVPN] startVPNTunnel 失败: \(PrismTunnelController.describe(error: error))")
            self.recoverOrFinish(
                error, configPath: "",
                attemptsRemaining: attemptsRemaining, completion: completion
            )
        }
    }

    /// 监听 NEVPNStatusDidChange，直到 connected / disconnected / 超时
    private func waitForConnected(
        connection: NEVPNConnection,
        timeout: TimeInterval,
        completion: @escaping (Error?) -> Void
    ) {
        var observer: NSObjectProtocol?
        var completed = false
        var timer: Timer?

        let finish: (Error?) -> Void = { error in
            guard !completed else { return }
            completed = true
            if let o = observer {
                NotificationCenter.default.removeObserver(o)
            }
            timer?.invalidate()
            completion(error)
        }

        // 立即检查当前状态
        if connection.status == .connected {
            NSLog("[PrismVPN] 状态已是 connected")
            finish(nil)
            return
        }

        observer = NotificationCenter.default.addObserver(
            forName: NSNotification.Name.NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { note in
            let status = connection.status
            NSLog("[PrismVPN] NEVPNStatusDidChange: \(status.rawValue)")
            switch status {
            case .connected:
                // 闪连即崩检测：startTunnel 成功 → connected → 扩展进程
                // 随后崩溃/被杀 → 系统静默断开。若立即 finish(nil)，
                // observer 移除后的断开无人感知，UI 报成功而隧道已死
                //（真机观测：App 显示成功但状态栏无 VPN 图标）。
                // 因此 connected 后再观察 3s：期间断开 → 走 describeDisconnect
                // 报真实原因；稳定 3s 后还要读扩展心跳——TrollStore 假
                // 团队配置可能上报【假 connected】（扩展从未被拉起），
                // 心跳是进程存活的唯一可靠证据（真机观测：状态 connected
                // 但状态栏无图标、扩展 API 无监听 → 节点栏"暂无节点"）。
                NSLog("[PrismVPN] connected, 稳定观察 3s + 心跳验证")
                DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                    // completed=true 说明期间已因断开/超时 finish，跳过
                    let hb = PrismTunnelController.readExtensionHeartbeat()
                    if hb.alive {
                        NSLog("[PrismVPN] 心跳验证通过 (stage=\(hb.stage), age=\(hb.age)s)")
                        // APP-5 任务2：记录「隧道曾成功连接」，供覆盖升级后
                        // 判断是否需要自动重建隧道
                        UserDefaults.standard.set(
                            true, forKey: PrismTunnelController.kWasConnectedKey)
                        finish(nil)
                        // 连接成功后启动巨魔看门狗：扩展被 Jetsam 静默强杀
                        // 且系统丢弃断开通知时，靠心跳时间戳兜底判死
                        self.startVpnWatchdog()
                        // 连接成功后启动长期断开监听：扩展崩溃/系统断开会
                        // 触发 NEVPNStatusDidChange(disconnected)，若无人
                        // 感知，App 将永远显示"已连接"而隧道实际已死
                        //（build 132 真机观测）
                        self.installDisconnectWatcher(connection: connection)
                        return
                    }
                    NSLog("[PrismVPN] 假连接: 状态 connected 但扩展无心跳 (stage=\(hb.stage), age=\(hb.age)s)")
                    finish(NSError(
                        domain: "PrismVPN", code: -6,
                        userInfo: [NSLocalizedDescriptionKey:
                            "系统状态 connected 但扩展进程无心跳（stage=\(hb.stage), age=\(hb.age)s）" +
                            "——扩展从未被系统拉起（TrollStore 假签名配置的状态显示不可信），" +
                            "注册层仍需修复；这不是内核或配置问题"]
                    ))
                }
            case .disconnected:
                // 解析真实断开原因（共享错误文件 → iOS16 系统 API → 通用描述）
                self.describeDisconnect(connection: connection) { desc, underlying in
                    // 底层 NSError 经 NSUnderlyingErrorKey 透传，
                    // 供 isStaleOrInvalid 识别 code=14 触发重建重试
                    var userInfo: [String: Any] = [
                        NSLocalizedDescriptionKey: desc
                    ]
                    if let underlying = underlying {
                        userInfo[NSUnderlyingErrorKey] = underlying
                    }
                    finish(NSError(
                        domain: "PrismVPN", code: -2,
                        userInfo: userInfo
                    ))
                }
            case .invalid:
                finish(NSError(
                    domain: "PrismVPN", code: -3,
                    userInfo: [NSLocalizedDescriptionKey: "VPN 配置无效（status=invalid）"]
                ))
            default:
                break // connecting / reasserting / disconnecting 继续等
            }
        }

        // 超时计时器
        timer = Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { _ in
            finish(NSError(
                domain: "PrismVPN", code: -4,
                userInfo: [NSLocalizedDescriptionKey:
                    "VPN 启动超时（\(Int(timeout))s），扩展未进入 connected 状态；当前 status=\(connection.status.rawValue)"]
            ))
        }
        RunLoop.main.add(timer!, forMode: .common)
    }

    /// 连接成功后的长期断开监听。
    /// 扩展进程崩溃 / 系统回收 / 内核失败 cancelTunnelWithError 都会以
    /// NEVPNStatusDidChange(.disconnected) 体现；若无人在场感知，UI 将
    /// 永远停留在"已连接"。这里把断开原因写进共享错误文件并打日志，
    /// 用户下次重试启动时即可看到真实原因（startAttempt 开头才会清理）。
    private func installDisconnectWatcher(connection: NEVPNConnection) {
        // 旧的长期监听先拆除，避免重复安装导致多个 observer 叠加
        if let old = disconnectWatcher {
            NotificationCenter.default.removeObserver(old)
            disconnectWatcher = nil
        }
        disconnectWatcher = NotificationCenter.default.addObserver(
            forName: NSNotification.Name.NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { [weak self] _ in
            guard connection.status == .disconnected else { return }
            // 立即拆除自身：一次断开只报告一次
            if let token = self?.disconnectWatcher {
                NotificationCenter.default.removeObserver(token)
                self?.disconnectWatcher = nil
            }
            // 同步拆除看门狗：VPN 已断开，心跳冻结是预期行为，不再判死
            self?.stopVpnWatchdog()
            NSLog("[PrismVPN] 连接成功后检测到断开，读取原因")
            self?.describeDisconnect(connection: connection) { desc, _ in
                NSLog("[PrismVPN] 连接后断开原因: \(desc)")
                if let groupURL = FileManager.default.containerURL(
                    forSecurityApplicationGroupIdentifier: prismAppGroupID
                ) {
                    let ts = Int(Date().timeIntervalSince1970)
                    try? "\(ts) 连接后断开: \(desc)".write(
                        to: groupURL.appendingPathComponent("prism_error.txt"),
                        atomically: true, encoding: .utf8
                    )
                }
            }
        }
    }

    /// 【APP16 任务3】扩展心跳结果：用结构体替代命名元组。
    struct ExtensionHeartbeat {
        let alive: Bool
        let stage: String
        let age: Int
    }

    /// 读取扩展心跳（prism_status.txt，扩展每 60s 刷新）。
    /// TrollStore 假团队配置下系统可能上报假 connected（扩展进程从未
    /// 被拉起），心跳是扩展存活的唯一可靠证据。
    static func readExtensionHeartbeat() -> ExtensionHeartbeat {
        guard let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: prismAppGroupID
        ) else { return ExtensionHeartbeat(alive: false, stage: "appGroup不可用", age: -1) }
        guard let text = try? String(
            contentsOf: groupURL.appendingPathComponent("prism_status.txt"),
            encoding: .utf8
        ), !text.isEmpty else {
            return ExtensionHeartbeat(alive: false, stage: "无心跳文件", age: -1)
        }
        let parts = text.split(separator: " ")
        guard let ts = Double(parts.first ?? "") else {
            return ExtensionHeartbeat(alive: false, stage: "心跳格式异常", age: -1)
        }
        let stage = parts.dropFirst().joined(separator: " ")
        let age = Int(Date().timeIntervalSince1970 - ts)
        // 心跳间隔已由 3s 调整为 60s（低功耗）：宽限期取 90s，
        // 允许一次心跳延迟仍判定存活，避免锁屏/后台挂起误判
        return ExtensionHeartbeat(alive: age <= 90, stage: stage, age: age)
    }

    /// 读取 App Group 共享错误文件（扩展写入的内核错误原文/断开原因）。
    /// 看门狗判死时优先取这里的精确报错，读不到再给通用 Jetsam 描述
    static func readSharedErrorFile() -> String? {
        guard let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: prismAppGroupID
        ) else { return nil }
        guard let text = try? String(
            contentsOf: groupURL.appendingPathComponent("prism_error.txt"),
            encoding: .utf8
        ), !text.isEmpty else { return nil }
        return sanitizeKernelError(text)
    }

    // MARK: - 巨魔看门狗：扩展被 Jetsam 静默强杀的兜底判死
    //
    // TrollStore App 的插件极易受到 iOS Jetsam 内存监控（15MB/50MB）
    // 的物理制裁直接被强杀，此时 iOS 可能静默丢弃断开通知，App 将
    // 永远显示"已连接"。连接成功后每 4s 轮询扩展心跳文件
    //（prism_status.txt，扩展每 60s 刷新），时间戳冻结（>90s 未更新）
    // 即判定内核死亡，强制重置本地 VPN 状态并回报错误。

    private func startVpnWatchdog() {
        stopVpnWatchdog()
        // Timer 创建须在主线程（scheduledTimer 挂当前 runloop）
        guard Thread.isMainThread else {
            DispatchQueue.main.async { self.startVpnWatchdog() }
            return
        }
        vpnWatchdogTimer = Timer.scheduledTimer(withTimeInterval: 4.0, repeats: true) { [weak self] _ in
            guard let self = self,
                  let manager = self.activeManager,
                  manager.connection.status == .connected
            else { return }

            let hb = PrismTunnelController.readExtensionHeartbeat()
            // alive = 心跳时间戳距今 ≤ 10s（readExtensionHeartbeat 内置判定，
            // 等价于 IPA.txt 的 alive && (now - timestamp < 10)）
            guard hb.alive else {
                // ipa-8 隐患 A（锁屏误杀）：iOS 休眠会挂起后台进程的 Timer，
                // 扩展心跳文件停在睡眠前的时间戳，但 utun 网卡与 Go 隧道
                // 仍在正常待机；亮屏瞬间主 App 的定时器先于扩展心跳恢复
                // 触发，会读到滞后时间戳。以系统 connection.status 为准：
                // 只要系统仍认为已连接/重连中，绝不因心跳滞后调用
                // stopVPNTunnel——扩展真被 Jetsam 强杀时 nesessionmanagerd
                // 会立刻把 status 置为 .disconnected，由 NEVPNStatusDidChange
                // 监听器处理断开回报，无需心跳文件判死
                let st = manager.connection.status
                if st == .connected || st == .reasserting || st == .connecting {
                    NSLog("[PrismVPN] 心跳滞后 (stage=\(hb.stage), age=\(hb.age)s) 但系统状态仍为 \(st.rawValue)（疑似锁屏休眠），保持连接不误杀")
                    return
                }

                NSLog("[PrismVPN] 扩展心跳丢失 (stage=\(hb.stage), age=\(hb.age)s)，判定为内核已在后台崩溃！")
                self.stopVpnWatchdog()

                // 读取精确报错；扩展来不及写文件时给通用 Jetsam 描述
                let errorMsg = PrismTunnelController.readSharedErrorFile()
                    ?? "插件因内存不足(Jetsam)或其他原因被系统强杀"

                // 1. 断开原因落盘：断开原因回显与下次启动诊断都从这里读取
                if let groupURL = FileManager.default.containerURL(
                    forSecurityApplicationGroupIdentifier: prismAppGroupID
                ) {
                    let ts = Int(Date().timeIntervalSince1970)
                    try? "\(ts) 看门狗判死: \(errorMsg)".write(
                        to: groupURL.appendingPathComponent("prism_error.txt"),
                        atomically: true, encoding: .utf8
                    )
                }

                // 2. 通知监听方（Swift→Rust 暂无回调通道，预留扩展点）
                self.onVpnUnexpectedDisconnect?(errorMsg)

                // 3. 强行重置本地 VPN 状态（防止 iOS 卡在挂起状态）
                manager.connection.stopVPNTunnel()
                return
            }
        }
    }

    private func stopVpnWatchdog() {
        vpnWatchdogTimer?.invalidate()
        vpnWatchdogTimer = nil
    }

    /// 解析 VPN 断开原因，三级回退：
    /// 1. App Group「prism_error.txt」：扩展 startTunnel 失败时写入，
    ///    含内核返回的精确错误原文，兼容所有 iOS 版本
    /// 2. iOS 16+ 系统 API fetchLastDisconnectError（扩展进程崩溃等
    ///    来不及写文件的场景；code=14 也只在这里出现）
    /// 3. 通用描述
    ///
    /// 同时回传底层系统 NSError（若有），供上层做失效配置分类。
    private func describeDisconnect(
        connection: NEVPNConnection,
        completion: @escaping (String, Error?) -> Void
    ) {
        let generic = "扩展启动后立即断开（status=disconnected）"

        // 0. 扩展心跳判死：prism_status.txt 由扩展每 60s 刷新，时间戳
        // 超过 75s（一次心跳 + 15s 裕度）未更新 = 扩展进程已崩溃/被杀。
        // 这一信息在扩展来不及写错误文件时是唯一的死因线索。
        if let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: prismAppGroupID
        ) {
            let statusFile = groupURL.appendingPathComponent("prism_status.txt")
            if let text = try? String(contentsOf: statusFile, encoding: .utf8),
               let tsText = text.split(separator: " ").first,
               let ts = Double(tsText)
            {
                let age = Date().timeIntervalSince1970 - ts
                if age > 75 {
                    let stage = text.split(separator: " ").dropFirst().joined(separator: " ")
                    let crash = "扩展进程已崩溃（心跳停于 \(Int(age))s 前，阶段=\(stage)）"
                    NSLog("[PrismVPN] \(crash)")
                    completion(crash, nil)
                    return
                }
            }
        }

        // 1. 共享错误文件
        if let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: prismAppGroupID
        ) {
            let errFile = groupURL.appendingPathComponent("prism_error.txt")
            if let text = try? String(contentsOf: errFile, encoding: .utf8),
               !text.isEmpty
            {
                NSLog("[PrismVPN] 读到共享错误: \(text)")
                completion(text, nil)
                return
            }
        }

        // 2. iOS 16+ 系统 API。completionHandler 可能在后台线程回调，
        // 统一切回主线程，避免与超时计时器产生 finish 竞态
        if #available(iOS 16, *) {
            connection.fetchLastDisconnectError { err in
                let desc = err.map {
                    PrismTunnelController.describe(error: $0)
                } ?? generic
                if err != nil {
                    NSLog("[PrismVPN] fetchLastDisconnectError: \(desc)")
                }
                DispatchQueue.main.async { completion(desc, err) }
            }
        } else {
            // 3. iOS 14/15 无系统 API 且扩展未写文件（如进程被系统直接杀死）
            completion(generic, nil)
        }
    }

    func stop(completion: @escaping (Error?) -> Void) {
        // 主动停止：先拆看门狗，避免停止期间心跳冻结被误判为崩溃
        stopVpnWatchdog()
        // APP-5 任务2：用户主动断开 → 清除「曾连接」标记，
        // 避免下次升级时误判为需要自动重建隧道
        UserDefaults.standard.set(
            false, forKey: PrismTunnelController.kWasConnectedKey)
        loadOrCreateManager { result in
            switch result {
            case .failure(let error):
                completion(error)
            case .success(let manager):
                manager.connection.stopVPNTunnel()
                // 等待 disconnected 确认（与 start 对称）
                self.waitForDisconnected(connection: manager.connection, timeout: 10) { _ in
                    self.activeManager = nil
                    completion(nil)
                }
            }
        }
    }

    /// 监听 NEVPNStatusDidChange，直到 disconnected / invalid / 超时
    private func waitForDisconnected(
        connection: NEVPNConnection,
        timeout: TimeInterval,
        completion: @escaping (Error?) -> Void
    ) {
        var observer: NSObjectProtocol?
        var completed = false
        var timer: Timer?

        let finish: (Error?) -> Void = { error in
            guard !completed else { return }
            completed = true
            if let o = observer { NotificationCenter.default.removeObserver(o) }
            timer?.invalidate()
            completion(error)
        }

        if connection.status == .disconnected || connection.status == .invalid {
            finish(nil)
            return
        }

        observer = NotificationCenter.default.addObserver(
            forName: NSNotification.Name.NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { _ in
            let status = connection.status
            NSLog("[PrismVPN] stop status change: \(status.rawValue)")
            if status == .disconnected || status == .invalid {
                finish(nil)
            }
        }

        timer = Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { _ in
            finish(NSError(
                domain: "PrismVPN", code: -5,
                userInfo: [NSLocalizedDescriptionKey: "VPN 停止超时（\(Int(timeout))s）"]
            ))
        }
        RunLoop.main.add(timer!, forMode: .common)
    }

    // MARK: - Manager 持久化

    private func loadOrCreateManager(
        completion: @escaping (Result<NETunnelProviderManager, Error>) -> Void
    ) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                NSLog("[PrismVPN] loadAllFromPreferences 失败: \(PrismTunnelController.describe(error: error))")
                completion(.failure(error))
                return
            }
            let all = managers ?? []
            PrismTunnelController.lastManagerCount = all.count
            NSLog("[PrismVPN] loadAllFromPreferences 成功, 找到 \(all.count) 个 manager")

            // 匹配即复用（IPA.txt 第 3 步 / ipa2.txt 清单 5）：
            // 旧「影子配置清道夫」每次启动全删重建，是 managers=0 与
            // 第二次「添加 VPN 配置」授权弹窗的根源（build 137/138 实证）。
            // 旧签名残留条目已由 preCleanAndSyncVersion 处理（只删
            // providerBundleIdentifier 不匹配的 .PrismVPN 条目），此处
            // 匹配到的直接复用，找不到才新建。
            let expectedExtID = "com.prism.proxy.PrismVPN"
            let matched = all.first { manager in
                (manager.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerBundleIdentifier == expectedExtID
            }
            if let matched = matched {
                NSLog("[PrismVPN] 复用既有 VPN 配置 (provider=\(expectedExtID))")
                completion(.success(matched))
            } else {
                if !all.isEmpty {
                    NSLog("[PrismVPN] \(all.count) 个配置均无匹配 provider，新建 manager")
                }
                completion(.success(NETunnelProviderManager()))
            }
        }
    }

    /// 删除 App Group 中的诊断残留（主 App 侧清理）。
    /// - prism_error.txt：code=14 场景下扩展进程根本不会启动，扩展端
    ///   clearSharedError 无法执行，必须由主 App 在每轮启动前主动清除
    /// - prism_status.txt：扩展心跳。【必须同步清除】否则 10s 内重试
    ///   启动时，上一轮扩展的旧心跳会被 readExtensionHeartbeat 误判为
    ///   本次存活，假连接穿透心跳验证（build 130 真机复现）
    private func clearSharedErrorFile() {
        guard let groupURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: prismAppGroupID
        ) else { return }
        try? FileManager.default.removeItem(
            at: groupURL.appendingPathComponent("prism_error.txt")
        )
        try? FileManager.default.removeItem(
            at: groupURL.appendingPathComponent("prism_status.txt")
        )
    }

    /// 【build 169 方案】无条件删除全部 VPN 配置的入口已从启动/自愈
    /// 失败路径移除（误删合法配置 → managers=0 → 反复授权弹窗 +
    /// 新建配置首启必报 Code=12 的死循环）。

    private func reload(
        manager: NETunnelProviderManager,
        completion: @escaping (Result<NETunnelProviderManager, Error>) -> Void
    ) {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error = error {
                completion(.failure(error))
                return
            }
            // 严格匹配：server 标签 + 当前预期的扩展 bundle ID。
            // save 成功却找不到配置 → 按失效处理，交由上层重建重试，
            // 不再回落给 in-memory manager（其 connection 未持久化，
            // startVPNTunnel 必然失败）。
            let saved = managers?.first {
                guard let proto = $0.protocolConfiguration as? NETunnelProviderProtocol,
                      proto.serverAddress == managerServerTag
                else { return false }
                return proto.providerBundleIdentifier == extensionBundleIdentifier
            }
            if let saved = saved {
                completion(.success(saved))
            } else {
                completion(.failure(NSError(
                    domain: "NEVPNErrorDomain", code: 1,
                    userInfo: [NSLocalizedDescriptionKey:
                        "save 后未找到与 \(extensionBundleIdentifier) 匹配的持久化 VPN 配置"]
                )))
            }
        }
    }
}

// MARK: - Keychain 辅助（kSecAttrSynchronizable = false）

private enum PrismKeychain {
    /// 从 Keychain 读字符串值；不存在返回 nil
    static func get(account: CFString) -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: false,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let str = String(data: data, encoding: .utf8)
        else { return nil }
        return str
    }

    /// 写入 Keychain（不存在则 add，存在则 update）；成功返回 true
    static func set(account: CFString, value: String) -> Bool {
        let data = Data(value.utf8)
        let base: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: account,
            kSecAttrSynchronizable: false,
        ]
        let addQuery = base
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecSuccess {
            return SecItemUpdate(addQuery as CFDictionary, [kSecValueData: data] as CFDictionary) == errSecSuccess
        }
        if status == errSecDuplicateItem {
            return SecItemUpdate(addQuery as CFDictionary, [kSecValueData: data] as CFDictionary) == errSecSuccess
        }
        return false
    }
}

// MARK: - SHA-256 工具

import CommonCrypto

private extension String {
    /// 返回 64 字符小写 hex SHA-256
    func sha256Hex() -> String {
        let data = Data(self.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, UInt32(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
