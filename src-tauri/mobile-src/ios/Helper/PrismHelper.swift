// PrismHelper — 随包 root helper（Mach-O CLI，TrollStore 环境专用）
//
// 由主 App 以 root persona（persona-mgmt + no-sandbox entitlement）spawn，
// 职责：
//   1. register — 用 LSApplicationWorkspace 强扭注册主 App + 扩展
//      （registerApplicationDictionary: 完整官方字典 + registerPlugin:）
//   2. fixperm  — Bundle 目录/文件属主修回 _installd:_installd (33:33)，
//      目录/可执行 0755、其余 0644；数据容器目录设为 mobile(501:501)。
//      Bundle 内容绝不能 chown 成 mobile(501:501)：pkd/launchd 认为普通
//      用户属主的系统插件二进制可被篡改，直接拒绝执行（build 138 实证）
// 每一步结果打印到 stdout（形如 result=...），由主 App 捕获进诊断。
//
// build 141 加固（build 140 实证 sig=11 崩溃链）：
//   a. 所有私有 ObjC 调用改用 class_getMethodImplementation +
//      @convention(c) 函数指针：registerApplicationDictionary:/
//      registerPlugin: 返回原生 BOOL，绝不能用 NSObject.perform（返回
//      Unmanaged<AnyObject>——返回 YES 时 ARC 对 0x1 调 objc_retain，
//      当场 SIGSEGV）。BOOL 返回严格用 ObjCBool 接收
//   b. Entitlements 提取：直接扫描 Mach-O 0xfade7171
//      (CS_MAGIC_EMBEDDED_ENTITLEMENTS) + XML 解析，失败时用内置兜底
//      字典——step=ent 永远不会 main=0 appex=0（build 140 实证为 0，
//      SecStaticCode 系 API 在 iOS 真机返回 -50）
//   c. MCMPluginKitPluginDataContainer 增加文件系统级兜底：即使
//      containermanagerd 拒绝（调用方缺 container-manager 权限时），
//      也以 root 直接构建标准插件容器目录 + 元数据，消除 plugin=nil
//      与 pkdDir=absent

import Foundation
import CoreServices
import Security
import ObjectiveC

private let mainBundleID = "com.prism.proxy"
private let appexBundleID = "com.prism.proxy.PrismVPN"
private let appGroupID = "group.com.prism.proxy"

// MARK: - C ABI 函数指针定义（避免 NSObject.perform 在 BOOL 返回值上触发 SIGSEGV）

private typealias MCMContainerCreateFn = @convention(c) (
    AnyClass,
    Selector,
    NSString,
    ObjCBool,
    UnsafeMutablePointer<ObjCBool>?,
    UnsafeMutableRawPointer?
) -> Unmanaged<AnyObject>?

private typealias DefaultWorkspaceFn = @convention(c) (
    AnyClass,
    Selector
) -> Unmanaged<AnyObject>?

private typealias LSRegisterDictFn = @convention(c) (
    AnyObject,
    Selector,
    NSDictionary
) -> ObjCBool

private typealias LSRegisterPluginFn = @convention(c) (
    AnyObject,
    Selector,
    NSURL
) -> ObjCBool

// MARK: - 1. 提取 Mach-O 内嵌 Entitlements（带强兜底，绝不返回 0 项）

private func extractEntitlements(fromBinary path: String, isAppex: Bool) -> [String: Any] {
    // appex 兜底字典必须与 PrismVPN.entitlements.plist 保持一致：
    // build 145 恢复 no-sandbox（build 142 的归因已修正——Code=14 真凶
    // 是 selfHelper 用残缺字典覆盖官方注册表，pkd 并不拒绝免沙盒扩展，
    // build 138/140 带 no-sandbox 时期注册同样成功），并申请提升
    // 网络扩展 Jetsam 内存上限；主 App 侧字典保持 container-manager 等
    let fallback: [String: Any] = isAppex ? [
        "platform-application": true,
        "com.apple.private.security.no-sandbox": true,
        "com.apple.private.security.storage.AppDataContainers": true,
        "com.apple.developer.memory.increased-memory-limit": true,
        "com.apple.developer.kernel.increased-memory-limit": true,
        "application-identifier": "TROLLTROLL.\(appexBundleID)",
        "com.apple.developer.team-identifier": "TROLLTROLL",
        "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
        "com.apple.security.application-groups": [appGroupID]
    ] : [
        "platform-application": true,
        "com.apple.private.security.no-sandbox": true,
        "com.apple.private.security.container-manager": true,
        "com.apple.private.security.storage.AppDataContainers": true,
        "com.apple.private.persona-mgmt": true,
        "application-identifier": "TROLLTROLL.\(mainBundleID)",
        "com.apple.developer.team-identifier": "TROLLTROLL",
        "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
        "com.apple.security.application-groups": [appGroupID]
    ]

    guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)), data.count > 16 else {
        return fallback
    }

    // 搜索 CS_MAGIC_EMBEDDED_ENTITLEMENTS (0xFADE7171) + "<?xml"
    let magic = Data([0xFA, 0xDE, 0x71, 0x71])
    var searchRange = data.startIndex..<data.endIndex
    while let range = data.range(of: magic, options: [], in: searchRange) {
        let offset = range.lowerBound
        if offset + 8 <= data.count {
            let b0 = UInt32(data[offset + 4]) << 24
            let b1 = UInt32(data[offset + 5]) << 16
            let b2 = UInt32(data[offset + 6]) << 8
            let b3 = UInt32(data[offset + 7])
            let blobLen = Int(b0 | b1 | b2 | b3)
            if blobLen > 8 && offset + blobLen <= data.count {
                let xmlData = data.subdata(in: (offset + 8)..<(offset + blobLen))
                if let dict = (try? PropertyListSerialization.propertyList(from: xmlData, options: [], format: nil)) as? [String: Any],
                   !dict.isEmpty {
                    return dict
                }
            }
        }
        searchRange = (offset + 1)..<data.endIndex
    }
    return fallback
}

// MARK: - 2. 安全调用 MobileContainerManager 创建容器（带磁盘兜底）

private func getOrCreateMCMContainer(className: String, identifier: String) -> String? {
    _ = dlopen("/System/Library/PrivateFrameworks/MobileContainerManager.framework/MobileContainerManager", RTLD_NOW)
    guard let cls = NSClassFromString(className) else { return nil }
    let sel = NSSelectorFromString("containerWithIdentifier:createIfNecessary:existed:error:")
    guard let method = class_getClassMethod(cls, sel) else { return nil }
    let imp = method_getImplementation(method)
    let fn = unsafeBitCast(imp, to: MCMContainerCreateFn.self)

    var existed: ObjCBool = false
    guard let unmanaged = fn(cls, sel, identifier as NSString, ObjCBool(true), &existed, nil) else {
        return nil
    }
    let containerObj = unmanaged.takeUnretainedValue()
    if let url = (containerObj as AnyObject).value(forKey: "url") as? URL {
        return url.path
    }
    return nil
}

private func ensurePluginContainerOnDisk(pluginID: String) -> String {
    if let mcmPath = getOrCreateMCMContainer(className: "MCMPluginKitPluginDataContainer", identifier: pluginID),
       !mcmPath.isEmpty {
        return mcmPath
    }

    let baseDir = "/private/var/mobile/Containers/Data/PluginKitPlugin"
    let fm = FileManager.default
    if let items = try? fm.contentsOfDirectory(atPath: baseDir) {
        for uuid in items {
            let dir = "\(baseDir)/\(uuid)"
            let metaPath = "\(dir)/.com.apple.mobile_container_manager.metadata.plist"
            if let meta = NSDictionary(contentsOfFile: metaPath),
               (meta["MCMMetadataIdentifier"] as? String) == pluginID {
                return dir
            }
        }
    }

    // 磁盘兜底创建：当 containermanagerd 拒绝时，以 root 直接构建标准插件容器
    let newUUID = UUID().uuidString.uppercased()
    let targetDir = "\(baseDir)/\(newUUID)"
    for sub in ["", "/Documents", "/Library", "/Library/Caches", "/Library/Preferences", "/tmp"] {
        try? fm.createDirectory(atPath: targetDir + sub, withIntermediateDirectories: true, attributes: [
            .ownerAccountID: 501,
            .groupOwnerAccountID: 501,
            .posixPermissions: 0o755
        ])
    }
    let meta: NSDictionary = [
        "MCMMetadataIdentifier": pluginID,
        "MCMMetadataContentClass": 4,
        "MCMMetadataUUID": newUUID,
        "MCMMetadataVersion": 1
    ]
    let metaPath = "\(targetDir)/.com.apple.mobile_container_manager.metadata.plist"
    meta.write(toFile: metaPath, atomically: true)
    chown(metaPath, 501, 501)
    return targetDir
}

private func ensureAppContainerOnDisk(appID: String) -> String {
    if let mcmPath = getOrCreateMCMContainer(className: "MCMAppDataContainer", identifier: appID),
       !mcmPath.isEmpty {
        return mcmPath
    }
    let baseDir = "/private/var/mobile/Containers/Data/Application"
    if let items = try? FileManager.default.contentsOfDirectory(atPath: baseDir) {
        for uuid in items {
            let dir = "\(baseDir)/\(uuid)"
            let metaPath = "\(dir)/.com.apple.mobile_container_manager.metadata.plist"
            if let meta = NSDictionary(contentsOfFile: metaPath),
               (meta["MCMMetadataIdentifier"] as? String) == appID {
                return dir
            }
        }
    }
    return "/private/var/mobile"
}

// MARK: - 3. 注册主程序与插件到 LSApplicationWorkspace

private func runRegister(appBundlePath: String) {
    let appexBundlePath = "\(appBundlePath)/PlugIns/PrismVPN.appex"
    let mainExecPath = "\(appBundlePath)/Prism"
    let appexExecPath = "\(appexBundlePath)/PrismVPN"

    let mainEnt = extractEntitlements(fromBinary: mainExecPath, isAppex: false)
    let appexEnt = extractEntitlements(fromBinary: appexExecPath, isAppex: true)
    print("result=reg step=ent main=\(mainEnt.count) appex=\(appexEnt.count)")
    fflush(stdout)

    let mainContainerPath = ensureAppContainerOnDisk(appID: mainBundleID)
    let pluginContainerPath = ensurePluginContainerOnDisk(pluginID: appexBundleID)

    var groupContainerMap: [String: String] = [:]
    let groups = (mainEnt["com.apple.security.application-groups"] as? [String]) ?? [appGroupID]
    for group in groups {
        if let gPath = getOrCreateMCMContainer(className: "MCMSharedDataContainer", identifier: group) {
            groupContainerMap[group] = gPath
        }
    }
    print("result=reg step=containers plugin=\(pluginContainerPath) groups=\(groupContainerMap.count)")
    fflush(stdout)

    // 【build 144 方案】必须以 Info.plist 为基底合并字段：
    // 从零新建的字典缺 NSExtension（扩展点声明）、CFBundleExecutable、
    // TeamIdentifier 等关键项，一旦写回 LaunchServices 会把官方注册
    // 的完整记录覆盖成残缺条目 → 扩展点标识被抹掉 → Code=14
    // （build 143 实证）。只在官方字段之上补充容器/签名信息
    guard let infoPlistRaw = NSDictionary(contentsOfFile: "\(appBundlePath)/Info.plist") as? [String: Any] else {
        print("result=reg ls=0 plugin=0 err=noInfoPlist")
        fflush(stdout)
        return
    }
    guard let appexInfoPlistRaw = NSDictionary(contentsOfFile: "\(appexBundlePath)/Info.plist") as? [String: Any] else {
        print("result=reg ls=0 plugin=0 err=noAppexInfoPlist")
        fflush(stdout)
        return
    }

    var pluginDict = appexInfoPlistRaw
    pluginDict["Entitlements"] = appexEnt
    pluginDict["GroupContainers"] = groupContainerMap
    pluginDict["Container"] = pluginContainerPath

    var appDict = infoPlistRaw
    appDict["Entitlements"] = mainEnt
    appDict["GroupContainers"] = groupContainerMap
    appDict["Container"] = mainContainerPath
    appDict["_LSBundlePlugins"] = [appexBundleID: pluginDict]

    guard let wsClass = NSClassFromString("LSApplicationWorkspace"),
          let defaultSel = NSSelectorFromString("defaultWorkspace") as Selector?,
          let defaultMethod = class_getClassMethod(wsClass, defaultSel) else {
        print("result=reg ls=0 plugin=0 err=noWorkspaceClass")
        fflush(stdout)
        return
    }

    let getWS = unsafeBitCast(method_getImplementation(defaultMethod), to: DefaultWorkspaceFn.self)
    guard let wsUnmanaged = getWS(wsClass, defaultSel) else {
        print("result=reg ls=0 plugin=0 err=nilWorkspace")
        fflush(stdout)
        return
    }
    let ws = wsUnmanaged.takeUnretainedValue()

    var lsOK = false
    let regDictSel = NSSelectorFromString("registerApplicationDictionary:")
    if let m = class_getInstanceMethod(wsClass, regDictSel) {
        let fn = unsafeBitCast(method_getImplementation(m), to: LSRegisterDictFn.self)
        lsOK = fn(ws, regDictSel, appDict as NSDictionary).boolValue
    }

    var pluginOK = false
    let regPluginSel = NSSelectorFromString("registerPlugin:")
    if let m = class_getInstanceMethod(wsClass, regPluginSel) {
        let fn = unsafeBitCast(method_getImplementation(m), to: LSRegisterPluginFn.self)
        let pluginURL = NSURL(fileURLWithPath: appexBundlePath)
        pluginOK = fn(ws, regPluginSel, pluginURL).boolValue
    }

    print("result=reg ls=\(lsOK ? 1 : 0) plugin=\(pluginOK ? 1 : 0)")
    fflush(stdout)
}

// MARK: - 4. 修复权限（Bundle 保持 _installd 33:33，数据容器设为 mobile 501:501）

private func runFixPerm(appBundlePath: String) {
    let pluginContainerPath = ensurePluginContainerOnDisk(pluginID: appexBundleID)
    let pkdState = FileManager.default.fileExists(atPath: pluginContainerPath) ? "present" : "absent"
    print("result=fixperm pkdDir=\(pkdState)")

    var fixed = 0
    var failed = 0
    let fm = FileManager.default

    // 【build 144 方案】不再对 Prism.app Bundle 做 chown/chmod：主 App
    // spawn 的 helper 并非真正的 setuid 环境（persona 提权后对系统
    // Bundle 目录 chown 仍会 EPERM），build 143 实证 fixed=0 failed=24
    // 纯属无效循环。Bundle 属主由 TrollStore 官方安装时置好
    // （_installd 33:33），无需也不应干预

    // 修复插件数据容器属主为 mobile (501:501)
    chown(pluginContainerPath, 501, 501)
    fixed += 1
    if let enumerator = fm.enumerator(atPath: pluginContainerPath) {
        for case let relPath as String in enumerator {
            let fullPath = "\(pluginContainerPath)/\(relPath)"
            if chown(fullPath, 501, 501) == 0 {
                fixed += 1
            } else {
                failed += 1
            }
        }
    }

    print("result=fixperm fixed=\(fixed) failed=\(failed)")
    fflush(stdout)
}

// MARK: - 入口

@main
struct PrismHelperMain {
    static func main() {
        setuid(0)
        setgid(0)

        let args = CommandLine.arguments
        let cmd = args.count > 1 ? args[1] : "register"
        let bundlePath: String = {
            if args.count > 2 && !args[2].isEmpty {
                return args[2]
            }
            return URL(fileURLWithPath: args[0]).deletingLastPathComponent().path
        }()

        switch cmd {
        case "register":
            runRegister(appBundlePath: bundlePath)
        case "fixperm":
            runFixPerm(appBundlePath: bundlePath)
        case "killext":
            runKillExt()
        case "resetne":
            runResetNE(appBundlePath: bundlePath)
        default:
            runRegister(appBundlePath: bundlePath)
            runFixPerm(appBundlePath: bundlePath)
        }
    }
}

/// 覆盖安装 / Code=12 自愈专用清场（不触碰主 App 注册，绝不触发 uicache 注销主进程）：
/// 1. 确保插件数据容器在磁盘就绪且属主为 mobile(501:501)；
/// 2. 仅对 PlugIns/PrismVPN.appex 调用 registerPlugin:（增量刷新新 UUID 路径，不卸载主 App）；
/// 3. 清理残留的旧 PrismVPN、neagent 与 pkd 进程，迫使 launchd 按最新 LaunchServices
///    路径拉起干净的插件宿主会话，根治 TrollStore 覆盖升级后 Code=12 且 hb=无。
private func runResetNE(appBundlePath: String) {
    let appexBundlePath = "\(appBundlePath)/PlugIns/PrismVPN.appex"
    let pluginContainerPath = ensurePluginContainerOnDisk(pluginID: appexBundleID)
    chown(pluginContainerPath, 501, 501)

    var pluginOK = false
    if FileManager.default.fileExists(atPath: appexBundlePath),
       let wsClass = NSClassFromString("LSApplicationWorkspace"),
       let defaultSel = NSSelectorFromString("defaultWorkspace") as Selector?,
       let defaultMethod = class_getClassMethod(wsClass, defaultSel)
    {
        let getWS = unsafeBitCast(method_getImplementation(defaultMethod), to: DefaultWorkspaceFn.self)
        if let wsUnmanaged = getWS(wsClass, defaultSel) {
            let ws = wsUnmanaged.takeUnretainedValue()
            let regPluginSel = NSSelectorFromString("registerPlugin:")
            if let m = class_getInstanceMethod(wsClass, regPluginSel) {
                let fn = unsafeBitCast(method_getImplementation(m), to: LSRegisterPluginFn.self)
                let pluginURL = NSURL(fileURLWithPath: appexBundlePath)
                pluginOK = fn(ws, regPluginSel, pluginURL).boolValue
            }
        }
    }

    let killed = killProcessesByNames(["PrismVPN", "neagent", "pkd"])
    print("result=resetne plugin=\(pluginOK ? 1 : 0) killed=\(killed)")
    fflush(stdout)
}

/// 杀掉后台驻留的旧版 PrismVPN 扩展进程（build 150 方案）：TrollStore
/// 覆盖安装只杀主 App 不杀扩展，旧 PrismVPN 进程挂在 nesessionmanager
/// 上但磁盘二进制已被新版覆盖，占住 VPN 会话导致新版 startTunnel 无法
/// 被拉起（Code=12 且 hb=无）。
private func runKillExt() {
    let killed = killProcessesByNames(["PrismVPN"])
    print("result=killext killed=\(killed)")
    fflush(stdout)
}

private func killProcessesByNames(_ targets: Set<String>) -> Int {
    let selfPid = getpid()

    guard let lib = dlopen("/usr/lib/system/libproc.dylib", RTLD_LAZY) else {
        print("result=killext err=dlopen")
        fflush(stdout)
        return 0
    }
    typealias ListAllPidsFn = @convention(c) (UnsafeMutableRawPointer?, Int32) -> Int32
    typealias PidPathFn = @convention(c) (pid_t, UnsafeMutablePointer<CChar>?, UInt32) -> Int32
    guard let listSym = dlsym(lib, "proc_listallpids"),
          let pathSym = dlsym(lib, "proc_pidpath") else {
        print("result=killext err=dlsym")
        fflush(stdout)
        return 0
    }
    let listAllPids = unsafeBitCast(listSym, to: ListAllPidsFn.self)
    let pidPath = unsafeBitCast(pathSym, to: PidPathFn.self)

    // 第一次调用取进程数，多留 16 个余量再取全表（防竞态遗漏）
    let total = listAllPids(nil, 0)
    guard total > 0 else {
        print("result=killext err=no-processes")
        fflush(stdout)
        return 0
    }
    let cap = Int(total) + 16
    var pids = [pid_t](repeating: 0, count: cap)
    let bufBytes = Int32(cap * MemoryLayout<pid_t>.stride)
    let count = pids.withUnsafeMutableBytes { raw -> Int32 in
        listAllPids(raw.baseAddress, bufBytes)
    }

    var killed = 0
    for i in 0..<max(Int(count), 0) {
        let pid = pids[i]
        guard pid > 0, pid != selfPid else { continue }
        var path = [CChar](repeating: 0, count: 4096)
        let len = path.withUnsafeMutableBufferPointer { buf -> Int32 in
            pidPath(pid, buf.baseAddress, 4096)
        }
        guard len > 0 else { continue }
        let execPath = String(cString: path)
        let execName = execPath.split(separator: "/").last.map(String.init) ?? ""
        if targets.contains(execName), kill(pid, SIGKILL) == 0 {
            killed += 1
            NSLog("[PrismHelper] SIGKILL \(execName) pid=\(pid) path=\(execPath)")
        }
    }
    return killed
}
