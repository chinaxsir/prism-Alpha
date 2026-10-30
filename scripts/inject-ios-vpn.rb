#!/usr/bin/env ruby
# frozen_string_literal: true

# 将 iOS VPN 网络扩展注入 `tauri ios init` 生成的工程。
#
# gen/apple 由 CLI 现生成，所有定制必须在 init 之后经本脚本幂等注入：
#   1. 拷贝 PacketTunnelProvider.swift / Info.plist / bridging header / entitlements
#   2. 新建 PrismVPN app-extension target（链接 libprismkernel.a，打包 geo 数据库）
#   3. 主 App target 加入 PrismTunnelController.swift 并链接 NetworkExtension framework
#   4. 主 App 依赖扩展并添加 Embed Foundation Extensions 拷贝阶段
require 'xcodeproj'
require 'json'
require 'fileutils'

ROOT = File.expand_path('..', __dir__)
GEN_APPLE = File.join(ROOT, 'src-tauri', 'gen', 'apple')
KERNEL_DIR = File.join(ROOT, 'src-tauri', 'ios-kernel')
EXT_NAME = 'PrismVPN'

# IPA-3 任务1：强制竖屏。
# Info.plist 里可能已存在 UISupportedInterfaceOrientations（Tauri 默认四方向），
# 必须先 Delete 再 Add，否则 PlistBuddy 的 Add 会因键已存在而失败。
#   - UISupportedInterfaceOrientations      → iPhone
#   - UISupportedInterfaceOrientations~ipad → iPad（不覆盖则 iPad 横屏仍可旋转）
def lock_portrait(plist)
  pb = '/usr/libexec/PlistBuddy'
  %w[UISupportedInterfaceOrientations UISupportedInterfaceOrientations~ipad].each do |key|
    system(pb, '-c', "Delete :#{key}", plist, out: File::NULL, err: File::NULL)
    ok = system(pb, '-c', "Add :#{key} array", plist, out: File::NULL, err: File::NULL)
    ok &&= system(pb, '-c', "Add :#{key}:0 string UIInterfaceOrientationPortrait",
                  plist, out: File::NULL, err: File::NULL)
    puts "  [orientation] #{key} => portrait (#{ok ? 'ok' : 'FAILED'})"
  end
  # 保险：plutil 校验 plist 仍是合法 XML/binary，防止注入损坏导致签名失败
  system('/usr/bin/plutil', '-lint', plist, out: File::NULL, err: File::NULL)
end

# 【APP26 任务3.1】主 App 强制深色外观。
# 防止 iOS SpringBoard 在浅色系统主题下为 App 切换动画生成白色快照底板，
# 进而导致上滑退后台缩成桌面图标时四角露白。键可能已存在，必须先 Delete。
def lock_dark_interface_style(plist)
  pb = '/usr/libexec/PlistBuddy'
  system(pb, '-c', 'Delete :UIUserInterfaceStyle', plist, out: File::NULL, err: File::NULL)
  ok = system(pb, '-c', 'Add :UIUserInterfaceStyle string Dark',
              plist, out: File::NULL, err: File::NULL)
  puts "  [dark-style] UIUserInterfaceStyle => Dark (#{ok ? 'ok' : 'FAILED'})"
  system('/usr/bin/plutil', '-lint', plist, out: File::NULL, err: File::NULL)
end

def inject
  project_path = Dir[File.join(GEN_APPLE, '*.xcodeproj')].first
  abort "[inject-ios-vpn] #{GEN_APPLE} 不存在，请先执行 npx tauri ios init" unless project_path

  project = Xcodeproj::Project.open(project_path)

  if project.targets.any? { |t| t.name == EXT_NAME }
    puts '[inject-ios-vpn] already injected, skip'
    return
  end

  app_target = project.targets.find { |t| t.product_type == 'com.apple.product-type.application' }
  abort '[inject-ios-vpn] 未找到主 App target' unless app_target

  # 默认值仅用于日志；真正的扩展 bundle ID 在下面按各构建配置分别匹配，
  # 避免 Debug/Release 主 App bundle ID 不一致时 appex 固定跟随第一个配置
  app_bundle_id = app_target.build_configurations.first.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] || 'com.prism.proxy'
  tauri_conf_path = File.join(ROOT, 'src-tauri', 'tauri.conf.json')
  raw_json = File.read(tauri_conf_path, encoding: 'bom|utf-8').sub(/\A\uFEFF/, '')
  version = JSON.parse(raw_json)['version']
  # CI 构建把 commit 短 SHA 写入 CFBundleVersion，App 启动失败时输出，
  # 用于远程确认用户实际安装的是哪个构建（排除装到旧 IPA 的歧义）
  # CI 构建在 mobile.yml 中用 GITHUB_RUN_NUMBER 覆盖 CFBundleVersion；
  # 此处设为纯数字 "1" 避免字母（Apple 规范禁止 CFBundleVersion 含字母，
  # NetworkExtension 底层验证器会静默拒载含字母的插件）
  current_project_version = '1'

  # 主 App 也同步打标 CFBundleVersion，App 内诊断输出 build= 即真实
  # 构建 SHA（此前只改了扩展 target，主 App 仍显示 0.3.7 无法辨识构建）
  app_target.build_configurations.each do |config|
    config.build_settings['CURRENT_PROJECT_VERSION'] = current_project_version
  end

  # CI 构建在 mobile.yml 中用 GITHUB_RUN_NUMBER 覆盖 CFBundleVersion，
  # 此处仅设占位纯数字（Apple 规范禁止字母）
  app_plist = File.join(GEN_APPLE, 'ios', 'App', 'Info.plist')
  if File.exist?(app_plist)
    system('/usr/libexec/PlistBuddy', '-c',
           "Set :CFBundleVersion 1", app_plist)
  end

  # IPA-3 任务1：全终端强制竖屏，禁止随设备旋转横屏（移动端布局仅适配竖屏）。
  # iPhone 与 iPad 两个方向键都要覆盖，否则 iPad 横屏仍会旋转。
  lock_portrait(app_plist) if File.exist?(app_plist)
  # APP26 任务3.1：强制深色外观，避免浅色主题下白底系统快照
  lock_dark_interface_style(app_plist) if File.exist?(app_plist)

  # ---- 1. 拷贝扩展源文件 ----
  ext_dir = File.join(GEN_APPLE, EXT_NAME)
  FileUtils.mkdir_p(ext_dir)
  src_dir = File.join(ROOT, 'src-tauri', 'mobile-src', 'ios', 'PrismVPN')
  Dir[File.join(src_dir, '*')].each { |f| FileUtils.cp(f, ext_dir) }
  FileUtils.cp(
    File.join(ROOT, 'src-tauri', 'mobile-src', 'ios', 'App', 'PrismTunnelController.swift'),
    GEN_APPLE
  )

  # ---- 2. 创建扩展 target ----
  ext_target = project.new_target(:app_extension, EXT_NAME, :ios, '14.0')

  group = project.main_group.new_group(EXT_NAME, EXT_NAME)
  swift_ref = group.new_file(File.join(ext_dir, 'PacketTunnelProvider.swift'))
  ext_target.add_file_references([swift_ref])

  # geo 数据库随扩展包分发（扩展进程内运行内核，直接读自身 Bundle）
  %w[geoip.db geosite.db].each do |db|
    src = File.join(ROOT, 'src-tauri', 'binaries', db)
    abort "[inject-ios-vpn] 缺少 #{src}（先执行 fetch-kernel.cjs --geo-only）" unless File.exist?(src)
    FileUtils.cp(src, File.join(ext_dir, db))
    ref = group.new_file(File.join(ext_dir, db))
    # PBXResourcesBuildPhase 没有 add_file 方法（CI 实证 NoMethodError），
    # 构建阶段加文件的正确 API 是 add_file_reference
    ext_target.resources_build_phase.add_file_reference(ref)
  end
  group.new_file(File.join(ext_dir, 'Info.plist'))

  common_settings = {
    'PRODUCT_NAME' => EXT_NAME,
    # 占位值，下面按各构建配置对应的主 App bundle ID 逐个覆盖
    'PRODUCT_BUNDLE_IDENTIFIER' => "#{app_bundle_id}.#{EXT_NAME}",
    'INFOPLIST_FILE' => "#{EXT_NAME}/Info.plist",
    'GENERATE_INFOPLIST_FILE' => 'NO',
    'CODE_SIGN_ENTITLEMENTS' => "#{EXT_NAME}/PrismVPN.entitlements.plist",
    'PRODUCT_MODULE_NAME' => EXT_NAME,
    'SWIFT_VERSION' => '5.0',
    'SWIFT_OBJC_BRIDGING_HEADER' => "#{EXT_NAME}/PrismVPN-Bridging-Header.h",
    'CLANG_ENABLE_MODULES' => 'YES',
    'TARGETED_DEVICE_FAMILY' => '1,2',
    'SKIP_INSTALL' => 'YES',
    'MARKETING_VERSION' => version.to_s,
    'CURRENT_PROJECT_VERSION' => current_project_version,
    # Go c-archive 头文件与静态库
    'HEADER_SEARCH_PATHS' => "$(inherited)\n\"#{KERNEL_DIR}\"",
    'LIBRARY_SEARCH_PATHS' => "$(inherited)\n\"#{KERNEL_DIR}\"",
    # 与 build.rs 主 App 链接一致的内核依赖
    'OTHER_LDFLAGS' => '$(inherited) -lprismkernel -lresolv -lz ' \
                       '-framework Security -framework Foundation ' \
                       '-framework CoreFoundation -framework SystemConfiguration ' \
                       '-framework CoreServices',
    # /usr/lib/swift 必须排第一（build 138 实证）：appex 是 Swift 二进制，
    # 默认 runpath 只有 @executable_path/{,../../}Frameworks——打包时
    # Frameworks 已删空（只留 back-deploy _Concurrency），@rpath/
    # libswiftCore.dylib 解析不到 / dyld 命中 ad-hoc back-deploy 副本
    # （撞 CS_REQUIRE_LV）→ 扩展在 main() 之前崩溃 → code=12。
    # 必须编译期写入，绝不能对 appex 用 install_name_tool 事后重写
    # （Xcode 直编的 Mach-O header 紧凑无 padding，重写越界损坏 → code 14）
    'LD_RUNPATH_SEARCH_PATHS' => '/usr/lib/swift $(inherited) @executable_path/Frameworks @executable_path/../../Frameworks',
    # 显式部署目标 15.0（build 144 方案）：tauri 模板默认 target 偏低，
    # 低 target 的 Swift 二进制会引用 back-deploy libswift_Concurrency
    # （Frameworks 里的 ad-hoc 副本，撞 CS_REQUIRE_LV）；15.0+ 直接用
    # 系统共享缓存内的并发库
    'IPHONEOS_DEPLOYMENT_TARGET' => '15.0',
  }
  ext_target.build_configurations.each do |cfg|
    cfg.build_settings.merge!(common_settings)
    # 扩展 bundle ID 必须与【同名构建配置】的主 App bundle ID 对齐：
    # 运行时主 App 以 Bundle.main.bundleIdentifier + ".PrismVPN"
    # 作为 providerBundleIdentifier，任何不一致都会触发系统
    # NEVPNConnectionErrorDomain code=14（VPN app not installed）
    app_cfg = app_target.build_configurations.find { |c| c.name == cfg.name } ||
              app_target.build_configurations.first
    cfg_bundle_id = app_cfg.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] || 'com.prism.proxy'
    cfg.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = "#{cfg_bundle_id}.#{EXT_NAME}"
  end

  # ---- 3. 主 App：隧道控制器 + NetworkExtension 框架 ----
  ctrl_ref = project.main_group.new_file(File.join(GEN_APPLE, 'PrismTunnelController.swift'))
  app_target.add_file_references([ctrl_ref])

  app_target.build_configurations.each do |cfg|
    flags = cfg.build_settings['OTHER_LDFLAGS'] || '$(inherited)'
    unless flags.include?('NetworkExtension')
      cfg.build_settings['OTHER_LDFLAGS'] = "#{flags} -framework Network -framework NetworkExtension"
    end
  end

  # ---- 4. 依赖 + 嵌入 ----
  app_target.add_dependency(ext_target)
  embed = app_target.new_copy_files_build_phase('Embed Foundation Extensions')
  embed.dst_subfolder_spec = '13' # PlugIns
  embed.add_file_reference(ext_target.product_reference)

  project.save
  puts "[inject-ios-vpn] injected #{EXT_NAME} (#{app_bundle_id}.#{EXT_NAME}) into #{File.basename(project_path)}"
end

inject
