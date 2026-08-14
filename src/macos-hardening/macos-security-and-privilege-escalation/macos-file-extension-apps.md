# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

这是 macOS 中所有已安装应用程序的数据库，可以查询每个已安装应用程序的信息，例如支持的 **URL schemes**、**document types**、**UTIs** 以及默认 handlers。

可以使用以下命令 dump 此数据库：
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
或者使用工具 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)。

**`/usr/libexec/lsd`** 是该数据库的核心。它提供了**多个 XPC 服务**，例如 `.lsd.installation`、`.lsd.open`、`.lsd.openurl` 等。但应用程序要使用这些公开的 XPC 功能，也需要具备某些 **entitlements**，例如 `.launchservices.changedefaulthandler` 或 `.launchservices.changeurlschemehandler`，用于更改 MIME 类型或 URL scheme 的默认应用程序，此外还有其他 entitlements。

**`/System/Library/CoreServices/launchservicesd`** 声明了服务 `com.apple.coreservices.launchservicesd`，可以对其进行查询以获取正在运行的应用程序信息。可以使用系统工具 **`/usr/bin/lsappinfo`** 或 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 对其进行查询。

从 operator 的角度来看，请注意通常有**两个有用的视图**：

- 由 LaunchServices / `lsd` 管理的**注册数据库**（由 `.csstore` 文件提供支持）。
- 存储在 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` 中 `LSHandlers` 数组内的**每个用户的有效默认设置**。

这一差异很重要：应用程序可以被**注册**为能够处理某种类型或 scheme，但**当前默认应用程序**仍可能是另一个 bundle ID。

在近期的 macOS 版本中，注册发现并不局限于 `/Applications`：位于其他 Spotlight 可见且可访问的文件夹，以及已挂载或共享卷中的应用程序，也可能进入注册表。因此，在 triage 期间应保留 `lsregister -dump` 中的 `path` 和卷信息，并且不要认为只要应用程序 bundle 仍可被发现，取消注册应用程序就能持久生效。<sup>[[4]](#references)</sup>

## 文件扩展名和 URL scheme 应用程序处理程序

以下命令可用于查找能够根据扩展名打开文件的应用程序：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
或者使用类似 [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) 的工具：
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
你还可以通过以下方式检查应用支持的扩展名：
```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
<string>css</string>
<string>pdf</string>
<string>webarchive</string>
<string>webbookmark</string>
<string>webhistory</string>
<string>webloc</string>
<string>download</string>
<string>safariextz</string>
<string>gif</string>
<string>html</string>
<string>htm</string>
<string>js</string>
<string>jpg</string>
<string>jpeg</string>
<string>jp2</string>
<string>txt</string>
<string>text</string>
<string>png</string>
<string>tiff</string>
<string>tif</string>
<string>url</string>
<string>ico</string>
<string>xhtml</string>
<string>xht</string>
<string>xml</string>
<string>xbl</string>
<string>svg</string>
```
## 枚举有效处理程序

对于**当前用户的默认设置**，最有用的文件通常是：
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
从中转储 **URL scheme** 处理程序：
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
要导出 **content-type / UTI** 处理程序：
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
解析示例文件的 UTI 树：
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
如果你想使用更友好的 CLI 来查询或更改默认设置：
```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```
### 每个文件的 `Open With` 覆盖设置

Handler resolution 还包含一个**特定于文件**的层级。在回退到文件的 UTI 和用户的全局默认设置之前，LaunchServices 会检查 `com.apple.LaunchServices.OpenWith` extended attribute。当用户为某个文件选择 **Always Open With** 时，Finder 会创建该属性；其值是一个二进制 property list，其中包含应用程序路径、bundle identifier 和版本选择器。<sup>[[3]](#references)</sup>

在不信任文件扩展名的情况下检查并解码它：
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
当单个诱饵打开时意外启动某个应用程序，即使 `duti`、`dutix` 或 `LSHandlers` 报告的是无害的全局默认设置，这一点很有用。在受控实验环境中，可以从通过 Finder 配置的文件中复制确切的不透明值；删除该值即可恢复正常的基于类型的解析：
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Interesting Info.plist keys

在对 application bundle 进行 triage 时，以下 keys 最为重要：

- **`CFBundleDocumentTypes`**：该 bundle 声明可以打开的 document groups。
- **`LSItemContentTypes`**：将 document types 绑定到 UTI 的**现代 / 首选**方式。
- **`LSHandlerRank`**：LaunchServices 使用的 ranking（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**：application 实现的 custom URI schemes。
- **`UTExportedTypeDeclarations`**：application **拥有**的 UTIs。
- **`UTImportedTypeDeclarations`**：application 不拥有、但希望系统识别的 UTIs。

一个实用的快速 triage command 是：
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
一个细微但重要的细节是：如果存在 **`LSItemContentTypes`**，那么 **`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`** 和 **`CFBundleTypeOSTypes`** 等较旧的键实际上只是 legacy compatibility data。对于实际的 handler resolution，应首先关注 UTI path。

## Offensive notes

应用程序不需要被执行才会引起关注。一个被放置或克隆的 `.app` bundle 在写入磁盘后，可能会立即被 **`lsd` 自动解析**；其声明的 document types / URL schemes 也可能被注册，而用户甚至无需启动该 bundle。

这对于 **persistence / hijacking research** 和 **initial-access chains** 都很有用：

- 恶意应用可以声明一个**罕见扩展名**或**自定义 UTI**，然后等待受害者打开诱导文件。
- 恶意应用可以注册一个**自定义 URL scheme**，该 scheme 可从 browser、Electron app、office document、chat client 或其他 helper app 中访问。<sup>[[1]](#references)</sup>
- 要将正常的 default resolution 与对特定 candidate handler 的测试区分开来，可以通过 LaunchServices 调用该 scheme：`open 'targetscheme://host/path?value=test'`；然后使用 `open -b com.vendor.Target 'targetscheme://host/path?value=test'` 指定某个已注册的 bundle。这对于审计接收 app 如何验证和解码由 attacker 控制的 URL components 很有用。<sup>[[1]](#references)</sup>
- 如果在构建 app bundle 后对其进行编辑，可以使用以下命令强制 LaunchServices 重新解析它：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
测试可疑 bundles 时，请特别注意：

- **`LSHandlerRank=Owner`** 是否出现在不常见的类型上。
- 声称支持许多扩展名的**宽泛 `CFBundleDocumentTypes`** 数组。
- **Helper / wrapper apps**，其唯一有趣的行为隐藏在 document 或 URI handler 后面。
- 最终会调度到 LaunchServices 的**类似快捷方式的文件**（`.webloc`、`.inetloc`、`.fileloc`）。对于 `.fileloc` 风格的技巧及相关的 Gatekeeper 方向，请查看[此页面](macos-security-protections/macos-fs-tricks/README.md)。<sup>[[2]](#references)</sup>

如果你的目标是仅通过浏览文件夹或选择文件来被动触发 code-execution，也请查看专门介绍 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 的页面，因为那是一个不同但密切相关的 file-handler 攻击面。



## References

- [1] [Objective-See - 通过自定义 URL Schemes 远程利用 Mac](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - 绕过 Gate：深入了解 macOS 中的 Gatekeeper 漏洞](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS 如何在正确的 app 中打开文件](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - 在 macOS Sequoia 中控制 LaunchServices](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
