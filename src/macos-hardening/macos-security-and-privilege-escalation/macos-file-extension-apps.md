# macOS 文件扩展名和 URL scheme 应用处理程序

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices 数据库

这是 macOS 中所有已安装应用程序的数据库，可以通过查询获取每个已安装应用程序的信息，例如支持的 **URL schemes**、**文档类型**、**UTIs** 和默认处理程序。

可以使用以下命令转储此数据库：
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
或者使用工具 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)。

**`/usr/libexec/lsd`** 是该数据库的核心。它提供了**多个 XPC 服务**，例如 `.lsd.installation`、`.lsd.open`、`.lsd.openurl` 等。但应用程序还需要具备**某些 entitlements**，才能使用所暴露的 XPC 功能，例如使用 `.launchservices.changedefaulthandler` 或 `.launchservices.changeurlschemehandler` 来更改 MIME 类型或 URL scheme 的默认应用，以及其他功能。

**`/System/Library/CoreServices/launchservicesd`** 声明了服务 `com.apple.coreservices.launchservicesd`，可以通过查询它来获取正在运行的应用程序信息。可以使用系统工具 **`/usr/bin/lsappinfo`** 或 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 对其进行查询。

从 operator 的角度来看，请记住通常有**两个有用的视图**：

- 由 LaunchServices / `lsd` 管理的**注册数据库**（由 `.csstore` 文件提供支持）。
- 存储在 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` 中 `LSHandlers` 数组内的**每用户有效默认设置**。

这种区别很重要：应用程序可以被**注册**为能够处理某种类型或 scheme，但**当前默认应用**仍可能是另一个 bundle ID。

## 文件扩展名和 URL scheme 应用处理程序

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
你还可以通过以下方式检查应用程序支持的扩展名：
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
从中 dump **URL scheme** 处理程序：
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
解析样本文件的 UTI 树：
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
如果你想使用更友好的 CLI 查询或更改默认设置：
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
## 有趣的 Info.plist keys

对 application bundle 进行 triage 时，以下 keys 最为重要：

- **`CFBundleDocumentTypes`**：该 bundle 声明可以打开的文档组。
- **`LSItemContentTypes`**：将文档类型绑定到 UTI 的**现代 / 首选**方式。
- **`LSHandlerRank`**：LaunchServices 使用的优先级（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**：application 实现的自定义 URI schemes。
- **`UTExportedTypeDeclarations`**：application **拥有**的 UTIs。
- **`UTImportedTypeDeclarations`**：application 不拥有、但希望系统识别的 UTIs。

一个实用的 quick triage command 是：
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
一个微妙但重要的细节是：如果存在 **`LSItemContentTypes`**，那么较旧的键（如 **`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`** 和 **`CFBundleTypeOSTypes`**）实际上只是 legacy compatibility data。对于实际的 handler resolution，应优先关注 UTI 路径。

## Offensive notes

应用不需要被执行才会变得值得关注。一个被放置或克隆的 `.app` bundle 在写入磁盘后，可能会立即被 **`lsd` 自动解析**，其声明的 document types / URL schemes 也可能被注册，即使用户从未启动过该 bundle。

这对于 **persistence / hijacking research** 和 **initial-access chains** 都很有用：

- 恶意应用可以声明一个**罕见扩展名**或**自定义 UTI**，等待受害者打开诱饵文件。
- 恶意应用可以注册一个**自定义 URL scheme**，该 scheme 可从浏览器、Electron 应用、office document、chat client 或其他 helper app 访问。<sup>[1]</sup>
- 如果你在构建 app bundle 后对其进行编辑，可以使用以下命令强制 LaunchServices 重新解析它：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
测试可疑 bundles 时，请特别注意：

- **`LSHandlerRank=Owner`** 是否出现在不常见的类型上。
- 声称支持许多扩展名的**宽泛 `CFBundleDocumentTypes`** 数组。
- **Helper / wrapper apps**，其唯一有趣的行为隐藏在 document 或 URI handler 后面。
- 最终将分派到 LaunchServices 的**快捷方式类文件**（`.webloc`、`.inetloc`、`.fileloc`）。有关 `.fileloc` 类 tricks 及相关 Gatekeeper 角度，请查看[此页面](macos-security-protections/macos-fs-tricks/README.md)。<sup>[2]</sup>

如果你的目标是仅通过浏览文件夹或选择文件来实现被动 code-execution，也请查看专门介绍 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 的页面，因为那是一个不同但密切相关的 file-handler 攻击面。

## 参考资料

- [1] [Objective-See - 通过自定义 URL Schemes 远程利用 Mac](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - 绕过 Gate：深入了解 macOS 上的 Gatekeeper flaws](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
