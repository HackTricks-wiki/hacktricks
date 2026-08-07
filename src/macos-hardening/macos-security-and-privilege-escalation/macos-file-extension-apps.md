# macOS 文件扩展名和 URL scheme 应用处理程序

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices 数据库

这是 macOS 中所有已安装应用程序的数据库，可以查询每个已安装应用程序的信息，例如支持的 **URL schemes**、**文档类型**、**UTIs** 以及默认处理程序。

可以使用以下命令转储此数据库：
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
或者使用工具 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)。

**`/usr/libexec/lsd`** 是该数据库的核心。它提供了**多个 XPC 服务**，例如 `.lsd.installation`、`.lsd.open`、`.lsd.openurl` 等。但应用程序要使用这些公开的 XPC 功能，也需要具备某些 **entitlements**，例如 `.launchservices.changedefaulthandler` 或 `.launchservices.changeurlschemehandler`，前者用于更改 MIME 类型的默认应用，后者用于更改 URL scheme 的默认应用，此外还有其他功能。

**`/System/Library/CoreServices/launchservicesd`** 声明了服务 `com.apple.coreservices.launchservicesd`，可以查询正在运行的应用程序的信息。可以使用系统工具 **`/usr/bin/lsappinfo`** 或 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 对其进行查询。

从 operator 的角度来看，请记住通常有**两个有用的视图**：

- 由 LaunchServices / `lsd` 管理的**注册数据库**（由 `.csstore` 文件支持）。
- 存储在 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` 中 `LSHandlers` 数组内的**每个用户的有效默认设置**。

这种区别很重要：应用程序可以被**注册**为能够处理某种类型或 scheme，但**当前默认应用**仍可能是另一个 bundle ID。

## 文件扩展名和 URL scheme 应用处理程序

以下命令可用于查找能够根据扩展名打开文件的应用程序：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
或者使用类似 [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps)：
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
要从中转储 **URL scheme** 处理程序：
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
要转储 **content-type / UTI** 处理程序：
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
解析示例文件的 UTI 树：
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
如果你想使用更友好的 CLI 来查询或更改默认值：
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

在对应用程序 bundle 进行 triage 时，以下 keys 最值得关注：

- **`CFBundleDocumentTypes`**：bundle 声明其可以打开的文档组。
- **`LSItemContentTypes`**：将文档类型绑定到 UTI 的**现代 / 首选**方式。
- **`LSHandlerRank`**：LaunchServices 使用的优先级（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**：应用实现的自定义 URI schemes。
- **`UTExportedTypeDeclarations`**：应用**拥有**的 UTI。
- **`UTImportedTypeDeclarations`**：应用不拥有、但希望系统识别的 UTI。

一个实用的快速 triage 命令是：
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
一个细微但重要的细节：如果存在 **`LSItemContentTypes`**，则较旧的键 **`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`** 和 **`CFBundleTypeOSTypes`** 实际上只是 legacy compatibility data。对于实际的 handler resolution，应首先关注 UTI path。

## Offensive notes

应用不需要被执行才会变得有价值。一个被放置或克隆的 `.app` bundle 在写入磁盘后，可能会立即被 **`lsd` 自动解析**，其声明的 document types / URL schemes 可能会被注册，即使用户从未启动过该 bundle。

这对于 **persistence / hijacking research** 和 **initial-access chains** 都很有用：

- 恶意应用可以声明一个**罕见扩展名**或**自定义 UTI**，等待受害者打开诱导文件。
- 恶意应用可以注册一个可从浏览器、Electron app、office document、chat client 或其他 helper app 访问的**自定义 URL scheme**。<sup>[[1]](#references)</sup>
- 如果你在构建 app bundle 后对其进行编辑，可以使用以下命令强制 LaunchServices 重新解析它：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
测试可疑 bundle 时，请特别注意：

- **`LSHandlerRank=Owner`** 出现在不常见的文件类型上。
- 声称支持许多扩展名的**宽泛 `CFBundleDocumentTypes`** 数组。
- **Helper / wrapper apps**，其唯一的有趣行为隐藏在 document 或 URI handler 后面。
- **类似快捷方式的文件**（`.webloc`、`.inetloc`、`.fileloc`）最终会被 dispatch 到 LaunchServices。有关 `.fileloc` 风格的 tricks 及相关 Gatekeeper 角度，请查看[此页面](macos-security-protections/macos-fs-tricks/README.md)。<sup>[[2]](#references)</sup>

如果你的目标是仅通过浏览文件夹或选择文件来实现 passive code-execution，还应查看专门介绍 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 的页面，因为这是一个不同但密切相关的 file-handler attack surface。

## 参考资料


- [1] [Objective-See - 通过自定义 URL Schemes 进行 Remote Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate：深入了解 macOS 上的 Gatekeeper flaws](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
