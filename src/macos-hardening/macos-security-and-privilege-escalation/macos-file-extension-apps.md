# macOS 文件扩展名 & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

这是 macOS 中所有已安装应用程序的数据库，可用于查询每个已安装应用程序的信息，例如支持的 **URL schemes**、**document types**、**UTIs** 和默认 handlers。

可以用以下方式导出这个数据库：
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
或者使用工具 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)。

**`/usr/libexec/lsd`** 是 database 的核心。它提供 **several XPC services**，比如 `.lsd.installation`、`.lsd.open`、`.lsd.openurl` 等。不过它也 **requires some entitlements**，应用要想使用暴露出来的 XPC 功能，必须具备这些权限，比如 `.launchservices.changedefaulthandler` 或 `.launchservices.changeurlschemehandler`，用于更改 MIME types 或 URL schemes 的默认应用，以及其他功能。

**`/System/Library/CoreServices/launchservicesd`** 声明了服务 `com.apple.coreservices.launchservicesd`，可以查询它来获取正在运行的应用信息。可以使用系统工具 **`/usr/bin/lsappinfo`** 或 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 来查询。

从 operator 的角度看，要记住通常有 **two useful views**：

- 由 LaunchServices / `lsd` 管理的 **registration database**（由 `.csstore` files 支持）。
- 存储在 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` 的 `LSHandlers` 数组中的 **per-user effective defaults**。

这个区别很重要：一个应用可以被 **registered** 为能够处理某种类型或 scheme，但 **current default** 仍然可能是另一个 bundle ID。

## File Extension & URL scheme app handlers

下面这一行可用于查找可根据扩展名打开文件的应用：
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
你也可以通过以下方式检查某个应用程序支持的扩展：
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
## 枚举有效的 handlers

对于 **current user's defaults**，最有用的文件通常是：
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
要解析一个样本文件的 UTI 树：
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
如果你想要一个更友好的 CLI 来查询或更改 defaults：
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
## 有趣的 Info.plist 键

在筛查一个 application bundle 时，这些键最重要：

- **`CFBundleDocumentTypes`**: bundle 声称可以打开的 document groups。
- **`LSItemContentTypes`**: 将 document types 绑定到 UTIs 的**现代 / 首选**方式。
- **`LSHandlerRank`**: LaunchServices 使用的排名（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: 应用实现的自定义 URI schemes。
- **`UTExportedTypeDeclarations`**: 应用**拥有**的 UTIs。
- **`UTImportedTypeDeclarations`**: 应用不拥有但希望系统识别的 UTIs。

一个有用的快速筛查命令是：
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
一个微妙但重要的细节：如果存在 **`LSItemContentTypes`**，那么像 **`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`** 和 **`CFBundleTypeOSTypes`** 这类较旧的键实际上只是 legacy 兼容数据。对于实际的 handler resolution，先关注 UTI 路径。

## Offensive notes

Applications 不需要被执行也能变得有趣。一个被放置或克隆的 `.app` bundle 一旦写入磁盘，就可以被 **`lsd` 自动解析**，其声明的 document types / URL schemes 可能会在用户从未启动该 bundle 的情况下就被注册。

这对 **persistence / hijacking research** 和 **initial-access chains** 都很有用：

- 恶意 app 可以声明一个 **rare extension** 或一个 **custom UTI**，然后等待受害者打开诱饵文件。
- 恶意 app 可以注册一个 **custom URL scheme**，该 scheme 可从浏览器、Electron app、office document、chat client 或其他 helper app 触发。
- 如果你在构建后编辑 app bundle，你可以强制 LaunchServices 重新解析它，方法是：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
当测试可疑 bundle 时，请特别注意：

- 在不常见类型上出现的 **`LSHandlerRank=Owner`**。
- 声称支持许多扩展名的、范围很广的 **`CFBundleDocumentTypes`** 数组。
- **Helper / wrapper apps**，其唯一有趣的行为隐藏在 document 或 URI handler 后面。
- **Shortcut-like files**（`.webloc`、`.inetloc`、`.fileloc`）最终会调度到 LaunchServices。关于 `.fileloc` 风格的技巧以及相关的 Gatekeeper 角度，请查看[此另一页](macos-security-protections/macos-fs-tricks/README.md)。

如果你的目标是仅通过浏览到某个文件夹或选择一个文件就实现被动 code-execution，也请查看 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 的专门页面，因为那是一个不同但密切相关的 file-handler surface。

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}
