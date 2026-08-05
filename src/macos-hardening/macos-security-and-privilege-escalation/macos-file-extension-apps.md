# macOS File Extension & URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

这是 macOS 中所有已安装应用程序的数据库，可以通过查询获取每个已安装应用程序的信息，例如支持的 **URL schemes**、**document types**、**UTIs** 以及默认 handlers。

可以使用以下命令导出此数据库：
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
或者使用工具 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)。

**`/usr/libexec/lsd`** 是该数据库的核心。它提供了**多个 XPC 服务**，例如 `.lsd.installation`、`.lsd.open`、`.lsd.openurl` 等。但应用程序还必须具备某些 **entitlements**，才能使用所暴露的 XPC 功能，例如 `.launchservices.changedefaulthandler` 或 `.launchservices.changeurlschemehandler`，以更改 MIME 类型或 URL scheme 的默认应用，以及其他功能。

**`/System/Library/CoreServices/launchservicesd`** 声明了 `com.apple.coreservices.launchservicesd` 服务，可以通过查询获取有关正在运行的应用程序的信息。可以使用系统工具 **`/usr/bin/lsappinfo`** 或 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 进行查询。

从 operator 的角度来看，请注意通常有**两个有用的视图**：

- 由 LaunchServices / `lsd` 管理的**注册数据库**（由 `.csstore` 文件提供支持）。
- 存储在 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` 的 `LSHandlers` 数组中的**每用户生效默认值**。

这个区别很重要：某个应用程序可以被**注册**为能够处理某种类型或 scheme，但**当前默认应用**仍可能是另一个 bundle ID。

## 文件扩展名和 URL scheme app handlers

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
从中 dump **URL scheme** handlers：
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
要 dump **content-type / UTI** 处理程序：
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
## 有趣的 Info.plist 键

在对 application bundle 进行 triage 时，以下键最为重要：

- **`CFBundleDocumentTypes`**：bundle 声明其可以打开的 document groups。
- **`LSItemContentTypes`**：将 document types 绑定到 UTI 的 **modern / preferred** 方式。
- **`LSHandlerRank`**：LaunchServices 使用的 ranking（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**：app 实现的 custom URI schemes。
- **`UTExportedTypeDeclarations`**：app **owns** 的 UTI。
- **`UTImportedTypeDeclarations`**：app 不 owns，但希望 system 识别的 UTI。

一个实用的 quick triage command 是：
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
一个细微但重要的细节：如果存在 **`LSItemContentTypes`**，则 **`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`** 和 **`CFBundleTypeOSTypes`** 等较旧的键实际上只是 legacy compatibility data。对于实际的 handler resolution，应首先关注 UTI path。

## Offensive notes

Applications 不需要被执行才会变得有价值。一个被投放或克隆的 `.app` bundle 在写入磁盘后，可能会立即被 **`lsd` 自动解析**，其声明的 document types / URL schemes 也可能被注册，即使用户从未启动过该 bundle。

这对 **persistence / hijacking research** 和 **initial-access chains** 都很有用：

- 恶意 app 可以声明一个**罕见扩展名**或**自定义 UTI**，等待受害者打开 lure file。
- 恶意 app 可以注册一个**自定义 URL scheme**，该 scheme 可从 browser、Electron app、office document、chat client 或其他 helper app 访问。<sup>[[1]](#references)</sup>
- 如果你在构建 app bundle 后对其进行编辑，可以使用以下命令强制 LaunchServices 重新解析它：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
测试可疑 bundles 时，请特别注意：

- **`LSHandlerRank=Owner`** 是否用于不常见的文件类型。
- 声称支持许多扩展名的宽泛 **`CFBundleDocumentTypes`** 数组。
- **Helper / wrapper apps**，其唯一有趣的行为隐藏在 document 或 URI handler 后面。
- 最终会将处理请求分派到 LaunchServices 的**快捷方式类文件**（`.webloc`、`.inetloc`、`.fileloc`）。对于 `.fileloc` 类技巧及相关的 Gatekeeper 角度，请查看[此页面](macos-security-protections/macos-fs-tricks/README.md)。<sup>[[2]](#references)</sup>

如果你的目标是仅通过浏览文件夹或选择文件来实现被动 code-execution，也请查看专门介绍 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 的页面，因为那是一个不同但密切相关的 file-handler 攻击面。

## 参考资料

- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}
