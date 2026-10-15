# macOS 文件扩展名与 URL scheme 应用处理程序

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices 数据库

这是一个包含 macOS 中所有已安装应用程序的数据库，可用于查询每个已安装应用程序的信息，例如支持的 **URL schemes**、**文档类型**、**UTI** 和默认处理程序。

可以通过以下方式转储此数据库：

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

或者使用工具 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)。

**`/usr/libexec/lsd`** 是数据库的核心。它提供**多个 XPC 服务**，例如 `.lsd.installation`、`.lsd.open`、`.lsd.openurl` 等。但应用要使用公开的 XPC 功能，也**需要具备某些 entitlement**，例如 `.launchservices.changedefaulthandler` 或 `.launchservices.changeurlschemehandler`，才能更改 MIME 类型或 URL scheme 的默认应用等。

**`/System/Library/CoreServices/launchservicesd`** 声明了服务 `com.apple.coreservices.launchservicesd`，可通过查询获取正在运行的应用程序信息。可以使用系统工具 **`/usr/bin/lsappinfo`** 或 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 进行查询。

从 operator 的角度来看，请记住通常有**两种有用的视图**：

- 由 LaunchServices / `lsd` 管理的**注册数据库**（由 `.csstore` 文件提供支持）。
- 存储在 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` 中 `LSHandlers` 数组里的**每用户有效默认值**。

这个区别很重要：某个应用可以**注册为能够处理**某种类型或 scheme，但**当前默认应用**仍可能是另一个 bundle ID。

在较新的 macOS 版本中，注册发现不限于 `/Applications`：其他 Spotlight 可见且可访问的文件夹，以及已挂载或共享的卷中的应用，也可能进入注册表。因此，在分诊期间，应保留 `lsregister -dump` 输出中的 `path` 和卷信息；只要应用 bundle 仍可被发现，就不要假设取消注册会一直有效。<sup>[[4]](#references)</sup>

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

你还可以通过以下方式检查应用支持的扩展：

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

对于**当前用户的默认设置**，通常最有用的文件是：

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

从中转储 **URL scheme** 处理程序：

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Dump **content-type / UTI** 处理程序：

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

要解析样本文件的 UTI 树：

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

如果你想用更友好的 CLI 来查询或更改默认值：

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

### 每个文件的 `Open With` 覆盖项

处理程序解析还有一层**针对特定文件**的机制。在回退到文件的 UTI 和用户的全局默认设置之前，LaunchServices 会检查 `com.apple.LaunchServices.OpenWith` 扩展属性。选择一个文件的 **Always Open With** 后，Finder 会创建此属性；其值是一个二进制属性列表，包含应用程序路径、bundle identifier 和版本选择器。<sup>[[3]](#references)</sup>

检查并解码它，不要信任文件扩展名：

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

当单个诱饵打开时意外启动了某个应用，即使 `duti`、`dutix` 或 `LSHandlers` 报告的全局默认应用是良性的，这种方法也很有用。在受控实验室中，可以从通过 Finder 配置的文件中复制确切的不透明值；删除该值即可恢复正常的基于类型的解析：

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## 有趣的 Info.plist 键

对应用程序包进行初步检查时，以下键最重要：

- **`CFBundleDocumentTypes`**：应用程序包声明可打开的文档类型。
- **`LSItemContentTypes`**：将文档类型关联到 UTI 的**现代/首选**方式。
- **`LSHandlerRank`**：LaunchServices 使用的优先级（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**：应用实现的自定义 URI schemes。
- **`UTExportedTypeDeclarations`**：应用**拥有**的 UTI。
- **`UTImportedTypeDeclarations`**：应用不拥有、但希望系统识别的 UTI。

一个实用的快速检查命令是：

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

一个细微但重要的细节：如果存在 **`LSItemContentTypes`**，那么 **`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`** 和 **`CFBundleTypeOSTypes`** 等旧键实际上只是用于兼容旧版的元数据。实际解析处理程序时，应优先关注 UTI 路径。

## 攻击说明

应用无需先运行，其处理程序声明就可能值得关注，但**仅写入一个 `.app` bundle 并不能保证它会立即注册**。Finder 发现应用时可以注册它，包括用户浏览应用所在文件夹时；系统启动或用户登录时也可能注册，或者通过显式的注册调用来注册。测试声明之前，先检查 `lsregister -dump`。仅注册应用既不会启动它，也不会使其成为实际的默认处理程序。<sup>[[5]](#references)</sup> 有关持久化前提条件，请参阅 [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices)。

这对**持久化 / 劫持研究**和**初始访问链**都很有用：

- 恶意应用可以声明一个**罕见的扩展名**或**自定义 UTI**，然后等待受害者打开诱饵文件。
- 恶意应用可以注册一个**自定义 URL scheme**，使其可从浏览器、Electron 应用、办公文档、聊天客户端或其他辅助应用触发。<sup>[[1]](#references)</sup>
- 若要将常规默认解析与测试特定候选处理程序区分开来，可通过 LaunchServices 使用 `open 'targetscheme://host/path?value=test'` 调用该 scheme，然后使用 `open -b com.vendor.Target 'targetscheme://host/path?value=test'` 指定一个已注册的 bundle。这有助于审查接收应用如何验证和解码攻击者控制的 URL 组件。<sup>[[1]](#references)</sup>
- 如果在构建应用后编辑了其 bundle，可以强制 LaunchServices 重新解析它：

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

测试可疑 bundle 时，请特别注意：

- 不常见类型上的 **`LSHandlerRank=Owner`**。
- 声称处理许多扩展名的宽泛 **`CFBundleDocumentTypes`** 数组。
- **Helper / wrapper apps**，其唯一值得关注的行为隐藏在文档或 URI handler 后面。
- 最终会派发给 LaunchServices 的快捷方式类文件（`.webloc`、`.inetloc`、`.fileloc`）。关于 `.fileloc` 类技巧和相关 Gatekeeper 攻击面，请参阅[此页面](macos-security-protections/macos-fs-tricks/README.md)。<sup>[[2]](#references)</sup>

### 转发到下游选项的 URL 参数

浏览器的外部协议确认只批准打开 handler，并不意味着 URL 参数可信。追踪接收应用的 URL parser，检查它是否会将内容传递给任何 library、media engine、helper process 或 file-writing option。查找一种 query-key 前缀，它会将 URL 字段转换为下游选项名称。在 disposable account 中使用无害标记，测试字面分隔符和 percent-encoded 分隔符。<sup>[[6]](#references)</sup>

验证下游组件**最终接受的选项**，而不只是应用的初始解析。有个 handler 允许带前缀的 query keys 传递给 mpv input commands；即使阻止该选项，仍然存在 file-write 路径。测试可触达的选项类别，而不只是某个已知危险的 key。<sup>[[7]](#references)</sup>

### 内置的 `applescript://` handler

`applescript://com.apple.scripteditor` URL handler 接受 `action=new` 和 URL-encoded 的 `script` 参数。因此，浏览器链接可以打开 Script Editor，并预先填入攻击者控制的 AppleScript，从而省去粘贴到 Terminal 的步骤。这**不会自动执行**：浏览器可能会询问是否打开 Script Editor，而且用户必须运行该脚本。<sup>[[8]](#references)</sup>

较新的 macOS 版本可能会显示脚本文档警告，而 XProtect 会在执行时扫描 AppleScript。<sup>[[8]](#references)[[9]](#references)</sup>

使用无害的本地探针，检查正在评估的 macOS 版本上的 handler 和提示；在点击 **Run** 之前，它应该只会填充编辑器。<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

如果你的目标是仅通过浏览文件夹或选择文件来被动触发代码执行，也请查看专门介绍 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 的页面，因为这是一个不同但密切相关的文件处理程序攻击面。



## References

- [1] [Objective-See - 通过自定义 URL schemes 远程利用 Mac](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - 绕过 Gate：深入了解 macOS 上的 Gatekeeper 漏洞](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS 如何在正确的 app 中打开文件](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - 在 macOS Sequoia 中控制 LaunchServices](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Launch Services 概念](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - IINA URL scheme 命令执行研究](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - URL scheme 中对 mpv 选项的不安全处理](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - ClickFix 技术改用 Script Editor，而非 Terminal](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Terminal 和脚本保护](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}
