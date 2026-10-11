# macOS 文件扩展名和 URL scheme 应用处理程序

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices 数据库

这是 macOS 中所有已安装应用程序的数据库，可以查询以获取每个已安装应用程序的信息，例如支持的 **URL schemes**、**文档类型**、**UTI** 和默认处理程序。

可以通过以下命令转储此数据库：

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

或者使用工具 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)。

**`/usr/libexec/lsd`** 是数据库的核心。它提供**多个 XPC 服务**，例如 `.lsd.installation`、`.lsd.open`、`.lsd.openurl` 等。但应用还需要具备**某些 entitlements**，才能使用这些公开的 XPC 功能，例如 `.launchservices.changedefaulthandler` 或 `.launchservices.changeurlschemehandler`，以更改 MIME 类型或 URL scheme 的默认应用等。

**`/System/Library/CoreServices/launchservicesd`** 声明了服务 `com.apple.coreservices.launchservicesd`，可通过查询获取正在运行的应用的信息。可以使用系统工具 **`/usr/bin/lsappinfo`** 或 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 查询它。

从 operator 的角度来看，请记住，通常有**两个有用的视图**：

- 由 LaunchServices / `lsd` 管理的**注册数据库**（由 `.csstore` 文件提供支持）。
- 存储在 `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` 的 `LSHandlers` 数组中的**每用户有效默认设置**。

这个区别很重要：应用可以**注册**为能够处理某种类型或 scheme，但**当前默认应用**仍可能是另一个 bundle ID。

在较新的 macOS 版本中，应用注册发现并不局限于 `/Applications`：位于其他 Spotlight 可见且可访问的文件夹，以及已挂载或共享卷中的应用，也可能被纳入注册表。因此，在分诊期间，请保留 `lsregister -dump` 输出中的 `path` 和卷信息；只要应用 bundle 仍可被发现，就不要假设注销应用后这一状态会一直保持。<sup>[[4]](#references)</sup>

## 文件扩展名和 URL scheme 处理应用

以下命令可用于查找能够根据文件扩展名打开文件的应用：

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

## 枚举生效的处理程序

最有用的文件通常是用于查看**当前用户的默认设置**的文件：

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

从中导出 **URL scheme** 处理程序：

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

### 每个文件的 `Open With` 覆盖项

处理程序解析还有一层**针对特定文件**的机制。在回退到文件的 UTI 和用户的全局默认设置之前，LaunchServices 会检查 `com.apple.LaunchServices.OpenWith` 扩展属性。用户为某个文件选择**始终使用此应用打开**时，Finder 会创建此属性；其值是一个二进制属性列表，其中包含应用程序路径、bundle identifier 和版本选择器。<sup>[[3]](#references)</sup>

检查并解码此属性，不要信任文件扩展名：

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

当单个诱饵打开时意外启动了某个应用，即使 `duti`、`dutix` 或 `LSHandlers` 报告的全局默认值是安全的，这种方法就很有用。在受控实验室中，可以从通过 Finder 配置的文件中复制确切的不透明值；删除该值即可恢复正常的基于类型的解析：

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## 有趣的 Info.plist 键

对应用程序包进行初步分析时，以下键最重要：

- **`CFBundleDocumentTypes`**：应用程序包声明可打开的文档类型组。
- **`LSItemContentTypes`**：将文档类型绑定到 UTI 的**现代/首选**方式。
- **`LSHandlerRank`**：LaunchServices 使用的优先级（`Owner`、`Default`、`Alternate`、`None`）。
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**：应用实现的自定义 URI scheme。
- **`UTExportedTypeDeclarations`**：应用**拥有**的 UTI。
- **`UTImportedTypeDeclarations`**：应用不拥有、但希望系统识别的 UTI。

一个实用的快速分析命令是：

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

一个细微但重要的细节：如果存在 **`LSItemContentTypes`**，那么 **`CFBundleTypeExtensions`**、**`CFBundleTypeMIMETypes`** 和 **`CFBundleTypeOSTypes`** 等较旧的键实际上只是用于兼容旧版本的数据。要确定实际的处理程序解析结果，应优先关注 UTI 路径。

## 攻击说明

应用无需执行就可能引发关注。`.app` bundle 一旦被写入磁盘，`lsd` 就可能自动解析被放置或克隆的 bundle；即使用户从未启动该 bundle，它声明的文档类型和 URL scheme 也可能被注册。

这对于 **persistence / hijacking 研究** 和 **初始访问链** 都很有用：

- 恶意应用可以声明一个 **罕见扩展名** 或 **自定义 UTI**，然后等待受害者打开诱饵文件。
- 恶意应用可以注册一个 **自定义 URL scheme**，使其可从浏览器、Electron 应用、办公文档、聊天客户端或其他辅助应用访问。<sup>[[1]](#references)</sup>
- 要将正常的默认解析与测试特定候选处理程序区分开来，可以通过 LaunchServices 使用 `open 'targetscheme://host/path?value=test'` 调用该 scheme，然后使用 `open -b com.vendor.Target 'targetscheme://host/path?value=test'` 指定一个已注册的 bundle。这有助于审计接收应用如何验证和解码由攻击者控制的 URL 组件。<sup>[[1]](#references)</sup>
- 如果在构建 app bundle 后对其进行编辑，可以使用以下命令强制 LaunchServices 重新解析：

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

测试可疑 bundle 时，请特别注意：

- **`LSHandlerRank=Owner`** 被用于不常见的类型。
- **`CFBundleDocumentTypes`** 数组范围过广，声称支持许多扩展名。
- **Helper / wrapper apps**，其唯一有趣的行为隐藏在文档或 URI handler 后面。
- **类似快捷方式的文件**（`.webloc`、`.inetloc`、`.fileloc`），最终会将操作分派给 LaunchServices。有关 `.fileloc` 风格的技巧及相关 Gatekeeper 角度，请查看[此页面](macos-security-protections/macos-fs-tricks/README.md)。<sup>[[2]](#references)</sup>

如果你的目标是仅通过浏览文件夹或选择文件就被动触发代码执行，也请查看关于 [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) 的专门页面，因为这是一个不同但密切相关的文件 handler 攻击面。



## References

- [1] [Objective-See - 通过自定义 URL scheme 远程攻击 Mac](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - 绕过 Gate：深入了解 macOS 上的 Gatekeeper 漏洞](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS 如何在正确的 app 中打开文件](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - 在 macOS Sequoia 中控制 LaunchServices](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}
