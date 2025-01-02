# macOS 文件扩展名和 URL 方案应用程序处理程序

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices 数据库

这是一个包含 macOS 中所有已安装应用程序的数据库，可以查询以获取有关每个已安装应用程序的信息，例如它支持的 URL 方案和 MIME 类型。

可以使用以下命令导出此数据库：
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
或使用工具 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)。

**`/usr/libexec/lsd`** 是数据库的核心。它提供 **多个 XPC 服务**，如 `.lsd.installation`、`.lsd.open`、`.lsd.openurl` 等。但它也 **要求某些权限** 以便应用程序能够使用暴露的 XPC 功能，如 `.launchservices.changedefaulthandler` 或 `.launchservices.changeurlschemehandler` 来更改 MIME 类型或 URL 方案的默认应用程序等。

**`/System/Library/CoreServices/launchservicesd`** 声明服务 `com.apple.coreservices.launchservicesd`，可以查询以获取有关正在运行的应用程序的信息。可以使用系统工具 /**`usr/bin/lsappinfo`** 或 [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) 进行查询。

## 文件扩展名和 URL 方案应用程序处理程序

以下行可以用于查找可以根据扩展名打开文件的应用程序：
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
或者使用类似于 [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps)：
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
您还可以通过以下方式检查应用程序支持的扩展：
```
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
{{#include ../../banners/hacktricks-training.md}}
