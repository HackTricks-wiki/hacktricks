# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Firefox 浏览器 Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts 包含 web browsers 存储的各种类型数据，例如导航历史记录、书签和缓存数据。这些 artifacts 保存在 operating system 中的特定文件夹内，不同 browser 的位置和名称各不相同，但通常存储类似的数据类型。

以下是最常见的 browser artifacts：

- **Navigation History**：记录用户访问过的网站，可用于确定用户是否访问过恶意网站。
- **Autocomplete Data**：基于常用搜索生成的建议，与导航历史记录结合使用时可提供有价值的信息。
- **Bookmarks**：用户保存以便快速访问的网站。
- **Extensions and Add-ons**：用户安装的 browser extensions 或 add-ons。
- **Cache**：存储 web 内容（例如 images、JavaScript files）以提高网站加载速度，对 forensic analysis 很有价值。
- **Logins**：存储的登录凭据。
- **Favicons**：与网站关联的图标，显示在 tabs 和 bookmarks 中，可用于获取用户访问记录的额外信息。
- **Browser Sessions**：与已打开 browser sessions 相关的数据。
- **Downloads**：通过 browser 下载的文件记录。
- **Form Data**：用户在 web forms 中输入的信息，用于保存以供未来的 autofill 建议使用。
- **Thumbnails**：网站的预览图像。
- **Custom Dictionary.txt**：用户添加到 browser dictionary 中的单词。

## Firefox

Firefox 根据 profiles 组织用户数据，并根据 operating system 将其存储在特定位置：<sup>[[1]](#references)</sup>

- **Linux**：`~/.mozilla/firefox/`
- **MacOS**：`/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**：`%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

这些目录中的 `profiles.ini` 文件会列出用户 profiles。每个 profile 的数据存储在 `profiles.ini` 中 `Path` 变量所指定名称的文件夹内，该文件夹与 `profiles.ini` 位于同一目录中。如果某个 profile 的文件夹缺失，则可能已被删除。

在每个 profile 文件夹中，可以找到多个重要文件：<sup>[[1]](#references)</sup>

- **places.sqlite**：存储历史记录、书签和下载记录。在 Windows 上，可以使用 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) 等工具访问历史数据。
- 使用特定的 SQL queries 提取历史记录和下载信息。
- **bookmarkbackups**：包含书签备份。
- **formhistory.sqlite**：存储 web form 数据。
- **handlers.json**：管理 protocol handlers。
- **persdict.dat**：自定义 dictionary 单词。
- **addons.json** 和 **extensions.sqlite**：已安装 add-ons 和 extensions 的信息。
- **cookies.sqlite**：Cookie 存储文件，在 Windows 上可以使用 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) 进行检查。
- **cache2/entries** 或 **startupCache**：缓存数据，可通过 [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) 等工具访问。
- **favicons.sqlite**：存储 favicons。
- **prefs.js**：用户设置和 preferences。
- **downloads.sqlite**：旧版 downloads database，目前已集成到 places.sqlite。
- **thumbnails**：网站 thumbnails。
- **logins.json**：加密的登录信息。
- **key4.db** 或 **key3.db**：存储用于保护敏感信息的 encryption keys。

此外，可以通过在 `prefs.js` 中搜索 `browser.safebrowsing` 条目来检查 browser 的 anti-phishing 设置，从而确定 safe browsing 功能是否已启用或禁用。<sup>[[2]](#references)</sup>

若要尝试解密 master password，可以使用 [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
使用以下 script 和调用方式，可以指定一个 password file 进行 brute force：
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![浏览器Artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome 根据操作系统将用户配置文件存储在特定位置：<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

在这些目录中，大多数用户数据位于 **Default/** 或 **ChromeDefaultData/** 文件夹中。以下文件包含重要数据：<sup>[[1]](#references)</sup>

- **History**：包含 URL、下载记录和搜索关键词。在 Windows 上，可以使用 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) 读取历史记录。“Transition Type”列具有多种含义，包括用户点击链接、输入 URL、提交表单和重新加载页面。
- **Cookies**：存储 cookies。可以使用 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) 进行检查。
- **Cache**：保存缓存数据。Windows 用户可以使用 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) 进行检查。

基于 Electron 的桌面应用（例如 Discord）也使用 Chromium Simple Cache，并会在磁盘上留下丰富的Artifacts。参见：

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**：用户书签。
- **Web Data**：包含表单历史记录。
- **Favicons**：存储网站 favicon。
- **Login Data**：包含用户名和密码等登录凭据。
- **Current Session**/**Current Tabs**：当前浏览会话和打开标签页的数据。
- **Last Session**/**Last Tabs**：Chrome 关闭前上一个会话中处于活动状态的网站信息。
- **Extensions**：浏览器扩展和 addons 的目录。
- **Thumbnails**：存储网站缩略图。
- **Preferences**：包含大量信息的文件，包括插件、扩展、弹窗、通知等设置。
- **Browser’s built-in anti-phishing**：要检查 anti-phishing 和 malware protection 是否启用，请运行 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`。在输出中查找 `{"enabled: true,"}`。<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

如前文所述，Chrome 和 Firefox 都使用 **SQLite** 数据库来存储数据。可以使用工具 [**sqlparse**](https://github.com/padfoot999/sqlparse) **或** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **恢复已删除的条目**。

## **Internet Explorer 11**

Internet Explorer 11 将其数据和元数据分布存储在多个位置，以便分离存储的信息及其对应的详细信息，从而更容易访问和管理。

### Metadata Storage

Internet Explorer 的元数据存储在 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` 中（其中 VX 可以是 V01、V16 或 V24）。此外，`V01.log` 文件可能显示与 `WebcacheVX.data` 不一致的修改时间，这表示可能需要使用 `esentutl /r V01 /d` 进行修复。这些存储在 ESE 数据库中的元数据可以使用 photorec 恢复，并分别使用 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 检查。在 **Containers** 表中，可以确定每个数据段所存储的具体表或容器，其中还包括 Skype 等其他 Microsoft 工具的缓存详细信息。

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 工具可用于检查缓存，但需要指定缓存数据提取文件夹的位置。缓存元数据包括文件名、目录、访问次数、URL 来源，以及表示缓存创建、访问、修改和过期时间的时间戳。

### Cookies Management

可以使用 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) 检查 cookies，其元数据包括名称、URL、访问次数以及各种时间相关信息。持久 cookies 存储在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` 中，而会话 cookies 则存储在内存中。

### Download Details

可以通过 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 访问下载元数据，其中的特定容器保存 URL、文件类型和下载位置等数据。物理文件位于 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` 下。

### Browsing History

要查看浏览历史记录，可以使用 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)，但需要提供提取后的历史记录文件位置，并配置 Internet Explorer。这里的元数据包括修改时间、访问时间以及访问次数。历史记录文件位于 `%userprofile%\Appdata\Local\Microsoft\Windows\History`。

### Typed URLs

输入的 URL 及其使用时间存储在 `NTUSER.DAT` 注册表中的 `Software\Microsoft\InternetExplorer\TypedURLs` 和 `Software\Microsoft\InternetExplorer\TypedURLsTime` 下，用于记录用户输入的最近 50 个 URL 及其最后输入时间。

## Microsoft Edge

Microsoft Edge 将用户数据存储在 `%userprofile%\Appdata\Local\Packages` 中。不同数据类型的路径如下：<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 数据存储在 `/Users/$User/Library/Safari`。主要文件包括：<sup>[[3]](#references)</sup>

- **History.db**：包含 `history_visits` 和 `history_items` 表，其中存有 URL 和访问时间戳。使用 `sqlite3` 进行查询。
- **Downloads.plist**：已下载文件的信息。
- **Bookmarks.plist**：存储加入书签的 URL。
- **TopSites.plist**：访问频率最高的网站。
- **Extensions.plist**：Safari 浏览器扩展列表。使用 `plutil` 或 `pluginkit` 获取。
- **UserNotificationPermissions.plist**：允许推送通知的域名。使用 `plutil` 解析。
- **LastSession.plist**：上一个会话中的标签页。使用 `plutil` 解析。
- **Browser’s built-in anti-phishing**：使用 `defaults read com.apple.Safari WarnAboutFraudulentWebsites` 检查。响应为 1 表示该功能处于启用状态。<sup>[[2]](#references)</sup>

## Opera

Opera 的数据位于 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`，其历史记录和下载记录使用与 Chrome 相同的格式。

- **Browser’s built-in anti-phishing**：使用 `grep` 检查 Preferences 文件中的 `fraud_protection_enabled` 是否设置为 `true`，以确认该功能是否启用。<sup>[[2]](#references)</sup>

这些路径和命令对于访问和理解不同 web 浏览器存储的浏览数据至关重要。

## References

- [1] [Web Browsers Forensics: A Guide On Doing Web Browsers Forensic Analysis](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis by Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}
