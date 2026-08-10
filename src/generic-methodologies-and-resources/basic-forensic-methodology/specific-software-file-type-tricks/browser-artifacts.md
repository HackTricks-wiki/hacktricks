# Browser Artifacts

## 浏览器 Artifacts <a href="#id-3def" id="id-3def"></a>

浏览器 artifacts 包括 Web 浏览器存储的各种类型数据，例如浏览历史、书签和缓存数据。这些 artifacts 保存在操作系统中的特定文件夹内，不同浏览器的位置和名称各不相同，但通常存储类似的数据类型。

以下是最常见的浏览器 artifacts：

- **Navigation History**：记录用户访问过的网站，可用于识别对恶意网站的访问。
- **Autocomplete Data**：基于常用搜索提供建议，与浏览历史结合后可获得更多信息。
- **Bookmarks**：用户保存以便快速访问的网站。
- **Extensions and Add-ons**：用户安装的浏览器扩展或 add-ons。
- **Cache**：存储 Web 内容（例如图像、JavaScript 文件）以提高网站加载速度，对 forensic analysis 很有价值。
- **Logins**：存储的登录凭据。
- **Favicons**：与网站关联的图标，会显示在标签页和书签中，可用于获取有关用户访问记录的额外信息。
- **Browser Sessions**：与打开的浏览器会话相关的数据。
- **Downloads**：通过浏览器下载的文件记录。
- **Form Data**：在 Web 表单中输入的信息，会被保存以供未来自动填充建议使用。
- **Thumbnails**：网站的预览图像。
- **Custom Dictionary.txt**：用户添加到浏览器词典中的单词。

## Firefox

Firefox 会将用户数据组织在 profile 中，并根据操作系统将其存储在特定位置：<sup>[[1]](#references)</sup>

- **Linux**：`~/.mozilla/firefox/`
- **MacOS**：`/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**：`%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

这些目录中的 `profiles.ini` 文件会列出用户 profile。每个 profile 的数据都存储在 `profiles.ini` 中 `Path` 变量所指定名称的文件夹内，该文件夹与 `profiles.ini` 位于同一目录中。如果 profile 文件夹缺失，则可能已被删除。

在每个 profile 文件夹中，可以找到多个重要文件：<sup>[[1]](#references)</sup>

- **places.sqlite**：存储历史记录、书签和下载记录。Windows 上的 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) 等工具可以访问历史数据。
- 使用特定的 SQL 查询提取历史记录和下载信息。
- **bookmarkbackups**：包含书签备份。
- **formhistory.sqlite**：存储 Web 表单数据。
- **handlers.json**：管理协议处理程序。
- **persdict.dat**：自定义词典单词。
- **addons.json** 和 **extensions.sqlite**：已安装 add-ons 和扩展的信息。
- **cookies.sqlite**：Cookie 存储文件，Windows 上可使用 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) 进行检查。
- **cache2/entries** 或 **startupCache**：缓存数据，可通过 [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) 等工具访问。
- **favicons.sqlite**：存储 favicons。
- **prefs.js**：用户设置和偏好。
- **downloads.sqlite**：旧版下载数据库，现在已整合到 places.sqlite 中。
- **thumbnails**：网站缩略图。
- **logins.json**：加密的登录信息。
- **key4.db** 或 **key3.db**：存储用于保护敏感信息的加密密钥。

此外，可以通过在 `prefs.js` 中搜索 `browser.safebrowsing` 条目来检查浏览器的 anti-phishing 设置，以确定安全浏览功能是否已启用或禁用。<sup>[[2]](#references)</sup>

要尝试解密 master password，可以使用 [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
使用以下 script 和调用方式，可以指定密码文件进行 brute force：
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![浏览器伪影 - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome 根据操作系统将用户配置文件存储在特定位置：<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

在这些目录中，大多数用户数据可以在 **Default/** 或 **ChromeDefaultData/** 文件夹中找到。以下文件包含重要数据：<sup>[[1]](#references)</sup>

- **History**: 包含 URL、下载记录和搜索关键词。在 Windows 上，可以使用 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) 读取历史记录。"Transition Type" 列有多种含义，包括用户点击链接、输入 URL、提交表单和重新加载页面。
- **Cookies**: 存储 cookies。可以使用 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) 进行检查。
- **Cache**: 保存缓存数据。Windows 用户可以使用 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) 进行检查。

基于 Electron 的 desktop apps（例如 Discord）也使用 Chromium Simple Cache，并会在磁盘上留下丰富的 artifacts。参见：

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: 用户书签。
- **Web Data**: 包含表单历史记录。
- **Favicons**: 存储网站 favicon。
- **Login Data**: 包含用户名和密码等登录凭据。
- **Current Session**/**Current Tabs**: 当前 browsing session 和打开的标签页数据。
- **Last Session**/**Last Tabs**: Chrome 关闭前上一个 session 中处于活动状态的网站信息。
- **Extensions**: browser extensions 和 addons 的目录。
- **Thumbnails**: 存储网站缩略图。
- **Preferences**: 包含大量信息的文件，包括 plugins、extensions、pop-ups、notifications 等设置。
- **Browser’s built-in anti-phishing**: 要检查 anti-phishing 和 malware protection 是否启用，请运行 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`。在输出中查找 `{"enabled: true,"}`。<sup>[[2]](#references)</sup>

## **SQLite DB 数据恢复**

如前几节所述，Chrome 和 Firefox 都使用 **SQLite** 数据库存储数据。可以使用工具 [**sqlparse**](https://github.com/padfoot999/sqlparse) **或** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **恢复已删除的条目**。

## **Internet Explorer 11**

Internet Explorer 11 在多个位置管理其数据和 metadata，有助于分离存储的信息及其对应的详细信息，以便轻松访问和管理。

### Metadata 存储

Internet Explorer 的 metadata 存储在 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` 中（VX 可以是 V01、V16 或 V24）。此外，`V01.log` 文件显示的修改时间可能与 `WebcacheVX.data` 不一致，这表示需要使用 `esentutl /r V01 /d` 进行修复。这些 metadata 存储在 ESE database 中，可以分别使用 photorec 和 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 进行恢复和检查。在 **Containers** 表中，可以确定每个数据段存储在哪些具体表或 containers 中，其中包括 Skype 等其他 Microsoft tools 的缓存详细信息。

### Cache 检查

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 工具允许检查缓存，但需要提供缓存数据提取文件夹的位置。缓存 metadata 包括文件名、目录、访问次数、URL 来源，以及表示缓存创建、访问、修改和过期时间的 timestamps。

### Cookies 管理

可以使用 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) 检查 cookies，其 metadata 包括名称、URL、访问次数和各种时间相关详细信息。持久 cookies 存储在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` 中，而 session cookies 存在于内存中。

### Download 详细信息

可以通过 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 访问 downloads metadata，其中的特定 containers 保存 URL、文件类型和下载位置等数据。实际文件可以在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` 下找到。

### Browsing History

要查看 browsing history，可以使用 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)，但需要提供提取出的 history files 位置并配置 Internet Explorer。这里的 metadata 包括修改和访问时间，以及访问次数。History files 位于 `%userprofile%\Appdata\Local\Microsoft\Windows\History`。

### Typed URLs

Typed URLs 及其使用时间存储在 `NTUSER.DAT` registry 中的 `Software\Microsoft\InternetExplorer\TypedURLs` 和 `Software\Microsoft\InternetExplorer\TypedURLsTime` 下，用于记录用户输入的最近 50 个 URL 及其最后输入时间。

## Microsoft Edge

Microsoft Edge 将用户数据存储在 `%userprofile%\Appdata\Local\Packages` 中。各种数据类型的路径如下：<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 数据存储在 `/Users/$User/Library/Safari`。主要文件包括：<sup>[[3]](#references)</sup>

- **History.db**: 包含带有 URL 和访问 timestamps 的 `history_visits` 和 `history_items` 表。使用 `sqlite3` 进行查询。
- **Downloads.plist**: 下载文件的信息。
- **Bookmarks.plist**: 存储已添加书签的 URL。
- **TopSites.plist**: 最常访问的网站。
- **Extensions.plist**: Safari browser extensions 列表。使用 `plutil` 或 `pluginkit` 获取。
- **UserNotificationPermissions.plist**: 被允许推送 notifications 的 domains。使用 `plutil` 解析。
- **LastSession.plist**: 上一个 session 中的标签页。使用 `plutil` 解析。
- **Browser’s built-in anti-phishing**: 使用 `defaults read com.apple.Safari WarnAboutFraudulentWebsites` 检查。返回 1 表示该功能处于活动状态。<sup>[[2]](#references)</sup>

## Opera

Opera 的数据位于 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`，其 history 和 downloads 使用与 Chrome 相同的格式。

- **Browser’s built-in anti-phishing**: 使用 `grep` 检查 Preferences 文件中的 `fraud_protection_enabled` 是否设置为 `true`，以进行验证。<sup>[[2]](#references)</sup>

这些路径和命令对于访问和理解不同 web browsers 存储的 browsing data 至关重要。

## References

- [1] [Web Browsers Forensics：执行 Web Browsers Forensic Analysis 的指南](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | 第 3 部分：System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response：Jaron Bradley 编写的 Scripting and Analysis](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
