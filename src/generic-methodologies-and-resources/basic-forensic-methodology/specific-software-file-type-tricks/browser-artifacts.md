# 浏览器痕迹

{{#include ../../../banners/hacktricks-training.md}}

## Browsers Artifacts <a href="#id-3def" id="id-3def"></a>

浏览器痕迹包括由网页浏览器存储的各种类型的数据，例如浏览历史、书签和缓存数据。这些痕迹保存在操作系统内的特定文件夹中，不同浏览器的位置和名称各异，但通常存储类似类型的数据。

下面是最常见的浏览器痕迹的概述：

- **Navigation History**: 跟踪用户访问网站的记录，有助于识别访问恶意站点。
- **Autocomplete Data**: 基于常用搜索的建议，与访问历史结合可提供更多线索。
- **Bookmarks**: 用户为快速访问保存的网站。
- **Extensions and Add-ons**: 用户安装的浏览器扩展或附加组件。
- **Cache**: 存储网页内容（例如图片、JavaScript 文件），用于加快网站加载速度，对取证分析很有价值。
- **Logins**: 存储的登录凭据。
- **Favicons**: 与网站关联的图标，出现在标签和书签中，可用于补充用户访问的信息。
- **Browser Sessions**: 与打开的浏览器会话相关的数据。
- **Downloads**: 通过浏览器下载的文件记录。
- **Form Data**: 在网页表单中输入的信息，为以后自动填充保存。
- **Thumbnails**: 网站的预览图像。
- **Custom Dictionary.txt**: 用户添加到浏览器词典的单词。

## Firefox

Firefox 将用户数据组织在 profiles（配置文件）中，存储在基于操作系统的特定位置：

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

这些目录下有一个 `profiles.ini` 文件列出用户配置文件。每个配置文件的数据存储在 `profiles.ini` 中 `Path` 变量指定的文件夹中，该文件夹与 `profiles.ini` 位于相同目录。如果配置文件的文件夹不存在，可能已被删除。

在每个配置文件文件夹内，你可以找到几个重要的文件：

- **places.sqlite**: 存储历史、书签和下载。Windows 上的工具如 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) 可用于访问历史数据。
- 使用特定的 SQL 查询来提取历史和下载信息。
- **bookmarkbackups**: 包含书签的备份。
- **formhistory.sqlite**: 存储网页表单数据。
- **handlers.json**: 管理协议处理程序。
- **persdict.dat**: 自定义词典单词。
- **addons.json** 和 **extensions.sqlite**: 已安装的 add-ons 和扩展的信息。
- **cookies.sqlite**: Cookie 存储；Windows 上可使用 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) 检查。
- **cache2/entries** 或 **startupCache**: 缓存数据，可使用 [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) 等工具访问。
- **favicons.sqlite**: 存储 favicons。
- **prefs.js**: 用户设置和偏好。
- **downloads.sqlite**: 旧版的下载数据库，现已合并到 places.sqlite 中。
- **thumbnails**: 网站缩略图。
- **logins.json**: 加密的登录信息。
- **key4.db** 或 **key3.db**: 存储用于保护敏感信息的加密密钥。

另外，可以通过在 `prefs.js` 中搜索 `browser.safebrowsing` 条目来检查浏览器的反钓鱼设置，从而判断安全浏览功能是启用还是禁用。

To try to decrypt the master password, you can use https://github.com/unode/firefox_decrypt\
With the following script and call you can specify a password file to brute force:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Google Chrome 会根据操作系统将用户配置文件存储在特定位置：

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

在这些目录中，大多数用户数据可以在 **Default/** 或 **ChromeDefaultData/** 文件夹中找到。以下文件包含重要数据：

- **History**: 包含 URLs、downloads 和搜索关键词。在 Windows 上，可以使用 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) 来读取 history。"Transition Type" 列有多种含义，包括用户点击链接、手动输入 URL、表单提交和页面重新加载等。
- **Cookies**: 存储 cookies。可使用 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) 检查。
- **Cache**: 保存缓存数据。Windows 用户可使用 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) 检查。

基于 Electron 的桌面应用（例如 Discord）也使用 Chromium Simple Cache，并在磁盘上留下丰富的痕迹。参见：

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: 用户书签。
- **Web Data**: 包含表单历史。
- **Favicons**: 存储网站的 favicon。
- **Login Data**: 包含登录凭据，如用户名和密码。
- **Current Session**/**Current Tabs**: 有关当前浏览会话和打开标签页的数据。
- **Last Session**/**Last Tabs**: 在 Chrome 关闭前最后一次会话中活跃站点的信息。
- **Extensions**: 浏览器扩展和 addon 的目录。
- **Thumbnails**: 存储网站缩略图。
- **Preferences**: 一个包含大量信息的文件，包括插件、扩展、弹窗、通知等设置。
- **Browser’s built-in anti-phishing**: 要检查 anti-phishing 和 malware protection 是否启用，运行 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`。在输出中查找 `{"enabled: true,"}`。

## **SQLite DB Data Recovery**

如前面章节所示，Chrome 和 Firefox 都使用 **SQLite** 数据库来存储数据。可以使用工具 [**sqlparse**](https://github.com/padfoot999/sqlparse) 或 [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **恢复已删除的条目**。

## **Internet Explorer 11**

Internet Explorer 11 在多个位置管理其数据和元数据，便于将存储的信息与其相应的详细信息分离以便访问和管理。

### Metadata Storage

Internet Explorer 的元数据存储在 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`（其中 VX 为 V01、V16 或 V24）。同时，`V01.log` 文件可能显示与 `WebcacheVX.data` 的修改时间不一致，这表明需要使用 `esentutl /r V01 /d` 进行修复。此元数据位于一个 ESE 数据库中，可以使用 photorec 恢复，并可使用 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 进行检查。在 **Containers** 表中，可以辨别每个数据段存放的具体表或容器，包括其他 Microsoft 工具（如 Skype）的缓存细节。

### Cache Inspection

使用 [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 工具可以检查缓存，需提供提取的缓存数据文件夹位置。缓存元数据包括文件名、目录、访问计数、URL 来源，以及表示缓存创建、访问、修改和过期时间的时间戳。

### Cookies Management

可以使用 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) 浏览 cookies，元数据包括名称、URL、访问计数和各种时间相关细节。持久性 cookie 存储在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`，会话 cookie 则驻留在内存中。

### Download Details

下载元数据可通过 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 访问，特定容器包含诸如 URL、文件类型和下载位置等数据。物理文件可在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` 下找到。

### Browsing History

要查看浏览历史，可使用 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)，需要已提取的 history 文件位置并为 Internet Explorer 配置。此处的元数据包括修改和访问时间以及访问计数。History 文件位于 `%userprofile%\Appdata\Local\Microsoft\Windows\History`。

### Typed URLs

Typed URLs 及其使用时间存储在注册表的 `NTUSER.DAT` 下：`Software\Microsoft\InternetExplorer\TypedURLs` 和 `Software\Microsoft\InternetExplorer\TypedURLsTime`，用于追踪用户最后输入的 50 个 URL 及其最后输入时间。

## Microsoft Edge

Microsoft Edge 将用户数据存储在 `%userprofile%\Appdata\Local\Packages`。各类数据的路径如下：

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 数据存储在 `/Users/$User/Library/Safari`。关键文件包括：

- **History.db**: 包含 `history_visits` 和 `history_items` 表，含有 URLs 和访问时间戳。使用 `sqlite3` 查询。
- **Downloads.plist**: 有关下载文件的信息。
- **Bookmarks.plist**: 存储书签 URL。
- **TopSites.plist**: 最常访问的网站。
- **Extensions.plist**: Safari 浏览器扩展列表。使用 `plutil` 或 `pluginkit` 获取。
- **UserNotificationPermissions.plist**: 被允许推送通知的域名。使用 `plutil` 解析。
- **LastSession.plist**: 上次会话的标签页。使用 `plutil` 解析。
- **Browser’s built-in anti-phishing**: 通过 `defaults read com.apple.Safari WarnAboutFraudulentWebsites` 检查。返回 1 表示该功能已启用。

## Opera

Opera 的数据位于 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`，其 history 和 downloads 的格式与 Chrome 相同。

- **Browser’s built-in anti-phishing**: 通过检查 Preferences 文件中 `fraud_protection_enabled` 是否为 `true`（使用 `grep`）来验证。

这些路径和命令对于访问和理解不同 web 浏览器存储的浏览数据非常重要。

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- 书：OS X Incident Response: Scripting and Analysis 作者 Jaron Bradley 第123页


{{#include ../../../banners/hacktricks-training.md}}
