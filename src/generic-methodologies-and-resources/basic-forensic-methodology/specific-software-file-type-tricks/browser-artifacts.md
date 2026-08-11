# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## 浏览器 Artifacts <a href="#id-3def" id="id-3def"></a>

浏览器 artifacts 包括 Web 浏览器存储的各种类型数据，例如导航历史记录、书签和缓存数据。这些 artifacts 存储在操作系统中的特定文件夹内，不同浏览器的存储位置和名称有所不同，但通常保存相似的数据类型。

以下是最常见的浏览器 artifacts：

- **导航历史记录**：记录用户访问过的网站，可用于确认用户是否访问过恶意网站。
- **自动完成数据**：基于常用搜索生成的建议，与导航历史记录结合分析时可以提供有价值的信息。
- **书签**：用户保存以便快速访问的网站。
- **扩展和附加组件**：用户安装的浏览器扩展或附加组件。
- **缓存**：存储 Web 内容（例如图像、JavaScript 文件）以提高网站加载速度，对 forensic 分析很有价值。
- **登录信息**：存储的登录凭据。
- **Favicons**：与网站关联的图标，会显示在标签页和书签中，可用于获取用户访问记录的额外信息。
- **浏览器会话**：与打开的浏览器会话相关的数据。
- **下载记录**：通过浏览器下载的文件记录。
- **表单数据**：在 Web 表单中输入的信息，会被保存以便日后提供自动填充建议。
- **缩略图**：网站的预览图像。
- **Custom Dictionary.txt**：用户添加到浏览器词典中的单词。

## Firefox

Firefox 会将用户数据组织在 profiles 中，并根据操作系统将其存储在特定位置：<sup>[[1]](#references)</sup>

- **Linux**：`~/.mozilla/firefox/`
- **MacOS**：`/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**：`%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

这些目录中的 `profiles.ini` 文件会列出用户 profiles。每个 profile 的数据都存储在 `profiles.ini` 中 `Path` 变量指定的文件夹内，该文件夹与 `profiles.ini` 位于同一目录。如果某个 profile 的文件夹缺失，则可能已被删除。

在每个 profile 文件夹中，可以找到几个重要文件：<sup>[[1]](#references)</sup>

- **places.sqlite**：存储历史记录、书签和下载记录。在 Windows 上，可以使用 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) 等工具访问历史记录数据。
- 使用特定的 SQL 查询提取历史记录和下载信息。
- **bookmarkbackups**：包含书签备份。
- **formhistory.sqlite**：存储 Web 表单数据。
- **handlers.json**：管理协议处理程序。
- **persdict.dat**：自定义词典单词。
- **addons.json** 和 **extensions.sqlite**：已安装附加组件和扩展的信息。
- **cookies.sqlite**：Cookie 存储文件，在 Windows 上可以使用 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) 进行检查。
- **cache2/entries** 或 **startupCache**：缓存数据，可通过 [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) 等工具访问。
- **favicons.sqlite**：存储 Favicons。
- **prefs.js**：用户设置和偏好。
- **downloads.sqlite**：旧版下载数据库，目前已集成到 places.sqlite 中。
- **thumbnails**：网站缩略图。
- **logins.json**：加密的登录信息。
- **key4.db** 或 **key3.db**：存储用于保护敏感信息的加密密钥。

此外，可以通过在 `prefs.js` 中搜索 `browser.safebrowsing` 条目来检查浏览器的反钓鱼设置，从而确认安全浏览功能是否已启用或禁用。<sup>[[2]](#references)</sup>

要尝试解密 master password，可以使用 [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
使用以下脚本和调用方式，可以指定密码文件进行 brute force：
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![浏览器取证痕迹 - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome 会根据操作系统将用户配置文件存储在特定位置：<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

在这些目录中，大多数用户数据位于 **Default/** 或 **ChromeDefaultData/** 文件夹中。以下文件包含重要数据：<sup>[[1]](#references)</sup>

- **History**: 包含 URL、下载记录和搜索关键词。在 Windows 上，可以使用 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) 读取历史记录。"Transition Type" 列包含多种含义，包括用户点击链接、输入 URL、提交表单和重新加载页面。
- **Cookies**: 存储 cookies。可以使用 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) 进行检查。
- **Cache**: 保存缓存数据。Windows 用户可以使用 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) 进行检查。

基于 Electron 的桌面应用（例如 Discord）也使用 Chromium Simple Cache，并会在磁盘上留下丰富的 artifacts。参见：

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: 用户书签。
- **Web Data**: 包含表单历史记录。
- **Favicons**: 存储网站 favicon。
- **Login Data**: 包含用户名和密码等登录凭据。
- **Current Session**/**Current Tabs**: 当前浏览会话和打开标签页的数据。
- **Last Session**/**Last Tabs**: Chrome 关闭前上次会话中处于活动状态的网站信息。
- **Extensions**: 浏览器扩展和 addons 的目录。
- **Thumbnails**: 存储网站缩略图。
- **Preferences**: 包含大量信息的文件，包括插件、扩展、弹窗、通知等设置。
- **Browser’s built-in anti-phishing**: 要检查 anti-phishing 和 malware 防护是否启用，请运行 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`。在输出中查找 `{"enabled: true,"}`。<sup>[[2]](#references)</sup>

## **SQLite DB 数据恢复**

如前几节所示，Chrome 和 Firefox 都使用 **SQLite** 数据库存储数据。可以使用工具 [**sqlparse**](https://github.com/padfoot999/sqlparse) **或** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **恢复已删除的条目**。

## **Internet Explorer 11**

Internet Explorer 11 将数据及其元数据存储在多个位置，从而有助于分离已存储的信息及其对应的详细信息，便于访问和管理。

### 元数据存储

Internet Explorer 的元数据存储在 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` 中（其中 VX 为 V01、V16 或 V24）。此外，`V01.log` 文件中的修改时间可能与 `WebcacheVX.data` 不一致，这表示可能需要使用 `esentutl /r V01 /d` 进行修复。这些元数据存储在 ESE 数据库中，可以分别使用 photorec 和 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 进行恢复和检查。在 **Containers** 表中，可以确定每个数据段存储在哪些具体表或容器中，其中也包括 Skype 等其他 Microsoft 工具的缓存详细信息。

### 缓存检查

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 工具可用于检查缓存，但需要提供缓存数据提取文件夹的位置。缓存元数据包括文件名、目录、访问次数、URL 来源，以及表示缓存创建、访问、修改和过期时间的时间戳。

### Cookies 管理

可以使用 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) 查看 cookies，其元数据包括名称、URL、访问次数以及各种时间相关详细信息。持久 cookies 存储在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` 中，会话 cookies 则存储在内存中。

### 下载详细信息

可以通过 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 访问下载元数据，特定容器中包含 URL、文件类型和下载位置等数据。物理文件位于 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` 下。

### 浏览历史记录

要查看浏览历史记录，可以使用 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)，但需要提供提取的历史记录文件位置，并配置 Internet Explorer。这里的元数据包括修改时间、访问时间和访问次数。历史记录文件位于 `%userprofile%\Appdata\Local\Microsoft\Windows\History`。

### 输入的 URL

输入的 URL 及其使用时间存储在 `NTUSER.DAT` 注册表中的 `Software\Microsoft\InternetExplorer\TypedURLs` 和 `Software\Microsoft\InternetExplorer\TypedURLsTime` 下，用于记录用户输入的最近 50 个 URL 及其最后输入时间。

## Microsoft Edge

Microsoft Edge 将用户数据存储在 `%userprofile%\Appdata\Local\Packages` 中。不同数据类型的路径如下：<sup>[[1]](#references)</sup>

- **配置文件路径**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **历史记录、Cookies 和下载记录**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **设置、书签和阅读列表**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **缓存**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **最近活动会话**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 数据存储在 `/Users/$User/Library/Safari` 中。重要文件包括：<sup>[[3]](#references)</sup>

- **History.db**: 包含 `history_visits` 和 `history_items` 表，其中记录 URL 和访问时间戳。使用 `sqlite3` 进行查询。
- **Downloads.plist**: 已下载文件的信息。
- **Bookmarks.plist**: 存储已添加书签的 URL。
- **TopSites.plist**: 访问频率最高的网站。
- **Extensions.plist**: Safari 浏览器扩展列表。使用 `plutil` 或 `pluginkit` 获取。
- **UserNotificationPermissions.plist**: 被允许推送通知的域。使用 `plutil` 进行解析。
- **LastSession.plist**: 上次会话中的标签页。使用 `plutil` 进行解析。
- **Browser’s built-in anti-phishing**: 使用 `defaults read com.apple.Safari WarnAboutFraudulentWebsites` 检查。返回 1 表示该功能处于启用状态。<sup>[[2]](#references)</sup>

## Opera

Opera 的数据位于 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`，其历史记录和下载记录使用与 Chrome 相同的格式。

- **Browser’s built-in anti-phishing**: 使用 `grep` 检查 Preferences 文件中的 `fraud_protection_enabled` 是否设置为 `true`，以确认该功能是否启用。<sup>[[2]](#references)</sup>

这些路径和命令对于访问和理解不同 web 浏览器存储的浏览数据至关重要。

## References

- [1] [Web 浏览器取证：执行 Web 浏览器取证分析指南](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS 事件响应 | 第 3 部分：系统操作](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X 事件响应：Jaron Bradley 编写的脚本与分析](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
