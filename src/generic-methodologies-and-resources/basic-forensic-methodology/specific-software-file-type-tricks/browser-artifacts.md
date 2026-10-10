# 浏览器痕迹

{{#include ../../../banners/hacktricks-training.md}}

## 浏览器痕迹 <a href="#id-3def" id="id-3def"></a>

浏览器痕迹包括 Web 浏览器存储的各种数据，例如浏览历史、书签和缓存数据。这些痕迹保存在操作系统中的特定文件夹内。不同浏览器的文件夹位置和名称各不相同，但通常存储相似类型的数据。

以下是最常见浏览器痕迹的摘要：

- **浏览历史**：记录用户访问过的网站，可用于识别用户是否访问过恶意网站。
- **自动完成数据**：根据常用搜索提供建议，与浏览历史结合分析时可提供有价值的信息。
- **书签**：用户保存以便快速访问的网站。
- **扩展和附加组件**：用户安装的浏览器扩展或附加组件。
- **缓存**：存储 Web 内容（例如图片、JavaScript 文件），以提高网站加载速度，对取证分析很有价值。
- **登录信息**：存储的登录凭据。
- **网站图标**：与网站关联的图标，会显示在标签页和书签中，可提供有关用户访问情况的补充信息。
- **浏览器会话**：与打开的浏览器会话相关的数据。
- **下载记录**：通过浏览器下载的文件记录。
- **表单数据**：在 Web 表单中输入的信息，会保存下来以便日后提供自动填充建议。
- **缩略图**：网站的预览图片。
- **Custom Dictionary.txt**：用户添加到浏览器词典中的词语。

## Firefox

Firefox 会将用户数据整理到配置文件中，并根据操作系统将其存储在特定位置：<sup>[[1]](#references)</sup>

- **Linux**：`~/.mozilla/firefox/`
- **MacOS**：`/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**：`%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

这些目录中的 `profiles.ini` 文件会列出用户配置文件。每个配置文件的数据都存储在 `profiles.ini` 中 `Path` 变量指定的文件夹内，该文件夹与 `profiles.ini` 位于同一目录。如果配置文件对应的文件夹缺失，该配置文件可能已被删除。

在每个配置文件夹中，可以找到多个重要文件：<sup>[[1]](#references)</sup>

- **places.sqlite**：存储浏览历史、书签和下载记录。在 Windows 上，可以使用 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) 等工具访问历史数据。
  - 使用特定的 SQL 查询提取浏览历史和下载信息。
- **bookmarkbackups**：包含书签备份。
- **formhistory.sqlite**：存储 Web 表单数据。
- **handlers.json**：管理协议处理程序。
- **persdict.dat**：自定义词典中的词语。
- **addons.json** 和 **extensions.sqlite**：有关已安装附加组件和扩展的信息。
- **cookies.sqlite**：Cookie 存储文件；在 Windows 上可使用 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) 查看。
- **cache2/entries** 或 **startupCache**：缓存数据，可使用 [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) 等工具访问。
- **favicons.sqlite**：存储网站图标。
- **prefs.js**：用户设置和首选项。
- **downloads.sqlite**：较旧的下载数据库，现已整合到 places.sqlite 中。
- **thumbnails**：网站缩略图。
- **logins.json**：加密的登录信息。
- **key4.db** 或 **key3.db**：存储用于保护敏感信息的加密密钥。

此外，可以在 `prefs.js` 中搜索 `browser.safebrowsing` 条目，检查浏览器的反钓鱼设置，以判断安全浏览功能是否已启用或禁用。<sup>[[2]](#references)</sup>

若要解密可访问配置文件中保存的登录信息，必须提供已配置的 [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins)，或另行找回该密码；配置文件本身不会泄露该密码。请确认找回的登录信息能够通过其 Web 账户的身份验证。Unix root 访问权限需要单独证明该凭据也能通过 Unix 的 root 身份验证。你可以使用 [firefox_decrypt](https://github.com/unode/firefox_decrypt) 查看已保存的登录信息。以下示例会从密码文件中测试候选 Primary Password：

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![浏览器痕迹 - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome 会根据操作系统将用户配置文件存储在特定位置：<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

在这些目录中，大多数用户数据都可以在 **Default/** 或 **ChromeDefaultData/** 文件夹中找到。以下文件包含重要数据：<sup>[[1]](#references)</sup>

- **History**: 包含 URL、下载记录和搜索关键词。在 Windows 上，可以使用 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) 查看历史记录。“Transition Type”列有多种含义，包括用户点击链接、输入 URL、提交表单和重新加载页面。
- **Cookies**: 存储 cookies。可使用 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) 检查。
- **Cache**: 存储缓存数据。Windows 用户可使用 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) 检查。

  基于 Electron 的桌面应用（例如 Discord）也使用 Chromium Simple Cache，并会在磁盘上留下丰富的痕迹。参见：

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: 用户书签。
- **Web Data**: 包含表单历史记录。
- **Favicons**: 存储网站 favicon。
- **Login Data**: 包含用户名和密码等登录凭据。
- **Current Session**/**Current Tabs**: 当前浏览会话和已打开标签页的数据。
- **Last Session**/**Last Tabs**: Chrome 关闭前上一个会话中活动网站的信息。
- **Extensions**: 浏览器扩展和插件的目录。
- **Thumbnails**: 存储网站缩略图。
- **Preferences**: 信息丰富的文件，包含插件、扩展、弹出窗口、通知等设置。
- **浏览器内置的反钓鱼功能**: 运行 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`，检查是否启用了反钓鱼和恶意软件防护。在输出中查找 `{"enabled: true,"}`。<sup>[[2]](#references)</sup>

Chromium 配置文件的 `Local Extension Settings/<extension-id>/` 目录可能包含扩展本地状态，包括密码管理器的密钥材料。例如，[Passbolt 表示其加密私钥保存在浏览器扩展的本地存储中](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/)，其 [Chrome 扩展 ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) 可用于定位相关目录。仅凭目录存在，既无法证明其中有密钥，也无法解锁保险库：用户必须能够访问配置文件数据，并持有可用的私钥和密码短语，同时还需要通过服务器授权的恢复/身份验证途径。若保险库条目包含操作系统帐户密码，则需要单独验证该密码是否被重复使用。常规枚举只应报告存储路径，不应转储其 LevelDB 文件或机密值。

## **SQLite 数据库数据恢复**

如前文所示，Chrome 和 Firefox 都使用 **SQLite** 数据库存储数据。可以使用工具 [**sqlparse**](https://github.com/padfoot999/sqlparse) **或** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **恢复已删除的条目**。

## **Internet Explorer 11**

Internet Explorer 11 在多个位置管理其数据和元数据，以便将存储的信息及其相关详情分开，方便访问和管理。

### 元数据存储

Internet Explorer 的元数据存储在 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` 中（VX 为 V01、V16 或 V24）。与之关联的 `V01.log` 文件可能会显示其修改时间与 `WebcacheVX.data` 不一致，这表示可能需要使用 `esentutl /r V01 /d` 进行修复。这些元数据存储在 ESE 数据库中，可分别使用 photorec 和 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 等工具进行恢复和检查。在 **Containers** 表中，可以查看每个数据段存储在哪些具体表或容器中，其中也包括 Skype 等其他 Microsoft 工具的缓存详情。

### 缓存检查

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 工具可用于检查缓存，需要指定缓存数据的提取文件夹位置。缓存元数据包括文件名、目录、访问次数、URL 来源，以及表示缓存创建、访问、修改和过期时间的时间戳。

### Cookie 管理

可以使用 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) 检查 cookies，其元数据包括名称、URL、访问次数和各种时间信息。持久性 cookies 存储在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` 中，会话 cookies 则驻留在内存中。

### 下载详情

可通过 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 查看下载元数据；特定容器中包含 URL、文件类型和下载位置等数据。实际文件可在 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` 中找到。

### 浏览历史记录

若要查看浏览历史记录，可使用 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)，并指定已提取历史记录文件的位置以及 Internet Explorer 的配置。此处的元数据包括修改和访问时间，以及访问次数。历史记录文件位于 `%userprofile%\Appdata\Local\Microsoft\Windows\History`。

### 输入的 URL

用户输入的 URL 及其输入时间存储在注册表 `NTUSER.DAT` 中的 `Software\Microsoft\InternetExplorer\TypedURLs` 和 `Software\Microsoft\InternetExplorer\TypedURLsTime` 下，记录用户输入的最近 50 个 URL 及其最后输入时间。

## Microsoft Edge

Microsoft Edge 将用户数据存储在 `%userprofile%\Appdata\Local\Packages` 中。各种数据类型对应的路径如下：<sup>[[1]](#references)</sup>

- **配置文件路径**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **历史记录、Cookies 和下载记录**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **设置、书签和阅读列表**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **缓存**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **最近活动的会话**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 数据存储在 `/Users/$User/Library/Safari`。重要文件包括：<sup>[[3]](#references)</sup>

- **History.db**: 包含 `history_visits` 和 `history_items` 表，其中有 URL 和访问时间戳。可使用 `sqlite3` 查询。
- **Downloads.plist**: 下载文件的信息。
- **Bookmarks.plist**: 存储已加入书签的 URL。
- **TopSites.plist**: 访问频率最高的网站。
- **Extensions.plist**: Safari 浏览器扩展列表。可使用 `plutil` 或 `pluginkit` 获取。
- **UserNotificationPermissions.plist**: 获准发送推送通知的域名。可使用 `plutil` 解析。
- **LastSession.plist**: 上个会话中的标签页。可使用 `plutil` 解析。
- **浏览器内置的反钓鱼功能**: 使用 `defaults read com.apple.Safari WarnAboutFraudulentWebsites` 检查。返回值为 1 表示该功能已启用。<sup>[[2]](#references)</sup>

## Opera

Opera 的数据存储在 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`，其历史记录和下载记录使用与 Chrome 相同的格式。

- **浏览器内置的反钓鱼功能**: 使用 `grep` 检查 Preferences 文件中的 `fraud_protection_enabled` 是否设置为 `true`。<sup>[[2]](#references)</sup>

这些路径和命令对于访问和了解不同 Web 浏览器存储的浏览数据至关重要。

## References

- [1] [Web 浏览器取证：Web 浏览器取证分析指南](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS 事件响应 | 第 3 部分：系统操纵](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X 事件响应：Jaron Bradley 编写的脚本与分析](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
