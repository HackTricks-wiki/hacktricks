# Browser 아티팩트

{{#include ../../../banners/hacktricks-training.md}}

## 브라우저 아티팩트 <a href="#id-3def" id="id-3def"></a>

브라우저 아티팩트에는 웹 브라우저에 저장된 탐색 기록, 북마크, 캐시 데이터 등 다양한 유형의 데이터가 포함됩니다. 이러한 아티팩트는 운영 체제 내 특정 폴더에 저장되며, 브라우저마다 위치와 이름은 다르지만 일반적으로 유사한 유형의 데이터를 저장합니다.

다음은 가장 일반적인 브라우저 아티팩트의 요약입니다.

- **탐색 기록**: 사용자의 웹사이트 방문 기록을 추적하며, 악성 사이트 방문 여부를 확인하는 데 유용합니다.
- **자동 완성 데이터**: 자주 검색한 내용을 기반으로 한 제안으로, 탐색 기록과 함께 분석하면 유용한 정보를 제공합니다.
- **북마크**: 빠르게 접근할 수 있도록 사용자가 저장한 사이트입니다.
- **확장 프로그램 및 Add-on**: 사용자가 설치한 브라우저 확장 프로그램 또는 Add-on입니다.
- **캐시**: 웹사이트 로딩 시간을 개선하기 위해 웹 콘텐츠(예: 이미지, JavaScript 파일)를 저장하며, forensic analysis에 유용합니다.
- **로그인**: 저장된 로그인 자격 증명입니다.
- **파비콘**: 웹사이트와 연결된 아이콘으로, 탭과 북마크에 표시되며 사용자의 추가 방문 정보를 확인하는 데 유용합니다.
- **브라우저 세션**: 열려 있는 브라우저 세션과 관련된 데이터입니다.
- **다운로드**: 브라우저를 통해 다운로드한 파일의 기록입니다.
- **폼 데이터**: 웹 폼에 입력한 정보로, 이후 자동 완성 제안에 사용하기 위해 저장됩니다.
- **썸네일**: 웹사이트의 미리보기 이미지입니다.
- **Custom Dictionary.txt**: 사용자가 브라우저 사전에 추가한 단어입니다.

## Firefox

Firefox는 운영 체제에 따라 특정 위치에 저장되는 프로필 내에 사용자 데이터를 구성합니다.<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

이 디렉터리 내의 `profiles.ini` 파일에는 사용자 프로필 목록이 포함되어 있습니다. 각 프로필의 데이터는 `profiles.ini`의 `Path` 변수에 지정된 이름의 폴더에 저장되며, 이 폴더는 `profiles.ini` 자체와 동일한 디렉터리에 있습니다. 프로필 폴더가 없다면 삭제되었을 수 있습니다.

각 프로필 폴더에서는 몇 가지 중요한 파일을 확인할 수 있습니다.<sup>[[1]](#references)</sup>

- **places.sqlite**: 기록, 북마크, 다운로드를 저장합니다. Windows의 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)와 같은 도구를 사용하면 기록 데이터에 접근할 수 있습니다.
- 특정 SQL 쿼리를 사용하여 기록 및 다운로드 정보를 추출합니다.
- **bookmarkbackups**: 북마크 백업을 포함합니다.
- **formhistory.sqlite**: 웹 폼 데이터를 저장합니다.
- **handlers.json**: protocol handler를 관리합니다.
- **persdict.dat**: 사용자 지정 사전 단어를 저장합니다.
- **addons.json** 및 **extensions.sqlite**: 설치된 Add-on 및 확장 프로그램 정보를 포함합니다.
- **cookies.sqlite**: 쿠키 저장소이며, Windows에서는 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)를 사용하여 검사할 수 있습니다.
- **cache2/entries** 또는 **startupCache**: 캐시 데이터이며, [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)와 같은 도구를 통해 접근할 수 있습니다.
- **favicons.sqlite**: 파비콘을 저장합니다.
- **prefs.js**: 사용자 설정 및 환경 설정을 저장합니다.
- **downloads.sqlite**: 이전 다운로드 데이터베이스이며, 현재는 places.sqlite에 통합되었습니다.
- **thumbnails**: 웹사이트 썸네일입니다.
- **logins.json**: 암호화된 로그인 정보입니다.
- **key4.db** 또는 **key3.db**: 민감한 정보를 보호하기 위한 암호화 키를 저장합니다.

또한 `prefs.js`에서 `browser.safebrowsing` 항목을 검색하면 브라우저의 anti-phishing 설정을 확인할 수 있으며, 이를 통해 safe browsing 기능의 활성화 또는 비활성화 여부를 확인할 수 있습니다.<sup>[[2]](#references)</sup>

master password를 decrypt하려면 [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)를 사용할 수 있습니다.\
다음 스크립트와 호출 방법을 사용하면 brute force에 사용할 password file을 지정할 수 있습니다:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Browsers Artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome은 운영 체제에 따라 특정 위치에 사용자 프로필을 저장합니다:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

이 디렉터리에서 대부분의 사용자 데이터는 **Default/** 또는 **ChromeDefaultData/** 폴더에 있습니다. 다음 파일에는 중요한 데이터가 저장됩니다:<sup>[[1]](#references)</sup>

- **History**: URL, 다운로드 및 검색 키워드를 포함합니다. Windows에서는 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)를 사용하여 기록을 읽을 수 있습니다. "Transition Type" 열에는 사용자의 링크 클릭, 입력한 URL, 양식 제출 및 페이지 새로 고침 등을 나타내는 다양한 값이 있습니다.
- **Cookies**: 쿠키를 저장합니다. 검사에는 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)를 사용할 수 있습니다.
- **Cache**: 캐시된 데이터를 보관합니다. Windows 사용자는 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)를 사용하여 검사할 수 있습니다.

Electron 기반 desktop app(예: Discord)도 Chromium Simple Cache를 사용하며 디스크에 풍부한 artifact를 남깁니다. 다음을 참조하세요.

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: 사용자 북마크입니다.
- **Web Data**: 양식 기록을 포함합니다.
- **Favicons**: 웹사이트 파비콘을 저장합니다.
- **Login Data**: 사용자 이름 및 비밀번호와 같은 로그인 자격 증명을 포함합니다.
- **Current Session**/**Current Tabs**: 현재 browsing session 및 열린 탭에 대한 데이터입니다.
- **Last Session**/**Last Tabs**: Chrome이 종료되기 전 마지막 session에서 활성화되어 있던 사이트에 대한 정보입니다.
- **Extensions**: browser extension 및 addon 디렉터리입니다.
- **Thumbnails**: 웹사이트 썸네일을 저장합니다.
- **Preferences**: plugin, extension, 팝업, 알림 등의 설정을 포함하는 정보가 풍부한 파일입니다.
- **Browser’s built-in anti-phishing**: anti-phishing 및 malware protection이 활성화되어 있는지 확인하려면 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`를 실행합니다. 출력에서 `{"enabled: true,"}`를 찾습니다.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

이전 섹션에서 확인할 수 있듯이 Chrome과 Firefox는 모두 **SQLite** database를 사용하여 데이터를 저장합니다. [**sqlparse**](https://github.com/padfoot999/sqlparse) **또는** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) 도구를 사용하여 **삭제된 entry를 복구할 수 있습니다**.

## **Internet Explorer 11**

Internet Explorer 11은 다양한 위치에서 데이터와 metadata를 관리하므로, 저장된 정보와 관련 세부 정보를 분리하여 쉽게 접근하고 관리할 수 있습니다.

### Metadata Storage

Internet Explorer의 metadata는 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`에 저장됩니다(VX는 V01, V16 또는 V24). 이와 함께 `V01.log` 파일에 `WebcacheVX.data`와의 modification time 불일치가 나타날 수 있으며, 이는 `esentutl /r V01 /d`를 사용한 repair가 필요함을 의미합니다. ESE database에 저장된 이 metadata는 각각 photorec 및 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)와 같은 도구를 사용하여 복구하고 검사할 수 있습니다. **Containers** table에서는 각 데이터 세그먼트가 저장된 특정 table 또는 container를 확인할 수 있으며, 여기에는 Skype와 같은 다른 Microsoft 도구의 cache 세부 정보도 포함됩니다.

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 도구를 사용하면 cache를 검사할 수 있으며, cache data extraction folder의 위치가 필요합니다. Cache metadata에는 filename, directory, access count, URL origin 및 cache 생성, 접근, 수정, 만료 시간을 나타내는 timestamp가 포함됩니다.

### Cookies Management

[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)를 사용하여 cookie를 확인할 수 있으며, metadata에는 이름, URL, access count 및 다양한 time-related 세부 정보가 포함됩니다. Persistent cookie는 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`에 저장되고, session cookie는 memory에 저장됩니다.

### Download Details

Download metadata는 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)를 통해 확인할 수 있으며, 특정 container에는 URL, file type 및 download location과 같은 데이터가 저장됩니다. 실제 파일은 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`에서 찾을 수 있습니다.

### Browsing History

Browsing history를 검토하려면 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)를 사용할 수 있으며, 추출된 history file의 위치와 Internet Explorer 구성이 필요합니다. 여기의 metadata에는 modification time, access time 및 access count가 포함됩니다. History file은 `%userprofile%\Appdata\Local\Microsoft\Windows\History`에 있습니다.

### Typed URLs

입력한 URL과 사용 시간은 `NTUSER.DAT`의 `Software\Microsoft\InternetExplorer\TypedURLs` 및 `Software\Microsoft\InternetExplorer\TypedURLsTime` registry key에 저장되며, 사용자가 입력한 마지막 50개의 URL과 마지막 입력 시간을 추적합니다.

## Microsoft Edge

Microsoft Edge는 `%userprofile%\Appdata\Local\Packages`에 사용자 데이터를 저장합니다. 다양한 데이터 유형의 경로는 다음과 같습니다:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 데이터는 `/Users/$User/Library/Safari`에 저장됩니다. 주요 파일은 다음과 같습니다:<sup>[[3]](#references)</sup>

- **History.db**: URL 및 방문 timestamp가 포함된 `history_visits` 및 `history_items` table을 포함합니다. 쿼리에는 `sqlite3`를 사용합니다.
- **Downloads.plist**: 다운로드한 파일에 대한 정보입니다.
- **Bookmarks.plist**: 북마크한 URL을 저장합니다.
- **TopSites.plist**: 가장 자주 방문한 사이트입니다.
- **Extensions.plist**: Safari browser extension 목록입니다. 검색에는 `plutil` 또는 `pluginkit`을 사용합니다.
- **UserNotificationPermissions.plist**: push notification이 허용된 domain입니다. parsing에는 `plutil`을 사용합니다.
- **LastSession.plist**: 마지막 session의 탭입니다. parsing에는 `plutil`을 사용합니다.
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`를 사용하여 확인합니다. 응답이 1이면 해당 기능이 활성화되어 있음을 의미합니다.<sup>[[2]](#references)</sup>

## Opera

Opera의 데이터는 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`에 있으며, history 및 download에 Chrome과 동일한 형식을 사용합니다.

- **Browser’s built-in anti-phishing**: `grep`을 사용하여 Preferences 파일의 `fraud_protection_enabled`가 `true`로 설정되어 있는지 확인합니다.<sup>[[2]](#references)</sup>

이러한 경로와 command는 여러 web browser가 저장한 browsing data에 접근하고 이를 이해하는 데 중요합니다.

## References

- [1] [Web browser forensics: web browser forensic analysis 수행 가이드](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Jaron Bradley의 Scripting and Analysis](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
