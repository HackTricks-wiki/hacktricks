# 브라우저 아티팩트

{{#include ../../../banners/hacktricks-training.md}}

## 브라우저 아티팩트 <a href="#id-3def" id="id-3def"></a>

브라우저 아티팩트는 내비게이션 기록, 즐겨찾기, 캐시 데이터 등 웹 브라우저가 저장하는 다양한 유형의 데이터를 포함합니다. 이러한 아티팩트는 운영체제 내의 특정 폴더에 보관되며, 브라우저마다 위치와 이름이 다르지만 일반적으로 유사한 유형의 데이터를 저장합니다.

다음은 가장 일반적인 브라우저 아티팩트의 요약입니다:

- **Navigation History**: 사용자의 웹사이트 방문을 추적하며, 악성 사이트 방문 식별에 유용합니다.
- **Autocomplete Data**: 자주 사용하는 검색을 기반으로 한 제안으로, 내비게이션 기록과 결합하면 유용한 통찰을 제공합니다.
- **Bookmarks**: 사용자가 빠르게 접근하기 위해 저장한 사이트들입니다.
- **Extensions and Add-ons**: 사용자가 설치한 브라우저 확장 또는 애드온입니다.
- **Cache**: 웹 콘텐츠(예: 이미지, JavaScript 파일)를 저장하여 웹사이트 로딩 시간을 개선하며, 포렌식 분석에 가치가 있습니다.
- **Logins**: 저장된 로그인 자격 증명입니다.
- **Favicons**: 탭과 즐겨찾기에 표시되는 웹사이트 아이콘으로, 사용자의 방문에 대한 추가 정보를 제공할 수 있습니다.
- **Browser Sessions**: 열린 브라우저 세션과 관련된 데이터입니다.
- **Downloads**: 브라우저를 통해 다운로드한 파일의 기록입니다.
- **Form Data**: 웹 폼에 입력된 정보로, 이후 자동 완성 제안을 위해 저장됩니다.
- **Thumbnails**: 웹사이트의 미리보기 이미지입니다.
- **Custom Dictionary.txt**: 사용자가 브라우저 사전에 추가한 단어들입니다.

## Firefox

Firefox는 프로파일 내에 사용자 데이터를 구성하며, 운영체제에 따라 특정 위치에 저장됩니다:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

이 디렉터리들 안의 `profiles.ini` 파일은 사용자 프로파일을 나열합니다. 각 프로파일의 데이터는 `profiles.ini` 내 `Path` 변수에 명시된 이름의 폴더에 저장되며, 해당 폴더는 `profiles.ini`가 있는 동일한 디렉터리에 위치합니다. 프로파일 폴더가 없으면 삭제되었을 가능성이 있습니다.

각 프로파일 폴더 내에서 다음과 같은 중요한 파일들을 찾을 수 있습니다:

- **places.sqlite**: 기록, 즐겨찾기, 다운로드를 저장합니다. Windows에서 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) 같은 도구로 기록 데이터를 확인할 수 있습니다.
- 특정 SQL 쿼리를 사용해 기록 및 다운로드 정보를 추출할 수 있습니다.
- **bookmarkbackups**: 즐겨찾기 백업을 포함합니다.
- **formhistory.sqlite**: 웹 폼 데이터를 저장합니다.
- **handlers.json**: 프로토콜 핸들러를 관리합니다.
- **persdict.dat**: 사용자 지정 사전 단어들입니다.
- **addons.json** 및 **extensions.sqlite**: 설치된 애드온 및 확장에 대한 정보입니다.
- **cookies.sqlite**: 쿠키 저장소로, Windows에서는 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)로 검사할 수 있습니다.
- **cache2/entries** 또는 **startupCache**: 캐시 데이터로, [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) 같은 도구로 접근할 수 있습니다.
- **favicons.sqlite**: 파비콘을 저장합니다.
- **prefs.js**: 사용자 설정 및 환경설정입니다.
- **downloads.sqlite**: 이전의 다운로드 데이터베이스로, 현재는 places.sqlite에 통합되었습니다.
- **thumbnails**: 웹사이트 썸네일입니다.
- **logins.json**: 암호화된 로그인 정보입니다.
- **key4.db** 또는 **key3.db**: 민감한 정보를 보호하기 위한 암호화 키를 저장합니다.

또한, 브라우저의 안티 피싱 설정은 `prefs.js`에서 `browser.safebrowsing` 항목을 검색하여 안전한 브라우징 기능이 활성화되었는지 여부를 확인할 수 있습니다.

마스터 비밀번호를 복호화하려 시도하려면 [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\  
다음 스크립트와 호출로 브루트포스에 사용할 비밀번호 파일을 지정할 수 있습니다:
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

Google Chrome는 운영체제에 따라 사용자 프로필을 다음 위치에 저장합니다:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

이 디렉터리 내에서 대부분의 사용자 데이터는 **Default/** 또는 **ChromeDefaultData/** 폴더에서 찾을 수 있습니다. 다음 파일들이 중요한 데이터를 포함합니다:

- **History**: URL, 다운로드 및 검색 키워드를 포함합니다. Windows에서는 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)를 사용해 기록을 읽을 수 있습니다. "Transition Type" 열은 링크 클릭, 직접 입력한 URL, 폼 제출, 페이지 새로고침 등 다양한 의미를 가집니다.
- **Cookies**: 쿠키를 저장합니다. 검사하려면 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)를 사용할 수 있습니다.
- **Cache**: 캐시된 데이터를 보관합니다. 검사하려면 Windows 사용자는 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)를 사용할 수 있습니다.

Electron 기반 데스크톱 앱(예: Discord)도 Chromium Simple Cache를 사용하며 풍부한 디스크 상의 아티팩트를 남깁니다. 참조:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: 사용자 즐겨찾기.
- **Web Data**: 폼 히스토리 포함.
- **Favicons**: 웹사이트 파비콘 저장.
- **Login Data**: 사용자 이름과 비밀번호 같은 로그인 자격 증명을 포함합니다.
- **Current Session**/**Current Tabs**: 현재 브라우징 세션과 열린 탭에 대한 데이터.
- **Last Session**/**Last Tabs**: Chrome 종료 직전 마지막 세션 동안 활성화된 사이트 정보.
- **Extensions**: 브라우저 확장 및 애드온 디렉터리.
- **Thumbnails**: 웹사이트 썸네일 저장.
- **Preferences**: 플러그인, 확장, 팝업, 알림 등 설정을 포함한 많은 정보를 담고 있는 파일입니다.
- **Browser’s built-in anti-phishing**: 안티 피싱 및 맬웨어 보호가 활성화되었는지 확인하려면 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`를 실행하세요. 출력에서 `{"enabled: true,"}`를 찾으세요.

## **SQLite DB Data Recovery**

앞의 섹션에서 알 수 있듯이 Chrome과 Firefox는 데이터를 저장하기 위해 **SQLite** 데이터베이스를 사용합니다. [**sqlparse**](https://github.com/padfoot999/sqlparse) 또는 [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) 도구를 사용하여 삭제된 항목을 복구할 수 있습니다.

## **Internet Explorer 11**

Internet Explorer 11은 데이터와 메타데이터를 여러 위치에 걸쳐 관리하여 저장된 정보와 해당 세부 정보를 분리해 쉽게 접근하고 관리할 수 있도록 합니다.

### Metadata Storage

Internet Explorer의 메타데이터는 %userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data에 저장됩니다 (VX는 V01, V16 또는 V24). 이와 함께 `V01.log` 파일은 `WebcacheVX.data`와 수정 시간에 불일치가 보일 수 있으며, 이 경우 `esentutl /r V01 /d`로 복구가 필요함을 나타냅니다. 이 메타데이터는 ESE 데이터베이스에 저장되어 있으며 photorec 및 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) 같은 도구로 복구 및 검사할 수 있습니다. **Containers** 테이블에서는 각 데이터 조각이 저장된 특정 테이블이나 컨테이너(예: Skype와 같은 다른 Microsoft 도구의 캐시 세부사항)를 확인할 수 있습니다.

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 도구를 사용하면 캐시를 검사할 수 있으며, 캐시 데이터 추출 폴더 위치가 필요합니다. 캐시 메타데이터에는 파일 이름, 디렉터리, 접근 횟수, URL 출처 및 캐시 생성, 접근, 수정, 만료 시간을 나타내는 타임스탬프가 포함됩니다.

### Cookies Management

쿠키는 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html)로 탐색할 수 있으며 메타데이터에는 이름, URL, 접근 횟수 및 다양한 시간 관련 정보가 포함됩니다. 영구 쿠키는 %userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies에 저장되며 세션 쿠키는 메모리에 존재합니다.

### Download Details

[ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)로 다운로드 메타데이터에 접근할 수 있으며, 특정 컨테이너에는 URL, 파일 형식, 다운로드 위치 같은 데이터가 들어 있습니다. 실제 파일은 %userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory에 있습니다.

### Browsing History

브라우징 기록을 검토하려면 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)를 사용할 수 있으며, 추출한 히스토리 파일의 위치와 Internet Explorer 구성을 지정해야 합니다. 여기의 메타데이터에는 수정 및 접근 시간과 접근 횟수가 포함됩니다. 히스토리 파일은 %userprofile%\Appdata\Local\Microsoft\Windows\History에 있습니다.

### Typed URLs

입력된 URL과 사용 시간은 NTUSER.DAT의 레지스트리 하위 키 Software\Microsoft\InternetExplorer\TypedURLs 및 Software\Microsoft\InternetExplorer\TypedURLsTime에 저장되며, 사용자가 입력한 마지막 50개의 URL과 마지막 입력 시간을 추적합니다.

## Microsoft Edge

Microsoft Edge는 사용자 데이터를 %userprofile%\Appdata\Local\Packages에 저장합니다. 다양한 데이터 유형의 경로는 다음과 같습니다:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 데이터는 `/Users/$User/Library/Safari`에 저장됩니다. 주요 파일은 다음과 같습니다:

- **History.db**: history_visits 및 history_items 테이블에 URL과 방문 타임스탬프가 포함되어 있습니다. 쿼리하려면 sqlite3를 사용하세요.
- **Downloads.plist**: 다운로드된 파일에 대한 정보.
- **Bookmarks.plist**: 즐겨찾기 URL 저장.
- **TopSites.plist**: 가장 자주 방문한 사이트.
- **Extensions.plist**: Safari 브라우저 확장 목록. 검색하려면 `plutil` 또는 `pluginkit`을 사용하세요.
- **UserNotificationPermissions.plist**: 알림을 보낼 수 있도록 허용된 도메인. `plutil`로 파싱하세요.
- **LastSession.plist**: 마지막 세션의 탭 정보. `plutil`로 파싱하세요.
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`를 사용해 확인합니다. 출력이 1이면 기능이 활성화된 것입니다.

## Opera

Opera의 데이터는 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`에 저장되며 히스토리 및 다운로드 형식은 Chrome과 동일합니다.

- **Browser’s built-in anti-phishing**: Preferences 파일에서 `fraud_protection_enabled`가 `true`로 설정되어 있는지 `grep`으로 확인하세요.

이 경로들과 명령들은 다양한 웹 브라우저가 저장하는 브라우징 데이터를 접근하고 이해하는 데 중요합니다.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}
