# 브라우저 아티팩트

{{#include ../../../banners/hacktricks-training.md}}

## 브라우저 아티팩트 <a href="#id-3def" id="id-3def"></a>

브라우저 아티팩트는 탐색 기록, 북마크 및 캐시 데이터와 같은 웹 브라우저에 저장된 다양한 유형의 데이터를 포함합니다. 이러한 아티팩트는 운영 체제 내의 특정 폴더에 보관되며, 브라우저마다 위치와 이름이 다르지만 일반적으로 유사한 데이터 유형을 저장합니다.

가장 일반적인 브라우저 아티팩트의 요약은 다음과 같습니다:

- **탐색 기록**: 사용자가 방문한 웹사이트를 추적하며, 악성 사이트 방문 식별에 유용합니다.
- **자동 완성 데이터**: 자주 검색한 내용을 기반으로 한 제안으로, 탐색 기록과 결합할 때 통찰력을 제공합니다.
- **북마크**: 사용자가 빠르게 접근하기 위해 저장한 사이트입니다.
- **확장 프로그램 및 애드온**: 사용자가 설치한 브라우저 확장 프로그램 또는 애드온입니다.
- **캐시**: 웹 콘텐츠(예: 이미지, JavaScript 파일)를 저장하여 웹사이트 로딩 시간을 개선하며, 포렌식 분석에 유용합니다.
- **로그인 정보**: 저장된 로그인 자격 증명입니다.
- **파비콘**: 웹사이트와 관련된 아이콘으로, 탭 및 북마크에 나타나며, 사용자 방문에 대한 추가 정보를 제공합니다.
- **브라우저 세션**: 열린 브라우저 세션과 관련된 데이터입니다.
- **다운로드**: 브라우저를 통해 다운로드한 파일의 기록입니다.
- **양식 데이터**: 웹 양식에 입력된 정보로, 향후 자동 완성 제안을 위해 저장됩니다.
- **썸네일**: 웹사이트의 미리보기 이미지입니다.
- **Custom Dictionary.txt**: 사용자가 브라우저 사전에 추가한 단어입니다.

## Firefox

Firefox는 사용자 데이터를 프로필 내에서 구성하며, 운영 체제에 따라 특정 위치에 저장됩니다:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

이 디렉토리 내의 `profiles.ini` 파일은 사용자 프로필을 나열합니다. 각 프로필의 데이터는 `profiles.ini` 내의 `Path` 변수에 명시된 이름의 폴더에 저장되며, `profiles.ini`와 동일한 디렉토리에 위치합니다. 프로필 폴더가 누락된 경우 삭제되었을 수 있습니다.

각 프로필 폴더 내에서 여러 중요한 파일을 찾을 수 있습니다:

- **places.sqlite**: 기록, 북마크 및 다운로드를 저장합니다. Windows에서 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)와 같은 도구를 사용하여 기록 데이터를 접근할 수 있습니다.
- 특정 SQL 쿼리를 사용하여 기록 및 다운로드 정보를 추출합니다.
- **bookmarkbackups**: 북마크의 백업을 포함합니다.
- **formhistory.sqlite**: 웹 양식 데이터를 저장합니다.
- **handlers.json**: 프로토콜 핸들러를 관리합니다.
- **persdict.dat**: 사용자 정의 사전 단어입니다.
- **addons.json** 및 **extensions.sqlite**: 설치된 애드온 및 확장 프로그램에 대한 정보입니다.
- **cookies.sqlite**: 쿠키 저장소로, Windows에서 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)를 사용하여 검사할 수 있습니다.
- **cache2/entries** 또는 **startupCache**: 캐시 데이터로, [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html)와 같은 도구를 통해 접근할 수 있습니다.
- **favicons.sqlite**: 파비콘을 저장합니다.
- **prefs.js**: 사용자 설정 및 기본 설정입니다.
- **downloads.sqlite**: 이전 다운로드 데이터베이스로, 현재 places.sqlite에 통합되었습니다.
- **thumbnails**: 웹사이트 썸네일입니다.
- **logins.json**: 암호화된 로그인 정보입니다.
- **key4.db** 또는 **key3.db**: 민감한 정보를 보호하기 위한 암호화 키를 저장합니다.

또한, 브라우저의 피싱 방지 설정을 확인하려면 `prefs.js`에서 `browser.safebrowsing` 항목을 검색하여 안전한 탐색 기능이 활성화되었는지 비활성화되었는지 확인할 수 있습니다.

마스터 비밀번호를 복호화하려면 [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
다음 스크립트와 호출을 사용하여 비밀번호 파일을 지정하여 무차별 대입 공격을 시도할 수 있습니다:
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

Google Chrome은 운영 체제에 따라 사용자 프로필을 특정 위치에 저장합니다:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

이 디렉토리 내에서 대부분의 사용자 데이터는 **Default/** 또는 **ChromeDefaultData/** 폴더에 있습니다. 다음 파일들은 중요한 데이터를 포함하고 있습니다:

- **History**: URL, 다운로드 및 검색 키워드를 포함합니다. Windows에서는 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)를 사용하여 기록을 읽을 수 있습니다. "Transition Type" 열은 링크 클릭, 입력된 URL, 양식 제출 및 페이지 새로 고침을 포함한 다양한 의미를 가집니다.
- **Cookies**: 쿠키를 저장합니다. 검사를 위해 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)를 사용할 수 있습니다.
- **Cache**: 캐시된 데이터를 보유합니다. 검사를 위해 Windows 사용자는 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)를 사용할 수 있습니다.
- **Bookmarks**: 사용자 북마크.
- **Web Data**: 양식 기록을 포함합니다.
- **Favicons**: 웹사이트 파비콘을 저장합니다.
- **Login Data**: 사용자 이름 및 비밀번호와 같은 로그인 자격 증명을 포함합니다.
- **Current Session**/**Current Tabs**: 현재 브라우징 세션 및 열린 탭에 대한 데이터.
- **Last Session**/**Last Tabs**: Chrome이 닫히기 전 마지막 세션 동안 활성 상태였던 사이트에 대한 정보.
- **Extensions**: 브라우저 확장 및 애드온을 위한 디렉토리.
- **Thumbnails**: 웹사이트 썸네일을 저장합니다.
- **Preferences**: 플러그인, 확장, 팝업, 알림 등에 대한 설정을 포함한 정보가 풍부한 파일입니다.
- **Browser’s built-in anti-phishing**: 안티 피싱 및 맬웨어 보호가 활성화되어 있는지 확인하려면 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`를 실행합니다. 출력에서 `{"enabled: true,"}`를 찾습니다.

## **SQLite DB Data Recovery**

앞의 섹션에서 볼 수 있듯이, Chrome과 Firefox는 데이터를 저장하기 위해 **SQLite** 데이터베이스를 사용합니다. 삭제된 항목을 **복구할 수 있는 도구** [**sqlparse**](https://github.com/padfoot999/sqlparse) **또는** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases)를 사용할 수 있습니다.

## **Internet Explorer 11**

Internet Explorer 11은 다양한 위치에서 데이터와 메타데이터를 관리하여 저장된 정보와 해당 세부 정보를 쉽게 접근하고 관리할 수 있도록 돕습니다.

### Metadata Storage

Internet Explorer의 메타데이터는 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`에 저장됩니다 (VX는 V01, V16 또는 V24). 이와 함께 `V01.log` 파일은 `WebcacheVX.data`와의 수정 시간 불일치를 보여줄 수 있으며, 이는 `esentutl /r V01 /d`를 사용하여 수리할 필요가 있음을 나타냅니다. 이 메타데이터는 ESE 데이터베이스에 저장되며, photorec 및 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)와 같은 도구를 사용하여 복구하고 검사할 수 있습니다. **Containers** 테이블 내에서 각 데이터 세그먼트가 저장된 특정 테이블 또는 컨테이너를 식별할 수 있으며, Skype와 같은 다른 Microsoft 도구의 캐시 세부 정보도 포함됩니다.

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 도구를 사용하여 캐시를 검사할 수 있으며, 캐시 데이터 추출 폴더 위치가 필요합니다. 캐시의 메타데이터에는 파일 이름, 디렉토리, 접근 횟수, URL 출처 및 캐시 생성, 접근, 수정 및 만료 시간을 나타내는 타임스탬프가 포함됩니다.

### Cookies Management

쿠키는 [IECookiesView](https://www.nirsoft.net/utils/iecookies.html)를 사용하여 탐색할 수 있으며, 메타데이터에는 이름, URL, 접근 횟수 및 다양한 시간 관련 세부 정보가 포함됩니다. 지속적인 쿠키는 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`에 저장되며, 세션 쿠키는 메모리에 존재합니다.

### Download Details

다운로드 메타데이터는 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)를 통해 접근할 수 있으며, 특정 컨테이너는 URL, 파일 유형 및 다운로드 위치와 같은 데이터를 보유합니다. 물리적 파일은 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` 아래에서 찾을 수 있습니다.

### Browsing History

브라우징 기록을 검토하려면 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)를 사용할 수 있으며, 추출된 기록 파일의 위치와 Internet Explorer에 대한 구성이 필요합니다. 여기의 메타데이터에는 수정 및 접근 시간과 접근 횟수가 포함됩니다. 기록 파일은 `%userprofile%\Appdata\Local\Microsoft\Windows\History`에 위치합니다.

### Typed URLs

입력된 URL 및 사용 시간은 `NTUSER.DAT`의 `Software\Microsoft\InternetExplorer\TypedURLs` 및 `Software\Microsoft\InternetExplorer\TypedURLsTime` 레지스트리에 저장되어 있으며, 사용자가 입력한 마지막 50개의 URL과 마지막 입력 시간을 추적합니다.

## Microsoft Edge

Microsoft Edge는 사용자 데이터를 `%userprofile%\Appdata\Local\Packages`에 저장합니다. 다양한 데이터 유형에 대한 경로는 다음과 같습니다:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 데이터는 `/Users/$User/Library/Safari`에 저장됩니다. 주요 파일은 다음과 같습니다:

- **History.db**: `history_visits` 및 `history_items` 테이블에 URL 및 방문 타임스탬프가 포함되어 있습니다. 쿼리를 위해 `sqlite3`를 사용합니다.
- **Downloads.plist**: 다운로드된 파일에 대한 정보.
- **Bookmarks.plist**: 북마크된 URL을 저장합니다.
- **TopSites.plist**: 가장 자주 방문한 사이트.
- **Extensions.plist**: Safari 브라우저 확장 목록. `plutil` 또는 `pluginkit`을 사용하여 검색합니다.
- **UserNotificationPermissions.plist**: 푸시 알림을 허용하는 도메인. `plutil`을 사용하여 구문 분석합니다.
- **LastSession.plist**: 마지막 세션의 탭. `plutil`을 사용하여 구문 분석합니다.
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`를 사용하여 확인합니다. 1의 응답은 기능이 활성화되어 있음을 나타냅니다.

## Opera

Opera의 데이터는 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`에 위치하며, 기록 및 다운로드에 대한 Chrome의 형식을 공유합니다.

- **Browser’s built-in anti-phishing**: `grep`을 사용하여 Preferences 파일에서 `fraud_protection_enabled`가 `true`로 설정되어 있는지 확인합니다.

이 경로와 명령은 다양한 웹 브라우저에 저장된 브라우징 데이터에 접근하고 이해하는 데 중요합니다.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

{{#include ../../../banners/hacktricks-training.md}}
