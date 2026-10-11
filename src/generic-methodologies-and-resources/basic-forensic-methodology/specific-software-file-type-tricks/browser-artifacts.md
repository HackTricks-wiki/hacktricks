# 브라우저 아티팩트

{{#include ../../../banners/hacktricks-training.md}}

## 브라우저 아티팩트 <a href="#id-3def" id="id-3def"></a>

브라우저 아티팩트에는 탐색 기록, 북마크, 캐시 데이터 등 웹 브라우저에 저장된 다양한 유형의 데이터가 포함됩니다. 이러한 아티팩트는 운영 체제 내 특정 폴더에 보관되며, 브라우저마다 위치와 이름은 다르지만 일반적으로 유사한 유형의 데이터를 저장합니다.

가장 흔한 브라우저 아티팩트는 다음과 같습니다.

- **탐색 기록**: 사용자가 방문한 웹사이트를 추적하며, 악성 사이트 방문 여부를 파악하는 데 유용합니다.
- **자동 완성 데이터**: 자주 검색한 내용을 기반으로 제안하며, 탐색 기록과 함께 분석하면 유용한 정보를 얻을 수 있습니다.
- **북마크**: 사용자가 빠르게 방문할 수 있도록 저장한 사이트입니다.
- **확장 프로그램 및 애드온**: 사용자가 설치한 브라우저 확장 프로그램 또는 애드온입니다.
- **캐시**: 웹사이트 로딩 시간을 줄이기 위해 웹 콘텐츠(예: 이미지, JavaScript 파일)를 저장하며, 포렌식 분석에 유용합니다.
- **로그인 정보**: 저장된 로그인 자격 증명입니다.
- **파비콘**: 웹사이트와 연결된 아이콘으로, 탭과 북마크에 표시되며 사용자가 방문한 사이트에 관한 추가 정보를 얻는 데 유용합니다.
- **브라우저 세션**: 열린 브라우저 세션과 관련된 데이터입니다.
- **다운로드**: 브라우저를 통해 다운로드한 파일의 기록입니다.
- **양식 데이터**: 웹 양식에 입력한 정보로, 향후 자동 완성 제안에 사용되도록 저장됩니다.
- **썸네일**: 웹사이트 미리보기 이미지입니다.
- **Custom Dictionary.txt**: 사용자가 브라우저 사전에 추가한 단어입니다.

## Firefox

Firefox는 운영 체제에 따라 정해진 위치에 저장되는 프로필 내에 사용자 데이터를 정리합니다.<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

이 디렉터리 내의 `profiles.ini` 파일에는 사용자 프로필 목록이 있습니다. 각 프로필의 데이터는 `profiles.ini`와 같은 디렉터리에 있는 `profiles.ini` 파일의 `Path` 변수에 지정된 폴더에 저장됩니다. 프로필 폴더가 없다면 삭제되었을 수 있습니다.

각 프로필 폴더에서 다음과 같은 중요한 파일을 찾을 수 있습니다.<sup>[[1]](#references)</sup>

- **places.sqlite**: 기록, 북마크, 다운로드를 저장합니다. Windows에서는 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) 같은 도구로 기록 데이터에 접근할 수 있습니다.
  - 특정 SQL 쿼리를 사용해 기록 및 다운로드 정보를 추출합니다.
- **bookmarkbackups**: 북마크 백업을 포함합니다.
- **formhistory.sqlite**: 웹 양식 데이터를 저장합니다.
- **handlers.json**: 프로토콜 핸들러를 관리합니다.
- **persdict.dat**: 사용자 지정 사전 단어를 저장합니다.
- **addons.json** 및 **extensions.sqlite**: 설치된 애드온 및 확장 프로그램에 관한 정보입니다.
- **cookies.sqlite**: 쿠키 저장소입니다. Windows에서는 [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html)를 사용해 확인할 수 있습니다.
- **cache2/entries** 또는 **startupCache**: 캐시 데이터이며, [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) 같은 도구로 확인할 수 있습니다.
- **favicons.sqlite**: 파비콘을 저장합니다.
- **prefs.js**: 사용자 설정 및 기본 설정입니다.
- **downloads.sqlite**: 이전 버전의 다운로드 데이터베이스이며, 현재는 places.sqlite에 통합되었습니다.
- **thumbnails**: 웹사이트 썸네일입니다.
- **logins.json**: 암호화된 로그인 정보입니다.
- **key4.db** 또는 **key3.db**: 민감한 정보를 보호하는 데 사용되는 암호화 키를 저장합니다.

또한 `prefs.js`에서 `browser.safebrowsing` 항목을 검색하면 브라우저의 피싱 방지 설정을 확인할 수 있으며, 이를 통해 안전 브라우징 기능이 활성화되었는지 비활성화되었는지 알 수 있습니다.<sup>[[2]](#references)</sup>

접근 가능한 프로필에서 저장된 로그인을 복호화하려면, 설정되어 있는 경우 [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins)를 제공하거나 별도로 복구해야 합니다. 프로필에서 해당 비밀번호를 알아낼 수는 없습니다. 복구한 로그인 정보가 해당 웹 계정에 실제로 인증되는지 확인하세요. Unix root 접근 권한을 입증하려면 해당 자격 증명이 Unix 인증에서 root 계정에도 허용되는지 별도로 증명해야 합니다. 저장된 로그인 정보는 [firefox_decrypt](https://github.com/unode/firefox_decrypt)를 사용해 확인할 수 있습니다. 다음 예제에서는 비밀번호 파일에 있는 후보 Primary Password를 테스트합니다.

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![브라우저 아티팩트 - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome은 운영 체제에 따라 특정 위치에 사용자 프로필을 저장합니다:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

이 디렉터리에서 대부분의 사용자 데이터는 **Default/** 또는 **ChromeDefaultData/** 폴더에 있습니다. 다음 파일에는 중요한 데이터가 저장됩니다:<sup>[[1]](#references)</sup>

- **History**: URL, 다운로드, 검색 키워드가 포함됩니다. Windows에서는 [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html)를 사용해 기록을 읽을 수 있습니다. "Transition Type" 열에는 링크 클릭, URL 직접 입력, 양식 제출, 페이지 새로고침 등 다양한 의미가 있습니다.
- **Cookies**: 쿠키가 저장됩니다. 확인할 때는 [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html)를 사용할 수 있습니다.
- **Cache**: 캐시된 데이터가 들어 있습니다. 확인하려면 Windows 사용자는 [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html)를 사용할 수 있습니다.

  Electron 기반 데스크톱 앱(예: Discord)도 Chromium Simple Cache를 사용하며 디스크에 풍부한 아티팩트를 남깁니다. 자세한 내용은 다음을 참조하세요.

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: 사용자가 저장한 북마크입니다.
- **Web Data**: 양식 기록이 포함됩니다.
- **Favicons**: 웹사이트 favicon이 저장됩니다.
- **Login Data**: 사용자 이름, 비밀번호 같은 로그인 자격 증명이 포함됩니다.
- **Current Session**/**Current Tabs**: 현재 브라우징 세션 및 열려 있는 탭에 관한 데이터입니다.
- **Last Session**/**Last Tabs**: Chrome을 닫기 전 마지막 세션에서 활성 상태였던 사이트에 관한 정보입니다.
- **Extensions**: 브라우저 확장 프로그램 및 애드온 디렉터리입니다.
- **Thumbnails**: 웹사이트 썸네일이 저장됩니다.
- **Preferences**: 플러그인, 확장 프로그램, 팝업, 알림 등의 설정을 포함한 풍부한 정보가 들어 있는 파일입니다.
- **브라우저 내장 anti-phishing 기능**: anti-phishing 및 malware 보호 기능이 활성화되어 있는지 확인하려면 `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`를 실행하세요. 출력에서 `{"enabled: true,"}`를 찾습니다.<sup>[[2]](#references)</sup>

Chromium 프로필의 `Local Extension Settings/<extension-id>/` 디렉터리에는 비밀번호 관리자 키 자료를 비롯한 확장 프로그램별 상태가 저장될 수 있습니다. 예를 들어, [Passbolt는 암호화된 비공개 키가 브라우저 확장 프로그램의 로컬 저장소에 보관된다고 설명합니다](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/). 해당 [Chrome 확장 프로그램 ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf)는 관련 디렉터리를 식별하는 데 사용할 수 있습니다. 디렉터리가 존재한다는 사실만으로 키가 들어 있다고 증명되지는 않으며, vault 잠금이 해제되는 것도 아닙니다. 사용자는 프로필 데이터, 사용 가능한 비공개 키와 passphrase, 그리고 서버에 대한 승인된 복구/인증 경로에 접근할 수 있어야 합니다. 운영 체제 계정 비밀번호가 포함된 vault 항목은 별도로 계정 재사용 여부를 확인해야 합니다. 일상적인 열거에서는 LevelDB 파일이나 비밀 값을 덤프하지 말고 저장 경로만 보고해야 합니다.

## **SQLite DB 데이터 복구**

앞 섹션에서 확인한 것처럼 Chrome과 Firefox는 모두 **SQLite** 데이터베이스를 사용해 데이터를 저장합니다. [**sqlparse**](https://github.com/padfoot999/sqlparse) **또는** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **도구를 사용해 삭제된 항목을 복구할 수 있습니다.**

## **Internet Explorer 11**

Internet Explorer 11은 다양한 위치에 데이터와 메타데이터를 관리해 저장된 정보와 이에 해당하는 세부 정보를 분리하므로, 쉽게 접근하고 관리할 수 있습니다.

### 메타데이터 저장

Internet Explorer의 메타데이터는 `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data`에 저장됩니다(VX는 V01, V16 또는 V24). 이와 함께 있는 `V01.log` 파일의 수정 시간이 `WebcacheVX.data`와 일치하지 않을 수 있습니다. 이런 경우 `esentutl /r V01 /d`를 사용해 복구해야 할 수 있습니다. ESE 데이터베이스에 저장된 이 메타데이터는 photorec로 복구하고 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)와 같은 도구로 검사할 수 있습니다. **Containers** 테이블에서는 각 데이터 세그먼트가 저장된 특정 테이블이나 컨테이너를 확인할 수 있으며, 여기에는 Skype 등 다른 Microsoft 도구의 캐시 세부 정보도 포함됩니다.

### 캐시 검사

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) 도구를 사용하면 캐시를 검사할 수 있으며, 캐시 데이터가 추출된 폴더 위치가 필요합니다. 캐시 메타데이터에는 파일 이름, 디렉터리, 접근 횟수, URL 출처, 캐시 생성·접근·수정·만료 시각이 포함됩니다.

### 쿠키 관리

[IECookiesView](https://www.nirsoft.net/utils/iecookies.html)를 사용해 쿠키를 확인할 수 있으며, 메타데이터에는 이름, URL, 접근 횟수 및 다양한 시간 관련 세부 정보가 포함됩니다. 영구 쿠키는 `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies`에 저장되고, 세션 쿠키는 메모리에 저장됩니다.

### 다운로드 세부 정보

다운로드 메타데이터는 [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html)에서 확인할 수 있으며, 특정 컨테이너에 URL, 파일 형식, 다운로드 위치 등의 데이터가 저장됩니다. 실제 파일은 `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory`에서 찾을 수 있습니다.

### 브라우징 기록

브라우징 기록을 확인하려면 [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html)를 사용할 수 있습니다. 이 도구에는 추출된 기록 파일의 위치를 지정하고 Internet Explorer에 맞게 구성해야 합니다. 기록 메타데이터에는 수정 및 접근 시간과 접근 횟수가 포함됩니다. 기록 파일은 `%userprofile%\Appdata\Local\Microsoft\Windows\History`에 있습니다.

### 직접 입력한 URL

사용자가 직접 입력한 URL과 입력 시각은 레지스트리의 `NTUSER.DAT`에 있는 `Software\Microsoft\InternetExplorer\TypedURLs` 및 `Software\Microsoft\InternetExplorer\TypedURLsTime`에 저장됩니다. 여기에는 사용자가 마지막으로 입력한 URL 50개와 각 URL의 마지막 입력 시각이 기록됩니다.

## Microsoft Edge

Microsoft Edge는 사용자 데이터를 `%userprofile%\Appdata\Local\Packages`에 저장합니다. 데이터 유형별 경로는 다음과 같습니다:<sup>[[1]](#references)</sup>

- **프로필 경로**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **기록, 쿠키, 다운로드**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **설정, 북마크, 읽기 목록**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **캐시**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **마지막으로 활성화된 세션**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari 데이터는 `/Users/$User/Library/Safari`에 저장됩니다. 주요 파일은 다음과 같습니다:<sup>[[3]](#references)</sup>

- **History.db**: URL과 방문 시각이 저장된 `history_visits` 및 `history_items` 테이블이 포함됩니다. `sqlite3`를 사용해 쿼리할 수 있습니다.
- **Downloads.plist**: 다운로드한 파일에 관한 정보입니다.
- **Bookmarks.plist**: 북마크한 URL이 저장됩니다.
- **TopSites.plist**: 가장 자주 방문한 사이트입니다.
- **Extensions.plist**: Safari 브라우저 확장 프로그램 목록입니다. `plutil` 또는 `pluginkit`을 사용해 조회할 수 있습니다.
- **UserNotificationPermissions.plist**: push 알림을 허용한 도메인입니다. `plutil`을 사용해 파싱할 수 있습니다.
- **LastSession.plist**: 마지막 세션의 탭입니다. `plutil`을 사용해 파싱할 수 있습니다.
- **브라우저 내장 anti-phishing 기능**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites`를 사용해 확인합니다. 응답이 1이면 기능이 활성화되어 있습니다.<sup>[[2]](#references)</sup>

## Opera

Opera의 데이터는 `/Users/$USER/Library/Application Support/com.operasoftware.Opera`에 있으며, 기록 및 다운로드에는 Chrome과 같은 형식을 사용합니다.

- **브라우저 내장 anti-phishing 기능**: `grep`을 사용해 Preferences 파일의 `fraud_protection_enabled` 값이 `true`인지 확인합니다.<sup>[[2]](#references)</sup>

이러한 경로와 명령은 웹 브라우저마다 저장된 브라우징 데이터에 접근하고 이를 이해하는 데 중요합니다.

## References

- [1] [웹 브라우저 포렌식: 웹 브라우저 포렌식 분석을 위한 가이드](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS 인시던트 대응 | 3부: 시스템 조작](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X 인시던트 대응: Jaron Bradley의 스크립팅 및 분석](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}
