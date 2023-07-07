<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


フィッシングアセスメントでは、時には完全に**ウェブサイトをクローン**することが役立つ場合があります。

クローンされたウェブサイトには、BeEFフックなどのペイロードを追加することもできます。これにより、ユーザーのタブを「制御」することができます。

この目的のために使用できるさまざまなツールがあります：

## wget
```text
wget -mk -nH
```
## goclone

gocloneは、ウェブサイトをクローンするためのツールです。このツールを使用すると、ターゲットのウェブサイトの外観と機能を完全に複製することができます。

### インストール

gocloneをインストールするには、次のコマンドを実行します。

```bash
go get -u github.com/muhammadmuzzammil1998/goclone
```

### 使用方法

gocloneを使用するには、次のコマンドを実行します。

```bash
goclone -url <target_url> -output <output_directory>
```

- `<target_url>`: クローンするターゲットのウェブサイトのURLを指定します。
- `<output_directory>`: クローンされたウェブサイトの出力ディレクトリを指定します。

### クローンの注意事項

gocloneを使用してウェブサイトをクローンする際には、法的な制約や倫理的な考慮事項に留意する必要があります。許可なく他人のウェブサイトをクローンすることは違法行為となりますので、必ず適切な許可を得るか、自身のウェブサイトのクローンを作成することをお勧めします。

### まとめ

gocloneは、ウェブサイトのクローン作成に便利なツールです。ただし、適切な許可を得ずに他人のウェブサイトをクローンすることは違法ですので、注意が必要です。
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## ソーシャルエンジニアリングツールキット

### クローンウェブサイト

このモジュールでは、フィッシング攻撃の一環としてウェブサイトをクローンする方法について説明します。クローンウェブサイトは、攻撃者が被害者を騙すために使用する偽のウェブサイトです。被害者は、本物のウェブサイトと間違えて情報を入力する可能性があります。

### クローンウェブサイトの作成手順

1. クローンしたいウェブサイトを選択します。一般的なターゲットは、銀行、ソーシャルメディア、オンラインショッピングサイトなどです。

2. ウェブサイトのソースコードを取得します。これには、ブラウザの開発者ツールを使用するか、`wget`コマンドを使用してウェブサイトのHTMLをダウンロードする方法があります。

3. ソースコードを編集し、攻撃者が情報を収集できるようにします。例えば、ログインフォームの`action`属性を攻撃者が制御するサーバーのURLに変更します。

4. クローンウェブサイトをホストするためのインフラストラクチャをセットアップします。これには、Webサーバーの設定やドメイン名の取得が含まれます。

5. クローンウェブサイトを被害者に送信するための手段を選択します。一般的な方法には、メール、SMS、ソーシャルメディアのメッセージなどがあります。

6. 被害者がクローンウェブサイトにアクセスし、情報を入力すると、攻撃者はその情報を収集できます。

### クローンウェブサイトの注意点

- クローンウェブサイトを作成することは、法的に違法な行為です。この技術は、セキュリティテストや教育目的でのみ使用するべきです。

- クローンウェブサイトは、被害者を騙すための手段として使用されるため、倫理的な観点からも慎重に使用する必要があります。

- クローンウェブサイトは、セキュリティ対策が強化されたウェブサイトに対しても効果的な攻撃手法ですが、被害者が警戒心を持っている場合や、セキュリティ対策が十分に実施されている場合は成功しづらくなります。

- クローンウェブサイトを作成する際には、被害者のプライバシーとセキュリティを尊重することが重要です。収集した情報は適切に処理し、不正な目的で使用しないように注意してください。

以上がクローンウェブサイトの作成手順と注意点です。この技術を使用する際には、法的な制約と倫理的な観点を常に意識し、慎重に行動してください。
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
