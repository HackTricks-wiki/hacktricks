# フィッシングの方法論

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>

## 方法論

1. ターゲットの情報収集
1. **ターゲットドメイン**を選択します。
2. ターゲットが使用している**ログインポータル**を検索し、**なりすます**ものを決定します。
3. いくつかの**OSINT**を使用して**メールアドレスを見つけます**。
2. 環境の準備
1. フィッシング評価に使用するドメインを**購入**します。
2. 関連するメールサービスのレコード（SPF、DMARC、DKIM、rDNS）を**設定**します。
3. **gophish**を使用してVPSを設定します。
3. キャンペーンの準備
1. **メールテンプレート**を準備します。
2. 資格情報を盗むための**ウェブページ**を準備します。
4. キャンペーンを開始します！

## 類似のドメイン名を生成するか、信頼できるドメインを購入する

### ドメイン名の変更技術

* **キーワード**: オリジナルドメインの重要な**キーワードを含む**ドメイン名（例：zelster.com-management.com）。
* **ハイフン付きサブドメイン**: サブドメインの**ドットをハイフンに変更**します（例：www-zelster.com）。
* **新しいTLD**: 同じドメインを**新しいTLD**を使用して表現します（例：zelster.org）。
* **ホモグリフ**: ドメイン名の一部の文字を、**似たような文字**で置き換えます（例：zelfser.com）。
* **転置**: ドメイン名内の2つの文字を**入れ替えます**（例：zelster.com）。
* **単数形/複数形**: ドメイン名の末尾に「s」を追加または削除します（例：zeltsers.com）。
* **省略**: ドメイン名から1つの文字を**削除します**（例：zelser.com）。
* **繰り返し**: ドメイン名の1つの文字を**繰り返します**（例：zeltsser.com）。
* **置換**: ホモグリフと同様ですが、より目立たないです。ドメイン名の1つの文字を、元の文字に近いキーボード上の文字で置き換えます（例：zektser.com）。
* **サブドメイン**: ドメイン名内に**ドット**を挿入します（例：ze.lster.com）。
* **挿入**: ドメイン名に1つの文字を**挿入します**（例：zerltser.com）。
* **ドットの欠落**: ドメイン名にTLDを追加します（例：zelstercom.com）。

**自動ツール**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**ウェブサイト**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### ビットフリッピング

コンピューティングの世界では、メモリ内にはビット（0と1）ですべてが格納されています。\
ドメインも同様です。たとえば、_windows.com_は、コンピューティングデバイスの揮発性メモリ内では_01110111..._となります。\
しかし、もしソーラーフレアや宇宙線、ハードウェアエラーによってビットの1つが自動的に反転した場合はどうでしょうか。つまり、0の1つが1に、1の1つが0になることです。\
このコンセプトをDNSリクエストに適用すると、**DNSサーバーに到着するドメインリクエストが最初に要求されたドメインとは異なる可能性があります**。

たとえば、ドメインwindows.comの1ビットの変更により、_windnws.com_に変換される可能性があります。\
**攻撃者は、被害者に関連するビットフリッピングドメインをできるだけ多く登録し、正規のユーザーを自身のインフラストラクチャにリダイレクトすることができます**。

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を参照してください。
### 信頼できるドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net)で使用できる期限切れのドメインを検索することができます。\
購入する前に、購入する期限切れのドメインが**既に良いSEOを持っているかどうか**を確認するために、以下のサイトでカテゴリ分けされているかどうかを調べることができます：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（100％無料）
- [https://phonebook.cz/](https://phonebook.cz)（100％無料）
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

さらに、有効なメールアドレスを**さらに発見**するか、すでに発見したメールアドレスを**検証**するために、被害者のSMTPサーバーのユーザー名をブルートフォースできるかどうかを確認することができます。[ここでメールアドレスの検証/発見方法を学ぶ](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration)。\
さらに、ユーザーが**メールにアクセスするためのウェブポータル**を使用している場合、**ユーザー名のブルートフォース**に対して脆弱性があるかどうかを確認し、可能であればその脆弱性を悪用することができます。

## GoPhishの設定

### インストール

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)からダウンロードすることができます。

`/opt/gophish`内にダウンロードして解凍し、`/opt/gophish/gophish`を実行します。\
出力には、ポート3333の管理者ユーザーのパスワードが表示されます。したがって、そのポートにアクセスし、これらの資格情報を使用して管理者パスワードを変更します。ローカルにそのポートをトンネリングする必要がある場合があります。
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS証明書の設定**

この手順の前に、使用するドメインを**すでに購入している必要があります**。また、そのドメインは**gophishを設定しているVPSのIPに向けられている必要があります**。
```bash
DOMAIN="<domain>"
wget https://dl.eff.org/certbot-auto
chmod +x certbot-auto
sudo apt install snapd
sudo snap install core
sudo snap refresh core
sudo apt-get remove certbot
sudo snap install --classic certbot
sudo ln -s /snap/bin/certbot /usr/bin/certbot
certbot certonly --standalone -d "$DOMAIN"
mkdir /opt/gophish/ssl_keys
cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem" /opt/gophish/ssl_keys/key.pem
cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" /opt/gophish/ssl_keys/key.crt​
```
**メールの設定**

インストールを開始します：`apt-get install postfix`

次に、次のファイルにドメインを追加します：

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**また、/etc/postfix/main.cf内の次の変数の値も変更します**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、ファイル**`/etc/hostname`**と**`/etc/mailname`**をドメイン名に変更し、**VPSを再起動します。**

次に、`mail.<domain>`の**IPアドレス**を指す**DNS Aレコード**と、`mail.<domain>`を指す**DNS MXレコード**を作成します。

さて、メールを送信するテストを行いましょう：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

Gophishの実行を停止し、設定を行いましょう。\
`/opt/gophish/config.json`を以下のように変更してください（httpsの使用に注意してください）:
```bash
{
"admin_server": {
"listen_url": "127.0.0.1:3333",
"use_tls": true,
"cert_path": "gophish_admin.crt",
"key_path": "gophish_admin.key"
},
"phish_server": {
"listen_url": "0.0.0.0:443",
"use_tls": true,
"cert_path": "/opt/gophish/ssl_keys/key.crt",
"key_path": "/opt/gophish/ssl_keys/key.pem"
},
"db_name": "sqlite3",
"db_path": "gophish.db",
"migrations_prefix": "db/db_",
"contact_address": "",
"logging": {
"filename": "",
"level": ""
}
}
```
**gophishサービスの設定**

gophishサービスを自動的に起動し、サービスとして管理するために、以下の内容で`/etc/init.d/gophish`というファイルを作成します。
```bash
#!/bin/bash
# /etc/init.d/gophish
# initialization file for stop/start of gophish application server
#
# chkconfig: - 64 36
# description: stops/starts gophish application server
# processname:gophish
# config:/opt/gophish/config.json
# From https://github.com/gophish/gophish/issues/586

# define script variables

processName=Gophish
process=gophish
appDirectory=/opt/gophish
logfile=/var/log/gophish/gophish.log
errfile=/var/log/gophish/gophish.error

start() {
echo 'Starting '${processName}'...'
cd ${appDirectory}
nohup ./$process >>$logfile 2>>$errfile &
sleep 1
}

stop() {
echo 'Stopping '${processName}'...'
pid=$(/bin/pidof ${process})
kill ${pid}
sleep 1
}

status() {
pid=$(/bin/pidof ${process})
if [["$pid" != ""| "$pid" != "" ]]; then
echo ${processName}' is running...'
else
echo ${processName}' is not running...'
fi
}

case $1 in
start|stop|status) "$1" ;;
esac
```
サービスの設定を完了し、次の手順で確認してください：
```bash
mkdir /var/log/gophish
chmod +x /etc/init.d/gophish
update-rc.d gophish defaults
#Check the service
service gophish start
service gophish status
ss -l | grep "3333\|443"
service gophish stop
```
## メールサーバーとドメインの設定

### 待つ

ドメインが古ければ古いほど、スパムとして検知される可能性は低くなります。そのため、フィッシング評価を行う前にできるだけ長い時間（少なくとも1週間）待つ必要があります。\
ただし、1週間待つ必要がある場合でも、すべての設定を今すぐ完了することができます。

### 逆引きDNS（rDNS）レコードの設定

VPSのIPアドレスをドメイン名に解決するrDNS（PTR）レコードを設定します。

### Sender Policy Framework（SPF）レコード

新しいドメインには、**SPFレコードを設定する必要があります**。SPFレコードが何かわからない場合は、[**このページ**](../../network-services-pentesting/pentesting-smtp/#spf)を読んでください。

[https://www.spfwizard.net/](https://www.spfwizard.net)を使用して、SPFポリシーを生成することができます（VPSマシンのIPを使用してください）。

![](<../../.gitbook/assets/image (388).png>)

以下のコンテンツをドメイン内のTXTレコードに設定する必要があります。
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースのメッセージ認証、レポート、および適合性（DMARC）レコード

新しいドメインには、**DMARCレコードを設定する必要があります**。DMARCレコードが何かわからない場合は、[**このページ**](../../network-services-pentesting/pentesting-smtp/#dmarc)を読んでください。

次の内容で、ホスト名 `_dmarc.<ドメイン>` を指す新しいDNS TXTレコードを作成する必要があります：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインにDKIMを設定する必要があります。DMARCレコードが何かわからない場合は、[このページ](../../network-services-pentesting/pentesting-smtp/#dkim)を読んでください。

このチュートリアルは次のものに基づいています：[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
DKIMキーが生成する両方のB64値を連結する必要があります：
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### メール設定のスコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com)を使用してそれを行うことができます。\
単にページにアクセスし、彼らが提供するアドレスにメールを送信してください。
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
あなたのメール設定を確認するために、`check-auth@verifier.port25.com` にメールを送信し、レスポンスを読むこともできます（これにはポート25を開いて、メールをrootとして送信した場合は、_ /var/mail/root_ ファイルでレスポンスを確認する必要があります）。
すべてのテストに合格していることを確認してください：
```bash
==========================================================
Summary of Results
==========================================================
SPF check:          pass
DomainKeys check:   neutral
DKIM check:         pass
Sender-ID check:    pass
SpamAssassin check: ham
```
代わりに、**自分が制御しているGmailアドレスにメッセージを送信**することもできます。Gmailの受信トレイで受け取った**メールのヘッダー**を**表示**すると、`Authentication-Results`ヘッダーフィールドに`dkim=pass`が表示されるはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### スパムハウスのブラックリストからの削除

ウェブサイトwww.mail-tester.comは、あなたのドメインがスパムハウスによってブロックされているかどうかを示すことができます。ドメイン/IPの削除をリクエストするには、[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)にアクセスしてください。

### マイクロソフトのブラックリストからの削除

ドメイン/IPの削除をリクエストするには、[https://sender.office.com/](https://sender.office.com)にアクセスしてください。

## GoPhishキャンペーンの作成と実行

### 送信プロファイル

* 送信者プロファイルを識別するための**名前を設定**します。
* フィッシングメールを送信するアカウントを選択します。提案: _noreply, support, servicedesk, salesforce..._
* ユーザー名とパスワードは空白のままにしておくこともできますが、証明書エラーを無視するオプションをチェックすることを確認してください。

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
動作確認のためには、**「テストメールを送信」**機能を使用することをお勧めします。\
テストメールは、テスト中にブラックリストに登録されないように、**10分メールアドレス**に送信することをお勧めします。
{% endhint %}

### メールテンプレート

* テンプレートを識別するための**名前を設定**します。
* 次に、**件名**を書きます（普通のメールで読むことができるもので、特別なものではありません）。
* 「**トラッキングイメージを追加**」をチェックしていることを確認してください。
* **メールテンプレート**を書きます（以下の例のように変数を使用することができます）：
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>

<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">As you may be aware, due to the large number of employees working from home, the "PLATFORM NAME" platform is being migrated to a new domain with an improved and more secure version. To finalize account migration, please use the following link to log into the new HR portal and move your account to the new site: <a href="{{.URL}}"> "PLATFORM NAME" login portal </a><br />
<br />
Please Note: We require all users to move their accounts by 04/01/2021. Failure to confirm account migration may prevent you from logging into the application after the migration process is complete.<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
注意：**メールの信頼性を高めるために**、クライアントのメールからいくつかの署名を使用することをお勧めします。提案：

- **存在しないアドレス**にメールを送信し、応答に署名があるかどうかを確認します。
- info@ex.comやpress@ex.com、public@ex.comなどの**公開メール**を検索し、メールを送信して応答を待ちます。
- **いくつかの有効な発見済み**のメールに連絡を取り、応答を待ちます。

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
メールテンプレートでは、**送信するためにファイルを添付**することもできます。特別に作成されたファイル/ドキュメントを使用してNTLMチャレンジを盗む場合は、[このページ](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)を参照してください。
{% endhint %}

### ランディングページ

- 名前を**書く**
- ウェブページのHTMLコードを**書く**。ウェブページを**インポート**することもできます。
- **送信されたデータをキャプチャ**し、**パスワードをキャプチャ**するように設定します。
- リダイレクトを設定します。

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
通常、ページのHTMLコードを変更し、ローカルでテストを行う必要があります（おそらくApacheサーバーを使用して）。**結果が気に入るまで**、ローカルでテストを行ってください。その後、そのHTMLコードをボックスに書き込んでください。\
HTMLに**静的リソース**（CSSやJSページなど）を使用する必要がある場合は、それらを_**/opt/gophish/static/endpoint**_に保存し、_**/static/\<filename>**_からアクセスできます。
{% endhint %}

{% hint style="info" %}
リダイレクトでは、ユーザーを被害者の正規のメインウェブページに**リダイレクトする**か、例えば_/static/migration.html_にリダイレクトし、**5秒間スピニングホイール**（[**https://loading.io/**](https://loading.io)**）を表示し、その後処理が成功したことを示します**。
{% endhint %}

### ユーザーとグループ

- 名前を設定します
- データを**インポート**します（例のテンプレートを使用する場合、各ユーザーの名前、姓、メールアドレスが必要です）

![](<../../.gitbook/assets/image (395).png>)

### キャンペーン

最後に、キャンペーンを作成し、名前、メールテンプレート、ランディングページ、URL、送信プロファイル、グループを選択します。URLは被害者に送信されるリンクになります。

**送信プロファイルでは、最終的なフィッシングメールの見た目を確認するためにテストメールを送信**することができます：

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
テストメールを10分メールアドレスに送信することをお勧めします。これにより、テストを行うことでブラックリストに登録されるのを回避できます。
{% endhint %}

準備ができたら、キャンペーンを開始するだけです！

## ウェブサイトのクローニング

何らかの理由でウェブサイトをクローンしたい場合は、次のページを参照してください：

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## バックドア付きのドキュメントとファイル

一部のフィッシング評価（主にレッドチーム向け）では、**バックドアを含むファイルを送信**することも必要になる場合があります（C2を含む場合もあれば、単に認証をトリガーするものかもしれません）。\
いくつかの例については、次のページを参照してください：

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## MFAを用いたフィッシング

### プロキシMitMを介して

前の攻撃は非常に巧妙であり、実際のウェブサイトを偽装し、ユーザーが設定した情報を収集しています。ただし、ユーザーが正しいパスワードを入力しなかった場合や、偽装したアプリケーションが2FAで構成されている場合、**この情報ではトリックされたユーザーをなりすますことはできません**。

これは、[**evilginx2**](https://github.com/kgretzky/evilginx2)や[**CredSniper**](https://github.com/ustayready/CredSniper)などのツールが役立つ場所です。このツールを使用すると、MitMのような攻撃を生成できます。基本的に、攻撃は次のように機能します。

1. 実際のウェブページの**ログインフォームをなりすます**。
2. ユーザーは自分の資格情報を偽のページに送信し、ツールはそれらを実際のウェブページに送信して、**資格情報が機能するかどうかを確認**します。
3. アカウントが**2FAで構成**されている場合、MitMページはそれを要求し、**ユーザーが入力**すると、ツールはそれを実際のウェブページに送信します。
4. ユーザーが認証されると、攻撃者として、ツールがMitMを実行している間に、**資格情報、2FA、クッキー、およびすべてのインタラクションの情報**をキャプチャします。

### VNCを介して

もし、被害者を**元のウェブページに接続されたブラウザを持つVNCセッションに送信**する場合はどうでしょうか？彼が何をするかを見ることができ、パスワード、使用されたMFA、クッキーを盗むことができます...\
これは[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)で行うことができます。

## 検出の検出

明らかに、バスターされたかどうかを知るための最良の方法の1つは、**ドメインをブラックリストで検索**することです。リストに表示される場合、どうやらあなたのドメインが疑わしいと検出されたようです。\
ドメインがブラックリストに表示されているかどうかを確認する簡単な方法は、[https://malwareworld.com/](https://malwareworld.com)を使用することです。

ただし、次のような方法もあります。被害者のドメインと非常に似た名前のドメインを**購入**するか、被害者のドメインの**キーワード**を含む、あなたが制御しているドメインの**サブドメイン**の証明書を**生成**することができます。被害者がそれらと**DNSまたはHTTPのやり取り**を行うと、彼が**積極的に不審なドメインを探している**ことがわかり、非常に慎重にする必要があります。

### フィッシングの評価

[**Phishious**](https://github.com/Rices/Phishious)を使用して、メールがスパムフォルダに入るか、ブロックされるか、成功するかを評価してください。
## 参考文献

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
