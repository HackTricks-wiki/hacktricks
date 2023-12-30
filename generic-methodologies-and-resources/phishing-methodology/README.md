# フィッシング手法

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## 手法

1. 被害者の情報収集
1. **被害者ドメイン**を選択する。
2. 被害者が使用している**ログインポータルを検索**して基本的なWeb列挙を行い、どれを**偽装する**か**決定**する。
3. **OSINT**を使用して**メールアドレスを見つける**。
2. 環境の準備
1. フィッシング評価に使用するドメインを**購入する**
2. 関連するメールサービスのレコード（SPF、DMARC、DKIM、rDNS）を**設定する**
3. **gophish**を使ってVPSを設定する
3. キャンペーンの準備
1. **メールテンプレート**を準備する
2. 資格情報を盗むための**ウェブページ**を準備する
4. キャンペーンを開始する！

## 類似のドメイン名を生成するか、信頼できるドメインを購入する

### ドメイン名変更技術

* **キーワード**: ドメイン名には元のドメインの重要な**キーワード**が**含まれている**（例：zelster.com-management.com）。
* **ハイフン付きサブドメイン**: サブドメインの**ドットをハイフンに変更する**（例：www-zelster.com）。
* **新しいTLD**: 新しいTLDを使用した同じドメイン（例：zelster.org）
* **ホモグリフ**: ドメイン名の文字を**似ている文字に置き換える**（例：zelfser.com）。
* **転置**: ドメイン名内の二つの文字を**入れ替える**（例：zelster.com）。
* **単数化/複数化**: ドメイン名の最後に「s」を追加または削除する（例：zeltsers.com）。
* **省略**: ドメイン名から文字を**一つ取り除く**（例：zelser.com）。
* **繰り返し**: ドメイン名の文字を**繰り返す**（例：zeltsser.com）。
* **置換**: ホモグリフと似ているが、あまり隠れていない。ドメイン名の文字を置き換える、キーボード上で元の文字の近くにある文字にすることがある（例：zektser.com）。
* **サブドメイン化**: ドメイン名内に**ドットを挿入する**（例：ze.lster.com）。
* **挿入**: ドメイン名に文字を**挿入する**（例：zerltser.com）。
* **ドットの欠落**: TLDをドメイン名に追加する。（例：zelstercom.com）

**自動ツール**

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**ウェブサイト**

* [https://dnstwist.it/](https://dnstwist.it)
* [https://dnstwister.report/](https://dnstwister.report)
* [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### ビットフリッピング

コンピューティングの世界では、すべてが裏でメモリのビット（ゼロとワン）に格納されています。\
これはドメインにも適用されます。例えば、_windows.com_ はあなたのコンピューティングデバイスの揮発性メモリで _01110111..._ になります。\
しかし、太陽フレア、宇宙線、ハードウェアエラーなどによってこれらのビットの一つが自動的に反転したらどうでしょうか。つまり、0の一つが1になり、その逆も同様です。\
この概念をDNSリクエストに適用すると、DNSサーバーに到着する**要求されたドメイン**が、最初に要求されたドメインと**同じではない可能性があります。**

例えば、windows.comのドメインで1ビットの変更が行われると、それは_windnws.com_に変わるかもしれません。\
**攻撃者は、正当なユーザーを自分たちのインフラストラクチャにリダイレクトするために、被害者に関連するできるだけ多くのビットフリッピングドメインを登録するかもしれません。**

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を読んでください。

### 信頼できるドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net)で使用できる期限切れのドメインを検索できます。\
購入する期限切れのドメインが**すでに良いSEOを持っていることを確認する**ために、以下でどのように分類されているかを検索できます：

* [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
* [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

* [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 無料)
* [https://phonebook.cz/](https://phonebook.cz) (100% 無料)
* [https://maildb.io/](https://maildb.io)
* [https://hunter.io/](https://hunter.io)
* [https://anymailfinder.com/](https://anymailfinder.com)

**より多くの**有効なメールアドレスを**発見する**ため、またはすでに発見したメールアドレスを**検証する**ために、被害者のsmtpサーバーをブルートフォースできるかどうかを確認できます。[メールアドレスの検証/発見方法はこちら](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration)。\
さらに、ユーザーが**メールにアクセスするためのウェブポータルを使用している場合**、それが**ユーザー名ブルートフォース**に対して脆弱であるかどうかを確認し、可能であればその脆弱性を利用することを忘れないでください。

## GoPhishの設定

### インストール

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)からダウンロードできます。

`/opt/gophish`内にダウンロードして解凍し、`/opt/gophish/gophish`を実行します。\
出力でadminユーザーのパスワードが与えられるので、そのポートにアクセスしてその資格情報を使用してadminパスワードを変更します。そのポートをローカルにトンネリングする必要があるかもしれません。
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS証明書の設定**

このステップの前に、使用する**ドメインを既に購入**しており、それが設定している**gophish**の**VPSのIP**を**指している**必要があります。
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
**メール設定**

インストールを開始します: `apt-get install postfix`

次に、以下のファイルにドメインを追加します:

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**また、/etc/postfix/main.cf内の以下の変数の値を変更します**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、ファイル **`/etc/hostname`** と **`/etc/mailname`** をあなたのドメイン名に変更し、**VPSを再起動します。**

次に、**DNS A レコード**を `mail.<domain>` に作成し、VPSの**IPアドレス**を指定し、`mail.<domain>` を指す **DNS MX** レコードを作成します。

さて、メールの送信をテストしましょう:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

gophishの実行を停止し、設定しましょう。\
以下のように`/opt/gophish/config.json`を変更してください（httpsの使用に注意）：
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

gophishサービスを自動的に開始し、管理するサービスとして機能させるために、以下の内容で`/etc/init.d/gophish`ファイルを作成できます：
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
サービスの設定を完了し、以下を実行して確認します:
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

ドメインが古いほどスパムとして捉えられる可能性が低くなります。そのため、フィッシング評価を行う前にできるだけ長く（少なくとも1週間）待つべきです。\
ただし、1週間待つ必要があるとしても、今すべての設定を完了することができます。

### 逆引きDNS (rDNS) レコードの設定

VPSのIPアドレスがドメイン名に解決されるように、rDNS（PTR）レコードを設定します。

### Sender Policy Framework (SPF) レコード

新しいドメインに対して**SPFレコードを設定する必要があります**。SPFレコードが何かわからない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net) を使用して、SPFポリシーを生成します（VPSマシンのIPを使用してください）

![](<../../.gitbook/assets/image (388).png>)

これはドメイン内のTXTレコードに設定する必要がある内容です：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) レコード

新しいドメインに対して**DMARC レコードを設定する必要があります**。DMARC レコードが何かわからない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/#dmarc)。

ホスト名 `_dmarc.<domain>` を指す新しい DNS TXT レコードを以下の内容で作成する必要があります：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインには**DKIMを設定する必要があります**。DMARCレコードが何かわからない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/#dkim)。

このチュートリアルは次に基づいています: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
DKIMキーが生成する両方のB64値を連結する必要があります：
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### メール設定スコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com) を使用してこれを行うことができます。\
ページにアクセスし、彼らが提供するアドレスにメールを送信してください：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
メール設定を確認するには、`check-auth@verifier.port25.com` にメールを送信し、応答を読む必要があります（これにはポート **25** を開き、rootとしてメールを送信した場合、ファイル _/var/mail/root_ で応答を確認する必要があります）。\
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
代わりに、**自分で管理しているGmailアドレスにメッセージを送信し**、Gmailの受信トレイで受信した**メールのヘッダーを表示**します。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が存在している必要があります。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouseブラックリストからの削除

www.mail-tester.comのページは、ドメインがSpamhouseによってブロックされているかどうかを示すことができます。ドメイン/IPの削除をリクエストするには、次のURLにアクセスしてください: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoftブラックリストからの削除

ドメイン/IPの削除をリクエストするには、次のURLにアクセスしてください: [https://sender.office.com/](https://sender.office.com).

## GoPhishキャンペーンの作成と開始

### 送信プロファイル

* 送信者プロファイルを識別するための**名前を設定**します
* フィッシングメールを送信するアカウントを決定します。提案: _noreply, support, servicedesk, salesforce..._
* ユーザー名とパスワードは空白のままにすることができますが、証明書エラーを無視することを確認してください

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
"**テストメールを送信**"機能を使用して、すべてが正常に動作しているかテストすることをお勧めします。\
テストメールを10分メールアドレスに送信することをお勧めします。これにより、テストを行っている間にブラックリストに載るのを避けることができます。
{% endhint %}

### メールテンプレート

* テンプレートを識別するための**名前を設定**します
* **件名**を書きます（変わったものではなく、通常のメールで期待されるようなもの）
* "**トラッキング画像を追加**"がチェックされていることを確認します
* **メールテンプレート**を書きます（以下の例のように変数を使用できます）：
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
```markdown
**メールの信頼性を高めるために**、クライアントのメールから何らかの署名を使用することをお勧めします。以下の提案を参考にしてください：

* **存在しないアドレス**にメールを送信し、返信に署名が含まれているか確認します。
* info@ex.com や press@ex.com、public@ex.com などの**公開メール**を検索し、メールを送信して返信を待ちます。
* **有効な発見された**メールアドレスに連絡を試み、返信を待ちます。

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
Email Template では、**送信するファイルを添付**することもできます。特別に作成されたファイル/ドキュメントを使用して NTLM チャレンジを盗みたい場合は、[このページを読んでください](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。
{% endhint %}

### ランディングページ

* **名前**を書く
* ウェブページの**HTMLコードを記述**します。ウェブページを**インポート**できることに注意してください。
* **送信されたデータのキャプチャ**と**パスワードのキャプチャ**にチェックを入れます。
* **リダイレクション**を設定します。

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
通常、ページの HTML コードを変更し、ローカルでテスト（Apache サーバーを使用することもあります）を行い、**結果に満足するまで**行います。その後、その HTML コードをボックスに書き込みます。\
HTML に**静的リソースを使用する**必要がある場合（CSS や JS ページなど）、それらを _**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできることに注意してください。
{% endhint %}

{% hint style="info" %}
リダイレクションについては、ユーザーを被害者の正規のメインウェブページに**リダイレクトする**か、例えば _/static/migration.html_ にリダイレクトし、5秒間**スピニングホイール**（[**https://loading.io/**](https://loading.io)）を表示した後、プロセスが成功したことを示すことができます。
{% endhint %}

### ユーザー & グループ

* 名前を設定する
* **データをインポート**します（例のテンプレートを使用するには、各ユーザーの名、姓、メールアドレスが必要です）

![](<../../.gitbook/assets/image (395).png>)

### キャンペーン

最後に、名前、メールテンプレート、ランディングページ、URL、送信プロファイル、グループを選択してキャンペーンを作成します。URL は被害者に送信されるリンクになります。

**送信プロファイルでは、最終的なフィッシングメールの見た目を確認するためのテストメールを送信できる**ことに注意してください：

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
テストメールは、テストを行ってブラックリストに載るのを避けるために、10分メールアドレスに**送信することをお勧めします**。
{% endhint %}

準備が整ったら、キャンペーンを開始しましょう！

## ウェブサイトのクローニング

何らかの理由でウェブサイトをクローンしたい場合は、以下のページを確認してください：

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## バックドア付きドキュメント & ファイル

フィッシング評価（主にレッドチーム向け）では、何らかのバックドア（C2 または認証をトリガーするもの）を含むファイルを送信することもあります。\
例については、以下のページを確認してください：

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## MFA のフィッシング

### プロキシ MitM 経由

前述の攻撃は、本物のウェブサイトを偽装し、ユーザーが設定した情報を収集するという賢い方法です。残念ながら、ユーザーが正しいパスワードを入力していない場合や、偽装したアプリケーションに 2FA が設定されている場合、**この情報ではだまされたユーザーになりすますことはできません**。

このような場合に役立つのが、[**evilginx2**](https://github.com/kgretzky/evilginx2)、[**CredSniper**](https://github.com/ustayready/CredSniper)、[**muraena**](https://github.com/muraenateam/muraena) などのツールです。このツールを使用すると、MitM のような攻撃を生成できます。基本的に、攻撃は以下のように機能します：

1. 本物のウェブページの**ログインフォームを偽装**します。
2. ユーザーが自分の**認証情報を偽のページに送信**し、ツールがそれらを本物のウェブページに送信して、**認証情報が機能するかどうかを確認**します。
3. アカウントに**2FA が設定されている場合**、MitM ページはそれを要求し、**ユーザーが入力すると**、ツールはそれを本物のウェブページに送信します。
4. ユーザーが認証されると、攻撃者は**認証情報、2FA、クッキー、および MitM を実行している間のすべてのインタラクションの情報をキャプチャ**します。

### VNC 経由

**被害者を悪意のあるページに送る代わりに**、本物と同じ外観のページに送るのではなく、実際のウェブページに接続されたブラウザがある**VNC セッションに送る**とどうでしょうか？ ユーザーが何をしているかを見ることができ、パスワード、使用された MFA、クッキーなどを盗むことができます...\
これは [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) で行うことができます。

## 検出の検出

当然ながら、バレたかどうかを知る最善の方法の1つは、**ドメインをブラックリスト内で検索する**ことです。リストに載っていれば、何らかの方法でドメインが疑わしいと検出されたということです。\
ドメインがブラックリストに載っているかどうかを簡単にチェックする方法の1つは、[https://malwareworld.com/](https://malwareworld.com) を使用することです。

しかし、被害者が**野生で疑わしいフィッシング活動を積極的に探しているかどうか**を知る他の方法もあります。以下で説明されています：

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

被害者のドメインに非常に似た名前の**ドメインを購入する**か、被害者のドメインの**キーワードを含む**ドメインの**サブドメイン**に対して**証明書を生成**することができます。**被害者**がそれらと**DNS または HTTP のやり取り**を行った場合、**積極的に疑わしいドメインを探している**ことがわかり、非常に慎重である必要があります。

### フィッシングの評価

[**Phishious**](https://github.com/Rices/Phishious) を使用して、メールがスパムフォルダに入るか、ブロックされるか、成功するかを評価します。

## 参考文献

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)

<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricks をサポートする他の方法：

* **HackTricks に広告を掲載したい**場合や**HackTricks を PDF でダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFT**](https://opensea.io/collection/the-peass-family) コレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、Twitter 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォロー**してください。
* **HackTricks** の [**GitHub リポジトリ**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) に PR を提出して、ハッキングのコツを共有してください。

</details>
```
