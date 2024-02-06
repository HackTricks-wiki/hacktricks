# フィッシング手法

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学びましょう</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **Discordグループ**に**参加**する💬（https://discord.gg/hRep4RUj7f）または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する[**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## 手法

1. ターゲットの情報収集
1. **ターゲットドメイン**を選択する。
2. ターゲットが使用しているログインポータルを検索し、**なりすます**ことに決めるために基本的なWeb列挙を実行する。
3. いくつかの**OSINT**を使用して**メールアドレスを見つける**。
2. 環境の準備
1. フィッシングアセスメントに使用するドメインを**購入**する
2. 関連するレコード（SPF、DMARC、DKIM、rDNS）を**設定する**
3. **gophish**を使用してVPSを構成する
3. キャンペーンの準備
1. **メールテンプレート**を準備する
2. 資格情報を盗むための**Webページ**を準備する
4. キャンペーンを開始する！

## 類似のドメイン名を生成するか信頼できるドメインを購入する

### ドメイン名の変更手法

- **キーワード**: オリジナルドメインの重要な**キーワードを含む**ドメイン名（例：zelster.com-management.com）。
- **ハイフン付きサブドメイン**: サブドメインの**ドットをハイフンに変更**する（例：www-zelster.com）。
- **新しいTLD**: 同じドメインを**新しいTLD**を使用して（例：zelster.org）。
- **ホモグリフ**: ドメイン名の1つの文字を**似ている文字で置き換える**（例：zelfser.com）。
- **転置**: ドメイン名内の2つの文字を**入れ替える**（例：zelster.com）。
- **単数形/複数形**: ドメイン名の末尾に「s」を追加または削除する（例：zeltsers.com）。
- **省略**: ドメイン名から1つの文字を**削除する**（例：zelser.com）。
- **繰り返し**: ドメイン名内の1つの文字を**繰り返す**（例：zeltsser.com）。
- **置換**: ホモグリフよりも洗練されていないが、ドメイン名内の1つの文字を置き換え、おそらく元の文字の隣にあるキーボード上の文字で置き換える（例：zektser.com）。
- **サブドメイン**: ドメイン名内に**ドット**を挿入する（例：ze.lster.com）。
- **挿入**: ドメイン名に**文字を挿入する**（例：zerltser.com）。
- **ドットの欠落**: ドメイン名にTLDを追加する（例：zelstercom.com）

**自動ツール**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**ウェブサイト**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### ビットフリップ

コンピューティングの世界では、すべてがメモリ内のビット（0と1）に格納されています。\
これはドメインにも当てはまります。たとえば、_windows.com_は、コンピューティングデバイスの揮発性メモリ内で_01110111..._になります。\
ただし、太陽フレア、宇宙線、またはハードウェアエラーにより、これらのビットの1つが自動的に反転した場合はどうなるでしょうか？ つまり、0の1になり、その逆もまた然りです。\
この概念をDNSリクエストに適用すると、DNSサーバーに到着する**要求されたドメインが最初に要求されたドメインと同じでない可能性があります**。

たとえば、ドメインwindows.comの1ビットの変更により、_windnws.com._に変換される可能性があります。\
**攻撃者は、被害者に関連する可能な限り多くのビットフリップドメインを登録して、合法的なユーザーを自分たちのインフラストラクチャにリダイレクトすることができます**。

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を参照してください。

### 信頼できるドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net)で使用可能な期限切れのドメインを検索できます。\
購入する期限切れのドメインが**すでに優れたSEOを持っている**ことを確認するために、次のカテゴリーにどのように分類されているかを調べることができます：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（100％無料）
- [https://phonebook.cz/](https://phonebook.cz)（100％無料）
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

より多くの有効なメールアドレスを**発見**したり、すでに発見したメールアドレスを**検証**したりするために、被害者のsmtpサーバーをブルートフォースできるかどうかを確認できます。[ここでメールアドレスを検証/発見する方法を学ぶ](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration)。\
さらに、ユーザーがメールにアクセスするために**Webポータルを使用**している場合は、**ユーザー名ブルートフォース**に対して脆弱かどうかを確認し、可能であれば脆弱性を悪用できます。

## GoPhishの設定

### インストール

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)からダウンロードできます。

ダウンロードして`/opt/gophish`内に展開し、`/opt/gophish/gophish`を実行します。\
出力には、管理ユーザーのパスワードが3333ポートで表示されます。したがって、そのポートにアクセスして、それらの資格情報を使用して管理者パスワードを変更します。そのポートをローカルにトンネリングする必要がある場合があります。
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS証明書の設定**

この手順の前に、使用するドメインを**すでに購入**しておく必要があり、そのドメインが**gophish**を設定している**VPSのIP**を**指している**必要があります。
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

- **/etc/postfix/virtual\_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual\_regexp**

**また、/etc/postfix/main.cf内の次の変数の値を変更します**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、**`/etc/hostname`** と **`/etc/mailname`** ファイルをドメイン名に変更し、**VPSを再起動します。**

次に、`mail.<domain>`の**IPアドレス**を指す**DNS Aレコード**と、`mail.<domain>`を指す**DNS MX**レコードを作成します。

さて、メールを送信するテストを行いましょう：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

Gophishの実行を停止し、設定を行います。\
`/opt/gophish/config.json`を以下のように変更してください（httpsの使用に注意）:
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

gophishサービスを作成して自動的に起動および管理できるようにするために、次の内容で`/etc/init.d/gophish`ファイルを作成します:
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
サービスの設定を完了し、次の手順を実行して確認します：
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

ドメインが古いほど、スパムとして検出される可能性が低くなります。そのため、フィッシングアセスメントを行う前にできるだけ長い時間（少なくとも1週間）待つべきです。\
1週間待たなければならないとしても、今すぐすべてを設定しておくことができます。

### 逆引きDNS（rDNS）レコードの設定

VPSのIPアドレスをドメイン名に解決するrDNS（PTR）レコードを設定します。

### 送信者ポリシーフレームワーク（SPF）レコード

新しいドメインには**SPFレコードを設定する必要があります**。SPFレコードが何かわからない場合は、[**このページ**](../../network-services-pentesting/pentesting-smtp/#spf)を参照してください。

[https://www.spfwizard.net/](https://www.spfwizard.net)を使用して、SPFポリシーを生成できます（VPSマシンのIPを使用します）

![](<../../.gitbook/assets/image (388).png>)

これは、ドメイン内のTXTレコードに設定する必要がある内容です。
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースのメッセージ認証、レポート、遵守（DMARC）レコード

新しいドメインに**DMARCレコードを設定する必要があります**。DMARCレコードが何かわからない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/#dmarc)。

次の内容を持つ新しいDNS TXTレコードを作成して、ホスト名を`_dmarc.<domain>`に向ける必要があります：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインにDKIMを**設定する必要があります**。DMARCレコードが何かわからない場合は、[**このページ**](../../network-services-pentesting/pentesting-smtp/#dkim)を読んでください。

このチュートリアルは次に基づいています: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

{% hint style="info" %}
DKIMキーが生成する両方のB64値を連結する必要があります:
```
v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
```
{% endhint %}

### メール構成スコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com)を使用してテストできます。\
ページにアクセスして、指定されたアドレスにメールを送信してください：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
あなたのメール構成もチェックできます。`check-auth@verifier.port25.com` にメールを送信し、**応答を読み取る**ことができます（これにはポート **25** を**開いて**、root としてメールを送信した場合はファイル _/var/mail/root_ で応答を確認する必要があります）。\
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
あるいは、**コントロールしているGmailアドレスにメッセージを送信**し、Gmailの受信トレイで受信した**メールのヘッダー**を表示します。`Authentication-Results`ヘッダーフィールドに`dkim=pass`が存在する必要があります。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### スパムハウスブラックリストからの削除

www.mail-tester.comのページは、あなたのドメインがスパムハウスによってブロックされているかどうかを示すことができます。あなたはあなたのドメイン/IPを次の場所で削除することができます：[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### マイクロソフトブラックリストからの削除

あなたは、[https://sender.office.com/](https://sender.office.com)であなたのドメイン/IPを削除することができます。

## GoPhishキャンペーンの作成と開始

### 送信プロファイル

* 送信者プロファイルを識別するための**名前を設定**
* どのアカウントからフィッシングメールを送信するかを決定します。提案：_noreply、support、servicedesk、salesforce..._
* ユーザー名とパスワードを空白のままにしても構いませんが、証明書エラーを無視するようにチェックを入れてください

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (17).png>)

{% hint style="info" %}
すべてが正常に動作しているかをテストするために、**「テストメールを送信」**機能を使用することをお勧めします。\
テストを行う際にブラックリストに登録されないように、**テストメールを10分メールアドレスに送信することをお勧めします**。
{% endhint %}

### メールテンプレート

* テンプレートを識別するための**名前を設定**
* 次に、**件名**を記入します（奇妙なものではなく、通常のメールで読みたいと思えるもの）
* **トラッキング画像を追加**するようにチェックを入れていることを確認してください
* **メールテンプレート**を記入します（次の例のように変数を使用することができます）:
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
**電子メールの信頼性を高めるために**、クライアントからの電子メールにいくつかの署名を使用することが推奨されています。提案：

- **存在しないアドレス**に電子メールを送信し、応答に署名があるかどうかを確認します。
- info@ex.com や press@ex.com、public@ex.com などの**公開された電子メール**を検索し、電子メールを送信して応答を待ちます。
- **いくつかの有効な発見された**電子メールに連絡を取り、応答を待ちます。

![](<../../.gitbook/assets/image (393).png>)

{% hint style="info" %}
電子メールテンプレートには、**添付ファイルを送信**する機能もあります。特別に作成されたファイル/ドキュメントを使用して NTLM チャレンジを盗む場合は、[このページ](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)を参照してください。
{% endhint %}

### ランディングページ

- **名前を記入**
- ウェブページの HTML コードを**記入**します。ウェブページを**インポート**することもできます。
- **送信されたデータをキャプチャ**し、**パスワードをキャプチャ**
- **リダイレクト**を設定

![](<../../.gitbook/assets/image (394).png>)

{% hint style="info" %}
通常、ページの HTML コードを変更してローカルでテストを行い（たとえば Apache サーバーを使用して）、**結果が気に入るまで**調整します。その後、その HTML コードをボックスに記入します。\
HTML に**静的リソースを使用する必要がある場合**（たとえば、いくつかの CSS および JS ページ）、それらを _**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。
{% endhint %}

{% hint style="info" %}
リダイレクトでは、ユーザーを被害者の正規のメインウェブページに**リダイレクト**するか、例えば _/static/migration.html_ にリダイレクトして、**5秒間スピニングホイール**（[**https://loading.io/**](https://loading.io)**）を表示し、その後処理が成功したことを示します。
{% endhint %}

### ユーザー＆グループ

- 名前を設定
- データを**インポート**します（例のテンプレートを使用する場合は、各ユーザーの名、姓、電子メールアドレスが必要です）

![](<../../.gitbook/assets/image (395).png>)

### キャンペーン

最後に、キャンペーンを作成し、名前、電子メールテンプレート、ランディングページ、URL、送信プロファイル、グループを選択します。URL は被害者に送信されるリンクになります。

**送信プロファイルを使用して、最終的なフィッシングメールの外観を確認するためにテストメールを送信できます**：

![](<../../.gitbook/assets/image (396).png>)

{% hint style="info" %}
テストメールは、テストを行ってブラックリストに登録されるのを避けるために、**10分間メールアドレスに送信することをお勧めします**。
{% endhint %}

すべてが準備できたら、キャンペーンを開始します！

## ウェブサイトのクローン

何らかの理由でウェブサイトをクローンしたい場合は、次のページを確認してください：

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## バックドア付きドキュメント＆ファイル

一部のフィッシングアセスメント（主に Red Team 向け）では、**バックドアを含むファイルを送信**したい場合があります（たとえば、C2 または認証をトリガーするもの）。\
いくつかの例については、次のページを参照してください：

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## フィッシング MFA

### プロキシ MitM 経由

前述の攻撃はかなり巧妙で、実際のウェブサイトを偽装し、ユーザーが設定した情報を収集しています。残念ながら、ユーザーが正しいパスワードを入力しなかった場合や、偽装したアプリケーションが2要素認証（2FA）で構成されている場合、**この情報ではだまされたユーザーをなりすますことはできません**。

このような場合、[**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper)、**[**muraena**](https://github.com/muraenateam/muraena) などのツールが役立ちます。このツールを使用すると、MitM のような攻撃を生成できます。基本的に、攻撃は次のように機能します：

1. 実際のウェブページの**ログインフォームをなりすます**。
2. ユーザーは**自分の資格情報**を偽のページに送信し、ツールはそれらを実際のウェブページに送信して、**資格情報が有効かどうかを確認**します。
3. アカウントが**2FA**で構成されている場合、MitM ページはそれを要求し、**ユーザーが入力**すると、ツールはそれを実際のウェブページに送信します。
4. ユーザーが認証されると、あなた（攻撃者）は、ツールが MitM を実行している間に、**資格情報、2FA、クッキー、およびすべてのインタラクションの情報**をキャプチャします。

### VNC 経由

被害者を**悪意のあるページ**に送る代わりに、元のページと同じ外観の**VNC セッションに接続されたブラウザ**に送るとどうなりますか？彼が何をしているかを見ることができ、パスワード、使用された MFA、クッキーなどを盗むことができます。\
これは [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) で行うことができます。

## 検出の検出

バレたかどうかを知るための最良の方法の1つは、**ドメインをブラックリスト内で検索**することです。リストされている場合、いかなる方法であれ、あなたのドメインが疑わしいとして検出されました。\
どのブラックリストにも登録されているかどうかを確認する簡単な方法は、[https://malwareworld.com/](https://malwareworld.com) を使用することです。

ただし、被害者が**野生の中で疑わしいフィッシング活動を積極的に探しているかどうか**を知るための他の方法があります。詳細は次のページで説明されています：

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

被害を受けたかどうかを知るために、被害者のドメイン名に非常に似た名前のドメインを**購入**したり、被害者のドメインの**キーワードを含む**あなたが管理するドメインの**サブドメイン**のために**証明書を生成**したりすることができます。被害者がそれらと**DNS または HTTP のインタラクション**を行うと、**疑わしいドメインを積極的に探している**ことがわかります。その場合は、非常に慎重である必要があります。

### フィッシングの評価

[**Phishious** ](https://github.com/Rices/Phishious)を使用して、あなたの電子メールがスパムフォルダに入るか、ブロックされるか、成功するかを評価してください。

## 参考文献

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</strong></summary>

HackTricks をサポートする他の方法：

- **HackTricks で企業を宣伝**したり、**HackTricks を PDF でダウンロード**したりする場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
- [**公式 PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れる
- 独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションである [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見
- 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live) をフォローする
- **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks) の GitHub リポジトリに PR を提出して、あなたのハッキングトリックを共有する

</details>
