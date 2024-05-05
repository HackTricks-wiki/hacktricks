# フィッシング手法

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **Discordグループ**に参加する 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) または [**telegram group**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live) をフォローする。
- **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## 手法

1. ターゲットを調査する
2. **ターゲットドメイン**を選択する。
3. ターゲットが使用しているログインポータルを検索し、**なりすます** ためにどれを **選択するかを決定**するために基本的なWeb列挙を実行する。
4. いくつかの **OSINT** を使用して **メールアドレスを見つける**。
5. 環境を準備する
6. フィッシングアセスメントに使用するドメインを**購入**する
7. 関連するレコード（SPF、DMARC、DKIM、rDNS）を **設定する**
8. **gophish**を使用してVPSを構成する
9. キャンペーンを準備する
10. **メールテンプレート**を準備する
11. 資格情報を盗むための **Webページ**を準備する
12. キャンペーンを開始する！

## 類似のドメイン名を生成するか信頼できるドメインを購入する

### ドメイン名の変更手法

- **キーワード**: オリジナルドメインの重要な **キーワードを含む** ドメイン名（例：zelster.com-management.com）。
- **ハイフン付きサブドメイン**: サブドメインの **ドットをハイフンに変更** する（例：www-zelster.com）。
- **新しいTLD**: 同じドメインを **新しいTLD** を使用して（例：zelster.org）。
- **ホモグリフ**: ドメイン名の文字を **似ている文字で置き換える**（例：zelfser.com）。
- **転置**: ドメイン名内の2つの文字を **入れ替える**（例：zelsetr.com）。
- **単数形/複数形**: ドメイン名の末尾に「s」を追加または削除する（例：zeltsers.com）。
- **省略**: ドメイン名から1つの文字を **削除する**（例：zelser.com）。
- **繰り返し**: ドメイン名内の1つの文字を **繰り返す**（例：zeltsser.com）。
- **置換**: ホモグリフと同様ですが、より控えめです。ドメイン名の1つの文字を置き換え、おそらくキーボード上で元の文字に近い位置の文字で置き換えます（例：zektser.com）。
- **サブドメイン**: ドメイン名内に **ドット** を挿入する（例：ze.lster.com）。
- **挿入**: ドメイン名に1つの文字を **挿入する**（例：zerltser.com）。
- **ドットの欠落**: ドメイン名にTLDを追加する（例：zelstercom.com）

**自動ツール**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**ウェブサイト**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### ビットフリップ

**太陽フレア、宇宙線、ハードウェアエラー**などのさまざまな要因により、 **保存されたビットのいくつかが自動的に反転** される可能性があります。

この概念を **DNSリクエストに適用** すると、DNSサーバーが受信したドメインが最初に要求されたドメインと異なる可能性があります。

たとえば、ドメイン「windows.com」の1ビットの変更で「windnws.com」に変更される可能性があります。

攻撃者は、被害者のドメインに類似した **複数のビットフリップドメインを登録** し、合法的なユーザーを自分のインフラストラクチャにリダイレクトすることを意図しています。

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を参照してください。

### 信頼できるドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net) で使用できる期限切れドメインを検索できます。\
購入する期限切れドメインが **既にSEOが良い** かどうかを確認するには、次のカテゴリーにどのように分類されているかを調べることができます：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（100%無料）
- [https://phonebook.cz/](https://phonebook.cz)（100%無料）
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

より多くの有効なメールアドレスを **発見** するか、すでに発見したメールアドレスを **検証** するために、被害者のsmtpサーバーをブルートフォースできるかどうかを確認できます。[ここでメールアドレスを検証/発見する方法を学ぶ](../../network-services-pentesting/pentesting-smtp/#username-bruteforce-enumeration)。\
さらに、ユーザーが **メールにアクセスするためにWebポータルを使用** している場合は、それが **ユーザー名ブルートフォース** に対して脆弱かどうかを確認し、可能であれば脆弱性を悪用できます。

## GoPhishの設定

### インストール

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) からダウンロードできます。

ダウンロードして `/opt/gophish` 内に解凍し、 `/opt/gophish/gophish` を実行します。\
出力には、ポート3333の管理者ユーザーのパスワードが表示されます。したがって、そのポートにアクセスし、その資格情報を使用して管理者パスワードを変更します。そのポートをローカルにトンネリングする必要がある場合があります。
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
**メール構成**

インストールを開始します：`apt-get install postfix`

次に、次のファイルにドメインを追加します：

* **/etc/postfix/virtual\_domains**
* **/etc/postfix/transport**
* **/etc/postfix/virtual\_regexp**

**また、/etc/postfix/main.cf内の次の変数の値を変更します**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、ファイル **`/etc/hostname`** と **`/etc/mailname`** をドメイン名に変更し、**VPSを再起動します。**

次に、`mail.<domain>`の**IPアドレス**を指す**DNS Aレコード**と、`mail.<domain>`を指す**DNS MX**レコードを作成します。

さて、メールを送信するテストを行いましょう：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

Gophishの実行を停止し、設定を行いましょう。\
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

gophishサービスを作成して自動的に起動および管理できるようにするために、次の内容でファイル`/etc/init.d/gophish`を作成します:
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

### 待つ & レジットになる

ドメインが古いほど、スパムとして検出される可能性が低くなります。そのため、フィッシングアセスメントを行う前にできるだけ長い時間（少なくとも1週間）待つべきです。さらに、信頼性の高いセクターに関するページを設置すれば、得られる評判もより良くなります。

1週間待たなければならないとしても、今すぐすべてを設定することができます。

### 逆引きDNS（rDNS）レコードの設定

VPSのIPアドレスをドメイン名に解決するrDNS（PTR）レコードを設定します。

### 送信者ポリシーフレームワーク（SPF）レコード

新しいドメインには**SPFレコードを設定する必要があります**。SPFレコードが何かわからない場合は、[**このページ**](../../network-services-pentesting/pentesting-smtp/#spf)を参照してください。

[https://www.spfwizard.net/](https://www.spfwizard.net)を使用して、SPFポリシーを生成できます（VPSマシンのIPを使用してください）

![](<../../.gitbook/assets/image (1037).png>)

これは、ドメイン内のTXTレコードに設定する必要がある内容です。
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースのメッセージ認証、レポート、遵守（DMARC）レコード

新しいドメインに**DMARCレコードを設定する必要があります**。DMARCレコードが何かわからない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/#dmarc)。

次の内容で、ホスト名 `_dmarc.<domain>` を指す新しいDNS TXTレコードを作成する必要があります：
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
あなたのメール構成をチェックすることもできます。`check-auth@verifier.port25.com` にメールを送信し、**応答を読む**ことができます（これにはポート **25** を**開く**必要があり、ルートとしてメールを送信すると、ファイル _/var/mail/root_ で応答を確認する必要があります）。\
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
あなたのコントロール下のGmailに**メッセージを送信**し、Gmailの受信トレイで**メールのヘッダー**を確認してください。`Authentication-Results`ヘッダーフィールドに`dkim=pass`が存在しているはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### スパムハウスブラックリストからの削除

ページ[www.mail-tester.com](https://www.mail-tester.com)は、あなたのドメインがスパムハウスによってブロックされているかどうかを示すことができます。あなたはあなたのドメイン/IPを削除するようにリクエストすることができます: [https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### マイクロソフトブラックリストからの削除

あなたは、[https://sender.office.com/](https://sender.office.com)であなたのドメイン/IPを削除するようにリクエストすることができます。

## GoPhishキャンペーンの作成と開始

### 送信プロファイル

* 送信者プロファイルを識別するための**名前を設定**
* どのアカウントからフィッシングメールを送信するかを決定します。提案: _noreply, support, servicedesk, salesforce..._
* ユーザー名とパスワードを空白のままにしても構いませんが、証明書エラーを無視するようにチェックを入れてください

![](<../../.gitbook/assets/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

{% hint style="info" %}
すべてが正常に動作しているかをテストするために、**「テストメールを送信」**機能を使用することをお勧めします。\
テストを行う際にブラックリストに登録されないように、**テストメールを10分メールアドレスに送信することをお勧めします**。
{% endhint %}

### メールテンプレート

* テンプレートを識別するための**名前を設定**
* 次に、**件名**を記述します（奇妙なものではなく、通常のメールで読むことができるもの）
* **トラッキング画像を追加**するようにチェックを入れていることを確認してください
* **メールテンプレート**を記述します（次の例のように変数を使用することができます）:
```markup
<html>
<head>
<title></title>
</head>
<body>
<p class="MsoNormal"><span style="font-size:10.0pt;font-family:&quot;Verdana&quot;,sans-serif;color:black">Dear {{.FirstName}} {{.LastName}},</span></p>
<br />
Note: We require all user to login an a very suspicios page before the end of the week, thanks!<br />
<br />
Regards,</span></p>

WRITE HERE SOME SIGNATURE OF SOMEONE FROM THE COMPANY

<p>{{.Tracker}}</p>
</body>
</html>
```
注意：**メールの信頼性を高めるために**、クライアントからのメールにいくつかの署名を使用することが推奨されています。提案：

* **存在しないアドレス**にメールを送信し、返信に署名があるかどうかを確認します。
* info@ex.com や press@ex.com、public@ex.com などの**公開メール**を検索して、メールを送信して返信を待ちます。
* **いくつかの有効な発見された**メールに連絡を取り、返信を待ちます

![](<../../.gitbook/assets/image (80).png>)

{% hint style="info" %}
メールテンプレートには、**送信するファイルを添付**することもできます。特別に作成されたファイル/ドキュメントを使用して NTLM チャレンジを盗む場合は、[このページ](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)を参照してください。
{% endhint %}

### ランディングページ

* **名前を記入**
* ウェブページの HTML コードを**記入**します。ウェブページを**インポート**することもできます。
* **送信されたデータをキャプチャ**し、**パスワードをキャプチャ**します
* **リダイレクト**を設定

![](<../../.gitbook/assets/image (826).png>)

{% hint style="info" %}
通常、ページの HTML コードを変更してローカルでテストを行い（たとえば Apache サーバーを使用して）、**結果に満足するまで**行います。その後、その HTML コードをボックスに記入します。\
HTML に**静的リソースを使用する必要がある場合**（たとえば、いくつかの CSS および JS ページ）、それらを _**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。
{% endhint %}

{% hint style="info" %}
リダイレクトでは、ユーザーを被害者の正規のメインウェブページに**リダイレクト**するか、例えば _/static/migration.html_ にリダイレクトして、**5秒間スピニングホイール**（[**https://loading.io/**](https://loading.io)**）を表示し、その後処理が成功したことを示します。
{% endhint %}

### ユーザー＆グループ

* 名前を設定
* データを**インポート**します（例のテンプレートを使用する場合、各ユーザーの名、姓、メールアドレスが必要です）

![](<../../.gitbook/assets/image (163).png>)

### キャンペーン

最後に、キャンペーンを作成し、名前、メールテンプレート、ランディングページ、URL、送信プロファイル、グループを選択します。URL は被害者に送信されるリンクになります

**送信プロファイルを使用して、最終的なフィッシングメールの見た目を確認することができます**：

![](<../../.gitbook/assets/image (192).png>)

{% hint style="info" %}
テストメールを送信して最終的なフィッシングメールの見た目を確認することをお勧めします。テストメールは、テストを行うことでブラックリストに登録されるのを避けるために、10分間のメールアドレスに送信することをお勧めします。
{% endhint %}

すべてが準備できたら、キャンペーンを開始してください！

## ウェブサイトのクローン

何らかの理由でウェブサイトをクローンしたい場合は、次のページを確認してください：

{% content-ref url="clone-a-website.md" %}
[clone-a-website.md](clone-a-website.md)
{% endcontent-ref %}

## バックドア付きドキュメント＆ファイル

一部のフィッシングアセスメント（主に Red Team 向け）では、バックドアを含むファイルを送信したい場合があります（たとえば、C2 または認証をトリガーするもの）。\
いくつかの例については、次のページを参照してください：

{% content-ref url="phishing-documents.md" %}
[phishing-documents.md](phishing-documents.md)
{% endcontent-ref %}

## フィッシング MFA

### プロキシ MitM 経由

前述の攻撃はかなり巧妙で、実際のウェブサイトを偽装し、ユーザーが設定した情報を収集しています。ただし、ユーザーが正しいパスワードを入力しなかった場合や、偽装したアプリケーションが2要素認証（2FA）で構成されている場合、**この情報ではだまされたユーザーをなりすますことはできません**。

これは、[**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper)、**[**muraena**](https://github.com/muraenateam/muraena) などのツールが役立ちます。このツールを使用すると、MitM のような攻撃を生成できます。基本的に、攻撃は次のように機能します：

1. 実際のウェブページの**ログインフォームをなりすまします**。
2. ユーザーは**自分の資格情報**をあなたの偽のページに送信し、ツールはそれらを実際のウェブページに送信して、**資格情報が機能するかどうかを確認**します。
3. アカウントが**2FA**で構成されている場合、MitM ページはそれを要求し、**ユーザーが入力**すると、ツールはそれを実際のウェブページに送信します。
4. ユーザーが認証されると、あなた（攻撃者）は、ツールが MitM を実行している間に、**資格情報、2FA、クッキー、およびすべてのインタラクションの情報**をキャプチャします。

### VNC 経由

被害者を**悪意のあるページに送信**する代わりに、実際のウェブページに接続されたブラウザを持つ**VNC セッションに被害者を送信**するとどうなりますか？彼が何をしているかを見ることができ、パスワード、使用された MFA、クッキーなどを盗むことができます。\
これは [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) で行うことができます。

## 検出の検出

明らかに、バレたかどうかを知る最良の方法の1つは、**ドメインをブラックリスト内で検索**することです。リストされている場合、どこかであなたのドメインが疑わしいとして検出されたということです。\
どのブラックリストにも登録されているかどうかを確認する簡単な方法は、[https://malwareworld.com/](https://malwareworld.com) を使用することです。

ただし、被害者が**野生の中で疑わしいフィッシング活動を積極的に探しているかどうか**を知るための他の方法があります。詳細は次のページで説明されています：

{% content-ref url="detecting-phising.md" %}
[detecting-phising.md](detecting-phising.md)
{% endcontent-ref %}

被害者のドメイン名に非常に似た名前のドメインを**購入**したり、被害者のドメインの**キーワードを含むサブドメイン**の証明書を**生成**したりすることができます。被害者がそれらと**DNS または HTTP インタラクション**を行うと、**疑わしいドメインを積極的に探している**ことがわかります。その場合は、非常に慎重である必要があります。

### フィッシングの評価

[**Phishious** ](https://github.com/Rices/Phishious)を使用して、メールがスパムフォルダに入るか、ブロックされるか、成功するかを評価します。

## 参考文献

* [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
* [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
* [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
* [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
