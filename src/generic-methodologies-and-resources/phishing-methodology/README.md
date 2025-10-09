# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## 方法論

1. 被害者のRecon
1. Select the **victim domain**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. 環境を準備する
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. キャンペーンを準備する
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. キャンペーンを開始する！

## 似たドメイン名を生成するか、信頼されたドメインを購入する

### Domain Name Variation Techniques

- **Keyword**: 元のドメインの重要な**キーワードを含む**ドメイン名（例: zelster.com-management.com）。
- **hypened subdomain**: サブドメインの**ドットをハイフンに変える**（例: www-zelster.com）。
- **New TLD**: 同じドメインで**別のTLDを使う**（例: zelster.org）
- **Homoglyph**: ドメイン内の文字を**見た目が似ている文字に置き換える**（例: zelfser.com）。

{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** ドメイン名内で**2つの文字を入れ替える**（例: zelsetr.com）。
- **Singularization/Pluralization**: ドメイン名の末尾に「s」を**追加または削除**する（例: zeltsers.com）。
- **Omission**: ドメイン名から**1文字を削除する**（例: zelser.com）。
- **Repetition:** ドメイン名内の**1文字を重複させる**（例: zeltsser.com）。
- **Replacement**: homoglyphに似ているが目立ちやすい。ドメイン内の文字を別の文字に置き換える（例: zektser.com）。
- **Subdomained**: ドメイン名の中に**ドットを挿入する**（例: ze.lster.com）。
- **Insertion**: ドメイン名に**文字を挿入する**（例: zerltser.com）。
- **Missing dot**: ドメイン名にTLDを付け加える（例: zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

保存されているビットや通信中のビットが、太陽フレア、宇宙線、ハードウェアのエラーなどの要因で**自動的に反転する可能性**があります。

この概念を**DNS要求に適用すると**、DNSサーバーが受け取る**ドメインが最初に要求したドメインと異なる**場合があります。

例えば、ドメイン "windows.com" の1ビットの変更で "windnws.com" に変わることがあります。

攻撃者はこれを利用して、被害者のドメインに似た**複数のbit-flippingドメインを登録し**、正規ユーザを自分たちのインフラにリダイレクトしようとする可能性があります。

詳細は [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) を参照してください。

### Buy a trusted domain

Expired domainを探すには [https://www.expireddomains.net/](https://www.expireddomains.net) を検索できます。\
購入するexpired domainが**既に良いSEOを持っているか確認する**には、以下でどのカテゴリに分類されているかを確認すると良いです：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

さらに有効なメールアドレスを**発見したり既存のものを検証したりするために**、被害者のsmtpサーバに対してユーザ名のブルートフォースが可能かどうかを確認できます。[Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
また、ユーザが**メールにアクセスするために使っているwebポータル**がある場合、そのポータルが**username brute force**に対して脆弱かどうか確認し、可能ならその脆弱性を悪用することを忘れないでください。

## GoPhishの設定

### インストール

以下からダウンロードできます: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

`/opt/gophish` 内にダウンロードして展開し、`/opt/gophish/gophish` を実行してください。\
出力にport 3333のadminユーザ用パスワードが表示されます。表示された資格情報でそのポートにアクセスし、adminパスワードを変更してください。必要に応じてそのポートをローカルにトンネルする必要があります：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS certificate configuration**

この手順の前に、使用する **既に購入した domain** を用意しておく必要があり、**gophish** を設定している **VPS の IP** を **指している** ように設定されている必要があります。
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

インストールを開始：`apt-get install postfix`

次に、ドメインを次のファイルに追加します:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf 内の以下の変数の値も変更してください**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に **`/etc/hostname`** と **`/etc/mailname`** のファイルをあなたのドメイン名に変更し、**VPS を再起動**してください。

次に、`mail.<domain>` を VPS の **ip address** を指す **DNS A record** として作成し、`mail.<domain>` を指す **DNS MX** レコードを作成します。

では、メール送信をテストしてみましょう：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 設定**

gophish の実行を停止して設定を行います。\
`/opt/gophish/config.json` を次の内容に変更します（https の使用に注意）:
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
**gophish サービスを設定する**

gophishサービスを自動的に起動し、サービスとして管理できるようにするには、次の内容で `/etc/init.d/gophish` ファイルを作成します:
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
サービスの設定を完了し、動作確認を行ってください:
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
## メールサーバとドメインの設定

### 待つ & 正当性を示す

ドメインが古いほどスパム判定を受けにくくなります。したがって、phishing assessment の前にはできるだけ長く待つべきです（少なくとも1週間）。さらに、評判が重要なセクターに関するページを設置すると、得られる評判は良くなります。

たとえ1週間待つ必要があっても、今すぐすべての設定を完了しておくことができます。

### Reverse DNS (rDNS) レコードの設定

VPS の IP アドレスをドメイン名に解決する rDNS (PTR) レコードを設定してください。

### Sender Policy Framework (SPF) レコード

あなたは **新しいドメインに SPF レコードを設定する必要があります**。もし SPF レコードが何かわからない場合は [**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

SPF ポリシーを生成するには [https://www.spfwizard.net/](https://www.spfwizard.net) を使用できます（VPS の IP を使用してください）

![](<../../images/image (1037).png>)

以下がドメインの TXT レコードに設定すべき内容です：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) レコード

新しいドメインに対して**DMARCレコードを設定する必要があります**。DMARCレコードが何か分からない場合は[**このページを読む**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指す新しい DNS TXT レコードを次の内容で作成する必要があります:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインに対して**DKIMを設定する必要があります**。DMARCレコードが何かわからない場合は[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIMキーが生成する2つのB64値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### メール設定のスコアをテストする

これには [https://www.mail-tester.com/](https://www.mail-tester.com/) を使用できます\
ページにアクセスし、表示されるアドレスにメールを送信してください:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
また、`check-auth@verifier.port25.com` にメールを送信して、**メール設定を確認する**こともできます。**レスポンスを確認する**には、ポート**25**を**開く**必要があり、メールを root として送信した場合はレスポンスを _/var/mail/root_ ファイルで確認してください。\
テストにすべて合格していることを確認してください:
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
また、あなたが管理する **Gmail にメッセージを送信** して、Gmail の受信トレイで **メールのヘッダー** を確認することもできます。`Authentication-Results` ヘッダーに `dkim=pass` が含まれているはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Blacklist からの削除

The page [www.mail-tester.com](https://www.mail-tester.com) は、あなたのドメインが spamhouse によってブロックされているかどうかを示してくれます。ドメイン/IP の削除をリクエストするには次を使用してください: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist からの削除

​​ドメイン/IP の削除は [https://sender.office.com/](https://sender.office.com) でリクエストできます。

## Create & Launch GoPhish Campaign

### Sending Profile

- 送信者プロファイルを識別するための **識別用の名前** を設定する
- どのアカウントからフィッシングメールを送信するか決めます。推奨: _noreply, support, servicedesk, salesforce..._
- username と password を空白のままにできますが、必ず "Ignore Certificate Errors" をチェックしてください

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 機能 "**Send Test Email**" を使って、すべてが正しく動作しているかテストすることを推奨します。\
> テストでブラックリスト入りするのを避けるため、**テストメールは 10min mails のアドレスに送る**ことをおすすめします。

### Email Template

- テンプレートを識別するための **識別用の名前** を設定する
- 次に **件名** を書きます（不自然なものではなく、通常のメールで見かけるような内容）
- "**Add Tracking Image**" をチェックしていることを確認する
- **メールテンプレート** を作成する（以下の例のように変数を使用できます）:
```html
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
注意：**in order to increase the credibility of the email**、クライアントのemailからの署名を使うことを推奨します。提案：

- 存在しないアドレスに**emailを送信**し、返信に署名が含まれているか確認する。
- info@ex.com や press@ex.com、public@ex.com のような**公開されているemail**を探し、そこに送信して返信を待つ。
- 発見した**有効なemail**のいずれかに連絡して、返信を待つ。

![](<../../images/image (80).png>)

> [!TIP]
> Email Templateは**添付ファイルを送信**することも可能です。特別に作成したファイル/ドキュメントでNTLMチャレンジを盗みたい場合は、このページを参照してください（[read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)）。

### ランディングページ

- 名前を**入力**する
- ウェブページの**HTMLコードを記述**する。ページを**インポート**することもできる点に注意。
- **Capture Submitted Data** と **Capture Passwords** をチェックする
- **リダイレクト**を設定する

![](<../../images/image (826).png>)

> [!TIP]
> 通常、HTMLコードを修正してローカルで（例えばApacheを使って）テストを繰り返し、**納得のいく結果になるまで**調整する必要があります。満足できたら、そのHTMLコードをボックスに貼り付けてください。\
> HTMLで**静的リソース**（CSSやJSなど）を使う必要がある場合、それらを _**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。

> [!TIP]
> リダイレクトでは、被害者を被害者組織の正規のメインページに**リダイレクト**するか、例えば _/static/migration.html_ にリダイレクトして、5秒間**スピニングホイール**（[https://loading.io/](https://loading.io)）を表示し、その後プロセスが成功したと表示する、といった手法が使えます。

### ユーザー & グループ

- 名前を設定する
- **データをインポート**する（テンプレートを使う場合、各ユーザーに対して firstname、last name、email address が必要な点に注意）

![](<../../images/image (163).png>)

### キャンペーン

最後に、名前、email template、landing page、URL、sending profile、group を選択してキャンペーンを作成します。URLは被害者に送られるリンクになります。

Sending Profile は、最終的なphishing emailがどのように見えるかを確認するために**test emailを送る**ことを許可します：

![](<../../images/image (192).png>)

> [!TIP]
> テストによってブラックリスト入りを避けるため、test emailsは10min mailsのアドレスに送ることを推奨します。

すべて準備が整ったら、キャンペーンを開始してください！

## Webサイトのクローン作成

何らかの理由でサイトをクローンしたい場合は、次のページを確認してください：

{{#ref}}
clone-a-website.md
{{#endref}}

## バックドア入りドキュメント & ファイル

一部のフィッシング評価（主にRed Teams）では、**C2を含むようなバックドア**を含むファイルを送ることがあります（あるいは認証をトリガーするだけのもの）。例については次のページを参照してください：

{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### プロキシ MitM 経由

前の攻撃は非常に巧妙で、実際のウェブサイトを偽装してユーザーが入力した情報を収集します。しかし、ユーザーが正しいパスワードを入力しなかった場合や、偽装したアプリケーションが2FAで保護されている場合、**その情報だけでは騙されたユーザーを完全になりすますことはできません**。

ここで [**evilginx2**](https://github.com/kgretzky/evilginx2)、[**CredSniper**](https://github.com/ustayready/CredSniper)、[**muraena**](https://github.com/muraenateam/muraena) のようなツールが有用になります。これらのツールはMitM型の攻撃を実現します。基本的な流れは次の通りです：

1. 実際のウェブページのログインフォームを**偽装**する。
2. ユーザーが偽ページに**credentials**を送信すると、ツールはそれらを本物のウェブページに送信し、**認証情報が有効か確認**する。
3. アカウントが**2FA**で保護されている場合、MitMページはそれを要求し、ユーザーが入力するとツールはそれを本物のページに送信する。
4. ユーザーが認証されると、攻撃者は（ツールがMitMを行っている間の）すべてのやり取りから**credentials、2FA、cookie、およびその他の情報**を捕捉できます。

### VNC 経由

被害者を元のページと同じ見た目の悪意あるページに**誘導する代わりに**、ブラウザが本物のウェブページに接続された状態の**VNCセッション**に誘導したらどうなるでしょうか？被害者の操作を見て、パスワード、MFA、cookieなどを盗むことができます。これには [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) を使用できます。

## 検出の検知

自分が検出されたかどうかを知る最も簡単な方法の一つは、自分のドメインがブラックリストに載っていないか**確認する**ことです。リストに載っている場合、何らかの方法でドメインが疑わしいと検出されたことを意味します。\
自分のドメインがブラックリストに載っているか確認する簡単な方法としては [https://malwareworld.com/](https://malwareworld.com) を使う方法があります。

しかし、被害者側が**積極的に疑わしいphishing活動を探しているかどうか**を知る別の方法もあります。詳細は次のページを参照してください：

{{#ref}}
detecting-phising.md
{{#endref}}

非常に似た名前のドメインを購入したり、自分が管理するドメインのサブドメインに被害者ドメインの**キーワードを含む証明書**を生成したりできます。被害者がそれらのドメインへDNSやHTTPで何らかの操作を行った場合、被害者が**積極的に疑わしいドメインを探している**ことが分かり、より慎重に行動する必要があります。

### フィッシングの評価

自分のemailがスパムフォルダに入るか、ブロックされるか、成功するかを評価するために [**Phishious**](https://github.com/Rices/Phishious) を使ってください。

## High-Touch Identity Compromise（Help-Desk MFA リセット）

最近の侵入手口では、メール誘導を完全にスキップして、MFAを回避するために**サービスデスク / identity-recovery ワークフロー**を直接狙う手法が増えています。攻撃は完全に「living-off-the-land」で行われます：オペレーターが有効な資格情報を得ると、組み込みの管理ツールでピボットし、マルウェアは不要です。

### 攻撃フロー
1. 被害者の情報収集
- LinkedIn、データ漏洩、公開GitHubなどから個人・企業の詳細情報を収集する。
- 高価値のアイデンティティ（役員、IT、財務など）を特定し、パスワード/MFAリセットの**正確なヘルプデスク手順**を列挙する。
2. リアルタイムのソーシャルエンジニアリング
- 電話、Teams、チャットでヘルプデスクに連絡し、ターゲットになりすます（多くの場合**発信者ID偽装**や**声のクローン**を使用）。
- 事前に収集したPIIを提示して知識ベース認証を通過する。
- エージェントに対して**MFAのシークレットをリセット**させるか、登録済みの携帯番号で**SIM-swap**を実行させるよう説得する。
3. 即時のポストアクセス活動（実際のケースでは≤60分）
- 任意のweb SSOポータルを経由して足場を確立する。
- 組み込みツールで AD / AzureAD を列挙（バイナリを落とさない）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
- 環境内で既にホワイトリスト化された正当な RMM エージェント や **WMI**, **PsExec** を使って横移動する。

### 検知 & 緩和
- ヘルプデスクの identity recovery を**特権操作**として扱い、ステップアップ認証と上長の承認を要求する。
- **Identity Threat Detection & Response (ITDR)** / **UEBA** ルールを導入し、以下を検知してアラートを出す：
  - MFA方法が変更され、かつ新しいデバイス/ジオからの認証が行われた場合。
  - 同一のプリンシパルが即座に昇格（user → admin）した場合。
- ヘルプデスクの通話を録音し、リセット前に**既に登録済みの番号へ折り返し**を義務付ける。
- 新しくリセットされたアカウントが高権限トークンを自動的に継承しないよう、**Just-In-Time (JIT) / Privileged Access** を実装する。

---

## 大規模な偽装 – SEO Poisoning & “ClickFix” キャンペーン
ローエンドの攻撃集団は、高度な手作業オペレーションのコストを相殺するために、検索エンジンや広告ネットワークを配信チャネルとして利用する大量攻撃を行います。

1. **SEO poisoning / malvertising** により、`chromium-update[.]site` のような偽結果を検索広告の上位に押し上げる。
2. 被害者は小さな**first-stage loader**（多くはJS/HTA/ISO）をダウンロードする。Unit 42が確認した例：
- `RedLine stealer`
- `Lumma stealer`
- `Lampion Trojan`
3. LoaderはブラウザのcookieやクレデンシャルDBを持ち出し、その後**サイレントローダー**を引き込み、リアルタイムで次に何を展開するか決定する：
- RAT（例：AsyncRAT、RustDesk）
- ランサムウェア / ワイパー
- 永続化コンポーネント（registry Run key + scheduled task）

### ハードニングのヒント
- 新規登録ドメインをブロックし、検索広告やメールの両方で**Advanced DNS / URL Filtering**を実施する。
- ソフトウェアのインストールを署名された MSI / Store パッケージに限定し、`HTA`、`ISO`、`VBS` の実行をポリシーで禁止する。
- ブラウザの子プロセスがインストーラを開く動作を監視する：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
- first-stage loader に悪用されやすい LOLBins（例：`regsvr32`, `curl`, `mshta`）をハントする。

---

## AI強化フィッシング作戦
攻撃者は現在、LLM & voice-clone API を連携させて、完全に個別化された誘い文句やリアルタイムのやり取りを行っています。

| レイヤー | 攻撃者による利用例 |
|-------|-----------------------------|
| 自動化 | Generate & send >100 k emails / SMS with randomised wording & tracking links. |
| Generative AI | 公開M&Aやソーシャルメディアの内輪ネタを参照する一回限りのメールを作成；コールバック詐欺でCEOのdeep-fake voiceを使う。 |
| Agentic AI | ドメインを自律的に登録し、OSSインテリジェンスをスクレイピングし、被害者がクリックしたが提出しなかった場合に次の段階のメールを自動生成する。 |

防御：
• ARC/DKIMの異常を元に、信頼できない自動化から送信されたメッセージを強調する**動的バナー**を追加する。  
• 高リスクの電話要求に対して**音声バイオメトリクスのチャレンジフレーズ**を導入する。  
• 意識向上プログラムでAI生成誘い文句を継続的にシミュレートする — 静的なテンプレートは時代遅れです。

関連：agentic browsing abuse による credential phishing も参照してください：

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing 変種 – 強制リセット
クラシックなpush-bombingに加え、オペレーターは単にヘルプデスクの通話中に**新しいMFA登録を強制**してユーザーの既存トークンを無効化することがあります。これにより、その後のログインプロンプトは被害者にとって正当なものに見えます。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
同一IPから数分以内に **`deleteMFA` + `addMFA`** が発生する AzureAD/AWS/Okta のイベントを監視してください。



## Clipboard Hijacking / Pastejacking

攻撃者は、侵害されたまたはタイポスクワットされたウェブページから被害者のクリップボードに悪意のあるコマンドを密かにコピーし、ユーザーを騙して **Win + R**, **Win + X** またはターミナルウィンドウに貼り付けさせることで、ダウンロードや添付ファイルなしに任意のコードを実行させることができます。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
オペレーターはフィッシングフローを簡単なデバイスチェックの裏に置き、デスクトップのクローラーが最終ページに到達しないようにすることが増えています。一般的なパターンは、タッチ対応のDOMを検出して結果をサーバーエンドポイントにPOSTする小さなスクリプトで、非モバイルクライアントにはHTTP 500（または空白のページ）が返され、モバイルユーザーにはフルフローが提供されます。

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` ロジック (簡略化):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
よく観察されるサーバーの挙動:
- 最初の読み込み時にセッションcookieを設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` の場合、以降のGETに対して500（またはプレースホルダ）を返す；`true` の場合のみ phishing を配信する。

ハンティングと検出のヒューリスティック:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: `GET /static/detect_device.js` → `POST /detect` → 非モバイルでは HTTP 500；正規のモバイルアクセス経路は200を返し、その後のHTML/JSを返す。
- コンテンツを `ontouchstart` や類似のデバイスチェックのみに基づいて条件分岐しているページはブロックまたは精査する。

防御のヒント:
- モバイル類似のフィンガープリントとJSを有効にした状態でクローラーを実行し、ゲートされたコンテンツを露出させる。
- 新規登録ドメインで `POST /detect` に続く疑わしい500応答を検知して警告する。

## 参考資料

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
