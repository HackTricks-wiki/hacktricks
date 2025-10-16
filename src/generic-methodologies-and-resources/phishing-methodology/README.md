# Phishing 方法論

{{#include ../../banners/hacktricks-training.md}}

## 手順

1. Recon the victim
1. Select the **被害者ドメイン**.
2. Perform some basic web enumeration **searching for login portals** used by the victim and **decide** which one you will **impersonate**.
3. Use some **OSINT** to **find emails**.
2. Prepare the environment
1. **Buy the domain** you are going to use for the phishing assessment
2. **Configure the email service** related records (SPF, DMARC, DKIM, rDNS)
3. Configure the VPS with **gophish**
3. Prepare the campaign
1. Prepare the **email template**
2. Prepare the **web page** to steal the credentials
4. Launch the campaign!

## 類似ドメインを生成するか信頼されたドメインを購入する

### Domain Name Variation Techniques

- **Keyword**: The domain name **contains** an important **keyword** of the original domain (e.g., zelster.com-management.com).
- **hypened subdomain**: Change the **dot for a hyphen** of a subdomain (e.g., www-zelster.com).
- **New TLD**: Same domain using a **new TLD** (e.g., zelster.org)
- **Homoglyph**: It **replaces** a letter in the domain name with **letters that look similar** (e.g., zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** It **swaps two letters** within the domain name (e.g., zelsetr.com).
- **Singularization/Pluralization**: Adds or removes “s” at the end of the domain name (e.g., zeltsers.com).
- **Omission**: It **removes one** of the letters from the domain name (e.g., zelser.com).
- **Repetition:** It **repeats one** of the letters in the domain name (e.g., zeltsser.com).
- **Replacement**: Like homoglyph but less stealthy. It replaces one of the letters in the domain name, perhaps with a letter in proximity of the original letter on the keyboard (e.g, zektser.com).
- **Subdomained**: Introduce a **dot** inside the domain name (e.g., ze.lster.com).
- **Insertion**: It **inserts a letter** into the domain name (e.g., zerltser.com).
- **Missing dot**: Append the TLD to the domain name. (e.g., zelstercom.com)

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

There is a **possibility that one of some bits stored or in communication might get automatically flipped** due to various factors like solar flares, cosmic rays, or hardware errors.

When this concept is **applied to DNS requests**, it is possible that the **domain received by the DNS server** is not the same as the domain initially requested.

For example, a single bit modification in the domain "windows.com" can change it to "windnws.com."

Attackers may **take advantage of this by registering multiple bit-flipping domains** that are similar to the victim's domain. Their intention is to redirect legitimate users to their own infrastructure.

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### Buy a trusted domain

You can search in [https://www.expireddomains.net/](https://www.expireddomains.net) for a expired domain that you could use.\
In order to make sure that the expired domain that you are going to buy **has already a good SEO** you could search how is it categorized in:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの収集

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

有効なメールアドレスをさらに**発見**したり、既に見つけたアドレスを**検証**するために、victim の smtp サーバを使ってブルートフォースを試みることができます。詳しくは [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
さらに、ユーザがメールにアクセスするために**任意の web portal**を使用している場合、そのポータルが **username brute force** に脆弱かどうかを確認し、可能であればその脆弱性を悪用してください。

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS 証明書の設定**

この手順の前に、使用するドメインを**すでに購入している**必要があり、そのドメインは、あなたが**gophish**を設定している**VPS の IP**を**指している**必要があります。
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

その後、ドメインを次のファイルに追加します:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf 内の次の変数の値も変更してください**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に **`/etc/hostname`** と **`/etc/mailname`** をあなたのドメイン名に変更し、**VPS を再起動してください。**

次に、VPS の **IPアドレス** を指す `mail.<domain>` の **DNS A record** と、`mail.<domain>` を指す **DNS MX** record を作成してください

では、メールを送信してテストします:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish の設定**

gophish の実行を停止して、設定を行います.\
次のように `/opt/gophish/config.json` を変更します（https を使用している点に注意）：
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
**gophish サービスの設定**

gophish サービスを作成して自動起動およびサービスとして管理できるようにするには、次の内容でファイル `/etc/init.d/gophish` を作成します:
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
サービスの設定を完了し、動作確認を行ってください：
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

### Wait & be legit

ドメインの登録が古いほど、スパムとして検出される可能性は低くなります。したがって、phishingの評価を行う前にできるだけ長く（少なくとも1週間）待つべきです。さらに、評判の良い業種に関するページを用意すると、得られる評判はより良くなります。

たとえ1週間待つ必要があっても、今のうちに設定をすべて終えておくことはできます。

### Configure Reverse DNS (rDNS) record

VPSのIPアドレスがドメイン名に解決されるように、rDNS (PTR) レコードを設定してください。

### Sender Policy Framework (SPF) Record

新しいドメインに対して**SPF レコードを設定する必要があります**。SPFレコードが何か分からない場合は[**このページを読む**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

You can use [https://www.spfwizard.net/](https://www.spfwizard.net) to generate your SPF policy (use the IP of the VPS machine)

![](<../../images/image (1037).png>)

これはドメインのTXTレコードに設定する内容です:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) レコード

新しいドメインに対して**DMARC レコードを構成する必要があります**。もし DMARC レコードが何か分からない場合は[**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指す新しい DNS TXT レコードを、次の内容で作成する必要があります:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインに対して**DKIMを設定する必要があります**。DMARCレコードが何かわからない場合は[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIMキーが生成する両方のB64値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

これには [https://www.mail-tester.com/](https://www.mail-tester.com)\
を使用できます。ページにアクセスして、表示されるアドレスにメールを送信してください：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
また、`check-auth@verifier.port25.com` にメールを送信して、**メール設定を確認する**および**応答を確認する**こともできます（これを行うには **open** port **25** を開き、root としてメールを送信した場合はファイル _/var/mail/root_ で応答を確認する必要があります）。\
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
**あなたが管理する Gmail にメッセージを送信する**こともでき、Gmail の受信トレイで**メールのヘッダ**を確認してください。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が存在するはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Removing from Spamhouse Blacklist

ページ [www.mail-tester.com](https://www.mail-tester.com) は、あなたのドメインが spamhouse によってブロックされているかどうかを確認できます。ドメイン/IP の削除をリクエストするには次を利用してください: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Removing from Microsoft Blacklist

​​ドメイン/IP の削除をリクエストするには [https://sender.office.com/](https://sender.office.com) を利用してください。

## Create & Launch GoPhish Campaign

### Sending Profile

- 送信プロファイルを識別するための **name to identify** を設定してください
- どのアカウントから phishing emails を送信するか決めてください。提案: _noreply, support, servicedesk, salesforce..._
- username と password は空欄でも構いませんが、必ず **Ignore Certificate Errors** にチェックを入れてください

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 動作確認のために "**Send Test Email**" 機能を使うことを推奨します。\
> テストでブラックリスト登録されるのを避けるため、**send the test emails to 10min mails addresses** にテストメールを送ることをおすすめします。

### Email Template

- テンプレートを識別するための **name to identify** を設定してください
- 次に **subject** を記入してください（不審な内容ではなく、通常のメールで目にするような件名）
- 「**Add Tracking Image**」にチェックが入っていることを確認してください
- **email template** を作成してください（以下の例のように変数を使用できます）：
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
Note that **in order to increase the credibility of the email**, it's recommended to use some signature from an email from the client. Suggestions:

- 存在しないアドレスにメールを送って、返信に署名が含まれていないか確認する。
- info@ex.com や press@ex.com や public@ex.com のような **公開されているメール** を探してメールを送り、返信を待つ。
- 発見した **有効なメール** に連絡を取り、返信を待つ。

![](<../../images/image (80).png>)

> [!TIP]
> Email Template は **ファイルを添付して送信する** 機能も許容します。もし特別に作成したファイル/ドキュメントを使って NTLM challenges を盗みたい場合は [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md) を参照してください。

### Landing Page

- 名前を記入する
- ページの **HTML コードを記述する**。web ページを **import** できることに注意。
- **Capture Submitted Data** と **Capture Passwords** をマークする
- **リダイレクト** を設定する

![](<../../images/image (826).png>)

> [!TIP]
> 通常は HTML コードを修正してローカルで（Apache 等を使って）テストを繰り返し、**満足する結果になるまで** 調整する必要があります。その後、その HTML コードをボックスに書き込んでください。\
> HTML に静的リソース（CSS や JS など）を使用する必要がある場合は、それらを _**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ から参照できます。

> [!TIP]
> リダイレクト先としては、被害者の正規サイトのメインページに **リダイレクト** するか、例えば _/static/migration.html_ にリダイレクトして、5秒間の **スピニングホイール**（[https://loading.io/](https://loading.io/)）を表示してから処理が成功したと示す、という手法が考えられます。

### Users & Groups

- 名前を設定する
- **データをインポートする**（テンプレートを使用する例では、各ユーザの firstname、last name、email address が必要になる点に注意）

![](<../../images/image (163).png>)

### Campaign

最後に、name、email template、landing page、URL、sending profile、group を選んで campaign を作成します。URL は被害者に送るリンクになります。

Sending Profile により、最終的な phishing メールがどのように見えるかを確認するためのテストメールを送ることができます:

![](<../../images/image (192).png>)

> [!TIP]
> テストを行う際はブラックリスト登録を避けるために **10min mails** のアドレスにテストメールを送ることを推奨します。

準備が整ったら、campaign を開始してください。

## Website Cloning

何らかの理由でウェブサイトをクローンしたい場合は、次のページを確認してください：


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

一部の phishing 評価（主に Red Teams）では、backdoor を含むファイルを送信したい場合があります（C2 か、認証を引き起こすだけのものなど）。例については次のページを参照してください：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述の攻撃は、実際のサイトを偽装してユーザが入力した情報を収集する点で非常に巧妙です。しかし、ユーザが正しいパスワードを入力しなかった場合や、偽装したアプリケーションが 2FA によって保護されている場合、その情報だけでは **騙されたユーザになりすますことはできません**。

ここで [**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper) および [**muraena**](https://github.com/muraenateam/muraena) のようなツールが有用になります。これらのツールは MitM のような攻撃を実行可能にします。攻撃の流れは概ね次の通りです：

1. 実際のウェブページのログインフォームを **impersonate** する。
2. ユーザは偽ページに **credentials** を送信し、ツールはそれらを実際のウェブページに転送して **credentials が有効かを確認する**。
3. アカウントが **2FA** を設定している場合、MitM ページはそれを要求し、ユーザが入力するとツールはそれを実際のウェブページへ送信する。
4. ユーザが認証されると、攻撃者は（ツールが MitM を実行している間の）すべてのやり取りから **credentials、2FA、cookie、および関連情報** を取得することができます。

### Via VNC

元のページに似せた悪意あるページに被害者を誘導する代わりに、被害者を **VNC セッション内のブラウザで実際のウェブページに接続させる**とどうなるでしょうか？被害者の操作をリアルタイムで観察でき、パスワード、MFA、cookie などを盗むことができます。これには [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) を利用できます。

## Detecting the detection

明らかに、自分のドメインが検出されたかどうかを知る最良の方法の一つは、**ブラックリスト内で自分のドメインを検索すること**です。リストに載っていれば、何らかの方法でドメインが怪しいと検出されたことになります。\
ドメインがブラックリストに載っているかを簡単に確認する方法の一つは [https://malwareworld.com/](https://malwareworld.com) を使うことです。

しかし、被害者側が **外部で疑わしい phishing 活動を積極的に探しているか** を知る方法は他にもあります。詳しくは次を参照してください：


{{#ref}}
detecting-phising.md
{{#endref}}

非常に似た名前のドメインを購入したり、あなたが管理するドメインのサブドメインに被害者ドメインのキーワードを含む証明書を**発行**したりすることができます。被害者がそれらに対して DNS や HTTP のいかなる操作を行えば、彼らが疑わしいドメインを **積極的に探している** と判断でき、その場合は非常にステルスに行動する必要があります。

### Evaluate the phishing

メールが spam フォルダに入るか、ブロックされるか、成功するかを評価するには [**Phishious**](https://github.com/Rices/Phishious) を使用してください。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

近年の侵入グループは、メール誘導を完全に飛ばして **サービスデスク／identity-recovery ワークフローを直接ターゲットにして MFA を破る**ことが増えています。この攻撃は完全に "living-off-the-land" で、オペレータが有効な資格情報を得ると、組み込みの管理ツールを使ってピボットし、マルウェアは不要です。

### Attack flow
1. 被害者のリコン
* LinkedIn、データ漏洩、public GitHub などから個人情報・企業情報を収集する。
* 価値の高い ID（経営陣、IT、財務など）を特定し、password/MFA reset に関する **正確な help-desk の手順** を列挙する。
2. リアルタイムの social engineering
* help-desk に電話、Teams、チャットなどで被害者になりすまして連絡（多くの場合 **spoofed caller-ID** や **cloned voice** を使用）。
* 事前に収集した PII を提示して知識ベースの検証を通過させる。
* エージェントを説得して **MFA secret をリセット** させるか、登録されている携帯番号で **SIM-swap** を実行させる。
3. 即時のポストアクセスアクション（実際のケースでは ≤60 分）
* いかなる web SSO ポータルでも踏み台を確立する。
* 組み込みツールで AD / AzureAD を列挙（バイナリを落とさない）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* WMI、PsExec、あるいはすでに環境でホワイトリスト化されている正当な RMM エージェントを使ってラテラルムーブメントを実行する。

### Detection & Mitigation
* help-desk の identity recovery を **特権操作** として扱い、step-up auth とマネージャ承認を要求する。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** ルールを導入し、次をアラートする：
* MFA method が変更された＋新しいデバイス／ジオからの認証。
* 同一プリンシパルの即時の昇格（user → admin）。
* help-desk の通話を記録し、リセット前に既に登録済みの番号へ **コールバック** を要求する。
* Just-In-Time (JIT) / Privileged Access を実装し、リセットされたアカウントが自動的に高権限トークンを継承しないようにする。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
多くのクルーは、ハイタッチな作戦のコストを補うために、大量攻撃で **検索エンジン＆広告ネットワークを配信チャネルに変える**。

1. **SEO poisoning / malvertising** により、`chromium-update[.]site` のような偽結果を検索広告の上位に押し上げる。
2. 被害者は小さな **first-stage loader**（多くは JS/HTA/ISO）をダウンロードする。Unit 42 が観測した例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader はブラウザ cookie と credential DB を窃取し、次に **silent loader** を引き込み、リアルタイムで以下を判断して展開する：
* RAT（例：AsyncRAT、RustDesk）
* ransomware / wiper
* persistence コンポーネント（registry Run キー + scheduled task）

### Hardening tips
* 新規登録ドメインをブロックし、検索広告だけでなくメールでも **Advanced DNS / URL Filtering** を適用する。
* ソフトウェアのインストールを署名済み MSI / Store パッケージに制限し、ポリシーで `HTA`、`ISO`、`VBS` の実行を拒否する。
* ブラウザの子プロセスがインストーラを開く挙動を監視する：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader に悪用される LOLBins（例：`regsvr32`、`curl`、`mshta`）をハントする。

---

## AI-Enhanced Phishing Operations
攻撃者は現在、**LLM & voice-clone APIs** を連携させ、完全にパーソナライズされた誘導やリアルタイムの対話を行えるようにしています。

| Layer | Example use by threat actor |
|-------|-----------------------------|
| Automation | ランダム化された文言とトラッキングリンクで >100k のメール/SMS を生成・送信する。 |
| Generative AI | 公開された M&A 情報やソーシャルメディア上の内輪ネタを参照する *一回限り* のメールを生成；コールバック詐欺で CEO の deep-fake 音声を使用。 |
| Agentic AI | ドメインを自律的に登録し、オープンソースのインテリをスクレイプし、被害者がクリックしたが資格情報を送信しなかった場合に次段のメールを自動作成する。 |

**Defence:**
• ARC/DKIM の異常を検出した場合に未信頼の自動化送信を強調する **動的バナー** を追加する。  
• 高リスクの電話要求に対して **voice-biometric challenge phrases** を導入する。  
• awareness プログラムで AI 生成の誘導を継続的にシミュレートする — 静的テンプレートは時代遅れです。

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
クラシックな push-bombing に加え、オペレータは help-desk の通話中に単純に **新しい MFA 登録を強制** してユーザの既存トークンを無効化することがあります。その結果、以降のログインプロンプトは被害者にとって正当なものに見えます。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.
  
AzureAD/AWS/Oktaで、同一IPから数分以内に**`deleteMFA` + `addMFA`**が発生するイベントを監視する。

## Clipboard Hijacking / Pastejacking

Attackers can silently copy malicious commands into the victim’s clipboard from a compromised or typosquatted web page and then trick the user to paste them inside **Win + R**, **Win + X** or a terminal window, executing arbitrary code without any download or attachment.

攻撃者は、compromised や typosquatted な web ページから被害者のクリップボードに悪意あるコマンドを密かにコピーし、ユーザーをだまして**Win + R**、**Win + X**、またはターミナルウィンドウに貼り付けさせ、ダウンロードや添付なしで任意のコードを実行させることができます。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators increasingly gate their phishing flows behind a simple device check so desktop crawlers never reach the final pages. A common pattern is a small script that tests for a touch-capable DOM and posts the result to a server endpoint; non‑mobile clients receive HTTP 500 (or a blank page), while mobile users are served the full flow.

オペレーターは、desktop crawlers が最終ページに到達しないように、単純なデバイスチェックの裏に phishing フローを隠すことが増えています。一般的なパターンは、touch-capable DOM を検出してその結果を server endpoint に送信する小さなスクリプトで、非モバイルクライアントは HTTP 500（または空白ページ）を受け取り、モバイルユーザーにはフルフローが提供されます。

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` のロジック（簡略化）：
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
サーバーでよく観察される挙動:
- 初回ロード時にセッションCookieを設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` のとき、その後の GET に対して 500（またはプレースホルダ）を返す；`true` の場合のみ phishing を配信する。

ハンティングと検出のヒューリスティック:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: `GET /static/detect_device.js` → `POST /detect` → 非モバイルでは HTTP 500；正規のモバイル向けパスは 200 を返し、続く HTML/JS を配信する。
- コンテンツを `ontouchstart` や類似のデバイスチェックのみに基づいて条件分岐しているページはブロックまたは精査する。

対策のヒント:
- モバイル風の fingerprint を持ち、JS を有効にしたクローラーを実行してゲートされたコンテンツを露出させる。
- 新規登録ドメイン上で `POST /detect` に続いて発生する疑わしい 500 レスポンスにアラートを出す。

## 参考資料

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
