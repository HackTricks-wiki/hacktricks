# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## 方法論

1. Reconでターゲットを調査する
1. **ターゲットドメイン**を選択する。
2. ターゲットが使用するログインポータルを基本的に列挙して**どれを偽装するか決める**。
3. 一部の**OSINT**を利用して**メールを見つける**。
2. 環境を準備する
1. **phishing評価で使用するドメインを購入する**
2. **メールサービスに関するレコード**を設定する（SPF, DMARC, DKIM, rDNS）
3. VPSに**gophish**をセットアップする
3. キャンペーンを準備する
1. **メールテンプレート**を準備する
2. 認証情報を盗むための**ウェブページ**を準備する
4. キャンペーンを開始！

## 類似ドメインを生成するか信頼されたドメインを購入する

### ドメイン名バリエーション手法

- **Keyword**: ドメイン名が元のドメインの重要な**キーワード**を含む（例: zelster.com-management.com）。
- **hypened subdomain**: サブドメインのドットをハイフンに変更する（例: www-zelster.com）。
- **New TLD**: 同じドメインで**新しいTLD**を使用する（例: zelster.org）
- **Homoglyph**: ドメイン名の文字を**類似して見える文字**に置き換える（例: zelfser.com）。

{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** ドメイン名内で2つの文字を**入れ替える**（例: zelsetr.com）。
- **Singularization/Pluralization**: ドメイン名の末尾に “s” を追加または削除する（例: zeltsers.com）。
- **Omission**: ドメイン名の文字を**1つ削除する**（例: zelser.com）。
- **Repetition:** ドメイン名の文字を**繰り返す**（例: zeltsser.com）。
- **Replacement**: homoglyphに似ているが目立ちやすい。キーボード上で元の文字に近い文字に置き換える（例: zektser.com）。
- **Subdomained**: ドメイン名の内部に**ドットを挿入する**（例: ze.lster.com）。
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

保存中または通信中のビットが、太陽フレア、宇宙線、ハードウェアのエラーなどの要因で自動的に反転する可能性があります。

この概念を**DNSリクエストに適用すると**、DNSサーバーが受け取ったドメインが最初に要求したドメインと同じでない可能性があります。

例えば、ドメイン "windows.com" の1ビットが変更されると "windnws.com" に変わることがあります。

攻撃者はこの特性を利用して、被害者のドメインに似た複数のbit-flippingドメインを登録し、正当なユーザーを自分たちのインフラへリダイレクトさせることがあります。

詳細は次を参照してください: [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 信頼されたドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net) で利用可能な期限切れドメインを検索できます。\
購入する期限切れドメインが**既に良好なSEOを持っているか**を確認するには、次のようなカテゴリ分類を確認できます:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 無料)
- [https://phonebook.cz/](https://phonebook.cz) (100% 無料)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

さらに多くの有効なメールアドレスを**発見**したり、既に発見したものを**検証**するために、対象のSMTPサーバーに対してブルートフォースを試みることができます。検証/発見の方法はこちらを参照してください: [../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration]。\
また、ユーザーがメールにアクセスするために**任意のweb portal**を使用している場合、そのポータルが**username brute force**に対して脆弱かどうかを確認し、可能ならその脆弱性を悪用することを忘れないでください。

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

ダウンロードして `/opt/gophish` に展開し、`/opt/gophish/gophish` を実行する\
出力にadminユーザーのパスワードが表示されます（ポート3333）。そのため、そのポートにアクセスして表示された資格情報で管理者パスワードを変更してください。ローカルにトンネルする必要があるかもしれません:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS 証明書の設定**

この手順の前に、使用するドメインを**すでに購入している**必要があり、**gophish**を設定している**VPS の IP**を**指している**必要があります。
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

次に、ドメインを以下のファイルに追加します:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf 内の次の変数の値も変更してください**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に **`/etc/hostname`** と **`/etc/mailname`** をドメイン名に変更し、**VPSを再起動してください。**

次に、`mail.<domain>` の **DNS A record** を VPS の **ip address** を指すように作成し、`mail.<domain>` を指す **DNS MX** レコードを作成してください。

では、メール送信のテストを行います:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish 設定**

gophishの実行を停止して、設定を行います。\
`/opt/gophish/config.json` を次のように変更します（https の使用に注意）:
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

gophish サービスを自動起動およびサービスとして管理できるようにするには、次の内容で `/etc/init.d/gophish` ファイルを作成します:
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
サービスの設定を完了し、次の点を確認してください:
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

ドメインが古ければ古いほど、スパムとして検出される可能性は低くなります。可能な限り長く待つべきです（少なくとも1週間）。また、信頼性に関するページを設けると、得られる評価は向上します。

ただし、1週間待つ必要があっても、設定作業自体は今すぐ完了させて構いません。

### Configure Reverse DNS (rDNS) record

rDNS (PTR) レコードを設定し、VPS の IP アドレスがドメイン名に解決されるようにしてください。

### Sender Policy Framework (SPF) Record

新しいドメインに対して **SPF レコードを設定する必要があります**。SPF レコードが何か分からない場合は [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf) を参照してください。

https://www.spfwizard.net/ を使って SPF ポリシーを生成できます（VPS の IP を使用してください）

![](<../../images/image (1037).png>)

これはドメインの TXT レコード内に設定すべき内容です：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) Record

新しいドメインに対して**DMARC レコードを構成する必要があります**。DMARC レコードが何か分からない場合は[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

hostname `_dmarc.<domain>` を指す新しい DNS TXT レコードを次の内容で作成してください:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

You must **DKIM を新しいドメインに設定する必要があります**。DMARC レコードが何か分からない場合は [**このページをお読みください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM キーが生成する 2 つの B64 値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

You can do that using [https://www.mail-tester.com/](https://www.mail-tester.com/)\  
ページにアクセスし、表示されるアドレスにメールを送ってください：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
また、`check-auth@verifier.port25.com` にメールを送信して、**メール設定を確認**し、応答を**読む**こともできます（このためには、**open** port **25** を開放し、rootとしてメールを送信した場合はファイル _/var/mail/root_ で応答を確認する必要があります）。\\
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
**自分で管理しているGmailへのメッセージ**を送信し、Gmailの受信トレイで**メールのヘッダー**を確認すると、`Authentication-Results` ヘッダーに `dkim=pass` が含まれているはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Blacklistからの削除

ページ [www.mail-tester.com](https://www.mail-tester.com) は、あなたのドメインがspamhouseにブロックされているかどうかを示してくれます。ドメイン/IPを削除するには次でリクエストしてください: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklistからの削除

​​ドメイン/IPの削除は [https://sender.office.com/](https://sender.office.com) でリクエストできます。

## GoPhishキャンペーンの作成と開始

### Sending Profile

- 送信プロファイルを識別するための**名前を設定**する
- どのアカウントからフィッシングメールを送るか決める。提案: _noreply, support, servicedesk, salesforce..._
- usernameとpasswordは空のままにしてもよいですが、必ず Ignore Certificate Errors にチェックを入れてください

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 動作確認のために "**Send Test Email**" 機能を使うことを推奨します。\
> テストでブラックリスト入りするのを避けるために、**テストメールは 10min mail のアドレスに送る**ことをおすすめします。

### Email Template

- テンプレートを識別するための**名前を設定**する
- 次に**subject**を書く（不自然なものではなく、通常のメールで読めそうな内容にする）
- 必ず "**Add Tracking Image**" にチェックが入っていることを確認する
- **email template** を作成する（以下の例のように変数を使うことができます）:
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

- Send an email to a **non existent address** and check if the response has any signature.
- Search for **public emails** like info@ex.com or press@ex.com or public@ex.com and send them an email and wait for the response.
- Try to contact **some valid discovered** email and wait for the response

![](<../../images/image (80).png>)

> [!TIP]
> The Email Template also allows to **attach files to send**. If you would also like to steal NTLM challenges using some specially crafted files/documents [read this page](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md).

### Landing Page

- Write a **name**
- **Write the HTML code** of the web page. Note that you can **import** web pages.
- Mark **Capture Submitted Data** and **Capture Passwords**
- Set a **redirection**

![](<../../images/image (826).png>)

> [!TIP]
> Usually you will need to modify the HTML code of the page and make some tests in local (maybe using some Apache server) **until you like the results.** Then, write that HTML code in the box.\
> Note that if you need to **use some static resources** for the HTML (maybe some CSS and JS pages) you can save them in _**/opt/gophish/static/endpoint**_ and then access them from _**/static/\<filename>**_

> [!TIP]
> For the redirection you could **redirect the users to the legit main web page** of the victim, or redirect them to _/static/migration.html_ for example, put some **spinning wheel (**[**https://loading.io/**](https://loading.io)**) for 5 seconds and then indicate that the process was successful**.

### Users & Groups

- Set a name
- **Import the data** (note that in order to use the template for the example you need the firstname, last name and email address of each user)

![](<../../images/image (163).png>)

### Campaign

Finally, create a campaign selecting a name, the email template, the landing page, the URL, the sending profile and the group. Note that the URL will be the link sent to the victims

Note that the **Sending Profile allow to send a test email to see how will the final phishing email looks like**:

![](<../../images/image (192).png>)

> [!TIP]
> I would recommend to **send the test emails to 10min mails addresses** in order to avoid getting blacklisted making tests.

Once everything is ready, just launch the campaign!

## Website Cloning

If for any reason you want to clone the website check the following page:


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

In some phishing assessments (mainly for Red Teams) you will want to also **send files containing some kind of backdoor** (maybe a C2 or maybe just something that will trigger an authentication).\
Check out the following page for some examples:


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

The previous attack is pretty clever as you are faking a real website and gathering the information set by the user. Unfortunately, if the user didn't put the correct password or if the application you faked is configured with 2FA, **this information won't allow you to impersonate the tricked user**.

This is where tools like [**evilginx2**](https://github.com/kgretzky/evilginx2)**,** [**CredSniper**](https://github.com/ustayready/CredSniper) and [**muraena**](https://github.com/muraenateam/muraena) are useful. This tool will allow you to generate a MitM like attack. Basically, the attacks works in the following way:

1. You **impersonate the login** form of the real webpage.
2. The user **send** his **credentials** to your fake page and the tool send those to the real webpage, **checking if the credentials work**.
3. If the account is configured with **2FA**, the MitM page will ask for it and once the **user introduces** it the tool will send it to the real web page.
4. Once the user is authenticated you (as attacker) will have **captured the credentials, the 2FA, the cookie and any information** of every interaction your while the tool is performing a MitM.

### Via VNC

What if instead of **sending the victim to a malicious page** with the same looks as the original one, you send him to a **VNC session with a browser connected to the real web page**? You will be able to see what he does, steal the password, the MFA used, the cookies...\
You can do this with [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)

## Detecting the detection

Obviously one of the best ways to know if you have been busted is to **search your domain inside blacklists**. If it appears listed, somehow your domain was detected as suspicions.\
One easy way to check if you domain appears in any blacklist is to use [https://malwareworld.com/](https://malwareworld.com)

However, there are other ways to know if the victim is **actively looking for suspicions phishing activity in the wild** as explained in:


{{#ref}}
detecting-phising.md
{{#endref}}

You can **buy a domain with a very similar name** to the victims domain **and/or generate a certificate** for a **subdomain** of a domain controlled by you **containing** the **keyword** of the victim's domain. If the **victim** perform any kind of **DNS or HTTP interaction** with them, you will know that **he is actively looking** for suspicious domains and you will need to be very stealth.

### Evaluate the phishing

Use [**Phishious** ](https://github.com/Rices/Phishious)to evaluate if your email is going to end in the spam folder or if it's going to be blocked or successful.

## High-Touch Identity Compromise (Help-Desk MFA Reset)

Modern intrusion sets increasingly skip email lures entirely and **directly target the service-desk / identity-recovery workflow** to defeat MFA.  The attack is fully "living-off-the-land": once the operator owns valid credentials they pivot with built-in admin tooling – no malware is required.

### Attack flow
1. Recon the victim
* Harvest personal & corporate details from LinkedIn, data breaches, public GitHub, etc.
* Identify high-value identities (executives, IT, finance) and enumerate the **exact help-desk process** for password / MFA reset.
2. Real-time social engineering
* Phone, Teams or chat the help-desk while impersonating the target (often with **spoofed caller-ID** or **cloned voice**).
* Provide the previously-collected PII to pass knowledge-based verification.
* Convince the agent to **reset the MFA secret** or perform a **SIM-swap** on a registered mobile number.
3. Immediate post-access actions (≤60 min in real cases)
* Establish a foothold through any web SSO portal.
* Enumerate AD / AzureAD with built-ins (no binaries dropped):
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* Lateral movement with **WMI**, **PsExec**, or legitimate **RMM** agents already whitelisted in the environment.

### Detection & Mitigation
* Treat help-desk identity recovery as a **privileged operation** – require step-up auth & manager approval.
* Deploy **Identity Threat Detection & Response (ITDR)** / **UEBA** rules that alert on:
* MFA method changed + authentication from new device / geo.
* Immediate elevation of the same principal (user-→-admin).
* Record help-desk calls and enforce a **call-back to an already-registered number** before any reset.
* Implement **Just-In-Time (JIT) / Privileged Access** so newly reset accounts do **not** automatically inherit high-privilege tokens.

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
Commodity crews offset the cost of high-touch ops with mass attacks that turn **search engines & ad networks into the delivery channel**.

1. **SEO poisoning / malvertising** pushes a fake result such as `chromium-update[.]site` to the top search ads.
2. Victim downloads a small **first-stage loader** (often JS/HTA/ISO).  Examples seen by Unit 42:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader exfiltrates browser cookies + credential DBs, then pulls a **silent loader** which decides – *in realtime* – whether to deploy:
* RAT (e.g. AsyncRAT, RustDesk)
* ransomware / wiper
* persistence component (registry Run key + scheduled task)

### Hardening tips
* Block newly-registered domains & enforce **Advanced DNS / URL Filtering** on *search-ads* as well as e-mail.
* Restrict software installation to signed MSI / Store packages, deny `HTA`, `ISO`, `VBS` execution by policy.
* Monitor for child processes of browsers opening installers:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* Hunt for LOLBins frequently abused by first-stage loaders (e.g. `regsvr32`, `curl`, `mshta`).

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

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
Besides classic push-bombing, operators simply **force a new MFA registration** during the help-desk call, nullifying the user’s existing token.  Any subsequent login prompt appears legitimate to the victim.
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
Monitor for AzureAD/AWS/Okta events where **`deleteMFA` + `addMFA`** occur **within minutes from the same IP**.

## Clipboard Hijacking / Pastejacking

攻撃者は、侵害されたまたは typosquatted なウェブページから被害者のクリップボードに悪意あるコマンドを静かにコピーし、ユーザーを騙して **Win + R**, **Win + X** またはターミナルウィンドウに貼り付けさせることで、ダウンロードや添付ファイルなしに任意のコードを実行させることができる。

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
オペレーターは、デスクトップのクローラーが最終ページに到達しないよう、フィッシングフローを簡単なデバイスチェックの背後に置くことが増えている。一般的なパターンは、タッチ対応の DOM をテストしてその結果をサーバーエンドポイントにポストする小さなスクリプトで、非モバイルクライアントには HTTP 500（または空白ページ）が返され、モバイルユーザーには完全なフローが提供される。

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` のロジック (簡略化):
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
よく観察されるサーバー挙動:
- 初回読み込み時にセッションクッキーを設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` の場合、以降の GET に対して 500（またはプレースホルダ）を返す。`true` の場合にのみフィッシングを配信する。

ハンティングと検出のヒューリスティクス:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: `GET /static/detect_device.js` → `POST /detect` → 非モバイルに対して HTTP 500; 正常なモバイル被害者パスは 200 を返し、その後の HTML/JS を返す。
- コンテンツを `ontouchstart` や類似のデバイスチェックのみに依存して条件分岐しているページはブロックするか精査する。

対策のヒント:
- モバイルライクなフィンガープリントを持ち、JS を有効にしたクローラーを実行して、ゲートされたコンテンツを露出させる。
- 新規登録ドメイン上で `POST /detect` に続く不審な 500 応答を検知してアラートする。

## 参考資料

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
