# Phishing 手法

{{#include ../../banners/hacktricks-training.md}}

## 方法論

1. 被害者をReconする
1. 選択する **ターゲットドメイン**。
2. 被害者が使用する**ログインポータルを検索する**などの基本的なweb列挙を行い、どのポータルを**偽装**するか**決定**する。
3. いくつかの**OSINT**を使用して**メールアドレスを見つける**。
2. 環境を準備する
1. フィッシング評価で使用する**ドメインを購入する**
2. **メールサービスの関連レコードを設定する** (SPF, DMARC, DKIM, rDNS)
3. VPSを**gophish**で設定する
3. キャンペーンを準備する
1. **メールテンプレート**を準備する
2. 資格情報を盗むための**webページ**を準備する
4. キャンペーンを開始する！

## 類似ドメインを生成するか信頼されたドメインを購入する

### ドメイン名の変形手法

- **キーワード**: ドメイン名が元のドメインの重要な**キーワードを含む** (例: zelster.com-management.com).
- **ハイフン化されたサブドメイン**: サブドメインの**ドットをハイフンに変更する** (例: www-zelster.com).
- **新しいTLD**: 同じドメインで**新しいTLDを使用する** (例: zelster.org)
- **Homoglyph**: ドメイン名の文字を**似た見た目の別の文字に置き換える** (例: zelfser.com).


{{#ref}}
homograph-attacks.md
{{#endref}}
- **Transposition:** ドメイン名内の2文字を**入れ替える** (例: zelsetr.com).
- **Singularization/Pluralization**: ドメイン名の末尾に「s」を**追加または削除する** (例: zeltsers.com).
- **Omission**: ドメイン名から1文字を**削除する** (例: zelser.com).
- **Repetition:** ドメイン名の文字を1つ**繰り返す** (例: zeltsser.com).
- **Replacement**: Homoglyphに似るが目立ちやすい。ドメイン名の文字を置き換える（例えば、キーボード上で元の文字に近い文字にする）（例: zektser.com）。
- **Subdomained**: ドメイン名の中に**ドットを挿入する** (例: ze.lster.com).
- **Insertion**: ドメイン名に文字を**挿入する** (例: zerltser.com).
- **Missing dot**: ドメイン名にTLDを付加する (例: zelstercom.com)

**自動ツール**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Websites**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

太陽フレア、宇宙線、ハードウェアエラーなどの要因により、保存中または通信中のビットの一部が**自動的に反転する可能性がある**。

この概念が**DNSリクエストに適用される**と、**DNSサーバーが受け取るドメイン**が最初に要求したドメインと異なる可能性がある。

例えば、ドメイン "windows.com" の1ビットの変更で "windnws.com" に変わることがある。

攻撃者は**これを利用して、被害者ドメインに類似した複数のビット反転ドメインを登録する**場合がある。意図は正規のユーザーを自分たちのインフラへリダイレクトすることだ。

For more information read [https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

### 信頼できるドメインを購入する

使用できる期限切れドメインは [https://www.expireddomains.net/](https://www.expireddomains.net) で検索できます。\
購入予定の期限切れドメインが**既に良好なSEOを持っている**かを確認するには、以下のサイトでカテゴリを確認するとよい。

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100% 無料)
- [https://phonebook.cz/](https://phonebook.cz) (100% 無料)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

さらに多くの有効なメールアドレスを**発見する**か、既に見つけたものを**検証する**ために、被害者のSMTPサーバーに対してブルートフォースできるか確認できます。 [Learn how to verify/discover email address here](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration).\
また、ユーザーが**任意のウェブポータルでメールにアクセスしている**場合、そのポータルが**username brute force**に脆弱でないか確認し、可能であれば脆弱性を悪用してください。

## GoPhish の設定

### インストール

以下からダウンロードできます: [https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)

`/opt/gophish` の中にダウンロードして展開し、`/opt/gophish/gophish` を実行してください。\
実行時の出力に、ポート3333のadminユーザー用のパスワードが表示されます。したがって、そのポートにアクセスしてその資格情報を使いadminパスワードを変更してください。ローカルにそのポートをトンネルする必要があるかもしれません:
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS certificate configuration**

この手順に進む前に、使用する**already bought the domain**を既に購入しておく必要があり、またそれがあなたが**gophish**を設定している**IP of the VPS**を指すように**pointing**されている必要があります。
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

次に、以下のファイルにドメインを追加してください：

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf 内の以下の変数の値も変更してください**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に **`/etc/hostname`** と **`/etc/mailname`** をドメイン名に変更し、**VPSを再起動してください。**

次に、`mail.<domain>` の **DNS A record** を作成し、VPSの **ip address** を指すようにし、`mail.<domain>` を指す **DNS MX** レコードも作成してください。

では、メール送信をテストします：
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophish の設定**

gophish の実行を停止して、設定を行います。\\
`/opt/gophish/config.json` を以下のように変更します（https の使用に注意）:
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
サービスの設定を完了し、以下の手順で動作確認を行います:
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

ドメインが古いほどスパムとして検出される可能性は低くなります。したがって、phishing assessment の前にできるだけ長く（最低でも1週間）待つべきです。さらに、reputational sector に関するページを設置すると得られる評判は良くなります。

たとえ1週間待つ必要があっても、今すぐすべての設定を完了しておくことは可能です。

### Configure Reverse DNS (rDNS) record

VPS の IP アドレスをドメイン名に解決する rDNS (PTR) レコードを設定してください。

### Sender Policy Framework (SPF) Record

新しいドメインに対して **SPF レコードを設定する** 必要があります。SPF レコードが何か分からない場合は [**このページを読む**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

SPF ポリシーを生成するには [https://www.spfwizard.net/](https://www.spfwizard.net) を使用できます（VPS マシンの IP を使用してください）

![](<../../images/image (1037).png>)

以下はドメイン内の TXT record に設定する内容です:
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### Domain-based Message Authentication, Reporting & Conformance (DMARC) レコード

新しいドメインに対して**DMARC レコードを設定する必要があります**。DMARC レコードが何か分からない場合は [**read this page**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc) を参照してください。

ホスト名 `_dmarc.<domain>` を指す新しい DNS TXT record を作成し、以下の内容にしてください:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインに対して**DKIMを設定する必要があります**。DMARCレコードが何か分からない場合は[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

This tutorial is based on: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)

> [!TIP]
> DKIMキーが生成する両方のB64値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

これには [https://www.mail-tester.com/](https://www.mail-tester.com/)\
ページにアクセスし、表示されるアドレスにメールを送ってください:
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
また、`check-auth@verifier.port25.com` にメールを送信して、**メール設定を確認する**と**応答を読む**こともできます（このためには **open** port **25** が必要で、rootとしてメールを送信した場合はファイル _/var/mail/root_ で応答を確認してください）。\
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
**自分が管理するGmailへのメッセージ**を送信し、Gmailの受信トレイで**メールのヘッダ**を確認してください。`dkim=pass` は `Authentication-Results` ヘッダフィールドに存在しているはずです。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### Spamhouse Blacklist からの削除

The page [www.mail-tester.com](https://www.mail-tester.com) can indicate you if you your domain is being blocked by spamhouse. You can request your domain/IP to be removed at: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklist からの削除

​​You can request your domain/IP to be removed at [https://sender.office.com/](https://sender.office.com).

## GoPhish キャンペーンの作成と開始

### Sending Profile

- 送信プロファイルを識別するための **識別用の名前** を設定する
- どのアカウントからフィッシングメールを送るか決める。提案: _noreply, support, servicedesk, salesforce..._
- ユーザー名とパスワードは空欄にしても構いませんが、必ず Ignore Certificate Errors をチェックすること

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> 機能が正しく動作しているか確認するには、"**Send Test Email**" 機能を使うことを推奨します。\
> テストでブラックリストに登録されるのを避けるため、**テスト用メールを 10min mails のアドレス宛に送る**ことをおすすめします。

### Email Template

- テンプレートを識別するための **識別用の名前** を設定する
- 次に **件名** を書く（不自然なものではなく、通常のメールであり得る内容にする）
- 必ず **Add Tracking Image** にチェックを入れること
- **メールテンプレート** を作成する（以下の例のように変数を使用できます）:
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
Note that **メールの信頼性を高めるために**、クライアントの実際のメールの署名を利用することを推奨します。提案:

- **存在しないアドレス**にメールを送り、返信に署名が含まれているか確認する。
- info@ex.com や press@ex.com、public@ex.com のような **公開メールアドレス** を探してメールを送り、返信を待つ。
- **見つかった有効な**メールアドレスに連絡して、返信を待つ。

![](<../../images/image (80).png>)

> [!TIP]
> Email Templateでは**送付するファイルを添付**することもできます。特別に作成したファイル/ドキュメントを使ってNTLMチャレンジを盗みたい場合は[このページを読む](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### Landing Page

- **名前** を記入する
- ウェブページの**HTMLコードを書く**。ウェブページを**import**できる点に注意。
- **Capture Submitted Data** と **Capture Passwords** をマークする
- **リダイレクト** を設定する

![](<../../images/image (826).png>)

> [!TIP]
> 通常はページのHTMLコードを修正し、ローカル（場合によってはApacheサーバを使用）でテストを繰り返して**満足のいく結果になるまで**調整する必要があります。その後、そのHTMLコードをボックスに記入してください。\
> HTMLで**静的リソースを使用する**必要がある場合（CSSやJSファイルなど）、それらを_**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ から参照できます。

> [!TIP]
> リダイレクトでは、被害者の正規のメインページへ**ユーザーをリダイレクト**するか、例えば _/static/migration.html_ にリダイレクトして、5秒間**スピニングホイール（**[**https://loading.io/**](https://loading.io)**）**を表示してから処理が成功したと伝える、などが使えます。

### Users & Groups

- 名前を設定する
- **データをインポート**する（テンプレートを例で使うには各ユーザーの firstname、last name、email address が必要です）

![](<../../images/image (163).png>)

### Campaign

最後に、名前、email template、landing page、URL、sending profile、group を選んでキャンペーンを作成します。URL は被害者に送られるリンクになります。

Sending Profile によりテストメールを送って、最終的なフィッシングメールの見た目を確認できます:

![](<../../images/image (192).png>)

> [!TIP]
> テストではブラックリスト入りを避けるために 10min mails のアドレスに送ることをおすすめします。

すべて準備ができたら、キャンペーンを開始してください！

## Website Cloning

Webサイトをクローンしたい場合は次のページを確認してください：


{{#ref}}
clone-a-website.md
{{#endref}}

## Backdoored Documents & Files

一部のフィッシング評価（主に Red Teams）では、**backdoor を含むファイルを送る**ことがあります（C2 や認証をトリガーするものなど）。\
例については次のページを確認してください：


{{#ref}}
phishing-documents.md
{{#endref}}

## Phishing MFA

### Via Proxy MitM

前述の攻撃は巧妙で、実際のウェブサイトを偽装してユーザが入力した情報を収集します。残念ながら、ユーザが正しいパスワードを入力しなかった場合や、偽装したアプリケーションが 2FA で保護されている場合、**この情報だけでは被害者になりすますことはできません**。

ここで [**evilginx2**](https://github.com/kgretzky/evilginx2)、[**CredSniper**](https://github.com/ustayready/CredSniper) や [**muraena**](https://github.com/muraenateam/muraena) のようなツールが有用になります。これらのツールは MitM 型の攻撃を実現します。基本的な攻撃の流れは次の通りです:

1. あなたは実際のウェブページの**login フォームを偽装**する。
2. ユーザは偽ページに**credentials**を送信し、ツールはそれを実際のウェブページに転送して、**credentials が有効か確認する**。
3. アカウントが**2FA**で保護されている場合、MitM ページはそれを要求し、**ユーザが入力すると**ツールがそれを実ページへ送信する。
4. ユーザが認証されると、攻撃者であるあなたは MitM 中に行われたすべてのやり取りから**credentials、2FA、cookie、およびあらゆる情報を捕捉**することになる。

### Via VNC

被害者を元のページに似せた悪意あるページに誘導する代わりに、実際のウェブページに接続されたブラウザを備えたVNCセッションに誘導したらどうでしょうか？そうすれば被害者の操作を直接見て、パスワード、使用された MFA、cookie などを盗むことができます。\
これは [**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) で実行できます。

## Detecting the detection

明らかに、バレているかどうかを知る最良の方法の一つは、**自分のドメインがブラックリストに登録されているか検索する**ことです。リストに載っていれば、何らかの方法であなたのドメインが疑わしいと検知されたということです。\
ドメインがブラックリストに載っているか簡単に確認する方法の一つは [https://malwareworld.com/](https://malwareworld.com) を使うことです。

しかし、被害者が実際に**疑わしいフィッシング活動を積極的に探しているか**を知る別の方法もあります。詳しくは次を参照してください：


{{#ref}}
detecting-phising.md
{{#endref}}

被害者のドメインに非常に似た名前のドメインを**購入**したり、あなたが管理するドメインの**サブドメイン**に被害者ドメインの**キーワード**を含む証明書を**発行**したりできます。もし**被害者**がそれらと何らかの**DNS または HTTP のやり取り**を行えば、彼が**積極的に疑わしいドメインを探している**ことが分かり、よりステルスに行動する必要があります。

### Evaluate the phishing

[**Phishious**](https://github.com/Rices/Phishious) を使って、あなたのメールがスパムフォルダに入るか、ブロックされるか、あるいは成功するかを評価してください。

## High-Touch Identity Compromise (Help-Desk MFA Reset)

近年の侵入者はメール誘導を完全に省き、MFA を回避するために **直接 service-desk / identity-recovery ワークフローを狙う**ことが増えています。攻撃は完全に "living-off-the-land" で、オペレータが有効な資格情報を得ると組み込みの管理ツールで横展開し、マルウェアは不要です。

### Attack flow
1. 被害者の偵察
* LinkedIn、データブリーチ、公開 GitHub 等から個人および企業情報を収集する。
* 価値の高いアカウント（経営陣、IT、財務など）を特定し、パスワード / MFA リセットのための**正確な help-desk プロセス**を列挙する。
2. リアルタイムのソーシャルエンジニアリング
* 対象になりすまして電話、Teams、チャットで help-desk に連絡する（多くの場合 **spoofed caller-ID** や **cloned voice** を使用）。
* 事前に収集した PII を提供してナレッジベースの認証を通過する。
* エージェントを説得して **MFA secret をリセット**させるか、登録済みの携帯番号で **SIM-swap** を実行させる。
3. 即時のポストアクセス行動（実際のケースでは ≤60 分）
* 任意の web SSO ポータルを通じて足場を確立する。
* 組み込みツールで AD / AzureAD を列挙する（バイナリをドロップしない）:
```powershell
# list directory groups & privileged roles
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – list directory roles
Get-MgDirectoryRole | ft DisplayName,Id

# Enumerate devices the account can login to
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* **WMI**, **PsExec**, または環境内で既にホワイトリスト化されている正当な **RMM** エージェントを使って横展開する。
4. 検出と緩和
* help-desk の identity recovery を **特権操作** と見なし、step-up 認証とマネージャ承認を要求する。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** ルールを導入して以下をアラートする:
  * MFA 方法が変更され + 新しいデバイス/ジオからの認証。
  * 同一プリンシパルの即時昇格（user → admin）。
* help-desk の通話を記録し、リセット前に **既に登録された番号へのコールバック** を義務付ける。
* **Just-In-Time (JIT) / Privileged Access** を実装し、リセットされたアカウントが自動的に高権限トークンを継承しないようにする。

---

## At-Scale Deception – SEO Poisoning & “ClickFix” Campaigns
コモディティ化したグループは、高タッチな攻撃のコストを大量攻撃で相殺し、**検索エンジンや広告ネットワークを配信チャネルに変える**。

1. **SEO poisoning / malvertising** により `chromium-update[.]site` のような偽の結果を検索広告の上位に押し上げる。
2. 被害者は小さな **first-stage loader** をダウンロードする（多くは JS/HTA/ISO）。Unit 42 が確認した例:
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. ローダーはブラウザの cookie と credential DB を窃取し、その後 **silent loader** を取得して、リアルタイムで展開を判断する:
* RAT（例: AsyncRAT, RustDesk）
* ransomware / wiper
* 永続化コンポーネント（レジストリの Run キー + scheduled task）

### Hardening tips
* 新規登録ドメインをブロックし、検索広告だけでなくメールに対しても **Advanced DNS / URL Filtering** を強制する。
* ソフトウェアのインストールを署名された MSI / Store パッケージに制限し、`HTA`、`ISO`、`VBS` の実行をポリシーで拒否する。
* ブラウザの子プロセスがインストーラを起動しているか監視する:
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* first-stage loader に頻繁に悪用される LOLBins（例: `regsvr32`, `curl`, `mshta`）をハントする。

---

## AI-Enhanced Phishing Operations
攻撃者は現在、LLM と voice-clone API を連携させ、完全にパーソナライズされた誘いとリアルタイムの相互作用を行っています。

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|Generate & send >100 k emails / SMS with randomised wording & tracking links.|
|Generative AI|Produce *one-off* emails referencing public M&A, inside jokes from social media; deep-fake CEO voice in callback scam.|
|Agentic AI|Autonomously register domains, scrape open-source intel, craft next-stage mails when a victim clicks but doesn’t submit creds.|

**Defence:**
• ARC/DKIM の異常を利用して信頼されていない自動化から送られたメッセージを強調表示する**動的バナー**を追加する。  
• 高リスクの電話要求に対しては**音声生体認証のチャレンジフレーズ**を導入する。  
• 意識向上プログラムで AI 生成の誘いを継続的にシミュレートする — 静的テンプレートは時代遅れです。

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
古典的な push-bombing に加えて、オペレータは単に help-desk コール中に **新しい MFA 登録を強制**し、ユーザの既存トークンを無効にします。以降のログインプロンプトは被害者にとって正当なものに見えます。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Okta のイベントで **`deleteMFA` + `addMFA`** が **同一IPから数分以内に** 発生するものを監視してください。



## Clipboard Hijacking / Pastejacking

攻撃者は、侵害されたまたはタイポスクワットされたウェブページから被害者のクリップボードに悪意あるコマンドを静かにコピーし、その後ユーザーを騙して **Win + R**, **Win + X** やターミナルウィンドウに貼り付けさせ、ダウンロードや添付ファイルなしで任意のコードを実行させることができます。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### Mobile‑gated phishing to evade crawlers/sandboxes
運営者はフィッシングのフローをシンプルなデバイスチェックの背後に置くことが増えており、デスクトップのクローラーが最終ページに到達しないようにしています。一般的なパターンは、タッチ対応のDOMをテストしてその結果をサーバーエンドポイントにPOSTする小さなスクリプトで、非モバイルクライアントにはHTTP 500（または空白ページ）を返し、モバイルユーザーにはフルフローを提供します。

Minimal client snippet (typical logic):
```html
<script src="/static/detect_device.js"></script>
```
`detect_device.js` のロジック（簡略化）:
```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
.then(()=>location.reload());
```
サーバの挙動（よく観察されるもの）:
- 最初のロード時にsession cookieを設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` の場合、以降の GET に 500（またはプレースホルダ）を返す。`true` の場合のみフィッシングを表示する。

ハンティングと検出のヒューリスティック:
- urlscan クエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: シーケンス `GET /static/detect_device.js` → `POST /detect` → 非モバイルでは HTTP 500；正当なモバイル被害者パスは 200 を返し、その後の HTML/JS を返す。
- コンテンツを `ontouchstart` のようなデバイスチェックのみに基づいて表示しているページはブロックするか精査する。

防御のヒント:
- モバイルに似たフィンガープリントとJSを有効にしたクローラを実行して、ゲートされたコンテンツを検出する。
- 新規登録ドメインで `POST /detect` に続いて発生する疑わしい 500 レスポンスについてアラートを出す。

## 参考文献

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [Silent Smishing – mobile-gated phishing infra and heuristics (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)

{{#include ../../banners/hacktricks-training.md}}
