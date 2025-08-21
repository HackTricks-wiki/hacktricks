# フィッシング手法

{{#include ../../banners/hacktricks-training.md}}

## 手法

1. 被害者の調査
1. **被害者のドメイン**を選択します。
2. 被害者が使用している**ログインポータル**を探すために基本的なウェブ列挙を行い、**なりすます**ポータルを**決定**します。
3. **OSINT**を使用して**メールアドレス**を**見つけます**。
2. 環境の準備
1. フィッシング評価に使用する**ドメインを購入**します。
2. **メールサービス**に関連するレコード（SPF、DMARC、DKIM、rDNS）を**設定**します。
3. **gophish**でVPSを設定します。
3. キャンペーンの準備
1. **メールテンプレート**を準備します。
2. 認証情報を盗むための**ウェブページ**を準備します。
4. キャンペーンを開始！

## 類似のドメイン名を生成するか、信頼できるドメインを購入する

### ドメイン名のバリエーション技術

- **キーワード**: ドメイン名は元のドメインの重要な**キーワード**を**含みます**（例: zelster.com-management.com）。
- **ハイフン付きサブドメイン**: サブドメインの**ドットをハイフンに変更**します（例: www-zelster.com）。
- **新しいTLD**: 同じドメインを使用して**新しいTLD**を使用します（例: zelster.org）。
- **ホモグリフ**: ドメイン名の文字を**似た文字に置き換えます**（例: zelfser.com）。

{{#ref}}
homograph-attacks.md
{{#endref}}
- **転置**: ドメイン名内の**2つの文字を入れ替えます**（例: zelsetr.com）。
- **単数化/複数化**: ドメイン名の末尾に「s」を追加または削除します（例: zeltsers.com）。
- **省略**: ドメイン名から**1つの文字を削除します**（例: zelser.com）。
- **繰り返し**: ドメイン名内の**1つの文字を繰り返します**（例: zeltsser.com）。
- **置換**: ホモグリフのようですが、あまり目立ちません。ドメイン名の1つの文字を、元の文字の近くにある文字に置き換えます（例: zektser.com）。
- **サブドメイン化**: ドメイン名内に**ドットを挿入します**（例: ze.lster.com）。
- **挿入**: ドメイン名に**文字を挿入します**（例: zerltser.com）。
- **ドットの欠落**: ドメイン名にTLDを追加します（例: zelstercom.com）。

**自動ツール**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**ウェブサイト**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### ビットフリッピング

いくつかのビットが保存または通信中に**自動的に反転する可能性があります**。これは、太陽フレア、宇宙線、またはハードウェアエラーなどのさまざまな要因によるものです。

この概念が**DNSリクエストに適用されると**、**DNSサーバーによって受信されたドメイン**が、最初にリクエストされたドメインと同じでない可能性があります。

例えば、ドメイン「windows.com」の1ビットの変更により、「windnws.com」に変わることがあります。

攻撃者は、被害者のドメインに似た複数のビットフリッピングドメインを**登録することでこれを利用する**かもしれません。彼らの意図は、正当なユーザーを自分たちのインフラにリダイレクトすることです。

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)をお読みください。

### 信頼できるドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net)で使用できる期限切れのドメインを検索できます。\
購入する期限切れのドメインが**すでに良好なSEOを持っていることを確認するために**、以下のサイトでそのカテゴリを検索できます：

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100%無料)
- [https://phonebook.cz/](https://phonebook.cz) (100%無料)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

**さらに多くの**有効なメールアドレスを**発見するか、すでに発見したものを**確認するために、被害者のSMTPサーバーをブルートフォース攻撃できるか確認できます。[ここでメールアドレスを確認/発見する方法を学びます](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
さらに、ユーザーが**メールにアクセスするためのウェブポータルを使用している場合**、それが**ユーザー名のブルートフォース攻撃に対して脆弱かどうかを確認し、可能であればその脆弱性を悪用することを忘れないでください**。

## GoPhishの設定

### インストール

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)からダウンロードできます。

`/opt/gophish`内にダウンロードして解凍し、`/opt/gophish/gophish`を実行します。\
出力にポート3333の管理ユーザー用のパスワードが表示されます。したがって、そのポートにアクセスし、その資格情報を使用して管理者パスワードを変更します。そのポートをローカルにトンネリングする必要があるかもしれません。
```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```
### 設定

**TLS証明書の設定**

このステップの前に、使用するドメインを**すでに購入している**必要があり、**gophish**を設定している**VPSのIP**に**ポイント**している必要があります。
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

**/etc/postfix/main.cf内の以下の変数の値も変更します**

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、ファイル **`/etc/hostname`** と **`/etc/mailname`** をあなたのドメイン名に変更し、**VPSを再起動します。**

次に、**DNS Aレコード** `mail.<domain>` をVPSの**IPアドレス**にポイントさせ、**DNS MX**レコードを `mail.<domain>` にポイントさせます。

次に、メールを送信するテストを行いましょう:
```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```
**Gophishの設定**

gophishの実行を停止し、設定を行いましょう。\
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
**gophishサービスの設定**

gophishサービスを自動的に開始し、サービスとして管理できるようにするために、次の内容でファイル`/etc/init.d/gophish`を作成できます:
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
サービスの設定を完了し、次のことを確認します:
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

ドメインが古いほど、スパムとして検出される可能性は低くなります。そのため、フィッシング評価の前にできるだけ長く（少なくとも1週間）待つべきです。さらに、評判の良い分野に関するページを作成すれば、得られる評判はより良くなります。

1週間待たなければならない場合でも、今すぐにすべての設定を終えることができます。

### リバースDNS（rDNS）レコードの設定

VPSのIPアドレスをドメイン名に解決するrDNS（PTR）レコードを設定します。

### 送信者ポリシーフレームワーク（SPF）レコード

新しいドメインのために**SPFレコードを設定する必要があります**。SPFレコードが何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net)を使用して、SPFポリシーを生成できます（VPSマシンのIPを使用してください）。

![](<../../images/image (1037).png>)

これは、ドメイン内のTXTレコードに設定する必要がある内容です：
```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```
### ドメインベースのメッセージ認証、報告および適合性 (DMARC) レコード

新しいドメインのために**DMARCレコードを設定する必要があります**。DMARCレコードが何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

次の内容でホスト名`_dmarc.<domain>`を指す新しいDNS TXTレコードを作成する必要があります:
```bash
v=DMARC1; p=none
```
### DomainKeys Identified Mail (DKIM)

新しいドメインのために**DKIMを設定する必要があります**。DMARCレコードが何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

このチュートリアルは、[https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)に基づいています。

> [!TIP]
> DKIMキーが生成する両方のB64値を連結する必要があります：
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### Test your email configuration score

[https://www.mail-tester.com/](https://www.mail-tester.com)を使用してそれを行うことができます。\
ページにアクセスして、彼らが提供するアドレスにメールを送信してください：
```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```
あなたはまた、**メール設定を確認する**ために `check-auth@verifier.port25.com` にメールを送信し、**レスポンスを読む**ことができます（これには、**ポート25を開く**必要があり、メールをrootとして送信した場合はファイル _/var/mail/root_ でレスポンスを確認します）。\
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
あなたはまた、**あなたの管理下にあるGmailにメッセージを送信し**、Gmailの受信トレイで**メールのヘッダー**を確認することができます。`dkim=pass`は`Authentication-Results`ヘッダー欄に存在する必要があります。
```
Authentication-Results: mx.google.com;
spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
dkim=pass header.i=@example.com;
```
### ​Spamhouseのブラックリストからの削除

ページ [www.mail-tester.com](https://www.mail-tester.com) は、あなたのドメインがspamhouseによってブロックされているかどうかを示すことができます。あなたのドメイン/IPの削除をリクエストすることができます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoftのブラックリストからの削除

あなたのドメイン/IPの削除をリクエストすることができます: [https://sender.office.com/](https://sender.office.com).

## GoPhishキャンペーンの作成と開始

### 送信プロファイル

- 送信者プロファイルを識別するための**名前を設定**します
- フィッシングメールを送信するアカウントを決定します。提案: _noreply, support, servicedesk, salesforce..._
- ユーザー名とパスワードは空白のままにできますが、「証明書エラーを無視する」にチェックを入れることを確認してください

![](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> "**テストメールを送信**"機能を使用して、すべてが正常に動作しているかをテストすることをお勧めします。\
> テストを行う際にブラックリストに載らないように、**テストメールを10分メールアドレスに送信することをお勧めします**。

### メールテンプレート

- テンプレートを識別するための**名前を設定**します
- 次に、**件名**を書きます（奇妙なものではなく、通常のメールで読むことができるもの）
- "**トラッキング画像を追加**"にチェックを入れていることを確認してください
- **メールテンプレート**を書きます（以下の例のように変数を使用できます）：
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
注意してほしいのは、**メールの信頼性を高めるために**、クライアントからのメールの署名を使用することが推奨されるということです。提案：

- **存在しないアドレス**にメールを送信し、返信に署名が含まれているか確認します。
- **public emails**（例：info@ex.com、press@ex.com、public@ex.com）を探し、メールを送信して返信を待ちます。
- **いくつかの有効な発見された**メールに連絡を試み、返信を待ちます。

![](<../../images/image (80).png>)

> [!TIP]
> Email Templateでは、**送信するファイルを添付することもできます**。NTLMチャレンジを特別に作成したファイル/ドキュメントを使用して盗むことに興味がある場合は、[このページを読む](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### ランディングページ

- **名前**を記入
- **ウェブページのHTMLコード**を記入します。ウェブページを**インポート**することもできます。
- **提出されたデータをキャプチャ**と**パスワードをキャプチャ**にチェックを入れます。
- **リダイレクト**を設定します。

![](<../../images/image (826).png>)

> [!TIP]
> 通常、ページのHTMLコードを修正し、ローカルでいくつかのテストを行う必要があります（おそらくApacheサーバーを使用して）**結果に満足するまで**。その後、そのHTMLコードをボックスに記入します。\
> HTML用に**静的リソース**（おそらくCSSやJSページ）を使用する必要がある場合は、_**/opt/gophish/static/endpoint**_に保存し、_**/static/\<filename>**_からアクセスできます。

> [!TIP]
> リダイレクトでは、**被害者の正当なメインウェブページにユーザーをリダイレクトする**か、例えば_/static/migration.html_にリダイレクトし、5秒間**スピニングホイール**（**[https://loading.io/](https://loading.io)**）を表示し、その後プロセスが成功したことを示すことができます。

### ユーザーとグループ

- 名前を設定
- **データをインポート**します（例のテンプレートを使用するには、各ユーザーの名、姓、メールアドレスが必要です）。

![](<../../images/image (163).png>)

### キャンペーン

最後に、名前、メールテンプレート、ランディングページ、URL、送信プロファイル、グループを選択してキャンペーンを作成します。URLは被害者に送信されるリンクになります。

**送信プロファイルでは、最終的なフィッシングメールがどのように見えるかを確認するためにテストメールを送信できます**：

![](<../../images/image (192).png>)

> [!TIP]
> テストメールは**10分メールアドレス**に送信することをお勧めします。テスト中にブラックリストに載るのを避けるためです。

すべてが準備できたら、キャンペーンを開始してください！

## ウェブサイトのクローン

何らかの理由でウェブサイトをクローンしたい場合は、次のページを確認してください：

{{#ref}}
clone-a-website.md
{{#endref}}

## バックドア付きドキュメントとファイル

いくつかのフィッシング評価（主にレッドチーム向け）では、**バックドアを含むファイルを送信する**ことも望ましいです（おそらくC2、または認証をトリガーする何か）。\
いくつかの例については、次のページを確認してください：

{{#ref}}
phishing-documents.md
{{#endref}}

## フィッシングMFA

### プロキシMitM経由

前述の攻撃は非常に巧妙で、実際のウェブサイトを偽装し、ユーザーが設定した情報を収集します。残念ながら、ユーザーが正しいパスワードを入力しなかった場合や、偽装したアプリケーションが2FAで設定されている場合、**この情報では騙されたユーザーを偽装することはできません**。

ここで、[**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper)および[**muraena**](https://github.com/muraenateam/muraena)のようなツールが役立ちます。このツールは、MitMのような攻撃を生成することを可能にします。基本的に、攻撃は次のように機能します：

1. 実際のウェブページのログインフォームを**偽装**します。
2. ユーザーは**資格情報**を偽のページに送信し、ツールはそれを実際のウェブページに送信し、**資格情報が機能するか確認します**。
3. アカウントが**2FA**で設定されている場合、MitMページはそれを要求し、**ユーザーが入力**すると、ツールはそれを実際のウェブページに送信します。
4. ユーザーが認証されると、あなた（攻撃者）は**資格情報、2FA、クッキー、ツールがMitMを実行している間のすべてのインタラクションの情報をキャプチャ**します。

### VNC経由

もし、**被害者を元のページと同じ外観の悪意のあるページに送る代わりに、実際のウェブページに接続されたブラウザの**VNCセッションに送ることができればどうでしょうか？彼が何をしているかを見ることができ、パスワード、使用されるMFA、クッキーを盗むことができます...\
これを[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)で行うことができます。

## 検出の検出

明らかに、バストされたかどうかを知る最良の方法の1つは、**ブラックリスト内で自分のドメインを検索すること**です。リストに表示されている場合、何らかの形であなたのドメインが疑わしいと検出されました。\
ドメインがブラックリストに表示されているかどうかを確認する簡単な方法は、[https://malwareworld.com/](https://malwareworld.com)を使用することです。

ただし、被害者が**野生で疑わしいフィッシング活動を積極的に探しているかどうかを知る他の方法もあります**。これは次のように説明されています：

{{#ref}}
detecting-phising.md
{{#endref}}

非常に似た名前のドメインを**購入する**ことができます。被害者のドメインの**キーワード**を含む**サブドメイン**のために証明書を**生成する**こともできます。もし**被害者**がそれらと何らかの**DNSまたはHTTPインタラクション**を行うと、**彼が積極的に探している**ことがわかり、非常にステルスである必要があります。

### フィッシングの評価

[**Phishious**](https://github.com/Rices/Phishious)を使用して、あなたのメールがスパムフォルダに入るか、ブロックされるか、成功するかを評価します。

## 高接触型アイデンティティ侵害（ヘルプデスクMFAリセット）

現代の侵入セットは、メールの誘惑を完全にスキップし、**サービスデスク/アイデンティティ回復ワークフローを直接ターゲットにしてMFAを打破します**。攻撃は完全に「土地を生きる」ものであり、オペレーターが有効な資格情報を持つと、組み込みの管理ツールを使用してピボットします - マルウェアは必要ありません。

### 攻撃フロー
1. 被害者の偵察
* LinkedIn、データ侵害、公開GitHubなどから個人および企業の詳細を収集します。
* 高価値のアイデンティティ（役員、IT、財務）を特定し、パスワード/MFAリセットのための**正確なヘルプデスクプロセス**を列挙します。
2. リアルタイムのソーシャルエンジニアリング
* ターゲットを偽装してヘルプデスクに電話、Teams、またはチャットします（しばしば**偽の発信者ID**または**クローン音声**を使用）。
* 以前に収集したPIIを提供して、知識ベースの検証を通過します。
* エージェントに**MFAシークレットをリセット**させるか、登録された携帯番号で**SIMスワップ**を実行させます。
3. アクセス後の即時アクション（実際のケースでは≤60分）
* 任意のウェブSSOポータルを通じて足場を確立します。
* 組み込みを使用してAD/AzureADを列挙します（バイナリはドロップされません）：
```powershell
# ディレクトリグループと特権ロールをリスト
Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

# AzureAD / Graph – ディレクトリロールをリスト
Get-MgDirectoryRole | ft DisplayName,Id

# アカウントがログインできるデバイスを列挙
Get-MgUserRegisteredDevice -UserId <user@corp.local>
```
* **WMI**、**PsExec**、または環境内で既にホワイトリストに登録されている正当な**RMM**エージェントを使用して横移動します。

### 検出と緩和
* ヘルプデスクのアイデンティティ回復を**特権操作**として扱います - ステップアップ認証とマネージャーの承認を要求します。
* 次のことに警告する**アイデンティティ脅威検出と応答（ITDR）** / **UEBA**ルールを展開します：
* MFAメソッドが変更され、新しいデバイス/地理からの認証。
* 同じプリンシパル（ユーザー→管理者）の即時昇格。
* ヘルプデスクの通話を記録し、リセットの前に**既に登録された番号へのコールバック**を強制します。
* **ジャストインタイム（JIT）/特権アクセス**を実装し、新しくリセットされたアカウントが**自動的に高特権トークンを継承しない**ようにします。

---

## 大規模な欺瞞 - SEOポイズニングと「ClickFix」キャンペーン
コモディティクルーは、高接触オペレーションのコストをオフセットするために、**検索エンジンと広告ネットワークを配信チャネルに変えた大量攻撃**を行います。

1. **SEOポイズニング/マルバタイジング**は、`chromium-update[.]site`のような偽の結果を検索広告のトップに押し上げます。
2. 被害者は小さな**第一段階のローダー**（しばしばJS/HTA/ISO）をダウンロードします。Unit 42によって見られた例：
* `RedLine stealer`
* `Lumma stealer`
* `Lampion Trojan`
3. ローダーはブラウザのクッキーと資格情報DBを外部に送信し、その後**サイレントローダー**を引き出し、*リアルタイム*でデプロイするかどうかを決定します：
* RAT（例：AsyncRAT、RustDesk）
* ランサムウェア/ワイパー
* 永続コンポーネント（レジストリのRunキー + スケジュールされたタスク）

### ハードニングのヒント
* 新しく登録されたドメインをブロックし、**高度なDNS/URLフィルタリング**を*検索広告*およびメールに強制します。
* ソフトウェアのインストールを署名されたMSI/ストアパッケージに制限し、ポリシーによって`HTA`、`ISO`、`VBS`の実行を拒否します。
* インストーラーを開くブラウザの子プロセスを監視します：
```yaml
- parent_image: /Program Files/Google/Chrome/*
and child_image: *\\*.exe
```
* 第一段階のローダーによって頻繁に悪用されるLOLBins（例：`regsvr32`、`curl`、`mshta`）をハントします。

---

## AI強化フィッシングオペレーション
攻撃者は現在、**LLMおよび音声クローンAPI**を連鎖させて、完全にパーソナライズされた誘惑とリアルタイムのインタラクションを実現しています。

| レイヤー | 脅威アクターによる使用例 |
|-------|-----------------------------|
|自動化|ランダム化された文言とトラッキングリンクを使用して、>100kのメール/SMSを生成して送信。|
|生成AI|公開M&A、ソーシャルメディアの内部ジョークを参照する*一回限り*のメールを生成；コールバック詐欺でのディープフェイクCEO音声。|
|エージェンティックAI|自律的にドメインを登録し、オープンソースのインテリジェンスをスクレイピングし、被害者がクリックするが資格情報を提出しない場合に次の段階のメールを作成。|

**防御：**
• **動的バナー**を追加し、信頼できない自動化から送信されたメッセージを強調表示します（ARC/DKIMの異常を介して）。
• 高リスクの電話リクエストに対して**音声生体認証チャレンジフレーズ**を展開します。
• 意識プログラムでAI生成の誘惑を継続的にシミュレートします - 静的テンプレートは時代遅れです。

---

## MFA疲労/プッシュボンビングバリアント - 強制リセット
クラシックなプッシュボンビングに加えて、オペレーターは単に**ヘルプデスクの呼び出し中に新しいMFA登録を強制し、ユーザーの既存のトークンを無効にします**。その後のログインプロンプトは被害者にとって正当なものに見えます。
```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```
AzureAD/AWS/Oktaのイベントを監視し、**`deleteMFA` + `addMFA`** が**同じIPから数分以内に**発生する場合を確認します。

## クリップボードハイジャック / ペーストジャッキング

攻撃者は、侵害されたまたはタイポスクワットされたウェブページから被害者のクリップボードに悪意のあるコマンドを静かにコピーし、その後ユーザーを騙して**Win + R**、**Win + X**、またはターミナルウィンドウ内にペーストさせ、ダウンロードや添付なしで任意のコードを実行させることができます。

{{#ref}}
clipboard-hijacking.md
{{#endref}}

## モバイルフィッシング & 悪意のあるアプリ配布 (Android & iOS)

{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

## 参考文献

- [https://zeltser.com/domain-name-variations-in-phishing/](https://zeltser.com/domain-name-variations-in-phishing/)
- [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)
- [https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [2025 Unit 42 Global Incident Response Report – Social Engineering Edition](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)

{{#include ../../banners/hacktricks-training.md}}
