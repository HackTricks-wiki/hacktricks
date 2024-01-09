# AD CS アカウントの永続性

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>

## 証明書を介したアクティブユーザーの資格情報盗難 – PERSIST1

ユーザーがドメイン認証を許可する証明書を要求できる場合、攻撃者はそれを**要求**し、**盗む**ことで**永続性**を**維持**することができます。

**`User`** テンプレートはそれを許可し、**デフォルト**で提供されています。ただし、無効になっている可能性があります。したがって、[**Certify**](https://github.com/GhostPack/Certify)を使用すると、永続化に有効な証明書を見つけることができます：
```
Certify.exe find /clientauth
```
**証明書は有効である限り**、ユーザーが**パスワードを変更しても**、そのユーザーとしての**認証に使用できる**ことに注意してください。

**GUI**からは、`certmgr.msc`を使用して証明書を要求することができますし、コマンドラインからは`certreq.exe`を使用することができます。

[**Certify**](https://github.com/GhostPack/Certify)を使用すると、次の操作を実行できます：
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
結果は **証明書** + **秘密鍵** `.pem` 形式のテキストブロックになります。
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
**その証明書を使用するには**、`.pfx`をターゲットに**アップロード**し、[**Rubeus**](https://github.com/GhostPack/Rubeus)を使用して登録されたユーザーのTGTを**要求**することができます。証明書の有効期間が続く限り（デフォルトの有効期間は1年です）：
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
[**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5)セクションで説明されている技術と組み合わせることで、攻撃者は**アカウントのNTLMハッシュを永続的に取得**することもできます。これを利用して、攻撃者は**パス・ザ・ハッシュ**や**クラック**を通じて**プレーンテキスト**の**パスワード**を取得することができます。\
これは**LSASSに触れずに**、**非昇格コンテキスト**から可能な**長期的なクレデンシャル盗難**の代替方法です。
{% endhint %}

## 証明書を通じたマシンの永続化 - PERSIST2

証明書テンプレートが**ドメインコンピュータ**を登録主体として許可している場合、攻撃者は**侵害されたシステムのマシンアカウントを登録**することができます。デフォルトの**`Machine`**テンプレートは、これらの特性すべてに一致します。

攻撃者が侵害されたシステムで**権限を昇格**すると、攻撃者は**SYSTEM**アカウントを使用して、マシンアカウントに登録権限を付与する証明書テンプレートに登録することができます（詳細は[**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)を参照）。

[**Certify**](https://github.com/GhostPack/Certify) を使用して、自動的にSYSTEMに昇格し、マシンアカウントの証明書を取得することができます。
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
```markdown
マシンアカウントの証明書にアクセスできると、攻撃者はマシンアカウントとして**Kerberosに認証**することができます。**S4U2Self**を使用すると、攻撃者は任意のユーザーとしてホスト上の任意のサービス（例：CIFS、HTTP、RPCSSなど）に対する**Kerberosサービスチケットを取得**することができます。

結局のところ、これは攻撃者にマシンの永続性メソッドを提供します。

## 証明書更新によるアカウントの永続性 - PERSIST3

証明書テンプレートには、発行された証明書が使用できる期間を決定する**有効期間**と、通常6週間の**更新期間**があります。これは証明書が**期限切れになる前の時間**で、**アカウントが発行証明機関からそれを更新できる**ウィンドウです。

攻撃者が盗難または悪意のある登録によってドメイン認証が可能な証明書を侵害した場合、攻撃者は証明書の有効期間中、**ADに認証することができます**。しかし、攻撃者は**期限切れ前に証明書を更新する**ことができます。これは、追加のチケット登録が要求されることを**防ぎ**、CAサーバー自体に**アーティファクトを残す可能性がある**、**拡張された永続性**アプローチとして機能することができます。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
```
