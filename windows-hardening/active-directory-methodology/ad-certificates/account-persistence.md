# AD CS アカウントの永続性

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦で私をフォローする [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **ハッキングテクニックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

**これは、[https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)** からの素晴らしい研究のマシン永続性章の要約です。

## **証明書を使用したアクティブユーザー資格情報の盗難の理解 – PERSIST1**

ユーザーがドメイン認証を許可する証明書をリクエストできるシナリオでは、攻撃者はネットワーク上で**永続性を維持**するためにこの証明書を**リクエスト**および**盗む**機会があります。Active Directoryの`User`テンプレートは、そのようなリクエストを許可するようになっていますが、時々無効になっていることがあります。

[**Certify**](https://github.com/GhostPack/Certify)というツールを使用すると、永続的なアクセスを可能にする有効な証明書を検索できます。
```bash
Certify.exe find /clientauth
```
強調されているのは、証明書の力は、証明書が**有効である限り**、パスワードの変更に関係なく、それが所属するユーザーとして**認証**できることにあります。

証明書は、`certmgr.msc`を使用してグラフィカルインターフェースを介してリクエストするか、`certreq.exe`を使用してコマンドラインを介してリクエストすることができます。**Certify**を使用すると、証明書をリクエストするプロセスは次のように簡略化されます：
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
成功したリクエストの後、証明書とその秘密鍵が`.pem`形式で生成されます。これをWindowsシステムで使用可能な`.pfx`ファイルに変換するには、次のコマンドを使用します：
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
`.pfx`ファイルは、その後、ターゲットシステムにアップロードされ、ユーザーのためにチケット発行チケット（TGT）を要求するために[**Rubeus**](https://github.com/GhostPack/Rubeus)と呼ばれるツールと共に使用され、証明書が**有効**である限り（通常1年間）、攻撃者のアクセスを延長します。
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
重要な警告が共有されており、この技術が、**THEFT5**セクションで概説されている別の方法と組み合わさることで、攻撃者がローカルセキュリティ機関サブシステムサービス（LSASS）とやり取りせずに、非昇格コンテキストからアカウントの**NTLMハッシュ**を持続的に取得することが可能となり、長期間の資格情報盗難のためのよりステルスな方法が提供されます。

## **証明書を使用したマシンの持続性の獲得 - PERSIST2**

別の方法は、侵害されたシステムのマシンアカウントを証明書に登録することで、デフォルトの`Machine`テンプレートを利用するものです。システムで昇格権限を取得した場合、**SYSTEM**アカウントを使用して証明書を要求することができ、一種の**持続性**を提供します。
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
このアクセスにより、攻撃者はマシンアカウントとして**Kerberos**に認証し、**S4U2Self**を利用してホスト上の任意のサービスのKerberosサービスチケットを取得し、事実上、攻撃者にマシンへの持続的アクセスが与えられます。

## **証明書の更新を通じた持続性の拡張 - PERSIST3**

最後に議論された方法は、証明書テンプレートの**有効期間**と**更新期間**を活用することです。証明書を有効期限切れ前に更新することで、攻撃者は追加のチケット登録が必要なくActive Directoryへの認証を維持できます。これにより、証明書機関（CA）サーバーに痕跡を残す可能性がある追加のチケット登録を回避できます。

このアプローチにより、CAサーバーとのやり取りが少なくなり、侵入を管理者に知らせる可能性のあるアーティファクトの生成を回避することで、**拡張された持続性**方法が可能となり、検出リスクが最小限に抑えられます。
