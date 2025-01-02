# AD CS アカウント持続性

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) の素晴らしい研究のマシン持続性章の小さな要約です。**

## **証明書を使用したアクティブユーザー資格情報の盗難の理解 – PERSIST1**

ドメイン認証を許可する証明書がユーザーによって要求できるシナリオでは、攻撃者はこの証明書を**要求**し、**盗む**機会があり、ネットワーク上で**持続性を維持**することができます。デフォルトでは、Active Directoryの`User`テンプレートはそのような要求を許可しますが、時には無効にされることもあります。

[**Certify**](https://github.com/GhostPack/Certify)というツールを使用すると、持続的なアクセスを可能にする有効な証明書を検索できます：
```bash
Certify.exe find /clientauth
```
証明書の力は、その証明書が属する**ユーザーとして認証する**能力にあることが強調されています。パスワードの変更に関係なく、証明書が**有効**である限りです。

証明書は、`certmgr.msc`を使用したグラフィカルインターフェースまたは`certreq.exe`を使用したコマンドラインを通じて要求できます。**Certify**を使用すると、証明書を要求するプロセスは次のように簡素化されます：
```bash
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
成功したリクエストにより、証明書とその秘密鍵が `.pem` 形式で生成されます。これをWindowsシステムで使用可能な `.pfx` ファイルに変換するには、次のコマンドが使用されます：
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
`.pfx`ファイルはターゲットシステムにアップロードされ、[**Rubeus**](https://github.com/GhostPack/Rubeus)というツールを使用してユーザーのチケットグラントチケット（TGT）を要求するために使用され、攻撃者のアクセスを証明書が**有効**である限り（通常は1年）延長します：
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
重要な警告があります。この技術は、**THEFT5** セクションで概説されている別の方法と組み合わせることで、攻撃者がローカル セキュリティ権限サブシステム サービス (LSASS) と対話することなく、アカウントの **NTLM ハッシュ** を持続的に取得できることを示しています。これにより、非特権コンテキストから、長期的な資格情報の窃取に対してよりステルスな方法が提供されます。

## **証明書を使用したマシンの持続性の獲得 - PERSIST2**

別の方法は、妥協されたシステムのマシン アカウントを証明書に登録することを含み、デフォルトの `Machine` テンプレートを利用してそのようなアクションを許可します。攻撃者がシステム上で特権を取得すると、**SYSTEM** アカウントを使用して証明書を要求でき、**持続性**の一形態を提供します。
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
このアクセスにより、攻撃者はマシンアカウントとして**Kerberos**に認証し、**S4U2Self**を利用してホスト上の任意のサービスのKerberosサービスチケットを取得でき、実質的に攻撃者にマシンへの持続的なアクセスを付与します。

## **証明書の更新による持続性の拡張 - PERSIST3**

最後に議論される方法は、証明書テンプレートの**有効性**と**更新期間**を利用することです。証明書が期限切れになる前に**更新**することで、攻撃者は追加のチケット登録を必要とせずにActive Directoryへの認証を維持でき、これにより証明書認証局（CA）サーバーに痕跡を残すことがありません。

このアプローチは、CAサーバーとの相互作用を最小限に抑え、管理者に侵入を警告する可能性のあるアーティファクトの生成を回避することで、**持続性の拡張**方法を可能にします。

{{#include ../../../banners/hacktricks-training.md}}
