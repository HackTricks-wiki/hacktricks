# AD CS アカウント持続性

{{#include ../../../banners/hacktricks-training.md}}

**これは、[https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)の素晴らしい研究のマシン持続性章の小さな要約です。**

## **証明書を使用したアクティブユーザー資格情報の盗難の理解 – PERSIST1**

ユーザーがドメイン認証を許可する証明書を要求できるシナリオでは、攻撃者はこの証明書を**要求**し、**盗む**機会を得て、ネットワーク上で**持続性**を維持することができます。デフォルトでは、Active Directoryの`User`テンプレートはそのような要求を許可しますが、場合によっては無効にされることがあります。

[**Certify**](https://github.com/GhostPack/Certify)というツールを使用すると、持続的なアクセスを可能にする有効な証明書を検索できます：
```bash
Certify.exe find /clientauth
```
証明書の力は、その証明書が属する**ユーザーとして認証する**能力にあることが強調されています。パスワードの変更に関係なく、証明書が**有効**である限りです。

証明書は、`certmgr.msc`を使用したグラフィカルインターフェースまたは`certreq.exe`を使用したコマンドラインを通じて要求できます。**Certify**を使用すると、証明書を要求するプロセスは次のように簡素化されます:
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
重要な警告として、この技術が**THEFT5**セクションで概説されている別の方法と組み合わさることで、攻撃者がローカルセキュリティ認証局サブシステムサービス（LSASS）と対話することなく、非特権コンテキストからアカウントの**NTLMハッシュ**を持続的に取得できることが示されています。これにより、長期的な資格情報の窃盗に対してよりステルスな方法が提供されます。

## **証明書を使用したマシンの持続性の獲得 - PERSIST2**

別の方法は、妥協されたシステムのマシンアカウントを証明書に登録することを含み、デフォルトの`Machine`テンプレートを利用してそのようなアクションを許可します。攻撃者がシステム上で特権を取得した場合、**SYSTEM**アカウントを使用して証明書を要求でき、**持続性**の一形態を提供します。
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
このアクセスにより、攻撃者はマシンアカウントとして**Kerberos**に認証し、**S4U2Self**を利用してホスト上の任意のサービスのKerberosサービスチケットを取得でき、実質的に攻撃者にマシンへの持続的なアクセスを付与します。

## **証明書の更新による持続性の拡張 - PERSIST3**

最後に議論される方法は、証明書テンプレートの**有効性**と**更新期間**を利用することです。証明書の有効期限前に**更新**することで、攻撃者は追加のチケット登録を必要とせずにActive Directoryへの認証を維持でき、これは証明書認証局（CA）サーバーに痕跡を残す可能性があります。

### Certify 2.0による証明書の更新

**Certify 2.0**から、更新ワークフローは新しい`request-renew`コマンドを通じて完全に自動化されています。以前に発行された証明書（**base-64 PKCS#12**形式）を用いることで、攻撃者は元の所有者と対話することなくそれを更新でき、隠密で長期的な持続性に最適です。
```powershell
Certify.exe request-renew --ca SERVER\\CA-NAME \
--cert-pfx MIACAQMwgAYJKoZIhvcNAQcBoIAkgA...   # original PFX
```
コマンドは、新しいフルライフタイム期間に対して有効な新しいPFXを返します。これにより、最初の証明書が期限切れまたは取り消された後でも、認証を続けることができます。

## 参考文献

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)

{{#include ../../../banners/hacktricks-training.md}}
