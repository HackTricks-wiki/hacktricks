# 証明書

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**AWSハッキングをゼロからヒーローまで学ぶ**</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@hacktricks_live**をフォローする
- **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

## 証明書とは

**公開鍵証明書**は、暗号化に使用されるデジタルIDであり、誰かが公開鍵を所有していることを証明するために使用されます。これには、鍵の詳細、所有者の身元（サブジェクト）、および信頼された機関（発行者）からのデジタル署名が含まれます。ソフトウェアが発行者を信頼し、署名が有効であれば、鍵の所有者との安全な通信が可能です。

証明書は、主に[証明機関](https://en.wikipedia.org/wiki/Certificate_authority)（CAs）によって[公開鍵インフラストラクチャ](https://en.wikipedia.org/wiki/Public-key_infrastructure)（PKI）のセットアップで発行されます。別の方法は、[信頼のウェブ](https://en.wikipedia.org/wiki/Web_of_trust)であり、ここではユーザーが直接お互いの鍵を検証します。証明書の一般的な形式は[X.509](https://en.wikipedia.org/wiki/X.509)であり、RFC 5280で概説されている特定のニーズに適応できます。

## x509共通フィールド

### **x509証明書の共通フィールド**

x509証明書では、いくつかの**フィールド**が証明書の有効性とセキュリティを確保するために重要な役割を果たします。これらのフィールドの詳細は以下の通りです：

- **バージョン番号**はx509形式のバージョンを示します。
- **シリアル番号**は、証明書を一意に識別し、主に取り消し追跡のために証明機関（CA）システム内で使用されます。
- **サブジェクト**フィールドは、証明書の所有者を表し、機械、個人、または組織である可能性があります。以下の詳細な識別情報が含まれます：
  - **Common Name (CN)**: 証明書でカバーされるドメイン。
  - **Country (C)**、**Locality (L)**、**State or Province (ST, S, or P)**、**Organization (O)**、および**Organizational Unit (OU)**は地理的および組織的な詳細を提供します。
  - **Distinguished Name (DN)**は完全なサブジェクト識別をカプセル化します。
- **発行者**は、証明書を検証し署名した人物を詳細に示し、CAの場合と同様のサブフィールドが含まれます。
- **有効期間**は**Not Before**および**Not After**のタイムスタンプによって示され、証明書が特定の日付前または後に使用されないようにします。
- 証明書のセキュリティに重要な**公開鍵**セクションは、公開鍵のアルゴリズム、サイズ、およびその他の技術的詳細を指定します。
- **x509v3拡張**は証明書の機能を向上させ、**Key Usage**、**Extended Key Usage**、**Subject Alternative Name**、および証明書のアプリケーションを微調整するためのその他のプロパティを指定します。

#### **Key Usageと拡張**

- **Key Usage**は、公開鍵の暗号化アプリケーション（デジタル署名や鍵の暗号化など）を識別します。
- **Extended Key Usage**は、証明書の使用事例をさらに絞り込みます（例：TLSサーバー認証用）。
- **Subject Alternative Name**および**Basic Constraint**は、証明書でカバーされる追加のホスト名と、CAまたはエンドエンティティ証明書であるかどうかを定義します。
- **Subject Key Identifier**および**Authority Key Identifier**などの識別子は、鍵の一意性と追跡可能性を確保します。
- **Authority Information Access**および**CRL Distribution Points**は、発行CAの検証パスを提供し、証明書の取り消し状態を確認します。
- **CT Precertificate SCTs**は、証明書への公共の信頼に不可欠な透明性ログを提供します。
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **OCSPとCRL配布ポイントの違い**

**OCSP**（**RFC 2560**）は、デジタル公開鍵証明書が取り消されたかどうかを確認するために、クライアントとレスポンダーが協力して作業することを含みます。**CRL**全体をダウンロードする必要がなく、取り消された証明書のシリアル番号のリストを提供しますが、潜在的に大きなファイルをダウンロードする必要がある従来の**CRL**よりも効率的な方法です。CRLには最大512エントリを含めることができます。詳細は[こちら](https://www.arubanetworks.com/techdocs/ArubaOS%206\_3\_1\_Web\_Help/Content/ArubaFrameStyles/CertRevocation/About\_OCSP\_and\_CRL.htm)で入手できます。

### **証明書透明性とは**

証明書透明性は、SSL証明書の発行と存在がドメイン所有者、CA、およびユーザーに可視であることを確認することで、証明書関連の脅威に対抗します。その目的は次のとおりです：

* ドメイン所有者の知識なしにドメインのためにSSL証明書を発行するCAを防ぐこと。
* 誤ってまたは悪意を持って発行された証明書を追跡するためのオープンな監査システムを確立すること。
* ユーザーを詐欺的な証明書から保護すること。

#### **証明書ログ**

証明書ログは、ネットワークサービスによって維持される証明書の公開監査可能な追加専用レコードです。これらのログは監査目的のための暗号的証拠を提供します。発行権限と一般の両者は、これらのログに証明書を提出したり、検証のためにクエリを送信したりすることができます。ログサーバーの正確な数は固定されていませんが、グローバルで1000未満であると予想されています。これらのサーバーは、CA、ISP、または関連するエンティティによって独立して管理されることができます。

#### **クエリ**

任意のドメインの証明書透明性ログを調べるには、[https://crt.sh/](https://crt.sh)を訪れてください。

## **フォーマット**

### **PEMフォーマット**

* 証明書のために最も広く使用されるフォーマット。
* 証明書と秘密鍵用に別々のファイルが必要で、Base64 ASCIIでエンコードされています。
* 一般的な拡張子：.cer、.crt、.pem、.key。
* 主にApacheおよび類似のサーバーで使用されます。

### **DERフォーマット**

* 証明書のバイナリフォーマット。
* PEMファイルに見られる「BEGIN/END CERTIFICATE」ステートメントが欠けています。
* 一般的な拡張子：.cer、.der。
* Javaプラットフォームと一緒によく使用されます。

### **P7B/PKCS#7フォーマット**

* Base64 ASCIIで保存され、拡張子は.p7bまたは.p7cです。
* 秘密鍵を除く証明書とチェーン証明書のみを含みます。
* Microsoft WindowsおよびJava Tomcatでサポートされています。

### **PFX/P12/PKCS#12フォーマット**

* サーバー証明書、中間証明書、および秘密鍵を1つのファイルにカプセル化するバイナリフォーマットです。
* 拡張子：.pfx、.p12。
* 証明書のインポートおよびエクスポートにWindowsで主に使用されます。

### **フォーマットの変換**

**PEM変換**は互換性のために重要です：

* **x509からPEMへ**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
* **PEMからDERへ**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
* **DERからPEMへ**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
* **PEMからP7Bへ**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
* **PKCS7をPEM形式に変換する**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX変換**はWindowsで証明書を管理するために重要です：

* **PFXからPEMへ**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
* **PFX to PKCS#8** には2つのステップが関与します：
1. PFX を PEM に変換します。
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. PEMをPKCS8に変換します。
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
* **P7BからPFXへ**変換するには、2つのコマンドが必要です:
1. P7BをCERに変換します
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. CERおよびプライベートキーをPFXに変換します。
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
***

<figure><img src="../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_term=trickest&utm_content=certificates)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=certificates" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、**あなたのハッキングトリックを共有**してください。

</details>
