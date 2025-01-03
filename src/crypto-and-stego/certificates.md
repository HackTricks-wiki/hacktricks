# 証明書

{{#include ../banners/hacktricks-training.md}}

## 証明書とは

**公開鍵証明書**は、暗号学で誰かが公開鍵を所有していることを証明するために使用されるデジタルIDです。これには鍵の詳細、所有者の身元（主題）、および信頼できる機関（発行者）からのデジタル署名が含まれます。ソフトウェアが発行者を信頼し、署名が有効であれば、鍵の所有者との安全な通信が可能です。

証明書は主に[証明書機関](https://en.wikipedia.org/wiki/Certificate_authority)（CA）によって[公開鍵基盤](https://en.wikipedia.org/wiki/Public-key_infrastructure)（PKI）セットアップで発行されます。別の方法は[信頼のウェブ](https://en.wikipedia.org/wiki/Web_of_trust)で、ユーザーが直接お互いの鍵を検証します。証明書の一般的な形式は[X.509](https://en.wikipedia.org/wiki/X.509)で、RFC 5280に記載されている特定のニーズに合わせて適応できます。

## x509の一般的なフィールド

### **x509証明書の一般的なフィールド**

x509証明書には、証明書の有効性とセキュリティを確保するために重要な役割を果たすいくつかの**フィールド**があります。これらのフィールドの内訳は以下の通りです：

- **バージョン番号**はx509形式のバージョンを示します。
- **シリアル番号**は、証明書機関（CA）のシステム内で証明書を一意に識別し、主に取り消し追跡のために使用されます。
- **主題**フィールドは証明書の所有者を表し、機械、個人、または組織である可能性があります。詳細な識別情報が含まれます：
- **共通名（CN）**：証明書でカバーされるドメイン。
- **国（C）**、**地域（L）**、**州または省（ST、S、またはP）**、**組織（O）**、および**組織単位（OU）**は地理的および組織的な詳細を提供します。
- **識別名（DN）**は完全な主題識別をカプセル化します。
- **発行者**は証明書を検証し署名した人物を示し、CAのための主題と同様のサブフィールドを含みます。
- **有効期間**は**Not Before**および**Not After**のタイムスタンプで示され、証明書が特定の日付の前または後に使用されないことを保証します。
- **公開鍵**セクションは、証明書のセキュリティにとって重要で、公開鍵のアルゴリズム、サイズ、およびその他の技術的詳細を指定します。
- **x509v3拡張**は証明書の機能を強化し、**鍵の使用**、**拡張鍵の使用**、**主題代替名**、および証明書の適用を微調整するためのその他のプロパティを指定します。

#### **鍵の使用と拡張**

- **鍵の使用**は、公開鍵の暗号化アプリケーションを特定します。例えば、デジタル署名や鍵の暗号化などです。
- **拡張鍵の使用**は、証明書の使用ケースをさらに絞り込みます。例えば、TLSサーバー認証のためです。
- **主題代替名**および**基本制約**は、証明書でカバーされる追加のホスト名と、それがCAまたはエンドエンティティ証明書であるかどうかを定義します。
- **主題鍵識別子**や**権限鍵識別子**のような識別子は、鍵の一意性と追跡可能性を保証します。
- **権限情報アクセス**および**CRL配布ポイント**は、発行CAを検証し、証明書の取り消し状況を確認するためのパスを提供します。
- **CTプレ証明書SCT**は、証明書に対する公的信頼にとって重要な透明性ログを提供します。
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

**OCSP** (**RFC 2560**) は、クライアントとレスポンダーが協力してデジタル公開鍵証明書が取り消されたかどうかを確認する方法で、完全な**CRL**をダウンロードする必要がありません。この方法は、取り消された証明書のシリアル番号のリストを提供する従来の**CRL**よりも効率的であり、潜在的に大きなファイルをダウンロードする必要があります。CRLには最大512エントリが含まれることがあります。詳細は[こちら](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm)で確認できます。

### **証明書の透明性とは**

証明書の透明性は、SSL証明書の発行と存在がドメイン所有者、CA、およびユーザーに見えるようにすることで、証明書関連の脅威と戦うのに役立ちます。その目的は次のとおりです：

- ドメイン所有者の知らないうちにCAがドメインのSSL証明書を発行するのを防ぐこと。
- 誤ってまたは悪意を持って発行された証明書を追跡するためのオープンな監査システムを確立すること。
- ユーザーを詐欺的な証明書から保護すること。

#### **証明書ログ**

証明書ログは、ネットワークサービスによって維持される公開監査可能な追加専用の証明書記録です。これらのログは監査目的のための暗号的証明を提供します。発行機関と一般の人々は、これらのログに証明書を提出したり、検証のために照会したりできます。ログサーバーの正確な数は固定されていませんが、世界中で千未満であると予想されています。これらのサーバーは、CA、ISP、または関心のある任意の団体によって独立して管理されることがあります。

#### **クエリ**

任意のドメインの証明書透明性ログを探索するには、[https://crt.sh/](https://crt.sh)を訪問してください。

証明書を保存するためのさまざまな形式が存在し、それぞれに独自の使用ケースと互換性があります。この要約では、主要な形式をカバーし、それらの間の変換に関するガイダンスを提供します。

## **形式**

### **PEM形式**

- 証明書の最も広く使用されている形式。
- 証明書と秘密鍵のために別々のファイルが必要で、Base64 ASCIIでエンコードされています。
- 一般的な拡張子：.cer、.crt、.pem、.key。
- 主にApacheや同様のサーバーで使用されます。

### **DER形式**

- 証明書のバイナリ形式。
- PEMファイルに見られる「BEGIN/END CERTIFICATE」ステートメントがありません。
- 一般的な拡張子：.cer、.der。
- Javaプラットフォームでよく使用されます。

### **P7B/PKCS#7形式**

- Base64 ASCIIで保存され、拡張子は.p7bまたは.p7c。
- 秘密鍵を除く証明書とチェーン証明書のみを含みます。
- Microsoft WindowsおよびJava Tomcatでサポートされています。

### **PFX/P12/PKCS#12形式**

- サーバー証明書、中間証明書、および秘密鍵を1つのファイルにカプセル化するバイナリ形式。
- 拡張子：.pfx、.p12。
- 主にWindowsで証明書のインポートとエクスポートに使用されます。

### **形式の変換**

**PEM変換**は互換性のために重要です：

- **x509からPEMへ**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEMからDER**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DERからPEMへ**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM から P7B へ**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7をPEMに**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX 変換**は、Windows上での証明書管理において重要です：

- **PFX から PEM**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX to PKCS#8** は2つのステップを含みます：
1. PFXをPEMに変換する
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. PEMをPKCS8に変換する
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B to PFX** には2つのコマンドも必要です：
1. P7BをCERに変換します
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. CERとプライベートキーをPFXに変換する
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
- **ASN.1 (DER/PEM) 編集** (証明書やほぼすべての他のASN.1構造で動作します):
1. [asn1template](https://github.com/wllm-rbnt/asn1template/)をクローンします。
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. DER/PEMをOpenSSLの生成フォーマットに変換する
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. 要件に応じて certificatename.tpl を編集します。
```bash
vim certificatename.tpl
```
4. 修正された証明書を再構築する
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
---

{{#include ../banners/hacktricks-training.md}}
