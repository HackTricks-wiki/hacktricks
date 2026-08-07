# TLSとCertificates

{{#include ../../banners/hacktricks-training.md}}


このセクションでは、**X.509のparsing、formats、conversions、一般的なmistakes**について説明します。

## X.509: parsing、formats、一般的なmistakes

### Quick parsing
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
確認すべき有用なフィールド:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (CA かどうか)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Formats & conversion

- PEM (BEGIN/END ヘッダー付きの Base64)
- DER (バイナリ)
- PKCS#7 (`.p7b`) (cert chain、private key なし)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Conversions:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### 一般的な攻撃観点

- ユーザーが提供した root を信頼する / chain validation の欠如
- 弱い signature algorithms（legacy）
- Name constraints / SAN の parsing バグ（実装固有）
- クライアント証明書認証の誤った binding による confused deputy の問題

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
