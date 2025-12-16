# TLS と証明書

{{#include ../../banners/hacktricks-training.md}}

このセクションは**X.509 のパース、フォーマット、変換、およびよくある間違い**についてです。

## X.509: パース、フォーマット、およびよくある間違い

### クイックパース
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
確認すべき重要なフィールド:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints（CAかどうか？）
- Validity window（NotBefore/NotAfter）
- Signature algorithm（MD5? SHA1?）

### フォーマットと変換

- PEM（Base64、BEGIN/END ヘッダ付き）
- DER（バイナリ）
- PKCS#7 (`.p7b`)（証明書チェーン、秘密鍵なし）
- PKCS#12 (`.pfx/.p12`)（証明書 + 秘密鍵 + チェーン）

変換:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### 一般的な攻撃アプローチ

- user-provided roots を信用する / chain validation の欠如
- 弱い signature algorithms (legacy)
- Name constraints / SAN parsing bugs（実装依存）
- Confused deputy 問題（client-certificate authentication の misbinding）

### CTログ

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
