# TLS & Certificates

{{#include ../../banners/hacktricks-training.md}}

このエリアは**X.509 の解析、フォーマット、変換、および一般的なミス**に関するものです。

## X.509: 解析、フォーマット & 一般的なミス

### クイック解析
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
確認すべき有用なフィールド:

- Subject（サブジェクト） / Issuer（発行者） / SAN
- Key Usage / EKU（鍵用途）
- Basic Constraints（CAかどうか）
- Validity window（NotBefore/NotAfter）
- Signature algorithm（MD5? SHA1?）

### フォーマットと変換

- PEM（BEGIN/END ヘッダを含むBase64）
- DER（バイナリ）
- PKCS#7 (`.p7b`)（証明書チェーン、秘密鍵なし）
- PKCS#12 (`.pfx/.p12`)（証明書 + 秘密鍵 + チェーン）

変換:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### 一般的な攻撃ベクトル

- ユーザー提供のルートを信頼すること／チェーン検証の欠如
- 弱い署名アルゴリズム（レガシー）
- 名前制約／SANの解析バグ（実装依存）
- Confused deputy による client-certificate authentication の misbinding 問題

### CTログ

- https://crt.sh/

{{#include ../../banners/hacktricks-training.md}}
