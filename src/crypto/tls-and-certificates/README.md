# TLS と証明書

{{#include ../../banners/hacktricks-training.md}}

このセクションでは、X.509 の検査、エンコーディング、変換、および security に関係する検証ミスについて説明します。

## X.509 の解析

OpenSSL では証明書のデコードされたフィールドを表示でき、`asn1parse` では基盤となる ASN.1 構造を確認できます。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
少なくとも以下を確認してください。

- subject、issuer、および Subject Alternative Name (SAN);
- key usage および extended key usage;
- basic constraints および path-length constraints;
- `notBefore` および `notAfter` の有効期間;
- 公開鍵のパラメータおよび署名アルゴリズム。

MD5 または SHA-1 ベースの証明書署名などの Legacy signatures は、特に重要な findings です。ただし、正確な受け入れ可否と影響は、validator と trust context に依存します。<sup>[[3]](#references)</sup>

RFC 5280 は、Internet X.509 profile と、SAN、key usage、name constraints、basic constraints などの extensions に関する処理ルールを定義しています。<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM-style textual encoding:** `BEGIN` と `END` の境界の間にある Base64 データ。
- **DER:** バイナリの Distinguished Encoding Rules 表現。
- **PKCS#7/CMS (`.p7b`):** 通常、証明書と certificate chain を格納しますが、private keys は格納しません。
- **PKCS#12 (`.p12` または `.pfx`):** private keys、証明書、および supporting certificates を格納できます。

RFC 7468 は、PKIX、PKCS、CMS structures に使用される textual encodings を規定しています。OpenSSL の `pkcs12` command は PKCS#12 files を作成および解析します。<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
`out.pem` は機密情報として扱ってください。`-nokeys` などのオプションを使用しない限り、出力に秘密鍵の情報が含まれる可能性があります。<sup>[[5]](#references)</sup>

## Security Review Checklist

validator または trust decision をレビューする際は、RFC 5280 の証明書処理要件を適用してください。<sup>[[3]](#references)</sup>

- 明示的に信頼された anchor までの完全な chain を検証し、user-supplied root を暗黙的に信頼しない。
- SAN の値と hostname または service identity が一致することを確認する。<sup>[[8]](#references)</sup>
- basic constraints、name constraints、key usage、extended key usage を適用する。
- 期限切れまたは有効期間前の証明書、および許可されていない key または signature algorithm を拒否する。
- client-certificate identity を正しい application account および authorization context に紐付ける。

## Certificate Transparency Logs

Certificate Transparency は、発行された証明書を公開監査可能な logs として提供します。<sup>[[6]](#references)</sup> 許可された asset discovery の際は、crt.sh で domain を検索してください。<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL ドキュメント - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL ドキュメント - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 公開鍵基盤の証明書および CRL プロファイル](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - PKIX、PKCS、および CMS 構造体のテキストエンコーディング](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL ドキュメント - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - 証明書検索](https://crt.sh/)
- [8] [RFC 9525 - TLS における Service Identity](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
