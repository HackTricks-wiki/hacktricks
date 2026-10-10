# TLS と証明書

{{#include ../../banners/hacktricks-training.md}}

このセクションでは、X.509 の検査、エンコーディング、変換、セキュリティに関わる検証上のミスを扱います。

## X.509 の解析

OpenSSL では証明書のデコード済みフィールドを表示でき、`asn1parse` では基盤となる ASN.1 構造を確認できます。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

少なくとも次の項目を確認してください。

- subject、issuer、Subject Alternative Name (SAN)
- key usage と extended key usage
- basic constraints と path-length constraints
- 有効期間の `notBefore` と `notAfter`
- 公開鍵のパラメーターと署名アルゴリズム

MD5 や SHA-1 ベースの証明書署名など、レガシーな署名は特に重要な検出事項です。ただし、実際に受け入れられるか、どのような影響があるかは、検証器と信頼コンテキストによって異なります。<sup>[[3]](#references)</sup>

RFC 5280 は、インターネット向け X.509 プロファイルと、SAN、key usage、name constraints、basic constraints などの拡張機能に関する処理ルールを定義しています。<sup>[[3]](#references)</sup>

## エンコーディングとコンテナ

- **PEM 形式のテキストエンコーディング:** `BEGIN` と `END` の境界に挟まれた Base64 データ。
- **DER:** バイナリ形式の Distinguished Encoding Rules 表現。
- **PKCS#7/CMS (`.p7b`):** 一般に証明書と証明書チェーンを格納しますが、秘密鍵は格納しません。
- **PKCS#12 (`.p12` または `.pfx`):** 秘密鍵、証明書、および補助証明書を格納できます。

RFC 7468 は、PKIX、PKCS、CMS 構造で使用されるテキストエンコーディングを規定しています。OpenSSL の `pkcs12` コマンドは、PKCS#12 ファイルの作成と解析に使用されます。<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

`out.pem` は機密情報として扱ってください。`-nokeys` などのオプションを指定しない限り、出力に秘密鍵の情報が含まれる可能性があります。<sup>[[5]](#references)</sup>

## Security Review Checklist

validator または信頼判断をレビューする際は、RFC 5280 の証明書処理要件を適用してください。<sup>[[3]](#references)</sup>

- 明示的に信頼されたアンカーまでの完全なチェーンを検証してください。ユーザーが提供したルートを暗黙に信頼しないでください。
- ホスト名またはサービス ID が SAN の値と一致することを確認してください。<sup>[[8]](#references)</sup>
- 基本制約、名前制約、鍵の使用目的、拡張鍵の使用目的を適用してください。
- 有効期限が切れた証明書、まだ有効でない証明書、および許可されていない鍵アルゴリズムや署名アルゴリズムを拒否してください。
- クライアント証明書の ID を、適切なアプリケーションアカウントおよび認可コンテキストに紐付けてください。

## Certificate Transparency Logs

Certificate Transparency は、発行済み証明書を公開監査可能なログに記録します。<sup>[[6]](#references)</sup> 許可されたアセット調査では、crt.sh でドメインを検索してください。<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL ドキュメント - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL ドキュメント - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - インターネット X.509 公開鍵基盤の証明書および CRL プロファイル](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - PKIX、PKCS、CMS 構造のテキストエンコーディング](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL ドキュメント - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency バージョン 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - 証明書検索](https://crt.sh/)
- [8] [RFC 9525 - TLS におけるサービス ID](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
