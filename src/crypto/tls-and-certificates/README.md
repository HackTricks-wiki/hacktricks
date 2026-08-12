# TLS 및 인증서

{{#include ../../banners/hacktricks-training.md}}

이 섹션에서는 X.509 검사, 인코딩, 변환 및 보안과 관련된 검증 실수를 다룹니다.

## X.509 파싱

OpenSSL은 인증서의 디코딩된 필드를 출력할 수 있으며, `asn1parse`는 기본 ASN.1 구조를 표시합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
다음 항목을 최소한 검토해야 합니다.

- subject, issuer 및 Subject Alternative Name (SAN);
- key usage 및 extended key usage;
- basic constraints 및 path-length constraints;
- `notBefore` 및 `notAfter` 유효 시간;
- public-key 매개변수 및 signature algorithm.

MD5 또는 SHA-1 기반 certificate signature와 같은 레거시 signature는 특히 중요한 findings이지만, 정확한 수용 여부와 영향은 validator 및 trust context에 따라 달라집니다.<sup>[[3]](#references)</sup>

RFC 5280은 Internet X.509 profile과 SAN, key usage, name constraints 및 basic constraints와 같은 extension의 처리 규칙을 정의합니다.<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM-style textual encoding:** `BEGIN` 및 `END` 경계 사이의 Base64 데이터.
- **DER:** binary Distinguished Encoding Rules 표현.
- **PKCS#7/CMS (`.p7b`):** 일반적으로 certificates와 certificate chain을 포함하지만 private keys는 포함하지 않습니다.
- **PKCS#12 (`.p12` 또는 `.pfx`):** private keys, certificates 및 supporting certificates를 포함할 수 있습니다.

RFC 7468은 PKIX, PKCS 및 CMS structures에 사용되는 textual encodings를 정의하며, OpenSSL의 `pkcs12` command는 PKCS#12 files를 생성하고 parsing합니다.<sup>[[4]](#references)[[5]](#references)</sup>
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
`out.pem`을 민감한 정보로 취급하세요. `-nokeys`와 같은 옵션을 사용하지 않으면 출력에 private-key material이 포함될 수 있습니다.<sup>[[5]](#references)</sup>

## Security Review Checklist

validator 또는 trust decision을 검토할 때 RFC 5280의 certificate-processing 요구 사항을 적용하세요.<sup>[[3]](#references)</sup>

- 명시적으로 신뢰된 anchor까지의 전체 chain을 검증하세요. user-supplied root를 암묵적으로 신뢰하지 마세요.
- SAN 값을 기준으로 hostname 또는 service identity를 확인하세요.<sup>[[8]](#references)</sup>
- basic constraints, name constraints, key usage 및 extended key usage를 적용하세요.
- 만료되었거나 아직 유효하지 않은 certificate와 허용되지 않는 key 또는 signature algorithm을 거부하세요.
- client-certificate identity를 올바른 application account 및 authorization context에 연결하세요.

## Certificate Transparency Logs

Certificate Transparency는 발급된 certificate를 공개적으로 감사할 수 있는 logs를 제공합니다.<sup>[[6]](#references)</sup> 권한이 부여된 asset discovery 중에는 crt.sh를 사용하여 domain을 검색하세요.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL documentation - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL documentation - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - Textual Encodings of PKIX, PKCS, and CMS Structures](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL documentation - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - Certificate Search](https://crt.sh/)
- [8] [RFC 9525 - Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
