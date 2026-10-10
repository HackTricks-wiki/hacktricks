# TLS 및 인증서

{{#include ../../banners/hacktricks-training.md}}

이 섹션에서는 X.509 검사, 인코딩, 변환 및 보안과 관련된 검증 실수를 다룹니다.

## X.509 파싱

OpenSSL은 인증서의 디코딩된 필드를 출력할 수 있으며, `asn1parse`는 기본 ASN.1 구조를 보여줍니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```

최소한 다음을 검토하세요.

- subject, issuer, Subject Alternative Name (SAN);
- key usage 및 extended key usage;
- basic constraints 및 path-length constraints;
- 유효 기간인 `notBefore` 및 `notAfter`;
- 공개 키 매개변수 및 서명 알고리즘.

MD5 또는 SHA-1 기반 인증서 서명과 같은 레거시 서명은 특히 중요한 점검 결과입니다. 다만 정확한 허용 여부와 영향은 검증자 및 신뢰 컨텍스트에 따라 달라집니다.<sup>[[3]](#references)</sup>

RFC 5280은 Internet X.509 프로파일과 SAN, key usage, name constraints, basic constraints 등의 확장에 대한 처리 규칙을 정의합니다.<sup>[[3]](#references)</sup>

## Encodings and Containers

- **PEM 스타일 텍스트 인코딩:** `BEGIN`과 `END` 경계 사이의 Base64 데이터.
- **DER:** 바이너리 Distinguished Encoding Rules 표현.
- **PKCS#7/CMS (`.p7b`):** 일반적으로 인증서와 인증서 체인을 담지만, 개인 키는 담지 않습니다.
- **PKCS#12 (`.p12` 또는 `.pfx`):** 개인 키, 인증서, 지원 인증서를 담을 수 있습니다.

RFC 7468은 PKIX, PKCS, CMS 구조에 사용되는 텍스트 인코딩을 규정합니다. OpenSSL의 `pkcs12` 명령은 PKCS#12 파일을 생성하고 파싱합니다.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform DER -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```

`out.pem`은 민감한 파일로 취급하세요. `-nokeys`와 같은 옵션을 사용하지 않으면 출력에 private key material이 포함될 수 있습니다.<sup>[[5]](#references)</sup>

## 보안 검토 체크리스트

validator 또는 trust decision을 검토할 때 RFC 5280의 인증서 처리 요구사항을 적용하세요.<sup>[[3]](#references)</sup>

- 명시적으로 신뢰하는 anchor까지 전체 chain을 검증하세요. 사용자가 제공한 root를 암묵적으로 신뢰하지 마세요.
- SAN 값을 기준으로 hostname 또는 service identity를 확인하세요.<sup>[[8]](#references)</sup>
- basic constraints, name constraints, key usage, extended key usage를 적용하세요.
- 만료되었거나 아직 유효하지 않은 인증서와 허용되지 않는 key 또는 signature algorithm을 거부하세요.
- client certificate의 identity를 올바른 application account 및 authorization context에 연결하세요.

## Certificate Transparency Logs

Certificate Transparency는 발급된 인증서를 공개적으로 감사할 수 있는 log를 제공합니다.<sup>[[6]](#references)</sup> 승인된 asset discovery 중에는 crt.sh에서 도메인을 검색하세요.<sup>[[7]](#references)</sup>

## References

- [1] [OpenSSL 문서 - `openssl-x509`](https://docs.openssl.org/master/man1/openssl-x509/)
- [2] [OpenSSL 문서 - `openssl-asn1parse`](https://docs.openssl.org/master/man1/openssl-asn1parse/)
- [3] [RFC 5280 - Internet X.509 공개 키 인프라 인증서 및 CRL 프로파일](https://www.rfc-editor.org/rfc/rfc5280)
- [4] [RFC 7468 - PKIX, PKCS 및 CMS 구조의 텍스트 인코딩](https://www.rfc-editor.org/rfc/rfc7468)
- [5] [OpenSSL 문서 - `openssl-pkcs12`](https://docs.openssl.org/master/man1/openssl-pkcs12/)
- [6] [RFC 9162 - Certificate Transparency 버전 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [7] [crt.sh - 인증서 검색](https://crt.sh/)
- [8] [RFC 9525 - TLS의 Service Identity](https://www.rfc-editor.org/rfc/rfc9525)
{{#include ../../banners/hacktricks-training.md}}
