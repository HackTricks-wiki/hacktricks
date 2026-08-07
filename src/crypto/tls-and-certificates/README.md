# TLS 및 인증서

{{#include ../../banners/hacktricks-training.md}}


이 영역에서는 **X.509 파싱, 형식, 변환 및 일반적인 실수**를 다룹니다.

## X.509: 파싱, 형식 및 일반적인 실수

### 빠른 파싱
```bash
openssl x509 -in cert.pem -noout -text
openssl asn1parse -in cert.pem
```
확인할 유용한 필드:

- Subject / Issuer / SAN
- Key Usage / EKU
- Basic Constraints (CA인가?)
- Validity window (NotBefore/NotAfter)
- Signature algorithm (MD5? SHA1?)

### Formats & conversion

- PEM (BEGIN/END 헤더가 포함된 Base64)
- DER (binary)
- PKCS#7 (`.p7b`) (cert chain, private key 없음)
- PKCS#12 (`.pfx/.p12`) (cert + private key + chain)

Conversions:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### 일반적인 공격 관점

- 사용자 제공 root 신뢰 / 체인 검증 누락
- 취약한 signature algorithms (legacy)
- Name constraints / SAN parsing bugs (구현별)
- client-certificate authentication misbinding으로 인한 confused deputy 문제

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
