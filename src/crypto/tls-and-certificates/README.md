# TLS 및 인증서

{{#include ../../banners/hacktricks-training.md}}

이 섹션은 **X.509 파싱, 포맷, 변환 및 일반적인 실수**에 관한 것입니다.

## X.509: 파싱, 포맷 및 일반적인 실수

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

### 형식 및 변환

- PEM (Base64, BEGIN/END 헤더 포함)
- DER (바이너리)
- PKCS#7 (`.p7b`) (인증서 체인, 개인 키 없음)
- PKCS#12 (`.pfx/.p12`) (인증서 + 개인 키 + 체인)

변환:
```bash
openssl x509 -in cert.cer -outform PEM -out cert.pem
openssl x509 -in cert.pem -outform der -out cert.der
openssl pkcs12 -in file.pfx -out out.pem
```
### 일반적인 공격 벡터

- 사용자 제공 루트 신뢰 / 체인 검증 누락
- 약한 서명 알고리즘(레거시)
- 이름 제약 / SAN 파싱 버그(구현별)
- Confused deputy issues with client-certificate authentication misbinding

### CT logs

- [https://crt.sh/](https://crt.sh/)

{{#include ../../banners/hacktricks-training.md}}
