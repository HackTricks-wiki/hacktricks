# 암호학

{{#include ../banners/hacktricks-training.md}}

이 섹션은 **hacking/CTF를 위한 실전 암호학**에 초점을 맞춥니다. 일반적인 패턴을 빠르게 인식하고, 적절한 도구를 선택하며, 알려진 공격을 적용하는 방법을 다룹니다.

파일 안에 데이터를 숨기는 것이 목적이라면 **Stego** 섹션으로 이동하세요.

## 이 섹션 사용 방법

Crypto challenge에서는 속도가 중요합니다. primitive를 분류하고, 자신이 제어할 수 있는 것(oracle/leak/nonce reuse)을 식별한 다음, 알려진 공격 템플릿을 적용하세요.

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### 대칭 암호
{{#ref}}
symmetric/README.md
{{#endref}}

### 해시, MAC, KDF
{{#ref}}
hashes/README.md
{{#endref}}

### 공개키 암호
{{#ref}}
public-key/README.md
{{#endref}}

### TLS 및 인증서
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### malware에서의 암호학
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### 기타
{{#ref}}
ctf-misc/README.md
{{#endref}}

## 빠른 설정

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- 라이브러리: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (lattice/RSA/ECC에 자주 필수): <https://www.sagemath.org/>

{{#include ../banners/hacktricks-training.md}}
