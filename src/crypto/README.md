# Crypto

{{#include ../banners/hacktricks-training.md}}

이 섹션은 **해킹/CTFs를 위한 실무 암호학**에 중점을 둡니다: 일반적인 패턴을 빠르게 인식하고, 적절한 도구를 선택하며, 알려진 공격을 적용하는 방법을 다룹니다.

파일 안에 데이터를 숨기는 목적이라면 **Stego** 섹션으로 가세요.

## 이 섹션 사용 방법

Crypto 챌린지에서는 속도가 중요합니다: primitive를 분류하고, 제어하는 요소(oracle/leak/nonce reuse)를 식별한 뒤, 알려진 공격 템플릿을 적용하세요.

### CTF workflow
{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric crypto
{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, and KDFs
{{#ref}}
hashes/README.md
{{#endref}}

### Public-key crypto
{{#ref}}
public-key/README.md
{{#endref}}

### TLS and certificates
{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Crypto in malware
{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Misc
{{#ref}}
ctf-misc/README.md
{{#endref}}

## 빠른 설정

- Python: `python3 -m venv .venv && source .venv/bin/activate`
- Libraries: `pip install pycryptodome gmpy2 sympy pwntools`
- SageMath (종종 lattice/RSA/ECC에 필수적임): https://www.sagemath.org/

{{#include ../banners/hacktricks-training.md}}
