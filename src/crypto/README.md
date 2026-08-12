# Crypto

{{#include ../banners/hacktricks-training.md}}

이 섹션에서는 security testing 및 CTF를 위한 practical cryptography를 다룹니다. 일반적인 패턴을 인식하고, 적절한 tools를 선택하며, 알려진 attacks를 적용하는 방법을 설명합니다.

파일 내부에 데이터를 숨기는 techniques는 **Stego** 섹션을 참고하세요.

## 이 섹션 사용 방법

먼저 primitive와 해당 parameters를 식별하세요. 그런 다음 attack을 선택하기 전에 attacker가 제어하거나 관찰할 수 있는 대상이 oracle, leaked value 또는 nonce reuse인지 확인하세요.

### CTF workflow

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Symmetric cryptography

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs, and KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Public-key cryptography

{{#ref}}
public-key/README.md
{{#endref}}

### TLS and certificates

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Cryptography in malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Miscellaneous

{{#ref}}
ctf-misc/README.md
{{#endref}}

## 빠른 설정

격리된 Python environment를 생성하고 일반적으로 사용하는 packages를 설치하세요. PyCryptodome documentation에서는 `pip`를 사용하여 `pycryptodome`을 설치할 것을 권장하며, SageMath는 지원되는 각 platform에 대한 별도의 installation guidance를 제공합니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath는 대수학, lattice, RSA 및 elliptic-curve 계산에 자주 유용합니다.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome documentation - 설치](https://www.pycryptodome.org/src/installation)
- [2] [SageMath documentation - 설치 가이드](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
