# 암호학

{{#include ../banners/hacktricks-training.md}}

이 섹션에서는 보안 테스트와 CTF에 활용할 수 있는 실용적인 암호학을 다룹니다. 일반적인 패턴을 파악하고, 적절한 도구를 선택하며, 알려진 공격을 적용하는 방법을 알아봅니다.

파일 안에 데이터를 숨기는 기법은 **Stego** 섹션을 참조하세요.

## 이 섹션의 활용 방법

먼저 primitive와 해당 매개변수를 파악합니다. 그런 다음 공격을 선택하기 전에 oracle, leak된 값, nonce 재사용 등 공격자가 제어하거나 관찰할 수 있는 요소를 확인합니다.

### CTF 워크플로

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### 대칭 암호화

{{#ref}}
symmetric/README.md
{{#endref}}

### 해시, MAC, KDF

{{#ref}}
hashes/README.md
{{#endref}}

### 공개 키 암호화

{{#ref}}
public-key/README.md
{{#endref}}

### TLS 및 인증서

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### 악성코드의 암호화

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### 기타

{{#ref}}
ctf-misc/README.md
{{#endref}}

## 빠른 설정

격리된 Python 환경을 만들고 자주 사용하는 패키지를 설치합니다. PyCryptodome 문서에서는 `pip`으로 `pycryptodome`을 설치하도록 안내하며, SageMath는 지원하는 각 플랫폼별로 별도의 설치 지침을 제공합니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```

SageMath는 대수, 격자, RSA 및 타원 곡선 계산에 자주 유용합니다.<sup>[[2]](#references)</sup>

## References

- [1] [PyCryptodome 문서 - 설치](https://www.pycryptodome.org/src/installation)
- [2] [SageMath 문서 - 설치 안내서](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}
