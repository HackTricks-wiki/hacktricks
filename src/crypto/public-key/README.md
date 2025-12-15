# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}

대부분의 CTF 고난도 crypto는 여기로 모입니다: RSA, ECC/ECDSA, lattices, 그리고 약한 randomness.

## Recommended tooling

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (quick factor checks): http://factordb.com/

## RSA

`n,e,c`와 몇 가지 추가 힌트(공유된 modulus, low exponent, partial bits, 관련 메시지)가 있을 때 여기서 시작하세요.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

서명이 관여된 경우, 어려운 수학을 가정하기 전에 먼저 nonce 문제(reuse/bias/leaks)를 테스트하세요.

### ECDSA nonce reuse / bias

두 서명이 동일한 nonce `k`를 재사용하면 private key를 복원할 수 있습니다.

비록 `k`가 완전히 같지 않더라도, 서명들 간의 nonce 비트에 대한 **bias/leakage**는 lattice 복구에 충분할 수 있습니다(흔한 CTF 테마).

기술적 복구 (k 재사용 시):

ECDSA 서명 방정식 (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

동일한 `k`가 두 메시지 `m1, m2`에 대해 재사용되어 서명 `(r, s1)` 및 `(r, s2)`를 생성하면:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

프로토콜이 포인트가 기대하는 곡선(on-curve) 위에 있고 올바른 subgroup에 속하는지를 검증하지 않으면, 공격자는 약한 그룹에서 연산을 강제해 비밀을 회수할 수 있습니다.

기술적 메모:

- 포인트가 on-curve이며 올바른 subgroup에 속하는지 검증하세요.
- 많은 CTF 과제는 이를 "server가 공격자가 선택한 포인트에 secret scalar를 곱하고 무언가를 반환"하는 식으로 모델링합니다.

### Tooling

- SageMath for curve arithmetic / lattices
- `ecdsa` Python library for parsing/verification

{{#include ../../banners/hacktricks-training.md}}
