# Public-Key Crypto

{{#include ../../banners/hacktricks-training.md}}


대부분의 CTF hard crypto는 여기서 다룹니다: RSA, ECC/ECDSA, lattices, 그리고 나쁜 randomness.

## Recommended tooling

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (빠른 factor 확인): http://factordb.com/

## RSA

`n,e,c`와 추가 힌트(shared modulus, low exponent, partial bits, related messages)가 있을 때 여기서 시작하세요.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

signatures가 관련된 경우, 어려운 수학을 가정하기 전에 nonce 문제(reuse/bias/leaks)를 먼저 테스트하세요.

### ECDSA nonce reuse / bias

두 signatures가 동일한 nonce `k`를 재사용하면 private key를 복구할 수 있습니다.

`k`가 동일하지 않더라도, signatures 간 nonce bits의 **bias/leakage**만으로도 lattice recovery가 가능할 수 있습니다(일반적인 CTF 주제).

`k`가 재사용된 경우의 technical recovery:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

동일한 `k`가 두 messages `m1, m2`에 재사용되어 signatures `(r, s1)` 및 `(r, s2)`가 생성된 경우:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

protocol이 points가 예상된 curve(또는 subgroup) 위에 있는지 검증하지 않으면, attacker가 weak group에서 연산을 수행하도록 유도하여 secrets를 복구할 수 있습니다.

Technical note:

- points가 on-curve에 있고 올바른 subgroup에 속하는지 검증하세요.
- 많은 CTF tasks에서는 이를 "server가 attacker가 선택한 point에 secret scalar를 곱하고 무언가를 반환하는 경우"로 모델링합니다.

### Tooling

- SageMath for curve arithmetic / lattices
- `ecdsa` Python library for parsing/verification

{{#include ../../banners/hacktricks-training.md}}
