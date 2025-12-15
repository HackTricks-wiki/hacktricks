# RSA 공격

{{#include ../../../banners/hacktricks-training.md}}

## 빠른 초기 평가

수집:

- `n`, `e`, `c` (and any additional ciphertexts)
- 메시지 간의 관계 (same plaintext? shared modulus? structured plaintext?)
- Any leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

그 다음 시도:

- 인수분해 확인 (Factordb / `sage: factor(n)` — 작은 규모의 경우)
- 낮은 지수 패턴 (`e=3`, broadcast)
- 공통 modulus / 반복된 primes
- 무언가 거의 알려져 있을 때 Lattice 방법 (Coppersmith/LLL)

## 일반적인 RSA 공격

### Common modulus

만약 두 개의 암호문 `c1, c2`가 **같은 메시지**를 동일한 **modulus** `n` 아래 서로 다른 지수 `e1, e2` (그리고 `gcd(e1,e2)=1`)로 암호화했다면, 확장 유클리드 알고리즘을 사용해 `m`을 복구할 수 있습니다:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

예시 개요:

1. `(a, b) = xgcd(e1, e2)` 를 계산해 `a*e1 + b*e2 = 1` 을 만든다
2. 만약 `a < 0` 라면, `c1^a` 를 `inv(c1)^{-a} mod n` 로 해석한다 (`b` 도 동일)
3. 곱한 후 `n`으로 나머지를 취한다

### 여러 moduli에서의 공유된 primes

동일한 챌린지에서 여러 RSA moduli를 얻었다면, 이들이 prime을 공유하는지 확인하세요:

- `gcd(n1, n2) != 1` 은 치명적인 키 생성 실패를 의미합니다.

이는 CTF에서 자주 나타나며 "we generated many keys quickly" 또는 "bad randomness" 같은 경우가 많습니다.

### Håstad broadcast / low exponent

If the same plaintext is sent to multiple recipients with small `e` (often `e=3`) and no proper padding, you can recover `m` via CRT and integer root.

기술적 조건:

만약 서로 소인 pairwise-coprime moduli `n_i` 아래 동일한 메시지에 대한 `e` 개의 암호문이 있다면:

- CRT를 사용해 `N = Π n_i` 위에서 `M = m^e` 를 복원한다
- 만약 `m^e < N` 이면, `M` 은 진짜 정수 거듭제곱이고 `m = integer_root(M, e)` 이다

### Wiener attack: small private exponent

If `d` is too small, continued fractions can recover it from `e/n`.

### Textbook RSA의 함정

만약 다음을 보면:

- No OAEP/PSS, raw modular exponentiation
- Deterministic encryption

그러면 algebraic attacks와 oracle abuse가 훨씬 더 가능성이 높아집니다.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## 관련 메시지 패턴

같은 modulus 아래에서 메시지들이 대수적으로 관련되어 있다면 (예: `m2 = a*m1 + b`), Franklin–Reiter와 같은 "related-message" 공격을 찾아보세요. 이들은 보통 다음을 필요로 합니다:

- 같은 modulus `n`
- 같은 exponent `e`
- plaintexts 간의 알려진 관계

실제로는 Sage에서 `n`을 모듈로 하는 다항식을 설정하고 GCD를 계산하여 해결하는 경우가 많습니다.

## 격자 / Coppersmith

미지값의 일부 비트가 알려져 있거나, 구조화된 plaintext, 또는 미지값이 작아지는 근접한 관계가 있을 때 이 방법을 사용하세요.

격자 방법(LLL/Coppersmith)은 부분 정보가 있을 때 자주 등장합니다:

- 부분적으로 알려진 plaintext (미지의 꼬리를 가진 구조화된 메시지)
- 부분적으로 알려진 `p`/`q` (상위 비트 leaked)
- 관련 값들 사이의 작은 미지 차이

### 확인해야 할 사항

챌린지에서 자주 나오는 힌트:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### 도구

실제로는 LLL을 위해 Sage를 사용하고 특정 인스턴스에 맞는 템플릿을 사용합니다.

시작점:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
