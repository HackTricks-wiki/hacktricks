# RSA 공격

{{#include ../../../banners/hacktricks-training.md}}

## 빠른 triage

수집할 항목:

- `n`, `e`, `c` (및 추가 ciphertext)
- 메시지 간 관계 (동일한 plaintext? shared modulus? 구조화된 plaintext?)
- 모든 leak (`p/q`의 일부, `d`의 비트, `dp/dq`, 알려진 padding)

그런 다음 시도:

- 인수분해 확인 (Factordb / 작은 값에는 `sage: factor(n)`)
- 낮은 지수 패턴 (`e=3`, broadcast)
- Common modulus / repeated primes
- 무언가가 거의 알려진 경우 lattice methods (Coppersmith/LLL)

## 일반적인 RSA 공격

### Common modulus

두 ciphertext `c1, c2`가 서로 다른 exponent `e1, e2` (및 `gcd(e1,e2)=1`)를 사용하지만 **동일한 modulus** `n`으로 **동일한 message**를 암호화한 경우, extended Euclidean algorithm을 사용해 `m`을 복구할 수 있습니다.

`m = c1^a * c2^b mod n` 여기서 `a*e1 + b*e2 = 1`입니다.

예시 개요:

1. `(a, b) = xgcd(e1, e2)`를 계산하여 `a*e1 + b*e2 = 1`을 얻습니다.
2. `a < 0`이면 `c1^a`를 `inv(c1)^{-a} mod n`으로 해석합니다 (`b`도 동일).
3. 곱한 뒤 `n`으로 나눈 나머지를 계산합니다.

### 모듈러 간 Shared primes

동일한 challenge에서 생성된 여러 RSA modulus가 있다면, prime을 공유하는지 확인합니다.

- `gcd(n1, n2) != 1`이면 치명적인 key-generation failure를 의미합니다.

이는 CTF에서 "많은 키를 빠르게 생성했다" 또는 "bad randomness"와 같은 상황으로 자주 나타납니다.

### Sparse / short-sleeve moduli

일부 손상된 big-integer generator는 public modulus에 구조를 직접 노출합니다. 각 limb에는 작은 random subfield만 포함되고 나머지 비트는 `0`입니다. 실제로는 `n` 전체에 걸쳐 **일정한 간격의 zero block**으로 나타나며, 보통 32-bit 또는 128-bit limb에 맞춰 정렬됩니다.<sup>[[1]](#references)</sup>

빠른 확인 방법:

- `n`을 hex로 덤프하고 고정된 간격으로 반복되는 zero window를 찾습니다.
- `n`을 limb (`2^32`, `2^64`, `2^128`) 단위로 다시 나누고 각 limb가 비정상적으로 작은지 확인합니다.
- weak host-key generation이 의심되면 **badkeys**와 같은 tooling으로 public SSH/TLS key를 audit합니다.<sup>[[2]](#references)[[3]](#references)</sup>

이는 단순한 statistical bias보다 심각합니다. private factor `p`와 `q`가 모두 short-sleeve이면 modulus가 **쉽게 factor될 수 있습니다**.<sup>[[1]](#references)</sup>

### 구조화된 RSA key의 Polynomial factorization

의심되는 limb width를 `w`라고 할 때, modulus를 base `B = 2^w`로 표현합니다.

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

evaluation은 multiplicative이므로 `f_a(B) * f_c(B) = (f_a * f_c)(B)`입니다. factor에도 sparse limb coefficient가 있다면 다음이 성립합니다.

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

공격 개요:

1. limb width `w`를 추정합니다.
2. base `2^w`를 사용하여 public modulus `n`을 `f_n(x)`로 변환합니다.
3. `f_n(x)`를 integers 위에서 factor합니다.
4. candidate factor를 `B = 2^w`에 대입합니다.
5. 어떤 candidate 조합이 `n`을 곱셈으로 재현하는지 확인합니다.

이는 **일반적인 RSA를 break하지 않습니다**. prime factor 자체가 매우 작고 고도로 구조화된 limb coefficient를 가질 때만 동작합니다.<sup>[[1]](#references)</sup>

### Shifted limb leakage

sparse byte가 항상 각 limb의 low end에 정렬되는 것은 아닙니다. 직접 base-`2^w` 변환을 수행했을 때 coefficient가 크다면, 해당 limb basis에서 `2^i p`와 `2^j q`가 sparse해지는 shift `i,j`를 탐색합니다. Product polynomial은 여전히 public modulus에서 도출하고 factor한 뒤, 원래의 integer factor로 다시 조합할 수 있습니다.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

위험한 패턴은 **32-bit limb**의 개수를 계산하고, 그만큼의 **byte**만 할당한 다음 이를 limb array에 복사하는 것입니다:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
각 32비트 limb에는 **8비트의 entropy**와 마지막 limb에 강제로 설정된 상위 비트만 포함됩니다. 그 결과 생성된 RSA 소수는 public key만으로도 식별하고 인수분해할 수 있는 경우가 많습니다.<sup>[[1]](#references)</sup>

### 관련 DSA failure mode

동일한 잘못된 big-integer routine이 DSA private exponent 생성에도 재사용되면, public key `y = g^x`에서 `x`에 대한 **극도로 축소되고 구조화된** search space가 leak될 수 있습니다. limb pattern을 알고 있다면 **baby-step giant-step** 같은 discrete-log attacks가 public parameters를 대상으로 실용적이 될 수 있습니다.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

동일한 plaintext가 작은 `e`(대개 `e=3`)를 사용하는 여러 recipient에게 proper padding 없이 전송되었다면, CRT와 integer root를 통해 `m`을 복구할 수 있습니다.

Technical condition:

동일한 message의 `e`개 ciphertext가 서로 pairwise-coprime인 modulus `n_i` 아래에 있다면:

- CRT를 사용해 곱 `N = Π n_i`에 대해 `M = m^e`를 복구합니다.
- `m^e < N`이면 `M`은 실제 integer power이고, `m = integer_root(M, e)`입니다.

### Wiener attack: small private exponent

`d`가 너무 작으면 continued fractions를 통해 `e/n`에서 이를 복구할 수 있습니다.

### Textbook RSA pitfalls

다음과 같은 경우:

- OAEP/PSS 없음, raw modular exponentiation
- Deterministic encryption

algebraic attacks와 oracle abuse가 발생할 가능성이 훨씬 커집니다.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

동일한 modulus 아래에서 서로 algebraically related된 messages(예: `m2 = a*m1 + b`)를 사용하는 두 ciphertexts가 보이면 Franklin–Reiter 같은 "related-message" attacks를 살펴보세요. 일반적으로 다음 조건이 필요합니다:

- 동일한 modulus `n`
- 동일한 exponent `e`
- plaintexts 간의 알려진 relationship

실제로는 `n`을 법으로 하는 polynomials를 설정하고 GCD를 계산하여 Sage로 해결하는 경우가 많습니다.

## Lattices / Coppersmith

partial bits, structured plaintext 또는 unknown을 작게 만드는 close relations가 있을 때 사용합니다.

Lattice methods (LLL/Coppersmith)는 partial information이 있을 때마다 등장합니다:

- Partially known plaintext (unknown tail이 있는 structured message)
- Partially known `p`/`q` (high bits가 leak됨)
- Related values 사이의 small unknown differences

### What to recognize

Challenges에서 나타나는 일반적인 hints:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

실제로는 LLL에 Sage를 사용하고 특정 instance에 맞는 known template을 사용합니다.

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - polynomials를 사용한 "short-sleeve" RSA keys factoring](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
