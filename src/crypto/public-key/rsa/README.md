# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

수집:

- `n`, `e`, `c` (그리고 추가 ciphertexts)
- 메시지 간 관계 (same plaintext? shared modulus? structured plaintext?)
- Any leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

그 다음 시도:

- Factorization check (Factordb / `sage: factor(n)` for small-ish)
- Low exponent patterns (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL) when something is almost known

## Common RSA attacks

### Common modulus

두 ciphertexts `c1, c2`가 같은 modulus `n` 아래에서 **same message**를 서로 다른 exponents `e1, e2`로 encrypt했고 (`gcd(e1,e2)=1`), 확장 유클리드 알고리즘으로 `m`을 복구할 수 있습니다:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

Example outline:

1. `(a, b) = xgcd(e1, e2)`를 계산해 `a*e1 + b*e2 = 1` 만들기
2. `a < 0`이면 `c1^a`를 `inv(c1)^{-a} mod n`으로 해석하기 (`b`도 동일)
3. 곱한 뒤 modulo `n`으로 reduce

### Shared primes across moduli

같은 challenge에서 나온 여러 RSA moduli가 있다면, prime을 공유하는지 확인하세요:

- `gcd(n1, n2) != 1`이면 치명적인 key-generation failure를 의미합니다.

이는 CTF에서 종종 "we generated many keys quickly" 또는 "bad randomness" 형태로 나타납니다.

### Sparse / short-sleeve moduli

일부 깨진 big-integer generators는 public modulus에 구조를 직접 leak합니다: 각 limb는 작은 random subfield만 포함하고 나머지 bits는 `0`입니다. 실제로는 `n` 전체에 걸쳐 **regularly spaced zero blocks**로 나타나며, 보통 32-bit 또는 128-bit limbs에 정렬됩니다.

빠른 확인:

- `n`을 hex로 덤프하고 고정된 stride로 반복되는 zero windows가 있는지 확인
- `n`을 limbs (`2^32`, `2^64`, `2^128`)로 다시 잘라 각 limb가 비정상적으로 작은지 검사
- 약한 host-key generation이 의심되면 **badkeys** 같은 tooling으로 public SSH/TLS keys를 audit

이것은 통계적 bias보다 더 심각합니다: private factors `p`와 `q` 둘 다 short-sleeved이면 modulus는 **쉽게 factor**될 수 있습니다.

### Polynomial factorization of structured RSA keys

의심되는 limb width `w`에 대해 modulus를 base `B = 2^w`로 씁니다:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

evaluation은 multiplicative이므로 `f_a(B) * f_c(B) = (f_a * f_c)(B)`입니다. factors 역시 sparse limb coefficients를 가진다면:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. limb width `w`를 guess합니다.
2. base `2^w`를 사용해 public modulus `n`을 `f_n(x)`로 변환합니다.
3. 정수 범위에서 `f_n(x)`를 factor합니다.
4. candidate factors를 다시 `B = 2^w`에서 evaluate합니다.
5. 어떤 candidate들이 `n`을 곱해 만드는지 verify합니다.

이 방법은 **normal RSA를 깨지 못합니다**. prime factors 자체가 매우 작고 highly structured limb coefficients를 가질 때만 동작합니다.

### Shifted limb leakage

Sparse bytes가 항상 각 limb의 low end에 정렬되는 것은 아닙니다. base-`2^w` 변환에서 큰 coefficients가 나오면, `2^i p`와 `2^j q`가 그 limb basis에서 sparse해지는 shifts `i,j`를 search하세요. product polynomial은 여전히 public modulus로부터 유도할 수 있고, factor한 뒤 원래 integer factors로 recombine할 수 있습니다.

### Implementation smell: byte-to-limb RNG bug

위험한 패턴은 **32-bit limbs**의 개수를 계산한 뒤, 그만큼의 **bytes**만 할당하고 그것을 limb array에 copy하는 것입니다:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
이렇게 하면 각 32-bit limb에 **8 bits의 entropy**만 들어가고, 마지막 limb에는 강제로 top bit가 설정됩니다. 그 결과 RSA prime은 공개 키만으로도 종종 식별되고 factor될 수 있습니다.

### Related DSA failure mode

같은 broken big-integer routine이 DSA private exponent 생성에 재사용되면, 공개 키 `y = g^x`가 `x`에 대한 **극도로 줄어든 구조화된** search space를 leak할 수 있습니다. limb pattern을 알게 되면, **baby-step giant-step** 같은 discrete-log 공격이 공개 파라미터에 대해 실용적으로 적용될 수 있습니다.

### Håstad broadcast / low exponent

같은 plaintext를 작은 `e`(보통 `e=3`)와 proper padding 없이 여러 수신자에게 보내면, CRT와 integer root를 통해 `m`을 복구할 수 있습니다.

Technical condition:

서로 pairwise-coprime인 moduli `n_i` 아래에서 같은 메시지의 ciphertext `e`개를 가지고 있다면:

- CRT를 사용해 곱 `N = Π n_i` 위에서 `M = m^e`를 복구
- 만약 `m^e < N`이면, `M`은 실제 정수 거듭제곱이고 `m = integer_root(M, e)`

### Wiener attack: small private exponent

`d`가 너무 작으면, continued fractions로 `e/n`에서 이를 복구할 수 있습니다.

### Textbook RSA pitfalls

다음이 보이면:

- OAEP/PSS 없음, raw modular exponentiation
- deterministic encryption

대수적 공격과 oracle abuse가 훨씬 더 가능해집니다.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

같은 modulus 아래의 두 ciphertext가 있고, 메시지들이 대수적으로 관련되어 있다면(예: `m2 = a*m1 + b`), Franklin–Reiter 같은 "related-message" 공격을 찾아보세요. 보통 다음이 필요합니다:

- same modulus `n`
- same exponent `e`
- plaintext 사이의 known relationship

실제로는 대개 Sage에서 modulus `n`에 대한 polynomials를 세팅하고 GCD를 계산해서 해결합니다.

## Lattices / Coppersmith

unknown이 작고, partial bits나 structured plaintext, 또는 가까운 관계가 있을 때 사용합니다.

Lattice methods(LLL/Coppersmith)는 부분 정보가 있을 때 나타납니다:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Related values 사이의 작은 unknown difference

### What to recognize

챌린지에서 보이는 전형적인 힌트:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

실제로는 LLL용 Sage와 해당 인스턴스에 맞는 known template를 사용하게 됩니다.

좋은 시작점:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
