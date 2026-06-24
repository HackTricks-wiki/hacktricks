# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Збирайте:

- `n`, `e`, `c` (та будь-які додаткові ciphertexts)
- Будь-які зв’язки між повідомленнями (same plaintext? shared modulus? structured plaintext?)
- Будь-які leak (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Потім спробуйте:

- Перевірку factorization (Factordb / `sage: factor(n)` для small-ish)
- Патерни low exponent (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL), коли щось майже відоме

## Common RSA attacks

### Common modulus

Якщо два ciphertexts `c1, c2` encrypt the **same message** під **тим самим modulus** `n`, але з різними exponents `e1, e2` (і `gcd(e1,e2)=1`), ви можете відновити `m` using the extended Euclidean algorithm:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

Приклад outline:

1. Обчисліть `(a, b) = xgcd(e1, e2)`, so `a*e1 + b*e2 = 1`
2. If `a < 0`, interpret `c1^a` as `inv(c1)^{-a} mod n` (same for `b`)
3. Multiply and reduce modulo `n`

### Shared primes across moduli

If you have multiple RSA moduli from the same challenge, check whether they share a prime:

- `gcd(n1, n2) != 1` implies a catastrophic key-generation failure.

This shows up frequently in CTFs as "we generated many keys quickly" or "bad randomness".

### Sparse / short-sleeve moduli

Some broken big-integer generators leak structure directly into the public modulus: each limb contains only a small random subfield and the rest of the bits are `0`. In practice this appears as **regularly spaced zero blocks** across `n`, often aligned to 32-bit or 128-bit limbs.

Quick checks:

- Dump `n` in hex and look for repeated zero windows at a fixed stride.
- Re-slice `n` as limbs (`2^32`, `2^64`, `2^128`) and inspect whether each limb is unusually small.
- Audit public SSH/TLS keys with tooling such as **badkeys** when you suspect weak host-key generation.

This is more serious than a statistical bias: if both private factors `p` and `q` are short-sleeved, the modulus may become **easy to factor**.

### Polynomial factorization of structured RSA keys

For a suspected limb width `w`, write the modulus in base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Because evaluation is multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. If the factors also have sparse limb coefficients, then:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. Guess the limb width `w`.
2. Convert the public modulus `n` into `f_n(x)` using base `2^w`.
3. Factor `f_n(x)` over the integers.
4. Evaluate candidate factors back at `B = 2^w`.
5. Verify which candidates multiply to `n`.

This **does not break normal RSA**. It only works when the prime factors themselves have very small, highly structured limb coefficients.

### Shifted limb leakage

The sparse bytes are not always aligned at the low end of each limb. If direct base-`2^w` conversion produces large coefficients, search for shifts `i,j` such that `2^i p` and `2^j q` become sparse in that limb basis. The product polynomial can still be derived from the public modulus, factored, and recombined into the original integer factors.

### Implementation smell: byte-to-limb RNG bug

A dangerous pattern is computing the number of **32-bit limbs**, allocating only that many **bytes**, and copying them into the limb array:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Це дає кожному 32-бітному limb лише **8 біт ентропії** плюс примусово встановлений верхній біт у останньому limb. Отримані RSA-прості числа часто можна розпізнати й факторизувати лише з public key.

### Пов’язаний режим збою DSA

Якщо той самий зламаний big-integer routine повторно використовується для генерації private exponent у DSA, public key `y = g^x` може розкрити **різко зменшений і структурований** search space для `x`. Коли шаблон limb уже відомий, discrete-log атаки на кшталт **baby-step giant-step** можуть стати практичними проти public parameters.

### Håstad broadcast / low exponent

Якщо той самий plaintext надсилається кільком отримувачам із малим `e` (часто `e=3`) і без правильного padding, можна відновити `m` через CRT та integer root.

Технічна умова:

Якщо у вас є `e` ciphertexts одного й того ж повідомлення під попарно взаємно простими moduli `n_i`:

- Використайте CRT, щоб відновити `M = m^e` над добутком `N = Π n_i`
- Якщо `m^e < N`, тоді `M` є справжнім цілим степенем, і `m = integer_root(M, e)`

### Wiener attack: small private exponent

Якщо `d` занадто малий, continued fractions можуть відновити його з `e/n`.

### Pitfalls textbook RSA

Якщо ви бачите:

- Немає OAEP/PSS, raw modular exponentiation
- Deterministic encryption

тоді algebraic attacks та oracle abuse стають набагато ймовірнішими.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Якщо ви бачите два ciphertexts під одним і тим самим modulus із повідомленнями, які algebraically related (наприклад, `m2 = a*m1 + b`), шукайте "related-message" attacks, такі як Franklin–Reiter. Зазвичай вони потребують:

- same modulus `n`
- same exponent `e`
- known relationship between plaintexts

На практиці це часто розв’язують у Sage, задаючи polynomials modulo `n` і обчислюючи GCD.

## Lattices / Coppersmith

Використовуйте це, коли маєте partial bits, structured plaintext або close relations, що роблять невідоме малим.

Lattice methods (LLL/Coppersmith) з’являються, коли є partial information:

- Частково відомий plaintext (structured message з невідомим хвостом)
- Частково відомі `p`/`q` (витекли старші біти)
- Малі невідомі різниці між related values

### Що розпізнавати

Типові підказки в задачах:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

На практиці ви використовуватимете Sage для LLL і готовий template для конкретного випадку.

Гарні стартові точки:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
