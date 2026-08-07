# Mashambulizi ya RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triage ya haraka

Kusanya:

- `n`, `e`, `c` (na ciphertext nyingine zozote za ziada)
- Mahusiano yoyote kati ya messages (plaintext ileile? modulus iliyoshirikiwa? plaintext yenye muundo?)
- Leaks zozote (`p/q` za sehemu, bits za `d`, `dp/dq`, padding inayojulikana)

Kisha jaribu:

- Ukaguzi wa factorization (Factordb / `sage: factor(n)` kwa namba ndogo kiasi)
- Mifumo ya low exponent (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL) wakati kitu kinakaribia kujulikana

## Mashambulizi ya kawaida ya RSA

### Common modulus

Ikiwa ciphertext mbili `c1, c2` zinasimba **message ileile** kwa kutumia **modulus ileile** `n` lakini zikiwa na exponents tofauti `e1, e2` (na `gcd(e1,e2)=1`), unaweza kurejesha `m` kwa kutumia extended Euclidean algorithm:

`m = c1^a * c2^b mod n` ambapo `a*e1 + b*e2 = 1`.

Muhtasari wa mfano:

1. Hesabu `(a, b) = xgcd(e1, e2)` ili `a*e1 + b*e2 = 1`
2. Ikiwa `a < 0`, tafsiri `c1^a` kama `inv(c1)^{-a} mod n` (vivyo hivyo kwa `b`)
3. Zidisha na punguza modulo `n`

### Shared primes across moduli

Ikiwa una RSA moduli nyingi kutoka challenge ileile, angalia kama zinashiriki prime:

- `gcd(n1, n2) != 1` inaashiria hitilafu kubwa katika utengenezaji wa key.

Hili hujitokeza mara kwa mara katika CTFs kama "tulitengeneza keys nyingi kwa haraka" au "randomness mbaya".

### Sparse / short-sleeve moduli

Baadhi ya big-integer generators zilizoharibika huvuja muundo moja kwa moja kwenye public modulus: kila limb huwa na subfield ndogo ya random na sehemu iliyobaki ya bits huwa `0`. Kwa vitendo, hii huonekana kama **blocks za zero zilizotengana kwa vipindi vya kawaida** ndani ya `n`, mara nyingi zikiwa zimepangwa kulingana na limbs za 32-bit au 128-bit.<sup>[[1]](#references)</sup>

Ukaguzi wa haraka:

- Dump `n` katika hex na utafute zero windows zinazorudiwa kwa stride ileile.
- Gawa tena `n` kuwa limbs (`2^32`, `2^64`, `2^128`) na ukague kama kila limb ni ndogo isivyo kawaida.
- Kagua public SSH/TLS keys kwa tooling kama **badkeys** unaposhuku utengenezaji dhaifu wa host-key.<sup>[[2]](#references)[[3]](#references)</sup>

Hili ni kubwa zaidi kuliko statistical bias: ikiwa private factors `p` na `q` zote ni short-sleeved, modulus inaweza kuwa **rahisi kufactor**.<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

Kwa limb width `w` inayoshukiwa, andika modulus katika base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Kwa sababu evaluation ni multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Ikiwa factors pia zina sparse limb coefficients, basi:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Muhtasari wa attack:

1. Kisia limb width `w`.
2. Geuza public modulus `n` kuwa `f_n(x)` kwa kutumia base `2^w`.
3. Factor `f_n(x)` over the integers.
4. Evaluate candidate factors kurudi kwenye `B = 2^w`.
5. Thibitisha ni candidates zipi zinazozidishwa kupata `n`.

Hii **haivunji RSA ya kawaida**. Inafanya kazi tu wakati prime factors zenyewe zina limb coefficients ndogo sana na zenye muundo maalum.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse bytes si mara zote hupangwa kwenye mwisho wa chini wa kila limb. Ikiwa direct base-`2^w` conversion inazalisha coefficients kubwa, tafuta shifts `i,j` ambapo `2^i p` na `2^j q` huwa sparse katika limb basis hiyo. Product polynomial bado inaweza kutolewa kutoka kwenye public modulus, kufactorishwa, na kuunganishwa tena kuwa integer factors za awali.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

Muundo hatari ni kukokotoa idadi ya **32-bit limbs**, kutenga **bytes** chache tu za idadi hiyo, na kuzinakili kwenye limb array:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
This gives each 32-bit limb only **8 bits of entropy** plus a forced top bit in the last limb. The resulting RSA primes can often be recognized and factored from the public key alone.<sup>[[1]](#references)</sup>

### Hali ya hitilafu inayohusiana na DSA

If the same broken big-integer routine is reused for DSA private exponent generation, the public key `y = g^x` may leak a **dramatically reduced and structured** search space for `x`. Once the limb pattern is known, discrete-log attacks such as **baby-step giant-step** can become practical against the public parameters.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

If the same plaintext is sent to multiple recipients with small `e` (often `e=3`) and no proper padding, you can recover `m` via CRT and integer root.

Technical condition:

If you have `e` ciphertexts of the same message under pairwise-coprime moduli `n_i`:

- Use CRT to recover `M = m^e` over the product `N = Π n_i`
- If `m^e < N`, then `M` is the true integer power, and `m = integer_root(M, e)`

### Wiener attack: small private exponent

If `d` is too small, continued fractions can recover it from `e/n`.

### Pitfalls za Textbook RSA

If you see:

- No OAEP/PSS, raw modular exponentiation
- Deterministic encryption

then algebraic attacks and oracle abuse become much more likely.

### Zana

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Miundo ya Related-message

If you see two ciphertexts under the same modulus with messages that are algebraically related (e.g., `m2 = a*m1 + b`), look for "related-message" attacks such as Franklin–Reiter. These typically require:

- same modulus `n`
- same exponent `e`
- known relationship between plaintexts

In practice this is often solved with Sage by setting up polynomials modulo `n` and computing a GCD.

## Lattices / Coppersmith

Reach for this when you have partial bits, structured plaintext, or close relations that make the unknown small.

Lattice methods (LLL/Coppersmith) show up whenever you have partial information:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Small unknown differences between related values

### Cha kutambua

Typical hints in challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

In practice you’ll use Sage for LLL and a known template for the specific instance.

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## Marejeo

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
