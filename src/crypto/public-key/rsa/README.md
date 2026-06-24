# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Kusanya:

- `n`, `e`, `c` (na ciphertexts zozote za ziada)
- Mahusiano yoyote kati ya messages (same plaintext? shared modulus? structured plaintext?)
- Leaks zozote (partial `p/q`, bits za `d`, `dp/dq`, known padding)

Kisha jaribu:

- Factorization check (Factordb / `sage: factor(n)` kwa small-ish)
- Low exponent patterns (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL) wakati kitu kiko karibu kujulikana

## Common RSA attacks

### Common modulus

Ikiwa ciphertexts mbili `c1, c2` zinaencrypt **same message** chini ya **same modulus** `n` lakini zikiwa na exponents tofauti `e1, e2` (na `gcd(e1,e2)=1`), unaweza kurecover `m` kwa kutumia extended Euclidean algorithm:

`m = c1^a * c2^b mod n` ambapo `a*e1 + b*e2 = 1`.

Mfano wa hatua:

1. Compute `(a, b) = xgcd(e1, e2)` hivyo `a*e1 + b*e2 = 1`
2. Ikiwa `a < 0`, tafsiri `c1^a` kama `inv(c1)^{-a} mod n` (vilevile kwa `b`)
3. Zidisha na punguza modulo `n`

### Shared primes across moduli

Ikiwa una RSA moduli nyingi kutoka challenge moja, angalia kama zinashare prime:

- `gcd(n1, n2) != 1` inaashiria catastrophic key-generation failure.

Hii huonekana mara kwa mara kwenye CTFs kama "we generated many keys quickly" au "bad randomness".

### Sparse / short-sleeve moduli

Baadhi ya broken big-integer generators hu-leak structure moja kwa moja kwenye public modulus: kila limb ina random subfield ndogo tu na sehemu nyingine ya bits ni `0`. Kwa practice hii huonekana kama **regularly spaced zero blocks** kwenye `n`, mara nyingi zikiwa aligned kwa 32-bit au 128-bit limbs.

Quick checks:

- Dump `n` kwa hex na uangalie repeated zero windows kwa fixed stride.
- Re-slice `n` kama limbs (`2^32`, `2^64`, `2^128`) na inspect kama kila limb ni unusually small.
- Audit public SSH/TLS keys kwa tooling kama **badkeys** unaposhuku weak host-key generation.

Hii ni serious zaidi kuliko statistical bias: ikiwa private factors `p` na `q` zote ni short-sleeved, modulus inaweza kuwa **easy to factor**.

### Polynomial factorization of structured RSA keys

Kwa suspected limb width `w`, andika modulus katika base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Kwa sababu evaluation ni multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Ikiwa factors pia zina sparse limb coefficients, basi:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. Guess limb width `w`.
2. Convert public modulus `n` kuwa `f_n(x)` kwa kutumia base `2^w`.
3. Factor `f_n(x)` over the integers.
4. Evaluate candidate factors back at `B = 2^w`.
5. Verify ni candidates gani zinamultiply kuwa `n`.

Hii **haivunji normal RSA**. Inafanya kazi tu wakati prime factors wenyewe wana coefficients za limb ndogo sana, zenye structure kubwa.

### Shifted limb leakage

Sparse bytes si lazima ziwe aligned mwisho wa chini wa kila limb. Ikiwa direct base-`2^w` conversion inatoa large coefficients, tafuta shifts `i,j` ili `2^i p` na `2^j q` ziwe sparse kwenye limb basis hiyo. Product polynomial bado inaweza kutolewa kutoka public modulus, kufactored, na kuunganishwa tena kuwa original integer factors.

### Implementation smell: byte-to-limb RNG bug

Pattern hatari ni kuhesabu idadi ya **32-bit limbs**, kisha kuallocate only that many **bytes**, na kuzicopy ndani ya limb array:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Hii hutoa kila limb ya 32-bit bits **8 tu za entropy** pamoja na forced top bit kwenye limb ya mwisho. RSA primes zinazotokana na hili mara nyingi zinaweza kutambuliwa na kufactoriwa kutoka public key pekee.

### Related DSA failure mode

Ikiwa same broken big-integer routine inatumika tena kwa DSA private exponent generation, public key `y = g^x` inaweza kuvuja search space **iliyopunguzwa sana na yenye muundo** kwa `x`. Mara tu limb pattern inapojulikana, discrete-log attacks kama **baby-step giant-step** zinaweza kuwa practical dhidi ya public parameters.

### Håstad broadcast / low exponent

Ikiwa same plaintext inatumwa kwa recipients wengi wenye small `e` (mara nyingi `e=3`) na hakuna proper padding, unaweza kurecover `m` kupitia CRT na integer root.

Technical condition:

If you have `e` ciphertexts of the same message under pairwise-coprime moduli `n_i`:

- Use CRT to recover `M = m^e` over the product `N = Π n_i`
- If `m^e < N`, then `M` is the true integer power, and `m = integer_root(M, e)`

### Wiener attack: small private exponent

If `d` is too small, continued fractions can recover it from `e/n`.

### Textbook RSA pitfalls

If you see:

- No OAEP/PSS, raw modular exponentiation
- Deterministic encryption

then algebraic attacks and oracle abuse become much more likely.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

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

### What to recognize

Typical hints in challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

In practice you’ll use Sage for LLL and a known template for the specific instance.

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
