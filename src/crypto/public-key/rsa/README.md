# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Versamel:

- `n`, `e`, `c` (en enige addisionele ciphertexts)
- Enige verwantskappe tussen messages (selfde plaintext? gedeelde modulus? structured plaintext?)
- Enige leaks (gedeeltelike `p/q`, bits van `d`, `dp/dq`, bekende padding)

Probeer dan:

- Factorization check (Factordb / `sage: factor(n)` vir klein-ish)
- Low exponent patterns (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL) when something is almost known

## Common RSA attacks

### Common modulus

As twee ciphertexts `c1, c2` dieselfde message onder dieselfde modulus `n` en met verskillende exponents `e1, e2` en `gcd(e1,e2)=1` encrypt, kan jy `m` recover met die extended Euclidean algorithm:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

Voorbeeld-oorsig:

1. Compute `(a, b) = xgcd(e1, e2)` so `a*e1 + b*e2 = 1`
2. If `a < 0`, interpreteer `c1^a` as `inv(c1)^{-a} mod n` (selfde vir `b`)
3. Vermenigvuldig en reduce modulo `n`

### Shared primes across moduli

As jy multiple RSA moduli van dieselfde challenge het, check of hulle 'n prime deel:

- `gcd(n1, n2) != 1` implies 'n catastrophic key-generation failure.

Dit kom gereeld voor in CTFs as "we generated many keys quickly" of "bad randomness".

### Sparse / short-sleeve moduli

Sommige broken big-integer generators leak struktuur direk in die public modulus: elke limb bevat slegs 'n klein random subfield en die res van die bits is `0`. In practice verskyn dit as **regularly spaced zero blocks** oor `n`, dikwels aligned tot 32-bit of 128-bit limbs.

Quick checks:

- Dump `n` in hex en kyk vir repeated zero windows by 'n fixed stride.
- Re-slice `n` as limbs (`2^32`, `2^64`, `2^128`) en inspecteer of elke limb unusually small is.
- Audit public SSH/TLS keys met tooling soos **badkeys** wanneer jy weak host-key generation vermoed.

Dit is ernstiger as 'n statistical bias: as albei private factors `p` en `q` short-sleeved is, kan die modulus **easy to factor** word.

### Polynomial factorization of structured RSA keys

Vir 'n suspected limb width `w`, skryf die modulus in base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Omdat evaluation multiplicative is, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. As die factors ook sparse limb coefficients het, dan:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. Raai die limb width `w`.
2. Convert die public modulus `n` na `f_n(x)` using base `2^w`.
3. Factor `f_n(x)` oor die integers.
4. Evaluate candidate factors terug by `B = 2^w`.
5. Verify watter candidates vermenigvuldig tot `n`.

Dit **breek nie normal RSA** nie. Dit werk slegs wanneer die prime factors self baie small, highly structured limb coefficients het.

### Shifted limb leakage

Die sparse bytes is nie altyd aligned by die low end van elke limb nie. As direkte base-`2^w` conversion groot coefficients produseer, search vir shifts `i,j` sodat `2^i p` en `2^j q` sparse word in daardie limb basis. Die product polynomial kan steeds uit die public modulus derived word, gefactoriseer word, en recombined word in die original integer factors.

### Implementation smell: byte-to-limb RNG bug

'n Dangerous pattern is om die aantal **32-bit limbs** te bereken, slegs soveel **bytes** te allokeer, en hulle in die limb array te kopieer:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Dit gee elke 32-bis limb slegs **8 bis van entropie** plus ’n geforseerde boonste bit in die laaste limb. Die resulterende RSA-prime kan dikwels net aan die publieke sleutel herken en gefaktoriseer word.

### Related DSA failure mode

As dieselfde stukkende big-integer-routine hergebruik word vir DSA private exponent generation, kan die publieke sleutel `y = g^x` ’n **dramaties verminderde en gestruktureerde** search space vir `x` verraai. Sodra die limb-patroon bekend is, kan discrete-log attacks soos **baby-step giant-step** prakties word teen die publieke parameters.

### Håstad broadcast / low exponent

As dieselfde plaintext na verskeie ontvangers gestuur word met klein `e` (dikwels `e=3`) en geen behoorlike padding nie, kan jy `m` via CRT en integer root herstel.

Technical condition:

As jy `e` ciphertexts van dieselfde boodskap onder paarwyse-koprime moduli `n_i` het:

- Gebruik CRT om `M = m^e` oor die produk `N = Π n_i` te herstel
- As `m^e < N`, dan is `M` die ware integer power, en `m = integer_root(M, e)`

### Wiener attack: small private exponent

As `d` te klein is, kan continued fractions dit uit `e/n` herstel.

### Textbook RSA pitfalls

As jy sien:

- No OAEP/PSS, raw modular exponentiation
- Deterministic encryption

dan word algebraic attacks en oracle abuse baie meer waarskynlik.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

As jy twee ciphertexts onder dieselfde modulus sien met boodskappe wat algebraïes verwant is (bv. `m2 = a*m1 + b`), soek vir "related-message" attacks soos Franklin–Reiter. Dit vereis tipies:

- same modulus `n`
- same exponent `e`
- known relationship between plaintexts

In practice word dit dikwels met Sage opgelos deur polinome modulo `n` op te stel en ’n GCD te bereken.

## Lattices / Coppersmith

Gebruik dit wanneer jy partial bits, structured plaintext, of close relations het wat die onbekende klein maak.

Lattice methods (LLL/Coppersmith) verskyn wanneer jy partial information het:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Small unknown differences between related values

### What to recognize

Tipiese leidrade in challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

In practice sal jy Sage gebruik vir LLL en ’n bekende template vir die spesifieke instance.

Goeie beginpunte:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
