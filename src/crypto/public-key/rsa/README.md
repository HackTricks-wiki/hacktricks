# Mashambulizi ya RSA

{{#include ../../../banners/hacktricks-training.md}}

## Triage ya haraka

Kusanya:

- `n`, `e`, `c` (na ciphertexts zozote za ziada)
- Mahusiano yoyote kati ya messages (plaintext ileile? modulus iliyoshirikiwa? plaintext yenye muundo?)
- leak zozote (`p/q` kwa sehemu, bits za `d`, `dp/dq`, padding inayojulikana)

Kisha jaribu:

- Ukaguzi wa factorization (Factordb / `sage: factor(n)` kwa nambari ndogo kiasi)
- Mifumo ya low exponent (`e=3`, broadcast)
- Common modulus / repeated primes
- Mbinu za lattice (Coppersmith/LLL) wakati kitu kinakaribia kujulikana

## Common RSA attacks

### Common modulus

Ikiwa ciphertexts mbili `c1, c2` zinasimba **ujumbe uleule** chini ya **modulus ileile** `n`, lakini zikiwa na exponents tofauti `e1, e2` (na `gcd(e1,e2)=1`), unaweza kurejesha `m` kwa kutumia extended Euclidean algorithm:

`m = c1^a * c2^b mod n` ambapo `a*e1 + b*e2 = 1`.

Muhtasari wa mfano:

1. Hesabu `(a, b) = xgcd(e1, e2)` ili `a*e1 + b*e2 = 1`
2. Ikiwa `a < 0`, tafsiri `c1^a` kama `inv(c1)^{-a} mod n` (vivyo hivyo kwa `b`)
3. Zidisha na punguza modulo `n`

### Shared primes across moduli

Ikiwa una RSA moduli nyingi kutoka kwenye challenge ileile, kagua kama zinashirikiana prime:

- `gcd(n1, n2) != 1` inaashiria hitilafu kubwa ya key-generation.

Hii hujitokeza mara kwa mara katika CTFs kama "we generated many keys quickly" au "bad randomness".

### Sparse / short-sleeve moduli

Baadhi ya big-integer generators zilizoharibika huvuja muundo moja kwa moja kwenye public modulus: kila limb huwa na subfield ndogo tu ya random, na bits zilizobaki huwa `0`. Kwa matumizi halisi, hii huonekana kama **blocks za zero zilizotenganishwa kwa mpangilio** kote kwenye `n`, mara nyingi zikiwa zimepangiliwa kwa limbs za 32-bit au 128-bit.<sup>[[1]](#references)</sup>

Ukaguzi wa haraka:

- Dump `n` katika hex na utafute windows za zero zinazorudiwa kwa stride isiyobadilika.
- Gawanya tena `n` kuwa limbs (`2^32`, `2^64`, `2^128`) na kagua kama kila limb ni ndogo isivyo kawaida.
- Kagua public SSH/TLS keys kwa tooling kama **badkeys** unaposhuku weak host-key generation.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Hili ni kubwa zaidi kuliko statistical bias: ikiwa private factors zote mbili `p` na `q` zina short-sleeves, modulus inaweza kuwa **rahisi kufactor**.<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

Kwa limb width `w` inayoshukiwa, andika modulus katika base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Kwa sababu evaluation ni multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Ikiwa factors pia zina sparse limb coefficients, basi:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Muhtasari wa attack:

1. Kisia limb width `w`.
2. Badilisha public modulus `n` kuwa `f_n(x)` kwa kutumia base `2^w`.
3. Factor `f_n(x)` juu ya integers.
4. Fanya evaluation ya candidate factors tena kwenye `B = 2^w`.
5. Thibitisha ni candidates zipi zinazozidishwa kupata `n`.

Hii **haivunji normal RSA**. Inafanya kazi tu wakati prime factors zenyewe zina limb coefficients ndogo sana na zenye muundo maalum.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse bytes hazipangiliwi kila mara kwenye mwisho wa chini wa kila limb. Ikiwa conversion ya moja kwa moja ya base-`2^w` inazalisha coefficients kubwa, tafuta shifts `i,j` kiasi kwamba `2^i p` na `2^j q` ziwe sparse katika limb basis hiyo. Product polynomial bado inaweza kutolewa kutoka kwenye public modulus, kufactorishwa, na kuunganishwa tena kuwa original integer factors.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

Pattern hatari ni kuhesabu idadi ya **32-bit limbs**, kutenga **bytes** hizo pekee, na kuzinakili kwenye limb array:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Hii huipa kila limb ya biti-32 **biti 8 za entropy** pamoja na biti ya juu iliyolazimishwa katika limb ya mwisho. RSA primes zinazotokana na hili mara nyingi zinaweza kutambuliwa na kufactor kutoka kwenye public key pekee.<sup>[[1]](#references)</sup>

### Related DSA failure mode

Ikiwa routine hiyo hiyo iliyovunjika ya big-integer itatumika tena kuzalisha DSA private exponent, public key `y = g^x` inaweza ku-leak **search space iliyopunguzwa sana na yenye muundo** ya `x`. Mara tu pattern ya limb inapojulikana, mashambulizi ya discrete-log kama **baby-step giant-step** yanaweza kuwa practical dhidi ya public parameters.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Ikiwa plaintext ile ile inatumwa kwa recipients wengi wenye `e` ndogo (mara nyingi `e=3`) na bila proper padding, unaweza kurecover `m` kupitia CRT na integer root.

Technical condition:

Ikiwa una ciphertexts `e` za message ile ile chini ya moduli zilizo pairwise-coprime `n_i`:

- Tumia CRT kurecover `M = m^e` juu ya product `N = Π n_i`
- Ikiwa `m^e < N`, basi `M` ni true integer power, na `m = integer_root(M, e)`

### Wiener attack: small private exponent

Ikiwa `d` ni ndogo sana, continued fractions zinaweza kuirecover kutoka `e/n`.

### Textbook RSA pitfalls

Ukiona:

- Hakuna OAEP/PSS, raw modular exponentiation
- Deterministic encryption

basi algebraic attacks na oracle abuse huwa na uwezekano mkubwa zaidi.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Ukiona ciphertexts mbili chini ya modulus ile ile zenye messages zinazohusiana algebraically (kwa mfano, `m2 = a*m1 + b`), tafuta mashambulizi ya "related-message" kama Franklin–Reiter. Kwa kawaida haya yanahitaji:

- modulus `n` ile ile
- exponent `e` ile ile
- relationship inayojulikana kati ya plaintexts

Kwa vitendo, hili mara nyingi hutatuliwa kwa Sage kwa kuunda polynomials modulo `n` na kukokotoa GCD.

## Lattices / Coppersmith

Tumia hii unapokuwa na partial bits, structured plaintext, au close relations zinazofanya unknown iwe ndogo.

Lattice methods (LLL/Coppersmith) hujitokeza unapokuwa na partial information:

- Partially known plaintext (structured message yenye tail isiyojulikana)
- Partially known `p`/`q` (high bits zime-leak)
- Small unknown differences kati ya related values

### What to recognize

Dalili za kawaida katika challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

Kwa vitendo utatumia Sage kwa LLL na known template kwa specific instance.

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Kufactor "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
