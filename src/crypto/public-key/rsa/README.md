# Mashambulizi ya RSA

{{#include ../../../banners/hacktricks-training.md}}

## Uchunguzi wa haraka

Kusanya:

- `n`, `e`, `c` (na ciphertext nyingine zozote)
- Uhusiano wowote kati ya ujumbe (plaintext ileile? modulus inayoshirikiwa? plaintext yenye muundo?)
- leaks zozote (`p/q` za sehemu, biti za `d`, `dp/dq`, padding inayojulikana)

Kisha jaribu:

- Kukagua uwezekano wa factorization (Factordb / `sage: factor(n)` kwa nambari ndogo kiasi)
- Miundo ya exponent ndogo (`e=3`, broadcast)
- Modulus inayoshirikiwa / primes zinazorudiwa
- Mbinu za lattice (Coppersmith/LLL) wakati kuna kitu kinachokaribia kujulikana

## Mashambulizi ya kawaida ya RSA

### Modulus inayoshirikiwa

Ikiwa ciphertext mbili `c1, c2` zimesimba **ujumbe uleule** kwa kutumia **modulus ileile** `n` lakini exponents tofauti `e1, e2` (na `gcd(e1,e2)=1`), unaweza kurejesha `m` kwa kutumia extended Euclidean algorithm:

`m = c1^a * c2^b mod n` ambapo `a*e1 + b*e2 = 1`.

Muhtasari wa mfano:

1. Kokotoa `(a, b) = xgcd(e1, e2)` ili `a*e1 + b*e2 = 1`
2. Ikiwa `a < 0`, tafsiri `c1^a` kama `inv(c1)^{-a} mod n` (vivyo hivyo kwa `b`)
3. Zidisha na upunguze modulo `n`

### Primes zinazoshirikiwa kati ya moduli

Ikiwa una moduli nyingi za RSA kutoka kwa changamoto ileile, angalia kama zinashiriki prime:

- `gcd(n1, n2) != 1` inaashiria hitilafu kubwa katika uzalishaji wa key.

Hali hii hujitokeza mara nyingi katika CTF kama "tulitengeneza keys nyingi kwa haraka" au "randomness hafifu".

### Moduli za Sparse / short-sleeve

Baadhi ya jenereta zilizoharibika za nambari kubwa huvuja muundo moja kwa moja ndani ya modulus ya umma: kila limb huwa na subfield ndogo tu ya nasibu, na biti zilizosalia ni `0`. Kwa vitendo, hii huonekana kama **vitalu vya sifuri vilivyopangwa kwa nafasi sawa** kwenye `n`, mara nyingi vikiwa vimepangiliwa na limbs za biti 32 au 128.<sup>[[1]](#references)</sup>

Ukaguzi wa haraka:

- Onyesha `n` katika hex na utafute madirisha ya sifuri yanayojirudia kwa stride isiyobadilika.
- Gawa upya `n` katika limbs (`2^32`, `2^64`, `2^128`) na ukague kama kila limb ni ndogo isivyo kawaida.
- Kagua keys za umma za SSH/TLS kwa kutumia zana kama **badkeys** unaposhuku uzalishaji dhaifu wa host-key.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Hili ni zito zaidi kuliko upendeleo wa takwimu: ikiwa factors zote mbili za faragha `p` na `q` ni short-sleeve, modulus inaweza kuwa **rahisi kufactor**.<sup>[[1]](#references)</sup>

### Polynomial factorization ya keys za RSA zenye muundo

Kwa upana wa limb unaoshukiwa kuwa `w`, andika modulus katika base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Kwa kuwa tathmini ni ya kuzidishana, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Ikiwa coefficients za limb za factors pia ni sparse, basi:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Muhtasari wa shambulizi:

1. Kisia upana wa limb `w`.
2. Geuza modulus ya umma `n` kuwa `f_n(x)` kwa kutumia base `2^w`.
3. Factor `f_n(x)` juu ya nambari kamili.
4. Tathmini factors zinazowezekana tena kwa `B = 2^w`.
5. Thibitisha ni factors zipi zikizidishwa zinatoa `n`.

Hili **halivunji RSA ya kawaida**. Hufanya kazi tu wakati prime factors zenyewe zina coefficients za limb ndogo sana na zenye muundo dhahiri.<sup>[[1]](#references)</sup>

### Kuvuja kwa limb zilizohamishwa

Baiti sparse hazipangiliwi kila mara kwenye mwanzo wa chini wa kila limb. Ikiwa ubadilishaji wa moja kwa moja wa base-`2^w` unatoa coefficients kubwa, tafuta shifts `i,j` ambazo hufanya `2^i p` na `2^j q` kuwa sparse katika msingi huo wa limb. Polynomial ya zao bado inaweza kutolewa kutoka kwa modulus ya umma, kufactor, na kuunganishwa tena kuwa factors asilia za nambari kamili.<sup>[[1]](#references)</sup>

### Dalili ya hitilafu ya utekelezaji: hitilafu ya byte-to-limb RNG

Muundo hatari ni kukokotoa idadi ya **limbs za biti 32**, kutenga **baiti** chache tu kiasi hicho, na kuzinakili kwenye array ya limb:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

Hii huipa kila limb ya biti 32 **biti 8 pekee za entropy**, pamoja na biti ya juu iliyolazimishwa kwenye limb ya mwisho. Mara nyingi primes za RSA zinazotokana na hali hii zinaweza kutambuliwa na kufactoriwa kwa kutumia public key pekee.<sup>[[1]](#references)</sup>

### Hali inayohusiana ya hitilafu ya DSA

Ikiwa routine ileile yenye hitilafu ya big-integer itatumika tena kuzalisha private exponent ya DSA, public key `y = g^x` inaweza kufichua nafasi ya utafutaji ya `x` ambayo **imepunguzwa sana na ina muundo maalum**. Muundo wa limb ukishajulikana, mashambulizi ya discrete-log kama **baby-step giant-step** yanaweza kutumika dhidi ya public parameters.<sup>[[1]](#references)</sup>

### Håstad broadcast / exponent ndogo

Ikiwa plaintext ileile imetumwa kwa wapokeaji wengi kwa kutumia `e` ndogo (mara nyingi `e=3`) na bila padding inayofaa, unaweza kurejesha `m` kupitia CRT na integer root.

Sharti la kiufundi:

Ikiwa una ciphertexts `e` za ujumbe uleule chini ya moduli zinazokaribiana kuwa coprime `n_i`:

- Tumia CRT kurejesha `M = m^e` kwenye product `N = Π n_i`
- Ikiwa `m^e < N`, basi `M` ni power halisi ya integer, na `m = integer_root(M, e)`

### Shambulizi la Wiener: private exponent ndogo

Ikiwa `d` ni ndogo mno, continued fractions zinaweza kuirejesha kutoka `e/n`.

### Mitego ya Textbook RSA

Ukiona:

- Hakuna OAEP/PSS, modular exponentiation ya kawaida
- Encryption ya deterministic

basi mashambulizi ya algebra na matumizi mabaya ya oracle huwa na uwezekano mkubwa zaidi.

### Zana

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Miundo ya ujumbe unaohusiana

Ukiona ciphertexts mbili chini ya modulus ileile zenye ujumbe unaohusiana kwa algebra (kwa mfano, `m2 = a*m1 + b`), tafuta mashambulizi ya "related-message" kama Franklin–Reiter. Kwa kawaida mashambulizi haya yanahitaji:

- modulus `n` ileile
- exponent `e` ileile
- uhusiano unaojulikana kati ya plaintexts

Kwa vitendo, mara nyingi hili hutatuliwa kwa kutumia Sage kuweka polynomials modulo `n` na kukokotoa GCD.

## Lattices / Coppersmith

Tumia mbinu hii unapokuwa na biti za sehemu, plaintext yenye muundo maalum, au uhusiano wa karibu unaofanya thamani isiyojulikana kuwa ndogo.

Mbinu za lattice (LLL/Coppersmith) hutumika unapokuwa na taarifa za sehemu:

- Plaintext inayojulikana kwa sehemu (ujumbe wenye muundo maalum na mkia usiojulikana)
- `p`/`q` inayojulikana kwa sehemu (biti za juu zimevuja)
- Tofauti ndogo zisizojulikana kati ya thamani zinazohusiana

### Unachopaswa kutambua

Vidokezo vya kawaida kwenye challenges:

- "Tumevuja biti za juu/chini za p"
- "Flag imepachikwa hivi: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Tulitumia RSA lakini kwa padding ndogo ya random"

### Zana

Kwa vitendo, utatumia Sage kwa LLL na template inayojulikana kwa instance husika.

Sehemu nzuri za kuanzia:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Rejea ya muhtasari: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Kufactorisha funguo za RSA za "short-sleeve" kwa kutumia polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [Zana huru ya badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

