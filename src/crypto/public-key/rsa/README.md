# Shambulio za RSA

{{#include ../../../banners/hacktricks-training.md}}

## Tathmini ya haraka

Kusanya:

- `n`, `e`, `c` (na ciphertexts yoyote ya ziada)
- Uhusiano wowote kati ya ujumbe (same plaintext? shared modulus? structured plaintext?)
- Any leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Kisha jaribu:

- Kagua factorization (Factordb / `sage: factor(n)` kwa n ndogo)
- Mifumo ya low exponent (`e=3`, broadcast)
- Common modulus / primes zilizorudiwa
- Mbinu za lattice (Coppersmith/LLL) wakati kitu kinakaribia kujulikana

## Shambulio za kawaida za RSA

### Common modulus

Ikiwa ciphertexts mbili `c1, c2` zinatoa encryption ya ujumbe mmoja chini ya modulus moja `n` lakini zikiwa na exponents tofauti `e1, e2` (na `gcd(e1,e2)=1`), unaweza kurekebisha `m` kutumia algorithm ya Euclidean iliyopanuliwa:

`m = c1^a * c2^b mod n` ambapo `a*e1 + b*e2 = 1`.

Muhtasari wa mfano:

1. Pata `(a, b) = xgcd(e1, e2)` hivyo `a*e1 + b*e2 = 1`
2. Ikiwa `a < 0`, tafsiri `c1^a` kama `inv(c1)^{-a} mod n` (vivyo hivyo kwa `b`)
3. Zidisha na punguza modulo `n`

### Primes zinashirikiwa kwenye moduli

Kama una moduli nyingi za RSA kutoka kwenye changamoto moja, angalia kama zinashiriki prime:

- `gcd(n1, n2) != 1` inaonyesha hitilafu mbaya ya uzalishaji wa key.

Hii inaonekana mara nyingi katika CTFs kama "we generated many keys quickly" au "bad randomness".

### Håstad broadcast / low exponent

Ikiwa plaintext moja inatumwa kwa wapokeaji wengi na `e` ndogo (mara nyingi `e=3`) bila padding sahihi, unaweza kupata `m` kupitia CRT na root ya integer.

Sharti la kiufundi:

Ikiwa una ciphertexts `e` za ujumbe uleule chini ya moduli `n_i` jozi-jozi-coprime:

- Tumia CRT kupata `M = m^e` juu ya bidhaa `N = Π n_i`
- Ikiwa `m^e < N`, basi `M` ni nguvu ya integer halisi, na `m = integer_root(M, e)`

### Wiener attack: small private exponent

Ikiwa `d` ni ndogo sana, continued fractions zinaweza kuirejesha kutoka `e/n`.

### Textbook RSA pitfalls

Ikiwa unaona:

- Hakuna OAEP/PSS, raw modular exponentiation
- Deterministic encryption

basi algebraic attacks na oracle abuse zinakuwa za uwezekano mkubwa zaidi.

### Zana

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Mifumo ya ujumbe unaohusiana

Ikiwa unaona ciphertexts mbili chini ya modulus ileile na ujumbe ambazo ziko algebraically related (mfano, `m2 = a*m1 + b`), tafuta shambulio za "related-message" kama Franklin–Reiter. Hizi kawaida zinahitaji:

- same modulus `n`
- same exponent `e`
- known relationship between plaintexts

Katika vitendo mara nyingi hutatuliwa kwa Sage kwa kuunda polynomials modulo `n` na kuhesabu GCD.

## Lattices / Coppersmith

Fikia hii unapokuwa na bits za sehemu, structured plaintext, au uhusiano karibu unaofanya yasiyojulikana kuwa madogo.

Mbinu za lattice (LLL/Coppersmith) zinaonekana kila unapokuwa na taarifa sehemu:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Small unknown differences between related values

### Vidokezo vya kutambua

Dalili za kawaida katika changamoto:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Vifaa

Katika vitendo utatumia Sage kwa LLL na template inayojulikana kwa kesi maalum.

Mwanzo mzuri:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
