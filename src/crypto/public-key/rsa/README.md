# RSA Napadi

{{#include ../../../banners/hacktricks-training.md}}

## Brza trijaža

Prikupi:

- `n`, `e`, `c` (i bilo koje dodatne ciphertexts)
- Bilo kakve relacije između poruka (isti plaintext? shared modulus? structured plaintext?)
- Bilo kakve leak-ove (delimični `p/q`, bitovi od `d`, `dp/dq`, poznati padding)

Zatim probaj:

- Proveru faktorizacije (Factordb / `sage: factor(n)` za manje-više male vrednosti)
- Obrazce sa niskim eksponentom (`e=3`, broadcast)
- Common modulus / ponovljeni prajmovi
- Lattice metode (Coppersmith/LLL) kada je nešto skoro poznato

## Uobičajeni RSA napadi

### Common modulus

Ako dva ciphertexts `c1, c2` šifruju **istu poruku** pod **istim modulusom** `n`, ali sa različitim eksponentima `e1, e2` (i `gcd(e1,e2)=1`), možeš povratiti `m` koristeći prošireni Euklidov algoritam:

`m = c1^a * c2^b mod n` gde je `a*e1 + b*e2 = 1`.

Primer koraka:

1. Izračunaj `(a, b) = xgcd(e1, e2)` tako da `a*e1 + b*e2 = 1`
2. Ako je `a < 0`, interpretiraj `c1^a` kao `inv(c1)^{-a} mod n` (isto važi i za `b`)
3. Pomnoži i redukuj modulo `n`

### Shared primes across moduli

Ako imaš više RSA moduli iz istog izazova, proveri da li dele prajm:

- `gcd(n1, n2) != 1` znači katastrofalan failure pri generisanju ključa.

Ovo se često pojavljuje u CTF-ovima kao "generisali smo mnogo ključeva brzo" ili "loš randomness".

### Sparse / short-sleeve moduli

Neki neispravni generators za velike integer-e direktno curi strukturu u javni modulus: svaki limb sadrži samo malo nasumično podpolje, a ostatak bitova je `0`. U praksi se ovo pojavljuje kao **pravilno raspoređeni zero blokovi** kroz `n`, često poravnati na 32-bit ili 128-bit limbs.

Brze provere:

- Ispiši `n` u hex i traži ponavljajuće zero prozore sa fiksnim razmakom.
- Ponovo iseći `n` kao limbs (`2^32`, `2^64`, `2^128`) i proveri da li je svaki limb neuobičajeno mali.
- Audituj javne SSH/TLS ključeve alatima kao što je **badkeys** kada sumnjaš na slabu generaciju host-ključa.

Ovo je ozbiljnije od statističke bias: ako su oba privatna faktora `p` i `q` short-sleeved, modulus može postati **lak za faktorizaciju**.

### Polynomial factorization of structured RSA keys

Za sumnjivu širinu limb-a `w`, zapiši modulus u bazi `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Pošto je evaluacija multiplikativna, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Ako i faktori imaju sparse limb koeficijente, onda:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Plan napada:

1. Pogodi širinu limb-a `w`.
2. Pretvori javni modulus `n` u `f_n(x)` koristeći bazu `2^w`.
3. Faktoriši `f_n(x)` nad celim brojevima.
4. Evaluiraj kandidat-faktore nazad na `B = 2^w`.
5. Proveri koji kandidati daju proizvod `n`.

Ovo **ne lomi normalan RSA**. Radi samo kada sami prosti faktori imaju veoma male, visoko strukturisane limb koeficijente.

### Shifted limb leakage

Sparse bajtovi nisu uvek poravnati na donjem kraju svakog limb-a. Ako direktna konverzija u bazu `2^w` daje velike koeficijente, traži shift-e `i,j` tako da `2^i p` i `2^j q` postanu sparse u toj limb bazi. Polinomial proizvoda se i dalje može izvesti iz javnog modula, faktorisati i recombined u originalne cele faktore.

### Implementation smell: byte-to-limb RNG bug

Opasan obrazac je računanje broja **32-bit limbova**, alociranje samo toliko **bajtova**, i kopiranje njih u limb niz:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Ovo daje svakom 32-bitnom limb-u samo **8 bitova entropije** plus forsirani najviši bit u poslednjem limb-u. Nastali RSA prosti brojevi često mogu da se prepoznaju i faktorišu samo iz javnog ključa.

### Related DSA failure mode

Ako se ista pokvarena big-integer rutina ponovo koristi za generisanje DSA privatnog eksponenta, javni ključ `y = g^x` može otkriti **dramatično smanjen i strukturisan** search space za `x`. Kada je obrazac limb-ova poznat, discrete-log attacks kao što je **baby-step giant-step** mogu postati praktični protiv javnih parametara.

### Håstad broadcast / low exponent

Ako se isti plaintext šalje više primaoca sa malim `e` (često `e=3`) i bez pravilnog padding-a, možete oporaviti `m` preko CRT i integer root.

Tehnički uslov:

Ako imate `e` ciphertext-ova iste poruke pod pairwise-coprime modulus-ima `n_i`:

- Koristite CRT da oporavite `M = m^e` preko proizvoda `N = Π n_i`
- Ako je `m^e < N`, onda je `M` pravi celobrojni stepen, i `m = integer_root(M, e)`

### Wiener attack: small private exponent

Ako je `d` previše mali, continued fractions mogu da ga oporave iz `e/n`.

### Textbook RSA pitfalls

Ako vidite:

- Nema OAEP/PSS, raw modular exponentiation
- Deterministic encryption

onda algebraic attacks i oracle abuse postaju mnogo verovatniji.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Ako vidite dva ciphertext-a pod istim modulus-om sa porukama koje su algebraically related (npr. `m2 = a*m1 + b`), tražite "related-message" attacks kao što je Franklin–Reiter. Ovo tipično zahteva:

- isti modulus `n`
- isti exponent `e`
- poznatu vezu između plaintext-a

U praksi se ovo često rešava u Sage tako što se postave polinomi modulo `n` i izračuna GCD.

## Lattices / Coppersmith

Koristite ovo kada imate delimične bitove, strukturisan plaintext, ili bliske relacije koje čine nepoznato malo.

Lattice methods (LLL/Coppersmith) se pojavljuju kad god imate delimične informacije:

- Delimično poznat plaintext (strukturisana poruka sa nepoznatim repom)
- Delimično poznat `p`/`q` (otkriveni visoki bitovi)
- Mali nepoznati razmaci između related values

### What to recognize

Tipični tragovi u izazovima:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

U praksi ćete koristiti Sage za LLL i poznati template za konkretnu instancu.

Dobri početni resursi:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
