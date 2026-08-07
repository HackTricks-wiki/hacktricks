# RSA-aanvalle

{{#include ../../../banners/hacktricks-training.md}}

## Vinnige triage

Versamel:

- `n`, `e`, `c` (en enige bykomende ciphertexts)
- Enige verhoudings tussen boodskappe (dieselfde plaintext? gedeelde modulus? gestruktureerde plaintext?)
- Enige leaks (gedeeltelike `p/q`, bisse van `d`, `dp/dq`, bekende padding)

Probeer dan:

- Faktoriseringstoets (Factordb / `sage: factor(n)` vir redelike klein waardes)
- Lae eksponent-patrone (`e=3`, broadcast)
- Common modulus / herhaalde primes
- Lattice-metodes (Coppersmith/LLL) wanneer iets byna bekend is

## Algemene RSA-aanvalle

### Common modulus

As twee ciphertexts `c1, c2` dieselfde **boodskap** onder dieselfde **modulus** `n`, maar met verskillende eksponente `e1, e2` (en `gcd(e1,e2)=1`), enkripteer, kan jy `m` met die uitgebreide Euklidiese algoritme herwin:

`m = c1^a * c2^b mod n` waar `a*e1 + b*e2 = 1`.

Voorbeeld-oorsig:

1. Bereken `(a, b) = xgcd(e1, e2)` sodat `a*e1 + b*e2 = 1`
2. As `a < 0`, interpreteer `c1^a` as `inv(c1)^{-a} mod n` (dieselfde vir `b`)
3. Vermenigvuldig en verminder modulo `n`

### Gedeelde primes oor moduli

As jy veelvuldige RSA-moduli uit dieselfde uitdaging het, kyk of hulle 'n prime deel:

- `gcd(n1, n2) != 1` impliseer 'n katastrofiese sleutelgenereringsfout.

Dit kom gereeld in CTFs voor as "ons het baie sleutels vinnig gegenereer" of "slegte randomness".

### Sparse / short-sleeve-moduli

Sommige gebroke big-integer generators lek struktuur direk in die publieke modulus: elke limb bevat slegs 'n klein random subveld en die res van die bisse is `0`. In die praktyk verskyn dit as **gereeld gespasieerde zero blocks** oor `n`, dikwels in lyn met 32-bis- of 128-bis-limbs.<sup>[[1]](#references)</sup>

Vinnige toetse:

- Dump `n` in hex en soek na herhaalde zero windows met 'n vaste stride.
- Sny `n` weer in limbs (`2^32`, `2^64`, `2^128`) en inspekteer of elke limb buitengewoon klein is.
- Oudit publieke SSH/TLS-sleutels met tooling soos **badkeys** wanneer jy swak host-key generation vermoed.<sup>[[2]](#references)[[3]](#references)</sup>

Dit is ernstiger as 'n statistiese bias: as beide private faktore `p` en `q` short-sleeved is, kan die modulus **maklik wees om te factor**.<sup>[[1]](#references)</sup>

### Polynomial factorization van gestruktureerde RSA-sleutels

Vir 'n vermoedelike limb width `w`, skryf die modulus in basis `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Omdat evaluering multiplicatief is, is `f_a(B) * f_c(B) = (f_a * f_c)(B)`. As die faktore ook sparse limb coefficients het, dan:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Aanvalsoorsig:

1. Raai die limb width `w`.
2. Skakel die publieke modulus `n` om na `f_n(x)` met basis `2^w`.
3. Factor `f_n(x)` oor die heelgetalle.
4. Evalueer kandidaatfaktore weer by `B = 2^w`.
5. Verifieer watter kandidate tot `n` vermenigvuldig.

Hierdie **breek nie normale RSA nie**. Dit werk slegs wanneer die prime-faktore self baie klein, hoogs gestruktureerde limb coefficients het.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Die sparse bytes is nie altyd aan die lae kant van elke limb belyn nie. As direkte basis-`2^w`-omskakeling groot coefficients oplewer, soek na shifts `i,j` sodat `2^i p` en `2^j q` sparse in daardie limb-basis word. Die produkpolinoom kan steeds uit die publieke modulus afgelei, gefactor en weer saamgestel word in die oorspronklike heelgetalfaktore.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

'n Gevaarlike patroon is om die aantal **32-bit limbs** te bereken, slegs soveel **bytes** toe te ken, en hulle na die limb-array te kopieer:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Dit gee elke 32-bit limb slegs **8 bits of entropy**, plus ’n geforseerde boonste bit in die laaste limb. Die gevolglike RSA-priemgetalle kan dikwels uit die publieke sleutel alleen herken en gefaktoriseer word.<sup>[[1]](#references)</sup>

### Verwante DSA-failure mode

As dieselfde gebroke big-integer-roetine hergebruik word vir DSA-private eksponentgenerering, kan die publieke sleutel `y = g^x` ’n **dramaties verkleinde en gestruktureerde** soekruimte vir `x` uitlek. Sodra die limb-patroon bekend is, kan discrete-log-aanvalle soos **baby-step giant-step** prakties word teen die publieke parameters.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

As dieselfde plaintext na verskeie ontvangers gestuur word met ’n klein `e` (dikwels `e=3`) en sonder behoorlike padding, kan jy `m` via CRT en ’n heelgetalwortel herwin.

Tegniese voorwaarde:

As jy `e` ciphertexts van dieselfde boodskap onder paargewys onderling priem moduli `n_i` het:

- Gebruik CRT om `M = m^e` oor die produk `N = Π n_i` te herwin
- As `m^e < N`, dan is `M` die ware heelgetalverheffing, en `m = integer_root(M, e)`

### Wiener attack: klein private eksponent

As `d` te klein is, kan continued fractions dit uit `e/n` herwin.

### Textbook RSA-slaggate

As jy die volgende sien:

- Geen OAEP/PSS nie, raw modular exponentiation
- Deterministiese encryption

dan word algebraïese aanvalle en oracle abuse baie waarskynliker.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Verwante-message-patrone

As jy twee ciphertexts onder dieselfde modulus sien met boodskappe wat algebraïes verwant is (bv. `m2 = a*m1 + b`), soek na "related-message"-aanvalle soos Franklin–Reiter. Dit vereis tipies:

- dieselfde modulus `n`
- dieselfde eksponent `e`
- ’n bekende verhouding tussen plaintexts

In die praktyk word dit dikwels met Sage opgelos deur polinome modulo `n` op te stel en ’n GCD te bereken.

## Lattices / Coppersmith

Gebruik dit wanneer jy gedeeltelike bits, gestruktureerde plaintext of nabye verhoudings het wat die onbekende klein maak.

Lattice-metodes (LLL/Coppersmith) verskyn wanneer jy gedeeltelike inligting het:

- Gedeeltelik bekende plaintext (gestruktureerde boodskap met ’n onbekende stert)
- Gedeeltelik bekende `p`/`q` (boonste bits geleak)
- Klein onbekende verskille tussen verwante waardes

### Wat om te herken

Tipiese leidrade in challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

In die praktyk sal jy Sage vir LLL en ’n bekende template vir die spesifieke geval gebruik.

Goeie beginpunte:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- ’n Oorsigstyl-verwysing: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## Verwysings

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
