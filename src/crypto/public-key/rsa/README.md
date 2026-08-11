# RSA-aanvalle

{{#include ../../../banners/hacktricks-training.md}}

## Vinnige triage

Versamel:

- `n`, `e`, `c` (en enige bykomende ciphertexts)
- Enige verwantskappe tussen boodskappe (dieselfde plaintext? gedeelde modulus? gestruktureerde plaintext?)
- Enige leaks (gedeeltelike `p/q`, bisse van `d`, `dp/dq`, bekende padding)

Probeer dan:

- Faktoriseringskontrole (Factordb / `sage: factor(n)` vir redelik klein waardes)
- Lae-eksponentpatrone (`e=3`, broadcast)
- Gemeenskaplike modulus / herhaalde priemgetalle
- Lattice-metodes (Coppersmith/LLL) wanneer iets byna bekend is

## Algemene RSA-aanvalle

### Gemeenskaplike modulus

As twee ciphertexts `c1, c2` die **selfde boodskap** onder die **selfde modulus** `n`, maar met verskillende eksponente `e1, e2` (en `gcd(e1,e2)=1`) enkripteer, kan jy `m` met die uitgebreide Euklidiese algoritme herstel:

`m = c1^a * c2^b mod n` waar `a*e1 + b*e2 = 1`.

Voorbeeld-oorsig:

1. Bereken `(a, b) = xgcd(e1, e2)` sodat `a*e1 + b*e2 = 1`
2. As `a < 0`, interpreteer `c1^a` as `inv(c1)^{-a} mod n` (dieselfde vir `b`)
3. Vermenigvuldig en verminder modulo `n`

### Gedeelde priemgetalle oor moduli

As jy meerdere RSA-moduli uit dieselfde uitdaging het, kyk of hulle ’n priemgetal deel:

- `gcd(n1, n2) != 1` impliseer ’n katastrofiese sleutelgenereringsfout.

Dit kom gereeld in CTFs voor as "ons het baie sleutels vinnig gegenereer" of "slegte randomness".

### Sparse / kortmou-moduli

Sommige gebroke big-integer generators lek struktuur direk in die publieke modulus: elke limb bevat slegs ’n klein random subveld en die res van die bisse is `0`. In die praktyk verskyn dit as **gereeld gespasieerde nulblokke** oor `n`, wat dikwels met 32-bis- of 128-bis-limbs belyn is.<sup>[[1]](#references)</sup>

Vinnige kontroles:

- Dump `n` in hex en kyk vir herhaalde nulvensters met ’n vaste stride.
- Sny `n` weer as limbs (`2^32`, `2^64`, `2^128`) en ondersoek of elke limb buitengewoon klein is.
- Oudit publieke SSH/TLS-sleutels met tooling soos **badkeys** wanneer jy swak host-key-generering vermoed.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Dit is ernstiger as ’n statistiese bias: as beide private faktore `p` en `q` kortmou is, kan die modulus **maklik wees om te faktoriseer**.<sup>[[1]](#references)</sup>

### Polinoomfaktorisering van gestruktureerde RSA-sleutels

Vir ’n vermoedelike limbwydte `w`, skryf die modulus in basis `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Omdat evaluering multiplikatief is, is `f_a(B) * f_c(B) = (f_a * f_c)(B)`. As die faktore ook sparse limb-koëffisiënte het, dan:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Aanvalsoorsig:

1. Raai die limbwydte `w`.
2. Skakel die publieke modulus `n` om na `f_n(x)` met basis `2^w`.
3. Faktoriseer `f_n(x)` oor die heelgetalle.
4. Evalueer kandidaatfaktore terug by `B = 2^w`.
5. Verifieer watter kandidate tot `n` vermenigvuldig.

Dit **breek nie normale RSA nie**. Dit werk slegs wanneer die priemfaktore self baie klein, hoogs gestruktureerde limb-koëffisiënte het.<sup>[[1]](#references)</sup>

### Verskuifde limb-leakage

Die sparse grepe is nie altyd aan die lae kant van elke limb belyn nie. As direkte basis-`2^w`-omskakeling groot koëffisiënte lewer, soek na verskuiwings `i,j` waarvoor `2^i p` en `2^j q` sparse in daardie limb-basis word. Die produkpolinoom kan steeds uit die publieke modulus afgelei, gefaktoriseer en weer saamgestel word tot die oorspronklike heelgetalfaktore.<sup>[[1]](#references)</sup>

### Implementeringsreuk: byte-to-limb RNG-bug

’n Gevaarlike patroon is om die aantal **32-bis-limbs** te bereken, slegs soveel **bytes** te allokeer, en dit na die limb-skikking te kopieer:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Dit gee elke 32-bis-liggaam slegs **8 bisse entropie**, plus 'n afgedwonge boonste bis in die laaste liggaam. Die gevolglike RSA-priemgetalle kan dikwels vanaf die publieke sleutel alleen herken en gefaktoriseer word.<sup>[[1]](#references)</sup>

### Verwante DSA-faalmodus

As dieselfde gebroke grootheelgetalroetine vir DSA-private eksponentgenerering hergebruik word, kan die publieke sleutel `y = g^x` 'n **drasties verkleinde en gestruktureerde** soekruimte vir `x` lek. Sodra die liggaamspatroon bekend is, kan diskrete-logaritme-aanvalle soos **baby-step giant-step** prakties teen die publieke parameters word.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

As dieselfde plaintext na veelvuldige ontvangers met klein `e` (dikwels `e=3`) en sonder behoorlike padding gestuur word, kan jy `m` via CRT en integer root herwin.

Tegniese voorwaarde:

As jy `e` ciphertexts van dieselfde boodskap onder paarsgewys relatief priem moduli `n_i` het:

- Gebruik CRT om `M = m^e` oor die produk `N = Π n_i` te herwin
- As `m^e < N`, dan is `M` die ware heelgetal-magmagtelling, en `m = integer_root(M, e)`

### Wiener attack: small private exponent

As `d` te klein is, kan continued fractions dit uit `e/n` herwin.

### Textbook RSA pitfalls

As jy die volgende sien:

- Geen OAEP/PSS nie, rou modulêre eksponensiëring
- Deterministiese enkripsie

dan word algebraïese aanvalle en oracle-misbruik baie waarskynliker.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Verwante-boodskap-patrone

As jy twee ciphertexts onder dieselfde modulus sien met boodskappe wat algebraïes aan mekaar verwant is (byvoorbeeld `m2 = a*m1 + b`), soek na "related-message"-aanvalle soos Franklin–Reiter. Dit vereis tipies:

- dieselfde modulus `n`
- dieselfde eksponent `e`
- 'n bekende verwantskap tussen die plaintexts

In die praktyk word dit dikwels met Sage opgelos deur polinome modulo `n` op te stel en 'n GCD te bereken.

## Lattices / Coppersmith

Gebruik dit wanneer jy gedeeltelike bisse, gestruktureerde plaintext of nou verwantskappe het wat die onbekende klein maak.

Lattice-metodes (LLL/Coppersmith) verskyn wanneer jy gedeeltelike inligting het:

- Gedeeltelik bekende plaintext (gestruktureerde boodskap met onbekende stert)
- Gedeeltelik bekende `p`/`q` (hoë bisse geleak)
- Klein onbekende verskille tussen verwante waardes

### Wat om te herken

Tipiese leidrade in challenges:

- "Ons het die boonste/onderste bisse van p geleak"
- "Die flag is ingebed soos: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Ons het RSA gebruik, maar met 'n klein random padding"

### Tooling

In die praktyk sal jy Sage vir LLL en 'n bekende template vir die spesifieke instansie gebruik.

Goeie beginpunte:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- 'n Oorsigstylverwysing: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Faktorisering van "short-sleeve" RSA-sleutels met polinome](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
