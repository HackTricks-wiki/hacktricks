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
- Common modulus / herhaalde priemgetalle
- Lattice-metodes (Coppersmith/LLL) wanneer iets byna bekend is

## Algemene RSA-aanvalle

### Common modulus

As twee ciphertexts `c1, c2` die **dieselfde boodskap** onder dieselfde modulus `n`, maar met verskillende eksponente `e1, e2` (en `gcd(e1,e2)=1`), enkripteer, kan jy `m` met die uitgebreide Euklidiese algoritme herstel:

`m = c1^a * c2^b mod n` waar `a*e1 + b*e2 = 1`.

Voorbeeldskets:

1. Bereken `(a, b) = xgcd(e1, e2)` sodat `a*e1 + b*e2 = 1`
2. As `a < 0`, interpreteer `c1^a` as `inv(c1)^{-a} mod n` (dieselfde vir `b`)
3. Vermenigvuldig en neem die res modulo `n`

### Gedeelde priemgetalle oor moduli heen

As jy verskeie RSA-moduli van dieselfde uitdaging het, kyk of hulle ’n priemgetal deel:

- `gcd(n1, n2) != 1` dui op ’n katastrofiese fout met sleutelskepping.

Dit kom dikwels in CTFs voor as "ons het baie sleutels vinnig gegenereer" of "swak randomness".

### Sparse / short-sleeve-moduli

Sommige stukkende big-integer-opwekkers laat struktuur direk in die publieke modulus uitlek: elke limb bevat slegs ’n klein ewekansige subveld en die res van die bisse is `0`. In die praktyk verskyn dit as **reëlmatig gespasieerde nulblokke** deurgaans in `n`, dikwels in lyn met 32-bis- of 128-bis-limbs.<sup>[[1]](#references)</sup>

Vinnige kontroles:

- Gee `n` in heksadesimaal weer en soek herhaalde nulvensters met ’n vaste spasiëring.
- Verdeel `n` weer in limbs (`2^32`, `2^64`, `2^128`) en kyk of elke limb buitengewoon klein is.
- Oudit publieke SSH/TLS-sleutels met nutsmiddels soos **badkeys** wanneer jy swak host-key-generering vermoed.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Dit is ernstiger as ’n statistiese vooroordeel: as beide private faktore `p` en `q` short-sleeved is, kan die modulus **maklik faktoriseerbaar** word.<sup>[[1]](#references)</sup>

### Polinoomfaktorisasie van gestruktureerde RSA-sleutels

Vir ’n vermoedelike limbwydte `w`, skryf die modulus in basis `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Omdat evaluering vermenigvuldigend is, geld `f_a(B) * f_c(B) = (f_a * f_c)(B)`. As die faktore ook sparse limb-koëffisiënte het, dan:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Aanvalskets:

1. Raai die limbwydte `w`.
2. Skakel die publieke modulus `n` om na `f_n(x)` met basis `2^w`.
3. Faktoriseer `f_n(x)` oor die heelgetalle.
4. Evalueer kandidaatfaktore weer by `B = 2^w`.
5. Verifieer watter kandidate met mekaar vermenigvuldig om `n` te gee.

Dit **breek nie normale RSA nie**. Dit werk slegs wanneer die priemfaktore self baie klein, hoogs gestruktureerde limb-koëffisiënte het.<sup>[[1]](#references)</sup>

### Verskuiwing in limb-leakage

Die sparse grepe is nie altyd aan die lae kant van elke limb in lyn nie. As direkte basis-`2^w`-omskakeling groot koëffisiënte oplewer, soek vir verskuiwings `i,j` sodat `2^i p` en `2^j q` sparse in daardie limb-basis word. Die produkpolinoom kan steeds uit die publieke modulus afgelei, gefaktoriseer en weer saamgestel word tot die oorspronklike heelgetalfaktore.<sup>[[1]](#references)</sup>

### Implementeringswaarskuwing: byte-to-limb RNG-fout

’n Gevaarlike patroon is om die aantal **32-bis-limbs** te bereken, slegs daardie aantal **grepe** te allokeer en hulle dan na die limb-skikking te kopieer:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

Dit gee elke 32-bis-limb slegs **8 bits entropie** plus ’n geforseerde boonste bit in die laaste limb. Die resulterende RSA-prime kan dikwels aan die hand van die publieke sleutel alleen herken en gefaktoriseer word.<sup>[[1]](#references)</sup>

### Verwante DSA-foutmodus

As dieselfde gebrekkige grootheelgetalroetine vir DSA-private eksponentgenerering hergebruik word, kan die publieke sleutel `y = g^x` ’n **dramaties verkleinde en gestruktureerde** soekruimte vir `x` uitlek. Sodra die limb-patroon bekend is, kan diskrete-logaritme-aanvalle soos **baby-step giant-step** prakties word teen die publieke parameters.<sup>[[1]](#references)</sup>

### Håstad-uitsending / lae eksponent

As dieselfde plaintext sonder behoorlike padding aan verskeie ontvangers gestuur word met ’n klein `e` (dikwels `e=3`), kan jy `m` via CRT en ’n heelgetalwortel herwin.

Tegniese voorwaarde:

As jy `e` ciphertexts van dieselfde boodskap onder paarsgewys onderling priem moduli `n_i` het:

- Gebruik CRT om `M = m^e` oor die produk `N = Π n_i` te herwin
- As `m^e < N`, is `M` die ware heelgetalmag, en `m = integer_root(M, e)`

### Wiener-aanval: klein private eksponent

As `d` te klein is, kan voortbreuke dit uit `e/n` herwin.

### Slaggate van textbook RSA

As jy die volgende sien:

- Geen OAEP/PSS nie, rou modulêre eksponensiëring
- Deterministiese enkripsie

is algebraïese aanvalle en misbruik van orakels baie waarskynliker.

### Gereedskap

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, wortels, CF): https://www.sagemath.org/

## Verwante-boodskap-patrone

As jy twee ciphertexts onder dieselfde modulus sien met boodskappe wat algebraïes verwant is (bv. `m2 = a*m1 + b`), kyk na "related-message"-aanvalle soos Franklin–Reiter. Dit vereis gewoonlik:

- dieselfde modulus `n`
- dieselfde eksponent `e`
- ’n bekende verwantskap tussen plaintexts

In die praktyk word dit dikwels met Sage opgelos deur polinome modulo `n` op te stel en ’n GCD te bereken.

## Roosters / Coppersmith

Gebruik dit wanneer jy gedeeltelike bisse, gestruktureerde plaintext of nou verwante waardes het wat die onbekende klein maak.

Roostermetodes (LLL/Coppersmith) kom ter sprake wanneer jy gedeeltelike inligting het:

- Gedeeltelik bekende plaintext (gestruktureerde boodskap met ’n onbekende agterste deel)
- Gedeeltelik bekende `p`/`q` (hoë bisse het gelek)
- Klein onbekende verskille tussen verwante waardes

### Waarna om te kyk

Tipiese leidrade in uitdagings:

- "Ons het die boonste/ onderste bisse van p uitgelek"
- "Die flag is ingebed soos: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Ons het RSA gebruik, maar met ’n klein ewekansige padding"

### Gereedskap

In die praktyk gebruik jy Sage vir LLL en ’n bekende template vir die spesifieke geval.

Goeie beginpunte:

- Sage CTF-crypto-templates: https://github.com/defund/coppersmith
- ’n Oorsigagtige verwysing: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Faktorisering van "short-sleeve"-RSA-sleutels met polinome](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys selfstandige hulpmiddel](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

