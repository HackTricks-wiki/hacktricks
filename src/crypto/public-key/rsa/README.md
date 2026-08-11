# RSA napadi

{{#include ../../../banners/hacktricks-training.md}}

## Brza procena

Prikupite:

- `n`, `e`, `c` (i sve dodatne ciphertexts)
- Sve odnose između poruka (isti plaintext? deljeni modulus? strukturirani plaintext?)
- Sve leaks (delimični `p/q`, bitovi `d`, `dp/dq`, poznati padding)

Zatim probajte:

- Proveru faktorizacije (Factordb / `sage: factor(n)` za manje vrednosti)
- Obrasce malog eksponenta (`e=3`, broadcast)
- Common modulus / ponovljene proste brojeve
- Lattice methods (Coppersmith/LLL) kada je nešto gotovo poznato

## Uobičajeni RSA napadi

### Common modulus

Ako dva ciphertexts `c1, c2` šifruju **istu poruku** koristeći isti **modulus** `n`, ali sa različitim eksponentima `e1, e2` (i `gcd(e1,e2)=1`), možete oporaviti `m` koristeći prošireni Euklidov algoritam:

`m = c1^a * c2^b mod n` gde je `a*e1 + b*e2 = 1`.

Okvirni postupak:

1. Izračunajte `(a, b) = xgcd(e1, e2)` tako da je `a*e1 + b*e2 = 1`
2. Ako je `a < 0`, tumačite `c1^a` kao `inv(c1)^{-a} mod n` (isto važi za `b`)
3. Pomnožite i redukujte modulo `n`

### Deljeni prosti brojevi između moduli

Ako imate više RSA moduli iz istog izazova, proverite da li dele prost broj:

- `gcd(n1, n2) != 1` podrazumeva katastrofalni propust u generisanju ključeva.

Ovo se često pojavljuje u CTFs kao "generisali smo mnogo ključeva brzo" ili "loša slučajnost".

### Sparse / short-sleeve moduli

Neki neispravni generatori velikih celih brojeva direktno otkrivaju strukturu u javnom modulu: svaki limb sadrži samo malo slučajno podpolje, dok su preostali bitovi `0`. U praksi se ovo pojavljuje kao **pravilno raspoređeni blokovi nula** kroz `n`, često poravnati sa limbovima od 32 ili 128 bita.<sup>[[1]](#references)</sup>

Brze provere:

- Ispišite `n` u hex formatu i potražite ponovljene prozore nula sa fiksnim korakom.
- Ponovo razdvojite `n` na limbove (`2^32`, `2^64`, `2^128`) i proverite da li je svaki limb neuobičajeno mali.
- Proverite javne SSH/TLS ključeve pomoću alata kao što je **badkeys** kada sumnjate na slabo generisanje host-key vrednosti.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Ovo je ozbiljnije od statističke pristrasnosti: ako su oba privatna faktora `p` i `q` short-sleeve, modulus može postati **lak za faktorizaciju**.<sup>[[1]](#references)</sup>

### Polynomial factorization strukturiranih RSA ključeva

Za pretpostavljenu širinu limba `w`, zapišite modulus u bazi `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Pošto je evaluacija multiplikativna, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Ako faktori takođe imaju sparse limb koeficijente, tada:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Okvirni postupak napada:

1. Pogodite širinu limba `w`.
2. Konvertujte javni modulus `n` u `f_n(x)` koristeći bazu `2^w`.
3. Faktorišite `f_n(x)` nad celim brojevima.
4. Evaluirajte kandidate za faktore ponovo u `B = 2^w`.
5. Proverite koji kandidati daju proizvod jednak `n`.

Ovo **ne razbija normalan RSA**. Radi samo kada sami prosti faktori imaju veoma male, visoko strukturirane limb koeficijente.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse bytes nisu uvek poravnati na donjem kraju svakog limba. Ako direktna konverzija u bazi `2^w` proizvodi velike koeficijente, pretražite pomeranja `i,j` takva da `2^i p` i `2^j q` postanu sparse u toj limb bazi. Polynomial proizvod se i dalje može izvesti iz javnog modula, faktorisati i ponovo sastaviti u originalne celobrojne faktore.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

Opasan obrazac je izračunavanje broja **32-bitnih limbova**, alociranje samo tolikog broja **bajtova** i njihovo kopiranje u limb niz:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Ovo svakom 32-bitnom limb-u daje samo **8 bitova entropije**, uz nametnuti najviši bit u poslednjem limb-u. Dobijeni RSA prosti brojevi često mogu da se prepoznaju i faktorišu samo na osnovu javnog ključa.<sup>[[1]](#references)</sup>

### Related DSA failure mode

Ako se ista neispravna rutina za velike cele brojeve ponovo koristi za generisanje privatnog eksponenta DSA, javni ključ `y = g^x` može da otkrije **dramatično smanjen i strukturiran** prostor za pretragu vrednosti `x`. Kada je obrazac limb-ova poznat, napadi na diskretni logaritam kao što je **baby-step giant-step** mogu postati praktični protiv javnih parametara.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Ako se isti plaintext šalje većem broju primalaca sa malim `e` (često `e=3`) i bez odgovarajućeg padding-a, možete povratiti `m` pomoću CRT-a i integer root-a.

Tehnički uslov:

Ako imate `e` ciphertext-ova iste poruke pod modulima `n_i` koji su uzajamno prosti:

- Koristite CRT da povratite `M = m^e` nad proizvodom `N = Π n_i`
- Ako je `m^e < N`, onda je `M` stvarni stepen celog broja, a `m = integer_root(M, e)`

### Wiener attack: mali privatni eksponent

Ako je `d` premalo, continued fractions mogu da ga povrate iz `e/n`.

### Zamke textbook RSA-a

Ako vidite:

- Bez OAEP/PSS-a, sirova modularna eksponencijacija
- Determinističko šifrovanje

onda algebarski napadi i zloupotreba oracle-a postaju mnogo verovatniji.

### Alati

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Obrasci povezanih poruka

Ako vidite dva ciphertext-a pod istim modulom, sa porukama koje su algebarski povezane (npr. `m2 = a*m1 + b`), potražite napade na "related-message", kao što je Franklin–Reiter. Oni obično zahtevaju:

- isti modul `n`
- isti eksponent `e`
- poznatu vezu između plaintext-ova

U praksi se ovo često rešava pomoću Sage-a, postavljanjem polinoma modulo `n` i izračunavanjem GCD-a.

## Lattices / Coppersmith

Koristite ovo kada imate parcijalne bitove, strukturirani plaintext ili bliske relacije zbog kojih nepoznata vrednost postaje mala.

Lattice metode (LLL/Coppersmith) pojavljuju se kada imate parcijalne informacije:

- Delimično poznat plaintext (strukturirana poruka sa nepoznatim završetkom)
- Delimično poznat `p`/`q` (procureli najviši bitovi)
- Male nepoznate razlike između povezanih vrednosti

### Šta prepoznati

Tipični nagoveštaji u izazovima:

- "Procureli su nam najviši/najniži bitovi od p"
- "Zastava je ugrađena ovako: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Koristili smo RSA, ali sa malim nasumičnim padding-om"

### Alati

U praksi ćete koristiti Sage za LLL i poznati template za konkretnu instancu.

Dobre početne tačke:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Referenca u formi pregleda: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Faktorisanje "short-sleeve" RSA ključeva pomoću polinoma](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys samostalni alat](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
