# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Brza procena

Prikupite:

- `n`, `e`, `c` (i sve dodatne ciphertext-e)
- Sve odnose između poruka (isti plaintext? deljeni modulus? strukturirani plaintext?)
- Sve leak-ove (delimični `p/q`, bitove od `d`, `dp/dq`, poznati padding)

Zatim pokušajte:

- Proveru faktorizacije (Factordb / `sage: factor(n)` za relativno male vrednosti)
- Obrasce sa malim eksponentom (`e=3`, broadcast)
- Common modulus / ponovljene proste brojeve
- Lattice metode (Coppersmith/LLL) kada je nešto gotovo poznato

## Common RSA attacks

### Common modulus

Ako dva ciphertext-a `c1, c2` šifruju **istu poruku** pod **istim modulusom** `n`, ali sa različitim eksponentima `e1, e2` (i `gcd(e1,e2)=1`), možete oporaviti `m` pomoću proširenog Euklidovog algoritma:

`m = c1^a * c2^b mod n` gde je `a*e1 + b*e2 = 1`.

Okvirni postupak:

1. Izračunajte `(a, b) = xgcd(e1, e2)` tako da važi `a*e1 + b*e2 = 1`
2. Ako je `a < 0`, tumačite `c1^a` kao `inv(c1)^{-a} mod n` (isto važi i za `b`)
3. Pomnožite i redukujte modulo `n`

### Shared primes across moduli

Ako imate više RSA modula iz istog izazova, proverite da li dele jedan prost broj:

- `gcd(n1, n2) != 1` podrazumeva katastrofalan propust pri generisanju ključeva.

Ovo se često pojavljuje u CTF-ovima kao "we generated many keys quickly" ili "bad randomness".

### Sparse / short-sleeve moduli

Neki neispravni generatori velikih celih brojeva direktno otkrivaju strukturu u javnom modulu: svaki limb sadrži samo malo nasumično podpolje, dok su preostali bitovi `0`. U praksi se ovo ispoljava kao **pravilno raspoređeni blokovi nula** duž `n`, često poravnati sa limb-ovima od 32 ili 128 bitova.<sup>[[1]](#references)</sup>

Brze provere:

- Ispišite `n` u hex formatu i potražite ponovljene prozore nula sa fiksnim korakom.
- Ponovo isecite `n` na limb-ove (`2^32`, `2^64`, `2^128`) i proverite da li je svaki limb neuobičajeno mali.
- Proverite javne SSH/TLS ključeve alatima kao što je **badkeys** kada sumnjate na slabo generisanje host-key-eva.<sup>[[2]](#references)[[3]](#references)</sup>

Ovo je ozbiljnije od statističke pristrasnosti: ako su oba privatna faktora `p` i `q` short-sleeved, modulus može postati **lak za faktorisanje**.<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

Za pretpostavljenu širinu limb-a `w`, zapišite modulus u bazi `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Pošto je evaluacija multiplikativna, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Ako faktori takođe imaju sparse limb koeficijente, onda važi:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Okvirni postupak napada:

1. Pogodite širinu limb-a `w`.
2. Konvertujte javni modulus `n` u `f_n(x)` koristeći bazu `2^w`.
3. Faktorišite `f_n(x)` nad celim brojevima.
4. Evaluirajte kandidate faktora ponovo u `B = 2^w`.
5. Proverite koji kandidati daju proizvod jednak `n`.

Ovo **ne razbija normalni RSA**. Funkcioniše samo kada sami prosti faktori imaju veoma male, visoko strukturirane limb koeficijente.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Sparse bajtovi nisu uvek poravnati sa nižim krajem svakog limb-a. Ako direktna konverzija sa bazom `2^w` daje velike koeficijente, pretražite pomeranja `i,j` takva da `2^i p` i `2^j q` postanu sparse u toj limb bazi. Polinom proizvoda se i dalje može izvesti iz javnog modula, faktorisati i ponovo kombinovati u originalne celobrojne faktore.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

Opasan obrazac je izračunavanje broja **32-bitnih limb-ova**, alociranje samo toliko **bajtova** i njihovo kopiranje u niz limb-ova:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Ovo svakom 32-bitnom limb-u daje samo **8 bitova entropije**, uz nametnuti najviši bit u poslednjem limb-u. Dobijeni RSA prosti brojevi često mogu biti prepoznati i faktorisani samo na osnovu javnog ključa.<sup>[[1]](#references)</sup>

### Povezani DSA failure mode

Ako se ista neispravna big-integer rutina ponovo koristi za generisanje privatnog eksponenta za DSA, javni ključ `y = g^x` može otkriti **dramatično smanjen i strukturiran** prostor pretrage za `x`. Kada je obrazac limb-ova poznat, napadi na diskretni logaritam, kao što je **baby-step giant-step**, mogu postati praktični protiv javnih parametara.<sup>[[1]](#references)</sup>

### Håstad broadcast / mali eksponent

Ako se isti plaintext šalje većem broju primalaca sa malim `e` (često `e=3`) i bez odgovarajućeg padding-a, možete oporaviti `m` pomoću CRT-a i celobrojnog korena.

Tehnički uslov:

Ako imate `e` ciphertext-a iste poruke, šifrovanih pomoću modula `n_i` koji su uzajamno uzajamno prosti:

- Koristite CRT da oporavite `M = m^e` nad proizvodom `N = Π n_i`
- Ako je `m^e < N`, tada je `M` stvarni celobrojni stepen, a `m = integer_root(M, e)`

### Wiener attack: mali privatni eksponent

Ako je `d` premalo, continued fractions ga mogu oporaviti iz `e/n`.

### Zamke textbook RSA

Ako vidite:

- Bez OAEP/PSS, sirova modularna eksponencijacija
- Determinističko šifrovanje

tada algebarski napadi i oracle abuse postaju mnogo verovatniji.

### Alati

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Obrasci related-message

Ako vidite dva ciphertext-a pod istim modulom, sa porukama koje su algebarski povezane (npr. `m2 = a*m1 + b`), potražite napade tipa "related-message", kao što je Franklin–Reiter. Oni obično zahtevaju:

- isti modul `n`
- isti eksponent `e`
- poznatu vezu između plaintext-ova

U praksi se ovo često rešava pomoću Sage-a, postavljanjem polinoma modulo `n` i izračunavanjem GCD-a.

## Lattice / Coppersmith

Primenite ovo kada imate delimične bitove, strukturirani plaintext ili bliske relacije zbog kojih je nepoznata vrednost mala.

Lattice metode (LLL/Coppersmith) pojavljuju se kada imate delimične informacije:

- Delimično poznat plaintext (strukturirana poruka sa nepoznatim nastavkom)
- Delimično poznat `p`/`q` (procureli najviši bitovi)
- Male nepoznate razlike između povezanih vrednosti

### Šta prepoznati

Tipični nagoveštaji u challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Alati

U praksi ćete koristiti Sage za LLL i poznati template za konkretnu instancu.

Dobre početne tačke:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## Reference

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
