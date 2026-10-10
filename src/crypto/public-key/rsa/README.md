# RSA napadi

{{#include ../../../banners/hacktricks-training.md}}

## Brza procena

Prikupite:

- `n`, `e`, `c` (i sve dodatne šifrate)
- Sve veze između poruka (isti otvoreni tekst? zajednički modul? strukturirani otvoreni tekst?)
- Sve leaks (delimični `p/q`, bitove od `d`, `dp/dq`, poznato dopunjavanje)

Zatim pokušajte:

- Proveru faktorizacije (Factordb / `sage: factor(n)` za relativno male vrednosti)
- Obrasce malog eksponenta (`e=3`, broadcast)
- Common modulus / ponovljene proste brojeve
- Lattice metode (Coppersmith/LLL) kada je nešto gotovo poznato

## Uobičajeni RSA napadi

### Common modulus

Ako dva šifrata `c1, c2` šifruju **istu poruku** pod **istim modulom** `n`, ali sa različitim eksponentima `e1, e2` (i `gcd(e1,e2)=1`), možete oporaviti `m` pomoću proširenog Euklidovog algoritma:

`m = c1^a * c2^b mod n` gde je `a*e1 + b*e2 = 1`.

Primer postupka:

1. Izračunajte `(a, b) = xgcd(e1, e2)` tako da je `a*e1 + b*e2 = 1`
2. Ako je `a < 0`, tumačite `c1^a` kao `inv(c1)^{-a} mod n` (isto važi za `b`)
3. Pomnožite i svedite po modulu `n`

### Zajednički prosti činioci među modulima

Ako imate više RSA modula iz istog izazova, proverite da li dele neki prost činilac:

- `gcd(n1, n2) != 1` ukazuje na katastrofalan propust u generisanju ključeva.

Ovo se često pojavljuje u CTF-ovima uz objašnjenja poput „brzo smo generisali mnogo ključeva“ ili „loša slučajnost“.

### Retki / short-sleeve moduli

Neki pokvareni generatori velikih celih brojeva direktno ostavljaju strukturu u javnom modulu: svaki limb sadrži samo malo nasumično podpolje, a ostali bitovi su `0`. U praksi se to vidi kao **blokovi nula u pravilnim razmacima** širom `n`, često poravnati sa limbovima od 32 ili 128 bita.<sup>[[1]](#references)</sup>

Brze provere:

- Ispišite `n` u heksadecimalnom obliku i potražite ponovljene prozore nula sa fiksnim razmakom.
- Ponovo podelite `n` na limbove (`2^32`, `2^64`, `2^128`) i proverite da li je svaki limb neuobičajeno mali.
- Proverite javne SSH/TLS ključeve alatima kao što je **badkeys** ako sumnjate na slabo generisanje host ključeva.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Ovo je ozbiljnije od statističke pristrasnosti: ako su oba privatna činioca `p` i `q` short-sleeve, modul može postati **lak za faktorizaciju**.<sup>[[1]](#references)</sup>

### Polinomijalna faktorizacija strukturiranih RSA ključeva

Za pretpostavljenu širinu limba `w`, zapišite modul u bazi `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Pošto je evaluacija multiplikativna, važi `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Ako faktori takođe imaju retke limb koeficijente, onda važi:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Okvirni postupak napada:

1. Pogodite širinu limba `w`.
2. Pretvorite javni modul `n` u `f_n(x)` koristeći bazu `2^w`.
3. Faktorišite `f_n(x)` nad celim brojevima.
4. Evaluirajte kandidate za faktore nazad u `B = 2^w`.
5. Proverite koji kandidati daju proizvod `n`.

Ovim se **ne razbija normalan RSA**. Funkcioniše samo kada sami prosti činioci imaju veoma male, visoko strukturirane limb koeficijente.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Retki bajtovi nisu uvek poravnati na donjem kraju svakog limba. Ako direktna konverzija u bazu `2^w` daje velike koeficijente, potražite pomeraje `i,j` takve da `2^i p` i `2^j q` postanu retki u toj bazi limbova. Polinom proizvoda i dalje se može izvesti iz javnog modula, faktorisati i ponovo kombinovati u originalne celobrojne faktore.<sup>[[1]](#references)</sup>

### Miris implementacije: greška u byte-to-limb RNG-u

Opasan obrazac je izračunavanje broja **32-bitnih limbova**, alociranje samo toliko **bajtova** i njihovo kopiranje u niz limbova:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

Ovo svakom 32-bitnom limb-u daje samo **8 bitova entropije** uz nametnuti najviši bit u poslednjem limb-u. Dobijeni RSA prosti brojevi često se mogu prepoznati i faktorisati samo na osnovu javnog ključa.<sup>[[1]](#references)</sup>

### Povezani DSA način otkaza

Ako se ista neispravna rutina za velike cele brojeve ponovo koristi za generisanje privatnog eksponenta za DSA, javni ključ `y = g^x` može da otkrije **dramatično smanjen i strukturisan** prostor za pretragu vrednosti `x`. Kada je obrazac limb-ova poznat, napadi na diskretni logaritam kao što je **baby-step giant-step** mogu postati praktični nad javnim parametrima.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Ako se ista poruka šalje većem broju primalaca sa malim `e` (često `e=3`) i bez ispravnog padding-a, možete da oporavite `m` pomoću CRT-a i celobrojnog korena.

Tehnički uslov:

Ako imate `e` šifrovanih tekstova iste poruke pod međusobno uzajamno prostim modulima `n_i`:

- Koristite CRT da oporavite `M = m^e` nad proizvodom `N = Π n_i`
- Ako je `m^e < N`, onda je `M` pravi celobrojni stepen, a `m = integer_root(M, e)`

### Wiener attack: mali privatni eksponent

Ako je `d` premalo, verižni razlomci mogu da ga oporave iz `e/n`.

### Zamke textbook RSA

Ako primetite:

- Nema OAEP/PSS, samo sirovo modularno stepenovanje
- Determinističko šifrovanje

onda su algebarski napadi i zloupotreba oracle-a mnogo verovatniji.

### Alati

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, koreni, CF): https://www.sagemath.org/

## Obrasci povezanih poruka

Ako primetite dva šifrovana teksta pod istim modulom čije su poruke algebarski povezane (npr. `m2 = a*m1 + b`), potražite napade na „povezane poruke“ kao što je Franklin–Reiter. Za njih je obično potrebno:

- isti modul `n`
- isti eksponent `e`
- poznata veza između otvorenih tekstova

U praksi se ovo često rešava pomoću Sage-a tako što se postave polinomi modulo `n` i izračuna NZD.

## Lattices / Coppersmith

Koristite ovo kada imate delimične bitove, strukturisan otvoreni tekst ili bliske veze zbog kojih je nepoznata vrednost mala.

Metode rešetki (LLL/Coppersmith) koriste se kad god imate delimične informacije:

- Delimično poznat otvoreni tekst (strukturisana poruka sa nepoznatim završetkom)
- Delimično poznat `p`/`q` (procureli su najviši bitovi)
- Male nepoznate razlike između povezanih vrednosti

### Šta treba prepoznati

Tipični nagoveštaji u izazovima:

- „Procureli su nam najviši/najniži bitovi broja p“
- „Zastavica je ugrađena ovako: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`“
- „Koristili smo RSA, ali sa malim nasumičnim padding-om“

### Alati

U praksi ćete koristiti Sage za LLL i poznati šablon za konkretnu instancu.

Dobri početni izvori:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Referenca u stilu pregleda: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Faktorisanje RSA ključeva sa „kratkim rukavima“ pomoću polinoma](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys samostalni alat](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

