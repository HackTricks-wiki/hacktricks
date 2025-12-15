# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Brza trijaža

Prikupite:

- `n`, `e`, `c` (and any additional ciphertexts)
- Bilo kakve veze između poruka (isti plaintext? deljeni modul? strukturiran plaintext?)
- Any leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Zatim pokušajte:

- Provera faktorizacije (Factordb / `sage: factor(n)` for small-ish)
- Obrasci malog eksponenta (`e=3`, broadcast)
- Deljeni modul / ponovljeni prosti faktori
- Metode rešetke (Coppersmith/LLL) kada je nešto skoro poznato

## Uobičajeni RSA napadi

### Common modulus

Ako dva šifroteksta `c1, c2` šifruju **istu poruku** pod **istim modulom** `n` ali sa različitim eksponentima `e1, e2` (i `gcd(e1,e2)=1`), možete oporaviti `m` koristeći prošireni Euklidov algoritam:

`m = c1^a * c2^b mod n` gde je `a*e1 + b*e2 = 1`.

Skica primera:

1. Izračunajte `(a, b) = xgcd(e1, e2)` tako da je `a*e1 + b*e2 = 1`
2. Ako je `a < 0`, interpretirajte `c1^a` kao `inv(c1)^{-a} mod n` (isto važi za `b`)
3. Pomnožite i redukujte modulo `n`

### Deljeni prosti faktori među modulima

Ako imate više RSA modula iz istog izazova, proverite da li dele prosti faktor:

- `gcd(n1, n2) != 1` implicira katastrofalan neuspeh pri generisanju ključeva.

Ovo se često pojavljuje u CTFs kao "we generated many keys quickly" ili "bad randomness".

### Håstad broadcast / mali eksponent

Ako je isti otvoreni tekst poslat više primalaca sa malim `e` (često `e=3`) i bez pravilnog paddinga, možete oporaviti `m` koristeći CRT i celobrojni koren.

Tehnički uslov:

Ako imate `e` šifrotekstova iste poruke pod parno-koprim modulima `n_i`:

- Koristite CRT da rekonstrušete `M = m^e` nad proizvodom `N = Π n_i`
- Ako je `m^e < N`, tada je `M` pravi ceo stepen, i `m = integer_root(M, e)`

### Wiener attack: mali privatni eksponent

Ako je `d` previše mali, kontinuirani lanci (continued fractions) mogu ga izdvojiti iz `e/n`.

### Zamke Textbook RSA

Ako vidite:

- No OAEP/PSS, raw modular exponentiation
- Determinističko šifrovanje

onda algebrački napadi i zloupotreba oracle-a postaju mnogo verovatniji.

### Alati

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Obrasci povezanih poruka

Ako vidite dva šifroteksta pod istim modulom sa porukama koje su algebarski povezane (npr. `m2 = a*m1 + b`), tražite "related-message" napade kao što je Franklin–Reiter. To obično zahteva:

- isti modul `n`
- isti eksponent `e`
- poznat odnos između plaintext-ova

U praksi se ovo često rešava u Sage tako što se postave polinomi modulo `n` i izračuna GCD.

## Rešetke / Coppersmith

Okrenite se ovome kada imate delimične bitove, strukturiran otvoreni tekst, ili bliske relacije koje čine nepoznato malim.

Metode rešetke (LLL/Coppersmith) se primenjuju kad god imate delimične informacije:

- Delimično poznat plaintext (strukturirana poruka sa nepoznatim krajem)
- Delimično poznat `p`/`q` (high bits leaked)
- Male nepoznate razlike između povezanih vrednosti

### Šta prepoznati

Tipični nagoveštaji u izazovima:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Alati i resursi

U praksi ćete koristiti Sage za LLL i poznat šablon za specifičan slučaj.

Dobre polazne tačke:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
