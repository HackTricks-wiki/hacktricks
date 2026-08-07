# Ataki RSA

{{#include ../../../banners/hacktricks-training.md}}

## Szybki triage

Zbierz:

- `n`, `e`, `c` (oraz wszelkie dodatkowe ciphertexts)
- Wszelkie zależności między wiadomościami (ten sam plaintext? współdzielony modulus? ustrukturyzowany plaintext?)
- Wszelkie leaki (częściowe `p/q`, bity `d`, `dp/dq`, znany padding)

Następnie spróbuj:

- Sprawdzenia faktoryzacji (Factordb / `sage: factor(n)` dla wartości niewielkich lub względnie niewielkich)
- Wzorców niskiego wykładnika (`e=3`, broadcast)
- Common modulus / powtarzających się liczb pierwszych
- Metod kratowych (Coppersmith/LLL), gdy coś jest prawie znane

## Typowe ataki na RSA

### Common modulus

Jeśli dwa ciphertexts `c1, c2` szyfrują **tę samą wiadomość** przy użyciu **tego samego modulu** `n`, ale z różnymi wykładnikami `e1, e2` (oraz `gcd(e1,e2)=1`), możesz odzyskać `m` za pomocą rozszerzonego algorytmu Euklidesa:

`m = c1^a * c2^b mod n`, gdzie `a*e1 + b*e2 = 1`.

Zarys przykładu:

1. Oblicz `(a, b) = xgcd(e1, e2)`, tak aby `a*e1 + b*e2 = 1`
2. Jeśli `a < 0`, zinterpretuj `c1^a` jako `inv(c1)^{-a} mod n` (analogicznie dla `b`)
3. Pomnóż i zredukuj modulo `n`

### Współdzielone liczby pierwsze między modulusami

Jeśli masz wiele moduli RSA z tego samego zadania, sprawdź, czy współdzielą liczbę pierwszą:

- `gcd(n1, n2) != 1` oznacza katastrofalny błąd generowania klucza.

Często pojawia się to w CTF-ach jako „wygenerowaliśmy szybko wiele kluczy” albo „zła losowość”.

### Rzadkie / short-sleeve moduli

Niektóre wadliwe generatory big-integer ujawniają strukturę bezpośrednio w publicznym modulusie: każdy limb zawiera tylko małe losowe podpole, a pozostałe bity to `0`. W praktyce objawia się to jako **regularnie rozmieszczone bloki zer** w `n`, często wyrównane do limbów 32-bitowych lub 128-bitowych.<sup>[[1]](#references)</sup>

Szybkie sprawdzenia:

- Zrzuć `n` w zapisie szesnastkowym i poszukaj powtarzających się okien zer ze stałym krokiem.
- Podziel ponownie `n` na limby (`2^32`, `2^64`, `2^128`) i sprawdź, czy każdy limb jest nietypowo mały.
- Przeprowadź audyt publicznych kluczy SSH/TLS za pomocą narzędzi takich jak **badkeys**, gdy podejrzewasz słabe generowanie kluczy hosta.<sup>[[2]](#references)[[3]](#references)</sup>

Jest to poważniejsze niż bias statystyczny: jeśli oba prywatne czynniki `p` i `q` są short-sleeve, modulus może stać się **łatwy do sfaktoryzowania**.<sup>[[1]](#references)</sup>

### Wielomianowa faktoryzacja ustrukturyzowanych kluczy RSA

Dla podejrzewanej szerokości limbu `w` zapisz modulus w bazie `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Ponieważ ewaluacja zachowuje mnożenie, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Jeśli czynniki również mają rzadkie współczynniki limbów, wtedy:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Zarys ataku:

1. Zgadnij szerokość limbu `w`.
2. Przekształć publiczny modulus `n` w `f_n(x)` za pomocą bazy `2^w`.
3. Sfaktoryzuj `f_n(x)` nad liczbami całkowitymi.
4. Oblicz wartości potencjalnych czynników ponownie dla `B = 2^w`.
5. Sprawdź, które potencjalne czynniki po pomnożeniu dają `n`.

To **nie łamie standardowego RSA**. Działa wyłącznie wtedy, gdy czynniki pierwsze mają bardzo małe, wysoce ustrukturyzowane współczynniki limbów.<sup>[[1]](#references)</sup>

### Wyciek przesuniętych limbów

Rzadkie bajty nie zawsze są wyrównane do dolnego końca każdego limbu. Jeśli bezpośrednia konwersja do bazy `2^w` daje duże współczynniki, poszukaj przesunięć `i,j`, dla których `2^i p` i `2^j q` stają się rzadkie w tej bazie limbów. Wielomian iloczynu nadal można wyprowadzić z publicznego modulu, sfaktoryzować i ponownie połączyć w oryginalne czynniki całkowite.<sup>[[1]](#references)</sup>

### Zapach implementacji: błąd RNG przy konwersji bajtów do limbów

Niebezpieczny wzorzec polega na obliczeniu liczby **32-bitowych limbów**, zaalokowaniu tylko takiej liczby **bajtów** i skopiowaniu ich do tablicy limbów:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
This daje każdemu 32-bitowemu limbowi tylko **8 bitów entropii** oraz wymuszony najwyższy bit w ostatnim limbie. Wynikowe prime'y RSA można często rozpoznać i sfaktoryzować wyłącznie na podstawie klucza publicznego.<sup>[[1]](#references)</sup>

### Powiązany tryb awarii DSA

Jeśli ta sama uszkodzona procedura big-integer zostanie ponownie użyta do generowania prywatnego wykładnika DSA, klucz publiczny `y = g^x` może leakować **drastycznie zredukowaną i ustrukturyzowaną** przestrzeń wyszukiwania dla `x`. Gdy wzorzec limbów jest znany, ataki na discrete-log, takie jak **baby-step giant-step**, mogą stać się praktyczne przeciwko parametrom publicznym.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Jeśli ten sam plaintext zostanie wysłany do wielu odbiorców z małym `e` (często `e=3`) i bez właściwego paddingu, możesz odzyskać `m` za pomocą CRT i pierwiastka całkowitego.

Warunek techniczny:

Jeśli masz `e` ciphertextów tej samej wiadomości przy użyciu parami względnie pierwszych modulusów `n_i`:

- Użyj CRT, aby odzyskać `M = m^e` modulo iloczynu `N = Π n_i`
- Jeśli `m^e < N`, wtedy `M` jest prawdziwą potęgą całkowitą, a `m = integer_root(M, e)`

### Wiener attack: mały prywatny wykładnik

Jeśli `d` jest zbyt małe, ułamki łańcuchowe mogą odzyskać je z `e/n`.

### Pułapki textbook RSA

Jeśli widzisz:

- Brak OAEP/PSS, surowe modular exponentiation
- Deterministyczne szyfrowanie

wtedy ataki algebraiczne i nadużywanie oracle stają się znacznie bardziej prawdopodobne.

### Narzędzia

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Wzorce related-message

Jeśli widzisz dwa ciphertexty przy użyciu tego samego modulu, których wiadomości są powiązane algebraicznie (np. `m2 = a*m1 + b`), szukaj ataków typu "related-message", takich jak Franklin–Reiter. Zwykle wymagają one:

- tego samego modulu `n`
- tego samego wykładnika `e`
- znanej zależności między plaintextami

W praktyce często rozwiązuje się to w Sage, definiując wielomiany modulo `n` i obliczając GCD.

## Lattices / Coppersmith

Sięgnij po tę technikę, gdy masz częściowe bity, ustrukturyzowany plaintext lub bliskie zależności, które sprawiają, że niewiadoma jest mała.

Metody lattice (LLL/Coppersmith) pojawiają się zawsze, gdy masz częściowe informacje:

- Częściowo znany plaintext (ustrukturyzowana wiadomość z nieznanym końcem)
- Częściowo znane `p`/`q` (wyciekły wysokie bity)
- Małe nieznane różnice między powiązanymi wartościami

### Co rozpoznawać

Typowe wskazówki w challenge'ach:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

W praktyce użyjesz Sage do LLL oraz znanego template'u dla konkretnej instancji.

Dobre punkty wyjścia:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
