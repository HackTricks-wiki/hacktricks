# Ataki RSA

{{#include ../../../banners/hacktricks-training.md}}

## Szybki triage

Zbierz:

- `n`, `e`, `c` (oraz wszelkie dodatkowe ciphertexts)
- Wszelkie zależności między wiadomościami (ten sam plaintext? wspólny modulus? ustrukturyzowany plaintext?)
- Wszelkie leaki (częściowe `p/q`, bity `d`, `dp/dq`, znane padding)

Następnie spróbuj:

- Sprawdzenia faktoryzacji (Factordb / `sage: factor(n)` dla niezbyt dużych wartości)
- Wzorców niskiego wykładnika (`e=3`, broadcast)
- Common modulus / powtarzających się liczb pierwszych
- Metod kratowych (Coppersmith/LLL), gdy coś jest prawie znane

## Typowe ataki RSA

### Common modulus

Jeśli dwa ciphertexts `c1, c2` szyfrują **tę samą wiadomość** przy użyciu **tego samego modulu** `n`, ale z różnymi wykładnikami `e1, e2` (oraz `gcd(e1,e2)=1`), możesz odzyskać `m` za pomocą rozszerzonego algorytmu Euklidesa:

`m = c1^a * c2^b mod n` gdzie `a*e1 + b*e2 = 1`.

Zarys:

1. Oblicz `(a, b) = xgcd(e1, e2)`, tak aby `a*e1 + b*e2 = 1`
2. Jeśli `a < 0`, zinterpretuj `c1^a` jako `inv(c1)^{-a} mod n` (analogicznie dla `b`)
3. Pomnóż i zredukuj modulo `n`

### Współdzielone liczby pierwsze między modulami

Jeśli masz wiele moduli RSA z tego samego challenge'u, sprawdź, czy współdzielą liczbę pierwszą:

- `gcd(n1, n2) != 1` oznacza katastrofalny błąd generowania kluczy.

Często pojawia się to w CTF-ach jako „wygenerowaliśmy wiele kluczy szybko” lub „zła losowość”.

### Sparse / short-sleeve moduli

Niektóre uszkodzone generatory big-integerów ujawniają strukturę bezpośrednio w publicznym modulu: każdy limb zawiera tylko małe losowe podpole, a pozostałe bity mają wartość `0`. W praktyce objawia się to **regularnie rozmieszczonymi blokami zer** w `n`, często wyrównanymi do 32-bitowych lub 128-bitowych limbów.<sup>[[1]](#references)</sup>

Szybkie sprawdzenia:

- Zrzuć `n` w systemie szesnastkowym i poszukaj powtarzających się okien zer o stałym kroku.
- Podziel ponownie `n` na limby (`2^32`, `2^64`, `2^128`) i sprawdź, czy każdy limb jest nietypowo mały.
- Przeprowadź audyt publicznych kluczy SSH/TLS za pomocą narzędzi takich jak **badkeys**, gdy podejrzewasz słabe generowanie host-key.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Jest to poważniejsze niż statystyczny bias: jeśli oba prywatne czynniki `p` i `q` mają short-sleeve, modulus może stać się **łatwy do faktoryzacji**.<sup>[[1]](#references)</sup>

### Faktoryzacja wielomianowa ustrukturyzowanych kluczy RSA

Dla podejrzewanej szerokości limba `w` zapisz modulus w bazie `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Ponieważ ewaluacja jest multiplikatywna, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Jeśli czynniki również mają rzadkie współczynniki limbów, wtedy:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Zarys ataku:

1. Zgadnij szerokość limba `w`.
2. Przekształć publiczny modulus `n` do `f_n(x)` za pomocą bazy `2^w`.
3. Rozłóż `f_n(x)` na czynniki nad liczbami całkowitymi.
4. Oblicz wartości potencjalnych czynników ponownie dla `B = 2^w`.
5. Sprawdź, które potencjalne czynniki dają w iloczynie `n`.

To **nie łamie normalnego RSA**. Działa wyłącznie wtedy, gdy czynniki pierwsze same mają bardzo małe, wysoce ustrukturyzowane współczynniki limbów.<sup>[[1]](#references)</sup>

### Wyciek przesuniętych limbów

Rzadkie bajty nie zawsze są wyrównane do dolnego końca każdego limba. Jeśli bezpośrednia konwersja w bazie `2^w` daje duże współczynniki, poszukaj przesunięć `i,j`, takich że `2^i p` i `2^j q` stają się rzadkie w tej bazie limbów. Wielomian iloczynu nadal można wyprowadzić z publicznego modulu, rozłożyć na czynniki i ponownie połączyć w oryginalne czynniki całkowite.<sup>[[1]](#references)</sup>

### Problem implementacyjny: błąd RNG przy konwersji bajtów na limby

Niebezpieczny wzorzec polega na obliczeniu liczby **32-bitowych limbów**, przydzieleniu tylko takiej liczby **bajtów** i skopiowaniu ich do tablicy limbów:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
To daje każdemu 32-bitowemu limbowi tylko **8 bitów entropii** oraz wymuszony najwyższy bit w ostatnim limb. Wynikowe liczby pierwsze RSA można często rozpoznać i rozłożyć na czynniki wyłącznie na podstawie klucza publicznego.<sup>[[1]](#references)</sup>

### Related DSA failure mode

Jeśli ta sama wadliwa procedura obsługi dużych liczb zostanie ponownie użyta do generowania prywatnego wykładnika DSA, klucz publiczny `y = g^x` może leakować **dramatycznie zmniejszoną i uporządkowaną** przestrzeń wyszukiwania dla `x`. Po poznaniu wzorca limbów ataki na logarytm dyskretny, takie jak **baby-step giant-step**, mogą stać się praktyczne dla parametrów publicznych.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Jeśli ten sam plaintext zostanie wysłany do wielu odbiorców z małym `e` (często `e=3`) i bez prawidłowego paddingu, można odzyskać `m` za pomocą CRT i pierwiastka całkowitoliczbowego.

Warunek techniczny:

Jeśli masz `e` ciphertextów tej samej wiadomości zaszyfrowanych przy użyciu parami względnie pierwszych modułów `n_i`:

- Użyj CRT, aby odzyskać `M = m^e` względem iloczynu `N = Π n_i`
- Jeśli `m^e < N`, wtedy `M` jest prawdziwą potęgą całkowitą, a `m = integer_root(M, e)`

### Wiener attack: small private exponent

Jeśli `d` jest zbyt małe, ułamki łańcuchowe mogą odzyskać je z `e/n`.

### Textbook RSA pitfalls

Jeśli widzisz:

- Brak OAEP/PSS, surowe potęgowanie modularne
- Deterministyczne szyfrowanie

wówczas ataki algebraiczne i nadużywanie oracle stają się znacznie bardziej prawdopodobne.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Jeśli widzisz dwa ciphertexty przy użyciu tego samego modułu, z wiadomościami powiązanymi algebraicznie (np. `m2 = a*m1 + b`), szukaj ataków typu "related-message", takich jak Franklin–Reiter. Zwykle wymagają one:

- tego samego modułu `n`
- tego samego wykładnika `e`
- znanej zależności między plaintextami

W praktyce często rozwiązuje się to za pomocą Sage, definiując wielomiany modulo `n` i obliczając ich NWD.

## Lattices / Coppersmith

Sięgnij po tę metodę, gdy masz częściowe bity, uporządkowany plaintext lub bliskie zależności powodujące, że niewiadoma jest mała.

Metody lattice (LLL/Coppersmith) pojawiają się zawsze wtedy, gdy masz częściowe informacje:

- Częściowo znany plaintext (uporządkowana wiadomość z nieznaną końcówką)
- Częściowo znane `p`/`q` (wysokie bity zostały leak)
- Małe, nieznane różnice między powiązanymi wartościami

### What to recognize

Typowe wskazówki w challenge'ach:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

W praktyce użyjesz Sage do LLL oraz znanego szablonu dla konkretnej instancji.

Dobre punkty wyjścia:

- Szablony Sage do CTF crypto: https://github.com/defund/coppersmith
- Referencja w formie przeglądu: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Faktoryzacja kluczy RSA typu "short-sleeve" za pomocą wielomianów](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [samodzielne narzędzie badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
