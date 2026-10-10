# Ataki RSA

{{#include ../../../banners/hacktricks-training.md}}

## Szybka wstępna analiza

Zbierz:

- `n`, `e`, `c` (oraz wszelkie dodatkowe szyfrogramy)
- Wszelkie zależności między wiadomościami (ten sam tekst jawny? wspólny modulus? ustrukturyzowany tekst jawny?)
- Wszelkie leaks (częściowe `p/q`, bity `d`, `dp/dq`, znane padding)

Następnie spróbuj:

- Sprawdzić faktoryzację (`Factordb` / `sage: factor(n)` dla niezbyt dużych liczb)
- Sprawdzić wzorce dla niskiego wykładnika (`e=3`, broadcast)
- Wykorzystać wspólny modulus / powtarzające się liczby pierwsze
- Zastosować metody lattice (Coppersmith/LLL), gdy coś jest prawie znane

## Typowe ataki na RSA

### Wspólny modulus

Jeśli dwa szyfrogramy `c1, c2` szyfrują **tę samą wiadomość** przy użyciu **tego samego modulu** `n`, ale różnych wykładników `e1, e2` (i `gcd(e1,e2)=1`), możesz odzyskać `m` za pomocą rozszerzonego algorytmu Euklidesa:

`m = c1^a * c2^b mod n`, gdzie `a*e1 + b*e2 = 1`.

Przykładowy schemat:

1. Oblicz `(a, b) = xgcd(e1, e2)`, tak aby `a*e1 + b*e2 = 1`
2. Jeśli `a < 0`, zinterpretuj `c1^a` jako `inv(c1)^{-a} mod n` (analogicznie dla `b`)
3. Pomnóż i zredukuj modulo `n`

### Wspólne czynniki pierwsze w różnych modulach

Jeśli masz wiele moduli RSA z tego samego wyzwania, sprawdź, czy mają wspólny czynnik pierwszy:

- `gcd(n1, n2) != 1` oznacza katastrofalny błąd generowania kluczy.

Często pojawia się to w CTF-ach w sytuacjach typu „szybko wygenerowaliśmy wiele kluczy” lub „słaba losowość”.

### Rzadkie / short-sleeve moduli

Niektóre wadliwe generatory dużych liczb całkowitych ujawniają strukturę bezpośrednio w publicznym modulu: każda limb zawiera tylko małe losowe podpole, a pozostałe bity to `0`. W praktyce w `n` widać wtedy **regularnie rozmieszczone bloki zer**, często wyrównane do limb o rozmiarze 32 lub 128 bitów.<sup>[[1]](#references)</sup>

Szybkie sprawdzenia:

- Wyświetl `n` w systemie szesnastkowym i szukaj powtarzających się okien zer o stałym odstępie.
- Podziel ponownie `n` na limb (`2^32`, `2^64`, `2^128`) i sprawdź, czy każda limb jest nietypowo mała.
- Jeśli podejrzewasz słabe generowanie kluczy hosta, sprawdź publiczne klucze SSH/TLS za pomocą narzędzi takich jak **badkeys**.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

To poważniejszy problem niż obciążenie statystyczne: jeśli oba czynniki prywatne `p` i `q` mają strukturę short-sleeve, modulus może być **łatwy do faktoryzacji**.<sup>[[1]](#references)</sup>

### Wielomianowa faktoryzacja ustrukturyzowanych kluczy RSA

Dla podejrzewanej szerokości limb `w` zapisz modulus w systemie o podstawie `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Ponieważ podstawianie zachowuje mnożenie, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Jeśli współczynniki limb czynników również są rzadkie, to:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Schemat ataku:

1. Zgadnij szerokość limb `w`.
2. Zamień publiczny modulus `n` na `f_n(x)`, używając podstawy `2^w`.
3. Rozłóż `f_n(x)` na czynniki nad liczbami całkowitymi.
4. Oblicz wartości potencjalnych czynników dla `B = 2^w`.
5. Sprawdź, które z nich po pomnożeniu dają `n`.

To **nie łamie standardowego RSA**. Działa tylko wtedy, gdy same czynniki pierwsze mają bardzo małe, silnie ustrukturyzowane współczynniki limb.<sup>[[1]](#references)</sup>

### Wyciek przesuniętych limb

Rzadkie bajty nie zawsze są wyrównane do początku każdej limb. Jeśli bezpośrednia konwersja do systemu o podstawie `2^w` daje duże współczynniki, poszukaj przesunięć `i,j`, dla których `2^i p` i `2^j q` stają się rzadkie w tym systemie limb. Wielomian iloczynu nadal można wyprowadzić z publicznego modulu, rozłożyć na czynniki i złożyć ponownie w oryginalne czynniki całkowite.<sup>[[1]](#references)</sup>

### Oznaka błędu implementacji: błąd RNG przy konwersji bajtów na limb

Niebezpieczny wzorzec polega na obliczeniu liczby **32-bitowych limb**, zaalokowaniu tylko tylu **bajtów** i skopiowaniu ich do tablicy limb:

```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```

Każdy 32-bitowy limb ma tylko **8 bitów entropii**, a w ostatnim limbie dodatkowo ustawiony jest wymuszony najwyższy bit. Wynikowe liczby pierwsze RSA można często rozpoznać i rozłożyć na czynniki na podstawie samego klucza publicznego.<sup>[[1]](#references)</sup>

### Powiązany tryb awarii DSA

Jeśli ta sama wadliwa funkcja do obsługi dużych liczb jest używana ponownie do generowania prywatnego wykładnika DSA, klucz publiczny `y = g^x` może ujawnić **znacznie mniejszą i ustrukturyzowaną** przestrzeń poszukiwań dla `x`. Gdy znany jest wzorzec limbów, ataki na logarytm dyskretny, takie jak **baby-step giant-step**, mogą stać się wykonalne dla parametrów publicznych.<sup>[[1]](#references)</sup>

### Atak broadcast Håstada / mały wykładnik

Jeśli ta sama wiadomość jest wysyłana do wielu odbiorców z małym `e` (często `e=3`) i bez odpowiedniego paddingu, możesz odzyskać `m` za pomocą CRT i pierwiastka całkowitoliczbowego.

Warunek techniczny:

Jeśli masz `e` szyfrogramów tej samej wiadomości, zaszyfrowanych przy użyciu parami względnie pierwszych modułów `n_i`:

- Użyj CRT, aby odzyskać `M = m^e` modulo iloczynu `N = Π n_i`
- Jeśli `m^e < N`, wtedy `M` jest prawdziwą potęgą całkowitą, a `m = integer_root(M, e)`

### Atak Wienera: mały wykładnik prywatny

Jeśli `d` jest zbyt małe, ułamki łańcuchowe mogą odzyskać tę wartość z `e/n`.

### Pułapki związane z textbook RSA

Jeśli widzisz:

- Brak OAEP/PSS, surowe potęgowanie modularne
- Szyfrowanie deterministyczne

wtedy ataki algebraiczne i nadużywanie oracle stają się znacznie bardziej prawdopodobne.

### Narzędzia

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, pierwiastki, ułamki łańcuchowe): https://www.sagemath.org/

## Wzorce wiadomości powiązanych

Jeśli widzisz dwa szyfrogramy z tym samym modułem, których wiadomości są powiązane algebraicznie (np. `m2 = a*m1 + b`), poszukaj ataków na wiadomości powiązane, takich jak Franklin–Reiter. Zazwyczaj wymagają one:

- tego samego modułu `n`
- tego samego wykładnika `e`
- znanej zależności między tekstami jawnymi

W praktyce często rozwiązuje się to w Sage, tworząc wielomiany modulo `n` i obliczając NWD.

## Kraty / Coppersmith

Sięgnij po tę metodę, gdy masz częściowe bity, ustrukturyzowany tekst jawny lub bliskie zależności, które sprawiają, że niewiadoma jest mała.

Metody kratowe (LLL/Coppersmith) przydają się zawsze, gdy masz częściowe informacje:

- Częściowo znany tekst jawny (ustrukturyzowana wiadomość z nieznaną końcówką)
- Częściowo znane `p`/`q` (ujawnione wysokie bity)
- Małe, nieznane różnice między powiązanymi wartościami

### Na co zwrócić uwagę

Typowe wskazówki w zadaniach:

- „Ujawniliśmy górne/dolne bity p”
- „Flaga jest osadzona w ten sposób: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`”
- „Użyliśmy RSA z małym losowym paddingiem”

### Narzędzia

W praktyce używa się Sage do LLL oraz znanego szablonu dla danego przypadku.

Dobre punkty wyjścia:

- Szablony kryptograficzne Sage dla CTF: https://github.com/defund/coppersmith
- Przeglądowy materiał źródłowy: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Rozkładanie „short-sleeve” kluczy RSA na czynniki za pomocą wielomianów](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [Samodzielne narzędzie badkeys](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}

