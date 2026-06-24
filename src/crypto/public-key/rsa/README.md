# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Szybka triage

Zbierz:

- `n`, `e`, `c` (i wszelkie dodatkowe ciphertexts)
- Wszelkie relacje między wiadomościami (to samo plaintext? wspólny modulus? ustrukturyzowany plaintext?)
- Wszelkie leaks (częściowe `p/q`, bity `d`, `dp/dq`, znane padding)

Następnie spróbuj:

- Sprawdzenia faktoryzacji (Factordb / `sage: factor(n)` dla małych wartości)
- Wzorców dla niskiego exponent (`e=3`, broadcast)
- Common modulus / repeated primes
- Metod lattice (Coppersmith/LLL), gdy coś jest prawie znane

## Common RSA attacks

### Common modulus

Jeśli dwa ciphertexts `c1, c2` szyfrują **ten sam message** przy **tym samym modulus** `n`, ale z różnymi exponentami `e1, e2` (i `gcd(e1,e2)=1`), możesz odzyskać `m` używając rozszerzonego algorytmu Euklidesa:

`m = c1^a * c2^b mod n`, gdzie `a*e1 + b*e2 = 1`.

Przykładowy zarys:

1. Oblicz `(a, b) = xgcd(e1, e2)`, więc `a*e1 + b*e2 = 1`
2. Jeśli `a < 0`, interpretuj `c1^a` jako `inv(c1)^{-a} mod n` (tak samo dla `b`)
3. Pomnóż i zredukuj modulo `n`

### Shared primes across moduli

Jeśli masz wiele RSA modulusów z tego samego challenge, sprawdź, czy współdzielą prime:

- `gcd(n1, n2) != 1` oznacza katastrofalny błąd generowania kluczy.

To często pojawia się w CTF-ach jako „wygenerowaliśmy dużo kluczy szybko” albo „bad randomness”.

### Sparse / short-sleeve moduli

Niektóre wadliwe generatory big-integer ujawniają strukturę bezpośrednio w publicznym modulus: każdy limb zawiera tylko mały losowy podzbiór bitów, a reszta bitów to `0`. W praktyce wygląda to jak **regularnie rozmieszczone bloki zer** w `n`, często wyrównane do limbów 32-bitowych lub 128-bitowych.

Szybkie sprawdzenia:

- Zrzut `n` w hex i szukanie powtarzających się okienek zer w stałym odstępie.
- Ponowny podział `n` na limby (`2^32`, `2^64`, `2^128`) i sprawdzenie, czy każdy limb jest nietypowo mały.
- Audyt publicznych kluczy SSH/TLS za pomocą narzędzi takich jak **badkeys**, gdy podejrzewasz słabe generowanie host-key.

To jest poważniejsze niż bias statystyczny: jeśli oba prywatne czynniki `p` i `q` są short-sleeved, modulus może stać się **łatwy do faktoryzacji**.

### Polynomial factorization of structured RSA keys

Dla podejrzewanej szerokości limb `w`, zapisz modulus w bazie `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Ponieważ ewaluacja jest multiplikatywna, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Jeśli czynniki również mają sparse współczynniki limbów, to:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Zarys ataku:

1. Zgadnij szerokość limb `w`.
2. Przekształć publiczny modulus `n` do `f_n(x)` używając bazy `2^w`.
3. Zsfaktoryzuj `f_n(x)` nad liczbami całkowitymi.
4. Oblicz wartości kandydackich czynników z powrotem przy `B = 2^w`.
5. Zweryfikuj, które kandydaty mnożą się do `n`.

To **nie łamie normalnego RSA**. Działa tylko wtedy, gdy same prime factors mają bardzo małe, silnie ustrukturyzowane współczynniki limbów.

### Shifted limb leakage

Sparse bajty nie zawsze są wyrównane na dolnym końcu każdego limb. Jeśli bezpośrednia konwersja do bazy `2^w` daje duże współczynniki, szukaj przesunięć `i,j`, takich że `2^i p` i `2^j q` staną się sparse w tej bazie limbów. Wielomian iloczynu nadal można wyprowadzić z publicznego modulus, zsfaktoryzować i zrekombinować do oryginalnych czynników całkowitych.

### Implementation smell: byte-to-limb RNG bug

Niebezpieczny wzorzec to obliczenie liczby **32-bit limbów**, zaalokowanie tylko tylu **bajtów** i skopiowanie ich do tablicy limbów:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
To daje każdemu 32-bitowemu limbowi tylko **8 bitów entropii** plus wymuszony najwyższy bit w ostatnim limbie. Powstałe liczby pierwsze RSA można często rozpoznać i sfaktoryzować wyłącznie na podstawie publicznego klucza.

### Powiązany tryb awarii DSA

Jeśli ta sama uszkodzona procedura big-integer zostanie ponownie użyta do generowania prywatnego wykładnika DSA, publiczny klucz `y = g^x` może ujawniać **drastycznie zredukowaną i strukturalną** przestrzeń przeszukiwania dla `x`. Gdy wzorzec limbów jest znany, ataki na dyskretny logarytm, takie jak **baby-step giant-step**, mogą stać się praktyczne przeciwko parametrom publicznym.

### Håstad broadcast / low exponent

Jeśli ten sam plaintext jest wysyłany do wielu odbiorców z małym `e` (często `e=3`) i bez poprawnego paddingu, możesz odzyskać `m` przez CRT i integer root.

Warunek techniczny:

Jeśli masz `e` ciphertextów tej samej wiadomości pod parami względnie pierwszymi modułami `n_i`:

- Użyj CRT, aby odzyskać `M = m^e` nad iloczynem `N = Π n_i`
- Jeśli `m^e < N`, to `M` jest prawdziwą potęgą całkowitą, a `m = integer_root(M, e)`

### Atak Wienera: mały prywatny wykładnik

Jeśli `d` jest zbyt małe, ułamki łańcuchowe mogą odzyskać je z `e/n`.

### Pułapki Textbook RSA

Jeśli widzisz:

- Brak OAEP/PSS, surowe potęgowanie modularne
- Deterministic encryption

to ataki algebraiczne i nadużycie oracle stają się znacznie bardziej prawdopodobne.

### Narzędzia

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Wzorce powiązanych wiadomości

Jeśli widzisz dwa ciphertexty pod tym samym modułem, a wiadomości są algebraicznie powiązane (np. `m2 = a*m1 + b`), szukaj ataków typu "related-message", takich jak Franklin–Reiter. Zwykle wymagają one:

- tego samego modułu `n`
- tego samego wykładnika `e`
- znanej zależności między plaintextami

W praktyce często rozwiązuje się to w Sage, ustawiając wielomiany modulo `n` i obliczając GCD.

## Lattice / Coppersmith

Użyj tego, gdy masz częściowe bity, strukturalny plaintext lub bliskie zależności, które czynią nieznane małym.

Metody lattice (LLL/Coppersmith) pojawiają się zawsze, gdy masz częściową informację:

- Częściowo znany plaintext (ustrukturyzowana wiadomość z nieznanym ogonem)
- Częściowo znane `p`/`q` (ujawnione wysokie bity)
- Małe nieznane różnice między powiązanymi wartościami

### Co rozpoznać

Typowe wskazówki w zadaniach:

- "Ujawniliśmy górne/dolne bity p"
- "Flaga jest osadzona tak: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "Użyliśmy RSA, ale z małym losowym paddingiem"

### Narzędzia

W praktyce użyjesz Sage do LLL oraz znanego szablonu dla konkretnego przypadku.

Dobre punkty startowe:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- Reference w stylu przeglądowym: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
