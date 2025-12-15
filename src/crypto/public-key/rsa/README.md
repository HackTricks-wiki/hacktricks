# Ataki RSA

{{#include ../../../banners/hacktricks-training.md}}

## Szybkie rozpoznanie

Zbierz:

- `n`, `e`, `c` (and any additional ciphertexts)
- Wszelkie relacje między wiadomościami (same plaintext? shared modulus? structured plaintext?)
- Any leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Następnie spróbuj:

- Sprawdzenie faktoryzacji (Factordb / `sage: factor(n)` dla stosunkowo małych)
- Wzorce małego wykładnika (`e=3`, broadcast)
- Wspólny modulus / powtarzające się czynniki pierwsze
- Metody lattice (Coppersmith/LLL) gdy coś jest prawie znane

## Typowe ataki na RSA

### Common modulus

Jeżeli dwa ciphertexty `c1, c2` szyfrują **tę samą wiadomość** pod **tym samym modulus** `n`, ale przy różnych wykładnikach `e1, e2` (i `gcd(e1,e2)=1`), możesz odzyskać `m` używając rozszerzonego algorytmu Euklidesa:

`m = c1^a * c2^b mod n` gdzie `a*e1 + b*e2 = 1`.

Zarys przykładu:

1. Oblicz `(a, b) = xgcd(e1, e2)` tak, aby `a*e1 + b*e2 = 1`
2. Jeśli `a < 0`, traktuj `c1^a` jako `inv(c1)^{-a} mod n` (analogicznie dla `b`)
3. Pomnóż i zredukuj modulo `n`

### Shared primes across moduli

Jeśli masz wiele modułów RSA z tego samego zadania, sprawdź czy dzielą prime:

- `gcd(n1, n2) != 1` oznacza katastrofalny błąd w generowaniu kluczy.

Często występuje w CTFs jako "we generated many keys quickly" lub "bad randomness".

### Håstad broadcast / low exponent

Jeżeli ta sama plaintext jest wysłana do wielu odbiorców z małym `e` (często `e=3`) i bez poprawnego paddingu, możesz odzyskać `m` używając CRT i pierwiastka całkowitego.

Warunek techniczny:

Jeżeli masz `e` ciphertextów tej samej wiadomości pod parami względnie pierwszymi modułami `n_i`:

- Użyj CRT aby odzyskać `M = m^e` modulo iloczynu `N = Π n_i`
- Jeśli `m^e < N`, to `M` jest prawdziwą potęgą całkowitą, i `m = integer_root(M, e)`

### Wiener attack: small private exponent

Jeśli `d` jest za małe, continued fractions mogą je odzyskać z `e/n`.

### Pułapki Textbook RSA

Jeśli widzisz:

- Brak OAEP/PSS, raw modular exponentiation
- Deterministyczne szyfrowanie

to ataki algebraiczne i nadużycia oracle stają się znacznie bardziej prawdopodobne.

### Narzędzia

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Wzorce powiązanych wiadomości

Jeśli widzisz dwa ciphertexty pod tym samym modulus z wiadomościami, które są algebraicznie powiązane (np. `m2 = a*m1 + b`), szukaj ataków "related-message" takich jak Franklin–Reiter. Zwykle wymagają:

- tego samego modulus `n`
- tego samego wykładnika `e`
- znanej relacji między plaintextami

W praktyce często rozwiązuje się to w Sage ustawiając wielomiany modulo `n` i obliczając GCD.

## Lattices / Coppersmith

Sięgnij po to, gdy masz częściowe bity, strukturalny plaintext lub bliskie relacje, które czynią nieznane małymi.

Metody lattice (LLL/Coppersmith) pojawiają się zawsze, gdy masz częściowe informacje:

- Częściowo znany plaintext (strukturalna wiadomość z nieznanym końcem)
- Częściowo znane `p`/`q` (wycieknięte wysokie bity)
- Małe nieznane różnice między powiązanymi wartościami

### Na co zwrócić uwagę

Typowe wskazówki w zadaniach:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Narzędzia

W praktyce użyjesz Sage do LLL i znanego szablonu dla konkretnego przypadku.

Przydatne źródła:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
