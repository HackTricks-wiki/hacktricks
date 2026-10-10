# Steganografia tekstowa

{{#include ../../banners/hacktricks-training.md}}

## Praktyczna ścieżka

Jeśli zwykły tekst zachowuje się nieoczekiwanie, zachowaj oryginalny materiał dowodowy, sprawdź jego punkty kodowe i normalizuj wyłącznie kopię.

### Technika

Steganografia tekstowa często wykorzystuje znaki, które wyglądają identycznie lub są niewidoczne:

- Homoglify: różne punkty kodowe Unicode, które wyglądają podobnie (na przykład łacińskie `a` i cyrylickie `а`)<sup>[[1]](#references)</sup>
- Znaki o zerowej szerokości: łączniki, niełączniki i spacje o zerowej szerokości<sup>[[2]](#references)</sup>
- Kodowanie za pomocą białych znaków: spacje zamiast tabulatorów, wzorce spacji na końcu wiersza i celowe wzorce długości wierszy<sup>[[3]](#references)[[4]](#references)</sup>

Dodatkowe przypadki o wysokiej wartości sygnału:

- Znaki sterujące kierunkiem tekstu, które mogą wizualnie zmieniać kolejność tekstu<sup>[[1]](#references)</sup>
- Selektory wariantów i znaki łączące, które mogą przenosić ukryty stan, pozostawiając widoczny tekst niemal niezmienionym<sup>[[1]](#references)</sup>

### Narzędzia pomocnicze do dekodowania

- [Koder/dekoder homoglifów Unicode i znaków o zerowej szerokości](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Sprawdzanie punktów kodowych

```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
  if ord(ch) > 127 or ch.isspace():
    print(i, hex(ord(ch)), repr(ch))
PY
```

## Kanały CSS `unicode-range`

Reguły `@font-face` można wykorzystać do zakodowania bajtów we wpisach `unicode-range: U+..`. Wyodrębnij punkty kodowe, połącz wartości szesnastkowe i zdekoduj je:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Jeśli zakresy zawierają wiele wartości w jednej deklaracji, najpierw podziel je po przecinkach i znormalizuj (`tr ',+' '\n'`). Python może sparsować i wyemitować bajty, gdy formatowanie jest niespójne.<sup>[[3]](#references)</sup>

## References

- [1] [Raport techniczny Unicode nr 36: kwestie bezpieczeństwa Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: steganografia Unicode z użyciem znaków o zerowej szerokości i homoglifów](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — lista życzeń Świętego Mikołaja](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Podręcznik Debiana: steganografia z użyciem białych znaków w `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
