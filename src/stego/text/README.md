# Steganografia tekstu

{{#include ../../banners/hacktricks-training.md}}

Szukaj:

- Unicode homoglyphs
- Zero-width characters
- Wzorce białych znaków (spacje vs tabulatory)

## Praktyczna ścieżka

Jeśli zwykły tekst zachowuje się nieoczekiwanie, sprawdź codepoints i ostrożnie wykonaj normalizację (nie niszcz dowodów).

### Technika

Text stego często opiera się na znakach, które wyglądają identycznie (lub są niewidoczne):

- Homoglyphs: różne codepoints Unicode, które wyglądają tak samo (łacińskie `a` vs cyrylickie `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Kodowanie białymi znakami: spacje vs tabulatory, spacje na końcu wierszy, wzorce długości wierszy<sup>[[1]](#references)</sup>

Dodatkowe przypadki o wysokiej wartości sygnału:

- Znaki sterujące/nadpisujące kierunkiem dwukierunkowym (mogą wizualnie zmieniać kolejność tekstu)
- Variation selectors i combining characters używane jako covert channel

### Pomocniki dekodowania

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Sprawdzanie codepoints
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

Reguły `@font-face` mogą kodować bajty we wpisach `unicode-range: U+..`. Wyodrębnij punkty kodowe, połącz wartości szesnastkowe i zdekoduj:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Jeśli zakresy zawierają wiele bajtów w jednej deklaracji, najpierw podziel je po przecinkach i znormalizuj (`tr ',+' '\n'`). Python ułatwia analizowanie i generowanie bajtów, gdy formatowanie jest niespójne.<sup>[[1]](#references)</sup>

## Referencje

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
