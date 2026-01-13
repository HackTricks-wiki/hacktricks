# Steganografia tekstu

{{#include ../../banners/hacktricks-training.md}}

Szukaj:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Praktyczna ścieżka

Jeśli zwykły tekst zachowuje się nieoczekiwanie, zbadaj punkty kodowe i normalizuj ostrożnie (nie niszcz dowodów).

### Technika

Steganografia tekstu często opiera się na znakach, które wyświetlają się identycznie (lub są niewidoczne):

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Dodatkowe przypadki o wysokim sygnale:

- Bidirectional override/control characters (can visually reorder text)
- Variation selectors and combining characters used as a covert channel

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Sprawdź punkty kodowe
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

Reguły `@font-face` mogą kodować bajty w wpisach `unicode-range: U+..`. Wyodrębnij punkty kodowe, połącz szesnastkowe wartości i zdekoduj:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Jeżeli zakresy zawierają wiele bytes w jednej deklaracji, najpierw rozdziel je przecinkami i znormalizuj (`tr ',+' '\n'`). Python ułatwia parsowanie i emitowanie bytes, jeśli formatowanie jest niespójne.

## Źródła

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
