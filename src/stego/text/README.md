# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Szukaj:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Praktyczna ścieżka

Jeśli plain text zachowuje się nieoczekiwanie, sprawdź codepoints i normalizuj ostrożnie (nie niszcz dowodów).

### Technika

Text stego często polega na znakach, które renderują się identycznie (lub są niewidoczne):

- Homoglyphs: różne Unicode codepoints, które wyglądają tak samo (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Dodatkowe przypadki o wysokim sygnale:

- Bidirectional override/control characters (mogą wizualnie przestawiać tekst)
- Variation selectors and combining characters używane jako kanał ukryty

### Narzędzia do dekodowania

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Sprawdź codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
{{#include ../../banners/hacktricks-training.md}}
