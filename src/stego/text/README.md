# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Potražite:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Praktičan pristup

Ako se običan tekst ponaša neočekivano, proverite kodne tačke i normalizujte pažljivo (nemojte uništiti dokaze).

### Tehnika

Text stego često se oslanja na karaktere koji se prikazuju identično (ili nevidljivo):

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Dodatni visokosignalni slučajevi:

- Bidirectional override/control characters (can visually reorder text)
- Variation selectors and combining characters used as a covert channel

### Alati za dekodiranje

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Pregled kodnih tačaka
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
