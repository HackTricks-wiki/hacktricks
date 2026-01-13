# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Potražite:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Praktičan put

Ako se plain text ponaša neočekivano, pregledajte codepoints i pažljivo normalizujte (ne uništavajte dokaze).

### Tehnika

Text stego često se oslanja na karaktere koji se prikazuju identično (ili nevidljivo):

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Dodatni značajni slučajevi:

- Bidirectional override/control characters (mogu vizuelno promeniti redosled teksta)
- Variation selectors and combining characters used as a covert channel

### Alati za dekodiranje

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Pregled codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range` kanali

`@font-face` pravila mogu kodirati bajtove u `unicode-range: U+..` unosima. Izvucite codepoints, spojite hex i dekodirajte:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Ako opsezi sadrže više bajtova po deklaraciji, prvo razdvojite zarezima i normalizujte (`tr ',+' '\n'`). Python olakšava parsiranje i emitovanje bajtova ako je formatiranje nekonzistentno.

## Reference

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
