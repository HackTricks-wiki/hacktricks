# Steganografija teksta

{{#include ../../banners/hacktricks-training.md}}

Potražite:

- Unicode homoglyphs
- Zero-width characters
- Obrasce razmaka (spaces naspram tabs)

## Praktični pristup

Ako se običan tekst ponaša neočekivano, proverite codepoints i pažljivo izvršite normalizaciju (nemojte uništiti dokaze).

### Tehnika

Text stego se često oslanja na znakove koji se prikazuju identično (ili nevidljivo):

- Homoglyphs: različiti Unicode codepoints koji izgledaju isto (Latin `a` naspram Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces naspram tabs, završni razmaci, obrasci dužine redova<sup>[[1]](#references)</sup>

Dodatni slučajevi sa visokim signalom:

- Bidirectional override/control characters (mogu vizuelno preurediti tekst)
- Variation selectors i combining characters korišćeni kao covert channel

### Pomoćni alati za dekodiranje

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Provera codepoints
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

`@font-face` pravila mogu da kodiraju bajtove u `unicode-range: U+..` unosima. Izdvojite codepoint vrednosti, spojite heksadecimalne vrednosti i dekodirajte:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Ako opsezi sadrže više bajtova po deklaraciji, prvo ih podelite po zarezima i normalizujte (`tr ',+' '\n'`). Python olakšava parsiranje i emitovanje bajtova kada je formatiranje nedosledno.

## Reference

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
