# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Potražite:

- Unicode homoglyphs
- Zero-width characters
- Obrasce whitespace-a (razmaci naspram tabulatora)

## Practical path

Ako se plain text ponaša neočekivano, pregledajte codepoints i pažljivo izvršite normalizaciju (nemojte uništiti dokaze).

### Technique

Text stego se često oslanja na karaktere koji se prikazuju identično (ili nevidljivo):

- Homoglyphs: različiti Unicode codepoints koji izgledaju isto (Latin `a` naspram ćiriličnog `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: razmaci naspram tabulatora, razmaci na kraju reda, obrasci dužine redova<sup>[[1]](#references)</sup>

Dodatni slučajevi sa visokim signalom:

- Bidirectional override/control characters (mogu vizuelno preurediti tekst)
- Variation selectors i combining characters koji se koriste kao covert channel

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspect codepoints
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

Pravila `@font-face` mogu da kodiraju bajtove u stavkama `unicode-range: U+..`. Izdvojite kodne tačke, spojite heksadecimalne vrednosti i dekodirajte:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Ako opsezi sadrže više bajtova po deklaraciji, prvo ih razdvojite zarezima i normalizujte (`tr ',+' '\n'`). Python olakšava parsiranje i emitovanje bajtova kada je formatiranje nedosledno.<sup>[[1]](#references)</sup>

## Reference

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
