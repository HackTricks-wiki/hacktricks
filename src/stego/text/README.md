# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Rechercher :

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Approche pratique

Si le plain text se comporte de façon inattendue, inspectez les codepoints et normalisez soigneusement (ne pas détruire les preuves).

### Technique

Text stego dépend fréquemment de caractères qui s'affichent de façon identique (ou invisiblement) :

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Autres cas à fort signal :

- Bidirectional override/control characters (can visually reorder text)
- Variation selectors and combining characters used as a covert channel

### Aides au décodage

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspecter les codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Canaux CSS `unicode-range`

Les règles `@font-face` peuvent encoder des octets dans des entrées `unicode-range: U+..`. Extraire les codepoints, concaténer l'hexadécimal, puis décoder :
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Si les plages contiennent plusieurs octets par déclaration, scindez d'abord sur les virgules et normalisez (`tr ',+' '\n'`). Python facilite l'analyse et l'émission d'octets si le formatage est incohérent.

## Références

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
