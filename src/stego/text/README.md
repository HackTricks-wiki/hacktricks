# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Soek na:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Praktiese pad

As plain text onverwags optree, inspekteer codepoints en normaliseer versigtig (moenie bewyse vernietig nie).

### Tegniek

Text stego berus dikwels op karakters wat identies (of onsigbaar) vertoon:

- Homoglyphs: verskillende Unicode codepoints wat dieselfde lyk (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Aanvullende hoë-signaal gevalle:

- Bidirectional override/control characters (kan teks visueel herorden)
- Variation selectors en combining characters wat as 'n covert channel gebruik word

### Ontsleutel-hulp

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspekteer codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range` kanale

`@font-face` reëls kan bytes enkodeer in `unicode-range: U+..` inskrywings. Haal die codepoints uit, koppel die hex saam, en dekodeer:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
As reekse meerdere bytes per deklarasie bevat, skei eers by kommas en normaliseer (`tr ',+' '\n'`). Python maak dit maklik om bytes te ontleed en uit te gee as die formattering inkonsekwent is.

## Verwysings

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
