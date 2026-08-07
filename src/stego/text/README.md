# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Soek na:

- Unicode-homogliewe
- Zero-width characters
- Whitespace-patrone (spasies teenoor tabs)

## Praktiese pad

As plain text onverwags optree, inspekteer codepoints en normaliseer versigtig (moenie bewyse vernietig nie).

### Tegniek

Text stego maak dikwels staat op karakters wat identies (of onsigbaar) vertoon:

- Homogliewe: verskillende Unicode-codepoints wat dieselfde lyk (Latynse `a` teenoor Cyrilliese `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace-enkoderings: spasies teenoor tabs, spasies aan die einde, patrone in reëllengtes<sup>[[1]](#references)</sup>

Bykomende hoë-sein-gevalle:

- Bidirectional override/control characters (kan teks visueel herrangskik)
- Variation selectors en combining characters wat as 'n covert channel gebruik word

### Dekoderingshulpmiddels

- Unicode-homoglyph/zero-width-speelplek: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

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
## CSS `unicode-range` channels

`@font-face`-reëls kan grepe in `unicode-range: U+..`-inskrywings enkodeer. Onttrek die codepoints, voeg die heksadesimale waardes saam en dekodeer:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Indien reekse veelvuldige grepe per deklarasie bevat, verdeel dit eers op kommas en normaliseer (`tr ',+' '\n'`). Python maak dit maklik om grepe te ontleed en uit te voer wanneer formatering inkonsekwent is.<sup>[[1]](#references)</sup>

## Verwysings

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
