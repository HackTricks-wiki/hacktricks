# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Soek na:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Praktiese pad

As plain text onverwags optree, inspekteer codepoints en normaliseer versigtig (moet nie bewyse vernietig nie).

### Tegniek

Text stego maak dikwels staat op karakters wat identies (of onsigbaar) vertoon:

- Homoglyphs: verskillende Unicode codepoints wat dieselfde lyk (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Bykomende hoë-sein gevalle:

- Bidirectional override/control characters (kan teks visueel herordeneer)
- Variation selectors en combining characters wat as 'n geheime kanaal gebruik word

### Dekodeerhelpers

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
{{#include ../../banners/hacktricks-training.md}}
