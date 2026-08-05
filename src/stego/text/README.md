# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Let op vir:

- Unicode-homogliewe
- Zero-width characters
- Whitespace-patrone (spasies vs tabs)

## Praktiese benadering

As gewone teks onverwags optree, inspekteer die kodepunte en normaliseer versigtig (moenie bewyse vernietig nie).

### Tegniek

Text stego maak dikwels staat op karakters wat identies (of onsigbaar) vertoon:

- Homogliewe: verskillende Unicode-kodepunte wat dieselfde lyk (Latynse `a` vs Cyrilliese `а`)
- Zero-width characters: verbindingskarakters, nie-verbindingskarakters, zero-width spaces
- Whitespace-enkoderings: spasies vs tabs, spasies aan die einde, lynlengtepatrone<sup>[[1]](#references)</sup>

Bykomende gevalle met hoë seinwaarde:

- Tweerigting-override-/beheerkarakters (kan teks visueel herrangskik)
- Variation selectors en combining characters wat as ’n covert channel gebruik word

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspekteer kodepunte
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range`-kanale

`@font-face`-reëls kan grepe in `unicode-range: U+..`-inskrywings enkodeer. Onttrek die kodepunte, voeg die heksadesimale waardes saam, en dekodeer:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
As ranges veelvuldige bytes per verklaring bevat, verdeel dit eers op kommas en normaliseer (`tr ',+' '\n'`). Python maak dit maklik om bytes te ontleed en uit te voer wanneer formatering inkonsekwent is.

## Verwysings

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
