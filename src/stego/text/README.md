# Tekssteganografie

{{#include ../../banners/hacktricks-training.md}}

## Praktiese pad

As gewone teks onverwags optree, bewaar die oorspronklike bewys, inspekteer die codepoints daarvan, en normaliseer slegs 'n kopie.

### Tegniek

Tekssteganografie maak dikwels staat op karakters wat identies of onsigbaar vertoon:

- Homoglyphs: verskillende Unicode-codepoints wat eenders lyk (byvoorbeeld Latynse `a` en Cyrilliese `а`)<sup>[[1]](#references)</sup>
- Zero-width characters: joiners, non-joiners en zero-width spaces<sup>[[2]](#references)</sup>
- Whitespace encodings: spasies teenoor tabs, patrone van spasies aan die einde, en doelbewuste lynlengtepatrone<sup>[[3]](#references)[[4]](#references)</sup>

Bykomende hoë-sein-gevalle:

- Bidirectional controls, wat teks visueel kan herrangskik<sup>[[1]](#references)</sup>
- Variation selectors en combining characters, wat verborge toestand kan dra terwyl die sigbare teks byna onveranderd bly<sup>[[1]](#references)</sup>

### Decode helpers

- [Unicode homoglyph and zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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
## CSS `unicode-range`-kanale

`@font-face`-reëls kan misbruik word om grepe in `unicode-range: U+..`-inskrywings te enkodeer. Onttrek die codepoints, voeg die heksadesimale waardes saam en dekodeer hulle:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
As reekse veelvuldige waardes per deklarasie bevat, verdeel dit eers op kommas en normaliseer dit (`tr ',+' '\n'`). Python kan die grepe ontleed en uitvoer wanneer die formatering inkonsekwent is.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Unicode-sekuriteitsoorwegings](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Unicode-steganografie met nulwydtekarakters en homogliewe](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Kersvader se wenslys](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian-handleiding: `stegsnow`-witruimte-steganografie](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
