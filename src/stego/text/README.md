# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Tafuta:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Njia ya vitendo

Ikiwa plain text inafanya kazi isivyotarajiwa, chunguza codepoints na normalize kwa uangalifu (usiharibu ushahidi).

### Mbinu

Text stego mara nyingi hutegemea herufi ambazo zinaonyeshwa sawa (au kwa njia isiyoonekana):

- Homoglyphs: codepoints tofauti za Unicode zinazofanana kwa sura (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Mifano ya ziada zenye ishara kubwa:

- Bidirectional override/control characters (zinaweza kupanga tena maandishi kwa muonekano)
- Variation selectors na combining characters zinazotumika kama chaneli ya siri

### Vifaa vya decode

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Chunguza codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Chaneli za CSS `unicode-range`

`@font-face` rules zinaweza kuunda bytes ndani ya entries za `unicode-range: U+..`. Toa codepoints, ungana hex, kisha decode:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Ikiwa masafa yanajumuisha bytes nyingi kwa kila tamko, gawanya kwa koma kwanza na weka kwenye muundo wa kawaida (`tr ',+' '\n'`). Python inafanya iwe rahisi kuchanganua na kutoa bytes ikiwa muundo hauko thabiti.

## Marejeleo

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
