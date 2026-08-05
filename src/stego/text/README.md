# Steganography ya Maandishi

{{#include ../../banners/hacktricks-training.md}}

Tafuta:

- Unicode homoglyphs
- Zero-width characters
- Miundo ya whitespace (spaces dhidi ya tabs)

## Njia ya vitendo

Ikiwa plain text inatenda bila kutarajiwa, kagua codepoints na ufanye normalize kwa uangalifu (usiharibu ushahidi).

### Mbinu

Text stego mara nyingi hutegemea characters zinazoonekana sawa (au zisizoonekana):

- Homoglyphs: codepoints tofauti za Unicode zinazoonekana sawa (Latin `a` dhidi ya Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Usimbaji wa whitespace: spaces dhidi ya tabs, trailing spaces, patterns za urefu wa mistari<sup>[[1]](#references)</sup>

Mifano ya ziada yenye signal kubwa:

- Bidirectional override/control characters (zinaweza kupanga upya maandishi kwa mwonekano)
- Variation selectors na combining characters zinazotumika kama covert channel

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Kagua codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Vituo vya CSS `unicode-range`

Sheria za `@font-face` zinaweza kusimba baiti katika maingizo ya `unicode-range: U+..`. Toa codepoint, unganisha thamani za hex, kisha decode:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Ikiwa ranges zina bytes nyingi kwa kila declaration, zigawanye kwanza kwa koma na uzinormalize (`tr ',+' '\n'`). Python hurahisisha kuchanganua na kutoa bytes ikiwa formatting haiendani.

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
