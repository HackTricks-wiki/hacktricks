# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

## Njia ya vitendo

Ikiwa maandishi ya kawaida yanaonyesha tabia isiyotarajiwa, hifadhi ushahidi wa awali, kagua codepoints zake, na ufanye normalization kwenye nakala pekee.

### Technique

Text steganography mara nyingi hutegemea characters zinazowakilishwa kwa mwonekano unaofanana au zisizoonekana:

- Homoglyphs: Unicode codepoints tofauti zinazoonekana kufanana (kwa mfano, Latin `a` na Cyrillic `а`)<sup>[[1]](#references)</sup>
- Zero-width characters: joiners, non-joiners, na zero-width spaces<sup>[[2]](#references)</sup>
- Whitespace encodings: spaces dhidi ya tabs, mifumo ya trailing-space, na mifumo ya makusudi ya urefu wa mistari<sup>[[3]](#references)[[4]](#references)</sup>

Mifano mingine yenye signal kubwa:

- Bidirectional controls, ambazo zinaweza kupanga upya maandishi kwa mwonekano<sup>[[1]](#references)</sup>
- Variation selectors na combining characters, ambazo zinaweza kubeba hali iliyofichwa huku zikiacha maandishi yanayoonekana karibu hayajabadilika<sup>[[1]](#references)</sup>

### Helpers za Decode

- [Unicode homoglyph and zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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
## Vituo vya `unicode-range` vya CSS

Sheria za `@font-face` zinaweza kutumiwa vibaya kusimba baiti katika maingizo ya `unicode-range: U+..`. Toa codepoints, unganisha thamani za heksadesimali, na uzifanye decode:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Ikiwa ranges zina thamani nyingi kwa kila declaration, zigawanye kwa koma kwanza na uzifanye ziwe katika muundo sanifu (`tr ',+' '\n'`). Python inaweza kuchanganua na kutoa bytes wakati formatting hailingani.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Mazingatio ya Usalama ya Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Steganografia ya Unicode kwa Herufi Zisizo na Upana na Homoglyphs](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Orodha ya Matakwa ya Santa](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Mwongozo wa Debian: steganografia ya nafasi nyeupe ya `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
