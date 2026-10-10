# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

## Njia ya vitendo

Ikiwa maandishi ya kawaida yana tabia isiyotarajiwa, hifadhi ushahidi asilia, kagua codepoint zake, na urekebishe nakala pekee.

### Mbinu

Text steganography mara nyingi hutegemea herufi zinazoonekana sawa au zisizoonekana:

- Herufi zinazofanana: codepoint tofauti za Unicode zinazoonekana kufanana (kwa mfano, `a` ya Kilatini na `а` ya Kisiriliki)<sup>[[1]](#references)</sup>
- Herufi za upana sifuri: viunganishi, vitenganishi na nafasi za upana sifuri<sup>[[2]](#references)</sup>
- Usimbaji kwa nafasi nyeupe: nafasi dhidi ya tabo, mifumo ya nafasi mwishoni mwa mistari, na mifumo ya urefu wa mistari iliyokusudiwa<sup>[[3]](#references)[[4]](#references)</sup>

Matukio mengine muhimu sana:

- Vidhibiti vya mwelekeo wa maandishi ya pande mbili, vinavyoweza kubadilisha mpangilio wa maandishi yanavyoonekana<sup>[[1]](#references)</sup>
- Vichaguzi vya tofauti na herufi zinazounganishwa, vinavyoweza kuhifadhi hali iliyofichwa huku maandishi yanayoonekana yakibaki karibu vilevile<sup>[[1]](#references)</sup>

### Zana za kusaidia kufumbua

- [Kisimbaji/kisimbuaji cha Unicode homoglyph na herufi za upana sifuri](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Kagua codepoint za herufi

```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
  if ord(ch) > 127 or ch.isspace():
    print(i, hex(ord(ch)), repr(ch))
PY
```

## Njia za CSS `unicode-range`

Sheria za `@font-face` zinaweza kutumiwa vibaya kusimba baiti katika maingizo ya `unicode-range: U+..`. Toa codepoint, unganisha thamani za heksadesimali, kisha uzidecode:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Ikiwa ranges zina values nyingi kwa kila declaration, gawanya kwanza kwa koma na u-normalize (`tr ',+' '\n'`). Python inaweza kuchanganua na kutoa bytes wakati formatting haifanani.<sup>[[3]](#references)</sup>

## References

- [1] [Ripoti ya Kiufundi ya Unicode #36: Mambo ya Kuzingatia Kuhusu Usalama wa Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Steganography ya Unicode kwa Kutumia Herufi za Zero-Width na Homoglyphs](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Orodha ya Matamanio ya Santa](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Mwongozo wa Debian: Steganography ya whitespace ya `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
