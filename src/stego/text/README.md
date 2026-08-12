# Tekstualna steganografija

{{#include ../../banners/hacktricks-training.md}}

## Praktični put

Ako se običan tekst ponaša neočekivano, sačuvajte originalne dokaze, proverite njegove codepoints i normalizujte samo kopiju.

### Tehnika

Tekstualna steganografija se često oslanja na znakove koji se prikazuju identično ili nevidljivo:

- Homoglifi: različiti Unicode codepoints-i koji izgledaju slično (na primer, latinično `a` i ćirilično `а`)<sup>[[1]](#references)</sup>
- Zero-width characters: joiners, non-joiners i zero-width spaces<sup>[[2]](#references)</sup>
- Kodiranja razmacima: razmaci naspram tabulatora, obrasci završnih razmaka i namerni obrasci dužine redova<sup>[[3]](#references)[[4]](#references)</sup>

Dodatni slučajevi sa visokim signalom:

- Bidirectional controls, koji mogu vizuelno promeniti redosled teksta<sup>[[1]](#references)</sup>
- Variation selectors i combining characters, koji mogu nositi skriveno stanje, a da vidljivi tekst ostane gotovo nepromenjen<sup>[[1]](#references)</sup>

### Pomoćni alati za dekodiranje

- [Unicode homoglyph and zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Provera codepoints-a
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range` kanali

`@font-face` pravila mogu biti zloupotrebljena za kodiranje bajtova u `unicode-range: U+..` stavkama. Izdvojite codepoint vrednosti, spojite heksadecimalne vrednosti i dekodirajte ih:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Ako deklaracije sadrže više vrednosti po opsegu, prvo ih razdvojite zarezima i normalizujte (`tr ',+' '\n'`). Python može da parsira i generiše bajtove kada je formatiranje nedosledno.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Razmatranja o bezbednosti Unicode-a](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Unicode steganografija pomoću znakova nulte širine i homoglifâ](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Deda Mrazova lista želja](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian priručnik: stegsnow steganografija razmacima](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
