# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Tafuta:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Njia ya vitendo

Iwapo plain text itatenda kinyume na matarajio, kagua codepoints na normalize kwa uangalifu (usiharibu ushahidi).

### Mbinu

Text stego mara nyingi inategemea herufi zinazochapwa kwa njia ile ile (au zisizoonekana):

- Homoglyphs: Unicode codepoints tofauti ambazo zinaonekana sawa (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Mifano ya ziada yenye ishara kubwa:

- Bidirectional override/control characters (zinaweza kupangia upya maandishi kimaoni)
- Variation selectors and combining characters zinazotumika kama chaneli ya siri

### Vifaa vya decode

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
{{#include ../../banners/hacktricks-training.md}}
