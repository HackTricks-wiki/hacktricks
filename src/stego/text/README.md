# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Achte auf:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Praktischer Ablauf

Wenn Plaintext sich unerwartet verhält, untersuche die Codepunkte und normalisiere sorgfältig (vernichte keine Beweise).

### Technik

Text stego nutzt häufig Zeichen, die identisch (oder unsichtbar) dargestellt werden:

- Homoglyphs: verschiedene Unicode-Codepunkte, die gleich aussehen (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Weitere aussagekräftige Fälle:

- Bidirectional override/control characters (kann Text visuell neu anordnen)
- Variation selectors and combining characters used as a covert channel

### Hilfsmittel zum Dekodieren

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Codepunkte untersuchen
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
