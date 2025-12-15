# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Cerca:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Percorso pratico

Se il plain text si comporta in modo inatteso, ispeziona i codepoints e normalizza con attenzione (non distruggere le prove).

### Tecnica

Text stego spesso si basa su caratteri che vengono visualizzati in modo identico (o invisibili):

- Homoglyphs: diversi codepoint Unicode che appaiono uguali (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Ulteriori casi ad alto segnale:

- Bidirectional override/control characters (possono riordinare visivamente il testo)
- Variation selectors and combining characters (usati come canale nascosto)

### Strumenti di decodifica

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Ispeziona i codepoints
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
