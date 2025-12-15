# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Look for:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Practical path

If plain text behaves unexpectedly, inspect codepoints and normalize carefully (do not destroy evidence).

### Technique

Text stego frequently relies on characters that render identically (or invisibly):

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Additional high-signal cases:

- Bidirectional override/control characters (can visually reorder text)
- Variation selectors and combining characters used as a covert channel

### Decode helpers

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

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

{{#include ../../banners/hacktricks-training.md}}
