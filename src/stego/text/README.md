# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Шукайте:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Практичний шлях

If plain text behaves unexpectedly, inspect codepoints and normalize carefully (do not destroy evidence).

### Техніка

Text stego frequently relies on characters that render identically (or invisibly):

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Додаткові випадки з високим сигналом:

- Bidirectional override/control characters (can visually reorder text)
- Variation selectors and combining characters used as a covert channel

### Інструменти декодування

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Перевірка codepoints
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
