# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

इन चीज़ों को देखें:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Practical path

यदि plain text अप्रत्याशित रूप से व्यवहार करता है, तो codepoints का निरीक्षण करें और सावधानी से normalize करें (evidence को नष्ट न करें)।

### Technique

Text stego अक्सर ऐसे characters पर निर्भर करता है जो एक जैसे (या अदृश्य) दिखाई देते हैं:

- Homoglyphs: अलग-अलग Unicode codepoints जो एक जैसे दिखाई देते हैं (Latin `a` और Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces और tabs, trailing spaces, line-length patterns<sup>[[1]](#references)</sup>

अतिरिक्त high-signal cases:

- Bidirectional override/control characters (जो text को दृश्य रूप से पुनर्व्यवस्थित कर सकते हैं)
- Variation selectors और combining characters का covert channel के रूप में उपयोग

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
## CSS `unicode-range` चैनल

`@font-face` rules `unicode-range: U+..` प्रविष्टियों में bytes encode कर सकते हैं। codepoints निकालें, hex को concatenate करें और decode करें:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
यदि ranges में प्रत्येक declaration में multiple bytes हों, तो पहले commas पर split करें और normalize करें (`tr ',+' '\n'`)। Formatting inconsistent होने पर Python bytes को parse और emit करना आसान बनाता है।<sup>[[1]](#references)</sup>

## संदर्भ

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
