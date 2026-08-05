# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

इन चीज़ों को देखें:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces बनाम tabs)

## Practical path

यदि plain text अप्रत्याशित तरीके से व्यवहार करे, तो codepoints का निरीक्षण करें और सावधानी से normalize करें (evidence नष्ट न करें)।

### Technique

Text stego अक्सर ऐसे characters पर निर्भर करता है जो एक जैसे (या अदृश्य) दिखाई देते हैं:

- Homoglyphs: अलग-अलग Unicode codepoints जो एक जैसे दिखते हैं (Latin `a` बनाम Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces बनाम tabs, trailing spaces, line-length patterns<sup>[[1]](#references)</sup>

अतिरिक्त high-signal cases:

- Bidirectional override/control characters (जो text को दृश्य रूप से पुनःक्रमित कर सकते हैं)
- Variation selectors और combining characters, जिनका उपयोग covert channel के रूप में किया जाता है

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

`@font-face` rules `unicode-range: U+..` entries में bytes encode कर सकते हैं। Codepoints extract करें, hex को concatenate करें और decode करें:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
यदि ranges में प्रति declaration कई bytes हों, तो पहले commas पर split करें और normalize करें (`tr ',+' '\n'`)। Formatting असंगत होने पर Python bytes को parse और emit करना आसान बनाता है।

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
