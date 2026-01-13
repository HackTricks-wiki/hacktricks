# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

खोजें:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## व्यावहारिक मार्ग

यदि plain text अनपेक्षित ढंग से व्यवहार करे, तो codepoints की जाँच करें और सावधानी से normalize करें (साक्ष्य न नष्ट करें)।

### तकनीक

Text stego अक्सर उन characters पर निर्भर करता है जो समान रूप से प्रदर्शित होते हैं (या अदृश्य होते हैं):

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

अतिरिक्त उच्च-सिग्नल मामले:

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
## CSS `unicode-range` चैनल

`@font-face` rules bytes को `unicode-range: U+..` entries में encode कर सकते हैं। codepoints निकालें, hex को concatenate करें, और decode करें:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
यदि ranges में प्रति declaration एक से अधिक bytes शामिल हों, तो पहले commas पर split करें और normalize (`tr ',+' '\n'`)। यदि formatting inconsistent है तो Python से bytes को parse और emit करना आसान है।

## References

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
