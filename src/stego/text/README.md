# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

खोजें:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## व्यावहारिक पथ

यदि सादा टेक्स्ट असामान्य व्यवहार करे, तो codepoints की जाँच करें और सावधानी से normalize करें (साक्ष्य न नष्ट करें)।

### तकनीक

Text stego अक्सर उन characters पर निर्भर करता है जो समान (या अदृश्य) रूप से प्रदर्शित होते हैं:

- Homoglyphs: अलग-अलग Unicode codepoints जो समान दिखते हैं (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

अतिरिक्त उच्च‑सिग्नल मामले:

- Bidirectional override/control characters (दृश्य रूप से टेक्स्ट का क्रम बदल सकते हैं)
- Variation selectors और combining characters का उपयोग covert channel के रूप में किया जा सकता है

### डिकोड सहायक

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### codepoints की जाँच
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
