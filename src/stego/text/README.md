# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

## Practical path

यदि plain text अप्रत्याशित रूप से व्यवहार करे, तो मूल evidence को सुरक्षित रखें, उसके codepoints का निरीक्षण करें, और केवल एक copy को normalize करें।

### Technique

Text steganography अक्सर ऐसे characters पर निर्भर करती है जो एक जैसे या अदृश्य दिखाई देते हैं:

- Homoglyphs: अलग-अलग Unicode codepoints जो एक जैसे दिखते हैं (उदाहरण के लिए, Latin `a` और Cyrillic `а`)<sup>[[1]](#references)</sup>
- Zero-width characters: joiners, non-joiners और zero-width spaces<sup>[[2]](#references)</sup>
- Whitespace encodings: spaces बनाम tabs, trailing-space patterns और जानबूझकर बनाए गए line-length patterns<sup>[[3]](#references)[[4]](#references)</sup>

अतिरिक्त high-signal cases:

- Bidirectional controls, जो text को दृश्य रूप से पुनः क्रमित कर सकते हैं<sup>[[1]](#references)</sup>
- Variation selectors और combining characters, जो visible text को लगभग अपरिवर्तित रखते हुए hidden state वहन कर सकते हैं<sup>[[1]](#references)</sup>

### Decode helpers

- [Unicode homoglyph and zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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

`@font-face` rules का उपयोग `unicode-range: U+..` entries में bytes encode करने के लिए किया जा सकता है। codepoints निकालें, hexadecimal values को concatenate करें, और उन्हें decode करें:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
यदि declarations में ranges के अंदर कई values हों, तो पहले commas पर split करें और normalize करें (`tr ',+' '\n'`)। Formatting असंगत होने पर Python bytes को parse और emit कर सकता है।<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Unicode Security Considerations](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Zero-Width Characters और Homoglyphs के साथ Unicode Steganography](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Santa's Wishlist](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian manual: `stegsnow` whitespace steganography](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
