# पाठ स्टेग्नोग्राफी

{{#include ../../banners/hacktricks-training.md}}

## व्यावहारिक मार्ग

अगर plain text अप्रत्याशित तरीके से व्यवहार करे, तो मूल साक्ष्य सुरक्षित रखें, उसके codepoints की जाँच करें और केवल एक कॉपी को normalize करें।

### तकनीक

Text steganography अक्सर ऐसे characters पर निर्भर करती है जो एक जैसी या अदृश्य दिखाई देते हैं:

- Homoglyphs: अलग-अलग Unicode codepoints जो एक जैसे दिखते हैं (उदाहरण के लिए, Latin `a` और Cyrillic `а`)<sup>[[1]](#references)</sup>
- Zero-width characters: joiners, non-joiners और zero-width spaces<sup>[[2]](#references)</sup>
- Whitespace encodings: spaces और tabs का अंतर, trailing-space patterns और जानबूझकर बनाए गए line-length patterns<sup>[[3]](#references)[[4]](#references)</sup>

अतिरिक्त high-signal मामले:

- Bidirectional controls, जो text को देखने में पुनर्व्यवस्थित कर सकते हैं<sup>[[1]](#references)</sup>
- Variation selectors और combining characters, जो दिखाई देने वाले text को लगभग अपरिवर्तित रखते हुए hidden state ले जा सकते हैं<sup>[[1]](#references)</sup>

### Decode helpers

- [Unicode homoglyph और zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Codepoints की जाँच करें

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

`@font-face` rules का इस्तेमाल `unicode-range: U+..` entries में bytes encode करने के लिए किया जा सकता है। Codepoints निकालें, hexadecimal values को जोड़ें और उन्हें decode करें:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

यदि ranges में हर declaration में कई मान हों, तो पहले commas पर split करें और फिर normalize करें (`tr ',+' '\n'`)। Formatting असंगत होने पर Python bytes को parse और emit कर सकता है।<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Unicode सुरक्षा संबंधी विचार](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Zero-Width Characters और Homoglyphs के साथ Unicode Steganography](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Santa की इच्छा-सूची](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian manual: `stegsnow` whitespace steganography](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
