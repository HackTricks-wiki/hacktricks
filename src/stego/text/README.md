# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Ara:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Pratik yol

Düz metin beklenmedik davranış gösteriyorsa, kod noktalarını inceleyin ve dikkatle normalleştirin (delilleri yok etmeyin).

### Teknik

Text stego genellikle aynı şekilde (veya görünmez olarak) görüntülenen karakterlere dayanır:

- Homoglyphs: aynı görünen farklı Unicode kod noktaları (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Ek olarak yüksek sinyalli durumlar:

- Bidirectional override/control characters (metni görsel olarak yeniden sıralayabilir)
- Variation selectors and combining characters used as a covert channel (gizli kanal olarak kullanılabilir)

### Çözüm yardımcıları

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Kod noktalarını inceleyin
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
