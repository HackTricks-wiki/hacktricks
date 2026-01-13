# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Kontrol edilecekler:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Pratik yol

Düz metin beklenmedik şekilde davranıyorsa, codepoints'i inceleyin ve dikkatlice normalize edin (kanıtları yok etmeyin).

### Teknik

Text stego genellikle aynı (veya görünmez) şekilde görüntülenen karakterlere dayanır:

- Homoglyphs: aynı görünen farklı Unicode codepoints (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Ek olarak dikkat edilmesi gereken durumlar:

- Bidirectional override/control characters (metni görsel olarak yeniden sıralayabilir)
- Variation selectors ve combining characters gizli kanal olarak kullanılabilir

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
## CSS `unicode-range` kanalları

`@font-face` kuralları `unicode-range: U+..` girdilerinde baytları kodlayabilir. Kod noktalarını çıkarın, hex'leri birleştirin ve çözün:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Eğer aralıklar her deklarasyonda birden fazla bytes içeriyorsa, önce virgüllere göre bölün ve normalize edin (`tr ',+' '\n'`). Biçimlendirme tutarsızsa, bytes'ları ayrıştırmak ve üretmek için Python kullanmak kolaydır.

## Referanslar

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
