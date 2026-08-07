# Metin Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Şunları arayın:

- Unicode homoglyph'leri
- Zero-width karakterler
- Whitespace pattern'leri (space ve tab)

## Pratik yol

Plain text beklenmedik şekilde davranıyorsa codepoint'leri inceleyin ve dikkatlice normalize edin (kanıtları yok etmeyin).

### Technique

Text stego sıklıkla aynı şekilde görüntülenen (veya görünmez olan) karakterlere dayanır:

- Homoglyph'ler: aynı görünen farklı Unicode codepoint'leri (Latin `a` ve Cyrillic `а`)
- Zero-width karakterler: joiner'lar, non-joiner'lar, zero-width space'ler
- Whitespace encoding'leri: space ve tab'ler, satır sonundaki space'ler, satır uzunluğu pattern'leri<sup>[[1]](#references)</sup>

Yüksek sinyalli ek durumlar:

- Bidirectional override/control karakterleri (metni görsel olarak yeniden sıralayabilir)
- Covert channel olarak kullanılan variation selector'lar ve combining karakterler

### Decode yardımcıları

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Codepoint'leri inceleme
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## CSS `unicode-range` channels

`@font-face` kuralları, `unicode-range: U+..` girdilerinde baytları kodlayabilir. Kod noktalarını çıkarın, hex değerlerini birleştirin ve kodunu çözün:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Aralıklar her tanımda birden fazla byte içeriyorsa önce virgüllere göre bölün ve normalize edin (`tr ',+' '\n'`). Python, biçimlendirme tutarsız olduğunda byte'ları ayrıştırıp üretmeyi kolaylaştırır.<sup>[[1]](#references)</sup>

## Referanslar

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
