# Metin Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Şunları arayın:

- Unicode homoglyph'leri
- Sıfır genişlikli karakterler
- Boşluk kalıpları (space ve tab)

## Pratik yol

Düz metin beklenmedik şekilde davranıyorsa codepoint'leri inceleyin ve dikkatlice normalize edin (kanıtları yok etmeyin).

### Teknik

Text stego sıklıkla aynı şekilde görüntülenen (veya görünmez) karakterlere dayanır:

- Homoglyph'ler: aynı görünen farklı Unicode codepoint'leri (Latin `a` ve Kiril `а`)
- Sıfır genişlikli karakterler: joiner'lar, non-joiner'lar, sıfır genişlikli space'ler
- Whitespace encoding'leri: space ve tab'ler, satır sonundaki space'ler, satır uzunluğu kalıpları<sup>[[1]](#references)</sup>

Ek yüksek sinyalli durumlar:

- Bidirectional override/control karakterleri (metni görsel olarak yeniden sıralayabilir)
- Gizli bir kanal olarak kullanılan variation selector'lar ve combining karakterleri

### Decode yardımcıları

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Codepoint'leri inceleyin
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

`@font-face` kuralları, `unicode-range: U+..` girdilerinde byte'ları encode edebilir. Codepoint'leri çıkarın, hex değerlerini birleştirin ve decode edin:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
If ranges bir declaration içinde birden fazla byte içeriyorsa, önce virgüllere göre ayırın ve normalize edin (`tr ',+' '\n'`). Biçimlendirme tutarsızsa Python, byte'ları ayrıştırmayı ve üretmeyi kolaylaştırır.

## Referanslar

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
