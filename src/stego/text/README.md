# Metin Steganografisi

{{#include ../../banners/hacktricks-training.md}}

## Pratik yol

Düz metin beklenmedik şekilde davranıyorsa özgün kanıtı koruyun, codepoint'lerini inceleyin ve yalnızca bir kopyayı normalize edin.

### Teknik

Text steganography sıklıkla aynı görünen veya görünmez karakterlere dayanır:

- Homoglyphs: birbirine benzeyen farklı Unicode codepoint'leri (örneğin Latin `a` ve Kiril `а`)<sup>[[1]](#references)</sup>
- Zero-width characters: joiner'lar, non-joiner'lar ve zero-width space'ler<sup>[[2]](#references)</sup>
- Whitespace encodings: space'ler ile tab'lar arasındaki farklar, satır sonundaki space kalıpları ve kasıtlı satır uzunluğu kalıpları<sup>[[3]](#references)[[4]](#references)</sup>

Ek yüksek sinyalli durumlar:

- Metni görsel olarak yeniden sıralayabilen bidirectional control'ler<sup>[[1]](#references)</sup>
- Görünür metni neredeyse değiştirmeden gizli durum taşıyabilen variation selector'ler ve combining character'ler<sup>[[1]](#references)</sup>

### Decode yardımcıları

- [Unicode homoglyph ve zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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
## CSS `unicode-range` kanalları

`@font-face` kuralları, `unicode-range: U+..` girdilerinde baytları kodlamak için kötüye kullanılabilir. Codepoint'leri çıkarın, hexadecimal değerleri birleştirin ve kodlarını çözün:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Bildirim başına birden fazla değer içeriyorsa önce virgüllere göre ayırın ve normalleştirin (`tr ',+' '\n'`). Biçimlendirme tutarsız olduğunda Python baytları ayrıştırıp oluşturabilir.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Teknik Raporu #36: Unicode Güvenlik Hususları](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Sıfır Genişlikli Karakterler ve Homoglyph'ler ile Unicode Steganography](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Santa'nın İstek Listesi](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian kılavuzu: `stegsnow` whitespace steganography](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
