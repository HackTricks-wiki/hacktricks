# Metin Steganografisi

{{#include ../../banners/hacktricks-training.md}}

## Uygulama yolu

Düz metin beklenmedik şekilde davranıyorsa özgün kanıtı koruyun, codepoint'lerini inceleyin ve yalnızca bir kopyayı normalize edin.

### Teknik

Metin steganografisi çoğunlukla aynı görünen veya görünmez karakterlere dayanır:

- Homoglifler: birbirinden farklı ama benzer görünen Unicode codepoint'leri (örneğin, Latin `a` ve Kiril `а`)<sup>[[1]](#references)</sup>
- Sıfır genişlikli karakterler: birleştiriciler, birleştirmeyenler ve sıfır genişlikli boşluklar<sup>[[2]](#references)</sup>
- Boşluk kodlamaları: boşluklar ve sekmeler, satır sonu boşluk desenleri ve kasıtlı satır uzunluğu desenleri<sup>[[3]](#references)[[4]](#references)</sup>

Ek yüksek sinyalli durumlar:

- Metni görsel olarak yeniden sıralayabilen çift yönlü denetim karakterleri<sup>[[1]](#references)</sup>
- Görünen metni neredeyse hiç değiştirmeden gizli durum taşıyabilen varyasyon seçiciler ve birleştirici karakterler<sup>[[1]](#references)</sup>

### Kod çözme yardımcıları

- [Unicode homoglif ve sıfır genişlikli karakter kodlayıcı/kod çözücü](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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

`@font-face` kuralları, baytları `unicode-range: U+..` girdilerinde kodlamak için kötüye kullanılabilir. Kod noktalarını çıkarın, onaltılık değerleri birleştirin ve çözümleyin:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Aralıklar her bildirimde birden fazla değer içeriyorsa önce virgüllere göre bölün ve normalize edin (`tr ',+' '\n'`). Biçim tutarsız olduğunda Python baytları ayrıştırıp çıktı olarak verebilir.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Teknik Raporu #36: Unicode Güvenliğiyle İlgili Hususlar](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Sıfır Genişlikli Karakterler ve Homogliflerle Unicode Steganografisi](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Santa'nın İstek Listesi](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian kılavuzu: `stegsnow` boşluk steganografisi](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
