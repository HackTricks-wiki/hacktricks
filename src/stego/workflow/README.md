# Stego İş Akışı

{{#include ../../banners/hacktricks-training.md}}

Çoğu stego problemi, rastgele araçlar denemek yerine sistematik triyajla daha hızlı çözülür.

## Temel akış

### Hızlı triyaj kontrol listesi

Amaç, iki soruyu verimli şekilde yanıtlamaktır:

1. Gerçek container/format nedir?
2. Payload metadata'da mı, eklenmiş baytlarda mı, gömülü dosyalarda mı, yoksa içerik düzeyinde stego'da mı?

#### 1) Container'ı belirleyin

```bash
file target
ls -lah target
```

`file` ile uzantı uyuşmuyorsa, uzantıya güvenmek yerine imzayı inceleyin. `file` sezgiseldir ve bozuk ya da poliglot girdilerle yanıltılabilir. Uygun olduğunda yaygın biçimleri kapsayıcılar olarak değerlendirin (örneğin, OOXML belgeleri ZIP paketleridir).<sup>[[2]](#references)</sup>

#### 2) Metadata ve belirgin dizeleri arayın

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Birden fazla kodlamayı deneyin:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Sona eklenmiş verileri / gömülü dosyaları kontrol edin

```bash
binwalk target
binwalk -e target
```

Extraction başarısız olur ancak imzalar raporlanırsa, `dd` ile ofsetleri elle ayıklayın ve ayıklanan bölge üzerinde `file` komutunu yeniden çalıştırın.

#### 4) Görselse

- Anormallikleri inceleyin: `magick identify -verbose file`
- PNG/BMP ise bit düzlemlerini/LSB’yi listeleyin: `zsteg -a file.png`
- PNG yapısını doğrulayın: `pngcheck -v file.png`
- İçerik kanal/düzlem dönüşümleriyle ortaya çıkabilecekse görsel filtreler kullanın (Stegsolve / StegoVeritas)

#### 5) Ses ise

- Önce spektrogramı inceleyin (Sonic Visualiser)
- Akışları çözümleyin/inceleyin: `ffmpeg -v info -i file -f null -`
- Ses yapılandırılmış tonlara benziyorsa DTMF çözümlemeyi deneyin

### Temel araçlar

Bunlar, yüksek frekanslı kapsayıcı düzeyindeki durumları yakalar: metadata yükleri, sona eklenmiş baytlar ve uzantısı değiştirilerek gizlenmiş gömülü dosyalar.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk

```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```

Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost

```bash
foremost -i file
```

Proje deposu: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2

```bash
exiftool file
exiv2 file
```

#### file / strings

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### Container'lar, sona eklenen veriler ve polyglot numaraları

Birçok steganografi yarışmasında, geçerli bir dosyanın sonuna eklenmiş fazladan baytlar veya uzantısıyla gizlenmiş gömülü arşivler bulunur.

#### Sona eklenen payload'lar

Birçok format sondaki baytları yok sayar. Bir ZIP/PDF/script, bir görüntü/ses container'ının sonuna eklenebilir.

Hızlı kontroller:

```bash
binwalk file
tail -c 200 file | xxd
```

Bir offset biliyorsanız, `dd` ile carve edin:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Magic bytes

`file` kafası karıştığında, `xxd` ile magic bytes'ları bulun ve bilinen imzalarla karşılaştırın:

```bash
xxd -g 1 -l 32 file
```

#### Kılık Değiştirmiş Zip

Uzantısı zip olduğunu göstermese bile `7z` ve `unzip` komutlarını deneyin:

```bash
7z l file
unzip -l file
```

### Stego yakınındaki sıra dışı durumlar

Stego'nun yanında sıkça görülen örüntüler için hızlı bağlantılar (binary'den QR, braille vb.).

#### Binary'den QR kodları

Bir blob'un uzunluğu tam kareyse, ham piksellerden oluşan bir görüntü/QR olabilir.

```python
import math
math.isqrt(2500)  # 50
```

İkili-görüntü yardımcı aracı:

- dCode ikili-görüntü yardımcısı.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille çevirmeni.<sup>[[6]](#references)</sup>

Steganografi yardımcı programları ve tekniğe özgü kaynaklardan oluşan daha geniş koleksiyonlar için birlikte sunulan stego-toolkit’e ve 0xRick’in derlediği listeye bakın.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - En popüler steganografi araçlarının bir arada sunulduğu Docker imajı](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Açık Paketleme Kuralları](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — İkili Görüntü](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille Çevirmeni](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganografi Kaynakları](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
