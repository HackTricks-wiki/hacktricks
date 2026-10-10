# Görsel Steganografisi

{{#include ../../banners/hacktricks-training.md}}

CTF’lerdeki görsel stego yöntemlerinin çoğu şu kategorilerden birine girer:

- LSB/bit düzlemleri (PNG/BMP)
- Metadata/comment payload’ları
- PNG chunk’larındaki anormallikler / bozulma onarımı
- JPEG DCT-domain araçları (OutGuess vb.)
- Kare tabanlı yöntemler (GIF/APNG)

## Hızlı ön inceleme

Derin içerik analizine geçmeden önce container düzeyindeki kanıtlara öncelik verin:

- Dosyayı doğrulayın ve yapısını inceleyin: `file`, `magick identify -verbose`, format doğrulayıcıları (örn. `pngcheck`).
- Metadata’yı ve görünür dizeleri çıkarın: `exiftool -a -u -g1`, `strings`.
- Gömülü/sona eklenmiş içerik olup olmadığını kontrol edin: `binwalk` ve dosya sonunu inceleme (`tail | xxd`).
- Container türüne göre ilerleyin:
  - PNG/BMP: bit düzlemleri/LSB ve chunk düzeyindeki anormallikler.
  - JPEG: metadata + DCT-domain araçları (OutGuess/F5 tarzı aileler).
  - GIF/APNG: kare çıkarma, kare farkı, palette hileleri.

## Bit düzlemleri / LSB

### Teknik

PNG/BMP, pikselleri **bit düzeyinde işlemeyi** kolaylaştıran bir biçimde sakladıkları için CTF’lerde sık kullanılır. Klasik gizleme/çıkarma yöntemi şöyledir:

- Her piksel kanalı (R/G/B/A) birden çok bit içerir.
- Her kanalın **en önemsiz biti** (LSB), görseli çok az değiştirir.
- Saldırganlar verileri bu düşük değerli bitlere, bazen belirli bir adımla, permütasyonla veya kanal seçimiyle gizler.

Challenge’larda karşılaşabilecekleriniz:

- Payload yalnızca tek bir kanaldadır (örn. `R` LSB).
- Payload alpha kanalındadır.
- Payload çıkarıldıktan sonra sıkıştırılmış/kodlanmıştır.
- Mesaj, bit düzlemlerine yayılmıştır veya düzlemler arasındaki XOR işlemiyle gizlenmiştir.

Karşılaşabileceğiniz diğer aileler (uygulamaya bağlıdır):

- **LSB matching** (yalnızca biti değiştirmek yerine, hedef bite uyması için +/-1 ayarlama)
- **Palette/index tabanlı gizleme** (indexed PNG/GIF: payload ham RGB yerine renk indekslerindedir)
- **Yalnızca alpha kanalında bulunan payload’lar** (RGB görünümünde tamamen görünmez)

### Araçlar

#### zsteg

`zsteg`, PNG/BMP için birçok LSB/bit düzlemi çıkarma desenini tarar:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: bir dizi dönüşüm uygular (metadata, image transforms, LSB varyantlarını brute force ile deneme).
- `stegsolve`: manuel görsel filtreler (kanal izolasyonu, düzlem inceleme, XOR vb.).

Stegsolve indirme: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT tabanlı görünürlük teknikleri

FFT, LSB çıkarma yöntemi değildir; içeriğin frekans uzayında veya ince desenlerde kasıtlı olarak gizlendiği durumlarda kullanılır.

- EPFL demosu: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF'lerde sık kullanılan web tabanlı triage araçları:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG iç yapısı: chunk'lar, bozulma ve gizli veriler

### Teknik

PNG, chunk'lara bölünmüş bir formattır. Birçok challenge'da payload, piksel değerleri yerine kapsayıcı/chunk düzeyinde saklanır:

- **`IEND` sonrasındaki ekstra baytlar** (birçok görüntüleyici sondaki baytları yok sayar)
- **Payload taşıyan standart dışı ancillary chunk'lar**
- **Boyutları gizleyen veya düzeltilene kadar parser'ları bozan bozuk header'lar**

İncelenmesi gereken, yüksek sinyal taşıyan chunk konumları:

- `tEXt` / `iTXt` / `zTXt` (metin metadata'sı; bazen sıkıştırılmış)
- `iCCP` (ICC profili) ve taşıyıcı olarak kullanılan diğer ancillary chunk'lar
- `eXIf` (PNG'deki EXIF verisi)

### Triage komutları

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Nelere bakmalı:

- Tuhaf genişlik/yükseklik/bit derinliği/renk türü kombinasyonları
- CRC/chunk hataları (pngcheck genellikle tam ofseti belirtir)
- `IEND` sonrasında ek veri olduğuna dair uyarılar

Daha ayrıntılı bir chunk görünümüne ihtiyacınız varsa:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Faydalı kaynaklar:

- PNG spesifikasyonu (yapı, parçalar): https://www.w3.org/TR/PNG/
- Dosya biçimi hileleri (PNG/JPEG/GIF uç durumları): https://github.com/corkami/docs

## JPEG: metadata, DCT alanı araçları ve ELA sınırlamaları

### Teknik

JPEG, ham pikseller olarak saklanmaz; DCT alanında sıkıştırılır. Bu nedenle JPEG stego araçları PNG LSB araçlarından farklıdır:

- Metadata/yorum payload'ları dosya düzeyindedir (yüksek sinyalli ve hızlıca incelenebilir)
- DCT alanı stego araçları, frekans katsayılarına bit gömer

Operasyonel olarak JPEG'i şöyle ele alın:

- Metadata segmentleri için bir kapsayıcı (yüksek sinyalli, hızlıca incelenebilir)
- Uzmanlaşmış stego araçlarının çalıştığı sıkıştırılmış bir sinyal alanı (DCT katsayıları)

### Hızlı kontroller

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Yüksek sinyalli konumlar:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Yaygın araçlar

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Özellikle JPEG’lerde steghide payload’larıyla karşılaşıyorsanız, `stegseek` kullanmayı düşünebilirsiniz (eski script’lere göre daha hızlı bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA, farklı yeniden sıkıştırma artefaktlarını vurgular; düzenlenen bölgeleri bulmanıza yardımcı olabilir, ancak tek başına bir stego detector değildir:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animasyonlu görseller

### Teknik

Animasyonlu görsellerde mesajın şu şekillerde olduğunu varsayın:

- Tek bir frame’de (kolay), veya
- Frame’lere yayılmış (sıralama önemlidir), veya
- Yalnızca ardışık frame’leri diff ettiğinizde görünür

### Frame’leri çıkarma

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Ardından kareleri normal PNG'ler gibi ele alın: `zsteg`, `pngcheck`, kanal izolasyonu.

Alternatif araçlar:

- `gifsicle --explode anim.gif` (kareleri hızlıca çıkarma)
- Kare başına dönüşümler için `imagemagick`/`magick`

Kare farklarını alma yöntemi çoğu zaman belirleyicidir:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG piksel sayısı kodlaması

- APNG kapsayıcılarını algılayın: `exiftool -a -G1 file.png | grep -i animation` veya `file`.
- Kareleri yeniden zamanlama yapmadan çıkarın: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Kare başına piksel sayısı olarak kodlanmış payload'ları kurtarın:

```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
    counts = Image.open(f).getcolors()
    target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
    out.append(target or 0)
print(bytes(out).decode('latin1'))
```

Animasyonlu challenge'lar, her byte'ı her karede belirli bir rengin sayısı olarak kodlayabilir; sayıların birleştirilmesi mesajı yeniden oluşturur.<sup>[[1]](#references)</sup>

## Parola korumalı gömme

Piksel düzeyinde manipülasyon yerine bir passphrase ile korunan gömme işleminden şüpheleniyorsanız, bu genellikle en hızlı yoldur.

### steghide

`JPEG, BMP, WAV, AU` formatlarını destekler ve şifrelenmiş payload'ları gömebilir/çıkarabilir.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV formatlarını destekler.

Repo: https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (Medium) — pembe, Noel Baba’nın İstek Listesi, Noel Metadata’sı, Yakalanan Gürültü](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
