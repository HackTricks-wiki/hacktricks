# Görsel Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Çoğu CTF görsel stego örneği şu kategorilerden birine girer:

- LSB/bit düzlemleri (PNG/BMP)
- Metadata/yorum payload’ları
- PNG chunk düzensizlikleri / bozulma onarımı
- JPEG DCT alanı araçları (OutGuess vb.)
- Kare tabanlı (GIF/APNG)

## Hızlı ilk inceleme

Derin içerik analizinden önce kapsayıcı düzeyindeki kanıtlara öncelik verin:

- Dosyayı doğrulayın ve yapısını inceleyin: `file`, `magick identify -verbose`, biçim doğrulayıcıları (ör. `pngcheck`).
- Metadata’yı ve görünür dizeleri çıkarın: `exiftool -a -u -g1`, `strings`.
- Gömülü/sona eklenmiş içerik olup olmadığını kontrol edin: `binwalk` ve dosya sonunu inceleme (`tail | xxd`).
- Kapsayıcı türüne göre ilerleyin:
  - PNG/BMP: bit düzlemleri/LSB ve chunk düzeyindeki anormallikler.
  - JPEG: metadata + DCT alanı araçları (OutGuess/F5 tarzı aileler).
  - GIF/APNG: kare çıkarma, kare farkı analizi, palet hileleri.

## Bit düzlemleri / LSB

### Teknik

PNG/BMP, pikselleri **bit düzeyinde işlemeyi** kolaylaştıran biçimde sakladıkları için CTF’lerde sık kullanılır. Klasik gizleme/çıkarma yöntemi şöyledir:

- Her piksel kanalı (R/G/B/A) birden fazla bit içerir.
- Her kanalın **en az anlamlı biti** (LSB), görüntüyü çok az değiştirir.
- Saldırganlar verileri bu düşük sıralı bitlere, bazen belirli bir adım aralığıyla, permütasyonla veya kanal başına seçim yaparak gizler.

Meydan okumalarda karşılaşabilecekleriniz:

- Payload yalnızca tek bir kanaldadır (ör. `R` LSB).
- Payload alpha kanalındadır.
- Payload, çıkarıldıktan sonra sıkıştırılmış/kodlanmıştır.
- Mesaj bit düzlemlerine yayılmıştır veya düzlemler arasında XOR kullanılarak gizlenmiştir.

Karşılaşabileceğiniz diğer yöntem aileleri (uygulamaya bağlıdır):

- **LSB matching** (yalnızca biti çevirmek yerine hedef bite uyması için +/-1 ayarlamaları yapmak)
- **Palet/indeks tabanlı gizleme** (indeksli PNG/GIF: payload’ı ham RGB değerleri yerine renk indekslerinde gizlemek)
- **Yalnızca alpha kanalında payload’lar** (RGB görünümünde tamamen görünmez)

### Araçlar

#### zsteg

`zsteg`, PNG/BMP için birçok LSB/bit düzlemi çıkarma desenini dener:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: bir dizi dönüşüm uygular (metadata, image transforms, LSB varyantlarını brute force ile deneme).
- `stegsolve`: manuel görsel filtreler (kanalları ayırma, düzlemleri inceleme, XOR vb.).

Stegsolve indirme: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT tabanlı görünürlük hileleri

FFT, LSB extraction değildir; içerik frequency space içinde kasıtlı olarak gizlendiğinde veya ince desenlerde kullanılır.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF'lerde sıklıkla kullanılan web tabanlı triage araçları:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG iç yapısı: chunks, bozulma ve gizli veriler

### Teknik

PNG, chunk tabanlı bir formattır. Birçok challenge'da payload, pixel değerleri yerine container/chunk seviyesinde saklanır:

- **`IEND` sonrasındaki fazladan baytlar** (birçok görüntüleyici sondaki baytları yok sayar)
- **Payload taşıyan standart dışı ancillary chunks**; [PNG chunk walker ve carving iş akışına](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads) bakın.
- **Boyutları gizleyen veya düzeltilene kadar parser'ları bozan bozuk header'lar**

İncelenmesi gereken, yüksek sinyal taşıyan chunk konumları:

- `tEXt` / `iTXt` / `zTXt` (text metadata, bazen sıkıştırılmış)
- `iCCP` (ICC profile) ve taşıyıcı olarak kullanılan diğer ancillary chunks
- `eXIf` (PNG içindeki EXIF verileri)

### Triage komutları

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Neleri kontrol etmeli:

- Tuhaf genişlik/yükseklik/bit derinliği/renk türü kombinasyonları
- CRC/chunk hataları (`pngcheck` genellikle tam offset'i gösterir)
- `IEND` sonrasında ek veri olduğuna dair uyarılar

Daha ayrıntılı bir chunk görünümüne ihtiyacınız varsa:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Faydalı referanslar:

- PNG specification (yapı, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF köşe durumları): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools ve ELA limitations

### Teknik

JPEG, ham pixels olarak saklanmaz; DCT domain içinde sıkıştırılır. Bu nedenle JPEG stego tools, PNG LSB tools'tan farklıdır:

- Metadata/comment payloads dosya düzeyindedir (yüksek sinyalli ve hızlıca incelenebilir)
- DCT-domain stego tools, bits'leri frequency coefficients içine gömer

Operasyonel olarak JPEG'i şöyle değerlendirin:

- Metadata segments için bir container (yüksek sinyalli, hızlıca incelenebilir)
- Specialized stego tools'un çalıştığı sıkıştırılmış bir signal domain (DCT coefficients)

### Hızlı kontroller

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Yüksek sinyalli konumlar:

- EXIF/XMP/IPTC metadata
- JPEG yorum segmenti (`COM`)
- Application segmentleri (`EXIF` için `APP1`, üretici verileri için `APPn`)

### Yaygın araçlar

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Özellikle JPEG’lerde steghide payload’larıyla karşılaşıyorsanız, `stegseek` kullanmayı düşünün (eski script’lerden daha hızlı brute-force):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA farklı yeniden sıkıştırma izlerini vurgular; düzenlenen bölgeleri bulmanıza yardımcı olabilir, ancak tek başına bir stego detector değildir:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animasyonlu görseller

### Teknik

Animasyonlu görsellerde mesajın:

- Tek bir karede olduğunu (kolay),
- Karelere yayıldığını (sıralama önemlidir) veya
- Yalnızca ardışık kareleri karşılaştırdığınızda göründüğünü varsayın

### Kareleri çıkarma

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Ardından kareleri normal PNG'ler gibi işleyin: `zsteg`, `pngcheck`, kanal izolasyonu.

Alternatif araçlar:

- `gifsicle --explode anim.gif` (hızlı kare çıkarma)
- Kare başına dönüşümler için `imagemagick`/`magick`

Kare farkı alma genellikle belirleyicidir:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG piksel sayısı kodlaması

- APNG kapsayıcılarını algılayın: `exiftool -a -G1 file.png | grep -i animation` veya `file`.
- Zamanlamayı değiştirmeden kareleri çıkarın: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

Animasyonlu görevlerde her byte, her karede belirli bir rengin sayısı olarak kodlanabilir; bu sayıları birleştirmek mesajı yeniden oluşturur.<sup>[[1]](#references)</sup>

## Parola korumalı veri gömme

Piksel düzeyinde manipülasyon yerine bir parola ifadesiyle korunan veri gömme işleminden şüpheleniyorsanız, bu genellikle en hızlı yoldur.

### steghide

`JPEG, BMP, WAV, AU` biçimlerini destekler ve şifrelenmiş payload’ları gömebilir/çıkarabilir.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Depo: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Depo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV formatlarını destekler.

Depo: https://github.com/dhsdshdhk/stegpy



## References

- [1] [Flagvent 2025 (Medium) — pembe, Noel Baba’nın İstek Listesi, Noel Metadata’sı, Yakalanan Gürültü](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
