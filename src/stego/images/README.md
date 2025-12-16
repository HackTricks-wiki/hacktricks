# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Çoğu CTF image stego şu kategorilerden birine indirgenir:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Hızlı triyaj

İçerik derin analizinden önce konteyner-seviyesindeki kanıtlara öncelik verin:

- Dosyayı doğrulayın ve yapısını inceleyin: `file`, `magick identify -verbose`, format doğrulayıcıları (ör. `pngcheck`).
- Metadata ve görünür stringleri çıkarın: `exiftool -a -u -g1`, `strings`.
- Gömülü/eklenmiş içeriği kontrol edin: `binwalk` ve dosya sonu incelemesi (`tail | xxd`).
- Konteynere göre dallandırma:
- PNG/BMP: bit-planes/LSB ve chunk-seviyesi anomaliler.
- JPEG: metadata + DCT-domain araçları (OutGuess/F5-style aileleri).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Teknik

PNG/BMP, pikselleri **bit-düzeyinde manipülasyonu** kolay hale getiren bir şekilde depoladıkları için CTF'lerde popülerdir. Klasik gizleme/çıkartma mekanizması:

- Her piksel kanalı (R/G/B/A) birden fazla bit içerir.
- Her kanalın **least significant bit** (LSB) görüntüyü çok az değiştirir.
- Saldırganlar veriyi bu düşük öncelikli bitlere gizler; bazen bir stride, permütasyon veya kanal başına seçim ile.

Zorluklarda ne beklenir:

- Payload sadece tek bir kanalda olur (ör. `R` LSB).
- Payload alpha kanalındadır.
- Çıkartmadan sonra payload sıkıştırılmış/kodlanmış olur.
- Mesaj plane'lar arasında yayılmıştır veya plane'lar arasındaki XOR ile saklanmıştır.

Karşılaşabileceğiniz ek aileler (uygulamaya bağlı olarak):

- **LSB matching** (sadece biti çevirmek değil, hedef biti tutturmak için +/-1 ayarlamaları)
- **Palette/index-based hiding** (indexed PNG/GIF: payload renk indekslerinde, ham RGB yerine)
- **Alpha-only payloads** (RGB görünümünde tamamen görünmez)

### Araçlar

#### zsteg

`zsteg` PNG/BMP için birçok LSB/bit-plane çıkarma desenini listeler:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: metadata, image transforms, brute forcing LSB variants içeren bir dizi dönüşüm çalıştırır.
- `stegsolve`: manuel görsel filtreler (channel isolation, plane inspection, XOR, vb.).

Stegsolve indirme: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT, LSB çıkarımı değildir; içerik kasıtlı olarak frekans uzayında veya ince desenlerde gizlendiği durumlar içindir.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF'lerde sık kullanılan web tabanlı triage:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG iç yapısı: chunks, bozulma ve gizli veri

### Teknik

PNG, chunk'lanmış bir formattır. Birçok görevde payload, piksel değerleri yerine container/chunk düzeyinde saklanır:

- **Extra bytes after `IEND`** (many viewers ignore trailing bytes)
- **Non-standard ancillary chunks** carrying payloads
- **Corrupted headers** that hide dimensions or break parsers until fixed

İncelenecek yüksek sinyalli chunk konumları:

- `tEXt` / `iTXt` / `zTXt` (text metadata, bazen sıkıştırılmış)
- `iCCP` (ICC profile) ve taşıyıcı olarak kullanılan diğer ancillary chunks
- `eXIf` (PNG içindeki EXIF verisi)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Nelere bakmalı:

- Garip genişlik/yükseklik/bit-derinliği/renk-tipi kombinasyonları
- CRC/chunk hataları (pngcheck genellikle tam offset'i gösterir)
- `IEND` sonrasındaki ek veri uyarıları

Daha ayrıntılı bir chunk görünümüne ihtiyaç duyuyorsanız:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Yararlı referanslar:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain araçları ve ELA sınırlamaları

### Teknik

JPEG ham piksel olarak saklanmaz; DCT domaininde sıkıştırılır. Bu yüzden JPEG stego araçları PNG LSB araçlarından farklıdır:

- Metadata/comment payloads dosya düzeyindedir (yüksek sinyal, hızlı incelenir)
- DCT-domain stego araçları bitleri frekans katsayılarına gömer

Pratikte, JPEG'i şu şekilde ele alın:

- Metadata segmentleri için bir konteyner (yüksek sinyal, hızlı incelenir)
- Uzmanlaşmış stego araçlarının çalıştığı sıkıştırılmış bir sinyal alanı (DCT coefficients)

### Hızlı kontroller
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Yüksek sinyal konumları:

- EXIF/XMP/IPTC metaveri
- JPEG yorum segmenti (`COM`)
- Uygulama segmentleri (`APP1` EXIF için, `APPn` üretici verisi için)

### Yaygın araçlar

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG'lerde özellikle steghide payloads ile karşılaşıyorsanız, `stegseek` kullanmayı düşünün (eski script'lere göre daha hızlı bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA farklı yeniden sıkıştırma artefaktlarını öne çıkarır; düzenlenmiş bölgelere işaret edebilir, ancak tek başına bir stego dedektörü değildir:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animasyonlu görüntüler

### Teknik

Animasyonlu görüntüler için, mesajın şu şekilde olduğunu varsayın:

- Tek bir karede (kolay), veya
- Kareler arasında yayılmış (sıralama önemli), veya
- Sadece ardışık kareleri diff'lediğinizde görünür

### Kareleri çıkarma
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Sonra frame'leri normal PNG'ler gibi işle: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (fast frame extraction)
- `imagemagick`/`magick` for per-frame transforms

Frame differencing çoğunlukla belirleyicidir:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Parola ile korunan embedding

Eğer piksel düzeyindeki manipülasyondan ziyade bir passphrase ile korunan embedding olduğunu düşünüyorsanız, bu genellikle en hızlı yoldur.

### steghide

`JPEG, BMP, WAV, AU` formatlarını destekler ve şifrelenmiş payload'ları embed/extract edebilir.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to the repository files. Please paste the contents of src/stego/images/README.md here (or the part you want translated), and I will translate the English text to Turkish while keeping the markdown, tags, links and paths unchanged.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV formatlarını destekler.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
