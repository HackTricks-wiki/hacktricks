# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Çoğu CTF image stego şu başlıklardan birine indirgenir:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Hızlı triyaj

Derin içerik analizinden önce container düzeyindeki kanıtlara öncelik verin:

- Dosyayı doğrulayın ve yapısını inceleyin: `file`, `magick identify -verbose`, format doğrulayıcıları (ör. `pngcheck`).
- Metadata ve görünen string'leri çıkarın: `exiftool -a -u -g1`, `strings`.
- Gömülü/append edilmiş içerik olup olmadığını kontrol edin: `binwalk` ve dosya sonu incelemesi (`tail | xxd`).
- Container'a göre dallanın:
  - PNG/BMP: bit-planes/LSB ve chunk düzeyindeki anormallikler.
  - JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
  - GIF/APNG: frame extraction, frame differencing, palet hileleri.

## Bit-planes / LSB

### Teknik

PNG/BMP, pikselleri **bit-seviyesi manipülasyonu** kolaylaştıracak şekilde sakladıkları için CTF'lerde popülerdir. Klasik gizleme/çıkartma mekanizması şudur:

- Her piksel kanalı (R/G/B/A) birden fazla bit içerir.
- Her kanalın **least significant bit** (LSB) görüntüyü çok az değiştirir.
- Saldırganlar veriyi bu düşük dereceli bitlerde saklar; bazen stride, permutation veya kanal başına seçim kullanılır.

Meydan okumalarda bekleyebilecekleriniz:

- Payload sadece tek bir kanalda olur (ör. `R` LSB).
- Payload alpha kanalında olur.
- Payload çıkarıldıktan sonra sıkıştırılmış/kodlanmış olabilir.
- Mesaj bit-planları arasında yayılmış veya planlar arasında XOR ile gizlenmiş olabilir.

Karşılaşabileceğiniz ek aileler (uygulamaya bağlı olarak):

- **LSB matching** (sadece biti çevirmek değil, hedef biti eşleştirmek için +/-1 ayarlamaları)
- **Palette/index-based hiding** (indexed PNG/GIF: payload renk indekslerinde, ham RGB yerine)
- **Alpha-only payloads** (RGB görünümünde tamamen görünmez)

### Araçlar

#### zsteg

`zsteg` PNG/BMP için birçok LSB/bit-plane çıkarma desenini listeler:
```bash
zsteg -a file.png
```
Depo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: bir dizi dönüşüm çalıştırır (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: manuel görsel filtreler uygular (channel isolation, plane inspection, XOR, vb).

Stegsolve indirme: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT, LSB extraction değildir; içerik frekans uzayında veya ince desenlerde kasıtlı olarak gizlendiğinde kullanılır.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF'lerde sıklıkla kullanılan web tabanlı ön inceleme araçları:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Teknik

PNG, chunk tabanlı bir formattır. Birçok görevde payload, piksel değerleri yerine container/chunk seviyesinde saklanır:

- **`IEND` sonrasında ekstra byte'lar** (birçok görüntüleyici sonundaki byte'ları yok sayar)
- **Standart dışı yardımcı chunk'lar** payload taşır
- **Bozulmuş başlıklar** boyutları gizleyebilir veya düzeltileene kadar ayrıştırıcıları bozabilir

Öncelikli kontrol edilecek chunk konumları:

- `tEXt` / `iTXt` / `zTXt` (metin meta verisi, bazen sıkıştırılmış)
- `iCCP` (ICC profile) ve taşıyıcı olarak kullanılan diğer yardımcı chunk'lar
- `eXIf` (PNG'de EXIF verisi)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Nelere dikkat edilmeli:

- Garip width/height/bit-depth/colour-type kombinasyonları
- CRC/chunk hataları (pngcheck genellikle tam offset'i gösterir)
- `IEND` sonrası ek veri ile ilgili uyarılar

Daha derin bir chunk görünümüne ihtiyacınız varsa:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Faydalı referanslar:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Teknik

JPEG ham piksel olarak saklanmaz; DCT domaininde sıkıştırılır. Bu yüzden JPEG stego araçları PNG LSB araçlarından farklıdır:

- Metadata/comment payloads dosya seviyesindedir (high-signal ve hızlıca incelenebilir)
- DCT-domain stego araçları bitleri frekans katsayılarına gömer

Operasyonel olarak JPEG'i şu şekilde ele alın:

- A container for metadata segments (high-signal, quick to inspect)
- Özel stego araçlarının çalıştığı sıkıştırılmış bir sinyal domaini (DCT katsayıları)

### Hızlı kontroller
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Yüksek-sinyal konumları:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Yaygın araçlar

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA farklı yeniden sıkıştırma artefaktlarını vurgular; düzenlenmiş bölgelere işaret edebilir, ancak tek başına bir stego detector değildir:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animasyonlu görüntüler

### Teknik

Animasyonlu görüntüler için, mesajın şunlardan biri olduğunu varsayın:

- Tek bir karede (kolay), veya
- Karelere yayılmış (sıra önemli), veya
- Sadece ardışık kareleri difflediğinizde görünür

### Kareleri çıkarma
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Sonra frame'leri normal PNG'ler gibi ele al: `zsteg`, `pngcheck`, channel isolation.

Alternatif araçlar:

- `gifsicle --explode anim.gif` (hızlı frame çıkarma)
- `imagemagick`/`magick` frame başına dönüşümler için

Frame differencing genellikle belirleyicidir:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNG konteynerlerini tespit et: `exiftool -a -G1 file.png | grep -i animation` veya `file`.
- Zamanlamayı değiştirmeden kareleri çıkar: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Her kare başına piksel sayısı olarak kodlanmış payload'ları kurtar:
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
Animasyonlu zorluklar, her baytı her karede belirli bir rengin sayısı olarak kodlayabilir; bu sayıların birleştirilmesi mesajı yeniden oluşturur.

## Password-protected embedding

Eğer piksel düzeyindeki manipülasyon yerine passphrase ile korunan embedding olduğunu düşünüyorsanız, bu genellikle en hızlı yoldur.

### steghide

`JPEG, BMP, WAV, AU`'yi destekler ve şifrelenmiş payloadları embed/extract edebilir.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
src/stego/images/README.md dosyasının içeriğini buraya yapıştırır mısınız (veya raw link verin)? İçeriği aldıktan sonra istenen kurallara uyarak Türkçeye çevirip aynı markdown/html sözdizimini koruyacağım.
```bash
stegcracker file.jpg wordlist.txt
```
Depo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV desteği.

Depo: https://github.com/dhsdshdhk/stegpy

## Referanslar

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
