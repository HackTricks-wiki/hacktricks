# Görüntü Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Çoğu CTF image stego örneği şu kategorilerden birine girer:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk anormallikleri / bozulma onarımı
- JPEG DCT-domain tools (OutGuess vb.)
- Frame-based (GIF/APNG)

## Hızlı ön inceleme

Derin content analysis işleminden önce container-level kanıtları önceliklendirin:

- Dosyayı doğrulayın ve yapıyı inceleyin: `file`, `magick identify -verbose`, format validators (ör. `pngcheck`).
- Metadata ve görünür string'leri çıkarın: `exiftool -a -u -g1`, `strings`.
- Embedded/appended content olup olmadığını kontrol edin: `binwalk` ve dosya sonu incelemesi (`tail | xxd`).
- Container türüne göre ilerleyin:
- PNG/BMP: bit-planes/LSB ve chunk-level anormallikleri.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP, pikselleri **bit-level manipulation** işlemini kolaylaştıracak şekilde sakladıkları için CTF'lerde popülerdir. Klasik hide/extract mekanizması şöyledir:

- Her pixel channel (R/G/B/A) birden fazla bit içerir.
- Her channel'ın **least significant bit** (LSB) değeri görüntüyü çok az değiştirir.
- Attackers verileri bu düşük anlamlı bitlere gizler; bazen stride, permutation veya channel başına seçim kullanılır.

Challenge'larda beklenebilecekler:

- Payload yalnızca tek bir channel içindedir (ör. `R` LSB).
- Payload alpha channel içindedir.
- Payload extraction sonrasında compressed/encoded durumdadır.
- Message plane'ler arasına dağıtılmış veya plane'ler arasındaki XOR kullanılarak gizlenmiştir.

Karşılaşabileceğiniz ek family'ler (implementation-dependent):

- **LSB matching** (yalnızca biti değiştirmek yerine target bit ile eşleşmesi için +/-1 ayarlamaları yapmak)
- **Palette/index-based hiding** (indexed PNG/GIF: payload raw RGB yerine color indices içinde)
- **Alpha-only payloads** (RGB görünümünde tamamen görünmez)

### Tooling

#### zsteg

`zsteg`, PNG/BMP için birçok LSB/bit-plane extraction pattern'ını enumerate eder:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: bir dizi transform çalıştırır (metadata, image transforms, LSB varyantlarının brute forcing işlemi).
- `stegsolve`: manuel görsel filtreler (kanal izolasyonu, plane incelemesi, XOR vb.).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT tabanlı görünürlük teknikleri

FFT, LSB extraction değildir; içeriğin frequency space içinde kasıtlı olarak gizlendiği veya ince pattern'lerin kullanıldığı durumlar içindir.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF'lerde sıklıkla kullanılan web tabanlı triage araçları:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunk'lar, corruption ve hidden data

### Technique

PNG, chunk tabanlı bir formattır. Birçok challenge'da payload, pixel değerleri yerine container/chunk seviyesinde saklanır:

- **`IEND` sonrasındaki extra bytes** (birçok viewer trailing bytes'ı yok sayar)
- **Payload taşıyan non-standard ancillary chunk'lar**
- **Boyutları gizleyen veya düzeltilene kadar parser'ları bozan corrupted header'lar**

İncelenmesi gereken high-signal chunk konumları:

- `tEXt` / `iTXt` / `zTXt` (text metadata; bazen compressed)
- `iCCP` (ICC profile) ve carrier olarak kullanılan diğer ancillary chunk'lar
- `eXIf` (PNG içindeki EXIF data)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Neleri kontrol etmeli:

- Olağandışı width/height/bit-depth/colour-type kombinasyonları
- CRC/chunk hataları (`pngcheck` genellikle tam offset'i gösterir)
- `IEND` sonrasında ek veri olduğuna dair uyarılar

Daha ayrıntılı bir chunk görünümüne ihtiyacınız varsa:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Yararlı referanslar:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Technique

JPEG ham pikseller olarak saklanmaz; DCT domain içinde sıkıştırılır. JPEG stego tools bu nedenle PNG LSB tools'tan farklıdır:

- Metadata/comment payload'ları dosya seviyesindedir (yüksek sinyalli ve hızlıca incelenebilir)
- DCT-domain stego tools, bit'leri frekans katsayılarına gömer

Operasyonel olarak JPEG'i şu şekilde ele alın:

- Metadata segment'leri için bir container (yüksek sinyalli, hızlıca incelenebilir)
- Specialized stego tools'un çalıştığı sıkıştırılmış bir sinyal domain'i (DCT katsayıları)

### Quick checks
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

Özellikle JPEG dosyalarındaki steghide payload'larıyla karşılaşıyorsanız `stegseek` kullanmayı değerlendirin (eski script'lerden daha hızlı bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA, farklı yeniden sıkıştırma artefact'larını vurgular; düzenlenmiş bölgeleri tespit etmenize yardımcı olabilir, ancak tek başına bir stego detector değildir:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animated images

### Technique

Animated images için mesajın şu şekillerden biri olduğunu varsayın:

- Tek bir frame'de (kolay), veya
- Frame'lere yayılmış (sıralama önemlidir), veya
- Yalnızca ardışık frame'leri diff ettiğinizde görünür

### Kareleri çıkarma
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Sonrasında karelere normal PNG'ler gibi davranın: `zsteg`, `pngcheck`, kanal izolasyonu.

Alternatif araçlar:

- `gifsicle --explode anim.gif` (hızlı kare çıkarma)
- Kare başına dönüşümler için `imagemagick`/`magick`

Kare fark analizi çoğu zaman belirleyicidir:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNG container'larını tespit edin: `exiftool -a -G1 file.png | grep -i animation` veya `file`.
- Yeniden zamanlama yapmadan frame'leri çıkarın: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Frame başına pixel count olarak encode edilmiş payload'ları kurtarın:
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
Animasyonlu challenge'lar, her byte'ı her frame'deki belirli bir rengin sayısı olarak kodlayabilir; bu sayıları birleştirmek mesajı yeniden oluşturur.<sup>[[1]](#references)</sup>

## Parola korumalı embedding

Embedding işleminin pixel-level manipulation yerine bir passphrase ile korunduğundan şüpheleniyorsanız, bu genellikle en hızlı yoldur.

### steghide

`JPEG, BMP, WAV, AU` formatlarını destekler ve şifrelenmiş payload'ları embed/extract edebilir.
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

PNG/BMP/GIF/WebP/WAV destekler.

Repo: https://github.com/dhsdshdhk/stegpy

## Referanslar

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
