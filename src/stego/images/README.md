# Görsel Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Çoğu CTF image stego örneği şu kategorilerden birine girer:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, vb.)
- Frame-based (GIF/APNG)

## Hızlı triage

Derin içerik analizinden önce container-level kanıtları önceliklendirin:

- Dosyayı doğrulayın ve yapısını inceleyin: `file`, `magick identify -verbose`, format validators (ör. `pngcheck`).
- Metadata ve görünür string'leri çıkarın: `exiftool -a -u -g1`, `strings`.
- Embedded/appended content olup olmadığını kontrol edin: `binwalk` ve dosyanın sonunu inceleme (`tail | xxd`).
- Container'a göre ilerleyin:
- PNG/BMP: bit-planes/LSB ve chunk-level anomalileri.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP, pikselleri **bit-level manipulation** işlemlerini kolaylaştıran bir biçimde sakladıkları için CTF'lerde popülerdir. Klasik hide/extract mekanizması şöyledir:

- Her pixel channel (R/G/B/A) birden fazla bit içerir.
- Her channel'ın **least significant bit**'i (LSB), görseli çok az değiştirir.
- Attackers, bazen bir stride, permutation veya channel seçimi kullanarak veriyi bu low-order bit'lerde gizler.

Challenge'larda karşılaşılması beklenen durumlar:

- Payload yalnızca bir channel içindedir (ör. `R` LSB).
- Payload alpha channel içindedir.
- Payload, extraction sonrasında compressed/encoded durumdadır.
- Mesaj plane'ler arasına dağıtılmıştır veya plane'ler arasındaki XOR kullanılarak gizlenmiştir.

Karşılaşabileceğiniz ek family'ler (implementation-dependent):

- **LSB matching** (yalnızca biti flip etmek yerine, hedef bit ile eşleştirmek için +/-1 adjustments kullanır)
- **Palette/index-based hiding** (indexed PNG/GIF: payload raw RGB yerine color indices içinde saklanır)
- **Alpha-only payloads** (RGB görünümünde tamamen görünmez)

### Tooling

#### zsteg

`zsteg`, PNG/BMP için birçok LSB/bit-plane extraction pattern'ını enumerate eder:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: bir dizi dönüşüm çalıştırır (metadata, image transforms, LSB varyantlarının brute forcing işlemi).
- `stegsolve`: manuel visual filters (channel isolation, plane inspection, XOR vb.).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT, LSB extraction değildir; içeriğin frequency space içinde kasıtlı olarak gizlendiği veya subtle patterns kullanıldığı durumlar içindir.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF'lerde sıklıkla kullanılan Web-based triage:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG, chunk tabanlı bir formattır. Birçok challenge'da payload, pixel values yerine container/chunk seviyesinde saklanır:

- **`IEND` sonrasındaki Extra bytes** (birçok viewer trailing bytes'ları yok sayar)
- **Payload taşıyan Non-standard ancillary chunks**
- **Boyutları gizleyen veya düzeltilene kadar parser'ları bozan Corrupted headers**

İncelenmesi gereken high-signal chunk locations:

- `tEXt` / `iTXt` / `zTXt` (text metadata, bazen compressed)
- `iCCP` (ICC profile) ve carrier olarak kullanılan diğer ancillary chunks
- `eXIf` (PNG içindeki EXIF data)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Bakılacaklar:

- Tuhaf width/height/bit-depth/colour-type kombinasyonları
- CRC/chunk hataları (`pngcheck` genellikle tam offset'i gösterir)
- `IEND` sonrasında ek data olduğuna dair uyarılar

Daha ayrıntılı bir chunk görünümüne ihtiyacınız varsa:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Faydalı referanslar:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Teknik

JPEG, ham pikseller olarak depolanmaz; DCT domain'inde sıkıştırılır. JPEG stego araçlarının PNG LSB araçlarından farklı olmasının nedeni budur:

- Metadata/comment payload'ları dosya seviyesindedir (yüksek sinyalli ve hızlı incelenir)
- DCT-domain stego araçları, bit'leri frekans katsayılarına gömer

Operasyonel olarak JPEG'i şu şekilde değerlendirin:

- Metadata segment'leri için bir container (yüksek sinyalli, hızlı incelenir)
- Uzman stego araçlarının çalıştığı sıkıştırılmış bir sinyal domain'i (DCT katsayıları)

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

Özellikle JPEG dosyalarındaki steghide payload'larıyla karşılaşıyorsanız `stegseek` kullanmayı değerlendirin (eski script'lerden daha hızlı bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA, farklı yeniden sıkıştırma artefact'larını vurgular; düzenlenmiş bölgeleri belirlemenize yardımcı olabilir, ancak tek başına bir stego detector değildir:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animasyonlu görseller

### Teknik

Animasyonlu görseller için mesajın şunlardan biri olduğunu varsayın:

- Tek bir frame içinde (kolay), veya
- Frame'ler arasına dağıtılmış (sıralama önemlidir), veya
- Yalnızca ardışık frame'ler arasında diff yaptığınızda görünür

### Frame'leri çıkarma
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Ardından kareleri normal PNG'ler gibi ele alın: `zsteg`, `pngcheck`, kanal izolasyonu.

Alternatif araçlar:

- Hızlı kare çıkarma için `gifsicle --explode anim.gif`
- Kare başına dönüşümler için `imagemagick`/`magick`

Kare farklandırma genellikle belirleyicidir:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- APNG container'larını tespit edin: `exiftool -a -G1 file.png | grep -i animation` veya `file`.
- Yeniden zamanlama yapmadan frame'leri çıkarın: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Frame başına pixel sayıları olarak encode edilmiş payload'ları kurtarın:
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
Animasyonlu challenge'lar, her frame'deki belirli bir rengin sayısını bir byte olarak kodlayabilir; bu sayıların birleştirilmesi mesajı yeniden oluşturur.<sup>[[1]](#references)</sup>

## Parola korumalı embedding

Pixel-level manipulation yerine passphrase ile korunan bir embedding'den şüpheleniyorsanız, bu genellikle en hızlı yoldur.

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
Depo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV formatlarını destekler.

Depo: https://github.com/dhsdshdhk/stegpy

## Referanslar

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
