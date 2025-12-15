# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Çoğu CTF image stego şu kategorilerden birine düşer:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Hızlı triaj

Derin içerik analizinden önce container-level delillerini önceliklendirin:

- Dosyayı doğrulayın ve yapısını inceleyin: `file`, `magick identify -verbose`, format doğrulayıcıları (örn., `pngcheck`).
- Metadata ve görünen stringleri çıkarın: `exiftool -a -u -g1`, `strings`.
- Gömülü/eklenmiş içerik için kontrol edin: `binwalk` ve dosya sonu incelemesi (`tail | xxd`).
- Container türüne göre dallanın:
- PNG/BMP: bit-planes/LSB and chunk-level anomalies.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Teknik

PNG/BMP CTF'lerde popülerdir çünkü pikselleri **bit-level manipulation**'ı kolaylaştıracak şekilde depolar. Klasik gizleme/çıkarma mekanizması şudur:

- Her piksel kanalı (R/G/B/A) birden fazla bit içerir.
- Her kanalın **least significant bit** (LSB) görüntüyü çok az değiştirir.
- Saldırganlar veriyi bu düşük öncelikli bitlere gizler; bazen bir stride, permutasyon veya kanal başına seçim kullanılır.

Challenge'larda beklenenler:

- Payload sadece tek bir kanalda bulunur (örn., `R` LSB).
- Payload alpha channel'dadır.
- Çıkarım sonrası payload sıkıştırılmış/encoded olabilir.
- Mesaj plane'ler arasında yayılmıştır veya plane'ler arasındaki XOR ile gizlenmiştir.

Karşılaşabileceğiniz ek varyantlar (uygulamaya bağlı):

- **LSB matching** (sadece biti çevirmek değil, hedef biti eşleştirmek için +/-1 ayarlamaları)
- **Palette/index-based hiding** (indexed PNG/GIF: payload renk indekslerinde, ham RGB yerine)
- **Alpha-only payloads** (RGB görünümünde tamamen görünmez)

### Araçlar

#### zsteg

`zsteg` PNG/BMP için birçok LSB/bit-plane çıkarma desenini listeler:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: bir dizi dönüşüm çalıştırır (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: manuel görsel filtreler (channel isolation, plane inspection, XOR, vb).

Stegsolve indirme: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT, LSB çıkarımı değildir; içeriğin kasıtlı olarak frekans alanında veya ince desenlerde gizlendiği durumlar içindir.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF'lerde sıkça kullanılan web tabanlı triage araçları:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG, chunk tabanlı bir formattır. Birçok challenge'de payload piksel değerleri yerine container/chunk düzeyinde saklanır:

- **Extra bytes after `IEND`** (birçok görüntüleyici sondaki baytları yoksayar)
- **Non-standard ancillary chunks** payload taşıyabilir
- **Corrupted headers** boyutları gizleyebilir veya parser'ları düzeltilene kadar bozabilir

İncelenmesi gereken yüksek öncelikli chunk konumları:

- `tEXt` / `iTXt` / `zTXt` (text metadata, bazen sıkıştırılmış)
- `iCCP` (ICC profile) ve diğer ancillary chunk'lar taşıyıcı olarak kullanılabilir
- `eXIf` (PNG içindeki EXIF verisi)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Nelere bakmalı:

- Garip genişlik/yükseklik/bit-derinliği/renk-tipi kombinasyonları
- CRC/chunk hataları (pngcheck genellikle tam offset'i gösterir)
- `IEND` sonrasındaki ek veriler hakkında uyarılar

Daha ayrıntılı bir chunk görünümüne ihtiyacınız varsa:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Faydalı referanslar:

- PNG spesifikasyonu (structure, chunks): https://www.w3.org/TR/PNG/
- Dosya formatı hileleri (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Teknik

JPEG ham piksel olarak depolanmaz; DCT domain'ünde sıkıştırılır. Bu yüzden JPEG stego araçları PNG LSB araçlarından farklıdır:

- Metadata/yorum payload'ları dosya düzeyindedir (yüksek sinyal ve hızlı incelenir)
- DCT-domain stego araçları bitleri frekans katsayılarına gömer

Operasyonel olarak, JPEG'i şu şekilde ele alın:

- Metadata segmentleri için bir konteyner (yüksek sinyal, hızlı incelenir)
- Uzmanlaşmış stego araçlarının çalıştığı sıkıştırılmış bir sinyal alanı (DCT katsayıları)

### Hızlı kontroller
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Yüksek sinyal konumları:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Yaygın araçlar

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

JPEG'lerde özellikle steghide payloads ile karşılaşıyorsanız, `stegseek` kullanmayı düşünebilirsiniz (eski scriptslere göre daha hızlı bir bruteforce):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA farklı recompression artifacts'ları vurgular; düzenlenmiş bölgelere işaret edebilir, ancak tek başına bir stego detector değildir:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Animasyonlu görüntüler

### Teknik

Animasyonlu görüntüler için mesajın şu şekillerde olduğunu varsayın:

- Tek bir karede (kolay), veya
- Kareler arasında yayılmış (sıralama önemli), veya
- Sadece ardışık kareleri difflediğinizde görünen

### Kareleri çıkarma
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Sonra frame'leri normal PNG'ler gibi ele al: `zsteg`, `pngcheck`, channel isolation.

Alternatif araçlar:

- `gifsicle --explode anim.gif` (hızlı kare çıkarımı)
- `imagemagick`/`magick` - her kare için dönüşümler

Kare farklandırma genellikle belirleyicidir:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Parola korumalı embedding

Eğer embedding'in pixel-level manipulation yerine bir passphrase ile korunduğundan şüpheleniyorsanız, bu genellikle en hızlı yol olur.

### steghide

`JPEG, BMP, WAV, AU`'yi destekler ve şifrelenmiş payloadları embed/extract edebilir.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to external URLs or repositories. Please paste the contents of src/stego/images/README.md here (including any markdown/code blocks and links). I will translate the English text to Turkish while preserving all markdown/html tags, paths, refs and code exactly as requested.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

PNG/BMP/GIF/WebP/WAV dosyalarını destekler.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
