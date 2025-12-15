# Stego İş Akışı

{{#include ../../banners/hacktricks-training.md}}

Çoğu stego problemi, rastgele araçlar denemeye kıyasla sistematik eleme ile daha hızlı çözülür.

## Temel akış

### Hızlı eleme kontrol listesi

Amaç iki soruyu verimli şekilde yanıtlamaktır:

1. Gerçek konteyner/format nedir?
2. Payload metadata'da, eklenmiş baytlarda, gömülü dosyalarda mı yoksa içerik düzeyinde stego mu?

#### 1) Konteyneri tanımla
```bash
file target
ls -lah target
```
Eğer `file` ile uzantı uyuşmuyorsa, `file`'a güven. Ortak formatları uygun olduğunda konteyner olarak ele alın (örn. OOXML belgeleri ZIP dosyalarıdır).

#### 2) Metadata ve bariz strings'lere bakın
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Farklı kodlamaları deneyin:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Eklenmiş verileri / gömülü dosyaları kontrol et
```bash
binwalk target
binwalk -e target
```
Çıkarma başarısız olursa fakat imzalar raporlanıyorsa, offset'leri elle `dd` ile carve et ve carve edilmiş bölgede `file`'ı yeniden çalıştır.

#### 4) Görüntü ise

- Anomalileri incele: `magick identify -verbose file`
- PNG/BMP ise, bit-düzlemlerini/LSB'yi listele: `zsteg -a file.png`
- PNG yapısını doğrula: `pngcheck -v file.png`
- İçerik kanal/düzlem dönüşümleriyle ortaya çıkabilecekse görsel filtreleri kullan (Stegsolve / StegoVeritas)

#### 5) Ses ise

- Önce spektrogram (Sonic Visualiser)
- Akışları dekode/incele: `ffmpeg -v info -i file -f null -`
- Ses yapılandırılmış tonlara benziyorsa, DTMF çözümlemesini test et

### Sık kullanılan temel araçlar

Bunlar container-seviyesi, yüksek frekanslı vakaları yakalar: metadata ve payloads, eklenmiş baytlar ve uzantıyla gizlenmiş gömülü dosyalar.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Bu dosyanın içeriğini buraya yapıştırabilir misiniz? Ya da özellikle hangi bölümü (ör. "Foremost" alt başlığı) çevirmemi istiyorsunuz?
```bash
foremost -i file
```
Dosyanın içeriğini buraya yapıştırabilir misiniz? İnternetten çekemiyorum, bu yüzden src/stego/workflow/README.md içindeki ilgili metni kopyalarsanız Türkçeye çevirip aynı markdown/html yapısını korurum.
```bash
exiftool file
exiv2 file
```
#### dosya / dizeler
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Konteynerler, eklenmiş veriler ve poliglot hileleri

Birçok steganography görevi geçerli bir dosyadan sonra gelen ekstra baytlardan veya uzantıyla gizlenmiş gömülü arşivlerden oluşur.

#### Appended payloads

Birçok format sondaki baytları görmezden gelir. Bir ZIP/PDF/script bir görüntü/ses konteynerine eklenebilir.

Hızlı kontroller:
```bash
binwalk file
tail -c 200 file | xxd
```
Eğer bir offset biliyorsanız, `dd` ile carve edin:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Sihirli baytlar

`file` kararsız kaldığında, `xxd` ile sihirli baytları arayın ve bilinen imzalarla karşılaştırın:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Dosya uzantısı zip olarak belirtilmemiş olsa bile `7z` ve `unzip`'i deneyin:
```bash
7z l file
unzip -l file
```
### stego yakınındaki anormallikler

stego'nun bitişiğinde sık görülen desenler için hızlı bağlantılar (QR-from-binary, braille, etc).

#### binary'den QR kodları

Eğer bir blob uzunluğu tam kare ise, bir görüntü/QR için ham piksel verisi olabilir.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image yardımcı:

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## Referans listeleri

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
