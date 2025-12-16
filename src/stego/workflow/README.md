# Stego İş Akışı

{{#include ../../banners/hacktricks-training.md}}

Çoğu stego problemi rastgele araçlar denemektense sistematik triage ile daha hızlı çözülür.

## Temel akış

### Hızlı triage kontrol listesi

Amaç, iki soruyu verimli şekilde cevaplamaktır:

1. Gerçek container/format nedir?
2. Payload metadata'da mı, appended bytes içinde mi, embedded files içinde mi yoksa content-level stego içinde mi?

#### 1) Container/format'ı belirleyin
```bash
file target
ls -lah target
```
Eğer `file` ile uzantı uyuşmuyorsa, `file`'a güven. Uygunsa yaygın formatları kapsayıcı olarak ele alın (e.g., OOXML documents are ZIP files).

#### 2) metadata ve bariz strings'e bakın
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Birden fazla kodlama deneyin:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Eklenmiş veriler / gömülü dosyalar için kontrol edin
```bash
binwalk target
binwalk -e target
```
If extraction başarısız olursa ama imzalar rapor ediliyorsa, offsetleri elle `dd` ile carve edin ve carve edilmiş bölge üzerinde `file`'ı yeniden çalıştırın.

#### 4) Eğer görüntü ise

- Anomalileri inceleyin: `magick identify -verbose file`
- PNG/BMP ise, bit-düzlemleri/LSB'leri listeleyin: `zsteg -a file.png`
- PNG yapısını doğrulayın: `pngcheck -v file.png`
- İçerik kanal/düzlem dönüşümleriyle ortaya çıkabiliyorsa görsel filtreler kullanın (Stegsolve / StegoVeritas)

#### 5) Eğer ses ise

- Önce spektrograma bakın (Sonic Visualiser)
- Akışları dekode/inceleyin: `ffmpeg -v info -i file -f null -`
- Ses yapısal tonlara benziyorsa, DTMF dekodlamasını test edin

### Temel araçlar

Bunlar container-seviyesi sık karşılaşılan durumları yakalar: metadata payload'lar, eklenmiş byte'lar ve uzantıyla gizlenmiş embedded dosyalar.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have access to the repository files. Please paste the contents of src/stego/workflow/README.md here (or the part you want translated). I will translate the English text to Turkish while keeping all markdown, tags, links, code, paths and specified tokens unchanged.
```bash
foremost -i file
```
src/stego/workflow/README.md dosyasının içeriğini gönderir misiniz? Verilen içerik olmadan çeviri yapamam.
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
### Kapsayıcılar, eklenmiş veriler ve polyglot tricks

Birçok steganografi görevi, geçerli bir dosyadan sonra gelen ek baytlardır veya uzantıyla gizlenen gömülü arşivlerdir.

#### Eklenmiş payload'lar

Birçok format sonundaki baytları yok sayar. Bir ZIP/PDF/script bir image/audio container'ın sonuna eklenebilir.

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

`file` kararsız kaldığında, `xxd` ile magic bytes'ları kontrol edin ve bilinen imzalarla karşılaştırın:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Uzantı zip demese bile `7z` ve `unzip`'i dene:
```bash
7z l file
unzip -l file
```
### Near-stego tuhaflıkları

Stego'ya bitişik olarak sıkça ortaya çıkan desenler için hızlı bağlantılar (QR-from-binary, braille, etc).

#### QR codes from binary

Eğer bir blob uzunluğu tam kare ise, image/QR için raw pixels olabilir.
```python
import math
math.isqrt(2500)  # 50
```
- Binary-to-image yardımcı aracı:
- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Referans listeleri

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
