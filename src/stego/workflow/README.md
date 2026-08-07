# Stego İş Akışı

{{#include ../../banners/hacktricks-training.md}}

Çoğu stego problemi, rastgele araçlar denemek yerine sistematik triage ile daha hızlı çözülür.

## Temel akış

### Hızlı triage kontrol listesi

Amaç, iki soruyu verimli şekilde yanıtlamaktır:

1. Gerçek container/format nedir?
2. Payload metadata'da, eklenmiş byte'larda, gömülü dosyalarda veya content-level stego'da mı?

#### 1) Container'ı belirleyin
```bash
file target
ls -lah target
```
`file` ve uzantı birbiriyle uyuşmuyorsa `file` komutuna güvenin. Uygun olduğunda yaygın formatları container olarak değerlendirin (ör. OOXML belgeleri ZIP dosyalarıdır).

#### 2) Metadata ve bariz string'leri arayın
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Birden fazla encoding deneyin:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Sona eklenmiş verileri / gömülü dosyaları kontrol edin
```bash
binwalk target
binwalk -e target
```
Çıkarma başarısız olur ancak imzalar raporlanırsa offset'leri `dd` ile manuel olarak carve edin ve carve edilen bölge üzerinde `file` komutunu yeniden çalıştırın.

#### 4) Görüntü ise

- Anomalileri inceleyin: `magick identify -verbose file`
- PNG/BMP ise bit-plane/LSB'leri enumerate edin: `zsteg -a file.png`
- PNG yapısını doğrulayın: `pngcheck -v file.png`
- İçerik channel/plane dönüşümleriyle ortaya çıkabilecekse görsel filtreler (Stegsolve / StegoVeritas) kullanın

#### 5) Ses ise

- Önce spectrogram oluşturun (Sonic Visualiser)
- Stream'leri decode/inceleyin: `ffmpeg -v info -i file -f null -`
- Ses yapılandırılmış tonlara benziyorsa DTMF decoding'i test edin

### Temel araçlar

Bunlar yüksek sıklıkta karşılaşılan container-level durumları yakalar: metadata payload'ları, sona eklenmiş byte'lar ve uzantısıyla gizlenmiş embedded file'lar.<sup>[[1]](#references)</sup>

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
Repo: https://github.com/korczis/foremost

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### dosya / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Konteynerler, eklenmiş veriler ve polyglot teknikleri

Birçok steganography challenge'ı, geçerli bir dosyanın sonuna eklenmiş ekstra byte'lardan veya uzantıyla gizlenmiş embedded archive'lar içerir.

#### Eklenmiş payload'lar

Birçok format sondaki byte'ları yok sayar. Bir ZIP/PDF/script, bir image/audio container'ının sonuna eklenebilir.

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

`file` kafası karıştığında, `xxd` ile magic bytes değerlerini arayın ve bilinen signature'larla karşılaştırın:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Uzantı zip olduğunu belirtmese bile `7z` ve `unzip` kullanmayı deneyin:
```bash
7z l file
unzip -l file
```
### Near-stego oddities

stego ile bitişik olarak düzenli şekilde ortaya çıkan pattern'ler için hızlı bağlantılar (binary'den QR, braille vb.).

#### QR codes from binary

Bir blob uzunluğu perfect square ise, bu değer bir image/QR için raw pixel'lar olabilir.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Referanslar

- [1] [DominicBreuker/stego-toolkit - En popüler steganography araçlarının bir arada bulunduğu Docker image](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
