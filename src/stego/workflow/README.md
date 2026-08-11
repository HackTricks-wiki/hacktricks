# Stego İş Akışı

{{#include ../../banners/hacktricks-training.md}}

Çoğu stego problemi, rastgele araçlar denemek yerine sistematik triage ile daha hızlı çözülür.

## Temel akış

### Hızlı triage kontrol listesi

Amaç, iki soruyu verimli bir şekilde yanıtlamaktır:

1. Gerçek container/format nedir?
2. Payload metadata'da mı, eklenmiş byte'larda mı, gömülü dosyalarda mı yoksa içerik düzeyinde stego olarak mı bulunuyor?

#### 1) Container'ı belirleyin
```bash
file target
ls -lah target
```
`file` ve uzantı uyuşmuyorsa soneke güvenmek yerine imzayı inceleyin. `file` de sezgiseldir ve hatalı biçimlendirilmiş veya polyglot girdiler nedeniyle yanıltılabilir. Uygun olduğunda yaygın formatları container olarak değerlendirin (örneğin, OOXML belgeleri ZIP paketleridir).<sup>[[2]](#references)</sup>

#### 2) Metadata ve belirgin string'leri arayın
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
#### 3) Eklenmiş verileri / gömülü dosyaları kontrol edin
```bash
binwalk target
binwalk -e target
```
Çıkarma başarısız olur ancak imzalar raporlanırsa, `dd` ile offset'leri manuel olarak carve edin ve carve edilen bölge üzerinde `file` komutunu yeniden çalıştırın.

#### 4) Görüntü ise

- Anomalileri inceleyin: `magick identify -verbose file`
- PNG/BMP ise bit düzlemlerini/LSB'yi listeleyin: `zsteg -a file.png`
- PNG yapısını doğrulayın: `pngcheck -v file.png`
- İçerik kanal/düzlem dönüşümleriyle ortaya çıkabilecekse görsel filtreleri (Stegsolve / StegoVeritas) kullanın

#### 5) Ses ise

- Önce spektrogramı inceleyin (Sonic Visualiser)
- Akışları decode edin/inceleyin: `ffmpeg -v info -i file -f null -`
- Ses yapılandırılmış tonlara benziyorsa DTMF decoding'i test edin

### Temel araçlar

Bunlar yüksek sıklıkta görülen container-level durumlarını yakalar: metadata payload'ları, eklenmiş byte'lar ve uzantı aracılığıyla gizlenmiş embedded file'lar.<sup>[[1]](#references)[[3]](#references)</sup>

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
Proje deposu: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
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
### Container'lar, eklenen veriler ve polyglot teknikleri

Birçok steganography challenge'ı, geçerli bir dosyadan sonra gelen ek byte'lar veya uzantı değiştirilerek gizlenmiş embedded archive'lar içerir.

#### Eklenen payload'lar

Birçok format, sondaki byte'ları yok sayar. Bir ZIP/PDF/script, bir image/audio container'ına eklenebilir.

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

`file` kararsız kaldığında, `xxd` ile magic bytes değerlerini arayın ve bilinen signature'larla karşılaştırın:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Uzantısı zip olduğunu belirtmese bile `7z` ve `unzip` komutlarını deneyin:
```bash
7z l file
unzip -l file
```
### Yakın stego tuhaflıkları

Stego'nun yakınında düzenli olarak görülen pattern'ler için hızlı bağlantılar (QR-from-binary, braille vb.).

#### Binary'den QR kodları

Bir blob uzunluğu tam kareyse bu, bir görüntü/QR için ham pikseller olabilir.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - En popüler steganography araçlarını bir araya getiren Docker image](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binary Image](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille Translator](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
