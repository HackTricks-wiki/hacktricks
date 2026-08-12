# Stego İş Akışı

{{#include ../../banners/hacktricks-training.md}}

Çoğu stego problemi, rastgele araçlar denemek yerine sistematik triage ile daha hızlı çözülür.

## Temel akış

### Hızlı triage checklist

Amaç, iki soruyu verimli bir şekilde yanıtlamaktır:

1. Gerçek container/format nedir?
2. Payload metadata'da, eklenmiş byte'larda, gömülü dosyalarda mı yoksa content-level stego'da mı? 

#### 1) Container'ı belirle
```bash
file target
ls -lah target
```
`file` ve uzantı uyuşmuyorsa, soneke güvenmek yerine imzayı inceleyin. `file` ayrıca sezgiseldir ve hatalı biçimlendirilmiş veya polyglot girdiler tarafından yanıltılabilir. Uygun olduğunda yaygın formatları container olarak değerlendirin (örneğin, OOXML belgeleri ZIP paketleridir).<sup>[[2]](#references)</sup>

#### 2) Metadata ve belirgin string'leri arayın
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Birden fazla kodlamayı deneyin:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Eklenmiş verileri / gömülü dosyaları kontrol edin
```bash
binwalk target
binwalk -e target
```
Çıkarma başarısız olur ancak signature'lar bildirilirse, offset'leri `dd` ile manuel olarak carve edin ve carve edilen bölge üzerinde `file` komutunu yeniden çalıştırın.

#### 4) Görüntüyse

- Anomalileri inceleyin: `magick identify -verbose file`
- PNG/BMP ise bit-plane/LSB'leri listeleyin: `zsteg -a file.png`
- PNG yapısını doğrulayın: `pngcheck -v file.png`
- İçerik channel/plane dönüşümleriyle açığa çıkabilecekse görsel filtreler kullanın (Stegsolve / StegoVeritas)

#### 5) Audiyoysa

- Önce spectrogram oluşturun (Sonic Visualiser)
- Stream'leri decode edin/inceleyin: `ffmpeg -v info -i file -f null -`
- Audio yapılandırılmış tonlara benziyorsa DTMF decoding'i test edin

### Temel araçlar

Bunlar yüksek frekanslı container-level vakalarını yakalar: metadata payload'ları, sona eklenmiş byte'lar ve extension kullanılarak gizlenmiş embedded file'lar.<sup>[[1]](#references)[[3]](#references)</sup>

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
Çevrilecek metin sağlanmamış.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Container'lar, eklenmiş veriler ve polyglot teknikleri

Birçok steganografi challenge'ı, geçerli bir dosyadan sonra gelen ek byte'lar veya uzantı aracılığıyla gizlenmiş archive'lardır.

#### Eklenmiş payload'lar

Birçok format, sondaki byte'ları yok sayar. Bir ZIP/PDF/script, bir image/audio container'ının sonuna eklenebilir.

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

`file` confused olduğunda, `xxd` ile magic bytes arayın ve bilinen signature'larla karşılaştırın:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Uzantı zip olduğunu göstermese bile `7z` ve `unzip` kullanmayı deneyin:
```bash
7z l file
unzip -l file
```
### Stego'ya yakın tuhaflıklar

Stego'nun yanında düzenli olarak görülen örüntüler için hızlı bağlantılar (binary'den QR, braille vb.).

#### Binary'den QR kodları

Bir blob uzunluğu tam kareyse, bu bir görüntü/QR için ham pikseller olabilir.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator.<sup>[[6]](#references)</sup>

Steganography araçlarının ve tekniğe özel kaynakların daha kapsamlı koleksiyonları için bundled stego-toolkit'e ve 0xRick'in derlediği listeye bakın.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - En popüler steganography araçlarını bir arada sunan Docker image](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binary Image](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille Translator](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganography Resources](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
