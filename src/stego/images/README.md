# Görsel Steganografisi

{{#include ../../banners/hacktricks-training.md}}

Çoğu CTF görsel stego örneği şu kategorilerden birine girer:

- LSB/bit düzlemleri (PNG/BMP)
- Metadata/comment payload'ları
- PNG chunk anomalileri / bozulma onarımı
- JPEG DCT-domain araçları (OutGuess vb.)
- Kare tabanlı (GIF/APNG)

## Hızlı ön inceleme

Derin içerik analizinden önce container düzeyindeki kanıtlara öncelik verin. Dosya tanımlama ve carving işlemleri için görsele özgü testlerden önce [genel stego iş akışına](../workflow/) bakın.

- Dosyayı doğrulayın ve yapısını inceleyin: `file`, `magick identify -verbose`, format doğrulayıcıları (ör. `pngcheck`).
- Metadata'yı ve görünür dizeleri çıkarın: `exiftool -a -u -g1`, `strings`.
- Gömülü/sona eklenmiş içerik olup olmadığını kontrol edin: `binwalk` ve dosya sonunu inceleme (`tail | xxd`).
- Container türüne göre ilerleyin:
  - PNG/BMP: bit düzlemleri/LSB ve chunk düzeyinde anormallikler.
  - JPEG: metadata + DCT-domain araçları (OutGuess/F5 tarzı aileler).
  - GIF/APNG: kare çıkarma, kareler arasındaki farkları bulma, palette hileleri.

## Bit düzlemleri / LSB

### Teknik

PNG/BMP, pikselleri **bit düzeyinde manipülasyonu** kolaylaştıran bir şekilde sakladıkları için CTF'lerde popülerdir. Klasik gizleme/çıkarma mekanizması şöyledir:

- Her piksel kanalında (R/G/B/A) birden fazla bit bulunur.
- Her kanalın **en az anlamlı biti** (LSB), görseli çok az değiştirir.
- Saldırganlar verileri bu düşük anlamlı bitlerde, bazen bir adım aralığı, permütasyon veya kanal başına seçim kullanarak gizler.

Challenge'larda karşılaşabilecekleriniz:

- Payload yalnızca tek bir kanaldadır (ör. `R` LSB).
- Payload alpha kanalındadır.
- Payload çıkarıldıktan sonra sıkıştırılmış/kodlanmıştır.
- Mesaj bit düzlemlerine yayılmıştır veya düzlemler arasında XOR kullanılarak gizlenmiştir.

Karşılaşabileceğiniz ek aileler (uygulamaya bağlıdır):

- **LSB matching** (yalnızca biti değiştirmek yerine, hedef bite uyması için +/-1 ayarlamaları)
- **Palette/index tabanlı gizleme** (indeksli PNG/GIF: ham RGB yerine renk indekslerinde payload)
- **Yalnızca alpha kanalında payload** (RGB görünümünde tamamen görünmez)

### İndeksli renk paleti indeksleri

İndeksli bir PNG veya GIF, piksel başına RGB üçlüsü değil, bir palette **indeksi** saklar. İki indeks aynı görünür renge karşılık gelebilir; bu nedenle analizden önce RGB'ye dönüştürmek gizli ayrımı ortadan kaldırabilir. Yinelenen veya birbirine çok benzeyen palette girişlerini inceleyin, ardından şüpheli her indeksi kullanan piksellerin ikili maskesini oluşturun. Bu yöntem, yakın tarihli GIF challenge'larında gizli metinleri ve QR kodu değişikliklerini ortaya çıkardı.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Tek kareli indeksli bir PNG (veya GIF'in **ilk karesi**) için Pillow'un `P` modunu koruyun ve `target` değerini betiğin bildirdiği ilgi çekici bir indeksle değiştirin. İndeksleri seçerken RGB'nin yanı sıra saydamlığı da (`tRNS` veya GIF saydamlık indeksi) kontrol edin.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Animasyonlu GIF'lerde kareleri ayrı ayrı inceleyin. Pillow, birleştirme sırasında sonraki kareleri genellikle RGB/RGBA'ya dönüştürür; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` ise palet değişmediği sürece `P` modunu korur. Bir karede yerel palet varsa veya kare zaten birleştirilmişse, RGB'ye dönüştürülmüş pikselleri indeks olarak değerlendirmek yerine özgün indeksli kare verilerini inceleyin.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Araçlar

#### zsteg

`zsteg`, PNG/BMP için birçok LSB/bit düzlemi çıkarma desenini listeler:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: bir dizi dönüşüm uygular (metadata, görüntü dönüşümleri, LSB varyantlarını brute force ile deneme).
- `stegsolve`: manuel görsel filtreler (kanalları ayırma, bit düzlemlerini inceleme, XOR vb.).

Stegsolve indirme: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT tabanlı görünürlük hileleri

FFT, LSB çıkarımı değildir; içeriğin frekans uzayında kasıtlı olarak gizlendiği veya ince desenler kullanıldığı durumlar içindir.

- EPFL demosu: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

CTF'lerde sık kullanılan web tabanlı ilk inceleme araçları:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG iç yapısı: chunk'lar, bozulma ve gizli veriler

### Teknik

PNG, chunk'lara bölünmüş bir formattır. Birçok challenge'da payload, piksel değerleri yerine container/chunk düzeyinde saklanır:

- **`IEND` sonrasındaki fazladan baytlar** (birçok görüntüleyici sondaki baytları yok sayar)
- **Payload taşıyan standart dışı ancillary chunk'lar**; bkz. [PNG chunk inceleme ve veri ayıklama iş akışı](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- Boyutları gizleyen veya düzeltilene kadar parser'ları bozan **bozuk header'lar**

İncelenmesi gereken, yüksek sinyal taşıyan chunk konumları:

- `tEXt` / `iTXt` / `zTXt` (metin metadata'sı, bazen sıkıştırılmış)
- Taşıyıcı olarak kullanılan `iCCP` (ICC profili) ve diğer ancillary chunk'lar
- `eXIf` (PNG'deki EXIF verisi)

### Taşıyıcı olarak PNG tarama satırı filtre baytları

PNG, sıkıştırması açılmış `IDAT` akışında her tarama satırından önce bir filtre türü baytı (0–4) saklar. Bu baytlar piksel değerleri değildir; çözümlenen RGB pikselleri orijinal filtre seçimlerini korumaz ve yeniden kodlama bunları değiştirebilir. Bir encoder filtreleri geçerli şekilde farklı seçebilir, ancak kasıtlı desenler küçük bir mesaj kodlayabilir; yakın tarihli bir challenge'da 1–4 filtre değerleri iki bitlik semboller olarak kullanılmıştı. **Orijinal dosyayı** inceleyin ve sıkıştırmayı açmadan önce tüm `IDAT` verilerini birleştirin. Aşağıdaki, interlace kullanılmayan 8 bit RGB/RGBA durumu için stride, genişlik ile kanal sayısının çarpımına eşittir; Adam7 görüntüleri geçişe özgü tarama satırı genişlikleri gerektirir.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Yeniden kodlamadan PNG tarama satırı filtre baytlarını listeleme</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Şu şekilde çalıştırın: `python3 filters.py suspect.png`. Çözümlenmiş piksellerin değil, filtre dizisinin makul bir sembol eşlemesini izleyip izlemediğini kontrol edin. Eşleme seçimi challenge'a özgüdür; tek başına farklılık olması steganografi kanıtı değildir.<sup>[[3]](#references)[[7]](#references)</sup>

### Ön inceleme komutları

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Nelere dikkat etmeli:

- Tuhaf genişlik/yükseklik/bit derinliği/renk türü kombinasyonları
- CRC/chunk hataları (pngcheck genellikle tam offset'i gösterir)
- `IEND` sonrasında ek veri olduğuna dair uyarılar

Daha ayrıntılı bir chunk görünümüne ihtiyacınız varsa:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Faydalı referanslar:

- PNG specification (yapı, parçalar): https://www.w3.org/TR/PNG/
- Dosya biçimi püf noktaları (PNG/JPEG/GIF uç durumları): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain araçları ve ELA sınırlamaları

### Teknik

JPEG, ham pikseller olarak saklanmaz; DCT alanında sıkıştırılır. Bu nedenle JPEG stego araçları PNG LSB araçlarından farklıdır:

- Metadata/yorum payload'ları dosya düzeyindedir (yüksek sinyalli ve hızlıca incelenebilir)
- DCT-domain stego araçları bitleri frekans katsayılarına gömer

Operasyonel olarak JPEG'i şöyle ele alın:

- Metadata segmentleri içeren bir kapsayıcı (yüksek sinyalli, hızlıca incelenebilir)
- Uzmanlaşmış stego araçlarının çalıştığı sıkıştırılmış bir sinyal alanı (DCT katsayıları)

### Hızlı kontroller

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Yüksek sinyalli konumlar:

- EXIF/XMP/IPTC metadata
- JPEG comment segmenti (`COM`)
- Application segmentleri (EXIF için `APP1`, üretici verileri için `APPn`)

### Yaygın araçlar

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Özellikle JPEG'lerde steghide payload'larıyla karşılaşıyorsanız `stegseek` kullanmayı düşünebilirsiniz (eski script'lerden daha hızlı bruteforce):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA, farklı yeniden sıkıştırma artifact'lerini vurgular; düzenlenmiş bölgeleri tespit etmenize yardımcı olabilir ancak tek başına bir stego detector değildir:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animasyonlu görseller

### Teknik

Animasyonlu görsellerde mesajın şunlardan biri olduğunu varsayın:

- Tek bir frame'de (kolay), veya
- Frame'lere dağıtılmış (sıralama önemlidir), veya
- Yalnızca ardışık frame'ler karşılaştırıldığında görünür

### Frame'leri çıkarın

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Ardından kareleri normal PNG'ler gibi ele alın: `zsteg`, `pngcheck`, kanal izolasyonu.

Alternatif araçlar:

- `gifsicle --explode anim.gif` (kareleri hızlıca çıkarma)
- Kare başına dönüşümler için `imagemagick`/`magick`

Kare farkı analizi genellikle belirleyicidir:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG pixel-count encoding

- APNG container'larını tespit edin: `exiftool -a -G1 file.png | grep -i animation` veya `file`.
- Zamanlamayı değiştirmeden frame'leri çıkarın: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Frame başına pixel count olarak kodlanmış payload'ları kurtarın:

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

Animasyonlu challenge'lar, her byte'ı her karedeki belirli bir rengin sayısıyla kodlayabilir; sayıları birleştirmek mesajı yeniden oluşturur.<sup>[[1]](#references)</sup>

## Parola korumalı gömme

Piksel düzeyinde manipülasyon yerine passphrase ile korunan bir gömme işleminden şüpheleniyorsanız, bu genellikle en hızlı yoldur.

### steghide

`JPEG, BMP, WAV, AU` formatlarını destekler ve şifrelenmiş payload'ları gömebilir/çıkarabilir.

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

PNG/BMP/GIF/WebP/WAV formatlarını destekler.

Repo: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’nın İstek Listesi, Noel Metadata’sı, Yakalanan Gürültü](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024 çözüm yazısı — Bükülmüş Renkler](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Taşınabilir Ağ Grafikleri (PNG) Belirtimi, Üçüncü Baskı](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Derinlerde, Suda Bir Şey Var](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Pillow görsel dosyası biçimleri — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [GIF89a belirtimi](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Afterimage Protocol — CTF çözüm yazısı](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
