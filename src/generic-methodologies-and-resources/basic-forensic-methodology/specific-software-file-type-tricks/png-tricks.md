# PNG Püf Noktaları

{{#include ../../../banners/hacktricks-training.md}}

**PNG dosyaları**, **kayıpsız**, **chunk tabanlı** oldukları ve birçok araç **ek metadata**, **eklenmiş payload'lar** veya **kısmen bozulmuş chunk'lar** içerseler bile bunları sorunsuzca görüntüleyebildiği için **CTF'lerde**, **olay müdahalesinde** ve **malware staging** işlemlerinde çok yaygındır.

PNG'yi yalnızca bir görüntü olarak değil, bir **container** olarak ele alın.

## Hızlı inceleme

LSB stego'ya geçmeden önce container düzeyindeki kontrollerle başlayın. Bit düzlemi/LSB iş akışı için [özel görüntü steganografisi sayfasına](../../../stego/images/) bakın.

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Kontrol edilmesi gerekenler:

- `tEXt`, `zTXt`, `iTXt`, `eXIf` veya `iCCP` gibi **beklenmeyen yardımcı chunk'lar**
- **CRC hataları** veya hatalı chunk uzunlukları
- `IEND` sonrasındaki **ek veriler**
- **Birden fazla `IEND` işaretçisi** veya dosyanın resmî sonundan sonra kurtarılabilir `IDAT` parçaları
- Geçerli bir PNG olan **ve** carve edildiğinde ZIP/PDF/script gibi görünen bir dosya

Minimum geçerli yapının genellikle şu şekilde olduğunu unutmayın:

- `IHDR` (ilk sırada olmalı)
- `IDAT` (bir veya daha fazla ardışık chunk)
- `IEND` (son sırada olmalı)

## `IEND` sonrasındaki veriler

En belirgin PNG artefaktlarından biri, **son `IEND` chunk'ından sonra eklenmiş verilerdir**. Birçok decoder bu verileri yok sayar; bu da onları şu amaçlar için kullanışlı kılar:

- **Basit stego / gizli payload'lar**
- **PNG polyglot'ları**
- **Malware hazırlama**
- Hatalı editörlerden **eski görüntü verilerini kurtarma**

Hızlı tespit:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

`IEND` için bayt araması yalnızca bir ipucudur: aynı baytlar parça verisinde veya sahte bir sondan eklenmiş veride bulunabilir. Güvenilir biçimde veri çıkarmak için PNG imzasından başlayarak uzunluk önekli parçaları sırayla inceleyin ve yapısal `IEND` parçasında durun; [aşağıdaki parça gezgini](#extract-ancillary-chunk-payloads) sondan eklenmiş veriyi de kaydeder.<sup>[[6]](#references)</sup>

Genel arşiv ayrıştırıcılarını doğrudan PNG dosyası veya çıkarılan sondan eklenmiş veri üzerinde de deneyin:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Kırpılmış/karartılmış ekran görüntülerinin Acropalypse tarzı kurtarılması

Yakın zamanda ortaya çıkan oldukça kullanışlı bir PNG adli inceleme tekniği, ekran görüntüsü düzenleyicisinin eski dosyayı önce **kesmeden** PNG dosyasının üzerine **yazıp yazmadığını** kontrol etmektir. Böyle durumlarda, **önceki görüntüye** ait baytlar `IEND` sonrasında kalabilir ve bazen ek `IDAT` verileri kısmen yeniden oluşturulabilir.

Bu sorun, **aCropalypse** (Google Pixel Markup) ve ilgili **Windows Snipping Tool** sorunuyla tanınır hâle geldi.<sup>[[3]](#references)</sup> Uygulamada, "kırpılmış" veya "karartılmış" bir PNG hâlâ eski verileri içeriyorsa, özgün ekran görüntüsünün bir kısmını kurtarabilirsiniz.<sup>[[1]](#references)</sup>

Uygulamalı iş akışı:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Daha derin analiz gerektirdiğini güçlü biçimde gösteren işaretler:

- `pngcheck`, **`IEND` sonrasında ek veri** olduğunu bildiriyor
- **Birden fazla `IEND`** buluyorsunuz
- Görüntünün görünen bitişinden sonra **ek `IDAT` chunk’ları** buluyorsunuz
- Ekran görüntüsü, etkilendiği bilinen bir cihazdan/düzenleyiciden alınmış

Böyle bir durumda, redaksiyonu güvenilir kabul etmeden önce dosyayı bir **aCropalypse kurtarma aracına** verin.

## Pratikte önem taşıyan chunk kötüye kullanımları

Araştırmalarda en ilgi çekici PNG chunk’ları genellikle bariz görüntü chunk’ları değil, **metin**, **metadata** veya **payload baytları** taşıyabilen chunk’lardır:

- `tEXt` / `zTXt` / `iTXt` – metin metadata’sı ve sıkıştırılmış metin
- `eXIf` – PNG içindeki EXIF verisi
- `iCCP` – gömülü ICC profili
- `PLTE` – indeksli görüntülerde palet verisi; ayrıca payload gizleme senaryolarında da kullanışlıdır.<sup>[[2]](#references)</sup>

Bunları şu komutla dökebilirsiniz:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

PNG parçaları içinde saldırı amaçlı payload kalıcılığı için (örneğin bazı PHP görsel dönüşümlerinden sağ çıkabilen **PLTE**, **IDAT** veya **tEXt** hileleri), yüklemeye odaklanan daha ayrıntılı notlara buradan bakın:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Yardımcı parça payload'larını çıkarma

Bir saldırgan, `IEND` öncesindeki **bilinmeyen bir yardımcı parçaya** rastgele baytlar yerleştirebilir. Sıradan PNG kod çözücüler bilinmeyen bir yardımcı parçayı yok sayabilir; görüntüyü baytlar olarak alan bir betik ise payload'ı okuyup kullanabilir. PNG'yi tek başına açmak payload'ı çalıştırmaz.<sup>[[4]](#references)[[6]](#references)</sup> İlk araştırmada sıkıştırılmış ve şifrelenmiş özel bir parça gösterilmişti.<sup>[[4]](#references)</sup> Daha sonraki bir tarayıcı örneğinde çıkarılan baytlar HTML veya indirme sağlamak için kullanılmıştı.<sup>[[5]](#references)</sup>

İlk parça türü harfinin küçük olması, parçanın *yardımcı* olduğu anlamına gelir; ikinci harfin küçük olması ise *özel* olduğu anlamına gelir. Örneğin, `paMP` özeldir; `pAMP` ise gösterim için icat edilmiş olmasına rağmen genel ad alanını kullanır.<sup>[[4]](#references)[[6]](#references)</sup> Bir parçanın yapısı şöyledir: `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)`; CRC, türü ve veriyi kapsar. Sıkıştırılmış `IDAT` verisinin içinde tür adını aramak yerine bu yapıyı ayrıştırın. Aşağıdaki gezici, sınırları ve CRC'leri doğrular, yardımcı payload'ları ham baytlar olarak dışa aktarır ve yapısal `IEND` sonrasındaki baytları `png-trailer.bin` dosyasına yazar.<sup>[[6]](#references)</sup>

<details>
<summary>Yardımcı parçaları ve PNG son ekini çıkarma</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Carve edilmiş baytları `file`, `strings` veya `binwalk` ile inceleyin; yalnızca taşıyıcı gerçekten sıkıştırılmışsa açın.<sup>[[4]](#references)</sup> Yeniden kodlama taşıyıcıyı kaldırabilir; bu nedenle buna güvenmeden önce yüklenen ve geri alınan baytları karşılaştırın.<sup>[[2]](#references)[[6]](#references)</sup>

## Bozulmuş PNG onarımı

Bütünlüğü denetlemek ve bozuk alanın tam yerini belirlemek için **pngcheck** hâlâ ilk başvurulacak en iyi araçlardan biridir:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Dosya kasıtlı olarak kötü amaçlı değil de hasarlıysa **PCRT**, CTF’lerde ve laboratuvar çalışmalarında bozuk başlıklar, yanlış IHDR değerleri, CRC sorunları veya hatalı chunk düzenleri gibi yaygın sorunları düzeltmek için kullanışlı olabilir.

Amacınız görünür görüntüyü korurken şüpheli sondaki verileri içeren bir PNG’yi **sanitize** etmekse ExifTool, bu sondaki verileri açıkça kaldırabilir:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Hassas kanıtlarla çalışırken daima bir **kopya** üzerinde çalışın ve onarmayı denemeden önce orijinalin hash değerlerini alın.



## References

- [1] [aCropalypse Açığından Yararlanma: Kesilmiş PNG'leri Kurtarma](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG'lerde kalıcı PHP payload'ları: Bir görsele PHP kodu nasıl eklenir ve orada nasıl tutulur](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Yardımcı chunk'lar, hassas bilgileri saklamak için mükemmel bir yerdir](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Bir uç noktaya veri sızdırmak için geçerli yardımcı chunk'ları kullanma](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Portable Network Graphics (PNG) Specification (Third Edition)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
