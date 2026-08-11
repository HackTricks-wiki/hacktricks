# PNG Hileleri

{{#include ../../../banners/hacktricks-training.md}}

**PNG dosyaları**, **CTF'lerde**, **olay müdahalesinde** ve **malware staging** işlemlerinde çok yaygındır; çünkü **kayıpsızdır**, **chunk tabanlıdır** ve birçok araç, içinde **ek metadata**, **sonuna eklenmiş payload'lar** veya **kısmen bozulmuş chunk'lar** olsa bile bunları sorunsuzca görüntüler.

Bir PNG'yi yalnızca görüntü olarak değil, bir **container** olarak değerlendirin.

## Hızlı triage

LSB stego analizine geçmeden önce container düzeyinde kontrollerle başlayın. Bit-plane/LSB iş akışı için [özel image stego sayfasına](../../../stego/images/README.md) bakın.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Aranacak yararlı şeyler:

- `tEXt`, `zTXt`, `iTXt`, `eXIf` veya `iCCP` gibi **beklenmeyen yardımcı chunk'lar**
- **CRC hataları** veya hatalı chunk uzunlukları
- `IEND` sonrasında **ek veriler**
- **Birden fazla `IEND` işaretçisi** veya dosyanın resmi sonundan sonra kurtarılabilir `IDAT` parçaları
- Geçerli bir PNG olan ve aynı zamanda carve edildiğinde ZIP/PDF/script gibi görünen bir dosya

Minimum geçerli yapı genellikle şöyledir:

- `IHDR` (ilk olmalıdır)
- `IDAT` (bir veya daha fazla ardışık chunk)
- `IEND` (son olmalıdır)

## `IEND` sonrasında trailing data

En yüksek sinyale sahip PNG artefact'larından biri, **son `IEND` chunk'ından sonra eklenen verilerdir**. Birçok decoder bu verileri yok sayar; bu da onları şu amaçlar için kullanışlı hâle getirir:

- **Basit stego / gizli payload'lar**
- **PNG polyglot'ları**
- **Malware staging**
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
Son `IEND` sonrasındaki her şeyi carve etmek istiyorsanız:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Ayrıca genel arşiv parser'larını doğrudan PNG'ye veya carve edilmiş trailer'a karşı deneyin:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Kırpılmış/gizlenmiş ekran görüntülerinin Acropalypse tarzı kurtarılması

Çok pratik ve güncel bir PNG forensic tekniği, bir screenshot editor'ün eski dosyayı önce **truncating** yapmadan bir PNG'nin üzerine yazıp yazmadığını kontrol etmektir. Bu durumlarda, **previous image**'a ait byte'lar `IEND` sonrasında kalabilir ve bazen ek `IDAT` verileri kısmen yeniden oluşturulabilir.

Bu durum **aCropalypse** (Google Pixel Markup) ve ilgili **Windows Snipping Tool** sorunuyla bilinir hâle geldi.<sup>[[3]](#references)</sup> Pratikte, "kırpılmış" veya "gizlenmiş" bir PNG hâlâ eski trailing data içeriyorsa, original screenshot'ın bir bölümünü kurtarmanız mümkün olabilir.<sup>[[1]](#references)</sup>

Pratik iş akışı:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Derinlemesine analizi güçlü biçimde gerektiren işaretler:

- `pngcheck`, **`IEND` sonrasında ek veri** bildiriyor
- **Birden fazla `IEND`** buluyorsunuz
- Görüntünün görünürdeki sonundan sonra **ek `IDAT` chunk'ları** buluyorsunuz
- Ekran görüntüsü, etkilenmiş olduğu bilinen bir cihazdan/editörden alınmış

Bu durum gerçekleşirse, redaction'a güvenilir kabul etmeden önce dosyayı bir **aCropalypse recovery tool** ile işleyin.

## Pratikte önem taşıyan chunk abuse

İncelemeler için en ilginç PNG chunk'ları genellikle bariz görüntü chunk'ları değil; **metin**, **metadata** veya **payload bytes** taşıyabilen chunk'lardır:

- `tEXt` / `zTXt` / `iTXt` – metin metadata'sı ve sıkıştırılmış metin
- `eXIf` – PNG içinde EXIF verisi
- `iCCP` – gömülü ICC profile
- `PLTE` – indexed images içindeki palette data; ayrıca payload-smuggling senaryolarında da kullanışlıdır.<sup>[[2]](#references)</sup>

Şunları kullanarak dump edin:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunk’ları içinde offensive payload persistence için (örneğin bazı PHP image transformations işlemlerinden kurtulan **PLTE**, **IDAT** veya **tEXt** tricks), upload odaklı daha ayrıntılı notlara buradan bakın:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Bozulmuş PNG onarımı

Integrity kontrolü yapmak ve tam olarak bozuk bölgeyi bulmak için **pngcheck**, hâlâ kullanılabilecek en iyi ilk araçlardan biridir:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Dosya kasıtlı olarak malicious değil de hasarlıysa **PCRT**, CTF’lerde ve lab çalışmalarında hatalı header’lar, yanlış IHDR değerleri, CRC sorunları veya hatalı chunk düzenleri gibi yaygın sorunları düzeltmek için yararlı olabilir.

Amacınız görünür görüntüyü korurken şüpheli trailer data içeren bir PNG’yi **sanitize** etmekse, ExifTool trailer’ı açıkça kaldırabilir:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Hassas kanıtlar için her zaman bir **kopya** üzerinde çalışın ve onarım işlemlerine başlamadan önce orijinalin hash değerlerini saklayın.

## References

- [1] [aCropalypse'i Exploiting: Kesilmiş PNG'leri Kurtarma](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG'lerde kalıcı PHP payload'ları: Bir görsele PHP kodu nasıl enjekte edilir ve orada tutulur](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
