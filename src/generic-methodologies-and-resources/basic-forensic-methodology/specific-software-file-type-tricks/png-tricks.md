# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files**, **kayıpsız**, **chunk tabanlı** oldukları ve birçok aracın **extra metadata**, **appended payloads** veya **partially corrupted chunks** içerseler bile bunları sorunsuzca render etmesi nedeniyle **CTFs**, **incident response** ve **malware staging** süreçlerinde oldukça yaygındır.

Bir PNG'yi yalnızca bir görsel olarak değil, bir **container** olarak ele alın.

## Quick triage

LSB stego analizine geçmeden önce container seviyesindeki kontrollerle başlayın. Bit-plane/LSB workflow için [the dedicated image stego page](../../../stego/images/README.md) sayfasına bakın.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Aranabilecek faydalı şeyler:

- `tEXt`, `zTXt`, `iTXt`, `eXIf` veya `iCCP` gibi **beklenmeyen ancillary chunk'lar**
- **CRC hataları** veya hatalı chunk uzunlukları
- `IEND` sonrasında **ek veriler**
- **Birden fazla `IEND` işaretçisi** veya dosyanın resmi sonundan sonra kurtarılabilir `IDAT` parçaları
- Geçerli bir PNG olan ve aynı zamanda carve edildiğinde ZIP/PDF/script gibi görünen bir dosya

Minimum geçerli yapı genellikle şöyledir:

- `IHDR` (ilk olmalıdır)
- `IDAT` (bir veya daha fazla ardışık chunk)
- `IEND` (son olmalıdır)

## `IEND` sonrasında trailing data

En yüksek sinyalli PNG artefact'larından biri, son `IEND` chunk'ından **sonra eklenmiş verilerdir**. Birçok decoder bu verileri yok sayar; bu da onları şu amaçlar için kullanışlı hâle getirir:

- **Basit stego / gizli payload'lar**
- **PNG polyglot'ları**
- **Malware staging**
- Hatalı editor'lerden **eski image verilerini kurtarma**

Hızlı tespit:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Son `IEND` sonrasındaki her şeyi çıkarmak istiyorsanız:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Ayrıca genel arşiv parser'larını doğrudan PNG dosyası veya carve edilerek çıkarılan trailer üzerinde deneyin:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style kırpılmış/karartılmış ekran görüntülerinin kurtarılması

Son derece pratik ve güncel bir PNG forensic trick, bir screenshot editor'ün eski dosyayı önce **truncating** yapmadan bir PNG'nin üzerine **yazıp yazmadığını** kontrol etmektir. Bu durumlarda, **önceki image**'a ait byte'lar `IEND` sonrasında kalabilir ve bazen ek `IDAT` verileri kısmen yeniden oluşturulabilir.

Bu durum **aCropalypse** (Google Pixel Markup) ve bununla ilişkili **Windows Snipping Tool** sorunu sayesinde iyi bilinir hâle geldi. Pratikte, bir "cropped" veya "redacted" PNG hâlâ eski trailing data içeriyorsa, orijinal screenshot'ın bir bölümünü kurtarabilirsiniz.<sup>[[1]](#references)</sup>

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Daha derin analizi güçlü şekilde gerektiren işaretler:

- `pngcheck`, **`IEND` sonrasında ek veri** bildiriyor
- **Birden fazla `IEND`** buluyorsunuz
- Görüntünün görünürdeki sonundan sonra **ek `IDAT` chunk'ları** buluyorsunuz
- Ekran görüntüsü, etkilendiği bilinen bir cihazdan/editor'den alınmış

Bu gerçekleşirse, redaction'a güvenmeden önce dosyayı bir **aCropalypse recovery tool** ile işleyin.

## Pratikte önemli olan chunk abuse

İncelemeler için en ilgi çekici PNG chunk'ları genellikle bariz görüntü chunk'ları değil, **metin**, **metadata** veya **payload bytes** taşıyabilen chunk'lardır:

- `tEXt` / `zTXt` / `iTXt` – metin metadata'sı ve sıkıştırılmış metin
- `eXIf` – PNG içindeki EXIF verileri
- `iCCP` – gömülü ICC profili
- `PLTE` – indexed görüntülerde palette verileri; ancak payload-smuggling senaryolarında da kullanışlıdır<sup>[[2]](#references)</sup>

Şunlarla dump edin:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunk’ları içinde offensive payload persistence için (örneğin bazı PHP image transformations işlemlerinden geçen **PLTE**, **IDAT** veya **tEXt** tricks), upload-focused daha ayrıntılı notlara buradan<sup>[[2]](#references)</sup> bakın:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Bozuk PNG onarımı

Bütünlüğü kontrol etmek ve bozuk bölgenin tam konumunu belirlemek için **pngcheck**, hâlâ en iyi ilk araçlardan biridir:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Dosya kasıtlı olarak malicious değil de hasarlıysa **PCRT**, CTF'lerde ve lab çalışmalarında hatalı header'lar, yanlış IHDR değerleri, CRC sorunları veya bozuk chunk düzenleri gibi yaygın sorunları düzeltmek için yararlı olabilir.

Amacınız görünür görüntüyü korurken şüpheli trailer data içeren bir PNG’yi **sanitize** etmekse ExifTool, trailer'ı açıkça kaldırabilir:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Hassas kanıtlar için her zaman bir **kopya** üzerinde çalışın ve onarım işlemlerini denemeden önce orijinalin hash değerlerini saklayın.

## Referanslar

- [1] [aCropalypse Exploiting: Truncated PNGs Recovering](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG'lerde kalıcı PHP payload'ları: Bir görsele PHP kodu nasıl enjekte edilir ve orada nasıl tutulur](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
