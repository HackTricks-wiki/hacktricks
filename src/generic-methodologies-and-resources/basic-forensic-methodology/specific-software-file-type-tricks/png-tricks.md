# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG dosyaları** **CTF'ler**, **incident response** ve **malware staging** için çok yaygındır çünkü **lossless**'tirler, **chunk-based** yapıdadırlar ve birçok araç, **extra metadata**, **appended payloads** veya **partially corrupted chunks** içerseler bile onları memnuniyetle render eder.

Bir PNG'yi yalnızca bir görüntü olarak değil, bir **container** olarak ele alın.

## Quick triage

LSB stego'ya geçmeden önce container-level kontrollerle başlayın. Bit-plane/LSB workflow için [the dedicated image stego page](../../../stego/images/README.md) sayfasını kontrol edin.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Bakılacak faydalı şeyler:

- **Beklenmedik yardımcı chunk'lar** gibi `tEXt`, `zTXt`, `iTXt`, `eXIf` veya `iCCP`
- **CRC hataları** veya bozuk chunk uzunlukları
- **`IEND` sonrası ek veri**
- **Birden fazla `IEND` işareti** veya dosyanın resmi sonundan sonra kurtarılabilir `IDAT` parçaları
- Carving sırasında hem geçerli bir PNG **hem de** ZIP/PDF/script gibi görünen bir dosya

Minimum geçerli yapı genelde şudur:

- `IHDR` (ilk olmalı)
- `IDAT` (bir veya daha fazla ardışık chunk)
- `IEND` (son olmalı)

## `IEND` sonrası trailing data

En yüksek sinyalli PNG artefact'lerinden biri, **son `IEND` chunk'ından sonra eklenmiş veri**dir. Birçok decoder bunu yok sayar, bu da şunlar için faydalı olmasını sağlar:

- **Basit stego / gizli payload**
- **PNG polyglot'ları**
- **Malware staging**
- **Hatalı editörlerden eski image data'yı kurtarma**

Hızlı tespit:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Final `IEND`'den sonraki her şeyi ayıklamak istiyorsanız:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Ayrıca generic archive parser’ları doğrudan PNG’ye veya carved trailer’a karşı deneyin:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Kırpılmış/redakte edilmiş screenshot’ların Acropalypse tarzı kurtarımı

Çok pratik ve yeni bir PNG forensic trick, bir screenshot editor’ünün bir PNG’yi önceki dosyayı **truncate** etmeden **overwrite** edip etmediğini kontrol etmektir. Bu durumlarda, önceki **image**’dan kalan bytes `IEND` sonrasında kalabilir ve bazen ek `IDAT` verisi kısmen yeniden oluşturulabilir.

Bu durum **aCropalypse** (Google Pixel Markup) ve ilgili **Windows Snipping Tool** sorunuyla geniş çapta bilinir hale geldi. Pratikte, bir "cropped" veya "redacted" PNG hâlâ eski trailing data içeriyorsa, orijinal screenshot’ın bir kısmını kurtarabilirsiniz.

Pratik workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Derinlemesine analiz için güçlü gerekçeler oluşturan işaretler:

- `pngcheck`, **`IEND` sonrasında ek veri** raporluyor
- **Birden fazla `IEND`** buluyorsunuz
- Görüntünün görünen sonundan sonra **ek `IDAT` chunk’ları** buluyorsunuz
- Ekran görüntüsü, etkilenmiş olduğu bilinen bir cihazdan/editor’den geldi

Bu olursa, redaksiyona güvenilir demeden önce dosyayı bir **aCropalypse recovery tool**’a verin.

## Pratikte önemli olan chunk abuse

Soruşturmalar için en ilginç PNG chunk’ları genelde bariz görüntü chunk’ları değil, **text**, **metadata** veya **payload bytes** taşıyabilen chunk’lardır:

- `tEXt` / `zTXt` / `iTXt` – text metadata ve compressed text
- `eXIf` – PNG içinde EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images içinde palette data, ama payload-smuggling senaryolarında da kullanışlıdır

Şununla dump edin:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Offensive payload persistence inside PNG chunks (for example **PLTE**, **IDAT**, or **tEXt** tricks that survive some PHP image transformations) için, daha ayrıntılı upload odaklı notlara buradan bakın:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Bütünlüğü kontrol etmek ve tam olarak bozuk alanı bulmak için, **pngcheck** hâlâ en iyi ilk araçlardan biridir:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Eğer dosya kasıtlı olarak malicious olmaktan ziyade hasarlıysa, **PCRT** CTF'lerde ve lab çalışmalarında kötü header'lar, yanlış IHDR değerleri, CRC problemleri veya hatalı chunk düzenleri gibi yaygın sorunları düzeltmek için faydalı olabilir.

Amacınız, görünür image'i korurken şüpheli trailer data içeren bir PNG'yi **sanitize** etmekse, ExifTool trailer'ı açıkça kaldırabilir:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Hassas deliller için, onarıma başlamadan önce her zaman bir **kopya** üzerinde çalışın ve orijinalin hash’lerini saklayın.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
