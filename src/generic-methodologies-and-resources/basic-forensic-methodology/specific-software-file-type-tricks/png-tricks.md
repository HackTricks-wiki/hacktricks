# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG dosyaları** **CTFs**, **incident response** ve **malware staging** içinde çok yaygındır çünkü **lossless**’tir, **chunk-based** yapıdadır ve birçok araç, içinde **extra metadata**, **appended payloads** veya **partially corrupted chunks** olsa bile onları memnuniyetle render eder.

Bir PNG’ye sadece bir image olarak değil, bir **container** olarak yaklaşın.

## Quick triage

LSB stego’ya geçmeden önce container-level kontrollerle başlayın. Bit-plane/LSB workflow için [the dedicated image stego page](../../../stego/images/README.md) adresine bakın.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Bakılacak faydalı şeyler:

- `tEXt`, `zTXt`, `iTXt`, `eXIf` veya `iCCP` gibi **beklenmedik ek chunk'lar**
- **CRC hataları** veya bozuk chunk uzunlukları
- `IEND` sonrasında **ek veri**
- **Birden fazla `IEND` işareti** veya dosyanın resmi sonundan sonra kurtarılabilir `IDAT` parçaları
- Carve edildiğinde hem geçerli bir PNG **hem de** ZIP/PDF/script gibi görünen bir dosya

Minimum geçerli yapı genellikle şudur:

- `IHDR` (ilk olmalı)
- `IDAT` (bir veya daha fazla ardışık chunk)
- `IEND` (son olmalı)

## `IEND` sonrasında kalan veri

En yüksek sinyal veren PNG artefaktlarından biri, **son `IEND` chunk'ından sonra eklenmiş veri**dir. Birçok decoder bunu yok sayar; bu da onu şu amaçlar için faydalı kılar:

- **Basit stego / gizli payload**
- **PNG polyglot'ları**
- **Malware staging**
- Hatalı editörlerden **eski görüntü verisini kurtarma**

Hızlı tespit:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Son `IEND`'den sonraki her şeyi carve etmek istiyorsanız:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Ayrıca generic archive parser'ları doğrudan PNG'ye veya carved trailer'a karşı deneyin:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Kırpılmış/redakte edilmiş ekran görüntülerinin Acropalypse tarzı kurtarılması

Çok pratik bir yakın dönem PNG adli bilişim hilesi, bir ekran görüntüsü düzenleyicisinin bir PNG'yi önce **truncating** etmeden **overwrote** edip etmediğini kontrol etmektir. Bu durumlarda, **önceki görüntüden** kalan baytlar `IEND` sonrasında kalabilir ve bazen ek `IDAT` verileri kısmen yeniden oluşturulabilir.

Bu, **aCropalypse** (Google Pixel Markup) ve ilgili **Windows Snipping Tool** sorunu ile yaygın biçimde bilinir hale geldi. Pratikte, "kırpılmış" veya "redacted" bir PNG hâlâ eski sondaki verileri içeriyorsa, orijinal ekran görüntüsünün bir kısmını kurtarabilirsiniz.

Pratik iş akışı:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Daha derin analiz gerektiğini güçlü şekilde haklı çıkaran işaretler:

- `pngcheck` **`IEND` sonrası ek veri** raporluyor
- **Birden fazla `IEND`** buluyorsunuz
- Görüntünün görünen sonundan sonra **ek `IDAT` chunk’ları** buluyorsunuz
- Screenshot, etkilendiği bilinen bir cihaz/editor’dan geldi

Bu olursa, redaksiyona güvenilir muamelesi yapmadan önce dosyayı bir **aCropalypse recovery tool** ile işleyin.

## Pratikte önemli olan chunk abuse

Investigations için en ilginç PNG chunk’ları genellikle bariz image olanlar değil, **text**, **metadata** veya **payload bytes** taşıyabilen chunk’lardır:

- `tEXt` / `zTXt` / `iTXt` – text metadata ve compressed text
- `eXIf` – PNG içindeki EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images içinde palette data, ancak payload-smuggling senaryolarında da kullanışlıdır

Şunla dökün:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Offensive payload persistence inside PNG chunks (örneğin **PLTE**, **IDAT** veya bazı PHP image transformations sonrası hayatta kalan **tEXt** tricks) için, daha detaylı upload odaklı notlara burada bakın:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Bütünlüğü kontrol etmek ve tam bozuk alanı bulmak için, **pngcheck** hâlâ en iyi ilk tools’lardan biridir:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Dosya kasıtlı olarak malicious yerine gerçekten damaged ise, **PCRT** CTF’lerde ve lab çalışmalarında kötü header’lar, yanlış IHDR values, CRC problemleri veya malformed chunk layouts gibi yaygın sorunları düzeltmek için faydalı olabilir.

Amacınız görünür image’ı korurken suspicious trailer data içeren bir PNG’yi **sanitize** etmekse, ExifTool trailer’ı explicit olarak kaldırabilir:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Hassas deliller için, onarımlara girişmeden önce her zaman bir **kopya** üzerinde çalışın ve orijinalin hash'lerini saklayın.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
