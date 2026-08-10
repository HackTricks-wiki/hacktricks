# PNG Hileleri

**PNG dosyaları**, **kayıpsız**, **chunk tabanlı** oldukları ve birçok aracın, **ek metadata**, **sonuna eklenmiş payload** veya **kısmen bozulmuş chunk'lar** içerseler bile bunları sorunsuz şekilde render etmesi nedeniyle **CTF'lerde**, **incident response** süreçlerinde ve **malware staging** için çok yaygındır.

PNG'yi yalnızca bir görüntü olarak değil, bir **container** olarak ele alın.

## Hızlı ön inceleme

LSB stego'ya geçmeden önce container düzeyinde kontrollerle başlayın. Bit-plane/LSB workflow için [özel image stego sayfasına](../../../stego/images/README.md) bakın.
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Aranacak faydalı şeyler:

- `tEXt`, `zTXt`, `iTXt`, `eXIf` veya `iCCP` gibi **beklenmeyen ancillary chunk'lar**
- **CRC hataları** veya hatalı chunk uzunlukları
- `IEND` sonrasında **ek veriler**
- **Birden fazla `IEND` işaretçisi** veya dosyanın resmi sonundan sonra kurtarılabilir `IDAT` parçaları
- Geçerli bir PNG olan ve aynı zamanda carve edildiğinde ZIP/PDF/script gibi görünen bir dosya

Minimum geçerli yapı genellikle şöyledir:

- `IHDR` (ilk olmalıdır)
- `IDAT` (bir veya daha fazla ardışık chunk)
- `IEND` (son olmalıdır)

## `IEND` sonrasındaki veriler

En yüksek sinyal değerine sahip PNG artefact'larından biri, **son `IEND` chunk'ından sonra eklenmiş verilerdir**. Birçok decoder bu verileri yok sayar; bu da onları şunlar için kullanışlı hâle getirir:

- **Basit stego / gizli payload'lar**
- **PNG polyglot'ları**
- **Malware staging**
- Hatalı editörlerden **eski image data'larını kurtarma**

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
Ayrıca generic archive parsers'ı doğrudan PNG'ye veya carve edilmiş trailer'a karşı deneyin:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style cropped/redacted screenshot kurtarma

Çok pratik ve güncel bir PNG adli bilişim tekniği, bir screenshot editor'ünün önceki dosyayı **truncating** yapmadan **overwrote** edip etmediğini kontrol etmektir. Bu durumlarda, **previous image**'a ait byte'lar `IEND` sonrasında kalabilir ve bazen ek `IDAT` verileri kısmen yeniden oluşturulabilir.

Bu durum, **aCropalypse** (Google Pixel Markup) ve ilgili **Windows Snipping Tool** sorunu sayesinde yaygın olarak bilinir.<sup>[[3]](#references)</sup> Pratikte, "cropped" veya "redacted" bir PNG hâlâ eski sondaki verileri içeriyorsa, orijinal screenshot'ın bir bölümünü kurtarabilirsiniz.<sup>[[1]](#references)</sup>

Pratik iş akışı:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Daha derin bir analizi güçlü biçimde gerektiren işaretler:

- `pngcheck`, **`IEND` sonrasında ek veri** olduğunu bildirir
- **Birden fazla `IEND`** bulursunuz
- Görüntünün görünen sonundan sonra **ek `IDAT` chunk'ları** bulursunuz
- Ekran görüntüsü, etkilendiği bilinen bir cihazdan/editor'den alınmıştır

Bu gerçekleşirse, redaction'a güvenmeden önce dosyayı bir **aCropalypse recovery tool** ile işleyin.

## Uygulamada önemli olan chunk abuse

İncelemeler için en ilgi çekici PNG chunk'ları genellikle bariz görüntü chunk'ları değil, **metin**, **metadata** veya **payload byte'ları** taşıyabilen chunk'lardır:

- `tEXt` / `zTXt` / `iTXt` – metin metadata'sı ve sıkıştırılmış metin
- `eXIf` – PNG içindeki EXIF verileri
- `iCCP` – gömülü ICC profili
- `PLTE` – indekslenmiş görüntülerde palette verileri; ayrıca payload-smuggling senaryolarında da kullanışlıdır.<sup>[[2]](#references)</sup>

Şunları şu komutla çıkarın:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunk’ları içinde offensive payload persistence için (örneğin bazı PHP image transformations sonrasında korunan **PLTE**, **IDAT** veya **tEXt** tricks) daha ayrıntılı upload-focused notes için buraya bakın:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Integrity kontrolü yapmak ve tam olarak bozuk alanı belirlemek için **pngcheck**, hâlâ kullanılabilecek en iyi ilk araçlardan biridir:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Dosya kasıtlı olarak malicious değil de hasarlıysa **PCRT**, CTF’lerde ve lab çalışmalarında hatalı header’lar, yanlış IHDR değerleri, CRC sorunları veya malformed chunk düzenleri gibi yaygın sorunları düzeltmek için yararlı olabilir.

Amacınız, görünür görüntüyü korurken şüpheli trailer data içeren bir PNG’yi **sanitize** etmekse ExifTool, trailer’ı açıkça kaldırabilir:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Hassas kanıtlar için her zaman bir **kopya** üzerinde çalışın ve onarım girişiminde bulunmadan önce orijinalin hash değerlerini saklayın.

## References

- [1] [aCropalypse'i Exploit Etme: Kesilmiş PNG'leri Kurtarma](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG'lerde Kalıcı PHP payload'ları: Bir görsele PHP kodu nasıl enjekte edilir ve orada nasıl tutulur](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
