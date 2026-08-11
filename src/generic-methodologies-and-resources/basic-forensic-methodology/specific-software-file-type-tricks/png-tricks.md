# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** **CTFs**, **incident response**, और **malware staging** में बहुत आम हैं, क्योंकि वे **lossless**, **chunk-based** होते हैं और कई tools उन्हें तब भी आसानी से render कर देंगे, जब उनमें **extra metadata**, **appended payloads**, या **partially corrupted chunks** मौजूद हों।

PNG को केवल एक image के रूप में नहीं, बल्कि एक **container** के रूप में देखें।

## Quick triage

LSB stego पर जाने से पहले container-level checks से शुरुआत करें। bit-plane/LSB workflow के लिए [dedicated image stego page](../../../stego/images/README.md) देखें।
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
देखने योग्य उपयोगी चीज़ें:

- **Unexpected ancillary chunks** जैसे `tEXt`, `zTXt`, `iTXt`, `eXIf`, या `iCCP`
- **CRC errors** या malformed chunk lengths
- **Additional data after `IEND`**
- **Multiple `IEND` markers** या file के formal end के बाद recoverable `IDAT` fragments
- ऐसी file जो एक valid PNG हो **और** carve किए जाने पर ZIP/PDF/script जैसी भी दिखाई दे

याद रखें, minimum valid structure आमतौर पर यह होती है:

- `IHDR` (पहला होना आवश्यक है)
- `IDAT` (एक या अधिक consecutive chunks)
- `IEND` (अंतिम होना आवश्यक है)

## `IEND` के बाद trailing data

सबसे अधिक signal देने वाले PNG artefacts में से एक **final `IEND` chunk के बाद appended data** है। कई decoders इसे ignore कर देते हैं, जिससे यह इन कार्यों के लिए उपयोगी बन जाता है:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- Buggy editors से **पुराना image data recover करना**

Quick detection:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
यदि आप अंतिम `IEND` के बाद की हर चीज़ को `carve` करना चाहते हैं:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
PNG या carved trailer के विरुद्ध सीधे generic archive parsers भी आज़माएँ:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Acropalypse-style cropped/redacted screenshots की recovery

एक बहुत practical हालिया PNG forensic trick यह जाँचना है कि क्या किसी screenshot editor ने पहले पुरानी file को **truncating** किए बिना PNG को **overwrote** किया था। ऐसे मामलों में **previous image** के bytes `IEND` के बाद रह सकते हैं, और कभी-कभी अतिरिक्त `IDAT` data को आंशिक रूप से reconstruct किया जा सकता है।

यह **aCropalypse** (Google Pixel Markup) और संबंधित **Windows Snipping Tool** issue के साथ प्रसिद्ध हुआ।<sup>[[3]](#references)</sup> व्यवहार में, यदि कोई "cropped" या "redacted" PNG अभी भी पुराना trailing data रखता है, तो आप original screenshot के कुछ हिस्से recover कर सकते हैं।<sup>[[1]](#references)</sup>

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
गहरे analysis को दृढ़ता से उचित ठहराने वाले संकेत:

- `pngcheck` **`IEND` के बाद additional data** रिपोर्ट करता है
- आपको **एक से अधिक `IEND`** मिलते हैं
- आपको image के apparent end के बाद **extra `IDAT` chunks** मिलते हैं
- screenshot ऐसे device/editor से आया है जिसके प्रभावित होने के लिए जाना जाता है

यदि ऐसा होता है, तो redaction को trustworthy मानने से पहले file को **aCropalypse recovery tool** में चलाएँ।

## व्यवहार में महत्वपूर्ण Chunk abuse

Investigations के लिए सबसे interesting PNG chunks आमतौर पर obvious image वाले नहीं होते, बल्कि वे chunks होते हैं जो **text**, **metadata**, या **payload bytes** रख सकते हैं:

- `tEXt` / `zTXt` / `iTXt` – text metadata और compressed text
- `eXIf` – PNG के अंदर EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images में palette data, लेकिन payload-smuggling scenarios में भी उपयोगी।<sup>[[2]](#references)</sup>

इन्हें इस command से dump करें:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunks के अंदर offensive payload persistence के लिए (उदाहरण के लिए **PLTE**, **IDAT**, या **tEXt** tricks, जो कुछ PHP image transformations के बाद भी बनी रहती हैं), अधिक विस्तृत upload-focused notes यहाँ देखें:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Integrity जाँचने और exact broken area का पता लगाने के लिए, **pngcheck** अब भी सबसे अच्छे शुरुआती tools में से एक है:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

यदि file जानबूझकर malicious नहीं है बल्कि damaged है, तो **PCRT** CTFs और lab work में bad headers, गलत IHDR values, CRC problems या malformed chunk layouts जैसी common समस्याओं को ठीक करने में उपयोगी हो सकता है।

यदि आपका लक्ष्य suspicious trailer data वाली PNG को **sanitize** करना है और visible image को बनाए रखना है, तो ExifTool trailer को स्पष्ट रूप से हटा सकता है:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
संवेदनशील evidence के लिए, हमेशा एक **कॉपी** पर काम करें और repair का प्रयास करने से पहले original के hashes सुरक्षित रखें।

## References

- [1] [aCropalypse का Exploiting: Truncated PNGs को Recover करना](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNGs में Persistent PHP payloads: image में PHP code inject करना और उसे वहीं बनाए रखना](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}
