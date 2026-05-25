# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** **CTFs**, **incident response**, और **malware staging** में बहुत common हैं क्योंकि ये **lossless**, **chunk-based** होते हैं, और कई tools इन्हें आसानी से render कर देते हैं even when they contain **extra metadata**, **appended payloads**, या **partially corrupted chunks**.

PNG को एक **container** की तरह treat करें, सिर्फ एक image की तरह नहीं।

## Quick triage

LSB stego में जाने से पहले container-level checks से start करें। bit-plane/LSB workflow के लिए, [the dedicated image stego page](../../../stego/images/README.md) देखें।
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
देखने लायक उपयोगी चीज़ें:

- **Unexpected ancillary chunks** जैसे `tEXt`, `zTXt`, `iTXt`, `eXIf`, या `iCCP`
- **CRC errors** या malformed chunk lengths
- **`IEND` के बाद additional data**
- **Multiple `IEND` markers** या file के formal end के बाद recoverable `IDAT` fragments
- एक file जो valid PNG **भी** है और carved करने पर ZIP/PDF/script जैसी भी दिखती है

याद रखें, minimum valid structure आम तौर पर यह होता है:

- `IHDR` (must be first)
- `IDAT` (one or more consecutive chunks)
- `IEND` (must be last)

## Trailing data after `IEND`

सबसे high-signal PNG artefacts में से एक है **final `IEND` chunk के बाद appended data**। बहुत से decoders इसे ignore कर देते हैं, जिससे यह इन चीज़ों के लिए useful हो जाता है:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **Buggy editors से older image data recover करना**

Quick detection:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
यदि आप अंतिम `IEND` के बाद की हर चीज़ को carve करना चाहते हैं:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
साथ ही generic archive parsers को सीधे PNG या carved trailer के खिलाफ भी आज़माएँ:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Cropped/redacted screenshots की Acropalypse-style recovery

एक बहुत ही practical recent PNG forensic trick यह check करना है कि क्या कोई screenshot editor ने PNG को **overwrite** किया लेकिन पुराने file को पहले **truncate** नहीं किया। ऐसे मामलों में, **previous image** के bytes `IEND` के बाद रह सकते हैं, और कभी-कभी extra `IDAT` data को partially reconstruct भी किया जा सकता है।

यह **aCropalypse** (Google Pixel Markup) और related **Windows Snipping Tool** issue के साथ widely known हुआ। Practice में, अगर कोई "cropped" या "redacted" PNG अभी भी old trailing data रखता है, तो आप original screenshot का कुछ हिस्सा recover कर सकते हैं।

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
गहन विश्लेषण को दृढ़ता से उचित ठहराने वाले संकेत:

- `pngcheck` **`IEND` के बाद अतिरिक्त data** रिपोर्ट करता है
- आपको **एक से अधिक `IEND`** मिलते हैं
- आपको image के apparent end के बाद **extra `IDAT` chunks** मिलते हैं
- screenshot ऐसे device/editor से आया था जो known तौर पर affected था

अगर ऐसा होता है, तो redaction को trustworthy मानने से पहले file को **aCropalypse recovery tool** में feed करें।

## Chunk abuse जो practical रूप से मायने रखता है

Investigations के लिए सबसे interesting PNG chunks आमतौर पर obvious image ones नहीं होते, बल्कि वे chunks होते हैं जो **text**, **metadata**, या **payload bytes** carry कर सकते हैं:

- `tEXt` / `zTXt` / `iTXt` – text metadata और compressed text
- `eXIf` – PNG के अंदर EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images में palette data, लेकिन payload-smuggling scenarios में भी useful

इन्हें dump करें with:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
PNG chunks के अंदर offensive payload persistence के लिए (उदाहरण के लिए **PLTE**, **IDAT**, या **tEXt** tricks जो कुछ PHP image transformations के बाद भी survive करते हैं), अधिक detailed upload-focused notes के लिए यहाँ देखें:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

Integrity check करने और exact broken area locate करने के लिए, **pngcheck** अभी भी सबसे अच्छे first tools में से एक है:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

अगर file intentionally malicious होने के बजाय damaged है, तो **PCRT** CTFs और lab work में common issues जैसे bad headers, wrong IHDR values, CRC problems, या malformed chunk layouts fix करने के लिए useful हो सकता है।

अगर आपका goal एक PNG को **sanitize** करना है जिसमें suspicious trailer data है, while visible image को preserve करते हुए, ExifTool explicitly trailer को remove कर सकता है:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
संवेदनशील साक्ष्य के लिए, हमेशा एक **copy** पर काम करें और repairs करने से पहले original के hashes सुरक्षित रखें।

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
