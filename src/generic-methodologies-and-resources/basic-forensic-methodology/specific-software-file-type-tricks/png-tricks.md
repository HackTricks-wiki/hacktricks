# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** **CTFs**, **incident response**, और **malware staging** में बहुत आम हैं क्योंकि वे **lossless**, **chunk-based** होते हैं, और कई tools उन्हें खुशी-खुशी render कर देते हैं, भले ही उनमें **extra metadata**, **appended payloads**, या **partially corrupted chunks** हों।

PNG को सिर्फ एक image नहीं, बल्कि एक **container** की तरह treat करें।

## Quick triage

LSB stego में जाने से पहले container-level checks से शुरू करें। bit-plane/LSB workflow के लिए, [the dedicated image stego page](../../../stego/images/README.md) देखें।
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
- **`IEND` के बाद अतिरिक्त data**
- **Multiple `IEND` markers** या file के formal end के बाद recoverable `IDAT` fragments
- एक file जो valid PNG भी हो **और** carve करने पर ZIP/PDF/script जैसी भी लगे

याद रखें minimum valid structure आमतौर पर यह होता है:

- `IHDR` (must be first)
- `IDAT` (one or more consecutive chunks)
- `IEND` (must be last)

## `IEND` के बाद trailing data

सबसे high-signal PNG artefacts में से एक है **final `IEND` chunk के बाद appended data**। कई decoders इसे ignore कर देते हैं, जिससे यह उपयोगी हो जाता है:

- **Simple stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- **buggy editors से older image data recover करना**

Quick detection:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
यदि आप अंतिम `IEND` के बाद की हर चीज़ carve करना चाहते हैं:
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

एक बहुत practical recent PNG forensic trick यह जांचना है कि क्या screenshot editor ने पुराने file को पहले **truncating** किए बिना PNG को **overwrote** किया था। ऐसे cases में, **previous image** के bytes `IEND` के बाद बचे रह सकते हैं, और कभी-कभी extra `IDAT` data को partially reconstruct किया जा सकता है।

यह **aCropalypse** (Google Pixel Markup) और related **Windows Snipping Tool** issue के साथ काफी प्रसिद्ध हुआ। Practical तौर पर, अगर कोई "cropped" या "redacted" PNG अभी भी पुराने trailing data को रखता है, तो आप original screenshot का कुछ हिस्सा recover कर सकते हैं।

Practical workflow:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
गहरी विश्लेषण को दृढ़ता से उचित ठहराने वाले संकेत:

- `pngcheck` **`IEND` के बाद अतिरिक्त data** रिपोर्ट करता है
- आपको **एक से अधिक `IEND`** मिलते हैं
- आपको इमेज के स्पष्ट end के बाद **extra `IDAT` chunks** मिलते हैं
- screenshot किसी ऐसे device/editor से आया है जो ज्ञात रूप से affected रहा है

अगर ऐसा होता है, तो redaction को भरोसेमंद मानने से पहले file को एक **aCropalypse recovery tool** में feed करें।

## Chunk abuse that matters in practice

Investigation के लिए सबसे दिलचस्प PNG chunks आम तौर पर स्पष्ट image वाले नहीं होते, बल्कि वे chunks होते हैं जो **text**, **metadata**, या **payload bytes** carry कर सकते हैं:

- `tEXt` / `zTXt` / `iTXt` – text metadata और compressed text
- `eXIf` – PNG के अंदर EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images में palette data, लेकिन payload-smuggling scenarios में भी उपयोगी

इन्हें dump करें:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
आक्रामक payload persistence के लिए PNG chunks के अंदर (उदाहरण के लिए **PLTE**, **IDAT**, या **tEXt** tricks जो कुछ PHP image transformations के बाद भी बने रहें), अधिक विस्तृत upload-focused notes यहाँ देखें:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Corrupted PNG repair

integrity की जाँच और exact broken area ढूँढने के लिए, **pngcheck** अभी भी सबसे अच्छे first tools में से एक है:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

यदि file intentionally malicious होने के बजाय damaged है, तो **PCRT** CTFs और lab work में bad headers, wrong IHDR values, CRC problems, या malformed chunk layouts जैसी common issues को ठीक करने में उपयोगी हो सकता है।

यदि आपका goal एक ऐसे PNG को **sanitize** करना है जिसमें suspicious trailer data हो, जबकि visible image को preserve करना हो, तो ExifTool trailer को explicitly remove कर सकता है:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
संवेदनशील evidence के लिए, हमेशा एक **copy** पर काम करें और repairs करने से पहले original के hashes रखें।

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}
