# PNG की तरकीबें

{{#include ../../../banners/hacktricks-training.md}}

**PNG files** **CTFs**, **incident response**, और **malware staging** में बहुत आम हैं, क्योंकि वे **lossless** और **chunk-based** होते हैं, और कई tools उन्हें तब भी render कर देते हैं जब उनमें **extra metadata**, **appended payloads**, या **आंशिक रूप से corrupted chunks** हों।

PNG को सिर्फ़ एक image नहीं, बल्कि एक **container** मानें।

## शुरुआती जाँच

LSB stego पर जाने से पहले container-level जाँच से शुरुआत करें। Bit-plane/LSB workflow के लिए, [dedicated image stego page](../../../stego/images/) देखें।

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

ध्यान देने योग्य चीज़ें:

- **अनपेक्षित ancillary chunks** जैसे `tEXt`, `zTXt`, `iTXt`, `eXIf`, या `iCCP`
- **CRC errors** या malformed chunk lengths
- `IEND` के बाद **अतिरिक्त डेटा**
- **एक से अधिक `IEND` markers** या फ़ाइल के औपचारिक अंत के बाद recoverable `IDAT` fragments
- ऐसी फ़ाइल जो एक वैध PNG हो **और** carve करने पर ZIP/PDF/script जैसी भी दिखे

ध्यान रखें कि न्यूनतम वैध संरचना आमतौर पर यह होती है:

- `IHDR` (पहला होना चाहिए)
- `IDAT` (एक या अधिक लगातार chunks)
- `IEND` (आखिरी होना चाहिए)

## `IEND` के बाद का trailing data

सबसे अधिक संकेत देने वाले PNG artefacts में से एक है **अंतिम `IEND` chunk के बाद जोड़ा गया डेटा**। कई decoders इसे अनदेखा कर देते हैं, जिससे यह इन कामों के लिए उपयोगी है:

- **सरल stego / hidden payloads**
- **PNG polyglots**
- **Malware staging**
- Buggy editors से **पुराना image data recover करना**

त्वरित पहचान:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

`IEND` के लिए byte search केवल एक संकेत है: वही bytes chunk data या forged trailer में भी हो सकते हैं। भरोसेमंद तरीके से carve करने के लिए, PNG signature से शुरू करके length-prefixed chunks को पढ़ें और पहले structural `IEND` पर रुकें; [नीचे दिया गया chunk walker](#extract-ancillary-chunk-payloads) trailer को भी सेव करता है।<sup>[[6]](#references)</sup>

Generic archive parsers को सीधे PNG या carved trailer पर भी आज़माएँ:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Cropped/redacted screenshots की Acropalypse-style recovery

हाल ही में इस्तेमाल की गई एक बहुत व्यावहारिक PNG forensic trick यह जाँचना है कि screenshot editor ने PNG को **overwrite** तो किया, लेकिन पुरानी file को पहले **truncate** नहीं किया। ऐसे मामलों में **previous image** के bytes `IEND` के बाद रह सकते हैं, और कभी-कभी अतिरिक्त `IDAT` data को आंशिक रूप से reconstruct किया जा सकता है।

यह **aCropalypse** (Google Pixel Markup) और इससे जुड़े **Windows Snipping Tool** issue के कारण काफ़ी मशहूर हुआ।<sup>[[3]](#references)</sup> व्यवहार में, अगर किसी "cropped" या "redacted" PNG में पुराना trailing data अब भी मौजूद है, तो आप original screenshot का कुछ हिस्सा recover कर सकते हैं।<sup>[[1]](#references)</sup>

व्यावहारिक प्रक्रिया:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

ऐसे संकेत जो गहन विश्लेषण को उचित ठहराते हैं:

- `pngcheck` **`IEND` के बाद अतिरिक्त डेटा** रिपोर्ट करता है
- आपको **एक से अधिक `IEND`** मिलते हैं
- छवि के स्पष्ट अंत के बाद आपको **अतिरिक्त `IDAT` chunks** मिलते हैं
- स्क्रीनशॉट ऐसे डिवाइस/एडिटर से लिया गया था जिसके प्रभावित होने की जानकारी है

ऐसा होने पर, redaction को भरोसेमंद मानने से पहले फ़ाइल को **aCropalypse recovery tool** में डालें।

## व्यवहार में महत्वपूर्ण chunk abuse

जांच के लिए सबसे दिलचस्प PNG chunks आमतौर पर स्पष्ट image वाले नहीं, बल्कि वे chunks होते हैं जिनमें **text**, **metadata** या **payload bytes** हो सकते हैं:

- `tEXt` / `zTXt` / `iTXt` – text metadata और compressed text
- `eXIf` – PNG के अंदर EXIF data
- `iCCP` – embedded ICC profile
- `PLTE` – indexed images में palette data, लेकिन payload-smuggling scenarios में भी उपयोगी।<sup>[[2]](#references)</sup>

इन्हें dump करें:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

PNG chunks के अंदर offensive payload persistence के लिए (उदाहरण के लिए, **PLTE**, **IDAT**, या **tEXt** tricks जो कुछ PHP image transformations के बाद भी बने रहते हैं), यहाँ अधिक विस्तृत upload-focused notes देखें:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Ancillary chunk payloads निकालें

हमलावर `IEND` से पहले किसी **unknown ancillary chunk** में मनमाने bytes रख सकता है। सामान्य PNG decoders किसी unknown ancillary chunk को अनदेखा कर सकते हैं, जबकि image को bytes के रूप में fetch करने वाली script payload को पढ़कर इस्तेमाल कर सकती है; केवल PNG खोलने से यह execute नहीं होता।<sup>[[4]](#references)[[6]](#references)</sup> मूल research में compressed और encrypted custom chunk दिखाया गया था।<sup>[[4]](#references)</sup> बाद के browser example में निकाले गए bytes का इस्तेमाल HTML या download उपलब्ध कराने के लिए किया गया था।<sup>[[5]](#references)</sup>

पहले chunk-type letter का lowercase होना *ancillary* दर्शाता है; दूसरे letter का lowercase होना *private* दर्शाता है। उदाहरण के लिए, `paMP` private है, जबकि `pAMP` public namespace का उपयोग करता है, भले ही बाद वाला demonstration के लिए बनाया गया था।<sup>[[4]](#references)[[6]](#references)</sup> एक chunk का ढाँचा `length (4 bytes, big-endian) | type (4 bytes) | data | CRC (4 bytes)` होता है; CRC में type और data शामिल होते हैं। Compressed `IDAT` data के अंदर type name को grep करने के बजाय इस ढाँचे को parse करें। नीचे दिया गया walker bounds और CRCs को validate करता है, ancillary payloads को raw bytes के रूप में export करता है, और structural `IEND` के बाद के किसी भी bytes को `png-trailer.bin` में लिखता है।<sup>[[6]](#references)</sup>

<details>
<summary>Ancillary chunks और PNG trailer को carve करें</summary>

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

Carved bytes को `file`, `strings` या `binwalk` से जाँचें; decompress केवल तभी करें, जब carrier वास्तव में compressed हो।<sup>[[4]](#references)</sup> Re-encoding से carrier हट सकता है, इसलिए इस पर निर्भर होने से पहले uploaded और retrieved bytes की तुलना करें।<sup>[[2]](#references)[[6]](#references)</sup>

## Corrupted PNG की मरम्मत

Integrity जाँचने और टूटे हुए सटीक हिस्से का पता लगाने के लिए, **pngcheck** अब भी शुरुआती जाँच के सबसे अच्छे tools में से एक है:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

अगर फ़ाइल जानबूझकर malicious बनाने के बजाय damaged है, तो **PCRT** CTFs और lab work में bad headers, गलत IHDR values, CRC समस्याओं या malformed chunk layouts जैसी आम समस्याओं को ठीक करने में उपयोगी हो सकता है।

अगर आपका लक्ष्य suspicious trailer data वाले PNG को **sanitize** करते हुए दिखाई देने वाली image को बनाए रखना है, तो ExifTool trailer को स्पष्ट रूप से हटा सकता है:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

संवेदनशील साक्ष्य के लिए, हमेशा एक **कॉपी** पर काम करें और मरम्मत करने से पहले मूल फ़ाइल के hashes रखें।



## References

- [1] [Exploiting aCropalypse: Truncated PNGs को रिकवर करना](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [PNG में Persistent PHP payloads: किसी image में PHP code कैसे inject करें – और उसे वहीं कैसे बनाए रखें](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [संवेदनशील जानकारी छिपाकर रखने के लिए Ancillary chunks एक आदर्श जगह हैं](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Endpoint तक data smuggle करने के लिए valid ancillary chunks का उपयोग](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Portable Network Graphics (PNG) Specification (Third Edition)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}
