# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** for managing **zip files** are आवश्यक हैं diagnosing, repairing, और cracking zip files के लिए। यहाँ कुछ प्रमुख utilities हैं:

- **`unzip`**: बताता है कि कोई zip file क्यों decompress नहीं हो रहा है।
- **`zipdetails -v`**: zip file format के fields का विस्तृत विश्लेषण प्रदान करता है।
- **`zipinfo`**: बिना extract किए zip file की सामग्री को सूचीबद्ध करता है।
- **`zip -F input.zip --out output.zip`** और **`zip -FF input.zip --out output.zip`**: corrupted zip files को repair करने की कोशिश करते हैं।
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip passwords को brute-force करने का एक tool, जो लगभग 7 characters तक के passwords के लिए प्रभावी है।

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) comprehensive विवरण प्रदान करता है zip files की structure और standards पर।

यह जानना महत्वपूर्ण है कि password-protected zip files अंदर filenames या file sizes को encrypt नहीं करते — यह एक security flaw है जो RAR या 7z files में मौजूद encryption के साथ शेयर नहीं होता। इसके अलावा, पुराने ZipCrypto method से encrypted zip files plaintext attack के प्रति संवेदनशील होते हैं यदि कोई unencrypted copy of a compressed file उपलब्ध हो। यह attack ज्ञात कंटेंट का उपयोग करके zip का password क्रैक करता है, इस vulnerability का वर्णन HackThis के लेख में किया गया है और इसे इस academic paper में और विस्तार से समझाया गया है। हालांकि, AES-256 encryption के साथ secured zip files इस plaintext attack से immune होती हैं, जो sensitive data के लिए secure encryption methods चुनने की महत्त्वता दिखाती है।

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers malformed ZIP metadata का उपयोग करते हैं static tools (jadx/apktool/unzip) को तोड़ने के लिए, जबकि APK को on-device installable रखा जाता है। सबसे सामान्य tricks हैं:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

लक्षण:
- `jadx-gui` ऐसे errors के साथ fail हो जाता है:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` core APK files के लिए password माँगता है हालाँकि एक valid APK में encrypted `classes*.dex`, `resources.arsc`, या `AndroidManifest.xml` नहीं हो सकते:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detection with zipdetails:
```bash
zipdetails -v sample.apk | less
```
local और central headers के लिए General Purpose Bit Flag देखें। एक स्पष्ट संकेतक मान bit 0 set (Encryption) होना है, यहाँ तक कि core entries के लिए भी:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ह्यूरिस्टिक: यदि कोई APK डिवाइस पर इंस्टॉल होकर चलता है लेकिन core entries टूल्स के लिए "encrypted" दिखाई देती हैं, तो GPBF में छेड़छाड़ की गई है।

GPBF के bit 0 को दोनों Local File Headers (LFH) और Central Directory (CD) एंट्रीज़ में क्लियर करके समस्या ठीक करें। न्यूनतम बाइट-पैचर:

<details>
<summary>न्यूनतम GPBF बिट-क्लियर पैचर</summary>
```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
out = bytearray(buf)
i = 0
patched = 0
while True:
i = out.find(sig, i)
if i == -1:
break
flags, = struct.unpack_from('<H', out, i + flag_off)
if flags & 1:  # encryption bit set
struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
patched += 1
i += 4  # move past signature to continue search
return bytes(out), patched

if __name__ == '__main__':
inp, outp = sys.argv[1], sys.argv[2]
data = open(inp, 'rb').read()
data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
open(outp, 'wb').write(data)
print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```
</details>

उपयोग:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
अब आप core entries पर `General Purpose Flag  0000` देखेंगे और टूल्स APK को फिर से पार्स कर पाएँगे।

### 2) पार्सर्स को तोड़ने के लिए बड़े/कस्टम Extra fields

हमलावर oversized Extra fields और अजीब IDs को headers में भरकर decompilers को फँसाते हैं। वास्तविक दुनिया में आप वहाँ custom markers (उदाहरण के लिए, `JADXBLOCK` जैसी स्ट्रिंग्स) embedded देख सकते हैं।

निरीक्षण:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
देखे गए उदाहरण: अज्ञात IDs जैसे `0xCAFE` ("Java Executable") या `0x414A` ("JA:") जिनमें बड़े payloads मिलते हैं।

DFIR heuristics:
- जब core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) पर Extra fields असामान्य रूप से बड़े हों तो अलर्ट करें।
- उन entries पर अज्ञात Extra IDs को संदिग्ध मानें।

व्यावहारिक निवारण: आर्काइव को फिर से बनाना (उदा., extracted files को फिर से re-zipping करना) हानिकारक Extra fields को हटा देता है। यदि tools fake encryption के कारण extract करने से इंकार करें, तो पहले ऊपर बताए अनुसार GPBF bit 0 को क्लियर करें, फिर repackage करें:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions (वास्तविक आर्टिफैक्ट्स को छुपाना)

एक ZIP में एक file `X` और एक directory `X/` दोनों हो सकते हैं। कुछ extractors और decompilers भ्रमित हो जाते हैं और directory entry के साथ वास्तविक file को overlay या छुपा सकते हैं। यह core APK नामों जैसे `classes.dex` के साथ टकराने वाली entries में देखा गया है।

Triage and safe extraction:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
प्रोग्रामेटिक डिटेक्शन पोस्ट-फिक्स:
```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
names = z.namelist()

collisions = defaultdict(list)
for n in names:
base = n[:-1] if n.endswith('/') else n
collisions[base].append(n)

for base, variants in collisions.items():
if len(variants) > 1:
print('COLLISION', base, '->', variants)
```
Blue-team के लिए detection सुझाव:
- उन APKs को फ़्लैग करें जिनके local headers एन्क्रिप्शन को मार्क करते हैं (GPBF bit 0 = 1) फिर भी install/run होते हैं।
- core entries पर बड़े/अज्ञात Extra fields को फ़्लैग करें (ऐसे markers खोजें जैसे `JADXBLOCK`)।
- path-collisions (`X` and `X/`) को फ़्लैग करें, खासकर `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` के लिए।

---

## अन्य दुर्भावनापूर्ण ZIP ट्रिक्स (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Recent phishing campaigns एक single blob भेजते हैं जो वास्तव में **two ZIP files concatenated** होता है। हर एक में अपनी End of Central Directory (EOCD) + central directory होता है। विभिन्न extractors अलग-अलग directories को parse करते हैं (7zip पहला पढ़ता है, WinRAR आख़िरी), जिससे attackers उन payloads को छिपा सकते हैं जो सिर्फ कुछ tools दिखाते हैं। यह basic mail gateway AV को भी bypass कर देता है जो केवल पहले directory का निरीक्षण करता है।

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
यदि एक से अधिक EOCD दिखाई देते हैं या "data after payload" चेतावनियाँ हैं, तो blob को विभाजित करें और प्रत्येक भाग का निरीक्षण करें:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" एक छोटा **kernel** (highly compressed DEFLATE block) बनाता है और overlapping local headers के जरिए इसे पुन: उपयोग करता है। प्रत्येक central directory entry एक ही compressed data की ओर इशारा करता है, जिससे nesting archives के बिना >28M:1 से अधिक अनुपात प्राप्त होता है। जो libraries central directory sizes पर भरोसा करती हैं (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds), उन्हें पेटाबाइट्स आवंटित करने के लिए मजबूर किया जा सकता है।

**त्वरित पहचान (duplicate LFH offsets)**
```python
# detect overlapping entries by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
i = buf.find(b'PK\x01\x02', off)
if i<0: break
rel = struct.unpack_from('<I', buf, i+42)[0]
if rel in seen:
print('OVERLAP at offset', rel)
break
seen.add(rel); off = i+4
```
**हैंडलिंग**
- ड्राई-रन वॉक करें: `zipdetails -v file.zip | grep -n "Rel Off"` और सुनिश्चित करें कि offsets सख्ती से बढ़ते हुए और अद्वितीय हैं।
- एक्सट्रैक्शन से पहले स्वीकार्य कुल अनकंप्रेस्ड साइज और एंट्री गिनती को सीमित करें (`zipdetails -t` या कस्टम पार्सर)।
- जब आपको एक्सट्रैक्ट करना आवश्यक हो, तो इसे cgroup/VM के अंदर करें जिसमें CPU और डिस्क सीमाएँ लगी हों (अनियंत्रित वृद्धि से होने वाले क्रैश से बचें)।

---

### Local-header vs central-directory parser confusion

हालिया differential-parser शोध ने दिखाया कि ZIP अस्पष्टता अभी भी आधुनिक टूलचेन में शोषण योग्य है। मुख्य विचार सरल है: कुछ सॉफ़्टवेयर **Local File Header (LFH)** पर भरोसा करते हैं जबकि अन्य **Central Directory (CD)** पर, इसलिए एक आर्काइव विभिन्न टूल्स को अलग-अलग filenames, paths, comments, offsets, या entry सेट दिखा सकता है।

Practical offensive uses:
- एक upload filter, AV pre-scan, या package validator को CD में एक benign फ़ाइल दिखाएँ जबकि extractor एक अलग LFH नाम/पाथ को मानता है।
- डुप्लिकेट नामों, केवल एक स्ट्रक्चर में मौजूद एंट्रीज़, या ambiguous Unicode path metadata (उदाहरण के लिए, Info-ZIP Unicode Path Extra Field `0x7075`) का दुरुपयोग करें ताकि अलग-अलग पार्सर अलग-अलग ट्रीज़ पुनर्निर्मित करें।
- इसे path traversal के साथ जोड़कर एक "harmless" archive view को extraction के दौरान write-primitive में बदल दें। एक्सट्रैक्शन पक्ष के लिए, देखें [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md)。

DFIR triage:
```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
n, e = struct.unpack_from('<HH', b, i + 26)
lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
n = struct.unpack_from('<H', b, i + 28)[0]
off = struct.unpack_from('<I', b, i + 42)[0]
cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
if off in lfh and cd != lfh[off]:
print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
i += 4
```
I don't have the content of src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md. Please paste the markdown you want translated (or specify the exact sections to complement) and I will translate them to Hindi following your rules.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- LFH/CD नामों में असंगति, डुप्लिकेट फ़ाइलनाम, एकाधिक EOCD रिकॉर्ड, या अंतिम EOCD के बाद ट्रेलिंग बाइट्स वाले archives को अस्वीकार या अलग करें।
- यदि अलग-अलग टूल्स द्वारा निकाले गए tree पर असहमति हो तो असामान्य Unicode-path extra fields या असंगत comments का उपयोग करने वाले ZIPs को संदिग्ध मानें।
- यदि विश्लेषण मूल बाइट्स को बनाये रखने से अधिक महत्वपूर्ण है, तो sandbox में extraction के बाद archive को एक strict parser के साथ पुनः पैकेज करें और बन रही फ़ाइल सूची की तुलना original metadata से करें।

यह package ecosystems से परे भी मायने रखता है: वही ambiguity class mail gateways, static scanners, और custom ingestion pipelines से payloads को छिपा सकती है, जो अलग extractor द्वारा archive को हैंडल करने से पहले ZIP सामग्री पर "peek" करते हैं।

---

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
