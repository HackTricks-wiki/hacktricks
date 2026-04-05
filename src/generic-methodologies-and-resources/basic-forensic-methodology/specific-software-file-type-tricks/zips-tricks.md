# ZIPs ट्रिक्स

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** for managing **zip files** are essential for diagnosing, repairing, and cracking zip files. Here are some key utilities:

- **`unzip`**: बताता है कि zip फ़ाइल क्यों decompress नहीं हो रही है।
- **`zipdetails -v`**: zip file format फ़ील्ड्स का विस्तृत विश्लेषण देता है।
- **`zipinfo`**: फ़ाइलों को extract किए बिना zip फ़ाइल की सामग्री सूचीबद्ध करता है।
- **`zip -F input.zip --out output.zip`** and **`zip -FF input.zip --out output.zip`**: corrupted zip फ़ाइलों की मरम्मत करने की कोशिश करते हैं।
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: brute-force cracking के लिए एक टूल, जो लगभग 7 characters तक के पासवर्ड के लिए प्रभावी है।

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

यह ध्यान रखना महत्वपूर्ण है कि password-protected zip फ़ाइलें अंदर के फ़ाइलनाम या फ़ाइल आकारों को **एन्क्रिप्ट नहीं करतीं**, यह एक security flaw है जो RAR या 7z फाइलों के साथ साझा नहीं होता क्योंकि वे इस जानकारी को एन्क्रिप्ट करते हैं। आगे, ZipCrypto method से एन्क्रिप्ट की गई zip फ़ाइलें यदि किसी compressed फ़ाइल की unencrypted copy उपलब्ध हो तो **plaintext attack** के प्रति vulnerable होती हैं। यह attack ज्ञात सामग्री का उपयोग करके zip का पासवर्ड क्रैक कर देता है — यह vulnerability [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) में विस्तार से बताई गई है और [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) में और समझाई गई है। हालाँकि, **AES-256** एन्क्रिप्शन के साथ सुरक्षित की गई zip फ़ाइलें इस plaintext attack से immune होती हैं, जो संवेदनशील डेटा के लिए मजबूत एन्क्रिप्शन चुनने के महत्त्व को दर्शाती हैं।

---

## APKs में संशोधित ZIP headers का उपयोग करके Anti-reversing ट्रिक्स

आधुनिक Android malware droppers malformed ZIP metadata का उपयोग करके static tools (jadx/apktool/unzip) को तोड़ते हैं, जबकि APK को डिवाइस पर installable बनाए रखते हैं। सबसे आम ट्रिक्स हैं:

- Fake encryption — ZIP General Purpose Bit Flag (GPBF) का bit 0 सेट करके
- parsers को confuse करने के लिए बड़े/custom Extra fields का दुरुपयोग
- असली artifacts को छिपाने के लिए file/directory name collisions (उदा., एक directory जिसका नाम `classes.dex/` असली `classes.dex` के बगल में)

### 1) Fake encryption (GPBF bit 0 set) बिना वास्तविक क्रिप्टो के

लक्षण:
- `jadx-gui` निम्न त्रुटियों के साथ fail करता है:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` core APK फ़ाइलों के लिए पासवर्ड पूछता है, जबकि एक वैध APK में encrypted `classes*.dex`, `resources.arsc`, या `AndroidManifest.xml` नहीं हो सकते:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails से पहचान:
```bash
zipdetails -v sample.apk | less
```
local और central headers के लिए General Purpose Bit Flag को देखें। एक स्पष्ट संकेतक मान है bit 0 set (Encryption) यहाँ तक कि core entries के लिए भी:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
ह्यूरिस्टिक: अगर एक APK डिवाइस पर इंस्टॉल होकर चलता है लेकिन मुख्य प्रविष्टियाँ टूल्स को "एन्क्रिप्टेड" दिखाई देती हैं, तो GPBF में छेड़छाड़ हुई थी।

समाधान: Local File Headers (LFH) और Central Directory (CD) दोनों प्रविष्टियों में GPBF का बिट 0 क्लियर करें। न्यूनतम byte-patcher:

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
अब आपको core entries पर `General Purpose Flag  0000` दिखाई देना चाहिए और tools फिर से APK को parse कर पाएँगे।

### 2) पार्सर्स को तोड़ने के लिए Large/custom Extra fields

हमलावर oversized Extra fields और odd IDs को headers में भर देते हैं ताकि decompilers अटक जाएँ। वास्तविक दुनिया में आप वहाँ custom markers (उदा., strings जैसे `JADXBLOCK`) embedded हुए देख सकते हैं।

निरीक्षण:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Examples observed: unknown IDs like `0xCAFE` ("Java Executable") or `0x414A` ("JA:") carrying large payloads.

DFIR heuristics:
- जब core entries पर Extra fields असामान्य रूप से बड़े हों (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) तो अलर्ट करें।
- उन एंट्रीज़ पर अनजान Extra IDs को संदिग्ध मानें।

Practical mitigation: archive को पुनर्निर्मित करने (उदा., निकाली गई फाइलों को पुनः-ज़िप करना) से हानिकारक Extra fields हट जाती हैं। यदि टूल्स नकली एन्क्रिप्शन के कारण निकालने से इनकार करते हैं, तो पहले ऊपर बताये अनुसार GPBF bit 0 को क्लियर करें, फिर पुनः पैकेज करें:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) फ़ाइल/डायरेक्टरी नाम टकराव (असली आर्टिफैक्ट छुपाना)

एक ZIP दोनों रख सकता है: एक फ़ाइल `X` और एक डायरेक्टरी `X/`। कुछ extractors और decompilers भ्रमित हो जाते हैं और डायरेक्टरी एंट्री के साथ असली फ़ाइल को ओवरले या छिपा सकते हैं। यह मुख्य APK नामों जैसे `classes.dex` के साथ एंट्रीज़ के टकराने पर देखा गया है।

प्राथमिक मूल्यांकन और सुरक्षित निष्कर्षण:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
प्रोग्रामेटिक पहचान पोस्ट-फिक्स:
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
Blue-team का detection विचार:
- फ़्लैग करें उन APKs को जिनके local headers encryption (GPBF bit 0 = 1) दिखाते हैं फिर भी install/run होते हैं।
- core entries पर large/unknown Extra fields को फ़्लैग करें (जैसे मार्कर `JADXBLOCK` खोजें)।
- path-collisions (`X` and `X/`) को फ़्लैग करें, विशेष रूप से `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` के लिए।

---

## अन्य malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

हालिया phishing campaigns एक single blob भेजती हैं जो वास्तव में **two ZIP files concatenated** होती है। प्रत्येक की अपनी End of Central Directory (EOCD) + central directory होती है। अलग-अलग extractors अलग directories parse करते हैं (7zip पहला पढ़ता है, WinRAR आखिरी), जिससे attackers ऐसे payloads छुपा सकते हैं जो केवल कुछ tools दिखाते हैं। यह उन basic mail gateway AV को भी बायपास करता है जो केवल पहले directory की जाँच करते हैं।

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
यदि एक से अधिक EOCD दिखाई दे या "data after payload" चेतावनियाँ हों, blob को विभाजित करें और प्रत्येक भाग का निरीक्षण करें:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

आधुनिक "better zip bomb" एक छोटा **kernel** (highly compressed DEFLATE block) बनाता है और overlapping local headers के माध्यम से उसे पुन: उपयोग करता है। हर central directory entry उसी compressed data की ओर इशारा करता है, जिससे nesting archives के बिना >28M:1 अनुपात प्राप्त होता है। जो libraries central directory sizes पर भरोसा करती हैं (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) उन्हें petabytes allocate करने के लिए मजबूर किया जा सकता है।

**Quick detection (duplicate LFH offsets)**
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
- Perform a dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` and ensure offsets are strictly increasing and unique.
- Extraction से पहले कुल अनcompressed आकार और entry count पर सीमा लगाएँ (`zipdetails -t` or custom parser).
- जब आपको निकालना अनिवार्य हो, इसे cgroup/VM के अंदर CPU+disk सीमाओं के साथ करें (अनbounded inflation crashes से बचें).

---

### Local-header बनाम central-directory parser भ्रम

हालिया differential-parser रिसर्च ने दिखाया कि ZIP ambiguity आधुनिक टूलचैन में अभी भी शोषण योग्य है। मुख्य विचार सरल है: कुछ सॉफ्टवेयर **Local File Header (LFH)** पर भरोसा करते हैं जबकि अन्य **Central Directory (CD)** पर भरोसा करते हैं, इसलिए एक ही archive विभिन्न टूल्स को अलग filenames, paths, comments, offsets, या entry sets दिखा सकता है।

व्यावहारिक आक्रामक उपयोग:
- एक upload filter, AV pre-scan, या package validator को CD में benign file दिखाएँ जबकि extractor अलग LFH name/path का पालन करे।
- डुप्लिकेट नामों, केवल एक संरचना में मौजूद एंट्रीज़, या अस्पष्ट Unicode path metadata (उदाहरण के लिए, Info-ZIP Unicode Path Extra Field `0x7075`) का दुरुपयोग करें ताकि अलग पार्सर अलग trees reconstruct करें।
- इसे path traversal के साथ मिलाएँ ताकि extraction के दौरान एक "harmless" archive view को write-primitive में बदला जा सके। Extraction पक्ष के लिए, देखें [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR प्राथमिक जाँच:
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
आपने "Complement it with:" लिखा है — मैं आगे बढ़ने के लिए उस फाइल/सामग्री की वास्तविक टेक्स्ट चाहिए होगी। कृपया src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md की सामग्री यहाँ चिपकाएँ, या बताएँ आप किस तरह का complemento चाह रहे हैं (उदाहरण: अतिरिक्त tricks, उदाहरण कमांड, detection/mitigation टिप्स)। मैं फिर वही Markdown/HTML संरचना बनाए रखते हुए संबंधित अंग्रेज़ी टेक्स्ट को हिन्दी में अनुवाद कर दूँगा।
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
ह्यूरिस्टिक्स:
- LFH/CD नाम मेल नहीं होने, duplicate filenames, multiple EOCD रिकॉर्ड, या final EOCD के बाद trailing bytes वाले आर्काइव को reject या isolate करें।
- असामान्य Unicode-path extra fields या inconsistent comments वाले ZIPs को संदिग्ध मानें अगर अलग-अलग tools extracted tree पर सहमत न हों।
- अगर analysis मूल bytes को preserve करने से अधिक महत्वपूर्ण है, तो sandbox में extraction के बाद strict parser के साथ archive को repackage करें और resulting file list की तुलना original metadata से करें।

This matters beyond package ecosystems: वही ambiguity class mail gateways, static scanners, और custom ingestion pipelines से payloads छुपा सकता है जो ZIP contents को किसी अलग extractor के archive handle करने से पहले "peek" करते हैं।

---



## संदर्भ

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
