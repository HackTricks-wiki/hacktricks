# ZIPs tricks

**Command-line tools** द्वारा **zip files** को manage करना, उनकी diagnosis, repairing और cracking के लिए essential है। यहाँ कुछ key utilities दी गई हैं:<sup>[[1]](#references)</sup>

- **`unzip`**: यह बताता है कि कोई zip file decompress क्यों नहीं हो सकती।
- **`zipdetails -v`**: zip file format के fields का detailed analysis प्रदान करता है।<sup>[[3]](#references)</sup>
- **`zipinfo`**: zip file के contents को extract किए बिना list करता है।
- **`zip -F input.zip --out output.zip`** और **`zip -FF input.zip --out output.zip`**: corrupted zip files को repair करने का प्रयास करते हैं।
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: zip passwords की brute-force cracking के लिए एक tool, जो लगभग 7 characters तक के passwords के लिए effective है।

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) zip files की structure और standards पर comprehensive details प्रदान करती है।<sup>[[4]](#references)</sup>

यह ध्यान रखना crucial है कि traditional password-protected ZIP files आमतौर पर filenames और file sizes को visible छोड़ती हैं, जबकि RAR और 7z द्वारा supported header-encryption modes ऐसा नहीं करते। इसके अलावा, पुराने ZipCrypto method से encrypted ZIP files **plaintext attack** के प्रति vulnerable होती हैं, यदि किसी compressed file की unencrypted copy available हो।<sup>[[1]](#references)</sup> यह attack known content का उपयोग करके ZIP का password crack करता है, जैसा कि [इस academic paper](https://math.ucr.edu/~mike/zipattacks.pdf) में explain किया गया है और [इस Hack This Site walk-through](https://www.hackthissite.org/articles/read/793) में demonstrate किया गया है।<sup>[[11]](#references)[[12]](#references)</sup> हालांकि, ZipCrypto known-plaintext attack **AES-256** encryption से secured entries पर लागू नहीं होता।<sup>[[1]](#references)</sup>

---

## manipulated ZIP headers का उपयोग करके APKs में Anti-reversing tricks

Modern Android malware droppers malformed ZIP metadata का उपयोग static tools (jadx/apktool/unzip) को break करने के लिए करते हैं, जबकि APK को device पर installable बनाए रखते हैं। सबसे common tricks हैं:<sup>[[2]](#references)</sup>

- ZIP General Purpose Bit Flag (GPBF) के bit 0 को set करके Fake encryption
- Parsers को confuse करने के लिए बड़े/custom Extra fields का abuse
- Real artifacts को hide करने के लिए file/directory name collisions (जैसे, real `classes.dex` के पास `classes.dex/` नाम की directory)

### 1) बिना real crypto के Fake encryption (GPBF bit 0 set)

Symptoms:
- `jadx-gui` इस तरह के errors के साथ fail होता है:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` core APK files के लिए password prompt करता है, हालांकि valid APK में `classes*.dex`, `resources.arsc` या `AndroidManifest.xml` encrypted नहीं हो सकते:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

zipdetails से Detection:
```bash
zipdetails -v sample.apk | less
```
स्थानीय और केंद्रीय headers के लिए General Purpose Bit Flag देखें। core entries के लिए भी bit 0 का set होना (Encryption) एक संकेतक मान है:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristic: यदि कोई APK डिवाइस पर install और run हो जाता है, लेकिन core entries tools को "encrypted" दिखाई देती हैं, तो GPBF के साथ छेड़छाड़ की गई है।

इसे Local File Headers (LFH) और Central Directory (CD) entries, दोनों में GPBF bit 0 को clear करके ठीक करें। Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit-clear patcher</summary>
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
अब आपको core entries पर `General Purpose Flag  0000` दिखाई देना चाहिए और tools APK को फिर से parse कर पाएंगे।

### 2) Parsers को बाधित करने के लिए बड़े/custom Extra fields

Attackers decompilers को बाधित करने के लिए headers में oversized Extra fields और असामान्य IDs भर देते हैं। वास्तविक परिस्थितियों में आपको वहाँ embedded custom markers (जैसे `JADXBLOCK` जैसी strings) दिखाई दे सकती हैं।

Inspection:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
देखे गए उदाहरण: `0xCAFE` ("Java Executable") या `0x414A` ("JA:") जैसी अज्ञात IDs, जिनमें बड़े payloads थे।<sup>[[2]](#references)</sup>

DFIR heuristics:
- core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) पर Extra fields असामान्य रूप से बड़े होने पर alert करें।
- उन entries पर अज्ञात Extra IDs को suspicious मानें।

Practical mitigation: archive को दोबारा बनाना (जैसे, extracted files को फिर से zip करना) malicious Extra fields को हटा देता है। यदि fake encryption के कारण tools extract करने से इनकार करें, तो पहले ऊपर बताए अनुसार GPBF bit 0 को clear करें, फिर repackage करें:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions (वास्तविक artifacts को छिपाना)

एक ZIP में एक file `X` और एक directory `X/` दोनों हो सकते हैं। कुछ extractors और decompilers भ्रमित हो जाते हैं और directory entry के साथ वास्तविक file को overlay या hide कर सकते हैं। ऐसा `classes.dex` जैसे core APK names से collide करने वाली entries के साथ देखा गया है।

Triage और safe extraction:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Fix के बाद Programmatic detection:
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
Blue-team detection ideas:
- उन APKs को flag करें जिनके local headers encryption को mark करते हैं (GPBF bit 0 = 1), फिर भी वे install/run होते हैं।
- core entries पर बड़े/unknown Extra fields को flag करें (जैसे `JADXBLOCK` जैसे markers देखें)।
- विशेष रूप से `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` के लिए path-collisions (`X` और `X/`) को flag करें।

---

## Other malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

2024 के एक phishing campaign में attackers ने एक single blob भेजा, जो वास्तव में **दो ZIP files को concatenate करके बनाया गया था**। प्रत्येक में अपना End of Central Directory (EOCD) record और central directory था। अलग-अलग extractors ने अलग-अलग directories parse कीं (7-Zip ने पहली, जबकि WinRAR ने आखिरी पढ़ी), जिससे attackers ऐसे payloads छिपा सके जिन्हें केवल कुछ tools दिखाते थे; जो scanners केवल एक directory inspect करते हैं, वे दूसरे archive को miss कर सकते हैं।<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
यदि एक से अधिक EOCD दिखाई दे या "data after payload" warnings हों, तो blob को विभाजित करें और प्रत्येक भाग का निरीक्षण करें:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs एक छोटे **kernel** (अत्यधिक compressed DEFLATE block) का निर्माण करते हैं और overlapping entries में उसका पुनः उपयोग करते हैं। Full-overlap variants कई central-directory entries को एक ही local header की ओर point करते हैं, जबकि quoted-overlap variants DEFLATE streams के अंदर local headers को quote करते हैं; प्रकाशित construction nested archives के बिना 28M:1 से अधिक अनुपात प्राप्त करता है।<sup>[[7]](#references)</sup>

**त्वरित पहचान (duplicate LFH offsets)**
```python
# detect full-overlap variants by identical relative offsets
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
- एक dry-run walk करें: `zipdetails -v file.zip | grep -n "Local Header Offset"` और संदर्भित local-header offsets तथा compressed-data ranges की तुलना करें; duplicate offsets full-overlap variants का संकेत देते हैं।<sup>[[7]](#references)[[8]](#references)</sup>
- extraction से पहले parser के साथ स्वीकार्य कुल uncompressed size और entry count की सीमा तय करें; `zipinfo -t file.zip` totals रिपोर्ट करता है, लेकिन safety limit लागू नहीं करता।<sup>[[8]](#references)</sup>
- जब extraction करना आवश्यक हो, तो इसे CPU और disk limits वाले cgroup/VM के अंदर करें (unbounded inflation crashes से बचें)।<sup>[[8]](#references)</sup>

---

### Local-header बनाम central-directory parser confusion

हालिया differential-parser research ने दिखाया कि ZIP ambiguity अभी भी modern toolchains में exploitable है। मुख्य विचार सरल है: कुछ software **Local File Header (LFH)** पर भरोसा करते हैं, जबकि अन्य **Central Directory (CD)** पर, इसलिए एक archive अलग-अलग tools के सामने अलग filenames, paths, comments, offsets या entry sets प्रस्तुत कर सकता है।<sup>[[9]](#references)</sup>

Practical offensive uses:
- किसी upload filter, AV pre-scan या package validator को CD में एक benign file दिखाएँ, जबकि extractor किसी अलग LFH name/path को मान्य करे।
- duplicate names, केवल एक structure में मौजूद entries या ambiguous Unicode path metadata (उदाहरण के लिए, Info-ZIP Unicode Path Extra Field `0x7075`) का दुरुपयोग करें, ताकि अलग-अलग parsers अलग trees reconstruct करें।
- इसे path traversal के साथ combine करके extraction के दौरान एक "harmless" archive view को write-primitive में बदलें। Extraction side के लिए [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) देखें।

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
कृपया वह अंग्रेज़ी सामग्री भेजें जिसे आप पूरक या अनुवादित करवाना चाहते हैं।
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
ह्यूरिस्टिक्स:
- Security-sensitive ingestion के लिए, mismatched LFH/CD names, duplicate filenames, multiple EOCD records या अंतिम EOCD के बाद trailing bytes वाले archives को reject या isolate करें।<sup>[[9]](#references)[[10]](#references)</sup>
- Unusual Unicode-path extra fields या inconsistent comments वाले ZIPs को suspicious मानें, यदि अलग-अलग tools extracted tree के बारे में असहमत हों।<sup>[[4]](#references)[[9]](#references)</sup>
- यदि original bytes को preserve करने से analysis अधिक महत्वपूर्ण है, तो sandbox में extraction के बाद strict parser से archive को दोबारा package करें और resulting file list की original metadata से तुलना करें।

यह package ecosystems से आगे भी महत्वपूर्ण है: यही ambiguity class mail gateways, static scanners और custom ingestion pipelines से payloads को छिपा सकती है, जो ZIP contents को "peek" करते हैं और फिर कोई अलग extractor archive को handle करता है।<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress script)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistic Web Mission, Level 15 (known-plaintext ZIP attack)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
