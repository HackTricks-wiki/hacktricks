# Mbinu za ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** za kusimamia **zip files** ni muhimu kwa kuchunguza, kurekebisha, na kuvunja zip files. Hapa kuna utilities muhimu:<sup>[[1]](#references)</sup>

- **`unzip`**: Hufichua sababu inayoweza kufanya zip file ishindwe kufunguka.
- **`zipdetails -v`**: Hutoa uchanganuzi wa kina wa sehemu za format ya zip file.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Huorodhesha yaliyomo kwenye zip file bila kuyatoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Hujaribu kurekebisha zip files zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Tool ya brute-force cracking ya passwords za zip, inayofaa kwa passwords zenye hadi takriban herufi 7.

[Specification ya format ya Zip file](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) hutoa maelezo kamili kuhusu muundo na standards za zip files.<sup>[[4]](#references)</sup>

Ni muhimu kutambua kwamba ZIP files za kawaida zilizolindwa kwa password kwa ujumla huacha filenames na file sizes zikiwa zinaonekana, tofauti na header-encryption modes zinazoungwa mkono na RAR na 7z. Zaidi ya hayo, ZIP files zilizofichwa kwa kutumia method ya zamani ya ZipCrypto ziko hatarini kwa **plaintext attack** ikiwa nakala isiyofichwa ya file iliyocompressiwa inapatikana.<sup>[[1]](#references)</sup> Attack hii hutumia content inayojulikana kuvunja password ya ZIP, kama ilivyoelezwa katika [academic paper hii](https://math.ucr.edu/~mike/zipattacks.pdf) na kuonyeshwa katika [walk-through hii ya Hack This Site](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Hata hivyo, ZipCrypto known-plaintext attack haitumiki kwa entries zilizolindwa kwa encryption ya **AES-256**.<sup>[[1]](#references)</sup>

---

## Mbinu za anti-reversing katika APKs kwa kutumia ZIP headers zilizobadilishwa

Modern Android malware droppers hutumia ZIP metadata iliyoharibiwa kuvuruga static tools (jadx/apktool/unzip), huku APK ikiendelea kusakinika kwenye device. Mbinu zinazotumika zaidi ni:<sup>[[2]](#references)</sup>

- Fake encryption kwa kuweka bit 0 ya ZIP General Purpose Bit Flag (GPBF)
- Kutumia vibaya Extra fields kubwa/custom ili kuchanganya parsers
- Migongano ya majina ya file/directory ili kuficha artifacts halisi (kwa mfano, directory inayoitwa `classes.dex/` iliyo karibu na `classes.dex` halisi)

### 1) Fake encryption (GPBF bit 0 set) bila crypto halisi

Dalili:
- `jadx-gui` hushindwa na errors kama:

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` huomba password kwa core APK files ingawa APK halali haiwezi kuwa na `classes*.dex`, `resources.arsc`, au `AndroidManifest.xml` zilizofichwa:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detection kwa kutumia zipdetails:
```bash
zipdetails -v sample.apk | less
```
Angalia General Purpose Bit Flag kwa local na central headers. Thamani inayoashiria ni bit 0 kuwa imewekwa (Encryption) hata kwa core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristic: Ikiwa APK inasakinishwa na kuendeshwa kwenye kifaa, lakini entries za msingi zinaonekana kuwa "encrypted" kwa tools, GPBF imechezewa.

Rekebisha kwa kufuta bit 0 ya GPBF katika Local File Headers (LFH) na entries za Central Directory (CD). Minimal byte-patcher:

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

Matumizi:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sasa unapaswa kuona `General Purpose Flag  0000` kwenye entries za msingi, na tools zitaweza ku-parse APK tena.

### 2) Large/custom Extra fields to break parsers

Attackers huweka Extra fields kubwa kupita kiasi na IDs zisizo za kawaida kwenye headers ili kuathiri decompilers. Katika mazingira halisi unaweza kuona custom markers (kwa mfano, strings kama `JADXBLOCK`) zikiwa zimewekwa humo.

Ukaguzi:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Mifano iliyobainika: IDs zisizojulikana kama `0xCAFE` ("Java Executable") au `0x414A` ("JA:") zinazobeba payloads kubwa.<sup>[[2]](#references)</sup>

Heuristics za DFIR:
- Toa alert wakati Extra fields ni kubwa isivyo kawaida kwenye core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Chukulia Extra IDs zisizojulikana kwenye entries hizo kuwa suspicious.

Mitigation ya vitendo: kujenga upya archive (kwa mfano, kuunda upya ZIP ya files zilizotolewa) huondoa Extra fields hasidi. Ikiwa tools zinakataa kutoa files kwa sababu ya encryption bandia, kwanza clear GPBF bit 0 kama ilivyo hapo juu, kisha package upya:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Migongano ya majina ya faili/ direktori (kuficha artifacts halisi)

ZIP inaweza kuwa na faili `X` pamoja na direktori `X/`. Baadhi ya extractors na decompilers huchanganyikiwa na zinaweza kuweka juu ya au kuficha faili halisi kwa entry ya direktori. Hili limeonekana kwa entries zinazogongana na majina msingi ya APK kama `classes.dex`.

Triage na extraction salama:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Utambuzi wa kiprogramu baada ya marekebisho:
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
Mawazo ya utambuzi kwa Blue-team:
- Weka alama kwa APK ambazo local headers zake zinaonyesha encryption (GPBF bit 0 = 1), lakini bado zinaweza kusakinishwa/kuendeshwa.
- Weka alama kwa Extra fields kubwa/zisizojulikana kwenye core entries (tafuta markers kama `JADXBLOCK`).
- Weka alama kwa path-collisions (`X` na `X/`) hasa kwa `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Mbinu nyingine hasidi za ZIP (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Katika phishing campaign ya 2024, attackers walituma blob moja ambayo kwa kweli ilikuwa **ZIP files mbili zilizounganishwa**. Kila moja ilikuwa na rekodi yake ya End of Central Directory (EOCD) na central directory. Extractors tofauti ziliparse directories tofauti (7-Zip ilisoma ya kwanza, huku WinRAR ikisoma ya mwisho), hivyo kuwawezesha attackers kuficha payloads ambazo baadhi tu ya tools ziliweza kuonyesha; scanners zinazokagua directory moja pekee zinaweza kukosa archive nyingine.<sup>[[5]](#references)[[6]](#references)</sup>

**Amri za Triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Ikiwa zaidi ya EOCD moja itaonekana au kuna maonyo ya "data after payload", gawanya blob na kagua kila sehemu:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs huunda **kernel** ndogo (DEFLATE block iliyobanwa kwa kiwango kikubwa) na kuitumia tena katika entries zinazoingiliana. Full-overlap variants huelekeza entries nyingi za central directory kwenye local header moja, huku quoted-overlap variants zikiweka nukuu za local headers ndani ya DEFLATE streams; construction iliyochapishwa hufikia zaidi ya 28M:1 bila nested archives.<sup>[[7]](#references)</sup>

**Utambuzi wa haraka (duplicate LFH offsets)**
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
**Ushughulikiaji**
- Fanya ukaguzi wa dry-run: `zipdetails -v file.zip | grep -n "Local Header Offset"` na linganisha offsets za local-header zilizorejelewa pamoja na safu za data iliyobanwa; offsets zinazorudiwa zinaashiria variants zenye overlap kamili.<sup>[[7]](#references)[[8]](#references)</sup>
- Weka kikomo cha ukubwa wa jumla unaokubaliwa baada ya kufunguliwa na idadi ya entries kabla ya extraction kwa kutumia parser; `zipinfo -t file.zip` huripoti jumla hizo lakini hailazimishi kikomo cha usalama.<sup>[[8]](#references)</sup>
- Unapolazimika kufanya extraction, fanyia ndani ya cgroup/VM yenye vikomo vya CPU na disk (epuka crashes zinazosababishwa na inflation isiyo na kikomo).<sup>[[8]](#references)</sup>

---

### Mkanganyiko kati ya parser ya local-header na central-directory

Utafiti wa hivi karibuni wa differential-parser umeonyesha kuwa utata wa ZIP bado unaweza kutumiwa katika toolchains za kisasa. Wazo kuu ni rahisi: baadhi ya software huamini **Local File Header (LFH)**, huku nyingine zikiamini **Central Directory (CD)**, hivyo archive moja inaweza kuwasilisha filenames, paths, comments, offsets, au entry sets tofauti kwa tools tofauti.<sup>[[9]](#references)</sup>

Matumizi ya kiutendaji ya offensive:
- Fanya upload filter, AV pre-scan, au package validator ione file salama katika CD, huku extractor ikifuata jina/path tofauti ya LFH.
- Tumia vibaya majina yaliyorudiwa, entries zilizopo katika structure moja pekee, au metadata yenye utata ya Unicode path (kwa mfano, Info-ZIP Unicode Path Extra Field `0x7075`) ili parsers tofauti zijenge trees tofauti.
- Unganisha hili na path traversal ili kugeuza mwonekano wa archive "usio na madhara" kuwa write-primitive wakati wa extraction. Kwa upande wa extraction, tazama [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Uchunguzi wa awali wa DFIR:
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
Iongeze kwa:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Kanuni za utambuzi:
- Kwa ingestion inayohusiana na usalama, kataa au tenga archives zenye majina ya LFH/CD yasiyolingana, filenames zilizorudiwa, rekodi nyingi za EOCD, au bytes zilizo nyuma ya EOCD ya mwisho.<sup>[[9]](#references)[[10]](#references)</sup>
- Chukulia ZIP zinazotumia extra fields zisizo za kawaida za Unicode-path au comments zisizolingana kuwa za kutiliwa shaka ikiwa tools tofauti hazikubaliani kuhusu tree iliyotolewa.<sup>[[4]](#references)[[9]](#references)</sup>
- Ikiwa uchanganuzi ni muhimu zaidi kuliko kuhifadhi bytes asilia, tengeneza upya archive kwa kutumia parser madhubuti baada ya extraction kwenye sandbox, kisha linganisha file list inayotokana na metadata asilia.

Hili ni muhimu zaidi ya package ecosystems: aina hii ya utata inaweza kuficha payloads kutoka kwa mail gateways, static scanners, na custom ingestion pipelines ambazo "huangalia kwa haraka" yaliyomo kwenye ZIP kabla ya extractor tofauti kushughulikia archive.<sup>[[9]](#references)</sup>

---



## References

- [1] [Mwongozo wa Uchunguzi wa CTF (Blogu ya Mike, kategoria ya CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Sehemu ya 1 – Multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress script)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Maelezo ya Muundo wa Faili ya ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Muundo Unaobadilika wa ZIP Archives Umetumiwa Kuficha Malware Bila Kugunduliwa (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers huficha malware katika shambulio jipya la faili za ZIP — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Kuelewa Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [ZIP yangu si ZIP yako: Kutambua na Kutumia Semantic Gaps Kati ya ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Kuzuia mashambulio ya mkanganyiko wa ZIP parser kwenye Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistic Web Mission, Level 15 (known-plaintext ZIP attack)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
