# Mbinu za ZIPs

{{#include ../../../banners/hacktricks-training.md}}

Vifaa vya mstari wa amri kwa kusimamia zip files ni muhimu kwa kutambua matatizo, kutengeneza, na kuvunja zip files. Hapa kuna zana kuu:

- **`unzip`**: Inaonyesha kwa nini zip file haiwezi ku-decompress.
- **`zipdetails -v`**: Inatoa uchambuzi wa kina wa fields za muundo wa zip file.
- **`zipinfo`**: Inaorodhesha yaliyomo ndani ya zip file bila kuvi-extract.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Jaribu kutengeneza zip files zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana ya kuvunja nywila za zip kwa brute-force, inayofanya kazi vizuri kwa nywila za takriban hadi herufi 7.

[Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) inatoa maelezo kamili juu ya muundo na viwango vya zip files.

Ni muhimu kutambua kwamba password-protected zip files hazisimbwi majina ya faili au ukubwa wa faili ndani yake, kasoro ya usalama ambayo haipo kwenye RAR au 7z ambazo zinaficha taarifa hizi. Zaidi ya hayo, zip files zilizosimbwa kwa njia ya zamani ZipCrypto zinakabiliwa na plaintext attack ikiwa nakala isiyosimbwa ya faili iliyobanwa inapatikana. Shambulio hili linatumia yaliyomo yanayojulikana kuvunja password ya zip, udhaifu uliobainishwa katika [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) na umefafanuliwa zaidi katika [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Hata hivyo, zip files zilizosimbwa kwa **AES-256** hazina hatari ya plaintext attack, jambo linaloonyesha umuhimu wa kuchagua mbinu salama za usimbaji kwa data nyeti.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers hutumia malformed ZIP metadata kuvunja static tools (jadx/apktool/unzip) huku zikihakikisha APK inaweza ku-install kwenye kifaa. Mbinu za kawaida ni:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Dalili:
- `jadx-gui` inashindwa na makosa kama:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` inauliza password kwa ajili ya faili kuu za APK ingawa APK halali haiwezi kuwa na `classes*.dex`, `resources.arsc`, au `AndroidManifest.xml` zilizofichwa:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Utambuzi kwa zipdetails:
```bash
zipdetails -v sample.apk | less
```
Tazama General Purpose Bit Flag kwa local and central headers. Thamani inayoonyesha ni bit 0 imewekwa (Encryption) hata kwa core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiki: Ikiwa APK inasakinishwa na inafanya kazi kwenye kifaa lakini rekodi za msingi zinaonekana "encrypted" kwa zana, GPBF iliharibiwa.

Rekebisha kwa kufuta bit 0 ya GPBF katika Local File Headers (LFH) na rekodi za Central Directory (CD). Patcher ndogo ya byte:

<details>
<summary>Patcher ndogo ya kufuta biti ya GPBF</summary>
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
Sasa unapaswa kuona `General Purpose Flag  0000` kwenye core entries na tools zita-parse APK tena.

### 2) Extra fields kubwa/custom za kuvunja parsers

Washambulizi huweka Extra fields kubwa kupita kiasi na odd IDs ndani ya headers ili kuifanya decompilers kushindwa. Katika mazingira halisi unaweza kuona custom markers (mfano, strings kama `JADXBLOCK`) zikiingizwa hapo.

Ukaguzi:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Mifano iliyoshuhudiwa: vitambulisho visivyojulikana kama `0xCAFE` ("Java Executable") au `0x414A` ("JA:") vikiwa na payload kubwa.

Vigezo vya DFIR:
- Taarifu wakati Extra fields zinapokuwa kubwa isivyokuwa kawaida kwenye core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Chukulia Extra IDs zisizojulikana kwenye entries hizo kuwa za kutiliwa shaka.

Kupunguza hatari kwa vitendo: kujenga upya archive (e.g., re-zipping extracted files) huondoa Extra fields hatarishi. Ikiwa zana zinakataa kuvunja kutokana na encryption ya bandia, kwanza futa GPBF bit 0 kama ilivyo hapo juu, kisha pakia tena:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions (kuficha artefakti halisi)

ZIP inaweza kuwa na faili `X` na pia directory `X/`. Baadhi ya extractors na decompilers hupata mkanganyiko na zinaweza kuweka juu au kuficha faili halisi kwa kipengee cha directory. Hili limeonekana kwa entries zinazogongana na majina ya msingi ya APK kama `classes.dex`.

Triage na uondoaji salama:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Kiongezo (post-fix) cha ugunduzi wa kimaprogramu:
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
Mapendekezo za utambuzi za Blue-team:
- Alamisha APKs ambazo vichwa vya ndani vinaonyesha encryption (GPBF bit 0 = 1) lakini zinaweka/kukimbia.
- Alamisha Extra fields kubwa/zisizojulikana kwenye core entries (tazama alama kama `JADXBLOCK`).
- Alamisha path-collisions (`X` and `X/`) hasa kwa `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Mbinu nyingine za ZIP zenye madhara (2024–2026)

### Directories kuu zilizounganishwa (multi-EOCD evasion)

Campaigns za hivi karibuni za phishing hutoa blob moja ambayo kwa kweli ni **ZIP files mbili zilizounganishwa**. Kila moja ina End of Central Directory (EOCD) yake + central directory. Extractors tofauti husoma directories tofauti (7zip reads the first, WinRAR the last), ikimruhusu attacker kuficha payloads ambazo zana chache tu zinaonyesha. Hii pia inaepuka basic mail gateway AV ambayo inachunguza tu directory ya kwanza.

**Amri za Triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Ikiwa EOCD zaidi ya moja inatokea au kuna onyo la "data after payload", gawanya blob na chunguza kila sehemu:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Za kisasa "better zip bomb" hujenga **kernel** ndogo (highly compressed DEFLATE block) na kuitumia tena kupitia overlapping local headers. Kila central directory entry inaelekeza kwenye data iliyobanwa ile ile, ikifikisha uwiano wa >28M:1 bila nesting archives. Maktaba ambazo zinaamini central directory sizes (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) zinaweza kulazimishwa kugawa petabytes.

**Ugunduzi wa haraka (duplicate LFH offsets)**
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
**Kukabiliana**
- Fanya dry-run: `zipdetails -v file.zip | grep -n "Rel Off"` na uhakikishe offsets zinaongezeka kwa mpangilio (strictly increasing) na ni za kipekee.
- Weka kikomo kwa jumla ya ukubwa isiyo-kompreshendi na idadi ya entry kabla ya extraction (`zipdetails -t` or custom parser).
- Unapohitaji extract, fanya ndani ya cgroup/VM yenye mipaka ya CPU+disk (epuka unbounded inflation crashes).

---

### Mkanganyiko wa parser: Local-header vs central-directory

Utafiti wa hivi karibuni wa differential-parser ulibaini kuwa kutokuwa wazi kwa ZIP bado kunaweza kutumika katika toolchains za kisasa. Wazo kuu ni rahisi: baadhi ya software zinaamini **Local File Header (LFH)** wakati nyingine zinaamini **Central Directory (CD)**, hivyo archive moja inaweza kuonyesha majina tofauti ya faili, paths, comments, offsets, au seti za entries kwa zana tofauti.

Matumizi ya vitendo ya mashambulizi:
- Fanya upload filter, AV pre-scan, au package validator ione faili isiyo-hatari katika CD wakati extractor inaheshimu jina/path tofauti kutoka LFH.
- Tumia majina rudufu, entries zilizopo tu katika moja ya muundo, au metadata ya Unicode path isiyoeleweka (kwa mfano, Info-ZIP Unicode Path Extra Field `0x7075`) ili parsers tofauti wajenge miti tofauti.
- Changanya hili na path traversal ili kugeuza muonekano "harmless" wa archive kuwa write-primitive wakati wa extraction. Kwa upande wa extraction, angalia [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Nahitaji yaliyomo ya faili ambayo unataka nitafsiri na/au kuongeza. Tafadhali weka hapa maudhui ya src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md au eleza ni nini ungependa "complement" ifanye (maneno ya kuongeza, sehemu maalum, nk.).
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Kanuni za uchambuzi:
- Kataa au zitenganishe archives zenye LFH/CD names zisizolingana, filenames zinazorudia, rekodi nyingi za EOCD, au trailing bytes baada ya EOCD ya mwisho.
- Chukulia ZIPs zinazotumia unusual Unicode-path extra fields au comments zisizolingana kuwa za kutiliwa shaka ikiwa zana tofauti hazikubaliani kuhusu extracted tree.
- Ikiwa uchambuzi ni muhimu zaidi kuliko kuhifadhi original bytes, repack the archive kwa strict parser baada ya extraction kwenye sandbox na linganisha resulting file list na original metadata.

Hii ni muhimu zaidi ya package ecosystems: class moja ya ambiguity inaweza kuficha payloads kutoka kwa mail gateways, static scanners, na custom ingestion pipelines ambazo "peek" at ZIP contents kabla extractor tofauti ashughulikie archive.

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
