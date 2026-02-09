# Mbinu za ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Vifaa vya mstari wa amri** vya kusimamia **zip files** ni muhimu kwa kubaini matatizo, kurekebisha, na cracking **zip files**. Hapa kuna zana muhimu:

- **`unzip`**: Inaonyesha kwanini zip file inaweza isifunguke.
- **`zipdetails -v`**: Inatoa uchambuzi wa kina wa vipengele vya muundo wa zip file.
- **`zipinfo`**: Inaorodhesha yaliyomo katika zip file bila kuyatoa.
- **`zip -F input.zip --out output.zip`** and **`zip -FF input.zip --out output.zip`**: Jaribu kurekebisha zip files zilizo corrupted.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana ya brute-force cracking ya nywila za zip, yenye ufanisi kwa nywila hadi takriban herufi 7.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) inatoa maelezo kamili juu ya muundo na viwango vya zip files.

Ni muhimu kutambua kwamba zip files zilizolindwa kwa password hazifanyi encrypt majina ya faili au ukubwa wa faili ndani yao, dosari ya usalama ambayo haipo kwa RAR au 7z ambazo hu-encrypt taarifa hizi. Zaidi ya hayo, zip files zilizo encrypted kwa ZipCrypto zinaweza kuwa dhaifu kwa plaintext attack ikiwa nakala isiyo-encrypted ya faili iliyoshinikizwa inapatikana. Shambulio hili linatumia yaliyomo yanayojulikana kuvunja password ya zip, udhaifu uliotajwa katika makala ya HackThis na kuelezwa zaidi katika karatasi hii ya kitaaluma. Hata hivyo, zip files zilizolindwa kwa AES-256 encryption zina kinga dhidi ya plaintext attack, ikionyesha umuhimu wa kuchagua mbinu za encryption salama kwa data nyeti.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers hutumia malformed ZIP metadata kuvunja zana za static (jadx/apktool/unzip) huku zikidumisha APK iweze kusakinishwa kwenye kifaa. Mbinu zinazotumika mara kwa mara ni:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Dalili:
- `jadx-gui` inashindwa kwa makosa kama:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` inauliza password kwa faili kuu za APK ingawa APK halali haiwezi kuwa na encrypted `classes*.dex`, `resources.arsc`, au `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Kugundua kwa zipdetails:
```bash
zipdetails -v sample.apk | less
```
Angalia General Purpose Bit Flag kwa local na central headers. Thamani inayofichua ni bit 0 set (Encryption) hata kwa core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiki: Ikiwa APK inasakinishwa na kuendeshwa kwenye kifaa lakini viingilio vya msingi vinaonekana "encrypted" kwa zana, GPBF ilibadilishwa.

Rekebisha kwa kufuta bit 0 ya GPBF katika viingilio vya Local File Headers (LFH) na Central Directory (CD). Minimal byte-patcher:

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
Sasa unapaswa kuona `General Purpose Flag  0000` kwenye entries za msingi na zana zitasoma APK tena.

### 2) Mawanja makubwa/maalum ya Extra kuvunja parsers

Washambuliaji huwaweka mawanja ya Extra yenye ukubwa kupita kiasi na IDs zisizo za kawaida ndani ya vichwa ili kuwachanganya decompilers. Katika mazingira halisi unaweza kuona alama maalum (kwa mfano, mnyororo kama `JADXBLOCK`) iliyowekwa hapo.

Ukaguzi:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Mifano yaliyobainika: vitambulisho visivyofahamika kama `0xCAFE` ("Java Executable") au `0x414A` ("JA:") vikibeba payload kubwa.

DFIR heuristics:
- Waarifu pale Extra fields zinapokuwa kubwa kupita kawaida kwenye core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Chukulia Extra IDs zisizojulikana kwenye entries hizo kama zenye shaka.

Urejesho wa vitendo: kujenga upya archive (mfano, re-zipping extracted files) kunafuta Extra fields hatari. Ikiwa zana zinakataa kutoa kwa sababu ya fake encryption, kwanza futa GPBF bit 0 kama ilivyo hapo juu, kisha pakiwa tena:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Mgongano ya majina ya Faili/Saraka (kuficha mabaki halisi)

ZIP inaweza kuwa na faili `X` na pia saraka `X/`. Baadhi ya extractors na decompilers huvurugika na wanaweza kuweka juu (overlay) au kuficha faili halisi kwa kipengee cha saraka. Hii imeonekana wakati ingizo linapogongana na majina ya msingi ya APK kama `classes.dex`.

Kuchuja na uchimbaji salama:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Kiambishi cha baada cha ugundaji kwa programu:
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
Mapendekezo ya utambuzi kwa Blue-team:
- Taja APKs ambazo vichwa vyao vya ndani vinaonyesha encryption (GPBF bit 0 = 1) lakini zinaweza kufunguliwa/kukimbizwa.
- Taja Extra fields kubwa/zisizojulikana kwenye core entries (tazama alama kama `JADXBLOCK`).
- Taja path-collisions (`X` and `X/`) hasa kwa `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Mbinu nyingine hatarishi za ZIP (2024–2025)

### Central directories zilizoambatanishwa (multi-EOCD evasion)

Kampeni za hivi karibuni za phishing hutuma blob moja ambalo kwa kweli ni **faili mbili za ZIP zilioambatanishwa**. Kila moja ina End of Central Directory (EOCD) yake + central directory. Extractors tofauti huchambua directories tofauti (7zip husoma ya kwanza, WinRAR ya mwisho), na hivyo kuwapa attackers uwezo wa kuficha payloads ambazo zana chache tu zinaonyesha. Hii pia inavuka mail gateway AV ya msingi ambayo inachunguza tu directory ya kwanza.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Ikiwa EOCD inatokea zaidi ya moja au kuna onyo la "data after payload", gawanya blob na chunguza kila sehemu:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" huunda **kernel** ndogo (DEFLATE block iliyoshinikizwa kwa kiwango kikubwa) na kuitumia tena kupitia overlapping local headers. Kila central directory entry inaonyesha kwa data iliyoshinikizwa ile ile, ikipata uwiano wa >28M:1 bila kuweka archives ndani ya nyingine. Maktaba zinazomwamini ukubwa wa central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP kabla ya hardened builds) zinaweza kulazimishwa kutenga petabytes.

**Utambuzi wa haraka (duplicate LFH offsets)**
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
**Ushughulikiaji**
- Fanya dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` na uhakikishe offsets zinaongezeka kwa mpangilio na ni za kipekee.
- Weka kikomo kwa jumla ya ukubwa usiofinywa na idadi ya entry kabla ya extraction (`zipdetails -t` or custom parser).
- Unapohitajika extract, fanya ndani ya cgroup/VM yenye vikwazo vya CPU na disk (epuka crashes za inflation zisizo na kikomo).

---

## Marejeleo

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
