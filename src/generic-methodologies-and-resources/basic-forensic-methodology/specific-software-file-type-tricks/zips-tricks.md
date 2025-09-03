# Mbinu za ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** za kusimamia **zip files** ni muhimu kwa uchunguzi, ukarabati, na kuvunja zip files. Hapa kuna utiliti kuu:

- **`unzip`**: Inaonyesha kwa nini faili ya zip inaweza kushindwa kutolewa.
- **`zipdetails -v`**: Inatoa uchambuzi wa kina wa mashamba ya muundo wa zip file.
- **`zipinfo`**: Inaorodhesha yaliyomo ya zip file bila kuyatoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Jaribu kurekebisha zip files zilizo haribika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Chombo cha brute-force kuvunja nywila za zip, kinachofaa kwa nywila hadi takriban herufi 7.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) inatoa maelezo kamili juu ya muundo na viwango vya zip files.

Ni muhimu kutambua kwamba zip files zilizolindwa kwa nywila hazifichi majina ya faili au ukubwa wa faili ndani yao, kosa la usalama ambalo halitokei kwenye RAR au 7z ambazo huficha taarifa hizi. Zaidi ya hayo, zip files zilizoencrypted kwa njia ya zamani ya ZipCrypto zina uwezekano wa kufahamika kwa plaintext attack ikiwa nakala isiyofichwa ya faili iliyofinyangwa inapatikana. Shambulio hili linatumia yaliyomo yanayojulikana kuvunja nywila ya zip, udhaifu uliobainishwa katika makala ya HackThis na umeelezewa zaidi katika karatasi hii ya kitaaluma. Hata hivyo, zip files zilizo secured kwa AES-256 zina kinga dhidi ya plaintext attack, ikionyesha umuhimu wa kuchagua mbinu salama za encryption kwa data nyeti.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers hutumia metadata ya ZIP iliyofomatiwa vibaya kuvunja zana za static (jadx/apktool/unzip) huku wakihakikisha APK inaweza kusakinishwa kwenye kifaa. Mbinu zinazotumika mara kwa mara ni:

- Ulaghai wa encryption kwa kuweka ZIP General Purpose Bit Flag (GPBF) bit 0
- Kutumia Extra fields kubwa/za custom kuvuruga parsers
- Migongano ya majina ya faili/directory kuficha artefact halisi (mfano, directory liitwalo `classes.dex/` kando ya `classes.dex` halisi)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Dalili:
- `jadx-gui` inashindwa na makosa kama:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` inauliza nywila kwa faili kuu za APK ingawa APK halali haiwezi kuwa na `classes*.dex`, `resources.arsc`, au `AndroidManifest.xml` zilizofichwa:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Uchunguzi kwa kutumia zipdetails:
```bash
zipdetails -v sample.apk | less
```
Angalia General Purpose Bit Flag kwa vichwa vya local na central. Thamani inayofichua ni bit 0 imewekwa (Encryption) hata kwa core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiki: Ikiwa APK inasakinishwa na inaendesha kwenye kifaa lakini core entries zinaonekana "encrypted" kwa zana, GPBF ilibadilishwa.

Rekebisha kwa kuweka bit 0 ya GPBF kuwa 0 kwenye entries zote za Local File Headers (LFH) na Central Directory (CD). Minimal byte-patcher:
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
Matumizi:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sasa unapaswa kuona `General Purpose Flag  0000` kwenye core entries na tools zitachakata APK tena.

### 2) Large/custom Extra fields to break parsers

Wavamizi huingiza Extra fields zilizo kubwa mno na IDs zisizo za kawaida ndani ya headers ili kuwapotosha decompilers. Katika mazingira halisi unaweza kuona alama za custom (kwa mfano, strings kama `JADXBLOCK`) zikiwa zimeingizwa pale.
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Mifano iliyobainika: vitambulisho visivyojulikana kama `0xCAFE` ("Java Executable") au `0x414A` ("JA:") vinabeba mizigo mikubwa.

DFIR heuristics:
- Onyo wakati Extra fields ni kubwa kupita kiasi kwenye core entries (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Chukulia Extra IDs zisizojulikana kwenye entries hizi kama zenye shaka.

Kukabiliana kwa vitendo: kujenga tena archive (mf. re-zipping faili zilizotolewa) huondoa Extra fields zenye uharibifu. Ikiwa zana zinakataa kutoa kwa sababu ya fake encryption, kwanza clear GPBF bit 0 kama hapo juu, kisha repackage:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Mgongano wa majina ya Faili/Saraka (kuficha hati halisi)

A ZIP inaweza kuwa na faili `X` na pia saraka `X/`. Baadhi ya extractors na decompilers huchanganyikiwa na zinaweza kuifunika au kuficha faili halisi kwa kiingizo cha saraka. Hii imeonekana kwa vile kiingizo kinapogongana na majina ya msingi ya APK kama `classes.dex`.

Uainishaji na uchimbaji salama:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Kiambishi cha mwisho kwa ugunduzi wa kimaprogremu:
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
Mapendekezo za utambuzi kwa Blue-team:
- Bainisha APKs zilizo na vichwa vya ndani vinavyoonyesha encryption (GPBF bit 0 = 1) lakini bado zinasakinishwa/kukimbia.
- Bainisha Extra fields kubwa/zisizojulikana kwenye core entries (tafuta alama kama `JADXBLOCK`).
- Bainisha path-collisions (`X` and `X/`) hasa kwa `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Marejeleo

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
