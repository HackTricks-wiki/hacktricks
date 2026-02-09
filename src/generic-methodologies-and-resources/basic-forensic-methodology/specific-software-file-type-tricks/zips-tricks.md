# ZIPs truuks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** for managing **zip files** are essential for diagnosing, repairing, and cracking zip files. Here are some key utilities:

- **`unzip`**: Toon hoekom 'n zip file dalk nie ontpak kan word nie.
- **`zipdetails -v`**: Bied gedetailleerde ontleding van zip file formaat velde.
- **`zipinfo`**: Lys die inhoud van 'n zip file sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** and **`zip -FF input.zip --out output.zip`**: Probeer beskadigde zip files herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: A tool for brute-force cracking of zip passwords, effective for passwords up to around 7 characters.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

It's crucial to note that password-protected zip files **do not encrypt filenames or file sizes** within, a security flaw not shared with RAR or 7z files which encrypt this information. Furthermore, zip files encrypted with the older ZipCrypto method are vulnerable to a **plaintext attack** if an unencrypted copy of a compressed file is available. This attack leverages the known content to crack the zip's password, a vulnerability detailed in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) and further explained in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). However, zip files secured with **AES-256** encryption are immune to this plaintext attack, showcasing the importance of choosing secure encryption methods for sensitive data.

---

## Anti-reversing truuks in APKs wat gemanipuleerde ZIP headers gebruik

Moderne Android malware droppers gebruik misvormde ZIP metadata om statiese tools (jadx/apktool/unzip) te breek, terwyl hulle die APK op die toestel installeerbaar hou. Die mees algemene truuks is:

- Vals enkripsie deur die ZIP General Purpose Bit Flag (GPBF) bit 0 te stel
- Misbruik van groot/pasmaak Extra-velde om parsers te verwar
- Lêer/gids naam botsings om werklike artefakte te verberg (bv. 'n gids met die naam `classes.dex/` langs die werklike `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Simptome:
- `jadx-gui` misluk met foute soos:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` vra vir 'n wagwoord vir kern APK-lêers, alhoewel 'n geldige APK nie `classes*.dex`, `resources.arsc`, of `AndroidManifest.xml` kan hê wat enkripteer is nie:

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
Kyk na die General Purpose Bit Flag vir local en central headers. 'n kenmerkende waarde is bit 0 set (Encryption) selfs vir core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiek: As 'n APK op die toestel installeer en uitvoer, maar kerninskrywings vir gereedskap as "geënkripteer" voorkom, is die GPBF gemanipuleer.

Los dit op deur GPBF bit 0 in beide Local File Headers (LFH) en Central Directory (CD) inskrywings skoon te maak. Minimaal byte-patcher:

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

Gebruik:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Jy behoort nou `General Purpose Flag  0000` op kerninskrywings te sien en tools sal die APK weer parse.

### 2) Groot/aangepaste Ekstra velde om parsers te breek

Aanvallers prop oorgrootte ekstra velde en vreemde ID's in headers om dekompilers te laat struikel. In die wild kan jy pasgemaakte merkers (bv. stringe soos `JADXBLOCK`) daar ingebed sien.

Inspeksie:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Voorbeelde waargeneem: onbekende IDs soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot payloads dra.

DFIR heuristics:
- Waarsku wanneer Extra fields ongewoon groot is op kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Beskou onbekende Extra IDs op daardie inskrywings as verdag.

Praktiese mitigasie: deur die argief te herbou (bv. deur die uitgepakte lêers weer te zip) word kwaadwillige Extra fields verwyder. As tools weier om uit te pak weens vals enkripsie, maak eers GPBF bit 0 skoon soos hierbo, en pak dan weer:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Lêer/gidsnaam-botsings (versteek regte artefakte)

'n ZIP kan beide 'n lêer `X` en 'n gids `X/` bevat. Sommige extractors en decompilers raak deurmekaar en kan die regte lêer met 'n gidsinskrywing oorlaai of verberg. Dit is waargeneem met inskrywings wat bots met kern-APK-name soos `classes.dex`.

Triage en veilige ekstraksie:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programmatiese opsporing agtervoegsel:
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
Blue-team opsporingsidees:
- Vlag APKs waarvan plaaslike headers enkripsie aandui (GPBF bit 0 = 1) maar tog installeer/loop.
- Vlag groot/onbekende Extra fields op kerninskrywings (kyk na merkers soos `JADXBLOCK`).
- Vlag path-collisions (`X` and `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ander kwaadwillige ZIP truuks (2024–2025)

### Aaneengeplakte sentrale directories (multi-EOCD ontduiking)

Onlangse phishing-campagnes stuur 'n enkele blob wat eintlik **twee ZIP-lêers aaneengekoppeld** is. Elkeen het sy eie End of Central Directory (EOCD) + central directory. Verskillende extractors parseer verskillende directories (7zip lees die eerste, WinRAR die laaste), wat aanvallers toelaat om payloads te verberg wat net sommige tools wys. Dit omseil ook basiese mail gateway AV wat net die eerste directory inspekteer.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
As meer as een EOCD verskyn, of as daar "data after payload" waarskuwings is, verdeel die blob en ondersoek elke deel:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderne "better zip bomb" bou 'n klein **kernel** (hoogs saamgeperste DEFLATE block) en hergebruik dit deur oorvleuelende local headers. Elke central directory entry wys na dieselfde saamgeperste data, wat >28M:1 verhoudings bereik sonder geneste argiewe. Biblioteke wat central directory sizes vertrou (Python `zipfile`, Java `java.util.zip`, Info-ZIP voor geharde builds) kan gedwing word om petabytes toe te ken.

**Vinnige opsporing (duplicate LFH offsets)**
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
**Hantering**
- Voer 'n dry-run walk uit: `zipdetails -v file.zip | grep -n "Rel Off"` en verseker dat offsets streng toenemend en uniek is.
- Beperk die aanvaarbare totale ongekomprimeerde grootte en die aantal inskrywings voor ekstraksie (`zipdetails -t` of 'n pasgemaakte parser).
- Wanneer jy moet uitpak, doen dit binne 'n cgroup/VM met CPU- en skyfbeperkings (voorkom onbeperkte uitbreiding wat tot crashes lei).

---

## Verwysings

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
