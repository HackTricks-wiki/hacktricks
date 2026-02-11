# ZIPs truuks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** vir die bestuur van **zip-lêers** is noodsaaklik vir die diagnose, herstel en kraak van zip-lêers. Hier is 'n paar sleutelgereedskap:

- **`unzip`**: Onthul waarom 'n zip-lêer moontlik nie uitgepak kan word nie.
- **`zipdetails -v`**: Bied 'n gedetaileerde ontleding van die velde in die zip-lêerformaat.
- **`zipinfo`**: Lys die inhoud van 'n zip-lêer sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** and **`zip -FF input.zip --out output.zip`**: Probeer beskadigde zip-lêers herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 'n Instrument vir brute-force kraak van zip-wagwoorde, effektief vir wagwoorde tot ongeveer 7 karakters.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) verskaf omvattende besonderhede oor die struktuur en standaarde van zip-lêers.

Dit is belangrik om daarop te let dat wagwoord-beskermde zip-lêers **nie lêernaam- of lêergrootte-inligting enkodeer nie**, 'n sekuriteitsgebrekkigheid wat nie met RAR of 7z gedeel word nie, aangesien dié formate hierdie inligting enkodeer. Verder is zip-lêers wat met die ouer ZipCrypto-metode versleutel is vatbaar vir 'n **plaintext attack** as 'n onversleutelde kopie van 'n gecomprimeerde lêer beskikbaar is. Hierdie aanval maak gebruik van die bekende inhoud om die zip se wagwoord te kraak, 'n kwesbaarheid uiteengesit in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) en verder verduidelik in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Zip-lêers wat egter met **AES-256** versleutel is, is immuun vir hierdie plaintext attack, wat die belangrikheid toon om veilige enkripsiemetodes vir sensitiewe data te kies.

---

## Anti-reversing truuks in APKs wat gemanipuleerde ZIP-kopstukke gebruik

Moderne Android malware-droppers gebruik verkeerd gevormde ZIP-metadata om statiese gereedskap (jadx/apktool/unzip) te breek, terwyl die APK steeds op die toestel geïnstalleer kan word. Die mees algemene truuks is:

- Valse enkripsie deur die ZIP General Purpose Bit Flag (GPBF) bit 0 te stel
- Misbruik van groot/aangepaste Extra-velde om parsers te verwar
- Lêer/gids naam-botsings om werklike artefakte te verberg (bv. 'n gids met die naam `classes.dex/` langs die werklike `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Simptome:
- `jadx-gui` faal met foute soos:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` vra vir 'n wagwoord vir kern-APK-lêers selfs al kan 'n geldige APK nie versleutelde `classes*.dex`, `resources.arsc`, of `AndroidManifest.xml` hê nie:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Opsporing met zipdetails:
```bash
zipdetails -v sample.apk | less
```
Kyk na die General Purpose Bit Flag vir die lokale en sentrale headers. 'n Kenmerkende waarde is bit 0 gestel (Encryption) selfs vir kerninskrywings:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiek: As 'n APK op die toestel installeer en op die toestel loop, maar kerninskrywings deur gereedskap as "encrypted" voorkom, is die GPBF gemanipuleer.

Los dit deur GPBF bit 0 te skoon te maak in beide Local File Headers (LFH) en Central Directory (CD) inskrywings. Minimal byte-patcher:

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
Jy behoort nou `General Purpose Flag  0000` op kerninskrywings te sien en gereedskap sal die APK weer ontleed.

### 2) Groot/aangepaste Extra-velde om parsers te breek

Aanvallers prop oorgrootte Extra-velde en vreemde IDs in headers om decompilers te laat struikel. In die praktyk kan jy aangepaste merkers sien (e.g., stringe soos `JADXBLOCK`) wat daar ingebed is.

Inspeksie:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Voorbeelde waargeneem: onbekende IDs soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot payloads dra.

DFIR heuristieke:
- Waarsku wanneer Extra fields ongewoon groot is op kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Behandel onbekende Extra IDs op daardie inskrywings as verdag.

Praktiese mitigasie: die herbou van die argief (bv. deur uitgepakte lêers weer te zip) verwyder kwaadwillige Extra fields. As tools weier om te onttrek weens valse enkripsie, maak eers GPBF bit 0 soos hierbo skoon, en herverpak:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Lêer/Gids-naam botsings (wegsteek van werklike artefakte)

’n ZIP kan beide ’n lêer `X` en ’n gids `X/` bevat. Sommige extractors en decompilers raak deurmekaar en kan die werklike lêer deur ’n gidsinskrywing oorskryf of verberg. Dit is waargeneem by inskrywings wat bots met kern-APK-name soos `classes.dex`.

Triasie en veilige ekstraksie:
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
Blue-team detection ideas:
- Vlag APKs waarvan plaaslike headers enkripsie aandui (GPBF bit 0 = 1) maar steeds installeer/loop.
- Vlag groot/onbekende Extra fields op kerninskrywings (kyk na merkers soos `JADXBLOCK`).
- Vlag padbotsings (`X` en `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ander kwaadwillige ZIP-truuks (2024–2025)

### Aaneengeskakelde central directories (multi-EOCD evasion)

Onlangse phishingveldtogte stuur 'n enkele blob wat eintlik uit **twee ZIP-lêers aaneengeskakel** bestaan. Elkeen het sy eie End of Central Directory (EOCD) + central directory. Verskillende extractors parse verskillende directories (7zip lees die eerste, WinRAR die laaste), wat aanvallers toelaat om payloads te verberg wat slegs sommige gereedskap wys. Dit omseil ook basiese mail gateway AV wat slegs die eerste directory inspekteer.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
As meer as een EOCD verskyn of daar "data after payload" waarskuwings is, splits die blob en inspekteer elke deel:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" bou 'n klein **kernel** (hoog saamgeperste DEFLATE-blok) en hergebruik dit via oorvleuelende local headers. Elke central directory entry wys na dieselfde saamgeperste data en bereik >28M:1 verhoudings sonder geneste argiewe. Biblioteke wat central directory sizes vertrou (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) kan gedwing word om petabytte toe te wys.

**Vinnige opsporing (dubbele LFH-offsets)**
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
- Beperk die aanvaarbare totale ongekomprimeerde grootte en die aantal inskrywings voordat onttrekking plaasvind (`zipdetails -t` of 'n aangepaste parser).
- Wanneer jy moet onttrek, doen dit binne 'n cgroup/VM met CPU+disk-beperkings (voorkom onbeperkte uitbreiding wat tot ineenstortings lei).

---

## Verwysings

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
