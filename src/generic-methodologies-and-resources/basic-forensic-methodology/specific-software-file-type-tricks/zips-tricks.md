# ZIPs truuks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** vir die hantering van **zip files** is noodsaaklik om zip files te diagnoseer, te herstel en te kraak. Hier is 'n paar sleutelnutsmiddels:

- **`unzip`**: Wys waarom 'n zip file moontlik nie ontpak/gedekomprimeer kan word nie.
- **`zipdetails -v`**: Bied gedetailleerde ontleding van die velde in die zip file-formaat.
- **`zipinfo`**: Lys die inhoud van 'n zip file sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer beskadigde zip files herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 'n hulpmiddel vir brute-force kraak van zip-wagwoorde, effektief vir wagwoorde tot omtrent 7 karakters.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) gee omvattende besonderhede oor die struktuur en standaarde van zip files.

Dit is belangrik om te let dat wagwoord-beskermde zip files **nie bestandsname of lêergroottes binne die argief enkripteer nie**, 'n sekuriteitsgebrek wat nie met RAR of 7z files gedeel word nie — dié enkripteer daardie inligting. Verder is zip files wat met die ouer ZipCrypto-metode enkripteer is kwesbaar vir 'n **plaintext attack** as 'n ongeënkripteerde kopie van 'n gecomprimeerde lêer beskikbaar is. Hierdie aanval maak gebruik van die bekende inhoud om die zip se wagwoord te kraak, 'n kwesbaarheid wat in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) uiteengesit word en verder in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) verduidelik word. Zip files wat met **AES-256** beveilig is, is egter immuun teen hierdie plaintext attack, wat die belangrikheid aantoon om veilige enkripsiemetodes vir sensitiewe data te kies.

---

## Anti-reversing truuks in APKs wat gemanipuleerde ZIP headers gebruik

Modern Android malware droppers gebruik foutief gevormde ZIP-metagegewens om statiese gereedskap (jadx/apktool/unzip) te breek terwyl die APK installeerbaar op die toestel bly. Die mees algemene truuks is:

- Valse enkripsie deur die ZIP General Purpose Bit Flag (GPBF) bit 0 te stel
- Misbruik van groot/gespesialiseerde Extra fields om parsers te verwar
- Lêer/gids naambotsings om werklike artefakte te verberg (bv. 'n gids genaamd `classes.dex/` langs die werklike `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Simptome:
- `jadx-gui` faal met foute soos:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` vra vir 'n wagwoord vir kern-APK-lêers al kan 'n geldige APK nie versleutelde `classes*.dex`, `resources.arsc`, of `AndroidManifest.xml` hê nie:

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
Kyk na die Algemene Doel-bitvlag vir plaaslike en sentrale headers. 'n Duidelike teken is dat bit 0 gestel is (Encryption), selfs vir kerninskrywings:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiek: As 'n APK op die toestel geïnstalleer en uitgevoer word, maar kerninskrywings vir gereedskap as "geënkripteer" voorkom, is die GPBF gemanipuleer.

Los dit op deur bit 0 van die GPBF in beide Local File Headers (LFH) en Central Directory (CD)-inskrywings te wis. Minimale byte-patcher:

<details>
<summary>Minimale GPBF bit-clear patcher</summary>
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

Aanvallers prop oorgrootte Extra-velde en vreemde IDs in headers om dekompileerders te laat struikel. In die veld kan jy aangepaste merkers (bv. stringe soos `JADXBLOCK`) daar ingebed sien.

Inspeksie:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Voorbeelde waargeneem: onbekende ID's soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot payloads dra.

DFIR-heuristieke:
- Waarsku wanneer Extra-velde ongewoon groot is op kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Beskou onbekende Extra-ID's op daardie inskrywings as verdag.

Praktiese mitigasie: die herbou van die argief (bv. re-zipping van uitgepakte lêers) verwyder kwaadwillige Extra-velde. As gereedskap weier om uit te pak weens vals enkripsie, maak eers GPBF bit 0 soos hierbo skoon, en herverpak:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Lêer/gids-naam botsings (wegsteek van werklike artefakte)

'n ZIP kan beide 'n lêer `X` en 'n gids `X/` bevat. Sommige uitpakprogramme en dekompileerders raak verward en kan die werklike lêer oorskryf of verberg met 'n gidsinskrywing. Dit is waargeneem by inskrywings wat bots met kern-APK name soos `classes.dex`.

Triering en veilige uitpak:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programmatiese opsporing nabehandeling:
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
Blue-team deteksie-idees:
- Flag APKs waarvan die plaaslike headers enkripsie aandui (GPBF bit 0 = 1) maar tog installeer/draai.
- Flag groot/onbekende Extra fields op kerninskrywings (kyk vir merkers soos `JADXBLOCK`).
- Flag path-collisions (`X` and `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ander kwaadwillige ZIP-truuks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Onlangs lewer phishing-veldtogte ’n enkele blob af wat eintlik **twee ZIP-lêers aaneengeskakel** is. Elkeen het sy eie End of Central Directory (EOCD) + central directory. Verskillende extractors parse verskillende directories (7zip lees die eerste, WinRAR die laaste), wat aanvalleerders toelaat om payloads te verberg wat net sommige tools wys. Dit omseil ook basiese mail gateway AV wat slegs die eerste directory inspekteer.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
As meer as een EOCD verskyn of daar "data after payload" waarskuwings is, verdeel die blob en inspekteer elke deel:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderne "better zip bomb" bou 'n klein **kernel** (sterk saamgeperste DEFLATE-blok) en hergebruik dit via oorlappende local headers. Elke central directory entry wys na dieselfde saamgeperste data en bereik >28M:1 verhoudings sonder geneste argiewe. Biblioteke wat op central directory groottes vertrou (Python `zipfile`, Java `java.util.zip`, Info-ZIP voor geharde weergawes) kan gedwing word om petabytes toe te ken.

**Vinnige opsporing (duplikaat LFH offsets)**
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
- Voer 'n dry-run deurloop uit: `zipdetails -v file.zip | grep -n "Rel Off"` en verseker dat die offsets streng toenemend en uniek is.
- Beperk die toegelate totale ongekomprimeerde grootte en die aantal inskrywings voordat onttrekking plaasvind (`zipdetails -t` of 'n eie parser).
- Wanneer jy moet onttrek, doen dit binne 'n cgroup/VM met CPU- en skyfbeperkings (voorkom onbeperkte inflasie wat tot crashes lei).

---

### Local-header vs central-directory parser verwarring

Onlangse differential-parser navorsing het getoon dat ZIP-ambiguïteit steeds uitbuitbaar is in moderne toolchains. Die hoofgedagte is eenvoudig: sommige sagteware vertrou die **Local File Header (LFH)** terwyl ander die **Central Directory (CD)** vertrou, so een argief kan verskillende lêernomme, paaie, kommentaar, offsets, of inskrywingstelle aan verskillende gereedskap voorhou.

Praktiese offensiewe gebruike:
- Laat 'n upload-filter, AV pre-scan, of pakket-validator 'n onskadelike lêer in die CD sien, terwyl die extractor 'n ander LFH-naam/pad respekteer.
- Misbruik duplikaatname, inskrywings wat slegs in een struktuur voorkom, of ambigue Unicode-padmetadata (byvoorbeeld Info-ZIP Unicode Path Extra Field `0x7075`) sodat verskillende parsers verskillende bome herkonstitueer.
- Kombineer dit met path traversal om 'n "harmless" argief-oorsig tydens onttrekking in 'n write-primitive om te skakel. Vir die onttrekkingskant, sien [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
I don't have the file content to complement or translate. Please either:

- Paste the contents of src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md here, or
- Tell me which specific items you want me to complement it with (e.g., zip slip, password cracking (fcrackzip, john), ZipCrypto vs AES, zip bombs, nested archives, alternate data streams inside zips, zip64 quirks, metadata and timestamps, carving compressed files, tool commands and examples).

Once you provide the file text or choose the additions, I'll return the translated Afrikaans Markdown (keeping all tags, links and code unchanged).
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristieke:
- Verwerp of isoleer argiewe met wanpassende LFH/CD-name, dubbele lêernaam, meerdere EOCD-rekords, of agterlopende bytes ná die finale EOCD.
- Behandel ZIPs wat ongebruiklike Unicode-path ekstra-velde gebruik of inkonsekwente kommentare het as verdag indien verskillende gereedskap nie saamstem oor die geëkstraheerde boom nie.
- As ontleding belangriker is as die bewaring van die oorspronklike bytes, herpak die argief met 'n streng parser ná ekstraksie in 'n sandbox en vergelyk die resulterende lêerlys met die oorspronklike metadata.

Dit geld buite pakket-ekosisteme: dieselfde ambiguïteitsklas kan payloads verberg vir mail gateways, statiese skandeerders, en aangepaste ingestion pipelines wat "peek" by ZIP-inhoud voordat 'n ander extractor die argief hanteer.

---



## Verwysings

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
