# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Opdragreël-gereedskap** vir die bestuur van **zip files** is noodsaaklik vir die diagnose, herstel en kraak van zip files. Hier is 'n paar sleutelnutsgereedskap:

- **`unzip`**: Toon waarom 'n zip file dalk nie uitgepak kan word nie.
- **`zipdetails -v`**: Bied gedetailleerde ontleding van zip file formaat-velde.
- **`zipinfo`**: Lys die inhoud van 'n zip file sonder om dit te onttrek.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer beskadigde zip files herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 'n hulpmiddel vir brute-force kraak van zip-wagwoorde, effektief vir wagwoorde tot ongeveer 7 karakters.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) verskaf omvattende besonderhede oor die struktuur en standaarde van zip files.

Dit is belangrik om daarop te let dat wagwoord-beskermde zip files **nie bestandsname of lêergroottes binne-in enkodeer nie**, 'n sekuriteitsgebrek wat nie met RAR of 7z files gedeel word nie wat hierdie inligting enkodeer. Verder is zip files wat met die ouer ZipCrypto metode versleutel is kwesbaar vir 'n **plaintext attack** as 'n onversleutelde afskrif van 'n gecomprimeerde lêer beskikbaar is. Hierdie aanval benut die bekende inhoud om die zip se wagwoord te kraak, 'n kwesbaarheid uiteengesit in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) en verder verduidelik in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Zip files wat egter met **AES-256** enkripsie beveilig is, is immuun teen hierdie plaintext attack, wat die belangrikheid toon om veilige enkripsiemetodes vir sensitiewe data te kies.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Moderne Android malware droppers gebruik wanvormige ZIP metadata om statiese gereedskap (jadx/apktool/unzip) te breek, terwyl die APK steeds op die toestel installeerbaar bly. Die mees algemene truuks is:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Simptome:
- `jadx-gui` misluk met foutboodskappe soos:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` vra vir 'n wagwoord vir kern APK-lêers, al kan 'n geldige APK nie versleutelde `classes*.dex`, `resources.arsc`, of `AndroidManifest.xml` hê nie:

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
Kyk na die General Purpose Bit Flag vir lokale en sentrale headers. 'n Duiende waarde is bit 0 gestel (Encryption) selfs vir kerninskrywings:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiek: As 'n APK op die toestel installeer en uitgevoer word, maar kerninskrywings vir gereedskap as "encrypted" voorkom, is die GPBF gemanipuleer.

Los dit op deur GPBF bit 0 in beide Local File Headers (LFH) en Central Directory (CD) inskrywings op 0 te stel. Minimale byte-patcher:

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

### 2) Groot/aangepaste Extra-velde om parsers te breek

Aanvallers prop oorgroot Extra-velde en vreemde IDs in kopstukke om decompilers te laat struikel. In die veld kan jy aangepaste merkers sien (bv. stringe soos `JADXBLOCK`) wat daar ingebed is.

Inspeksie:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Waargenome voorbeelde: onbekende IDs soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot payloads bevat.

DFIR heuristieke:
- Waarsku wanneer Extra fields ongewoon groot is op kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Behandel onbekende Extra IDs op daardie inskrywings as verdagtig.

Praktiese mitigasie: die herbou van die argief (bv. re-zipping van uitgepakte lêers) verwyder kwaadaardige Extra fields. As gereedskap weier om te onttrek weens valse enkripsie, maak eers GPBF bit 0 skoon soos hierbo, en herverpak dan:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Lêer/Map-naambotsings (versteek werklike artefakte)

'n ZIP kan beide 'n lêer `X` en 'n gids `X/` bevat. Sommige extractors en decompilers raak verward en kan die werklike lêer oorlaai of verberg met 'n gidsinskrywing. Dit is waargeneem by inskrywings wat bots met kern-APK-name soos `classes.dex`.

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
Programmatiese opsporing post-fix:
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
- Merk APKs waarvan die lokale headers enkripsie aandui (GPBF bit 0 = 1), maar steeds geïnstalleer/uitgevoer word.
- Merk groot/onbekende Extra fields op kerninskrywings (kyk vir merkers soos `JADXBLOCK`).
- Merk padbotsings (`X` en `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ander kwaadwillige ZIP-truuks (2024–2026)

### Aaneengeskakelde central directories (multi-EOCD evasion)

Onlangse phishing-veldtogte lewer 'n enkele blob wat eintlik **twee ZIP-lêers aaneengeskakel** is. Elkeen het sy eie End of Central Directory (EOCD) + central directory. Verskillende extractors ontleed verskillende directories (7zip lees die eerste, WinRAR die laaste), wat aanvallers toelaat om payloads te verberg wat slegs sommige gereedskap wys. Dit omseil ook basiese mail gateway AV wat slegs die eerste directory inspekteer.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
As meer as een EOCD verskyn of daar "data after payload" waarskuwings is, verdeel die blob en ondersoek elke deel:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderne "better zip bomb" bou 'n klein **kernel** (hoog saamgeperste DEFLATE block) en hergebruik dit via oorvleuelende local headers. Elke central directory entry wys na dieselfde saamgeperste data en bewerkstellig >28M:1 verhoudings sonder om archives te nest. Biblioteke wat op central directory sizes vertrou (Python `zipfile`, Java `java.util.zip`, Info-ZIP voor geharde builds) kan gedwing word om petabytes toe te ken.

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
**Behandeling**
- Voer 'n droë-run-ondersoek uit: `zipdetails -v file.zip | grep -n "Rel Off"` en verseker dat offsets strikt toenemend en uniek is.
- Beperk die aanvaarde totale ongedrukte grootte en aantal inskrywings voor uitpakking (`zipdetails -t` of custom parser).
- Wanneer jy moet uitpak, doen dit binne 'n cgroup/VM met CPU- en skyfbeperkings (voorkom onbegrensde inflasie-crashes).

---

### Local-header vs central-directory parser verwarring

Onlangse differensiële-parser navorsing het getoon dat ZIP-ambigueit steeds in moderne toolchains uitgebuit kan word. Die hoofgedagte is eenvoudig: sommige sagteware vertrou die **Local File Header (LFH)** terwyl ander die **Central Directory (CD)** vertrou, sodat een argief verskillende lêernaam, paaie, kommentare, offsets, of inskrywingsstelle aan verskillende gereedskap kan voorhou.

Praktiese offensiewe gebruike:
- Laat 'n upload-filter, AV pre-scan, of package validator 'n onskadelike lêer in die CD sien terwyl die extractor 'n ander LFH-naam/pad eerbiedig.
- Misbruik duplikaatname, inskrywings wat slegs in een struktuur teenwoordig is, of ambigue Unicode-pad-metadata (byvoorbeeld Info-ZIP Unicode Path Extra Field `0x7075`) sodat verskillende parsers verskillende bome herbou.
- Kombineer dit met path traversal om 'n "onskadelike" argief-beeld tydens uitpakking in 'n write-primitive te omskep. Vir die uitpakkingskant, sien [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Ek het nie die inhoud van src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md ontvang nie. Plak asseblief die Markdown-inhoud wat vertaal en aangevul moet word, en verduidelik kort waarmee jy wil hê ek dit moet aanvul (bv. voorbeelde, commands, verduidelikings of ekstra truuks). 

Ek sal alle Markdown-/HTML-tags, refere, links en paths onaangeroer laat en ander teks na Afrikaans vertaal volgens die gegewe riglyne.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristieke riglyne:
- Verwerp of isoleer argiewe met nie-ooreenstemmende LFH/CD-name, duplikaatlêernaam(e), meervoudige EOCD-rekords, of oortollige bytes ná die finale EOCD.
- Beskou ZIPs wat ongebruiklike Unicode-path extra fields of inkonsekwente kommentare gebruik as verdag indien verskillende gereedskap oor die extracted tree verskil.
- As ontleding belangriker is as die behoud van die oorspronklike bytes, herverpak die argief met 'n strict parser ná ekstraksie in 'n sandbox en vergelyk die resulterende lêerlys met die oorspronklike metadata.

Dit is relevant buite pakket-ekosisteme: dieselfde onduidelikheidsklas kan payloads verberg vir mail gateways, static scanners, en custom ingestion pipelines wat "peek" na ZIP-inhoud voordat 'n ander extractor die argief hanteer.

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
