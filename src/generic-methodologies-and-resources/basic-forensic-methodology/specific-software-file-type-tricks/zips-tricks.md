# ZIP-truuks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** vir die bestuur van **zip files** is noodsaaklik vir die diagnose, herstel en cracking van zip files. Hier is ’n paar belangrike utilities:<sup>[[1]](#references)</sup>

- **`unzip`**: Toon waarom ’n zip file moontlik nie gedekomprimeer kan word nie.
- **`zipdetails -v`**: Bied ’n gedetailleerde ontleding van zip file-formaatvelde.
- **`zipinfo`**: Lys die inhoud van ’n zip file sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer beskadigde zip files herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ’n Tool vir brute-force cracking van zip-wagwoorde, effektief vir wagwoorde van tot ongeveer 7 karakters.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) verskaf omvattende besonderhede oor die struktuur en standaarde van zip files.<sup>[[4]](#references)</sup>

Dit is belangrik om daarop te let dat wagwoordbeskermde zip files **nie lêername of lêergroottes** binne die file enkripteer nie, ’n sekuriteitsfout wat nie met RAR- of 7z-files gedeel word nie, aangesien hulle hierdie inligting enkripteer. Verder is zip files wat met die ouer ZipCrypto-metode geënkripteer is kwesbaar vir ’n **plaintext attack** indien ’n ongeënkripteerde kopie van ’n saamgeperste file beskikbaar is.<sup>[[1]](#references)</sup> Hierdie aanval gebruik die bekende inhoud om die zip se wagwoord te crack, ’n kwesbaarheid wat in [HackThis se artikel](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) beskryf word en verder in [hierdie akademiese artikel](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) verduidelik word.<sup>[[11]](#references)[[12]](#references)</sup> Zip files wat egter met **AES-256**-enkripsie beveilig is, is immuun teen hierdie plaintext attack, wat die belangrikheid daarvan beklemtoon om veilige enkripsiemetodes vir sensitiewe data te kies.<sup>[[1]](#references)</sup>

---

## Anti-reversing-truuks in APKs wat gemanipuleerde ZIP-headers gebruik

Moderne Android-malware-droppers gebruik misvormde ZIP-metadata om statiese tools (jadx/apktool/unzip) te breek terwyl die APK steeds op die toestel installeerbaar bly. Die algemeenste truuks is:<sup>[[2]](#references)</sup>

- Valse enkripsie deur die ZIP General Purpose Bit Flag (GPBF) bit 0 te stel
- Misbruik van groot/custom Extra fields om parsers te verwar
- Botsings tussen file-/directory-name om werklike artifacts te versteek (bv. ’n directory genaamd `classes.dex/` langs die werklike `classes.dex`)

### 1) Valse enkripsie (GPBF bit 0 gestel) sonder werklike crypto

Simptome:
- `jadx-gui` misluk met foute soos:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` vra vir ’n wagwoord vir kern-APK-files, alhoewel ’n geldige APK nie geënkripteerde `classes*.dex`, `resources.arsc`, of `AndroidManifest.xml` kan hê nie:

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
Kyk na die General Purpose Bit Flag vir plaaslike en sentrale headers. 'n Kenmerkende waarde is bit 0 wat gestel is (Encryption), selfs vir core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiek: As ’n APK op die toestel installeer en loop, maar kerninskrywings vir tools as "encrypted" verskyn, is die GPBF gewysig.

Maak dit reg deur GPBF bit 0 in beide Local File Headers (LFH)- en Central Directory (CD)-inskrywings skoon te maak. Minimale byte-patcher:

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
Jy behoort nou `General Purpose Flag  0000` op kerninskrywings te sien, en tools sal die APK weer parse.

### 2) Groot/pasgemaakte Extra fields om parsers te breek

Aanvallers plaas oorgrootte Extra fields en vreemde IDs in headers om decompilers te laat struikel. In die wild kan jy pasgemaakte merkers sien (bv. strings soos `JADXBLOCK`) wat daarin ingebed is.

Inspeksie:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Voorbeelde wat waargeneem is: onbekende ID's soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot payloads bevat.

DFIR-heuristieke:
- Genereer 'n waarskuwing wanneer Extra fields buitengewoon groot is op kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Behandel onbekende Extra IDs op daardie inskrywings as verdag.

Praktiese versagting: herbou die archive (byvoorbeeld deur onttrekte lêers weer te zip), wat kwaadwillige Extra fields verwyder. As tools weier om te onttrek weens fake encryption, maak eers GPBF bit 0 skoon soos hierbo, en package dit dan weer:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Lêer-/gidsnaambotsings (versteek werklike artefakte)

'n ZIP kan beide 'n lêer `X` en 'n gids `X/` bevat. Sommige ekstraktors en decompilers raak verward en kan die werklike lêer met 'n gidsinskrywing oorlê of versteek. Dit is waargeneem met inskrywings wat met kern-APK-name soos `classes.dex` bots.

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
Programmatiese opsporing ná die fix:
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
- Flag APKs waarvan die plaaslike headers encryption aandui (GPBF bit 0 = 1), maar wat steeds installeer/run.
- Flag groot/onbekende Extra fields op core entries (soek na markers soos `JADXBLOCK`).
- Flag path-collisions (`X` en `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ander malicious ZIP tricks (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Onlangse phishing campaigns versprei ’n enkele blob wat eintlik **twee ZIP files wat aaneengeskakel is** is. Elke file het sy eie End of Central Directory (EOCD) + central directory. Verskillende extractors parse verskillende directories (7zip lees die eerste, WinRAR die laaste), wat attackers toelaat om payloads te verberg wat slegs deur sekere tools gewys word. Dit omseil ook basiese mail gateway AV wat slegs die eerste directory inspekteer.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
As meer as een EOCD voorkom of daar "data after payload"-waarskuwings is, verdeel die blob en ondersoek elke deel:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Moderne "better zip bomb"-bouwerkings skep 'n klein **kernel** (hoogsgekomprimeerde DEFLATE-blok) en hergebruik dit via overlapping local headers. Elke central directory entry wys na dieselfde gecomprimeerde data, wat verhoudings van >28M:1 behaal sonder om archives te nestel. Libraries wat die groottes van die central directory vertrou (`Python zipfile`, `Java java.util.zip`, Info-ZIP voor hardened builds) kan gedwing word om petagrepe toe te ken.<sup>[[7]](#references)[[8]](#references)</sup>

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
- Voer ’n dry-run walk uit: `zipdetails -v file.zip | grep -n "Rel Off"` en maak seker dat offsets streng toenemend en uniek is.
- Beperk die aanvaarde totale ongekomprimeerde grootte en aantal entries voordat jy dit uitpak (`zipdetails -t` of ’n custom parser).
- Wanneer jy dit moet uitpak, doen dit binne ’n cgroup/VM met CPU- en skyfbeperkings (vermy onbeperkte inflation crashes).

---

### Verwarring tussen Local-header- en central-directory-parsers

Onlangse navorsing oor differential-parsers het getoon dat ZIP-ambiguïteit steeds in moderne toolchains uitbuitbaar is. Die hoofidee is eenvoudig: sommige sagteware vertrou die **Local File Header (LFH)**, terwyl ander die **Central Directory (CD)** vertrou, sodat een archive verskillende lêername, paths, kommentare, offsets of entry-stelle aan verskillende tools kan wys.<sup>[[9]](#references)</sup>

Praktiese offensive uses:
- Laat ’n upload filter, AV pre-scan of package validator ’n onskadelike lêer in die CD sien, terwyl die extractor ’n ander LFH-naam/path eerbiedig.
- Misbruik duplicate names, entries wat slegs in een struktuur voorkom, of ambiguous Unicode path metadata (byvoorbeeld Info-ZIP Unicode Path Extra Field `0x7075`) sodat verskillende parsers verskillende trees rekonstrueer.
- Kombineer dit met path traversal om ’n "harmless" archive view tydens extraction in ’n write-primitive te verander. Sien [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) vir die extraction-kant.

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
Verskaf asseblief die teks wat vertaal en aangevul moet word.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristieke:
- Verwerp of isoleer argiewe met nie-ooreenstemmende LFH/CD-name, duplikaatlêername, veelvuldige EOCD-rekords of ekstra grepe ná die finale EOCD.<sup>[[10]](#references)</sup>
- Behandel ZIPs wat ongewone Unicode-pad-ekstra-velde of teenstrydige opmerkings gebruik as verdag indien verskillende tools nie saamstem oor die onttrekte boom nie.<sup>[[9]](#references)</sup>
- Indien analise belangriker is as die behoud van die oorspronklike grepe, pak die argief met ’n streng parser oor nadat dit in ’n sandbox onttrek is, en vergelyk die resulterende lêerlys met die oorspronklike metadata.

Dit is belangrik buite package ecosystems: dieselfde dubbelsinnigheidsklas kan payloads vir mail gateways, static scanners en custom ingestion pipelines verberg wat ZIP-inhoud “loer” voordat ’n ander extractor die argief hanteer.

---



## Verwysings

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF category)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
