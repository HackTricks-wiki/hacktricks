# ZIP-truuks

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** vir die bestuur van **zip files** is noodsaaklik vir die diagnose, herstel en cracking van zip files. Hier is sommige belangrike utilities:<sup>[[1]](#references)</sup>

- **`unzip`**: Toon waarom 'n zip file moontlik nie gedekomprimeer kan word nie.
- **`zipdetails -v`**: Bied gedetailleerde ontleding van zip file-formaatvelde.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Lys die inhoud van 'n zip file sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer om beskadigde zip files te herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 'n Tool vir brute-force cracking van zip-wagwoorde, effektief vir wagwoorde van tot ongeveer 7 karakters.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) bied omvattende besonderhede oor die struktuur en standaarde van zip files.<sup>[[4]](#references)</sup>

Dit is belangrik om daarop te let dat wagwoordbeskermde zip files **nie filenames of file sizes** daarin enkripteer nie, 'n sekuriteitsfout wat nie met RAR- of 7z-files gedeel word nie, aangesien hulle hierdie inligting enkripteer. Verder is zip files wat met die ouer ZipCrypto-metode geënkripteer is, kwesbaar vir 'n **plaintext attack** indien 'n ongeënkripteerde kopie van 'n saamgeperste file beskikbaar is.<sup>[[1]](#references)</sup> Hierdie aanval gebruik die bekende inhoud om die zip se wagwoord te crack, 'n kwesbaarheid wat in [HackThis se artikel](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) uiteengesit en verder in [hierdie akademiese artikel](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf) verduidelik word.<sup>[[11]](#references)[[12]](#references)</sup> Zip files wat egter met **AES-256**-enkripsie beveilig is, is immuun teen hierdie plaintext attack, wat die belangrikheid beklemtoon daarvan om veilige enkripsiemetodes vir sensitiewe data te kies.<sup>[[1]](#references)</sup>

---

## Anti-reversing-truuks in APKs deur gemanipuleerde ZIP headers te gebruik

Moderne Android malware droppers gebruik verkeerd gevormde ZIP metadata om static tools (jadx/apktool/unzip) te laat faal, terwyl die APK steeds op die toestel installeerbaar bly. Die algemeenste truuks is:<sup>[[2]](#references)</sup>

- Valse enkripsie deur die ZIP General Purpose Bit Flag (GPBF) bit 0 te stel
- Misbruik van groot/custom Extra fields om parsers te verwar
- Botsings tussen file- en directory-name om werklike artifacts te versteek (bv. 'n directory genaamd `classes.dex/` langs die werklike `classes.dex`)

### 1) Valse enkripsie (GPBF bit 0 gestel) sonder werklike crypto

Simptome:
- `jadx-gui` faal met foute soos:

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` vra vir 'n wagwoord vir kern-APK-files, selfs al kan 'n geldige APK nie `classes*.dex`, `resources.arsc` of `AndroidManifest.xml` geënkripteer hê nie:

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
Kyk na die General Purpose Bit Flag vir plaaslike en sentrale headers. ’n Duidelike aanduiding is bit 0 gestel (Encryption), selfs vir kerninskrywings:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiek: As ’n APK op die toestel installeer en loop, maar kerninskrywings vir nutsprogramme as "encrypted" voorkom, is daar met die GPBF gepeuter.

Maak dit reg deur bit 0 van die GPBF in beide Local File Headers (LFH)- en Central Directory (CD)-inskrywings te skrap. Minimale byte-patcher:

<details>
<summary>Minimale GPBF-bit-skraper</summary>
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
Jy behoort nou `General Purpose Flag  0000` op kerninskrywings te sien, en tools sal die APK weer kan parse.

### 2) Groot/pasgemaakte Extra fields om parsers te breek

Attackers plaas oorgrootte Extra fields en vreemde ID's in headers om decompilers te laat faal. In die praktyk kan jy pasgemaakte markers (bv. stringe soos `JADXBLOCK`) sien wat daarin ingebed is.

Inspeksie:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Voorbeelde wat waargeneem is: onbekende ID's soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot payloads bevat.

DFIR-heuristieke:
- Gee ’n waarskuwing wanneer Extra fields buitengewoon groot is in kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Behandel onbekende Extra IDs in daardie inskrywings as verdag.

Praktiese versagting: herbou die archive (byvoorbeeld deur onttrekte lêers weer te zip); dit verwyder kwaadwillige Extra fields. As tools weier om te onttrek weens vals encryption, maak eers GPBF bit 0 skoon soos hierbo, en package dit dan weer:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Botsings tussen lêer-/gidsname (verberging van werklike artefakte)

'n ZIP kan beide 'n lêer `X` en 'n gids `X/` bevat. Sommige extractors en decompilers raak verward en kan die werklike lêer met 'n gidsinskrywing oorlê of verberg. Dit is waargeneem by inskrywings wat met kern-APK-name soos `classes.dex` bots.

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
Programmatiese opsporing ná die regstelling:
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
- Merk APK's waarvan die plaaslike headers enkripsie aandui (GPBF bit 0 = 1), maar wat steeds installeer/loop.
- Merk groot/onbekende Extra-velde op kerninskrywings (soek merkers soos `JADXBLOCK`).
- Merk padbotsings (`X` en `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ander kwaadwillige ZIP-truuks (2024–2026)

### Aaneengeskakelde sentrale gidse (multi-EOCD-ontduiking)

Onlangse phishing-veldtogte versprei 'n enkele blob wat eintlik **twee ZIP-lêers wat aaneengeskakel is** bevat. Elkeen het sy eie End of Central Directory (EOCD) + sentrale gids. Verskillende extractors ontleed verskillende gidse (7zip lees die eerste, WinRAR die laaste), wat aanvallers toelaat om payloads te versteek wat slegs deur sommige nutsmiddels vertoon word. Dit omseil ook basiese mail gateway AV wat slegs die eerste gids inspekteer.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage-opdragte**
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

Moderne "better zip bomb"-bouwerke skep ’n klein **kernel** (hoogs saamgeperste DEFLATE-blok) en hergebruik dit via oorvleuelende plaaslike headers. Elke sentrale gidsinskrywing wys na dieselfde saamgeperste data, wat verhoudings van >28M:1 bereik sonder om argiewe te nes. Biblioteke wat die groottes van die sentrale gids vertrou (`zipfile` in Python, `java.util.zip` in Java, Info-ZIP voor hardened builds) kan gedwing word om petagrepe toe te ken.<sup>[[7]](#references)[[8]](#references)</sup>

**Vinnige opsporing (duplikaat LFH-offsets)**
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
- Voer ’n dry-run walk uit: `zipdetails -v file.zip | grep -n "Rel Off"` en verseker dat offsets streng toenemend en uniek is.
- Beperk die aanvaarde totale ongekomprimeerde grootte en entry count vóór extraction (`zipdetails -t` of ’n custom parser).
- Wanneer jy moet extract, doen dit binne ’n cgroup/VM met CPU- en skyfbeperkings (vermy onbegrensde inflation crashes).

---

### Verwarring tussen Local-header- en central-directory-parsers

Onlangse navorsing oor differential-parsers het getoon dat ZIP-ambiguïteit steeds in moderne toolchains uitbuitbaar is. Die hoofidee is eenvoudig: sommige software vertrou die **Local File Header (LFH)**, terwyl ander die **Central Directory (CD)** vertrou. Een archive kan dus verskillende filenames, paths, comments, offsets of entry sets aan verskillende tools toon.<sup>[[9]](#references)</sup>

Praktiese offensiewe gebruike:
- Laat ’n upload filter, AV pre-scan of package validator ’n harmless file in die CD sien, terwyl die extractor ’n ander LFH name/path eerbiedig.
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
Vul dit aan met:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristieke:
- Verwerp of isoleer argiewe met LFH/CD-name wat nie ooreenstem nie, duplikaat-lêername, veelvuldige EOCD-rekords, of agterblywende grepe ná die finale EOCD.<sup>[[10]](#references)</sup>
- Behandel ZIPs wat ongewone Unicode-pad-ekstra-velde of teenstrydige opmerkings gebruik as verdag indien verskillende tools nie saamstem oor die geëkstraheerde boom nie.<sup>[[9]](#references)</sup>
- Indien analise belangriker is as die behoud van die oorspronklike grepe, herverpak die argief met ’n streng parser nadat dit in ’n sandbox geëkstraheer is, en vergelyk die gevolglike lêerlys met die oorspronklike metadata.

Dit is belangrik buite package-ekosisteme: dieselfde dubbelsinnigheidsklas kan payloads vir mail gateways, statiese skandeerders en pasgemaakte ingestion-pipelines verberg wat die ZIP-inhoud “loer” voordat ’n ander extractor die argief hanteer.

---



## Verwysings

- [1] [CTF Forensics Field Guide (Mike's Blog, CTF-kategorie)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Deel 1 – ’n Multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (Archive::Zip-script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [ZIP-lêerformaatspesifikasie (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}
