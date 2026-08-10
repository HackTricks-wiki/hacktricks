# ZIP-truuks

**Command-line tools** vir die bestuur van **zip files** is noodsaaklik vir die diagnose, herstel en cracking van zip files. Hier is enkele belangrike utilities:<sup>[[1]](#references)</sup>

- **`unzip`**: Toon waarom 'n zip file moontlik nie gedekomprimeer kan word nie.
- **`zipdetails -v`**: Bied gedetailleerde ontleding van zip file-formaatvelde.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Lys die inhoud van 'n zip file sonder om dit te onttrek.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer beskadigde zip files herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: 'n Tool vir brute-force cracking van zip passwords, wat effektief is vir passwords van tot ongeveer 7 karakters.

Die [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) verskaf omvattende besonderhede oor die struktuur en standaarde van zip files.<sup>[[4]](#references)</sup>

Dit is belangrik om daarop te let dat tradisionele password-beskermde ZIP files oor die algemeen filenames en file sizes sigbaar laat, anders as header-encryption modes wat deur RAR en 7z ondersteun word. Verder is ZIP files wat met die ouer ZipCrypto-metode geënkripteer is, kwesbaar vir 'n **plaintext attack** indien 'n ongeënkripteerde kopie van 'n saamgeperste file beskikbaar is.<sup>[[1]](#references)</sup> Hierdie attack gebruik die bekende inhoud om die ZIP se password te crack, soos verduidelik in [this academic paper](https://math.ucr.edu/~mike/zipattacks.pdf) en geïllustreer in [this Hack This Site walk-through](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Die ZipCrypto known-plaintext attack is egter nie van toepassing op entries wat met **AES-256**-encryption beveilig is nie.<sup>[[1]](#references)</sup>

---

## Anti-reversing-truuks in APKs met gemanipuleerde ZIP headers

Moderne Android malware droppers gebruik misvormde ZIP metadata om static tools (jadx/apktool/unzip) te laat breek, terwyl die APK steeds op die device installeerbaar bly. Die algemeenste truuks is:<sup>[[2]](#references)</sup>

- Fake encryption deur die ZIP General Purpose Bit Flag (GPBF) bit 0 te stel
- Misbruik van groot/custom Extra fields om parsers te verwar
- Botsings tussen file- en directory-name om werklike artifacts te versteek (byvoorbeeld 'n directory genaamd `classes.dex/` langs die werklike `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) sonder werklike crypto

Simptome:
- `jadx-gui` faal met errors soos:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` vra vir 'n password vir kern-APK files, selfs al kan 'n geldige APK nie encrypted `classes*.dex`, `resources.arsc`, of `AndroidManifest.xml` hê nie:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detection met zipdetails:
```bash
zipdetails -v sample.apk | less
```
Kyk na die General Purpose Bit Flag vir plaaslike en sentrale headers. ’n Kenmerkende waarde is bit 0 set (Encryption), selfs vir core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristiek: As ’n APK op die toestel installeer en loop, maar kerninskrywings vir tools as "encrypted" verskyn, is daar met die GPBF gepeuter.

Los dit op deur bit 0 van die GPBF in beide Local File Headers (LFH)- en Central Directory (CD)-inskrywings te skrap. Minimale byte-patcher:

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
Jy behoort nou `General Purpose Flag  0000` op kerninskrywings te sien, en tools sal die APK weer kan parse.

### 2) Groot/pasgemaakte Extra fields om parsers te breek

Aanvallers prop oorgrootte Extra fields en vreemde ID's in headers om decompilers te laat faal. In die praktyk kan jy pasgemaakte markers sien (bv. strings soos `JADXBLOCK`) wat daarin ingebed is.

Inspeksie:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Voorbeelde wat waargeneem is: onbekende ID's soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot payloads bevat.<sup>[[2]](#references)</sup>

DFIR-heuristieke:
- Waarsku wanneer Extra fields buitengewoon groot is op kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Beskou onbekende Extra IDs op daardie inskrywings as verdag.

Praktiese versagting: die herbou van die argief (byvoorbeeld deur onttrekte lêers weer te zip) verwyder kwaadwillige Extra fields. As tools weier om weens vals encryption te onttrek, maak eers GPBF-bit 0 skoon soos hierbo, en verpak dit dan weer:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Lêer-/gidsnaambotsings (verberging van werklike artifacts)

’n ZIP kan beide ’n lêer `X` en ’n gids `X/` bevat. Sommige ekstraktors en dekompileerders raak verward en kan die werklike lêer met ’n gidsinskrywing oorlê of verberg. Dit is waargeneem met inskrywings wat bots met kern-APK-name soos `classes.dex`.

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
Programmatiese opsporing ná regstelling:
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
- Merk APK's waarvan die plaaslike headers encryption aandui (GPBF bit 0 = 1), maar wat steeds installeer/loop.
- Merk groot/onbekende Extra fields in kernentries (soek merkers soos `JADXBLOCK`).
- Merk padbotsings (`X` en `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ander malicious ZIP-tricks (2024–2026)

### Aaneengeskakelde central directories (multi-EOCD evasion)

In 'n 2024-phishingveldtog het aanvallers 'n enkele blob versend wat eintlik **twee ZIP-lêers was wat aaneengeskakel is**. Elkeen het sy eie End of Central Directory (EOCD)-rekord en central directory gehad. Verskillende extractors het verskillende directories geparse (7-Zip het die eerste een gelees, terwyl WinRAR die laaste een gelees het), wat aanvallers toegelaat het om payloads te versteek wat slegs deur sommige tools gewys is; scanners wat net een directory inspekteer, kan die ander archive mis.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage-opdragte**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
As meer as een EOCD voorkom of daar "data after payload"-waarskuwings is, verdeel die blob en inspekteer elke deel:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs bou ’n klein **kernel** (’n hoogsgekomprimeerde DEFLATE-blok) en hergebruik dit oor oorvleuelende entries. Full-overlap-variante wys verskeie central-directory entries na een local header, terwyl quoted-overlap-variante local headers binne DEFLATE-streams aanhaal; die gepubliseerde konstruksie bereik meer as 28M:1 sonder geneste argiewe.<sup>[[7]](#references)</sup>

**Quick detection (duplicate LFH offsets)**
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
**Hantering**
- Voer ’n dry-run-walk uit: `zipdetails -v file.zip | grep -n "Local Header Offset"` en vergelyk die verwysde local-header-offsets en compressed-data-reekse; duplikaat-offsets dui full-overlap-variante aan.<sup>[[7]](#references)[[8]](#references)</sup>
- Beperk die aanvaarde totale uncompressed-grootte en aantal entries vóór extraction met ’n parser; `zipinfo -t file.zip` rapporteer totale, maar dwing nie ’n veiligheidslimiet af nie.<sup>[[8]](#references)</sup>
- Wanneer jy moet extract, doen dit binne ’n cgroup/VM met CPU- en skyflimiete (vermy crashes weens onbeperkte inflation).<sup>[[8]](#references)</sup>

---

### Verwarring tussen Local-header- en central-directory-parsers

Onlangse differential-parser-navorsing het getoon dat ZIP-ambiguïteit steeds in moderne toolchains uitbuitbaar is. Die hoofidee is eenvoudig: sommige sagteware vertrou die **Local File Header (LFH)**, terwyl ander die **Central Directory (CD)** vertrou; dus kan een archive verskillende filenames, paths, comments, offsets of entry-stelle aan verskillende tools vertoon.<sup>[[9]](#references)</sup>

Praktiese offensiewe gebruike:
- Laat ’n upload-filter, AV-pre-scan of package-validator ’n benign file in die CD sien, terwyl die extractor ’n ander LFH-naam/-path eerbiedig.
- Misbruik duplicate names, entries wat slegs in een struktuur voorkom, of ambiguous Unicode path-metadata (byvoorbeeld Info-ZIP Unicode Path Extra Field `0x7075`) sodat verskillende parsers verskillende trees rekonstrueer.
- Kombineer dit met path traversal om ’n "harmless" archive view tydens extraction in ’n write-primitive te verander. Sien [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) vir die extraction-kant.

DFIR-triage:
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
- Vir sekuriteitsensitiewe inname, verwerp of isoleer argiewe met LFH/CD-name wat nie ooreenstem nie, duplikaatlêername, veelvuldige EOCD-rekords, of agterblywende grepe ná die finale EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Behandel ZIPs wat ongewone Unicode-pad-ekstra velde of teenstrydige opmerkings gebruik as verdag indien verskillende nutsprogramme nie saamstem oor die onttrekte boom nie.<sup>[[4]](#references)[[9]](#references)</sup>
- Indien analise belangriker is as die behoud van die oorspronklike grepe, herverpak die argief met ’n streng parser nadat dit in ’n sandbox onttrek is, en vergelyk die gevolglike lêerlys met die oorspronklike metadata.

Dit is belangrik buite package-ekosisteme: dieselfde dubbelsinnigheidsklas kan payloads vir mail gateways, statiese skandeerders en pasgemaakte inname-pipelines verberg wat die ZIP-inhoud "loer" voordat ’n ander extractor die argief hanteer.<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF Forensics-veldgids (Mike's Blog, CTF-kategorie)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Deel 1 – ’n Multistadium-dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress-skrip)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP-lêerformaatspesifikasie (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Buigsame struktuur van ZIP-argiewe uitgebuit om malware onopgemerk te versteek (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers begrawe malware in nuwe ZIP-lêeraanval — aaneengeskakelde ZIP-sentrale gidse](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [’n Beter zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Verstaan zip bombs: konstruksie van oorvleuelende/gequote oorvleueling in die kernel](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP is nie jou ZIP nie: Identifisering en uitbuiting van semantiese gapings tussen ZIP-parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Voorkoming van ZIP-parserverwarringsaanvalle op Python-package-installeerders](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP-aanvalle met verminderde bekende plaintext (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistiese webmissie, vlak 15 (bekende-plaintext ZIP-aanval)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
