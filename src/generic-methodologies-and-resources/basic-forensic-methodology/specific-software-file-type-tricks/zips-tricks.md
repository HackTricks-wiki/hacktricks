# ZIP-truuks

{{#include ../../../banners/hacktricks-training.md}}

**Opdragreëlnutsgoed** vir die bestuur van **zip-lêers** is noodsaaklik om zip-lêers te diagnoseer, te herstel en te crack. Hier is ’n paar belangrike nutsprogramme:<sup>[[1]](#references)</sup>

- **`unzip`**: Wys waarom ’n zip-lêer moontlik nie gedekomprimeer kan word nie.
- **`zipdetails -v`**: Bied ’n gedetailleerde ontleding van die formaatvelde van ’n zip-lêer.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Lys die inhoud van ’n zip-lêer sonder om dit uit te pak.
- **`zip -F input.zip --out output.zip`** en **`zip -FF input.zip --out output.zip`**: Probeer om beskadigde zip-lêers te herstel.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: ’n Nutsprogram vir woordeboek- en brute-force-aanvalle op ZIP-wagwoorde; die haalbaarheid hang van die wagwoordsoekruimte af.<sup>[[15]](#references)</sup>

Die [Zip-lêerformaatspesifikasie](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) bevat omvattende besonderhede oor die struktuur en standaarde van zip-lêers.<sup>[[4]](#references)</sup>

Tradisionele wagwoordbeskermde ZIP-lêers laat gewoonlik lêername en -groottes sigbaar, anders as kopierenkripsiemodusse wat deur RAR en 7z ondersteun word. ’n ZipCrypto known-plaintext attack herwin **interne enkripsiesleutels**, nie noodwendig die oorspronklike wagwoord nie; die sleutels is genoeg om inskrywings te dekripteer wat met dieselfde wagwoord geënkripteer is.<sup>[[13]](#references)</sup> Die aanval benodig bekende grepe van die stroom **voor enkripsie**: vir ’n gestoorde lid is dit die oorspronklike lêergrepe, maar vir ’n DEFLATE-lid is dit die saamgeperste grepe, waarvoor die presiese kompressie-uitset moontlik herskep moet word.<sup>[[13]](#references)[[14]](#references)</sup> Sien [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) vir ’n praktiese werkvloei. Vir agtergrond oor kriptanalise, sien [die artikel](https://math.ucr.edu/~mike/zipattacks.pdf) en [deurstap](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Hierdie ZipCrypto-aanval is nie van toepassing op AES-geënkripteerde ZIP-inskrywings nie.<sup>[[13]](#references)</sup>

---

## Anti-reversing-truuks in APKs wat gemanipuleerde ZIP-koptekste gebruik

Moderne Android-malware-droppers gebruik misvormde ZIP-metadata om statiese nutsprogramme (jadx/apktool/unzip) te laat faal, terwyl die APK steeds op die toestel geïnstalleer kan word. Die algemeenste truuks is:<sup>[[2]](#references)</sup>

- Vals enkripsie deur bit 0 van die ZIP General Purpose Bit Flag (GPBF) te stel
- Misbruik van groot/pasgemaakte Extra-velde om ontleders te verwar
- Botsings tussen lêer- en gidsname om werklike artefakte te versteek (bv. ’n gids met die naam `classes.dex/` langs die werklike `classes.dex`)

### 1) Vals enkripsie (GPBF-bit 0 gestel) sonder werklike kriptografie

Simptome:
- `jadx-gui` misluk met foute soos volg:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` vra vir 'n wagwoord vir kern-APK-lêers, al kan 'n geldige APK nie geënkripteerde `classes*.dex`, `resources.arsc` of `AndroidManifest.xml` bevat nie:
  
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

Kyk na die General Purpose Bit Flag vir plaaslike en sentrale opskrifte. ’n Veelseggende waarde is bit 0 wat gestel is (Encryption), selfs vir kerninskrywings:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heuristiek: As ’n APK op die toestel installeer en loop, maar kerningange vir nutsgoed "geënkripteer" lyk, is daar met die GPBF gepeuter.

Maak reg deur bit 0 van GPBF in beide Local File Headers (LFH) en Central Directory (CD)-inskrywings skoon te maak. Minimale byte-patcher:

<details>
<summary>Minimale GPBF-bit-skoonmaker</summary>

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

Slegs bit 0 moet verander: byvoorbeeld, `0A09` word `0A08`, nie `0000` nie. Hierdie minimale patcher soek na header-handtekeninge in rou grepe, dus kan handtekeningagtige grepe binne lêerdata vals treffers veroorsaak; werk met ’n kopie en bevestig die gevolglike inskrywingslys en headers voordat jy die uitvoer gebruik.<sup>[[4]](#references)</sup>

### 2) Groot/pasgemaakte Extra-velde om parsers te breek

Aanvallers prop oorgroot Extra-velde en vreemde ID’s in headers om decompilers te laat struikel. In die praktyk kan jy pasgemaakte merkers daar teëkom (bv. stringe soos `JADXBLOCK`).

Inspeksie:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Voorbeelde wat waargeneem is: onbekende ID's soos `0xCAFE` ("Java Executable") of `0x414A` ("JA:") wat groot loonvragte bevat.<sup>[[2]](#references)</sup>

DFIR-heuristieke:
- Gee 'n waarskuwing wanneer Extra-velde buitengewoon groot is op kerninskrywings (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Behandel onbekende Extra-ID's op daardie inskrywings as verdag.

Praktiese versagting: die argief herbou (bv. deur onttrekte lêers weer te zip) verwyder kwaadwillige Extra-velde. As nutsgoed weier om te onttrek weens vals enkripsie, maak eers GPBF-bis 0 soos hierbo skoon en verpak dan weer:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Lêer-/gidsnaam-botsings (wat werklike artefakte versteek)

’n ZIP kan beide ’n lêer `X` en ’n gids `X/` bevat. Sommige extractors en decompilers raak verward en kan die werklike lêer met ’n gidsinskrywing oorvleuel of versteek. Dit is waargeneem met inskrywings wat bots met kern-APK-name soos `classes.dex`.

Triage en veilige onttrekking:

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

Blue-team-idees vir opsporing:
- Merk APK's waarvan die plaaslike opskrifte enkripsie aandui (GPBF bit 0 = 1), maar wat steeds installeer/loop.
- Merk groot/onbekende Extra-velde op kerninskrywings (soek na merkers soos `JADXBLOCK`).
- Merk padbotsings (`X` en `X/`) spesifiek vir `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ander kwaadwillige ZIP-truuks (2024–2026)

### Aaneengeskakelde sentrale gidse (multi-EOCD-ontduiking)

In 'n phishing-veldtog in 2024 het aanvallers 'n enkele blob versprei wat in werklikheid **twee ZIP-lêers was wat aaneengeskakel is**. Elkeen het sy eie End of Central Directory (EOCD)-rekord en sentrale gids gehad. Verskillende uitpakprogramme het verskillende gidse ontleed (7-Zip het die eerste gelees, terwyl WinRAR die laaste gelees het), wat aanvallers in staat gestel het om payloads weg te steek wat net deur sommige nutsmiddels gewys is; skandeerders wat net een gids ondersoek, kan die ander argief miskyk.<sup>[[5]](#references)[[6]](#references)</sup>

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

### Quoted-overlap / overlapping-entry bombs (nie-rekursief)

Quoted-overlap ZIP-bombs bou ’n klein **kernel** (’n hoogs saamgeperste DEFLATE-blok) en hergebruik dit oor oorvleuelende inskrywings. Variante met volledige oorvleueling laat verskeie central-directory-inskrywings na een plaaslike kopskrif wys, terwyl quoted-overlap-variante plaaslike kopskrifte binne DEFLATE-strome aanhaal; die gepubliseerde konstruksie behaal meer as 28M:1 sonder geneste argiewe.<sup>[[7]](#references)</sup>

**Vinnige opsporing (duplikaat-LFH-offsets)**

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
- Doen ’n droëloopkontrole: `zipdetails -v file.zip | grep -n "Local Header Offset"` en vergelyk die verwysde local-header-offsets en saamgeperste datareekse; dubbele offsets dui op full-overlap-variante.<sup>[[7]](#references)[[8]](#references)</sup>
- Beperk die totale aanvaarde ongekomprimeerde grootte en aantal inskrywings met ’n parser voordat jy uitpak; `zipinfo -t file.zip` rapporteer totale, maar dwing nie ’n veiligheidslimiet af nie.<sup>[[8]](#references)</sup>
- Wanneer jy moet uitpak, doen dit binne ’n cgroup/VM met CPU- en skyflimiete (vermy ineenstortings weens onbeperkte dekomprimering).<sup>[[8]](#references)</sup>

---

### Verwarring tussen Local-header- en central-directory-parsers

Onlangse navorsing oor differensiële parsers het getoon dat ZIP-dubbelsinnigheid steeds in moderne gereedskapkettings uitgebuit kan word. Die hoofidee is eenvoudig: sommige sagteware vertrou die **Local File Header (LFH)**, terwyl ander die **Central Directory (CD)** vertrou. Daarom kan een argief verskillende lêername, paaie, opmerkings, offsets of inskrywingsversamelings aan verskillende nutsgoed voorlê.<sup>[[9]](#references)</sup>

Praktiese offensiewe gebruike:
- Laat ’n oplaai-filter, AV-voorskandering of pakketvalideerder ’n onskadelike lêer in die CD sien, terwyl die uitpakprogram ’n ander LFH-naam/-pad gebruik.
- Misbruik duplikaatname, inskrywings wat net in een struktuur voorkom, of dubbelsinnige Unicode-padmetadata (byvoorbeeld, Info-ZIP Unicode Path Extra Field `0x7075`) sodat verskillende parsers verskillende gidstrukture saamstel.
- Kombineer dit met padtraversering om ’n “onskadelike” argiefaansig tydens uitpak in ’n skryfprimitief te verander. Sien [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md) vir die uitpakgedeelte.

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
- Vir sekuriteitsensitiewe inname, verwerp of isoleer argiewe met verskillende LFH/CD-name, duplikaatlêername, veelvuldige EOCD-rekords of agteraanstaande grepe ná die finale EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Behandel ZIP-lêers wat ongewone ekstra velde vir Unicode-paaie of inkonsekwente opmerkings gebruik as verdag indien verskillende nutsprogramme nie saamstem oor die onttrekte lêerboom nie.<sup>[[4]](#references)[[9]](#references)</sup>
- As ontleding belangriker is as die behoud van die oorspronklike grepe, pak die argief ná onttrekking in ’n sandbox met ’n streng ontleder weer in, en vergelyk die gevolglike lêerlys met die oorspronklike metadata.

Dit is nie net vir pakket-ekosisteme belangrik nie: dieselfde klas dubbelsinnigheid kan payloads vir e-pospoorte, statiese skandeerders en pasgemaakte innamepyplyne versteek wat ZIP-inhoud vooraf “loer” voordat ’n ander onttrekker die argief verwerk.<sup>[[9]](#references)</sup>

---





## References

- [1] [CTF-forensiese veldgids (Mike se blog, CTF-kategorie)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Deel 1 – ’n Multi-stadium dropper (APK ZIP-teen-omkering)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress-skrip)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP-lêerformaatspesifikasie (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Buigsame struktuur van ZIP-argiewe uitgebuit om malware onopgemerk weg te steek (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers begrawe malware in nuwe ZIP-lêeraanval — aaneengeskakelde ZIP-sentrale gidse](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [’n Beter zip-bom (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Verstaan zip-bomme: konstruksie van oorvleuelende/aangehaalde oorvleuelings in die kern](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP is nie jou ZIP nie: Identifisering en uitbuiting van semantiese gapings tussen ZIP-ontleders (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Voorkoming van verwarringsaanvalle op ZIP-ontleders in Python-pakketinstalleerders](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP-aanvalle met verminderde bekende gewone teks (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistiese webmissie, vlak 15 (ZIP-aanval met bekende gewone teks)](https://www.hackthissite.org/articles/read/793)
- [13] [bkcrack-gebruik](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [bkcrack-handleiding vir bekende gewone teks](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [bkcrack-bewaarplek](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
