# ZIP trikovi

**Command-line alati** za upravljanje **zip datotekama** neophodni su za dijagnostikovanje, popravku i cracking zip datoteka. Evo nekih ključnih alata:<sup>[[1]](#references)</sup>

- **`unzip`**: Otkriva zašto zip datoteka možda ne može da se dekompresuje.
- **`zipdetails -v`**: Pruža detaljnu analizu polja formata zip datoteke.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Izlistava sadržaj zip datoteke bez ekstrakcije.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušavaju da poprave oštećene zip datoteke.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force cracking zip passworda, efikasan za passworde dužine do približno 7 karaktera.

[Specifikacija formata Zip datoteka](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima zip datoteka.<sup>[[4]](#references)</sup>

Važno je napomenuti da tradicionalne password-protected ZIP datoteke uglavnom ostavljaju nazive datoteka i njihove veličine vidljivim, za razliku od header-encryption režima koje podržavaju RAR i 7z. Pored toga, ZIP datoteke šifrovane starijom metodom ZipCrypto ranjive su na **plaintext attack** ako je dostupna nešifrovana kopija kompresovane datoteke.<sup>[[1]](#references)</sup> Ovaj napad koristi poznati sadržaj za cracking ZIP passworda, kao što je objašnjeno u [ovom akademskom radu](https://math.ucr.edu/~mike/zipattacks.pdf) i prikazano u [ovom Hack This Site walk-through-u](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Međutim, ZipCrypto known-plaintext attack ne može da se primeni na entries zaštićene **AES-256** enkripcijom.<sup>[[1]](#references)</sup>

---

## Anti-reversing trikovi u APK-ovima korišćenjem izmenjenih ZIP headera

Moderni Android malware droppers koriste neispravne ZIP metadata podatke kako bi ometali static tools (jadx/apktool/unzip), dok APK i dalje ostaje moguće instalirati na uređaju. Najčešći trikovi su:<sup>[[2]](#references)</sup>

- Lažna enkripcija postavljanjem bita 0 ZIP General Purpose Bit Flag-a (GPBF)
- Zloupotreba velikih/custom Extra polja radi zbunjivanja parsera
- Kolizije naziva datoteka/direktorijuma radi skrivanja stvarnih artifacts (npr. direktorijum nazvan `classes.dex/` pored stvarnog `classes.dex`)

### 1) Lažna enkripcija (postavljen GPBF bit 0) bez stvarne kriptografije

Simptomi:
- `jadx-gui` ne uspeva uz greške poput:

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` traži password za ključne APK datoteke iako validan APK ne može imati enkriptovane `classes*.dex`, `resources.arsc` ili `AndroidManifest.xml`:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detekcija pomoću zipdetails-a:
```bash
zipdetails -v sample.apk | less
```
Pogledajte General Purpose Bit Flag za local i central headers. Vrednost koja ukazuje na to je postavljen bit 0 (Encryption), čak i za osnovne stavke:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heuristika: Ako se APK instalira i pokreće na uređaju, ali se ključne stavke alatima prikazuju kao „encrypted“, GPBF je izmenjen.

Rešenje je brisanje GPBF bita 0 u Local File Headers (LFH) i Central Directory (CD) stavkama. Minimalni byte-patcher:

<details>
<summary>Minimalni GPBF bit-clear patcher</summary>
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

Upotreba:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Sada bi trebalo da vidite `General Purpose Flag  0000` u osnovnim unosima, a alati će ponovo parsirati APK.

### 2) Velika/prilagođena Extra polja za ometanje parsera

Napadači ubacuju prevelika Extra polja i neobične ID-jeve u zaglavlja kako bi izazvali probleme u dekompajlerima. U praksi možete videti prilagođene markere (npr. stringove poput `JADXBLOCK`) ugrađene u njih.

Inspekcija:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Primećeni primeri: nepoznati ID-ovi poput `0xCAFE` („Java Executable“) ili `0x414A` („JA:“) koji sadrže velike payload-e.<sup>[[2]](#references)</sup>

DFIR heuristike:
- Upozoriti kada su Extra polja neuobičajeno velika u ključnim unosima (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Nepoznate Extra ID-ove u tim unosima tretirati kao sumnjive.

Praktična mera: ponovna izgradnja arhive (npr. ponovno zipovanje ekstrahovanih datoteka) uklanja zlonamerna Extra polja. Ako alati odbijaju ekstrakciju zbog lažne enkripcije, najpre obrišite GPBF bit 0 kao što je gore opisano, a zatim ponovo zapakujte:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Kolizije naziva datoteka/direktorijuma (skrivanje stvarnih artefakata)

ZIP može da sadrži i datoteku `X` i direktorijum `X/`. Neki extractors i decompilers se zbune i mogu da preklapaju ili sakriju stvarnu datoteku unosom direktorijuma. Ovo je primećeno kod unosa koji su u koliziji sa osnovnim APK nazivima kao što je `classes.dex`.

Triage i bezbedno raspakivanje:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Programatska detekcija nakon ispravke:
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
Ideje za Blue-team detekciju:
- Označiti APK-ove čija lokalna zaglavlja označavaju enkripciju (GPBF bit 0 = 1), a koji se ipak instaliraju/pokreću.
- Označiti velike/nepoznate Extra fields u osnovnim entries (tražiti markere poput `JADXBLOCK`).
- Označiti kolizije putanja (`X` i `X/`), posebno za `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Drugi zlonamerni ZIP trikovi (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

U phishing kampanji iz 2024. godine, napadači su poslali jedan blob koji je zapravo predstavljao **dve spojene ZIP datoteke**. Svaka je imala sopstveni zapis End of Central Directory (EOCD) i centralni direktorijum. Različiti extractors su parsirali različite direktorijume (7-Zip je čitao prvi, dok je WinRAR čitao poslednji), što je napadačima omogućilo da sakriju payloads koje su prikazivali samo neki alati; skeneri koji proveravaju samo jedan direktorijum mogu propustiti drugu arhivu.<sup>[[5]](#references)[[6]](#references)</sup>

**Komande za trijažu**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Ako se pojavi više od jednog EOCD zapisa ili postoje upozorenja „data after payload“, podelite blob i pregledajte svaki deo:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs grade sićušni **kernel** (visoko kompresovani DEFLATE blok) i ponovo ga koriste kroz preklapajuće entries. Varijante sa potpunim preklapanjem usmeravaju više central-directory entries na jedno zaglavlje local header-a, dok varijante sa quoted-overlap navode local headers unutar DEFLATE stream-ova; objavljena konstrukcija postiže odnos veći od 28M:1 bez ugnježdenih arhiva.<sup>[[7]](#references)</sup>

**Brza detekcija (duplikatni LFH offsets)**
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
**Rukovanje**
- Izvršite dry-run pregled: `zipdetails -v file.zip | grep -n "Local Header Offset"` i uporedite referencirane offsete local-header-a i opsege komprimovanih podataka; duplirani offseti ukazuju na varijante sa potpunim preklapanjem.<sup>[[7]](#references)[[8]](#references)</sup>
- Ograničite prihvatljivu ukupnu nekomprimovanu veličinu i broj entry-ja pre ekstrakcije pomoću parser-a; `zipinfo -t file.zip` prikazuje ukupne vrednosti, ali ne primenjuje bezbednosno ograničenje.<sup>[[8]](#references)</sup>
- Kada morate da izvršite ekstrakciju, uradite to unutar cgroup/VM okruženja sa ograničenjima CPU-a i diska (izbegavajte crash-eve izazvane neograničenom dekompresijom).<sup>[[8]](#references)</sup>

---

### Zabuna parser-a između local-header-a i central-directory-ja

Nedavna istraživanja differential-parser-a pokazala su da je ZIP dvosmislenost i dalje eksploatabilna u modernim toolchain-ovima. Osnovna ideja je jednostavna: neki software veruje **Local File Header-u (LFH)**, dok drugi veruje **Central Directory-ju (CD)**, pa jedna arhiva može različitim alatima prikazati različita imena fajlova, putanje, komentare, offsete ili skupove entry-ja.<sup>[[9]](#references)</sup>

Praktične offensive primene:
- Omogućite da upload filter, AV pre-scan ili validator paketa u CD-u vidi bezopasan fajl, dok extractor poštuje drugačije LFH ime/putanju.
- Iskoristite duplirana imena, entry-je prisutne samo u jednoj strukturi ili dvosmislene Unicode path metadata podatke (na primer, Info-ZIP Unicode Path Extra Field `0x7075`), tako da različiti parser-i rekonstruišu različita stabla.
- Kombinujte ovo sa path traversal-om da biste bezopasan prikaz arhive pretvorili u write-primitive tokom ekstrakcije. Za stranu ekstrakcije pogledajte [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR trijaža:
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
Dopunite ga sledećim:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristike:
- Za ingestion osetljiv na bezbednost, odbacite ili izolujte arhive sa neusaglašenim LFH/CD imenima, dupliranim nazivima datoteka, višestrukim EOCD zapisima ili bajtovima nakon poslednjeg EOCD-a.<sup>[[9]](#references)[[10]](#references)</sup>
- ZIP-ove koji koriste neuobičajena dodatna polja za Unicode putanje ili neusaglašene komentare tretirajte kao sumnjive ako se različiti alati ne slažu oko izdvojenog stabla.<sup>[[4]](#references)[[9]](#references)</sup>
- Ako je analiza važnija od očuvanja originalnih bajtova, ponovo zapakujte arhivu pomoću strogog parsera nakon ekstrakcije u sandbox-u i uporedite dobijenu listu datoteka sa originalnim metapodacima.

Ovo je važno i izvan package ekosistema: ista klasa dvosmislenosti može sakriti payload-e od mail gateway-a, static scanner-a i prilagođenih ingestion pipeline-ova koji „zavire“ u ZIP sadržaj pre nego što drugi extractor obradi arhivu.<sup>[[9]](#references)</sup>

---



## References

- [1] [CTF Forensics vodič za teren (Mike's Blog, CTF kategorija)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Deo 1 – Višestepeni dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress skripta)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Specifikacija ZIP formata datoteke (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Fleksibilna struktura ZIP arhiva iskorišćena za neotkriveno sakrivanje malware-a (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hakeri zakopavaju malware u novom ZIP napadu — konkatenirani centralni direktorijumi ZIP-a](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Bolji zip bomb (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Razumevanje zip bomb-ova: konstrukcija overlapping/quoted-overlap kernela](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Moj ZIP nije vaš ZIP: Identifikovanje i iskorišćavanje semantičkih razlika između ZIP parsera (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Sprečavanje napada izazvanih zabunom ZIP parsera na Python package installere](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP napadi sa smanjenim poznatim plaintext-om (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistična web misija, nivo 15 (known-plaintext ZIP napad)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
