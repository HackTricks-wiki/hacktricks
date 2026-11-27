# Trikovi sa ZIP-ovima

{{#include ../../../banners/hacktricks-training.md}}

**Alati komandne linije** za upravljanje **ZIP datotekama** neophodni su za dijagnostikovanje, popravku i probijanje ZIP datoteka. Evo nekoliko ključnih uslužnih programa:<sup>[[1]](#references)</sup>

- **`unzip`**: Otkriva zašto ZIP datoteka možda ne može da se raspakuje.
- **`zipdetails -v`**: Pruža detaljnu analizu polja formata ZIP datoteke.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Prikazuje sadržaj ZIP datoteke bez raspakivanja.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušavaju da poprave oštećene ZIP datoteke.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za napade rečnikom i brute-force napade na ZIP lozinke; izvodljivost zavisi od prostora za pretragu lozinki.<sup>[[15]](#references)</sup>

[Specifikacija formata Zip datoteke](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima ZIP datoteka.<sup>[[4]](#references)</sup>

Tradicionalne ZIP datoteke zaštićene lozinkom uglavnom ostavljaju nazive datoteka i njihove veličine vidljivim, za razliku od režima šifrovanja zaglavlja koje podržavaju RAR i 7z. Napad poznatim otvorenim tekstom na ZipCrypto oporavlja **interne ključeve za šifrovanje**, a ne nužno originalnu lozinku; ti ključevi su dovoljni za dešifrovanje stavki šifrovanih istom lozinkom.<sup>[[13]](#references)</sup> Za napad su potrebni poznati bajtovi toka **pre šifrovanja**: kod sačuvane stavke to su bajtovi originalne datoteke, dok su kod DEFLATE stavke to komprimovani bajtovi, za čije dobijanje može biti potrebno ponovno kreiranje potpuno istog izlaza kompresije.<sup>[[13]](#references)[[14]](#references)</sup> Pogledajte [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) za praktičan postupak. Za osnovne informacije o kriptoanalizi pogledajte [the paper](https://math.ucr.edu/~mike/zipattacks.pdf) i [walk-through](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Ovaj ZipCrypto napad ne može da se primeni na AES-om šifrovane ZIP stavke.<sup>[[13]](#references)</sup>

---

## Trikovi za otežavanje reverznog inženjeringa u APK-ovima pomoću izmenjenih ZIP zaglavlja

Moderni Android malware dropperi koriste neispravne ZIP metapodatke kako bi omeli statičke alate (jadx/apktool/unzip), a da APK pritom ostane instalabilan na uređaju. Najčešći trikovi su:<sup>[[2]](#references)</sup>

- Lažno šifrovanje postavljanjem bita 0 u ZIP General Purpose Bit Flag (GPBF)
- Zloupotreba velikih/prilagođenih Extra polja radi zbunjivanja parsera
- Sukobi imena datoteka i direktorijuma radi skrivanja stvarnih artefakata (npr. direktorijum nazvan `classes.dex/` pored stvarnog `classes.dex`)

### 1) Lažno šifrovanje (postavljen GPBF bit 0) bez stvarne kriptografije

Simptomi:
- `jadx-gui` ne uspeva i prikazuje greške kao što su:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` traži lozinku za ključne APK datoteke, iako važeći APK ne može da sadrži šifrovane datoteke `classes*.dex`, `resources.arsc` ili `AndroidManifest.xml`:
  
  ```bash
  unzip sample.apk
  [sample.apk] classes3.dex password:
    skipping: classes3.dex                          incorrect password
    skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
    skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
    skipping: classes2.dex                          incorrect password
  ```

Detekcija pomoću zipdetails:

```bash
zipdetails -v sample.apk | less
```

Pogledajte General Purpose Bit Flag u lokalnim i centralnim zaglavljima. Znak koji ukazuje na to je postavljen bit 0 (šifrovanje), čak i kod osnovnih stavki:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heuristika: Ako se APK instalira i pokreće na uređaju, ali alati prikazuju ključne unose kao „šifrovane“, GPBF je izmenjen.

Popravite tako što ćete obrisati bit 0 GPBF-a u zaglavljima lokalnih datoteka (LFH) i unosima Centralnog direktorijuma (CD). Minimalni alat za izmenu bajtova:

<details>
<summary>Minimalni alat za brisanje GPBF bita</summary>

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

Menja se samo bit 0: na primer, `0A09` postaje `0A08`, a ne `0000`. Ovaj minimalni patcher pretražuje sirove bajtove u potrazi za potpisima zaglavlja, pa bajtovi unutar podataka datoteke koji liče na potpise mogu da izazovu lažna poklapanja; radite na kopiji i proverite listu stavki i zaglavlja u rezultatu pre nego što ga upotrebite.<sup>[[4]](#references)</sup>

### 2) Velika/prilagođena Extra polja za ometanje parsera

Napadači ubacuju prevelika Extra polja i neobične ID-jeve u zaglavlja kako bi zbunili dekompilatore. U praksi možete naići na prilagođene oznake (npr. nizove poput `JADXBLOCK`) ugrađene u ta polja.

Pregled:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Primećeni primeri: nepoznati ID-jevi, poput `0xCAFE` („Java Executable“) ili `0x414A` („JA:“), sa velikim sadržajem.<sup>[[2]](#references)</sup>

DFIR heuristike:
- Upozorite kada su Extra polja neuobičajeno velika u ključnim stavkama (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tretirajte nepoznate Extra ID-jeve u tim stavkama kao sumnjive.

Praktična mera za ublažavanje: ponovno pravljenje arhive (npr. ponovno zipovanje ekstrahovanih datoteka) uklanja zlonamerna Extra polja. Ako alati odbijaju da ekstrahuju sadržaj zbog lažnog šifrovanja, prvo obrišite GPBF bit 0 kao što je opisano iznad, pa zatim ponovo zapakujte:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Sukobi naziva datoteka/direktorijuma (skrivanje stvarnih artefakata)

ZIP može da sadrži i datoteku `X` i direktorijum `X/`. Neki alati za raspakivanje i dekompilatori mogu da se zbune i da preklapaju stvarnu datoteku unosom direktorijuma ili je sakriju. Ovo je primećeno kod unosa koji se sukobljavaju sa osnovnim nazivima APK datoteka, kao što je `classes.dex`.

Trijaža i bezbedno raspakivanje:

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

Ideje za detekciju za blue-team:
- Označiti APK-ove čija lokalna zaglavlja označavaju šifrovanje (GPBF bit 0 = 1), a koji se ipak instaliraju/pokreću.
- Označiti velika/nepoznata Extra polja u ključnim stavkama (tražiti markere kao što je `JADXBLOCK`).
- Označiti kolizije putanja (`X` i `X/`), posebno za `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Ostali zlonamerni ZIP trikovi (2024–2026)

### Konkatenisani centralni direktorijumi (izbegavanje pomoću više EOCD zapisa)

U phishing kampanji iz 2024. napadači su isporučili jedan blob koji je zapravo sadržao **dve konkatenisane ZIP datoteke**. Svaka je imala sopstveni zapis End of Central Directory (EOCD) i centralni direktorijum. Različiti alati za ekstrakciju analizirali su različite direktorijume (7-Zip je čitao prvi, dok je WinRAR čitao poslednji), što je napadačima omogućilo da sakriju payload-e koje su prikazivali samo neki alati; skeneri koji pregledaju samo jedan direktorijum mogu da previde drugu arhivu.<sup>[[5]](#references)[[6]](#references)</sup>

**Komande za trijažu**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Ako se pojavi više EOCD-ova ili postoje upozorenja „data after payload“, podelite blob i pregledajte svaki deo:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / bombe sa preklapajućim unosima (nerekurzivne)

Quoted-overlap ZIP bombe formiraju mali **kernel** (visoko komprimovani DEFLATE blok) i ponovo ga koriste u preklapajućim unosima. Varijante sa potpunim preklapanjem usmeravaju više unosa centralnog direktorijuma na jedno lokalno zaglavlje, dok varijante Quoted-overlap citiraju lokalna zaglavlja unutar DEFLATE tokova; objavljena konstrukcija postiže odnos veći od 28M:1 bez ugnježdenih arhiva.<sup>[[7]](#references)</sup>

**Brza detekcija (duplirani pomaci LFH-a)**

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
- Obavite probni prolaz: `zipdetails -v file.zip | grep -n "Local Header Offset"` i uporedite navedene offsete lokalnih zaglavlja i opsege komprimiranih podataka; duplirani offseti ukazuju na varijante potpunog preklapanja.<sup>[[7]](#references)[[8]](#references)</sup>
- Pomoću parsera ograničite prihvaćenu ukupnu nekomprimovanu veličinu i broj stavki pre izdvajanja; `zipinfo -t file.zip` prikazuje ukupne vrednosti, ali ne nameće bezbednosno ograničenje.<sup>[[8]](#references)</sup>
- Ako morate da izdvojite sadržaj, uradite to unutar cgroup-a/VM-a sa ograničenjima CPU-a i diska (izbegavajte padove usled neograničene dekompresije).<sup>[[8]](#references)</sup>

---

### Zabuna parsera oko lokalnog zaglavlja i centralnog direktorijuma

Nedavna istraživanja diferencijalnih parsera pokazala su da se dvosmislenosti ZIP formata i dalje mogu iskoristiti u savremenim skupovima alata. Osnovna ideja je jednostavna: neki softver veruje **Local File Header (LFH)** strukturi, dok drugi veruje **Central Directory (CD)** strukturi, pa jedna arhiva različitim alatima može prikazati različite nazive datoteka, putanje, komentare, offsete ili skupove stavki.<sup>[[9]](#references)</sup>

Praktične ofanzivne primene:
- Učinite da filter za otpremanje, AV pred-skeniranje ili validator paketa u CD-u vidi bezopasnu datoteku, dok alat za izdvajanje uzima drugačiji naziv/putanju iz LFH-a.
- Iskoristite duplirane nazive, stavke prisutne samo u jednoj strukturi ili dvosmislene metapodatke Unicode putanje (na primer, Info-ZIP Unicode Path Extra Field `0x7075`) kako bi različiti parseri rekonstruisali različita stabla.
- Kombinujte ovo sa path traversal-om kako biste „bezopasan“ prikaz arhive pretvorili u primitiv za upis tokom izdvajanja. Za stranu izdvajanja pogledajte [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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

Dopunite to sledećim:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Heuristike:
- Za unos osetljiv na bezbednost, odbacite ili izolujte arhive sa neusklađenim LFH/CD nazivima, dupliranim nazivima datoteka, više EOCD zapisa ili bajtovima nakon završnog EOCD zapisa.<sup>[[9]](#references)[[10]](#references)</sup>
- ZIP-ove koji koriste neuobičajena dodatna polja za Unicode putanje ili nedosledne komentare tretirajte kao sumnjive ako različiti alati daju različite rezultate za izdvojeno stablo datoteka.<sup>[[4]](#references)[[9]](#references)</sup>
- Ako je analiza važnija od očuvanja originalnih bajtova, ponovo zapakujte arhivu pomoću strogog parsera nakon raspakivanja u sandbox-u i uporedite dobijenu listu datoteka sa originalnim metapodacima.

Ovo je važno i izvan ekosistema paketa: ista klasa dvosmislenosti može da sakrije payload-e od mail gateway-a, statičkih skenera i prilagođenih pipeline-ova za unos koji „zavire” u sadržaj ZIP-a pre nego što drugi extractor obradi arhivu.<sup>[[9]](#references)</sup>

---





## References

- [1] [Vodič za CTF forenziku (Mike's Blog, CTF kategorija)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – 1. deo – Višestepeni dropper (APK ZIP zaštita od reverznog inženjeringa)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress skripta)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Specifikacija formata ZIP datoteka (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Fleksibilna struktura ZIP arhiva iskorišćena za neotkriveno sakrivanje malware-a (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hakeri sakrivaju malware u novom napadu pomoću ZIP datoteka — ulančani centralni direktorijumi ZIP-a](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Bolja ZIP bomba (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Razumevanje ZIP bombi: konstrukcija sa preklapanjem/citiranim preklapanjem](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Moj ZIP nije tvoj ZIP: prepoznavanje i iskorišćavanje semantičkih razlika između ZIP parsera (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Sprečavanje napada zbunjivanjem ZIP parsera na Python instalacionim programima paketa](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP napadi sa smanjenim poznatim otvorenim tekstom (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistična veb misija, nivo 15 (ZIP napad sa poznatim otvorenim tekstom)](https://www.hackthissite.org/articles/read/793)
- [13] [Uputstvo za bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [bkcrack vodič za napad sa poznatim otvorenim tekstom](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [fcrackzip repozitorijum](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
