# Trucchi per ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** for managing **zip files** sono essenziali per diagnosticare, riparare e craccare zip files. Ecco alcune utility chiave:

- **`unzip`**: Rivela perché un zip file potrebbe non decomprimersi.
- **`zipdetails -v`**: Offre un'analisi dettagliata dei campi del formato zip file.
- **`zipinfo`**: Elenca il contenuto di un zip file senza estrarlo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentano di riparare zip files corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uno strumento per il brute-force cracking delle password degli zip, efficace per password fino a circa 7 caratteri.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli completi sulla struttura e sugli standard dei zip files.

È fondamentale notare che i zip files protetti da password **non cifrano i nomi dei file né le dimensioni dei file** al loro interno, una falla di sicurezza non presente in RAR o 7z che cifrano queste informazioni. Inoltre, i zip files crittografati con il metodo ZipCrypto sono vulnerabili a un **plaintext attack** se è disponibile una copia non cifrata di un file compresso. Questo attacco sfrutta il contenuto noto per craccare la password dello zip, una vulnerabilità dettagliata in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e ulteriormente spiegata in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Tuttavia, i zip files protetti con **AES-256** sono immuni a questo plaintext attack, evidenziando l'importanza di scegliere metodi di crittografia sicuri per i dati sensibili.

---

## Trucchi anti-reversing negli APK usando header ZIP manipolati

I moderni Android malware droppers usano metadati ZIP malformati per rompere gli strumenti statici (jadx/apktool/unzip) mantenendo però l'APK installabile sul dispositivo. I trucchi più comuni sono:

- Fake encryption impostando il bit 0 del ZIP General Purpose Bit Flag (GPBF)
- Abuso di campi Extra grandi/personalizzati per confondere i parser
- Collisioni di nomi file/directory per nascondere artefatti reali (es., una directory chiamata `classes.dex/` accanto al vero `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Sintomi:
- `jadx-gui` fallisce con errori come:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` chiede una password per file core dell'APK anche se un APK valido non può avere `classes*.dex`, `resources.arsc`, o `AndroidManifest.xml` cifrati:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Rilevamento con zipdetails:
```bash
zipdetails -v sample.apk | less
```
Esamina il General Purpose Bit Flag per le intestazioni locali e centrali. Un valore rivelatore è il bit 0 impostato (Encryption) anche per le voci core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Euristica: se un APK si installa e viene eseguito sul dispositivo ma le voci core appaiono "encrypted" agli strumenti, il GPBF è stato manomesso.

Correggi cancellando il bit 0 del GPBF sia nelle Local File Headers (LFH) che nelle voci della Central Directory (CD). Minimal byte-patcher:

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

Uso:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Dovresti ora vedere `General Purpose Flag  0000` sulle voci principali e gli strumenti analizzeranno nuovamente l'APK.

### 2) Campi Extra grandi/personalizzati per rompere i parser

Gli attaccanti inseriscono campi Extra sovradimensionati e ID strani nelle intestazioni per far fallire i decompilatori. Nel mondo reale potresti vedere marker personalizzati (es., stringhe come `JADXBLOCK`) incorporati lì.

Ispezione:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Esempi osservati: ID sconosciuti come `0xCAFE` ("Java Executable") o `0x414A` ("JA:") che contengono payload di grandi dimensioni.

Euristiche DFIR:
- Segnalare quando i campi Extra sono insolitamente grandi sulle voci core (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considerare sospetti gli ID Extra sconosciuti su quelle voci.

Mitigazione pratica: ricreare l'archivio (es., re-zipping dei file estratti) rimuove i campi Extra dannosi. Se gli strumenti rifiutano di estrarre a causa di una falsa crittografia, prima azzerare il bit 0 del GPBF come sopra, quindi ripacchettare:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisioni di nomi file/directory (nascondere artefatti reali)

A ZIP può contenere sia un file `X` che una directory `X/`. Alcuni extractors e decompilers si confondono e possono sovrapporre o nascondere il file reale con una voce di directory. Questo è stato osservato con entries che collisionano con nomi core di APK come `classes.dex`.

Triage e estrazione sicura:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Post-fix per il rilevamento programmatico:
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
- Flag APKs i cui header locali indicano crittografia (GPBF bit 0 = 1) ma vengono comunque installati/eseguiti.
- Flag Extra fields grandi/sconosciuti sulle core entries (cerca marcatori come `JADXBLOCK`).
- Flag collisioni di percorso (`X` and `X/`) specificamente per `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Altri trucchi maligni con ZIP (2024–2026)

### Directory centrali concatenate (evasione multi-EOCD)

Campagne di phishing recenti inviano un singolo blob che è in realtà **due file ZIP concatenati**. Ognuno ha il suo End of Central Directory (EOCD) + central directory. Diversi extractors parsano directory diverse (7zip legge la prima, WinRAR l'ultima), permettendo agli attaccanti di nascondere payload che solo alcuni strumenti mostrano. Questo aggira anche mail gateway AV di base che ispezionano solo la prima directory.

**Comandi di triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Se appare più di un EOCD o ci sono avvisi "data after payload", dividi il blob e ispeziona ogni parte:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Una moderna "better zip bomb" costruisce un minuscolo **kernel** (blocco DEFLATE altamente compresso) e lo riutilizza tramite header locali sovrapposti. Ogni voce della central directory punta agli stessi dati compressi, raggiungendo rapporti >28M:1 senza annidare archivi. Le librerie che si affidano alle dimensioni della central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) possono essere costrette ad allocare petabyte.

**Rilevamento rapido (duplicate LFH offsets)**
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
**Gestione**
- Eseguire un dry-run: `zipdetails -v file.zip | grep -n "Rel Off"` e assicurarsi che gli offset siano strettamente crescenti e univoci.
- Limitare la dimensione totale decompressa accettata e il numero di voci prima dell'estrazione (`zipdetails -t` o un parser personalizzato).
- Se è necessario estrarre, farlo dentro un cgroup/VM con limiti CPU e disco (evitare crash dovuti a inflazione non limitata).

---

### Confusione tra parser local-header vs central-directory

Ricerche recenti sui differential parser hanno mostrato che l'ambiguità ZIP è ancora sfruttabile nelle toolchain moderne. L'idea principale è semplice: alcuni software si fidano del **Local File Header (LFH)** mentre altri si affidano alla **Central Directory (CD)**, quindi un unico archivio può presentare nomi file, percorsi, commenti, offset o insiemi di voci diversi a strumenti differenti.

Usi offensivi pratici:
- Fare in modo che un filtro di upload, uno pre-scan AV o un package validator veda un file benigno nella CD mentre l'estrattore rispetta un nome/percorso diverso nel LFH.
- Abusare di nomi duplicati, voci presenti solo in una struttura, o di metadati di percorso Unicode ambigui (per esempio, Info-ZIP Unicode Path Extra Field `0x7075`) in modo che parser diversi ricostruiscano alberi differenti.
- Combinare questo con path traversal per trasformare una vista dell'archivio "innocua" in una write-primitive durante l'estrazione. Per il lato estrazione, vedi [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triage DFIR:
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
Non hai fornito il contenuto da tradurre o il testo con cui completarlo. Per favore incolla il contenuto di src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md o il testo aggiuntivo che vuoi venga integrato; procederò a tradurre e completare non appena lo ricevo.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Euristiche:
- Rifiutare o isolare gli archivi con nomi LFH/CD non corrispondenti, nomi di file duplicati, multiple voci EOCD, o byte finali dopo l'EOCD finale.
- Considerare sospetti gli ZIP che usano campi extra Unicode-path insoliti o commenti incoerenti se strumenti diversi discordano sull'albero estratto.
- Se l'analisi è più importante della preservazione dei byte originali, ripacchettare l'archivio con un parser rigoroso dopo l'estrazione in una sandbox e confrontare l'elenco dei file risultante con i metadati originali.

Questo è rilevante oltre gli ecosistemi di pacchetti: la stessa classe di ambiguità può nascondere payload a gateway di posta, scanner statici e pipeline di ingestione personalizzate che "sbirciano" il contenuto dello ZIP prima che un altro extractor gestisca l'archivio.

---



## Riferimenti

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}
