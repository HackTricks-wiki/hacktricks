# Trucchi ZIP

{{#include ../../../banners/hacktricks-training.md}}

Gli **strumenti da riga di comando** per gestire i **file zip** sono essenziali per diagnosticare, riparare e craccare i file zip. Ecco alcune utility importanti:<sup>[[1]](#references)</sup>

- **`unzip`**: rivela perché un file zip potrebbe non essere decompresso.
- **`zipdetails -v`**: offre un'analisi dettagliata dei campi del formato zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: elenca i contenuti di un file zip senza estrarli.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: tentano di riparare i file zip corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: uno strumento per il brute-force delle password zip, efficace per password fino a circa 7 caratteri.

La [specifica del formato dei file Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli completi sulla struttura e sugli standard dei file zip.<sup>[[4]](#references)</sup>

È fondamentale notare che i file zip protetti da password **non criptano i nomi dei file né le dimensioni dei file** contenuti al loro interno, una falla di sicurezza non condivisa dai file RAR o 7z, che criptano queste informazioni. Inoltre, i file zip criptati con il metodo precedente ZipCrypto sono vulnerabili a un **plaintext attack** se è disponibile una copia non criptata di un file compresso.<sup>[[1]](#references)</sup> Questo attacco sfrutta il contenuto noto per craccare la password dello zip, una vulnerabilità descritta nell'[articolo di HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e spiegata ulteriormente in [questo paper accademico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> Tuttavia, i file zip protetti con la cifratura **AES-256** sono immuni a questo plaintext attack, dimostrando l'importanza di scegliere metodi di cifratura sicuri per i dati sensibili.<sup>[[1]](#references)</sup>

---

## Trucchi anti-reversing negli APK usando header ZIP manipolati

I moderni malware droppers Android utilizzano metadati ZIP malformati per mandare in errore gli strumenti statici (jadx/apktool/unzip), mantenendo però l'APK installabile sul dispositivo. I trucchi più comuni sono:<sup>[[2]](#references)</sup>

- Finta cifratura impostando il bit 0 del General Purpose Bit Flag (GPBF) dello ZIP
- Abuso di campi Extra di grandi dimensioni o personalizzati per confondere i parser
- Collisioni tra nomi di file/directory per nascondere artefatti reali (ad esempio, una directory denominata `classes.dex/` accanto al vero `classes.dex`)

### 1) Finta cifratura (bit 0 del GPBF impostato) senza crittografia reale

Sintomi:
- `jadx-gui` fallisce con errori come:

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` richiede una password per i file core dell'APK, anche se un APK valido non può avere `classes*.dex`, `resources.arsc` o `AndroidManifest.xml` criptati:

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
Controlla il General Purpose Bit Flag per gli header locali e centrali. Un valore rivelatore è il bit 0 impostato (Encryption) anche per le entry core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Euristica: se un APK si installa e viene eseguito sul dispositivo, ma le voci principali risultano "crittografate" agli strumenti, il GPBF è stato manomesso.

Risolvi cancellando il bit 0 del GPBF sia nelle Local File Headers (LFH) sia nelle voci della Central Directory (CD). Minimal byte-patcher:

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

Utilizzo:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Dovresti ora vedere `General Purpose Flag  0000` nelle voci principali e gli strumenti analizzeranno nuovamente l'APK.

### 2) Campi Extra grandi/personalizzati per mandare in errore i parser

Gli aggressori inseriscono campi Extra sovradimensionati e ID insoliti negli header per mandare in errore i decompiler. In natura potresti vedere marker personalizzati (ad esempio stringhe come `JADXBLOCK`) incorporati al loro interno.

Ispezione:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Esempi osservati: ID sconosciuti come `0xCAFE` ("Java Executable") o `0x414A` ("JA:") contenenti payload di grandi dimensioni.

Euristiche DFIR:
- Generare un alert quando i campi Extra sono insolitamente grandi nelle voci principali (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considerare sospetti gli ID Extra sconosciuti in tali voci.

Mitigazione pratica: ricostruire l'archivio (ad esempio, ricomprimendo i file estratti) rimuove i campi Extra malevoli. Se gli strumenti rifiutano di estrarre i file a causa di una falsa cifratura, prima azzerare il bit 0 del GPBF come indicato sopra, quindi ricreare il pacchetto:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisioni tra nomi di file/directory (nascondere artefatti reali)

Un ZIP può contenere sia un file `X` sia una directory `X/`. Alcuni estrattori e decompilatori possono confondersi e sovrapporre o nascondere il file reale con una voce di directory. Questo è stato osservato con voci in collisione con nomi APK fondamentali come `classes.dex`.

Analisi preliminare ed estrazione sicura:
```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```
Rilevamento programmatico post-fix:
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
Idee per il rilevamento da parte del blue-team:
- Segnalare gli APK i cui header locali indicano la cifratura (GPBF bit 0 = 1) ma che vengono installati/eseguiti.
- Segnalare campi Extra grandi/sconosciuti nelle entry principali (cercare marker come `JADXBLOCK`).
- Segnalare le collisioni nei path (`X` e `X/`) in particolare per `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Altri trucchi ZIP malevoli (2024–2026)

### Concatenated central directories (multi-EOCD evasion)

Recenti campagne di phishing distribuiscono un singolo blob che in realtà contiene **due file ZIP concatenati**. Ognuno ha il proprio End of Central Directory (EOCD) e la propria central directory. Extractor diversi analizzano directory diverse (7zip legge la prima, WinRAR l’ultima), consentendo agli attaccanti di nascondere payload che solo alcuni strumenti mostrano. Questo permette inoltre di eludere gli antivirus dei mail gateway di base che analizzano solo la prima directory.<sup>[[5]](#references)[[6]](#references)</sup>

**Comandi di triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Se compare più di un EOCD o ci sono avvisi "data after payload", dividi il blob ed esamina ogni parte:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Le build moderne di **better zip bomb** costruiscono un piccolo **kernel** (blocco DEFLATE altamente compresso) e lo riutilizzano tramite local header sovrapposti. Ogni entry della central directory punta agli stessi dati compressi, ottenendo rapporti >28M:1 senza archivi annidati. Le librerie che si fidano delle dimensioni della central directory (`zipfile` di Python, `java.util.zip` di Java, Info-ZIP prima delle build hardened) possono essere costrette ad allocare petabyte.<sup>[[7]](#references)[[8]](#references)</sup>

**Rilevamento rapido (offset LFH duplicati)**
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
**Handling**
- Esegui una scansione a secco: `zipdetails -v file.zip | grep -n "Rel Off"` e assicurati che gli offset siano strettamente crescenti e univoci.
- Imposta un limite alla dimensione totale non compressa accettata e al numero di entry prima dell'estrazione (`zipdetails -t` o un parser personalizzato).
- Quando devi estrarre, fallo all'interno di un cgroup/VM con limiti su CPU e disco (evita crash dovuti a espansioni non limitate).

---

### Confusione tra parser del local header e del central directory

Recenti ricerche sui differential-parser hanno dimostrato che l'ambiguità ZIP è ancora sfruttabile nelle toolchain moderne. L'idea principale è semplice: alcuni software si fidano del **Local File Header (LFH)**, mentre altri si fidano del **Central Directory (CD)**, quindi un solo archivio può presentare nomi di file, percorsi, commenti, offset o set di entry diversi a strumenti diversi.<sup>[[9]](#references)</sup>

Usi offensivi pratici:
- Fai in modo che un upload filter, una pre-scansione AV o un package validator visualizzi un file benigno nel CD mentre l'estrattore utilizza un nome/percorso LFH diverso.
- Sfrutta nomi duplicati, entry presenti solo in una delle due strutture o metadati ambigui dei percorsi Unicode (ad esempio l'Info-ZIP Unicode Path Extra Field `0x7075`), in modo che parser diversi ricostruiscano alberi differenti.
- Combina tutto questo con il path traversal per trasformare una visualizzazione "innocua" dell'archivio in una write-primitive durante l'estrazione. Per il lato dell'estrazione, consulta [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Integrarlo con:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Euristiche:
- Rifiuta o isola gli archivi con nomi LFH/CD non corrispondenti, nomi di file duplicati, più record EOCD o byte aggiuntivi dopo l'ultimo EOCD.<sup>[[10]](#references)</sup>
- Considera sospetti gli ZIP che utilizzano campi extra insoliti per i percorsi Unicode o commenti incoerenti, se strumenti diversi non concordano sull'albero estratto.<sup>[[9]](#references)</sup>
- Se l'analisi è più importante della conservazione dei byte originali, reimpacchetta l'archivio con un parser rigoroso dopo l'estrazione in un sandbox e confronta l'elenco di file risultante con i metadati originali.

Questo è importante anche al di fuori degli ecosistemi dei package: la stessa classe di ambiguità può nascondere payload ai gateway di posta, agli scanner statici e alle pipeline di ingestion personalizzate che fanno "peek" sul contenuto degli ZIP prima che un extractor differente gestisca l'archivio.

---



## Riferimenti

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
