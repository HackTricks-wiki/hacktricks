# Trucchi ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Strumenti da riga di comando** per la gestione dei **file zip** sono essenziali per diagnosticare, riparare e craccare zip. Ecco alcune utility chiave:

- **`unzip`**: Rivela perché un file zip potrebbe non decomprimersi.
- **`zipdetails -v`**: Offre un'analisi dettagliata dei campi del formato zip.
- **`zipinfo`**: Elenca il contenuto di un file zip senza estrarlo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Provano a riparare zip corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uno strumento per il brute-force delle password degli zip, efficace per password fino a circa 7 caratteri.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli completi sulla struttura e gli standard dei file zip.

È importante notare che i file zip protetti da password **non cifrano nomi di file o dimensioni dei file** al loro interno, una falla di sicurezza non presente in RAR o 7z che cifrano queste informazioni. Inoltre, gli zip cifrati con il metodo più vecchio ZipCrypto sono vulnerabili a un **plaintext attack** se è disponibile una copia non cifrata di un file compresso. Questo attacco sfrutta il contenuto noto per craccare la password dello zip, una vulnerabilità descritta nell'[articolo di HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e ulteriormente spiegata in [questo paper accademico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Tuttavia, gli zip protetti con cifratura **AES-256** sono immuni a questo plaintext attack, il che evidenzia l'importanza di scegliere metodi di cifratura sicuri per dati sensibili.

---

## Trucchi anti-reversing negli APK usando header ZIP manipolati

I droppers di malware Android moderni usano metadati ZIP malformati per rompere strumenti statici (jadx/apktool/unzip) mantenendo comunque l'APK installabile sul dispositivo. I trucchi più comuni sono:

- Fake encryption impostando il ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusare di Extra fields grandi/personalizzati per confondere i parser
- Collisioni di nomi file/directory per nascondere artefatti reali (es., una directory chiamata `classes.dex/` accanto al vero `classes.dex`)

### 1) Fake encryption (GPBF bit 0 impostato) senza vera crittografia

Sintomi:
- `jadx-gui` fallisce con errori come:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` richiede una password per file core dell'APK anche se un APK valido non può avere cifrati `classes*.dex`, `resources.arsc`, o `AndroidManifest.xml`:

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
Controlla il General Purpose Bit Flag per gli header locali e centrali. Un valore rivelatore è il bit 0 impostato (Encryption) anche per le voci core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Euristica: Se un APK si installa e viene eseguito sul dispositivo ma le voci principali appaiono "encrypted" agli strumenti, il GPBF è stato manomesso.

Correggi azzerando il bit 0 di GPBF sia nelle Local File Headers (LFH) che nelle voci del Central Directory (CD). Byte-patcher minimo:

<details>
<summary>Patcher minimo per azzerare il bit GPBF</summary>
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
Ora dovresti vedere `General Purpose Flag  0000` sulle voci core e gli strumenti analizzeranno nuovamente l'APK.

### 2) Campi Extra grandi/personalizzati per rompere i parser

Gli attaccanti inseriscono campi Extra sovradimensionati e ID insoliti negli header per mandare in errore i decompilatori. Nel mondo reale potresti vedere marcatori personalizzati (ad es., stringhe come `JADXBLOCK`) incorporati lì.

Ispezione:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Esempi osservati: ID sconosciuti come `0xCAFE` ("Eseguibile Java") o `0x414A` ("JA:") che trasportano payload di grandi dimensioni.

DFIR heuristics:
- Segnala quando i campi Extra sono insolitamente grandi nelle voci core (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratta come sospetti gli ID Extra sconosciuti in quelle voci.

Mitigazione pratica: ricostruire l'archivio (es., re-zippando i file estratti) elimina i campi Extra maligni. Se gli strumenti rifiutano di estrarre a causa di falsa crittografia, prima azzera GPBF bit 0 come sopra, quindi ripacchetta:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisioni di nomi file/directory (nascondere artefatti reali)

Un ZIP può contenere sia un file `X` che una directory `X/`. Alcuni extractors e decompilers si confondono e possono sovrapporre o nascondere il file reale con una voce di directory. Questo è stato osservato con voci che collidono con nomi principali di APK come `classes.dex`.

Triage and safe extraction:
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
Idee di rilevamento per il Blue-team:
- Segnala APKs i cui header locali indicano encryption (GPBF bit 0 = 1) ma che comunque si installano/run.
- Segnala Extra fields grandi/sconosciuti sulle core entries (cerca marker come `JADXBLOCK`).
- Segnala path-collisions (`X` and `X/`) specificamente per `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Altri trucchi ZIP malevoli (2024–2026)

### Directory centrali concatenate (evasione multi-EOCD)

Recenti campagne di phishing inviano un unico blob che è in realtà **due file ZIP concatenati**. Ognuno ha il proprio End of Central Directory (EOCD) + central directory. Diversi extractors parseano directory diverse (7zip legge la prima, WinRAR l'ultima), permettendo agli attackers di nascondere payload che solo alcuni strumenti mostrano. Questo bypassa anche gli AV dei mail gateway che ispezionano solo la prima directory.

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
### Quoted-overlap / overlapping-entry bombs (non ricorsivo)

Una moderna "better zip bomb" costruisce un piccolo **kernel** (blocco DEFLATE altamente compresso) e lo riutilizza tramite intestazioni locali sovrapposte. Ogni voce della central directory punta agli stessi dati compressi, ottenendo rapporti >28M:1 senza nidificare archivi. Le librerie che si affidano alle dimensioni della central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP prima di hardened builds) possono essere costrette ad allocare petabyte.

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
**Gestione**
- Eseguire un dry-run: `zipdetails -v file.zip | grep -n "Rel Off"` e assicurarsi che gli offset siano strettamente crescenti e unici.
- Limitare la dimensione totale non compressa accettata e il numero di voci prima dell'estrazione (`zipdetails -t` o parser personalizzato).
- Se è necessario estrarre, farlo dentro un cgroup/VM con limiti CPU e disco (evitare crash per inflazione illimitata).

---

### Confusione parser Local-header vs Central-directory

Recenti ricerche su differential-parser hanno dimostrato che l'ambiguità degli ZIP è ancora sfruttabile nelle toolchain moderne. L'idea principale è semplice: alcuni software si fidano del **Local File Header (LFH)** mentre altri si fidano della **Central Directory (CD)**, quindi un singolo archivio può presentare nomi file, percorsi, commenti, offset o insiemi di voci differenti a strumenti diversi.

Usi offensivi pratici:
- Far sì che un filtro di upload, un pre-scan AV o un validator di pacchetti veda un file benigno nella CD mentre l'estrattore rispetta un nome/percorso LFH differente.
- Abusare di nomi duplicati, voci presenti solo in una struttura, o metadati di percorso Unicode ambigui (per esempio, Info-ZIP Unicode Path Extra Field `0x7075`) così che parser diversi ricostruiscano alberi diversi.
- Combinare questo con path traversal per trasformare una vista "innocua" dell'archivio in una write-primitive durante l'estrazione. Per il lato estrazione, vedi [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
You didn’t include the file content or the text to “complement.” Please paste the markdown (or specify the exact additions) you want me to translate and/or append, and I’ll return the Italian translation preserving all tags, links and code as requested.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Euristiche:
- Rifiutare o isolare gli archivi con nomi LFH/CD discordanti, nomi di file duplicati, più record EOCD o byte terminali dopo l'EOCD finale.
- Considerare sospetti gli ZIP che utilizzano insoliti Unicode-path extra fields o commenti incoerenti se strumenti diversi non concordano sull'albero estratto.
- Se l'analisi è più importante della conservazione dei byte originali, ripacchettare l'archivio con un strict parser dopo l'estrazione in una sandbox e confrontare la lista dei file risultante con i metadati originali.

Questo è rilevante anche oltre gli ecosistemi dei package: la stessa classe di ambiguità può nascondere payloads a mail gateways, static scanners e custom ingestion pipelines che "peek" nei contenuti ZIP prima che un altro extractor gestisca l'archivio.

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
