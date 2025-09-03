# Trucchi per ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** per gestire **zip files** sono essenziali per diagnosticare, riparare e crackare zip files. Ecco alcune utility chiave:

- **`unzip`**: Mostra perché un file zip potrebbe non decomprimersi.
- **`zipdetails -v`**: Offre un'analisi dettagliata dei campi del formato zip.
- **`zipinfo`**: Elenca i contenuti di un file zip senza estrarli.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentano di riparare file zip corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uno strumento per il brute-force delle password di zip, efficace per password fino a circa 7 caratteri.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli completi sulla struttura e sugli standard dei file zip.

È importante notare che i file zip protetti da password **non criptano i nomi dei file né le dimensioni dei file** al loro interno, una falla di sicurezza non presente in RAR o 7z che criptano queste informazioni. Inoltre, i file zip criptati con il vecchio metodo ZipCrypto sono vulnerabili a un **plaintext attack** se è disponibile una copia non criptata di un file compresso. Questo attacco sfrutta il contenuto noto per crackare la password dello zip, una vulnerabilità descritta nell'articolo di [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e ulteriormente spiegata in [questo paper accademico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Tuttavia, i file zip protetti con crittografia **AES-256** sono immuni a questo plaintext attack, evidenziando l'importanza di scegliere metodi di crittografia sicuri per dati sensibili.

---

## Trucchi anti-reversing negli APK usando header ZIP manipolati

I moderni droppers per Android usano metadata ZIP malformati per rompere strumenti statici (jadx/apktool/unzip) mantenendo però l'APK installabile sul dispositivo. I trucchi più comuni sono:

- Finta crittografia impostando il ZIP General Purpose Bit Flag (GPBF) bit 0
- Abuso di Extra fields grandi/personalizzati per confondere i parser
- Collisioni di nomi file/directory per nascondere artefatti reali (es., una directory chiamata `classes.dex/` accanto al vero `classes.dex`)

### 1) Finta crittografia (GPBF bit 0 impostato) senza vera crittografia

Sintomi:
- `jadx-gui` fallisce con errori come:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` chiede una password per file core dell'APK anche se un APK valido non può avere cifrati `classes*.dex`, `resources.arsc`, o `AndroidManifest.xml`:

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
Guarda il General Purpose Bit Flag per le intestazioni locali e centrali. Un valore indicativo è il bit 0 impostato (Encryption) anche per le voci principali:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Euristica: se un APK viene installato ed eseguito sul dispositivo ma le voci core appaiono "encrypted" agli strumenti, la GPBF è stata manomessa.

Risolvi azzerando il bit 0 del GPBF sia nelle Local File Headers (LFH) sia nelle voci della Central Directory (CD). Minimal byte-patcher:
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
Uso:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Ora dovresti vedere `General Purpose Flag  0000` sulle voci core e gli strumenti analizzeranno di nuovo l'APK.

### 2) Campi Extra grandi/personalizzati per rompere i parser

Gli attaccanti inseriscono campi Extra sovradimensionati e ID insoliti negli header per mandare in errore i decompilatori. Nel mondo reale potresti vedere marker personalizzati (es., stringhe come `JADXBLOCK`) incorporati lì.

Ispezione:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Esempi osservati: ID sconosciuti come `0xCAFE` ("Java Executable") o `0x414A` ("JA:") che contengono payload di grandi dimensioni.

Euristiche DFIR:
- Segnalare quando i campi Extra sono insolitamente grandi sulle voci core (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considerare gli ID Extra sconosciuti su quelle voci come sospetti.

Mitigazione pratica: ricostruire l'archivio (ad esempio, comprimere nuovamente i file estratti) rimuove i campi Extra maligni. Se gli strumenti si rifiutano di estrarre a causa di una falsa crittografia, prima azzerare il bit 0 di GPBF come sopra, poi ricreare il pacchetto:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) File/Directory name collisions (nascondere artefatti reali)

Un file ZIP può contenere sia un file `X` che una directory `X/`. Alcuni extractors e decompilers si confondono e possono sovrapporre o nascondere il file reale con una voce di directory. Ciò è stato osservato con voci che collidevano con nomi core di APK come `classes.dex`.

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
Suffisso post-rilevamento programmatico:
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
- Segnala gli APK i cui header locali indicano crittografia (GPBF bit 0 = 1) ma che comunque vengono installati/avviati.
- Segnala campi Extra grandi/sconosciuti sulle core entries (cerca marker come `JADXBLOCK`).
- Segnala collisioni di percorso (`X` and `X/`) specificamente per `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Riferimenti

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
