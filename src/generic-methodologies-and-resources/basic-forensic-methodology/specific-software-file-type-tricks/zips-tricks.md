# Trucchi per ZIP

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** per gestire i **file zip** sono essenziali per diagnosticare, riparare e crackare zip. Ecco alcune utility chiave:

- **`unzip`**: Rivela perché un file zip potrebbe non decomprimersi.
- **`zipdetails -v`**: Offre un'analisi dettagliata dei campi del formato zip.
- **`zipinfo`**: Elenca il contenuto di uno zip senza estrarlo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Provano a riparare zip corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uno strumento per brute-force delle password di zip, efficace per password fino a circa 7 caratteri.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli completi sulla struttura e sugli standard dei file zip.

È importante notare che gli zip protetti da password **non criptano nomi di file o dimensioni dei file** al loro interno, un difetto di sicurezza non presente in RAR o 7z che invece criptano queste informazioni. Inoltre, gli zip criptati con il vecchio metodo ZipCrypto sono vulnerabili a un **plaintext attack** se è disponibile una copia non criptata di un file compresso. Questo attacco sfrutta il contenuto noto per crackare la password dello zip, una vulnerabilità descritta nell'[HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e spiegata più approfonditamente in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Tuttavia, gli zip protetti con crittografia **AES-256** sono immuni a questo plaintext attack, evidenziando l'importanza di scegliere metodi di cifratura sicuri per dati sensibili.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

I moderni malware droppers per Android utilizzano metadata ZIP malformati per rompere gli strumenti statici (jadx/apktool/unzip) mantenendo però l'APK installabile sul dispositivo. I trucchi più comuni sono:

- Fake encryption impostando il bit 0 del ZIP General Purpose Bit Flag (GPBF)
- Abuso di campi Extra di grandi dimensioni/personalizzati per confondere i parser
- Collisioni di nomi di file/directory per nascondere artefatti reali (es. una directory chiamata `classes.dex/` accanto al reale `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) senza crittografia reale

Sintomi:
- `jadx-gui` fallisce con errori come:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` chiede una password per file core dell'APK anche se un APK valido non può avere `classes*.dex`, `resources.arsc`, o `AndroidManifest.xml` criptati:

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
Guarda il General Purpose Bit Flag per gli header locali e centrali. Un valore rivelatore è il bit 0 impostato (Encryption) anche per le voci core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Euristica: Se un APK si installa e viene eseguito sul dispositivo ma le core entries appaiono "encrypted" agli strumenti, il GPBF è stato manomesso.

Correzione: cancellare il bit 0 del GPBF sia nelle Local File Headers (LFH) che nelle Central Directory (CD) entries. Minimal byte-patcher:
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
Ora dovresti vedere `General Purpose Flag  0000` sulle voci principali e gli strumenti analizzeranno nuovamente l'APK.

### 2) Grandi/personalizzati Extra fields per rompere i parsers

Gli attaccanti inseriscono Extra fields sovradimensionati e ID strani nei header per mandare in errore i decompilers. Nel mondo reale potresti vedere marcatori personalizzati (p.es., stringhe come `JADXBLOCK`) incorporati lì.

Ispezione:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Esempi osservati: ID sconosciuti come `0xCAFE` ("Eseguibile Java") o `0x414A` ("JA:") che contengono payloads di grandi dimensioni.

DFIR euristiche:
- Alert quando i campi Extra sono insolitamente grandi nelle voci core (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considerare sospetti gli Extra ID sconosciuti in quelle voci.

Mitigazione pratica: ricostruire l'archivio (ad esempio, ricomprimendo i file estratti) rimuove i campi Extra malevoli. Se gli strumenti rifiutano di estrarre a causa di una falsa crittografia, prima azzerare il bit 0 di GPBF come sopra, poi ripacchettare:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisioni tra nomi di file e directory (nascondere artefatti reali)

Un file ZIP può contenere sia un file `X` sia una directory `X/`. Alcuni strumenti di estrazione e decompilazione si confondono e possono sovrapporre o nascondere il file reale con una voce di directory. Questo è stato osservato per voci che collisionano con nomi principali degli APK come `classes.dex`.

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
Blue-team detection ideas:
- Segnala APKs i cui header locali indicano crittografia (GPBF bit 0 = 1) ma vengono comunque installati/eseguiti.
- Segnala campi Extra grandi o sconosciuti nelle entry core (cerca marker come `JADXBLOCK`).
- Segnala collisioni di percorso (`X` e `X/`) specificamente per `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Riferimenti

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}
