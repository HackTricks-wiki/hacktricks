# Trucchi per ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Strumenti da riga di comando** per gestire **file ZIP** sono essenziali per diagnosticare, riparare e crackare file ZIP. Ecco alcune utility chiave:

- **`unzip`**: Rivela perché un file ZIP potrebbe non decomprimersi.
- **`zipdetails -v`**: Offre un'analisi dettagliata dei campi del formato ZIP.
- **`zipinfo`**: Elenca il contenuto di un file ZIP senza estrarlo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Provano a riparare file ZIP corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uno strumento per il brute-force delle password ZIP, efficace per password fino a circa 7 caratteri.

La [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli completi sulla struttura e sugli standard dei file ZIP.

È fondamentale notare che i file ZIP protetti da password **do not encrypt filenames or file sizes** al loro interno, una falla di sicurezza non presente in RAR o 7z che criptano queste informazioni. Inoltre, i file ZIP criptati con il vecchio metodo ZipCrypto sono vulnerabili a un **plaintext attack** se è disponibile una copia non criptata di un file compresso. Questo attacco sfrutta il contenuto noto per crackare la password dello ZIP, una vulnerabilità dettagliata in [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e ulteriormente spiegata in [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Tuttavia, i file ZIP protetti con crittografia **AES-256** sono immuni a questo plaintext attack, evidenziando l'importanza di scegliere metodi di crittografia sicuri per i dati sensibili.

---

## Anti-reversing tricks negli APK che usano header ZIP manipolati

I modern Android malware droppers usano metadata ZIP malformati per rompere strumenti statici (jadx/apktool/unzip) mantenendo però l'APK installabile sul dispositivo. I trucchi più comuni sono:

- Fake encryption impostando il ZIP General Purpose Bit Flag (GPBF) bit 0
- Abuso di Extra fields grandi/personalizzati per confondere i parser
- Collisioni di nomi file/directory per nascondere artefatti reali (es., una directory chiamata `classes.dex/` accanto al reale `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Sintomi:
- `jadx-gui` fallisce con errori come:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` richiede una password per file APK core anche se un APK valido non può avere `classes*.dex`, `resources.arsc`, o `AndroidManifest.xml` criptati:

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
Guarda il General Purpose Bit Flag per gli header locali e centrali. Un valore rivelatore è il bit 0 impostato (Encryption) anche per le voci principali:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Euristica: se un APK si installa ed esegue sul dispositivo ma le voci core appaiono "encrypted" agli strumenti, il GPBF è stato manomesso.

Soluzione: cancellare il bit 0 del GPBF sia nelle Local File Headers (LFH) sia nelle voci della Central Directory (CD). Minimal byte-patcher:

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

### 2) Campi Extra grandi/personalizzati per far fallire i parser

Gli attaccanti inseriscono campi Extra sovradimensionati e ID strani negli header per mandare in errore i decompilatori. In natura potresti vedere marcatori personalizzati (es., stringhe come `JADXBLOCK`) incorporati lì.

Ispezione:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Esempi osservati: ID sconosciuti come `0xCAFE` ("Java Executable") o `0x414A` ("JA:") che trasportano payload di grandi dimensioni.

DFIR heuristics:
- Segnalare quando i campi Extra sono insolitamente grandi sulle voci core (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considerare sospetti gli Extra ID sconosciuti su quelle voci.

Mitigazione pratica: ricostruire l'archivio (es. re-zippare i file estratti) rimuove i campi Extra malevoli. Se gli strumenti si rifiutano di estrarre a causa di una falsa crittografia, prima azzerare GPBF bit 0 come sopra, poi riconfezionare:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisione nomi file/directory (nascondere artefatti reali)

Un ZIP può contenere sia un file `X` che una directory `X/`. Alcuni estrattori e decompilatori si confondono e possono sovrapporre o nascondere il file reale con una voce di directory. Questo è stato osservato con voci che collidono con nomi core di APK come `classes.dex`.

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
Blue-team: idee di rilevamento:
- Segnala APKs i cui header locali indicano crittografia (GPBF bit 0 = 1) ma che comunque installano/eseguono.
- Segnala campi Extra grandi/sconosciuti nelle entry core (cerca marker come `JADXBLOCK`).
- Segnala collisioni di percorso (`X` e `X/`) specificamente per `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Altri trucchi ZIP malevoli (2024–2025)

### Directory centrali concatenate (evasione multi-EOCD)

Recenti campagne di phishing inviano un singolo blob che in realtà è **due file ZIP concatenati**. Ognuno ha il proprio End of Central Directory (EOCD) + central directory. Estrattori diversi parsano directory diverse (7zip legge la prima, WinRAR l'ultima), permettendo agli attaccanti di nascondere payload che solo alcuni tool mostrano. Questo bypassa anche i semplici AV dei mail gateway che ispezionano solo la prima directory.

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

Le moderne "better zip bomb" costruiscono un piccolo **nucleo** (blocco DEFLATE altamente compresso) e lo riutilizzano tramite local headers sovrapposti. Ogni voce della central directory punta agli stessi dati compressi, raggiungendo rapporti >28M:1 senza nidificare archivi. Le librerie che si fidano delle dimensioni nella central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP prima delle hardened builds) possono essere costrette ad allocare petabyte.

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
- Eseguire una simulazione (dry-run): `zipdetails -v file.zip | grep -n "Rel Off"` e verificare che gli offset siano strettamente crescenti e univoci.
- Limitare la dimensione totale non compressa accettata e il conteggio delle entry prima dell'estrazione (`zipdetails -t` o un parser personalizzato).
- Quando è necessario estrarre, farlo all'interno di un cgroup/VM con limiti su CPU e disco (evitare crash da inflazione illimitata).

---

## Riferimenti

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}
