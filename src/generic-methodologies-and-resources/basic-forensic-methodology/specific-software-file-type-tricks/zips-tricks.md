# Trucchi per ZIP

Gli **strumenti da riga di comando** per gestire i **file zip** sono essenziali per diagnosticare, riparare e craccare i file zip. Ecco alcune utility chiave:<sup>[[1]](#references)</sup>

- **`unzip`**: rivela perché un file zip potrebbe non essere decompresso.
- **`zipdetails -v`**: offre un'analisi dettagliata dei campi del formato dei file zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: elenca i contenuti di un file zip senza estrarli.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: tentano di riparare i file zip corrotti.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: uno strumento per il brute-force delle password zip, efficace per password fino a circa 7 caratteri.

La [specifica del formato dei file Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce dettagli completi sulla struttura e sugli standard dei file zip.<sup>[[4]](#references)</sup>

È fondamentale notare che i file ZIP protetti da password tradizionali generalmente lasciano visibili i nomi dei file e le dimensioni dei file, a differenza delle modalità di cifratura degli header supportate da RAR e 7z. Inoltre, i file ZIP cifrati con il metodo ZipCrypto più obsoleto sono vulnerabili a un **plaintext attack** se è disponibile una copia non cifrata di un file compresso.<sup>[[1]](#references)</sup> Questo attacco sfrutta il contenuto noto per craccare la password dello ZIP, come spiegato in [questo paper accademico](https://math.ucr.edu/~mike/zipattacks.pdf) e illustrato in [questo walk-through di Hack This Site](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Tuttavia, il known-plaintext attack di ZipCrypto non si applica alle entry protette con cifratura **AES-256**.<sup>[[1]](#references)</sup>

---

## Trucchi anti-reversing negli APK che usano header ZIP manipolati

I moderni malware dropper per Android utilizzano metadati ZIP malformati per compromettere gli strumenti statici (jadx/apktool/unzip), mantenendo però l'APK installabile sul dispositivo. I trucchi più comuni sono:<sup>[[2]](#references)</sup>

- Finta cifratura impostando il bit 0 del General Purpose Bit Flag (GPBF) dello ZIP
- Abuso di campi Extra di grandi dimensioni o personalizzati per confondere i parser
- Collisioni tra nomi di file e directory per nascondere artefatti reali (ad esempio, una directory denominata `classes.dex/` accanto al vero `classes.dex`)

### 1) Finta cifratura (bit 0 del GPBF impostato) senza crittografia reale

Sintomi:
- `jadx-gui` fallisce con errori come:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` richiede una password per i file principali dell'APK, anche se un APK valido non può avere `classes*.dex`, `resources.arsc` o `AndroidManifest.xml` cifrati:

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
Osserva il General Purpose Bit Flag per gli header locali e centrali. Un valore rivelatore è il bit 0 impostato (Encryption) anche per le voci core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Euristica: se un APK si installa e viene eseguito sul dispositivo, ma le voci principali appaiono "crittografate" agli strumenti, il GPBF è stato manomesso.

Correggi cancellando il bit 0 del GPBF sia nelle Local File Headers (LFH) sia nelle voci della Central Directory (CD). Patcher minimale dei byte:

<details>
<summary>Patcher minimale per cancellare il bit GPBF</summary>
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
Ora dovresti vedere `General Purpose Flag  0000` nelle voci principali e gli strumenti potranno analizzare nuovamente l'APK.

### 2) Campi Extra grandi/personalizzati per mandare in errore i parser

Gli attaccanti inseriscono campi Extra sovradimensionati e ID anomali negli header per mandare in errore i decompiler. In natura potresti trovare marker personalizzati, ad esempio stringhe come `JADXBLOCK`, incorporati al loro interno.

Ispezione:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Esempi osservati: ID sconosciuti come `0xCAFE` ("Java Executable") o `0x414A` ("JA:") contenenti payload di grandi dimensioni.<sup>[[2]](#references)</sup>

Euristiche DFIR:
- Generare un avviso quando i campi Extra sono insolitamente grandi nelle voci principali (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considerare sospetti gli Extra ID sconosciuti in tali voci.

Mitigazione pratica: ricostruire l'archivio (ad esempio, ricomprimendo i file estratti) rimuove i campi Extra malevoli. Se gli strumenti rifiutano di eseguire l'estrazione a causa di una crittografia falsa, prima cancellare il bit 0 di GPBF come indicato sopra, quindi ricreare il package:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Collisioni tra nomi di file/directory (nascondere artefatti reali)

Un file ZIP può contenere sia un file `X` sia una directory `X/`. Alcuni extractor e decompiler si confondono e possono sovrapporre o nascondere il file reale con una voce di directory. Questo è stato osservato con voci in conflitto con nomi core degli APK come `classes.dex`.

Triage ed estrazione sicura:
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
Idee per il rilevamento da parte del Blue-team:
- Segnalare gli APK i cui local headers indicano la cifratura (GPBF bit 0 = 1), ma che vengono comunque installati/eseguiti.
- Segnalare campi Extra grandi o sconosciuti nelle entry principali (cercare marker come `JADXBLOCK`).
- Segnalare le collisioni nei percorsi (`X` e `X/`) in particolare per `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Altri trucchi dannosi per ZIP (2024–2026)

### Central directories concatenate (elusione multi-EOCD)

In una campagna di phishing del 2024, gli attaccanti hanno distribuito un singolo blob che in realtà era costituito da **due file ZIP concatenati**. Ognuno aveva il proprio record End of Central Directory (EOCD) e la propria central directory. Extractor diversi analizzavano directory diverse (7-Zip leggeva la prima, mentre WinRAR leggeva l'ultima), consentendo agli attaccanti di nascondere payload che solo alcuni tool mostravano; gli scanner che ispezionano una sola directory possono non rilevare l'altro archivio.<sup>[[5]](#references)[[6]](#references)</sup>

**Comandi di triage**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```
Se compare più di un EOCD o vengono visualizzati avvisi di "data after payload", suddividi il blob ed esamina ogni parte:
```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Le ZIP bombs Quoted-overlap costruiscono un piccolo **kernel** (un blocco DEFLATE altamente compresso) e lo riutilizzano tra voci sovrapposte. Le varianti full-overlap fanno puntare più voci della directory centrale a un unico local header, mentre le varianti quoted-overlap includono i local header all'interno degli stream DEFLATE; la costruzione pubblicata raggiunge un rapporto superiore a 28M:1 senza archivi annidati.<sup>[[7]](#references)</sup>

**Rilevamento rapido (duplicate LFH offsets)**
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
**Gestione**
- Esegui una scansione preliminare a secco: `zipdetails -v file.zip | grep -n "Local Header Offset"` e confronta gli offset dei local header indicati e gli intervalli dei dati compressi; gli offset duplicati indicano varianti con sovrapposizione completa.<sup>[[7]](#references)[[8]](#references)</sup>
- Limita la dimensione totale non compressa accettata e il numero di entry prima dell'estrazione tramite un parser; `zipinfo -t file.zip` riporta i totali, ma non applica alcun limite di sicurezza.<sup>[[8]](#references)</sup>
- Quando devi eseguire l'estrazione, fallo all'interno di un cgroup/VM con limiti di CPU e disco (evita crash dovuti a un'inflazione non limitata).<sup>[[8]](#references)</sup>

---

### Confusione tra parser di local header e central directory

Recenti ricerche sui parser differential hanno dimostrato che l'ambiguità ZIP è ancora sfruttabile nelle toolchain moderne. L'idea principale è semplice: alcuni software si fidano del **Local File Header (LFH)**, mentre altri si fidano della **Central Directory (CD)**; di conseguenza, un singolo archivio può presentare nomi di file, percorsi, commenti, offset o set di entry diversi a tool differenti.<sup>[[9]](#references)</sup>

Usi offensivi pratici:
- Fai in modo che un upload filter, una pre-scansione AV o un package validator visualizzi un file benigno nella CD, mentre l'estrattore utilizza un nome/percorso LFH diverso.
- Sfrutta nomi duplicati, entry presenti soltanto in una delle due strutture o metadati ambigui dei percorsi Unicode (ad esempio, l'Info-ZIP Unicode Path Extra Field `0x7075`), in modo che parser diversi ricostruiscano alberi differenti.
- Combina questo con il path traversal per trasformare una visualizzazione "innocua" dell'archivio in una primitiva di scrittura durante l'estrazione. Per il lato dell'estrazione, consulta [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Incolla il contenuto da tradurre e integrare.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Euristiche:
- Per l'ingestion sensibile alla sicurezza, rifiuta o isola gli archivi con nomi LFH/CD non corrispondenti, nomi di file duplicati, più record EOCD o byte aggiuntivi dopo l'EOCD finale.<sup>[[9]](#references)[[10]](#references)</sup>
- Considera sospetti gli ZIP che utilizzano extra field insoliti per i percorsi Unicode o commenti incoerenti, se strumenti diversi non concordano sull'albero estratto.<sup>[[4]](#references)[[9]](#references)</sup>
- Se l'analisi è più importante della conservazione dei byte originali, riconfeziona l'archivio con un parser rigoroso dopo l'estrazione in un sandbox e confronta l'elenco dei file risultante con i metadati originali.

Questo è importante anche oltre gli ecosistemi dei pacchetti: la stessa classe di ambiguità può nascondere payload ai gateway email, agli scanner statici e alle pipeline di ingestion personalizzate che "danno un'occhiata" ai contenuti ZIP prima che un extractor diverso gestisca l'archivio.<sup>[[9]](#references)</sup>

---



## References

- [1] [Guida pratica alla computer forensics per CTF (blog di Mike, categoria CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Parte 1 – Un dropper multistadio (anti-reversing degli APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Specifiche del formato ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [La struttura flessibile degli archivi ZIP sfruttata per nascondere malware senza essere rilevati (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Gli hacker nascondono malware in un nuovo attacco tramite file ZIP — central directories ZIP concatenate](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Una zip bomb migliore (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Capire le Zip Bomb: costruzione del kernel con overlap/quoted-overlap](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Il mio ZIP non è il tuo ZIP: identificare e sfruttare i divari semantici tra i parser ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Prevenire gli attacchi di confusione dei parser ZIP negli installer di pacchetti Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Attacchi ZIP con testo in chiaro noto ridotto (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: missione Web realistica, livello 15 (attacco ZIP con testo in chiaro noto)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}
