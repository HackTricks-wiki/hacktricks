# Trucchi con gli ZIP

{{#include ../../../banners/hacktricks-training.md}}

Gli **strumenti da riga di comando** per gestire i **file zip** sono essenziali per diagnosticare, riparare e craccare file zip. Ecco alcune utilità importanti:<sup>[[1]](#references)</sup>

- **`unzip`**: rivela perché un file zip potrebbe non essere decompresso.
- **`zipdetails -v`**: offre un’analisi dettagliata dei campi del formato zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: elenca i contenuti di un file zip senza estrarli.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: tentano di riparare file zip danneggiati.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: uno strumento per attacchi a dizionario e brute-force sulle password ZIP; la fattibilità dipende dallo spazio di ricerca delle password.<sup>[[15]](#references)</sup>

La [specifica del formato di file Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornisce informazioni complete sulla struttura e sugli standard dei file zip.<sup>[[4]](#references)</sup>

I tradizionali file ZIP protetti da password lasciano generalmente visibili i nomi e le dimensioni dei file, a differenza delle modalità di cifratura delle intestazioni supportate da RAR e 7z. Un attacco known-plaintext a ZipCrypto recupera le **chiavi di cifratura interne**, non necessariamente la password originale; le chiavi bastano per decifrare le voci cifrate con la stessa password.<sup>[[13]](#references)</sup> L’attacco richiede byte noti del flusso **prima della cifratura**: per un membro memorizzato, si tratta dei byte del file originale, mentre per un membro DEFLATE sono i byte compressi, che potrebbe essere necessario ricreare producendo esattamente lo stesso output di compressione.<sup>[[13]](#references)[[14]](#references)</sup> Consulta [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) per un flusso di lavoro pratico. Per approfondire la crittoanalisi, consulta [il documento](https://math.ucr.edu/~mike/zipattacks.pdf) e la [guida dettagliata](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Questo attacco a ZipCrypto non si applica alle voci ZIP cifrate con AES.<sup>[[13]](#references)</sup>

---

## Trucchi anti-reversing negli APK che usano intestazioni ZIP manipolate

I moderni dropper di malware Android usano metadati ZIP malformati per mandare in errore gli strumenti statici (jadx/apktool/unzip), mantenendo però l’APK installabile sul dispositivo. I trucchi più comuni sono:<sup>[[2]](#references)</sup>

- Finta cifratura impostando il bit 0 del General Purpose Bit Flag (GPBF) ZIP
- Abuso di campi Extra grandi o personalizzati per confondere i parser
- Collisioni tra nomi di file e directory per nascondere artefatti reali (ad es., una directory chiamata `classes.dex/` accanto al vero `classes.dex`)

### 1) Finta cifratura (bit 0 del GPBF impostato) senza crittografia reale

Sintomi:
- `jadx-gui` fallisce con errori come:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` richiede una password per i file APK principali, anche se un APK valido non può avere `classes*.dex`, `resources.arsc` o `AndroidManifest.xml` crittografati:
  
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

Controlla il General Purpose Bit Flag per gli header locali e centrali. Un valore rivelatore è il bit 0 impostato (Crittografia), anche per le voci principali:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Euristica: Se un APK si installa e funziona sul dispositivo, ma gli strumenti mostrano le voci principali come "crittografate", il GPBF è stato manomesso.

Correggi azzerando il bit 0 del GPBF sia nelle intestazioni dei file locali (LFH) sia nelle voci della directory centrale (CD). Patcher minimo dei byte:

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

Utilizzo:

```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```

Solo il bit 0 dovrebbe cambiare: per esempio, `0A09` diventa `0A08`, non `0000`. Questo patcher minimale cerca le signature degli header nei byte grezzi, quindi byte simili a una signature all’interno dei dati del file possono causare falsi match; lavora su una copia e verifica l’elenco delle voci e gli header risultanti prima di usare l’output.<sup>[[4]](#references)</sup>

### 2) Campi Extra grandi/personalizzati per mandare in errore i parser

Gli attacker inseriscono nei header campi Extra sovradimensionati e ID insoliti per mandare in errore i decompiler. In natura si possono trovare marker personalizzati (per esempio, stringhe come `JADXBLOCK`) incorporati al loro interno.

Ispezione:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Esempi osservati: ID sconosciuti come `0xCAFE` ("Java Executable") o `0x414A` ("JA:") che contengono payload di grandi dimensioni.<sup>[[2]](#references)</sup>

Euristiche DFIR:
- Genera un avviso quando i campi Extra sono insolitamente grandi nelle voci principali (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considera sospetti gli ID Extra sconosciuti in quelle voci.

Mitigazione pratica: ricreare l’archivio (ad esempio, ricomprimendo i file estratti) rimuove i campi Extra malevoli. Se gli strumenti si rifiutano di estrarre i file a causa della falsa crittografia, prima azzera il bit 0 di GPBF come sopra, poi ricrea il pacchetto:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Collisioni tra nomi di file/directory (nascondere artefatti reali)

Uno ZIP può contenere sia un file `X` sia una directory `X/`. Alcuni estrattori e decompilatori si confondono e possono sovrapporre o nascondere il file reale con una voce di directory. Questo comportamento è stato osservato con voci in conflitto con nomi di APK fondamentali come `classes.dex`.

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

Rilevamento programmatico dopo la correzione:

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

Idee di rilevamento per il blue team:
- Segnalare gli APK i cui header locali indicano la cifratura (GPBF bit 0 = 1), ma che si installano o vengono eseguiti.
- Segnalare campi Extra di grandi dimensioni o sconosciuti nelle entry principali (cercare indicatori come `JADXBLOCK`).
- Segnalare collisioni di percorso (`X` e `X/`) specificamente per `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Altri trucchi ZIP malevoli (2024–2026)

### Directory centrali concatenate (elusione tramite più EOCD)

In una campagna di phishing del 2024, gli attaccanti hanno distribuito un singolo blob che in realtà era composto da **due file ZIP concatenati**. Ognuno aveva il proprio record End of Central Directory (EOCD) e la propria directory centrale. Estrattori diversi analizzavano directory diverse (7-Zip leggeva la prima, mentre WinRAR leggeva l’ultima), consentendo agli attaccanti di nascondere payload visibili solo con alcuni strumenti; gli scanner che controllano una sola directory possono non rilevare l’altro archivio.<sup>[[5]](#references)[[6]](#references)</sup>

**Comandi di triage**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Se compare più di un EOCD o sono presenti avvisi "data after payload", suddividi il blob e ispeziona ogni parte:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Bombe quoted-overlap / con voci sovrapposte (non ricorsive)

Le ZIP bomb quoted-overlap creano un piccolo **kernel** (un blocco DEFLATE altamente compresso) e lo riutilizzano in voci sovrapposte. Le varianti full-overlap puntano più voci della directory centrale a un’unica intestazione locale, mentre le varianti quoted-overlap includono intestazioni locali all’interno dei flussi DEFLATE; la costruzione pubblicata raggiunge un rapporto superiore a 28M:1 senza archivi annidati.<sup>[[7]](#references)</sup>

**Rilevamento rapido (offset LFH duplicati)**

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
- Esegui un'analisi a secco: `zipdetails -v file.zip | grep -n "Local Header Offset"` e confronta gli offset dei local header e gli intervalli dei dati compressi; gli offset duplicati indicano varianti con sovrapposizione completa.<sup>[[7]](#references)[[8]](#references)</sup>
- Prima dell'estrazione, limita con un parser la dimensione totale non compressa e il numero di voci accettati; `zipinfo -t file.zip` riporta i totali, ma non applica un limite di sicurezza.<sup>[[8]](#references)</sup>
- Se devi estrarre, fallo all'interno di un cgroup/VM con limiti di CPU e disco (evita crash dovuti a decompressione senza limiti).<sup>[[8]](#references)</sup>

---

### Confusione tra parser di local header e central directory

Recenti ricerche sui parser differenziali hanno dimostrato che le ambiguità ZIP sono ancora sfruttabili nelle toolchain moderne. L'idea di base è semplice: alcuni software si fidano del **Local File Header (LFH)**, mentre altri si fidano della **Central Directory (CD)**; quindi, uno stesso archivio può presentare nomi file, percorsi, commenti, offset o insiemi di voci diversi a seconda dello strumento.<sup>[[9]](#references)</sup>

Usi offensivi pratici:
- Fai in modo che un filtro di upload, una scansione AV preliminare o un validatore di pacchetti veda un file innocuo nel CD, mentre l'estrattore rispetta un nome/percorso LFH diverso.
- Sfrutta nomi duplicati, voci presenti solo in una struttura o metadati ambigui del percorso Unicode (per esempio, il campo extra Unicode Path di Info-ZIP `0x7075`) affinché parser diversi ricostruiscano alberi differenti.
- Combina questa tecnica con il path traversal per trasformare la visualizzazione di un archivio "innocuo" in una primitiva di scrittura durante l'estrazione. Per il lato dell'estrazione, vedi [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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

Integralo con:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Euristiche:
- Per l'acquisizione di dati sensibili alla sicurezza, rifiuta o isola gli archivi con nomi LFH/CD non corrispondenti, nomi di file duplicati, più record EOCD o byte aggiuntivi dopo l'ultimo EOCD.<sup>[[9]](#references)[[10]](#references)</sup>
- Considera sospetti gli ZIP che usano campi extra insoliti per i percorsi Unicode o commenti incoerenti, se strumenti diversi restituiscono alberi di file estratti discordanti.<sup>[[4]](#references)[[9]](#references)</sup>
- Se l'analisi è più importante della conservazione dei byte originali, riconfeziona l'archivio con un parser rigoroso dopo averlo estratto in una sandbox e confronta l'elenco dei file risultante con i metadati originali.

Questo aspetto è rilevante anche al di fuori degli ecosistemi di pacchetti: la stessa classe di ambiguità può nascondere payload ai gateway di posta, agli scanner statici e alle pipeline di acquisizione personalizzate che «sbirciano» nei contenuti ZIP prima che un estrattore diverso elabori l'archivio.<sup>[[9]](#references)</sup>

---





## References

- [1] [Guida pratica all'analisi forense CTF (blog di Mike, categoria CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Parte 1 – Un dropper multistadio (tecnica anti-reversing per ZIP APK)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Specifiche del formato di file ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [La struttura flessibile degli archivi ZIP viene sfruttata per nascondere malware senza essere rilevati (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Gli hacker nascondono malware in un nuovo attacco con file ZIP: directory centrali ZIP concatenate](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Una zip bomb migliore (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Capire le zip bomb: costruzione del kernel con sovrapposizione/sovrapposizione quotata](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Il mio ZIP non è il tuo ZIP: identificare e sfruttare le lacune semantiche tra parser ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Prevenire gli attacchi di confusione dei parser ZIP agli installer di pacchetti Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Attacchi ZIP con plaintext noto ridotto (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: missione web realistica, livello 15 (attacco ZIP con plaintext noto)](https://www.hackthissite.org/articles/read/793)
- [13] [Utilizzo di bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [Tutorial bkcrack sul plaintext noto](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [Repository di fcrackzip](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}
