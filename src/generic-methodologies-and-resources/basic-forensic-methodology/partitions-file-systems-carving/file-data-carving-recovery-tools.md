# Strumenti di carving e recupero di file/dati

{{#include ../../../banners/hacktricks-training.md}}

## Strumenti di carving e recupero

Esegui sempre il carving su una **copia verificata**, mai sul dispositivo originale. Consulta [Image Acquisition & Mount](../image-acquisition-and-mount.md) per le procedure di acquisizione in sola lettura e hashing.

Altri strumenti su [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Lo strumento più comune usato in forensics per estrarre file dalle immagini è [**Autopsy**](https://www.autopsy.com/download/). Scaricalo, installalo e fagli analizzare il file per trovare file "nascosti". Tieni presente che Autopsy è progettato per supportare immagini disco e altri tipi di immagini, ma non file semplici.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** è uno strumento per analizzare file binari e trovare contenuti incorporati. **Binwalk v3** è una riscrittura in Rust che offre estrazione automatica (`-e`), carving raw di oggetti noti e sconosciuti (`-c`), scansione ricorsiva/Matrioska (`-M`) e thread worker configurabili. Il progetto consiglia la versione Docker quando servono tutti gli estrattori esterni; `cargo install binwalk` installa la CLI Rust, ma non quelle dipendenze esterne.<sup>[[11]](#references)</sup>

**Comandi utili della v3**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

La ricetta legacy v2 `--dd='.*'` non è l'equivalente v3 di `-c`; quando segui i vecchi comandi di CTF/write-up, controlla prima `binwalk --version`.<sup>[[11]](#references)</sup>

⚠️  **Nota sulla sicurezza** – Le versioni dalla **2.1.2b** alla **2.3.3** sono affette da una vulnerabilità di **Path Traversal** (CVE-2022-4510); l'advisory non indica alcuna versione di pip corretta. Evita di estrarre campioni non attendibili con le versioni affette oppure isola lo strumento usando un container/UID non privilegiato.<sup>[[4]](#references)</sup>

### Foremost

Un altro strumento comune per trovare file nascosti è **foremost**. Puoi trovare il file di configurazione di foremost in `/etc/foremost.conf`. Se vuoi cercare solo alcuni file specifici, rimuovi il commento dalle relative righe. Se non rimuovi alcun commento, foremost cercherà i tipi di file configurati per impostazione predefinita.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** è un altro strumento che può essere usato per trovare ed estrarre **file incorporati in un file**. In questo caso, dovrai rimuovere il commento dalle righe del file di configurazione (_/etc/scalpel/scalpel.conf_) relative ai tipi di file che vuoi estrarre.

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Ricostruzione di file frammentati con Scalpel3

Quando il recupero basato prima sui metadati e i carver per file contigui non riescono a recuperare file suddivisi, **Scalpel3** può riassemblare i formati supportati usando validator per file/blocchi. È una codebase diversa dal comando legacy `scalpel` menzionato sopra. Per prima cosa, crea il blockmap richiesto usando la **stessa dimensione dei blocchi** impiegata per il carving; se nota, usa la dimensione dei cluster del filesystem indicata da `fsstat`, oppure stabilisci un valore giustificabile prima di analizzare un’immagine di partizione. Esegui l’operazione solo su una copia verificata e salva l’output su un volume separato.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Sostituisci `4096` con la dimensione del blocco selezionata. `-w` conserva i candidati **PROMISING** oltre a quelli convalidati, mentre `-b` scrive i blockvectors per facilitare la verifica dei layout ricostruiti. Un file in stato PROMISING, o con un'estensione familiare, non dimostra che il recupero sia completo; convalida il contenuto prima di usarlo.<sup>[[13]](#references)[[14]](#references)</sup> Per individuare partizioni eliminate o spazi vuoti prima del carving, vedi [Finding data outside listed partitions](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

Questo tool è incluso in kali, ma puoi trovarlo qui: <https://github.com/simsong/bulk_extractor>

Bulk Extractor può analizzare un'immagine forense ed eseguire il carving di **frammenti pcap**, **artefatti di rete (URL, domini, IP, MAC, e-mail)** e molti altri oggetti **in parallelo usando più scanner**.

La release v2.1.1 documenta una build Autotools e l'impostazione `-S jpeg_carve_mode=2` per eseguire il carving di tutti i JPEG contigui.<sup>[[2]](#references)</sup>

```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```

Il `bulk_diff.py` incluso confronta due esecuzioni di bulk_extractor, mentre `bulk_extractor_reader.py` legge i file di report e delle feature.<sup>[[3]](#references)</sup>

### PhotoRec

Puoi trovarlo su <https://www.cgsecurity.org/wiki/TestDisk_Download>

È disponibile in versione GUI e CLI. Puoi selezionare i **tipi di file** che vuoi far cercare a PhotoRec.

![Esegui tutti gli scanner, esegui carving aggressivo dei JPEG e genera un bodyfile - PhotoRec: è disponibile in versione GUI e CLI. Puoi selezionare i tipi di file che vuoi far cercare a PhotoRec](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (prima i metadati)

Prima di eseguire il carving delle firme raw, prova il recupero basato sul filesystem quando i metadati del volume sono ancora analizzabili. Per impostazione predefinita, `tsk_recover` esporta solo i file non allocati; `-a` seleziona i file allocati e `-e` esporta entrambi. Per un'immagine dell'intero disco, passa a `-o` il **settore iniziale** della partizione indicato da `mmls` (non convertirlo in byte). Se l'input è già un'immagine della partizione, ometti `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Questo passaggio può preservare nomi e percorsi derivati dal filesystem, cosa che il carving di header/footer non può fare; esegui Foremost, Scalpel o PhotoRec in seguito per le voci con metadati mancanti o inutilizzabili.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (creazione di immagini di unità danneggiate)

Quando un'unità fisica è instabile, è buona norma **crearne prima un'immagine** ed eseguire gli strumenti di carving solo sull'immagine. `ddrescue` (progetto GNU) è progettato per copiare in modo affidabile dischi danneggiati mantenendo un log dei settori illeggibili.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

L'opzione **`--cluster-size`** controlla quanti settori vengono copiati alla volta; valori più piccoli possono essere utili con unità lente.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (recupero di file eliminati da EXT 3/4)

Se il file system di origine è basato su Linux EXT, potresti riuscire a recuperare i file eliminati di recente **senza eseguire un carving completo**; questi strumenti basati sul journal funzionano su un file system non montato o su un'immagine in sola lettura.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Nota sulla compatibilità** – ext4magic è abbandonato; la pagina del progetto avverte che i file system attuali non sono più compatibili con esso.<sup>[[10]](#references)</sup>

> 🛈 Se il file system è stato montato dopo l’eliminazione, i blocchi di dati potrebbero essere già stati riutilizzati: in tal caso è comunque necessario eseguire un carving appropriato (Foremost/Scalpel).

### binvis

Controlla il [codice](https://code.google.com/archive/p/binvis/) e lo [strumento web](https://binvis.io/#/).

#### Funzionalità di BinVis

- **Visualizzatore di strutture** visivo e interattivo
- Diversi grafici per punti di interesse differenti
- Analisi di porzioni di un campione
- **Visualizzazione di stringhe e risorse**, ad esempio negli eseguibili PE o ELF
- Individuazione di **pattern** utili per la crittoanalisi dei file
- **Rilevamento** di algoritmi di packing o codifica
- **Identificazione** della steganografia tramite pattern
- **Diffing** binario visivo

BinVis è un ottimo **punto di partenza per familiarizzare con un target sconosciuto** in uno scenario black-box.

## Strumenti specifici per il carving dei dati

### FindAES

Cerca chiavi AES individuandone gli schedule. È in grado di trovare chiavi a 128, 192 e 256 bit, come quelle usate da TrueCrypt e BitLocker.

Scaricalo [qui](https://sourceforge.net/projects/findaes/).

### YARA-X (triage degli artefatti estratti)

[YARA-X](https://github.com/VirusTotal/yara-x) è una riscrittura di YARA in Rust, introdotta nel 2024; VirusTotal riferisce che alcune regole con espressioni regolari e cicli complessi possono essere eseguite molto più velocemente.<sup>[[5]](#references)</sup> La sua CLI si chiama `yr` e il comando `scan` supporta scansioni ricorsive, l’impostazione del numero di thread e l’output dei metadati.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Strumenti complementari

Puoi usare [**viu** ](https://github.com/atanunq/viu)per visualizzare immagini dal terminale.  \
Puoi usare lo strumento da riga di comando di Linux **pdftotext** per convertire un PDF in testo e leggerlo.







## References

- [1] [Note di rilascio di Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README di bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README degli strumenti Python di bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal in binwalk (CVE-2022-4510) - Database degli avvisi di GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA è morto, lunga vita a YARA-X - Blog di VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Comandi CLI di YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Manuale di GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Manuale di ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Stato del progetto ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [README di Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: manuale di tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [README di Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Manuale di Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Workflow di test di Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
