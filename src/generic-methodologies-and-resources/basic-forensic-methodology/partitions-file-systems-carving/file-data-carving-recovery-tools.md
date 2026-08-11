# Strumenti di Carving e Recupero di File/Dati

{{#include ../../../banners/hacktricks-training.md}}

## Strumenti di Carving e Recupero

Altri strumenti su [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Lo strumento più comune utilizzato in ambito forense per estrarre file dalle immagini è [**Autopsy**](https://www.autopsy.com/download/). Scaricalo, installalo e fagli analizzare il file per trovare file "nascosti". Nota che Autopsy è progettato per supportare immagini disco e altri tipi di immagini, ma non file semplici.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** è uno strumento per analizzare file binari e individuare contenuti incorporati. È installabile tramite `apt` e il suo codice sorgente si trova su [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandi utili**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Nota di sicurezza** – Le versioni dalla **2.1.2b** alla **2.3.3** sono interessate da una vulnerabilità di **Path Traversal** (CVE-2022-4510); l'avviso non indica alcuna versione pip corretta. Evita di estrarre campioni non attendibili con le release interessate oppure isola lo strumento con un container/UID non privilegiato.<sup>[[4]](#references)</sup>

### Foremost

Un altro strumento comune per trovare file nascosti è **foremost**. Puoi trovare il file di configurazione di foremost in `/etc/foremost.conf`. Se vuoi cercare solo file specifici, decommentali. Se non decommenti nulla, foremost cercherà i tipi di file configurati per impostazione predefinita.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** è un altro tool che può essere utilizzato per trovare ed estrarre **file incorporati in un file**. In questo caso, sarà necessario decommentare dal file di configurazione (_/etc/scalpel/scalpel.conf_) i tipi di file che si desidera estrarre.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Questo strumento è incluso in kali, ma puoi trovarlo qui: <https://github.com/simsong/bulk_extractor>

Bulk Extractor può analizzare un'immagine di prova e recuperare **frammenti pcap**, **artefatti di rete (URL, domini, IP, MAC, e-mail)** e molti altri oggetti **in parallelo utilizzando più scanner**.

La release v2.1.1 documenta una build Autotools e l'impostazione `-S jpeg_carve_mode=2` per il carving di tutti i file JPEG contigui.<sup>[[2]](#references)</sup>
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
Il file `bulk_diff.py` incluso confronta due esecuzioni di bulk_extractor, mentre `bulk_extractor_reader.py` legge il report e i file delle feature.<sup>[[3]](#references)</sup>

### PhotoRec

Puoi trovarlo su <https://www.cgsecurity.org/wiki/TestDisk_Download>

Include versioni GUI e CLI. Puoi selezionare i **tipi di file** che vuoi che PhotoRec cerchi.

![Esegui ogni scanner, esegui il carving aggressivo dei JPEG e genera un bodyfile - PhotoRec: include versioni GUI e CLI. Puoi selezionare i tipi di file che vuoi che PhotoRec cerchi](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imaging di unità in errore)

Quando un'unità fisica è instabile, è buona pratica **crearne prima un'immagine** ed eseguire gli strumenti di carving solo sull'immagine. `ddrescue` (progetto GNU) è incentrato sulla copia affidabile dei dischi danneggiati, mantenendo un log dei settori illeggibili.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
L’opzione **`--cluster-size`** controlla quanti settori vengono copiati alla volta; valori più piccoli possono essere utili con unità lente.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (undelete EXT 3/4)

Se il file system di origine è basato su Linux EXT, potresti riuscire a recuperare i file eliminati di recente **senza eseguire un full carving**; questi strumenti basati sul journal funzionano su un filesystem non montato o su un’immagine in sola lettura.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Nota sulla compatibilità** – ext4magic è abbandonato; la pagina del progetto avverte che i filesystem attuali non sono più compatibili con esso.<sup>[[10]](#references)</sup>

> 🛈 Se il file system è stato montato dopo l'eliminazione, i blocchi di dati potrebbero essere già stati riutilizzati; in tal caso è comunque necessario un corretto carving (Foremost/Scalpel).

### binvis

Controlla il [codice](https://code.google.com/archive/p/binvis/) e lo [strumento della pagina web](https://binvis.io/#/).

#### Funzionalità di BinVis

- **Visualizzatore della struttura** visivo e attivo
- Più grafici per diversi punti di interesse
- Focus su porzioni di un campione
- **Visualizzazione di stringhe e risorse**, ad esempio negli eseguibili PE o ELF
- Ottenimento di **pattern** per la crittoanalisi dei file
- **Individuazione** di algoritmi di packer o encoder
- **Identificazione** della Steganography tramite pattern
- **Confronto visivo** di file binari

BinVis è un ottimo **punto di partenza per acquisire familiarità con un target sconosciuto** in uno scenario di black-boxing.

## Strumenti specifici per il Data Carving

### FindAES

Cerca chiavi AES ricercando i relativi key schedule. È in grado di trovare chiavi da 128, 192 e 256 bit, come quelle utilizzate da TrueCrypt e BitLocker.

Scaricalo [qui](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging degli artefatti sottoposti a carving)

[YARA-X](https://github.com/VirusTotal/yara-x) è una riscrittura di YARA in Rust introdotta nel 2024; VirusTotal riferisce che alcune regole con espressioni regolari e loop complessi possono essere eseguite significativamente più velocemente.<sup>[[5]](#references)</sup> La sua CLI si chiama `yr` e il comando `scan` supporta scansioni ricorsive, il numero di thread e l'output dei metadati.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Strumenti complementari

Puoi usare [**viu** ](https://github.com/atanunq/viu) per visualizzare immagini dal terminale.  \
Puoi usare lo strumento da riga di comando Linux **pdftotext** per trasformare un pdf in testo e leggerlo.



## References

- [1] [Note sulla release di Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README di bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README degli strumenti Python di bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal in binwalk (CVE-2022-4510) - Database degli avvisi di GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA è morto, lunga vita a YARA-X - Blog di VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Comandi CLI di YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Manuale di GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Manuale di ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Stato del progetto ext4magic](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
