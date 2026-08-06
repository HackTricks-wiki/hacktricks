# Strumenti di carving e recupero di file/dati

{{#include ../../../banners/hacktricks-training.md}}

## Strumenti di carving e recupero

Altri strumenti sono disponibili su [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Lo strumento più comune utilizzato in ambito forense per estrarre file dalle immagini è [**Autopsy**](https://www.autopsy.com/download/). Scaricalo, installalo e fagli analizzare il file per trovare i file "nascosti". Nota che Autopsy è progettato per supportare le immagini disco e altri tipi di immagini, ma non i file semplici.

> **Aggiornamento 2024-2025** – La versione **4.21** (rilasciata a febbraio 2025) ha aggiunto un **modulo di carving basato su SleuthKit v4.13** completamente ricostruito, che è sensibilmente più veloce nella gestione di immagini di diversi terabyte e supporta l'estrazione parallela sui sistemi multi-core. È stato inoltre introdotto un piccolo wrapper CLI (`autopsycli ingest <case> <image>`), che consente di creare script per il carving all'interno di ambienti CI/CD o di laboratori su larga scala.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** è uno strumento per analizzare file binari e individuare contenuti incorporati. È installabile tramite `apt` e il suo codice sorgente è disponibile su [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandi utili**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Nota di sicurezza** – Le versioni **≤2.3.3** sono affette da una vulnerabilità di **Path Traversal** (CVE-2022-4510). Esegui l'upgrade (oppure isola con un container/UID non privilegiato) prima di eseguire il carving su sample non attendibili.<sup>[[2]](#references)</sup>

### Foremost

Un altro strumento comune per trovare file nascosti è **foremost**. Puoi trovare il file di configurazione di foremost in `/etc/foremost.conf`. Se vuoi cercare solo alcuni file specifici, decommentali. Se non decommenti nulla, foremost cercherà i tipi di file configurati per impostazione predefinita.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** è un altro strumento che può essere utilizzato per trovare ed estrarre **file incorporati in un file**. In questo caso, dovrai decommentare nel file di configurazione (_/etc/scalpel/scalpel.conf_) i tipi di file che vuoi estrarre.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Questo tool è incluso in kali, ma puoi trovarlo qui: <https://github.com/simsong/bulk_extractor>

Bulk Extractor può analizzare un evidence image ed eseguire il carving di **frammenti pcap**, **artefatti di rete (URL, domini, IP, MAC, e-mail)** e molti altri oggetti **in parallelo usando più scanner**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Gli utili script di post-processing (`bulk_diff`, `bulk_extractor_reader.py`) possono rimuovere i duplicati dagli artefatti tra due immagini o convertire i risultati in JSON per l'importazione in un SIEM.

### PhotoRec

Puoi trovarlo su <https://www.cgsecurity.org/wiki/TestDisk_Download>

È disponibile nelle versioni GUI e CLI. Puoi selezionare i **tipi di file** che vuoi che PhotoRec cerchi.

![Esegui ogni scanner, estrai aggressivamente i file JPEG e genera un bodyfile - PhotoRec: è disponibile nelle versioni GUI e CLI. Puoi selezionare i tipi di file che vuoi che PhotoRec cerchi](<../../../images/image (242).png>)

### ddrescue + ddrescueview (acquisizione di unità difettose)

Quando un'unità fisica è instabile, è buona pratica **crearne prima un'immagine** ed eseguire gli strumenti di carving solo sull'immagine. `ddrescue` (progetto GNU) si concentra sulla copia affidabile dei dischi danneggiati, mantenendo un log dei settori illeggibili.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
La versione **1.28** (dicembre 2024) ha introdotto **`--cluster-size`**, che può velocizzare l’imaging degli SSD ad alta capacità, dove le dimensioni dei settori tradizionali non sono più allineate ai blocchi flash.

### Extundelete / Ext4magic (undelete EXT 3/4)

Se il file system sorgente è basato su Linux EXT, potresti riuscire a recuperare i file eliminati di recente **senza eseguire un carving completo**. Entrambi gli strumenti funzionano direttamente su un’immagine in sola lettura:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Se il file system è stato montato dopo l'eliminazione, i blocchi di dati potrebbero essere già stati riutilizzati: in tal caso è comunque necessario eseguire un carving corretto (Foremost/Scalpel).

### binvis

Controlla il [codice](https://code.google.com/archive/p/binvis/) e lo [strumento della pagina web](https://binvis.io/#/).

#### Funzionalità di BinVis

- **Visualizzatore della struttura** visivo e interattivo
- Molteplici grafici per diversi punti di interesse
- Possibilità di concentrarsi su porzioni di un campione
- **Visualizzazione di stringhe e risorse**, ad esempio negli eseguibili PE o ELF
- Ottenimento di **pattern** per la crittoanalisi dei file
- **Individuazione** di algoritmi di packing o encoding
- **Identificazione** della Steganography tramite pattern
- **Diffing** binario **visuale**

BinVis è un ottimo **punto di partenza per acquisire familiarità con un target sconosciuto** in uno scenario di black-boxing.

## Specific Data Carving Tools

### FindAES

Cerca chiavi AES individuando i relativi key schedule. È in grado di trovare chiavi da 128, 192 e 256 bit, come quelle utilizzate da TrueCrypt e BitLocker.

Scaricalo [qui](https://sourceforge.net/projects/findaes/).

### YARA-X (triage degli artefatti recuperati)

[YARA-X](https://github.com/VirusTotal/yara-x) è una riscrittura di YARA in Rust, pubblicata nel 2024. È **10-30× più veloce** della YARA classica e può essere utilizzata per classificare molto rapidamente migliaia di oggetti recuperati:<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
La velocizzazione rende realistico **auto-taggare** tutti i file recuperati tramite carving nelle indagini su larga scala.

## Strumenti complementari

Puoi usare [**viu** ](https://github.com/atanunq/viu)per visualizzare immagini dal terminale.  \
Puoi usare lo strumento da riga di comando Linux **pdftotext** per trasformare un PDF in testo e leggerlo.



## Riferimenti

- [1] [Note di rilascio di Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal in binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA è morto, lunga vita a YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
