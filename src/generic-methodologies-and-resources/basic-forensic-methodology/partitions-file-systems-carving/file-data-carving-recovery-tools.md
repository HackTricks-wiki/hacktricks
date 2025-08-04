# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

More tools in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Lo strumento più comune utilizzato in forense per estrarre file da immagini è [**Autopsy**](https://www.autopsy.com/download/). Scaricalo, installalo e fallo elaborare il file per trovare file "nascosti". Nota che Autopsy è progettato per supportare immagini disco e altri tipi di immagini, ma non file semplici.

> **Aggiornamento 2024-2025** – La versione **4.21** (rilasciata a febbraio 2025) ha aggiunto un **modulo di carving ricostruito basato su SleuthKit v4.13** che è notevolmente più veloce nella gestione di immagini multi-terabyte e supporta l'estrazione parallela su sistemi multi-core.¹ È stato anche introdotto un piccolo wrapper CLI (`autopsycli ingest <case> <image>`), rendendo possibile scriptare il carving all'interno di ambienti CI/CD o laboratori su larga scala.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** è uno strumento per analizzare file binari per trovare contenuti incorporati. È installabile tramite `apt` e il suo sorgente è su [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandi utili**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Nota di sicurezza** – Le versioni **≤2.3.3** sono affette da una vulnerabilità di **Path Traversal** (CVE-2022-4510). Aggiorna (o isola con un container/UID non privilegiato) prima di eseguire il carving di campioni non fidati.

### Foremost

Un altro strumento comune per trovare file nascosti è **foremost**. Puoi trovare il file di configurazione di foremost in `/etc/foremost.conf`. Se vuoi cercare solo alcuni file specifici, decommentali. Se non decommenti nulla, foremost cercherà i suoi tipi di file configurati di default.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** è un altro strumento che può essere utilizzato per trovare ed estrarre **file incorporati in un file**. In questo caso, dovrai decommentare dal file di configurazione (_/etc/scalpel/scalpel.conf_) i tipi di file che desideri estrarre.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

Questo strumento è incluso in kali ma puoi trovarlo qui: <https://github.com/simsong/bulk_extractor>

Bulk Extractor può scansionare un'immagine di prova e estrarre **frammenti pcap**, **artefatti di rete (URL, domini, IP, MAC, e-mail)** e molti altri oggetti **in parallelo utilizzando più scanner**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Utili script di post-elaborazione (`bulk_diff`, `bulk_extractor_reader.py`) possono de-duplicare artefatti tra due immagini o convertire i risultati in JSON per l'ingestione SIEM.

### PhotoRec

Puoi trovarlo in <https://www.cgsecurity.org/wiki/TestDisk_Download>

Viene fornito con versioni GUI e CLI. Puoi selezionare i **tipi di file** che desideri che PhotoRec cerchi.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (imaging di dischi in fase di guasto)

Quando un'unità fisica è instabile, è buona pratica **creare prima un'immagine** e utilizzare gli strumenti di carving solo sull'immagine. `ddrescue` (progetto GNU) si concentra sulla copia affidabile di dischi danneggiati mantenendo un registro dei settori illeggibili.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Versione **1.28** (dicembre 2024) ha introdotto **`--cluster-size`** che può accelerare l'imaging di SSD ad alta capacità dove le dimensioni dei settori tradizionali non si allineano più con i blocchi flash.

### Extundelete / Ext4magic (recupero EXT 3/4)

Se il file system sorgente è basato su Linux EXT, potresti essere in grado di recuperare file recentemente eliminati **senza carving completo**. Entrambi gli strumenti funzionano direttamente su un'immagine di sola lettura:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Se il file system è stato montato dopo la cancellazione, i blocchi di dati potrebbero essere già stati riutilizzati – in tal caso è ancora necessaria una corretta carving (Foremost/Scalpel).

### binvis

Controlla il [codice](https://code.google.com/archive/p/binvis/) e la [pagina web dello strumento](https://binvis.io/#/).

#### Caratteristiche di BinVis

- Visuale e attivo **visualizzatore di strutture**
- Plots multipli per diversi punti di interesse
- Focalizzazione su porzioni di un campione
- **Visualizzazione di stringhe e risorse**, in eseguibili PE o ELF, ad esempio
- Ottenere **pattern** per la crittoanalisi su file
- **Identificazione** di algoritmi di packer o encoder
- **Identificare** la steganografia tramite pattern
- **Visuale** binary-diffing

BinVis è un ottimo **punto di partenza per familiarizzare con un obiettivo sconosciuto** in uno scenario di black-boxing.

## Strumenti Specifici per la Carving dei Dati

### FindAES

Cerca chiavi AES esaminando i loro piani chiave. In grado di trovare chiavi a 128, 192 e 256 bit, come quelle utilizzate da TrueCrypt e BitLocker.

Scarica [qui](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging artefatti carvati)

[YARA-X](https://github.com/VirusTotal/yara-x) è una riscrittura in Rust di YARA rilasciata nel 2024. È **10-30× più veloce** della classica YARA e può essere utilizzata per classificare migliaia di oggetti carvati molto rapidamente:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
L'accelerazione rende realistico **auto-tag** tutti i file estratti in indagini su larga scala.

## Strumenti complementari

Puoi usare [**viu** ](https://github.com/atanunq/viu) per vedere immagini dal terminale.  \
Puoi usare lo strumento da riga di comando linux **pdftotext** per trasformare un pdf in testo e leggerlo.

## Riferimenti

1. Note di rilascio di Autopsy 4.21 – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
