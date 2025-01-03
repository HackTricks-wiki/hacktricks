# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Strumenti di Carving & Recupero

Altri strumenti in [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Lo strumento più comune utilizzato in forense per estrarre file da immagini è [**Autopsy**](https://www.autopsy.com/download/). Scaricalo, installalo e fallo elaborare il file per trovare file "nascosti". Nota che Autopsy è progettato per supportare immagini di disco e altri tipi di immagini, ma non file semplici.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** è uno strumento per analizzare file binari per trovare contenuti incorporati. È installabile tramite `apt` e il suo sorgente è su [GitHub](https://github.com/ReFirmLabs/binwalk).

**Comandi utili**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Un altro strumento comune per trovare file nascosti è **foremost**. Puoi trovare il file di configurazione di foremost in `/etc/foremost.conf`. Se vuoi solo cercare alcuni file specifici, decommentali. Se non decommenti nulla, foremost cercherà i suoi tipi di file configurati per impostazione predefinita.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** è un altro strumento che può essere utilizzato per trovare ed estrarre **file incorporati in un file**. In questo caso, dovrai decommentare dal file di configurazione (_/etc/scalpel/scalpel.conf_) i tipi di file che desideri estrarre.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

Questo strumento è incluso in kali ma puoi trovarlo qui: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

Questo strumento può scansionare un'immagine e **estrarre pcaps** al suo interno, **informazioni di rete (URL, domini, IP, MAC, email)** e altri **file**. Devi solo fare:
```
bulk_extractor memory.img -o out_folder
```
Naviga attraverso **tutte le informazioni** che lo strumento ha raccolto (password?), **analizza** i **pacchetti** (leggi [**analisi Pcaps**](../pcap-inspection/)), cerca **domini strani** (domini relativi a **malware** o **inesistenti**).

### PhotoRec

Puoi trovarlo in [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

È disponibile in versioni GUI e CLI. Puoi selezionare i **tipi di file** che vuoi che PhotoRec cerchi.

![](<../../../images/image (242).png>)

### binvis

Controlla il [codice](https://code.google.com/archive/p/binvis/) e la [pagina web dello strumento](https://binvis.io/#/).

#### Caratteristiche di BinVis

- Visualizzatore di **struttura** visivo e attivo
- Plots multipli per diversi punti di interesse
- Focalizzazione su porzioni di un campione
- **Visualizzazione di stringhe e risorse**, in eseguibili PE o ELF, ad esempio
- Ottenere **pattern** per crittanalisi su file
- **Identificare** algoritmi di packer o encoder
- **Identificare** la steganografia tramite pattern
- **Differenziazione** binaria visiva

BinVis è un ottimo **punto di partenza per familiarizzare con un obiettivo sconosciuto** in uno scenario di black-boxing.

## Strumenti specifici per il Data Carving

### FindAES

Cerca chiavi AES cercando i loro programmi di chiave. In grado di trovare chiavi da 128, 192 e 256 bit, come quelle utilizzate da TrueCrypt e BitLocker.

Scarica [qui](https://sourceforge.net/projects/findaes/).

## Strumenti complementari

Puoi usare [**viu**](https://github.com/atanunq/viu) per vedere immagini dal terminale.\
Puoi usare lo strumento da riga di comando linux **pdftotext** per trasformare un pdf in testo e leggerlo.

{{#include ../../../banners/hacktricks-training.md}}
