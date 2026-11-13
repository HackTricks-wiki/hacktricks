# Partizioni/File system/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partizioni

Un disco può contenere più **partizioni**: intervalli logici di blocchi, non unità di archiviazione fisicamente separate. L'inizio e la lunghezza delle partizioni sono misurati in **settori logici**; non presumere che ogni immagine usi settori da 512 byte, perché esistono anche settori logici da 4096 byte.<sup>[[4]](#references)</sup>

### MBR (Master Boot Record)

L'MBR occupa il primo settore logico (LBA 0); le sue quattro voci di partizione da 16 byte iniziano al byte 446. L'area precedente include il codice di avvio e può contenere una firma del disco.<sup>[[4]](#references)</sup>\
Consente fino a **4 partizioni** (al massimo **solo 1** può essere attiva/**avviabile**). Tuttavia, se servono più partizioni, è possibile usare **partizioni estese**. Gli ultimi **due byte** dell'MBR da 512 byte contengono la firma di avvio **0x55 0xAA**. Solo una partizione può essere contrassegnata come attiva.\
Con settori logici da 512 byte, i campi a 32 bit dell'MBR limitano l'indirizzamento a circa **2 TiB** (2,2 TB).<sup>[[4]](#references)</sup>

![Partizioni - MBR (Master Boot Record): l'MBR consente al massimo 2,2 TB](<../../../images/image (350).png>)

![Partizioni - MBR (Master Boot Record): l'MBR consente al massimo 2,2 TB](<../../../images/image (304).png>)

Nei **byte da 440 a 443** dell'MBR è possibile trovare la **firma del disco di Windows** (se viene usato Windows). La lettera dell'unità logica del disco rigido dipende dalla firma del disco di Windows. Modificare questa firma potrebbe impedire l'avvio di Windows (strumento: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partizioni - MBR (Master Boot Record): nei byte da 440 a 443 dell'MBR è possibile trovare la firma del disco di Windows (se viene usato Windows). La lettera dell'unità logica del disco rigido...](<../../../images/image (310).png>)

**Formato**

| Offset      | Lunghezza  | Elemento                    |
| ----------- | ---------- | --------------------------- |
| 0 (0x00)    | 446(0x1BE) | Codice di avvio             |
| 446 (0x1BE) | 16 (0x10)  | Prima partizione            |
| 462 (0x1CE) | 16 (0x10)  | Seconda partizione          |
| 478 (0x1DE) | 16 (0x10)  | Terza partizione            |
| 494 (0x1EE) | 16 (0x10)  | Quarta partizione           |
| 510 (0x1FE) | 2 (0x2)    | Firma 0x55 0xAA              |

**Formato del record di partizione**

| Offset    | Lunghezza | Elemento                                                       |
| --------- | --------- | -------------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01)  | Flag attivo (0x80 = avviabile)                                 |
| 1 (0x01)  | 1 (0x01)  | Testina iniziale                                               |
| 2 (0x02)  | 1 (0x01)  | Settore iniziale (bit 0-5); bit superiori del cilindro (6- 7) |
| 3 (0x03)  | 1 (0x01)  | 8 bit meno significativi del cilindro iniziale                 |
| 4 (0x04)  | 1 (0x01)  | Codice del tipo di partizione (0x83 = Linux)                   |
| 5 (0x05)  | 1 (0x01)  | Testina finale                                                 |
| 6 (0x06)  | 1 (0x01)  | Settore finale (bit 0-5); bit superiori del cilindro (6- 7)   |
| 7 (0x07)  | 1 (0x01)  | 8 bit meno significativi del cilindro finale                   |
| 8 (0x08)  | 4 (0x04)  | Settori precedenti alla partizione (little endian)              |
| 12 (0x0C) | 4 (0x04)  | Settori nella partizione                                       |

Per esaminare una partizione in un'immagine MBR dell'intero disco, ricava prima il suo LBA iniziale e la dimensione del settore logico. `mount` richiede un **offset in byte**, non un LBA; l'esempio seguente è valido solo per un'immagine con settori da 512 byte e una partizione che inizia all'LBA 63. Per immagini non attendibili o file system con journaling, usa invece la procedura isolata e in sola lettura descritta in [Acquisizione e montaggio di immagini](../image-acquisition-and-mount.md).<sup>[[5]](#references)[[11]](#references)</sup>

![Partizioni - MBR (Master Boot Record): per montare un MBR in Linux, devi prima ottenere l'offset iniziale (puoi usare fdisk e il comando p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) è uno schema comune usato per **specificare la posizione dei blocchi** di dati memorizzati sui dispositivi di archiviazione dei computer, generalmente sistemi di archiviazione secondaria come le unità disco rigido. LBA è uno schema di indirizzamento lineare particolarmente semplice: **i blocchi sono individuati tramite un indice intero**, dove il primo blocco è LBA 0, il secondo LBA 1 e così via.

### GPT (GUID Partition Table)

La GUID Partition Table (GPT) memorizza un GUID univoco per ogni partizione e usa metadati primari e di backup. Il suo layout differisce da quello di MBR come segue:<sup>[[4]](#references)</sup>

- **Posizione e dimensioni**: LBA 0 contiene un **MBR protettivo**. L'header GPT primario si trova in LBA 1; l'array delle voci di partizione è subito dopo, mentre un array e un header di backup si trovano alla fine del disco. GPT usa campi LBA a 64 bit, mentre le voci di partizione MBR usano campi LBA a 32 bit.
- **Limiti delle partizioni**: un array di voci comune da 16 KiB contiene **128 voci da 128 byte**, ma il numero di voci è registrato nell'header e non è fissato da GPT. Anche la dimensione indirizzabile dipende dalla dimensione del settore logico (circa **9,4 ZB** con settori da 512 byte).<sup>[[4]](#references)</sup>
- **Nomi delle partizioni**: permette di assegnare nomi alle partizioni, fino a 36 caratteri Unicode.

**Resilienza e recupero dei dati**:

- **Ridondanza**: a differenza di MBR, GPT non limita i dati delle partizioni e di avvio a un'unica posizione. Replica questi dati sul disco, migliorando l'integrità e la resilienza dei dati.
- **Controllo di ridondanza ciclica (CRC)**: l'header e l'array delle voci di partizione hanno ciascuno un CRC32. Un CRC rileva le incoerenze; non monitora continuamente il disco né lo ripara autonomamente. Se la copia primaria non è valida, convalidare il backup nell'ultimo LBA prima di eseguire qualsiasi recupero su una copia di lavoro.<sup>[[4]](#references)</sup>

**MBR protettivo (LBA0)**:

- GPT mantiene la compatibilità con le versioni precedenti tramite un MBR protettivo. Questa funzionalità risiede nello spazio MBR legacy, ma è progettata per impedire alle utility meno recenti basate su MBR di sovrascrivere per errore i dischi GPT, proteggendo così l'integrità dei dati sui dischi formattati con GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**MBR ibrido (LBA 0 + GPT)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Nei sistemi operativi che supportano **l'avvio basato su GPT tramite** i servizi **BIOS** anziché EFI, il primo settore può ancora essere usato per memorizzare il codice del primo stadio del **bootloader**, ma **modificato** per riconoscere le **partizioni** **GPT**. Il bootloader nell'MBR non deve presupporre una dimensione del settore di 512 byte.

**Header della tabella delle partizioni (LBA 1)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

L'header della tabella delle partizioni definisce i blocchi utilizzabili sul disco. Definisce inoltre il numero e la dimensione delle voci di partizione che compongono la tabella delle partizioni (offset 80 e 84 nella tabella).

| Offset    | Lunghezza   | Contenuto                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 byte  | Firma ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h o 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)su macchine little-endian) |
| 8 (0x08)  | 4 byte  | Revisione 1.0 (00h 00h 01h 00h) per UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 byte  | Dimensione dell'header in little-endian (in byte, solitamente 5Ch 00h 00h 00h o 92 byte)                                                                                                 |
| 16 (0x10) | 4 byte  | [CRC32](https://en.wikipedia.org/wiki/CRC32) dell'header (da offset +0 fino alla dimensione dell'header) in little-endian, con questo campo azzerato durante il calcolo                             |
| 20 (0x14) | 4 byte  | Riservato; deve essere zero                                                                                                                                                       |
| 24 (0x18) | 8 byte  | LBA corrente (posizione di questa copia dell'header)                                                                                                                                   |
| 32 (0x20) | 8 byte  | LBA di backup (posizione dell'altra copia dell'header)                                                                                                                               |
| 40 (0x28) | 8 byte  | Primo LBA utilizzabile per le partizioni (ultimo LBA della tabella delle partizioni primaria + 1)                                                                                                       |
| 48 (0x30) | 8 byte  | Ultimo LBA utilizzabile (primo LBA della tabella delle partizioni secondaria − 1)                                                                                                                    |
| 56 (0x38) | 16 byte | GUID del disco in endian misto                                                                                                                                                    |
| 72 (0x48) | 8 byte  | LBA iniziale di un array di voci di partizione (sempre 2 nella copia primaria)                                                                                                     |
| 80 (0x50) | 4 byte  | Numero di voci di partizione nell'array                                                                                                                                         |
| 84 (0x54) | 4 byte  | Dimensione di una singola voce di partizione (solitamente 80h o 128)                                                                                                                        |
| 88 (0x58) | 4 byte  | CRC32 dell'array delle voci di partizione in little-endian                                                                                                                            |
| 92 (0x5C) | \*       | Riservato; deve essere composto da zeri per il resto del blocco (420 byte per una dimensione del settore di 512 byte; può essere maggiore con dimensioni del settore superiori)                                      |

**Voci di partizione (LBA 2–33)**

| Formato delle voci di partizione GUID |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Lunghezza   | Contenuto                                                                                                      |
| 0 (0x00)                    | 16 byte | [GUID del tipo di partizione](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (endian misto) |
| 16 (0x10)                   | 16 byte | GUID univoco della partizione (endian misto)                                                                          |
| 32 (0x20)                   | 8 byte  | Primo LBA ([little-endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 byte  | Ultimo LBA (inclusivo, solitamente dispari)                                                                             |
| 48 (0x30)                   | 8 byte  | Flag degli attributi (ad es. il bit 60 indica la sola lettura)                                                               |
| 56 (0x38)                   | 72 byte | Nome della partizione (36 unità di codice [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                               |

**Tipi di partizione**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 byte | Nome della partizione (36 unità di codice UTF-16LE)](<../../../images/image (83).png>)

Altri tipi di partizione sono disponibili su [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Ispezione

Dopo aver montato l'immagine forense con [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), è possibile ispezionare il primo settore usando lo strumento Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Nell'immagine seguente è stato rilevato e interpretato un **MBR** nel **settore 0**:

![GPT (GUID Partition Table) - Ispezione: dopo aver montato l'immagine forense con ArsenalImageMounter, è possibile ispezionare il primo settore usando lo strumento Windows Active Disk Editor. Nell'immagine...](<../../../images/image (354).png>)

Per GPT, cercare la firma _EFI PART_ nell'header primario in **LBA 1**; LBA 0 contiene ancora l'MBR protettivo.<sup>[[4]](#references)</sup>

### Individuare dati al di fuori delle partizioni elencate

Una voce di partizione eliminata o uno spazio inutilizzato intenzionalmente possono lasciare un filesystem al di fuori della mappa delle partizioni corrente. Su una **copia di lavoro raw verificata**, elencare gli intervalli non allocati, quindi verificare un LBA iniziale candidato come filesystem. `mmls` e `fsstat` usano **offset di settore**; specificare per entrambi la dimensione effettiva del settore logico. Non confondere i settori dei metadati GPT con un volume nascosto.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

Se `fsstat` non riesce a identificare un file system all'inizio dello spazio vuoto, usa TestDisk **Analyse → Quick Search**, quindi **Deeper Search** se necessario. Premi `P` su un candidato per ispezionare i file; non selezionare **Write** sulle prove. Sulle immagini GPT, `sgdisk --verify disk.img` verifica i CRC e la corrispondenza tra la tabella principale e quella di backup, ma un header di backup può essere obsoleto dopo il ripartizionamento; prima del recupero, verifica quindi i limiti dei candidati confrontandoli con le strutture del file system.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## File system

### Elenco dei file system Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Il file system **FAT (File Allocation Table)** è progettato attorno al suo componente centrale, la tabella di allocazione dei file, collocata all'inizio del volume. Un volume ha comunemente **due copie della FAT**, anche se il BPB ne consente una sola. FAT12/16 collocano la directory principale in una regione fissa; FAT32 memorizza la directory principale nell'area dati, nel cluster indicato da `BPB_RootClus`.<sup>[[7]](#references)</sup>

L'unità di allocazione è un **cluster**: `BPB_BytsPerSec × BPB_SecPerClus`, quindi non necessariamente 512 byte. Il tipo di FAT è determinato dal numero di cluster di dati, non da una stringa di versione nel settore di avvio. I limiti del numero di cluster sono:<sup>[[7]](#references)</sup>

- **FAT12**: meno di 4.085 cluster di dati.
- **FAT16**: da 4.085 a 65.524 cluster di dati.
- **FAT32**: almeno 65.525 cluster di dati; per il numero del cluster vengono usati solo 28 bit di ogni voce FAT a 32 bit.

Il campo a 32 bit per la dimensione del file limita un file normale a **2³²−1 byte** (poco meno di 4 GiB).<sup>[[7]](#references)</sup>

I componenti principali della directory principale, in particolare per FAT12 e FAT16, includono:

- **Nome del file/della cartella** (fino a 8 caratteri)
- **Attributi**
- **Date di creazione, modifica e ultimo accesso**
- **Indirizzo della tabella FAT** (indica il cluster iniziale del file)
- **Dimensione del file**

### EXT

**Ext2** è il file system più comune per le partizioni **senza journaling** (**partizioni che non cambiano molto**), come la partizione di avvio. **Ext3/4** supportano il **journaling** e vengono solitamente usati per le **altre partizioni**.

## **Metadati**

Alcuni file contengono metadati. Queste informazioni riguardano il contenuto del file e a volte possono interessare un analista, poiché, a seconda del tipo di file, possono includere informazioni come:

- Titolo
- Versione di MS Office usata
- Autore
- Date di creazione e ultima modifica
- Modello della fotocamera
- Coordinate GPS
- Informazioni sull'immagine

Puoi usare strumenti come [**exiftool**](https://exiftool.org) e [**Metadiver**](https://www.easymetadata.com/metadiver-2/) per ottenere i metadati di un file.

## **Recupero dei file eliminati**

### File eliminati registrati

Come già visto, ci sono diversi punti in cui il file rimane salvato dopo essere stato "eliminato". Questo perché di solito l'eliminazione di un file da un file system lo contrassegna semplicemente come eliminato, senza toccare i dati. È quindi possibile esaminare i registri dei file (come la MFT) e trovare i file eliminati.<sup>[[2]](#references)</sup>

Inoltre, il sistema operativo salva solitamente molte informazioni sulle modifiche al file system e sui backup; è quindi possibile provare a usarle per recuperare il file o quante più informazioni possibili.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

Il **File carving** è una tecnica che cerca di **trovare file all'interno di grandi quantità di dati**. Gli strumenti di questo tipo funzionano principalmente in 3 modi: **in base alle intestazioni e ai footer dei tipi di file**, in base alle **strutture** dei tipi di file e in base al **contenuto** stesso.

Il carving semplice basato su header/footer presuppone che i blocchi siano contigui e può restituire solo un frammento se un file è suddiviso. Questo non è un limite assoluto: PhotoRec offre un'opzione **Paranoid → bruteforce**, intensiva per la CPU, per alcuni JPEG frammentati, mentre la ricomposizione dei frammenti consapevole del formato può recuperare altri tipi supportati. Consulta [strumenti di file carving e recupero](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) per un workflow aggiornato di ricomposizione dei frammenti.<sup>[[8]](#references)</sup>

Esistono diversi strumenti che puoi usare per il File carving, specificando i tipi di file da cercare


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Il Data Stream Carving è simile al File Carving, ma **invece di cercare file completi, cerca frammenti di informazioni interessanti**.\
Per esempio, invece di cercare un file completo contenente URL registrati, questa tecnica cerca gli URL.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Eliminazione sicura

Ovviamente, esistono modi per **eliminare "in modo sicuro" i file e parte dei registri che li riguardano**. Per esempio, è possibile **sovrascrivere il contenuto** di un file più volte con dati spazzatura, quindi **rimuovere** i **registri** relativi al file da **$MFT** e **$LOGFILE** e **rimuovere le copie shadow del volume**.<sup>[[3]](#references)</sup>\
Potresti notare che, anche dopo aver eseguito questa operazione, l'esistenza del file potrebbe essere ancora registrata **in altri punti**; è vero, e individuare questi elementi è parte del lavoro di un professionista della computer forensics.



## References

- [1] [Tabella delle partizioni GUID - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Come analizzare le voci $I30 (directory) di NTFS per trovare prove di file eliminati](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Servizio Copia Shadow del volume (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [Specifiche UEFI: layout del disco GPT](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [Manuale mmls di The Sleuth Kit](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [Manuale fsstat di The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Specifiche FAT di Microsoft](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [Opzioni di recupero di PhotoRec](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [Recupero delle partizioni eliminate con TestDisk](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [Manuale di sgdisk](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [Manuale di mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
