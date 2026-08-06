# Partizioni/File System/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partizioni

Un hard disk o un **disco SSD può contenere partizioni diverse** con l'obiettivo di separare fisicamente i dati.\
L'unità **minima** di un disco è il **settore** (normalmente composto da 512B). Pertanto, la dimensione di ogni partizione deve essere un multiplo di tale dimensione.

### MBR (master Boot Record)

È allocato nel **primo settore del disco, dopo i 446B del boot code**. Questo settore è essenziale per indicare al PC quale partizione montare e da dove.\
Consente fino a **4 partizioni** (al massimo **solo 1** può essere attiva/**bootable**). Tuttavia, se sono necessarie più partizioni, è possibile usare le **extended partitions**. Il **byte finale** di questo primo settore è la boot record signature **0x55AA**. Solo una partizione può essere contrassegnata come attiva.\
MBR consente un massimo di **2.2TB**.

![Partizioni - MBR (master Boot Record): MBR consente un massimo di 2.2TB](<../../../images/image (350).png>)

![Partizioni - MBR (master Boot Record): MBR consente un massimo di 2.2TB](<../../../images/image (304).png>)

Dai **byte 440 a 443** dell'MBR è possibile trovare la **Windows Disk Signature** (se viene usato Windows). La lettera dell'unità logica dell'hard disk dipende dalla Windows Disk Signature. La modifica di questa signature potrebbe impedire l'avvio di Windows (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partizioni - MBR (master Boot Record): dai byte 440 a 443 dell'MBR è possibile trovare la Windows Disk Signature (se viene usato Windows). La lettera dell'unità logica dell'hard disk...](<../../../images/image (310).png>)

**Formato**

| Offset      | Lunghezza     | Elemento                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | Prima partizione     |
| 462 (0x1CE) | 16 (0x10)  | Seconda partizione    |
| 478 (0x1DE) | 16 (0x10)  | Terza partizione     |
| 494 (0x1EE) | 16 (0x10)  | Quarta partizione    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Formato del record della partizione**

| Offset    | Lunghezza   | Elemento                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Active flag (0x80 = bootable)                          |
| 1 (0x01)  | 1 (0x01) | Start head                                             |
| 2 (0x02)  | 1 (0x01) | Start sector (bits 0-5); upper bits of cylinder (6- 7) |
| 3 (0x03)  | 1 (0x01) | Start cylinder lowest 8 bits                           |
| 4 (0x04)  | 1 (0x01) | Partition type code (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | End head                                               |
| 6 (0x06)  | 1 (0x01) | End sector (bits 0-5); upper bits of cylinder (6- 7)   |
| 7 (0x07)  | 1 (0x01) | End cylinder lowest 8 bits                             |
| 8 (0x08)  | 4 (0x04) | Sectors preceding partition (little endian)            |
| 12 (0x0C) | 4 (0x04) | Sectors in partition                                   |

Per montare un MBR in Linux è prima necessario ottenere lo start offset (è possibile usare `fdisk` e il comando `p`)

![Partizioni - MBR (master Boot Record): per montare un MBR in Linux è prima necessario ottenere lo start offset (è possibile usare fdisk e il comando p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

E poi usare il seguente codice
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**L'indirizzamento a blocchi logici** (**LBA**) è uno schema comune utilizzato per **specificare la posizione dei blocchi** di dati archiviati sui dispositivi di storage dei computer, generalmente sistemi di storage secondario come le unità disco rigido. LBA è uno schema di indirizzamento lineare particolarmente semplice; **i blocchi vengono individuati tramite un indice intero**, con il primo blocco indicato come LBA 0, il secondo come LBA 1 e così via.

### GPT (GUID Partition Table)

La GUID Partition Table, nota come GPT, è preferita per le sue funzionalità avanzate rispetto a MBR (Master Boot Record). Caratterizzata dal suo **identificatore globalmente univoco** per le partizioni, GPT si distingue per diversi aspetti:

- **Posizione e dimensioni**: sia GPT sia MBR iniziano dal **settore 0**. Tuttavia, GPT opera su **64 bit**, a differenza dei 32 bit di MBR.
- **Limiti delle partizioni**: GPT supporta fino a **128 partizioni** sui sistemi Windows e gestisce fino a **9.4ZB** di dati.
- **Nomi delle partizioni**: consente di assegnare nomi alle partizioni usando fino a 36 caratteri Unicode.

**Resilienza e recupero dei dati**:

- **Ridondanza**: a differenza di MBR, GPT non limita i dati relativi al partizionamento e all'avvio a una sola posizione. Replica questi dati sul disco, migliorando l'integrità e la resilienza dei dati.
- **Cyclic Redundancy Check (CRC)**: GPT utilizza CRC per garantire l'integrità dei dati. Monitora attivamente la presenza di corruzione dei dati e, quando ne rileva una, tenta di recuperare i dati corrotti da un'altra posizione del disco.

**Protective MBR (LBA0)**:

- GPT mantiene la compatibilità con le versioni precedenti tramite un protective MBR. Questa funzionalità risiede nello spazio del MBR legacy, ma è progettata per impedire alle utility MBR meno recenti di sovrascrivere erroneamente i dischi GPT, proteggendo così l'integrità dei dati sui dischi formattati con GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Nei sistemi operativi che supportano l'avvio **basato su GPT tramite i servizi BIOS**, invece di EFI, il primo settore può essere ancora utilizzato per memorizzare il codice della prima fase del **bootloader**, ma **modificato** per riconoscere le **partizioni** **GPT**. Il bootloader nel MBR non deve presupporre una dimensione del settore di 512 byte.

**Header della partition table (LBA 1)**

[Da Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

L'header della partition table definisce i blocchi utilizzabili sul disco. Definisce inoltre il numero e la dimensione delle voci delle partizioni che costituiscono la partition table (offset 80 e 84 nella tabella).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)on little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) for UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size in little endian (in bytes, usually 5Ch 00h 00h 00h or 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) of header (offset +0 up to header size) in little endian, with this field zeroed during calculation                             |
| 20 (0x14) | 4 bytes  | Reserved; must be zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (location of this header copy)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (location of the other header copy)                                                                                                                               |
| 40 (0x28) | 8 bytes  | First usable LBA for partitions (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Disk GUID in mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Starting LBA of an array of partition entries (always 2 in primary copy)                                                                                                     |
| 80 (0x50) | 4 bytes  | Number of partition entries in array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Size of a single partition entry (usually 80h or 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 of partition entries array in little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; must be zeroes for the rest of the block (420 bytes for a sector size of 512 bytes; but can be more with larger sector sizes)                                      |

**Voci delle partizioni (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Tipi di partizioni**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Altri tipi di partizioni sono disponibili su [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### Ispezione

Dopo aver montato l'immagine forensics con [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), è possibile ispezionare il primo settore usando lo strumento Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Nell'immagine seguente è stato rilevato un **MBR** nel **settore 0** e ne è stata eseguita l'interpretazione:

![GPT (GUID Partition Table) - Ispezione: dopo aver montato l'immagine forensics con ArsenalImageMounter, è possibile ispezionare il primo settore usando lo strumento Windows Active Disk Editor. Nell'immagine...](<../../../images/image (354).png>)

Se fosse presente una **table GPT invece di un MBR**, la signature _EFI PART_ dovrebbe comparire nel **settore 1** (che nell'immagine precedente è vuoto).

## File system

### Elenco dei file system Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Il file system **FAT (File Allocation Table)** è progettato attorno al suo componente principale, la file allocation table, posizionata all'inizio del volume. Questo sistema protegge i dati mantenendo **due copie** della table, garantendo l'integrità dei dati anche se una delle due viene corrotta. La table, insieme alla cartella root, deve trovarsi in una **posizione fissa**, elemento fondamentale per il processo di avvio del sistema.

L'unità di storage di base del file system è un **cluster, solitamente di 512B**, composto da più settori. FAT si è evoluto attraverso diverse versioni:

- **FAT12**, che supporta indirizzi dei cluster a 12 bit e gestisce fino a 4078 cluster (4084 con UNIX).
- **FAT16**, che aumenta gli indirizzi a 16 bit, consentendo di gestire fino a 65.517 cluster.
- **FAT32**, che utilizza indirizzi a 32 bit, permettendo di gestire ben 268.435.456 cluster per volume.

Una limitazione significativa comune a tutte le versioni di FAT è la **dimensione massima dei file di 4GB**, imposta dal campo a 32 bit utilizzato per memorizzare la dimensione del file.

I componenti principali della directory root, in particolare per FAT12 e FAT16, includono:

- **Nome file/cartella** (fino a 8 caratteri)
- **Attributi**
- **Date di creazione, modifica e ultimo accesso**
- **Indirizzo della FAT table** (che indica il cluster iniziale del file)
- **Dimensione del file**

### EXT

**Ext2** è il file system più comune per le partizioni **senza journaling** (**partizioni che non cambiano molto**), come la partizione di boot. **Ext3/4** supportano il **journaling** e vengono generalmente utilizzati per le **partizioni restanti**.

## **Metadata**

Alcuni file contengono metadata. Queste informazioni riguardano il contenuto del file e talvolta possono essere interessanti per un analista poiché, a seconda del tipo di file, possono includere informazioni come:

- Titolo
- Versione di MS Office utilizzata
- Autore
- Date di creazione e ultima modifica
- Modello della fotocamera
- Coordinate GPS
- Informazioni sull'immagine

È possibile utilizzare strumenti come [**exiftool**](https://exiftool.org) e [**Metadiver**](https://www.easymetadata.com/metadiver-2/) per ottenere i metadata di un file.

## **Recupero dei file eliminati**

### File eliminati registrati

Come visto in precedenza, esistono diverse posizioni in cui il file continua a essere salvato dopo essere stato "eliminato". Questo accade perché normalmente l'eliminazione di un file da un file system lo contrassegna semplicemente come eliminato, senza modificare i dati. È quindi possibile esaminare i registri dei file (come l'MFT) e trovare i file eliminati.<sup>[[2]](#references)</sup>

Inoltre, il sistema operativo salva generalmente molte informazioni sulle modifiche al file system e sui backup, quindi è possibile provare a utilizzarle per recuperare il file o quante più informazioni possibili.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** è una tecnica che tenta di **trovare file nella massa dei dati**. Esistono 3 modalità principali con cui funzionano strumenti di questo tipo: **in base agli header e ai footer dei tipi di file**, in base alle **strutture** dei tipi di file e in base al **contenuto** stesso.

Si noti che questa tecnica **non funziona per recuperare file frammentati**. Se un file **non è memorizzato in settori contigui**, questa tecnica non sarà in grado di trovarlo, o almeno di trovarne una parte.

Esistono diversi strumenti utilizzabili per il File Carving, indicando i tipi di file che si desidera cercare.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving è simile al File Carving, ma **invece di cercare file completi, cerca frammenti di informazioni interessanti**.\
Ad esempio, invece di cercare un file completo contenente URL registrati, questa tecnica cercherà gli URL.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Ovviamente, esistono modi per **eliminare "in modo sicuro" i file e parte dei log che li riguardano**. Ad esempio, è possibile **sovrascrivere il contenuto** di un file con dati casuali diverse volte, quindi **rimuovere** i **log** relativi al file da **$MFT** e **$LOGFILE**, e **rimuovere le Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Si potrebbe notare che, anche eseguendo questa operazione, potrebbero esserci **altre parti in cui l'esistenza del file è ancora registrata**; ciò è corretto, e parte del lavoro del professionista forensics consiste nel trovarle.

## Riferimenti

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
