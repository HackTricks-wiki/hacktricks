# Particije/Sistemi datoteka/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Particije

Hard disk ili **SSD disk može sadržati različite particije** sa ciljem fizičkog razdvajanja podataka.\
**Minimalna** jedinica diska je **sektor** (obično se sastoji od 512B). Zato veličina svake particije mora biti umnožak te veličine.

### MBR (master Boot Record)

Smešten je u **prvom sektoru diska, nakon 446B boot koda**. Ovaj sektor je ključan za određivanje particije koju računar treba da montira i lokacije sa koje to treba da uradi.\
Omogućava do **4 particije** (najviše **samo 1** može biti aktivna/**bootable**). Međutim, ako su vam potrebne dodatne particije, možete koristiti **extended partitions**. **Poslednji bajt** ovog prvog sektora je potpis boot zapisa **0x55AA**. Samo jedna particija može biti označena kao aktivna.\
MBR podržava **najviše 2.2TB**.

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (304).png>)

U **bajtovima 440 do 443** MBR-a možete pronaći **Windows Disk Signature** (ako se koristi Windows). Logičko slovo disk jedinice hard diska zavisi od Windows Disk Signature. Promena ovog potpisa može sprečiti pokretanje Windows-a (alat: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): From the bytes 440 to the 443 of the MBR you can find the Windows Disk Signature (if Windows is used). The logical drive letter of the hard disk depends on the Windows Disk Signature. Changing this signature could prevent Windows from booting (tool: Active Disk Editor).](<../../../images/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Format zapisa particije**

| Offset    | Length   | Item                                                   |
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

Da biste montirali MBR u Linux-u, najpre morate dobiti početni offset (možete koristiti `fdisk` i komandu `p`)

![Partitions - MBR (master Boot Record): In order to mount an MBR in Linux you first need to get the start offset (you can use fdisk and the p command)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

A zatim koristite sledeći kod
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) je uobičajena šema koja se koristi za **navođenje lokacije blokova** podataka sačuvanih na računarskim uređajima za skladištenje, uglavnom sekundarnim sistemima za skladištenje kao što su hard diskovi. LBA je naročito jednostavna linearna šema adresiranja; **blokovi se lociraju pomoću celobrojnog indeksa**, pri čemu je prvi blok LBA 0, drugi LBA 1 i tako dalje.

### GPT (GUID Partition Table)

GUID Partition Table, poznat kao GPT, favorizovan je zbog naprednijih mogućnosti u poređenju sa MBR (Master Boot Record). Karakterističan po svom **globalno jedinstvenom identifikatoru** za particije, GPT se izdvaja na nekoliko načina:

- **Lokacija i veličina**: I GPT i MBR počinju od **sektora 0**. Međutim, GPT radi sa **64 bita**, za razliku od MBR-a koji koristi 32 bita.
- **Ograničenja particija**: GPT podržava do **128 particija** na Windows sistemima i može da podrži do **9.4ZB** podataka.
- **Nazivi particija**: Omogućava imenovanje particija sa najviše 36 Unicode znakova.

**Otpornost podataka i oporavak**:

- **Redundantnost**: Za razliku od MBR-a, GPT ne ograničava podatke o particionisanju i boot podacima na jednu lokaciju. On replicira ove podatke širom diska, čime poboljšava integritet i otpornost podataka.
- **Cyclic Redundancy Check (CRC)**: GPT koristi CRC za obezbeđivanje integriteta podataka. Aktivno prati oštećenje podataka i, kada ga otkrije, GPT pokušava da oporavi oštećene podatke sa druge lokacije na disku.

**Protective MBR (LBA0)**:

- GPT održava kompatibilnost unazad pomoću protective MBR-a. Ova funkcija se nalazi u prostoru starog MBR-a, ali je dizajnirana tako da spreči starije MBR-based alate da greškom prebrišu GPT diskove, čime štiti integritet podataka na diskovima formatiranim kao GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

U operativnim sistemima koji podržavaju **GPT-based boot kroz BIOS** servise umesto EFI-ja, prvi sektor se i dalje može koristiti za čuvanje koda prve faze **bootloader**-a, ali izmenjenog tako da prepoznaje **GPT** **particije**. Bootloader u MBR-u ne sme pretpostaviti da je veličina sektora 512 bajtova.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Zaglavlje particione tabele definiše upotrebljive blokove na disku. Takođe definiše broj i veličinu unosa particija koji čine particionu tabelu (pomaci 80 i 84 u tabeli).

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

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Više tipova particija nalazi se na [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

### Inspecting

Nakon montiranja forensics image-a pomoću alata [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), prvi sektor možete pregledati pomoću Windows alata [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na sledećoj slici detektovan je **MBR** na **sektoru 0** i prikazano je njegovo tumačenje:

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

Ako je u pitanju **GPT tabela umesto MBR-a**, potpis _EFI PART_ trebalo bi da se pojavi u **sektoru 1** (koji je na prethodnoj slici prazan).

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system je dizajniran oko svoje osnovne komponente, tabele alokacije datoteka, koja se nalazi na početku volumena. Ovaj sistem štiti podatke održavanjem **dve kopije** tabele, čime obezbeđuje integritet podataka čak i ako je jedna kopija oštećena. Tabela, zajedno sa root folderom, mora biti na **fiksnoj lokaciji**, što je ključno za proces pokretanja sistema.

Osnovna jedinica skladištenja ovog file system-a je **cluster, obično veličine 512B**, koji se sastoji od više sektora. FAT se razvijao kroz sledeće verzije:

- **FAT12**, koji podržava 12-bitne adrese cluster-a i upravlja sa do 4078 cluster-a (4084 sa UNIX-om).
- **FAT16**, koji koristi 16-bitne adrese i time podržava do 65,517 cluster-a.
- **FAT32**, koji dalje napreduje sa 32-bitnim adresama i omogućava impresivnih 268,435,456 cluster-a po volumenu.

Značajno ograničenje svih FAT verzija jeste **maksimalna veličina datoteke od 4GB**, nametnuta 32-bitnim poljem koje se koristi za čuvanje veličine datoteke.

Ključne komponente root direktorijuma, naročito kod FAT12 i FAT16, obuhvataju:

- **File/Folder Name** (do 8 znakova)
- **Attributes**
- **Creation, Modification, and Last Access Dates**
- **FAT Table Address** (označava početni cluster datoteke)
- **File Size**

### EXT

**Ext2** je najčešći file system za **particije bez journaling-a** (**particije koje se ne menjaju često**), kao što je boot particija. **Ext3/4** koriste **journaling** i obično se koriste za **preostale particije**.

## **Metadata**

Neke datoteke sadrže metadata podatke. Ove informacije odnose se na sadržaj datoteke i ponekad mogu biti zanimljive analitičaru, jer u zavisnosti od tipa datoteke mogu sadržati informacije kao što su:

- Naslov
- Korišćena MS Office verzija
- Autor
- Datumi kreiranja i poslednje izmene
- Model kamere
- GPS koordinate
- Informacije o slici

Za dobijanje metadata podataka datoteke možete koristiti alate kao što su [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/).

## **Deleted Files Recovery**

### Logged Deleted Files

Kao što je ranije prikazano, postoji nekoliko mesta na kojima je datoteka i dalje sačuvana nakon što je „obrisana“. Razlog je to što brisanje datoteke iz file system-a obično samo označava datoteku kao obrisanu, dok se podaci ne menjaju. Zatim je moguće pregledati registre datoteka (kao što je MFT) i pronaći obrisane datoteke.<sup>[[2]](#references)</sup>

Takođe, OS obično čuva veliki broj informacija o promenama file system-a i backup-ima, pa je moguće pokušati da se one iskoriste za oporavak datoteke ili što veće količine informacija.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** je tehnika koja pokušava da **pronađe datoteke u velikoj količini podataka**. Postoje 3 glavna načina na koja ovakvi alati rade: **na osnovu header-a i footer-a tipova datoteka**, na osnovu **struktura** tipova datoteka i na osnovu samog **sadržaja**.

Imajte na umu da ova tehnika **ne funkcioniše za pronalaženje fragmentovanih datoteka**. Ako datoteka **nije sačuvana u susednim sektorima**, ova tehnika neće moći da je pronađe, ili će pronaći samo njen deo.

Postoji nekoliko alata koje možete koristiti za File Carving, uz navođenje tipova datoteka koje želite da pretražite.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving je sličan tehnici File Carving, ali **umesto traženja kompletnih datoteka, traži zanimljive fragmente** informacija.\
Na primer, umesto traženja kompletne datoteke koja sadrži zabeležene URL-ove, ova tehnika će pretraživati URL-ove.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Očigledno je da postoje načini za **„bezbedno“ brisanje datoteka i delova logova o njima**. Na primer, moguće je nekoliko puta **prepisati sadržaj** datoteke nasumičnim podacima, zatim ukloniti **logove** iz **$MFT** i **$LOGFILE** koji se odnose na datoteku i ukloniti **Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Možda ćete primetiti da čak i nakon izvršavanja te radnje mogu postojati **drugi delovi u kojima je postojanje datoteke i dalje zabeleženo**, što je tačno; deo posla forensics profesionalca jeste da ih pronađe.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
