# Particije/Sistemi datoteka/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Particije

Hard disk ili **SSD disk može sadržati različite particije** sa ciljem fizičkog odvajanja podataka.\
**Minimalna** jedinica diska je **sektor** (obično se sastoji od 512B). Zato veličina svake particije mora biti višekratnik te veličine.

### MBR (master Boot Record)

On se nalazi u **prvom sektoru diska, nakon 446B boot koda**. Ovaj sektor je ključan za određivanje računaru šta treba montirati kao particiju i odakle.\
Omogućava do **4 particije** (najviše **samo 1** može biti aktivna/**bootable**). Međutim, ako vam je potrebno više particija, možete koristiti **extended partitions**. **Poslednji bajt** ovog prvog sektora je potpis boot record-a **0x55AA**. Samo jedna particija može biti označena kao aktivna.\
MBR omogućava **najviše 2.2TB**.

![Particije - MBR (master Boot Record): MBR omogućava najviše 2.2TB](<../../../images/image (350).png>)

![Particije - MBR (master Boot Record): MBR omogućava najviše 2.2TB](<../../../images/image (304).png>)

U **bajtovima 440 do 443** MBR-a možete pronaći **Windows Disk Signature** (ako se koristi Windows). Logičko slovo diska hard diska zavisi od Windows Disk Signature-a. Promena ovog potpisa može sprečiti podizanje sistema Windows (alat: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Particije - MBR (master Boot Record): U bajtovima 440 do 443 MBR-a možete pronaći Windows Disk Signature (ako se koristi Windows). Logičko slovo diska hard diska...](<../../../images/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot kod            |
| 446 (0x1BE) | 16 (0x10)  | Prva particija      |
| 462 (0x1CE) | 16 (0x10)  | Druga particija     |
| 478 (0x1DE) | 16 (0x10)  | Treća particija     |
| 494 (0x1EE) | 16 (0x10)  | Četvrta particija   |
| 510 (0x1FE) | 2 (0x2)    | Potpis 0x55 0xAA    |

**Format zapisa particije**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktivna zastavica (0x80 = bootable)                   |
| 1 (0x01)  | 1 (0x01) | Početna glava                                         |
| 2 (0x02)  | 1 (0x01) | Početni sektor (bitovi 0-5); gornji bitovi cilindra (6- 7) |
| 3 (0x03)  | 1 (0x01) | Najnižih 8 bitova početnog cilindra                   |
| 4 (0x04)  | 1 (0x01) | Kod tipa particije (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | Krajnja glava                                          |
| 6 (0x06)  | 1 (0x01) | Krajnji sektor (bitovi 0-5); gornji bitovi cilindra (6- 7) |
| 7 (0x07)  | 1 (0x01) | Najnižih 8 bitova krajnjeg cilindra                    |
| 8 (0x08)  | 4 (0x04) | Sektori koji prethode particiji (little endian)        |
| 12 (0x0C) | 4 (0x04) | Sektori u particiji                                    |

Da biste montirali MBR u Linux-u, najpre morate dobiti početni offset (možete koristiti `fdisk` i komandu `p`)

![Particije - MBR (master Boot Record): Da biste montirali MBR u Linux-u, najpre morate dobiti početni offset (možete koristiti fdisk i komandu p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Zatim upotrebite sledeći kod
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) je uobičajena šema koja se koristi za **navođenje lokacije blokova** podataka sačuvanih na računarskim uređajima za skladištenje, uglavnom sekundarnim sistemima za skladištenje kao što su hard diskovi. LBA je naročito jednostavna linearna šema adresiranja; **blokovi se lociraju celobrojnim indeksom**, pri čemu je prvi blok LBA 0, drugi LBA 1 i tako dalje.

### GPT (GUID Partition Table)

GUID Partition Table, poznat kao GPT, ima prednost zbog naprednijih mogućnosti u poređenju sa MBR (Master Boot Record). GPT se odlikuje **globalno jedinstvenim identifikatorom** za particije i izdvaja se na nekoliko načina:

- **Lokacija i veličina**: I GPT i MBR počinju od **sektora 0**. Međutim, GPT radi sa **64 bita**, za razliku od MBR-a koji koristi 32 bita.
- **Ograničenja particija**: GPT podržava do **128 particija** na Windows sistemima i može da prihvati do **9.4ZB** podataka.
- **Nazivi particija**: Omogućava imenovanje particija sa najviše 36 Unicode karaktera.

**Otpornost podataka i oporavak**:

- **Redundansa**: Za razliku od MBR-a, GPT ne ograničava particionisanje i boot podatke na jednu lokaciju. Ove podatke replicira širom diska, čime poboljšava integritet i otpornost podataka.
- **Cyclic Redundancy Check (CRC)**: GPT koristi CRC za obezbeđivanje integriteta podataka. Aktivno nadgleda oštećenje podataka i, kada ga otkrije, pokušava da oporavi oštećene podatke sa druge lokacije na disku.

**Protective MBR (LBA0)**:

- GPT održava kompatibilnost unazad pomoću zaštitnog MBR-a. Ova funkcija se nalazi u prostoru legacy MBR-a, ali je dizajnirana tako da spreči starije MBR-based alate da greškom prebrišu GPT diskove, čime se štiti integritet podataka na diskovima formatiranim kao GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Sa Wikipedije](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

U operativnim sistemima koji podržavaju **GPT-based boot through BIOS** servise umesto EFI-ja, prvi sektor se i dalje može koristiti za čuvanje prve faze koda **bootloader-a**, ali je **izmenjen** tako da prepoznaje **GPT** **particije**. Bootloader u MBR-u ne sme pretpostaviti veličinu sektora od 512 bajtova.

**Zaglavlje particione tabele (LBA 1)**

[Sa Wikipedije](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Zaglavlje particione tabele definiše upotrebljive blokove na disku. Takođe definiše broj i veličinu unosa particija koji čine particionu tabelu (pomaci 80 i 84 u tabeli).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ili 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)na little-endian mašinama) |
| 8 (0x08)  | 4 bytes  | Revizija 1.0 (00h 00h 01h 00h) za UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Veličina zaglavlja u little endian formatu (u bajtovima, obično 5Ch 00h 00h 00h ili 92 bajta)                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) zaglavlja (od pomaka +0 do veličine zaglavlja) u little endian formatu, pri čemu je ovo polje tokom izračunavanja postavljeno na nulu                             |
| 20 (0x14) | 4 bytes  | Rezervisano; mora biti nula                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Trenutni LBA (lokacija ove kopije zaglavlja)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (lokacija druge kopije zaglavlja)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Prvi upotrebljivi LBA za particije (poslednji LBA primarne particione tabele + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Poslednji upotrebljivi LBA (prvi LBA sekundarne particione tabele − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | GUID diska u mixed endian formatu                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Početni LBA niza unosa particija (uvek 2 u primarnoj kopiji)                                                                                                     |
| 80 (0x50) | 4 bytes  | Broj unosa particija u nizu                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Veličina pojedinačnog unosa particije (obično 80h ili 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 niza unosa particija u little endian formatu                                                                                                                            |
| 92 (0x5C) | \*       | Rezervisano; ostatak bloka mora sadržati nule (420 bajtova za veličinu sektora od 512 bajtova; ali može biti više kod većih veličina sektora)                                      |

**Unosi particija (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [GUID tipa particije](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Jedinstveni GUID particije (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | Prvi LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Poslednji LBA (uključujući njega, obično neparan)                                                                             |
| 48 (0x30)                   | 8 bytes  | Zastavice atributa (npr. bit 60 označava read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Naziv particije (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Tipovi particija**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Naziv particije (36 UTF-16LE code units)](<../../../images/image (83).png>)

Više tipova particija dostupno je na [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspekcija

Nakon montiranja forensics image-a pomoću alata [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), prvi sektor možete pregledati pomoću Windows alata [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na sledećoj slici detektovan je **MBR** na **sektoru 0** i izvršena je njegova interpretacija:

![GPT (GUID Partition Table) - Inspekcija: Nakon montiranja forensics image-a pomoću alata ArsenalImageMounter, prvi sektor možete pregledati pomoću Windows alata Active Disk Editor. Na...](<../../../images/image (354).png>)

Ako je u pitanju **GPT tabela umesto MBR-a**, potpis _EFI PART_ trebalo bi da se pojavi u **sektoru 1** (koji je na prethodnoj slici prazan).

## File-Systems

### Lista Windows file-systems

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system zasnovan je oko svoje osnovne komponente, file allocation table, koja se nalazi na početku volumena. Ovaj sistem štiti podatke tako što održava **dve kopije** tabele, čime obezbeđuje integritet podataka čak i ako se jedna kopija ošteti. Tabela, zajedno sa root folderom, mora biti na **fiksnoj lokaciji**, što je od ključne važnosti za proces pokretanja sistema.

Osnovna jedinica skladištenja file system-a je **cluster, obično veličine 512B**, koji se sastoji od više sektora. FAT je evoluirao kroz sledeće verzije:

- **FAT12**, koji podržava 12-bitne cluster adrese i obrađuje do 4078 cluster-a (4084 sa UNIX-om).
- **FAT16**, koji uvodi 16-bitne adrese i time podržava do 65.517 cluster-a.
- **FAT32**, koji dalje napreduje sa 32-bitnim adresama i omogućava impresivnih 268.435.456 cluster-a po volumenu.

Značajno ograničenje svih FAT verzija jeste **maksimalna veličina datoteke od 4 GB**, nametnuta 32-bitnim poljem koje se koristi za čuvanje veličine datoteke.

Ključne komponente root direktorijuma, naročito kod FAT12 i FAT16, obuhvataju:

- **Naziv datoteke/foldera** (do 8 karaktera)
- **Atribute**
- **Datume kreiranja, izmene i poslednjeg pristupa**
- **Adresu FAT tabele** (koja označava početni cluster datoteke)
- **Veličinu datoteke**

### EXT

**Ext2** je najčešći file system za **particije bez journaling-a** (**particije koje se ne menjaju često**), kao što je boot particija. **Ext3/4** koriste **journaling** i obično se upotrebljavaju za **ostale particije**.

## **Metadata**

Neke datoteke sadrže metadata podatke. Ove informacije odnose se na sadržaj datoteke i ponekad mogu biti interesantne analitičaru, jer u zavisnosti od tipa datoteke mogu sadržati informacije kao što su:

- Naslov
- Korišćena MS Office verzija
- Autor
- Datumi kreiranja i poslednje izmene
- Model kamere
- GPS koordinate
- Informacije o slici

Za pribavljanje metadata podataka datoteke možete koristiti alate kao što su [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/).

## **Oporavak obrisanih datoteka**

### Logged Deleted Files

Kao što je ranije prikazano, postoji nekoliko mesta na kojima je datoteka i dalje sačuvana nakon što je „obrisana“. To je zato što brisanje datoteke iz file system-a obično samo označava datoteku kao obrisanu, dok se podaci ne menjaju. Zatim je moguće pregledati registre datoteka (kao što je MFT) i pronaći obrisane datoteke.<sup>[[2]](#references)</sup>

Takođe, OS obično čuva mnogo informacija o promenama file system-a i backup-ima, pa je moguće pokušati da ih iskoristite za oporavak datoteke ili što veće količine informacija.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** je tehnika koja pokušava da **pronađe datoteke u velikoj količini podataka**. Postoje 3 glavna načina na koja ovakvi alati rade: **na osnovu header-a i footer-a tipova datoteka**, na osnovu **struktura** tipova datoteka i na osnovu samog **sadržaja**.

Imajte na umu da ova tehnika **ne funkcioniše za preuzimanje fragmentovanih datoteka**. Ako datoteka **nije sačuvana u susednim sektorima**, ova tehnika neće moći da je pronađe ili će pronaći samo njen deo.

Postoji nekoliko alata koje možete koristiti za File Carving, uz navođenje tipova datoteka koje želite da pretražite.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving je sličan File Carving-u, ali **umesto traženja kompletnih datoteka, traži interesantne fragmente** informacija.\
Na primer, umesto traženja kompletne datoteke koja sadrži logged URL-ove, ova tehnika će pretraživati URL-ove.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Očigledno, postoje načini za **„bezbedno“ brisanje datoteka i delova log-ova o njima**. Na primer, moguće je nekoliko puta **prepisati sadržaj** datoteke besmislenim podacima, zatim **ukloniti** **log-ove** iz **$MFT** i **$LOGFILE** koji se odnose na datoteku i **ukloniti Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Možda ćete primetiti da čak i nakon izvršavanja te radnje mogu postojati **drugi delovi u kojima je postojanje datoteke i dalje zabeleženo**, što je tačno; deo posla forensics profesionalca jeste da ih pronađe.

## References

- [1] [GUID Partition Table - Vikipedija](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Kako skenirati NTFS $I30 (directory) unose radi pronalaženja dokaza o obrisanim datotekama](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
