# Particije/Sistemi datoteka/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Particije

Disk može da sadrži više **particija**: logičke opsege blokova, a ne fizički odvojene memorijske prostore. Početak i dužina particija mere se u **logičkim sektorima**; nemojte pretpostavljati da svaka slika koristi sektore od 512 bajtova, jer postoje i logički sektori od 4096 bajtova.<sup>[[4]](#references)</sup>

### MBR (glavni zapis za pokretanje)

MBR zauzima prvi logički sektor (LBA 0); njegova četiri zapisa particija od po 16 bajtova počinju na bajtu 446. Prethodna oblast sadrži boot kod i može da sadrži potpis diska.<sup>[[4]](#references)</sup>\
Omogućava do **4 particije** (najviše **samo 1** može biti aktivna/**bootable**). Međutim, ako vam treba više particija, možete koristiti **proširene particije**. Poslednja **dva bajta** MBR-a od 512 bajtova predstavljaju boot potpis **0x55 0xAA**. Samo jedna particija može biti označena kao aktivna.\
Kod logičkih sektora od 512 bajtova, 32-bitna polja sektora u MBR-u ograničavaju adresabilnost na oko **2 TiB** (2,2 TB).<sup>[[4]](#references)</sup>

![Particije - MBR (glavni zapis za pokretanje): MBR podržava najviše 2,2 TB](<../../../images/image (350).png>)

![Particije - MBR (glavni zapis za pokretanje): MBR podržava najviše 2,2 TB](<../../../images/image (304).png>)

U MBR-u, od **bajta 440 do 443**, možete pronaći **Windows Disk Signature** (ako se koristi Windows). Logičko slovo diska zavisi od Windows Disk Signature. Promena ovog potpisa može sprečiti pokretanje sistema Windows (alat: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Particije - MBR (glavni zapis za pokretanje): U MBR-u, od bajta 440 do 443, možete pronaći Windows Disk Signature (ako se koristi Windows). Logičko slovo diska...](<../../../images/image (310).png>)

**Format**

| Pomak       | Dužina     | Stavka                 |
| ----------- | ---------- | ---------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot kod               |
| 446 (0x1BE) | 16 (0x10)  | Prva particija         |
| 462 (0x1CE) | 16 (0x10)  | Druga particija        |
| 478 (0x1DE) | 16 (0x10)  | Treća particija        |
| 494 (0x1EE) | 16 (0x10)  | Četvrta particija      |
| 510 (0x1FE) | 2 (0x2)    | Potpis 0x55 0xAA       |

**Format zapisa particije**

| Pomak     | Dužina   | Stavka                                                    |
| --------- | -------- | --------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Aktivna zastavica (0x80 = bootable)                       |
| 1 (0x01)  | 1 (0x01) | Početna glava                                             |
| 2 (0x02)  | 1 (0x01) | Početni sektor (bitovi 0-5); viši bitovi cilindra (6- 7)  |
| 3 (0x03)  | 1 (0x01) | Najnižih 8 bitova početnog cilindra                       |
| 4 (0x04)  | 1 (0x01) | Kod tipa particije (0x83 = Linux)                         |
| 5 (0x05)  | 1 (0x01) | Završna glava                                             |
| 6 (0x06)  | 1 (0x01) | Završni sektor (bitovi 0-5); viši bitovi cilindra (6- 7)  |
| 7 (0x07)  | 1 (0x01) | Najnižih 8 bitova završnog cilindra                       |
| 8 (0x08)  | 4 (0x04) | Sektori ispred particije (little endian)                   |
| 12 (0x0C) | 4 (0x04) | Broj sektora u particiji                                  |

Da biste pregledali particiju u slici celog diska sa MBR-om, najpre pribavite njen početni LBA i veličinu logičkog sektora. `mount` prima **pomak u bajtovima**, a ne LBA; primer ispod važi samo za sliku sa sektorima od 512 bajtova čija particija počinje na LBA 63. Za nepouzdane slike ili sisteme datoteka sa journalingom, umesto toga koristite izolovani režim rada samo za čitanje iz odeljka [Image Acquisition & Mount](../image-acquisition-and-mount.md).<sup>[[5]](#references)[[11]](#references)</sup>

![Particije - MBR (glavni zapis za pokretanje): Da biste montirali MBR u Linuxu, najpre morate da pronađete početni pomak (možete koristiti fdisk i komandu p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) je uobičajena šema za **navođenje lokacije blokova** podataka uskladištenih na računarskim uređajima za skladištenje, uglavnom sistemima sekundarnog skladištenja kao što su hard diskovi. LBA je posebno jednostavna linearna šema adresiranja; **blokovi se lociraju pomoću celobrojnog indeksa**, pri čemu je prvi blok LBA 0, drugi LBA 1 i tako dalje.

### GPT (GUID Partition Table)

GUID Partition Table (GPT) čuva jedinstveni GUID za svaku particiju i koristi primarne i rezervne metapodatke. Njegov raspored se razlikuje od MBR-a na sledeće načine:<sup>[[4]](#references)</sup>

- **Lokacija i veličina**: LBA 0 sadrži **protective MBR**. Zaglavlje primarne GPT particije nalazi se na LBA 1; iza njega se nalazi niz unosa particija, dok se rezervni niz i zaglavlje nalaze na kraju diska. GPT koristi 64-bitna LBA polja, dok unosi particija u MBR-u koriste 32-bitna LBA polja.
- **Ograničenja particija**: Uobičajeni niz unosa od 16 KiB sadrži **128 unosa od 128 bajtova**, ali se broj unosa beleži u zaglavlju, a ne fiksira GPT-om. Adresabilna veličina zavisi i od veličine logičkog sektora (oko **9,4 ZB** sa sektorima od 512 bajtova).<sup>[[4]](#references)</sup>
- **Nazivi particija**: Omogućava imenovanje particija sa najviše 36 Unicode znakova.

**Otpornost podataka i oporavak**:

- **Redundantnost**: Za razliku od MBR-a, GPT ne ograničava particionisanje i podatke za pokretanje sistema na jednu lokaciju. Ove podatke replicira na disku, čime se povećavaju integritet i otpornost podataka.
- **Ciklična provera redundantnosti (CRC)**: Zaglavlje i niz unosa particija imaju zasebne CRC32 vrednosti. CRC otkriva nedoslednosti; ne nadgleda disk neprekidno niti ga sam popravlja. Ako je primarna kopija nevažeća, proverite rezervnu kopiju na poslednjem LBA pre bilo kakvog oporavka na radnoj kopiji.<sup>[[4]](#references)</sup>

**Protective MBR (LBA0)**:

- GPT održava kompatibilnost sa starijim sistemima putem protective MBR-a. Ova funkcija se nalazi u prostoru nasleđenog MBR-a, ali je osmišljena tako da spreči starije uslužne programe zasnovane na MBR-u da greškom prepišu GPT diskove i tako zaštiti integritet podataka na diskovima formatiranim kao GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Sa Wikipedije](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

U operativnim sistemima koji podržavaju **pokretanje sistema zasnovano na GPT-u putem BIOS** usluga umesto EFI-ja, prvi sektor se i dalje može koristiti za čuvanje prve faze koda **bootloader-a**, ali **izmenjenog** tako da prepoznaje **GPT** **particije**. Bootloader u MBR-u ne sme pretpostaviti da je veličina sektora 512 bajtova.

**Zaglavlje tabele particija (LBA 1)**

[Sa Wikipedije](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Zaglavlje tabele particija definiše upotrebljive blokove na disku. Takođe definiše broj i veličinu unosa particija koji čine tabelu particija (pomaci 80 i 84 u tabeli).

| Pomak     | Dužina   | Sadržaj                                                                                                                                                                       |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bajtova | Potpis ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ili 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)na little-endian računarima) |
| 8 (0x08)  | 4 bajta   | Revizija 1.0 (00h 00h 01h 00h) za UEFI 2.8                                                                                                                                   |
| 12 (0x0C) | 4 bajta   | Veličina zaglavlja u little-endian formatu (u bajtovima, obično 5Ch 00h 00h 00h ili 92 bajta)                                                                                |
| 16 (0x10) | 4 bajta   | [CRC32](https://en.wikipedia.org/wiki/CRC32) zaglavlja (od pomaka +0 do veličine zaglavlja) u little-endian formatu; ovo polje se postavlja na nulu tokom izračunavanja      |
| 20 (0x14) | 4 bajta   | Rezervisano; mora biti nula                                                                                                                                                   |
| 24 (0x18) | 8 bajtova | Trenutni LBA (lokacija ove kopije zaglavlja)                                                                                                                                 |
| 32 (0x20) | 8 bajtova | Rezervni LBA (lokacija druge kopije zaglavlja)                                                                                                                               |
| 40 (0x28) | 8 bajtova | Prvi upotrebljivi LBA za particije (poslednji LBA primarne tabele particija + 1)                                                                                             |
| 48 (0x30) | 8 bajtova | Poslednji upotrebljivi LBA (prvi LBA sekundarne tabele particija − 1)                                                                                                         |
| 56 (0x38) | 16 bajtova | GUID diska u mešanom endian formatu                                                                                                                                         |
| 72 (0x48) | 8 bajtova | Početni LBA niza unosa particija (uvek 2 u primarnoj kopiji)                                                                                                                 |
| 80 (0x50) | 4 bajta   | Broj unosa particija u nizu                                                                                                                                                  |
| 84 (0x54) | 4 bajta   | Veličina pojedinačnog unosa particije (obično 80h ili 128)                                                                                                                   |
| 88 (0x58) | 4 bajta   | CRC32 niza unosa particija u little-endian formatu                                                                                                                           |
| 92 (0x5C) | \*        | Rezervisano; ostatak bloka mora sadržati nule (420 bajtova za veličinu sektora od 512 bajtova; može biti više za veće veličine sektora)                                      |

**Unosi particija (LBA 2–33)**

| Format unosa GUID particije |          |                                                                                                                  |
| --------------------------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| Pomak                       | Dužina   | Sadržaj                                                                                                         |
| 0 (0x00)                    | 16 bajtova | [GUID tipa particije](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mešani endian format) |
| 16 (0x10)                   | 16 bajtova | Jedinstveni GUID particije (mešani endian format)                                                               |
| 32 (0x20)                   | 8 bajtova | Prvi LBA ([little-endian](https://en.wikipedia.org/wiki/Little_endian))                                        |
| 40 (0x28)                   | 8 bajtova | Poslednji LBA (uključivo, obično neparan)                                                                       |
| 48 (0x30)                   | 8 bajtova | Zastavice atributa (npr. bit 60 označava samo za čitanje)                                                       |
| 56 (0x38)                   | 72 bajta  | Naziv particije (36 kodnih jedinica [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                          |

**Tipovi particija**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bajta | Naziv particije (36 kodnih jedinica UTF-16LE)](<../../../images/image (83).png>)

Više tipova particija potražite na [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Pregled

Nakon montiranja forensics image-a pomoću [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), možete pregledati prvi sektor pomoću Windows alata [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na sledećoj slici detektovan je **MBR** na **sektoru 0** i protumačen:

![GPT (GUID Partition Table) - Pregled: Nakon montiranja forensics image-a pomoću ArsenalImageMounter-a, možete pregledati prvi sektor pomoću Windows alata Active Disk Editor. Na sledećoj slici...](<../../../images/image (354).png>)

Kod GPT-a potražite potpis _EFI PART_ u primarnom zaglavlju na **LBA 1**; LBA 0 i dalje sadrži protective MBR.<sup>[[4]](#references)</sup>

### Pronalaženje podataka izvan navedenih particija

Izbrisani unos particije ili namerno ostavljen neiskorišćeni prostor mogu ostaviti filesystem izvan trenutne mape particija. Na **proverenoj sirovoj radnoj kopiji** navedite nealocirane opsege, a zatim proverite da li je početni LBA kandidata početak filesystem-a. `mmls` i `fsstat` koriste **pomake sektora**; navedite stvarnu veličinu logičkog sektora za oba alata. Nemojte pomešati GPT sektore metapodataka sa skrivenim volumenom.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

Ako `fsstat` ne može da identifikuje sistem datoteka na početku praznine, upotrebite TestDisk **Analyse → Quick Search**, a zatim **Deeper Search** ako je potrebno. Pritisnite `P` na kandidatu da biste pregledali datoteke; nemojte izabrati **Write** na dokaznom materijalu. Na GPT slikama, `sgdisk --verify disk.img` proverava CRC-ove i podudaranje primarne i rezervne tabele, ali zaglavlje rezervne tabele može biti zastarelo nakon promene particija, pa pre oporavka proverite granice kandidata pomoću struktura sistema datoteka.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Sistemi datoteka

### Lista Windows sistema datoteka

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Sistem datoteka **FAT (File Allocation Table)** zasnovan je na svojoj osnovnoj komponenti, tabeli alokacije datoteka, koja se nalazi na početku volumena. Volume obično ima **dve kopije FAT-a**, mada BPB dozvoljava jednu. FAT12/16 smeštaju korenski direktorijum u fiksnu oblast; FAT32 čuva korenski direktorijum u oblasti podataka, u klasteru navedenom u `BPB_RootClus`.<sup>[[7]](#references)</sup>

Jedinica alokacije je **klaster**: `BPB_BytsPerSec × BPB_SecPerClus`, što ne mora biti 512 bajtova. Tip FAT-a određuje se brojem klastera podataka, a ne nizom verzije u sektoru za pokretanje. Granice broja klastera su:<sup>[[7]](#references)</sup>

- **FAT12**: manje od 4.085 klastera podataka.
- **FAT16**: od 4.085 do 65.524 klastera podataka.
- **FAT32**: najmanje 65.525 klastera podataka; za broj klastera koriste se samo 28 bitova svakog 32-bitnog FAT unosa.

32-bitno polje veličine datoteke ograničava običnu datoteku na **2³²−1 bajtova** (nešto manje od 4 GiB).<sup>[[7]](#references)</sup>

Ključne komponente korenskog direktorijuma, naročito kod FAT12 i FAT16, obuhvataju:

- **Naziv datoteke/fascikle** (do 8 znakova)
- **Atribute**
- **Datume kreiranja, izmene i poslednjeg pristupa**
- **Adresu FAT tabele** (koja označava početni klaster datoteke)
- **Veličinu datoteke**

### EXT

**Ext2** je najčešći sistem datoteka za particije **bez dnevnika** (**particije koje se ne menjaju mnogo**), poput particije za pokretanje. **Ext3/4** imaju **dnevnik** i obično se koriste za **preostale particije**.

## **Metapodaci**

Neke datoteke sadrže metapodatke. Ti podaci odnose se na sadržaj datoteke i ponekad mogu biti zanimljivi analitičaru jer, u zavisnosti od tipa datoteke, mogu sadržati informacije kao što su:

- Naslov
- Verzija MS Office-a
- Autor
- Datumi kreiranja i poslednje izmene
- Model kamere
- GPS koordinate
- Informacije o slici

Možete koristiti alate kao što su [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/) da biste dobili metapodatke datoteke.

## **Oporavak obrisanih datoteka**

### Evidentirane obrisane datoteke

Kao što je ranije pomenuto, postoji nekoliko mesta na kojima je datoteka i dalje sačuvana nakon što je „obrisana“. To je zato što brisanje datoteke iz sistema datoteka obično samo označi datoteku kao obrisanu, ali ne dira podatke. Zatim je moguće pregledati evidenciju datoteka (kao što je MFT) i pronaći obrisane datoteke.<sup>[[2]](#references)</sup>

Pored toga, OS obično čuva mnogo informacija o promenama sistema datoteka i rezervnim kopijama, pa je moguće pokušati da se one iskoriste za oporavak datoteke ili što većeg broja informacija.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** je tehnika kojom se pokušavaju **pronaći datoteke u velikoj količini podataka**. Postoje 3 glavna načina rada ovakvih alata: **na osnovu zaglavlja i završetaka tipova datoteka**, na osnovu **struktura** tipova datoteka i na osnovu samog **sadržaja**.

Jednostavan carving na osnovu zaglavlja/završetka pretpostavlja da su blokovi neprekinuti i može vratiti samo fragment ako je datoteka podeljena. To nije apsolutno ograničenje: PhotoRec ima opciju **Paranoid → bruteforce**, koja intenzivno koristi CPU za neke fragmentirane JPEG datoteke, dok ponovno sastavljanje fragmenata uz poznavanje formata može oporaviti i druge podržane tipove. Pogledajte [alate za file carving i oporavak](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) za aktuelni postupak ponovnog sastavljanja fragmenata.<sup>[[8]](#references)</sup>

Postoji nekoliko alata koje možete koristiti za File Carving, uz navođenje tipova datoteka koje želite da pretražite.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving je sličan File Carving-u, ali **umesto potrage za kompletnim datotekama, traži zanimljive fragmente informacija**.\
Na primer, umesto potrage za kompletnom datotekom koja sadrži evidentirane URL-ove, ova tehnika će tražiti URL-ove.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Bezbedno brisanje

Očigledno, postoje načini da se datoteke **„bezbedno“ obrišu, zajedno sa delom evidencije o njima**. Na primer, moguće je **nekoliko puta prepisati sadržaj** datoteke besmislenim podacima, a zatim **ukloniti** evidenciju o datoteci iz **$MFT** i **$LOGFILE** i **ukloniti Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Možda ćete primetiti da se i nakon toga **postojanje datoteke i dalje beleži na drugim mestima**. To je tačno, a deo posla forenzičkog stručnjaka jeste da ih pronađe.



## References

- [1] [GUID Partition Table - Vikipedija](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Kako skenirati NTFS $I30 (direktorijumske) unose u potrazi za dokazima o obrisanim datotekama](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Usluga Volume Shadow Copy (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [UEFI specifikacija: raspored GPT diska](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [Priručnik za The Sleuth Kit mmls](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [Priručnik za The Sleuth Kit fsstat](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Microsoft FAT specifikacija](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [PhotoRec opcije oporavka](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [Oporavak obrisanih particija pomoću TestDisk-a](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [Priručnik za sgdisk](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [Priručnik za mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
