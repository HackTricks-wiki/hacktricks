# Partitions/File Systems/Carving

## Partitions

Ένας σκληρός δίσκος ή ένας **SSD disk μπορεί να περιέχει διαφορετικά partitions** με στόχο τον φυσικό διαχωρισμό των δεδομένων.\
Η **ελάχιστη** μονάδα ενός δίσκου είναι ο **τομέας (sector)** (συνήθως αποτελείται από 512B). Επομένως, το μέγεθος κάθε partition πρέπει να είναι πολλαπλάσιο αυτού του μεγέθους.

### MBR (master Boot Record)

Τοποθετείται στον **πρώτο τομέα του δίσκου, μετά τα 446B του boot code**. Αυτός ο τομέας είναι απαραίτητος για να υποδείξει στον υπολογιστή ποιο partition πρέπει να προσαρτηθεί και από πού.\
Επιτρέπει έως και **4 partitions** (το πολύ **μόνο 1** μπορεί να είναι active/**bootable**). Ωστόσο, αν χρειάζεστε περισσότερα partitions, μπορείτε να χρησιμοποιήσετε **extended partitions**. Το **τελικό byte** αυτού του πρώτου τομέα είναι η υπογραφή boot record **0x55AA**. Μόνο ένα partition μπορεί να επισημανθεί ως active.\
Το MBR επιτρέπει **μέγιστο μέγεθος 2.2TB**.

![Partitions - MBR (master Boot Record): Το MBR επιτρέπει μέγιστο μέγεθος 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): Το MBR επιτρέπει μέγιστο μέγεθος 2.2TB](<../../../images/image (304).png>)

Από τα **bytes 440 έως 443** του MBR μπορείτε να βρείτε το **Windows Disk Signature** (αν χρησιμοποιείται Windows). Το λογικό γράμμα μονάδας του σκληρού δίσκου εξαρτάται από το Windows Disk Signature. Η αλλαγή αυτής της υπογραφής μπορεί να εμποδίσει την εκκίνηση των Windows (εργαλείο: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): Από τα bytes 440 έως 443 του MBR μπορείτε να βρείτε το Windows Disk Signature (αν χρησιμοποιείται Windows). Το λογικό γράμμα μονάδας του σκληρού δίσκου...](<../../../images/image (310).png>)

**Μορφή**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Μορφή εγγραφής partition**

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

Για να προσαρτήσετε ένα MBR στο Linux, πρέπει πρώτα να βρείτε το start offset (μπορείτε να χρησιμοποιήσετε το `fdisk` και την εντολή `p`).

![Partitions - MBR (master Boot Record): Για να προσαρτήσετε ένα MBR στο Linux, πρέπει πρώτα να βρείτε το start offset (μπορείτε να χρησιμοποιήσετε το fdisk και την εντολή p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Στη συνέχεια, χρησιμοποιήστε τον ακόλουθο κώδικα
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

Το **Logical block addressing** (**LBA**) είναι ένα συνηθισμένο σχήμα που χρησιμοποιείται για τον **καθορισμό της τοποθεσίας blocks** δεδομένων που είναι αποθηκευμένα σε συσκευές αποθήκευσης υπολογιστών, γενικά σε συστήματα δευτερεύουσας αποθήκευσης, όπως οι hard disk drives. Το LBA είναι ένα ιδιαίτερα απλό γραμμικό σχήμα διευθυνσιοδότησης· **τα blocks εντοπίζονται με έναν ακέραιο δείκτη**, όπου το πρώτο block είναι το LBA 0, το δεύτερο το LBA 1 κ.ο.κ.

### GPT (GUID Partition Table)

Το GUID Partition Table, γνωστό ως GPT, προτιμάται για τις ενισχυμένες δυνατότητές του σε σύγκριση με το MBR (Master Boot Record). Χαρακτηριστικό του είναι το **globally unique identifier** για τα partitions, ενώ το GPT ξεχωρίζει με διάφορους τρόπους:

- **Τοποθεσία και μέγεθος**: Τόσο το GPT όσο και το MBR ξεκινούν από το **sector 0**. Ωστόσο, το GPT λειτουργεί σε **64bits**, σε αντίθεση με τα 32bits του MBR.
- **Όρια partitions**: Το GPT υποστηρίζει έως **128 partitions** σε συστήματα Windows και μπορεί να διαχειριστεί έως **9.4ZB** δεδομένων.
- **Ονόματα partitions**: Παρέχει τη δυνατότητα ονομασίας partitions με έως 36 Unicode χαρακτήρες.

**Ανθεκτικότητα και ανάκτηση δεδομένων**:

- **Πλεονασμός**: Σε αντίθεση με το MBR, το GPT δεν περιορίζει τα δεδομένα partitioning και boot σε ένα μόνο σημείο. Αντιγράφει αυτά τα δεδομένα σε ολόκληρο τον δίσκο, ενισχύοντας την ακεραιότητα και την ανθεκτικότητα των δεδομένων.
- **Cyclic Redundancy Check (CRC)**: Το GPT χρησιμοποιεί CRC για να διασφαλίσει την ακεραιότητα των δεδομένων. Παρακολουθεί ενεργά για καταστροφή δεδομένων και, όταν αυτή εντοπιστεί, το GPT προσπαθεί να ανακτήσει τα κατεστραμμένα δεδομένα από άλλη τοποθεσία του δίσκου.

**Protective MBR (LBA0)**:

- Το GPT διατηρεί backward compatibility μέσω ενός protective MBR. Αυτή η δυνατότητα βρίσκεται στον χώρο του legacy MBR, αλλά έχει σχεδιαστεί ώστε να αποτρέπει παλαιότερα utilities που βασίζονται σε MBR από το να αντικαταστήσουν κατά λάθος GPT disks, προστατεύοντας έτσι την ακεραιότητα των δεδομένων σε GPT-formatted disks.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Από τη Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Σε operating systems που υποστηρίζουν **GPT-based boot μέσω BIOS** services αντί για EFI, το πρώτο sector μπορεί επίσης να χρησιμοποιείται για την αποθήκευση του first stage του κώδικα του **bootloader**, αλλά **τροποποιημένου** ώστε να αναγνωρίζει **GPT** **partitions**. Το bootloader στο MBR δεν πρέπει να υποθέτει sector size 512 bytes.

**Partition table header (LBA 1)**

[Από τη Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Το partition table header καθορίζει τα χρησιμοποιήσιμα blocks στον δίσκο. Καθορίζει επίσης τον αριθμό και το μέγεθος των partition entries που αποτελούν το partition table (offsets 80 και 84 στον πίνακα).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h ή 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)σε little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) για UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size σε little endian (σε bytes, συνήθως 5Ch 00h 00h 00h ή 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) του header (offset +0 έως header size) σε little endian, με αυτό το field μηδενισμένο κατά τον υπολογισμό                             |
| 20 (0x14) | 4 bytes  | Reserved· πρέπει να είναι μηδέν                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (τοποθεσία αυτού του αντιγράφου του header)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (τοποθεσία του άλλου αντιγράφου του header)                                                                                                                               |
| 40 (0x28) | 8 bytes  | First usable LBA για partitions (τελευταίο LBA του primary partition table + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (πρώτο LBA του secondary partition table − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Disk GUID σε mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Starting LBA ενός array από partition entries (πάντα 2 στο primary copy)                                                                                                     |
| 80 (0x50) | 4 bytes  | Αριθμός partition entries στο array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Μέγεθος ενός partition entry (συνήθως 80h ή 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 του array των partition entries σε little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserved· πρέπει να είναι μηδενικά για το υπόλοιπο του block (420 bytes για sector size 512 bytes· μπορεί όμως να είναι περισσότερα με μεγαλύτερα sector sizes)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, συνήθως μονός)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (π.χ. το bit 60 δηλώνει read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Όνομα partition (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Όνομα partition (36 UTF-16LE code units)](<../../../images/image (83).png>)

Περισσότεροι τύποι partitions στο [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspecting

Αφού κάνετε mount το forensics image με το [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), μπορείτε να επιθεωρήσετε το πρώτο sector χρησιμοποιώντας το Windows tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Στην παρακάτω εικόνα εντοπίστηκε ένα **MBR** στο **sector 0** και έγινε interpret:

![GPT (GUID Partition Table) - Inspecting: Αφού κάνετε mount το forensics image με το ArsenalImageMounter , μπορείτε να επιθεωρήσετε το πρώτο sector χρησιμοποιώντας το Windows tool Active Disk Editor . Στην...](<../../../images/image (354).png>)

Αν υπήρχε **GPT table αντί για MBR**, θα έπρεπε να εμφανίζεται η signature _EFI PART_ στο **sector 1** (το οποίο στην προηγούμενη εικόνα είναι κενό).

## File-Systems

### Λίστα Windows file-systems

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Το **FAT (File Allocation Table)** file system είναι σχεδιασμένο γύρω από το βασικό του component, το file allocation table, το οποίο βρίσκεται στην αρχή του volume. Αυτό το σύστημα προστατεύει τα δεδομένα διατηρώντας **δύο αντίγραφα** του table, εξασφαλίζοντας την ακεραιότητα των δεδομένων ακόμη και αν ένα από αυτά καταστραφεί. Το table, μαζί με το root folder, πρέπει να βρίσκεται σε **σταθερή τοποθεσία**, κάτι κρίσιμο για τη διαδικασία εκκίνησης του συστήματος.

Η βασική μονάδα αποθήκευσης του file system είναι ένα **cluster, συνήθως 512B**, που αποτελείται από πολλά sectors. Το FAT έχει εξελιχθεί σε διάφορες εκδόσεις:

- **FAT12**, που υποστηρίζει 12-bit cluster addresses και διαχειρίζεται έως 4078 clusters (4084 με UNIX).
- **FAT16**, που αυξάνει τις addresses σε 16-bit και έτσι υποστηρίζει έως 65.517 clusters.
- **FAT32**, που προχωρά περαιτέρω με 32-bit addresses, επιτρέποντας εντυπωσιακά 268.435.456 clusters ανά volume.

Ένας σημαντικός περιορισμός σε όλες τις εκδόσεις FAT είναι το **μέγιστο μέγεθος αρχείου 4GB**, το οποίο επιβάλλεται από το 32-bit field που χρησιμοποιείται για την αποθήκευση του file size.

Τα βασικά components του root directory, ιδιαίτερα για FAT12 και FAT16, περιλαμβάνουν:

- **Όνομα αρχείου/folder** (έως 8 χαρακτήρες)
- **Attributes**
- **Ημερομηνίες δημιουργίας, τροποποίησης και τελευταίας πρόσβασης**
- **FAT Table Address** (υποδεικνύει το cluster εκκίνησης του αρχείου)
- **File Size**

### EXT

Το **Ext2** είναι το πιο συνηθισμένο file system για **partitions χωρίς journaling** (**partitions που δεν αλλάζουν πολύ**), όπως το boot partition. Τα **Ext3/4** έχουν **journaling** και συνήθως χρησιμοποιούνται για τα **υπόλοιπα partitions**.

## **Metadata**

Ορισμένα αρχεία περιέχουν metadata. Αυτές οι πληροφορίες αφορούν το περιεχόμενο του αρχείου και μερικές φορές μπορεί να είναι ενδιαφέρουσες για έναν analyst, καθώς ανάλογα με τον τύπο του αρχείου μπορεί να περιλαμβάνουν πληροφορίες όπως:

- Τίτλος
- Έκδοση MS Office που χρησιμοποιήθηκε
- Author
- Ημερομηνίες δημιουργίας και τελευταίας τροποποίησης
- Μοντέλο της κάμερας
- GPS coordinates
- Πληροφορίες εικόνας

Μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [**exiftool**](https://exiftool.org) και [**Metadiver**](https://www.easymetadata.com/metadiver-2/) για να λάβετε τα metadata ενός αρχείου.

## **Deleted Files Recovery**

### Logged Deleted Files

Όπως είδαμε προηγουμένως, υπάρχουν αρκετές τοποθεσίες όπου το αρχείο εξακολουθεί να είναι αποθηκευμένο μετά τη «διαγραφή» του. Αυτό συμβαίνει επειδή συνήθως η διαγραφή ενός αρχείου από ένα file system απλώς το επισημαίνει ως deleted, χωρίς να τροποποιούνται τα δεδομένα. Επομένως, είναι δυνατό να επιθεωρηθούν τα registries των αρχείων (όπως το MFT) και να εντοπιστούν τα deleted files.<sup>[[2]](#references)</sup>

Επίσης, το OS συνήθως αποθηκεύει πολλές πληροφορίες σχετικά με αλλαγές στο file system και backups, επομένως είναι δυνατό να προσπαθήσετε να τις χρησιμοποιήσετε για να ανακτήσετε το αρχείο ή όσο το δυνατόν περισσότερες πληροφορίες.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

Το **File carving** είναι μια τεχνική που προσπαθεί να **εντοπίσει αρχεία μέσα στον όγκο των δεδομένων**. Υπάρχουν 3 βασικοί τρόποι με τους οποίους λειτουργούν εργαλεία αυτού του τύπου: **με βάση τα headers και footers των file types**, με βάση τις **structures** των file types και με βάση το ίδιο το **content**.

Σημειώστε ότι αυτή η τεχνική **δεν λειτουργεί για την ανάκτηση fragmented files**. Αν ένα αρχείο **δεν είναι αποθηκευμένο σε contiguous sectors**, τότε αυτή η τεχνική δεν θα μπορέσει να το εντοπίσει ή τουλάχιστον να εντοπίσει ένα μέρος του.

Υπάρχουν διάφορα εργαλεία που μπορείτε να χρησιμοποιήσετε για File Carving, υποδεικνύοντας τους file types που θέλετε να αναζητήσετε


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Το Data Stream Carving είναι παρόμοιο με το File Carving, αλλά **αντί να αναζητά ολοκληρωμένα αρχεία, αναζητά ενδιαφέροντα fragments** πληροφοριών.\
Για παράδειγμα, αντί να αναζητά ένα ολοκληρωμένο αρχείο που περιέχει logged URLs, αυτή η τεχνική θα αναζητήσει URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Προφανώς, υπάρχουν τρόποι για **«secure» διαγραφή αρχείων και τμημάτων των logs που τα αφορούν**. Για παράδειγμα, είναι δυνατό να **αντικατασταθεί το content** ενός αρχείου με junk data αρκετές φορές και στη συνέχεια να **αφαιρεθούν** τα **logs** από τα **$MFT** και **$LOGFILE** σχετικά με το αρχείο, καθώς και να **αφαιρεθούν τα Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Μπορεί να παρατηρήσετε ότι ακόμη και μετά την εκτέλεση αυτής της ενέργειας ενδέχεται να υπάρχουν **άλλα σημεία όπου η ύπαρξη του αρχείου εξακολουθεί να καταγράφεται**, και αυτό είναι αλήθεια· μέρος της εργασίας ενός forensics professional είναι να τα εντοπίσει.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Πώς να σαρώσετε τις εγγραφές NTFS $I30 (directory) για στοιχεία deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Υπηρεσία Volume Shadow Copy (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
