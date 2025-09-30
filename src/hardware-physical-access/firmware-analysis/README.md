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


Firmware είναι το απαραίτητο λογισμικό που επιτρέπει στις συσκευές να λειτουργούν σωστά, διαχειριζόμενο και διευκολύνοντας την επικοινωνία μεταξύ των hardware components και του λογισμικού με το οποίο αλληλεπιδρούν οι χρήστες. Αποθηκεύεται σε μόνιμη μνήμη, εξασφαλίζοντας ότι η συσκευή μπορεί να προσπελάσει κρίσιμες οδηγίες από τη στιγμή που θα ενεργοποιηθεί, οδηγώντας στην εκκίνηση του λειτουργικού συστήματος. Η εξέταση και η πιθανή τροποποίηση του firmware είναι ένα κρίσιμο βήμα για τον εντοπισμό ευπαθειών ασφαλείας.

## **Συλλογή πληροφοριών**

**Συλλογή πληροφοριών** είναι ένα κρίσιμο αρχικό βήμα για την κατανόηση της σύνθεσης μιας συσκευής και των τεχνολογιών που χρησιμοποιεί. Αυτή η διαδικασία περιλαμβάνει τη συλλογή δεδομένων σχετικά με:

- Την CPU architecture και το λειτουργικό σύστημα που τρέχει
- Bootloader specifics
- Το hardware layout και datasheets
- Μετρικά κώδικα και τοποθεσίες του source
- Εξωτερικές βιβλιοθήκες και τύπους license
- Ιστορικά updates και πιστοποιήσεις κανονισμών
- Διαγράμματα αρχιτεκτονικής και ροής
- Αξιολογήσεις ασφαλείας και εντοπισμένες ευπάθειες

Για αυτόν τον σκοπό, εργαλεία **OSINT** είναι ανεκτίμητα, όπως και η ανάλυση οποιωνδήποτε διαθέσιμων open-source software components μέσω χειροκίνητης και αυτοματοποιημένης ανασκόπησης. Εργαλεία όπως [Coverity Scan](https://scan.coverity.com) και [Semmle’s LGTM](https://lgtm.com/#explore) προσφέρουν δωρεάν static analysis που μπορεί να αξιοποιηθεί για τον εντοπισμό πιθανών προβλημάτων.

## **Απόκτηση του Firmware**

Η απόκτηση του firmware μπορεί να προσεγγιστεί με διάφορους τρόπους, ο καθένας με το δικό του επίπεδο πολυπλοκότητας:

- **Άμεσα** από την πηγή (developers, manufacturers)
- **Χτίζοντάς** το από τις παρεχόμενες οδηγίες
- **Κατεβάζοντάς** το από επίσημους support sites
- Χρησιμοποιώντας **Google dork** queries για την εύρεση hosted firmware files
- Πρόσβαση σε **cloud storage** απευθείας, με εργαλεία όπως [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Παρεμπόδιση **updates** μέσω man-in-the-middle τεχνικών
- **Εξαγωγή** από τη συσκευή μέσω συνδέσεων όπως **UART**, **JTAG**, ή **PICit**
- **Sniffing** για update requests μέσα στην επικοινωνία της συσκευής
- Εντοπισμός και χρήση hardcoded update endpoints
- **Dumping** από τον bootloader ή το δίκτυο
- **Αφαίρεση και ανάγνωση** του storage chip, όταν όλα τα άλλα αποτύχουν, χρησιμοποιώντας κατάλληλα hardware εργαλεία

## Ανάλυση του firmware

Τώρα που **έχετε το firmware**, χρειάζεται να εξάγετε πληροφορίες γι' αυτό για να γνωρίζετε πώς να το χειριστείτε. Διάφορα εργαλεία που μπορείτε να χρησιμοποιήσετε για αυτό:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Getting the Filesystem

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Sometimes, binwalk will **not have the magic byte of the filesystem in its signatures**. In these cases, use binwalk to **find the offset of the filesystem and carve the compressed filesystem** from the binary and **manually extract** the filesystem according to its type using the steps below.
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
Εναλλακτικά, μπορεί να εκτελεστεί και η παρακάτω εντολή.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Για squashfs (χρησιμοποιήθηκε στο παραπάνω παράδειγμα)

`$ unsquashfs dir.squashfs`

Τα αρχεία θα βρίσκονται στον κατάλογο `squashfs-root` στη συνέχεια.

- Για αρχεία CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Για συστήματα αρχείων jffs2

`$ jefferson rootfsfile.jffs2`

- Για συστήματα αρχείων ubifs με NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ανάλυση Firmware

Μόλις αποκτηθεί το firmware, είναι απαραίτητο να το αναλύσουμε για να κατανοήσουμε τη δομή του και τις πιθανές ευπάθειες. Αυτή η διαδικασία περιλαμβάνει τη χρήση διαφόρων εργαλείων για να αναλύσουμε και να εξάγουμε πολύτιμα δεδομένα από το firmware image.

### Εργαλεία αρχικής ανάλυσης

Παρέχεται ένα σύνολο εντολών για την αρχική επιθεώρηση του δυαδικού αρχείου (αναφερόμενου ως `<bin>`). Οι εντολές αυτές βοηθούν στον εντοπισμό τύπων αρχείων, στην εξαγωγή strings, στην ανάλυση δυαδικών δεδομένων και στην κατανόηση των λεπτομερειών partition και filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Για να εκτιμηθεί η κατάσταση κρυπτογράφησης της εικόνας, ελέγχεται η **entropy** με `binwalk -E <bin>`. Χαμηλή entropy υποδηλώνει έλλειψη κρυπτογράφησης, ενώ υψηλή entropy υποδεικνύει πιθανή κρυπτογράφηση ή συμπίεση.

Για την εξαγωγή των **embedded files**, προτείνονται εργαλεία και πόροι όπως η τεκμηρίωση **file-data-carving-recovery-tools** και το **binvis.io** για επιθεώρηση αρχείων.

### Εξαγωγή του filesystem

Χρησιμοποιώντας `binwalk -ev <bin>`, συνήθως μπορεί κανείς να εξαγάγει το filesystem, συχνά σε έναν κατάλογο ονοματισμένο από τον τύπο του filesystem (π.χ. squashfs, ubifs). Ωστόσο, όταν το **binwalk** αποτύχει να αναγνωρίσει τον τύπο του filesystem λόγω έλλειψης magic bytes, απαιτείται χειροκίνητη εξαγωγή. Αυτό περιλαμβάνει τη χρήση του `binwalk` για τον εντοπισμό του filesystem offset, ακολουθούμενο από την εντολή `dd` για να carve out το filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Στη συνέχεια, ανάλογα με τον τύπο του filesystem (π.χ. squashfs, cpio, jffs2, ubifs), χρησιμοποιούνται διαφορετικές εντολές για χειροκίνητη εξαγωγή του περιεχομένου.

### Ανάλυση συστήματος αρχείων

Με το σύστημα αρχείων εξαγμένο, ξεκινά η αναζήτηση για ευπάθειες. Δίνεται προσοχή σε insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts και compiled binaries για offline analysis.

**Κύριες τοποθεσίες** και **αντικείμενα** προς έλεγχο περιλαμβάνουν:

- **etc/shadow** και **etc/passwd** για διαπιστευτήρια χρηστών
- Πιστοποιητικά SSL και κλειδιά στο **etc/ssl**
- Αρχεία ρυθμίσεων και script για πιθανές ευπάθειες
- Ενσωματωμένα binaries για περαιτέρω ανάλυση
- Συνήθεις web servers και binaries σε συσκευές IoT

Πολλά εργαλεία βοηθούν στον εντοπισμό ευαίσθητων πληροφοριών και ευπαθειών μέσα στο σύστημα αρχείων:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) και [**Firmwalker**](https://github.com/craigz28/firmwalker) για αναζήτηση ευαίσθητων πληροφοριών
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) για ολοκληρωμένη ανάλυση firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) και [**EMBA**](https://github.com/e-m-b-a/emba) για στατική και δυναμική ανάλυση

### Έλεγχοι ασφάλειας σε compiled binaries

Τόσο ο πηγαίος κώδικας όσο και τα compiled binaries που βρέθηκαν στο σύστημα αρχείων πρέπει να ελεγχθούν σχολαστικά για ευπάθειες. Εργαλεία όπως το **checksec.sh** για Unix binaries και το **PESecurity** για Windows binaries βοηθούν στον εντοπισμό μη προστατευμένων binaries που θα μπορούσαν να εκμεταλλευτούν επιτιθέμενοι.

## Εξομοίωση firmware για δυναμική ανάλυση

Η διαδικασία εξομοίωσης firmware επιτρέπει τη **dynamic analysis** είτε της λειτουργίας μιας συσκευής είτε ενός μεμονωμένου προγράμματος. Αυτή η προσέγγιση μπορεί να αντιμετωπίσει προβλήματα λόγω εξαρτήσεων από hardware ή αρχιτεκτονική, αλλά η μεταφορά του root filesystem ή συγκεκριμένων binaries σε μια συσκευή με συμβατή αρχιτεκτονική και endianness, όπως ένα Raspberry Pi, ή σε μια pre-built virtual machine, μπορεί να διευκολύνει περαιτέρω δοκιμές.

### Εξομοίωση μεμονωμένων binaries

Για την εξέταση μεμονωμένων προγραμμάτων, η αναγνώριση του endianness και της αρχιτεκτονικής CPU του προγράμματος είναι κρίσιμη.

#### Παράδειγμα με αρχιτεκτονική MIPS

Για να εξομοιωθεί ένα binary αρχιτεκτονικής MIPS, μπορεί να χρησιμοποιηθεί η εντολή:
```bash
file ./squashfs-root/bin/busybox
```
Και για να εγκαταστήσετε τα απαραίτητα εργαλεία εξομοίωσης:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Για MIPS (big-endian), το `qemu-mips` χρησιμοποιείται, ενώ για little-endian binaries, επιλογή είναι το `qemu-mipsel`.

#### Προσομοίωση αρχιτεκτονικής ARM

Για ARM binaries, η διαδικασία είναι παρόμοια, με τον emulator `qemu-arm` να χρησιμοποιείται για την προσομοίωση.

### Πλήρης προσομοίωση συστήματος

Εργαλεία όπως [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), και άλλα, διευκολύνουν την πλήρη προσομοίωση firmware, αυτοματοποιώντας τη διαδικασία και βοηθώντας στη δυναμική ανάλυση.

## Δυναμική ανάλυση στην πράξη

Σε αυτό το στάδιο, χρησιμοποιείται είτε πραγματικό είτε εξομοιωμένο περιβάλλον συσκευής για ανάλυση. Είναι κρίσιμο να διατηρείται πρόσβαση σε shell προς το OS και το filesystem. Η εξομοίωση μπορεί να μην μιμηθεί τέλεια τις αλληλεπιδράσεις με το hardware, γεγονός που απαιτεί περιστασιακές επανεκκινήσεις της εξομοίωσης. Η ανάλυση πρέπει να επανεξετάζει το filesystem, να εκμεταλλεύεται εκτεθειμένες ιστοσελίδες και network services, και να ερευνά ευπάθειες στον bootloader. Τα tests ακεραιότητας του firmware είναι κρίσιμα για τον εντοπισμό πιθανών backdoor ευπαθειών.

## Τεχνικές Runtime ανάλυσης

Η runtime ανάλυση περιλαμβάνει αλληλεπίδραση με μια διεργασία ή binary στο περιβάλλον εκτέλεσής του, χρησιμοποιώντας εργαλεία όπως gdb-multiarch, Frida, και Ghidra για την τοποθέτηση breakpoints και τον εντοπισμό ευπαθειών μέσω fuzzing και άλλων τεχνικών.

## Binary Exploitation and Proof-of-Concept

Η ανάπτυξη ενός PoC για εντοπισμένες ευπάθειες απαιτεί βαθιά κατανόηση της στόχου αρχιτεκτονικής και προγραμματισμό σε χαμηλού επιπέδου γλώσσες. Οι binary runtime protections σε embedded συστήματα είναι σπάνιες, αλλά όταν υπάρχουν, τεχνικές όπως Return Oriented Programming (ROP) μπορεί να είναι απαραίτητες.

## Προ-εγκατεστημένα λειτουργικά συστήματα για ανάλυση firmware

Λειτουργικά όπως [AttifyOS](https://github.com/adi0x90/attifyos) και [EmbedOS](https://github.com/scriptingxss/EmbedOS) παρέχουν προ-διαμορφωμένα περιβάλλοντα για testing ασφάλειας firmware, εξοπλισμένα με τα απαραίτητα εργαλεία.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): Το AttifyOS είναι ένα distro που στοχεύει να σας βοηθήσει να πραγματοποιήσετε security assessment και penetration testing των Internet of Things (IoT) συσκευών. Σας εξοικονομεί χρόνο παρέχοντας ένα προ-διαμορφωμένο περιβάλλον με όλα τα απαραίτητα εργαλεία.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system βασισμένο σε Ubuntu 18.04, προφορτωμένο με εργαλεία για firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Ακόμα και όταν ένας vendor εφαρμόζει cryptographic signature checks για εικόνες firmware, **version rollback (downgrade) protection is frequently omitted**. Όταν ο boot- ή recovery-loader επαληθεύει μόνο τη υπογραφή με ένα ενσωματωμένο public key αλλά δεν συγκρίνει την *version* (ή έναν monotonic counter) της εικόνας που θα φλασαριστεί, ένας επιτιθέμενος μπορεί νόμιμα να εγκαταστήσει ένα **παλαιότερο, ευάλωτο firmware που εξακολουθεί να φέρει έγκυρη υπογραφή** και έτσι να επανεισάγει ευπάθειες που είχαν επιδιορθωθεί.

Τυπική ροή επίθεσης:

1. **Obtain an older signed image**
* Λήψη από το δημόσιο portal λήψεων του προμηθευτή, CDN ή site υποστήριξης.
* Εξαγωγή από συνοδευτικές mobile/desktop εφαρμογές (π.χ. μέσα σε ένα Android APK κάτω από `assets/firmware/`).
* Ανάκτηση από third-party repositories όπως VirusTotal, Internet archives, forums, κ.λπ.
2. **Upload or serve the image to the device** μέσω οποιουδήποτε εκτεθειμένου update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, κ.λπ.
* Πολλές καταναλωτικές IoT συσκευές εκθέτουν *unauthenticated* HTTP(S) endpoints που δέχονται Base64-encoded firmware blobs, τα αποκωδικοποιούν server-side και ενεργοποιούν recovery/upgrade.
3. Μετά το downgrade, εκμετάλλευση μιας ευπάθειας που είχε επιδιορθωθεί στη νεότερη έκδοση (για παράδειγμα ένα command-injection filter που προστέθηκε αργότερα).
4. Προαιρετικά, φλάς ξανά την τελευταία εικόνα ή απενεργοποίηση των updates για να αποφευχθεί η ανίχνευση μόλις αποκτηθεί persistence.

### Παράδειγμα: Command Injection μετά από Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Στο ευάλωτο (downgraded) firmware, η παράμετρος `md5` συγχωνεύεται απευθείας σε μια εντολή shell χωρίς απολύμανση, επιτρέποντας injection αυθαίρετων εντολών (εδώ — ενεργοποίηση SSH key-based root access). Αργότερες εκδόσεις firmware εισήγαγαν ένα βασικό φίλτρο χαρακτήρων, αλλά η απουσία προστασίας downgrade καθιστά την επιδιόρθωση άσκοπη.

### Εξαγωγή Firmware από Εφαρμογές για Κινητά

Πολλοί κατασκευαστές συσκευάζουν πλήρεις εικόνες firmware μέσα στις συνοδευτικές εφαρμογές για κινητά, ώστε η εφαρμογή να μπορεί να ενημερώνει τη συσκευή μέσω Bluetooth/Wi-Fi. Αυτά τα πακέτα συνήθως αποθηκεύονται χωρίς κρυπτογράφηση στο APK/APEX κάτω από μονοπάτια όπως `assets/fw/` ή `res/raw/`. Εργαλεία όπως `apktool`, `ghidra` ή ακόμα και το απλό `unzip` σας επιτρέπουν να εξαγάγετε υπογεγραμμένες εικόνες χωρίς να αγγίξετε το φυσικό hardware.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Λίστα ελέγχου για την αξιολόγηση της λογικής ενημέρωσης

* Είναι η μεταφορά/αυθεντικοποίηση του *update endpoint* επαρκώς προστατευμένη (TLS + authentication);
* Συγκρίνει η συσκευή **version numbers** ή **monotonic anti-rollback counter** πριν το flashing;
* Επαληθεύεται η image μέσα σε secure boot chain (π.χ. signatures checked by ROM code);
* Εκτελεί το userland code επιπλέον ελέγχους ορθότητας (π.χ. allowed partition map, model number);
* Επαναχρησιμοποιούν οι ροές ενημέρωσης *partial* ή *backup* την ίδια λογική επαλήθευσης;

> 💡  Εάν οποιοδήποτε από τα παραπάνω λείπει, η πλατφόρμα πιθανότατα είναι ευάλωτη σε rollback attacks.

## Ευάλωτο firmware για εξάσκηση

Για εξάσκηση στην ανακάλυψη ευπαθειών σε firmware, χρησιμοποιήστε τα παρακάτω vulnerable firmware projects ως σημείο εκκίνησης.

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

## Εκπαίδευση και Πιστοποιήσεις

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
