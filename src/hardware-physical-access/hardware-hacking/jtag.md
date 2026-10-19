# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## Ασφαλέστερος εντοπισμός pin και ρύθμιση υλικού

- Εντοπίστε πρώτα τα Vtref και GND με πολύμετρο. Πολλοί adapters χρειάζονται το Vtref για να ρυθμίσουν την τάση I/O.
- Level shifting: προτιμήστε bidirectional level shifters σχεδιασμένους για push-pull σήματα (οι γραμμές JTAG δεν είναι open-drain). Αποφύγετε τα auto-direction I2C shifters για JTAG.
- Χρήσιμοι adapters: πλακέτες FT2232H/FT232H (π.χ. Tigard), CMSIS-DAP, J-Link, ST-LINK (ειδικά για κάθε vendor), ESP-USB-JTAG (σε ESP32-Sx). Συνδέστε τουλάχιστον τα TCK, TMS, TDI, TDO, GND και Vtref· προαιρετικά τα TRST και SRST.

Για μια κεφαλίδα χωρίς τεκμηρίωση, εντοπίστε το GND ελέγχοντας τη συνέχεια προς ένα γνωστό επίπεδο γείωσης **ενώ ο στόχος δεν τροφοδοτείται**. Αφού μεταβείτε σε λειτουργία μέτρησης τάσης και τροφοδοτήσετε τη συσκευή, μην ταξινομείτε κάθε pin με υψηλή τάση ως Vtref: οι ψηφιακές είσοδοι υψηλής στάθμης μπορεί να μοιάζουν με αυτό στο πολύμετρο. Ακολουθήστε τις υποψήφιες γραμμές τροφοδοσίας μέχρι κοντινούς πυκνωτές αποσύζευξης και συγκρίνετε τις κυματομορφές τους κατά την ενεργοποίηση και απενεργοποίηση με παλμογράφο. Μια πιο αργή άνοδος ή πτώση σε σχήμα πυκνωτή αποτελεί ένδειξη γραμμής τροφοδοσίας/αναφοράς, αλλά επαληθεύστε την τάση και την καλωδίωση προτού συνδέσετε probe με level shifting. Στο PiFex, μπορείτε να επιλέξετε εξωτερική αναφορά χαμηλότερης τάσης για τον στόχο μέσω του `VCCA_IN`, αντί για την προεπιλεγμένη ρύθμιση 3.3 V.<sup>[[4]](#references)</sup>

## JTAGenum

Το **JTAGenum** είναι ένα εργαλείο που μπορείτε να φορτώσετε σε MCU συμβατό με Arduino ή, πειραματικά, σε Raspberry Pi, για να δοκιμάσετε με brute force άγνωστες διατάξεις pin JTAG και να απαριθμήσετε instruction registers.<sup>[[3]](#references)</sup>

- Arduino: συνδέστε τα ψηφιακά pin D2–D11 σε έως και 10 ύποπτα JTAG pads/testpoints και το Arduino GND στο GND του στόχου. Τροφοδοτήστε τον στόχο ξεχωριστά, εκτός αν γνωρίζετε ότι η γραμμή τροφοδοσίας είναι ασφαλής. Προτιμήστε λογική 3.3 V (π.χ. Arduino Due) ή χρησιμοποιήστε level shifter/αντιστάσεις σε σειρά κατά τη διερεύνηση στόχων 1.8–3.3 V.
- Raspberry Pi: το build για Pi διαθέτει λιγότερα αξιοποιήσιμα GPIO (οπότε οι σαρώσεις είναι πιο αργές)· ελέγξτε το repo για την τρέχουσα αντιστοίχιση pin και τους περιορισμούς.

Αφού γίνει flash, ανοίξτε το serial monitor στα 115200 baud και στείλτε `h` για βοήθεια. Συνήθης ροή:

- `l` εντοπισμός loopbacks για αποφυγή false positives
- `r` εναλλαγή των εσωτερικών pull-ups, αν χρειάζεται
- `s` σάρωση για TCK/TMS/TDI/TDO (και μερικές φορές TRST/SRST)
- `y` brute-force στο IR για εντοπισμό μη τεκμηριωμένων opcodes
- `x` στιγμιότυπο boundary-scan των καταστάσεων των pin

![JTAG - JTAGenum: x στιγμιότυπο boundary-scan των καταστάσεων των pin](<../../images/image (939).png>)

![JTAG - JTAGenum: x στιγμιότυπο boundary-scan των καταστάσεων των pin](<../../images/image (578).png>)

![JTAG - JTAGenum: x στιγμιότυπο boundary-scan των καταστάσεων των pin](<../../images/image (774).png>)



Αν εντοπιστεί έγκυρο TAP, θα δείτε γραμμές που αρχίζουν με `FOUND!` και υποδεικνύουν τα pin που ανακαλύφθηκαν.

### Συμβουλές ασφάλειας για το JTAGenum

- Συνδέετε πάντα τις γειώσεις μεταξύ τους και μην οδηγείτε ποτέ άγνωστα pin με τάση υψηλότερη από το Vtref του στόχου. Αν δεν είστε βέβαιοι, προσθέστε αντιστάσεις 100–470 Ω σε σειρά στα υποψήφια pin.
- Αν η συσκευή χρησιμοποιεί SWD/SWJ αντί για JTAG 4 καλωδίων, το JTAGenum μπορεί να μην το εντοπίσει· δοκιμάστε εργαλεία SWD ή adapter που υποστηρίζει SWJ-DP.

## Εντοπισμός GPIO pin με το go-jtagenum

Σε έναν τροφοδοτούμενο στόχο με επαληθευμένη κοινή γείωση και συμβατή τάση I/O, το `go-jtagenum` μπορεί να απαριθμήσει υποψήφια σήματα JTAG από τα GPIO του Raspberry Pi. Το JSON `-pins` αντιστοιχίζει ετικέτες σε **αριθμούς GPIO**, όχι σε φυσικές θέσεις της κεφαλίδας.<sup>[[5]](#references)</sup> Στο παράδειγμα SSD, η πρώτη σάρωση IDCODE ανέφερε επίσης μια απίθανα μεγάλη αλυσίδα μεταβαλλόμενων τιμών: μια γραμμή TDO που μεταβάλλεται από μόνη της δεν αποδεικνύει ότι υπάρχει έγκυρο TAP. Επαληθεύστε ξανά ένα εύλογο αποτέλεσμα με σάρωση BYPASS, η οποία μετατοπίζει ένα γνωστό μοτίβο bit από το TDI μέσω του καταχωρητή bypass ενός bit προς το TDO.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

Για αυτή την πλακέτα, το BYPASS επιβεβαίωσε τα `TCK=10`, `TMS=14`, `TDI=9` και `TDO=15`· οι επιπλέον ακροδέκτες ήταν μόνο **πιθανοί** υποψήφιοι για nTRST. Αν ένας υποψήφιος επιστρέφει μόνο μηδενικά ή ασυνεπές μοτίβο, ελέγξτε την επαφή, την τροφοδοσία του στόχου, τις pull-up αντιστάσεις και τις καθυστερήσεις ρολογιού/επαναφοράς προτού του αντιστοιχίσετε κάποιο σήμα.<sup>[[4]](#references)[[5]](#references)</sup> Το εργαλείο δέχεται επίσης το `-known-pins` με το `test_bypass`, για να επανελέγξετε μια ανακτημένη αντιστοίχιση ακροδεκτών.<sup>[[5]](#references)</sup>

## Χαρακτηρισμός ενός μη τεκμηριωμένου TAP με το UrJTAG

Ένα pinout που εντοπίστηκε δεν προσδιορίζει τους κωδικούς opcode του instruction register (IR) ή τα πλάτη του data register (DR) που απαιτούνται για τον εντοπισμό σφαλμάτων. Με μια έκδοση του UrJTAG που υποστηρίζει το καλώδιο GPIO του Raspberry Pi, ορίστε την ανακτημένη αντιστοίχιση και εκτελέστε `idcode`, έπειτα `detect` και στη συνέχεια `discover`. Το παράδειγμα SSD επέστρεψε ένα TAP, ένα IR τεσσάρων bit και διαφορετικά πλάτη DR για διαφορετικές τιμές IR. Μήκος DR `-1` ή το μήνυμα “TDO stuck at 0” δεν αποτελεί αξιοποιήσιμο ορισμό καταχωρητή· ελέγξτε τον χρονισμό, την καλωδίωση και την επιλεγμένη εντολή, αντί να του αποδώσετε κάποιο πλάτος.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

Αυτή είναι αναγνώριση TAP, όχι αυτόματη αναγνώριση CPU: συγκρίνετε το IDCODE που προκύπτει με την τεκμηρίωση της συσκευής και τους υποστηριζόμενους στόχους του OpenOCD. Η τοπική βάση δεδομένων κατασκευαστών του UrJTAG ενδέχεται να χαρακτηρίσει ως άγνωστο ένα κατά τα άλλα έγκυρο ID.<sup>[[4]](#references)</sup>

## Πρώτη επαφή με το OpenOCD (σάρωση και IDCODE)

Το OpenOCD είναι το de facto OSS για JTAG/SWD. Με έναν υποστηριζόμενο adapter, μπορείτε να σαρώσετε την αλυσίδα και να διαβάσετε τα IDCODE:<sup>[[1]](#references)</sup>

- Γενικό παράδειγμα με J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- Ενσωματωμένο USB-JTAG του ESP32-S3 (δεν απαιτείται εξωτερικό probe):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Σημειώσεις

- Αν λάβετε IDCODE με «όλα 1/0», ελέγξτε την καλωδίωση, την τροφοδοσία, το Vtref και αν η θύρα είναι κλειδωμένη από fuses/option bytes.
- Δείτε τις εντολές χαμηλού επιπέδου `irscan`/`drscan` του OpenOCD για χειροκίνητη αλληλεπίδραση με το TAP κατά την αρχική ρύθμιση άγνωστων αλυσίδων.<sup>[[1]](#references)</sup>

## Προσθήκη μη τεκμηριωμένου target στο OpenOCD

Μόλις γνωρίζετε το TAP ID και το μήκος IR, εξετάστε τα scripts `cpu/`, `target/` και `board/` του OpenOCD για **αντίστοιχη αρχιτεκτονική CPU** και, στη συνέχεια, δημιουργήστε ξεχωριστές ρυθμίσεις adapter και target.<sup>[[4]](#references)[[6]](#references)</sup> Η παρακάτω αντιστοίχιση Pi GPIO και το target ARCv2 είναι το δοκιμασμένο παράδειγμα SSD, όχι μια καθολική ρύθμιση JTAG. Η επιλογή target ARC και οι ρυθμίσεις debug ήταν υποθέσεις που πέτυχαν σε αυτήν τη συσκευή· σε άλλη πλακέτα, χρησιμοποιήστε το μετρημένο ID, το μήκος IR, την αρχιτεκτονική και τους αριθμούς GPIO του target.<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

Εκτελέστε `openocd -f raspberrypi-io.cfg -f target.cfg` και επιβεβαιώστε ότι η εξέταση του TAP ολοκληρώνεται με επιτυχία πριν διαβάσετε τη μνήμη. Το παράδειγμα άνοιξε Telnet στη θύρα `4444` και έναν GDB server στη θύρα `3333`. Η αναγνώριση ενός IDCODE από μόνη της δεν αποδεικνύει ότι το επιλεγμένο CPU target μπορεί να εξεταστεί ή να γίνει debug.<sup>[[4]](#references)</sup> Τα GPIO του Raspberry Pi δεν είναι απαραίτητο να είναι οι ακροδέκτες με την ένδειξη JTAG σε μια breakout board, όταν ο adapter επιτρέπει την αντιστοίχιση με `adapter gpio`.<sup>[[4]](#references)[[6]](#references)</sup>

## Διακοπή της CPU και αποθήκευση dump μνήμης/flash

Μόλις αναγνωριστεί το TAP και επιλεγεί ένα target script, μπορείτε να διακόψετε τον πυρήνα και να αποθηκεύσετε dump περιοχών μνήμης ή εσωτερικής flash. Παραδείγματα (προσαρμόστε το target, τις διευθύνσεις βάσης και τα μεγέθη):<sup>[[1]](#references)</sup>

- Generic target μετά το init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (προτιμήστε το SBA όταν είναι διαθέσιμο):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, προγραμματισμός ή ανάγνωση μέσω βοηθητικού εργαλείου OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Συμβουλές για memory dumping

- Χρησιμοποιήστε `mdw/mdh/mdb` για έναν γρήγορο έλεγχο της μνήμης πριν από μεγάλα dumps.
- Για αλυσίδες πολλών συσκευών, ορίστε BYPASS στις συσκευές που δεν σας ενδιαφέρουν ή χρησιμοποιήστε ένα αρχείο board που ορίζει όλα τα TAP.

Για έναν μη τεκμηριωμένο χάρτη μνήμης, η έρευνα για SSD έλεγξε ένα dump 1 MiB για αναγνωρίσιμα strings του controller και στη συνέχεια χρησιμοποίησε ένα GDB με υποστήριξη της αρχιτεκτονικής μέσω OpenOCD, για να επιθεωρήσει τα `$pc`, disassembly και registers. Αυτές οι ενεργές διευθύνσεις καθοδήγησαν ένα δεύτερο dump περιοχής, το οποίο ελέγχθηκε σε σύγκριση με αντίστοιχες εντολές σε έκδοση του Ghidra με υποστήριξη ARC. Τα strings από μόνα τους είναι μόνο ένας έλεγχος ευλογοφάνειας, όχι απόδειξη ότι το image είναι πλήρες ή έχει αντιστοιχιστεί σωστά στη μνήμη.<sup>[[4]](#references)</sup> Δείτε την [ανάλυση firmware](../firmware-analysis/) για ευρύτερα βήματα static analysis.

## Τεχνάσματα boundary-scan (EXTEST/SAMPLE)

Ακόμα κι όταν η πρόσβαση στο CPU debug είναι κλειδωμένη, το boundary-scan μπορεί να παραμένει διαθέσιμο. Με UrJTAG/OpenOCD μπορείτε να:<sup>[[1]](#references)</sup>
- Χρησιμοποιήσετε SAMPLE για να καταγράψετε την κατάσταση των ακίδων ενώ το σύστημα λειτουργεί (εντοπισμός δραστηριότητας bus, επιβεβαίωση αντιστοίχισης ακίδων).
- Χρησιμοποιήσετε EXTEST για να οδηγήσετε ακίδες (π.χ., να κάνετε bit-bang τις γραμμές εξωτερικού SPI flash μέσω του MCU, ώστε να το διαβάσετε offline, αν το επιτρέπει η καλωδίωση της πλακέτας).

Ελάχιστη ροή UrJTAG με προσαρμογέα FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Χρειάζεστε το BSDL της συσκευής για να γνωρίζετε τη σειρά των bit στο boundary register. Προσοχή: ορισμένοι κατασκευαστές κλειδώνουν τα boundary-scan cells κατά την παραγωγή.

## Σύγχρονοι στόχοι και σημειώσεις

- Τα ESP32‑S3/C3 περιλαμβάνουν εγγενή γέφυρα USB‑JTAG· το OpenOCD μπορεί να επικοινωνεί απευθείας μέσω USB, χωρίς εξωτερικό probe. Πολύ βολικό για triage και dumps.<sup>[[2]](#references)</sup>
- Το RISC‑V debug (v0.13+) υποστηρίζεται ευρέως από το OpenOCD· προτιμήστε το SBA για πρόσβαση στη μνήμη, όταν ο πυρήνας δεν μπορεί να τεθεί με ασφάλεια σε halt.
- Πολλά MCU υλοποιούν authentication για το debug και καταστάσεις lifecycle. Αν το JTAG φαίνεται ανενεργό ενώ η τροφοδοσία είναι σωστή, η συσκευή μπορεί να έχει καεί σε κλειστή κατάσταση ή να απαιτεί authenticated probe.

## Άμυνες και ενίσχυση ασφάλειας (τι να περιμένετε σε πραγματικές συσκευές)

- Απενεργοποιήστε ή κλειδώστε μόνιμα το JTAG/SWD στην παραγωγή (π.χ., STM32 RDP level 2, ESP eFuses που απενεργοποιούν το PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Απαιτήστε authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response διαχειριζόμενο από τον OEM), διατηρώντας παράλληλα την πρόσβαση για την κατασκευή.
- Μην οδηγείτε εύκολα προσβάσιμα test pads· θάψτε τα test vias, αφαιρέστε/τοποθετήστε αντιστάσεις για να απομονώσετε το TAP και χρησιμοποιήστε connectors με κλειδί ή fixtures με pogo pins.
- Κλείδωμα debug κατά την ενεργοποίηση: απομονώστε το TAP πίσω από την early ROM, η οποία επιβάλλει secure boot.

## References

- [1] [Οδηγός χρήσης του OpenOCD – Εντολές JTAG και ρύθμιση](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, χρήση του OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – σαρωτής pinout JTAG βασισμένος σε Arduino](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — JTAG Hacking με Raspberry Pi](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — απαρίθμηση GPIO JTAG](https://github.com/gremwell/go-jtagenum)
- [6] [Οδηγός χρήσης του OpenOCD — ρύθμιση Debug Adapter](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
