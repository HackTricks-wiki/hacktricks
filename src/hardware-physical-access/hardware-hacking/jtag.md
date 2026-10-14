# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

Το **JTAGenum** είναι ένα εργαλείο που μπορείτε να φορτώσετε σε έναν MCU συμβατό με Arduino ή, πειραματικά, σε ένα Raspberry Pi, για να δοκιμάσετε με brute force άγνωστα pinout JTAG και να απαριθμήσετε καταχωρητές εντολών.<sup>[[3]](#references)</sup>

- Arduino: συνδέστε τις ψηφιακές ακίδες D2–D11 σε έως και 10 ύποπτα pads/testpoints JTAG και το GND του Arduino στο GND του στόχου. Τροφοδοτήστε τον στόχο ξεχωριστά, εκτός αν γνωρίζετε ότι η γραμμή τροφοδοσίας είναι ασφαλής. Προτιμήστε λογική 3.3 V (π.χ. Arduino Due) ή χρησιμοποιήστε level shifter/αντιστάσεις σε σειρά κατά τη δοκιμή στόχων 1.8–3.3 V.
- Raspberry Pi: η έκδοση για Pi διαθέτει λιγότερα αξιοποιήσιμα GPIO (οπότε οι σαρώσεις είναι πιο αργές)· ελέγξτε το repo για την τρέχουσα αντιστοίχιση ακίδων και τους περιορισμούς.

Μετά το flash, ανοίξτε το serial monitor στα 115200 baud και στείλτε `h` για βοήθεια. Συνήθης ροή:

- `l` εντοπισμός loopbacks για αποφυγή false positives
- `r` ενεργοποίηση/απενεργοποίηση των εσωτερικών pull-up, αν χρειάζεται
- `s` σάρωση για TCK/TMS/TDI/TDO (και μερικές φορές TRST/SRST)
- `y` brute force στο IR για εντοπισμό μη τεκμηριωμένων opcodes
- `x` στιγμιότυπο boundary-scan των καταστάσεων των ακίδων

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



Αν εντοπιστεί έγκυρο TAP, θα δείτε γραμμές που ξεκινούν με `FOUND!` και υποδεικνύουν τις ακίδες που εντοπίστηκαν.

### Συμβουλές ασφαλείας για το JTAGenum

- Συνδέετε πάντα τη γείωση και μην οδηγείτε ποτέ άγνωστες ακίδες σε τάση μεγαλύτερη από το Vtref του στόχου. Αν δεν είστε βέβαιοι, προσθέστε αντιστάσεις 100–470 Ω σε σειρά στις υποψήφιες ακίδες.
- Αν η συσκευή χρησιμοποιεί SWD/SWJ αντί για JTAG 4 καλωδίων, το JTAGenum ενδέχεται να μην το εντοπίσει· δοκιμάστε εργαλεία SWD ή έναν adapter που υποστηρίζει SWJ‑DP.

## Ασφαλέστερος εντοπισμός ακίδων και εγκατάσταση υλικού

- Εντοπίστε πρώτα τα Vtref και GND με ένα πολύμετρο. Πολλοί adapters χρειάζονται το Vtref για να ρυθμίσουν την τάση I/O.
- Μετατόπιση στάθμης: προτιμήστε αμφίδρομους level shifters σχεδιασμένους για push-pull σήματα (οι γραμμές JTAG δεν είναι open-drain). Αποφύγετε I2C shifters αυτόματης κατεύθυνσης για JTAG.
- Χρήσιμοι adapters: πλακέτες FT2232H/FT232H (π.χ., Tigard), CMSIS-DAP, J-Link, ST-LINK (ειδικές για τον κατασκευαστή), ESP-USB-JTAG (σε ESP32-Sx). Συνδέστε τουλάχιστον TCK, TMS, TDI, TDO, GND και Vtref· προαιρετικά TRST και SRST.

## Πρώτη επαφή με το OpenOCD (σάρωση και IDCODE)

Το OpenOCD είναι το de facto OSS για JTAG/SWD. Με έναν υποστηριζόμενο adapter, μπορείτε να σαρώσετε την αλυσίδα και να διαβάσετε IDCODEs:<sup>[[1]](#references)</sup>

- Γενικό παράδειγμα με J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- Ενσωματωμένο USB-JTAG του ESP32-S3 (δεν απαιτείται εξωτερικός ανιχνευτής):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Σημειώσεις

- Αν λάβετε IDCODE «all ones/zeros», ελέγξτε την καλωδίωση, την τροφοδοσία, το Vtref και αν η θύρα είναι κλειδωμένη από fuses/option bytes.
- Για χειροκίνητη αλληλεπίδραση με το TAP κατά την αρχική ρύθμιση άγνωστων chains, δείτε τα low-level `irscan`/`drscan` του OpenOCD.<sup>[[1]](#references)</sup>

## Διακοπή της CPU και dumping της μνήμης/flash

Μόλις αναγνωριστεί το TAP και επιλεγεί ένα script για τον target, μπορείτε να διακόψετε τον πυρήνα και να κάνετε dump περιοχών μνήμης ή της εσωτερικής flash. Παραδείγματα (προσαρμόστε τον target, τις διευθύνσεις βάσης και τα μεγέθη):<sup>[[1]](#references)</sup>

- Γενικός target μετά το init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (προτιμήστε το SBA όταν είναι διαθέσιμο):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, προγραμματισμός ή ανάγνωση μέσω του βοηθητικού εργαλείου OpenOCD:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Συμβουλές για Memory-Dumping

- Χρησιμοποιήστε `mdw/mdh/mdb` για να ελέγξετε γρήγορα τη μνήμη πριν από μεγάλα dumps.
- Για αλυσίδες πολλών συσκευών, ορίστε BYPASS στις μη στοχευόμενες συσκευές ή χρησιμοποιήστε ένα board file που ορίζει όλα τα TAPs.

## Τεχνάσματα Boundary-scan (EXTEST/SAMPLE)

Ακόμα κι όταν η πρόσβαση στο CPU debug είναι κλειδωμένη, το boundary-scan μπορεί να είναι εκτεθειμένο. Με UrJTAG/OpenOCD μπορείτε να κάνετε:<sup>[[1]](#references)</sup>
- SAMPLE για να καταγράψετε την κατάσταση των ακίδων ενώ το σύστημα λειτουργεί (εντοπίστε δραστηριότητα bus, επιβεβαιώστε την αντιστοίχιση ακίδων).
- EXTEST για να ελέγξετε ακίδες (π.χ. να κάνετε bit-bang τις γραμμές εξωτερικού SPI flash μέσω του MCU, ώστε να το διαβάσετε εκτός σύνδεσης, αν το επιτρέπει η καλωδίωση της πλακέτας).

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
Χρειάζεσαι το BSDL της συσκευής για να γνωρίζεις τη σειρά των bit του boundary register. Πρόσεχε: ορισμένοι κατασκευαστές κλειδώνουν τα boundary-scan cells κατά την παραγωγή.

## Σύγχρονοι στόχοι και σημειώσεις

- Τα ESP32‑S3/C3 περιλαμβάνουν εγγενή γέφυρα USB‑JTAG· το OpenOCD μπορεί να επικοινωνήσει απευθείας μέσω USB χωρίς εξωτερικό probe. Πολύ βολικό για αρχική αξιολόγηση και dumps.<sup>[[2]](#references)</sup>
- Το RISC‑V debug (v0.13+) υποστηρίζεται ευρέως από το OpenOCD· προτίμησε το SBA για πρόσβαση στη μνήμη όταν δεν είναι ασφαλές να τεθεί ο πυρήνας σε halt.
- Πολλά MCU υλοποιούν authentication για debug και καταστάσεις κύκλου ζωής. Αν το JTAG φαίνεται ανενεργό ενώ η τροφοδοσία είναι σωστή, η συσκευή μπορεί να έχει καεί σε κλειστή κατάσταση ή να απαιτεί authenticated probe.

## Άμυνες και ενίσχυση ασφάλειας (τι να περιμένεις σε πραγματικές συσκευές)

- Απενεργοποίησε ή κλείδωσε μόνιμα το JTAG/SWD στην παραγωγή (π.χ. STM32 RDP level 2, ESP eFuses που απενεργοποιούν το PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Απαίτησε authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response διαχειριζόμενο από τον OEM), διατηρώντας παράλληλα την πρόσβαση για την κατασκευή.
- Μην τοποθετείς εύκολα προσβάσιμα test pads· κάλυψε τα test vias, αφαίρεσε/τοποθέτησε αντιστάσεις για απομόνωση του TAP και χρησιμοποίησε connectors με κλειδί ή fixtures με pogo pins.
- Κλείδωμα debug κατά την ενεργοποίηση: βάλε το TAP πίσω από την early ROM που επιβάλλει το secure boot.

## References

- [1] [Οδηγός χρήσης του OpenOCD – Εντολές και διαμόρφωση JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Debugging JTAG στο Espressif ESP32‑S3 (USB‑JTAG, χρήση OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Σαρωτής pinout JTAG βασισμένος σε Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
