# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

Το [**JTAGenum**](https://github.com/cyphunk/JTAGenum) είναι ένα εργαλείο που μπορείτε να φορτώσετε σε ένα Arduino-compatible MCU ή (πειραματικά) σε ένα Raspberry Pi, για brute-force άγνωστων JTAG pinouts και ακόμη και enumeration των instruction registers.

- Arduino: συνδέστε τα digital pins D2–D11 σε έως και 10 ύποπτα JTAG pads/testpoints και το Arduino GND στο GND του target. Τροφοδοτήστε το target ξεχωριστά, εκτός αν γνωρίζετε ότι το rail είναι ασφαλές. Προτιμήστε λογική 3.3 V (π.χ. Arduino Due) ή χρησιμοποιήστε level shifter/series resistors όταν κάνετε probing σε targets των 1.8–3.3 V.
- Raspberry Pi: το build για Pi εκθέτει λιγότερα χρήσιμα GPIOs (οπότε τα scans είναι πιο αργά). Ελέγξτε το repo για το τρέχον pin map και τους περιορισμούς.

Αφού γίνει το flash, ανοίξτε το serial monitor στα 115200 baud και στείλτε `h` για βοήθεια. Τυπική ροή:

- `l` εύρεση loopbacks για αποφυγή false positives
- `r` εναλλαγή των internal pull-ups, αν χρειάζεται
- `s` scan για TCK/TMS/TDI/TDO (και μερικές φορές TRST/SRST)
- `y` brute-force του IR για ανακάλυψη undocumented opcodes
- `x` boundary-scan snapshot των pin states

![JTAG - JTAGenum: x boundary-scan snapshot των pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scan snapshot των pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scan snapshot των pin states](<../../images/image (774).png>)



Αν βρεθεί έγκυρο TAP, θα δείτε γραμμές που ξεκινούν με `FOUND!` και υποδεικνύουν τα pins που ανακαλύφθηκαν.

Συμβουλές
- Να μοιράζεστε πάντα το ground και να μην οδηγείτε ποτέ άγνωστα pins πάνω από το target Vtref. Αν δεν είστε βέβαιοι, προσθέστε series resistors 100–470 Ω στα υποψήφια pins.
- Αν η συσκευή χρησιμοποιεί SWD/SWJ αντί για 4-wire JTAG, το JTAGenum ενδέχεται να μην το ανιχνεύσει. Δοκιμάστε SWD tools ή adapter που υποστηρίζει SWJ-DP.

## Ασφαλέστερο pin hunting και hardware setup

- Εντοπίστε πρώτα τα Vtref και GND με ένα multimeter. Πολλά adapters χρειάζονται Vtref για να ρυθμίσουν την I/O voltage.
- Level shifting: προτιμήστε bidirectional level shifters σχεδιασμένα για push-pull signals (οι γραμμές JTAG δεν είναι open-drain). Αποφύγετε auto-direction I2C shifters για JTAG.
- Χρήσιμα adapters: πλακέτες FT2232H/FT232H (π.χ. Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (σε ESP32-Sx). Συνδέστε τουλάχιστον TCK, TMS, TDI, TDO, GND και Vtref, και προαιρετικά TRST και SRST.

## Πρώτη επαφή με το OpenOCD (scan και IDCODE)

Το OpenOCD είναι το de-facto OSS για JTAG/SWD. Με ένα supported adapter μπορείτε να κάνετε scan στην chain και να διαβάσετε τα IDCODEs:<sup>[[1]](#references)</sup>

- Generic example με J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Ενσωματωμένο USB-JTAG στο ESP32‑S3 (δεν απαιτείται εξωτερικός probe):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Σημειώσεις
- Αν λάβετε IDCODE με "all ones/zeros", ελέγξτε την καλωδίωση, την τροφοδοσία, το Vtref και ότι η θύρα δεν είναι κλειδωμένη από fuses/option bytes.
- Δείτε το low-level `irscan`/`drscan` του OpenOCD για χειροκίνητη αλληλεπίδραση με το TAP κατά την αρχικοποίηση άγνωστων chains.<sup>[[1]](#references)</sup>

## Διακοπή της CPU και dumping μνήμης/flash

Μόλις αναγνωριστεί το TAP και επιλεγεί ένα target script, μπορείτε να διακόψετε τον core και να κάνετε dump περιοχών μνήμης ή internal flash. Παραδείγματα (προσαρμόστε το target, τις base addresses και τα μεγέθη):<sup>[[1]](#references)</sup>

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
Συμβουλές
- Χρησιμοποιήστε `mdw/mdh/mdb` για έναν γρήγορο έλεγχο της μνήμης πριν από μεγάλα dumps.
- Για αλυσίδες πολλών συσκευών, ορίστε BYPASS στις συσκευές που δεν αποτελούν στόχο ή χρησιμοποιήστε ένα board file που ορίζει όλα τα TAP.

## Κόλπα boundary-scan (EXTEST/SAMPLE)

Ακόμα και όταν η πρόσβαση για CPU debug είναι κλειδωμένη, το boundary-scan μπορεί να παραμένει εκτεθειμένο. Με UrJTAG/OpenOCD μπορείτε να:<sup>[[1]](#references)</sup>
- Χρησιμοποιήσετε SAMPLE για τη λήψη στιγμιότυπων των καταστάσεων των pin ενώ το σύστημα εκτελείται (εντοπισμός δραστηριότητας στο bus, επιβεβαίωση αντιστοίχισης των pin).
- Χρησιμοποιήσετε EXTEST για την οδήγηση των pin (π.χ. bit-bang των γραμμών εξωτερικού SPI flash μέσω του MCU, ώστε να το διαβάσετε εκτός σύνδεσης, εφόσον το wiring της πλακέτας το επιτρέπει).

Ελάχιστη ροή UrJTAG με adapter FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Χρειάζεστε το BSDL της συσκευής για να γνωρίζετε τη σειρά των bit του boundary register. Προσοχή: ορισμένοι vendors κλειδώνουν τα boundary-scan cells στην παραγωγή.

## Σύγχρονοι στόχοι και σημειώσεις

- Τα ESP32-S3/C3 περιλαμβάνουν native USB-JTAG bridge· το OpenOCD μπορεί να επικοινωνεί απευθείας μέσω USB χωρίς external probe. Πολύ χρήσιμο για triage και dumps.<sup>[[2]](#references)</sup>
- Το RISC-V debug (v0.13+) υποστηρίζεται ευρέως από το OpenOCD· προτιμήστε SBA για memory access όταν ο πυρήνας δεν μπορεί να γίνει halt με ασφάλεια.
- Πολλά MCUs υλοποιούν debug authentication και lifecycle states. Αν το JTAG φαίνεται νεκρό αλλά η τροφοδοσία είναι σωστή, η συσκευή μπορεί να είναι fused σε closed state ή να απαιτεί authenticated probe.

## Άμυνες και hardening (τι να περιμένετε σε πραγματικές συσκευές)

- Απενεργοποιήστε ή κλειδώστε μόνιμα το JTAG/SWD στην παραγωγή (π.χ. STM32 RDP level 2, ESP eFuses που απενεργοποιούν το PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Απαιτήστε authenticated debug (ARMv8.2-A ADIv6 Debug Authentication, OEM-managed challenge-response), διατηρώντας παράλληλα την πρόσβαση manufacturing.
- Μην δρομολογείτε εύκολα test pads· buried test vias, αφαιρέστε/τοποθετήστε resistors για να απομονώσετε το TAP και χρησιμοποιήστε connectors με keying ή pogo-pin fixtures.
- Power-on debug lock: τοποθετήστε το TAP πίσω από early ROM που επιβάλλει secure boot.

## Αναφορές

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
