# UART

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το UART είναι μια ασύγχρονη σειριακή διεπαφή που μεταφέρει μια πλαισιωμένη ροή bits χωρίς κοινό clock. Μην συγχέετε το UART επιπέδου λογικής με το RS-232: το RS-232 χρησιμοποιεί διαφορετικά, συχνά αρνητικά, επίπεδα τάσης και απαιτεί transceiver.<sup>[[1]](#references)[[3]](#references)</sup>

Γενικά, η γραμμή διατηρείται σε υψηλό επίπεδο (λογική τιμή 1) όταν το UART βρίσκεται σε κατάσταση αδράνειας. Στη συνέχεια, για να σηματοδοτήσει την έναρξη μιας μεταφοράς δεδομένων, ο transmitter στέλνει ένα start bit στον receiver, κατά τη διάρκεια του οποίου το σήμα διατηρείται σε χαμηλό επίπεδο (λογική τιμή 0). Έπειτα, ο transmitter στέλνει πέντε έως οκτώ data bits που περιέχουν το πραγματικό μήνυμα, ακολουθούμενα από ένα προαιρετικό parity bit και ένα ή δύο stop bits (με λογική τιμή 1), ανάλογα με τη διαμόρφωση. Το parity bit, που χρησιμοποιείται για τον έλεγχο σφαλμάτων, σπάνια συναντάται στην πράξη. Το stop bit (ή τα stop bits) σηματοδοτεί το τέλος της μετάδοσης.

Η πιο συνηθισμένη διαμόρφωση είναι η 8N1: οκτώ data bits, χωρίς parity και ένα stop bit. Το UART στέλνει πρώτα το least-significant data bit, επομένως το ASCII `C` (`0x43`) μεταδίδεται ως εξής: start `0`; data `1, 1, 0, 0, 0, 0, 1, 0`; stop `1`.<sup>[[1]](#references)</sup>

![UART: Η πιο συνηθισμένη διαμόρφωση ονομάζεται 8N1: οκτώ data bits, χωρίς parity και ένα stop bit. Για παράδειγμα, αν θέλαμε να στείλουμε τον χαρακτήρα C, ή 0x43 σε ASCII, σε ένα 8N1 UART](<../../images/image (764).png>)

Hardware εργαλεία για επικοινωνία με UART:

- USB-to-serial adapter
- Adapters με τα chips CP2102 ή PL2303
- Multipurpose εργαλείο όπως: Bus Pirate, το Adafruit FT232H, το Shikra ή το Attify Badge

### Εντοπισμός θυρών UART

Ένα τυπικό debug header διαθέτει **TX**, **RX** και **GND**. Μπορεί επίσης να διαθέτει pin **Vcc/Vref**, reset ή pins ελέγχου ροής. Το Vcc δεν είναι σήμα UART και κανονικά πρέπει να χρησιμοποιείται μόνο ως αναφορά τάσης — όχι να συνδέεται ως πηγή τροφοδοσίας — εκτός αν είναι γνωστό το schematic της πλακέτας και οι απαιτήσεις ρεύματος.<sup>[[2]](#references)[[3]](#references)</sup>

Ξεκινήστε με τη συσκευή **απενεργοποιημένη** και αποσυνδεδεμένη:

- Εντοπίστε το **GND** σε λειτουργία continuity, χρησιμοποιώντας ως αναφορά ένα γνωστό ground plane, το shield ενός connector ή το ground της τροφοδοσίας. Μην χρησιμοποιείτε ποτέ τη λειτουργία continuity/resistance σε πλακέτα που τροφοδοτείται.
- Μεταβείτε στη λειτουργία μέτρησης τάσης DC πριν τροφοδοτήσετε το target. Μετρήστε τα υποψήφια pins ως προς το ground, για να εντοπίσετε την τάση λογικής. Μια σταθερή γραμμή τροφοδοσίας μπορεί να είναι Vcc/Vref. Μην υποθέσετε ότι είναι ασφαλές να τη συνδέσετε.
- Παρατηρήστε τα υποψήφια pins με logic analyzer ή oscilloscope κατά την εκκίνηση. Το **TX** συνήθως βρίσκεται σε υψηλό επίπεδο όταν είναι σε αδράνεια και εμφανίζει bursts πλαισιωμένων δεδομένων. Ένα multimeter μπορεί να εμφανίσει μια μέση μεταβολή, αλλά δεν μπορεί να επιβεβαιώσει το framing ή το baud rate.
- Το **RX** μπορεί να παραμένει σε αδράνεια και δεν μπορεί να εντοπιστεί με ασφάλεια απλώς επειδή βρίσκεται δίπλα στο TX. Trace το PCB, συμβουλευτείτε το datasheet του SoC ή χρησιμοποιήστε analyzer υψηλής αντίστασης πριν το οδηγήσετε.

Η εναλλαγή των TX και RX συνήθως δεν επιτρέπει την επικοινωνία. Η σύγχυση μεταξύ τροφοδοσίας, ground ή επιπέδων σήματος μπορεί να προκαλέσει μόνιμη βλάβη στο target ή στον adapter. Συνδέστε πρώτα το ground και ξεκινήστε σε λειτουργία **receive-only** (target TX προς adapter RX).

Οι κατασκευαστές μπορεί να παραλείψουν το header, να αφήσουν μη τοποθετημένες τις series resistors, να απενεργοποιήσουν την κονσόλα στο firmware ή να εκθέσουν μόνο το TX. Trace τα κοντινά test pads και τα resistor footprints προς το SoC και προσθέστε προσωρινή σύνδεση υψηλής αντίστασης μόνο αφού επιβεβαιώσετε το ηλεκτρικό επίπεδο. Η ύπαρξη εγγύησης δεν σημαίνει ότι πρέπει να υπάρχει προσβάσιμο UART.

### Εντοπισμός του UART Baud Rate

Ο ευκολότερος τρόπος για να εντοπίσετε το σωστό baud rate είναι να εξετάσετε την έξοδο του **TX pin** και να προσπαθήσετε να διαβάσετε τα δεδομένα. Αν τα δεδομένα που λαμβάνετε δεν είναι αναγνώσιμα, μεταβείτε στο επόμενο πιθανό baud rate μέχρι τα δεδομένα να γίνουν αναγνώσιμα. Μπορείτε να χρησιμοποιήσετε έναν USB-to-serial adapter ή μια multipurpose συσκευή όπως το Bus Pirate, σε συνδυασμό με ένα helper script, όπως το [baudrate.py](https://github.com/devttys0/baudrate/). Τα πιο συνηθισμένα baud rates είναι τα 9600, 38400, 19200, 57600 και 115200.

> [!CAUTION]
> Είναι σημαντικό να σημειωθεί ότι σε αυτό το protocol πρέπει να συνδέσετε το TX της μίας συσκευής στο RX της άλλης!

## CP210X UART προς TTY Adapter

Τα CP210x USB-to-UART bridges εμφανίζονται σε πολλές πλακέτες prototyping και οικονομικούς adapters. Τα συνηθισμένα modules εκθέτουν pins τροφοδοσίας μαζί με τα GND, RXD και TXD, αλλά τα headers και τα επίπεδα I/O διαφέρουν. Επιβεβαιώστε την πραγματική τάση από το design της πλακέτας ή το data sheet. Συνήθως συνδέετε μόνο το GND, το adapter RX στο target TX και — αφού επιβεβαιώσετε τη λήψη σε receive-only — το adapter TX στο target RX. Μην συνδέετε το pin τροφοδοσίας 5 V/3.3 V του adapter, εκτός αν τροφοδοτείτε σκόπιμα ένα target που είναι γνωστό ότι το ανέχεται.<sup>[[3]](#references)</sup>

Σε περίπτωση που ο adapter δεν ανιχνεύεται, βεβαιωθείτε ότι οι CP210X drivers είναι εγκατεστημένοι στο host system. Μόλις ο adapter ανιχνευθεί και συνδεθεί, μπορούν να χρησιμοποιηθούν εργαλεία όπως τα picocom, minicom ή screen.

Για να εμφανίσετε τις συσκευές που είναι συνδεδεμένες σε Linux/MacOS συστήματα:
```
ls /dev/
```
Για βασική αλληλεπίδραση με το UART interface, χρησιμοποιήστε την ακόλουθη εντολή:
```
picocom /dev/<adapter> --baud <baudrate>
```
Για το minicom, χρησιμοποιήστε την ακόλουθη εντολή για να το ρυθμίσετε:
```
minicom -s
```
Διαμορφώστε τις ρυθμίσεις, όπως το baudrate και το όνομα της συσκευής, στην επιλογή `Serial port setup`.

Μετά τη διαμόρφωση, εκτελέστε το `minicom` για να ανοίξετε την κονσόλα UART.

## UART Μέσω Arduino UNO R3 (Πλακέτες με Αφαιρούμενο Chip Atmel 328p)

Σε περίπτωση που δεν υπάρχουν διαθέσιμοι UART Serial to USB adapters, το Arduino UNO R3 μπορεί να χρησιμοποιηθεί με ένα γρήγορο hack. Επειδή το Arduino UNO R3 είναι συνήθως διαθέσιμο παντού, αυτό μπορεί να εξοικονομήσει πολύ χρόνο.

Το Arduino UNO R3 διαθέτει ενσωματωμένο USB to Serial adapter πάνω στην ίδια την πλακέτα. Για να αποκτήσετε σύνδεση UART, απλώς αφαιρέστε το μικροελεγκτή Atmel 328p από την πλακέτα. Αυτό το hack λειτουργεί σε εκδόσεις του Arduino UNO R3 στις οποίες το Atmel 328p δεν είναι συγκολλημένο στην πλακέτα (σε αυτό χρησιμοποιείται η έκδοση SMD). Συνδέστε το pin RX του Arduino (Digital Pin 0) στο pin TX του UART Interface και το pin TX του Arduino (Digital Pin 1) στο pin RX του UART interface.

Χρησιμοποιήστε το **Serial Monitor** του Arduino IDE ή ένα dedicated terminal με το baud rate του target. Τα serial signals του Classic Uno R3 είναι logic 5 V, επομένως χρησιμοποιήστε level shifter ή divider πριν τα συνδέσετε σε target 3,3 V ή χαμηλότερης τάσης.

## Bus Pirate

Το ακόλουθο transcript χρησιμοποιεί το legacy Bus Pirate firmware interface για την παρακολούθηση της εξόδου UART. Το νεότερο Bus Pirate firmware χρησιμοποιεί commands όπως `m uart`, `{`/`}`, `monitor` ή `bridge`. Συμβουλευτείτε την τεκμηρίωση για την εγκατεστημένη έκδοση.<sup>[[2]](#references)</sup>
```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Dumping Firmware με κονσόλα UART

Μια κονσόλα UART παρέχει πρόσβαση κατά τον χρόνο εκτέλεσης στα boot logs και, μερικές φορές, σε ένα bootloader ή shell λειτουργικού συστήματος. Ακόμη και μια κονσόλα μόνο για ανάγνωση αποκαλύπτει memory maps, flash drivers, boot arguments, partition layouts και εκδόσεις firmware. Το firmware μπορεί να βρίσκεται σε SPI NOR/NAND, eMMC ή κάποια άλλη συσκευή· γενικά δεν εκτελείται από EEPROM, και τα αρχεία που γράφονται σε ένα προσαρτημένο persistent filesystem δεν εξαφανίζονται απαραίτητα μετά από reboot.

Υπάρχουν αρκετές διαδρομές απόκτησης, ενώ η ενότητα SPI καλύπτει τις απευθείας αναγνώσεις από external flash. Η απόκτηση με βοήθεια κονσόλας μπορεί να είναι λιγότερο παρεμβατική όταν ο bootloader παρέχει ήδη μια ασφαλή εντολή read, όμως οποιαδήποτε διακοπή του boot ή εντολή flash μπορεί να επηρεάσει τη διαθεσιμότητα, επομένως καταγράψτε την αρχική κατάσταση και αποφύγετε λειτουργίες write/erase.

Το dumping firmware με βοήθεια κονσόλας συχνά ξεκινά με τη διακοπή ενός bootloader. Πολλές συσκευές embedded Linux χρησιμοποιούν το **Das U-Boot**, όμως άλλες χρησιμοποιούν proprietary bootloaders ή απενεργοποιούν την interactive console.

Για να ελέγξετε αν υπάρχει interactive bootloader, συνδέστε τη διαδρομή λήψης UART και το terminal ενώ ο στόχος είναι απενεργοποιημένος, ξεκινήστε την καταγραφή και ενεργοποιήστε τον. Ακολουθήστε το autoboot prompt που εμφανίζεται· ανάλογα με το build, η διακοπή μπορεί να απαιτεί ένα πλήκτρο, μια σύντομη ακολουθία ή να είναι πλήρως απενεργοποιημένη.

Αν η διακοπή επιτύχει, χρησιμοποιήστε τις `help`, `printenv` και read-only discovery commands για να κατανοήσετε το memory και storage layout του συγκεκριμένου vendor πριν αποκτήσετε πρόσβαση σε διευθύνσεις.

Στο U-Boot, η `md` εμφανίζει **addressable memory**, όχι αυτόματα «το EEPROM». Αρχικά χρησιμοποιήστε board-specific commands όπως `mtd list`, `sf probe`, `mmc info`, `part list`, environment variables και boot logs, για να εντοπίσετε τη σωστή mapped address ή να φορτώσετε μια flash region στη RAM. Στη συνέχεια εμφανίστε ένα γνωστό range byte-by-byte:<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
Καταγράψτε τη σειριακή έξοδο πριν από την εκκίνηση. Η έξοδος του `md.b` περιέχει διευθύνσεις και μια στήλη ASCII, επομένως αποτελεί αναπαράσταση κειμένου και όχι ακατέργαστη εικόνα ROM.

Αφαιρέστε τις στήλες διευθύνσεων και ASCII, ενώστε μόνο τα δεκαεξαδικά πεδία byte και αποκωδικοποιήστε τα σε δυαδικά δεδομένα (για παράδειγμα, με `xxd -r -p`). Επαληθεύστε τον αναμενόμενο αριθμό byte και καταγράψτε ένα hash πριν από την ανάλυση:
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Στη συνέχεια, το Binwalk εντοπίζει γνωστές signatures στο ανακατασκευασμένο binary. Μια απευθείας ανάγνωση της flash μέσω της κατάλληλης διεπαφής SPI/eMMC/NAND είναι συνήθως ταχύτερη και λιγότερο επιρρεπής σε σφάλματα, όταν η console δεν μπορεί να μεταφέρει δεδομένα αξιόπιστα.

Το U-Boot μπορεί να απενεργοποιεί τη διακοπή, να απαιτεί vendor-specific sequence πλήκτρων ή να κλειδώνει τις εντολές memory/flash. Ακολούθησε το autoboot prompt και το boot log αντί να μεταδίδεις χαρακτήρες στα τυφλά. Αν η console δεν μπορεί να διακοπεί, διατήρησε το boot log και προχώρησε σε non-invasive firmware acquisition path.

## References

- [1] [Εγχειρίδιο αναφοράς οικογένειας Microchip PIC32 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Τεκμηρίωση Bus Pirate - λειτουργία UART και ηλεκτρικά όρια](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - φύλλο δεδομένων CP2102C](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [Τεκμηρίωση U-Boot - εντολή `md` για εμφάνιση μνήμης](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
