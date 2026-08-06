# UART

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το UART είναι ένα serial protocol, δηλαδή μεταφέρει δεδομένα μεταξύ components ένα bit κάθε φορά. Αντίθετα, τα parallel communication protocols μεταδίδουν δεδομένα ταυτόχρονα μέσω πολλαπλών καναλιών. Συνηθισμένα serial protocols είναι τα RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express και USB.

Γενικά, η γραμμή διατηρείται σε υψηλή στάθμη (λογική τιμή 1) όσο το UART βρίσκεται σε κατάσταση αδράνειας. Στη συνέχεια, για να σηματοδοτήσει την έναρξη μιας μεταφοράς δεδομένων, ο transmitter στέλνει ένα start bit στον receiver, κατά τη διάρκεια του οποίου το σήμα διατηρείται σε χαμηλή στάθμη (λογική τιμή 0). Έπειτα, ο transmitter στέλνει πέντε έως οκτώ data bits που περιέχουν το πραγματικό μήνυμα, ακολουθούμενα από ένα προαιρετικό parity bit και ένα ή δύο stop bits (με λογική τιμή 1), ανάλογα με τη διαμόρφωση. Το parity bit, που χρησιμοποιείται για error checking, σπάνια εμφανίζεται στην πράξη. Το stop bit (ή τα stop bits) δηλώνει το τέλος της μετάδοσης.

Τη συνηθέστερη διαμόρφωση την ονομάζουμε 8N1: οκτώ data bits, χωρίς parity και ένα stop bit. Για παράδειγμα, αν θέλαμε να στείλουμε τον χαρακτήρα C, ή 0x43 σε ASCII, σε μια διαμόρφωση 8N1 UART, θα στέλναμε τα εξής bits: 0 (το start bit), 0, 1, 0, 0, 0, 0, 1, 1 (η τιμή του 0x43 σε δυαδική μορφή) και 0 (το stop bit).

![UART: Τη συνηθέστερη διαμόρφωση την ονομάζουμε 8N1: οκτώ data bits, χωρίς parity και ένα stop bit. Για παράδειγμα, αν θέλαμε να στείλουμε τον χαρακτήρα C, ή 0x43 σε ASCII, σε μια διαμόρφωση 8N1 UART](<../../images/image (764).png>)

Hardware tools για επικοινωνία με UART:

- USB-to-serial adapter
- Adapters με τα chips CP2102 ή PL2303
- Multipurpose tool όπως τα: Bus Pirate, Adafruit FT232H, Shikra ή Attify Badge

### Εντοπισμός θυρών UART

Το UART διαθέτει 4 θύρες: **TX** (Transmit), **RX** (Receive), **Vcc** (Voltage) και **GND** (Ground). Ίσως μπορέσετε να βρείτε 4 θύρες με τα γράμματα **`TX`** και **`RX`** **γραμμένα** στο PCB. Αν όμως δεν υπάρχει καμία ένδειξη, ίσως χρειαστεί να τις εντοπίσετε μόνοι σας χρησιμοποιώντας ένα **multimeter** ή έναν **logic analyzer**.

Με ένα **multimeter** και τη συσκευή απενεργοποιημένη:

- Για να εντοπίσετε το pin **GND**, χρησιμοποιήστε τη λειτουργία **Continuity Test**, τοποθετήστε το μαύρο probe στη γείωση και ελέγξτε με το κόκκινο probe μέχρι να ακούσετε έναν ήχο από το multimeter. Στο PCB μπορεί να βρεθούν αρκετά pins GND, επομένως μπορεί να εντοπίσατε ή να μην εντοπίσατε αυτό που ανήκει στο UART.
- Για να εντοπίσετε τη θύρα **VCC**, επιλέξτε τη λειτουργία **DC voltage** και ρυθμίστε την τάση στα 20 V. Τοποθετήστε το μαύρο probe στη γείωση και το κόκκινο probe στο pin. Ενεργοποιήστε τη συσκευή. Αν το multimeter μετρήσει σταθερή τάση είτε 3.3 V είτε 5 V, έχετε βρει το pin Vcc. Αν λάβετε άλλες τάσεις, δοκιμάστε ξανά με άλλες θύρες.
- Για να εντοπίσετε τη θύρα **TX**, επιλέξτε τη λειτουργία **DC voltage** έως 20 V, τοποθετήστε το μαύρο probe στη γείωση και το κόκκινο probe στο pin και ενεργοποιήστε τη συσκευή. Αν η τάση μεταβάλλεται για λίγα δευτερόλεπτα και στη συνέχεια σταθεροποιείται στην τιμή Vcc, πιθανότατα έχετε βρει τη θύρα TX. Αυτό συμβαίνει επειδή κατά την ενεργοποίηση η συσκευή στέλνει ορισμένα debug δεδομένα.
- Η **θύρα RX** θα είναι η πλησιέστερη στις άλλες 3, θα παρουσιάζει τη μικρότερη μεταβολή τάσης και τη χαμηλότερη συνολική τιμή από όλα τα pins UART.

Αν μπερδέψετε τις θύρες TX και RX, δεν θα συμβεί τίποτα, αλλά αν μπερδέψετε τις GND και VCC, μπορεί να καταστρέψετε το κύκλωμα.

Σε ορισμένες target συσκευές, η θύρα UART είναι απενεργοποιημένη από τον κατασκευαστή, με την απενεργοποίηση του RX ή του TX ή και των δύο. Σε αυτή την περίπτωση, μπορεί να είναι χρήσιμο να ακολουθήσετε τις συνδέσεις στην πλακέτα και να βρείτε κάποιο breakout point. Μια ισχυρή ένδειξη για την επιβεβαίωση της μη ανίχνευσης του UART και της διακοπής του κυκλώματος είναι να ελέγξετε την εγγύηση της συσκευής. Αν η συσκευή έχει αποσταλεί με εγγύηση, ο κατασκευαστής αφήνει ορισμένα debug interfaces (σε αυτή την περίπτωση, UART) και επομένως πρέπει να έχει αποσυνδέσει το UART, ώστε να το συνδέσει ξανά κατά το debugging. Αυτά τα breakout pins μπορούν να συνδεθούν με soldering ή jumper wires.

### Εντοπισμός του baud rate του UART

Ο ευκολότερος τρόπος για να εντοπίσετε το σωστό baud rate είναι να δείτε το **output του TX pin και να προσπαθήσετε να διαβάσετε τα δεδομένα**. Αν τα δεδομένα που λαμβάνετε δεν είναι αναγνώσιμα, δοκιμάστε το επόμενο πιθανό baud rate μέχρι τα δεδομένα να γίνουν αναγνώσιμα. Για αυτό μπορείτε να χρησιμοποιήσετε έναν USB-to-serial adapter ή μια multipurpose συσκευή όπως το Bus Pirate, σε συνδυασμό με ένα helper script, όπως το [baudrate.py](https://github.com/devttys0/baudrate/). Τα συνηθέστερα baud rates είναι 9600, 38400, 19200, 57600 και 115200.

> [!CAUTION]
> Είναι σημαντικό να σημειωθεί ότι σε αυτό το protocol πρέπει να συνδέσετε το TX της μίας συσκευής στο RX της άλλης!

## CP210X UART to TTY Adapter

Το chip CP210X χρησιμοποιείται σε πολλές πλακέτες prototyping, όπως η NodeMCU (με esp8266), για Serial Communication. Αυτοί οι adapters είναι σχετικά οικονομικοί και μπορούν να χρησιμοποιηθούν για σύνδεση στη διεπαφή UART του target. Η συσκευή διαθέτει 5 pins: 5V, GND, RXD, TXD και 3.3V. Βεβαιωθείτε ότι συνδέετε την τάση που υποστηρίζεται από το target, ώστε να αποφύγετε τυχόν ζημιές. Τέλος, συνδέστε το pin RXD του Adapter στο TXD του target και το pin TXD του Adapter στο RXD του target.

Σε περίπτωση που ο adapter δεν ανιχνεύεται, βεβαιωθείτε ότι οι drivers του CP210X είναι εγκατεστημένοι στο host system. Μόλις ο adapter ανιχνευθεί και συνδεθεί, μπορούν να χρησιμοποιηθούν εργαλεία όπως τα picocom, minicom ή screen.

Για να εμφανίσετε τις συσκευές που είναι συνδεδεμένες σε συστήματα Linux/MacOS:
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

Μετά τη διαμόρφωση, χρησιμοποιήστε την εντολή `minicom` για να ξεκινήσετε το UART Console.

## UART μέσω Arduino UNO R3 (Πλακέτες με αφαιρούμενο chip Atmel 328p)

Σε περίπτωση που δεν υπάρχουν διαθέσιμοι UART Serial to USB adapters, μπορεί να χρησιμοποιηθεί ένα Arduino UNO R3 με ένα γρήγορο hack. Επειδή το Arduino UNO R3 είναι συνήθως διαθέσιμο παντού, αυτό μπορεί να εξοικονομήσει πολύ χρόνο.

Το Arduino UNO R3 διαθέτει ενσωματωμένο USB to Serial adapter. Για να αποκτήσετε σύνδεση UART, απλώς αφαιρέστε το microcontroller chip Atmel 328p από την πλακέτα. Αυτό το hack λειτουργεί σε εκδόσεις του Arduino UNO R3 στις οποίες το Atmel 328p δεν είναι κολλημένο στην πλακέτα (σε αυτήν χρησιμοποιείται η έκδοση SMD). Συνδέστε το pin RX του Arduino (Digital Pin 0) στο pin TX του UART Interface και το pin TX του Arduino (Digital Pin 1) στο pin RX του UART interface.

Τέλος, συνιστάται να χρησιμοποιήσετε το Arduino IDE για να αποκτήσετε το Serial Console. Στην ενότητα `tools` του μενού, επιλέξτε την επιλογή `Serial Console` και ορίστε το baud rate σύμφωνα με το UART interface.

## Bus Pirate

Σε αυτό το σενάριο θα κάνουμε sniff στην UART επικοινωνία του Arduino, το οποίο στέλνει όλα τα prints του προγράμματος στο Serial Monitor.
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
## Dumping Firmware with UART Console

Το UART Console παρέχει έναν εξαιρετικό τρόπο για εργασία με το underlying firmware σε runtime environment. Ωστόσο, όταν η πρόσβαση στο UART Console είναι read-only, αυτό μπορεί να δημιουργήσει πολλούς περιορισμούς. Σε πολλές embedded συσκευές, το firmware αποθηκεύεται σε EEPROMs και εκτελείται σε processors που διαθέτουν volatile memory. Επομένως, το firmware παραμένει read-only, καθώς το αρχικό firmware κατά την κατασκευή βρίσκεται μέσα στην ίδια την EEPROM και τυχόν νέα αρχεία θα χάνονταν λόγω της volatile memory. Για αυτόν τον λόγο, το dumping του firmware αποτελεί σημαντική ενέργεια κατά την εργασία με embedded firmwares.

Υπάρχουν πολλοί τρόποι για να γίνει αυτό και η ενότητα SPI καλύπτει μεθόδους εξαγωγής του firmware απευθείας από την EEPROM με διάφορες συσκευές. Ωστόσο, συνιστάται να δοκιμάσετε πρώτα το dumping του firmware μέσω UART, καθώς το dumping του firmware με physical devices και external interactions μπορεί να είναι επικίνδυνο.

Το dumping firmware από το UART Console απαιτεί πρώτα την απόκτηση πρόσβασης στους bootloaders. Πολλοί δημοφιλείς vendors χρησιμοποιούν το uboot (Universal Bootloader) ως bootloader για τη φόρτωση του Linux. Επομένως, είναι απαραίτητο να αποκτήσετε πρόσβαση στο uboot.

Για να αποκτήσετε πρόσβαση στον boot bootloader, συνδέστε τη θύρα UART στον υπολογιστή και χρησιμοποιήστε οποιοδήποτε από τα Serial Console tools, διατηρώντας την παροχή ρεύματος προς τη συσκευή αποσυνδεδεμένη. Μόλις η εγκατάσταση είναι έτοιμη, πατήστε το Enter Key και κρατήστε το πατημένο. Τέλος, συνδέστε την παροχή ρεύματος στη συσκευή και αφήστε την να εκκινήσει.

Αυτό θα διακόψει τη φόρτωση του uboot και θα εμφανίσει ένα menu. Συνιστάται να κατανοήσετε τις εντολές του uboot και να χρησιμοποιήσετε το help menu για να τις εμφανίσετε. Αυτή μπορεί να είναι η εντολή `help`. Επειδή διαφορετικοί vendors χρησιμοποιούν διαφορετικές configurations, είναι απαραίτητο να κατανοήσετε καθεμία ξεχωριστά.

Συνήθως, η εντολή για το dumping του firmware είναι:
```
md
```
που σημαίνει "memory dump". Αυτό θα εμφανίσει τη μνήμη (περιεχόμενο EEPROM) στην οθόνη. Συνιστάται να καταγράψετε την έξοδο της Serial Console πριν ξεκινήσετε τη διαδικασία, ώστε να καταγράψετε το memory dump.

Τέλος, αφαιρέστε όλα τα περιττά δεδομένα από το αρχείο καταγραφής, αποθηκεύστε το αρχείο ως `filename.rom` και χρησιμοποιήστε το binwalk για να εξαγάγετε τα περιεχόμενα:
```
binwalk -e <filename.rom>
```
Αυτό θα εμφανίσει τα πιθανά περιεχόμενα από το EEPROM, σύμφωνα με τις signatures που βρέθηκαν στο αρχείο hex.

Ωστόσο, είναι απαραίτητο να σημειωθεί ότι δεν ισχύει πάντα πως το uboot είναι unlocked, ακόμη και αν χρησιμοποιείται. Αν το Enter Key δεν κάνει τίποτα, ελέγξτε διαφορετικά πλήκτρα, όπως το Space Key κ.λπ. Αν ο bootloader είναι locked και δεν διακόπτεται, αυτή η μέθοδος δεν θα λειτουργήσει. Για να ελέγξετε αν το uboot είναι ο bootloader της συσκευής, ελέγξτε την έξοδο στην UART Console κατά την εκκίνηση της συσκευής. Ενδέχεται να αναφέρει το uboot κατά την εκκίνηση.

{{#include ../../banners/hacktricks-training.md}}
