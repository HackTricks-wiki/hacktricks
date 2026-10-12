# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Επαληθεύστε την τάση-στόχο, το pinout, τη διάταξη των pull-up και την κοινή γείωση πριν συνδέσετε ένα Bus Pirate. Μην ενεργοποιείτε τις τροφοδοσίες του Bus Pirate σε ενεργό bus που τροφοδοτείται από τη συσκευή-στόχο, απλώς για να το κάνετε sniff· δύο τροφοδοσίες μπορεί να έρθουν σε σύγκρουση και να προκαλέσουν ζημιά στο hardware. Το παρακάτω transcript είναι ένα παράδειγμα ειδικό για συγκεκριμένη συσκευή, με Bus Pirate v3/community firmware, και όχι μια καθολική συνταγή καλωδίωσης.<sup>[[1]](#references)[[2]](#references)</sup>

Για να ελέγξετε αν λειτουργεί ένα Bus Pirate, συνδέστε τα +5V στο VPU και τα 3.3V στο ADC, αποκτήστε πρόσβαση στο Bus Pirate (για παράδειγμα, χρησιμοποιώντας το Tera Term) και χρησιμοποιήστε την εντολή `~`:

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

Όπως μπορείτε να δείτε στην προηγούμενη γραμμή εντολών, ανέφερε ότι εντόπισε 0 σφάλματα. Είναι πολύ χρήσιμο να γνωρίζετε ότι λειτουργεί αφού το αγοράσετε ή αφού κάνετε flash ένα firmware.

Για να συνδεθείτε στο Bus Pirate, μπορείτε να ακολουθήσετε την τεκμηρίωση:

![Χρήση εντολής - Πατήστε το πλήκτρο διαστήματος: Για να συνδεθείτε στο Bus Pirate, μπορείτε να ακολουθήσετε την τεκμηρίωση](<../../images/image (484).png>)

Σε αυτή την περίπτωση, ο στόχος είναι μια I²C EEPROM της οικογένειας 24C256. Επιβεβαιώστε το ακριβές επίθημα και το datasheet, επειδή η υποστηριζόμενη τάση τροφοδοσίας διαφέρει ανάλογα με το εξάρτημα.<sup>[[3]](#references)</sup>

![Χρήση εντολής - Πατήστε το πλήκτρο διαστήματος: Σε αυτή την περίπτωση θα συνδεθώ σε μια EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Για να επικοινωνήσω με το Bus Pirate, χρησιμοποίησα το Tera Term, συνδεδεμένο στη θύρα COM του Bus Pirate, με τη ρύθμιση Setup --> Serial Port --> Speed στα 115200.\
Στην ακόλουθη επικοινωνία μπορείτε να δείτε πώς να προετοιμάσετε το Bus Pirate για επικοινωνία μέσω I2C και πώς να γράψετε και να διαβάσετε από τη μνήμη (τα σχόλια εμφανίζονται με "#", μην περιμένετε να δείτε αυτό το μέρος στην επικοινωνία):

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
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

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Sniffer

Σε αυτό το σενάριο θα υποκλέψουμε την επικοινωνία I2C μεταξύ του arduino και της προηγούμενης EPROM. Αρκεί να επικοινωνήσετε με τις δύο συσκευές και, στη συνέχεια, να συνδέσετε το bus pirate στις ακίδες SCL, SDA και GND:

![Ανάγνωση 20B από τη διεύθυνση 0x69 που διαμορφώθηκε προηγουμένως - Sniffer: Σε αυτό το σενάριο θα υποκλέψουμε την επικοινωνία I2C μεταξύ του arduino και της προηγούμενης EPROM. Αρκεί να...](<../../images/image (166).png>)

```bash
I2C>m
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

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## Ανακατασκευή πρωτοκόλλου I2C black-box

### Αναγνώριση του διαύλου από ενεργές ακίδες

Όταν το περιφερειακό δεν έχει pinout ή datasheet, ξεκινήστε παθητικά με έναν logic analyzer υψηλής αντίστασης εισόδου, ενώ λειτουργεί ο αρχικός host. Αφού συνδέσετε κοινή γείωση και επιβεβαιώσετε ασφαλή λογική στάθμη, ταξινομήστε τις σταθερές ακίδες ως πιθανούς αγωγούς τροφοδοσίας, γειώσεις ή σήματα με pull-up και, στη συνέχεια, συγκρίνετε τις ενεργές γραμμές με συνήθεις διαύλους: το UART έχει ασύγχρονα TX/RX με ανεξάρτητη κατεύθυνση· το συμβατικό SPI συνήθως έχει clock, chip select και ξεχωριστές γραμμές δεδομένων για κάθε κατεύθυνση· το I2C έχει κανονικό clock και μία αμφίδρομη γραμμή δεδομένων. Έπειτα, η αποκωδικοποίηση I2C θα πρέπει να αποκαλύψει διευθύνσεις στόχων 7 bit, κατεύθυνση ανάγνωσης/εγγραφής, ACK/NACK και επαναλαμβανόμενα payloads.<sup>[[2]](#references)[[4]](#references)</sup>

Καταγράψτε αρκετές νόμιμες ανταλλαγές και διατηρήστε τόσο τα αποκωδικοποιημένα bytes όσο και τον ακατέργαστο χρονισμό. Τα επαναλαμβανόμενα frames είναι χρήσιμα γνωστά αποτελέσματα για δοκιμές μελλοντικών serializers, ενώ οι διαφορές μεταξύ αιτημάτων μπορεί να αποκαλύψουν πιθανά πεδία opcode, index, offset, length, sequence ή checksum.<sup>[[4]](#references)</sup>

### Ανάκτηση της δομής των frames από το firmware του host

Αν δεν είναι προσβάσιμο το firmware του περιφερειακού, εξαγάγετε το firmware του **host** και εντοπίστε το component που ανοίγει τη συσκευή I2C. Αναζητήστε strings και symbols για το όνομα του περιφερειακού, το `/dev/i2c-`, command builders, response parsers, ρουτίνες reset/initialization και συναρτήσεις checksum. Για κάθε builder, καταγράψτε τις ακριβείς θέσεις πεδίων, τις σταθερές, τα αποδεκτά μεγέθη ορισμάτων, το μήκος payload, τα bytes που καλύπτει το checksum, τη σειρά byte του checksum και το μήκος του frame που επιστρέφεται, αντί να συμπεραίνετε τη μορφή από τα ονόματα των συναρτήσεων.<sup>[[4]](#references)</sup>

Μια συνάρτηση checksum με όνομα `crc16_ccitt` δεν αρκεί για να επιλέξετε ένα preset. Προσδιορίστε την κατεύθυνση των shifts, το byte του table index, το πολυώνυμο που αναπαριστά ο πίνακας, τον αρχικό καταχωρητή, την ανάκλαση εισόδου/εξόδου, το τελικό XOR/την αντιστροφή και τη σειρά byte που χρησιμοποιεί ο serializer στο wire. Για παράδειγμα, ένας πίνακας χαμηλού byte με shift προς τα δεξιά, βασισμένος στο ανεστραμμένο πολυώνυμο `0x8408`, με αρχικοποίηση `0xFFFF` και συμπλήρωση στο τέλος, προσδιορίζει το **CRC-16/X-25 (IBM-SDLC)**. Συχνά απαιτείται σωστό checksum ώστε τα test cases να περάσουν την επαλήθευση ακεραιότητας και να φτάσουν στον command parser.<sup>[[4]](#references)</sup>

Αφού ανακατασκευάσετε τη μορφή, αναζητήστε χαρακτηριστικά ονόματα symbols και σταθερές σε δημόσιο κώδικα. Στην περίπτωση του MJA1, ένα SDK wrapper που εντοπίστηκε ανεξάρτητα επιβεβαίωσε τα command IDs, την επικύρωση ορισμάτων, τους ορισμούς αποκρίσεων και την αντίστοιχη υλοποίηση CRC· χρησιμοποιήστε τέτοιες πηγές για επιβεβαίωση, όχι ως υποκατάστατο της εξέτασης του ακριβούς binary-στόχου και της σειράς byte στο wire.<sup>[[4]](#references)[[5]](#references)</sup>

### Αποστολή frames από rooted host Linux

Ένας παραβιασμένος embedded Linux host μπορεί να επικοινωνήσει με το περιφερειακό χωρίς να προστεθεί άλλος bus controller. Ανοίξτε τον σχετικό adapter, επιλέξτε τη διεύθυνση 7 bit με `I2C_SLAVE` και στείλτε ένα frame που παράγεται από ειδικό serializer· διατηρήστε και μια λειτουργία raw-frame για mutation και fuzzing.<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

Κάντε cross-compile με toolchain συμβατό με την CPU και τη libc του στόχου και συγκρίνετε τα ίχνη του analyzer από το test client με τη νόμιμη κίνηση. Τα όρια των συναλλαγών, η σειρά εγγραφής/ανάγνωσης, οι καθυστερήσεις και η κατάσταση των περιφερειακών μπορεί να έχουν σημασία, ακόμη κι όταν τα ορατά byte είναι ίδια.<sup>[[4]](#references)</sup>

### Απαρίθμηση opcode με καθοδήγηση από τις αποκρίσεις

Μόλις προσδιοριστούν το συντομότερο έγκυρο frame και το checksum, απαριθμήστε όλο το εύρος του opcode και χρησιμοποιήστε την ρητή απόκριση **unsupported-command** του πρωτοκόλλου ως αρνητική βάση αναφοράς. Ένα διαφορετικό αποτέλεσμα —όπως μη έγκυρα ορίσματα, μη έγκυρη κατάσταση ή μη τεκμηριωμένο status— υποδεικνύει ότι η αποκωδικοποίηση έφτασε σε έναν υλοποιημένο ή μερικώς υλοποιημένο handler. Αυτό **δεν** αποδεικνύει ότι υπάρχει δυνατότητα εκμετάλλευσης· δώστε προτεραιότητα στην υποψήφια περίπτωση για fuzzing με δομημένες δοκιμές μήκους, ορισμάτων, κατάστασης και ακολουθιών εντολών.<sup>[[4]](#references)</sup>

Αν μια δοκιμή κολλήσει το περιφερειακό, αυτοματοποιήστε μία μεμονωμένη περίπτωση ανά boot από έναν εξωτερικό controller: συνδεθείτε μέσω SSH, εκτελέστε την περίπτωση, αποθηκεύστε το ακατέργαστο request/response και τον χρονισμό, κάντε reboot ή power-cycle, περιμένετε να ανακάμψουν οι έλεγχοι υγείας και συνεχίστε. Η μεταφορά του component σε ένα fixture που ελέγχεται από μικροελεγκτή μπορεί αργότερα να προσφέρει ντετερμινιστικά resets, άμεσο έλεγχο τροφοδοσίας και ταχύτερο fuzzing.<sup>[[4]](#references)</sup>

## References

- [1] [Τεκμηρίωση του Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — Προδιαγραφή I²C-bus και εγχειρίδιο χρήσης](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — Φύλλο δεδομένων σειριακής EEPROM I²C AT24C256C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Διερεύνηση μαύρου κουτιού: ανάλυση ασφαλείας του ασφαλούς chip MJA1 της Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Wrapper κρυπτογραφίας MJA1 του Mijia BLE SDK](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
