# SPI

{{#include ../../banners/hacktricks-training.md}}

## Βασικές Πληροφορίες

Το SPI (Serial Peripheral Interface) είναι ένα Synchronous Serial Communication Protocol που χρησιμοποιείται σε embedded systems για επικοινωνία μικρής απόστασης μεταξύ ICs (Integrated Circuits). Το SPI Communication Protocol χρησιμοποιεί την αρχιτεκτονική master-slave, η οποία ενορχηστρώνεται από τα Clock και Chip Select Signals. Μια αρχιτεκτονική master-slave αποτελείται από έναν master (συνήθως έναν microprocessor) που διαχειρίζεται εξωτερικά peripherals όπως EEPROMs, sensors, control devices κ.λπ., τα οποία θεωρούνται slaves.

Πολλαπλά slaves μπορούν να συνδεθούν σε έναν master, αλλά οι slaves δεν μπορούν να επικοινωνήσουν μεταξύ τους. Οι slaves ελέγχονται μέσω δύο pins, του clock και του chip select. Καθώς το SPI είναι synchronous communication protocol, τα input και output pins ακολουθούν τα clock signals. Το chip select χρησιμοποιείται από τον master για να επιλέξει έναν slave και να αλληλεπιδράσει μαζί του. Όταν το chip select είναι high, η slave device δεν είναι επιλεγμένη, ενώ όταν είναι low, το chip έχει επιλεγεί και ο master αλληλεπιδρά με τον slave.

Τα MOSI (Master Out, Slave In) και MISO (Master In, Slave Out) είναι υπεύθυνα για την αποστολή και τη λήψη δεδομένων. Τα δεδομένα αποστέλλονται στη slave device μέσω του MOSI pin, ενώ το chip select παραμένει low. Τα input data περιέχουν instructions, memory addresses ή data, σύμφωνα με το datasheet του vendor της slave device. Μετά από έγκυρο input, το MISO pin είναι υπεύθυνο για τη μετάδοση δεδομένων στον master. Τα output data αποστέλλονται ακριβώς στον επόμενο clock cycle μετά το τέλος του input. Τα MISO pins μεταδίδουν δεδομένα μέχρι να μεταδοθούν πλήρως ή μέχρι ο master να θέσει το chip select pin σε high (σε αυτήν την περίπτωση, ο slave θα σταματήσει να μεταδίδει και ο master δεν θα ακούσει μετά από εκείνον τον clock cycle).

## Dumping Firmware από EEPROMs

Το dumping firmware μπορεί να είναι χρήσιμο για την ανάλυση του firmware και τον εντοπισμό vulnerabilities σε αυτό. Συχνά, το firmware δεν είναι διαθέσιμο στο internet ή είναι άσχετο λόγω παραγόντων όπως ο αριθμός μοντέλου, η έκδοση κ.λπ. Επομένως, η απευθείας εξαγωγή του firmware από τη physical device μπορεί να βοηθήσει ώστε η αναζήτηση threats να είναι πιο στοχευμένη.

Η απόκτηση Serial Console μπορεί να είναι χρήσιμη, αλλά συχνά τα αρχεία είναι read-only. Αυτό περιορίζει την ανάλυση για διάφορους λόγους. Για παράδειγμα, tools που απαιτούνται για την αποστολή και τη λήψη packages δεν θα υπάρχουν στο firmware. Επομένως, η εξαγωγή των binaries για reverse engineering δεν είναι εφικτή. Συνεπώς, η ύπαρξη ολόκληρου του firmware dumped στο system και η εξαγωγή των binaries για ανάλυση μπορεί να είναι πολύ χρήσιμη.

Επίσης, κατά τη διάρκεια red teaming και της απόκτησης physical access σε devices, το dumping του firmware μπορεί να βοηθήσει στην τροποποίηση αρχείων ή στην εισαγωγή malicious αρχείων και, στη συνέχεια, στο reflashing τους στη memory, κάτι που θα μπορούσε να είναι χρήσιμο για την εμφύτευση backdoor στη device. Επομένως, το firmware dumping μπορεί να ξεκλειδώσει πολλές δυνατότητες.

### CH341A EEPROM Programmer and Reader

Αυτή η device είναι ένα οικονομικό tool για το dumping firmwares από EEPROMs και επίσης για το reflashing τους με firmware files. Αποτελεί δημοφιλή επιλογή για την εργασία με computer BIOS chips (τα οποία είναι απλώς EEPROMs). Η device συνδέεται μέσω USB και απαιτεί ελάχιστα tools για να ξεκινήσει. Επίσης, συνήθως ολοκληρώνει γρήγορα την εργασία, επομένως μπορεί να είναι χρήσιμη και σε physical device access.

![drawing](../../images/board_image_ch341a.jpg)

Συνδέστε τη μνήμη EEPROM με το CH341a Programmer και συνδέστε τη device στον computer. Σε περίπτωση που η device δεν ανιχνεύεται, δοκιμάστε να εγκαταστήσετε drivers στον computer. Επίσης, βεβαιωθείτε ότι η EEPROM είναι συνδεδεμένη με τον σωστό προσανατολισμό (συνήθως, τοποθετήστε το VCC Pin με αντίστροφο προσανατολισμό σε σχέση με τον USB connector), διαφορετικά το software δεν θα μπορεί να ανιχνεύσει το chip. Ανατρέξτε στο διάγραμμα, εάν απαιτείται:

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Τέλος, χρησιμοποιήστε softwares όπως τα flashrom, G-Flash (GUI) κ.λπ. για το dumping του firmware. Το G-Flash είναι ένα minimal GUI tool, είναι γρήγορο και ανιχνεύει αυτόματα την EEPROM. Αυτό μπορεί να είναι χρήσιμο όταν το firmware πρέπει να εξαχθεί γρήγορα, χωρίς εκτεταμένη ενασχόληση με την τεκμηρίωση.

![drawing](../../images/connected_status_ch341a.jpg)

Μετά το dumping του firmware, η ανάλυση μπορεί να γίνει στα binary files. Tools όπως τα strings, hexdump, xxd, binwalk κ.λπ. μπορούν να χρησιμοποιηθούν για την εξαγωγή πολλών πληροφοριών σχετικά με το firmware, καθώς και για ολόκληρο το file system.

Για την εξαγωγή των περιεχομένων από το firmware, μπορεί να χρησιμοποιηθεί το binwalk. Το Binwalk αναλύει hex signatures, εντοπίζει τα αρχεία στο binary file και έχει τη δυνατότητα να τα εξάγει.
```
binwalk -e <filename>
```
Μπορεί να είναι `.bin` ή `.rom`, ανάλογα με τα εργαλεία και τις ρυθμίσεις που χρησιμοποιούνται.

> [!CAUTION]
> Σημειώστε ότι η εξαγωγή firmware είναι μια ευαίσθητη διαδικασία και απαιτεί πολλή υπομονή. Οποιοσδήποτε λανθασμένος χειρισμός μπορεί ενδεχομένως να καταστρέψει το firmware ή ακόμη και να το διαγράψει εντελώς, καθιστώντας τη συσκευή μη λειτουργική. Συνιστάται να μελετήσετε τη συγκεκριμένη συσκευή πριν επιχειρήσετε να εξαγάγετε το firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Σημειώστε ότι, ακόμη και αν το PINOUT του Bus Pirate υποδεικνύει ακροδέκτες **MOSI** και **MISO** για σύνδεση στο SPI, ορισμένα SPI μπορεί να υποδεικνύουν τους ακροδέκτες ως DI και DO. **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Σημειώστε ότι, ακόμη και αν το PINOUT του Bus Pirate υποδεικνύει ακροδέκτες MOSI και MISO για σύνδεση στο SPI, ορισμένα SPI μπορεί...](<../../images/image (360).png>)

Σε Windows ή Linux μπορείτε να χρησιμοποιήσετε το πρόγραμμα [**`flashrom`**](https://www.flashrom.org/Flashrom) για να κάνετε dump του περιεχομένου της μνήμης flash, εκτελώντας κάτι όπως:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
