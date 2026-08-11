# SPI

{{#include ../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το SPI (Serial Peripheral Interface) είναι ένας σύγχρονος σειριακός δίαυλος που χρησιμοποιείται συνήθως για επικοινωνία μικρής απόστασης μεταξύ ολοκληρωμένων κυκλωμάτων. Ένας controller παρέχει το clock και επιλέγει ένα peripheral, όπως μια EEPROM, έναν sensor ή μια συσκευή ελέγχου, χρησιμοποιώντας ένα σήμα chip-select.<sup>[[1]](#references)</sup>

Πολλά peripherals μπορούν να μοιράζονται τις γραμμές clock και data, συνήθως με ξεχωριστό chip-select για κάθε peripheral. Ο controller ενορχηστρώνει τις μεταφορές· τα peripherals συνήθως δεν επικοινωνούν απευθείας μεταξύ τους μέσω του SPI bus. Η πολικότητα και ο χρονισμός του chip-select εξαρτώνται από τη συσκευή· η επιλογή active-low είναι συνηθισμένη, αλλά όχι καθολική. Το SPI δεν ορίζει discovery, addressing, commands ή ένα ενιαίο μέγιστο μήκος μεταφοράς, επομένως να συμβουλεύεστε πάντα το datasheet του στόχου.<sup>[[1]](#references)</sup>

Το MOSI/COPI μεταφέρει δεδομένα από τον controller προς το peripheral και το MISO/CIPO μεταφέρει δεδομένα από το peripheral προς τον controller. Και οι δύο κατευθύνσεις μπορούν να μετακινούν δεδομένα ταυτόχρονα. Η σχέση μεταξύ ενός command, της διεύθυνσης, των dummy cycles και των δεδομένων που επιστρέφονται ορίζεται από το peripheral — όχι από το SPI — και εξαρτάται από την πολικότητα και τη φάση του clock (modes 0–3). Μην θεωρείτε δεδομένο ότι η έξοδος ξεκινά ακριβώς έναν κύκλο clock μετά το τέλος της εισόδου.<sup>[[1]](#references)</sup>

## Dumping Firmware από EEPROMs

Το dumping firmware μπορεί να είναι χρήσιμο για την ανάλυσή του και τον εντοπισμό vulnerabilities. Η σωστή image μπορεί να μην είναι διαθέσιμη online ή να διαφέρει ανά model, hardware revision ή version, επομένως η απευθείας εξαγωγή της από τη φυσική συσκευή παρέχει έναν ακριβή στόχο αξιολόγησης.

Μια serial console μπορεί να βοηθήσει, αλλά το filesystem της μπορεί να είναι read-only και ο στόχος μπορεί να μην διαθέτει εργαλεία ανάλυσης, συμπεριλαμβανομένων utilities που απαιτούνται για την αποστολή/λήψη δοκιμαστικής κίνησης ή για την εύκολη εξαγωγή binaries. Μια offline image διατηρεί την πλήρη διάταξη του flash και επιτρέπει την εξαγωγή του filesystem και το reverse engineering χωρίς τροποποίηση του ενεργού στόχου.

Κατά τη διάρκεια μιας εξουσιοδοτημένης physical assessment, ένα επαληθευμένο dump μπορεί επίσης να υποστηρίξει ελεγχόμενες δοκιμές τροποποίησης και reflashing. Αυτό περιλαμβάνει την αλλαγή αρχείων ή την εισαγωγή ενός test payload/backdoor για την επίδειξη persistence σε επίπεδο firmware. Διατηρήστε πολλαπλές matching reads και την αρχική image πριν από οποιαδήποτε εγγραφή: λανθασμένη τάση, επιλογή chip, διάταξη ή image μπορεί να καταστήσει τη συσκευή μη λειτουργική.

### CH341A EEPROM Programmer και Reader

Αυτό το οικονομικό USB tool μπορεί να κάνει dump και reflash συμβατών serial EEPROM και SPI flash συσκευών. Χρησιμοποιείται συχνά με τα SPI NOR flash chips που αποθηκεύουν firmware PC BIOS/UEFI και είναι πρακτικό κατά τη διάρκεια physical access περιορισμένου χρόνου.

![drawing](../../images/board_image_ch341a.jpg)

Συνδέστε τη flash memory στο CH341A και, στη συνέχεια, συνδέστε τον programmer στον υπολογιστή. Εάν ο ίδιος ο programmer δεν ανιχνεύεται, ελέγξτε το USB cable, τα OS permissions και τον κατάλληλο CH341A driver πριν από την αντιμετώπιση προβλημάτων του chip-στόχου. Επιβεβαιώστε την τάση του chip, το pin 1, την καλωδίωση του adapter και την έξοδο του programmer χρησιμοποιώντας τα datasheets ή ένα meter — **μην** βασίζεστε σε κανόνα όπως η τοποθέτηση του VCC απέναντι από το USB connector. Λανθασμένος προσανατολισμός ή εφαρμογή 5 V σε εξάρτημα 3.3/1.8 V μπορεί να το καταστρέψει. Οι in-circuit αναγνώσεις μπορεί επίσης να αποτύχουν επειδή το υπόλοιπο board φορτώνει ή τροφοδοτεί το bus.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

Χρησιμοποιήστε software όπως τα `flashrom` ή G-Flash για να διαβάσετε το chip. Το G-Flash είναι ένα minimal GUI και μπορεί να κάνει auto-detect συμβατές συσκευές, κάτι που μπορεί να είναι πρακτικό κατά τη διάρκεια γρήγορης απόκτησης, αλλά επιβεβαιώστε οι ίδιοι το detected model και την τάση. Καθορίστε τον ακριβή programmer και, όταν είναι απαραίτητο, το ακριβές chip model· πραγματοποιήστε τουλάχιστον δύο reads και συγκρίνετε τα hashes τους πριν θεωρήσετε ένα dump αξιόπιστο.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Μετά το dumping του firmware, η ανάλυση μπορεί να πραγματοποιηθεί στα binary files. Εργαλεία όπως τα strings, hexdump, xxd, binwalk κ.λπ. μπορούν να χρησιμοποιηθούν για την εξαγωγή πολλών πληροφοριών σχετικά με το firmware, καθώς και για ολόκληρο το filesystem.

Για το αρχικό triage, το Binwalk μπορεί να σαρώσει για γνωστές signatures και να εξαγάγει υποστηριζόμενο embedded content:
```
binwalk -e <filename>
```
Το αρχείο εξόδου μπορεί να χρησιμοποιεί την επέκταση `.bin`, `.rom` ή κάποια άλλη· η επέκταση δεν καθορίζει τη μορφή.

> [!CAUTION]
> Σημειώστε ότι η εξαγωγή firmware είναι μια ευαίσθητη διαδικασία και απαιτεί πολλή υπομονή. Οποιοσδήποτε λανθασμένος χειρισμός μπορεί ενδεχομένως να καταστρέψει το firmware ή ακόμη και να το διαγράψει εντελώς, καθιστώντας τη συσκευή μη χρησιμοποιήσιμη. Συνιστάται να μελετήσετε τη συγκεκριμένη συσκευή πριν επιχειρήσετε να εξαγάγετε το firmware.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Ορισμένα datasheets επισημαίνουν τα pins-στόχους ως `DI` και `DO`: για μια συμβατική σύνδεση flash με μία γραμμή δεδομένων, το **MOSI/COPI του controller συνδέεται στο DI** και το **MISO/CIPO του controller συνδέεται στο DO**. Επαληθεύστε το datasheet του στόχου, επειδή τα εξαρτήματα dual/quad I/O επαναχρησιμοποιούν τα pins σε άλλες λειτουργίες.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Σημειώστε ότι ακόμη και αν το PINOUT του Pirate Bus υποδεικνύει pins για τη σύνδεση των MOSI και MISO στο SPI, ορισμένα SPI μπορεί να...](<../../images/image (360).png>)

Σε Windows ή Linux μπορείτε να χρησιμοποιήσετε το πρόγραμμα [**`flashrom`**](https://www.flashrom.org/Flashrom) για να κάνετε dump των περιεχομένων της μνήμης flash, εκτελώντας κάτι όπως:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
Η πρόσφατη τεκμηρίωση του Bus Pirate εμφανίζει επίσης τις προαιρετικές παραμέτρους `serialspeed` και `spispeed`. Ξεκινήστε συντηρητικά αν τα μακριά καλώδια ή η φόρτιση στο κύκλωμα καθιστούν τις αναγνώσεις ασταθείς.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — Εισαγωγή στη διεπαφή SPI](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [Εγχειρίδιο flashrom — Προγραμματιστής CH341A SPI και επιλογές ανάγνωσης/εγγραφής](https://flashrom.org/classic_cli_manpage.html)
- [3] [Τεκμηρίωση Bus Pirate — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
