# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή <a href="#introduction" id="introduction"></a>

Το Flipper Zero μπορεί να **λαμβάνει και να μεταδίδει ραδιοσυχνότητες στο εύρος 300-928 MHz** με το ενσωματωμένο module του, με την επιφύλαξη των περιορισμών συχνότητας για την configured region. Μπορεί να διαβάζει, να αποθηκεύει και να εξομοιώνει συμβατά τηλεχειριστήρια που χρησιμοποιούνται σε πύλες, μπάρες, radio locks, διακόπτες, ασύρματα κουδούνια, smart lights και άλλες συσκευές.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Hardware <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Το Flipper Zero διαθέτει ενσωματωμένο module κάτω του 1 GHz, βασισμένο σε transceiver CC1101 και radio antenna. Η πραγματική εμβέλεια εξαρτάται από τη συχνότητα, την κεραία, το περιβάλλον και τον transmitter· το Flipper αναφέρει έως περίπου 50 μέτρα υπό ευνοϊκές συνθήκες. Το hardware καλύπτει τα 300-348 MHz, 387-464 MHz και 779-928 MHz, ενώ το firmware και οι regional rules περιορίζουν περαιτέρω τη μετάδοση.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Ενέργειες

### Frequency Analyser

> [!TIP]
> Πώς να βρείτε ποια συχνότητα χρησιμοποιεί το τηλεχειριστήριο

Κατά την ανάλυση, το Flipper Zero σαρώνει την ισχύ των σημάτων (RSSI) σε όλες τις συχνότητες που είναι διαθέσιμες στο frequency configuration. Το Flipper Zero εμφανίζει τη συχνότητα με την υψηλότερη τιμή RSSI, με ισχύ σήματος μεγαλύτερη από -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Για να προσδιορίσετε τη συχνότητα του τηλεχειριστηρίου, κάντε τα εξής:

1. Τοποθετήστε το τηλεχειριστήριο πολύ κοντά στην αριστερή πλευρά του Flipper Zero.
2. Μεταβείτε στο **Main Menu** **→ Sub-GHz**.
3. Επιλέξτε **Frequency Analyzer** και, στη συνέχεια, πατήστε παρατεταμένα το κουμπί στο τηλεχειριστήριο που θέλετε να αναλύσετε.
4. Ελέγξτε την τιμή της συχνότητας στην οθόνη.

### Read

> [!TIP]
> Βρείτε πληροφορίες σχετικά με τη χρησιμοποιούμενη συχνότητα (επίσης ένας άλλος τρόπος για να βρείτε ποια συχνότητα χρησιμοποιείται)

Η επιλογή **Read** ακούει στη configured frequency και modulation (433.92 MHz AM by default). Όταν αναγνωρίσει ένα υποστηριζόμενο σήμα, η οθόνη εμφανίζει πληροφορίες που μπορούν να αποθηκευτούν και να αναπαραχθούν αργότερα.<sup>[[1]](#references)</sup>

Κατά τη χρήση του Read, είναι δυνατή η πίεση του **left button** και η **διαμόρφωσή του**.\
Αυτή τη στιγμή διαθέτει **4 modulations** (AM270, AM650, FM328 και FM476), καθώς και **αρκετές σχετικές συχνότητες** αποθηκευμένες:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Μπορείτε να επιλέξετε οποιαδήποτε επιτρεπόμενη συχνότητα. Αν δεν είστε βέβαιοι ποια συχνότητα χρησιμοποιεί το τηλεχειριστήριο, ενεργοποιήστε το **Hopping** (απενεργοποιημένο by default) και, στη συνέχεια, πατήστε το κουμπί του τηλεχειριστηρίου αρκετές φορές μέχρι το Flipper να καταγράψει το σήμα και να αναφέρει τη συχνότητα.

> [!CAUTION]
> Η εναλλαγή μεταξύ συχνοτήτων απαιτεί κάποιο χρόνο, επομένως τα σήματα που μεταδίδονται τη στιγμή της εναλλαγής ενδέχεται να χαθούν. Για καλύτερη λήψη σήματος, ορίστε μια fixed frequency που προσδιορίστηκε μέσω του Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Κλέψτε (και αναπαραγάγετε) ένα σήμα στη configured frequency

Η επιλογή **Read Raw** καταγράφει σήματα που αποστέλλονται στην επιλεγμένη συχνότητα. Αυτό μπορεί να χρησιμοποιηθεί για την capture και replay ενός σήματος κατά τη διάρκεια authorized testing.<sup>[[1]](#references)</sup>

By default, το **Read Raw χρησιμοποιεί επίσης 433.92 MHz με AM650**. Αν η επιλογή Read εντόπισε σήμα σε διαφορετική συχνότητα ή modulation, πατήστε Left μέσα στο Read Raw για να αλλάξετε αυτές τις ρυθμίσεις.

### Brute-Force

Αν γνωρίζετε το protocol που χρησιμοποιείται από μια συσκευή, όπως μια γκαραζόπορτα, ενδέχεται να είναι δυνατή η **δημιουργία candidate codes και η μετάδοσή τους με το Flipper Zero**. Το project `flipperzero-bruteforce` υποστηρίζει αρκετά common static-code protocols.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Προσθέστε σήματα από μια configured λίστα protocols

#### Λίστα υποστηριζόμενων protocols <a href="#id-3iglu" id="id-3iglu"></a>

Το μενού Add Manually εμφανίζει τα protocol presets που τεκμηριώνονται από το Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (λειτουργεί με την πλειονότητα των static code systems) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Υποστηριζόμενοι Sub-GHz vendors

Ελέγξτε τη λίστα supported-vendors του Flipper Zero.<sup>[[5]](#references)</sup>

### Υποστηριζόμενες συχνότητες ανά region

Ελέγξτε την επίσημη regional-frequency list πριν από τη μετάδοση.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Λάβετε τα dBms των αποθηκευμένων συχνοτήτων

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 data sheet](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Add a manually created remote](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Supported Sub-GHz vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regional Sub-GHz frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
