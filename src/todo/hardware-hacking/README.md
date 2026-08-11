# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

Το JTAG (IEEE 1149.1) υποστηρίζει testing boundary-scan μέσω cells που τοποθετούνται γύρω από τα I/O pins μιας συσκευής. Πολλοί processors εκθέτουν επίσης vendor-specific λειτουργίες debug μέσω του ίδιου Test Access Port (TAP)· το boundary scan και το CPU debugging είναι σχετικές χρήσεις του JTAG, όχι συνώνυμα.<sup>[[1]](#references)</sup>

Το πρότυπο JTAG ορίζει **συγκεκριμένες εντολές για τη διεξαγωγή boundary scans**, όπως οι παρακάτω:

- **BYPASS** επιλέγει έναν bypass register ενός bit, ώστε να είναι δυνατή η πρόσβαση σε άλλες συσκευές μιας scan chain με ελάχιστο overhead.
- **SAMPLE/PRELOAD** καταγράφει τις τιμές των pins κατά την κανονική λειτουργία και μπορεί να κάνει preload τον boundary-scan register πριν από μια άλλη instruction.
- **EXTEST** ορίζει και διαβάζει τις καταστάσεις των pins.

Μπορεί επίσης να υποστηρίζει άλλες εντολές, όπως:

- **IDCODE** για την αναγνώριση μιας συσκευής
- **INTEST** για το internal testing της συσκευής

Μπορεί να συναντήσετε αυτές τις instructions όταν χρησιμοποιείτε ένα tool όπως το JTAGulator.

### Το Test Access Port

Το **Test Access Port (TAP)** παρέχει πρόσβαση στη λογική JTAG test ενός component. Απαιτούνται τέσσερα signals και το `TRST` είναι optional:<sup>[[1]](#references)</sup>

- Είσοδος test clock (**TCK**) Το TCK είναι το **clock** που καθορίζει πόσο συχνά ο TAP controller θα εκτελεί μία ενέργεια (με άλλα λόγια, θα μεταβαίνει στην επόμενη κατάσταση του state machine).
- Είσοδος test mode select (**TMS**) Το TMS ελέγχει το **finite state machine**. Σε κάθε beat του clock, ο JTAG TAP controller της συσκευής ελέγχει την τάση στο pin TMS. Αν η τάση είναι κάτω από ένα συγκεκριμένο threshold, το signal θεωρείται low και ερμηνεύεται ως 0, ενώ αν η τάση είναι πάνω από ένα συγκεκριμένο threshold, το signal θεωρείται high και ερμηνεύεται ως 1.
- Είσοδος test data (**TDI**) Μεταφέρει serial instruction ή test data στον επιλεγμένο TAP register. Το IEEE 1149.1 ορίζει τη συμπεριφορά μεταφοράς του TAP, ενώ οι vendors ορίζουν optional instructions και debug registers.
- Έξοδος test data (**TDO**) Το TDO είναι το pin που στέλνει **data out of the chip**.
- Είσοδος test reset (**TRST**) Το optional TRST επαναφέρει το finite state machine **σε μια γνωστή, σωστή κατάσταση**. Εναλλακτικά, αν το TMS παραμείνει στο 1 για πέντε συνεχόμενους κύκλους clock, ενεργοποιεί reset, με τον ίδιο τρόπο που θα το έκανε το pin TRST, γι' αυτό το TRST είναι optional.

Μερικές φορές θα μπορείτε να βρείτε αυτά τα pins σημειωμένα στο PCB. Σε άλλες περιπτώσεις μπορεί να χρειαστεί να **τα εντοπίσετε**.

### Αναγνώριση των JTAG pins

Μια γρήγορη, ειδικά σχεδιασμένη — αλλά συγκριτικά ακριβή — επιλογή για τον εντοπισμό JTAG ports είναι το **JTAGulator**, το οποίο μπορεί επίσης να αναγνωρίσει UART pinouts.<sup>[[2]](#references)</sup>

Διαθέτει **24 channels** που μπορούν να συνδεθούν σε test points της πλακέτας. Enumerates candidate pin combinations χρησιμοποιώντας **IDCODE** και **BYPASS** scans και αναφέρει τα channels που αντιστοιχούν στα JTAG signals που εντοπίστηκαν.

Ένας φθηνότερος αλλά πολύ πιο αργός τρόπος αναγνώρισης JTAG pinouts είναι η χρήση του [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) φορτωμένου σε έναν Arduino-compatible microcontroller.

Με το **JTAGenum**, αρχικά ορίστε τα pins του probing microcontroller που χρησιμοποιούνται για enumeration. Συμβουλευτείτε το pinout του και, στη συνέχεια, συνδέστε αυτά τα pins σε υποψήφια test points της target board.<sup>[[3]](#references)</sup>

Ένας **τρίτος τρόπος** αναγνώρισης των JTAG pins είναι η **επιθεώρηση του PCB** για ένα γνωστό footprint. Ορισμένες πλακέτες εκθέτουν ένα **Tag-Connect** footprint, αν και το Tag-Connect είναι connector system που μπορεί να μεταφέρει JTAG, SWD, UART ή άλλο interface — δεν αποτελεί από μόνο του απόδειξη ότι τα pins είναι JTAG. Τα datasheets των components και οι μετρήσεις continuity μπορούν, στη συνέχεια, να προσδιορίσουν τα πραγματικά signals.<sup>[[5]](#references)</sup>

## SDW

Το SWD είναι το two-pin, packet-based debug interface της Arm.<sup>[[4]](#references)</sup>

Το interface χρησιμοποιεί το bidirectional **SWDIO** για data και το **SWCLK** για το clock. Πολλές συσκευές υλοποιούν ένα **Serial Wire/JTAG Debug Port (SWJ-DP)** που επιτρέπει την επιλογή μεταξύ SWD και JTAG σε κοινά pins.<sup>[[4]](#references)</sup>

## References

- [1] [Ομάδα εργασίας IEEE 1149.1 — JTAG και boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Τεκμηρίωση JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeration JTAG pins σε Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug Interfaces με μικρό αριθμό pins για συστήματα με πολλές συσκευές](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — Footprints για debug και programming cables](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
