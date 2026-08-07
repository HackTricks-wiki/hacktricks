# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

Το JTAG επιτρέπει την εκτέλεση boundary scan. Το boundary scan αναλύει συγκεκριμένα κυκλώματα, συμπεριλαμβανομένων των ενσωματωμένων boundary-scan cells και των registers για κάθε pin.

Το πρότυπο JTAG ορίζει **συγκεκριμένες εντολές για τη διεξαγωγή boundary scans**, συμπεριλαμβανομένων των εξής:

- Το **BYPASS** σάς επιτρέπει να ελέγξετε ένα συγκεκριμένο chip χωρίς το overhead της διέλευσης από άλλα chips.
- Το **SAMPLE/PRELOAD** λαμβάνει ένα sample των δεδομένων που εισέρχονται και εξέρχονται από τη συσκευή όταν βρίσκεται στη normal functioning mode.
- Το **EXTEST** ορίζει και διαβάζει τις καταστάσεις των pins.

Μπορεί επίσης να υποστηρίζει άλλες εντολές, όπως:

- Το **IDCODE** για την αναγνώριση μιας συσκευής
- Το **INTEST** για το internal testing της συσκευής

Ενδέχεται να συναντήσετε αυτές τις εντολές όταν χρησιμοποιείτε ένα tool όπως το JTAGulator.

### Το Test Access Port

Τα boundary scans περιλαμβάνουν ελέγχους του τετρασύρματου **Test Access Port (TAP)**, ενός general-purpose port που παρέχει **access στις λειτουργίες υποστήριξης των JTAG tests** οι οποίες είναι ενσωματωμένες σε ένα component. Το TAP χρησιμοποιεί τα ακόλουθα πέντε signals:

- Είσοδος test clock (**TCK**) Το TCK είναι το **clock** που καθορίζει πόσο συχνά ο TAP controller θα εκτελεί μία ενέργεια (με άλλα λόγια, θα μεταβαίνει στην επόμενη κατάσταση του state machine).
- Είσοδος test mode select (**TMS**) Το TMS ελέγχει το **finite state machine**. Σε κάθε beat του clock, ο JTAG TAP controller της συσκευής ελέγχει την τάση στο TMS pin. Αν η τάση είναι κάτω από ένα συγκεκριμένο threshold, το signal θεωρείται low και ερμηνεύεται ως 0, ενώ αν η τάση είναι πάνω από ένα συγκεκριμένο threshold, το signal θεωρείται high και ερμηνεύεται ως 1.
- Είσοδος test data (**TDI**) Το TDI είναι το pin που στέλνει **data στο chip μέσω των scan cells**. Κάθε vendor είναι υπεύθυνος για τον ορισμό του communication protocol μέσω αυτού του pin, επειδή το JTAG δεν το ορίζει.
- Έξοδος test data (**TDO**) Το TDO είναι το pin που στέλνει **data έξω από το chip**.
- Είσοδος test reset (**TRST**) Το προαιρετικό TRST επαναφέρει το finite state machine **σε μια γνωστή και λειτουργική κατάσταση**. Εναλλακτικά, αν το TMS παραμείνει στο 1 για πέντε διαδοχικούς κύκλους clock, ενεργοποιεί ένα reset, όπως ακριβώς θα έκανε το TRST pin, γι’ αυτό και το TRST είναι προαιρετικό.

Μερικές φορές θα μπορείτε να βρείτε αυτά τα pins σημειωμένα στο PCB. Σε άλλες περιπτώσεις μπορεί να χρειαστεί να **τα βρείτε**.

### Identifying JTAG pins

Ο ταχύτερος αλλά ακριβότερος τρόπος εντοπισμού JTAG ports είναι η χρήση του **JTAGulator**, μιας συσκευής που δημιουργήθηκε ειδικά για αυτόν τον σκοπό (αν και μπορεί να **ανιχνεύσει επίσης UART pinouts**).

Διαθέτει **24 channels** τα οποία μπορείτε να συνδέσετε στα pins των boards. Στη συνέχεια εκτελεί μια **BF attack** σε όλους τους πιθανούς συνδυασμούς, στέλνοντας τις εντολές **IDCODE** και **BYPASS** του boundary scan. Αν λάβει απάντηση, εμφανίζει το channel που αντιστοιχεί σε κάθε JTAG signal.

Ένας φθηνότερος αλλά πολύ πιο αργός τρόπος αναγνώρισης JTAG pinouts είναι η χρήση του [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) φορτωμένου σε έναν Arduino-compatible microcontroller.

Χρησιμοποιώντας το **JTAGenum**, αρχικά θα πρέπει να **ορίσετε τα pins της probing** συσκευής που θα χρησιμοποιήσετε για την enumeration. Θα πρέπει να συμβουλευτείτε το pinout diagram της συσκευής και, στη συνέχεια, να συνδέσετε αυτά τα pins με τα test points της target device.

Ένας **τρίτος τρόπος** αναγνώρισης JTAG pins είναι η **επιθεώρηση του PCB** για ένα από τα pinouts. Σε ορισμένες περιπτώσεις, τα PCBs μπορεί να παρέχουν βολικά το **Tag-Connect interface**, κάτι που αποτελεί σαφή ένδειξη ότι το board διαθέτει επίσης JTAG connector. Μπορείτε να δείτε πώς μοιάζει αυτό το interface στη διεύθυνση [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Επιπλέον, η επιθεώρηση των **datasheets των chipsets στο PCB** μπορεί να αποκαλύψει pinout diagrams που υποδεικνύουν JTAG interfaces.

## SDW

Το SWD είναι ένα ARM-specific protocol σχεδιασμένο για debugging.

Το SWD interface απαιτεί **δύο pins**: ένα bidirectional **SWDIO** signal, το οποίο είναι το αντίστοιχο των **TDI και TDO pins του JTAG, καθώς και ενός clock**, και το **SWCLK**, το οποίο είναι το αντίστοιχο του **TCK** στο JTAG. Πολλές συσκευές υποστηρίζουν το **Serial Wire or JTAG Debug Port (SWJ-DP)**, ένα combined JTAG και SWD interface που σας επιτρέπει να συνδέσετε είτε ένα SWD είτε ένα JTAG probe στο target.

{{#include ../../banners/hacktricks-training.md}}
