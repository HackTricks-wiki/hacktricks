# FISSURE - Το RF Framework

**Ανεξάρτητη Συχνότητα SDR-βασισμένη Κατανόηση και Αντίστροφη Μηχανική Σημάτων**

Το FISSURE είναι ένα ανοιχτού κώδικα RF και πλαίσιο αντίστροφης μηχανικής σχεδιασμένο για όλα τα επίπεδα δεξιοτήτων με hooks για ανίχνευση και ταξινόμηση σημάτων, ανακάλυψη πρωτοκόλλων, εκτέλεση επιθέσεων, χειρισμό IQ, ανάλυση ευπαθειών, αυτοματοποίηση και AI/ML. Το πλαίσιο έχει κατασκευαστεί για να προάγει την ταχεία ενσωμάτωση λογισμικών μονάδων, ραδιοφώνων, πρωτοκόλλων, δεδομένων σημάτων, scripts, ροών γραφημάτων, υλικού αναφοράς και εργαλείων τρίτων. Το FISSURE είναι ένας επιταχυντής ροής εργασίας που διατηρεί το λογισμικό σε μία τοποθεσία και επιτρέπει στις ομάδες να προσαρμόζονται εύκολα ενώ μοιράζονται την ίδια αποδεδειγμένη βασική διαμόρφωση για συγκεκριμένες διανομές Linux.

Το πλαίσιο και τα εργαλεία που περιλαμβάνονται στο FISSURE έχουν σχεδιαστεί για να ανιχνεύουν την παρουσία RF ενέργειας, να κατανοούν τα χαρακτηριστικά ενός σήματος, να συλλέγουν και να αναλύουν δείγματα, να αναπτύσσουν τεχνικές μετάδοσης και/ή ένεσης, και να δημιουργούν προσαρμοσμένα payloads ή μηνύματα. Το FISSURE περιέχει μια αυξανόμενη βιβλιοθήκη πληροφοριών πρωτοκόλλων και σημάτων για να βοηθήσει στην αναγνώριση, τη δημιουργία πακέτων και το fuzzing. Υπάρχουν δυνατότητες online αρχείου για τη λήψη αρχείων σημάτων και τη δημιουργία playlists για την προσομοίωση κυκλοφορίας και τη δοκιμή συστημάτων.

Η φιλική βάση κώδικα Python και η διεπαφή χρήστη επιτρέπουν στους αρχάριους να μάθουν γρήγορα για δημοφιλή εργαλεία και τεχνικές που σχετίζονται με RF και αντίστροφη μηχανική. Οι εκπαιδευτές στον τομέα της κυβερνοασφάλειας και της μηχανικής μπορούν να εκμεταλλευτούν το ενσωματωμένο υλικό ή να χρησιμοποιήσουν το πλαίσιο για να επιδείξουν τις δικές τους εφαρμογές στον πραγματικό κόσμο. Οι προγραμματιστές και οι ερευνητές μπορούν να χρησιμοποιήσουν το FISSURE για τις καθημερινές τους εργασίες ή για να εκθέσουν τις πρωτοποριακές λύσεις τους σε ένα ευρύτερο κοινό. Καθώς η ευαισθητοποίηση και η χρήση του FISSURE αυξάνονται στην κοινότητα, θα αυξάνεται και η έκταση των δυνατοτήτων του και η ποικιλία της τεχνολογίας που περιλαμβάνει.

**Επιπλέον Πληροφορίες**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Ξεκινώντας

**Υποστηριζόμενα**

Υπάρχουν τρεις κλάδοι μέσα στο FISSURE για να διευκολύνουν την πλοήγηση στα αρχεία και να μειώσουν την επαναληψιμότητα του κώδικα. Ο κλάδος Python2\_maint-3.7 περιέχει μια βάση κώδικα που έχει κατασκευαστεί γύρω από Python2, PyQt4 και GNU Radio 3.7; ο κλάδος Python3\_maint-3.8 έχει κατασκευαστεί γύρω από Python3, PyQt5 και GNU Radio 3.8; και ο κλάδος Python3\_maint-3.10 έχει κατασκευαστεί γύρω από Python3, PyQt5 και GNU Radio 3.10.

|   Λειτουργικό Σύστημα   |   Κλάδος FISSURE   |
| :----------------------: | :----------------: |
|  Ubuntu 18.04 (x64)     | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64)    | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64)    | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64)    | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64)    | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64)    | Python3\_maint-3.8 |

**Σε Πρόοδο (beta)**

Αυτά τα λειτουργικά συστήματα είναι ακόμα σε κατάσταση beta. Είναι υπό ανάπτυξη και αρκετές δυνατότητες είναι γνωστό ότι λείπουν. Αντικείμενα στον εγκαταστάτη μπορεί να συγκρούονται με υπάρχοντα προγράμματα ή να αποτύχουν να εγκατασταθούν μέχρι να αφαιρεθεί η κατάσταση.

|     Λειτουργικό Σύστημα     |    Κλάδος FISSURE   |
| :--------------------------: | :-----------------: |
| DragonOS Focal (x86\_64)    |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)       | Python3\_maint-3.10 |

Σημείωση: Ορισμένα εργαλεία λογισμικού δεν λειτουργούν για κάθε OS. Ανατρέξτε σε [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Εγκατάσταση**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Αυτό θα εγκαταστήσει τις εξαρτήσεις λογισμικού PyQt που απαιτούνται για την εκκίνηση των GUI εγκατάστασης αν δεν βρεθούν.

Στη συνέχεια, επιλέξτε την επιλογή που ταιριάζει καλύτερα στο λειτουργικό σας σύστημα (θα ανιχνευθεί αυτόματα αν το λειτουργικό σας σύστημα ταιριάζει με μια επιλογή).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Συνιστάται να εγκαταστήσετε το FISSURE σε ένα καθαρό λειτουργικό σύστημα για να αποφύγετε υπάρχουσες συγκρούσεις. Επιλέξτε όλα τα συνιστώμενα πλαίσια ελέγχου (κουμπί προεπιλογής) για να αποφύγετε σφάλματα κατά τη λειτουργία των διαφόρων εργαλείων εντός του FISSURE. Θα υπάρχουν πολλαπλές προτροπές κατά τη διάρκεια της εγκατάστασης, κυρίως ζητώντας ανυψωμένα δικαιώματα και ονόματα χρηστών. Αν ένα στοιχείο περιέχει μια ενότητα "Επαλήθευση" στο τέλος, ο εγκαταστάτης θα εκτελέσει την εντολή που ακολουθεί και θα επισημάνει το στοιχείο του πλαισίου ελέγχου πράσινο ή κόκκινο ανάλογα με το αν παραχθούν σφάλματα από την εντολή. Τα ελεγμένα στοιχεία χωρίς ενότητα "Επαλήθευση" θα παραμείνουν μαύρα μετά την εγκατάσταση.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Χρήση**

Ανοίξτε ένα τερματικό και εισάγετε:
```
fissure
```
Ανατρέξτε στο μενού βοήθειας του FISSURE για περισσότερες λεπτομέρειες σχετικά με τη χρήση.

## Λεπτομέρειες

**Συστατικά**

* Πίνακας ελέγχου
* Κεντρικός κόμβος (HIPRFISR)
* Αναγνώριση σήματος στόχου (TSI)
* Ανακάλυψη πρωτοκόλλου (PD)
* Γράφημα ροής & Εκτελεστής σεναρίων (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Δυνατότητες**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Ανιχνευτής Σήματος**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Manipulation IQ**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Αναζήτηση Σήματος**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Αναγνώριση Προτύπων**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Επιθέσεις**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Λίστες Αναπαραγωγής Σήματος**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Γκαλερί Εικόνας**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Δημιουργία Πακέτων**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Ενσωμάτωση Scapy**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Υπολογιστής CRC**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Καταγραφή**_            |

**Υλικό**

Ακολουθεί μια λίστα με "υποστηριζόμενο" υλικό με διάφορα επίπεδα ενσωμάτωσης:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Αντάπτορες
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Μαθήματα

Το FISSURE συνοδεύεται από αρκετούς χρήσιμους οδηγούς για να εξοικειωθείτε με διάφορες τεχνολογίες και τεχνικές. Πολλοί περιλαμβάνουν βήματα για τη χρήση διαφόρων εργαλείων που είναι ενσωματωμένα στο FISSURE.

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)

## Οδικός Χάρτης

* [ ] Προσθήκη περισσότερων τύπων υλικού, RF πρωτοκόλλων, παραμέτρων σήματος, εργαλείων ανάλυσης
* [ ] Υποστήριξη περισσότερων λειτουργικών συστημάτων
* [ ] Ανάπτυξη υλικού μαθήματος γύρω από το FISSURE (RF Επιθέσεις, Wi-Fi, GNU Radio, PyQt, κ.λπ.)
* [ ] Δημιουργία ενός ρυθμιστή σήματος, εξαγωγέα χαρακτηριστικών και ταξινομητή σήματος με επιλεγμένες τεχνικές AI/ML
* [ ] Υλοποίηση μηχανισμών αναδρομικής αποδιαμόρφωσης για την παραγωγή bitstream από άγνωστα σήματα
* [ ] Μετάβαση των κύριων συστατικών του FISSURE σε ένα γενικό σχέδιο ανάπτυξης κόμβων αισθητήρων

## Συμμετοχή

Προτάσεις για τη βελτίωση του FISSURE είναι ιδιαίτερα ευπρόσδεκτες. Αφήστε ένα σχόλιο στη σελίδα [Discussions](https://github.com/ainfosec/FISSURE/discussions) ή στο Discord Server αν έχετε οποιαδήποτε σκέψη σχετικά με τα εξής:

* Προτάσεις νέων χαρακτηριστικών και αλλαγές σχεδίασης
* Λογισμικό εργαλεία με βήματα εγκατάστασης
* Νέα μαθήματα ή επιπλέον υλικό για υπάρχοντα μαθήματα
* RF πρωτόκολλα ενδιαφέροντος
* Περισσότερο υλικό και τύποι SDR για ενσωμάτωση
* Σενάρια ανάλυσης IQ σε Python
* Διορθώσεις και βελτιώσεις εγκατάστασης

Οι συνεισφορές για τη βελτίωση του FISSURE είναι κρίσιμες για την επιτάχυνση της ανάπτυξής του. Οποιεσδήποτε συνεισφορές κάνετε είναι πολύ εκτιμητέες. Εάν επιθυμείτε να συνεισφέρετε μέσω ανάπτυξης κώδικα, παρακαλώ κάντε fork το repo και δημιουργήστε ένα pull request:

1. Fork το έργο
2. Δημιουργήστε το branch χαρακτηριστικού σας (`git checkout -b feature/AmazingFeature`)
3. Δεσμεύστε τις αλλαγές σας (`git commit -m 'Add some AmazingFeature'`)
4. Push στο branch (`git push origin feature/AmazingFeature`)
5. Ανοίξτε ένα pull request

Η δημιουργία [Issues](https://github.com/ainfosec/FISSURE/issues) για να επιστήσει την προσοχή σε σφάλματα είναι επίσης ευπρόσδεκτη.

## Συνεργασία

Επικοινωνήστε με την Assured Information Security, Inc. (AIS) Business Development για να προτείνετε και να τυποποιήσετε οποιεσδήποτε ευκαιρίες συνεργασίας με το FISSURE–είτε μέσω αφιέρωσης χρόνου για την ενσωμάτωση του λογισμικού σας, είτε με την ανάπτυξη λύσεων για τις τεχνικές σας προκλήσεις από τους ταλαντούχους ανθρώπους της AIS, είτε με την ενσωμάτωση του FISSURE σε άλλες πλατφόρμες/εφαρμογές.

## Άδεια

GPL-3.0

Για λεπτομέρειες σχετικά με την άδεια, δείτε το αρχείο LICENSE.

## Επικοινωνία

Εγγραφείτε στο Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Ακολουθήστε στο Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Πιστώσεις

Αναγνωρίζουμε και είμαστε ευγνώμονες σε αυτούς τους προγραμματιστές:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Ευχαριστίες

Ιδιαίτερες ευχαριστίες στον Dr. Samuel Mantravadi και τον Joseph Reith για τις συνεισφορές τους σε αυτό το έργο.
