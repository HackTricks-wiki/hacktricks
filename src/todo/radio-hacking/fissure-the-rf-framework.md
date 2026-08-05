# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Κατανόηση και Reverse Engineering σημάτων βασισμένα σε SDR, ανεξάρτητα από τη συχνότητα**

Το FISSURE είναι ένα open-source framework για RF και reverse engineering, σχεδιασμένο για όλα τα επίπεδα δεξιοτήτων, με hooks για ανίχνευση και ταξινόμηση σημάτων, ανακάλυψη πρωτοκόλλων, εκτέλεση επιθέσεων, χειρισμό IQ, ανάλυση ευπαθειών, αυτοματοποίηση και AI/ML. Το framework δημιουργήθηκε για να προωθήσει την ταχεία ενσωμάτωση software modules, radios, πρωτοκόλλων, δεδομένων σημάτων, scripts, flow graphs, υλικού αναφοράς και εργαλείων τρίτων. Το FISSURE λειτουργεί ως workflow enabler, διατηρώντας το software σε μία τοποθεσία και επιτρέποντας στις ομάδες να εξοικειώνονται γρήγορα, ενώ μοιράζονται την ίδια δοκιμασμένη baseline configuration για συγκεκριμένες Linux distributions.<sup>[[1]](#references)[[2]](#references)</sup>

Το framework και τα εργαλεία που περιλαμβάνονται στο FISSURE έχουν σχεδιαστεί για να ανιχνεύουν την παρουσία RF energy, να κατανοούν τα χαρακτηριστικά ενός σήματος, να συλλέγουν και να αναλύουν samples, να αναπτύσσουν τεχνικές μετάδοσης και/ή injection και να δημιουργούν custom payloads ή messages. Το FISSURE περιέχει μια συνεχώς διευρυνόμενη library πληροφοριών για πρωτόκολλα και σήματα, ώστε να υποστηρίζει την αναγνώριση, το packet crafting και το fuzzing. Υπάρχουν δυνατότητες online archive για τη λήψη signal files και τη δημιουργία playlists, με σκοπό την προσομοίωση traffic και τον έλεγχο συστημάτων.

Το φιλικό Python codebase και το user interface επιτρέπουν στους αρχάριους να μάθουν γρήγορα δημοφιλή εργαλεία και τεχνικές που σχετίζονται με RF και reverse engineering. Οι εκπαιδευτικοί στον τομέα της κυβερνοασφάλειας και της μηχανικής μπορούν να αξιοποιήσουν το ενσωματωμένο υλικό ή να χρησιμοποιήσουν το framework για να παρουσιάσουν τις δικές τους εφαρμογές από τον πραγματικό κόσμο. Οι developers και οι researchers μπορούν να χρησιμοποιούν το FISSURE στις καθημερινές τους εργασίες ή να παρουσιάζουν τις cutting-edge λύσεις τους σε ένα ευρύτερο κοινό. Καθώς η ενημέρωση και η χρήση του FISSURE αυξάνονται στην κοινότητα, θα διευρύνονται τόσο οι δυνατότητές του όσο και το εύρος της τεχνολογίας που περιλαμβάνει.

**Πρόσθετες πληροφορίες**

* [Σελίδα AIS](https://www.ainfosec.com/technologies/fissure/)
* [Slides του GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Paper του GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Video του GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Transcript του Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Ξεκινώντας

**Υποστηριζόμενα**

Υπάρχουν τρία branches στο FISSURE, ώστε να διευκολύνεται η πλοήγηση στα αρχεία και να μειώνεται η redundancy στον κώδικα. Το branch Python2\_maint-3.7 περιέχει ένα codebase βασισμένο σε Python2, PyQt4 και GNU Radio 3.7· το branch Python3\_maint-3.8 βασίζεται σε Python3, PyQt5 και GNU Radio 3.8· και το branch Python3\_maint-3.10 βασίζεται σε Python3, PyQt5 και GNU Radio 3.10.

|   Λειτουργικό σύστημα   |   FISSURE Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**Σε εξέλιξη (beta)**

Αυτά τα λειτουργικά συστήματα βρίσκονται ακόμη σε κατάσταση beta. Είναι υπό ανάπτυξη και είναι γνωστό ότι λείπουν αρκετές δυνατότητες. Τα στοιχεία του installer ενδέχεται να έρχονται σε conflict με υπάρχοντα προγράμματα ή να αποτυγχάνουν να εγκατασταθούν έως ότου καταργηθεί αυτή η κατάσταση.

|     Λειτουργικό σύστημα     |    FISSURE Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

Σημείωση: Ορισμένα software tools δεν λειτουργούν σε κάθε λειτουργικό σύστημα. Ανατρέξτε στο [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)

**Εγκατάσταση**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
Αυτό θα εγκαταστήσει τις απαιτούμενες εξαρτήσεις λογισμικού PyQt για την εκκίνηση των GUI εγκατάστασης, εάν δεν εντοπιστούν.

Στη συνέχεια, επιλέξτε την επιλογή που ταιριάζει καλύτερα στο λειτουργικό σας σύστημα (θα πρέπει να εντοπιστεί αυτόματα, εάν το λειτουργικό σας σύστημα αντιστοιχεί σε κάποια επιλογή).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Συνιστάται να εγκαταστήσετε το FISSURE σε ένα καθαρό λειτουργικό σύστημα, ώστε να αποφύγετε υπάρχουσες διενέξεις. Επιλέξτε όλα τα συνιστώμενα πλαίσια ελέγχου (κουμπί Default), για να αποφύγετε σφάλματα κατά τη χρήση των διαφόρων εργαλείων στο FISSURE. Κατά την εγκατάσταση θα εμφανιστούν πολλές προτροπές, οι οποίες θα ζητούν κυρίως αυξημένα δικαιώματα και ονόματα χρηστών. Εάν ένα στοιχείο περιέχει στο τέλος μια ενότητα "Verify", το πρόγραμμα εγκατάστασης θα εκτελέσει την εντολή που ακολουθεί και θα επισημάνει το στοιχείο του πλαισίου ελέγχου με πράσινο ή κόκκινο χρώμα, ανάλογα με το αν η εντολή παρήγαγε σφάλματα. Τα επιλεγμένα στοιχεία χωρίς ενότητα "Verify" θα παραμείνουν μαύρα μετά την εγκατάσταση.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Χρήση**

Ανοίξτε ένα terminal και εισαγάγετε:
```
fissure
```
Για περισσότερες λεπτομέρειες σχετικά με τη χρήση, ανατρέξτε στο μενού Help του FISSURE.

## Λεπτομέρειες

**Στοιχεία**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Δυνατότητες**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Υλικό**

Ακολουθεί μια λίστα με το «υποστηριζόμενο» hardware, με διαφορετικά επίπεδα integration:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## Μαθήματα

Το FISSURE περιλαμβάνει αρκετούς χρήσιμους οδηγούς για την εξοικείωση με διάφορες τεχνολογίες και τεχνικές. Πολλοί περιλαμβάνουν βήματα για τη χρήση διαφόρων εργαλείων που είναι ενσωματωμένα στο FISSURE.

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

## Οδικός χάρτης

* [ ] Προσθήκη περισσότερων τύπων hardware, RF protocols, παραμέτρων σημάτων και εργαλείων ανάλυσης
* [ ] Υποστήριξη περισσότερων λειτουργικών συστημάτων
* [ ] Ανάπτυξη εκπαιδευτικού υλικού γύρω από το FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt κ.λπ.)
* [ ] Δημιουργία signal conditioner, feature extractor και signal classifier με επιλέξιμες τεχνικές AI/ML
* [ ] Υλοποίηση recursive demodulation mechanisms για την παραγωγή bitstream από άγνωστα σήματα
* [ ] Μετάβαση των βασικών στοιχείων του FISSURE σε ένα generic sensor node deployment scheme

## Συνεισφορά

Οι προτάσεις για τη βελτίωση του FISSURE ενθαρρύνονται ιδιαίτερα. Αφήστε ένα σχόλιο στη σελίδα [Discussions](https://github.com/ainfosec/FISSURE/discussions) ή στον Discord Server, αν έχετε σκέψεις σχετικά με τα παρακάτω:

* Προτάσεις για νέα features και αλλαγές σχεδιασμού
* Software tools με βήματα εγκατάστασης
* Νέα μαθήματα ή πρόσθετο υλικό για υπάρχοντα μαθήματα
* RF protocols ενδιαφέροντος
* Περισσότερο hardware και τύπους SDR για integration
* IQ analysis scripts σε Python
* Διορθώσεις και βελτιώσεις εγκατάστασης

Οι συνεισφορές για τη βελτίωση του FISSURE είναι κρίσιμες για την επιτάχυνση της ανάπτυξής του. Κάθε συνεισφορά σας εκτιμάται ιδιαίτερα. Αν επιθυμείτε να συνεισφέρετε μέσω ανάπτυξης κώδικα, κάντε fork το repo και δημιουργήστε ένα pull request:

1. Κάντε fork το project
2. Δημιουργήστε το feature branch σας (`git checkout -b feature/AmazingFeature`)
3. Κάντε commit τις αλλαγές σας (`git commit -m 'Add some AmazingFeature'`)
4. Κάντε push στο branch (`git push origin feature/AmazingFeature`)
5. Ανοίξτε ένα pull request

Η δημιουργία [Issues](https://github.com/ainfosec/FISSURE/issues) για την επισήμανση bugs είναι επίσης ευπρόσδεκτη.

## Συνεργασία

Επικοινωνήστε με το Business Development της Assured Information Security, Inc. (AIS), για να προτείνετε και να επισημοποιήσετε ευκαιρίες συνεργασίας στο FISSURE — είτε μέσω της αφιέρωσης χρόνου για το integration του software σας, είτε μέσω της ανάπτυξης λύσεων από το ταλαντούχο προσωπικό της AIS για τις τεχνικές σας προκλήσεις, είτε μέσω της ενσωμάτωσης του FISSURE σε άλλες πλατφόρμες/εφαρμογές.

## Άδεια χρήσης

GPL-3.0

Για λεπτομέρειες σχετικά με την άδεια χρήσης, δείτε το αρχείο LICENSE.

## Επικοινωνία

Γίνετε μέλος του Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Ακολουθήστε μας στο Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Συντελεστές

Αναγνωρίζουμε και ευχαριστούμε τους παρακάτω developers:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Ευχαριστίες

Ιδιαίτερες ευχαριστίες στους Dr. Samuel Mantravadi και Joseph Reith για τη συνεισφορά τους σε αυτό το project.

## Αναφορές

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
