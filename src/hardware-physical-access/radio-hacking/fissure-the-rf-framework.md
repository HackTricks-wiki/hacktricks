# FISSURE - Το RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Κατανόηση και αντίστροφη μηχανική σημάτων με βάση SDR, ανεξάρτητα από τη συχνότητα**

Το FISSURE είναι ένα framework ανοικτού κώδικα για RF και αντίστροφη μηχανική, σχεδιασμένο για όλα τα επίπεδα δεξιοτήτων, με δυνατότητες για ανίχνευση και ταξινόμηση σημάτων, ανακάλυψη πρωτοκόλλων, εκτέλεση επιθέσεων, χειρισμό IQ, ανάλυση ευπαθειών, αυτοματοποίηση και AI/ML. Το framework δημιουργήθηκε για να προωθήσει την ταχεία ενσωμάτωση μονάδων λογισμικού, radios, πρωτοκόλλων, δεδομένων σημάτων, scripts, flow graphs, υλικού αναφοράς και εργαλείων τρίτων. Το FISSURE διευκολύνει τη ροή εργασιών, διατηρώντας το λογισμικό σε μία τοποθεσία και επιτρέποντας στις ομάδες να εξοικειώνονται γρήγορα, ενώ μοιράζονται την ίδια δοκιμασμένη βασική διαμόρφωση για συγκεκριμένες διανομές Linux.<sup>[[1]](#references)[[2]](#references)</sup>

Το framework και τα εργαλεία που περιλαμβάνει το FISSURE έχουν σχεδιαστεί για να ανιχνεύουν ενέργεια RF, να χαρακτηρίζουν σήματα, να συλλέγουν και να αναλύουν δείγματα, να αναπτύσσουν τεχνικές μετάδοσης ή injection και να δημιουργούν προσαρμοσμένα payloads ή μηνύματα. Το FISSURE παρέχει επίσης πληροφορίες για πρωτόκολλα και σήματα, για αναγνώριση, δημιουργία πακέτων και fuzzing, καθώς και αρχεία και playlists για προσομοίωση και δοκιμή κίνησης.<sup>[[1]](#references)[[2]](#references)</sup>

Η βάση κώδικα Python και το γραφικό περιβάλλον βοηθούν τους αρχάριους να μάθουν εργαλεία RF και αντίστροφης μηχανικής. Οι εκπαιδευτές μπορούν να αξιοποιήσουν τα ενσωματωμένα μαθήματα, ενώ οι προγραμματιστές και οι ερευνητές μπορούν να ενσωματώσουν τις δικές τους μονάδες και ροές εργασιών. Οι τρέχουσες εκδόσεις υποστηρίζουν επίσης κατανεμημένους αισθητήρες, ενσωμάτωση TAK, ροές εργασιών γεωεντοπισμού και αναπτύξεις Apptainer ειδικά για κάθε ρόλο.<sup>[[1]](#references)[[3]](#references)</sup>

**Πρόσθετες πληροφορίες**

* [Σελίδα AIS](https://www.ainfosec.com/technologies/fissure/)
* [Παρουσίαση GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [Άρθρο GRCon22](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [Βίντεο GRCon22](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Απομαγνητοφώνηση Hack Chat](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Ξεκινώντας

**Υποστηρίζονται**

Η τρέχουσα έκδοση του FISSURE χρησιμοποιεί τον κλάδο **`Python3`** για ενεργή ανάπτυξη με PyQt5 και GNU Radio 3.8 ή 3.10. Ο παρωχημένος κλάδος **`Python2_maint-3.7`** παραμένει διαθέσιμος για παλαιότερα λειτουργικά συστήματα και εργαλεία τρίτων που απαιτούν GNU Radio 3.7. Οι παλαιότερες ονομασίες κλάδων `Python3_maint-3.8` και `Python3_maint-3.10` είναι ιστορικές· η επιλογή έκδοσης συντήρησης GNU Radio γίνεται πλέον από τον κλάδο `Python3`.<sup>[[1]](#references)[[3]](#references)</sup>

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | use a supported Linux version | use the matching version |

**Σε εξέλιξη (beta)**

Αυτά τα λειτουργικά συστήματα βρίσκονται ακόμη σε κατάσταση beta. Είναι υπό ανάπτυξη και είναι γνωστό ότι αρκετές λειτουργίες απουσιάζουν. Στοιχεία του installer ενδέχεται να έρχονται σε διένεξη με υπάρχοντα προγράμματα ή να μην εγκαθίστανται μέχρι να αρθεί αυτή η κατάσταση.

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Ορισμένα εργαλεία τρίτων δεν λειτουργούν σε όλα τα λειτουργικά συστήματα. Πριν από την εγκατάσταση, συμβουλευτείτε την τρέχουσα τεκμηρίωση [Γνωστές διενέξεις και λογισμικό τρίτων](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts).<sup>[[3]](#references)</sup>

**Εγκατάσταση**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

Το βήμα του submodule κατεβάζει τα out-of-tree modules του GNU Radio που χρησιμοποιεί το FISSURE και απαιτείται κατά την εγκατάσταση αυτών των modules. Το πρόγραμμα εγκατάστασης θα εγκαταστήσει επίσης τυχόν εξαρτήσεις PyQt που λείπουν και είναι απαραίτητες για την εκκίνηση των GUI εγκατάστασης.<sup>[[3]](#references)</sup>

Στη συνέχεια, επιλέξτε την επιλογή που ταιριάζει καλύτερα στο λειτουργικό σας σύστημα (θα πρέπει να εντοπιστεί αυτόματα, αν το λειτουργικό σας σύστημα αντιστοιχεί σε κάποια επιλογή).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Συνιστάται να εγκαταστήσετε το FISSURE σε καθαρό λειτουργικό σύστημα, ώστε να αποφύγετε υπάρχουσες διενέξεις. Επιλέξτε όλα τα προτεινόμενα πλαίσια ελέγχου (κουμπί Default), για να αποφύγετε σφάλματα κατά τη χρήση των διαφόρων εργαλείων του FISSURE. Κατά τη διάρκεια της εγκατάστασης θα εμφανιστούν πολλές προτροπές, οι περισσότερες από τις οποίες θα ζητούν αυξημένα δικαιώματα και ονόματα χρηστών. Αν ένα στοιχείο περιλαμβάνει ενότητα "Verify" στο τέλος, το πρόγραμμα εγκατάστασης θα εκτελέσει την εντολή που ακολουθεί και θα επισημάνει το πλαίσιο ελέγχου του στοιχείου με πράσινο ή κόκκινο χρώμα, ανάλογα με το αν η εντολή εμφανίσει σφάλματα. Τα επιλεγμένα στοιχεία χωρίς ενότητα "Verify" θα παραμείνουν μαύρα μετά την εγκατάσταση.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Χρήση**

Ανοίξτε ένα τερματικό και πληκτρολογήστε:

```
fissure
```

Για περισσότερες λεπτομέρειες σχετικά με τη χρήση, ανατρέξτε στο μενού Help του FISSURE.

## Λεπτομέρειες

**Στοιχεία**

* Dashboard
* Κεντρικός κόμβος (HIPRFISR)
* Αναγνώριση σήματος-στόχου (TSI)
* Ανακάλυψη πρωτοκόλλων (PD)
* Flow Graph & εκτέλεση Script (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Δυνατότητες**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Ανιχνευτής σήματος**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Επεξεργασία IQ**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Αναζήτηση σήματος**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Αναγνώριση προτύπων**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Επιθέσεις**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Λίστες αναπαραγωγής σημάτων**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Συλλογή εικόνων**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Δημιουργία πακέτων**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Ενσωμάτωση Scapy**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Υπολογιστής CRC**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Καταγραφή**_            |

**Υλικό**

Το παρακάτω υλικό έχει διαφορετικά επίπεδα ενσωμάτωσης στο FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* Προσαρμογείς 802.11
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Μαθήματα

Το FISSURE περιλαμβάνει αρκετούς χρήσιμους οδηγούς για την εξοικείωση με διάφορες τεχνολογίες και τεχνικές. Πολλοί περιλαμβάνουν βήματα για τη χρήση διαφόρων εργαλείων που είναι ενσωματωμένα στο FISSURE.

* [Μάθημα 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Μάθημα 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Μάθημα 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Μάθημα 4: Πλακέτες ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Μάθημα 5: Παρακολούθηση Radiosonde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Μάθημα 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Μάθημα 7: Τύποι δεδομένων](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Μάθημα 8: Προσαρμοσμένα μπλοκ GNU Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Μάθημα 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Μάθημα 10: Εξετάσεις Ham Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Μάθημα 11: Εργαλεία Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Μάθημα 12: Δημιουργία εκκινήσιμων USB](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Μάθημα 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Μάθημα 14: Ανεμιστήρες οροφής](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Οδικός χάρτης

* [ ] Προσθήκη περισσότερων τύπων υλικού, πρωτοκόλλων RF, παραμέτρων σημάτων και εργαλείων ανάλυσης
* [ ] Υποστήριξη περισσότερων λειτουργικών συστημάτων
* [ ] Ανάπτυξη εκπαιδευτικού υλικού γύρω από το FISSURE (επιθέσεις RF, Wi-Fi, GNU Radio, PyQt κ.λπ.)
* [ ] Δημιουργία ενός signal conditioner, ενός feature extractor και ενός signal classifier με επιλέξιμες τεχνικές AI/ML
* [ ] Υλοποίηση μηχανισμών αναδρομικής αποδιαμόρφωσης για την παραγωγή bitstream από άγνωστα σήματα
* [ ] Μετάβαση των κύριων στοιχείων του FISSURE σε ένα σχήμα ανάπτυξης γενικών κόμβων αισθητήρων

## Συνεισφορά

Οι προτάσεις για τη βελτίωση του FISSURE είναι ιδιαίτερα ευπρόσδεκτες. Αφήστε ένα σχόλιο στη σελίδα [Συζητήσεις](https://github.com/ainfosec/FISSURE/discussions) ή στον Discord Server, αν έχετε προτάσεις σχετικά με τα εξής:

* Προτάσεις νέων δυνατοτήτων και αλλαγές σχεδιασμού
* Εργαλεία λογισμικού μαζί με οδηγίες εγκατάστασης
* Νέα μαθήματα ή πρόσθετο υλικό για υπάρχοντα μαθήματα
* Πρωτόκολλα RF που σας ενδιαφέρουν
* Περισσότερο υλικό και τύποι SDR προς ενσωμάτωση
* Scripts ανάλυσης IQ σε Python
* Διορθώσεις και βελτιώσεις στην εγκατάσταση

Οι συνεισφορές για τη βελτίωση του FISSURE είναι απαραίτητες για την επιτάχυνση της ανάπτυξής του. Εκτιμούμε ιδιαίτερα κάθε συνεισφορά σας. Αν θέλετε να συνεισφέρετε στον κώδικα, κάντε fork το repo και δημιουργήστε ένα pull request:

1. Κάντε fork το project
2. Δημιουργήστε το branch της δυνατότητάς σας (`git checkout -b feature/AmazingFeature`)
3. Κάντε commit τις αλλαγές σας (`git commit -m 'Add some AmazingFeature'`)
4. Κάντε push στο branch (`git push origin feature/AmazingFeature`)
5. Ανοίξτε ένα pull request

Είναι επίσης ευπρόσδεκτη η δημιουργία [Issues](https://github.com/ainfosec/FISSURE/issues) για την επισήμανση σφαλμάτων.

## Συνεργασία

Επικοινωνήστε με το τμήμα επιχειρηματικής ανάπτυξης της Assured Information Security, Inc. (AIS) για να προτείνετε και να επισημοποιήσετε ευκαιρίες συνεργασίας στο FISSURE — είτε προσφέροντας χρόνο για την ενσωμάτωση του λογισμικού σας, είτε αναθέτοντας στους ταλαντούχους ανθρώπους της AIS την ανάπτυξη λύσεων για τις τεχνικές σας προκλήσεις, είτε ενσωματώνοντας το FISSURE σε άλλες πλατφόρμες/εφαρμογές.

## Άδεια χρήσης

GPL-3.0

Για λεπτομέρειες σχετικά με την άδεια χρήσης, δείτε το αρχείο LICENSE.

## Επικοινωνία

Εγγραφείτε στον Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Ακολουθήστε μας στο Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Επιχειρηματική ανάπτυξη - Assured Information Security, Inc. - bd@ainfosec.com

## Συντελεστές

Αναγνωρίζουμε και ευχαριστούμε τους παρακάτω προγραμματιστές:

[Συντελεστές](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Ευχαριστίες

Ιδιαίτερες ευχαριστίες στους Dr. Samuel Mantravadi και Joseph Reith για τη συνεισφορά τους σε αυτό το έργο.

## References

- [1] [FISSURE - Το RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Άρθρο για το FISSURE (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Τεκμηρίωση FISSURE - Εγκατάσταση](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
