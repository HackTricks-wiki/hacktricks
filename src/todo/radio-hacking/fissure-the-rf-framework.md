# FISSURE - Το RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Κατανόηση και Reverse Engineering σημάτων βασισμένα σε SDR και ανεξάρτητα από τη συχνότητα**

Το FISSURE είναι ένα open-source RF και reverse engineering framework, σχεδιασμένο για όλα τα επίπεδα δεξιοτήτων, με hooks για ανίχνευση και ταξινόμηση σημάτων, ανακάλυψη πρωτοκόλλων, εκτέλεση επιθέσεων, χειρισμό IQ, ανάλυση ευπαθειών, αυτοματοποίηση και AI/ML. Το framework δημιουργήθηκε για να προωθήσει την ταχεία ενσωμάτωση software modules, radios, πρωτοκόλλων, signal data, scripts, flow graphs, υλικού αναφοράς και third-party tools. Το FISSURE είναι ένα workflow enabler που διατηρεί το software σε μία τοποθεσία και επιτρέπει στις ομάδες να εξοικειώνονται εύκολα, ενώ μοιράζονται την ίδια δοκιμασμένη baseline configuration για συγκεκριμένες Linux distributions.<sup>[[1]](#references)[[2]](#references)</sup>

Το framework και τα εργαλεία που περιλαμβάνονται στο FISSURE είναι σχεδιασμένα για την ανίχνευση RF ενέργειας, τον χαρακτηρισμό σημάτων, τη συλλογή και ανάλυση samples, την ανάπτυξη τεχνικών μετάδοσης ή injection και τη δημιουργία custom payloads ή messages. Το FISSURE παρέχει επίσης πληροφορίες πρωτοκόλλων και σημάτων για identification, packet crafting και fuzzing, καθώς και archives και playlists για traffic simulation και testing.<sup>[[1]](#references)[[2]](#references)</sup>

Το Python codebase και το graphical interface βοηθούν τους αρχάριους να μάθουν εργαλεία RF και reverse-engineering. Οι εκπαιδευτικοί μπορούν να χρησιμοποιούν τα ενσωματωμένα lessons, ενώ οι developers και οι researchers μπορούν να ενσωματώνουν τα δικά τους modules και workflows. Οι τρέχουσες releases υποστηρίζουν επίσης distributed sensor nodes, TAK integration, geolocation workflows και role-specific Apptainer deployments.<sup>[[1]](#references)[[3]](#references)</sup>

**Πρόσθετες πληροφορίες**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Ξεκινώντας

**Υποστηριζόμενα**

Το τρέχον FISSURE χρησιμοποιεί το **`Python3`** branch για ενεργή ανάπτυξη με PyQt5 και GNU Radio 3.8 ή 3.10. Το deprecated **`Python2_maint-3.7`** branch παραμένει διαθέσιμο για παλαιότερα λειτουργικά συστήματα και third-party tools που απαιτούν GNU Radio 3.7. Οι παλαιότερες ονομασίες branch `Python3_maint-3.8` και `Python3_maint-3.10` είναι ιστορικές. Η επιλογή maintenance του GNU Radio γίνεται πλέον από το `Python3` branch.<sup>[[1]](#references)[[3]](#references)</sup>

| Λειτουργικό Σύστημα | Κλάδος FISSURE | Προεπιλεγμένος κλάδος GNU Radio |
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

Αυτά τα λειτουργικά συστήματα βρίσκονται ακόμη σε beta status. Είναι υπό ανάπτυξη και είναι γνωστό ότι λείπουν αρκετές λειτουργίες. Τα στοιχεία του installer ενδέχεται να έρχονται σε conflict με υπάρχοντα προγράμματα ή να αποτυγχάνουν να εγκατασταθούν μέχρι να αφαιρεθεί αυτό το status.

| Λειτουργικό Σύστημα | Κλάδος FISSURE | Προεπιλεγμένος κλάδος GNU Radio |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

Ορισμένα third-party tools δεν λειτουργούν σε κάθε λειτουργικό σύστημα. Ελέγξτε την τρέχουσα τεκμηρίωση [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) πριν από την εγκατάσταση.<sup>[[3]](#references)</sup>

**Εγκατάσταση**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
Το βήμα του submodule κατεβάζει τα out-of-tree modules του GNU Radio που χρησιμοποιούνται από το FISSURE και απαιτείται κατά την εγκατάσταση αυτών των modules. Ο installer θα εγκαταστήσει επίσης τυχόν missing PyQt dependencies που απαιτούνται για την εκκίνηση των installation GUIs του.<sup>[[3]](#references)</sup>

Στη συνέχεια, επιλέξτε την option που ταιριάζει καλύτερα στο operating system σας (θα πρέπει να ανιχνευτεί αυτόματα, εάν το OS σας αντιστοιχεί σε κάποια option).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

Συνιστάται να εγκαταστήσετε το FISSURE σε clean operating system, ώστε να αποφύγετε υπάρχουσες conflicts. Επιλέξτε όλα τα recommended checkboxes (κουμπί Default), ώστε να αποφύγετε errors κατά τη χρήση των διάφορων tools μέσα στο FISSURE. Κατά τη διάρκεια της εγκατάστασης θα εμφανιστούν multiple prompts, τα οποία θα ζητούν κυρίως elevated permissions και user names. Εάν ένα item περιέχει ενότητα "Verify" στο τέλος, ο installer θα εκτελέσει την command που ακολουθεί και θα επισημάνει το checkbox item με πράσινο ή κόκκινο, ανάλογα με το αν η command παράγει errors. Τα checked items χωρίς ενότητα "Verify" θα παραμείνουν μαύρα μετά την εγκατάσταση.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**Χρήση**

Ανοίξτε ένα terminal και εισαγάγετε:
```
fissure
```
Ανατρέξτε στο μενού Help του FISSURE για περισσότερες λεπτομέρειες σχετικά με τη χρήση.

## Λεπτομέρειες

**Στοιχεία**

* Dashboard
* Central Hub (HIPRFISR)
* Αναγνώριση σήματος-στόχου (TSI)
* Ανακάλυψη πρωτοκόλλου (PD)
* Εκτελεστής Flow Graph και Script (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Δυνατότητες**

| ![Εικονίδιο ανιχνευτή σήματος](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Ανιχνευτής σήματος**_ | ![Εικονίδιο χειρισμού IQ](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**Χειρισμός IQ**_      | ![Εικονίδιο αναζήτησης σήματος](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Αναζήτηση σήματος**_          | ![Εικονίδιο αναγνώρισης μοτίβων](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Αναγνώριση μοτίβων**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Εικονίδιο επιθέσεων](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Επιθέσεις**_           | ![Εικονίδιο Fuzzing](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Εικονίδιο λιστών αναπαραγωγής σημάτων](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Λίστες αναπαραγωγής σημάτων**_       | ![Εικονίδιο συλλογής εικόνων](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Συλλογή εικόνων**_  |
| ![Εικονίδιο δημιουργίας πακέτων](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Δημιουργία πακέτων**_   | ![Εικονίδιο ενσωμάτωσης Scapy](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Ενσωμάτωση Scapy**_ | ![Εικονίδιο υπολογιστή CRC](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**Υπολογιστής CRC**_ | ![Εικονίδιο καταγραφής](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Καταγραφή**_            |

**Υλικό**

Το ακόλουθο υλικό διαθέτει διαφορετικά επίπεδα ενσωμάτωσης στο FISSURE:<sup>[[1]](#references)[[3]](#references)</sup>

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

Το FISSURE συνοδεύεται από αρκετούς χρήσιμους οδηγούς για την εξοικείωση με διαφορετικές τεχνολογίες και τεχνικές. Πολλοί περιλαμβάνουν βήματα για τη χρήση διαφόρων εργαλείων που είναι ενσωματωμένα στο FISSURE.

* [Μάθημα 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Μάθημα 2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Μάθημα 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Μάθημα 4: Πλακέτες ESP](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Μάθημα 5: Παρακολούθηση radiosonde](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Μάθημα 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Μάθημα 7: Τύποι δεδομένων](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Μάθημα 8: Προσαρμοσμένα GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Μάθημα 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Μάθημα 10: Εξετάσεις Ham Radio](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Μάθημα 11: Εργαλεία Wi-Fi](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Μάθημα 12: Δημιουργία εκκινήσιμων USB](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Μάθημα 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Μάθημα 14: Ανεμιστήρες οροφής](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Οδικός χάρτης

* [ ] Προσθήκη περισσότερων τύπων υλικού, RF πρωτοκόλλων, παραμέτρων σημάτων και εργαλείων ανάλυσης
* [ ] Υποστήριξη περισσότερων λειτουργικών συστημάτων
* [ ] Ανάπτυξη εκπαιδευτικού υλικού γύρω από το FISSURE (RF Attacks, Wi-Fi, GNU Radio, PyQt κ.λπ.)
* [ ] Δημιουργία conditioner σήματος, extractor χαρακτηριστικών και classifier σημάτων με επιλέξιμες τεχνικές AI/ML
* [ ] Υλοποίηση recursive μηχανισμών demodulation για την παραγωγή bitstream από άγνωστα σήματα
* [ ] Μετάβαση των βασικών στοιχείων του FISSURE σε ένα γενικό σχήμα ανάπτυξης sensor node

## Συνεισφορά

Οι προτάσεις για τη βελτίωση του FISSURE ενθαρρύνονται ιδιαίτερα. Αφήστε ένα σχόλιο στη σελίδα [Discussions](https://github.com/ainfosec/FISSURE/discussions) ή στον Discord Server, αν έχετε σκέψεις σχετικά με τα ακόλουθα:

* Προτάσεις για νέες δυνατότητες και αλλαγές σχεδιασμού
* Εργαλεία λογισμικού με βήματα εγκατάστασης
* Νέα μαθήματα ή πρόσθετο υλικό για υπάρχοντα μαθήματα
* RF πρωτόκολλα ενδιαφέροντος
* Περισσότερο υλικό και τύπους SDR για ενσωμάτωση
* Scripts ανάλυσης IQ σε Python
* Διορθώσεις και βελτιώσεις εγκατάστασης

Οι συνεισφορές για τη βελτίωση του FISSURE είναι κρίσιμες για την επιτάχυνση της ανάπτυξής του. Εκτιμούμε ιδιαίτερα κάθε συνεισφορά σας. Αν επιθυμείτε να συνεισφέρετε μέσω ανάπτυξης κώδικα, κάντε fork το repo και δημιουργήστε ένα pull request:

1. Κάντε fork το project
2. Δημιουργήστε το feature branch σας (`git checkout -b feature/AmazingFeature`)
3. Κάντε commit τις αλλαγές σας (`git commit -m 'Add some AmazingFeature'`)
4. Κάντε push στο branch (`git push origin feature/AmazingFeature`)
5. Ανοίξτε ένα pull request

Η δημιουργία [Issues](https://github.com/ainfosec/FISSURE/issues) για την επισήμανση bugs είναι επίσης ευπρόσδεκτη.

## Συνεργασία

Επικοινωνήστε με το Business Development της Assured Information Security, Inc. (AIS) για να προτείνετε και να επισημοποιήσετε ευκαιρίες συνεργασίας με το FISSURE - είτε μέσω αφιέρωσης χρόνου για την ενσωμάτωση του λογισμικού σας, είτε μέσω ανάπτυξης λύσεων από το ταλαντούχο προσωπικό της AIS για τις τεχνικές σας προκλήσεις, είτε μέσω ενσωμάτωσης του FISSURE σε άλλες πλατφόρμες/εφαρμογές.

## Άδεια χρήσης

GPL-3.0

Για λεπτομέρειες σχετικά με την άδεια χρήσης, ανατρέξτε στο αρχείο LICENSE.

## Επικοινωνία

Εγγραφείτε στον Discord Server: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Ακολουθήστε στο Twitter: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Συντελεστές

Αναγνωρίζουμε και ευχαριστούμε τους ακόλουθους developers:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Ευχαριστίες

Ιδιαίτερες ευχαριστίες στους Dr. Samuel Mantravadi και Joseph Reith για τη συνεισφορά τους σε αυτό το project.

## References

- [1] [FISSURE - Το RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [Έγγραφο FISSURE (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [Τεκμηρίωση FISSURE - Εγκατάσταση](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
