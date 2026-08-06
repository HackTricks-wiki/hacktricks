# Υπέρυθρες

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργούν οι υπέρυθρες <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Το υπέρυθρο φως είναι αόρατο στους ανθρώπους**. Το μήκος κύματος των IR κυμαίνεται από **0,7 έως 1000 μικρόμετρα**. Τα οικιακά τηλεχειριστήρια χρησιμοποιούν σήμα IR για τη μετάδοση δεδομένων και λειτουργούν στο εύρος μήκους κύματος 0.75..1.4 μικρομέτρων. Ένας μικροελεγκτής στο τηλεχειριστήριο κάνει ένα infrared LED να αναβοσβήνει σε συγκεκριμένη συχνότητα, μετατρέποντας το ψηφιακό σήμα σε σήμα IR.

Για τη λήψη σημάτων IR χρησιμοποιείται ένας **photoreceiver**. **Μετατρέπει το IR φως σε παλμούς τάσης**, οι οποίοι είναι ήδη **ψηφιακά σήματα**. Συνήθως υπάρχει ένα **φίλτρο σκοτεινού φωτός στο εσωτερικό του δέκτη**, το οποίο επιτρέπει να **περάσει μόνο το επιθυμητό μήκος κύματος** και αποκόπτει τον θόρυβο.<sup>[[1]](#references)</sup>

### Ποικιλία πρωτοκόλλων IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Τα πρωτόκολλα IR διαφέρουν σε 3 παράγοντες:<sup>[[1]](#references)</sup>

- κωδικοποίηση bit
- δομή δεδομένων
- συχνότητα carrier — συχνά στο εύρος 36..38 kHz

#### Τρόποι κωδικοποίησης bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Τα bit κωδικοποιούνται με τη διαμόρφωση της διάρκειας του διαστήματος μεταξύ των παλμών. Το πλάτος του ίδιου του παλμού είναι σταθερό.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Τα bit κωδικοποιούνται με τη διαμόρφωση του πλάτους του παλμού. Το πλάτος του διαστήματος μετά το pulse burst είναι σταθερό.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Είναι επίσης γνωστό ως Manchester encoding. Η λογική τιμή καθορίζεται από την πολικότητα της μετάβασης μεταξύ του pulse burst και του διαστήματος. Το "Space to pulse burst" δηλώνει λογικό "0", ενώ το "pulse burst to space" δηλώνει λογικό "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Συνδυασμός των προηγούμενων και άλλων εξωτικών**

> [!TIP]
> Υπάρχουν πρωτόκολλα IR που **προσπαθούν να γίνουν universal** για διάφορους τύπους συσκευών. Τα πιο γνωστά είναι τα RC5 και NEC. Δυστυχώς, το πιο γνωστό **δεν σημαίνει και το πιο συνηθισμένο**. Στο περιβάλλον μου συνάντησα μόλις δύο τηλεχειριστήρια NEC και κανένα RC5.
>
> Οι κατασκευαστές λατρεύουν να χρησιμοποιούν τα δικά τους μοναδικά πρωτόκολλα IR, ακόμη και μέσα στο ίδιο εύρος συσκευών (για παράδειγμα, TV-boxes). Επομένως, τηλεχειριστήρια από διαφορετικές εταιρείες και μερικές φορές από διαφορετικά μοντέλα της ίδιας εταιρείας δεν μπορούν να λειτουργήσουν με άλλες συσκευές του ίδιου τύπου.

### Εξέταση ενός σήματος IR

Ο πιο αξιόπιστος τρόπος για να δούμε πώς μοιάζει το σήμα IR ενός τηλεχειριστηρίου είναι να χρησιμοποιήσουμε έναν παλμογράφο. Δεν κάνει demodulate ούτε invert το λαμβανόμενο σήμα· απλώς το εμφανίζει "ως έχει". Αυτό είναι χρήσιμο για testing και debugging. Θα παρουσιάσω το αναμενόμενο σήμα χρησιμοποιώντας ως παράδειγμα το πρωτόκολλο IR της NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Συνήθως υπάρχει ένα preamble στην αρχή ενός encoded packet. Αυτό επιτρέπει στον δέκτη να προσδιορίσει το επίπεδο gain και το background. Υπάρχουν επίσης πρωτόκολλα χωρίς preamble, για παράδειγμα το Sharp.

Στη συνέχεια μεταδίδονται τα δεδομένα. Η δομή, το preamble και η μέθοδος κωδικοποίησης bit καθορίζονται από το συγκεκριμένο πρωτόκολλο.

Το **NEC IR protocol** περιέχει μια σύντομη εντολή και έναν repeat code, ο οποίος αποστέλλεται όσο είναι πατημένο το κουμπί. Τόσο η εντολή όσο και ο repeat code έχουν το ίδιο preamble στην αρχή.

Η **εντολή** NEC, εκτός από το preamble, αποτελείται από ένα address byte και ένα command-number byte, μέσω των οποίων η συσκευή καταλαβαίνει τι πρέπει να εκτελεστεί. Τα address και command-number bytes επαναλαμβάνονται με αντίστροφες τιμές, ώστε να ελέγχεται η ακεραιότητα της μετάδοσης. Υπάρχει ένα επιπλέον stop bit στο τέλος της εντολής.

Ο **repeat code** έχει ένα "1" μετά το preamble, το οποίο είναι stop bit.

Για τα **logic "0" και "1"**, η NEC χρησιμοποιεί Pulse Distance Encoding: αρχικά μεταδίδεται ένα pulse burst και στη συνέχεια υπάρχει μια παύση, το μήκος της οποίας καθορίζει την τιμή του bit.

### Κλιματιστικά

Σε αντίθεση με άλλα τηλεχειριστήρια, **τα κλιματιστικά δεν μεταδίδουν μόνο τον κωδικό του πατημένου κουμπιού**. Επίσης **μεταδίδουν όλες τις πληροφορίες** όταν πατιέται ένα κουμπί, ώστε να διασφαλίζεται ότι το **κλιματιστικό και το τηλεχειριστήριο είναι συγχρονισμένα**.\
Αυτό αποτρέπει την αύξηση της ρύθμισης ενός μηχανήματος από 20ºC σε 21ºC με ένα τηλεχειριστήριο και, στη συνέχεια, όταν χρησιμοποιηθεί άλλο τηλεχειριστήριο, το οποίο εξακολουθεί να έχει τη θερμοκρασία ρυθμισμένη στους 20ºC, την "αύξησή" της στους 21ºC (και όχι στους 22ºC, θεωρώντας ότι βρίσκεται στους 21ºC).<sup>[[1]](#references)</sup>

---

## Επιθέσεις & Offensive Research <a href="#attacks" id="attacks"></a>

Μπορείτε να επιτεθείτε στις Infrared με το Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Κατάληψη Smart-TV / Set-top Box (EvilScreen)

Πρόσφατη ακαδημαϊκή έρευνα (EvilScreen, 2022) απέδειξε ότι **multi-channel τηλεχειριστήρια που συνδυάζουν Infrared με Bluetooth ή Wi-Fi μπορούν να χρησιμοποιηθούν καταχρηστικά για την πλήρη κατάληψη σύγχρονων smart-TV**. Η επίθεση συνδυάζει IR service codes υψηλών προνομίων με authenticated Bluetooth packets, παρακάμπτοντας την απομόνωση καναλιών και επιτρέποντας την αυθαίρετη εκκίνηση εφαρμογών, την ενεργοποίηση του μικροφώνου ή factory-reset χωρίς φυσική πρόσβαση. Επιβεβαιώθηκε ότι οκτώ mainstream TVs από διαφορετικούς vendors —συμπεριλαμβανομένου ενός μοντέλου Samsung που δήλωνε συμμόρφωση με το ISO/IEC 27001— ήταν ευάλωτες. Για τον μετριασμό του κινδύνου απαιτούνται διορθώσεις στο firmware από τον vendor ή πλήρης απενεργοποίηση των μη χρησιμοποιούμενων IR receivers.<sup>[[2]](#references)</sup>

### Exfiltration δεδομένων από Air-Gapped συστήματα μέσω IR LEDs (οικογένεια aIR-Jumper)

Κάμερες ασφαλείας, routers ή ακόμη και κακόβουλα USB sticks συχνά περιλαμβάνουν **IR LEDs για night vision**. Η έρευνα δείχνει ότι malware μπορεί να διαμορφώσει αυτά τα LEDs (<10–20 kbit/s με απλό OOK) ώστε να **κάνει exfiltrate secrets μέσα από τοίχους και παράθυρα** προς μια εξωτερική κάμερα που βρίσκεται σε απόσταση δεκάδων μέτρων.<sup>[[3]](#references)</sup> Επειδή το φως βρίσκεται εκτός του ορατού φάσματος, οι operators σπάνια το αντιλαμβάνονται. Counter-measures:

* Θωρακίστε ή αφαιρέστε φυσικά τα IR LEDs σε ευαίσθητες περιοχές
* Παρακολουθείτε το duty-cycle των LEDs της κάμερας και την ακεραιότητα του firmware
* Εγκαταστήστε IR-cut filters σε παράθυρα και κάμερες παρακολούθησης

Ένας attacker μπορεί επίσης να χρησιμοποιήσει ισχυρούς IR projectors για να **εισάγει** commands στο δίκτυο, αναβοσβήνοντας δεδομένα προς μη ασφαλείς κάμερες.

### Brute-Force μεγάλης εμβέλειας & Extended Protocols με Flipper Zero 1.0

Το Firmware 1.0 (September 2024) πρόσθεσε **δεκάδες επιπλέον IR protocols και προαιρετικά external amplifier modules**. Σε συνδυασμό με το universal-remote brute-force mode, ένα Flipper μπορεί να απενεργοποιήσει ή να επαναρυθμίσει τις περισσότερες δημόσιες TVs/ACs από απόσταση έως 30 m, χρησιμοποιώντας diode υψηλής ισχύος.

---

## Tooling & Πρακτικά Παραδείγματα <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – φορητός transceiver με modes για learning, replay και dictionary-bruteforce (βλ. παραπάνω).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – οικονομικός DIY analyser/transmitter. Συνδυάστε το με τη βιβλιοθήκη `Arduino-IRremote` (η v4.x υποστηρίζει >40 protocols).
* **Logic analysers** (Saleae/FX2) – καταγράφουν raw timings όταν το protocol είναι άγνωστο.
* **Smartphones με IR-blaster** (π.χ. Xiaomi) – γρήγορο field test, αλλά με περιορισμένη εμβέλεια.

### Software

* **`Arduino-IRremote`** – C++ library που συντηρείται ενεργά:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI decoders που εισάγουν raw captures, αναγνωρίζουν αυτόματα το protocol και δημιουργούν κώδικα Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – λαμβάνουν και εισάγουν IR από τη γραμμή εντολών:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Απενεργοποιήστε ή καλύψτε τους IR receivers σε συσκευές που είναι εγκατεστημένες σε δημόσιους χώρους, όταν δεν απαιτούνται.
* Επιβάλετε *pairing* ή cryptographic checks μεταξύ smart-TVs και τηλεχειριστηρίων· απομονώστε τα privileged “service” codes.
* Εγκαταστήστε IR-cut filters ή continuous-wave detectors γύρω από classified περιοχές, ώστε να διακόπτονται τα optical covert channels.
* Παρακολουθείτε την ακεραιότητα του firmware σε κάμερες/IoT appliances που εκθέτουν controllable IR LEDs.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
