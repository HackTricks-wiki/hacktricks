# Υπέρυθρες

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργούν οι υπέρυθρες <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Το υπέρυθρο φως είναι αόρατο για τους ανθρώπους**. Το μήκος κύματος IR κυμαίνεται από **0,7 έως 1000 μικρά**. Τα οικιακά τηλεχειριστήρια χρησιμοποιούν σήμα IR για τη μετάδοση δεδομένων και λειτουργούν στο εύρος μήκους κύματος 0.75..1.4 μικρών. Ένας microcontroller στο τηλεχειριστήριο κάνει ένα infrared LED να αναβοσβήνει σε συγκεκριμένη συχνότητα, μετατρέποντας το ψηφιακό σήμα σε σήμα IR.

Για τη λήψη σημάτων IR χρησιμοποιείται ένας **photoreceiver**. **Μετατρέπει το υπέρυθρο φως σε παλμούς τάσης**, οι οποίοι είναι ήδη **ψηφιακά σήματα**. Συνήθως, στο εσωτερικό του receiver υπάρχει ένα **φίλτρο σκοτεινού φωτός**, το οποίο επιτρέπει να **περάσει μόνο το επιθυμητό μήκος κύματος** και αποκόπτει τον θόρυβο.<sup>[[1]](#references)</sup>

### Ποικιλία πρωτοκόλλων IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Τα πρωτόκολλα IR διαφέρουν σε 3 παράγοντες:<sup>[[1]](#references)</sup>

- κωδικοποίηση bit
- δομή δεδομένων
- συχνότητα carrier — συχνά στο εύρος 36..38 kHz

#### Τρόποι κωδικοποίησης bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Τα bits κωδικοποιούνται με τη διαμόρφωση της διάρκειας του κενού μεταξύ των παλμών. Το πλάτος του ίδιου του παλμού παραμένει σταθερό.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Τα bits κωδικοποιούνται με τη διαμόρφωση του πλάτους του παλμού. Το πλάτος του κενού μετά το pulse burst παραμένει σταθερό.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Είναι επίσης γνωστό ως Manchester encoding. Η λογική τιμή καθορίζεται από την πολικότητα της μετάβασης μεταξύ του pulse burst και του κενού. Το "κενό προς pulse burst" δηλώνει λογικό "0", ενώ το "pulse burst προς κενό" δηλώνει λογικό "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Συνδυασμός των προηγούμενων και άλλων εξωτικών μεθόδων**

> [!TIP]
> Υπάρχουν πρωτόκολλα IR που **προσπαθούν να γίνουν universal** για διάφορους τύπους συσκευών. Τα πιο γνωστά είναι τα RC5 και NEC. Δυστυχώς, το πιο γνωστό **δεν σημαίνει και το πιο συνηθισμένο**. Στο περιβάλλον μου, συνάντησα μόνο δύο τηλεχειριστήρια NEC και κανένα RC5.
>
> Οι κατασκευαστές προτιμούν να χρησιμοποιούν τα δικά τους μοναδικά πρωτόκολλα IR, ακόμη και μέσα στο ίδιο εύρος συσκευών (για παράδειγμα, TV-boxes). Επομένως, τηλεχειριστήρια από διαφορετικές εταιρείες και μερικές φορές από διαφορετικά μοντέλα της ίδιας εταιρείας, δεν μπορούν να λειτουργήσουν με άλλες συσκευές του ίδιου τύπου.

### Εξέταση ενός σήματος IR

Ο πιο αξιόπιστος τρόπος για να δούμε πώς εμφανίζεται το σήμα IR ενός τηλεχειριστηρίου είναι να χρησιμοποιήσουμε έναν oscilloscope. Δεν κάνει demodulate ούτε invert το λαμβανόμενο σήμα· απλώς το εμφανίζει "ως έχει". Αυτό είναι χρήσιμο για testing και debugging. Θα παρουσιάσω το αναμενόμενο σήμα με βάση το πρωτόκολλο IR NEC.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Συνήθως, στην αρχή ενός encoded packet υπάρχει ένα preamble. Αυτό επιτρέπει στον receiver να καθορίσει το επίπεδο gain και το background. Υπάρχουν επίσης πρωτόκολλα χωρίς preamble, όπως το Sharp.

Στη συνέχεια μεταδίδονται τα δεδομένα. Η δομή, το preamble και η μέθοδος κωδικοποίησης bit καθορίζονται από το συγκεκριμένο πρωτόκολλο.

Το **πρωτόκολλο IR NEC** περιέχει μια σύντομη εντολή και έναν repeat code, ο οποίος αποστέλλεται όσο το κουμπί παραμένει πατημένο. Τόσο η εντολή όσο και ο repeat code έχουν το ίδιο preamble στην αρχή.

Η **εντολή** NEC, εκτός από το preamble, αποτελείται από ένα byte διεύθυνσης και ένα byte αριθμού εντολής, μέσω των οποίων η συσκευή κατανοεί τι πρέπει να εκτελεστεί. Τα bytes διεύθυνσης και αριθμού εντολής επαναλαμβάνονται με αντίστροφες τιμές, ώστε να ελέγχεται η ακεραιότητα της μετάδοσης. Στο τέλος της εντολής υπάρχει ένα επιπλέον stop bit.

Ο **repeat code** έχει ένα "1" μετά το preamble, το οποίο είναι stop bit.

Για τα **λογικά "0" και "1"**, το NEC χρησιμοποιεί Pulse Distance Encoding: πρώτα μεταδίδεται ένα pulse burst και στη συνέχεια υπάρχει μια παύση, το μήκος της οποίας καθορίζει την τιμή του bit.

### Κλιματιστικά

Σε αντίθεση με άλλα τηλεχειριστήρια, **τα κλιματιστικά δεν μεταδίδουν μόνο τον κωδικό του πατημένου κουμπιού**. Επίσης **μεταδίδουν όλες τις πληροφορίες** κατά το πάτημα ενός κουμπιού, ώστε να διασφαλίζεται ότι **η μονάδα κλιματισμού και το τηλεχειριστήριο είναι συγχρονισμένα**.\
Αυτό αποτρέπει την αύξηση της ρύθμισης μιας μονάδας από 20ºC σε 21ºC με ένα τηλεχειριστήριο και, στη συνέχεια, όταν χρησιμοποιηθεί άλλο τηλεχειριστήριο που εξακολουθεί να έχει τη θερμοκρασία ρυθμισμένη στους 20ºC για περαιτέρω αύξηση, η θερμοκρασία να "αυξηθεί" στους 21ºC (αντί για 22ºC, επειδή θεωρεί ότι είναι ήδη στους 21ºC).<sup>[[1]](#references)</sup>

---

## Επιθέσεις και Offensive Research <a href="#attacks" id="attacks"></a>

Μπορείτε να επιτεθείτε σε συσκευές Infrared με το Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Takeover Smart-TV / Set-top Box (EvilScreen)

Πρόσφατη ακαδημαϊκή έρευνα (EvilScreen, 2022) απέδειξε ότι **multi-channel τηλεχειριστήρια που συνδυάζουν Infrared με Bluetooth ή Wi-Fi μπορούν να χρησιμοποιηθούν καταχρηστικά για την πλήρη hijacking σύγχρονων smart-TV**. Η επίθεση συνδυάζει IR service codes υψηλών προνομίων με authenticated Bluetooth packets, παρακάμπτοντας το channel-isolation και επιτρέποντας την εκκίνηση αυθαίρετων εφαρμογών, την ενεργοποίηση του μικροφώνου ή factory-reset χωρίς φυσική πρόσβαση. Επιβεβαιώθηκε ότι οκτώ mainstream TVs από διαφορετικούς vendors — συμπεριλαμβανομένου ενός μοντέλου Samsung που δήλωνε συμμόρφωση με το ISO/IEC 27001 — ήταν ευάλωτες. Η αντιμετώπιση απαιτεί διορθώσεις firmware από τον vendor ή πλήρη απενεργοποίηση των μη χρησιμοποιούμενων IR receivers.<sup>[[2]](#references)</sup>

### Exfiltration δεδομένων μέσω IR LEDs από Air-Gapped συστήματα (οικογένεια aIR-Jumper)

Οι κάμερες ασφαλείας περιλαμβάνουν συχνά **IR LEDs για night vision**. Το πρωτότυπο aIR-Jumper έδειξε ότι malware που ελέγχει αυτά τα LEDs μπορεί να **κάνει exfiltrate secrets μέσω παραθύρων** προς εξωτερική κάμερα με ταχύτητα έως **20 bit/s ανά κάμερα παρακολούθησης**, σε απόσταση δεκάδων μέτρων. Προς την αντίστροφη κατεύθυνση, οι ερευνητές απέδειξαν infiltration με ταχύτητα άνω των **100 bit/s**, σε αποστάσεις από εκατοντάδες μέτρα έως χιλιόμετρα.<sup>[[3]](#references)</sup> Επειδή το φως βρίσκεται εκτός του ορατού φάσματος, οι operators ενδέχεται να μην το αντιληφθούν. Τα countermeasures περιλαμβάνουν:

* Φυσική θωράκιση ή αφαίρεση των IR LEDs σε ευαίσθητους χώρους
* Παρακολούθηση του duty-cycle των LEDs της κάμερας και της ακεραιότητας του firmware
* Ανάπτυξη IR-cut filters σε παράθυρα και κάμερες παρακολούθησης

Ένας attacker μπορεί επίσης να χρησιμοποιήσει ισχυρούς IR projectors για να **κάνει infiltrate** commands στο network, αναβοσβήνοντας δεδομένα προς μη ασφαλείς κάμερες.

### Long-Range Brute-Force και Extended Protocols με Flipper Zero 1.0

Το firmware 1.0 (Σεπτέμβριος 2024) επέκτεινε τη βιβλιοθήκη universal-remotes και πρόσθεσε dynamic loading αρχείων infrared assets από microSD.<sup>[[4]](#references)</sup> Οι λειτουργίες learning και universal-remote μπορούν να κάνουν replay ή να δοκιμάσουν γνωστές εντολές σε κοντινές TVs και κλιματιστικά. Η εμβέλεια εξαρτάται σε μεγάλο βαθμό από τον emitter, τα optics, το ambient light και τον receiver· εξωτερικό IR hardware μπορεί να την επεκτείνει, αλλά δεν πρέπει να θεωρείται δεδομένη κάποια σταθερή απόσταση.

---

## Εργαλεία και Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – portable transceiver με λειτουργίες learning, replay και dictionary-bruteforce (βλ. παραπάνω).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – φθηνός DIY analyser/transmitter. Συνδυάζεται με τη βιβλιοθήκη `Arduino-IRremote` (η v4.x υποστηρίζει >40 protocols).
* **Logic analysers** (Saleae/FX2) – καταγραφή raw timings όταν το protocol είναι άγνωστο.
* **Smartphones με IR-blaster** (π.χ. Xiaomi) – γρήγορο field test, αλλά με περιορισμένη εμβέλεια.

### Software

* **`Arduino-IRremote`** – ενεργά συντηρούμενη βιβλιοθήκη C++:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI decoders που εισάγουν raw captures, αναγνωρίζουν αυτόματα το protocol και δημιουργούν κώδικα Pronto/Arduino.
* **LIRC / ir-keytable (Linux)** – λήψη και injection IR από τη γραμμή εντολών:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Αμυντικά μέτρα <a href="#defense" id="defense"></a>

* Απενεργοποιήστε ή καλύψτε τους IR receivers σε συσκευές που έχουν εγκατασταθεί σε δημόσιους χώρους, όταν δεν απαιτούνται.
* Επιβάλετε *pairing* ή cryptographic checks μεταξύ smart-TVs και τηλεχειριστηρίων· απομονώστε τα privileged “service” codes.
* Αναπτύξτε IR-cut filters ή continuous-wave detectors γύρω από classified areas, ώστε να διακόπτονται τα optical covert channels.
* Παρακολουθείτε την ακεραιότητα του firmware καμερών/IoT appliances που διαθέτουν controllable IR LEDs.

## References

- [1] [Άρθρο blog του Flipper Zero για τις Infrared](https://blog.flipperzero.one/infrared/)
- [2] [Επίθεση EvilScreen: Hijacking Smart TV μέσω Mimicry Multi-channel Remote Control (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration μέσω Security Cameras και Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Blog Flipper Zero - Κυκλοφόρησε το Firmware 1.0](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - τεκμηρίωση χρήσης και πρωτοκόλλων](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
