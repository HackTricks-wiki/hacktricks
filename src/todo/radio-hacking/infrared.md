# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Πώς λειτουργεί το Infrared <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Το Infrared φως είναι αόρατο για τους ανθρώπους**. Το μήκος κύματος IR κυμαίνεται από **0.7 έως 1000 microns**. Τα οικιακά τηλεχειριστήρια χρησιμοποιούν σήμα IR για μετάδοση δεδομένων και λειτουργούν στην περιοχή μήκους κύματος 0.75..1.4 microns. Ένας microcontroller στο τηλεχειριστήριο κάνει ένα infrared LED να αναβοσβήνει με συγκεκριμένη συχνότητα, μετατρέποντας το digital signal σε σήμα IR.<sup>[[1]](#references)</sup>

Για τη λήψη σημάτων IR χρησιμοποιείται ένας **photoreceiver**. **Μετατρέπει το IR φως σε voltage pulses**, τα οποία είναι ήδη **digital signals**. Συνήθως, στο εσωτερικό του receiver υπάρχει ένα **dark light filter**, το οποίο επιτρέπει να περάσει **μόνο το επιθυμητό μήκος κύματος** και αποκόπτει τον θόρυβο.

### Ποικιλία IR Protocols <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Τα IR protocols διαφέρουν σε 3 παράγοντες:

- bit encoding
- data structure
- carrier frequency — συχνά στην περιοχή 36..38 kHz

#### Τρόποι Bit Encoding <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

Τα bits κωδικοποιούνται με modulation της διάρκειας του κενού μεταξύ των pulses. Το πλάτος του ίδιου του pulse είναι σταθερό.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

Τα bits κωδικοποιούνται με modulation του πλάτους του pulse. Το πλάτος του κενού μετά το pulse burst είναι σταθερό.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Είναι επίσης γνωστό ως Manchester encoding. Η λογική τιμή καθορίζεται από την πολικότητα της μετάβασης μεταξύ pulse burst και κενού. Το "Space to pulse burst" δηλώνει logic "0", ενώ το "pulse burst to space" δηλώνει logic "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Συνδυασμός των προηγούμενων και άλλων εξωτικών μεθόδων**

> [!TIP]
> Υπάρχουν IR protocols που **προσπαθούν να γίνουν universal** για διάφορους τύπους συσκευών. Τα πιο γνωστά είναι τα RC5 και NEC. Δυστυχώς, το ότι είναι τα πιο γνωστά **δεν σημαίνει ότι είναι και τα πιο συνηθισμένα**. Στο περιβάλλον μου, συνάντησα μόνο δύο NEC remotes και κανένα RC5.
>
> Οι κατασκευαστές προτιμούν να χρησιμοποιούν τα δικά τους μοναδικά IR protocols, ακόμη και μέσα στην ίδια κατηγορία συσκευών (για παράδειγμα, TV-boxes). Επομένως, remotes από διαφορετικές εταιρείες και μερικές φορές από διαφορετικά μοντέλα της ίδιας εταιρείας δεν μπορούν να λειτουργήσουν με άλλες συσκευές του ίδιου τύπου.

### Εξερεύνηση ενός IR signal

Ο πιο αξιόπιστος τρόπος για να δούμε πώς είναι το IR signal ενός remote είναι να χρησιμοποιήσουμε oscilloscope. Δεν κάνει demodulation ή inversion του ληφθέντος signal· απλώς το εμφανίζει "as is". Αυτό είναι χρήσιμο για testing και debugging. Θα δείξω το αναμενόμενο signal χρησιμοποιώντας ως παράδειγμα το NEC IR protocol.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Συνήθως, στην αρχή ενός encoded packet υπάρχει ένα preamble. Αυτό επιτρέπει στον receiver να καθορίσει το επίπεδο του gain και του background. Υπάρχουν επίσης protocols χωρίς preamble, για παράδειγμα το Sharp.

Στη συνέχεια μεταδίδονται τα δεδομένα. Η δομή, το preamble και η μέθοδος bit encoding καθορίζονται από το συγκεκριμένο protocol.

Το **NEC IR protocol** περιέχει μια σύντομη command και έναν repeat code, ο οποίος αποστέλλεται όσο το button παραμένει πατημένο. Τόσο η command όσο και ο repeat code έχουν το ίδιο preamble στην αρχή.

Η **command** του NEC, εκτός από το preamble, αποτελείται από ένα address byte και ένα command-number byte, μέσω των οποίων η συσκευή καταλαβαίνει τι πρέπει να εκτελεστεί. Τα address και command-number bytes αντιγράφονται με inverse values, ώστε να ελέγχεται η ακεραιότητα της μετάδοσης. Στο τέλος της command υπάρχει ένα επιπλέον stop bit.

Ο **repeat code** έχει ένα "1" μετά το preamble, το οποίο αποτελεί stop bit.

Για τα **logic "0" και "1"**, το NEC χρησιμοποιεί Pulse Distance Encoding: πρώτα μεταδίδεται ένα pulse burst και στη συνέχεια υπάρχει μια pause, το μήκος της οποίας καθορίζει την τιμή του bit.

### Air Conditioners

Σε αντίθεση με άλλα remotes, τα **air conditioners δεν μεταδίδουν μόνο τον κωδικό του πατημένου button**. Επίσης **μεταδίδουν όλες τις πληροφορίες** όταν πατηθεί ένα button, ώστε να διασφαλίζεται ότι το **air conditioned machine και το remote είναι synchronised**.\
Έτσι αποφεύγεται η περίπτωση όπου ένα machine ρυθμισμένο στους 20ºC αυξάνεται στους 21ºC με ένα remote και, στη συνέχεια, όταν χρησιμοποιηθεί ένα άλλο remote που εξακολουθεί να έχει τη θερμοκρασία στους 20ºC για να την αυξήσει περισσότερο, αυτή θα "αυξηθεί" στους 21ºC (και όχι στους 22ºC, επειδή θεωρεί ότι βρίσκεται στους 21ºC).

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Μπορείτε να επιτεθείτε σε Infrared με το Flipper Zero:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

Πρόσφατη academic research (EvilScreen, 2022) έδειξε ότι **multi-channel remotes που συνδυάζουν Infrared με Bluetooth ή Wi-Fi μπορούν να χρησιμοποιηθούν για την πλήρη hijacking σύγχρονων smart-TVs**. Η επίθεση συνδυάζει high-privilege IR service codes με authenticated Bluetooth packets, παρακάμπτοντας το channel-isolation και επιτρέποντας arbitrary app launches, ενεργοποίηση microphone ή factory-reset χωρίς physical access. Οκτώ mainstream TVs από διαφορετικούς vendors —συμπεριλαμβανομένου ενός μοντέλου Samsung που δήλωνε compliance με ISO/IEC 27001— επιβεβαιώθηκε ότι ήταν vulnerable. Η mitigation απαιτεί vendor firmware fixes ή πλήρη απενεργοποίηση των unused IR receivers.<sup>[[2]](#references)</sup>

### Air-Gapped Data Exfiltration μέσω IR LEDs (aIR-Jumper family)

Security cameras, routers ή ακόμη και malicious USB sticks συχνά περιλαμβάνουν **night-vision IR LEDs**. Η research δείχνει ότι malware μπορεί να κάνει modulation σε αυτά τα LEDs (<10–20 kbit/s με απλό OOK), ώστε να **exfiltrate secrets μέσω τοίχων και παραθύρων** προς μια εξωτερική camera που βρίσκεται σε απόσταση δεκάδων μέτρων. Επειδή το φως βρίσκεται εκτός του visible spectrum, οι operators σπάνια το αντιλαμβάνονται. Counter-measures:

* Physically shield ή αφαιρέστε τα IR LEDs σε sensitive areas
* Παρακολουθείτε το camera LED duty-cycle και το firmware integrity
* Deploy IR-cut filters σε παράθυρα και surveillance cameras

Ένας attacker μπορεί επίσης να χρησιμοποιήσει ισχυρά IR projectors για να **εισάγει** commands στο network, αναβοσβήνοντας data προς insecure cameras.

### Long-Range Brute-Force & Extended Protocols με Flipper Zero 1.0

Το firmware 1.0 (September 2024) πρόσθεσε **δεκάδες επιπλέον IR protocols και προαιρετικά external amplifier modules**. Σε συνδυασμό με το universal-remote brute-force mode, ένα Flipper μπορεί να απενεργοποιήσει ή να επαναδιαμορφώσει τα περισσότερα public TVs/ACs από απόσταση έως 30 m, χρησιμοποιώντας high-power diode.

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – portable transceiver με learning, replay και dictionary-bruteforce modes (βλ. παραπάνω).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – φθηνός DIY analyser/transmitter. Συνδυάστε το με τη βιβλιοθήκη `Arduino-IRremote` (το v4.x υποστηρίζει >40 protocols).
* **Logic analysers** (Saleae/FX2) – καταγράφουν raw timings όταν το protocol είναι άγνωστο.
* **Smartphones με IR-blaster** (π.χ. Xiaomi) – γρήγορο field test, αλλά με περιορισμένο range.

### Software

* **`Arduino-IRremote`** – actively-maintained C++ library:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – GUI decoders που εισάγουν raw captures, αναγνωρίζουν αυτόματα το protocol και δημιουργούν Pronto/Arduino code.
* **LIRC / ir-keytable (Linux)** – λαμβάνουν και εισάγουν IR από τη command line:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* Απενεργοποιήστε ή καλύψτε τους IR receivers σε συσκευές που έχουν εγκατασταθεί σε public spaces, όταν δεν απαιτούνται.
* Επιβάλετε *pairing* ή cryptographic checks μεταξύ smart-TVs και remotes· απομονώστε τα privileged “service” codes.
* Deploy IR-cut filters ή continuous-wave detectors γύρω από classified areas, ώστε να διακόπτονται τα optical covert channels.
* Παρακολουθείτε το firmware integrity των cameras/IoT appliances που εκθέτουν controllable IR LEDs.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: Smart TV hijacking via remote control mimicry](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
