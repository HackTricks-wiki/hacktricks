# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Εισαγωγή <a href="#id-9wrzi" id="id-9wrzi"></a>

Για πληροφορίες σχετικά με RFID και NFC, δείτε την ακόλουθη σελίδα:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Υποστηριζόμενες κάρτες NFC <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Εκτός από κάρτες NFC, το Flipper Zero υποστηρίζει **και άλλους τύπους καρτών υψηλής συχνότητας**, όπως αρκετές κάρτες **Mifare** Classic και Ultralight, καθώς και **NTAG**.

Νέοι τύποι καρτών NFC θα προστεθούν στη λίστα των υποστηριζόμενων καρτών. Το Flipper Zero υποστηρίζει τους ακόλουθους **τύπους καρτών NFC A** (ISO 14443A):

- **Τραπεζικές κάρτες (EMV)** — μόνο ανάγνωση των UID, SAK και ATQA χωρίς αποθήκευση.
- **Άγνωστες κάρτες** — ανάγνωση (UID, SAK, ATQA) και emulation ενός UID.

Για **κάρτες NFC τύπου B, τύπου F και τύπου V**, το Flipper Zero μπορεί να διαβάσει ένα UID χωρίς να το αποθηκεύσει.

### Κάρτες NFC τύπου A <a href="#uvusf" id="uvusf"></a>

#### Τραπεζική κάρτα (EMV) <a href="#kzmrp" id="kzmrp"></a>

Το Flipper Zero μπορεί να διαβάσει μόνο ένα UID, SAK, ATQA και τα αποθηκευμένα δεδομένα των τραπεζικών καρτών **χωρίς αποθήκευση**.

Οθόνη ανάγνωσης τραπεζικής κάρταςΓια τις τραπεζικές κάρτες, το Flipper Zero μπορεί μόνο να διαβάσει τα δεδομένα **χωρίς να τα αποθηκεύσει και να τα κάνει emulate**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Άγνωστες κάρτες <a href="#id-37eo8" id="id-37eo8"></a>

Όταν το Flipper Zero **δεν μπορεί να προσδιορίσει τον τύπο της κάρτας NFC**, τότε μπορούν να **διαβαστούν και να αποθηκευτούν** μόνο ένα **UID, SAK και ATQA**.

Οθόνη ανάγνωσης άγνωστης κάρταςΓια άγνωστες κάρτες NFC, το Flipper Zero μπορεί να κάνει emulate μόνο ένα UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Κάρτες NFC τύπων B, F και V <a href="#wyg51" id="wyg51"></a>

Για **κάρτες NFC τύπων B, F και V**, το Flipper Zero μπορεί μόνο να **διαβάσει και να εμφανίσει ένα UID** χωρίς να το αποθηκεύσει.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Ενέργειες

Για μια εισαγωγή στο NFC, [**διαβάστε αυτή τη σελίδα**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Ανάγνωση

Το Flipper Zero μπορεί να **διαβάσει κάρτες NFC**, ωστόσο **δεν κατανοεί όλα τα πρωτόκολλα** που βασίζονται στο ISO 14443. Επειδή όμως το **UID είναι ένα attribute χαμηλού επιπέδου**, μπορεί να βρεθείτε σε μια κατάσταση όπου το **UID έχει ήδη διαβαστεί, αλλά το πρωτόκολλο μεταφοράς δεδομένων υψηλού επιπέδου παραμένει άγνωστο**. Μπορείτε να διαβάσετε, να κάνετε emulate και να εισαγάγετε χειροκίνητα το UID χρησιμοποιώντας το Flipper για primitive readers που χρησιμοποιούν UID για authorization.<sup>[[1]](#references)</sup>

#### Ανάγνωση του UID VS Ανάγνωση των δεδομένων στο εσωτερικό <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Στο Flipper, η ανάγνωση tags 13.56 MHz μπορεί να χωριστεί σε δύο μέρη:<sup>[[1]](#references)</sup>

- **Ανάγνωση χαμηλού επιπέδου** — διαβάζει μόνο τα UID, SAK και ATQA. Το Flipper προσπαθεί να μαντέψει το πρωτόκολλο υψηλού επιπέδου με βάση αυτά τα δεδομένα που διαβάστηκαν από την κάρτα. Δεν μπορείτε να είστε 100% βέβαιοι γι' αυτό, καθώς πρόκειται απλώς για μια υπόθεση που βασίζεται σε ορισμένους παράγοντες.
- **Ανάγνωση υψηλού επιπέδου** — διαβάζει τα δεδομένα από τη μνήμη της κάρτας χρησιμοποιώντας ένα συγκεκριμένο πρωτόκολλο υψηλού επιπέδου. Αυτό μπορεί να σημαίνει ανάγνωση των δεδομένων σε μια Mifare Ultralight, ανάγνωση των sectors από μια Mifare Classic ή ανάγνωση των attributes της κάρτας από PayPass/Apple Pay.

### Συγκεκριμένη ανάγνωση

Σε περίπτωση που το Flipper Zero δεν μπορεί να εντοπίσει τον τύπο της κάρτας από τα δεδομένα χαμηλού επιπέδου, στο `Extra Actions` μπορείτε να επιλέξετε `Read Specific Card Type` και να **υποδείξετε** **χειροκίνητα** τον τύπο της κάρτας που θέλετε να διαβάσετε.

#### Τραπεζικές κάρτες EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Εκτός από την απλή ανάγνωση του UID, μπορείτε να εξαγάγετε πολύ περισσότερα δεδομένα από μια τραπεζική κάρτα. Είναι δυνατό να **λάβετε τον πλήρη αριθμό της κάρτας** (τα 16 ψηφία στο μπροστινό μέρος της κάρτας), την **ημερομηνία ισχύος** και, σε ορισμένες περιπτώσεις, ακόμη και το **όνομα του κατόχου**, μαζί με μια λίστα των **πιο πρόσφατων συναλλαγών**.\
Ωστόσο, **δεν μπορείτε να διαβάσετε το CVV με αυτόν τον τρόπο** (τα 3 ψηφία στο πίσω μέρος της κάρτας). Επίσης, **οι τραπεζικές κάρτες προστατεύονται από replay attacks**, επομένως η αντιγραφή τους με το Flipper και στη συνέχεια η προσπάθεια να γίνει emulate για την πληρωμή κάποιου προϊόντος δεν θα λειτουργήσει.<sup>[[1]](#references)</sup>

## Αναφορές

- [1] [Εμβάθυνση στα RFID Protocols με το Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
