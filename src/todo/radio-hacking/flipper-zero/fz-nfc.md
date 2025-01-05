# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Για πληροφορίες σχετικά με το RFID και το NFC, ελέγξτε την παρακάτω σελίδα:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Supported NFC cards <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Εκτός από τις κάρτες NFC, το Flipper Zero υποστηρίζει **άλλους τύπους καρτών Υψηλής Συχνότητας** όπως αρκετές **Mifare** Classic και Ultralight και **NTAG**.

Νέοι τύποι καρτών NFC θα προστεθούν στη λίστα των υποστηριζόμενων καρτών. Το Flipper Zero υποστηρίζει τους εξής **τύπους καρτών NFC A** (ISO 14443A):

- **Κάρτες τραπέζης (EMV)** — διαβάζει μόνο UID, SAK και ATQA χωρίς αποθήκευση.
- **Άγνωστες κάρτες** — διαβάζει (UID, SAK, ATQA) και προσομοιώνει ένα UID.

Για **τύπους καρτών NFC B, F και V**, το Flipper Zero μπορεί να διαβάσει ένα UID χωρίς να το αποθηκεύσει.

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Το Flipper Zero μπορεί να διαβάσει μόνο ένα UID, SAK, ATQA και αποθηκευμένα δεδομένα σε κάρτες τραπέζης **χωρίς αποθήκευση**.

Οθόνη ανάγνωσης κάρτας τραπέζηςΓια τις κάρτες τραπέζης, το Flipper Zero μπορεί να διαβάσει μόνο δεδομένα **χωρίς αποθήκευση και προσομοίωση**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

Όταν το Flipper Zero είναι **ανίκανο να προσδιορίσει τον τύπο της κάρτας NFC**, τότε μόνο ένα **UID, SAK και ATQA** μπορούν να **διαβαστούν και να αποθηκευτούν**.

Οθόνη ανάγνωσης άγνωστης κάρταςΓια άγνωστες κάρτες NFC, το Flipper Zero μπορεί να προσομοιώσει μόνο ένα UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

Για **τύπους καρτών NFC B, F και V**, το Flipper Zero μπορεί μόνο να **διαβάσει και να εμφανίσει ένα UID** χωρίς αποθήκευση.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

Για μια εισαγωγή σχετικά με το NFC [**διαβάστε αυτή τη σελίδα**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Read

Το Flipper Zero μπορεί να **διαβάσει κάρτες NFC**, ωστόσο, **δεν κατανοεί όλα τα πρωτόκολλα** που βασίζονται στο ISO 14443. Ωστόσο, δεδομένου ότι το **UID είναι ένα χαμηλού επιπέδου χαρακτηριστικό**, μπορεί να βρεθείτε σε μια κατάσταση όπου το **UID έχει ήδη διαβαστεί, αλλά το πρωτόκολλο μεταφοράς δεδομένων υψηλού επιπέδου είναι ακόμα άγνωστο**. Μπορείτε να διαβάσετε, να προσομοιώσετε και να εισάγετε χειροκίνητα το UID χρησιμοποιώντας το Flipper για τους πρωτόγονους αναγνώστες που χρησιμοποιούν το UID για εξουσιοδότηση.

#### Reading the UID VS Reading the Data Inside <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Στο Flipper, η ανάγνωση ετικετών 13.56 MHz μπορεί να χωριστεί σε δύο μέρη:

- **Χαμηλού επιπέδου ανάγνωση** — διαβάζει μόνο το UID, SAK και ATQA. Το Flipper προσπαθεί να μαντέψει το πρωτόκολλο υψηλού επιπέδου με βάση αυτά τα δεδομένα που διαβάστηκαν από την κάρτα. Δεν μπορείτε να είστε 100% σίγουροι με αυτό, καθώς είναι απλώς μια υπόθεση βασισμένη σε ορισμένους παράγοντες.
- **Υψηλού επιπέδου ανάγνωση** — διαβάζει τα δεδομένα από τη μνήμη της κάρτας χρησιμοποιώντας ένα συγκεκριμένο πρωτόκολλο υψηλού επιπέδου. Αυτό θα ήταν η ανάγνωση των δεδομένων σε μια Mifare Ultralight, η ανάγνωση των τομέων από μια Mifare Classic ή η ανάγνωση των χαρακτηριστικών της κάρτας από το PayPass/Apple Pay.

### Read Specific

Σε περίπτωση που το Flipper Zero δεν είναι ικανό να βρει τον τύπο της κάρτας από τα δεδομένα χαμηλού επιπέδου, στην `Extra Actions` μπορείτε να επιλέξετε `Read Specific Card Type` και **χειροκίνητα** **να υποδείξετε τον τύπο της κάρτας που θα θέλατε να διαβάσετε**.

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Εκτός από την απλή ανάγνωση του UID, μπορείτε να εξάγετε πολύ περισσότερα δεδομένα από μια κάρτα τραπέζης. Είναι δυνατόν να **λάβετε τον πλήρη αριθμό της κάρτας** (τους 16 ψηφίους στην μπροστινή πλευρά της κάρτας), **ημερομηνία λήξης**, και σε ορισμένες περιπτώσεις ακόμη και το **όνομα του κατόχου** μαζί με μια λίστα με τις **πιο πρόσφατες συναλλαγές**.\
Ωστόσο, δεν μπορείτε να διαβάσετε το CVV με αυτόν τον τρόπο (τους 3 ψηφίους στην πίσω πλευρά της κάρτας). Επίσης, **οι κάρτες τραπέζης προστατεύονται από επιθέσεις επανάληψης**, οπότε η αντιγραφή τους με το Flipper και στη συνέχεια η προσπάθεια προσομοίωσής τους για να πληρώσετε κάτι δεν θα λειτουργήσει.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
