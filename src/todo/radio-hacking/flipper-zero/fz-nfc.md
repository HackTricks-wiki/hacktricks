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

Η παρακάτω λίστα δυνατοτήτων περιγράφει το firmware που τεκμηριωνόταν στο αρχικό άρθρο και δεν πρέπει να θεωρείται η τρέχουσα, πλήρης μήτρα υποστήριξης. Το firmware του Flipper έχει προσθέσει πρωτόκολλα και έχει αλλάξει τη συμπεριφορά NFC με την πάροδο του χρόνου. Ελέγξτε την τρέχουσα επίσημη τεκμηρίωση για το εγκατεστημένο firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Τραπεζικές κάρτες (EMV)** — μόνο ανάγνωση των UID, SAK και ATQA χωρίς αποθήκευση.
- **Άγνωστες κάρτες** — ανάγνωση των UID, SAK και ATQA και emulation ενός UID.

Για **τύπους καρτών NFC B, F και V**, το τεκμηριωμένο firmware μπορούσε να διαβάσει ένα UID χωρίς να το αποθηκεύσει.

### Κάρτες NFC τύπου A <a href="#uvusf" id="uvusf"></a>

#### Τραπεζική κάρτα (EMV) <a href="#kzmrp" id="kzmrp"></a>

Το τεκμηριωμένο firmware μπορούσε να διαβάσει ένα UID, SAK, ATQA και διαθέσιμα δεδομένα εφαρμογής από μια τραπεζική κάρτα **χωρίς να τα αποθηκεύσει**.

Για αυτές τις τραπεζικές κάρτες, το firmware εμφάνιζε τα δεδομένα χωρίς να αποθηκεύει ή να κάνει emulation της κάρτας.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Άγνωστες κάρτες <a href="#id-37eo8" id="id-37eo8"></a>

Όταν το Flipper Zero **δεν μπορεί να προσδιορίσει τον τύπο της κάρτας NFC**, μπορούν να **διαβαστούν και να αποθηκευτούν** μόνο ένα **UID, SAK και ATQA**.

Για μια άγνωστη κάρτα NFC, αυτή η λειτουργία μπορεί να κάνει emulation μόνο του UID της.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Κάρτες NFC τύπων B, F και V <a href="#wyg51" id="wyg51"></a>

Στο firmware που τεκμηριωνόταν στο αρχικό άρθρο, από τους τύπους καρτών NFC B, F και V μπορούσε να διαβαστεί και να εμφανιστεί μόνο ένα αναγνωριστικό, χωρίς να αποθηκευτεί.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Ενέργειες

Για μια εισαγωγή στο NFC, [**διαβάστε αυτήν τη σελίδα**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Ανάγνωση

Το Flipper Zero μπορεί να διαβάσει κάρτες NFC, αλλά δεν υλοποιεί κάθε πρωτόκολλο υψηλότερου επιπέδου που βασίζεται στο ISO 14443. Επομένως, μπορεί να ανακτήσει τα UID, SAK και ATQA χαμηλού επιπέδου, αφήνοντας άγνωστο το πρωτόκολλο εφαρμογής. Σε primitive συστήματα πρόσβασης που εξουσιοδοτούν μόνο βάσει UID, το εργαλείο μπορεί να διαβάσει, να εισαγάγει χειροκίνητα και να κάνει emulation αυτού του αναγνωριστικού. Τα κρυπτογραφικά authenticated συστήματα απαιτούν περισσότερα από ένα αντιγραμμένο UID.<sup>[[1]](#references)</sup>

#### Ανάγνωση του UID έναντι ανάγνωσης των δεδομένων στο εσωτερικό <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Στο Flipper, η ανάγνωση tags 13.56 MHz μπορεί να χωριστεί σε δύο μέρη:<sup>[[1]](#references)</sup>

- **Ανάγνωση χαμηλού επιπέδου** — διαβάζει μόνο τα UID, SAK και ATQA. Το Flipper προσπαθεί να μαντέψει το πρωτόκολλο υψηλού επιπέδου με βάση αυτά τα δεδομένα που διαβάστηκαν από την κάρτα. Δεν μπορείτε να είστε 100% βέβαιοι, καθώς πρόκειται απλώς για υπόθεση που βασίζεται σε ορισμένους παράγοντες.
- **Ανάγνωση υψηλού επιπέδου** — διαβάζει τα δεδομένα από τη μνήμη της κάρτας χρησιμοποιώντας ένα συγκεκριμένο πρωτόκολλο υψηλού επιπέδου. Αυτό μπορεί να σημαίνει ανάγνωση των δεδομένων σε μια Mifare Ultralight, ανάγνωση των sectors από μια Mifare Classic ή ανάγνωση των attributes της κάρτας από PayPass/Apple Pay.

### Ανάγνωση συγκεκριμένου τύπου

Σε περίπτωση που το Flipper Zero δεν μπορεί να εντοπίσει τον τύπο της κάρτας από τα δεδομένα χαμηλού επιπέδου, στις `Extra Actions` μπορείτε να επιλέξετε `Read Specific Card Type` και να **υποδείξετε** **χειροκίνητα τον τύπο της κάρτας που θέλετε να διαβάσετε**.

#### Τραπεζικές κάρτες EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Παλαιότερα firmware του Flipper και συμβατές κάρτες EMV μπορούσαν να εκθέσουν περισσότερα από το UID, ενδεχομένως συμπεριλαμβανομένων του PAN, της ημερομηνίας λήξης, του ονόματος του κατόχου της κάρτας ή του transaction log, όταν αυτές οι εγγραφές ήταν διαθέσιμες από την κάρτα. Η διαθεσιμότητα διαφέρει ανάλογα με την κάρτα, την εφαρμογή και το firmware. Το CVV της μαγνητικής λωρίδας που είναι τυπωμένο στην κάρτα δεν εκτίθεται με αυτόν τον τρόπο, ενώ η ανάγνωση αυτών των εγγραφών δεν κλωνοποιεί την κρυπτογραφική δυνατότητα συναλλαγών που απαιτείται για την πραγματοποίηση ανέπαφης πληρωμής.<sup>[[1]](#references)</sup>

## References

- [1] [Κατάδυση στα πρωτόκολλα RFID με το Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Τεκμηρίωση Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
