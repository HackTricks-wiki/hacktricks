# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Επιθέσεις σε συστήματα RFID με το Proxmark3

Εγκαταστήστε τον ενεργά συντηρούμενο client RRG/Iceman Proxmark3 και το αντίστοιχο firmware και, στη συνέχεια, επιβεβαιώστε τη σύνταξη των εντολών με αυτήν την έκδοση, καθώς οι παλαιότερες εντολές που εμφανίζονται παρακάτω ενδέχεται να έχουν αλλάξει.<sup>[[1]](#references)[[5]](#references)</sup>

### Επίθεση σε MIFARE Classic 1KB

Το MIFARE Classic 1K έχει **16 τομείς**, καθένας με **4 blocks** των **16 bytes**. Το block 0 του κατασκευαστή περιέχει τα δεδομένα UID/κατασκευαστή και είναι μόνο για ανάγνωση στις αυθεντικές κάρτες NXP· οι ειδικές κάρτες κλώνων ή «magic» ενδέχεται να επιτρέπουν την επανεγγραφή του.<sup>[[1]](#references)[[2]](#references)</sup>\
Για να αποκτήσετε πρόσβαση σε κάθε τομέα, χρειάζεστε **2 κλειδιά** (**A** και **B**), τα οποία είναι αποθηκευμένα στο **block 3 κάθε τομέα** (trailer τομέα). Το trailer τομέα αποθηκεύει επίσης τα **access bits**, τα οποία καθορίζουν τα δικαιώματα **ανάγνωσης και εγγραφής** για **κάθε block**, χρησιμοποιώντας τα 2 κλειδιά.\
Τα 2 κλειδιά είναι χρήσιμα, για παράδειγμα, για να επιτρέπουν την ανάγνωση αν γνωρίζετε το πρώτο και την εγγραφή αν γνωρίζετε το δεύτερο.

Μπορούν να πραγματοποιηθούν αρκετές επιθέσεις

```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```

Το Proxmark3 επιτρέπει την εκτέλεση άλλων ενεργειών, όπως η **υποκλοπή** μιας **επικοινωνίας από Tag προς Reader**, για την αναζήτηση ευαίσθητων δεδομένων. Σε αυτή την κάρτα, μπορείτε απλώς να καταγράψετε την επικοινωνία και να υπολογίσετε το χρησιμοποιούμενο κλειδί, επειδή **οι κρυπτογραφικές λειτουργίες που χρησιμοποιούνται είναι αδύναμες** και, γνωρίζοντας το απλό κείμενο και το κρυπτοκείμενο, μπορείτε να το υπολογίσετε (εργαλείο `mfkey64`).<sup>[[3]](#references)</sup>

#### Γρήγορη ροή εργασίας MiFare Classic για κατάχρηση αποθηκευμένης αξίας

Για την ακολουθία ανάκτησης κλειδιού, σύγκρισης διαφορών υπολοίπου, πεδίου ακεραιότητας και κλωνοποίησης UID — συμπεριλαμβανομένου του transcript του Proxmark3 client και των περιορισμών των magic-card — δείτε [MiFare Classic offline stored-value tampering](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Ακατέργαστες εντολές

Τα συστήματα IoT μερικές φορές χρησιμοποιούν **μη επώνυμα ή μη εμπορικά tags**. Σε αυτή την περίπτωση, μπορείτε να χρησιμοποιήσετε το Proxmark3 για να στείλετε προσαρμοσμένες **ακατέργαστες εντολές στα tags**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Με αυτές τις πληροφορίες, μπορείτε να αναζητήσετε πληροφορίες σχετικά με την κάρτα και τον τρόπο επικοινωνίας μαζί της. Το Proxmark3 επιτρέπει την αποστολή ακατέργαστων εντολών, όπως: `hf 14a raw -p -b 7 26`

### Scripts

Το λογισμικό Proxmark3 περιλαμβάνει μια προφορτωμένη λίστα από **σενάρια αυτοματοποίησης**, τα οποία μπορείτε να χρησιμοποιήσετε για να εκτελέσετε απλές εργασίες. Για να ανακτήσετε την πλήρη λίστα, χρησιμοποιήστε την εντολή `script list`. Έπειτα, χρησιμοποιήστε την εντολή `script run`, ακολουθούμενη από το όνομα του σεναρίου:

```
proxmark3> script run mfkeys
```

Μπορείτε να δημιουργήσετε ένα script για να κάνετε **fuzzing στους αναγνώστες καρτών**: αντιγράψτε τα δεδομένα μιας **έγκυρης κάρτας** και γράψτε απλώς ένα **Lua script** που **τυχαιοποιεί** ένα ή περισσότερα τυχαία **bytes** και ελέγχει αν ο **αναγνώστης καταρρέει** σε κάποια επανάληψη.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: Κάρτες HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Δήλωση της NXP για το MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Εκμετάλλευση ευπάθειας κάρτας NFC στο KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Εγκατάσταση σε Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
