# Συμμετρική Κρυπτογραφία

{{#include ../../banners/hacktricks-training.md}}

## Τι να αναζητήσετε σε CTFs

- **Κακή χρήση λειτουργίας**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: διαφορετικά σφάλματα/χρόνοι απόκρισης για κακό padding.
- **MAC confusion**: χρήση CBC-MAC με μηνύματα μεταβλητού μήκους, ή λάθη MAC-then-encrypt.
- **XOR παντού**: stream ciphers και custom constructions συχνά μειώνονται σε XOR με ένα keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Αυτό επιτρέπει:

- Cut-and-paste / αναδιάταξη blocks
- Διαγραφή blocks (αν η μορφή παραμένει έγκυρη)

Αν μπορείτε να ελέγξετε το plaintext και να παρατηρήσετε ciphertext (ή cookies), δοκιμάστε να δημιουργήσετε επαναλαμβανόμενα blocks (π.χ., πολλά `A`s) και ψάξτε για επαναλήψεις.

### CBC: Cipher Block Chaining

- CBC is **malleable**: flipping bits in `C[i-1]` flips predictable bits in `P[i]`.
- Αν το σύστημα αποκαλύπτει έγκυρο padding έναντι μη έγκυρου padding, μπορεί να έχετε έναν **padding oracle**.

### CTR

CTR turns AES into a stream cipher: `C = P XOR keystream`.

If a nonce/IV is reused with the same key:

- `C1 XOR C2 = P1 XOR P2` (classic keystream reuse)
- Με γνωστό plaintext, μπορείτε να ανακτήσετε το keystream και να αποκρυπτογραφήσετε άλλα μηνύματα.

### GCM

GCM επίσης σπάει άσχημα υπό nonce reuse. Αν το ίδιο key+nonce χρησιμοποιηθεί περισσότερες από μία φορές, συνήθως έχετε:

- Keystream reuse για κρυπτογράφηση (όπως CTR), επιτρέποντας ανάκτηση plaintext όταν οποιοδήποτε plaintext είναι γνωστό.
- Απώλεια εγγυήσεων ακεραιότητας. Ανάλογα με το τι αποκαλύπτεται (πολλαπλά message/tag ζεύγη με τον ίδιο nonce), επιτιθέμενοι μπορεί να καταφέρουν να forge tags.

Επιχειρησιακές οδηγίες:

- Θεωρήστε το "nonce reuse" σε AEAD ως κρίσιμη ευπάθεια.
- Αν έχετε πολλαπλά ciphertext υπό τον ίδιο nonce, ξεκινήστε ελέγχοντας σχέσεις του τύπου `C1 XOR C2 = P1 XOR P2`.

### Εργαλεία

- CyberChef για γρήγορα πειράματα: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` για scripting

## Πρότυπα εκμετάλλευσης ECB

ECB (Electronic Code Book) κρυπτογραφεί κάθε block ανεξάρτητα:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ιδέα ανίχνευσης: μοτίβο token/cookie

Αν συνδεθείτε πολλές φορές και **πάντα λαμβάνετε το ίδιο cookie**, το ciphertext μπορεί να είναι deterministic (ECB ή fixed IV).

Αν δημιουργήσετε δύο χρήστες με κυρίως ίδια plaintext διατάξεις (π.χ., μακριές επαναλαμβανόμενες χαρακτήρες) και δείτε επαναλαμβανόμενα ciphertext blocks στις ίδιες θέσεις, το ECB είναι κύριος ύποπτος.

### Σχέδια εκμετάλλευσης

#### Αφαίρεση ολόκληρων blocks

Αν η μορφή token είναι κάτι σαν `<username>|<password>` και τα όρια των blocks ευθυγραμμίζονται, μερικές φορές μπορείτε να κατασκευάσετε έναν χρήστη ώστε το block που περιέχει `admin` να ευθυγραμμιστεί, και μετά να αφαιρέσετε τα προηγούμενα blocks για να αποκτήσετε ένα έγκυρο token για `admin`.

#### Μετακίνηση blocks

Αν το backend ανεχτεί padding/extra spaces (`admin` vs `admin    `), μπορείτε:

- Να ευθυγραμμίσετε ένα block που περιέχει `admin   `
- Να ανταλλάξετε/επαναχρησιμοποιήσετε εκείνο το ciphertext block σε άλλο token

## Padding Oracle

### Τι είναι

Σε CBC mode, αν ο server αποκαλύπτει (απευθείας ή έμμεσα) αν το αποκρυπτογραφημένο plaintext έχει **έγκυρο PKCS#7 padding**, συχνά μπορείτε:

- Να αποκρυπτογραφήσετε ciphertext χωρίς το κλειδί
- Να κρυπτογραφήσετε επιλεγμένο plaintext (forge ciphertext)

Το oracle μπορεί να είναι:

- Ένα συγκεκριμένο μήνυμα σφάλματος
- Ένας διαφορετικός HTTP status / μέγεθος απάντησης
- Μια διαφορά στον χρόνο απόκρισης

### Πρακτική εκμετάλλευση

PadBuster είναι το κλασικό εργαλείο:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Παράδειγμα:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Σημειώσεις:

- Το μέγεθος block είναι συχνά `16` για AES.
- `-encoding 0` σημαίνει Base64.
- Χρησιμοποίησε `-error` αν το oracle είναι μια συγκεκριμένη συμβολοσειρά.

### Γιατί λειτουργεί

Η αποκρυπτογράφηση CBC υπολογίζει `P[i] = D(C[i]) XOR C[i-1]`. Τροποποιώντας bytes στο `C[i-1]` και παρατηρώντας αν το padding είναι έγκυρο, μπορείς να ανακτήσεις το `P[i]` byte-προς-byte.

## Bit-flipping in CBC

Ακόμα και χωρίς padding oracle, το CBC είναι αλλοιώσιμο. Αν μπορείς να τροποποιήσεις blocks του ciphertext και η εφαρμογή χρησιμοποιεί το αποκρυπτογραφημένο plaintext ως δομημένα δεδομένα (π.χ. `role=user`), μπορείς να αντιστρέψεις συγκεκριμένα bits για να αλλάξεις επιλεγμένα bytes του plaintext σε συγκεκριμένη θέση στο επόμενο block.

Τυπικό μοτίβο CTF:

- Token = `IV || C1 || C2 || ...`
- Ελέγχεις bytes στο `C[i]`
- Στοχεύεις bytes του plaintext σε `P[i+1]` επειδή `P[i+1] = D(C[i+1]) XOR C[i]`

Αυτό από μόνο του δεν παραβιάζει την εμπιστευτικότητα, αλλά είναι ένα κοινό primitive για αύξηση προνομίων όταν λείπει η ακεραιότητα.

## CBC-MAC

CBC-MAC είναι ασφαλές μόνο υπό συγκεκριμένες συνθήκες (ιδιαίτερα **μηνύματα σταθερού μήκους** και σωστή domain separation).

### Κλασικό μοτίβο παραποίησης μεταβλητού μήκους

CBC-MAC συνήθως υπολογίζεται ως:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Αν μπορείς να λάβεις tags για επιλεγμένα μηνύματα, συχνά μπορείς να κατασκευάσεις ένα tag για μια συνένωση (ή σχετική κατασκευή) χωρίς να γνωρίζεις το κλειδί, εκμεταλλευόμενος τον τρόπο που το CBC αλυσιδώνει τα blocks.

Συχνά εμφανίζεται σε CTF cookies/tokens που κάνουν MAC το username ή το role με CBC-MAC.

### Ασφαλέστερες εναλλακτικές

- Χρησιμοποίησε HMAC (SHA-256/512)
- Χρησιμοποίησε CMAC (AES-CMAC) σωστά
- Συμπερίλαβε το μήκος του μηνύματος / domain separation

## Stream ciphers: XOR and RC4

### Το νοητικό μοντέλο

Οι περισσότερες καταστάσεις με stream ciphers μειώνονται σε:

`ciphertext = plaintext XOR keystream`

Έτσι:

- Αν γνωρίζεις το plaintext, ανακτάς το keystream.
- Αν το keystream επαναχρησιμοποιηθεί (ίδιο key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Κρυπτογράφηση βασισμένη σε XOR

Αν γνωρίζεις οποιοδήποτε τμήμα plaintext στη θέση `i`, μπορείς να ανακτήσεις τα bytes του keystream και να αποκρυπτογραφήσεις άλλα ciphertexts στις ίδιες θέσεις.

Αυτόματοι λύτες:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 είναι stream cipher· η κρυπτογράφηση/αποκρυπτογράφηση είναι η ίδια λειτουργία.

Αν μπορείς να πάρεις RC4 κρυπτογράφηση γνωστού plaintext με το ίδιο κλειδί, μπορείς να ανακτήσεις το keystream και να αποκρυπτογραφήσεις άλλα μηνύματα του ίδιου μήκους/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
