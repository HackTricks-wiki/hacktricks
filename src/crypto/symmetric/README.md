# Συμμετρική Κρυπτογράφηση

{{#include ../../banners/hacktricks-training.md}}

## Τι να αναζητήσετε σε CTFs

- **Κακή χρήση mode**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: διαφορετικά σφάλματα/χρόνοι για κακό padding.
- **MAC confusion**: χρήση CBC-MAC με μηνύματα μεταβλητού μήκους ή λάθη MAC-then-encrypt.
- **XOR everywhere**: stream ciphers και προσαρμοσμένες κατασκευές συχνά ανάγονται σε XOR με keystream.

## AES modes and misuse

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Αυτό επιτρέπει:

- Cut-and-paste / block reordering
- Block deletion (αν το format παραμένει έγκυρο)

Αν μπορείτε να ελέγξετε το plaintext και να παρατηρήσετε το ciphertext (ή cookies), δοκιμάστε να φτιάξετε επαναλαμβανόμενα μπλοκ (π.χ. πολλά `A`s) και ψάξτε για επαναλήψεις.

### CBC: Cipher Block Chaining

- Το CBC είναι **malleable**: η αλλαγή bit στο `C[i-1]` αλλάζει προβλέψιμα bits στο `P[i]`.
- Αν το σύστημα αποκαλύπτει valid padding vs invalid padding, μπορεί να υπάρχει ένα **padding oracle**.

### CTR

Το CTR μετατρέπει το AES σε stream cipher: `C = P XOR keystream`.

Αν ένα nonce/IV επαναχρησιμοποιηθεί με το ίδιο κλειδί:

- `C1 XOR C2 = P1 XOR P2` (κλασική επανάχρηση keystream)
- Με γνωστό plaintext, μπορείτε να ανακτήσετε το keystream και να αποκρυπτογραφήσετε άλλα μηνύματα.

### GCM

Το GCM επίσης καταρρέει άσχημα υπό nonce reuse. Αν το ίδιο key+nonce χρησιμοποιηθεί περισσότερες από μία φορές, συνήθως έχετε:

- Επανάχρηση keystream για κρυπτογράφηση (όπως CTR), επιτρέποντας ανάκτηση plaintext όταν οποιοδήποτε plaintext είναι γνωστό.
- Απώλεια εγγυήσεων ακεραιότητας. Ανάλογα με το τι αποκαλύπτεται (πολλαπλά ζεύγη message/tag κάτω από το ίδιο nonce), επιτιθέμενοι ενδέχεται να μπορούν να δημιουργήσουν forged tags.

Λειτουργικές οδηγίες:

- Θεωρήστε το "nonce reuse" σε AEAD ως κρίσιμη ευπάθεια.
- Αν έχετε πολλαπλά ciphertexts κάτω από το ίδιο nonce, ξεκινήστε ελέγχοντας σχέσεις τύπου `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef for quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` για scripting

## ECB exploitation patterns

ECB (Electronic Code Book) κρυπτογραφεί κάθε μπλοκ ανεξάρτητα:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Detection idea: token/cookie pattern

Αν κάνετε login αρκετές φορές και **πάντα παίρνετε το ίδιο cookie**, το ciphertext μπορεί να είναι deterministic (ECB ή fixed IV).

Αν δημιουργήσετε δύο χρήστες με κατά βάση όμοια layouts plaintext (π.χ. μακριά επαναλαμβανόμενα χαρακτήρες) και δείτε επαναλαμβανόμενα ciphertext μπλοκ στις ίδιες offset θέσεις, το ECB είναι ύποπτο.

### Exploitation patterns

#### Removing entire blocks

Αν το format του token είναι κάτι σαν `<username>|<password>` και το όριο μπλοκ ευθυγραμμίζεται, μπορείτε κάποιες φορές να κατασκευάσετε έναν χρήστη έτσι ώστε το μπλοκ με `admin` να εμφανιστεί ευθυγραμμισμένο, και μετά να αφαιρέσετε τα προηγούμενα μπλοκ για να πάρετε ένα έγκυρο token για `admin`.

#### Moving blocks

Αν το backend ανέχεται padding/extra spaces (`admin` vs `admin    `), μπορείτε να:

- Ευθυγραμμίσετε ένα μπλοκ που περιέχει `admin   `
- Αντικαταστήσετε/επαναχρησιμοποιήσετε εκείνο το ciphertext μπλοκ σε άλλο token

## Padding Oracle

### What it is

In CBC mode, if the server reveals (directly or indirectly) whether decrypted plaintext has **valid PKCS#7 padding**, you can often:

- Decrypt ciphertext without the key
- Encrypt chosen plaintext (forge ciphertext)

The oracle can be:

- A specific error message
- A different HTTP status / response size
- A timing difference

### Practical exploitation

PadBuster is the classic tool:

{{#ref}}
https://github.com/AonCyberLabs/PadBuster
{{#endref}}

Example:
```bash
perl ./padBuster.pl http://10.10.10.10/index.php "RVJDQrwUdTRWJUVUeBKkEA==" 16 \
-encoding 0 -cookies "login=RVJDQrwUdTRWJUVUeBKkEA=="
```
Notes:

- Το μέγεθος block είναι συχνά `16` για AES.
- `-encoding 0` σημαίνει Base64.
- Χρησιμοποιήστε `-error` αν το oracle είναι συγκεκριμένη συμβολοσειρά.

### Why it works

Η αποκρυπτογράφηση CBC υπολογίζει `P[i] = D(C[i]) XOR C[i-1]`. Με το να τροποποιείτε bytes στο `C[i-1]` και παρατηρώντας αν το padding είναι έγκυρο, μπορείτε να ανακτήσετε το `P[i]` byte-προς-byte.

## Bit-flipping in CBC

Ακόμη και χωρίς padding oracle, το CBC είναι επιδεκτικό παραποίησης. Αν μπορείτε να τροποποιήσετε μπλοκ του ciphertext και η εφαρμογή χρησιμοποιεί το αποκρυπτογραφημένο plaintext ως δομημένα δεδομένα (π.χ. `role=user`), μπορείτε να αλλάξετε συγκεκριμένα bits ώστε να τροποποιήσετε επιλεγμένα bytes του plaintext σε επιλεγμένη θέση στο επόμενο μπλοκ.

Τυπικό μοτίβο CTF:

- Token = `IV || C1 || C2 || ...`
- You control bytes in `C[i]`
- You target plaintext bytes in `P[i+1]` because `P[i+1] = D(C[i+1]) XOR C[i]`

Αυτό από μόνο του δεν αποτελεί παραβίαση εμπιστευτικότητας, αλλά είναι ένα κοινό privilege-escalation primitive όταν λείπει η ακεραιότητα.

## CBC-MAC

CBC-MAC είναι ασφαλές μόνο υπό συγκεκριμένες συνθήκες (ιδίως **fixed-length messages** και σωστό domain separation).

### Classic variable-length forgery pattern

CBC-MAC υπολογίζεται συνήθως ως:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Αν μπορείτε να αποκτήσετε tags για επιλεγμένα μηνύματα, συχνά μπορείτε να δημιουργήσετε ένα tag για μια concatenation (ή σχετική κατασκευή) χωρίς να γνωρίζετε το key, εκμεταλλευόμενοι τον τρόπο με τον οποίο το CBC συνδέει τα μπλοκ.

Αυτό εμφανίζεται συχνά σε CTF cookies/tokens που κάνουν MAC το username ή το role με CBC-MAC.

### Safer alternatives

- Use HMAC (SHA-256/512)
- Use CMAC (AES-CMAC) correctly
- Include message length / domain separation

## Stream ciphers: XOR and RC4

### The mental model

Οι περισσότερες περιπτώσεις stream cipher μειώνονται σε:

`ciphertext = plaintext XOR keystream`

Οπότε:

- Αν γνωρίζετε το plaintext, ανακτάτε το keystream.
- Αν το keystream επαναχρησιμοποιείται (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Αν γνωρίζετε οποιοδήποτε τμήμα plaintext στη θέση `i`, μπορείτε να ανακτήσετε τα bytes του keystream και να αποκρυπτογραφήσετε άλλα ciphertexts σε αυτές τις θέσεις.

Autosolvers:

- https://wiremask.eu/tools/xor-cracker/

### RC4

RC4 είναι stream cipher· encrypt/decrypt είναι η ίδια λειτουργία.

Αν μπορείτε να πάρετε RC4 encryption γνωστού plaintext υπό το ίδιο key, μπορείτε να ανακτήσετε το keystream και να αποκρυπτογραφήσετε άλλα μηνύματα του ίδιου μήκους/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
