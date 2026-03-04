# Συμμετρική Κρυπτογραφία

{{#include ../../banners/hacktricks-training.md}}

## Τι να ψάχνετε σε CTFs

- **Mode misuse**: ECB patterns, CBC malleability, CTR/GCM nonce reuse.
- **Padding oracles**: διαφορετικά σφάλματα/χρονισμοί για κακό padding.
- **MAC confusion**: χρήση CBC-MAC με μηνύματα μεταβλητού μήκους, ή λάθη MAC-then-encrypt.
- **XOR everywhere**: stream ciphers και custom constructions συχνά μειώνονται σε XOR με ένα keystream.

## Λειτουργίες AES και κακή χρήση

### ECB: Electronic Codebook

ECB leaks patterns: equal plaintext blocks → equal ciphertext blocks. Αυτό επιτρέπει:

- Cut-and-paste / αναδιάταξη μπλοκ
- Διαγραφή μπλοκ (εάν η μορφή παραμένει έγκυρη)

Αν μπορείτε να ελέγξετε το plaintext και να παρατηρήσετε το ciphertext (ή cookies), δοκιμάστε να δημιουργήσετε επαναλαμβανόμενα μπλοκ (π.χ. πολλά `A`s) και ψάξτε για επαναλήψεις.

### CBC: Cipher Block Chaining

- CBC είναι **malleable**: το γύρισμα bits στο `C[i-1]` αλλάζει προβλέψιμα bits στο `P[i]`.
- Εάν το σύστημα αποκαλύπτει έγκυρο padding vs μη έγκυρο padding, μπορεί να έχετε ένα **padding oracle**.

### CTR

Το CTR μετατρέπει το AES σε stream cipher: `C = P XOR keystream`.

Εάν ένας nonce/IV επαναχρησιμοποιηθεί με το ίδιο κλειδί:

- `C1 XOR C2 = P1 XOR P2` (κλασική επαναχρησιμοποίηση keystream)
- Με γνωστό plaintext, μπορείτε να ανακτήσετε το keystream και να αποκρυπτογραφήσετε άλλα.

**Nonce/IV reuse exploitation patterns**

- Ανακτήστε το keystream όπου το plaintext είναι γνωστό/μπορεί να μαντευτεί:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Εφαρμόστε τα ανακτημένα bytes του keystream για να αποκρυπτογραφήσετε οποιοδήποτε άλλο ciphertext που παράχθηκε με το ίδιο key+IV στις ίδιες θέσεις.
- Δομημένα δεδομένα (π.χ., ASN.1/X.509 certificates, file headers, JSON/CBOR) δίνουν μεγάλες περιοχές γνωστού plaintext. Συχνά μπορείτε να XORάρετε το ciphertext του certificate με το προβλέψιμο certificate body για να προκύψει το keystream, και μετά να αποκρυπτογραφήσετε άλλα μυστικά κρυπτογραφημένα κάτω από το επαναχρησιμοποιημένο IV. Δείτε επίσης [TLS & Certificates](../tls-and-certificates/README.md) για τυπικές διατάξεις πιστοποιητικών.
- Όταν πολλαπλά μυστικά της **ίδιας σειριοποιημένης μορφής/μεγέθους** κρυπτογραφούνται με το ίδιο key+IV, η στοίχιση πεδίων αποκαλύπτει πληροφορία ακόμα και χωρίς πλήρες γνωστό plaintext. Παράδειγμα: PKCS#8 RSA κλειδιά με το ίδιο μέγεθος modulus τοποθετούν τους πρώτους παράγοντες σε αντίστοιχες θέσεις (~99.6% στοίχιση για 2048-bit). Το XOR δύο ciphertexts υπό το επαναχρησιμοποιημένο keystream απομονώνει `p ⊕ p'` / `q ⊕ q'`, τα οποία μπορούν να ανακτηθούν με brute force σε δευτερόλεπτα.
- Προεπιλεγμένα IVs σε βιβλιοθήκες (π.χ., σταθερό `000...01`) είναι κρίσιμο πρόβλημα: κάθε κρυπτογράφηση επαναλαμβάνει το ίδιο keystream, μετατρέποντας το CTR σε επαναχρησιμοποιημένο one-time pad.

**CTR malleability**

- Το CTR παρέχει μόνο εμπιστευτικότητα: το γύρισμα bits στο ciphertext αλλάζει με καθοριστικό τρόπο τα ίδια bits στο plaintext. Χωρίς authentication tag, οι επιτιθέμενοι μπορούν να τροποποιούν δεδομένα (π.χ., να αλλάξουν κλειδιά, flags ή μηνύματα) χωρίς να εντοπίζονται.
- Χρησιμοποιήστε AEAD (GCM, GCM-SIV, ChaCha20-Poly1305, κ.λπ.) και επιβάλετε επαλήθευση tag για να εντοπίζονται bit-flips.

### GCM

Το GCM επίσης καταρρέει άσχημα υπό επαναχρησιμοποίηση nonce. Αν το ίδιο key+nonce χρησιμοποιηθεί περισσότερες από μία φορές, συνήθως παίρνετε:

- Επαναχρησιμοποίηση keystream για κρυπτογράφηση (όπως CTR), επιτρέποντας ανάκτηση plaintext όταν οποιοδήποτε plaintext είναι γνωστό.
- Απώλεια εγγυήσεων ακεραιότητας. Ανάλογα με το τι εκτίθεται (πολλαπλά pairs message/tag κάτω από το ίδιο nonce), οι επιτιθέμενοι μπορεί να μπορούν να falsify tags.

Λειτουργικές οδηγίες:

- Θεωρήστε την "nonce reuse" σε AEAD ως κρίσιμη ευπάθεια.
- Misuse-resistant AEADs (π.χ., GCM-SIV) μειώνουν την επίπτωση της misuse αλλά εξακολουθούν να απαιτούν μοναδικά nonces/IVs.
- Αν έχετε πολλαπλά ciphertexts κάτω από το ίδιο nonce, ξεκινήστε ελέγχοντας σχέσεις του τύπου `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef για γρήγορα πειράματα: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` για scripting

## ECB exploitation patterns

Το ECB (Electronic Code Book) κρυπτογραφεί κάθε block ανεξάρτητα:

- equal plaintext blocks → equal ciphertext blocks
- this leaks structure and enables cut-and-paste style attacks

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ιδέα ανίχνευσης: token/cookie pattern

Αν συνδεθείτε πολλές φορές και **πάντα λαμβάνετε το ίδιο cookie**, το ciphertext μπορεί να είναι deterministic (ECB ή fixed IV).

Αν δημιουργήσετε δύο χρήστες με κατά βάση παρόμοια layouts του plaintext (π.χ., μακριά επαναλαμβανόμενα χαρακτήρες) και δείτε επαναλαμβανόμενα ciphertext blocks στις ίδιες θέσεις, το ECB είναι ο κύριος ύποπτος.

### Σχέδια εκμετάλλευσης

#### Αφαίρεση ολόκληρων μπλοκ

Αν η μορφή του token είναι κάτι σαν `<username>|<password>` και τα όρια μπλοκ ευθυγραμμίζονται, μερικές φορές μπορείτε να κατασκευάσετε έναν χρήστη έτσι ώστε το μπλοκ που περιέχει `admin` να εμφανίζεται ευθυγραμμισμένο, και μετά να αφαιρέσετε τα προηγούμενα μπλοκ για να αποκτήσετε ένα έγκυρο token για `admin`.

#### Μετακίνηση μπλοκ

Αν το backend ανέχεται padding/extra spaces (`admin` vs `admin    `), μπορείτε:

- Να ευθυγραμμίσετε ένα μπλοκ που περιέχει `admin   `
- Να ανταλλάξετε/επανχρησιμοποιήσετε αυτό το ciphertext block σε άλλο token

## Padding Oracle

### Τι είναι

Σε λειτουργία CBC, αν ο server αποκαλύπτει (άμεσα ή έμμεσα) αν το αποκρυπτογραφημένο plaintext έχει **έγκυρο PKCS#7 padding**, συχνά μπορείτε:

- Να αποκρυπτογραφήσετε ciphertext χωρίς το κλειδί
- Να κρυπτογραφήσετε επιλεγμένο plaintext (forge ciphertext)

Το oracle μπορεί να είναι:

- Ένα συγκεκριμένο μήνυμα σφάλματος
- Ένα διαφορετικό HTTP status / μέγεθος απάντησης
- Μια διαφορά στο χρόνο

### Πρακτική εκμετάλλευση

Το PadBuster είναι το κλασικό εργαλείο:

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
- Χρησιμοποίησε `-error` αν το oracle είναι συγκεκριμένο string.

### Γιατί λειτουργεί

CBC decryption computes `P[i] = D(C[i]) XOR C[i-1]`. Τροποποιώντας bytes στο `C[i-1]` και παρακολουθώντας αν το padding είναι έγκυρο, μπορείς να ανακτήσεις το `P[i]` byte ανά byte.

## Bit-flipping in CBC

Even without a padding oracle, CBC is malleable. Αν μπορείς να τροποποιήσεις ciphertext blocks και η εφαρμογή χρησιμοποιεί το αποκρυπτογραφημένο plaintext ως δομημένα δεδομένα (π.χ. `role=user`), μπορείς να αλλάξεις συγκεκριμένα bits για να μεταβάλεις επιλεγμένα bytes του plaintext σε μια επιλεγμένη θέση στο επόμενο block.

Τυπικό μοτίβο σε CTF:

- Token = `IV || C1 || C2 || ...`
- Ελέγχεις bytes στο `C[i]`
- Στοχεύεις bytes του plaintext στο `P[i+1]` γιατί `P[i+1] = D(C[i+1]) XOR C[i]`

Αυτό δεν αποτελεί από μόνο του παραβίαση εμπιστευτικότητας, αλλά αποτελεί κοινό privilege-escalation primitive όταν λείπει η ακεραιότητα.

## CBC-MAC

CBC-MAC είναι ασφαλές μόνο υπό συγκεκριμένες συνθήκες (ιδιαίτερα **fixed-length messages** και σωστό domain separation).

### Classic variable-length forgery pattern

CBC-MAC υπολογίζεται συνήθως ως:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Αν μπορείς να αποκτήσεις tags για επιλεγμένα μηνύματα, συχνά μπορείς να δημιουργήσεις ένα tag για μια συνένωση (ή σχετική κατασκευή) χωρίς να γνωρίζεις το κλειδί, εκμεταλλευόμενος το πώς τα CBC αλυσσοποιούν τα block.

Αυτό εμφανίζεται συχνά σε CTF cookies/tokens που MAC-άρουν username ή role με CBC-MAC.

### Safer alternatives

- Χρησιμοποίησε HMAC (SHA-256/512)
- Χρησιμοποίησε CMAC (AES-CMAC) σωστά
- Συμπεριέλαβε μήκος μηνύματος / domain separation

## Stream ciphers: XOR and RC4

### Το νοητικό μοντέλο

Οι περισσότερες περιπτώσεις stream cipher μειώνονται σε:

`ciphertext = plaintext XOR keystream`

Άρα:

- Αν γνωρίζεις το plaintext, ανακτάς το keystream.
- Αν το keystream επαναχρησιμοποιείται (same key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Αν γνωρίζεις οποιοδήποτε τμήμα plaintext στη θέση `i`, μπορείς να ανακτήσεις τα bytes του keystream και να αποκρυπτογραφήσεις άλλα ciphertexts σε αυτές τις θέσεις.

Αυτοματοποιητές:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

RC4 is a stream cipher; encrypt/decrypt are the same operation.

Αν μπορείς να πάρεις RC4 κρυπτογράφηση γνωστού plaintext με το ίδιο κλειδί, μπορείς να ανακτήσεις το keystream και να αποκρυπτογραφήσεις άλλα μηνύματα του ίδιου μήκους/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## Αναφορές

- [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
