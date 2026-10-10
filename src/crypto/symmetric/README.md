# Συμμετρική Κρυπτογραφία

{{#include ../../banners/hacktricks-training.md}}

## Τι να αναζητάτε σε CTFs

- **Κακή χρήση mode**: μοτίβα ECB, malleability του CBC, επαναχρησιμοποίηση nonce σε CTR/GCM.
- **Padding oracles**: διαφορετικά σφάλματα/χρόνοι απόκρισης για εσφαλμένο padding.
- **Σύγχυση MAC**: χρήση CBC-MAC με μηνύματα μεταβλητού μήκους ή λάθη τύπου MAC-then-encrypt.
- **XOR παντού**: τα stream ciphers και οι προσαρμοσμένες κατασκευές συχνά καταλήγουν σε XOR με ένα keystream.

## Modes AES και κακή χρήση τους

Το NIST ορίζει τα modes εμπιστευτικότητας ECB, CBC και CTR στο SP 800-38A και την authenticated encryption GCM στο SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

Το ECB διαρρέει μοτίβα: ίδια plaintext blocks → ίδια ciphertext blocks. Αυτό επιτρέπει:

- Cut-and-paste / αναδιάταξη blocks
- Διαγραφή block (αν η μορφή παραμένει έγκυρη)

Αν μπορείτε να ελέγξετε το plaintext και να παρατηρήσετε το ciphertext (ή cookies), δοκιμάστε να δημιουργήσετε επαναλαμβανόμενα blocks (π.χ. πολλά `A`) και αναζητήστε επαναλήψεις.

### CBC: Cipher Block Chaining

- Το CBC είναι **malleable**: η αντιστροφή bits στο `C[i-1]` αντιστρέφει προβλέψιμα bits στο `P[i]`, ενώ παράλληλα αλλοιώνει το `P[i-1]`. Η τροποποίηση του IV στοχεύει το πρώτο plaintext block χωρίς να αλλοιώνει προηγούμενο plaintext block.
- Αν το σύστημα αποκαλύπτει αν το padding είναι έγκυρο ή άκυρο, μπορεί να έχετε **padding oracle**.

### CTR

Το CTR μετατρέπει το AES σε stream cipher: `C = P XOR keystream`.

Αν επαναχρησιμοποιηθεί nonce/IV με το ίδιο key:

- `C1 XOR C2 = P1 XOR P2` (κλασική επαναχρησιμοποίηση keystream)
- Με γνωστό plaintext, μπορείτε να ανακτήσετε το keystream και να αποκρυπτογραφήσετε άλλα μηνύματα.

**Μοτίβα εκμετάλλευσης επαναχρησιμοποίησης nonce/IV**

- Ανακτήστε το keystream όπου το plaintext είναι γνωστό/μπορεί να προβλεφθεί:

  ```text
  keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
  ```

  Εφαρμόστε τα ανακτημένα bytes του keystream για να αποκρυπτογραφήσετε οποιοδήποτε άλλο ciphertext έχει παραχθεί με το ίδιο key+IV, στα ίδια offsets.
- Τα δεδομένα με ιδιαίτερα προβλέψιμη δομή (π.χ. πιστοποιητικά ASN.1/X.509, headers αρχείων, JSON/CBOR) παρέχουν μεγάλες περιοχές known-plaintext. Συχνά μπορείτε να κάνετε XOR στο ciphertext του πιστοποιητικού με το προβλέψιμο σώμα του πιστοποιητικού για να παράγετε keystream και, στη συνέχεια, να αποκρυπτογραφήσετε άλλα secrets που έχουν κρυπτογραφηθεί με το ίδιο IV. Δείτε επίσης το [TLS & Certificates](../tls-and-certificates/README.md) για τυπικές διατάξεις πιστοποιητικών.<sup>[[1]](#references)</sup>
- Όταν πολλά secrets με την **ίδια serialized format/size** κρυπτογραφούνται με το ίδιο key+IV, η ευθυγράμμιση των πεδίων κάνει leak πληροφορίες ακόμη και χωρίς πλήρες known plaintext. Για παράδειγμα, τα κλειδιά RSA PKCS#8 του ίδιου μεγέθους modulus τοποθετούν τους παράγοντες πρώτους σε αντίστοιχα offsets (περίπου 99.6% ευθυγράμμιση για 2048-bit). Το XOR δύο ciphertexts με το ίδιο keystream απομονώνει τα `p ⊕ p'` / `q ⊕ q'`, τα οποία μπορούν να ανακτηθούν με brute force σε δευτερόλεπτα.<sup>[[1]](#references)</sup>
- Τα προεπιλεγμένα IVs σε βιβλιοθήκες (π.χ. σταθερό `000...01`) αποτελούν κρίσιμο footgun: κάθε κρυπτογράφηση επαναλαμβάνει το ίδιο keystream, μετατρέποντας το CTR σε one-time pad που χρησιμοποιείται ξανά.<sup>[[1]](#references)</sup>

**Malleability του CTR**

- Το CTR παρέχει μόνο confidentiality: η αναστροφή bits στο ciphertext αναστρέφει ντετερμινιστικά τα ίδια bits στο plaintext. Χωρίς authentication tag, οι attackers μπορούν να παραποιήσουν δεδομένα (π.χ. να τροποποιήσουν κλειδιά, flags ή μηνύματα) χωρίς να εντοπιστούν.
- Χρησιμοποιήστε AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 κ.λπ.) και επιβάλλετε την επαλήθευση του tag για να εντοπίζετε αναστροφές bits.

### GCM

Το GCM επίσης καταρρέει όταν επαναχρησιμοποιείται το nonce. Αν το ίδιο key+nonce χρησιμοποιηθεί περισσότερες από μία φορές, συνήθως προκύπτουν τα εξής:

- Επαναχρησιμοποίηση keystream για την κρυπτογράφηση (όπως στο CTR), που επιτρέπει την ανάκτηση plaintext όταν είναι γνωστό οποιοδήποτε plaintext.
- Απώλεια των εγγυήσεων ακεραιότητας. Ανάλογα με τα δεδομένα που είναι διαθέσιμα (πολλαπλά ζεύγη message/tag με το ίδιο nonce), οι attackers ενδέχεται να μπορούν να πλαστογραφήσουν tags.

Οδηγίες λειτουργίας:

- Αντιμετωπίζετε την «επαναχρησιμοποίηση nonce» σε AEAD ως κρίσιμη ευπάθεια.
- AEADs ανθεκτικά στην κακή χρήση, όπως το AES-GCM-SIV, περιορίζουν τις συνέπειες της επαναχρησιμοποίησης nonce. Οι callers θα πρέπει και πάλι να παρέχουν μοναδικά nonces, όπως απαιτεί το interface της κατασκευής· η τυχαία επαναχρησιμοποίηση έχει περιορισμένες συνέπειες σε σύγκριση με το συνηθισμένο GCM.<sup>[[3]](#references)[[4]](#references)</sup>
- Αν έχετε πολλά ciphertexts με το ίδιο nonce, ξεκινήστε ελέγχοντας σχέσεις της μορφής `C1 XOR C2 = P1 XOR P2`.

### Εργαλεία

- Το [CyberChef](https://gchq.github.io/CyberChef/) για γρήγορα πειράματα.<sup>[[8]](#references)</sup>
- Το πακέτο [PyCryptodome](https://www.pycryptodome.org/) της Python για scripting.<sup>[[9]](#references)</sup>

## Μοτίβα εκμετάλλευσης ECB

Το ECB (Electronic Code Book) κρυπτογραφεί κάθε block ανεξάρτητα:

- ίσα plaintext blocks → ίσα ciphertext blocks
- αυτό προκαλεί leak της δομής και επιτρέπει επιθέσεις τύπου cut-and-paste

![Διάγραμμα block αποκρυπτογράφησης της λειτουργίας ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ιδέα εντοπισμού: μοτίβο token/cookie

Αν συνδεθείτε πολλές φορές και **παίρνετε πάντα το ίδιο cookie**, το ciphertext μπορεί να είναι ντετερμινιστικό (ECB ή σταθερό IV).

Αν δημιουργήσετε δύο χρήστες με σχεδόν ίδια διάταξη plaintext (π.χ. μεγάλες επαναλήψεις χαρακτήρων) και δείτε επαναλαμβανόμενα ciphertext blocks στα ίδια offsets, το ECB είναι βασικός ύποπτος.

### Μοτίβα εκμετάλλευσης

#### Αφαίρεση ολόκληρων blocks

Αν η μορφή του token είναι κάτι σαν `<username>|<password>` και το όριο block είναι ευθυγραμμισμένο, μερικές φορές μπορείτε να δημιουργήσετε έναν χρήστη έτσι ώστε το block `admin` να είναι ευθυγραμμισμένο και, στη συνέχεια, να αφαιρέσετε τα προηγούμενα blocks για να αποκτήσετε έγκυρο token για τον `admin`.

#### Μετακίνηση blocks

Αν το backend δέχεται padding/επιπλέον spaces (`admin` έναντι `admin    `), μπορείτε να:

- Ευθυγραμμίσετε ένα block που περιέχει `admin   `
- Ανταλλάξετε/επαναχρησιμοποιήσετε αυτό το ciphertext block σε άλλο token

## Padding Oracle

### Τι είναι

Σε λειτουργία CBC, αν ο server αποκαλύψει (άμεσα ή έμμεσα) αν το αποκρυπτογραφημένο plaintext έχει **έγκυρο padding PKCS#7**, συχνά μπορείτε να:<sup>[[7]](#references)</sup>

- Αποκρυπτογραφήσετε ciphertext χωρίς το key
- Δημιουργήσετε ciphertext που αποκρυπτογραφείται σε επιλεγμένο plaintext, όταν μπορείτε να υποβάλετε κατασκευασμένα προηγούμενα blocks ή IVs και η εφαρμογή αποδέχεται το μήνυμα με έγκυρο padding

Το oracle μπορεί να είναι:

- Ένα συγκεκριμένο μήνυμα σφάλματος
- Διαφορετικό HTTP status / μέγεθος απόκρισης
- Διαφορά στον χρόνο απόκρισης

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

- Το μέγεθος block είναι συχνά `16` για το AES.
- Το `-encoding 0` σημαίνει Base64.
- Χρησιμοποιήστε το `-error` αν το oracle είναι μια συγκεκριμένη συμβολοσειρά.

### Γιατί λειτουργεί

Η αποκρυπτογράφηση CBC υπολογίζει `P[i] = D(C[i]) XOR C[i-1]`. Τροποποιώντας bytes στο `C[i-1]` και παρατηρώντας αν το padding είναι έγκυρο, μπορείτε να ανακτήσετε το `P[i]` byte προς byte.

## Bit-flipping in CBC

Ακόμα και χωρίς padding oracle, το CBC είναι malleable. Αν μπορείτε να τροποποιήσετε blocks του ciphertext και η εφαρμογή χρησιμοποιεί το αποκρυπτογραφημένο plaintext ως δομημένα δεδομένα (π.χ., `role=user`), μπορείτε να αντιστρέψετε συγκεκριμένα bits ώστε να αλλάξετε επιλεγμένα bytes plaintext σε μια συγκεκριμένη θέση του επόμενου block.

Τυπικό μοτίβο CTF:

- Token = `IV || C1 || C2 || ...`
- Ελέγχετε bytes στο `C[i]`
- Στοχεύετε bytes plaintext στο `P[i+1]`, επειδή `P[i+1] = D(C[i+1]) XOR C[i]`

Αυτό από μόνο του δεν παραβιάζει την εμπιστευτικότητα, αλλά αποτελεί συνηθισμένο primitive κλιμάκωσης προνομίων όταν απουσιάζει η ακεραιότητα.

## CBC-MAC

Το CBC-MAC είναι ασφαλές μόνο υπό συγκεκριμένες συνθήκες (κυρίως **μηνύματα σταθερού μήκους** και σωστό domain separation). Το AES-CMAC είναι μια τυποποιημένη κατασκευή που χειρίζεται με ασφάλεια εισόδους μεταβλητού μήκους.<sup>[[5]](#references)</sup>

### Κλασικό μοτίβο πλαστογράφησης μεταβλητού μήκους

Το CBC-MAC υπολογίζεται συνήθως ως εξής:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Αν μπορείτε να λάβετε tags για μηνύματα της επιλογής σας, συχνά μπορείτε να κατασκευάσετε ένα tag για συνένωση (ή σχετική κατασκευή) χωρίς να γνωρίζετε το κλειδί, εκμεταλλευόμενοι τον τρόπο με τον οποίο το CBC συνδέει τα blocks.

Αυτό εμφανίζεται συχνά σε cookies/tokens CTF που υπολογίζουν MAC για το username ή το role με CBC-MAC.

### Ασφαλέστερες εναλλακτικές

- Χρησιμοποιήστε HMAC (SHA-256/512)
- Χρησιμοποιήστε σωστά το CMAC (AES-CMAC)
- Συμπεριλάβετε το μήκος του μηνύματος / domain separation

## Stream ciphers: XOR and RC4

### Το νοητικό μοντέλο

Οι περισσότερες περιπτώσεις χρήσης stream cipher ανάγονται στο εξής:

`ciphertext = plaintext XOR keystream`

Άρα:

- Αν γνωρίζετε το plaintext, ανακτάτε το keystream.
- Αν επαναχρησιμοποιηθεί το keystream (ίδιο key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Αν γνωρίζετε οποιοδήποτε τμήμα plaintext στη θέση `i`, μπορείτε να ανακτήσετε bytes του keystream και να αποκρυπτογραφήσετε άλλα ciphertext στις ίδιες θέσεις.

Αυτόματοι επιλυτές:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

Το RC4 είναι ένα παρωχημένο stream cipher· η κρυπτογράφηση και η αποκρυπτογράφηση είναι η ίδια πράξη XOR. Οι γνωστές μεροληψίες του το καθιστούν ακατάλληλο για νέα συστήματα, ενώ το TLS απαγορεύει ρητά τις cipher suites του.<sup>[[6]](#references)</sup>

Αν μπορείτε να λάβετε κρυπτογράφηση RC4 γνωστού plaintext με το ίδιο κλειδί, μπορείτε να ανακτήσετε το keystream και να αποκρυπτογραφήσετε άλλα μηνύματα ίδιου μήκους/offset.

Writeup αναφοράς (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Απροσεξία έναντι δεξιοτεχνίας στην κρυπτογραφία](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Σύσταση για τρόπους λειτουργίας block cipher](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Σύσταση για το Galois/Counter Mode (GCM) και το GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Αυθεντικοποιημένη κρυπτογράφηση ανθεκτική σε κακή χρήση nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - Ο αλγόριθμος AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Απαγόρευση των cipher suites RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Έλεγχος για Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Τεκμηρίωση PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
