# Συμμετρική Κρυπτογραφία

{{#include ../../banners/hacktricks-training.md}}

## Τι να αναζητάτε σε CTFs

- **Κακή χρήση mode**: μοτίβα ECB, malleability του CBC, επαναχρησιμοποίηση nonce στο CTR/GCM.
- **Padding oracles**: διαφορετικά errors/timings για λανθασμένο padding.
- **Σύγχυση MAC**: χρήση CBC-MAC με μηνύματα μεταβλητού μήκους ή λάθη MAC-then-encrypt.
- **XOR παντού**: τα stream ciphers και οι custom constructions συχνά καταλήγουν σε XOR με ένα keystream.

## AES modes και κακή χρήση

Το NIST καθορίζει τα modes εμπιστευτικότητας ECB, CBC και CTR στο SP 800-38A, καθώς και το authenticated encryption GCM στο SP 800-38D.<sup>[[2]](#references)[[3]](#references)</sup>

### ECB: Electronic Codebook

Το ECB κάνει leak τα patterns: ίσα plaintext blocks → ίσα ciphertext blocks. Αυτό επιτρέπει:

- Cut-and-paste / αναδιάταξη blocks
- Διαγραφή block (αν η μορφή παραμένει έγκυρη)

Αν μπορείτε να ελέγξετε το plaintext και να παρατηρήσετε το ciphertext (ή cookies), δοκιμάστε να δημιουργήσετε επαναλαμβανόμενα blocks (π.χ. πολλά `A`) και αναζητήστε επαναλήψεις.

### CBC: Cipher Block Chaining

- Το CBC είναι **malleable**: η αντιστροφή bits στο `C[i-1]` αντιστρέφει προβλέψιμα bits στο `P[i]`, ενώ ταυτόχρονα καταστρέφει το `P[i-1]`. Η τροποποίηση του IV στοχεύει το πρώτο plaintext block χωρίς να καταστρέφει ένα προηγούμενο plaintext block.
- Αν το σύστημα αποκαλύπτει αν το padding είναι έγκυρο ή μη έγκυρο, μπορεί να έχετε ένα **padding oracle**.

### CTR

Το CTR μετατρέπει το AES σε stream cipher: `C = P XOR keystream`.

Αν ένα nonce/IV επαναχρησιμοποιηθεί με το ίδιο key:

- `C1 XOR C2 = P1 XOR P2` (κλασική επαναχρησιμοποίηση keystream)
- Με γνωστό plaintext, μπορείτε να ανακτήσετε το keystream και να κάνετε decrypt άλλα ciphertexts.

**Μοτίβα exploitation επαναχρησιμοποίησης Nonce/IV**

- Ανακτήστε το keystream όπου το plaintext είναι γνωστό/προβλέψιμο:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Εφαρμόστε τα ανακτημένα bytes του keystream για να κάνετε decrypt οποιοδήποτε άλλο ciphertext δημιουργήθηκε με το ίδιο key+IV και στα ίδια offsets.
- Δεδομένα με ιδιαίτερα δομημένη μορφή (π.χ. certificates ASN.1/X.509, file headers, JSON/CBOR) παρέχουν μεγάλες περιοχές γνωστού plaintext. Συχνά μπορείτε να κάνετε XOR το ciphertext του certificate με το προβλέψιμο σώμα του certificate για να παράγετε το keystream και στη συνέχεια να κάνετε decrypt άλλα secrets που έχουν κρυπτογραφηθεί με το επαναχρησιμοποιημένο IV. Δείτε επίσης το [TLS & Certificates](../tls-and-certificates/README.md) για τυπικές διατάξεις certificates.<sup>[[1]](#references)</sup>
- Όταν πολλά secrets της **ίδιας serialized μορφής/μεγέθους** κρυπτογραφούνται με το ίδιο key+IV, η ευθυγράμμιση των πεδίων κάνει leak ακόμη και χωρίς πλήρες γνωστό plaintext. Παράδειγμα: τα RSA keys PKCS#8 με modulus ίδιου μεγέθους τοποθετούν τους prime factors στα ίδια offsets (περίπου 99,6% ευθυγράμμιση για 2048-bit). Κάνοντας XOR δύο ciphertexts με το επαναχρησιμοποιημένο keystream απομονώνεται το `p ⊕ p'` / `q ⊕ q'`, τα οποία μπορούν να ανακτηθούν με brute force σε δευτερόλεπτα.<sup>[[1]](#references)</sup>
- Τα προεπιλεγμένα IVs σε libraries (π.χ. σταθερό `000...01`) αποτελούν κρίσιμο footgun: κάθε encryption επαναλαμβάνει το ίδιο keystream, μετατρέποντας το CTR σε one-time pad που έχει επαναχρησιμοποιηθεί.<sup>[[1]](#references)</sup>

**CTR malleability**

- Το CTR παρέχει μόνο εμπιστευτικότητα: η αντιστροφή bits στο ciphertext αντιστρέφει ντετερμινιστικά τα ίδια bits στο plaintext. Χωρίς authentication tag, οι attackers μπορούν να τροποποιούν δεδομένα (π.χ. να αλλάζουν keys, flags ή messages) χωρίς να εντοπίζονται.
- Χρησιμοποιήστε AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 κ.λπ.) και επιβάλετε την επαλήθευση του tag για την ανίχνευση bit-flips.

### GCM

Το GCM επίσης καταρρέει όταν γίνεται επαναχρησιμοποίηση nonce. Αν το ίδιο key+nonce χρησιμοποιηθεί περισσότερες από μία φορές, συνήθως προκύπτουν:

- Επαναχρησιμοποίηση keystream για encryption (όπως στο CTR), επιτρέποντας την ανάκτηση plaintext όταν οποιοδήποτε plaintext είναι γνωστό.
- Απώλεια των εγγυήσεων ακεραιότητας. Ανάλογα με το τι εκτίθεται (πολλαπλά ζεύγη message/tag με το ίδιο nonce), οι attackers ενδέχεται να μπορούν να κάνουν forge tags.

Οδηγίες λειτουργίας:

- Αντιμετωπίστε την "επαναχρησιμοποίηση nonce" σε AEAD ως κρίσιμη ευπάθεια.
- Τα misuse-resistant AEADs, όπως το AES-GCM-SIV, μειώνουν τις συνέπειες της επαναχρησιμοποίησης nonce. Οι callers θα πρέπει και πάλι να παρέχουν μοναδικά nonces, όπως απαιτεί το interface της construction· η τυχαία επαναχρησιμοποίηση έχει περιορισμένες συνέπειες σε σύγκριση με το συνηθισμένο GCM.<sup>[[3]](#references)[[4]](#references)</sup>
- Αν έχετε πολλά ciphertexts με το ίδιο nonce, ξεκινήστε ελέγχοντας σχέσεις τύπου `C1 XOR C2 = P1 XOR P2`.

### Εργαλεία

- Το [CyberChef](https://gchq.github.io/CyberChef/) για γρήγορα experiments.<sup>[[8]](#references)</sup>
- Το package [PyCryptodome](https://www.pycryptodome.org/) της Python για scripting.<sup>[[9]](#references)</sup>

## Μοτίβα exploitation του ECB

Το ECB (Electronic Code Book) κρυπτογραφεί κάθε block ανεξάρτητα:

- ίσα plaintext blocks → ίσα ciphertext blocks
- αυτό κάνει leak τη δομή και επιτρέπει επιθέσεις τύπου cut-and-paste

![Διάγραμμα blocks αποκρυπτογράφησης ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ιδέα εντοπισμού: μοτίβο token/cookie

Αν κάνετε login πολλές φορές και **λαμβάνετε πάντα το ίδιο cookie**, το ciphertext μπορεί να είναι deterministic (ECB ή fixed IV).

Αν δημιουργήσετε δύο users με σχεδόν πανομοιότυπες διατάξεις plaintext (π.χ. μεγάλους χαρακτήρες που επαναλαμβάνονται) και δείτε επαναλαμβανόμενα ciphertext blocks στα ίδια offsets, το ECB είναι ο βασικός ύποπτος.

### Μοτίβα exploitation

#### Αφαίρεση ολόκληρων blocks

Αν η μορφή του token είναι κάτι όπως `<username>|<password>` και η ευθυγράμμιση των blocks ταιριάζει, μερικές φορές μπορείτε να δημιουργήσετε έναν user έτσι ώστε το block `admin` να είναι ευθυγραμμισμένο και στη συνέχεια να αφαιρέσετε τα προηγούμενα blocks για να αποκτήσετε ένα έγκυρο token για το `admin`.

#### Μετακίνηση blocks

Αν το backend ανέχεται padding/επιπλέον spaces (`admin` αντί για `admin    `), μπορείτε:

- Να ευθυγραμμίσετε ένα block που περιέχει `admin   `
- Να ανταλλάξετε/επαναχρησιμοποιήσετε αυτό το ciphertext block σε άλλο token

## Padding Oracle

### Τι είναι

Στο CBC mode, αν ο server αποκαλύπτει (άμεσα ή έμμεσα) αν το decrypted plaintext έχει **έγκυρο PKCS#7 padding**, συχνά μπορείτε:<sup>[[7]](#references)</sup>

- Να κάνετε decrypt ciphertext χωρίς το key
- Να κατασκευάσετε ένα ciphertext που γίνεται decrypt σε επιλεγμένο plaintext, όταν μπορείτε να υποβάλετε crafted preceding blocks ή IVs και η application αποδέχεται το resulting message με έγκυρο padding

Το oracle μπορεί να είναι:

- Ένα συγκεκριμένο error message
- Διαφορετικό HTTP status / μέγεθος response
- Διαφορά στον χρόνο απόκρισης

### Πρακτικό exploitation

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
- Χρησιμοποίησε `-error` αν το oracle είναι μια συγκεκριμένη συμβολοσειρά.

### Γιατί λειτουργεί

Η CBC αποκρυπτογράφηση υπολογίζει `P[i] = D(C[i]) XOR C[i-1]`. Τροποποιώντας bytes στο `C[i-1]` και παρατηρώντας αν το padding είναι έγκυρο, μπορείς να ανακτήσεις το `P[i]` byte προς byte.

## Bit-flipping στην CBC

Ακόμη και χωρίς padding oracle, η CBC είναι malleable. Αν μπορείς να τροποποιήσεις ciphertext blocks και η εφαρμογή χρησιμοποιεί το decrypted plaintext ως structured data (π.χ. `role=user`), μπορείς να αλλάξεις συγκεκριμένα bits ώστε να τροποποιήσεις επιλεγμένα plaintext bytes σε μια συγκεκριμένη θέση του επόμενου block.

Τυπικό CTF μοτίβο:

- Token = `IV || C1 || C2 || ...`
- Ελέγχεις bytes στο `C[i]`
- Στοχεύεις plaintext bytes στο `P[i+1]`, επειδή `P[i+1] = D(C[i+1]) XOR C[i]`

Αυτό από μόνο του δεν αποτελεί παραβίαση της εμπιστευτικότητας, αλλά είναι ένα συνηθισμένο privilege-escalation primitive όταν λείπει η ακεραιότητα.

## CBC-MAC

Το CBC-MAC είναι ασφαλές μόνο υπό συγκεκριμένες προϋποθέσεις (κυρίως **fixed-length messages** και σωστό domain separation). Το AES-CMAC είναι μια τυποποιημένη κατασκευή που χειρίζεται με ασφάλεια inputs μεταβλητού μήκους.<sup>[[5]](#references)</sup>

### Κλασικό μοτίβο forgery μεταβλητού μήκους

Το CBC-MAC υπολογίζεται συνήθως ως εξής:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Αν μπορείς να αποκτήσεις tags για messages της επιλογής σου, συχνά μπορείς να δημιουργήσεις ένα tag για μια concatenation (ή σχετική κατασκευή) χωρίς να γνωρίζεις το key, εκμεταλλευόμενος τον τρόπο με τον οποίο το CBC συνδέει τα blocks.

Αυτό εμφανίζεται συχνά σε CTF cookies/tokens που υπολογίζουν MAC για username ή role με CBC-MAC.

### Ασφαλέστερες εναλλακτικές

- Χρησιμοποίησε HMAC (SHA-256/512)
- Χρησιμοποίησε σωστά CMAC (AES-CMAC)
- Συμπέλαβε το μήκος του message / domain separation

## Stream ciphers: XOR και RC4

### Το νοητικό μοντέλο

Οι περισσότερες περιπτώσεις με stream ciphers ανάγονται στο εξής:

`ciphertext = plaintext XOR keystream`

Επομένως:

- Αν γνωρίζεις το plaintext, ανακτάς το keystream.
- Αν το keystream επαναχρησιμοποιείται (ίδιο key+nonce), `C1 XOR C2 = P1 XOR P2`.

### Κρυπτογράφηση βασισμένη σε XOR

Αν γνωρίζεις οποιοδήποτε τμήμα plaintext στη θέση `i`, μπορείς να ανακτήσεις bytes του keystream και να αποκρυπτογραφήσεις άλλα ciphertexts στις ίδιες θέσεις.

Αυτόματα εργαλεία επίλυσης:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

Το RC4 είναι ένα legacy stream cipher· η κρυπτογράφηση και η αποκρυπτογράφηση είναι η ίδια λειτουργία XOR. Τα γνωστά biases του το καθιστούν ακατάλληλο για νέα συστήματα και το TLS απαγορεύει ρητά τα cipher suites του.<sup>[[6]](#references)</sup>

Αν μπορείς να λάβεις RC4 encryption γνωστού plaintext με το ίδιο key, μπορείς να ανακτήσεις το keystream και να αποκρυπτογραφήσεις άλλα messages ίδιου μήκους/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Απροσεξία έναντι επιμελούς κατασκευής στην κρυπτογραφία](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)
- [2] [NIST SP 800-38A - Σύσταση για τρόπους λειτουργίας block ciphers](https://csrc.nist.gov/pubs/sp/800/38/a/final)
- [3] [NIST SP 800-38D - Σύσταση για το Galois/Counter Mode (GCM) και το GMAC](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [4] [RFC 8452 - AES-GCM-SIV: Authenticated Encryption με ανθεκτικότητα σε κακή χρήση nonce](https://www.rfc-editor.org/rfc/rfc8452)
- [5] [RFC 4493 - Ο αλγόριθμος AES-CMAC](https://www.rfc-editor.org/rfc/rfc4493)
- [6] [RFC 7465 - Απαγόρευση των cipher suites του RC4](https://www.rfc-editor.org/rfc/rfc7465)
- [7] [OWASP Web Security Testing Guide - Έλεγχος για Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)
- [8] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [9] [Τεκμηρίωση PyCryptodome](https://www.pycryptodome.org/)
{{#include ../../banners/hacktricks-training.md}}
