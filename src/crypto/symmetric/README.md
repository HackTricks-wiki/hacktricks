# Συμμετρική Κρυπτογραφία

{{#include ../../banners/hacktricks-training.md}}

## Τι να αναζητάτε σε CTFs

- **Κακή χρήση mode**: μοτίβα ECB, malleability του CBC, επαναχρησιμοποίηση nonce στο CTR/GCM.
- **Padding oracles**: διαφορετικά errors/timings για κακό padding.
- **Σύγχυση MAC**: χρήση CBC-MAC με μηνύματα μεταβλητού μήκους ή λάθη MAC-then-encrypt.
- **XOR παντού**: τα stream ciphers και οι custom κατασκευές συχνά ανάγονται σε XOR με ένα keystream.

## AES modes και κακή χρήση

### ECB: Electronic Codebook

Το ECB κάνει leak μοτίβα: ίσα plaintext blocks → ίσα ciphertext blocks. Αυτό επιτρέπει:

- Cut-and-paste / αναδιάταξη blocks
- Διαγραφή block (αν το format παραμένει έγκυρο)

Αν μπορείτε να ελέγξετε το plaintext και να παρατηρήσετε το ciphertext (ή cookies), δοκιμάστε να δημιουργήσετε επαναλαμβανόμενα blocks (π.χ. πολλά `A`) και αναζητήστε επαναλήψεις.

### CBC: Cipher Block Chaining

- Το CBC είναι **malleable**: η αλλαγή bits στο `C[i-1]` αλλάζει προβλέψιμα bits στο `P[i]`.
- Αν το σύστημα εκθέτει valid padding έναντι invalid padding, μπορεί να έχετε ένα **padding oracle**.

### CTR

Το CTR μετατρέπει το AES σε stream cipher: `C = P XOR keystream`.

Αν ένα nonce/IV επαναχρησιμοποιηθεί με το ίδιο key:

- `C1 XOR C2 = P1 XOR P2` (κλασική επαναχρησιμοποίηση keystream)
- Με γνωστό plaintext, μπορείτε να ανακτήσετε το keystream και να κάνετε decrypt άλλα.

**Μοτίβα exploitation επαναχρησιμοποίησης Nonce/IV**

- Ανακτήστε το keystream όπου το plaintext είναι γνωστό/προβλέψιμο:

```text
keystream[i..] = ciphertext[i..] XOR known_plaintext[i..]
```

Εφαρμόστε τα ανακτημένα bytes του keystream για να κάνετε decrypt οποιοδήποτε άλλο ciphertext που δημιουργήθηκε με το ίδιο key+IV στα ίδια offsets.
- Τα highly structured δεδομένα (π.χ. πιστοποιητικά ASN.1/X.509, file headers, JSON/CBOR) παρέχουν μεγάλες περιοχές γνωστού plaintext. Συχνά μπορείτε να κάνετε XOR το ciphertext του πιστοποιητικού με το προβλέψιμο certificate body για να εξαγάγετε το keystream και έπειτα να κάνετε decrypt άλλα secrets που είναι encrypted με το reused IV. Δείτε επίσης το [TLS & Certificates](../tls-and-certificates/README.md) για τυπικά certificate layouts.<sup>[[1]](#references)</sup>
- Όταν πολλά secrets του **ίδιου serialized format/size** είναι encrypted με το ίδιο key+IV, το field alignment κάνει leak ακόμη και χωρίς πλήρες γνωστό plaintext. Παράδειγμα: τα PKCS#8 RSA keys ίδιου μεγέθους modulus τοποθετούν τους prime factors στα ίδια offsets (~99.6% alignment για 2048-bit). Κάνοντας XOR δύο ciphertexts υπό το reused keystream, απομονώνετε τα `p ⊕ p'` / `q ⊕ q'`, τα οποία μπορούν να ανακτηθούν με brute force σε δευτερόλεπτα.<sup>[[1]](#references)</sup>
- Τα default IVs σε libraries (π.χ. σταθερό `000...01`) αποτελούν critical footgun: κάθε encryption επαναλαμβάνει το ίδιο keystream, μετατρέποντας το CTR σε reused one-time pad.<sup>[[1]](#references)</sup>

**CTR malleability**

- Το CTR παρέχει μόνο confidentiality: η αλλαγή bits στο ciphertext αλλάζει ντετερμινιστικά τα ίδια bits στο plaintext. Χωρίς authentication tag, οι attackers μπορούν να κάνουν tamper στα δεδομένα (π.χ. να αλλάξουν keys, flags ή messages) χωρίς να εντοπιστούν.
- Χρησιμοποιήστε AEAD (GCM, GCM-SIV, ChaCha20-Poly1305 κ.λπ.) και επιβάλετε tag verification για να εντοπίζετε bit-flips.

### GCM

Το GCM επίσης καταρρέει σοβαρά υπό nonce reuse. Αν το ίδιο key+nonce χρησιμοποιηθεί περισσότερες από μία φορές, συνήθως προκύπτουν:

- Keystream reuse για encryption (όπως στο CTR), επιτρέποντας την ανάκτηση plaintext όταν οποιοδήποτε plaintext είναι γνωστό.
- Απώλεια integrity guarantees. Ανάλογα με το τι εκτίθεται (πολλά message/tag pairs υπό το ίδιο nonce), οι attackers μπορεί να μπορούν να κάνουν forge tags.

Οδηγίες λειτουργίας:

- Αντιμετωπίστε το "nonce reuse" σε AEAD ως critical vulnerability.
- Τα misuse-resistant AEADs (π.χ. GCM-SIV) μειώνουν τις επιπτώσεις του nonce misuse, αλλά και πάλι απαιτούν unique nonces/IVs.
- Αν έχετε πολλά ciphertexts υπό το ίδιο nonce, ξεκινήστε ελέγχοντας σχέσεις τύπου `C1 XOR C2 = P1 XOR P2`.

### Tools

- CyberChef για quick experiments: https://gchq.github.io/CyberChef/
- Python: `pycryptodome` για scripting

## Μοτίβα exploitation ECB

Το ECB (Electronic Code Book) κάνει encrypt κάθε block ανεξάρτητα:

- ίσα plaintext blocks → ίσα ciphertext blocks
- αυτό κάνει leak τη δομή και επιτρέπει attacks τύπου cut-and-paste

![Διάγραμμα block decryption του ECB](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

### Ιδέα detection: μοτίβο token/cookie

Αν κάνετε login αρκετές φορές και **λαμβάνετε πάντα το ίδιο cookie**, το ciphertext μπορεί να είναι deterministic (ECB ή fixed IV).

Αν δημιουργήσετε δύο users με σχεδόν ίδια plaintext layouts (π.χ. μεγάλους επαναλαμβανόμενους χαρακτήρες) και δείτε επαναλαμβανόμενα ciphertext blocks στα ίδια offsets, το ECB είναι βασικός ύποπτος.

### Μοτίβα exploitation

#### Αφαίρεση ολόκληρων blocks

Αν το token format είναι κάτι όπως `<username>|<password>` και το block boundary είναι aligned, μερικές φορές μπορείτε να δημιουργήσετε έναν user έτσι ώστε το block `admin` να εμφανίζεται aligned και έπειτα να αφαιρέσετε τα προηγούμενα blocks για να αποκτήσετε valid token για `admin`.

#### Μετακίνηση blocks

Αν το backend ανέχεται padding/extra spaces (`admin` έναντι `admin    `), μπορείτε να:

- Κάνετε align ένα block που περιέχει `admin   `
- Κάνετε swap/reuse αυτό το ciphertext block σε άλλο token

## Padding Oracle

### Τι είναι

Στο CBC mode, αν ο server αποκαλύπτει (άμεσα ή έμμεσα) αν το decrypted plaintext έχει **valid PKCS#7 padding**, συχνά μπορείτε να:

- Κάνετε decrypt ciphertext χωρίς το key
- Κάνετε encrypt chosen plaintext (forge ciphertext)

Το oracle μπορεί να είναι:

- Ένα συγκεκριμένο error message
- Διαφορετικό HTTP status / response size
- Διαφορά στο timing

### Practical exploitation

Το PadBuster είναι το κλασικό tool:

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
- Το `-encoding 0` σημαίνει Base64.
- Χρησιμοποίησε `-error` αν το oracle είναι μια συγκεκριμένη συμβολοσειρά.

### Γιατί λειτουργεί

Η αποκρυπτογράφηση CBC υπολογίζει `P[i] = D(C[i]) XOR C[i-1]`. Τροποποιώντας bytes στο `C[i-1]` και παρατηρώντας αν το padding είναι έγκυρο, μπορείς να ανακτήσεις το `P[i]` byte-byte.

## Bit-flipping σε CBC

Ακόμη και χωρίς padding oracle, το CBC είναι malleable. Αν μπορείς να τροποποιήσεις ciphertext blocks και η εφαρμογή χρησιμοποιεί το αποκρυπτογραφημένο plaintext ως structured data (π.χ. `role=user`), μπορείς να αντιστρέψεις συγκεκριμένα bits για να αλλάξεις επιλεγμένα bytes του plaintext σε μια επιλεγμένη θέση στο επόμενο block.

Τυπικό CTF pattern:

- Token = `IV || C1 || C2 || ...`
- Ελέγχεις bytes στο `C[i]`
- Στοχεύεις bytes plaintext στο `P[i+1]`, επειδή `P[i+1] = D(C[i+1]) XOR C[i]`

Αυτό από μόνο του δεν αποτελεί παραβίαση της confidentiality, αλλά είναι ένα συνηθισμένο privilege-escalation primitive όταν απουσιάζει η integrity.

## CBC-MAC

Το CBC-MAC είναι ασφαλές μόνο υπό συγκεκριμένες προϋποθέσεις (κυρίως **fixed-length messages** και σωστό domain separation).

### Classic variable-length forgery pattern

Το CBC-MAC συνήθως υπολογίζεται ως εξής:

- IV = 0
- `tag = last_block( CBC_encrypt(key, message, IV=0) )`

Αν μπορείς να λάβεις tags για messages της επιλογής σου, συχνά μπορείς να δημιουργήσεις ένα tag για concatenation (ή σχετική κατασκευή) χωρίς να γνωρίζεις το key, εκμεταλλευόμενος τον τρόπο με τον οποίο το CBC συνδέει τα blocks.

Αυτό εμφανίζεται συχνά σε CTF cookies/tokens που χρησιμοποιούν CBC-MAC για MAC του username ή του role.

### Ασφαλέστερες εναλλακτικές

- Χρησιμοποίησε HMAC (SHA-256/512)
- Χρησιμοποίησε σωστά το CMAC (AES-CMAC)
- Συμπέλαβε το message length / domain separation

## Stream ciphers: XOR και RC4

### Το mental model

Οι περισσότερες περιπτώσεις με stream ciphers ανάγονται στο εξής:

`ciphertext = plaintext XOR keystream`

Επομένως:

- Αν γνωρίζεις το plaintext, ανακτάς το keystream.
- Αν το keystream επαναχρησιμοποιείται (ίδιο key+nonce), `C1 XOR C2 = P1 XOR P2`.

### XOR-based encryption

Αν γνωρίζεις οποιοδήποτε τμήμα plaintext στη θέση `i`, μπορείς να ανακτήσεις bytes του keystream και να αποκρυπτογραφήσεις άλλα ciphertexts στις ίδιες θέσεις.

Αυτόματοι λύτες:

- [https://wiremask.eu/tools/xor-cracker/](https://wiremask.eu/tools/xor-cracker/)

### RC4

Το RC4 είναι stream cipher· η κρυπτογράφηση και η αποκρυπτογράφηση είναι η ίδια λειτουργία.

Αν μπορείς να λάβεις RC4 encryption γνωστού plaintext με το ίδιο key, μπορείς να ανακτήσεις το keystream και να αποκρυπτογραφήσεις άλλα messages ίδιου length/offset.

Reference writeup (HTB Kryptos):

{{#ref}}
https://0xrick.github.io/hack-the-box/kryptos/
{{#endref}}

## References

- [1] [Trail of Bits – Carelessness versus craftsmanship in cryptography](https://blog.trailofbits.com/2026/02/18/carelessness-versus-craftsmanship-in-cryptography/)

{{#include ../../banners/hacktricks-training.md}}
