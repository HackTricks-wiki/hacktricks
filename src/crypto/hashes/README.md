# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Συνήθη μοτίβα σε CTF

- Η «υπογραφή» είναι στην πραγματικότητα `hash(secret || message)` → length extension.
- Hashes κωδικών πρόσβασης χωρίς salt → ταχύτερο επαναλαμβανόμενο cracking και επιθέσεις αναζήτησης σε προϋπολογισμένους πίνακες.
- Σύγχυση μεταξύ hash και MAC (hash != authentication).

## Επίθεση length extension σε hash

### Τεχνική

Μια επίθεση length extension μπορεί να είναι δυνατή όταν ένας server υπολογίζει μια «υπογραφή» όπως:

`sig = HASH(secret || message)`

και χρησιμοποιεί ένα hash Merkle-Damgård, όπως MD5, SHA-1 ή SHA-256.

Αν γνωρίζετε:

- `message`
- `sig`
- τη συνάρτηση hash
- (ή μπορείτε να κάνετε brute-force) το `len(secret)`

Τότε μπορείτε να υπολογίσετε μια έγκυρη υπογραφή για:

`message || padding || appended_data`

χωρίς να γνωρίζετε το secret.<sup>[[1]](#references)</sup>

### Σημαντικός περιορισμός: το HMAC δεν επηρεάζεται

Οι επιθέσεις length extension εφαρμόζονται σε ευάλωτες κατασκευές με πρόθεμα, όπως `HASH(secret || message)`. Δεν αποκαλύπτουν την κατασκευή HMAC (για παράδειγμα, HMAC-SHA256), η οποία συνδυάζει ένα κλειδί με ξεχωριστές εσωτερικές και εξωτερικές εφαρμογές hash.<sup>[[1]](#references)[[2]](#references)</sup>

### Εργαλεία

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings Python για το εργαλείο length extension HashPump<sup>[[7]](#references)</sup>

### Καλή επεξήγηση

[Everything you need to know about hash length extension attacks](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing και cracking κωδικών πρόσβασης

### Πρώτες ερωτήσεις<sup>[[4]](#references)</sup>

- Χρησιμοποιείται **salt**; (αναζητήστε μορφές `salt$hash`)
- Είναι **γρήγορο hash** (MD5/SHA1/SHA256) ή **αργό KDF** (bcrypt/scrypt/argon2/PBKDF2);
- Έχετε κάποια **ένδειξη μορφής** (λειτουργία hashcat / μορφή John);

### Πρακτική ροή εργασίας<sup>[[5]](#references)[[6]](#references)</sup>

1. Προσδιορίστε το hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Αν δεν έχει salt και είναι συνηθισμένο: δοκιμάστε online DBs και εργαλεία αναγνώρισης από την ενότητα ροής εργασίας κρυπτογραφίας.
3. Διαφορετικά, κάντε cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Συνήθη λάθη που μπορείτε να εκμεταλλευτείτε

- Επαναχρησιμοποίηση του ίδιου κωδικού πρόσβασης από πολλούς χρήστες → κάντε crack έναν και κάντε pivot.
- Περικομμένα hashes / προσαρμοσμένοι μετασχηματισμοί → κανονικοποιήστε και δοκιμάστε ξανά.
- Αδύναμες παράμετροι KDF (π.χ. λίγες επαναλήψεις PBKDF2) → εξακολουθεί να είναι δυνατή η αποκρυπτογράφηση με cracking.

### Oracle bcrypt με επιλεγμένη είσοδο και προσαρτημένο secret

Μια callable helper που επιστρέφει `bcrypt(user_input || secret)` μπορεί να αποκαλύψει πληροφορίες για ένα προσαρτημένο secret, αν η υλοποίηση bcrypt περικόπτει σιωπηρά την είσοδο μετά από 72 **bytes**. Ένα όριο στον αριθμό χαρακτήρων πριν από την κωδικοποίηση UTF-8 δεν επιβάλλει αυτό το όριο σε bytes: οι πολυ-byte χαρακτήρες μπορούν να γεμίσουν την είσοδο του bcrypt, αφήνοντας χώρο μόνο για ένα μικρό πρόθεμα του secret. Οι επιλεγμένες είσοδοι και τα hashes που επιστρέφονται μπορεί κατόπιν να επιτρέψουν offline ελέγχους υποψήφιων bytes του επιθέματος. Αυτό απαιτεί έλεγχο της εισόδου της helper, γνώση του ακριβούς μετασχηματισμού και της κωδικοποίησής της, καθώς και υλοποίηση που πράγματι περικόπτει· μια callable helper ή ένα hash bcrypt από μόνα τους δεν αποδεικνύουν ότι ισχύουν όλα αυτά. Η [pyca/bcrypt τεκμηριώνει](https://github.com/pyca/bcrypt#maximum-password-length) ότι η τρέχουσα `hashpw` προκαλεί σφάλμα για εισόδους μεγαλύτερες από 72 bytes, ενώ παλαιότερες εκδόσεις τις περικόπταν σιωπηρά. Άλλα wrappers μπορεί να κάνουν prehash ή να απορρίπτουν μεγάλες εισόδους, επομένως επαληθεύστε την εγκατεστημένη υλοποίηση αντί να υποθέτετε ότι γίνεται περικοπή.

Η χρήση ενός secret που ανακτήθηκε για διαφορετικό λογαριασμό απαιτεί επίσης αποδείξεις ότι το εκτεθειμένο hash δημιουργήθηκε με το **ίδιο** secret και τον ίδιο μετασχηματισμό, καθώς και ξεχωριστό διαπιστευτήριο ή διαδρομή σύνδεσης. Μια helper hashing που εκτελείται ως root πρέπει να εξετάζεται ως oracle μόνο αν ο χρήστης με χαμηλότερα προνόμια μπορεί να την εκτελέσει βάσει της ισχύουσας πολιτικής· η παθητική απαρίθμηση του host δεν χρειάζεται να την καλέσει ή να υποβάλει επιλεγμένους κωδικούς πρόσβασης.

## References

- [1] [SkullSecurity - Όσα πρέπει να γνωρίζετε για τις επιθέσεις length extension σε hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Κώδικας επαλήθευσης ταυτότητας μηνύματος με keyed hash](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Φύλλο αναφοράς αποθήκευσης κωδικών πρόσβασης](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Παραδείγματα hashes του Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Επιλογές γραμμής εντολών του John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: bindings Python του `hashpumpy` για το HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
