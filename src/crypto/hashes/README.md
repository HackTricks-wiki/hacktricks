# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Συνήθη μοτίβα σε CTF

- Το «signature» είναι στην πραγματικότητα `hash(secret || message)` → length extension.
- Hashes κωδικών χωρίς salt → ταχύτερο επαναλαμβανόμενο cracking και επιθέσεις αναζήτησης με προϋπολογισμένους πίνακες.
- Σύγχυση ανάμεσα σε hash και MAC (hash != authentication).

## Επίθεση hash length extension

### Technique

Μια επίθεση length extension μπορεί να είναι δυνατή όταν ένας server υπολογίζει ένα «signature» όπως:

`sig = HASH(secret || message)`

και χρησιμοποιεί ένα hash Merkle-Damgård, όπως MD5, SHA-1 ή SHA-256.

Αν γνωρίζεις:

- `message`
- `sig`
- τη συνάρτηση hash
- (ή μπορείς να κάνεις brute-force) το `len(secret)`

Τότε μπορείς να υπολογίσεις ένα έγκυρο signature για:

`message || padding || appended_data`

χωρίς να γνωρίζεις το secret.<sup>[[1]](#references)</sup>

### Σημαντικός περιορισμός: Το HMAC δεν επηρεάζεται

Οι επιθέσεις length extension εφαρμόζονται σε ευάλωτες κατασκευές prefix, όπως `HASH(secret || message)`. Δεν αποκαλύπτουν την κατασκευή HMAC (για παράδειγμα, HMAC-SHA256), η οποία συνδυάζει ένα key με ξεχωριστές εσωτερικές και εξωτερικές εφαρμογές hash.<sup>[[1]](#references)[[2]](#references)</sup>

### Tools

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), Python bindings για το εργαλείο length extension HashPump<sup>[[7]](#references)</sup>

### Καλή επεξήγηση

[Όλα όσα χρειάζεται να γνωρίζετε για τις επιθέσεις hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing και cracking κωδικών

### Πρώτες ερωτήσεις<sup>[[4]](#references)</sup>

- Έχει **salt**; (αναζήτησε μορφές `salt$hash`)
- Είναι **γρήγορο hash** (MD5/SHA1/SHA256) ή **αργό KDF** (bcrypt/scrypt/argon2/PBKDF2);
- Υπάρχει **υπόδειξη μορφής** (hashcat mode / John format);

### Πρακτική ροή εργασίας<sup>[[5]](#references)[[6]](#references)</sup>

1. Αναγνώρισε το hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Αν δεν έχει salt και είναι συνηθισμένο: δοκίμασε online DBs και εργαλεία αναγνώρισης από την ενότητα crypto workflow.
3. Διαφορετικά, κάνε cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Συνήθη λάθη που μπορείς να εκμεταλλευτείς

- Ίδιος κωδικός επαναχρησιμοποιείται από πολλούς χρήστες → κάνε crack τον έναν και μετά pivot.
- Truncated hashes / custom transforms → κανονικοποίησε και δοκίμασε ξανά.
- Αδύναμες παράμετροι KDF (π.χ. λίγες επαναλήψεις PBKDF2) → παραμένουν ευάλωτες σε cracking.

### Oracle bcrypt με επιλεγμένη είσοδο και προσαρτημένο secret

Ένα callable helper που επιστρέφει `bcrypt(user_input || secret)` μπορεί να αποκαλύψει πληροφορίες για ένα προσαρτημένο secret, αν η υλοποίηση του bcrypt αποκόπτει σιωπηρά την είσοδο μετά τα 72 **bytes**. Ένα όριο στον αριθμό χαρακτήρων πριν από την κωδικοποίηση UTF-8 δεν επιβάλλει αυτό το όριο bytes: οι χαρακτήρες πολλών bytes μπορούν να γεμίσουν την είσοδο bcrypt, αφήνοντας χώρο μόνο για ένα μικρό πρόθεμα του secret. Οι επιλεγμένες είσοδοι και τα hashes που επιστρέφονται μπορεί τότε να επιτρέψουν offline ελέγχους υποψήφιων bytes του suffix. Αυτό απαιτεί έλεγχο της εισόδου του helper, γνώση του ακριβούς transform και της κωδικοποίησής του, καθώς και υλοποίηση που πράγματι αποκόπτει την είσοδο· η ύπαρξη ενός callable helper ή ενός bcrypt hash από μόνη της δεν αρκεί για να τεκμηριώσει όλη την αλυσίδα. Η [τεκμηρίωση του pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) αναφέρει ότι το τρέχον `hashpw` προκαλεί σφάλμα για εισόδους άνω των 72 bytes, ενώ παλαιότερες συμπεριφορές τις απέκοπταν σιωπηρά. Άλλα wrappers μπορεί να κάνουν prehash ή να απορρίπτουν μεγάλες εισόδους, επομένως επαλήθευσε την εγκατεστημένη υλοποίηση αντί να υποθέτεις ότι γίνεται αποκοπή.

Η χρήση ενός ανακτημένου secret σε διαφορετικό account απαιτεί επίσης στοιχεία ότι το εκτεθειμένο hash του δημιουργήθηκε με το **ίδιο** secret και transform, καθώς και ξεχωριστό credential ή login path. Ένα hashing helper που εκτελείται ως root πρέπει να εξεταστεί ως oracle μόνο αν ο χρήστης με χαμηλότερα privileges μπορεί να το καλέσει σύμφωνα με την ισχύουσα πολιτική· η παθητική απαρίθμηση του host δεν χρειάζεται να το καλέσει ή να υποβάλει επιλεγμένους κωδικούς.

## References

- [1] [SkullSecurity - Όλα όσα χρειάζεται να γνωρίζετε για τις επιθέσεις hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Κώδικας πιστοποίησης μηνυμάτων με keyed hash](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Συνοπτικός οδηγός αποθήκευσης κωδικών](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Παραδείγματα hashes του Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Επιλογές γραμμής εντολών του John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: `hashpumpy` Python bindings για το HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}
