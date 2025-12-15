# Επιθέσεις RSA

{{#include ../../../banners/hacktricks-training.md}}

## Γρήγορη αξιολόγηση

Συλλέξτε:

- `n`, `e`, `c` (and any additional ciphertexts)
- Οποιαδήποτε σχέσεις μεταξύ των μηνυμάτων (same plaintext? shared modulus? structured plaintext?)
- Οποιαδήποτε leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Έπειτα δοκιμάστε:

- Έλεγχος παραγοντοποίησης (Factordb / `sage: factor(n)` για σχετικά μικρά)
- Μοτίβα μικρού εκθέτη (`e=3`, broadcast)
- Κοινό modulus / επαναλαμβανόμενοι πρώτοι αριθμοί
- Μέθοδοι πλεγμάτων (Coppersmith/LLL) όταν κάτι είναι σχεδόν γνωστό

## Συνηθισμένες επιθέσεις RSA

### Κοινό modulus

Αν δύο ciphertexts `c1, c2` κρυπτογραφούν το **ίδιο μήνυμα** κάτω από το **ίδιο modulus** `n` αλλά με διαφορετικούς εκθέτες `e1, e2` (και `gcd(e1,e2)=1`), μπορείτε να ανακτήσετε το `m` χρησιμοποιώντας τον εκτεταμένο αλγόριθμο του Ευκλείδη:

`m = c1^a * c2^b mod n` where `a*e1 + b*e2 = 1`.

Περίγραμμα παραδείγματος:

1. Υπολογίστε `(a, b) = xgcd(e1, e2)` ώστε `a*e1 + b*e2 = 1`
2. Αν `a < 0`, ερμηνεύστε `c1^a` ως `inv(c1)^{-a} mod n` (το ίδιο για `b`)
3. Πολλαπλασιάστε και μειώστε modulo `n`

### Κοινά πρώτοι παράγοντες μεταξύ moduli

Αν έχετε πολλαπλά RSA moduli από το ίδιο challenge, ελέγξτε αν μοιράζονται κάποιο prime:

- `gcd(n1, n2) != 1` implies a catastrophic key-generation failure.

Αυτό εμφανίζεται συχνά σε CTFs ως "we generated many keys quickly" or "bad randomness".

### Håstad broadcast / χαμηλός εκθέτης

Αν το ίδιο plaintext αποστέλλεται σε πολλούς παραλήπτες με μικρό `e` (συχνά `e=3`) και χωρίς σωστό padding, μπορείτε να ανακτήσετε το `m` μέσω CRT και ακέραιας ρίζας.

Τεχνική προϋπόθεση:

Αν έχετε `e` ciphertexts του ίδιου μηνύματος κάτω από αμοιβαία πρώτους moduli `n_i`:

- Χρησιμοποιήστε CRT για να ανακτήσετε `M = m^e` πάνω στο γινόμενο `N = Π n_i`
- Αν `m^e < N`, τότε `M` είναι η πραγματική ακέραια δύναμη, και `m = integer_root(M, e)`

### Wiener attack: μικρός ιδιωτικός εκθέτης

Αν το `d` είναι πολύ μικρό, τα συνεχόμενα κλάσματα μπορούν να το ανακτήσουν από `e/n`.

### Παγίδες του Textbook RSA

Αν δείτε:

- Χωρίς OAEP/PSS, raw modular exponentiation
- Deterministic encryption

τότε οι αλγεβρικές επιθέσεις και η κατάχρηση oracle γίνονται πολύ πιο πιθανές.

### Εργαλεία

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Πρότυπα σχετικών μηνυμάτων

Αν δείτε δύο ciphertexts κάτω από το ίδιο modulus με μηνύματα που συνδέονται αλγεβρικά (π.χ., `m2 = a*m1 + b`), ψάξτε για "related-message" επιθέσεις όπως Franklin–Reiter. Αυτές συνήθως απαιτούν:

- ίδιο modulus `n`
- ίδιο exponent `e`
- γνωστή σχέση μεταξύ plaintexts

Στην πράξη αυτό λύνεται συχνά με Sage, δημιουργώντας πολυώνυμα modulo `n` και υπολογίζοντας ένα GCD.

## Πλέγματα / Coppersmith

Χρησιμοποιήστε το όταν έχετε μερικά μπιτ, δομημένο plaintext, ή στενές σχέσεις που κάνουν το άγνωστο μικρό.

Οι μέθοδοι πλεγμάτων (LLL/Coppersmith) εμφανίζονται όποτε έχετε μερικές πληροφορίες:

- Μερικώς γνωστό plaintext (δομημένο μήνυμα με άγνωστο τελείωμα)
- Μερικώς γνωστό `p`/`q` (high bits leaked)
- Μικρές άγνωστες διαφορές μεταξύ σχετικών τιμών

### Τι να αναγνωρίζετε

Τυπικά σημάδια σε challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Εργαλεία

Στην πράξη θα χρησιμοποιήσετε το Sage για LLL και ένα γνωστό template για τη συγκεκριμένη περίπτωση.

Καλά σημεία εκκίνησης:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

{{#include ../../../banners/hacktricks-training.md}}
