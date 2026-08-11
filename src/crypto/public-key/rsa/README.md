# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Συλλέξτε:

- `n`, `e`, `c` (και τυχόν πρόσθετα ciphertexts)
- Τυχόν σχέσεις μεταξύ των μηνυμάτων (ίδιο plaintext; shared modulus; structured plaintext;)
- Τυχόν leaks (μερικά τμήματα των `p/q`, bits του `d`, `dp/dq`, γνωστό padding)

Στη συνέχεια δοκιμάστε:

- Έλεγχο παραγοντοποίησης (Factordb / `sage: factor(n)` για σχετικά μικρούς αριθμούς)
- Patterns χαμηλού exponent (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL) όταν κάτι είναι σχεδόν γνωστό

## Common RSA attacks

### Common modulus

Αν δύο ciphertexts `c1, c2` κρυπτογραφούν το **ίδιο μήνυμα** υπό το **ίδιο modulus** `n`, αλλά με διαφορετικούς exponents `e1, e2` (και `gcd(e1,e2)=1`), μπορείτε να ανακτήσετε το `m` χρησιμοποιώντας τον extended Euclidean algorithm:

`m = c1^a * c2^b mod n` όπου `a*e1 + b*e2 = 1`.

Περίγραμμα παραδείγματος:

1. Υπολογίστε `(a, b) = xgcd(e1, e2)` ώστε `a*e1 + b*e2 = 1`
2. Αν `a < 0`, ερμηνεύστε το `c1^a` ως `inv(c1)^{-a} mod n` (το ίδιο και για το `b`)
3. Πολλαπλασιάστε και κάντε reduce modulo `n`

### Shared primes across moduli

Αν έχετε πολλά RSA moduli από το ίδιο challenge, ελέγξτε αν μοιράζονται έναν prime:

- `gcd(n1, n2) != 1` υποδηλώνει καταστροφική αποτυχία στη δημιουργία του key.

Αυτό εμφανίζεται συχνά σε CTFs ως "we generated many keys quickly" ή "bad randomness".

### Sparse / short-sleeve moduli

Ορισμένοι προβληματικοί big-integer generators διαρρέουν απευθείας structure στο public modulus: κάθε limb περιέχει μόνο ένα μικρό random subfield και τα υπόλοιπα bits είναι `0`. Στην πράξη αυτό εμφανίζεται ως **regularly spaced zero blocks** σε όλο το `n`, συχνά ευθυγραμμισμένα σε limbs των 32-bit ή 128-bit.<sup>[[1]](#references)</sup>

Γρήγοροι έλεγχοι:

- Κάντε dump το `n` σε hex και αναζητήστε επαναλαμβανόμενα zero windows με σταθερό stride.
- Κάντε re-slice το `n` ως limbs (`2^32`, `2^64`, `2^128`) και ελέγξτε αν κάθε limb είναι ασυνήθιστα μικρό.
- Ελέγξτε public SSH/TLS keys με tooling όπως το **badkeys** όταν υποψιάζεστε weak host-key generation.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Αυτό είναι σοβαρότερο από ένα statistical bias: αν και οι δύο private factors `p` και `q` είναι short-sleeved, το modulus μπορεί να γίνει **εύκολο να παραγοντοποιηθεί**.<sup>[[1]](#references)</sup>

### Polynomial factorization of structured RSA keys

Για ένα ύποπτο limb width `w`, γράψτε το modulus σε base `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Επειδή η evaluation είναι multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Αν οι factors έχουν επίσης sparse limb coefficients, τότε:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Περίγραμμα επίθεσης:

1. Μαντέψτε το limb width `w`.
2. Μετατρέψτε το public modulus `n` σε `f_n(x)` χρησιμοποιώντας base `2^w`.
3. Κάντε factor το `f_n(x)` πάνω από τους ακεραίους.
4. Κάντε evaluate τους candidate factors ξανά στο `B = 2^w`.
5. Επαληθεύστε ποιοι candidates πολλαπλασιάζονται ώστε να δώσουν `n`.

Αυτό **δεν σπάει το normal RSA**. Λειτουργεί μόνο όταν οι prime factors έχουν οι ίδιοι πολύ μικρούς, highly structured limb coefficients.<sup>[[1]](#references)</sup>

### Shifted limb leakage

Τα sparse bytes δεν είναι πάντα ευθυγραμμισμένα στο low end κάθε limb. Αν η άμεση μετατροπή σε base-`2^w` παράγει μεγάλους coefficients, αναζητήστε shifts `i,j` ώστε τα `2^i p` και `2^j q` να γίνουν sparse σε αυτή τη limb basis. Το product polynomial μπορεί και πάλι να εξαχθεί από το public modulus, να γίνει factor και να recombine στους αρχικούς integer factors.<sup>[[1]](#references)</sup>

### Implementation smell: byte-to-limb RNG bug

Ένα επικίνδυνο pattern είναι ο υπολογισμός του αριθμού των **32-bit limbs**, η δέσμευση μόνο τόσων **bytes** και η αντιγραφή τους στον limb array:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Αυτό δίνει σε κάθε limb των 32 bit μόνο **8 bits εντροπίας**, καθώς και ένα υποχρεωτικό top bit στο τελευταίο limb. Τα παραγόμενα RSA primes μπορούν συχνά να αναγνωριστούν και να παραγοντοποιηθούν μόνο από το public key.<sup>[[1]](#references)</sup>

### Related DSA failure mode

Αν η ίδια προβληματική big-integer routine επαναχρησιμοποιηθεί για τη generation του DSA private exponent, το public key `y = g^x` μπορεί να διαρρεύσει ένα **δραματικά μειωμένο και δομημένο** search space για το `x`. Μόλις γίνει γνωστό το limb pattern, επιθέσεις discrete-log, όπως το **baby-step giant-step**, μπορεί να γίνουν πρακτικές ενάντια στις public parameters.<sup>[[1]](#references)</sup>

### Håstad broadcast / low exponent

Αν το ίδιο plaintext σταλεί σε πολλούς recipients με μικρό `e` (συχνά `e=3`) και χωρίς proper padding, μπορείτε να ανακτήσετε το `m` μέσω CRT και integer root.

Technical condition:

Αν έχετε `e` ciphertexts του ίδιου message κάτω από pairwise-coprime moduli `n_i`:

- Χρησιμοποιήστε CRT για να ανακτήσετε το `M = m^e` πάνω από το γινόμενο `N = Π n_i`
- Αν `m^e < N`, τότε το `M` είναι η πραγματική integer power και `m = integer_root(M, e)`

### Wiener attack: small private exponent

Αν το `d` είναι υπερβολικά μικρό, τα continued fractions μπορούν να το ανακτήσουν από το `e/n`.

### Textbook RSA pitfalls

Αν δείτε:

- Χωρίς OAEP/PSS, raw modular exponentiation
- Deterministic encryption

τότε οι algebraic attacks και η κατάχρηση oracle γίνονται πολύ πιο πιθανές.

### Εργαλεία

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Αν δείτε δύο ciphertexts κάτω από το ίδιο modulus με messages που συνδέονται αλγεβρικά (π.χ. `m2 = a*m1 + b`), αναζητήστε attacks τύπου "related-message", όπως το Franklin–Reiter. Αυτές συνήθως απαιτούν:

- ίδιο modulus `n`
- ίδιο exponent `e`
- γνωστή σχέση μεταξύ των plaintexts

Στην πράξη αυτό συχνά επιλύεται με Sage, με τη δημιουργία polynomials modulo `n` και τον υπολογισμό ενός GCD.

## Lattices / Coppersmith

Χρησιμοποιήστε το όταν έχετε partial bits, structured plaintext ή close relations που κάνουν το unknown μικρό.

Οι lattice methods (LLL/Coppersmith) εμφανίζονται κάθε φορά που έχετε partial information:

- Partially known plaintext (structured message με άγνωστο tail)
- Partially known `p`/`q` (high bits leaked)
- Small unknown differences μεταξύ related values

### Τι να αναγνωρίζετε

Τυπικές ενδείξεις σε challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

Στην πράξη θα χρησιμοποιήσετε Sage για LLL και ένα γνωστό template για το συγκεκριμένο instance.

Καλά σημεία εκκίνησης:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [1] [Trail of Bits - Παραγοντοποίηση "short-sleeve" RSA keys με polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [2] [badkeys](https://badkeys.info/)
- [3] [badkeys αυτόνομο εργαλείο](https://github.com/badkeys/badkeys)
{{#include ../../../banners/hacktricks-training.md}}
