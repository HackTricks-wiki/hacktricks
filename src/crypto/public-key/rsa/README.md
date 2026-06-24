# RSA Attacks

{{#include ../../../banners/hacktricks-training.md}}

## Fast triage

Συλλέξτε:

- `n`, `e`, `c` (και οποιαδήποτε επιπλέον ciphertexts)
- Οποιεσδήποτε σχέσεις μεταξύ μηνυμάτων (same plaintext? shared modulus? structured plaintext?)
- Οποιεσδήποτε leaks (partial `p/q`, bits of `d`, `dp/dq`, known padding)

Έπειτα δοκιμάστε:

- Έλεγχο factorization (Factordb / `sage: factor(n)` για small-ish)
- Low exponent patterns (`e=3`, broadcast)
- Common modulus / repeated primes
- Lattice methods (Coppersmith/LLL) όταν κάτι είναι σχεδόν γνωστό

## Common RSA attacks

### Common modulus

Αν δύο ciphertexts `c1, c2` κρυπτογραφούν το **ίδιο μήνυμα** κάτω από το **ίδιο modulus** `n` αλλά με διαφορετικούς exponents `e1, e2` (και `gcd(e1,e2)=1`), μπορείτε να ανακτήσετε το `m` χρησιμοποιώντας τον extended Euclidean algorithm:

`m = c1^a * c2^b mod n` όπου `a*e1 + b*e2 = 1`.

Παράδειγμα outline:

1. Υπολογίστε `(a, b) = xgcd(e1, e2)` ώστε `a*e1 + b*e2 = 1`
2. Αν `a < 0`, ερμηνεύστε το `c1^a` ως `inv(c1)^{-a} mod n` (το ίδιο για το `b`)
3. Πολλαπλασιάστε και μειώστε modulo `n`

### Shared primes across moduli

Αν έχετε πολλαπλά RSA moduli από το ίδιο challenge, ελέγξτε αν μοιράζονται έναν prime:

- `gcd(n1, n2) != 1` υποδηλώνει καταστροφικό key-generation failure.

Αυτό εμφανίζεται συχνά σε CTFs ως "we generated many keys quickly" ή "bad randomness".

### Sparse / short-sleeve moduli

Κάποιοι broken big-integer generators διαρρέουν δομή απευθείας στο public modulus: κάθε limb περιέχει μόνο ένα μικρό random subfield και τα υπόλοιπα bits είναι `0`. Στην πράξη αυτό εμφανίζεται ως **regularly spaced zero blocks** σε όλο το `n`, συχνά ευθυγραμμισμένα σε 32-bit ή 128-bit limbs.

Γρήγοροι έλεγχοι:

- Κάντε dump το `n` σε hex και αναζητήστε επαναλαμβανόμενα zero windows σε σταθερό stride.
- Κόψτε ξανά το `n` ως limbs (`2^32`, `2^64`, `2^128`) και ελέγξτε αν κάθε limb είναι ασυνήθιστα μικρό.
- Ελέγξτε δημόσια SSH/TLS keys με tooling όπως το **badkeys** όταν υποψιάζεστε weak host-key generation.

Αυτό είναι πιο σοβαρό από ένα statistical bias: αν και οι δύο private factors `p` και `q` είναι short-sleeved, το modulus μπορεί να γίνει **easy to factor**.

### Polynomial factorization of structured RSA keys

Για ένα ύποπτο limb width `w`, γράψτε το modulus στη βάση `B = 2^w`:

- `n = Σ_i n_i B^i`
- `f_n(x) = Σ_i n_i x^i`

Επειδή η αξιολόγηση είναι multiplicative, `f_a(B) * f_c(B) = (f_a * f_c)(B)`. Αν οι factors έχουν επίσης sparse limb coefficients, τότε:

- `n = p*q`
- `f_n(x) = f_p(x) * f_q(x)`

Attack outline:

1. Μαντέψτε το limb width `w`.
2. Μετατρέψτε το public modulus `n` σε `f_n(x)` χρησιμοποιώντας βάση `2^w`.
3. Factor το `f_n(x)` πάνω από τους integers.
4. Αξιολογήστε τα υποψήφια factors ξανά στο `B = 2^w`.
5. Επαληθεύστε ποια υποψήφια πολλαπλασιάζονται ώστε να δώσουν `n`.

Αυτό **δεν σπάει το normal RSA**. Λειτουργεί μόνο όταν οι prime factors οι ίδιοι έχουν πολύ μικρούς, έντονα structured limb coefficients.

### Shifted limb leakage

Τα sparse bytes δεν είναι πάντα ευθυγραμμισμένα στο χαμηλό άκρο κάθε limb. Αν η απευθείας μετατροπή σε βάση `2^w` παράγει μεγάλους coefficients, αναζητήστε shifts `i,j` ώστε τα `2^i p` και `2^j q` να γίνουν sparse σε αυτή τη βάση limb. Το product polynomial μπορεί ακόμη να εξαχθεί από το public modulus, να γίνει factorization και να συνδυαστεί ξανά στα αρχικά integer factors.

### Implementation smell: byte-to-limb RNG bug

Ένα επικίνδυνο pattern είναι να υπολογίζετε τον αριθμό των **32-bit limbs**, να δεσμεύετε μόνο τόσα **bytes**, και να τα αντιγράφετε στο limb array:
```csharp
int numLimbs = bits / 32;
byte[] array = new byte[numLimbs];
rngProvider.GetNonZeroBytes(array);
Array.Copy(array, 0, bignumLimbs, 0, numLimbs);
bignumLimbs[numLimbs - 1] |= 0x80000000;
```
Αυτό δίνει σε κάθε 32-bit limb μόνο **8 bits entropy** plus ένα forced top bit στο τελευταίο limb. Τα resulting RSA primes μπορούν συχνά να αναγνωριστούν και να factored από το public key alone.

### Related DSA failure mode

Αν η ίδια broken big-integer routine επαναχρησιμοποιείται για DSA private exponent generation, το public key `y = g^x` μπορεί να leak ένα **drastically reduced and structured** search space για το `x`. Μόλις γίνει γνωστό το limb pattern, discrete-log attacks όπως **baby-step giant-step** μπορούν να γίνουν practical against the public parameters.

### Håstad broadcast / low exponent

Αν το ίδιο plaintext σταλεί σε πολλούς recipients με small `e` (συχνά `e=3`) και χωρίς proper padding, μπορείς να recover το `m` via CRT and integer root.

Technical condition:

Αν έχεις `e` ciphertexts του ίδιου message under pairwise-coprime moduli `n_i`:

- Use CRT to recover `M = m^e` over the product `N = Π n_i`
- If `m^e < N`, τότε `M` είναι η true integer power, και `m = integer_root(M, e)`

### Wiener attack: small private exponent

Αν το `d` είναι too small, continued fractions can recover it from `e/n`.

### Textbook RSA pitfalls

Αν δεις:

- No OAEP/PSS, raw modular exponentiation
- Deterministic encryption

τότε algebraic attacks και oracle abuse γίνονται πολύ πιο likely.

### Tools

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- SageMath (CRT, roots, CF): https://www.sagemath.org/

## Related-message patterns

Αν δεις δύο ciphertexts under the same modulus με messages που είναι algebraically related (π.χ. `m2 = a*m1 + b`), ψάξε για "related-message" attacks όπως Franklin–Reiter. Αυτά συνήθως απαιτούν:

- same modulus `n`
- same exponent `e`
- known relationship between plaintexts

Στην πράξη αυτό συχνά λύνεται με Sage by setting up polynomials modulo `n` και computing a GCD.

## Lattices / Coppersmith

Χρησιμοποίησέ το όταν έχεις partial bits, structured plaintext, ή close relations που κάνουν το unknown small.

Lattice methods (LLL/Coppersmith) εμφανίζονται whenever you have partial information:

- Partially known plaintext (structured message with unknown tail)
- Partially known `p`/`q` (high bits leaked)
- Small unknown differences between related values

### What to recognize

Typical hints in challenges:

- "We leaked the top/bottom bits of p"
- "The flag is embedded like: `m = bytes_to_long(b\"HTB{\" + unknown + b\"}\")`"
- "We used RSA but with a small random padding"

### Tooling

Στην πράξη θα χρησιμοποιήσεις Sage for LLL και a known template για το specific instance.

Good starting points:

- Sage CTF crypto templates: https://github.com/defund/coppersmith
- A survey-style reference: https://martinralbrecht.wordpress.com/2013/05/06/coppersmiths-method/

## References

- [Trail of Bits - Factoring "short-sleeve" RSA keys with polynomials](https://blog.trailofbits.com/2026/06/12/factoring-short-sleeve-rsa-keys-with-polynomials/)
- [badkeys](https://badkeys.info/)
- [badkeys standalone tool](https://github.com/badkeys/badkeys)

{{#include ../../../banners/hacktricks-training.md}}
