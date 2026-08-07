# Κρυπτογραφία Δημόσιου Κλειδιού

{{#include ../../banners/hacktricks-training.md}}


Οι περισσότερες δύσκολες ασκήσεις crypto σε CTF καταλήγουν εδώ: RSA, ECC/ECDSA, lattices και κακή τυχαιότητα.

## Προτεινόμενα εργαλεία

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (Swiss-army knife): https://github.com/Ganapati/RsaCtfTool
- factordb (γρήγοροι έλεγχοι παραγοντοποίησης): http://factordb.com/

## RSA

Ξεκινήστε εδώ όταν έχετε `n,e,c` και κάποιο επιπλέον hint (shared modulus, low exponent, partial bits, related messages).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Αν εμπλέκονται signatures, ελέγξτε πρώτα για nonce problems (reuse/bias/leaks), πριν θεωρήσετε ότι απαιτούνται δύσκολα μαθηματικά.

### ECDSA nonce reuse / bias

Αν δύο signatures χρησιμοποιούν ξανά το ίδιο nonce `k`, το private key μπορεί να ανακτηθεί.

Ακόμη κι αν το `k` δεν είναι πανομοιότυπο, το **bias/leakage** των bits του nonce μεταξύ signatures μπορεί να είναι αρκετό για lattice recovery (συνηθισμένο θέμα σε CTF).

Τεχνική ανάκτηση όταν το `k` χρησιμοποιείται ξανά:

Εξισώσεις signature του ECDSA (τάξη ομάδας `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Αν το ίδιο `k` χρησιμοποιείται για δύο messages `m1, m2`, παράγοντας signatures `(r, s1)` και `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Αν ένα protocol δεν επαληθεύει ότι τα points ανήκουν στην αναμενόμενη curve (ή subgroup), ένας attacker μπορεί να εξαναγκάσει operations σε μια weak group και να ανακτήσει secrets.

Τεχνική σημείωση:

- Validate ότι τα points ανήκουν στην curve και στο σωστό subgroup.
- Πολλά CTF tasks το μοντελοποιούν ως εξής: ο "server multiplies attacker-chosen point by secret scalar and returns something."

### Tooling

- SageMath για curve arithmetic / lattices
- `ecdsa` Python library για parsing/verification

{{#include ../../banners/hacktricks-training.md}}
