# Κρυπτογραφία Δημόσιου Κλειδιού

{{#include ../../banners/hacktricks-training.md}}

Τα περισσότερα δύσκολα CTF crypto καταλήγουν εδώ: RSA, ECC/ECDSA, lattices, και κακή τυχαιότητα.

## Προτεινόμενα εργαλεία

- SageMath (LLL/lattices, modular arithmetic): https://www.sagemath.org/
- RsaCtfTool (πολυεργαλείο): https://github.com/Ganapati/RsaCtfTool
- factordb (γρήγοροι έλεγχοι παραγοντοποίησης): http://factordb.com/

## RSA

Ξεκινήστε εδώ όταν έχετε `n,e,c` και κάποια επιπλέον υπόδειξη (shared modulus, low exponent, partial bits, related messages).

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Εάν υπάρχουν υπογραφές, ελέγξτε πρώτα προβλήματα με nonce (reuse/bias/leaks) πριν υποθέσετε ότι πρόκειται για δύσκολα μαθηματικά.

### ECDSA nonce reuse / bias

Αν δύο υπογραφές επαναχρησιμοποιήσουν το ίδιο nonce `k`, το ιδιωτικό κλειδί μπορεί να ανακτηθεί.

Ακόμα κι αν το `k` δεν είναι ίδιο, **bias/leakage** των bit του nonce μεταξύ υπογραφών μπορεί να είναι αρκετό για ανάκτηση με χρήση lattices (συνηθισμένο θέμα σε CTF).

Τεχνική ανάκτησης όταν το `k` επαναχρησιμοποιείται:

ECDSA signature equations (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Αν το ίδιο `k` επαναχρησιμοποιηθεί για δύο μηνύματα `m1, m2` που παράγουν υπογραφές `(r, s1)` και `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Αν ένα πρωτόκολλο δεν επαληθεύει ότι τα σημεία βρίσκονται στην αναμενόμενη καμπύλη (ή στην σωστή υπο-ομάδα), ένας επιτιθέμενος μπορεί να αναγκάσει λειτουργίες σε μια αδύναμη ομάδα και να ανακτήσει μυστικά.

Τεχνική σημείωση:

- Επαληθεύστε ότι τα σημεία βρίσκονται πάνω στην καμπύλη και στην σωστή υπο-ομάδα.
- Πολλές εργασίες CTF το μοντελοποιούν ως "server multiplies attacker-chosen point by secret scalar and returns something."

### Tooling

- SageMath για αριθμητική καμπύλης / lattices
- `ecdsa` Python library για ανάλυση/επικύρωση

{{#include ../../banners/hacktricks-training.md}}
