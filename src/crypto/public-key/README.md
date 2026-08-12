# Κρυπτογραφία Δημόσιου Κλειδιού

{{#include ../../banners/hacktricks-training.md}}

Πολλές προηγμένες προκλήσεις κρυπτογραφίας σε CTF περιλαμβάνουν RSA, κρυπτογραφία ελλειπτικών καμπυλών (ECC), ECDSA, lattices ή weak randomness.

## Συνιστώμενα εργαλεία

- [SageMath](https://www.sagemath.org/) για modular arithmetic, elliptic curves και lattice reduction<sup>[[1]](#references)</sup>
- [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool) για τον έλεγχο συνηθισμένων αδυναμιών του RSA<sup>[[2]](#references)</sup>
- [FactorDB](https://factordb.com/) για τον έλεγχο του αν ένας ακέραιος έχει γνωστούς παράγοντες<sup>[[3]](#references)</sup>
- Η Python [`ecdsa` library](https://ecdsa.readthedocs.io/) για key parsing, signing και verification<sup>[[7]](#references)</sup>

## RSA

Ξεκινήστε από εδώ όταν μια πρόκληση παρέχει τα `n`, `e` και `c`, μαζί με ένα hint όπως shared modulus, low exponent, partial key bits ή related messages.

{{#ref}}
rsa/README.md
{{#endref}}

## ECC / ECDSA

Αν εμπλέκονται υπογραφές, ελέγξτε για nonce reuse, bias ή leak πριν υποθέσετε ότι πρέπει να λυθεί το underlying discrete-logarithm problem.

### ECDSA nonce reuse / bias

Το ECDSA απαιτεί έναν νέο secret αριθμό `k` για κάθε μήνυμα. Αν το ίδιο `k` υπογράψει δύο διαφορετικά message hashes, το private key μπορεί να ανακτηθεί από τις public signature values.<sup>[[4]](#references)</sup>

Ακόμη και όταν το `k` δεν είναι ίδιο, bias ή leak των nonce bits σε πολλές υπογραφές μπορεί να επιτρέψει lattice-based recovery.<sup>[[5]](#references)</sup>

Τεχνική ανάκτηση όταν το `k` επαναχρησιμοποιείται:<sup>[[4]](#references)</sup>

Εξισώσεις υπογραφής ECDSA (group order `n`):

- `r = (kG)_x mod n`
- `s = k^{-1}(h(m) + r*d) mod n`

Αν το ίδιο `k` επαναχρησιμοποιηθεί για δύο messages `m1, m2`, παράγοντας signatures `(r, s1)` και `(r, s2)`:

- `k = (h(m1) - h(m2)) * (s1 - s2)^{-1} mod n`
- `d = (s1*k - h(m1)) * r^{-1} mod n`

### Invalid-curve attacks

Αν ένα protocol δεν επικυρώνει ότι ένα input point ανήκει στην αναμενόμενη curve και στο σωστό subgroup, ένας attacker μπορεί να εξαναγκάσει operations σε weaker group και να ανακτήσει πληροφορίες για ένα secret scalar. Το SEC 1 καθορίζει public-key validation checks που αποσκοπούν στην αποτροπή τέτοιων inputs.<sup>[[6]](#references)</sup>

Τεχνική σημείωση:

- Επικυρώστε ότι τα points δεν είναι το point at infinity, έχουν valid coordinates, ικανοποιούν την curve equation και ανήκουν στο απαιτούμενο subgroup.<sup>[[6]](#references)</sup>
- Σε CTF challenges, αυτό συχνά μοντελοποιείται ως ένας server που πολλαπλασιάζει ένα point επιλεγμένο από τον attacker με ένα secret scalar και επιστρέφει μια derived value.

## References

- [1] [SageMath](https://www.sagemath.org/)
- [2] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [3] [FactorDB](https://factordb.com/)
- [4] [NIST FIPS 186-5: Πρότυπο Ψηφιακής Υπογραφής](https://csrc.nist.gov/pubs/fips/186-5/final)
- [5] [Breitner and Heninger: Biased Nonce Sense — Lattice Attacks against Weak ECDSA Signatures](https://eprint.iacr.org/2019/023)
- [6] [SEC 1 v2.0: Κρυπτογραφία Ελλειπτικών Καμπυλών](https://www.secg.org/sec1-v2.pdf)
- [7] [Τεκμηρίωση της Python `ecdsa`](https://ecdsa.readthedocs.io/)
{{#include ../../banners/hacktricks-training.md}}
