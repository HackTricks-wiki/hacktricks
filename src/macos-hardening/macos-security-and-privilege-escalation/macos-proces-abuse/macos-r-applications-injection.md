# Έγχυση εφαρμογών R στο macOS

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Κατά την εκκίνηση, το R φορτώνει αρχεία site και user profile που περιέχουν κώδικα R. Το `R_PROFILE` επιλέγει το site profile και το `R_PROFILE_USER` επιλέγει το user profile, επιτρέποντας σε ένα κληρονομημένο environment να ανακατευθύνει οποιαδήποτε από τις δύο αναζητήσεις σε ένα αρχείο αναγνώσιμο από τον attacker.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` παρακάμπτει το προφίλ χρήστη, το `--no-site-file` παρακάμπτει το προφίλ site και το `--vanilla` περιλαμβάνει και τις δύο προστασίες. Το R επεξεργάζεται πρώτα τα αρχεία περιβάλλοντος που επιλέγονται από τα `R_ENVIRON` και `R_ENVIRON_USER`, όμως αυτά τα αρχεία ορίζουν μόνο μεταβλητές· οι μεταβλητές του προφίλ αποτελούν το άμεσο primitive για arbitrary-code execution.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` και library paths

Το R συνδέει κατά την εκκίνηση τα packages που διαχωρίζονται με κόμματα στη μεταβλητή `R_DEFAULT_PACKAGES`. Το `Rscript` δίνει προτεραιότητα στο `R_SCRIPT_DEFAULT_PACKAGES`. Ο συνδυασμός οποιασδήποτε από τις δύο μεταβλητές με τις `R_LIBS`, `R_LIBS_USER` ή `R_LIBS_SITE` μπορεί να κάνει το R να εντοπίσει και να φορτώσει ένα εγκατεστημένο package που ελέγχεται από attacker· το hook `.onLoad` ή `.onAttach` εκτελείται αυτόματα.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Αυτό απαιτεί ένα δομικά έγκυρο εγκατεστημένο πακέτο R, όχι απλώς ένα μεμονωμένο αρχείο `.R`. Το `--vanilla` δεν διαγράφει τις άμεσα κληρονομημένες μεταβλητές, επομένως ένα αξιόπιστο wrapper πρέπει επίσης να καταργεί ή να αντικαθιστά τις μεταβλητές του προεπιλεγμένου πακέτου και της διαδρομής βιβλιοθηκών, καθώς και να απενεργοποιεί τα αρχεία profile.

## References

- [1] [Εκκίνηση κατά την έναρξη μιας συνεδρίας R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [Εγκατάσταση και διαχείριση R: Πρόσθετα πακέτα](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
