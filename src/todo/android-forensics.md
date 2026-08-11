# Forensics Android

{{#include ../banners/hacktricks-training.md}}

## Κλειδωμένη συσκευή

Προτιμήστε μεθόδους απόκτησης που διατηρούν την κατάσταση της συσκευής και καταγράψτε κάθε ενέργεια. Εάν η συσκευή είναι κλειδωμένη, οι διαθέσιμες επιλογές εξαρτώνται από το μοντέλο, την έκδοση Android, το επίπεδο ενημερώσεων και το αν η πρόσβαση είχε ρυθμιστεί πριν από την κατάσχεση. Το NIST συνιστά την επιλογή μεθόδου ανάλογα με τη συσκευή και την αρμοδιότητα για την εξέταση.<sup>[[1]](#references)</sup>

- Ελέγξτε αν το USB debugging ήταν ενεργοποιημένο και αν ο σταθμός εργασίας απόκτησης έχει ήδη εξουσιοδοτηθεί. Η πρόσβαση μέσω ADB απαιτεί κανονικά από τον χρήστη να ξεκλειδώσει τη συσκευή και να επιβεβαιώσει το RSA key του σταθμού εργασίας.<sup>[[3]](#references)</sup>
- Εξετάστε αν η βιομετρική πρόσβαση παραμένει διαθέσιμη σύμφωνα με τους ισχύοντες νομικούς και διαδικαστικούς κανόνες.
- Ένα **smudge attack** μπορεί να αποκαλύψει ένα graphical unlock pattern από υπολείμματα στην οθόνη, αν και τα μεταγενέστερα αγγίγματα και ο καθαρισμός μειώνουν την αξιοπιστία του.<sup>[[2]](#references)</sup>
- Χρησιμοποιείτε commercial ή research lock-bypass tooling μόνο όταν υποστηρίζει ρητά την ακριβή συσκευή και το software build.

## Απόκτηση δεδομένων

Σε παλαιότερες συσκευές, ένα παλαιού τύπου [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) μπορεί να δημιουργήσει ένα αρχείο `.backup`, το οποίο το Android Backup Extractor μπορεί να αποσυσκευάσει:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Μην υποθέτετε ότι αυτό καλύπτει κάθε εφαρμογή. Το ADB χαρακτηρίζει την εντολή ως deprecated, ενώ το Android 12 εξαιρεί τα δεδομένα εφαρμογών που στοχεύουν στο API level 31 ή νεότερο, εκτός αν η εφαρμογή είναι debuggable.<sup>[[4]](#references)</sup>

### Root ή physical debug access

Με root access σε live device, πρώτα καταγράψτε τα partitions και τα mounts· οι παρακάτω εντολές δεν εφαρμόζονται απευθείας σε physical JTAG acquisition. Το σωστό block device εξαρτάται από το hardware, επομένως μην υποθέτετε ότι είναι πάντα `mmcblk0`. Δημιουργήστε image μόνο από την επαληθευμένη πηγή σε ξεχωριστό storage:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Κάνε Hash στο αποτέλεσμα και κατέγραψε την ακριβή εντολή, τα αναγνωριστικά της συσκευής, την ώρα και τυχόν αλλαγές που έγιναν κατά την απόκτηση.<sup>[[1]](#references)</sup>

### Μνήμη

Το LiME μπορεί να αποκτήσει τη φυσική μνήμη από Linux και ορισμένες συσκευές Android, αλλά το kernel module του πρέπει να έχει γίνει build για το kernel-στόχο και να φορτωθεί με επαρκή δικαιώματα. Η υπογραφή module, το kernel lockdown και τα σύγχρονα μέτρα hardening του Android ενδέχεται να εμποδίσουν τη φόρτωσή του.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Οδηγίες για Mobile Device Forensics](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge Attacks σε οθόνες αφής smartphone](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Περιορισμός ADB backup του Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
