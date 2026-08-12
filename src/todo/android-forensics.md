# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Κλειδωμένη συσκευή

Προτιμήστε μεθόδους acquisition που διατηρούν την κατάσταση της συσκευής και τεκμηριώστε κάθε ενέργεια. Εάν η συσκευή είναι κλειδωμένη, οι διαθέσιμες επιλογές εξαρτώνται από το μοντέλο, την έκδοση του Android, το επίπεδο patch και το εάν η πρόσβαση είχε ρυθμιστεί πριν από την κατάσχεση. Το NIST συνιστά την επιλογή μεθόδου σύμφωνα με τη συσκευή και την αρμοδιότητα για την εξέταση.<sup>[[1]](#references)</sup>

- Ελέγξτε εάν το USB debugging ήταν ενεργοποιημένο και εάν το workstation acquisition είναι ήδη εξουσιοδοτημένο. Η πρόσβαση μέσω ADB απαιτεί συνήθως από τον χρήστη να ξεκλειδώσει τη συσκευή και να επιβεβαιώσει το RSA key του workstation.<sup>[[3]](#references)</sup>
- Εξετάστε εάν η πρόσβαση μέσω biometric παραμένει διαθέσιμη σύμφωνα με τους ισχύοντες νομικούς και διαδικαστικούς κανόνες.
- Ένα **smudge attack** μπορεί να αποκαλύψει ένα graphical unlock pattern από τα υπολείμματα στην οθόνη, αν και τα μεταγενέστερα αγγίγματα και ο καθαρισμός μειώνουν την αξιοπιστία του.<sup>[[2]](#references)</sup>
- Όπου το εξουσιοδοτημένο tooling υποστηρίζει την ακριβή συσκευή και το software build, μπορεί να επιχειρήσει ανάκτηση ή brute force PIN, password ή pattern. Η hardware-backed επαλήθευση credentials, οι καθυστερήσεις μεταξύ προσπαθειών και οι πολιτικές wipe καθιστούν αυτό ιδιαίτερα εξαρτώμενο από τη συσκευή, επομένως μην αντικαθιστάτε μια τεχνική ή ένα αποτέλεσμα για iPhone με στοιχεία που αποδεικνύουν ότι υποστηρίζεται μια Android συσκευή.<sup>[[1]](#references)</sup>

## Απόκτηση δεδομένων

Σε παλαιότερες συσκευές, ένα legacy [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) μπορεί να δημιουργήσει ένα αρχείο `.backup` το οποίο το Android Backup Extractor μπορεί να αποσυσκευάσει:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Μην θεωρείτε ότι αυτό καλύπτει κάθε εφαρμογή. Το ADB επισημαίνει την εντολή ως deprecated, ενώ το Android 12 εξαιρεί δεδομένα από εφαρμογές που στοχεύουν το API level 31 ή νεότερο, εκτός αν η εφαρμογή είναι debuggable.<sup>[[4]](#references)</sup>

### Πρόσβαση root ή physical debug

Με πρόσβαση root σε μια ενεργή συσκευή, καταγράψτε πρώτα τα partitions και τα mounts· οι παρακάτω εντολές δεν εφαρμόζονται απευθείας σε physical JTAG acquisition. Το σωστό block device εξαρτάται από το hardware, επομένως μην θεωρείτε ότι είναι πάντα `mmcblk0`. Δημιουργήστε image μόνο από την επαληθευμένη πηγή και αποθηκεύστε το σε ξεχωριστό μέσο:<sup>[[1]](#references)</sup>

Μια JTAG acquisition χρησιμοποιεί αντίθετα το hardware test-access interface της συσκευής και συμβατό acquisition equipment για την ανάγνωση της προσβάσιμης μνήμης. Το pinout, η υποστήριξη του chipset, η κατάσταση της συσκευής και η διάκριση μεταξύ volatile και non-volatile targets διαφέρουν ανά συσκευή· καταγράψτε τη διαδρομή hardware και χρησιμοποιήστε μια επικυρωμένη διαδικασία για το συγκεκριμένο μοντέλο.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Για παράδειγμα, εάν το inventory των partitions επιβεβαιώνει ότι το `/dev/block/mmcblk0` είναι ολόκληρη η συσκευή flash και ο προορισμός διαθέτει επαρκή χώρο, η αρχική εντολή απόκτησης γίνεται:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Εδώ, το `df /data` βοηθά στη συσχέτιση του `/data` με το mounted filesystem του· δεν θα πρέπει να θεωρείται απόδειξη ότι το `mmcblk0` είναι το σωστό whole-device source ή ότι το `4096` είναι το μοναδικό έγκυρο `dd` block size.

Υπολογίστε το hash του αποτελέσματος και καταγράψτε την ακριβή εντολή, τα αναγνωριστικά της συσκευής, την ώρα και τυχόν αλλαγές που έγιναν κατά την acquisition.<sup>[[1]](#references)</sup>

### Μνήμη

Το LiME μπορεί να αποκτήσει physical memory από Linux και ορισμένες Android συσκευές, αλλά το kernel module του πρέπει να έχει γίνει build για το kernel-στόχο και να φορτωθεί με επαρκή privileges. Το module signing, το kernel lockdown και τα σύγχρονα Android hardening μέτρα ενδέχεται να εμποδίσουν τη φόρτωσή του.<sup>[[5]](#references)</sup>

Το Android workflow του project προωθεί το matching module με ADB, κάνει forward μια TCP port, φορτώνει το module από root shell και καταγράφει το stream στο examination host:<sup>[[5]](#references)</sup>
```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```
Το LiME μπορεί εναλλακτικά να γράψει στον αποθηκευτικό χώρο της συσκευής με `path=/sdcard/ram.lime`, αλλά αυτό τροποποιεί τον αποθηκευτικό χώρο της συσκευής και απαιτεί επαρκή ελεύθερο χώρο. Καταγράψτε αυτή την παρενέργεια και υπολογίστε το hash της εικόνας που αποκτήθηκε.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Οδηγίες για Mobile Device Forensics](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Επιθέσεις Smudge σε οθόνες αφής smartphone](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Περιορισμός αντιγράφων ασφαλείας ADB στο Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
