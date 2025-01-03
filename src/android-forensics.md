# Android Forensics

{{#include ./banners/hacktricks-training.md}}

## Κλειδωμένη Σ συσκευή

Για να ξεκινήσετε την εξαγωγή δεδομένων από μια συσκευή Android, πρέπει να είναι ξεκλειδωμένη. Αν είναι κλειδωμένη, μπορείτε να:

- Ελέγξετε αν η συσκευή έχει ενεργοποιημένη την αποσφαλμάτωση μέσω USB.
- Ελέγξετε για μια πιθανή [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- Δοκιμάστε με [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

## Απόκτηση Δεδομένων

Δημιουργήστε ένα [android backup using adb](mobile-pentesting/android-app-pentesting/adb-commands.md#backup) και εξαγάγετέ το χρησιμοποιώντας το [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Αν έχετε πρόσβαση root ή φυσική σύνδεση στη διεπαφή JTAG

- `cat /proc/partitions` (αναζητήστε τη διαδρομή στη μνήμη flash, γενικά η πρώτη καταχώρηση είναι _mmcblk0_ και αντιστοιχεί σε ολόκληρη τη μνήμη flash).
- `df /data` (Ανακαλύψτε το μέγεθος μπλοκ του συστήματος).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (εκτελέστε το με τις πληροφορίες που συλλέξατε από το μέγεθος μπλοκ).

### Μνήμη

Χρησιμοποιήστε το Linux Memory Extractor (LiME) για να εξαγάγετε τις πληροφορίες RAM. Είναι μια επέκταση πυρήνα που πρέπει να φορτωθεί μέσω adb.

{{#include ./banners/hacktricks-training.md}}
