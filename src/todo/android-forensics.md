# Forensics σε Android

{{#include ../banners/hacktricks-training.md}}

## Κλειδωμένη συσκευή

Για να ξεκινήσετε την εξαγωγή δεδομένων από μια συσκευή Android, πρέπει να είναι ξεκλείδωτη. Αν είναι κλειδωμένη, μπορείτε να:

- Ελέγξετε αν έχει ενεργοποιηθεί το debugging μέσω USB.
- Ελέγξετε για πιθανή [smudge attack](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)<sup>[[1]](#references)</sup>
- Δοκιμάσετε [Brute-force](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)<sup>[[2]](#references)</sup>

## Απόκτηση δεδομένων

Δημιουργήστε ένα [android backup using adb](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) και εξαγάγετέ το χρησιμοποιώντας το [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/): `java -jar abe.jar unpack file.backup file.tar`

### Αν υπάρχει root access ή φυσική σύνδεση σε interface JTAG

- `cat /proc/partitions` (αναζητήστε τη διαδρομή προς τη μνήμη flash· γενικά, η πρώτη καταχώριση είναι η _mmcblk0_ και αντιστοιχεί σε ολόκληρη τη μνήμη flash).
- `df /data` (εντοπίστε το block size του συστήματος).
- dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096 (εκτελέστε το χρησιμοποιώντας τις πληροφορίες που συλλέχθηκαν σχετικά με το block size).

### Μνήμη

Χρησιμοποιήστε το Linux Memory Extractor (LiME) για να εξαγάγετε τις πληροφορίες της RAM. Πρόκειται για kernel extension που πρέπει να φορτωθεί μέσω adb.

## Αναφορές

- [1] [Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [2] [This brute force device can crack any iPhone's PIN code](https://www.cultofmac.com/316532/this-brute-force-device-can-crack-any-iphones-pin-code/)

{{#include ../banners/hacktricks-training.md}}
