# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα καταγράφει ένα πρακτικό break του secure-boot σε πολλαπλές πλατφόρμες MediaTek εκμεταλλευόμενη ένα κενό επαλήθευσης όταν η ρύθμιση του bootloader της συσκευής (seccfg) είναι "unlocked". Το σφάλμα επιτρέπει την εκτέλεση ενός patched bl2_ext σε ARM EL3 για να απενεργοποιήσει την επαλήθευση υπογραφών στην συνέχεια, καταρρίπτοντας την αλυσίδα εμπιστοσύνης και επιτρέποντας την φόρτωση αυθαίρετων unsigned TEE/GZ/LK/Kernel.

> Προσοχή: Το early-boot patching μπορεί να κάνει μόνιμα brick τις συσκευές αν τα offsets είναι λάθος. Κρατήστε πάντα πλήρη dumps και έναν αξιόπιστο δρόμο ανάκτησης.

## Επηρεασμένη ροή εκκίνησης (MediaTek)

- Κανονική διαδρομή: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ευάλωτη διαδρομή: Όταν το seccfg είναι ρυθμισμένο σε "unlocked", ο Preloader μπορεί να παραλείψει την επαλήθευση του bl2_ext. Ο Preloader εξακολουθεί να κάνει jump στο bl2_ext σε EL3, οπότε ένα crafted bl2_ext μπορεί να φορτώσει μη επαληθευμένα components στη συνέχεια.

Κρίσιμο όριο εμπιστοσύνης:
- Το bl2_ext εκτελείται σε EL3 και είναι υπεύθυνο για την επαλήθευση του TEE, GenieZone, LK/AEE και του kernel. Αν το bl2_ext δεν είναι αυθεντικοποιημένο, η υπόλοιπη αλυσίδα παρακάμπτεται εύκολα.

## Αιτία

Σε επηρεαζόμενες συσκευές, ο Preloader δεν επιβάλλει την αυθεντικοποίηση του partition bl2_ext όταν το seccfg δείχνει κατάσταση "unlocked". Αυτό επιτρέπει να flashαριστεί ένα attacker-controlled bl2_ext που τρέχει σε EL3.

Μέσα στο bl2_ext, η συνάρτηση πολιτικής επαλήθευσης μπορεί να τροποποιηθεί ώστε να αναφέρει αδιακρίτως ότι η επαλήθευση δεν απαιτείται. Ένα ελάχιστο εννοιολογικό patch είναι:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Με αυτή την αλλαγή, όλες οι επακόλουθες images (TEE, GZ, LK/AEE, Kernel) γίνονται αποδεκτές χωρίς κρυπτογραφικούς ελέγχους όταν φορτώνονται από το patched bl2_ext που τρέχει στο EL3.

## Πώς να αξιολογήσετε έναν στόχο (expdb logs)

Dump/inspect boot logs (e.g., expdb) γύρω από τη φόρτωση του bl2_ext. Εάν img_auth_required = 0 και ο χρόνος επαλήθευσης πιστοποιητικού είναι ~0 ms, η επιβολή πιθανότατα είναι απενεργοποιημένη και η συσκευή είναι εκμεταλλεύσιμη.

Παράδειγμα αποσπάσματος καταγραφής:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Σημείωση: Ορισμένες συσκευές αναφέρεται ότι παρακάμπτουν την επαλήθευση του bl2_ext ακόμη και με locked bootloader, κάτι που επιδεινώνει τον αντίκτυπο.

## Πρακτική ροή εκμετάλλευσης (Fenrir PoC)

Το Fenrir είναι ένα reference exploit/patching toolkit για αυτή την κατηγορία ευπαθειών. Υποστηρίζει τα Nothing Phone (2a) (Pacman) και είναι γνωστό ότι λειτουργεί (με μερική υποστήριξη) στο CMF Phone 1 (Tetris). Η μεταφορά σε άλλα μοντέλα απαιτεί αντίστροφη μηχανική του bl2_ext ειδικού για τη συσκευή.

High-level process:
- Απόκτησε την εικόνα του device bootloader για το target codename σου και τοποθέτησέ την ως bin/<device>.bin
- Δημιούργησε μια patched image που απενεργοποιεί την πολιτική επαλήθευσης του bl2_ext
- Flash το προκύπτον payload στη συσκευή (το helper script υποθέτει fastboot)

Εντολές:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Δυνατότητες runtime payload (EL3)

Ένα patched bl2_ext payload μπορεί να:
- Καταχωρεί προσαρμοσμένες εντολές fastboot
- Ελέγχει/παρακάμπτει το boot mode
- Καλεί δυναμικά ενσωματωμένες συναρτήσεις του bootloader κατά το runtime
- Παραπλανεί την “lock state” ως locked ενώ στην πραγματικότητα είναι unlocked για να περάσει αυστηρότερους ελέγχους ακεραιότητας (ορισμένα περιβάλλοντα μπορεί να απαιτούν ακόμη ρυθμίσεις vbmeta/AVB)

Περιορισμός: Τα τρέχοντα PoC επισημαίνουν ότι η τροποποίηση μνήμης σε runtime μπορεί να κάνει fault λόγω περιορισμών MMU· τα payloads γενικά αποφεύγουν εγγραφές σε ζωντανή μνήμη μέχρι να επιλυθεί αυτό.

## Συμβουλές porting

- Κάντε reverse engineering του device-specific bl2_ext για να εντοπίσετε τη λογική της πολιτικής επαλήθευσης (π.χ., sec_get_vfy_policy).
- Εντοπίστε τη θέση επιστροφής της πολιτικής ή τον κλάδο απόφασης και κάντε patch ώστε να «δεν απαιτείται επαλήθευση» (return 0 / unconditional allow).
- Διατηρήστε τα offsets απολύτως συγκεκριμένα για συσκευή και firmware· μην επαναχρησιμοποιείτε διευθύνσεις ανάμεσα σε παραλλαγές.
- Επιβεβαιώστε πρώτα σε μια θυσιαστική μονάδα. Προετοιμάστε σχέδιο ανάκτησης (π.χ., EDL/BootROM loader/SoC-specific download mode) πριν κάνετε flash.

## Επιπτώσεις στην ασφάλεια

- Εκτέλεση κώδικα σε EL3 μετά το Preloader και πλήρης κατάρρευση της αλυσίδας εμπιστοσύνης για το υπόλοιπο της διαδικασίας εκκίνησης.
- Ικανότητα να γίνει boot unsigned TEE/GZ/LK/Kernel, παρακάμπτοντας τις προσδοκίες secure/verified boot και επιτρέποντας μόνιμη παραβίαση.

## Ιδέες ανίχνευσης και ενίσχυσης ασφάλειας

- Βεβαιώστε ότι ο Preloader επαληθεύει το bl2_ext ανεξάρτητα από την κατάσταση seccfg.
- Επιβάλετε τα αποτελέσματα authentication και συλλέξτε αποδεικτικά στοιχεία audit (timings > 0 ms, αυστηρά σφάλματα σε mismatch).
- Το spoofing της lock-state θα πρέπει να γίνεται άχρηστο για attestation (συνδέστε την lock state με τις αποφάσεις επαλήθευσης AVB/vbmeta και με fuse-backed state).

## Σημειώσεις συσκευής

- Επιβεβαιωμένα υποστηριζόμενο: Nothing Phone (2a) (Pacman)
- Γνωστό ότι λειτουργεί (ατελής υποστήριξη): CMF Phone 1 (Tetris)
- Παρατηρήθηκε: Φημολογείται ότι το Vivo X80 Pro δεν επαλήθευε το bl2_ext ακόμη και όταν ήταν locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
