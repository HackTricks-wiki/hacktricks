# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει ένα πρακτικό secure-boot break σε πολλαπλές πλατφόρμες MediaTek, εκμεταλλευόμενο ένα κενό επαλήθευσης όταν η ρύθμιση του bootloader της συσκευής (seccfg) είναι "unlocked". Το σφάλμα επιτρέπει την εκτέλεση ενός patched bl2_ext σε ARM EL3 για να απενεργοποιήσει την downstream signature verification, να καταρρεύσει την chain of trust και να επιτρέψει το φόρτωμα αυθαίρετων unsigned TEE/GZ/LK/Kernel.

> Προειδοποίηση: Η Early-boot patching μπορεί να οδηγήσει σε μόνιμο brick των συσκευών αν οι offsets είναι λάθος. Διατηρείτε πάντα πλήρη dumps και μια αξιόπιστη recovery path.

## Επηρεασμένη ροή εκκίνησης (MediaTek)

- Κανονική διαδρομή: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ευπαθής διαδρομή: Όταν το seccfg είναι ορισμένο σε unlocked, ο Preloader μπορεί να παραλείψει την επαλήθευση του bl2_ext. Ο Preloader εξακολουθεί να κάνει jump στο bl2_ext σε EL3, οπότε ένα crafted bl2_ext μπορεί να φορτώσει μη επαληθευμένα components στη συνέχεια.

Κρίσιμο όριο εμπιστοσύνης:
- Το bl2_ext εκτελείται σε EL3 και είναι υπεύθυνο για την επαλήθευση του TEE, GenieZone, LK/AEE και του kernel. Αν το bl2_ext δεν είναι authenticated, το υπόλοιπο της chain παρακάμπτεται εύκολα.

## Βασική αιτία

Σε επηρεασμένες συσκευές, ο Preloader δεν επιβάλλει authentication του bl2_ext partition όταν το seccfg δείχνει κατάσταση "unlocked". Αυτό επιτρέπει το flashing ενός attacker-controlled bl2_ext που τρέχει σε EL3.

Μέσα στο bl2_ext, η verification policy function μπορεί να patched ώστε να αναφέρει ανεπιφύλακτα ότι η verification δεν απαιτείται. Ένα ελάχιστο εννοιολογικό patch είναι:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Με αυτή την αλλαγή, όλες οι επόμενες images (TEE, GZ, LK/AEE, Kernel) γίνονται αποδεκτές χωρίς κρυπτογραφικούς ελέγχους όταν φορτώνονται από το patched bl2_ext που εκτελείται στο EL3.

## Πώς να αξιολογήσετε έναν στόχο (expdb logs)

Dump/inspect τα boot logs (π.χ., expdb) γύρω από το φόρτωμα του bl2_ext. Αν img_auth_required = 0 και ο χρόνος επαλήθευσης πιστοποιητικού είναι ~0 ms, η επιβολή πιθανότατα είναι off και η συσκευή είναι exploitable.

Παράδειγμα αποσπάσματος log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Σημείωση: Φαίνεται ότι ορισμένες συσκευές παρακάμπτουν την επαλήθευση του bl2_ext ακόμα και με κλειδωμένο bootloader, γεγονός που επιδεινώνει τον αντίκτυπο.

## Πρακτική ροή εκμετάλλευσης (Fenrir PoC)

Fenrir είναι ένα reference exploit/patching toolkit για αυτή την κατηγορία ζητήματος. Υποστηρίζει Nothing Phone (2a) (Pacman) και είναι γνωστό ότι λειτουργεί (μερικώς υποστηριζόμενο) στο CMF Phone 1 (Tetris). Η μεταφορά σε άλλα μοντέλα απαιτεί reverse engineering του bl2_ext συγκεκριμένης συσκευής.

High-level process:
- Πάρτε το device bootloader image για το target codename και τοποθετήστε το ως bin/<device>.bin
- Δημιουργήστε ένα patched image που απενεργοποιεί την πολιτική επαλήθευσης του bl2_ext
- Φλασάρετε το προκύπτον payload στη συσκευή (το helper script υποθέτει fastboot)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Εγγραφή προσαρμοσμένων εντολών fastboot
- Έλεγχος/παράκαμψη του boot mode
- Κλήση κατά runtime των ενσωματωμένων συναρτήσεων του bootloader
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Porting tips

- Αναλύστε (reverse engineer) το device-specific bl2_ext για να εντοπίσετε τη λογική πολιτικής επαλήθευσης (π.χ., sec_get_vfy_policy).
- Εντοπίστε το policy return site ή το decision branch και τροποποιήστε το σε “no verification required” (return 0 / unconditional allow).
- Keep offsets fully device- and firmware-specific; do not reuse addresses between variants.
- Validate on a sacrificial unit first. Prepare a recovery plan (e.g., EDL/BootROM loader/SoC-specific download mode) before you flash.

## Security impact

- EL3 code execution after Preloader and full chain-of-trust collapse for the rest of the boot path.
- Ability to boot unsigned TEE/GZ/LK/Kernel, bypassing secure/verified boot expectations and enabling persistent compromise.

## Detection and hardening ideas

- Ensure Preloader verifies bl2_ext regardless of seccfg state.
- Enforce authentication results and gather audit evidence (timings > 0 ms, strict errors on mismatch).
- Lock-state spoofing should be made ineffective for attestation (tie lock state to AVB/vbmeta verification decisions and fuse-backed state).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
