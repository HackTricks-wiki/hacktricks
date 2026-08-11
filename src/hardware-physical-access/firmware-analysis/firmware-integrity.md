# Ακεραιότητα Firmware

{{#include ../../banners/hacktricks-training.md}}

Όταν μια εξουσιοδοτημένη αξιολόγηση εντοπίζει ανεπαρκή ή ανύπαρκτη επαλήθευση υπογραφής του firmware, μια τροποποιημένη εικόνα firmware μπορεί να καταδείξει τον αντίκτυπο στην ακεραιότητα. Η ακόλουθη εργαστηριακή ροή εργασίας προσθέτει ένα bind shell, διατηρώντας παράλληλα τα αρχικά βήματα εξαγωγής, emulation και repacking.<sup>[[2]](#references)[[3]](#references)</sup>

1. Το firmware μπορεί να εξαχθεί χρησιμοποιώντας το firmware-mod-kit (FMK).
2. Θα πρέπει να αναγνωριστούν η αρχιτεκτονική και το endianness του firmware-στόχου.
3. Μπορεί να δημιουργηθεί ένας cross compiler χρησιμοποιώντας το Buildroot ή άλλες κατάλληλες μεθόδους για το περιβάλλον.
4. Το backdoor μπορεί να δημιουργηθεί με τον cross compiler.
5. Το backdoor μπορεί να αντιγραφεί στον κατάλογο /usr/bin του εξαχθέντος firmware.
6. Το κατάλληλο binary του QEMU μπορεί να αντιγραφεί στο rootfs του εξαχθέντος firmware.
7. Το backdoor μπορεί να γίνει emulated χρησιμοποιώντας chroot και QEMU.
8. Η πρόσβαση στο backdoor μπορεί να γίνει μέσω netcat.
9. Το binary του QEMU θα πρέπει να αφαιρεθεί από το rootfs του εξαχθέντος firmware.
10. Το τροποποιημένο firmware μπορεί να γίνει repackaged χρησιμοποιώντας το FMK.
11. Το firmware με backdoor μπορεί να ελεγχθεί με emulation μέσω του firmware analysis toolkit (FAT) και σύνδεση στη διεύθυνση IP και τη θύρα του backdoor-στόχου χρησιμοποιώντας netcat.

Εάν έχει ήδη αποκτηθεί root shell μέσω dynamic analysis, χειραγώγησης bootloader ή hardware security testing, μπορούν να εκτελεστούν precompiled test binaries, όπως implants ή reverse shells. Το `msfvenom` του Metasploit μπορεί να δημιουργήσει ένα payload ειδικό για την αρχιτεκτονική, για αυτήν τη ροή εργασίας επικύρωσης:<sup>[[4]](#references)</sup>

1. Θα πρέπει να αναγνωριστούν η αρχιτεκτονική και το endianness του firmware-στόχου.
2. Το Msfvenom μπορεί να χρησιμοποιηθεί για τον καθορισμό του payload-στόχου, της IP του host του attacker, του αριθμού της listening port, του filetype, της αρχιτεκτονικής, της πλατφόρμας και του αρχείου εξόδου.
3. Το payload μπορεί να μεταφερθεί στη compromised συσκευή και να διασφαλιστεί ότι διαθέτει δικαιώματα εκτέλεσης.
4. Το Metasploit μπορεί να προετοιμαστεί για τη διαχείριση εισερχόμενων αιτημάτων με εκκίνηση του msfconsole και ρύθμιση των παραμέτρων σύμφωνα με το payload.
5. Το meterpreter reverse shell μπορεί να εκτελεστεί στη compromised συσκευή.

## Unauthenticated transport bridges to privileged update protocols

Ένα συνηθισμένο σχεδιαστικό λάθος σε embedded συστήματα είναι η έκθεση του **ίδιου εσωτερικού command protocol μέσω πολλών transports**, με επιβολή authentication μόνο σε ένα από αυτά. Για παράδειγμα, το USB μπορεί να απαιτεί challenge-response, ενώ το BLE απλώς προωθεί μη authenticated **GATT writes** στον ίδιο privileged firmware-update handler.<sup>[[1]](#references)</sup>

Τυπική offensive ροή εργασίας:

1. Κάντε enumerate τη BLE GATT database και αναγνωρίστε τα writable characteristics που χρησιμοποιούνται από την επίσημη mobile app.
2. Κάντε sniff την κίνηση της app και αναζητήστε **magic bytes / opcodes** που αντιστοιχούν στο wired protocol.
3. Κάντε replay privileged commands μέσω BLE **χωρίς pairing** και επαληθεύστε αν οι sensitive operations εξακολουθούν να λειτουργούν.
4. Εάν είναι προσβάσιμα opcodes για firmware upgrade, config write, debug ή factory-test, αντιμετωπίστε το BLE ως **radio-reachable admin port**.

Γρήγοροι έλεγχοι:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Πράγματα που πρέπει να επαληθεύσετε κατά το reversing:

- Απαιτεί το BLE **pairing/bonding** ή μόνο μια απλή σύνδεση;
- Δρομολογούνται όλα τα transports στον ίδιο εσωτερικό dispatcher table;
- Φιλτράρονται διαφορετικά τα privileged opcodes μέσω USB / BLE / UART / Wi-Fi;
- Μπορεί η mobile app να ενεργοποιήσει απομακρυσμένα firmware update, recovery ή diagnostic handlers;

## Τα firmware containers που προστατεύονται μόνο με checksum εξακολουθούν να περιέχουν firmware υπό τον έλεγχο του attacker

Ένα firmware container που προστατεύεται μόνο από ένα **unkeyed checksum** (CRC32, SHA-256, MD5 κ.λπ.) παρέχει ανίχνευση αλλοίωσης, **όχι αυθεντικότητα**. Αν ο attacker μπορεί να φτάσει στη διαδικασία update, μπορεί να τροποποιήσει το image, να υπολογίσει ξανά το checksum και να κάνει flash arbitrary code.<sup>[[1]](#references)</sup>

Red flags κατά το RE:

- Ο κώδικας update επικυρώνει μόνο ένα trailing checksum blob όπως `CHK2`, `CRC` ή `SHA256`.
- Δεν υπάρχει signature verification ή secure-boot root of trust.
- Δεν χρησιμοποιείται device-bound MAC / HMAC / authenticated encryption.
- Το recovery mode δέχεται το ίδιο unauthenticated image format.

Πρακτική ροή validation:

1. Κάντε extract το firmware container και εντοπίστε τα bootloader, main firmware και integrity metadata.
2. Τροποποιήστε ένα harmless string ή banner στο image.
3. Υπολογίστε ξανά το checksum ακριβώς όπως απαιτεί ο updater.
4. Κάντε reflash το image μέσω της κανονικής διαδρομής update.
5. Επιβεβαιώστε την αλλαγή κατά το boot, ώστε να αποδείξετε την arbitrary firmware replacement.

Αν αυτό λειτουργεί μέσω ενός remotely reachable transport, όπως BLE/Wi-Fi, το bug είναι ουσιαστικά **unauthenticated OTA firmware replacement**.

## Μετατροπή ενός trusted USB peripheral σε BadUSB μέσω firmware reflashing

Όταν η συσκευή-στόχος είναι ήδη trusted από το host μέσω USB, το malicious firmware μπορεί να μη χρειάζεται να υλοποιήσει ένα πλήρες νέο USB stack. Ένα πολύ ευκολότερο pivot είναι συχνά η **επαναχρησιμοποίηση του υπάρχοντος HID support**.<sup>[[1]](#references)</sup>

Χρήσιμο pattern:

1. Ελέγξτε αν η συσκευή κάνει ήδη enumeration ως **HID Consumer Control** / media / vendor HID interface.
2. Εντοπίστε το υπάρχον **HID report descriptor** στο firmware.
3. Προσθέστε ή αντικαταστήστε descriptor entries, ώστε η συσκευή να διαφημίζει επίσης **keyboard** capability.
4. Επαναχρησιμοποιήστε τις υπάρχουσες firmware routines που στέλνουν ήδη HID reports, αντί να γράψετε νέα transport implementation.
5. Κάντε inject key press + key release reports, για να πληκτρολογείτε commands στο host.

Αυτό μετατρέπει το firmware compromise σε **host compromise**, επειδή το PC θα εμπιστευτεί το reflashed peripheral ως legitimate keyboard.

### Minimal assessment checklist

- Εμφανίζουν τα `dmesg`, Device Manager ή τα USB descriptors ένα υπάρχον HID interface;
- Υπάρχει διαθέσιμος χώρος κοντά στο report descriptor ή relocatable descriptor table;
- Μπορούν να επαναχρησιμοποιηθούν οι υπάρχουσες media-control send routines για keyboard reports;
- Αποδέχεται αυτόματα το host το νέο keyboard interface μετά το reflashing;

## Αξιόπιστη payload execution μέσα σε RTOS firmware

Αντί να εισάγετε fragile trampolines σε τυχαία code paths, αναζητήστε **υπάρχοντα RTOS tasks** που δεν χρησιμοποιούνται ή έχουν χαμηλό impact κατά την κανονική λειτουργία.<sup>[[1]](#references)</sup>

Γιατί είναι χρήσιμο:

- Ο scheduler ξεκινά το payload φυσικά κατά το boot.
- Αποφεύγετε την αλλοίωση κρίσιμου control flow.
- Τα delayed payloads είναι λιγότερο πιθανό να προκαλέσουν watchdog resets σε σχέση με την εκτέλεσή τους μέσα σε latency-sensitive USB/network handler.

Καλοί στόχοι είναι diagnostic, factory-test, telemetry ή coprocessor service tasks που φαίνονται dormant κατά τη συνήθη χρήση.

## Γρήγορο exploit iteration: επαναχρησιμοποίηση benign protocol handlers

Μόλις καταστεί δυνατή η τροποποίηση firmware, ένας compact τρόπος επιτάχυνσης του RE είναι η αντικατάσταση ενός harmless command handler (για παράδειγμα ενός **echo/debug opcode**) με custom **memory read / write / execute** primitives. Έτσι αποφεύγεται το πλήρες reflashing για κάθε experiment και είναι ιδιαίτερα χρήσιμο όταν η συσκευή υποστηρίζει τον τροποποιημένο handler μέσω fast wired transport.<sup>[[1]](#references)</sup>

Χρησιμοποιήστε το για:

- Επαλήθευση scatter-loaded memory maps
- Live inspection της κατάστασης heap/task
- Δοκιμή μικρών payloads πριν την εγγραφή τους στο flash
- Ασφαλή ανάκτηση function pointers, strings και descriptor tables

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - How to use `msfvenom`](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
