# Ακεραιότητα Firmware

{{#include ../../banners/hacktricks-training.md}}

Το **custom firmware ή/και τα compiled binaries μπορούν να μεταφορτωθούν για την εκμετάλλευση αδυναμιών ακεραιότητας ή επαλήθευσης υπογραφής**. Τα ακόλουθα βήματα μπορούν να χρησιμοποιηθούν για τη compilation ενός backdoor bind shell:

1. Το firmware μπορεί να εξαχθεί χρησιμοποιώντας το firmware-mod-kit (FMK).
2. Θα πρέπει να αναγνωριστούν η αρχιτεκτονική και το endianness του firmware-στόχου.
3. Μπορεί να δημιουργηθεί ένας cross compiler χρησιμοποιώντας το Buildroot ή άλλες κατάλληλες μεθόδους για το περιβάλλον.
4. Το backdoor μπορεί να γίνει build χρησιμοποιώντας τον cross compiler.
5. Το backdoor μπορεί να αντιγραφεί στον κατάλογο /usr/bin του εξαχθέντος firmware.
6. Το κατάλληλο QEMU binary μπορεί να αντιγραφεί στο rootfs του εξαχθέντος firmware.
7. Το backdoor μπορεί να γίνει emulate χρησιμοποιώντας chroot και QEMU.
8. Η πρόσβαση στο backdoor μπορεί να γίνει μέσω netcat.
9. Το QEMU binary θα πρέπει να αφαιρεθεί από το rootfs του εξαχθέντος firmware.
10. Το τροποποιημένο firmware μπορεί να γίνει repackage χρησιμοποιώντας το FMK.
11. Το backdoored firmware μπορεί να δοκιμαστεί με emulation μέσω του firmware analysis toolkit (FAT) και σύνδεση στη backdoor IP και port του στόχου χρησιμοποιώντας netcat.

Εάν έχει ήδη αποκτηθεί root shell μέσω dynamic analysis, manipulation του bootloader ή hardware security testing, μπορούν να εκτελεστούν precompiled malicious binaries, όπως implants ή reverse shells. Automated payload/implant tools, όπως το Metasploit framework και το 'msfvenom', μπορούν να αξιοποιηθούν με τα ακόλουθα βήματα:

1. Θα πρέπει να αναγνωριστούν η αρχιτεκτονική και το endianness του firmware-στόχου.
2. Το Msfvenom μπορεί να χρησιμοποιηθεί για τον καθορισμό του target payload, του attacker host IP, του listening port number, του filetype, της αρχιτεκτονικής, της πλατφόρμας και του output file.
3. Το payload μπορεί να μεταφερθεί στη compromised συσκευή και να διασφαλιστεί ότι διαθέτει execution permissions.
4. Το Metasploit μπορεί να προετοιμαστεί για τη διαχείριση incoming requests, με εκκίνηση του msfconsole και ρύθμιση των settings σύμφωνα με το payload.
5. Το meterpreter reverse shell μπορεί να εκτελεστεί στη compromised συσκευή.

## Unauthenticated transport bridges to privileged update protocols

Ένα συνηθισμένο embedded design mistake είναι η έκθεση του **ίδιου internal command protocol μέσω πολλών transports**, με authentication να επιβάλλεται μόνο σε ένα από αυτά. Για παράδειγμα, το USB μπορεί να απαιτεί challenge-response, ενώ το BLE απλώς προωθεί unauthenticated **GATT writes** στον ίδιο privileged firmware-update handler.<sup>[[1]](#references)</sup>

Τυπικό offensive workflow:

1. Κάντε enumerate τη BLE GATT database και εντοπίστε writable characteristics που χρησιμοποιούνται από το official mobile app.
2. Κάντε sniff την app traffic και αναζητήστε **magic bytes / opcodes** που ταιριάζουν με το wired protocol.
3. Κάντε replay privileged commands μέσω BLE **χωρίς pairing** και επαληθεύστε εάν οι sensitive operations εξακολουθούν να λειτουργούν.
4. Εάν τα firmware upgrade, config write, debug ή factory-test opcodes είναι προσβάσιμα, αντιμετωπίστε το BLE ως **radio-reachable admin port**.

Γρήγοροι έλεγχοι:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Πράγματα που πρέπει να επαληθεύονται κατά το reversing:

- Απαιτεί το BLE **pairing/bonding** ή απλώς μια απλή σύνδεση;
- Δρομολογούνται όλα τα transports στον ίδιο εσωτερικό πίνακα dispatcher;
- Φιλτράρονται διαφορετικά τα privileged opcodes σε USB / BLE / UART / Wi-Fi;
- Μπορεί το mobile app να ενεργοποιήσει απομακρυσμένα handlers για firmware update, recovery ή diagnostics;

## Τα firmware containers που προστατεύονται μόνο με checksum ελέγχονται ακόμη από τον attacker

Ένα firmware container που προστατεύεται μόνο από ένα **unkeyed checksum** (CRC32, SHA-256, MD5 κ.λπ.) παρέχει ανίχνευση corruption, **όχι αυθεντικότητα**. Αν ο attacker μπορεί να φτάσει στη ρουτίνα update, μπορεί να τροποποιήσει το image, να υπολογίσει ξανά το checksum και να κάνει flash arbitrary code.<sup>[[1]](#references)</sup>

Red flags κατά το RE:

- Ο κώδικας update επικυρώνει μόνο ένα trailing checksum blob, όπως `CHK2`, `CRC` ή `SHA256`.
- Δεν υπάρχει signature verification ή secure-boot root of trust.
- Δεν χρησιμοποιείται device-bound MAC / HMAC / authenticated encryption.
- Το recovery mode αποδέχεται το ίδιο unauthenticated image format.

Πρακτική ροή validation:

1. Κάντε extract το firmware container και εντοπίστε το bootloader, το main firmware και τα integrity metadata.
2. Τροποποιήστε ένα harmless string ή banner στο image.
3. Υπολογίστε ξανά το checksum ακριβώς όπως το περιμένει ο updater.
4. Κάντε reflash το image μέσω του κανονικού update path.
5. Επιβεβαιώστε την αλλαγή κατά το boot, ώστε να αποδείξετε την arbitrary firmware replacement.

Αν αυτό λειτουργεί μέσω ενός remotely reachable transport, όπως BLE/Wi-Fi, το bug είναι ουσιαστικά **unauthenticated OTA firmware replacement**.

## Μετατροπή ενός trusted USB peripheral σε BadUSB μέσω firmware reflashing

Όταν η target συσκευή είναι ήδη trusted από το host μέσω USB, το malicious firmware ενδέχεται να μην χρειάζεται να υλοποιήσει ένα πλήρες νέο USB stack. Ένα πολύ ευκολότερο pivot είναι συχνά η **reuse του υπάρχοντος HID support**.<sup>[[1]](#references)</sup>

Χρήσιμο pattern:

1. Ελέγξτε αν η συσκευή κάνει ήδη enumerate ως **HID Consumer Control** / media / vendor HID interface.
2. Εντοπίστε το υπάρχον **HID report descriptor** στο firmware.
3. Προσθέστε ή αντικαταστήστε descriptor entries, ώστε η συσκευή να διαφημίζει επίσης **keyboard** capability.
4. Κάντε reuse των υπαρχουσών firmware routines που στέλνουν ήδη HID reports, αντί να γράψετε νέα transport implementation.
5. Κάντε inject key press + key release reports για να πληκτρολογείτε commands στο host.

Αυτό μετατρέπει το firmware compromise σε **host compromise**, επειδή το PC θα εμπιστευτεί το reflashed peripheral ως legitimate keyboard.

### Minimal assessment checklist

- Εμφανίζουν τα `dmesg`, Device Manager ή τα USB descriptors ένα υπάρχον HID interface;
- Υπάρχει διαθέσιμος χώρος κοντά στο report descriptor ή ένας relocatable descriptor table;
- Μπορούν να γίνουν reuse οι υπάρχουσες media-control send routines για keyboard reports;
- Αποδέχεται αυτόματα το host το νέο keyboard interface μετά το reflashing;

## Αξιόπιστη payload execution μέσα σε RTOS firmware

Αντί να εισάγετε fragile trampolines σε τυχαία code paths, αναζητήστε **υπάρχοντα RTOS tasks** που δεν χρησιμοποιούνται ή έχουν χαμηλό αντίκτυπο στην κανονική λειτουργία.<sup>[[1]](#references)</sup>

Γιατί είναι χρήσιμο:

- Ο scheduler εκκινεί φυσικά το payload κατά το boot.
- Αποφεύγετε την καταστροφή κρίσιμου control flow.
- Τα delayed payloads είναι λιγότερο πιθανό να προκαλέσουν watchdog resets σε σχέση με την εκτέλεσή τους μέσα σε έναν latency-sensitive USB/network handler.

Καλοί στόχοι είναι diagnostic, factory-test, telemetry ή coprocessor service tasks που φαίνονται dormant στην κανονική χρήση.

## Γρήγορη exploit iteration: επαναχρησιμοποίηση benign protocol handlers

Όταν είναι δυνατή η τροποποίηση firmware, ένας compact τρόπος για επιτάχυνση του RE είναι η αντικατάσταση ενός harmless command handler (για παράδειγμα ενός **echo/debug opcode**) με custom **memory read / write / execute** primitives. Έτσι αποφεύγετε το πλήρες reflashing για κάθε experiment και είναι ιδιαίτερα χρήσιμο όταν η συσκευή υποστηρίζει τον modified handler μέσω fast wired transport.<sup>[[1]](#references)</sup>

Χρησιμοποιήστε το για:

- Επαλήθευση scatter-loaded memory maps
- Live inspection της κατάστασης heap/task
- Δοκιμή μικρών payloads πριν εγγραφούν στο flash
- Ασφαλή ανάκτηση function pointers, strings και descriptor tables

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
