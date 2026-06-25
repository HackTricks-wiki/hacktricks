# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

Το **custom firmware και/ή compiled binaries μπορούν να uploaded για να exploit flaws ακεραιότητας ή signature verification**. Τα παρακάτω βήματα μπορούν να ακολουθηθούν για backdoor bind shell compilation:

1. Το firmware μπορεί να εξαχθεί χρησιμοποιώντας firmware-mod-kit (FMK).
2. Η αρχιτεκτονική και το endianness του target firmware πρέπει να εντοπιστούν.
3. Ένας cross compiler μπορεί να γίνει build χρησιμοποιώντας Buildroot ή άλλες κατάλληλες μεθόδους για το περιβάλλον.
4. Το backdoor μπορεί να γίνει build χρησιμοποιώντας τον cross compiler.
5. Το backdoor μπορεί να αντιγραφεί στον extracted firmware κατάλογο /usr/bin.
6. Το κατάλληλο QEMU binary μπορεί να αντιγραφεί στο extracted firmware rootfs.
7. Το backdoor μπορεί να emulated χρησιμοποιώντας chroot και QEMU.
8. Το backdoor μπορεί να προσπελαστεί μέσω netcat.
9. Το QEMU binary θα πρέπει να αφαιρεθεί από το extracted firmware rootfs.
10. Το modified firmware μπορεί να ξαναπακεταριστεί χρησιμοποιώντας FMK.
11. Το backdoored firmware μπορεί να δοκιμαστεί με emulating it με firmware analysis toolkit (FAT) και connecting to το target backdoor IP και port χρησιμοποιώντας netcat.

Αν ένα root shell έχει ήδη αποκτηθεί μέσω dynamic analysis, bootloader manipulation, ή hardware security testing, precompiled malicious binaries όπως implants ή reverse shells μπορούν να εκτελεστούν. Automated payload/implant tools όπως το Metasploit framework και 'msfvenom' μπορούν να αξιοποιηθούν χρησιμοποιώντας τα παρακάτω βήματα:

1. Η αρχιτεκτονική και το endianness του target firmware πρέπει να εντοπιστούν.
2. Το Msfvenom μπορεί να χρησιμοποιηθεί για να καθορίσει το target payload, attacker host IP, listening port number, filetype, architecture, platform, και το output file.
3. Το payload μπορεί να μεταφερθεί στη compromised συσκευή και να διασφαλιστεί ότι έχει execution permissions.
4. Το Metasploit μπορεί να προετοιμαστεί για να χειριστεί incoming requests ξεκινώντας το msfconsole και ρυθμίζοντας τις παραμέτρους σύμφωνα με το payload.
5. Το meterpreter reverse shell μπορεί να εκτελεστεί στη compromised συσκευή.

## Unauthenticated transport bridges to privileged update protocols

Ένα συνηθισμένο embedded design mistake είναι η έκθεση του **ίδιου internal command protocol μέσω πολλαπλών transports** αλλά η επιβολή authentication μόνο σε ένα από αυτά. Για παράδειγμα, το USB μπορεί να απαιτεί challenge-response ενώ το BLE απλώς προωθεί unauthenticated **GATT writes** στο ίδιο privileged firmware-update handler.

Τυπικό offensive workflow:

1. Enumerate το BLE GATT database και εντόπισε writable characteristics που χρησιμοποιούνται από την official mobile app.
2. Sniff app traffic και αναζήτησε **magic bytes / opcodes** που ταιριάζουν με το wired protocol.
3. Replay privileged commands over BLE **without pairing** και επαλήθευσε αν οι sensitive operations εξακολουθούν να λειτουργούν.
4. Αν firmware upgrade, config write, debug, ή factory-test opcodes είναι reachable, αντιμετώπισε το BLE ως **radio-reachable admin port**.

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Πράγματα που πρέπει να επαληθεύσετε κατά το reversing:

- Χρειάζεται το BLE **pairing/bonding** ή αρκεί μια απλή σύνδεση;
- Κατευθύνονται όλα τα transports στον ίδιο εσωτερικό dispatcher table;
- Φιλτράρονται διαφορετικά τα privileged opcodes σε USB / BLE / UART / Wi-Fi;
- Μπορεί η mobile app να ενεργοποιήσει remotely firmware update, recovery ή diagnostic handlers;

## Τα firmware containers μόνο με checksum παραμένουν attacker-controlled firmware

Ένα firmware container που προστατεύεται μόνο από ένα **unkeyed checksum** (CRC32, SHA-256, MD5, κ.λπ.) παρέχει ανίχνευση αλλοίωσης, **όχι authenticity**. Αν ο attacker μπορεί να φτάσει τη ρουτίνα update, μπορεί να patchάρει το image, να επανυπολογίσει το checksum και να κάνει flash arbitrary code.

Red flags κατά το RE:

- Ο κώδικας update επικυρώνει μόνο ένα trailing checksum blob όπως `CHK2`, `CRC` ή `SHA256`.
- Δεν υπάρχει signature verification ή secure-boot root of trust.
- Δεν χρησιμοποιείται device-bound MAC / HMAC / authenticated encryption.
- Το recovery mode δέχεται το ίδιο unauthenticated image format.

Πρακτικό validation flow:

1. Εξαγάγετε το firmware container και εντοπίστε bootloader, main firmware και integrity metadata.
2. Τροποποιήστε ένα ακίνδυνο string ή banner μέσα στο image.
3. Επανυπολογίστε το checksum ακριβώς όπως το περιμένει ο updater.
4. Κάντε reflash το image μέσω του κανονικού update path.
5. Επιβεβαιώστε την αλλαγή στο boot για να αποδείξετε arbitrary firmware replacement.

Αν αυτό λειτουργεί μέσω ενός remotely reachable transport όπως BLE/Wi-Fi, το bug είναι ουσιαστικά **unauthenticated OTA firmware replacement**.

## Μετατροπή ενός trusted USB peripheral σε BadUSB μέσω firmware reflashing

Όταν η συσκευή-στόχος είναι ήδη trusted από τον host μέσω USB, το malicious firmware μπορεί να μην χρειάζεται να υλοποιήσει ένα πλήρες νέο USB stack. Ένα πολύ ευκολότερο pivot είναι συχνά η **επαναχρησιμοποίηση υπάρχουσας HID support**.

Χρήσιμο pattern:

1. Ελέγξτε αν η συσκευή ήδη κάνει enumerate ως **HID Consumer Control** / media / vendor HID interface.
2. Εντοπίστε το υπάρχον **HID report descriptor** στο firmware.
3. Προσθέστε ή αντικαταστήστε descriptor entries ώστε η συσκευή να δηλώνει επίσης **keyboard** capability.
4. Επαναχρησιμοποιήστε υπάρχουσες ρουτίνες firmware που ήδη στέλνουν HID reports αντί να γράψετε νέα transport implementation.
5. Inject key press + key release reports για να πληκτρολογήσετε commands στον host.

Αυτό μετατρέπει το firmware compromise σε **host compromise**, επειδή ο PC θα εμπιστευτεί το reflashed peripheral ως νόμιμο keyboard.

### Ελάχιστο assessment checklist

- Δείχνει το `dmesg`, το Device Manager ή τα USB descriptors ένα υπάρχον HID interface;
- Υπάρχει ελεύθερος χώρος κοντά στο report descriptor ή ένας relocatable descriptor table;
- Μπορούν να επαναχρησιμοποιηθούν υπάρχουσες ρουτίνες media-control για keyboard reports;
- Ο host αποδέχεται αυτόματα το νέο keyboard interface μετά το reflashing;

## Αξιόπιστη εκτέλεση payload μέσα σε RTOS firmware

Αντί να εισάγετε fragile trampolines σε τυχαία code paths, αναζητήστε **υπάρχοντα RTOS tasks** που είναι αχρησιμοποίητα ή χαμηλού αντίκτυπου στη φυσιολογική λειτουργία.

Γιατί αυτό είναι χρήσιμο:

- Ο scheduler ξεκινά το payload σας φυσικά κατά το boot.
- Αποφεύγετε να καταστρέψετε κρίσιμο control flow.
- Τα delayed payloads είναι λιγότερο πιθανό να προκαλέσουν watchdog resets από ό,τι όταν εκτελούνται μέσα σε latency-sensitive USB/network handler.

Καλοί στόχοι είναι diagnostic, factory-test, telemetry ή coprocessor service tasks που φαίνονται ανενεργά στη φυσιολογική χρήση.

## Γρήγορη επανάληψη exploit: επαναχρησιμοποίηση benign protocol handlers

Μόλις γίνει δυνατή η patching του firmware, ένας συμπαγής τρόπος για να επιταχύνετε το RE είναι να αντικαταστήσετε έναν ακίνδυνο command handler (για παράδειγμα ένα **echo/debug opcode**) με custom **memory read / write / execute** primitives. Αυτό αποφεύγει το πλήρες reflashing για κάθε πείραμα και είναι ιδιαίτερα χρήσιμο όταν η συσκευή υποστηρίζει τον τροποποιημένο handler μέσω ενός γρήγορου wired transport.

Χρησιμοποιήστε το για να:

- Επαληθεύσετε scatter-loaded memory maps
- Επιθεωρήσετε live το heap/task state
- Δοκιμάσετε μικρά payloads πριν τα γράψετε σε flash
- Ανακτήσετε function pointers, strings και descriptor tables με ασφάλεια

## Αναφορές

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
