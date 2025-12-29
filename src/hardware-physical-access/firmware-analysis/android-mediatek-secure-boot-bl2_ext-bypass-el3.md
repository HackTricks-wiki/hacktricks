# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει ένα πρακτικό break στο secure-boot σε πολλαπλές πλατφόρμες MediaTek εκμεταλλευόμενη ένα κενό επαλήθευσης όταν η διαμόρφωση του bootloader της συσκευής (seccfg) είναι "unlocked". Το σφάλμα επιτρέπει την εκτέλεση ενός τροποποιημένου bl2_ext στο ARM EL3 για να απενεργοποιήσει την επαλήθευση υπολοίπων υπογραφών, καταρρίπτοντας την αλυσίδα εμπιστοσύνης και επιτρέποντας τη φόρτωση αυθαίρετων unsigned TEE/GZ/LK/Kernel.

> Προσοχή: Η patching σε πολύ πρώιμο στάδιο εκκίνησης μπορεί να κάνει τις συσκευές μη αναστρέψιμα brick αν οι offsets είναι λανθασμένες. Κρατήστε πάντα πλήρη dumps και μια αξιόπιστη οδό ανάκτησης.

## Επηρεαζόμενη ροή εκκίνησης (MediaTek)

- Κανονική διαδρομή: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ευάλωτη διαδρομή: Όταν το seccfg είναι ρυθμισμένο σε unlocked, ο Preloader μπορεί να παραλείψει την επαλήθευση του bl2_ext. Ο Preloader εξακολουθεί να κάνει jump στο bl2_ext στο EL3, επομένως ένα crafted bl2_ext μπορεί να φορτώσει μη επαληθευμένα components στη συνέχεια.

Βασικό όριο εμπιστοσύνης:
- Το bl2_ext εκτελείται στο EL3 και είναι υπεύθυνο για την επαλήθευση του TEE, GenieZone, LK/AEE και του kernel. Αν το bl2_ext δεν είναι πιστοποιημένο, το υπόλοιπο της αλυσίδας παρακάμπτεται πολύ εύκολα.

## Αιτία

Σε επηρεαζόμενες συσκευές, ο Preloader δεν επιβάλλει την authentication του partition bl2_ext όταν το seccfg υποδεικνύει κατάσταση "unlocked". Αυτό επιτρέπει το flashing ενός attacker-controlled bl2_ext που τρέχει στο EL3.

Μέσα στο bl2_ext, η συνάρτηση verification policy μπορεί να τροποποιηθεί ώστε να επιστρέφει χωρίς όρους ότι η επαλήθευση δεν απαιτείται. Μια ελάχιστη εννοιολογική patch είναι:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Με αυτή την αλλαγή, όλες οι επακόλουθες εικόνες (TEE, GZ, LK/AEE, Kernel) γίνονται αποδεκτές χωρίς κρυπτογραφικούς ελέγχους όταν φορτώνονται από το τροποποιημένο bl2_ext που τρέχει στο EL3.

## Πώς να αξιολογήσετε έναν στόχο (expdb logs)

Εξάγετε/επιθεωρήστε τα boot logs (π.χ., expdb) γύρω από τη φόρτωση του bl2_ext. Εάν img_auth_required = 0 και ο χρόνος επαλήθευσης πιστοποιητικού είναι ~0 ms, η επιβολή πιθανότατα είναι απενεργοποιημένη και η συσκευή είναι εκμεταλλεύσιμη.

Παράδειγμα αποσπάσματος καταγραφής:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note: Αναφέρεται ότι ορισμένες συσκευές παρακάμπτουν την επαλήθευση του bl2_ext ακόμα και με κλειδωμένο bootloader, κάτι που επιδεινώνει τον αντίκτυπο.

Συσκευές που αποστέλλονται με τον δευτερεύοντα bootloader lk2 έχουν παρατηρηθεί με το ίδιο λογικό κενό, οπότε συλλέξτε expdb logs για τα partitions bl2_ext και lk2 για να επιβεβαιώσετε αν κάποια από τις δύο διαδρομές επιβάλλει υπογραφές πριν επιχειρήσετε porting.

## Πρακτική ροή εκμετάλλευσης (Fenrir PoC)

Fenrir είναι ένα reference exploit/patching toolkit για αυτή την κατηγορία προβλημάτων. Υποστηρίζει Nothing Phone (2a) (Pacman) και είναι γνωστό ότι λειτουργεί (ατελώς υποστηριζόμενο) στο CMF Phone 1 (Tetris). Το porting σε άλλα μοντέλα απαιτεί reverse engineering του device-specific bl2_ext.

High-level process:
- Obtain the device bootloader image for your target codename and place it as `bin/<device>.bin`
- Build a patched image that disables the bl2_ext verification policy
- Flash the resulting payload to the device (fastboot assumed by the helper script)

Εντολές:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

### Build automation & payload debugging

- `build.sh` τώρα κατεβάζει αυτόματα και εξάγει το Arm GNU Toolchain 14.2 (aarch64-none-elf) την πρώτη φορά που το τρέχετε, οπότε δεν χρειάζεται να διαχειρίζεστε cross-compilers χειροκίνητα.
- Εξάγετε `DEBUG=1` πριν καλέσετε `build.sh` για να compile-άρετε payloads με verbose serial prints, κάτι που βοηθά σημαντικά όταν κάνετε blind-patching σε διαδρομές κώδικα EL3.
- Οι επιτυχημένες builds παράγουν τόσο το `lk.patched` όσο και το `<device>-fenrir.bin`; το δεύτερο έχει ήδη τον payload εγχυμένο και είναι αυτό που πρέπει να flash/boot-test.

## Runtime payload capabilities (EL3)

Ένα patched bl2_ext payload μπορεί:
- Καταχωρεί custom fastboot commands
- Ελέγχει/override-άρει το boot mode
- Καλεί δυναμικά built‑in bootloader functions κατά το runtime
- Spoof-άρει το “lock state” ως locked ενώ στην πραγματικότητα είναι unlocked για να περάσει ισχυρότερους ελέγχους ακεραιότητας (σε ορισμένα περιβάλλοντα μπορεί ακόμα να απαιτούνται vbmeta/AVB adjustments)

Limitation: Τα τρέχοντα PoCs σημειώνουν ότι οι runtime memory modifications μπορεί να προκαλέσουν fault λόγω περιορισμών του MMU; τα payloads γενικά αποφεύγουν live memory writes έως ότου αυτό επιλυθεί.

## Payload staging patterns (EL3)

Fenrir χωρίζει την instrumentation του σε τρία compile-time στάδια: το stage1 τρέχει πριν το `platform_init()`, το stage2 τρέχει πριν το LK σηματοδοτήσει fastboot entry, και το stage3 εκτελείται αμέσως πριν το LK φορτώσει Linux. Κάθε device header κάτω από `payload/devices/` παρέχει τις διευθύνσεις για αυτά τα hooks καθώς και τα fastboot helper symbols, οπότε κρατήστε αυτά τα offsets συγχρονισμένα με το target build σας.

Stage2 είναι ένα βολικό σημείο για να καταχωρήσετε αυθαίρετα `fastboot oem` verbs:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 δείχνει πώς να αναστρέψεις προσωρινά τα page-table attributes για να κάνεις patch immutable strings όπως την προειδοποίηση “Orange State” του Android χωρίς να χρειάζεται πρόσβαση στο downstream kernel:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Because stage1 fires prior to platform bring-up, it is the right place to call into OEM power/reset primitives or to insert additional integrity logging before the verified boot chain is torn down.

## Συμβουλές μεταφοράς

- Reverse engineer το device-specific bl2_ext για να εντοπίσετε τη verification policy logic (π.χ., sec_get_vfy_policy).
- Εντοπίστε το policy return site ή το decision branch και κάντε patch ώστε να “no verification required” (return 0 / unconditional allow).
- Διατηρήστε τα offsets πλήρως device- και firmware-specific· μην επαναχρησιμοποιείτε διευθύνσεις μεταξύ παραλλαγών.
- Επικυρώστε πρώτα σε μια θυσιαστική μονάδα. Προετοιμάστε σχέδιο ανάκτησης (π.χ., EDL/BootROM loader/SoC-specific download mode) πριν κάνετε flash.
- Συσκευές που χρησιμοποιούν τον lk2 secondary bootloader ή αναφέρουν “img_auth_required = 0” για το bl2_ext ακόμα και όταν είναι locked, θα πρέπει να θεωρούνται ευάλωτες παραλλαγές αυτής της κλάσης σφαλμάτων· έχει ήδη παρατηρηθεί ότι το Vivo X80 Pro παρακάμπτει την επαλήθευση παρά την αναφερόμενη κατάσταση κλειδώματος.
- Συγκρίνετε τα expdb logs από την κατάσταση locked και unlocked — αν ο χρόνος του πιστοποιητικού αυξάνει από 0 ms σε μη μηδενική τιμή όταν ξανακλειδώνετε, πιθανότατα κάνατε patch το σωστό decision point αλλά χρειάζεται να ενισχύσετε το lock-state spoofing για να αποκρύψετε την τροποποίηση.

## Επιπτώσεις στην ασφάλεια

- Εκτέλεση κώδικα EL3 μετά τον Preloader και πλήρης κατάρρευση του chain-of-trust για το υπόλοιπο μονοπάτι εκκίνησης.
- Ικανότητα εκκίνησης unsigned TEE/GZ/LK/Kernel, παρακάμπτοντας τις προσδοκίες secure/verified boot και επιτρέποντας επίμονη παραβίαση.

## Σημειώσεις συσκευής

- Επιβεβαιωμένη υποστήριξη: Nothing Phone (2a) (Pacman)
- Γνωστό ότι λειτουργεί (ατελής υποστήριξη): CMF Phone 1 (Tetris)
- Παρατηρήθηκε: Αναφέρθηκε ότι το Vivo X80 Pro δεν επαλήθευε το bl2_ext ακόμη και όταν ήταν locked
- Η κάλυψη του κλάδου επισημαίνει πρόσθετους vendors βασισμένους σε lk2 που στέλνουν το ίδιο λογικό σφάλμα, οπότε αναμένετε περαιτέρω επικάλυψη στις κυκλοφορίες MTK 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
