# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει μια πρακτική παραβίαση του secure-boot σε πολλαπλές πλατφόρμες MediaTek, αξιοποιώντας ένα κενό επαλήθευσης όταν η διαμόρφωση του bootloader της συσκευής (seccfg) είναι "unlocked". Το σφάλμα επιτρέπει την εκτέλεση ενός patched bl2_ext στο ARM EL3 για να απενεργοποιήσει την επαλήθευση υπογραφών στα downstream, καταρρίπτοντας την αλυσίδα εμπιστοσύνης και επιτρέποντας τη φόρτωση αυθαίρετων unsigned TEE/GZ/LK/Kernel.

> Προσοχή: Το early-boot patching μπορεί να κάνει τις συσκευές μη ανακτήσιμες (brick) μόνιμα αν τα offsets είναι λάθος. Πάντοτε κρατάτε full dumps και έναν αξιόπιστο τρόπο ανάκτησης.

## Επηρεασμένη ροή εκκίνησης (MediaTek)

- Κανονική διαδρομή: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ευάλωτη διαδρομή: Όταν το seccfg είναι σε κατάσταση unlocked, ο Preloader μπορεί να παραλείψει την επαλήθευση του bl2_ext. Ο Preloader εξακολουθεί να κάνει jump στο bl2_ext στο EL3, οπότε ένα crafted bl2_ext μπορεί να φορτώσει μη επαληθευμένα components στη συνέχεια.

Κρίσιμο όριο εμπιστοσύνης:
- Το bl2_ext εκτελείται στο EL3 και είναι υπεύθυνο για την επαλήθευση του TEE, GenieZone, LK/AEE και του kernel. Αν το bl2_ext αυτό καθαυτό δεν είναι authenticated, το υπόλοιπο της αλυσίδας παρακάμπτεται προφανώς.

## Βασική αιτία

Σε επηρεαζόμενες συσκευές, ο Preloader δεν επιβάλλει authentication του partition bl2_ext όταν το seccfg υποδεικνύει κατάσταση "unlocked". Αυτό επιτρέπει το flashing ενός attacker-controlled bl2_ext που εκτελείται στο EL3.

Μέσα στο bl2_ext, η συνάρτηση πολιτικής επαλήθευσης μπορεί να patched ώστε να επιστρέφει ανεπιφύλακτα ότι η επαλήθευση δεν απαιτείται. Μια ελάχιστη εννοιολογική τροποποίηση είναι:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Με αυτή την αλλαγή, όλες οι επακόλουθες images (TEE, GZ, LK/AEE, Kernel) γίνονται αποδεκτές χωρίς κρυπτογραφικούς ελέγχους όταν φορτώνονται από το patched bl2_ext που τρέχει στο EL3.

## Πώς να triage έναν στόχο (expdb logs)

Dump/inspect boot logs (π.χ., expdb) γύρω από τη φόρτωση του bl2_ext. Εάν img_auth_required = 0 και certificate verification time είναι ~0 ms, το enforcement πιθανότατα είναι off και η συσκευή είναι exploitable.

Παράδειγμα αποσπάσματος log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Σημείωση: Αναφέρεται ότι ορισμένες συσκευές παραλείπουν την επαλήθευση του bl2_ext ακόμη και με κλειδωμένο bootloader, γεγονός που επιδεινώνει τον αντίκτυπο.

Συσκευές που αποστέλλονται με τον δευτερεύοντα bootloader lk2 έχουν παρατηρηθεί να εμφανίζουν το ίδιο λογικό κενό, οπότε πάρτε expdb logs για τα bl2_ext και lk2 partitions για να επιβεβαιώσετε αν κάποια από τις διαδρομές εφαρμόζει signatures πριν επιχειρήσετε το porting.

Αν μετά από OTA ο Preloader καταγράφει τώρα img_auth_required = 1 για το bl2_ext ακόμη και ενώ το seccfg είναι unlocked, ο vendor πιθανότατα έκλεισε το κενό — δείτε τις OTA persistence notes παρακάτω.

## Πρακτική ροή εκμετάλλευσης (Fenrir PoC)

Το Fenrir είναι ένα reference exploit/patching toolkit για αυτή την κατηγορία προβλημάτων. Υποστηρίζει Nothing Phone (2a) (Pacman) και είναι γνωστό ότι λειτουργεί (εν μέρει υποστηριζόμενο) στο CMF Phone 1 (Tetris). Το porting σε άλλα μοντέλα απαιτεί reverse engineering του bl2_ext ειδικού για τη συσκευή.

High-level process:
- Προμηθευτείτε την εικόνα bootloader της συσκευής για τον target codename σας και τοποθετήστε την ως `bin/<device>.bin`
- Κατασκευάστε ένα patched image που απενεργοποιεί την bl2_ext verification policy
- Flash-άρετε το προκύπτον payload στη συσκευή (fastboot υποτίθεται από το helper script)

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

### Firmware με OTA patch: διατήρηση του bypass ενεργού (NothingOS 4, τέλη 2025)

Η Nothing έκανε patch τον Preloader στο σταθερό OTA του NothingOS 4 (Νοέμβριος 2025, build BP2A.250605.031.A3) ώστε να επιβάλει την επαλήθευση bl2_ext ακόμα και όταν το seccfg είναι ξεκλείδωτο. Το Fenrir `pacman-v2.0` λειτουργεί ξανά αναμειγνύοντας τον ευάλωτο Preloader από το NOS 4 beta με το σταθερό LK payload:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Important:
- Φλασάρετε τον παρεχόμενο Preloader **μόνο** στη matching device/slot; ένας λάθος preloader είναι instant hard brick.
- Ελέγξτε expdb μετά το flashing; img_auth_required should drop back to 0 για bl2_ext, επιβεβαιώνοντας ότι ο vulnerable Preloader εκτελείται πριν από το patched LK.
- Αν μελλοντικά OTAs patch τόσο τον Preloader όσο και το LK, κρατήστε τοπικό αντίγραφο ενός vulnerable Preloader για να επανεισάγετε το κενό.

### Build automation & payload debugging

- `build.sh` τώρα auto-downloads και export-άρει το Arm GNU Toolchain 14.2 (aarch64-none-elf) την πρώτη φορά που το τρέχετε, οπότε δεν χρειάζεται να διαχειρίζεστε χειροκίνητα cross-compilers.
- Export `DEBUG=1` πριν καλέσετε `build.sh` για να compile-άρετε payloads με verbose σειριακές εκτυπώσεις, κάτι που βοηθά σημαντικά όταν κάνετε blind-patching σε EL3 code paths.
- Επιτυχείς builds παράγουν τόσο το `lk.patched` όσο και το `<device>-fenrir.bin`; το δεύτερο έχει ήδη το payload injected και είναι αυτό που πρέπει να flash/boot-test.

## Runtime payload capabilities (EL3)

Ένα patched bl2_ext payload μπορεί:
- Να εγγράψει custom fastboot commands
- Να ελέγξει/override το boot mode
- Να καλέσει δυναμικά built‑in bootloader functions κατά το runtime
- Να spoof-άρει την “lock state” ως locked ενώ στην πραγματικότητα είναι unlocked, για να περάσει ισχυρότερους ελέγχους ακεραιότητας (ορισμένα περιβάλλοντα μπορεί ακόμα να απαιτούν vbmeta/AVB adjustments)

Limitation: Τα τρέχοντα PoCs αναφέρουν ότι runtime memory modification μπορεί να fault-άρει λόγω περιορισμών MMU; τα payloads γενικά αποφεύγουν live memory writes μέχρι να λυθεί αυτό.

## Payload staging patterns (EL3)

Fenrir χωρίζει την instrumentation του σε τρία compile-time stages: το stage1 τρέχει πριν το `platform_init()`, το stage2 τρέχει πριν το LK signals fastboot entry, και το stage3 εκτελείται αμέσως πριν το LK φορτώσει το Linux. Κάθε device header κάτω από `payload/devices/` παρέχει τις διευθύνσεις για αυτά τα hooks καθώς και fastboot helper symbols, οπότε κρατήστε αυτά τα offsets συγχρονισμένα με το target build.

Stage2 είναι μια βολική θέση για να εγγράψετε αυθαίρετα `fastboot oem` εντολές:
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
Το Stage3 δείχνει πώς να αντιστρέψεις προσωρινά τα χαρακτηριστικά του πίνακα σελίδων (page-table attributes) για να τροποποιήσεις αμετάβλητες συμβολοσειρές, όπως την προειδοποίηση του Android «Orange State», χωρίς να απαιτείται πρόσβαση στον downstream kernel:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Επειδή το stage1 εκτελείται πριν το platform bring-up, είναι το σωστό σημείο για να καλέσετε τα OEM power/reset primitives ή να εισάγετε επιπλέον logging ακεραιότητας πριν η αλυσίδα verified boot καταρρεύσει.

## Porting tips

- Reverse engineer το device-specific bl2_ext για να εντοπίσετε τη λογική της πολιτικής επαλήθευσης (π.χ., sec_get_vfy_policy).
- Εντοπίστε το policy return site ή τον decision branch και τροποποιήστε το σε “no verification required” (return 0 / unconditional allow).
- Κρατήστε τα offsets πλήρως εξαρτώμενα από τη συσκευή και το firmware· μην επαναχρησιμοποιείτε διευθύνσεις μεταξύ παραλλαγών.
- Validate πρώτα σε μια θυσιαστική μονάδα. Ετοιμάστε ένα recovery plan (π.χ., EDL/BootROM loader/SoC-specific download mode) πριν κάνετε flash.
- Συσκευές που χρησιμοποιούν τον lk2 secondary bootloader ή που αναφέρουν “img_auth_required = 0” για bl2_ext ακόμη και ενώ είναι locked πρέπει να θεωρούνται ευάλωτες εκδόσεις αυτής της κλάσης σφαλμάτων· το Vivo X80 Pro έχει ήδη παρατηρηθεί να παρακάμπτει την επαλήθευση παρά την αναφερόμενη κατάσταση κλειδώματος.
- Όταν ένα OTA αρχίσει να επιβάλλει bl2_ext signatures (img_auth_required = 1) στην ξεκλείδωτη κατάσταση, ελέγξτε αν ένας παλαιότερος Preloader (συχνά διαθέσιμος σε beta OTAs) μπορεί να φλασαριστεί για να ξανανοίξει το κενό, και στη συνέχεια επαντρέξτε fenrir με ενημερωμένα offsets για τον νεότερο LK.

## Security impact

- Εκτέλεση κώδικα σε EL3 μετά τον Preloader και πλήρης κατάρρευση της chain-of-trust για το υπόλοιπο της διαδρομής εκκίνησης.
- Ικανότητα εκκίνησης unsigned TEE/GZ/LK/Kernel, παράκαμψη των secure/verified boot προσδοκιών και δυνατότητα persistent compromise.

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by flashing the beta Preloader plus patched LK as shown above
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
