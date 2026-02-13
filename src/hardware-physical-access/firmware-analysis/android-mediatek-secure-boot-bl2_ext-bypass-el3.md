# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει μια πρακτική παράκαμψη του secure-boot σε πολλαπλές πλατφόρμες MediaTek εκμεταλλευόμενη ένα κενό επαλήθευσης όταν η ρύθμιση του bootloader (seccfg) είναι "unlocked". Το σφάλμα επιτρέπει την εκτέλεση ενός τροποποιημένου bl2_ext σε ARM EL3 για να απενεργοποιήσει την επαλήθευση υπογραφών στα επόμενα στάδια, καταρρίπτοντας την αλυσίδα εμπιστοσύνης και επιτρέποντας το φόρτωμα αυθαίρετων μη υπογραφόμενων TEE/GZ/LK/Kernel.

Προειδοποίηση: Η πρωιμόβια (early-boot) τροποποίηση μπορεί να μπλοκάρει μόνιμα συσκευές αν οι offset είναι λάθος. Κρατήστε πάντα πλήρη dumps και μια αξιόπιστη διαδρομή ανάκτησης.

## Affected boot flow (MediaTek)

- Κανονική διαδρομή: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ευάλωτη διαδρομή: Όταν το seccfg είναι "unlocked", ο Preloader μπορεί να παραλείψει την επαλήθευση του bl2_ext. Ο Preloader εξακολουθεί να κάνει jump στο bl2_ext σε EL3, οπότε ένα χειροποίητο bl2_ext μπορεί μετά να φορτώσει μη επαληθευμένα components.

Κρίσιμο όριο εμπιστοσύνης:
- Το bl2_ext εκτελείται σε EL3 και είναι υπεύθυνο για την επαλήθευση του TEE, GenieZone, LK/AEE και του kernel. Αν το bl2_ext δεν είναι αυθεντικοποιημένο, το υπόλοιπο της αλυσίδας παρακάμπτεται εύκολα.

## Root cause

Σε επηρεαζόμενες συσκευές, ο Preloader δεν επιβάλλει την αυθεντικοποίηση του partition bl2_ext όταν το seccfg δείχνει κατάσταση "unlocked". Αυτό επιτρέπει το flashing ενός bl2_ext υπό τον έλεγχο του επιτιθέμενου που τρέχει σε EL3.

Μέσα στο bl2_ext, η συνάρτηση πολιτικής επαλήθευσης μπορεί να τροποποιηθεί ώστε να επιστρέφει ανεπιφύλακτα ότι η επαλήθευση δεν απαιτείται (ή πάντα πετυχαίνει), αναγκάζοντας την αλυσίδα εκκίνησης να αποδεχτεί μη υπογραφόμενες εικόνες TEE/GZ/LK/Kernel. Επειδή αυτή η τροποποίηση τρέχει σε EL3, είναι αποτελεσματική ακόμη και αν τα κατώτερα components έχουν τους δικούς τους ελέγχους.

## Practical exploit chain

1. Αποκτήστε τα partitions του bootloader (Preloader, bl2_ext, LK/AEE, κ.λπ.) μέσω OTA/firmware packages, EDL/DA readback, ή hardware dumping.
2. Εντοπίστε τη ρουτίνα επαλήθευσης στο bl2_ext και τροποποιήστε την ώστε να παραλείπει/αποδέχεται πάντα την επαλήθευση.
3. Flash-άρετε το τροποποιημένο bl2_ext χρησιμοποιώντας fastboot, DA, ή παρόμοια maintenance κανάλια που επιτρέπονται σε unlocked συσκευές.
4. Επανεκκινήστε· ο Preloader κάνει jump στο patched bl2_ext σε EL3 το οποίο στη συνέχεια φορτώνει μη υπογεγραμμένες εικόνες downstream (τροποποιημένο TEE/GZ/LK/Kernel) και απενεργοποιεί την επιβολή υπογραφής.

Αν η συσκευή είναι ρυθμισμένη ως locked (seccfg locked), ο Preloader αναμένεται να επαληθεύει το bl2_ext. Σε αυτή τη διαμόρφωση, αυτή η επίθεση θα αποτύχει εκτός αν υπάρχει άλλο σφάλμα που επιτρέπει το φόρτωμα ενός μη υπογεγραμμένου bl2_ext.

## Triage (expdb boot logs)

- Dump τα boot/expdb logs γύρω από το φόρτωμα του bl2_ext. Αν `img_auth_required = 0` και ο χρόνος επαλήθευσης πιστοποιητικού είναι ~0 ms, η επαλήθευση πιθανότατα παραλείπεται.

Παράδειγμα απόσπασμα log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Ορισμένες συσκευές παρακάμπτουν τον έλεγχο bl2_ext ακόμα και όταν είναι κλειδωμένες· οι διαδρομές δευτερεύοντος bootloader lk2 έχουν εμφανίσει το ίδιο κενό. Εάν ένας post-OTA Preloader καταγράφει `img_auth_required = 1` για bl2_ext ενώ είναι ξεκλείδωτο, η επιβολή πιθανότατα αποκαταστάθηκε.

## Verification logic locations

- Ο σχετικός έλεγχος συνήθως βρίσκεται μέσα στην εικόνα bl2_ext σε συναρτήσεις με ονόματα παρόμοια με `verify_img` ή `sec_img_auth`.
- Η patched έκδοση αναγκάζει τη συνάρτηση να επιστρέψει επιτυχία ή να παρακάμψει εντελώς την κλήση επαλήθευσης.

Example patch approach (conceptual):
- Εντοπίστε τη συνάρτηση που καλεί `sec_img_auth` σε εικόνες TEE, GZ, LK και kernel.
- Αντικαταστήστε το σώμα της με ένα stub που επιστρέφει αμέσως επιτυχία, ή overwrite το conditional branch που χειρίζεται την αποτυχία επαλήθευσης.

Βεβαιωθείτε ότι το patch διατηρεί τη ρύθμιση στοίβας/πλαισίου και επιστρέφει τους αναμενόμενους κωδικούς κατάστασης στους καλούντες.

## Fenrir PoC workflow (Nothing/CMF)

Το Fenrir είναι ένα reference patching toolkit για αυτό το ζήτημα (Nothing Phone (2a) fully supported; CMF Phone 1 partially). Σε υψηλό επίπεδο:
- Τοποθετήστε την εικόνα bootloader της συσκευής ως `bin/<device>.bin`.
- Build μια patched image που απενεργοποιεί την πολιτική επαλήθευσης bl2_ext.
- Flash το προκύπτον payload (fastboot helper provided).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Χρησιμοποίησε άλλο κανάλι flashing αν το fastboot δεν είναι διαθέσιμο.

## Σημειώσεις για EL3 patching

- bl2_ext εκτελείται σε ARM EL3. Σφάλματα εδώ μπορούν να brickάρουν τη συσκευή μέχρι να επαναπρογραμματιστεί μέσω EDL/DA ή test points.
- Χρησιμοποίησε board-specific logging/UART για να επικυρώσεις τη διαδρομή εκτέλεσης και να διαγνώσεις crashes.
- Διατήρησε αντίγραφα ασφαλείας όλων των partitions που τροποποιούνται και δοκίμασε πρώτα σε disposable hardware.

## Επιπτώσεις

- Εκτέλεση κώδικα σε EL3 μετά τον Preloader και πλήρης κατάρρευση της αλυσίδας εμπιστοσύνης για την υπόλοιπη πορεία εκκίνησης.
- Δυνατότητα εκκίνησης unsigned TEE/GZ/LK/Kernel, παρακάμπτοντας τις απαιτήσεις secure/verified boot και επιτρέποντας επίμονη παραβίαση.

## Σημειώσεις συσκευής

- Επιβεβαιωμένα υποστηριζόμενο: Nothing Phone (2a) (Pacman)
- Γνωστό ότι λειτουργεί (μερική υποστήριξη): CMF Phone 1 (Tetris)
- Παρατηρήθηκε: Vivo X80 Pro αναφέρθηκε ότι δεν επαλήθευε το bl2_ext ακόμα και όταν ήταν locked
- Το NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) επανενεργοποίησε την επαλήθευση του bl2_ext· το fenrir `pacman-v2.0` αποκαθιστά το bypass αναμειγνύοντας τον beta Preloader με ένα patched LK
- Αναφορές του κλάδου επισημαίνουν επιπλέον lk2-based vendors που αποστέλλουν το ίδιο λογικό σφάλμα, οπότε αναμένεται μεγαλύτερη επικάλυψη στις MTK εκδόσεις 2024–2025.

## MTK DA readback and seccfg manipulation with Penumbra

Το Penumbra είναι ένα Rust crate/CLI/TUI που αυτοματοποιεί την αλληλεπίδραση με τον MTK preloader/bootrom μέσω USB για DA-mode operations. Με φυσική πρόσβαση σε ένα ευάλωτο handset (DA extensions επιτρεπτά), μπορεί να εντοπίσει τη MTK USB θύρα, να φορτώσει ένα Download Agent (DA) blob, και να εκδώσει προνομιούχες εντολές όπως seccfg lock flipping και partition readback.

- **Environment/driver setup**: Σε Linux εγκατάστησε `libudev`, πρόσθεσε τον χρήστη στην ομάδα `dialout`, και δημιούργησε udev κανόνες ή τρέξε με `sudo` αν ο κόμβος συσκευής δεν είναι προσβάσιμος. Η υποστήριξη σε Windows είναι αναξιόπιστη· μερικές φορές λειτουργεί μόνο αφού αντικαταστήσεις τον MTK driver με WinUSB χρησιμοποιώντας το Zadig (σύμφωνα με τις οδηγίες του project).
- **Workflow**: Διάβασε ένα DA payload (π.χ. `std::fs::read("../DA_penangf.bin")`), κάνε poll για τη θύρα MTK με `find_mtk_port()`, και δημιούργησε μια session με `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Αφού το `init()` ολοκληρώσει το handshake και συλλέξει πληροφορίες συσκευής, έλεγξε τις προστασίες μέσω των bitfields του `dev_info.target_config()` (bit 0 set → SBC enabled). Μπες σε DA mode και προσπάθησε `set_seccfg_lock_state(LockFlag::Unlock)`—αυτό πετυχαίνει μόνο αν η συσκευή δέχεται extensions. Τα partitions μπορούν να εξαχθούν με `read_partition("lk_a", &mut progress_cb, &mut writer)` για offline analysis ή patching.
- **Security impact**: Η επιτυχής απεμπλοκή του seccfg ξανανοίγει διαδρομές flashing για unsigned boot images, επιτρέποντας επίμονες παραβιάσεις όπως το EL3 patching του bl2_ext που περιγράφηκε παραπάνω. Το partition readback παρέχει firmware artifacts για reverse engineering και δημιουργία τροποποιημένων images.

<details>
<summary>Rust DA συνεδρία + seccfg unlock + partition dump (Penumbra)</summary>
```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
let da = std::fs::read("../DA_penangf.bin")?;
let mtk_port = loop {
if let Some(port) = find_mtk_port().await {
break port;
}
};

let mut dev = DeviceBuilder::default()
.with_mtk_port(mtk_port)
.with_da_data(da)
.build()?;

dev.init().await?;
let cfg = dev.dev_info.target_config().await;
println!("SBC: {}", (cfg & 0x1) != 0);

dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

let mut progress = |_read: usize, _total: usize| {};
let mut writer = BufWriter::new(File::create("lk_a.bin")?);
dev.read_partition("lk_a", &mut progress, &mut writer).await?;
writer.flush().await?;
Ok(())
}
```
</details>

## Αναφορές

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC exploit που κυκλοφόρησε για ευπάθεια εκτέλεσης κώδικα στο Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 κυκλοφορία (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC παραβιάζει το secure boot στο Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – εργαλεία MTK DA flash/readback & seccfg](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
