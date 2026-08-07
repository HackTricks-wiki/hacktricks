# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Αυτή η σελίδα τεκμηριώνει ένα πρακτικό secure-boot break σε πολλαπλές πλατφόρμες MediaTek, εκμεταλλευόμενο ένα κενό επαλήθευσης όταν η διαμόρφωση bootloader της συσκευής (seccfg) είναι "unlocked". Το flaw επιτρέπει την εκτέλεση ενός patched bl2_ext στο ARM EL3, ώστε να απενεργοποιηθεί η downstream επαλήθευση υπογραφών, καταρρέοντας την αλυσίδα εμπιστοσύνης και επιτρέποντας τη φόρτωση αυθαίρετων unsigned TEE/GZ/LK/Kernel.<sup>[[1]](#references)</sup>

> Προσοχή: Το early-boot patching μπορεί να προκαλέσει μόνιμο brick στις συσκευές αν τα offsets είναι λανθασμένα. Διατηρείτε πάντα πλήρη dumps και μια αξιόπιστη διαδρομή recovery.

## Affected boot flow (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: Όταν το seccfg έχει οριστεί ως unlocked, ο Preloader ενδέχεται να παραλείψει την επαλήθευση του bl2_ext. Ο Preloader εξακολουθεί να μεταβαίνει στο bl2_ext στο EL3, επομένως ένα crafted bl2_ext μπορεί στη συνέχεια να φορτώσει μη επαληθευμένα components.

Βασικό trust boundary:
- Το bl2_ext εκτελείται στο EL3 και είναι υπεύθυνο για την επαλήθευση των TEE, GenieZone, LK/AEE και του kernel. Αν το ίδιο το bl2_ext δεν είναι authenticated, η υπόλοιπη αλυσίδα παρακάμπτεται trivially.<sup>[[1]](#references)</sup>

## Root cause

Σε affected συσκευές, ο Preloader δεν επιβάλλει την authentication του bl2_ext partition όταν το seccfg υποδεικνύει κατάσταση "unlocked". Αυτό επιτρέπει το flashing ενός attacker-controlled bl2_ext που εκτελείται στο EL3.

Μέσα στο bl2_ext, η verification policy function μπορεί να γίνει patched ώστε να αναφέρει unconditional ότι η επαλήθευση δεν απαιτείται (ή ότι επιτυγχάνει πάντα), εξαναγκάζοντας το boot chain να αποδέχεται unsigned TEE/GZ/LK/Kernel images. Επειδή αυτό το patch εκτελείται στο EL3, είναι effective ακόμη και αν τα downstream components υλοποιούν τους δικούς τους ελέγχους.<sup>[[1]](#references)</sup>

## Practical exploit chain

1. Αποκτήστε bootloader partitions (Preloader, bl2_ext, LK/AEE κ.λπ.) μέσω OTA/firmware packages, EDL/DA readback ή hardware dumping.
2. Εντοπίστε τη bl2_ext verification routine και κάντε patch ώστε να παραλείπει/αποδέχεται πάντα την επαλήθευση.
3. Κάντε flash το modified bl2_ext χρησιμοποιώντας fastboot, DA ή παρόμοια maintenance channels που εξακολουθούν να επιτρέπονται σε unlocked συσκευές.
4. Κάντε reboot· ο Preloader μεταβαίνει στο patched bl2_ext στο EL3, το οποίο στη συνέχεια φορτώνει unsigned downstream images (patched TEE/GZ/LK/Kernel) και απενεργοποιεί το signature enforcement.<sup>[[1]](#references)</sup>

Αν η συσκευή έχει διαμορφωθεί ως locked (seccfg locked), ο Preloader αναμένεται να επαληθεύσει το bl2_ext. Σε αυτή τη διαμόρφωση, το attack θα αποτύχει, εκτός αν κάποια άλλη vulnerability επιτρέπει τη φόρτωση ενός unsigned bl2_ext.

## Triage (expdb boot logs)

- Κάντε dump των boot/expdb logs γύρω από τη φόρτωση του bl2_ext. Αν το `img_auth_required = 0` και ο χρόνος certificate verification είναι περίπου 0 ms, η επαλήθευση πιθανότατα παρακάμπτεται.<sup>[[1]](#references)</sup>

Παράδειγμα αποσπάσματος log:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Σε ορισμένες συσκευές παραλείπεται το bl2_ext verification ακόμη και όταν είναι locked· οι διαδρομές του lk2 secondary bootloader έχουν παρουσιάσει το ίδιο κενό. Αν ένας Preloader μετά το OTA καταγράφει `img_auth_required = 1` για το bl2_ext ενώ η συσκευή είναι unlocked, πιθανότατα έχει αποκατασταθεί το enforcement.<sup>[[1]](#references)[[2]](#references)</sup>

## Τοποθεσίες verification logic

- Ο σχετικός έλεγχος βρίσκεται συνήθως μέσα στο image του bl2_ext, σε functions με ονόματα παρόμοια με `verify_img` ή `sec_img_auth`.
- Η patched έκδοση υποχρεώνει τη function να επιστρέφει success ή παρακάμπτει πλήρως το verification call.<sup>[[1]](#references)</sup>

Παράδειγμα προσέγγισης patch (εννοιολογικό):
- Εντοπίστε τη function που καλεί το `sec_img_auth` στα TEE, GZ, LK και kernel images.
- Αντικαταστήστε το body της με ένα stub που επιστρέφει αμέσως success ή αντικαταστήστε το conditional branch που χειρίζεται την αποτυχία του verification.

Βεβαιωθείτε ότι το patch διατηρεί τη ρύθμιση του stack/frame και επιστρέφει τους αναμενόμενους status codes στους callers.<sup>[[1]](#references)</sup>

## Fenrir PoC workflow (Nothing/CMF)

Το Fenrir είναι reference patching toolkit για αυτό το ζήτημα (το Nothing Phone (2a) υποστηρίζεται πλήρως, ενώ το CMF Phone 1 μερικώς).<sup>[[1]](#references)</sup> Σε υψηλό επίπεδο:
- Τοποθετήστε το bootloader image της συσκευής ως `bin/<device>.bin`.
- Δημιουργήστε ένα patched image που απενεργοποιεί την policy verification του bl2_ext.
- Κάντε flash το payload που προέκυψε (παρέχεται fastboot helper).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Χρησιμοποιήστε άλλο flashing channel αν το fastboot δεν είναι διαθέσιμο.

## Σημειώσεις για το EL3 patching

- Το bl2_ext εκτελείται στο ARM EL3. Τα crashes εδώ μπορούν να προκαλέσουν brick στη συσκευή μέχρι να γίνει εκ νέου flash μέσω EDL/DA ή test points.
- Χρησιμοποιήστε logging/UART ειδικά για την πλακέτα, για να επικυρώσετε τη διαδρομή εκτέλεσης και να διαγνώσετε crashes.
- Διατηρείτε backups όλων των partitions που τροποποιούνται και δοκιμάστε πρώτα σε hardware που μπορεί να διατεθεί χωρίς συνέπειες.<sup>[[1]](#references)</sup>

## Επιπτώσεις

- Εκτέλεση κώδικα στο EL3 μετά το Preloader και πλήρης κατάρρευση της chain-of-trust για το υπόλοιπο boot path.
- Δυνατότητα εκκίνησης unsigned TEE/GZ/LK/Kernel, παρακάμπτοντας τις προσδοκίες του secure/verified boot και επιτρέποντας persistent compromise.<sup>[[1]](#references)</sup>

## Σημειώσεις συσκευών

- Επιβεβαιωμένη υποστήριξη: Nothing Phone (2a) (Pacman)
- Γνωστό ότι λειτουργεί (μη πλήρης υποστήριξη): CMF Phone 1 (Tetris)
- Παρατηρήθηκε: Το Vivo X80 Pro φέρεται να μην επαλήθευε το bl2_ext ακόμη και όταν ήταν locked<sup>[[1]](#references)</sup>
- Το NothingOS 4 stable (BP2A.250605.031.A3, Νοέμβριος 2025) ενεργοποίησε ξανά την επαλήθευση του bl2_ext· το fenrir `pacman-v2.0` επαναφέρει το bypass συνδυάζοντας το beta Preloader με ένα patched LK<sup>[[3]](#references)</sup>
- Η κάλυψη από τον κλάδο επισημαίνει επιπλέον vendors που βασίζονται στο lk2 και διαθέτουν την ίδια λογική αδυναμία, επομένως αναμένεται περαιτέρω επικάλυψη μεταξύ των MTK releases του 2024–2025.<sup>[[2]](#references)[[4]](#references)</sup>

## MTK DA readback και seccfg manipulation με το Penumbra

Το Penumbra είναι ένα Rust crate/CLI/TUI που αυτοματοποιεί την αλληλεπίδραση με το MTK preloader/bootrom μέσω USB για λειτουργίες DA-mode. Με φυσική πρόσβαση σε ένα ευάλωτο handset (όπου επιτρέπονται DA extensions), μπορεί να εντοπίσει τη θύρα MTK USB, να φορτώσει ένα Download Agent (DA) blob και να εκτελέσει privileged commands, όπως αλλαγή της κατάστασης lock του seccfg και readback partitions.<sup>[[5]](#references)</sup>

- **Ρύθμιση περιβάλλοντος/driver**: Σε Linux εγκαταστήστε το `libudev`, προσθέστε τον χρήστη στην ομάδα `dialout` και δημιουργήστε udev rules ή εκτελέστε με `sudo` αν το device node δεν είναι προσβάσιμο. Η υποστήριξη Windows είναι unreliable· μερικές φορές λειτουργεί μόνο αφού αντικατασταθεί ο MTK driver με WinUSB μέσω του Zadig (σύμφωνα με τις οδηγίες του project).
- **Workflow**: Διαβάστε ένα DA payload (π.χ. `std::fs::read("../DA_penangf.bin")`), κάντε polling για τη θύρα MTK με `find_mtk_port()` και δημιουργήστε ένα session χρησιμοποιώντας `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Αφού η `init()` ολοκληρώσει το handshake και συγκεντρώσει πληροφορίες συσκευής, ελέγξτε τις protections μέσω των bitfields του `dev_info.target_config()` (το bit 0 είναι set → SBC enabled). Εισέλθετε σε DA mode και δοκιμάστε `set_seccfg_lock_state(LockFlag::Unlock)`—αυτό επιτυγχάνει μόνο αν η συσκευή αποδέχεται extensions. Τα partitions μπορούν να γίνουν dump με `read_partition("lk_a", &mut progress_cb, &mut writer)` για offline analysis ή patching.
- **Security impact**: Το επιτυχές seccfg unlocking ανοίγει ξανά flashing paths για unsigned boot images, επιτρέποντας persistent compromises όπως το bl2_ext EL3 patching που περιγράφηκε παραπάνω. Το partition readback παρέχει firmware artifacts για reverse engineering και δημιουργία modified images.

<details>
<summary>Rust DA session + seccfg unlock + partition dump (Penumbra)</summary>
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

## Παραπομπές

- [1] [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Κυκλοφόρησε PoC exploit για ευπάθεια Code Execution στο Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Κυκλοφορία Fenrir pacman-v2.0 (πακέτο bypass για NothingOS 4)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Το Fenrir PoC παρακάμπτει το secure boot στα Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
