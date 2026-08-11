# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Περίληψη

Το "Carbonara" καταχράται τη διαδρομή λήψης XFlash του MediaTek για να εκτελέσει ένα τροποποιημένο στάδιο 2 του Download Agent (DA2), παρά τους ελέγχους ακεραιότητας του DA1. Το DA1 αποθηκεύει το αναμενόμενο SHA-256 του DA2 στη RAM και το συγκρίνει πριν από τη μετάβαση. Σε πολλούς loaders, το host ελέγχει πλήρως τη διεύθυνση/το μέγεθος φόρτωσης του DA2, παρέχοντας μια μη ελεγμένη εγγραφή μνήμης που μπορεί να αντικαταστήσει αυτό το hash στη μνήμη και να ανακατευθύνει την εκτέλεση σε αυθαίρετα payloads (σε περιβάλλον pre-OS, με τον χειρισμό του cache invalidation από το DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Όριο εμπιστοσύνης στο XFlash (DA1 → DA2)

- **Το DA1** υπογράφεται/φορτώνεται από το BootROM/Preloader. Όταν είναι ενεργοποιημένο το Download Agent Authorization (DAA), θα πρέπει να εκτελείται μόνο υπογεγραμμένο DA1.
- **Το DA2** αποστέλλεται μέσω USB. Το DA1 λαμβάνει το **μέγεθος**, τη **διεύθυνση φόρτωσης** και το **SHA-256**, υπολογίζει το hash του ληφθέντος DA2 και το συγκρίνει με ένα **αναμενόμενο hash ενσωματωμένο στο DA1** (το οποίο αντιγράφεται στη RAM).
- **Αδυναμία:** Σε μη patched loaders, το DA1 δεν επικυρώνει τη διεύθυνση/το μέγεθος φόρτωσης του DA2 και διατηρεί το αναμενόμενο hash εγγράψιμο στη μνήμη, επιτρέποντας στο host να παραποιήσει τον έλεγχο.<sup>[[1]](#references)[[2]](#references)</sup>

## Ροή Carbonara (κόλπο "two BOOT_TO")

1. **Πρώτο `BOOT_TO`:** Είσοδος στη ροή staging DA1→DA2 (το DA1 εκχωρεί μνήμη, προετοιμάζει τη DRAM και εκθέτει το buffer του αναμενόμενου hash στη RAM).
2. **Αντικατάσταση hash-slot:** Αποστολή ενός μικρού payload που σαρώνει τη μνήμη του DA1 για το αποθηκευμένο αναμενόμενο hash του DA2 και το αντικαθιστά με το SHA-256 του τροποποιημένου από τον attacker DA2. Αυτό αξιοποιεί το ελεγχόμενο από τον χρήστη load, ώστε να τοποθετήσει το payload στη θέση όπου βρίσκεται το hash.
3. **Δεύτερο `BOOT_TO` + digest:** Ενεργοποίηση ενός ακόμη `BOOT_TO` με τα patched metadata του DA2 και αποστολή του raw digest των 32 byte που αντιστοιχεί στο τροποποιημένο DA2. Το DA1 υπολογίζει ξανά το SHA-256 του ληφθέντος DA2, το συγκρίνει με το πλέον patched αναμενόμενο hash και η μετάβαση καταλήγει σε κώδικα του attacker.

Σε loaders που επηρεάζονται, η μη ελεγμένη διεύθυνση και το μέγεθος μπορούν να παρέχουν στον attacker ένα pre-OS primitive εγγραφής μνήμης, επιλεγμένο από τον ίδιο, πέρα από το hash slot. Ανάλογα με το memory map του SoC και τα μεταγενέστερα στάδια verification, αυτό μπορεί να υποστηρίξει early-boot implants, helpers για secure-boot-bypass ή payloads τύπου rootkit. Η εκτέλεση κώδικα DA από μόνη της δεν παρέχει αυτόματα persistence ή πλήρες secure-boot bypass· εξακολουθεί να απαιτείται ξεχωριστός μηχανισμός persistence και συμβατή αλυσίδα verification.<sup>[[1]](#references)[[2]](#references)</sup>

## Μοτίβο Minimal PoC (τύπου mtkclient)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- Το 16-byte `payload` αναπαράγει το blob που παρατηρήθηκε στο paid-tool workflow και χρησιμοποιήθηκε από τη δημοσιευμένη υλοποίηση για την τροποποίηση του buffer του αναμενόμενου hash. Είναι loader-specific και όχι portable patch για hash slot σε κάθε SoC ή DA.<sup>[[1]](#references)[[2]](#references)</sup>
- Το `sha256(...).digest()` στέλνει raw bytes (όχι hex), ώστε το DA1 να συγκρίνει με τον τροποποιημένο buffer.
- Σε έναν ευάλωτο loader που ταιριάζει, το DA2 μπορεί να είναι image κατασκευασμένο από τον attacker και τα επιλεγμένα load metadata ελέγχουν τη θέση του στη μνήμη. Επικυρώστε τον συνδυασμό DA/SoC πριν από τη μετάδοση, επειδή εσφαλμένες διευθύνσεις μπορούν να προκαλέσουν hang ή ζημιά στο target.<sup>[[3]](#references)</sup>

## Τοπίο των patch (hardened loaders)

- **Παρατηρούμενο mitigation**: Τα hardened DAs που εξέτασαν οι researchers επιβάλλουν τη διεύθυνση φόρτωσης του DA2 σε `0x40000000` και αγνοούν τη διεύθυνση που παρέχει το host, αποτρέποντας writes στην παρατηρημένη περιοχή hash του DA1 κοντά στη `0x200000`. Θεωρήστε και τις δύο διευθύνσεις implementation-specific και όχι architectural constants.
- **Εντοπισμός patched DAs**: Τα mtkclient/penumbra σαρώνουν το DA1 για patterns που υποδεικνύουν address-hardening· αν βρεθούν, το Carbonara παραλείπεται. Τα παλιά DAs εκθέτουν writable hash slots (συνήθως γύρω από offsets όπως το `0x22dea4` στο V5 DA1) και παραμένουν exploitable.
- **V5 έναντι V6**: Ορισμένοι V6 (XML) loaders εξακολουθούν να αποδέχονται user-supplied addresses· τα νεότερα V6 binaries συνήθως επιβάλλουν τη fixed address και είναι immune στο Carbonara, εκτός αν γίνει downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Σημείωση Post-Carbonara (heapb8)

Η MediaTek έκανε patch στο Carbonara· μια νεότερη ευπάθεια, το **heapb8**, στοχεύει τον DA2 USB file download handler σε patched V6 loaders, παρέχοντας code execution ακόμη και όταν το `boot_to` είναι hardened. Εκμεταλλεύεται ένα heap overflow κατά τις chunked file transfers για να καταλάβει τον έλεγχο της ροής εκτέλεσης του DA2. Το exploit είναι public στα Penumbra/mtk-payloads και δείχνει ότι τα fixes του Carbonara δεν κλείνουν ολόκληρη την attack surface των DA.<sup>[[4]](#references)</sup>

## Σημειώσεις για triage και hardening

- Οι συσκευές όπου η διεύθυνση/το μέγεθος του DA2 δεν ελέγχονται και το DA1 διατηρεί το expected hash writable είναι ευάλωτες. Αν ένα μεταγενέστερο Preloader/DA επιβάλλει address bounds ή διατηρεί το hash immutable, το Carbonara έχει γίνει mitigated.
- Η ενεργοποίηση του DAA και η διασφάλιση ότι τα DA1/Preloader επικυρώνουν τις παραμέτρους του BOOT_TO (bounds + authenticity του DA2) κλείνουν το primitive. Το κλείσιμο μόνο του hash patch χωρίς bounding του load εξακολουθεί να αφήνει κίνδυνο arbitrary write.

## References

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
