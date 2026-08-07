# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Σύνοψη

Το "Carbonara" καταχράται τη διαδρομή λήψης του MediaTek XFlash για να εκτελέσει ένα τροποποιημένο στάδιο 2 του Download Agent (DA2), παρά τους ελέγχους ακεραιότητας του DA1. Το DA1 αποθηκεύει στη RAM το αναμενόμενο SHA-256 του DA2 και το συγκρίνει πριν από τη διακλάδωση. Σε πολλούς loaders, ο host ελέγχει πλήρως τη διεύθυνση/το μέγεθος φόρτωσης του DA2, παρέχοντας μια μη ελεγμένη εγγραφή μνήμης που μπορεί να αντικαταστήσει αυτό το hash στη μνήμη και να ανακατευθύνει την εκτέλεση σε αυθαίρετα payloads (context πριν από το OS, με την invalidation της cache να διαχειρίζεται το DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary στο XFlash (DA1 → DA2)

- **DA1** υπογράφεται/φορτώνεται από το BootROM/Preloader. Όταν είναι ενεργοποιημένο το Download Agent Authorization (DAA), θα πρέπει να εκτελείται μόνο υπογεγραμμένο DA1.
- **DA2** αποστέλλεται μέσω USB. Το DA1 λαμβάνει το **size**, τη **load address** και το **SHA-256**, υπολογίζει το hash του ληφθέντος DA2 και το συγκρίνει με ένα **expected hash ενσωματωμένο στο DA1** (το οποίο αντιγράφεται στη RAM).
- **Αδυναμία:** Σε μη patched loaders, το DA1 δεν επικυρώνει τη load address/το size του DA2 και διατηρεί το expected hash εγγράψιμο στη μνήμη, επιτρέποντας στον host να παραποιήσει τον έλεγχο.<sup>[[1]](#references)[[2]](#references)</sup>

## Ροή Carbonara (το trick των "δύο BOOT_TO")

1. **Πρώτο `BOOT_TO`:** Είσοδος στη ροή staging DA1→DA2 (το DA1 δεσμεύει μνήμη, προετοιμάζει τη DRAM και εκθέτει το expected-hash buffer στη RAM).
2. **Αντικατάσταση hash-slot:** Αποστολή ενός μικρού payload που κάνει scan στη μνήμη του DA1 για το αποθηκευμένο expected hash του DA2 και το αντικαθιστά με το SHA-256 του τροποποιημένου από τον attacker DA2. Αυτό αξιοποιεί τη load που ελέγχεται από τον χρήστη, ώστε το payload να τοποθετηθεί εκεί όπου βρίσκεται το hash.
3. **Δεύτερο `BOOT_TO` + digest:** Ενεργοποίηση ενός ακόμη `BOOT_TO` με τα patched metadata του DA2 και αποστολή του raw digest των 32 byte που αντιστοιχεί στο τροποποιημένο DA2. Το DA1 υπολογίζει ξανά το SHA-256 του ληφθέντος DA2, το συγκρίνει με το πλέον patched expected hash και το jump ολοκληρώνεται προς τον κώδικα του attacker.

Επειδή η load address/το size ελέγχονται από τον attacker, το ίδιο primitive μπορεί να γράψει οπουδήποτε στη μνήμη (όχι μόνο στο hash buffer), επιτρέποντας early-boot implants, helpers για secure-boot bypass ή κακόβουλα rootkits.<sup>[[1]](#references)[[2]](#references)</sup>

## Minimal PoC pattern (mtkclient-style)
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
- `payload` αναπαράγει το blob του paid-tool που κάνει patch στο buffer του expected-hash μέσα στο DA1.
- Το `sha256(...).digest()` στέλνει raw bytes (όχι hex), ώστε το DA1 να συγκρίνει με το buffer που έχει υποστεί patch.
- Το DA2 μπορεί να είναι οποιοδήποτε image κατασκευασμένο από τον attacker· η επιλογή της load address/size επιτρέπει αυθαίρετη τοποθέτηση στη μνήμη, με το cache invalidation να αναλαμβάνεται από το DA.<sup>[[3]](#references)</sup>

## Τοπίο των patch (hardened loaders)

- **Mitigation**: Τα ενημερωμένα DAs κάνουν hardcode τη load address του DA2 σε `0x40000000` και αγνοούν τη διεύθυνση που παρέχει ο host, επομένως οι εγγραφές δεν μπορούν να φτάσουν στο hash slot του DA1 (περίπου στην περιοχή `0x200000`). Το hash εξακολουθεί να υπολογίζεται, αλλά δεν μπορεί πλέον να τροποποιηθεί από τον attacker.
- **Εντοπισμός patched DAs**: Τα mtkclient/penumbra σαρώνουν το DA1 για patterns που υποδεικνύουν address-hardening· αν τα εντοπίσουν, το Carbonara παρακάμπτεται. Τα παλαιότερα DAs εκθέτουν writable hash slots (συνήθως σε offsets όπως το `0x22dea4` στο V5 DA1) και παραμένουν exploitable.
- **V5 έναντι V6**: Ορισμένοι V6 (XML) loaders εξακολουθούν να δέχονται διευθύνσεις που παρέχονται από τον user· τα νεότερα V6 binaries συνήθως επιβάλλουν τη fixed address και δεν είναι ευάλωτα στο Carbonara, εκτός αν γίνει downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Σημείωση μετά το Carbonara (heapb8)

Η MediaTek έκανε patch στο Carbonara· μια νεότερη ευπάθεια, το **heapb8**, στοχεύει τον DA2 USB file download handler σε patched V6 loaders, παρέχοντας code execution ακόμη και όταν το `boot_to` είναι hardened. Εκμεταλλεύεται ένα heap overflow κατά τη διάρκεια chunked file transfers για να αποκτήσει τον έλεγχο του control flow του DA2. Το exploit είναι public στο Penumbra/mtk-payloads και δείχνει ότι τα fixes του Carbonara δεν κλείνουν ολόκληρη την attack surface του DA.<sup>[[4]](#references)</sup>

## Σημειώσεις για triage και hardening

- Οι συσκευές στις οποίες η address/size του DA2 δεν ελέγχεται και το DA1 διατηρεί writable το expected hash είναι ευάλωτες. Αν ένα μεταγενέστερο Preloader/DA επιβάλλει address bounds ή διατηρεί το hash immutable, το Carbonara αντιμετωπίζεται.
- Η ενεργοποίηση του DAA και η διασφάλιση ότι το DA1/Preloader επικυρώνει τις παραμέτρους του BOOT_TO (bounds + authenticity του DA2) κλείνουν το primitive. Το κλείσιμο μόνο του hash patch, χωρίς περιορισμό του load, εξακολουθεί να αφήνει κίνδυνο αυθαίρετων εγγραφών.

## Αναφορές

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
