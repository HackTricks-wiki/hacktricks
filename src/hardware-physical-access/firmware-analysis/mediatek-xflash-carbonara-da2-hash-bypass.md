# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

Το "Carbonara" εκμεταλλεύεται τη διαδρομή λήψης XFlash της MediaTek για να τρέξει έναν τροποποιημένο Download Agent stage 2 (DA2) παρά τους ελέγχους ακεραιότητας του DA1. Ο DA1 αποθηκεύει το αναμενόμενο SHA-256 του DA2 στη RAM και το συγκρίνει πριν τη διακλάδωση. Σε πολλούς loaders, ο host ελέγχει πλήρως τη DA2 load address/size, δίνοντας μια ανεπαλήθευτη εγγραφή μνήμης που μπορεί να αντικαταστήσει αυτό το hash στη μνήμη και να ανακατευθύνει την εκτέλεση σε αυθαίρετα payloads (προ-OS context με invalidation της cache χειριζόμενο από τον DA).

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** is signed/loaded by BootROM/Preloader. When Download Agent Authorization (DAA) is enabled, only signed DA1 should run.
- **DA2** is sent over USB. DA1 receives **size**, **load address**, and **SHA-256** and hashes the received DA2, comparing it to an **expected hash embedded in DA1** (copied into RAM).
- **Weakness:** Σε μη ενημερωμένους loaders, ο DA1 δεν επικυρώνει τη DA2 load address/size και διατηρεί το expected hash εγγράψιμο στη μνήμη, επιτρέποντας στον host να αλλοιώσει τον έλεγχο.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Εισέρχεται στη ροή staging DA1→DA2 (ο DA1 δεσμεύει, προετοιμάζει DRAM και εκθέτει το expected-hash buffer στη RAM).
2. **Hash-slot overwrite:** Στέλνεται ένα μικρό payload που σαρώνει τη μνήμη του DA1 για το αποθηκευμένο DA2-expected hash και το αντικαθιστά με το SHA-256 του attacker-modified DA2. Αυτό εκμεταλλεύεται τη φόρτωση υπό έλεγχο του χρήστη για να τοποθετήσει το payload εκεί όπου βρίσκεται το hash.
3. **Second `BOOT_TO` + digest:** Ενεργοποιείται άλλο ένα `BOOT_TO` με τα patched DA2 metadata και στέλνεται το raw 32-byte digest που ταιριάζει με τον τροποποιημένο DA2. Ο DA1 επανυπολογίζει SHA-256 πάνω στο ληφθέν DA2, το συγκρίνει με το πλέον τροποποιημένο expected hash, και το άλμα πετυχαίνει στον κώδικα του attacker.

Επειδή η load address/size ελέγχονται από τον attacker, το ίδιο primitive μπορεί να γράψει οπουδήποτε στη μνήμη (όχι μόνο στο hash buffer), επιτρέποντας early-boot implants, βοηθήματα bypass για secure-boot ή κακόβουλα rootkits.

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
- `payload` αναπαράγει το paid-tool blob που κάνει patch στο buffer του expected-hash μέσα στο DA1.
- `sha256(...).digest()` στέλνει raw bytes (όχι hex) ώστε το DA1 να συγκρίνει με τον patched buffer.
- DA2 μπορεί να είναι οποιαδήποτε εικόνα που δημιούργησε ο επιτιθέμενος· η επιλογή της διεύθυνσης/του μεγέθους φόρτωσης επιτρέπει αυθαίρετη τοποθέτηση στη μνήμη με την εκκαθάριση της cache να διαχειρίζεται ο DA.

## Patch landscape (hardened loaders)

- **Αντιμετώπιση**: Ενημερωμένα DAs κάνουν hardcode τη διεύθυνση φόρτωσης του DA2 σε `0x40000000` και αγνοούν τη διεύθυνση που παρέχει ο host, οπότε οι εγγραφές δεν μπορούν να φτάσουν στο hash slot του DA1 (~περιοχή 0x200000). Το hash εξακολουθεί να υπολογίζεται αλλά δεν είναι πλέον εγγράψιμο από επιτιθέμενο.
- **Εντοπισμός patched DAs**: mtkclient/penumbra σκανάρουν το DA1 για μοτίβα που υποδεικνύουν address-hardening· αν βρεθεί, το Carbonara παραλείπεται. Τα παλιά DAs εκθέτουν εγγράψιμα hash slots (συνήθως γύρω από offsets όπως `0x22dea4` στο V5 DA1) και παραμένουν εκμεταλλεύσιμα.
- **V5 vs V6**: Κάποιοι V6 (XML) loaders εξακολουθούν να δέχονται διευθύνσεις που παρέχει ο χρήστης· τα νεότερα V6 binaries συνήθως επιβάλλουν τη σταθερή διεύθυνση και είναι ανθεκτικά στο Carbonara εκτός αν γίνει downgrade.

## Μετά την Carbonara (heapb8) — σημείωση

MediaTek διόρθωσε το Carbonara· μια νεότερη ευπάθεια, **heapb8**, στοχεύει τον DA2 USB file download handler σε patched V6 loaders, παρέχοντας εκτέλεση κώδικα ακόμα και όταν το `boot_to` είναι σκληρυμένο. Εκμεταλλεύεται ένα heap overflow κατά τη διάρκεια chunked file transfers για να καταλάβει τη ροή ελέγχου του DA2. Το exploit είναι δημόσιο στο Penumbra/mtk-payloads και δείχνει ότι οι διορθώσεις του Carbonara δεν κλείνουν όλη την επιφάνεια επίθεσης των DA.

## Σημειώσεις για αξιολόγηση και σκληροποίηση

- Συσκευές όπου η διεύθυνση/το μέγεθος του DA2 δεν ελέγχονται και το DA1 διατηρεί το expected hash εγγράψιμο είναι ευάλωτες. Εάν ένας μεταγενέστερος Preloader/DA επιβάλει όρια διευθύνσεων ή διατηρεί το hash αμετάβλητο, το Carbonara μετριάζεται.
- Η ενεργοποίηση του DAA και η διασφάλιση ότι το DA1/Preloader επικυρώνουν τις παραμέτρους BOOT_TO (όρια + αυθεντικότητα του DA2) κλείνει το primitive. Το να κλείσετε μόνο το patch του hash χωρίς να περιορίσετε τη φόρτωση αφήνει ακόμη κίνδυνο αυθαίρετων εγγραφών.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
