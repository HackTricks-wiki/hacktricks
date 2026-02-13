# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Περίληψη

"Carbonara" εκμεταλλεύεται τη διαδρομή λήψης XFlash της MediaTek για να εκτελέσει ένα τροποποιημένο Download Agent stage 2 (DA2) παρά τους ελέγχους ακεραιότητας του DA1. Το DA1 αποθηκεύει το αναμενόμενο SHA-256 του DA2 στη RAM και το συγκρίνει πριν από το branching. Σε πολλούς loaders, ο host ελέγχει πλήρως τη load address/size του DA2, δίνοντας μια unchecked memory write που μπορεί να overwrite αυτό το in-memory hash και να redirect την εκτέλεση σε αυθαίρετα payloads (pre-OS context με cache invalidation χειριζόμενο από το DA).

## Όριο εμπιστοσύνης στο XFlash (DA1 → DA2)

- **DA1** υπογράφεται/φορτώνεται από το BootROM/Preloader. Όταν το Download Agent Authorization (DAA) είναι ενεργοποιημένο, μόνο signed DA1 πρέπει να τρέχει.
- **DA2** αποστέλλεται μέσω USB. Το DA1 λαμβάνει **size**, **load address**, και **SHA-256** και κάνει hash στο ληφθέν DA2, συγκρίνοντάς το με ένα **expected hash embedded in DA1** (αντιγραμμένο στη RAM).
- **Weakness:** Σε unpatched loaders, το DA1 δεν sanitize την DA2 load address/size και διατηρεί το expected hash writable στη μνήμη, επιτρέποντας στον host να τροποποιήσει τον έλεγχο.

## Carbonara flow (το κόλπο "two BOOT_TO")

1. **First `BOOT_TO`:** Εισαγωγή στη ροή staging DA1→DA2 (το DA1 δεσμεύει και προετοιμάζει DRAM, και εκθέτει το buffer του expected-hash στη RAM).
2. **Hash-slot overwrite:** Στείλτε ένα μικρό payload που σαρώνει τη μνήμη του DA1 για το αποθηκευμένο DA2-expected hash και το overwrite με το SHA-256 του attacker-modified DA2. Αυτό εκμεταλλεύεται το user-controlled load για να τοποθετήσει το payload εκεί όπου βρίσκεται το hash.
3. **Second `BOOT_TO` + digest:** Trigger ένα ακόμα `BOOT_TO` με τα patched DA2 metadata και στείλτε το raw 32-byte digest που ταιριάζει με το modified DA2. Το DA1 επαναϋπολογίζει SHA-256 πάνω στο ληφθέν DA2, το συγκρίνει με το τώρα-patched expected hash, και το jump επιτυγχάνει στον attacker code.

Επειδή το load address/size ελέγχεται από τον attacker, το ίδιο primitive μπορεί να γράψει οπουδήποτε στη μνήμη (όχι μόνο στο hash buffer), επιτρέποντας early-boot implants, secure-boot bypass helpers, ή κακόβουλα rootkits.

## Ελάχιστο πρότυπο PoC (mtkclient-style)
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
- `payload` αναπαράγει το paid-tool blob που patchάρει το expected-hash buffer μέσα στο DA1.
- `sha256(...).digest()` στέλνει raw bytes (όχι hex) ώστε το DA1 να συγκρίνει με το patched buffer.
- DA2 μπορεί να είναι οποιαδήποτε attacker-built image· η επιλογή του load address/size επιτρέπει αυθαίρετη τοποθέτηση στη μνήμη, με την cache invalidation να χειρίζεται το DA.

## Σημειώσεις για triage και hardening

- Συσκευές όπου η διεύθυνση/μέγεθος του DA2 δεν ελέγχεται και το DA1 κρατά το expected hash εγγράψιμο είναι ευάλωτες. Εάν ένας μεταγενέστερος Preloader/DA επιβάλλει όρια διευθύνσεων ή διατηρεί το hash αμετάβλητο, το Carbonara μετριάζεται.
- Η ενεργοποίηση του DAA και η διασφάλιση ότι το DA1/Preloader επικυρώνουν τις παραμέτρους BOOT_TO (όρια + αυθεντικότητα του DA2) κλείνουν το primitive. Το να κλείσει μόνο το hash patch χωρίς να θεσπιστούν όρια φόρτωσης εξακολουθεί να αφήνει κίνδυνο αυθαίρετης εγγραφής.

## Αναφορές

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
