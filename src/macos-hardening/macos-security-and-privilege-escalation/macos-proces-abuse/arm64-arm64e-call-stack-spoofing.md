# Spoofing στο Call-Stack ARM64/ARM64e

{{#include ../../../banners/hacktricks-training.md}}

## Γιατί μπορεί να πλαστογραφηθεί η αναδίπλωση στοίβας βάσει metadata

Ορισμένα εργαλεία ασφάλειας του macOS αναθέτουν τη συλλογή της στοίβας νημάτων στο `/usr/sbin/spindump` ή εμπιστεύονται με άλλον τρόπο έναν συμβατικό μηχανισμό αναδίπλωσης βάσει metadata. Ένα implant μπορεί να εκμεταλλευτεί αυτό το όριο εμπιστοσύνης, τοποθετώντας στη στοίβα του συνθετικές εγγραφές συμβατές με το ABI, ώστε να φαίνεται ότι η πρόσβαση σε ένα ευαίσθητο API έγινε μέσω συναρτήσεων που επέλεξε ο attacker στο dyld και σε φορτωμένα Apple frameworks, αντί για κώδικα implant χωρίς υποστήριξη. Πρόκειται για παραπλάνηση τηλεμετρίας, όχι για αλλαγή του εκτελέσιμου αρχείου ή των metadata αναδίπλωσής του.<sup>[[1]](#references)</sup>

Δείτε [stackshots του macOS και `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) για το πλαίσιο συλλογής.

Ένας μηχανισμός αναδίπλωσης δεν αποδεικνύει ότι μια εγγραφή δημιουργήθηκε από prologue που παρήγαγε ο compiler. Χρησιμοποιεί επανειλημμένα το τρέχον `PC` για να επιλέξει μια συνταγή Mach-O, εφαρμόζει αυτήν τη συνταγή στα `SP`, `x29`, `x30`, στη μνήμη της στοίβας και σε τυχόν δηλωμένους μη πτητικούς καταχωρητές, και χρησιμοποιεί το ανακτημένο `PC` του caller για να επιλέξει την επόμενη συνταγή. Αν η μνήμη που ελέγχει ο attacker ικανοποιεί κάθε επιλεγμένη συνταγή, η αλυσίδα που προκύπτει μπορεί να είναι δομικά έγκυρη και να αντιστοιχίζεται σε σύμβολα, παρόλο που αυτές οι κλήσεις δεν έγιναν ποτέ.<sup>[[1]](#references)</sup>

## Κατάσταση frame ARM64

Η [επισκόπηση assembly ARM64](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) καλύπτει τους ρόλους των καταχωρητών και τη σύμβαση κλήσης. Για ένα συμβατικό frame που δημιουργείται με `stp x29, x30, [sp, #-16]!` και στη συνέχεια `mov x29, sp`, η Κανονική Διεύθυνση Frame (CFA), η οποία αντιπροσωπεύει το `SP` του caller κατά την είσοδό του, είναι `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Οι εγγραφές frame σχηματίζουν συνδεδεμένη λίστα μέσω του `[FP]`, αλλά δεν αρκεί να ακολουθούμε τυφλά αυτή τη λίστα: οι leaf functions μπορεί να μην έχουν frame, τα tail calls μπορεί να παραλείπουν λογικές μεταβάσεις και οι ασυνήθιστες διατάξεις χρησιμοποιούν DWARF CFI. Η συνταγή που επιλέγεται από την τρέχουσα διεύθυνση καθορίζει αν ο unwinder θα διαβάσει καθόλου την αλυσίδα FP.<sup>[[1]](#references)[[4]](#references)</sup>

## Επιλογή συνταγής unwind Mach-O

Τα τελικά linked images αποθηκεύουν compact unwind δεδομένα στο `__TEXT,__unwind_info`. Η επικεφαλίδα του section δείχνει σε ένα first-level function index· κάθε περιοχή του index δείχνει σε μια second-level page κανονική (`kind=2`) ή συμπιεσμένη (`kind=3`). Για διατάξεις που δεν μπορούν να περιγραφούν από το compact unwind, χρησιμοποιούνται ένα FDE και οδηγίες call-frame στο `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Για κάθε υποψήφιο runtime PC:<sup>[[1]](#references)[[2]](#references)</sup>

1. Αφαιρέστε ή κανονικοποιήστε τα ARM64e PAC bits μόνο για την αναζήτηση.
2. Βρείτε το φορτωμένο Mach-O του οποίου η εκτελέσιμη περιοχή `__TEXT` περιέχει τη διεύθυνση.
3. Υπολογίστε `functionOffset = normalizedPC - loadedImageBase` και απορρίψτε αρνητικά αποτελέσματα ή τιμές μεγαλύτερες από `UINT32_MAX`.
4. Επιλέξτε την περιοχή first-level που ικανοποιεί τη συνθήκη `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Αναλύστε τη second-level page που αναφέρεται, επιλέξτε την πλησιέστερη εγγραφή της οποίας η αρχή δεν υπερβαίνει το offset και επαληθεύστε ότι η διεύθυνση είναι μικρότερη από την επόμενη εγγραφή ή το τέλος της περιοχής first-level.
6. Αποκωδικοποιήστε αυτή την εγγραφή και κατασκευάστε ακριβώς την κατάσταση που περιγράφει.

Όταν μια διεύθυνση προέρχεται από αποθηκευμένο LR, η αναζήτηση μπορεί να χρησιμοποιήσει το `PC-1`, ώστε μια διεύθυνση αμέσως μετά από μια κλήση να παραμένει εντός της περιοχής του caller. Αυτό αλλάζει την επιλογή συνταγής, όχι οποιοδήποτε stack offset.<sup>[[1]](#references)</sup>

Ένας parser πρέπει να ελέγχει τα όρια κάθε header και array, να απαιτεί section version `1`, να λαμβάνει υπόψη τον τελικό first-level sentinel, να απορρίπτει μηδενικό second-level-page offset και να διακρίνει τις κανονικές από τις συμπιεσμένες pages. Σε μια κανονική page, το `entryPageOffset` είναι σχετικό με την αρχή αυτής της page, ενώ το first-level page offset είναι σχετικό με την αρχή του `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

Η γενική λειτουργία είναι `encoding & 0x0F000000`. Οι τρέχοντες ορισμοί του LLVM περιλαμβάνουν τις εξής λειτουργίες· ένας parser δεν πρέπει να θεωρεί κάθε τιμή εκτός DWARF ως κλασικό frame:<sup>[[1]](#references)[[2]](#references)</sup>

| Λειτουργία | Τιμή | Ανάκτηση caller |
| --- | --- | --- |
| Χωρίς compact recipe | `0x00000000` | Διακοπή ή χρήση ανεξάρτητου fallback. |
| Χωρίς frame | `0x02000000` | Προσθήκη του κωδικοποιημένου μεγέθους stack στο τρέχον `SP`· το PC του caller είναι το live LR. |
| DWARF | `0x03000000` | Εκτέλεση του FDE/CFI που προσδιορίζεται από τα low 24 bits. |
| Frame | `0x04000000` | Ανάγνωση της συμβατικής εγγραφής frame `x29`. |
| arm64e frame με authenticated LR range | `0x05000000` | Χειρισμός του `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`· το πεδίο offset εντοπίζει το `pacibsppc` εντός της καλυπτόμενης περιοχής. |

Για τη λειτουργία frameless, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. Για τη λειτουργία frame, τα πέντε low bits δηλώνουν συνεχόμενα αποθηκευμένα ζεύγη GPR από `x19/x20` έως `x27/x28`· τα bits `0x100-0x800` δηλώνουν αντίστοιχα ζεύγη `d8-d15`. Αυτά τα αποθηκευμένα registers μπορεί να μην είναι απαραίτητα για να βρεθεί το επόμενο PC, αλλά μια πειστική εικονική κατάσταση caller πρέπει να ικανοποιεί κάθε πεδίο που ανακατασκευάζει ο consumer.<sup>[[1]](#references)[[2]](#references)</sup>

## Κατασκευή συνθετικών εγγραφών frame-mode

Η διαδικασία κατασκευής αντιστρέφει τη λειτουργία του unwinder, αντί να σαρώνει το stack για τιμές που μοιάζουν με διευθύνσεις:<sup>[[1]](#references)</sup>

1. Επιλέξτε ένα πραγματικό εκτελέσιμο PC σε ένα ήδη φορτωμένο image.
2. Αποκωδικοποιήστε τη συνταγή που καλύπτει αυτό το ακριβές PC ή τη διεύθυνση του call site.
3. Δεσμεύστε μια συνθετική εγγραφή με την απαιτούμενη ευθυγράμμιση και σχέση CFA.
4. Αποθηκεύστε το επόμενο συνθετικό FP στο `[FP]`, το αποθηκευμένο PC του caller αυτού του frame στο `[FP+8]` και κάθε save GPR/FPR που δηλώνεται από το encoding κάτω από το FP.
5. Συνδέστε πολλές εγγραφές και τοποθετήστε την πρώτη εγγραφή στο live `x29`.
6. Ρυθμίστε το live LR και τη διαδρομή επιστροφής του API έτσι ώστε το unwinding να εισέλθει στην επιλεγμένη αλυσίδα, ενώ η εκτέλεση να μπορεί να αποκατασταθεί με ασφάλεια.

Για παράδειγμα, το `0x04000001` σημαίνει λειτουργία frame συν το ζεύγος `x19/x20`. Η αντίστοιχη μεταβολή κατάστασης και η απαιτούμενη μνήμη είναι:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Επομένως, μια διεύθυνση που φαίνεται νόμιμη δεν αρκεί. Κάθε PC που ανακτάται γίνεται το κλειδί για την επόμενη αναζήτηση, οπότε μία μόνο διεύθυνση με κωδικοποίηση που δεν συμφωνεί με το πλαστό layout διακόπτει την αλυσίδα ή κάνει τον consumer να ανακατασκευάσει ασυνεπή κατάσταση καταχωρητών.<sup>[[1]](#references)</sup>

## Απαιτήσεις PAC για ARM64e

Το PAC αποθηκεύει μια keyed τιμή ακεραιότητας σε κατά τα άλλα μη χρησιμοποιούμενα bits του pointer· δεν κρυπτογραφεί τη διεύθυνση. Το schema return-address του Clang για arm64e χρησιμοποιεί το instruction key B και τον stack pointer κατά την είσοδο στη συνάρτηση ως discriminator. Για ένα συμβατικό frame, εκείνο το `SP` είναι το CFA, επομένως το αποθηκευμένο LR στο `[FP+8]` δεσμεύεται στο `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Κάθε synthetic LR πρέπει να υπογράφεται ανεξάρτητα, επειδή η μετακίνηση ενός ήδη υπογεγραμμένου LR σε frame με διαφορετικό CFA αλλάζει το discriminator και προκαλεί αποτυχία του authentication. Το `ptrauth_strip()` είναι κατάλληλο για κανονικοποίηση διευθύνσεων και αναζήτηση συμβόλων, αλλά **δεν** επιβεβαιώνει τη γνησιότητα· κάθε πραγματική επιστροφή ή authenticated έμμεσο branch πρέπει να χρησιμοποιεί το key και το modifier που αναμένονται στη συγκεκριμένη μετάβαση.<sup>[[1]](#references)[[3]](#references)</sup>

Μια τυπική συνάρτηση arm64e που δεν είναι leaf υπογράφει το LR πριν το αποθηκεύσει και το επαληθεύει μετά την επαναφορά του αρχικού SP:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline and restore bridge

Οι συνθετικές εγγραφές χρειάζεται μόνο να ικανοποιούν τον unwinder· δεν περιέχουν πλήρες execution context. Η επιστροφή από το ευαίσθητο API απευθείας στους κατασκευασμένους callers θα προκαλούσε συνήθως crash. Επομένως, η πρακτική σχεδίαση τοποθετεί ένα gadget frame ακριβώς κάτω από το API: το API επιστρέφει σε εκτελέσιμο κώδικα ενός φορτωμένου framework και αυτό το gadget κάνει branch μέσω ενός ελεγχόμενου callee-saved register προς ένα restore bridge στο implant.<sup>[[1]](#references)</sup>

Ένα χρήσιμο gadget διατηρεί το LR και μεταφέρει τον έλεγχο μέσω ενός ελεγχόμενου register, για παράδειγμα με κατάλληλη ακολουθία `br`, `braa` ή `brab`. Το restore bridge πρέπει να ανακτήσει τις αρχικές τιμές των `x19-x30` και του `SP` προτού συνεχιστεί η εκτέλεση του implant. Στο arm64e, κάθε authenticated return ή branch στη διαδρομή API-to-gadget, gadget-to-bridge και bridge-to-implant απαιτεί pointer υπογεγραμμένο για το key και το discriminator που χρησιμοποιεί αυτή η εντολή.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

Το αποτέλεσμα αποτελεί σημαντική αστοχία στα όρια εμπιστοσύνης για τις ανιχνεύσεις που βασίζονται στη στοίβα: μια αλυσίδα μπορεί να περιέχει μόνο PCs από αντιστοιχισμένα Apple frameworks, για τα οποία μπορούν να προσδιοριστούν σύμβολα, και παρ' όλα αυτά να μην αντιπροσωπεύει την πραγματική ροή ελέγχου. Επομένως, τα αποτελέσματα του unwind πρέπει να διασταυρώνονται με ανεξάρτητα στοιχεία σχετικά με την προέλευση της εκτελέσιμης μνήμης του thread και τις πραγματικές μεταβάσεις γύρω από το ευαίσθητο API, αντί να αντιμετωπίζονται ως ίχνος εκτέλεσης.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Εσωτερικά στοιχεία της στοίβας ARM64 και obfuscation σε Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Ορισμοί κωδικοποίησης compact unwind του Mach-O](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Pointer Authentication](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Πρότυπο κλήσεων διαδικασιών για την αρχιτεκτονική Arm 64-bit](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
