# Ροή ελέγχου μέσω εξαιρέσεων στα Windows και anti-debugging

{{#include ../banners/hacktricks-training.md}}

Ένα προστατευμένο πρόγραμμα Windows μπορεί να χρησιμοποιεί μια σκόπιμη εξαίρεση ως κλάδο: η εντολή που προκαλεί το σφάλμα είναι απλώς η είσοδος σε έναν handler που επιλέγει την επόμενη διεύθυνση κώδικα χρήστη. Έτσι, οι ακμές κρύβονται από τη γραμμική αποσυναρμολόγηση και το επόμενο βήμα μεταφέρεται στη διαδικασία dispatch των εξαιρέσεων.<sup>[[1]](#references)</sup>

## Σημασία του dispatch

Ένας debugger που είναι συνδεδεμένος στη διεργασία λαμβάνει μια εξαίρεση **first-chance** πριν από τους application handlers. Αν την αφήσει ως μη διαχειρισμένη, τα Windows αναζητούν τους handlers της διεργασίας· μια εξαίρεση χωρίς handler επιστρέφει στον debugger ως **last-chance**. Επομένως, ένας debugger που καταναλώνει ένα συμβάν breakpoint ή single-step μπορεί να αλλάξει το αν θα εκτελεστεί ο handler του προγράμματος.<sup>[[2]](#references)</sup>

Η `AddVectoredExceptionHandler(1, handler)` καταχωρίζει ένα VEH για ολόκληρη τη διεργασία, στην αρχή της λίστας vectored handlers. Εκτελείται πριν από το frame-based SEH, αλλά μια μεταγενέστερη καταχώριση με πρώτη προτεραιότητα μπορεί να τοποθετήσει άλλον handler πριν από αυτόν. Η επιστροφή `EXCEPTION_CONTINUE_SEARCH` αφήνει την εξαίρεση για άλλους handlers· η επιστροφή `EXCEPTION_CONTINUE_EXECUTION` συνεχίζει την εκτέλεση από το αποθηκευμένο `CONTEXT`, συμπεριλαμβανομένων τυχόν αλλαγών στους καταχωρητές που έκανε ο handler.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Το κλασικό x86 SEH χρησιμοποιεί καταχωρίσεις συνδεδεμένες στη στοίβα, τις οποίες μπορεί να επιθεωρήσει η `!exchain`. Το native x64 χρησιμοποιεί εγγραφές `RUNTIME_FUNCTION` στο `.pdata` με unwind data στο `.xdata`, όχι αυτή την αλυσίδα x86. Μην εφαρμόζετε τη [ροή εργασίας παράκαμψης x86 SEH](../binary-exploitation/stack-overflow/windows-seh-overflow.md) σε native x64 διεργασία.<sup>[[5]](#references)[[6]](#references)</sup>

## Μετατροπή ενός σφάλματος σε ακμή ροής ελέγχου

Για παράδειγμα, ένας μηδενικός διαιρέτης μπορεί να προκαλέσει σκόπιμα την `EXCEPTION_INT_DIVIDE_BY_ZERO`, αντί να αποτελεί σφάλμα. Ο handler πρέπει να αναγνωρίσει την εξαίρεση και τη διεύθυνση όπου προκλήθηκε το σφάλμα και, στη συνέχεια, να ορίσει το `ContextRecord->Rip` (ή το `Eip` σε x86) σε μια έγκυρη συνέχεια πριν επιστρέψει `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Ο πυρήνας του handler παρακάτω υποθέτει ότι τα `fault_site` και `continuation` είναι γνωστές διευθύνσεις στο ίδιο context ροής ελέγχου. Μια πραγματική υλοποίηση πρέπει να διατηρεί το αναμενόμενο stack και τους καταχωρητές και δεν πρέπει να συνεχίζει από την ίδια εντολή που προκάλεσε το fault, διαφορετικά θα προκληθεί ξανά fault.<sup>[[7]](#references)</sup>

```c
if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO &&
    e->ExceptionRecord->ExceptionAddress == fault_site) {
#ifdef _M_X64
    e->ContextRecord->Rip = (DWORD64)continuation;
#else
    e->ContextRecord->Eip = (DWORD)continuation;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
return EXCEPTION_CONTINUE_SEARCH;
```

Ο ίδιος μηχανισμός μπορεί να καταναλώσει ένα σκόπιμο `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) και να ανακατευθύνει την εκτέλεση. **Μην** αυξάνετε τυφλά το `Rip` για να «προσπεράσετε το breakpoint»: η αποθηκευμένη διεύθυνση και η απαιτούμενη προσαρμογή εξαρτώνται από το trap, την κωδικοποίηση της εντολής και τη συμπεριφορά του debugger. Συγκρίνετε το `ExceptionRecord->ExceptionAddress` με τον αποθηκευμένο δείκτη εντολής και κάντε disassemble τα bytes προτού επιλέξετε τη συνέχεια.<sup>[[8]](#references)</sup> Ο [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) είναι ξεχωριστό παράδειγμα hardware-breakpoint που αλλάζει την κατάσταση επιστροφής μιας κλήσης syscall του loader.

## Υλοποίηση σελίδων μέσω page faults

Ένα VEH μπορεί να μετατρέψει ένα page fault σε **lazy loader**, όχι απλώς σε άλμα. Δεσμεύστε ένα ιδιωτικό εύρος image με σελίδες που παραμένουν μη δεσμευμένες ή χρησιμοποιήστε guard σελίδες που έχουν γίνει map, όπου υποστηρίζεται. Πριν εκτελέσετε το image, καταχωρίστε τις θέσεις relocation και τα IAT thunks ανά σελίδα προορισμού. Σε ένα fault εντός αυτού του εύρους, ο handler δεσμεύει τη σελίδα στην οποία έγινε πρόσβαση ή την καθιστά εγγράψιμη, αντιγράφει τα bytes της ενότητάς της, εφαρμόζει τα relocations και τα imports της συγκεκριμένης σελίδας, ορίζει την τελική προστασία της και επιστρέφει `EXCEPTION_CONTINUE_EXECUTION`. Η αρχική εντολή εκτελείται ξανά· **μην** προχωρήσετε το `Rip`, όπως θα κάνατε σε έναν handler που προσπερνά το fault. Οι σελίδες στις οποίες δεν έγινε ποτέ πρόσβαση δεν χρειάζεται να περιέχουν το payload στη μνήμη.<sup>[[11]](#references)</sup>

Σε περίπτωση access violation, το `ExceptionRecord->ExceptionAddress` προσδιορίζει την **εντολή** που προκάλεσε το fault, ενώ το `ExceptionInformation[1]` προσδιορίζει τη διεύθυνση στην οποία έγινε πρόσβαση.<sup>[[10]](#references)</sup> Ελέγξτε τον κωδικό εξαίρεσης, τον αριθμό παραμέτρων και το εύρος της διεύθυνσης πρόσβασης προτού υλοποιήσετε μια σελίδα· διαφορετικά, ένα άσχετο fault μπορεί να εκληφθεί ως αίτημα του loader.<sup>[[10]](#references)[[11]](#references)</sup> Το `PAGE_GUARD` προκαλεί `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) κατά την πρώτη πρόσβαση και τα Windows διαγράφουν αυτόματα το bit guard, επομένως η επαναφορά του είναι ξεχωριστό βήμα και όχι συνεχές hook.<sup>[[12]](#references)</sup> Διατηρήστε το VEH και όλα τα metadata που χρειάζεται προσβάσιμα κατά τη διαχείριση της εξαίρεσης.<sup>[[11]](#references)</sup> Σε x64, τα δεδομένα unwind μπορεί να πρέπει να είναι διαθέσιμα πριν από το πρώτο fault· ο loader που αναφέρεται υλοποιεί τις σελίδες εκ των προτέρων, πριν καλέσει το `DllMain`, για να αποφύγει race conditions κατά την αρχικοποίηση.<sup>[[11]](#references)</sup> Κάντε flush την instruction cache αφού γράψετε κώδικα και πριν τον εκτελέσετε.<sup>[[13]](#references)</sup>

Για να ανακτήσετε αυτή τη ροή κατά το reversing, ορίστε breakpoint σε guard-page violations και access violations πρώτης ευκαιρίας, εξετάστε το exception record και έπειτα προωθήστε το συμβάν στον handler της εφαρμογής με `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Χρησιμοποιήστε το `!vprot` στη διεύθυνση πρόσβασης για να εξετάσετε την τρέχουσα προστασία της σελίδας της.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Αφού ο handler υλοποιήσει τη σελίδα, κάντε dump των bytes της και συγκρίνετέ τα με την εικόνα του αρχείου.<sup>[[11]](#references)</sup> Ένα `!vprot` μετά το fault δεν μπορεί να αποδείξει ότι η σελίδα ήταν guarded προηγουμένως, επειδή η κατάσταση guard είναι one-shot.<sup>[[11]](#references)[[12]](#references)</sup> Περιορίστε τα exception filters ή τα breakpoints του handler μόλις γίνει γνωστό το σχετικό εύρος της εικόνας, ώστε να αποφύγετε άσχετα faults.<sup>[[16]](#references)</sup> Δείτε το [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) για τη ρύθμιση των filters.<sup>[[16]](#references)</sup>

## Το Trap Flag ως gate που εξαρτάται από τον debugger

Το bit `0x100` στο `EFLAGS`/`RFLAGS` είναι το Trap Flag (TF). Η ενεργοποίησή του προκαλεί την εμφάνιση του `STATUS_SINGLE_STEP` (`0x80000004`) στο επόμενο όριο εντολής. Ένας κλάδος VEH ή SEH μπορεί να διακρίνει ένα συμβάν single-step που μεταβιβάζεται στην εφαρμογή από ένα συμβάν που καταναλώνεται από debugger, αλλά πρόκειται για **ευρετική μέθοδο που ελέγχεται από την πολιτική εξαιρέσεων του debugger** και όχι για αξιόπιστη απόδειξη ότι υπάρχει debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Αν ο handler θέλει μόνο ένα βήμα, κάντε clear το `0x100` στο `EFlags` του context που θα συνεχίσει, πριν συνεχίσετε. Επίσης, διακρίνετε τα βήματα που προκαλούνται από το TF από τα συμβάντα hardware-breakpoint, ελέγχοντας τη διεύθυνση που προκάλεσε το συμβάν και την κατάσταση debug· και τα δύο μπορεί να εμφανιστούν ως `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Για τις ρυθμίσεις first-/second-chance των `sxe`, `sxd` και `sxi` του WinDbg, δείτε [Αυτοματοποίηση εξαιρέσεων στο WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Εξαιρέσεις](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Χειρισμός εξαιρέσεων από debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Χειρισμός εξαιρέσεων μέσω vectored](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Χειρισμός εξαιρέσεων x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Χρήση ενός Vectored Exception Handler](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Οδηγίες assembly](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Αρχιτεκτονική x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Φόρτωση image μέσω fault](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Δημιουργία Guard Pages](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Εμφάνιση εγγραφής εξαίρεσης)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - Φίλτρα εξαιρέσεων sx](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Συνέχιση όταν η εξαίρεση δεν έχει αντιμετωπιστεί)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
