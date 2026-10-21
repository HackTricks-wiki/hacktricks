# Ροή ελέγχου Windows καθοδηγούμενη από εξαιρέσεις και Anti-Debugging

{{#include ../banners/hacktricks-training.md}}

Ένα προστατευμένο πρόγραμμα Windows μπορεί να χρησιμοποιήσει μια σκόπιμη εξαίρεση ως διακλάδωση: η εντολή που προκαλεί το σφάλμα είναι απλώς η είσοδος σε έναν handler που επιλέγει την επόμενη διεύθυνση κώδικα χρήστη. Αυτό αποκρύπτει ακμές από τη γραμμική αποσυναρμολόγηση και μεταφέρει το επόμενο βήμα στη διαδικασία διαχείρισης εξαιρέσεων.<sup>[[1]](#references)</sup>

## Η διαδικασία διαχείρισης εξαιρέσεων έχει σημασία

Ένας debugger που είναι συνδεδεμένος στη διεργασία λαμβάνει μια εξαίρεση **first-chance** πριν από τους handlers της εφαρμογής. Αν την παραδώσει ως μη διαχειρισμένη, τα Windows αναζητούν τους handlers της διεργασίας· μια εξαίρεση χωρίς handler επιστρέφει στον debugger ως **last-chance**. Επομένως, ένας debugger που καταναλώνει ένα συμβάν breakpoint ή single-step μπορεί να αλλάξει το αν θα εκτελεστεί ο handler του προγράμματος.<sup>[[2]](#references)</sup>

Η `AddVectoredExceptionHandler(1, handler)` καταχωρίζει έναν VEH σε επίπεδο διεργασίας στην αρχή της λίστας vectored handlers. Εκτελείται πριν από το frame-based SEH, αλλά μια μεταγενέστερη καταχώριση με πρώτη προτεραιότητα μπορεί να τοποθετήσει άλλον handler πριν από αυτόν. Η επιστροφή `EXCEPTION_CONTINUE_SEARCH` αφήνει την εξαίρεση στους υπόλοιπους handlers· η επιστροφή `EXCEPTION_CONTINUE_EXECUTION` συνεχίζει από το αποθηκευμένο `CONTEXT`, συμπεριλαμβανομένων τυχόν αλλαγών στους καταχωρητές που έκανε ο handler.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

Το κλασικό x86 SEH χρησιμοποιεί καταχωρίσεις συνδεδεμένες μέσω της στοίβας, τις οποίες μπορεί να επιθεωρήσει η εντολή `!exchain`. Το native x64 χρησιμοποιεί καταχωρίσεις `RUNTIME_FUNCTION` στο `.pdata` με unwind data στο `.xdata` και όχι αυτή την αλυσίδα x86. Μην εφαρμόζετε τη [διαδικασία overwrite x86 SEH](../binary-exploitation/stack-overflow/windows-seh-overflow.md) σε μια native x64 διεργασία.<sup>[[5]](#references)[[6]](#references)</sup>

## Μετατρέψτε ένα σφάλμα σε ακμή ροής ελέγχου

Για παράδειγμα, ένας διαιρέτης μηδέν μπορεί σκόπιμα να προκαλέσει `EXCEPTION_INT_DIVIDE_BY_ZERO` αντί να υποδηλώνει σφάλμα. Ο handler πρέπει να αναγνωρίσει την εξαίρεση και τη διεύθυνση του σφάλματος και, στη συνέχεια, να ορίσει το `ContextRecord->Rip` (ή το `Eip` σε x86) σε μια έγκυρη διεύθυνση συνέχειας πριν επιστρέψει `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

Ο πυρήνας του handler παρακάτω υποθέτει ότι τα `fault_site` και `continuation` είναι γνωστές διευθύνσεις στο ίδιο πλαίσιο control-flow. Μια πραγματική υλοποίηση πρέπει να διατηρεί τα αναμενόμενα stack και registers και να μην συνεχίζει από την ίδια εντολή που προκάλεσε το fault, διαφορετικά θα προκληθεί ξανά fault.<sup>[[7]](#references)</sup>

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

Ο ίδιος μηχανισμός μπορεί να καταναλώσει ένα σκόπιμο `INT3`/`__debugbreak()` (`EXCEPTION_BREAKPOINT`) και να ανακατευθύνει την εκτέλεση. Μην αυξάνετε **τυφλά** το `Rip` για να «παραλείψετε το breakpoint»: η αποθηκευμένη διεύθυνση και η απαιτούμενη προσαρμογή εξαρτώνται από το trap, την κωδικοποίηση της εντολής και τη συμπεριφορά του debugger. Συγκρίνετε το `ExceptionRecord->ExceptionAddress` με τον αποθηκευμένο δείκτη εντολών και κάντε disassemble τα bytes πριν επιλέξετε τη συνέχεια.<sup>[[8]](#references)</sup> Ο [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) είναι ένα ξεχωριστό παράδειγμα hardware-breakpoint που αλλάζει την κατάσταση επιστροφής μιας κλήσης συστήματος του loader.

## Το Trap Flag ως πύλη που εξαρτάται από τον debugger

Το bit `0x100` στο `EFLAGS`/`RFLAGS` είναι το Trap Flag (TF). Η ενεργοποίησή του προκαλεί την εμφάνιση του `STATUS_SINGLE_STEP` (`0x80000004`) στο επόμενο όριο εντολής. Ένας κλάδος VEH ή SEH μπορεί να διακρίνει ένα συμβάν single-step που διαβιβάζεται στην εφαρμογή από ένα συμβάν που καταναλώνεται από debugger, αλλά αυτό αποτελεί **ευρετική που ελέγχεται από την πολιτική εξαιρέσεων του debugger** και όχι αξιόπιστη απόδειξη ότι υπάρχει debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Αν ο handler θέλει μόνο ένα βήμα, καθαρίστε το `0x100` στο `EFlags` του context που συνεχίζει την εκτέλεση. Επίσης, διακρίνετε τα βήματα που προκαλούνται από το TF από τα συμβάντα hardware-breakpoint, ελέγχοντας τη διεύθυνση που προκάλεσε το συμβάν και την κατάσταση αποσφαλμάτωσης· και τα δύο μπορούν να εμφανιστούν ως `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Για τις ρυθμίσεις first-/second-chance των `sxe`, `sxd` και `sxi` του WinDbg, ανατρέξτε στην ενότητα [Αυτοματοποίηση εξαιρέσεων στο WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Εξαιρέσεις](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Χειρισμός εξαιρέσεων από τον debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Χειρισμός εξαιρέσεων μέσω διανυσματικών χειριστών](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Χειρισμός εξαιρέσεων x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Χρήση διανυσματικού χειριστή εξαιρέσεων](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Οδηγίες assembly](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Αρχιτεκτονική x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
