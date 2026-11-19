# Windows Process Injection μέσω Thread Names και Waiting Threads

{{#include ../banners/hacktricks-training.md}}

Το Thread Name-Calling (TNC) μεταφέρει bytes σε μια εκτελούμενη διεργασία χωρίς `WriteProcessMemory`, ενώ το Waiting Thread Hijacking (WTH) τα εκτελεί σε ένα υπάρχον thread χωρίς `SetThreadContext` ή δημιουργία remote thread.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Πρόκειται για **primitives process injection, όχι για ευπάθειες κλιμάκωσης προνομίων**: ο injector εξακολουθεί να χρειάζεται πρόσβαση στη διεργασία και στο thread-στόχο. Τα API περιγραφής thread απαιτούν Windows 10 έκδοση 1607 ή νεότερη.<sup>[[1]](#references)[[3]](#references)</sup> Δείτε το [Antivirus (AV) Bypass](av-bypass.md) για άλλες προσεγγίσεις injection και evasion.

## Thread Name-Calling: αντιγραφή payload στην πλευρά του στόχου

Το `NtSetInformationThread(ThreadNameInformation)` αντιγράφει ένα παρεχόμενο `UNICODE_STRING` στον χώρο αποθήκευσης του ονόματος του thread. Η κλήση του `GetThreadDescription` **μέσα στον στόχο** δημιουργεί κατόπιν ένα αντίγραφο αυτού του ονόματος στο user-mode heap. Έτσι, η μεταφορά του payload διαχωρίζεται από την τελική αντιγραφή στη μνήμη: ο injector μπορεί να διαβάσει τον **pointer** του heap που επιστρέφεται, ενώ ένα APC που εκτελεί το `RtlMoveMemory` μέσα στον στόχο αντιγράφει τα bytes στον προορισμό τους.<sup>[[1]](#references)</sup> Η αρχική τεχνική υποστηρίζει επίσης special user APCs· η υλοποίηση WhisperHijack χρησιμοποιεί αντίθετα το συνηθισμένο `NtQueueApcThread` σε ένα thread που βρίσκεται σε αναμονή.<sup>[[1]](#references)[[3]](#references)</sup>

Για κάθε chunk έως και `0xFFFE` bytes, το PoC χρησιμοποιεί την παρακάτω σειρά. Ένα duplicated auto-reset event σηματοδοτεί την ολοκλήρωση μόνο αφού ο στόχος συμπληρώσει το scratch slot· ο injector περιμένει αυτό το σήμα πριν διαβάσει τον pointer. Το event επιβεβαιώνει το APC που χειρίζεται τον heap pointer, όχι το επόμενο copy APC. Το PoC ειδοποιεί το ίδιο thread αφού τοποθετήσει στην ουρά το copy και βασίζεται στη σειρά εκτέλεσης των APC αντί για δεύτερο σήμα ολοκλήρωσης.<sup>[[3]](#references)[[4]](#references)</sup>

```text
NtSetInformationThread(ThreadNameInformation, chunk)
APC: RtlFillMemory(scratch, sizeof(void *), 0)
APC: GetThreadDescription(NtCurrentThread(), scratch)
APC: NtSetEvent(duplicated_event)
NtWaitForSingleObject(local_event); NtReadVirtualMemory(scratch, &heap_ptr, 8)
APC: RtlMoveMemory(destination + offset, heap_ptr, chunk_length)
NtAlertThread(thread)
```

Η scratch διεύθυνση πρέπει να είναι εγγράψιμη στον target και γνωστή στον injector χωρίς να χρειάζεται να προηγηθεί εγγραφή σε αυτήν. Το αρχικό PoC χρησιμοποιεί το `PEB.SpareUlongs`.<sup>[[1]](#references)</sup> Το WhisperHijack προσφέρει επίσης τα `PEB.PostProcessInitRoutine` και, ως προεπιλογή, το `TEB.TlsSlots[63]` (εντοπίζεται με το `NtQueryInformationThread(ThreadBasicInformation)`). Δεν είναι **εγγυημένο** ότι το TLS slot δεν χρησιμοποιείται σε κάθε target· η αντικατάσταση ενός ενεργού slot μπορεί να διαταράξει το συγκεκριμένο thread. Ενεργοποιήστε ακριβώς μία επιλογή στο `Main.c`. Οι έλεγχοι κατά τη μεταγλώττιση απορρίπτουν επιλογές PEB/TEB που λείπουν ή συγκρούονται.<sup>[[4]](#references)</sup>

Μια κανονική κλήση `RtlInitUnicodeString` θα σταματούσε σε ένα ενσωματωμένο ευρύ null. Για τη μεταφορά δυαδικών δεδομένων, αρχικοποιήστε το μήκος του `UNICODE_STRING` χρησιμοποιώντας ένα buffer padding ίδιου μεγέθους που δεν περιέχει null, αντικαταστήστε τα bytes του `Buffer` με το πραγματικό chunk και έπειτα περάστε το στο `NtSetInformationThread`. Αυτή η μεταφορά βάσει μήκους διαφέρει από την απευθείας μεταβίβαση του shellcode στο `SetThreadDescription` ως συμβολοσειράς που τερματίζεται με null.<sup>[[1]](#references)[[3]](#references)</sup>

## Waiting Thread Hijacking: επιστροφή από αναμονή σε ουρά

Απαριθμήστε τα threads με το `NtQuerySystemInformation(SystemProcessInformation)` και αναζητήστε `ThreadState == Waiting` με `WaitReason == WrQueue`. Ένα thread που είναι μπλοκαρισμένο σε έναν wrapper syscall, όπως το `NtWaitForWorkViaWorkerFactory`, έχει αποθηκευμένη τη διεύθυνση επιστροφής του καλούντος στο `[Rsp]`. Η αντικατάσταση αυτής της θέσης στη στοίβα ανακατευθύνει το `ret` του wrapper σε ένα stub, χωρίς να αλλάξει το `Rip` μέσω του `SetThreadContext`. Το stub πρέπει να αποθηκεύσει τα flags και τους καταχωρητές, να **καλέσει** ένα payload που επιστρέφει, να επαναφέρει την κατάσταση και έπειτα να κάνει jump μέσω της αποθηκευμένης αρχικής διεύθυνσης επιστροφής.<sup>[[2]](#references)[[3]](#references)</sup>

Στο x64 PoC, το stub έχει ένα slot αποθηκευμένης διεύθυνσης επιστροφής 8 byte στο `+0x00`, εντολές στο `+0x08` και το payload στο `+0x45`. Στη θέση της στοίβας γράφεται το `allocation_base + 0x08`, όχι η διεύθυνση του slot δεδομένων. Το `WrQueue` από μόνο του **δεν αποδεικνύει** αναμονή σε worker factory: η αρχική έρευνα αναγνωρίζει επίσης τα `NtRemoveIoCompletion`/`GetQueuedCompletionStatus` ως διαδρομή αναμονής σε ουρά. Ελέγξτε την πραγματική στοίβα αναμονής/κλήσεων και βεβαιωθείτε ότι το `[Rsp]` είναι η προβλεπόμενη θέση επιστροφής προτού βασιστείτε σε αυτή τη διάταξη.<sup>[[2]](#references)[[3]](#references)</sup>

## Συνδυασμός TNC και WTH χωρίς εγγραφές μεταξύ διεργασιών

Το WhisperHijack παρουσιάζει τη συνδυασμένη ροή εργασίας σε μια υπάρχουσα native x64 διεργασία. Το Writer επιλέγει μια υποψήφια διεργασία/thread, ενώ ένα child Flipper κληρονομεί τα handles που χρειάζονται για την τελική παράδοση. Το process handle ζητά `PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE`, **όχι** `PROCESS_VM_WRITE`· παρ' όλα αυτά, το τρέχον PoC ανοίγει το thread με `THREAD_ALL_ACCESS`. Εξακολουθούν να ισχύουν οι έλεγχοι πρόσβασης και τα process mitigations.<sup>[[3]](#references)[[4]](#references)</sup>

Το συνδυασμένο PoC χρησιμοποιεί την ακόλουθη ακολουθία· τα memory copy APCs εκτελούνται στον target και όχι μέσω handle με δικαιώματα απομακρυσμένης εγγραφής.<sup>[[4]](#references)</sup>

1. Δεσμεύστε στον target ελεύθερα blocks ευθυγραμμισμένα στα 64 KB και, στη συνέχεια, κάντε commit τις σελίδες των 4 KB ως `PAGE_READWRITE`. Το PoC ελέγχει σταθερές υποψήφιες διευθύνσεις με το `NtQueryVirtualMemory`· αυτές οι διευθύνσεις είναι επιλογές υλοποίησης, όχι απαίτηση των TNC ή WTH.
2. Συναρμολογήστε το `[stub WTH 0x45 byte][payload x64 που επιστρέφει][δείκτης εισόδου stub 8 byte]`, όπου ο τελικός δείκτης είναι `allocation_base + 0x08`. Παραδώστε αυτό το buffer με τον βρόχο chunk του TNC.
3. Στο Flipper, λάβετε το `Rsp` του thread που βρίσκεται σε αναμονή με το `NtGetContextThread(CONTEXT_CONTROL)`. Προγραμματίστε ένα APC `RtlMoveMemory` εντός του target, ώστε να αντιγράψει την αρχική τιμή 8 byte στο `[Rsp]` στο slot δεδομένων του stub.
4. Αλλάξτε την περιοχή που έχει προετοιμαστεί ώστε να είναι εκτελέσιμη με το `NtProtectVirtualMemory`. Αυτό το PoC επιλέγει `PAGE_EXECUTE_READWRITE` επειδή το polymorphic payload του κάνει self-decode· το WTH δεν απαιτεί από μόνο του payload που τροποποιεί τον εαυτό του.
5. Προγραμματίστε ένα ακόμη APC `RtlMoveMemory` εντός του target, ώστε να αντιγράψει τον **pointer ουράς που έχει προετοιμαστεί εκ των προτέρων** στο `[Rsp]`, και έπειτα καλέστε το `NtAlertThread`. Η FIFO σειρά των APCs αποθηκεύει την αρχική διεύθυνση επιστροφής πριν την αντικαταστήσει· η επιστροφή του wrapper εισέρχεται στο stub και, αφού επιστρέψει το payload, η εκτέλεση συνεχίζεται από τον αρχικό καλούντα.

Η απουσία του `NtWriteVirtualMemory` **δεν** σημαίνει ότι δεν γίνονται εγγραφές στον target: τα `GetThreadDescription` και `RtlMoveMemory` τις εκτελούν μέσα στον target.<sup>[[1]](#references)[[3]](#references)</sup> Η παράδοση συνηθισμένων user APC εξαρτάται επίσης από το αν το επιλεγμένο thread εξυπηρετεί την ουρά APC του· μια στιγμιαία κατάσταση `WrQueue` και μια ειδοποίηση δεν εγγυώνται γενικά άμεση εκτέλεση.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup> Το παράδειγμα αποφεύγει τη δημιουργία remote thread, την αναστολή και την άμεση αντικατάσταση του context, αλλά παραμένει ανιχνεύσιμο μέσω των APCs και της αλλαγής προστασίας.<sup>[[3]](#references)</sup>

## References

- [1] [Check Point Research – Κλήση μέσω ονόματος thread](https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/)
- [2] [Check Point Research – Παραβίαση thread σε αναμονή](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [3] [Maldev Academy – WhisperHijack PoC και README](https://github.com/Maldev-Academy/WhisperHijack)
- [4] [Maldev Academy – Υλοποίηση WhisperHijack Main.c](https://raw.githubusercontent.com/Maldev-Academy/WhisperHijack/main/WhisperHijack/Main.c)
