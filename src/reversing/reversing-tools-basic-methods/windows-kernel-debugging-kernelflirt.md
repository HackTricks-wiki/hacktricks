# Debugging του Windows Kernel με το KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

Το KernelFlirt είναι ένας debugger για Windows x64, σχεδιασμένος για ελεγχόμενα εργαστήρια reverse engineering. Ένα WPF UI στην πλευρά του host ή το `KfConsole.exe` στέλνει εντολές στο `KfRelay.exe` σε μια test-signed Windows VM. Το relay τις μεταφράζει σε αιτήματα `DeviceIoControl` προς το `KernelFlirt.sys`, το οποίο παρέχει λειτουργίες για μνήμη, registers, breakpoints, έλεγχο εκτέλεσης και modules του kernel. Ο driver τροποποιεί επίσης τη διαδρομή debugging του kernel με ένα inline hook `KdpStub`/`KdTrap`, γι’ αυτό χρησιμοποιήστε τον μόνο σε VM που προορίζεται για απόρριψη.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

Το relay αποτελεί ένα προνομιακό όριο αποσφαλμάτωσης και όχι μια συνηθισμένη απομακρυσμένη υπηρεσία. Διατηρήστε το TCP `31337` σε ένα απομονωμένο host-only δίκτυο και μην εκθέτετε ποτέ το test-signed driver ή το relay σε μη έμπιστο δίκτυο.<sup>[[1]](#references)</sup>

Σχετικές τεχνικές Windows exploitation:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Ρύθμιση lab και πρώτη στάση

Οι builds απαιτούν Windows 10/11 x64, Visual Studio 2022 με C++, WDK 10.0.26100.0 ή νεότερο και .NET 9. Φορτώστε τον driver και το relay μέσα στο VM και, στη συνέχεια, συνδεθείτε από το host. Το UI μπορεί να ανοίξει ένα απομακρυσμένο EXE ή SYS, ενώ η προβολή **Kernel Modules** μπορεί να ορίσει breakpoints σε ήδη φορτωμένους drivers.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Χρησιμοποιήστε το `KfLoader.exe unload` όταν ολοκληρωθεί το lab. Η κονσόλα υποστηρίζει μη συνδεδεμένο REPL, άμεση πρόσβαση σε τοπική συσκευή και πρόσβαση μέσω relay· μόνο η λειτουργία relay υλοποιεί την ντετερμινιστική ροή εργασίας `open` που περιγράφεται παρακάτω.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Μια ελάχιστη ροή εργασίας μέσω κονσόλας είναι:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Οι διευθύνσεις είναι εκφράσεις. Οι γυμνοί αριθμοί είναι δεκαεξαδικοί, ενώ οι εκφράσεις μπορούν να χρησιμοποιούν registers, αριθμητικές πράξεις, αποαναφορές όπως `[rsp]` και σύμβολα όπως `ntdll!NtCreateFile`. Τα symbol breakpoints πρέπει να προστίθενται μόνο αφού η εντολή `open` ή `attach` απαριθμήσει τα modules και φορτώσει τα PDB τους.<sup>[[2]](#references)</sup>

## Ντετερμινιστική παγίδευση στο σημείο εισόδου με `EB FE`

Η εντολή `open` στην πλευρά του relay δημιουργεί τη διεργασία-στόχο σε αναστολή, αποθηκεύει τα πρώτα bytes του entry point, γράφει `EB FE`, επαναφέρει το thread εισόδου σε εκτέλεση και ελέγχει επανειλημμένα μέχρι ο instruction pointer να φτάσει σε εκείνη τη διεύθυνση. Το `EB FE` είναι ένα άλμα δύο bytes πίσω στον εαυτό του, οπότε παγιδεύει την εκτέλεση χωρίς να βασίζεται στην παράδοση user-mode debug exception. Έπειτα, το relay επαναφέρει τα αρχικά bytes και αφήνει τη διεργασία-στόχο σταματημένη στο entry point της.<sup>[[2]](#references)</sup>

Αυτή η μέθοδος είναι επίσης χρήσιμη όταν πρέπει να παρατηρηθεί μια πρώιμη διαδρομή του loader, πριν ολοκληρωθεί η κανονική ρύθμιση του debugger.<sup>[[2]](#references)</sup>

1. Δημιούργησε τη διεργασία σε αναστολή και εντόπισε το πραγματικό entry point μετά το mapping της εικόνας.
2. Αποθήκευσε τα αρχικά bytes του entry point και αντικατάστησέ τα με τον βρόχο δύο bytes που μεταπηδά στον εαυτό του.
3. Επανέφερε το thread εισόδου σε εκτέλεση και έλεγχε επανειλημμένα τον instruction pointer μέχρι να φτάσει στη διεύθυνση με το patch.
4. Ανέστειλε τη διεργασία-στόχο και επανέφερε ακριβώς τα αρχικά bytes πριν συνεχιστεί η ανάλυση.

Η τεχνική είναι σκόπιμα παρεμβατική. Αν ο debugger ή το relay τερματιστεί πριν από την επαναφορά, η διεργασία-στόχος μπορεί να παραμείνει σε ατέρμονα βρόχο. Η τοπική λειτουργία του KernelFlirt δεν παρέχει patching entry point από την πλευρά του relay. Ξεκίνα τη διεργασία χειροκίνητα και χρησιμοποίησε την εντολή `attach <pid>`.<sup>[[2]](#references)</sup>

## Επιλογή primitive breakpoint

Το KernelFlirt παρέχει διάφορους μηχανισμούς breakpoint με διαφορετικές παρενέργειες. Οι παρακάτω εντολές επιτρέπουν στον αναλυτή να αλλάζει primitive όταν ο packed κώδικας αυτοτροποποιείται, οι εκτελέσιμες σελίδες είναι μόνο για ανάγνωση ή τα bytes των software breakpoint ελέγχονται ως προς την ακεραιότητά τους.<sup>[[1]](#references)[[2]](#references)</sup>

| Primitive | Εντολή | Μηχανισμός και χρήση |
| --- | --- | --- |
| Software | `bp <expr>` | `INT3` με υποστήριξη MDL· μπορεί να instrumentάρει σελίδες RX `.text` |
| Conditional software | `bp <expr> if <condition>` | Αξιολογείται σε κάθε hit και συνεχίζει σιωπηρά όταν η συνθήκη είναι false |
| Hardware execute | `ba e1 <expr>` | Χρησιμοποιεί ένα από τα DR0-DR3 χωρίς να αλλάζει τα bytes του κώδικα |
| Hardware data | `ba w4 <expr>` / `ba r8 <expr>` | Παρακολουθεί εγγραφές ή αναγνώσεις/εγγραφές 1, 2, 4 ή 8 bytes |
| Guard page | `bm <expr> [size]` | Χρησιμοποιεί `PAGE_GUARD` για breakpoint σε περιοχή μνήμης |
| Temporary | `g <expr>`, `p` ή `o` | Βοηθητικό breakpoint για εκτέλεση μέχρι διεύθυνση, step-over και step-out |

Χρησιμοποίησε την εντολή `bl` για να διακρίνεις τις εγγραφές software, hardware, memory και temporary, και την `bc <address|handle|all>` για να τις αφαιρέσεις. Τα hardware slots είναι περιορισμένα και λειτουργούν μέσω της κατάστασης των debug register, ενώ οι guard pages καλύπτουν μεγαλύτερη περιοχή αλλά ενεργοποιούνται και από άσχετες προσβάσεις στην ίδια σελίδα.

## Single-step σε native x64 έναντι WoW64

Το single-step σε native x64 θέτει το trap flag του επεξεργαστή μέσω του `IOCTL_KF_SINGLE_STEP`. Το Step Over αποκωδικοποιεί την τρέχουσα εντολή και τοποθετεί temporary breakpoints στις πιθανές επόμενες διευθύνσεις της. Το Step Out διαβάζει τη διεύθυνση επιστροφής από την κορυφή της τρέχουσας στοίβας. Σε ένα function prologue, αυτή η υπόθεση για τη στοίβα μπορεί να είναι λανθασμένη, επομένως προτίμησε ένα γνωστό internal breakpoint.<sup>[[2]](#references)</sup>

Το hook `KdTrap` δεν συλλαμβάνει 32-bit exceptions με τον ίδιο τρόπο. Για στόχους WoW64, ο debugger αποκωδικοποιεί την εντολή με το Iced, γράφει `EB FE` στο υπολογισμένο επόμενο `EIP` και ελέγχει επανειλημμένα τους instruction pointer των thread. Κατά συνέπεια, η εντολή `g <address>` δεν είναι διαθέσιμη για WoW64 και μια απλή `g` μπλοκάρει την κονσόλα μέχρι να επιτευχθεί ένα breakpoint. Όρισε πρώτα ένα breakpoint που μπορεί να επιτευχθεί και απόφυγε την απεριόριστη εκτέλεση, επειδή το `Ctrl+C` τερματίζει την κονσόλα αντί να ακυρώνει τον έλεγχο.<sup>[[2]](#references)</sup>

## Ανάλυση με υποβοήθηση μνήμης, register και συμβόλων

Η κονσόλα μπορεί να συνδυάσει μια συμβολική στάση με επιθεώρηση μνήμης και ελεγχόμενο patch. Οι κλήσεις αναζήτησης δέχονται wildcards για bytes, ASCII ή UTF-16 και έχουν όριο 4 MB, με έως 256 αναφερόμενα matches. Οι εντολές allocation και protection αντιστοιχούν στα IOCTL allocate, free και protect του driver.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

Η φόρτωση PDB διαβάζει τον κατάλογο εντοπισμού σφαλμάτων PE κάθε απομακρυσμένου module, εξάγει το αναγνωριστικό RSDS, εντοπίζει το αντίστοιχο PDB μέσω των DbgHelp/SymSrv και επαληθεύει ότι φορτώθηκε ως PDB. Τοποθετήστε τα private PDB δίπλα στο target στον relay machine ή προσθέστε τον κατάλογό τους στο `_NT_SYMBOL_PATH` στον host.<sup>[[2]](#references)</sup>

## Αλλαγές κατάστασης anti-debug με υποστήριξη από τον kernel

Η πρόσβαση στον kernel επιτρέπει στον debugger να αφαιρεί ενδείξεις που ένας user-mode debugger δεν μπορεί να αποκρύψει αξιόπιστα. Εφαρμόστε μία αλλαγή κάθε φορά, επιβεβαιώστε τον έλεγχο του target και επαναφέρετε το αντίστοιχο hook πριν τερματίσετε τη συνεδρία.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- Το `clr_debug_port` εκκαθαρίζει το `EPROCESS.DebugPort`.
- Το `clr_thread_hide` αφαιρεί το `HideFromDebugger` από τα νήματα-στόχους.
- Το `ntqsi on` πλαστογραφεί την κλάση `0x23` (`SystemKernelDebuggerInformation`) του `NtQuerySystemInformation`.
- Το `spoof on` κάνει τις αναγνώσεις σε user mode του `KUSER_SHARED_DATA.KdDebuggerEnabled` να επιστρέφουν false, διατηρώντας παράλληλα την κατάσταση του kernel που απαιτείται από τον μηχανισμό trap.
- Το `stats` ελέγχει τους μετρητές των hook και την καταγεγραμμένη κατάσταση των `KiDebugRoutine`, `KdpStub` και `KdTrap`.

Αυτές οι λειτουργίες αλλάζουν την κατάσταση της διεργασίας και του kernel. Ένα crash, ένα παρωχημένο inline hook, ένα λανθασμένο offset δομής ή μια ημιτελής επαναφορά patch μπορεί να αποσταθεροποιήσει την VM· γι’ αυτό είναι υποχρεωτικά τα snapshots και ένα απομονωμένο περιβάλλον δοκιμών με υπογραφή.<sup>[[1]](#references)</sup>

## References

- [1] [Αποθετήριο KernelFlirt και κύρια τεκμηρίωση](https://github.com/AkaTorich/KernelFlirt)
- [2] [Αναφορά κονσόλας KernelFlirt](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
