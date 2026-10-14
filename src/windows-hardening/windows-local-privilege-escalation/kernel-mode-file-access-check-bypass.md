# Παρακάμψεις ελέγχου πρόσβασης αρχείων σε kernel mode

{{#include ../../banners/hacktricks-training.md}}

## Ευάλωτο μοτίβο driver

Ένας driver δεν διατηρεί τα όρια ασφαλείας του caller μόνο και μόνο επειδή κάνει impersonation αυτού του caller. Τα ανοίγματα αντικειμένων σε kernel mode παρακάμπτουν κανονικά τους ελέγχους πρόσβασης. Το `OBJ_KERNEL_HANDLE` απλώς καθιστά το handle που προκύπτει προσβάσιμο από kernel mode. Όταν ένας driver ανοίγει ή χειρίζεται ένα αντικείμενο για λογαριασμό του user mode, πρέπει επίσης να χρησιμοποιεί το `OBJ_FORCE_ACCESS_CHECK`, ώστε ο Object Manager να αξιολογεί την αιτούμενη πρόσβαση βάσει του effective token.<sup>[[3]](#references)[[4]](#references)</sup>

Ελέγξτε τα IOCTL και τα create callbacks που χειρίζονται αρχεία για την εξής ακολουθία:<sup>[[3]](#references)[[4]](#references)</sup>

1. Το user mode παρέχει ένα path, source handle, επιθυμητό επίπεδο πρόσβασης ή τύπο λειτουργίας.
2. Ο driver κάνει impersonation του caller, αλλά καλεί `IoCreateFileEx`, `ZwCreateFile` ή παρόμοια routine χωρίς `OBJ_FORCE_ACCESS_CHECK`.
3. Ένα handle αρχείου ή καταλόγου που είναι διαθέσιμο μόνο σε kernel mode αποθηκεύεται σε κατάσταση ανά handle.
4. Μια μεταγενέστερη λειτουργία αποφασίζει αν θα κάνει impersonation βάσει κατάστασης που επηρεάζεται από τον attacker, όπως το access mask που ζητήθηκε κατά το πρώτο άνοιγμα.
5. Ο κλάδος με αυξημένα προνόμια εκτελεί rename ή link με information class `BypassAccessCheck`.

Αυτό είναι ένα **confused-deputy file primitive**, όχι απαραίτητα αλλοίωση μνήμης. Μια ιδιαίτερα επικίνδυνη αντιστροφή κατάστασης είναι «αν ζητήθηκε write, κάνε impersonation· αν δεν ζητήθηκε write, διατήρησε τα αυξημένα προνόμια». Σε αυτή τη σχεδίαση, το να ζητήσει κανείς σκόπιμα μόνο read access μπορεί να ξεκλειδώσει την ισχυρότερη διαδρομή.<sup>[[3]](#references)</sup>

## Παράδειγμα vSMB: privileged root και privileged rename

Το `storvsp.sys` υλοποιεί το Virtual Server Message Block (vSMB). Όταν είναι ενεργοποιημένη η δυνατότητα **Virtual Machine Platform**, το user mode μπορεί να αποκτήσει πρόσβαση στο `\Device\STORVSP` μέσω του `\\.\STORVSP`. Ένα path συστήματος αρχείων vSMB έχει τη μορφή `\\.\STORVSP\VSMB\??\C:\path`. Τα CVE-2025-59517 και CVE-2025-64673 έδειξαν πώς δύο ασυνεπείς αποφάσεις ελέγχου πρόσβασης μπορούσαν να μετατρέψουν αυτή τη διεπαφή σε τοπική κλιμάκωση προνομίων.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Η αντιστοίχιση των functions με τα CVE στην πηγή βασίζεται σε reverse engineering του patched binary και όχι σε πηγαίο κώδικα της Microsoft. Οι ερευνητές προειδοποιούν ότι τα δύο αναγνωριστικά μπορεί να αντιστοιχούν στις αντίθετες functions.<sup>[[3]](#references)</sup>

### 1. Δημιουργία share μόνο για ανάγνωση με root έναν προστατευμένο κατάλογο

Η ευάλωτη διαδρομή create κατέγραφε τα ζητούμενα δικαιώματα σε persistent flags όπως `HasReadAccess`, `HasWriteAccess` και `HasAppendAccess`. Έπειτα άνοιγε το backing path με `OBJ_KERNEL_HANDLE`, αλλά χωρίς `OBJ_FORCE_ACCESS_CHECK`. Επομένως, η απόπειρα για impersonation δεν έκανε το άνοιγμα του αρχείου να σέβεται τα δικαιώματα NTFS του caller.<sup>[[3]](#references)[[4]](#references)</sup>

Ζητήστε μόνο `FILE_READ_DATA`. Έτσι, το `HasWriteAccess` παραμένει μη ορισμένο, ενώ εξακολουθείτε να αποκτάτε ένα share με εσωτερικό root που είναι προστατευμένος κατάλογος:<sup>[[3]](#references)</sup>

```c
HANDLE root = CreateFileW(
    L"\\\\.\\STORVSP\\VSMB\\??\\C:\\Windows\\System32\\",
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY,
    NULL
);
```

Το σημαντικό αντικείμενο δεν είναι μια λαβή καταλόγου System32 σε user-mode. Είναι μια λαβή συσκευής vSMB που σχετίζεται με κατάσταση driver, η οποία περιέχει μια προνομιούχα λαβή ρίζας kernel.<sup>[[3]](#references)</sup>

### 2. Μετατροπή της ασυμφωνίας κατάστασης σε αντικατάσταση προστατευμένου αρχείου

Το IOCTL `0x240330` δεχόταν μια λαβή αρχείου προέλευσης, μια κλάση πληροφοριών και ένα buffer πληροφοριών μεταβλητού μήκους:<sup>[[3]](#references)</sup>

```c
#define IOCTL_VSMB_SET_INFORMATION_FILE_REQUEST 0x240330

typedef struct _VSMB_SET_INFO {
    DWORD Version;
    DWORD Reserved;
    UINT64 SourceHandle;
    DWORD InformationClass;
    DWORD BufferLength;
    BYTE Buffer[1];
} VSMB_SET_INFO;
```

Ο ευάλωτος handler δεχόταν τα `FileRenameInformation`, `FileLinkInformation` και `FileRenameInformationEx`. Για μια κανονική διαδρομή μετονομασίας, διαχώριζε τη διαδρομή του γονικού καταλόγου από το τελικό στοιχείο και έπειτα άνοιγε τον γονικό κατάλογο σε σχέση με το αποθηκευμένο root handle. Και αυτή η κλήση ανοίγματος χρησιμοποιούσε `OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE` χωρίς `OBJ_FORCE_ACCESS_CHECK`. Αν το `RootDirectory` που παρείχε ο επιτιθέμενος μέσα στη δομή μετονομασίας ήταν μη μηδενικό, απορριπτόταν, οπότε ο driver παρείχε το δικό του προνομιούχο directory handle.<sup>[[3]](#references)</sup>

Ο ευάλωτος κλάδος επιλεγόταν αν **δεν** ζητούνταν write access κατά το stage 1:<sup>[[3]](#references)</sup>

- `HasWriteAccess == 1`: γίνεται impersonation του αποθηκευμένου security context της root.
- `HasWriteAccess == 0`: παραλείπεται το impersonation και το `FileRenameInformation` ή `FileRenameInformationEx` μετατρέπεται στην αντίστοιχη παραλλαγή `BypassAccessCheck`.

Ο handler αντέγραψε το source handle που παρείχε ο επιτιθέμενος στο `PsInitialSystemProcess`, το αναφέρθηκε ως file object, εγκατέστησε το προνομιούχο target-directory handle στη δομή μετονομασίας και κάλεσε το `ZwSetInformationFile`. Επομένως, με `ReplaceIfExists = TRUE`, ένα αρχείο που ελεγχόταν από τον καλούντα μπορούσε να αντικαταστήσει ένα υπάρχον αρχείο κάτω από το προστατευμένο root.<sup>[[3]](#references)</sup>

Κατά την εξέταση ενός παρόμοιου handler, παρακολούθησε **τόσο την προέλευση των handles όσο και το security context** σε κάθε κλάδο. Η επικύρωση εισόδου, οι έλεγχοι integer overflow, το `IO_STOP_ON_SYMLINK` και ο περιορισμός των αποδεκτών information classes δεν αντισταθμίζουν τον συνδυασμό ενός προνομιούχου root handle με μια λειτουργία παράκαμψης ελέγχου πρόσβασης.<sup>[[3]](#references)</sup>

## Από προστατευμένη εγγραφή σε εκτέλεση ως SYSTEM

Ένα primitive αντικατάστασης προστατευμένου αρχείου οδηγεί σε εκτέλεση κώδικα όταν μια προνομιούχα διεργασία φορτώσει αργότερα το αντικατασταθέν module. Στην αλυσίδα που παρουσιάζεται, ο προορισμός ήταν το `C:\Windows\System32\wuapi.dll`. Η ενεργοποίηση της local-server COM class `{72566E27-1ABB-4EB3-B4F0-EB431CB1CB32}` για το interface `{b4c1d279-966e-44e9-a9c5-ccaf4a77023d}` και η κλήση του `IWaaSRemediation::LaunchDetectionOnly()` προκάλεσαν τη φόρτωση αυτού του DLL από μια διεργασία SYSTEM.<sup>[[3]](#references)</sup>

Αυτή η κλήση COM είναι **activation trigger**, όχι [COM registry hijacking](com-hijacking.md). Το file primitive παρέχει το φυτεμένο module και ο προνομιούχος loader παρέχει την εκτέλεση. Για άλλες αλυσίδες προστατευμένης εγγραφής, εντόπισε το ακριβές image, τη διαδρομή DLL, την πολιτική υπογραφών, το bitness, τις exported functions και ένα αξιόπιστο trigger πριν επιλέξεις στόχο. Δες το [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) για τη γενική ροή εργασίας ανάλυσης loader.<sup>[[3]](#references)</sup>

### Μεταφορά token από Session 0 στην αλληλεπιδραστική επιφάνεια εργασίας

Ένα payload που φορτώνεται από υπηρεσία εκτελείται συνήθως στο Session 0. Για να δημιουργήσει μια αλληλεπιδραστική διεργασία, μπορεί να ανακτήσει το ενεργό console session μέσω του `WTSGetActiveConsoleSessionId`, να ενεργοποιήσει τα απαιτούμενα token privileges, να αντιγράψει το τρέχον SYSTEM token ως primary token και να ορίσει το `TokenSessionId` στην ενεργή συνεδρία. Στη συνέχεια, το `CreateProcessAsUserW` χρησιμοποιεί αυτό το token με `STARTUPINFO.lpDesktop = L"winsta0\\default"`.<sup>[[3]](#references)[[5]](#references)</sup>

```c
DWORD sid = WTSGetActiveConsoleSessionId();
DuplicateTokenEx(currentToken, MAXIMUM_ALLOWED, NULL,
                 SecurityImpersonation, TokenPrimary, &primary);
SetTokenInformation(primary, TokenSessionId, &sid, sizeof(sid));
si.lpDesktop = L"winsta0\\default";
CreateProcessAsUserW(primary, L"C:\\Windows\\System32\\cmd.exe",
                     NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE,
                     NULL, NULL, &si, &pi);
```

`SeTcbPrivilege` απαιτείται για να οριστεί το session ID ενός token σε αυτό το σενάριο. Το interactive window station και το desktop πρέπει επίσης να επιτρέπουν στο token την πρόσβαση. Δείτε το [token duplication από το Session 0](sedebug-+-seimpersonate-copy-token.md) για την ευρύτερη ροή εργασίας αντιγραφής token.<sup>[[3]](#references)[[5]](#references)</sup>

## Οδηγίες επιδιόρθωσης και αναθεώρησης

Οι ενημερώσεις της Microsoft του Δεκεμβρίου 2025 διόρθωσαν την αλυσίδα που παρουσιάζεται. Η αντίστροφη μηχανική έδειξε ότι η διορθωμένη διαδρομή δημιουργίας του vSMB απορρίπτει μη έμπιστους καλούντες που ζητούν τη ρίζα ενός share χωρίς `FILE_WRITE_DATA`. Στις σχετικές λειτουργίες προστέθηκε επίσης υποχρεωτικός έλεγχος πρόσβασης. Αυτό αποτρέπει την αντιστροφή κατάστασης πριν ένας μη προνομιούχος καλών αποκτήσει πρόσβαση στη ρίζα με προνόμια.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

Για κώδικα driver, εφαρμόστε τους εξής κανόνες:<sup>[[3]](#references)[[4]](#references)</sup>

- Προσθέστε `OBJ_FORCE_ACCESS_CHECK` κάθε φορά που ένα αντικείμενο ανοίγεται για λογαριασμό αιτήματος από user mode. Μην αντιμετωπίζετε το `OBJ_KERNEL_HANDLE` ως μηχανισμό ελέγχου εξουσιοδότησης.<sup>[[4]](#references)</sup>
- Καταγράψτε και επικυρώστε τη λειτουργία του αιτούντος και το ενεργό subject context. Μην επιτρέπετε στα ζητούμενα δικαιώματα να επιλέγουν διαδρομή εκτέλεσης με περισσότερα προνόμια.
- Επικυρώστε τα user handles με τον σωστό τύπο αντικειμένου, τη μάσκα πρόσβασης και το `UserMode`. Η αντιγραφή ενός handle στη διεργασία συστήματος δεν επικυρώνει την εξουσιοδότηση της ζητούμενης λειτουργίας.
- Διατηρήστε την επίλυση του στόχου σχετική με ένα έμπιστο handle, αλλά βεβαιωθείτε ότι το ίδιο το έμπιστο handle ανοίχτηκε με τον επιβαλλόμενο έλεγχο πρόσβασης του αιτούντος.
- Αποφύγετε τις κλάσεις `File*BypassAccessCheck` για λειτουργίες που ξεκινούν από τον χρήστη. Αν ο εσωτερικός κώδικας τις χρειάζεται πραγματικά, περιορίστε αυτή τη διαδρομή με απόφαση εξουσιοδότησης ανεξάρτητη από τις ελεγχόμενες από τον χρήστη σημαίες πρόσβασης.
- Εγκαταστήστε τις ενημερώσεις στα επηρεαζόμενα συστήματα. Η ευάλωτη επιφάνεια έχει σημασία όταν το Virtual Machine Platform φορτώνει το `storvsp.sys`.<sup>[[3]](#references)</sup>

## References

- [1] [Microsoft Security Response Center - CVE-2025-59517](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-59517)
- [2] [Microsoft Security Response Center - CVE-2025-64673](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-64673)
- [3] [Exodus Intelligence - Από το Virtual Share στο Physical Shell: Αξιοποίηση του ασυνεπούς ελέγχου πρόσβασης των Windows για LPE](https://blog.exodusintel.com/2026/07/27/from-virtual-share-to-physical-shell-leveraging-windows-inconsistent-access-control-for-lpe/)
- [4] [Microsoft Learn - Χειριστές αντικειμένων](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles)
- [5] [Microsoft Learn - Συνάρτηση CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)
{{#include ../../banners/hacktricks-training.md}}
