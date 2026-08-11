# Παρακάμψεις Admin Protection μέσω UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση
- Το Windows AppInfo εκθέτει την εσωτερική διαδρομή `RAiLaunchAdminProcess`, η οποία χρησιμοποιείται για την εκκίνηση εφαρμογών UIAccess για λόγους προσβασιμότητας. Το UIAccess επιτρέπει επιλεγμένη αλληλεπίδραση μεταξύ ορίων User Interface Privilege Isolation (UIPI). Δεν αποτελεί γενική παράκαμψη κάθε ορίου ασφάλειας διεργασιών.<sup>[[1]](#references)[[3]](#references)</sup>
- Η άμεση ενεργοποίηση του UIAccess απαιτεί `NtSetInformationToken(TokenUIAccess)` με **SeTcbPrivilege**, επομένως οι callers με χαμηλά δικαιώματα βασίζονται στην υπηρεσία. Η υπηρεσία πραγματοποιεί τρεις ελέγχους στο binary-στόχο πριν ορίσει το UIAccess:
- Το ενσωματωμένο manifest περιέχει `uiAccess="true"`.
- Είναι υπογεγραμμένο από οποιοδήποτε certificate που είναι έμπιστο από το Local Machine root store (χωρίς απαίτηση EKU/Microsoft).
- Βρίσκεται σε διαδρομή μόνο για administrators στο system drive (π.χ. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), εξαιρουμένων συγκεκριμένων writable subpaths.
- Το `RAiLaunchAdminProcess` δεν εμφανίζει consent prompt για εκκινήσεις UIAccess (διαφορετικά τα εργαλεία προσβασιμότητας δεν θα μπορούσαν να χειριστούν το prompt).<sup>[[1]](#references)</sup>

## Διαμόρφωση token και επίπεδα ακεραιότητας
- Αν οι έλεγχοι επιτύχουν, το AppInfo **αντιγράφει το token του caller**, ενεργοποιεί το UIAccess και αυξάνει το Integrity Level (IL):
- Limited admin user (ο user ανήκει στους Administrators αλλά εκτελείται με filtered token) ➜ **High IL**.
- Non-admin user ➜ το IL αυξάνεται κατά **+16 levels** έως το όριο **High** (το System IL δεν εκχωρείται ποτέ).
- Αν το token του caller διαθέτει ήδη UIAccess, το IL παραμένει αμετάβλητο.
- Κόλπο “Ratchet”: μια διεργασία UIAccess μπορεί να απενεργοποιήσει το UIAccess στον εαυτό της, να επανεκκινηθεί μέσω του `RAiLaunchAdminProcess` και να κερδίσει άλλη μία αύξηση IL κατά +16 levels. Η μετάβαση Medium➜High απαιτεί 255 relaunches (θορυβώδες, αλλά λειτουργεί).<sup>[[1]](#references)</sup>

## Γιατί το UIAccess επιτρέπει διαφυγή από το Admin Protection
- Το UIAccess επιτρέπει σε μια διεργασία με χαμηλότερο IL να στέλνει window messages σε windows με υψηλότερο IL (παρακάμπτοντας τα UIPI filters). Σε **ίδιο IL**, κλασικά UI primitives όπως το `SetWindowsHookEx` **επιτρέπουν code injection/DLL loading** σε οποιαδήποτε διεργασία κατέχει ένα window (συμπεριλαμβανομένων των **message-only windows** που χρησιμοποιούνται από το COM).
- Το Admin Protection εκκινεί τη διεργασία UIAccess με την ταυτότητα του **limited user**, αλλά σε **High IL**, αθόρυβα. Μόλις εκτελεστεί arbitrary code μέσα σε αυτή τη διεργασία UIAccess με High IL, ο attacker μπορεί να κάνει inject σε άλλες διεργασίες με High IL στο desktop (ακόμη και αν ανήκουν σε διαφορετικούς users), καταστρέφοντας τον προβλεπόμενο διαχωρισμό.<sup>[[1]](#references)</sup>

## Primitive handle από HWND προς διεργασία (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Στα Windows 10 1803+ το API μεταφέρθηκε στο Win32k (`NtUserGetWindowProcessHandle`) και μπορεί να ανοίξει process handle χρησιμοποιώντας ένα `DesiredAccess` που παρέχεται από τον caller. Η kernel path χρησιμοποιεί `ObOpenObjectByPointer(..., KernelMode, ...)`, παρακάμπτοντας τους κανονικούς user-mode access checks.<sup>[[2]](#references)</sup>
- Προϋποθέσεις στην πράξη: το target window πρέπει να βρίσκεται στο ίδιο desktop και οι UIPI checks πρέπει να επιτύχουν. Ιστορικά, ένας caller με UIAccess μπορούσε να παρακάμψει την αποτυχία UIPI και να λάβει kernel-mode handle (διορθώθηκε ως CVE-2023-41772).
- Ιστορικός αντίκτυπος: ένα window handle μετατρεπόταν σε **capability** για process access, όπως `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE` ή `PROCESS_VM_OPERATION`, το οποίο ο caller δεν θα μπορούσε κανονικά να αποκτήσει. Πριν από τα documented fixes, αυτό μπορούσε να παρακάμψει sandbox και protected-process boundaries όταν ένα target εξέθετε window, συμπεριλαμβανομένου ενός message-only window.<sup>[[2]](#references)</sup>
- Πρακτική ροή abuse: enumerate ή locate HWNDs (π.χ. `EnumWindows`/`FindWindowEx`), επίλυση του owning PID (`GetWindowThreadProcessId`), κλήση του `GetProcessHandleFromHwnd` και στη συνέχεια χρήση του returned handle για memory read/write ή code-hijack primitives.
- Συμπεριφορά μετά το fix: το UIAccess δεν παρέχει πλέον kernel-mode opens σε περίπτωση αποτυχίας UIPI και τα επιτρεπόμενα access rights περιορίζονται στο legacy hook set. Τα Windows 11 24H2 προσθέτουν process-protection checks και safer paths που ελέγχονται μέσω feature flags. Η καθολική απενεργοποίηση του UIPI (`EnforceUIPI=0`) αποδυναμώνει αυτές τις προστασίες.<sup>[[2]](#references)</sup>

## Αδυναμίες επικύρωσης secure-directory (AppInfo `AiCheckSecureApplicationDirectory`)
Το AppInfo επιλύει το παρεχόμενο path μέσω του `GetFinalPathNameByHandle` και στη συνέχεια εφαρμόζει **string allow/deny checks** σε hardcoded roots/exclusions. Πολλαπλές κατηγορίες bypass προκύπτουν από αυτή την απλοϊκή επικύρωση:
- **Named streams σε directories**: Writable directories που εξαιρούνται (π.χ. `C:\Windows\tracing`) μπορούν να παρακαμφθούν με named stream στο ίδιο το directory, π.χ. `C:\Windows\tracing:file.exe`. Τα string checks βλέπουν `C:\Windows\` και δεν εντοπίζουν το excluded subpath.
- **Writable file/directory μέσα σε allowed root**: Το `CreateProcessAsUser` **δεν απαιτεί επέκταση `.exe`**. Η αντικατάσταση οποιουδήποτε writable file κάτω από allowed root με executable payload λειτουργεί, ή η αντιγραφή ενός signed EXE με `uiAccess="true"` σε οποιοδήποτε writable subdirectory (π.χ. update leftovers όπως το `Tasks_Migrated`, όταν υπάρχει) επιτρέπει να περάσει το secure-path check.
- **MSIX στο `C:\Program Files\WindowsApps` (διορθώθηκε)**: Non-admins μπορούσαν να εγκαταστήσουν signed MSIX packages που τοποθετούνταν στο `WindowsApps`, το οποίο δεν εξαιρούνταν. Η συσκευασία ενός UIAccess binary μέσα στο MSIX και η εκκίνησή του μέσω `RAiLaunchAdminProcess` παρείχε μια **promptless High-IL UIAccess process**. Η Microsoft μετρίασε το πρόβλημα εξαιρώντας αυτό το path. Η ίδια η restricted MSIX capability `uiAccess` απαιτεί ήδη admin install.<sup>[[1]](#references)</sup>

## Attack workflow (High IL χωρίς prompt)
1. Απόκτησε/κατασκεύασε ένα **signed UIAccess binary** (manifest `uiAccess="true"`). Για μια ρεαλιστική αξιολόγηση, δοκίμασε με trust material και paths που έχουν εγκριθεί ρητά για το lab. Μην προσθέσεις certificate του attacker στο Local Machine root store ενός production machine.
2. Τοποθέτησέ το εκεί όπου το allowlist του AppInfo το αποδέχεται (ή κάνε abuse σε edge case επικύρωσης path/writable artifact όπως παραπάνω).
3. Κάλεσε το `RAiLaunchAdminProcess` για να το κάνεις spawn **σιωπηλά**, με UIAccess + elevated IL.
4. Από αυτό το foothold με High IL, στόχευσε άλλη διεργασία με High IL στο desktop χρησιμοποιώντας **window hooks/DLL injection** ή άλλα same-IL primitives, ώστε να γίνει πλήρες compromise του admin context.<sup>[[1]](#references)</sup>

## Enumerating candidate writable paths
Εκτέλεσε το PowerShell helper για να εντοπίσεις writable/overwritable objects μέσα σε nominally secure roots από την οπτική γωνία ενός επιλεγμένου token:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Εκτέλεση ως Administrator για ευρύτερη ορατότητα· ορίστε το `-ProcessId` σε μια low-priv διεργασία, ώστε να αναπαραχθεί η πρόσβαση του token της.
- Χειροκίνητο φιλτράρισμα για την εξαίρεση γνωστών μη επιτρεπόμενων υποκαταλόγων πριν από τη χρήση των candidates με το `RAiLaunchAdminProcess`.

## Σχετικά

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## References

- [1] [Παράκαμψη του Administrator Protection μέσω κατάχρησης του UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [Σε βάθος ανάλυση του GetProcessHandleFromHwnd (GPHFH)](https://projectzero.google/2026/02/gphfh-deep-dive.html)
- [3] [Microsoft Learn — εφαρμογές UIAccess](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works#uiaccess-applications)
{{#include ../../banners/hacktricks-training.md}}
