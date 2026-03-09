# Admin Protection Παρακάμψεις μέσω UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση
- Το Windows AppInfo εκθέτει το `RAiLaunchAdminProcess` για την εκκίνηση διεργασιών UIAccess (προοριζόμενες για accessibility). Το UIAccess παρακάμπτει τους περισσότερους ελέγχους φιλτραρίσματος μηνυμάτων του User Interface Privilege Isolation (UIPI) ώστε το λογισμικό accessibility να μπορεί να χειρίζεται UI με υψηλότερο IL.
- Η ενεργοποίηση του UIAccess απευθείας απαιτεί `NtSetInformationToken(TokenUIAccess)` με **SeTcbPrivilege**, οπότε οι χαμηλής-άδειας καλούντες βασίζονται στην υπηρεσία. Η υπηρεσία εκτελεί τρεις ελέγχους στο στοχευόμενο binary πριν θέσει UIAccess:
- Το ενσωματωμένο manifest περιέχει `uiAccess="true"`.
- Υπογράφεται από οποιοδήποτε πιστοποιητικό που εμπιστεύεται το Local Machine root store (χωρίς απαίτηση EKU/Microsoft).
- Βρίσκεται σε διαδρομή που προορίζεται μόνο για administrators στο system drive (π.χ., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, εξαιρουμένων συγκεκριμένων εγγράψιμων υποδιαδρομών).
- Το `RAiLaunchAdminProcess` δεν εμφανίζει prompt συγκατάθεσης για εκκινήσεις UIAccess (αλλιώς τα εργαλεία accessibility δεν θα μπορούσαν να χειριστούν το prompt).

## Token shaping and integrity levels
- Αν οι έλεγχοι περάσουν, το AppInfo **αντιγράφει το caller token**, ενεργοποιεί το UIAccess, και αυξάνει το Integrity Level (IL):
- Limited admin user (ο χρήστης είναι στους Administrators αλλά τρέχει φιλτραρισμένος) ➜ **High IL**.
- Non-admin user ➜ το IL αυξάνεται κατά **+16 levels** έως ένα όριο **High** (το System IL δεν ανατίθεται ποτέ).
- Αν το caller token ήδη έχει UIAccess, το IL παραμένει αμετάβλητο.
- “Ratchet” trick: μια διεργασία UIAccess μπορεί να απενεργοποιήσει το UIAccess στον εαυτό της, να ξαναεκκινήσει μέσω `RAiLaunchAdminProcess`, και να κερδίσει άλλη +16 αύξηση IL. Medium➜High χρειάζεται 255 relaunches (θορυβώδες, αλλά λειτουργεί).

## Γιατί το UIAccess επιτρέπει παράκαμψη του Admin Protection
- Το UIAccess επιτρέπει σε διεργασία με χαμηλότερο IL να στέλνει window messages σε παράθυρα με υψηλότερο IL (παρακάμπτοντας τα UIPI φίλτρα). Σε **ίδιο IL**, τα κλασικά UI primitives όπως `SetWindowsHookEx` **επιτρέπουν injection κώδικα/φόρτωση DLL** σε οποιαδήποτε διεργασία που κατέχει παράθυρο (συμπεριλαμβανομένων των **message-only windows** που χρησιμοποιεί COM).
- Το Admin Protection εκκινεί τη διεργασία UIAccess με την ταυτότητα του **limited user** αλλά σε **High IL**, σιωπηρά. Μόλις arbitrary code τρέξει μέσα σε αυτήν τη High-IL διεργασία UIAccess, ο επιτιθέμενος μπορεί να κάνει injection σε άλλες High-IL διεργασίες στην επιφάνεια εργασίας (ακόμα και που ανήκουν σε διαφορετικούς χρήστες), καταλύοντας τον προοριζόμενο διαχωρισμό.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Σε Windows 10 1803+ το API μεταφέρθηκε στο Win32k (`NtUserGetWindowProcessHandle`) και μπορεί να ανοίξει ένα process handle χρησιμοποιώντας ένα caller-supplied `DesiredAccess`. Η διαδρομή του kernel χρησιμοποιεί `ObOpenObjectByPointer(..., KernelMode, ...)`, που παρακάμπτει τους κανονικούς user-mode access checks.
- Προαπαιτούμενα στην πράξη: το στοχευόμενο παράθυρο πρέπει να είναι στο ίδιο desktop, και οι έλεγχοι UIPI πρέπει να περνάνε. Ιστορικά, ένας caller με UIAccess μπορούσε να παρακάμψει αποτυχία UIPI και παρόλα αυτά να πάρει kernel-mode handle (διορθώθηκε ως CVE-2023-41772).
- Επιπτώσεις: ένα window handle γίνεται μια **ικανότητα (capability)** για να αποκτηθεί ένα ισχυρό process handle (συνήθως `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) που ο καλών δεν θα μπορούσε κανονικά να ανοίξει. Αυτό επιτρέπει cross-sandbox πρόσβαση και μπορεί να καταλύσει Protected Process / PPL όρια αν ο στόχος εκθέτει οποιοδήποτε παράθυρο (συμπεριλαμβανομένων message-only windows).
- Πρακτική ροή κατάχρησης: εντοπισμός ή αναγραφή HWNDs (π.χ., `EnumWindows`/`FindWindowEx`), επίλυση του owning PID (`GetWindowThreadProcessId`), κλήση `GetProcessHandleFromHwnd`, και χρήση του επιστρεφόμενου handle για memory read/write ή code-hijack primitives.
- Συμπεριφορά μετά το fix: το UIAccess δεν δίνει πια kernel-mode opens σε περίπτωση UIPI failure και τα επιτρεπόμενα access rights περιορίζονται στο legacy hook set· τα Windows 11 24H2 προσθέτουν process-protection checks και feature-flagged ασφαλέστερες διαδρομές. Η απενεργοποίηση του UIPI σε σύστημα (`EnforceUIPI=0`) εξασθενεί αυτές τις προστασίες.

## Αδυναμίες στην επαλήθευση secure-directory (AppInfo `AiCheckSecureApplicationDirectory`)
Το AppInfo επιλύει την παρεχόμενη διαδρομή μέσω `GetFinalPathNameByHandle` και στη συνέχεια εφαρμόζει **string allow/deny checks** ενάντια σε hardcoded roots/exclusions. Πολλές κλάσεις bypass προκύπτουν από αυτήν την απλοϊκή επαλήθευση:
- **Directory named streams**: Εξαιρεμένες εγγράψιμες διαδρομές (π.χ., `C:\Windows\tracing`) μπορούν να παρακαμφθούν με ένα named stream πάνω στον ίδιο τον κατάλογο, π.χ. `C:\Windows\tracing:file.exe`. Οι string checks βλέπουν `C:\Windows\` και χάνουν την εξαιρεμένη υποδιαδρομή.
- **Writable file/directory inside an allowed root**: Το `CreateProcessAsUser` δεν απαιτεί **`.exe` extension**. Η αντικατάσταση οποιουδήποτε εγγράψιμου αρχείου κάτω από έναν επιτρεπόμενο root με ένα εκτελέσιμο payload λειτουργεί, ή η αντιγραφή ενός signed `uiAccess="true"` EXE σε οποιοδήποτε εγγράψιμο υποφάκελο (π.χ., leftovers ενημέρωσης όπως `Tasks_Migrated` όταν υπάρχουν) το αφήνει να περάσει τον έλεγχο secure-path.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Non-admins μπορούσαν να εγκαταστήσουν signed MSIX πακέτα που τοποθετούνταν σε `WindowsApps`, το οποίο δεν ήταν εξαιρεμένο. Η συσκευασία ενός UIAccess binary μέσα στο MSIX και η εκκίνηση του μέσω `RAiLaunchAdminProcess` παρήγαγαν μια **promptless High-IL UIAccess διεργασία**. Η Microsoft μείωσε το πρόβλημα εξαιρώντας αυτή τη διαδρομή· η περιορισμένη MSIX capability για `uiAccess` ήδη απαιτεί admin install.

## Attack workflow (High IL χωρίς prompt)
1. Αποκτήστε/συντάξτε ένα **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Τοποθετήστε το όπου το allowlist του AppInfo το αποδέχεται (ή εκμεταλλευτείτε κάποιο edge case της επαλήθευσης διαδρομής/εγγράψιμου artifact όπως παραπάνω).
3. Καλέστε `RAiLaunchAdminProcess` για να το εκκινήσετε **σιωπηρά** με UIAccess + αυξημένο IL.
4. Από αυτό το High-IL foothold, στοχεύστε άλλη High-IL διεργασία στην επιφάνεια εργασίας χρησιμοποιώντας **window hooks/DLL injection** ή άλλα same-IL primitives για να καταλάβετε πλήρως το admin context.

## Εντοπισμός υποψήφιων εγγράψιμων διαδρομών
Τρέξτε το PowerShell helper για να ανακαλύψετε εγγράψιμα/επαναγραφόμενα αντικείμενα μέσα σε ονομαστικά secure roots από την οπτική ενός επιλεγμένου token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Εκτελέστε ως Administrator για ευρύτερη ορατότητα· ορίστε `-ProcessId` σε μια low-priv διεργασία για να αντικατοπτρίσετε την πρόσβαση αυτού του token.
- Φιλτράρετε χειροκίνητα για να αποκλείσετε γνωστούς μη επιτρεπόμενους υποκαταλόγους πριν χρησιμοποιήσετε τους υποψήφιους με `RAiLaunchAdminProcess`.

## Αναφορές
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
