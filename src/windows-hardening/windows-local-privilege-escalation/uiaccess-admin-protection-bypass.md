# Παρακάμψεις του Admin Protection μέσω UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση
- Το Windows AppInfo εκθέτει το `RAiLaunchAdminProcess` για να δημιουργεί διεργασίες UIAccess (προορίζονται για accessibility). Το UIAccess παρακάμπτει τους περισσότερους μηχανισμούς φιλτραρίσματος μηνυμάτων του User Interface Privilege Isolation (UIPI) ώστε το λογισμικό προσβασιμότητας να μπορεί να χειρίζεται UI με υψηλότερο IL.
- Η ενεργοποίηση του UIAccess άμεσα απαιτεί `NtSetInformationToken(TokenUIAccess)` με **SeTcbPrivilege**, οπότε οι callers με χαμηλά προνόμια βασίζονται στην υπηρεσία. Η υπηρεσία εκτελεί τρεις ελέγχους στο στοχευόμενο binary πριν ορίσει UIAccess:
  - Το embedded manifest περιέχει `uiAccess="true"`.
  - Υπογράφεται από κάποιο πιστοποιητικό που εμπιστεύεται το Local Machine root store (χωρίς απαίτηση EKU/Microsoft).
  - Βρίσκεται σε διαδρομή μόνο για διαχειριστές στο system drive (π.χ., `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, εξαιρουμένων συγκεκριμένων εγγράψιμων υποδιαδρομών).
- Το `RAiLaunchAdminProcess` δεν εμφανίζει prompt συγκατάθεσης για launches με UIAccess (αλλιώς τα εργαλεία προσβασιμότητας δεν θα μπορούσαν να χειριστούν το prompt).

## Μορφοποίηση token και επίπεδα ακεραιότητας
- Αν οι έλεγχοι περάσουν, το AppInfo **αντιγράφει το caller token**, ενεργοποιεί UIAccess, και αυξάνει το Integrity Level (IL):
  - Limited admin user (ο χρήστης είναι στην ομάδα Administrators αλλά τρέχει με φιλτραρισμένο token) ➜ **High IL**.
  - Non-admin user ➜ το IL αυξάνεται κατά **+16 levels** μέχρι το όριο **High** (System IL δεν ανατίθεται ποτέ).
- Αν το caller token ήδη έχει UIAccess, το IL παραμένει αμετάβλητο.
- “Ratchet” trick: μια διεργασία UIAccess μπορεί να απενεργοποιήσει το UIAccess στον εαυτό της, να επανεκκινηθεί μέσω `RAiLaunchAdminProcess`, και να κερδίσει ακόμη +16 αύξηση IL. Medium➜High απαιτεί 255 επανεκκινήσεις (θορυβώδες, αλλά λειτουργεί).

## Γιατί το UIAccess επιτρέπει παράκαμψη του Admin Protection
- Το UIAccess επιτρέπει σε διεργασία με χαμηλότερο IL να στέλνει window messages σε παράθυρα με υψηλότερο IL (παρακάμπτοντας τα UIPI φίλτρα). Σε ίσο IL, κλασικά UI primitives όπως `SetWindowsHookEx` **επιτρέπουν ένεση κώδικα/φόρτωμα DLL** σε οποιαδήποτε διεργασία που κατέχει παράθυρο (συμπεριλαμβανομένων των **message-only windows** που χρησιμοποιούνται από COM).
- Το Admin Protection εκκινεί τη διεργασία UIAccess υπό την ταυτότητα του limited user αλλά σε **High IL**, χωρίς ειδοποίηση. Μόλις εκτελεστεί αυθαίρετος κώδικας μέσα σε αυτή τη High-IL διεργασία UIAccess, ο επιτιθέμενος μπορεί να εγχύσει σε άλλες High-IL διεργασίες στο desktop (ακόμη και αν ανήκουν σε διαφορετικούς χρήστες), σπάζοντας τον προοριζόμενο διαχωρισμό.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Στα Windows 10 1803+ το API μεταφέρθηκε στο Win32k (`NtUserGetWindowProcessHandle`) και μπορεί να ανοίξει handle διεργασίας χρησιμοποιώντας `DesiredAccess` που περνάει ο caller. Η διαδρομή kernel χρησιμοποιεί `ObOpenObjectByPointer(..., KernelMode, ...)`, που παρακάμπτει τους κανονικούς user-mode ελέγχους πρόσβασης.
- Προϋποθέσεις στην πράξη: το στοχευόμενο παράθυρο πρέπει να είναι στο ίδιο desktop, και οι έλεγχοι UIPI πρέπει να περάσουν. Ιστορικά, ένας caller με UIAccess μπορούσε να παρακάμψει την αποτυχία UIPI και να λάβει kernel-mode handle (διόρθωση: CVE-2023-41772).
- Επιπτώσεις: ένα handle παραθύρου γίνεται μια **ικανότητα** για να αποκτηθεί ισχυρό handle διεργασίας (συνήθως `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) που ο caller κανονικά δεν θα μπορούσε να ανοίξει. Αυτό επιτρέπει cross-sandbox πρόσβαση και μπορεί να σπάσει Protected Process / PPL όρια αν ο στόχος εκθέτει οποιοδήποτε παράθυρο (συμπεριλαμβανομένων message-only windows).
- Πρακτική ροή κατάχρησης: εντοπίζετε ή απαριθμείτε HWNDs (π.χ., `EnumWindows`/`FindWindowEx`), επιλύετε το PID που τα κατέχει (`GetWindowThreadProcessId`), καλείτε `GetProcessHandleFromHwnd`, και μετά χρησιμοποιείτε το επιστρεφόμενο handle για ανάγνωση/γραφή μνήμης ή primitives hijack κώδικα.
- Μετά τη διόρθωση: το UIAccess δεν παρέχει πλέον kernel-mode ανοίγματα σε περίπτωση αποτυχίας UIPI και τα επιτρεπόμενα δικαιώματα περιορίστηκαν στο legacy hook set· τα Windows 11 24H2 προσθέτουν ελέγχους προστασίας διεργασίας και feature-flagged ασφαλέστερες διαδρομές. Η απενεργοποίηση του UIPI σε επίπεδο συστήματος (`EnforceUIPI=0`) αποδυναμώνει αυτές τις προστασίες.

## Αδυναμίες στην επικύρωση secure-directory (AppInfo `AiCheckSecureApplicationDirectory`)
Το AppInfo επιλύει την παρεχόμενη διαδρομή μέσω `GetFinalPathNameByHandle` και στη συνέχεια εφαρμόζει **έλεγχους string allow/deny** έναντι hardcoded roots/exclusions. Πολλές κατηγορίες παράκαμψης προκύπτουν από αυτήν την απλοϊκή επικύρωση:
- **Directory named streams**: Εξαιρεθείσες εγγράψιμες διαδρομές (π.χ., `C:\Windows\tracing`) μπορούν να παρακαμφθούν με ένα named stream πάνω στον ίδιο τον κατάλογο, π.χ. `C:\Windows\tracing:file.exe`. Οι έλεγχοι string βλέπουν `C:\Windows\` και χάνουν την εξαιρεθείσα υποδιαδρομή.
- **Εγγράψιμο αρχείο/φάκελος μέσα σε επιτρεπόμενη ρίζα**: Το `CreateProcessAsUser` **δεν απαιτεί επέκταση `.exe`**. Η αντικατάσταση οποιουδήποτε εγγράψιμου αρχείου κάτω από μια επιτρεπόμενη ρίζα με εκτελέσιμο payload λειτουργεί, ή η αντιγραφή ενός υπογεγραμμένου EXE με `uiAccess="true"` σε οποιοδήποτε εγγράψιμο υποφάκελο (π.χ., leftovers ενημερώσεων όπως `Tasks_Migrated` όταν υπάρχουν) το κάνει να περάσει τον έλεγχο secure-path.
- **MSIX στο `C:\Program Files\WindowsApps` (διορθώθηκε)**: Οι μη-admin θα μπορούσαν να εγκαταστήσουν υπογεγραμμένα MSIX packages που τοποθετούνταν στο `WindowsApps`, το οποίο δεν είχε εξαιρεθεί. Η συσκευασία ενός UIAccess binary μέσα στο MSIX και η εκκίνησή του μέσω `RAiLaunchAdminProcess` παρήγαγε μια **χωρίς prompt High-IL UIAccess διεργασία**. Η Microsoft αντιμετώπισε το πρόβλημα εξαιρώντας αυτή τη διαδρομή· η περιορισμένη δυνατότητα `uiAccess` για MSIX ήδη απαιτούσε admin εγκατάσταση.

## Ροή επίθεσης (High IL χωρίς prompt)
1. Αποκτήστε/δημιουργήστε ένα **υπογεγραμμένο UIAccess binary** (manifest `uiAccess="true"`).
2. Τοποθετήστε το όπου η allowlist του AppInfo το αποδέχεται (ή εκμεταλλευτείτε κάποιο edge case επικύρωσης διαδρομής/εγγράψιμου artifact όπως παραπάνω).
3. Καλέστε `RAiLaunchAdminProcess` για να το εκκινήσετε **σιωπηρά** με UIAccess + αυξημένο IL.
4. Από αυτό το High-IL foothold, στοχεύστε άλλη High-IL διεργασία στο desktop χρησιμοποιώντας **window hooks/DLL injection** ή άλλα same-IL primitives για να πλήρως να συμβιβαστεί το περιβάλλον διαχειριστή.

## Εντοπισμός υποψήφιων εγγράψιμων διαδρομών
Τρέξτε το helper PowerShell για να ανακαλύψετε εγγράψιμα/επαναεγγράψιμα αντικείμενα μέσα σε ονομαστικά secure roots από την οπτική ενός επιλεγμένου token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Run as Administrator για ευρύτερη ορατότητα· ορίστε `-ProcessId` σε μια low-priv process ώστε να αντικατοπτρίζει την πρόσβαση του token.
- Φιλτράρετε χειροκίνητα για να εξαιρέσετε γνωστούς μη επιτρεπτούς υποκαταλόγους πριν χρησιμοποιήσετε υποψήφιους με `RAiLaunchAdminProcess`.

## Αναφορές
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
