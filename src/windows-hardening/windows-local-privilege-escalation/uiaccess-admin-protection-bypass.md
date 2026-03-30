# Παρακάμψεις του Admin Protection μέσω UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση
- Το Windows AppInfo εκθέτει τη `RAiLaunchAdminProcess` για να ξεκινά διαδικασίες UIAccess (προοριζόμενες για accessibility). Το UIAccess παρακάμπτει το μεγαλύτερο μέρος του User Interface Privilege Isolation (UIPI) φιλτραρίσματος μηνυμάτων ώστε το accessibility software να μπορεί να χειρίζεται UI με υψηλότερο IL.
- Η ενεργοποίηση του UIAccess απευθείας απαιτεί `NtSetInformationToken(TokenUIAccess)` με **SeTcbPrivilege**, οπότε οι callers με χαμηλά προνόμια βασίζονται στην υπηρεσία. Η υπηρεσία εκτελεί τρεις ελέγχους στο στοχευόμενο binary πριν ορίσει UIAccess:
- Το embedded manifest περιέχει `uiAccess="true"`.
- Υπογράφεται από οποιοδήποτε πιστοποιητικό εμπιστεύεται το Local Machine root store (χωρίς απαίτηση EKU/Microsoft).
- Βρίσκεται σε διαδρομή μόνο για administrators στο system drive (π.χ. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, εξαιρουμένων συγκεκριμένων εγγράψιμων υπο-διαδρομών).
- Η `RAiLaunchAdminProcess` δεν εμφανίζει prompt συναίνεσης για launches με UIAccess (διαφορετικά τα accessibility εργαλεία δεν θα μπορούσαν να χειριστούν το prompt).

## Token shaping and integrity levels
- Αν οι έλεγχοι περάσουν, το AppInfo **αντιγράφει το caller token**, ενεργοποιεί UIAccess, και αυξάνει το Integrity Level (IL):
- Limited admin user (ο χρήστης είναι στους Administrators αλλά τρέχει με φιλτραρισμένο token) ➜ **High IL**.
- Non-admin user ➜ IL αυξάνεται κατά **+16 levels** έως ένα όριο **High** (το System IL δεν ανατίθεται ποτέ).
- Αν το caller token ήδη έχει UIAccess, το IL παραμένει αμετάβλητο.
- Το κόλπο “ratchet”: μια διεργασία UIAccess μπορεί να απενεργοποιήσει το UIAccess στον εαυτό της, να ξαναξεκινήσει μέσω `RAiLaunchAdminProcess`, και να κερδίσει άλλη μια αύξηση +16 IL. Από Medium➜High απαιτούνται 255 relaunches (θορυβώδες, αλλά δουλεύει).

## Γιατί το UIAccess επιτρέπει παράκαμψη του Admin Protection
- Το UIAccess επιτρέπει σε μια διεργασία με χαμηλότερο IL να στέλνει window messages σε παράθυρα με υψηλότερο IL (παρακάμπτοντας τα UIPI φίλτρα). Σε **ίδιο IL**, οι κλασικές UI primitives όπως `SetWindowsHookEx` **επιτρέπουν injection κώδικα / φόρτωση DLL** σε οποιαδήποτε διεργασία που κατέχει παράθυρο (συμπεριλαμβανομένων των **message-only windows** που χρησιμοποιεί COM).
- Το Admin Protection ξεκινά τη διεργασία UIAccess υπό την ταυτότητα του **limited user** αλλά σε **High IL**, σιωπηρά. Μόλις τρέξει αυθαίρετος κώδικας μέσα σε αυτή τη High-IL διεργασία UIAccess, ο attacker μπορεί να εγχύσει σε άλλες High-IL διεργασίες στο desktop (ακόμα και αν ανήκουν σε διαφορετικούς χρήστες), σπάζοντας την προοριζόμενη απομόνωση.

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Σε Windows 10 1803+ το API μεταφέρθηκε στο Win32k (`NtUserGetWindowProcessHandle`) και μπορεί να ανοίξει ένα process handle χρησιμοποιώντας ένα caller-supplied `DesiredAccess`. Η kernel διαδρομή χρησιμοποιεί `ObOpenObjectByPointer(..., KernelMode, ...)`, που παρακάμπτει τους κανονικούς user-mode ελέγχους πρόσβασης.
- Πρακτικές προϋποθέσεις: το στοχευόμενο παράθυρο πρέπει να βρίσκεται στο ίδιο desktop, και οι UIPI έλεγχοι πρέπει να περάσουν. Ιστορικά, ένας caller με UIAccess μπορούσε να παρακάμψει την αποτυχία UIPI και να λάβει ένα kernel-mode handle (fixed ως CVE-2023-41772).
- Επίπτωση: ένα window handle γίνεται μια **ικανότητα** για να αποκτήσει κάποιος ένα ισχυρό process handle (συνήθως `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) που ο caller κανονικά δεν θα μπορούσε να ανοίξει. Αυτό επιτρέπει cross-sandbox πρόσβαση και μπορεί να σπάσει Protected Process / PPL boundaries αν ο στόχος εκθέτει οποιοδήποτε παράθυρο (συμπεριλαμβανομένων των message-only windows).
- Πρακική ροή κατάχρησης: ανίχνευση ή εντοπισμός HWNDs (π.χ., `EnumWindows`/`FindWindowEx`), επίλυση του κατόχου PID (`GetWindowThreadProcessId`), κλήση `GetProcessHandleFromHwnd`, και μετά χρήση του επιστρεφόμενου handle για memory read/write ή primitives hijack κώδικα.
- Συμπεριφορά μετά το fix: το UIAccess πλέον δεν παρέχει kernel-mode opens όταν η UIPI αποτυγχάνει και τα επιτρεπόμενα δικαιώματα περιορίζονται στο legacy hook set· τα Windows 11 24H2 προσθέτουν ελέγχους process-protection και ασφαλέστερες διαδρομές με feature-flag. Η απενεργοποίηση του UIPI σε όλο το σύστημα (`EnforceUIPI=0`) αποδυναμώνει αυτές τις προστασίες.

## Weaknesses στην επικύρωση secure-directory (AppInfo `AiCheckSecureApplicationDirectory`)
Το AppInfo επιλύει την παρεχόμενη διαδρομή μέσω `GetFinalPathNameByHandle` και στη συνέχεια εφαρμόζει **string allow/deny checks** ενάντια σε hardcoded roots/exclusions. Πολλές κατηγορίες bypass προκύπτουν από αυτή την απλοϊκή επικύρωση:
- **Directory named streams**: Εξαιρεθείσες εγγράψιμες διαδρομές (π.χ., `C:\Windows\tracing`) μπορούν να παρακαμφθούν με ένα named stream στο ίδιο το directory, π.χ. `C:\Windows\tracing:file.exe`. Οι string checks βλέπουν `C:\Windows\` και χάνουν την εξαιρεθείσα υποδιαδρομή.
- **Εγγράψιμο αρχείο/φάκελος μέσα σε επιτρεπόμενη ρίζα**: Το `CreateProcessAsUser` **δεν απαιτεί επέκταση `.exe`**. Η αντικατάσταση οποιουδήποτε εγγράψιμου αρχείου κάτω από μια επιτρεπόμενη ρίζα με payload εκτελέσιμου δουλεύει, ή το αντιγραφή ενός signed `uiAccess="true"` EXE σε οποιοδήποτε εγγράψιμο υποφάκελο (π.χ. update leftovers όπως `Tasks_Migrated` όταν υπάρχει) του επιτρέπει να περάσει τον έλεγχο secure-path.
- **MSIX στο `C:\Program Files\WindowsApps` (fixed)**: Non-admins μπορούσαν να εγκαταστήσουν signed MSIX packages που κατέληγαν στο `WindowsApps`, το οποίο δεν είχε εξαχθεί. Το πακετάρισμα ενός UIAccess binary μέσα στο MSIX και το launch μέσω `RAiLaunchAdminProcess` παρήγαγε μια **χωρίς-prompt High-IL UIAccess διεργασία**. Η Microsoft μείωσε το πρόβλημα εξαιρώντας αυτή τη διαδρομή· η περιορισμένη `uiAccess` MSIX capability από μόνη της ήδη απαιτούσε admin install.

## Attack workflow (High IL χωρίς prompt)
1. Απόκτηση/κατασκευή ενός **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Τοποθέτησή του όπου η allowlist του AppInfo το δέχεται (ή εκμετάλλευση ενός edge case επικύρωσης διαδρομής/εγγράψιμου artifact όπως παραπάνω).
3. Κλήση της `RAiLaunchAdminProcess` για να το spawn-άρει **σιωπηλά** με UIAccess + αυξημένο IL.
4. Από εκείνο το High-IL foothold, στόχευση σε άλλη High-IL διεργασία στο desktop χρησιμοποιώντας **window hooks/DLL injection** ή άλλες same-IL primitives για πλήρη συμβιβασμό του admin context.

## Εντοπισμός υποψήφιων εγγράψιμων διαδρομών
Τρέξτε το PowerShell helper για να ανακαλύψετε εγγράψιμα/επαναγραφόμενα αντικείμενα μέσα σε ονομαστικά secure roots από την οπτική ενός επιλεγμένου token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Εκτελέστε ως Διαχειριστής για μεγαλύτερη ορατότητα· ορίστε το `-ProcessId` σε μια διεργασία με χαμηλά προνόμια για να αντικατοπτρίσετε την πρόσβαση αυτού του token.
- Φιλτράρετε χειροκίνητα ώστε να εξαιρέσετε γνωστούς απαγορευμένους υποκαταλόγους πριν χρησιμοποιήσετε υποψήφιους με το `RAiLaunchAdminProcess`.

## Σχετικά

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Αναφορές
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
