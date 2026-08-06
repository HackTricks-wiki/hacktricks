# Bypasses του Admin Protection μέσω UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση
- Το Windows AppInfo εκθέτει το `RAiLaunchAdminProcess` για τη δημιουργία UIAccess processes (με σκοπό την προσβασιμότητα). Το UIAccess παρακάμπτει το μεγαλύτερο μέρος του φιλτραρίσματος μηνυμάτων του User Interface Privilege Isolation (UIPI), ώστε το λογισμικό προσβασιμότητας να μπορεί να χειρίζεται UI υψηλότερου IL.
- Η άμεση ενεργοποίηση του UIAccess απαιτεί `NtSetInformationToken(TokenUIAccess)` με **SeTcbPrivilege**, επομένως οι callers με χαμηλά privileges βασίζονται στο service. Το service εκτελεί τρεις ελέγχους στο target binary πριν ενεργοποιήσει το UIAccess:
- Το embedded manifest περιέχει `uiAccess="true"`.
- Είναι υπογεγραμμένο με οποιοδήποτε certificate που είναι trusted από το Local Machine root store (χωρίς απαίτηση για EKU/Microsoft).
- Βρίσκεται σε path του administrator-only στο system drive (π.χ. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`), εξαιρουμένων συγκεκριμένων writable subpaths.
- Το `RAiLaunchAdminProcess` δεν εμφανίζει consent prompt για UIAccess launches (διαφορετικά τα accessibility tools δεν θα μπορούσαν να χειριστούν το prompt).<sup>[[1]](#references)</sup>

## Token shaping και integrity levels
- Αν οι έλεγχοι επιτύχουν, το AppInfo **αντιγράφει το caller token**, ενεργοποιεί το UIAccess και αυξάνει το Integrity Level (IL):
- Limited admin user (ο user ανήκει στους Administrators αλλά εκτελείται με filtered token) ➜ **High IL**.
- Non-admin user ➜ αύξηση του IL κατά **+16 levels**, έως το όριο **High** (το System IL δεν εκχωρείται ποτέ).
- Αν το caller token έχει ήδη UIAccess, το IL παραμένει αμετάβλητο.
- Trick “Ratchet”: ένα UIAccess process μπορεί να απενεργοποιήσει το UIAccess στον εαυτό του, να κάνει relaunch μέσω `RAiLaunchAdminProcess` και να κερδίσει άλλη μία αύξηση IL κατά +16 levels. Η μετάβαση Medium➜High απαιτεί 255 relaunches (θορυβώδες, αλλά λειτουργεί).<sup>[[1]](#references)</sup>

## Γιατί το UIAccess επιτρέπει διαφυγή από το Admin Protection
- Το UIAccess επιτρέπει σε ένα process χαμηλότερου IL να στέλνει window messages σε windows υψηλότερου IL (παρακάμπτοντας τα UIPI filters). Σε **ίδιο IL**, κλασικά UI primitives όπως το `SetWindowsHookEx` **επιτρέπουν code injection/DLL loading** σε οποιοδήποτε process διαθέτει window (συμπεριλαμβανομένων των **message-only windows** που χρησιμοποιούνται από το COM).
- Το Admin Protection εκκινεί το UIAccess process με την identity του **limited user**, αλλά σε **High IL**, αθόρυβα. Μόλις εκτελεστεί arbitrary code μέσα σε αυτό το High-IL UIAccess process, ο attacker μπορεί να κάνει inject σε άλλα High-IL processes στο desktop (ακόμη και αν ανήκουν σε διαφορετικούς users), παραβιάζοντας τον προβλεπόμενο διαχωρισμό.<sup>[[1]](#references)</sup>

## HWND-to-process handle primitive (`GetProcessHandleFromHwnd` / `NtUserGetWindowProcessHandle`)
- Στα Windows 10 1803+ το API μεταφέρθηκε στο Win32k (`NtUserGetWindowProcessHandle`) και μπορεί να ανοίξει process handle χρησιμοποιώντας ένα `DesiredAccess` που παρέχεται από τον caller. Η kernel path χρησιμοποιεί `ObOpenObjectByPointer(..., KernelMode, ...)`, παρακάμπτοντας τους κανονικούς access checks του user mode.<sup>[[2]](#references)</sup>
- Προϋποθέσεις στην πράξη: το target window πρέπει να βρίσκεται στο ίδιο desktop και οι UIPI checks πρέπει να επιτύχουν. Ιστορικά, ένας caller με UIAccess μπορούσε να παρακάμψει το UIPI failure και να αποκτήσει kernel-mode handle (διορθώθηκε ως CVE-2023-41772).
- Impact: ένα window handle γίνεται **capability** για την απόκτηση ενός ισχυρού process handle (συνήθως `PROCESS_DUP_HANDLE`, `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`) το οποίο ο caller κανονικά δεν θα μπορούσε να ανοίξει. Αυτό επιτρέπει cross-sandbox access και μπορεί να παραβιάσει τα όρια Protected Process / PPL, αν το target εκθέτει οποιοδήποτε window (συμπεριλαμβανομένων των message-only windows).
- Practical abuse flow: enumerate ή εντόπισε HWNDs (π.χ. `EnumWindows`/`FindWindowEx`), επίλυσε το owning PID (`GetWindowThreadProcessId`), κάλεσε `GetProcessHandleFromHwnd` και στη συνέχεια χρησιμοποίησε το returned handle για memory read/write ή code-hijack primitives.
- Post-fix behavior: το UIAccess δεν παρέχει πλέον kernel-mode opens σε περίπτωση UIPI failure και τα επιτρεπόμενα access rights περιορίζονται στο legacy hook set. Τα Windows 11 24H2 προσθέτουν process-protection checks και ασφαλέστερα paths μέσω feature flags. Η καθολική απενεργοποίηση του UIPI (`EnforceUIPI=0`) αποδυναμώνει αυτές τις protections.<sup>[[2]](#references)</sup>

## Αδυναμίες secure-directory validation (AppInfo `AiCheckSecureApplicationDirectory`)
Το AppInfo επιλύει το supplied path μέσω `GetFinalPathNameByHandle` και στη συνέχεια εφαρμόζει **string allow/deny checks** σε hardcoded roots/exclusions. Πολλαπλές κατηγορίες bypass προκύπτουν από αυτό το απλοϊκό validation:
- **Directory named streams**: Writable directories που εξαιρούνται (π.χ. `C:\Windows\tracing`) μπορούν να παρακαμφθούν με named stream στο ίδιο το directory, π.χ. `C:\Windows\tracing:file.exe`. Τα string checks βλέπουν το `C:\Windows\` και δεν εντοπίζουν το excluded subpath.
- **Writable file/directory μέσα σε allowed root**: Το `CreateProcessAsUser` **δεν απαιτεί extension `.exe`**. Η αντικατάσταση οποιουδήποτε writable file κάτω από allowed root με executable payload λειτουργεί, ή η αντιγραφή ενός signed EXE με `uiAccess="true"` σε οποιοδήποτε writable subdirectory (π.χ. update leftovers όπως το `Tasks_Migrated`, όταν υπάρχει) του επιτρέπει να περάσει το secure-path check.
- **MSIX στο `C:\Program Files\WindowsApps` (διορθώθηκε)**: Non-admins μπορούσαν να εγκαταστήσουν signed MSIX packages που κατέληγαν στο `WindowsApps`, το οποίο δεν εξαιρούνταν. Η συσκευασία ενός UIAccess binary μέσα στο MSIX και στη συνέχεια η εκκίνησή του μέσω `RAiLaunchAdminProcess` παρείχε ένα **promptless High-IL UIAccess process**. Η Microsoft μετρίασε το ζήτημα εξαιρώντας αυτό το path· το ίδιο το `uiAccess` restricted MSIX capability απαιτεί ήδη admin install.<sup>[[1]](#references)</sup>

## Attack workflow (High IL χωρίς prompt)
1. Απόκτησε/κατασκεύασε ένα **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Τοποθέτησέ το σε σημείο που αποδέχεται το allowlist του AppInfo (ή εκμεταλλεύσου ένα path-validation edge case/writable artifact όπως παραπάνω).
3. Κάλεσε το `RAiLaunchAdminProcess` για να το εκκινήσεις **σιωπηλά** με UIAccess + elevated IL.
4. Από αυτό το High-IL foothold, στόχευσε ένα άλλο High-IL process στο desktop χρησιμοποιώντας **window hooks/DLL injection** ή άλλα same-IL primitives, ώστε να compromιστεί πλήρως το admin context.<sup>[[1]](#references)</sup>

## Enumerating candidate writable paths
Εκτέλεσε το PowerShell helper για να εντοπίσεις writable/overwritable objects μέσα σε nominally secure roots από την οπτική γωνία ενός επιλεγμένου token:<sup>[[1]](#references)</sup>
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Εκτελέστε ως Administrator για ευρύτερη ορατότητα· ορίστε το `-ProcessId` σε μια διεργασία με χαμηλά δικαιώματα, ώστε να αναπαραγάγετε την πρόσβαση του token της.
- Φιλτράρετε χειροκίνητα για να εξαιρέσετε γνωστούς μη επιτρεπόμενους υποκαταλόγους πριν χρησιμοποιήσετε τους υποψήφιους με το `RAiLaunchAdminProcess`.

## Σχετικά

Secure Desktop accessibility registry propagation LPE (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Αναφορές

- [1] [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [2] [GetProcessHandleFromHwnd (GPHFH) Deep Dive](https://projectzero.google/2026/02/gphfh-deep-dive.html)

{{#include ../../banners/hacktricks-training.md}}
