# Παράκαμψεις Προστασίας Διαχειριστή μέσω UIAccess

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση
- Το Windows AppInfo εκθέτει το `RAiLaunchAdminProcess` για να εκκινεί διεργασίες UIAccess (προορίζονται για προσβασιμότητα). Το UIAccess παρακάμπτει το μεγαλύτερο μέρος του φιλτραρίσματος μηνυμάτων του User Interface Privilege Isolation (UIPI) ώστε το λογισμικό προσβασιμότητας να μπορεί να χειρίζεται UI με υψηλότερο IL.
- Η ενεργοποίηση του UIAccess απευθείας απαιτεί `NtSetInformationToken(TokenUIAccess)` με **SeTcbPrivilege**, οπότε κλήτες με χαμηλά προνόμια βασίζονται στην υπηρεσία. Η υπηρεσία εκτελεί τρεις ελέγχους στο στοχευόμενο binary πριν ορίσει το UIAccess:
  - Το ενσωματωμένο manifest περιέχει `uiAccess="true"`.
  - Υπογράφεται από οποιοδήποτε πιστοποιητικό εμπιστεύεται το Local Machine root store (χωρίς απαίτηση EKU/Microsoft).
  - Βρίσκεται σε διαδρομή μόνο για διαχειριστές στο system drive (π.χ. `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, αποκλείοντας συγκεκριμένα εγγράψιμα υπομονοπάτια).
- Το `RAiLaunchAdminProcess` δεν εμφανίζει προτροπή συναίνεσης για εκκινήσεις UIAccess (διαφορετικά τα εργαλεία προσβασιμότητας δεν θα μπορούσαν να αλληλεπιδράσουν με την προτροπή).

## Διαμόρφωση token και επίπεδα ακεραιότητας
- Αν οι έλεγχοι περάσουν, το AppInfo **αντιγράφει το caller token**, ενεργοποιεί το UIAccess και αυξάνει το Integrity Level (IL):
  - Limited admin user (ο χρήστης είναι στους Administrators αλλά τρέχει φιλτραρισμένα) ➜ **High IL**.
  - Μη-admin χρήστης ➜ IL αυξάνεται κατά **+16 levels** μέχρι το όριο **High** (το System IL δεν αποδίδεται ποτέ).
- Αν το caller token ήδη έχει UIAccess, το IL παραμένει αμετάβλητο.
- “Ratchet” trick: μια διεργασία UIAccess μπορεί να απενεργοποιήσει το UIAccess στον εαυτό της, να ξαναεκκινήσει μέσω του `RAiLaunchAdminProcess`, και να κερδίσει ακόμα +16 IL. Medium➜High απαιτεί 255 επανεκκινήσεις (θορυβώδες, αλλά λειτουργεί).

## Γιατί το UIAccess επιτρέπει παράκαμψη του Admin Protection
- Το UIAccess επιτρέπει σε διεργασία με χαμηλότερο IL να στέλνει window messages σε παράθυρα με υψηλότερο IL (παρακάμπτοντας τα φίλτρα UIPI). Σε ίσο IL, κλασικές UI primitive όπως το `SetWindowsHookEx` **do allow code injection/DLL loading** σε οποιαδήποτε διεργασία που κατέχει παράθυρο (συμπεριλαμβανομένων των **message-only windows** που χρησιμοποιεί το COM).
- Το Admin Protection εκκινεί τη διεργασία UIAccess υπό την ταυτότητα του **limited user** αλλά σε **High IL**, αθόρυβα. Μόλις τρέξει αυθαίρετος κώδικας μέσα σε αυτήν τη High-IL διεργασία UIAccess, ο επιτιθέμενος μπορεί να κάνει injection σε άλλες High-IL διεργασίες στο desktop (ακόμα και αν ανήκουν σε διαφορετικούς χρήστες), σπάζοντας την επιδιωκόμενη απομόνωση.

## Αδυναμίες στην επικύρωση ασφαλούς καταλόγου (AppInfo `AiCheckSecureApplicationDirectory`)
Το AppInfo επιλύει την παρεχόμενη διαδρομή με `GetFinalPathNameByHandle` και μετά εφαρμόζει **string allow/deny checks** απέναντι σε hardcoded ρίζες/εξαιρέσεις. Πολλές κατηγορίες bypass προέρχονται από αυτή την απλοϊκή επικύρωση:
- **Directory named streams**: Αποκλεισμένοι εγγράψιμοι κατάλογοι (π.χ. `C:\Windows\tracing`) μπορούν να παρακαμφθούν με named stream στον ίδιο τον κατάλογο, π.χ. `C:\Windows\tracing:file.exe`. Οι έλεγχοι συμβολοσειράς βλέπουν `C:\Windows\` και χάνουν το εξαιρούμενο υπομονοπάτι.
- **Writable file/directory inside an allowed root**: Το `CreateProcessAsUser` **δεν απαιτεί επέκταση `.exe`**. Η αντικατάσταση οποιουδήποτε εγγράψιμου αρχείου κάτω από μια επιτρεπόμενη ρίζα με εκτελέσιμο payload λειτουργεί, ή η αντιγραφή ενός υπογεγραμμένου EXE με `uiAccess="true"` σε οποιοδήποτε εγγράψιμο υποφάκελο (π.χ. υπολείμματα ενημέρωσης όπως `Tasks_Migrated` όταν υπάρχουν) το αφήνει να περάσει τον έλεγχο ασφαλούς διαδρομής.
- **MSIX into `C:\Program Files\WindowsApps` (fixed)**: Μη-admin χρήστες μπορούσαν να εγκαταστήσουν υπογεγραμμένα πακέτα MSIX που τοποθετούνταν στο `WindowsApps`, το οποίο δεν ήταν εξαιρεμένο. Η συσκευασία ενός UIAccess binary μέσα στο MSIX και η εκκίνησή του μέσω `RAiLaunchAdminProcess` παρήγαγε μια **promptless High-IL UIAccess process**. Η Microsoft μείωσε το πρόβλημα αποκλείοντας αυτή τη διαδρομή· η περιορισμένη MSIX δυνατότητα `uiAccess` απαιτεί ήδη admin εγκατάσταση.

## Workflow επίθεσης (High IL χωρίς προτροπή)
1. Αποκτήστε/δημιουργήστε ένα **signed UIAccess binary** (manifest `uiAccess="true"`).
2. Τοποθετήστε το εκεί που το allowlist του AppInfo το δέχεται (ή εκμεταλλευτείτε ένα edge case/εγγράψιμο artifact όπως παραπάνω).
3. Καλέστε `RAiLaunchAdminProcess` για να το εκκινήσετε **σιωπηλά** με UIAccess + αυξημένο IL.
4. Από εκείνο το High-IL foothold, στοχεύστε άλλη High-IL διεργασία στο desktop χρησιμοποιώντας **window hooks/DLL injection** ή άλλα same-IL primitives για να πλήρως συμβιβαστεί το context του admin.

## Εντοπισμός υποψήφιων εγγράψιμων διαδρομών
Τρέξτε το PowerShell helper για να ανακαλύψετε εγγράψιμα/αντικαταστάσιμα αντικείμενα μέσα σε ονομαστικά ασφαλείς ρίζες από την οπτική γωνία ενός επιλεγμένου token:
```powershell
$paths = "C:\\Windows","C:\\Program Files","C:\\Program Files (x86)"
Get-AccessibleFile -Win32Path $paths -Access Execute,WriteData `
-DirectoryAccess AddFile -Recurse -ProcessId <PID>
```
- Εκτελέστε ως Administrator για ευρύτερη ορατότητα· ορίστε `-ProcessId` σε μια διεργασία με χαμηλά προνόμια για να αντικατοπτρίσετε την πρόσβαση αυτού του token.
- Φιλτράρετε χειροκίνητα για να εξαιρέσετε γνωστούς απαγορευμένους υποκαταλόγους πριν χρησιμοποιήσετε υποψηφίους με `RAiLaunchAdminProcess`.

## Αναφορές
- [Bypassing Administrator Protection by Abusing UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
