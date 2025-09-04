# Missbrauch von Enterprise-Auto-Updaters und privilegiertem IPC (z. B. Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows Local Privilege Escalation-Ketten, die in Enterprise‑Endpoint‑Agents und Updaters gefunden werden und eine niedrigschwellige IPC‑Schnittstelle sowie einen privilegierten Update‑Flow bereitstellen. Ein repräsentatives Beispiel ist Netskope Client for Windows < R129 (CVE-2025-0309), bei dem ein niedrig privilegierter Benutzer eine Registrierung zu einem vom Angreifer kontrollierten Server erzwingen und anschließend ein bösartiges MSI ausliefern kann, das der SYSTEM‑Dienst installiert.

Wesentliche Ideen, die Sie gegen ähnliche Produkte wiederverwenden können:
- Missbrauche die localhost‑IPC eines privilegierten Dienstes, um eine Re‑Enrollment oder Neukonfiguration zu einem Angreifer‑Server zu erzwingen.
- Implementiere die Update‑Endpoints des Vendors, liefere ein bösartiges Trusted Root CA und weise den Updater auf ein bösartiges, „signiertes“ Paket.
- Umgehe schwache Signer‑Checks (CN allow‑lists), optionale Digest‑Flags und lax konfigurierte MSI‑Eigenschaften.
- Falls IPC „verschlüsselt“ ist, leite den key/IV aus für alle lesbaren Maschinenidentifikatoren ab, die in der Registry gespeichert sind.
- Falls der Service Anrufer nach image path/process name einschränkt, injiziere in einen allow‑listed Prozess oder starte einen Prozess im suspended‑Zustand und bootstrappe deine DLL via einen minimalen thread‑context patch.

---
## 1) Erzwingen der Enrollment zu einem Angreifer‑Server über localhost IPC

Viele Agenten enthalten einen User‑Mode UI‑Prozess, der über localhost TCP mit einem SYSTEM‑Dienst mittels JSON kommuniziert.

Beobachtet in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit‑Ablauf:
1) Erstelle ein JWT‑Enrollment‑Token, dessen Claims den Backend‑Host steuern (z. B. AddonUrl). Verwende alg=None, sodass keine Signatur erforderlich ist.
2) Sende die IPC‑Nachricht, die den Provisioning‑Befehl mit deinem JWT und Tenant‑Namen aufruft:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der Service beginnt, deinen rogue server für enrollment/config anzusprechen, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- If caller verification is path/name‑based, originate the request from a allow‑listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sobald der client mit deinem server spricht, implementiere die erwarteten endpoints und lenke ihn auf ein attacker MSI. Typische Sequenz:

1) /v2/config/org/clientconfig → Gib eine JSON config mit einem sehr kurzen updater interval zurück, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gibt ein PEM-CA-Zertifikat zurück. Der Dienst installiert es im Local Machine Trusted Root store.
3) /v2/checkupdate → Liefert Metadaten, die auf ein bösartiges MSI und eine gefälschte Version verweisen.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: der Dienst prüft möglicherweise nur, ob der Subject CN gleich „netSkope Inc“ oder „Netskope, Inc.“ ist. Deine Rogue-CA kann ein Leaf mit diesem CN ausstellen und das MSI signieren.
- CERT_DIGEST property: Füge eine harmlose MSI‑Property namens CERT_DIGEST hinzu. Keine Durchsetzung beim Install.
- Optional digest enforcement: ein Config‑Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Result: der SYSTEM‑Dienst installiert dein MSI aus
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.

---
## 3) Forging encrypted IPC requests (when present)

Ab R127 hat Netskope IPC‑JSON in ein encryptData‑Feld verpackt, das wie Base64 aussieht. Reverse‑Engineering zeigte AES mit Key/IV, die aus Registry‑Werten abgeleitet werden, die von jedem Benutzer gelesen werden können:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung reproduzieren und gültige verschlüsselte Befehle von einem Standardbenutzer senden. Allgemeiner Tipp: wenn ein Agent plötzlich seine IPC „verschlüsselt“, suche nach device IDs, product GUIDs, install IDs unter HKLM als Material.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Einige Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP‑Verbindung auflösen und den Image‑Path/Name gegen allow‑gelistete Vendor‑Binaries unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Bypässe:
- DLL‑Injection in einen allow‑gelisteten Prozess (z. B. nsdiag.exe) und Proxy‑IPC von innen heraus.
- Starte ein allow‑gelistetes Binary im Suspended‑Zustand und bootstrappe deine Proxy‑DLL ohne CreateRemoteThread (siehe §5), um driver‑enforced Tamper‑Regeln zu erfüllen.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Produkte bringen oft einen minifilter/OB callbacks Driver (z. B. Stadrv) mit, der gefährliche Rechte von Handles zu geschützten Prozessen entfernt:
- Process: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User‑Mode Loader, der diese Einschränkungen respektiert:
1) CreateProcess eines Vendor‑Binaries mit CREATE_SUSPENDED.
2) Hole die Handles, die du noch darfst: PROCESS_VM_WRITE | PROCESS_VM_OPERATION für den Prozess und ein Thread‑Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du Code an einer bekannten RIP patchst).
3) Überschreibe ntdll!NtContinue (oder einen anderen frühen, garantiert gemappten Thunk) mit einem kleinen Stub, der LoadLibraryW auf deinem DLL‑Pfad aufruft und dann zurückspringt.
4) ResumeThread, um deinen Stub im Prozess auszulösen und deine DLL zu laden.

Weil du nie PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME auf einem bereits geschützten Prozess verwendet hast (du hast ihn erstellt), ist die Policy des Drivers erfüllt.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatisiert eine Rogue‑CA, bösartiges MSI‑Signing und bedient die benötigten Endpunkte: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ist ein custom IPC‑Client, der beliebige (optional AES‑verschlüsselte) IPC‑Nachrichten erzeugt und die suspended‑process Injection enthält, um von einem allow‑gelisteten Binary auszugehen.

---
## 7) Detection opportunities (blue team)
- Überwache Hinzufügungen zum Local Machine Trusted Root. Sysmon + registry‑mod Eventing (siehe SpecterOps Guidance) funktioniert gut.
- Flagge MSI‑Ausführungen, die vom Agent‑Service aus Pfaden wie C:\ProgramData\<vendor>\<agent>\data\*.msi initiiert werden.
- Prüfe Agent‑Logs auf unerwartete Enrollment‑Hosts/Tenants, z. B.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – achte auf addonUrl / tenant‑Anomalien und provisioning msg 148.
- Alarmiere bei localhost‑IPC‑Clients, die nicht die erwarteten signed Binaries sind oder aus ungewöhnlichen Child‑Process‑Trees stammen.

---
## Hardening tips for vendors
- Binde Enrollment/Update‑Hosts an eine strikte Allow‑List; lehne untrusted Domains im clientcode ab.
- Authentifiziere IPC‑Peers mit OS‑Primitiven (ALPC security, named‑pipe SIDs) statt mit Image‑Path/Name‑Checks.
- Halte geheime Materialien aus weltlesbarem HKLM; wenn IPC verschlüsselt werden muss, leite Keys aus geschützten Secrets ab oder verhandle über authentifizierte Kanäle.
- Betrachte den Updater als Supply‑Chain‑Surface: require eine vollständige Chain zu einer trusted CA, die du kontrollierst, verifiziere Package‑Signaturen gegen gepinnte Keys und fail closed, wenn die Validierung in der Config deaktiviert ist.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
