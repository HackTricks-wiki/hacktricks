# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Neuere Windows-Builds haben **SMB client support for alternative TCP ports** eingeführt. Diese Funktion kann missbraucht werden, um **local NTLM authentication** in eine **SYSTEM local privilege escalation** umzuwandeln, wenn der Angreifer:

1. Eine SMB connection zu einem attacker-controlled listener auf einem **non-445 port** öffnen kann
2. Diese TCP connection am Leben hält
3. Einen **privileged local client** dazu bringt, denselben **SMB share path** zu öffnen
4. Die resultierende **local NTLM authentication** zurück zum echten SMB service der Maschine relayed

Das ist die Primitive hinter **CVE-2026-24294**, gepatcht in **March 2026**.

## Why it works

Der ältere CMTI / serialized-SPN reflection trick ist hier beschrieben:

{{#ref}}
../ntlm/README.md
{{#endref}}

Diese neuere Variante braucht **keinen marshalled hostname**. Stattdessen missbraucht sie zwei SMB client behaviours:

- **Alternative port support** unter **Windows 11 24H2** und **Windows Server 2025**, erreichbar für Benutzer mit `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, bei dem mehrere authenticated sessions über dieselbe TCP connection laufen können

Das bedeutet, ein low-privileged user kann zuerst eine TCP connection vom SMB client zu einem attacker SMB server auf einem hohen Port erstellen und dann einen privileged service dazu bringen, auf denselben **UNC path** zuzugreifen. Wenn Windows entscheidet, die bestehende TCP connection wiederzuverwenden, wird der privileged NTLM exchange über den attacker-controlled transport gesendet und kann an den lokalen SMB server relayed werden.

## Preconditions

- Target unterstützt SMB alternative ports:
- **Windows 11 24H2** oder neuer
- **Windows Server 2025** oder neuer
- Der Angreifer kann einen lokalen oder entfernten SMB server auf einem gewählten hohen Port betreiben
- Der Angreifer kann einen privileged service dazu bringen, auf einen UNC path zuzugreifen
- Die privileged authentication muss **NTLM local authentication** sein
- Das Target muss relayable sein:
- Synacktiv berichtete, dass es standardmäßig auf **Windows Server 2025** funktionierte
- Ihre chain funktionierte **nicht** auf **Windows 11 24H2**, weil dort outbound SMB signing standardmäßig erzwungen wird

## Userland and internals

Von der command line aus sieht die Funktion einfach aus:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmgesteuert verwendet der Client `WNetAddConnection4W` mit undokumentierten `lpUseOptions`-Daten. Die relevante Option ist `TraP` (transport parameters), die schließlich über ein FSCTL den Kernel-SMB-Client erreicht und von `mrxsmb` geparst wird.

Wichtige praktische Hinweise:

- **UNC-Syntax hat weiterhin kein Port-Feld**
- **`net use` ist pro Logon-Session**
- Der Bypass funktioniert weiterhin, weil **die TCP-Verbindung und die SMB-Session separate Objekte sind**
- Die Wiederverwendung desselben **Share-Pfads** ist zwingend erforderlich, wenn der Exploit davon abhängt, dass der SMB-Client die zuvor erstellte TCP-Verbindung wiederverwendet

## Exploitation flow

### 1. Erstelle den vom Angreifer kontrollierten SMB-Transport

Starte einen SMB-Server auf einem hohen Port und lasse Windows sich damit verbinden:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Der Server kann jedes Credential-Paar akzeptieren, das du kontrollierst, zum Beispiel `user:user`. Das Ziel dieses Schritts ist noch nicht Privilege Escalation, sondern nur, den Windows SMB Client dazu zu bringen, eine wiederverwendbare TCP-Verbindung zu deinem Listener zu öffnen und offen zu halten.

### 2. Einen privilegierten Dienst auf denselben UNC-Pfad zwingen

Verwende einen Coercion-Primitive wie **PetitPotam** gegen denselben `\\192.168.56.3\share`-Pfad. Wenn der erzwungene Client privilegiert ist und der Zielname lokal ist (`localhost` oder eine lokale IP/ein lokaler Host), führt Windows **NTLM local authentication** aus.

Da die TCP-Verbindung wiederverwendet wird, läuft dieser privilegierte NTLM-Austausch zum SMB-Service des Angreifers statt direkt zum echten lokalen SMB-Server.

### 3. Die privilegierte Authentifizierung zurück an lokales SMB relayn

Der vom Angreifer kontrollierte SMB-Service leitet den privilegierten NTLM-Austausch an `ntlmrelayx.py` weiter, das ihn an den echten SMB Listener des Systems relayed und eine Session als `NT AUTHORITY\SYSTEM` erhält.

Typische Tools aus dem öffentlichen Writeup:

- `smbserver.py` auf einem benutzerdefinierten Port, um die privilegierte Auth über die wiederverwendete TCP-Verbindung zu empfangen
- `ntlmrelayx.py`, um das abgefangene NTLM an lokales SMB zu relayn
- `PetitPotam.exe` oder ein anderer Coercion-Primitive, um die privilegierte Authentifizierung zu erzwingen

## Operator Notes

- Dies ist eine **local privilege escalation**-Technik, kein generischer Remote-Relay-Trick
- Der vom Angreifer kontrollierte SMB-Service muss die privilegierte Authentifizierung über **dieselbe TCP-Verbindung** verarbeiten, die ursprünglich für das Share-Mounting verwendet wurde
- Wenn der erzwungene Zugriff einen **anderen Share-Pfad** trifft, kann Windows eine andere Verbindung aufbauen und die Kette bricht
- SMB-Signing-Anforderungen können das Relay verhindern, selbst wenn der arbitrary-port-Schritt funktioniert
- Wenn du nur Kerberos-Material hast oder kein lokales NTLM erzwingen kannst, reicht diese exakte Variante nicht aus

## Detection and hardening

- Patche **CVE-2026-24294** aus dem **March 2026 Patch Tuesday**
- Achte auf `net use` oder `New-SmbMapping` mit **nicht-standardmäßigen SMB-Ports**
- Alarmiere bei ungewöhnlichem ausgehendem SMB von Workstations oder Servern zu **hohen TCP-Ports**
- Prüfe Coercion-Möglichkeiten wie **EFSRPC / PetitPotam-style**-Trigger
- Erzwinge SMB signing, wo möglich; Synacktiv merkt speziell an, dass dies ihr Relay auf Windows 11 24H2 blockiert hat

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
