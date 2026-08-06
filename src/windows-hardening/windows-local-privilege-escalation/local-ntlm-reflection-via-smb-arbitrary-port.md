# Lokale NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Neuere Windows-Builds führten **SMB client support for alternative TCP ports** ein. Diese Funktion kann missbraucht werden, um **lokale NTLM authentication** in eine **lokale SYSTEM privilege escalation** umzuwandeln, wenn der Angreifer Folgendes kann:<sup>[[1]](#references)</sup>

1. Eine SMB-Verbindung zu einem vom Angreifer kontrollierten Listener auf einem **nicht-445-Port** öffnen
2. Diese TCP-Verbindung offen halten
3. Einen **privilegierten lokalen Client** dazu zwingen, auf denselben **SMB share path** zuzugreifen
4. Die daraus resultierende **lokale NTLM authentication** zurück an den echten SMB service des Rechners relayen

Dies ist das Primitive hinter **CVE-2026-24294**, das im **März 2026** gepatcht wurde.<sup>[[1]](#references)[[4]](#references)</sup>

## Warum es funktioniert

Der ältere CMTI / serialized-SPN reflection trick wird hier behandelt:

{{#ref}}
../ntlm/README.md
{{#endref}}

Diese neuere Variante benötigt keinen marshalled hostname. Stattdessen missbraucht sie zwei Verhaltensweisen des SMB clients:<sup>[[1]](#references)</sup>

- **Alternative port support** auf **Windows 11 24H2** und **Windows Server 2025**, für Benutzer verfügbar über `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, wobei mehrere authentifizierte Sessions dieselbe TCP-Verbindung verwenden können

Das bedeutet, dass ein Benutzer mit niedrigen Privilegien zunächst eine TCP-Verbindung vom SMB client zu einem SMB server des Angreifers auf einem hohen Port herstellen kann und anschließend einen privilegierten service dazu zwingen kann, auf den **exakt gleichen UNC path** zuzugreifen. Wenn Windows entscheidet, die bestehende TCP-Verbindung wiederzuverwenden, wird der privilegierte NTLM-Austausch über den vom Angreifer kontrollierten Transport gesendet und kann an den lokalen SMB server relayed werden.<sup>[[1]](#references)</sup>

## Voraussetzungen

- Das Target unterstützt SMB alternative ports:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** oder neuer
- **Windows Server 2025** oder neuer
- Der Angreifer kann einen lokalen oder remote SMB server auf einem ausgewählten hohen Port ausführen
- Der Angreifer kann einen privilegierten service dazu zwingen, auf einen UNC path zuzugreifen
- Die privilegierte authentication muss **lokale NTLM authentication** sein
- Das Target muss relayable sein:<sup>[[1]](#references)</sup>
- Synacktiv berichtete, dass dies standardmäßig auf **Windows Server 2025** funktionierte
- Ihre chain funktionierte nicht auf **Windows 11 24H2**, da ausgehendes SMB signing dort standardmäßig erzwungen wird

## Userland und Internals

Über die command line wirkt die Funktion einfach:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programmgesteuert verwendet der Client `WNetAddConnection4W` mit undokumentierten `lpUseOptions`-Daten. Die relevante Option ist `TraP` (Transportparameter), die schließlich über ein FSCTL den Kernel-SMB-Client erreicht und von `mrxsmb` verarbeitet wird.<sup>[[1]](#references)[[3]](#references)</sup>

Wichtige praktische Hinweise:<sup>[[1]](#references)</sup>

- **Die UNC-Syntax enthält weiterhin kein Portfeld**
- **`net use` gilt pro Logon-Session**
- Der Bypass funktioniert weiterhin, weil **die TCP-Verbindung und die SMB-Session separate Objekte sind**
- Die **Verwendung desselben Share-Pfads** ist zwingend erforderlich, wenn der Exploit davon abhängt, dass der SMB-Client die zuvor erstellte TCP-Verbindung wiederverwendet

## Ablauf der Exploitation

### 1. Den vom Angreifer kontrollierten SMB-Transport erstellen

Starte einen SMB-Server auf einem hohen Port und veranlasse Windows, eine Verbindung zu ihm herzustellen:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Der Server kann jedes von dir kontrollierte Anmeldeinformationspaar akzeptieren, zum Beispiel `user:user`. Das Ziel dieses Schritts ist noch keine Privilege Escalation, sondern lediglich, den Windows-SMB-Client dazu zu bringen, eine wiederverwendbare TCP-Verbindung zu deinem Listener zu öffnen und aufrechtzuerhalten.<sup>[[1]](#references)</sup>

### 2. Einen privilegierten Dienst zum gleichen UNC-Pfad zwingen

Verwende ein Coercion-Primitive wie **PetitPotam** gegen denselben Pfad `\\192.168.56.3\share`. Wenn der erzwungene Client privilegiert ist und der Zielname lokal ist (`localhost` oder eine lokale IP-Adresse bzw. ein lokaler Host), führt Windows eine **NTLM local authentication** durch.

Da die TCP-Verbindung wiederverwendet wird, wird dieser privilegierte NTLM-Austausch an den SMB-Dienst des Angreifers statt direkt an den echten lokalen SMB-Server gesendet.<sup>[[1]](#references)</sup>

### 3. Die privilegierte Authentifizierung zurück an den lokalen SMB-Dienst relayn

Der vom Angreifer kontrollierte SMB-Dienst leitet den privilegierten NTLM-Austausch an `ntlmrelayx.py` weiter. Dieses relayed ihn an den echten SMB-Listener des Rechners und erhält eine Sitzung als `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Typische Tools aus der öffentlichen Beschreibung:<sup>[[1]](#references)</sup>

- `smbserver.py` an einem benutzerdefinierten Port, um die privilegierte Authentifizierung über die wiederverwendete TCP-Verbindung zu empfangen
- `ntlmrelayx.py`, um das abgefangene NTLM an den lokalen SMB-Dienst zu relayn
- `PetitPotam.exe` oder ein anderes Coercion-Primitive, um die privilegierte Authentifizierung zu erzwingen

## Hinweise für Operatoren

- Dies ist eine Technik zur **local privilege escalation**, kein allgemeiner Remote-Relay-Trick<sup>[[1]](#references)</sup>
- Der vom Angreifer kontrollierte SMB-Dienst muss die privilegierte Authentifizierung auf derselben **TCP-Verbindung** verarbeiten, die ursprünglich für das Einbinden der Freigabe verwendet wurde<sup>[[1]](#references)</sup>
- Wenn der erzwungene Zugriff einen **anderen Freigabepfad** erreicht, erstellt Windows möglicherweise eine andere Verbindung und die Kette bricht ab<sup>[[1]](#references)</sup>
- Anforderungen an SMB signing können das Relay verhindern, selbst wenn der Schritt mit dem benutzerdefinierten Port funktioniert<sup>[[1]](#references)</sup>
- Wenn du nur Kerberos-Material besitzt oder kein lokales NTLM erzwingen kannst, reicht diese Variante allein nicht aus<sup>[[1]](#references)</sup>

## Erkennung und Härtung

- **CVE-2026-24294** aus dem **Patch Tuesday im März 2026** patchen<sup>[[4]](#references)</sup>
- Auf `net use` oder `New-SmbMapping` achten, die **nicht standardmäßige SMB-Ports** verwenden<sup>[[1]](#references)</sup>
- Bei ungewöhnlichem ausgehendem SMB-Datenverkehr von Workstations oder Servern zu **hohen TCP-Ports** alarmieren<sup>[[1]](#references)</sup>
- Coercion-Möglichkeiten wie **EFSRPC-/PetitPotam-ähnliche** Trigger überprüfen<sup>[[1]](#references)</sup>
- SMB signing nach Möglichkeit erzwingen; Synacktiv weist ausdrücklich darauf hin, dass dies ihr Relay unter Windows 11 24H2 blockierte<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
