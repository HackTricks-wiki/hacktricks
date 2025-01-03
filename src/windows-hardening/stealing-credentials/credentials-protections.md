# Windows Credentials Protections

## Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Das [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) Protokoll, das mit Windows XP eingeführt wurde, ist für die Authentifizierung über das HTTP-Protokoll konzipiert und ist **standardmäßig auf Windows XP bis Windows 8.0 und Windows Server 2003 bis Windows Server 2012 aktiviert**. Diese Standardeinstellung führt zu **der Speicherung von Passwörtern im Klartext in LSASS** (Local Security Authority Subsystem Service). Ein Angreifer kann Mimikatz verwenden, um **diese Anmeldeinformationen zu extrahieren**, indem er Folgendes ausführt:
```bash
sekurlsa::wdigest
```
Um diese Funktion **ein- oder auszuschalten**, müssen die _**UseLogonCredential**_ und _**Negotiate**_ Registrierungswerte innerhalb von _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ auf "1" gesetzt werden. Wenn diese Werte **fehlen oder auf "0" gesetzt sind**, ist WDigest **deaktiviert**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA-Schutz

Beginnend mit **Windows 8.1** hat Microsoft die Sicherheit von LSA verbessert, um **nicht autorisierte Speicherlesungen oder Code-Injektionen durch nicht vertrauenswürdige Prozesse zu blockieren**. Diese Verbesserung beeinträchtigt die typische Funktionsweise von Befehlen wie `mimikatz.exe sekurlsa:logonpasswords`. Um **diesen verbesserten Schutz zu aktivieren**, sollte der _**RunAsPPL**_ Wert in _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ auf 1 eingestellt werden:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Es ist möglich, diesen Schutz mit dem Mimikatz-Treiber mimidrv.sys zu umgehen:

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**, eine Funktion, die exklusiv für **Windows 10 (Enterprise- und Education-Editionen)** ist, verbessert die Sicherheit von Maschinenanmeldeinformationen mithilfe von **Virtual Secure Mode (VSM)** und **Virtualization Based Security (VBS)**. Es nutzt CPU-Virtualisierungserweiterungen, um wichtige Prozesse innerhalb eines geschützten Speicherbereichs zu isolieren, der vom Hauptbetriebssystem nicht erreicht werden kann. Diese Isolation stellt sicher, dass selbst der Kernel nicht auf den Speicher in VSM zugreifen kann, wodurch Anmeldeinformationen effektiv vor Angriffen wie **pass-the-hash** geschützt werden. Die **Local Security Authority (LSA)** arbeitet in dieser sicheren Umgebung als Trustlet, während der **LSASS**-Prozess im Hauptbetriebssystem lediglich als Kommunikator mit der LSA von VSM fungiert.

Standardmäßig ist **Credential Guard** nicht aktiv und erfordert eine manuelle Aktivierung innerhalb einer Organisation. Es ist entscheidend für die Verbesserung der Sicherheit gegen Tools wie **Mimikatz**, die in ihrer Fähigkeit, Anmeldeinformationen zu extrahieren, eingeschränkt sind. Allerdings können Schwachstellen weiterhin ausgenutzt werden, indem benutzerdefinierte **Security Support Providers (SSP)** hinzugefügt werden, um Anmeldeinformationen im Klartext während der Anmeldeversuche zu erfassen.

Um den Aktivierungsstatus von **Credential Guard** zu überprüfen, kann der Registrierungsschlüssel _**LsaCfgFlags**_ unter _**HKLM\System\CurrentControlSet\Control\LSA**_ inspiziert werden. Ein Wert von "**1**" zeigt die Aktivierung mit **UEFI-Sperre** an, "**2**" ohne Sperre und "**0**" bedeutet, dass es nicht aktiviert ist. Diese Registrierungskontrolle, obwohl ein starker Indikator, ist nicht der einzige Schritt zur Aktivierung von Credential Guard. Detaillierte Anleitungen und ein PowerShell-Skript zur Aktivierung dieser Funktion sind online verfügbar.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Für ein umfassendes Verständnis und Anleitungen zur Aktivierung von **Credential Guard** in Windows 10 und seiner automatischen Aktivierung in kompatiblen Systemen von **Windows 11 Enterprise und Education (Version 22H2)**, besuchen Sie [Microsofts Dokumentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Weitere Details zur Implementierung benutzerdefinierter SSPs zur Erfassung von Anmeldeinformationen finden Sie in [diesem Leitfaden](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin-Modus

**Windows 8.1 und Windows Server 2012 R2** führten mehrere neue Sicherheitsfunktionen ein, darunter den _**Restricted Admin-Modus für RDP**_. Dieser Modus wurde entwickelt, um die Sicherheit zu erhöhen, indem die Risiken im Zusammenhang mit [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) -Angriffen gemindert werden.

Traditionell werden bei der Verbindung zu einem Remote-Computer über RDP Ihre Anmeldeinformationen auf dem Zielcomputer gespeichert. Dies stellt ein erhebliches Sicherheitsrisiko dar, insbesondere bei der Verwendung von Konten mit erhöhten Rechten. Mit der Einführung des _**Restricted Admin-Modus**_ wird dieses Risiko jedoch erheblich reduziert.

Bei der Initiierung einer RDP-Verbindung mit dem Befehl **mstsc.exe /RestrictedAdmin** erfolgt die Authentifizierung am Remote-Computer, ohne Ihre Anmeldeinformationen darauf zu speichern. Dieser Ansatz stellt sicher, dass im Falle einer Malware-Infektion oder wenn ein böswilliger Benutzer Zugriff auf den Remote-Server erhält, Ihre Anmeldeinformationen nicht gefährdet sind, da sie nicht auf dem Server gespeichert sind.

Es ist wichtig zu beachten, dass im **Restricted Admin-Modus** Versuche, auf Netzwerkressourcen aus der RDP-Sitzung zuzugreifen, nicht Ihre persönlichen Anmeldeinformationen verwenden; stattdessen wird die **Identität des Computers** verwendet.

Dieses Feature stellt einen bedeutenden Fortschritt bei der Sicherung von Remote-Desktop-Verbindungen dar und schützt sensible Informationen vor der Offenlegung im Falle eines Sicherheitsvorfalls.

![](../../images/RAM.png)

Für detailliertere Informationen besuchen Sie [diese Ressource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Zwischengespeicherte Anmeldeinformationen

Windows sichert **Domänenanmeldeinformationen** über die **Local Security Authority (LSA)** und unterstützt Anmeldeprozesse mit Sicherheitsprotokollen wie **Kerberos** und **NTLM**. Ein wichtiges Merkmal von Windows ist die Fähigkeit, die **letzten zehn Domänenanmeldungen** zwischenzuspeichern, um sicherzustellen, dass Benutzer weiterhin auf ihre Computer zugreifen können, selbst wenn der **Domänencontroller offline** ist – ein Vorteil für Laptop-Benutzer, die oft außerhalb des Netzwerks ihres Unternehmens sind.

Die Anzahl der zwischengespeicherten Anmeldungen kann über einen bestimmten **Registrierungsschlüssel oder Gruppenrichtlinie** angepasst werden. Um diese Einstellung anzuzeigen oder zu ändern, wird der folgende Befehl verwendet:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Der Zugriff auf diese zwischengespeicherten Anmeldeinformationen ist streng kontrolliert, wobei nur das **SYSTEM**-Konto die erforderlichen Berechtigungen hat, um sie anzuzeigen. Administratoren, die auf diese Informationen zugreifen müssen, müssen dies mit SYSTEM-Benutzerprivilegien tun. Die Anmeldeinformationen werden unter folgendem Pfad gespeichert: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** kann verwendet werden, um diese zwischengespeicherten Anmeldeinformationen mit dem Befehl `lsadump::cache` zu extrahieren.

Für weitere Details bietet die ursprüngliche [source](http://juggernaut.wikidot.com/cached-credentials) umfassende Informationen.

## Geschützte Benutzer

Die Mitgliedschaft in der **Gruppe der geschützten Benutzer** führt zu mehreren Sicherheitsverbesserungen für Benutzer und gewährleistet höhere Schutzmaßnahmen gegen Diebstahl und Missbrauch von Anmeldeinformationen:

- **Anmeldeinformationsdelegation (CredSSP)**: Selbst wenn die Gruppenrichtlinieneinstellung für **Standardanmeldeinformationen delegieren zulassen** aktiviert ist, werden die Klartextanmeldeinformationen geschützter Benutzer nicht zwischengespeichert.
- **Windows Digest**: Ab **Windows 8.1 und Windows Server 2012 R2** wird das System die Klartextanmeldeinformationen geschützter Benutzer nicht zwischenspeichern, unabhängig vom Status von Windows Digest.
- **NTLM**: Das System wird die Klartextanmeldeinformationen geschützter Benutzer oder NT-Einwegfunktionen (NTOWF) nicht zwischenspeichern.
- **Kerberos**: Für geschützte Benutzer wird die Kerberos-Authentifizierung keine **DES**- oder **RC4-Schlüssel** generieren, noch werden Klartextanmeldeinformationen oder langfristige Schlüssel über den ursprünglichen Ticket-Granting Ticket (TGT)-Erwerb hinaus zwischengespeichert.
- **Offline-Anmeldung**: Geschützte Benutzer haben bei der Anmeldung oder Entsperrung keinen zwischengespeicherten Verifier, was bedeutet, dass die Offline-Anmeldung für diese Konten nicht unterstützt wird.

Diese Schutzmaßnahmen werden aktiviert, sobald ein Benutzer, der Mitglied der **Gruppe der geschützten Benutzer** ist, sich am Gerät anmeldet. Dies stellt sicher, dass kritische Sicherheitsmaßnahmen zum Schutz vor verschiedenen Methoden des Anmeldeinformationskompromisses vorhanden sind.

Für detailliertere Informationen konsultieren Sie die offizielle [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabelle aus** [**den docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

{{#include ../../banners/hacktricks-training.md}}
