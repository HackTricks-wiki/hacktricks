# AD-Zertifikate

{{#include ../../banners/hacktricks-training.md}}

## Einführung

### Komponenten eines Zertifikats

- Der **Betreff** des Zertifikats bezeichnet dessen Eigentümer.
- Ein **Öffentlicher Schlüssel** wird mit einem privat gehaltenen Schlüssel gekoppelt, um das Zertifikat mit seinem rechtmäßigen Eigentümer zu verknüpfen.
- Der **Gültigkeitszeitraum**, definiert durch die **NotBefore**- und **NotAfter**-Daten, markiert die effektive Dauer des Zertifikats.
- Eine eindeutige **Seriennummer**, die von der Zertifizierungsstelle (CA) bereitgestellt wird, identifiziert jedes Zertifikat.
- Der **Aussteller** bezieht sich auf die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Betreff und verbessert die Identifikationsflexibilität.
- **Basic Constraints** identifizieren, ob das Zertifikat für eine CA oder eine Endstelle gedacht ist, und definieren Nutzungsbeschränkungen.
- **Extended Key Usages (EKUs)** umreißen die spezifischen Zwecke des Zertifikats, wie Code-Signierung oder E-Mail-Verschlüsselung, durch Objektbezeichner (OIDs).
- Der **Signaturalgorithmus** gibt die Methode zum Signieren des Zertifikats an.
- Die **Signatur**, erstellt mit dem privaten Schlüssel des Ausstellers, garantiert die Authentizität des Zertifikats.

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten, was für Server mit mehreren Domänen entscheidend ist. Sichere Ausstellungsprozesse sind wichtig, um das Risiko der Identitätsübernahme durch Angreifer, die die SAN-Spezifikation manipulieren, zu vermeiden.

### Zertifizierungsstellen (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einem AD-Wald durch bestimmte Container an, die jeweils einzigartige Rollen erfüllen:

- Der Container **Zertifizierungsstellen** enthält vertrauenswürdige Root-CA-Zertifikate.
- Der Container **Registrierungsdienste** enthält Informationen zu Enterprise-CAs und deren Zertifikatvorlagen.
- Das Objekt **NTAuthCertificates** umfasst CA-Zertifikate, die für die AD-Authentifizierung autorisiert sind.
- Der Container **AIA (Authority Information Access)** erleichtert die Validierung der Zertifikatkette mit Zwischen- und Cross-CA-Zertifikaten.

### Zertifikatserwerb: Client-Zertifikatsanforderungsfluss

1. Der Anforderungsprozess beginnt mit Clients, die eine Enterprise-CA finden.
2. Ein CSR wird erstellt, der einen öffentlichen Schlüssel und andere Details enthält, nachdem ein öffentlich-privates Schlüsselpaar generiert wurde.
3. Die CA bewertet den CSR anhand der verfügbaren Zertifikatvorlagen und stellt das Zertifikat basierend auf den Berechtigungen der Vorlage aus.
4. Nach Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und gibt es an den Client zurück.

### Zertifikatvorlagen

Diese Vorlagen, die innerhalb von AD definiert sind, umreißen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten, einschließlich erlaubter EKUs und Rechte zur Registrierung oder Modifikation, die entscheidend für die Verwaltung des Zugriffs auf Zertifikatsdienste sind.

## Zertifikatsregistrierung

Der Registrierungsprozess für Zertifikate wird von einem Administrator initiiert, der **eine Zertifikatvorlage erstellt**, die dann von einer Enterprise-Zertifizierungsstelle (CA) **veröffentlicht** wird. Dadurch wird die Vorlage für die Client-Registrierung verfügbar, ein Schritt, der erreicht wird, indem der Name der Vorlage in das Feld `certificatetemplates` eines Active Directory-Objekts eingefügt wird.

Damit ein Client ein Zertifikat anfordern kann, müssen **Registrierungsrechte** gewährt werden. Diese Rechte werden durch Sicherheitsbeschreibungen auf der Zertifikatvorlage und der Enterprise-CA selbst definiert. Berechtigungen müssen an beiden Orten gewährt werden, damit eine Anfrage erfolgreich ist.

### Vorlagenregistrierungsrechte

Diese Rechte werden durch Zugriffssteuerungseinträge (ACEs) spezifiziert, die Berechtigungen wie:

- **Zertifikat-Registrierung** und **Zertifikat-Auto-Registrierung**-Rechte, die jeweils mit spezifischen GUIDs verbunden sind.
- **ExtendedRights**, die alle erweiterten Berechtigungen erlauben.
- **Vollzugriff/GenericAll**, die vollständige Kontrolle über die Vorlage bieten.

### Enterprise-CA-Registrierungsrechte

Die Rechte der CA sind in ihrem Sicherheitsdescriptor festgelegt, der über die Verwaltungs-Konsole der Zertifizierungsstelle zugänglich ist. Einige Einstellungen erlauben sogar Benutzern mit niedrigen Berechtigungen den Remote-Zugriff, was ein Sicherheitsrisiko darstellen könnte.

### Zusätzliche Ausstellungssteuerungen

Bestimmte Kontrollen können gelten, wie:

- **Managergenehmigung**: Versetzt Anfragen in einen ausstehenden Zustand, bis sie von einem Zertifikatsmanager genehmigt werden.
- **Registrierungsagenten und autorisierte Signaturen**: Geben die Anzahl der erforderlichen Signaturen auf einem CSR und die notwendigen Anwendungsrichtlinien-OIDs an.

### Methoden zur Anforderung von Zertifikaten

Zertifikate können angefordert werden über:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE), unter Verwendung von DCOM-Schnittstellen.
2. **ICertPassage Remote Protocol** (MS-ICPR), über benannte Pipes oder TCP/IP.
3. Die **Zertifikatsregistrierungs-Webschnittstelle**, mit der Rolle der Web-Registrierung der Zertifizierungsstelle installiert.
4. Den **Zertifikatsregistrierungsdienst** (CES), in Verbindung mit dem Zertifikatsregistrierungspolitikdienst (CEP).
5. Den **Network Device Enrollment Service** (NDES) für Netzwerkgeräte, unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können auch Zertifikate über die GUI (`certmgr.msc` oder `certlm.msc`) oder Befehlszeilentools (`certreq.exe` oder PowerShells `Get-Certificate`-Befehl) anfordern.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikatauthentifizierung

Active Directory (AD) unterstützt die Zertifikatauthentifizierung, hauptsächlich unter Verwendung der Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers nach einem Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anfrage unterliegt mehreren Validierungen durch den Domänencontroller, einschließlich der **Gültigkeit**, **Pfad** und **Widerrufsstatus** des Zertifikats. Zu den Validierungen gehört auch die Überprüfung, dass das Zertifikat von einer vertrauenswürdigen Quelle stammt und die Bestätigung der Anwesenheit des Ausstellers im **NTAUTH-Zertifikatspeicher**. Erfolgreiche Validierungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD, zu finden unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ist zentral für die Etablierung von Vertrauen für die Zertifikatauthentifizierung.

### Secure Channel (Schannel) Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen, bei denen der Client während eines Handshakes ein Zertifikat präsentiert, das, wenn es erfolgreich validiert wird, den Zugriff autorisiert. Die Zuordnung eines Zertifikats zu einem AD-Konto kann die **S4U2Self**-Funktion von Kerberos oder den **Subject Alternative Name (SAN)** des Zertifikats sowie andere Methoden umfassen.

### AD-Zertifikatdienste Aufzählung

Die Zertifikatdienste von AD können durch LDAP-Abfragen aufgezählt werden, wodurch Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offengelegt werden. Dies ist für jeden domänenauthentifizierten Benutzer ohne besondere Berechtigungen zugänglich. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden zur Aufzählung und Schwachstellenbewertung in AD CS-Umgebungen verwendet.

Befehle zur Verwendung dieser Tools umfassen:
```bash
# Enumerate trusted root CA certificates and Enterprise CAs with Certify
Certify.exe cas
# Identify vulnerable certificate templates with Certify
Certify.exe find /vulnerable

# Use Certipy (>=4.0) for enumeration and identifying vulnerable templates
certipy find -vulnerable -dc-only -u john@corp.local -p Passw0rd -target dc.corp.local

# Request a certificate over the web enrollment interface (new in Certipy 4.x)
certipy req -web -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```
---

## Aktuelle Schwachstellen & Sicherheitsupdates (2022-2025)

| Jahr | ID / Name | Auswirkungen | Wichtige Erkenntnisse |
|------|-----------|--------------|----------------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilegieneskalation* durch Spoofing von Maschinenkontozertifikaten während PKINIT. | Patch ist in den Sicherheitsupdates vom **10. Mai 2022** enthalten. Auditing- & Strong-Mapping-Kontrollen wurden über **KB5014754** eingeführt; Umgebungen sollten jetzt im *Full Enforcement*-Modus sein. citeturn2search0 |
| 2023 | **CVE-2023-35350 / 35351** | *Remote Code-Ausführung* in der AD CS Web Enrollment (certsrv) und CES-Rollen. | Öffentliche PoCs sind begrenzt, aber die anfälligen IIS-Komponenten sind oft intern exponiert. Patch ab **Juli 2023** Patch Tuesday. citeturn3search0 |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Niedrigprivilegierte Benutzer mit Anmelderechten könnten **irgendeine** EKU oder SAN während der CSR-Generierung überschreiben, was zur Ausstellung von Zertifikaten führt, die für die Client-Authentifizierung oder Code-Signierung verwendet werden können und zu *Domänenkompromittierung* führen. | In den Updates vom **April 2024** behoben. Entfernen Sie “Supply in the request” aus Vorlagen und beschränken Sie die Anmeldeberechtigungen. citeturn1search3 |

### Microsoft-Härtungszeitplan (KB5014754)

Microsoft führte einen dreiphasigen Rollout (Kompatibilität → Audit → Durchsetzung) ein, um die Kerberos-Zertifikatauthentifizierung von schwachen impliziten Zuordnungen wegzuführen. Ab dem **11. Februar 2025** wechseln Domänencontroller automatisch zu **Full Enforcement**, wenn der `StrongCertificateBindingEnforcement`-Registrierungswert nicht gesetzt ist. Administratoren sollten:

1. Alle DCs & AD CS-Server patchen (Mai 2022 oder später).
2. Ereignis-ID 39/41 während der *Audit*-Phase auf schwache Zuordnungen überwachen.
3. Client-Auth-Zertifikate mit der neuen **SID-Erweiterung** neu ausstellen oder starke manuelle Zuordnungen vor Februar 2025 konfigurieren. citeturn2search0

---

## Erkennung & Härtungsverbesserungen

* **Defender for Identity AD CS-Sensor (2023-2024)** zeigt jetzt Statusbewertungen für ESC1-ESC8/ESC11 an und generiert Echtzeitwarnungen wie *“Zertifikatsausstellung für einen Nicht-DC”* (ESC8) und *“Zertifikatsanmeldung mit beliebigen Anwendungsrichtlinien verhindern”* (ESC15). Stellen Sie sicher, dass Sensoren auf allen AD CS-Servern bereitgestellt werden, um von diesen Erkennungen zu profitieren. citeturn5search0
* Deaktivieren oder eng einschränken die **“Supply in the request”**-Option in allen Vorlagen; bevorzugen Sie explizit definierte SAN/EKU-Werte.
* Entfernen Sie **Any Purpose** oder **No EKU** aus Vorlagen, es sei denn, es ist absolut erforderlich (behandelt ESC2-Szenarien).
* Erfordern Sie **Managergenehmigung** oder dedizierte Enrollment-Agent-Workflows für sensible Vorlagen (z. B. WebServer / CodeSigning).
* Beschränken Sie die Webanmeldung (`certsrv`) und CES/NDES-Endpunkte auf vertrauenswürdige Netzwerke oder hinter der Client-Zertifikatauthentifizierung.
* Erzwingen Sie die RPC-Anmeldeverschlüsselung (`certutil –setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQ`), um ESC11 zu mindern.

---

## Referenzen

- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
