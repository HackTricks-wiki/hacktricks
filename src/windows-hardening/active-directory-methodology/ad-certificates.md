# AD-Zertifikate

{{#include ../../banners/hacktricks-training.md}}

## Einführung

### Komponenten eines Zertifikats

- Der **Subject** des Zertifikats bezeichnet seinen Besitzer.
- Ein **Public Key** ist mit einem privat gehaltenen Schlüssel gepaart, um das Zertifikat seinem rechtmäßigen Besitzer zuzuordnen.
- Der **Validity Period**, definiert durch die **NotBefore**- und **NotAfter**-Daten, markiert die Gültigkeitsdauer des Zertifikats.
- Eine eindeutige **Serial Number**, vom Certificate Authority (CA) vergeben, identifiziert jedes Zertifikat.
- Der **Issuer** bezeichnet die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** erlaubt zusätzliche Namen für das Subject und erhöht die Flexibilität bei der Identifikation.
- **Basic Constraints** geben an, ob das Zertifikat für eine CA oder eine Endentität gedacht ist und definieren Nutzungsbeschränkungen.
- **Extended Key Usages (EKUs)** legen die spezifischen Verwendungszwecke des Zertifikats (z. B. code signing oder email encryption) über Object Identifiers (OIDs) fest.
- Der **Signature Algorithm** spezifiziert die Methode zum Signieren des Zertifikats.
- Die **Signature**, erstellt mit dem privaten Schlüssel des Issuers, garantiert die Authentizität des Zertifikats.

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten und sind wichtig für Server mit mehreren Domains. Sichere Ausstellungsprozesse sind entscheidend, um zu verhindern, dass Angreifer die SAN-Spezifikation manipulieren und sich so impersonifizieren können.

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einem AD-Forest über bestimmte Container an, die jeweils unterschiedliche Rollen erfüllen:

- Der **Certification Authorities**-Container enthält vertrauenswürdige Root-CA-Zertifikate.
- Der **Enrolment Services**-Container beschreibt Enterprise CAs und ihre certificate templates.
- Das **NTAuthCertificates**-Objekt umfasst CA-Zertifikate, die für AD-Authentifizierung autorisiert sind.
- Der **AIA (Authority Information Access)**-Container erleichtert die Validierung von Zertifikatketten mit Intermediate- und Cross-CA-Zertifikaten.

### Zertifikatserwerb: Client Certificate Request Flow

1. Der Prozess beginnt damit, dass Clients eine Enterprise CA finden.
2. Es wird ein CSR erstellt, das einen public key und weitere Details enthält, nachdem ein public-private Key-Paar erzeugt wurde.
3. Die CA prüft den CSR im Hinblick auf verfügbare certificate templates und stellt das Zertifikat basierend auf den Rechten des Templates aus.
4. Nach Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und gibt es an den Client zurück.

### Certificate Templates

In AD definierte Templates legen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten fest, einschließlich erlaubter EKUs und Enrollment- bzw. Änderungsrechte — entscheidend für die Verwaltung des Zugriffs auf Certificate Services.

Die Template-Schema-Version ist wichtig. Legacy **v1**-Templates (z. B. das eingebaute **WebServer**-Template) fehlen mehrere moderne Durchsetzungsmechanismen. Die **ESC15/EKUwu**-Forschung zeigte, dass bei **v1 templates** ein Antragsteller Application Policies/EKUs im CSR einbetten kann, die gegenüber den im Template konfigurierten EKUs bevorzugt werden, wodurch client-auth-, enrollment agent- oder code-signing-Zertifikate mit nur Enrollment-Rechten möglich werden. Bevorzugen Sie **v2/v3 templates**, entfernen oder überschreiben Sie v1-Standards und beschränken Sie EKUs eng auf den vorgesehenen Zweck.

## Certificate Enrollment

Der Enrollment-Prozess für Zertifikate wird durch einen Administrator initiiert, der ein **certificate template** erstellt, das dann von einer Enterprise Certificate Authority (CA) **published** wird. Dadurch wird das Template für Client-Enrollment verfügbar — erreicht durch Hinzufügen des Template-Namens zum `certificatetemplates` Feld eines Active Directory-Objekts.

Damit ein Client ein Zertifikat anfordern kann, müssen **enrollment rights** gewährt werden. Diese Rechte werden durch Security Descriptors auf dem certificate template und auf der Enterprise CA selbst definiert. Berechtigungen müssen an beiden Stellen gesetzt sein, damit eine Anforderung erfolgreich ist.

### Template Enrollment Rights

Diese Rechte werden durch Access Control Entries (ACEs) spezifiziert und beschreiben Berechtigungen wie:

- **Certificate-Enrollment** und **Certificate-AutoEnrollment**-Rechte, jeweils mit zugehörigen GUIDs.
- **ExtendedRights**, die alle erweiterten Berechtigungen erlauben.
- **FullControl/GenericAll**, die vollständige Kontrolle über das Template gewähren.

### Enterprise CA Enrollment Rights

Die Rechte der CA sind im Security Descriptor der CA festgelegt, zugänglich über die Certificate Authority Management Console. Einige Einstellungen erlauben sogar Low-Privileged-Usern Remote-Zugriff, was ein Sicherheitsproblem darstellen kann.

### Zusätzliche Ausgabekontrollen

Bestimmte Kontrollen können angewendet werden, wie zum Beispiel:

- **Manager Approval**: Platziert Anfragen in einen Pending-Zustand, bis ein Zertifikats-Manager sie genehmigt.
- **Enrolment Agents and Authorized Signatures**: Legt die Anzahl erforderlicher Unterschriften auf einem CSR und die notwendigen Application Policy OIDs fest.

### Methoden, um Zertifikate anzufordern

Zertifikate können über folgende Methoden angefordert werden:

1. Windows Client Certificate Enrollment Protocol (MS-WCCE), über DCOM-Interfaces.
2. ICertPassage Remote Protocol (MS-ICPR), über named pipes oder TCP/IP.
3. Die certificate enrollment web interface, wenn die Certificate Authority Web Enrollment-Rolle installiert ist.
4. Der Certificate Enrollment Service (CES) in Verbindung mit dem Certificate Enrollment Policy (CEP) Service.
5. Der Network Device Enrollment Service (NDES) für Netzwerkgeräte, unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate auch über die GUI (`certmgr.msc` oder `certlm.msc`) oder Kommandozeilentools (`certreq.exe` oder PowerShells `Get-Certificate`-Befehl) anfordern.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikat-Authentifizierung

Active Directory (AD) unterstützt Zertifikatsauthentifizierung und nutzt hauptsächlich die Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers für ein Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anfrage wird vom Domänencontroller mehreren Prüfungen unterzogen, einschließlich der **Gültigkeit**, des **Pfads** und des **Widerrufsstatus** des Zertifikats. Zu den Prüfungen gehört außerdem die Überprüfung, dass das Zertifikat aus einer vertrauenswürdigen Quelle stammt, sowie die Bestätigung, dass der Aussteller im **NTAUTH certificate store** vorhanden ist. Erfolgreiche Prüfungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD, zu finden unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ist zentral für den Aufbau von Vertrauen bei der Zertifikatsauthentifizierung.

### Secure Channel (Schannel) Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen, bei denen der Client während eines Handshakes ein Zertifikat präsentiert, das bei erfolgreicher Validierung Zugriff autorisiert. Die Zuordnung eines Zertifikats zu einem AD-Konto kann die **S4U2Self**-Funktion von Kerberos oder das Zertifikatfeld **Subject Alternative Name (SAN)** sowie andere Methoden umfassen.

### AD Certificate Services Enumeration

Die Certificate Services von AD können mittels LDAP-Abfragen aufgelistet werden, wobei Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offenbart werden. Dies ist für jeden domänenauthentifizierten Benutzer ohne spezielle Privilegien zugänglich. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden zur Enumeration und Schwachstellenbewertung in AD CS-Umgebungen verwendet.

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
{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Aktuelle Verwundbarkeiten & Sicherheitsupdates (2022-2025)

| Jahr | ID / Name | Auswirkung | Wichtigste Erkenntnisse |
|------|-----------|------------|-------------------------|
| 2022 | **CVE-2022-26923** – “Certifried” / ESC6 | *Privilege escalation* durch Spoofing von Machine-Account-Zertifikaten während PKINIT. | Der Patch ist in den **May 10 2022** Sicherheitsupdates enthalten. Auditing- & strong-mapping-Kontrollen wurden via **KB5014754** eingeführt; Umgebungen sollten jetzt im *Full Enforcement*-Modus sein.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in den AD CS Web Enrollment (certsrv) und CES-Rollen. | Öffentliche PoCs sind begrenzt, aber die verwundbaren IIS-Komponenten sind intern oft exponiert. Patch ab **July 2023** Patch Tuesday.  |
| 2024 | **CVE-2024-49019** – “EKUwu” / ESC15 | Bei **v1 templates** kann ein Antragsteller mit Enrollment-Rechten **Application Policies/EKUs** in die CSR einbetten, die gegenüber den Template-EKUs Vorrang haben und so client-auth-, enrollment agent- oder code-signing-Zertifikate erzeugen. | Gepatcht ab **November 12, 2024**. v1-Templates ersetzen oder superseden (z. B. default WebServer), EKUs auf den beabsichtigten Zweck beschränken und Enrollment-Rechte einschränken. |

### Microsoft-Härtungszeitplan (KB5014754)

Microsoft führte einen Drei-Phasen-Rollout (Compatibility → Audit → Enforcement) ein, um Kerberos-Zertifikatsauthentifizierung von schwachen impliziten Mappings wegzuführen. Ab **February 11 2025** wechseln Domain Controllers automatisch in **Full Enforcement**, wenn der Registry-Wert `StrongCertificateBindingEnforcement` nicht gesetzt ist. Administratoren sollten:

1. Alle DCs & AD CS-Server patchen (May 2022 oder neuer).
2. Event ID 39/41 während der *Audit*-Phase auf schwache Mappings überwachen.
3. Client-auth-Zertifikate mit der neuen **SID extension** neu ausstellen oder starke manuelle Mappings konfigurieren, bevor Februar 2025 erreicht ist.

---

## Erkennung & Härtungsverbesserungen

* **Defender for Identity AD CS sensor (2023-2024)** zeigt jetzt Posture-Assessments für ESC1-ESC8/ESC11 und erzeugt Echtzeit-Alerts wie *“Domain-controller certificate issuance for a non-DC”* (ESC8) und *“Prevent Certificate Enrollment with arbitrary Application Policies”* (ESC15). Stellen Sie sicher, dass Sensoren auf allen AD CS-Servern bereitgestellt sind, um von diesen Erkennungen zu profitieren.
* Deaktivieren oder eng einschränken der **“Supply in the request”**-Option auf allen Templates; bevorzugen Sie explizit definierte SAN-/EKU-Werte.
* Entfernen Sie **Any Purpose** oder **No EKU** aus Templates, sofern nicht absolut erforderlich (adressiert ESC2-Szenarien).
* Erfordern Sie **Genehmigung durch einen Manager** oder dedizierte Enrollment Agent-Workflows für sensible Templates (z. B. WebServer / CodeSigning).
* Beschränken Sie Web Enrollment (`certsrv`) und CES/NDES-Endpunkte auf vertrauenswürdige Netzwerke oder setzen Sie sie hinter Client-Zertifikat-Authentifizierung.
* Erzwingen Sie RPC-Enrollment-Verschlüsselung (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), um ESC11 (RPC relay) zu mitigieren. Das Flag ist **on by default**, wird aber oft für Legacy-Clients deaktiviert, was das Relay-Risiko wieder öffnet.
* Sichern Sie **IIS-based enrollment endpoints** (CES/Certsrv): NTLM deaktivieren, wo möglich, oder HTTPS + Extended Protection verlangen, um ESC8-Relays zu blockieren.

---



## Quellen

- [https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/](https://advisory.eventussecurity.com/advisory/critical-vulnerability-in-ad-cs-allows-privilege-escalation/)
{{#include ../../banners/hacktricks-training.md}}
