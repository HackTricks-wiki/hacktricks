# AD-Zertifikate

{{#include ../../banners/hacktricks-training.md}}

## Einführung

### Bestandteile eines Zertifikats

- Der **Subject** des Zertifikats bezeichnet dessen Inhaber.
- Ein **Public Key** ist einem privat gehaltenen Schlüssel zugeordnet, um das Zertifikat mit seinem rechtmäßigen Inhaber zu verknüpfen.
- Der **Validity Period**, festgelegt durch die Daten **NotBefore** und **NotAfter**, gibt die Gültigkeitsdauer des Zertifikats an.
- Eine eindeutige **Serial Number**, die von der Certificate Authority (CA) bereitgestellt wird, identifiziert jedes Zertifikat.
- Der **Issuer** bezeichnet die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Subject und bietet dadurch mehr Flexibilität bei der Identifizierung.
- **Basic Constraints** geben an, ob das Zertifikat für eine CA oder eine Endentität bestimmt ist, und legen Nutzungsbeschränkungen fest.
- **Extended Key Usages (EKUs)** legen über Object Identifiers (OIDs) die konkreten Verwendungszwecke des Zertifikats fest, etwa Code-Signierung oder E-Mail-Verschlüsselung.
- Der **Signature Algorithm** gibt das Verfahren an, mit dem das Zertifikat signiert wird.
- Die **Signature**, die mit dem privaten Schlüssel des Issuers erstellt wird, gewährleistet die Authentizität des Zertifikats.<sup>[[4]](#references)</sup>

### Besondere Aspekte

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten. Dies ist besonders wichtig für Server mit mehreren Domains. Sichere Ausstellungsprozesse sind entscheidend, um das Risiko einer Identitätsvortäuschung durch Angreifer zu vermeiden, die die SAN-Angabe manipulieren.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS berücksichtigt CA-Zertifikate in einer AD-Forest über ausgewiesene Container, die jeweils eine bestimmte Funktion erfüllen:<sup>[[4]](#references)</sup>

- Der Container **Certification Authorities** enthält vertrauenswürdige Root-CA-Zertifikate.
- Der Container **Enrolment Services** enthält Informationen zu Enterprise CAs und deren Zertifikatvorlagen.
- Das Objekt **NTAuthCertificates** enthält CA-Zertifikate, die für die AD-Authentifizierung autorisiert sind.
- Der Container **AIA (Authority Information Access)** erleichtert die Überprüfung der Zertifikatskette mithilfe von Intermediate- und Cross-CA-Zertifikaten.

### Zertifikatserwerb: Ablauf einer Client-Zertifikatsanforderung

1. Der Anforderungsprozess beginnt damit, dass Clients eine Enterprise CA suchen.
2. Nach dem Erzeugen eines Public-Private-Key-Paars wird eine CSR mit einem Public Key und weiteren Angaben erstellt.
3. Die CA prüft die CSR anhand der verfügbaren Zertifikatvorlagen und stellt das Zertifikat entsprechend den Berechtigungen der Vorlage aus.
4. Nach der Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und sendet es an den Client zurück.<sup>[[4]](#references)</sup>

### Zertifikatvorlagen

Diese in AD definierten Vorlagen legen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten fest. Dazu gehören zulässige EKUs sowie Rechte zur Registrierung oder Änderung. Sie sind entscheidend für die Verwaltung des Zugriffs auf Zertifikatdienste.<sup>[[4]](#references)</sup>

**Die Version des Vorlagenschemas ist relevant.** Älteren **v1**-Vorlagen (zum Beispiel der integrierten Vorlage **WebServer**) fehlen mehrere moderne Durchsetzungsoptionen. Die Forschung zu **ESC15/EKUwu** zeigte, dass bei **v1-Vorlagen** ein Anforderer **Application Policies/EKUs** in die CSR einbetten kann, die gegenüber den in der Vorlage konfigurierten EKUs **bevorzugt werden**. Dadurch sind Client-Authentifizierungs-, Enrollment-Agent- oder Code-Signing-Zertifikate allein mit Registrierungsrechten möglich. Verwenden Sie bevorzugt **v2/v3-Vorlagen**, entfernen oder ersetzen Sie v1-Standardvorlagen und beschränken Sie EKUs strikt auf den vorgesehenen Zweck.<sup>[[1]](#references)</sup>

## Zertifikatsregistrierung

Der Registrierungsprozess für Zertifikate wird von einem Administrator gestartet, der **eine Zertifikatvorlage erstellt**. Anschließend wird sie von einer Enterprise Certificate Authority (CA) **veröffentlicht**. Dadurch steht die Vorlage für die Registrierung durch Clients zur Verfügung. Dazu wird der Name der Vorlage in das Feld `certificatetemplates` eines Active-Directory-Objekts eingetragen.<sup>[[4]](#references)</sup>

Damit ein Client ein Zertifikat anfordern kann, müssen ihm **Registrierungsrechte** gewährt werden. Diese Rechte werden durch Sicherheitsdeskriptoren auf der Zertifikatvorlage und der Enterprise CA selbst festgelegt. Damit eine Anforderung erfolgreich ist, müssen Berechtigungen an beiden Stellen gewährt werden.

### Registrierungsrechte für Vorlagen

Diese Rechte werden über Access Control Entries (ACEs) festgelegt, die Berechtigungen wie die folgenden definieren:

- Die Rechte **Certificate-Enrollment** und **Certificate-AutoEnrollment**, jeweils mit bestimmten GUIDs verknüpft.
- **ExtendedRights**, die alle erweiterten Berechtigungen gewähren.
- **FullControl/GenericAll**, die vollständige Kontrolle über die Vorlage ermöglichen.

### Registrierungsrechte der Enterprise CA

Die Rechte der CA sind in ihrem Sicherheitsdeskriptor festgelegt, der über die Verwaltungskonsole der Certificate Authority zugänglich ist. Einige Einstellungen ermöglichen sogar Benutzern mit geringen Berechtigungen den Fernzugriff, was ein Sicherheitsrisiko darstellen kann.

### Zusätzliche Ausstellungskontrollen

Es können bestimmte Kontrollen gelten, zum Beispiel:

- **Manager Approval**: Versetzt Anforderungen in einen ausstehenden Status, bis ein Zertifikatsmanager sie genehmigt.
- **Enrolment Agents and Authorized Signatures**: Legen die erforderliche Anzahl an Signaturen für eine CSR sowie die benötigten Application Policy OIDs fest.

### Methoden zum Anfordern von Zertifikaten

Zertifikate können auf folgende Weise angefordert werden:

1. Über das **Windows Client Certificate Enrollment Protocol** (MS-WCCE) mithilfe von DCOM-Schnittstellen.
2. Über das **ICertPassage Remote Protocol** (MS-ICPR) mit Named Pipes oder TCP/IP.
3. Über die **Webschnittstelle zur Zertifikatsregistrierung**, wenn die Rolle Certificate Authority Web Enrollment installiert ist.
4. Über den **Certificate Enrollment Service** (CES) in Verbindung mit dem Dienst Certificate Enrollment Policy (CEP).
5. Über den **Network Device Enrollment Service** (NDES) für Netzwerkgeräte mithilfe des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate auch über die GUI (`certmgr.msc` oder `certlm.msc`) oder Befehlszeilentools (`certreq.exe` oder den PowerShell-Befehl `Get-Certificate`) anfordern.

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Zertifikatauthentifizierung

Active Directory (AD) unterstützt die Zertifikatauthentifizierung und verwendet dabei hauptsächlich die Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Beim Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers nach einem Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anfrage wird vom Domänencontroller mehreren Prüfungen unterzogen, darunter der **Gültigkeit**, dem **Pfad** und dem **Sperrstatus** des Zertifikats. Zu den Prüfungen gehört außerdem, dass das Zertifikat aus einer vertrauenswürdigen Quelle stammt und der Aussteller im **NTAUTH-Zertifikatspeicher** vorhanden ist. Bei erfolgreichen Prüfungen wird ein TGT ausgestellt. Das AD-Objekt **`NTAuthCertificates`** befindet sich unter:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ist zentral für die Herstellung von Vertrauen bei der Zertifikatauthentifizierung.<sup>[[4]](#references)</sup>

Seit der Einführung von **KB5014754** geht es bei moderner Kerberos-Zertifikatauthentifizierung hauptsächlich um die **Stärke der Zuordnung** und nicht nur um EKUs.<sup>[[2]](#references)</sup> In gehärteten Forests gilt:

- Ein Zertifikat, das nur einen **UPN/DNS-SAN** enthält, reicht möglicherweise nicht mehr für die Anmeldung aus.
- Der KDC bevorzugt eine **starke Bindung**, typischerweise die **SID-Sicherheitserweiterung** (`1.3.6.1.4.1.311.25.2`) oder eine starke explizite Zuordnung in `altSecurityIdentities`.
- Fehlt dem Zertifikat eine starke Zuordnung, protokollieren DCs im Kompatibilitätsmodus **Kdcsvc Event ID 39/41** und verweigern im Enforcement-Modus die Authentifizierung.
- Bei gemischten Angriffspfaden sind **ESC9/ESC16** relevant, da sie die SID-Erweiterung aus ausgestellten Zertifikaten entfernen. Operatoren greifen dann auf explizite Zuordnungen oder auf SAN-URL-SID-Formate zurück, sofern der Angriffspfad diese unterstützt.

### Secure Channel (Schannel)-Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen. Während eines Handshakes legt der Client ein Zertifikat vor, das bei erfolgreicher Validierung den Zugriff autorisiert. Die Zuordnung eines Zertifikats zu einem AD-Konto kann unter anderem über die **S4U2Self**-Funktion von Kerberos oder den **Subject Alternative Name (SAN)** des Zertifikats erfolgen.<sup>[[4]](#references)</sup>

Schannel ist außerdem der praktische Ausweichweg, wenn **PKINIT** nicht verfügbar ist. Hat ein Domain Controller beispielsweise kein geeignetes **Smart Card Logon**-Zertifikat, kann `certipy auth`/PKINIT-Tooling möglicherweise kein TGT beziehen. Dasselbe Zertifikat kann jedoch weiterhin für die Authentifizierung und LDAP-Operationen über **LDAPS** oder **LDAP StartTLS** verwendet werden.

### Enumeration der AD Certificate Services

Die Certificate Services von AD lassen sich über LDAP-Abfragen enumerieren. Dabei werden Informationen zu **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offengelegt. Jeder mit der Domäne authentifizierte Benutzer kann darauf ohne besondere Berechtigungen zugreifen. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden zur Enumeration und Schwachstellenbewertung in AD-CS-Umgebungen verwendet.

Zu den Befehlen für diese Tools gehören:

```bash
# Enumerate trusted root CA certificates, Enterprise CAs, and web endpoints
Certify.exe cas

# Identify vulnerable templates and dump relevant permissions
Certify.exe find /vulnerable
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /showAdmins

# Certipy 5.x enumeration focused on enabled/vulnerable templates
certipy find -enabled -vulnerable -hide-admins -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Save JSON/CSV output for offline review or BloodHound correlation
certipy find -json -output corp_adcs -u john@corp.local -p Passw0rd -dc-ip 10.10.10.10

# Request a certificate over the Web Enrollment endpoint or DCOM/RPC
certipy req -web -ca corp-CA -target ca.corp.local -template WebServer -upn john@corp.local -dns www.corp.local
certipy req -ca corp-CA -target ca.corp.local -template User -upn administrator@corp.local -sid S-1-5-21-...-500

# Use the issued certificate either for PKINIT or directly for LDAP Schannel auth
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

---

## Aktuelle Schwachstellen & Sicherheitsupdates (2022-2025)

| Jahr | ID / Name | Auswirkung | Zentrale Erkenntnisse |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried“ / ESC6 | *Privilege escalation* durch Spoofing von Computerkontozertifikaten während PKINIT. | Der Patch ist in den Sicherheitsupdates vom **10. Mai 2022** enthalten. Über **KB5014754** wurden Überwachungs- und Strong-Mapping-Kontrollen eingeführt; Umgebungen sollten sich jetzt im *Full Enforcement*-Modus befinden.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote Code Execution* in den Rollen AD CS Web Enrollment (certsrv) und CES. | Öffentliche PoCs sind begrenzt, aber die verwundbaren IIS-Komponenten sind häufig intern erreichbar. Seit dem Patch Tuesday im **Juli 2023** gepatcht.  |
| 2024 | **CVE-2024-49019** – „EKUwu“ / ESC15 | Bei **v1-Vorlagen** kann ein Anforderer mit Berechtigungen zur Zertifikatsregistrierung **Application Policies/EKUs** in die CSR einbetten, die Vorrang vor den EKUs der Vorlage haben. Dadurch entstehen Zertifikate für Clientauthentifizierung, Enrollment Agent oder Codesignierung. | Seit dem **12. November 2024** gepatcht. v1-Vorlagen (z. B. die Standardvorlage WebServer) ersetzen oder ablösen, EKUs auf den jeweiligen Zweck beschränken und Berechtigungen zur Zertifikatsregistrierung einschränken. |

### Microsoft-Härtungszeitplan (KB5014754)

Microsoft führte einen dreiphasigen Rollout (Compatibility → Audit → Enforcement) ein, um die Kerberos-Zertifikatauthentifizierung von schwachen impliziten Zuordnungen wegzuführen. Seit dem **11. Februar 2025** wechseln Domänencontroller automatisch zu **Full Enforcement**, wenn der Registrierungswert `StrongCertificateBindingEnforcement` nicht gesetzt ist. Microsoft aktualisierte den Zeitplan später, sodass bis zum Sicherheitsupdate vom **9. September 2025** weiterhin ein Fallback in den Compatibility-Modus möglich ist.<sup>[[2]](#references)</sup> Administratoren sollten:

1. Alle DCs und AD CS-Server patchen (Mai 2022 oder später).
2. Während der *Audit*-Phase Ereignis-IDs 39/41 auf schwache Zuordnungen überwachen.
3. Clientauthentifizierungszertifikate mit der neuen **SID-Erweiterung** neu ausstellen oder vor der Durchsetzung, die schwache Zuordnungen blockiert, starke manuelle Zuordnungen konfigurieren.

### Hinweise für Operatoren in gehärteten Forests

- **ESC1/ESC6 allein erzählen in Umgebungen ab 2025 nicht mehr die ganze Geschichte.** Wenn Sie ein Zertifikat für einen anderen Principal anfordern, benötigen Sie in der Regel zusätzlich ein starkes Zuordnungsartefakt wie die SID-Erweiterung oder eine explizite Zuordnung.
- **ESC15 (EKUwu)** ist vor allem in ungepatchten Umgebungen relevant, da damit harmlose **v1**-Vorlagen wie **WebServer** durch das Einschleusen von **Application Policies** in Zertifikate für Authentifizierung oder Enrollment Agent umgewandelt werden können. Kerberos PKINIT wertet EKUs weiterhin aus, aber **LDAP Schannel** berücksichtigt auch Application Policies, wodurch LDAP-basierter Missbrauch relevant bleibt.<sup>[[1]](#references)</sup>
- **ESC16** ist eine CA-weite Einstellung: Wenn die CA die SID-Sicherheitserweiterung global deaktiviert, greifen ausgestellte Zertifikate auf schwächeres Zuordnungsverhalten zurück, sofern die Angriffskette keine SID in einem anderen unterstützten Format einschleust.
- **ESC7-Berechtigungen sind unterschiedlich:** Eine CA-Berechtigung `ManageCA` kann Änderungen an Einstellungen wie `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) ermöglichen, während `ManageCertificates` die Genehmigung von Anforderungen steuert. Ein explizites Deny für Zertifikatsmanager-Berechtigungen kann diesen Genehmigungsweg blockieren, selbst wenn auch ein Allow vorhanden ist. Bewerten Sie die effektive CA-ACL, bevor Sie Einstellungen und Vorlagen miteinander verknüpfen. Siehe [Microsofts Bewertung von CA-ACLs](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Verbesserungen bei Erkennung und Härtung

* Der **Defender for Identity AD CS-Sensor (2023-2024)** zeigt jetzt Sicherheitsbewertungen für ESC1-ESC8/ESC11 an und generiert Echtzeitwarnungen wie *„Ausstellung eines Domänencontrollerzertifikats für ein Nicht-DC-Gerät“* (ESC8) und *„Zertifikatsregistrierung mit beliebigen Application Policies verhindern“* (ESC15). Stellen Sie sicher, dass Sensoren auf allen AD CS-Servern bereitgestellt werden, um diese Erkennungen zu nutzen.<sup>[[3]](#references)</sup>
* Deaktivieren Sie die Option **„Supply in the request“** für alle Vorlagen oder schränken Sie sie stark ein; bevorzugen Sie explizit definierte SAN-/EKU-Werte.
* Entfernen Sie **Any Purpose** oder **No EKU** aus Vorlagen, sofern nicht unbedingt erforderlich (behebt Szenarien mit ESC2).
* Erfordern Sie **Managergenehmigung** oder dedizierte Enrollment-Agent-Workflows für sensible Vorlagen (z. B. WebServer / CodeSigning).
* Beschränken Sie Web Enrollment (`certsrv`) und CES/NDES-Endpunkte auf vertrauenswürdige Netzwerke oder schützen Sie sie mit Clientzertifikatauthentifizierung.
* Erzwingen Sie die Verschlüsselung der RPC-Zertifikatsregistrierung (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), um ESC11 (RPC Relay) abzuschwächen. Das Flag ist **standardmäßig aktiviert**, wird aber für ältere Clients häufig deaktiviert, wodurch das Relay-Risiko erneut entsteht.
* Sichern Sie **IIS-basierte Zertifikatsregistrierungsendpunkte** (CES/Certsrv): Deaktivieren Sie NTLM, wenn möglich, oder verlangen Sie HTTPS + Extended Protection, um ESC8-Relays zu verhindern.

Bewerten Sie ESC11 auf dem Host, auf dem die CA ausgeführt wird. Dabei kann es sich um einen Domänenmitgliedsserver statt um einen Domänencontroller handeln. Lesen Sie `InterfaceFlags` der aktiven CA unter `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` aus. Ein nicht lesbarer oder fehlender Wert ist ein unbekanntes Ergebnis und kein Beleg dafür, dass die RPC-Verschlüsselung deaktiviert ist. Ein nicht gesetztes Bit `IF_ENFORCEENCRYPTICERTREQUEST` ist ein Hinweis auf eine Konfiguration, für die weiterhin ein erreichbarer RPC-Endpunkt zur Zertifikatsregistrierung, erzwingbare Anmeldedaten und eine verwendbare Zertifikatvorlage erforderlich sind. Für ESC8 reicht eine HTTP-NTLM-Challenge allein nicht aus: Bestätigen Sie, dass ein funktionierender Zertifikatsregistrierungsendpunkt vorhanden ist.

---

## References

- [1] [EKUwu: Nicht einfach nur ein weiterer AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Änderungen der zertifikatbasierten Authentifizierung auf Windows-Domänencontrollern](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Bewertungen der Sicherheitslage von Zertifikaten – Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Missbrauch von Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
