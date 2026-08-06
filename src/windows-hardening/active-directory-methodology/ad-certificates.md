# AD-Zertifikate

{{#include ../../banners/hacktricks-training.md}}

## Einführung

### Komponenten eines Zertifikats

- Der **Subject** des Zertifikats bezeichnet dessen Eigentümer.
- Ein **Public Key** wird mit einem privat gehaltenen Schlüssel verknüpft, um das Zertifikat seinem rechtmäßigen Eigentümer zuzuordnen.
- Der **Validity Period**, definiert durch die Datumsangaben **NotBefore** und **NotAfter**, kennzeichnet die Gültigkeitsdauer des Zertifikats.
- Eine eindeutige **Serial Number**, die von der Certificate Authority (CA) bereitgestellt wird, identifiziert jedes Zertifikat.
- Der **Issuer** bezeichnet die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Subject und erweitert dadurch die Flexibilität bei der Identifikation.
- **Basic Constraints** geben an, ob das Zertifikat für eine CA oder eine End-Entity bestimmt ist, und definieren Nutzungsbeschränkungen.
- **Extended Key Usages (EKUs)** legen über Object Identifiers (OIDs) die spezifischen Zwecke des Zertifikats fest, beispielsweise Code-Signing oder E-Mail-Verschlüsselung.
- Der **Signature Algorithm** gibt die Methode an, mit der das Zertifikat signiert wird.
- Die **Signature**, die mit dem privaten Schlüssel des Issuers erstellt wird, gewährleistet die Authentizität des Zertifikats.<sup>[[4]](#references)</sup>

### Besondere Überlegungen

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten, was für Server mit mehreren Domains entscheidend ist. Sichere Ausstellungsprozesse sind unerlässlich, um Impersonation-Risiken durch Angreifer zu vermeiden, die die SAN-Spezifikation manipulieren.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einer AD-Forest über bestimmte Container, die jeweils unterschiedliche Aufgaben erfüllen:<sup>[[4]](#references)</sup>

- Der Container **Certification Authorities** enthält vertrauenswürdige Root-CA-Zertifikate.
- Der Container **Enrolment Services** enthält Informationen zu Enterprise CAs und deren Zertifikatvorlagen.
- Das Objekt **NTAuthCertificates** enthält CA-Zertifikate, die für die AD-Authentifizierung autorisiert sind.
- Der Container **AIA (Authority Information Access)** unterstützt die Validierung der Zertifikatskette mithilfe von Intermediate- und Cross-CA-Zertifikaten.

### Zertifikatserwerb: Ablauf einer Client-Zertifikatanforderung

1. Der Anforderungsprozess beginnt damit, dass Clients eine Enterprise CA finden.
2. Nach der Erstellung eines Public-Private-Key-Paars wird eine CSR erstellt, die einen Public Key und weitere Informationen enthält.
3. Die CA bewertet die CSR anhand der verfügbaren Zertifikatvorlagen und stellt das Zertifikat basierend auf den Berechtigungen der Vorlage aus.
4. Nach der Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und sendet es an den Client zurück.<sup>[[4]](#references)</sup>

### Zertifikatvorlagen

Diese in AD definierten Vorlagen legen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten fest, einschließlich zulässiger EKUs sowie Enrollment- oder Änderungsrechten. Sie sind entscheidend für die Verwaltung des Zugriffs auf Zertifikatdienste.<sup>[[4]](#references)</sup>

**Die Schema-Version der Vorlage ist relevant.** Ältere **v1**-Vorlagen, beispielsweise die integrierte **WebServer**-Vorlage, verfügen über mehrere moderne Durchsetzungsoptionen nicht. Die ESC15/EKUwu-Forschung zeigte, dass ein Requester bei **v1**-Vorlagen **Application Policies/EKUs** in die CSR einbetten kann, die gegenüber den in der Vorlage konfigurierten EKUs **bevorzugt** werden. Dadurch werden Client-Auth-, Enrollment-Agent- oder Code-Signing-Zertifikate mit ausschließlich Enrollment-Rechten ermöglicht. Bevorzugen Sie **v2/v3**-Vorlagen, entfernen oder ersetzen Sie v1-Standardeinstellungen und beschränken Sie EKUs strikt auf den vorgesehenen Zweck.<sup>[[1]](#references)</sup>

## Zertifikats-Enrollment

Der Enrollment-Prozess für Zertifikate wird von einem Administrator initiiert, der **eine Zertifikatvorlage erstellt**, die anschließend von einer Enterprise Certificate Authority (CA) **veröffentlicht** wird. Dadurch wird die Vorlage für das Client-Enrollment verfügbar. Dies geschieht, indem der Name der Vorlage zum Feld `certificatetemplates` eines Active-Directory-Objekts hinzugefügt wird.<sup>[[4]](#references)</sup>

Damit ein Client ein Zertifikat anfordern kann, müssen **Enrollment-Rechte** gewährt werden. Diese Rechte werden durch Security Descriptors auf der Zertifikatvorlage und auf der Enterprise CA definiert. Damit eine Anforderung erfolgreich ist, müssen an beiden Stellen Berechtigungen erteilt werden.

### Enrollment-Rechte der Vorlage

Diese Rechte werden über Access Control Entries (ACEs) festgelegt, die Berechtigungen wie die folgenden definieren:

- **Certificate-Enrollment**- und **Certificate-AutoEnrollment**-Rechte, die jeweils bestimmten GUIDs zugeordnet sind.
- **ExtendedRights**, die alle erweiterten Berechtigungen ermöglichen.
- **FullControl/GenericAll**, die vollständige Kontrolle über die Vorlage gewähren.

### Enrollment-Rechte der Enterprise CA

Die Rechte der CA sind in ihrem Security Descriptor definiert, der über die Verwaltungskonsole der Certificate Authority eingesehen werden kann. Einige Einstellungen ermöglichen sogar Benutzern mit geringen Berechtigungen den Remote-Zugriff, was ein Sicherheitsrisiko darstellen kann.

### Zusätzliche Ausgabekontrollen

Bestimmte Kontrollen können angewendet werden, darunter:

- **Manager Approval**: Versetzt Anforderungen in einen ausstehenden Status, bis sie von einem Certificate Manager genehmigt wurden.
- **Enrolment Agents and Authorized Signatures**: Legen die Anzahl der erforderlichen Signaturen für eine CSR sowie die notwendigen Application Policy OIDs fest.

### Methoden zum Anfordern von Zertifikaten

Zertifikate können angefordert werden über:

1. **Windows Client Certificate Enrollment Protocol** (MS-WCCE) unter Verwendung von DCOM-Schnittstellen.
2. **ICertPassage Remote Protocol** (MS-ICPR) über Named Pipes oder TCP/IP.
3. Die **Weboberfläche für das Zertifikats-Enrollment**, wenn die Rolle Certificate Authority Web Enrollment installiert ist.
4. Den **Certificate Enrollment Service** (CES) zusammen mit dem Dienst Certificate Enrollment Policy (CEP).
5. Den **Network Device Enrollment Service** (NDES) für Netzwerkgeräte unter Verwendung des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate auch über die GUI (`certmgr.msc` oder `certlm.msc`) oder über Kommandozeilentools (`certreq.exe` oder den PowerShell-Befehl `Get-Certificate`) anfordern.
```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```
## Zertifikatsauthentifizierung

Active Directory (AD) unterstützt die Zertifikatsauthentifizierung und verwendet hauptsächlich die Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Im Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers nach einem Ticket Granting Ticket (TGT) mit dem **private key** des Benutzerzertifikats signiert. Diese Anfrage wird vom Domain Controller mehreren Validierungen unterzogen, darunter der Überprüfung der **Gültigkeit**, des **Pfads** und des **Widerrufsstatus** des Zertifikats. Zu den Validierungen gehören außerdem die Überprüfung, dass das Zertifikat aus einer vertrauenswürdigen Quelle stammt, sowie die Bestätigung, dass der Aussteller im **NTAUTH certificate store** vorhanden ist. Erfolgreiche Validierungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD befindet sich unter:
```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```
ist zentral für die Herstellung von Vertrauen bei der Zertifikatauthentifizierung.<sup>[[4]](#references)</sup>

Seit dem Rollout von **KB5014754** geht es bei moderner Kerberos-Zertifikatauthentifizierung hauptsächlich um die **Mapping-Stärke**, nicht nur um EKUs.<sup>[[2]](#references)</sup> In gehärteten Forests gilt:

- Ein Zertifikat, das nur einen **UPN/DNS SAN** enthält, reicht für die Anmeldung möglicherweise nicht mehr aus.
- Der KDC bevorzugt ein **starkes Binding**, typischerweise die **SID-Sicherheitserweiterung** (`1.3.6.1.4.1.311.25.2`) oder ein starkes explizites Mapping in `altSecurityIdentities`.
- Fehlt dem Zertifikat ein starkes Mapping, protokollieren DCs im Kompatibilitätsmodus das **Kdcsvc Event ID 39/41** und verweigern die Authentifizierung im Enforcement-Modus.
- Bei kombinierten Angriffspfaden sind **ESC9/ESC16** relevant, da sie die SID-Erweiterung aus ausgestellten Zertifikaten entfernen. Operatoren greifen dann auf explizite Mappings oder SAN-URL-SID-Formate zurück, sofern der Angriffspfad diese unterstützt.

### Secure Channel (Schannel)-Authentifizierung

Schannel ermöglicht sichere TLS/SSL-Verbindungen. Während eines Handshakes präsentiert der Client ein Zertifikat, das bei erfolgreicher Validierung den Zugriff autorisiert. Das Mapping eines Zertifikats auf ein AD-Konto kann unter anderem über Kerberos’ **S4U2Self**-Funktion oder den **Subject Alternative Name (SAN)** des Zertifikats erfolgen.<sup>[[4]](#references)</sup>

Schannel ist außerdem der praktische Fallback, wenn **PKINIT** nicht verfügbar ist. Wenn ein Domain Controller beispielsweise kein geeignetes **Smart Card Logon**-Zertifikat besitzt, schlagen `certipy auth`/PKINIT-Tools möglicherweise beim Abrufen eines TGT fehl. Dasselbe Zertifikat kann jedoch weiterhin für die Authentifizierung und LDAP-Operationen über **LDAPS** oder **LDAP StartTLS** verwendet werden.

### Enumeration von AD Certificate Services

Die Certificate Services von AD können über LDAP-Abfragen enumeriert werden, wodurch Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen offengelegt werden. Dies ist für jeden domänenauthentifizierten Benutzer ohne besondere Berechtigungen möglich. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden für Enumeration und Vulnerability Assessment in AD-CS-Umgebungen verwendet.

Zu den Befehlen für die Verwendung dieser Tools gehören:
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

| Jahr | ID / Name | Auswirkungen | Wichtigste Erkenntnisse |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried“ / ESC6 | *Privilege escalation* durch das Spoofing von Machine-Account-Zertifikaten während PKINIT. | Der Patch ist in den Sicherheitsupdates vom **10. Mai 2022** enthalten. Über **KB5014754** wurden Auditing- und Strong-Mapping-Kontrollen eingeführt; Umgebungen sollten sich inzwischen im Modus *Full Enforcement* befinden.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in den AD CS Web Enrollment- (`certsrv`) und CES-Rollen. | Öffentliche PoCs sind begrenzt, aber die verwundbaren IIS-Komponenten sind intern häufig erreichbar. Seit dem Patch Tuesday im **Juli 2023** behoben.  |
| 2024 | **CVE-2024-49019** – „EKUwu“ / ESC15 | Bei **v1 templates** kann ein Requester mit Enrollment-Rechten **Application Policies/EKUs** in die CSR einbetten, die gegenüber den Template-EKUs bevorzugt werden. Dadurch können Zertifikate für Client-Authentifizierung, Enrollment Agents oder Code-Signing erzeugt werden. | Seit dem **12. November 2024** gepatcht. v1 templates (z. B. das standardmäßige WebServer) ersetzen oder außer Kraft setzen, EKUs auf den vorgesehenen Zweck beschränken und Enrollment-Rechte begrenzen. |

### Microsoft-Härtungszeitplan (KB5014754)

Microsoft führte einen dreistufigen Rollout (Compatibility → Audit → Enforcement) ein, um die Zertifikatsauthentifizierung von Kerberos von schwachen impliziten Mappings wegzuführen. Seit dem **11. Februar 2025** wechseln Domain Controller automatisch zu **Full Enforcement**, wenn der Registry-Wert `StrongCertificateBindingEnforcement` nicht gesetzt ist. Microsoft aktualisierte den Zeitplan später, sodass ein Fallback in den Compatibility-Modus bis zum Sicherheitsupdate vom **9. September 2025** möglich bleibt.<sup>[[2]](#references)</sup> Administratoren sollten:

1. Alle DCs und AD CS-Server patchen (Mai 2022 oder später).
2. Während der *Audit*-Phase die Event IDs 39/41 auf schwache Mappings überwachen.
3. Client-Authentifizierungszertifikate mit der neuen **SID extension** neu ausstellen oder vor dem Enforcement, das schwache Mappings blockiert, starke manuelle Mappings konfigurieren.

### Hinweise für Operatoren gehärteter Forests

- **ESC1/ESC6 allein sind in Umgebungen ab 2025 nicht mehr die ganze Geschichte.** Wenn ihr ein Zertifikat für einen anderen Principal anfordert, benötigt ihr normalerweise zusätzlich ein starkes Mapping-Artefakt wie die SID extension oder ein explizites Mapping.
- **ESC15 (EKUwu)** ist vor allem in ungepatchten Umgebungen relevant, da dadurch harmlose **v1 templates** wie **WebServer** durch das Injizieren von **Application Policies** in Zertifikate mit Authentifizierungs- oder Enrollment-Agent-Funktionalität umgewandelt werden. Kerberos PKINIT wertet EKUs weiterhin aus, aber **LDAP Schannel** berücksichtigt ebenfalls Application Policies, wodurch LDAP-basierter Missbrauch relevant bleibt.<sup>[[1]](#references)</sup>
- **ESC16** ist ein CA-weiter Schalter: Wenn die CA die SID security extension global deaktiviert, fällt jedes ausgestellte Zertifikat auf ein schwächeres Mapping-Verhalten zurück, sofern die Angriffskette keine SID in einem anderen unterstützten Format injiziert.

---

## Verbesserungen bei Detection & Hardening

* Der **Defender for Identity AD CS sensor (2023-2024)** zeigt jetzt Posture Assessments für ESC1-ESC8/ESC11 an und erzeugt Echtzeitwarnungen wie *„Domain-controller certificate issuance for a non-DC“* (ESC8) und *„Prevent Certificate Enrollment with arbitrary Application Policies“* (ESC15). Stellt sicher, dass auf allen AD CS-Servern Sensoren bereitgestellt sind, um von diesen Detections zu profitieren.<sup>[[3]](#references)</sup>
* Die Option **„Supply in the request“** auf allen Templates deaktivieren oder streng einschränken; stattdessen explizit definierte SAN/EKU-Werte bevorzugen.
* **Any Purpose** oder **No EKU** aus Templates entfernen, sofern dies nicht unbedingt erforderlich ist (behebt ESC2-Szenarien).
* Für sensible Templates (z. B. WebServer / CodeSigning) eine **manager approval** oder dedizierte Enrollment-Agent-Workflows voraussetzen.
* Web Enrollment (`certsrv`) sowie CES/NDES-Endpunkte auf vertrauenswürdige Netzwerke beschränken oder hinter Client-Zertifikatsauthentifizierung betreiben.
* Die Verschlüsselung beim RPC Enrollment erzwingen (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), um ESC11 (RPC relay) zu mitigieren. Das Flag ist **standardmäßig aktiviert**, wird für Legacy-Clients jedoch häufig deaktiviert, wodurch erneut ein Relay-Risiko entsteht.
* **IIS-basierte Enrollment-Endpunkte** (CES/Certsrv) absichern: NTLM, sofern möglich, deaktivieren oder HTTPS + Extended Protection voraussetzen, um ESC8-Relays zu blockieren.

---

## References

- [1] [EKUwu: Not just another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Certificates security posture assessments - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../banners/hacktricks-training.md}}
