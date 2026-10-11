# AD-Zertifikate

{{#include ../../banners/hacktricks-training.md}}

## Einführung

### Komponenten eines Zertifikats

- Der **Subject** des Zertifikats bezeichnet seinen Inhaber.
- Ein **Public Key** ist mit einem privat gehaltenen Schlüssel verknüpft, um das Zertifikat seinem rechtmäßigen Inhaber zuzuordnen.
- Der **Validity Period**, festgelegt durch die Daten **NotBefore** und **NotAfter**, gibt die Gültigkeitsdauer des Zertifikats an.
- Eine eindeutige **Serial Number**, die von der Certificate Authority (CA) vergeben wird, identifiziert jedes Zertifikat.
- Der **Issuer** bezeichnet die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Subject und macht die Identifizierung flexibler.
- **Basic Constraints** geben an, ob das Zertifikat für eine CA oder eine Endentität bestimmt ist, und legen Nutzungsbeschränkungen fest.
- **Extended Key Usages (EKUs)** legen mithilfe von Object Identifiers (OIDs) die konkreten Verwendungszwecke des Zertifikats fest, etwa Code Signing oder E-Mail-Verschlüsselung.
- Der **Signature Algorithm** legt das Verfahren fest, mit dem das Zertifikat signiert wird.
- Die **Signature**, die mit dem privaten Schlüssel des Issuers erstellt wird, garantiert die Authentizität des Zertifikats.<sup>[[4]](#references)</sup>

### Besondere Aspekte

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten. Das ist besonders für Server mit mehreren Domains wichtig. Sichere Ausstellungsprozesse sind entscheidend, um das Risiko einer Identitätsvortäuschung durch Angreifer zu vermeiden, die die SAN-Angabe manipulieren.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS verwaltet CA-Zertifikate in einer AD-Forest über bestimmte Container, die jeweils eigene Aufgaben erfüllen:<sup>[[4]](#references)</sup>

- Der Container **Certification Authorities** enthält vertrauenswürdige Root-CA-Zertifikate.
- Der Container **Enrolment Services** enthält Informationen zu Enterprise CAs und ihren Certificate Templates.
- Das Objekt **NTAuthCertificates** enthält CA-Zertifikate, die für die AD-Authentifizierung zugelassen sind.
- Der Container **AIA (Authority Information Access)** unterstützt die Validierung der Zertifikatskette mithilfe von Intermediate- und Cross-CA-Zertifikaten.

### Zertifikatsanforderung: Ablauf einer Client-Zertifikatsanforderung

1. Der Vorgang beginnt damit, dass Clients eine Enterprise CA suchen.
2. Nach der Erstellung eines öffentlichen und privaten Schlüsselpaares wird ein CSR mit einem öffentlichen Schlüssel und weiteren Angaben erstellt.
3. Die CA prüft den CSR anhand verfügbarer Certificate Templates und stellt das Zertifikat entsprechend den Berechtigungen der Vorlage aus.
4. Nach der Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und sendet es an den Client zurück.<sup>[[4]](#references)</sup>

### Certificate Templates

Diese in AD definierten Vorlagen legen Einstellungen und Berechtigungen für die Zertifikatsausstellung fest. Dazu gehören zulässige EKUs sowie Rechte für die Registrierung oder Änderung. Sie sind entscheidend für die Verwaltung des Zugriffs auf Zertifikatsdienste.<sup>[[4]](#references)</sup>

**Die Schema-Version der Vorlage ist wichtig.** Älteren **v1**-Vorlagen (z. B. der integrierten Vorlage **WebServer**) fehlen mehrere moderne Kontrollmöglichkeiten. Die Forschung zu **ESC15/EKUwu** hat gezeigt, dass ein Antragsteller bei **v1-Vorlagen** **Application Policies/EKUs** in den CSR einbetten kann, die gegenüber den in der Vorlage konfigurierten EKUs **bevorzugt werden**. Dadurch lassen sich Client-Auth-, Enrollment-Agent- oder Code-Signing-Zertifikate allein mit Registrierungsrechten erhalten. Verwende bevorzugt **v2/v3-Vorlagen**, entferne oder ersetze v1-Standardvorlagen und beschränke EKUs strikt auf den vorgesehenen Zweck.<sup>[[1]](#references)</sup>

## Zertifikatsregistrierung

Der Registrierungsprozess für Zertifikate wird von einem Administrator gestartet, der **eine Certificate Template erstellt**. Anschließend wird sie von einer Enterprise Certificate Authority (CA) **veröffentlicht**. Dadurch steht die Vorlage Clients zur Registrierung zur Verfügung. Dazu wird der Name der Vorlage in das Feld `certificatetemplates` eines Active Directory-Objekts eingetragen.<sup>[[4]](#references)</sup>

Damit ein Client ein Zertifikat anfordern kann, müssen ihm **Registrierungsrechte** gewährt werden. Diese Rechte werden durch Sicherheitsdeskriptoren auf der Certificate Template und der Enterprise CA festgelegt. Damit eine Anforderung erfolgreich ist, müssen Berechtigungen an beiden Stellen gewährt werden.

### Registrierungsrechte für Vorlagen

Diese Rechte werden über Access Control Entries (ACEs) festgelegt. Dazu gehören unter anderem:

- Die Rechte **Certificate-Enrollment** und **Certificate-AutoEnrollment**, die jeweils bestimmten GUIDs zugeordnet sind.
- **ExtendedRights**, die alle erweiterten Berechtigungen gewähren.
- **FullControl/GenericAll**, die vollständige Kontrolle über die Vorlage gewähren.

### Registrierungsrechte für Enterprise CAs

Die Rechte der CA sind in ihrem Sicherheitsdeskriptor festgelegt, der über die Verwaltungskonsole der Certificate Authority zugänglich ist. Einige Einstellungen ermöglichen sogar Benutzern mit geringen Berechtigungen den Fernzugriff, was ein Sicherheitsrisiko darstellen kann.

### Zusätzliche Ausstellungskontrollen

Es können bestimmte Kontrollen gelten, darunter:

- **Manager Approval**: Versetzt Anforderungen in einen ausstehenden Status, bis ein Certificate Manager sie genehmigt.
- **Enrolment Agents and Authorized Signatures**: Legen die erforderliche Anzahl an Signaturen für einen CSR sowie die erforderlichen Application Policy OIDs fest.

### Methoden zum Anfordern von Zertifikaten

Zertifikate können auf folgende Weise angefordert werden:

1. Über das **Windows Client Certificate Enrollment Protocol** (MS-WCCE) mithilfe von DCOM-Schnittstellen.
2. Über das **ICertPassage Remote Protocol** (MS-ICPR) mithilfe benannter Pipes oder TCP/IP.
3. Über die **Weboberfläche zur Zertifikatsregistrierung**, wenn die Rolle Certificate Authority Web Enrollment installiert ist.
4. Über den **Certificate Enrollment Service** (CES) in Verbindung mit dem Dienst Certificate Enrollment Policy (CEP).
5. Über den **Network Device Enrollment Service** (NDES) für Netzwerkgeräte mithilfe des Simple Certificate Enrollment Protocol (SCEP).

Windows-Benutzer können Zertifikate auch über die GUI (`certmgr.msc` oder `certlm.msc`) oder über Kommandozeilentools (`certreq.exe` oder den PowerShell-Befehl `Get-Certificate`) anfordern.

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Zertifikatauthentifizierung

Active Directory (AD) unterstützt die Zertifikatauthentifizierung, hauptsächlich über die Protokolle **Kerberos** und **Secure Channel (Schannel)**.

### Kerberos-Authentifizierungsprozess

Beim Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers nach einem Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Benutzerzertifikats signiert. Diese Anfrage wird vom Domänencontroller mehreren Prüfungen unterzogen, darunter der Prüfung der **Gültigkeit**, des **Zertifizierungspfads** und des **Sperrstatus** des Zertifikats. Zu den Prüfungen gehören außerdem die Verifizierung, dass das Zertifikat von einer vertrauenswürdigen Quelle stammt, und die Bestätigung, dass der Aussteller im **NTAUTH-Zertifikatspeicher** vorhanden ist. Bei erfolgreicher Prüfung wird ein TGT ausgestellt. Das **`NTAuthCertificates`**-Objekt in AD befindet sich unter:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ist zentral für die Herstellung von Vertrauen bei der Zertifikatauthentifizierung.<sup>[[4]](#references)</sup>

Seit der Einführung von **KB5014754** geht es bei moderner Kerberos-Zertifikatauthentifizierung hauptsächlich um die **Stärke der Zuordnung**, nicht nur um EKUs.<sup>[[2]](#references)</sup> In gehärteten Forests gilt:

- Ein Zertifikat, das nur eine **UPN/DNS-SAN** enthält, reicht für die Anmeldung möglicherweise nicht mehr aus.
- Der KDC bevorzugt eine **starke Bindung**, in der Regel die **SID-Sicherheitserweiterung** (`1.3.6.1.4.1.311.25.2`) oder eine starke explizite Zuordnung in `altSecurityIdentities`.
- Fehlt dem Zertifikat eine starke Zuordnung, protokollieren DCs im Kompatibilitätsmodus **Kdcsvc Event ID 39/41** und verweigern die Authentifizierung im Erzwingungsmodus.
- Bei gemischten Angriffspfaden sind **ESC9/ESC16** relevant, da sie die SID-Erweiterung aus ausgestellten Zertifikaten entfernen. Operatoren greifen dann auf explizite Zuordnungen oder SAN-URL-SID-Formate zurück, sofern der Angriffspfad diese unterstützt.

### Authentifizierung über den Secure Channel (Schannel)

Schannel ermöglicht sichere TLS/SSL-Verbindungen. Während des Handshakes legt der Client ein Zertifikat vor, das bei erfolgreicher Validierung den Zugriff autorisiert. Die Zuordnung eines Zertifikats zu einem AD-Konto kann unter anderem über die Kerberos-Funktion **S4U2Self** oder den **Subject Alternative Name (SAN)** des Zertifikats erfolgen.<sup>[[4]](#references)</sup>

Schannel ist außerdem die praktische Ausweichmöglichkeit, wenn **PKINIT** nicht verfügbar ist. Wenn beispielsweise ein Domain Controller kein geeignetes **Smart Card Logon**-Zertifikat besitzt, schlagen `certipy auth`/PKINIT-Tools möglicherweise beim Abrufen eines TGT fehl. Dasselbe Zertifikat kann jedoch weiterhin für die Authentifizierung und LDAP-Operationen über **LDAPS** oder **LDAP StartTLS** verwendet werden.

### Aufzählung von AD Certificate Services

Die Zertifikatdienste von AD lassen sich über LDAP-Abfragen aufzählen. Dabei werden Informationen über **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen sichtbar. Jeder domänenauthentifizierte Benutzer kann darauf ohne besondere Berechtigungen zugreifen. Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden zur Aufzählung und Schwachstellenbewertung in AD-CS-Umgebungen verwendet.

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

## Neuere Sicherheitslücken & Sicherheitsupdates (2022-2025)

| Jahr | ID / Name | Auswirkungen | Wichtigste Erkenntnisse |
|------|-----------|--------|----------------|
| 2022 | **CVE-2022-26923** – „Certifried“ / ESC6 | *Privilege escalation* durch Spoofing von Maschinenkonto-Zertifikaten während PKINIT. | Der Patch ist in den Sicherheitsupdates vom **10. Mai 2022** enthalten. Audit- und Strong-Mapping-Kontrollen wurden über **KB5014754** eingeführt; Umgebungen sollten sich jetzt im Modus *Full Enforcement* befinden.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code execution* in den AD-CS-Rollen Web Enrollment (certsrv) und CES. | Öffentliche PoCs sind begrenzt, aber die anfälligen IIS-Komponenten sind intern häufig erreichbar. Mit dem Patch vom **Juli 2023** Patch Tuesday behoben.  |
| 2024 | **CVE-2024-49019** – „EKUwu“ / ESC15 | Bei **v1-Vorlagen** kann ein anfragender Benutzer mit Enrollment-Rechten **Application Policies/EKUs** in die CSR einbetten, die Vorrang vor den EKUs der Vorlage haben. Dadurch können Zertifikate für Client-Authentifizierung, Enrollment Agents oder Code Signing ausgestellt werden. | Seit dem **12. November 2024** gepatcht. v1-Vorlagen (z. B. die standardmäßige WebServer-Vorlage) ersetzen oder ablösen, EKUs auf den vorgesehenen Zweck beschränken und Enrollment-Rechte begrenzen. |

### Microsoft-Härtungszeitplan (KB5014754)

Microsoft führte einen Rollout in drei Phasen ein (Compatibility → Audit → Enforcement), um die Kerberos-Zertifikatauthentifizierung von schwachen impliziten Zuordnungen wegzuführen. Seit dem **11. Februar 2025** wechseln Domänencontroller automatisch zu **Full Enforcement**, wenn der Registrierungswert `StrongCertificateBindingEnforcement` nicht gesetzt ist. Microsoft aktualisierte den Zeitplan später so, dass bis zum Sicherheitsupdate vom **9. September 2025** eine Rückkehr zum Compatibility-Modus möglich bleibt.<sup>[[2]](#references)</sup> Administratoren sollten:

1. Alle DCs und AD-CS-Server patchen (Mai 2022 oder später).
2. Während der *Audit*-Phase Ereignis-IDs 39/41 auf schwache Zuordnungen überwachen.
3. Client-Authentifizierungszertifikate mit der neuen **SID-Erweiterung** neu ausstellen oder vor Inkrafttreten der Erzwingung starke manuelle Zuordnungen konfigurieren.

### Hinweise für Operatoren gehärteter Forests

- **ESC1/ESC6 allein erzählen in Umgebungen ab 2025 nicht mehr die ganze Geschichte.** Wenn Sie ein Zertifikat für einen anderen Principal anfordern, benötigen Sie üblicherweise auch ein starkes Zuordnungsartefakt wie die SID-Erweiterung oder eine explizite Zuordnung.
- **ESC15 (EKUwu)** ist vor allem in ungepatchten Umgebungen nützlich, da damit harmlose **v1**-Vorlagen wie **WebServer** durch das Einfügen von **Application Policies** in Zertifikate für Authentifizierung oder Enrollment Agents umgewandelt werden können. Kerberos PKINIT wertet EKUs weiterhin aus, aber **LDAP Schannel** berücksichtigt auch Application Policies, wodurch LDAP-basierter Missbrauch relevant bleibt.<sup>[[1]](#references)</sup>
- **ESC16** ist eine CA-weite Einstellung: Deaktiviert die CA global die SID-Sicherheitserweiterung, greift bei jedem ausgestellten Zertifikat wieder ein schwächeres Zuordnungsverhalten, sofern die Angriffskette keine SID in einem anderen unterstützten Format einfügt.
- **ESC7-Rechte sind unterschiedlich:** Ein CA-`ManageCA`-Recht kann Änderungen an Einstellungen wie `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) erlauben, während `ManageCertificates` die Genehmigung von Anfragen steuert. Ein explizites Deny für Certificate-Manager-Rechte kann diesen Genehmigungsweg blockieren, selbst wenn zugleich ein Allow gilt. Prüfen Sie die effektive CA-ACL, bevor Sie Einstellungen und Vorlagen miteinander verknüpfen. Siehe [Microsofts Bewertung der CA-ACL](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Verbesserungen bei Erkennung & Härtung

* Der **Defender for Identity AD CS-Sensor (2023-2024)** zeigt jetzt Sicherheitslagebewertungen für ESC1-ESC8/ESC11 an und generiert Echtzeitwarnungen wie *„Ausstellung eines Domänencontrollerzertifikats für ein Nicht-DC-Konto“* (ESC8) und *„Zertifikatanforderung mit beliebigen Application Policies verhindern“* (ESC15). Stellen Sie sicher, dass auf allen AD-CS-Servern Sensoren installiert sind, um von diesen Erkennungen zu profitieren.<sup>[[3]](#references)</sup>
* Deaktivieren oder beschränken Sie die Option **„In der Anforderung angeben“** für alle Vorlagen; bevorzugen Sie explizit definierte SAN-/EKU-Werte.
* Entfernen Sie **Any Purpose** oder **No EKU** aus Vorlagen, sofern sie nicht unbedingt erforderlich sind (behebt ESC2-Szenarien).
* Verlangen Sie für sensible Vorlagen (z. B. WebServer / CodeSigning) eine **Managergenehmigung** oder dedizierte Enrollment-Agent-Workflows.
* Beschränken Sie Web Enrollment (`certsrv`) sowie CES-/NDES-Endpunkte auf vertrauenswürdige Netzwerke oder sichern Sie sie durch Client-Zertifikatauthentifizierung ab.
* Erzwingen Sie die Verschlüsselung bei der RPC-Enrollment-Anforderung (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), um ESC11 (RPC relay) einzudämmen. Das Flag ist **standardmäßig aktiviert**, wird aber für ältere Clients oft deaktiviert, wodurch das Relay-Risiko wieder entsteht.
* Sichern Sie **IIS-basierte Enrollment-Endpunkte** (CES/Certsrv) ab: Deaktivieren Sie NTLM, sofern möglich, oder verlangen Sie HTTPS + Extended Protection, um ESC8-Relays zu verhindern.

Bewerten Sie ESC11 auf dem Host, auf dem die CA läuft. Dabei kann es sich um einen Mitgliedsserver der Domäne statt um einen Domänencontroller handeln. Lesen Sie den Wert `InterfaceFlags` der aktiven CA unter `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` aus. Ein nicht lesbarer oder fehlender Wert bedeutet, dass das Ergebnis unbekannt ist; er beweist nicht, dass RPC-Verschlüsselung deaktiviert ist. Ein nicht gesetztes Bit `IF_ENFORCEENCRYPTICERTREQUEST` ist ein Hinweis auf eine mögliche Fehlkonfiguration, für die weiterhin ein erreichbarer Enrollment-RPC-Endpunkt, erzwingbare Zugangsdaten und eine geeignete Zertifikatvorlage erforderlich sind. Bei ESC8 reicht eine HTTP-NTLM-Challenge allein nicht aus: Bestätigen Sie, dass ein funktionierender Enrollment-Endpunkt vorhanden ist.

---

## References

- [1] [EKUwu: Nicht nur ein weiterer AD-CS-ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Änderungen an der zertifikatbasierten Authentifizierung auf Windows-Domänencontrollern](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Bewertungen der Sicherheitslage von Zertifikaten – Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Missbrauch von Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../banners/hacktricks-training.md}}
