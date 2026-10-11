# AD-CS-Domänenpersistenz

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung der in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) beschriebenen Techniken zur Domänenpersistenz.** Weitere Details findest du dort.<sup>[[5]](#references)</sup>

## Zertifikate mit gestohlenen CA-Zertifikaten fälschen (Golden Certificate) - DPERSIST1

Woran lässt sich erkennen, ob ein Zertifikat ein CA-Zertifikat ist?

Ein Zertifikat ist ein CA-Zertifikat, wenn mehrere Bedingungen erfüllt sind:<sup>[[5]](#references)</sup>

- Das Zertifikat ist auf dem CA-Server gespeichert. Sein privater Schlüssel ist durch die DPAPI des Computers oder, sofern das Betriebssystem dies unterstützt, durch Hardware wie ein TPM/HSM geschützt.
- Sowohl die Felder „Issuer“ als auch „Subject“ des Zertifikats stimmen mit dem Distinguished Name der CA überein.
- Eine Erweiterung „CA Version“ ist ausschließlich in CA-Zertifikaten vorhanden.
- Dem Zertifikat fehlen Extended-Key-Usage-Felder (EKU).

Zum Extrahieren des privaten Schlüssels dieses Zertifikats ist das Tool `certsrv.msc` auf dem CA-Server die unterstützte Methode über die integrierte GUI. Dieses Zertifikat unterscheidet sich jedoch nicht von anderen im System gespeicherten Zertifikaten. Daher können Extraktionsmethoden wie die [THEFT2-Technik](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) angewendet werden.

Das Zertifikat und der private Schlüssel können auch mit Certipy und dem folgenden Befehl abgerufen werden:<sup>[[2]](#references)</sup>

```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```

Nach dem Erhalt des CA-Zertifikats und seines privaten Schlüssels im `.pfx`-Format können Tools wie [ForgeCert](https://github.com/GhostPack/ForgeCert) verwendet werden, um gültige Zertifikate zu generieren:

```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```

> [!WARNING]
> Der Benutzer, für den das gefälschte Zertifikat erstellt wird, muss aktiv sein und sich bei Active Directory authentifizieren können, damit der Vorgang erfolgreich ist. Ein gefälschtes Zertifikat für spezielle Konten wie krbtgt ist wirkungslos.

Dieses gefälschte Zertifikat bleibt bis zum angegebenen Ablaufdatum **gültig** und zwar so **lange wie das Stammzertifikat der CA gültig ist** (üblicherweise 5 bis **über 10 Jahre**). Es ist auch für **Computer** gültig. In Kombination mit **S4U2Self** kann ein Angreifer daher **so lange Persistenz auf jedem Domänencomputer aufrechterhalten, wie das CA-Zertifikat gültig ist**.\
Außerdem können die **mit dieser Methode generierten Zertifikate** **nicht widerrufen werden**, da der CA nichts von ihnen bekannt ist.

### Betrieb mit Strong Certificate Mapping Enforcement (ab 2025)

Seit dem 11. Februar 2025 (nach der Einführung von KB5014754) verwenden Domänencontroller standardmäßig **Full Enforcement** für Zertifikatzuordnungen. Praktisch bedeutet das, dass gefälschte Zertifikate entweder:

- Eine starke Bindung an das Zielkonto enthalten müssen (zum Beispiel die SID-Sicherheitserweiterung), oder
- Mit einer starken, expliziten Zuordnung im Attribut `altSecurityIdentities` des Zielobjekts verknüpft werden müssen.<sup>[[1]](#references)</sup>

Ein zuverlässiger Ansatz für Persistenz besteht darin, ein gefälschtes Zertifikat auszustellen, das auf die gestohlene Enterprise CA zurückgeht, und dann eine starke explizite Zuordnung zum Opferprinzipal hinzuzufügen:

```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```

Hinweise
- Wenn du gefälschte Zertifikate mit der SID-Sicherheitserweiterung erstellen kannst, werden sie auch bei Full Enforcement implizit zugeordnet. Andernfalls solltest du explizite starke Zuordnungen bevorzugen. Weitere Informationen zu expliziten Zuordnungen findest du unter [account-persistence](account-persistence.md).
- Der Widerruf hilft Verteidigern hier nicht: Gefälschte Zertifikate sind der CA-Datenbank unbekannt und können daher nicht widerrufen werden.

#### Full-Enforcement-kompatibles Forging (SID-aware)

Aktualisierte Tools ermöglichen es dir, die SID direkt einzubetten, sodass Golden Certificates auch dann nutzbar bleiben, wenn DCs schwache Zuordnungen ablehnen:<sup>[[3]](#references)</sup>

```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
  --upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
  --outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
  -sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```

Indem du die SID einbettest, musst du `altSecurityIdentities` nicht anfassen, das möglicherweise überwacht wird, erfüllst aber dennoch die Anforderungen strenger Mapping-Prüfungen.

## Trusting Rogue CA Certificates - DPERSIST2

Das Objekt `NTAuthCertificates` ist dafür vorgesehen, ein oder mehrere **CA-Zertifikate** in seinem Attribut `cacertificate` zu enthalten, das Active Directory (AD) verwendet. Bei der Überprüfung kontrolliert der **Domänencontroller** das Objekt `NTAuthCertificates` auf einen Eintrag, der mit der **CA übereinstimmt**, die im Issuer-Feld des zu authentifizierenden **Zertifikats** angegeben ist. Wird eine Übereinstimmung gefunden, wird die Authentifizierung fortgesetzt.<sup>[[5]](#references)</sup>

Ein Angreifer kann dem Objekt `NTAuthCertificates` ein selbstsigniertes CA-Zertifikat hinzufügen, sofern er die Kontrolle über dieses AD-Objekt hat. Normalerweise dürfen nur Mitglieder der Gruppe **Enterprise Admin** sowie **Domain Admins** oder **Administrators** in der **Domäne der Gesamtstruktur-Stammdomäne** dieses Objekt ändern. Sie können das Objekt `NTAuthCertificates` mit `certutil.exe` und dem Befehl `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` bearbeiten oder dafür das [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) verwenden.

Weitere hilfreiche Befehle für diese Technik:

```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```

Diese Fähigkeit ist besonders relevant, wenn sie zusammen mit einer zuvor beschriebenen Methode eingesetzt wird, bei der ForgeCert zum dynamischen Generieren von Zertifikaten verwendet wird.

> Überlegungen zum Mapping nach 2025: Das Eintragen einer rogue CA in NTAuth stellt nur Vertrauen in die ausstellende CA her. Damit Leaf-Zertifikate für die Anmeldung verwendet werden können, wenn DCs **Full Enforcement** aktiviert haben, muss das Leaf entweder die SID-Sicherheitserweiterung enthalten oder es muss ein starkes explizites Mapping für das Zielobjekt vorhanden sein (zum Beispiel Issuer+Serial in `altSecurityIdentities`). Siehe {{#ref}}account-persistence.md{{#endref}}.

## Bösartige Fehlkonfiguration - DPERSIST3

Möglichkeiten für **Persistence** durch **Änderungen an Security Descriptors** von AD CS-Komponenten gibt es reichlich. Die im Abschnitt „[Domain Escalation](domain-escalation.md)“ beschriebenen Änderungen können von einem Angreifer mit erhöhtem Zugriff böswillig umgesetzt werden. Dazu gehört das Hinzufügen von „Control Rights“ (z. B. WriteOwner/WriteDACL/usw.) zu sensiblen Komponenten wie:<sup>[[5]](#references)</sup>

- Dem **AD-Computerobjekt des CA-Servers**
- Dem **RPC/DCOM-Server des CA-Servers**
- Jedem **untergeordneten AD-Objekt oder Container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (zum Beispiel dem Certificate Templates-Container, dem Certification Authorities-Container, dem NTAuthCertificates-Objekt usw.)
- **AD-Gruppen, denen die Organisation explizit CA- oder Template-Control-Rechte delegiert hat**. Die integrierte Gruppe Cert Publishers ist berechtigt, Zertifikate für Benutzerobjekte in AD zu veröffentlichen; die Mitgliedschaft allein gewährt keine CA- oder Template-Control- oder Enrollment-Rechte. Prüfen Sie die Berechtigungen für die jeweilige CA und das jeweilige Template separat. Siehe [Microsofts Beschreibung von Cert Publishers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers) und [Berechtigungen für Certificate Templates](https://learn.microsoft.com/en-us/intune/configmgr/protect/plan-design/planning-for-certificate-template-permissions).

Ein Beispiel für eine böswillige Umsetzung wäre, dass ein Angreifer mit **erhöhten Berechtigungen** in der Domäne dem standardmäßigen **`User`**-Zertifikat-Template die Berechtigung **`WriteOwner`** hinzufügt und dabei selbst als Principal für dieses Recht eingetragen wird. Um dies auszunutzen, würde der Angreifer zunächst den Besitzer des **`User`**-Templates auf sich selbst ändern. Anschließend würde **`mspki-certificate-name-flag`** für das Template auf **1** gesetzt, um **`ENROLLEE_SUPPLIES_SUBJECT`** zu aktivieren. Dadurch kann ein Benutzer in der Anfrage einen Subject Alternative Name angeben. Danach könnte sich der Angreifer über das **Template** **registrieren**, dabei den Namen eines **Domänenadministrators** als alternativen Namen auswählen und das erhaltene Zertifikat zur Authentifizierung als DA verwenden.

Praktische Stellschrauben, die Angreifer für langfristige Persistence in der Domäne setzen können (vollständige Details und Erkennung siehe {{#ref}}domain-escalation.md{{#endref}}):

- CA-Policy-Flags, die SANs von Anfragenden zulassen (z. B. durch Aktivieren von `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dadurch bleiben ESC1-ähnliche Angriffswege ausnutzbar.
- Template-DACLs oder Einstellungen, die eine Ausgabe authentifizierungsfähiger Zertifikate erlauben (z. B. durch Hinzufügen von Client Authentication EKU oder Aktivieren von `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolle über das `NTAuthCertificates`-Objekt oder die CA-Container, um rogue Issuer erneut einzuführen, falls Verteidiger versuchen, sie zu entfernen.

> [!TIP]
> In gehärteten Umgebungen nach KB5014754 stellt die Kombination dieser Fehlkonfigurationen mit expliziten starken Mappings (`altSecurityIdentities`) sicher, dass ausgestellte oder gefälschte Zertifikate weiterhin verwendet werden können, auch wenn DCs starkes Mapping erzwingen.

### Missbrauch der Zertifikatserneuerung (ESC14) für Persistence

Wenn Sie ein authentifizierungsfähiges Zertifikat (oder ein Enrollment-Agent-Zertifikat) kompromittieren, können Sie es **unbegrenzt erneuern**, solange das ausstellende Template veröffentlicht bleibt und Ihre CA der Issuer-Kette weiterhin vertraut. Bei der Erneuerung bleiben die ursprünglichen Identitätsbindungen erhalten, während die Gültigkeitsdauer verlängert wird. Dadurch ist es schwierig, den Zugriff zu beseitigen, sofern das Template nicht korrigiert oder die CA nicht erneut veröffentlicht wird.<sup>[[4]](#references)</sup>

```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```

Wenn sich die Domain Controller im **Full Enforcement**-Modus befinden, füge `-sid <victim SID>` hinzu (oder verwende eine Vorlage, die weiterhin die SID-Sicherheitserweiterung enthält), damit das erneuerte Leaf-Zertifikat weiterhin stark zugeordnet wird, ohne `altSecurityIdentities` anzufassen. Angreifer mit CA-Adminrechten können außerdem `policy\RenewalValidityPeriodUnits` ändern, um die Gültigkeitsdauer erneuerter Zertifikate zu verlängern, bevor sie sich selbst ein Zertifikat ausstellen.<sup>[[2]](#references)[[4]](#references)</sup>


## References

- [1] [Microsoft KB5014754 – Änderungen bei der zertifikatsbasierten Authentifizierung auf Windows-Domain-Controllern (Durchsetzungszeitplan und starke Zuordnungen)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Befehlsreferenz und Verwendung von forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (integriertes forge mit SID-Unterstützung)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Übersicht über den Missbrauch der ESC14-Erneuerung](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Missbrauch von Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)
{{#include ../../../banners/hacktricks-training.md}}
