# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung der in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) beschriebenen Domain-Persistence-Techniken**. Weitere Details finden Sie dort.<sup>[[5]](#references)</sup>

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Wie kann man feststellen, dass ein Zertifikat ein CA-Zertifikat ist?

Ein Zertifikat kann als CA-Zertifikat bestimmt werden, wenn mehrere Bedingungen erfüllt sind:<sup>[[5]](#references)</sup>

- Das Zertifikat ist auf dem CA-Server gespeichert, wobei sein privater Schlüssel durch die DPAPI des Computers oder, sofern vom Betriebssystem unterstützt, durch Hardware wie ein TPM/HSM geschützt ist.
- Die Felder Issuer und Subject des Zertifikats stimmen mit dem Distinguished Name der CA überein.
- Eine Erweiterung "CA Version" ist ausschließlich in CA-Zertifikaten vorhanden.
- Dem Zertifikat fehlen Extended-Key-Usage-(EKU-)Felder.

Zum Extrahieren des privaten Schlüssels dieses Zertifikats ist das Tool `certsrv.msc` auf dem CA-Server die unterstützte Methode über die integrierte GUI. Dennoch unterscheidet sich dieses Zertifikat nicht von anderen im System gespeicherten Zertifikaten; daher können Methoden wie die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zur Extraktion angewendet werden.

Das Zertifikat und der private Schlüssel können auch mit Certipy über den folgenden Befehl abgerufen werden:<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nach der Beschaffung des CA-Zertifikats und seines privaten Schlüssels im `.pfx`-Format können Tools wie [ForgeCert](https://github.com/GhostPack/ForgeCert) verwendet werden, um gültige Zertifikate zu generieren:
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
> Der für die Zertifikatsfälschung ausgewählte Benutzer muss aktiv sein und sich in Active Directory authentifizieren können, damit der Vorgang erfolgreich ist. Das Fälschen eines Zertifikats für spezielle Konten wie krbtgt ist unwirksam.

Dieses gefälschte Zertifikat bleibt **bis zum angegebenen Enddatum gültig** und **solange das Root-CA-Zertifikat gültig ist** (üblicherweise zwischen 5 und **mehr als 10 Jahren**). Es ist auch für **Maschinen** gültig. In Kombination mit **S4U2Self** kann ein Angreifer daher **auf jedem Domain-Computer Persistenz aufrechterhalten**, solange das CA-Zertifikat gültig ist.\
Außerdem können die mit dieser Methode **generierten Zertifikate** **nicht widerrufen werden**, da die CA nichts von ihnen weiß.

### Betrieb unter Strong Certificate Mapping Enforcement (2025+)

Seit dem 11. Februar 2025 (nach dem Rollout von KB5014754) verwenden Domain-Controller standardmäßig **Full Enforcement** für Certificate Mappings. Praktisch bedeutet dies, dass Ihre gefälschten Zertifikate entweder:

- Eine starke Bindung an das Zielkonto enthalten müssen (beispielsweise die SID-Sicherheitserweiterung), oder
- Mit einem starken, expliziten Mapping im Attribut `altSecurityIdentities` des Zielobjekts verknüpft sein müssen.<sup>[[1]](#references)</sup>

Ein zuverlässiger Ansatz für Persistenz besteht darin, ein gefälschtes Zertifikat auszustellen, das mit der gestohlenen Enterprise CA verkettet ist, und anschließend ein starkes, explizites Mapping zum betroffenen Principal hinzuzufügen:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notizen
- Wenn du gefälschte Zertifikate erstellen kannst, die die SID security extension enthalten, werden diese auch unter Full Enforcement implizit zugeordnet. Andernfalls solltest du explizite starke Mappings bevorzugen. Weitere Informationen zu expliziten Mappings findest du unter [account-persistence](account-persistence.md).
- Der Widerruf hilft Verteidigern hier nicht: Gefälschte Zertifikate sind der CA-Datenbank unbekannt und können daher nicht widerrufen werden.

#### Mit Full Enforcement kompatibles Forging (SID-aware)

Aktualisierte Tools ermöglichen es dir, die SID direkt einzubetten, sodass golden certificates auch dann verwendbar bleiben, wenn DCs schwache Mappings ablehnen:<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
By embedding the SID, vermeiden Sie, `altSecurityIdentities` anfassen zu müssen, das möglicherweise überwacht wird, und erfüllen dennoch die Anforderungen an starke Zuordnungsprüfungen.

## Vertrauen in Rogue CA Certificates - DPERSIST2

Das Objekt `NTAuthCertificates` ist dafür vorgesehen, ein oder mehrere **CA certificates** in seinem Attribut `cacertificate` zu enthalten, die von Active Directory (AD) verwendet werden. Der Überprüfungsprozess durch den **domain controller** umfasst die Prüfung des Objekts `NTAuthCertificates` auf einen Eintrag, der mit der **CA** übereinstimmt, die im Issuer-Feld des zur Authentifizierung verwendeten **certificates** angegeben ist. Die Authentifizierung wird fortgesetzt, wenn eine Übereinstimmung gefunden wird.<sup>[[5]](#references)</sup>

Ein selbstsigniertes CA certificate kann von einem Angreifer zum Objekt `NTAuthCertificates` hinzugefügt werden, sofern dieser das betreffende AD-Objekt kontrolliert. Normalerweise haben nur Mitglieder der Gruppe **Enterprise Admin** sowie **Domain Admins** oder **Administrators** in der **forest root’s domain** die Berechtigung, dieses Objekt zu ändern. Sie können das Objekt `NTAuthCertificates` mit `certutil.exe` und dem Befehl `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` bearbeiten oder das [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) verwenden.

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
Diese Fähigkeit ist besonders relevant, wenn sie zusammen mit der zuvor beschriebenen Methode verwendet wird, bei der ForgeCert zum dynamischen Generieren von Zertifikaten eingesetzt wird.

> Überlegungen zum Mapping nach 2025: Das Platzieren einer Rogue CA in NTAuth etabliert nur Vertrauen in die ausstellende CA. Um Leaf-Zertifikate für die Anmeldung verwenden zu können, wenn sich DCs im **Full Enforcement** befinden, muss das Leaf entweder die SID-Sicherheitserweiterung enthalten oder es muss ein starkes explizites Mapping auf dem Zielobjekt vorhanden sein (beispielsweise Issuer+Serial in `altSecurityIdentities`). Siehe {{#ref}}account-persistence.md{{#endref}}.

## Bösartige Fehlkonfiguration - DPERSIST3

Möglichkeiten für **Persistence** durch **Security-Descriptor-Modifikationen** von **AD CS**-Komponenten sind zahlreich. Die im Abschnitt "[Domain Escalation](domain-escalation.md)" beschriebenen Änderungen können von einem Angreifer mit erweiterten Zugriffsmöglichkeiten bösartig implementiert werden. Dies umfasst das Hinzufügen von "Control Rights" (z. B. WriteOwner/WriteDACL/usw.) zu sensiblen Komponenten wie:<sup>[[5]](#references)</sup>

- Das **AD-Computerobjekt des CA-Servers**
- Der **RPC/DCOM-Server des CA-Servers**
- Jedes **untergeordnete AD-Objekt oder jeder Container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (beispielsweise der Certificate Templates-Container, der Certification Authorities-Container, das NTAuthCertificates-Objekt usw.)
- **AD-Gruppen, denen standardmäßig oder von der Organisation delegierte Rechte zur Kontrolle von AD CS gewährt wurden** (beispielsweise die integrierte Cert Publishers-Gruppe und jedes ihrer Mitglieder)

Ein Beispiel für eine bösartige Implementierung wäre ein Angreifer, der über **erweiterte Berechtigungen** in der Domain verfügt und die Berechtigung **`WriteOwner`** zur standardmäßigen **`User`**-Zertifikatvorlage hinzufügt, wobei der Angreifer als Principal für dieses Recht festgelegt wird. Um dies auszunutzen, würde der Angreifer zunächst den Besitzer der **`User`**-Vorlage auf sich selbst ändern. Anschließend würde **`mspki-certificate-name-flag`** auf der Vorlage auf **1** gesetzt, um **`ENROLLEE_SUPPLIES_SUBJECT`** zu aktivieren, wodurch ein Benutzer einen Subject Alternative Name in der Anfrage angeben kann. Danach könnte der Angreifer sich über die **Vorlage** ein Zertifikat ausstellen lassen, dabei den Namen eines **Domain Administrators** als alternativen Namen auswählen und das erhaltene Zertifikat zur Authentifizierung als DA verwenden.

Praktische Einstellungen, die Angreifer für langfristige Domain-Persistence setzen können (vollständige Details und Erkennung siehe {{#ref}}domain-escalation.md{{#endref}}):

- CA-Policy-Flags, die SAN von Anforderern erlauben (z. B. durch Aktivieren von `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dadurch bleiben ESC1-ähnliche Pfade ausnutzbar.
- Template-DACLs oder Einstellungen, die die Ausstellung von für die Authentifizierung geeigneten Zertifikaten erlauben (z. B. durch Hinzufügen von Client Authentication EKU und Aktivieren von `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Die Kontrolle über das `NTAuthCertificates`-Objekt oder die CA-Container, um Rogue Issuer kontinuierlich erneut einzuführen, falls Defender versuchen, diese zu entfernen.

> [!TIP]
> In gehärteten Umgebungen nach KB5014754 stellt die Kombination dieser Fehlkonfigurationen mit expliziten starken Mappings (`altSecurityIdentities`) sicher, dass ausgestellte oder gefälschte Zertifikate weiterhin verwendet werden können, selbst wenn DCs Strong Mapping erzwingen.

### Missbrauch der Zertifikatserneuerung (ESC14) für Persistence

Wenn du ein für die Authentifizierung geeignetes Zertifikat (oder ein Enrollment-Agent-Zertifikat) kompromittierst, kannst du es **unbegrenzt erneuern**, solange die ausstellende Vorlage veröffentlicht bleibt und deine CA der Issuer-Kette weiterhin vertraut. Durch die Erneuerung bleiben die ursprünglichen Identitätsbindungen erhalten und die Gültigkeit wird verlängert, wodurch die Entfernung erschwert wird, sofern die Vorlage nicht korrigiert oder die CA nicht erneut veröffentlicht wird.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Wenn sich die Domain Controller im **Full Enforcement**-Modus befinden, füge `-sid <victim SID>` hinzu (oder verwende ein Template, das weiterhin die SID-Sicherheits-Extension enthält), damit das erneuerte Leaf-Zertifikat weiterhin stark zugeordnet wird, ohne `altSecurityIdentities` anzupassen. Angreifer mit CA-Administratorrechten können außerdem `policy\RenewalValidityPeriodUnits` anpassen, um die Gültigkeitsdauer erneuerter Zertifikate zu verlängern, bevor sie sich selbst ein Zertifikat ausstellen.<sup>[[2]](#references)[[4]](#references)</sup>


## Referenzen

- [1] [Microsoft KB5014754 – Änderungen an der zertifikatbasierten Authentifizierung auf Windows-Domaincontrollern (Durchsetzungszeitplan und starke Zuordnungen)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Befehlsreferenz sowie forge/auth-Nutzung](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certified 2.0 (integriertes forge mit SID-Unterstützung)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Übersicht zum Missbrauch der ESC14-Erneuerung](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned: Missbrauch der Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
