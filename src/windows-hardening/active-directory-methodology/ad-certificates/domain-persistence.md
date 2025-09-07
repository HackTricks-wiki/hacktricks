# AD CS Domänenpersistenz

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung der Domänenpersistenz-Techniken, die in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) geteilt werden. Weitere Details findest du dort.**

## Fälschen von Zertifikaten mit gestohlenen CA-Zertifikaten - DPERSIST1

Woran erkennt man, dass ein Zertifikat ein CA-Zertifikat ist?

Ein Zertifikat kann als CA-Zertifikat identifiziert werden, wenn mehrere Bedingungen erfüllt sind:

- Das Zertifikat ist auf dem CA-Server gespeichert, wobei sein privater Schlüssel durch die DPAPI der Maschine gesichert ist oder durch Hardware wie einen TPM/HSM, falls das Betriebssystem dies unterstützt.
- Sowohl die Issuer- als auch die Subject-Felder des Zertifikats stimmen mit dem distinguished name der CA überein.
- Eine "CA Version"-Erweiterung ist ausschließlich in CA-Zertifikaten vorhanden.
- Das Zertifikat enthält keine Extended Key Usage (EKU)-Felder.

Um den privaten Schlüssel dieses Zertifikats zu extrahieren, ist das Tool `certsrv.msc` auf dem CA-Server über die eingebaute GUI der unterstützte Weg. Nichtsdestotrotz unterscheidet sich dieses Zertifikat nicht von anderen im System gespeicherten; daher können Methoden wie die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) für die Extraktion angewendet werden.

Das Zertifikat und der private Schlüssel können auch mit Certipy mit folgendem Befehl erhalten werden:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Sobald das CA-Zertifikat und der zugehörige private Schlüssel im `.pfx`-Format erlangt wurden, können Werkzeuge wie [ForgeCert](https://github.com/GhostPack/ForgeCert) verwendet werden, um gültige Zertifikate zu erstellen:
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
> Der für die Zertifikatfälschung anvisierte Benutzer muss in Active Directory aktiv sein und sich authentifizieren können, damit der Prozess erfolgreich ist. Ein Zertifikat für spezielle Konten wie krbtgt zu fälschen ist wirkungslos.

Dieses gefälschte Zertifikat wird bis zum angegebenen Enddatum und **so lange das Root CA-Zertifikat gültig ist** (in der Regel von 5 bis **10+ Jahren**) **gültig** sein. Es ist auch für **Maschinen** gültig, sodass in Kombination mit **S4U2Self** ein Angreifer **Persistenz auf jedem Domain-Computer** so lange aufrechterhalten kann, wie das CA-Zertifikat gültig ist.\
Außerdem **können die mit dieser Methode erzeugten Zertifikate nicht widerrufen werden**, da die CA nichts von ihnen weiß.

### Betrieb unter Strong Certificate Mapping Enforcement (2025+)

Seit dem 11. Februar 2025 (nach Rollout von KB5014754) sind Domain-Controller standardmäßig auf **Full Enforcement** für Zertifikatszuordnungen eingestellt. Praktisch bedeutet das, dass Ihre gefälschten Zertifikate entweder:

- Eine starke Bindung an das Zielkonto enthalten (z. B. die SID-Sicherheits-Extension), oder
- Mit einer starken, expliziten Zuordnung im Zielobjekts-Attribut `altSecurityIdentities` gekoppelt sein müssen.

Ein zuverlässiger Ansatz zur Persistenz besteht darin, ein gefälschtes Zertifikat auszustellen, das an die gestohlene Enterprise CA angekettet ist, und dann eine starke, explizite Zuordnung zum Zielprinzipal hinzuzufügen:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Hinweise
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See
[account-persistence](account-persistence.md) for more on explicit mappings.
- Revocation does not help defenders here: forged certificates are unknown to the CA database and thus cannot be revoked.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Diese Fähigkeit ist besonders relevant, wenn sie in Kombination mit der zuvor beschriebenen Methode unter Verwendung von ForgeCert zum dynamischen Erzeugen von Zertifikaten eingesetzt wird.

> Hinweise zur Zuordnung nach 2025: Das Platzieren einer bösartigen CA in NTAuth bewirkt nur, dass der ausstellenden CA vertraut wird. Um Leaf-Zertifikate für die Anmeldung zu verwenden, wenn DCs in **Full Enforcement** sind, muss das Leaf entweder die SID-Sicherheits-Extension enthalten oder es muss eine starke explizite Zuordnung auf dem Zielobjekt vorhanden sein (zum Beispiel Issuer+Serial in `altSecurityIdentities`). Siehe {{#ref}}account-persistence.md{{#endref}}.

## Bösartige Fehlkonfiguration - DPERSIST3

Möglichkeiten für **Persistenz** durch **Änderungen an Sicherheitsdeskriptoren von AD CS**-Komponenten sind zahlreich. Änderungen, die im Abschnitt "[Domain Escalation](domain-escalation.md)" beschrieben sind, können von einem Angreifer mit erhöhten Rechten böswillig umgesetzt werden. Dazu gehört das Hinzufügen von "control rights" (z. B. WriteOwner/WriteDACL/etc.) zu sensiblen Komponenten wie:

- Das **AD-Computerobjekt** des **CA-Servers**
- Der **RPC/DCOM-Server** des **CA-Servers**
- Jedes **nachgeordnete AD-Objekt oder Container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (z. B. der Certificate Templates-Container, der Certification Authorities-Container, das NTAuthCertificates-Objekt etc.)
- **AD-Gruppen, denen standardmäßig oder organisationsseitig Rechte zur Kontrolle von AD CS delegiert wurden** (wie die integrierte Cert Publishers-Gruppe und deren Mitglieder)

Ein Beispiel für eine bösartige Umsetzung wäre, dass ein Angreifer mit **erhöhten Berechtigungen** in der Domäne die Berechtigung **`WriteOwner`** zur Standard-**`User`**-Zertifikatvorlage hinzufügt, wobei der Angreifer der Principal für dieses Recht ist. Um dies auszunutzen, würde der Angreifer zunächst den Besitzer der **`User`**-Vorlage auf sich selbst ändern. Anschließend würde das **`mspki-certificate-name-flag`** in der Vorlage auf **1** gesetzt, um **`ENROLLEE_SUPPLIES_SUBJECT`** zu aktivieren, was einem Benutzer erlaubt, einen Subject Alternative Name in der Anfrage anzugeben. Danach könnte der Angreifer sich mit der **Vorlage** registrieren, einen **Domain-Administrator**-Namen als alternativen Namen wählen und das erworbene Zertifikat zur Authentifizierung als DA verwenden.

Praktische Stellschrauben, die Angreifer für langfristige Domänenpersistenz setzen könnten (siehe {{#ref}}domain-escalation.md{{#endref}} für vollständige Details und Erkennung):

- CA-Policy-Flags, die SANs von Antragstellern erlauben (z. B. Aktivierung von `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dadurch bleiben ESC1-ähnliche Pfade ausnutzbar.
- Template-DACL oder Einstellungen, die die Ausstellung von für Authentifizierung tauglichen Zertifikaten erlauben (z. B. Hinzufügen von Client Authentication EKU, Aktivieren von `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolle über das `NTAuthCertificates`-Objekt oder die CA-Container, um bösartige Aussteller kontinuierlich wieder einzuführen, falls Verteidiger Bereinigungsversuche starten.

> [!TIP]
> In gehärteten Umgebungen nach KB5014754 stellt die Kombination dieser Fehlkonfigurationen mit expliziten starken Zuordnungen (`altSecurityIdentities`) sicher, dass Ihre ausgestellten oder gefälschten Zertifikate weiterhin nutzbar sind, selbst wenn DCs starke Zuordnungen erzwingen.

## Referenzen

- Microsoft KB5014754 – Änderungen bei zertifikatbasierter Authentifizierung auf Windows-Domain-Controllern (Einsatzzeitplan und starke Zuordnungen). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Befehlsreferenz und Verwendung von forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
