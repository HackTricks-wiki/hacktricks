# AD CS Domain-Persistenz

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung der Domain-Persistenz-Techniken, die in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) vorgestellt werden**. Prüfen Sie die Quelle für weitere Details.

## Fälschen von Zertifikaten mit gestohlenen CA-Zertifikaten - DPERSIST1

Woran erkennt man, dass ein Zertifikat ein CA-Zertifikat ist?

Man kann feststellen, dass ein Zertifikat ein CA-Zertifikat ist, wenn mehrere Bedingungen erfüllt sind:

- Das Zertifikat wird auf dem CA-Server gespeichert, wobei der private Schlüssel durch die DPAPI der Maschine oder durch Hardware wie TPM/HSM geschützt ist, sofern das Betriebssystem dies unterstützt.
- Sowohl die Issuer- als auch die Subject-Felder des Zertifikats stimmen mit dem Distinguished Name der CA überein.
- Eine "CA Version"-Erweiterung ist ausschließlich in CA-Zertifikaten vorhanden.
- Das Zertifikat enthält keine Extended Key Usage (EKU)-Felder.

Um den privaten Schlüssel dieses Zertifikats zu extrahieren, ist auf dem CA-Server das Tool `certsrv.msc` über die eingebaute GUI die unterstützte Methode. Nichtsdestotrotz unterscheidet sich dieses Zertifikat nicht von anderen, die im System gespeichert sind; daher können Methoden wie die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zur Extraktion angewendet werden.

Das Zertifikat und der private Schlüssel können auch mit Certipy mittels folgendem Befehl erhalten werden:
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Nachdem das CA-Zertifikat und sein privater Schlüssel im `.pfx`-Format erlangt wurden, können Werkzeuge wie [ForgeCert](https://github.com/GhostPack/ForgeCert) verwendet werden, um gültige Zertifikate zu erstellen:
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
> Der Benutzer, der für die Zertifikatsfälschung ausgewählt wird, muss in Active Directory aktiv sein und sich authentifizieren können, damit der Vorgang erfolgreich ist. Ein Zertifikat für spezielle Konten wie krbtgt zu fälschen ist wirkungslos.

Dieses gefälschte Zertifikat wird bis zum angegebenen Enddatum **gültig** sein und solange das root CA Zertifikat **gültig** ist (in der Regel von 5 bis **10+ Jahren**). Es ist außerdem für **Computer** gültig, sodass ein Angreifer in Kombination mit **S4U2Self** Persistenz auf **jedem Domain-Computer** aufrechterhalten kann, solange das CA Zertifikat gültig ist.\
Darüber hinaus können die mit dieser Methode erzeugten **Zertifikate nicht widerrufen werden**, da die CA nichts von ihnen weiß.

### Betrieb unter Strong Certificate Mapping Enforcement (2025+)

Seit dem 11. Februar 2025 (nach dem Rollout von KB5014754) verwenden Domain-Controller standardmäßig **Full Enforcement** für Zertifikatszuordnungen. Praktisch bedeutet das, dass gefälschte Zertifikate entweder:

- Eine starke Bindung an das Zielkonto enthalten (zum Beispiel die SID security extension), oder
- Mit einer starken, expliziten Zuordnung im `altSecurityIdentities`-Attribut des Zielobjekts gepaart sein müssen.

Eine verlässliche Methode zur Persistenz besteht darin, ein gefälschtes Zertifikat auszustellen, das an die gestohlene Enterprise CA gebunden ist, und dann eine starke explizite Zuordnung zum Opfer-Principal hinzuzufügen:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Hinweise
- If you can craft forged certificates that include the SID security extension, those will map implicitly even under Full Enforcement. Otherwise, prefer explicit strong mappings. See [account-persistence](account-persistence.md) for more on explicit mappings.
- Revocation does not help defenders here: forged certificates are unknown to the CA database and thus cannot be revoked.

## Vertrauen bösartiger CA-Zertifikate - DPERSIST2

Das `NTAuthCertificates`-Objekt ist dafür vorgesehen, ein oder mehrere **CA certificates** in seinem `cacertificate`-Attribut zu enthalten, die von Active Directory (AD) verwendet werden. Der Verifizierungsprozess durch den Domänencontroller prüft das `NTAuthCertificates`-Objekt auf einen Eintrag, der mit der in dem Issuer-Feld des authentifizierenden **certificate** angegebenen CA übereinstimmt. Die Authentifizierung wird fortgesetzt, wenn eine Übereinstimmung gefunden wird.

Ein selbstsigniertes CA-Zertifikat kann von einem Angreifer dem `NTAuthCertificates`-Objekt hinzugefügt werden, vorausgesetzt, er hat Kontrolle über dieses AD-Objekt. Normalerweise dürfen nur Mitglieder der Gruppen **Enterprise Admin**, sowie **Domain Admins** oder **Administrators** in der **forest root’s domain** dieses Objekt ändern. Sie können das `NTAuthCertificates`-Objekt mit `certutil.exe` bearbeiten, z. B. mit dem Befehl `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, oder indem sie das [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) verwenden.

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
Diese Fähigkeit ist besonders relevant in Kombination mit der zuvor beschriebenen Methode zur dynamischen Generierung von Zertifikaten mittels ForgeCert.

> Post-2025 Mapping-Überlegungen: Das Platzieren einer Rogue-CA in NTAuth stellt nur Vertrauen in die ausstellende CA her. Um Leaf-Zertifikate für die Anmeldung zu verwenden, wenn DCs in **Full Enforcement** sind, muss das Leaf entweder die SID-Sicherheits-Extension enthalten oder es muss eine starke explizite Zuordnung auf dem Zielobjekt vorhanden sein (zum Beispiel Issuer+Serial in `altSecurityIdentities`). Siehe {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Möglichkeiten für **Persistence** durch **Security-Descriptor-Modifikationen an AD CS**-Komponenten sind zahlreich. Änderungen, die im Abschnitt "[Domain Escalation](domain-escalation.md)" beschrieben sind, können von einem Angreifer mit erhöhtem Zugriff böswillig umgesetzt werden. Dazu gehört das Hinzufügen von "control rights" (z. B. WriteOwner/WriteDACL/etc.) zu sensiblen Komponenten wie:

- Dem **AD-Computerobjekt** des CA-Servers
- Dem **RPC/DCOM-Server** des CA-Servers
- Jedem **nachgeordneten AD-Objekt oder Container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (zum Beispiel der Certificate Templates-Container, der Certification Authorities-Container, das NTAuthCertificates-Objekt, etc.)
- **AD-Gruppen, denen standardmäßig oder organisatorisch Rechte zur Steuerung von AD CS delegiert wurden** (z. B. die eingebaute Cert Publishers-Gruppe und deren Mitglieder)

Ein Beispiel für eine böswillige Umsetzung wäre, dass ein Angreifer mit **erhöhten Rechten** in der Domäne die Berechtigung **`WriteOwner`** zur Standard-`User`-Zertifikatvorlage hinzufügt, wobei der Angreifer selbst der Principal für das Recht ist. Um dies auszunutzen, würde der Angreifer zunächst den Besitzer der `User`-Vorlage auf sich selbst ändern. Anschließend würde das **`mspki-certificate-name-flag`** auf **1** gesetzt, um **`ENROLLEE_SUPPLIES_SUBJECT`** zu aktivieren, wodurch ein Benutzer im Request einen Subject Alternative Name angeben kann. Danach könnte der Angreifer sich mit der **Vorlage registrieren**, einen Namen eines **Domänenadministrators** als alternativen Namen wählen und das erworbene Zertifikat zur Authentifizierung als Domänenadministrator (DA) verwenden.

Praktische Stellschrauben, die Angreifer für langfristige Domänenpersistenz setzen können (siehe {{#ref}}domain-escalation.md{{#endref}} für vollständige Details und Detektion):

- CA-Policy-Flags, die SAN von Requestern erlauben (z. B. Aktivierung von `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dadurch bleiben ESC1-ähnliche Pfade ausnutzbar.
- Template-DACLs oder Einstellungen, die ausstellungsfähige Authentifizierung erlauben (z. B. Hinzufügen der Client Authentication EKU, Aktivierung von `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolle über das `NTAuthCertificates`-Objekt oder die CA-Container, um Rogue-Issuer kontinuierlich wieder einzuführen, falls Verteidiger versuchen, aufzuräumen.

> [!TIP]
> In gehärteten Umgebungen nach KB5014754 stellt die Kombination dieser Fehlkonfigurationen mit expliziten starken Zuordnungen (`altSecurityIdentities`) sicher, dass ausgestellte oder gefälschte Zertifikate auch dann nutzbar bleiben, wenn DCs starke Zuordnungen durchsetzen.



## References

- Microsoft KB5014754 – Änderungen der zertifikatbasierten Authentifizierung auf Windows Domain Controllern (Durchsetzungszeitplan und starke Zuordnungen). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference und Nutzung von forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
