# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine Zusammenfassung der Domain-Persistence-Techniken, die in [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) geteilt werden. Prüfe das Dokument für weitere Details.**

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

How can you tell that a certificate is a CA certificate?

Es lässt sich feststellen, dass ein Zertifikat ein CA-Zertifikat ist, wenn mehrere Bedingungen erfüllt sind:

- Das Zertifikat ist auf dem CA-Server gespeichert, wobei sein privater Schlüssel durch die DPAPI der Maschine gesichert ist oder durch Hardware wie TPM/HSM, falls das Betriebssystem dies unterstützt.
- Sowohl die Issuer- als auch die Subject-Felder des Zertifikats stimmen mit dem Distinguished Name der CA überein.
- In den CA-Zertifikaten ist ausschließlich eine "CA Version"-Erweiterung vorhanden.
- Dem Zertifikat fehlen Extended Key Usage (EKU)-Felder.

Um den privaten Schlüssel dieses Zertifikats zu extrahieren, ist das Tool `certsrv.msc` auf dem CA-Server über die eingebaute GUI die unterstützte Methode. Nichtsdestotrotz unterscheidet sich dieses Zertifikat nicht von anderen im System gespeicherten; daher können Methoden wie die [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) zur Extraktion angewendet werden.

Das Zertifikat und der private Schlüssel können auch mit Certipy mit dem folgenden Befehl erlangt werden:
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
> Der Benutzer, auf den die Zertifikatfälschung abzielt, muss in Active Directory aktiv sein und sich authentifizieren können, damit der Vorgang erfolgreich ist. Ein Zertifikat für Spezialkonten wie krbtgt zu fälschen ist wirkungslos.

Dieses gefälschte Zertifikat wird bis zum angegebenen Enddatum **gültig** sein und solange das Root-CA-Zertifikat **gültig** ist (in der Regel 5 bis **10+ Jahre**). Es ist auch für **Maschinen** gültig, sodass in Kombination mit **S4U2Self** ein Angreifer **persistence auf jedem Domain-Computer aufrechterhalten** kann, solange das CA-Zertifikat gültig ist.\
Außerdem können die **mit dieser Methode generierten Zertifikate** nicht **widerrufen** werden, da die CA nicht darüber informiert ist.

### Betrieb unter Strong Certificate Mapping Enforcement (2025+)

Seit dem 11. Februar 2025 (nach dem Rollout von KB5014754) sind Domain Controller standardmäßig auf **Full Enforcement** für certificate mappings eingestellt. Praktisch bedeutet das, dass Ihre gefälschten Zertifikate entweder:

- Eine starke Bindung an das Zielkonto enthalten müssen (zum Beispiel die SID security extension), oder
- Mit einer starken, expliziten Zuordnung im Attribut `altSecurityIdentities` des Zielobjekts gepaart sein müssen.

Ein zuverlässiger Ansatz für persistence ist es, ein gefälschtes Zertifikat auszustellen, das an die gestohlene Enterprise CA gekettet ist, und dann eine starke, explizite Zuordnung zum Opferprinzipal hinzuzufügen:
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Hinweise
- Wenn Sie gefälschte Zertifikate erstellen können, die die SID-Sicherheitsverlängerung enthalten, werden diese implizit abgebildet, selbst unter Full Enforcement. Andernfalls bevorzugen Sie explizite, starke Zuordnungen. Siehe [account-persistence](account-persistence.md) für mehr zu expliziten Zuordnungen.
- Widerruf hilft Verteidigern hier nicht: gefälschte Zertifikate sind der CA-Datenbank unbekannt und können daher nicht widerrufen werden.

#### Full-Enforcement-kompatible forging (SID-aware)

Aktualisierte Tools ermöglichen es, die SID direkt einzubetten, sodass golden certificates weiterhin nutzbar bleiben, selbst wenn DCs schwache Zuordnungen ablehnen:
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
Indem man die SID einbettet, vermeidet man, `altSecurityIdentities` anfassen zu müssen, das überwacht werden könnte, und erfüllt trotzdem die strengen Mapping-Prüfungen.

## Trusting Rogue CA Certificates - DPERSIST2

Das Objekt `NTAuthCertificates` ist dafür definiert, ein oder mehrere **CA certificates** in seinem Attribut `cacertificate` zu enthalten, die von Active Directory (AD) genutzt werden. Der Verifizierungsprozess durch den **domain controller** prüft das Objekt `NTAuthCertificates` auf einen Eintrag, der mit der in dem Issuer field des authentifizierenden **certificate** angegebenen **CA specified** übereinstimmt. Wenn eine Übereinstimmung gefunden wird, wird die Authentifizierung fortgesetzt.

Ein selbstsigniertes CA certificate kann von einem Angreifer dem Objekt `NTAuthCertificates` hinzugefügt werden, vorausgesetzt, er hat Kontrolle über dieses AD-Objekt. Normalerweise dürfen nur Mitglieder der Gruppe **Enterprise Admin**, sowie **Domain Admins** oder **Administrators** in der **forest root’s domain**, dieses Objekt ändern. Sie können das `NTAuthCertificates`-Objekt mit `certutil.exe` bearbeiten, z. B. mit dem Befehl `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, oder indem sie das [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool) verwenden.

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
Diese Fähigkeit ist besonders relevant, wenn sie in Verbindung mit der zuvor beschriebenen Methode unter Verwendung von ForgeCert zum dynamischen Erstellen von Zertifikaten eingesetzt wird.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Bösartige Fehlkonfiguration - DPERSIST3

Möglichkeiten für **Persistenz** durch **security descriptor modifications** von AD CS-Komponenten sind zahlreich. Änderungen, die im Abschnitt "[Domain Escalation](domain-escalation.md)" beschrieben sind, können von einem Angreifer mit erhöhten Rechten böswillig umgesetzt werden. Dazu gehört das Hinzufügen von "control rights" (z. B. WriteOwner/WriteDACL/etc.) zu sensiblen Komponenten wie:

- Das **CA server’s AD computer** Objekt
- Der **CA server’s RPC/DCOM server**
- Jedes **descendant AD object or container** in **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (zum Beispiel der Certificate Templates container, Certification Authorities container, das NTAuthCertificates object, etc.)
- **AD groups delegated rights to control AD CS** standardmäßig oder durch die Organisation (wie die integrierte Cert Publishers group und deren Mitglieder)

Ein Beispiel für eine bösartige Umsetzung wäre, dass ein Angreifer mit erhöhten Berechtigungen in der Domäne die Berechtigung **`WriteOwner`** an die Standard-**`User`**-Zertifikatvorlage hinzufügt, wobei der Angreifer der Principal für dieses Recht ist. Um dies auszunutzen, würde der Angreifer zuerst den Besitzer der **`User`**-Vorlage auf sich selbst ändern. Anschließend würde das `mspki-certificate-name-flag` in der Vorlage auf **1** gesetzt, um **`ENROLLEE_SUPPLIES_SUBJECT`** zu aktivieren, wodurch ein Benutzer einen Subject Alternative Name in der Anfrage angeben kann. Daraufhin könnte der Angreifer die Vorlage verwenden, einen Namen eines Domänenadministrators als alternativen Namen wählen und das erhaltene Zertifikat zur Authentifizierung als DA nutzen.

Praktische Einstellungen, die Angreifer für langfristige Domain-Persistenz vornehmen können (siehe {{#ref}}domain-escalation.md{{#endref}} für vollständige Details und Erkennung):

- CA-Policy-Flags, die SAN vom Requester erlauben (z. B. Aktivierung von `EDITF_ATTRIBUTESUBJECTALTNAME2`). Dadurch bleiben ESC1-ähnliche Pfade ausnutzbar.
- Template-DACLs oder Einstellungen, die eine Ausgabe für Authentifizierungszwecke erlauben (z. B. Hinzufügen der Client Authentication EKU, Aktivierung von `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Kontrolle über das `NTAuthCertificates`-Objekt oder die CA-Container, um bösartige Aussteller kontinuierlich wieder einzuführen, falls Verteidiger Bereinigungsversuche unternehmen.

> [!TIP]
> In gehärteten Umgebungen nach KB5014754 stellt die Kombination dieser Fehlkonfigurationen mit expliziten starken Zuordnungen (`altSecurityIdentities`) sicher, dass Ihre ausgestellten oder gefälschten Zertifikate weiterhin nutzbar bleiben, selbst wenn DCs eine starke Zuordnung erzwingen.

### Missbrauch der Zertifikatserneuerung (ESC14) für Persistenz

Wenn Sie ein zur Authentifizierung geeignetes Zertifikat (oder ein Enrollment Agent-Zertifikat) kompromittieren, können Sie es unbegrenzt erneuern, solange die ausstellende Vorlage weiterhin veröffentlicht ist und Ihre CA der Ausstellerkette vertraut. Die Erneuerung behält die ursprünglichen Identitätsbindungen bei, verlängert jedoch die Gültigkeit, was eine Entfernung erschwert, es sei denn, die Vorlage wird korrigiert oder die CA wird neu veröffentlicht.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Wenn Domain Controller in **Full Enforcement** sind, füge `-sid <victim SID>` hinzu (oder verwende ein Template, das weiterhin die SID-Sicherheits-Extension enthält), damit das erneuerte Leaf-Zertifikat weiterhin stark zugeordnet wird, ohne `altSecurityIdentities` anzufassen. Angreifer mit CA-Administratorrechten können außerdem `policy\RenewalValidityPeriodUnits` anpassen, um die Laufzeit erneuerter Zertifikate zu verlängern, bevor sie sich selbst ein Zertifikat ausstellen.

## Referenzen

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
