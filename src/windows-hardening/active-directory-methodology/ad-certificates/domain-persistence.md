# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Voici un résumé des techniques de domain persistence présentées dans [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consultez ce document pour plus de détails.<sup>[[5]](#references)</sup>

## Forging Certificates with Stolen CA Certificates (Golden Certificate) - DPERSIST1

Comment déterminer qu’un certificat est un certificat d’autorité de certification (CA) ?

On peut déterminer qu’un certificat est un certificat CA si plusieurs conditions sont réunies :<sup>[[5]](#references)</sup>

- Le certificat est stocké sur le serveur CA, avec sa clé privée protégée par le DPAPI de la machine, ou par du matériel tel qu’un TPM/HSM si le système d’exploitation le prend en charge.
- Les champs Issuer et Subject du certificat correspondent au distinguished name de la CA.
- Une extension « CA Version » est présente exclusivement dans les certificats CA.
- Le certificat ne contient aucun champ Extended Key Usage (EKU).

Pour extraire la clé privée de ce certificat, l’outil `certsrv.msc` sur le serveur CA constitue la méthode prise en charge via l’interface graphique intégrée. Cependant, ce certificat ne diffère pas des autres certificats stockés dans le système ; des méthodes telles que la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) peuvent donc être utilisées pour l’extraire.

Le certificat et la clé privée peuvent également être obtenus avec Certipy à l’aide de la commande suivante :<sup>[[2]](#references)</sup>
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Après avoir obtenu le certificat de l'AC et sa clé privée au format `.pfx`, des outils tels que [ForgeCert](https://github.com/GhostPack/ForgeCert) peuvent être utilisés pour générer des certificats valides :
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
> L’utilisateur ciblé par la falsification de certificat doit être actif et capable de s’authentifier dans Active Directory pour que le processus réussisse. Falsifier un certificat pour des comptes spéciaux comme krbtgt est inefficace.

Ce certificat falsifié sera **valide** jusqu’à la date de fin spécifiée et **tant que le certificat de l’autorité de certification racine sera valide** (généralement de 5 à **plus de 10 ans**). Il est également valide pour les **machines** ; combiné à **S4U2Self**, il permet donc à un attaquant de **maintenir sa persistance sur n’importe quelle machine du domaine** tant que le certificat de l’autorité de certification reste valide.\
De plus, les **certificats générés** avec cette méthode **ne peuvent pas être révoqués**, car l’autorité de certification n’en a pas connaissance.

### Fonctionnement avec Strong Certificate Mapping Enforcement (2025+)

Depuis le 11 février 2025 (après le déploiement de KB5014754), les contrôleurs de domaine utilisent par défaut le mode **Full Enforcement** pour les mappings de certificats. En pratique, cela signifie que vos certificats falsifiés doivent soit :

- Contenir une liaison forte avec le compte cible (par exemple, l’extension de sécurité SID), ou
- Être associés à un mapping fort et explicite sur l’attribut `altSecurityIdentities` de l’objet cible.<sup>[[1]](#references)</sup>

Une approche fiable pour la persistance consiste à générer un certificat falsifié lié à l’Enterprise CA volée, puis à ajouter un mapping fort et explicite au principal victime :
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- Si vous pouvez créer des certificats falsifiés qui incluent l’extension de sécurité SID, ceux-ci seront mappés implicitement même sous Full Enforcement. Sinon, préférez les mappages forts explicites. Consultez [account-persistence](account-persistence.md) pour plus d’informations sur les mappages explicites.
- La révocation n’aide pas les défenseurs ici : les certificats falsifiés sont inconnus de la base de données de l’AC et ne peuvent donc pas être révoqués.

#### Falsification compatible avec Full-Enforcement (SID-aware)

Les outils mis à jour vous permettent d’intégrer directement le SID, afin que les golden certificates restent utilisables même lorsque les DC rejettent les mappages faibles :<sup>[[3]](#references)</sup>
```bash
# Certify 2.0 integrates ForgeCert and can embed SID
Certify.exe forge --ca-pfx CORP-DC-CA.pfx --ca-pass Password123! \
--upn administrator@corp.local --sid S-1-5-21-1111111111-2222222222-3333333333-500 \
--outfile administrator_sid.pfx

# Certipy also supports SID in forged certs
certipy forge -ca-pfx CORP-DC-CA.pfx -upn administrator@corp.local \
-sid S-1-5-21-1111111111-2222222222-3333333333-500 -out administrator_sid.pfx
```
En intégrant le SID, vous évitez de devoir modifier `altSecurityIdentities`, qui peut être surveillé, tout en satisfaisant les vérifications de strong mapping.

## Faire confiance aux certificats CA Rogue - DPERSIST2

L’objet `NTAuthCertificates` est défini pour contenir un ou plusieurs **certificats CA** dans son attribut `cacertificate`, qu’Active Directory (AD) utilise. Le processus de vérification par le **contrôleur de domaine** consiste à rechercher dans l’objet `NTAuthCertificates` une entrée correspondant à la **CA spécifiée** dans le champ Issuer du **certificat** utilisé pour l’authentification. L’authentification se poursuit si une correspondance est trouvée.<sup>[[5]](#references)</sup>

Un certificat CA auto-signé peut être ajouté à l’objet `NTAuthCertificates` par un attaquant, à condition qu’il contrôle cet objet AD. Normalement, seuls les membres du groupe **Enterprise Admin**, ainsi que les **Domain Admins** ou les **Administrators** du **domaine racine de la forêt**, disposent des autorisations nécessaires pour modifier cet objet. Ils peuvent modifier l’objet `NTAuthCertificates` à l’aide de `certutil.exe` avec la commande `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ou en utilisant le [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Cette capacité est particulièrement pertinente lorsqu’elle est utilisée conjointement avec une méthode présentée précédemment impliquant ForgeCert pour générer dynamiquement des certificats.

> Considérations de mapping postérieur à 2025 : placer une CA rogue dans NTAuth établit uniquement la confiance envers la CA émettrice. Pour utiliser des certificats finaux lors de l’authentification lorsque les DC sont en **Full Enforcement**, le certificat final doit soit contenir l’extension de sécurité SID, soit disposer d’un mapping fort explicite sur l’objet cible (par exemple, Issuer+Serial dans `altSecurityIdentities`). Voir {{#ref}}account-persistence.md{{#endref}}.

## Mauvaise configuration malveillante - DPERSIST3

Les possibilités de **persistence** via des modifications des **security descriptors** des composants d’AD CS sont nombreuses. Les modifications décrites dans la section "[Domain Escalation](domain-escalation.md)" peuvent être implémentées de manière malveillante par un attacker disposant d’un accès élevé. Cela inclut l’ajout de « control rights » (par exemple, WriteOwner/WriteDACL/etc.) à des composants sensibles tels que :<sup>[[5]](#references)</sup>

- L’objet **AD computer** du **CA server**
- Le **RPC/DCOM server** du **CA server**
- Tout **AD object ou container descendant** dans **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (par exemple, le Certificate Templates container, le Certification Authorities container, l’objet NTAuthCertificates, etc.)
- Les **AD groups** auxquels des droits de contrôle d’AD CS sont délégués par défaut ou par l’organisation (comme le groupe intégré Cert Publishers et chacun de ses membres)

Un exemple d’implémentation malveillante consisterait, pour un attacker disposant de **elevated permissions** dans le domaine, à ajouter la permission **`WriteOwner`** au **`User`** certificate template par défaut, l’attacker étant le principal associé à ce droit. Pour l’exploiter, l’attacker changerait d’abord la propriété du **`User`** template afin d’en devenir lui-même le propriétaire. Ensuite, **`mspki-certificate-name-flag`** serait défini sur **1** dans le template afin d’activer **`ENROLLEE_SUPPLIES_SUBJECT`**, permettant à un utilisateur de fournir un Subject Alternative Name dans la requête. L’attacker pourrait alors **enroll** via le **template**, en choisissant le nom d’un **domain administrator** comme nom alternatif, puis utiliser le certificat obtenu pour s’authentifier en tant que DA.

Paramètres pratiques que les attackers peuvent définir pour assurer une persistence à long terme dans le domaine (voir {{#ref}}domain-escalation.md{{#endref}} pour tous les détails et la détection) :

- Les indicateurs de stratégie de la CA qui autorisent le SAN fourni par les requesters (par exemple, en activant `EDITF_ATTRIBUTESUBJECTALTNAME2`). Cela maintient les chemins similaires à ESC1 exploitables.
- Les DACL ou paramètres du template qui autorisent l’émission compatible avec l’authentification (par exemple, en ajoutant le Client Authentication EKU et en activant `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Le contrôle de l’objet `NTAuthCertificates` ou des containers de la CA afin de réintroduire continuellement des issuers rogue si les defenders tentent un cleanup.

> [!TIP]
> Dans les environnements durcis après KB5014754, associer ces mauvaises configurations à des mappings forts explicites (`altSecurityIdentities`) garantit que les certificats émis ou forgés restent utilisables même lorsque les DC appliquent le strong mapping.

### Abus du renouvellement de certificat (ESC14) pour la persistence

Si vous compromettez un certificat compatible avec l’authentification (ou un certificat Enrollment Agent), vous pouvez le **renew** indéfiniment tant que le template émetteur reste publié et que votre CA fait toujours confiance à la chaîne d’issuer. Le renouvellement conserve les bindings d’identité d’origine tout en prolongeant la validité, ce qui rend l’éviction difficile, sauf si le template est corrigé ou si la CA est republiée.<sup>[[4]](#references)</sup>
```bash
# Renew a stolen user cert to extend validity
certipy req -ca CORP-DC-CA -template User -pfx stolen_user.pfx -renew -out user_renewed_2026.pfx

# Renew an on-behalf-of cert issued via an Enrollment Agent
certipy req -ca CORP-DC-CA -on-behalf-of 'CORP/victim' -pfx agent.pfx -renew -out victim_renewed.pfx
```
Si les contrôleurs de domaine sont en **Full Enforcement**, ajoutez `-sid <victim SID>` (ou utilisez un template qui inclut toujours l’extension de sécurité SID) afin que le certificat feuille renouvelé continue d’être mappé de manière forte sans modifier `altSecurityIdentities`. Les attaquants disposant de droits d’administration sur la CA peuvent également modifier `policy\RenewalValidityPeriodUnits` afin de prolonger la durée de validité des certificats renouvelés avant de s’en délivrer un.<sup>[[2]](#references)[[4]](#references)</sup>


## Références

- [1] [Microsoft KB5014754 – Modifications de l’authentification basée sur les certificats sur les contrôleurs de domaine Windows (calendrier d’application et mappages forts)](https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16)
- [2] [Certipy – Référence des commandes et utilisation de forge/auth](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference)
- [3] [SpecterOps – Certify 2.0 (forge intégré avec prise en charge des SID)](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [4] [Présentation de l’abus du renouvellement ESC14](https://www.adcs-security.com/attacks/esc14)
- [5] [SpecterOps – Certified Pre-Owned : Abus des Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}
