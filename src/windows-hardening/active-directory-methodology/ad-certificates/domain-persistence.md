# AD CS Domain Persistence

{{#include ../../../banners/hacktricks-training.md}}

**Ceci est un résumé des techniques de persistance de domaine partagées dans [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**. Consultez-le pour plus de détails.

## Forging Certificates with Stolen CA Certificates - DPERSIST1

Comment pouvez-vous savoir qu'un certificat est un certificat CA ?

Il peut être déterminé qu'un certificat est un certificat CA si plusieurs conditions sont remplies :

- Le certificat est stocké sur le serveur CA, avec sa clé privée sécurisée par le DPAPI de la machine, ou par du matériel tel qu'un TPM/HSM si le système d'exploitation le prend en charge.
- Les champs Émetteur et Sujet du certificat correspondent au nom distinctif de la CA.
- Une extension "CA Version" est présente dans les certificats CA exclusivement.
- Le certificat ne contient pas de champs d'Utilisation de Clé Étendue (EKU).

Pour extraire la clé privée de ce certificat, l'outil `certsrv.msc` sur le serveur CA est la méthode prise en charge via l'interface graphique intégrée. Néanmoins, ce certificat ne diffère pas des autres stockés dans le système ; ainsi, des méthodes telles que la [technique THEFT2](certificate-theft.md#user-certificate-theft-via-dpapi-theft2) peuvent être appliquées pour l'extraction.

Le certificat et la clé privée peuvent également être obtenus en utilisant Certipy avec la commande suivante :
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

Ce certificat falsifié sera **valide** jusqu'à la date de fin spécifiée et **tant que le certificat CA racine est valide** (généralement de 5 à **10+ ans**). Il est également valide pour les **machines**, donc combiné avec **S4U2Self**, un attaquant peut **maintenir une persistance sur n'importe quelle machine de domaine** tant que le certificat CA est valide.\
De plus, les **certificats générés** avec cette méthode **ne peuvent pas être révoqués** car la CA n'en est pas consciente.

## Confiance aux certificats CA malveillants - DPERSIST2

L'objet `NTAuthCertificates` est défini pour contenir un ou plusieurs **certificats CA** dans son attribut `cacertificate`, que Active Directory (AD) utilise. Le processus de vérification par le **contrôleur de domaine** implique de vérifier l'objet `NTAuthCertificates` pour une entrée correspondant à la **CA spécifiée** dans le champ Émetteur du **certificat** authentifiant. L'authentification se poursuit si une correspondance est trouvée.

Un certificat CA auto-signé peut être ajouté à l'objet `NTAuthCertificates` par un attaquant, à condition qu'il ait le contrôle de cet objet AD. Normalement, seuls les membres du groupe **Enterprise Admin**, ainsi que les **Domain Admins** ou **Administrators** dans le **domaine racine de la forêt**, ont la permission de modifier cet objet. Ils peuvent éditer l'objet `NTAuthCertificates` en utilisant `certutil.exe` avec la commande `certutil.exe -dspublish -f C:\Temp\CERT.crt NTAuthCA126`, ou en utilisant le [**PKI Health Tool**](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/import-third-party-ca-to-enterprise-ntauth-store#method-1---import-a-certificate-by-using-the-pki-health-tool).

Cette capacité est particulièrement pertinente lorsqu'elle est utilisée en conjonction avec une méthode précédemment décrite impliquant ForgeCert pour générer dynamiquement des certificats.

## Mauvaise configuration malveillante - DPERSIST3

Les opportunités de **persistance** à travers les **modifications de descripteurs de sécurité des composants AD CS** sont nombreuses. Les modifications décrites dans la section "[Domain Escalation](domain-escalation.md)" peuvent être mises en œuvre de manière malveillante par un attaquant ayant un accès élevé. Cela inclut l'ajout de "droits de contrôle" (par exemple, WriteOwner/WriteDACL/etc.) à des composants sensibles tels que :

- L'objet **ordinateur AD du serveur CA**
- Le **serveur RPC/DCOM du serveur CA**
- Tout **objet ou conteneur AD descendant** dans **`CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`** (par exemple, le conteneur des modèles de certificats, le conteneur des autorités de certification, l'objet NTAuthCertificates, etc.)
- **Groupes AD déléguant des droits pour contrôler AD CS** par défaut ou par l'organisation (comme le groupe Cert Publishers intégré et tous ses membres)

Un exemple de mise en œuvre malveillante impliquerait un attaquant, qui a des **permissions élevées** dans le domaine, ajoutant la permission **`WriteOwner`** au modèle de certificat par défaut **`User`**, l'attaquant étant le principal pour ce droit. Pour exploiter cela, l'attaquant changerait d'abord la propriété du modèle **`User`** à son profit. Ensuite, le **`mspki-certificate-name-flag`** serait défini sur **1** sur le modèle pour activer **`ENROLLEE_SUPPLIES_SUBJECT`**, permettant à un utilisateur de fournir un Nom Alternatif de Sujet dans la demande. Par la suite, l'attaquant pourrait **s'inscrire** en utilisant le **modèle**, choisissant un nom de **administrateur de domaine** comme nom alternatif, et utiliser le certificat acquis pour s'authentifier en tant que DA.

{{#include ../../../banners/hacktricks-training.md}}
