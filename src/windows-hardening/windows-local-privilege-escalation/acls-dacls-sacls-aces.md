# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Liste de contrôle d'accès (ACL)**

Une liste de contrôle d'accès (ACL) se compose d'un ensemble ordonné d'entrées de contrôle d'accès (ACE) qui définissent les protections d'un objet et de ses propriétés. En essence, une ACL définit quelles actions de quels security principals (utilisateurs ou groupes) sont autorisées ou refusées sur un objet donné.

Il existe deux types d'ACL :

- **Discretionary Access Control List (DACL) :** spécifie quels utilisateurs et groupes ont ou n'ont pas accès à un objet.
- **System Access Control List (SACL) :** régit l'audit des tentatives d'accès à un objet.

Le processus d'accès à un fichier implique que le système vérifie le security descriptor de l'objet par rapport à l'access token de l'utilisateur afin de déterminer si l'accès doit être accordé et l'étendue de cet accès, en fonction des ACE.<sup>[[1]](#references)</sup>

### **Composants clés**

- **DACL :** contient des ACE qui accordent ou refusent des permissions d'accès aux utilisateurs et aux groupes pour un objet. Il s'agit essentiellement de l'ACL principale qui définit les droits d'accès.
- **SACL :** utilisée pour auditer l'accès aux objets, les ACE définissant les types d'accès à enregistrer dans le Security Event Log. Cela peut être très utile pour détecter les tentatives d'accès non autorisées ou résoudre les problèmes d'accès.<sup>[[1]](#references)</sup>

### **Interaction du système avec les ACL**

Chaque session utilisateur est associée à un access token contenant les informations de sécurité pertinentes pour cette session, notamment les identités de l'utilisateur et des groupes, ainsi que les privilèges. Ce token contient également un logon SID qui identifie de manière unique la session.

La Local Security Authority (LSASS) traite les demandes d'accès aux objets en examinant la DACL à la recherche d'ACE correspondant au security principal qui tente d'accéder à l'objet. L'accès est immédiatement accordé si aucune ACE pertinente n'est trouvée. Sinon, LSASS compare les ACE au SID du security principal présent dans l'access token afin de déterminer si l'accès est autorisé.<sup>[[1]](#references)</sup>

### **Processus résumé**

- **ACL :** définit les permissions d'accès via les DACL et les règles d'audit via les SACL.
- **Access Token :** contient les informations sur l'utilisateur, les groupes et les privilèges d'une session.
- **Décision d'accès :** prise en comparant les ACE de la DACL avec l'access token ; les SACL sont utilisées pour l'audit.<sup>[[1]](#references)</sup>

### ACE

Il existe **trois principaux types d'Access Control Entries (ACE)** :<sup>[[1]](#references)</sup>

- **Access Denied ACE** : cette ACE refuse explicitement l'accès à un objet pour les utilisateurs ou groupes spécifiés (dans une DACL).
- **Access Allowed ACE** : cette ACE accorde explicitement l'accès à un objet pour les utilisateurs ou groupes spécifiés (dans une DACL).
- **System Audit ACE** : placée dans une System Access Control List (SACL), cette ACE est chargée de générer des journaux d'audit lors des tentatives d'accès à un objet par des utilisateurs ou des groupes. Elle indique si l'accès a été autorisé ou refusé, ainsi que la nature de l'accès.

Chaque ACE possède **quatre composants essentiels** :<sup>[[1]](#references)</sup>

1. Le **Security Identifier (SID)** de l'utilisateur ou du groupe (ou le nom de son principal dans une représentation graphique).
2. Un **flag** qui identifie le type d'ACE (access denied, allowed ou system audit).
3. Des **flags d'héritage** qui déterminent si les objets enfants peuvent hériter de l'ACE de leur parent.
4. Un [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), une valeur de 32 bits spécifiant les droits accordés sur l'objet.

La détermination de l'accès s'effectue en examinant séquentiellement chaque ACE jusqu'à ce que :<sup>[[1]](#references)</sup>

- Une **Access-Denied ACE** refuse explicitement les droits demandés à un trustee identifié dans l'access token.
- Une ou plusieurs **Access-Allowed ACE** accordent explicitement tous les droits demandés à un trustee présent dans l'access token.
- Après vérification de toutes les ACE, si un droit demandé n'a **pas été explicitement autorisé**, l'accès est implicitement **refusé**.

### Ordre des ACE

La manière dont les **ACE** (règles indiquant qui peut ou ne peut pas accéder à quelque chose) sont placées dans une liste appelée **DACL** est très importante. En effet, une fois que le système accorde ou refuse l'accès sur la base de ces règles, il cesse d'examiner les suivantes.<sup>[[1]](#references)</sup>

Il existe une meilleure manière d'organiser ces ACE, appelée **« ordre canonique »**. Cette méthode permet de garantir un fonctionnement fluide et cohérent. Voici comment elle fonctionne pour des systèmes tels que **Windows 2000** et **Windows Server 2003** :

- Commencer par placer toutes les règles **spécifiques à cet élément** avant celles qui proviennent d'un autre emplacement, comme un dossier parent.
- Parmi ces règles spécifiques, placer celles qui indiquent **« non » (deny)** avant celles qui indiquent **« oui » (allow)**.
- Pour les règles provenant d'un autre emplacement, commencer par celles issues de la **source la plus proche**, comme le parent, puis remonter progressivement. Là encore, placer les règles **« non »** avant les règles **« oui »**.

Cette configuration présente deux avantages principaux :

- Elle garantit que lorsqu'un **« non »** spécifique est présent, celui-ci est respecté, quelles que soient les autres règles **« oui »**.
- Elle permet au propriétaire d'un élément d'avoir le **dernier mot** sur les personnes autorisées à y accéder, avant que les règles des dossiers parents ou des niveaux supérieurs n'entrent en jeu.

En procédant ainsi, le propriétaire d'un fichier ou d'un dossier peut définir avec précision qui peut y accéder, en s'assurant que les bonnes personnes puissent y accéder et que les autres ne le puissent pas.

![Diagramme de l'ordre des entrées de contrôle d'accès NTFS](https://www.ntfs.com/images/screenshots/ACEs.gif)

Ainsi, cet **« ordre canonique »** vise à garantir que les règles d'accès sont claires et fonctionnelles, en plaçant les règles spécifiques en premier et en organisant le tout de manière cohérente.

### Exemple d'interface graphique

[**Exemple provenant d'ici**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Voici l'onglet de sécurité classique d'un dossier affichant l'ACL, la DACL et les ACE :

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Si nous cliquons sur le **bouton Advanced**, nous obtenons davantage d'options, comme l'héritage :

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Et si vous ajoutez ou modifiez un Security Principal :

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Enfin, la SACL se trouve dans l'onglet Auditing :

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explication simplifiée du contrôle d'accès

Lors de la gestion de l'accès à des ressources, comme un dossier, nous utilisons des listes et des règles appelées Access Control Lists (ACL) et Access Control Entries (ACE). Elles définissent qui peut ou ne peut pas accéder à certaines données.<sup>[[1]](#references)</sup>

#### Refuser l'accès à un groupe spécifique

Imaginons que vous possédez un dossier nommé Cost et que vous souhaitez que tout le monde puisse y accéder, à l'exception d'une équipe marketing. En configurant correctement les règles, nous pouvons nous assurer que l'accès à l'équipe marketing est explicitement refusé avant d'autoriser tous les autres utilisateurs. Pour cela, il faut placer la règle qui refuse l'accès à l'équipe marketing avant celle qui autorise l'accès à tout le monde.

#### Autoriser l'accès à un membre spécifique d'un groupe refusé

Supposons que Bob, le directeur marketing, ait besoin d'accéder au dossier Cost, même si l'équipe marketing ne doit généralement pas y avoir accès. Nous pouvons ajouter une règle spécifique (ACE) pour Bob afin de lui accorder l'accès, et la placer avant la règle qui refuse l'accès à l'équipe marketing. Bob obtient ainsi l'accès malgré la restriction générale appliquée à son équipe.

#### Comprendre les Access Control Entries

Les ACE sont les règles individuelles d'une ACL. Elles identifient les utilisateurs ou les groupes, spécifient les accès autorisés ou refusés et déterminent comment ces règles s'appliquent aux sous-éléments (héritage). Il existe deux principaux types d'ACE :

- **Generic ACEs** : elles s'appliquent de manière générale, en affectant tous les types d'objets ou en faisant uniquement la distinction entre les containers (comme les dossiers) et les objets qui n'en sont pas (comme les fichiers). Par exemple, une règle qui permet aux utilisateurs de voir le contenu d'un dossier sans leur permettre d'accéder aux fichiers qu'il contient.
- **Object-Specific ACEs** : elles fournissent un contrôle plus précis, en permettant de définir des règles pour des types d'objets spécifiques, voire pour des propriétés individuelles au sein d'un objet. Par exemple, dans un répertoire d'utilisateurs, une règle peut autoriser un utilisateur à modifier son numéro de téléphone, mais pas ses horaires de connexion.

Chaque ACE contient des informations importantes, notamment le sujet auquel la règle s'applique (à l'aide d'un Security Identifier ou SID), ce que la règle autorise ou refuse (à l'aide d'un access mask) et la manière dont elle est héritée par les autres objets.

#### Principales différences entre les types d'ACE

- Les **Generic ACEs** conviennent aux scénarios simples de contrôle d'accès, dans lesquels la même règle s'applique à tous les aspects d'un objet ou à tous les objets d'un container.
- Les **Object-Specific ACEs** sont utilisées dans des scénarios plus complexes, notamment dans des environnements comme Active Directory, où il peut être nécessaire de contrôler différemment l'accès à des propriétés spécifiques d'un objet.

En résumé, les ACL et les ACE permettent de définir des contrôles d'accès précis, en garantissant que seuls les individus ou groupes appropriés puissent accéder aux informations ou ressources sensibles, avec la possibilité d'adapter les droits d'accès jusqu'au niveau des propriétés individuelles ou des types d'objets.

### Structure d'une Access Control Entry

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flag indiquant le type d'ACE. Windows 2000 et Windows Server 2003 prennent en charge six types d'ACE : trois types d'ACE génériques associés à tous les objets sécurisables et trois types d'ACE spécifiques aux objets, qui peuvent concerner les objets Active Directory.                                                                                                                                                                                                                                                            |
| Flags       | Ensemble de flags binaires contrôlant l'héritage et l'audit.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Nombre d'octets de mémoire alloués pour l'ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Valeur de 32 bits dont les bits correspondent aux droits d'accès de l'objet. Les bits peuvent être activés ou désactivés, mais la signification de ce paramètre dépend du type d'ACE. Par exemple, si le bit correspondant au droit de lire les permissions est activé et que le type d'ACE est Deny, l'ACE refuse le droit de lire les permissions de l'objet. Si le même bit est activé mais que le type d'ACE est Allow, l'ACE accorde le droit de lire les permissions de l'objet. Plus de détails sur l'access mask figurent dans le tableau suivant. |
| SID         | Identifie un utilisateur ou un groupe dont l'accès est contrôlé ou surveillé par cette ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Structure de l'access mask

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Read data, Execute, Append data           |
| 16 - 22     | Standard Access Rights             | Delete, Write ACL, Write Owner            |
| 23          | Can access security ACL            |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Everything below                          |
| 29          | Generic Execute                    | All things necessary to execute a program |
| 30          | Generic Write                      | All things necessary to write to a file   |
| 31          | Generic Read                       | All things necessary to read a file       |

## Références

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
