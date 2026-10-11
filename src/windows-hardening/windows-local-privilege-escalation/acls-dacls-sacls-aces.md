# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Une Access Control List (ACL) est constituée d’un ensemble ordonné d’Access Control Entries (ACEs) qui définissent les protections appliquées à un objet et à ses propriétés. En substance, une ACL définit quelles actions sont autorisées ou interdites à quels principaux de sécurité (utilisateurs ou groupes) sur un objet donné.

Il existe deux types d’ACL :

- **Discretionary Access Control List (DACL) :** spécifie quels utilisateurs et groupes ont ou n’ont pas accès à un objet.
- **System Access Control List (SACL) :** régit l’audit des tentatives d’accès à un objet.

Pour accéder à un fichier, le système compare le descripteur de sécurité de l’objet au jeton d’accès de l’utilisateur afin de déterminer si l’accès doit être accordé et dans quelle mesure, en fonction des ACEs.<sup>[[1]](#references)</sup>

Lorsqu’un répertoire parent accorde un contrôle total, mais qu’un fichier enfant refuse la lecture, examinez séparément la DACL effective, le propriétaire et l’héritage du **fichier enfant**. Modifier la DACL de ce fichier nécessite `WRITE_DAC` sur le fichier ou le droit de propriétaire applicable ; [Microsoft définit `WRITE_DAC`](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) et [documente l’accès implicite du propriétaire](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Les autorisations du répertoire parent ne suffisent pas à établir que le fichier enfant peut être lu ou que sa DACL peut être modifiée.

### **Composants clés**

- **DACL :** contient des ACEs qui accordent ou refusent des autorisations d’accès à un objet aux utilisateurs et aux groupes. Il s’agit essentiellement de l’ACL principale qui définit les droits d’accès.
- **SACL :** utilisée pour auditer l’accès aux objets ; ses ACEs définissent les types d’accès à consigner dans le journal des événements de sécurité. Cela peut être très utile pour détecter les tentatives d’accès non autorisées ou résoudre les problèmes d’accès.<sup>[[1]](#references)</sup>

### **Interaction du système avec les ACLs**

Chaque session utilisateur est associée à un jeton d’accès qui contient les informations de sécurité pertinentes pour cette session, notamment l’identité de l’utilisateur et des groupes, ainsi que les privilèges. Ce jeton contient également un logon SID qui identifie de manière unique la session.

La Local Security Authority (LSASS) traite les demandes d’accès aux objets en examinant leur DACL à la recherche d’ACEs correspondant au principal de sécurité qui tente d’y accéder. L’accès est immédiatement accordé si aucune ACE pertinente n’est trouvée. Sinon, LSASS compare les ACEs au SID du principal de sécurité dans le jeton d’accès afin de déterminer si l’accès peut être accordé.<sup>[[1]](#references)</sup>

### **Processus résumé**

- **ACLs :** définissent les autorisations d’accès au moyen des DACLs et les règles d’audit au moyen des SACLs.
- **Jeton d’accès :** contient les informations sur l’utilisateur, les groupes et les privilèges d’une session.
- **Décision d’accès :** prise en comparant les ACEs de la DACL au jeton d’accès ; les SACLs servent à l’audit.<sup>[[1]](#references)</sup>

### ACEs

Il existe **trois principaux types d’Access Control Entries (ACEs)** :<sup>[[1]](#references)</sup>

- **Access Denied ACE** : cette ACE refuse explicitement l’accès à un objet aux utilisateurs ou aux groupes spécifiés (dans une DACL).
- **Access Allowed ACE** : cette ACE accorde explicitement l’accès à un objet aux utilisateurs ou aux groupes spécifiés (dans une DACL).
- **System Audit ACE** : placée dans une System Access Control List (SACL), cette ACE génère des journaux d’audit lors des tentatives d’accès à un objet par des utilisateurs ou des groupes. Elle indique si l’accès a été autorisé ou refusé, ainsi que la nature de l’accès.

Chaque ACE comporte **quatre composants essentiels** :<sup>[[1]](#references)</sup>

1. Le **Security Identifier (SID)** de l’utilisateur ou du groupe (ou son nom de principal dans une représentation graphique).
2. Un **indicateur** qui identifie le type d’ACE (accès refusé, autorisé ou audit système).
3. Des **indicateurs d’héritage** qui déterminent si les objets enfants peuvent hériter de l’ACE de leur parent.
4. Un [**masque d’accès**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), une valeur de 32 bits qui spécifie les droits accordés sur l’objet.

La détermination de l’accès se fait en examinant chaque ACE dans l’ordre jusqu’à ce que :<sup>[[1]](#references)</sup>

- Une **Access-Denied ACE** refuse explicitement les droits demandés à un trustee identifié dans le jeton d’accès.
- Une ou plusieurs **Access-Allowed ACEs** accordent explicitement tous les droits demandés à un trustee figurant dans le jeton d’accès.
- Après examen de toutes les ACEs, si un droit demandé n’a **pas été explicitement autorisé**, l’accès est **implicitement refusé**.

### Ordre des ACEs

L’ordre dans lequel les **ACEs** (les règles qui indiquent qui peut ou ne peut pas accéder à quelque chose) sont placées dans une liste appelée **DACL** est très important. En effet, dès que le système accorde ou refuse l’accès en fonction de ces règles, il cesse d’examiner les suivantes.<sup>[[1]](#references)</sup>

Il existe une façon optimale d’organiser ces ACEs, appelée **« ordre canonique »**. Cette méthode permet de garantir un fonctionnement fluide et équitable. Voici comment elle s’applique à des systèmes comme **Windows 2000** et **Windows Server 2003** :

- Placez d’abord toutes les règles **spécifiques à cet élément**, avant celles qui proviennent d’ailleurs, comme d’un dossier parent.
- Parmi ces règles spécifiques, placez celles qui disent **« non » (refus)** avant celles qui disent **« oui » (autorisation)**.
- Pour les règles provenant d’ailleurs, commencez par celles de la **source la plus proche**, comme le parent, puis remontez la hiérarchie. Là encore, placez les règles **« non »** avant les règles **« oui »**.

Cette configuration présente deux grands avantages :

- Elle garantit que tout **« non »** explicite est respecté, quelles que soient les autres règles **« oui »**.
- Elle permet au propriétaire d’un élément d’avoir le **dernier mot** sur les personnes autorisées à y accéder, avant que les règles des dossiers parents ou d’autres sources plus éloignées n’entrent en jeu.

En procédant ainsi, le propriétaire d’un fichier ou d’un dossier peut déterminer précisément qui y a accès, afin de s’assurer que les bonnes personnes peuvent y accéder et que les autres ne le peuvent pas.

![Diagramme de l’ordre des entrées de contrôle d’accès NTFS](https://www.ntfs.com/images/screenshots/ACEs.gif)

Cet **« ordre canonique »** vise donc à clarifier les règles d’accès et à assurer leur bon fonctionnement en plaçant les règles spécifiques en premier et en organisant le reste de façon logique.

### Exemple d’interface graphique

[**Exemple tiré de cette page**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Voici l’onglet de sécurité classique d’un dossier, qui montre l’ACL, la DACL et les ACEs :

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Si nous cliquons sur le **bouton Advanced**, nous obtenons plus d’options, comme l’héritage :

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Et si nous ajoutons ou modifions un principal de sécurité :

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Enfin, voici la SACL dans l’onglet Auditing :

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explication simplifiée du contrôle d’accès

Pour gérer l’accès aux ressources, comme un dossier, nous utilisons des listes et des règles appelées Access Control Lists (ACLs) et Access Control Entries (ACEs). Elles définissent qui peut ou ne peut pas accéder à certaines données.<sup>[[1]](#references)</sup>

#### Refuser l’accès à un groupe spécifique

Imaginons que vous ayez un dossier nommé Cost et que vous vouliez que tout le monde puisse y accéder, sauf une équipe marketing. En configurant correctement les règles, nous pouvons refuser explicitement l’accès à l’équipe marketing avant d’autoriser tout le monde. Pour cela, il faut placer la règle qui refuse l’accès à l’équipe marketing avant celle qui autorise tout le monde.

#### Autoriser l’accès à un membre précis d’un groupe auquel l’accès est refusé

Supposons que Bob, le directeur marketing, ait besoin d’accéder au dossier Cost, même si l’équipe marketing ne devrait généralement pas y avoir accès. Nous pouvons ajouter une règle spécifique (ACE) pour Bob qui lui accorde l’accès, et la placer avant la règle qui refuse l’accès à l’équipe marketing. Bob pourra ainsi accéder au dossier malgré la restriction générale qui s’applique à son équipe.

#### Comprendre les Access Control Entries

Les ACEs sont les règles individuelles d’une ACL. Elles identifient les utilisateurs ou les groupes, précisent les accès autorisés ou refusés et déterminent la manière dont ces règles s’appliquent aux éléments enfants (héritage). Il existe deux principaux types d’ACEs :

- **ACEs génériques** : elles s’appliquent largement et concernent tous les types d’objets, ou distinguent uniquement les conteneurs (comme les dossiers) des non-conteneurs (comme les fichiers). Par exemple, une règle qui permet aux utilisateurs de voir le contenu d’un dossier sans leur donner accès aux fichiers qu’il contient.
- **ACEs spécifiques à un objet** : elles offrent un contrôle plus précis et permettent de définir des règles pour certains types d’objets, voire pour des propriétés individuelles d’un objet. Par exemple, dans un répertoire d’utilisateurs, une règle pourrait autoriser un utilisateur à mettre à jour son numéro de téléphone, mais pas ses horaires de connexion.

Chaque ACE contient des informations importantes, comme la personne concernée par la règle (identifiée par un Security Identifier ou SID), ce que la règle autorise ou refuse (au moyen d’un masque d’accès) et la manière dont elle est héritée par d’autres objets.

#### Principales différences entre les types d’ACEs

- Les **ACEs génériques** conviennent aux scénarios simples de contrôle d’accès, où la même règle s’applique à tous les aspects d’un objet ou à tous les objets d’un conteneur.
- Les **ACEs spécifiques à un objet** sont utilisées dans des scénarios plus complexes, notamment dans des environnements comme Active Directory, où il peut être nécessaire de contrôler différemment l’accès à certaines propriétés d’un objet.

En résumé, les ACLs et les ACEs permettent de définir précisément les contrôles d’accès et de garantir que seules les bonnes personnes ou les bons groupes peuvent accéder aux informations ou ressources sensibles. Elles permettent d’ajuster les droits d’accès jusque dans les propriétés individuelles ou les types d’objets.

### Structure d’une Access Control Entry

| Champ ACE  | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type       | Indicateur qui précise le type d’ACE. Windows 2000 et Windows Server 2003 prennent en charge six types d’ACEs : trois types d’ACEs génériques qui s’appliquent à tous les objets sécurisables et trois types d’ACEs spécifiques aux objets, qui peuvent s’appliquer aux objets Active Directory.                                                                                                                                                                                                                  |
| Flags      | Ensemble d’indicateurs binaires qui contrôlent l’héritage et l’audit.                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Size       | Nombre d’octets de mémoire alloués à l’ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Access mask | Valeur de 32 bits dont les bits correspondent aux droits d’accès à l’objet. Les bits peuvent être activés ou désactivés, mais leur signification dépend du type d’ACE. Par exemple, si le bit correspondant au droit de lire les autorisations est activé et que le type d’ACE est Deny, l’ACE refuse le droit de lire les autorisations de l’objet. Si ce même bit est activé et que le type d’ACE est Allow, l’ACE accorde le droit de lire les autorisations de l’objet. Le tableau suivant donne plus de détails sur le masque d’accès. |
| SID        | Identifie l’utilisateur ou le groupe dont l’accès est contrôlé ou surveillé par cette ACE.                                                                                                                                                                                                                                                                                                                                                                                                                      |

### Structure du masque d’accès

| Bit (plage) | Signification                       | Description/Exemple                              |
| ----------- | ----------------------------------- | ------------------------------------------------ |
| 0 - 15      | Droits d’accès spécifiques à l’objet | Lire les données, exécuter, ajouter des données |
| 16 - 22     | Droits d’accès standard             | Supprimer, écrire l’ACL, écrire le propriétaire  |
| 23          | Peut accéder à la security ACL      |                                                  |
| 24 - 27     | Réservé                             |                                                  |
| 28          | Generic ALL (Read, Write, Execute)  | Tout ce qui suit                                 |
| 29          | Generic Execute                     | Tout ce qui est nécessaire pour exécuter un programme |
| 30          | Generic Write                       | Tout ce qui est nécessaire pour écrire dans un fichier |
| 31          | Generic Read                        | Tout ce qui est nécessaire pour lire un fichier  |

## References

- [1] [Comment le système utilise les ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL et l’ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
