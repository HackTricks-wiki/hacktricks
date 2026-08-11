# Trousseau macOS

{{#include ../../banners/hacktricks-training.md}}

## Trousseaux principaux

- Le **trousseau utilisateur** (`~/Library/Keychains/login.keychain-db`), utilisé pour stocker les **identifiants propres à l'utilisateur**, comme les mots de passe d'applications, les mots de passe Internet, les certificats générés par l'utilisateur, les mots de passe réseau et les clés publiques/privées générées par l'utilisateur.
- Le **trousseau système** (`/Library/Keychains/System.keychain`), qui stocke les **identifiants à l'échelle du système**, comme les mots de passe WiFi, les certificats racine du système, les clés privées du système et les mots de passe des applications système.<sup>[[1]](#references)</sup>
- Il est possible de trouver d'autres composants, comme des certificats, dans `/System/Library/Keychains/*`
- Dans **iOS**, il n'existe qu'un seul **trousseau**, situé dans `/private/var/Keychains/`. Ce dossier contient également des bases de données pour le `TrustStore`, les autorités de certification (`caissuercache`) et les entrées OSCP (`ocspache`).
- Les applications sont limitées dans le trousseau à leur zone privée, en fonction de leur identifiant d'application.

### Accès au trousseau par mot de passe

Ces fichiers, bien qu'ils ne disposent d'aucune protection intrinsèque et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe en clair de l'utilisateur pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour le déchiffrement.<sup>[[1]](#references)</sup>

## Protections des entrées du trousseau

### ACL

Chaque entrée du trousseau est régie par des **listes de contrôle d'accès (ACL)** qui déterminent qui peut effectuer différentes actions sur l'entrée du trousseau, notamment :<sup>[[1]](#references)</sup>

- **ACLAuthorizationExportClear** : permet au détenteur d'obtenir le secret en clair.
- **ACLAuthorizationExportWrapped** : permet au détenteur d'obtenir le secret en clair chiffré avec un autre mot de passe fourni.
- **ACLAuthorizationAny** : permet au détenteur d'effectuer n'importe quelle action.

Les ACL sont également accompagnées d'une **liste d'applications approuvées** qui peuvent effectuer ces actions sans demander de confirmation. Il peut s'agir de :<sup>[[1]](#references)</sup>

- **N`il`** (aucune autorisation requise, **tout le monde est approuvé**)
- Une liste **vide** (**personne** n'est approuvé)
- Une **liste** d'**applications** spécifiques.

L'entrée peut également contenir la clé **`ACLAuthorizationPartitionID`,** utilisée pour identifier le **teamid, apple** et le **cdhash**.<sup>[[1]](#references)</sup>

- Si le **teamid** est spécifié, l'application doit avoir le **même teamid** pour **accéder à la valeur de l'entrée** sans **demander de confirmation**.
- Si **apple** est spécifié, l'application doit être **signée** par **Apple**.
- Si le **cdhash** est indiqué, l'**application** doit avoir le **cdhash** spécifié.

### Création d'une entrée du trousseau

Lorsqu'une **nouvelle** **entrée** est créée à l'aide de **`Keychain Access.app`**, les règles suivantes s'appliquent :<sup>[[1]](#references)</sup>

- Toutes les applications peuvent chiffrer.
- **Aucune application** ne peut exporter/déchiffrer (sans demander confirmation à l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut modifier les ACL.
- Le **partitionID** est défini sur **`apple`**.

Lorsqu'une **application crée une entrée dans le trousseau**, les règles sont légèrement différentes :<sup>[[1]](#references)</sup>

- Toutes les applications peuvent chiffrer.
- Seule **l'application créatrice** (ou toute autre application ajoutée explicitement) peut exporter/déchiffrer (sans demander confirmation à l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut modifier les ACL.
- Le **partitionID** est défini sur **`teamid:[teamID here]`**.

## Accéder au trousseau

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entry's PartitionID value
security set-generic-password-partition-list -s "test service" -a "test account" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> L'**énumération et le dumping** des secrets du **keychain** qui **ne génèrent pas de prompt** peuvent être effectués avec l'outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> D'autres endpoints d'API sont disponibles dans le code source de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Lister et obtenir des **informations** sur chaque entrée du keychain à l'aide du **Security Framework**, ou consulter également l'outil cli open source d'Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Voici quelques exemples d'API :<sup>[[1]](#references)</sup>

- L'API **`SecItemCopyMatching`** fournit des informations sur chaque entrée et certains attributs peuvent être définis lors de son utilisation :
- **`kSecReturnData`** : Si la valeur est true, l'API essaiera de déchiffrer les données (définir sur false pour éviter les pop-ups potentiels)
- **`kSecReturnRef`** : Obtenir également une référence vers l'élément du keychain (définir sur true si vous constatez ensuite que vous pouvez le déchiffrer sans pop-up)
- **`kSecReturnAttributes`** : Obtenir les métadonnées des entrées
- **`kSecMatchLimit`** : Nombre de résultats à retourner
- **`kSecClass`** : Type d'entrée du keychain

Obtenir les **ACLs** de chaque entrée :<sup>[[1]](#references)</sup>

- Avec l'API **`SecAccessCopyACLList`**, vous pouvez obtenir l'**ACL de l'élément du keychain**. Elle renvoie une liste d'ACLs (telles que `ACLAuthorizationExportClear` et les autres mentionnées précédemment), où chaque entrée possède :
- Description
- **Trusted Application List**. Il peut s'agir de :
- Une app : /Applications/Slack.app
- Un binaire : /usr/libexec/airportd
- Un groupe : group://AirPort

Exporter les données :<sup>[[1]](#references)</sup>

- L'API **`SecKeychainItemCopyContent`** récupère le plaintext
- L'API **`SecItemExport`** exporte les clés et les certificats, mais il peut être nécessaire de définir des mots de passe pour exporter le contenu chiffré

Voici les conditions requises pour pouvoir **exporter un secret sans prompt** :<sup>[[1]](#references)</sup>

- Si **1+ trusted** apps sont listées :
- Il faut disposer des **autorisations** appropriées (**`Nil`**, ou faire **partie** de la liste autorisée des apps dans l'autorisation d'accès aux informations secrètes)
- La signature du code doit correspondre au **PartitionID**
- La signature du code doit correspondre à celle d'une **trusted app** (ou être membre du bon KeychainAccessGroup)
- Si **toutes les applications sont trusted** :
- Il faut disposer des **autorisations** appropriées
- La signature du code doit correspondre au **PartitionID**
- S'il n'y a **pas de PartitionID**, ce point n'est pas nécessaire

> [!CAUTION]
> Par conséquent, si **1 application est listée**, vous devez **injecter du code dans cette application**.
>
> Si **apple** est indiqué dans le **partitionID**, vous pouvez y accéder avec **`osascript`** ; cela concerne donc tout ce qui fait confiance à toutes les applications avec apple dans le partitionID. **`Python`** peut également être utilisé à cette fin.

### Deux attributs supplémentaires

- **Invisible** : Il s'agit d'un indicateur booléen permettant de **masquer** l'entrée dans l'application **UI** Keychain<sup>[[1]](#references)</sup>
- **General** : Sert à stocker des **métadonnées** (elles ne sont donc **PAS CHIFFRÉES**)<sup>[[1]](#references)</sup>
- Microsoft stockait en clair tous les refresh tokens permettant d'accéder à des endpoints sensibles.<sup>[[1]](#references)</sup>

## References

- [1] [#OBTS v5.0 : « Exploiter le macOS Keychain » - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
{{#include ../../banners/hacktricks-training.md}}
