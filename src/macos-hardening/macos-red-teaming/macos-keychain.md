# Trousseau macOS

{{#include ../../banners/hacktricks-training.md}}

## Principaux trousseaux

- Le **trousseau utilisateur** (`~/Library/Keychains/login.keychain-db`), utilisé pour stocker les **identifiants propres à l'utilisateur**, comme les mots de passe d'applications, les mots de passe Internet, les certificats générés par l'utilisateur, les mots de passe réseau et les clés publiques/privées générées par l'utilisateur.
- Le **trousseau système** (`/Library/Keychains/System.keychain`), qui stocke les **identifiants à l'échelle du système**, tels que les mots de passe WiFi, les certificats racine du système, les clés privées du système et les mots de passe des applications système.<sup>[1]</sup>
- Il est possible de trouver d'autres composants, comme des certificats, dans `/System/Library/Keychains/*`
- Dans **iOS**, il n'existe qu'un seul **trousseau**, situé dans `/private/var/Keychains/`. Ce dossier contient également les bases de données du `TrustStore`, des autorités de certification (`caissuercache`) et des entrées OSCP (`ocspache`).
- Les applications sont limitées, dans le trousseau, à leur zone privée en fonction de leur identifiant d'application.

### Accès au mot de passe du trousseau

Ces fichiers, bien qu'ils ne disposent d'aucune protection inhérente et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe en clair de l'utilisateur pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour le déchiffrement.<sup>[1]</sup>

## Protections des entrées du trousseau

### ACL

Chaque entrée du trousseau est régie par des **listes de contrôle d'accès (ACL)** qui déterminent qui peut effectuer différentes actions sur l'entrée du trousseau, notamment :<sup>[1]</sup>

- **ACLAuhtorizationExportClear** : permet au détenteur d'obtenir le secret en texte clair.
- **ACLAuhtorizationExportWrapped** : permet au détenteur d'obtenir le texte clair chiffré avec un autre mot de passe fourni.
- **ACLAuhtorizationAny** : permet au détenteur d'effectuer n'importe quelle action.

Les ACL sont également accompagnées d'une **liste d'applications approuvées** pouvant effectuer ces actions sans demande de confirmation. Cette liste peut être :<sup>[1]</sup>

- **N`il`** (aucune autorisation requise, **tout le monde est approuvé**)
- Une liste **vide** (**personne** n'est approuvé)
- Une **liste** d'**applications** spécifiques.

L'entrée peut également contenir la clé **`ACLAuthorizationPartitionID`,** utilisée pour identifier le **teamid, apple** et le **cdhash**.<sup>[1]</sup>

- Si le **teamid** est spécifié, pour **accéder à la valeur de l'entrée** **sans** **demande de confirmation**, l'application utilisée doit avoir le **même teamid**.
- Si **apple** est spécifié, l'application doit être **signée** par **Apple**.
- Si le **cdhash** est indiqué, l'**application** doit avoir le **cdhash** spécifique.

### Création d'une entrée de trousseau

Lorsqu'une **nouvelle** **entrée** est créée avec **`Keychain Access.app`**, les règles suivantes s'appliquent :<sup>[1]</sup>

- Toutes les applications peuvent chiffrer.
- **Aucune application** ne peut exporter/déchiffrer (sans demander confirmation à l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut modifier les ACL.
- Le **partitionID** est défini sur **`apple`**.

Lorsqu'une **application crée une entrée dans le trousseau**, les règles sont légèrement différentes :<sup>[1]</sup>

- Toutes les applications peuvent chiffrer.
- Seule **l'application qui a créé l'entrée** (ou toute autre application explicitement ajoutée) peut exporter/déchiffrer (sans demander confirmation à l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut modifier les ACL.
- Le **partitionID** est défini sur **`teamid:[teamID here]`**.

## Accès au trousseau

### `security`
```bash
# List keychains
security list-keychains

# Dump all metadata and decrypted secrets (a lot of pop-ups)
security dump-keychain -a -d

# Find generic password for the "Slack" account and print the secrets
security find-generic-password -a "Slack" -g

# Change the specified entrys PartitionID entry
security set-generic-password-parition-list -s "test service" -a "test acount" -S

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```
### APIs

> [!TIP]
> L'**enumeration et le dumping** des secrets du **keychain** qui **ne généreront pas de prompt** peuvent être effectués avec l'outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> D'autres endpoints API sont disponibles dans le code source de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Listez et obtenez des **informations** sur chaque entrée du keychain en utilisant le **Security Framework**, ou consultez également l'outil CLI open source d'Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Voici quelques exemples d'API :<sup>[1]</sup>

- L'API **`SecItemCopyMatching`** fournit des informations sur chaque entrée et certains attributs peuvent être définis lors de son utilisation :
- **`kSecReturnData`** : Si la valeur est true, l'API tentera de déchiffrer les données (définissez-la sur false pour éviter d'éventuelles fenêtres popup)
- **`kSecReturnRef`** : Obtient également une référence vers l'élément du keychain (définissez-la sur true si vous constatez par la suite que vous pouvez le déchiffrer sans popup)
- **`kSecReturnAttributes`** : Obtient les métadonnées des entrées
- **`kSecMatchLimit`** : Nombre de résultats à retourner
- **`kSecClass`** : Type d'entrée du keychain

Obtenez les **ACLs** de chaque entrée :<sup>[1]</sup>

- Avec l'API **`SecAccessCopyACLList`**, vous pouvez obtenir l'**ACL de l'élément du keychain**. Elle retournera une liste d'ACLs (comme `ACLAuhtorizationExportClear` et les autres mentionnées précédemment), chaque liste contenant :
- Description
- **Trusted Application List**. Elle peut contenir :
- Une app : /Applications/Slack.app
- Un binaire : /usr/libexec/airportd
- Un groupe : group://AirPort

Exportez les données :<sup>[1]</sup>

- L'API **`SecKeychainItemCopyContent`** obtient le texte en clair
- L'API **`SecItemExport`** exporte les clés et les certificats, mais il peut être nécessaire de définir des mots de passe pour exporter le contenu chiffré

Voici les **conditions** nécessaires pour pouvoir **exporter un secret sans popup** :<sup>[1]</sup>

- Si au moins **1 app trusted** est listée :
- Il faut les **autorisations** appropriées (**`Nil`**, ou faire **partie** de la liste autorisée d'apps dans l'autorisation d'accès aux informations secrètes)
- La signature du code doit correspondre à **PartitionID**
- La signature du code doit correspondre à celle d'une **app trusted** (ou être membre du bon KeychainAccessGroup)
- Si **toutes les applications sont trusted** :
- Il faut les **autorisations** appropriées
- La signature du code doit correspondre à **PartitionID**
- S'il n'y a pas de **PartitionID**, cette condition n'est pas nécessaire

> [!CAUTION]
> Par conséquent, si **1 application** est listée, vous devez **injecter du code dans cette application**.
>
> Si **apple** est indiqué dans le **partitionID**, vous pouvez y accéder avec **`osascript`**. Cela s'applique donc à tout ce qui truste toutes les applications avec apple dans le partitionID. **`Python`** peut également être utilisé à cette fin.

### Deux attributs supplémentaires

- **Invisible** : Il s'agit d'un flag booléen permettant de **masquer** l'entrée dans l'app Keychain de l'**UI**<sup>[1]</sup>
- **General** : Sert à stocker des **métadonnées** (elles ne sont donc **PAS CHIFFRÉES**)<sup>[1]</sup>
- Microsoft stockait en clair tous les refresh tokens permettant d'accéder à des endpoints sensibles.<sup>[1]</sup>

## References

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
