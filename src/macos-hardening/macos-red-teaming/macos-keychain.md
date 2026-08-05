# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Principaux Keychains

- Le **User Keychain** (`~/Library/Keychains/login.keychain-db`), utilisé pour stocker les **identifiants propres à l'utilisateur**, comme les mots de passe d'applications, les mots de passe Internet, les certificats générés par l'utilisateur, les mots de passe réseau et les clés publiques/privées générées par l'utilisateur.
- Le **System Keychain** (`/Library/Keychains/System.keychain`), qui stocke les **identifiants à l'échelle du système**, tels que les mots de passe WiFi, les certificats racine du système, les clés privées du système et les mots de passe des applications système.<sup>[[1]](#references)</sup>
- Il est possible de trouver d'autres composants, comme des certificats, dans `/System/Library/Keychains/*`
- Dans **iOS**, il n'existe qu'un seul **Keychain**, situé dans `/private/var/Keychains/`. Ce dossier contient également les bases de données du `TrustStore`, des autorités de certification (`caissuercache`) et des entrées OSCP (`ocspache`).
- Les applications sont limitées, dans le keychain, à leur zone privée en fonction de leur identifiant d'application.

### Accès au mot de passe du Keychain

Ces fichiers, bien qu'ils ne disposent d'aucune protection inhérente et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe en clair de l'utilisateur pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour le déchiffrement.<sup>[[1]](#references)</sup>

## Protections des entrées du Keychain

### ACLs

Chaque entrée du keychain est régie par des **listes de contrôle d'accès (ACLs)** qui déterminent qui peut effectuer différentes actions sur l'entrée du keychain, notamment :<sup>[[1]](#references)</sup>

- **ACLAuhtorizationExportClear** : permet au détenteur d'obtenir le secret en clair.
- **ACLAuhtorizationExportWrapped** : permet au détenteur d'obtenir le secret en clair, chiffré avec un autre mot de passe fourni.
- **ACLAuhtorizationAny** : permet au détenteur d'effectuer n'importe quelle action.

Les ACLs sont également accompagnées d'une **liste d'applications approuvées** pouvant effectuer ces actions sans demander de confirmation. Cette liste peut être :<sup>[[1]](#references)</sup>

- **N`il`** (aucune autorisation requise, **tout le monde est approuvé**)
- Une liste **vide** (**personne** n'est approuvé)
- Une **liste** d'**applications** spécifiques.

L'entrée peut également contenir la clé **`ACLAuthorizationPartitionID`,** utilisée pour identifier le **teamid, apple** et le **cdhash**.<sup>[[1]](#references)</sup>

- Si le **teamid** est spécifié, pour **accéder à la valeur de l'entrée** **sans** **demande de confirmation**, l'application utilisée doit avoir le **même teamid**.
- Si **apple** est spécifié, l'application doit être **signée** par **Apple**.
- Si le **cdhash** est indiqué, l'**application** doit avoir le **cdhash** spécifique.

### Création d'une entrée de Keychain

Lorsqu'une **nouvelle** **entrée** est créée avec **`Keychain Access.app`**, les règles suivantes s'appliquent :<sup>[[1]](#references)</sup>

- Toutes les applications peuvent chiffrer.
- **Aucune application** ne peut exporter/déchiffrer (sans demander confirmation à l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut modifier les ACLs.
- Le **partitionID** est défini sur **`apple`**.

Lorsqu'une **application crée une entrée dans le keychain**, les règles sont légèrement différentes :<sup>[[1]](#references)</sup>

- Toutes les applications peuvent chiffrer.
- Seule **l'application créatrice** (ou toute autre application explicitement ajoutée) peut exporter/déchiffrer (sans demander confirmation à l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut modifier les ACLs.
- Le **partitionID** est défini sur **`teamid:[teamID here]`**.

## Accès au Keychain

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
> L’**énumération et le dumping des secrets du keychain** qui **ne généreront pas de prompt** peuvent être effectués avec l’outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> D’autres API endpoints sont disponibles dans le code source de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Lister et obtenir des **infos** sur chaque entrée du keychain à l’aide du **Security Framework**, ou consulter également l’outil cli open source d’Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Quelques exemples d’API :<sup>[[1]](#references)</sup>

- L’API **`SecItemCopyMatching`** fournit des infos sur chaque entrée et certains attributs peuvent être définis lors de son utilisation :
- **`kSecReturnData`** : Si true, l’API tentera de déchiffrer les données (définir sur false pour éviter les pop-ups potentiels)
- **`kSecReturnRef`** : Obtenir également une référence vers l’élément du keychain (définir sur true si vous constatez plus tard que vous pouvez déchiffrer sans pop-up)
- **`kSecReturnAttributes`** : Obtenir les métadonnées des entrées
- **`kSecMatchLimit`** : Nombre de résultats à retourner
- **`kSecClass`** : Type d’entrée du keychain

Obtenir les **ACLs** de chaque entrée :<sup>[[1]](#references)</sup>

- Avec l’API **`SecAccessCopyACLList`**, vous pouvez obtenir l’**ACL de l’élément du keychain**. Elle renverra une liste d’ACLs (comme `ACLAuhtorizationExportClear` et les autres mentionnées précédemment), chaque liste contenant :
- Description
- **Trusted Application List**. Cela peut être :
- Une app : /Applications/Slack.app
- Un binaire : /usr/libexec/airportd
- Un groupe : group://AirPort

Exporter les données :<sup>[[1]](#references)</sup>

- L’API **`SecKeychainItemCopyContent`** obtient le texte en clair
- L’API **`SecItemExport`** exporte les clés et les certificats, mais il peut être nécessaire de définir des mots de passe pour exporter le contenu chiffré

Voici les **conditions** nécessaires pour pouvoir **exporter un secret sans prompt** :<sup>[[1]](#references)</sup>

- Si **1+ app trusted** est listée :
- Nécessite les **authorizations** appropriées (**`Nil`**, ou faire **partie** de la liste autorisée des apps dans l’authorization permettant d’accéder aux infos du secret)
- La signature du code doit correspondre au **PartitionID**
- La signature du code doit correspondre à celle d’une **app trusted** (ou être membre du bon KeychainAccessGroup)
- Si **toutes les applications sont trusted** :
- Nécessite les **authorizations** appropriées
- La signature du code doit correspondre au **PartitionID**
- En l’absence de **PartitionID**, ce n’est pas nécessaire

> [!CAUTION]
> Par conséquent, si **1 application est listée**, vous devez **injecter du code dans cette application**.
>
> Si **apple** est indiqué dans le **partitionID**, vous pouvez y accéder avec **`osascript`**. Cela s’applique donc à tout ce qui truste toutes les applications avec apple dans le partitionID. **`Python`** peut également être utilisé à cette fin.

### Deux attributs supplémentaires

- **Invisible** : C’est un flag booléen permettant de **masquer** l’entrée dans l’application **UI** Keychain<sup>[[1]](#references)</sup>
- **General** : Sert à stocker des **métadonnées** (elles ne sont donc PAS CHIFFRÉES)<sup>[[1]](#references)</sup>
- Microsoft stockait en texte brut tous les refresh tokens permettant d’accéder à des endpoint sensibles.<sup>[[1]](#references)</sup>

## Références

- [1] [#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
