# macOS Keychain

{{#include ../../banners/hacktricks-training.md}}

## Main Keychains

- Le **User Keychain** (`~/Library/Keychains/login.keychain-db`), qui est utilisé pour stocker des **identifiants spécifiques à l'utilisateur** comme des mots de passe d'application, des mots de passe internet, des certificats générés par l'utilisateur, des mots de passe réseau et des clés publiques/privées générées par l'utilisateur.
- Le **System Keychain** (`/Library/Keychains/System.keychain`), qui stocke des **identifiants à l'échelle du système** tels que des mots de passe WiFi, des certificats racine du système, des clés privées du système et des mots de passe d'application du système.
- Il est possible de trouver d'autres composants comme des certificats dans `/System/Library/Keychains/*`
- Dans **iOS**, il n'y a qu'un seul **Keychain** situé dans `/private/var/Keychains/`. Ce dossier contient également des bases de données pour le `TrustStore`, les autorités de certification (`caissuercache`) et les entrées OSCP (`ocspache`).
- Les applications seront restreintes dans le keychain uniquement à leur zone privée en fonction de leur identifiant d'application.

### Password Keychain Access

Ces fichiers, bien qu'ils n'aient pas de protection inhérente et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe en clair de l'utilisateur pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) pourrait être utilisé pour le déchiffrement.

## Keychain Entries Protections

### ACLs

Chaque entrée dans le keychain est régie par des **Access Control Lists (ACLs)** qui dictent qui peut effectuer diverses actions sur l'entrée du keychain, y compris :

- **ACLAuhtorizationExportClear** : Permet au titulaire d'obtenir le texte clair du secret.
- **ACLAuhtorizationExportWrapped** : Permet au titulaire d'obtenir le texte clair chiffré avec un autre mot de passe fourni.
- **ACLAuhtorizationAny** : Permet au titulaire d'effectuer n'importe quelle action.

Les ACLs sont également accompagnées d'une **liste d'applications de confiance** qui peuvent effectuer ces actions sans demande. Cela pourrait être :

- **N`il`** (aucune autorisation requise, **tout le monde est de confiance**)
- Une **liste vide** (**personne** n'est de confiance)
- **Liste** d'**applications** spécifiques.

De plus, l'entrée peut contenir la clé **`ACLAuthorizationPartitionID`,** qui est utilisée pour identifier le **teamid, apple,** et **cdhash.**

- Si le **teamid** est spécifié, alors pour **accéder à la valeur de l'entrée** **sans** **demande**, l'application utilisée doit avoir le **même teamid**.
- Si le **apple** est spécifié, alors l'application doit être **signée** par **Apple**.
- Si le **cdhash** est indiqué, alors l'**app** doit avoir le **cdhash** spécifique.

### Creating a Keychain Entry

Lorsque une **nouvelle** **entrée** est créée en utilisant **`Keychain Access.app`**, les règles suivantes s'appliquent :

- Toutes les applications peuvent chiffrer.
- **Aucune application** ne peut exporter/déchiffrer (sans demander à l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut changer les ACLs.
- Le **partitionID** est défini sur **`apple`**.

Lorsque une **application crée une entrée dans le keychain**, les règles sont légèrement différentes :

- Toutes les applications peuvent chiffrer.
- Seule l'**application créatrice** (ou toute autre application explicitement ajoutée) peut exporter/déchiffrer (sans demander à l'utilisateur).
- Toutes les applications peuvent voir le contrôle d'intégrité.
- Aucune application ne peut changer les ACLs.
- Le **partitionID** est défini sur **`teamid:[teamID ici]`**.

## Accessing the Keychain

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
> L'**énumération et l'extraction** de secrets du **trousseau** qui **ne générera pas d'invite** peuvent être effectuées avec l'outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> D'autres points de terminaison API peuvent être trouvés dans le code source de [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Listez et obtenez des **informations** sur chaque entrée du trousseau en utilisant le **Security Framework** ou vous pouvez également vérifier l'outil cli open source d'Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Quelques exemples d'API :

- L'API **`SecItemCopyMatching`** fournit des informations sur chaque entrée et il y a certains attributs que vous pouvez définir lors de son utilisation :
- **`kSecReturnData`** : Si vrai, il essaiera de déchiffrer les données (définir sur faux pour éviter les pop-ups potentiels)
- **`kSecReturnRef`** : Obtenez également une référence à l'élément du trousseau (définir sur vrai au cas où vous verriez plus tard que vous pouvez déchiffrer sans pop-up)
- **`kSecReturnAttributes`** : Obtenez des métadonnées sur les entrées
- **`kSecMatchLimit`** : Combien de résultats retourner
- **`kSecClass`** : Quel type d'entrée de trousseau

Obtenez les **ACL** de chaque entrée :

- Avec l'API **`SecAccessCopyACLList`**, vous pouvez obtenir l'**ACL pour l'élément du trousseau**, et cela renverra une liste d'ACL (comme `ACLAuhtorizationExportClear` et les autres mentionnés précédemment) où chaque liste a :
- Description
- **Liste des applications de confiance**. Cela pourrait être :
- Une application : /Applications/Slack.app
- Un binaire : /usr/libexec/airportd
- Un groupe : group://AirPort

Exportez les données :

- L'API **`SecKeychainItemCopyContent`** obtient le texte en clair
- L'API **`SecItemExport`** exporte les clés et certificats mais peut nécessiter de définir des mots de passe pour exporter le contenu chiffré

Et voici les **exigences** pour pouvoir **exporter un secret sans invite** :

- Si **1+ applications de confiance** listées :
- Besoin des **autorisations** appropriées (**`Nil`**, ou faire **partie** de la liste autorisée d'applications dans l'autorisation d'accès aux informations secrètes)
- Besoin que la signature de code corresponde au **PartitionID**
- Besoin que la signature de code corresponde à celle d'une **application de confiance** (ou faire partie du bon KeychainAccessGroup)
- Si **toutes les applications sont de confiance** :
- Besoin des **autorisations** appropriées
- Besoin que la signature de code corresponde au **PartitionID**
- Si **pas de PartitionID**, alors cela n'est pas nécessaire

> [!CAUTION]
> Par conséquent, s'il y a **1 application listée**, vous devez **injecter du code dans cette application**.
>
> Si **apple** est indiqué dans le **partitionID**, vous pourriez y accéder avec **`osascript`** donc tout ce qui fait confiance à toutes les applications avec apple dans le partitionID. **`Python`** pourrait également être utilisé pour cela.

### Deux attributs supplémentaires

- **Invisible** : C'est un indicateur booléen pour **cacher** l'entrée de l'application **UI** du trousseau
- **General** : C'est pour stocker des **métadonnées** (donc ce n'est PAS CHIFFRÉ)
- Microsoft stockait en texte clair tous les jetons de rafraîchissement pour accéder à des points de terminaison sensibles.

## References

- [**#OBTS v5.0: "Lock Picking the macOS Keychain" - Cody Thomas**](https://www.youtube.com/watch?v=jKE1ZW33JpY)

{{#include ../../banners/hacktricks-training.md}}
