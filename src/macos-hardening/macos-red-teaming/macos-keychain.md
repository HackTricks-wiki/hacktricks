# Trousseau macOS

{{#include ../../banners/hacktricks-training.md}}

## Principaux trousseaux

- Le **trousseau utilisateur** (`~/Library/Keychains/login.keychain-db`), utilisé pour stocker les **identifiants propres à l’utilisateur**, comme les mots de passe des applications, les mots de passe Internet, les certificats générés par l’utilisateur, les mots de passe réseau et les clés publiques/privées générées par l’utilisateur.
- Le **trousseau système** (`/Library/Keychains/System.keychain`), qui stocke les **identifiants à l’échelle du système**, comme les mots de passe WiFi, les certificats racine du système, les clés privées du système et les mots de passe des applications système.<sup>[[1]](#references)</sup>
  - Il est possible de trouver d’autres composants, comme des certificats, dans `/System/Library/Keychains/*`
- Dans **iOS**, il n’existe qu’un seul **trousseau**, situé dans `/private/var/Keychains/`. Ce dossier contient également les bases de données de `TrustStore`, des autorités de certification (`caissuercache`) et des entrées OSCP (`ocspache`).
  - Dans le trousseau, les apps sont limitées à leur espace privé en fonction de leur identifiant d’application.

### Accès au trousseau de mots de passe

Ces fichiers, bien qu’ils ne bénéficient d’aucune protection intrinsèque et puissent être **téléchargés**, sont chiffrés et nécessitent le **mot de passe de l’utilisateur en clair pour être déchiffrés**. Un outil comme [**Chainbreaker**](https://github.com/n0fate/chainbreaker) peut être utilisé pour le déchiffrement.<sup>[[1]](#references)</sup>

## Protections des entrées du trousseau

### ACL

Chaque entrée du trousseau est régie par des **listes de contrôle d’accès (ACL)** qui déterminent qui peut effectuer diverses actions sur l’entrée, notamment :<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`** : permet à son détenteur d’obtenir le secret en clair.
- **`kSecACLAuthorizationExportWrapped`** : permet à son détenteur d’obtenir le secret en clair, chiffré avec un autre mot de passe fourni.
- **`kSecACLAuthorizationAny`** : permet à son détenteur d’effectuer n’importe quelle action.

Les ACL sont également accompagnées d’une **liste d’applications approuvées** pouvant effectuer ces actions sans demander de confirmation. Cette liste peut être :<sup>[[1]](#references)</sup>

- **N`il`** (aucune autorisation requise, **tout le monde est approuvé**)
- Une liste **vide** (**personne** n’est approuvé)
- Une **liste** d’**applications** spécifiques.

L’entrée peut également contenir la clé **`kSecACLAuthorizationPartitionID`,** utilisée pour identifier le **teamid, apple,** et le **cdhash.**<sup>[[1]](#references)[[2]](#references)</sup>

- Si le **teamid** est spécifié, l’application doit avoir le **même teamid** pour **accéder à la valeur** de l’entrée **sans** **demande de confirmation**.
- Si **apple** est spécifié, l’app doit être **signée** par **Apple**.
- Si le **cdhash** est indiqué, l’**app** doit avoir le **cdhash** correspondant.

### Création d’une entrée du trousseau

Lorsqu’une **nouvelle** **entrée** est créée avec **`Keychain Access.app`**, les règles suivantes s’appliquent :<sup>[[1]](#references)</sup>

- Toutes les apps peuvent chiffrer.
- **Aucune app** ne peut exporter/déchiffrer (sans demander confirmation à l’utilisateur).
- Toutes les apps peuvent consulter le contrôle d’intégrité.
- Aucune app ne peut modifier les ACL.
- Le **partitionID** est défini sur **`apple`**.

Lorsqu’une **application crée une entrée dans le trousseau**, les règles sont légèrement différentes :<sup>[[1]](#references)</sup>

- Toutes les apps peuvent chiffrer.
- Seule l’**application créatrice** (ou toute autre app explicitement ajoutée) peut exporter/déchiffrer (sans demander confirmation à l’utilisateur).
- Toutes les apps peuvent consulter le contrôle d’intégrité.
- Aucune app ne peut modifier les ACL.
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` définit la liste de partitions de l’élément, tandis que `-k` fournit le mot de passe actuel du Keychain requis pour effectuer cette modification ; l’option qui accepte le mot de passe est obsolète.<sup>[[4]](#references)</sup> Une mise à jour réussie ne prouve pas qu’une lecture ultérieure se fera sans invite : un prototype observé, bien que désactivé, déclenchait toujours une invite de confirmation lorsqu’il interrogeait l’élément via `Security.framework`. Un ID de partition correspondant ne constitue qu’un élément des vérifications ACL et des applications de confiance décrites ci-dessus ; vérifiez donc le chemin de lecture réel.<sup>[[3]](#references)</sup>

### API

> [!TIP]
> **L’énumération et l’extraction des secrets du Keychain** qui **ne génèrent pas d’invite** peuvent être réalisées avec l’outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> D’autres points de terminaison d’API sont disponibles dans le code source [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Listez et obtenez des **informations** sur chaque entrée du Keychain avec le **Security Framework**, ou consultez également l’outil CLI open source d’Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Exemples d’API :<sup>[[1]](#references)</sup>

- L’API **`SecItemCopyMatching`** fournit des informations sur chaque entrée et permet de définir certains attributs lors de son utilisation :
  - **`kSecReturnData`** : si la valeur est true, l’API tente de déchiffrer les données (définissez-la sur false pour éviter d’éventuelles fenêtres contextuelles)
  - **`kSecReturnRef`** : obtient également une référence à l’élément du Keychain (définissez-la sur true si vous découvrez par la suite que vous pouvez le déchiffrer sans fenêtre contextuelle)
  - **`kSecReturnAttributes`** : obtient les métadonnées des entrées
  - **`kSecMatchLimit`** : nombre de résultats à renvoyer
  - **`kSecClass`** : type d’entrée du Keychain

Obtenez les **ACL** de chaque entrée :<sup>[[1]](#references)</sup>

- L’API **`SecAccessCopyACLList`** permet d’obtenir l’**ACL de l’élément du Keychain**. Elle renvoie une liste d’ACL (telles que `kSecACLAuthorizationExportClear` et les autres mentionnées précédemment), où chaque entrée comporte :<sup>[[1]](#references)[[2]](#references)</sup>
  - Une description
  - Une **liste d’applications de confiance**, qui peut contenir :
    - Une application : /Applications/Slack.app
    - Un binaire : /usr/libexec/airportd
    - Un groupe : group://AirPort

Exportez les données :<sup>[[1]](#references)</sup>

- L’API **`SecKeychainItemCopyContent`** récupère le texte en clair
- L’API **`SecItemExport`** exporte les clés et les certificats, mais il peut être nécessaire de définir des mots de passe pour exporter le contenu chiffré

Voici les **conditions** pour pouvoir **exporter un secret sans invite** :<sup>[[1]](#references)</sup>

- Si **au moins une application de confiance** est répertoriée :
  - Vous devez disposer des **autorisations** appropriées (**`Nil`**, ou faire **partie** de la liste des applications autorisées pour accéder aux informations secrètes)
  - La signature du code doit correspondre au **PartitionID**
  - La signature du code doit correspondre à celle d’une **application de confiance** (ou vous devez être membre du bon KeychainAccessGroup)
- Si **toutes les applications sont de confiance** :
  - Vous devez disposer des **autorisations** appropriées
  - La signature du code doit correspondre au **PartitionID**
    - En l’absence de **PartitionID**, cette condition n’est pas requise

> [!CAUTION]
> Par conséquent, si **une application est répertoriée**, vous devez **injecter du code dans cette application**.
>
> Si **apple** figure dans le **partitionID**, vous pouvez y accéder avec **`osascript`** : cela fonctionne donc pour tout élément qui fait confiance à toutes les applications et dont le partitionID contient apple. **`Python`** peut également être utilisé.

### Deux attributs supplémentaires

- **Invisible** : indicateur booléen qui **masque** l’entrée dans l’application Keychain de l’**interface utilisateur**<sup>[[1]](#references)</sup>
- **General** : permet de stocker des **métadonnées** (elles ne sont donc PAS CHIFFRÉES)<sup>[[1]](#references)</sup>
  - Microsoft stockait en texte brut tous les jetons d’actualisation permettant d’accéder à un point de terminaison sensible.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [#OBTS v5.0 : « Crocheter le Keychain de macOS » - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Documentation développeur Apple — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Une nouvelle version du stealer MacSync pour macOS cible les passionnés de crypto et les développeurs](https://securelist.com/macsync-new-version/121383/)
- [4] [Miroir de la page de manuel Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
