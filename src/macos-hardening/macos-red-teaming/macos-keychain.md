# Trousseau macOS

{{#include ../../banners/hacktricks-training.md}}

## Trousseaux principaux

- Le **trousseau utilisateur** (`~/Library/Keychains/login.keychain-db`), qui sert à stocker des **identifiants propres à l’utilisateur**, tels que les mots de passe des applications, les mots de passe Internet, les certificats générés par l’utilisateur, les mots de passe réseau et les clés publiques/privées générées par l’utilisateur.
- Le **trousseau système** (`/Library/Keychains/System.keychain`), qui stocke des **identifiants à l’échelle du système**, tels que les mots de passe Wi-Fi, les certificats racines du système, les clés privées du système et les mots de passe des applications système.<sup>[[1]](#references)</sup>
  - On peut trouver d’autres éléments, tels que des certificats, dans `/System/Library/Keychains/*`
- Le **trousseau de protection des données** propre à chaque utilisateur apparaît sous la forme **Local Items** ou **iCloud** dans Trousseaux d’accès. Il est distinct de `login.keychain-db` et comprend des éléments uniquement locaux ainsi que des éléments synchronisables ; `security` est principalement un outil pour les trousseaux basés sur des fichiers. Ainsi, un résultat succinct de `dump-keychain` ne permet pas d’exclure la présence d’identifiants ici.<sup>[[5]](#references)</sup>
- Dans **iOS**, il n’existe qu’un seul **trousseau**, situé dans `/private/var/Keychains/`. Ce dossier contient également des bases de données pour le `TrustStore`, les autorités de certification (`caissuercache`) et les entrées OSCP (`ocspache`).
  - Dans le trousseau, les applications sont limitées à leur zone privée en fonction de leur identifiant d’application.

### Accès au trousseau par mot de passe

Un trousseau **basé sur un fichier** copié n’est pas en texte brut. Le déchiffrement hors ligne de ses éléments protégés nécessite le mot de passe du trousseau ou un matériel de clé équivalent ; [**Chainbreaker**](https://github.com/n0fate/chainbreaker) cible ce format.<sup>[[1]](#references)</sup> Cela diffère d’une lecture en direct dans une session utilisateur déverrouillée, où les contrôles d’accès aux éléments peuvent autoriser la lecture ou déclencher une invite sans qu’il soit nécessaire de saisir à nouveau le mot de passe de connexion. Le trousseau de protection des données utilise un modèle différent de protection et de groupes d’accès.<sup>[[5]](#references)</sup>

## Protections des entrées du trousseau

### ACL des trousseaux basés sur des fichiers

Les règles `SecAccess` ACL et de liste de partitions ci-dessous décrivent les trousseaux **basés sur des fichiers**. Les éléments du trousseau de protection des données utilisent plutôt des groupes d’accès liés à la signature du code et des conditions `SecAccessControl` facultatives ; ne déduisez pas leur accessibilité à partir d’un vidage ACL d’un trousseau basé sur un fichier.<sup>[[5]](#references)</sup>

Chaque entrée d’un trousseau basé sur un fichier est régie par des **listes de contrôle d’accès (ACL)** qui définissent qui peut effectuer différentes actions sur l’entrée, notamment :<sup>[[1]](#references)[[2]](#references)</sup>

- **`kSecACLAuthorizationExportClear`** : autorise le détenteur à obtenir le secret en texte clair.
- **`kSecACLAuthorizationExportWrapped`** : autorise le détenteur à obtenir le secret en texte clair, chiffré avec un autre mot de passe fourni.
- **`kSecACLAuthorizationAny`** : autorise le détenteur à effectuer n’importe quelle action.

Les ACL sont également accompagnées d’une **liste d’applications approuvées** pouvant effectuer ces actions sans afficher d’invite. Cette liste peut être :<sup>[[1]](#references)</sup>

- **N`il`** (aucune autorisation requise, **tout le monde est approuvé**)
- Une liste **vide** (**personne** n’est approuvé)
- Une **liste** d’**applications** précises.

L’entrée peut également contenir la clé **`kSecACLAuthorizationPartitionID`**, utilisée pour identifier le **teamid, apple** et **cdhash**.<sup>[[1]](#references)[[2]](#references)</sup>

- Si le **teamid** est spécifié, l’application doit avoir le **même teamid** pour **accéder à la valeur** de l’entrée **sans** afficher d’**invite**.
- Si **apple** est spécifié, l’application doit être **signée** par **Apple**.
- Si **cdhash** est indiqué, l’**application** doit avoir le `cdhash` spécifié.

### Création d’une entrée dans un trousseau basé sur un fichier

Lorsqu’une **nouvelle** **entrée** est créée à l’aide de **`Keychain Access.app`**, les règles suivantes s’appliquent :<sup>[[1]](#references)</sup>

- Toutes les applications peuvent chiffrer.
- **Aucune application** ne peut exporter/déchiffrer sans afficher d’invite à l’utilisateur.
- Toutes les applications peuvent consulter la vérification d’intégrité.
- Aucune application ne peut modifier les ACL.
- Le **partitionID** est défini sur **`apple`**.

Lorsqu’une **application crée une entrée dans le trousseau**, les règles sont légèrement différentes :<sup>[[1]](#references)</sup>

- Toutes les applications peuvent chiffrer.
- Seule l’**application créatrice** (ou toute autre application explicitement ajoutée) peut exporter/déchiffrer sans afficher d’invite à l’utilisateur.
- Toutes les applications peuvent consulter la vérification d’intégrité.
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

# Change the specified entry's PartitionID value
security set-generic-password-partition-list \
  -s "test service" -a "test account" \
  -S 'apple-tool:,apple:,teamid:TEAMID' \
  -k 'KEYCHAIN_PASSWORD' ~/Library/Keychains/login.keychain-db

# Dump specifically the user keychain
security dump-keychain ~/Library/Keychains/login.keychain-db
```

`-S` définit la liste de partitions de l’élément, tandis que `-k` fournit le mot de passe actuel du trousseau requis pour effectuer cette modification ; l’option qui prend le mot de passe est obsolète.<sup>[[4]](#references)</sup> Une mise à jour réussie ne garantit pas qu’une lecture ultérieure se fera sans invite : un prototype désactivé observé a tout de même déclenché une invite de confirmation lorsqu’il a interrogé l’élément via `Security.framework`. Un ID de partition correspondant ne constitue qu’une partie des vérifications ACL et des applications approuvées décrites ci-dessus ; vérifiez donc le chemin de lecture réel.<sup>[[3]](#references)</sup>

### API

> [!TIP]
> **L’énumération et le dump des secrets du trousseau** qui **ne génèrent pas d’invite** peuvent être effectués avec l’outil [**LockSmith**](https://github.com/its-a-feature/LockSmith)
>
> D’autres points de terminaison d’API se trouvent dans le code source [**SecKeyChain.h**](https://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55017/lib/SecKeychain.h.auto.html).

Répertoriez et obtenez des **informations** sur chaque entrée du trousseau à l’aide du **Security Framework**, ou consultez l’outil CLI open source d’Apple [**security**](https://opensource.apple.com/source/Security/Security-59306.61.1/SecurityTool/macOS/security.c.auto.html)**.** Voici quelques exemples d’API :<sup>[[1]](#references)</sup>

- L’API **`SecItemCopyMatching`** fournit des informations sur chaque entrée et permet de définir certains attributs :
  - **`kSecReturnData`** : si la valeur est vraie, l’API tentera de déchiffrer les données (définissez-la sur false pour éviter les éventuelles fenêtres contextuelles)
  - **`kSecReturnRef`** : obtient une référence d’objet pour une clé, un certificat ou une identité ; les éléments de mot de passe n’ont pas cette représentation d’objet. Utilisez `kSecReturnPersistentRef` pour identifier un mot de passe lors d’une requête ciblée ultérieure.<sup>[[6]](#references)</sup>
  - **`kSecReturnAttributes`** : obtient les métadonnées des entrées
  - **`kSecMatchLimit`** : nombre de résultats à renvoyer
  - **`kSecClass`** : type d’entrée du trousseau

Obtenez les **ACL** de chaque entrée :<sup>[[1]](#references)</sup>

- L’API **`SecAccessCopyACLList`** permet d’obtenir l’**ACL de l’élément du trousseau**. Elle renvoie une liste d’ACL (telles que `kSecACLAuthorizationExportClear` et les autres mentionnées précédemment), où chaque entrée comporte :<sup>[[1]](#references)[[2]](#references)</sup>
  - Une description
  - Une **liste d’applications approuvées**. Il peut s’agir de :
    - Une application : /Applications/Slack.app
    - Un binaire : /usr/libexec/airportd
    - Un groupe : group://AirPort

Exportez les données :<sup>[[1]](#references)</sup>

- L’API **`SecKeychainItemCopyContent`** récupère le texte en clair
- L’API **`SecItemExport`** exporte les clés et les certificats, mais il peut être nécessaire de définir des mots de passe pour exporter le contenu chiffré

Voici les **conditions** permettant d’**exporter un secret sans invite** :<sup>[[1]](#references)</sup>

- Si **au moins une application approuvée** est répertoriée :
  - Vous devez disposer des **autorisations** appropriées (**`Nil`**, ou faire **partie** de la liste d’applications autorisées dans l’autorisation d’accès aux informations secrètes)
  - La signature du code doit correspondre au **PartitionID**
  - La signature du code doit correspondre à celle d’une **application approuvée** (ou vous devez appartenir au bon KeychainAccessGroup)
- Si **toutes les applications sont approuvées** :
  - Vous devez disposer des **autorisations** appropriées
  - La signature du code doit correspondre au **PartitionID**
    - S’il n’y a **pas de PartitionID**, cette condition n’est pas nécessaire

> [!CAUTION]
> Par conséquent, si **une application est répertoriée**, vous devez **injecter du code dans cette application**.
>
> Si **apple** est indiqué dans le **partitionID**, vous pouvez y accéder avec **`osascript`** ; cela concerne donc tout élément qui fait confiance à toutes les applications et dont le partitionID contient apple. Vous pouvez également utiliser **`Python`**.

### Deux attributs supplémentaires

- **Invisible** : indicateur booléen permettant de **masquer** l’entrée dans l’application Keychain de l’**interface utilisateur**<sup>[[1]](#references)</sup>
- **General** : sert à stocker des **métadonnées** (elles ne sont donc PAS CHIFFRÉES)<sup>[[1]](#references)</sup>
  - Microsoft stockait en texte brut tous les jetons d’actualisation permettant d’accéder à un point de terminaison sensible.<sup>[[1]](#references)</sup>

### Trousseau de protection des données : énumérer, puis interroger un élément

Exécutez `SecItemCopyMatching` depuis une **application signée dans le contexte de session de connexion de l’utilisateur cible**, avec `kSecUseDataProtectionKeychain: true` ; ne supposez pas que `security dump-keychain` ou qu’une requête SecItem par défaut a recherché dans ce trousseau. L’appelant ne voit que les groupes d’accès auxquels il est autorisé.<sup>[[5]](#references)</sup>

Si le code de test s’exécute dans un autre processus, son accès au trousseau de protection des données dépend des droits de cet exécutable hôte. Inspectez les droits réellement signés avec `codesign -d --entitlements - /path/to/Target.app` et consultez [les droits de signature de code macOS](../macos-security-and-privilege-escalation/macos-security-protections/macos-dangerous-entitlements.md) pour les vérifications associées.<sup>[[7]](#references)</sup>

Commencez par demander **uniquement les attributs** pour une classe d’élément. `kSecAttrSynchronizableAny` inclut les correspondances locales et celles synchronisées avec iCloud ; si vous omettez cet attribut, les éléments synchronisables sont exclus.<sup>[[8]](#references)</sup> `kSecUseAuthenticationUISkip` évite l’affichage de l’interface d’authentification pendant une énumération générale, au prix de l’exclusion des éléments protégés correspondants.<sup>[[9]](#references)</sup> Répétez l’opération avec `kSecClassInternetPassword` si nécessaire.

```swift
import Security
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip
]
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)
print(status)
if status == errSecSuccess, let items = result as? [[String: Any]] {
    for item in items { print(item) }
}
```

Pour une lecture autorisée d’un secret, créez une **nouvelle** requête ciblée sur l’élément sélectionné (par exemple, la classe, le service et le compte), définissez `kSecReturnData: true` et `kSecMatchLimit: kSecMatchLimitOne`, et attendez-vous à une authentification propre à l’élément ou à une erreur. Ne combinez **pas** `kSecReturnData` avec `kSecMatchLimitAll` pour les éléments de type mot de passe.<sup>[[10]](#references)</sup> Un résultat `errSecItemNotFound` peut également indiquer un mauvais trousseau, un filtre de synchronisation incorrect ou l’absence de l’autorisation d’access-group, plutôt que l’absence d’un identifiant.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>



## References

- [1] [#OBTS v5.0 : « Crocheter le trousseau macOS » - Cody Thomas](https://www.youtube.com/watch?v=jKE1ZW33JpY)
- [2] [Apple Developer — kSecACLAuthorizationExportClear](https://developer.apple.com/documentation/security/ksecaclauthorizationexportclear)
- [3] [Kaspersky Securelist - Une nouvelle version du voleur macOS MacSync cible les passionnés de cryptomonnaies et les développeurs](https://securelist.com/macsync-new-version/121383/)
- [4] [Miroir de la page de manuel Apple security(1)](https://keith.github.io/xcode-man-pages/security.1.html)
- [5] [Apple TN3137 — À propos des API et des implémentations du trousseau sur Mac](https://developer.apple.com/documentation/Technotes/tn3137-on-mac-keychains)
- [6] [Apple Developer Forums — SecItem : principes fondamentaux](https://developer.apple.com/forums/thread/724023)
- [7] [Apple Developer Forums — SecItem : pièges et bonnes pratiques](https://developer.apple.com/forums/thread/724013)
- [8] [Apple Developer — kSecAttrSynchronizable](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
- [9] [Apple Developer — Accéder aux éléments du trousseau avec Face ID ou Touch ID](https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id)
- [10] [Apple Developer — SecItemCopyMatching](https://developer.apple.com/documentation/security/secitemcopymatching%28_%3A_%3A%29)
{{#include ../../banners/hacktricks-training.md}}
