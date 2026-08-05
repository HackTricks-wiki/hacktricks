# Base de données des autorisations macOS & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Base de données des autorisations**

La base de données située dans `/var/db/auth.db` est utilisée pour stocker les permissions permettant d'effectuer des opérations sensibles. Ces opérations sont entièrement exécutées dans **l'espace utilisateur** et sont généralement utilisées par les services **XPC**, qui doivent vérifier **si le client appelant est autorisé** à effectuer une action donnée en consultant cette base de données.

Initialement, cette base de données est créée à partir du contenu de `/System/Library/Security/authorization.plist`. Ensuite, certains services peuvent ajouter ou modifier cette base de données afin d'y ajouter d'autres permissions.

Les règles sont stockées dans la table `rules` de la base de données et contiennent les colonnes suivantes :

- **id** : Identifiant unique pour chaque règle, incrémenté automatiquement et servant de clé primaire.
- **name** : Nom unique de la règle, utilisé pour l'identifier et la référencer au sein du système d'autorisation.
- **type** : Indique le type de la règle, limité aux valeurs 1 ou 2 afin de définir sa logique d'autorisation.
- **class** : Classe spécifique dans laquelle la règle est catégorisée, et qui doit être un entier positif.
- "allow" pour allow, "deny" pour deny, "user" si la propriété group indique un groupe dont l'appartenance permet l'accès, "rule" indique dans un tableau une règle à satisfaire, "evaluate-mechanisms" suivi d'un tableau `mechanisms` contenant soit des builtins, soit le nom d'un bundle situé dans `/System/Library/CoreServices/SecurityAgentPlugins/` ou `/Library/Security//SecurityAgentPlugins`
- **group** : Indique le groupe d'utilisateurs associé à la règle pour l'autorisation basée sur les groupes.
- **kofn** : Représente le paramètre « k-sur-n », déterminant combien de sous-règles doivent être satisfaites sur un nombre total donné.
- **timeout** : Définit la durée, en secondes, avant l'expiration de l'autorisation accordée par la règle.
- **flags** : Contient différents flags qui modifient le comportement et les caractéristiques de la règle.
- **tries** : Limite le nombre de tentatives d'autorisation permises afin de renforcer la sécurité.
- **version** : Suit la version de la règle pour le contrôle des versions et les mises à jour.
- **created** : Enregistre l'horodatage de création de la règle à des fins d'audit.
- **modified** : Stocke l'horodatage de la dernière modification apportée à la règle.
- **hash** : Contient une valeur de hash de la règle afin d'en garantir l'intégrité et de détecter toute altération.
- **identifier** : Fournit un identifiant unique sous forme de chaîne, tel qu'un UUID, pour les références externes à la règle.
- **requirement** : Contient des données sérialisées définissant les exigences et les mécanismes d'autorisation spécifiques de la règle.
- **comment** : Fournit une description ou un commentaire lisible par l'utilisateur à propos de la règle, à des fins de documentation et de clarté.

### Exemple
```bash
# List by name and comments
sudo sqlite3 /var/db/auth.db "select name, comment from rules"

# Get rules for com.apple.tcc.util.admin
security authorizationdb read com.apple.tcc.util.admin
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>rule</string>
<key>comment</key>
<string>For modification of TCC settings.</string>
<key>created</key>
<real>701369782.01043606</real>
<key>modified</key>
<real>701369782.01043606</real>
<key>rule</key>
<array>
<string>authenticate-admin-nonshared</string>
</array>
<key>version</key>
<integer>0</integer>
</dict>
</plist>
```
De plus, dans [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/), il est possible de voir la signification de `authenticate-admin-nonshared` :<sup>[1]</sup>
```json
{
"allow-root": "false",
"authenticate-user": "true",
"class": "user",
"comment": "Authenticate as an administrator.",
"group": "admin",
"session-owner": "false",
"shared": "false",
"timeout": "30",
"tries": "10000",
"version": "1"
}
```
## Authd

C'est un daemon qui reçoit les requêtes visant à autoriser des clients à effectuer des actions sensibles. Il fonctionne comme un service XPC défini dans le dossier `XPCServices/` et écrit ses logs dans `/var/log/authd.log`.

De plus, à l'aide de l'outil `security`, il est possible de tester de nombreuses API de `Security.framework`. Par exemple, l'exécution de `AuthorizationExecuteWithPrivileges` : `security execute-with-privileges /bin/ls`

Cela effectuera un fork et un exec de `/usr/libexec/security_authtrampoline /bin/ls` en tant que root, ce qui demandera une autorisation dans une boîte de dialogue pour exécuter ls en tant que root :

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## Références

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)

{{#include ../../../banners/hacktricks-training.md}}
