# macOS Authorizations DB & Authd

{{#include ../../../banners/hacktricks-training.md}}

## **Base de données des autorisations**

La base de données située dans `/var/db/auth.db` est utilisée pour stocker les autorisations nécessaires à l'exécution d'opérations sensibles. Ces opérations sont effectuées entièrement dans **l'espace utilisateur** et sont généralement utilisées par des **services XPC** qui doivent vérifier **si le client appelant est autorisé** à effectuer une certaine action en consultant cette base de données.

Initialement, cette base de données est créée à partir du contenu de `/System/Library/Security/authorization.plist`. Ensuite, certains services peuvent ajouter ou modifier cette base de données pour y ajouter d'autres autorisations.

Les règles sont stockées dans la table `rules` à l'intérieur de la base de données et contiennent les colonnes suivantes :

- **id** : Un identifiant unique pour chaque règle, automatiquement incrémenté et servant de clé primaire.
- **name** : Le nom unique de la règle utilisé pour l'identifier et la référencer dans le système d'autorisation.
- **type** : Spécifie le type de la règle, limité aux valeurs 1 ou 2 pour définir sa logique d'autorisation.
- **class** : Catégorise la règle dans une classe spécifique, garantissant qu'il s'agit d'un entier positif.
- "allow" pour autoriser, "deny" pour refuser, "user" si la propriété de groupe indique un groupe dont l'appartenance permet l'accès, "rule" indique dans un tableau une règle à respecter, "evaluate-mechanisms" suivi d'un tableau `mechanisms` qui sont soit des intégrés, soit un nom d'un bundle à l'intérieur de `/System/Library/CoreServices/SecurityAgentPlugins/` ou /Library/Security//SecurityAgentPlugins
- **group** : Indique le groupe d'utilisateurs associé à la règle pour l'autorisation basée sur le groupe.
- **kofn** : Représente le paramètre "k-of-n", déterminant combien de sous-règles doivent être satisfaites sur un nombre total.
- **timeout** : Définit la durée en secondes avant que l'autorisation accordée par la règle n'expire.
- **flags** : Contient divers indicateurs qui modifient le comportement et les caractéristiques de la règle.
- **tries** : Limite le nombre de tentatives d'autorisation autorisées pour améliorer la sécurité.
- **version** : Suit la version de la règle pour le contrôle de version et les mises à jour.
- **created** : Enregistre l'horodatage lorsque la règle a été créée à des fins d'audit.
- **modified** : Stocke l'horodatage de la dernière modification apportée à la règle.
- **hash** : Contient une valeur de hachage de la règle pour garantir son intégrité et détecter toute falsification.
- **identifier** : Fournit un identifiant de chaîne unique, tel qu'un UUID, pour les références externes à la règle.
- **requirement** : Contient des données sérialisées définissant les exigences et mécanismes d'autorisation spécifiques de la règle.
- **comment** : Offre une description ou un commentaire lisible par l'homme sur la règle pour la documentation et la clarté.

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
De plus, dans [https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/), il est possible de voir la signification de `authenticate-admin-nonshared` :
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

C'est un démon qui recevra des demandes pour autoriser les clients à effectuer des actions sensibles. Il fonctionne comme un service XPC défini à l'intérieur du dossier `XPCServices/` et utilise pour écrire ses journaux dans `/var/log/authd.log`.

De plus, en utilisant l'outil de sécurité, il est possible de tester de nombreuses API de `Security.framework`. Par exemple, `AuthorizationExecuteWithPrivileges` en exécutant : `security execute-with-privileges /bin/ls`

Cela va fork et exec `/usr/libexec/security_authtrampoline /bin/ls` en tant que root, ce qui demandera des permissions dans une invite pour exécuter ls en tant que root :

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

{{#include ../../../banners/hacktricks-training.md}}
