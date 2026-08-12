# Base de données des autorisations macOS & Authd

{{#include ../../../banners/hacktricks-training.md}}

## Base de données des autorisations

Les Authorization Services du framework Security permettent aux helpers privilégiés et aux autres composants d'évaluer des droits d'autorisation nommés. Dans les versions actuelles de macOS, nombre de ces règles sont persistées dans `/var/db/auth.db` et évaluées par `authd` ; ce fichier et son schéma SQLite sont des détails d'implémentation susceptibles de changer d'une version à l'autre.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Les valeurs par défaut du système ont historiquement été initialisées depuis `/System/Library/Security/authorization.plist`, et les installateurs ou services privilégiés peuvent ajouter des droits nommés. Préférez l'interface prise en charge `security authorizationdb read|write|remove` plutôt que de modifier directement la base de données.<sup>[[3]](#references)</sup>

La table `rules` observée sur le build documenté contient les colonnes suivantes. Considérez ceci comme une cartographie forensique, et non comme un schéma public stable :

- **id** : Identifiant unique de chaque règle, incrémenté automatiquement et utilisé comme clé primaire.
- **name** : Nom unique de la règle utilisé pour l'identifier et la référencer dans le système d'autorisation.
- **type** : Spécifie le type de la règle, limité aux valeurs 1 ou 2 afin de définir sa logique d'autorisation.
- **class** : Classe la règle dans une catégorie spécifique, qui doit être un entier positif.
- Les classes de règles courantes comprennent `allow`, `deny`, `user`, `rule` et `evaluate-mechanisms`. Les mécanismes peuvent être intégrés au système ou provenir de plug-ins Security Agent situés sous `/System/Library/CoreServices/SecurityAgentPlugins/` ou `/Library/Security/SecurityAgentPlugins/`.<sup>[[2]](#references)</sup>
- **group** : Indique le groupe d'utilisateurs associé à la règle pour l'autorisation basée sur les groupes.
- **kofn** : Représente le paramètre « k-of-n », qui détermine combien de sous-règles doivent être satisfaites sur un nombre total donné.
- **timeout** : Définit la durée en secondes avant l'expiration de l'autorisation accordée par la règle.
- **flags** : Contient différents flags qui modifient le comportement et les caractéristiques de la règle.
- **tries** : Limite le nombre de tentatives d'autorisation autorisées afin de renforcer la sécurité.
- **version** : Suit la version de la règle pour le contrôle des versions et les mises à jour.
- **created** : Enregistre l'horodatage de création de la règle à des fins d'audit.
- **modified** : Stocke l'horodatage de la dernière modification apportée à la règle.
- **hash** : Contient une valeur de hash de la règle afin d'en garantir l'intégrité et de détecter toute altération.
- **identifier** : Fournit un identifiant unique sous forme de chaîne, tel qu'un UUID, pour les références externes à la règle.
- **requirement** : Contient des données sérialisées définissant les exigences et les mécanismes d'autorisation propres à la règle.
- **comment** : Fournit une description ou un commentaire lisible par un humain au sujet de la règle, à des fins de documentation et de clarté.

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
La règle décodée suivante illustre `authenticate-admin-nonshared` sur une version documentée de macOS :<sup>[[1]](#references)</sup>
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

`authd` is the XPC service that evaluates Authorization Services requests. On current macOS builds its bundle can be inspected at `/System/Library/Frameworks/Security.framework/XPCServices/authd.xpc`; the path is an implementation detail and may differ across releases. Older releases wrote `/var/log/authd.log`; current releases primarily use the unified logging system, which can be queried with `log show`/`log stream` using an `authd` process predicate.<sup>[[2]](#references)</sup><sup>[[5]](#references)</sup>

The `security` tool exposes several Authorization Services operations. A historical example invokes `AuthorizationExecuteWithPrivileges` with `security execute-with-privileges /bin/ls`. Apple deprecated that API in macOS 10.7; modern privileged helpers should use a launchd-managed helper and XPC authorization instead.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>

On releases that still support it, this uses `/usr/libexec/security_authtrampoline` and displays an authorization prompt before running the command as root:

<figure><img src="../../../images/image (10).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [authenticate-admin-nonshared - Overview of the macOS Authorization Right](https://www.dssw.co.uk/reference/authorization-rights/authenticate-admin-nonshared/)
- [2] [Apple Authorization Services Programming Guide (archive)](https://developer.apple.com/library/archive/documentation/Security/Conceptual/authorization_concepts/)
- [3] [`security(1)` macOS manual page](https://keith.github.io/xcode-man-pages/security.1.html)
- [4] [Apple - Daemons and Services Programming Guide: Creating launchd jobs](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [5] [Apple open-source Security project - `authd`](https://github.com/apple-oss-distributions/Security/tree/main/OSX/authd)


{{#include ../../../banners/hacktricks-training.md}}
