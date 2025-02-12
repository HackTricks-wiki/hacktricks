{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash est utilisé pour **rassembler, transformer et dispatcher des journaux** à travers un système connu sous le nom de **pipelines**. Ces pipelines sont composés de **stages d'entrée**, **de filtrage** et **de sortie**. Un aspect intéressant se présente lorsque Logstash fonctionne sur une machine compromise.

### Configuration du Pipeline

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
Ce fichier révèle où se trouvent les fichiers **.conf**, contenant des configurations de pipeline. Lors de l'utilisation d'un **module de sortie Elasticsearch**, il est courant que les **pipelines** incluent des **identifiants Elasticsearch**, qui possèdent souvent des privilèges étendus en raison du besoin de Logstash d'écrire des données dans Elasticsearch. Les caractères génériques dans les chemins de configuration permettent à Logstash d'exécuter tous les pipelines correspondants dans le répertoire désigné.

### Escalade de privilèges via des pipelines écrits

Pour tenter une escalade de privilèges, identifiez d'abord l'utilisateur sous lequel le service Logstash s'exécute, généralement l'utilisateur **logstash**. Assurez-vous de répondre à **un** de ces critères :

- Posséder un **accès en écriture** à un fichier **.conf** de pipeline **ou**
- Le fichier **/etc/logstash/pipelines.yml** utilise un caractère générique, et vous pouvez écrire dans le dossier cible

De plus, **une** de ces conditions doit être remplie :

- Capacité à redémarrer le service Logstash **ou**
- Le fichier **/etc/logstash/logstash.yml** a **config.reload.automatic: true** défini

Étant donné un caractère générique dans la configuration, créer un fichier qui correspond à ce caractère générique permet l'exécution de commandes. Par exemple :
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
Ici, **interval** détermine la fréquence d'exécution en secondes. Dans l'exemple donné, la commande **whoami** s'exécute toutes les 120 secondes, avec sa sortie dirigée vers **/tmp/output.log**.

Avec **config.reload.automatic: true** dans **/etc/logstash/logstash.yml**, Logstash détectera et appliquera automatiquement les nouvelles configurations de pipeline ou les modifications sans nécessiter de redémarrage. S'il n'y a pas de caractère générique, des modifications peuvent toujours être apportées aux configurations existantes, mais il est conseillé de faire preuve de prudence pour éviter les interruptions.

## References

{{#include ../../banners/hacktricks-training.md}}
