# Surveillance de l'intégrité des fichiers

{{#include ../../banners/hacktricks-training.md}}

## Référence

Une référence consiste à prendre un instantané de certaines parties d'un système afin de **le comparer à un état futur pour mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hash de chaque fichier du système de fichiers afin de déterminer quels fichiers ont été modifiés.\
Cela peut également être fait avec les comptes utilisateur créés, les processus en cours d'exécution, les services actifs et tout autre élément qui ne devrait pas beaucoup changer, voire pas du tout.

Une **référence utile** stocke généralement davantage qu'un simple digest : les permissions, le propriétaire, le groupe, les horodatages, l'inode, la cible du lien symbolique, les ACL et certains attributs étendus sélectionnés méritent également d'être suivis. Du point de vue de la chasse aux attaquants, cela aide à détecter les **altérations limitées aux permissions**, le **remplacement atomique de fichiers** et la **persistance via la modification de fichiers de service/unités**, même lorsque le hash du contenu n'est pas le premier élément à changer.

### Surveillance de l'intégrité des fichiers

La surveillance de l'intégrité des fichiers (FIM) est une technique de sécurité essentielle qui protège les environnements informatiques et les données en suivant les changements apportés aux fichiers. Elle combine généralement :

1. **Comparaison avec la référence :** Stocker les métadonnées et les sommes de contrôle cryptographiques (préférer `SHA-256` ou une version plus robuste) pour les comparaisons futures.
2. **Notifications en temps réel :** S'abonner aux événements fichiers natifs de l'OS afin de savoir **quel fichier a changé, quand, et idéalement quel processus/utilisateur l'a modifié**.
3. **Nouvelle analyse périodique :** Restaurer la confiance après des redémarrages, des événements perdus, des interruptions de l'agent ou une activité anti-forensic délibérée.

Pour la threat hunting, la FIM est généralement plus utile lorsqu'elle se concentre sur les **chemins à forte valeur** tels que :

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Unités `systemd`, emplacements cron, éléments SSH, modules PAM, racines web
- Emplacements de persistance Windows, binaires de services, fichiers de tâches planifiées, dossiers de démarrage
- Couches accessibles en écriture des conteneurs et secrets/configurations montés via bind

## Backends en temps réel et angles morts

### Linux

Le backend de collecte est important :<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`** : simples et courants, mais les limites de surveillance peuvent être épuisées et certains cas particuliers peuvent ne pas être détectés.
- **`auditd` / framework d'audit** : préférable lorsque vous devez savoir **qui a modifié le fichier** (`auid`, processus, pid, exécutable).
- **`eBPF` / `kprobes`** : options plus récentes utilisées par les stacks FIM modernes pour enrichir les événements et réduire certains problèmes opérationnels des déploiements `inotify` classiques.

Quelques problèmes pratiques :<sup>[[1]](#references)</sup>

- Si un programme **remplace** un fichier avec `write temp -> rename`, surveiller le fichier lui-même peut ne plus être utile. **Surveillez le répertoire parent**, et pas uniquement le fichier.
- Les collecteurs basés sur `inotify` peuvent manquer des événements ou voir leurs performances se dégrader sur des **arbres de répertoires immenses**, lors d'**activités liées aux hard links**, ou après la **suppression d'un fichier surveillé**.
- Les ensembles de surveillance récursive très volumineux peuvent échouer silencieusement si `fs.inotify.max_user_watches`, `max_user_instances` ou `max_queued_events` sont trop faibles.
- Les systèmes de fichiers réseau sont généralement de mauvaises cibles pour une FIM produisant peu de bruit.

Exemple de référence et de vérification avec AIDE :
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Exemple de configuration `osquery` de FIM axée sur les chemins de persistence des attaquants :<sup>[[1]](#references)</sup>
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
Si vous avez besoin d’une **attribution des processus** plutôt que de simples changements au niveau des chemins, préférez une télémétrie basée sur l’audit, telle que `osquery` `process_file_events` ou le mode `whodata` de Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Sous Windows, le FIM est plus efficace lorsque vous combinez les **journaux de changements** avec une **télémétrie à forte valeur de signal sur les processus/fichiers** :

- Le **journal USN NTFS** fournit un journal persistant des changements de fichiers par volume.
- **Sysmon Event ID 11** est utile pour détecter la création et l’écrasement de fichiers.
- **Sysmon Event ID 2** aide à détecter le **timestomping**.
- **Sysmon Event ID 15** est utile pour les **named alternate data streams (ADS)** tels que `Zone.Identifier` ou les flux de payloads cachés.

Exemples rapides de triage USN :
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Pour des idées anti-forensics plus approfondies autour de la **timestamp manipulation**, de l’**ADS abuse** et de l’**USN tampering**, consultez [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Conteneurs

Le FIM des conteneurs manque souvent le véritable chemin d’écriture. Avec Docker `overlay2`, les changements sont validés dans la **couche inscriptible supérieure** du conteneur (`upperdir`/`diff`), et non dans les couches d’image en lecture seule. Par conséquent :

- Surveiller uniquement les chemins **à l’intérieur** d’un conteneur éphémère peut faire manquer les changements après la recréation du conteneur.
- Surveiller le **chemin hôte** qui correspond à la couche inscriptible ou au volume bind-mounted concerné est souvent plus utile.
- Le FIM des couches d’image est différent du FIM du système de fichiers du conteneur en cours d’exécution.

## Notes de chasse orientées attaquant

- Suivez les **définitions de services** et les **task schedulers** aussi soigneusement que les binaires. Les attaquants obtiennent souvent une persistence en modifiant un fichier unit, une entrée cron ou un fichier XML de tâche plutôt qu’en patchant `/bin/sshd`.
- Un hash de contenu seul est insuffisant. De nombreux compromissions se manifestent d’abord par une **dérive de owner/mode/xattr/ACL**.
- Si vous suspectez une intrusion mature, faites les deux : un **FIM en temps réel** pour détecter les activités récentes et une **comparaison avec une baseline à froid** depuis un support de confiance.
- Si l’attaquant dispose des privilèges root ou d’une exécution au niveau du kernel, partez du principe que l’agent FIM, sa base de données et même la source des événements peuvent être altérés. Stockez les logs et les baselines à distance ou sur un support en lecture seule autant que possible.

## Outils

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Références

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
