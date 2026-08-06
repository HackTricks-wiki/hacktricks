# Surveillance de l'intégrité des fichiers

{{#include ../../banners/hacktricks-training.md}}

## Référence

Une référence consiste à prendre un instantané de certaines parties d'un système afin de **le comparer à un état futur pour mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hash de chaque fichier du filesystem afin de déterminer quels fichiers ont été modifiés.\
Cela peut également être fait avec les comptes utilisateur créés, les processus en cours d'exécution, les services actifs et tout autre élément qui ne devrait pas beaucoup changer, voire pas du tout.

Une **référence utile** stocke généralement davantage qu'un simple digest : les permissions, le propriétaire, le groupe, les timestamps, l'inode, la cible du symlink, les ACLs et certains attributs étendus sélectionnés méritent également d'être suivis. Du point de vue de la chasse aux attaquants, cela aide à détecter la **modification des permissions uniquement**, le **remplacement atomique de fichiers** et la **persistance via des fichiers service/unit modifiés**, même lorsque le hash du contenu n'est pas le premier élément à changer.

### Surveillance de l'intégrité des fichiers

La surveillance de l'intégrité des fichiers (FIM) est une technique de sécurité essentielle qui protège les environnements IT et les données en suivant les changements apportés aux fichiers. Elle combine généralement :

1. **Comparaison avec la référence :** stocker les métadonnées et les checksums cryptographiques (préférer `SHA-256` ou mieux) pour les futures comparaisons.
2. **Notifications en temps réel :** s'abonner aux événements fichiers natifs de l'OS pour savoir **quel fichier a changé, quand, et idéalement quel processus/utilisateur l'a modifié**.
3. **Re-scan périodique :** rétablir la confiance après des redémarrages, des événements perdus, des interruptions d'agent ou une activité anti-forensic délibérée.

Pour la threat hunting, la FIM est généralement plus utile lorsqu'elle se concentre sur les **chemins à forte valeur** tels que :

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unités `systemd`, emplacements cron, éléments SSH, modules PAM, racines web
- emplacements de persistance Windows, binaires de services, fichiers de tâches planifiées, dossiers de démarrage
- couches inscriptibles des containers et secrets/configuration montés via bind

## Backends en temps réel et angles morts

### Linux

Le backend de collecte est important :<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`** : simples et courants, mais les limites de surveillance peuvent être épuisées et certains cas particuliers peuvent ne pas être détectés.
- **`auditd` / framework audit** : préférable lorsque vous devez savoir **qui a modifié le fichier** (`auid`, processus, pid, exécutable).
- **`eBPF` / `kprobes`** : options plus récentes utilisées par les stacks FIM modernes pour enrichir les événements et réduire certains problèmes opérationnels des déploiements `inotify` simples.

Quelques problèmes pratiques :<sup>[[1]](#references)</sup>

- Si un programme **remplace** un fichier avec `write temp -> rename`, surveiller le fichier lui-même peut ne plus être utile. **Surveillez le répertoire parent**, et pas uniquement le fichier.
- Les collecteurs basés sur `inotify` peuvent manquer des événements ou se dégrader sur de **très grandes arborescences de répertoires**, lors d'**activités liées aux hard links**, ou après la **suppression d'un fichier surveillé**.
- Des ensembles de surveillance récursive très volumineux peuvent échouer silencieusement si `fs.inotify.max_user_watches`, `max_user_instances` ou `max_queued_events` sont trop faibles.
- Les filesystems réseau sont généralement de mauvaises cibles pour une FIM à faible niveau de bruit.

Exemple de référence et de vérification avec AIDE :
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Exemple de configuration FIM d’`osquery` axée sur les chemins de persistance des attaquants :<sup>[[1]](#references)</sup>
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
Si vous avez besoin de l’**attribution du processus** plutôt que de simples modifications au niveau des chemins, préférez une télémétrie basée sur l’audit, telle que `osquery` `process_file_events` ou le mode `whodata` de Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

Sous Windows, le FIM est plus efficace lorsque vous combinez les **journaux de modifications** avec une **télémétrie à forte valeur de signal sur les processus et les fichiers** :

- Le **journal USN NTFS** fournit un journal persistant des modifications de fichiers par volume.
- **Sysmon Event ID 11** est utile pour détecter la création ou l’écrasement de fichiers.
- **Sysmon Event ID 2** aide à détecter le **timestomping**.
- **Sysmon Event ID 15** est utile pour les **flux de données alternatifs nommés (ADS)** tels que `Zone.Identifier` ou les flux de payloads cachés.

Exemples rapides de triage USN :
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Pour des idées anti-forensics plus approfondies autour de **timestamp manipulation**, **ADS abuse** et **USN tampering**, consultez [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Conteneurs

Le FIM des conteneurs manque fréquemment le véritable chemin d'écriture. Avec Docker `overlay2`, les modifications sont enregistrées dans la **writable upper layer** du conteneur (`upperdir`/`diff`), et non dans les read-only image layers. Par conséquent :

- La surveillance des chemins uniquement **à l'intérieur** d'un conteneur éphémère peut manquer les modifications après la recréation du conteneur.
- La surveillance du **chemin hôte** qui correspond à la writable layer ou du volume bind-mounté concerné est souvent plus utile.
- Le FIM des image layers diffère du FIM du filesystem du conteneur en cours d'exécution.

## Notes de Hunting orientées attaquant

- Suivez les **service definitions** et les **task schedulers** aussi attentivement que les binaires. Les attaquants obtiennent souvent une persistence en modifiant un unit file, une entrée cron ou un task XML plutôt qu'en patchant `/bin/sshd`.
- Un content hash seul est insuffisant. De nombreuses compromissions apparaissent d'abord sous la forme d'un **owner/mode/xattr/ACL drift**.
- Si vous suspectez une intrusion avancée, faites les deux : un **real-time FIM** pour détecter les activités récentes et une **cold baseline comparison** depuis un support de confiance.
- Si l'attaquant dispose d'une exécution root ou kernel, partez du principe que l'agent FIM, sa base de données et même la source des événements peuvent être altérés. Stockez les logs et les baselines à distance ou sur un support read-only lorsque cela est possible.

## Outils

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Références

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
