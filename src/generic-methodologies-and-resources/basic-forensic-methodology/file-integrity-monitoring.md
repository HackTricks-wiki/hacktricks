# Surveillance de l'intégrité des fichiers

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Une baseline consiste à prendre un instantané de certaines parties d'un système afin de **le comparer à un état futur pour mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hash de chaque fichier du système de fichiers afin de déterminer quels fichiers ont été modifiés.\
Cela peut également être fait avec les comptes utilisateur créés, les processus en cours d'exécution, les services actifs et tout autre élément qui ne devrait pas beaucoup changer, voire pas du tout.

Une **baseline utile** stocke généralement plus qu'un simple digest : les permissions, le propriétaire, le groupe, les horodatages, l'inode, la cible du lien symbolique, les ACL et certains attributs étendus sélectionnés méritent également d'être surveillés.<sup>[[4]](#references)</sup> Du point de vue de la recherche d'attaquants, cela aide à détecter les **altérations limitées aux permissions**, le **remplacement atomique de fichiers** et la **persistance via des fichiers service/unit modifiés**, même lorsque le hash du contenu n'est pas le premier élément à changer.

### Surveillance de l'intégrité des fichiers

La surveillance de l'intégrité des fichiers (File Integrity Monitoring, FIM) est une technique de sécurité essentielle qui protège les environnements IT et les données en suivant les changements apportés aux fichiers. Elle combine généralement :<sup>[[1]](#references)[[3]](#references)</sup>

1. **Comparaison avec la baseline :** stocker les métadonnées et les sommes de contrôle cryptographiques (préférer `SHA-256` ou mieux) pour les comparaisons futures.
2. **Notifications en temps réel :** s'abonner aux événements fichiers natifs de l'OS pour savoir **quel fichier a changé, quand et, idéalement, quel processus/utilisateur y a accédé**.
3. **Nouvelle analyse périodique :** rétablir la confiance après des redémarrages, des événements perdus, des interruptions de l'agent ou une activité anti-forensic délibérée.

Pour la recherche de menaces, la FIM est généralement plus utile lorsqu'elle se concentre sur des **chemins à forte valeur** tels que :

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unités `systemd`, emplacements cron, éléments SSH, modules PAM, racines web
- emplacements de persistance Windows, binaires de services, fichiers de tâches planifiées, dossiers de démarrage
- couches inscriptibles des conteneurs et secrets/configuration montés via bind

## Backends en temps réel et angles morts

### Linux

Le backend de collecte est important :<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`** : simples et courants, mais les limites de surveillance peuvent être atteintes et certains cas particuliers ne sont pas détectés.
- **`auditd` / framework d'audit** : préférable lorsque vous devez savoir **qui a modifié le fichier** (UID de connexion, ID du processus et nom du processus).
- **`eBPF` / `kprobes`** : options plus récentes utilisées par les stacks FIM modernes pour enrichir les événements et réduire certains problèmes opérationnels des déploiements `inotify` simples.

Quelques problèmes pratiques :<sup>[[1]](#references)[[5]](#references)</sup>

- Si un programme **remplace** un fichier avec `write temp -> rename`, surveiller le fichier lui-même peut ne plus être utile. **Surveillez le répertoire parent**, et pas uniquement le fichier.
- Les collecteurs basés sur `inotify` peuvent manquer des événements ou devenir moins fiables avec de **très grandes arborescences de répertoires**, une **activité sur les hard links** ou après la **suppression d'un fichier surveillé**.
- De très grands ensembles de surveillances récursives peuvent échouer silencieusement si `fs.inotify.max_user_watches`, `max_user_instances` ou `max_queued_events` sont trop faibles.
- Pour la surveillance basée sur `inotify`, les systèmes de fichiers réseau constituent un angle mort, car les changements distants ne sont pas signalés.

Exemple de baseline et de vérification avec AIDE :<sup>[[4]](#references)</sup>
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
Si vous avez besoin de **l’attribution des processus** plutôt que de simples changements au niveau des chemins, préférez une télémétrie soutenue par l’audit telle que `osquery` `process_file_events` ou le mode `whodata` de Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Sous Windows, le FIM est plus efficace lorsque vous combinez les **journaux de modifications** avec une **télémétrie des processus/fichiers à fort signal** :<sup>[[6]](#references)[[7]](#references)</sup>

- Le **journal USN NTFS** fournit un journal persistant des changements de fichiers pour chaque volume.
- **Sysmon Event ID 11** est utile pour détecter la création et l’écrasement de fichiers.
- **Sysmon Event ID 2** aide à détecter le **timestomping**.
- **Sysmon Event ID 15** est utile pour les **named alternate data streams (ADS)** tels que `Zone.Identifier` ou les streams de payloads cachés.

Exemples rapides de triage USN :<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Pour des idées anti-forensics plus approfondies autour de la **timestamp manipulation**, de l’**ADS abuse** et de l’**USN tampering**, consultez [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Conteneurs

Le FIM des conteneurs ne détecte souvent pas le véritable chemin d’écriture. Avec Docker `overlay2`, le système de fichiers du conteneur combine des couches `lowerdir` d’image en lecture seule avec une **couche supérieure** accessible en écriture (`upperdir`/`diff`), et les écritures dans les fichiers de l’image sont copiées dans cette couche supérieure.<sup>[[8]](#references)</sup> Par conséquent :

- La surveillance des chemins uniquement **à l’intérieur** d’un conteneur éphémère peut manquer les modifications après la recréation du conteneur.
- La surveillance du **chemin hôte** qui correspond à la couche accessible en écriture ou du volume bind-mount pertinent est souvent plus utile.
- Le FIM des couches d’image est différent du FIM du système de fichiers du conteneur en cours d’exécution.

## Notes de hunting orientées attaquant

- Suivez les **définitions de services** et les **task schedulers** aussi attentivement que les binaires. Les attaquants obtiennent souvent une persistance en modifiant un fichier d’unité, une entrée cron ou un fichier XML de tâche plutôt qu’en patchant `/bin/sshd`.
- Un simple hash du contenu est insuffisant. De nombreuses compromissions se manifestent d’abord par une **dérive du propriétaire/mode/xattr/ACL**.
- Si vous soupçonnez une intrusion avancée, faites les deux : un **FIM en temps réel** pour détecter l’activité récente et une **comparaison à froid de la baseline** depuis un support de confiance.
- Si l’attaquant dispose des privilèges root ou d’une exécution au niveau du kernel, considérez l’agent FIM et sa base de données comme non fiables. Stockez les logs et les baselines à distance ou sur un support en lecture seule chaque fois que possible.<sup>[[4]](#references)</sup>

## Outils

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Module File Integrity d’Elastic Auditbeat](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Surveillance de l’intégrité des fichiers avec osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Traçage de Linux : un cas d’utilisation de la surveillance de l’intégrité des fichiers (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Surveillance de l’intégrité des fichiers Wazuh (mode Syscheck et whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Manuel AIDE version 0.16.2](https://aide.github.io/doc/)
- [5] [Page de manuel Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Pilote de stockage OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Paramètres avancés du FIM Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
