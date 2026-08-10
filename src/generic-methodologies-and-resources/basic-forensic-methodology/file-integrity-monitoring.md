# File Integrity Monitoring

## Baseline

Une baseline consiste à prendre un instantané de certaines parties d'un système afin de **le comparer à un état futur pour mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hash de chaque fichier du filesystem afin de déterminer quels fichiers ont été modifiés.\
Cela peut également être fait avec les comptes utilisateur créés, les processus en cours d'exécution, les services actifs et tout autre élément qui ne devrait pas beaucoup changer, voire pas du tout.

Une **baseline utile** stocke généralement plus qu'un simple digest : les permissions, le propriétaire, le groupe, les timestamps, l'inode, la cible du symlink, les ACLs et certains attributs étendus sélectionnés méritent également d'être surveillés.<sup>[[4]](#references)</sup> Du point de vue du threat hunting, cela aide à détecter les **modifications des permissions uniquement**, le **remplacement atomique de fichiers** et la **persistance via la modification de fichiers de service/unit** même lorsque le hash du contenu n'est pas le premier élément à changer.

### File Integrity Monitoring

File Integrity Monitoring (FIM) est une technique de sécurité essentielle qui protège les environnements IT et les données en surveillant les changements dans les fichiers. Il combine généralement :<sup>[[1]](#references)[[3]](#references)</sup>

1. **Comparaison avec la baseline :** Stocker les métadonnées et les sommes de contrôle cryptographiques (préférer `SHA-256` ou mieux) pour les comparaisons futures.
2. **Notifications en temps réel :** S'abonner aux événements de fichiers natifs de l'OS afin de savoir **quel fichier a changé, quand et, idéalement, quel processus/utilisateur l'a modifié**.
3. **Nouvelle analyse périodique :** Restaurer la confiance après des redémarrages, des événements perdus, des pannes d'agent ou une activité anti-forensics délibérée.

Pour le threat hunting, le FIM est généralement plus utile lorsqu'il se concentre sur des **paths à haute valeur** tels que :

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Les units `systemd`, les emplacements cron, les éléments SSH, les modules PAM, les web roots
- Les emplacements de persistance Windows, les binaires de services, les fichiers de tâches planifiées, les dossiers de démarrage
- Les couches inscriptibles des containers et les secrets/configurations montés avec bind mount

## Real-Time Backends & Blind Spots

### Linux

Le backend de collecte est important :<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`** : facile à utiliser et courant, mais les limites de watch peuvent être épuisées et certains edge cases peuvent ne pas être détectés.
- **`auditd` / audit framework** : préférable lorsque vous devez savoir **qui a modifié le fichier** (UID de connexion, ID du processus et nom du processus).
- **`eBPF` / `kprobes`** : options plus récentes utilisées par les stacks FIM modernes pour enrichir les événements et réduire certains problèmes opérationnels des déploiements `inotify` classiques.

Quelques problèmes pratiques :<sup>[[1]](#references)[[5]](#references)</sup>

- Si un programme **remplace** un fichier avec `write temp -> rename`, surveiller le fichier lui-même peut ne plus être utile. **Surveillez le répertoire parent**, et pas uniquement le fichier.
- Les collecteurs basés sur `inotify` peuvent manquer des événements ou perdre en performances sur des **arbres de répertoires immenses**, lors d'**opérations sur des hard links** ou après la **suppression d'un fichier surveillé**.
- De très grands ensembles de watch récursifs peuvent échouer silencieusement si `fs.inotify.max_user_watches`, `max_user_instances` ou `max_queued_events` sont trop faibles.
- Pour la surveillance basée sur `inotify`, les filesystems réseau constituent un blind spot, car les changements distants ne sont pas signalés.

Exemple de baseline + vérification avec AIDE :<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Exemple de configuration `osquery` de FIM axée sur les chemins de persistance utilisés par les attaquants :<sup>[[1]](#references)</sup>
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
Si vous avez besoin de l’**attribution des processus** plutôt que de simples modifications au niveau des chemins, préférez une télémétrie soutenue par l’audit, telle que `osquery` `process_file_events` ou le mode `whodata` de Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

Sous Windows, le FIM est plus efficace lorsque vous combinez les **journaux de modifications** avec une **télémétrie processus/fichiers à fort signal** :<sup>[[6]](#references)[[7]](#references)</sup>

- Le **journal USN NTFS** fournit un journal persistant des modifications de fichiers par volume.
- **Sysmon Event ID 11** est utile pour détecter la création ou l’écrasement de fichiers.
- **Sysmon Event ID 2** aide à détecter le **timestomping**.
- **Sysmon Event ID 15** est utile pour les **named alternate data streams (ADS)** tels que `Zone.Identifier` ou les flux de payloads cachés.

Exemples rapides de triage USN :<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Pour approfondir les idées **anti-forensics** autour de la **timestamp manipulation**, de l’**ADS abuse** et de l’**USN tampering**, consultez [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Conteneurs

Le FIM des conteneurs ignore souvent le véritable chemin d’écriture. Avec Docker `overlay2`, le système de fichiers du conteneur combine des couches d’image en lecture seule (`lowerdir`) avec une **couche supérieure** inscriptible (`upperdir`/`diff`), et les écritures dans les fichiers de l’image sont copiées dans cette couche supérieure.<sup>[[8]](#references)</sup> Par conséquent :

- La surveillance des chemins situés **à l’intérieur** d’un conteneur éphémère peut ne pas détecter les modifications après la recréation du conteneur.
- La surveillance du **chemin hôte** qui correspond à la couche inscriptible ou du volume bind-mounted concerné est souvent plus utile.
- Le FIM des couches d’image diffère du FIM du système de fichiers du conteneur en cours d’exécution.

## Notes de chasse orientées attaquant

- Suivez les **définitions de services** et les **task schedulers** aussi attentivement que les binaires. Les attaquants obtiennent souvent une persistence en modifiant un fichier unit, une entrée cron ou un fichier XML de tâche plutôt qu’en patchant `/bin/sshd`.
- Un simple content hash est insuffisant. De nombreuses compromissions se manifestent d’abord par une **dérive du owner/mode/xattr/ACL**.
- Si vous suspectez une intrusion avancée, faites les deux : un **FIM en temps réel** pour détecter les activités récentes et une **comparaison avec une baseline à froid** depuis un support approuvé.
- Si l’attaquant dispose des privilèges root ou d’une exécution au niveau du kernel, considérez l’agent FIM et sa base de données comme non fiables. Stockez les logs et les baselines à distance ou sur un support en lecture seule lorsque cela est possible.<sup>[[4]](#references)</sup>

## Outils

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Surveillance de l’intégrité des fichiers avec osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux : un cas d’utilisation de la surveillance de l’intégrité des fichiers (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Surveillance de l’intégrité des fichiers Wazuh (mode Syscheck et whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Manuel AIDE version 0.16.2](https://aide.github.io/doc/)
- [5] [Page de manuel Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Pilote de stockage OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Paramètres avancés du FIM Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
