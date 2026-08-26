# Surveillance de l’intégrité des fichiers

{{#include ../../banners/hacktricks-training.md}}

## Référence

Une baseline consiste à prendre un instantané de certaines parties d’un système afin de **le comparer à un état ultérieur pour mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hash de chaque fichier du filesystem afin de déterminer quels fichiers ont été modifiés.\
Cela peut également être fait avec les comptes utilisateur créés, les processus en cours d’exécution, les services en cours d’exécution et tout autre élément qui ne devrait pas beaucoup changer, voire pas du tout.

Une **baseline utile** stocke généralement plus qu’un simple digest : les permissions, le propriétaire, le groupe, les horodatages, l’inode, la cible du symlink, les ACL et certains attributs étendus sélectionnés méritent également d’être suivis.<sup>[[4]](#references)</sup> Du point de vue de la chasse aux attaquants, cela aide à détecter les **altérations limitées aux permissions**, le **remplacement atomique de fichiers** et la **persistance via des fichiers service/unit modifiés**, même lorsque le hash du contenu n’est pas le premier élément à changer.

### File Integrity Monitoring

Le File Integrity Monitoring (FIM) est une technique de sécurité critique qui protège les environnements IT et les données en suivant les changements apportés aux fichiers. Il combine généralement :<sup>[[1]](#references)[[3]](#references)</sup>

1. **Comparaison avec la baseline :** stocker les métadonnées et les checksums cryptographiques (préférer `SHA-256` ou mieux) pour les comparaisons futures.
2. **Notifications en temps réel :** s’abonner aux événements fichiers natifs de l’OS afin de savoir **quel fichier a changé, quand et, idéalement, quel processus/utilisateur y a accédé**.
3. **Nouvelle analyse périodique :** rétablir la confiance après des redémarrages, des événements perdus, des interruptions des agents ou une activité anti-forensic délibérée.

Pour la threat hunting, le FIM est généralement plus utile lorsqu’il se concentre sur des **paths à forte valeur** tels que :

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unités `systemd`, emplacements cron, éléments SSH, modules PAM, racines web
- emplacements de persistance Windows, binaires de services, fichiers de tâches planifiées, dossiers de démarrage
- couches inscriptibles des conteneurs et secrets/configuration montés via bind

## Backends temps réel et angles morts

### Linux

Le backend de collecte est important :<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`** : simples et courants, mais les limites de surveillance peuvent être épuisées et certains cas particuliers peuvent ne pas être détectés.
- **`auditd` / audit framework** : préférable lorsque vous devez savoir **qui a modifié le fichier** (UID de connexion, ID du processus et nom du processus).
- **`eBPF` / `kprobes`** : options plus récentes utilisées par les stacks FIM modernes pour enrichir les événements et réduire certains problèmes opérationnels des déploiements `inotify` classiques.

Quelques problèmes pratiques :<sup>[[1]](#references)[[5]](#references)</sup>

- Si un programme **remplace** un fichier avec `write temp -> rename`, surveiller le fichier lui-même peut ne plus être utile. **Surveillez le répertoire parent**, et pas uniquement le fichier.
- Les collecteurs basés sur `inotify` peuvent ne pas détecter certains événements ou voir leurs performances se dégrader avec les **arborescences de répertoires volumineuses**, les **opérations sur les hard links** ou après la **suppression d’un fichier surveillé**.
- Les ensembles de surveillance récursive très volumineux peuvent échouer silencieusement si `fs.inotify.max_user_watches`, `max_user_instances` ou `max_queued_events` sont trop faibles.
- Pour la surveillance basée sur `inotify`, les filesystems réseau constituent un angle mort, car les changements distants ne sont pas signalés.

Exemple de baseline et de vérification avec AIDE :<sup>[[4]](#references)</sup>
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
Si vous avez besoin de l’**attribution du processus** et pas uniquement des changements au niveau du chemin, préférez une télémétrie étayée par l’audit, telle que `osquery` `process_file_events` ou le mode `whodata` de Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring` : la télémétrie des appels système n’est pas du FIM

Sur les systèmes Linux modernes, surveiller `openat(2)`, `write(2)` ou d’autres points d’entrée d’appels système n’est **pas équivalent à surveiller l’opération résultante sur le système de fichiers**. Le proof of concept **Curing** de 2025 a placé en file d’attente des requêtes de fichiers et de réseau via `io_uring`, de sorte que les produits ou politiques attachés uniquement aux points d’entrée d’appels système correspondant à chaque opération perdaient la télémétrie des processus. Lors des mêmes tests, un composant de FIM limité à un chemin a tout de même observé les modifications de fichiers, ce qui montre qu’il s’agit d’un **angle mort lié à l’emplacement du hook**, et non d’un contournement des permissions ou d’un moyen de neutraliser tous les backends de FIM.<sup>[[10]](#references)</sup>

Lors de la validation d’un sensor, modifiez le même canary par plusieurs chemins : `write` normal, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, remplacement atomique et `io_uring`. Vérifiez non seulement que la dérive du hash final est détectée, mais aussi si l’événement conserve le processus responsable, le conteneur/cgroup, le chemin visible dans le namespace, l’inode et la paire de renommage. L’absence d’un événement en temps réel suivie d’une divergence lors d’un scan périodique doit être traitée comme une **perte de télémétrie**, et non comme une modification inexpliquée ordinaire.<sup>[[10]](#references)[[11]](#references)</sup>

Pour la surveillance basée sur eBPF, préférez les points d’application courants du kernel à une liste de sondes d’entrée d’appels système. Par exemple, la politique d’accès aux fichiers de Tetragon utilise `security_file_permission` pour couvrir les opérations d’E/S ordinaires, `sendfile`, `copy_file_range`, AIO et `io_uring` ; elle couvre séparément les mappages mémoire avec `security_mmap_file` et les changements de taille avec `security_path_truncate`. Cela illustre également pourquoi un seul hook offre rarement une couverture complète.<sup>[[11]](#references)</sup>

### Windows

Sous Windows, le FIM est plus efficace lorsque vous combinez les **journaux de modifications** avec une **télémétrie à forte valeur de signal sur les processus et les fichiers** :<sup>[[6]](#references)[[7]](#references)</sup>

- Le **journal USN NTFS** fournit un journal persistant, par volume, des modifications de fichiers.
- **Sysmon Event ID 11** est utile pour détecter la création et l’écrasement de fichiers.
- **Sysmon Event ID 2** aide à détecter le **timestomping**.
- **Sysmon Event ID 15** est utile pour détecter les **flux de données alternatifs nommés (ADS)** tels que `Zone.Identifier` ou les flux de payloads cachés.

Exemples rapides de triage USN :<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Pour des idées anti-forensics plus approfondies concernant la **timestamp manipulation**, l’**ADS abuse** et l’**USN tampering**, consultez [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Conteneurs

Le FIM des conteneurs ne détecte souvent pas le véritable chemin d’écriture. Avec Docker `overlay2`, le système de fichiers du conteneur combine des couches d’image en lecture seule `lowerdir` avec une **couche supérieure** accessible en écriture (`upperdir`/`diff`), et les écritures dans les fichiers de l’image sont copiées dans cette couche supérieure.<sup>[[8]](#references)</sup> Par conséquent :

- Surveiller uniquement les chemins depuis **l’intérieur** d’un conteneur éphémère peut faire manquer des modifications après la recréation du conteneur.
- Surveiller le **chemin de l’hôte** qui correspond à la couche accessible en écriture ou au volume bind-mounted concerné est souvent plus utile.
- Le FIM des couches d’image est différent du FIM du système de fichiers du conteneur en cours d’exécution.

## Notes de hunting orientées attaquant

- Suivez les **définitions de services** et les **task schedulers** aussi attentivement que les binaires. Les attaquants obtiennent souvent leur persistence en modifiant un unit file, une entrée cron ou un fichier XML de tâche plutôt qu’en patchant `/bin/sshd`.
- Un content hash seul est insuffisant. De nombreuses compromissions se manifestent d’abord par une **dérive du owner/mode/xattr/ACL**.
- Si vous soupçonnez une intrusion avancée, faites les deux : un **FIM en temps réel** pour détecter les activités récentes et une **comparaison avec une baseline à froid** depuis un support de confiance.
- Si l’attaquant dispose des privilèges root ou d’une exécution au niveau du kernel, considérez l’agent FIM et sa base de données comme non fiables. Stockez autant que possible les logs et les baselines à distance ou sur un support en lecture seule.<sup>[[4]](#references)</sup>

## Outils

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Monitoring de l’intégrité des fichiers avec osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux : un cas d’utilisation du monitoring de l’intégrité des fichiers (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitoring de l’intégrité des fichiers Wazuh (mode Syscheck et whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Manuel AIDE version 0.16.2](https://aide.github.io/doc/)
- [5] [Page du manuel Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Pilote de stockage OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Paramètres avancés du FIM Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [Les rootkits io_uring contournent les outils de sécurité Linux (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Accès aux noms de fichiers : chemins synchrones, asynchrones, mappés et de troncature (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
