# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## État de référence

Un état de référence consiste à prendre un instantané de certaines parties d'un système pour **le comparer à un état futur afin de mettre en évidence les changements**.

Par exemple, vous pouvez calculer et stocker le hash de chaque fichier du filesystem pour pouvoir déterminer quels fichiers ont été modifiés.\
Cela peut aussi être fait avec les comptes utilisateurs créés, les processus en cours, les services en cours d'exécution et tout autre élément qui ne devrait pas beaucoup changer, voire pas du tout.

Un état de référence utile enregistre généralement plus qu'un simple digest : permissions, owner, group, timestamps, inode, symlink target, ACLs, et certains extended attributes valent également la peine d'être suivis. Du point de vue de la chasse aux attaquants, cela aide à détecter le permission-only tampering, l'atomic file replacement, et la persistance via des fichiers de service/unit modifiés même lorsque le content hash n'est pas la première chose qui change.

### File Integrity Monitoring

File Integrity Monitoring (FIM) est une technique de sécurité critique qui protège les environnements IT et les données en suivant les changements des fichiers. Elle combine généralement :

1. **Baseline comparison:** Stocker les métadonnées et les checksums cryptographiques (préférer `SHA-256` ou mieux) pour des comparaisons futures.
2. **Real-time notifications:** S'abonner aux événements fichiers natifs de l'OS pour savoir **quel fichier a changé, quand, et idéalement quel processus/utilisateur l'a touché**.
3. **Periodic re-scan:** Reconstruire la confiance après des reboots, des événements perdus, des pannes d'agent, ou une activité anti-forensique délibérée.

Pour threat hunting, FIM est généralement plus utile lorsqu'il est concentré sur des chemins à haute valeur ajoutée tels que :

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Backends en temps réel et angles morts

### Linux

Le backend de collecte a son importance :

- **`inotify` / `fsnotify`** : simple et courant, mais les limites de watch peuvent être épuisées et certains cas limites sont manqués.
- **`auditd` / audit framework** : mieux lorsque vous avez besoin de **qui a changé le fichier** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`** : options plus récentes utilisées par les stacks FIM modernes pour enrichir les événements et réduire une partie de la douleur opérationnelle des déploiements basiques `inotify`.

Quelques pièges pratiques :

- Si un programme remplace un fichier avec `write temp -> rename`, surveiller le fichier lui-même peut cesser d'être utile. Surveillez le répertoire parent, pas seulement le fichier.
- Les collecteurs basés sur `inotify` peuvent rater ou se dégrader sur des arborescences énormes, des activités de hard-link, ou après qu'un fichier surveillé ait été supprimé.
- Des ensembles de watch récursifs très volumineux peuvent échouer silencieusement si `fs.inotify.max_user_watches`, `max_user_instances`, ou `max_queued_events` sont trop bas.
- Les systèmes de fichiers réseau sont généralement de mauvaises cibles pour FIM lorsqu'on cherche une surveillance à faible bruit.

Exemple d'état de référence + vérification avec AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Exemple de configuration FIM `osquery` axée sur les chemins de persistance de l'attaquant :
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
Si vous avez besoin d'**attribution de processus** plutôt que seulement de changements au niveau du chemin, préférez une télémétrie appuyée par l'audit, comme `osquery` `process_file_events` ou le mode `whodata` de Wazuh.

### Windows

Sur Windows, FIM est plus efficace lorsque vous combinez les **change journals** avec une **télémétrie processus/fichier à haut signal** :

- **NTFS USN Journal** fournit un journal persistant par volume des modifications de fichiers.
- **Sysmon Event ID 11** est utile pour la création/écrasement de fichiers.
- **Sysmon Event ID 2** aide à détecter le **timestomping**.
- **Sysmon Event ID 15** est utile pour les **named alternate data streams (ADS)** tels que `Zone.Identifier` ou des flux payload cachés.

Exemples rapides de triage USN :
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Pour des idées anti-forensiques plus approfondies autour de **timestamp manipulation**, **ADS abuse**, et **USN tampering**, consultez [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Conteneurs

Container FIM frequently misses the real write path. With Docker `overlay2`, changes are committed into the container's **writable upper layer** (`upperdir`/`diff`), not the read-only image layers. Therefore:

- Monitoring only paths from **inside** a short-lived container may miss changes after the container is recreated.
- Monitoring the **host path** that backs the writable layer or the relevant bind-mounted volume is often more useful.
- FIM on image layers is different from FIM on the running container filesystem.

## Notes pour la chasse orientée attaquant

- Suivez les **service definitions** et **task schedulers** aussi attentivement que les binaires. Les attaquants obtiennent souvent la persistance en modifiant un unit file, une cron entry ou un task XML plutôt qu'en patchant `/bin/sshd`.
- A content hash alone is insufficient. Beaucoup de compromissions apparaissent d'abord comme une dérive d'**owner/mode/xattr/ACL**.
- Si vous suspectez une intrusion mature, faites les deux : **real-time FIM** pour l'activité récente et une **cold baseline comparison** depuis des médias de confiance.
- Si l'attaquant a root ou exécution kernel, supposez que l'agent FIM, sa base de données, et même la source d'événements peuvent être altérés. Stockez les logs et les baselines à distance ou sur des médias en lecture seule autant que possible.

## Outils

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Références

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
