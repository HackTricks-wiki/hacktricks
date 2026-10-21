# Chemins masqués

{{#include ../../../../banners/hacktricks-training.md}}

Les chemins masqués sont des protections à l’exécution qui cachent au conteneur des emplacements particulièrement sensibles du système de fichiers, accessibles au noyau, en les recouvrant par des montages bind ou en les rendant autrement inaccessibles. La spécification OCI Runtime définit `maskedPaths` comme des chemins absolus qui ne doivent pas être lisibles depuis le conteneur. <sup>[[1]](#references)</sup>

C’est important, car de nombreuses techniques d’évasion de conteneur et d’impact sur l’hôte commencent par la lecture ou l’écriture de fichiers spéciaux dans `/proc` ou `/sys`. Si ces emplacements sont masqués, l’attaquant perd l’accès direct à une partie utile de la surface de contrôle du noyau, même après avoir obtenu l’exécution de code dans le conteneur.

## Fonctionnement

Les runtimes masquent généralement certains chemins, tels que :

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La liste exacte dépend du runtime et de la configuration de l’hôte. L’essentiel est que le chemin devienne inaccessible ou soit remplacé du point de vue du conteneur, même s’il existe toujours sur l’hôte.

## Lab

Inspectez la configuration des chemins masqués exposée par Docker :

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Examinez le comportement réel des montages au sein de la charge de travail :

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

Un chemin répertorié n’est pas nécessairement lisible : runc peut masquer un fichier avec un bind mount vers `/dev/null` et un répertoire avec un tmpfs vide en lecture seule. Vérifiez le point de montage exact, pas seulement si `ls` réussit. <sup>[[4]](#references)</sup>

## Impact sur la sécurité

Le masquage ne constitue pas la principale frontière d’isolation, mais il supprime plusieurs cibles de grande valeur en post-exploitation. Sans masquage, un conteneur compromis peut être en mesure d’inspecter l’état du noyau, de lire des informations sensibles sur les processus ou les clés, ou d’interagir avec des objets procfs/sysfs qui n’auraient jamais dû être visibles par l’application.

## Mauvaises configurations

La principale erreur consiste à démasquer de larges catégories de chemins pour des raisons pratiques ou de débogage. Dans Podman, cela peut prendre la forme de `--security-opt unmask=ALL` ou d’un démasquage ciblé. <sup>[[2]](#references)</sup> Dans Kubernetes, une exposition trop large de proc peut se traduire par `procMount: Unmasked` ; les versions actuelles de Kubernetes exigent `spec.hostUsers: false` (un espace de noms utilisateur) pour ce paramètre, alors que les versions 1.12–1.29 n’imposaient pas cette exigence. <sup>[[3]](#references)</sup> Un autre problème grave consiste à exposer le `/proc` ou le `/sys` de l’hôte via un bind mount, ce qui contourne complètement le principe d’une vue réduite du conteneur.

## Exploitation

Si le masquage est insuffisant ou absent, commencez par repérer les chemins procfs/sysfs sensibles directement accessibles :

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

Si un chemin supposé masqué est accessible, examinez-le attentivement :

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

Ce que ces commandes peuvent révéler :

- `/proc/timer_list` peut exposer des données sur les timers et l'ordonnanceur de l'hôte. Il s'agit surtout d'un moyen de reconnaissance, mais cela confirme que le conteneur peut lire des informations liées au noyau qui sont normalement masquées.
- `/proc/keys` liste uniquement les métadonnées des clés pour lesquelles le lecteur dispose de la permission **view**, sous réserve des contrôles LSM. Il peut révéler les types et descriptions des clés, mais ne dump pas leur contenu. <sup>[[6]](#references)</sup>
- `/sys/firmware` aide à identifier le mode de démarrage, les interfaces du firmware et les détails de la plateforme, utiles pour identifier l'hôte et déterminer si la charge de travail voit l'état de l'hôte.
- `/proc/config.gz` peut révéler la configuration du noyau en cours d'exécution, ce qui est précieux pour vérifier les prérequis d'exploits de noyau publics ou comprendre pourquoi une fonctionnalité donnée est accessible.
- `/proc/sched_debug` expose l'état de l'ordonnanceur et contourne souvent l'idée intuitive selon laquelle l'espace de noms PID devrait masquer complètement les informations sur les processus sans rapport.

Les résultats intéressants incluent la lecture directe de ces fichiers, des preuves que les données proviennent de l'hôte plutôt que d'une vue restreinte du conteneur, ou l'accès à d'autres emplacements procfs/sysfs couramment masqués par défaut.

### Race sur la source du masque au démarrage du conteneur

Dans les implémentations vulnérables de runc, les masques de fichiers dépendent de l'inode du `/dev/null` du conteneur. Un attaquant capable de lancer des conteneurs simultanément avec des montages partagés, notamment au moyen d'étapes BuildKit parallèles, peut provoquer une race au démarrage et supprimer `/dev/null` avant que runc ne le monte par-dessus les fichiers procfs à masquer. Le runtime traite alors la **source** manquante comme si une destination de masque était absente et ignore silencieusement ces masques de fichiers. L'échec dépend d'une race pendant la configuration du runtime ; supprimer `/dev/null` après le démarrage n'annule pas un masque déjà installé. <sup>[[4]](#references)</sup>

Après un test contrôlé, comparez la liste des masques demandés aux points de montage exacts dans le nouveau conteneur. <sup>[[4]](#references)</sup> `findmnt -M` vérifie le point de montage nommé au lieu de se rabattre sur un montage parent ; si `findmnt` est absent, inspectez `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> La réussite d'un `ls` ou un `cat` vide ne peut pas prouver que le masque est absent. <sup>[[4]](#references)</sup>

Utilisez les [vérifications ci-dessous](#checks) pour comparer les masques demandés aux montages exacts dans le nouveau conteneur.

Un masque de fichier ignoré peut exposer des données procfs si les permissions normales et la politique LSM l'autorisent. Cela ne rend **pas** `/proc/sys` inscriptible à lui seul : il s'agit d'un contrôle [read-only-path](read-only-paths.md) distinct. La substitution distincte d'un lien symbolique `/dev/null`, qui peut rediriger un montage bind vers une cible procfs inscriptible, est abordée dans la section sur la [race du runtime liée à l'espace de noms PID](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Checks

L'objectif de ces vérifications est de déterminer quels chemins le runtime a intentionnellement masqués et si la charge de travail actuelle voit toujours un système de fichiers lié au noyau restreint.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Utilisez une vérification de montage exact, car un fichier masqué peut toujours exister et une lecture peut renvoyer un résultat vide depuis `/dev/null`. L’absence d’un point de montage est un élément à examiner, pas une preuve que les données de l’hôte sont lisibles à elle seule. <sup>[[4]](#references)[[5]](#references)</sup>

Voici les éléments intéressants :

- Une longue liste de chemins masqués est normale dans les runtimes renforcés.
- L’absence de masquage sur des entrées procfs sensibles mérite un examen plus approfondi.
- Si un chemin sensible est accessible et que le conteneur dispose également de capacités étendues ou de montages larges, l’exposition est plus importante.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste de chemins masqués par défaut | exposition des montages host proc/sys, `--privileged` |
| Podman | Activé par défaut | Podman applique les chemins masqués par défaut, sauf si ceux-ci sont démasqués manuellement | `--security-opt unmask=ALL`, démasquage ciblé, `--privileged` |
| Kubernetes | Hérite des valeurs par défaut du runtime | Utilise le comportement de masquage du runtime sous-jacent, sauf si les paramètres du pod affaiblissent l’exposition de proc | `procMount: Unmasked` (nécessite `hostUsers: false` dans les versions actuelles), modèles de workloads privilégiés, montages host étendus |
| containerd / CRI-O sous Kubernetes | Valeur par défaut du runtime | Applique généralement les chemins masqués OCI/runtime, sauf remplacement | modifications directes de la configuration du runtime, mêmes possibilités d’affaiblissement dans Kubernetes |

Les chemins masqués sont généralement présents par défaut. Le principal problème opérationnel n’est pas leur absence dans le runtime, mais leur démasquage délibéré ou les bind mounts de l’hôte qui annulent la protection.

## References

- [1] [Open Container Initiative - Configuration des conteneurs Linux : chemins masqués](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Documentation Podman - options de sécurité de `podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Documentation Kubernetes - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [Avis runc : course sur la source de montage des chemins masqués](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [Manuel de findmnt(8)](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [Manuel de keyrings(7)](https://man7.org/linux/man-pages/man7/keyrings.7.html)
{{#include ../../../../banners/hacktricks-training.md}}
