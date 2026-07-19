# Chemins masqués

{{#include ../../../../banners/hacktricks-training.md}}

Les chemins masqués sont des protections d'exécution qui dissimulent au conteneur des emplacements du système de fichiers particulièrement sensibles, liés au kernel, en effectuant un bind mount par-dessus ou en les rendant autrement inaccessibles. L'objectif est d'empêcher un workload d'interagir directement avec des interfaces dont les applications ordinaires n'ont pas besoin, en particulier dans procfs.

Cela est important, car de nombreuses container escapes et techniques ayant un impact sur l'hôte commencent par la lecture ou l'écriture de fichiers spéciaux sous `/proc` ou `/sys`. Si ces emplacements sont masqués, l'attaquant perd l'accès direct à une partie utile de la surface de contrôle du kernel, même après avoir obtenu une exécution de code dans le conteneur.

## Fonctionnement

Les runtimes masquent généralement certains chemins, tels que :

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La liste exacte dépend du runtime et de la configuration de l'hôte. La propriété importante est que le chemin devient inaccessible ou est remplacé du point de vue du conteneur, même s'il existe toujours sur l'hôte.

## Lab

Inspectez la configuration des chemins masqués exposée par Docker :
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspectez le comportement réel du montage à l’intérieur du workload :
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impact sur la sécurité

Le masquage ne constitue pas la principale limite d’isolation, mais il supprime plusieurs cibles post-exploitation à forte valeur. Sans masquage, un container compromis peut être capable d’inspecter l’état du kernel, de lire des informations sensibles sur les processus ou les clés, ou d’interagir avec des objets procfs/sysfs qui n’auraient jamais dû être visibles par l’application.

## Mauvaises configurations

L’erreur principale consiste à démasquer de larges catégories de chemins par souci de commodité ou pour le debugging. Dans Podman, cela peut apparaître sous la forme de `--security-opt unmask=ALL` ou d’un démasquage ciblé. Dans Kubernetes, une exposition trop large de proc peut apparaître via `procMount: Unmasked`. Un autre problème sérieux consiste à exposer le `/proc` ou le `/sys` de l’host via un bind mount, ce qui contourne entièrement le principe d’une vue réduite du container.

## Abuse

Si le masquage est faible ou absent, commencez par identifier les chemins procfs/sysfs sensibles directement accessibles :
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Si un chemin censé être masqué est accessible, examinez-le attentivement :
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Ce que ces commandes peuvent révéler :

- `/proc/timer_list` peut exposer les données des timers et du scheduler de l’hôte. Il s’agit principalement d’une primitive de reconnaissance, mais cela confirme que le container peut lire des informations liées au kernel qui sont normalement masquées.
- `/proc/keys` est beaucoup plus sensible. Selon la configuration de l’hôte, il peut révéler des entrées de keyring, des descriptions de clés et les relations entre les services de l’hôte utilisant le subsystem de keyring du kernel.
- `/sys/firmware` aide à identifier le mode de boot, les interfaces firmware et les détails de la plateforme, utiles pour le fingerprinting de l’hôte et pour déterminer si le workload voit un état au niveau de l’hôte.
- `/proc/config.gz` peut révéler la configuration du kernel en cours d’exécution, ce qui est utile pour faire correspondre les prérequis d’un exploit public du kernel ou comprendre pourquoi une fonctionnalité spécifique est accessible.
- `/proc/sched_debug` expose l’état du scheduler et contredit souvent l’idée intuitive selon laquelle le PID namespace devrait masquer complètement les informations relatives aux autres processus.

Les résultats intéressants comprennent la lecture directe de ces fichiers, les preuves que les données appartiennent à l’hôte plutôt qu’à une vue limitée du container, ou l’accès à d’autres emplacements procfs/sysfs généralement masqués par défaut.

## Vérifications

L’objectif de ces vérifications est de déterminer quels chemins le runtime a intentionnellement masqués et si le workload actuel voit toujours un filesystem réduit exposé au kernel.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Ce qui est intéressant ici :

- Une longue liste de chemins masqués est normale dans les runtimes renforcés.
- L'absence de masquage sur des entrées procfs sensibles mérite une inspection plus approfondie.
- Si un chemin sensible est accessible et que le container dispose également de capabilities importantes ou de mounts étendus, l'exposition est plus significative.

## Valeurs par défaut des runtimes

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste de chemins masqués par défaut | exposition des mounts proc/sys de l'hôte, `--privileged` |
| Podman | Activé par défaut | Podman applique les chemins masqués par défaut, sauf s'ils sont unmasked manuellement | `--security-opt unmask=ALL`, unmasking ciblé, `--privileged` |
| Kubernetes | Hérite des valeurs par défaut du runtime | Utilise le comportement de masquage du runtime sous-jacent, sauf si les paramètres Pod affaiblissent l'exposition de proc | `procMount: Unmasked`, patterns de workloads privilégiés, mounts étendus de l'hôte |
| containerd / CRI-O sous Kubernetes | Valeur par défaut du runtime | Applique généralement les chemins masqués OCI/runtime, sauf en cas de surcharge | modifications directes de la configuration du runtime, mêmes voies d'affaiblissement Kubernetes |

Les chemins masqués sont généralement présents par défaut. Le principal problème opérationnel n'est pas leur absence du runtime, mais leur unmasking délibéré ou les host bind mounts qui neutralisent la protection.
{{#include ../../../../banners/hacktricks-training.md}}
