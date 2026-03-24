# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths sont des protections au niveau du runtime qui masquent des emplacements du système de fichiers particulièrement sensibles côté kernel depuis le container en les recouvrant via bind-mounting ou en les rendant autrement inaccessibles. L'objectif est d'empêcher une workload d'interagir directement avec des interfaces dont les applications ordinaires n'ont pas besoin, en particulier à l'intérieur de procfs.

## Fonctionnement

Les runtimes masquent couramment certains chemins tels que :

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La liste exacte dépend du runtime et de la configuration de l'hôte. L'important est que le chemin devienne inaccessible ou remplacé du point de vue du container, même s'il existe toujours sur l'hôte.

## Lab

Inspectez la configuration masked-path exposée par Docker :
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspecter le comportement réel des montages à l'intérieur de la charge de travail :
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impact sur la sécurité

Le masquage ne crée pas la principale frontière d'isolation, mais il supprime plusieurs cibles post-exploitation de grande valeur. Sans masquage, un conteneur compromis peut être capable d'inspecter l'état du noyau, lire des informations sensibles sur des processus ou des clés, ou interagir avec des objets procfs/sysfs qui n'auraient jamais dû être visibles par l'application.

## Mauvaises configurations

La principale erreur est de désmasquer de larges classes de chemins par commodité ou pour le débogage. Dans Podman cela peut apparaître comme `--security-opt unmask=ALL` ou un désmasquage ciblé. Dans Kubernetes, une exposition trop large de proc peut apparaître via `procMount: Unmasked`. Un autre problème sérieux est d'exposer le `/proc` ou `/sys` de l'hôte via un bind mount, ce qui contourne entièrement l'idée d'une vue réduite du conteneur.

## Abus

Si le masquage est faible ou absent, commencez par identifier quels chemins sensibles procfs/sysfs sont directement accessibles :
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Si un chemin supposément masqué est accessible, inspectez-le attentivement :
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
Ce que ces commandes peuvent révéler :

- `/proc/timer_list` peut exposer les données de timer et de scheduler de l'hôte. C'est surtout un primitive de reconnaissance, mais cela confirme que le container peut lire des informations kernel-facing qui sont normalement cachées.
- `/proc/keys` est bien plus sensible. Selon la configuration de l'hôte, il peut révéler des entrées keyring, des descriptions de clés et des relations entre des services de l'hôte utilisant le kernel keyring subsystem.
- `/sys/firmware` aide à identifier le boot mode, les interfaces firmware et les détails de la plateforme utiles pour le host fingerprinting et pour comprendre si le workload voit un état au niveau hôte.
- `/proc/config.gz` peut révéler la configuration du kernel en cours d'exécution, ce qui est précieux pour faire correspondre des prérequis d'exploits kernel publics ou comprendre pourquoi une fonctionnalité spécifique est reachable.
- `/proc/sched_debug` expose l'état du scheduler et contourne souvent l'attente intuitive selon laquelle le PID namespace devrait complètement masquer les informations de processus non liées.

Les résultats intéressants incluent des lectures directes de ces fichiers, des preuves que les données appartiennent à l'hôte plutôt qu'à une vue container restreinte, ou l'accès à d'autres emplacements procfs/sysfs qui sont couramment masqués par défaut.

## Checks

Le but de ces vérifications est de déterminer quels chemins le runtime a intentionnellement cachés et si le workload actuel voit toujours un reduced kernel-facing filesystem.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Ce qui est intéressant ici :

- Une longue liste de chemins masqués est normale dans les runtimes renforcés.
- L'absence de masquage sur des entrées procfs sensibles mérite une inspection plus approfondie.
- Si un chemin sensible est accessible et que le conteneur dispose en outre de capacités élevées ou de montages hôtes étendus, l'exposition est d'autant plus critique.

## Paramètres d'exécution par défaut

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste par défaut de chemins masqués | exposition des montages proc/sys de l'hôte, `--privileged` |
| Podman | Activé par défaut | Podman applique des chemins masqués par défaut sauf si démasqués manuellement | `--security-opt unmask=ALL`, démasquage ciblé, `--privileged` |
| Kubernetes | Hérite des paramètres du runtime | Utilise le comportement de masquage du runtime sous-jacent sauf si les paramètres du Pod affaiblissent l'exposition de proc | `procMount: Unmasked`, modèles de workloads privilégiés, montages hôtes étendus |
| containerd / CRI-O under Kubernetes | Par défaut du runtime | Applique généralement les chemins masqués OCI/runtime sauf s'ils sont remplacés | modifications directes de la config du runtime, mêmes voies d'affaiblissement via Kubernetes |

Les chemins masqués sont généralement présents par défaut. Le principal problème opérationnel n'est pas leur absence du runtime, mais le démasquage délibéré ou les montages bind de l'hôte qui annulent la protection.
{{#include ../../../../banners/hacktricks-training.md}}
