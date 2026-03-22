# Chemins masqués

{{#include ../../../../banners/hacktricks-training.md}}

Les chemins masqués sont des protections d'exécution qui cachent des emplacements particulièrement sensibles côté kernel dans le système de fichiers au container en les bind-mountant par-dessus ou en les rendant autrement inaccessibles. Le but est d'empêcher une charge de travail d'interagir directement avec des interfaces dont les applications ordinaires n'ont pas besoin, surtout à l'intérieur de procfs.

Cela importe parce que de nombreux container escapes et techniques affectant l'hôte commencent par lire ou écrire des fichiers spéciaux sous `/proc` ou `/sys`. Si ces emplacements sont masqués, l'attaquant perd l'accès direct à une partie utile de la surface de contrôle du noyau même après avoir obtenu l'exécution de code à l'intérieur du container.

## Fonctionnement

Les runtimes masquent couramment des chemins sélectionnés tels que:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La liste exacte dépend du runtime et de la configuration de l'hôte. La propriété importante est que le chemin devienne inaccessible ou remplacé du point de vue du container même s'il existe toujours sur l'hôte.

## Laboratoire

Inspectez la configuration masked-path exposée par Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspecter le comportement réel des montages à l'intérieur du workload :
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impact sur la sécurité

Le masquage ne constitue pas la principale limite d'isolation, mais il supprime plusieurs cibles de post-exploitation à haute valeur. Sans masquage, un conteneur compromis peut être capable d'inspecter l'état du noyau, lire des informations sensibles sur les processus ou des données de clés, ou interagir avec des objets procfs/sysfs qui n'auraient jamais dû être visibles par l'application.

## Mauvaises configurations

La principale erreur consiste à désactiver le masquage sur de larges classes de chemins par commodité ou pour le débogage. Dans Podman, cela peut apparaître sous la forme `--security-opt unmask=ALL` ou un désmasquage ciblé. Dans Kubernetes, une exposition excessive de proc peut apparaître via `procMount: Unmasked`. Un autre problème sérieux est d'exposer le `/proc` ou `/sys` de l'hôte via un bind mount, ce qui contourne complètement l'idée d'une vue réduite du conteneur.

## Abus

Si le masquage est faible ou absent, commencez par identifier quels chemins sensibles procfs/sysfs sont directement accessibles :
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Si un chemin soi-disant masqué est accessible, inspectez-le attentivement :
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` peut exposer les données de timer et de scheduler de l'hôte. C'est surtout une primitive de reconnaissance, mais cela confirme que le container peut lire des informations kernel-facing qui sont normalement cachées.
- `/proc/keys` est beaucoup plus sensible. Selon la configuration de l'hôte, il peut révéler des entrées de keyring, des descriptions de clés et des relations entre les services de l'hôte utilisant le sous-système kernel keyring.
- `/sys/firmware` aide à identifier le mode de boot, les interfaces du firmware et les détails de la plateforme utiles pour le host fingerprinting et pour comprendre si la workload voit l'état au niveau host.
- `/proc/config.gz` peut révéler la configuration du kernel en cours d'exécution, ce qui est précieux pour faire correspondre les prérequis d'exploits publics du kernel ou pour comprendre pourquoi une fonctionnalité spécifique est accessible.
- `/proc/sched_debug` expose l'état du scheduler et contourne souvent l'attente intuitive selon laquelle le PID namespace devrait cacher complètement les informations de processus non liées.

Des résultats intéressants incluent la lecture directe de ces fichiers, des preuves que les données appartiennent à l'hôte plutôt qu'à une vue contrainte du container, ou l'accès à d'autres emplacements procfs/sysfs souvent masqués par défaut.

## Checks

Le but de ces vérifications est de déterminer quels chemins le runtime a intentionnellement cachés et si la workload actuelle voit toujours un système de fichiers orienté kernel réduit.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Ce qui est intéressant ici :

- Une longue masked-path list est normale dans les runtimes renforcés.
- L'absence de masking sur des entrées procfs sensibles mérite une inspection plus approfondie.
- Si un chemin sensible est accessible et que le container dispose également de fortes capabilities ou de montages larges, l'exposition est d'autant plus importante.

## Runtime Defaults

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste de masked paths par défaut | exposition des montages host proc/sys, `--privileged` |
| Podman | Activé par défaut | Podman applique des masked paths par défaut sauf si démasqué manuellement | `--security-opt unmask=ALL`, unmasking ciblé, `--privileged` |
| Kubernetes | Hérite des defaults du runtime | Utilise le comportement de masking du runtime sous-jacent sauf si les paramètres du Pod affaiblissent l'exposition de proc | `procMount: Unmasked`, schémas de workloads privilégiés, montages larges depuis l'hôte |
| containerd / CRI-O under Kubernetes | Par défaut du runtime | Applique généralement les masked paths OCI/runtime sauf override | modifications directes de la config du runtime, mêmes voies d'affaiblissement via Kubernetes |

Les masked paths sont généralement présents par défaut. Le principal problème opérationnel n'est pas leur absence dans le runtime, mais le unmasking délibéré ou les host bind mounts qui annulent la protection.
{{#include ../../../../banners/hacktricks-training.md}}
