# Chemins masqués

{{#include ../../../../banners/hacktricks-training.md}}

Les chemins masqués sont des protections runtime qui cachent, depuis le container, des emplacements du système de fichiers particulièrement sensibles exposés au kernel en les recouvrant via des bind-mounting ou en les rendant inaccessibles par d'autres moyens. Le but est d'empêcher une workload d'interagir directement avec des interfaces dont les applications ordinaires n'ont pas besoin, en particulier dans procfs.

C'est important car de nombreux container escapes et techniques ayant un impact sur l'hôte commencent par lire ou écrire des fichiers spéciaux sous `/proc` ou `/sys`. Si ces emplacements sont masqués, l'attaquant perd l'accès direct à une partie utile de la surface de contrôle du kernel même après avoir obtenu une code execution à l'intérieur du container.

## Fonctionnement

Les runtimes masquent couramment certains chemins tels que :

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

La liste exacte dépend du runtime et de la configuration de l'hôte. La propriété importante est que le chemin devient inaccessible ou remplacé du point de vue du container même s'il existe toujours sur l'hôte.

## Laboratoire

Inspectez la configuration masked-path exposée par Docker:
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```
Inspectez le comportement réel des montages à l'intérieur du workload :
```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```
## Impact sur la sécurité

Le masquage ne crée pas la frontière d'isolation principale, mais il supprime plusieurs cibles post-exploitation de grande valeur. Sans masquage, un container compromis peut être capable d'inspecter l'état du kernel, lire des informations sensibles sur les processus ou les clés, ou interagir avec des objets procfs/sysfs qui n'auraient jamais dû être visibles par l'application.

## Mauvaises configurations

L'erreur principale est de démasquer de larges catégories de chemins par commodité ou pour le débogage. Dans Podman cela peut apparaître comme `--security-opt unmask=ALL` ou un démasquage ciblé. Dans Kubernetes, une exposition trop large du proc peut se manifester via `procMount: Unmasked`. Un autre problème sérieux est d'exposer le `/proc` ou `/sys` de l'hôte via un bind mount, ce qui contourne complètement l'idée d'une vue réduite du container.

## Abus

Si le masquage est faible ou absent, commencez par identifier quels chemins sensibles procfs/sysfs sont directement accessibles :
```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```
Si un chemin supposément masqué est accessible, inspectez-le soigneusement :
```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```
What these commands can reveal:

- `/proc/timer_list` peut exposer les données de timers et du scheduler de l'hôte. Il s'agit surtout d'un primitif de reconnaissance, mais cela confirme que le conteneur peut lire des informations orientées noyau qui sont normalement cachées.
- `/proc/keys` est beaucoup plus sensible. Selon la configuration de l'hôte, il peut révéler des entrées de keyring, des descriptions de clés et des relations entre les services de l'hôte utilisant le sous-système kernel keyring.
- `/sys/firmware` aide à identifier le mode de démarrage, les interfaces firmware et les détails de la plateforme utiles pour le fingerprinting de l'hôte et pour comprendre si la charge de travail voit l'état au niveau de l'hôte.
- `/proc/config.gz` peut révéler la configuration du noyau en cours d'exécution, ce qui est précieux pour faire correspondre les prérequis d'exploits publics ciblant le noyau ou comprendre pourquoi une fonctionnalité spécifique est accessible.
- `/proc/sched_debug` expose l'état du scheduler et contourne souvent l'attente intuitive selon laquelle le PID namespace devrait masquer complètement les informations de processus non liées.

Les résultats intéressants incluent des lectures directes de ces fichiers, des preuves que les données appartiennent à l'hôte plutôt qu'à une vue de conteneur restreinte, ou l'accès à d'autres emplacements procfs/sysfs qui sont couramment masqués par défaut.

## Checks

Le but de ces vérifications est de déterminer quels chemins le runtime a intentionnellement masqués et si la charge de travail actuelle voit toujours un système de fichiers orienté noyau réduit.
```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```
Ce qui est intéressant ici :

- Une longue liste de chemins masqués est normale dans les runtimes durcis.
- L'absence de masquage sur des entrées procfs sensibles mérite une inspection approfondie.
- Si un chemin sensible est accessible et que le container dispose en plus de capabilities élevées ou de montages larges, l'exposition a plus d'importance.

## Paramètres par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Activé par défaut | Docker définit une liste par défaut de chemins masqués | exposition des montages proc/sys de l'hôte, `--privileged` |
| Podman | Activé par défaut | Podman applique des chemins masqués par défaut sauf s'ils sont démasqués manuellement | `--security-opt unmask=ALL`, démasquage ciblé, `--privileged` |
| Kubernetes | Hérite des paramètres par défaut du runtime | Utilise le comportement de masquage du runtime sous-jacent sauf si les paramètres du Pod affaiblissent l'exposition de proc | `procMount: Unmasked`, modèles de charges de travail privilégiées, montages étendus de l'hôte |
| containerd / CRI-O under Kubernetes | Par défaut du runtime | Applique généralement les chemins masqués OCI/runtime sauf si remplacés | modifications directes de la config du runtime, mêmes mécanismes d'affaiblissement que Kubernetes |

Les chemins masqués sont généralement présents par défaut. Le principal problème opérationnel n'est pas leur absence du runtime, mais le démasquage délibéré ou les montages bind de l'hôte qui annulent la protection.
