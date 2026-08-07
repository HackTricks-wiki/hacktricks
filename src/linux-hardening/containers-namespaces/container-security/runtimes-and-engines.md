# Runtimes de conteneurs, moteurs, outils de build et sandboxes

{{#include ../../../banners/hacktricks-training.md}}

L’une des principales sources de confusion en matière de container security vient du fait que plusieurs composants complètement différents sont souvent désignés par le même terme. « Docker » peut faire référence à un format d’image, une CLI, un daemon, un système de build, une stack de runtime ou simplement au concept général de conteneurs. Pour les travaux de sécurité, cette ambiguïté pose problème, car différentes couches sont responsables de différentes protections. Un breakout causé par un mauvais bind mount n’est pas la même chose qu’un breakout causé par une vulnérabilité du runtime bas niveau, et aucun des deux ne correspond à une erreur de policy au niveau du cluster dans Kubernetes.

Cette page sépare l’écosystème par rôle afin que le reste de la section puisse identifier précisément où se trouve réellement une protection ou une faiblesse.

## OCI comme langage commun

Les stacks modernes de conteneurs Linux interopèrent souvent parce qu’elles utilisent un ensemble de spécifications OCI. L’**OCI Image Specification** décrit la représentation des images et des layers. L’**OCI Runtime Specification** décrit la manière dont le runtime doit lancer le processus, notamment les namespaces, les mounts, les cgroups et les security settings. L’**OCI Distribution Specification** standardise la manière dont les registries exposent leur contenu.

Cela explique pourquoi une container image construite avec un outil peut souvent être exécutée avec un autre, et pourquoi plusieurs engines peuvent partager le même runtime bas niveau. Cela explique également pourquoi le comportement de sécurité peut sembler similaire entre différents produits : beaucoup d’entre eux construisent la même configuration de runtime OCI et la transmettent au même petit ensemble de runtimes.

## Runtimes OCI bas niveau

Le runtime bas niveau est le composant le plus proche de la limite avec le kernel. C’est lui qui crée réellement les namespaces, écrit les paramètres des cgroups, applique les capabilities et les filtres seccomp, puis exécute finalement `execve()` sur le processus du conteneur. Lorsque l’on parle d’« isolation des conteneurs » au niveau mécanique, c’est généralement cette couche qui est visée, même si cela n’est pas précisé explicitement.

### `runc`

`runc` est le runtime OCI de référence et reste l’implémentation la plus connue. Il est largement utilisé par Docker, containerd et de nombreux déploiements Kubernetes. Une grande partie des travaux de recherche publics et du matériel d’exploitation cible les environnements de type `runc`, simplement parce qu’ils sont courants et que `runc` définit la base que beaucoup de personnes imaginent lorsqu’elles pensent à un conteneur Linux. Comprendre `runc` fournit donc un modèle mental solide de l’isolation classique des conteneurs.

### `crun`

`crun` est un autre runtime OCI, écrit en C et largement utilisé dans les environnements Podman modernes. Il est souvent apprécié pour son bon support de cgroup v2, sa bonne ergonomie rootless et sa faible surcharge. Du point de vue de la sécurité, l’important n’est pas qu’il soit écrit dans un autre langage, mais qu’il joue le même rôle : c’est le composant qui transforme la configuration OCI en un arbre de processus en cours d’exécution sous le kernel. Un workflow Podman rootless paraît souvent plus sûr, non pas parce que `crun` corrige tout comme par magie, mais parce que la stack globale qui l’entoure s’appuie généralement davantage sur les user namespaces et le least privilege.

### `runsc` de gVisor

`runsc` est le runtime utilisé par gVisor. Ici, la limite prend une autre signification importante. Au lieu de transmettre la plupart des syscalls directement au kernel de l’hôte comme d’habitude, gVisor insère une couche de kernel en userspace qui émule ou médiatise une grande partie de l’interface Linux. Le résultat n’est pas un conteneur `runc` classique avec quelques flags supplémentaires ; il s’agit d’un design de sandbox différent, dont l’objectif est de réduire la attack surface du kernel hôte. Les compromis de compatibilité et de performance font partie de ce design. Les environnements utilisant `runsc` doivent donc être documentés différemment des environnements utilisant un runtime OCI classique.

### `kata-runtime`

Kata Containers repoussent davantage la limite en lançant le workload dans une lightweight virtual machine. D’un point de vue administratif, cela peut toujours ressembler à un déploiement de conteneurs, et les couches d’orchestration peuvent toujours le traiter comme tel, mais la limite d’isolation sous-jacente est plus proche de la virtualisation que d’un conteneur classique partageant le kernel de l’hôte. Cela rend Kata utile lorsqu’une isolation plus forte entre tenants est souhaitée sans abandonner les workflows centrés sur les conteneurs.

## Engines et container managers

Si le runtime bas niveau est le composant qui communique directement avec le kernel, l’engine ou le manager est celui avec lequel les utilisateurs et les opérateurs interagissent généralement. Il gère les pulls d’images, les métadonnées, les logs, les réseaux, les volumes, les opérations de lifecycle et l’exposition des APIs. Cette couche est extrêmement importante, car de nombreux compromissions réelles se produisent ici : un accès à un runtime socket ou à une API de daemon peut équivaloir à une compromission de l’hôte, même si le runtime bas niveau lui-même fonctionne parfaitement.

### Docker Engine

Docker Engine est la container platform la plus connue des développeurs et l’une des raisons pour lesquelles le vocabulaire des conteneurs est devenu si fortement associé à Docker. Le chemin typique va de la CLI `docker` à `dockerd`, qui coordonne à son tour des composants bas niveau tels que `containerd` et un runtime OCI. Historiquement, les déploiements Docker ont souvent été **rootful**, et l’accès au Docker socket constitue donc un primitive très puissant. C’est pourquoi une grande partie du matériel pratique sur la privilege escalation se concentre sur `docker.sock` : si un processus peut demander à `dockerd` de créer un conteneur privilégié, de monter des chemins de l’hôte ou de rejoindre les namespaces de l’hôte, il n’a peut-être pas besoin d’un kernel exploit.

### Podman

Podman a été conçu autour d’un modèle davantage daemonless. Sur le plan opérationnel, cela renforce l’idée que les conteneurs sont simplement des processus gérés au moyen des mécanismes Linux standards, plutôt que par un daemon privilégié et persistant. Podman possède également une histoire **rootless** beaucoup plus solide que les déploiements Docker classiques auxquels de nombreuses personnes ont été initialement formées. Cela ne rend pas Podman automatiquement sûr, mais modifie considérablement le risk profile par défaut, en particulier lorsqu’il est combiné aux user namespaces, à SELinux et à `crun`.

### containerd

containerd est un composant essentiel de gestion du runtime dans de nombreuses stacks modernes. Il est utilisé sous Docker et constitue également l’un des backends de runtime Kubernetes dominants. Il expose de puissantes APIs, gère les images et les snapshots, puis délègue la création finale du processus à un runtime bas niveau. Les discussions de sécurité autour de containerd doivent souligner qu’un accès au socket containerd ou aux fonctionnalités de `ctr`/`nerdctl` peut être tout aussi dangereux qu’un accès à l’API Docker, même si l’interface et le workflow semblent moins « developer friendly ».

### CRI-O

CRI-O est plus spécialisé que Docker Engine. Au lieu d’être une plateforme généraliste destinée aux développeurs, il est conçu pour implémenter proprement le Kubernetes Container Runtime Interface. Il est donc particulièrement courant dans les distributions Kubernetes et les écosystèmes fortement basés sur SELinux, tels qu’OpenShift. Du point de vue de la sécurité, ce périmètre plus étroit est utile, car il réduit la complexité conceptuelle : CRI-O appartient clairement à la couche « exécuter des conteneurs pour Kubernetes », plutôt qu’à une plateforme universelle.

### Incus, LXD et LXC

Les systèmes Incus/LXD/LXC doivent être distingués des application containers de type Docker, car ils sont souvent utilisés comme des **system containers**. Un system container est généralement censé ressembler davantage à une machine légère, avec un userspace plus complet, des services persistants, une exposition plus riche des devices et une intégration plus étendue avec l’hôte. Les mécanismes d’isolation restent des primitives du kernel, mais les attentes opérationnelles sont différentes. Par conséquent, les misconfigurations observées ici ressemblent souvent moins à de « mauvais defaults d’application container » qu’à des erreurs de lightweight virtualization ou de délégation à l’hôte.

### systemd-nspawn

systemd-nspawn occupe une place intéressante, car il est natif de systemd et très utile pour les tests, le debugging et l’exécution d’environnements similaires à des OS. Ce n’est pas le runtime cloud-native de production dominant, mais il apparaît suffisamment souvent dans les labs et les environnements orientés distributions pour mériter d’être mentionné. Pour l’analyse de sécurité, il rappelle une fois de plus que le concept de « conteneur » couvre plusieurs écosystèmes et styles opérationnels.

### Apptainer / Singularity

Apptainer (anciennement Singularity) est courant dans les environnements de recherche et de HPC. Ses assumptions de confiance, son workflow utilisateur et son modèle d’exécution diffèrent de manière importante des stacks centrées sur Docker/Kubernetes. Ces environnements accordent notamment souvent beaucoup d’importance à la possibilité pour les utilisateurs d’exécuter des workloads packagés sans leur accorder de larges privilèges de gestion de conteneurs. Si un reviewer suppose que chaque environnement de conteneurs est essentiellement « Docker sur un serveur », il comprendra très mal ces déploiements.

## Outils de build

De nombreuses discussions de sécurité ne parlent que du runtime, mais les outils utilisés au moment du build sont également importants, car ils déterminent le contenu des images, l’exposition des build secrets et la quantité de contexte de confiance intégrée à l’artifact final.

**BuildKit** et `docker buildx` sont des backends de build modernes qui prennent en charge des fonctionnalités telles que le caching, le secret mounting, le SSH forwarding et les builds multi-plateformes. Ces fonctionnalités sont utiles, mais du point de vue de la sécurité, elles créent également des endroits où des secrets peuvent leak dans des image layers ou où un build context trop large peut exposer des fichiers qui n’auraient jamais dû être inclus. **Buildah** joue un rôle similaire dans les écosystèmes natifs OCI, notamment autour de Podman, tandis que **Kaniko** est souvent utilisé dans les environnements CI qui ne souhaitent pas accorder de Docker daemon privilégié au build pipeline.

La leçon essentielle est que la création et l’exécution d’une image sont deux phases différentes, mais qu’un build pipeline faible peut créer une posture runtime faible bien avant le lancement du conteneur.

## L’orchestration est une autre couche, pas le runtime

Kubernetes ne doit pas être mentalement assimilé au runtime lui-même. Kubernetes est l’orchestrator. Il planifie les Pods, stocke l’état souhaité et exprime la security policy via la configuration des workloads. Le kubelet communique ensuite avec une implémentation CRI telle que containerd ou CRI-O, qui invoque à son tour un runtime bas niveau tel que `runc`, `crun`, `runsc` ou `kata-runtime`.

Cette séparation est importante, car beaucoup de personnes attribuent à tort une protection à « Kubernetes » alors qu’elle est réellement appliquée par le runtime du node, ou accusent les « defaults de containerd » pour un comportement provenant en réalité d’un Pod spec. En pratique, la posture de sécurité finale est une composition : l’orchestrator demande quelque chose, la runtime stack le traduit, puis le kernel l’applique finalement.

## Pourquoi l’identification du runtime est importante pendant l’assessment

Si vous identifiez rapidement l’engine et le runtime, de nombreuses observations ultérieures deviennent plus faciles à interpréter. Un conteneur Podman rootless indique que les user namespaces jouent probablement un rôle. Un Docker socket monté dans un workload suggère qu’une privilege escalation pilotée par API constitue un chemin réaliste. Un node CRI-O/OpenShift doit immédiatement faire penser aux labels SELinux et à la restricted workload policy. Un environnement gVisor ou Kata doit inciter à la prudence avant de supposer qu’un breakout PoC classique pour `runc` se comportera de la même manière.

C’est pourquoi l’une des premières étapes d’un container assessment doit toujours être de répondre à deux questions simples : **quel composant gère le conteneur** et **quel runtime a réellement lancé le processus**. Une fois ces réponses obtenues, le reste de l’environnement devient généralement beaucoup plus facile à analyser.

## Vulnérabilités du runtime

Tous les container escapes ne proviennent pas d’une misconfiguration de l’opérateur. Parfois, le runtime lui-même est le composant vulnérable. Cela est important, car un workload peut fonctionner avec une configuration apparemment prudente tout en restant exposé à une faille du runtime bas niveau.

L’exemple classique est **CVE-2019-5736** dans `runc`, où un conteneur malveillant pouvait écraser le binaire `runc` de l’hôte, puis attendre qu’une invocation ultérieure de `docker exec` ou d’un runtime similaire déclenche du code contrôlé par l’attaquant. Le chemin d’exploitation est très différent d’une simple erreur de bind mount ou de capabilities, car il abuse de la manière dont le runtime réintègre l’espace des processus du conteneur pendant la gestion de l’exec.<sup>[[1]](#references)</sup>

Un workflow de reproduction minimal du point de vue d’une red team consiste à :
```bash
go build main.go
./main
```
Ensuite, depuis l’hôte :
```bash
docker exec -it <container-name> /bin/sh
```
La leçon essentielle ne concerne pas l’implémentation exacte de l’exploit historique, mais son implication en matière d’évaluation : si la version du runtime est vulnérable, une simple exécution de code dans le conteneur peut suffire à compromettre l’hôte, même lorsque la configuration visible du conteneur ne semble pas manifestement faible.

Les CVE récentes affectant les runtimes, telles que `CVE-2024-21626` dans `runc`, les race conditions de montage de BuildKit et les bugs d’analyse de containerd, renforcent le même point. La version du runtime et son niveau de correctifs font partie de la frontière de sécurité, et ne sont pas de simples détails de maintenance.

## Références

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
