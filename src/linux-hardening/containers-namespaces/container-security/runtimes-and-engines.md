# Runtimes, Engines, Builders Et Sandboxes De Conteneurs

{{#include ../../../banners/hacktricks-training.md}}

L’une des principales sources de confusion en container security vient du fait que plusieurs composants complètement différents sont souvent regroupés sous le même mot. « Docker » peut désigner un format d’image, une CLI, un daemon, un système de build, une stack de runtime ou simplement l’idée générale des conteneurs. Pour les travaux de sécurité, cette ambiguïté pose problème, car différentes couches sont responsables de différentes protections. Un breakout causé par un mauvais bind mount n’est pas la même chose qu’un breakout causé par une vulnérabilité du runtime bas niveau, et aucun des deux ne correspond à une erreur de policy de cluster dans Kubernetes.

Cette page sépare l’écosystème par rôle afin que le reste de la section puisse indiquer précisément où se trouve réellement une protection ou une faiblesse.

## OCI Comme Langage Commun

Les stacks de conteneurs Linux modernes interopèrent souvent parce qu’elles utilisent un ensemble de spécifications OCI. L’**OCI Image Specification** décrit la représentation des images et des layers. L’**OCI Runtime Specification** décrit la manière dont le runtime doit lancer le process, notamment les namespaces, les mounts, les cgroups et les paramètres de sécurité. L’**OCI Distribution Specification** standardise la manière dont les registries exposent leur contenu.

Cela explique pourquoi une container image construite avec un outil peut souvent être exécutée avec un autre, et pourquoi plusieurs engines peuvent partager le même runtime bas niveau. Cela explique également pourquoi le comportement de sécurité peut sembler similaire entre différents produits : beaucoup d’entre eux construisent la même configuration de runtime OCI et la transmettent au même petit ensemble de runtimes.

## Runtimes OCI Bas Niveau

Le runtime bas niveau est le composant le plus proche de la limite avec le kernel. C’est lui qui crée réellement les namespaces, écrit les paramètres des cgroups, applique les capabilities et les filtres seccomp, puis exécute finalement `execve()` pour lancer le process du conteneur. Lorsque l’on parle d’« isolation des conteneurs » au niveau mécanique, c’est généralement cette couche qui est visée, même si cela n’est pas précisé explicitement.

### `runc`

`runc` est le runtime OCI de référence et reste l’implémentation la plus connue. Il est largement utilisé avec Docker, containerd et de nombreux déploiements Kubernetes. Une grande partie des recherches publiques et du matériel d’exploitation cible les environnements de type `runc`, simplement parce qu’ils sont courants et que `runc` définit la base que beaucoup de personnes associent à un conteneur Linux. Comprendre `runc` fournit donc au lecteur un modèle mental solide de l’isolation classique des conteneurs.

### `crun`

`crun` est un autre runtime OCI, écrit en C et largement utilisé dans les environnements Podman modernes. Il est souvent apprécié pour son bon support de cgroup v2, sa bonne ergonomie rootless et sa faible overhead. Du point de vue de la sécurité, l’important n’est pas qu’il soit écrit dans un langage différent, mais qu’il joue toujours le même rôle : c’est le composant qui transforme la configuration OCI en un process tree en fonctionnement sous le kernel. Un workflow Podman rootless donne souvent une impression de meilleure sécurité, non pas parce que `crun` corrige magiquement tous les problèmes, mais parce que la stack qui l’entoure s’appuie généralement davantage sur les user namespaces et le least privilege.

### `runsc` De gVisor

`runsc` est le runtime utilisé par gVisor. La limite d’isolation change ici de manière significative. Au lieu de transmettre la plupart des syscalls directement au kernel host de la manière habituelle, gVisor insère une couche de kernel en userspace qui émule ou contrôle de grandes parties de l’interface Linux. Le résultat n’est pas un conteneur `runc` normal avec quelques flags supplémentaires ; il s’agit d’un design de sandbox différent, dont l’objectif est de réduire la surface d’attaque du kernel host. Les compromis en matière de compatibilité et de performances font partie de ce design ; les environnements utilisant `runsc` doivent donc être documentés différemment des environnements utilisant un runtime OCI classique.

### `kata-runtime`

Kata Containers repousse davantage la limite en lançant la workload dans une lightweight virtual machine. Sur le plan administratif, cela peut toujours ressembler à un déploiement de conteneurs, et les couches d’orchestration peuvent toujours le traiter comme tel, mais la limite d’isolation sous-jacente est plus proche de la virtualisation que d’un conteneur classique partageant le kernel host. Cela rend Kata utile lorsqu’une isolation plus forte entre tenants est souhaitée sans abandonner les workflows centrés sur les conteneurs.

## Engines Et Container Managers

Si le runtime bas niveau est le composant qui communique directement avec le kernel, l’engine ou le manager est le composant avec lequel les utilisateurs et les opérateurs interagissent généralement. Il gère les pulls d’images, les métadonnées, les logs, les networks, les volumes, les opérations de lifecycle et l’exposition des APIs. Cette couche est extrêmement importante, car de nombreux compromissions réelles se produisent à ce niveau : l’accès à un runtime socket ou à l’API d’un daemon peut équivaloir à une compromission du host, même si le runtime bas niveau lui-même fonctionne parfaitement.

### Docker Engine

Docker Engine est la container platform la plus reconnaissable pour les développeurs et l’une des raisons pour lesquelles le vocabulaire des conteneurs est devenu aussi fortement associé à Docker. Le chemin typique va de la CLI `docker` à `dockerd`, qui coordonne ensuite des composants bas niveau tels que `containerd` et un runtime OCI. Historiquement, les déploiements Docker ont souvent été **rootful**, et l’accès au Docker socket constitue donc un primitive extrêmement puissant. C’est pourquoi une grande partie du matériel pratique sur la privilege escalation se concentre sur `docker.sock` : si un process peut demander à `dockerd` de créer un conteneur privileged, de monter des chemins du host ou de rejoindre les host namespaces, il peut ne pas avoir besoin d’un kernel exploit.

### Podman

Podman a été conçu autour d’un modèle davantage daemonless. Sur le plan opérationnel, cela renforce l’idée que les conteneurs ne sont que des process gérés via les mécanismes Linux standard, plutôt que par un daemon privilégié de longue durée. Podman possède également une approche **rootless** bien plus avancée que les déploiements Docker classiques avec lesquels de nombreuses personnes ont commencé. Cela ne rend pas Podman automatiquement sûr, mais modifie considérablement le profil de risque par défaut, en particulier lorsqu’il est combiné aux user namespaces, à SELinux et à `crun`.

### containerd

containerd est un composant central de gestion du runtime dans de nombreuses stacks modernes. Il est utilisé sous Docker et constitue également l’un des backends de runtime Kubernetes dominants. Il expose des APIs puissantes, gère les images et les snapshots, puis délègue la création finale du process à un runtime bas niveau. Les discussions de sécurité autour de containerd doivent souligner que l’accès au socket containerd ou aux fonctionnalités de `ctr`/`nerdctl` peut être tout aussi dangereux que l’accès à l’API de Docker, même si l’interface et le workflow semblent moins « developer friendly ».

### CRI-O

CRI-O est plus spécialisé que Docker Engine. Au lieu d’être une plateforme générale pour développeurs, il est conçu pour implémenter proprement la Kubernetes Container Runtime Interface. Il est donc particulièrement courant dans les distributions Kubernetes et les écosystèmes fortement basés sur SELinux, tels qu’OpenShift. Du point de vue de la sécurité, ce périmètre plus étroit est utile, car il réduit la complexité conceptuelle : CRI-O appartient clairement à la couche « exécuter des conteneurs pour Kubernetes », plutôt qu’à une plateforme polyvalente.

### Incus, LXD Et LXC

Les systèmes Incus/LXD/LXC doivent être séparés des application containers de type Docker, car ils sont souvent utilisés comme **system containers**. Un system container est généralement censé ressembler davantage à une machine légère, avec un userspace plus complet, des services persistants, une exposition plus riche des devices et une intégration plus poussée avec le host. Les mécanismes d’isolation restent des primitives du kernel, mais les attentes opérationnelles sont différentes. Par conséquent, les mauvaises configurations prennent souvent moins la forme de « mauvais defaults d’un app container » que d’erreurs de lightweight virtualization ou de délégation au host.

### systemd-nspawn

systemd-nspawn occupe une place intéressante, car il est natif de systemd et très utile pour les tests, le debugging et l’exécution d’environnements ressemblant à des OS. Ce n’est pas le runtime cloud-native de production dominant, mais il apparaît suffisamment souvent dans les labs et les environnements orientés distributions pour mériter d’être mentionné. Pour l’analyse de sécurité, il rappelle une fois de plus que le concept de « conteneur » couvre plusieurs écosystèmes et styles opérationnels.

### Apptainer / Singularity

Apptainer (anciennement Singularity) est courant dans les environnements de recherche et de HPC. Ses assumptions de confiance, son workflow utilisateur et son modèle d’exécution diffèrent de manière importante des stacks centrées sur Docker/Kubernetes. En particulier, ces environnements accordent souvent une grande importance à la possibilité pour les utilisateurs d’exécuter des workloads packagées sans leur donner de larges privilèges de gestion de conteneurs. Si un reviewer suppose que tous les environnements de conteneurs sont essentiellement « Docker sur un serveur », il comprendra très mal ces déploiements.

## Outils De Build

De nombreuses discussions de sécurité ne parlent que du runtime, mais les outils de build sont également importants, car ils déterminent le contenu des images, l’exposition des build secrets et la quantité de contexte trusted intégrée dans l’artifact final.

**BuildKit** et `docker buildx` sont des backends de build modernes qui prennent en charge des fonctionnalités telles que le caching, le secret mounting, le SSH forwarding et les builds multi-platformes. Ces fonctionnalités sont utiles, mais du point de vue de la sécurité, elles créent également des endroits où des secrets peuvent leak dans les image layers ou où un build context trop large peut exposer des fichiers qui n’auraient jamais dû être inclus. **Buildah** joue un rôle similaire dans les écosystèmes natifs OCI, notamment avec Podman, tandis que **Kaniko** est souvent utilisé dans les environnements CI qui ne veulent pas accorder de Docker daemon privileged au build pipeline.

La leçon principale est que la création d’une image et son exécution sont deux phases différentes, mais qu’un build pipeline faible peut créer une posture de sécurité runtime faible bien avant le lancement du conteneur.

## L’Orchestration Est Une Autre Couche, Pas Le Runtime

Kubernetes ne doit pas être mentalement assimilé au runtime lui-même. Kubernetes est l’orchestrator. Il schedule les Pods, stocke l’état désiré et exprime les security policies via la configuration des workloads. Le kubelet communique ensuite avec une implémentation CRI telle que containerd ou CRI-O, qui invoque à son tour un runtime bas niveau tel que `runc`, `crun`, `runsc` ou `kata-runtime`.

Cette séparation est importante, car de nombreuses personnes attribuent à tort une protection à « Kubernetes » alors qu’elle est réellement appliquée par le node runtime, ou accusent les « defaults de containerd » d’un comportement provenant en réalité d’un Pod spec. En pratique, la posture de sécurité finale est une composition : l’orchestrator demande quelque chose, la runtime stack le traduit, puis le kernel l’applique finalement.

## Pourquoi L’Identification Du Runtime Est Importante Pendant Un Assessment

Si vous identifiez rapidement l’engine et le runtime, de nombreuses observations ultérieures deviennent plus faciles à interpréter. Un conteneur Podman rootless indique probablement que les user namespaces jouent un rôle. Un Docker socket monté dans une workload suggère qu’une privilege escalation via API est une voie réaliste. Un node CRI-O/OpenShift doit immédiatement vous faire penser aux labels SELinux et aux restricted workload policies. Un environnement gVisor ou Kata doit vous inciter à être plus prudent avant de supposer qu’un breakout PoC classique pour `runc` se comportera de la même manière.

C’est pourquoi l’une des premières étapes d’un container assessment devrait toujours être de répondre à deux questions simples : **quel composant gère le conteneur** et **quel runtime a réellement lancé le process**. Une fois ces réponses obtenues, il devient généralement beaucoup plus facile de raisonner sur le reste de l’environnement.

## Vulnérabilités Du Runtime

Tous les container escapes ne proviennent pas d’une mauvaise configuration de l’opérateur. Parfois, le runtime lui-même est le composant vulnérable. C’est important, car une workload peut s’exécuter avec une configuration apparemment soigneuse tout en restant exposée à une faille du runtime bas niveau.

L’exemple classique est **CVE-2019-5736** dans `runc`, où un conteneur malveillant pouvait écraser le binaire `runc` du host, puis attendre qu’un appel ultérieur à `docker exec` ou une invocation similaire du runtime déclenche du code contrôlé par l’attaquant. Le chemin d’exploitation est très différent d’une simple erreur de bind-mount ou de capabilities, car il exploite la manière dont le runtime réintègre l’espace de process du conteneur lors de la gestion d’un exec.

Un workflow de reproduction minimal du point de vue d’une red-team est :
```bash
go build main.go
./main
```
Ensuite, depuis l’hôte :
```bash
docker exec -it <container-name> /bin/sh
```
La leçon essentielle ne concerne pas l’implémentation exacte de l’exploit historique, mais son implication pour l’évaluation : si la version du runtime est vulnérable, une simple exécution de code dans le conteneur peut suffire à compromettre l’hôte, même lorsque la configuration visible du conteneur ne semble pas manifestement faible.

Les CVE récentes affectant les runtimes, comme `CVE-2024-21626` dans `runc`, les race conditions de montage de BuildKit et les bugs d’analyse de containerd, renforcent le même constat. La version du runtime et son niveau de correctifs font partie de la boundary de sécurité, et ne sont pas de simples détails de maintenance.
{{#include ../../../banners/hacktricks-training.md}}
