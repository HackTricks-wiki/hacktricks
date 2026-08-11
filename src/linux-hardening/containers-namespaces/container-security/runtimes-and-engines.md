# Container Runtimes, Engines, Builders, And Sandboxes

L’une des principales sources de confusion en container security vient du fait que plusieurs composants complètement différents sont souvent désignés par le même mot. « Docker » peut faire référence à un format d’image, une CLI, un daemon, un système de build, une runtime stack ou simplement à l’idée générale des containers. Pour les travaux de sécurité, cette ambiguïté pose problème, car différentes couches sont responsables de différentes protections. Un breakout causé par un mauvais bind mount n’est pas la même chose qu’un breakout causé par une vulnérabilité du low-level runtime, et aucun des deux ne correspond à une erreur de policy au niveau du cluster dans Kubernetes.

Cette page sépare l’écosystème par rôle afin que le reste de cette section puisse préciser exactement où se trouve une protection ou une faiblesse.

## OCI As The Common Language

Les stacks de containers Linux modernes interopèrent souvent parce qu’elles utilisent un ensemble de spécifications OCI. L’**OCI Image Specification** décrit la manière dont les images et les layers sont représentés. L’**OCI Runtime Specification** décrit comment la runtime doit lancer le process, notamment les namespaces, les mounts, les cgroups et les paramètres de sécurité. L’**OCI Distribution Specification** standardise la manière dont les registries exposent leur contenu.

Cela explique pourquoi une container image créée avec un outil peut souvent être exécutée avec un autre, et pourquoi plusieurs engines peuvent utiliser la même low-level runtime. Cela explique également pourquoi le comportement de sécurité peut sembler similaire entre différents produits : beaucoup d’entre eux construisent la même configuration OCI runtime et la transmettent au même petit ensemble de runtimes.

## Low-Level OCI Runtimes

La low-level runtime est le composant le plus proche de la limite avec le kernel. C’est elle qui crée réellement les namespaces, écrit les paramètres des cgroups, applique les capabilities et les filtres seccomp, puis exécute finalement `execve()` sur le process du container. Lorsque l’on parle d’« isolation des containers » au niveau mécanique, c’est généralement cette couche qui est visée, même si cela n’est pas précisé explicitement.

### `runc`

`runc` est la référence en matière d’OCI runtime et reste l’implémentation la plus connue. Il est largement utilisé avec Docker, containerd et de nombreux déploiements Kubernetes. Une grande partie des recherches publiques et des contenus d’exploitation cible des environnements de type `runc`, simplement parce qu’ils sont courants et que `runc` définit la base que beaucoup de personnes associent à un container Linux. Comprendre `runc` fournit donc un modèle mental solide de l’isolation classique des containers.

### `crun`

`crun` est une autre OCI runtime, écrite en C et largement utilisée dans les environnements Podman modernes. Elle est souvent appréciée pour son bon support de cgroup v2, son excellente ergonomie rootless et sa faible surcharge. Du point de vue de la sécurité, l’important n’est pas qu’elle soit écrite dans un autre langage, mais qu’elle joue le même rôle : c’est le composant qui transforme la configuration OCI en un arbre de processes exécuté sous le kernel. Un workflow Podman rootless paraît souvent plus sûr, non pas parce que `crun` corrige tout comme par magie, mais parce que la stack globale qui l’entoure s’appuie généralement davantage sur les user namespaces et le least privilege.

### `runsc` From gVisor

`runsc` est la runtime utilisée par gVisor. Ici, la frontière change de manière significative. Au lieu de transmettre la plupart des syscalls directement au kernel de l’hôte comme d’habitude, gVisor insère une couche de kernel en userspace qui émule ou contrôle de grandes parties de l’interface Linux. Le résultat n’est pas un container `runc` normal avec quelques flags supplémentaires ; il s’agit d’un design de sandbox différent, dont l’objectif est de réduire la surface d’attaque du host kernel. Les compromis en matière de compatibilité et de performances font partie de ce design ; les environnements utilisant `runsc` doivent donc être documentés différemment des environnements OCI runtime classiques.

### `kata-runtime`

Kata Containers repoussent encore davantage la limite en lançant le workload dans une lightweight virtual machine. D’un point de vue administratif, cela peut toujours ressembler à un déploiement de containers, et les couches d’orchestration peuvent continuer à le traiter comme tel, mais la limite d’isolation sous-jacente est plus proche de la virtualisation que d’un container classique partageant le host kernel. Kata est donc utile lorsqu’une isolation plus forte entre tenants est souhaitée sans abandonner les workflows centrés sur les containers.

## Engines And Container Managers

Si la low-level runtime est le composant qui communique directement avec le kernel, l’engine ou le manager est celui avec lequel les utilisateurs et les opérateurs interagissent généralement. Il gère les pulls d’images, les metadata, les logs, les networks, les volumes, les opérations de lifecycle et l’exposition des APIs. Cette couche est extrêmement importante, car de nombreux compromissions réelles se produisent à ce niveau : l’accès à une runtime socket ou à une daemon API peut équivaloir à une compromission de l’hôte, même si la low-level runtime elle-même fonctionne parfaitement.

### Docker Engine

Docker Engine est la container platform la plus reconnaissable pour les développeurs et l’une des raisons pour lesquelles le vocabulaire des containers est devenu si fortement associé à Docker. Le chemin typique est `docker` CLI vers `dockerd`, qui coordonne ensuite des composants de niveau inférieur tels que `containerd` et une OCI runtime. Historiquement, les déploiements Docker ont souvent été **rootful**, et l’accès à la Docker socket constitue donc un primitive très puissant. C’est pourquoi une grande partie des contenus pratiques sur la privilege escalation se concentre sur `docker.sock` : si un process peut demander à `dockerd` de créer un container privilégié, de monter des host paths ou de rejoindre des host namespaces, il n’a peut-être besoin d’aucun kernel exploit.

### Podman

Podman a été conçu autour d’un modèle davantage daemonless. Sur le plan opérationnel, cela renforce l’idée que les containers sont simplement des processes gérés via les mécanismes Linux standards, plutôt que par un unique daemon privilégié et exécuté en permanence. Podman dispose également d’un modèle **rootless** bien plus solide que les déploiements Docker classiques avec lesquels de nombreuses personnes ont commencé. Cela ne rend pas Podman automatiquement sûr, mais modifie considérablement le profil de risque par défaut, notamment lorsqu’il est combiné aux user namespaces, à SELinux et à `crun`.

### containerd

containerd est un composant central de gestion de runtime dans de nombreuses stacks modernes. Il est utilisé sous Docker et constitue également l’un des principaux backends de runtime de Kubernetes. Il expose de puissantes APIs, gère les images et les snapshots, puis délègue la création finale des processes à une low-level runtime. Les discussions de sécurité autour de containerd doivent souligner que l’accès à la socket containerd ou aux fonctionnalités de `ctr`/`nerdctl` peut être tout aussi dangereux que l’accès à l’API de Docker, même si l’interface et le workflow semblent moins « developer friendly ».

### CRI-O

CRI-O est plus spécialisé que Docker Engine. Au lieu d’être une developer platform généraliste, il est conçu pour implémenter proprement le Kubernetes Container Runtime Interface. Il est donc particulièrement courant dans les distributions Kubernetes et les écosystèmes fortement axés sur SELinux, comme OpenShift. Du point de vue de la sécurité, ce périmètre plus restreint est utile, car il réduit la complexité conceptuelle : CRI-O appartient clairement à la couche « exécuter des containers pour Kubernetes », plutôt qu’à une plateforme universelle.

### Incus, LXD, And LXC

Les systèmes Incus/LXD/LXC doivent être distingués des application containers de type Docker, car ils sont souvent utilisés comme des **system containers**. Un system container est généralement censé ressembler davantage à une machine légère, avec un userspace plus complet, des services persistants, une exposition plus riche des devices et une intégration plus étendue avec l’hôte. Les mécanismes d’isolation restent des primitives du kernel, mais les attentes opérationnelles sont différentes. Par conséquent, les misconfigurations observées ici ressemblent souvent moins à de « mauvais paramètres par défaut d’app-container » qu’à des erreurs de lightweight virtualization ou de délégation de l’hôte.

### systemd-nspawn

systemd-nspawn occupe une place intéressante, car il est natif de systemd et très utile pour les tests, le debugging et l’exécution d’environnements ressemblant à des OS. Ce n’est pas la runtime cloud-native de production dominante, mais elle apparaît assez souvent dans les labs et les environnements orientés distributions pour mériter d’être mentionnée. Pour l’analyse de sécurité, elle rappelle une fois de plus que le concept de « container » couvre plusieurs écosystèmes et styles opérationnels.

### Apptainer / Singularity

Apptainer (anciennement Singularity) est courant dans les environnements de recherche et de HPC. Ses hypothèses de confiance, son workflow utilisateur et son modèle d’exécution diffèrent de manière importante des stacks centrées sur Docker/Kubernetes. En particulier, ces environnements cherchent souvent à permettre aux utilisateurs d’exécuter des workloads packagés sans leur accorder de larges privilèges de gestion des containers. Si un reviewer suppose que tout environnement de containers est essentiellement « Docker sur un serveur », il comprendra très mal ces déploiements.

## Build-Time Tooling

De nombreuses discussions de sécurité ne parlent que du runtime, mais les outils de build sont également importants, car ils déterminent le contenu des images, l’exposition des build secrets et la quantité de contexte de confiance intégrée à l’artefact final.

**BuildKit** et `docker buildx` sont des backends de build modernes qui prennent en charge des fonctionnalités telles que le caching, le secret mounting, le SSH forwarding et les builds multi-platformes. Ces fonctionnalités sont utiles, mais du point de vue de la sécurité, elles créent également des endroits où des secrets peuvent leak dans des image layers ou où un build context trop large peut exposer des fichiers qui n’auraient jamais dû être inclus. **Buildah** joue un rôle similaire dans les écosystèmes OCI-native, notamment autour de Podman, tandis que **Kaniko** est souvent utilisé dans des environnements CI qui ne souhaitent pas accorder de Docker daemon privilégié au build pipeline.

La leçon principale est que la création d’une image et son exécution sont deux phases différentes, mais qu’un build pipeline faible peut créer une runtime posture faible bien avant le lancement du container.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes ne doit pas être mentalement assimilé à la runtime elle-même. Kubernetes est l’orchestrateur. Il planifie les Pods, stocke l’état souhaité et exprime les security policies via la configuration des workloads. Le kubelet communique ensuite avec une implémentation CRI telle que containerd ou CRI-O, qui invoque à son tour une low-level runtime comme `runc`, `crun`, `runsc` ou `kata-runtime`.

Cette séparation est importante, car de nombreuses personnes attribuent à tort une protection à « Kubernetes » alors qu’elle est réellement appliquée par la node runtime, ou reprochent aux « containerd defaults » un comportement provenant en réalité d’un Pod spec. En pratique, la security posture finale est une composition : l’orchestrateur demande quelque chose, la runtime stack le traduit et le kernel l’applique finalement.

## Why Runtime Identification Matters During Assessment

Si vous identifiez rapidement l’engine et la runtime, de nombreuses observations ultérieures deviennent plus faciles à interpréter. Un container Podman rootless suggère que les user namespaces jouent probablement un rôle. Une Docker socket montée dans un workload suggère qu’une privilege escalation pilotée par API constitue une voie réaliste. Un nœud CRI-O/OpenShift doit immédiatement vous faire penser aux labels SELinux et aux restricted workload policies. Un environnement gVisor ou Kata doit vous inciter à davantage de prudence avant de supposer qu’un breakout PoC classique destiné à `runc` se comportera de la même manière.

C’est pourquoi l’une des premières étapes d’une container assessment devrait toujours consister à répondre à deux questions simples : **quel composant gère le container** et **quelle runtime a réellement lancé le process**. Une fois ces réponses établies, le reste de l’environnement devient généralement beaucoup plus facile à analyser.

## Runtime Vulnerabilities

Tous les container escapes ne proviennent pas d’une misconfiguration de l’opérateur. Parfois, la runtime elle-même est le composant vulnérable. Cela est important, car un workload peut s’exécuter avec une configuration qui semble soigneusement définie tout en restant exposé à une faille de low-level runtime.

L’exemple classique est **CVE-2019-5736** dans `runc`, où un container malveillant pouvait écraser le binaire `runc` de l’hôte, puis attendre qu’un appel ultérieur à `docker exec` ou à une invocation similaire de la runtime déclenche du code contrôlé par l’attaquant. Le chemin d’exploitation est très différent d’une simple erreur de bind mount ou de capabilities, car il exploite la manière dont la runtime réintègre l’espace des processes du container lors du traitement d’un exec.<sup>[[1]](#references)</sup>

Un workflow de reproduction minimal du point de vue d’une red team est le suivant :
```bash
go build main.go
./main
```
Ensuite, depuis l’hôte :
```bash
docker exec -it <container-name> /bin/sh
```
La leçon essentielle ne concerne pas l’implémentation exacte de l’exploit historique, mais son implication pour l’évaluation : si la version du runtime est vulnérable, une exécution de code ordinaire dans le conteneur peut suffire à compromettre l’hôte, même lorsque la configuration visible du conteneur ne semble pas manifestement faible.

Les CVE récentes affectant les runtimes, telles que `CVE-2024-21626` dans `runc`, les race conditions de montage de BuildKit et les bugs d’analyse de containerd, renforcent le même point. La version du runtime et son niveau de correctifs font partie de la frontière de sécurité, et ne sont pas de simples détails de maintenance.

## References

- [1] [Sortir de Docker via runC – Explication de CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
