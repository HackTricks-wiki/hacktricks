# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Une des plus grandes sources de confusion en sécurité des containers est que plusieurs composants complètement différents sont souvent regroupés sous le même mot. "Docker" peut désigner un format d'image, un CLI, un daemon, un système de build, une pile runtime, ou simplement l'idée de containers en général. Pour le travail de sécurité, cette ambiguïté pose un problème, parce que différentes couches sont responsables de protections différentes. Une breakout causée par un mauvais bind mount n'est pas la même chose qu'une breakout causée par un bug bas-niveau du runtime, et aucune des deux n'est la même chose qu'une erreur de politique de cluster dans Kubernetes.

Cette page sépare l'écosystème par rôle afin que le reste de la section puisse parler précisément de l'endroit où une protection ou une faiblesse existe réellement.

## OCI As The Common Language

Les stacks modernes de containers Linux interopèrent souvent parce qu'ils parlent un ensemble de spécifications OCI. La **OCI Image Specification** décrit comment les images et les couches sont représentées. La **OCI Runtime Specification** décrit comment le runtime doit lancer le processus, y compris les namespaces, les mounts, les cgroups, et les paramètres de sécurité. La **OCI Distribution Specification** standardise la façon dont les registries exposent le contenu.

Ceci est important car cela explique pourquoi une image de container construite avec un outil peut souvent être exécutée avec un autre, et pourquoi plusieurs engines peuvent partager le même runtime bas-niveau. Cela explique aussi pourquoi le comportement de sécurité peut sembler similaire entre différents produits : beaucoup d'entre eux construisent la même configuration OCI de runtime et la remettent au même petit ensemble de runtimes.

## Low-Level OCI Runtimes

Le runtime bas-niveau est le composant le plus proche de la frontière noyau. C'est la partie qui crée réellement les namespaces, écrit les paramètres de cgroup, applique les capabilities et les filtres seccomp, et enfin `execve()` le processus du container. Quand les gens discutent de "container isolation" au niveau mécanique, c'est généralement de cette couche qu'ils parlent, même s'ils ne le disent pas explicitement.

### `runc`

`runc` est le runtime OCI de référence et reste l'implémentation la mieux connue. Il est largement utilisé sous Docker, containerd, et dans de nombreuses déploiements Kubernetes. Beaucoup de recherches publiques et de matériel d'exploitation ciblent des environnements de type `runc` simplement parce qu'ils sont fréquents et parce que `runc` définit la baseline à laquelle beaucoup de gens pensent quand ils imaginent un container Linux. Comprendre `runc` donne donc au lecteur un modèle mental solide pour l'isolation classique des containers.

### `crun`

`crun` est un autre runtime OCI, écrit en C et largement utilisé dans les environnements Podman modernes. Il est souvent loué pour son bon support de cgroup v2, une bonne ergonomie rootless, et une moindre surcharge. D'un point de vue sécurité, l'important n'est pas qu'il soit écrit dans un langage différent, mais qu'il joue toujours le même rôle : il est le composant qui transforme la configuration OCI en un arbre de processus en cours d'exécution sous le noyau. Un workflow Podman rootless finit souvent par sembler plus sûr non pas parce que `crun` résout tout magiquement, mais parce que la pile autour a tendance à s'appuyer davantage sur les user namespaces et le principe du moindre privilège.

### `runsc` From gVisor

`runsc` est le runtime utilisé par gVisor. Ici, la frontière change de manière significative. Au lieu de passer la plupart des syscalls directement au noyau hôte de la manière habituelle, gVisor insère une couche de noyau en espace utilisateur qui émule ou médie une grande partie de l'interface Linux. Le résultat n'est pas un container `runc` normal avec quelques drapeaux en plus ; c'est une conception de sandbox différente dont le but est de réduire la surface d'attaque du noyau hôte. Les compromis de compatibilité et de performance font partie de cette conception, donc les environnements utilisant `runsc` devraient être documentés différemment des environnements runtime OCI normaux.

### `kata-runtime`

Kata Containers pousse la frontière plus loin en lançant la charge de travail à l'intérieur d'une machine virtuelle légère. Administrativement, cela peut toujours ressembler à un déploiement de container, et les couches d'orchestration peuvent encore le traiter comme tel, mais la frontière d'isolation sous-jacente est plus proche de la virtualisation que d'un classic host-kernel-shared container. Cela rend Kata utile quand une isolation plus forte des locataires est souhaitée sans abandonner les workflows centrés sur les containers.

## Engines And Container Managers

Si le runtime bas-niveau est le composant qui parle directement au noyau, l'engine ou le manager est le composant avec lequel les utilisateurs et opérateurs interagissent habituellement. Il gère les pulls d'images, les métadonnées, les logs, les réseaux, les volumes, les opérations de lifecycle, et l'exposition d'API. Cette couche est extrêmement importante car beaucoup de compromissions réelles se produisent ici : l'accès à un socket de runtime ou à une API de daemon peut équivaloir à une compromission de l'hôte même si le runtime bas-niveau lui-même est parfaitement sain.

### Docker Engine

Docker Engine est la plateforme de containers la plus reconnaissable pour les développeurs et l'une des raisons pour lesquelles le vocabulaire des containers est devenu si Docker-shaped. Le chemin typique est le CLI `docker` vers `dockerd`, qui coordonne à son tour des composants bas-niveau tels que `containerd` et un runtime OCI. Historiquement, les déploiements Docker ont souvent été **rootful**, et l'accès au socket Docker a donc été une primitive très puissante. C'est pourquoi tant de matériel pratique sur l'escalade de privilège se concentre sur `docker.sock` : si un processus peut demander à `dockerd` de créer un container privilégié, monter des chemins hôtes ou rejoindre des namespaces hôtes, il peut ne pas avoir besoin d'un exploit noyau du tout.

### Podman

Podman a été conçu autour d'un modèle plus daemonless. Opérationnellement, cela renforce l'idée que les containers ne sont que des processus gérés via des mécanismes Linux standards plutôt que via un daemon privilégié de longue durée. Podman a aussi un récit beaucoup plus fort sur le rootless que les déploiements Docker classiques que beaucoup ont appris en premier. Cela ne rend pas Podman automatiquement sûr, mais cela change significativement le profil de risque par défaut, spécialement lorsqu'il est combiné avec user namespaces, SELinux, et `crun`.

### containerd

containerd est un composant central de gestion runtime dans de nombreuses stacks modernes. Il est utilisé sous Docker et est aussi un des backends runtime dominants de Kubernetes. Il expose des APIs puissantes, gère les images et les snapshots, et délègue la création finale des processus à un runtime bas-niveau. Les discussions de sécurité autour de containerd doivent souligner que l'accès au socket containerd ou aux fonctionnalités `ctr`/`nerdctl` peut être tout aussi dangereux que l'accès à l'API de Docker, même si l'interface et le workflow semblent moins "orientés développeur".

### CRI-O

CRI-O est plus ciblé que Docker Engine. Au lieu d'être une plateforme généraliste pour développeurs, il est construit autour de l'implémentation propre de la Container Runtime Interface de Kubernetes. Cela le rend particulièrement courant dans les distributions Kubernetes et les écosystèmes très orientés SELinux comme OpenShift. D'un point de vue sécurité, ce champ d'application plus étroit est utile car il réduit le bruit conceptuel : CRI-O fait très clairement partie de la couche "exécuter des containers pour Kubernetes" plutôt que d'une plateforme tout-en-un.

### Incus, LXD, And LXC

Les systèmes Incus/LXD/LXC valent la peine d'être séparés des containers de style Docker car ils sont souvent utilisés comme **system containers**. Un system container est généralement attendu pour ressembler davantage à une machine légère avec un userspace plus complet, des services de long running, une exposition de périphériques plus riche, et une intégration hôte plus étendue. Les mécanismes d'isolation sont toujours des primitives du noyau, mais les attentes opérationnelles sont différentes. En conséquence, les mauvaises configurations ici ressemblent moins à des "mauvaises valeurs par défaut d'app-container" et plus à des erreurs dans la virtualisation légère ou la délégation d'hôte.

### systemd-nspawn

systemd-nspawn occupe une place intéressante parce qu'il est natif systemd et très utile pour les tests, le debugging, et l'exécution d'environnements de type OS. Ce n'est pas le runtime dominant en production cloud-native, mais il apparaît suffisamment souvent dans les labs et les environnements orientés distribution pour mériter une mention. Pour l'analyse de sécurité, c'est un autre rappel que le concept de "container" couvre plusieurs écosystèmes et styles opérationnels.

### Apptainer / Singularity

Apptainer (anciennement Singularity) est courant dans les environnements de recherche et HPC. Ses hypothèses de confiance, le workflow utilisateur, et le modèle d'exécution diffèrent de manière importante des stacks centrés Docker/Kubernetes. En particulier, ces environnements tiennent souvent à permettre aux utilisateurs d'exécuter des workloads packagés sans leur conférer des pouvoirs larges de gestion de containers privilégiés. Si un auditeur suppose que chaque environnement de container est essentiellement "Docker sur un serveur", il comprendra très mal ces déploiements.

## Build-Time Tooling

Beaucoup de discussions sur la sécurité ne parlent que du runtime, mais les outils de build comptent aussi car ils déterminent le contenu des images, l'exposition des secrets de build, et combien de contexte de confiance est incorporé dans l'artéfact final.

**BuildKit** et `docker buildx` sont des backends de build modernes qui supportent des fonctionnalités telles que le caching, le montage de secrets, le forwarding SSH, et les builds multi-plateformes. Ce sont des fonctionnalités utiles, mais d'un point de vue sécurité elles créent aussi des endroits où des secrets peuvent leak dans des couches d'image ou où un contexte de build trop large peut exposer des fichiers qui n'auraient jamais dû être inclus. **Buildah** joue un rôle similaire dans les écosystèmes OCI-native, spécialement autour de Podman, tandis que **Kaniko** est souvent utilisé dans les environnements CI qui ne veulent pas donner un daemon Docker privilégié à la pipeline de build.

La leçon clé est que la création d'image et l'exécution d'image sont des phases différentes, mais une pipeline de build faible peut créer une posture runtime faible bien avant que le container ne soit lancé.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes ne doit pas être mentalement confondu avec le runtime lui-même. Kubernetes est l'orchestrateur. Il planifie des Pods, stocke l'état désiré, et exprime la politique de sécurité via la configuration des workloads. Le kubelet parle ensuite à une implémentation CRI telle que containerd ou CRI-O, qui à son tour invoque un runtime bas-niveau comme `runc`, `crun`, `runsc`, ou `kata-runtime`.

Cette séparation est importante parce que beaucoup de gens attribuent à tort une protection à "Kubernetes" alors qu'elle est réellement appliquée par le runtime du nœud, ou ils blâment les "containerd defaults" pour un comportement qui venait d'un spec de Pod. En pratique, la posture finale de sécurité est une composition : l'orchestrateur demande quelque chose, la pile runtime le traduit, et le noyau l'applique finalement.

## Why Runtime Identification Matters During Assessment

Si vous identifiez l'engine et le runtime tôt, beaucoup d'observations ultérieures deviennent plus faciles à interpréter. Un container Podman rootless suggère que les user namespaces font probablement partie de l'histoire. Un socket Docker monté dans une charge de travail suggère que l'escalade de privilège via API est un chemin réaliste. Un nœud CRI-O/OpenShift devrait immédiatement vous faire penser aux labels SELinux et à la politique de workload restreinte. Un environnement gVisor ou Kata devrait vous rendre plus prudent à l'idée de supposer qu'un PoC d'évasion `runc` classique se comportera de la même manière.

C'est pourquoi une des premières étapes dans une évaluation de containers devrait toujours être de répondre à deux questions simples : **quel composant gère le container** et **quel runtime a réellement lancé le processus**. Une fois ces réponses claires, le reste de l'environnement devient généralement beaucoup plus facile à raisonner.

## Runtime Vulnerabilities

Toutes les échappées de container ne proviennent pas d'une mauvaise configuration d'opérateur. Parfois le runtime lui-même est le composant vulnérable. Cela importe parce qu'une charge de travail peut s'exécuter avec une configuration qui semble soignée et être quand même exposée via une faille bas-niveau du runtime.

L'exemple classique est **CVE-2019-5736** dans `runc`, où un container malveillant pouvait écraser le binaire `runc` de l'hôte puis attendre une invocation runtime ultérieure telle que `docker exec` pour déclencher du code contrôlé par l'attaquant. Le chemin d'exploitation est très différent d'un simple bind-mount ou d'une erreur de capability parce qu'il abuse de la façon dont le runtime réentre dans l'espace processus du container durant la gestion des exec.

Un workflow de reproduction minimal du point de vue d'une red-team est :
```bash
go build main.go
./main
```
Ensuite, depuis l'hôte :
```bash
docker exec -it <container-name> /bin/sh
```
La leçon essentielle n'est pas l'implémentation historique exacte d'un exploit, mais l'implication pour l'évaluation : si la version du runtime est vulnérable, l'exécution de code ordinaire dans le container peut suffire à compromettre l'hôte, même si la configuration visible du container ne semble pas manifestement faible.

Des CVE récentes des runtimes, telles que `CVE-2024-21626` dans `runc`, BuildKit mount races, et containerd parsing bugs renforcent ce point. La version du runtime et le niveau de patch font partie de la frontière de sécurité, et non de simples détails de maintenance.
{{#include ../../../banners/hacktricks-training.md}}
