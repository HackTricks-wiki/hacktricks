# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

L'une des principales sources de confusion en sécurité des conteneurs est que plusieurs composants complètement différents sont souvent regroupés sous le même mot. "Docker" peut désigner un format d'image, un CLI, un daemon, un système de build, une pile runtime, ou simplement l'idée des conteneurs en général. Pour le travail de sécurité, cette ambiguïté est problématique, car différentes couches sont responsables de protections différentes. Une sortie due à un mauvais bind mount n'est pas la même chose qu'une sortie provoquée par un bug bas‑niveau du runtime, et aucune des deux n'est la même chose qu'une erreur de politique de cluster dans Kubernetes.

Cette page sépare l'écosystème par rôle afin que le reste de la section puisse parler précisément de l'endroit où une protection ou une faiblesse se trouve réellement.

## OCI As The Common Language

Les piles de conteneurs Linux modernes interopèrent souvent parce qu'elles parlent un ensemble de spécifications OCI. L'OCI Image Specification décrit comment les images et les couches sont représentées. L'OCI Runtime Specification décrit comment le runtime doit lancer le processus, y compris les namespaces, les mounts, les cgroups et les réglages de sécurité. L'OCI Distribution Specification standardise la façon dont les registries exposent le contenu.

Ceci importe parce que cela explique pourquoi une image de conteneur construite avec un outil peut souvent être exécutée avec un autre, et pourquoi plusieurs engines peuvent partager le même runtime bas‑niveau. Cela explique aussi pourquoi le comportement de sécurité peut sembler similaire entre différents produits : beaucoup d'entre eux construisent la même configuration de runtime OCI et la passent au même petit ensemble de runtimes.

## Low-Level OCI Runtimes

Le runtime bas‑niveau est le composant le plus proche de la frontière du noyau. C'est la partie qui crée réellement les namespaces, écrit les réglages de cgroup, applique les capabilities et les filtres seccomp, et finalement `execve()` le processus du conteneur. Quand on discute d'« isolation de conteneur » au niveau mécanique, c'est généralement de cette couche qu'on parle, même si ce n'est pas dit explicitement.

### `runc`

`runc` est le runtime OCI de référence et reste l'implémentation la plus connue. Il est largement utilisé sous Docker, containerd, et dans de nombreuses déploiements Kubernetes. Beaucoup de recherches publiques et de matériel d'exploitation ciblent des environnements de type `runc` simplement parce qu'ils sont courants et parce que `runc` définit la base que beaucoup imaginent quand ils pensent à un conteneur Linux. Comprendre `runc` donne donc un modèle mental solide pour l'isolation classique des conteneurs.

### `crun`

`crun` est un autre runtime OCI, écrit en C et largement utilisé dans les environnements modernes Podman. Il est souvent loué pour son bon support de cgroup v2, sa forte ergonomie rootless, et son overhead plus faible. Du point de vue de la sécurité, l'important n'est pas qu'il soit écrit dans un langage différent, mais qu'il joue toujours le même rôle : c'est le composant qui transforme la configuration OCI en un arbre de processus en cours d'exécution sous le noyau. Un workflow rootless Podman finit souvent par sembler plus sûr non pas parce que `crun` corrige magiquement tout, mais parce que la pile environnante tend à s'appuyer davantage sur les user namespaces et le principe du moindre privilège.

### `runsc` From gVisor

`runsc` est le runtime utilisé par gVisor. Ici la frontière change de manière significative. Au lieu de transmettre la plupart des syscalls directement au noyau hôte de façon habituelle, gVisor insère une couche de noyau en espace utilisateur qui émule ou médie de larges parties de l'interface Linux. Le résultat n'est pas un conteneur `runc` normal avec quelques flags supplémentaires ; c'est un design de sandbox différent dont le but est de réduire la surface d'attaque du noyau hôte. Compatibilité et compromis de performance font partie de ce design, donc les environnements utilisant `runsc` devraient être documentés différemment des environnements de runtime OCI « normaux ».

### `kata-runtime`

Kata Containers pousse la frontière plus loin en lançant la charge de travail à l'intérieur d'une machine virtuelle légère. Administrativement, cela peut toujours ressembler à un déploiement de conteneurs, et les couches d'orchestration peuvent toujours le traiter comme tel, mais la frontière d'isolation sous-jacente est plus proche de la virtualisation que d'un conteneur classique partageant le noyau hôte. Cela rend Kata utile quand une isolation plus forte entre locataires est désirée sans abandonner les workflows centrés sur les conteneurs.

## Engines And Container Managers

Si le runtime bas‑niveau est le composant qui parle directement au noyau, l'engine ou manager est le composant avec lequel les utilisateurs et opérateurs interagissent habituellement. Il gère les pulls d'images, les métadonnées, les logs, les réseaux, les volumes, les opérations de cycle de vie et l'exposition d'API. Cette couche importe énormément parce que beaucoup de compromissions réelles se produisent ici : l'accès à une socket runtime ou à une API de daemon peut équivaloir à une compromission de l'hôte même si le runtime bas‑niveau lui‑même est parfaitement sain.

### Docker Engine

Docker Engine est la plateforme de conteneur la plus reconnaissable pour les développeurs et une des raisons pour lesquelles le vocabulaire des conteneurs est devenu si Docker‑centré. Le chemin typique est le CLI `docker` vers `dockerd`, qui coordonne à son tour des composants bas‑niveau comme `containerd` et un runtime OCI. Historiquement, les déploiements Docker ont souvent été **rootful**, et l'accès à la socket Docker a donc été un primitive très puissante. C'est pourquoi tant de matériel pratique sur l'escalade de privilèges se concentre sur `docker.sock` : si un processus peut demander à `dockerd` de créer un conteneur privilégié, monter des chemins hôtes, ou rejoindre des namespaces hôtes, il peut ne pas avoir besoin d'un exploit noyau du tout.

### Podman

Podman a été conçu autour d'un modèle sans daemon. Opérationnellement, cela aide à renforcer l'idée que les conteneurs ne sont que des processus gérés via des mécanismes Linux standards plutôt que par un long daemon privilégié. Podman a aussi un récit **rootless** bien plus fort que les déploiements Docker classiques que beaucoup ont appris en premier. Cela ne rend pas Podman automatiquement sûr, mais cela change significativement le profil de risque par défaut, surtout lorsqu'il est combiné avec les user namespaces, SELinux, et `crun`.

### containerd

containerd est un composant central de gestion des runtimes dans beaucoup de piles modernes. Il est utilisé sous Docker et est aussi l'un des backends runtime dominants de Kubernetes. Il expose des APIs puissantes, gère les images et les snapshots, et délègue la création finale du processus à un runtime bas‑niveau. Les discussions de sécurité autour de containerd devraient souligner que l'accès à la socket containerd ou aux fonctionnalités `ctr`/`nerdctl` peut être tout aussi dangereux que l'accès à l'API de Docker, même si l'interface et le workflow semblent moins « orientés développeur ».

### CRI-O

CRI-O est plus focalisé que Docker Engine. Plutôt que d'être une plateforme développeur à usage général, il est construit autour de l'implémentation propre de la Container Runtime Interface de Kubernetes. Cela le rend particulièrement courant dans les distributions Kubernetes et les écosystèmes à forte présence SELinux comme OpenShift. Du point de vue de la sécurité, cette portée plus étroite est utile car elle réduit la confusion conceptuelle : CRI-O fait très clairement partie de la couche « exécuter des conteneurs pour Kubernetes » plutôt que d'une plateforme tous‑usage.

### Incus, LXD, And LXC

Les systèmes Incus/LXD/LXC valent la peine d'être séparés des conteneurs de type Docker parce qu'ils sont souvent utilisés comme des system containers. Un system container est généralement censé ressembler davantage à une machine légère avec un userspace plus complet, des services longue durée, une exposition de périphériques plus riche et une intégration hôte plus étendue. Les mécanismes d'isolation sont toujours des primitives du noyau, mais les attentes opérationnelles diffèrent. En conséquence, les erreurs de configuration ici ressemblent souvent moins à des « mauvais paramètres par défaut d'app‑container » et davantage à des erreurs de virtualisation légère ou de délégation d'hôte.

### systemd-nspawn

systemd-nspawn occupe une place intéressante parce qu'il est natif systemd et très utile pour tester, déboguer et exécuter des environnements de type OS. Ce n'est pas le runtime dominant en production cloud‑native, mais il apparaît suffisamment dans les labs et les environnements orientés distribution pour mériter d'être mentionné. Pour l'analyse de sécurité, c'est un rappel que le concept de « conteneur » couvre plusieurs écosystèmes et styles opérationnels.

### Apptainer / Singularity

Apptainer (anciennement Singularity) est courant dans les environnements de recherche et HPC. Ses hypothèses de confiance, son workflow utilisateur et son modèle d'exécution diffèrent de façon importante des piles centrées Docker/Kubernetes. En particulier, ces environnements tiennent souvent beaucoup à permettre aux utilisateurs d'exécuter des workloads packagés sans leur donner de larges pouvoirs de gestion de conteneurs privilégiés. Si un évaluateur suppose que chaque environnement de conteneur est essentiellement « Docker sur un serveur », il comprendra mal ces déploiements.

## Build-Time Tooling

Beaucoup de discussions de sécurité ne parlent que du run time, mais les outils de build importent aussi car ils déterminent le contenu des images, l'exposition des secrets, et la quantité de contexte de confiance intégrée dans l'artefact final.

**BuildKit** et `docker buildx` sont des backends de build modernes qui supportent des fonctionnalités telles que le caching, le montage de secrets, le forwarding SSH, et les builds multi‑plateforme. Ce sont des fonctionnalités utiles, mais du point de vue de la sécurité elles créent aussi des endroits où des secrets peuvent leak dans les couches d'image ou où un contexte de build trop large peut exposer des fichiers qui n'auraient jamais dû être inclus. **Buildah** joue un rôle similaire dans les écosystèmes natifs OCI, en particulier autour de Podman, tandis que **Kaniko** est souvent utilisé dans des environnements CI qui ne veulent pas accorder un daemon Docker privilégié à la pipeline de build.

La leçon clé est que la création d'image et l'exécution d'image sont des phases différentes, mais une pipeline de build faible peut créer une posture runtime faible bien avant le lancement du conteneur.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes ne doit pas être mentalement assimilé au runtime lui‑même. Kubernetes est l'orchestrateur. Il programme les Pods, stocke l'état désiré et exprime la politique de sécurité via la configuration des workloads. Le kubelet parle ensuite à une implémentation CRI telle que containerd ou CRI-O, qui invoque à son tour un runtime bas‑niveau comme `runc`, `crun`, `runsc`, ou `kata-runtime`.

Cette séparation importe parce que beaucoup de gens attribuent à tort une protection à « Kubernetes » alors qu'elle est réellement appliquée par le runtime du nœud, ou ils reprochent aux « defaults de containerd » un comportement qui venait d'un spec de Pod. En pratique, la posture finale de sécurité est une composition : l'orchestrateur demande quelque chose, la pile runtime le traduit, et le noyau l'applique finalement.

## Why Runtime Identification Matters During Assessment

Si vous identifiez l'engine et le runtime tôt, beaucoup d'observations ultérieures deviennent plus faciles à interpréter. Un conteneur Podman rootless suggère que les user namespaces font probablement partie de l'histoire. Une socket Docker montée dans une charge de travail suggère que l'escalade de privilèges via l'API est un chemin réaliste. Un nœud CRI-O/OpenShift devrait immédiatement vous faire penser aux labels SELinux et à une politique de workloads restreinte. Un environnement gVisor ou Kata devrait vous rendre plus prudent avant de supposer qu'un PoC d'évasion `runc` classique se comportera de la même manière.

C'est pourquoi l'une des premières étapes dans une évaluation de conteneur devrait toujours être de répondre à deux questions simples : **quel composant gère le conteneur** et **quel runtime a réellement lancé le processus**. Une fois ces réponses claires, le reste de l'environnement devient généralement beaucoup plus facile à raisonner.

## Runtime Vulnerabilities

Toutes les échappées de conteneur ne proviennent pas d'une mauvaise configuration opérateur. Parfois le runtime lui‑même est le composant vulnérable. Cela importe parce qu'une charge de travail peut tourner avec ce qui semble être une configuration soigneuse et rester exposée via une faille bas‑niveau du runtime.

L'exemple classique est **CVE-2019-5736** dans `runc`, où un conteneur malveillant pouvait écraser le binaire `runc` de l'hôte puis attendre une invocation runtime ultérieure comme `docker exec` pour déclencher du code contrôlé par l'attaquant. Le chemin d'exploitation est très différent d'un simple bind‑mount ou d'une erreur de capabilities parce qu'il abuse de la façon dont le runtime ré‑entre dans l'espace de processus du conteneur lors de la gestion des exec.

Un workflow minimal de reproduction du point de vue d'une red-team est :
```bash
go build main.go
./main
```
Ensuite, depuis l'hôte :
```bash
docker exec -it <container-name> /bin/sh
```
La leçon clé n'est pas l'implémentation historique exacte de l'exploit, mais l'implication pour l'évaluation : si la version du runtime est vulnérable, l'exécution de code ordinaire à l'intérieur du conteneur peut suffire à compromettre l'hôte, même lorsque la configuration visible du conteneur ne semble pas manifestement faible.

Des CVE récents affectant les runtimes, tels que `CVE-2024-21626` dans `runc`, BuildKit mount races, et containerd parsing bugs, renforcent ce point. La version du runtime et le niveau de patch font partie du périmètre de sécurité, pas simplement des détails de maintenance.
{{#include ../../../banners/hacktricks-training.md}}
