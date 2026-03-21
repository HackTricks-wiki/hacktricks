# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Une des plus grandes sources de confusion en sécurité des conteneurs est que plusieurs composants complètement différents sont souvent amalgamés sous le même mot. "Docker" peut désigner un format d'image, un CLI, un daemon, un système de build, une pile runtime, ou simplement l'idée des conteneurs en général. Pour le travail de sécurité, cette ambiguïté est problématique, car différentes couches sont responsables de protections différentes. Une fuite provoquée par un mauvais bind mount n'est pas la même chose qu'une breakout causée par un bug bas-niveau du runtime, et aucune n'est la même chose qu'une erreur de politique de cluster dans Kubernetes.

Cette page sépare l'écosystème par rôle afin que le reste de la section puisse parler précisément de l'endroit où une protection ou une faiblesse se situe réellement.

## OCI As The Common Language

Les stacks modernes de conteneurs Linux interopèrent souvent parce qu'elles parlent un ensemble de spécifications OCI. La **OCI Image Specification** décrit comment les images et les couches sont représentées. La **OCI Runtime Specification** décrit comment le runtime devrait lancer le processus, y compris les namespaces, mounts, cgroups et paramètres de sécurité. La **OCI Distribution Specification** standardise la manière dont les registries exposent le contenu.

Ceci est important car cela explique pourquoi une image construite avec un outil peut souvent être exécutée avec un autre, et pourquoi plusieurs engines peuvent partager le même runtime bas-niveau. Cela explique aussi pourquoi le comportement de sécurité peut sembler similaire entre différents produits : beaucoup d'entre eux construisent la même configuration de runtime OCI et la confient au même petit ensemble de runtimes.

## Low-Level OCI Runtimes

Le runtime bas-niveau est le composant le plus proche de la frontière du kernel. C'est la partie qui crée réellement les namespaces, écrit les paramètres de cgroup, applique les capabilities et les filtres seccomp, et finalement fait un `execve()` du processus du conteneur. Quand les gens discutent de "container isolation" au niveau mécanique, c'est généralement de cette couche dont ils parlent, même s'ils ne le disent pas explicitement.

### `runc`

`runc` est le runtime de référence OCI et reste l'implémentation la mieux connue. Il est largement utilisé sous Docker, containerd, et de nombreuses déploiements Kubernetes. Beaucoup de recherches publiques et de matériel d'exploitation ciblent des environnements de type `runc` simplement parce qu'ils sont courants et parce que `runc` définit la base à laquelle beaucoup de gens pensent quand ils imaginent un conteneur Linux. Comprendre `runc` donne donc au lecteur un modèle mental solide pour l'isolation classique des conteneurs.

### `crun`

`crun` est un autre runtime OCI, écrit en C et largement utilisé dans les environnements modernes Podman. Il est souvent loué pour son bon support de cgroup v2, sa bonne ergonomie rootless, et son overhead plus faible. Du point de vue sécurité, l'important n'est pas qu'il soit écrit dans un langage différent, mais qu'il joue toujours le même rôle : il transforme la configuration OCI en un arbre de processus en cours d'exécution sous le kernel. Un workflow Podman rootless finit fréquemment par sembler plus sûr non pas parce que `crun` résout magiquement tout, mais parce que la pile globale autour tend à s'appuyer davantage sur les user namespaces et le principe du moindre privilège.

### `runsc` From gVisor

`runsc` est le runtime utilisé par gVisor. Ici la frontière change de manière significative. Au lieu de transférer la plupart des syscalls directement au kernel hôte de la façon habituelle, gVisor insère une couche de kernel en espace utilisateur qui émule ou médie de larges parties de l'interface Linux. Le résultat n'est pas un conteneur `runc` normal avec quelques flags en plus ; c'est un design de sandbox différent dont le but est de réduire la surface d'attaque du kernel hôte. Les compromis en termes de compatibilité et de performance font partie de ce design, donc les environnements utilisant `runsc` devraient être documentés différemment des environnements runtime OCI classiques.

### `kata-runtime`

Kata Containers pousse la frontière plus loin en lançant la charge de travail à l'intérieur d'une machine virtuelle légère. Administrativement, cela peut toujours ressembler à un déploiement de conteneurs, et les couches d'orchestration peuvent toujours le traiter comme tel, mais la frontière d'isolation sous-jacente est plus proche de la virtualisation que d'un conteneur partageant le kernel hôte. Cela rend Kata utile lorsque l'on désire une isolation locataire plus forte sans abandonner les workflows centrés conteneur.

## Engines And Container Managers

Si le runtime bas-niveau est le composant qui parle directement au kernel, l'engine ou manager est le composant avec lequel les utilisateurs et opérateurs interagissent généralement. Il gère les pulls d'images, les métadonnées, les logs, les réseaux, les volumes, les opérations de lifecycle et l'exposition d'API. Cette couche est extrêmement importante car de nombreuses compromissions du monde réel se produisent ici : l'accès à un socket runtime ou à une API de daemon peut équivaloir à une compromission de l'hôte même si le runtime bas-niveau lui-même est parfaitement sain.

### Docker Engine

Docker Engine est la plateforme de conteneur la plus reconnaissable pour les développeurs et une des raisons pour lesquelles le vocabulaire des conteneurs est devenu si Docker-centré. Le chemin typique est le CLI `docker` vers `dockerd`, qui coordonne à son tour des composants bas-niveau tels que `containerd` et un runtime OCI. Historiquement, les déploiements Docker ont souvent été **rootful**, et l'accès au socket Docker a donc été un primitive très puissante. C'est pourquoi tant de matériel pratique d'escalade de privilèges se concentre sur `docker.sock` : si un processus peut demander à `dockerd` de créer un conteneur privilégié, de monter des chemins hôtes, ou de rejoindre des namespaces hôtes, il peut ne pas avoir besoin d'un exploit kernel du tout.

### Podman

Podman a été conçu autour d'un modèle sans daemon. Opérationnellement, cela aide à renforcer l'idée que les conteneurs ne sont que des processus gérés via les mécanismes Linux standards plutôt que via un daemon privilégié de longue durée. Podman a aussi une histoire **rootless** bien plus forte que les déploiements Docker classiques que beaucoup ont appris au début. Cela ne rend pas Podman automatiquement sûr, mais cela change sensiblement le profil de risque par défaut, surtout lorsqu'il est combiné avec les user namespaces, SELinux, et `crun`.

### containerd

containerd est un composant central de gestion du runtime dans de nombreuses stacks modernes. Il est utilisé sous Docker et est aussi l'un des backends runtime dominants de Kubernetes. Il expose des API puissantes, gère les images et snapshots, et délègue la création finale de processus à un runtime bas-niveau. Les discussions de sécurité autour de containerd doivent souligner que l'accès au socket containerd ou aux fonctionnalités `ctr`/`nerdctl` peut être tout aussi dangereux que l'accès à l'API Docker, même si l'interface et le workflow paraissent moins "orientés développeur".

### CRI-O

CRI-O est plus ciblé que Docker Engine. Plutôt que d'être une plateforme développeur à usage général, il est construit autour de l'implémentation propre de la Kubernetes Container Runtime Interface. Cela le rend particulièrement courant dans les distributions Kubernetes et les écosystèmes fortement orientés SELinux comme OpenShift. Du point de vue sécurité, cette portée plus étroite est utile car elle réduit le bruit conceptuel : CRI-O fait clairement partie de la couche "exécuter des conteneurs pour Kubernetes" plutôt que d'une plateforme tout-en-un.

### Incus, LXD, And LXC

Les systèmes Incus/LXD/LXC valent la peine d'être séparés des conteneurs de type Docker car ils sont souvent utilisés comme des **system containers**. Un system container est généralement censé ressembler davantage à une machine légère avec un userspace plus complet, des services longue durée, une exposition de périphériques plus riche et une intégration hôte plus étendue. Les mécanismes d'isolation restent des primitives kernel, mais les attentes opérationnelles sont différentes. En conséquence, les mauvaises configurations ici ressemblent souvent moins à des "mauvaises valeurs par défaut d'app-container" et davantage à des erreurs en virtualisation légère ou délégation d'hôte.

### systemd-nspawn

systemd-nspawn occupe une place intéressante car il est natif systemd et très utile pour les tests, le debugging et l'exécution d'environnements de type OS. Ce n'est pas le runtime dominant cloud-native en production, mais il apparaît suffisamment souvent dans les labs et environnements orientés distro pour mériter une mention. Pour l'analyse de sécurité, c'est un autre rappel que le concept de "container" couvre plusieurs écosystèmes et styles opérationnels.

### Apptainer / Singularity

Apptainer (anciennement Singularity) est courant dans les environnements de recherche et HPC. Ses hypothèses de confiance, son workflow utilisateur et son modèle d'exécution diffèrent de manière importante des stacks centrés Docker/Kubernetes. En particulier, ces environnements tiennent souvent beaucoup à permettre aux utilisateurs d'exécuter des charges packagées sans leur confier de larges pouvoirs de gestion de conteneurs privilégiés. Si un évaluateur suppose que chaque environnement de conteneur est essentiellement "Docker sur un serveur", il comprendra très mal ces déploiements.

## Build-Time Tooling

Beaucoup de discussions sur la sécurité ne parlent que du runtime, mais les outils de build au moment de la construction comptent aussi car ils déterminent le contenu des images, l'exposition des secrets, et combien de contexte de confiance est intégré dans l'artéfact final.

**BuildKit** et `docker buildx` sont des backends de build modernes qui supportent des fonctionnalités comme le caching, le montage de secrets, le forwarding SSH, et les builds multi-plateformes. Ce sont des fonctionnalités utiles, mais du point de vue sécurité elles créent aussi des endroits où des secrets peuvent leak dans les couches d'image ou où un contexte de build trop large peut exposer des fichiers qui ne devraient jamais être inclus. **Buildah** joue un rôle similaire dans les écosystèmes OCI-native, notamment autour de Podman, tandis que **Kaniko** est souvent utilisé dans des environnements CI qui ne veulent pas donner un daemon Docker privilégié à la pipeline de build.

La leçon clé est que la création d'image et l'exécution d'image sont des phases différentes, mais une pipeline de build faible peut créer une posture runtime faible bien avant le lancement du conteneur.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes ne doit pas être mentalement assimilé au runtime lui-même. Kubernetes est l'orchestrateur. Il planifie les Pods, stocke l'état désiré, et exprime la politique de sécurité via la configuration des workloads. Le kubelet parle ensuite à une implémentation CRI telle que containerd ou CRI-O, qui invoque à son tour un runtime bas-niveau tel que `runc`, `crun`, `runsc`, ou `kata-runtime`.

Cette séparation est importante car beaucoup de gens attribuent à tort une protection à "Kubernetes" alors qu'elle est réellement appliquée par le runtime du nœud, ou ils blâment les "defaults de containerd" pour un comportement qui provient d'un spec de Pod. En pratique, la posture finale de sécurité est une composition : l'orchestrateur demande quelque chose, la pile runtime le traduit, et le kernel l'applique finalement.

## Why Runtime Identification Matters During Assessment

Si vous identifiez l'engine et le runtime tôt, beaucoup d'observations ultérieures deviennent plus faciles à interpréter. Un conteneur Podman rootless suggère que les user namespaces font probablement partie de l'équation. Un socket Docker monté dans une charge de travail suggère qu'une escalade de privilèges pilotée par API est un chemin réaliste. Un nœud CRI-O/OpenShift devrait immédiatement vous faire penser aux labels SELinux et à la politique de workloads restreints. Un environnement gVisor ou Kata devrait vous rendre plus prudent avant de supposer qu'un PoC d'évasion `runc` classique se comportera de la même manière.

C'est pourquoi l'une des premières étapes lors d'une évaluation de conteneur doit toujours être de répondre à deux questions simples : **quel composant gère le conteneur** et **quel runtime a effectivement lancé le processus**. Une fois ces réponses claires, le reste de l'environnement devient généralement beaucoup plus facile à raisonner.

## Runtime Vulnerabilities

Toutes les escapes de conteneur ne proviennent pas d'une mauvaise configuration opérateur. Parfois, le runtime lui-même est le composant vulnérable. Cela importe car une charge de travail peut fonctionner avec ce qui ressemble à une configuration soigneuse et être malgré tout exposée via une faille bas-niveau du runtime.

L'exemple classique est **CVE-2019-5736** dans `runc`, où un conteneur malveillant pouvait écraser le binaire `runc` de l'hôte puis attendre qu'un futur `docker exec` ou une invocation runtime similaire déclenche du code contrôlé par l'attaquant. Le chemin d'exploitation est très différent d'un simple bind-mount ou d'une erreur de capability car il abuse de la façon dont le runtime ré-entre dans l'espace de processus du conteneur pendant la gestion des exec.

A minimal reproduction workflow from a red-team perspective is:
```bash
go build main.go
./main
```
Ensuite, depuis l'hôte :
```bash
docker exec -it <container-name> /bin/sh
```
La leçon principale n'est pas l'implémentation exacte de l'exploit historique, mais l'implication pour l'évaluation : si la version du runtime est vulnérable, l'exécution de code ordinaire in-container peut suffire à compromettre l'hôte même lorsque la configuration visible du container ne semble pas manifestement faible.

Des CVE récentes du runtime telles que `CVE-2024-21626` dans `runc`, BuildKit mount races, et les parsing bugs de containerd renforcent ce point. La version du runtime et le niveau des correctifs font partie du périmètre de sécurité, pas simplement des détails de maintenance.
