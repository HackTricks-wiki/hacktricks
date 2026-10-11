# Environnements d’exécution, moteurs, outils de build et sandboxes pour conteneurs

{{#include ../../../banners/hacktricks-training.md}}

L’une des principales sources de confusion en sécurité des conteneurs tient au fait que plusieurs composants totalement différents sont souvent désignés par le même terme. « Docker » peut désigner un format d’image, une CLI, un daemon, un système de build, une pile d’exécution ou simplement l’idée générale des conteneurs. En sécurité, cette ambiguïté pose problème, car les différentes couches sont responsables de protections différentes. Une évasion causée par un bind mount mal configuré n’est pas la même chose qu’une évasion causée par un bug dans un runtime bas niveau, et aucune des deux ne correspond à une erreur de politique de cluster dans Kubernetes.

Cette page distingue les composants de l’écosystème selon leur rôle afin que le reste de cette section puisse préciser où se trouve réellement une protection ou une faiblesse.

## OCI comme langage commun

Les piles de conteneurs Linux modernes sont souvent interopérables parce qu’elles utilisent un ensemble de spécifications OCI. L’**OCI Image Specification** décrit la représentation des images et des couches. L’**OCI Runtime Specification** décrit la manière dont le runtime doit lancer le processus, notamment en ce qui concerne les namespaces, les montages, les cgroups et les paramètres de sécurité. L’**OCI Distribution Specification** normalise la façon dont les registres exposent leur contenu.

Cela explique pourquoi une image de conteneur créée avec un outil peut souvent être exécutée avec un autre, et pourquoi plusieurs moteurs peuvent partager le même runtime bas niveau. Cela explique aussi pourquoi le comportement en matière de sécurité peut sembler similaire entre différents produits : beaucoup construisent la même configuration de runtime OCI et la transmettent au même petit ensemble de runtimes.

## Runtimes OCI bas niveau

Le runtime bas niveau est le composant le plus proche de la frontière avec le noyau. C’est lui qui crée les namespaces, écrit les paramètres des cgroups, applique les capabilities et les filtres seccomp, puis lance le processus du conteneur avec `execve()`. Quand on parle d’« isolation des conteneurs » au niveau mécanique, c’est généralement de cette couche qu’il s’agit, même si ce n’est pas dit explicitement.

### `runc`

`runc` est le runtime OCI de référence et reste l’implémentation la plus connue. Il est largement utilisé par Docker, containerd et de nombreux déploiements Kubernetes. Une grande partie des recherches publiques et des ressources sur l’exploitation ciblent les environnements de type `runc`, tout simplement parce qu’ils sont courants et que `runc` définit le modèle de référence que beaucoup ont en tête lorsqu’ils pensent à un conteneur Linux. Comprendre `runc` donne donc au lecteur un solide modèle mental de l’isolation classique des conteneurs.

### `crun`

`crun` est un autre runtime OCI, écrit en C et largement utilisé dans les environnements Podman modernes. Il est souvent apprécié pour sa bonne prise en charge de cgroup v2, sa simplicité d’utilisation en rootless et sa faible surcharge. Du point de vue de la sécurité, l’essentiel n’est pas qu’il soit écrit dans un autre langage, mais qu’il joue le même rôle : il transforme la configuration OCI en un arbre de processus en cours d’exécution sous le noyau. Un workflow Podman rootless donne souvent une impression de sécurité accrue, non pas parce que `crun` résout magiquement tous les problèmes, mais parce que la pile dans son ensemble s’appuie davantage sur les user namespaces et le principe du moindre privilège.

### `runsc` de gVisor

`runsc` est le runtime utilisé par gVisor. Ici, la frontière change véritablement de nature. Au lieu de transmettre la plupart des appels système directement au noyau hôte de la manière habituelle, gVisor ajoute une couche de noyau en espace utilisateur qui émule ou intercepte une grande partie de l’interface Linux. Le résultat n’est pas un conteneur `runc` classique doté de quelques options supplémentaires : il s’agit d’une conception de sandbox différente, dont l’objectif est de réduire la surface d’attaque du noyau hôte. Les compromis en matière de compatibilité et de performances font partie de cette conception. Les environnements utilisant `runsc` doivent donc être documentés différemment des environnements utilisant un runtime OCI classique.

### `kata-runtime`

Kata Containers repoussent encore la frontière en lançant la charge de travail dans une machine virtuelle légère. D’un point de vue administratif, le déploiement peut toujours ressembler à un déploiement de conteneurs, et les couches d’orchestration peuvent toujours le traiter comme tel, mais la frontière d’isolation sous-jacente est plus proche de la virtualisation que d’un conteneur classique partageant le noyau hôte. Kata est ainsi utile lorsqu’une isolation plus forte entre les tenants est souhaitée sans renoncer aux workflows centrés sur les conteneurs.

## Moteurs et gestionnaires de conteneurs

Si le runtime bas niveau est le composant qui communique directement avec le noyau, le moteur ou le gestionnaire est celui avec lequel les utilisateurs et les opérateurs interagissent généralement. Il gère le téléchargement des images, les métadonnées, les logs, les réseaux, les volumes, le cycle de vie et l’exposition des API. Cette couche est extrêmement importante, car de nombreuses compromissions réelles se produisent à ce niveau : l’accès à un socket de runtime ou à l’API d’un daemon peut équivaloir à une compromission de l’hôte, même si le runtime bas niveau lui-même fonctionne parfaitement.

### Docker Engine

Docker Engine est la plateforme de conteneurs la plus reconnaissable pour les développeurs et l’une des raisons pour lesquelles le vocabulaire des conteneurs a pris une forme aussi marquée par Docker. Le chemin habituel va de la CLI `docker` à `dockerd`, qui coordonne ensuite des composants de plus bas niveau comme `containerd` et un runtime OCI. Historiquement, les déploiements Docker ont souvent été **rootful** ; l’accès au socket Docker constitue donc un accès très puissant. C’est pourquoi tant de ressources pratiques sur l’escalade de privilèges se concentrent sur `docker.sock` : si un processus peut demander à `dockerd` de créer un conteneur privilégié, de monter des chemins de l’hôte ou de rejoindre les namespaces de l’hôte, il n’a peut-être pas besoin d’un exploit du noyau.

Comparez les numéros de version selon leurs composantes majeure, mineure et de correctif, plutôt que de supprimer les points : `18.09.1` est antérieure à `18.09.2` et à `18.09.4`, malgré le zéro initial de sa composante mineure. Les [notes de version de Docker 18.09](https://docs.docker.com/engine/release-notes/18.09/) indiquent que le correctif de `runc` pour CVE-2019-5736 a été intégré dans la version 18.09.2, et que le correctif lié aux références de build pour CVE-2019-13139 l’a été dans la version 18.09.4. Ce sont des indices concernant les versions, pas la preuve qu’un exploit est exploitable dans le contexte considéré. Les mêmes notes de version avertissent que le daemon, le client et le runtime sont empaquetés séparément. Vérifiez donc le runtime installé et les backports du fournisseur en plus de la version du daemon ; un problème lié aux références de build nécessite également l’accès au workflow de build concerné et des entrées contrôlées par un attaquant.

### Podman

Podman a été conçu selon un modèle davantage dépourvu de daemon. Sur le plan opérationnel, cela contribue à faire comprendre que les conteneurs ne sont que des processus gérés par des mécanismes Linux standard, plutôt que par un unique daemon privilégié de longue durée. Podman offre aussi une prise en charge **rootless** bien plus aboutie que les déploiements Docker classiques que beaucoup découvrent en premier. Cela ne rend pas Podman automatiquement sûr, mais modifie considérablement le profil de risque par défaut, en particulier lorsqu’il est associé aux user namespaces, à SELinux et à `crun`.

### containerd

containerd est un composant central de gestion des runtimes dans de nombreuses piles modernes. Il est utilisé par Docker et constitue également l’un des principaux backends de runtime pour Kubernetes. Il expose des API puissantes, gère les images et les snapshots, et délègue la création finale du processus à un runtime bas niveau. Les discussions sur la sécurité de containerd doivent souligner que l’accès au socket de containerd ou aux fonctionnalités de `ctr`/`nerdctl` peut être tout aussi dangereux que l’accès à l’API de Docker, même si l’interface et le workflow semblent moins « conviviaux pour les développeurs ».

### CRI-O

CRI-O a une portée plus limitée que Docker Engine. Plutôt que d’être une plateforme générale pour les développeurs, il est conçu pour implémenter proprement la Kubernetes Container Runtime Interface. Il est donc particulièrement courant dans les distributions Kubernetes et les écosystèmes fortement basés sur SELinux, comme OpenShift. Du point de vue de la sécurité, cette portée plus étroite est utile, car elle réduit la complexité conceptuelle : CRI-O appartient clairement à la couche qui « exécute les conteneurs pour Kubernetes », et non à une plateforme qui fait tout.

Lorsqu’un nœud Kubernetes utilise CRI-O, vérifiez la **version active de CRI-O sur le nœud** et déterminez si l’identité actuelle peut créer des Pods dans un namespace qui y est planifié. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) permettait à des valeurs sysctl spécialement conçues dans un Pod de modifier un paramètre du noyau hôte et de mener à une exécution avec les privilèges root sur l’hôte dans les versions concernées. L’avis upstream indique les versions corrigées et les contournements. Un `crio --version` exécuté localement peut ne pas détecter un runtime imbriqué dans Minikube ou dans un autre conteneur de nœud ; un log de démarrage Minikube lisible peut donner une indication sur la version, mais il s’agit d’une preuve historique, et non d’une preuve du runtime actif ou de son état de correction. Confirmez le runtime réellement utilisé par le nœud, les autorisations de création de Pods, les règles d’admission ainsi que les frontières pertinentes de seccomp et des user namespaces avant de considérer qu’il s’agit d’une escalade exploitable.

Il existe aussi une piste d’analyse locale directe de `pinns` : les [chercheurs indiquent que Kubernetes n’est pas nécessaire pour invoquer l’outil vulnérable](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Vérifiez si le compte actuel peut exécuter un binaire `pinns` appartenant à root et doté du bit setuid, si NoNewPrivs ou un montage `nosuid` bloque cette élévation, et si le **build de l’outil** installé ne contient pas le correctif. L’[avis upstream](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) indique les versions corrigées, mais la version affichée par un daemon ne prouve pas à elle seule quel binaire auxiliaire est installé, et les backports des distributeurs peuvent modifier l’exposition. Un fichier setuid n’est qu’un élément à examiner : vérifiez la provenance de l’outil, sa configuration et le comportement des sysctl de l’hôte sans l’exécuter lors d’une énumération de routine.

### Incus, LXD et LXC

Il est utile de distinguer les systèmes Incus/LXD/LXC des conteneurs d’applications de type Docker, car ils sont souvent utilisés comme **conteneurs système**. Un conteneur système est généralement censé ressembler davantage à une machine légère, avec un espace utilisateur plus complet, des services de longue durée, une exposition plus importante des périphériques et une intégration plus poussée avec l’hôte. Les mécanismes d’isolation restent des primitives du noyau, mais les attentes opérationnelles sont différentes. Les erreurs de configuration ressemblent donc souvent moins à de « mauvais paramètres par défaut pour un conteneur d’application » qu’à des erreurs de virtualisation légère ou de délégation à l’hôte.

### systemd-nspawn

systemd-nspawn occupe une place particulière, car il est natif de systemd et très utile pour les tests, le débogage et l’exécution d’environnements proches d’un système d’exploitation. Ce n’est pas le runtime dominant en production dans les environnements cloud-native, mais il apparaît assez souvent dans les labs et les environnements axés sur les distributions pour mériter d’être mentionné. Pour l’analyse de sécurité, il rappelle encore une fois que la notion de « conteneur » recouvre plusieurs écosystèmes et modes d’exploitation.

### Apptainer / Singularity

Apptainer (anciennement Singularity) est courant dans les environnements de recherche et de calcul haute performance (HPC). Ses hypothèses de confiance, le workflow des utilisateurs et son modèle d’exécution diffèrent de manière importante des piles centrées sur Docker/Kubernetes. Ces environnements tiennent notamment souvent à permettre aux utilisateurs d’exécuter des charges de travail empaquetées sans leur confier de vastes privilèges de gestion des conteneurs. Si un évaluateur part du principe que tout environnement de conteneurs se résume à « Docker sur un serveur », il comprendra très mal ces déploiements.

## Outils utilisés au moment du build

De nombreuses discussions sur la sécurité ne portent que sur l’exécution, mais les outils utilisés au moment du build comptent aussi, car ils déterminent le contenu des images, l’exposition des secrets de build et la quantité de contexte de confiance intégrée à l’artefact final.

**BuildKit** et `docker buildx` sont des backends de build modernes qui prennent en charge des fonctionnalités comme la mise en cache, le montage de secrets, le transfert SSH et les builds multiplateformes. Ces fonctionnalités sont utiles, mais du point de vue de la sécurité, elles créent aussi des situations où des secrets peuvent fuiter dans les couches d’image ou un contexte de build trop large peut exposer des fichiers qui n’auraient jamais dû être inclus. **Buildah** joue un rôle similaire dans les écosystèmes natifs OCI, en particulier autour de Podman, tandis que **Kaniko** est souvent utilisé dans les environnements CI qui ne veulent pas accorder à la pipeline de build un accès à un daemon Docker privilégié.

La leçon essentielle est que la création et l’exécution d’une image sont deux phases différentes, mais qu’une pipeline de build faible peut compromettre la sécurité de l’environnement d’exécution bien avant le lancement du conteneur.

## L’orchestration est une autre couche, pas le runtime

Il ne faut pas assimiler Kubernetes au runtime. Kubernetes est l’orchestrateur. Il planifie les Pods, stocke l’état souhaité et exprime les politiques de sécurité au moyen de la configuration des workloads. Le kubelet communique ensuite avec une implémentation CRI comme containerd ou CRI-O, qui fait à son tour appel à un runtime bas niveau comme `runc`, `crun`, `runsc` ou `kata-runtime`.

Cette distinction est importante, car beaucoup attribuent à tort une protection à « Kubernetes », alors qu’elle est réellement appliquée par le runtime du nœud ; ou reprochent aux « paramètres par défaut de containerd » un comportement qui provient de la spécification d’un Pod. En pratique, la posture de sécurité finale résulte d’une combinaison : l’orchestrateur formule une demande, la pile de runtimes la traduit et le noyau l’applique finalement.

## Pourquoi l’identification du runtime est importante pendant une évaluation

Si vous identifiez tôt le moteur et le runtime, il devient plus facile d’interpréter de nombreuses observations ultérieures. Un conteneur Podman rootless indique que les user namespaces jouent probablement un rôle. Un socket Docker monté dans un workload suggère que l’escalade de privilèges via l’API est une piste réaliste. Un nœud CRI-O/OpenShift doit immédiatement faire penser aux labels SELinux et aux politiques de restriction des workloads. Un environnement gVisor ou Kata doit inciter à la prudence avant de supposer qu’un PoC d’évasion classique visant `runc` se comportera de la même manière.

C’est pourquoi l’une des premières étapes d’une évaluation de conteneurs devrait toujours consister à répondre à deux questions simples : **quel composant gère le conteneur** et **quel runtime a réellement lancé le processus**. Une fois ces réponses établies, il devient généralement beaucoup plus facile de comprendre le reste de l’environnement.

## Vulnérabilités des runtimes

Toutes les évasions de conteneurs ne sont pas dues à une mauvaise configuration de l’opérateur. Il arrive que le runtime lui-même soit le composant vulnérable. C’est important, car une charge de travail peut fonctionner avec une configuration apparemment rigoureuse tout en restant exposée à cause d’une faille dans un runtime bas niveau.

L’exemple classique est **CVE-2019-5736** dans `runc`, qui permettait à un conteneur malveillant d’écraser le binaire `runc` de l’hôte, puis d’attendre qu’un appel ultérieur à `docker exec` ou une invocation similaire du runtime déclenche du code contrôlé par l’attaquant. Le chemin d’exploitation est très différent d’une simple erreur de bind mount ou de capabilities, car il exploite la manière dont le runtime réintègre l’espace des processus du conteneur lors du traitement de `exec`.<sup>[[1]](#references)</sup>

Un workflow de reproduction minimal du point de vue d’une red team est le suivant :

```bash
go build main.go
./main
```

Ensuite, depuis l’hôte :

```bash
docker exec -it <container-name> /bin/sh
```

La leçon essentielle n’est pas l’implémentation exacte de l’exploit historique, mais son implication pour l’évaluation : si la version du runtime est vulnérable, une simple exécution de code dans le conteneur peut suffire à compromettre l’hôte, même si la configuration visible du conteneur ne semble pas manifestement faible.

Des CVE récentes touchant les runtimes, comme `CVE-2024-21626` dans `runc`, les race conditions de montage de BuildKit et les bugs d’analyse de containerd, renforcent le même point. La version du runtime et son niveau de correctifs font partie de la frontière de sécurité, ce ne sont pas de simples détails de maintenance.

## References

- [1] [Sortir de Docker via runC – Explication de CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
