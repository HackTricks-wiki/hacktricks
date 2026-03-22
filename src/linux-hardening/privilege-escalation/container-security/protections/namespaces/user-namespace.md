# Espace de noms utilisateur

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms utilisateur modifie la signification des IDs utilisateur et groupe en permettant au noyau de mapper les IDs vus à l'intérieur de l'espace de noms vers des IDs différents à l'extérieur. C'est l'une des protections de container modernes les plus importantes car elle traite directement le plus gros problème historique des containers classiques : **le root à l'intérieur du container était dangereusement proche du root sur l'hôte**.

Avec les espaces de noms utilisateur, un processus peut s'exécuter avec le UID 0 à l'intérieur du container et correspondre néanmoins à une plage d'UID non privilégiée sur l'hôte. Cela signifie que le processus peut se comporter comme root pour de nombreuses tâches à l'intérieur du container tout en étant beaucoup moins puissant du point de vue de l'hôte. Cela ne résout pas tous les problèmes de sécurité des containers, mais cela modifie significativement les conséquences d'une compromission de container.

Le point est subtil mais crucial : le root à l'intérieur du container n'est pas éliminé, il est **traduit**. Le processus conserve une expérience de type root localement, mais l'hôte ne devrait pas le considérer comme un root complet.

## Fonctionnement

Un espace de noms utilisateur dispose de fichiers de mapping tels que `/proc/self/uid_map` et `/proc/self/gid_map` qui décrivent comment les IDs du namespace sont traduits en IDs du parent. Si le root à l'intérieur du namespace est mappé vers un UID non privilégié sur l'hôte, alors les opérations qui nécessiteraient le vrai root de l'hôte n'ont tout simplement pas le même poids. C'est pourquoi les espaces de noms utilisateur sont au cœur des **rootless containers** et pourquoi ils représentent l'une des principales différences entre les anciens réglages par défaut rootful des containers et les conceptions modernes de moindre privilège.

Le point est subtil mais crucial : le root à l'intérieur du container n'est pas éliminé, il est **traduit**. Le processus conserve une expérience de type root localement, mais l'hôte ne devrait pas le considérer comme un root complet.

## Laboratoire

Un test manuel est :
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Cela fait apparaître l'utilisateur courant comme root à l'intérieur du namespace, tout en ne l'étant pas sur l'hôte à l'extérieur. C'est l'une des meilleures démonstrations simples pour comprendre pourquoi les user namespaces sont si précieux.

Dans les containers, vous pouvez comparer le mapping visible avec :
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
La sortie exacte dépend de si le moteur utilise user namespace remapping ou une configuration rootful plus traditionnelle.

Vous pouvez aussi lire le mapping depuis le host avec :
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Utilisation à l'exécution

Rootless Podman est un des exemples les plus clairs d'espaces de noms utilisateur traités comme un mécanisme de sécurité de première classe. Rootless Docker en dépend également. Le support userns-remap de Docker améliore la sécurité des déploiements avec daemon en root, bien que, historiquement, de nombreux déploiements l'aient laissé désactivé pour des raisons de compatibilité. Le support de Kubernetes pour les espaces de noms utilisateur s'est amélioré, mais l'adoption et les valeurs par défaut varient selon le runtime, la distro et la politique du cluster. Les systèmes Incus/LXC reposent aussi fortement sur le décalage UID/GID et les idées d'idmapping.

La tendance générale est claire : les environnements qui utilisent sérieusement les espaces de noms utilisateur offrent généralement une meilleure réponse à « que signifie réellement le root du conteneur ? » que ceux qui ne le font pas.

## Détails avancés du mapping

Lorsqu'un processus non privilégié écrit dans `uid_map` ou `gid_map`, le noyau applique des règles plus strictes que pour un écrivain privilégié du namespace parent. Seuls des mappages limités sont autorisés, et pour `gid_map` l'auteur de l'écriture doit généralement désactiver `setgroups(2)` au préalable :
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ce détail importe car il explique pourquoi la configuration de user-namespace échoue parfois dans des expérimentations rootless et pourquoi les runtimes ont besoin d'une logique d'aide soignée pour la délégation UID/GID.

Une autre fonctionnalité avancée est le **ID-mapped mount**. Plutôt que de modifier la propriété sur disque, un ID-mapped mount applique un mapping de user-namespace à un mount de sorte que la propriété semble traduite via cette vue de mount. Cela est particulièrement pertinent dans les environnements rootless et les configurations de runtime modernes car cela permet d'utiliser des chemins host partagés sans opérations `chown` récursives. Du point de vue de la sécurité, cette fonctionnalité modifie le caractère inscriptible d'un bind mount vu depuis l'intérieur du namespace, même si elle ne réécrit pas les métadonnées du système de fichiers sous-jacent.

Enfin, rappelez-vous que lorsqu'un processus crée ou entre dans un nouveau user namespace, il reçoit un ensemble complet de capabilities **à l'intérieur de ce namespace**. Cela ne signifie pas qu'il a soudainement acquis des pouvoirs globaux sur l'hôte. Cela signifie que ces capabilities ne peuvent être utilisées que là où le modèle de namespace et les autres protections le permettent. C'est la raison pour laquelle `unshare -U` peut soudainement rendre possibles le montage ou des opérations privilégiées locales au namespace sans pour autant faire disparaître directement la frontière root de l'hôte.

## Mauvaises configurations

La faiblesse principale est de ne pas utiliser les user namespaces dans des environnements où ils seraient possibles. Si le root du container se mappe trop directement sur le root de l'hôte, les host mounts inscriptibles et les opérations noyau privilégiées deviennent beaucoup plus dangereuses. Un autre problème est de forcer le partage du user namespace de l'hôte ou de désactiver le remapping pour des raisons de compatibilité sans reconnaître à quel point cela modifie la frontière de confiance.

Les user namespaces doivent aussi être considérés dans le contexte du modèle complet. Même lorsqu'ils sont actifs, une exposition large de l'API du runtime ou une configuration runtime très faible peuvent encore permettre une escalade de privilèges par d'autres chemins. Mais sans eux, beaucoup d'anciennes classes d'évasion deviennent beaucoup plus faciles à exploiter.

## Abus

Si le container fonctionne en rootful sans séparation de user namespace, un host bind mount inscriptible devient beaucoup plus dangereux car le processus peut réellement écrire en tant que host root. Les capabilities dangereuses prennent de même beaucoup plus d'importance. L'attaquant n'a plus besoin de lutter autant contre la frontière de traduction puisque celle-ci existe à peine.

La présence ou l'absence de user namespace doit être vérifiée tôt lors de l'évaluation d'un chemin d'évasion de container. Cela ne répond pas à toutes les questions, mais cela montre immédiatement si "root in container" a une pertinence directe sur l'hôte.

Le pattern d'abus le plus pratique est de confirmer le mapping puis de tester immédiatement si le contenu monté depuis l'hôte est inscriptible avec des privilèges pertinents pour l'hôte :
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si le fichier est créé en tant que véritable host root, l'isolation du user namespace est effectivement absente pour ce chemin. À ce stade, les abus classiques sur les fichiers de l'hôte deviennent réalistes :
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Une confirmation plus sûre lors d'une évaluation en direct consiste à écrire un marqueur bénin au lieu de modifier des fichiers critiques :
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ces vérifications sont importantes car elles répondent rapidement à la vraie question : est-ce que root dans ce conteneur correspond suffisamment au root de l'hôte pour qu'un writable host mount devienne immédiatement un chemin de compromission de l'hôte ?

### Exemple complet : Regaining Namespace-Local Capabilities

Si seccomp autorise `unshare` et que l'environnement autorise la création d'une nouvelle user namespace, le processus peut récupérer un ensemble complet de capabilities à l'intérieur de cette namespace :
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Ce n'est pas en soi une host escape. La raison pour laquelle cela importe est que les user namespaces peuvent réactiver des actions privilégiées locales au namespace qui peuvent ensuite se combiner avec des points de montage faibles, des noyaux vulnérables ou des surfaces d'exécution mal exposées.

## Vérifications

Ces commandes visent à répondre à la question la plus importante de cette page : à quoi correspond root à l'intérieur de ce conteneur sur l'hôte ?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Si le processus est UID 0 et que les fichiers de mapping montrent un mappage direct (ou très proche) vers root de l'hôte, le conteneur est beaucoup plus dangereux.
- Si root est mappé vers une plage d'UID non privilégiée sur l'hôte, c'est une base beaucoup plus sûre et indique généralement une vraie isolation du user namespace.
- Les fichiers de mapping sont plus utiles que `id` seul, parce que `id` n'affiche que l'identité locale au namespace.

Si la charge de travail s'exécute en UID 0 et que le mapping montre que cela correspond étroitement au root de l'hôte, vous devriez interpréter le reste des privilèges du conteneur de manière beaucoup plus stricte.
{{#include ../../../../../banners/hacktricks-training.md}}
