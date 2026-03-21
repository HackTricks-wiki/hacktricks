# Espace de noms utilisateur

{{#include ../../../../../banners/hacktricks-training.md}}

## Présentation

L'espace de noms utilisateur modifie la signification des UID et GID en permettant au noyau de mapper les IDs vus à l'intérieur de l'espace de noms vers des IDs différents à l'extérieur. C'est l'une des protections de container modernes les plus importantes car elle répond directement au principal problème historique des containers classiques : **le root à l'intérieur du container était inconfortablement proche du root de l'hôte**.

Avec les espaces de noms utilisateur, un processus peut s'exécuter avec UID 0 à l'intérieur du container et correspondre néanmoins à une plage d'UID non privilégiés sur l'hôte. Cela signifie que le processus peut se comporter comme root pour de nombreuses tâches à l'intérieur du container tout en étant beaucoup moins puissant du point de vue de l'hôte. Cela ne résout pas tous les problèmes de sécurité des containers, mais cela modifie significativement les conséquences d'une compromission d'un container.

## Fonctionnement

Un espace de noms utilisateur possède des fichiers de mappage tels que `/proc/self/uid_map` et `/proc/self/gid_map` qui décrivent comment les IDs de l'espace de noms se traduisent en IDs parent. Si le root à l'intérieur de l'espace de noms est mappé sur un UID non privilégié de l'hôte, alors les opérations qui nécessiteraient le vrai root de l'hôte n'ont tout simplement pas le même poids. C'est pourquoi les espaces de noms utilisateur sont centraux pour **rootless containers** et pourquoi ils constituent l'une des plus grandes différences entre les anciens paramètres par défaut de containers rootful et les conceptions modernes à moindre privilège.

Le point est subtil mais crucial : le root à l'intérieur du container n'est pas éliminé, il est **traduit**. Le processus conserve localement un environnement de type root, mais l'hôte ne devrait pas le traiter comme un root complet.

## Laboratoire

Un test manuel est :
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Cela fait apparaître l'utilisateur courant comme root à l'intérieur du namespace tout en ne l'étant pas sur l'hôte en dehors de celui-ci. C'est l'une des meilleures démonstrations simples pour comprendre pourquoi les user namespaces sont si utiles.

Dans les containers, vous pouvez comparer le mappage visible avec :
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
La sortie exacte dépend de si le moteur utilise user namespace remapping ou une configuration rootful plus traditionnelle.

Vous pouvez aussi lire le mapping depuis l'hôte avec :
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Utilisation au runtime

Rootless Podman est l'un des exemples les plus clairs de user namespaces traités comme un mécanisme de sécurité de première classe. Rootless Docker dépend aussi d'eux. Docker's userns-remap améliore la sécurité dans les déploiements avec démon en root, bien que historiquement de nombreux déploiements l'aient laissé désactivé pour des raisons de compatibilité. La prise en charge des user namespaces dans Kubernetes s'est améliorée, mais l'adoption et les valeurs par défaut varient selon le runtime, la distribution et la politique du cluster. Les systèmes Incus/LXC s'appuient également fortement sur le décalage UID/GID et le concept d'idmapping.

La tendance générale est claire : les environnements qui utilisent sérieusement les user namespaces fournissent généralement une meilleure réponse à « que signifie réellement le root du conteneur ? » que les environnements qui ne le font pas.

## Détails avancés du mapping

Lorsqu'un processus non privilégié écrit dans `uid_map` ou `gid_map`, le noyau applique des règles plus strictes que pour un écrivain privilégié du namespace parent. Seuls des mappages limités sont autorisés, et pour `gid_map` l'écrivain doit généralement désactiver `setgroups(2)` d'abord :
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ce détail est important car il explique pourquoi la configuration de user-namespace échoue parfois dans des expériences rootless et pourquoi les runtimes ont besoin d'une logique d'assistance soigneuse autour de la délégation UID/GID.

Another advanced feature is the **ID-mapped mount**. Instead of changing on-disk ownership, an ID-mapped mount applies a user-namespace mapping to a mount so that ownership appears translated through that mount view. This is especially relevant in rootless and modern runtime setups because it allows shared host paths to be used without recursive `chown` operations. Security-wise, the feature changes how writable a bind mount appears from inside the namespace, even though it does not rewrite the underlying filesystem metadata.

Enfin, souvenez-vous que lorsqu'un processus crée ou entre dans un nouveau user namespace, il reçoit un ensemble complet de capabilities **à l'intérieur de ce namespace**. Cela ne signifie pas qu'il obtient soudainement un pouvoir global sur l'hôte. Cela signifie que ces capabilities ne peuvent être utilisées que là où le modèle de namespace et les autres protections le permettent. C'est la raison pour laquelle `unshare -U` peut soudainement rendre possibles des opérations privilégiées locales au namespace, comme le mounting, sans faire disparaître directement la frontière root de l'hôte.

## Misconfigurations

La principale faiblesse est simplement de ne pas utiliser les user namespaces dans des environnements où ils seraient faisables. Si le root du container se mappe trop directement sur le root de l'hôte, les mounts host inscriptibles et les opérations kernel privilégiées deviennent beaucoup plus dangereuses. Un autre problème est de forcer le partage du user namespace de l'hôte ou de désactiver le remapping pour compatibilité sans reconnaître à quel point cela change la frontière de confiance.

Les user namespaces doivent aussi être considérés conjointement avec le reste du modèle. Même lorsqu'ils sont actifs, une API runtime trop large ou une configuration runtime très faible peut encore permettre une escalade de privilèges par d'autres chemins. Mais sans eux, de nombreuses anciennes classes d'évasion (breakout) deviennent beaucoup plus faciles à exploiter.

## Abuse

Si le container est rootful sans séparation de user namespace, un bind mount host inscriptible devient beaucoup plus dangereux car le processus peut réellement écrire en tant que host root. Les capabilities dangereuses deviennent de même plus significatives. L'attaquant n'a plus besoin de lutter autant contre la frontière de traduction parce que cette frontière existe à peine.

La présence ou l'absence de user namespace doit être vérifiée tôt lors de l'évaluation d'un chemin d'évasion de container (container breakout). Cela ne répond pas à toutes les questions, mais montre immédiatement si "root in container" a une pertinence directe pour l'hôte.

Le schéma d'abus le plus pratique est de confirmer le mapping puis de tester immédiatement si le contenu monté depuis l'hôte est inscriptible avec des privilèges pertinents pour l'hôte :
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si le fichier est créé en tant que root réel de l'hôte, l'isolation du user namespace est effectivement absente pour ce chemin. À ce stade, les abus classiques de fichiers host deviennent réalistes :
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Une confirmation plus sûre lors d'une évaluation en direct consiste à écrire un marqueur bénin au lieu de modifier des fichiers critiques :
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ces vérifications sont importantes car elles répondent rapidement à la vraie question : est-ce que root dans ce conteneur correspond suffisamment au root de l'hôte pour qu'un montage hôte en écriture devienne immédiatement une voie de compromission de l'hôte ?

### Exemple complet : récupération des capabilities locales du namespace

Si seccomp autorise `unshare` et que l'environnement permet un nouveau user namespace, le processus peut récupérer un ensemble complet de capabilities à l'intérieur de ce nouveau namespace :
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Ce n'est pas en soi un host escape. La raison pour laquelle c'est important est que les user namespaces peuvent réactiver des actions privilégiées namespace-local qui, par la suite, se combinent avec des mounts faibles, des kernels vulnérables ou des runtime surfaces mal exposées.

## Vérifications

Ces commandes visent à répondre à la question la plus importante de cette page : à quoi correspond root à l'intérieur de ce container sur le host ?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Si le processus est UID 0 et que les maps montrent un mapping direct ou très proche vers le root de l'hôte, le conteneur est beaucoup plus dangereux.
- Si root est mappé sur une plage d'UID hôte non privilégiée, c'est une base beaucoup plus sûre et indique généralement un isolement réel du user namespace.
- Les fichiers de mapping sont plus utiles que `id` seul, car `id` n'affiche que l'identité locale au namespace.

Si la charge de travail s'exécute en UID 0 et que le mapping montre que cela correspond étroitement au root de l'hôte, vous devez interpréter le reste des privilèges du conteneur de manière beaucoup plus stricte.
