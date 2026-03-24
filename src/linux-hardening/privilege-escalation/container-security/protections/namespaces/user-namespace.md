# Namespace utilisateur

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

Le user namespace change la signification des identifiants utilisateur et de groupe en permettant au kernel de mapper les IDs vus à l'intérieur du namespace vers des IDs différents à l'extérieur. C'est l'une des protections modernes des conteneurs les plus importantes car elle traite directement le plus grand problème historique des conteneurs classiques : **le root à l'intérieur du conteneur était dangereusement proche du root sur l'hôte**.

Avec les user namespaces, un processus peut s'exécuter en tant que UID 0 à l'intérieur du conteneur et correspondre néanmoins à une plage d'UID non privilégiés sur l'hôte. Cela signifie que le processus peut se comporter comme root pour de nombreuses tâches à l'intérieur du conteneur tout en étant beaucoup moins puissant du point de vue de l'hôte. Cela ne résout pas tous les problèmes de sécurité des conteneurs, mais cela modifie significativement les conséquences d'une compromission d'un conteneur.

## Fonctionnement

Un user namespace possède des fichiers de mapping tels que `/proc/self/uid_map` et `/proc/self/gid_map` qui décrivent comment les IDs du namespace se traduisent en IDs parent. Si le root à l'intérieur du namespace est mappé vers un UID non privilégié de l'hôte, alors les opérations qui exigeraient le vrai root de l'hôte n'ont tout simplement pas le même poids. C'est pourquoi les user namespaces sont au cœur des **rootless containers** et pourquoi ils représentent l'une des plus grandes différences entre les anciennes configurations par défaut des conteneurs avec root et les conceptions modernes de moindre privilège.

Le point est subtil mais crucial : le root à l'intérieur du conteneur n'est pas éliminé, il est **traduit**. Le processus ressent toujours un environnement de type root localement, mais l'hôte ne devrait pas le traiter comme un root complet.

## Laboratoire

Un test manuel consiste à :
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Cela fait apparaître l'utilisateur courant comme root à l'intérieur de l'espace de noms tout en n'étant pas root sur l'hôte en dehors de celui-ci. C'est l'une des meilleures démonstrations simples pour comprendre pourquoi les espaces de noms utilisateur sont si précieux.

Dans les conteneurs, vous pouvez comparer la correspondance visible avec :
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
La sortie exacte dépend du fait que le moteur utilise user namespace remapping ou une configuration rootful plus traditionnelle.

Vous pouvez aussi lire la correspondance depuis l'hôte avec :
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime Usage

Rootless Podman est l'un des exemples les plus clairs d'espaces de noms utilisateur traités comme un mécanisme de sécurité de premier ordre. Rootless Docker en dépend aussi. Le support userns-remap de Docker améliore la sécurité dans les déploiements de daemon rootful également, bien que historiquement de nombreux déploiements l'aient laissé désactivé pour des raisons de compatibilité. Le support de Kubernetes pour les espaces de noms utilisateur s'est amélioré, mais l'adoption et les paramètres par défaut varient selon le runtime, la distro et la politique du cluster. Les systèmes Incus/LXC s'appuient également fortement sur le décalage UID/GID et les idées d'idmapping.

La tendance générale est claire : les environnements qui utilisent sérieusement les espaces de noms utilisateur offrent généralement une meilleure réponse à « que signifie réellement le root d'un conteneur ? » que les environnements qui ne les utilisent pas.

## Advanced Mapping Details

Lorsqu'un processus non privilégié écrit dans `uid_map` ou `gid_map`, le noyau applique des règles plus strictes que pour un écrivain privilégié de l'espace de noms parent. Seuls des mappages limités sont autorisés, et pour `gid_map` l'écrivain doit généralement d'abord désactiver `setgroups(2)` :
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ce détail est important car il explique pourquoi la configuration du user-namespace échoue parfois dans des expérimentations rootless et pourquoi les runtimes ont besoin d'une logique auxiliaire soigneuse autour de la délégation UID/GID.

Une autre fonctionnalité avancée est le **ID-mapped mount**. Plutôt que de modifier la propriété sur disque, un ID-mapped mount applique un mapping de user namespace à un mount afin que la propriété apparaisse traduite dans cette vue de mount. Cela est particulièrement pertinent dans les environnements rootless et les runtimes modernes car cela permet d'utiliser des chemins partagés du host sans opérations récursives de `chown`. Du point de vue sécurité, cette fonctionnalité change la façon dont un bind mount est perçu comme writable depuis l'intérieur du namespace, même si elle ne réécrit pas les métadonnées du filesystem sous-jacent.

Enfin, souvenez-vous que lorsqu'un processus crée ou entre dans un nouveau user namespace, il reçoit un ensemble complet de capabilities **à l'intérieur de ce namespace**. Cela ne signifie pas qu'il a soudainement acquis un pouvoir global sur le host. Cela veut dire que ces capabilities ne peuvent être utilisées que là où le modèle de namespace et les autres protections le permettent. C'est la raison pour laquelle `unshare -U` peut soudainement rendre possibles des opérations privilégiées locales au namespace, comme le mounting, sans pour autant faire disparaître la frontière root du host.

## Mauvaises configurations

La principale faiblesse est de ne pas utiliser les user namespaces dans les environnements où cela serait possible. Si le container root mappe trop directement sur le host root, les host mounts writables et les opérations kernel privilégiées deviennent beaucoup plus dangereuses. Un autre problème est de forcer le partage du user namespace du host ou de désactiver le remapping pour la compatibilité sans reconnaître à quel point cela modifie la frontière de confiance.

Les user namespaces doivent aussi être considérés conjointement avec le reste du modèle. Même lorsqu'ils sont actifs, une exposition large de l'API runtime ou une configuration runtime très faible peut toujours permettre une escalation de privilèges par d'autres voies. Mais sans eux, de nombreuses classes d'escape anciennes deviennent beaucoup plus faciles à exploiter.

## Abus

Si le container est rootful sans séparation de user namespace, un host bind mount writable devient beaucoup plus dangereux car le processus peut réellement écrire en tant que host root. Les capabilities dangereuses deviennent également plus pertinentes. L'attaquant n'a plus besoin de lutter autant contre la frontière de traduction parce que cette frontière existe à peine.

La présence ou l'absence de user namespace doit être vérifiée tôt lors de l'évaluation d'un container breakout path. Cela ne répond pas à toutes les questions, mais montre immédiatement si « root in container » a une importance directe pour le host.

Le schéma d'abus le plus pratique est de confirmer le mapping puis de tester immédiatement si le contenu monté depuis le host est writable avec des privilèges pertinents pour le host :
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si le fichier est créé comme real host root, l'isolation du user namespace est en pratique absente pour ce chemin. À ce stade, les classic host-file abuses deviennent réalistes :
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Une confirmation plus sûre lors d'une évaluation en direct consiste à écrire un marqueur bénin au lieu de modifier des fichiers critiques :
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ces vérifications importent car elles répondent rapidement à la vraie question : est-ce que root dans ce container est mappé suffisamment près du host root pour qu'un writable host mount devienne immédiatement un host compromise path?

### Exemple complet : Regaining Namespace-Local Capabilities

Si seccomp permet `unshare` et que l'environnement autorise un nouveau user namespace, le processus peut regagner un ensemble complet de capabilities à l'intérieur de ce nouveau namespace :
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Ce n'est pas en soi un host escape. La raison pour laquelle cela importe est que user namespaces peuvent réactiver des privileged namespace-local actions qui peuvent ensuite se combiner avec des weak mounts, des vulnerable kernels ou des runtime surfaces mal exposées.

## Vérifications

Ces commandes sont destinées à répondre à la question la plus importante de cette page : à quoi correspond root à l'intérieur de ce container sur le host ?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Ce qui est intéressant ici :

- Si le processus est UID 0 et que les maps montrent un mappage host-root direct ou très proche, le container est beaucoup plus dangereux.
- Si root est mappé sur une plage host non privilégiée, c'est une base beaucoup plus sûre et indique généralement une véritable isolation du user namespace.
- Les fichiers de mapping ont plus de valeur que `id` seul, car `id` n'indique que l'identité locale du namespace.

Si la charge de travail s'exécute en tant que UID 0 et que le mapping montre que cela correspond étroitement au host root, vous devriez interpréter le reste des privilèges du container de manière beaucoup plus stricte.
{{#include ../../../../../banners/hacktricks-training.md}}
