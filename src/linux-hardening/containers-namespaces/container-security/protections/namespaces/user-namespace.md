# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

Le user namespace modifie la signification des identifiants utilisateur et groupe en permettant au kernel de mapper les identifiants vus à l'intérieur du namespace vers des identifiants différents à l'extérieur. Il s'agit de l'une des protections modernes les plus importantes pour les containers, car elle s'attaque directement au plus gros problème historique des containers classiques : **root à l'intérieur du container était autrefois dangereusement proche de root sur l'hôte**.

Avec les user namespaces, un processus peut s'exécuter avec l'UID 0 à l'intérieur du container tout en correspondant à une plage d'UID non privilégiés sur l'hôte. Cela signifie que le processus peut se comporter comme root pour de nombreuses tâches à l'intérieur du container, tout en étant beaucoup moins puissant du point de vue de l'hôte. Cela ne résout pas tous les problèmes de sécurité des containers, mais modifie considérablement les conséquences d'une compromission de container.

## Operation

Un user namespace possède des fichiers de mapping tels que `/proc/self/uid_map` et `/proc/self/gid_map`, qui décrivent comment les identifiants du namespace sont traduits en identifiants du namespace parent. Si root à l'intérieur du namespace est mappé vers un UID hôte non privilégié, les opérations qui nécessiteraient un véritable root sur l'hôte n'ont alors tout simplement pas la même portée. C'est pourquoi les user namespaces sont au cœur des **rootless containers** et constituent l'une des principales différences entre les anciens defaults de containers rootful et les designs modernes fondés sur le least privilege.

Le point est subtil, mais crucial : root à l'intérieur du container n'est pas supprimé, il est **traduit**. Le processus bénéficie toujours localement d'un environnement similaire à celui de root, mais l'hôte ne devrait pas le traiter comme un root complet.

## Lab

Un test manuel consiste à :
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Cela fait apparaître l’utilisateur actuel comme root à l’intérieur du namespace, tout en ne lui conférant toujours pas les privilèges de root sur l’hôte à l’extérieur de celui-ci. C’est l’une des démonstrations simples les plus efficaces pour comprendre pourquoi les user namespaces sont si précieux.

Dans les containers, vous pouvez comparer le mapping visible avec :
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
La sortie exacte dépend de l'utilisation par le moteur du remappage de l'espace de noms utilisateur ou d'une configuration rootful plus traditionnelle.

Vous pouvez également lire le mappage depuis le côté host avec :
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Utilisation en pratique

Rootless Podman est l'un des exemples les plus clairs d'espaces de noms utilisateur traités comme un mécanisme de sécurité de premier ordre. Rootless Docker en dépend également. La prise en charge de userns-remap par Docker améliore aussi la sécurité des déploiements avec daemon rootful, même si, historiquement, de nombreux déploiements la laissaient désactivée pour des raisons de compatibilité. La prise en charge des espaces de noms utilisateur par Kubernetes s'est améliorée, mais l'adoption et les valeurs par défaut varient selon le runtime, la distro et la politique du cluster. Les systèmes Incus/LXC reposent également largement sur le décalage UID/GID et les concepts d'idmapping.

La tendance générale est claire : les environnements qui utilisent sérieusement les espaces de noms utilisateur apportent généralement une meilleure réponse à la question « que signifie réellement root dans un container ? » que ceux qui ne les utilisent pas.

## Détails avancés du mapping

Lorsqu'un processus non privilégié écrit dans `uid_map` ou `gid_map`, le kernel applique des règles plus strictes que lorsqu'un processus parent privilégié de namespace effectue cette écriture. Seuls des mappings limités sont autorisés et, pour `gid_map`, le processus effectuant l'écriture doit généralement désactiver `setgroups(2)` au préalable :
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ce détail est important, car il explique pourquoi la configuration d’un user namespace échoue parfois dans les expériences rootless et pourquoi les runtimes ont besoin d’une logique d’assistance soigneusement conçue autour de la délégation des UID/GID.

Une autre fonctionnalité avancée est le **ID-mapped mount**. Au lieu de modifier la propriété sur disque, un ID-mapped mount applique un mapping de user namespace à un mount, de sorte que la propriété apparaisse traduite à travers cette vue du mount. Cela est particulièrement pertinent dans les configurations rootless et les runtimes modernes, car cela permet d’utiliser des chemins partagés de l’hôte sans effectuer d’opérations récursives de `chown`. Du point de vue de la sécurité, cette fonctionnalité modifie la manière dont un bind mount apparaît comme étant inscriptible depuis le namespace, même si elle ne réécrit pas les métadonnées du système de fichiers sous-jacent.

Enfin, rappelez-vous que lorsqu’un processus crée ou rejoint un nouveau user namespace, il reçoit un ensemble complet de capabilities **à l’intérieur de ce namespace**. Cela ne signifie pas qu’il a soudainement acquis des privilèges globaux sur l’hôte. Cela signifie que ces capabilities ne peuvent être utilisées que là où le modèle des namespaces et les autres protections les autorisent. C’est pourquoi `unshare -U` peut soudainement rendre possibles le mount ou des opérations privilégiées locales au namespace, sans faire directement disparaître la limite entre l’hôte et root.

## Mauvaises configurations

La principale faiblesse consiste simplement à ne pas utiliser de user namespaces dans les environnements où cela serait possible. Si root dans le container est mappé trop directement vers root sur l’hôte, les mounts inscriptibles de l’hôte et les opérations privilégiées du kernel deviennent beaucoup plus dangereuses. Un autre problème consiste à forcer le partage du user namespace de l’hôte ou à désactiver le remapping pour des raisons de compatibilité, sans prendre en compte l’ampleur du changement apporté à la trust boundary.

Les user namespaces doivent également être considérés avec le reste du modèle. Même lorsqu’ils sont actifs, une exposition étendue de l’API du runtime ou une configuration très faible du runtime peut encore permettre une privilege escalation par d’autres voies. Mais sans eux, de nombreuses anciennes classes de breakout deviennent beaucoup plus faciles à exploiter.

## Abus

Si le container est rootful sans séparation par user namespace, un bind mount inscriptible de l’hôte devient bien plus dangereux, car le processus peut réellement écrire en tant que root sur l’hôte. Les capabilities dangereuses deviennent également plus significatives. L’attaquant n’a plus besoin de lutter autant contre la translation boundary, car celle-ci est à peine présente.

La présence ou l’absence d’un user namespace doit être vérifiée rapidement lors de l’évaluation d’un chemin de container breakout. Cela ne répond pas à toutes les questions, mais indique immédiatement si « root dans le container » a une pertinence directe sur l’hôte.

Le pattern d’abus le plus pratique consiste à confirmer le mapping, puis à vérifier immédiatement si le contenu monté depuis l’hôte est inscriptible avec des privilèges pertinents sur l’hôte :
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Si le fichier est créé en tant que véritable root de l'hôte, l'isolation de l'espace de noms utilisateur est effectivement absente pour ce chemin. À ce stade, les abus classiques de fichiers de l'hôte deviennent réalistes :
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Une confirmation plus sûre lors d'une évaluation en direct consiste à écrire un marqueur inoffensif plutôt qu'à modifier des fichiers critiques :
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ces vérifications sont importantes, car elles répondent rapidement à la vraie question : est-ce que root dans ce container correspond suffisamment à root sur l’host pour qu’un mount host accessible en écriture devienne immédiatement un chemin de compromission de l’host ?

### Exemple complet : Récupération des capabilities locales au namespace

Si seccomp autorise `unshare` et que l’environnement permet de créer un nouvel espace de noms utilisateur, le processus peut récupérer un ensemble complet de capabilities dans ce nouvel espace de noms :
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Ce n’est pas en soi un host escape. La raison pour laquelle cela importe est que les user namespaces peuvent réactiver des actions privilégiées limitées au namespace, qui se combinent ensuite avec des mounts faibles, des kernels vulnérables ou des runtime surfaces mal exposées.

## Vérifications

Ces commandes visent à répondre à la question la plus importante de cette page : à quel utilisateur root à l’intérieur de ce conteneur correspond-il sur l’hôte ?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Ce qui est intéressant ici :

- Si le processus est UID 0 et que les mappings montrent une correspondance directe ou très proche avec le root de l’hôte, le container est beaucoup plus dangereux.
- Si root correspond à une plage non privilégiée sur l’hôte, il s’agit d’une base beaucoup plus sûre et cela indique généralement une véritable isolation via user namespace.
- Les fichiers de mapping sont plus utiles que `id` seul, car `id` affiche uniquement l’identité locale au namespace.

Si le workload s’exécute avec l’UID 0 et que le mapping montre que cela correspond étroitement au root de l’hôte, vous devez interpréter beaucoup plus strictement le reste des privilèges du container.

{{#include ../../../../../banners/hacktricks-training.md}}
