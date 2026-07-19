# Triaging sieci lokalnej i socketów

{{#include ../../banners/hacktricks-training.md}}

Po uzyskaniu shell na hoście Linux najbardziej użyteczne cele sieciowe często nie są dostępne z zewnątrz. Usługi dostępne wyłącznie przez loopback, sieci veth, sockety Unix, tymczasowe listenery, przechwycone pakiety oraz lokalne reguły firewalla mogą ujawniać dane uwierzytelniające lub lokalne powierzchnie ataku.

Ta strona koncentruje się na praktycznych technikach lokalnego post-exploitation, a nie na ogólnym zdalnym pentestingu sieci.

## Enumeracja usług loopback i lokalnych

Zacznij od zidentyfikowania nasłuchujących usług, ich adresów bind oraz procesu, który jest ich właścicielem, jeśli uprawnienia na to pozwalają:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Ważne wzorce:

- `127.0.0.1:<port>` lub `[::1]:<port>`: domyślnie dostępne tylko z hosta.
- `0.0.0.0:<port>`: dostępne na wszystkich interfejsach IPv4, chyba że są filtrowane.
- `172.x`, `10.x` lub `192.168.x` na interfejsach `veth*`, `docker*`, `br-*`, `cni*`: prawdopodobnie sieci kontenerów lub lokalnych laboratoriów.
- Gniazda Unix w `/run`, `/var/run`, `/tmp` lub katalogach aplikacji: lokalne powierzchnie IPC.

Zmapuj lokalne porty za pomocą lekkich sond:
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Użyj lokalnie `nmap`, jeśli jest dostępny:
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Ukryte interfejsy veth i podsieci kontenerów

Środowiska konteneryzowane lub laboratoryjne często udostępniają usługi wyłącznie za pośrednictwem podsieci bridge lub veth. Przed założeniem, że usługa jest niedostępna, zinwentaryzuj interfejsy i trasy:
```bash
ip -br addr
ip route
ip neigh
```
Znajdź prawdopodobne podsieci lokalne:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Ostrożnie przeskanuj wykrytą podsieć:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Ta technika jest przydatna, gdy panel webowy, endpoint debugowania lub usługa pomocnicza jest ukryta przed skanami zewnętrznymi, ale dostępna z zaatakowanego hosta lub sieci kontenera.

## Lokalny pivot za pomocą socat lub SSH

Jeśli usługa jest powiązana z loopbackiem, udostępnij ją przez dozwolony kanał zamiast zmieniać samą usługę.

Przekieruj lokalną usługę HTTP dostępną wyłącznie lokalnie za pomocą SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Zmostkuj lokalny port za pomocą `socat`, gdy masz już dostęp do powłoki:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Przekieruj socket Unix do TCP na potrzeby testów lokalnych:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Samo w sobie nie wykorzystuje żadnej podatności. Sprawia, że powierzchnia dostępna wyłącznie lokalnie staje się osiągalna z używanych przez Ciebie narzędzi, dzięki czemu możesz wchodzić z nią w interakcję jak ze zwykłą usługą.

## Banner Grabbing i proste protokoły

Nie każda usługa korzysta z HTTP. Wiele usług lokalnych ujawnia wystarczająco dużo informacji za pośrednictwem bannera lub jednoliniowego protokołu.

Podstawowe sondy:
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Sprawdzanie HTTP bez przeglądarki:
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Dla TLS:
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Celem jest zidentyfikowanie protokołu, schematu uwierzytelniania, wersji oraz tego, czy usługa ufa klientom lokalnym.

## Przechwytywanie ruchu loopback

Lokalny ruch może ujawnić nagłówki, tokeny bearer, dane uwierzytelniające Basic Auth lub sekrety specyficzne dla aplikacji. Przechwytuj ruch wyłącznie w autoryzowanych środowiskach.

Przechwyć ruch HTTP loopback:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Przechwyć określoną usługę lokalną:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Dekodowanie Basic Auth z przechwyconego lub zarejestrowanego nagłówka:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Przydatne ciągi znaków, których warto szukać w przechwyconym tekście:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Jeśli w labie możesz kontrolować środowisko procesu klienta, `SSLKEYLOGFILE` może umożliwić odszyfrowywanie sesji TLS w Wiresharku lub kompatybilnych narzędziach. Jest to przydatne do analizowania lokalnego ruchu HTTPS bez atakowania samego TLS.

Uruchom klienta z włączonym key loggingiem:
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Przechwytuj ruch w tym samym czasie:
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Następnie załaduj `/tmp/tls.pcap` i `/tmp/sslkeys.log` do Wireshark. Działa to tylko wtedy, gdy biblioteka klienta obsługuje logowanie kluczy w stylu NSS i można ustawić środowisko przed nawiązaniem połączenia.

## Interakcja z Unix Socketami i Command Injection

Unix sockets to lokalne punkty końcowe IPC. Mogą udostępniać API HTTP, niestandardowe protokoły lub niebezpieczne handlery poleceń.

Znajdź sockety:
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Interakcja z HTTP za pośrednictwem gniazda Unix:
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Interakcja z surowym gniazdem:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Jeśli dane wejściowe socketu kontrolowane przez użytkownika są przekazywane do powłoki lub uprzywilejowanego helpera, może to prowadzić do command injection. Skoncentrowany przykład znajdziesz tutaj: [Socket Command Injection](socket-command-injection.md).

## Przegląd nftables i autoryzowane zmiany reguł

Lokalne reguły firewalla mogą wyjaśniać, dlaczego usługa jest widoczna lokalnie, ale zablokowana zdalnie, lub dlaczego wysoki port wydaje się nieosiągalny z jednego interfejsu.

Przejrzyj reguły:
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Szukaj odrzuceń dotyczących portu docelowego:
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
W autoryzowanym laboratorium usuń konkretną regułę blokującą według uchwytu:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Preferuj usuwanie dokładnego uchwytu zamiast opróżniania całych tabel. Technika polega na zidentyfikowaniu dokładnego filtra powodującego dane zachowanie i zmianie tylko tej reguły.

## Szybki przebieg pracy
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Priorytetowo traktuj usługi dostępne wyłącznie lokalnie, uruchomione przez użytkownika o wyższych uprawnieniach, udostępniające funkcje administracyjne/debugowania lub ufające klientom z loopback/container network.
{{#include ../../banners/hacktricks-training.md}}
