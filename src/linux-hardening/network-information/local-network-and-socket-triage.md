# Triage lokalnej sieci i socketów

{{#include ../../banners/hacktricks-training.md}}

Po uzyskaniu shell na hoście Linux najbardziej użyteczne cele sieciowe często nie są dostępne z zewnątrz. Usługi dostępne wyłącznie przez loopback, sieci veth, sockety Unix, tymczasowe listenery, przechwycone pakiety i lokalne reguły firewalla mogą ujawnić credentials lub lokalne attack surface.

Ta strona koncentruje się na praktycznych technikach local post-exploitation, a nie na ogólnym zdalnym network pentestingu.

## Enumeracja loopback i lokalnych usług

Zacznij od zidentyfikowania nasłuchujących usług, ich adresów bind oraz procesu, który je posiada, o ile pozwalają na to uprawnienia:
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Ważne wzorce:

- `127.0.0.1:<port>` lub `[::1]:<port>`: domyślnie dostępne tylko z hosta.
- `0.0.0.0:<port>`: dostępne na wszystkich interfejsach IPv4, chyba że zostały odfiltrowane.
- `172.x`, `10.x` lub `192.168.x` na `veth*`, `docker*`, `br-*`, `cni*`: prawdopodobnie sieci kontenerów lub lokalnego labu.
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
## Ukryte veth i podsieci kontenerów

Środowiska konteneryzowane lub laboratoryjne często udostępniają usługi wyłącznie w podsieci bridge lub veth. Przed założeniem, że usługa jest nieosiągalna, wylicz interfejsy i trasy:
```bash
ip -br addr
ip route
ip neigh
```
Znajdź prawdopodobne podsieci lokalne:
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Ostrożnie zbadaj wykrytą podsieć:
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Technika jest przydatna, gdy panel webowy, endpoint debugowania lub usługa pomocnicza jest ukryta przed skanowaniem zewnętrznym, ale dostępna z zaatakowanego hosta lub sieci kontenera.

## Lokalny pivot za pomocą socat lub SSH

Jeśli usługa jest powiązana z interfejsem loopback, udostępnij ją przez dozwolony kanał zamiast zmieniać samą usługę.

Przekieruj lokalną usługę HTTP dostępną wyłącznie lokalnie za pomocą SSH:
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Zmostkuj lokalny port za pomocą `socat`, gdy masz już dostęp do powłoki:
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Przekieruj gniazdo Unix do TCP na potrzeby lokalnych testów:
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
To samo w sobie nie wykorzystuje żadnej podatności. Sprawia, że powierzchnia dostępna tylko lokalnie staje się osiągalna z używanych przez Ciebie narzędzi, dzięki czemu możesz korzystać z niej jak ze zwykłej usługi.

## Banner Grabbing i proste protokoły

Nie każda usługa korzysta z HTTP. Wiele usług lokalnych ujawnia wystarczającą ilość informacji za pośrednictwem bannera lub jednoliniowego protokołu.

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
Celem jest zidentyfikowanie protokołu, schematu uwierzytelniania, wersji oraz tego, czy usługa ufa lokalnym klientom.

## Przechwytywanie ruchu Loopback

Lokalny ruch może ujawniać nagłówki, tokeny bearer, dane uwierzytelniające Basic Auth lub sekrety specyficzne dla aplikacji. Przechwytuj ruch wyłącznie w autoryzowanych środowiskach.

Przechwyć ruch HTTP Loopback:
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Przechwytywanie konkretnej usługi lokalnej:
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Zdekoduj Basic Auth z przechwyconego lub zarejestrowanego nagłówka:
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Przydatne ciągi znaków, których warto szukać w przechwyconym tekście:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Jeśli możesz kontrolować środowisko procesu klienta w laboratorium, `SSLKEYLOGFILE` może umożliwić odszyfrowanie sesji TLS w Wiresharku lub kompatybilnych narzędziach. Jest to przydatne do analizowania lokalnego ruchu HTTPS bez atakowania samego TLS.

Uruchom klienta z włączonym logowaniem kluczy:
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

## Interakcja z Unix Socket i Command Injection

Unix sockety to lokalne punkty końcowe IPC. Mogą udostępniać API HTTP, niestandardowe protokoły lub niebezpieczne handlery poleceń.

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
Interakcja z raw socketem:
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Jeśli dane wejściowe kontrolowane przez użytkownika z socketu są przekazywane do powłoki lub uprzywilejowanego helpera, może to prowadzić do command injection. Skoncentrowany przykład znajdziesz w [Socket Command Injection](socket-command-injection.md).

## Przegląd nftables i autoryzowane zmiany reguł

Lokalne reguły firewall mogą wyjaśniać, dlaczego usługa jest widoczna lokalnie, ale zablokowana zdalnie, lub dlaczego wysoki port wydaje się nieosiągalny z jednego interfejsu.

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
W autoryzowanym laboratorium usuń konkretną regułę blokującą za pomocą uchwytu:
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Preferuj usuwanie dokładnego uchwytu zamiast opróżniania całych tabel. Technika polega na zidentyfikowaniu dokładnego filtra powodującego to zachowanie i zmianie tylko tej reguły.

## Szybki przebieg działań
```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```
Nadaj priorytet usługom dostępnym wyłącznie lokalnie, uruchamianym przez użytkownika o wyższych uprawnieniach, udostępniającym funkcje administracyjne/debugowania lub ufającym klientom loopback/sieci kontenerowej.

{{#include ../../banners/hacktricks-training.md}}
