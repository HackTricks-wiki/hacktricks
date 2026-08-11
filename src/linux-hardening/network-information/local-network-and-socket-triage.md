# Analiza lokalnej sieci i socketów

Po uzyskaniu shella na hoście Linux najbardziej użyteczne cele sieciowe często nie są wystawione z zewnątrz. Usługi dostępne wyłącznie przez loopback, sieci veth, sockety Unix, tymczasowe listenery, przechwycone pakiety oraz lokalne reguły firewalla mogą ujawniać dane uwierzytelniające lub lokalne powierzchnie ataku.

Ta strona skupia się na praktycznych technikach lokalnego post-exploitation, a nie na ogólnym remote network pentestingu.

## Enumeracja usług loopback i lokalnych

Zacznij od zidentyfikowania nasłuchujących usług, ich adresów bind oraz procesu, który je posiada, o ile pozwalają na to uprawnienia.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
ss -lntup
ss -lnx
ip addr
ip route
```
Ważne wzorce:

- `127.0.0.1:<port>` lub `[::1]:<port>`: domyślnie dostępne tylko z hosta.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: dostępne na wszystkich interfejsach IPv4, chyba że zostały odfiltrowane.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` lub `192.168.0.0/16` na `veth*`, `docker*`, `br-*`, `cni*`: prawdopodobnie sieci kontenerów lub lokalne sieci laboratoryjne.<sup>[[23]](#references)[[24]](#references)</sup>
- Gniazda Unix w `/run`, `/var/run`, `/tmp` lub katalogach aplikacji: lokalne powierzchnie IPC.<sup>[[5]](#references)</sup>

Mapuj lokalne porty za pomocą lekkich sond.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
for p in 80 443 8000 8080 8081 9000 5000; do
timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```
Korzystaj lokalnie z `nmap`, gdy jest dostępny.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```
## Ukryte veth i podsieci kontenerów

Środowiska kontenerowe lub laboratoryjne często udostępniają usługi wyłącznie w sieci bridge lub veth. Przed założeniem, że usługa jest nieosiągalna, wylicz interfejsy i trasy.<sup>[[2]](#references)</sup>
```bash
ip -br addr
ip route
ip neigh
```
Znajdź prawdopodobne podsieci lokalne.<sup>[[2]](#references)</sup>
```bash
ip -o -4 addr show | awk '{print $2, $4}'
```
Ostrożnie zbadaj wykrytą podsieć.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```
Technika jest przydatna, gdy panel webowy, endpoint debugowania lub usługa pomocnicza jest ukryta przed skanami zewnętrznymi, ale dostępna z zaatakowanego hosta lub sieci kontenera.

## Local Pivot With socat or SSH

Jeśli usługa jest powiązana z interfejsem loopback, udostępnij ją przez dozwolony kanał zamiast zmieniać samą usługę.

Przekieruj lokalną usługę HTTP za pomocą SSH.<sup>[[11]](#references)</sup>
```bash
ssh -L 8080:127.0.0.1:8080 user@target
```
Zmostkuj lokalny port za pomocą `socat`, gdy masz już dostęp do powłoki.<sup>[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```
Przekieruj gniazdo Unix do TCP na potrzeby lokalnych testów.<sup>[[5]](#references)[[12]](#references)</sup>
```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```
Samo w sobie nie wykorzystuje żadnej podatności. Udostępnia lokalny interfejs wyłącznie do użytku lokalnego za pośrednictwem Twoich narzędzi, dzięki czemu możesz wchodzić z nim w interakcję jak ze zwykłą usługą.

## Banner Grabbing i proste protokoły

Nie każda usługa korzysta z HTTP. Wiele usług lokalnych ujawnia wystarczająco dużo informacji za pośrednictwem bannera lub jednolinijkowego protokołu.

Podstawowe sondy.<sup>[[13]](#references)</sup>
```bash
nc -nv 127.0.0.1 9000
printf 'help\n' | nc -nv 127.0.0.1 9000
printf 'version\n' | nc -nv 127.0.0.1 9000
```
Sprawdzanie HTTP bez przeglądarki.<sup>[[13]](#references)[[14]](#references)</sup>
```bash
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' | nc -nv 127.0.0.1 8080
curl -i http://127.0.0.1:8080/
```
Dla TLS.<sup>[[14]](#references)[[15]](#references)</sup>
```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```
Celem jest zidentyfikowanie protokołu, schematu uwierzytelniania, wersji oraz tego, czy usługa ufa lokalnym klientom.

## Przechwytywanie ruchu Loopback

Lokalny ruch może ujawniać nagłówki, tokeny bearer, dane uwierzytelniające Basic Auth lub sekrety specyficzne dla aplikacji.<sup>[[17]](#references)[[25]](#references)</sup> Przechwytuj ruch wyłącznie w autoryzowanych środowiskach.

Przechwytuj ruch HTTP Loopback.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```
Przechwycenie konkretnej usługi lokalnej.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```
Dekoduj Basic Auth z przechwyconego lub zarejestrowanego nagłówka.<sup>[[17]](#references)[[18]](#references)</sup>
```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```
Przydatne ciągi znaków, których warto szukać w przechwyconym tekście:
```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```
## TLS Key Logging

Jeśli możesz kontrolować środowisko procesu klienta w labie, `SSLKEYLOGFILE` może umożliwić odszyfrowanie sesji TLS w Wiresharku lub kompatybilnych narzędziach.<sup>[[19]](#references)[[20]](#references)</sup> Jest to przydatne do analizy lokalnego ruchu HTTPS bez atakowania samego TLS.

Uruchom klienta z włączonym key loggingiem.<sup>[[19]](#references)[[20]](#references)</sup>
```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```
Przechwytuj ruch w tym samym czasie.<sup>[[16]](#references)</sup>
```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```
Następnie załaduj `/tmp/tls.pcap` i `/tmp/sslkeys.log` do Wireshark. Działa to tylko wtedy, gdy biblioteka klienta obsługuje logowanie kluczy w stylu NSS i można ustawić środowisko przed nawiązaniem połączenia.<sup>[[20]](#references)[[21]](#references)</sup>

## Interakcja z Unix sockets i Command Injection

Unix sockets to lokalne endpointy IPC.<sup>[[5]](#references)</sup> Mogą udostępniać interfejsy HTTP, niestandardowe protokoły lub niebezpieczne handlery poleceń.<sup>[[12]](#references)[[14]](#references)</sup>

Znajdź sockety.<sup>[[1]](#references)[[5]](#references)</sup>
```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```
Komunikuj się z HTTP za pośrednictwem gniazda Unix.<sup>[[14]](#references)</sup>
```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```
Wejdź w interakcję z surowym gniazdem.<sup>[[12]](#references)[[13]](#references)</sup>
```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```
Jeśli dane wejściowe kontrolowane przez użytkownika, pochodzące z socketu, są przekazywane do shellu lub uprzywilejowanego helpera, może to prowadzić do command injection.<sup>[[26]](#references)</sup> Skoncentrowany przykład znajdziesz w sekcji [Socket Command Injection](socket-command-injection.md).

## Przegląd nftables i autoryzowane zmiany reguł

Lokalne reguły firewalla mogą wyjaśniać, dlaczego usługa jest widoczna lokalnie, ale zablokowana zdalnie, lub dlaczego wysoki port wydaje się nieosiągalny z jednego interfejsu.<sup>[[22]](#references)</sup>

Sprawdź reguły.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```
Szukaj odrzuceń dotyczących portu docelowego.<sup>[[22]](#references)</sup>
```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```
W autoryzowanym laboratorium usuń konkretną regułę blokującą za pomocą handle.<sup>[[22]](#references)</sup>
```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```
Preferuj usunięcie dokładnego uchwytu zamiast opróżniania całych tabel. Technika polega na zidentyfikowaniu dokładnego filtra powodującego to zachowanie i zmianie wyłącznie tej reguły.<sup>[[22]](#references)</sup>

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
Priorytetyzuj usługi dostępne wyłącznie lokalnie, uruchomione przez użytkownika z większymi uprawnieniami, udostępniające funkcje administracyjne/debugowania lub ufające klientom loopback/container-network.

## References

- [1] [ss(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Architektura adresowania IP Version 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Przekierowania (Bash Reference Manual)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [wywołanie timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Techniki skanowania portów (Nmap Reference Guide)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Wykrywanie hostów (Nmap Reference Guide)](https://nmap.org/book/man-host-discovery.html)
- [10] [Specyfikacja portów i kolejność skanowania (Nmap Reference Guide)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — strona podręcznika Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — strona podręcznika OpenBSD](https://man.openbsd.org/nc.1)
- [14] [podręcznik narzędzia curl w wierszu poleceń](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — dokumentacja OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Schemat uwierzytelniania HTTP „Basic”](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [wywołanie base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — dokumentacja OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wireshark Wiki](https://wiki.wireshark.org/tls)
- [21] [Przewodnik użytkownika Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [podręcznik nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Przydzielanie adresów dla prywatnych sieci internetowych (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Framework autoryzacji OAuth 2.0: użycie tokenu Bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Niewłaściwa neutralizacja elementów specjalnych używanych w poleceniu systemu operacyjnego](https://cwe.mitre.org/data/definitions/78.html)
{{#include ../../banners/hacktricks-training.md}}
