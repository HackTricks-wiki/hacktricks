# Lokalna sieć i analiza socketów

{{#include ../../banners/hacktricks-training.md}}

Po uzyskaniu shella na hoście Linux najciekawsze cele sieciowe często nie są dostępne z zewnątrz. Usługi dostępne tylko przez Loopback, sieci veth, sockety Unix, tymczasowe listenery, przechwycone pakiety i lokalne reguły firewall mogą ujawnić dane uwierzytelniające lub lokalne powierzchnie ataku.

Ta strona skupia się na praktycznych technikach lokalnego post-exploitation, a nie na ogólnym zdalnym pentestingu sieci.

## Enumeracja Loopback i usług lokalnych

Zacznij od zidentyfikowania nasłuchujących usług, ich adresów nasłuchu oraz procesów, które je uruchomiły — o ile pozwalają na to uprawnienia.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Ważne wzorce:

- `127.0.0.1:<port>` lub `[::1]:<port>`: domyślnie dostępne tylko z hosta.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: dostępne przez wszystkie interfejsy IPv4, o ile ruch nie jest filtrowany.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` lub `192.168.0.0/16` na `veth*`, `docker*`, `br-*`, `cni*`: prawdopodobnie sieci kontenerów lub lokalnego laboratorium.<sup>[[23]](#references)[[24]](#references)</sup>
- Gniazda Unix w `/run`, `/var/run`, `/tmp` lub katalogach aplikacji: lokalne powierzchnie IPC.<sup>[[5]](#references)</sup>

W przypadku historycznego [problemu z parsowaniem gniazda snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) sprawdź działający demon, jego lokalne gniazdo API oraz zainstalowany pakiet lub rewizję snap względem poprawki dla danej dystrybucji. Błąd dotyczył walidacji adresu gniazda klienta przez snapd, a nie `snap-confine`; plik `snap-confine` z ustawionym set-user-ID ani sam ciąg wersji upstream nie potwierdzają podatności. Ubuntu udostępniło poprawki w wersjach pakietów właściwych dla poszczególnych wydań, a snapd mógł zostać zaktualizowany niezależnie od pakietu dystrybucji. Przed oceną granicy uprzywilejowanego API potwierdź faktycznie działającą kompilację i dostępność lokalnego gniazda. Pasywna enumeracja nie powinna wysyłać spreparowanego żądania przez gniazdo ani instalować snap.

Listener loopback uruchomiony przez [`socat` z `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) może przekazywać dane od lokalnego klienta do osobnego programu. Zanim uznasz niestandardową usługę należącą do root za trop prowadzący do eskalacji uprawnień, skoreluj polecenie uruchamiające listener, ścieżkę do pliku wykonywalnego, efektywną tożsamość procesu potomnego, lokalną dostępność i uwierzytelnianie. Błąd bezpieczeństwa pamięci lub niebezpieczna ścieżka od danych wejściowych do polecenia wymagają dowodów dotyczących konkretnego pliku binarnego i kompilacji; sam numer portu, proces `socat` ani właściciel root nie stanowią takiego dowodu. Pasywna enumeracja powinna ograniczyć się do metadanych procesów, gniazd i plików, bez wysyłania danych do usługi.

Lokalny master Salt może nasłuchiwać na portach TCP 4505 i 4506, także na loopback lub porcie hosta opublikowanym przez kontener. [Informacje o wydaniu Salt 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) opisują błąd umożliwiający dostęp do metod bez uwierzytelnienia, CVE-2020-11651, naprawiony upstream w wersjach 2019.2.4 i 3000.2. Zanim uznasz go za trop prowadzący do eskalacji uprawnień, skoreluj listener z faktycznym procesem `salt-master`, dostępnym interfejsem, zainstalowanym pakietem i poprawkami dostawcy oraz efektywną tożsamością kontenera lub hosta; sam port ani wersja upstream nie stanowią dowodu. Jeśli master działa w kontenerze, uzyskanie uprawnień root na hoście to osobna granica: potwierdź, że użyteczne gniazdo API środowiska uruchomieniowego hosta jest zamontowane i dostępne z tego kontenera. Pasywna enumeracja nie powinna odpytwać serwera żądań Salt ani tworzyć kontenera w celu oceny podatności. Zobacz [dokumentację portów Salt](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) oraz [triage API środowiska uruchomieniowego](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

Mapuj lokalne porty za pomocą lekkich sond.<sup>[[6]](#references)[[7]](#references)</sup>

```bash
for p in 80 443 8000 8080 8081 9000 5000; do
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$p" 2>/dev/null && echo "open: $p"
done
```

Użyj lokalnie `nmap`, jeśli jest dostępny.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn -p- 127.0.0.1
nmap -sT -Pn --open 127.0.0.1
```

## Ukryte podsieci veth i kontenerów

Środowiska kontenerowe lub laboratoryjne często udostępniają usługi tylko w podsieci bridge lub veth. Przed założeniem, że usługa jest nieosiągalna, wylicz interfejsy i trasy.<sup>[[2]](#references)</sup>

```bash
ip -br addr
ip route
ip neigh
```

Znajdź prawdopodobne podsieci lokalne.<sup>[[2]](#references)</sup>

```bash
ip -o -4 addr show | awk '{print $2, $4}'
```

Ostrożnie sonduj wykrytą podsieć.<sup>[[8]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
nmap -sT -Pn --open 172.17.0.0/24
nmap -sT -Pn -p 80,443,8000,8080,9000 172.17.0.0/24
```

Technika jest przydatna, gdy panel WWW, endpoint debugowania lub usługa pomocnicza są ukryte przed skanami zewnętrznymi, ale dostępne z zaatakowanego hosta lub sieci kontenerów.

Usługa notebooka nasłuchująca na loopback może uwierzytelniać za pomocą tokena startowego wypisanego na wyjściu procesu. Jeśli to wyjście jest przekierowywane do logu czytelnego dla innego lokalnego konta, token może przekroczyć granicę między użytkownikami i umożliwić wykonanie kodu na koncie serwera notebooka. Zanim uznasz ścieżkę do logu za potencjalną drogę eskalacji, sprawdź właściciela nasłuchującego procesu, lokalizację i uprawnienia logu, bieżącą konfigurację tokena oraz mechanizmy kontroli dostępu do notebooka. Podczas pasywnego rozpoznania zbieraj metadane logów; nie wyświetlaj tokenów ani nie łącz się z usługą tylko po to, by sklasyfikować host.

## Lokalny pivot za pomocą socat lub SSH

Jeśli usługa jest powiązana z loopback, udostępnij ją przez dozwolony kanał, zamiast zmieniać samą usługę.

Przekaż lokalną usługę HTTP przez SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Przekieruj lokalny port za pomocą `socat`, gdy masz już dostęp do powłoki.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Przekieruj gniazdo Unix na TCP do lokalnych testów.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Samo w sobie nie wykorzystuje żadnej podatności. Udostępnia powierzchnię dostępną tylko lokalnie Twoim narzędziom, dzięki czemu możesz wchodzić z nią w interakcje jak ze zwykłą usługą.

## Banner Grabbing i proste protokoły

Nie każda usługa korzysta z HTTP. Wiele usług lokalnych ujawnia wystarczająco dużo informacji w banerze lub jednoliniowym protokole.

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

Celem jest ustalenie protokołu, mechanizmu uwierzytelniania, wersji oraz tego, czy usługa ufa lokalnym klientom.

W przypadku listenera aiohttp sprawdź konfigurację tras statycznych oraz wersję. CVE-2024-23334 dotyczy aiohttp w wersjach wcześniejszych niż 3.9.2, gdy trasa statyczna ma włączone `follow_symlinks=True`: żądania do tej trasy mogą odczytywać pliki spoza katalogu głównego zasobów statycznych. Jeśli usługa działa jako root, może ujawnić pliki dostępne do odczytu dla root, o ile trasa jest osiągalna. Baner wersji ani nasłuchiwanie na loopback nie potwierdzają same w sobie podatnej konfiguracji ani możliwości dostępu do plików.<sup>[[27]](#references)</sup>

## Przechwytywanie ruchu Loopback

Ruch lokalny może ujawnić nagłówki, tokeny bearer, dane uwierzytelniające Basic Auth lub sekrety specyficzne dla aplikacji.<sup>[[17]](#references)[[25]](#references)</sup> Przechwytuj ruch wyłącznie w autoryzowanych środowiskach.

Przechwyć ruch HTTP loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Przechwyć konkretną usługę lokalną.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Dekoduj Basic Auth z przechwyconego lub zarejestrowanego w logach nagłówka.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Przydatne ciągi znaków, których warto szukać w zrzutach tekstowych:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Rejestrowanie kluczy TLS

Jeśli w laboratorium możesz kontrolować środowisko procesu klienta, `SSLKEYLOGFILE` może umożliwić odszyfrowywanie sesji TLS w Wiresharku lub kompatybilnych narzędziach.<sup>[[19]](#references)[[20]](#references)</sup> Przydaje się to do analizy lokalnego ruchu HTTPS bez atakowania samego TLS.

Uruchom klienta z włączonym rejestrowaniem kluczy.<sup>[[19]](#references)[[20]](#references)</sup>

```bash
export SSLKEYLOGFILE=/tmp/sslkeys.log
curl -k https://127.0.0.1:8443/
ls -l /tmp/sslkeys.log
```

Przechwytuj ruch w tym samym czasie.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/tls.pcap 'tcp port 8443'
```

Następnie załaduj `/tmp/tls.pcap` i `/tmp/sslkeys.log` do Wireshark. Działa to tylko wtedy, gdy biblioteka klienta obsługuje logowanie kluczy w stylu NSS i można ustawić zmienne środowiskowe przed nawiązaniem połączenia.<sup>[[20]](#references)[[21]](#references)</sup>

## Interakcja z Unix Socket i Command Injection

Unix Sockety to lokalne punkty końcowe IPC.<sup>[[5]](#references)</sup> Mogą udostępniać API HTTP, niestandardowe protokoły lub niebezpieczne procedury obsługi poleceń.<sup>[[12]](#references)[[14]](#references)</sup>

Socket należący do root, z uprawnieniami zapisu dla grupy, stanowi granicę autoryzacji, ale sam w sobie nie jest podatnością. Porównaj jego grupę i tryb dostępu z bieżącym kontem, ustal, który proces nasłuchuje, i sprawdź, jakie dane ten proces przyjmuje od klientów, zanim ocenisz ryzyko. W szczególności uprzywilejowana usługa, która wykonuje przesłany kod PHP, może przekraczać kolejną granicę, jeśli ufa ścieżce `php.ini` wybranej przez wywołującego lub pozwala mu zmienić `disable_functions` albo `open_basedir`; sprawdź efektywną konfigurację i ścieżkę walidacji usługi. [Przewodnik po konfiguracji PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) wyjaśnia te dyrektywy. Same metadane socketu nie potwierdzają możliwości wykonania kodu.

Znajdź sockety.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Komunikuj się z HTTP przez gniazdo Unix.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Interakcja z surowym socketem.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Jeśli dane wejściowe z gniazda kontrolowane przez użytkownika zostaną przekazane do powłoki lub uprzywilejowanego helpera, może dojść do command injection.<sup>[[26]](#references)</sup> Konkretny przykład znajdziesz w [Socket Command Injection](socket-command-injection.md).

## Przegląd nftables i autoryzowane zmiany reguł

Lokalne reguły firewalla mogą wyjaśniać, dlaczego usługa jest widoczna lokalnie, ale zablokowana zdalnie, albo dlaczego wysoki port wydaje się nieosiągalny z jednego interfejsu.<sup>[[22]](#references)</sup>

Przejrzyj reguły.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Szukaj odrzucanych pakietów dotyczących portu docelowego.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

W autoryzowanym laboratorium usuń konkretną regułę blokującą, używając jej uchwytu.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Preferuj usunięcie dokładnego uchwytu zamiast opróżniania całych tabel. Technika polega na zidentyfikowaniu konkretnego filtra powodującego dane zachowanie i zmianie tylko tej reguły.<sup>[[22]](#references)</sup>

## Szybki workflow

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Priorytetowo traktuj usługi dostępne tylko lokalnie, działające z uprawnieniami bardziej uprzywilejowanego użytkownika, udostępniające funkcje administracyjne/debugowania lub ufające klientom z loopbacka/sieci kontenerów.

## References

- [1] [ss(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: architektura adresowania IP w wersji 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Przekierowania (podręcznik Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [Wywołanie timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Techniki skanowania portów (przewodnik Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Wykrywanie hostów (przewodnik Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Określanie portów i kolejność skanowania (przewodnik Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — strona podręcznika Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — strona podręcznika OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Podręcznik narzędzia curl w wierszu poleceń](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — dokumentacja OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: schemat uwierzytelniania HTTP „Basic”](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [Wywołanie base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — dokumentacja OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — wiki Wireshark](https://wiki.wireshark.org/tls)
- [21] [Podręcznik użytkownika Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Podręcznik nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Przydzielanie adresów dla sieci prywatnych (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Struktura autoryzacji OAuth 2.0: użycie tokenów bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: niewłaściwa neutralizacja znaków specjalnych używanych w poleceniu systemu operacyjnego](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Ostrzeżenie opiekunów aiohttp: traversal tras statycznych z follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
{{#include ../../banners/hacktricks-training.md}}
