# Analiza lokalnej sieci i socketów

{{#include ../../banners/hacktricks-training.md}}

Po uzyskaniu powłoki na hoście Linux najbardziej przydatne cele sieciowe często nie są dostępne z zewnątrz. Usługi dostępne tylko przez loopback, sieci veth, sockety Unix, tymczasowe listenery, przechwycone pakiety i lokalne reguły zapory mogą ujawnić dane uwierzytelniające lub powierzchnie ataku dostępne tylko lokalnie.

Ta strona skupia się na praktycznych lokalnych technikach post-exploitation, a nie na ogólnym zdalnym pentestingu sieci.

## Enumeracja loopback i usług lokalnych

Zacznij od zidentyfikowania nasłuchujących usług, ich adresów powiązania oraz procesów, które je uruchomiły, jeśli pozwalają na to uprawnienia.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
ss -lntup
ss -lnx
ip addr
ip route
```

Ważne wzorce:

- `127.0.0.1:<port>` lub `[::1]:<port>`: domyślnie dostępne tylko z hosta.<sup>[[3]](#references)[[4]](#references)</sup>
- `0.0.0.0:<port>`: dostępne przez wszystkie interfejsy IPv4, o ile ruch nie jest filtrowany.<sup>[[3]](#references)</sup>
- `10.0.0.0/8`, `172.16.0.0/12` lub `192.168.0.0/16` na `veth*`, `docker*`, `br-*`, `cni*`: prawdopodobnie sieci kontenerów lub lokalnego labu.<sup>[[23]](#references)[[24]](#references)</sup>
- Gniazda Unix w `/run`, `/var/run`, `/tmp` lub katalogach aplikacji: lokalne powierzchnie IPC.<sup>[[5]](#references)</sup>

W przypadku historycznego [problemu z parsowaniem gniazda snapd, CVE-2019-7304](https://ubuntu.com/security/vulnerabilities/snap-socket-parsing) sprawdź działający daemon, jego lokalne gniazdo API oraz zainstalowaną wersję pakietu lub snap względem poprawki dla danej dystrybucji. Błąd dotyczył weryfikacji przez snapd adresu gniazda peera, a nie `snap-confine`; plik `snap-confine` z ustawionym set-user-ID ani sam numer wersji upstream nie potwierdzają podatności. Ubuntu udostępniało poprawki w wersjach pakietów zależnych od wydania, a snapd mógł zostać zaktualizowany przez snap niezależnie od pakietu dystrybucji. Przed oceną granicy uprzywilejowanego API potwierdź faktycznie działającą kompilację i lokalną dostępność gniazda. Pasywne rozpoznanie nie powinno wysyłać spreparowanego żądania do gniazda ani instalować snap.

Nasłuch uruchomiony na loopback przez [`socat` z `EXEC`](https://man7.org/linux/man-pages/man1/socat.1.html) może przekazywać lokalne dane wejściowe klienta do osobnego programu. Zanim uznasz niestandardową usługę należącą do roota za potencjalną ścieżkę eskalacji uprawnień, sprawdź polecenie uruchamiające nasłuch, ścieżkę pliku wykonywalnego, efektywną tożsamość procesu potomnego, lokalną dostępność oraz uwierzytelnianie. Błąd bezpieczeństwa pamięci lub niebezpieczna ścieżka od danych wejściowych do polecenia wymagają dowodów dotyczących konkretnego pliku binarnego i kompilacji; sam numer portu, proces `socat` ani właściciel root nie stanowią potwierdzenia. Pasywne rozpoznanie powinno ograniczyć się do metadanych procesów, gniazd i plików, bez wysyłania danych do usługi.

Lokalny Salt master może nasłuchiwać na TCP 4505 i 4506, także na loopback lub porcie hosta opublikowanym przez kontener. [Informacje o wydaniu Salt 3000.2](https://docs.saltproject.io/en/latest/topics/releases/3000.2.html) opisują błąd dostępu do metod bez uwierzytelnienia, CVE-2020-11651, naprawiony w upstream 2019.2.4 i 3000.2. Zanim uznasz go za potencjalną ścieżkę eskalacji uprawnień, sprawdź, czy nasłuch jest powiązany z faktycznym procesem `salt-master`, dostępny interfejs, zainstalowany pakiet i poprawki dostawcy oraz efektywną tożsamość kontenera lub hosta; sam port ani wersja upstream nie stanowią dowodu. Jeśli master działa w kontenerze, wpływ na uprawnienia roota hosta zależy od osobnej granicy: potwierdź, że użyteczne gniazdo API środowiska uruchomieniowego hosta jest zamontowane i dostępne z tego kontenera. Pasywne rozpoznanie nie powinno odpytywać serwera żądań Salt ani tworzyć kontenera w celu ustalenia podatności. Zobacz [dokumentację portów Salt](https://docs.saltproject.io/salt/install-guide/en/latest/topics/before-you-start/check-network-ports.html) oraz [rozpoznanie runtime API](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md).

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

Środowiska kontenerowe lub laboratoryjne często udostępniają usługi wyłącznie w podsieci bridge lub veth. Przed założeniem, że usługa jest nieosiągalna, wylicz interfejsy i trasy.<sup>[[2]](#references)</sup>

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

Ta technika jest przydatna, gdy panel webowy, endpoint debugowania lub usługa pomocnicza jest ukryta przed skanami zewnętrznymi, ale osiągalna z zaatakowanego hosta lub sieci kontenerów.

## Tokeny usług notebooków między kontami użytkowników

Usługa notebooka nasłuchująca na loopback może uwierzytelniać użytkowników za pomocą tokena startowego wypisanego w wyjściu procesu. Jeśli to wyjście jest przekierowane do logu czytelnego dla innego konta lokalnego, token może przekroczyć granicę kont użytkowników i umożliwić code execution na koncie usługi notebooka. Zanim uznasz ścieżkę do logu za trop prowadzący do eskalacji, sprawdź właściciela nasłuchującego procesu, lokalizację i uprawnienia logu, bieżącą konfigurację tokena oraz mechanizmy kontroli dostępu do notebooka. Podczas pasywnego rozpoznania sprawdź metadane logu; nie wyświetlaj tokenów ani nie łącz się z usługą wyłącznie po to, by sklasyfikować hosta.

Usługa Jupyter Lab może również ujawniać swój token w czytelnym dla użytkownika polu systemd `ExecStart` lub w wierszu poleceń uruchomionego procesu (`ps auxww`), a nie tylko w logach startowych. W opisanym przykładzie `User=analyst` i `--ServerApp.token` wskazywały zarówno dane uwierzytelniające, jak i konto stojące za listenerem `127.0.0.1:8888`. Dostęp do hosta oraz token i `ssh -L 8888:127.0.0.1:8888 user@host` umożliwiły dostęp do terminala Jupyter Lab jako użytkownik usługi. Sprawdź łącznie efektywnego użytkownika jednostki, argumenty procesu, listener i ważność tokena; samo powiązanie z loopback nie stanowi granicy autoryzacji.<sup>[[28]](#references)</sup>

## Lokalny pivot za pomocą socat lub SSH

Jeśli usługa jest powiązana z loopback, udostępnij ją przez dozwolony kanał, zamiast zmieniać samą usługę.

Przekaż lokalną usługę HTTP przez SSH.<sup>[[11]](#references)</sup>

```bash
ssh -L 8080:127.0.0.1:8080 user@target
```

Połącz lokalny port za pomocą `socat`, gdy masz już dostęp do powłoki.<sup>[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18080,fork,reuseaddr TCP:127.0.0.1:8080
```

Przekieruj gniazdo Unix do TCP na potrzeby lokalnych testów.<sup>[[5]](#references)[[12]](#references)</sup>

```bash
socat TCP-LISTEN:18081,fork,reuseaddr UNIX-CONNECT:/run/app/app.sock
```

Samo w sobie nie wykorzystuje żadnej podatności. Udostępnia powierzchnię dostępną wyłącznie lokalnie Twoim narzędziom, dzięki czemu możesz wchodzić z nią w interakcję jak ze zwykłą usługą.

## Banner Grabbing i proste protokoły

Nie każda usługa korzysta z HTTP. Wiele usług lokalnych ujawnia wystarczająco dużo informacji w banerze lub jednolinijkowym protokole.

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

W przypadku TLS.<sup>[[14]](#references)[[15]](#references)</sup>

```bash
openssl s_client -connect 127.0.0.1:8443 -servername localhost
curl -k -i https://127.0.0.1:8443/
```

Celem jest ustalenie protokołu, schematu uwierzytelniania, wersji oraz tego, czy usługa ufa lokalnym klientom.

W przypadku listenera aiohttp sprawdź konfigurację tras statycznych oraz wersję. CVE-2024-23334 dotyczy wersji aiohttp starszych niż 3.9.2, gdy trasa statyczna ma włączone `follow_symlinks=True`: żądania do tej trasy mogą odczytywać pliki spoza katalogu głównego zasobów statycznych. Jeśli usługa działa jako root, może udostępniać pliki, które root może odczytać, o ile trasa jest osiągalna. Baner wersji ani samo powiązanie z loopbackiem nie potwierdzają podatnej konfiguracji ani możliwości odczytu plików.<sup>[[27]](#references)</sup>

## Przechwytywanie ruchu Loopback

Ruch lokalny może ujawniać nagłówki, bearer tokeny, dane uwierzytelniające Basic Auth lub sekrety specyficzne dla aplikacji.<sup>[[17]](#references)[[25]](#references)</sup> Przechwytuj ruch wyłącznie w autoryzowanych środowiskach.

Przechwytuj ruch HTTP loopback.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -A -s0 'tcp port 80 or tcp port 8080'
```

Przechwyć konkretną usługę lokalną.<sup>[[16]](#references)</sup>

```bash
sudo tcpdump -i lo -w /tmp/loopback.pcap 'tcp port 8080'
```

Zdekoduj Basic Auth z przechwyconego lub zarejestrowanego nagłówka.<sup>[[17]](#references)[[18]](#references)</sup>

```bash
printf '%s' 'dXNlcjpwYXNz' | base64 -d
```

Przydatne ciągi do wyszukania w zrzutach tekstowych:

```bash
grep -Ei 'Authorization:|Cookie:|Bearer|Basic|token|api[_-]?key|password' /tmp/capture.txt
```

## Rejestrowanie kluczy TLS

Jeśli w laboratorium możesz kontrolować środowisko procesu klienta, `SSLKEYLOGFILE` może umożliwić odszyfrowanie sesji TLS w Wiresharku lub kompatybilnych narzędziach.<sup>[[19]](#references)[[20]](#references)</sup> Jest to przydatne do analizy lokalnego ruchu HTTPS bez atakowania samego TLS.

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

Następnie wczytaj `/tmp/tls.pcap` i `/tmp/sslkeys.log` do Wireshark. Działa to tylko wtedy, gdy biblioteka klienta obsługuje logowanie kluczy w stylu NSS i można ustawić zmienne środowiskowe przed nawiązaniem połączenia.<sup>[[20]](#references)[[21]](#references)</sup>

## Obsługa gniazd Unix i wstrzykiwanie poleceń

Gniazda Unix to lokalne punkty końcowe IPC.<sup>[[5]](#references)</sup> Mogą udostępniać API HTTP, niestandardowe protokoły lub niebezpieczne procedury obsługi poleceń.<sup>[[12]](#references)[[14]](#references)</sup>

Gniazdo należące do roota z uprawnieniami zapisu dla grupy stanowi granicę autoryzacji, ale samo w sobie nie jest podatnością. Porównaj jego grupę i tryb dostępu z bieżącym kontem, zidentyfikuj proces nasłuchujący i sprawdź, jakie dane proces ten akceptuje od klientów, zanim ocenisz ryzyko. W szczególności uprzywilejowana usługa wykonująca przesłany kod PHP może przekraczać kolejną granicę, jeśli ufa również ścieżce `php.ini` wybranej przez wywołującego albo pozwala mu zmieniać `disable_functions` lub `open_basedir`; sprawdź efektywną konfigurację i ścieżkę walidacji usługi. [Przewodnik po konfiguracji PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/README.md) wyjaśnia te dyrektywy. Same metadane gniazda nie dowodzą możliwości wykonania kodu.

Znajdź gniazda.<sup>[[1]](#references)[[5]](#references)</sup>

```bash
ss -lnx
find /run /var/run /tmp -type s -ls 2>/dev/null
```

Komunikuj się z HTTP przez gniazdo Unix.<sup>[[14]](#references)</sup>

```bash
curl --unix-socket /run/app/app.sock http://localhost/
curl --unix-socket /run/app/app.sock -i http://localhost/admin
```

Komunikuj się z raw socketem.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
printf 'status\n' | socat - UNIX-CONNECT:/run/app/app.sock
printf 'help\n' | nc -U /run/app/app.sock
```

Jeśli dane wejściowe z kontrolowanego przez użytkownika socketu zostaną przekazane do shell lub uprzywilejowanego helpera, może to doprowadzić do command injection.<sup>[[26]](#references)</sup> Przykład omawiający ten problem znajdziesz w [Socket Command Injection](socket-command-injection.md).

## Przegląd nftables i autoryzowane zmiany reguł

Lokalne reguły zapory mogą wyjaśniać, dlaczego usługa jest widoczna lokalnie, ale blokowana zdalnie, albo dlaczego wysoki port wydaje się nieosiągalny z jednego interfejsu.<sup>[[22]](#references)</sup>

Przejrzyj reguły.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset
sudo nft list tables
sudo nft list chains
```

Szukaj odrzuceń dotyczących portu docelowego.<sup>[[22]](#references)</sup>

```bash
sudo nft list ruleset | grep -Ei 'drop|reject|dport|tcp|udp'
```

W autoryzowanym laboratorium usuń określoną regułę blokującą, używając jej uchwytu.<sup>[[22]](#references)</sup>

```bash
sudo nft -a list chain inet filter input
sudo nft delete rule inet filter input handle <handle>
```

Preferuj usunięcie konkretnego uchwytu zamiast czyszczenia całych tabel. Technika polega na zidentyfikowaniu dokładnego filtra powodującego takie działanie i zmianie tylko tej reguły.<sup>[[22]](#references)</sup>

## Szybki przepływ pracy

```bash
ss -lntup
ss -lnx
ip -br addr
ip route
nmap -sT -Pn --open 127.0.0.1
find /run /var/run /tmp -type s -ls 2>/dev/null
sudo nft list ruleset 2>/dev/null | head -n 80
```

Priorytetowo traktuj usługi dostępne tylko lokalnie, działające z większymi uprawnieniami, udostępniające funkcje administracyjne/debugowania lub ufające klientom z loopbacku/sieci kontenerów.

## References

- [1] [ss(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ss.8.html)
- [2] [ip(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ip.8.html)
- [3] [ip(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [4] [RFC 4291: Architektura adresowania IP w wersji 6](https://www.rfc-editor.org/info/rfc4291/)
- [5] [unix(7) — strona podręcznika Linux](https://man7.org/linux/man-pages/man7/unix.7.html)
- [6] [Przekierowania (Podręcznik referencyjny Bash)](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [7] [wywołanie timeout (GNU Coreutils)](https://www.gnu.org/s/coreutils/timeout)
- [8] [Techniki skanowania portów (Podręcznik referencyjny Nmap)](https://nmap.org/book/man-port-scanning-techniques.html)
- [9] [Wykrywanie hostów (Podręcznik referencyjny Nmap)](https://nmap.org/book/man-host-discovery.html)
- [10] [Określanie portów i kolejność skanowania (Podręcznik referencyjny Nmap)](https://nmap.org/book/man-port-specification.html)
- [11] [ssh(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/ssh.1.html)
- [12] [socat(1) — strona podręcznika Linux](https://www.man7.org/linux/man-pages/man1/socat.1.html)
- [13] [nc(1) — podręcznik OpenBSD](https://man.openbsd.org/nc.1)
- [14] [Podręcznik narzędzia wiersza poleceń curl](https://curl.se/docs/manpage.html?category=23)
- [15] [openssl-s_client — dokumentacja OpenSSL](https://docs.openssl.org/3.0/man1/openssl-s_client/)
- [16] [tcpdump(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
- [17] [RFC 7617: Schemat uwierzytelniania HTTP „Basic”](https://www.rfc-editor.org/rfc/rfc7617.html)
- [18] [wywołanie base64 (GNU Coreutils)](https://www.gnu.org/software/coreutils/manual/html_node/base64-invocation.html)
- [19] [openssl-env — dokumentacja OpenSSL](https://docs.openssl.org/master/man7/openssl-env/)
- [20] [TLS — Wiki Wireshark](https://wiki.wireshark.org/tls)
- [21] [Podręcznik użytkownika Wireshark](https://www.wireshark.org/docs/wsug_html/)
- [22] [Podręcznik nftables](https://netfilter.org/projects/nftables/manpage.html)
- [23] [Przydzielanie adresów dla sieci prywatnych (RFC 1918)](https://www.rfc-editor.org/rfc/rfc1918.html)
- [24] [ip-link(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ip-link.8.html)
- [25] [Struktura autoryzacji OAuth 2.0: użycie tokenu Bearer (RFC 6750)](https://www.rfc-editor.org/rfc/rfc6750.html)
- [26] [CWE-78: Nieprawidłowe neutralizowanie znaków specjalnych używanych w poleceniu systemu operacyjnego](https://cwe.mitre.org/data/definitions/78.html)
- [27] [Ostrzeżenie opiekunów aiohttp: traversal ścieżek statycznych z follow_symlinks](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-5h86-8mv2-jq9f)
- [28] [HTB: DevHub — token Jupyter ujawniony przez systemd i argumenty procesów](https://0xdf.gitlab.io/2026/10/10/htb-devhub.html)
{{#include ../../banners/hacktricks-training.md}}
